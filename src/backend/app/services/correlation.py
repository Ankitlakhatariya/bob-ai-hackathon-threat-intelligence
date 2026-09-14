from datetime import datetime, timezone
from typing import List, Tuple, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.alert import Alert, AlertSeverity
from app.models.threat import Threat, ThreatSeverity, ThreatStatus
from app.models.correlation import Correlation
from app.services.threat_scoring import ThreatScoringEngine
from app.core.logging import logger


class CorrelationEngine:
    """Deterministic, rule-based correlation engine.
    Correlates alerts into cohesive threat campaigns without relying on non-deterministic LLMs.
    """

    @classmethod
    async def correlate_alerts(cls, db: AsyncSession) -> int:
        """Evaluates unassigned or open alerts and computes correlation links."""
        stmt = select(Alert).order_by(Alert.timestamp.desc())
        result = await db.execute(stmt)
        alerts: List[Alert] = list(result.scalars().all())

        new_correlations_count = 0

        # Compare pairs of alerts
        for i in range(len(alerts)):
            for j in range(i + 1, len(alerts)):
                a1 = alerts[i]
                a2 = alerts[j]

                # Check if already correlated
                score, reason, rule = cls.evaluate_pair(a1, a2)
                if score >= 0.5:
                    # Check if correlation already recorded
                    corr_check = await db.execute(
                        select(Correlation).where(
                            ((Correlation.alert_id == a1.id) & (Correlation.related_alert_id == a2.id)) |
                            ((Correlation.alert_id == a2.id) & (Correlation.related_alert_id == a1.id))
                        )
                    )
                    existing = corr_check.scalars().first()
                    if not existing:
                        corr = Correlation(
                            alert_id=a1.id,
                            related_alert_id=a2.id,
                            correlation_reason=reason,
                            correlation_score=score,
                            rule_name=rule,
                        )
                        db.add(corr)
                        new_correlations_count += 1

                        # If one has a threat and the other doesn't, fold the unassigned alert into the threat
                        if a1.related_threat_id and not a2.related_threat_id:
                            a2.related_threat_id = a1.related_threat_id
                            threat = await db.get(Threat, a1.related_threat_id)
                            if threat and a2.id not in threat.alert_ids:
                                threat.alert_ids = list(threat.alert_ids) + [a2.id]
                                threat.mitre_techniques = list(set(threat.mitre_techniques + a2.mitre_techniques))
                        elif a2.related_threat_id and not a1.related_threat_id:
                            a1.related_threat_id = a2.related_threat_id
                            threat = await db.get(Threat, a2.related_threat_id)
                            if threat and a1.id not in threat.alert_ids:
                                threat.alert_ids = list(threat.alert_ids) + [a1.id]
                                threat.mitre_techniques = list(set(threat.mitre_techniques + a1.mitre_techniques))

        await db.flush()
        return new_correlations_count

    @classmethod
    def evaluate_pair(cls, a1: Alert, a2: Alert) -> Tuple[float, str, str]:
        """Evaluates correlation strength between two alerts."""
        shared_indicators = set(a1.indicators or []) & set(a2.indicators or [])
        shared_techniques = set(a1.mitre_techniques or []) & set(a2.mitre_techniques or [])

        # Time difference in hours
        time_diff = abs((a1.timestamp - a2.timestamp).total_seconds()) / 3600.0

        reasons = []
        score = 0.0

        if shared_indicators:
            score += 0.55
            reasons.append(f"Shared indicators: {', '.join(list(shared_indicators)[:3])}")

        if shared_techniques:
            score += 0.25
            reasons.append(f"Shared MITRE ATT&CK techniques: {', '.join(list(shared_techniques)[:2])}")

        if time_diff <= 2.0:
            score += 0.20
            reasons.append(f"Temporal proximity ({time_diff:.1f} hours)")
        elif time_diff <= 24.0:
            score += 0.10
            reasons.append(f"Same 24-hour observation window")

        rule_name = "multi_indicator_match" if shared_indicators else "behavioral_technique_match"
        reason_str = " | ".join(reasons) if reasons else "Weak relationship"

        return min(score, 1.0), reason_str, rule_name
