import uuid
from datetime import datetime, timezone
from typing import List, Tuple, Optional, Dict, Set
from collections import defaultdict
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.alert import Alert, AlertSeverity
from app.models.threat import Threat, ThreatSeverity, ThreatStatus
from app.models.correlation import Correlation
from app.services.threat_scoring import ThreatScoringEngine
from app.core.logging import logger


class CorrelationEngine:
    """Deterministic, rule-based correlation engine.
    Combines thousands of individual security alerts into explainable, meaningful threat groups.
    Never relies on an LLM for core correlation.
    """

    # Stage weights for event escalation sequence
    STAGE_PROGRESSION = {
        "network_policy_violation": 1,
        "security_rule_match": 2,
        "process_execution": 3,
        "intel_ioc_match": 4,
    }

    @classmethod
    def evaluate_pair(cls, a1: Alert, a2: Alert) -> Tuple[float, str, str]:
        """Evaluates correlation strength between two alerts across all dimensions.
        Returns (score, explainable_reason, rule_name).
        """
        evidence_factors: List[str] = []
        score = 0.0

        # 1. Hostname match
        if a1.hostname and a2.hostname and a1.hostname.lower() == a2.hostname.lower():
            score += 0.35
            evidence_factors.append(f"Same host '{a1.hostname}'")

        # 2. Username match
        if a1.username and a2.username and a1.username.lower() == a2.username.lower():
            score += 0.30
            evidence_factors.append(f"Same user account '{a1.username}'")

        # 3. Source IP match
        if a1.source_ip and a2.source_ip and a1.source_ip == a2.source_ip:
            score += 0.30
            evidence_factors.append(f"Same source IP {a1.source_ip}")

        # 4. Destination IP match
        if a1.destination_ip and a2.destination_ip and a1.destination_ip == a2.destination_ip:
            score += 0.25
            evidence_factors.append(f"Same destination IP {a1.destination_ip}")

        # 5. Shared Indicators (IOCs: IPs, domains, hashes)
        shared_iocs = set(a1.indicators or []) & set(a2.indicators or [])
        if shared_iocs:
            ioc_list = list(shared_iocs)[:2]
            score += 0.35
            evidence_factors.append(f"Shared indicator(s): {', '.join(ioc_list)}")

        # 6. Shared MITRE ATT&CK techniques
        shared_techniques = set(a1.mitre_techniques or []) & set(a2.mitre_techniques or [])
        if shared_techniques:
            score += 0.20
            evidence_factors.append(f"Shared MITRE ATT&CK: {', '.join(list(shared_techniques)[:2])}")

        # 7. Temporal proximity
        delta_seconds = abs((a1.timestamp - a2.timestamp).total_seconds())
        delta_minutes = delta_seconds / 60.0
        delta_hours = delta_minutes / 60.0

        if delta_minutes <= 15.0:
            score += 0.25
            evidence_factors.append(f"Observed within {int(delta_minutes)} minutes")
        elif delta_hours <= 1.0:
            score += 0.15
            evidence_factors.append(f"Observed within {int(delta_minutes)} minutes")
        elif delta_hours <= 6.0:
            score += 0.10
            evidence_factors.append(f"Observed within {int(delta_hours)} hours")
        elif delta_hours <= 24.0:
            score += 0.05
            evidence_factors.append("Observed within same 24-hour window")
        else:
            # Significant time gap dampens overall correlation confidence
            score *= 0.70

        # 8. Related event types / Kill-chain progression
        t1 = a1.event_type or ""
        t2 = a2.event_type or ""
        if t1 and t2 and t1 != t2:
            stage1 = cls.STAGE_PROGRESSION.get(t1, 0)
            stage2 = cls.STAGE_PROGRESSION.get(t2, 0)
            if stage1 > 0 and stage2 > 0 and stage1 != stage2:
                score += 0.15
                evidence_factors.append(f"Attack lifecycle progression ({t1} -> {t2})")

        # 9. Threat intelligence matching attribution
        m1 = (a1.metadata_info or {}).get("threat_intelligence", [])
        m2 = (a2.metadata_info or {}).get("threat_intelligence", [])
        if m1 and m2:
            actors1 = {item.get("threat_actor") for item in m1 if item.get("threat_actor")}
            actors2 = {item.get("threat_actor") for item in m2 if item.get("threat_actor")}
            if actors1 & actors2:
                actor = list(actors1 & actors2)[0]
                score += 0.30
                evidence_factors.append(f"Attributed to threat actor '{actor}'")

        # Format deterministic, explainable reason
        if evidence_factors and score >= 0.40:
            reason = " and ".join(evidence_factors[:2])
            if len(evidence_factors) > 2:
                reason += f" | {'; '.join(evidence_factors[2:])}"
        else:
            reason = "Insufficient corroborating telemetry"

        rule_name = "multi_attribute_correlation" if len(evidence_factors) >= 2 else "single_factor_link"
        final_score = round(min(1.0, max(0.0, score)), 2)

        return final_score, reason, rule_name

    @classmethod
    async def correlate_alerts(cls, db: AsyncSession) -> int:
        """Executes the deterministic correlation engine over all open/investigating alerts.
        Creates explainable correlation links and groups connected alerts into Threats.
        """
        stmt = select(Alert).order_by(Alert.timestamp.desc()).limit(300)
        result = await db.execute(stmt)
        alerts: List[Alert] = list(result.scalars().all())

        new_correlations_count = 0
        adjacency: Dict[str, Set[str]] = defaultdict(set)
        alert_map: Dict[str, Alert] = {a.id: a for a in alerts}

        # Pairwise comparison
        for i in range(len(alerts)):
            for j in range(i + 1, len(alerts)):
                a1 = alerts[i]
                a2 = alerts[j]

                score, reason, rule = cls.evaluate_pair(a1, a2)

                # Threshold for a valid explainable correlation
                if score >= 0.50:
                    adjacency[a1.id].add(a2.id)
                    adjacency[a2.id].add(a1.id)

                    # Check if already recorded in correlations table
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
                            threat_id=a1.related_threat_id or a2.related_threat_id,
                            correlation_reason=reason,
                            correlation_score=score,
                            rule_name=rule,
                        )
                        db.add(corr)
                        new_correlations_count += 1

        # Group connected components into Threats (Union-Find / BFS)
        visited: Set[str] = set()
        components: List[List[str]] = []

        for aid in alerts:
            if aid.id not in visited and aid.id in adjacency:
                component = []
                queue = [aid.id]
                visited.add(aid.id)
                while queue:
                    curr = queue.pop(0)
                    component.append(curr)
                    for neighbor in adjacency[curr]:
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)
                if len(component) >= 2:
                    components.append(component)

        # Create or update Threat groups for components
        new_threats = []
        updated_threats = []
        
        for comp in components:
            comp_alerts = [alert_map[aid] for aid in comp if aid in alert_map]
            existing_threat_ids = {a.related_threat_id for a in comp_alerts if a.related_threat_id}

            threat: Optional[Threat] = None
            if existing_threat_ids:
                first_tid = list(existing_threat_ids)[0]
                threat = await db.get(Threat, first_tid)

            # Compute aggregated attributes
            timestamps = [a.timestamp for a in comp_alerts]
            first_seen = min(timestamps)
            last_seen = max(timestamps)

            # Collect affected assets
            assets = set()
            for a in comp_alerts:
                if a.hostname:
                    assets.add(f"Host: {a.hostname}")
                if a.username:
                    assets.add(f"User: {a.username}")
                if a.source_ip:
                    assets.add(f"IP: {a.source_ip}")
                if a.destination_ip:
                    assets.add(f"IP: {a.destination_ip}")

            # Collect all MITRE techniques
            mitre_set = set()
            for a in comp_alerts:
                mitre_set.update(a.mitre_techniques or [])

            # Highest severity
            severities = [a.severity for a in comp_alerts]
            if AlertSeverity.CRITICAL in severities:
                threat_sev = ThreatSeverity.CRITICAL
            elif AlertSeverity.HIGH in severities:
                threat_sev = ThreatSeverity.HIGH
            elif AlertSeverity.MEDIUM in severities:
                threat_sev = ThreatSeverity.MEDIUM
            else:
                threat_sev = ThreatSeverity.LOW

            # Calculate risk score & confidence
            max_alert_risk = max([a.risk_score for a in comp_alerts]) if comp_alerts else 60
            threat_risk = min(100, max_alert_risk + min(len(comp_alerts) * 4, 15))
            confidence = ThreatScoringEngine.calculate_threat_confidence(
                alert_count=len(comp_alerts),
                unique_sources=len({a.source for a in comp_alerts}),
                shared_indicators_count=len({ioc for a in comp_alerts for ioc in (a.indicators or [])}),
                mitre_techniques_count=len(mitre_set),
            )

            primary_alert = sorted(comp_alerts, key=lambda a: a.risk_score, reverse=True)[0]

            if not threat:
                # Use a UUID suffix to guarantee uniqueness across test runs.
                # Count-based IDs collide when old test data remains in the shared DB.
                new_tid = f"INC-{uuid.uuid4().hex[:8].upper()}"

                threat = Threat(
                    id=new_tid,
                    threat_id=new_tid,
                    title=f"Campaign: {primary_alert.title}",
                    summary=f"Correlated {len(comp_alerts)} alerts across affected assets: {', '.join(list(assets)[:3])}.",
                    description=f"Automated threat campaign identified by correlation engine. Aggregated evidence from {len(comp_alerts)} alerts.",
                    explanation=f"Correlated based on shared assets and temporal proximity across {len(comp_alerts)} detection points.",
                    severity=threat_sev,
                    status=ThreatStatus.ACTIVE,
                    risk_score=threat_risk,
                    confidence=confidence,
                    alert_count=len(comp_alerts),
                    affected_assets=list(assets)[:10],
                    first_seen=first_seen,
                    last_seen=last_seen,
                    opened_at=first_seen,
                    updated_at_custom=last_seen,
                    alert_ids=[a.id for a in comp_alerts],
                    mitre_techniques=list(mitre_set),
                )
                db.add(threat)
                new_threats.append(threat)
            else:
                threat.alert_count = len(comp_alerts)
                threat.affected_assets = list(assets)[:10]
                threat.first_seen = first_seen
                threat.last_seen = last_seen
                threat.updated_at_custom = last_seen
                threat.risk_score = threat_risk
                threat.confidence = confidence
                threat.alert_ids = [a.id for a in comp_alerts]
                threat.mitre_techniques = list(mitre_set)
                threat.severity = threat_sev
                updated_threats.append(threat)

            # Update alerts with this threat ID
            for a in comp_alerts:
                a.related_threat_id = threat.id

        await db.commit()
        
        from app.services.websocket_manager import ws_manager
        for t in new_threats:
            await ws_manager.broadcast_threat_event("threat.created", t)
        for t in updated_threats:
            await ws_manager.broadcast_threat_event("threat.updated", t)
            
        return new_correlations_count
