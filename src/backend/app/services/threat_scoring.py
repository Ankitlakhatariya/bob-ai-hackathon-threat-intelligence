from typing import List, Dict, Any, Optional
from app.models.alert import Alert, AlertSeverity
from app.models.threat import Threat, ThreatSeverity
from app.models.indicator import IndicatorReputation


class ThreatScoringEngine:
    """Transparent, deterministic, and fully explainable Risk Scoring Engine.
    Calculates reproducible risk scores (0–100) and priority bands without using an LLM.
    Stores granular scoring factors for SOC analyst auditability.
    """

    CRITICAL_ASSET_KEYWORDS = [
        "dc", "domain", "controller", "vault", "backup", "prod", "database", "k8s", "gateway", "pki"
    ]
    HIGH_IMPACT_MITRE = [
        "T1003",  # OS Credential Dumping
        "T1078",  # Valid Accounts
        "T1021.002",  # Remote Services / SMB
        "T1041",  # Exfiltration
        "T1486",  # Data Encrypted for Impact (Ransomware)
    ]

    @classmethod
    def get_priority_band(cls, score: int) -> str:
        """Enforces strictly defined priority bands."""
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        else:
            return "LOW"

    @classmethod
    def calculate_alert_risk(
        cls,
        severity: AlertSeverity,
        indicators_count: int = 0,
        mitre_count: int = 0,
        is_correlated: bool = False,
        source_weight: float = 1.0,
    ) -> int:
        """Calculates risk score for an alert (0-100)."""
        severity_base = {
            AlertSeverity.CRITICAL: 85,
            AlertSeverity.HIGH: 65,
            AlertSeverity.MEDIUM: 45,
            AlertSeverity.LOW: 20,
        }
        base = severity_base.get(severity, 50)
        score = base * source_weight

        if indicators_count > 0:
            score += min(indicators_count * 3, 10)
        if mitre_count > 0:
            score += min(mitre_count * 2, 8)
        if is_correlated:
            score += 5

        return int(max(0, min(100, round(score))))

    @classmethod
    def calculate_threat_confidence(
        cls,
        alert_count: int,
        unique_sources: int,
        shared_indicators_count: int,
        mitre_techniques_count: int,
    ) -> int:
        """Calculates correlation confidence score (0-100)."""
        confidence = 50
        confidence += min(alert_count * 5, 20)
        if unique_sources >= 3:
            confidence += 15
        elif unique_sources >= 2:
            confidence += 10
        if shared_indicators_count >= 2:
            confidence += 10
        elif shared_indicators_count >= 1:
            confidence += 5
        confidence += min(mitre_techniques_count * 2, 8)
        return int(max(40, min(99, confidence)))

    @classmethod
    def evaluate_threat_risk(
        cls,
        threat: Threat,
        alerts: Optional[List[Alert]] = None,
        max_correlation_score: float = 0.85,
    ) -> Dict[str, Any]:
        """Calculates transparent, reproducible threat risk score (0-100) and factors breakdown.

        Factors Breakdown:
        1. severity: 0 - 25 pts
        2. indicator_reputation: 0 - 20 pts
        3. correlation: 0 - 20 pts
        4. asset_criticality: 0 - 15 pts
        5. behavior: 0 - 20 pts
        Total: 0 - 100 pts
        """
        factors: Dict[str, int] = {}
        alerts_list = alerts or []

        # 1. Alert Severity Factor (max 25)
        severity_scores = {
            ThreatSeverity.CRITICAL: 25,
            ThreatSeverity.HIGH: 18,
            ThreatSeverity.MEDIUM: 10,
            ThreatSeverity.LOW: 5,
        }
        factors["severity"] = severity_scores.get(threat.severity, 15)

        # 2. Indicator Reputation Factor (max 20)
        # Check if any member alert has malicious indicators attached
        has_malicious = False
        has_suspicious = False
        for a in alerts_list:
            intel = (a.metadata_info or {}).get("threat_intelligence", [])
            for item in intel:
                rep = item.get("reputation")
                if rep == IndicatorReputation.MALICIOUS.value:
                    has_malicious = True
                elif rep == IndicatorReputation.SUSPICIOUS.value:
                    has_suspicious = True

        if has_malicious or threat.severity == ThreatSeverity.CRITICAL:
            factors["indicator_reputation"] = 20
        elif has_suspicious or len(threat.mitre_techniques) >= 2:
            factors["indicator_reputation"] = 14
        else:
            factors["indicator_reputation"] = 8

        # 3. Correlation Strength & Alert Volume (max 20)
        corr_score = 0
        if max_correlation_score >= 0.80:
            corr_score += 10
        elif max_correlation_score >= 0.50:
            corr_score += 6
        else:
            corr_score += 3

        alert_count = threat.alert_count or len(alerts_list) or len(threat.alert_ids)
        if alert_count >= 4:
            corr_score += 10
        elif alert_count >= 2:
            corr_score += 7
        else:
            corr_score += 4
        factors["correlation"] = min(20, corr_score)

        # 4. Asset Criticality (max 15)
        asset_score = 5  # Baseline
        assets_text = " ".join(threat.affected_assets or []).lower()
        for kw in cls.CRITICAL_ASSET_KEYWORDS:
            if kw in assets_text or any(kw in (a.hostname or "").lower() for a in alerts_list):
                asset_score = 15
                break
        factors["asset_criticality"] = asset_score

        # 5. Behavioral Anomaly & MITRE Impact (max 20)
        behavior_score = 0
        tech_count = len(threat.mitre_techniques)
        if tech_count >= 3:
            behavior_score += 10
        elif tech_count >= 1:
            behavior_score += 6

        # Check for high-impact techniques
        if any(tech in cls.HIGH_IMPACT_MITRE for tech in threat.mitre_techniques):
            behavior_score += 10
        elif any(a.event_type == "process_execution" for a in alerts_list):
            behavior_score += 6

        factors["behavior"] = min(20, behavior_score)

        # Calculate reproducible total score
        total_risk = sum(factors.values())
        total_risk = max(0, min(100, total_risk))

        priority = cls.get_priority_band(total_risk)

        return {
            "risk_score": total_risk,
            "priority": priority,
            "factors": factors,
        }
