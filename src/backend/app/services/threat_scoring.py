from typing import List, Dict, Any, Optional
from app.models.alert import AlertSeverity


class ThreatScoringEngine:
    """Deterministic, transparent risk scoring engine.
    Calculates risk score (0-100) and priority based on explainable factors.
    """

    SEVERITY_BASE_SCORES = {
        AlertSeverity.CRITICAL: 85,
        AlertSeverity.HIGH: 65,
        AlertSeverity.MEDIUM: 45,
        AlertSeverity.LOW: 20,
    }

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
        base = cls.SEVERITY_BASE_SCORES.get(severity, 50)
        score = base * source_weight

        # Boost score if indicators exist
        if indicators_count > 0:
            score += min(indicators_count * 3, 10)

        # Boost score if mapped to MITRE techniques
        if mitre_count > 0:
            score += min(mitre_count * 2, 8)

        # Boost if part of correlated incident
        if is_correlated:
            score += 5

        # Clamp between 0 and 100
        return int(max(0, min(100, round(score))))

    @classmethod
    def calculate_threat_confidence(
        cls,
        alert_count: int,
        unique_sources: int,
        shared_indicators_count: int,
        mitre_techniques_count: int,
    ) -> int:
        """Calculates incident correlation confidence score (0-100)."""
        confidence = 50  # Base confidence

        # Alert volume factor
        confidence += min(alert_count * 5, 20)

        # Multi-source corroboration factor
        if unique_sources >= 3:
            confidence += 15
        elif unique_sources >= 2:
            confidence += 10

        # Shared indicator factor
        if shared_indicators_count >= 2:
            confidence += 10
        elif shared_indicators_count >= 1:
            confidence += 5

        # MITRE coverage factor
        confidence += min(mitre_techniques_count * 2, 8)

        return int(max(40, min(99, confidence)))

    @classmethod
    def get_priority_band(cls, score: int) -> str:
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        else:
            return "LOW"
