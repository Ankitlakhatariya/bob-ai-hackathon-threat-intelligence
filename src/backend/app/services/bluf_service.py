from typing import Optional, Dict
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.bluf import BlufReport
from app.models.threat import Threat
from app.models.alert import Alert
from app.services.llm_service import OpenAIThreatAnalysisService
from app.schemas.llm import BlufLLMResponse


STANDARD_BRIEFS: Dict[str, Dict[str, any]] = {
    "INC-1001": {
        "bottom_line": "Spearphishing delivery led to malicious file execution and secondary C2 traffic on internal hosts. Active campaign requires immediate containment of host ws-042.",
        "impact": "Single workstation compromised with elevated execution attempts. High risk of lateral movement if domain credentials were harvested.",
        "key_evidence": [
            "ALERT-2033 — Malicious macro executed from email attachment invoice_sep26.xlsm",
            "ALERT-2036 — PowerShell spawned with obfuscated download string",
            "ALERT-2031 — Beaconing observed to known C2 IP 198.51.100.23 on port 443",
        ],
        "recommended_focus": "Isolate host ws-042 from the network immediately. Revoke active session tokens for user j.doe and inspect authentication logs for lateral SMB connections.",
    },
    "INC-1002": {
        "bottom_line": "External brute-force activity against the border VPN gateway was followed by a successful login from an anomalous geographic IP address.",
        "impact": "Potential unauthorized network ingress via corporate VPN. Secondary access to internal segments is being probed.",
        "key_evidence": [
            "ALERT-2032 — 450 failed authentication attempts against VPN gateway from 203.0.113.88",
            "ALERT-2034 — Single successful login for account svc-backup from same source IP",
            "ALERT-2037 — Unusual outbound SSH session initiated towards staging server",
        ],
        "recommended_focus": "Disable svc-backup external VPN profile. Terminate the active VPN session from 203.0.113.88 and verify SSH key integrity on the staging host.",
    },
    "INC-1003": {
        "bottom_line": "Credential dumping activity detected on backup server followed by attempted directory reconnaissance across domain controllers.",
        "impact": "High probability of domain privilege escalation. Critical operational impact if Active Directory is fully compromised.",
        "key_evidence": [
            "ALERT-2041 — LSASS memory access detected by endpoint sensor on srv-backup-01",
            "ALERT-2039 — High-volume Kerberos ticket requests (AS-REP roasting pattern)",
            "ALERT-2040 — SMB share enumeration across DC-01 and DC-02",
        ],
        "recommended_focus": "Reset KRBTGT account password and force ticket regeneration. Isolate srv-backup-01 and audit all admin accounts accessed in the last 6 hours.",
    },
    "INC-1004": {
        "bottom_line": "Data staging and encrypted archive creation observed on file server, likely preparatory to exfiltration.",
        "impact": "Potential data breach involving confidential engineering documents and customer records.",
        "key_evidence": [
            "ALERT-2042 — 7-Zip process created password-protected archive in temp directory",
            "ALERT-2043 — Large outbound data transfer (4.2 GB) via encrypted HTTPS to unclassified domain",
            "ALERT-2044 — Volume shadow copies deleted via vssadmin on srv-files-02",
        ],
        "recommended_focus": "Block destination IP 192.0.2.145 at the perimeter firewall. Preserve memory dump of srv-files-02 and initiate incident response breach assessment.",
    },
}


class BlufService:
    @classmethod
    async def get_or_generate_bluf(cls, db: AsyncSession, threat_id: str, force_regenerate: bool = False) -> Optional[BlufReport]:
        if not force_regenerate:
            stmt = select(BlufReport).where(BlufReport.threat_id == threat_id)
            result = await db.execute(stmt)
            report = result.scalars().first()
            if report:
                return report

        # Fallback dynamic generation based on threat record
        threat = await db.get(Threat, threat_id)
        if not threat:
            return None

        # Fetch associated alerts for evidence
        alerts_stmt = select(Alert).where(Alert.related_threat_id == threat_id)
        alerts_res = await db.execute(alerts_stmt)
        alerts = list(alerts_res.scalars().all())

        llm_service = OpenAIThreatAnalysisService()

        if llm_service.is_configured():
            threat_context = {
                "threat": {
                    "id": threat.id,
                    "title": threat.title,
                    "summary": threat.summary,
                    "severity": threat.severity,
                    "risk_score": threat.risk_score,
                    "confidence": threat.confidence,
                    "affected_assets": threat.affected_assets,
                    "mitre_techniques": threat.mitre_techniques
                },
                "alerts": [
                    {
                        "id": a.id,
                        "title": a.title,
                        "description": a.description,
                        "severity": a.severity,
                        "source": a.source,
                        "indicators": a.indicators
                    } for a in alerts
                ]
            }
            try:
                bluf_resp: BlufLLMResponse = await llm_service.generate_bluf(threat_context)
                
                bottom_line = f"**BOTTOM LINE:**\\n{bluf_resp.bottom_line}\\n\\n**SITUATION:**\\n{bluf_resp.situation}\\n\\n**ASSESSMENT:**\\n{bluf_resp.assessment}"
                impact = f"**IMPACT:**\\n{bluf_resp.impact}\\n\\n**MITRE ATT&CK:**\\n{bluf_resp.mitre_context}\\n\\n**UNCERTAINTIES:**\\n{bluf_resp.uncertainties}"
                key_evidence = bluf_resp.evidence
                recommended_focus = f"**RECOMMENDED FOCUS:**\\n{bluf_resp.recommended_focus}\\n\\n**PRIORITY:**\\n{bluf_resp.priority}"
                generated_by = f"AI Analysis ({llm_service.model})"
                
            except Exception:
                # Fallback on LLM failure
                bottom_line = threat.summary
                impact = f"Severity {threat.severity.value.upper()} incident impacting security posture."
                key_evidence = [f"{a.id} — {a.title} ({a.source_label})" for a in alerts] or [f"{threat.id} — Primary correlated event"]
                recommended_focus = f"Prioritize containment of alerts related to {threat.title} and review indicators."
                generated_by = "ThreatLens Correlation Engine (Fallback)"
        else:
            # Fallback when LLM not configured
            bottom_line = threat.summary
            impact = f"Severity {threat.severity.value.upper()} incident impacting security posture."
            key_evidence = [f"{a.id} — {a.title} ({a.source_label})" for a in alerts] or [f"{threat.id} — Primary correlated event"]
            recommended_focus = f"Prioritize containment of alerts related to {threat.title} and review indicators."
            generated_by = "ThreatLens Correlation Engine (Static)"

        # Save or update report
        stmt = select(BlufReport).where(BlufReport.threat_id == threat_id)
        result = await db.execute(stmt)
        report = result.scalars().first()
        
        if not report:
            report = BlufReport(threat_id=threat_id)
            db.add(report)

        report.bottom_line = bottom_line
        report.impact = impact
        report.key_evidence = key_evidence
        report.recommended_focus = recommended_focus
        report.generated_by = generated_by

        await db.commit()
        await db.refresh(report)
        return report

    @classmethod
    async def get_all_briefs_dict(cls, db: AsyncSession) -> Dict[str, Dict[str, any]]:
        """Returns map of { incidentId: { bottomLine, impact, keyEvidence, recommendedFocus } } for frontend."""
        stmt = select(BlufReport)
        result = await db.execute(stmt)
        reports = list(result.scalars().all())

        # If empty, pre-populate standard briefs
        if not reports:
            for threat_id, brief_data in STANDARD_BRIEFS.items():
                r = BlufReport(
                    threat_id=threat_id,
                    bottom_line=brief_data["bottom_line"],
                    impact=brief_data["impact"],
                    key_evidence=brief_data["key_evidence"],
                    recommended_focus=brief_data["recommended_focus"],
                )
                db.add(r)
            await db.commit()
            stmt = select(BlufReport)
            result = await db.execute(stmt)
            reports = list(result.scalars().all())

        return {
            r.threat_id: {
                "bottomLine": r.bottom_line,
                "impact": r.impact,
                "keyEvidence": r.key_evidence,
                "recommendedFocus": r.recommended_focus,
            }
            for r in reports
        }
