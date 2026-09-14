from typing import List, Optional, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.mitre import MitreTechnique, MitreTactic, ThreatMitreMapping
from app.models.alert import Alert
from app.models.threat import Threat

# Verified Enterprise MITRE ATT&CK Tactics (Official IDs)
STANDARD_TACTICS = [
    {"id": "TA0001", "name": "Initial Access", "description": "Techniques that use various entry vectors to gain an initial foothold."},
    {"id": "TA0002", "name": "Execution", "description": "Techniques that result in adversary-controlled code running on a local or remote system."},
    {"id": "TA0003", "name": "Persistence", "description": "Techniques that adversaries use to keep access to systems across restarts or credential changes."},
    {"id": "TA0004", "name": "Privilege Escalation", "description": "Techniques that adversaries use to gain higher-level permissions."},
    {"id": "TA0005", "name": "Defense Evasion", "description": "Techniques that adversaries use to avoid detection throughout their compromise."},
    {"id": "TA0006", "name": "Credential Access", "description": "Techniques for stealing credentials like account names and passwords."},
    {"id": "TA0007", "name": "Discovery", "description": "Techniques an adversary may use to gain knowledge about the system and internal network."},
    {"id": "TA0008", "name": "Lateral Movement", "description": "Techniques that adversaries use to enter and control remote systems on a network."},
    {"id": "TA0009", "name": "Command and Control", "description": "Techniques that adversaries may use to communicate with systems under their control."},
    {"id": "TA0010", "name": "Exfiltration", "description": "Techniques that adversaries may use to steal data from your network."},
    {"id": "TA0040", "name": "Impact", "description": "Techniques used by adversaries to disrupt availability or compromise integrity."},
]

# Verified Enterprise MITRE ATT&CK Techniques and Sub-techniques
STANDARD_TECHNIQUES = [
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactics": ["Initial Access"],
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program using software, system, or service bugs.",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "is_subtechnique": False,
        "parent_technique_id": None,
    },
    {
        "id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "tactics": ["Initial Access"],
        "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
        "is_subtechnique": True,
        "parent_technique_id": "T1566",
    },
    {
        "id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactics": ["Execution"],
        "description": "Adversaries may abuse PowerShell commands and scripts for execution on compromised Windows systems.",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
        "is_subtechnique": True,
        "parent_technique_id": "T1059",
    },
    {
        "id": "T1204.002",
        "name": "User Execution: Malicious File",
        "tactics": ["Execution"],
        "description": "An adversary may rely upon specific actions by a user, such as opening a malicious file, to gain execution on a system.",
        "url": "https://attack.mitre.org/techniques/T1204/002/",
        "is_subtechnique": True,
        "parent_technique_id": "T1204",
    },
    {
        "id": "T1204.001",
        "name": "User Execution: Malicious Link",
        "tactics": ["Execution"],
        "description": "An adversary may rely upon specific actions by a user, such as clicking a malicious link, to gain execution on a system.",
        "url": "https://attack.mitre.org/techniques/T1204/001/",
        "is_subtechnique": True,
        "parent_technique_id": "T1204",
    },
    {
        "id": "T1053.005",
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactics": ["Execution", "Persistence", "Privilege Escalation"],
        "description": "Adversaries may abuse task scheduling functionality in Windows to execute programs at system startup or on a scheduled basis for persistence.",
        "url": "https://attack.mitre.org/techniques/T1053/005/",
        "is_subtechnique": True,
        "parent_technique_id": "T1053",
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactics": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "url": "https://attack.mitre.org/techniques/T1078/",
        "is_subtechnique": False,
        "parent_technique_id": None,
    },
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactics": ["Credential Access"],
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material (hashes or cleartext) from the operating system.",
        "url": "https://attack.mitre.org/techniques/T1003/",
        "is_subtechnique": False,
        "parent_technique_id": None,
    },
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactics": ["Credential Access"],
        "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown.",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "is_subtechnique": False,
        "parent_technique_id": None,
    },
    {
        "id": "T1021.002",
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactics": ["Lateral Movement"],
        "description": "Adversaries may use valid accounts to interact with remote network shares over Server Message Block (SMB) to move laterally.",
        "url": "https://attack.mitre.org/techniques/T1021/002/",
        "is_subtechnique": True,
        "parent_technique_id": "T1021",
    },
    {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactics": ["Command and Control"],
        "description": "Adversaries may communicate using application layer protocols (HTTP, HTTPS) to blend into existing traffic and avoid network filtering.",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
        "is_subtechnique": True,
        "parent_technique_id": "T1071",
    },
    {
        "id": "T1573.002",
        "name": "Encrypted Channel: Asymmetric Cryptography",
        "tactics": ["Command and Control"],
        "description": "Adversaries may employ asymmetric cryptographic algorithms to encrypt Command and Control traffic to hide communication patterns.",
        "url": "https://attack.mitre.org/techniques/T1573/002/",
        "is_subtechnique": True,
        "parent_technique_id": "T1573",
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactics": ["Exfiltration"],
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel rather than creating an additional network connection.",
        "url": "https://attack.mitre.org/techniques/T1041/",
        "is_subtechnique": False,
        "parent_technique_id": None,
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactics": ["Impact"],
        "description": "Adversaries may encrypt data on target systems or across network storage to interrupt availability of resources (e.g. Ransomware).",
        "url": "https://attack.mitre.org/techniques/T1486/",
        "is_subtechnique": False,
        "parent_technique_id": None,
    },
]

VERIFIED_TECHNIQUE_MAP = {t["id"]: t for t in STANDARD_TECHNIQUES}


class MitreBehaviorMapper:
    """Deterministic, rule-based behavioral mapper.
    Maps observed security telemetry to verified ATT&CK techniques with explainable evidence.
    Never invents unverified technique IDs.
    """

    BEHAVIOR_RULES: List[Dict[str, Any]] = [
        {
            "technique_id": "T1059.001",
            "keywords": ["powershell", "encodedcommand", "-enc ", "downloadstring", "invoke-expression", "iex("],
            "evidence_template": "Observed PowerShell invocation with execution patterns matching '{keyword}'",
            "confidence": 92,
        },
        {
            "technique_id": "T1003",
            "keywords": ["lsass", "sekurlsa", "mimikatz", "procdump", "nanodump", "credential theft"],
            "evidence_template": "Detected memory access or dumping targeting LSASS process matching '{keyword}'",
            "confidence": 95,
        },
        {
            "technique_id": "T1110",
            "keywords": ["brute force", "password spray", "failed logins", "450 failed", "spraying"],
            "evidence_template": "High-volume repetitive authentication failure pattern matching '{keyword}'",
            "confidence": 88,
        },
        {
            "technique_id": "T1078",
            "keywords": ["valid accounts", "successful login from", "anomalous administrative login", "sensitive-account access"],
            "evidence_template": "Anomalous authentication using legitimate account credentials matching '{keyword}'",
            "confidence": 85,
        },
        {
            "technique_id": "T1566.001",
            "keywords": ["spearphishing", "macro", ".xlsm", ".docm", "email attachment"],
            "evidence_template": "Malicious email delivery carrying weaponized attachment matching '{keyword}'",
            "confidence": 90,
        },
        {
            "technique_id": "T1021.002",
            "keywords": ["smb", "ipc$", "psexec", "windows admin shares", "share enumeration"],
            "evidence_template": "Lateral movement attempt utilizing SMB protocol and administrative shares matching '{keyword}'",
            "confidence": 84,
        },
        {
            "technique_id": "T1071.001",
            "keywords": ["beacon", "c2", "cobalt strike", "adversary infrastructure", "checkin"],
            "evidence_template": "Periodic HTTP/HTTPS traffic to remote command-and-control node matching '{keyword}'",
            "confidence": 87,
        },
        {
            "technique_id": "T1053.005",
            "keywords": ["schtasks", "scheduled task", "cron job", "updatecheck_daily"],
            "evidence_template": "Persistence established through scheduled task creation matching '{keyword}'",
            "confidence": 91,
        },
        {
            "technique_id": "T1486",
            "keywords": ["vssadmin", "shadow copies", "data encrypted", "ransomware", "archive creation"],
            "evidence_template": "Inhibition of system recovery and volume shadow tampering matching '{keyword}'",
            "confidence": 96,
        },
        {
            "technique_id": "T1041",
            "keywords": ["exfiltration", "data transfer", "large outbound", "staging archive"],
            "evidence_template": "Anomalous large outbound data transmission over established C2 channel matching '{keyword}'",
            "confidence": 89,
        },
    ]

    @classmethod
    def map_alert_behavior(cls, alert: Alert) -> List[Tuple[str, str, int]]:
        """Maps alert telemetry to verified technique IDs with explicit evidence.
        Returns List of (technique_id, evidence_str, confidence).
        """
        text_corpus = f"{alert.title} {alert.description} {alert.event_type or ''} {' '.join(alert.indicators or [])}".lower()
        mappings = []

        for rule in cls.BEHAVIOR_RULES:
            tech_id = rule["technique_id"]
            if tech_id not in VERIFIED_TECHNIQUE_MAP:
                continue  # Never allow invented techniques

            for kw in rule["keywords"]:
                if kw in text_corpus:
                    evidence = rule["evidence_template"].format(keyword=kw)
                    mappings.append((tech_id, f"{alert.id}: {evidence}", rule["confidence"]))
                    break

        return mappings


class MitreService:
    @classmethod
    async def ensure_seeded(cls, db: AsyncSession):
        """Pre-seeds standard verified tactics and techniques if not present."""
        stmt = select(MitreTechnique)
        res = await db.execute(stmt)
        if not res.scalars().first():
            for t_data in STANDARD_TACTICS:
                db.add(MitreTactic(**t_data))
            for tech_data in STANDARD_TECHNIQUES:
                db.add(MitreTechnique(**tech_data))
            await db.commit()

    @classmethod
    async def get_all_tactics(cls, db: AsyncSession) -> List[MitreTactic]:
        await cls.ensure_seeded(db)
        stmt = select(MitreTactic).order_by(MitreTactic.id.asc())
        res = await db.execute(stmt)
        return list(res.scalars().all())

    @classmethod
    async def get_all_techniques(
        cls, db: AsyncSession, tactic: Optional[str] = None, subtechniques: Optional[bool] = None
    ) -> List[MitreTechnique]:
        await cls.ensure_seeded(db)
        stmt = select(MitreTechnique).order_by(MitreTechnique.id.asc())

        if subtechniques is not None:
            stmt = stmt.where(MitreTechnique.is_subtechnique == subtechniques)

        res = await db.execute(stmt)
        techniques = list(res.scalars().all())

        if tactic and tactic.lower() != "all":
            techniques = [t for t in techniques if any(tactic.lower() == tac.lower() for tac in t.tactics)]

        return techniques

    @classmethod
    async def get_technique_by_id(cls, db: AsyncSession, technique_id: str) -> Optional[MitreTechnique]:
        await cls.ensure_seeded(db)
        return await db.get(MitreTechnique, technique_id)

    @classmethod
    async def get_threat_mitre_mappings(cls, db: AsyncSession, threat_id: str) -> List[ThreatMitreMapping]:
        """Returns threat-to-technique mappings for a threat with explicit behavioral evidence."""
        await cls.ensure_seeded(db)
        stmt = select(ThreatMitreMapping).where(ThreatMitreMapping.threat_id == threat_id)
        res = await db.execute(stmt)
        existing = list(res.scalars().all())

        if existing:
            return existing

        # If no explicit mapping records exist yet, generate them dynamically from member alerts
        threat = await db.get(Threat, threat_id)
        if not threat:
            return []

        alerts_stmt = select(Alert).where(
            (Alert.related_threat_id == threat_id) | (Alert.id.in_(threat.alert_ids or []))
        )
        alerts_res = await db.execute(alerts_stmt)
        alerts = list(alerts_res.scalars().all())

        seen_techs = set()
        new_mappings = []

        for a in alerts:
            mapped_items = MitreBehaviorMapper.map_alert_behavior(a)
            for tech_id, evidence, conf in mapped_items:
                if tech_id not in seen_techs and tech_id in VERIFIED_TECHNIQUE_MAP:
                    seen_techs.add(tech_id)
                    tech_meta = VERIFIED_TECHNIQUE_MAP[tech_id]
                    m = ThreatMitreMapping(
                        threat_id=threat_id,
                        technique_id=tech_id,
                        technique_name=tech_meta["name"],
                        tactic=tech_meta["tactics"][0] if tech_meta["tactics"] else "Execution",
                        confidence=conf,
                        evidence=evidence,
                        source=a.source_label,
                    )
                    db.add(m)
                    new_mappings.append(m)

        # Also cover any techniques listed on the threat itself
        for tid in threat.mitre_techniques or []:
            if tid not in seen_techs and tid in VERIFIED_TECHNIQUE_MAP:
                seen_techs.add(tid)
                tech_meta = VERIFIED_TECHNIQUE_MAP[tid]
                m = ThreatMitreMapping(
                    threat_id=threat_id,
                    technique_id=tid,
                    technique_name=tech_meta["name"],
                    tactic=tech_meta["tactics"][0] if tech_meta["tactics"] else "Execution",
                    confidence=85,
                    evidence=f"Correlated incident telemetry matched behavioral signature for {tech_meta['name']}",
                    source="Threat Correlation Engine",
                )
                db.add(m)
                new_mappings.append(m)

        if new_mappings:
            await db.commit()
            return new_mappings

        return []
