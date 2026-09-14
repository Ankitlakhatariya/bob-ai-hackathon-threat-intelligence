from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.mitre import MitreTechnique, MitreTactic

# Verified MITRE ATT&CK dataset (14 standard techniques from frontend mockMitre.ts)
STANDARD_TECHNIQUES = [
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactics": ["Initial Access"],
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program using software, system, or service bugs to cause unintended or unanticipated behavior.",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    {
        "id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "tactics": ["Initial Access"],
        "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
    },
    {
        "id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactics": ["Execution"],
        "description": "Adversaries may abuse PowerShell commands and scripts for execution on compromised Windows systems.",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    {
        "id": "T1204.002",
        "name": "User Execution: Malicious File",
        "tactics": ["Execution"],
        "description": "An adversary may rely upon specific actions by a user, such as opening a malicious file, to gain execution on a system.",
        "url": "https://attack.mitre.org/techniques/T1204/002/",
    },
    {
        "id": "T1204.001",
        "name": "User Execution: Malicious Link",
        "tactics": ["Execution"],
        "description": "An adversary may rely upon specific actions by a user, such as clicking a malicious link, to gain execution on a system.",
        "url": "https://attack.mitre.org/techniques/T1204/001/",
    },
    {
        "id": "T1053.005",
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactics": ["Execution", "Persistence", "Privilege Escalation"],
        "description": "Adversaries may abuse task scheduling functionality in Windows to execute programs at system startup or on a scheduled basis for persistence.",
        "url": "https://attack.mitre.org/techniques/T1053/005/",
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactics": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactics": ["Credential Access"],
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software.",
        "url": "https://attack.mitre.org/techniques/T1003/",
    },
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactics": ["Credential Access"],
        "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes are obtained.",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    {
        "id": "T1021.002",
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactics": ["Lateral Movement"],
        "description": "Adversaries may use valid accounts to interact with remote network shares over Server Message Block (SMB) to move laterally.",
        "url": "https://attack.mitre.org/techniques/T1021/002/",
    },
    {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactics": ["Command and Control"],
        "description": "Adversaries may communicate using application layer protocols (HTTP, HTTPS) to blend into existing traffic and avoid network filtering.",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    {
        "id": "T1573.002",
        "name": "Encrypted Channel: Asymmetric Cryptography",
        "tactics": ["Command and Control"],
        "description": "Adversaries may employ asymmetric cryptographic algorithms to encrypt Command and Control traffic to hide communication patterns.",
        "url": "https://attack.mitre.org/techniques/T1573/002/",
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactics": ["Exfiltration"],
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel rather than creating an additional network connection.",
        "url": "https://attack.mitre.org/techniques/T1041/",
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactics": ["Impact"],
        "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.",
        "url": "https://attack.mitre.org/techniques/T1486/",
    },
]


class MitreService:
    @classmethod
    async def get_all_techniques(cls, db: AsyncSession, tactic: Optional[str] = None) -> List[MitreTechnique]:
        stmt = select(MitreTechnique)
        result = await db.execute(stmt)
        techniques = list(result.scalars().all())

        if not techniques:
            # Seed standard techniques if database table is currently empty
            for tech_data in STANDARD_TECHNIQUES:
                tech = MitreTechnique(**tech_data)
                db.add(tech)
            await db.commit()
            stmt = select(MitreTechnique)
            result = await db.execute(stmt)
            techniques = list(result.scalars().all())

        if tactic and tactic.lower() != "all":
            techniques = [t for t in techniques if any(tactic.lower() == tac.lower() for tac in t.tactics)]

        return techniques

    @classmethod
    async def get_technique_by_id(cls, db: AsyncSession, technique_id: str) -> Optional[MitreTechnique]:
        return await db.get(MitreTechnique, technique_id)
