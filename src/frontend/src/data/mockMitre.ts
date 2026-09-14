/**
 * MITRE ATT&CK technique catalogue for the demo explorer.
 *
 * Technique IDs, names, and tactic assignments below are verified against the
 * public MITRE ATT&CK knowledge base (attack.mitre.org). Descriptions are
 * short paraphrases for display only.
 *
 * IMPORTANT: Relationships between these techniques and alerts/incidents are
 * DEMO mappings until the AI/backend team supplies real technique detection.
 */

export type MitreTactic =
  | 'Execution'
  | 'Initial Access'
  | 'Credential Access'
  | 'Persistence'
  | 'Privilege Escalation'
  | 'Defense Evasion'
  | 'Command and Control'
  | 'Exfiltration'
  | 'Lateral Movement'
  | 'Impact'

export interface MitreTechnique {
  id: string
  name: string
  tactics: MitreTactic[]
  description: string
  url: string
}

/** Techniques referenced by the sample alerts, ordered for the explorer. */
export const mitreTechniques: MitreTechnique[] = [
  {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactics: ['Initial Access'],
    description:
      'Adversaries exploit a vulnerability in an internet-facing application, such as a web portal or database, to gain initial access to the environment.',
    url: 'https://attack.mitre.org/techniques/T1190/',
  },
  {
    id: 'T1204.001',
    name: 'User Execution: Malicious Link',
    tactics: ['Execution'],
    description:
      'Adversaries rely on a user clicking a malicious link that leads to code execution on the victim system.',
    url: 'https://attack.mitre.org/techniques/T1204/001/',
  },
  {
    id: 'T1204.002',
    name: 'User Execution: Malicious File',
    tactics: ['Execution'],
    description:
      'Adversaries rely on a user opening and executing a malicious file, such as a document or script, that was delivered to them.',
    url: 'https://attack.mitre.org/techniques/T1204/002/',
  },
  {
    id: 'T1566.001',
    name: 'Phishing: Spearphishing Attachment',
    tactics: ['Initial Access'],
    description:
      'Adversaries deliver a spearphishing email carrying a malicious attachment that the target is encouraged to open.',
    url: 'https://attack.mitre.org/techniques/T1566/001/',
  },
  {
    id: 'T1059.001',
    name: 'Command and Scripting Interpreter: PowerShell',
    tactics: ['Execution'],
    description:
      'Adversaries abuse PowerShell to execute commands, scripts, or compiled code on a victim system.',
    url: 'https://attack.mitre.org/techniques/T1059/001/',
  },
  {
    id: 'T1078',
    name: 'Valid Accounts',
    tactics: ['Defense Evasion', 'Initial Access', 'Persistence', 'Privilege Escalation'],
    description:
      'Adversaries obtain and use legitimately assigned credentials to access systems, blending in with valid user behaviour to evade detection.',
    url: 'https://attack.mitre.org/techniques/T1078/',
  },
  {
    id: 'T1110',
    name: 'Brute Force',
    tactics: ['Credential Access'],
    description:
      'Adversaries repeatedly and systematically test candidate credentials against accounts or services until a login succeeds.',
    url: 'https://attack.mitre.org/techniques/T1110/',
  },
  {
    id: 'T1003',
    name: 'OS Credential Dumping',
    tactics: ['Credential Access'],
    description:
      'Adversaries extract credentials such as password hashes or cleartext secrets from operating-system stores, applications, or memory.',
    url: 'https://attack.mitre.org/techniques/T1003/',
  },
  {
    id: 'T1547.001',
    name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder',
    tactics: ['Persistence'],
    description:
      'Adversaries add entries to registry Run keys or the Startup folder so their code executes each time the system boots or a user logs on.',
    url: 'https://attack.mitre.org/techniques/T1547/001/',
  },
  {
    id: 'T1091',
    name: 'Replication Through Removable Media',
    tactics: ['Lateral Movement'],
    description:
      'Adversaries copy malware to removable media and later execute it on another system when that media is connected.',
    url: 'https://attack.mitre.org/techniques/T1091/',
  },
  {
    id: 'T1071.001',
    name: 'Application Layer Protocol: Web Protocols',
    tactics: ['Command and Control'],
    description:
      'Adversaries communicate with a controller over standard web protocols such as HTTP and HTTPS to blend in with normal traffic.',
    url: 'https://attack.mitre.org/techniques/T1071/001/',
  },
  {
    id: 'T1573',
    name: 'Encrypted Channel',
    tactics: ['Command and Control'],
    description:
      'Adversaries encrypt command-and-control traffic to conceal it from network inspection.',
    url: 'https://attack.mitre.org/techniques/T1573/',
  },
  {
    id: 'T1567.002',
    name: 'Exfiltration Over Web Service: Exfiltration to Cloud Storage',
    tactics: ['Exfiltration'],
    description:
      'Adversaries exfiltrate data to a cloud-storage or file-sharing service to move data out while avoiding network-monitoring controls.',
    url: 'https://attack.mitre.org/techniques/T1567/002/',
  },
  {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    tactics: ['Impact'],
    description:
      'Adversaries encrypt data on target systems to disrupt availability, as seen in ransomware operations.',
    url: 'https://attack.mitre.org/techniques/T1486/',
  },
]