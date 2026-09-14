/**
 * Seed script — populates MongoDB with the same demo data the frontend uses.
 *
 * Usage:  npm run seed       (from src/backend)
 *    or:  node src/seeds/seed.js
 */

require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../config/db');
const Alert = require('../models/Alert');
const Incident = require('../models/Incident');
const MitreTechnique = require('../models/MitreTechnique');
const Brief = require('../models/Brief');

// ── Alert seed data ──────────────────────────────────────────────────────────
const alerts = [
  {
    alertId: 'ALERT-2041', teamId: 't-soc-north',
    title: 'Potential credential theft via sensitive-account access',
    description: 'A process flagged by the endpoint agent accessed multiple sensitive credential stores within seconds. Sample evidence below. Demo record — no real compromise.',
    source: 'edr', sourceLabel: 'EDR Endpoint Agent',
    timestamp: '2026-09-14T04:12:00Z', severity: 'high', status: 'investigating',
    riskScore: 78, relatedIncidentId: 'INC-1003',
    mitreTechniques: ['T1003'], indicators: ['198.51.100.7', 'svc-backup.example'],
  },
  {
    alertId: 'ALERT-2040', teamId: 't-soc-north',
    title: 'Outbound beacon to known C2 destination',
    description: 'A workstation initiated repeated connections to a destination matching a known command-and-control feed entry. Demo record.',
    source: 'network-sensor', sourceLabel: 'Network Sensor',
    timestamp: '2026-09-14T03:48:00Z', severity: 'critical', status: 'open',
    riskScore: 92, relatedIncidentId: 'INC-1002',
    mitreTechniques: ['T1071.001'], indicators: ['203.0.113.15'],
  },
  {
    alertId: 'ALERT-2039', teamId: 't-soc-north',
    title: 'Suspicious PowerShell execution',
    description: 'PowerShell ran a deobfuscated command referencing download helper patterns. Demo record.',
    source: 'edr', sourceLabel: 'EDR Endpoint Agent',
    timestamp: '2026-09-14T02:55:00Z', severity: 'medium', status: 'open',
    riskScore: 54, relatedIncidentId: 'INC-1004',
    mitreTechniques: ['T1059.001'], indicators: ['powershell.example.invalid'],
  },
  {
    alertId: 'ALERT-2038', teamId: 't-soc-north',
    title: 'Repeated failed admin logins correlated with later success',
    description: 'Admin account experienced a burst of failed logins followed by a successful sign-in from a new location. Demo record.',
    source: 'siem', sourceLabel: 'SIEM',
    timestamp: '2026-09-14T01:20:00Z', severity: 'medium', status: 'investigating',
    riskScore: 61, relatedIncidentId: 'INC-1003',
    mitreTechniques: ['T1110'], indicators: ['198.51.100.21'],
  },
  {
    alertId: 'ALERT-2037', teamId: 't-soc-north',
    title: 'Large outbound transfer from finance host',
    description: 'A finance workstation uploaded an atypical volume of data to an external host during business hours. Demo record.',
    source: 'network-sensor', sourceLabel: 'Network Sensor',
    timestamp: '2026-09-13T22:30:00Z', severity: 'high', status: 'investigating',
    riskScore: 74, relatedIncidentId: 'INC-1002',
    mitreTechniques: ['T1567.002'], indicators: ['198.51.100.99'],
  },
  {
    alertId: 'ALERT-2036', teamId: 't-soc-north',
    title: 'Threat intel match: known malicious file hash',
    description: 'A downloaded file matched a hash from the threat intelligence feed. Demo record.',
    source: 'threat-feed', sourceLabel: 'Threat Intel Feed',
    timestamp: '2026-09-13T19:05:00Z', severity: 'high', status: 'open',
    riskScore: 81, relatedIncidentId: 'INC-1001',
    mitreTechniques: ['T1204.002'], indicators: ['d41d8cd98f00b204e9800998ecf8427e'],
  },
  {
    alertId: 'ALERT-2035', teamId: 't-soc-north',
    title: 'Login from unexpected country',
    description: 'Account signed in from a country with no prior activity. Often benign — queued for false-positive review. Demo record.',
    source: 'siem', sourceLabel: 'SIEM',
    timestamp: '2026-09-13T17:42:00Z', severity: 'low', status: 'open',
    riskScore: 33, relatedIncidentId: 'INC-1003',
    mitreTechniques: ['T1078'], indicators: ['198.51.100.55'],
  },
  {
    alertId: 'ALERT-2034', teamId: 't-soc-north',
    title: 'Login from unexpected country',
    description: 'Two-factor authentication confirmed the user. Reviewed and marked as a false positive. Demo record.',
    source: 'siem', sourceLabel: 'SIEM',
    timestamp: '2026-09-13T14:11:00Z', severity: 'low', status: 'false-positive',
    riskScore: 22, relatedIncidentId: null,
    mitreTechniques: ['T1078'], indicators: ['203.0.113.81'],
  },
  {
    alertId: 'ALERT-2033', teamId: 't-soc-north',
    title: 'Email attachment dropped suspicious payload',
    description: 'A sandboxed email attachment executed and dropped a payload matching malware patterns. Demo record.',
    source: 'threat-feed', sourceLabel: 'Threat Intel Feed',
    timestamp: '2026-09-13T11:40:00Z', severity: 'critical', status: 'investigating',
    riskScore: 89, relatedIncidentId: 'INC-1001',
    mitreTechniques: ['T1204.001', 'T1566.001'], indicators: ['e2fc714c4727ee9395f324cd2e7f331f'],
  },
  {
    alertId: 'ALERT-2032', teamId: 't-soc-north',
    title: 'Registry persistence modification',
    description: 'Registry run-key modified on a server without a change request. Demo record.',
    source: 'edr', sourceLabel: 'EDR Endpoint Agent',
    timestamp: '2026-09-13T09:02:00Z', severity: 'medium', status: 'resolved',
    riskScore: 46, relatedIncidentId: 'INC-1004',
    mitreTechniques: ['T1547.001'], indicators: ['svc-monitor.example'],
  },
  {
    alertId: 'ALERT-2031', teamId: 't-soc-north',
    title: 'SQL injection attempt on web application',
    description: 'IDS flagged token patterns consistent with SQL injection in requests to a public web app. Demo record.',
    source: 'network-sensor', sourceLabel: 'Network Sensor',
    timestamp: '2026-09-12T23:15:00Z', severity: 'medium', status: 'open',
    riskScore: 58, relatedIncidentId: 'INC-1001',
    mitreTechniques: ['T1190'], indicators: ['198.51.100.201'],
  },
  {
    alertId: 'ALERT-2030', teamId: 't-soc-north',
    title: 'Unknown USB device connected',
    description: 'A previously unseen USB device was attached to a workstation. Queued for false-positive review. Demo record.',
    source: 'edr', sourceLabel: 'EDR Endpoint Agent',
    timestamp: '2026-09-12T18:47:00Z', severity: 'low', status: 'open',
    riskScore: 29, relatedIncidentId: null,
    mitreTechniques: ['T1091'], indicators: ['vendor:acme-example'],
  },
  {
    alertId: 'ALERT-2029', teamId: 't-soc-north',
    title: 'Certificate anomaly detected',
    description: 'A certificate with unusual validity windows was observed in TLS traffic and later explained by a scheduled rotation. Demo record.',
    source: 'siem', sourceLabel: 'SIEM',
    timestamp: '2026-09-12T13:33:00Z', severity: 'low', status: 'resolved',
    riskScore: 25, relatedIncidentId: null,
    mitreTechniques: ['T1573'], indicators: ['cert.example'],
  },
  {
    alertId: 'ALERT-2028', teamId: 't-soc-north',
    title: 'Ransomware signature block attempted',
    description: 'Endpoint protection blocked an encryption routine matching a known ransomware family. Demo record.',
    source: 'edr', sourceLabel: 'EDR Endpoint Agent',
    timestamp: '2026-09-12T08:10:00Z', severity: 'critical', status: 'resolved',
    riskScore: 88, relatedIncidentId: null,
    mitreTechniques: ['T1486'], indicators: ['329102f8a10d1fd0b9a148e6a19f99fe'],
  },
];

// ── Incident seed data ───────────────────────────────────────────────────────
const incidents = [
  {
    incidentId: 'INC-1001',
    title: 'Malware delivery via email campaign',
    summary: 'A sandboxed attachment dropped a payload whose hash matched the threat feed, followed by probing of a public web application.',
    severity: 'critical', status: 'investigating', confidence: 82,
    openedAt: '2026-09-13T11:52:00Z', updatedAt: '2026-09-13T19:05:00Z',
    alertIds: ['ALERT-2033', 'ALERT-2036', 'ALERT-2031'],
    mitreTechniques: ['T1204.001', 'T1566.001', 'T1204.002', 'T1190'],
  },
  {
    incidentId: 'INC-1002',
    title: 'Command & control beaconing',
    summary: 'Beacon-like traffic to a known C2 destination and a large outbound transfer from a related finance host.',
    severity: 'critical', status: 'active', confidence: 91,
    openedAt: '2026-09-14T00:06:00Z', updatedAt: '2026-09-14T03:48:00Z',
    alertIds: ['ALERT-2040', 'ALERT-2037'],
    mitreTechniques: ['T1071.001', 'T1567.002'],
  },
  {
    incidentId: 'INC-1003',
    title: 'Credential access cluster',
    summary: 'Brute-force burst, a successful sign-in from a new location, and access to sensitive credential stores around the same account.',
    severity: 'high', status: 'investigating', confidence: 76,
    openedAt: '2026-09-13T18:02:00Z', updatedAt: '2026-09-14T04:12:00Z',
    alertIds: ['ALERT-2041', 'ALERT-2038', 'ALERT-2035'],
    mitreTechniques: ['T1003', 'T1110', 'T1078'],
  },
  {
    incidentId: 'INC-1004',
    title: 'Persistence setup on endpoints',
    summary: 'Deobfuscated script execution followed by a registry run-key change on the same endpoints, consistent with a persistence attempt.',
    severity: 'medium', status: 'resolved', confidence: 68,
    openedAt: '2026-09-13T09:10:00Z', updatedAt: '2026-09-14T02:55:00Z',
    alertIds: ['ALERT-2039', 'ALERT-2032'],
    mitreTechniques: ['T1059.001', 'T1547.001'],
  },
];

// ── MITRE technique seed data ────────────────────────────────────────────────
const techniques = [
  { techniqueId: 'T1190', name: 'Exploit Public-Facing Application', tactics: ['Initial Access'], description: 'Adversaries exploit a vulnerability in an internet-facing application to gain initial access.', url: 'https://attack.mitre.org/techniques/T1190/' },
  { techniqueId: 'T1204.001', name: 'User Execution: Malicious Link', tactics: ['Execution'], description: 'Adversaries rely on a user clicking a malicious link that leads to code execution.', url: 'https://attack.mitre.org/techniques/T1204/001/' },
  { techniqueId: 'T1204.002', name: 'User Execution: Malicious File', tactics: ['Execution'], description: 'Adversaries rely on a user opening and executing a malicious file.', url: 'https://attack.mitre.org/techniques/T1204/002/' },
  { techniqueId: 'T1566.001', name: 'Phishing: Spearphishing Attachment', tactics: ['Initial Access'], description: 'Adversaries deliver a spearphishing email carrying a malicious attachment.', url: 'https://attack.mitre.org/techniques/T1566/001/' },
  { techniqueId: 'T1059.001', name: 'Command and Scripting Interpreter: PowerShell', tactics: ['Execution'], description: 'Adversaries abuse PowerShell to execute commands or scripts.', url: 'https://attack.mitre.org/techniques/T1059/001/' },
  { techniqueId: 'T1078', name: 'Valid Accounts', tactics: ['Defense Evasion', 'Initial Access', 'Persistence', 'Privilege Escalation'], description: 'Adversaries obtain and use legitimately assigned credentials.', url: 'https://attack.mitre.org/techniques/T1078/' },
  { techniqueId: 'T1110', name: 'Brute Force', tactics: ['Credential Access'], description: 'Adversaries repeatedly test candidate credentials until a login succeeds.', url: 'https://attack.mitre.org/techniques/T1110/' },
  { techniqueId: 'T1003', name: 'OS Credential Dumping', tactics: ['Credential Access'], description: 'Adversaries extract credentials from OS stores or memory.', url: 'https://attack.mitre.org/techniques/T1003/' },
  { techniqueId: 'T1547.001', name: 'Boot or Logon Autostart Execution: Registry Run Keys', tactics: ['Persistence'], description: 'Adversaries add entries to registry Run keys for persistence.', url: 'https://attack.mitre.org/techniques/T1547/001/' },
  { techniqueId: 'T1091', name: 'Replication Through Removable Media', tactics: ['Lateral Movement'], description: 'Adversaries copy malware to removable media for execution on other systems.', url: 'https://attack.mitre.org/techniques/T1091/' },
  { techniqueId: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', tactics: ['Command and Control'], description: 'Adversaries communicate with a controller over HTTP/HTTPS.', url: 'https://attack.mitre.org/techniques/T1071/001/' },
  { techniqueId: 'T1573', name: 'Encrypted Channel', tactics: ['Command and Control'], description: 'Adversaries encrypt C2 traffic to conceal it from inspection.', url: 'https://attack.mitre.org/techniques/T1573/' },
  { techniqueId: 'T1567.002', name: 'Exfiltration Over Web Service: Exfiltration to Cloud Storage', tactics: ['Exfiltration'], description: 'Adversaries exfiltrate data to cloud storage services.', url: 'https://attack.mitre.org/techniques/T1567/002/' },
  { techniqueId: 'T1486', name: 'Data Encrypted for Impact', tactics: ['Impact'], description: 'Adversaries encrypt data on target systems (ransomware).', url: 'https://attack.mitre.org/techniques/T1486/' },
];

// ── Brief seed data ──────────────────────────────────────────────────────────
const briefs = [
  {
    incidentId: 'INC-1001',
    bottomLine: 'A spearphishing attachment dropped a payload whose file hash matches the threat feed; treat the affected host as potentially compromised.',
    impact: 'Two exposure points: a user-executed payload and follow-on probing of the public web app, suggesting the attacker is mapping the perimeter.',
    keyEvidence: [
      'ALERT-2033 — email attachment dropped a sandboxed payload',
      'ALERT-2036 — downloaded file hash matched the threat intel feed',
      'ALERT-2031 — SQL-injection probing against the public web app',
    ],
    recommendedFocus: 'Confirm which user opened the attachment, quarantine the affected host, and review web-app logs for the probe window.',
  },
  {
    incidentId: 'INC-1002',
    bottomLine: 'A workstation is beaconing to a known C2 destination and a finance host performed a large outbound transfer consistent with data staging.',
    impact: 'If C2 is confirmed the attacker already holds a foothold; the finance-host exfil pattern makes data loss the primary risk.',
    keyEvidence: [
      'ALERT-2040 — repeated outbound beacon to 203.0.113.15',
      'ALERT-2037 — large outbound transfer from a finance host',
    ],
    recommendedFocus: 'Block the destination at the egress, isolate the beaconing host, and account for the finance-host transfer volume.',
  },
  {
    incidentId: 'INC-1003',
    bottomLine: 'A single admin credential shows a brute-force burst, a successful sign-in from a new location, and access to sensitive credential stores — a probable credential theft.',
    impact: 'A single compromised admin account could unlock the identity infrastructure, so the blast radius is broad.',
    keyEvidence: [
      'ALERT-2038 — failed-then-successful admin login',
      'ALERT-2035 — login from an unexpected country',
      'ALERT-2041 — access to sensitive credential stores',
    ],
    recommendedFocus: 'Force a password reset, review MFA configuration, and correlate the credential-store access with recent authentication logs.',
  },
  {
    incidentId: 'INC-1004',
    bottomLine: 'Deobfuscated script execution followed by a registry run-key change on the same endpoints is consistent with a persistence attempt; it was contained and marked resolved.',
    impact: 'Residual malware could survive reboots if the run-key change was not fully reverted on every affected host.',
    keyEvidence: [
      'ALERT-2039 — deobfuscated PowerShell execution',
      'ALERT-2032 — registry run-key modification',
    ],
    recommendedFocus: 'Audit registry run keys across the fleet, confirm the reported reverted change, and extend log retention on the affected endpoints.',
  },
];

// ── Run ──────────────────────────────────────────────────────────────────────
async function seed() {
  await connectDB();

  console.log('🗑️  Clearing existing data…');
  await Promise.all([
    Alert.deleteMany({}),
    Incident.deleteMany({}),
    MitreTechnique.deleteMany({}),
    Brief.deleteMany({}),
  ]);

  console.log('🌱 Seeding alerts…');
  await Alert.insertMany(alerts);

  console.log('🌱 Seeding incidents…');
  await Incident.insertMany(incidents);

  console.log('🌱 Seeding MITRE techniques…');
  await MitreTechnique.insertMany(techniques);

  console.log('🌱 Seeding analyst briefs…');
  await Brief.insertMany(briefs);

  console.log('✅ Database seeded successfully!');
  await mongoose.connection.close();
  process.exit(0);
}

seed().catch((err) => {
  console.error('❌ Seed failed:', err);
  process.exit(1);
});
