import type { Alert, SystemStatus, TrendPoint, TrendRange } from '../types/alert'

/**
 * Simulated demo alerts. Clearly fictional — no real security event data.
 *
 * Indicators use reserved, non-routable example values:
 *   - 203.0.113.x / 198.51.100.x — TEST-NET ranges
 *   - *.example / *.invalid domains
 *   - well-known public hash values only
 */

export const trendData: Record<TrendRange, TrendPoint[]> = {
  '24h': [
    { label: '00:00', alerts: 42, incidents: 3 },
    { label: '04:00', alerts: 28, incidents: 2 },
    { label: '08:00', alerts: 61, incidents: 5 },
    { label: '12:00', alerts: 74, incidents: 6 },
    { label: '16:00', alerts: 67, incidents: 5 },
    { label: '20:00', alerts: 83, incidents: 7 },
  ],
  '7d': [
    { label: 'Mon', alerts: 612, incidents: 34 },
    { label: 'Tue', alerts: 540, incidents: 29 },
    { label: 'Wed', alerts: 683, incidents: 41 },
    { label: 'Thu', alerts: 498, incidents: 26 },
    { label: 'Fri', alerts: 746, incidents: 44 },
    { label: 'Sat', alerts: 422, incidents: 23 },
    { label: 'Sun', alerts: 388, incidents: 21 },
  ],
  '30d': [
    { label: 'W1', alerts: 3900, incidents: 168 },
    { label: 'W2', alerts: 4210, incidents: 185 },
    { label: 'W3', alerts: 3540, incidents: 152 },
    { label: 'W4', alerts: 4480, incidents: 201 },
  ],
}

export const systemStatus: SystemStatus[] = [
  { id: 'siem', name: 'SIEM ingestion', detail: 'QRadar · healthy · 12s lag', health: 'healthy' },
  { id: 'edr', name: 'Endpoint detection', detail: 'All agents reporting', health: 'healthy' },
  {
    id: 'network',
    name: 'Network sensors',
    detail: 'Segment 4 degraded · 1 sensor offline',
    health: 'degraded',
  },
  {
    id: 'threatintel',
    name: 'Threat intel feed',
    detail: 'Last update 3 min ago',
    health: 'healthy',
  },
  {
    id: 'correlation',
    name: 'Correlation engine',
    detail: 'Jobs running normally',
    health: 'operational',
  },
]

export const mockAlerts: Alert[] = [
  {
    id: 'ALERT-2041',
    teamId: 't-soc-north',
    title: 'Potential credential theft via sensitive-account access',
    description:
      'A process flagged by the endpoint agent accessed multiple sensitive credential stores within seconds. Sample evidence below. Demo record — no real compromise.',
    source: 'edr',
    sourceLabel: 'EDR Endpoint Agent',
    timestamp: '2026-09-14T04:12:00Z',
    severity: 'high',
    status: 'investigating',
    riskScore: 78,
    relatedIncidentId: 'INC-1003',
    mitreTechniques: ['T1003'],
    indicators: ['198.51.100.7', 'svc-backup.example'],
  },
  {
    id: 'ALERT-2040',
    teamId: 't-soc-north',
    title: 'Outbound beacon to known C2 destination',
    description:
      'A workstation initiated repeated connections to a destination matching a known command-and-control feed entry. Demo record.',
    source: 'network-sensor',
    sourceLabel: 'Network Sensor',
    timestamp: '2026-09-14T03:48:00Z',
    severity: 'critical',
    status: 'open',
    riskScore: 92,
    relatedIncidentId: 'INC-1002',
    mitreTechniques: ['T1071.001'],
    indicators: ['203.0.113.15'],
  },
  {
    id: 'ALERT-2039',
    teamId: 't-soc-north',
    title: 'Suspicious PowerShell execution',
    description:
      'PowerShell ran a deobfuscated command referencing download helper patterns. Demo record.',
    source: 'edr',
    sourceLabel: 'EDR Endpoint Agent',
    timestamp: '2026-09-14T02:55:00Z',
    severity: 'medium',
    status: 'open',
    riskScore: 54,
    relatedIncidentId: 'INC-1004',
    mitreTechniques: ['T1059.001'],
    indicators: ['powershell.example.invalid'],
  },
  {
    id: 'ALERT-2038',
    teamId: 't-soc-north',
    title: 'Repeated failed admin logins correlated with later success',
    description:
      'Admin account experienced a burst of failed logins followed by a successful sign-in from a new location. Demo record.',
    source: 'siem',
    sourceLabel: 'SIEM',
    timestamp: '2026-09-14T01:20:00Z',
    severity: 'medium',
    status: 'investigating',
    riskScore: 61,
    relatedIncidentId: 'INC-1003',
    mitreTechniques: ['T1110'],
    indicators: ['198.51.100.21'],
  },
  {
    id: 'ALERT-2037',
    teamId: 't-soc-north',
    title: 'Large outbound transfer from finance host',
    description:
      'A finance workstation uploaded an atypical volume of data to an external host during business hours. Demo record.',
    source: 'network-sensor',
    sourceLabel: 'Network Sensor',
    timestamp: '2026-09-13T22:30:00Z',
    severity: 'high',
    status: 'investigating',
    riskScore: 74,
    relatedIncidentId: 'INC-1002',
    mitreTechniques: ['T1567.002'],
    indicators: ['198.51.100.99'],
  },
  {
    id: 'ALERT-2036',
    teamId: 't-soc-north',
    title: 'Threat intel match: known malicious file hash',
    description:
      'A downloaded file matched a hash from the threat intelligence feed. Demo record.',
    source: 'threat-feed',
    sourceLabel: 'Threat Intel Feed',
    timestamp: '2026-09-13T19:05:00Z',
    severity: 'high',
    status: 'open',
    riskScore: 81,
    relatedIncidentId: 'INC-1001',
    mitreTechniques: ['T1204.002'],
    indicators: ['d41d8cd98f00b204e9800998ecf8427e'],
  },
  {
    id: 'ALERT-2035',
    teamId: 't-soc-north',
    title: 'Login from unexpected country',
    description:
      'Account signed in from a country with no prior activity. Often benign — queued for false-positive review. Demo record.',
    source: 'siem',
    sourceLabel: 'SIEM',
    timestamp: '2026-09-13T17:42:00Z',
    severity: 'low',
    status: 'open',
    riskScore: 33,
    relatedIncidentId: 'INC-1003',
    mitreTechniques: ['T1078'],
    indicators: ['198.51.100.55'],
  },
  {
    id: 'ALERT-2034',
    teamId: 't-soc-north',
    title: 'Login from unexpected country',
    description:
      'Two-factor authentication confirmed the user. Reviewed and marked as a false positive. Demo record.',
    source: 'siem',
    sourceLabel: 'SIEM',
    timestamp: '2026-09-13T14:11:00Z',
    severity: 'low',
    status: 'false-positive',
    riskScore: 22,
    relatedIncidentId: null,
    mitreTechniques: ['T1078'],
    indicators: ['203.0.113.81'],
  },
  {
    id: 'ALERT-2033',
    teamId: 't-soc-north',
    title: 'Email attachment dropped suspicious payload',
    description:
      'A sandboxed email attachment executed and dropped a payload matching malware patterns. Demo record.',
    source: 'threat-feed',
    sourceLabel: 'Threat Intel Feed',
    timestamp: '2026-09-13T11:40:00Z',
    severity: 'critical',
    status: 'investigating',
    riskScore: 89,
    relatedIncidentId: 'INC-1001',
    mitreTechniques: ['T1204.001', 'T1566.001'],
    indicators: ['e2fc714c4727ee9395f324cd2e7f331f'],
  },
  {
    id: 'ALERT-2032',
    teamId: 't-soc-north',
    title: 'Registry persistence modification',
    description:
      'Registry run-key modified on a server without a change request. Demo record.',
    source: 'edr',
    sourceLabel: 'EDR Endpoint Agent',
    timestamp: '2026-09-13T09:02:00Z',
    severity: 'medium',
    status: 'resolved',
    riskScore: 46,
    relatedIncidentId: 'INC-1004',
    mitreTechniques: ['T1547.001'],
    indicators: ['svc-monitor.example'],
  },
  {
    id: 'ALERT-2031',
    teamId: 't-soc-north',
    title: 'SQL injection attempt on web application',
    description:
      'IDS flagged token patterns consistent with SQL injection in requests to a public web app. Demo record.',
    source: 'network-sensor',
    sourceLabel: 'Network Sensor',
    timestamp: '2026-09-12T23:15:00Z',
    severity: 'medium',
    status: 'open',
    riskScore: 58,
    relatedIncidentId: 'INC-1001',
    mitreTechniques: ['T1190'],
    indicators: ['198.51.100.201'],
  },
  {
    id: 'ALERT-2030',
    teamId: 't-soc-north',
    title: 'Unknown USB device connected',
    description:
      'A previously unseen USB device was attached to a workstation. Queued for false-positive review. Demo record.',
    source: 'edr',
    sourceLabel: 'EDR Endpoint Agent',
    timestamp: '2026-09-12T18:47:00Z',
    severity: 'low',
    status: 'open',
    riskScore: 29,
    relatedIncidentId: null,
    mitreTechniques: ['T1091'],
    indicators: ['vendor:acme-example'],
  },
  {
    id: 'ALERT-2029',
    teamId: 't-soc-north',
    title: 'Certificate anomaly detected',
    description:
      'A certificate with unusual validity windows was observed in TLS traffic and later explained by a scheduled rotation. Demo record.',
    source: 'siem',
    sourceLabel: 'SIEM',
    timestamp: '2026-09-12T13:33:00Z',
    severity: 'low',
    status: 'resolved',
    riskScore: 25,
    relatedIncidentId: null,
    mitreTechniques: ['T1573'],
    indicators: ['cert.example'],
  },
  {
    id: 'ALERT-2028',
    teamId: 't-soc-north',
    title: 'Ransomware signature block attempted',
    description:
      'Endpoint protection blocked an encryption routine matching a known ransomware family. Demo record.',
    source: 'edr',
    sourceLabel: 'EDR Endpoint Agent',
    timestamp: '2026-09-12T08:10:00Z',
    severity: 'critical',
    status: 'resolved',
    riskScore: 88,
    relatedIncidentId: null,
    mitreTechniques: ['T1486'],
    indicators: ['329102f8a10d1fd0b9a148e6a19f99fe'],
  },
]

export const incidentTitles: Record<string, string> = {
  'INC-1001': 'Malware delivery via email campaign',
  'INC-1002': 'Command & control beaconing',
  'INC-1003': 'Credential access cluster',
  'INC-1004': 'Persistence setup on endpoints',
}

export const incidentExplanations: Record<string, string> = {
  'INC-1001':
    'These alerts share the same delivery campaign: a malicious attachment, a matching file hash from the threat feed, and follow-on requests to a public-facing web application. Demo correlation, not a real finding.',
  'INC-1002':
    'These alerts describe beacon-like behaviour to the same destination and a large outbound transfer from a related host. The shared destination and timing bind them together. Demo correlation, not a real finding.',
  'INC-1003':
    'These alerts centre on the same set of credentials — a brute-force burst, a successful sign-in from a new location, and access to sensitive credential stores. Demo correlation, not a real finding.',
  'INC-1004':
    'These alerts show script execution and a registry run-key change on the same endpoints, consistent with a persistence attempt. Demo correlation, not a real finding.',
}