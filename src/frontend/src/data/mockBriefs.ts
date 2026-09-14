/**
 * BLUF (Bottom Line Up Front) demo brief content, keyed by incident ID.
 *
 * All text is simulated for the demo. It paraphrases the sample incidents in
 * `src/data/mockIncidents.ts` so cards stay consistent with the rest of the
 * product. The AI/backend team will replace these with generated briefs.
 */

export interface MitreBrief {
  bottomLine: string
  impact: string
  keyEvidence: string[]
  recommendedFocus: string
}

export const mockBriefs: Record<string, MitreBrief> = {
  'INC-1001': {
    bottomLine:
      'A spearphishing attachment dropped a payload whose file hash matches the threat feed; treat the affected host as potentially compromised.',
    impact:
      'Two exposure points: a user-executed payload and follow-on probing of the public web app, suggesting the attacker is mapping the perimeter.',
    keyEvidence: [
      'ALERT-2033 — email attachment dropped a sandboxed payload',
      'ALERT-2036 — downloaded file hash matched the threat intel feed',
      'ALERT-2031 — SQL-injection probing against the public web app',
    ],
    recommendedFocus:
      'Confirm which user opened the attachment, quarantine the affected host, and review web-app logs for the probe window.',
  },
  'INC-1002': {
    bottomLine:
      'A workstation is beaconing to a known C2 destination and a finance host performed a large outbound transfer consistent with data staging.',
    impact:
      'If C2 is confirmed the attacker already holds a foothold; the finance-host exfil pattern makes data loss the primary risk.',
    keyEvidence: [
      'ALERT-2040 — repeated outbound beacon to 203.0.113.15',
      'ALERT-2037 — large outbound transfer from a finance host',
    ],
    recommendedFocus:
      'Block the destination at the egress, isolate the beaconing host, and account for the finance-host transfer volume.',
  },
  'INC-1003': {
    bottomLine:
      'A single admin credential shows a brute-force burst, a successful sign-in from a new location, and access to sensitive credential stores — a probable credential theft.',
    impact:
      'A single compromised admin account could unlock the identity infrastructure, so the blast radius is broad.',
    keyEvidence: [
      'ALERT-2038 — failed-then-successful admin login',
      'ALERT-2035 — login from an unexpected country',
      'ALERT-2041 — access to sensitive credential stores',
    ],
    recommendedFocus:
      'Force a password reset, review MFA configuration, and correlate the credential-store access with recent authentication logs.',
  },
  'INC-1004': {
    bottomLine:
      'Deobfuscated script execution followed by a registry run-key change on the same endpoints is consistent with a persistence attempt; it was contained and marked resolved (sample state).',
    impact:
      'Residual malware could survive reboots if the run-key change was not fully reverted on every affected host.',
    keyEvidence: [
      'ALERT-2039 — deobfuscated PowerShell execution',
      'ALERT-2032 — registry run-key modification',
    ],
    recommendedFocus:
      'Audit registry run keys across the fleet, confirm the reported reverted change, and extend log retention on the affected endpoints.',
  },
}