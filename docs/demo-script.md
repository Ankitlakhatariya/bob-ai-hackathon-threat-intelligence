# ThreatLens — 3–5 minute demo script

Use this walkthrough for live judging and as the storyboard for the demo video
(`demo/demo-video-link.txt`). It follows the D2 problem end to end: alert
overload → correlation → prioritisation → investigation → reporting → analytics.

## Before you start

- Run locally: `npm install` then `npm run dev` in `src/frontend`, open
  `http://localhost:5173`.
- Use a logged-out browser tab if needed (refresh to replay).
- All data is simulated. Say this once up front; the UI labels it throughout.
- These numbers are illustrative and consistent across pages; do not quote them
  as real security facts.

## The story in one line

> ThreatLens turns a flood of raw alerts into a small set of correlated,
> risk-ranked incidents that an analyst can actually act on — and shows the
> paperwork that proves it.

## Screen by screen

| Time | Screen / route | Action & narration |
| --- | --- | --- |
| 00:00 | Landing (`/`) | "Security teams drown in alerts while real threats hide in the noise — that's the problem we're solving." Click **Launch demo**. |
| 00:20 | Login (`/login`) | Click **Use demo access (simulated)** — no credentials involved. "Authentication is simulated so judges can get straight to the product." |
| 00:30 | Dashboard (`/dashboard`) | "One pane with what matters first: open alerts, critical count, correlated incidents, and the false-positive review queue." Switch the trend range from **Last 24h** to **Last 7 days** to show the selector is live. Hover the charts to show tooltips. |
| 01:00 | Alerts (`/alerts`) | "Here's the raw load — searchable and filterable by severity, source, and status." Filter **Severity → critical**; sort by **Highest risk**. "We can always find a single alert, but the product's real value is correlation." |
| 01:30 | Alert detail (`/alerts/ALERT-2041`) | Walk the sections: Summary, risk score, Evidence (click **Copy** on one indicator), Timeline, Correlation, Recommended next steps. "Notice every panel says it's a sample record — nothing real is claimed." |
| 02:10 | Incidents (`/incidents`) | "Related alerts are grouped into incidents — one story instead of hundreds of fragments." Expand **INC-1001**: read *Why these alerts correlate*, the relationship diagram, and the timeline. "Confidence is transparently a demo value until our AI model ships." |
| 03:00 | MITRE (`/mitre`) | Search e.g. **T1190**. "Technique and tactic context so analysts can spot a campaign, not just an alert." Show the tactic filter. |
| 03:30 | BLUF briefs (`/briefs`) | Open **P1** brief. "Bottom line up front: what happened, why it matters, recommended focus — readable in 30 seconds." Click **Copy summary**, then **Print** to show the clean print rendering. |
| 04:00 | Analytics (`/analytics`) | "Analyst pressure at a glance: trend, severity and source mix, alert lifecycle, and false-positive review metrics." Switch ranges again to show it recomputes. |
| 04:30 | Settings (`/settings`) | Flip **Light** theme (whole app follows), toggle a notification, then **Reset preferences**. "Settings are stored locally — built for the demo, no backend required." |
| 04:50 | Anywhere | Theme toggle: switch dark ↔ light to show the design system is theme-aware. End: "See the signal. Stop the threat." |

## Demo traps to avoid

- Don't claim anything is real-time or model-based — the UI says *simulated*,
  and judges may unpick it. Say "the API contract for backends is ready; data is
  mocked until integration."
- Don't rush past **Incidents** or **BLUF briefs** — they are the two screens
  that best match the D2 problem statement.
- If a page shows the error card, click **Retry** once and continue — the mock
  failure is intentional UI polish, not a bug.

## Video checklist

- [ ] App running visibly (not slides)
- [ ] Covers at least one feature end-to-end (recommended: Alerts → Incidents → Briefs)
- [ ] Audio narration matches the table above
- [ ] 3–5 minutes total
- [ ] Add link to `demo/demo-video-link.txt`, deployment URL to
  `demo/live-demo-url.txt`, screenshots into `demo/screenshots/`