import uuid
from datetime import datetime, timezone
from typing import Optional, List, Any, Dict
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, cast, String
from app.models.investigation import Investigation, InvestigationStatus, InvestigationPriority
from app.models.threat import Threat, ThreatStatus
from app.models.alert import Alert, AlertStatus
from app.models.audit_log import AuditLog
from app.schemas.investigation import (
    InvestigationCreate,
    InvestigationUpdate,
)
from app.core.logging import logger


class InvestigationService:
    """Service handling investigation lifecycle, correlation links, and immutable audit trails."""

    @staticmethod
    async def create_investigation(
        db: AsyncSession,
        payload: InvestigationCreate,
        user_id: Optional[str] = None,
    ) -> Investigation:
        assigned = payload.assigned_analyst or payload.assigned_to or user_id
        title = payload.title or (f"Investigation for Threat {payload.threat_id}" if payload.threat_id else "Threat Investigation Case")

        case = Investigation(
            title=title,
            threat_id=payload.threat_id,
            alert_id=payload.alert_id,
            priority=payload.priority or InvestigationPriority.P2,
            assigned_to=assigned,
            notes=payload.notes,
            findings=payload.findings,
            status=payload.status or InvestigationStatus.OPEN,
            timeline_events=[
                {
                    "action": "CREATED",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "actor": user_id or assigned or "System",
                    "note": f"Investigation opened with priority {payload.priority.value if payload.priority else 'P2'}",
                }
            ],
        )
        db.add(case)
        await db.commit()
        await db.refresh(case)

        # Coordinate with associated Threat or Alert if present
        if case.threat_id:
            threat = await db.get(Threat, case.threat_id)
            if threat and threat.status == ThreatStatus.ACTIVE:
                threat.status = ThreatStatus.INVESTIGATING
                await db.commit()

        if case.alert_id:
            alert = await db.get(Alert, case.alert_id)
            if alert and alert.status == AlertStatus.OPEN:
                alert.status = AlertStatus.INVESTIGATING
                await db.commit()

        # Audit trail logging
        audit = AuditLog(
            action="INVESTIGATION_CREATED",
            entity_type="investigation",
            entity_id=str(case.id),
            user_id=user_id or assigned,
            details={
                "title": case.title,
                "threat_id": case.threat_id,
                "alert_id": case.alert_id,
                "priority": case.priority.value,
                "assigned_analyst": case.assigned_to,
            },
        )
        db.add(audit)
        await db.commit()

        logger.info(f"Investigation {case.id} created for threat={case.threat_id} by {user_id}")
        return case

    @staticmethod
    async def get_investigations(
        db: AsyncSession,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        threat_id: Optional[str] = None,
        assigned_analyst: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> List[Investigation]:
        stmt = select(Investigation).order_by(Investigation.created_at.desc())

        if status:
            stat_enum = InvestigationStatus(status)
            if stat_enum:
                stmt = stmt.where(Investigation.status == stat_enum)
        if priority:
            prio_enum = InvestigationPriority(priority)
            if prio_enum:
                stmt = stmt.where(Investigation.priority == prio_enum)
        if threat_id:
            stmt = stmt.where(Investigation.threat_id == threat_id)
        if assigned_analyst:
            stmt = stmt.where(
                or_(
                    Investigation.assigned_to.ilike(f"%{assigned_analyst}%"),
                    Investigation.assigned_analyst.ilike(f"%{assigned_analyst}%"),
                )
            )

        stmt = stmt.offset(skip).limit(limit)
        res = await db.execute(stmt)
        return list(res.scalars().all())

    @staticmethod
    async def get_investigation(
        db: AsyncSession,
        investigation_id: str,
    ) -> Optional[Investigation]:
        try:
            target_uuid = uuid.UUID(investigation_id)
            stmt = select(Investigation).where(Investigation.id == target_uuid)
        except ValueError:
            stmt = select(Investigation).where(cast(Investigation.id, String) == investigation_id)

        res = await db.execute(stmt)
        return res.scalars().first()

    @staticmethod
    async def update_investigation(
        db: AsyncSession,
        case: Investigation,
        payload: InvestigationUpdate,
        user_id: Optional[str] = None,
    ) -> Investigation:
        updated_fields: Dict[str, Any] = {}

        if payload.title is not None:
            case.title = payload.title
            updated_fields["title"] = payload.title
        if payload.threat_id is not None:
            case.threat_id = payload.threat_id
            updated_fields["threat_id"] = payload.threat_id
        if payload.status is not None:
            old_status = case.status
            case.status = payload.status
            updated_fields["status"] = payload.status.value
            if payload.status in [InvestigationStatus.RESOLVED, InvestigationStatus.CLOSED, InvestigationStatus.FALSE_POSITIVE]:
                if not case.closed_at:
                    case.closed_at = datetime.now(timezone.utc)
            else:
                case.closed_at = None

        if payload.priority is not None:
            case.priority = payload.priority
            updated_fields["priority"] = payload.priority.value
        assigned = payload.assigned_analyst or payload.assigned_to
        if assigned is not None:
            case.assigned_to = assigned
            updated_fields["assigned_analyst"] = assigned
        if payload.notes is not None:
            case.notes = payload.notes
            updated_fields["notes"] = "updated"
        if payload.findings is not None:
            case.findings = payload.findings
            updated_fields["findings"] = "updated"
        if payload.resolution_summary is not None:
            case.resolution_summary = payload.resolution_summary
            updated_fields["resolution_summary"] = payload.resolution_summary

        case.timeline_events = (case.timeline_events or []) + [
            {
                "action": "UPDATED",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "actor": user_id or "Analyst",
                "changes": updated_fields,
            }
        ]

        audit = AuditLog(
            action="INVESTIGATION_UPDATED",
            entity_type="investigation",
            entity_id=str(case.id),
            user_id=user_id,
            details={"changes": updated_fields},
        )
        db.add(audit)

        await db.commit()
        await db.refresh(case)
        return case

    @staticmethod
    async def add_note(
        db: AsyncSession,
        case: Investigation,
        note: str,
        author: str,
        user_id: Optional[str] = None,
    ) -> Investigation:
        timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        note_entry = f"\n[{timestamp_str}] ({author}): {note}"
        case.notes = (case.notes or "") + note_entry

        events = list(case.timeline_events or [])
        events.append(
            {
                "action": "NOTE_ADDED",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "author": author,
                "note": note,
            }
        )
        case.timeline_events = events

        audit = AuditLog(
            action="INVESTIGATION_NOTE_ADDED",
            entity_type="investigation",
            entity_id=str(case.id),
            user_id=user_id or author,
            details={"author": author, "note_length": len(note)},
        )
        db.add(audit)

        await db.commit()
        await db.refresh(case)
        return case

    @staticmethod
    async def resolve_investigation(
        db: AsyncSession,
        case: Investigation,
        resolution_summary: str,
        user_id: Optional[str] = None,
    ) -> Investigation:
        now_dt = datetime.now(timezone.utc)
        case.status = InvestigationStatus.RESOLVED
        case.closed_at = now_dt
        case.resolution_summary = resolution_summary

        events = list(case.timeline_events or [])
        events.append(
            {
                "action": "RESOLVED",
                "timestamp": now_dt.isoformat(),
                "actor": user_id or "Analyst",
                "resolution": resolution_summary,
            }
        )
        case.timeline_events = events

        # Update threat status if linked
        if case.threat_id:
            threat = await db.get(Threat, case.threat_id)
            if threat:
                threat.status = ThreatStatus.RESOLVED

        # Update alert status if linked
        if case.alert_id:
            alert = await db.get(Alert, case.alert_id)
            if alert:
                alert.status = AlertStatus.RESOLVED

        audit = AuditLog(
            action="INVESTIGATION_RESOLVED",
            entity_type="investigation",
            entity_id=str(case.id),
            user_id=user_id,
            details={
                "resolution_summary": resolution_summary,
                "threat_id": case.threat_id,
                "alert_id": case.alert_id,
            },
        )
        db.add(audit)

        await db.commit()
        await db.refresh(case)
        return case

    @staticmethod
    async def mark_false_positive(
        db: AsyncSession,
        case: Investigation,
        reason: str,
        user_id: Optional[str] = None,
        evidence_notes: Optional[str] = None,
    ) -> Investigation:
        """
        Marks the investigation and associated telemetry as FALSE_POSITIVE.
        CRITICAL GUARANTEE: Never deletes alerts, raw data, or correlation evidence.
        All evidence is preserved for auditability and compliance.
        """
        now_dt = datetime.now(timezone.utc)
        case.status = InvestigationStatus.FALSE_POSITIVE
        case.closed_at = now_dt
        case.resolution_summary = f"FALSE POSITIVE: {reason}"
        findings_append = f"\n[{now_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}] FALSE POSITIVE DETERMINATION: {reason}"
        if evidence_notes:
            findings_append += f"\nEvidence Notes: {evidence_notes}"
        findings_append += "\n[INTEGRITY] All telemetry, alert payloads, and correlation evidence retained."
        case.findings = (case.findings or "") + findings_append

        events = list(case.timeline_events or [])
        events.append(
            {
                "action": "MARKED_FALSE_POSITIVE",
                "timestamp": now_dt.isoformat(),
                "actor": user_id or "Analyst",
                "reason": reason,
                "evidence_preserved": True,
            }
        )
        case.timeline_events = events

        # Update alert status to false-positive without deleting any data or indicators
        if case.alert_id:
            alert = await db.get(Alert, case.alert_id)
            if alert:
                alert.status = AlertStatus.FALSE_POSITIVE
                # Retain raw data, indicators, and description intact

        # Audit trail with explicit evidence preservation guarantee
        audit = AuditLog(
            action="INVESTIGATION_FALSE_POSITIVE",
            entity_type="investigation",
            entity_id=str(case.id),
            user_id=user_id,
            details={
                "reason": reason,
                "threat_id": case.threat_id,
                "alert_id": case.alert_id,
                "evidence_preserved": True,
                "evidence_notes": evidence_notes,
            },
        )
        db.add(audit)

        await db.commit()
        await db.refresh(case)
        return case

    @staticmethod
    async def escalate_investigation(
        db: AsyncSession,
        case: Investigation,
        escalate_to: str = "P1",
        reason: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> Investigation:
        prio_enum = InvestigationPriority(escalate_to) or InvestigationPriority.P1
        case.status = InvestigationStatus.ESCALATED
        case.priority = prio_enum

        now_dt = datetime.now(timezone.utc)
        escalation_note = f"\n[{now_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}] ESCALATED to {prio_enum.value} by {user_id or 'Analyst'}. Reason: {reason or 'High-priority incident containment required'}"
        case.notes = (case.notes or "") + escalation_note

        events = list(case.timeline_events or [])
        events.append(
            {
                "action": "ESCALATED",
                "timestamp": now_dt.isoformat(),
                "actor": user_id or "Analyst",
                "escalate_to": prio_enum.value,
                "reason": reason,
            }
        )
        case.timeline_events = events

        audit = AuditLog(
            action="INVESTIGATION_ESCALATED",
            entity_type="investigation",
            entity_id=str(case.id),
            user_id=user_id,
            details={"priority": prio_enum.value, "reason": reason},
        )
        db.add(audit)

        await db.commit()
        await db.refresh(case)
        return case
