import asyncio
from datetime import datetime, timezone
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.database.database import Base
from app.database.session import async_engine, AsyncSessionLocal
from app.models.alert import Alert, AlertSeverity, AlertStatus, AlertSource
from app.models.threat import Threat, ThreatSeverity, ThreatStatus
from app.models.data_source import DataSource, DataSourceStatus
from app.models.mitre import MitreTechnique, MitreTactic
from app.models.bluf import BlufReport
from app.models.indicator import Indicator, IndicatorType, IndicatorReputation
from app.data.sample_data import (
    SAMPLE_ALERTS,
    SAMPLE_THREATS,
    SAMPLE_DATA_SOURCES,
    SAMPLE_TACTICS,
    SAMPLE_TECHNIQUES,
    SAMPLE_BRIEFS,
    SAMPLE_INDICATORS,
)
from app.core.logging import logger

_initialized = False
_lock = asyncio.Lock()


async def init_database():
    """Ensures database tables exist and baseline demo data is seeded."""
    global _initialized
    if _initialized:
        return

    async with _lock:
        if _initialized:
            return

        try:
            # 1. Create tables if they do not exist
            async with async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            # 2. Check if alerts table is populated
            async with AsyncSessionLocal() as db:
                try:
                    count_res = await db.execute(select(func.count(Alert.id)))
                    alert_count = count_res.scalar() or 0
                except Exception:
                    alert_count = 0

                if alert_count == 0:
                    logger.info("Database is empty or newly created. Auto-seeding standard dataset...")

                    # Seed MITRE Tactics & Techniques
                    for tac_data in SAMPLE_TACTICS:
                        db.add(MitreTactic(**tac_data))
                    for tech_data in SAMPLE_TECHNIQUES:
                        db.add(MitreTechnique(**tech_data))

                    # Seed Data Sources
                    for ds_data in SAMPLE_DATA_SOURCES:
                        db.add(
                            DataSource(
                                id=ds_data["id"],
                                name=ds_data["name"],
                                source_type=ds_data.get("source_type"),
                                detail=ds_data["detail"],
                                health=DataSourceStatus(ds_data["health"]),
                                lag_seconds=ds_data.get("lag_seconds", 0),
                                last_heartbeat=ds_data.get("last_heartbeat"),
                            )
                        )

                    # Seed Threats
                    for t_data in SAMPLE_THREATS:
                        db.add(
                            Threat(
                                id=t_data["id"],
                                threat_id=t_data["id"],
                                title=t_data["title"],
                                summary=t_data["summary"],
                                explanation=t_data.get("explanation"),
                                severity=ThreatSeverity(t_data["severity"]),
                                status=ThreatStatus(t_data["status"]),
                                confidence=t_data["confidence"],
                                risk_score=t_data["risk_score"],
                                alert_ids=t_data["alert_ids"],
                                mitre_techniques=t_data["mitre_techniques"],
                                affected_assets=t_data["affected_assets"],
                                scoring_factors=t_data["scoring_factors"],
                                opened_at=t_data["opened_at"],
                                updated_at_custom=t_data["updated_at"],
                            )
                        )

                    # Seed BLUF Reports
                    for t_id, b_data in SAMPLE_BRIEFS.items():
                        db.add(
                            BlufReport(
                                threat_id=t_id,
                                bottom_line=b_data["bottom_line"],
                                impact=b_data["impact"],
                                key_evidence=b_data["key_evidence"],
                                recommended_focus=b_data["recommended_focus"],
                                generated_by=b_data.get("generated_by", "ThreatLens BLUF Correlation Engine"),
                            )
                        )

                    # Seed Alerts
                    for a_data in SAMPLE_ALERTS:
                        db.add(
                            Alert(
                                id=a_data["id"],
                                team_id=a_data["team_id"],
                                title=a_data["title"],
                                description=a_data["description"],
                                source=AlertSource(a_data["source"]),
                                source_label=a_data["source_label"],
                                timestamp=a_data["timestamp"],
                                severity=AlertSeverity(a_data["severity"]),
                                status=AlertStatus(a_data["status"]),
                                risk_score=a_data["risk_score"],
                                related_threat_id=a_data.get("related_threat_id"),
                                mitre_techniques=a_data.get("mitre_techniques", []),
                                indicators=a_data.get("indicators", []),
                                event_type=a_data.get("event_type"),
                                source_ip=a_data.get("source_ip"),
                                destination_ip=a_data.get("destination_ip"),
                                hostname=a_data.get("hostname"),
                                username=a_data.get("username"),
                            )
                        )

                    # Seed Indicators
                    for i_data in SAMPLE_INDICATORS:
                        db.add(
                            Indicator(
                                id=i_data["id"],
                                indicator=i_data["indicator"],
                                indicator_type=IndicatorType(i_data["indicator_type"]),
                                reputation=IndicatorReputation(i_data["reputation"]),
                                confidence=i_data["confidence"],
                                source=i_data["source"],
                                threat_actor=i_data.get("threat_actor"),
                                campaign=i_data.get("campaign"),
                                threat_type=i_data.get("threat_type", "general_threat"),
                                tags=i_data.get("tags", []),
                                raw_intelligence=i_data.get("raw_intelligence"),
                                first_seen=i_data["first_seen"],
                                last_seen=i_data["last_seen"],
                            )
                        )

                    await db.commit()
                    logger.info("Successfully seeded all demo data.")
            _initialized = True
        except Exception as e:
            logger.warning(f"Database auto-init notice: {e}")
