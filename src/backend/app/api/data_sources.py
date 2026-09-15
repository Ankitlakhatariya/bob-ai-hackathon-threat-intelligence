from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.dependencies import get_db, require_permission, get_current_user
from app.core.permissions import Permission
from app.models.data_source import DataSource, DataSourceStatus
from app.schemas.data_source import DataSourceRead, DataSourceCreate, DataSourceUpdate
from app.data.sample_data import SAMPLE_DATA_SOURCES
from app.core.logging import logger

router = APIRouter()


@router.get("", response_model=List[DataSourceRead])
async def get_data_sources(db: AsyncSession = Depends(get_db)):
    try:
        stmt = select(DataSource).order_by(DataSource.name.asc())
        res = await db.execute(stmt)
        sources = list(res.scalars().all())
        if sources:
            return sources
    except Exception as e:
        logger.warning(f"Database data_sources query notice: {e}")

    return SAMPLE_DATA_SOURCES


@router.post(
    "",
    response_model=DataSourceRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.DATA_SOURCES_MANAGE))],
)
async def create_data_source(payload: DataSourceCreate, db: AsyncSession = Depends(get_db)):
    try:
        existing = await db.get(DataSource, payload.id)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "EXISTS", "message": f"Data source {payload.id} already exists"}},
            )

        ds = DataSource(
            id=payload.id,
            name=payload.name,
            source_type=payload.source_type,
            detail=payload.detail,
            health=payload.health,
            lag_seconds=payload.lag_seconds,
            last_heartbeat=datetime.now(timezone.utc),
        )
        db.add(ds)
        await db.commit()
        await db.refresh(ds)
        return ds
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Database create_data_source notice: {e}")
        return DataSourceRead(
            id=payload.id,
            name=payload.name,
            source_type=payload.source_type,
            detail=payload.detail,
            health=payload.health,
            lag_seconds=payload.lag_seconds,
            last_heartbeat=datetime.now(timezone.utc),
        )


@router.patch(
    "/{data_source_id}",
    response_model=DataSourceRead,
    dependencies=[Depends(require_permission(Permission.DATA_SOURCES_MANAGE))],
)
async def update_data_source(data_source_id: str, payload: DataSourceUpdate, db: AsyncSession = Depends(get_db)):
    try:
        ds = await db.get(DataSource, data_source_id)
        if ds:
            if payload.name is not None:
                ds.name = payload.name
            if payload.detail is not None:
                ds.detail = payload.detail
            if payload.health is not None:
                ds.health = payload.health
            if payload.lag_seconds is not None:
                ds.lag_seconds = payload.lag_seconds
            ds.last_heartbeat = datetime.now(timezone.utc)

            await db.commit()
            await db.refresh(ds)
            return ds
    except Exception as e:
        logger.warning(f"Database update_data_source notice: {e}")

    sample = next((s for s in SAMPLE_DATA_SOURCES if s["id"] == data_source_id), None)
    if sample:
        updated = dict(sample)
        if payload.name is not None:
            updated["name"] = payload.name
        if payload.detail is not None:
            updated["detail"] = payload.detail
        return updated

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"error": {"code": "NOT_FOUND", "message": f"Data source {data_source_id} not found"}},
    )


@router.delete(
    "/{data_source_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission(Permission.DATA_SOURCES_MANAGE))],
)
async def delete_data_source(data_source_id: str, db: AsyncSession = Depends(get_db)):
    try:
        ds = await db.get(DataSource, data_source_id)
        if ds:
            await db.delete(ds)
            await db.commit()
    except Exception as e:
        logger.warning(f"Database delete_data_source notice: {e}")
    return None
