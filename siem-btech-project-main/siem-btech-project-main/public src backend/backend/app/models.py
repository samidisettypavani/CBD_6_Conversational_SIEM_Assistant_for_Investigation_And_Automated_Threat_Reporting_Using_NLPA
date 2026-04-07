from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class LogEventModel(Base):
    __tablename__ = "log_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    source_ip: Mapped[str] = mapped_column(String(64), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_name: Mapped[str | None] = mapped_column(String(120), index=True, nullable=True)
    host: Mapped[str | None] = mapped_column(String(120), index=True, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    message: Mapped[str] = mapped_column(Text)
    raw_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_log_events_event_time_type", "ts", "event_type"),
        Index("ix_log_events_source_time", "source_ip", "ts"),
    )


class InvestigationModel(Base):
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    session_id: Mapped[str] = mapped_column(String(120), index=True)
    user_prompt: Mapped[str] = mapped_column(Text)
    assistant_text: Mapped[str] = mapped_column(Text)
    plan_json: Mapped[dict] = mapped_column(JSON)
    execution_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)


class AlertModel(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(20), index=True)
    summary: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(30), default="investigation", index=True)
    details_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    investigation_id: Mapped[int | None] = mapped_column(ForeignKey("investigations.id"), nullable=True)
