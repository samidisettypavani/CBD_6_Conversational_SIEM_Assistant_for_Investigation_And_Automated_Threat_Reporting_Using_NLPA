from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, text

from .anomaly import detect_anomaly_alerts
from .detection import detect_alerts
from .db import Base, SessionLocal, engine
from .logging_config import get_logger
from .mock_logs import generate_live_batch, generate_mock_logs
from .models import AlertModel, InvestigationModel, LogEventModel
from .schemas import (
    AlertRecord,
    ChatResponse,
    InvestigationReport,
    InvestigationRecord,
    InvestigationPlan,
    LiveStats,
    LogEvent,
    TopValue,
    SimulationStatus,
    SimulationTickResponse,
)

logger = get_logger("siem.store")


def _to_datetime(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _to_log_schema(model: LogEventModel) -> LogEvent:
    return LogEvent(
        ts=model.ts.isoformat(),
        event_type=model.event_type,
        source_ip=model.source_ip,
        destination_ip=model.destination_ip,
        user=model.user_name,
        host=model.host,
        severity=model.severity,  # type: ignore[arg-type]
        message=model.message,
    )


def _to_alert_schema(model: AlertModel) -> AlertRecord:
    return AlertRecord(
        id=model.id,
        ts=model.ts.astimezone().isoformat(timespec="seconds"),
        title=model.title,
        severity=model.severity,  # type: ignore[arg-type]
        summary=model.summary,
        source=model.source,
        details_json=model.details_json,
    )


def _to_investigation_schema(model: InvestigationModel) -> InvestigationRecord:
    return InvestigationRecord(
        id=model.id,
        session_id=model.session_id,
        user_prompt=model.user_prompt,
        assistant_text=model.assistant_text,
        plan_json=model.plan_json,
        execution_json=model.execution_json,
        created_at=model.created_at,
    )


class PostgresStore:
    def initialize(self) -> None:
        logger.info("Initializing database schema")
        Base.metadata.create_all(bind=engine)
        self.migrate_alerts_table()
        self.migrate_investigations_table()
        self.seed_logs_if_empty()

    def migrate_alerts_table(self) -> None:
        with SessionLocal() as db:
            db.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS source VARCHAR(30)"))
            db.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS details_json JSON"))
            db.execute(text("UPDATE alerts SET source = 'investigation' WHERE source IS NULL"))
            db.commit()
            logger.info("Alerts table migration ensured source column exists")

    def migrate_investigations_table(self) -> None:
        with SessionLocal() as db:
            db.execute(text("ALTER TABLE investigations ADD COLUMN IF NOT EXISTS execution_json JSON"))
            db.commit()
            logger.info("Investigations table migration ensured execution_json column exists")

    def seed_logs_if_empty(self, count: int = 350) -> None:
        with SessionLocal() as db:
            existing = db.scalar(select(LogEventModel.id).limit(1))
            if existing is not None:
                logger.info("Log seed skipped because log_events already contains data")
                return

            logger.info("Seeding initial log dataset | count=%s", count)
            for log in generate_mock_logs(count):
                db.add(
                    LogEventModel(
                        ts=_to_datetime(log.ts),
                        event_type=log.event_type,
                        source_ip=log.source_ip,
                        destination_ip=log.destination_ip,
                        user_name=log.user,
                        host=log.host,
                        severity=log.severity,
                        message=log.message,
                        raw_json=log.model_dump(),
                    )
                )
            db.commit()
            logger.info("Initial log seed completed")

    def load_logs(self, limit: int = 1000) -> list[LogEvent]:
        with SessionLocal() as db:
            rows = db.scalars(select(LogEventModel).order_by(LogEventModel.ts.desc()).limit(limit)).all()
            return [_to_log_schema(row) for row in rows]

    def list_recent_logs(self, limit: int = 50) -> list[LogEvent]:
        with SessionLocal() as db:
            rows = db.scalars(select(LogEventModel).order_by(LogEventModel.ts.desc()).limit(limit)).all()
            return [_to_log_schema(row) for row in rows]

    def log_count(self) -> int:
        with SessionLocal() as db:
            return db.scalar(select(func.count()).select_from(LogEventModel)) or 0

    def investigation_count(self) -> int:
        with SessionLocal() as db:
            return db.scalar(select(func.count()).select_from(InvestigationModel)) or 0

    def list_alerts(self, limit: int = 20, sources: list[str] | None = None) -> list[AlertRecord]:
        with SessionLocal() as db:
            stmt = select(AlertModel).order_by(AlertModel.ts.desc()).limit(limit)
            if sources:
                stmt = stmt.where(AlertModel.source.in_(sources))
            rows = db.scalars(stmt).all()
            return [_to_alert_schema(row) for row in rows]

    def get_alert(self, alert_id: int) -> AlertRecord | None:
        with SessionLocal() as db:
            row = db.get(AlertModel, alert_id)
            return _to_alert_schema(row) if row else None

    def list_investigations(self, session_id: str | None = None, limit: int = 100) -> list[InvestigationRecord]:
        with SessionLocal() as db:
            stmt = select(InvestigationModel).order_by(InvestigationModel.created_at.desc()).limit(limit)
            if session_id:
                stmt = stmt.where(InvestigationModel.session_id == session_id)
            rows = db.scalars(stmt).all()
            return [_to_investigation_schema(row) for row in rows]

    def record_investigation(self, session_id: str, message: str, response: ChatResponse) -> InvestigationRecord:
        with SessionLocal() as db:
            record = InvestigationModel(
                session_id=session_id,
                user_prompt=message,
                assistant_text=response.assistant_text,
                plan_json=response.investigation_plan.model_dump(),
                execution_json=response.execution.model_dump() if response.execution else None,
            )
            db.add(record)
            db.commit()
            db.refresh(record)
            logger.info("Investigation persisted | id=%s | session_id=%s", record.id, session_id)
            return _to_investigation_schema(record)

    def record_alert(
        self,
        plan: InvestigationPlan,
        assistant_text: str,
        investigation_id: int | None = None,
    ) -> AlertRecord:
        with SessionLocal() as db:
            alert = AlertModel(
                title=plan.intent.replace("_", " ").upper(),
                severity=plan.severity,
                summary=assistant_text[:140],
                source="investigation",
                investigation_id=investigation_id,
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)
            logger.info(
                "Alert persisted | id=%s | investigation_id=%s | severity=%s",
                alert.id,
                investigation_id,
                plan.severity,
            )
            return _to_alert_schema(alert)

    def record_generated_alert(self, title: str, severity: str, summary: str) -> AlertRecord:
        return self.record_detection_alert(title=title, severity=severity, summary=summary, source="detection")

    def record_detection_alert(
        self,
        title: str,
        severity: str,
        summary: str,
        source: str,
        details_json: dict | None = None,
    ) -> AlertRecord:
        with SessionLocal() as db:
            alert = AlertModel(
                title=title,
                severity=severity,
                summary=summary[:240],
                source=source,
                details_json=details_json,
                investigation_id=None,
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)
            logger.info(
                "Generated alert persisted | id=%s | title=%s | severity=%s | source=%s",
                alert.id,
                title,
                severity,
                source,
            )
            return _to_alert_schema(alert)

    def simulation_tick(self, count: int = 6) -> SimulationTickResponse:
        new_logs = generate_live_batch(count)
        logger.info("Simulation tick started | count=%s", count)
        with SessionLocal() as db:
            for log in new_logs:
                db.add(
                    LogEventModel(
                        ts=_to_datetime(log.ts),
                        event_type=log.event_type,
                        source_ip=log.source_ip,
                        destination_ip=log.destination_ip,
                        user_name=log.user,
                        host=log.host,
                        severity=log.severity,
                        message=log.message,
                        raw_json=log.model_dump(),
                    )
                )
            db.commit()

        for alert in detect_alerts(new_logs):
            self.record_detection_alert(
                title=str(alert["title"]),
                severity=str(alert["severity"]),
                summary=str(alert["summary"]),
                source="detection",
                details_json=alert.get("details_json") if isinstance(alert.get("details_json"), dict) else None,
            )

        all_recent_logs = self.load_logs(limit=500)
        for alert in detect_anomaly_alerts(all_recent_logs, new_logs):
            self.record_detection_alert(
                title=str(alert["title"]),
                severity=str(alert["severity"]),
                summary=str(alert["summary"]),
                source="ml_detection",
                details_json=alert.get("details_json") if isinstance(alert.get("details_json"), dict) else None,
            )

        logger.info("Simulation tick completed | inserted=%s | total_logs=%s", len(new_logs), self.log_count())
        return SimulationTickResponse(inserted=len(new_logs), total_logs=self.log_count())

    def live_stats(self, window_hours: int = 24) -> LiveStats:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        with SessionLocal() as db:
            log_rows = db.scalars(
                select(LogEventModel).where(LogEventModel.ts >= cutoff).order_by(LogEventModel.ts.desc())
            ).all()
            detection_alert_count = db.scalar(
                select(func.count()).select_from(AlertModel).where(
                    AlertModel.source.in_(["detection", "ml_detection"]),
                    AlertModel.ts >= cutoff,
                )
            ) or 0

        by_severity = Counter(row.severity for row in log_rows)
        by_event_type = Counter(row.event_type for row in log_rows)
        top_source_ips = [
            TopValue(value=value, count=count)
            for value, count in Counter(row.source_ip for row in log_rows).most_common(5)
        ]

        bucket_counter: dict[str, int] = {}
        for row in log_rows:
            bucket = row.ts.astimezone(timezone.utc).strftime("%m-%d %H:00")
            bucket_counter[bucket] = bucket_counter.get(bucket, 0) + 1

        timeline = [
            {"bucket": bucket, "count": count}
            for bucket, count in sorted(bucket_counter.items())[-8:]
        ]

        return LiveStats(
            total_events=len(log_rows),
            detection_alerts=int(detection_alert_count),
            by_severity=dict(by_severity),
            by_event_type=dict(by_event_type),
            top_source_ips=top_source_ips,
            timeline=timeline,
        )

    def build_investigation_report(self, investigation_id: int) -> InvestigationReport | None:
        with SessionLocal() as db:
            record = db.get(InvestigationModel, investigation_id)
            if record is None:
                return None

        execution = record.execution_json or {}
        stats = execution.get("stats", {})
        matched = execution.get("matched", [])
        findings = [
            f"Intent: {record.plan_json.get('intent', 'unknown')}",
            f"Time range: {record.plan_json.get('time_range', 'not specified')}",
            f"Matches found: {stats.get('total', 0)}",
            f"Top source IP: {(stats.get('topSourceIps') or [{}])[0].get('value', '-')}",
            f"Brute force detected: {'yes' if stats.get('bruteForceDetected') else 'no'}",
        ]
        evidence = [
            f"{item.get('ts', '-')}: {item.get('message', '-')}"
            for item in matched[:5]
        ]
        recommended_actions = [
            "Review the top source IP and associated hosts for malicious behavior.",
            "Validate user accounts involved in repeated failed authentication attempts.",
            "Escalate high-severity detections and preserve relevant log evidence.",
        ]

        return InvestigationReport(
            investigation_id=record.id,
            title=f"Investigation Report #{record.id}",
            generated_at=datetime.now(timezone.utc),
            summary=record.assistant_text,
            findings=findings,
            evidence=evidence,
            recommended_actions=recommended_actions,
        )


store = PostgresStore()
