from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.orm import Session

from .logging_config import get_logger
from .schemas import ExecutionResult, ExecutionStats, InvestigationPlan, LogEvent, TopValue

logger = get_logger("siem.execution")

ALLOWED_SQL_PREFIX = "select ts, event_type, source_ip, destination_ip, user_name as \"user\", host, severity, message from log_events"
FORBIDDEN_SQL_TOKENS = re.compile(r"\b(insert|update|delete|drop|alter|truncate|create|grant|revoke|comment|copy)\b", re.IGNORECASE)


def _normalize(value: object) -> str:
    return str(value or "").strip().lower()


def _time_range_bounds(time_range: str | None) -> tuple[datetime | None, str]:
    normalized = _normalize(time_range)
    if not normalized:
        return None, "none"

    hours_match = re.search(r"last\s+(\d+)\s*hour", normalized)
    if hours_match:
        hours = int(hours_match.group(1))
        return datetime.now(timezone.utc) - timedelta(hours=hours), f"last {hours} hours"

    days_match = re.search(r"last\s+(\d+)\s*day", normalized)
    if days_match:
        days = int(days_match.group(1))
        return datetime.now(timezone.utc) - timedelta(days=days), f"last {days} days"

    return None, time_range or "none"


def build_sql_from_plan(plan: InvestigationPlan) -> str:
    clauses: list[str] = []
    lower_bound, _ = _time_range_bounds(plan.time_range)
    if lower_bound is not None:
        clauses.append(f"ts >= TIMESTAMPTZ '{lower_bound.isoformat()}'")

    filters = plan.filters
    mapping = {
        "event_type": "event_type",
        "source_ip": "source_ip",
        "destination_ip": "destination_ip",
        "user": 'user_name',
        "host": 'host',
        "severity": 'severity',
    }
    for key, column in mapping.items():
        if filters.get(key):
            safe_value = filters[key].replace("'", "''")
            clauses.append(f"{column} = '{safe_value}'")

    where_clause = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    return f"{ALLOWED_SQL_PREFIX}{where_clause}"


def validate_query_sql(query_sql: str | None, plan: InvestigationPlan) -> tuple[str, str]:
    fallback_sql = build_sql_from_plan(plan)
    if not query_sql:
        return fallback_sql, "missing_query_sql"

    candidate = query_sql.strip().rstrip(";")
    lowered = candidate.lower()

    if FORBIDDEN_SQL_TOKENS.search(candidate):
        return fallback_sql, "forbidden_sql_token"
    if not lowered.startswith("select"):
        return fallback_sql, "not_select"
    if " from log_events" not in lowered:
        return fallback_sql, "missing_log_events_from"
    if " join " in lowered:
        return fallback_sql, "joins_not_allowed"
    if "*" in candidate.split("from", 1)[0]:
        return fallback_sql, "wildcard_not_allowed"

    return candidate, "gemini_sql"


def _rows_to_log_events(rows) -> list[LogEvent]:
    return [
        LogEvent(
            ts=row.ts.isoformat() if hasattr(row.ts, "isoformat") else str(row.ts),
            event_type=row.event_type,
            source_ip=row.source_ip,
            destination_ip=row.destination_ip,
            user=row.user,
            host=row.host,
            severity=row.severity,
            message=row.message,
        )
        for row in rows
    ]


def _top_values(db: Session, base_sql: str, column: str, limit: int = 5, unknown_label: str = "unknown") -> list[TopValue]:
    stmt = text(
        f"SELECT COALESCE({column}, :unknown_label) AS value, COUNT(*) AS count "
        f"FROM ({base_sql}) AS filtered GROUP BY value ORDER BY count DESC, value LIMIT :limit"
    )
    rows = db.execute(stmt, {"unknown_label": unknown_label, "limit": limit}).all()
    return [TopValue(value=row.value, count=row.count) for row in rows]


def _group_counts(db: Session, base_sql: str, column: str) -> dict[str, int]:
    stmt = text(
        f"SELECT {column} AS value, COUNT(*) AS count "
        f"FROM ({base_sql}) AS filtered GROUP BY value ORDER BY count DESC, value"
    )
    rows = db.execute(stmt).all()
    return {row.value: row.count for row in rows if row.value is not None}


def execute_investigation_plan_db(db: Session, plan: InvestigationPlan) -> ExecutionResult:
    query_sql, query_source = validate_query_sql(plan.query_sql, plan)
    time_window_used = plan.time_range or "none"
    limit = min(max(plan.limit, 1), 500)

    logger.info(
        "Executing investigation query | intent=%s | query_source=%s | time_range=%s | limit=%s",
        plan.intent,
        query_source,
        plan.time_range or "none",
        limit,
    )
    logger.info("SQL to execute | sql=%s", query_sql)

    matched_stmt = text(f"SELECT * FROM ({query_sql}) AS filtered ORDER BY ts DESC LIMIT :limit")
    matched_rows = db.execute(matched_stmt, {"limit": limit}).all()
    matched = _rows_to_log_events(matched_rows)

    total_stmt = text(f"SELECT COUNT(*) AS total FROM ({query_sql}) AS filtered")
    total = db.execute(total_stmt).scalar() or 0

    by_event_type = _group_counts(db, query_sql, "event_type")
    by_severity = _group_counts(db, query_sql, "severity")
    top_source_ips = _top_values(db, query_sql, "source_ip")
    top_users = _top_values(db, query_sql, '"user"')
    top_hosts = _top_values(db, query_sql, "host")
    brute_force_detected = (top_source_ips[0].count if top_source_ips else 0) >= 10 and (
        plan.filters.get("event_type") == "login_failed" or "login_failed" in query_sql
    )

    logger.info(
        "Query execution complete | matches=%s | top_source_ip=%s | brute_force=%s | window=%s",
        total,
        top_source_ips[0].value if top_source_ips else "none",
        brute_force_detected,
        time_window_used,
    )

    return ExecutionResult(
        matched=matched,
        stats=ExecutionStats(
            total=total,
            byEventType=by_event_type,
            bySeverity=by_severity,
            topSourceIps=top_source_ips,
            topUsers=top_users,
            timeWindowUsed=time_window_used,
            bruteForceDetected=brute_force_detected,
            topHosts=top_hosts,
        ),
    )
