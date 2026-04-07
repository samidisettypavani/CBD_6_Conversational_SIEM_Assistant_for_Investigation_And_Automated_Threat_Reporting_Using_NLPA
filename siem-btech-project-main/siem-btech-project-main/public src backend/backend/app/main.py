from __future__ import annotations

import json
import re
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from google.genai import Client

from .config import settings
from .db import SessionLocal
from .execution import execute_investigation_plan_db
from .logging_config import configure_logging, get_logger
from .schemas import ChatRequest, ChatResponse, Entity, InvestigationPlan, InvestigationReport, LiveStats, SimulationStatus
from .simulator import SimulatorManager
from .store import store

configure_logging()
logger = get_logger("siem.api")
simulator = SimulatorManager(lambda: store.simulation_tick())


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info("Starting backend lifespan")
    store.initialize()
    logger.info("Backend startup complete | logs_loaded=%s", store.log_count())
    yield
    simulator.stop()
    logger.info("Shutting down backend lifespan")


app = FastAPI(title="SIEM Chat Backend", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin, "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def fallback_plan(message: str) -> InvestigationPlan:
    lowered = message.lower()
    filters: dict[str, str] = {}
    entities: list[Entity] = []
    severity = "medium"
    intent = "search_logs"
    time_range = None

    days_match = re.search(r"last\s+(\d+)\s*day", lowered)
    hours_match = re.search(r"last\s+(\d+)\s*hour", lowered)
    if days_match:
        time_range = f"last {int(days_match.group(1))} days"
        entities.append(Entity(type="time_range", value=time_range, confidence=0.9))
    elif hours_match:
        time_range = f"last {int(hours_match.group(1))} hours"
        entities.append(Entity(type="time_range", value=time_range, confidence=0.9))
    elif "24" in lowered or "day" in lowered:
        time_range = "last 24 hours"
        entities.append(Entity(type="time_range", value=time_range, confidence=0.7))

    if "brute force" in lowered or "bruteforce" in lowered:
        filters["event_type"] = "login_failed"
        entities.append(Entity(type="event_type", value="login_failed", confidence=0.95))
        entities.append(Entity(type="threat_type", value="brute_force", confidence=0.95))
        severity = "high"
        intent = "detect_threat"
    elif "failed login" in lowered or "login failure" in lowered:
        filters["event_type"] = "login_failed"
        entities.append(Entity(type="event_type", value="login_failed", confidence=0.92))
        severity = "high" if "brute" in lowered else "medium"
    elif "port scan" in lowered:
        filters["event_type"] = "port_scan"
        entities.append(Entity(type="event_type", value="port_scan", confidence=0.92))
        severity = "high"
    elif "malware" in lowered:
        filters["event_type"] = "malware_alert"
        entities.append(Entity(type="event_type", value="malware_alert", confidence=0.92))
        severity = "critical"

    if "45.33.32.156" in message:
        filters["source_ip"] = "45.33.32.156"
        entities.append(Entity(type="source_ip", value="45.33.32.156", confidence=0.98))

    if not time_range:
        intent = "ask_clarifying_question"

    return InvestigationPlan(
        intent=intent,  # type: ignore[arg-type]
        time_range=time_range,
        filters=filters,
        query_sql=None,
        output="summary",
        severity=severity,  # type: ignore[arg-type]
        limit=100,
        detected_entities=entities,
        assumptions=["Fallback planner used in local backend scaffold."],
        next_questions=[] if time_range else ["What time range should I use: last 24 hours or last 7 days?"],
    )


def normalize_plan_payload(payload: dict, message: str) -> dict:
    normalized = dict(payload)
    lowered_message = message.lower()

    intent_aliases = {
        "investigate_attacks": "detect_threat",
        "investigate_attack": "detect_threat",
        "threat_detection": "detect_threat",
        "threat_detect": "detect_threat",
        "investigate": "search_logs",
        "query_logs": "search_logs",
        "search": "search_logs",
        "report": "generate_report",
        "clarify": "ask_clarifying_question",
    }
    output_aliases = {
        "alerts": "summary",
        "report": "summary",
        "list": "raw",
        "table": "raw",
        "events": "raw",
        "logs": "raw",
    }

    intent = normalized.get("intent")
    if intent in intent_aliases:
        normalized["intent"] = intent_aliases[intent]
    elif isinstance(intent, str):
        lowered_intent = intent.lower()
        if "threat" in lowered_intent or "attack" in lowered_intent or "detect" in lowered_intent:
            normalized["intent"] = "detect_threat"
        elif "report" in lowered_intent or "summary" in lowered_intent:
            normalized["intent"] = "generate_report"
        elif "clar" in lowered_intent or "question" in lowered_intent:
            normalized["intent"] = "ask_clarifying_question"
        elif "query" in lowered_intent or "search" in lowered_intent or "event" in lowered_intent or "log" in lowered_intent:
            normalized["intent"] = "search_logs"

    output = normalized.get("output")
    if output in output_aliases:
        normalized["output"] = output_aliases[output]
    elif isinstance(output, str):
        lowered_output = output.lower()
        if "time" in lowered_output:
            normalized["output"] = "timeline"
        elif "raw" in lowered_output or "log" in lowered_output or "event" in lowered_output or "list" in lowered_output:
            normalized["output"] = "raw"
        elif "summary" in lowered_output or "report" in lowered_output or "alert" in lowered_output:
            normalized["output"] = "summary"

    if normalized.get("severity") is None:
        normalized["severity"] = "high" if "brute force" in lowered_message or "attack" in lowered_message else "medium"

    if normalized.get("limit") is None:
        normalized["limit"] = 100

    if normalized.get("query_sql") is not None:
        normalized["query_sql"] = str(normalized["query_sql"])

    detected_entities = normalized.get("detected_entities", [])
    fixed_entities: list[dict] = []
    if isinstance(detected_entities, list):
        for item in detected_entities:
            if isinstance(item, dict):
                fixed_entities.append(
                    {
                        "type": item.get("type", "other"),
                        "value": str(item.get("value", "")),
                        "confidence": item.get("confidence"),
                    }
                )
            elif isinstance(item, str):
                fixed_entities.append({"type": "other", "value": item, "confidence": None})
    normalized["detected_entities"] = fixed_entities

    filters = normalized.get("filters")
    if not isinstance(filters, dict):
        normalized["filters"] = {}
    else:
        normalized["filters"] = {str(key): str(value) for key, value in filters.items() if value is not None}

    allowed_filter_keys = {"event_type", "source_ip", "destination_ip", "user", "host", "severity"}
    normalized["filters"] = {
        key: value for key, value in normalized["filters"].items() if key in allowed_filter_keys
    }

    if ("brute force" in lowered_message or "bruteforce" in lowered_message) and "event_type" not in normalized["filters"]:
        normalized["filters"]["event_type"] = "login_failed"

    if not normalized["detected_entities"] and "event_type" in normalized["filters"]:
        normalized["detected_entities"].append(
            {"type": "event_type", "value": normalized["filters"]["event_type"], "confidence": 0.85}
        )

    return normalized


def build_assistant_text(plan: InvestigationPlan, execution_total: int) -> str:
    findings = [
        f"- Intent: `{plan.intent}`",
        f"- Time range: `{plan.time_range or 'not specified'}`",
        f"- Filters: `{plan.filters or {}}`",
        f"- Matches found: `{execution_total}`",
    ]

    next_questions = plan.next_questions or [
        "Do you want a raw event list or a timeline view?",
        "Should I narrow this to one host, user, or source IP?",
    ]

    return "\n".join(
        [
            "## Summary",
            "Local FastAPI backend generated an investigation plan and executed it against the current event store.",
            "",
            "## Key Findings",
            *findings,
            "",
            "## Suggested Next Questions",
            *(f"- {question}" for question in next_questions),
        ]
    )


async def generate_plan_with_llm(message: str) -> InvestigationPlan:
    if not settings.gemini_api_key:
        logger.info("Gemini API key not configured, using fallback planner")
        return fallback_plan(message)

    client = Client(api_key=settings.gemini_api_key)
    prompt = f"""
You are a conversational SIEM assistant.
Return ONLY compact JSON.
Do not wrap the JSON in markdown.
Do not include explanation outside the JSON.

Return EXACTLY these keys:
- intent
- time_range
- filters
- query_sql
- output
- severity
- limit
- detected_entities
- assumptions
- next_questions

Valid values:
- intent must be exactly one of:
  - "search_logs"
  - "detect_threat"
  - "generate_report"
  - "ask_clarifying_question"
- output must be exactly one of:
  - "summary"
  - "raw"
  - "timeline"
- severity must be exactly one of:
  - "low"
  - "medium"
  - "high"
  - "critical"
- limit must be an integer between 1 and 500

Database model:
- table name: "log_events"
- valid columns:
  - ts
  - event_type
  - source_ip
  - destination_ip
  - user_name
  - host
  - severity
  - message

Known categorical values:
- event_type:
  - "login_failed"
  - "login_success"
  - "port_scan"
  - "waf_block"
  - "malware_alert"
- severity:
  - "low"
  - "medium"
  - "high"
  - "critical"
- user_name examples:
  - "admin"
  - "root"
  - "umesh"
  - "analyst"
  - "devops"
  - "john"
  - "mary"
- host examples:
  - "vpn-gateway-1"
  - "app-01"
  - "db-01"
  - "mail-01"
  - "jumpbox-1"
  - "waf-01"

Filter rules:
- filters must be an object
- only these filter keys are allowed:
  - "event_type"
  - "source_ip"
  - "destination_ip"
  - "user"
  - "host"
  - "severity"
- if no filters are needed, return {{}}
- use "user" in filters for analyst-facing plan output, but use "user_name" inside SQL

Detected entity rules:
- detected_entities must be an array of objects
- each object must have:
  - type: string
  - value: string
  - confidence: number from 0 to 1, optional
- do not return plain strings inside detected_entities

Time range rules:
- if the user specifies a time range, preserve it in plain language, for example:
  - "last 24 hours"
  - "last 2 days"
- if the user does not specify a time range, set intent to "ask_clarifying_question"

query_sql requirements:
- query_sql must be a PostgreSQL SELECT only
- query_sql must query only from "log_events"
- no JOIN, INSERT, UPDATE, DELETE, ALTER, DROP, TRUNCATE, CREATE
- no wildcard select
- use exactly this SELECT list and aliasing:
  SELECT ts, event_type, source_ip, destination_ip, user_name AS "user", host, severity, message FROM log_events
- add WHERE clauses when needed
- do not add LIMIT
- do not end query_sql with a semicolon

Behavior rules:
- for brute-force style requests, prefer:
  - intent = "detect_threat"
  - filters.event_type = "login_failed"
  - severity = "high"
- if the user asks for a report or summary document, use intent = "generate_report"
- if uncertain, choose the closest valid enum above, never invent a new label

Example valid JSON:
{{
  "intent": "detect_threat",
  "time_range": "last 2 days",
  "filters": {{"event_type": "login_failed"}},
  "query_sql": "SELECT ts, event_type, source_ip, destination_ip, user_name AS \\"user\\", host, severity, message FROM log_events WHERE ts >= NOW() - INTERVAL '2 days' AND event_type = 'login_failed'",
  "output": "raw",
  "severity": "high",
  "limit": 100,
  "detected_entities": [
    {{"type": "event_type", "value": "login_failed", "confidence": 0.95}},
    {{"type": "time_range", "value": "last 2 days", "confidence": 0.9}}
  ],
  "assumptions": [],
  "next_questions": []
}}

Message: {message}
"""

    try:
        logger.info("Calling Gemini planner")
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config={"response_mime_type": "application/json"},
        )
        payload = json.loads(response.text)
        try:
            plan = InvestigationPlan.model_validate(payload)
        except Exception:
            logger.warning("Gemini payload required normalization before validation")
            normalized_payload = normalize_plan_payload(payload, message)
            plan = InvestigationPlan.model_validate(normalized_payload)
        logger.info(
            "Gemini plan generated | intent=%s | severity=%s | filters=%s",
            plan.intent,
            plan.severity,
            plan.filters,
        )
        return plan
    except Exception as exc:
        logger.exception("Gemini planning failed, using fallback planner | error=%s", exc)
        return fallback_plan(message)


@app.get("/health")
async def health() -> dict[str, object]:
    logger.info("Health check requested")
    return {
        "status": "ok",
        "logs_loaded": store.log_count(),
        "investigations": store.investigation_count(),
    }


@app.get("/alerts")
async def list_alerts(source: str | None = Query(default=None), limit: int = Query(default=20, ge=1, le=100)) -> list[dict]:
    sources = [item.strip() for item in source.split(",") if item.strip()] if source else None
    alerts = store.list_alerts(limit=limit, sources=sources)
    logger.info("Alerts requested | source=%s | count=%s", ",".join(sources) if sources else "all", len(alerts))
    return [alert.model_dump() for alert in alerts]


@app.get("/alerts/{alert_id}")
async def get_alert(alert_id: int) -> dict:
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    logger.info("Alert detail requested | alert_id=%s | source=%s", alert_id, alert.source)
    return alert.model_dump()


@app.get("/logs/recent")
async def list_recent_logs(limit: int = Query(default=25, ge=1, le=100)) -> list[dict]:
    logs = store.list_recent_logs(limit=limit)
    logger.info("Recent logs requested | count=%s", len(logs))
    return [log.model_dump() for log in logs]


@app.get("/stats/live", response_model=LiveStats)
async def live_stats(window_hours: int = Query(default=24, ge=1, le=168)) -> LiveStats:
    stats = store.live_stats(window_hours=window_hours)
    logger.info("Live stats requested | window_hours=%s | total_events=%s", window_hours, stats.total_events)
    return stats


@app.get("/investigations")
async def list_investigations(session_id: str | None = Query(default=None)) -> list[dict]:
    records = store.list_investigations(session_id=session_id)
    logger.info("Investigations requested | session_id=%s | count=%s", session_id or "all", len(records))
    return [record.model_dump(mode="json") for record in records]


@app.get("/investigations/{investigation_id}/report", response_model=InvestigationReport)
async def investigation_report(investigation_id: int) -> InvestigationReport:
    report = store.build_investigation_report(investigation_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    logger.info("Investigation report requested | investigation_id=%s", investigation_id)
    return report


@app.post("/simulation/tick")
async def simulation_tick(count: int = 6) -> dict:
    logger.info("Simulation endpoint called | count=%s", count)
    return store.simulation_tick(count).model_dump()


@app.get("/simulation/status", response_model=SimulationStatus)
async def simulation_status() -> SimulationStatus:
    status = simulator.status()
    logger.info("Simulation status requested | running=%s | interval_seconds=%s", status["running"], status["interval_seconds"])
    return SimulationStatus(**status)


@app.post("/simulation/start", response_model=SimulationStatus)
async def simulation_start() -> SimulationStatus:
    status = simulator.start()
    logger.info("Simulation start requested | running=%s | interval_seconds=%s", status["running"], status["interval_seconds"])
    return SimulationStatus(**status)


@app.post("/simulation/stop", response_model=SimulationStatus)
async def simulation_stop() -> SimulationStatus:
    status = simulator.stop()
    logger.info("Simulation stop requested | running=%s | interval_seconds=%s", status["running"], status["interval_seconds"])
    return SimulationStatus(**status)


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    if not request.message.strip():
        logger.warning("Rejected empty chat request | session_id=%s", request.session_id)
        raise HTTPException(status_code=400, detail="Message is required.")

    logger.info(
        "Chat request received | session_id=%s | message=%s | history_count=%s",
        request.session_id,
        request.message[:160],
        len(request.messages),
    )
    plan = await generate_plan_with_llm(request.message)
    logger.info(
        "Plan ready | intent=%s | severity=%s | entities=%s",
        plan.intent,
        plan.severity,
        len(plan.detected_entities),
    )
    with SessionLocal() as db:
        execution = execute_investigation_plan_db(db, plan)
    assistant_text = build_assistant_text(plan, execution.stats.total)
    logger.info(
        "Assistant response prepared | total_matches=%s | brute_force=%s",
        execution.stats.total,
        execution.stats.bruteForceDetected,
    )

    response = ChatResponse(
        assistant_text=assistant_text,
        investigation_plan=plan,
        execution=execution,
        investigation_id=0,
    )

    record = store.record_investigation(request.session_id, request.message, response)
    store.record_alert(plan, assistant_text, investigation_id=record.id)
    logger.info("Chat request completed | investigation_id=%s", record.id)
    return response.model_copy(update={"investigation_id": record.id})
