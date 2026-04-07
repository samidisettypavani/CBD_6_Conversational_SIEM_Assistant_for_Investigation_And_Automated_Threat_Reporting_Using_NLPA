from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


Severity = Literal["low", "medium", "high", "critical"]
Intent = Literal["search_logs", "detect_threat", "generate_report", "ask_clarifying_question"]
OutputMode = Literal["summary", "raw", "timeline"]
MessageRole = Literal["user", "assistant"]


class ChatMessage(BaseModel):
    role: MessageRole
    content: str


class Entity(BaseModel):
    type: str
    value: str
    confidence: float | None = None


class InvestigationPlan(BaseModel):
    intent: Intent
    time_range: str | None = None
    filters: dict[str, str] = Field(default_factory=dict)
    query_sql: str | None = None
    output: OutputMode = "summary"
    severity: Severity = "medium"
    limit: int = 100
    detected_entities: list[Entity] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    next_questions: list[str] = Field(default_factory=list)


class LogEvent(BaseModel):
    ts: str
    event_type: str
    source_ip: str
    destination_ip: str | None = None
    user: str | None = None
    host: str | None = None
    severity: Severity
    message: str


class TopValue(BaseModel):
    value: str
    count: int


class ExecutionStats(BaseModel):
    total: int
    byEventType: dict[str, int]
    bySeverity: dict[str, int]
    topSourceIps: list[TopValue]
    topUsers: list[TopValue]
    timeWindowUsed: str
    bruteForceDetected: bool
    topHosts: list[TopValue]


class ExecutionResult(BaseModel):
    matched: list[LogEvent]
    stats: ExecutionStats


class ChatRequest(BaseModel):
    session_id: str = "local-session"
    message: str
    messages: list[ChatMessage] = Field(default_factory=list)


class ChatResponse(BaseModel):
    assistant_text: str
    investigation_plan: InvestigationPlan
    execution: ExecutionResult | None = None
    investigation_id: int


class AlertRecord(BaseModel):
    id: int
    ts: str
    title: str
    severity: Severity
    summary: str
    source: str
    details_json: dict[str, Any] | None = None


class InvestigationRecord(BaseModel):
    id: int
    session_id: str
    user_prompt: str
    assistant_text: str
    plan_json: dict[str, Any]
    execution_json: dict[str, Any] | None = None
    created_at: datetime


class SimulationTickResponse(BaseModel):
    inserted: int
    total_logs: int


class SimulationStatus(BaseModel):
    running: bool
    interval_seconds: int


class LiveStats(BaseModel):
    total_events: int
    detection_alerts: int
    by_severity: dict[str, int]
    by_event_type: dict[str, int]
    top_source_ips: list[TopValue]
    timeline: list[dict[str, int | str]]


class InvestigationReport(BaseModel):
    investigation_id: int
    title: str
    generated_at: datetime
    summary: str
    findings: list[str]
    evidence: list[str]
    recommended_actions: list[str]
