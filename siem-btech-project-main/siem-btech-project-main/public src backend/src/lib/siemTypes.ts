export type Entity = {
  type: string;
  value: string;
  confidence?: number;
};

export type InvestigationPlan = {
  intent: string;
  time_range?: string;
  filters?: Record<string, string>;
  query_sql?: string;
  output?: "summary" | "raw" | "timeline";
  severity?: "low" | "medium" | "high" | "critical";
  limit?: number;
  detected_entities: Entity[];
  assumptions?: string[];
  next_questions?: string[];
};

export type ExecutionStats = {
  total: number;
  byEventType: Record<string, number>;
  bySeverity: Record<string, number>;
  topSourceIps: { value: string; count: number }[];
  topUsers: { value: string; count: number }[];
  timeWindowUsed: string;
  bruteForceDetected: boolean;
  topHosts: { value: string; count: number }[];
};

export type ExecutionEvent = {
  ts: string;
  event_type: string;
  source_ip: string;
  destination_ip?: string;
  user?: string;
  host?: string;
  severity: "low" | "medium" | "high" | "critical";
  message: string;
};

export type ExecutionPayload = {
  matched: ExecutionEvent[];
  stats: ExecutionStats;
};

export type AlertRecord = {
  id: number;
  ts: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  summary: string;
  source: string;
  details_json?: Record<string, unknown> | null;
};

export type SimulationStatus = {
  running: boolean;
  interval_seconds: number;
};

export type InvestigationRecord = {
  id: number;
  session_id: string;
  user_prompt: string;
  assistant_text: string;
  plan_json: InvestigationPlan;
  execution_json?: ExecutionPayload | null;
  created_at: string;
};

export type LiveStats = {
  total_events: number;
  detection_alerts: number;
  by_severity: Record<string, number>;
  by_event_type: Record<string, number>;
  top_source_ips: { value: string; count: number }[];
  timeline: { bucket: string; count: number }[];
};

export type InvestigationReport = {
  investigation_id: number;
  title: string;
  generated_at: string;
  summary: string;
  findings: string[];
  evidence: string[];
  recommended_actions: string[];
};

export type ServerResponse = {
  assistant_text: string;
  investigation_plan: InvestigationPlan;
  execution?: ExecutionPayload | null;
  investigation_id?: number;
};
