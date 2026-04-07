import type { LogEvent } from "./mockLogs";
import type { InvestigationPlan } from "./siemTypes";

export type ExecutionResult = {
  matched: LogEvent[];
  stats: {
    total: number;
    byEventType: Record<string, number>;
    bySeverity: Record<string, number>;
    topSourceIps: { value: string; count: number }[];
    topUsers: { value: string; count: number }[];
    timeWindowUsed: string;
    bruteForceDetected: boolean;
    topHosts: { value: string; count: number }[];
  };
};

function topK(items: string[], k: number) {
  const m = new Map<string, number>();
  for (const it of items) m.set(it, (m.get(it) || 0) + 1);
  return [...m.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, k)
    .map(([value, count]) => ({ value, count }));
}

function withinLastHours(ts: string, hours: number) {
  const t = new Date(ts).getTime();
  const now = Date.now();
  return now - t <= hours * 3600 * 1000;
}

function withinLastDays(ts: string, days: number) {
  return withinLastHours(ts, days * 24);
}

function normalize(s: unknown) {
  return String(s ?? "").trim().toLowerCase();
}

export function executeInvestigationPlan(plan: InvestigationPlan, logs: LogEvent[]): ExecutionResult {
  const filters = plan?.filters || {};
  let filtered = [...logs];

  // ---- time_range parsing (simple but effective for demo)
  const tr = normalize(plan?.time_range);
  let timeWindowUsed = tr || "none";

  const mHours = tr.match(/last\s+(\d+)\s*hour/);
  const mDays = tr.match(/last\s+(\d+)\s*day/);
  if (mHours) {
    const hours = parseInt(mHours[1], 10);
    filtered = filtered.filter((l) => withinLastHours(l.ts, hours));
    timeWindowUsed = `last ${hours} hours`;
  } else if (mDays) {
    const days = parseInt(mDays[1], 10);
    filtered = filtered.filter((l) => withinLastDays(l.ts, days));
    timeWindowUsed = `last ${days} days`;
  }

  // ---- filters (flat map)
  if (filters.event_type) filtered = filtered.filter((l) => l.event_type === filters.event_type);
  if (filters.source_ip) filtered = filtered.filter((l) => l.source_ip === filters.source_ip);
  if (filters.destination_ip) filtered = filtered.filter((l) => l.destination_ip === filters.destination_ip);
  if (filters.user) filtered = filtered.filter((l) => l.user === filters.user);
  if (filters.host) filtered = filtered.filter((l) => l.host === filters.host);
  if (filters.severity) filtered = filtered.filter((l) => l.severity === filters.severity);

  const limit = Math.min(Number(plan?.limit ?? 100), 500);

  const byEventType: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  for (const e of filtered) {
    byEventType[e.event_type] = (byEventType[e.event_type] || 0) + 1;
    bySeverity[e.severity] = (bySeverity[e.severity] || 0) + 1;
  }

  const topSourceIps = topK(filtered.map((l) => l.source_ip), 5);
  const topUsers = topK(filtered.map((l) => l.user ?? "unknown"), 5);
  const topHosts = topK(filtered.map((l) => l.host ?? "unknown"), 5);
  const bruteForceDetected =
    filters.event_type === "login_failed" &&
    (topSourceIps[0]?.count ?? 0) >= 10;

  return {
    matched: filtered.slice(0, limit),
    stats: {
      total: filtered.length,
      byEventType,
      bySeverity,
      topSourceIps,
      topUsers,
      timeWindowUsed,
      bruteForceDetected,
      topHosts,
    },
  };
}
