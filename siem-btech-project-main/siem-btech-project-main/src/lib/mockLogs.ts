export type LogEvent = {
  ts: string; // ISO
  event_type: string; // login_failed, login_success, port_scan, malware_alert...
  source_ip: string;
  destination_ip?: string;
  user?: string;
  host?: string;
  severity: "low" | "medium" | "high" | "critical";
  message: string;
};

const USERS = ["admin", "root", "umesh", "analyst", "devops", "john", "mary"];
const HOSTS = ["vpn-gateway-1", "app-01", "db-01", "mail-01", "jumpbox-1", "waf-01"];
const IPS = ["8.8.8.8", "1.1.1.1", "45.33.32.156", "203.0.113.10", "198.51.100.23", "10.0.0.5", "10.0.0.8"];

function pick<T>(arr: T[]) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function isoMinutesAgo(minAgo: number) {
  const d = new Date(Date.now() - minAgo * 60_000);
  return d.toISOString();
}

/**
 * Generates deterministic-ish mock logs (fresh timestamps each run).
 * Use count ~200-500 for demo.
 */
export function generateMockLogs(count = 250): LogEvent[] {
  const logs: LogEvent[] = [];

  for (let i = 0; i < count; i++) {
    const eventSeed = Math.random();
    let event_type: LogEvent["event_type"] = "login_failed";
    let severity: LogEvent["severity"] = "medium";

    if (eventSeed < 0.45) {
      event_type = "login_failed";
      severity = Math.random() < 0.25 ? "high" : "medium";
    } else if (eventSeed < 0.70) {
      event_type = "login_success";
      severity = "low";
    } else if (eventSeed < 0.85) {
      event_type = "port_scan";
      severity = Math.random() < 0.35 ? "high" : "medium";
    } else if (eventSeed < 0.95) {
      event_type = "waf_block";
      severity = "medium";
    } else {
      event_type = "malware_alert";
      severity = Math.random() < 0.4 ? "critical" : "high";
    }

    const user = Math.random() < 0.75 ? pick(USERS) : undefined;
    const host = pick(HOSTS);

    // Bias: external IPs appear more often for suspicious events
    const source_ip =
      event_type === "login_failed" || event_type === "port_scan" || event_type === "malware_alert"
        ? pick(IPS.slice(0, 5))
        : pick(IPS);

    const destination_ip = Math.random() < 0.5 ? pick(["10.0.0.10", "10.0.0.11", "10.0.0.12"]) : undefined;

    const minutesAgo = Math.floor(Math.random() * 60 * 24 * 7); // up to last 7 days
    const ts = isoMinutesAgo(minutesAgo);

    const message =
      event_type === "login_failed"
        ? `Failed login${user ? ` for ${user}` : ""} from ${source_ip} on ${host}`
        : event_type === "login_success"
        ? `Successful login${user ? ` for ${user}` : ""} from ${source_ip} on ${host}`
        : event_type === "port_scan"
        ? `Port scan detected from ${source_ip} targeting ${host}`
        : event_type === "waf_block"
        ? `WAF blocked suspicious request from ${source_ip} on ${host}`
        : `Malware alert triggered on ${host}${user ? ` (user: ${user})` : ""}`;

    logs.push({
      ts,
      event_type,
      source_ip,
      destination_ip,
      user,
      host,
      severity,
      message,
    });
  }

  // Add a small “brute-force” cluster for demo realism
  const bruteIp = "45.33.32.156";
  for (let j = 0; j < 18; j++) {
    logs.push({
      ts: isoMinutesAgo(10 + j),
      event_type: "login_failed",
      source_ip: bruteIp,
      user: "admin",
      host: "vpn-gateway-1",
      severity: j > 12 ? "high" : "medium",
      message: `Failed login for admin from ${bruteIp} on vpn-gateway-1`,
    });
  }

  return logs.sort((a, b) => b.ts.localeCompare(a.ts));
}