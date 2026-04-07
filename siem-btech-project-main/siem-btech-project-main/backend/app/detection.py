from __future__ import annotations

from collections import Counter, defaultdict

from .logging_config import get_logger
from .schemas import LogEvent

logger = get_logger("siem.detection")


def _mitre_mapping(tactic: str, technique: str, technique_id: str) -> dict[str, str]:
    return {
        "tactic": tactic,
        "technique": technique,
        "technique_id": technique_id,
    }


def detect_alerts(new_logs: list[LogEvent]) -> list[dict[str, object]]:
    alerts: list[dict[str, object]] = []
    if not new_logs:
        return alerts

    failed_by_ip = Counter(log.source_ip for log in new_logs if log.event_type == "login_failed")
    for source_ip, count in failed_by_ip.items():
        if count >= 8:
            alerts.append(
                {
                    "title": "BRUTE FORCE DETECTED",
                    "severity": "high",
                    "summary": f"{count} failed logins observed from {source_ip} in the latest simulation window.",
                    "details_json": {
                        "rule_name": "brute_force",
                        "threshold": 8,
                        "observed_count": count,
                        "source_ip": source_ip,
                        "event_type": "login_failed",
                        "mitre_attack": _mitre_mapping("Credential Access", "Brute Force", "T1110"),
                    },
                }
            )

    port_scans = Counter(log.source_ip for log in new_logs if log.event_type == "port_scan")
    for source_ip, count in port_scans.items():
        if count >= 5:
            alerts.append(
                {
                    "title": "PORT SCAN DETECTED",
                    "severity": "high",
                    "summary": f"{count} port scan events observed from {source_ip} in the latest simulation window.",
                    "details_json": {
                        "rule_name": "port_scan",
                        "threshold": 5,
                        "observed_count": count,
                        "source_ip": source_ip,
                        "event_type": "port_scan",
                        "mitre_attack": _mitre_mapping("Discovery", "Network Service Scanning", "T1046"),
                    },
                }
            )

    failed_by_user: dict[str, set[str]] = defaultdict(set)
    for log in new_logs:
        if log.event_type == "login_failed" and log.user:
            failed_by_user[log.user].add(log.source_ip)
    for user, ips in failed_by_user.items():
        if len(ips) >= 3:
            alerts.append(
                {
                    "title": "SUSPICIOUS LOGIN FAILURES",
                    "severity": "medium",
                    "summary": f"User {user} had failed logins from {len(ips)} different source IPs in the latest simulation window.",
                    "details_json": {
                        "rule_name": "multi_ip_login_failures",
                        "threshold": 3,
                        "observed_ip_count": len(ips),
                        "user": user,
                        "source_ips": sorted(ips),
                        "event_type": "login_failed",
                        "mitre_attack": _mitre_mapping("Credential Access", "Brute Force", "T1110"),
                    },
                }
            )

    malware_count = sum(1 for log in new_logs if log.event_type == "malware_alert")
    if malware_count >= 2:
        alerts.append(
            {
                "title": "MALWARE ALERT CLUSTER",
                "severity": "critical",
                "summary": f"{malware_count} malware alerts were generated in the latest simulation window.",
                "details_json": {
                    "rule_name": "malware_cluster",
                    "threshold": 2,
                    "observed_count": malware_count,
                    "event_type": "malware_alert",
                },
            }
        )

    severe_count = sum(1 for log in new_logs if log.severity in {"high", "critical"})
    if severe_count >= 6:
        by_severity = Counter(log.severity for log in new_logs if log.severity in {"high", "critical"})
        alerts.append(
            {
                "title": "HIGH SEVERITY SPIKE",
                "severity": "high",
                "summary": f"{severe_count} high or critical severity events arrived in the latest simulation batch.",
                "details_json": {
                    "rule_name": "high_severity_spike",
                    "threshold": 6,
                    "observed_count": severe_count,
                    "severity_breakdown": dict(by_severity),
                },
            }
        )

    if alerts:
        logger.info("Rule detections generated | count=%s", len(alerts))
    else:
        logger.info("Rule detections generated no alerts for latest batch")

    return alerts
