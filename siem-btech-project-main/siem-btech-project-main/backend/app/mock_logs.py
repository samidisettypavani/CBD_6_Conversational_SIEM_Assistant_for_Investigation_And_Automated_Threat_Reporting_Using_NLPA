from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from .schemas import LogEvent

USERS = ["admin", "root", "umesh", "analyst", "devops", "john", "mary"]
HOSTS = ["vpn-gateway-1", "app-01", "db-01", "mail-01", "jumpbox-1", "waf-01"]
IPS = ["8.8.8.8", "1.1.1.1", "45.33.32.156", "203.0.113.10", "198.51.100.23", "10.0.0.5", "10.0.0.8"]
INTERNAL_IPS = ["10.0.0.5", "10.0.0.8", "10.0.0.10", "10.0.0.11", "10.0.0.12"]
EXTERNAL_IPS = ["8.8.8.8", "1.1.1.1", "45.33.32.156", "203.0.113.10", "198.51.100.23"]
POWER_USERS = {"analyst", "devops", "umesh"}


def _pick(items: list[str]) -> str:
    return random.choice(items)


def _iso_minutes_ago(minutes_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()


def _weighted_choice(weight_map: dict[str, float]) -> str:
    items = list(weight_map.keys())
    weights = list(weight_map.values())
    return random.choices(items, weights=weights, k=1)[0]


def _profile_for_time(ts: datetime) -> dict[str, object]:
    hour = ts.hour
    weekday = ts.weekday()
    business_hours = weekday < 5 and 8 <= hour <= 18
    late_night = hour < 6 or hour >= 22

    if business_hours:
        return {
            "event_weights": {
                "login_success": 0.48,
                "login_failed": 0.24,
                "waf_block": 0.12,
                "port_scan": 0.08,
                "malware_alert": 0.08,
            },
            "user_pool": ["analyst", "devops", "umesh", "john", "mary", "admin"],
            "host_pool": ["app-01", "db-01", "mail-01", "waf-01", "vpn-gateway-1"],
            "source_pool": INTERNAL_IPS + ["203.0.113.10", "198.51.100.23"],
        }

    if late_night:
        return {
            "event_weights": {
                "login_success": 0.18,
                "login_failed": 0.36,
                "waf_block": 0.18,
                "port_scan": 0.18,
                "malware_alert": 0.10,
            },
            "user_pool": ["admin", "root", "umesh", "analyst"],
            "host_pool": ["vpn-gateway-1", "jumpbox-1", "waf-01", "db-01"],
            "source_pool": EXTERNAL_IPS + ["10.0.0.5"],
        }

    return {
        "event_weights": {
            "login_success": 0.33,
            "login_failed": 0.30,
            "waf_block": 0.16,
            "port_scan": 0.11,
            "malware_alert": 0.10,
        },
        "user_pool": USERS,
        "host_pool": HOSTS,
        "source_pool": IPS,
    }


def _build_log(ts: datetime, event_type: str, user: str | None, host: str, source_ip: str) -> LogEvent:
    destination_ip = _pick(["10.0.0.10", "10.0.0.11", "10.0.0.12"]) if random.random() < 0.45 else None

    if event_type == "login_failed":
        severity = "high" if source_ip in EXTERNAL_IPS and random.random() < 0.35 else "medium"
        message = f"Failed login{' for ' + user if user else ''} from {source_ip} on {host}"
    elif event_type == "login_success":
        severity = "low"
        message = f"Successful login{' for ' + user if user else ''} from {source_ip} on {host}"
    elif event_type == "port_scan":
        severity = "high" if random.random() < 0.55 else "medium"
        message = f"Port scan detected from {source_ip} targeting {host}"
    elif event_type == "waf_block":
        severity = "medium"
        message = f"WAF blocked suspicious request from {source_ip} on {host}"
    else:
        severity = "critical" if random.random() < 0.45 else "high"
        message = f"Malware alert triggered on {host}{' (user: ' + user + ')' if user else ''}"

    return LogEvent(
        ts=ts.isoformat(),
        event_type=event_type,
        source_ip=source_ip,
        destination_ip=destination_ip,
        user=user,
        host=host,
        severity=severity,  # type: ignore[arg-type]
        message=message,
    )


def generate_mock_logs(count: int = 250) -> list[LogEvent]:
    logs: list[LogEvent] = []

    for _ in range(count):
        minutes_ago = random.randint(0, 60 * 24 * 7)
        ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
        profile = _profile_for_time(ts)
        event_type = _weighted_choice(profile["event_weights"])  # type: ignore[arg-type]
        user_pool = profile["user_pool"]  # type: ignore[assignment]
        host_pool = profile["host_pool"]  # type: ignore[assignment]
        source_pool = profile["source_pool"]  # type: ignore[assignment]
        user = _pick(user_pool) if random.random() < 0.82 else None
        host = _pick(host_pool)
        source_ip = _pick(source_pool)
        if event_type == "login_success" and user in POWER_USERS and random.random() < 0.45:
            host = _pick(["app-01", "db-01", "mail-01"])
        logs.append(_build_log(ts, event_type, user, host, source_ip))

    brute_ip = "45.33.32.156"
    for idx in range(18):
        ts = datetime.now(timezone.utc) - timedelta(minutes=10 + idx)
        logs.append(_build_log(ts, "login_failed", "admin", "vpn-gateway-1", brute_ip))

    logs.sort(key=lambda item: item.ts, reverse=True)
    return logs


def generate_live_batch(count: int = 6) -> list[LogEvent]:
    now = datetime.now(timezone.utc)
    profile = _profile_for_time(now)
    batch: list[LogEvent] = []

    scenario_roll = random.random()
    if scenario_roll < 0.18:
        attacker_ip = "45.33.32.156"
        target_user = random.choice(["admin", "root"])
        target_host = random.choice(["vpn-gateway-1", "jumpbox-1"])
        burst_count = max(count, random.randint(10, 16))
        for offset in range(burst_count):
            ts = now - timedelta(seconds=offset * 20)
            batch.append(_build_log(ts, "login_failed", target_user, target_host, attacker_ip))
    elif scenario_roll < 0.30:
        scanner_ip = random.choice(["203.0.113.10", "198.51.100.23"])
        burst_count = max(count, random.randint(8, 12))
        for offset in range(burst_count):
            ts = now - timedelta(seconds=offset * 25)
            batch.append(_build_log(ts, "port_scan", None, _pick(HOSTS), scanner_ip))
    elif scenario_roll < 0.40:
        host = random.choice(["app-01", "mail-01", "db-01"])
        burst_count = max(count, random.randint(6, 10))
        for offset in range(burst_count):
            ts = now - timedelta(seconds=offset * 35)
            batch.append(_build_log(ts, "malware_alert", random.choice(USERS), host, random.choice(EXTERNAL_IPS)))
    elif scenario_roll < 0.52:
        suspicious_user = random.choice(["admin", "analyst", "umesh"])
        ip_choices = random.sample(EXTERNAL_IPS, k=min(4, len(EXTERNAL_IPS)))
        for idx, source_ip in enumerate(ip_choices):
            ts = now - timedelta(seconds=idx * 45)
            batch.append(_build_log(ts, "login_failed", suspicious_user, "vpn-gateway-1", source_ip))
        while len(batch) < count:
            ts = now - timedelta(seconds=len(batch) * 50)
            batch.append(_build_log(ts, "login_failed", suspicious_user, "vpn-gateway-1", random.choice(ip_choices)))
    else:
        for offset in range(count):
            ts = now - timedelta(seconds=offset * 40)
            event_type = _weighted_choice(profile["event_weights"])  # type: ignore[arg-type]
            user_pool = profile["user_pool"]  # type: ignore[assignment]
            host_pool = profile["host_pool"]  # type: ignore[assignment]
            source_pool = profile["source_pool"]  # type: ignore[assignment]
            user = _pick(user_pool) if random.random() < 0.85 else None
            host = _pick(host_pool)
            source_ip = _pick(source_pool)
            batch.append(_build_log(ts, event_type, user, host, source_ip))

    batch.sort(key=lambda item: item.ts, reverse=True)
    return batch
