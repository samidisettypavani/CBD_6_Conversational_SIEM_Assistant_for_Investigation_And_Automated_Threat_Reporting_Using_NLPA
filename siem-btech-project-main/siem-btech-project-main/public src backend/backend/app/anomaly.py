from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from statistics import mean

from sklearn.ensemble import IsolationForest

from .logging_config import get_logger
from .schemas import LogEvent

logger = get_logger("siem.anomaly")

BUCKET_MINUTES = 15
BASELINE_HOURS = 48


def _bucket_start(ts: str) -> datetime:
    event_time = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
    minute_bucket = (event_time.minute // BUCKET_MINUTES) * BUCKET_MINUTES
    return event_time.replace(minute=minute_bucket, second=0, microsecond=0)


def _bucket_key(ts: str) -> str:
    return _bucket_start(ts).strftime("%Y-%m-%d %H:%M")


def _group_by_bucket(logs: list[LogEvent]) -> dict[str, list[LogEvent]]:
    grouped: dict[str, list[LogEvent]] = defaultdict(list)
    for log in logs:
        grouped[_bucket_key(log.ts)].append(log)
    return dict(grouped)


def _auth_features(logs: list[LogEvent]) -> tuple[list[int], dict[str, object]]:
    failed_by_ip = Counter(log.source_ip for log in logs if log.event_type == "login_failed")
    failed_by_user = Counter(log.user for log in logs if log.event_type == "login_failed" and log.user)
    login_failed_count = sum(1 for log in logs if log.event_type == "login_failed")
    login_success_count = sum(1 for log in logs if log.event_type == "login_success")
    unique_source_ips = len({log.source_ip for log in logs})
    unique_users = len({log.user for log in logs if log.user})
    unique_hosts = len({log.host for log in logs if log.host})
    max_failures_single_ip = failed_by_ip.most_common(1)[0][1] if failed_by_ip else 0
    max_failures_single_user = failed_by_user.most_common(1)[0][1] if failed_by_user else 0

    feature_map = {
        "event_count": len(logs),
        "failed_login_count": login_failed_count,
        "login_success_count": login_success_count,
        "unique_source_ip_count": unique_source_ips,
        "unique_user_count": unique_users,
        "unique_host_count": unique_hosts,
        "max_failures_single_ip": max_failures_single_ip,
        "max_failures_single_user": max_failures_single_user,
    }
    return list(feature_map.values()), feature_map


def _threat_features(logs: list[LogEvent]) -> tuple[list[int], dict[str, object]]:
    high_severity_count = sum(1 for log in logs if log.severity in {"high", "critical"})
    critical_count = sum(1 for log in logs if log.severity == "critical")
    malware_alert_count = sum(1 for log in logs if log.event_type == "malware_alert")
    port_scan_count = sum(1 for log in logs if log.event_type == "port_scan")
    waf_block_count = sum(1 for log in logs if log.event_type == "waf_block")
    unique_hosts = len({log.host for log in logs if log.host})
    unique_source_ips = len({log.source_ip for log in logs})

    feature_map = {
        "event_count": len(logs),
        "high_severity_count": high_severity_count,
        "critical_count": critical_count,
        "malware_alert_count": malware_alert_count,
        "port_scan_count": port_scan_count,
        "waf_block_count": waf_block_count,
        "unique_host_count": unique_hosts,
        "unique_source_ip_count": unique_source_ips,
    }
    return list(feature_map.values()), feature_map


def _fit_predict(
    model_name: str,
    feature_matrix: list[list[int]],
    latest_features: list[int],
    contamination: float,
) -> tuple[int, float]:
    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(feature_matrix)
    prediction = int(model.predict([latest_features])[0])
    score = float(model.decision_function([latest_features])[0])
    logger.info("ML model evaluated | model=%s | score=%s | prediction=%s", model_name, round(score, 4), prediction)
    return prediction, score


def _baseline_summary(feature_maps: list[dict[str, object]]) -> dict[str, float]:
    if not feature_maps:
        return {}

    numeric_keys = [key for key, value in feature_maps[0].items() if isinstance(value, (int, float))]
    summary: dict[str, float] = {}
    for key in numeric_keys:
        values = [float(feature_map[key]) for feature_map in feature_maps if isinstance(feature_map.get(key), (int, float))]
        if values:
            summary[key] = round(mean(values), 2)
    return summary


def _feature_deviations(current: dict[str, object], baseline: dict[str, float]) -> list[dict[str, object]]:
    deviations: list[dict[str, object]] = []
    for key, value in current.items():
        if not isinstance(value, (int, float)):
            continue
        baseline_value = baseline.get(key)
        if baseline_value is None:
            continue
        raw_delta = float(value) - baseline_value
        if baseline_value == 0:
            deviation_pct = 100.0 if raw_delta > 0 else 0.0
        else:
            deviation_pct = (raw_delta / baseline_value) * 100
        deviations.append(
            {
                "feature": key,
                "current": round(float(value), 2),
                "baseline_avg": round(baseline_value, 2),
                "delta": round(raw_delta, 2),
                "deviation_pct": round(deviation_pct, 2),
            }
        )

    deviations.sort(key=lambda item: abs(float(item["deviation_pct"])), reverse=True)
    return deviations[:5]


def _entity_anomalies(new_logs: list[LogEvent], recent_logs: list[LogEvent]) -> dict[str, list[dict[str, object]]]:
    baseline_failed_ip_counts = Counter(log.source_ip for log in recent_logs if log.event_type == "login_failed")
    current_failed_ip_counts = Counter(log.source_ip for log in new_logs if log.event_type == "login_failed")
    baseline_failed_user_counts = Counter(log.user for log in recent_logs if log.event_type == "login_failed" and log.user)
    current_failed_user_counts = Counter(log.user for log in new_logs if log.event_type == "login_failed" and log.user)
    baseline_host_counts = Counter(log.host for log in recent_logs if log.host)
    current_host_counts = Counter(log.host for log in new_logs if log.host)

    def build(current_counter: Counter, baseline_counter: Counter, label: str) -> list[dict[str, object]]:
        anomalies: list[dict[str, object]] = []
        for entity, current_count in current_counter.items():
            if not entity:
                continue
            baseline_count = baseline_counter.get(entity, 0)
            if current_count >= max(3, baseline_count + 3):
                ratio = round(current_count / max(baseline_count, 1), 2)
                anomalies.append(
                    {
                        label: entity,
                        "current_count": current_count,
                        "baseline_count": baseline_count,
                        "ratio_vs_baseline": ratio,
                    }
                )
        anomalies.sort(key=lambda item: (float(item["ratio_vs_baseline"]), int(item["current_count"])), reverse=True)
        return anomalies[:5]

    return {
        "source_ip_spikes": build(current_failed_ip_counts, baseline_failed_ip_counts, "source_ip"),
        "user_spikes": build(current_failed_user_counts, baseline_failed_user_counts, "user"),
        "host_spikes": build(current_host_counts, baseline_host_counts, "host"),
    }


def _build_alert(
    *,
    title: str,
    summary: str,
    severity: str,
    model_name: str,
    score: float,
    feature_map: dict[str, object],
    baseline_summary: dict[str, float],
    top_deviations: list[dict[str, object]],
    entity_anomalies: dict[str, list[dict[str, object]]],
    top_source_ip: str | None,
    top_user: str | None,
    mitre_attack: dict[str, str] | None = None,
) -> dict[str, object]:
    details = {
        "model": model_name,
        "bucket_minutes": BUCKET_MINUTES,
        "baseline_window_hours": BASELINE_HOURS,
        "score": round(score, 4),
        "feature_map": feature_map,
        "baseline_summary": baseline_summary,
        "top_feature_deviations": top_deviations,
        "entity_anomalies": entity_anomalies,
        "top_source_ip": top_source_ip,
        "top_user": top_user,
    }
    if mitre_attack:
        details["mitre_attack"] = mitre_attack

    return {
        "title": title,
        "severity": severity,
        "summary": summary,
        "details_json": details,
    }


def detect_anomaly_alerts(all_logs: list[LogEvent], new_logs: list[LogEvent]) -> list[dict[str, object]]:
    if len(all_logs) < 40 or len(new_logs) < 6:
        logger.info("ML anomaly detection skipped | insufficient data")
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(hours=BASELINE_HOURS)
    recent_logs = [
        log for log in all_logs if datetime.fromisoformat(log.ts.replace("Z", "+00:00")).astimezone(timezone.utc) >= cutoff
    ]
    if len(recent_logs) < 30:
        logger.info("ML anomaly detection skipped | not enough recent logs")
        return []

    grouped = _group_by_bucket(recent_logs)
    ordered_buckets = sorted(grouped.keys())
    if len(ordered_buckets) < 12:
        logger.info("ML anomaly detection skipped | not enough time buckets")
        return []

    auth_feature_matrix: list[list[int]] = []
    threat_feature_matrix: list[list[int]] = []
    auth_feature_maps: list[dict[str, object]] = []
    threat_feature_maps: list[dict[str, object]] = []
    for bucket in ordered_buckets:
        auth_features, auth_map = _auth_features(grouped[bucket])
        threat_features, threat_map = _threat_features(grouped[bucket])
        auth_feature_matrix.append(auth_features)
        threat_feature_matrix.append(threat_features)
        auth_feature_maps.append(auth_map)
        threat_feature_maps.append(threat_map)

    latest_auth_features, latest_auth_map = _auth_features(new_logs)
    latest_threat_features, latest_threat_map = _threat_features(new_logs)
    auth_baseline = _baseline_summary(auth_feature_maps)
    threat_baseline = _baseline_summary(threat_feature_maps)
    auth_deviations = _feature_deviations(latest_auth_map, auth_baseline)
    threat_deviations = _feature_deviations(latest_threat_map, threat_baseline)
    entity_anomalies = _entity_anomalies(new_logs, recent_logs)
    top_source_ip = Counter(log.source_ip for log in new_logs).most_common(1)
    top_user = Counter(log.user for log in new_logs if log.user).most_common(1)
    top_source_ip_value = top_source_ip[0][0] if top_source_ip else None
    top_user_value = top_user[0][0] if top_user else None

    alerts: list[dict[str, object]] = []

    auth_prediction, auth_score = _fit_predict(
        "IsolationForest-Auth",
        auth_feature_matrix,
        latest_auth_features,
        contamination=0.12,
    )
    if auth_prediction == -1:
        logger.info(
            "ML auth anomaly generated alert | score=%s | top_source_ip=%s | top_user=%s",
            round(auth_score, 4),
            top_source_ip_value,
            top_user_value,
        )
        alerts.append(
            _build_alert(
                title="AUTHENTICATION ANOMALY DETECTED",
                summary="The authentication anomaly model flagged the latest batch as unusual compared with recent login behavior.",
                severity="high"
                if int(latest_auth_map["failed_login_count"]) >= 10 or int(latest_auth_map["max_failures_single_ip"]) >= 8
                else "medium",
                model_name="IsolationForest-Auth",
                score=auth_score,
                feature_map=latest_auth_map,
                baseline_summary=auth_baseline,
                top_deviations=auth_deviations,
                entity_anomalies={
                    "source_ip_spikes": entity_anomalies["source_ip_spikes"],
                    "user_spikes": entity_anomalies["user_spikes"],
                },
                top_source_ip=top_source_ip_value,
                top_user=top_user_value,
                mitre_attack={
                    "tactic": "Credential Access",
                    "technique": "Brute Force",
                    "technique_id": "T1110",
                },
            )
        )

    threat_prediction, threat_score = _fit_predict(
        "IsolationForest-Threat",
        threat_feature_matrix,
        latest_threat_features,
        contamination=0.1,
    )
    if threat_prediction == -1:
        logger.info(
            "ML threat anomaly generated alert | score=%s | top_source_ip=%s | top_user=%s",
            round(threat_score, 4),
            top_source_ip_value,
            top_user_value,
        )
        alerts.append(
            _build_alert(
                title="THREAT PATTERN ANOMALY DETECTED",
                summary="The threat-severity anomaly model flagged the latest batch as unusual compared with recent security event patterns.",
                severity="high"
                if int(latest_threat_map["critical_count"]) >= 1 or int(latest_threat_map["malware_alert_count"]) >= 2
                else "medium",
                model_name="IsolationForest-Threat",
                score=threat_score,
                feature_map=latest_threat_map,
                baseline_summary=threat_baseline,
                top_deviations=threat_deviations,
                entity_anomalies={
                    "host_spikes": entity_anomalies["host_spikes"],
                    "source_ip_spikes": entity_anomalies["source_ip_spikes"],
                },
                top_source_ip=top_source_ip_value,
                top_user=top_user_value,
                mitre_attack=(
                    {
                        "tactic": "Discovery",
                        "technique": "Network Service Scanning",
                        "technique_id": "T1046",
                    }
                    if int(latest_threat_map["port_scan_count"]) >= 3
                    else None
                ),
            )
        )

    if not alerts:
        logger.info("ML anomaly detection found no anomaly across models")

    return alerts
