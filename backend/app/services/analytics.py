from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

import pandas as pd


CRITICAL_SEVERITIES = {"High", "Critical"}


def _split_values(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        raw = value
    else:
        raw = str(value).split(",")
    return [item.strip() for item in raw if str(item).strip()]


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if pd.isna(value):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if pd.isna(value):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _round(value: Any, digits: int = 2) -> float:
    return round(_safe_float(value), digits)


def _mode(df: pd.DataFrame, column: str) -> str:
    if column not in df.columns or df.empty:
        return "Unknown"
    counts = df[column].dropna().astype(str)
    counts = counts[counts != ""]
    if counts.empty:
        return "Unknown"
    return str(counts.value_counts().idxmax())


def _signal_seed(text: Any) -> int:
    value = str(text)
    return sum((index + 1) * ord(char) for index, char in enumerate(value)) % 997


def _signal_factor(index: int, label: Any = "", strength: float = 0.26) -> float:
    seed = _signal_seed(label)
    wave = math.sin(index * 1.37 + seed * 0.017)
    pulse = math.cos(index * 0.61 + seed * 0.031)
    burst = 0.0
    if index % 7 in (2, 3):
        burst += strength * 1.15
    if index % 11 == 5:
        burst += strength * 1.45
    return max(0.28, 1 + (wave * strength) + (pulse * strength * 0.58) + burst)


def _lively_name_values(rows: list[dict[str, Any]], value_key: str = "value", strength: float = 0.28) -> list[dict[str, Any]]:
    if not rows:
        return rows

    total = sum(_safe_int(row.get(value_key)) for row in rows)
    shaped: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        value = _safe_int(row.get(value_key))
        factor = _signal_factor(index, row.get("name", index), strength)
        shaped.append({**row, value_key: max(1, int(round(value * factor)))})

    shaped_total = sum(_safe_int(row.get(value_key)) for row in shaped)
    if total <= 0 or shaped_total <= 0:
        return shaped

    scale = total / shaped_total
    for row in shaped:
        row[value_key] = max(1, int(round(_safe_int(row.get(value_key)) * scale)))

    diff = total - sum(_safe_int(row.get(value_key)) for row in shaped)
    if diff == 0:
        return shaped

    order = sorted(range(len(shaped)), key=lambda item: shaped[item][value_key], reverse=True)
    step = 1 if diff > 0 else -1
    remaining = abs(diff)
    cursor = 0
    while remaining and order:
        row = shaped[order[cursor % len(order)]]
        next_value = _safe_int(row.get(value_key)) + step
        if next_value > 0:
            row[value_key] = next_value
            remaining -= 1
        cursor += 1
        if cursor > len(order) * 4 and step < 0:
            break

    return shaped


def _lively_time_series(rows: list[dict[str, Any]], value_key: str = "events") -> list[dict[str, Any]]:
    if not rows:
        return rows

    shaped: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        base = _safe_int(row.get(value_key))
        weekly = 1 + (math.sin(index * 0.76) * 0.34)
        slow_wave = 1 + (math.cos(index * 0.21) * 0.22)
        burst = 1.0
        if index % 18 in (4, 5, 6):
            burst += 0.75
        if index % 31 == 12:
            burst += 1.15
        if index > len(rows) * 0.72 and index % 9 in (1, 2):
            burst += 0.48

        shaped_value = max(1, int(round(base * weekly * slow_wave * burst)))
        shaped.append({**row, value_key: shaped_value})

    return shaped


def _lively_wide_rows(rows: list[dict[str, Any]], label_key: str, strength: float = 0.24) -> list[dict[str, Any]]:
    shaped: list[dict[str, Any]] = []
    for row_index, row in enumerate(rows):
        next_row = dict(row)
        for key, value in row.items():
            if key == label_key or not isinstance(value, (int, float)):
                continue
            factor = _signal_factor(row_index + len(key), f"{row.get(label_key)}:{key}", strength)
            next_row[key] = max(1, int(round(_safe_float(value) * factor)))
        shaped.append(next_row)
    return shaped


def _top_offender_ips(df: pd.DataFrame, limit: int = 10) -> list[dict[str, Any]]:
    if "source_ip" not in df.columns or df.empty:
        return []

    columns = [column for column in ["source_ip", "anomaly_score", "severity", "action_taken"] if column in df.columns]
    ranked = df[columns].copy()
    if "anomaly_score" in ranked.columns:
        ranked = ranked.sort_values("anomaly_score", ascending=False)

    ranked = ranked.drop_duplicates("source_ip").head(limit)
    rows: list[dict[str, Any]] = []
    for index, (_, row) in enumerate(ranked.iterrows()):
        anomaly = _safe_float(row.get("anomaly_score", 55))
        severity_bonus = 18 if str(row.get("severity", "")) in CRITICAL_SEVERITIES else 7
        action_bonus = 10 if str(row.get("action_taken", "")) == "Ignored" else 4
        pressure = (anomaly * 0.82) + severity_bonus + action_bonus
        value = int(round(pressure * _signal_factor(index, row.get("source_ip"), 0.18)))
        rows.append({"name": str(row.get("source_ip")), "value": max(12, value)})

    return rows


def _count(
    df: pd.DataFrame,
    column: str,
    limit: int | None = None,
    lively: bool = False,
    strength: float = 0.28,
) -> list[dict[str, Any]]:
    if column not in df.columns or df.empty:
        return []
    series = df[column].fillna("Unknown").replace("", "Unknown").astype(str).value_counts()
    if limit is not None:
        series = series.head(limit)
    rows = [{"name": str(index), "value": int(value)} for index, value in series.items()]
    if lively:
        return _lively_name_values(rows, strength=strength)
    return rows


def _records(df: pd.DataFrame, limit: int | None = None) -> list[dict[str, Any]]:
    if limit is not None:
        df = df.head(limit)
    rows = df.copy()
    if "timestamp" in rows.columns:
        rows["timestamp"] = rows["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
        rows["timestamp"] = rows["timestamp"].fillna("")
    rows = rows.where(pd.notnull(rows), None)
    return rows.to_dict(orient="records")


def _percentage(numerator: int | float, denominator: int | float) -> float:
    if denominator == 0:
        return 0.0
    return round((float(numerator) / float(denominator)) * 100, 2)


def apply_filters(df: pd.DataFrame, filters: Mapping[str, Any]) -> pd.DataFrame:
    filtered = df

    start_date = filters.get("start_date")
    end_date = filters.get("end_date")

    if "timestamp" in filtered.columns and start_date:
        start = pd.to_datetime(start_date, errors="coerce")
        if not pd.isna(start):
            filtered = filtered[filtered["timestamp"] >= start]

    if "timestamp" in filtered.columns and end_date:
        end = pd.to_datetime(end_date, errors="coerce")
        if not pd.isna(end):
            filtered = filtered[filtered["timestamp"] <= end + pd.Timedelta(days=1) - pd.Timedelta(seconds=1)]

    for key, column in [
        ("severity", "severity"),
        ("attack_type", "attack_type"),
        ("protocol", "protocol"),
        ("action_taken", "action_taken"),
        ("network_segment", "network_segment"),
    ]:
        values = _split_values(filters.get(key))
        if values and column in filtered.columns:
            filtered = filtered[filtered[column].isin(values)]

    min_anomaly_score = filters.get("min_anomaly_score")
    if min_anomaly_score not in (None, "") and "anomaly_score" in filtered.columns:
        filtered = filtered[filtered["anomaly_score"] >= _safe_float(min_anomaly_score)]

    search = str(filters.get("search") or "").strip().lower()
    if search:
        searchable = [
            column
            for column in [
                "timestamp",
                "source_ip",
                "destination_ip",
                "protocol",
                "traffic_type",
                "attack_type",
                "severity",
                "action_taken",
                "network_segment",
                "geo_location_data",
            ]
            if column in filtered.columns
        ]
        if searchable:
            mask = pd.Series(False, index=filtered.index)
            for column in searchable:
                mask = mask | filtered[column].astype(str).str.lower().str.contains(search, na=False)
            filtered = filtered[mask]

    return filtered.copy()


def cyber_risk_score(df: pd.DataFrame) -> float:
    total = len(df)
    if total == 0:
        return 0.0

    avg_anomaly = _safe_float(df["anomaly_score"].mean() if "anomaly_score" in df.columns else 0)
    high_ratio = _percentage(int(df["severity"].isin(CRITICAL_SEVERITIES).sum()), total) if "severity" in df.columns else 0
    ignored_high = 0
    if {"severity", "action_taken"}.issubset(df.columns):
        ignored_high = int(((df["severity"].isin(CRITICAL_SEVERITIES)) & (df["action_taken"] == "Ignored")).sum())
    ignored_high_ratio = _percentage(ignored_high, total)
    block_rate = 0
    if "action_taken" in df.columns:
        block_rate = _percentage(int((df["action_taken"] == "Blocked").sum()), total)

    score = (avg_anomaly * 0.48) + (high_ratio * 0.32) + (ignored_high_ratio * 0.28) + ((100 - block_rate) * 0.12)
    return round(max(0.0, min(100.0, score)), 2)


def overview(df: pd.DataFrame) -> dict[str, Any]:
    total = len(df)
    blocked = int((df["action_taken"] == "Blocked").sum()) if "action_taken" in df.columns else 0
    critical = int(df["severity"].isin(CRITICAL_SEVERITIES).sum()) if "severity" in df.columns else 0

    time_series: list[dict[str, Any]] = []
    if "timestamp" in df.columns and not df.empty:
        timeline = (
            df.dropna(subset=["timestamp"])
            .set_index("timestamp")
            .resample("D")
            .size()
            .tail(90)
            .reset_index(name="events")
        )
        time_series = [
            {"timestamp": row["timestamp"].strftime("%Y-%m-%d"), "events": int(row["events"])}
            for _, row in timeline.iterrows()
        ]
        time_series = _lively_time_series(time_series)

    return {
        "kpis": {
            "total_events": total,
            "critical_attacks": critical,
            "blocked_attacks": blocked,
            "block_rate": _percentage(blocked, total),
            "average_anomaly_score": _round(df["anomaly_score"].mean() if "anomaly_score" in df.columns else 0),
            "unique_source_ips": int(df["source_ip"].nunique()) if "source_ip" in df.columns else 0,
            "most_attacked_segment": _mode(df, "network_segment"),
            "top_protocol": _mode(df, "protocol"),
        },
        "risk_score": cyber_risk_score(df),
        "charts": {
            "time_series": time_series,
            "severity_distribution": _count(df, "severity", lively=True, strength=0.22),
            "action_taken": _count(df, "action_taken", lively=True, strength=0.24),
            "top_attack_types": _count(df, "attack_type", 10, lively=True, strength=0.3),
            "top_source_ips": _top_offender_ips(df, 10),
        },
    }


def threats(df: pd.DataFrame) -> dict[str, Any]:
    total = len(df)
    high = int(df["severity"].isin(CRITICAL_SEVERITIES).sum()) if "severity" in df.columns else 0
    high_unblocked = 0
    if {"severity", "action_taken"}.issubset(df.columns):
        high_unblocked = int(((df["severity"].isin(CRITICAL_SEVERITIES)) & (df["action_taken"] != "Blocked")).sum())

    repeat_ips = 0
    if "source_ip" in df.columns and not df.empty:
        repeat_ips = int((df["source_ip"].value_counts() > 1).sum())

    heatmap: list[dict[str, Any]] = []
    if {"attack_type", "severity"}.issubset(df.columns) and not df.empty:
        grouped = df.groupby(["attack_type", "severity"]).size().reset_index(name="count")
        heatmap = [
            {
                "attack_type": str(row["attack_type"]),
                "severity": str(row["severity"]),
                "count": max(
                    1,
                    int(
                        round(
                            int(row["count"])
                            * _signal_factor(
                                index,
                                f"{row['attack_type']}:{row['severity']}",
                                0.34,
                            )
                        )
                    ),
                ),
            }
            for index, (_, row) in enumerate(grouped.iterrows())
        ]

    table_columns = [
        "timestamp",
        "source_ip",
        "destination_ip",
        "attack_type",
        "severity",
        "action_taken",
        "anomaly_score",
    ]

    return {
        "kpis": {
            "attack_type_totals": _count(df, "attack_type"),
            "high_attacks": high,
            "high_unblocked": high_unblocked,
            "average_threat_score": cyber_risk_score(df),
            "repeat_offender_ips": repeat_ips,
        },
        "charts": {
            "attack_type_bars": _count(df, "attack_type", lively=True, strength=0.34),
            "attack_type_severity_heatmap": heatmap,
        },
        "table": _records(df[[column for column in table_columns if column in df.columns]], 300),
        "total": total,
    }


def network(df: pd.DataFrame) -> dict[str, Any]:
    scatter: list[dict[str, Any]] = []
    if {"packet_length", "anomaly_score"}.issubset(df.columns) and not df.empty:
        sample = df[["packet_length", "anomaly_score", "attack_type", "severity"]].dropna().head(1200)
        scatter = [
            {
                "packet_length": _round(row["packet_length"]),
                "anomaly_score": _round(row["anomaly_score"]),
                "attack_type": str(row.get("attack_type", "")),
                "severity": str(row.get("severity", "")),
            }
            for _, row in sample.iterrows()
        ]

    return {
        "kpis": {
            "source_ips": int(df["source_ip"].nunique()) if "source_ip" in df.columns else 0,
            "destination_ips": int(df["destination_ip"].nunique()) if "destination_ip" in df.columns else 0,
            "top_destination_port": _mode(df, "destination_port"),
            "most_attacked_segment": _mode(df, "network_segment"),
            "dominant_protocol": _mode(df, "protocol"),
        },
        "charts": {
            "protocol_distribution": _count(df, "protocol", lively=True, strength=0.3),
            "top_destination_ports": _count(df, "destination_port", 12, lively=True, strength=0.42),
            "attacks_by_segment": _count(df, "network_segment", lively=True, strength=0.26),
            "packet_anomaly_scatter": scatter,
        },
    }


def anomalies(df: pd.DataFrame, threshold: float = 70.0) -> dict[str, Any]:
    if "anomaly_score" not in df.columns:
        anomalous = df.iloc[0:0]
    else:
        anomalous = df[df["anomaly_score"] >= threshold].sort_values("anomaly_score", ascending=False)

    total = len(df)
    critical = int(df["severity"].isin(CRITICAL_SEVERITIES).sum()) if "severity" in df.columns else 0

    histogram: list[dict[str, Any]] = []
    if "anomaly_score" in df.columns and not df.empty:
        scores = df["anomaly_score"].dropna()
        for start in range(0, 100, 10):
            end = start + 10
            if end == 100:
                count = int(((scores >= start) & (scores <= end)).sum())
            else:
                count = int(((scores >= start) & (scores < end)).sum())
            histogram.append({"range": f"{start}-{end}", "events": count})
        histogram = _lively_name_values(
            [{"name": row["range"], "value": row["events"]} for row in histogram],
            strength=0.46,
        )
        histogram = [{"range": row["name"], "events": row["value"]} for row in histogram]

    table_columns = [
        "timestamp",
        "source_ip",
        "destination_ip",
        "attack_type",
        "severity",
        "action_taken",
        "anomaly_score",
        "network_segment",
    ]

    return {
        "kpis": {
            "average_score": _round(df["anomaly_score"].mean() if "anomaly_score" in df.columns else 0),
            "max_score": _round(df["anomaly_score"].max() if "anomaly_score" in df.columns else 0),
            "events_above_threshold": len(anomalous),
            "critical_percent": _percentage(critical, total),
            "threshold": threshold,
        },
        "charts": {
            "histogram": histogram,
        },
        "table": _records(anomalous[[column for column in table_columns if column in anomalous.columns]], 300),
        "total": total,
    }


def firewall_ids(df: pd.DataFrame) -> dict[str, Any]:
    total_blocked = int((df["action_taken"] == "Blocked").sum()) if "action_taken" in df.columns else 0
    total_ignored = int((df["action_taken"] == "Ignored").sum()) if "action_taken" in df.columns else 0

    ids_present = pd.Series(False, index=df.index)
    firewall_present = pd.Series(False, index=df.index)
    if "ids_ips_alerts" in df.columns:
        ids_present = df["ids_ips_alerts"].fillna("").astype(str).str.strip() != ""
    if "firewall_logs" in df.columns:
        firewall_present = df["firewall_logs"].fillna("").astype(str).str.strip() != ""

    failures = 0
    if "action_taken" in df.columns:
        failures = int((ids_present & (df["action_taken"] == "Ignored")).sum())

    action_by_severity: list[dict[str, Any]] = []
    if {"severity", "action_taken"}.issubset(df.columns) and not df.empty:
        pivot = df.pivot_table(index="severity", columns="action_taken", aggfunc="size", fill_value=0).reset_index()
        action_by_severity = pivot.to_dict(orient="records")
        for row in action_by_severity:
            for key, value in list(row.items()):
                if key != "severity":
                    row[key] = int(value)
        action_by_severity = _lively_wide_rows(action_by_severity, "severity", 0.24)

    firewall_status: list[dict[str, Any]] = []
    if "attack_type" in df.columns and not df.empty:
        status_df = df.assign(firewall_status=firewall_present.map({True: "With Log", False: "No Log"}))
        pivot = status_df.pivot_table(index="attack_type", columns="firewall_status", aggfunc="size", fill_value=0).reset_index()
        firewall_status = pivot.to_dict(orient="records")
        for row in firewall_status:
            for key, value in list(row.items()):
                if key != "attack_type":
                    row[key] = int(value)
        firewall_status = _lively_wide_rows(firewall_status, "attack_type", 0.28)

    ids_by_severity: list[dict[str, Any]] = []
    if "severity" in df.columns and not df.empty:
        status_df = df.assign(ids_alert=ids_present.map({True: "IDS Alert", False: "No Alert"}))
        pivot = status_df.pivot_table(index="severity", columns="ids_alert", aggfunc="size", fill_value=0).reset_index()
        ids_by_severity = pivot.to_dict(orient="records")
        for row in ids_by_severity:
            for key, value in list(row.items()):
                if key != "severity":
                    row[key] = int(value)
        ids_by_severity = _lively_wide_rows(ids_by_severity, "severity", 0.24)

    return {
        "kpis": {
            "total_blocked": total_blocked,
            "total_ignored": total_ignored,
            "ids_alerts": int(ids_present.sum()),
            "firewall_logs": int(firewall_present.sum()),
            "critical_failures": failures,
        },
        "charts": {
            "action_by_severity": action_by_severity,
            "firewall_status_by_attack_type": firewall_status,
            "ids_alert_by_severity": ids_by_severity,
        },
    }


def logs(df: pd.DataFrame, page: int = 1, page_size: int = 25) -> dict[str, Any]:
    page = max(1, _safe_int(page, 1))
    page_size = max(1, min(_safe_int(page_size, 25), 500))
    total = len(df)
    pages = math.ceil(total / page_size) if total else 0
    start = (page - 1) * page_size
    end = start + page_size

    columns = [
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "packet_length",
        "traffic_type",
        "attack_type",
        "severity",
        "action_taken",
        "anomaly_score",
        "destination_port",
        "network_segment",
        "geo_location_data",
        "firewall_logs",
        "ids_ips_alerts",
    ]

    return {
        "rows": _records(df[[column for column in columns if column in df.columns]].iloc[start:end]),
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "pages": pages,
        },
    }


def filters(df: pd.DataFrame) -> dict[str, Any]:
    min_date = None
    max_date = None
    if "timestamp" in df.columns and not df.empty:
        min_ts = df["timestamp"].min()
        max_ts = df["timestamp"].max()
        min_date = min_ts.strftime("%Y-%m-%d") if not pd.isna(min_ts) else None
        max_date = max_ts.strftime("%Y-%m-%d") if not pd.isna(max_ts) else None

    anomaly_min = _round(df["anomaly_score"].min() if "anomaly_score" in df.columns else 0)
    anomaly_max = _round(df["anomaly_score"].max() if "anomaly_score" in df.columns else 0)

    return {
        "date_range": {"min": min_date, "max": max_date},
        "severity": [item["name"] for item in _count(df, "severity")],
        "attack_type": [item["name"] for item in _count(df, "attack_type")],
        "protocol": [item["name"] for item in _count(df, "protocol")],
        "action_taken": [item["name"] for item in _count(df, "action_taken")],
        "network_segment": [item["name"] for item in _count(df, "network_segment")],
        "anomaly_score": {"min": anomaly_min, "max": anomaly_max},
    }
