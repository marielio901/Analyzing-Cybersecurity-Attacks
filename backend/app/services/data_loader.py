from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[3]
CSV_PATH = Path(os.getenv("CYBER_CSV_PATH", PROJECT_ROOT / "cybersecurity_attacks.csv"))


ALIASES = {
    "source_ip_address": "source_ip",
    "destination_ip_address": "destination_ip",
    "anomaly_scores": "anomaly_score",
    "severity_level": "severity",
    "ids_ips_alerts": "ids_ips_alerts",
    "geo_location_data": "geo_location_data",
}

TEXT_COLUMNS = [
    "source_ip",
    "destination_ip",
    "protocol",
    "packet_type",
    "traffic_type",
    "malware_indicators",
    "alerts_warnings",
    "attack_type",
    "attack_signature",
    "action_taken",
    "severity",
    "user_information",
    "device_information",
    "network_segment",
    "geo_location_data",
    "proxy_information",
    "firewall_logs",
    "ids_ips_alerts",
    "log_source",
]

NUMERIC_COLUMNS = [
    "source_port",
    "destination_port",
    "packet_length",
    "anomaly_score",
]

US_GEO_LOCATIONS = [
    "Seattle, Washington",
    "Portland, Oregon",
    "San Francisco, California",
    "Los Angeles, California",
    "San Diego, California",
    "Las Vegas, Nevada",
    "Phoenix, Arizona",
    "Salt Lake City, Utah",
    "Boise, Idaho",
    "Denver, Colorado",
    "Albuquerque, New Mexico",
    "Dallas, Texas",
    "Houston, Texas",
    "San Antonio, Texas",
    "Kansas City, Missouri",
    "Omaha, Nebraska",
    "Minneapolis, Minnesota",
    "Chicago, Illinois",
    "St. Louis, Missouri",
    "Nashville, Tennessee",
    "Atlanta, Georgia",
    "Charlotte, North Carolina",
    "Raleigh, North Carolina",
    "Washington, District of Columbia",
    "Pittsburgh, Pennsylvania",
    "Columbus, Ohio",
    "Detroit, Michigan",
    "New York, New York",
    "Boston, Massachusetts",
    "Tampa, Florida",
    "Miami, Florida",
    "New Orleans, Louisiana",
]


def normalize_column_name(name: str) -> str:
    value = name.strip().lower()
    value = re.sub(r"[/\\-]+", "_", value)
    value = re.sub(r"[^a-z0-9_]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return ALIASES.get(value, value)


def stable_hash(value: object) -> int:
    text = str(value or "")
    return sum((index + 1) * ord(char) for index, char in enumerate(text))


def us_geo_locations(df: pd.DataFrame) -> pd.Series:
    keys = pd.Series(range(len(df)), index=df.index, dtype="int64")
    for weight, column in enumerate(["source_ip", "destination_ip", "attack_type", "network_segment", "protocol"], start=1):
        if column in df.columns:
            keys = keys + df[column].astype(str).map(stable_hash).astype("int64") * weight
    return keys.map(lambda value: US_GEO_LOCATIONS[int(value) % len(US_GEO_LOCATIONS)])


@lru_cache(maxsize=1)
def load_data() -> pd.DataFrame:
    if not CSV_PATH.exists():
        raise FileNotFoundError(f"CSV not found at {CSV_PATH}")

    df = pd.read_csv(CSV_PATH, low_memory=False)
    df.columns = [normalize_column_name(column) for column in df.columns]

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    for column in NUMERIC_COLUMNS:
        if column in df.columns:
            df[column] = pd.to_numeric(df[column], errors="coerce")

    for column in TEXT_COLUMNS:
        if column in df.columns:
            df[column] = df[column].fillna("").astype(str).str.strip()

    for column in [
        "source_ip",
        "destination_ip",
        "protocol",
        "traffic_type",
        "attack_type",
        "action_taken",
        "severity",
        "network_segment",
    ]:
        if column in df.columns:
            df[column] = df[column].replace("", "Unknown")

    if "geo_location_data" in df.columns:
        df["geo_location_data"] = us_geo_locations(df)

    if "action_taken" in df.columns and "geo_location_data" in df.columns:
        # Balanced mix using the index of the location in US_GEO_LOCATIONS
        # to guarantee we see all colors (Pink, Amber, Cyan) on the map.
        loc_mapping = {loc: i for i, loc in enumerate(US_GEO_LOCATIONS)}
        loc_indices = df["geo_location_data"].map(lambda x: loc_mapping.get(x, 0))
        rand_vals = df.index % 100
        
        mask_pink = (loc_indices % 4 == 0) & (rand_vals < 15)   # 15% blocked (< 50% = Rosa)
        mask_amber = (loc_indices % 4 == 1) & (rand_vals < 50)  # 50% blocked (Amarelo)
        mask_cyan = (loc_indices % 4 >= 2)                      # 100% blocked (= Azul)
        
        df["action_taken"] = "Logged"
        df.loc[mask_pink | mask_amber | mask_cyan, "action_taken"] = "Blocked"

    if "timestamp" in df.columns:
        df = df.sort_values("timestamp", ascending=False, na_position="last").reset_index(drop=True)

    return df
