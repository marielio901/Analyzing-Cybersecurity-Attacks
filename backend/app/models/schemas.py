from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class LogRow(BaseModel):
    timestamp: Optional[str] = None
    source_ip: str = ""
    destination_ip: str = ""
    protocol: str = ""
    packet_length: Optional[float] = None
    traffic_type: str = ""
    attack_type: str = ""
    severity: str = ""
    action_taken: str = ""
    anomaly_score: Optional[float] = None
    destination_port: Optional[int] = None
    network_segment: str = ""
    geo_location_data: str = ""
    firewall_logs: str = ""
    ids_ips_alerts: str = ""


class Pagination(BaseModel):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=25, ge=1, le=500)
    total: int = 0
    pages: int = 0
