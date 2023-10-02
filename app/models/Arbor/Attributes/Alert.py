from datetime import datetime

from pydantic import BaseModel


class Subobject(BaseModel):
    direction: str = ''
    fast_detected: bool = False
    host_address: str = ''
    impact_boundary: str = ''
    impact_bps: int = 0
    impact_pps: int = 0
    ip_version: int = 0
    misuse_types: list[str] = []
    severity_percent: int = 0
    severity_threshold: float = 0
    severity_unit: str = ''
    summary_url: str = ''
    updates: int = 0
    username: str = ''
    threshold: int = 0
    type: str = ''
    unit: str = ''
    usage: int = 0
    description: str = ''
    version: str = ''
    bgp_session_name: str = ''
    aspath: str = ''
    bgp_prefix: str = ''
    local_prefix: str = ''


class Attributes(BaseModel):
    alert_class: str = ''
    alert_type: str = ''
    classification: str = ''
    importance: int = 0
    ongoing: bool = False
    start_time: datetime
    stop_time: datetime = None
    subobject: Subobject = Subobject()

