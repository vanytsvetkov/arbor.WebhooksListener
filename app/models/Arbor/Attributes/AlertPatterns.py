from datetime import datetime

from pydantic import BaseModel


class PortRange(BaseModel):
    low: int = 0
    high: int = 0


class TrafficData(BaseModel):
    avg: int = 0
    current: int = 0
    max: int = 0
    pct95: int = 0


class View(BaseModel):
    all_tcp_flags: list[str] = []
    dst_port_range: PortRange = PortRange()
    dst_prefix: str = ''
    protocol: str = ''
    src_port_range: PortRange = PortRange()
    src_prefix: str = ''
    step: int = 0
    timeseries_end: datetime
    timeseries_start: datetime
    traffic_data: TrafficData = TrafficData()
    unit: str = ''


class Attributes(BaseModel):
    view: dict[str, View]
