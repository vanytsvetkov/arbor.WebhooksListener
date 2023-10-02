from datetime import datetime

from pydantic import BaseModel


class TimeseriesData(BaseModel):
    avg_value: int = 0
    current_value: int = 0
    interface_asns: list[str] = []
    interface_boundary: str = ''
    interface_name: str = ''
    max_value: int = 0
    pct95_value: int = 0
    snmp_description: str = ''
    step: int = 0
    timeseries: list[int] = []
    timeseries_start: datetime = datetime.now()


class Unit(BaseModel):
    unit: dict[str, TimeseriesData] = {'bps': TimeseriesData(), 'pps': TimeseriesData()}


class Direction(BaseModel):
    incoming: Unit = Unit()
    outgoing: Unit = Unit()


class View(BaseModel):
    direction: Direction = Direction()


class Attributes(BaseModel):
    view: dict[str, View]
