from datetime import datetime

from pydantic import BaseModel


class TimeseriesData(BaseModel):
    avg_value: int = 0
    current_value: int = 0
    max_value: int = 0
    pct95_value: int = 0
    severity: int = 0
    step: int = 0
    timeseries: list[int] = []
    timeseries_start: datetime = datetime.now()


class Router(BaseModel):
    unit: dict[str, TimeseriesData] = {'bps': TimeseriesData(), 'pps': TimeseriesData()}


class Attributes(BaseModel):
    view: dict[str, Router]
