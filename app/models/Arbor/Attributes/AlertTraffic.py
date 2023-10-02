from datetime import datetime

from pydantic import BaseModel


class TimeseriesData(BaseModel):
    avg_value: int = 0
    country_code: str = ''
    current_value: int = 0
    max_value: int = 0
    name: str = ''
    pct95_value: int = 0
    step: int = 0
    timeseries: list[int] = []
    timeseries_start: datetime = datetime.now()


class Network(BaseModel):
    unit: dict[str, TimeseriesData] = {'bps': TimeseriesData(), 'pps': TimeseriesData()}


class View(BaseModel):
    network: Network = Network()


class Attributes(BaseModel):
    view: View = View()
