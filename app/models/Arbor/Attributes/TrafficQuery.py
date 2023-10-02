from pydantic import BaseModel


class TrafficClass(BaseModel):
    pct95_value: int = 0
    avg_value: int = 0
    max_value: int = 0
    sum: int = 0
    timeseries_end: str = ''
    timeseries_start: str = ''
    step: int = 0
    timeseries: list[int] = []
    current_value: int = 0


class FacetValue(BaseModel):
    facet: str = ''
    id: str = ''
    name: str = ''


class Result(BaseModel):
    traffic_classes: dict[str, TrafficClass] = {}
    facet_values: list[FacetValue] = []


class Attributes(BaseModel):
    results: list[Result] = []
    limit: int = 0
    filters: list[dict] = []
    query_start_time: str = ''
    query_end_time: str = ''
    traffic_classes: list[str] = []
    unit: str = ''
