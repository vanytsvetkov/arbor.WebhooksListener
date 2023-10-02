import json

from models import Arbor
from pydantic import BaseModel, validator


def format_value(size: int | float, vn: str, power=1e+3) -> str:
    n = 0
    power_labels = {0: f'{vn}', 1: f'k{vn}', 2: f'M{vn}', 3: f'G{vn}', 4: f'T{vn}', 5: f'P{vn}', 6: f'E{vn}'}
    while size > power:
        size /= power
        n += 1
    return f"{size:.1f} {power_labels[n]}"


class Char(BaseModel):
    name: str = ''
    pct: int = 0
    val: str = ''
    flag: str = ''


class PortRange(BaseModel):
    high: int = 0
    low: int = 0

    def __str__(self) -> str:
        if self.low == self.high:
            return str(self.low)
        else:
            return f'{self.low} – {self.high} (Dynamic)'


class PacketSize(BaseModel):
    high: int = 0
    low: int = 0
    val: int = 0


class Pattern(BaseModel):
    src: str = ''

    @validator('payload')
    def set_src(cls, src):
        if src == '0.0.0.0/0':
            src = 'Highly Distributed'
        return src

    dst: str = ''

    prot: str = ''
    flags: str = ''

    src_port: PortRange = PortRange()
    dst_port: PortRange = PortRange()

    val: int = 0
    unit: str = ''

    @property
    def traffic(self):
        return f'{format_value(self.val, self.unit)}'


class TrafficQueries(BaseModel):
    bps: Arbor.Response
    pps: Arbor.Response


class Impact(BaseModel):
    bps: int = 0
    pps: int = 0

    def __str__(self) -> str:
        return f"{format_value(self.bps, 'bps')}, {format_value(self.pps, 'pps')}"


class Excess(BaseModel):
    unit: str = ''
    threshold: float = 0
    percent: int = 0

    def __str__(self) -> str:
        return f'{format_value(self.threshold, self.unit)}'


class List(BaseModel):
    values: list[str] = []

    def __init__(self, *values: str):
        super().__init__(values=values)

    def __str__(self):
        return ', '.join(self.values)

    def __len__(self):
        return self.values.__len__()


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)  # Convert set to a list
        return super().default(obj)


class Set(BaseModel):
    values: set[str] = set()

    def __init__(self, *values: str):
        super().__init__(values=values)

    def __str__(self) -> str:
        return ', '.join(self.values)

    def __len__(self) -> int:
        return self.values.__len__()

    def __contains__(self, item):
        return item in self.values

    def update(self, values: list) -> None:
        self.values.update(values)

    def add(self, value: str) -> None:
        self.values.add(value)
