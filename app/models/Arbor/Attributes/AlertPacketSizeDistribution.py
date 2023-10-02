from datetime import datetime

from pydantic import BaseModel, validator


class PacketSizeRange(BaseModel):
    high: int | None = 9000
    low: int = 0


class Network(BaseModel):
    avg_value: int = 0
    max_value: int = 0
    packet_size_range: PacketSizeRange = PacketSizeRange()

    @validator('packet_size_range')
    def set_default_high(cls, packet_size_range):
        if packet_size_range.high is None:
            packet_size_range.high = 9000
        return packet_size_range

    pct95_value: int = 0
    step: int = 0
    timeseries: list[int] = []
    timeseries_start: datetime = datetime.now()


class View(BaseModel):
    network: Network = Network()


class PacketSizeDistribution(BaseModel):
    view: View = View()


class Attributes(BaseModel):
    packet_size_distribution: list[PacketSizeDistribution] = []
