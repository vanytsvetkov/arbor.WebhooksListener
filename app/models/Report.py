import re
from datetime import datetime

from models.helpers import Impact, Set, Char, Excess, Pattern, PacketSize
from pydantic import BaseModel


class Payload(BaseModel):
    sources: Set = Set()
    peers: Set = Set()
    # Characteristics
    misuse_types: list[Char] = []
    src_prefixes: list[Char] = []
    dst_prefixes: list[Char] = []
    protocols: list[Char] = []
    src_tcp_ports: list[Char] = []
    dst_tcp_ports: list[Char] = []
    src_udp_ports: list[Char] = []
    dst_udp_ports: list[Char] = []
    countries: list[Char] = []
    src_asn: list[Char] = []
    dst_asn: list[Char] = []
    # Patterns
    patterns: list[Pattern] = []

    @property
    def ready(self) -> bool:
        return any(value != self.__fields__[key].default for key, value in self.__dict__.items() if key != '__dict__')


class Characteristics(BaseModel):

    misuse_types: list[Char] = []

    highly_distributed: bool = False
    sources: list[Char] = []

    destinations: list[Char] = []
    protocols: list[Char] = []

    src_tcp_ports: list[Char] = []
    dst_tcp_ports: list[Char] = []

    src_udp_ports: list[Char] = []
    dst_udp_ports: list[Char] = []

    countries: list[Char] = []

    src_asn: list[Char] = []
    dst_asn: list[Char] = []

    @property
    def ready(self) -> bool:
        # return bool(self.misuse_types)
        return any(value != self.__fields__[key].default for key, value in self.__dict__.items() if key != '__dict__')


class Distribution(BaseModel):
    packet_size_distribution: list[PacketSize] = []
    plot: str = ''

    @property
    def ready(self) -> bool:
        return bool(self.plot)


class Table(BaseModel):

    characteristics: Characteristics = Characteristics()
    distribution: Distribution = Distribution()
    patterns: list[Pattern] = []

    @property
    def ready(self) -> bool:
        return any([
            self.characteristics.ready,
            self.distribution.ready,
            bool(self.patterns)
            ])


class Report(BaseModel):
    id: int | str = 0
    arborType: str = ''
    unit: str = ''
    excess: Excess = Excess()

    host: str = ''
    start_time: datetime = datetime.now()
    misuse_types: Set = Set()
    impact: Impact = Impact()
    sources: Set = Set()
    services: Set = Set()
    peers: Set = Set()

    table: Table = Table()

    @property
    def protocols(self) -> Set:
        return Set(*[prot.name for prot in self.table.characteristics.protocols if prot.name])

    content: str = ''
    # payload: Payload = Payload()

    # @property
    # def is_payload(self):
    #     return self.payload.ready
    is_payload: bool = False

    @property
    def payload(self) -> Payload:
        return Payload(
            sources=self.sources,
            peers=self.peers,
            misuse_types=self.table.characteristics.misuse_types,
            src_prefixes=self.table.characteristics.sources,
            dst_prefixes=self.table.characteristics.destinations,
            protocols=self.table.characteristics.protocols,
            src_tcp_ports=self.table.characteristics.src_tcp_ports,
            dst_tcp_ports=self.table.characteristics.dst_tcp_ports,
            src_udp_ports=self.table.characteristics.src_udp_ports,
            dst_udp_ports=self.table.characteristics.dst_udp_ports,
            countries=self.table.characteristics.countries,
            src_asn=self.table.characteristics.src_asn,
            dst_asn=self.table.characteristics.dst_asn,
            patterns=self.table.patterns
            )

    @property
    def servicePattern(self) -> re.Pattern:
        match self.arborType:
            case 'ix':
                return re.compile(r'((?:UA-|)(?:DATA|GBL)-IX-\d+(?:\[\d+]|))')
            case 'ipt':
                return re.compile(r'((?:UA-|)GBL-(?:IP|TMS|FS)-\d+(?:\[\d+]|))')
            case _:
                return re.compile('')
