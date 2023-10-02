from pydantic import BaseModel, Field, HttpUrl, validator

from .Attributes import *


class Links(BaseModel):
    first: HttpUrl | str = ""
    last: HttpUrl | str = ""
    self: HttpUrl | str = ""


class RelationshipData(BaseModel):
    id: int | str = 0
    type: str = ''

    @validator('id', pre=True)
    def str2int(cls, value):
        if isinstance(value, str) and value.isdigit():
            return int(value)
        return value


class Relationship(BaseModel):
    data: RelationshipData | list[RelationshipData] = RelationshipData()
    links: Links = Links()


class Relationships(BaseModel):
    annotations: Relationship = Relationship()
    device: Relationship = Relationship()
    collector: Relationship = Relationship()
    router: Relationship = Relationship()
    managed_object: Relationship = Relationship()
    packet_size_distribution: Relationship = Relationship()
    patterns: dict = {}
    router_traffic: dict = {}
    source_ip_addresses: Relationship = Relationship()
    thresholds: dict = {}
    traffic: Relationship = Relationship()
    alert: Relationship = Relationship()
    config_change_host: Relationship = Relationship()
    mitigation_templates_auto_ipv4: Relationship = Relationship()
    mitigation_templates_auto_ipv6: Relationship = Relationship()
    mitigation_templates_manual_ipv4: Relationship = Relationship()
    mitigation_templates_manual_ipv6: Relationship = Relationship()
    shared_host_detection_settings: Relationship = Relationship()


class Data(BaseModel):
    attrs: dict = Field({}, alias="attributes")
    id: str = ''
    links: Links = Links()
    relationships: Relationships = Relationships()
    type: str = ''

    @property
    def subid(self) -> str:
        return self.id.split('-')[-1]

    @property
    def attributes(self) -> dict \
                            | Alert.Attributes \
                            | Mitigation.Attributes \
                            | ManagedObject.Attributes \
                            | Configuration.Attributes \
                            | Router.Attributes \
                            | Device.Attributes \
                            | TrafficQuery.Attributes \
                            | AlertSourceIPAddresses.Attributes \
                            | AlertRouterInterfaceTraffic.Attributes \
                            | AlertTraffic.Attributes \
                            | AlertPacketSizeDistribution.Attributes:
        match self.type:
            case 'alert':
                return Alert.Attributes(**self.attrs)
            case 'mitigation':
                return Mitigation.Attributes(**self.attrs)
            case 'managed_object':
                return ManagedObject.Attributes(**self.attrs)
            case 'configuration':
                return Configuration.Attributes(**self.attrs)
            case 'router':
                return Router.Attributes(**self.attrs)
            case 'device':
                return Device.Attributes(**self.attrs)
            case 'traffic_query':
                return TrafficQuery.Attributes(**self.attrs)
            case 'shared_host_detection_settings':
                return HostDetection.Attributes(**self.attrs)
            case 'alert_source_ip_addresses':
                return AlertSourceIPAddresses.Attributes(**self.attrs)
            case 'alert_router_interface_traffic':
                return AlertRouterInterfaceTraffic.Attributes(**self.attrs)
            case 'alert_traffic_misuse_types' \
                 | 'alert_traffic_src_prefixes' \
                 | 'alert_traffic_dest_prefixes' \
                 | 'alert_traffic_protocols' \
                 | 'alert_traffic_src_tcp_ports' \
                 | 'alert_traffic_dest_tcp_ports' \
                 | 'alert_traffic_src_udp_ports' \
                 | 'alert_traffic_dest_udp_ports' \
                 | 'alert_traffic_src_countries' \
                 | 'alert_traffic_src_asn' \
                 | 'alert_traffic_dest_asn':
                return AlertTraffic.Attributes(**self.attrs)
            case 'alert_patterns':
                return AlertPatterns.Attributes(**self.attrs)
            case 'alert_packet_size_distribution':
                return AlertPacketSizeDistribution.Attributes(**self.attrs)
            case 'mitigation_template':
                return MitigationTemplate.Attributes(**self.attrs)
            case 'tms_filter_list':
                return TmsFilterList.Attributes(**self.attrs)
            case _:
                return self.attrs


class Response(BaseModel):
    data: Data | list[Data] = Data()
    included: Data | list[Data] = Data()
    links: Links = Links()
    meta: dict = {}

    errors: list = []
    message: str = ''

    response: dict = {}
    arborType: str = ''

    bypass: bool = False

    success: bool = False
    status_code: int = 0

    def __getitem__(self, item):
        return getattr(self, item)
