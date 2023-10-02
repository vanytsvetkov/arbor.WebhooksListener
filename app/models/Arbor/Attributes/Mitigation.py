from datetime import datetime

from pydantic import BaseModel


class AifHttpUrlRegexp(BaseModel):
    active: bool = False
    aif_http_level: str = ''


class DenyAllowLists(BaseModel):
    active: bool = False


class DnsAuth(BaseModel):
    active: bool = False
    mode: str = ''
    timeout: int = 0


class DnsMalformed(BaseModel):
    active: bool = False


class DnsNxRatelimiting(BaseModel):
    active: bool = False


class DnsObjectRatelimiting(BaseModel):
    active: bool = False
    limit: int = 0


class DnsRatelimiting(BaseModel):
    active: bool = False
    limit: int = 0


class DnsRegex(BaseModel):
    active: bool = False
    match_direction: str = ''


class DnsScoping(BaseModel):
    active: bool = False
    apply_on_match: bool = False


class HttpMalformed(BaseModel):
    active: bool = False
    level: str = ''


class HttpObject(BaseModel):
    active: bool = False


class HttpRequest(BaseModel):
    active: bool = False


class HttpScoping(BaseModel):
    active: bool = False
    apply_on_match: bool = False


class IpAddressFilterlist(BaseModel):
    active: bool = False


class IpLocationFilterlist(BaseModel):
    active: bool = False
    drop_matched_or_unmatched: str = ''


class IpLocationPolicing(BaseModel):
    active: bool = False


class PacketHeaderFiltering(BaseModel):
    active: bool = False


class Payload(BaseModel):
    active: bool = False
    deny_list_hosts: bool = False


class PerConnectionFloodProtection(BaseModel):
    active: bool = False
    enforcement: str = ''
    maximum_bps: int = 0
    maximum_pps: int = 0


class ProtocolBaselines(BaseModel):
    active: bool = False


class ProxyListThresholdExceptions(BaseModel):
    scaling_factor: float = 0


class Shaping(BaseModel):
    active: bool = False


class SipMalformed(BaseModel):
    active: bool = False


class SipRequestLimiting(BaseModel):
    active: bool = False


class TcpConnectionLimiting(BaseModel):
    active: bool = False
    deny_list: bool = False
    idle_timeout: int = 0
    ignore_idle: bool = False
    max_connections: int = 0


class TcpConnectionReset(BaseModel):
    active: bool = False


class TcpSynAuth(BaseModel):
    active: bool = False
    auto: bool = False
    spoofed_flood_protection_automation: bool = False


class TlsNegotiation(BaseModel):
    active: bool = False
    clients_can_alert: bool = 0
    max_cipher_suites: int = 0
    max_early_close: int = 0
    max_extensions: int = 0
    max_pend_secs: int = 0
    min_pend_secs: int = 0


class UdpReflectionAmp(BaseModel):
    active: bool = False
    auto_transfer_misuse: bool = False
    auto_transfer_misuse_dns: bool = False


class UdpSessionAuth(BaseModel):
    active: bool = False
    idle_session_timer: int = 0
    in_progress_period: int = 0
    retransmission_timer: int = 0


class ZombieDetection(BaseModel):
    active: bool = False
    deny_listing: bool = False


class Port(BaseModel):
    low: int = 0
    high: int = 0


class Action(BaseModel):
    type: str = ''


class Subobject(BaseModel):
    aif_http_url_regexp: AifHttpUrlRegexp = AifHttpUrlRegexp()
    bgp_announce: bool = False
    deny_allow_lists: DenyAllowLists = DenyAllowLists()
    diversion_prefix_mode: str = ''
    diversion_prefixes: list[str] = []
    dns_auth: DnsAuth = DnsAuth()
    dns_malformed: DnsMalformed = DnsMalformed()
    dns_nx_ratelimiting: DnsNxRatelimiting = DnsNxRatelimiting()
    dns_object_ratelimiting: DnsObjectRatelimiting = DnsObjectRatelimiting()
    dns_ratelimiting: DnsRatelimiting = DnsRatelimiting()
    dns_regex: DnsRegex = DnsRegex()
    dns_scoping: DnsScoping = DnsScoping()
    http_malformed: HttpMalformed = HttpMalformed()
    http_object: HttpObject = HttpObject()
    http_request: HttpRequest = HttpRequest()
    http_scoping: HttpScoping = HttpScoping()
    ip_address_filterlist: IpAddressFilterlist = IpAddressFilterlist()
    ip_location_filterlist: IpLocationFilterlist = IpLocationFilterlist()
    ip_location_policing: IpLocationPolicing = IpLocationPolicing()
    managed_services_user_access_enabled: bool = False
    mode: str = ''
    packet_header_filtering: PacketHeaderFiltering = PacketHeaderFiltering()
    payload: Payload = Payload()
    per_connection_flood_protection: PerConnectionFloodProtection = PerConnectionFloodProtection()
    protection_prefixes: list[str] = []
    protocol_baselines: ProtocolBaselines = ProtocolBaselines()
    proxy_list_threshold_exceptions: ProxyListThresholdExceptions = ProxyListThresholdExceptions()
    shaping: Shaping = Shaping()
    sip_malformed: SipMalformed = SipMalformed()
    sip_request_limiting: SipRequestLimiting = SipRequestLimiting()
    tcp_connection_limiting: TcpConnectionLimiting = TcpConnectionLimiting()
    tcp_connection_reset: TcpConnectionReset = TcpConnectionReset()
    tcp_syn_auth: TcpSynAuth = TcpSynAuth()
    tls_negotiation: TlsNegotiation = TlsNegotiation()
    udp_reflection_amp: UdpReflectionAmp = UdpReflectionAmp()
    udp_session_auth: UdpSessionAuth = UdpSessionAuth()
    zombie_detection: ZombieDetection = ZombieDetection()
    # flowspec mitigation
    dst_prefix: str = ''
    src_prefix: str = ''
    protocol: list = []
    src_port: list[Port] = []
    dst_port: list[Port] = []
    packet_length: list[str] = []
    fragment: list[str] = []
    action: Action = Action()


class Attributes(BaseModel):
    description: str = ''
    ip_version: int = 0
    is_automitigation: bool = False
    name: str = ''
    ongoing: bool = False
    start: datetime
    stop: datetime | None = None
    subobject: Subobject = Subobject()
    subtype: str = ''
    user: str = ''
