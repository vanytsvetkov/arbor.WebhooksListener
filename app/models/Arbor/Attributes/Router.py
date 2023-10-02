from pydantic import BaseModel


class Attributes(BaseModel):
    advanced_fallback_alg: str = ''
    advanced_local_as: str = ''
    advanced_local_as2: str = ''
    advanced_use_simpson_flowspec_redirect_ip: bool = False
    bgp2_capabilities_announce_ipv4_mitigation_routes: bool = False
    bgp2_capabilities_labeled_unicast: bool = False
    bgp2_ip_address: str = ''
    bgp2_remote_as: str = ''
    bgp2_session_name: str = ''
    bgp_capabilities_announce_ipv4_mitigation_routes: bool = False
    bgp_capabilities_as4byte: bool = False
    bgp_capabilities_l3vpn_flowspec_ipv4: bool = False
    bgp_capabilities_l3vpn_flowspec_ipv6: bool = False
    bgp_capabilities_labeled_unicast: bool = False
    bgp_capabilities_monitor_routes_ipv4: str = ''
    bgp_ip_address: str = ''
    bgp_remote_as: str = ''
    bgp_session_name: str = ''
    description: str = ''
    flow_alerting: bool = False
    flow_flow_ignored: str = ''
    flow_flow_ignored_ipv6: str = ''
    is_proxy: bool = False
    license_type: str = ''
    name: str = ''
    snmp_authprotocol: str = ''
    snmp_priv_protocol: str = ''
    snmp_security_level: str = ''
    snmp_version: int = 0
