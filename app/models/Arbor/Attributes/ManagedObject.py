from typing import Optional

from pydantic import BaseModel, Field


class Description(BaseModel):
    tenant: str = ''
    tenant_id: int = 0
    customer_id: str = ''
    peer_asn: list[int] = []
    services: list[str] = []
    custom: str = ''


class Attributes(BaseModel):
    autodetected: Optional[bool]
    automitigation_precise_protection_prefixes: Optional[bool]
    automitigation_precise_protection_prefixes_mit_on_query_failure: Optional[bool]
    automitigation_scope: Optional[list[str]]
    custom_shared_host_detection_setting: Optional[bool]
    description_str: str = Field(default='', alias='description')
    detection_profiled_autorate: Optional[bool]
    detection_profiled_enabled: Optional[bool]
    detection_profiled_fast_flood_enabled: Optional[bool]
    detection_profiled_severity_duration: Optional[int]
    detection_profiled_severity_snmp_enabled: Optional[bool]
    detection_profiled_threshold_bandwidth: Optional[int]
    detection_profiled_threshold_packet_rate: Optional[int]
    detection_profiled_threshold_protocol: Optional[int]
    dynamic_match_enabled: Optional[bool]
    dynamic_match_multiuse_enabled: Optional[bool]
    editable: Optional[bool]
    family: Optional[str]
    host_detection_point: Optional[str]
    match: Optional[str]
    match_enabled: Optional[bool]
    match_type: Optional[str]
    mitigation_automitigation: Optional[bool]
    mitigation_automitigation_profiled: Optional[bool]
    mitigation_automitigation_stop_event: Optional[str]
    mitigation_automitigation_stop_minutes: Optional[int]
    mitigation_automitigation_tms_enabled: Optional[bool]
    mitigation_automitigation_tms_reuse: Optional[bool]
    mitigation_automitigation_traffic: Optional[bool]
    mitigation_blackhole_auto_enabled: Optional[bool]
    mitigation_flowspec_auto_enabled: Optional[bool]
    mitigation_ip_location_policing_rates: Optional[bool]
    mitigation_sightline_signaling_auto_enabled: Optional[bool]
    name: Optional[str]
    num_children: Optional[int]
    parent_editable: Optional[bool]
    portal_mitigation_tms_scope: Optional[list[str]]
    scrub_insight_mo_match: Optional[bool]
    scrubber_baselines: Optional[bool]
    tags: list[str] = []

    @property
    def description(self) -> Description:
        if self.description_str and all(ch in self.description_str for ch in [';', '=']):
            description = {key.strip(): value for key, value in (item.split("=") for item in self.description_str.split(";") if item)}
            if 'peer_asn' in description:
                description['peer_asn'] = [int(asn) for asn in description['peer_asn'].split(', ') if asn.isdigit()]
            if 'services' in description:
                description['services'] = [service for service in description['services'].split(', ') if service]

            return Description(**description)
        else:
            return Description()

