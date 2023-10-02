from pydantic import BaseModel


class FlowSpecException(BaseModel):
    enabled: bool = False


class Metrics(BaseModel):
    cpu_load_limit: int = 0
    disk_data_partition_used_percent_limit: int = 0
    flows_total_dropped_per_five_minutes_limit: int = 0
    managed_objects_matched_per_flow_limit: int = 0
    memory_used_percent_limit: int = 0


class SNMP(BaseModel):
    authpassword: str = ''
    authprotocol: str = ''
    privprotocol: str = ''
    security_level: str = ''
    username: str = ''
    v3_support: bool = False


class Attributes(BaseModel):
    arf_enabled: str = ''
    cloud_signaling_only: bool = False
    device_type: str = ''
    flexible_license_submode: str = ''
    flow_ignored: str = ''
    flow_interfaces: list[str] = []
    flowspec_exception: FlowSpecException = FlowSpecException()
    forensics: str = ''
    insight_ingestion: bool = False
    ip_address: str = ''
    license_mode: str = ''
    metrics: Metrics = Metrics()
    model: str = ''
    name: str = ''
    snmp: SNMP = SNMP()
