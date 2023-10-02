from pydantic import BaseModel


class Attributes(BaseModel):
    custom: bool = False
    description: str = ''
    enabled: bool = False
    fast_flood_enabled: bool = False
    high_severity_duration: int = 0
    misuse_types: dict = {}
    name: str = ''
    number_of_managed_objects: int = 0
