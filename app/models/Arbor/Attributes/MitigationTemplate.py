from pydantic import BaseModel


class Subobject(BaseModel):
    bgp_announce: bool = False


class Attributes(BaseModel):
    description: str = ''
    ip_version: int = 0
    name: str = ''
    subobject: Subobject = Subobject()
    subtype: str = ''
    system: bool = False
