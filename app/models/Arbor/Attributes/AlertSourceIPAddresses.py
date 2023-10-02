from pydantic import BaseModel


class Attributes(BaseModel):
    source_ips: list = []
