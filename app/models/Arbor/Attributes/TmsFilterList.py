from pydantic import BaseModel


class Attributes(BaseModel):
    description: str = ''
    filter_type: str = ''
    flist_file_type: str = ''
    from_aps: bool = False
    name: str = ''
    size: int = 0
    system: bool = False
