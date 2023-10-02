from pydantic import BaseModel


class Bot(BaseModel):
    token: str
    users: dict[str, int]
    groups: dict[str, int]


class Cred(BaseModel):
    username: str | None = ''
    password: str | None = ''
    url: str | None = ''
    token: str | None = None


class Creds(BaseModel):
    tg: dict[str, Bot]
    arbors: dict[str, Cred]
    d42: Cred
