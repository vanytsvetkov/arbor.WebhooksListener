from datetime import datetime

from pydantic import BaseModel


class Attributes(BaseModel):
    author: str = ''
    commit_log_message: str = ''
    date: datetime = datetime.now()
