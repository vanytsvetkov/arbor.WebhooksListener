from pydantic import BaseModel, validator


class CustomField(BaseModel):
    key: str = ''
    notes: str | None = ''
    value: str | None = ''


class Contact(BaseModel):
    type: str = ''
    email: str | None = ''
    name: str = ''
    address: str = ''
    phone: str = ''

    class Config:
        validate_assignment = True

    @validator('email')
    def set_name(cls, email):
        return email or ''


class Customer(BaseModel):
    groups: str = ''
    id: int = 0
    manager: str = ''
    contact_info: str = ''
    name: str = ''
    subnets_url: str = ''
    custom_fields: list[CustomField] = []
    notes: str = ''
    devices_url: str = ''
    Contacts: list[Contact] = []
    tags: list[str] = []


class Response(BaseModel):
    errors: list = []
    message: str = ''

    total_count: int = 0
    limit: int = 1000

    Customers: list[Customer] = []
    offset: int = 0
