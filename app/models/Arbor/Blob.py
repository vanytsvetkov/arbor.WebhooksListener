from pydantic import BaseModel


class Tenant(BaseModel):
    name: str = ''
    id: int = ''
    customer_id: str = ''
    manager: str = ''
    emails: list[str] = []
    services: list[str] = []
    tags: list[str] = []
    ott: int = 0
    notify: int = 0
    notified: int = 0

    def __setattr__(self, key, value):
        if any(key == k for k in ['name', 'customer_id', 'id', 'manager']) and isinstance(value, bytes):
            value = value.decode('utf-8')
            if value.isdigit():
                value = int(value)
        elif any(key == k for k in ['emails', 'services', 'tags']) and isinstance(value, set):
            value = [v.decode('utf-8') for v in value if isinstance(v, bytes)]

        super().__setattr__(key, value)


class Blob(BaseModel):
    id: int = 0
    protected: bool = False
    name: str = ''
    tags: set[str] = set()
    tenant: Tenant = Tenant()

    def __setattr__(self, key, value):
        if any(key == k for k in ['name']):
            value = value.decode('utf-8') if isinstance(value, bytes) else value
        elif any(key == k for k in ['protected']):
            value = bool(int(value.decode('utf-8'))) if isinstance(value, bytes) else False
        elif any(key == k for k in ['tags']):
            value = set(tag.decode('utf-8') for tag in value if isinstance(tag, bytes))
        super().__setattr__(key, value)



