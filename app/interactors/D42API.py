import base64

import requests
from models import Creds
from models.Device42 import Response


class D42API:
    def __init__(self, creds: Creds):
        self.creds = creds

        self.requestsSession = requests.session()
        self.requestsSession.headers = {'Authorization': self.prepareBasicAuthValue()}

    def prepareBasicAuthValue(self) -> str:
        credentials = f'{self.creds.d42.username}:{self.creds.d42.password}'

        encoded_credentials = base64.b64encode(credentials.encode('ascii'))
        return f'Basic {encoded_credentials.decode("ascii")}'

    def request(self, api_method, method, params, **kwargs) -> dict:
        response = self.requestsSession.request(method, f'{self.creds.d42.url}/api/1.0/{api_method}', params, **kwargs)
        match response.status_code:
            case 200 | 500:
                return response.json()
            case _:
                return {'errors': ['API error'], 'message': response.text}

    def getCustomers(self, params=None, **kwargs) -> Response:
        if params is None:
            params = {
                'include_cols': ','.join(['id', 'name', 'Contacts', 'manager', 'contact_info', 'tags', 'custom_fields'])
                }

        return Response(**self.request("customers", "GET", params, **kwargs))

