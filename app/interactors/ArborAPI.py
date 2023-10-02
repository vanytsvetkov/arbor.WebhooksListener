import requests
from models import Creds

from models.Arbor import Response


class ArborAPI:

    def __init__(self, arborType: str, creds: Creds, **kwargs):
        self.arborType = arborType
        self.creds = creds

        self.url = kwargs.get('url', self.creds.arbors[self.arborType].url)

        if self.url:
            self.requestsSession = requests.session()
            self.requestsSession.verify = kwargs.get('verify', True)
            self.requestsSession.headers = {'X-Arbux-APIToken': self.creds.arbors[self.arborType].token}
        else:
            self.requestsSession = None

    def request(self, method: str, endpoint: str, headers: dict = None, params: dict = None, json: dict = None, **kwargs) -> dict:
        if self.requestsSession:
            response = self.requestsSession.request(method, f'https://{self.url}/api/sp/{endpoint}', headers=headers, params=params, json=json, **kwargs)
            match response.status_code:
                # 200 – OK | 201 – Created
                case 200 | 201:
                    return {**response.json(), 'success': True, 'status_code': response.status_code}
                # 204 – No Content
                case 204:
                    return {'message': response.text, 'success': True, 'status_code': response.status_code}
                case _:
                    return {'errors': ['API Error'], 'message': response.text, 'success': False, 'status_code': response.status_code}
        else:
            return {'errors': ['Wrong URL'], 'message': 'Please specify the correct arborType or pass the url argument via kwargs.'}

    def getManagedObjects(self, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', 'managed_objects', params=params, **kwargs))

    def patchManagedObject(self, blob_id: str | int, json: dict = None, **kwargs) -> Response:
        return Response(**self.request('PATCH', f'managed_objects/{blob_id}', json=json, **kwargs))

    def getRoutes(self, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', 'routers', params=params, **kwargs))

    def getDevices(self, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', 'devices', params=params, **kwargs))

    def getConfig(self, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', 'config', params=params, **kwargs))

    def getAlert(self, alert_id: str | int, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', f'alerts/{alert_id}', params=params, **kwargs))

    def getAlertSources(self, alert_id: str | int, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', f'alerts/{alert_id}/source_ip_addresses', params=params, **kwargs))

    def getAlertRouterTraffic(self, alert_id: str | int, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', f'alerts/{alert_id}/router_traffic', params=params, **kwargs))

    def getAlertTrafficMisuseTypes(self, alert_id: str | int, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', f'alerts/{alert_id}/traffic/misuse_types', params=params, **kwargs))

    def getAlertTrafficSrcPrefixes(self, alert_id: str | int, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', f'alerts/{alert_id}/traffic/src_prefixes', params=params, **kwargs))

    def getAlertTrafficDstPrefixes(self, alert_id: str | int, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', f'alerts/{alert_id}/traffic/dest_prefixes', params=params, **kwargs))

    def getAlertTrafficProtocols(self, alert_id: str | int, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', f'alerts/{alert_id}/traffic/protocols', params=params, **kwargs))

    def getAlertTrafficSrcTcpPorts(self, alert_id: str | int, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', f'alerts/{alert_id}/traffic/src_tcp_ports', params=params, **kwargs))

    def getAlertTrafficDstTcpPorts(self, alert_id: str | int, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', f'alerts/{alert_id}/traffic/dest_tcp_ports', params=params, **kwargs))

    def getAlertTrafficSrcUdpPorts(self, alert_id: str | int, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', f'alerts/{alert_id}/traffic/src_udp_ports', params=params, **kwargs))

    def getAlertTrafficDstUdpPorts(self, alert_id: str | int, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', f'alerts/{alert_id}/traffic/dest_udp_ports', params=params, **kwargs))

    def getAlertTrafficCounties(self, alert_id: str | int, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', f'alerts/{alert_id}/traffic/src_countries', params=params, **kwargs))

    def getAlertTrafficSrcAsn(self, alert_id: str | int, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', f'alerts/{alert_id}/traffic/src_asn', params=params, **kwargs))

    def getAlertTrafficDstAsn(self, alert_id: str | int, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', f'alerts/{alert_id}/traffic/dest_asn', params=params, **kwargs))

    def getAlertPacketSizeDistribution(self, alert_id: str | int, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', f'alerts/{alert_id}/packet_size_distribution', params=params, **kwargs))

    def getAlertPatterns(self, alert_id: str | int, params=None, **kwargs) -> Response:
        return Response(**self.request('GET', f'alerts/{alert_id}/patterns', params=params, **kwargs))

    def postTrafficQueries(self, json: dict = None, parsed: bool = True, **kwargs) -> Response | dict:
        if parsed:
            return Response(**self.request('POST', 'traffic_queries/', json=json, **kwargs))
        else:
            return self.request('POST', 'traffic_queries/', json=json, **kwargs)

    def getTmsFilterList(self, params: dict = None, **kwargs) -> Response:
        return Response(**self.request('GET', 'tms_filter_lists/', params=params, **kwargs))

    def postTmsFilterList(self, json: dict = None, **kwargs) -> Response:
        return Response(**self.request('POST', 'tms_filter_lists/', json=json, **kwargs))

    def patchTmsFilterList(self, filter_id: str | int, json: dict = None, **kwargs) -> Response:
        return Response(**self.request('PATCH', f'tms_filter_lists/{filter_id}/entries', headers={'Content-Type': 'application/vnd.api+json'}, json=json, **kwargs))

    def get_mitigation_templates(self, filter_id: str | int = None, params: dict = None, **kwargs) -> Response:
        if filter_id:
            return Response(**self.request('GET', f'mitigation_templates/{filter_id}', params=params, **kwargs))
        return Response(**self.request('GET', 'mitigation_templates', params=params, **kwargs))
