import httpx
from interactors import ArborAPI
from models import (
    Creds,
    TrafficQueries
)
from models.Arbor import Blob, Response, Attributes
from utils import gen_trafficQuery


async def ProcessProxy(hook: Response, creds: Creds):

    if hook.bypass:
        async with httpx.AsyncClient(verify=False) as client:
            await client.post(f"https://webhooks-listener/arbors/{hook.arborType}/ddos", json=hook.response, timeout=None)
        return

    bps_excess_threshold = 25
    pps_excess_threshold = 25

    # Емкость одной детекции не может быть больше суммарной емкости всех L3 аплинков,
    # Максимальная пропускная способность 100G линка в pps: 100Gbps / 86 (мин. размер ethernet кадра в байтах) / 8 ~= 150 Mpps

    bps_ignore_min_value = 1 * 1e+9
    bps_ignore_max_value = 600 * 1e+9

    pps_ignore_min_value = 10 * 1e+3
    pps_ignore_max_value = 100 * 1e+9 / 86 / 8

    bps_impact = hook.data.attributes.subobject.impact_bps
    pps_impact = hook.data.attributes.subobject.impact_pps

    if (bps_impact > bps_ignore_min_value and pps_impact > pps_ignore_min_value) and \
       (bps_impact < bps_ignore_max_value and pps_impact < pps_ignore_max_value):

        blob = Blob(id=hook.data.relationships.managed_object.data.id)

        api = ArborAPI(hook.arborType, creds)

        trafficQueries = TrafficQueries(
            bps=api.postTrafficQueries(json=gen_trafficQuery('bps', blob.id)),
            pps=api.postTrafficQueries(json=gen_trafficQuery('pps', blob.id))
            )

        if not trafficQueries.bps.errors and not trafficQueries.pps.errors:
            # avoid unparsed errors
            if isinstance(trafficQueries.bps.data.attributes, Attributes.TrafficQuery.Attributes) and isinstance(trafficQueries.pps.data.attributes, Attributes.TrafficQuery.Attributes):
                if trafficQueries.bps.data.attributes.results and trafficQueries.pps.data.attributes.results:

                    bps_max_value = trafficQueries.bps.data.attributes.results[0].traffic_classes['in'].max_value
                    pps_max_value = trafficQueries.pps.data.attributes.results[0].traffic_classes['in'].max_value

                    if bps_max_value and pps_max_value:

                        bps_excess = bps_impact / bps_max_value * 100
                        pps_excess = pps_impact / pps_max_value * 100

                        if bps_excess >= bps_excess_threshold or pps_excess >= pps_excess_threshold:

                            async with httpx.AsyncClient(verify=False) as client:
                                await client.post(f"https://webhooks-listener/arbors/{hook.arborType}/ddos", json=hook.response, timeout=None)
