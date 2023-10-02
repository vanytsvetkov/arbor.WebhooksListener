import redis as r
from interactors import ArborAPI, D42API
from models import Creds


def ProcessUpdate(updType: str, creds: Creds, redis: r.client.Redis) -> None:

    match updType:
        case 'ix' | 'ipt':
            api = ArborAPI(updType, creds)

            ManagedObjects = api.getManagedObjects(params={'perPage': 1000})
            if not ManagedObjects.errors:
                for blob in ManagedObjects.data:
                    redis.set(f"{updType}|blobs.{blob.id}.name", blob.attributes.name)
                    redis.set(f"{updType}|blobs.{blob.id}.tenant.name", blob.attributes.description.tenant)
                    redis.set(f"{updType}|blobs.{blob.id}.tenant.customer_id", blob.attributes.description.customer_id)
                    redis.set(f"{updType}|blobs.{blob.id}.tenant.id", blob.attributes.description.tenant_id)

                    # TODO: add customers' services to redis from D42 instead using blob's description. Check below.
                    if blob.attributes.description.services:
                        redis.delete(f'{updType}|blobs.{blob.id}.tenant.services')
                        redis.sadd(f'{updType}|blobs.{blob.id}.tenant.services', *blob.attributes.description.services)

                    redis.set(f"{updType}|blobs.{blob.id}.protected", 1 if any([
                                                                                blob.attributes.mitigation_automitigation,
                                                                                blob.attributes.mitigation_automitigation_tms_enabled,
                                                                                blob.attributes.mitigation_flowspec_auto_enabled,
                                                                                blob.attributes.mitigation_blackhole_auto_enabled,
                                                                                'protected' in blob.attributes.tags
                                                                            ]) else 0)

                    if blob.attributes.tags:
                        redis.delete(f"{updType}|blobs.{blob.id}.tags")
                        redis.sadd(f"{updType}|blobs.{blob.id}.tags", *blob.attributes.tags)

            Routers = api.getRoutes()
            if not Routers.errors:
                for router in Routers.data:
                    redis.set(f"{updType}|router.{router.id}.name", router.attributes.name)

            Devices = api.getDevices()
            if not Devices.errors:
                for device in Devices.data:
                    redis.set(f"{updType}|device.{device.id}.name", device.attributes.name)

        case 'd42':

            api = D42API(creds)

            customers = api.getCustomers()

            if not customers.errors:
                for customer in customers.Customers:

                    redis.set(f'{updType}|customers.{customer.id}.name', customer.name)                   # type: str
                    redis.set(f'{updType}|customers.{customer.id}.manager', customer.manager)             # type: str
                    redis.set(f'{updType}|customers.{customer.id}.contact_info', customer.contact_info)   # type: str

                    for cf in customer.custom_fields:
                        match cf.key:
                            case 'Arbor_ott':
                                redis.set(f'd42|customers.{customer.id}.ott', 1 if cf.value == 'yes' else 0)
                            case 'Arbor_notify':
                                redis.set(f'd42|customers.{customer.id}.notify', 1 if cf.value == 'yes' else 0)

                    if customer.tags:
                        redis.delete(f'{updType}|customers.{customer.id}.tags')
                        redis.sadd(f'{updType}|customers.{customer.id}.tags', *customer.tags)     # type: set

                    if customer.Contacts:
                        redis.delete(f'{updType}|customers.{customer.id}.emails')
                        redis.sadd(f'{updType}|customers.{customer.id}.emails', *[contact.email for contact in customer.Contacts])    # type: set

                    # TODO: make it here.
                    # if customer.services:
                    #     redis.sadd(f'{updType}|customers.{customer.id}.services', *customer.services)    # type: set
