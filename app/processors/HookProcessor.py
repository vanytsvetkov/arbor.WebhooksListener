import json
import traceback
from datetime import timedelta

import httpx
import redis as r

import vars
from interactors import ArborAPI
from models import Creds
from models.Arbor import Blob, Response
from utils import format_value, format_time, msg


async def ProcessHook(hook: Response, creds: Creds, redis: r.client.Redis) -> None:

    chat_indicators = ['SP']
    text = None

    try:
        match hook.data.type:
            case 'alert':
                match hook.data.attributes.alert_type:
                    case 'dos_host_detection':
                        do_inform = True

                        if not hook.data.attributes.importance == 2:
                            return

                        blob = Blob(id=hook.data.relationships.managed_object.data.id)
                        blob.protected = redis.get(f"{hook.arborType}|blobs.{blob.id}.protected")
                        blob.tags = redis.smembers(f"{hook.arborType}|blobs.{blob.id}.tags")

                        chat_indicators = ['TMS'] if blob.protected or any(tag in blob.tags for tag in ['backbone', 'broadband']) else ['FREE']
                        if any(tag in blob.tags for tag in ['broadband']):
                            chat_indicators.append('BB')

                        impact_bps = format_value(hook.data.attributes.subobject.impact_bps, "bps", 1000)
                        impact_pps = format_value(hook.data.attributes.subobject.impact_pps, "pps", 1000)
                        misuse_types = ", ".join(f'<code>{misuse_type}</code>' for misuse_type in hook.data.attributes.subobject.misuse_types)

                        if blob.id:
                            blob.name = redis.get(f"{hook.arborType}|blobs.{blob.id}.name")
                            blob.tenant.name = redis.get(f"{hook.arborType}|blobs.{blob.id}.tenant.name")
                            blob.tenant.id = redis.get(f'{hook.arborType}|blobs.{blob.id}.tenant.id')
                            blob.tenant.notify = redis.get(f'd42|customers.{blob.tenant.id}.notify')
                            blob.tenant.notified = redis.get(f'd42|customers.{blob.tenant.id}.notified')
                        else:
                            blob.name = 'Global Detection'

                        text = (
                            f'''<b>DoS Host Alert</b> [<a href="https://{hook.data.links.self.host}/page?id=host_alert&alert_id={hook.data.id}"><i>#{hook.data.id}</i></a>]\n'''
                            f'''<code>{hook.data.links.self.host}</code>\n\n'''
                            f'''{hook.data.attributes.subobject.direction} Host Alert to <code>{hook.data.attributes.subobject.host_address}</code>\n'''
                            f'''Impact <code>{impact_bps}</code>, <code>{impact_pps}</code>\n'''
                            f'''Misuse types: {misuse_types}\n\n'''
                            f'''Customer: <code>{blob.name if blob.name else '%service_id%'}</code> {f"(<code>{blob.tenant.name if blob.tenant.name else '%tenant%'}</code>)" if blob.id else ""}\n\n'''
                            f'''{format_time(hook.data.attributes)}'''
                            )

                        if (
                                hook.data.attributes.ongoing and not blob.protected
                                and blob.tenant.notify and not blob.tenant.notified
                                and all(tag not in blob.tags for tag in ['dnd', 'broadband', 'backbone'])
                                ) or hook.bypass:

                            go_proxy = False
                            if not hook.bypass:
                                iter_stage = 0
                                while True:
                                    if not redis.get(f'{hook.arborType}|iter_stage.{iter_stage}'):
                                        redis.set(f'{hook.arborType}|iter_stage', iter_stage)
                                        redis.expire(f'{hook.arborType}|iter_stage', timedelta(hours=24))
                                        break
                                    iter_stage += 1

                                if iter_stage <= 10:
                                    go_proxy = True

                            if go_proxy or hook.bypass:
                                # US #646488 [https://us.gblnet.net/oper/?core_section=task&action=show&id=646488]
                                async with httpx.AsyncClient(verify=False) as client:
                                    await client.post(f"https://webhooks-listener/arbors/{hook.arborType}/proxy", json=hook.response, timeout=None)

                    case "dos_profiled_network" | "dos_profiled_router":
                        do_inform = True

                    case "tms_fault":
                        do_inform = True

                        device = redis.get(f"{hook.arborType}|device.{hook.data.relationships.device.data.id}.name")

                        text = (
                            f'''<b>TMS Fault</b>\n'''
                            f'''<code>{hook.data.links.self.host}</code>\n\n'''
                            f'''Appliance: <b>{device.decode('utf-8') if device else '%device%'}</b>\n'''
                            f'''{hook.data.attributes.subobject.description}\n\n'''
                            f'''{format_time(hook.data.attributes)}'''
                            )

                    case "snmp_down":
                        do_inform = True

                        router = redis.get(f"{hook.arborType}|router.{hook.data.relationships.router.data.id}.name")

                        text = (
                            f'''<b>SNMP Down</b>\n'''
                            f'''<code>{hook.data.links.self.host}</code>\n\n'''
                            f'''Router: <b>{router.decode('utf-8') if router else '%router%'}</b>\n\n'''
                            f'''{format_time(hook.data.attributes)}'''
                            )

                    case "config_change":
                        do_inform = True

                        async with httpx.AsyncClient(verify=False) as client:
                            await client.post(f"https://webhooks-listener/arbors/{hook.arborType}/update_db", timeout=None)

                        api = ArborAPI(hook.arborType, creds)

                        commits = api.getConfig()
                        commit = [c for c in commits.data if c.id == hook.data.attributes.subobject.version]

                        device = redis.get(f"{hook.arborType}|device.{hook.data.relationships.device.data.id}.name")

                        text = (
                            f'''<b>System Configuration Update</b>\n'''
                            f'''<code>{hook.data.links.self.host}</code>\n\n'''
                            f'''User <b>{hook.data.attributes.subobject.username}</b> on <b>{device.decode('utf-8') if device else '%device%'}</b>\n'''
                            f'''Log Message:\n{commit[0].attributes.commit_log_message if commit else '%logmessage%'}\n\n'''
                            f'''{format_time(hook.data.attributes)}'''
                            )

                    case "flow_down":
                        do_inform = True

                        router = redis.get(f"{hook.arborType}|router.{hook.data.relationships.router.data.id}.name")

                        text = (
                            f'''<b>Flow Down</b>\n'''
                            f'''<code>{hook.data.links.self.host}</code>\n\n'''
                            f'''Router: <b>{router.decode('utf-8') if router else '%router%'}</b>\n\n'''
                            f'''{format_time(hook.data.attributes)}'''
                            )

                    case "bgp_down":
                        do_inform = True

                        router = redis.get(f"{hook.arborType}|router.{hook.data.relationships.router.data.id}.name")

                        text = (
                            f'''<b>BGP Down</b>\n'''
                            f'''<code>{hook.data.links.self.host}</code>\n\n'''
                            f'''Router: <b>{router.decode('utf-8') if router else '%router%'}</b>\n\n'''
                            f'''Session: <b>{hook.data.attributes.subobject.bgp_session_name}</b>\n\n'''
                            f'''{format_time(hook.data.attributes)}'''
                            )

                    case "bgp_hijack":
                        do_inform = True

                        router = redis.get(f"{hook.arborType}|router.{hook.data.relationships.router.data.id}.name")

                        text = (
                            f'<b>BGP Route Hijack</b>\n'
                            f'''<code>{hook.data.links.self.host}</code>\n\n'''
                            f'''Router: <b>{router.decode('utf-8') if router else '%router%'}</b>\n\n'''
                            f'''BGP Route: {hook.data.attributes.subobject.bgp_prefix}\n'''
                            f'''AS Path: {hook.data.attributes.subobject.aspath}\n'''
                            f'''Local Address Block: {hook.data.attributes.subobject.local_prefix}\n\n'''
                            f'''{format_time(hook.data.attributes)}'''
                            )

                    case "bgp_instability":
                        do_inform = True

                        router = redis.get(f"{hook.arborType}|router.{hook.data.relationships.router.data.id}.name")

                        text = (
                            f'''<b>BGP Instability</b>\n'''
                            f'''<code>{hook.data.links.self.host}</code>\n\n'''
                            f'''Too many BGP updates (max. per 5 min.):\n'''
                            f'''Router: <b>{router.decode('utf-8') if router else '%router%'}</b>\n\n'''
                            f'''Updates: {hook.data.attributes.subobject.updates}\n\n'''
                            f'''{format_time(hook.data.attributes)}'''
                            )

                    case "blob_thresh":
                        do_inform = True

                        blob = Blob(id=hook.data.relationships.managed_object.data.id)

                        blob.name = redis.get(f"{hook.arborType}|blobs.{blob.id}.name")
                        blob.tenant.name = redis.get(f"{hook.arborType}|blobs.{blob.id}.tenant.name")

                        usage = format_value(hook.data.attributes.subobject.usage, hook.data.attributes.subobject.unit, 1000)
                        threshold = format_value(hook.data.attributes.subobject.threshold, hook.data.attributes.subobject.unit, 1000)

                        relation = hook.data.attributes.subobject.usage/hook.data.attributes.subobject.threshold

                        text = (
                            f'''<b>Managed Object Threshold</b>\n'''
                            f'''<code>{hook.data.links.self.host}</code>\n\n'''
                            f'''{hook.data.attributes.subobject.type} usage for:\n'''
                            f'''Customer: <code>{blob.name if blob.name else '%service_id%'}</code> {f"(<code>{blob.tenant.name if blob.tenant.name else '%tenant%'}</code>)" if blob.id else ""}\n\n'''
                            f'''<code>{usage}</code> (<code>{relation:.1%}</code> of <code>{threshold}</code>)\n\n'''
                            f'''{format_time(hook.data.attributes)}'''
                            )

                    case "device_system_error":
                        do_inform = True

                    case "collector_down":
                        do_inform = True

                        collector = redis.get(f"{hook.arborType}|device.{hook.data.relationships.collector.data.id}.name")
                        device = redis.get(f"{hook.arborType}|device.{hook.data.relationships.device.data.id}.name")

                        text = (
                            f'''<b>SP/TMS Appliance Down</b>\n'''
                            f'''<code>{hook.data.links.self.host}</code>\n\n'''
                            f'''Appliance: <b>{collector.decode('utf-8') if collector else '%collector%'}</b>\n'''
                            f'''Detecting Appliance: <b>{device.decode('utf-8') if device else '%device%'}</b>\n\n'''
                            f'''{format_time(hook.data.attributes)}'''
                            )

                    case "cloud_mit_request":
                        do_inform = True

                    case "interface_usage":
                        do_inform = False

                    case _:
                        do_inform = True

            case "mitigation":
                blob = Blob(id=hook.data.relationships.managed_object.data.id)
                blob.tags = redis.smembers(f"{hook.arborType}|blobs.{blob.id}.tags")
                blob.name = redis.get(f"{hook.arborType}|blobs.{blob.id}.name")
                blob.tenant.name = redis.get(f"{hook.arborType}|blobs.{blob.id}.tenant.name")

                do_inform = True
                chat_indicators = ['TMS']
                if 'broadband' in blob.tags:
                    chat_indicators.append('BB')

                alert_link = ""
                if hook.data.relationships.alert:
                    alert_link = f'''<a href="https://{hook.data.links.self.host}/page?id=host_alert&alert_id={hook.data.relationships.alert.data.id}"><i>#{hook.data.relationships.alert.data.id}</i></a>, '''

                mitigation_link = f'''<a href="https://{hook.data.links.self.host}/page?id=mitigation_status&mitigation_id={hook.data.id.split("-")[-1]}"><i>#{hook.data.id}</i></a>'''

                match hook.data.attributes.subtype:
                    case "tms":
                        protection_prefixes = f'''{", ".join(f'<code>{prefix}</code>' for prefix in hook.data.attributes.subobject.protection_prefixes)}'''
                        rule = f'''Protection Prefixes {protection_prefixes}'''
                    case "flowspec":
                        ruleset = {
                            'Dst': hook.data.attributes.subobject.dst_prefix,
                            'Src': hook.data.attributes.subobject.src_prefix,
                            'Protocols': ', '.join(hook.data.attributes.subobject.protocol),
                            'Src Ports': f'''{', '.join([f'{port.low}-{port.high}' if port.low != port.high else f'{port.low}' for port in hook.data.attributes.subobject.src_port])}''' if hook.data.attributes.subobject.src_port else '',
                            'Dst Ports': f'''{', '.join([f'{port.low}-{port.high}' if port.low != port.high else f'{port.low}' for port in hook.data.attributes.subobject.dst_port])}''' if hook.data.attributes.subobject.dst_port else '',
                            'Packet Length': ', '.join(hook.data.attributes.subobject.packet_length),
                            'Fragment': ', '.join(hook.data.attributes.subobject.fragment),
                            'Action': hook.data.attributes.subobject.action.type
                           }
                        rule = '   '.join(f'<b>{key}:</b>  {val}' for key, val in ruleset.items() if val)
                    case _:
                        return

                text = (
                    f'''<b>{hook.data.attributes.name}</b> [{''.join([alert_link, mitigation_link])}]\n'''
                    f'''<code>{hook.data.links.self.host}</code>\n\n'''
                    f'''{rule}\n\n'''
                    f'''Customer: <code>{blob.name if blob.name else '%service_id%'}</code> {f"(<code>{blob.tenant.name if blob.tenant.name else '%tenant%'}</code>)" if blob.id else ""}\n\n'''
                    f'''{format_time(hook.data.attributes)}'''
                    )

            case _:
                do_inform = True
                chat_indicators = []

        if do_inform:
            chat_ids = []
            if chat_indicators:
                for chat_indicator in chat_indicators:
                    match chat_indicator:
                        case "SP" | "TMS":
                            chat_ids.append(creds.tg[vars.BOT_NAME].groups[f'[GBL-{chat_indicator}] Alerts']
                                            if hook.arborType == "ipt" else
                                            creds.tg[vars.BOT_NAME].groups[f'[DATA-{chat_indicator}] Alerts'])
                        case "BB":
                            chat_ids.append(creds.tg[vars.BOT_NAME].groups['Arbor Events'])
                        case "FREE":
                            chat_ids.append(creds.tg[vars.BOT_NAME].groups[f'[GBL-TMS] Free']
                                            if hook.arborType == "ipt" else
                                            creds.tg[vars.BOT_NAME].groups[f'[DATA-TMS] Free'])
                        case _:
                            chat_ids.append(creds.tg[vars.BOT_NAME].groups[vars.BOT_DFT_CHAT])
            else:
                chat_ids.append(creds.tg[vars.BOT_NAME].groups[vars.BOT_DFT_CHAT])

            if text:
                for chat_id in chat_ids:
                    match hook.data.type:
                        case 'mitigation':
                            reply_to_message_id = redis.get(f'bots.{vars.BOT_NAME}.groups.{abs(chat_id)}.alerts.{hook.data.relationships.alert.data.id}')
                        case _:
                            reply_to_message_id = redis.get(f'bots.{vars.BOT_NAME}.groups.{abs(chat_id)}.alerts.{hook.data.id}')

                    message_id = await msg(
                        text=text,
                        reply_to_message_id=int(reply_to_message_id) if reply_to_message_id else None,
                        token=creds.tg[vars.BOT_NAME].token,
                        chat_id=chat_id
                        )

                    if message_id:
                        match hook.data.type:
                            case 'mitigation':
                                redis.set(f'bots.{vars.BOT_NAME}.groups.{abs(chat_id)}.alerts.{hook.data.relationships.alert.data.id}', message_id)
                                redis.expire(f'bots.{vars.BOT_NAME}.groups.{abs(chat_id)}.alerts.{hook.data.relationships.alert.data.id}', timedelta(hours=72))
                            case _:
                                redis.set(f'bots.{vars.BOT_NAME}.groups.{abs(chat_id)}.alerts.{hook.data.id}', message_id)
                                redis.expire(f'bots.{vars.BOT_NAME}.groups.{abs(chat_id)}.alerts.{hook.data.id}', timedelta(hours=72))
            else:
                for chat_id in chat_ids:
                    await msg(
                        data={"filename": f"{hook.data.id}.json", "data": hook.response},
                        token=creds.tg[vars.BOT_NAME].token,
                        chat_id=chat_id
                        )
    except Exception:
        tb = traceback.format_exc()
        await msg(
            data={"filename": "exception.json", "data": json.dumps(hook.response) + f"\n\n{tb}"},
            token=creds.tg[vars.BOT_NAME].token,
            chat_id=creds.tg[vars.BOT_NAME].groups[vars.BOT_DFT_CHAT]
            )
