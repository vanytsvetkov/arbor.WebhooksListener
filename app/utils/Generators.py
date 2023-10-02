import base64
import io
import json
import re
import tarfile
import tempfile
from datetime import datetime, timedelta
from email.message import EmailMessage

import matplotlib.pyplot as plt
from interactors import ArborAPI
from models import (
    Arbor,
    Report,
    Creds,
    Impact,
    Set,
    SetEncoder,
    Char,
    Excess,
    Pattern,
    PacketSize
)

from utils import format_value, whois


def gen_trafficQuery(unit: str, blob_id: int | str) -> dict:
    return {
            "data": {
                "attributes": {
                    "query_start_time": (datetime.utcnow() - timedelta(minutes=45)).isoformat(),
                    "query_end_time": datetime.utcnow().isoformat(),
                    "unit": unit,
                    "limit": 100,
                    "traffic_classes": ["in"],
                    "filters": [
                            {
                                "facet": "Customer",
                                "values": [str(blob_id) if isinstance(blob_id, int) else blob_id],
                                "groupby": True
                                }
                        ]
                    }
                }
            }


def gen_distribution_plot(data: list) -> str:
    max_values = [x.val for x in data]
    step = 50

    lows = [i.low for i in data][:-1]
    highs = [j.high for j in data][:-1]

    bins = [*lows, lows[-1] + step, lows[-1] + step*2]
    y_axis = [*[f"{l}-{h}" if not (i % 2) else "" for i, (l, h) in enumerate(zip(lows, highs))], "jumbo"]

    fig, ax = plt.subplots()

    ax.hist(
            x=bins[:-1],
            bins=bins,
            weights=max_values,
            facecolor='#3a7eb0',
            alpha=0.75,
            orientation=u'horizontal',
            rwidth=0.85
        )

    ax.set_yticks([y+step/2 for y in bins[:-1]])
    ax.set_yticklabels(y_axis)

    x_max = max(max_values)
    x_half = round(x_max/4)
    x_avg = round(x_max/2)
    x_avg_half = round(x_max*3/4)

    ax.set_xticks([0, x_half, x_avg, x_avg_half, x_max])
    ax.set_xticklabels(["0",
                        format_value(x_half, ""),
                        format_value(x_avg, ""),
                        format_value(x_avg_half, ""),
                        format_value(x_max, "")])

    plt.ylim(max(bins) + step, min(bins) - step)
    plt.xlabel('packets')

    distribution = io.BytesIO()
    plt.savefig(distribution, format='png', bbox_inches='tight', transparent=True)

    distribution.seek(0)
    return base64.b64encode(distribution.read()).decode("utf-8")


def gen_email(report: Report, blob: Arbor.Blob) -> bytes:
    message = EmailMessage()

    message['Subject'] = f'Уведомление о входящей атаке #{report.id}'
    message['From'] = 'noc@gblnet.net'
    message['To'] = blob.tenant.manager
    message['Cc'] = ', '.join(blob.tenant.emails)
    message['Bcc'] = 'noc@gblnet.net'

    message.add_header('Content-Type', 'text/html')
    message.set_content(report.content, subtype='html')

    if report.payload.ready:
        with tempfile.NamedTemporaryFile('rb+', suffix='.tar.gz') as tmp:
            with io.BytesIO() as out_stream, tarfile.open(fileobj=tmp, mode='w:gz') as tar:
                for key, payload in report.payload.dict().items():
                    if payload != report.payload.__fields__[key].default:
                        for item in payload:
                            if isinstance(item, dict) and 'flag' in item:
                                item.pop('flag')

                        out_stream.write(json.dumps(payload, indent=2, cls=SetEncoder).encode())

                        out_stream.seek(0)

                        info = tarfile.TarInfo(f'{key}.json')
                        info.size = len(out_stream.getbuffer())

                        tar.addfile(info, out_stream)

                        out_stream.truncate(0)
                        out_stream.flush()
                        out_stream.seek(0)

            tmp.flush()
            tmp.seek(0)

            attachment = tmp.read()
            message.add_attachment(attachment, maintype='application', subtype='.tar.gz', filename=f'payload#{report.id}.tar.gz')

    return bytes(message)


def gen_report(hook: Arbor.Response, creds: Creds, blob: Arbor.Blob, **kwargs) -> Report:

    report = Report(
            id=hook.data.id,
            arborType=hook.arborType,
            unit=hook.data.attributes.subobject.severity_unit,
            excess=Excess(
                    unit=hook.data.attributes.subobject.severity_unit,
                    percent=hook.data.attributes.subobject.severity_percent,
                    threshold=hook.data.attributes.subobject.severity_threshold,
                ),
            host=hook.data.attributes.subobject.host_address,
            start_time=hook.data.attributes.start_time + timedelta(hours=3),
            misuse_types=Set(*hook.data.attributes.subobject.misuse_types),
            impact=Impact(
                bps=hook.data.attributes.subobject.impact_bps,
                pps=hook.data.attributes.subobject.impact_pps
                )
        )

    api = ArborAPI(hook.arborType, creds)

    # Search for sources of attack
    source_ip_addresses = api.getAlertSources(report.id, params={'query_limit': 1000})
    if not source_ip_addresses.errors:
        report.sources = Set(*source_ip_addresses.data.attributes.source_ips)

    # Search for related interfaces: peers and victims
    router_interface_traffics = api.getAlertRouterTraffic(report.id, params={'include': 'interface_traffic', 'query_unit': report.unit})
    if not router_interface_traffics.errors:
        for router_interface_traffic in router_interface_traffics.included:
            # Avoid exception when working with old peakflow api (less v9.0.0)
            if not isinstance(router_interface_traffic, tuple):
                for router_gid, interface_traffic in router_interface_traffic.attributes.view.items():
                    report.peers.update(re.findall(report.servicePattern, interface_traffic.direction.incoming.unit[report.unit].snmp_description))
                    for service in re.findall(report.servicePattern, interface_traffic.direction.outgoing.unit[report.unit].snmp_description):
                        if service in blob.tenant.services:
                            report.services.add(service)


    # # # # # # # # # # # # # # # # # #
    # Building attack characteristics #
    # # # # # # # # # # # # # # # # # #

    # Search for misuse types of attack
    traffic_misuse_types = api.getAlertTrafficMisuseTypes(report.id, params={'query_limit': 1000, 'query_unit': report.unit})
    if not traffic_misuse_types.errors:
        total_traffic = 0
        for mt in traffic_misuse_types.data:
            if mt.attributes.view.network.unit[report.unit].name == 'Total Traffic':
                total_traffic = mt.attributes.view.network.unit[report.unit].pct95_value
                break

        if total_traffic:
            report.table.characteristics.misuse_types = sorted([
                    Char(
                        name=mt.attributes.view.network.unit[report.unit].name,
                        pct=pct
                        ) for mt in traffic_misuse_types.data if mt.attributes.view.network.unit[report.unit].name in report.misuse_types and (pct := round(mt.attributes.view.network.unit[report.unit].pct95_value/total_traffic * 100))
                ], key=lambda char: char.pct, reverse=True)

    # Search for source prefixes
    traffic_src_prefixes = api.getAlertTrafficSrcPrefixes(report.id, params={'query_limit': 1000, 'query_unit': report.unit})
    if not traffic_src_prefixes.errors:
        total_traffic = 0
        for src_prefix in traffic_src_prefixes.data:
            if src_prefix.attributes.view.network.unit[report.unit].name == '0.0.0.0/0':
                report.table.characteristics.highly_distributed = True
                break
            total_traffic += src_prefix.attributes.view.network.unit[report.unit].pct95_value

        if not report.table.characteristics.highly_distributed and total_traffic:
            report.table.characteristics.sources = sorted([
                    Char(
                        name=src_prefix.attributes.view.network.unit[report.unit].name,
                        pct=pct
                        ) for src_prefix in traffic_src_prefixes.data if (pct := round(src_prefix.attributes.view.network.unit[report.unit].pct95_value/total_traffic * 100))
                ], key=lambda char: char.pct, reverse=True)

    # Search for destination prefixes
    traffic_dst_prefixes = api.getAlertTrafficDstPrefixes(report.id, params={'query_limit': 1000, 'query_unit': report.unit})
    if not traffic_dst_prefixes.errors:
        total_traffic = sum(dst_prefix.attributes.view.network.unit[report.unit].pct95_value for dst_prefix in traffic_dst_prefixes.data)

        if total_traffic:
            report.table.characteristics.destinations = sorted([
                    Char(
                        name=dst_prefix.attributes.view.network.unit[report.unit].name,
                        pct=pct
                        ) for dst_prefix in traffic_dst_prefixes.data if (pct := round(dst_prefix.attributes.view.network.unit[report.unit].pct95_value/total_traffic * 100))
                ], key=lambda char: char.pct, reverse=True)

    # Search for protocols prefixes
    traffic_protocols = api.getAlertTrafficProtocols(report.id, params={'query_limit': 1000, 'query_unit': report.unit})
    if not traffic_protocols.errors:
        total_traffic = sum(prot.attributes.view.network.unit[report.unit].pct95_value for prot in traffic_protocols.data)

        if total_traffic:
            report.table.characteristics.protocols = sorted([
                    Char(
                        name=prot.attributes.view.network.unit[report.unit].name,
                        val=prot.subid,
                        pct=pct
                        ) for prot in traffic_protocols.data if (pct := round(prot.attributes.view.network.unit[report.unit].pct95_value/total_traffic * 100))
                ], key=lambda char: char.pct, reverse=True)

    # Search for the source and destination ports

    if 'tcp' in report.protocols:
        traffic_src_tcp_ports = api.getAlertTrafficSrcTcpPorts(report.id, params={'query_limit': 1000, 'query_unit': report.unit})
        if not traffic_src_tcp_ports.errors:
            total_traffic = sum(port.attributes.view.network.unit[report.unit].pct95_value for port in traffic_src_tcp_ports.data)

            if total_traffic:
                report.table.characteristics.src_tcp_ports = sorted([
                        Char(
                            name=port.attributes.view.network.unit[report.unit].name,
                            val=kwargs.get('tcp_port_lookup')[port.subid]
                            if port.subid in kwargs.get('tcp_port_lookup')
                            else port.attributes.view.network.unit[report.unit].name,
                            pct=pct
                            ) for port in traffic_src_tcp_ports.data if (pct := round(port.attributes.view.network.unit[report.unit].pct95_value/total_traffic * 100))
                    ], key=lambda char: char.pct, reverse=True)

        traffic_dst_tcp_ports = api.getAlertTrafficDstTcpPorts(report.id, params={'query_limit': 1000, 'query_unit': report.unit})
        if not traffic_dst_tcp_ports.errors:
            total_traffic = sum(port.attributes.view.network.unit[report.unit].pct95_value for port in traffic_dst_tcp_ports.data)

            if total_traffic:
                report.table.characteristics.dst_tcp_ports = sorted([
                        Char(
                            name=port.attributes.view.network.unit[report.unit].name,
                            val=kwargs.get('tcp_port_lookup')[port.subid]
                            if port.subid in kwargs.get('tcp_port_lookup')
                            else port.attributes.view.network.unit[report.unit].name,
                            pct=pct
                            ) for port in traffic_dst_tcp_ports.data if (pct := round(port.attributes.view.network.unit[report.unit].pct95_value/total_traffic * 100))
                    ], key=lambda char: char.pct, reverse=True)

    if 'udp' in report.protocols:
        traffic_src_udp_ports = api.getAlertTrafficSrcUdpPorts(report.id, params={'query_limit': 1000, 'query_unit': report.unit})
        if not traffic_src_udp_ports.errors:
            total_traffic = sum(port.attributes.view.network.unit[report.unit].pct95_value for port in traffic_src_udp_ports.data)

            if total_traffic:
                report.table.characteristics.src_udp_ports = sorted([
                        Char(
                            name=port.attributes.view.network.unit[report.unit].name,
                            val=kwargs.get('udp_port_lookup')[port.subid]
                            if port.subid in kwargs.get('udp_port_lookup')
                            else port.attributes.view.network.unit[report.unit].name,
                            pct=pct
                            ) for port in traffic_src_udp_ports.data if (pct := round(port.attributes.view.network.unit[report.unit].pct95_value/total_traffic * 100))
                    ], key=lambda char: char.pct, reverse=True)

        traffic_dst_udp_ports = api.getAlertTrafficDstUdpPorts(report.id, params={'query_limit': 1000, 'query_unit': report.unit})
        if not traffic_dst_udp_ports.errors:
            total_traffic = sum(port.attributes.view.network.unit[report.unit].pct95_value for port in traffic_dst_udp_ports.data)

            if total_traffic:
                report.table.characteristics.dst_udp_ports = sorted([
                        Char(
                            name=port.attributes.view.network.unit[report.unit].name,
                            val=kwargs.get('udp_port_lookup')[port.subid]
                            if port.subid in kwargs.get('udp_port_lookup')
                            else port.attributes.view.network.unit[report.unit].name,
                            pct=pct
                            ) for port in traffic_dst_udp_ports.data if (pct := round(port.attributes.view.network.unit[report.unit].pct95_value/total_traffic * 100))
                    ], key=lambda char: char.pct, reverse=True)

    # Search for countries
    traffic_src_countries = api.getAlertTrafficCounties(report.id, params={'query_limit': 1000, 'query_unit': report.unit})
    if not traffic_src_countries.errors:
        total_traffic = sum(country.attributes.view.network.unit[report.unit].pct95_value for country in traffic_src_countries.data)

        if total_traffic:
            report.table.characteristics.countries = sorted([
                    Char(
                        name=country.attributes.view.network.unit[report.unit].name,
                        flag=kwargs.get('country_flags')[country.attributes.view.network.unit[report.unit].country_code]
                        if country.attributes.view.network.unit[report.unit].country_code in kwargs.get('country_flags')
                        else kwargs.get('country_flags')['DEFAULT'],
                        pct=pct
                        ) for country in traffic_src_countries.data if (pct := round(country.attributes.view.network.unit[report.unit].pct95_value/total_traffic * 100))
                ], key=lambda char: char.pct, reverse=True)

    # Search for the source and destination asn

    traffic_src_asn = api.getAlertTrafficSrcAsn(report.id, params={'query_limit': 1000, 'query_unit': report.unit})
    if not traffic_src_asn.errors:
        total_traffic = sum(asn.attributes.view.network.unit[report.unit].pct95_value for asn in traffic_src_asn.data)

        if total_traffic:
            report.table.characteristics.src_asn = sorted([
                    Char(
                        name=asn.attributes.view.network.unit[report.unit].name,
                        val=whois(asn.attributes.view.network.unit[report.unit].name, kwargs.get('range_asn_lookup')),
                        pct=pct
                        ) for asn in traffic_src_asn.data if (pct := round(asn.attributes.view.network.unit[report.unit].pct95_value/total_traffic * 100))
                ], key=lambda char: char.pct, reverse=True)

    traffic_dst_asn = api.getAlertTrafficDstAsn(report.id, params={'query_limit': 1000, 'query_unit': report.unit})
    if not traffic_dst_asn.errors:
        total_traffic = sum(asn.attributes.view.network.unit[report.unit].pct95_value for asn in traffic_dst_asn.data)

        if total_traffic:
            report.table.characteristics.dst_asn = sorted([
                    Char(
                        name=asn.attributes.view.network.unit[report.unit].name,
                        val=whois(asn.attributes.view.network.unit[report.unit].name, kwargs.get('range_asn_lookup')),
                        pct=pct
                        ) for asn in traffic_dst_asn.data if (pct := round(asn.attributes.view.network.unit[report.unit].pct95_value/total_traffic * 100))
                ], key=lambda char: char.pct, reverse=True)

    # # # # # # # # # # # # # # # # #
    #  Building packet distribution #
    # # # # # # # # # # # # # # # # #

    packet_size_distributions = api.getAlertPacketSizeDistribution(report.id, params={'query_limit': 1000})
    if not packet_size_distributions.errors:
        report.table.distribution.packet_size_distribution = sorted([
                PacketSize(
                        high=psd.view.network.packet_size_range.high,
                        low=psd.view.network.packet_size_range.low,
                        val=psd.view.network.pct95_value,
                    ) for psd in packet_size_distributions.data.attributes.packet_size_distribution
            ], key=lambda psd: psd.low)

        if any(psd.val for psd in report.table.distribution.packet_size_distribution):
            report.table.distribution.plot = gen_distribution_plot(report.table.distribution.packet_size_distribution)

    # # # # # # # # # # # # # # #
    #  Building attack patterns #
    # # # # # # # # # # # # # # #

    patterns = api.getAlertPatterns(report.id, params={'query_limit': 1000, 'query_unit': report.unit})
    if not patterns.errors:
        report.table.patterns = sorted([
                Pattern(
                    src=list(pattern.attributes.view.values())[0].src_prefix,
                    dst=list(pattern.attributes.view.values())[0].dst_prefix,

                    prot=kwargs.get('protocol_lookup')[list(pattern.attributes.view.values())[0].protocol].upper(),

                    flags=''.join(list(pattern.attributes.view.values())[0].all_tcp_flags)
                    if list(pattern.attributes.view.values())[0].all_tcp_flags else '--',

                    src_port=list(pattern.attributes.view.values())[0].src_port_range,
                    dst_port=list(pattern.attributes.view.values())[0].dst_port_range,

                    val=pct95,
                    unit=report.unit
                    ) for pattern in patterns.data if (pct95 := list(pattern.attributes.view.values())[0].traffic_data.pct95)
            ], key=lambda p: p.val, reverse=True)

    if report.payload.ready:
        report.is_payload = True

    return report
