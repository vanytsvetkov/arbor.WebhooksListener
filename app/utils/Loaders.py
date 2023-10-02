import base64
import glob
import json
import os

from jinja2 import Template

import vars


def load_datafiles(directory) -> dict:
    with open(f'{directory}/app/{vars.DATA_DIR}/fish.html') as fish:
        template = Template(fish.read(), autoescape=True)

    with open(f'{directory}/app/{vars.DATA_DIR}/protocol_lookup.json') as protocol_lookup_file:
        protocol_lookup = json.load(protocol_lookup_file)

    with open(f'{directory}/app/{vars.DATA_DIR}/tcp_port_lookup.json') as tcp_port_lookup_file:
        tcp_port_lookup = json.load(tcp_port_lookup_file)

    with open(f'{directory}/app/{vars.DATA_DIR}/udp_port_lookup.json') as udp_port_lookup_file:
        udp_port_lookup = json.load(udp_port_lookup_file)

    country_flags = {}
    for file_path in glob.glob(f'{directory}/app/{vars.DATA_DIR}/flags/*.png'):
        country = os.path.splitext(os.path.basename(file_path))[0]
        with open(file_path, 'rb') as flag_file:
            country_flags[country.upper()] = base64.b64encode(flag_file.read()).decode("utf-8")

    with open(f'{directory}/app/{vars.DATA_DIR}/range_asn_lookup.json') as range_asn_lookup_file:
        range_asn_lookup = json.load(range_asn_lookup_file)

    return {
        'template': template,
        'protocol_lookup': protocol_lookup,
        'tcp_port_lookup': tcp_port_lookup,
        'udp_port_lookup': udp_port_lookup,
        'country_flags': country_flags,
        'range_asn_lookup': range_asn_lookup
        }
