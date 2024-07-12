#!/usr/bin/env python3
#
# Parses the CSV version of the IANA Service Name and Transport Protocol Port Number Registry
# and generates a services(5) file.
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2013 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import sys
import getopt
import csv
import re
import collections
import urllib.request, urllib.error, urllib.parse
import codecs

iana_svc_url = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv'

__doc__ = '''\
Usage: make-services.py [url]

url defaults to
    %s
''' % (iana_svc_url)


services_file = 'epan/services-data.c'

exclude_services = [
    '^spr-itunes',
    '^spl-itunes',
    '^shilp',
    ]

min_source_lines = 14000 # Size was ~ 14800 on 2017-07-20

def parse_port(port_str):

    p = port_str.split('-')
    try:
        if len(p) == 1:
            return tuple([int(p[0])])
        if len(p) == 2:
            return tuple(range(int(p[0]), int(p[1]) + 1))
    except ValueError:
        pass
    return ()

def port_to_str(port):
    if len(port) == 2:
        return str(port[0]) + '-' + str(port[1])
    return str(port[0])

def parse_rows(svc_fd):
    port_reader = csv.reader(svc_fd)
    count = 0

    # Header positions as of 2013-08-06
    headers = next(port_reader)

    try:
        sn_pos = headers.index('Service Name')
    except Exception:
        sn_pos = 0
    try:
        pn_pos = headers.index('Port Number')
    except Exception:
        pn_pos = 1
    try:
        tp_pos = headers.index('Transport Protocol')
    except Exception:
        tp_pos = 2
    try:
        desc_pos = headers.index('Description')
    except Exception:
        desc_pos = 3

    services_map = {}

    for row in port_reader:
        service = row[sn_pos]
        port = parse_port(row[pn_pos])
        proto = row[tp_pos]
        description = row[desc_pos]
        count += 1

        if len(service) < 1 or not port or len(proto) < 1:
            continue

        if re.search('|'.join(exclude_services), service):
            continue

        # max 15 chars
        service = service[:15].rstrip()

        # replace blanks (for some non-standard long names)
        service = service.replace(" ", "-")

        description = description.replace("\n", "")
        description = re.sub("IANA assigned this well-formed service .+$", "", description)
        description = re.sub("  +", " ", description)
        description = description.strip()
        if description == service or description == service.replace("-", " "):
            description = None

        if port not in services_map:
            services_map[port] = collections.OrderedDict()

        # Remove some duplicates (first entry wins)
        proto_exists = False
        for k in services_map[port].keys():
            if proto in services_map[port][k]:
                proto_exists = True
                break
        if proto_exists:
            continue

        if service not in services_map[port]:
            services_map[port][service] = [description]
        services_map[port][service].append(proto)

    if count < min_source_lines:
        exit_msg('Not enough parsed data')

    return services_map

def compile_body(d):
    keys = list(d.keys())
    keys.sort()
    body = []

    for port in keys:
        for serv in d[port].keys():
            line = [port, d[port][serv][1:], serv]
            description = d[port][serv][0]
            if description:
                line.append(description)
            body.append(line)

    return body

def add_entry(table, port, service_name, description):
    table.append([int(port), service_name, description])


 # body = [(port-range,), [proto-list], service-name, optional-description]
 # table = [port-number, service-name, optional-description]
def compile_tables(body):

    body.sort()
    tcp_udp_table = []
    tcp_table = []
    udp_table = []
    sctp_table = []
    dccp_table = []

    for entry in body:
        if len(entry) == 4:
            port_range, proto_list, service_name, description = entry
        else:
            port_range, proto_list, service_name = entry
            description = None

        for port in port_range:
            if 'tcp' in proto_list and 'udp' in proto_list:
                add_entry(tcp_udp_table, port, service_name, description)
            else:
                if 'tcp' in proto_list:
                    add_entry(tcp_table, port, service_name, description)
                if 'udp' in proto_list:
                    add_entry(udp_table, port, service_name, description)
            if 'sctp' in proto_list:
                add_entry(sctp_table, port, service_name, description)
            if 'dccp' in proto_list:
                add_entry(dccp_table, port, service_name, description)

    return tcp_udp_table, tcp_table, udp_table, sctp_table, dccp_table


def exit_msg(msg=None, status=1):
    if msg is not None:
        sys.stderr.write(msg + '\n\n')
    sys.stderr.write(__doc__ + '\n')
    sys.exit(status)

def main(argv):
    if sys.version_info[0] < 3:
        print("This requires Python 3")
        sys.exit(2)

    try:
        opts, _ = getopt.getopt(argv, "h", ["help"])
    except getopt.GetoptError:
        exit_msg()
    for opt, _ in opts:
        if opt in ("-h", "--help"):
            exit_msg(None, 0)

    if (len(argv) > 0):
        svc_url = argv[0]
    else:
        svc_url = iana_svc_url

    try:
        if not svc_url.startswith('http'):
            svc_fd = open(svc_url)
        else:
            req = urllib.request.urlopen(svc_url)
            svc_fd = codecs.getreader('utf8')(req)
    except Exception:
        exit_msg('Error opening ' + svc_url)

    body = parse_rows(svc_fd)

    out = open(services_file, 'w')
    out.write('''\
/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This is a local copy of the IANA port-numbers file.
 *
 * Wireshark uses it to resolve port numbers into human readable
 * service names, e.g. TCP port 80 -> http.
 *
 * It is subject to copyright and being used with IANA's permission:
 * https://www.wireshark.org/lists/wireshark-dev/200708/msg00160.html
 *
 * The original file can be found at:
 * %s
 *
 * Generated by tools/make-services.py
 */

''' % (iana_svc_url))

    body = compile_body(body)
    # body = [(port-range,), [proto-list], service-name, optional-description]

    max_port = 0

    tcp_udp, tcp, udp, sctp, dccp = compile_tables(body)

    def write_entry(f, e, max_port):
        line = "    {{ {}, \"{}\", ".format(*e)
        sep_len = 32 - len(line)
        if sep_len <= 0:
            sep_len = 1
        line += ' ' * sep_len
        if len(e) == 3 and e[2]:
            line += "\"{}\" }},\n".format(e[2].replace('"', '\\"'))
        else:
            line += "\"\" },\n"
        f.write(line)
        if int(e[0]) > int(max_port):
            return e[0]
        return max_port

    out.write("static const ws_services_entry_t global_tcp_udp_services_table[] = {\n")
    for e in tcp_udp:
        max_port = write_entry(out, e, max_port)
    out.write("};\n\n")

    out.write("static const ws_services_entry_t global_tcp_services_table[] = {\n")
    for e in tcp:
        max_port = write_entry(out, e, max_port)
    out.write("};\n\n")

    out.write("static const ws_services_entry_t global_udp_services_table[] = {\n")
    for e in udp:
        max_port = write_entry(out, e, max_port)
    out.write("};\n\n")

    out.write("static const ws_services_entry_t global_sctp_services_table[] = {\n")
    for e in sctp:
        max_port = write_entry(out, e, max_port)
    out.write("};\n\n")

    out.write("static const ws_services_entry_t global_dccp_services_table[] = {\n")
    for e in dccp:
        max_port = write_entry(out, e, max_port)
    out.write("};\n\n")

    out.write("static const uint16_t _services_max_port = {};\n".format(max_port))

    out.close()

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
