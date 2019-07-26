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

iana_svc_url = 'http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv'

__doc__ = '''\
Usage: make-services.py [url]

url defaults to
    %s
''' % (iana_svc_url)

import sys
import getopt
import csv
import re
import collections

import urllib.request, urllib.error, urllib.parse
import codecs

services_file = 'services'

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
            return tuple([int(p[0]), int(p[1])])
    except ValueError:
        pass
    return ()

def port_to_str(port):
    if len(port) == 2:
        return str(port[0]) + '-' + str(port[1])
    return str(port[0])

def parse_rows(svc_fd):
    lines = []
    port_reader = csv.reader(svc_fd)
    count = 0

    # Header positions as of 2013-08-06
    headers = next(port_reader)

    try:
        sn_pos = headers.index('Service Name')
    except:
        sn_pos = 0
    try:
        pn_pos = headers.index('Port Number')
    except:
        pn_pos = 1
    try:
        tp_pos = headers.index('Transport Protocol')
    except:
        tp_pos = 2
    try:
        desc_pos = headers.index('Description')
    except:
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

        if not port in services_map:
            services_map[port] = collections.OrderedDict()

        # Remove some duplicates (first entry wins)
        proto_exists = False
        for k in services_map[port].keys():
            if proto in services_map[port][k]:
                proto_exists = True
                break
        if proto_exists:
            continue

        if not service in services_map[port]:
            services_map[port][service] = [description]
        services_map[port][service].append(proto)

    if count < min_source_lines:
        exit_msg('Not enough parsed data')

    return services_map

def write_body(d, f):
    keys = list(d.keys())
    keys.sort()

    for port in keys:
        for serv in d[port].keys():
            sep = "\t" * (1 + abs((15 - len(serv)) // 8))
            port_str = port_to_str(port) + "/" + "/".join(d[port][serv][1:])
            line = serv + sep + port_str
            description = d[port][serv][0]
            if description:
                sep = "\t"
                if len(port_str) < 8:
                    sep *= 2
                line += sep + "# " + description
            line += "\n"
            f.write(line)

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
        opts, args = getopt.getopt(argv, "h", ["help"])
    except getopt.GetoptError:
        exit_msg()
    for opt, arg in opts:
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
    except:
        exit_msg('Error opening ' + svc_url)

    body = parse_rows(svc_fd)

    out = open(services_file, 'w')
    out.write('''\
# This is a local copy of the IANA port-numbers file.
#
# Wireshark uses it to resolve port numbers into human readable
# service names, e.g. TCP port 80 -> http.
#
# It is subject to copyright and being used with IANA's permission:
# https://www.wireshark.org/lists/wireshark-dev/200708/msg00160.html
#
# The original file can be found at:
# %s
#
# The format is the same as that used for services(5). It is allowed to merge
# identical protocols, for example:
#   foo 64/tcp
#   foo 64/udp
# becomes
#   foo 64/tcp/udp
#

''' % (iana_svc_url))

    write_body(body, out)

    out.close()

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
