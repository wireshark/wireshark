#!/usr/bin/env python
#
# Parses the CSV version of the IANA Service Name and Transport Protocol Port Number Registry
# and generates a services(5) file.
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2013 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

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

python_version = sys.hexversion >> 16
if python_version < 0x300:
    import urllib
else:
    import urllib.request, urllib.error, urllib.parse
    import codecs

services_file = 'services'

exclude_services = [
    '^spr-itunes',
    '^spl-itunes',
    '^shilp',
    ]

exclude_comments = [
    'should not be used for discovery purposes',
    'NOTE Conflict',
]

min_body_size = 900000 # Size was ~ 922000 on 2013-08-06

def parse_rows(svc_fd):
    lines = []
    port_reader = csv.reader(svc_fd)

    # Header positions as of 2013-08-06
    if python_version < 0x206:
        headers = port_reader.next()
    else:
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

    positions = [sn_pos, pn_pos, tp_pos]
    positions.sort()
    positions.reverse()

    for row in port_reader:
        service = row[sn_pos]
        port = row[pn_pos]
        proto = row[tp_pos]
        
        if len(service) < 1 or len(port) < 1 or len(proto) < 1:
            continue
            
        for pos in positions:
            del row[pos]
        row = filter(None, row)
        comment = ' '.join(row)
        comment = re.sub('[\n]', '', comment)
        
        if re.search('|'.join(exclude_services), service):
            continue
        if re.search('|'.join(exclude_comments), comment):
            continue

        lines.append('%-15s %5s/%s # %s' % (
            service,
            port,
            proto,
            comment
        ))

    return '\n'.join(lines)

def exit_msg(msg=None, status=1):
    if msg is not None:
        sys.stderr.write(msg + '\n\n')
    sys.stderr.write(__doc__ + '\n')
    sys.exit(status)

def main(argv):
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
        if python_version < 0x300:
            svc_fd = urllib.urlopen(svc_url)
        else:
            req = urllib.request.urlopen(svc_url)
            svc_fd = codecs.getreader('utf8')(req)
    except:
        exit_msg('Error opening ' + svc_url)

    body = parse_rows(svc_fd)
    if len(body) < min_body_size:
        exit_msg('Not enough parsed data')

    out = open(services_file, 'w')
    out.write('''\
# This is a local copy of the IANA port-numbers file.
#
# Wireshark uses it to resolve port numbers into human readable
# service names, e.g. TCP port 80 -> http.
#
# It is subject to copyright and being used with IANA's permission:
# http://www.wireshark.org/lists/wireshark-dev/200708/msg00160.html
#
# The original file can be found at:
# %s
#

%s
''' % (iana_svc_url, body))

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
