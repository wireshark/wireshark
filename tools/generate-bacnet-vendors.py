#!/usr/bin/env python3
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''Update the BACNET vendors list.

generate-bacnet-vendors generates output containing BACNET vendor Identifiers.

Copyright 2023 Jaap Keuter <jaap.keuter@xs4all.nl>
based on work by Anish Bhatt <anish@chelsio.com>

'''

import sys
import urllib.request, urllib.error, urllib.parse
from bs4 import BeautifulSoup

def exit_msg(msg=None, status=1):
    if msg is not None:
        sys.stderr.write(msg + '\n\n')
    sys.stderr.write(__doc__ + '\n')
    sys.exit(status)

req_headers = { 'User-Agent': 'Wireshark generate-bacnet-vendors' }
try:
    req = urllib.request.Request("https://bacnet.org/assigned-vendor-ids/", headers=req_headers)
    response = urllib.request.urlopen(req)
    lines = response.read().decode()
    response.close()
except urllib.error.HTTPError as err:
    exit_msg("HTTP error fetching {0}: {1}".format(url, err.reason))
except urllib.error.URLError as err:
    exit_msg("URL error fetching {0}: {1}".format(url, err.reason))
except OSError as err:
    exit_msg("OS error fetching {0}".format(url, err.strerror))
except Exception:
    exit_msg("Unexpected error:", sys.exc_info()[0])

soup = BeautifulSoup(lines, "html.parser")
table = soup.find('table')
rows = table.findAll('tr')

entry = "static const value_string\nBACnetVendorIdentifiers [] = {"

for tr in rows:
    cols = tr.findAll('td')
    for index,td in enumerate(cols[0:2]):
        text = ''.join(td.find(string=True))
        if index == 0:
            entry = "    { %4s" % text
        else:
            entry += ", \"%s\" }," % text.rstrip()
    print(entry)

entry = "    { 0, NULL }\n};"
print(entry)

