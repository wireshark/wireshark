#!/usr/bin/env python
#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Write captures/dhcp.pcap to stdout, pause 1.5 seconds, and write it again.'''

import os
import os.path
import time
import sys

if sys.version_info[0] < 3 and sys.platform == "win32":
    import msvcrt
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

dhcp_pcap = os.path.join(os.path.dirname(__file__), 'captures', 'dhcp.pcap')

dhcp_fd = open(dhcp_pcap, 'rb')
contents = dhcp_fd.read()
os.write(1, contents)
time.sleep(1.5)
os.write(1, contents[24:])
