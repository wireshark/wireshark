#!/usr/bin/env python
#
# Wireshark tests
# By Gerald Combs <gerald@wireshark.org>
#
# Ported from a set of Bash scripts which were copyright 2005 Ulf Lamping
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Write captures/dhcp.pcap to stdout, optionally writing only packet records or writing them slowly.'''

import argparse
import os
import os.path
import time
import sys

def main():
    parser = argparse.ArgumentParser(description='Dump dhcp.pcap')
    parser.add_argument('dump_type', choices=['cat', 'slow', 'raw'],
        help='cat: Just dump the file. slow: Dump the file, pause, and dump its packet records. raw: Dump only the packet records.')
    args = parser.parse_args()

    if sys.version_info[0] < 3 and sys.platform == "win32":
        import msvcrt
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

    dhcp_pcap = os.path.join(os.path.dirname(__file__), 'captures', 'dhcp.pcap')

    dhcp_fd = open(dhcp_pcap, 'rb')
    contents = dhcp_fd.read()
    if args.dump_type != 'raw':
        os.write(1, contents)
    if args.dump_type == 'cat':
        sys.exit(0)
    if args.dump_type == 'slow':
        time.sleep(1.5)
    # slow, raw
    os.write(1, contents[24:])
    sys.exit(0)

if __name__ == '__main__':
    main()

