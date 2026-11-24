#!/usr/bin/env python3
# Generates test/captures/zbee_zdp_discovery_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the synthetic coverage captures for packet-zbee-zdp-discovery.c.
# Usage: mkzbee-zdp-discovery.py <outdir>
# Writes zbee-zdp-discovery-coverage.pcap (clean), zbee-zdp-discovery-coverage-malformed.pcap
# (truncated messages) and zbee_zdp_discovery_coverage.pcap.gz (gzip of the clean one).
# Everything is built with struct in zdplib.py; nothing is captured.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import gzip
import shutil
from zdplib import frames_discovery, LINKTYPE_IEEE802_15_4_NOFCS, truncated, write_pcap

def main(outdir):
    good = frames_discovery()
    frames = [f for n, f in good]
    bad = truncated(frames)
    main_pcap = os.path.join(outdir, 'zbee-zdp-discovery-coverage.pcap')
    write_pcap(main_pcap, LINKTYPE_IEEE802_15_4_NOFCS, frames)
    write_pcap(os.path.join(outdir, 'zbee-zdp-discovery-coverage-malformed.pcap'),
               LINKTYPE_IEEE802_15_4_NOFCS, bad)
    with open(main_pcap, 'rb') as i, gzip.GzipFile(os.path.join(outdir, 'zbee_zdp_discovery_coverage.pcap.gz'), 'wb', mtime=0) as o:
        shutil.copyfileobj(i, o)
    with open(os.path.join(outdir, 'zbee-zdp-discovery-coverage.names'), 'w') as f:
        f.write('\n'.join('%d %s' % (i + 1, n) for i, (n, _) in enumerate(good)) + '\n')
    print('zbee-zdp-discovery: %d clean frames, %d malformed frames' % (len(frames), len(bad)))

main(sys.argv[1] if len(sys.argv) > 1 else '.')
