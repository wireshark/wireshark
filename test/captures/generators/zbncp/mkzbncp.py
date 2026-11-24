#!/usr/bin/env python3
# Generates test/captures/zbncp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the synthetic coverage captures for packet-zbncp.c.
# Usage: mkzbncp.py <outdir>
# Writes zbncp-coverage.pcap (clean), zbncp-coverage-malformed.pcap
# (truncated and oversized frames) and zbncp_coverage.pcap.gz (gzip of the
# clean one).  Everything is built with struct (zbnlib.py, zbntable.py);
# nothing is captured.  The capture is LINKTYPE_ZBOSS_NCP (292).
import gzip
import os
import shutil
import sys
from zbnlib import frame, LINKTYPE_ZBOSS_NCP, REQ, write_pcap
from zbntable import BODIES, CALL_IDS
import zbnextra


def clean_frames():
    F = []
    n = 0
    def add(name, fr):
        F.append((name, fr))
    seq = 0
    names = dict(CALL_IDS)
    by_id = {}
    for cid, pt, body in BODIES:
        by_id.setdefault(cid, []).append((pt, body))
    for cid, nm in CALL_IDS:
        if cid not in by_id:
            add('%s_req' % nm, frame(REQ, cid, b'', tsn=seq))
            continue
        for pt, body in by_id[cid]:
            # the packet and ack sequence numbers in the flags rotate
            flags = 0xC0 | ((seq & 3) << 2) | (((seq >> 2) & 3) << 4)
            seq += 1
            add('%s_%s' % (nm, 'req rsp ind'.split()[pt]),
                frame(pt, cid, bytes.fromhex(body), flags=flags, tsn=seq))
    for name, fr in zbnextra.extra_clean():
        add(name, fr)
    return F


def malformed_frames(good):
    out = []
    for name, fr in good:
        n = len(fr)
        for cut in sorted({n - 1, 10 + (n - 10) // 2}):
            if 7 < cut < n and fr[:5] != b'ZBNCP':
                out.append(fr[:cut])
    out.extend(zbnextra.extra_malformed())
    return out


def main(outdir):
    good = clean_frames()
    frames = [f for _, f in good]
    bad = malformed_frames(good)
    main_pcap = os.path.join(outdir, 'zbncp-coverage.pcap')
    write_pcap(main_pcap, LINKTYPE_ZBOSS_NCP, frames)
    write_pcap(os.path.join(outdir, 'zbncp-coverage-malformed.pcap'), LINKTYPE_ZBOSS_NCP, bad)
    with open(main_pcap, 'rb') as i, gzip.GzipFile(os.path.join(outdir, 'zbncp_coverage.pcap.gz'), 'wb', mtime=0) as o:
        shutil.copyfileobj(i, o)
    with open(os.path.join(outdir, 'zbncp-coverage.names'), 'w') as f:
        f.write('\n'.join('%d %s' % (i + 1, n) for i, (n, _) in enumerate(good)) + '\n')
    print('zbncp: %d clean frames, %d malformed frames' % (len(frames), len(bad)))


main(sys.argv[1] if len(sys.argv) > 1 else '.')
