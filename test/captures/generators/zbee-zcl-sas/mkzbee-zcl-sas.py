#!/usr/bin/env python3
# Generates test/captures/zbee-zcl-sas_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Coverage capture generator for packet-zbee-zcl-sas.c (ZigBee ZCL sas clusters)
# Synthetic ZigBee frames, generated with struct only: 802.15.4 (linktype
# 230, no FCS) -> ZigBee NWK -> APS (HA profile) -> ZCL, reached through
# the default zbee_nwk heuristic.  Addresses are made up.
#   usage: mkzbee-zcl-sas.py <outdir>
# writes zbee-zcl-sas-coverage.pcap, zbee-zcl-sas-coverage-malformed.pcap and
# zbee-zcl-sas_coverage.pcap.gz
import struct
import sys
import os
import gzip

# cluster id -> (name, attributes, cluster-specific commands)
#   attribute entries: (attr id, data type, data length, fill) ; the data
#   is zeros, a 1..n ramp or 0xff bytes (strings carry the length byte)
#   command entries:   (command id, FCF direction bit, fill, payload length)
CLUSTERS = {1281: ('ias_ace', [],
        [(0, 0, 'ramp', 0), (0, 0, 'ramp', 40), (0, 0, 'zero', 0), (0, 0, 'zero', 40),
         (0, 1, 'ramp', 0), (0, 1, 'ramp', 40), (0, 1, 'zero', 0), (0, 1, 'zero', 40),
         (1, 0, 'ramp', 0), (1, 0, 'ramp', 40), (1, 0, 'zero', 0), (1, 0, 'zero', 40),
         (1, 1, 'ramp', 0), (1, 1, 'ramp', 40), (1, 1, 'zero', 0), (1, 1, 'zero', 40),
         (2, 0, 'ramp', 0), (2, 0, 'ramp', 40), (2, 0, 'zero', 0), (2, 0, 'zero', 40),
         (2, 1, 'ramp', 0), (2, 1, 'ramp', 40), (2, 1, 'zero', 0), (2, 1, 'zero', 40),
         (3, 0, 'ramp', 0), (3, 0, 'ramp', 40), (3, 0, 'zero', 0), (3, 0, 'zero', 40),
         (3, 1, 'ramp', 0), (3, 1, 'ramp', 40), (3, 1, 'zero', 0), (3, 1, 'zero', 40),
         (4, 0, 'ramp', 0), (4, 0, 'ramp', 40), (4, 0, 'zero', 0), (4, 0, 'zero', 40),
         (4, 1, 'ramp', 0), (4, 1, 'ramp', 40), (4, 1, 'zero', 0), (4, 1, 'zero', 40),
         (5, 0, 'ramp', 0), (5, 0, 'ramp', 40), (5, 0, 'zero', 0), (5, 0, 'zero', 40),
         (5, 1, 'ramp', 0), (5, 1, 'ramp', 40), (5, 1, 'zero', 0), (5, 1, 'zero', 40),
         (6, 0, 'ramp', 0), (6, 0, 'ramp', 40), (6, 0, 'zero', 0), (6, 0, 'zero', 40),
         (6, 1, 'ramp', 0), (6, 1, 'ramp', 40), (6, 1, 'zero', 0), (6, 1, 'zero', 40),
         (7, 0, 'ramp', 0), (7, 0, 'ramp', 40), (7, 0, 'zero', 0), (7, 0, 'zero', 40),
         (7, 1, 'ramp', 0), (7, 1, 'ramp', 40), (7, 1, 'zero', 0), (7, 1, 'zero', 40),
         (8, 0, 'ramp', 0), (8, 0, 'ramp', 40), (8, 0, 'zero', 0), (8, 0, 'zero', 40),
         (8, 1, 'ramp', 0), (8, 1, 'ramp', 40), (8, 1, 'zero', 0), (8, 1, 'zero', 40),
         (9, 0, 'ramp', 0), (9, 0, 'ramp', 40), (9, 0, 'zero', 0), (9, 0, 'zero', 40),
         (9, 1, 'ramp', 0), (9, 1, 'ramp', 40), (9, 1, 'zero', 0), (9, 1, 'zero', 40)]),
 1282: ('ias_wd',
        [(0, 32, 1, 'ramp'), (0, 33, 2, 'ramp'), (0, 32, 1, 'zero'), (0, 32, 1, 'ff'),
         (0, 32, 1, 'sgn'), (0, 32, 1, 'max'), (0, 33, 2, 'zero'), (0, 33, 2, 'ff'),
         (0, 33, 2, 'sgn'), (0, 33, 2, 'max')],
        [(0, 0, 'ramp', 0), (0, 0, 'ramp', 40), (0, 0, 'zero', 0), (0, 0, 'zero', 40),
         (1, 0, 'ramp', 0), (1, 0, 'ramp', 40), (1, 0, 'zero', 0), (1, 0, 'zero', 40),
         (2, 0, 'ramp', 0), (2, 0, 'ramp', 40), (2, 0, 'zero', 0), (2, 0, 'zero', 40),
         (3, 0, 'ramp', 0), (3, 0, 'ramp', 40), (3, 0, 'zero', 0), (3, 0, 'zero', 40)])}

# hand-made frames: (cluster id, ZCL frame as hex, comment)
EXTRA = []

# frames that are cut short on purpose (malformed capture only)
CUTS = []

def data(t, n, fill):
    if fill == 'ramp':
        d = bytes(range(1, n + 1))
    elif fill == 'zero':
        d = bytes(n)
    elif fill == 'sgn':
        d = bytes(n - 1) + b'\x80'
    elif fill == 'max':
        d = b'\xff' * (n - 1) + b'\x7f'
    else:
        d = b'\xff' * n
    if t in (0x41, 0x42):
        d = bytes([n - 1]) + d[1:]
    return d

def zcl_frame(seq, cluster, zcl, profile=0x0104):
    mac = struct.pack('<HBHHH', 0x8841, seq & 0xff, 0x1234, 0x0000, 0x0001)
    nwk = struct.pack('<HHHBB', 0x0008, 0x0000, 0x0001, 0x1e, seq & 0xff)
    aps = struct.pack('<BBHHBB', 0x00, 0x01, cluster, profile, 0x01, seq & 0xff)
    return mac + nwk + aps + zcl

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 230))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)

def build():
    fr = []
    cuts = []
    def add(cid, zcl):
        fr.append(zcl_frame(len(fr) + 1, cid, bytes(zcl)))
        return len(fr) - 1
    for cid in sorted(CLUSTERS):
        name, attrs, cmds = CLUSTERS[cid]
        # cluster-specific commands
        for cmd, d, fill, n in cmds:
            pl = bytes(n) if fill == 'zero' else bytes(range(1, n + 1))
            add(cid, bytes([0x01 | (d << 3), 1, cmd]) + pl)
        # one attribute per Report Attributes frame, server side
        recs = []
        for a, t, n, fill in attrs:
            rec = struct.pack('<HB', a, t) + data(t, n, fill)
            recs.append((a, t, rec))
            add(cid, bytes([0x08, 1, 0x0a]) + rec)
        # attributes the cluster does not know (generic data decoding)
        for t, d in ((0x20, b'\x05'), (0x42, b'\x02ab'), (0x21, b'\x01\x02'), (0x10, b'\x01')):
            add(cid, bytes([0x08, 1, 0x0a]) + struct.pack('<HB', 0x7ffe, t) + d)
        # unknown cluster-specific commands, both directions
        for d in (0x01, 0x09):
            add(cid, bytes([d, 1, 0x7f, 1, 2, 3]))
        ramps = [(a, t, struct.pack('<HB', a, t) + data(t, n, 'ramp')) for a, t, n, fill in attrs if fill == 'ramp']
        for i in range(0, len(ramps), 6):
            chunk = ramps[i:i + 6]
            # Report Attributes from the client side (client attributes)
            add(cid, bytes([0x00, 2, 0x0a]) + b''.join(r for _, _, r in chunk))
            # Read Attributes Response, server side and client side
            add(cid, bytes([0x08, 3, 0x01]) + b''.join(struct.pack('<HB', a, 0) + r[2:] for a, _, r in chunk))
            add(cid, bytes([0x00, 3, 0x01]) + b''.join(struct.pack('<HB', a, 0) + r[2:] for a, _, r in chunk))
            # Write Attributes, Undivided, No Response (both directions)
            add(cid, bytes([0x00, 4, 0x02]) + b''.join(r for _, _, r in chunk))
            add(cid, bytes([0x08, 4, 0x02]) + b''.join(r for _, _, r in chunk))
            add(cid, bytes([0x00, 5, 0x03]) + b''.join(r for _, _, r in chunk))
            add(cid, bytes([0x00, 6, 0x05]) + b''.join(r for _, _, r in chunk))
            # Read Attributes, Write Attributes Response (failure records)
            ids = b''.join(struct.pack('<H', a) for a, _, _ in chunk)
            add(cid, bytes([0x00, 7, 0x00]) + ids)
            add(cid, bytes([0x08, 7, 0x00]) + ids)
            add(cid, bytes([0x08, 8, 0x04]) + b''.join(bytes([0x86]) + struct.pack('<H', a) for a, _, _ in chunk))
            add(cid, bytes([0x00, 8, 0x04]) + b''.join(bytes([0x86]) + struct.pack('<H', a) for a, _, _ in chunk))
            # Discover Attributes Response
            for dd in (0x00, 0x08):
                add(cid, bytes([dd, 9, 0x0d, 1]) + b''.join(struct.pack('<HB', a, t) for a, t, _ in chunk))
            # Configure Reporting: reported, with change for analog types
            cfg = b''
            for (a, t, r), (_, _, n, _f) in zip(chunk, [x for x in attrs if x[3] == 'ramp'][i:i + 6]):
                cfg += bytes([0]) + struct.pack('<HBHH', a, t, 1, 60) + data(t, n, 'ramp') if (t & 0xf0) == 0x20 or (t & 0xf8) == 0x38 or (t & 0xf8) == 0xe0 else bytes([0]) + struct.pack('<HBHH', a, t, 1, 60)
            add(cid, bytes([0x00, 10, 0x06]) + cfg)
            add(cid, bytes([0x08, 10, 0x06]) + cfg)
            # Configure Reporting: received (timeout), response, read config
            add(cid, bytes([0x00, 11, 0x06]) + b''.join(bytes([1]) + struct.pack('<HH', a, 300) for a, _, _ in chunk))
            add(cid, bytes([0x08, 11, 0x06]) + b''.join(bytes([1]) + struct.pack('<HH', a, 300) for a, _, _ in chunk))
            add(cid, bytes([0x08, 12, 0x07]) + b''.join(bytes([0x8c, k & 1]) + struct.pack('<H', a) for k, (a, _, _) in enumerate(chunk)))
            add(cid, bytes([0x00, 12, 0x07]) + b''.join(bytes([0x8c, k & 1]) + struct.pack('<H', a) for k, (a, _, _) in enumerate(chunk)))
            add(cid, bytes([0x00, 13, 0x08]) + b''.join(bytes([k & 1]) + struct.pack('<H', a) for k, (a, _, _) in enumerate(chunk)))
            add(cid, bytes([0x08, 13, 0x08]) + b''.join(bytes([k & 1]) + struct.pack('<H', a) for k, (a, _, _) in enumerate(chunk)))
        if ramps:
            a, t, r = ramps[0]
            add(cid, bytes([0x08, 14, 0x09, 0, 0]) + struct.pack('<HBHH', a, t, 1, 60) + data(t, len(r) - 3, 'ramp'))
            add(cid, bytes([0x00, 14, 0x09, 0, 1]) + struct.pack('<HH', a, 300))
            add(cid, bytes([0x00, 14, 0x09, 0, 1]) + struct.pack('<HH', a, 300))
    for cid, hx, comment in EXTRA:
        add(cid, bytes.fromhex(hx))
    for k in CUTS:
        cuts.append(k)
    return fr

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    fr = build()
    write_pcap(os.path.join(out, 'zbee-zcl-sas-coverage.pcap'), fr)
    # malformed capture: every 7th frame cut by one byte, and every 11th by 3
    bad = [f[:-1] for f in fr[::7]] + [f[:-3] for f in fr[3::11]]
    write_pcap(os.path.join(out, 'zbee-zcl-sas-coverage-malformed.pcap'), bad)
    with open(os.path.join(out, 'zbee-zcl-sas-coverage.pcap'), 'rb') as f:
        raw = f.read()
    with gzip.GzipFile(os.path.join(out, 'zbee-zcl-sas_coverage.pcap.gz'), 'wb', mtime=0) as g:
        g.write(raw)
    print(len(fr), len(bad))

if __name__ == '__main__':
    main()
