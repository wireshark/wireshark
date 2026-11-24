#!/usr/bin/env python3
# Generates test/captures/lbmpdmtcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the LBMPDM-TCP coverage captures.  Usage: mklbmpdmtcp.py <outdir>

lbmpdmtcp-coverage.pcap            main capture (default preferences)
lbmpdmtcp-coverage-malformed.pcap  data that only a Decode As or the tag table reaches,
                                   and invalid PDM headers
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import socket
from common import pcap, Flow, csum, eth

BE, LE = '>', '<'
EOM = 0xff


def pdm(e, first, segs, def_id=100, vmaj=1, vmin=0, length=None):
    body = b''.join(segs)
    magic = b'\xa7\x1c\xca\xfe' if e == BE else b'\xfe\xca\x1c\xa7'
    if length is None:
        length = 16 + len(body)
    return magic + struct.pack(e + 'BBBBII', 0x10, first, vmaj, vmin, def_id, length) + body


def seg(e, nxt, data):
    return struct.pack(e + 'BBHI', nxt, 0, 0, len(data)) + data


def small_msg(e, def_id, text=b'small', with_defn=True):
    """Definition (INT32 + STRING), offset table and data segment."""
    d = struct.pack(e + 'i', 77)
    ents = [(1, len(d))]
    d += struct.pack(e + 'I', len(text)) + text
    segs = []
    first = 1
    if with_defn:
        first = 2
        fl = struct.pack(e + 'IIIIBBiiH', 0, 4, 0, 0, 1, 1, 0, 0, 5)
        fl += struct.pack(e + 'IIIIBBiiH', 1, 0, 0, 0, 0, 0, 1, 0, 14)
        dd = struct.pack(e + 'iiBBBBII', def_id, 2, 1, 1, 1, 0, 4, 0) + fl
        segs.append(seg(e, 1, dd))
    segs.append(seg(e, 0, b''.join(struct.pack(e + 'II', i, o) for i, o in ents)))
    segs.append(seg(e, EOM, d))
    return pdm(e, first, segs, def_id=def_id)


def tcp6(src, dst, sp, dp, seq, flags, payload=b''):
    h = struct.pack('>HHIIBBHHH', sp, dp, seq, 1, 0x50, flags, 65535, 0, 0)
    ps = socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + \
        struct.pack('>IBBBB', len(h) + len(payload), 0, 0, 0, 6)
    c = csum(ps + h + payload)
    h = h[:16] + struct.pack('>H', c) + h[18:]
    ip = struct.pack('>IHBB', 0x60000000, len(h) + len(payload), 6, 64) + \
        socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
    return eth(bytes.fromhex('020000000002'), bytes.fromhex('020000000001'), 0x86dd, ip + h + payload)


def build_main():
    fr = []
    # 1: client sends first, big endian, server port 14371 (the default low port)
    f = Flow(50001, 14371, fr)
    f.open()
    f.c2s(small_msg(BE, 1))
    f.s2c(small_msg(BE, 1, with_defn=False, text=b'server to client'))
    f.c2s(small_msg(BE, 1, with_defn=False, text=b'again'))
    f.close()
    # 2: the server (the higher address) sends first: the transport key is swapped
    f = Flow(50002, 14380, fr, cip='10.0.0.1', sip='10.0.0.2')
    f.open()
    f.s2c(small_msg(LE, 2))
    f.c2s(small_msg(LE, 2, with_defn=False, text=b'client'))
    f.close()
    # 3: both ends have the same address, the first sender has the lower port
    f = Flow(14385, 50003, fr, cip='10.0.0.9', sip='10.0.0.9')
    f.open()
    f.c2s(small_msg(BE, 3))
    f.s2c(small_msg(BE, 3, with_defn=False))
    f.close()
    # 4: same address, the first sender has the higher port; also the highest port (14390)
    f = Flow(50004, 14390, fr, cip='10.0.0.9', sip='10.0.0.9')
    f.open()
    f.c2s(small_msg(LE, 4))
    f.s2c(small_msg(LE, 4, with_defn=False))
    f.close()
    # 5: two PDUs in one segment, a PDU over two segments, a PDU over three
    f = Flow(50005, 14375, fr)
    f.open()
    a = small_msg(BE, 5)
    b = small_msg(BE, 5, with_defn=False, text=b'second')
    f.c2s(a + b)
    c = small_msg(BE, 5, with_defn=False, text=b'split in two segments')
    f.c2s(c[:30])
    f.c2s(c[30:])
    d = small_msg(BE, 5, with_defn=False, text=b'split in three')
    f.c2s(d[:16])
    f.c2s(d[16:40])
    f.c2s(d[40:])
    # a PDU followed by the start of another one
    e2 = small_msg(BE, 5, with_defn=False, text=b'tail')
    f.c2s(d + e2[:20])
    f.c2s(e2[20:])
    f.close()
    # 6: ports outside 14371-14390: not claimed by the heuristic
    f = Flow(50006, 5000, fr)
    f.open()
    f.c2s(small_msg(BE, 6))
    f.close()
    # 7: PDM over IPv6 on port 14371: the heuristic wants an IPv4 destination
    s6, d6 = '2001:db8::1', '2001:db8::2'
    fr.append(tcp6(s6, d6, 50007, 14371, 1000, 0x18, small_msg(BE, 7)))
    return fr


def build_malformed():
    fr = []
    # Everything here is only reached with Decode As (tcp.port 6000 or 14371 with the
    # LBMPDM-TCP dissector) or the tag table (runcov.sh): payload that is not PDM
    f = Flow(50021, 6000, fr)
    f.open()
    f.c2s(small_msg(BE, 11))                              # valid PDM, port not in the range
    f.c2s(b'\x00' * 40)                                   # not PDM at all
    f.c2s(b'\xa7\x1c\xca\xfe' + struct.pack('>BBBBII', 0x10, 9, 1, 0, 1, 40) + b'\0' * 24)  # bad next hdr
    f.c2s(b'\xa7\x1c\xca\xfe' + struct.pack('>BBBBII', 0x10, 0, 1, 0, 1, 0x80000000) + b'\0' * 24)  # length > INT_MAX
    f.c2s(b'\xa7\x1c')                                    # shorter than the header
    f.c2s(small_msg(BE, 11, with_defn=False)[:25])        # PDM cut short, never completed
    f.close()
    # the reproducer of "LBMPDM-TCP: Do not return a zero PDU length": a PDM
    # header with length 0 followed by plain data segments (the unfixed code asked
    # for one more segment each time and copied the growing buffer)
    f = Flow(50031, 14371, fr)
    f.open()
    first = bytes([0xA7, 0x1C, 0xCA, 0xFE]) + struct.pack('>BBBBII', 0x10, 0, 1, 0, 1, 0)
    f.c2s(first + b'\x41' * (1400 - len(first)))
    for _ in range(40):
        f.c2s(b'\x41' * 1400)
    # a PDM header whose length is smaller than the header
    f.c2s(first[:12] + struct.pack('>I', 9) + b'\x42' * 40)
    f.close()
    # tag table: a stream on ports 7000-7010 that only the tag table claims
    f = Flow(50022, 7005, fr)
    f.open()
    f.c2s(small_msg(BE, 12))
    f.s2c(small_msg(BE, 12, with_defn=False, text=b'tagged'))
    f.close()
    return fr


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    pcap(os.path.join(out, 'lbmpdmtcp-coverage.pcap'), build_main())
    pcap(os.path.join(out, 'lbmpdmtcp-coverage-malformed.pcap'), build_malformed())
