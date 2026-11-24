#!/usr/bin/env python3
# Generates test/captures/trueconf_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Builds trueconf-coverage.pcap and trueconf-coverage-malformed.pcap
import struct
import sys
import os
from pcaplib import Flow, write

MAGIC = b'_VS_TRANSPORT_'

def pdu(name=b'host.example', token=b'tokn', payload=bytes(range(32)), msg=1,
        len_a=None, len_b=None, flags=1, cap=1, sep=True, ver=(1, 2)):
    p = MAGIC + b'\0\0' + b'\x01\x02\x03' + bytes([flags]) + struct.pack('!H', cap)
    p += b'\0' + bytes(ver) + bytes([len(name)]) + name
    p += struct.pack('!H', len(token)) + token        # 2-byte length = sep0 + 1-byte length
    la = len(payload) if len_a is None else len_a
    lb = len(payload) if len_b is None else len_b
    p += struct.pack('!H', msg) + struct.pack('<II', la, lb) + bytes(range(100, 116)) + payload
    return p

def main(out):
    fr = []
    # 1-2: handshake PDU (named host) and a data PDU without a name, empty token
    f = Flow(40001, 4307)
    fr.append(f.seg(pdu(payload=b'')))                                   # no payload
    fr.append(f.seg(pdu(name=b'', token=b'', payload=bytes(range(8)), msg=2), client=False))  # < 16: no trailer
    # 3-4: payload of exactly 16 bytes (trailers) and a 200 byte one
    fr.append(f.seg(pdu(payload=bytes(range(16)), msg=3)))
    fr.append(f.seg(pdu(payload=bytes(range(200)), msg=4, flags=0x80, cap=0xbeef), client=False))
    # 5: the batch 37 reproducer: two PDUs back to back in one segment
    f2 = Flow(40002, 4307)
    fr.append(f2.seg(pdu() + pdu(payload=bytes(range(32, 64)), msg=5)))
    # 6-8: a PDU in three segments, then one PDU
    p = pdu(payload=bytes(range(100)), msg=6)
    fr.append(f2.seg(p[:10]))            # shorter than the magic
    fr.append(f2.seg(p[10:40]))          # inside the header (name)
    fr.append(f2.seg(p[40:]))
    # 9-10: header complete, payload in the next segment; PDU split after the token
    p = pdu(payload=bytes(range(60)), msg=7)
    cut = len(p) - 60
    fr.append(f2.seg(p[:cut]))
    fr.append(f2.seg(p[cut:]))
    # 11-12: a PDU split between the token and the message type
    p = pdu(token=b'abcdefgh', payload=bytes(range(20)), msg=8)
    fr.append(f2.seg(p[:14 + 12 + 12 + 1 + 4]))
    fr.append(f2.seg(p[14 + 12 + 12 + 1 + 4:]))
    # 13: length A smaller / larger than length B (the shorter one is used)
    fr.append(f2.seg(pdu(payload=bytes(range(40)), len_a=24, len_b=40, msg=9)[:-16]))
    fr.append(f2.seg(pdu(payload=bytes(range(40)), len_a=40, len_b=24, msg=10)[:-16]))
    f3 = Flow(40003, 4307)
    # 16: PDU followed by data that is not TrueConf in the same segment
    fr.append(f3.seg(pdu(payload=bytes(range(24)), msg=11) + b'trailing junk that is not a PDU'))
    # 17-18: a stream on the port that does not start with the magic (not TrueConf, passed on)
    f4 = Flow(40004, 4307)
    for i in range(3):
        fr.append(f4.seg(bytes([0x41 + i]) * 600))
    # 20: a segment shorter than the magic
    f5 = Flow(40005, 4307)
    # ... which is completed by the next segments (magic, then 5 octets, then the rest)
    p = pdu(payload=bytes(range(48)), msg=12)
    fr.append(f5.seg(p[:4]))
    fr.append(f5.seg(p[4:19]))
    fr.append(f5.seg(p[19:]))
    # many PDUs of increasing size in a long stream (reassembly across 1460 byte segments)
    f6 = Flow(40006, 4307)
    big = b''.join(pdu(payload=bytes([i]) * (700 + 150 * i), msg=20 + i) for i in range(6))
    for i in range(0, len(big), 1400):
        fr.append(f6.seg(big[i:i + 1400]))
    write(os.path.join(out, 'trueconf-coverage.pcap'), fr)
    n_main = len(fr)

    # malformed: truncated frames reaching bounds errors
    m = []
    # name_len says 5 but the segment ends after the fixed header (no more data)
    f3 = Flow(40003, 4307)
    m.append(f3.seg(pdu(name=b'abcde')[:14 + 12]))
    f7 = Flow(41001, 4307)
    m.append(f7.seg(pdu(payload=bytes(range(10)), len_a=1000, len_b=1000)))   # claims more than is sent
    f8 = Flow(41002, 4307)
    m.append(f8.seg(pdu(payload=bytes(range(40)))[:-3], flags=0x18))
    f9 = Flow(41003, 4307)
    m.append(f9.seg(pdu(name=b'x' * 200, token=b't' * 300, payload=b'')))
    f10 = Flow(41004, 4307)
    m.append(f10.seg(MAGIC + b'\0' * 12))         # header only up to the fixed part
    write(os.path.join(out, 'trueconf-coverage-malformed.pcap'), m)
    print('main frames', n_main, 'malformed', len(m))

main(sys.argv[1] if len(sys.argv) > 1 else '.')
