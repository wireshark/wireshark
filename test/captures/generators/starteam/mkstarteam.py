#!/usr/bin/env python3
# Generates test/captures/starteam_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the StarTeam coverage captures. Usage: mkstarteam.py <outdir> [-v]
Writes starteam-coverage.pcap (main) and starteam-coverage-malformed.pcap.
StarTeam has no port; it is found by the TCP heuristic (the "Alan" magic
with packet size == data size) and the conversation then goes through
tcp_dissect_pdus. Everything is synthetic (192.0.2.0/24); no encryption
(the key exchange commands are just opcodes with opaque data)."""
import os
import struct
import sys
from pcaplib import TcpFlow, write_pcap

MAGIC = b'Alan'
# every opcode of starteam_opcode_vals[]
OPCODES = [1, 2, 3, 4, 5, 10, 11, 12, 13, 14, 1001, 1002, 1011, 1013, 1014, 1015, 1016, 1017, 1018, 1020, 1021, 1022,
    1023, 1024, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1051, 1052, 1053, 1151, 1152,
    1154, 1160, 1161, 1162, 1163, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2010, 2011, 2012, 2013, 2020, 2021, 2022,
    2023, 2024, 2025, 2026, 2027, 2028, 2029, 2030, 2031, 2032, 2033, 2034, 2035, 2036, 2037, 2038, 2039, 2040, 2041,
    2042, 2043, 2045, 2046, 2050, 2060, 5001, 9034, 9035, 9036, 9037, 9038, 9039, 10001, 10005, 10011, 10012, 10013,
    10014, 10015, 10016, 10017, 10018, 10019, 10020, 10021, 10023, 10024, 10025, 10026, 10031, 10032, 10035, 10036,
    10037, 10038, 10039, 10040, 10053, 10054, 10060, 10061, 10062, 10063, 10065, 10083, 10085, 10086, 10090, 10091,
    10092, 10093, 10094, 10095, 10098, 10099, 10100, 10104, 10111, 10112, 10117, 10119, 10121, 10122, 10123, 10130,
    10131, 10132, 10133, 10134, 10135, 10136, 10137, 10138, 10139, 10141, 10142, 10143, 10201, 10202, 10203, 10205,
    10206, 10207, 10208, 10209, 10221, 10222, 10223, 10224, 10225, 10226, 10229, 10300, 10301, 10302, 10310, 10311,
    10400, 10401, 10402, 10403, 10404, 10405, 10408, 10409, 10410, 10411, 20070, 20071]

def request(cmd, data=b'', session=0x1234, same=False, ts=0x5f000000, flags=0, keyid=0, client=b'StarTeam Client!',
            connect=7, component=1, cmdtime=0x5f000001, userid=3, pkt=None, dsz=None):
    """MDH (20) + packet header (16) + ID (38) + data. packet_size covers ID + data."""
    body = struct.pack('<H16sIIIII', 8, client, connect, component, cmd, cmdtime, userid) + data
    psz = len(body) if pkt is None else pkt
    dz = psz if dsz is None else dsz
    mdh = struct.pack('<IIIII', session, ts, flags, keyid, 0)
    ph = MAGIC + struct.pack('<III', psz, dz, 0x80)
    return mdh + ph + body

def response(data=b'', flags=0, pkt=None, dsz=None):
    psz = len(data) if pkt is None else pkt
    dz = psz if dsz is None else dsz
    return MAGIC + struct.pack('<III', psz, dz, flags) + data

def main_frames():
    F = []; R = {}
    def add(name, fr):
        R[name] = len(F) + 1; F.append(fr)
    def addl(name, frs):
        R[name] = len(F) + 1; F.extend(frs)
    # ---- Connection 1: found by the heuristic (first request: packet size == data size) ----
    f = TcpFlow(49000, 49201)
    addl('c1-handshake', f.handshake())
    add('c1-get-session-tag', f.c2s(request(1)))
    add('c1-rsp-1', f.s2c(response(b'\x01\x00\x00\x00session tag data')))
    add('c1-server-params', f.c2s(request(3, b'param data')))
    add('c1-rsp-2', f.s2c(response(b'')))
    # every opcode, eight PDUs to a segment
    for i in range(0, len(OPCODES), 8):
        add('c1-ops-%d' % i, f.c2s(b''.join(request(c, b'x' * (c % 7)) for c in OPCODES[i:i + 8])))
    add('c1-unknown-op', f.c2s(request(31337, b'unknown opcode')))
    add('c1-op0', f.c2s(request(0)))
    # two responses in one segment
    add('c1-rsp-2in1', f.s2c(response(b'first reply') + response(b'second reply data')))
    # a request split over three segments, a response over two
    big = request(2001, b'F' * 3000)
    add('c1-req-split-1', f.c2s(big[:1000]))
    add('c1-req-split-2', f.c2s(big[1000:2000]))
    add('c1-req-split-3', f.c2s(big[2000:]))
    bigr = response(b'R' * 2500, flags=1)
    add('c1-rsp-split-1', f.s2c(bigr[:1200]))
    add('c1-rsp-split-2', f.s2c(bigr[1200:]))
    # a segment holding one whole PDU and the start of another, which is finished next
    r1 = request(10001, b'abc'); r2 = request(10005, b'defghijkl')
    add('c1-pdu-and-half', f.c2s(r1 + r2[:30]))
    add('c1-pdu-rest', f.c2s(r2[30:]))
    # header split after a few octets (less than 8: needs one more segment)
    r3 = request(10011, b'split header')
    add('c1-hdr-split-1', f.c2s(r3[:5]))
    add('c1-hdr-split-2', f.c2s(r3[5:]))
    # request PDUs without ID, with an incomplete ID, with flags and key id set
    add('c1-no-id', f.c2s(MAGIC.join([struct.pack('<IIIII', 1, 2, 3, 4, 0), struct.pack('<III', 0, 0, 0)])))
    add('c1-short-id', f.c2s(struct.pack('<IIIII', 1, 2, 3, 4, 0) + MAGIC + struct.pack('<III', 10, 10, 0) + b'0123456789'))
    add('c1-flags-key', f.c2s(request(11, b'key exchange', flags=0x00010001, keyid=0xdeadbeef)))
    add('c1-empty-reply', f.s2c(response(b'')))
    add('c1-reply-nodata-8', f.s2c(response(b'12345678')))
    addl('c1-fin', f.fin())
    # ---- Connection 2: first packet is a response (heuristic via the response magic) ---
    f = TcpFlow(49001, 49202)
    addl('c2-handshake', f.handshake())
    add('c2-rsp', f.s2c(response(b'greeting from the server, long enough for the heuristic')))
    add('c2-req', f.c2s(request(1, b'later request', session=0x4321)))
    add('c2-rsp2', f.s2c(response(b'ok')))
    addl('c2-fin', f.fin())
    # ---- Connection 3: not StarTeam (packet size != data size, short, no magic) -------
    f = TcpFlow(49002, 49203)
    addl('c3-handshake', f.handshake())
    add('c3-size-mismatch', f.c2s(request(1, b'data', pkt=60, dsz=50)))
    add('c3-short', f.c2s(MAGIC + b'\x00' * 8))
    add('c3-no-magic', f.c2s(b'This is plain text that is longer than thirty-two octets.\r\n'))
    addl('c3-fin', f.fin())
    return F, R

def malformed_frames():
    F = []; R = {}
    def add(name, fr):
        R[name] = len(F) + 1; F.append(fr)
    f = TcpFlow(49100, 49301)
    F += f.handshake()
    add('first', f.c2s(request(1, b'start')))
    # packet size larger than what follows: the PDU runs into the next segments
    add('too-long', f.c2s(request(2, b'x', pkt=100000, dsz=100000)))
    add('after', f.c2s(b'continuation'))
    add('more', f.s2c(response(b'reply while the request is incomplete')))
    f = TcpFlow(49101, 49302)
    F += f.handshake()
    add('first2', f.s2c(response(b'greeting for the heuristic')))
    add('rsp-size-huge', f.s2c(response(b'', pkt=0xffffffff, dsz=0xffffffff)))
    add('rsp-after', f.s2c(b'xx'))
    add('req-size-huge', f.c2s(request(1, b'', pkt=0xfffffff0, dsz=0xfffffff0)))
    # truncated frames for the heuristic
    f = TcpFlow(49102, 49303)
    F += f.handshake()
    add('trunc-req', f.c2s(request(3, b'cut')[:40]))
    add('trunc-rsp', f.s2c(response(b'cut again, a response that is cut short')[:20]))
    return F, R

if __name__ == '__main__':
    out = sys.argv[1]
    F, R = main_frames()
    write_pcap(os.path.join(out, 'starteam-coverage.pcap'), F)
    G, RM = malformed_frames()
    write_pcap(os.path.join(out, 'starteam-coverage-malformed.pcap'), G)
    if '-v' in sys.argv:
        print(len(F), R); print(len(G), RM)
