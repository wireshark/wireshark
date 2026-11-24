#!/usr/bin/env python3
# Generates test/captures/vj_comp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic PPP Van Jacobson TCP/IP header compression (VJC) captures for
packet-vj-comp.c.

Usage: mkvj-comp.py <outdir> [-v]
Writes vj-comp-coverage.pcapng (main capture: no malformed packets or error
expert infos; interface 0 is PPP with direction, interface 1 plain PPP) and
vj-comp-coverage-malformed.pcapng (truncated and unsupported packets, PPPMux).
Addresses are from 192.0.2.0/24.
"""
import os
import struct
import sys

from pcaplib import write_pcapng

SRC = bytes([192, 0, 2, 1])
DST = bytes([192, 0, 2, 2])
UC, CO = 0x002f, 0x002d     # PPP protocols of VJ uncompressed and compressed TCP/IP

RECV, SENT = 0, 1           # first octet of a PPP frame with direction


def ip_tcp(proto, sport, dport, seq, ack, payload=b'', ipid=100, ip_opts=b'', tcp_opts=b'',
           flags=0x18, win=8192, chk=0xbeef, urg=0, version=4):
    ihl = 5 + len(ip_opts) // 4
    toff = 5 + len(tcp_opts) // 4
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, toff << 4, flags, win, chk, urg) + tcp_opts
    tot = ihl * 4 + len(tcp) + len(payload)
    ip = struct.pack('>BBHHHBBH4s4s', (version << 4) | ihl, 0, tot, ipid, 0, 64, proto, 0, SRC, DST) + ip_opts
    return ip + tcp + payload


def delta(v):
    return bytes([v]) if 0 < v < 256 else b'\0' + struct.pack('>H', v)


def delta_s(v):
    return struct.pack('>b', v) if -128 <= v < 128 and v != 0 else b'\0' + struct.pack('>h', v)


def comp(flags, cnum=None, chk=0x1234, urg=None, dwin=None, dack=None, dseq=None, dipid=None, data=b''):
    out = bytes([flags])
    if flags & 0x40:
        out += bytes([cnum])
    out += struct.pack('>H', chk)
    if flags & 0x0f not in (0x0f, 0x0b):
        if flags & 0x01:
            out += struct.pack('>H', urg)
        if flags & 0x02:
            out += delta_s(dwin)
        if flags & 0x04:
            out += delta(dack)
        if flags & 0x08:
            out += delta(dseq)
    if flags & 0x20:
        out += delta(dipid)
    return out + data


def ppp(proto, body, d=None):
    """PPP frame; d is the direction octet (interface 0) or None (interface 1)."""
    f = b'\xff\x03' + struct.pack('>H', proto) + body
    return (0, bytes([d]) + f) if d is not None else (1, f)


def build():
    fr = []
    marks = []

    def mark(label):
        marks.append((len(fr) + 1, label))

    mark('Compressed packet as the first frame: no connection number, no connection')
    fr.append(ppp(CO, comp(0x00, chk=0x1111, data=b'first'), RECV))
    fr.append(ppp(CO, comp(0x40, cnum=3, chk=0x1112, data=b'second'), RECV))      # C flag, still no connection
    fr.append(ppp(CO, comp(0x04, chk=0x1113, dack=1, data=b'third'), RECV))       # no C, cnum 3 from the last frame, no connection
    mark('Connection 1 (received): uncompressed, then every kind of compressed packet')
    fr.append(ppp(UC, ip_tcp(1, 2000, 80, 0x10000000, 0x20000000, b'A' * 20, ipid=100), RECV))
    fr.append(ppp(CO, comp(0x40 | 0x20 | 0x10 | 0x08 | 0x04, cnum=1, chk=0x2001, dack=5, dseq=20, dipid=2,
                           data=b'B' * 8), RECV))                                  # C I P S A
    fr.append(ppp(CO, comp(0x03, chk=0x2002, urg=0x0102, dwin=-100, data=b'C' * 4), RECV))          # no C: W U
    fr.append(ppp(CO, comp(0x40 | 0x0f, cnum=1, chk=0x2003, data=b'D' * 6), RECV))  # SAWU: unidirectional
    fr.append(ppp(CO, comp(0x40 | 0x0b, cnum=1, chk=0x2004, data=b'E' * 3), RECV))  # SWU: echoed interactive
    fr.append(ppp(CO, comp(0x40 | 0x20 | 0x0e, cnum=1, chk=0x2005, dwin=300, dack=0, dseq=255, dipid=1000,
                           data=b'F' * 5), RECV))                                  # 3 octet deltas
    fr.append(ppp(CO, comp(0x20 | 0x0b, chk=0x2006, dipid=7, data=b'G'), RECV))     # SWU with an IP ID delta
    fr.append(ppp(CO, comp(0x20 | 0x0f, chk=0x2007, dipid=300, data=b'H'), RECV))   # SAWU with a 3 octet IP ID delta
    fr.append(ppp(CO, comp(0x00, chk=0x2008), RECV))                                # no data at all
    fr.append(ppp(CO, comp(0x01, chk=0x2009, urg=0), RECV))                         # urgent pointer 0
    fr.append(ppp(CO, comp(0x02, chk=0x200a, dwin=5, data=b'I'), RECV))             # W only, 1 octet
    fr.append(ppp(CO, comp(0x02, chk=0x200b, dwin=-1000, data=b'J'), RECV))         # W only, 3 octets
    mark('Connection 1 in the other direction is another conversation')
    fr.append(ppp(UC, ip_tcp(1, 80, 2000, 0x20000000, 0x10000000, b'a' * 10, ipid=500), SENT))
    fr.append(ppp(CO, comp(0x0f, chk=0x3001, data=b'b' * 2), SENT))
    fr.append(ppp(CO, comp(0x40 | 0x10, cnum=1, chk=0x3002, data=b'c' * 2), SENT))
    mark('Connection 7 with IP and TCP options (reproducer of the last_frame_len fix)')
    fr.append(ppp(UC, ip_tcp(7, 3000, 25, 0x30000000, 0x40000000, b'x' * 20, ipid=700,
                             ip_opts=b'\x01\x01\x01\x01', tcp_opts=b'\x01' * 12), RECV))
    fr.append(ppp(CO, comp(0x40 | 0x0f, cnum=7, chk=0x4001, data=b'\x01' * 12 + b'y' * 3), RECV))   # SAWU
    fr.append(ppp(CO, comp(0x0f, chk=0x4002, data=b'\x01' * 12 + b'z' * 3), RECV))
    mark('A refresh of connection 1 (uncompressed again) and a compressed packet that follows')
    fr.append(ppp(UC, ip_tcp(1, 2000, 80, 0x10001000, 0x20001000, b'N' * 4, ipid=900), RECV))
    fr.append(ppp(CO, comp(0x40 | 0x0f, cnum=1, chk=0x5001, data=b'O' * 4), RECV))
    mark('Interleaved connections 2 and 4 (last connection number follows uncompressed packets)')
    fr.append(ppp(UC, ip_tcp(2, 1111, 7777, 0x1000, 0x2000, b'p' * 5, ipid=1), RECV))
    fr.append(ppp(UC, ip_tcp(4, 2222, 7778, 0x3000, 0x4000, b'q' * 6, ipid=2), RECV))
    fr.append(ppp(CO, comp(0x08, chk=0x6001, dseq=6, data=b'r'), RECV))             # cnum 4 (last)
    fr.append(ppp(CO, comp(0x40 | 0x08, cnum=2, chk=0x6002, dseq=5, data=b's'), RECV))
    fr.append(ppp(CO, comp(0x08, chk=0x6003, dseq=1, data=b't'), RECV))             # cnum 2 now
    mark('Compressed packets for a connection that was never seen (cnum 9)')
    fr.append(ppp(CO, comp(0x40 | 0x04, cnum=9, chk=0x7001, dack=2, data=b'u'), RECV))
    mark('No direction (PPP without direction): uncompressed and compressed')
    fr.append(ppp(UC, ip_tcp(5, 4000, 443, 0x100, 0x200, b'v' * 4)))
    fr.append(ppp(CO, comp(0x40 | 0x0f, cnum=5, chk=0x8001, data=b'w')))
    fr.append(ppp(CO, comp(0x0f, chk=0x8002, data=b'w')))
    return fr, marks


def build_malformed():
    fr = []
    marks = []

    def mark(label):
        marks.append((len(fr) + 1, label))

    mark('Uncompressed packets that are too short or not IPv4')
    fr.append(ppp(UC, ip_tcp(1, 1, 2, 3, 4)[:9], RECV))                              # before the connection ID
    fr.append(ppp(UC, ip_tcp(1, 1, 2, 3, 4, b'p', version=6), RECV))                 # IPv6
    fr.append(ppp(UC, ip_tcp(1, 1, 2, 3, 4)[:30], RECV))                             # before the end of the TCP/IP headers
    fr.append(ppp(UC, ip_tcp(1, 1, 2, 3, 4)[:30]))                                   # same without direction (no direction first)
    fr.append(ppp(UC, ip_tcp(6, 3333, 80, 0x500, 0x600, b'k' * 8, ipid=60), RECV))   # a good one for the compressed ones below
    mark('Compressed packets cut short in the header')
    fr.append(ppp(CO, b'\x40', RECV))                                                # less than 3 octets
    fr.append(ppp(CO, b'\x40\x06\x12', RECV))                                        # C flag, checksum cut
    fr.append(ppp(CO, bytes([0x40 | 0x01, 6, 0x12, 0x34, 0x01]), RECV))              # U flag, urgent pointer cut
    fr.append(ppp(CO, bytes([0x40 | 0x02, 6, 0x12, 0x34, 0x00, 0x01]), RECV))        # W with a 3 octet delta, cut
    fr.append(ppp(CO, bytes([0x40 | 0x04, 6, 0x12, 0x34, 0x00]), RECV))              # A with a 3 octet delta, cut
    fr.append(ppp(CO, bytes([0x40 | 0x08, 6, 0x12, 0x34, 0x00, 0x00]), RECV))        # S with a 3 octet delta, cut
    fr.append(ppp(CO, bytes([0x40 | 0x20, 6, 0x12, 0x34, 0x00, 0x00]), RECV))        # I with a 3 octet delta, cut
    fr.append(ppp(CO, bytes([0x40 | 0x20, 6, 0x12, 0x34]), RECV))                    # I flag, delta missing
    mark('PPPMux (PPP protocol 0x59) with several VJ-compressed PDUs in one frame (the connection '
         'number is stored per frame: observation, round two)')
    def sub(pid, body):
        l = len(body) + 2
        return bytes([0x80 | l]) + struct.pack('>H', pid) + body
    fr.append(ppp(UC, ip_tcp(2, 2000, 80, 0x20000000, 0x22000000, b'A' * 4), RECV))
    fr.append(ppp(UC, ip_tcp(1, 1000, 80, 0x10000000, 0x11000000, b'B' * 4), RECV))
    mux = (sub(CO, comp(0x00, chk=0x1234, data=b'AAAA')) +
           sub(CO, comp(0x40, cnum=2, chk=0x5678, data=b'BBBB')) +
           sub(CO, comp(0x00, chk=0x9abc, data=b'CCCC')))
    fr.append(ppp(0x0059, mux, RECV))
    return fr, marks


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    for name, fn in (('vj-comp-coverage', build), ('vj-comp-coverage-malformed', build_malformed)):
        fr, marks = fn()
        write_pcapng(os.path.join(out, name + '.pcapng'), [204, 9], fr)
        print('%s.pcapng: %d frames' % (name, len(fr)))
        if verbose:
            ends = [m[0] for m in marks[1:]] + [len(fr) + 1]
            for (s, label), e in zip(marks, ends):
                print('  %d-%d %s' % (s, e - 1, label))


if __name__ == '__main__':
    main()
