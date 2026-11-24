#!/usr/bin/env python3
# Generates test/captures/dlsw_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic DLSw coverage captures (UDP 2067, TCP 2065).
Usage: mkdlsw.py <outdir>"""
import os
import random
import struct
import sys
from pcaplib import udp, Tcp, write_pcap

def cmd_header(mtype, mlen, flags=0, version=0x31, rdlc=0, rpid=0,
               prio=3, direction=1, dlchlen=0, oldtype=None, ssp=0x00,
               lf=0x30):
    """72 octet control header (RFC 1795 section 4)."""
    h = struct.pack('!BBHII2sBB', version, 72, mlen, rdlc, rpid, b'\0\0', mtype, flags)
    h += struct.pack('!BB2sBBBB6s6sBBB3sH',
                     0x42, 0x01, b'\0\0', lf, ssp, prio,
                     mtype if oldtype is None else oldtype,
                     bytes.fromhex('020000000aa1'), bytes.fromhex('020000000bb2'),
                     0x04, 0x04, direction, b'\0\0\0', dlchlen)
    h += struct.pack('!IIIIII4s', 0x11111111, 0x22222222, 0x33333333,
                     0x44444444, 0x55555555, 0x66666666, b'\0' * 4)
    assert len(h) == 72
    return h

def info_header(mtype, mlen, flags=0, version=0x31, rdlc=0x01020304, rpid=0x05060708):
    """16 octet information header."""
    return struct.pack('!BBHII2sBB', version, 16, mlen, rdlc, rpid, b'\0\0', mtype, flags)

def capex_header(mlen, capex_type=1, version=0x31):
    h = struct.pack('!BBHII2sBB', version, 72, mlen, 0, 0, b'\0\0', 0x20, 0)
    h += struct.pack('!BB5sB14sB33s', 0x42, 0x01, b'\0' * 5, 0x20, b'\0' * 14,
                     capex_type, b'\0' * 33)
    assert len(h) == 72
    return h

def cmd(mtype, data=b'', **kw):
    return cmd_header(mtype, len(data), **kw) + data

def info(mtype, data=b'', **kw):
    return info_header(mtype, len(data), **kw) + data

def capex(gds, body, capex_type=1, mlen=None):
    data = struct.pack('!HH', 4 + len(body) if mlen is None else mlen, gds) + body
    return capex_header(len(data), capex_type) + data

def cv(vtype, data):
    return bytes([len(data) + 2, vtype]) + data

ALL_CVS = (cv(0x81, b'\x00\x00\x0c')                       # vendor id
           + cv(0x82, b'\x02\x00')                         # version 2.00
           + cv(0x83, struct.pack('!h', 20))               # pacing window
           + cv(0x84, b'synthetic DLSw 1.0')               # version string
           + cv(0x85, b'\x01')                             # MAC excl on
           + cv(0x86, bytes([0xff, 0x55, 0xaa, 0x00] + [0x80] * 12))  # SAP list
           + cv(0x87, b'\x02')                             # TCP connections
           + cv(0x88, b'\x00')                             # NetBIOS excl off
           + cv(0x89, bytes.fromhex('020000000aa1ffffffffffff'))  # MAC list
           + cv(0x8a, b'SYNTHHOST*')                       # NetBIOS names
           + cv(0x8b, b'\x00\x00\x0c')             # vendor context
           + cv(0x8c, b'\x01')                             # multicast
           + cv(0x91, b'\x12\x34')                         # other CV
           + cv(0x85, b'\x00')                             # MAC excl off
           + cv(0x88, b'\x01'))                            # NetBIOS excl on

# DLC header (35 octets) for SSP messages carrying one.
# DA, SA and RIF are shown as strings, so the addresses avoid NUL octets
# (a NUL followed by more data is reported as stray characters).
DLC = (bytes([0x10, 0x40]) + bytes.fromhex('021122334455') + bytes.fromhex('026677889911')
       + bytes.fromhex('0830011002200330') + bytes(10) + bytes([0x04, 0x04, 0x03]))

def main_frames():
    f = []
    # --- UDP 2067 (SSP messages and capabilities exchange) ---
    u = lambda d, **kw: udp(2067, 2067, d, **kw)
    f.append(u(cmd(0x03, ssp=0x80, direction=1)))                  # 1 CANUREACH explorer
    f.append(u(cmd(0x04, ssp=0x80, direction=2), src='192.0.2.2', dst='192.0.2.1'))  # 2 ICANREACH
    f.append(u(cmd(0x12, b'NETBIOS-NAME-QUERY', prio=0)))          # 3 NETBIOS_NQ
    f.append(u(cmd(0x13, b'NBRECOG', prio=4, direction=2), src='192.0.2.2', dst='192.0.2.1'))  # 4
    f.append(u(cmd(0x1a, b'ANQ', prio=1)))                         # 5 NETBIOS_ANQ
    f.append(u(cmd(0x1b, b'ANR', prio=2, direction=2), src='192.0.2.2', dst='192.0.2.1'))  # 6
    f.append(u(cmd(0x06, DLC + b'UI datagram', dlchlen=35)))       # 7 DGRMFRAME with DLC header
    f.append(u(cmd(0x7a, b'test')))                                # 8 TEST_CIRCUIT_REQ
    f.append(u(cmd(0x7b, b'test', direction=2), src='192.0.2.2', dst='192.0.2.1'))  # 9
    f.append(u(info(0x0a, b'udp info frame')))                     # 10 INFOFRAME, 16 octets
    f.append(u(cmd(0x03, version=0x32, prio=7)))                   # 11 version 2
    f.append(u(cmd(0x03, version=0x4b, prio=5)))                   # 12 pre 1
    f.append(u(cmd(0x03, version=0x38, prio=6)))                   # 13 vendor specific
    f.append(u(b'\x40' + bytes(20)))                               # 14 unknown version: not DLSw

    # --- TCP 2065, one circuit ---
    t = Tcp(40001, 2065)
    f.append(t.c2s(capex(0x1520, ALL_CVS)))                        # 15 capex request, every CV
    f.append(t.s2c(capex(0x1521, b'', capex_type=2)))              # 16 positive response
    f.append(t.s2c(capex(0x1522, struct.pack('!hH', -1, 0x0d), capex_type=2)))  # 17 refused
    f.append(t.c2s(capex(0x1520, cv(0x81, b'\x00\x00\x0c') + cv(0x82, b'\x01\x00')
                         + cv(0x83, b'\x00\x14') + cv(0x86, b'\xff' * 16))))  # 18 short request
    f.append(t.c2s(capex(0x9999, b'\x01\x02\x03\x04')))            # 19 unknown GDS id
    f.append(t.c2s(cmd(0x03, ssp=0x80)))                           # 20 CANUREACH (circuit start)
    f.append(t.s2c(cmd(0x04, direction=2)))                        # 21 ICANREACH
    f.append(t.c2s(cmd(0x05)))                                     # 22 REACH_ACK
    f.append(t.c2s(cmd(0x07, DLC + b'\xbf\x81\x80', dlchlen=35)))  # 23 XIDFRAME with DLC
    f.append(t.c2s(cmd(0x08, flags=0x80)))                         # 24 CONTACT, FCI
    f.append(t.s2c(cmd(0x09, flags=0xc1, direction=2)))            # 25 CONTACTED, FCI+FCA, increment
    # 26: two information frames and a keepalive in one segment
    f.append(t.c2s(info(0x0a, b'I frame one', flags=0x82) + info(0x0a, b'I frame two', flags=0x83)
                   + info(0x1d, b'')))
    # 27-28: an information frame split over two segments
    big = info(0x0a, bytes(range(256)) * 2, flags=0x84)
    f.append(t.s2c(big[:100]))
    f.append(t.s2c(big[100:]))
    f.append(t.c2s(info(0x21, b'\x00\x01', flags=0x80)))           # 29 IFCM
    f.append(t.c2s(cmd(0x0c)))                                     # 30 ENTER_BUSY
    f.append(t.c2s(cmd(0x0d)))                                     # 31 EXIT_BUSY
    f.append(t.c2s(cmd(0x14, DLC + b'data frame', dlchlen=35)))    # 32 DATAFRAME
    f.append(t.c2s(cmd(0x10)))                                     # 33 RESTART_DL
    f.append(t.s2c(cmd(0x11, direction=2)))                        # 34 DL_RESTARTED
    f.append(t.c2s(cmd(0x0e)))                                     # 35 HALT_DL
    f.append(t.s2c(cmd(0x0f, direction=2)))                        # 36 DL_HALTED
    f.append(t.c2s(cmd(0x19)))                                     # 37 HALT_DL_NOACK
    f.append(t.c2s(cmd(0x55, b'\x01\x02')))                        # 38 unknown message type
    # 39: a TCP segment to port 2065 that does not start with a DLSw version
    f.append(Tcp(40003, 2065).c2s(b'not DLSw\r\n'))
    return f

def malformed_frames():
    f = []
    t = Tcp(40002, 2065)
    # 1: DLC header length larger than the message length (warning).
    f.append(t.c2s(cmd_header(0x06, 4, dlchlen=40) + b'abcd'))
    # 2: capex vector length below 3 (error).
    f.append(t.c2s(capex(0x1520, cv(0x81, b'\x00\x00\x0c') + b'\x02\x82')))
    # 3: capex vector running past the message.
    f.append(t.c2s(capex(0x1520, b'\x20\x84abc')))
    # 4: DLC header length set but too short data.
    f.append(t.c2s(cmd(0x06, b'xy', dlchlen=2)))
    # 5: OUI vector of the wrong length (FT_UINT24 with 4 octets).
    f.append(t.c2s(capex(0x1520, cv(0x81, b'\x00\x00\x0c\x01'))))
    # 6: refuse GDS without the error fields.
    f.append(t.c2s(capex(0x1522, b'', capex_type=2)))
    # 7: header cut short.
    f.append(udp(2067, 2067, b'\x31\x48\x00'))
    # Frames 8-10: the start of the review reproducer dlsw_capex_short.py
    # (capex with GDS length 0 and 3 and an unknown GDS id, and a SAP list
    # vector), then 60 of its random vectors.
    def dlsw(mtype, data, hlen=72):
        h = struct.pack('!BBHII2sBB', 0x31, hlen, len(data), 0, 0, b'\0\0', mtype, 0)
        h += bytes(max(hlen - 16, 0))
        return h + data
    f.append(udp(2067, 2067, dlsw(0x20, struct.pack('!HH', 0, 0x9999))))
    f.append(udp(2067, 2067, dlsw(0x20, struct.pack('!HH', 3, 0x9999))))
    vec = bytes([4, 0x81, 1, 2]) + bytes([6, 0x86, 0xff, 0xff, 0xff, 0xff]) + bytes([9, 0x87, 1, 2, 3, 4, 5, 6, 7])
    f.append(udp(2067, 2067, dlsw(0x20, struct.pack('!HH', 4 + len(vec), 0x1520) + vec)))
    random.seed(3)
    for i in range(60):
        v = bytes(random.randrange(256) for _ in range(random.randint(0, 40)))
        f.append(udp(2067, 2067, dlsw(random.choice([0x20, 0x20, 0x01, 0x03, 0x0a]),
                                      struct.pack('!HH', random.randrange(60), 0x1520) + v,
                                      hlen=random.choice([16, 72, 72, 0, 20]))))
    return f

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'dlsw-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'dlsw-coverage-malformed.pcap'), malformed_frames())
