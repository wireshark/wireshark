#!/usr/bin/env python3
# Generates test/captures/hcrt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the HCrt coverage captures.  Usage: mkhcrt.py <outdir>

HCrt (Hotline Command-Response Transaction) over UDP port 47000 and
directly over Ethernet (ethertype 0xf052).  Everything is built with
struct; nothing comes from a real network."""
import struct
import sys
import os

CLI = bytes([192, 0, 2, 1])
SRV = bytes([192, 0, 2, 2])
MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')

NOP, WRITE, READ, RESP = 0, 1, 2, 3


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp_frame(payload, sport=40000, dport=47000, to_server=True, ipid=1):
    src, dst = (CLI, SRV) if to_server else (SRV, CLI)
    ms, md = (MAC_C, MAC_S) if to_server else (MAC_S, MAC_C)
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), ipid, 0, 64, 17,
                     0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return md + ms + b'\x08\x00' + ip + udp


def eth_frame(payload, etype=0xf052, to_server=True):
    ms, md = (MAC_C, MAC_S) if to_server else (MAC_S, MAC_C)
    return md + ms + struct.pack('!H', etype) + payload


def msg(typ, tag=0, am=0, do=0, b1=0xff, adl=0, last=True, body=None, b0=None):
    """One HCrt message.  am: 0 = 32 bit, 1 = 64 bit.  body defaults to
    the size the dissector expects, filled with placeholder values."""
    if b0 is None:
        b0 = (tag & 0xf) | (typ << 4) | (am << 6) | (do << 7)
    w = 8 if am else 4
    if body is None:
        n = {NOP: adl, WRITE: adl + 1, READ: 1, RESP: adl}[typ]
        body = b''.join(((0x1000 + i * 0x11) & ((1 << (8 * w)) - 1)).to_bytes(w, 'little')
                        for i in range(n))
    h = struct.pack('<BBH', b0, b1, (adl & 0xfff) | (0x8000 if last else 0))
    return h + body


class Cap:
    def __init__(self):
        self.frames = []
        self.t = 1700000000

    def add(self, fr):
        self.frames.append((self.t, fr))
        self.t += 1

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for t, fr in self.frames:
                f.write(struct.pack('<IIII', t, 0, len(fr), len(fr)) + fr)


def main(out):
    c = Cap()
    u = lambda p, **kw: c.add(udp_frame(p, **kw))
    # UDP 47000
    u(msg(NOP, tag=1, adl=0))                                  # 1
    u(msg(NOP, tag=2, adl=2))                                  # 2
    u(msg(NOP, tag=3, am=1, adl=1))                            # 3 64 bit NOP
    u(msg(WRITE, tag=4, adl=0, b1=0xf1))                       # 4 write, one dword
    u(msg(WRITE, tag=5, adl=1, b1=0xcc))                       # 5 Info: address and data
    u(msg(WRITE, tag=6, adl=3, b1=0x33))                       # 6 four dwords
    u(msg(WRITE, tag=7, am=1, adl=1, b1=0x88))                 # 7 64 bit write
    u(msg(WRITE, tag=8, am=1, adl=2, b1=0x44))                 # 8
    u(msg(READ, tag=9, adl=1, b1=0x22))                        # 9 Info: address
    u(msg(READ, tag=10, adl=0, b1=0x11))                       # 10
    u(msg(READ, tag=11, am=1, adl=1, b1=0x5a))                 # 11 64 bit read, unlisted enables
    u(msg(RESP, tag=12, adl=0, b1=0x00), to_server=False, sport=47000, dport=40000)   # 12
    u(msg(RESP, tag=13, adl=2, b1=0x10), to_server=False, sport=47000, dport=40000)   # 13 timeout
    u(msg(RESP, tag=14, am=1, adl=1, b1=0x20), to_server=False, sport=47000, dport=40000)  # 14 error
    u(msg(RESP, tag=15, adl=1, b1=0x30), to_server=False, sport=47000, dport=40000)   # 15 reserved
    u(msg(RESP, tag=0, adl=1, b1=0xf0), to_server=False, sport=47000, dport=40000)    # 16
    u(msg(NOP, tag=1, do=1, adl=1))                            # 17 discovery operation
    # several messages in one packet: byte 0 must be equal in all
    u(msg(WRITE, tag=3, adl=1, last=False) + msg(WRITE, tag=3, adl=2, last=False) +
      msg(WRITE, tag=3, adl=0, last=True))                     # 18
    u(msg(READ, tag=4, last=False, b1=0x11) + msg(READ, tag=4, b1=0x22, last=False) +
      msg(READ, tag=4, b1=0x33, last=True))                    # 19
    u(msg(NOP, tag=5, do=1, adl=1, last=False) + msg(NOP, tag=5, do=1, adl=0, last=True))  # 20
    u(msg(WRITE, tag=6, am=1, adl=1, last=False) + msg(WRITE, tag=6, am=1, adl=1, last=True))  # 21
    u(msg(RESP, tag=7, adl=1, last=False) + msg(RESP, tag=7, adl=0, last=True),
      to_server=False, sport=47000, dport=40000)               # 22
    # Ethernet, ethertype 0xf052
    c.add(eth_frame(msg(NOP, tag=1, adl=1)))                   # 23
    c.add(eth_frame(msg(WRITE, tag=2, adl=1, b1=0xff)))        # 24
    c.add(eth_frame(msg(READ, tag=3, am=1, adl=1)))            # 25
    c.add(eth_frame(msg(RESP, tag=4, adl=1, b1=0x20), to_server=False))   # 26
    c.write(os.path.join(out, 'hcrt-coverage.pcap'))

    m = Cap()
    mu = lambda p, **kw: m.add(udp_frame(p, **kw))
    # byte 0 differs between the messages: expert info
    mu(msg(WRITE, tag=1, adl=0, last=False) + msg(WRITE, tag=2, adl=0, last=True))
    mu(msg(WRITE, tag=1, adl=0, last=False) + msg(READ, tag=1, adl=0, last=True))
    mu(msg(RESP, tag=1, adl=0, last=False) + msg(NOP, tag=1, adl=0, last=True))
    # ADL larger than the data present
    mu(msg(WRITE, tag=1, adl=3, body=struct.pack('<II', 1, 2)))
    mu(msg(WRITE, tag=1, am=1, adl=2, body=struct.pack('<QQ', 1, 2)))
    mu(msg(NOP, tag=1, adl=0xfff, body=b''))
    mu(msg(RESP, tag=1, adl=5, body=b'\0' * 4))
    mu(msg(READ, tag=1, adl=1, body=b'\0\0'))
    mu(msg(READ, tag=1, am=1, adl=1, body=b'\0' * 4))
    # message is not marked last and nothing follows
    mu(msg(NOP, tag=1, adl=0, last=False))
    # header cut short
    mu(b'\x01\xff\x01')
    mu(msg(NOP, tag=1, last=False) + b'\x01\xff')
    # Info column reads address and data of ADL 1 messages beyond the data
    mu(msg(WRITE, tag=1, adl=1, body=b''))
    mu(msg(READ, tag=1, adl=1, body=b''))
    m.add(eth_frame(msg(WRITE, tag=1, adl=1, body=b'\0\0\0\0')))
    m.write(os.path.join(out, 'hcrt-coverage-malformed.pcap'))


main(sys.argv[1])
