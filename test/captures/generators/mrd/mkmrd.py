#!/usr/bin/env python3
# Generates test/captures/mrd_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MRD coverage captures.  Usage: mkmrd.py <outdir> [-v]
MRD (Multicast Router Discovery) rides on IGMP (IP protocol 2, TTL 1).
Addresses are from 192.0.2.0/24; nothing comes from a real network."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from r13_pcaplib import csum, eth, exported_pdu

frames = []; marks = []   # frames: (interface, bytes)
def mark(n): marks.append((n, len(frames) + 1))

def igmp(payload, dst='224.0.0.106', src='192.0.2.1', bad=False, ttl=1):
    """payload: IGMP message with a zero checksum at octets 2-3."""
    c = csum(payload)
    if bad: c ^= 0x1234
    payload = payload[:2] + struct.pack('!H', c) + payload[4:]
    d = bytes(int(x) for x in dst.split('.')); s = bytes(int(x) for x in src.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0xc0, 20 + len(payload), 1, 0, ttl, 2, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    mac = b'\x01\x00\x5e\x00\x00' + bytes([d[3]]) if d[0] == 224 else b'\x02\0\0\0\0\x02'
    frames.append((0, eth(h + payload, 0x0800, b'\x02\0\0\0\0\x01', mac)))

def expdu(payload, bad=False):
    """The message handed to the 'mrd' dissector directly, with no IP header
    (Exported PDU, second interface); the IGMP type table of the real path
    gives 0x24 and 0x25 to MSNIP, so this is the only way to reach them."""
    c = csum(payload)
    if bad: c ^= 0x1234
    frames.append((1, exported_pdu('mrd', payload[:2] + struct.pack('!H', c) + payload[4:])))

def opt(t, data): return bytes([t, len(data)]) + data

def mra(adv, qi, rv, **kw): igmp(bytes([0x30, adv, 0, 0]) + struct.pack('!HH', qi, rv), **kw)
def mrs(**kw): igmp(bytes([0x31, 0, 0, 0]), **kw)
def mrt(**kw): igmp(bytes([0x32, 0, 0, 0]), **kw)
def mra_old(adv, opts, nopts=None, bad=False):
    n = len(opts) if nopts is None else nopts
    expdu(bytes([0x24, adv, 0, 0, 0, 0]) + struct.pack('!H', n) + b''.join(opts), bad)

def build_main():
    mark('RFC 4286 messages to 224.0.0.106')
    mra(20, 125, 2)
    mra(255, 65535, 7)
    mrs()
    mrt()
    mark('draft 06 messages (deprecated types 0x24-0x26; Exported PDU naming mrd, plus 0x26 to 224.0.0.2 over IP)')
    mra_old(30, [])
    mra_old(30, [opt(1, struct.pack('!H', 125)), opt(2, struct.pack('!H', 2))])
    mra_old(30, [opt(1, struct.pack('!H', 60)), opt(0x7f, b'\x01\x02\x03'), opt(2, struct.pack('!H', 3))])
    expdu(bytes([0x25, 0, 0, 0]))
    expdu(bytes([0x26, 0, 0, 0]))
    igmp(bytes([0x26, 0, 0, 0]), dst='224.0.0.2')
    mark('draft 08-10: MRA and MRT to All-Systems 224.0.0.1')
    mra(10, 100, 2, dst='224.0.0.1')
    mrt(dst='224.0.0.1')
    mark('MRS to All-Routers')
    mrs(dst='224.0.0.2')

def build_malformed():
    global frames, marks
    frames = []; marks = []
    mark('bad checksum (error)')
    mra(20, 125, 2, bad=True)
    mrs(bad=True)
    mra_old(30, [], bad=True)
    mark('destination outside 224.0.0/24 (warning)')
    mra(20, 125, 2, dst='239.1.2.3')
    mrs(dst='192.0.2.9')
    mark('truncated')
    igmp(bytes([0x30, 20, 0, 0, 0, 125]))                                   # MRA cut in the Robustness Variable
    igmp(bytes([0x30, 20]))
    expdu(bytes([0x24, 30, 0, 0, 0, 0, 0, 2]) + opt(1, struct.pack('!H', 125)))   # two options announced, one present
    expdu(bytes([0x24, 30, 0, 0, 0, 0, 0xff, 0xff]) + opt(1, b'\x00\x01') * 3)   # 65535 options announced
    expdu(bytes([0x24, 30, 0, 0, 0, 0, 0, 1, 1, 9, 0, 1]))                         # option length beyond the data
    expdu(bytes([0x24, 30, 0, 0, 0, 0, 0, 1, 0x7f, 200, 1]))                      # unknown option length beyond the data
    expdu(bytes([0x24, 30, 0, 0, 0, 0, 0, 1, 1, 1, 1]))                           # query interval of length 1
    expdu(bytes([0x24, 30, 0, 0, 0, 0, 0, 1, 2, 4, 1, 2, 3, 4]))                  # robustness variable of length 4
    expdu(bytes([0x24, 30, 0, 0, 0, 0, 0, 1, 1]))                                  # option cut before its length
    igmp(bytes([0x31]))                                                      # MRS cut before the checksum
    mark('TTL other than 1')
    mra(20, 125, 2, ttl=64)

def block(t, body):
    body += b'\0' * (-len(body) % 4)
    return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)

def write_pcapng(name, frames):
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', 1, 0, 262144))      # Ethernet
    out += block(1, struct.pack('<HHI', 252, 0, 262144))    # Exported PDU
    for i, (ifc, data) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)
    open(name, 'wb').write(out)

if __name__ == '__main__':
    out = sys.argv[1]
    build_main()
    write_pcapng(os.path.join(out, 'mrd-coverage.pcapng'), frames)
    if '-v' in sys.argv: print(len(frames), 'frames'); print(marks)
    frames = []
    build_malformed()
    write_pcapng(os.path.join(out, 'mrd-coverage-malformed.pcapng'), frames)
    if '-v' in sys.argv: print(len(frames), 'malformed frames'); print(marks)
