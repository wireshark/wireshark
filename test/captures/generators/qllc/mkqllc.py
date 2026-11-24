#!/usr/bin/env python3
# Generates test/captures/qllc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic QLLC captures. Usage: mkqllc.py <outdir> [-v]

X.25 over TCP (XOT, port 1998, Ethernet frames, link type 1): call set up
of two virtual circuits, then Q-bit data packets (QLLC: address, control
and the XID / TEST / FRMR data) and data packets without the Q bit (SNA
path information units, passed on by QLLC to the SNA dissector). QLLC is
only reached when the X.25 preference x25.payload_is_qllc_sna is on (the
dissector has no other way to be selected), so the tests and runcov.sh
pass -o x25.payload_is_qllc_sna:TRUE. Built with struct; all values are
made up."""
import struct
import sys
import os
import random

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv
random.seed(1998)

def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (d, n) in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(d), len(d)))
            f.write(d)

def eth_tcp(payload, sport, dport, seq, flags=0x18, ack=1, rev=False):
    opt = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt + payload
    a, b = (bytes([192, 0, 2, 2]), bytes([192, 0, 2, 1])) if rev else (bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, a, b) + tcp
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip

frames = []
state = {'c': 1000, 's': 7000}
def tcp_send(payload, note, from_client=True, flags=0x18):
    if from_client:
        d = eth_tcp(payload, 4001, 1998, state['c'], flags, ack=state['s'])
        state['c'] += len(payload) + (1 if flags & 0x03 else 0)
    else:
        d = eth_tcp(payload, 1998, 4001, state['s'], flags, ack=state['c'], rev=True)
        state['s'] += len(payload) + (1 if flags & 0x03 else 0)
    frames.append((d, note))

def xot(x25):
    return struct.pack('>HH', 0, len(x25)) + x25

def bcd(digits):
    digits = digits + ('0' if len(digits) % 2 else '')
    return bytes(int(digits[i], 16) << 4 | int(digits[i + 1], 16) for i in range(0, len(digits), 2))

def call_request(lcn, called='123456', calling='654321', cud=b'\xc3'):
    addrs = bcd(called + calling) if (len(called) + len(calling)) % 2 == 0 else bcd(called + calling)
    return bytes([0x10 | (lcn >> 8), lcn & 0xff, 0x0b, (len(calling) << 4) | len(called)]) + addrs + bytes([0]) + cud

def call_accepted(lcn):
    return bytes([0x10 | (lcn >> 8), lcn & 0xff, 0x0f, 0x00, 0x00])

def data(lcn, payload, q=True, ps=0, pr=0, m=0):
    return bytes([(0x80 if q else 0x00) | 0x10 | (lcn >> 8), lcn & 0xff, (pr << 5) | (m << 4) | (ps << 1)]) + payload

def clear(lcn, cause=0):
    return bytes([0x10 | (lcn >> 8), lcn & 0xff, 0x13, cause, 0])

# handshake
tcp_send(b'', 'TCP SYN', True, 0x02)
tcp_send(b'', 'TCP SYN/ACK', False, 0x12)
tcp_send(b'', 'TCP ACK', True, 0x10)

for lcn in (1, 2):
    tcp_send(xot(call_request(lcn)), 'X.25 call request, LCN %d' % lcn)
    tcp_send(xot(call_accepted(lcn)), 'X.25 call accepted, LCN %d' % lcn, False)

# QLLC commands and responses: address 0xff = command, others response
ps = [0, 0, 0]
def q(lcn, addr, ctrl, extra=b'', note='', fwd=True):
    i = lcn
    pkt = data(lcn, bytes([addr, ctrl]) + extra, True, ps=ps[i] % 8)
    ps[i] += 1
    tcp_send(xot(pkt), 'QLLC %s' % note, fwd)

CTRL = [(0x03, 'QUI'), (0x13, 'QUI reply required'), (0x17, 'QSIM'), (0x1f, 'QDM'), (0x73, 'QUA'), (0x93, 'QSM'),
        (0x97, 'QFRMR'), (0xbf, 'QXID'), (0xf1, 'QRR'), (0xf3, 'QTEST'), (0x53, 'QDISC / QRD')]
for addr, who in ((0xff, 'command'), (0x01, 'response'), (0x00, 'response, address 0')):
    for ctrl, n in CTRL:
        extra = b''
        if ctrl == 0xbf:
            extra = bytes.fromhex('0d00000000000000')
        elif ctrl == 0xf3:
            extra = b'test data 123'
        elif ctrl == 0x97:
            extra = bytes([0x00, 0x01, 0x02, 0x03, 0x04])
        q(1 if who == 'command' else 2, addr, ctrl, extra, '%s %s (addr 0x%02x)' % (n, who, addr), who == 'command')
for ctrl in (0x01, 0x55, 0x80, 0xff, 0x23):
    q(1, 0xff, ctrl, b'', 'unknown control 0x%02x' % ctrl)
# QRR with the address 0xff is not a command
q(2, 0xff, 0xf1, b'', 'QRR with address 0xff')
# two-octet QLLC header only (no extra)
q(1, 0xc1, 0x73, b'', 'QUA, response with address 0xc1')

# Data without the Q bit: SNA path information units (FID2)
th = bytes([0x2e, 0x00, 0x05, 0x06, 0x00, 0x01])
rh = bytes([0x0b, 0x80, 0x00])
for i, ru in enumerate((b'\x31\x00\x00', b'\x01\x02\x03\x04', b'\x11\x01\x02', b'\x00')):
    pkt = data(1, th[:4] + bytes([0, i + 1]) + rh + ru, False, ps=ps[1] % 8)
    ps[1] += 1
    tcp_send(xot(pkt), 'SNA PIU without the Q bit (%d)' % i, True)
tcp_send(xot(data(2, th + rh + b'\x31\x00', False, ps=0)), 'SNA PIU, VC 2', False)
tcp_send(xot(data(2, th + rh + b'\x31\x00', False, ps=1, m=1)), 'SNA PIU with the M bit', False)
# clear
for lcn in (1, 2):
    tcp_send(xot(clear(lcn)), 'X.25 clear request, LCN %d' % lcn)

write_pcap(os.path.join(OUT, 'qllc-coverage.pcap'), frames)

# ---------------------------------------------------------------- malformed
mal = []
state['c'] = 1000; state['s'] = 7000
frames_save = frames[:]
frames[:] = []
tcp_send(b'', 'TCP SYN', True, 0x02)
tcp_send(b'', 'TCP SYN/ACK', False, 0x12)
tcp_send(b'', 'TCP ACK', True, 0x10)
tcp_send(xot(call_request(7)), 'call')
tcp_send(xot(call_accepted(7)), 'call accepted', False)
tcp_send(xot(data(7, b'\xff')), 'QLLC with a single octet')
tcp_send(xot(data(7, b'')), 'Q data without payload')
tcp_send(xot(data(7, bytes([0xff, 0xbf]))), 'QLLC XID without data')
tcp_send(xot(data(7, b'\x2e')), 'SNA data cut', True)
tcp_send(xot(data(7, bytes([0x2e, 0x00, 0x05]), False)), 'SNA cut inside the TH')
for i in range(30):
    tcp_send(xot(data(7, bytes(random.getrandbits(8) for _ in range(random.randint(2, 12))), random.random() < 0.7, ps=i % 8)), 'random data')
write_pcap(os.path.join(OUT, 'qllc-coverage-malformed.pcap'), frames)
frames[:] = frames_save

if VERBOSE:
    print('frames', len(frames), 'malformed', len(mal))
    for i, (d, n) in enumerate(frames, 1):
        print(i, n)
