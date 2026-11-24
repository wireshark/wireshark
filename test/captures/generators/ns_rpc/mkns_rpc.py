#!/usr/bin/env python3
# Generates test/captures/ns_rpc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the NetScaler RPC (NS-RPC) coverage captures (synthetic, struct only).

Usage: mkns_rpc.py <outdir> [-v]

Writes, into <outdir>:
  ns-rpc-coverage.pcap            main capture: Exported PDU frames (link type 252)
                                  naming "nstrace.mep" (an NS-MEP frame with the
                                  signature 0xA5A5 goes to NS-RPC), a few naming
                                  "nsrpc" directly
  ns-rpc-coverage-malformed.pcap  messages cut short
  ns-rpc-tcp.pcap                 messages over TCP port 3010 (the heuristic
                                  dissector, disabled by default): runcov.sh only
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
VERBOSE = '-v' in sys.argv

# cmd values the dissector knows (value_string) and a few it does not
CMDS = list(range(1, 0x10)) + [0x1f, 0x20, 0x7f]
ERRS = [0x000, 0x101, 0x10c, 0x135, 0x150, 0x153, 0x154, 0x155, 0x156, 0x160, 0x161, 0x162, 0x163, 0x413, 0x6ff, 0x777]
IOCTLS = [0x40404E0A, 0x42004E04, 0x44006E3E, 0xF0916E12, 0xF2C15027, 0x12345678]


def rpc(cmd, err=0, ioctl=None, extra=b'', length=None, sig=0xA5A5, resp_pad=True):
    """Length (4), signature (2), 2 octets, command, 1 octet, status code (2),
    4 octets, then for a remote IOCTL the IOCTL number."""
    body = struct.pack('<HBBHI', 0, cmd, 0, err, 0)
    if ioctl is not None:
        body += struct.pack('<I', ioctl)
    body += extra
    n = 6 + len(body) if length is None else length
    return struct.pack('<IH', n, sig) + body


def expdu(data, name=b'nstrace.mep'):
    pad = (-len(name)) % 4
    return struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad + struct.pack('!HH', 0, 0) + data


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def tcp_frame(payload, seq, sport=40000, dport=3010):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 0x50, 0x18, 65535, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(t), 1, 0, 64, 6, 0, bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00' + ip + t


def write_pcap(fname, frames, linktype):
    with open(os.path.join(OUT, fname), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


RANGES = []


def main():
    os.makedirs(OUT, exist_ok=True)
    frames, tcp = [], []

    def add(group, items, name=b'nstrace.mep'):
        first = len(frames) + 1
        for d in items:
            frames.append(expdu(d, name))
            tcp.append(d)
        RANGES.append(('ns-rpc-coverage.pcap', first, len(frames), group))

    add('requests: every command 0x01-0x0F, 0x1F and unknown ones (0x20, 0x7f); the remote IOCTL request is frame 2',
        [rpc(c, ioctl=0x42004E04 if c == 2 else None, extra=b'\0' * 8) for c in CMDS])
    add('responses (command | 0x80): every command with the status code; remote IOCTL responses with the error code 8 octets after the extra data starting at the IOCTL number',
        [rpc(c | 0x80, err=ERRS[i % len(ERRS)], ioctl=0x42004E04 if c == 2 else None,
             extra=struct.pack('<IIII', 0, 0, ERRS[(i + 3) % len(ERRS)], 0)) for i, c in enumerate(CMDS)])
    add('status codes of responses: every value of the table and an unknown one',
        [rpc(0x85, err=e) for e in ERRS])
    add('remote IOCTL requests and responses: known and unknown IOCTL numbers; response error codes (success, NO MEM, unknown)',
        [rpc(2, ioctl=i, extra=b'\0' * 8) for i in IOCTLS] +
        [rpc(0x82, ioctl=i, extra=struct.pack('<IIII', 0, 0, e, 0)) for i, e in zip(IOCTLS, (0, 0x10c, 0x777, 0x6ff, 0x150, 0x413))])
    add('messages handed over by the named dissector "nsrpc": a request, a response and a remote IOCTL pair',
        [rpc(5), rpc(0x85, err=0), rpc(2, ioctl=0x44006E3E, extra=b'\0' * 8), rpc(0x82, ioctl=0x44006E3E, extra=struct.pack('<IIII', 0, 0, 0x160, 0))],
        name=b'nsrpc')
    write_pcap('ns-rpc-coverage.pcap', frames, 252)
    # the TCP capture: the same messages, one per segment; a stream that does not carry RPC
    seq = 1
    tf = []
    for d in tcp + [b'not an rpc message at all, no signature here', b'\x01\x02']:
        tf.append(tcp_frame(d, seq))
        seq += len(d)
    write_pcap('ns-rpc-tcp.pcap', tf, 1)

    mal = []
    full = {'req': rpc(5), 'ioctl': rpc(2, ioctl=0x42004E04, extra=b'\0' * 8),
            'resp': rpc(0x82, ioctl=0x42004E04, extra=struct.pack('<IIII', 0, 0, 0x10c, 0))}
    for k, d in full.items():
        for n in range(7 if k == 'req' else 12, len(d), 3):
            mal.append(expdu(d[:n]))
    mal.append(expdu(b'\x05\x00\x00\x00\xa5'))
    mal.append(expdu(rpc(0x82, ioctl=0x42004E04)))             # IOCTL response without the trailing error code
    write_pcap('ns-rpc-coverage-malformed.pcap', mal, 252)
    RANGES.append(('ns-rpc-coverage-malformed.pcap', 1, len(mal), 'messages cut short (exceptions), IOCTL response without the error code'))
    if VERBOSE:
        for r in RANGES:
            print(*r)
        print(len(frames), len(mal), len(tf))


main()
