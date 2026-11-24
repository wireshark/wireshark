#!/usr/bin/env python3
# Generates test/captures/osmo_trx_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the OsmoTRX (osmo_trxd / osmo_trxc) coverage captures.

Usage: mkosmo_trx.py <outdir>

The dissector registers no UDP port (the port registration is under
#if 0, only Decode As exists), so the main capture uses Exported PDU
frames that name "osmo_trxd" / "osmo_trxc" and carry the UDP port numbers
(the direction of a PDU comes from the ports). osmo-trx-wire.pcapng has
real UDP frames for Decode As (runcov.sh only).

Writes osmo_trx-coverage.pcapng (clean), osmo_trx-coverage-malformed.pcapng
and osmo_trx-coverage-wire.pcapng.
Synthetic: nothing comes from a real network.
"""
import struct
import sys
import os

def _blk(btype, body):
    pad = (-len(body)) % 4
    tl = 12 + len(body) + pad
    return struct.pack('<II', btype, tl) + body + b'\0' * pad + struct.pack('<I', tl)

def pcapng(path, frames):
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    lts = []
    for lt, _ in frames:
        if lt not in lts:
            lts.append(lt)
            out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (lt, p) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        out += _blk(6, struct.pack('<IIIII', lts.index(lt), ts >> 32, ts & 0xffffffff,
                                   len(p), len(p)) + p)
    with open(path, 'wb') as f:
        f.write(out)

def exppdu(proto, payload, sport, dport):
    t = struct.pack('>HH', 12, (len(proto) + 3) & ~3) + proto.encode().ljust((len(proto) + 3) & ~3, b'\0')
    t += struct.pack('>HHI', 24, 4, 2)            # port type: UDP
    t += struct.pack('>HHI', 25, 4, sport) + struct.pack('>HHI', 26, 4, dport)
    return (252, t + struct.pack('>HH', 0, 0) + payload)

def udp_frame(data, sport, dport):
    u = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0,
                     bytes((127, 0, 0, 1)), bytes((127, 0, 0, 1)))
    s = sum((ip[i] << 8) | ip[i + 1] for i in range(0, 20, 2))
    s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack('>H', (~s) & 0xffff) + ip[12:]
    return (1, b'\0' * 12 + b'\x08\x00' + ip + u)

BLEN = {0: 148, 2: 444, 3: 296, 4: 592, 5: 740, 6: 148, 7: 0}

def mod_of(mts):
    if (mts >> 5) in (0, 3): return mts >> 5
    if (mts >> 4) != 3: return mts >> 4
    return mts >> 3

# L1 -> TRX: src - dst == 100;  TRX -> L1: dst - src == 100
TX = (5802, 5702)
RX = (5702, 5802)
TX1 = (5804, 5704)
RX1 = (5704, 5804)
MS_TX = (6802, 6702)
MS_RX = (6702, 6802)

def mts_values():
    vals = []
    for hi in range(16):                 # bits 6..3: modulation and TSC set
        for tsc in ((hi * 3) % 8, (hi * 3 + 4) % 8):
            vals.append((hi << 3) | tsc)
    return vals

def burst(mts, soft=True):
    if mts & 0x80:
        return b''
    n = BLEN[mod_of(mts & 0x7f)]
    if soft:
        return bytes((i * 7) % 256 for i in range(n))
    return bytes((i % 2) for i in range(n))

def clean():
    f = []
    def add(proto, data, ports): f.append(exppdu(proto, data, *ports))
    d = 'osmo_trxd'
    # v0 Tx: GMSK, 8-PSK, NOPE.req, an unknown length; v1 Tx is the same format
    for ver in (0, 1):
        for n in (148, 444, 0, 100):
            add(d, bytes((ver << 4 | 1,)) + struct.pack('>I', 1000 + n) + b'\x10' + bytes((i % 2) for i in range(n)), TX)
    # v0 Rx: a burst with and without the two padding octets, another TN and FN
    add(d, b'\x00' + struct.pack('>I', 2000) + b'\x45' + b'\x01\x00' + b'\x80' * 148, RX)
    add(d, b'\x00' + struct.pack('>I', 2001) + b'\x42' + b'\x02\x01' + b'\x81' * 150, RX1)
    add(d, b'\x00' + struct.pack('>I', 2002) + b'\x40' + b'\x00\x00' + b'\x7f' * 148 + b'\0\0', MS_RX)
    # v1 and v2, Rx and Tx, for each MTS value and for NOPE
    for mts in mts_values() + [0x80 | v for v in (0, 0x20, 0x08)]:
        b = burst(mts)
        # v1 Rx
        add(d, b'\x10' + struct.pack('>I', 7) + b'\x45\x01\x23' + bytes((mts,)) + b'\x00\x20' + b, RX)
        # v2 Rx: one PDU and two batched PDUs (the second without FN, with another TRX)
        p1 = b'\x25' + b'\x80' + bytes((mts,)) + b'\x40' + b'\x01\x02\x03\x04' + struct.pack('>I', 9) + b
        p2 = b'\x01' + b'\x42' + bytes((mts,)) + b'\x44' + b'\x00\x05\x00\x06' + b
        add(d, p1 + p2, RX)
        # a shadow PDU, last of its batch (0x40 = SHADOW.ind)
        add(d, b'\x23' + b'\x41' + bytes((mts,)) + b'\x40' + b'\0\0\0\0' + struct.pack('>I', 10) + b, RX1)
        # v2 Tx: two batched PDUs
        t1 = b'\x25' + b'\x80' + bytes((mts,)) + b'\x03\x05' + b'\0' * 3 + struct.pack('>I', 9) + burst(mts, False)
        t2 = b'\x01' + b'\x00' + bytes((mts,)) + b'\x04\x00' + b'\0' * 3 + burst(mts, False)
        add(d, t1 + t2, TX)
    # v2 Tx single PDU
    add(d, b'\x23\x01' + b'\x10' + b'\x00\x00' + b'\0' * 3 + struct.pack('>I', 11) + burst(0x10, False), TX1)
    add(d, b'\x20\x00' + b'\x10' + b'\x00\x00' + b'\0' * 3 + struct.pack('>I', 12) + burst(0x10, False), MS_TX)
    # a burst from a random source port: direction guessed from the destination
    # port, and an expert comment ("Injected message") on each of them
    for dport, ver in ((5702, 1), (5704, 0), (6702, 1), (5802, 1), (5804, 0), (6802, 1)):
        tx = dport in (5702, 5704, 6702)
        if tx:
            add(d, bytes((ver << 4 | 1,)) + struct.pack('>I', 3) + b'\x00' + b'\x01' * 148, (40000, dport))
        else:
            add(d, b'\x10' + struct.pack('>I', 4) + b'\x40\0\0' + b'\x00\0\0' + burst(0), (40000, dport))
    # TRXC: commands, responses and indications
    c = 'osmo_trxc'
    cmds = [b'CMD POWERON', b'CMD POWEROFF', b'CMD SETFORMAT 2', b'CMD RXTUNE 935200',
            b'CMD SETTSC 3', b'CMD SETSLOT 2 1', b'CMD SETMAXDLY 62', b'CMD NOMTXPOWER']
    for m in cmds:
        add(c, m + b'\0', (5801, 5701))
    for m in (b'RSP POWERON 0', b'RSP POWEROFF 0', b'RSP SETFORMAT 0 2', b'RSP RXTUNE 0 935200',
              b'RSP NOMTXPOWER 0 50', b'RSP SETSLOT 1 2 1'):
        add(c, m + b'\0', (5701, 5801))
    for m in (b'IND CLOCK 123456', b'IND CLOCK 4', b'IND NOP'):
        add(c, m + b'\0', (5700, 5800))
    add(c, b'IND CLOCK 99\0', (6700, 6800))
    # injected control messages (guessed direction): every port of the table
    for dport in (5701, 5703, 6701, 5801, 5803, 6801, 5800, 6800):
        add(c, b'CMD POWERON\0', (40000, dport))
    return f

def malformed():
    f = []
    def add(proto, data, ports): f.append(exppdu(proto, data, *ports))
    d = 'osmo_trxd'
    add(d, b'\x70' + b'\0' * 8, TX)                         # unknown version, Tx
    add(d, b'\x30' + b'\0' * 8, RX)                         # unknown version, Rx
    add(d, b'\x00' * 8, (1, 2))                             # direction unknown
    add(d, b'\x10' + struct.pack('>I', 7) + b'\x40\0\0\x00\0\0' + b'\1' * 148 + b'\xaa' * 3, RX)   # tail octets
    add(d, b'\x00' + struct.pack('>I', 1) + b'\x40' + b'\0\0' + b'\x80' * 10, RX)   # burst too short
    add(d, b'\x00', RX)                                     # nothing after the version
    add(d, b'\x20\x80', RX)                                 # truncated v2 header
    add(d, b'\x25\x80\x00\x40' + b'\0' * 6, RX)             # truncated v2 header, batch
    add(d, b'\x25\x80\x00\x40\0\0\0\0' + struct.pack('>I', 1) + b'\0' * 50, RX)   # batch, short burst
    add(d, b'\x21\x00\x00\x00\0\0\0\0\0' + struct.pack('>I', 1) + b'\0' * 5, TX)  # Tx short burst
    add(d, b'\x01\0\0\0\x01\x00', TX)
    c = 'osmo_trxc'
    for m in (b'XYZ POWERON', b'CMDX', b'IND', b'RSP A ', b'RSP', b'CMD', b'CMD\x00POWERON\x00x',
              b'RSP POWEROFF', b'RSP POWEROFF ', b'RSP POWERON\x20', b'IND-CLOCK 1', b'CMD'):
        add(c, m, (5701, 5801))
    add(c, b'CMD POWERON\0', (1, 2))                        # direction unknown and not injected
    add(c, b'RSP SETFORMAT 0 1\0', (40000, 12345))
    return f

def wire():
    f = []
    f.append(udp_frame(b'\x10' + struct.pack('>I', 7) + b'\x40\0\0\x00\0\0' + burst(0), 5702, 5802))
    f.append(udp_frame(b'\x25\x80\x00\x40' + b'\0' * 4 + struct.pack('>I', 9) + burst(0) +
                       b'\x01\x00\x00\x40' + b'\0' * 4 + burst(0), 5802, 5702))
    f.append(udp_frame(b'CMD POWERON\0', 5801, 5701))
    f.append(udp_frame(b'RSP POWERON 0\0', 5701, 5801))
    f.append(udp_frame(b'IND CLOCK 5\0', 5800, 5700))
    return f

if __name__ == '__main__':
    d = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcapng(os.path.join(d, 'osmo_trx-coverage.pcapng'), clean())
    pcapng(os.path.join(d, 'osmo_trx-coverage-malformed.pcapng'), malformed())
    pcapng(os.path.join(d, 'osmo_trx-coverage-wire.pcapng'), wire())
