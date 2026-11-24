#!/usr/bin/env python3
# Generates test/captures/ouch_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the OUCH 4.x coverage captures.

Usage: mkouch.py <outdir>

Writes ouch-coverage.pcapng (clean: Exported PDU frames for "ouch" and
for "soupbintcp" carrying OUCH, which is how OUCH is reached by default,
and three TCP frames to port 9100 that are OUCH only with Decode As),
ouch-coverage-malformed.pcapng (truncated messages) and
ouch-coverage-wire.pcapng (TCP, reached with Decode As; runcov.sh only).
Synthetic: nothing comes from a real network.
"""
import struct
import sys
import os

# ---------------------------------------------------------------- pcapng
def _blk(btype, body):
    pad = (-len(body)) % 4
    tl = 12 + len(body) + pad
    return struct.pack('<II', btype, tl) + body + b'\0' * pad + struct.pack('<I', tl)

def pcapng(path, frames):
    """frames: list of (linktype, bytes)"""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    lts = []
    for lt, _ in frames:
        if lt not in lts:
            lts.append(lt)
            out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (lt, p) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        out += _blk(6, struct.pack('<IIIII', lts.index(lt), ts >> 32,
                                   ts & 0xffffffff, len(p), len(p)) + p)
    with open(path, 'wb') as f:
        f.write(out)

def exppdu(proto, payload):
    return (struct.pack('>HH', 12, (len(proto) + 3) & ~3) +
            proto.encode().ljust((len(proto) + 3) & ~3, b'\0') +
            struct.pack('>HH', 0, 0) + payload)

def eth_ip_tcp(sp, dp, seq, data):
    tcp = struct.pack('>HHIIBBHHH', sp, dp, seq, 1, 5 << 4, 0x18, 65535, 0, 0) + data
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2)))
    s = sum((ip[i] << 8) | ip[i + 1] for i in range(0, 20, 2))
    s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack('>H', (~s) & 0xffff) + ip[12:]
    return b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00' + ip + tcp

# ------------------------------------------------------------------ OUCH
# Field value lists (the value strings of the dissector).
V = {
    'bbo_weight_indicator': b'0123 SN',
    'broken_trade_reason': b'ECSX',
    'buy_sell_indicator': b'BSTE',
    'cancel_reason': b'CDEHIKQSTUXZ',
    'capacity': b'AOPR',
    'cross_type': b'NOCIHRS',
    'customer_type': b'RN ',
    'display': b'AILMNOPQRTWYZ',
    'event_code': b'SE',
    'iso_eligible': b'YN',
    'liquidity_flag': b'045678ACHIJKLMNORWabcdefghjkmrtxy',
    'order_state': b'LD',
    'price_correction_reason': b'ECSX',
    'reject_reason': b'THZSDCLMRXNOWabcdefghijklmn',
    'trade_correction_reason': b'N',
}
TIF = [0, 99998, 99999, 3661, 1, 86400]
PRICE = [1234500, 0x7fffffff, 0, 99, 10000]
REFTYPE = [ord('I'), 0x00, ord('x'), 0x01, 0xff, 0x7e, 0x20]
STR = {'order_token': 14, 'existing_order_token': 14, 'replacement_order_token': 14,
       'previous_order_token': 14, 'stock': 8, 'firm': 4}
U32 = ('shares', 'decrement_shares', 'executed_shares', 'min_quantity',
       'quantity_prevented_from_trading')
U64 = ('order_reference_number', 'match_number')
PRICES = ('price', 'execution_price', 'new_execution_price', 'reference_price')

# Message layouts: (type byte, [field...]); 'if N' fields exist from length N.
L = {
 'O': ['order_token', 'buy_sell_indicator', 'shares', 'stock', 'price', 'tif', 'firm',
       'display', 'capacity', 'iso_eligible', 'min_quantity', 'cross_type', ('customer_type', 49)],
 'A': ['ts', 'order_token', 'buy_sell_indicator', 'shares', 'stock', 'price', 'tif', 'firm',
       'display', 'order_reference_number', 'capacity', 'iso_eligible', 'min_quantity',
       'cross_type', 'order_state', ('bbo_weight_indicator', 66)],
 'U': ['existing_order_token', 'replacement_order_token', 'shares', 'price', 'tif', 'display',
       'iso_eligible', 'min_quantity'],
 'X': ['order_token', 'shares'],
 'M': ['order_token', 'buy_sell_indicator', 'shares'],
 'S': ['ts', 'event_code'],
 'R': ['ts', 'replacement_order_token', 'buy_sell_indicator', 'shares', 'stock', 'price', 'tif',
       'firm', 'display', 'order_reference_number', 'capacity', 'iso_eligible', 'min_quantity',
       'cross_type', 'order_state', 'previous_order_token', ('bbo_weight_indicator', 80)],
 'C': ['ts', 'order_token', 'decrement_shares', 'cancel_reason'],
 'D': ['ts', 'order_token', 'decrement_shares', 'cancel_reason', 'quantity_prevented_from_trading',
       'execution_price', 'liquidity_flag'],
 'E': ['ts', 'order_token', 'executed_shares', 'execution_price', 'liquidity_flag', 'match_number'],
 'B': ['ts', 'order_token', 'match_number', 'broken_trade_reason'],
 'F': ['ts', 'order_token', 'executed_shares', 'execution_price', 'liquidity_flag', 'match_number',
       'trade_correction_reason'],
 'G': ['ts', 'order_token', 'executed_shares', 'execution_price', 'liquidity_flag', 'match_number',
       'reference_price', 'reference_price_type'],
 'K': ['ts', 'order_token', 'match_number', 'new_execution_price', 'price_correction_reason'],
 'J': ['ts', 'order_token', 'reject_reason'],
 'P': ['ts', 'order_token'],
 'I': ['ts', 'order_token'],
 'T': ['ts', 'order_token', 'price', 'display', 'order_reference_number'],
 'm': ['ts', 'order_token', 'buy_sell_indicator', 'shares'],   # 'M' on the wire, 28 bytes
}

def field(name, i, serial):
    if name == 'ts':
        return struct.pack('>Q', (3600 * 9 + 1800 + i) * 10**9 + 123456789 + i)
    if name in V:
        v = V[name]
        return bytes((v[i % len(v)],))
    if name in STR:
        base = {'stock': b'AAPL', 'firm': b'FRM', }.get(name, b'TOK%d_' % serial)
        return (base + str(i).encode()).ljust(STR[name], b' ')[:STR[name]]
    if name in U32:
        return struct.pack('>I', 100 * (i + 1))
    if name in U64:
        return struct.pack('>Q', 0x1122334455667788 + i)
    if name == 'tif':
        return struct.pack('>I', TIF[i % len(TIF)])
    if name in PRICES:
        return struct.pack('>I', PRICE[i % len(PRICE)])
    if name == 'reference_price_type':
        return bytes((REFTYPE[i % len(REFTYPE)],))
    if name == 'rest':
        return b'\xaa' * 8
    raise KeyError(name)

def build(t, long, i, serial):
    """long: include the optional trailing field (4.1/4.2)"""
    out = bytes((ord({'m': 'M', 'R': 'U'}.get(t, t)),))
    for f in L[t]:
        if isinstance(f, tuple):
            if not long:
                continue
            f = f[0]
        out += field(f, i, serial)
    return out

def count(t):
    """number of variants so that every value of every list is used"""
    n = 1
    for f in L[t]:
        f = f[0] if isinstance(f, tuple) else f
        if f in V: n = max(n, len(V[f]))
        elif f == 'tif': n = max(n, len(TIF))
        elif f in PRICES: n = max(n, len(PRICE))
        elif f == 'reference_price_type': n = max(n, len(REFTYPE))
    return n

def messages():
    msgs = []
    serial = 0
    for t in L:
        n = count(t)
        has_long = any(isinstance(f, tuple) for f in L[t])
        for i in range(n):
            serial += 1
            # alternate between the 4.0/4.1 and the 4.2 layouts
            msgs.append((t, build(t, has_long and (i % 2 == 0 or t in 'AR') and
                                  (i % 2 == 0), i, serial)))
        if has_long:
            msgs.append((t, build(t, True, 0, serial + 1000)))
            msgs.append((t, build(t, False, 1, serial + 1001)))
    return msgs

def soup(kind, data):
    return struct.pack('>H', len(data) + 1) + kind.encode() + data

def clean():
    fr = []
    msgs = messages()
    # direct: Exported PDU "ouch"
    for t, m in msgs:
        fr.append((252, exppdu('ouch', m)))
    # unknown message type
    fr.append((252, exppdu('ouch', b'Z' + b'\0\0\0\0')))
    fr.append((252, exppdu('ouch', b'Q' + b'abc')))
    # through the SoupBinTCP heuristic: one of each type and length
    seen = set()
    for t, m in msgs:
        if (t, len(m)) in seen:
            continue
        seen.add((t, len(m)))
        fr.append((252, exppdu('soupbintcp', soup('S', m) if t in 'AREDFGBKJPITCSm' else soup('U', m))))
    # not recognised by the heuristic (wrong length for the type): left to SoupBinTCP
    for t in 'OUXMSACDEFGBKJPIT':
        fr.append((252, exppdu('soupbintcp', soup('U', t.encode() + b'\0' * 2))))
    fr.append((252, exppdu('soupbintcp', soup('U', b'Q' + b'\0' * 30))))
    # OUCH directly on TCP port 9100 (plain TCP unless Decode As is used)
    fr.extend(wire()[:3])
    return fr

def malformed():
    fr = []
    for t in L:
        m = build(t, True, 0, 1)
        for cut in (2, 9, len(m) // 2, len(m) - 1):
            if 0 < cut < len(m):
                fr.append((252, exppdu('ouch', m[:cut])))
    fr.append((252, exppdu('ouch', b'U' + b'\0' * 100)))
    return fr

def wire():
    fr = []
    seq = 5000
    for t, m in messages()[:60:3]:
        fr.append((1, eth_ip_tcp(40000, 9100, seq, m)))
        seq += len(m)
    return fr

if __name__ == '__main__':
    d = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcapng(os.path.join(d, 'ouch-coverage.pcapng'), clean())
    pcapng(os.path.join(d, 'ouch-coverage-malformed.pcapng'), malformed())
    pcapng(os.path.join(d, 'ouch-coverage-wire.pcapng'), wire())  # runcov.sh only
