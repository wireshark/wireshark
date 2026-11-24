#!/usr/bin/env python3
# Generates test/captures/f5ethtrailer_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-f5ethtrailer.c (F5 Ethernet trailer and
F5 FILEINFO). Usage: mkf5ethtrailer.py <outdir> [-v]
Writes f5ethtrailer-coverage.pcapng (clean), f5ethtrailer-coverage-malformed.pcapng
and f5ethtrailer-fi-*.pcapng (variants of the first frame, used by runcov.sh).
The TLS provider's secret-carrying types (0 and 2 with a secret) are NOT
generated: no key material is produced."""
import os
import struct
import sys

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

ETH4 = bytes.fromhex('020000000002020000000001') + b'\x08\x00'
ETH6 = bytes.fromhex('020000000002020000000001') + b'\x86\xdd'
A4 = bytes([192, 0, 2, 1]); B4 = bytes([192, 0, 2, 2])
A6 = bytes.fromhex('20010db8000000000000000000000001')
B6 = bytes.fromhex('20010db8000000000000000000000002')

def ip4(proto, payload, off=0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, off, 64, proto, 0, A4, B4)
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload

def ip6(nxt, payload):
    return struct.pack('!IHBB16s16s', 0x60000000, len(payload), nxt, 64, A6, B6) + payload

CNT = [0]
def nextport():
    CNT[0] += 1
    return 20000 + CNT[0]

def tcp(flags=0x10, data=b'dddddd', sp=None, dp=80):
    opt = struct.pack('!BBH', 2, 4, 1460) if flags & 0x02 else b''
    return struct.pack('!HHIIBBHHH', sp or nextport(), dp, 1000, 2000 if flags & 0x10 else 0,
                       (5 + len(opt) // 4) << 4, flags, 8192, 0, 0) + opt + data

def udp(data=b'x' * 18, sp=None, dp=9, v6=False):
    sp = sp or nextport()
    u = struct.pack('!HHHH', sp, dp, 8 + len(data), 0) + data
    if v6:
        c = csum(A6 + B6 + struct.pack('!IHBB', len(u), 0, 0, 17) + u) or 0xffff
        u = u[:6] + struct.pack('!H', c) + u[8:]
    return u

def f4(trailer=b'', flags=0x10, proto='tcp', off=0, short=False):
    if proto == 'tcp': l4 = tcp(flags, b'' if short else b'dddddd'); p = 6
    elif proto == 'udp': l4 = udp(); p = 17
    else:
        l4 = b'abcdefghijklmnop'; p = 253   # experimental protocol number
    return ETH4 + ip4(p, l4, off) + trailer

def f6(trailer=b'', flags=0x10, proto='tcp'):
    l4 = tcp(flags) if proto == 'tcp' else udp(v6=True)
    return ETH6 + ip6(6 if proto == 'tcp' else 17, l4) + trailer

# ---- old format trailers -------------------------------------------------
def hdr(t, total, ver): return bytes([t, total - 2, ver])
def vip16(s=b''): return s.ljust(16, b'\0')
SYN = 0x02; ACK = 0x10

def low0_22(ing, slot, tmm, vip=b'vs_http'):
    return hdr(1, 22, 0) + bytes([ing, slot, tmm]) + vip16(vip)
def low0_35(ing, slot, tmm, flow, peer, cf, ft, vip=b'vs_flow'):
    return hdr(1, 35, 0) + bytes([ing, slot, tmm]) + struct.pack('>IIIB', flow, peer, cf, ft) + vip16(vip)
def low1(ing, slot, tmm, name=b'vs_https'):
    return hdr(1, 7 + len(name), 1) + bytes([ing, slot, tmm, len(name)]) + name
def med0_8(ha=1, rsv=0): return hdr(2, 8, 0) + bytes([ha]) + struct.pack('>I', rsv)
def med0_21(flow, peer, cf, ft, ha=1):
    return hdr(2, 21, 0) + struct.pack('>IIIBB', flow, peer, cf, ft, ha) + b'\0' * 4
def rst(text=b'', ver=0, peer=0, val=0x123456789abc, line=77):
    if ver == 0:
        b = bytes([peer & 1]) + struct.pack('>Q', (val << 16) | line)[0:8] + text
    else:
        b = bytes([(ver << 1) | (peer & 1)]) + b'\x11' * 8 + text
    return bytes([len(b)]) + b
def med_n(ver, flow, peer, cf, ft, ha, rc, cf2=0x01020304, prio=5):
    # ver 1: 29 + rstlen byte; ver 2 adds priority; ver 3 adds flags2
    body = struct.pack('>QQ', flow, peer)
    if ver >= 3: body += struct.pack('>I', cf2)
    body += struct.pack('>IBB', cf, ft, ha) + b'\0' * 4
    if ver >= 2: body += bytes([prio])
    body += rc if rc else b'\0'
    return hdr(2, 3 + len(body), ver) + body
def addr4(a): return b'\0' * 10 + b'\xff\xff' + bytes(a)
def addr_rd(rd, a): return bytes.fromhex('2620 0000 0c10 f501 0000'.replace(' ', '')) + struct.pack('>H', rd) + bytes(a)
ADDR6 = bytes.fromhex('20010db8000000000000000000000099')
def high_body(ipp, vlan, rem, loc, rp, lp): return bytes([ipp]) + struct.pack('>H', vlan) + rem + loc + struct.pack('>HH', rp, lp)
def high0(ipp=6, vlan=100, rem=None, loc=None, rp=443, lp=50000):
    return hdr(3, 42, 0) + high_body(ipp, vlan, rem or addr4([10, 1, 1, 1]), loc or addr4([10, 1, 1, 2]), rp, lp)
def high0_raw(body39): return hdr(3, 42, 0) + body39

# ---- new format (DPT) ----------------------------------------------------
def tlv(prov, typ, ver, body): return struct.pack('>HHHH', prov, typ, 8 + len(body), ver) + body
def dpt(tlvs, ver=1, ln=None):
    b = b''.join(tlvs)
    return struct.pack('>IHH', 0xf5deb0f5, 12 - 4 + len(b) - 4 + 4 if ln is None else ln, ver) + b
def dptl(tlvs, ver=1):
    b = b''.join(tlvs); return struct.pack('>IHH', 0xf5deb0f5, 8 + len(b), ver) + b
def nlow2(ing, slot, tmm, name): return tlv(1, 1, 2, bytes([ing, slot, tmm, len(name)]) + name)
def nlow3(fl, slot, tmm, name): return tlv(1, 1, 3, bytes([fl, slot, tmm, len(name)]) + name)
def objs(*items):
    b = b''.join(bytes([t, len(s)]) + s for t, s in items); return bytes([len(b)]) + b
def nlow4(fl, slot, tmm, objb): return tlv(1, 1, 4, bytes([fl, slot, tmm]) + objb)
def nmed4(flow, peer, cf2, cf, ft, ha, rc, prio=3):
    return tlv(1, 2, 4, struct.pack('>QQIIBB', flow, peer, cf2, cf, ft, ha) + b'\0' * 4 + bytes([prio]) + (rc if rc else b'\0'))
def nhigh1(ipp, vlan, rem, loc, rp, lp): return tlv(1, 3, 1, high_body(ipp, vlan, rem, loc, rp, lp))

# ---- fileinfo ------------------------------------------------------------
FIMAGIC = b'\0' * 12 + b'\x05\xff' + b'F5-Pseudo-pkt\0'
def fileinfo(objs_):
    return FIMAGIC + b''.join(o + b'\0' for o in objs_)

# ---- files ---------------------------------------------------------------
def pcapng(path, frames):
    """frames: bytes (Ethernet, if 0), ('x', bytes) Exported PDU (if 1),
    ('c', bytes, caplen) Ethernet truncated to caplen."""
    def blk(t, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += blk(1, struct.pack('<HHI', 1, 0, 65535))
    out += blk(1, struct.pack('<HHI', 252, 0, 65535))
    for i, fr in enumerate(frames):
        ifid, cap, orig = 0, None, None
        if isinstance(fr, tuple):
            if fr[0] == 'x': ifid, d = 1, fr[1]; cap = orig = len(d)
            else: d = fr[1][:fr[2]]; cap = fr[2]; orig = len(fr[1])
        else:
            d = fr; cap = orig = len(d)
        ts = 1700000000 * 10**6 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, cap, orig) + d)
    open(path, 'wb').write(out)

def tag(t, v): return struct.pack('>HH', t, len(v)) + v + b'\0' * (-len(v) % 4)
def xpdu(name, payload): return ('x', tag(12, name.encode()) + struct.pack('>HH', 0, 0) + payload)

def main(out):
    verbose = '-v' in sys.argv
    ok = []
    notes = []
    def add(fr, note=None):
        ok.append(fr)
        if note: notes.append((len(ok), note))
    FI = [b'CMD: tcpdump -i 0.0:nnn -s0 -w /var/tmp/x.pcap', b'VER: BIG-IP 13.1.3.4 0.0.5',
          b'HOST: bigip1.example.com', b'PLAT: C115', b'PROD: BIG-IP', b'SESS: 1a2b3c', b'XXX: ignored']
    add(fileinfo(FI), 'FILEINFO')
    n = len(ok)
    # --- old format single trailers
    add(f4(low0_22(1, 0, 2)), 'low v0 22 in')
    add(f4(low0_22(0, 1, 3, b'')), 'low v0 22 out, empty vip name')
    add(f4(low0_35(1, 2, 4, 0x1000, 0x2000, 0xdeadbeef, 3)), 'low v0 35 in with flows')
    add(f4(low0_35(0, 0, 1, 0, 0, 0, 0, b'')), 'low v0 35 out, no flows, no vip')
    add(f4(low1(1, 0, 5)), 'low v1 in'); add(f4(low1(0, 1, 6, b'')), 'low v1 out, no vip')
    add(f4(low1(1, 1, 7, b'a' * 100)), 'low v1 long vip name')
    add(f4(med0_8()), 'med v0 8'); add(f4(med0_21(5, 6, 7, 1)), 'med v0 21 (32-bit flows)')
    # med v0 29: the layout is v1 minus the rst length byte
    add(f4(hdr(2, 29, 0) + struct.pack('>QQIBB', 0x100, 0x200, 5, 1, 2) + b'\0' * 4), 'med v0 29 (64-bit flows)')
    add(f4(med_n(1, 0x100, 0x200, 5, 1, 1, b'')), 'med v1, no rst cause')
    add(f4(med_n(1, 0x100, 0x200, 5, 1, 1, rst(b'no route to host'))), 'med v1, rst cause v0')
    add(f4(med_n(1, 0x100, 0x200, 5, 1, 1, rst(b'peer reset', peer=1))), 'med v1, rst cause v0 peer')
    add(f4(med_n(1, 0x100, 0x200, 5, 1, 1, rst(b'zzzz', ver=3, peer=1))), 'med v1, rst cause other version')
    add(f4(med_n(2, 0x100, 0x200, 5, 1, 1, b'')), 'med v2, no rst cause')
    add(f4(med_n(2, 0x100, 0x200, 5, 1, 1, rst(b'tcp ack timeout'))), 'med v2, rst cause')
    add(f4(med_n(3, 0x100, 0x200, 5, 1, 1, b'')), 'med v3, no rst cause')
    add(f4(med_n(3, 0x100, 0x200, 5, 1, 1, rst(b'v3 reset', peer=1))), 'med v3, rst cause peer')
    add(f4(med_n(3, 0x100, 0x200, 5, 1, 1, rst(b'', ver=0))), 'med v3, rst cause 9 octets, no text')
    add(f4(high0()), 'high v0 alone, no peer flow (nopeer)')
    # --- combinations
    L = low1(1, 0, 3)
    add(f4(L + med_n(3, 0x300, 0x400, 5, 1, 1, rst(b'combo')) + high0()), 'low v1 + med v3 + high: IPv4-as-IPv6 addresses, TCP')
    add(f4(low1(0, 1, 2) + med_n(2, 0x300, 0x400, 5, 1, 1, b'') + high0(17, 200, addr_rd(5, [10, 2, 2, 1]), addr_rd(6, [10, 2, 2, 2]), 53, 5353), proto='udp'),
        'low v1 + med v2 + high: route-domain addresses, UDP')
    add(f4(low1(1, 0, 2) + med_n(1, 0x300, 0x400, 5, 1, 1, b'') + high0(0, 0, addr4([10, 3, 3, 1]), addr4([10, 3, 3, 2]), 1, 2)), 'ip proto 0 in TCP frame')
    add(f4(low1(1, 0, 2) + med_n(1, 0x300, 0x400, 5, 1, 1, b'') + high0(0, 0, addr4([10, 3, 3, 1]), addr4([10, 3, 3, 2]), 1, 2), proto='udp'), 'ip proto 0 in UDP frame')
    add(f4(low1(1, 0, 2) + med_n(1, 0x300, 0x400, 5, 1, 1, b'') + high0(1, 0, ADDR6, ADDR6, 0, 0), proto='icmp'), 'high with IPv6 addresses, IP protocol 253')
    add(f4(low0_22(1, 3, 3) + med0_21(1, 2, 3, 4) + high0()), 'low v0 22 + med v0 21 + high')
    add(f4(low0_35(0, 4, 5, 9, 10, 1, 1) + med0_8() + high0()), 'low v0 35 + med v0 8 + high nopeer')
    add(f6(low1(1, 0, 3) + med_n(3, 5, 6, 0, 0, 0, b'') + high0(6, 0, ADDR6, ADDR6, 80, 81)), 'IPv6 TCP, old format')
    add(f6(low1(0, 0, 3), proto='udp'), 'IPv6 UDP')
    # --- padding, non-F5 and bail-out cases
    add(f4(b'\0' * 12 + low1(1, 0, 3)), 'zero padding before a low v1 trailer')
    add(f4(b'\0' * 4 + low1(1, 0, 3), short=True), 'short frame: Ethernet strips the zero padding, low v1 trailer')
    add(f4(b'\x11' * 20), 'not an F5 trailer')
    add(f4(b'\x11' * 5 + low1(1, 0, 3)), 'non-zero padding before the trailer (needs pref_walk_trailer)')
    add(f4(low1(1, 0, 3) + bytes([9, 20, 0]) + b'\x01' * 20), 'old trailer followed by unknown type')
    add(f4(low1(1, 0, 3) + bytes([1, 200, 1]) + b'\x01' * 10), 'old trailer followed by a too long one')
    add(f4(bytes([1, 12, 3]) + b'\x01' * 12), 'low ver 3 not understood')
    add(f4(hdr(2, 10, 0) + b'\x01' * 7), 'med v0 with length 10')
    add(f4(hdr(3, 42, 1) + b'\x01' * 39), 'high ver 1 (old format)')
    add(f4(hdr(2, 40, 1) + b'\x01' * 37), 'med v1 length mismatch')
    add(f4(hdr(1, 25, 0) + b'\x01' * 22), 'low v0 length mismatch')
    add(f4(hdr(1, 7, 1) + bytes([1, 0, 3, 5])), 'low v1 vip length mismatch')
    add(f4(hdr(2, 12, 1) + b'\x01' * 9), 'med v1 shorter than the minimum')
    add(f4(hdr(2, 13, 2) + b'\x01' * 10), 'med v2 shorter than the minimum')
    add(f4(hdr(2, 14, 3) + b'\x01' * 11), 'med v3 shorter than the minimum')
    add(f4(hdr(2, 50, 2) + b'\x01' * 47), 'med v2 length mismatch')
    add(f4(hdr(2, 50, 3) + b'\x01' * 47), 'med v3 length mismatch')
    add(f4(low1(1, 0, 3, b'') + med_n(3, 0x700, 0x800, 0, 0, 0, b'')), 'no virtual server name but a flow (statistics)')
    add(f4(low1(1, 0, 3, b'') + med_n(3, 0, 0, 0, 0, 0, b'')), 'no virtual server name and no flow')
    add(f4(low0_35(0, 1, 2, 7, 8, 0, 0, b'')), 'low v0 35 with flows and no virtual server name')
    add(f4(struct.pack('>IHH', 0xf5deb0f5, 0xffff, 1) + nlow2(1, 0, 2, b'vs')), 'DPT magic with a length past the end (not dissected)')
    add(f4(b'\xaa\xbb\xcc\xdd' + struct.pack('>IHH', 0xf5deb0f5, 0xffff, 1) + nlow2(1, 0, 2, b'vs')), 'FCS then DPT magic with a length past the end (not dissected)')
    # reproducers of the fixes
    add(f4(b'\0' * 10 + b'\x11' * 7, proto='udp'), 'REPRO heuristic short remainder (7 octets after zeros)')
    add(f4(b'\0' * 10 + b'\x11' * 8, proto='udp'), 'control, 8 octets')
    add(f4(med_n(1, 0, 0, 0, 0, 0, bytes([1, 0])), proto='udp'), 'REPRO rst cause length 1 (old v1)')
    add(f4(med_n(1, 0, 0, 0, 0, 0, bytes([8]) + bytes([0] + [1] * 7)), proto='udp'), 'REPRO rst cause length 8 (old v1)')
    add(f4(med_n(2, 0, 0, 0, 0, 0, bytes([4]) + b'\0' * 4)), 'rst cause length 4 (old v2)')
    add(f4(med_n(3, 0, 0, 0, 0, 0, bytes([2]) + b'\0' * 2)), 'rst cause length 2 (old v3)')
    add(f4(med_n(3, 0, 0, 0, 0, 0, bytes([200]) + b'\x01' * 200)), 'rst cause length 200 (v3, unsigned)')
    # --- DPT
    add(f4(dptl([nlow2(1, 0, 2, b'vs_dpt2')])), 'DPT low v2 ingress')
    add(f4(dptl([nlow2(0, 1, 3, b'')])), 'DPT low v2 egress, empty vip')
    add(f4(dptl([nlow3(0x01, 0, 2, b'vs_dpt3')])), 'DPT low v3 ingress flag')
    add(f4(dptl([nlow3(0x04, 2, 4, b'vs_dpt3')])), 'DPT low v3 hwaction flags')
    add(f4(dptl([nlow4(0x01, 0, 2, objs((0, b'vs_dpt4'), (1, b'1.1'), (2, b'trk1')))])), 'DPT low v4: virtual server, port, trunk')
    add(f4(dptl([nlow4(0x00, 1, 2, objs((0, b''), (1, b'2.1')))])), 'DPT low v4: empty virtual server name')
    add(f4(dptl([nlow4(0x01, 0, 2, objs((7, b'unk'), (0, b'vs_after')))])), 'DPT low v4: unknown object type (undecoded note)')
    add(f4(dptl([nlow4(0x01, 0, 2, bytes([0]))])), 'DPT low v4: no objects')
    add(f4(dptl([nlow4(0x01, 0, 2, objs((0, b'vs_a'), (0, b'vs_b')))])), 'DPT low v4: two virtual servers')
    N = dptl([nlow4(0x01, 0, 2, objs((0, b'vs_full'))), nmed4(0x500, 0x600, 1, 2, 3, 1, rst(b'dpt reset')),
              nhigh1(6, 10, addr4([10, 9, 9, 1]), addr4([10, 9, 9, 2]), 8080, 8081)])
    add(f4(N), 'DPT low v4 + med v4 (rst cause) + high v1 with peer')
    add(f4(dptl([nlow3(0x01, 0, 2, b'vs'), nmed4(0x500, 0x600, 1, 2, 3, 1, rst(b'peer rst', peer=1)), nhigh1(17, 10, addr_rd(1, [10, 8, 8, 1]), addr_rd(2, [10, 8, 8, 2]), 53, 54)]), proto='udp'), 'DPT low v3 + med v4 (peer rst) + high v1, route domains, UDP')
    add(f4(dptl([nlow2(1, 0, 2, b'vs'), nmed4(0x500, 0, 1, 2, 3, 1, b''), nhigh1(0, 0, ADDR6, ADDR6, 1, 2)])), 'DPT med v4 without rst and no peer flow: high nopeer')
    add(f4(dptl([nlow2(1, 0, 2, b'vs'), nmed4(0x500, 0x600, 1, 2, 3, 1, rst(b'', ver=5)), nhigh1(0, 0, addr4([1, 2, 3, 4]), addr4([5, 6, 7, 8]), 1, 2)])), 'DPT med v4, rst cause other version; high ipproto 0')
    add(f4(dptl([nlow2(1, 0, 2, b'vs'), nmed4(0x500, 0x600, 1, 2, 3, 1, b''), nhigh1(0, 0, addr4([1, 2, 3, 4]), addr4([5, 6, 7, 8]), 1, 2)])), 'DPT three TLVs, no rst')
    D = dptl([nlow3(1, 1, 5, b'vs_fcs'), nmed4(0x1, 0x2, 0, 0, 0, 0, b'')])
    add(f4(b'\xaa\xbb\xcc\xdd' + D), 'original FCS before the DPT trailer')
    add(f4(b'\x00\x00\xcc\xdd' + D), 'FCS starting with two zero octets')
    add(f4(b'\x00\x00\x00\xdd' + D), 'FCS starting with three zero octets')
    add(f4(dptl([tlv(1, 1, 2, bytes([1, 0, 2, 0]))], ver=2)), 'DPT unknown version 2')
    add(f4(dptl([tlv(9, 1, 0, b'\x01\x02\x03'), nlow2(1, 0, 2, b'vs')])), 'DPT unknown provider, then noise')
    add(f4(dptl([tlv(1, 1, 9, b'\x01\x02\x03\x04')])), 'DPT noise with unknown type/version')
    add(f4(dptl([tlv(1, 7, 1, b'')])), 'DPT noise with unknown type 7, no data')
    add(f4(dptl([nlow2(1, 0, 2, b'vs')]) + b'\x01\x02\x03'), 'DPT with trailing octets past the TLVs (less than a TLV header)')
    add(f4(struct.pack('>IHH', 0xf5deb0f5, 0, 1) + nlow2(1, 0, 2, b'vs')), 'DPT with length 0 (fix: use all data)')
    add(f4(struct.pack('>IHH', 0xf5deb0f5, 4, 1) + nlow2(1, 0, 2, b'vs')), 'DPT with length 4 (fix: use all data)')
    # TLS provider: only the types without secrets
    add(f4(dptl([nlow2(1, 0, 2, b'vs'), tlv(4, 1, 0, bytes(range(16)))])), 'DPT TLS extended type 1')
    add(f4(dptl([tlv(4, 3, 0, b'\x01\x02\x03\x04\x05')])), 'DPT TLS extended type 3')
    add(f4(dptl([tlv(4, 2, 0, b'\x00')])), 'DPT TLS type 2 v0 with secret length 0 (no secrets)')
    add(f4(dptl([tlv(4, 2, 1, b'\x00')])), 'DPT TLS type 2 v1 with secret length 0')
    add(f4(dptl([tlv(4, 5, 0, b'\x01\x02')])), 'DPT TLS unknown type')
    # --- IP variants and analysis
    add(f4(low1(1, 0, 3) + med_n(3, 0x700, 0x800, 0, 0, 0, b''), flags=SYN), 'ingress SYN with a flow (flow reuse analysis)')
    add(f4(low1(1, 0, 3) + med_n(3, 0, 0, 0, 0, 0, b''), flags=ACK), 'ingress ACK without flow (flow lost analysis)')
    add(f4(low1(0, 0, 3) + med_n(3, 0x700, 0x800, 0, 0, 0, b''), flags=ACK), 'egress ACK')
    add(f4(dptl([nlow3(1, 0, 3, b'vs'), nmed4(0x900, 0, 0, 0, 0, 0, b'')]), flags=SYN), 'DPT ingress SYN with a flow')
    add(f4(dptl([nlow3(1, 0, 3, b'vs'), nmed4(0, 0, 0, 0, 0, 0, b'')]), flags=ACK), 'DPT ingress ACK without flow')
    add(f4(dptl([nlow3(1, 0, 3, b'vs'), nmed4(0, 0, 0, 0, 0, 0, b'')]), flags=0x12), 'DPT ingress SYN+ACK without flow')
    add(f6(dptl([nlow3(1, 0, 3, b'vs'), nmed4(0, 0, 0, 0, 0, 0, b'')]), flags=ACK), 'IPv6 TCP DPT ingress ACK without flow')
    add(f6(dptl([nlow3(1, 0, 3, b'vs'), nmed4(0x1, 0, 0, 0, 0, 0, b'')]), flags=SYN), 'IPv6 TCP DPT ingress SYN with flow')
    add(f6(dptl([nlow3(0, 0, 3, b'vs')]), proto='udp'), 'IPv6 UDP DPT')
    add(f4(low1(1, 0, 3) + med_n(3, 0x700, 0x800, 0, 0, 0, b''), flags=SYN, proto='icmp'), 'IP protocol 253 (not TCP)')
    add(f4(low1(1, 0, 3) + med_n(3, 0x700, 0x800, 0, 0, 0, b''), flags=SYN, off=0x2000), 'first IPv4 fragment of TCP (MF set)')
    add(f4(low1(1, 0, 3) + med_n(3, 0x700, 0x800, 0, 0, 0, b''), flags=SYN, off=0x0010), 'later IPv4 fragment')
    add(f4(low1(1, 0, 3) + med_n(3, 0, 0, 0, 0, 0, b''), flags=ACK, off=0x2000), 'ingress ACK fragment without flow')
    # snaplen-truncated frame: trailer not complete, so not dissected
    add(('c', f4(low1(1, 0, 3)), len(f4(low1(1, 0, 3))) - 3), 'truncated capture (caplen < len)')
    # Exported PDU reproducers: noise dissector called with no data
    add(xpdu('f5ethtrailer.noise', tlv(1, 1, 2, b'\x01\x00\x00\x03abc')), 'REPRO exported PDU noise low v2')
    add(xpdu('f5ethtrailer.noise', tlv(1, 2, 4, b'\0' * 40)), 'REPRO exported PDU noise med v4')
    add(xpdu('f5ethtrailer.noise', tlv(1, 3, 1, b'\0' * 40)), 'REPRO exported PDU noise high v1')
    pcapng(os.path.join(out, 'f5ethtrailer-coverage.pcapng'), ok)
    if verbose:
        for i, t in notes: print(i, t)
        print(len(ok), 'frames')

    # ---- malformed
    m = []
    m.append(f4(dptl([tlv(1, 1, 2, b'')])[:-8] + struct.pack('>HHHH', 1, 1, 4, 2)))  # TLV length < header
    m.append(f4(dptl([struct.pack('>HHHH', 1, 1, 200, 2) + b'\0' * 8])))              # TLV past the end
    m.append(f4(dptl([tlv(1, 1, 2, bytes([1, 0, 2, 30]) + b'abc')])))  # vip name too long
    m.append(f4(dptl([nlow4(1, 0, 2, bytes([50]) + b'\x00\x03abc')])))                # data_len past the end
    m.append(f4(dptl([nlow4(1, 0, 2, bytes([6, 0, 40]) + b'abc' + b'\0')])))          # object length past the data
    m.append(f4(dptl([nlow4(1, 0, 2, bytes([4, 5, 40]) + b'ab')])))                   # unknown object with bad length
    m.append(f4(dptl([nlow4(1, 0, 2, bytes([4, 1, 40]) + b'ab'), ])))                 # port with bad length
    m.append(f4(dptl([nlow4(1, 0, 2, bytes([4, 2, 40]) + b'ab'), ])))                 # trunk with bad length
    for rl in (1, 5, 8, 100):                                                          # med v4 invalid rst length
        m.append(f4(dptl([nlow2(1, 0, 2, b'v'), tlv(1, 2, 4, struct.pack('>QQIIBB', 1, 2, 0, 0, 0, 0) + b'\0' * 4 + bytes([3, rl]) + b'\0' * 3)])))
    m.append(f4(dptl([tlv(4, 2, 0, bytes([200]) + b'\0' * 20)])))                      # TLS secret length > 64
    m.append(f4(dptl([tlv(4, 2, 1, bytes([65]) + b'\0' * 20)])))
    m.append(f4(dptl([tlv(1, 1, 2, b'\x01')])[:] ))                                    # TLV truncated inside low v2
    m.append(f4(dptl([nlow2(1, 0, 2, b'ab')]) + b''))                                 # (clean control)
    # exported PDU with the TLS dissector and a short TLV
    m.append(xpdu('f5ethtrailer.tls', tlv(4, 1, 0, b'\x01\x02\x03')))
    m.append(xpdu('f5ethtrailer.noise', tlv(1, 1, 9, b'\0' * 10)))
    m.append(xpdu('f5ethtrailer.noise', tlv(1, 1, 3, b'\x01\x00')))
    m.append(xpdu('f5ethtrailer.noise', b'\x00\x01'))
    pcapng(os.path.join(out, 'f5ethtrailer-coverage-malformed.pcapng'), m)

    # ---- FILEINFO variants: the first frame, then a few trailer frames
    tail = [f4(low1(1, 0, 3)), f4(low1(0, 1, 4)), f4(low0_22(1, 0, 2)), f4(dptl([nlow3(1, 0, 3, b'vs')]))]
    for name, objs_ in (('z101', [b'CMD: tcpdump', b'VER: 11.6', b'PLAT: Z101']),
                        ('unk', [b'PLAT: Q999', b'SESS: s']),
                        ('noplat', [b'HOST: h']),
                        ('empty', [])):
        pcapng(os.path.join(out, 'f5ethtrailer-fi-%s.pcapng' % name), [fileinfo(objs_)] + tail)
    # frame 1 with only part of the magic: not FILEINFO
    pcapng(os.path.join(out, 'f5ethtrailer-fi-nomagic.pcapng'), [FIMAGIC[:20]] + tail)

if __name__ == '__main__':
    main(sys.argv[1])
