#!/usr/bin/env python3
# Generates test/captures/eth_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic Ethernet (packet-eth.c) coverage captures.
Usage: mketh.py <outdir> [-v]   (writes eth-coverage.pcapng, eth-coverage-malformed.pcapng,
eth-coverage.erf).  Everything is generated; addresses are from 192.0.2.0/24 and
locally administered / documentation MACs."""
import struct
import sys
import zlib

# ------------------------------------------------------------ file writers
LT_ETH, LT_CHDLC, LT_SLL, LT_NFLOG = 1, 104, 113, 239

def pcapng(path, ifaces, frames):
    """ifaces: list of (linktype, fcslen or None). frames: (ifc, data, orig_len)"""
    def block(bt, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return struct.pack('<II', bt, ln) + body + struct.pack('<I', ln)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt, fl in ifaces:
        opts = b''
        if fl is not None:
            opts = struct.pack('<HH', 13, 1) + bytes([fl, 0, 0, 0]) + struct.pack('<HH', 0, 0)
        out += block(1, struct.pack('<HHI', lt, 0, 262144) + opts)
    t0 = 1700000000 * 1000000
    for i, (ifc, data, orig) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                    len(data), orig) + data)
    open(path, 'wb').write(out)

def erf(path, recs):
    """recs: (erf type, payload). ERF type 2 = Ethernet (2 pad bytes first)."""
    out = b''
    for i, (t, flags, data) in enumerate(recs):
        body = b'\0\0' + data
        body += b'\0' * (-(16 + len(body)) % 8)
        rlen = 16 + len(body)
        ts = ((1700000000 + i) << 32)
        out += struct.pack('<Q', ts) + struct.pack('>BBHHH', t, flags, rlen, 0, len(data) + 2) + body
    open(path, 'wb').write(out)

# ----------------------------------------------------------------- helpers
def mac(x): return bytes([2, 0, 0, 0, 0, x])
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff
def ipv4(src, dst, payload=b'', proto=253):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                    bytes(src), bytes(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload
def udp(sp, dp, payload):
    return struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
def fcs(b): return struct.pack('<I', zlib.crc32(b) & 0xffffffff)
A = [192, 0, 2, 1]; B = [192, 0, 2, 2]
def ip(n=26, proto=253, src=A, dst=B): return ipv4(src, dst, bytes((i * 7 + 1) & 0xff for i in range(n)), proto)
def eth2(dst, src, et, payload): return dst + src + struct.pack('!H', et) + payload
def e802(dst, src, payload): return dst + src + struct.pack('!H', len(payload)) + payload
def pad(b, n=60): return b + b'\0' * max(0, n - len(b))
def stp():
    return (b'\x42\x42\x03' + struct.pack('!HBBB', 0, 0, 0, 0) + bytes([0x80, 0, 2, 0, 0, 0, 0, 1])
            + struct.pack('!I', 0) + bytes([0x80, 0, 2, 0, 0, 0, 0, 1]) + struct.pack('!HHHHH', 0x8001, 0, 0x1400, 0x200, 0x0f00))
def prp1(seq, lan, size): return struct.pack('!HHH', seq, (lan << 12) | size, 0x88fb)
def prp0(seq, lan, size): return struct.pack('!HH', seq, (lan << 12) | size)
def ixia(orig=64):
    tlv = struct.pack('!BBH', 1, 2, orig)      # original packet size
    body = tlv + bytes([len(tlv)]) + b'\xaf\x12'
    return body + struct.pack('!H', csum(body))
GARB = bytes([0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])

def ipx(n=8):
    return (struct.pack('!HHBB', 0xffff, 30 + n, 0, 0) + struct.pack('!I', 1) + mac(2) + struct.pack('!H', 0x4000)
            + struct.pack('!I', 1) + mac(1) + struct.pack('!H', 0x4001) + bytes(range(n)))

def isl_frame(inner):
    h = bytes([0x01, 0x00, 0x0c, 0x00, 0x00, 0x00]) + mac(9) + struct.pack('!H', len(inner) + 16)
    h += bytes([0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c]) + struct.pack('!HHH', 100 << 1, 0, 0)
    return h + inner + fcs(inner) + b'\xde\xad\xbe\xef'

def sflow(inner):
    hdr = struct.pack('!IIII', 1, len(inner) + 4, 0, len(inner))
    # raw packet header record: tag 1, length, protocol 1, frame_length, stripped, header_length
    body = struct.pack('!IIIII', 1, 16 + len(inner) + (-len(inner) % 4), 1, len(inner), 0) + struct.pack('!I', len(inner))
    body += inner + b'\0' * (-len(inner) % 4)
    samp = struct.pack('!IIIIIIII', 7, 0x00000001, 1000, 100, 0, 1, 2, 1) + body
    dg = struct.pack('!II4sIIII', 5, 1, bytes([192, 0, 2, 9]), 0, 1, 5000, 1)
    dg += struct.pack('!II', 1, len(samp)) + samp
    return dg

def nsh(inner):
    return bytes([0x00, 0x02, 0x02, 0x03]) + struct.pack('!I', (7 << 8) | 255) + inner

# ----------------------------------------------------------------- captures
class Cap:
    def __init__(s): s.f = []; s.marks = []
    def add(s, label, ifc, data, orig=None):
        s.f.append((ifc, data, len(data) if orig is None else orig))
        s.marks.append((len(s.f), label))

def main_capture():
    c = Cap()
    IFH, IFF, IFN, IFS, IFC, IFL = 0, 1, 2, 3, 4, 5   # heuristic / FCS 4 / FCS 0 / SLL / CHDLC / NFLOG
    D, S = mac(2), mac(1)
    def ii(n=26, **kw): return eth2(D, S, 0x0800, ip(n, **kw))
    # --- Ethernet II basics (IF0: FCS unknown -> heuristic)
    c.add('Ethernet II IPv4, 64 octets, no trailer', IFH, ii(30))
    c.add('known OUIs, resolved names', IFH, eth2(bytes.fromhex('0000 0c01 0203'.replace(' ', '')), bytes.fromhex('0050 5601 0203'.replace(' ', '')), 0x0800, ip(30)))
    c.add('broadcast destination', IFH, eth2(b'\xff' * 6, S, 0x0800, ip(30)))
    c.add('multicast destination, locally administered source', IFH, eth2(bytes.fromhex('01005e000001'), bytes.fromhex('020000000009'), 0x0800, ip(30)))
    c.add('source is a group address (expert warning)', IFH, eth2(D, bytes.fromhex('010203040506'), 0x0800, ip(30)))
    c.add('Ethernet II ethertype 0 (Vegas)', IFH, eth2(D, S, 0, bytes(range(46))))
    c.add('ethertype with no dissector', IFH, eth2(D, S, 0x88b5, bytes(range(46))))
    c.add('VLAN tagged IPv4 (payload offset 18)', IFH, eth2(D, S, 0x8100, struct.pack('!HH', 5, 0x0800) + ip(30)))
    # --- padding (default padding: zeros)
    c.add('zero padding 60 octets', IFH, pad(ii(6)))
    c.add('padding zeros then PRP-1 trailer', IFH, eth2(D, S, 0x0800, ip(4)) + b'\0' * 16 + prp1(0x1234, 0xa, 46))
    c.add('padding zeros then PRP-0 trailer', IFH, eth2(D, S, 0x0800, ip(4)) + b'\0' * 18 + prp0(0x1234, 0xb, 46))
    c.add('no zero padding, undecoded trailer (expert note)', IFH, eth2(D, S, 0x0800, ip(4)) + (GARB * 3)[:22])
    c.add('zero padding then undecoded trailer', IFH, eth2(D, S, 0x0800, ip(4)) + b'\0' * 12 + GARB[:10])
    c.add('trailer on a frame of exactly 60 octets, all zero (padding only)', IFH, pad(ii(0)))
    c.add('trailer on a frame over 64: FCS guessed + trailer', IFH, ii(46) + GARB[:4] + fcs(ii(46) + GARB[:4]))
    c.add('frame over 64, trailer shorter than FCS', IFH, ii(46) + b'\x01\x02\x03')
    c.add('Ixia trailer', IFH, eth2(D, S, 0x0800, ip(12)) + ixia(64) + b'\0' * 0)
    c.add('Ixia trailer after padding', IFH, eth2(D, S, 0x0800, ip(4)) + b'\0' * 13 + ixia(60))
    c.add('PRP-1 trailer on a long frame with guessed FCS', IFH, (lambda f: f + fcs(f))(eth2(D, S, 0x0800, ip(46)) + prp1(7, 0xa, 66)))
    # --- 802.3 / LLC
    stpf = e802(bytes.fromhex('0180c2000000'), S, stp())
    c.add('802.3 LLC STP BPDU, padded', IFH, pad(stpf))
    c.add('802.3 LLC STP BPDU, non-zero trailer', IFH, stpf + GARB[:10])
    c.add('802.3 LLC SNAP IPv4', IFH, e802(D, S, bytes([0xaa, 0xaa, 3, 0, 0, 0, 8, 0]) + ip(40)))
    c.add('802.3 LLC SNAP, trailer, FCS guessed', IFH, (lambda f: f + fcs(f))(e802(D, S, bytes([0xaa, 0xaa, 3, 0, 0, 0, 8, 0]) + ip(10)) + b'\0' * 50))
    c.add('802.3 raw IPX (0xffff)', IFH, pad(e802(D, S, ipx(10))))
    c.add('802.3 LLC with unknown SAPs', IFH, pad(e802(D, S, bytes([0x20, 0x22, 3]) + bytes(range(20)))))
    # CCSDS space packet inside 802.3 (decodes as LLC by default; length, version, header, bit preferences)
    cc = bytes([0x08, 0x01, 0xc0, 0x01]) + struct.pack('!H', 20 - 7) + bytes([0x12, 0x34, 0x56, 0x78, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee][:14])
    cc = cc[:20] if len(cc) >= 20 else cc + b'\0' * (20 - len(cc))
    c.add('802.3 carrying a CCSDS-looking payload (length 20)', IFH, pad(e802(D, S, cc)))
    c.add('invalid length/type 0x05ff (expert warning)', IFH, eth2(D, S, 0x05ff, bytes(range(46))))
    c.add('smallest valid Ethernet II type 0x0600', IFH, eth2(D, S, 0x0600, bytes(range(46))))
    c.add('invalid length/type 0x05dd', IFH, eth2(D, S, 0x05dd, bytes(range(46))))
    # --- ISL, TTE, FW-1, dedup
    inner = ii(30)
    c.add('Cisco ISL wrapping Ethernet', IFH, isl_frame(inner))
    c.add('Cisco ISL wrapping Ethernet (dst 0c:00:0c:00:00)', IFH, bytes([0x0c]) + isl_frame(inner)[1:])
    c.add('TTEthernet frame (heuristic, constant field 0x0fff)', IFH, bytes.fromhex('0fff00000001') + S + struct.pack('!H', 0x88d7) + bytes(range(46)))
    c.add('TTEthernet PCF frame', IFH, bytes.fromhex('0fff00000002') + S + struct.pack('!H', 0x891d) + bytes(range(46)))
    c.add('dst starts with "i" (FW-1 monitor look-alike)', IFH, eth2(b'iabcde', S, 0x0800, ip(30)))
    c.add('dst starts with "o"', IFH, eth2(b'o\x00\x00\x00\x00\x01', S, 0x0800, ip(30)))
    c.add('dst starts with "E"', IFH, eth2(b'E\x00\x00\x00\x00\x01', S, 0x0800, ip(30)))
    c.add('extra destination MAC prepended (FEX)', IFH, D + D + bytes.fromhex('88b500000001') + struct.pack('!H', 0x0800) + ip(30))
    # --- FCS known (IF1)
    def wf(f): return f + fcs(f)
    c.add('FCS, IPv4, 64 octets', IFF, wf(ii(26)))
    c.add('FCS, runt with zero padding (fix: FCS starts with 0x00)', IFF, ii(0) + b'\0' * 22 + b'\x00\x11\x22\x33')
    c.add('FCS, runt padding (fix: non-zero FCS)', IFF, ii(0) + b'\0' * 22 + b'\xaa\x11\x22\x33')
    c.add('FCS, 64 octets all-zero FCS', IFF, ii(0) + b'\0' * 26 + b'\0\0\0\0')
    c.add('FCS, valid padded frame', IFF, wf(pad(ii(6), 56)))
    c.add('FCS after padding and PRP-1 trailer', IFF, wf(eth2(D, S, 0x0800, ip(4)) + b'\0' * 12 + prp1(0x4321, 0xb, 46)))
    c.add('FCS and trailer on a long frame', IFF, wf(ii(80) + GARB[:6]))
    c.add('FCS, VLAN tag', IFF, wf(eth2(D, S, 0x8100, struct.pack('!HH', 5, 0x0800) + ip(46))))
    c.add('FCS, 802.3 LLC STP', IFF, wf(pad(stpf, 56)))
    c.add('FCS, 802.3 SNAP', IFF, wf(e802(D, S, bytes([0xaa, 0xaa, 3, 0, 0, 0, 8, 0]) + ip(40))))
    f = wf(ii(46)); c.add('FCS cut by the snap length (2 of 4 octets captured)', IFF, f[:-2], len(f))
    f = wf(ii(46)) + b''; c.add('FCS entirely cut off by the snap length', IFF, f[:-4], len(f))
    f = wf(eth2(D, S, 0x0800, ip(4)) + prp1(1, 0xa, 24) + GARB); c.add('FCS and trailer cut by the snap length', IFF, f[:-6], len(f))
    c.add('FCS, tvb of exactly 4 octets after the payload', IFF, wf(eth2(D, S, 0x0800, ip(26))))
    # --- no FCS (IF2)
    c.add('no FCS, 64 octets', IFN, ii(30))
    c.add('no FCS, trailer', IFN, ii(46) + GARB[:8])
    c.add('no FCS, padded, PRP-1 trailer', IFN, eth2(D, S, 0x0800, ip(4)) + b'\0' * 16 + prp1(0x1111, 0xa, 46))
    c.add('no FCS, 802.3 padded', IFN, pad(stpf))
    # --- padding "any" reproducer (also default prefs: a short frame)
    f = ii(26)[:0] + eth2(D, S, 0x0800, ipv4(A, B)) + b'\0' * 26
    c.add('snaplen reproducer: 60 octet frame captured as 40', IFH, f[:40], 60)
    # --- tap/conv: stale stream reproducer (frames 6 of that group is invalid length/type)
    def fr(s, d, et=0x0800): return eth2(mac(d), mac(s), et, ipv4([192, 0, 2, s], [192, 0, 2, d]) + b'\0' * 26)
    for s, d in ((1, 2), (3, 4), (5, 6), (7, 8), (1, 2)):
        c.add('stale tap stream: %d -> %d' % (s, d), IFH, fr(s, d))
    c.add('stale tap stream: invalid length/type 1 -> 2', IFH, fr(1, 2, 0x05ff))
    # --- encapsulated Ethernet
    inn = eth2(mac(4), mac(3), 0x0800, ip(30))
    c.add('ethertype 0x6558 bridging, Ethernet in Ethernet', IFH, eth2(D, S, 0x6558, inn))
    c.add('3 levels of Ethernet in Ethernet', IFH, eth2(D, S, 0x6558, eth2(mac(6), mac(5), 0x6558, inn)))
    gre = lambda proto, inner: ipv4(A, B, struct.pack('!HH', 0, proto) + inner, 47)
    c.add('GRE transparent Ethernet bridging', IFH, eth2(D, S, 0x0800, gre(0x6558, inn)))
    c.add('GRE MikroTik EoIP', IFH, eth2(D, S, 0x0800, gre(0x6400, inn)))
    c.add('IP protocol 143 (Ethernet), maybe FCS', IFH, eth2(D, S, 0x0800, ipv4(A, B, inn, 143)))
    c.add('IP protocol 143, longer than 64: FCS guessed', IFH, eth2(D, S, 0x0800, ipv4(A, B, (lambda g: g + fcs(g))(eth2(mac(4), mac(3), 0x0800, ip(60))), 143)))
    vx = struct.pack('!BBHI', 0x08, 0, 0, 100 << 8) + inn
    c.add('VXLAN', IFH, eth2(D, S, 0x0800, ipv4(A, B, udp(40000, 4789, vx), 17)))
    c.add('UDP 9999 Ethernet (Cisco CMTS; needs Decode As)', IFH, eth2(D, S, 0x0800, ipv4(A, B, udp(40000, 9999, inn), 17)))
    c.add('NSH Ethernet', IFH, eth2(D, S, 0x894f, nsh(inn)))
    c.add('sFlow raw header sample, Ethernet', IFH, eth2(D, S, 0x0800, ipv4(A, B, udp(40000, 6343, sflow(inn)), 17)))
    sll = struct.pack('!HHH8sH', 0, 1, 6, mac(1) + b'\0\0', 3) + inn
    c.add('Linux cooked SLL, protocol Ethernet', IFS, sll)
    c.add('Cisco HDLC, protocol 0x6558', IFC, bytes([0x0f, 0x00]) + struct.pack('!H', 0x6558) + inn)
    def tlv(t, v): return struct.pack('<HH', 4 + len(v), t) + v + b'\0' * (-len(v) % 4)
    nfl = bytes([2, 0, 0, 0]) + tlv(1, struct.pack('!HBB', 0x0800, 1, 0)) + tlv(16, eth2(D, S, 0x0800, b'')) + tlv(9, ip(20))
    c.add('NFLOG with a hardware header: Ethernet header only (eth_header)', IFL, nfl)
    c.add('802.3 CCSDS-looking payload with the spare bit set', IFH, pad(e802(D, S, cc[:12] + b'\x80' + cc[13:])))
    c.add('encapsulated header only: ethertype dissector for 0x6558 inside VLAN', IFH, eth2(D, S, 0x8100, struct.pack('!HH', 5, 0x6558) + inn))
    return c

def malformed_capture():
    c = Cap()
    IFH, IFF, IFN = 0, 1, 2
    D, S = mac(2), mac(1)
    def ii(n=26): return eth2(D, S, 0x0800, ip(n))
    def wf(f, bad=False): return f + (b'\x01\x02\x03\x04' if bad else fcs(f))
    c.add('802.3 carrying a 3 octet payload (CCSDS check runs out of data)', IFH, pad(e802(D, S, b'\x08\x01\xc0')))
    c.add('bad FCS (error with check_fcs)', IFF, wf(ii(26), True))
    c.add('good FCS', IFF, wf(ii(26)))
    c.add('802.3 length past the end of the frame', IFH, D + S + struct.pack('!H', 200) + bytes([0x42, 0x42, 3]) + bytes(20))
    c.add('802.3 length past the end, SNAP', IFH, pad(D + S + struct.pack('!H', 1400) + bytes([0xaa, 0xaa, 3, 0, 0, 0, 8, 0]) + ip(10)))
    c.add('13 octet frame (header cut short)', IFH, (D + S + b'\x08')[:13])
    c.add('14 octet frame, IPv4 with nothing', IFH, D + S + b'\x08\x00')
    c.add('6 octet frame', IFH, D)
    c.add('snaplen: header only, 802.3, 15 octets', IFH, (D + S + struct.pack('!H', 40) + b'\x42')[:15], 60)
    c.add('802.3 header + 1 octet with CCSDS-style length check', IFH, (D + S + struct.pack('!H', 10) + b'\x08'), 40)
    c.add('FCS interface, 3 octet frame body', IFF, D + S + b'\x08\x00' + b'\0\0\0')
    c.add('FCS interface, trailer shorter than FCS (3 octets)', IFF, eth2(D, S, 0x0800, ip(0)) + b'\x01\x02\x03')
    c.add('FCS interface, 802.3 frame with FCS and a length past the end', IFF, D + S + struct.pack('!H', 500) + bytes([0x42, 0x42, 3]) + bytes(40) + b'\0\0\0\0')
    c.add('padding any: runt 60 octets incl. FCS, non-zero padding', IFF, ii(0) + bytes(range(1, 23)) + b'\x00\x11\x22\x33')
    f = wf(ii(46)); c.add('FCS interface, snap cut inside the payload', IFF, f[:40], len(f))
    # nesting: 2000 Ethernet-in-Ethernet headers (ethertype depth limit)
    c.add('2000 nested Ethernet headers', IFH, b''.join(mac(1) + mac(2) + b'\x65\x58' for _ in range(2000)) + mac(1) + mac(2) + b'\x08\x00' + ip(0))
    c.add('FW-1 monitor look-alike with garbage', IFH, eth2(b'i\0\0\0\0\1', S, 0x0800, bytes(30)))
    c.add('dedup: extra dst MAC but truncated', IFH, D + D + bytes.fromhex('88b5'), 40)
    c.add('Exported/short: ISL header cut off', IFH, bytes([0x01, 0x00, 0x0c, 0x00, 0x00, 0x00]) + mac(9) + struct.pack('!H', 30) + bytes(8))
    c.add('ISL with Ethernet cut off', IFH, isl_frame(ii(30))[:50], len(isl_frame(ii(30))))
    c.add('ethertype 0x6558 with truncated inner header', IFH, eth2(D, S, 0x6558, mac(4) + mac(3)[:3]))
    c.add('TTE frame cut short', IFH, bytes.fromhex('0fff00000001') + S + b'\x88\xd7')
    return c

def erf_records():
    D, S = mac(2), mac(1)
    f = eth2(D, S, 0x0800, ip(30))
    return [(2, 0x00, f), (2, 0x00, f + fcs(f)), (2, 0x00, pad(eth2(D, S, 0x0800, ip(6)))),
            (11, 0x00, f), (16, 0x00, f), (20, 0x00, f)]

if __name__ == '__main__':
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    ifaces = [(LT_ETH, None), (LT_ETH, 4), (LT_ETH, 0), (LT_SLL, None), (LT_CHDLC, None), (LT_NFLOG, None)]
    m = main_capture()
    pcapng(out + '/eth-coverage.pcapng', ifaces, m.f)
    x = malformed_capture()
    pcapng(out + '/eth-coverage-malformed.pcapng', ifaces, x.f)
    erf(out + '/eth-coverage.erf', erf_records())
    if verbose:
        for n, l in m.marks: print('main', n, l)
        for n, l in x.marks: print('malformed', n, l)
