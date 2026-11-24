#!/usr/bin/env python3
# Generates test/captures/gquic_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the GQUIC coverage captures. Usage: mkgquic.py <outdir>"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from common import eth, ip4, pcap, udp
import random
from walker import walk

EM = bytes.fromhex('020000000002'), bytes.fromhex('020000000001')
CIP, SIP = '192.0.2.1', '192.0.2.2'

def dgram(cport, sport, payload, c2s=True):
    if c2s:
        u = udp(cport, sport, payload); s, d = CIP, SIP
        e = eth(EM[0], EM[1], 0x0800, ip4(s, d, 17, u))
    else:
        u = udp(sport, cport, payload)
        e = eth(EM[1], EM[0], 0x0800, ip4(SIP, CIP, 17, u))
    return e

def mk_ver_ctx(ver):
    """endianness for a version"""
    return '>' if ver >= 39 else '<'

# ---------------------------------------------------------------- tags
def tags(lst, tag=None):
    """lst: list of (4 byte name, value). Returns [msgtag] count pad headers values"""
    hdr = b''; data = b''; end = 0
    for n, v in lst:
        end += len(v); hdr += n + struct.pack('<I', end); data += v
    return (tag or b'') + struct.pack('<HH', len(lst), 0) + hdr + data

def scfg(lst):
    hdr = b''; data = b''; end = 0
    for n, v in lst:
        end += len(v); hdr += n + struct.pack('<I', end); data += v
    return b'SCFG' + struct.pack('<I', len(lst)) + hdr + data

def pubs(n=11): return struct.pack('<H', 0x2100) + bytes(range(1, 3 * n + 1))
NONC = bytes(range(32))
CADR4 = struct.pack('<H', 2) + bytes([192, 0, 2, 1]) + struct.pack('<H', 4444)
CADR6 = struct.pack('<H', 10) + b'\x20\x01\x0d\xb8' + bytes(11) + b'\x01' + struct.pack('<H', 4444)
CADRX = struct.pack('<H', 7) + b'\xaa\xbb\xcc\xdd' + struct.pack('<H', 4444)
def le32(x): return struct.pack('<I', x)
def le64(x): return struct.pack('<Q', x)

QLVE = bytes.fromhex('c3') + b'Q050' + bytes([0x08]) + bytes(range(8)) + bytes([0x00, 0x00, 0x40, 0x20, 0x01]) + bytes(32)
CHLO_TAGS = [
    (b'PAD\0', b'-' * 20), (b'SNI\0', b'www.example.org'), (b'VER\0', b'Q043Q039Q035'),
    (b'CCS\0', bytes(range(16))), (b'UAID', b'Chrome/70 Linux'), (b'PDMD', b'X509'),
    (b'STK\0', bytes(range(40))), (b'SNO\0', bytes(range(24))), (b'AEAD', b'AESGS20P'),
    (b'SCID', bytes(range(16))), (b'PUBS', pubs()), (b'KEXS', b'C255P256'), (b'OBIT', bytes(8)),
    (b'NONC', NONC), (b'MSPC', le32(100)), (b'TCID', le32(0)), (b'SRBF', le32(1048576)),
    (b'ICSL', le32(30)), (b'SCLS', le32(1)), (b'COPT', b'TBBRIW10'), (b'CCRT', bytes(range(8))),
    (b'IRTT', le32(30000)), (b'CFCW', le32(65536)), (b'SFCW', le32(131072)), (b'CETV', bytes(range(12))),
    (b'XLCT', bytes(range(8))), (b'NONP', NONC), (b'CSCT', b''), (b'CTIM', struct.pack('<II', 1700000000, 5)),
    (b'MIDS', le32(100)), (b'FHOL', le32(1)), (b'STTL', le64(86400)), (b'SMHL', le32(1)),
    (b'TBKP', b'PHL1'), (b'MAD\0', le32(25)), (b'CGST', b'\x01\x02'), (b'EPID', b'gws'), (b'SRST', bytes(16)),
    (b'ZZZZ', b'unknown'),
]
SHLO_TAGS = [
    (b'SCFG', scfg([(b'SCID', bytes(range(16))), (b'AEAD', b'AESGS20PCC12'), (b'PUBS', pubs()),
                    (b'KEXS', b'C255P256'), (b'OBIT', bytes(8)), (b'EXPY', le64(1800000000))])),
    (b'STK\0', bytes(range(40))), (b'SNO\0', bytes(range(24))), (b'PROF', bytes(range(64))),
    (b'CRT\xff', bytes(range(100))), (b'VER\0', b'Q043Q035'), (b'RREJ', le32(0) + le32(1) + le32(2) + le32(5) + le32(99)),
    (b'EXPY', le64(1800000000)), (b'RNON', le64(1)), (b'RSEQ', le64(2)),
]

# ---------------------------------------------------------------- frames
def stream(sid, data, off=0, fin=False, dlen=False, sslen=None, ooo=None):
    sslen = sslen if sslen is not None else (0 if sid < 256 else 1)
    if ooo is None:
        ooo = 0 if off == 0 else (1 if off < 0x10000 else 3)
    OL = [0, 2, 3, 4, 5, 6, 7, 8][ooo]
    return stream_e(sid, data, off, fin, dlen, sslen, ooo, '<')

def stream_e(sid, data, off, fin, dlen, sslen, ooo, e):
    t = 0x80 | (0x40 if fin else 0) | (0x20 if dlen else 0) | (ooo << 2) | sslen
    OL = [0, 2, 3, 4, 5, 6, 7, 8][ooo]
    f = bytes([t])
    f += int(sid).to_bytes(sslen + 1, 'big' if e == '>' else 'little')
    if OL:
        f += int(off).to_bytes(OL, 'big' if e == '>' else 'little')
    if dlen:
        f += struct.pack(e + 'H', len(data))
    return f + data

def num(e, n, v):
    return int(v).to_bytes(n, 'big' if e == '>' else 'little')

L4 = {0: 1, 1: 2, 2: 4, 3: 6}

def ack_old(e, N=False, T=False, ll=0, mm=0, ts=0, ranges=0, revived=0, entropy=1):
    t = 0x40 | (0x20 if N else 0) | (0x10 if T else 0) | (ll << 2) | mm
    f = bytes([t, entropy]) + num(e, L4[ll], 100) + struct.pack(e + 'H', 5) + bytes([ts])
    if ts:
        f += bytes([1]) + struct.pack(e + 'I', 1000)
        for i in range(ts - 1):
            f += bytes([1]) + struct.pack(e + 'H', 10)
    if N:
        f += bytes([ranges])
        for i in range(ranges):
            f += num(e, L4[mm], 90 + i) + bytes([3])
        f += bytes([revived])
        for i in range(revived):
            f += num(e, L4[ll], 80 + i)
    return f

def ack_new(e, N=False, U=False, ll=0, mm=0, blocks=0, ts=0):
    t = 0x40 | (0x20 if N else 0) | (0x10 if U else 0) | (ll << 2) | mm
    f = bytes([t]) + num(e, L4[ll], 100) + struct.pack(e + 'H', 5)
    if N:
        f += bytes([blocks])
    f += num(e, L4[mm], 7)
    for i in range(blocks):
        f += bytes([2]) + num(e, L4[mm], 4 + i)
    f += bytes([ts])
    if ts:
        f += bytes([1]) + struct.pack(e + 'I', 1000)
        for i in range(ts - 1):
            f += bytes([1]) + struct.pack(e + 'H', 10)
    return f

def rst(e): return b'\x01' + struct.pack(e + 'I', 5) + struct.pack(e + 'Q', 1000) + struct.pack(e + 'I', 3)
def conclose(e, reason=b'bye', code=25): return b'\x02' + struct.pack(e + 'IH', code, len(reason)) + reason
def goaway(e, reason=b'go', code=2): return b'\x03' + struct.pack(e + 'II', code, 9) + struct.pack(e + 'H', len(reason)) + reason
def winup(e): return b'\x04' + struct.pack(e + 'I', 5) + struct.pack(e + 'Q', 65536)
def blocked(e): return b'\x05' + struct.pack(e + 'I', 5)
def stopw(e, pkn, ver):
    return b'\x06' + (b'\x01' if ver < 34 else b'') + num(e, pkn, 3)
PING = b'\x07'

HASH = bytes(range(0xA0, 0xAC))

def pkn_bits(n): return {1: 0x00, 2: 0x10, 4: 0x20, 6: 0x30}[n]

def pkt_old(ver, c2s, pkn, plen, body, cid=0x0102030405060708, vflag=False, cidflag=True,
            dnonce=None, enc_cid=None, rst=False, extra_flags=0, hash_=HASH, priv=0x03):
    """Packet of versions up to Q043."""
    e = mk_ver_ctx(ver)
    flags = pkn_bits(plen) | extra_flags
    if vflag: flags |= 0x01
    if cidflag: flags |= 0x08
    if dnonce is not None: flags |= 0x04
    p = bytes([flags])
    if cidflag: p += num(e, 8, cid)
    if vflag: p += b'Q%03d' % ver
    if dnonce is not None: p += dnonce
    p += num(e, plen, pkn)
    p += hash_
    if ver < 34: p += bytes([priv])
    return p + body

def main(outdir):
    F, marks = [], []
    def add(cport, sport, c2s, p): F.append(dgram(cport, sport, p, c2s))
    def mark(s): marks.append((len(F) + 1, s))

    # --------------------------------------------------------- Q025
    ver = 25; e = '<'; cp = 50025; sp = 443
    mark('Q025 (little endian, private flags, old ACK, entropy): CHLO with every client tag, REJ/SHLO, close, reset, version negotiation')
    # first packet: version flag + CID: detected by the heuristic
    body = (ack_old(e, N=True, T=True, ll=1, mm=1, ts=3, ranges=2, revived=1) + stopw(e, 1, ver) + rst(e) + winup(e)
            + blocked(e) + PING + conclose(e, b'x')[:0] + stream(1, b'CHLO' + tags(CHLO_TAGS), dlen=False))
    add(cp, sp, True, pkt_old(ver, True, 1, 1, body, vflag=True))
    body = ack_old(e, N=False, ll=0, mm=0, ts=0) + stream(1, b'REJ\0' + tags(SHLO_TAGS), off=0x100, dlen=True, sslen=0)
    add(cp, sp, False, pkt_old(ver, False, 1, 2, body, priv=0x04))
    body = (ack_old(e, N=True, ll=3, mm=3, ts=1, ranges=1, revived=2) + stream(1, b'SHLO' + tags(SHLO_TAGS[:6]), off=0x10000, ooo=3))
    add(cp, sp, False, pkt_old(ver, False, 0x0304, 2, body))
    body = goaway(e) + conclose(e, b'closing now')
    add(cp, sp, False, pkt_old(ver, False, 0x01020304, 4, body))
    body = rst(e) + conclose(e, b'?')
    add(cp, sp, True, pkt_old(ver, True, 0x010203040506, 6, body))
    add(cp, sp, True, pkt_old(ver, True, 5, 1, bytes(range(30)), ))            # encrypted payload
    add(cp, sp, True, pkt_old(ver, True, 6, 1, b'', ))                         # too short: encrypted
    # data stream and H2 stream frames (after a CHLO so they are decoded)
    h2 = b'\x00\x00\x06\x04\x00\x00\x00\x00\x00' + struct.pack('>HI', 4, 65535)       # HTTP/2 SETTINGS (HEADERS need nghttp2)
    body = stream(1, b'CHLO' + tags(CHLO_TAGS[:3]), dlen=True) + stream(3, h2, off=0)
    add(cp, sp, True, pkt_old(ver, True, 7, 1, body))
    body = stream(1, b'CHLO' + tags(CHLO_TAGS[:3]), dlen=True) + stream(5, b'application data', fin=True, off=300)
    add(cp, sp, True, pkt_old(ver, True, 8, 1, body))
    # public reset (server)
    prst = tags([(b'RNON', le64(0x1122334455667788)), (b'RSEQ', le64(9)), (b'CADR', CADR4)], b'PRST')
    add(cp, sp, False, bytes([0x0a]) + num(e, 8, 0x0102030405060708) + prst)
    # version negotiation (server)
    cp_ = cp
    cp = 50098     # own conversation: the version list changes the version of the conversation
    add(cp, sp, False, bytes([0x09]) + num(e, 8, 0x0102030405060708) + b'Q043Q039Q035Q025')
    cp = cp_
    # client public reset with ipv6 and unknown address
    add(cp, sp, True, bytes([0x0a]) + num(e, 8, 0x0102030405060708) + tags([(b'RNON', le64(1)), (b'CADR', CADR6)], b'PRST'))
    add(cp, sp, True, bytes([0x0a]) + num(e, 8, 0x0102030405060708) + tags([(b'CADR', CADRX)], b'PRST'))

    # truncated frames: the packet is not recognised as unencrypted ("Payload (Encrypted)")
    pk = 20
    for frame in [ack_old(e, N=True, T=True, ll=1, mm=1, ts=2, ranges=1, revived=1), conclose(e, b'abc')[:5], goaway(e)[:10],
                  stream(1, b'CHLO', dlen=True)[:6]]:
        for cut in range(1, len(frame)):
            pk += 1
            add(cp, sp, True, pkt_old(ver, True, pk, 1, frame[:cut] + bytes(max(0, 3 - cut))))

    # --------------------------------------------------------- Q033 diversification nonce
    ver = 33; e = '<'; cp = 50033
    mark('Q033: diversification nonce from the server, 8 octet CID flags')
    body = stream(1, b'CHLO' + tags(CHLO_TAGS[:6]), dlen=True) + ack_old(e, N=True, ll=2, mm=2, ts=2, ranges=1, revived=1)
    add(cp, sp, True, pkt_old(ver, True, 1, 1, body, vflag=True))
    body = stream(1, b'SHLO' + tags(SHLO_TAGS[:6]), dlen=True)
    add(cp, sp, False, pkt_old(ver, False, 1, 1, body, dnonce=bytes(range(32))))

    # --------------------------------------------------------- Q035
    ver = 35; e = '<'; cp = 50035
    mark('Q035: no private flags, new style ACK frames')
    body = (ack_new(e, N=True, U=True, ll=1, mm=1, blocks=2, ts=3) + ack_new(e, N=False, ll=3, mm=3, ts=0)
            + ack_new(e, N=True, ll=2, mm=2, blocks=1, ts=1) + stopw(e, 2, ver) + rst(e) + winup(e) + blocked(e)
            + stream(1, b'CHLO' + tags(CHLO_TAGS), dlen=True))
    add(cp, sp, True, pkt_old(ver, True, 1, 2, body, vflag=True))
    body = stream(1, b'SHLO' + tags(SHLO_TAGS[:5]), dlen=True) + ack_new(e, ts=2)
    add(cp, sp, False, pkt_old(ver, False, 1, 2, body))
    # CONNECTION CLOSE ends the packet
    add(cp, sp, False, pkt_old(ver, False, 2, 2, ack_new(e) + conclose(e, b'closed')))
    add(cp, sp, True, pkt_old(ver, True, 3, 2, bytes(40)))   # padding: encrypted

    # congestion feedback (a "special" frame that is neither STREAM nor ACK) before the CHLO, stream
    # frames with 2 octet stream IDs and 3 and 7 octet offsets
    body = bytes([0x20, 0x21]) + stream_e(1, b'CHLO' + tags(CHLO_TAGS[:2]), 0, False, True, 1, 0, e)
    add(cp, sp, True, pkt_old(ver, True, 4, 2, body))
    body = stream_e(1, b'CHLO' + tags(CHLO_TAGS[:2]), 0x010203, False, True, 0, 2, e) + stream_e(5, b'data', 0x01020304050607, False, False, 0, 6, e)
    add(cp, sp, True, pkt_old(ver, True, 5, 2, body))
    # a CHLO with a tag of length 0 only: "Invalid Length" (total tag length 0)
    add(cp, sp, True, pkt_old(ver, True, 6, 2, stream_e(1, b'CHLO' + tags([(b'PAD\0', b'')]), 0, False, True, 0, 0, e)))
    pk = 20
    for frame in [ack_new(e, N=True, U=True, ll=1, mm=1, blocks=2, ts=2), conclose(e, b'abc')[:5], goaway(e)[:10],
                  stream_e(1, b'CHLO', 0, False, True, 0, 0, e)[:6]]:
        for cut in range(1, len(frame)):
            pk += 1
            add(cp, sp, True, pkt_old(ver, True, pk, 2, frame[:cut] + bytes(max(0, 3 - cut))))

    # --------------------------------------------------------- Q039 big endian
    ver = 39; e = '>'; cp = 50039
    mark('Q039: big endian integers')
    body = (ack_new(e, N=True, U=True, ll=3, mm=2, blocks=1, ts=2) + stopw(e, 4, ver) + rst(e) + winup(e)
            + stream_e(1, b'CHLO' + tags(CHLO_TAGS[:12]), 0, False, True, 0, 0, e))
    add(cp, sp, True, pkt_old(ver, True, 0x0a0b0c0d, 4, body, vflag=True))
    body = (goaway(e, b'') + stream_e(1, b'REJ\0' + tags(SHLO_TAGS), 0x12345678, True, True, 3, 4, e))
    add(cp, sp, False, pkt_old(ver, False, 0x0a0b0c0e, 4, body))

    # --------------------------------------------------------- Q043, server on port 4444
    ver = 43; e = '>'; cp = 50043; sp2 = 4444
    mark('Q043 with the server on port 4444 (learnt from the CHLO), nonce, version negotiation, H2 and data streams')
    body = stream_e(1, b'CHLO' + tags(CHLO_TAGS[:4]), 0, False, True, 0, 0, e)
    add(cp, sp2, True, pkt_old(ver, True, 1, 1, body, vflag=True))
    body = stream_e(1, b'SHLO' + tags(SHLO_TAGS[:4]), 0, False, True, 0, 0, e) + ack_new(e)
    add(cp, sp2, False, pkt_old(ver, False, 1, 1, body, dnonce=bytes(range(32))))
    add(cp, sp2, False, bytes([0x09]) + num(e, 8, 0x1122) + b'Q043Q039')
    add(cp, sp2, False, pkt_old(ver, False, 2, 1, stopw(e, 1, ver) + PING + conclose(e, b'done')))
    body = stream_e(1, b'CHLO' + tags(CHLO_TAGS[:2]), 0, False, True, 0, 0, e) + stream_e(3, h2, 0, False, False, 0, 0, e)
    add(cp, sp2, True, pkt_old(ver, True, 3, 1, body))
    body = stream_e(1, b'CHLO' + tags(CHLO_TAGS[:2]), 0, False, True, 0, 0, e) + stream_e(7, b'data', 5, False, False, 0, 1, e)
    add(cp, sp2, True, pkt_old(ver, True, 4, 1, body))
    add(cp, sp2, True, pkt_old(ver, True, 5, 1, b'\x40' * 30))
    # the 6-byte packet number, empty CID
    body = stream_e(1, b'CHLO' + tags(CHLO_TAGS[:2]), 0, False, True, 0, 0, e)
    add(cp, sp2, True, pkt_old(ver, True, 6, 6, body, cidflag=False))

    # --------------------------------------------------------- Q046
    mark('Q046 long and short headers (client with CID, server without)')
    ver = 46; e = '>'; cp = 50046; sp = 443
    def q46_long(c2s, pkn, plen, body, ptype=0, ver_s=b'Q046', cid=0x0102030405060708):
        fb = 0xC0 | (ptype << 4) | (plen - 1)
        cil = 0x50 if c2s else 0x05
        return bytes([fb]) + ver_s + bytes([cil]) + num(e, 8, cid) + num(e, plen, pkn) + HASH + body
    def q46_short(c2s, pkn, plen, body, cid=0x0102030405060708):
        fb = 0x40 | (plen - 1)
        return bytes([fb]) + (num(e, 8, cid) if c2s else b'') + num(e, plen, pkn) + HASH + body
    body = stream_e(1, b'CHLO' + tags(CHLO_TAGS[:3]), 0, False, True, 0, 0, e) + ack_new(e)
    add(cp, sp, True, q46_long(True, 1, 4, body))
    body = stream_e(1, b'SHLO' + tags(SHLO_TAGS[:3]), 0, False, True, 0, 0, e) + ack_new(e)
    add(cp, sp, False, q46_long(False, 1, 2, body, ptype=2))
    add(cp, sp, True, q46_short(True, 2, 3, ack_new(e, N=True, blocks=1) + stopw(e, 3, 46) + conclose(e, b'q46')))
    add(cp, sp, False, q46_short(False, 3, 1, ack_new(e) + conclose(e, b'q46s')))
    add(cp, sp, True, q46_short(True, 4, 1, bytes(40)))
    add(cp, sp, False, q46_short(False, 4, 2, bytes(30)))
    body = stream_e(1, b'CHLO' + tags(CHLO_TAGS[:1]), 0, False, True, 0, 0, e) + stream_e(3, h2, 0, False, False, 0, 0, e)
    add(cp, sp, True, q46_long(True, 5, 1, body, ptype=1))

    mark('reproducers of the review: CRYPTO frame in Q043 (was an assertion), PUBS of 1 octet and SCFG with a huge tag count')
    e = '>'
    chlo_ = stream_e(1, b'CHLO' + tags(CHLO_TAGS[:1]), 0, False, True, 0, 0, e)
    add(50044, 443, True, pkt_old(43, True, 1, 1, b'\x08' + chlo_, vflag=True))
    huge = b'SCFG' + struct.pack('<I', 0x20000000) + b'VER\0' + struct.pack('<I', 4) + b'Q043'
    add(50045, 443, True, pkt_old(43, True, 1, 1, stream_e(1, b'CHLO' + tags([(b'SNI\0', b'abcd'), (b'PUBS', b'\x01'), (b'SCFG', huge)]), 0, False, True, 0, 0, e), vflag=True))
    # H2 HEADERS on stream 3 right after (same conversation as above, big endian)
    add(50045, 443, True, pkt_old(43, True, 2, 1, stream_e(1, b'CHLO' + tags(CHLO_TAGS[:1]), 0, False, True, 0, 0, e) + stream_e(3, h2, 0, False, False, 0, 0, e)))

    # --------------------------------------------------------- Q050 / T051 CRYPTO frames
    mark('Q050 (GQUIC tags in a CRYPTO frame) and T051 (TLS 1.3 handshake in a CRYPTO frame) in long header packets')
    cp = 50050
    def varint(v):
        if v < 64: return bytes([v])
        return struct.pack('>H', 0x4000 | v)
    def tls_chlo(pad):
        sni = b'www.example.org'
        ext_sni = struct.pack('>HHHBH', 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni
        ext_sv = struct.pack('>HHB', 0x2b, 3, 2) + b'\x03\x04'
        ext_pad = struct.pack('>HH', 0x15, len(pad)) + pad
        exts = ext_sv + ext_sni + ext_pad
        body = b'\x03\x03' + bytes(range(32)) + b'\x00' + struct.pack('>HH', 2, 0x1301) + b'\x01\x00' + struct.pack('>H', len(exts)) + exts
        return b'\x01' + struct.pack('>I', len(body))[1:] + body
    def tls_shlo(rand):
        exts = struct.pack('>HHH', 0x2b, 2, 0x0304)
        body = b'\x03\x03' + rand + b'\x00' + struct.pack('>H', 0x1301) + b'\x00' + struct.pack('>H', len(exts)) + exts
        return b'\x02' + struct.pack('>I', len(body))[1:] + body
    def q50_pkt(c2s, pkn, plen, ver_s, body):
        fb = 0xC0 | (plen - 1)
        cil = 0x50 if c2s else 0x05
        return bytes([fb]) + ver_s + bytes([cil]) + num('>', 8, 0x0102030405060708) + num('>', plen, pkn) + HASH + body
    # first a Q046 long header packet so that the heuristic claims the conversation
    body = stream_e(1, b'CHLO' + tags(CHLO_TAGS[:1]), 0, False, True, 0, 0, '>')
    add(cp, sp, True, q46_long(True, 1, 1, body))
    rnd = random.Random(5)
    tail = stream_e(1, b'CHLO' + tags(CHLO_TAGS[:1]), 0, False, True, 0, 0, '>')
    for kind, ver_s in (('Q050', b'Q050'), ('T051', b'T051')):
        for attempt in range(100000):
            off = rnd.randrange(1, 64)
            pad = bytes(rnd.randrange(256) for _ in range(rnd.randrange(8, 40)))
            if kind == 'Q050':
                data = b'CHLO' + tags([(b'PAD\0', pad), (b'SNI\0', b'www.example.org'), (b'VER\0', b'Q050')])
            else:
                data = tls_chlo(pad)
            frame = b'\x08' + bytes([off]) + struct.pack('>H', 0x4000 | len(data)) + data
            pk = q50_pkt(True, 2, 1, ver_s, frame + b'\x07' * rnd.randrange(0, 40) + tail)
            if walk(pk, 1 + 4 + 1 + 8 + 1, 1):
                break
        else:
            raise SystemExit('no CRYPTO alignment found ' + kind)
        add(cp, sp, True, pk)
        # server reply with a CRYPTO frame too
        for attempt in range(100000):
            off = rnd.randrange(1, 64)
            pad = bytes(rnd.randrange(256) for _ in range(rnd.randrange(8, 40)))
            if kind == 'Q050':
                data = b'SHLO' + tags([(b'PAD\0', pad), (b'VER\0', b'Q050')])
            else:
                data = tls_shlo(bytes(rnd.randrange(256) for _ in range(32)))
            frame = b'\x08' + bytes([off]) + struct.pack('>H', 0x4000 | len(data)) + data
            pk = q50_pkt(False, 3, 2, ver_s, frame + b'\x07' * rnd.randrange(0, 40) + stream_e(1, b'SHLO' + tags(SHLO_TAGS[:2]), 0, False, True, 0, 0, '>'))
            if walk(pk, 1 + 4 + 1 + 8 + 2, 2):
                break
        else:
            raise SystemExit('no CRYPTO alignment found (server) ' + kind)
        add(cp, sp, False, pk)

    # ----------------------------------------------------- malformed capture
    M = []
    def madd(cport, sport, c2s, p): M.append(dgram(cport, sport, p, c2s))
    # CRYPTO frame in Q043 (reproducer of the assertion); invalid versions; truncated tags; bad CID length
    e = '>'
    chlo_ = stream_e(1, b'CHLO' + tags(CHLO_TAGS[:1]), 0, False, True, 0, 0, e)
    # one conversation that changes from Q025 (little endian) to Q043 (big endian): the second pass decodes the first frame as big endian
    madd(51010, 443, True, pkt_old(25, True, 1, 1, stream(1, b'CHLO' + tags(CHLO_TAGS[:2]), dlen=True), vflag=True))
    madd(51010, 443, True, pkt_old(43, True, 2, 1, stream_e(1, b'CHLO' + tags(CHLO_TAGS[:2]), 0, False, True, 0, 0, '>'), vflag=True))
    madd(51001, 443, True, pkt_old(43, True, 1, 1, b'\x08' + chlo_, vflag=True)[:0] + b'\x09' + bytes(range(1, 9)) + b'Q04x' + b'\x01' + HASH + chlo_)
    # Q046 long header with a connection ID length that is not 8 (3 octets): invalid parameter
    madd(51002, 443, True, q46_long(True, 1, 1, chlo_))                       # claims the conversation
    madd(51002, 443, True, bytes([0xC0]) + b'Q046' + bytes([0x00]) + bytes(3) + num('>', 1, 2) + HASH + chlo_)
    madd(51002, 443, True, bytes([0xC0]) + b'Q0x6' + bytes([0x50]) + bytes(8) + num('>', 1, 3) + HASH + chlo_)   # invalid version
    # a tag length past the end of the packet (truncated tag), a CADR with the wrong length
    trunc = b'CHLO' + struct.pack('<HH', 1, 0) + b'SNI\0' + struct.pack('<I', 500) + b'abcd'
    madd(51003, 443, True, pkt_old(43, True, 1, 1, stream_e(1, trunc, 0, False, True, 0, 0, '>'), vflag=True))
    madd(51004, 443, True, pkt_old(43, True, 1, 1, stream_e(1, b'CHLO' + tags(CHLO_TAGS[:1]), 0, False, True, 0, 0, '>'), vflag=True))
    madd(51004, 443, True, bytes([0x0a]) + num('>', 8, 5) + b'PRST' + struct.pack('<HH', 1, 0) + b'CADR' + struct.pack('<I', 3) + b'\x02\x00\x01')
    # a public reset whose tags are cut off
    madd(51005, 443, True, bytes([0x09]) + num('>', 8, 5) + b'Q043' + bytes([0x0a]) + bytes(6))
    madd(51005, 443, True, bytes([0x0a]) + num('>', 8, 5) + b'PRST\x05\x00\x00\x00')
    madd(51006, 443, True, bytes([0x09]) + bytes(8) + b'Q043')    # nothing after the version
    madd(51008, 443, True, pkt_old(43, True, 1, 1, stream_e(1, b'CHLO' + tags([(b'SNI\0', b'abcd'), (b'QLVE', QLVE)]), 0, False, True, 0, 0, '>'), vflag=True))   # IETF QUIC inside (decryption fails)
    madd(51007, 443, True, bytes([0x09]) + num('>', 8, 5) + b'Q043' + bytes([0x01]) + HASH[:11])   # cut inside the hash

    # UDP packets the heuristic rejects
    for i, p in enumerate([bytes([0x09]) + bytes(8) + b'Q0',                       # too short
                           bytes([0x08]) + bytes(20),                              # no version flag
                           bytes([0x01]) + bytes(20),                              # no CID flag
                           bytes([0x09]) + bytes(8) + b'Q059' + bytes(8),          # not Q02, Q03 or Q04
                           bytes([0xC0]) + b'Q046' + bytes(6),                     # long header, too short
                           bytes([0xC0]) + b'Q047' + bytes(12),                    # long header, not Q046
                           bytes([0x80]) + bytes(20)]):                            # reserved bit only
        madd(51100 + i, 443, True, p)
    pcap(outdir + '/gquic-coverage.pcap', F)
    pcap(outdir + '/gquic-coverage-malformed.pcap', M)
    for n, s in marks:
        print(n, s)
    print(len(F), 'frames;', len(M), 'malformed')

main(sys.argv[1])
