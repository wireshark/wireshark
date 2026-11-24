# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
from util import csum

NAT, AD, HID, CID, SID, UNI4, I4, U4, XDP, SERVAL, FLOWID, ZF = 0, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20
EMPTY = 0x7f
ENTRY = 0x7e

def xid(n):
    """20 octet XID derived from a number"""
    return struct.pack('>5I', n, n * 3 + 1, n * 5 + 2, n * 7 + 3, n * 11 + 4)

def node(ty, n, edges=(), raw_edges=None):
    e = list(edges)[:4]
    e += [EMPTY] * (4 - len(e))
    if raw_edges is not None:
        e = list(raw_edges)
    return struct.pack('>I', ty) + xid(n) + bytes(e)

def dag(*nodes):
    return b''.join(nodes)

def xip(dst, src, payload=b'', nxth=0, hop=250, last=ENTRY, plen=None, ndst=None, nsrc=None, ver=1):
    nd = len(dst) // 28 if ndst is None else ndst
    ns = len(src) // 28 if nsrc is None else nsrc
    return (struct.pack('>BBHBBBB', ver, nxth, len(payload) if plen is None else plen, hop, nd, ns, last)
            + dst + src + payload)

def eth_xip(p, src=1, dst=2):
    return bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) + b'\xc0\xde' + p

def serval_hdr(ptype, ext=b'', hlen=None, chk=True, pad=b''):
    """Serval header: length in 32 bit words, protocol, checksum, extension headers.
    hlen None: computed; chk False: a wrong checksum"""
    body = ext + pad
    n = (4 + len(body)) // 4 if hlen is None else hlen
    h = struct.pack('>BBH', n, ptype, 0) + body
    c = csum(h[:n * 4]) if chk else 0xdead
    return struct.pack('>BBH', n, ptype, c) + body

def serval_cext(flags, verno, ackno, nonce=b'\x01\x02\x03\x04\x05\x06\x07\x08', length=20, typ=0):
    return struct.pack('>BBBBII', typ, length, flags, 0, verno, ackno) + nonce

def tcp_hdr(sport, dport, seq, ack, flags, opts=b'', win=1000):
    doff = (20 + len(opts)) // 4
    return struct.pack('>HHIIBBHHH', sport, dport, seq, ack, doff << 4, flags, win, 0x1234, 0) + opts

def udp_hdr(sport, dport, plen=0):
    return struct.pack('>HHHH', sport, dport, 8 + plen, 0x1234)
