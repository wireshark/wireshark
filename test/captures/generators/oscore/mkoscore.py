#!/usr/bin/env python3
# Generates test/captures/oscore_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the OSCORE coverage captures.

Usage: mkoscore.py <outdir>

OSCORE (RFC 8613) is reached only through CoAP (UDP port 5683, the OSCORE
option 9) with a matching security context in the "Security Contexts" UAT.
This generator produces no ciphertext and no keys: the payloads are
arbitrary bytes, and cfg/oscore_contexts holds three placeholder contexts
(dummy secrets) so that the context lookup succeeds. The authentication tag
check therefore always fails; nothing is decrypted. What is covered is
everything before that: the context lookup, the partial IV checks, the
nonce construction and the error paths.

Writes oscore-coverage.pcapng (full frames) and
oscore-coverage-malformed.pcapng (frames with the end of the payload not
captured, so that no tag is present and the garbage "plaintext" is
dissected as CoAP).
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
    """frames: list of (bytes, captured length[, linktype])"""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    lts = []
    for fr in frames:
        lt = fr[2] if len(fr) > 2 else 1
        if lt not in lts:
            lts.append(lt)
            out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, fr in enumerate(frames):
        p, cl = fr[0], fr[1]
        lt = fr[2] if len(fr) > 2 else 1
        ts = 1700000000 * 1000000 + i * 1000
        out += _blk(6, struct.pack('<IIIII', lts.index(lt), ts >> 32, ts & 0xffffffff, cl, len(p)) + p[:cl])
    with open(path, 'wb') as f:
        f.write(out)

def udp_frame(payload, sport, dport):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    if sport == 5683:
        src, dst = bytes((192, 0, 2, 2)), bytes((192, 0, 2, 1))
    else:
        src, dst = bytes((192, 0, 2, 1)), bytes((192, 0, 2, 2))
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0, src, dst)
    s = sum((ip[i] << 8) | ip[i + 1] for i in range(0, 20, 2))
    s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack('>H', (~s) & 0xffff) + ip[12:]
    return b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00' + ip + u

def exppdu(proto, payload):
    return (struct.pack('>HH', 12, (len(proto) + 3) & ~3) +
            proto.encode().ljust((len(proto) + 3) & ~3, b'\0') +
            struct.pack('>HH', 0, 0) + payload)

def filler(n, seed):
    """n arbitrary bytes (not ciphertext of anything)"""
    x = seed * 2654435761 & 0xffffffff
    out = bytearray()
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0x7fffffff
        out.append((x >> 16) & 0xff)
    return bytes(out)

def coap(code, mid, token, optval, payload, typ=0):
    hdr = bytes([0x40 | (typ << 4) | len(token), code]) + struct.pack('>H', mid) + token
    l = len(optval)
    if l < 13:
        opt = bytes([(9 << 4) | l]) + optval
    elif l < 269:
        opt = bytes([(9 << 4) | 13, l - 13]) + optval
    else:
        opt = bytes([(9 << 4) | 14]) + struct.pack('>H', l - 269) + optval
    return hdr + opt + (b'\xff' + payload if payload else b'')

def oscore_opt(piv=b'', kid=None, kid_context=None, flags_extra=0):
    flags = len(piv) | flags_extra
    out = b''
    if kid_context is not None:
        flags |= 0x10
    if kid is not None:
        flags |= 0x08
    out = bytes([flags]) + piv
    if kid_context is not None:
        out += bytes([len(kid_context)]) + kid_context
    if kid is not None:
        out += kid
    return out

REQ, CHANGED, CONTENT = 0x02, 0x44, 0x45

def frames():
    f = []          # (bytes, captured length)
    n = [0]
    def req(opt, plen, tok=None, code=REQ, sport=40000):
        n[0] += 1
        mid = n[0]
        tok = tok or struct.pack('>H', mid)
        p = udp_frame(coap(code, mid, tok, opt, filler(plen, mid)), sport, 5683)
        f.append((p, len(p)))
        return mid, tok
    def rsp(mid, tok, opt, plen, code=CHANGED, dport=40000, typ=2):
        p = udp_frame(coap(code, mid, tok, opt, filler(plen, mid + 500), typ=typ), 5683, dport)
        f.append((p, len(p)))
    # requests matching context 1 (sender ID 01): PIV of 1 to 5 octets
    for i in range(1, 6):
        mid, tok = req(oscore_opt(piv=filler(i, i), kid=b'\x01'), 12 + i)
        # response without PIV: nonce from the request PIV, response key
        rsp(mid, tok, b'', 20)
    # a response with its own PIV (recipient ID is the PIV generator)
    mid, tok = req(oscore_opt(piv=b'\x07', kid=b'\x01'), 15)
    rsp(mid, tok, oscore_opt(piv=b'\x09\x08'), 22)
    rsp(mid, tok, oscore_opt(piv=b'\x01'), 9, typ=0)    # second response, same transaction
    # request matching context 2 (sender ID empty, no KID in the option)
    mid, tok = req(oscore_opt(piv=b'\x2a'), 30)
    rsp(mid, tok, b'', 11)
    mid, tok = req(oscore_opt(piv=b'\x2a\x2b'), 30, tok=b'')    # empty token
    # the smallest payloads: no ciphertext at all, one octet, exactly the tag
    for plen in (1, 7, 8, 9):
        req(oscore_opt(piv=b'\x03', kid=b'\x01'), plen)
    # a request without a PIV (and a response without a request): no PIV found
    req(oscore_opt(kid=b'\x01'), 20)
    rsp(0x7001, b'\xee', b'', 20)
    req(b'', 20)                                            # empty OSCORE option
    # KID the context table does not have; KID context the table does not have
    req(oscore_opt(piv=b'\x04', kid=b'\x01\x02'), 20)
    req(oscore_opt(piv=b'\x04', kid=b'\x01', kid_context=b'\xaa\xbb'), 20)
    req(oscore_opt(piv=b'\x04', kid=b'\x01', kid_context=b''), 20)
    # a PIV longer than the 5 octets of the specification
    req(oscore_opt(piv=filler(6, 6), kid=b'\x01'), 20)
    req(oscore_opt(piv=filler(7, 7), kid=b'\x01'), 20)
    mid, tok = req(oscore_opt(piv=b'\x01', kid=b'\x01'), 20)
    rsp(mid, tok, oscore_opt(piv=filler(6, 8)), 20)
    # a long option (extended length) with a long KID and KID context
    req(oscore_opt(piv=b'\x05', kid=filler(20, 9), kid_context=filler(30, 10)), 20)
    # a confirmable response and non-confirmable request, GET
    req(oscore_opt(piv=b'\x06', kid=b'\x01'), 25, code=0x01)
    # a request over a port other than 40000, and a long payload
    req(oscore_opt(piv=b'\x0a\x0b', kid=b'\x01'), 600, sport=41234)
    # Exported PDU naming "oscore": there is no CoAP information, so OSCORE
    # declines the data (it needs the OSCORE info CoAP passes along)
    for n in (24, 5):
        p = exppdu('oscore', filler(n, 77))
        f.append((p, len(p), 252))
    return f

def malformed():
    """Frames whose end (the tag, more) is not captured."""
    f = []
    mid = 1000
    for trunc in (4, 8, 10, 16, 30):
        for plen, opt in ((40, oscore_opt(piv=b'\x01', kid=b'\x01')),
                          (30, oscore_opt(piv=b'\x05\x06', kid=None)),
                          (12, oscore_opt(piv=b'\x03', kid=b'\x01'))):
            mid += 1
            tok = struct.pack('>H', mid)
            p = udp_frame(coap(REQ, mid, tok, opt, filler(plen, mid)), 40000, 5683)
            f.append((p, max(len(p) - trunc, 60)))
            r = udp_frame(coap(CHANGED, mid, tok, b'', filler(plen, mid + 3), typ=2), 5683, 40000)
            f.append((r, max(len(r) - trunc, 60)))
    # a reserved flag bit in the OSCORE option (a malformed option error from CoAP)
    p = udp_frame(coap(REQ, 3000, b'\x08', oscore_opt(piv=b'\x05', kid=b'\x01', flags_extra=0x80),
                       filler(20, 3)), 40000, 5683)
    f.append((p, len(p)))
    # a response whose request was truncated and a partial option
    p = udp_frame(coap(REQ, 2000, b'\x07', oscore_opt(piv=b'\x01', kid=b'\x01'), filler(5, 1)), 40000, 5683)
    f.append((p, len(p) - 1))
    return f

if __name__ == '__main__':
    d = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcapng(os.path.join(d, 'oscore-coverage.pcapng'), frames())
    pcapng(os.path.join(d, 'oscore-coverage-malformed.pcapng'), malformed())
