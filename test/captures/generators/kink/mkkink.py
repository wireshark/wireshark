#!/usr/bin/env python3
# Generates test/captures/kink_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the KINK coverage captures: mkkink.py <outdir>.

KINK (Kerberized Internet Negotiation of Keys, RFC 4430) runs over UDP
port 910, registered by default. Writes kink-coverage.pcapng (all
payload types, the three reproducers of "KINK: Bound the payload chain
recursion") and kink-coverage-malformed.pcapng. Kerberos AP-REQ, AP-REP,
KRB-ERROR, checksums and the KINK_ENCRYPT payloads carry placeholder
bytes: there are no keys, so the decryption of KINK_ENCRYPT and the
use of the key type stay uncovered.
"""
import os
import struct
import sys
from pylib import Pcapng, eth_udp, eth, csum

PORT = 910

# ---- minimal DER encoder ---------------------------------------------
def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        l = bytes([n])
    elif n < 0x100:
        l = bytes([0x81, n])
    else:
        l = bytes([0x82, n >> 8, n & 0xff])
    return bytes([tag]) + l + body

def seq(*items): return tlv(0x30, b''.join(items))
def ctx(n, body): return tlv(0xa0 | n, body)
def integer(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big')
    return tlv(0x02, b)
def gstring(s): return tlv(0x1b, s.encode())
def octets(b): return tlv(0x04, b)
def gtime(s): return tlv(0x18, s.encode())

def principal(ntype, *names):
    return seq(ctx(0, integer(ntype)), ctx(1, seq(*[gstring(n) for n in names])))

def enc_data(etype, cipher, kvno=None):
    items = [ctx(0, integer(etype))]
    if kvno is not None:
        items.append(ctx(1, integer(kvno)))
    items.append(ctx(2, octets(cipher)))
    return seq(*items)

def ticket(realm='EXAMPLE.TEST', sname=('kadmin', 'changepw'), cipher=bytes([0xc0] * 40)):
    return tlv(0x61, seq(ctx(0, integer(5)), ctx(1, gstring(realm)),
                         ctx(2, principal(2, *sname)),
                         ctx(3, enc_data(18, cipher, 2))))

def ap_req(cipher=bytes([0xa0] * 32), tkt=None):
    return tlv(0x6e, seq(ctx(0, integer(5)), ctx(1, integer(14)),
                         ctx(2, tlv(0x03, b'\x00\x00\x00\x00\x00')),
                         ctx(3, tkt or ticket()),
                         ctx(4, enc_data(18, cipher))))

def ap_rep(cipher=bytes([0xa1] * 24)):
    return tlv(0x6f, seq(ctx(0, integer(5)), ctx(1, integer(15)),
                         ctx(2, enc_data(18, cipher))))

def krb_priv(cipher=bytes([0xb0] * 48)):
    return tlv(0x76, seq(ctx(0, integer(5)), ctx(1, integer(21)),
                         ctx(3, enc_data(18, cipher))))

def krb_error(code=0x18, etext=None, edata=None, cname=True):
    items = [ctx(0, integer(5)), ctx(1, integer(30)),
             ctx(4, gtime('20231114221320Z')), ctx(5, integer(123456)),
             ctx(6, integer(code))]
    if cname:
        items += [ctx(7, gstring('EXAMPLE.TEST')), ctx(8, principal(1, 'alice'))]
    items += [ctx(9, gstring('EXAMPLE.TEST')),
              ctx(10, principal(2, 'kadmin', 'changepw'))]
    if etext:
        items.append(ctx(11, gstring(etext)))
    if edata is not None:
        items.append(ctx(12, octets(edata)))
    return tlv(0x7e, seq(*items))



# ---- KINK ------------------------------------------------------------
DONE, AP_REQ, AP_REP, KRB_ERROR, TGT_REQ, TGT_REP, ISAKMP, ENCRYPT, ERROR = \
    0, 14, 15, 16, 17, 18, 19, 20, 21

def pad4(b):
    return b + bytes((-len(b)) % 4)

def payload(nxt, body, plen=None, pad=True):
    """Payload header (next, reserved, length) + body, padded to 4."""
    n = 4 + len(body) if plen is None else plen
    d = struct.pack('>BBH', nxt, 0, n) + body
    return pad4(d) if pad else d

def header(ktype, nxt, rest=b'', tid=0x01020304, a=0, doi=1, chk=b'', version=0x10,
           length=None):
    chk_p = pad4(chk)
    body = struct.pack('>IIBBH', doi, tid, len(chk), nxt, (a << 15)) + chk_p + rest
    n = 4 + len(body) if length is None else length
    return struct.pack('>BBH', ktype, version, n) + body

def ap_req_pl(nxt, cipher=bytes([0xa0] * 32), epoch=1700000000):
    k = ap_req(cipher)
    return payload(nxt, struct.pack('>I', epoch) + k, 8 + len(k))

def ap_rep_pl(nxt, cipher=bytes([0xa1] * 24), epoch=1700000001):
    k = ap_rep(cipher)
    return payload(nxt, struct.pack('>I', epoch) + k, 8 + len(k))

def krb_error_pl(nxt, code=0x18, etext=None):
    k = krb_error(code, etext=etext)
    return payload(nxt, k, 4 + len(k))

def tgt_req_pl(nxt, realm='EXAMPLE.TEST'):
    r = realm.encode()
    return payload(nxt, struct.pack('>H', len(r)) + r, 6 + len(r))

def tgt_rep_pl(nxt, princ='krbtgt/EXAMPLE.TEST@EXAMPLE.TEST', tgt='PLACEHOLDER-TGT-BYTES'):
    pr, tg = princ.encode(), tgt.encode()
    pp = bytes((-(len(pr) + 6)) % 4)
    body = struct.pack('>H', len(pr)) + pr + pp + struct.pack('>H', len(tg)) + tg
    return payload(nxt, body, 4 + len(body))

def nonce(nxt, n=16):
    return struct.pack('>BBH', nxt, 0, 4 + n) + bytes([0x3c] * n)

def ipid(nxt):
    return struct.pack('>BBHBBH', nxt, 0, 12, 1, 0, 0) + bytes([192, 0, 2, 7])

def isakmp_pl(nxt, inner=None, qm=0x10, inner_next=10):
    inner = inner if inner is not None else nonce(5) + ipid(0)
    return payload(nxt, struct.pack('>BBH', inner_next, qm, 0) + inner, 8 + len(inner))

def encrypt_pl(nxt, n=24, inner_next=ISAKMP):
    return payload(nxt, struct.pack('>B3x', inner_next) + bytes([0xe0] * n), 8 + n)

def error_pl(nxt, code):
    return struct.pack('>BBHI', nxt, 0, 8, code)

def unknown_pl(nxt, n=8, kind=99):
    return payload(nxt, bytes([0x55] * n), 4 + n)

# ---- the recursion reproducers (kink_recursion.py of the review) -----
def chain(total):
    hdr = struct.pack('>BBHIIBBH', 1, 0x10, 0, 1, 1, 0, 0xff, 0)
    n = (total - len(hdr)) // 4
    body = b''.join(struct.pack('>BBH', 0xff, 0, 4) for _ in range(n - 1))
    body += struct.pack('>BBH', 0, 0, 4)
    return hdr + body

def main(out):
    ng = Pcapng()
    eth_if = ng.add_if(1, 262144)
    epdu_if = ng.add_if(252, 262144)
    def add(data, rev=False, sport=910):
        sp, dp = (PORT, sport) if rev else (sport, PORT)
        ng.add(eth_if, eth_udp(sp, dp, data, rev=rev))

    # 1-4: a CREATE with the Kerberos AP-REQ, the ISAKMP payload and an
    # encrypted payload; the REPLY with the AP-REP; DELETE; ACK
    add(header(1, AP_REQ, a=1, chk=bytes([0xcc] * 12),
               rest=ap_req_pl(ISAKMP) + isakmp_pl(ENCRYPT) + encrypt_pl(DONE)))
    add(header(3, AP_REP, rest=ap_rep_pl(ENCRYPT) + encrypt_pl(DONE, 16)), rev=True)
    add(header(2, ENCRYPT, a=1, chk=bytes([0xcd] * 8), tid=7,
               rest=encrypt_pl(DONE, 40, inner_next=DONE)))
    add(header(5, DONE, tid=7), rev=True)
    # 5-7: GETTGT with the realm; the reply with the principal and the
    # TGT; a reply with a KRB-ERROR payload
    add(header(4, TGT_REQ, tid=8, rest=tgt_req_pl(DONE)))
    add(header(3, TGT_REP, tid=8, rest=tgt_rep_pl(DONE)), rev=True)
    add(header(3, TGT_REP, tid=9, rest=tgt_rep_pl(DONE, 'a@B', 'x')), rev=True)    # name needs no padding... (3+6)%4 != 0
    for i, et in enumerate((None, 'a', 'ab', 'abc', 'abcd')):      # payload lengths of every residue mod 4
        add(header(3, KRB_ERROR, tid=10 + i, rest=krb_error_pl(DONE, 0x1f, et)), rev=True)
    # 9: STATUS with a chain of ERROR payloads, one per code range
    codes = [0, 1, 2, 3, 4, 5, 6, 7, 8191, 8192, 16383, 16384, 0xffffffff]
    rest = b''.join(error_pl(ERROR if i + 1 < len(codes) else DONE, c) for i, c in enumerate(codes))
    add(header(6, ERROR, tid=11, rest=rest))
    # 10: every payload kind in one chain, ending in an undefined payload
    add(header(1, TGT_REQ, tid=12, a=1, chk=bytes([0xce] * 5),
               rest=tgt_req_pl(AP_REQ, 'A.B') + ap_req_pl(AP_REP) + ap_rep_pl(KRB_ERROR) +
               krb_error_pl(TGT_REP, etext='abc') + tgt_rep_pl(ISAKMP) +
               isakmp_pl(ENCRYPT, inner=nonce(0, 5), qm=0x20) +
               encrypt_pl(ERROR, 13) + error_pl(99, 1) + unknown_pl(DONE, 6)))
    # 11: not IPsec DOI, reserved type, unknown type, checksum of 3 and 13 octets
    add(header(0, DONE, doi=0, tid=13, chk=b'\x01\x02\x03'))
    add(header(99, DONE, doi=2, tid=14, chk=bytes(13), a=1))
    # 13: ISAKMP payload whose body is only the header, one longer than the
    # inner payloads
    add(header(1, ISAKMP, tid=16, rest=isakmp_pl(DONE, inner=nonce(0, 4), inner_next=10)))
    add(header(1, AP_REQ, tid=17, rest=ap_req_pl(DONE, bytes([0xa9] * 300))))

    # the reproducers: 64 KiB IPv4 datagram, Exported PDU, IPv6 jumbogram
    pl = chain(65535 - 20 - 8)
    add(pl)
    name = b'kink'
    tags = struct.pack('>HH', 12, len(name)) + name + struct.pack('>HH', 0, 0)
    ng.add(epdu_if, tags + chain(262144 - len(tags) - 16))
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    pl = chain(262144 - 14 - 40 - 8 - 8 - 4)
    ulen = 8 + len(pl)
    hbh = struct.pack('>BBBBI', 17, 0, 0xC2, 4, 8 + ulen)
    u = struct.pack('>HHHH', 910, 910, 0, 0) + pl
    pseudo = src + dst + struct.pack('>IxxxB', ulen, 17)
    c = csum(pseudo + u) or 0xffff
    u = u[:6] + struct.pack('>H', c) + u[8:]
    ip6 = struct.pack('>IHBB', 0x60000000, 0, 0, 64) + src + dst
    ng.add(eth_if, eth('02:00:00:00:00:02', '02:00:00:00:00:01', 0x86dd, ip6 + hbh + u))
    ng.write(os.path.join(out, 'kink-coverage.pcapng'))

    m = Pcapng()
    mif = m.add_if(1, 65535)
    def madd(data, rev=False):
        sp, dp = (PORT, 45100) if rev else (45100, PORT)
        m.add(mif, eth_udp(sp, dp, data, rev=rev))
    # small payload lengths (warning), ERROR with the wrong length
    madd(header(1, ISAKMP, rest=isakmp_pl(DONE, inner=b'')))
    madd(header(1, AP_REQ, rest=payload(DONE, struct.pack('>I', 1700000000), 8)))
    madd(header(1, AP_REP, rest=payload(DONE, struct.pack('>I', 1700000000), 8)))
    madd(header(1, KRB_ERROR, rest=payload(DONE, b'', 4)))
    madd(header(1, ISAKMP, rest=payload(DONE, b'\x00\x10\x00\x00', 8)))
    madd(header(1, ENCRYPT, rest=payload(DONE, b'\x00\x00\x00\x00', 8)))
    madd(header(1, ERROR, rest=struct.pack('>BBHI', DONE, 0, 12, 1)))
    madd(header(1, ERROR, rest=struct.pack('>BBHI', DONE, 0, 4, 1)))
    madd(header(1, 99, rest=payload(DONE, b'', 4)))
    madd(header(1, 99, rest=struct.pack('>BBH', 99, 0, 2) + b'\x00\x00'))    # chain on a length of 2
    madd(header(1, 99, rest=struct.pack('>BBH', 0, 0, 0)))                  # length 0 stops the chain
    # truncated and over-long fields
    full = header(1, AP_REQ, a=1, chk=bytes([0xcc] * 12),
                  rest=ap_req_pl(ISAKMP) + isakmp_pl(ENCRYPT) + encrypt_pl(DONE))
    madd(full[:5])
    madd(full[:19])
    madd(full[:24])
    madd(full[:40])
    madd(full[:70])
    madd(full[:-6])
    madd(header(1, TGT_REQ, rest=struct.pack('>BBHH', DONE, 0, 12, 400) + b'EXAMPLE.TEST'))
    madd(header(1, TGT_REP, rest=struct.pack('>BBHH', DONE, 0, 12, 400) + b'krbtgt'))
    madd(header(1, TGT_REP, rest=struct.pack('>BBHH', DONE, 0, 12, 2) + b'ab' + struct.pack('>H', 900) + b'xx'))
    madd(header(1, ENCRYPT, rest=struct.pack('>BBH', DONE, 0, 400) + bytes(8)))
    madd(header(1, ISAKMP, rest=struct.pack('>BBH', DONE, 0, 300) + b'\x0a\x10\x00\x00' + nonce(0, 8)))
    madd(header(1, AP_REQ, rest=struct.pack('>BBH', DONE, 0, 300) + bytes(8) + b'\x6e\x03\x30\x01\x00'))
    madd(header(1, DONE, chk=bytes(200)))                                    # checksum length beyond the packet
    madd(header(1, DONE)[:10])
    m.write(os.path.join(out, 'kink-coverage-malformed.pcapng'))

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
