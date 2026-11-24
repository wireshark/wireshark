#!/usr/bin/env python3
# Generates test/captures/kpasswd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the kpasswd coverage captures: mkkpasswd.py <outdir>.

Writes kpasswd-coverage.pcap (UDP and TCP port 464: requests, replies,
KRB-ERROR, TCP reassembly) and kpasswd-coverage-malformed.pcap.
The AP-REQ, AP-REP, KRB-PRIV and ticket carry placeholder bytes in
every encrypted part; no keys exist, so the decrypted ChangePasswdData
and result code paths stay uncovered.
"""
import os
import struct
import sys
from pylib import Pcap, Tcp, eth_udp

PORT = 464

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

# ---- kpasswd framing -------------------------------------------------
def kpasswd(version, ap, priv):
    body = struct.pack('>HHH', 6 + len(ap) + len(priv), version, len(ap)) + ap + priv
    return body

def request(**kw):
    return kpasswd(0xff80, ap_req(**kw), krb_priv())

def reply(**kw):
    return kpasswd(0x0001, ap_rep(**kw), krb_priv(bytes([0xb1] * 40)))

def rm(pdu):
    return struct.pack('>I', 0x80000000 | len(pdu)) + pdu

def main(out):
    p = Pcap()
    def udp(data, rev=False, sport=45000):
        sp, dp = (PORT, sport) if rev else (sport, PORT)
        p.add(eth_udp(sp, dp, data, rev=rev))

    # 1-6 UDP
    udp(request())
    udp(reply(), rev=True)
    udp(krb_error(0x18, etext=None), rev=True)                  # KRB-ERROR, no e-data
    udp(krb_error(0x1e, edata=struct.pack('>H', 3) + b'denied by policy'), rev=True)
    udp(kpasswd(0x0002, ap_rep(), krb_priv()), rev=True)        # unknown version
    udp(request(cipher=bytes([0xa2] * 300), tkt=ticket(cipher=bytes([0xc1] * 260))), sport=45001)

    # TCP stream 1: request, reply, KRB-ERROR, two PDUs in one segment
    t = Tcp(p, sport=50464, dport=PORT)
    t.seg(b'', True, 0x02)
    t.seg(b'', False, 0x12)
    t.seg(b'', True, 0x10)
    t.seg(rm(request()), True)                                  # 10
    r = rm(reply())
    t.seg(r[:30], False)                                        # reassembled over two segments
    t.seg(r[30:], False)
    t.seg(rm(krb_error(0x18)), False)
    t.seg(rm(request()) + rm(request(cipher=bytes([0xa3] * 16))), True)
    t.seg(rm(reply()) + rm(krb_error(0x1d, etext='no such principal'))[:20], False)
    t.seg(rm(krb_error(0x1d, etext='no such principal'))[20:], False)
    t.seg(b'', True, 0x11)
    p.write(os.path.join(out, 'kpasswd-coverage.pcap'))

    m = Pcap()
    def mudp(data, rev=False):
        sp, dp = (PORT, 45100) if rev else (45100, PORT)
        m.add(eth_udp(sp, dp, data, rev=rev))
    q = request()
    mudp(q[:4])                       # shorter than the header
    mudp(q[:6])                       # no AP-REQ
    mudp(q[:40])                      # AP-REQ cut
    mudp(q[:6 + len(ap_req())])       # no KRB-PRIV
    mudp(struct.pack('>HHH', 0xffff, 0xff80, 0x4000) + q[6:])     # AP-REQ length beyond the packet
    mudp(kpasswd(0xff80, b'\x00\x01\x02', krb_priv()))            # AP-REQ is not ASN.1
    mudp(kpasswd(0xff80, ap_req(), b'\xff\xff'))                  # KRB-PRIV garbage
    mudp(kpasswd(0x0001, ap_rep(), krb_priv()[:20]), rev=True)
    mudp(krb_error(0x18)[:30], rev=True)                          # KRB-ERROR cut
    mudp(b'\x7e')
    m2 = Tcp(m, sport=50465, dport=PORT)
    m2.seg(b'', True, 0x02)
    m2.seg(b'', False, 0x12)
    m2.seg(b'', True, 0x10)
    m2.seg(rm(request())[:20], True)  # incomplete PDU, never completed
    m2.seg(struct.pack('>I', 0x80000000 | 0x00a00001) + b'\x00' * 40, True)   # > 10 MB record
    m2.seg(struct.pack('>I', 0x80000000 | 12) + b'\x00\x0c\xff\x80\x00\x00' + b'\x01' * 6, True)
    m.write(os.path.join(out, 'kpasswd-coverage-malformed.pcap'))

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
