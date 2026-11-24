#!/usr/bin/env python3
# Generates test/captures/gssapi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build gssapi-coverage.pcap and gssapi-coverage-malformed.pcap.

GSS-API (packet-gssapi.c) is reached by default through the DNS TSIG
dissector (MAC of algorithm gss-tsig, UDP 53) and through DCE/RPC
authentication type 9 (SPNEGO).  All tokens are placeholders: no keys,
no ciphertext; the Kerberos tickets and authenticators carry constant
bytes.  Usage: mkgssapi.py <outdir> [-v]
"""
import struct
import socket
import sys
import os

def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

ids = [0]
def ip4(src, dst, proto, payload):
    ids[0] += 1
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ids[0], 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def eth(payload):
    return bytes.fromhex('020000000002' '020000000001') + b'\x08\x00' + payload

def udp_frame(payload, src, dst, sport, dport):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ip4(src, dst, 17, u))

def tcp_seg(src, dst, sp, dp, seq, ack, flags, payload=b''):
    opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 2 else b''
    h = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
    ps = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 6, len(h) + len(payload))
    c = csum(ps + h + payload)
    h = h[:16] + struct.pack('>H', c) + h[18:]
    return eth(ip4(src, dst, 6, h + payload))

# ---- DER ----
def tlv(tag, body):
    n = len(body)
    if n < 0x80: l = bytes([n])
    elif n < 0x100: l = b'\x81' + bytes([n])
    else: l = b'\x82' + struct.pack('>H', n)
    return bytes([tag]) + l + body
def seq(*a): return tlv(0x30, b''.join(a))
def ctx(n, body): return tlv(0xa0 + n, body)
def integer(v): return tlv(0x02, bytes([v]))
def gstr(s): return tlv(0x1b, s.encode())
def octets(b): return tlv(0x04, b)
def oid_der(dotted):
    p = [int(x) for x in dotted.split('.')]
    out = bytes([p[0] * 40 + p[1]])
    for v in p[2:]:
        e = [v & 0x7f]; v >>= 7
        while v: e.append(0x80 | (v & 0x7f)); v >>= 7
        out += bytes(reversed(e))
    return tlv(0x06, out)

KRB5 = '1.2.840.113554.1.2.2'
SPNEGO = '1.3.6.1.5.5.2'
NTLM_OID = '1.3.6.1.4.1.311.2.2.10'

def gss(oid, inner, extra_len=0):
    """[APPLICATION 0] { OID, inner }"""
    return tlv(0x60, oid_der(oid) + inner)

def enc_data(etype, kvno, nbytes):
    return seq(ctx(0, integer(etype)), ctx(1, integer(kvno)), ctx(2, octets(b'\x00' * nbytes)))

def ticket(realm, nbytes=24):
    return tlv(0x61, seq(ctx(0, integer(5)), ctx(1, gstr(realm)),
        ctx(2, seq(ctx(0, integer(1)), ctx(1, seq(gstr('host'), gstr('dc1.example.test'))))),
        ctx(3, enc_data(18, 2, nbytes))))

def ap_req(nbytes=24):
    return tlv(0x6e, seq(ctx(0, integer(5)), ctx(1, integer(14)),
        ctx(2, tlv(0x03, b'\x00\x20\x00\x00\x00')), ctx(3, ticket('EXAMPLE.TEST', nbytes)),
        ctx(4, enc_data(18, 0, 32))))

def ap_rep():
    return tlv(0x6f, seq(ctx(0, integer(5)), ctx(1, integer(15)), ctx(2, enc_data(18, 0, 24))))

def krb_err():
    return tlv(0x7e, seq(ctx(0, integer(5)), ctx(1, integer(30)), ctx(4, tlv(0x18, b'20260101000000Z')),
        ctx(5, integer(0)), ctx(6, integer(25)), ctx(9, gstr('EXAMPLE.TEST')),
        ctx(10, seq(ctx(0, integer(1)), ctx(1, seq(gstr('krbtgt'), gstr('EXAMPLE.TEST')))))))

def tgt_req():
    return seq(ctx(0, integer(5)), ctx(1, integer(16)), ctx(2, seq(ctx(0, integer(1)), ctx(1, seq(gstr('krbtgt'))))), ctx(3, gstr('EXAMPLE.TEST')))
def tgt_rep():
    return seq(ctx(0, integer(5)), ctx(1, integer(17)), ctx(2, ticket('EXAMPLE.TEST')))

def krb5_token(inner, tokid=b'\x01\x00'):
    return gss(KRB5, tokid + inner)

def negtokeninit(mechs, mechtoken=None):
    mt = seq(*[oid_der(m) for m in mechs])
    body = ctx(0, mt)
    if mechtoken is not None:
        body += ctx(2, octets(mechtoken))
    return gss(SPNEGO, ctx(0, seq(body)))

# ---- NTLMSSP placeholders (no responses, no keys) ----
def secbuf(length, off):
    return struct.pack('<HHI', length, length, off)
def ntlm_negotiate():
    return b'NTLMSSP\0' + struct.pack('<II', 1, 0xe2088297) + secbuf(0, 0) + secbuf(0, 0)
def ntlm_challenge():
    ti = struct.pack('<HH', 2, 8) + 'EXAMPLE'.encode('utf-16le')[:8] + struct.pack('<HH', 0, 0)
    ti = struct.pack('<HH', 2, 14) + 'EXAMPLE'.encode('utf-16le') + struct.pack('<HH', 0, 0)
    tn = 'EXAMPLE'.encode('utf-16le')
    off = 56
    return (b'NTLMSSP\0' + struct.pack('<I', 2) + secbuf(len(tn), off) + struct.pack('<I', 0xe2898215)
            + bytes(range(1, 9)) + bytes(8) + secbuf(len(ti), off + len(tn)) + bytes(8)) + tn + ti
def ntlm_authenticate():
    return (b'NTLMSSP\0' + struct.pack('<I', 3) + secbuf(0, 72) * 6
            + struct.pack('<I', 0xe2888215) + bytes(8))
def ntlm_payload_blob(n):
    return b'\x01\x00\x00\x00' + bytes(n)

def negoex_nego():
    hdr = b'NEGOEXTS' + struct.pack('<IIII', 0, 0, 96, 128) + bytes(range(16))
    body = bytes(range(32)) + struct.pack('<Q', 0)
    body += struct.pack('<IHH', 96, 2, 0) + struct.pack('<IHH', 128, 0, 0)
    return hdr + body + bytes(range(16)) + bytes(range(16, 32))

DNSQ = 'example.test'
def dns_name(s):
    out = b''
    for l in s.split('.'):
        out += bytes([len(l)]) + l.encode()
    return out + b'\0'

def dns_tsig(qid, mac, resp=False, alg='gss-tsig'):
    hdr = struct.pack('>HHHHHH', qid, 0x8000 if resp else 0x0000, 1, 0, 0, 1)
    q = dns_name(DNSQ) + struct.pack('>HH', 1, 1)
    rdata = dns_name(alg) + b'\0\0\0\0\0\0' + struct.pack('>HH', 300, len(mac)) + mac \
        + struct.pack('>HHH', qid, 0, 0)
    rr = b'\0' + struct.pack('>HHIH', 250, 255, 0, len(rdata)) + rdata
    return hdr + q + rr

C, S = '192.0.2.1', '192.0.2.53'
class Fr(bytes):
    pass

def plain_resp(qid, port):
    p = struct.pack('>HHHHHH', qid, 0x8000, 1, 0, 0, 0) + dns_name(DNSQ) + struct.pack('>HH', 1, 1)
    return udp_frame(p, S, C, 53, port)

class Conv:
    def __init__(self, port):
        self.port = port; self.n = 0
    def q(self, mac, alg='gss-tsig'):
        self.n += 1
        f = Fr(udp_frame(dns_tsig(self.n, mac, False, alg), C, S, self.port, 53))
        f.q = (self.n, self.port)
        return f
    def r(self, mac, alg='gss-tsig'):
        f = Fr(udp_frame(dns_tsig(self.n, mac, True, alg), S, C, 53, self.port))
        f.a = (self.n, self.port)
        return f

def expand(F, marks=()):
    """Add a plain DNS response after each query that has none, so that the
    DNS 'response missing' expert info does not differ between passes."""
    out = []; newpos = {}
    for i, f in enumerate(F):
        newpos[i + 1] = len(out) + 1
        out.append(f)
        if getattr(f, 'q', None):
            nxt = F[i + 1] if i + 1 < len(F) else None
            if not (nxt is not None and getattr(nxt, 'a', None) == f.q):
                out.append(plain_resp(*f.q))
    return out, [(newpos[n], m) for n, m in marks]

def build_main():
    F = []; marks = []
    def mark(name): marks.append((len(F) + 1, name))
    # SPNEGO, Kerberos, user-to-user, MS Kerberos, IAKERB OIDs
    mark('OIDs with a dissector')
    a = Conv(40001)
    F.append(a.q(negtokeninit(['1.2.840.48018.1.2.2', KRB5, '1.3.6.1.4.1.311.2.2.30', NTLM_OID])))
    F.append(a.r(negtokeninit([KRB5])))
    F.append(a.q(krb5_token(ap_req())))
    F.append(a.r(krb5_token(ap_rep(), b'\x02\x00')))
    F.append(a.q(krb5_token(krb_err(), b'\x03\x00')))
    # not an APPLICATION 0 header, the conversation knows the OID now
    mark('non-application token, OID from the conversation')
    F.append(a.r(b'\x02\x01\x00\x00' + bytes(12)))
    F.append(a.q(b'\x02\x01\x00\x00' + bytes(12), 'gss.microsoft.com'))
    b = Conv(40002)
    F.append(b.q(gss('1.2.840.48018.1.2.2', b'\x01\x00' + ap_req())))
    F.append(b.q(gss('1.2.840.113554.1.2.2.3', b'\x04\x00' + tgt_req())))
    F.append(b.q(gss('1.2.840.113554.1.2.2.3', b'\x04\x01' + tgt_rep())))
    F.append(b.q(gss(KRB5, b'\x01\x01' + struct.pack('<H', 0x0000) + b'\xff' * 4 + bytes(8) + bytes(8))))
    F.append(b.q(gss(KRB5, b'\x02\x01' + struct.pack('<HHH', 0x0011, 0xffff, 0xffff) + bytes(8) + bytes(8) + bytes(8) + b'data')))
    F.append(b.q(gss(KRB5, b'\x01\x02')))
    F.append(b.q(gss(KRB5, b'\x04\x04' + bytes([0, 0xff, 0, 0, 0, 0]) + struct.pack('>Q', 4) + bytes(12))))
    F.append(b.q(gss(KRB5, b'\x05\x04' + bytes([0, 0xff, 0, 0, 0, 0]) + struct.pack('>Q', 5) + bytes(28))))
    F.append(b.q(gss(KRB5, b'\x09\x09')))
    F.append(b.q(gss('1.3.6.1.5.2.5', b'\x01\x00' + ap_req())))
    F.append(b.q(gss('1.3.6.1.4.1.311.2.2.40', b'\x01\x00' + ap_req())))
    # NTLMSSP OID tokens and unsigned NTLMSSP
    mark('NTLMSSP')
    c = Conv(40003)
    F.append(c.q(gss(NTLM_OID, ntlm_negotiate())))
    F.append(c.r(ntlm_challenge()))
    F.append(c.q(ntlm_authenticate()))
    F.append(c.r(ntlm_negotiate()))
    F.append(c.q(ntlm_payload_blob(24)))
    F.append(c.r(ntlm_payload_blob(12)))
    F.append(c.q(ntlm_payload_blob(0)[:4] + bytes(12)))   # 16 octets, no encrypted data
    F.append(c.q(ntlm_payload_blob(0)[:4] + bytes(8)))    # too short for either, unknown header
    # CFX wrap tokens
    mark('Kerberos CFX tokens')
    d = Conv(40004)
    F.append(d.q(bytes([5, 4, 0, 0, 0, 0, 0, 0]) + struct.pack('>Q', 1) + bytes(16)))
    F.append(d.r(bytes([4, 4, 0, 0xff, 0, 0, 0, 0]) + struct.pack('>Q', 2) + bytes(12)))
    F.append(d.q(bytes([5, 4, 2, 0xff, 0, 0, 0, 0]) + struct.pack('>Q', 3) + bytes(44)))
    # token without APPLICATION header and no OID known
    mark('unknown header, unknown OID')
    e = Conv(40005)
    F.append(e.q(b'\x30\x08' + bytes(8)))
    F.append(e.r(b'\x17\x00'))
    f = Conv(40006)
    F.append(f.q(gss('1.2.3.4.5', b'\x01\x00' + bytes(10))))
    F.append(f.r(gss('1.3.6.1.4.1.311.2.2.30', negoex_nego())))
    F.append(f.q(gss(NTLM_OID, ntlm_negotiate()), 'gss-tsig'))
    # reassembly: a Kerberos token cut at the end of the first frame is
    # completed by the next frames of the conversation
    mark('reassembly')
    g = Conv(40007)
    tok = krb5_token(ap_req(40))
    F.append(g.q(tok[:30]))
    F.append(g.q(tok[30:70]))
    F.append(g.q(tok[70:]))
    F.append(g.r(krb5_token(ap_rep(), b'\x02\x00')))
    h = Conv(40008)
    tok = negtokeninit([KRB5], krb5_token(ap_req(60)))
    F.append(h.q(tok[:25]))
    F.append(h.q(tok[25:]))
    F.append(h.q(negtokeninit([KRB5])))
    mark('DCE/RPC authentication type 9')
    F += dcerpc_frames()
    return expand(F, marks)

IFACE = bytes.fromhex('c84f324b7016d30112785a47bf6ee188') + struct.pack('<HH', 3, 0)
NDR = bytes.fromhex('045d888aeb1cc9119fe808002b104860') + struct.pack('<HH', 2, 0)
def rpc_pdu(ptype, flags, call, body, auth=b'', auth_level=0, auth_type=9, ctxid=0):
    if auth:
        pad = (-len(body)) % 4
        body += bytes(pad)
        body += struct.pack('<BBBBI', auth_type, auth_level, pad, 0, ctxid) + auth
    alen = len(auth or b"")
    flen = 16 + len(body)
    return struct.pack('<BBBB4sHHI', 5, 0, ptype, flags, b'\x10\0\0\0', flen, alen, call) + body

def dcerpc_conn(cport, bind_tok, ack_tok, auth3_tok, reqs, level=6):
    """One TCP connection with a bind, bind_ack, optional auth3 and requests
    (list of (verifier, level)); every request gets a response."""
    c, s = '192.0.2.1', '192.0.2.50'
    F = []
    st = {'c': 1000, 's': 5000}
    def send(pdu, fromc=True):
        if fromc:
            F.append(tcp_seg(c, s, cport, 135, st['c'], st['s'], 0x18, pdu)); st['c'] += len(pdu)
        else:
            F.append(tcp_seg(s, c, 135, cport, st['s'], st['c'], 0x18, pdu)); st['s'] += len(pdu)
    F.append(tcp_seg(c, s, cport, 135, st['c'] - 1, 0, 0x02))
    F.append(tcp_seg(s, c, 135, cport, st['s'] - 1, st['c'], 0x12))
    F.append(tcp_seg(c, s, cport, 135, st['c'], st['s'], 0x10))
    ctxl = struct.pack('<HBB', 0, 1, 0) + IFACE + NDR
    bind = struct.pack('<HHIBBBB', 4280, 4280, 0, 1, 0, 0, 0) + ctxl
    send(rpc_pdu(11, 3, 1, bind, bind_tok, level))
    ack = struct.pack('<HHIH', 4280, 4280, 0x1234, 4) + b'135\0'
    ack += bytes((-len(ack)) % 4) + struct.pack('<IHHH', 1, 0, 0, 0) + bytes(16) + struct.pack('<I', 0)
    send(rpc_pdu(12, 3, 1, ack, ack_tok, level), False)
    if auth3_tok:
        send(rpc_pdu(16, 3, 1, struct.pack('<HH', 4280, 4280), auth3_tok, level))
    stub = bytes(range(16))
    call = 2
    for verf, lvl in reqs:
        send(rpc_pdu(0, 3, call, struct.pack('<IHH', 16, 0, 99) + stub, verf, lvl))
        send(rpc_pdu(2, 3, call, struct.pack('<IHBB', 16, 0, 0, 0) + stub, verf, lvl), False)
        call += 1
    return F

def dcerpc_frames():
    F = []
    verf = b'\x01\x00\x00\x00' + bytes(12)
    # SPNEGO with NTLMSSP: verifiers at integrity and privacy level
    F += dcerpc_conn(49000, negtokeninit([NTLM_OID], ntlm_negotiate()), ntlm_challenge(),
                     ntlm_authenticate(), [(verf, 5), (verf, 6), (gss(NTLM_OID, verf), 5)])
    # Kerberos: the verifier is a Kerberos wrap token with or without the
    # APPLICATION header
    wrap = b'\x02\x01' + struct.pack('<HHH', 0x0011, 0xffff, 0xffff) + bytes(8) + bytes(8) + bytes(8)
    F += dcerpc_conn(49001, krb5_token(ap_req()), krb5_token(ap_rep(), b'\x02\x00'), None,
                     [(gss(KRB5, wrap), 5), (wrap, 5), (wrap[:2] + b'\xff' * 4 + bytes(24), 6),
                      (bytes([5, 4, 0, 0xff, 0, 0, 0, 0]) + struct.pack('>Q', 1) + bytes(12), 5)], 5)
    # NEGOEX has no handler for verifiers
    F += dcerpc_conn(49002, gss('1.3.6.1.4.1.311.2.2.30', negoex_nego()), None, None,
                     [(gss('1.3.6.1.4.1.311.2.2.30', negoex_nego()), 5), (b'\x30\x03abc', 5)], 5)
    return F

def build_malformed():
    F = []
    # reproducers of the reassembly review (not fixed): one pass and -2 differ
    def gh(len1, extra):
        return b'\x60\x84' + struct.pack('>I', len1) + oid_der(KRB5) + extra
    w = Conv(41001)
    F.append(w.q(gh(0xFFFFFFFE, b'\x01\x00' + b'\x42' * 20)))
    F.append(w.q(b'\x43' * 30))
    F.append(w.q(b'\x44' * 30))
    s = Conv(41002)
    good = krb5_token(ap_rep(), b'\x02\x00')
    F.append(s.q(gh(0x7FFFFFFF, b'\x01\x00' + b'\x42' * 20)))
    F.append(s.r(good))
    F.append(s.q(good))
    F.append(s.r(good))
    # reassembly never completes, and a fragment longer than announced
    t = Conv(41003)
    F.append(t.q(gh(200, b'\x01\x00' + bytes(20))))
    F.append(t.q(bytes(40)))
    F.append(t.q(bytes(300)))
    F.append(t.q(krb5_token(ap_rep(), b'\x02\x00')))
    # tokens that stop inside the OID or the header
    u = Conv(41004)
    F.append(u.q(b'\x60\x20\x06\x09\x2a\x86\x48'))
    F.append(u.q(b'\x60'))
    F.append(u.q(b'\x60\x84\x00'))
    # Kerberos / SPNEGO / NTLMSSP payloads that are cut short
    v = Conv(41005)
    F.append(v.q(gss(KRB5, b'\x01\x00' + ap_req()[:30])))
    F.append(v.q(gss(KRB5, b'\x01\x00\x6e\x82\xff')))
    F.append(v.q(gss(SPNEGO, ctx(0, seq(ctx(0, seq(oid_der(KRB5)))))[:12])))
    F.append(v.q(gss(NTLM_OID, ntlm_negotiate()[:14])))
    F.append(v.q(ntlm_challenge()[:30]))
    F.append(v.q(bytes([5, 4, 0, 0xff, 0, 0])))
    F.append(v.q(bytes([5, 4, 0, 0xff, 0, 0, 0, 0]) + struct.pack('>Q', 1)))
    F.append(v.q(b'\x02\x01'))
    F.append(v.q(b'\x02\x01', 'bogus-alg'))
    # DNS TSIG MAC larger than the packet
    pkt = bytearray(dns_tsig(7, gss(KRB5, b'\x01\x00' + bytes(10))))
    F.append(udp_frame(bytes(pkt[:-12]), C, S, 41006, 53))
    return expand(F)[0]

if __name__ == '__main__':
    out = sys.argv[1]
    F, marks = build_main()
    pcap(os.path.join(out, 'gssapi-coverage.pcap'), F)
    M = build_malformed()
    pcap(os.path.join(out, 'gssapi-coverage-malformed.pcap'), M)
    if '-v' in sys.argv:
        for n, m in marks: print(n, m)
        print('main', len(F), 'malformed', len(M))
