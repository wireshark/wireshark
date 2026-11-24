#!/usr/bin/env python3
# Generates test/captures/spnego_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SPNEGO coverage captures.  Usage: mkspnego.py <outdir>
All packets are synthetic.  SPNEGO tokens are carried in HTTP "Negotiate"
authentication (TCP port 80), GSS-API wrap and MIC tokens in LDAP SASL
buffers (TCP port 389).  Kerberos messages and NTLMSSP messages inside the
tokens carry filler octets instead of cryptographic values (no keys, no
real ciphertext, no hashes)."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import base64
import struct
from berlib import bitstr, boolean, gz, integer, octets, oid, seq, TcpStream, tlv, write_pcap

SPNEGO = '1.3.6.1.5.5.2'
KRB5 = '1.2.840.113554.1.2.2'
MSKRB5 = '1.2.840.48018.1.2.2'
KRB5U2U = '1.2.840.113554.1.2.2.3'
IAKERB = '1.3.6.1.5.2.5'
NTLMSSP = '1.3.6.1.4.1.311.2.2.10'
NEGOEX = '1.3.6.1.4.1.311.2.2.30'
FALLBACK = '1.3.6.1.4.1.311.2.2.40'
UNKNOWN = '1.3.6.1.4.1.99999.1'

def ctx(n, v): return tlv(0xa0 | n, v)
def app(n, v): return tlv(0x60 | n, v)

# ---- SPNEGO ----
def mechs(*oids): return seq(*[oid(o) for o in oids])
def neg_init(mech_list=None, flags=None, token=None, mic=None, hints=None, init2=False):
    b = b''
    if mech_list: b += ctx(0, mechs(*mech_list))
    if flags is not None: b += ctx(1, bitstr(bytes([flags]), 1))
    if token is not None: b += ctx(2, octets(token))
    if hints is not None:
        hb = b''
        if hints[0] is not None: hb += ctx(0, tlv(0x1b, hints[0].encode()))
        if hints[1] is not None: hb += ctx(1, octets(hints[1]))
        b += ctx(3, seq(hb))
    if mic is not None: b += ctx(4 if init2 else 3, octets(mic))
    return ctx(0, seq(b))
def neg_targ(result=None, mech=None, token=None, mic=None, mechlist=None):
    b = b''
    if result is not None: b += ctx(0, tlv(0x0a, bytes([result])))
    if mech is not None: b += ctx(1, oid(mech))
    if token is not None: b += ctx(2, octets(token))
    if mic is not None: b += ctx(3, octets(mic))
    if mechlist: b += ctx(4, mechs(*mechlist))
    return ctx(1, seq(b))
def gss(mech, inner): return app(0, oid(mech) + inner)

# ---- NTLMSSP (no crypto: negotiate, challenge, anonymous authenticate) ----
def secbuf(length, offset): return struct.pack('<HHI', length, length, offset)
VER = struct.pack('<BBHBBBB', 10, 0, 19041, 0, 0, 0, 15)
def ntlm_negotiate():
    return b'NTLMSSP\0' + struct.pack('<II', 1, 0xe2088297) + secbuf(0, 40) + secbuf(0, 40) + VER
def ntlm_challenge():
    name = 'EXAMPLE'.encode('utf-16le')
    av = struct.pack('<HH', 2, len(name)) + name + struct.pack('<HH', 1, len(name)) + name + struct.pack('<HH', 0, 0)
    return (b'NTLMSSP\0' + struct.pack('<I', 2) + secbuf(len(name), 56) + struct.pack('<I', 0xe2898215)
            + bytes(range(1, 9)) + b'\0' * 8 + secbuf(len(av), 56 + len(name)) + VER + name + av)
def ntlm_authenticate():
    return (b'NTLMSSP\0' + struct.pack('<I', 3) + secbuf(1, 72) + secbuf(0, 73) + secbuf(0, 73) + secbuf(0, 73)
            + secbuf(0, 73) + secbuf(0, 73) + struct.pack('<I', 0xe2088297) + VER + b'\0')
def ntlm_mic():            # version, checksum, sequence number: filler, not a real signature
    return struct.pack('<I', 1) + b'\x00' * 8 + struct.pack('<I', 0)

# ---- Kerberos (filler instead of ciphertext) ----
def gstr(s): return tlv(0x1b, s.encode())
def princ(ntype, *names): return seq(ctx(0, integer(ntype)), ctx(1, seq(*[gstr(n) for n in names])))
def enc_data(etype=18, kvno=None, n=48):
    b = ctx(0, integer(etype))
    if kvno is not None: b += ctx(1, integer(kvno))
    return seq(b + ctx(2, octets(bytes((i * 3) & 0xff for i in range(n)))))
def ticket(realm='EXAMPLE.COM', name=('host', 'server.example.com')):
    return app(1, seq(ctx(0, integer(5)), ctx(1, gstr(realm)), ctx(2, princ(2, *name)), ctx(3, enc_data(18, 2, 64))))
def ap_req():
    return tlv(0x6e, seq(ctx(0, integer(5)), ctx(1, integer(14)), ctx(2, bitstr(b'\x20\x00\x00\x00', 0)),
                         ctx(3, ticket()), ctx(4, enc_data(18, None, 40))))
def ap_rep():
    return tlv(0x6f, seq(ctx(0, integer(5)), ctx(1, integer(15)), ctx(2, enc_data(18, None, 24))))
def krb_error():
    return tlv(0x7e, seq(ctx(0, integer(5)), ctx(1, integer(30)), ctx(4, tlv(0x18, b'20250101000000Z')),
                         ctx(5, integer(1)), ctx(6, integer(25)), ctx(9, gstr('EXAMPLE.COM')),
                         ctx(10, princ(2, 'krbtgt', 'EXAMPLE.COM'))))
def as_req():
    body = seq(ctx(0, bitstr(b'\x40\x81\x00\x10', 0)), ctx(1, princ(1, 'user')), ctx(2, gstr('EXAMPLE.COM')),
               ctx(3, princ(2, 'krbtgt', 'EXAMPLE.COM')), ctx(5, tlv(0x18, b'20260101000000Z')),
               ctx(7, integer(12345)), ctx(8, seq(integer(18))))
    return tlv(0x6a, seq(ctx(1, integer(5)), ctx(2, integer(10)), ctx(4, body)))
def tgt_req(): return seq(ctx(0, integer(5)), ctx(1, integer(16)), ctx(2, princ(2, 'krbtgt', 'EXAMPLE.COM')), ctx(3, gstr('EXAMPLE.COM')))
def tgt_rep(): return seq(ctx(0, integer(5)), ctx(1, integer(17)), ctx(2, ticket('EXAMPLE.COM', ('krbtgt', 'EXAMPLE.COM'))))
def iakerb_header(realm='EXAMPLE.COM', cookie=None, flags=None, octet_realm=False):
    r = octets(realm) if octet_realm else tlv(0x0c, realm.encode())
    b = ctx(1, r)
    if cookie is not None: b += ctx(2, octets(cookie))
    if flags is not None: b += ctx(3, bitstr(struct.pack('>I', flags), 0))
    return seq(b)

def tokid(n): return struct.pack('<H', n)
def krb_token(mech, tid, body=b''): return app(0, oid(mech) + tokid(tid) + body)

# ---- GSS wrap / MIC tokens (RFC 1964 and RFC 4121), filler checksums ----
def krb_wrap(sgn=0x11, seal=0x10, data=b'', conf=True):
    t = tokid(0x0102) + struct.pack('<HHH', sgn, seal, 0xffff) + b'\x11' * 8 + b'\x22' * 8
    if sgn in (0x11, 0x00): t += b'\x33' * 8        # confounder
    return t + data
def krb_getmic(sgn=0x11, conf=True):
    t = tokid(0x0101) + struct.pack('<H', sgn) + b'\xff' * 4 + b'\x11' * 8 + b'\x22' * 8
    if sgn == 0x11: t += b'\x33' * 8
    return t
def cfx_wrap(flags, ec=12, rrc=0, seqno=1, data=b'', cksum=b'\x44' * 12):
    hdr = tokid(0x0405) + bytes([flags, 0xff]) + struct.pack('>HHQ', ec, rrc, seqno)
    if flags & 2:          # sealed: the dissector shows 44 + EC octets of (here: filler) checksum/ciphertext
        return hdr + b'\x5a' * (44 + ec + 30)
    if rrc == ec:          # checksum rotated in front of the data
        return hdr + cksum + data
    return hdr + data + cksum
def cfx_getmic(flags, seqno=1, cksum=b'\x44' * 12):
    return tokid(0x0404) + bytes([flags]) + b'\xff' * 5 + struct.pack('>Q', seqno) + cksum

# ---- HTTP ----
def http_req(auth=None, path='/'):
    h = 'GET %s HTTP/1.1\r\nHost: www.example.com\r\n' % path
    if auth is not None: h += 'Authorization: Negotiate %s\r\n' % base64.b64encode(auth).decode()
    return (h + '\r\n').encode()
def http_rsp(code, auth=None, body=b''):
    h = 'HTTP/1.1 %s\r\nContent-Length: %d\r\n' % (code, len(body))
    if auth is not None: h += 'WWW-Authenticate: Negotiate%s\r\n' % ((' ' + base64.b64encode(auth).decode()) if auth else '')
    return (h + '\r\n').encode() + body

# ---- LDAP ----
def ldap_bind(msgid, mech, creds):
    return seq(integer(msgid), tlv(0x60, integer(3) + octets(b'') + tlv(0xa3, octets(mech) + octets(creds))))
def ldap_bind_rsp(msgid, code, creds=None):
    b = tlv(0x0a, bytes([code])) + octets(b'') + octets(b'')
    if creds is not None: b += tlv(0x87, creds)
    return seq(integer(msgid), tlv(0x61, b))
def ldap_search(msgid):
    f = tlv(0x87, b'objectClass')
    return seq(integer(msgid), tlv(0x63, octets(b'dc=example,dc=com') + tlv(0x0a, b'\x02') + tlv(0x0a, b'\x00')
                                  + integer(0) + integer(0) + boolean(False) + f + seq()))
def sasl(tok, data=b''): return struct.pack('>I', len(tok) + len(data)) + tok + data

def main(out):
    f = []
    t = [1750000000.0]
    def add(fr): t[0] += 0.02; f.append((t[0], fr))
    port = [40000]
    def conn(sp, items):
        s = TcpStream(port[0], sp); port[0] += 1
        for fr in s.handshake(): add(fr)
        for who, b in items:
            add(s.c2s(b) if who == 'c' else s.s2c(b))
        return s

    ntlm_mechs = [NTLMSSP]
    # --- 1: NTLM through SPNEGO: negTokenInit with a mechToken, negTokenTarg with a challenge,
    #        negTokenTarg with the response and the mechListMIC, final negTokenTarg
    conn(80, [
        ('c', http_req()),
        ('s', http_rsp('401 Unauthorized', b'')),
        ('c', http_req(gss(SPNEGO, neg_init([NTLMSSP, KRB5], 0x7e, ntlm_negotiate())))),
        ('s', http_rsp('401 Unauthorized', neg_targ(1, NTLMSSP, ntlm_challenge()))),
        ('c', http_req(neg_targ(None, None, ntlm_authenticate(), ntlm_mic()))),
        ('s', http_rsp('200 OK', neg_targ(0, None, None, ntlm_mic()))),
    ])
    # --- 2: Kerberos through SPNEGO (AP-REQ / AP-REP in GSS-API tokens)
    conn(80, [
        ('c', http_req(gss(SPNEGO, neg_init([MSKRB5, KRB5, NTLMSSP], 0x62,
                                           app(0, oid(KRB5) + tokid(1) + ap_req()),
                                           ntlm_mic())))),
        ('s', http_rsp('200 OK', neg_targ(0, KRB5, app(0, oid(KRB5) + tokid(2) + ap_rep()), ntlm_mic()))),
        # the Kerberos messages directly as mechToken / responseToken (no GSS-API header)
        ('c', http_req(gss(SPNEGO, neg_init([KRB5], 0x02, ap_req())))),
        ('s', http_rsp('200 OK', neg_targ(0, KRB5, ap_rep()))),
    ])
    # --- 3: server sent negTokenInit2 with negHints (the response direction), reject and request-mic
    conn(80, [
        ('c', http_req()),
        ('s', http_rsp('401 Unauthorized', gss(SPNEGO, neg_init([KRB5U2U, MSKRB5, KRB5, NTLMSSP], None, None,
                                                                 b'\x01' * 16, ('not_defined_in_RFC4178@please_ignore', b'host'), True)))),
        ('c', http_req(gss(SPNEGO, neg_init([NTLMSSP], None, ntlm_negotiate())))),
        ('s', http_rsp('401 Unauthorized', neg_targ(3, KRB5, b'', None, [KRB5, NTLMSSP]))),
        ('c', http_req(neg_targ(1, None, b'\x01\x02'))),
        ('s', http_rsp('401 Unauthorized', neg_targ(2))),
    ])
    # --- 4: unknown mechanisms, empty and absent fields, NegoEx and the late fallback OID
    conn(80, [
        ('c', http_req(gss(SPNEGO, neg_init([UNKNOWN], 0x02, b'unknown token')))),
        ('s', http_rsp('401 Unauthorized', neg_targ(1, UNKNOWN, b'\xaa\xbb', b'\xcc'))),
        ('c', http_req(gss(SPNEGO, neg_init([NEGOEX, FALLBACK], 0x00, b'')))),
        ('s', http_rsp('401 Unauthorized', neg_targ(1, FALLBACK, tokid(1) + ap_req()))),
        ('c', http_req(gss(SPNEGO, neg_init()))),
        ('s', http_rsp('401 Unauthorized', neg_targ())),
        ('c', http_req(gss(SPNEGO, neg_init([NTLMSSP], None, None, ntlm_mic())))),
        ('s', http_rsp('401 Unauthorized', neg_targ(1, NTLMSSP, None, ntlm_mic()))),
    ])
    # --- 5: Kerberos mechanism used directly (no SPNEGO): every token id of the krb5 handler
    conn(80, [
        ('c', http_req(krb_token(KRB5, 1, ap_req()))),
        ('s', http_rsp('200 OK', krb_token(KRB5, 2, ap_rep()))),
        ('c', http_req(krb_token(MSKRB5, 1, ap_req()))),
        ('s', http_rsp('401 Unauthorized', krb_token(KRB5, 3, krb_error()))),
        ('c', http_req(krb_token(KRB5U2U, 4, tgt_req()))),
        ('s', http_rsp('401 Unauthorized', krb_token(KRB5U2U, 0x0104, tgt_rep()))),
        ('c', http_req(krb_token(KRB5, 0x0201))),
        ('s', http_rsp('401 Unauthorized', krb_token(KRB5, 0x0999, b'\x00\x01'))),
        ('c', http_req(krb_token(IAKERB, 0x0105, iakerb_header('EXAMPLE.COM', b'cookie', 0x00400000) + as_req()))),
        ('s', http_rsp('401 Unauthorized', krb_token(IAKERB, 0x0105, iakerb_header('EXAMPLE.COM', None, None, True)))),
        # GSS-API MIC and wrap tokens of the Kerberos mechanism (RFC 1964 and RFC 4121)
        ('c', http_req(gss(KRB5, krb_getmic(0x11)))),
        ('s', http_rsp('401 Unauthorized', gss(KRB5, krb_getmic(0x00)))),
        ('c', http_req(gss(KRB5, krb_wrap(0x11, 0x10, b'\x01\x02\x03')))),
        ('s', http_rsp('401 Unauthorized', gss(KRB5, krb_wrap(0x00, 0xffff)))),
        ('c', http_req(cfx_getmic(0x04))),
        ('s', http_rsp('401 Unauthorized', cfx_getmic(0x01, 2, b'\x44' * 16))),
        ('c', http_req(gss(KRB5, cfx_getmic(0x04)))),
        ('s', http_rsp('401 Unauthorized', gss(KRB5, cfx_wrap(0x00, 12, 0, 7, b'\x02' * 6)))),
        ('c', http_req(cfx_wrap(0x02, 12, 0, 5))),
        ('s', http_rsp('401 Unauthorized', cfx_wrap(0x05, 12, 12, 6, b'\x01' * 10))),
    ])
    # --- GSS-API wrap and MIC tokens in LDAP SASL buffers (bind with SPNEGO, then signed/sealed data)
    def ldap_session(sp, mech_oid_list, mech_for_tokens, tokens):
        init = gss(SPNEGO, neg_init(mech_oid_list, 0x7e, app(0, oid(mech_for_tokens) + tokid(1) + ap_req())))
        items = [
            ('c', ldap_bind(1, b'GSS-SPNEGO', init)),
            ('s', ldap_bind_rsp(1, 14, neg_targ(1, mech_for_tokens, app(0, oid(mech_for_tokens) + tokid(2) + ap_rep())))),
            ('c', ldap_bind(2, b'GSS-SPNEGO', b'')),
            ('s', ldap_bind_rsp(2, 0, neg_targ(0))),
        ]
        for who, tok in tokens: items.append((who, tok))
        conn(sp, items)
    msg = ldap_search(3)
    ldap_session(389, [KRB5, NTLMSSP], KRB5, [
        ('c', sasl(gss(KRB5, krb_wrap(0x11, 0x10)), msg)),
        ('s', sasl(gss(KRB5, krb_wrap(0x11, 0xffff)), msg)),
        ('c', sasl(gss(KRB5, krb_wrap(0x00, 0x00)), msg)),
        ('c', sasl(gss(KRB5, krb_getmic(0x11)), msg)),
        ('c', sasl(gss(KRB5, krb_getmic(0x00)), msg)),
        ('c', sasl(cfx_wrap(0x00, 12, 0, 1, msg))),
        ('s', sasl(cfx_wrap(0x01, 12, 12, 2, msg))),
        ('c', sasl(cfx_wrap(0x04, 12, 0, 3, msg))),
        ('s', sasl(cfx_wrap(0x07, 4, 28, 4))),
    ])
    write_pcap(os.path.join(out, 'spnego-coverage.pcap'), f)
    gz(os.path.join(out, 'spnego-coverage.pcap'), os.path.join(out, 'spnego_coverage.pcap.gz'))

def malformed(out):
    f = []
    t = [1750000000.0]
    def add(fr): t[0] += 0.02; f.append((t[0], fr))
    port = [41000]
    def conn(sp, items):
        s = TcpStream(port[0], sp); port[0] += 1
        for fr in s.handshake(): add(fr)
        for who, b in items:
            add(s.c2s(b) if who == 'c' else s.s2c(b))
    # Kerberos messages and SPNEGO tokens without the GSS-API header: the GSS-API dissector warns
    conn(80, [
        ('c', http_req(ap_req())),
        ('s', http_rsp('200 OK', ap_rep())),
        ('c', http_req(tlv(0x7d, seq(integer(1))))),
        ('s', http_rsp('401 Unauthorized', tokid(0x0001) + ap_req())),
        ('c', http_req(neg_init([NTLMSSP], 0x02, ntlm_negotiate()))),
        ('s', http_rsp('401 Unauthorized', neg_targ(1, NTLMSSP, ntlm_challenge()))),
        ('c', http_req(neg_targ(None, None, ntlm_authenticate()))),
        ('s', http_rsp('200 OK', neg_targ(0))),
    ])
    # Kerberos token in the SPNEGO mechToken with a header that is not [APPLICATION 0/14/15]
    conn(80, [
        ('c', http_req(gss(SPNEGO, neg_init([KRB5], 0x02, tlv(0x7d, seq(integer(1))))))),
        ('s', http_rsp('401 Unauthorized', neg_targ(1, KRB5, tlv(0x30, b'\x01\x02')))),
        ('c', http_req(gss(SPNEGO, neg_init([KRB5], 0x02, b'\x04\x00\x01')))),
    ])
    # truncated tokens
    full = gss(SPNEGO, neg_init([MSKRB5, KRB5, NTLMSSP], 0x62, app(0, oid(KRB5) + tokid(1) + ap_req()), ntlm_mic()))
    for n in (5, 12, 20, 40, 80, len(full) - 3):
        conn(80, [('c', http_req(full[:n]))])
    full = gss(SPNEGO, neg_targ(1, KRB5, app(0, oid(KRB5) + tokid(2) + ap_rep()), ntlm_mic()))
    for n in (5, 12, 30, len(full) - 3):
        conn(80, [('s', http_rsp('200 OK', full[:n]))])
    # wrap and MIC tokens cut short
    for tok in (gss(KRB5, krb_wrap(0x11, 0x10))[:20], gss(KRB5, krb_getmic(0x11))[:24], cfx_wrap(0x04)[:10],
                cfx_wrap(0x01)[:20], cfx_getmic(0x04)[:12]):
        conn(389, [
            ('c', ldap_bind(1, b'GSS-SPNEGO', gss(SPNEGO, neg_init([KRB5], 0x7e, app(0, oid(KRB5) + tokid(1) + ap_req()))))),
            ('s', ldap_bind_rsp(1, 0, neg_targ(0, KRB5))),
            ('c', sasl(tok)),
        ])
    # a GSS-API wrap token inside a SPNEGO wrap token (SPNEGO's own wrap handler: the plaintext
    # that follows is decoded from the wrong offset)
    for tok in (gss(SPNEGO, gss(KRB5, krb_wrap(0x11, 0xffff))), gss(SPNEGO, gss(KRB5, krb_getmic(0x11))),
                gss(SPNEGO, gss(UNKNOWN, b'\x01\x02')), gss(SPNEGO, gss(NTLMSSP, b'\x01\x02'))):
        conn(389, [
            ('c', ldap_bind(1, b'GSS-SPNEGO', gss(SPNEGO, neg_init([KRB5], 0x7e, app(0, oid(KRB5) + tokid(1) + ap_req()))))),
            ('s', ldap_bind_rsp(1, 0, neg_targ(0, KRB5))),
            ('c', sasl(tok, ldap_search(3))),
        ])
    # the fixed recursion: a negTokenInit that names SPNEGO as mechanism and carries another one as
    # mechToken (HTTP), and nested SPNEGO wrap tokens (LDAP SASL buffer), a few levels past the
    # limit of 8
    inner = b'\x05\x00'
    smech = ctx(0, seq(oid(SPNEGO)))
    for i in range(12):
        inner = ctx(0, seq(smech + ctx(2, octets(inner))))
    conn(80, [('c', http_req(gss(SPNEGO, inner)))])
    tok = b'\x01\x02'
    for i in range(12):
        tok = gss(SPNEGO, tok)
    conn(389, [
        ('c', ldap_bind(1, b'GSS-SPNEGO', gss(SPNEGO, neg_init([KRB5], 0x7e, app(0, oid(KRB5) + tokid(1) + ap_req()))))),
        ('s', ldap_bind_rsp(1, 0, neg_targ(0, KRB5))),
        ('c', sasl(tok, ldap_search(3))),
    ])
    # an indefinite length, an unknown choice and tokens of the wrong type
    for tok in (b'\x60\x80\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x80\x30\x80\x00\x00\x00\x00\x00\x00',
                gss(SPNEGO, b'\xa2\x00'), gss(SPNEGO, ctx(0, integer(1))), gss(SPNEGO, ctx(1, octets(b'x'))),
                b'\x60\x03\x06\x01'):
        conn(80, [('c', http_req(tok))])
    write_pcap(os.path.join(out, 'spnego-coverage-malformed.pcap'), f)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
    malformed(sys.argv[1] if len(sys.argv) > 1 else '.')
