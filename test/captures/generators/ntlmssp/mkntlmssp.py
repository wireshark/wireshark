#!/usr/bin/env python3
# Generates test/captures/ntlmssp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the NTLMSSP coverage captures.

  ntlmssp-coverage.pcapng            main capture (Ethernet + Exported PDU)
  ntlmssp-coverage-malformed.pcapng  frames that raise exceptions

NTLMSSP is reached the way real traffic reaches it: HTTP (Authorization:
NTLM / WWW-Authenticate: NTLM, base64), DCE/RPC authentication type 10
(bind, bind_ack, auth3, request and response verifiers, privacy level),
LDAP SASL GSS-SPNEGO binds and the SASL security layer, and Exported PDU
for the helper dissectors that have no transport of their own
(ntlmssp, ntlmssp_payload, ntlmssp_data_only, ntlmssp_verf).

No keys, no passwords and no ciphertext are produced.  The only key
state is the "anonymous" one the dissector derives itself: an
AUTHENTICATE with empty LM/NT responses and a placeholder (constant
bytes) EncryptedRandomSessionKey.  Responses, proofs and the MIC are
constant bytes too.  Usage: mkntlmssp.py <outdir>
"""
import base64
import os
import socket
import struct
import sys

# ---------------------------------------------------------------- pcapng
def blk(btype, body):
    body += b'\0' * ((-len(body)) % 4)
    n = 12 + len(body)
    return struct.pack('<II', btype, n) + body + struct.pack('<I', n)

def write_pcapng(path, frames):
    """frames: list of (ifid, bytes)"""
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += blk(1, struct.pack('<HHI', 1, 0, 65535))      # Ethernet
    out += blk(1, struct.pack('<HHI', 252, 0, 65535))    # Exported PDU
    for i, (ifid, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += blk(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    with open(path, 'wb') as f:
        f.write(out)

# ---------------------------------------------------------------- IP/TCP
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

ipid = [0]
def eth_ip(src, dst, proto, payload, smac, dmac):
    ipid[0] += 1
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ipid[0], 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return dmac + smac + b'\x08\x00' + h + payload

CMAC = bytes.fromhex('020000000001'); SMAC = bytes.fromhex('020000000002')
CIP, SIP = '192.0.2.1', '192.0.2.2'

class Tcp:
    def __init__(self, cport, sport, out):
        self.cp, self.sp, self.out = cport, sport, out
        self.cs, self.ss = 1000, 5000
        self._seg(True, 0x02, b'', consume=1)
        self._seg(False, 0x12, b'', consume=1)
        self._seg(True, 0x10, b'')
    def _seg(self, to_srv, flags, payload, consume=0):
        if to_srv:
            src, dst, sp, dp, seq, ack = CIP, SIP, self.cp, self.sp, self.cs, self.ss
            sm, dm = CMAC, SMAC
        else:
            src, dst, sp, dp, seq, ack = SIP, CIP, self.sp, self.cp, self.ss, self.cs
            sm, dm = SMAC, CMAC
        if not (flags & 0x10): ack = 0
        h = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0)
        ps = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 6, len(h) + len(payload))
        h = h[:16] + struct.pack('>H', csum(ps + h + payload)) + h[18:]
        self.out.append((0, eth_ip(src, dst, 6, h + payload, sm, dm)))
        n = len(payload) + consume
        if to_srv: self.cs += n
        else: self.ss += n
    def send(self, to_srv, payload):
        self._seg(to_srv, 0x18, payload)
    def close(self):
        self._seg(True, 0x11, b'', consume=1)
        self._seg(False, 0x11, b'', consume=1)
        self._seg(True, 0x10, b'')

# ---------------------------------------------------------------- Exported PDU
def etlv(tag, val):
    val += b'\0' * ((-len(val)) % 4)
    return struct.pack('!HH', tag, len(val)) + val

def exp_pdu(name, payload, dport=389, sport=40000):
    h = etlv(12, name.encode())
    h += etlv(20, bytes([192, 0, 2, 1])) + etlv(21, bytes([192, 0, 2, 2]))
    h += etlv(24, struct.pack('!I', 2))                     # EXP_PDU_PT_TCP
    h += etlv(25, struct.pack('!I', sport)) + etlv(26, struct.pack('!I', dport))
    h += struct.pack('!HH', 0, 0)
    return (1, h + payload)

# ---------------------------------------------------------------- NTLMSSP messages
UNICODE, OEM, REQ_TARGET, SIGN, SEAL, DATAGRAM, LM_KEY, NTLM = 1, 2, 4, 0x10, 0x20, 0x40, 0x80, 0x200
ANON, OEM_DOM, OEM_WS, ALWAYS_SIGN = 0x800, 0x1000, 0x2000, 0x8000
NONNT = 0x400000
TGT_DOM, TGT_SRV, ESS, IDENTIFY, TGT_INFO = 0x10000, 0x20000, 0x80000, 0x100000, 0x800000
VERSION, N128, KEY_EXCH, N56 = 0x2000000, 0x20000000, 0x40000000, 0x80000000

TYPICAL = UNICODE | OEM | REQ_TARGET | SIGN | SEAL | NTLM | ALWAYS_SIGN | TGT_DOM | ESS | TGT_INFO | VERSION | N128 | KEY_EXCH | N56
VER = struct.pack('<BBHBBBB', 10, 0, 19041, 0, 0, 0, 15)
SIG = b'NTLMSSP\0'

def sb(length, off):
    return struct.pack('<HHI', length, length, off)

def u16(s):
    return s.encode('utf-16-le')

def av(t, v):
    return struct.pack('<HH', t, len(v)) + v

def target_info(full=True):
    ti = av(1, u16('SRV1')) + av(2, u16('EXAMPLE')) + av(3, u16('srv1.example.test')) \
        + av(4, u16('example.test')) + av(5, u16('test'))
    ti += av(6, struct.pack('<I', 2)) + av(7, struct.pack('<Q', 133500000000000000))
    ti += av(8, bytes(range(48))) + av(9, u16('cifs/srv1')) + av(10, bytes(range(16)))
    return ti + av(0, b'')

def negotiate(flags=TYPICAL, domain=b'EXAMPLE', ws=b'CLIENT1', version=True):
    hl = 32 + (8 if version else 0)
    m = SIG + struct.pack('<II', 1, flags) + sb(len(domain), hl) + sb(len(ws), hl + len(domain))
    if version: m += VER
    return m + domain + ws

def challenge(flags=TYPICAL, tname='EXAMPLE', ti=None, chal=bytes(range(1, 9)), layout='full'):
    uni = bool(flags & UNICODE)
    tn = u16(tname) if uni else tname.encode()
    ti = target_info() if ti is None else ti
    if layout == 'short':           # Win9x style: no reserved, no target info
        return SIG + struct.pack('<I', 2) + sb(len(tn), 32) + struct.pack('<I', flags) + chal + tn
    if layout == 'noti':            # reserved but no target info field
        return SIG + struct.pack('<I', 2) + sb(len(tn), 40) + struct.pack('<I', flags) + chal + bytes(8) + tn
    hl = 48 + (8 if layout == 'full' else 0)
    m = SIG + struct.pack('<I', 2) + sb(len(tn), hl) + struct.pack('<I', flags) + chal + bytes(8) \
        + sb(len(ti), hl + len(tn))
    if layout == 'full': m += VER
    return m + tn + ti

def ntlmv2_resp(avs=None, trail=4):
    avs = avs if avs is not None else (av(2, u16('EXAMPLE')) + av(1, u16('CLIENT1')) + av(3, u16('client1.example.test'))
          + av(6, struct.pack('<I', 2)) + av(7, struct.pack('<Q', 133500000000000000))
          + av(9, u16('cifs/srv1')) + av(10, bytes(range(16))) + av(8, bytes(range(48))) + av(0, b''))
    return bytes(range(0x30, 0x40)) + b'\x01\x01' + bytes(6) + struct.pack('<Q', 133500000000000000) \
        + bytes(range(0x50, 0x58)) + bytes(4) + avs + bytes(trail)

def authenticate(flags=TYPICAL, lm=b'', nt=b'', domain='EXAMPLE', user='user1', host='CLIENT1',
                 skey=b'', layout='mic', uni=None, dom_off_adj=0):
    """layout: min (no session key), key (+session key), flags (+flags), ver (+version/zero), mic (+MIC)"""
    uni = bool(flags & UNICODE) if uni is None else uni
    enc = (lambda s: u16(s)) if uni else (lambda s: s.encode())
    d, u, h = enc(domain), enc(user), enc(host)
    hl = {'min': 52, 'key': 60, 'flags': 64, 'ver': 72, 'mic': 88}[layout]
    off = hl
    fields = []
    for blob in (lm, nt, d, u, h):
        fields.append(sb(len(blob), off if blob else off)); off += len(blob)
    m = SIG + struct.pack('<I', 3) + b''.join(fields)
    if layout != 'min': m += sb(len(skey), off)
    if layout in ('flags', 'ver', 'mic'): m += struct.pack('<I', flags)
    if layout in ('ver', 'mic'): m += VER if flags & VERSION else bytes(8)
    if layout == 'mic': m += bytes(range(0xa0, 0xb0))
    assert len(m) == hl, (len(m), hl)
    return m + lm + nt + d + u + h + skey

SKEY = bytes(range(0x41, 0x51))
def anon_auth(flags=TYPICAL, skey=SKEY, layout='mic'):
    return authenticate(flags, b'', b'', '', '', '', skey, layout)

# ---------------------------------------------------------------- HTTP
def b64(m): return base64.b64encode(m).decode()

def http_req(path, hdr, val):
    h = 'GET %s HTTP/1.1\r\nHost: www.example.test\r\n' % path
    if hdr: h += '%s: %s\r\n' % (hdr, val)
    return (h + '\r\n').encode()

def http_resp(code, text, hdr=None, val=None):
    h = 'HTTP/1.1 %d %s\r\n' % (code, text)
    if hdr: h += '%s: %s\r\n' % (hdr, val)
    h += 'Content-Length: 0\r\n\r\n'
    return h.encode()

def http_flow(F, cport, steps, port=80):
    t = Tcp(cport, port, F)
    for kind, hdr, msg in steps:
        if kind == 'q':
            t.send(True, http_req('/', hdr, ('NTLM ' + b64(msg)) if isinstance(msg, bytes) else msg))
        elif kind == 'r':
            t.send(False, http_resp(401, 'Unauthorized', hdr, ('NTLM ' + b64(msg)) if isinstance(msg, bytes) else msg))
        else:
            t.send(False, http_resp(200, 'OK'))
    t.close()

# ---------------------------------------------------------------- DCE/RPC
IFACE = bytes.fromhex('0123456789abcdef0123456789abcdef') + struct.pack('<HH', 1, 0)   # unknown interface
NDR = bytes.fromhex('045d888aeb1cc9119fe808002b104860') + struct.pack('<HH', 2, 0)

def rpc_pdu(ptype, call, body, auth=b'', level=6, flags=3):
    if auth:
        pad = (-len(body)) % 4
        body += bytes(pad)
        body += struct.pack('<BBBBI', 10, level, pad, 0, 0) + auth
    return struct.pack('<BBBB4sHHI', 5, 0, ptype, flags, b'\x10\0\0\0', 16 + len(body), len(auth), call) + body

def verifier(sig, seqno, extra=0):
    return b'\x01\0\0\0' + sig + struct.pack('<I', seqno) + b'\xdd' * extra

def dcerpc_flow(F, cport, level, msgs, reqs):
    """msgs = (negotiate, challenge, authenticate); reqs = list of
    (request verifier, request stub, response verifier, response stub)"""
    t = Tcp(cport, 135, F)
    ctxl = struct.pack('<HBB', 0, 1, 0) + IFACE + NDR
    bind = struct.pack('<HHIBBBB', 4280, 4280, 0, 1, 0, 0, 0) + ctxl
    t.send(True, rpc_pdu(11, 1, bind, msgs[0], level))
    ack = struct.pack('<HHIH', 4280, 4280, 0x1234, 4) + b'135\0'
    ack += bytes((-len(ack)) % 4) + struct.pack('<IHHH', 1, 0, 0, 0) + bytes(16) + struct.pack('<I', 0)
    t.send(False, rpc_pdu(12, 1, ack, msgs[1], level))
    t.send(True, rpc_pdu(16, 1, struct.pack('<HH', 4280, 4280), msgs[2], level))
    call = 2
    for qv, qs, rv, rs in reqs:
        t.send(True, rpc_pdu(0, call, struct.pack('<IHH', len(qs), 0, 1) + qs, qv, level))
        if rv is not None:
            t.send(False, rpc_pdu(2, call, struct.pack('<IHBB', len(rs), 0, 0, 0) + rs, rv, level))
        call += 1
    t.close()

# ---------------------------------------------------------------- LDAP
def blen(n):
    if n < 128: return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b
def tlv(tag, body=b''): return bytes([tag]) + blen(len(body)) + body
def integer(n, tag=0x02): return tlv(tag, n.to_bytes((n.bit_length() + 8) // 8, 'big', signed=True))
def octets(s, tag=0x04): return tlv(tag, s.encode() if isinstance(s, str) else s)
def seq(*a): return tlv(0x30, b''.join(a))
def ldapmsg(mid, op): return seq(integer(mid), op)
def bind_sasl(mech, cred):
    return tlv(0x60, integer(3) + octets('') + tlv(0xa3, octets(mech) + octets(cred)))
def bind_resp(rc, creds=None):
    return tlv(0x61, tlv(0x0a, bytes([rc])) + octets('') + octets('') + (octets(creds, 0x87) if creds else b''))
OID_NTLM = bytes.fromhex('060a2b06010401823702020a')
OID_SPNEGO = bytes.fromhex('06062b0601050502')
def spnego_init(tok):
    return tlv(0x60, OID_SPNEGO + tlv(0xa0, seq(tlv(0xa0, seq(OID_NTLM)) + tlv(0xa2, octets(tok)))))
def spnego_resp(state, tok=None, mech=None):
    b = tlv(0xa0, tlv(0x0a, bytes([state])))
    if mech: b += tlv(0xa1, mech)
    if tok is not None: b += tlv(0xa2, octets(tok))
    return tlv(0xa1, seq(b))
def sasl(d): return struct.pack('>I', len(d)) + d

def ldap_flow(F, cport, msgs, sealed, n0=90):
    t = Tcp(cport, 389, F)
    t.send(True, ldapmsg(n0, bind_sasl('GSS-SPNEGO', spnego_init(msgs[0]))))
    t.send(False, ldapmsg(n0, bind_resp(14, spnego_resp(1, msgs[1], OID_NTLM))))
    t.send(True, ldapmsg(n0 + 1, bind_sasl('GSS-SPNEGO', spnego_resp(1, msgs[2]))))
    t.send(False, ldapmsg(n0 + 1, bind_resp(0, spnego_resp(0))))
    for to_srv, data in sealed:
        t.send(to_srv, sasl(data))
    t.close()

# ---------------------------------------------------------------- the captures
def crc32c(data):
    tab = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        tab.append(c)
    crc = 0xffffffff
    for b in data:
        crc = tab[(crc ^ b) & 0xff] ^ (crc >> 8)
    return crc ^ 0xffffffff

def colliding_headers():
    """Two different 12 octet signature+sequence prefixes (zero padded to the
    16 octet cache key) with the same CRC-32C: the cache hash compares equal
    but the keys are not.  Found by a deterministic birthday search."""
    seen = {}
    x = 12345
    while True:
        x = (x * 1103515245 + 12345) & 0x7fffffff
        h = struct.pack('<III', x, x ^ 0x5a5a5a5a, (x * 7) & 0xffffffff) + bytes(4)
        c = crc32c(h)
        if c in seen and seen[c] != h:
            return seen[c][:12], h[:12]
        seen[c] = h

def stub(n): return bytes((0x60 + i) & 0xff for i in range(n))

def build_main():
    F = []
    marks = []
    def mark(s): marks.append((len(F) + 1, s))

    # ---- HTTP: full NEGOTIATE / CHALLENGE / AUTHENTICATE with NTLMv2
    mark('HTTP NTLM: NTLMv2 exchange, all target info attributes')
    http_flow(F, 41001, [
        ('q', 'Authorization', negotiate()),
        ('r', 'WWW-Authenticate', challenge()),
        ('q', 'Authorization', authenticate(lm=bytes(range(8)) + bytes(16), nt=ntlmv2_resp(), skey=SKEY)),
        ('o', None, None)])
    mark('HTTP NTLM: proxy style, NTLMv1 responses, OEM strings, no version')
    http_flow(F, 41002, [
        ('q', 'Proxy-Authorization', negotiate(OEM | NTLM | OEM_DOM | OEM_WS | REQ_TARGET, b'', b'', False)),
        ('r', 'Proxy-Authenticate', challenge(OEM | NTLM | REQ_TARGET | TGT_DOM, 'EXAMPLE', b'', layout='noti')),
        ('q', 'Proxy-Authorization', authenticate(OEM | NTLM, bytes(range(24)), bytes(range(24, 48)), skey=b'', layout='ver')),
        ('o', None, None)], 3128)
    mark('HTTP NTLM: Win9x short CHALLENGE, AUTHENTICATE without session key, flags and MIC')
    http_flow(F, 41003, [
        ('q', 'Authorization', negotiate(NTLM | OEM, b'', b'', False)),
        ('r', 'WWW-Authenticate', challenge(OEM | NTLM, 'SRV1', layout='short')),
        ('q', 'Authorization', authenticate(OEM | NTLM, bytes(24), bytes(24), 'EXAMPLE', 'user1', 'CLIENT1', b'', 'min')),
        ('o', None, None)])
    mark('HTTP NTLM: AUTHENTICATE strings and flags taken from the CHALLENGE (Unicode), empty target info')
    http_flow(F, 41004, [
        ('r', 'WWW-Authenticate', challenge(UNICODE | NTLM | TGT_INFO | VERSION, 'SRV1', layout='full')),
        ('q', 'Authorization', authenticate(UNICODE | NTLM, bytes(24), bytes(24), 'EXAMPLE', 'user1', 'CLIENT1', b'', 'key')),
        ('r', 'WWW-Authenticate', challenge(UNICODE | NTLM | TGT_INFO | VERSION, 'SRV1', b'', chal=bytes(range(40, 48)))),
        ('q', 'Authorization', authenticate(UNICODE | NTLM, bytes(24), bytes(24), 'EXAMPLE', 'user1', 'CLIENT1', b'', 'min', uni=True)),
        ('o', None, None)])
    mark('HTTP NTLM: NTLMv2 AUTHENTICATE with a very long user name and a very long domain name; NTLMv1 responses with ESS')
    http_flow(F, 41012, [
        ('r', 'WWW-Authenticate', challenge()),
        ('q', 'Authorization', authenticate(lm=bytes(range(8)) + bytes(16), nt=ntlmv2_resp(), user='u' * 130, skey=SKEY)),
        ('r', 'WWW-Authenticate', challenge(chal=bytes(range(50, 58)))),
        ('q', 'Authorization', authenticate(lm=bytes(range(8)) + bytes(16), nt=ntlmv2_resp(), domain='D' * 300, skey=SKEY)),
        ('r', 'WWW-Authenticate', challenge(chal=bytes(range(60, 68)))),
        ('q', 'Authorization', authenticate(lm=bytes(range(24)), nt=bytes(range(24, 48)), skey=SKEY)),
        ('o', None, None)])
    mark('HTTP NTLM: AUTHENTICATE with flags but no version (zero field), odd Unicode string offset')
    odd = authenticate(UNICODE | NTLM | ESS, b'', b'', 'EXAMPLE', 'user1', 'CLIENT1', b'', 'ver')
    http_flow(F, 41005, [
        ('q', 'Authorization', odd),
        ('o', None, None)])
    mark('HTTP NTLM: anonymous AUTHENTICATE, domain/user empty; session key too long; unknown type')
    http_flow(F, 41006, [
        ('q', 'Authorization', anon_auth(ESS | NTLM | UNICODE, skey=SKEY + b'\x99' * 4)),
        ('q', 'Authorization', SIG + struct.pack('<I', 4) + bytes(16)),
        ('o', None, None)])
    mark('HTTP NTLM: two CHALLENGEs on one connection (new server challenge replaces the state)')
    http_flow(F, 41007, [
        ('r', 'WWW-Authenticate', challenge(chal=bytes(range(1, 9)))),
        ('r', 'WWW-Authenticate', challenge(chal=bytes(range(9, 17)))),
        ('r', 'WWW-Authenticate', challenge(chal=bytes(range(9, 17)))),
        ('o', None, None)])
    mark('HTTP NTLM: non-ESS CHALLENGE (NTLMv1/LM key derivation runs with unknown password)')
    http_flow(F, 41008, [
        ('q', 'Authorization', negotiate(UNICODE | NTLM | LM_KEY | SIGN | SEAL)),
        ('r', 'WWW-Authenticate', challenge(UNICODE | NTLM | LM_KEY | SIGN | SEAL | TGT_INFO | N56, 'SRV1')),
        ('q', 'Authorization', authenticate(UNICODE | NTLM | LM_KEY, bytes(24), bytes(24), skey=SKEY, layout='ver')),
        ('r', 'WWW-Authenticate', challenge(UNICODE | NTLM | SIGN | SEAL | TGT_INFO | N128, 'SRV1', chal=bytes(range(20, 28)))),
        ('o', None, None)])
    mark('HTTP NTLM: target info with odd lengths (reproducer ntlmssp_avpair_lengths), short NTLMv2 response')
    ti = struct.pack('<HH', 6, 8) + b'\x11' * 8 + struct.pack('<HH', 7, 2) + b'\x22\x22' + struct.pack('<HH', 0, 0)
    ti2 = av(0x0b, b'\x01\x02\x03\x04') + av(1, u16('SRV1')) + av(2, u16('A'))[:6]
    http_flow(F, 41009, [
        ('r', 'WWW-Authenticate', challenge(UNICODE | NTLM | TGT_INFO | VERSION, 'SRV1', ti)),
        ('r', 'WWW-Authenticate', challenge(UNICODE | NTLM | TGT_INFO | VERSION, 'SRV1', ti2, chal=bytes(range(30, 38)))),
        ('o', None, None)])
    mark('HTTP NTLM: NTLMv2 response with unknown and cut-short attributes, LM response blob over 10 KB')
    nt2 = ntlmv2_resp(av(0x0c, b'\x01\x02\x03\x04') + av(7, b'\x01\x02') + struct.pack('<HH', 1, 20) + b'ab', 0)
    http_flow(F, 41010, [
        ('q', 'Authorization', authenticate(UNICODE | NTLM, bytes(range(8)) + bytes(16), nt2, layout='ver')),
        ('q', 'Authorization', authenticate(UNICODE | NTLM, bytes(10300), bytes(24), layout='ver')),
        ('q', 'Authorization', authenticate(UNICODE | NTLM, bytes(24), ntlmv2_resp(trail=0), layout='mic', skey=SKEY)),
        ('o', None, None)])
    mark('HTTP NTLM: Negotiate scheme header carrying a bare NTLMSSP token (goes through GSS-API)')
    http_flow(F, 41011, [
        ('q', 'Authorization', 'Negotiate ' + b64(negotiate())),
        ('r', 'WWW-Authenticate', 'Negotiate ' + b64(challenge())),
        ('q', 'Authorization', 'Negotiate ' + b64(anon_auth(NTLM | UNICODE))),
        ('o', None, None)])

    # ---- DCE/RPC
    sig1 = bytes(range(1, 9))
    sigs = [bytes(range(i, i + 8)) for i in range(0x10, 0x60, 8)]
    for i, (cflags, name) in enumerate([
            (TYPICAL, 'ESS, 128-bit, key exchange'),
            (UNICODE | NTLM | SIGN | SEAL | ESS | TGT_INFO | N128, 'ESS, 128-bit, no key exchange'),
            (UNICODE | NTLM | SIGN | SEAL | ESS | KEY_EXCH | N56, 'ESS, 56-bit, key exchange'),
            (UNICODE | NTLM | SIGN | SEAL | ESS | KEY_EXCH, 'ESS, 40-bit, key exchange'),
            (UNICODE | NTLM | SIGN | SEAL | ESS | KEY_EXCH | N128 | LM_KEY, 'ESS, 128-bit, key exchange, LM key'),
            (UNICODE | NTLM | SIGN | SEAL | ESS | KEY_EXCH | N128 | NONNT, 'ESS, 128-bit, key exchange, non-NT session key'),
            ]):
        mark('DCE/RPC privacy level, anonymous AUTHENTICATE: ' + name)
        dcerpc_flow(F, 42000 + i, 6,
            (negotiate(cflags), challenge(cflags, chal=bytes([i + 1] * 8)), anon_auth(cflags)),
            [(verifier(sigs[0], 0), stub(40), verifier(sigs[1], 0), stub(24)),
             (verifier(sigs[2], 1), stub(16), verifier(sigs[3], 1), stub(300)),
             (verifier(sigs[4], 2, 300), stub(32), verifier(sigs[5], 2, 40), stub(16)),
             (verifier(sigs[6], 3, 28), stub(20), None, None)])
    mark('DCE/RPC privacy level, non-ESS flags (no key state), verifiers only stored')
    f = UNICODE | NTLM | SIGN | SEAL | N128 | TGT_INFO
    dcerpc_flow(F, 42010, 6, (negotiate(f), challenge(f), authenticate(f, bytes(24), bytes(24), layout='ver')),
                [(verifier(sigs[0], 0), stub(24), verifier(sigs[1], 0), stub(24))])
    for lvl, lname in ((2, 'connect'), (4, 'packet'), (5, 'packet integrity')):
        mark('DCE/RPC %s level: sign-only verifiers, verifier length 16 and 12 and 40' % lname)
        dcerpc_flow(F, 42020 + lvl, lvl, (negotiate(), challenge(), anon_auth()),
            [(verifier(sigs[0], 0), stub(24), verifier(sigs[1], 0), stub(8)),
             (verifier(sigs[2], 1, 24), stub(16), verifier(sigs[3], 1)[:12], stub(16)),
             (verifier(sigs[4], 2)[:10], stub(16), None, None)])

    # ---- LDAP
    mark('LDAP GSS-SPNEGO with NTLMSSP, no key state: sealed SASL data is not decrypted')
    hdr = b'\x01\0\0\0' + bytes.fromhex('1122334455667788') + struct.pack('<I', 0)
    f = UNICODE | NTLM | SIGN | SEAL | N128
    ldap_flow(F, 43002, (negotiate(f), challenge(f), authenticate(f, bytes(24), bytes(24), layout='ver')),
              [(True, hdr + b'\xaa' * 20), (False, hdr + b'\xbb' * 40)], 95)
    mark('LDAP, bare NTLMSSP tokens in the bind (no SPNEGO), 16 octet signature token')
    t = Tcp(43003, 389, F)
    t.send(True, ldapmsg(1, bind_sasl('GSS-SPNEGO', negotiate())))
    t.send(False, ldapmsg(1, bind_resp(14, challenge())))
    t.send(True, ldapmsg(2, bind_sasl('GSS-SPNEGO', anon_auth(NTLM | UNICODE))))
    t.close()

    # ---- Exported PDU
    mark('Exported PDU: ntlmssp, ntlmssp_payload, ntlmssp_data_only, ntlmssp_verf')
    F.append(exp_pdu('ntlmssp', anon_auth(), 389, 40100))
    F.append(exp_pdu('ntlmssp_payload', b'\x01\0\0\0' + hdr[4:] + b'\xaa' * 8, 389, 40100))
    F.append(exp_pdu('ntlmssp_payload', b'\x01\0\0\0' + hdr[4:] + b'\xbb' * 4000, 389, 40100))
    F.append(exp_pdu('ntlmssp_payload', b'\x01\0\0\0' + bytes(range(12)) + b'\xcc' * 300, 40100, 389))
    F.append(exp_pdu('ntlmssp_payload', b'\x01\0\0\0' + bytes(range(12)) + b'\xcc' * 300, 40100, 389))
    F.append(exp_pdu('ntlmssp_payload', b'\x01\0\0\0' + bytes(8), 389, 40100))
    F.append(exp_pdu('ntlmssp_data_only', b'\xee' * 20, 389, 40100))
    F.append(exp_pdu('ntlmssp_data_only', b'\xee' * 20, 389, 40100))
    F.append(exp_pdu('ntlmssp_verf', verifier(sigs[0], 5, 0), 389, 40100))
    F.append(exp_pdu('ntlmssp_verf', verifier(sigs[0], 5, 300), 389, 40100))
    F.append(exp_pdu('ntlmssp_verf', verifier(sigs[0], 5)[:14], 389, 40100))
    F.append(exp_pdu('ntlmssp', verifier(sigs[1], 6), 389, 40100))        # 16 octet signature
    F.append(exp_pdu('ntlmssp', verifier(sigs[1], 6), 389, 40100))
    F.append(exp_pdu('ntlmssp', b'\x01' + bytes(15), 40100, 389))
    F.append(exp_pdu('ntlmssp', challenge(), 389, 40101))
    F.append(exp_pdu('ntlmssp', challenge(chal=bytes(8)), 389, 40101))
    # no conversation / no NTLMSSP state: payload on a connection that never authenticated
    F.append(exp_pdu('ntlmssp_payload', b'\x01\0\0\0' + bytes(12) + b'\xcc' * 30, 389, 40102))
    F.append(exp_pdu('ntlmssp_data_only', b'\xee' * 20, 389, 40102))
    # a TCP conversation that never carried NTLMSSP
    mark('plain TCP connection, then Exported PDU payload on the same ports (conversation without NTLMSSP state)')
    t = Tcp(40103, 7777, F)
    t.send(True, b'hello')
    t.close()
    F.append(exp_pdu('ntlmssp_payload', b'\x01\0\0\0' + bytes(range(12)) + b'\xcc' * 30, 7777, 40103))
    F.append(exp_pdu('ntlmssp_data_only', b'\xee' * 20, 7777, 40103))
    # two signature+sequence prefixes with the same CRC-32C (cache hash collision)
    mark('Exported PDU: payloads whose cache keys collide in the hash table')
    ka, kb = colliding_headers()
    F.append(exp_pdu('ntlmssp_payload', b'\x01\0\0\0' + ka + b'\xaa' * 20, 389, 40100))
    F.append(exp_pdu('ntlmssp_payload', b'\x01\0\0\0' + kb + b'\xbb' * 20, 389, 40100))
    F.append(exp_pdu('ntlmssp_payload', b'\x01\0\0\0' + ka + b'\xaa' * 20, 389, 40100))
    F.append(exp_pdu('ntlmssp_payload', b'\x01\0\0\0' + kb + b'\xbb' * 20, 389, 40100))
    return F, marks

def build_malformed():
    F = []
    # truncated messages through HTTP
    t = Tcp(44001, 80, F)
    def q(m): t.send(True, http_req('/', 'Authorization', 'NTLM ' + b64(m)))
    def r(m): t.send(False, http_resp(401, 'Unauthorized', 'WWW-Authenticate', 'NTLM ' + b64(m)))
    n = negotiate(); c = challenge(); a = authenticate(lm=bytes(24), nt=ntlmv2_resp(), skey=SKEY)
    for m in (n[:10], n[:20], n[:27], n[:33]):
        q(m)
    for m in (c[:14], c[:20], c[:34], c[:50], c[:60]):
        r(m)
    for m in (a[:14], a[:30], a[:50], a[:70], a[:90]):
        q(m)
    # offsets that point outside the message
    bad = bytearray(a); bad[16:20] = struct.pack('<HH', 24, 24); bad[20:24] = struct.pack('<I', 5000); q(bytes(bad))
    bad = bytearray(a); bad[28:32] = struct.pack('<I', 0x7fffffff); q(bytes(bad))
    bad = bytearray(a); bad[16:20] = struct.pack('<I', 0x80000000); q(bytes(bad))      # blob offset above INT_MAX
    bad = bytearray(a); bad[24:28] = struct.pack('<I', 0xffffffff); q(bytes(bad))
    bad = bytearray(a); bad[28:32] = struct.pack('<I', 0x80000000); q(bytes(bad))
    bad = bytearray(a); bad[36:40] = struct.pack('<I', 0x80000000); q(bytes(bad))
    bad = bytearray(a); bad[44:48] = struct.pack('<I', 0xffffffff); q(bytes(bad))
    bad = bytearray(c); bad[16:20] = struct.pack('<I', 0x7fffffff); r(bytes(bad))
    bad = bytearray(c); bad[12:16] = struct.pack('<HH', 14, 14); bad[16:20] = struct.pack('<I', 0x7fffffff); r(bytes(bad))
    bad = bytearray(n); bad[16:20] = struct.pack('<I', 0x80000000); q(bytes(bad))
    bad = bytearray(n); bad[20:24] = struct.pack('<HH', 7, 7); bad[24:28] = struct.pack('<I', 0x7fffffff); q(bytes(bad))
    bad = bytearray(c); bad[40:44] = struct.pack('<HH', 100, 100); r(bytes(bad))      # target info beyond the end
    bad = bytearray(c); bad[44:48] = struct.pack('<I', 0x7ffffff0); r(bytes(bad))
    # NTLMv2 response whose attribute list is cut short by the blob length
    q(authenticate(lm=bytes(24), nt=ntlmv2_resp()[:52], layout='ver'))
    q(authenticate(lm=bytes(24), nt=ntlmv2_resp()[:30], layout='ver'))
    q(authenticate(lm=bytes(24), nt=ntlmv2_resp(av(1, u16('SRVSRV'))[:7], 0), layout='ver'))
    # blob length field larger than the data
    bad = bytearray(authenticate(lm=bytes(24), nt=bytes(24), layout='ver')); bad[12:14] = struct.pack('<H', 400); q(bytes(bad))
    t.close()
    # NTLMv2 response of 30 octets (reproducer ntlmssp_avpair_lengths frame 2): the
    # remaining length goes negative and wraps
    t = Tcp(44003, 80, F)
    t.send(True, http_req('/', 'Authorization', 'NTLM ' + b64(authenticate(UNICODE | NTLM, bytes(24), b'\x33' * 30, layout='ver'))))
    t.close()
    # DCE/RPC privacy level with a stub shorter than 16 octets after decryption
    cf = TYPICAL
    dcerpc_flow(F, 44004, 6, (negotiate(cf), challenge(cf), anon_auth(cf)),
                [(verifier(bytes(range(8)), 0), stub(8), verifier(bytes(range(8, 16)), 0), stub(8)),
                 (verifier(bytes(range(16, 24)), 1), b'', None, None)])
    # LDAP: sealed data decrypted with the anonymous key is not LDAP; short tokens
    hdr = b'\x01\0\0\0' + bytes.fromhex('1122334455667788') + struct.pack('<I', 0)
    ldap_flow(F, 44005, (negotiate(), challenge(), anon_auth()),
              [(True, hdr + b'\xaa' * 8), (True, hdr + b'\xbb' * 400),
               (False, b'\x01\0\0\0' + bytes(range(12)) + b'\xcc' * 24)], 90)
    f = UNICODE | NTLM | SIGN | SEAL | N128
    ldap_flow(F, 44006, (negotiate(f), challenge(f), authenticate(f, bytes(24), bytes(24), layout='ver')),
              [(False, b'\x01\0\0\0' + bytes(8)), (True, b'\x01\0\0\0' + bytes(12)),
               (False, b'\x01\0\0\0' + bytes(11))], 95)
    # DCE/RPC: verifier shorter than 16 octets, auth data cut short
    dcerpc_flow(F, 44002, 6, (negotiate()[:20], challenge()[:30], anon_auth()[:70]),
                [(verifier(bytes(8), 0)[:8], bytes(8), verifier(bytes(8), 0), b'')])
    # Exported PDU: sealed payload where the decrypted LDAP is garbage
    F.append(exp_pdu('ntlmssp', anon_auth(), 389, 40200))
    F.append(exp_pdu('ntlmssp', negotiate()[:12], 389, 40201))
    F.append(exp_pdu('ntlmssp', b'NTLMSSP\0', 389, 40201))
    F.append(exp_pdu('ntlmssp', b'NTLMSSP\0\x01\0\0\0', 389, 40201))
    F.append(exp_pdu('ntlmssp', b'NTLMSSP\0\x02\0\0\0' + bytes(10), 389, 40201))
    F.append(exp_pdu('ntlmssp', b'NTLMSSP\0\x03\0\0\0' + bytes(10), 389, 40201))
    F.append(exp_pdu('ntlmssp_verf', b'\x01\0\0\0' + bytes(11), 389, 40201))
    return F

if __name__ == '__main__':
    out = sys.argv[1]
    F, marks = build_main()
    write_pcapng(os.path.join(out, 'ntlmssp-coverage.pcapng'), F)
    M = build_malformed()
    write_pcapng(os.path.join(out, 'ntlmssp-coverage-malformed.pcapng'), M)
    print('main', len(F), 'malformed', len(M))
    for n, m in marks: print(n, m)
