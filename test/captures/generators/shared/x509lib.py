# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Shared DER and capture helpers for the synthetic X.509 coverage captures
# (x509af, x509ce, x509if, x509sat).  Everything is generated: no real
# certificates, no crypto (signatures are fixed filler bytes).
import socket
import struct
import base64

# ---------------------------------------------------------------- DER
def dlen(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b

def tlv(tag, content=b''):
    return bytes([tag]) + dlen(len(content)) + content

def seq(*items):
    return tlv(0x30, b''.join(items))

def setof(*items):
    return tlv(0x31, b''.join(items))

def ctx(n, *items):
    """constructed context-specific [n] (explicit tag or implicit constructed)"""
    return tlv(0xa0 | n, b''.join(items))

def ctxp(n, content):
    """primitive context-specific [n] (implicit primitive)"""
    return tlv(0x80 | n, content)

def oid(s):
    parts = [int(x) for x in s.split('.')]
    out = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7f]
        p >>= 7
        while p:
            enc.append(0x80 | (p & 0x7f))
            p >>= 7
        out += bytes(reversed(enc))
    return tlv(0x06, out)

def oid_content(s):
    return oid(s)[2:]

def integer(v):
    if v >= 0:
        b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big')
    else:
        b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), 'big', signed=True)
    return tlv(0x02, b)

def boolean(v):
    return tlv(0x01, b'\xff' if v else b'\x00')

def null():
    return b'\x05\x00'

def enum(v):
    return tlv(0x0a, bytes([v]))

def octets(b):
    return tlv(0x04, b)

def bitstr(b, unused=0):
    return tlv(0x03, bytes([unused]) + b)

def bits(value, nbits):
    """named bit string, bit 0 = MSB of first octet (DER trailing zeros trimmed)"""
    n = (nbits + 7) // 8
    raw = bytearray(n)
    for i in range(nbits):
        if value & (1 << i):
            raw[i // 8] |= 0x80 >> (i % 8)
    last = max((i for i in range(nbits) if value & (1 << i)), default=-1)
    if last < 0:
        return tlv(0x03, b'\x00')
    n = last // 8 + 1
    return tlv(0x03, bytes([(8 - (last + 1) % 8) % 8]) + bytes(raw[:n]))

def _s(tag):
    return lambda s: tlv(tag, s.encode() if isinstance(s, str) else s)
utf8 = _s(0x0c)
printable = _s(0x13)
teletex = _s(0x14)
ia5 = _s(0x16)
numeric = _s(0x12)
visible = _s(0x1a)
graphic = _s(0x19)
general = _s(0x1b)
def bmp(s):
    return tlv(0x1e, s.encode('utf-16-be'))
def universal(s):
    return tlv(0x1c, s.encode('utf-32-be'))
def utctime(s):
    return tlv(0x17, s.encode())
def gentime(s):
    return tlv(0x18, s.encode())

# ------------------------------------------------------------ X.501/X.509
SHA256RSA = '1.2.840.113549.1.1.11'

def algid(o=SHA256RSA, params=b'\x05\x00'):
    return seq(oid(o), params) if params is not None else seq(oid(o))

def avatv(type_oid, value_der, primary=None, ctxs=None):
    items = [oid(type_oid), value_der]
    if primary is not None:
        items.append(boolean(primary))
    if ctxs is not None:
        items.append(setof(*ctxs))
    return seq(*items)

def rdn(type_oid, value, enc=None):
    """one RDN with one AVA; value str -> UTF8String unless enc given"""
    v = (enc or utf8)(value) if isinstance(value, str) else value
    return setof(seq(oid(type_oid), v))

def rdn_multi(*avas):
    return setof(*[seq(oid(t), v) for t, v in avas])

def name(*rdns):
    return seq(*rdns)

def cn(s):
    return rdn('2.5.4.3', s)

def std_name(common='host.example.com', c='XX', o='Example Org', ou=None):
    r = [rdn('2.5.4.6', c, printable), rdn('2.5.4.10', o)]
    if ou:
        r.append(rdn('2.5.4.11', ou))
    r.append(rdn('2.5.4.3', common))
    return name(*r)

def extension(ext_oid, value_der, critical=None):
    items = [oid(ext_oid)]
    if critical is not None:
        items.append(boolean(critical))
    items.append(octets(value_der))
    return seq(*items)

RSA_KEY = bitstr(seq(integer(0xc0ffee1234567c0ffee1234567c0ffee1234567c0ffee1234567c0ffee), integer(65537)))
def spki_rsa():
    return seq(algid('1.2.840.113549.1.1.1'), RSA_KEY)

def spki_dsa():
    return seq(seq(oid('1.2.840.10040.4.1'),
                   seq(integer(0xfca682ce8e12caba26efccf7110e526db078b05e), integer(0xe1d6b2fa5b2c5a9c0d6bd5f1),
                       integer(0x678471b27a9cf44ee91a49c5147db1a9aaf244f0))),
               bitstr(integer(0x1234567890abcdef1234567890abcdef)))

def spki_dh():
    return seq(seq(oid('1.2.840.10046.2.1'),
                   seq(integer(0xfca682ce8e12caba26efccf7110e526d), integer(2))),
               bitstr(integer(0x1122334455667788)))

def spki_ec():
    return seq(seq(oid('1.2.840.10045.2.1'), oid('1.2.840.10045.3.1.7')),
               bitstr(b'\x04' + bytes(range(64))))

SIG = bitstr(b'\x11' * 32)

def validity(nb='230101000000Z', na='330101000000Z', gen=False):
    mk = gentime if gen else utctime
    return seq(mk(nb), mk(na))

def certificate(subject=None, issuer=None, extensions=(), version=2, serial=1,
                sigalg=None, spki=None, valid=None, uid_issuer=None, uid_subject=None,
                sig_params=b'\x05\x00', outer_alg=None):
    sigalg = sigalg or algid(SHA256RSA, sig_params)
    if issuer is None:
        issuer = std_name('Example CA')
    if subject is None:
        subject = std_name()
    if valid is None:
        valid = validity()
    tbs = []
    if version is not None:
        tbs.append(ctx(0, integer(version)))
    tbs += [integer(serial), sigalg, issuer, valid, subject, spki or spki_rsa()]
    if uid_issuer is not None:
        tbs.append(ctxp(1, b'\x00' + uid_issuer))
    if uid_subject is not None:
        tbs.append(ctxp(2, b'\x00' + uid_subject))
    if extensions:
        tbs.append(ctx(3, seq(*extensions)))
    return seq(seq(*tbs), outer_alg or sigalg, SIG)

def crl(issuer=None, version=None, revoked=None, crl_exts=None, this='230601000000Z',
        next_=None, gen=False, sigalg=None):
    sigalg = sigalg or algid()
    issuer = issuer or std_name('Example CA')
    mk = gentime if gen else utctime
    tbs = []
    if version is not None:
        tbs.append(integer(version))
    tbs += [sigalg, issuer, mk(this)]
    if next_:
        tbs.append(mk(next_))
    if revoked is not None:
        tbs.append(seq(*revoked))
    if crl_exts:
        tbs.append(ctx(0, seq(*crl_exts)))
    return seq(seq(*tbs), sigalg, SIG)

def revoked(serial, date='230501000000Z', exts=None, gen=False):
    mk = gentime if gen else utctime
    items = [integer(serial), mk(date)]
    if exts:
        items.append(seq(*exts))
    return seq(*items)

def pem(label, der):
    b = base64.b64encode(der).decode()
    lines = [b[i:i + 64] for i in range(0, len(b), 64)]
    return '-----BEGIN %s-----\n%s\n-----END %s-----\n' % (label, '\n'.join(lines), label)

# ---------------------------------------------------------------- GeneralName
def gn_dns(s):
    return ctxp(2, s.encode())
def gn_email(s):
    return ctxp(1, s.encode())
def gn_uri(s):
    return ctxp(6, s.encode())
def gn_ip(b):
    return ctxp(7, b)
def gn_rid(o):
    return ctxp(8, oid_content(o))
def gn_dir(nm):
    return ctx(4, nm)
def gn_other(type_oid, value_der):
    return ctx(0, oid(type_oid), ctx(0, value_der))
def gn_edi(assigner, party):
    items = []
    if assigner is not None:
        items.append(ctx(0, assigner))
    items.append(ctx(1, party))
    return ctx(5, *items)
def gn_x400(orad):
    return ctx(3, orad)

def gns(*names):
    return seq(*names)

# ---------------------------------------------------------------- capture
class Cap:
    def __init__(self, t0=1700000000):
        self.frames = []
        self.t = t0
        self.seqno = {}
        self.ipid = 1

    @staticmethod
    def csum(b):
        if len(b) % 2:
            b += b'\0'
        s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
        while s >> 16:
            s = (s & 0xffff) + (s >> 16)
        return ~s & 0xffff

    def add(self, frame, iface=0):
        self.frames.append((self.t, frame, iface))
        self.t += 1

    def _seg(self, src, sport, dst, dport, flags, data=b''):
        sip, dip = socket.inet_aton(src), socket.inet_aton(dst)
        key = (src, sport, dst, dport)
        sq = self.seqno.get(key, 1000)
        ack = self.seqno.get((dst, dport, src, sport), 0) if flags & 0x10 else 0
        opts = b'\x02\x04\x05\xb4\x01\x03\x03\x07' if flags & 0x02 else b''
        tcp = struct.pack('!HHIIBBHHH', sport, dport, sq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + data
        ph = sip + dip + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', self.csum(ph + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), self.ipid, 0, 64, 6, 0, sip, dip)
        self.ipid += 1
        ip = ip[:10] + struct.pack('!H', self.csum(ip)) + ip[12:]
        self.add(b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + tcp)
        self.seqno[key] = sq + len(data) + (1 if flags & 0x02 else 0)

    def tcp(self, payload, sport, dport, src='192.0.2.1', dst='192.0.2.2', seg=1400, flags=0x18):
        sip, dip = socket.inet_aton(src), socket.inet_aton(dst)
        key = (src, sport, dst, dport)
        if key not in self.seqno and (dst, dport, src, sport) not in self.seqno:
            # three-way handshake, the receiver of the data is the client
            self._seg(dst, dport, src, sport, 0x02)
            self._seg(src, sport, dst, dport, 0x12)
            self._seg(dst, dport, src, sport, 0x10)
        n = 0
        for i in range(0, max(len(payload), 1), seg):
            self._seg(src, sport, dst, dport, flags, payload[i:i + seg])
            n += 1
        return n

    # --- carriers
    def tls_certs(self, certs, sport=443, dport=50000, **kw):
        cl = b''.join(len(c).to_bytes(3, 'big') + c for c in certs)
        body = len(cl).to_bytes(3, 'big') + cl
        hs = b'\x0b' + len(body).to_bytes(3, 'big') + body
        out = b''
        for i in range(0, len(hs), 16384):
            frag = hs[i:i + 16384]
            out += b'\x16\x03\x03' + struct.pack('>H', len(frag)) + frag
        return self.tcp(out, sport, dport, **kw)

    def http_resp(self, ctype, body, sport=80, dport=50001, **kw):
        hdr = ('HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n'
               % (ctype, len(body))).encode()
        return self.tcp(hdr + body, sport, dport, **kw)

    def ldap_entry(self, dn, attrs, msgid=2, sport=389, dport=50002, **kw):
        """SearchResultEntry; attrs = [(attr description, [value bytes])]"""
        a = seq(*[seq(octets(t.encode()), setof(*[octets(v) for v in vs])) for t, vs in attrs])
        op = tlv(0x64, octets(dn.encode()) + a)
        return self.tcp(seq(integer(msgid), op), sport, dport, **kw)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for t, fr, _ in self.frames:
                f.write(struct.pack('<IIII', t, 0, len(fr), len(fr)))
                f.write(fr)

    def write_pcapng(self, path, linktypes=(1,)):
        def blk(t, body):
            body += b'\0' * ((4 - len(body) % 4) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        with open(path, 'wb') as f:
            f.write(blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
            for lt in linktypes:
                f.write(blk(1, struct.pack('<HHI', lt, 0, 0)))
            for t, fr, ifc in self.frames:
                ts = t * 1000000
                f.write(blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xFFFFFFFF, len(fr), len(fr)) + fr))

# CMS certs-only SignedData carrying certificates / attribute certificates / CRLs
def cms_certs(certs_der=(), crls=()):
    sd = [integer(1), setof(), seq(oid('1.2.840.113549.1.7.1'))]
    if certs_der:
        sd.append(tlv(0xa0, b''.join(certs_der)))
    if crls:
        sd.append(tlv(0xa1, b''.join(crls)))
    sd.append(setof())
    return seq(oid('1.2.840.113549.1.7.2'), ctx(0, seq(*sd)))

def inner(der):
    """content octets of a TLV"""
    n = der[1]
    if n < 0x80:
        return der[2:]
    return der[2 + (n & 0x7f):]
