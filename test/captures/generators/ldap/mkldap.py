#!/usr/bin/env python3
# Generates test/captures/ldap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic LDAP / CLDAP coverage captures.

Usage: mkldap.py <outdir>

LDAPMessages are built with small BER helpers (no library). Addresses
come from 192.0.2.0/24. SASL / GSS-API wrapped data and NTLMSSP tokens
hold placeholder bytes only: no keys, no crypto. Nothing comes from a
real network.
"""
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'


# ---- BER ----
def blen(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body=b''):
    return bytes([tag]) + blen(len(body)) + body


def integer(n, tag=0x02):
    if n == 0:
        return tlv(tag, b'\x00')
    nb = (n.bit_length() + 8) // 8
    return tlv(tag, n.to_bytes(nb, 'big', signed=True))


def enum(n):
    return integer(n, 0x0a)


def boolean(v, tag=0x01):
    return tlv(tag, b'\xff' if v else b'\x00')


def octets(s, tag=0x04):
    if isinstance(s, str):
        s = s.encode()
    return tlv(tag, s)


def seq(*parts, tag=0x30):
    return tlv(tag, b''.join(parts))


def sset(*parts):
    return tlv(0x31, b''.join(parts))


def ldapmsg(mid, op, controls=None):
    c = b''
    if controls:
        c = tlv(0xa0, b''.join(controls))
    return seq(integer(mid), op, c)


def control(oid, value=None, crit=False):
    return seq(octets(oid), boolean(True) if crit else b'', octets(value) if value is not None else b'')


def result(rc, dn='', msg='', referral=None, extra=b''):
    r = enum(rc) + octets(dn) + octets(msg)
    if referral:
        r += tlv(0xa3, b''.join(octets(u) for u in referral))
    return r + extra


def attr(typ, *vals):
    return seq(octets(typ), sset(*[octets(v) for v in vals]))


# ---- protocol ops ----
def bind_simple(name, pw, ver=3):
    return tlv(0x60, integer(ver) + octets(name) + octets(pw, 0x80))


def bind_sasl(name, mech, cred=None):
    return tlv(0x60, integer(3) + octets(name) + tlv(0xa3, octets(mech) + (octets(cred) if cred is not None else b'')))


def bind_ntlm(name, blob, auth=False):
    return tlv(0x60, integer(3) + octets(name) + octets(blob, 0x8b if auth else 0x8a))


def bind_resp(rc, dn='', msg='', creds=None, referral=None):
    extra = octets(creds, 0x87) if creds is not None else b''
    return tlv(0x61, result(rc, dn, msg, referral, extra))


def unbind():
    return tlv(0x42)


def search(base, scope, deref, size, tlim, typesonly, filt, attrs):
    return tlv(0x63, octets(base) + enum(scope) + enum(deref) + integer(size) + integer(tlim) +
               boolean(typesonly) + filt + seq(*[octets(a) for a in attrs]))


def f_and(*f):
    return tlv(0xa0, b''.join(f))


def f_or(*f):
    return tlv(0xa1, b''.join(f))


def f_not(f):
    return tlv(0xa2, f)


def f_eq(a, v):
    return tlv(0xa3, octets(a) + octets(v))


def f_sub(a, init=None, anys=(), final=None):
    items = b''
    if init is not None:
        items += octets(init, 0x80)
    for x in anys:
        items += octets(x, 0x81)
    if final is not None:
        items += octets(final, 0x82)
    return tlv(0xa4, octets(a) + seq(items and items or b''))


def f_ge(a, v):
    return tlv(0xa5, octets(a) + octets(v))


def f_le(a, v):
    return tlv(0xa6, octets(a) + octets(v))


def f_present(a):
    return octets(a, 0x87)


def f_approx(a, v):
    return tlv(0xa8, octets(a) + octets(v))


def f_ext(rule=None, typ=None, val=b'', dn=None):
    b = b''
    if rule is not None:
        b += octets(rule, 0x81)
    if typ is not None:
        b += octets(typ, 0x82)
    b += octets(val, 0x83)
    if dn is not None:
        b += boolean(dn, 0x84)
    return tlv(0xa9, b)


def entry(dn, *attrs):
    return tlv(0x64, octets(dn) + seq(*attrs))


def done(rc=0, dn='', msg='', referral=None):
    return tlv(0x65, result(rc, dn, msg, referral))


def ref(*urls):
    return tlv(0x73, b''.join(octets(u) for u in urls))


def modify(dn, *mods):
    return tlv(0x66, octets(dn) + seq(*[seq(enum(op), attr(t, *v)) for op, t, v in mods]))


def add(dn, *attrs):
    return tlv(0x68, octets(dn) + seq(*attrs))


def delreq(dn):
    return octets(dn, 0x4a)


def moddn(dn, rdn, delold, newsup=None):
    return tlv(0x6c, octets(dn) + octets(rdn) + boolean(delold) + (octets(newsup, 0x80) if newsup else b''))


def compare(dn, a, v):
    return tlv(0x6e, octets(dn) + seq(octets(a), octets(v)))


def abandon(mid):
    return integer(mid, 0x50)


def ext_req(oid, value=None):
    return tlv(0x77, octets(oid, 0x80) + (octets(value, 0x81) if value is not None else b''))


def ext_resp(rc, dn='', msg='', name=None, value=None, referral=None):
    extra = (octets(name, 0x8a) if name else b'') + (octets(value, 0x8b) if value is not None else b'')
    return tlv(0x78, result(rc, dn, msg, referral, extra))


def inter(name=None, value=None):
    return tlv(0x79, (octets(name, 0x80) if name else b'') + (octets(value, 0x81) if value is not None else b''))


# ---- control / extended values ----
OID_PAGED = '1.2.840.113556.1.4.319'
OID_SORT = '1.2.840.113556.1.4.473'
OID_SORTRESP = '1.2.840.113556.1.4.474'
OID_DIRSYNC = '1.2.840.113556.1.4.841'
OID_PASSWD = '1.3.6.1.4.1.4203.1.11.1'
OID_CANCEL = '1.3.6.1.1.8'
OID_SYNCREQ = '1.3.6.1.4.1.4203.1.9.1.1'
OID_SYNCSTATE = '1.3.6.1.4.1.4203.1.9.1.2'
OID_SYNCDONE = '1.3.6.1.4.1.4203.1.9.1.3'
OID_SYNCINFO = '1.3.6.1.4.1.4203.1.9.1.4'
OID_PWPOLICY = '1.3.6.1.4.1.42.2.27.8.5.1'
OID_STARTTLS = '1.3.6.1.4.1.1466.20037'
OID_WHOAMI = '1.3.6.1.4.1.4203.1.11.3'
UUID = bytes(range(0x10, 0x20))


# ---- SIDs and security descriptors ----
def sid(subs, auth=5):
    return struct.pack('>BB', 1, len(subs)) + auth.to_bytes(6, 'big') + b''.join(struct.pack('<I', s) for s in subs)


SID_DOM = sid([21, 1004336348, 1177238915, 682003330])
SID_USER = sid([21, 1004336348, 1177238915, 682003330, 1105])
SID_ADMINS = sid([32, 544])
SID_EVERYONE = sid([0], auth=1)


def ace(typ, flags, mask, s, obj=None):
    body = struct.pack('<I', mask)
    if obj is not None:
        body += struct.pack('<I', obj[0]) + obj[1] + obj[2]
    body += s
    return struct.pack('<BBH', typ, flags, 4 + len(body)) + body


def acl(*aces):
    body = b''.join(aces)
    return struct.pack('<BBHHH', 4, 0, 8 + len(body), len(aces), 0) + body


def secdesc():
    dacl = acl(ace(0, 0, 0x000f01ff, SID_ADMINS), ace(0, 2, 0x00020094, SID_EVERYONE),
               ace(5, 0, 0x00000130, SID_USER, (3, UUID, bytes(range(0x30, 0x40)))),
               ace(1, 0, 0x00000010, SID_USER), ace(6, 0, 0x00000100, SID_USER, (1, UUID, b'')))
    sacl = acl(ace(2, 0xc0, 0x000f01ff, SID_EVERYONE))
    hdr = 20
    owner = hdr
    group = owner + len(SID_ADMINS)
    sa = group + len(SID_ADMINS)
    da = sa + len(sacl)
    return struct.pack('<BBHIIII', 1, 0, 0x8014 | 0x8000, owner, group, sa, da) + SID_ADMINS + SID_ADMINS + sacl + dacl


# ---- GSS / SPNEGO / NTLMSSP placeholders ----
OID_KRB5 = bytes.fromhex('06092a864886f712010202')
OID_NTLM = bytes.fromhex('060a2b06010401823702020a')
OID_SPNEGO = bytes.fromhex('06062b0601050502')


def spnego_init(mechtoken):
    mt = tlv(0xa0, seq(OID_NTLM))
    tok = tlv(0xa2, octets(mechtoken))
    return tlv(0x60, OID_SPNEGO + tlv(0xa0, seq(mt + tok)))


def spnego_resp(state, token=None, mech=None):
    b = tlv(0xa0, enum(state))
    if mech:
        b += tlv(0xa1, mech)
    if token is not None:
        b += tlv(0xa2, octets(token))
    return tlv(0xa1, seq(b))


NTLM_NEG = b'NTLMSSP\x00' + struct.pack('<IIHHIHHI', 1, 0xe2088297, 0, 0, 0, 0, 0, 0)
NTLM_CHAL = b'NTLMSSP\x00' + struct.pack('<IHHIIQQHHI', 2, 0, 0, 56, 0xe0898215, 0x0102030405060708, 0, 0, 0, 56)
NTLM_AUTH = b'NTLMSSP\x00' + struct.pack('<I', 3) + struct.pack('<HHI', 0, 0, 64) * 6 + struct.pack('<I', 0xe2888215)


def cfx_wrap(payload, sealed=False, ec=12):
    """Placeholder RFC 4121 WRAP token header plus data plus a zero checksum."""
    hdr = struct.pack('>BBBBHHQ', 5, 4, 0x01 | (2 if sealed else 0), 0xff, ec, 0, 7)
    return hdr + payload + b'\x00' * ec


KRB_OID = bytes.fromhex('06092a864886f712010202')
KRB1964 = (lambda body: b'\x60' + blen(len(body)) + body)(
    KRB_OID + b'\x02\x01' + b'\x11\x00\xff\xff\xff\xff' + bytes(8) + bytes(8) + bytes(8) + ldapmsg(5, done()))


def sasl(d):
    return struct.pack('>I', len(d)) + d


# ---- netlogon (CLDAP) ----
def dnsname(*labels, ptr=None):
    b = b''
    for l in labels:
        b += bytes([len(l)]) + l.encode()
    if ptr is not None:
        return b + struct.pack('>H', 0xc000 | ptr)
    return b + b'\x00'


def u16z(s):
    return s.encode('utf-16-le') + b'\x00\x00'


def nl_ex(flags, ntver, ip=True, site=True, closest=False):
    b = struct.pack('<HHI', 23, 0, flags) + UUID
    forest = dnsname('example', 'test')
    b += forest
    # the domain name is a pointer to the forest name (offset of the forest in this tvb)
    b += struct.pack('>H', 0xc000 | 24)
    b += dnsname('dc1', ptr=24)
    b += dnsname('EXAMPLE') + dnsname('DC1') + dnsname('user') + dnsname('Default-First-Site-Name') + dnsname('Branch')
    if ip:
        b += b'\x10' + struct.pack('<HH', 2, 0) + bytes([192, 0, 2, 20]) + b'\x00' * 8
    if closest:
        b += dnsname('Next-Site')
    b += struct.pack('<IHH', ntver, 0xffff, 0xffff)
    return b


def nl_resp(ntver, flags=0x000003fd):
    b = struct.pack('<H', 19) + b'\x00\x00'
    b = struct.pack('<H', 19)
    b += u16z('\\\\DC1')
    if len(b) & 1:
        b += b'\x00'
    b += u16z('user')
    if len(b) & 1:
        b += b'\x00'
    b += u16z('EXAMPLE')
    b += UUID + b'\x00' * 16
    forest_off = len(b)
    b += dnsname('example', 'test') + dnsname(ptr=forest_off) + dnsname('dc1', ptr=forest_off)
    b += bytes([192, 0, 2, 20]) + struct.pack('<I', flags)
    b += struct.pack('<IHH', ntver, 0xffff, 0xffff)
    return b


def nl_other(op, ntver):
    return struct.pack('<H', op) + b'\x00' * 8 + struct.pack('<IHH', ntver, 0xffff, 0xffff)


# ---- packet framing ----
def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(src, dst, proto, payload, ident=1):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                     bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    return ip[:10] + struct.pack('!H', csum(ip)) + ip[12:] + payload


def eth(d):
    a, b = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
    return (b + a if d == 0 else a + b) + b'\x08\x00'


FRAMES = []
RANGES = []


class Flow:
    """TCP flow builder with a handshake (d=0 client to server)."""
    def __init__(self, cip='192.0.2.10', sip='192.0.2.20', cport=40001, sport=389, handshake=True):
        self.ip = {0: (cip, sip), 1: (sip, cip)}
        self.port = {0: (cport, sport), 1: (sport, cport)}
        self.seq = {0: 1000, 1: 5000}
        if handshake:
            self.raw(0, b'', 0x02)
            self.seq[0] += 1
            self.raw(1, b'', 0x12)
            self.seq[1] += 1
            self.raw(0, b'', 0x10)

    def raw(self, d, payload, flags):
        src, dst = self.ip[d]
        sp, dp = self.port[d]
        ack = self.seq[1 - d] if flags & 0x10 else 0
        tcp = struct.pack('!HHIIBBHHH', sp, dp, self.seq[d], ack, 5 << 4, flags, 65535, 0, 0)
        FRAMES.append(eth(d) + ip4(src, dst, 6, tcp + payload, len(FRAMES) + 1))

    def send(self, d, data, mss=1400):
        for i in range(0, max(len(data), 1), mss):
            seg = data[i:i + mss]
            self.raw(d, seg, 0x18)
            self.seq[d] += len(seg)

    def fin(self):
        self.raw(0, b'', 0x11)
        self.seq[0] += 1
        self.raw(1, b'', 0x11)
        self.seq[1] += 1
        self.raw(0, b'', 0x10)


def udp(src, dst, sp, dp, payload):
    u = struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
    FRAMES.append(eth(0 if src.endswith('.10') else 1) + ip4(src, dst, 17, u, len(FRAMES) + 1))


def mark(name):
    RANGES.append([name, len(FRAMES) + 1, None])


def endmark():
    RANGES[-1][2] = len(FRAMES)


def write_pcap(name, frames):
    with open(os.path.join(OUT, name), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def ok(mid, op_resp):
    return ldapmsg(mid, op_resp)


def main():
    # ---------------------------------------------------------------
    # 1: unauthenticated rootDSE search, simple bind, searches of every filter kind
    mark('rootDSE search and simple bind')
    f = Flow()
    f.send(0, ldapmsg(1, search('', 0, 0, 0, 0, False, f_present('objectClass'),
                                ['supportedControl', 'supportedCapabilities', 'namingContexts', 'defaultNamingContext'])))
    f.send(1, ldapmsg(1, entry('', attr('supportedControl', OID_PAGED, OID_SORT, OID_DIRSYNC, '1.2.3.4.5.6'),
                               attr('supportedCapabilities', '1.2.840.113556.1.4.800', '1.2.840.113556.1.4.1670'),
                               attr('namingContexts', 'DC=example,DC=test', 'CN=Configuration,DC=example,DC=test'),
                               attr('objectGUID', UUID), attr('objectSid', SID_DOM),
                               attr('supportedLDAPVersion', '3', '2'))))
    f.send(1, ldapmsg(1, done()))
    f.send(0, ldapmsg(2, bind_simple('cn=admin,dc=example,dc=test', 'secret')))
    f.send(1, ldapmsg(2, bind_resp(0)))
    f.send(0, ldapmsg(3, bind_simple('', '', 2)))
    f.send(1, ldapmsg(3, bind_resp(49, '', 'invalid credentials')))
    f.send(0, ldapmsg(4, bind_simple('cn=x', 'y')))
    f.send(1, ldapmsg(4, bind_resp(10, '', 'referral', referral=['ldap://other.example.test/'])))
    endmark()

    mark('search filters')
    filters = [
        f_eq('uid', 'alice'),
        f_and(f_eq('objectClass', 'person'), f_present('mail'), f_ge('uidNumber', '1000'), f_le('uidNumber', '2000')),
        f_or(f_approx('cn', 'Jon'), f_not(f_eq('sn', 'Smith')), f_present('telephoneNumber')),
        f_sub('cn', init='Al', anys=['ic'], final='ce'),
        f_sub('cn', init='Al'),
        f_sub('cn', anys=['li', 'ce']),
        f_sub('cn', final='ce'),
        f_ext('1.2.840.113556.1.4.803', 'userAccountControl', '2', True),
        f_ext(None, 'cn', 'abc'),
        f_ext('caseExactMatch', None, 'abc', False),
        f_and(f_or(f_and(f_eq('a', 'b'), f_not(f_not(f_present('c')))), f_sub('d', init='x')), f_eq('e', 'f')),
        f_eq('binaryAttr', bytes([0, 1, 2, 0xff, 0x80])),
        f_eq('empty', ''),
        f_not(f_present('x')),
    ]
    f = Flow(cport=40002)
    for i, flt in enumerate(filters):
        mid = 10 + i
        base = ['dc=example,dc=test', 'ou=people,dc=example,dc=test', ''][i % 3]
        f.send(0, ldapmsg(mid, search(base, i % 3, i % 4, i * 10, i, bool(i & 1), flt, ['cn', 'mail'] if i % 2 else [])))
        f.send(1, ldapmsg(mid, entry('uid=alice,ou=people,dc=example,dc=test',
                                     attr('cn', 'Alice Example'), attr('mail', 'alice@example.test', 'a@example.test'))))
        if i % 3 == 0:
            f.send(1, ldapmsg(mid, ref('ldap://ldap2.example.test/dc=example,dc=test', 'ldap://ldap3.example.test/')))
        f.send(1, ldapmsg(mid, done(0 if i % 5 else 4, '', '' if i % 5 else 'size limit')))
    endmark()

    mark('write operations')
    f = Flow(cport=40003)
    ops = [
        (modify('uid=alice,dc=example,dc=test', (0, 'mail', ['a@example.test']), (1, 'description', []),
                (2, 'cn', ['Alice', 'A. Example']), (3, 'uidNumber', ['1'])), tlv(0x67, result(0))),
        (add('uid=bob,dc=example,dc=test', attr('objectClass', 'top', 'person'), attr('cn', 'Bob'), attr('sn', 'B')),
         tlv(0x69, result(68, '', 'entry exists'))),
        (delreq('uid=bob,dc=example,dc=test'), tlv(0x6b, result(32, 'dc=example,dc=test', 'no such object'))),
        (moddn('uid=alice,dc=example,dc=test', 'uid=alicia', True, 'ou=staff,dc=example,dc=test'), tlv(0x6d, result(0))),
        (moddn('uid=alicia,ou=staff,dc=example,dc=test', 'uid=alice', False), tlv(0x6d, result(53, '', 'no'))),
        (compare('uid=alice,dc=example,dc=test', 'mail', 'alice@example.test'), tlv(0x6f, result(6))),
        (compare('uid=alice,dc=example,dc=test', 'mail', 'nobody@example.test'), tlv(0x6f, result(5))),
    ]
    for i, (req, resp) in enumerate(ops):
        f.send(0, ldapmsg(30 + i, req))
        f.send(1, ldapmsg(30 + i, resp))
    f.send(0, ldapmsg(40, search('dc=example,dc=test', 2, 0, 0, 0, False, f_present('x'), [])))
    f.send(0, ldapmsg(41, abandon(40)))
    f.send(0, ldapmsg(42, unbind()))
    f.fin()
    endmark()

    mark('controls and extended operations')
    f = Flow(cport=40004)
    page = seq(integer(100), octets(b'\x01\x02\x03'))
    f.send(0, ldapmsg(50, search('dc=example,dc=test', 2, 0, 0, 0, False, f_present('cn'), ['cn']),
                      [control(OID_PAGED, page, True), control(OID_SORT, seq(seq(octets('cn')), seq(octets('sn'), octets('2.5.13.3', 0x80), boolean(True, 0x81)))),
                       control(OID_DIRSYNC, seq(integer(0x80000801), integer(1048576), octets(b'cookie'))),
                       control(OID_DIRSYNC, seq(integer(0), integer(4096), octets(b''))),
                       control('1.2.840.113556.1.4.1339', None), control(OID_SYNCREQ, seq(enum(3), octets(b'ck'), boolean(True))),
                       control(OID_SYNCREQ, seq(enum(1)))]))
    f.send(1, ldapmsg(50, entry('cn=a,dc=example,dc=test', attr('cn', 'a')),
                      [control(OID_SYNCSTATE, seq(enum(1), octets(UUID), octets(b'ck'))),
                       control(OID_SYNCSTATE, seq(enum(0), octets(UUID)))]))
    f.send(1, ldapmsg(50, done(), [control(OID_PAGED, seq(integer(0), octets(b''))),
                                    control(OID_SORTRESP, seq(enum(0))),
                                    control(OID_SORTRESP, seq(enum(16), octets('cn', 0x80))),
                                    control(OID_SYNCDONE, seq(octets(b'ck'), boolean(True))),
                                    control(OID_SYNCDONE, seq()),
                                    control(OID_PWPOLICY, seq(tlv(0xa0, integer(3600, 0x80)), enum(1) and tlv(0x81, b'\x01'))),
                                    control(OID_PWPOLICY, seq(tlv(0xa0, integer(2, 0x81)))),
                                    control(OID_PWPOLICY, seq()),
                                    control('1.2.3.4.5.99', b'\x01\x02', True)]))
    # extended requests / responses
    f.send(0, ldapmsg(51, ext_req(OID_WHOAMI)))
    f.send(1, ldapmsg(51, ext_resp(0, name=None, value=b'dn:cn=admin,dc=example,dc=test')))
    f.send(0, ldapmsg(52, ext_req(OID_PASSWD, seq(octets('uid=alice', 0x80), octets('old', 0x81), octets('new', 0x82)))))
    f.send(1, ldapmsg(52, ext_resp(0, value=seq(octets('generated', 0x80)))))
    f.send(0, ldapmsg(53, ext_req(OID_CANCEL, seq(integer(50)))))
    f.send(1, ldapmsg(53, ext_resp(118, '', 'canceled', name='1.3.6.1.1.8')))
    f.send(0, ldapmsg(54, ext_req('1.2.3.4.5.77', b'\x01\x02\x03')))
    f.send(1, ldapmsg(54, ext_resp(2, '', 'unsupported', name='1.2.3.4.5.77', referral=['ldap://r.example.test/'])))
    f.send(1, ldapmsg(55, inter(OID_SYNCINFO, tlv(0x80, b'newcookie'))))
    f.send(1, ldapmsg(55, inter(OID_SYNCINFO, tlv(0xa1, octets(b'ck') + boolean(False)))))
    f.send(1, ldapmsg(55, inter(OID_SYNCINFO, tlv(0xa2, octets(b'ck') + boolean(True)))))
    f.send(1, ldapmsg(55, inter(OID_SYNCINFO, tlv(0xa3, octets(b'ck') + boolean(True) + sset(octets(UUID), octets(UUID))))))
    f.send(1, ldapmsg(55, inter('1.2.3.4.5.78', b'\x04\x01x')))
    f.send(1, ldapmsg(55, inter()))
    endmark()

    mark('attribute values: SID, GUID, security descriptor, binary')
    f = Flow(cport=40005)
    f.send(0, ldapmsg(60, search('dc=example,dc=test', 2, 0, 0, 0, False, f_eq('objectClass', 'user'),
                                 ['objectSid', 'objectGUID', 'nTSecurityDescriptor'])))
    f.send(1, ldapmsg(60, entry('cn=u,dc=example,dc=test',
                                attr('objectSid', SID_USER), attr('objectGUID', UUID),
                                attr('tokenGroups', SID_DOM, SID_USER, SID_ADMINS), attr('sIDHistory', SID_EVERYONE),
                                attr('mS-DS-CreatorSID', SID_USER), attr('msDS-QuotaTrustee', SID_USER),
                                attr('securityIdentifier', SID_USER), attr('syncWithSID', SID_USER),
                                attr('tokenGroupsGlobalAndUniversal', SID_DOM), attr('tokenGroupsNoGCAcceptable', SID_DOM),
                                attr('nTSecurityDescriptor', secdesc()),
                                attr('binaryThing;binary', bytes(range(40))), attr('jpegPhoto;binary', b'\xff\xd8\xff'),
                                attr('member;range=0-1', 'cn=a', 'cn=b'), attr('description;lang-en', 'text', 'with\x01ctrl'),
                                attr('emptyval', ''), attr('unicode', 'caf\u00e9'))))
    f.send(1, ldapmsg(60, done()))
    # DomainSid / DomainGuid / NtVer assertion values
    f.send(0, ldapmsg(61, search('', 0, 0, 0, 0, False,
                                 f_and(f_eq('DomainSid', SID_DOM), f_eq('DomainGuid', UUID), f_eq('DomainGuid', b'short'),
                                       f_eq('NtVer', struct.pack('<I', 6)), f_eq('DnsDomain', 'example.test')), ['netlogon'])))
    f.send(1, ldapmsg(61, entry('', attr('netlogon', nl_ex(0x000003fd, 0x20000006)))))
    f.send(1, ldapmsg(61, done()))
    endmark()

    mark('reassembly')
    f = Flow(cport=40006)
    big = ldapmsg(70, entry('cn=big,dc=example,dc=test', attr('description', *['value %04d ' % i + 'x' * 30 for i in range(80)])))
    f.send(1, big, mss=700)
    small1 = ldapmsg(71, done())
    small2 = ldapmsg(72, done(32, 'dc=example,dc=test', 'nope'))
    f.send(1, small1 + small2)
    f.send(1, small1 + small2[:6])
    f.send(1, small2[6:])
    None
    endmark()

    mark('StartTLS')
    f = Flow(cport=40007)
    f.send(0, ldapmsg(80, ext_req(OID_STARTTLS)))
    f.send(1, ldapmsg(80, ext_resp(0, name=OID_STARTTLS)))
    # a TLS ClientHello record (placeholder random bytes, no keys)
    hello = b'\x01\x00\x00\x2d\x03\x03' + bytes(range(32)) + b'\x00\x00\x02\x00\x2f\x01\x00\x00\x00'
    f.send(0, b'\x16\x03\x01' + struct.pack('>H', len(hello)) + hello)
    endmark()

    mark('SASL GSS-SPNEGO bind with NTLMSSP and a security layer')
    f = Flow(cport=40008)
    f.send(0, ldapmsg(90, bind_sasl('', 'GSS-SPNEGO', spnego_init(NTLM_NEG))))
    f.send(1, ldapmsg(90, bind_resp(14, '', '', creds=spnego_resp(1, NTLM_CHAL, OID_NTLM))))
    f.send(0, ldapmsg(91, bind_sasl('', 'GSS-SPNEGO', spnego_resp(1, NTLM_AUTH))))
    f.send(1, ldapmsg(91, bind_resp(0, creds=spnego_resp(0))))
    # frames from here on use a security layer: integrity (unsealed) tokens, then sealed
    q = ldapmsg(92, search('dc=example,dc=test', 0, 0, 0, 0, False, f_present('objectClass'), ['cn']))
    f.send(0, sasl(cfx_wrap(q)))
    r = ldapmsg(92, entry('dc=example,dc=test', attr('cn', 'x'))) + ldapmsg(92, done())
    f.send(1, sasl(cfx_wrap(r)))
    f.send(0, sasl(cfx_wrap(b'\x00' * 100, sealed=True)))
    f.send(1, sasl(cfx_wrap(b'\x01' * 100, sealed=True)))
    f.send(0, sasl(cfx_wrap(q)) + sasl(cfx_wrap(q)))
    endmark()

    q0 = ldapmsg(99, search('dc=example,dc=test', 0, 0, 0, 0, False, f_present('objectClass'), ['cn']))
    mark('SASL GSSAPI / PLAIN / GSS-SPNEGO(NTLMSSP) / empty mechanism binds, one connection each')
    f = Flow(cport=40009)
    f.send(0, ldapmsg(100, bind_sasl('', 'GSSAPI', b'\x60\x05\x06\x03\x2a\x03\x04')))
    f.send(1, ldapmsg(100, bind_resp(14, creds=b'\x60\x05\x06\x03\x2a\x03\x04')))
    f.send(0, ldapmsg(101, bind_sasl('', 'GSSAPI', b'')))
    f.send(1, ldapmsg(101, bind_resp(14, creds=b'\x01\x02\x03\x04')))
    f.send(0, ldapmsg(102, bind_sasl('', 'GSSAPI')))
    f.send(1, ldapmsg(102, bind_resp(0)))
    f.send(0, sasl(cfx_wrap(q0)))
    f = Flow(cport=40013)
    f.send(0, ldapmsg(103, bind_sasl('', 'PLAIN', b'\x00user\x00pass')))
    f.send(1, ldapmsg(103, bind_resp(0, creds=b'x')))
    f = Flow(cport=40014)
    f.send(0, ldapmsg(104, bind_sasl('', 'GSS-SPNEGO', NTLM_NEG)))
    f.send(1, ldapmsg(104, bind_resp(14, creds=NTLM_CHAL)))
    f = Flow(cport=40015)
    f.send(0, ldapmsg(107, bind_sasl('', '')))
    endmark()

    mark('NTLMSSP in the bind (sicily) and in matchedDN')
    f = Flow(cport=40010)
    f.send(0, ldapmsg(110, bind_ntlm('', NTLM_NEG)))
    f.send(1, ldapmsg(110, tlv(0x61, enum(0) + octets(NTLM_CHAL) + octets(''))))
    f.send(0, ldapmsg(111, bind_ntlm('', NTLM_AUTH, True)))
    f.send(1, ldapmsg(111, bind_resp(0)))
    endmark()

    mark('SASL security layer detected without seeing the bind')
    f = Flow(cport=40011)
    f.send(0, sasl(cfx_wrap(q)))
    f.send(1, sasl(KRB1964))
    f = Flow(cport=40016)
    f.send(0, sasl(KRB1964))
    endmark()

    mark('reproducers of the fixes')
    f = Flow(cport=40012)
    # empty constructed OCTET STRING as an attribute value (NULL tvb)
    f.send(1, ldapmsg(120, tlv(0x64, octets('cn=x') + seq(seq(octets('cn'), sset(b'\x24\x00'))))))
    f.send(1, ldapmsg(121, tlv(0x64, octets('cn=x') + seq(seq(octets('objectGUID'), sset(b'\x24\x00')),
                                                          seq(octets('objectSid'), sset(b'\x24\x00'))))))
    # SASL bind with empty credentials (04 00) twice, the second one on the same conversation
    f.send(0, ldapmsg(122, bind_sasl('', 'GSS-SPNEGO', b'')))
    # many 'any' substrings: the display string is bounded
    f.send(0, ldapmsg(125, search('', 2, 0, 0, 0, False, f_sub('cn', init='start', anys=['a%03d' % i for i in range(300)], final='end'), [])), mss=1400)
    f.send(0, ldapmsg(126, search('', 2, 0, 0, 0, False, f_sub('cn', anys=['q' * 100] * 10), [])))
    # nested not and and/or with long values
    v = 'A' * 400
    flt = f_eq('cn', v)
    for _ in range(12):
        flt = f_not(flt)
    f.send(0, ldapmsg(127, search('', 2, 0, 0, 0, False, flt, [])))
    f.send(0, ldapmsg(128, search('', 2, 0, 0, 0, False, f_and(*[f_eq('cn', 'B' * 100 + str(i)) for i in range(8)]), [])))
    f.send(0, ldapmsg(129, search('', 2, 0, 0, 0, False, f_or(*[f_present('p' * 100 + str(i)) for i in range(8)]), [])))
    # DirSyncFlags with several flags
    f.send(0, ldapmsg(130, search('', 2, 0, 0, 0, False, f_present('cn'), []),
                      [control(OID_DIRSYNC, seq(integer(0x00002001), integer(100), octets(b'')))]))
    endmark()

    # ---- CLDAP ----
    mark('CLDAP')
    cl = '192.0.2.10'
    sv = '192.0.2.20'
    qf = f_and(f_eq('DnsDomain', 'example.test'), f_eq('Host', 'client1'), f_eq('DomainSid', SID_DOM),
               f_eq('User', 'user'), f_eq('AAC', b'\x00\x00\x00\x00'), f_eq('NtVer', struct.pack('<I', 0x2000001e)))
    for i, (ntv, body) in enumerate([
        (0x2000001e, nl_ex(0x000003fd, 0x2000001e, True, True, True)),
        (0x00000006, nl_resp(6)),
        (0x00000016, nl_ex(0x0000e3fd, 0x00000016, False, True, True)),
        (0x00000004, nl_ex(0x00000000, 0x00000004, False)),
        (0x00000001, nl_other(7, 1)),
        (0x00000001, nl_other(12, 1)),
        (0x00000001, nl_other(21, 1)),
        (0x00000001, struct.pack('<H', 25) + b'\x00' * 8 + struct.pack('<IHH', 0x1c, 0xffff, 0xffff)),
        (0x00000001, b'\x13\x00'),
    ]):
        udp(cl, sv, 50000 + i, 389, ldapmsg(1, search('', 0, 0, 0, 0, False, qf, ['netlogon'])))
        udp(sv, cl, 389, 50000 + i, ldapmsg(1, entry('', attr('netlogon', body))) + ldapmsg(1, done()))
    endmark()

    write_pcap('ldap-coverage.pcap', FRAMES)
    main_n = len(FRAMES)
    for r in RANGES:
        print(r)
    print(main_n)
    FRAMES.clear()

    # ---- malformed capture ----
    good = ldapmsg(1, search('', 2, 0, 0, 0, False, f_and(f_eq('a', 'b'), f_sub('c', init='d')), ['cn']))
    f = Flow(cport=41001)
    f.send(0, good[:len(good) // 2])
    f.send(0, ldapmsg(2, tlv(0x64, octets('cn=x') + seq(seq(octets('cn'))))) [:-1])
    f.send(0, b'\x30\x84\xff\xff\xff\xff' + b'\x02\x01\x01\x42\x00')
    f.send(0, b'\x30\x03\x02\x01\x01')
    f.send(0, ldapmsg(3, tlv(0x7e, b'\x00')))
    f.send(0, ldapmsg(4, tlv(0x4a, b'')))
    f.send(0, ldapmsg(5, search('', 2, 0, 0, 0, False, b'\xbf\x00', [])))
    # filter nesting beyond the limit (4096) and more than 200 elements
    flt = f_present('x')
    for _ in range(210):
        flt = f_not(flt)
    f.send(0, ldapmsg(6, search('', 2, 0, 0, 0, False, flt, [])))
    f.send(0, ldapmsg(7, search('', 2, 0, 0, 0, False, f_and(*[f_present('p') for _ in range(250)]), [])))
    f.send(0, ldapmsg(8, ext_req(OID_PASSWD, b'\x01\x02')))
    f.send(0, ldapmsg(9, search('', 0, 0, 0, 0, False, f_eq('NtVer', b'\x06'), ['netlogon'])))
    f.send(1, ldapmsg(10, entry('', attr('netlogon', b'\x13\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09'))))
    f.send(1, ldapmsg(11, entry('', attr('netlogon', struct.pack('<H', 19) + u16z('x') + b'\x00' * 12))))
    f.send(1, ldapmsg(12, entry('', attr('netlogon', struct.pack('<H', 23) + b'\x00' * 40 + struct.pack('<IHH', 0x1c, 0, 0)))))
    f.send(0, b'\x30\x80' + b'\x02\x01\x01\x42\x00\x00\x00')
    f.send(0, ldapmsg(105, bind_sasl('', 'GSS-SPNEGO', b'\xa1\x00')))
    f.send(0, ldapmsg(106, bind_sasl('', 'EXTERNAL', b'\x60\x00')))
    # second SASL bind resets first_auth_frame only on the first pass (the bind response sets it on every pass)
    g = Flow(cport=41002)
    g.send(0, ldapmsg(123, bind_sasl('', 'GSSAPI')))
    g.send(1, ldapmsg(123, bind_resp(0, creds=b'\x01\x02')))
    g.send(0, ldapmsg(124, bind_sasl('', 'GSSAPI')))
    g.send(0, sasl(bytes([0x11, 0x22]) + b'\x00' * 8))
    g.send(0, ldapmsg(125, bind_sasl('', 'GSS-SPNEGO', NTLM_NEG)))
    g.send(1, ldapmsg(125, bind_resp(14, creds=NTLM_CHAL)))
    # TCP payloads that are neither SASL nor LDAP
    h = Flow(cport=41003)
    h.send(0, bytes(8))
    h.send(0, b'\x30\x01\x02\x03\x04\x05\x06\x07')
    # a security layer whose payload is not an LDAPMessage SEQUENCE
    h.send(0, sasl(cfx_wrap(b'\x04\x08' + bytes(8))))
    # netlogon response with unterminated, unaligned strings
    h.send(1, ldapmsg(30, entry('', attr('netlogon', struct.pack('<H', 19) + b'AAAAAAAAAAAAAAA'))))
    # GSSAPI security layer (the mechanism is kept) with garbage instead of a token
    k = Flow(cport=41004)
    k.send(0, ldapmsg(1, bind_sasl('', 'GSSAPI', b'\x60\x05\x06\x03\x2a\x03\x04')))
    k.send(1, ldapmsg(1, bind_resp(14, creds=b'\x01\x02\x03\x04')))
    k.send(0, sasl(bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])))
    k.send(0, sasl(bytes([0xff, 0xff]) + bytes(20)))
    # SASL layer with a bad token
    f.send(0, ldapmsg(13, bind_sasl('', 'GSS-SPNEGO', b'')))
    f.send(1, ldapmsg(13, bind_resp(0, creds=b'\x01')))
    f.send(0, sasl(b'\x05\x04\x00\xff\x00'))
    f.send(0, sasl(b'\x00\x01\x02'))
    f.send(0, sasl(cfx_wrap(b'\x00' * 10, sealed=True)))
    f.send(0, b'\x00\xff\xff\xff\x01\x02')
    f.send(0, struct.pack('>I', 0xfffffffc) + b'\x01\x02')
    # cldap: truncated
    udp(cl, sv, 51000, 389, ldapmsg(1, search('', 0, 0, 0, 0, False, f_eq('NtVer', b'\x06'), ['netlogon']))[:20])
    write_pcap('ldap-coverage-malformed.pcap', FRAMES)
    print(len(FRAMES))


if __name__ == '__main__':
    main()
