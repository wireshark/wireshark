#!/usr/bin/env python3
# Generates the kerberos captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""mkkerberos_regress.py <outdir>: a small regression capture for the fixed Kerberos
robustness bugs (kerberos_regress.pcapng). Derived from the review reproducers.

Every packet is built here with struct; nothing comes from a network.
Addresses are from 192.0.2.0/24. Encryption and PAC signing call the
system MIT libkrb5 through ctypes (krb5_c_encrypt, krb5_pac_sign);
no cryptography is implemented here.

Usage: python3 mkkerberos_regress.py <outdir>
"""
import ctypes
import os
import struct
import sys


# ------------------------------------------------------------- DER helpers
def blen(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + blen(len(body)) + body


def bint(v):
    length = max(1, (v.bit_length() + 8) // 8)
    return tlv(0x02, v.to_bytes(length, 'big'))


def ctx(n, body):
    return tlv(0xa0 | n, body)


def seq(body):
    return tlv(0x30, body)


def octet(b):
    return tlv(0x04, b)


def app(n, body):
    return tlv(0x60 | n, body)


def gstr(s):
    return tlv(0x1b, s.encode())


def principal(nt, parts):
    return seq(ctx(0, bint(nt)) + ctx(1, seq(b''.join(gstr(p) for p in parts))))



def wrap(layers, inner):
    p = inner
    for tag, pre in layers:
        p = tlv(tag, pre + p)
    return p


def nested(layers, inner, n):
    """inner wrapped n times in layers (inner to outer)."""
    for _ in range(n):
        inner = wrap(layers, inner)
    return inner


# ------------------------------------------------------------ pcap helpers
def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


ETH = bytes.fromhex('020000000088') + bytes.fromhex('020000000077') + b'\x08\x00'


def ipv4(proto, payload, sip, dip):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0, 0x4000, 64,
                     proto, 0, bytes(sip), bytes(dip))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return ETH + ip + payload


def udp(payload, sport=50000, dport=88, sip=(192, 0, 2, 1), dip=(192, 0, 2, 88)):
    if 8 + 20 + len(payload) > 65535:
        raise RuntimeError('UDP payload too large: %d' % len(payload))
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
    ph = bytes(sip) + bytes(dip) + struct.pack('>BBH', 0, 17, len(u) + len(payload))
    u = u[:6] + struct.pack('>H', csum(ph + u + payload)) + u[8:]
    return ipv4(17, u + payload, sip, dip)


def tcp_stream(data, sport=50001, dport=88, sip=(192, 0, 2, 1), dip=(192, 0, 2, 88),
               mss=60000):
    """A client->server TCP stream (3-way handshake, data, no FIN)."""
    frames = []

    def seg(src, dst, sp, dp, seqn, ackn, flags, payload=b''):
        t = struct.pack('>HHIIBBHHH', sp, dp, seqn, ackn, 5 << 4, flags, 65535, 0, 0)
        ph = bytes(src) + bytes(dst) + struct.pack('>BBH', 0, 6, len(t) + len(payload))
        t = t[:16] + struct.pack('>H', csum(ph + t + payload)) + t[18:]
        return ipv4(6, t + payload, src, dst)
    cseq, sseq = 1000, 5000
    frames.append(seg(sip, dip, sport, dport, cseq, 0, 0x02))
    frames.append(seg(dip, sip, dport, sport, sseq, cseq + 1, 0x12))
    cseq += 1
    sseq += 1
    frames.append(seg(sip, dip, sport, dport, cseq, sseq, 0x10))
    for i in range(0, len(data), mss):
        chunk = data[i:i + mss]
        frames.append(seg(sip, dip, sport, dport, cseq, sseq, 0x18, chunk))
        cseq += len(chunk)
    return frames


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def _blk(btype, body):
    body += b'\0' * ((4 - len(body) % 4) % 4)
    total = 12 + len(body)
    return struct.pack('<II', btype, total) + body + struct.pack('<I', total)


def write_pcapng(path, frames, secrets):
    shb = struct.pack('<IHHQ', 0x1A2B3C4D, 1, 0, 0xFFFFFFFFFFFFFFFF) + struct.pack('<HH', 0, 0)
    idb = struct.pack('<HHI', 1, 0, 262144) + struct.pack('<HH', 0, 0)
    blocks = [_blk(0x0A0D0D0A, shb), _blk(1, idb)]
    data = secrets.encode()
    blocks.append(_blk(0x0A, struct.pack('<II', 0x4B524235, len(data)) + data))
    for i, fr in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        epb = struct.pack('<IIIII', 0, ts >> 32, ts & 0xFFFFFFFF, len(fr), len(fr)) + fr
        epb += b'\0' * ((4 - len(fr) % 4) % 4) + struct.pack('<HH', 0, 0)
        blocks.append(_blk(6, epb))
    with open(path, 'wb') as f:
        f.write(b''.join(blocks))


# ----------------------------------------------------------- libkrb5 ctypes
KV5M_DATA = -1760647422
KV5M_KEYBLOCK = -1760647421
KV5M_ENC_DATA = -1760647418


class KData(ctypes.Structure):
    _fields_ = [('magic', ctypes.c_int32), ('length', ctypes.c_uint32), ('data', ctypes.c_void_p)]


class KKeyblock(ctypes.Structure):
    _fields_ = [('magic', ctypes.c_int32), ('enctype', ctypes.c_int32),
                ('length', ctypes.c_uint32), ('_pad', ctypes.c_uint32),
                ('contents', ctypes.c_void_p)]


class KEncData(ctypes.Structure):
    _fields_ = [('magic', ctypes.c_int32), ('enctype', ctypes.c_int32),
                ('kvno', ctypes.c_uint32), ('_pad', ctypes.c_uint32), ('ciphertext', KData)]


_K = None


def krb5():
    global _K
    if _K is not None:
        return _K
    k = ctypes.CDLL('libkrb5.so.3')
    vp = ctypes.c_void_p
    k.krb5_init_context.argtypes = [ctypes.POINTER(vp)]
    k.krb5_pac_init.argtypes = [vp, ctypes.POINTER(vp)]
    k.krb5_pac_add_buffer.argtypes = [vp, vp, ctypes.c_uint32, ctypes.POINTER(KData)]
    k.krb5_pac_sign.argtypes = [vp, vp, ctypes.c_int32, vp, ctypes.POINTER(KKeyblock),
                                ctypes.POINTER(KKeyblock), ctypes.POINTER(KData)]
    k.krb5_free_data_contents.argtypes = [vp, ctypes.POINTER(KData)]
    k.krb5_c_encrypt_length.argtypes = [vp, ctypes.c_int32, ctypes.c_size_t,
                                        ctypes.POINTER(ctypes.c_size_t)]
    k.krb5_c_encrypt.argtypes = [vp, ctypes.POINTER(KKeyblock), ctypes.c_int32, vp,
                                 ctypes.POINTER(KData), ctypes.POINTER(KEncData)]
    k.ctx = vp()
    if k.krb5_init_context(ctypes.byref(k.ctx)):
        raise RuntimeError('krb5_init_context')
    _K = k
    return k


def keyblock(etype, key):
    kb = KKeyblock()
    kb.magic, kb.enctype, kb.length = KV5M_KEYBLOCK, etype, len(key)
    kb._buf = ctypes.create_string_buffer(key)
    kb.contents = ctypes.cast(kb._buf, ctypes.c_void_p)
    return kb


def kdata(b):
    d = KData()
    d.magic, d.length = KV5M_DATA, len(b)
    d._buf = ctypes.create_string_buffer(b)
    d.data = ctypes.cast(d._buf, ctypes.c_void_p)
    return d


def encrypt(etype, key, plain, usage):
    k = krb5()
    kb = keyblock(etype, key)
    n = ctypes.c_size_t()
    if k.krb5_c_encrypt_length(k.ctx, etype, len(plain), ctypes.byref(n)):
        raise RuntimeError('encrypt_length')
    buf = ctypes.create_string_buffer(n.value)
    out = KEncData()
    out.magic, out.enctype, out.kvno = KV5M_ENC_DATA, etype, 1
    out.ciphertext.magic, out.ciphertext.length = KV5M_DATA, n.value
    out.ciphertext.data = ctypes.cast(buf, ctypes.c_void_p)
    inp = kdata(plain)
    if k.krb5_c_encrypt(k.ctx, ctypes.byref(kb), usage, None, ctypes.byref(inp), ctypes.byref(out)):
        raise RuntimeError('encrypt')
    return buf.raw[:out.ciphertext.length]


def sign_pac(etype, key, buffers):
    k = krb5()
    pac = ctypes.c_void_p()
    if k.krb5_pac_init(k.ctx, ctypes.byref(pac)):
        raise RuntimeError('pac_init')
    held = []
    for typ, blob in buffers:
        d = kdata(blob)
        held.append(d)
        if k.krb5_pac_add_buffer(k.ctx, pac, typ, ctypes.byref(d)):
            raise RuntimeError('pac_add_buffer %d' % typ)
    kb = keyblock(etype, key)
    out = KData()
    if k.krb5_pac_sign(k.ctx, pac, 0, None, ctypes.byref(kb), ctypes.byref(kb), ctypes.byref(out)):
        raise RuntimeError('pac_sign')
    signed = ctypes.string_at(out.data, out.length)
    k.krb5_free_data_contents(k.ctx, ctypes.byref(out))
    return signed


ETYPE = 18
KEY = bytes(range(0x61, 0x81))     # aes256, in the pcapng secrets block
KEYLOG = 'aes256-cts-hmac-sha1-96 %s\n' % KEY.hex()


def enc_ticket_part(authz, with_key=True):
    flags = tlv(0x03, b'\x00' + struct.pack('>I', 0x40e00000))
    body = ctx(0, flags)
    if with_key:
        body += ctx(1, seq(ctx(0, bint(ETYPE)) + ctx(1, octet(b'\x22' * 32))))
    body += (ctx(2, gstr('REPRO.TEST')) + ctx(3, principal(1, ['alice'])) +
             ctx(4, seq(ctx(0, bint(0)) + ctx(1, octet(b'')))) +
             ctx(5, tlv(0x18, b'20261101000000Z')) +
             ctx(7, tlv(0x18, b'20261102000000Z')) +
             ctx(10, authz))
    return app(3, seq(body))


def ticket(plain):
    cipher = encrypt(ETYPE, KEY, plain, 2)
    enc = seq(ctx(0, bint(ETYPE)) + ctx(1, bint(1)) + ctx(2, octet(cipher)))
    return app(1, seq(ctx(0, bint(5)) + ctx(1, gstr('REPRO.TEST')) +
                      ctx(2, principal(2, ['krbtgt', 'REPRO.TEST'])) + ctx(3, enc)))


def ad(entries):
    return seq(b''.join(seq(ctx(0, bint(t)) + ctx(1, octet(d))) for t, d in entries))


# ------------------------------------------------------------- reproducers
# Recursion: one level of each self-embedding construct, inner to outer.
KRB_ERROR_HDR = (ctx(0, bint(5)) + ctx(1, bint(30)) + ctx(4, tlv(0x18, b'20261101000000Z')) +
                 ctx(5, bint(0)) + ctx(6, bint(60)) + ctx(9, gstr('R')) + ctx(10, principal(1, ['x'])))
AUTH_HDR = (ctx(0, bint(5)) + ctx(1, gstr('R')) + ctx(2, principal(1, ['x'])) +
            ctx(4, bint(0)) + ctx(5, tlv(0x18, b'20261101000000Z')))
SAFE_BODY = ctx(2, seq(ctx(0, octet(b'u')) + ctx(4, seq(ctx(0, bint(2)) + ctx(1, octet(b'\xc0\x00\x02\x01'))))))
L_PA_FX_ERROR = [(0x04, b''), (0xa2, b''), (0x30, b'\xa1\x04\x02\x02\x00\x89'),
                 (0x04, b''), (0xac, b''), (0x30, KRB_ERROR_HDR), (0x7e, b'')]   # KRB-ERROR e-data
L_PA_TGS_REQ = [(0x04, b''), (0xa2, b''), (0x30, b'\xa1\x03\x02\x01\x01'),
                (0x30, b''), (0xa3, b''), (0x30, b'\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\x0c'), (0x6c, b'')]    # TGS-REQ padata
L_AD_IF_REL = [(0x04, b''), (0xa1, b''), (0x30, b'\xa0\x03\x02\x01\x01'), (0x30, b'')]
L_ARMOR = [(0x04, b''), (0xa1, b''), (0x30, b'\xa0\x03\x02\x01\x01'),  # KrbFastArmor AP-REQ
           (0xa0, b''), (0x30, b''),               # KrbFastArmoredReq armor [0]
           (0xa0, b''),                            # PA-FX-FAST-REQUEST armored-data [0]
           (0x04, b''), (0xa2, b''), (0x30, b'\xa1\x04\x02\x02\x00\x88'),  # PA-DATA PA-FX-FAST (136)
           (0x30, b''), (0xa3, b''),
           (0x30, b'\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\x0a'),  # KDC-REQ pvno 5, msg-type AS-REQ
           (0x6a, b'')]



DEPTH = 20          # the dissector stops at 16 levels


def gss_nested(n):
    """KRB-SAFE whose cksum is a GSSAPI checksum delegating another KRB-SAFE."""
    inner = app(20, seq(b''))
    for _ in range(n):
        gss = struct.pack('<II', 0, 1) + struct.pack('<HH', 1, len(inner)) + inner
        ck = seq(ctx(0, bint(0x8003)) + ctx(1, octet(gss)))
        inner = app(20, seq(ctx(0, bint(5)) + ctx(1, bint(20)) + SAFE_BODY + ctx(3, ck)))
    return inner


def upn_info(name):
    n = name.encode('utf-16-le')
    return struct.pack('<HHHHI', len(n), 16, len(n), 16, 0) + b'\0' * 4 + n


def pac_entries(entries, data):
    """entries: (type, length, offset); data follows the 16 byte entries."""
    out = struct.pack('<II', len(entries), 0)
    for t, ln, off in entries:
        out += struct.pack('<IIQ', t, ln, off)
    return out + data


def kdc_req_addrs(addrs):
    body = (ctx(0, tlv(0x03, b'\x00\x00\x00\x00\x00')) + ctx(2, gstr('R')) + ctx(7, bint(1)) +
            ctx(8, seq(bint(18))) +
            ctx(9, seq(b''.join(seq(ctx(0, bint(t)) + ctx(1, octet(a))) for t, a in addrs))))
    return app(10, seq(ctx(1, bint(5)) + ctx(2, bint(10)) + ctx(4, seq(body))))


def enc_kdc_rep_part(tag):
    key = seq(ctx(0, bint(ETYPE)) + ctx(1, octet(b'\x33' * 32)))
    return app(tag, seq(ctx(0, key) + ctx(1, seq(seq(ctx(0, bint(1)) + ctx(1, tlv(0x18, b'20261101000000Z'))))) +
                        ctx(2, bint(1)) + ctx(4, tlv(0x03, b'\x00\x40\xe0\x00\x00')) +
                        ctx(5, tlv(0x18, b'20261101000000Z')) + ctx(7, tlv(0x18, b'20261102000000Z')) +
                        ctx(9, gstr('R')) + ctx(10, principal(1, ['krbtgt', 'R']))))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames = []
    port = [50000]

    def add(data):
        port[0] += 1
        frames.append(udp(data, sport=port[0]))

    # 1-2, 3, 4: a checksum or key value that is not an OCTET STRING, Bnd length
    bad_ck = seq(ctx(0, bint(0x8003)) + ctx(1, seq(b'')))
    pa = seq(ctx(1, bint(149)) + ctx(2, octet(bad_ck)))
    add(app(10, seq(ctx(1, bint(5)) + ctx(2, bint(10)) + ctx(3, seq(pa)))))
    add(app(20, seq(ctx(0, bint(5)) + ctx(1, bint(20)) + SAFE_BODY + ctx(3, bad_ck))))
    badkey = seq(ctx(0, bint(18)) + ctx(1, seq(b'')))
    add(app(3, seq(ctx(0, tlv(0x03, b'\x00\x00\x00\x00\x00')) + ctx(1, badkey))))
    gss = struct.pack('<II', 0xfffffffc, 0)
    ck = seq(ctx(0, bint(0x8003)) + ctx(1, octet(gss)))
    pa = seq(ctx(1, bint(149)) + ctx(2, octet(ck)))
    add(app(10, seq(ctx(1, bint(5)) + ctx(2, bint(10)) + ctx(3, seq(pa)))))

    # 5: PAC_INFO_BUFFERs: a UPN_DNS_INFO, the same type again, a client info that
    # overlaps it, one outside the PAC, one with a high dword in the offset,
    # then a valid PAC_ATTRIBUTES_INFO that must still be dissected
    upn = upn_info('alice@regress.test')
    attr = struct.pack('<II', 4, 3)
    base = 8 + 16 * 6
    pac = pac_entries([(12, len(upn), base), (12, len(upn), base), (10, 20, base + 4),
                       (1, 64, 100000), (18, 8, (1 << 32) + base), (17, len(attr), base + len(upn))],
                      upn + attr)
    add(app(2, seq(AUTH_HDR + ctx(8, ad([(128, pac)])))))

    # 6-10: nesting past the limit of 16, once for each construct
    add(nested(L_PA_TGS_REQ, app(12, seq(b'')), DEPTH))
    add(nested(L_PA_FX_ERROR, app(30, seq(b'')), DEPTH))
    add(nested(L_ARMOR, app(10, seq(b'')), DEPTH))
    add(gss_nested(DEPTH))
    add(wrap([(0xa8, b''), (0x30, AUTH_HDR), (0x62, b'')], nested(L_AD_IF_REL, seq(b''), DEPTH)))

    # 11: K1: an empty PAC in the first IF-RELEVANT, a real one in the second
    tkt_ck = struct.pack('<I', 16) + b'\0' * 12
    real = sign_pac(ETYPE, KEY, [(16, tkt_ck)])
    tkt = ticket(enc_ticket_part(ad([(1, ad([(128, b'')])), (1, ad([(128, real)]))])))
    frames.append(udp(tkt, sport=88, dport=50100))

    # 12-13: K4: frame 12 is under a key that frame 13 carries
    k2 = bytes(range(0x10, 0x30))
    cipher = encrypt(ETYPE, k2, enc_ticket_part(ad([]), with_key=False), 2)
    enc = seq(ctx(0, bint(ETYPE)) + ctx(1, bint(1)) + ctx(2, octet(cipher)))
    t1 = app(1, seq(ctx(0, bint(5)) + ctx(1, gstr('REPRO.TEST')) +
                    ctx(2, principal(2, ['host', 'srv'])) + ctx(3, enc)))
    flags = tlv(0x03, b'\x00' + struct.pack('>I', 0x40e00000))
    etp = app(3, seq(ctx(0, flags) + ctx(1, seq(ctx(0, bint(ETYPE)) + ctx(1, octet(k2)))) +
                     ctx(2, gstr('REPRO.TEST')) + ctx(3, principal(1, ['alice'])) +
                     ctx(4, seq(ctx(0, bint(0)) + ctx(1, octet(b'')))) +
                     ctx(5, tlv(0x18, b'20261101000000Z')) + ctx(7, tlv(0x18, b'20261102000000Z'))))
    frames.append(udp(t1, sport=88, dport=50101))
    add(etp)

    # 14-15: bare EncASRepPart and EncTGSRepPart
    add(enc_kdc_rep_part(25))
    add(enc_kdc_rep_part(26))

    # 16: HostAddress whose length does not match the type: IPv4 of 2 octets,
    # IPv6 of 4, NetBIOS of 3, then a good IPv4 address
    add(kdc_req_addrs([(2, b'\xc0\x00'), (24, b'\x20\x01\x0d\xb8'), (20, b'abc'), (2, b'\xc0\x00\x02\x01')]))

    write_pcapng(os.path.join(out, 'kerberos_regress.pcapng'), frames, KEYLOG)
    print('%d frames' % len(frames))


if __name__ == '__main__':
    main()
