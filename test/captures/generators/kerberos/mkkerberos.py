#!/usr/bin/env python3
# Generates the kerberos captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""mkkerberos.py <outdir>: synthetic captures for the Kerberos v5 dissector
(epan/dissectors/packet-kerberos.c, generated from asn1/kerberos).

Every packet is built with struct and a small DER writer. Nothing comes
from a real network; addresses are from 192.0.2.0/24, realm and
principals are made up (EXAMPLE.TEST). All encryption, decryption
helpers and checksums are the system MIT libkrb5 (ctypes): krb5_c_encrypt,
krb5_c_encrypt_iov, krb5_c_make_checksum, krb5_c_string_to_key,
krb5_c_fx_cf2_simple. No cryptographic algorithm is implemented here.
The long-term keys are fixed test values; the session keys are fixed too.
The ciphertext carries a random confounder, so the output is not byte
reproducible: the committed .gz is canonical and the tests check the
decrypted values.

Writes kerberos_coverage.pcapng (the keys are in its decryption secrets
block), kerberos-coverage-malformed.pcapng, kerberos-coverage-nokeys.pcapng
(the same frames without the secrets block) and cfg/kerberos.keytab.
"""

import ctypes
import os
import struct
import sys


# ------------------------------------------------------------------ pcap/TCP
def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 10, 100000 * (i % 10), len(fr), len(fr)))
            f.write(fr)


def _pcapng_block(btype, body):
    pad = (4 - len(body) % 4) % 4
    body += b'\0' * pad
    total = 12 + len(body)
    return struct.pack('<II', btype, total) + body + struct.pack('<I', total)


def write_pcapng(path, frames, secrets=None):
    """pcapng with an Ethernet interface (0) and an Exported PDU interface
    (1). A frame is its bytes (interface 0) or a tuple (interface, bytes).
    secrets, if given, is a Kerberos key log and is written in a
    decryption secrets block before the first packet."""
    shb = struct.pack('<IHHQ', 0x1A2B3C4D, 1, 0, 0xFFFFFFFFFFFFFFFF)
    shb += struct.pack('<HH', 0, 0)
    idb = struct.pack('<HHI', 1, 0, 262144)
    idb += struct.pack('<HH', 0, 0)
    idb2 = struct.pack('<HHI', 252, 0, 262144)
    idb2 += struct.pack('<HH', 0, 0)
    blocks = [_pcapng_block(0x0A0D0D0A, shb), _pcapng_block(0x00000001, idb),
              _pcapng_block(0x00000001, idb2)]
    if secrets:
        for data in (secrets if isinstance(secrets, list) else [secrets]):
            data = data if isinstance(data, bytes) else data.encode()
            dsb = struct.pack('<II', 0x4B524235, len(data)) + data
            blocks.append(_pcapng_block(0x0000000A, dsb))
    for i, fr in enumerate(frames):
        ifid = 0
        if isinstance(fr, tuple):
            ifid, fr = fr
        ts = (1700000000 + i // 10) * 1000000 + 100000 * (i % 10)
        epb = struct.pack('<IIIII', ifid, (ts >> 32) & 0xFFFFFFFF, ts & 0xFFFFFFFF,
                          len(fr), len(fr))
        epb += fr
        epb += b'\0' * ((4 - len(fr) % 4) % 4)
        epb += struct.pack('<HH', 0, 0)
        blocks.append(_pcapng_block(0x00000006, epb))
    with open(path, 'wb') as f:
        f.write(b''.join(blocks))


def exp_pdu(payload, name, sip, dip, sport, dport, ptype=2):
    """An Exported PDU frame: the dissector name, addresses and ports as
    TLVs in front of the payload. The ports and addresses give the PDUs
    of one stream a conversation."""
    def tlv(tag, val):
        pad = (-len(val)) % 4
        return struct.pack('>HH', tag, len(val) + pad) + val + b'\0' * pad
    h = tlv(12, name.encode()) + tlv(20, bytes(sip)) + tlv(21, bytes(dip))
    h += tlv(24, struct.pack('>I', ptype)) + tlv(25, struct.pack('>I', sport))
    h += tlv(26, struct.pack('>I', dport)) + struct.pack('>HH', 0, 0)
    return (1, h + payload)


class TCP:
    """One TCP connection with a handshake; seq/ack kept per side."""
    MSS = 1460

    def __init__(self, frames, cport, sport=49157,
                 cip=(192, 0, 2, 70), sip=(192, 0, 2, 80)):
        self.frames = frames
        self.c = (bytes(cip), cport)
        self.s = (bytes(sip), sport)
        self.cseq, self.sseq = 0x10000000 + cport * 7, 0x20000000 + cport * 11
        self.seg(True, b'', 0x02)
        self.cseq += 1
        self.seg(False, b'', 0x12)
        self.sseq += 1
        self.seg(True, b'', 0x10)

    def seg(self, from_client, payload, flags=0x18):
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        seq = self.cseq if from_client else self.sseq
        ack = 0 if flags == 0x02 else (self.sseq if from_client else self.cseq)
        opts = struct.pack('>BBH', 2, 4, self.MSS) if flags & 0x02 else b''
        tcp = struct.pack('>HHIIBBHHH', src[1], dst[1], seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        ph = src[0] + dst[0] + struct.pack('>BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('>H', csum(ph + tcp + payload)) + tcp[18:]
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 0, 0x4000, 64, 6, 0,
                         src[0], dst[0])
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        mc, ms = bytes.fromhex('020000000070'), bytes.fromhex('020000000080')
        eth = (ms + mc) if from_client else (mc + ms)
        self.frames.append(eth + b'\x08\x00' + ip + tcp + payload)
        if from_client:
            self.cseq += len(payload)
        else:
            self.sseq += len(payload)

    def send(self, from_client, data):
        for i in range(0, len(data), self.MSS):
            self.seg(from_client, data[i:i + self.MSS])

    def fin(self):
        self.seg(True, b'', 0x11)
        self.cseq += 1
        self.seg(False, b'', 0x11)
        self.sseq += 1
        self.seg(True, b'', 0x10)



# ------------------------------------------------------------------ NDR writer
class W:
    """NDR writer that follows packet-dcerpc.c's pointer handling."""

    def __init__(self, le=True, ndr64=False, base=0):
        self.le, self.ndr64 = le, ndr64
        self.e = '<' if le else '>'
        self.buf = bytearray()
        self.base = base           # offset of buf[0] in the tvb (alignment)
        self.top = True
        self.pending = None
        self.ref = 0x00020000

    # primitives
    def align(self, n):
        while (self.base + len(self.buf)) % n:
            self.buf.append(0)

    def align5(self):          # ALIGN_TO_5_BYTES
        self.align(8 if self.ndr64 else 4)

    def u8(self, v):
        self.buf += struct.pack('B', v)

    def u16(self, v):
        self.align(2)
        self.buf += struct.pack(self.e + 'H', v)

    def u32(self, v):
        self.align(4)
        self.buf += struct.pack(self.e + 'I', v)

    def u64(self, v):          # dissect_ndr_uint64: aligned to 8
        self.align(8)
        self.buf += struct.pack(self.e + 'Q', v)

    def duint32(self, v):      # dissect_ndr_duint32: aligned to 4
        self.align(4)
        self.buf += struct.pack(self.e + 'Q', v)

    def nttime(self, v):       # dissect_ndr_nt_NTTIME: aligned to 4
        self.align(4)
        self.buf += struct.pack(self.e + 'Q', v)

    def u3264(self, v):
        if self.ndr64:
            self.u64(v)
        else:
            self.u32(v)

    def u1632(self, v):
        if self.ndr64:
            self.u32(v)
        else:
            self.u16(v)

    def raw(self, b):
        self.buf += b

    def guid(self, b):         # dissect_ndr_uuid_t / dissect_nt_GUID: aligned to 4
        self.align(4)
        self.buf += b

    # pointers
    def ptr(self, fn, kind='unique'):
        """fn writes the pointee (None: NULL pointer)."""
        if self.top:
            if kind != 'ref':
                if fn is None:
                    self.u3264(0)
                    return
                self.u3264(self.ref)
                self.ref += 4
            if fn is None:
                return
            self.top = False
            self.pending = []
            self._run([fn])
            self.pending = None
            self.top = True
        else:
            if fn is None:
                self.u3264(0)
                return
            self.u3264(self.ref)
            self.ref += 4
            self.pending.append(fn)

    def _run(self, lst):
        for fn in lst:
            sub = []
            saved, self.pending = self.pending, sub
            fn()
            self.pending = saved
            self._run(sub)

    # arrays
    def carray(self, items, fn):
        """dissect_ndr_ucarray: max_count, then the elements."""
        self.u3264(len(items))
        for it in items:
            fn(it)

    def cvarray(self, items, fn):
        """dissect_ndr_ucvarray: max_count, offset, actual_count, elements."""
        self.u3264(len(items))
        self.u3264(0)
        self.u3264(len(items))
        for it in items:
            fn(it)

    def bytes_carray(self, b):
        self.u3264(len(b))
        self.raw(b)

    def bytes_cvarray(self, b, maxc=None):
        self.u3264(len(b) if maxc is None else maxc)
        self.u3264(0)
        self.u3264(len(b))
        self.raw(b)

    # strings
    def cvstring(self, s, nul=True, maxc=None):
        """dissect_ndr_wchar_cvstring / dissect_ndr_cvstring(size 2)."""
        u = s.encode('utf-16-le' if self.le else 'utf-16-be') + (b'\0\0' if nul else b'')
        n = len(u) // 2
        self.u3264(n if maxc is None else maxc)
        self.u3264(0)
        self.u3264(n)
        self.raw(u)

    def astring(self, s):
        """[string] char array: dissect_ndr_cvstring with size 1."""
        u = s.encode() + b'\0'
        self.u3264(len(u))
        self.u3264(0)
        self.u3264(len(u))
        self.raw(u)

    def wstr(self, s, kind='unique'):
        """dissect_ndr_str_pointer_item: pointer to a [string] wchar_t."""
        self.ptr(None if s is None else (lambda: self.cvstring(s)), kind)

    def ustr(self, s, extra=0):
        """UNICODE_STRING: dissect_ndr_counted_string / lsa_String."""
        self.align5()
        if s is None:
            self.u16(0)
            self.u16(0)
            self.ptr(None)
        else:
            n = len(s.encode('utf-16-le'))
            self.u16(n)
            self.u16(n + extra)
            self.ptr(lambda: self.cvstring(s, nul=False, maxc=(n + extra) // 2))
        if self.ndr64:
            self.align5()

    def bytes_ptr(self, b, kind='unique'):
        """pointer to a block conformant array of bytes (ucarray_block)."""
        self.ptr(None if b is None else (lambda: self.bytes_carray(b)), kind)



def sid_bytes(s):
    p = s.split('-')
    rev, auth, subs = int(p[1]), int(p[2]), [int(x) for x in p[3:]]
    return struct.pack('<BB', rev, len(subs)) + auth.to_bytes(6, 'big') + \
        b''.join(struct.pack('<I', x) for x in subs)


DOM = 'S-1-5-21-1004336348-1177238915-682003330'
GUID1 = bytes.fromhex('00112233445566778899aabbccddeeff')
GUID2 = bytes.fromhex('a0a1a2a3b0b1c0c1d0d1d2d3d4d5d6d7')
NT1 = 133500000000000000


def w_sid(w, s):
    """dissect_ndr_nt_SID: count, SID."""
    p = s.split('-')
    w.u3264(len(p) - 3)
    w.raw(sid_bytes(s))


def w_psid(w, s):
    """dissect_ndr_nt_PSID: unique pointer to a SID."""
    w.ptr(None if s is None else (lambda: w_sid(w, s)))



def n_group_membership(w, rid, attr):
    w.u32(rid)
    w.u32(attr)


def n_group_memberships(w, groups):
    """count, unique pointer to GROUP_MEMBERSHIP_ARRAY."""
    w.u32(len(groups) if groups else 0)
    w.ptr(None if groups is None else (lambda: w.carray(groups, lambda g: n_group_membership(w, *g))))


GROUPS = [(513, 0x00000007), (512, 0x20000007), (1105, 0x0000000f)]
EXTRA_SIDS = [('S-1-18-1', 7), (DOM + '-1106', 0x20000007)]


def n_sid_and_attributes_array(w, sids):
    def one(sa):
        w_psid(w, sa[0])
        w.u32(sa[1])
    w.carray(sids, one)


def n_validation_sam(w, r=True):
    for i in range(6):
        w.nttime(NT1 + i * 10000000)
    for s in ('alice', 'Alice Example', 'logon.cmd', '\\\\fs\\profiles\\alice', '\\\\fs\\home\\alice', 'H:'):
        w.ustr(s if r else None)
    w.u16(17)
    w.u16(1)
    w.u32(1104)
    w.u32(513)
    n_group_memberships(w, GROUPS if r else None)
    w.u32(0x00000220 if r else 0)        # USER_FLAGS (extra sids, resource groups)
    w.raw(bytes(range(0x60, 0x70)))      # USER_SESSION_KEY
    w.ustr('DC1' if r else None)
    w.ustr('EXAMPLE' if r else None)
    w_psid(w, DOM if r else None)
    w.u32(0)
    w.u32(0)
    w.u32(0x00000210 if r else 0)        # USER_ACCOUNT_CONTROL
    for i in range(7):
        w.u32(0)


def n_validation_sam2(w, r=True):
    n_validation_sam(w, r)
    w.u32(len(EXTRA_SIDS) if r else 0)
    w.ptr(None if not r else (lambda: n_sid_and_attributes_array(w, EXTRA_SIDS)))


def n_validation_sam4(w, r=True):
    n_validation_sam2(w, r)
    w.ustr('example.test' if r else None)
    w.ustr('alice@example.test' if r else None)
    for i in range(10):
        w.ustr(('dummy%d' % i) if r and i < 2 else None)



def compress_lznt1(data, plain_chunk=False):
    """LZNT1 with literal-only chunks (and optionally one stored chunk)."""
    out = b''
    for i in range(0, len(data), 4096):
        chunk = data[i:i + 4096]
        if plain_chunk and i == 0:
            out += struct.pack('<H', 0x3000 | (len(chunk) - 1)) + chunk
            continue
        body = b''
        for j in range(0, len(chunk), 8):
            body += b'\0' + chunk[j:j + 8]
        out += struct.pack('<H', 0xb000 | (len(body) - 1)) + body
    return out


def compress_xpress(data):
    """Plain LZ77 (MS-XCA) with only literals; a final flag bit ends it."""
    out = b''
    i = 0
    while True:
        k = min(32, len(data) - i)
        if k == 32:
            out += struct.pack('<I', 0) + data[i:i + 32]
            i += 32
            continue
        out += struct.pack('<I', 1 << (31 - k)) + data[i:i + k]
        return out


def compress_xpress_huff(data):
    """LZ77+Huffman with every one of the 512 symbols coded in 9 bits:
    the literals and the end-of-stream symbol 256."""
    table = bytes([0x99]) * 256
    codes = [b for b in data] + [256]
    bits = []
    for c in codes:
        bits += [(c >> (8 - k)) & 1 for k in range(9)]
    # The decoder reads 16-bit words: two at start, one more each time
    # fewer than 16 bits are buffered. Find how many it has read after
    # the last code, and supply exactly those (zero filled).
    nwords, avail = 2, 32
    for _ in bits:
        avail -= 1
        if avail < 16:
            nwords += 1
            avail += 16
    bits += [0] * (nwords * 16 - len(bits))
    out = b''
    for k in range(nwords):
        v = 0
        for b in bits[k * 16:(k + 1) * 16]:
            v = (v << 1) | b
        out += struct.pack('<H', v)
    return table + out


def mes(body):
    """MES type serialisation header: version 1, LE, header length 8,
    filler, and the 8-octet object length; then the body."""
    return struct.pack('<BBHI', 1, 0x10, 8, 0xcccccccc) + struct.pack('<Q', len(body)) + body


def n_claims_set(w, rich=True):
    """netlogon_dissect_CLAIMS_SET (the pointee)."""
    def entry(e):
        cid, ctype, vals = e
        w.wstr(cid)
        w.u1632(ctype)
        if w.ndr64:
            w.align(4)
        if ctype in (1, 2, 6):
            w.u32(len(vals))
            w.ptr(lambda: w.carray(vals, w.u64))
        elif ctype == 3:
            w.u32(len(vals))
            w.ptr(lambda: w.carray(vals, lambda s: w.wstr(s)))

    def array(a):
        src, entries = a
        w.u1632(src)
        w.u32(len(entries))
        w.ptr(lambda: w.carray(entries, entry))
    arrays = [(1, [('ad://ext/department', 3, ['Engineering', 'Research']),
                   ('ad://ext/level', 1, [5, 0xfffffffffffffffe]),
                   ('ad://ext/clearance', 2, [3]),
                   ('ad://ext/manager', 6, [1, 0])]),
              (2, [('ad://ext/unknown', 7, [])])]
    if not rich:
        arrays = arrays[:1]
    w.u32(len(arrays))
    w.ptr(lambda: w.carray(arrays, array))
    w.u16(0)
    res = b'RSVD' if rich else b''
    w.u32(len(res))
    w.ptr((lambda: w.bytes_carray(res)) if rich else None)


def claims_set_buffer(rich=True):
    """The uncompressed claims: MES header, then a unique pointer to
    CLAIMS_SET with the deferred data (NDR32 little endian)."""
    w = W(True, False, base=16)
    w.ptr(lambda: n_claims_set(w, rich))
    return mes(bytes(w.buf))


def n_claims_set_metadata(w, fmt, rich=True):
    claims = claims_set_buffer(rich)
    if isinstance(fmt, tuple):
        # undecodable compressed data: shown as a blob
        fmt, comp = fmt[1], {2: b'\x05\xb0\x01\xff\xff\x41\x42\x43',
                             3: b'\x00\x00\x00\x00\x41',
                             4: b'\x99' * 16}[fmt[1]]
    elif fmt == 2:
        comp = compress_lznt1(claims, plain_chunk=not rich)
    elif fmt == 3:
        comp = compress_xpress(claims)
    elif fmt == 4:
        comp = compress_xpress_huff(claims)
    elif fmt == 0:
        comp = claims
    elif fmt == 'trunc':
        fmt, comp = 0, claims[:72]     # the claims set ends early
    else:
        comp = b'\x5a' * 24            # unknown compression: opaque
    w.u32(len(comp))
    w.align(4)
    w.ptr(lambda: w.bytes_carray(comp))
    w.u1632(fmt)
    w.u32(len(claims))
    w.u16(0)
    res = b'R1' if rich else b''
    w.u32(len(res))
    w.ptr((lambda: w.bytes_carray(res)) if rich else None)


def claims_metadata_blob(base, fmt, rich=True):
    """CLAIMS_SET_METADATA_BLOB: MES header and a top-level unique pointer;
    aligned on the offset in the PDU, as the dissector does."""
    w = W(True, False, base=base + 16)
    w.ptr(lambda: n_claims_set_metadata(w, fmt, rich))
    return mes(bytes(w.buf))


def w_claims_blob(w, fmt, rich=True):
    """A conformant byte array holding a claims metadata blob."""
    a = 8 if w.ndr64 else 4
    base = -(-len(w.buf) // a) * a + a + w.base
    blob = claims_metadata_blob(base, fmt, rich) if fmt not in (None, 'empty') else b''
    w.u3264(len(blob))
    w.raw(blob)
    return blob


# ------------------------------------------------------------------ libkrb5
KV5M_DATA = -1760647422
KV5M_KEYBLOCK = -1760647421
KV5M_ENC_DATA = -1760647418
KV5M_CHECKSUM = -1760647423

ET_DES_MD5, ET_DES3, ET_AES128, ET_AES256 = 3, 16, 17, 18
ET_AES128_SHA2, ET_AES256_SHA384, ET_RC4 = 19, 20, 23
ET_CAM128, ET_CAM256 = 25, 26
KEYLEN = {3: 8, 16: 24, 17: 16, 18: 32, 19: 16, 20: 32, 23: 16, 25: 16, 26: 32}
# the mandatory checksum type of each enctype (RFC 3961 and friends)
CKSUM_FOR = {17: 15, 18: 16, 19: 19, 20: 20, 23: -138, 25: 17, 26: 18}


class _KrbData(ctypes.Structure):
    _fields_ = [('magic', ctypes.c_int32), ('length', ctypes.c_uint32),
                ('data', ctypes.c_void_p)]


class _KrbKeyblock(ctypes.Structure):
    _fields_ = [('magic', ctypes.c_int32), ('enctype', ctypes.c_int32),
                ('length', ctypes.c_uint32), ('_pad', ctypes.c_uint32),
                ('contents', ctypes.c_void_p)]


class _KrbEncData(ctypes.Structure):
    _fields_ = [('magic', ctypes.c_int32), ('enctype', ctypes.c_int32),
                ('kvno', ctypes.c_uint32), ('_pad', ctypes.c_uint32),
                ('ciphertext', _KrbData)]


class _KrbChecksum(ctypes.Structure):
    _fields_ = [('magic', ctypes.c_int32), ('checksum_type', ctypes.c_int32),
                ('length', ctypes.c_uint32), ('_pad', ctypes.c_uint32),
                ('contents', ctypes.c_void_p)]


class _KrbIov(ctypes.Structure):
    _fields_ = [('flags', ctypes.c_int32), ('_pad', ctypes.c_uint32),
                ('data', _KrbData)]


IOV_HEADER, IOV_DATA, IOV_SIGN_ONLY, IOV_PADDING, IOV_TRAILER = 1, 2, 3, 4, 5
IOV_EMPTY = 0


def krb5():
    """One libkrb5 context, kept for the rest of the process."""
    k = getattr(krb5, '_k', None)
    if k is not None:
        return k
    k = ctypes.CDLL('libkrb5.so.3')
    P = ctypes.POINTER
    vp, i32, u32 = ctypes.c_void_p, ctypes.c_int32, ctypes.c_uint32
    k.krb5_init_context.argtypes = [P(vp)]
    k.krb5_init_context.restype = i32
    k.krb5_get_error_message.argtypes = [vp, i32]
    k.krb5_get_error_message.restype = ctypes.c_char_p
    k.krb5_c_encrypt_length.argtypes = [vp, i32, ctypes.c_size_t, P(ctypes.c_size_t)]
    k.krb5_c_encrypt_length.restype = i32
    k.krb5_c_encrypt.argtypes = [vp, P(_KrbKeyblock), i32, vp, P(_KrbData), P(_KrbEncData)]
    k.krb5_c_encrypt.restype = i32
    k.krb5_c_encrypt_iov.argtypes = [vp, P(_KrbKeyblock), i32, vp, P(_KrbIov), ctypes.c_size_t]
    k.krb5_c_encrypt_iov.restype = i32
    k.krb5_c_crypto_length.argtypes = [vp, i32, i32, P(u32)]
    k.krb5_c_crypto_length.restype = i32
    k.krb5_c_make_checksum.argtypes = [vp, i32, P(_KrbKeyblock), i32, P(_KrbData), P(_KrbChecksum)]
    k.krb5_c_make_checksum.restype = i32
    k.krb5_c_checksum_length.argtypes = [vp, i32, P(ctypes.c_size_t)]
    k.krb5_c_checksum_length.restype = i32
    k.krb5_c_string_to_key.argtypes = [vp, i32, P(_KrbData), P(_KrbData), P(_KrbKeyblock)]
    k.krb5_c_string_to_key.restype = i32
    k.krb5_c_fx_cf2_simple.argtypes = [vp, P(_KrbKeyblock), ctypes.c_char_p,
                                       P(_KrbKeyblock), ctypes.c_char_p, P(P(_KrbKeyblock))]
    k.krb5_c_fx_cf2_simple.restype = i32
    k.krb5_free_keyblock.argtypes = [vp, P(_KrbKeyblock)]
    k.krb5_free_checksum_contents.argtypes = [vp, P(_KrbChecksum)]
    k.krb5_pac_parse.argtypes = [vp, vp, ctypes.c_size_t, P(vp)]
    k.krb5_pac_parse.restype = i32
    k.krb5_pac_verify.argtypes = [vp, vp, ctypes.c_int64, vp, P(_KrbKeyblock), P(_KrbKeyblock)]
    k.krb5_pac_verify.restype = i32
    k._ctx = ctypes.c_void_p()
    err = k.krb5_init_context(ctypes.byref(k._ctx))
    if err:
        raise RuntimeError('krb5_init_context %s' % err)
    krb5._k = k
    return k


def _krb_check(k, err, what):
    if err:
        msg = k.krb5_get_error_message(k._ctx, err)
        raise RuntimeError('%s: %s (%s)' % (what, msg.decode(), err))


def _keyblock(etype, key):
    kb = _KrbKeyblock()
    kb.magic = KV5M_KEYBLOCK
    kb.enctype = etype
    kb.length = len(key)
    buf = ctypes.create_string_buffer(key, len(key))
    kb.contents = ctypes.cast(buf, ctypes.c_void_p)
    kb._buf = buf
    return kb


def _krb_data(blob):
    d = _KrbData()
    d.magic = KV5M_DATA
    d.length = len(blob)
    buf = ctypes.create_string_buffer(blob, max(1, len(blob)))
    d.data = ctypes.cast(buf, ctypes.c_void_p)
    d._buf = buf
    return d


def krb5_encrypt(etype, key, plain, usage):
    """krb5_c_encrypt: the cipher text with its confounder and checksum."""
    k = krb5()
    kb = _keyblock(etype, key)
    n = ctypes.c_size_t()
    _krb_check(k, k.krb5_c_encrypt_length(k._ctx, etype, len(plain), ctypes.byref(n)),
               'encrypt_length')
    cipher = ctypes.create_string_buffer(n.value)
    out = _KrbEncData()
    out.magic = KV5M_ENC_DATA
    out.enctype = etype
    out.kvno = 1
    out.ciphertext.magic = KV5M_DATA
    out.ciphertext.length = n.value
    out.ciphertext.data = ctypes.cast(cipher, ctypes.c_void_p)
    inp = _krb_data(plain)
    _krb_check(k, k.krb5_c_encrypt(k._ctx, ctypes.byref(kb), usage, None,
                                   ctypes.byref(inp), ctypes.byref(out)), 'encrypt')
    return cipher.raw[:out.ciphertext.length]


def krb5_checksum(cktype, key_et, key, data, usage):
    """krb5_c_make_checksum with the key's keyblock."""
    k = krb5()
    kb = _keyblock(key_et, key)
    d = _krb_data(data)
    cs = _KrbChecksum()
    _krb_check(k, k.krb5_c_make_checksum(k._ctx, cktype, ctypes.byref(kb), usage,
                                         ctypes.byref(d), ctypes.byref(cs)), 'make_checksum')
    out = ctypes.string_at(cs.contents, cs.length)
    k.krb5_free_checksum_contents(k._ctx, ctypes.byref(cs))
    return out


def krb5_cksum_len(cktype):
    k = krb5()
    n = ctypes.c_size_t()
    _krb_check(k, k.krb5_c_checksum_length(k._ctx, cktype, ctypes.byref(n)), 'checksum_length')
    return n.value


def krb5_s2k(etype, password, salt):
    """krb5_c_string_to_key."""
    k = krb5()
    buf = ctypes.create_string_buffer(KEYLEN[etype])
    kb = _KrbKeyblock()
    kb.magic = KV5M_KEYBLOCK
    kb.enctype = etype
    kb.length = KEYLEN[etype]
    kb.contents = ctypes.cast(buf, ctypes.c_void_p)
    pw, sl = _krb_data(password), _krb_data(salt)
    _krb_check(k, k.krb5_c_string_to_key(k._ctx, etype, ctypes.byref(pw),
                                         ctypes.byref(sl), ctypes.byref(kb)), 'string_to_key')
    return buf.raw


def krb5_cf2(etype1, key1, pepper1, etype2, key2, pepper2):
    """krb5_c_fx_cf2_simple: returns (etype, key)."""
    k = krb5()
    k1, k2 = _keyblock(etype1, key1), _keyblock(etype2, key2)
    out = ctypes.POINTER(_KrbKeyblock)()
    _krb_check(k, k.krb5_c_fx_cf2_simple(k._ctx, ctypes.byref(k1), pepper1,
                                         ctypes.byref(k2), pepper2, ctypes.byref(out)), 'cf2')
    res = (out.contents.enctype, ctypes.string_at(out.contents.contents, out.contents.length))
    k.krb5_free_keyblock(k._ctx, out)
    return res


def krb5_crypto_len(etype, kind):
    k = krb5()
    n = ctypes.c_uint32()
    _krb_check(k, k.krb5_c_crypto_length(k._ctx, etype, kind, ctypes.byref(n)), 'crypto_length')
    return n.value


def krb5_encrypt_iov(etype, key, usage, parts):
    """krb5_c_encrypt_iov. parts is a list of (kind, bytes); the kinds
    IOV_HEADER and IOV_TRAILER are outputs sized by libkrb5. Returns the
    list of resulting buffers in the same order (DATA is encrypted in
    place)."""
    k = krb5()
    kb = _keyblock(etype, key)
    iov = (_KrbIov * len(parts))()
    bufs = []
    for i, (kind, data) in enumerate(parts):
        if kind == IOV_HEADER:
            data = b'\0' * krb5_crypto_len(etype, IOV_HEADER)
        elif kind == IOV_TRAILER:
            data = b'\0' * krb5_crypto_len(etype, IOV_TRAILER)
        buf = ctypes.create_string_buffer(data, max(1, len(data)))
        bufs.append((buf, len(data)))
        iov[i].flags = kind
        iov[i].data.magic = KV5M_DATA
        iov[i].data.length = len(data)
        iov[i].data.data = ctypes.cast(buf, ctypes.c_void_p)
    _krb_check(k, k.krb5_c_encrypt_iov(k._ctx, ctypes.byref(kb), usage, None, iov, len(parts)),
               'encrypt_iov')
    return [b.raw[:n] for b, n in bufs]


# ------------------------------------------------------------------ DER
def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def _ber(tag, body):
    return bytes([tag]) + _ber_len(len(body)) + body


def _ber_int(v):
    length = max(1, (v.bit_length() + 8) // 8) if v >= 0 else max(1, ((-v - 1).bit_length() + 8) // 8)
    return _ber(0x02, v.to_bytes(length, 'big', signed=True))


def _ctx(n, body):
    return _ber(0xa0 | n, body)


def _gstring(s):
    return _ber(0x1b, s.encode('ascii'))


def _octet(b):
    return _ber(0x04, b)


def _seq(*parts):
    return _ber(0x30, b''.join(parts))


def _seqof(items):
    return _ber(0x30, b''.join(items))


def _app(n, body):
    return _ber(0x60 | n, body)


def _bool(v):
    return _ber(0x01, b'\xff' if v else b'\0')


def _gtime(t='20261118120000Z'):
    return _ber(0x18, t.encode())


def _bits32(v):
    """A 32-bit KerberosFlags BIT STRING, MSB first as in RFC 4120."""
    return _ber(0x03, b'\x00' + struct.pack('>I', v))


def _field(n, body):
    """An optional field: nothing when body is None."""
    return b'' if body is None else _ctx(n, body)


# bit n of KerberosFlags (bit 0 is the most significant)
def flagbits(*bits):
    v = 0
    for b in bits:
        v |= 1 << (31 - b)
    return v


T0 = '20261118120000Z'
T1 = '20261118120030Z'
T_END = '20261118220000Z'
T_RENEW = '20261125120000Z'


def principal(nt, *parts):
    return _seq(_ctx(0, _ber_int(nt)), _ctx(1, _seqof([_gstring(p) for p in parts])))


def enc_key(etype, key):
    return _seq(_ctx(0, _ber_int(etype)), _ctx(1, _octet(key)))


def cksum(ctype, value):
    return _seq(_ctx(0, _ber_int(ctype)), _ctx(1, _octet(value)))


def enc_data(etype, cipher, kvno=None):
    return _seq(_ctx(0, _ber_int(etype)), _field(1, None if kvno is None else _ber_int(kvno)),
                _ctx(2, _octet(cipher)))


def encrypt_der(etype, key, plain, usage, kvno=None):
    """EncryptedData, with libkrb5 doing the encryption."""
    return enc_data(etype, krb5_encrypt(etype, key, plain, usage), kvno)


def padata(ptype, value):
    return _seq(_ctx(1, _ber_int(ptype)), _ctx(2, _octet(value)))


def host_addr(atype, addr):
    return _seq(_ctx(0, _ber_int(atype)), _ctx(1, _octet(addr)))


def addresses(*items):
    return _seqof(list(items))


def authz(*items):
    """AuthorizationData from (type, bytes) pairs."""
    return _seqof([_seq(_ctx(0, _ber_int(t)), _ctx(1, _octet(d))) for t, d in items])


# ------------------------------------------------------------------ test keys
REALM = 'EXAMPLE.TEST'
ALICE_PW = b'AlicePassw0rd!'


def fixed_key(etype, tag):
    return bytes(((tag * 53 + i * 29 + 7) & 0xff) for i in range(KEYLEN[etype]))


class Princ:
    """A principal with its long-term keys, one per enctype."""

    def __init__(self, name, tag, nt=1, ets=(18, 17, 23)):
        self.name, self.nt, self.tag = name, nt, tag
        self.parts = name.split('/')
        self.keys = {et: fixed_key(et, tag) for et in ets}

    def der(self):
        return principal(self.nt, *self.parts)

    def key(self, et=18):
        return self.keys[et]


ALICE = Princ('alice', 1, 1)
ALICE.keys = {18: krb5_s2k(18, ALICE_PW, b'EXAMPLE.TESTalice'),
              17: krb5_s2k(17, ALICE_PW, b'EXAMPLE.TESTalice'),
              23: krb5_s2k(23, ALICE_PW, b''),
              19: krb5_s2k(19, ALICE_PW, b'EXAMPLE.TESTalice'),
              25: krb5_s2k(25, ALICE_PW, b'EXAMPLE.TESTalice')}
BOB = Princ('bob', 2, 1)
KRBTGT = Princ('krbtgt/EXAMPLE.TEST', 3, 2, (18, 17, 23, 19, 20, 25, 26))
FILES = Princ('host/files.example.test', 4, 3, (18, 17, 23, 19, 20, 25, 26))
CIFS = Princ('cifs/files.example.test', 5, 3, (18, 17, 23))
WS01 = Princ('host/ws01.example.test', 6, 3, (18, 17, 23))
LDAPS = Princ('ldap/dc1.example.test', 7, 3, (18, 17, 23))
DCEP = Princ('rpcss/dc1.example.test', 8, 3, (18, 17, 23))
# keys that belong to nothing in the capture: they make the key search
# try several keys before the right one
DECOYS = [(et, fixed_key(et, 90 + i)) for i, et in enumerate((18, 18, 17, 17, 23, 23))]

# Session keys (the keys a KDC would have made up)
SK = {}


def skey(name, etype=18, tag=None):
    if name not in SK:
        SK[name] = (etype, fixed_key(etype, tag if tag is not None else 120 + len(SK)))
    return SK[name]


# Key usages
U_ENC_TS, U_TICKET, U_ASREP, U_TGS_AD, U_TGS_AD_SUB = 1, 2, 3, 4, 5
U_TGS_CKSUM, U_TGS_AUTH, U_TGSREP, U_TGSREP_SUB = 6, 7, 8, 9
U_AP_AUTH, U_AP_REP, U_PRIV, U_CRED, U_SAFE, U_CRED_OTHER = 11, 12, 13, 14, 15, 16
U_APP_CKSUM = 17
U_FAST_REQ_CKSUM, U_FAST_ENC, U_FAST_REP, U_FAST_FINISHED = 50, 51, 52, 53
U_CHALLENGE_CLIENT, U_CHALLENGE_KDC = 54, 55
U_ACCEPTOR_SEAL, U_INITIATOR_SEAL = 22, 24


# ------------------------------------------------------------------ PAC
def utf16(s):
    return s.encode('utf-16-le')


def pac_pad(b, n=8):
    return b + b'\0' * ((-len(b)) % n)


def sid_blob(s):
    return sid_bytes(s)


def pac_client_info(name='alice', ft=NT1):
    n = utf16(name)
    return struct.pack('<QH', ft, len(n)) + n


def pac_upn_dns(upn, dns, sam=None, sid=None, flags=None):
    """UPN_DNS_INFO, with the SAM name and SID extension when sam is given."""
    ext = sam is not None
    flags = (flags if flags is not None else 0) | (2 if ext else 0)
    hdr = 12 + (8 if ext else 0)
    u, d = utf16(upn), utf16(dns)
    uo = hdr
    do = uo + len(u)
    body = u + d
    so = so_len = sido = sid_len = 0
    if ext:
        s = utf16(sam)
        so = hdr + len(body)
        body += s
        pad = (-(hdr + len(body))) % 8
        body += b'\0' * pad
        sb = sid_blob(sid)
        sido = hdr + len(body)
        sid_len = len(sb)
        so_len = len(s)
        body += sb
    out = struct.pack('<HHHHI', len(u), uo, len(d), do, flags)
    if ext:
        out += struct.pack('<HHHH', so_len, so, sid_len, sido)
    return pac_pad(out + body)


def pac_attributes(flags=3):
    return struct.pack('<II', 2, flags)


def pac_requester_sid(sid):
    return sid_blob(sid)


def pac_credential_info(etype, key):
    """PAC_CREDENTIAL_INFO: version, etype and the encrypted
    PAC_CREDENTIAL_DATA (usage 16): an NDR MES blob holding one NTLM
    supplemental credential."""
    w = W(True, False)

    def body():
        w.u32(1)           # CredentialCount
        w.ptr(lambda: w.carray([0], lambda _: cred()))

    def cred():
        w.ustr('NTLM')
        w.u32(len(CRED_BLOB))
        w.ptr(lambda: w.bytes_carray(CRED_BLOB))
    w.ptr(body)
    plain = mes(bytes(w.buf))
    return struct.pack('<II', 0, etype) + krb5_encrypt(etype, key, plain, U_CRED_OTHER)


CRED_BLOB = struct.pack('<IIBB', 0, 3, 0, 0) + bytes(range(0x10, 0x20)) + bytes(range(0x20, 0x30))


def _mes_header(body):
    """16-octet NDR MES header. The second byte is the drep Wireshark keeps."""
    return struct.pack('<BBHII', 1, 0x10, 8, 0xcccccccc, len(body)) + b'\0\0\0\0'


def pac_logon_buffer(level=0):
    """PAC_LOGON_INFO: VALIDATION_SAM_INFO, extra SIDs, domain groups."""
    w = W(True, False)

    def body():
        n_validation_sam(w, True)
        w.u32(len(EXTRA_SIDS))
        w.ptr(lambda: n_sid_and_attributes_array(w, EXTRA_SIDS))
        w_psid(w, DOM)
        n_group_memberships(w, GROUPS)
    w.ptr(body)
    return _mes_header(bytes(w.buf)) + bytes(w.buf)


def pac_s4u_buffer():
    w = W(True, False)

    def body():
        w.ustr('cifs/files.example.test')
        w.u32(2)
        w.ptr(lambda: w.carray(['host/ws01.example.test', 'ldap/dc1.example.test'],
                               lambda s: w.ustr(s)))
    w.ptr(body)
    return _mes_header(bytes(w.buf)) + bytes(w.buf)


def pac_device_buffer():
    w = W(True, False)

    def one_domain():
        w_psid(w, DOM)
        n_group_memberships(w, [(515, 7)])

    def body():
        w.u32(1107)
        w.u32(515)
        w_psid(w, DOM)
        n_group_memberships(w, [(515, 7)])
        w.u32(len(EXTRA_SIDS))
        w.ptr(lambda: n_sid_and_attributes_array(w, EXTRA_SIDS))
        w.u32(1)
        w.ptr(lambda: w.carray([0], lambda _: one_domain()))
    w.ptr(body)
    return _mes_header(bytes(w.buf)) + bytes(w.buf)


def pac_assemble(buffers, misalign=False):
    """PACTYPE: count, version, the info buffers, the 8-aligned data.
    Returns the bytes and {type: (offset, length)}."""
    n = len(buffers)
    off = 8 + 16 * n
    infos, data, where = b'', b'', {}
    for t, b in buffers:
        pad = (-off) % 8 + (4 if misalign else 0)
        data += b'\0' * pad
        off += pad
        infos += struct.pack('<IIQ', t, len(b), off)
        where[t] = (off, len(b))
        data += b
        off += len(b)
    data += b'\0' * ((-off) % 8)
    return struct.pack('<II', n, 0) + infos + data, where


def sig_buf(cktype, value=None):
    """A PAC_SIGNATURE_DATA: the type, then the checksum (zeros as a placeholder)."""
    value = value if value is not None else b'\0' * krb5_cksum_len(cktype)
    return struct.pack('<I', cktype & 0xffffffff) + value


def patch(pac, where, typ, value):
    off, ln = where[typ]
    assert len(value) <= ln
    return pac[:off] + value + pac[off + len(value):]


def pac_verify_mit(pac, srv_et, srv_key, kdc_et, kdc_key):
    """Ask libkrb5 whether the signatures verify (a generator self check)."""
    k = krb5()
    p = ctypes.c_void_p()
    buf = ctypes.create_string_buffer(pac, len(pac))
    _krb_check(k, k.krb5_pac_parse(k._ctx, buf, len(pac), ctypes.byref(p)), 'pac_parse')
    skb, kkb = _keyblock(srv_et, srv_key), _keyblock(kdc_et, kdc_key)
    _krb_check(k, k.krb5_pac_verify(k._ctx, p, 0, None, ctypes.byref(skb), ctypes.byref(kkb)),
               'pac_verify')


def signed_pac(infos, srv, kdc, ticket_cksum=None, full=True, tamper=None, ticket_cktype=None,
               misalign=False, srv_cktype=None):
    """A PAC with server, KDC, ticket and full checksums, all made by
    krb5_c_make_checksum (usage 17). srv and kdc are (etype, key).
    ticket_cksum is a callable returning the ticket checksum value (it is
    not known until the ticket is built) or None. tamper names a checksum
    ('ticket' or 'full') to spoil after it has been made."""
    sct, kct = CKSUM_FOR[srv[0]], CKSUM_FOR[kdc[0]]
    bufs = list(infos)
    bufs.append((6, sig_buf(sct)))
    bufs.append((7, sig_buf(kct)))
    if ticket_cksum is not None:
        bufs.append((16, sig_buf(ticket_cktype or kct, ticket_cksum)))
    if full == 'short':
        bufs.append((19, struct.pack('<I', kct & 0xffffffff) + b'\0' * 4))
    elif full == 'badtype':
        bufs.append((19, struct.pack('<I', 0x7777) + b'\0' * 12))
    elif full:
        bufs.append((19, sig_buf(kct)))
    pac, where = pac_assemble(bufs, misalign)
    if full is True:
        v = krb5_checksum(kct, kdc[0], kdc[1], pac, U_APP_CKSUM)
        if tamper == 'full':
            v = bytes([v[0] ^ 0xff]) + v[1:]
        pac = patch(pac, where, 19, struct.pack('<I', kct & 0xffffffff) + v)
    sv = krb5_checksum(sct, srv[0], srv[1], pac, U_APP_CKSUM)
    pac = patch(pac, where, 6, struct.pack('<I', (srv_cktype or sct) & 0xffffffff) + sv)
    kv = krb5_checksum(kct, kdc[0], kdc[1], sv, U_APP_CKSUM)
    pac = patch(pac, where, 7, struct.pack('<I', kct & 0xffffffff) + kv)
    return pac


# ------------------------------------------------------------------ tickets
def enc_ticket_part(skey_, crealm, cname, authz_der, flags=None, caddr=None,
                    start=None, renew=T_RENEW, transited=(0, b''), authtime=None):
    flags = flags if flags is not None else flagbits(1, 5, 8, 9, 10, 13)
    sk_et, sk = skey_
    return _app(3, _seq(
        _ctx(0, _bits32(flags)), _ctx(1, enc_key(sk_et, sk)),
        _ctx(2, _gstring(crealm)), _ctx(3, cname),
        _ctx(4, _seq(_ctx(0, _ber_int(transited[0])), _ctx(1, _octet(transited[1])))),
        _ctx(5, _gtime(authtime or T0)), _field(6, None if start is None else _gtime(start)),
        _ctx(7, _gtime(T_END)), _field(8, None if renew is None else _gtime(renew)),
        _field(9, caddr), _field(10, authz_der)))


def pac_authz(pac, extra=()):
    """authorization-data: AD-IF-RELEVANT { AD-WIN2K-PAC } and extras."""
    inner = authz((128, pac))
    return authz((1, inner), *extra)


def make_ticket(realm, sname_der, srv_et, srv_key, plain, kvno=2):
    enc = encrypt_der(srv_et, srv_key, plain, U_TICKET, kvno)
    return _app(1, _seq(_ctx(0, _ber_int(5)), _ctx(1, _gstring(realm)),
                        _ctx(2, sname_der), _ctx(3, enc)))


def pac_ticket(srv, kdc_p, skey_, cname_p, infos, srv_et=18, kdc_et=18, pac_srv_et=None,
               flags=None, tamper=None, extra_ad=(), caddr=None, full=True, ticket_ck=True,
               start=None, renew=T_RENEW, cname_der=None, realm=REALM, srv_key=None, kdc_key=None,
               ticket_cktype=None, misalign=False, top_level_pac=False, verify=True, authtime=None,
               srv_cktype=None, ticket_cklen=None, bad_if_relevant=False):
    """A Ticket for srv whose PAC is signed by srv (server) and krbtgt (KDC)
    with ticket and full checksums. Returns (ticket DER, EncTicketPart DER)."""
    kdc = kdc_key or (kdc_et, kdc_p.key(kdc_et))
    s = srv_key or (pac_srv_et or srv_et, srv.key(pac_srv_et or srv_et))
    cname_der = cname_der or cname_p.der()
    # the ticket checksum is over the EncTicketPart with a one byte PAC
    stub = pac_authz(b'\0', extra_ad)
    plain0 = enc_ticket_part(skey_, realm, cname_der, stub, flags, caddr, start, renew, authtime=authtime)
    tck = None
    if ticket_ck:
        tck = krb5_checksum(CKSUM_FOR[kdc[0]], kdc[0], kdc[1], plain0, U_APP_CKSUM)
        if ticket_cklen:
            tck = tck[:ticket_cklen]
        if tamper == 'ticket':
            tck = bytes([tck[0] ^ 0xff]) + tck[1:]
    pac = signed_pac(infos, s, kdc, tck, full, tamper, ticket_cktype, misalign, srv_cktype)
    if verify:
        pac_verify_mit(pac, s[0], s[1], kdc[0], kdc[1])
    if top_level_pac:
        az = authz((128, pac), (1, b'\xff\xff' if bad_if_relevant else authz((143, struct.pack('<I', 1)))),
                   *extra_ad)
    else:
        az = pac_authz(pac, extra_ad)
    plain = enc_ticket_part(skey_, realm, cname_der, az, flags, caddr, start, renew, authtime=authtime)
    return make_ticket(realm, srv.der(), srv_et, srv.key(srv_et), plain), plain


def std_infos(sid_rid=1104, rich=True, creds=None):
    """The PAC info buffers of a user logon (everything but the checksums)."""
    b = [(1, pac_logon_buffer()),
         (10, pac_client_info()),
         (12, pac_upn_dns('alice@example.test', 'EXAMPLE.TEST', 'alice', DOM + '-%d' % sid_rid)),
         (13, claims_metadata_blob(0, 2, True)),
         (17, pac_attributes(3)),
         (18, pac_requester_sid(DOM + '-%d' % sid_rid)),
         (30, b'an unknown PAC buffer'),
         (31, b'\1\2\3\4')]
    if creds:
        b.insert(1, (2, pac_credential_info(*creds)))
    return b


# ------------------------------------------------------------------ messages
PA_TGS_REQ, PA_ENC_TIMESTAMP, PA_PW_SALT, PA_ETYPE_INFO, PA_ETYPE_INFO2 = 1, 2, 3, 11, 19
PA_PAC_REQUEST, PA_FOR_USER, PA_FOR_X509_USER = 128, 129, 130
PA_FX_COOKIE, PA_FX_FAST, PA_FX_ERROR, PA_ENCRYPTED_CHALLENGE = 133, 136, 137, 138
PA_REQ_ENC_PA_REP, PA_KERB_KEY_LIST_REQ, PA_KERB_KEY_LIST_REP = 149, 161, 162
PA_SUPPORTED_ETYPES, PA_EXTENDED_ERROR, PA_PAC_OPTIONS = 165, 166, 167

KDC_OPTS = flagbits(1, 3, 8, 15)          # forwardable, proxiable, renewable, canonicalize


def kdc_req_body(cname, sname, nonce, etypes, options=KDC_OPTS, realm=REALM, till=T_END,
                 frm=None, rtime=None, addrs=None, enc_authz=None, add_tickets=None):
    return _seq(_ctx(0, _bits32(options)), _field(1, cname), _ctx(2, _gstring(realm)),
                _field(3, sname), _field(4, None if frm is None else _gtime(frm)),
                _field(5, None if till is None else _gtime(till)),
                _field(6, None if rtime is None else _gtime(rtime)),
                _ctx(7, _ber_int(nonce)), _ctx(8, _seqof([_ber_int(e) for e in etypes])),
                _field(9, addrs), _field(10, enc_authz),
                _field(11, None if add_tickets is None else _seqof(add_tickets)))


def as_req(padatas, body):
    return _app(10, _seq(_ctx(1, _ber_int(5)), _ctx(2, _ber_int(10)),
                         _field(3, None if padatas is None else _seqof(padatas)), _ctx(4, body)))


def tgs_req(padatas, body):
    return _app(12, _seq(_ctx(1, _ber_int(5)), _ctx(2, _ber_int(12)),
                         _field(3, None if padatas is None else _seqof(padatas)), _ctx(4, body)))


def kdc_rep(app, padatas, crealm, cname, ticket, encpart):
    return _app(app, _seq(_ctx(0, _ber_int(5)), _ctx(1, _ber_int(app)),
                          _field(2, None if padatas is None else _seqof(padatas)),
                          _ctx(3, _gstring(crealm)), _ctx(4, cname), _ctx(5, ticket),
                          _ctx(6, encpart)))


def last_req(*items):
    return _seqof([_seq(_ctx(0, _ber_int(t)), _ctx(1, _gtime(v))) for t, v in items])


def enc_kdc_rep_part(app, skey_, nonce, flags, sname, caddr=None, enc_pa=None,
                     key_exp=T_RENEW, start=None, renew=T_RENEW, lr=None):
    return _app(app, _seq(
        _ctx(0, enc_key(*skey_)),
        _ctx(1, lr or last_req((1, T0), (6, '20270101000000Z'))),
        _ctx(2, _ber_int(nonce)), _field(3, None if key_exp is None else _gtime(key_exp)),
        _ctx(4, _bits32(flags)), _ctx(5, _gtime(T0)),
        _field(6, None if start is None else _gtime(start)), _ctx(7, _gtime(T_END)),
        _field(8, None if renew is None else _gtime(renew)), _ctx(9, _gstring(REALM)),
        _ctx(10, sname), _field(11, caddr),
        _field(12, None if enc_pa is None else _seqof(enc_pa))))


def authenticator(cname_der, ctime=T1, cusec=123456, subkey=None, seq=None, cks=None,
                  ad=None, realm=REALM):
    return _app(2, _seq(_ctx(0, _ber_int(5)), _ctx(1, _gstring(realm)), _ctx(2, cname_der),
                        _field(3, cks), _ctx(4, _ber_int(cusec)), _ctx(5, _gtime(ctime)),
                        _field(6, None if subkey is None else enc_key(*subkey)),
                        _field(7, None if seq is None else _ber_int(seq)), _field(8, ad)))


def ap_req(ticket, auth_der, auth_key, opts=0, usage=U_AP_AUTH, kvno=None):
    enc = encrypt_der(auth_key[0], auth_key[1], auth_der, usage, kvno)
    return _app(14, _seq(_ctx(0, _ber_int(5)), _ctx(1, _ber_int(14)),
                         _ctx(2, _bits32(opts)), _ctx(3, ticket), _ctx(4, enc)))


def enc_ap_rep_part(ctime=T1, cusec=123456, subkey=None, seq=None):
    return _app(27, _seq(_ctx(0, _gtime(ctime)), _ctx(1, _ber_int(cusec)),
                         _field(2, None if subkey is None else enc_key(*subkey)),
                         _field(3, None if seq is None else _ber_int(seq))))


def ap_rep(plain, key):
    enc = encrypt_der(key[0], key[1], plain, U_AP_REP)
    return _app(15, _seq(_ctx(0, _ber_int(5)), _ctx(1, _ber_int(15)), _ctx(2, enc)))


def krb_error(code, stime=T1, susec=100, realm=REALM, sname=None, ctime=None, cusec=None,
              crealm=None, cname=None, etext=None, edata=None, echeck=None):
    return _app(30, _seq(
        _ctx(0, _ber_int(5)), _ctx(1, _ber_int(30)),
        _field(2, None if ctime is None else _gtime(ctime)),
        _field(3, None if cusec is None else _ber_int(cusec)),
        _ctx(4, _gtime(stime)), _ctx(5, _ber_int(susec)), _ctx(6, _ber_int(code)),
        _field(7, None if crealm is None else _gstring(crealm)), _field(8, cname),
        _ctx(9, _gstring(realm)), _ctx(10, sname or KRBTGT.der()),
        _field(11, None if etext is None else _gstring(etext)),
        _field(12, None if edata is None else _octet(edata)),
        _field(13, echeck)))


def krb_priv(plain, key, usage=U_PRIV):
    enc = encrypt_der(key[0], key[1], plain, usage)
    return _app(21, _seq(_ctx(0, _ber_int(5)), _ctx(1, _ber_int(21)), _ctx(3, enc)))


def enc_krb_priv_part(data, ts=T1, usec=5, seq=7, saddr=None, raddr=None):
    return _app(28, _seq(_ctx(0, _octet(data)), _field(1, None if ts is None else _gtime(ts)),
                         _field(2, None if usec is None else _ber_int(usec)),
                         _field(3, None if seq is None else _ber_int(seq)),
                         _ctx(4, saddr or host_addr(2, bytes([192, 0, 2, 10]))),
                         _field(5, raddr)))


def krb_safe(data, key, ts=T1, usec=6, seq=8, saddr=None, raddr=None):
    body = _seq(_ctx(0, _octet(data)), _field(1, None if ts is None else _gtime(ts)),
                _field(2, None if usec is None else _ber_int(usec)),
                _field(3, None if seq is None else _ber_int(seq)),
                _field(4, saddr), _field(5, raddr))
    ck = krb5_checksum(CKSUM_FOR[key[0]], key[0], key[1], body, U_SAFE)
    return _app(20, _seq(_ctx(0, _ber_int(5)), _ctx(1, _ber_int(20)), _ctx(2, body),
                         _ctx(3, cksum(CKSUM_FOR[key[0]], ck))))


def krb_cred_info(skey_, prealm=REALM, pname=None, flags=None, srealm=REALM, sname=None,
                  caddr=None, times=True):
    return _seq(_ctx(0, enc_key(*skey_)), _field(1, None if prealm is None else _gstring(prealm)),
                _field(2, pname), _field(3, None if flags is None else _bits32(flags)),
                _field(4, _gtime(T0) if times else None), _field(5, _gtime(T0) if times else None),
                _field(6, _gtime(T_END) if times else None),
                _field(7, _gtime(T_RENEW) if times else None),
                _field(8, None if srealm is None else _gstring(srealm)),
                _field(9, sname), _field(10, caddr))


def enc_krb_cred_part(infos, nonce=99, ts=T1, usec=7, saddr=None, raddr=None):
    return _app(29, _seq(_ctx(0, _seqof(infos)),
                         _field(1, None if nonce is None else _ber_int(nonce)),
                         _field(2, None if ts is None else _gtime(ts)),
                         _field(3, None if usec is None else _ber_int(usec)),
                         _field(4, saddr), _field(5, raddr)))


def krb_cred(tickets, plain, key=None):
    if key is None:
        enc = enc_data(0, plain)
    else:
        enc = encrypt_der(key[0], key[1], plain, U_CRED)
    return _app(22, _seq(_ctx(0, _ber_int(5)), _ctx(1, _ber_int(22)),
                         _ctx(2, _seqof(tickets)), _ctx(3, enc)))


# ------------------------------------------------------------------ pa-data values
def pa_enc_ts(key, ts=T1, usec=654321, usage=U_ENC_TS, with_usec=True):
    plain = _seq(_ctx(0, _gtime(ts)), _field(1, _ber_int(usec) if with_usec else None))
    return padata(PA_ENC_TIMESTAMP, encrypt_der(key[0], key[1], plain, usage))


def etype_info2(entries):
    """entries: (etype, salt or None, s2kparams or None)."""
    return _seqof([_seq(_ctx(0, _ber_int(e)), _field(1, None if s is None else _gstring(s)),
                        _field(2, None if p is None else _octet(p))) for e, s, p in entries])


def etype_info(entries):
    return _seqof([_seq(_ctx(0, _ber_int(e)), _field(1, None if s is None else _octet(s)))
                   for e, s in entries])


def pa_pac_request(include=True):
    return padata(PA_PAC_REQUEST, _seq(_ctx(0, _bool(include))))


def pa_pac_options(bits=flagbits(0, 1, 3)):
    return padata(PA_PAC_OPTIONS, _seq(_ctx(0, _bits32(bits))))


def pa_supported_etypes(v=0x1f):
    return padata(PA_SUPPORTED_ETYPES, struct.pack('<I', v))


def pa_tgs_req(apreq):
    return padata(PA_TGS_REQ, apreq)


# ------------------------------------------------------------------ transport
def mac_of(ip):
    return bytes([2, 0, 0, 0, 0, ip[3]])


class Cap:
    """The frames of one capture file."""

    def __init__(self):
        self.frames = []

    def udp(self, payload, sip, sport, dip, dport):
        sip, dip = bytes(sip), bytes(dip)
        udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
        ph = sip + dip + struct.pack('>BBH', 0, 17, len(udp) + len(payload))
        udp = udp[:6] + struct.pack('>H', csum(ph + udp + payload) or 0xffff) + udp[8:]
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp) + len(payload),
                         0, 0x4000, 64, 17, 0, sip, dip)
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        self.frames.append(mac_of(dip) + mac_of(sip) + b'\x08\x00' + ip + udp + payload)

    def tcp(self, cport, cip, sip, sport=88):
        return TCP(self.frames, cport, sport=sport, cip=cip, sip=sip)


def rm(pdu, flag=0):
    """Kerberos over TCP: a record mark (length) before each message."""
    return struct.pack('>I', len(pdu) | flag) + pdu


C1 = (192, 0, 2, 10)
KDC = (192, 0, 2, 88)
FILES_IP = (192, 0, 2, 20)
DC_IP = (192, 0, 2, 21)


def gss_cksum(flags, bnd=b'\0' * 16, deleg=None, ext=(), dlgopt=1):
    out = struct.pack('<I', len(bnd)) + bnd + struct.pack('<I', flags)
    if flags & 1:
        out += struct.pack('<HH', dlgopt, len(deleg)) + deleg
    for t, d in ext:
        out += struct.pack('>II', t, len(d)) + d
    return cksum(0x8003, out)


GSS_DELEG, GSS_MUTUAL, GSS_REPLAY, GSS_SEQ, GSS_CONF, GSS_INTEG, GSS_DCE = 1, 2, 4, 8, 0x10, 0x20, 0x1000
AP_MUTUAL = 0x20000000
AP_USE_SESSION_KEY = 0x40000000


# ------------------------------------------------------------------ the key log
def longterm_keys():
    """(etype, key) of every long-term key the capture needs."""
    out = []
    for p in (ALICE, BOB, KRBTGT, FILES, CIFS, WS01, LDAPS, DCEP):
        for et, k in p.keys.items():
            out.append((et, k))
    return out


ETYPE_NAMES = {
    3: 'des-cbc-md5', 16: 'des3-cbc-sha1', 17: 'aes128-cts-hmac-sha1-96', 18: 'aes256-cts-hmac-sha1-96',
    19: 'aes128-cts-hmac-sha256-128', 20: 'aes256-cts-hmac-sha384-192', 23: 'arcfour-hmac',
    25: 'camellia128-cts-cmac', 26: 'camellia256-cts-cmac'}
ETYPE_ALIASES = {17: ('aes128-cts', 'etype-aes128-cts', '17'), 18: ('aes256-cts', 'ETYPE-aes256-cts', '18'),
                 23: ('rc4-hmac', 'arcfour-hmac-md5', '23')}


def kerberos_keylog():
    """One long-term key per line: an encryption type (a name or a number)
    and a hex key. Every spelling the parser knows is used, then a few
    lines it must refuse. Empty lines and comments are ignored."""
    lines = ['# encryption-type hex-key', '', '   # an indented comment']
    keys = longterm_keys()
    for n, (et, k) in enumerate(keys):
        spell = [ETYPE_NAMES[et]] + list(ETYPE_ALIASES.get(et, ()))
        lines.append('%s %s' % (spell[n % len(spell)], k.hex()))
    for et, k in DECOYS:
        lines.append('%d\t%s' % (et, k.hex()))
    # table entries nothing in the capture uses
    for name, ln in (('des-cbc-crc', 8), ('des-cbc-md4', 8), ('des3-hmac-sha1', 24),
                     ('arcfour-hmac-exp', 16), ('aes128-cts', 16), ('aes256-cts', 32),
                     ('ETYPE-aes256-cts-hmac-sha1-96', 32), ('camellia128-cts-cmac', 16)):
        lines.append('%s %s' % (name, bytes([0x5a ^ ln] * ln).hex()))
    lines += [
        'aes256-cts-hmac-sha1-96',                       # no key
        'aes256-cts-hmac-sha1-96 0123456789abcdef x',    # data after the key
        'no-such-etype 0011223344556677',                # unknown type
        '18 0g11',                                       # bad hex
        '18 ' + '00' * 40,                               # key too long
        '18 ' + keys[0][1].hex() + ' ',                  # a repeat, trailing blank
        '18  ' + keys[1][1].hex(),                       # two blanks
    ]
    return ('\r\n'.join(lines[:12]) + '\n' + '\n'.join(lines[12:]) + '\n').encode()


# ------------------------------------------------------------------ scenario 1
SK_TGT = skey('tgt', 18)
SK_FILES = skey('files', 18)
SUB_TGS = skey('tgs-sub', 18)
SUB_AP = skey('ap-sub', 18)
SUB_ACC = skey('acc-sub', 18)

ADDRS_OK = addresses(host_addr(2, bytes([192, 0, 2, 10])),
                     host_addr(24, bytes([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10])),
                     host_addr(20, b'WS01' + b' ' * 11 + b'\0'))
ADDRS_BAD = addresses(host_addr(2, bytes([192, 0, 2, 10])),
                  host_addr(24, bytes([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10])),
                  host_addr(20, b'WS01' + b' ' * 11 + b'\0'),
                  host_addr(7, b'\x01\x02'))
ADDRS = ADDRS_OK


def scenario_basic(F):
    """AS exchange with pre-authentication, TGS and AP exchanges, over UDP."""
    sp = 50010
    body = kdc_req_body(ALICE.der(), KRBTGT.der(), 1111, [18, 17, 23, 3, 1], addrs=ADDRS,
                        frm=T0, rtime=T_RENEW)
    F.udp(as_req([pa_pac_request(True)], body), C1, sp, KDC, 88)
    edata = _seqof([padata(PA_ETYPE_INFO2, etype_info2([(18, 'EXAMPLE.TESTalice', None),
                                                         (17, 'EXAMPLE.TESTalice', None),
                                                         (23, None, None)])),
                    padata(PA_ETYPE_INFO, etype_info([(18, b'EXAMPLE.TESTalice'), (23, None)])),
                    padata(PA_PW_SALT, b'EXAMPLE.TESTalice'),
                    padata(PA_ENC_TIMESTAMP, b''),
                    padata(PA_FX_COOKIE, b'cookie-1')])
    F.udp(krb_error(25, sname=KRBTGT.der(), crealm=REALM, cname=ALICE.der(), edata=edata,
                    etext='Pre-authentication required'), KDC, 88, C1, sp)
    # AS-REQ with encrypted timestamp, and a lot of padata
    body = kdc_req_body(ALICE.der(), KRBTGT.der(), 2222, [18, 17, 23], addrs=ADDRS)
    pas = [pa_enc_ts((18, ALICE.key(18))), pa_pac_request(True), pa_pac_options(),
           pa_supported_etypes(0x1f),
           padata(PA_KERB_KEY_LIST_REQ, _seqof([_ber_int(23), _ber_int(18)])),
           padata(PA_FX_COOKIE, b'cookie-1')]
    F.udp(as_req(pas, body), C1, sp, KDC, 88)
    tgt, _ = pac_ticket(KRBTGT, KRBTGT, SK_TGT, ALICE, std_infos(creds=(18, ALICE.key(18))))
    flags = flagbits(1, 5, 8, 9, 10, 13)
    enc_pa = [pa_supported_etypes(0x1f),
              padata(PA_KERB_KEY_LIST_REP, _seqof([enc_key(23, bytes(range(16)))])),
              padata(PA_REQ_ENC_PA_REP, cksum(16, bytes(12)))]
    plain = enc_kdc_rep_part(25, SK_TGT, 2222, flags, KRBTGT.der(), caddr=ADDRS, enc_pa=enc_pa)
    rep = kdc_rep(11, [padata(PA_ETYPE_INFO2, etype_info2([(18, 'EXAMPLE.TESTalice', None)])),
                       padata(PA_PW_SALT, b'EXAMPLE.TESTalice')],
                  REALM, ALICE.der(), tgt, encrypt_der(18, ALICE.key(18), plain, U_ASREP, 1))
    F.udp(rep, KDC, 88, C1, sp)
    # TGS-REQ, authenticator subkey, KDC reply encrypted with the subkey
    sname = FILES.der()
    ad = authz((1, authz((143, struct.pack('<I', 1)))))
    body = kdc_req_body(None, sname, 3333, [18, 17, 23],
                        enc_authz=encrypt_der(18, SUB_TGS[1], ad, U_TGS_AD_SUB))
    ck = krb5_checksum(16, 18, SK_TGT[1], body, U_TGS_CKSUM)
    auth = authenticator(ALICE.der(), subkey=SUB_TGS, seq=0x1234, cks=cksum(16, ck))
    apreq = ap_req(tgt, auth, SK_TGT, usage=U_TGS_AUTH)
    F.udp(tgs_req([pa_tgs_req(apreq), pa_pac_options()], body), C1, sp + 1, KDC, 88)
    svc, _ = pac_ticket(FILES, KRBTGT, SK_FILES, ALICE, std_infos())
    plain = enc_kdc_rep_part(26, SK_FILES, 3333, flags, sname)
    rep = kdc_rep(13, None, REALM, ALICE.der(), svc,
                  encrypt_der(18, SUB_TGS[1], plain, U_TGSREP_SUB, 1))
    F.udp(rep, KDC, 88, C1, sp + 1)
    # AP-REQ / AP-REP
    dcred = krb_cred([svc], enc_krb_cred_part([krb_cred_info(SK_FILES, pname=ALICE.der(),
                                                              flags=flags, sname=sname)]))
    ck = gss_cksum(GSS_MUTUAL | GSS_REPLAY | GSS_SEQ | GSS_CONF | GSS_INTEG)
    adl = authz((1, authz((143, struct.pack('<I', 1)), (144, utf16('host/files.example.test@EXAMPLE.TEST')))))
    auth = authenticator(ALICE.der(), subkey=SUB_AP, seq=0x4321, cks=ck, ad=adl)
    F.udp(ap_req(svc, auth, SK_FILES, AP_MUTUAL), C1, sp + 2, FILES_IP, 88)
    F.udp(ap_rep(enc_ap_rep_part(subkey=SUB_ACC, seq=0x5555), SK_FILES), FILES_IP, 88, C1, sp + 2)
    F.udp(krb_priv(enc_krb_priv_part(b'private-data'), SK_FILES), C1, sp + 3, FILES_IP, 88)
    F.udp(krb_safe(b'safe-data', SK_FILES), C1, sp + 3, FILES_IP, 88)


# ------------------------------------------------------------------ FAST
MACH = Princ('ws01$', 9, 1)
SK_TGT_M = skey('tgt-m', 18)
ARMOR_SUB = skey('armor-sub', 18)
SK_STRENGTH = skey('strengthen', 18)
SUB_TGS_F = skey('tgs-sub-fast', 18)
SK_FILES_F = skey('files-fast', 18)
EXPL_SUB = skey('expl-sub', 18)


def light_infos():
    """A small PAC: logon info and client info only."""
    return [(1, pac_logon_buffer()), (10, pac_client_info())]


def fast_req(armor_key, outer_body, inner_padata, inner_body, armor_der=None, options=flagbits(1, 16)):
    """PA-FX-FAST value: KrbFastArmoredReq. The request checksum covers the
    outer KDC-REQ-BODY and uses the armor key (usage 50)."""
    req = _seq(_ctx(0, _bits32(options)), _ctx(1, _seqof(inner_padata)), _ctx(2, inner_body))
    ck = krb5_checksum(CKSUM_FOR[armor_key[0]], armor_key[0], armor_key[1], outer_body, U_FAST_REQ_CKSUM)
    enc = _seq(_ctx(0, _ber_int(armor_key[0])), _ctx(2, _octet(krb5_encrypt(armor_key[0], armor_key[1], req, U_FAST_ENC))))
    return _ctx(0, _seq(_field(0, armor_der), _ctx(1, cksum(CKSUM_FOR[armor_key[0]], ck)), _ctx(2, enc)))


def fast_rep(armor_key, padatas, nonce, strengthen=None, finished=None):
    resp = _seq(_ctx(0, _seqof(padatas)), _field(1, None if strengthen is None else enc_key(*strengthen)),
                _field(2, finished), _ctx(3, _ber_int(nonce)))
    enc = _seq(_ctx(0, _ber_int(armor_key[0])), _ctx(2, _octet(krb5_encrypt(armor_key[0], armor_key[1], resp, U_FAST_REP))))
    return _ctx(0, _seq(_ctx(0, enc)))


def armor_ap(tgt, sk, sub, cname):
    """KrbFastArmor: an AP-REQ built from a TGT."""
    auth = authenticator(cname, subkey=sub, ctime=T1)
    return _seq(_ctx(0, _ber_int(1)), _ctx(1, _octet(ap_req(tgt, auth, sk))))


def challenge(armor_key, client_key, pepper, usage):
    """PA-ENCRYPTED-CHALLENGE value: PA-ENC-TS-ENC encrypted with
    CF2(armor key, pepper, client key, "challengelongterm")."""
    et, k = krb5_cf2(armor_key[0], armor_key[1], pepper, client_key[0], client_key[1], b'challengelongterm')
    plain = _seq(_ctx(0, _gtime(T1)), _ctx(1, _ber_int(777)))
    return _seq(_ctx(0, _ber_int(et)), _ctx(2, _octet(krb5_encrypt(et, k, plain, usage))))


def scenario_fast(F):
    """FAST (RFC 6113): an armored AS exchange with an encrypted challenge,
    an armored TGS exchange with the TGS subkey as armor, and the
    compound identity armor of [MS-KILE]."""
    sp = 50030
    tgt_m, _ = pac_ticket(KRBTGT, KRBTGT, SK_TGT_M, MACH, light_infos())
    armor_key = krb5_cf2(18, ARMOR_SUB[1], b'subkeyarmor', 18, SK_TGT_M[1], b'ticketarmor')
    armor_key = (armor_key[0], armor_key[1])
    outer = kdc_req_body(None, KRBTGT.der(), 4444, [18, 17], realm=REALM, till=None, options=KDC_OPTS)
    # frame: armored AS-REQ without pre-authentication
    inner_body = kdc_req_body(ALICE.der(), KRBTGT.der(), 4444, [18, 17], addrs=ADDRS)
    fa = fast_req(armor_key, outer, [pa_pac_request(True)], inner_body, armor_ap(tgt_m, SK_TGT_M, ARMOR_SUB, MACH.der()))
    F.udp(as_req([padata(PA_FX_FAST, fa)], outer), C1, sp, KDC, 88)
    # the KDC asks for pre-authentication, inside FAST
    err_inner = krb_error(25, crealm=REALM, cname=ALICE.der(), etext='Pre-authentication required')
    fr = fast_rep(armor_key, [padata(PA_ETYPE_INFO2, etype_info2([(18, 'EXAMPLE.TESTalice', None)])),
                              padata(PA_FX_COOKIE, b'fast-cookie')], 4444)
    F.udp(krb_error(25, edata=_seqof([padata(PA_FX_FAST, fr), padata(PA_FX_ERROR, err_inner)]),
                    crealm=REALM, cname=ALICE.der()), KDC, 88, C1, sp)
    # armored AS-REQ with an encrypted challenge
    ech = challenge(armor_key, (18, ALICE.key(18)), b'clientchallengearmor', U_CHALLENGE_CLIENT)
    fa = fast_req(armor_key, outer, [padata(PA_ENCRYPTED_CHALLENGE, ech), pa_pac_request(True)], inner_body,
                  armor_ap(tgt_m, SK_TGT_M, ARMOR_SUB, MACH.der()))
    F.udp(as_req([padata(PA_FX_FAST, fa)], outer), C1, sp, KDC, 88)
    # AS-REP: strengthen key, KDC challenge and the finished structure
    tgt, _ = pac_ticket(KRBTGT, KRBTGT, SK_TGT, ALICE, light_infos())
    kch = challenge(armor_key, (18, ALICE.key(18)), b'kdcchallengearmor', U_CHALLENGE_KDC)
    tck = krb5_checksum(16, armor_key[0], armor_key[1], tgt, U_FAST_FINISHED)
    fin = _seq(_ctx(0, _gtime(T1)), _ctx(1, _ber_int(5)), _ctx(2, _gstring(REALM)),
               _ctx(3, ALICE.der()), _ctx(4, cksum(16, tck)))
    fr = fast_rep(armor_key, [padata(PA_ENCRYPTED_CHALLENGE, kch)], 4444, SK_STRENGTH, fin)
    rk = krb5_cf2(18, SK_STRENGTH[1], b'strengthenkey', 18, ALICE.key(18), b'replykey')
    plain = enc_kdc_rep_part(25, SK_TGT, 4444, flagbits(1, 5, 8, 9, 10, 13), KRBTGT.der())
    F.udp(kdc_rep(11, [padata(PA_FX_FAST, fr)], REALM, ALICE.der(), tgt,
                  encrypt_der(rk[0], rk[1], plain, U_ASREP, 1)), KDC, 88, C1, sp)
    # TGS-REQ armored with the TGS subkey (no armor field)
    sname = FILES.der()
    outer = kdc_req_body(None, sname, 5555, [18, 17], till=None)
    tgs_armor = krb5_cf2(18, SUB_TGS_F[1], b'subkeyarmor', 18, SK_TGT[1], b'ticketarmor')
    inner_body = kdc_req_body(None, sname, 5555, [18, 17], till=T_END)
    fa = fast_req(tgs_armor, outer, [pa_pac_options()], inner_body)
    ck = krb5_checksum(16, 18, SK_TGT[1], outer, U_TGS_CKSUM)
    auth = authenticator(ALICE.der(), subkey=SUB_TGS_F, cks=cksum(16, ck))
    apreq = ap_req(tgt, auth, SK_TGT, usage=U_TGS_AUTH)
    F.udp(tgs_req([pa_tgs_req(apreq), padata(PA_FX_FAST, fa)], outer), C1, sp + 1, KDC, 88)
    svc, _ = pac_ticket(FILES, KRBTGT, SK_FILES_F, ALICE, light_infos())
    sk2 = skey('strengthen2', 18)
    fr = fast_rep(tgs_armor, [], 5555, sk2)
    rk = krb5_cf2(18, sk2[1], b'strengthenkey', 18, SUB_TGS_F[1], b'replykey')
    plain = enc_kdc_rep_part(26, SK_FILES_F, 5555, flagbits(1, 5, 8, 9, 10, 13), sname)
    F.udp(kdc_rep(13, [padata(PA_FX_FAST, fr)], REALM, ALICE.der(), svc,
                  encrypt_der(rk[0], rk[1], plain, U_TGSREP_SUB, 1)), KDC, 88, C1, sp + 1)
    # TGS-REQ with an armor AP-REQ and a TGS subkey: compound identity
    expl = krb5_cf2(18, armor_key[1], b'explicitarmor', 18, SUB_TGS_F[1], b'tgsarmor')
    # the first step uses the armor AP-REQ's subkey and the armor ticket's session key
    first = krb5_cf2(18, ARMOR_SUB[1], b'subkeyarmor', 18, SK_TGT_M[1], b'ticketarmor')
    expl = krb5_cf2(first[0], first[1], b'explicitarmor', 18, SUB_TGS_F[1], b'tgsarmor')
    inner_body = kdc_req_body(None, sname, 6666, [18], till=T_END)
    outer = kdc_req_body(None, sname, 6666, [18], till=None)
    fa = fast_req(expl, outer, [pa_pac_options()], inner_body, armor_ap(tgt_m, SK_TGT_M, ARMOR_SUB, MACH.der()))
    ck = krb5_checksum(16, 18, SK_TGT[1], outer, U_TGS_CKSUM)
    auth = authenticator(ALICE.der(), subkey=SUB_TGS_F, cks=cksum(16, ck), seq=77)
    apreq = ap_req(tgt, auth, SK_TGT, usage=U_TGS_AUTH)
    F.udp(tgs_req([pa_tgs_req(apreq), padata(PA_FX_FAST, fa)], outer), C1, sp + 2, KDC, 88)

# ------------------------------------------------------------------ TCP and RC4
SK_TGT_RC4 = skey('tgt-rc4', 23, 140)
SK_FILES_RC4 = skey('files-rc4', 23, 141)
SK_CIFS_RC4 = skey('cifs-rc4', 23, 142)


def scenario_tcp(F):
    """RC4-HMAC exchanges over TCP: record marks, a request sent in pieces,
    a reply longer than one segment, two messages in one segment, and
    the UDP reply that asks the client to retry over TCP."""
    C2 = (192, 0, 2, 11)
    body = kdc_req_body(ALICE.der(), KRBTGT.der(), 7001, [23, 18], addrs=ADDRS)
    pas = [pa_enc_ts((23, ALICE.key(23))), pa_pac_request(True)]
    req = as_req(pas, body)
    # the UDP reply that makes the client retry over TCP
    F.udp(req, C2, 50040, KDC, 88)
    F.udp(krb_error(52, etext='Response too big for UDP, retry with TCP'), KDC, 88, C2, 50040)
    t = F.tcp(50041, C2, KDC)
    pdu = rm(req)
    t.seg(True, pdu[:3])
    t.seg(True, pdu[3:20])
    t.seg(True, pdu[20:])
    tgt, _ = pac_ticket(KRBTGT, KRBTGT, SK_TGT_RC4, ALICE, std_infos(), srv_et=23, kdc_et=23)
    flags = flagbits(1, 5, 8, 9, 10, 13)
    plain = enc_kdc_rep_part(25, SK_TGT_RC4, 7001, flags, KRBTGT.der())
    rep = kdc_rep(11, [padata(PA_ETYPE_INFO2, etype_info2([(23, None, None)]))], REALM, ALICE.der(), tgt,
                  encrypt_der(23, ALICE.key(23), plain, U_ASREP, 1))
    t.send(False, rm(rep))
    # two TGS-REQs in one segment, two replies in one segment
    reqs, reps = [], []
    for n, (svc_p, sk, nonce) in enumerate(((FILES, SK_FILES_RC4, 7002), (CIFS, SK_CIFS_RC4, 7003))):
        sname = svc_p.der()
        b = kdc_req_body(None, sname, nonce, [23])
        ck = krb5_checksum(-138, 23, SK_TGT_RC4[1], b, U_TGS_CKSUM)
        auth = authenticator(ALICE.der(), cks=cksum(-138, ck))
        apreq = ap_req(tgt, auth, SK_TGT_RC4, usage=U_TGS_AUTH)
        reqs.append(rm(tgs_req([pa_tgs_req(apreq)], b)))
        svc, _ = pac_ticket(svc_p, KRBTGT, sk, ALICE, light_infos(), srv_et=23, kdc_et=23)
        plain = enc_kdc_rep_part(26, sk, nonce, flags, sname)
        reps.append(rm(kdc_rep(13, None, REALM, ALICE.der(), svc,
                               encrypt_der(23, SK_TGT_RC4[1], plain, U_TGSREP, 1))))
    t.seg(True, b''.join(reqs))
    t.seg(False, b''.join(reps))
    t.fin()

# ------------------------------------------------------------------ pre-authentication data
def alg_id(oid_der):
    return _seq(oid_der, _ber(0x05, b''))


OID_SHA256 = _ber(0x06, bytes.fromhex('608648016503040201'))
OID_SHA1 = _ber(0x06, bytes.fromhex('2b0e03021a'))


def srp_announce():
    groups = _ber(0x31, _seq(_ctx(0, _ber_int(1)), _ctx(1, _octet(b'salt-salt')), _ctx(2, _ber_int(4096))))
    return _seq(_ctx(0, groups), _ctx(1, cksum(7, bytes(16))))


def spake_values():
    """The four PA-SPAKE choices."""
    support = _ctx(0, _seq(_ctx(0, _seqof([_ber_int(1), _ber_int(2)]))))
    challenge = _ctx(1, _seq(_ctx(0, _ber_int(1)), _ctx(1, _octet(b'P' * 32)),
                             _ctx(2, _seqof([_seq(_ctx(0, _ber_int(1)), _ctx(1, _octet(b'f'))),
                                             _seq(_ctx(0, _ber_int(1)))]))))
    response = _ctx(2, _seq(_ctx(0, _octet(b'Q' * 32)),
                            _ctx(1, _seq(_ctx(0, _ber_int(18)), _ctx(1, _ber_int(1)), _ctx(2, _octet(b'c' * 40))))))
    encdata = _ctx(3, _seq(_ctx(0, _ber_int(18)), _ctx(1, _ber_int(3)), _ctx(2, _octet(b'd' * 40))))
    return support, challenge, response, encdata


def ps4u_cksum(key_et, key, name_parts, realm, nt, auth=b'Kerberos'):
    """The PA-FOR-USER checksum: HMAC-MD5 (-138) over the name type
    (little endian), the name strings, the realm and the auth package,
    with key usage 17."""
    data = struct.pack('<I', nt) + b''.join(p.encode() for p in name_parts) + realm.encode() + auth
    return krb5_checksum(-138, key_et, key, data, U_APP_CKSUM)


def pa_for_user(key_et, key, user, realm=REALM):
    ck = ps4u_cksum(key_et, key, user.parts, realm, user.nt)
    return padata(PA_FOR_USER, _seq(_ctx(0, user.der()), _ctx(1, _gstring(realm)),
                                    _ctx(2, cksum(-138, ck)), _ctx(3, _gstring('Kerberos'))))


def pa_for_x509_user(key_et, key, user, nonce, realm=REALM):
    uid = _seq(_ctx(0, _ber_int(nonce)), _ctx(1, user.der()), _ctx(2, _gstring(realm)),
               _ctx(4, _bits32(flagbits(1))))
    ck = krb5_checksum(-138, key_et, key, uid, U_APP_CKSUM)
    return padata(PA_FOR_X509_USER, _seq(_ctx(0, uid), _ctx(1, cksum(-138, ck))))


def sample_ads(with_pac=False):
    """Authorization data of every type the dissector decodes."""
    cammac = _seq(_ctx(0, authz((1, authz((143, struct.pack('<I', 3)))))),
                  _ctx(1, _seq(_ctx(0, principal(1, 'krbtgt')), _ctx(1, _ber_int(2)), _ctx(2, _ber_int(18)),
                               _ctx(3, cksum(16, bytes(12))))),
                  _ctx(2, _seq(_ctx(3, cksum(16, bytes(12))))),
                  _ctx(3, _seqof([_seq(_ctx(0, principal(1, 'svc')), _ctx(3, cksum(16, bytes(12))))])))
    indicator = _seqof([_ber(0x0c, b'pkinit'), _ber(0x0c, b'otp')])
    strength = _seq(_ctx(0, _ber_int(PA_ENC_TIMESTAMP)), _ctx(1, _octet(b'hint')), _ctx(2, _octet(b'val')))
    etypes = _seqof([_ber_int(18), _ber_int(17), _ber_int(23)])
    # the dissector wants the [UNIVERSAL 16] tag explicit: a SEQUENCE in a SEQUENCE
    restriction = _seq(_seq(_ctx(0, _ber_int(0)), _ctx(1, _octet(struct.pack('<IIII', 0, 0x3000, 0, 0)))))
    return [(96, cammac), (97, indicator), (70, strength), (129, etypes), (141, restriction),
            (143, struct.pack('<I', 3)), (144, utf16('cifs/files.example.test@EXAMPLE.TEST')),
            (4, b'kdc-issued'), (142, b'\1\2\3\4')]


def scenario_padata(F):
    """Pre-authentication data of every kind the dissector decodes, KRB-ERROR
    with every e-data shape, authorization data of every type, and S4U."""
    sp = 50050
    sup, chal, resp, encd = spake_values()
    # An AS-REQ that carries the request-side values
    srp_init = _app(0, _seq(_ctx(0, _ber_int(1)), _ctx(1, _octet(b'A' * 20))))
    pas = [pa_enc_ts((18, ALICE.key(18)), with_usec=False),
           padata(PA_PW_SALT, b'x'),
           padata(135, _seq(_ctx(0, _ber_int(PA_ENC_TIMESTAMP)), _ctx(1, _octet(b'hint')))),
           padata(151, sup), padata(151, resp),
           padata(250, srp_init), padata(250, _app(2, _octet(b'm' * 20))),
           padata(250, _app(9, _octet(b'unknown'))),
           padata(250, srp_announce()),
           padata(PA_KERB_KEY_LIST_REQ, _seqof([_ber_int(18)])),
           padata(PA_REQ_ENC_PA_REP, cksum(16, bytes(12))),
           padata(-1, _ber(0x1b, b'prov.example.test:80')),
           padata(PA_PAC_OPTIONS, _seq(_ctx(0, _bits32(flagbits(0, 1, 2, 3))))),
           padata(111, _seqof([alg_id(OID_SHA256), alg_id(OID_SHA1)])),
           padata(112, _seq(_ctx(0, _seqof([alg_id(OID_SHA256)])), _ctx(1, alg_id(OID_SHA1)))),
           pa_supported_etypes(0xffff), pa_pac_request(False),
           padata(150, b'\x30\x00')]
    body = kdc_req_body(ALICE.der(), KRBTGT.der(), 8001, [18, 17, 23])
    F.udp(as_req(pas, body), C1, sp, KDC, 88)
    # KRB-ERROR with each e-data shape
    err = lambda code, **kw: krb_error(code, crealm=REALM, cname=ALICE.der(), **kw)
    mdata = lambda *p: _seqof(list(p))
    F.udp(err(25, edata=mdata(padata(250, srp_announce()), padata(PA_ETYPE_INFO2, etype_info2([(18, 'S', b'\0\0\x10\0')])))),
          KDC, 88, C1, sp)
    F.udp(err(25, edata=mdata(padata(151, chal), padata(151, encd), padata(PA_PW_SALT, bytes(range(5))))),
          KDC, 88, C1, sp)
    F.udp(err(24, edata=mdata(padata(PA_PW_SALT, struct.pack('<III', 0xC000006A, 0, 1)),
                              padata(PA_EXTENDED_ERROR, struct.pack('<III', 0xC000006A, 0, 1)))),
          KDC, 88, C1, sp)
    F.udp(err(24, edata=mdata(padata(PA_PW_SALT, struct.pack('<III', 0xC000006A, 1, 0)))), KDC, 88, C1, sp)
    F.udp(err(24, edata=mdata(padata(PA_PW_SALT, struct.pack('<III', 0x12345678, 0, 1)))), KDC, 88, C1, sp)
    F.udp(err(25, edata=padata(PA_ETYPE_INFO2, etype_info2([(23, None, None)]))), KDC, 88, C1, sp)
    F.udp(err(25, edata=b'not-a-der-structure'), KDC, 88, C1, sp)
    F.udp(err(25, edata=_seq()), KDC, 88, C1, sp)
    F.udp(err(25, edata=_seq(_ber(0x02, b'\x01'))), KDC, 88, C1, sp)
    F.udp(err(31, etext='Integrity check on decrypted field failed', echeck=cksum(16, bytes(12))), KDC, 88, C1, sp)
    F.udp(err(41, ctime=T0, cusec=1, sname=FILES.der()), KDC, 88, C1, sp)
    F.udp(err(60, edata=mdata(padata(PA_FX_ERROR, krb_error(25)))), KDC, 88, C1, sp)
    # an AS-REP with every encrypted-pa-data kind, and an S4U TGS exchange
    tgt, _ = pac_ticket(KRBTGT, KRBTGT, SK_TGT, ALICE, light_infos())
    S4U_SK = skey('s4u-tgt', 23, 150)
    flags = flagbits(1, 5, 8, 9, 10, 13)
    enc_pa = [padata(PA_FOR_X509_USER, _seq(_ctx(0, _seq(_ctx(0, _ber_int(8001)), _ctx(2, _gstring(REALM)))),
                                            _ctx(1, cksum(-138, bytes(16))))),
              pa_supported_etypes(), padata(PA_KERB_KEY_LIST_REP, _seqof([enc_key(18, bytes(range(32))), enc_key(23, bytes(16))])),
              padata(PA_EXTENDED_ERROR, struct.pack('<III', 0, 0, 1)),
              padata(PA_REQ_ENC_PA_REP, cksum(16, bytes(12))), padata(PA_PAC_OPTIONS, _seq(_ctx(0, _bits32(0x80000000))))]
    plain = enc_kdc_rep_part(25, SK_TGT, 8001, flags, KRBTGT.der(), enc_pa=enc_pa)
    F.udp(kdc_rep(11, [padata(PA_ETYPE_INFO2, etype_info2([(18, 'EXAMPLE.TESTalice', b'\0\0\x10\0')])),
                       padata(PA_PW_SALT, b'EXAMPLE.TESTalice'), padata(250, _app(1, _octet(b'B' * 20))),
                       padata(250, _app(3, _octet(b'H' * 20))), padata(250, srp_announce())],
                  REALM, ALICE.der(), tgt, encrypt_der(18, ALICE.key(18), plain, U_ASREP, 1)), KDC, 88, C1, sp)
    # S4U2Self: the service asks for a ticket to itself in the name of bob
    SK_S = skey('svc-tgt', 23, 151)
    tgt_s, _ = pac_ticket(KRBTGT, KRBTGT, SK_S, ALICE, light_infos(), srv_et=23, kdc_et=23, pac_srv_et=18)
    sname = FILES.der()
    body = kdc_req_body(None, sname, 8002, [23])
    ck = krb5_checksum(-138, 23, SK_S[1], body, U_TGS_CKSUM)
    auth = authenticator(ALICE.der(), cks=cksum(-138, ck))
    apreq = ap_req(tgt_s, auth, SK_S, usage=U_TGS_AUTH)
    F.udp(tgs_req([pa_tgs_req(apreq), pa_for_user(23, SK_S[1], BOB), pa_for_x509_user(23, SK_S[1], BOB, 8002)], body),
          C1, sp + 1, KDC, 88)
    SK_B = skey('s4u-svc', 23, 152)
    infos = [(1, pac_logon_buffer()), (10, pac_client_info('bob'))]
    svc, _ = pac_ticket(FILES, KRBTGT, SK_B, BOB, infos, srv_et=23, kdc_et=23)
    plain = enc_kdc_rep_part(26, SK_B, 8002, flags, sname)
    F.udp(kdc_rep(13, [padata(PA_FOR_USER, _seq(_ctx(0, BOB.der()), _ctx(1, _gstring(REALM)),
                                              _ctx(2, cksum(-138, ps4u_cksum(23, SK_S[1], BOB.parts, REALM, 1))),
                                              _ctx(3, _gstring('Kerberos')))),
                      padata(PA_FOR_X509_USER, _seq(_ctx(0, _seq(_ctx(0, _ber_int(8002)), _ctx(2, _gstring(REALM)))),
                                                   _ctx(1, cksum(-138, bytes(16)))))],
                  REALM, BOB.der(), svc, encrypt_der(23, SK_S[1], plain, U_TGSREP, 1)), KDC, 88, C1, sp + 1)
    # S4U2Proxy: constrained delegation with the S4U ticket as additional ticket,
    # and the PAC of the resulting ticket carries PAC_S4U_DELEGATION_INFO
    sname2 = CIFS.der()
    opts = flagbits(1, 3, 8, 14, 15)
    ad = authz((1, authz((143, struct.pack('<I', 1)))), (5, _seq(_ctx(0, _ber_int(1)), _ctx(1, authz((143, b'\1\0\0\0'))))),
               (8, authz((144, utf16('cifs/files.example.test')))))
    body = kdc_req_body(None, sname2, 8003, [23, 18], options=opts, add_tickets=[svc],
                        enc_authz=encrypt_der(23, SK_S[1], ad, U_TGS_AD))
    ck = krb5_checksum(-138, 23, SK_S[1], body, U_TGS_CKSUM)
    auth = authenticator(ALICE.der(), cks=cksum(-138, ck), ad=authz(*sample_ads()))
    apreq = ap_req(tgt_s, auth, SK_S, usage=U_TGS_AUTH)
    F.udp(tgs_req([pa_tgs_req(apreq), pa_pac_options(flagbits(3))], body), C1, sp + 2, KDC, 88)
    SK_C = skey('cifs', 23, 153)
    infos = [(1, pac_logon_buffer()), (10, pac_client_info('bob')), (11, pac_s4u_buffer()),
             (14, pac_device_buffer()), (15, claims_metadata_blob(0, 3, True))]
    svc2, _ = pac_ticket(CIFS, KRBTGT, SK_C, BOB, infos, srv_et=23, kdc_et=23,
                         extra_ad=sample_ads(), caddr=ADDRS_OK)
    plain = enc_kdc_rep_part(26, SK_C, 8003, flags, sname2)
    F.udp(kdc_rep(13, None, REALM, BOB.der(), svc2, encrypt_der(23, SK_S[1], plain, U_TGSREP, 1)),
          KDC, 88, C1, sp + 2)

# ------------------------------------------------------------------ GSS-API CFX over DCE/RPC
OID_SPNEGO = _ber(0x06, bytes.fromhex('2b0601050502'))
OID_KRB5 = _ber(0x06, bytes.fromhex('2a864886f712010202'))
OID_MSKRB5 = _ber(0x06, bytes.fromhex('2a864882f712010202'))
UUID_OTHER = '12345678-1234-1234-1234-123456789abc'


def gss_token(token_id, inner):
    """RFC 2743 InitialContextToken for the Kerberos mechanism."""
    return _app(0, OID_KRB5 + struct.pack('>H', token_id) + inner)


def spnego_init(token):
    return _app(0, OID_SPNEGO + _ctx(0, _seq(_ctx(0, _seqof([OID_MSKRB5, OID_KRB5])),
                                            _ctx(2, _octet(token)))))


def spnego_resp(token=None, mic=None, state=0):
    return _ctx(1, _seq(_ctx(0, _ber(0x0a, bytes([state]))), _ctx(1, OID_KRB5),
                        _field(2, None if token is None else _octet(token)),
                        _field(3, None if mic is None else _octet(mic))))


def cfx_header(flags, ec, rrc, seq, kind=0x0504):
    return struct.pack('>HBBHHQ', kind, flags, 0xff, ec, rrc, seq)


def cfx_mic(flags, seq, key, usage):
    """A CFX GetMIC token: the 16 octet header with the checksum of the
    data (here no data) behind it."""
    hdr = struct.pack('>HBB4xQ', 0x0404, flags, 0xff, seq)
    hdr = hdr[:4] + b'\xff' * 4 + hdr[8:]
    ck = krb5_checksum(CKSUM_FOR[key[0]], key[0], key[1], b'mic data', usage)
    return hdr + ck


def cfx_dce_seal(key, flags, ec, seq, stub, rpc_hdr, sec_trailer, usage):
    """The checksum part of a DCE-style CFX wrap token, and the sealed
    stub. libkrb5 does the sealing with krb5_c_encrypt_iov; the pieces
    come back in the order the dissector expects them: [encrypted filler
    and header copy][trailer][header]."""
    hdr_copy = cfx_header(flags, ec, 0, seq)
    parts = [(IOV_HEADER, b''),
             (IOV_SIGN_ONLY, rpc_hdr) if rpc_hdr is not None else (IOV_EMPTY, b''),
             (IOV_DATA, stub),
             (IOV_SIGN_ONLY, sec_trailer) if sec_trailer is not None else (IOV_EMPTY, b''),
             (IOV_DATA, b'\0' * ec + hdr_copy),
             (IOV_TRAILER, b'')]
    out = krb5_encrypt_iov(key[0], key[1], usage, parts)
    conf, _, sealed, _, enc_tail, trailer = out
    rrc = len(enc_tail) + len(trailer)
    token = cfx_header(flags, ec, rrc, seq) + enc_tail + trailer + conf
    return token, sealed


def dce_pdu(ptype, pfc, call_id, body, trailer=b'', auth=b''):
    hdr = struct.pack('<BBBB4sHHI', 5, 0, ptype, pfc, bytes([0x10, 0, 0, 0]),
                      16 + len(body) + len(trailer) + len(auth), len(auth), call_id)
    return hdr + body + trailer + auth


def sec_trailer(level, pad, ctx_id=1, atype=9):
    return struct.pack('<BBBBI', atype, level, pad, 0, ctx_id)


def dce_bind_body(uuid=UUID_OTHER):
    h = uuid.replace('-', '')
    abstract = struct.pack('<IHH', int(h[0:8], 16), int(h[8:12], 16), int(h[12:16], 16)) + bytes.fromhex(h[16:])
    ndr = struct.pack('<IHH', 0x8a885d04, 0x1ceb, 0x11c9) + bytes.fromhex('9fe808002b104860')
    return (struct.pack('<HHI', 4280, 4280, 0) + struct.pack('<B3x', 1) + struct.pack('<HBx', 0, 1) +
            abstract + struct.pack('<I', 1) + ndr + struct.pack('<I', 2))


def dce_ack_body():
    sec = b'49664\0'
    body = struct.pack('<HHI', 4280, 4280, 0x4321) + struct.pack('<H', len(sec)) + sec
    body += b'\0' * ((-(16 + len(body))) % 4)
    ndr = struct.pack('<IHH', 0x8a885d04, 0x1ceb, 0x11c9) + bytes.fromhex('9fe808002b104860')
    return body + struct.pack('<B3x', 1) + struct.pack('<HH', 0, 0) + ndr + struct.pack('<I', 2)


def dce_auth_session(F, cport, cip, sip, key_sub, hdr_sign, ec, svc_tkt_sk, svc_ticket, calls, level=6):
    """One DCE/RPC connection with SPNEGO/Kerberos at the given level.
    calls is a list of plaintext stubs for request/response pairs."""
    t = F.tcp(cport, cip, sip, sport=49664)
    pfc = 0x03 | (0x04 if hdr_sign else 0)
    cks = gss_cksum(GSS_MUTUAL | GSS_SEQ | GSS_CONF | GSS_INTEG | GSS_DCE)
    auth = authenticator(ALICE.der(), subkey=skey('dce-init-%d' % cport, 18), seq=0x100, cks=cks)
    apreq = ap_req(svc_ticket, auth, svc_tkt_sk, AP_MUTUAL)
    init = spnego_init(gss_token(0x0100, apreq))
    body = dce_bind_body()
    body += b'\0' * ((-(16 + len(body))) % 4)
    tr = sec_trailer(level, (-(16 + len(dce_bind_body()))) % 4)
    t.send(True, dce_pdu(11, pfc, 1, body[:len(dce_bind_body())] + b'\0' * (-(16 + len(dce_bind_body())) % 4), tr, init))
    rep = ap_rep(enc_ap_rep_part(subkey=key_sub, seq=0x200), svc_tkt_sk)
    resp = spnego_resp(gss_token(0x0200, rep))
    ack = dce_ack_body()
    t.send(False, dce_pdu(12, pfc, 1, ack, sec_trailer(level, 0), resp))
    t.send(True, dce_pdu(16, 0x03, 1, struct.pack('<I', 0), sec_trailer(level, 0),
                         spnego_resp(None, cfx_mic(0, 0, key_sub, 25), 0)))
    seq_c, seq_s = 0x1000, 0x2000
    for call_id, stub in enumerate(calls, 2):
        for direction in (0, 1):
            ptype = 0 if direction == 0 else 2
            # the sealed stub is padded to 16 octets
            pad = (-len(stub)) % 16
            plain = stub + b'\xbd' * pad
            flags = 0x02 | 0x04 | direction
            usage = U_ACCEPTOR_SEAL if direction else U_INITIATOR_SEAL
            seq = seq_s if direction else seq_c
            if direction:
                seq_s += 1
            else:
                seq_c += 1
            rh = struct.pack('<IHH', len(plain), 0, 7) if ptype == 0 else struct.pack('<IHBB', len(plain), 0, 0, 0)
            trailer = sec_trailer(level, pad)
            hdr = struct.pack('<BBBB4sHHI', 5, 0, ptype, 3, bytes([0x10, 0, 0, 0]),
                              24 + len(plain) + 8 + (60 + ec), 60 + ec, call_id)
            token, sealed = cfx_dce_seal(key_sub, flags, ec, seq, plain, (hdr + rh) if hdr_sign else None,
                                         trailer if hdr_sign else None, usage)
            assert len(token) == 60 + ec
            t.send(direction == 0, hdr + rh + sealed + trailer + token)
    t.fin()


def scenario_dce(F):
    """DCE/RPC with SPNEGO (Kerberos) at packet privacy: DCE-style CFX
    wrap tokens, with and without header signing, sealed by libkrb5."""
    SK_D = skey('dcep', 18, 160)
    tkt, _ = pac_ticket(DCEP, KRBTGT, SK_D, ALICE, light_infos())
    dce_auth_session(F, 50060, C1, DC_IP, skey('dce-acc-a', 18), True, 16, SK_D, tkt,
                     [b'sealed call one', b'second call with a longer stub ' * 3])
    SK_D2 = skey('dcep2', 18, 161)
    tkt2, _ = pac_ticket(DCEP, KRBTGT, SK_D2, ALICE, light_infos())
    dce_auth_session(F, 50061, C1, DC_IP, skey('dce-acc-b', 18), False, 24, SK_D2, tkt2,
                     [b'no header signing here'])

# ------------------------------------------------------------------ keytab
def keytab_bytes(princs, kvno=2):
    """A version 2 MIT keytab (a file format, no cryptography)."""
    out = b'\x05\x02'
    for p in princs:
        for et, key in p.keys.items():
            comps = p.parts
            e = struct.pack('>H', len(comps)) + struct.pack('>H', len(REALM)) + REALM.encode()
            for c in comps:
                e += struct.pack('>H', len(c)) + c.encode()
            e += struct.pack('>IIBHH', p.nt, 1700000000, kvno, et, len(key)) + key
            e += struct.pack('>I', kvno)
            out += struct.pack('>i', len(e)) + e
    return out


def write_cfg(out):
    d = os.path.join(out, 'cfg')
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'kerberos.keytab'), 'wb') as f:
        f.write(keytab_bytes([ALICE, KRBTGT, FILES, CIFS, WS01, LDAPS, DCEP, MACH]))


# ------------------------------------------------------------------ AP exchanges, enctypes, delegation
def iakerb_finished():
    return _seq(_ctx(1, cksum(16, bytes(12))))


def scenario_ap(F):
    """AP-REQ/AP-REP with GSS-API checksums: delegation with a KRB-CRED,
    channel bindings and the RFC 6542 extensions; then service tickets of
    every other enctype the capture has keys for."""
    sp = 50020
    SK_A = skey('ap2', 18, 170)
    tkt, _ = pac_ticket(CIFS, KRBTGT, SK_A, ALICE, light_infos(), srv_et=18)
    flags = flagbits(1, 5, 8, 9, 10, 13)
    # delegation: the checksum carries a KRB-CRED holding a forwarded TGT
    fwd, _ = pac_ticket(KRBTGT, KRBTGT, SK_TGT, ALICE, [(10, pac_client_info())])
    cred_sk = skey('cred-key', 18, 171)
    infos = [krb_cred_info(cred_sk, pname=ALICE.der(), flags=flags, sname=KRBTGT.der(), caddr=ADDRS_OK)]
    cred = krb_cred([fwd], enc_krb_cred_part(infos, saddr=host_addr(2, bytes([192, 0, 2, 10])),
                                             raddr=host_addr(2, bytes([192, 0, 2, 20]))), key=SK_A)
    ck = gss_cksum(GSS_DELEG | GSS_MUTUAL | GSS_SEQ | GSS_CONF | GSS_INTEG, deleg=cred,
                   ext=[(0, bytes(range(16))), (2, iakerb_finished()), (1, iakerb_finished()), (77, b'xyz')])
    auth = authenticator(ALICE.der(), cks=ck, subkey=skey('ap2-sub', 18, 172), seq=5)
    F.udp(ap_req(tkt, auth, SK_A, AP_MUTUAL | AP_USE_SESSION_KEY), C1, sp, DC_IP, 88)
    # an unencrypted KRB-CRED (etype 0) inside the checksum, as CredSSP and
    # Windows credential delegation carry it
    cred0 = krb_cred([fwd], enc_krb_cred_part(infos), key=None)
    ck = gss_cksum(GSS_DELEG | GSS_MUTUAL, deleg=cred0, bnd=bytes(16))
    auth = authenticator(ALICE.der(), cks=ck, seq=6)
    F.udp(ap_req(tkt, auth, SK_A), C1, sp + 1, DC_IP, 88)
    ck = gss_cksum(GSS_DCE | GSS_MUTUAL | GSS_REPLAY | GSS_SEQ | GSS_CONF | GSS_INTEG, bnd=b'', ext=[(0, b'')])
    auth = authenticator(ALICE.der(), cks=ck, seq=7)
    F.udp(ap_req(tkt, auth, SK_A), C1, sp + 2, DC_IP, 88)
    # service tickets of other enctypes
    for n, et in enumerate((17, 19, 20, 25, 26)):
        sk = skey('ap-et-%d' % et, et, 180 + et)
        tkt, _ = pac_ticket(FILES, KRBTGT, sk, ALICE, light_infos(), srv_et=et, kdc_et=et)
        ck = gss_cksum(GSS_MUTUAL | GSS_CONF | GSS_INTEG)
        sub = skey('ap-et-sub-%d' % et, et, 200 + et)
        auth = authenticator(ALICE.der(), cks=ck, subkey=sub, seq=10 + n)
        F.udp(ap_req(tkt, auth, sk, AP_MUTUAL), C1, sp + 10 + n, FILES_IP, 88)
        F.udp(ap_rep(enc_ap_rep_part(subkey=skey('ap-et-acc-%d' % et, et, 220 + et), seq=n), sk),
              FILES_IP, 88, C1, sp + 10 + n)
    # KRB-PRIV and KRB-SAFE under a subkey, with addresses
    SK_P = SK_A
    F.udp(krb_priv(enc_krb_priv_part(b'priv', raddr=host_addr(24, bytes(15) + b'\x14'),
                                     saddr=host_addr(2, bytes([192, 0, 2, 10]))), SK_P),
          C1, sp + 30, FILES_IP, 88)
    F.udp(krb_safe(b'safe', SK_P, saddr=host_addr(2, bytes([192, 0, 2, 10])),
                   raddr=host_addr(20, b'FILES' + b' ' * 10 + b'\x20')), C1, sp + 30, FILES_IP, 88)


# ------------------------------------------------------------------ LDAP SASL and CredSSP
def ldap_msg(mid, op):
    return _seq(_ber_int(mid), op)


def ldap_bind_request(mid, token):
    return ldap_msg(mid, _app(0, _ber_int(3) + _octet(b'') +
                              _ber(0xa3, _octet(b'GSS-SPNEGO') + _octet(token))))


def ldap_bind_response(mid, token):
    return ldap_msg(mid, _app(1, _ber(0x0a, b'\0') + _octet(b'') + _octet(b'') + _ber(0x87, token)))


def ldap_search_request(mid):
    return ldap_msg(mid, _app(3, _octet(b'dc=example,dc=test') + _ber(0x0a, b'\2') + _ber(0x0a, b'\0') +
                              _ber_int(0) + _ber_int(0) + _bool(False) +
                              _ber(0x87, b'objectClass') + _seqof([_octet(b'cn')])))


def ldap_search_done(mid):
    return ldap_msg(mid, _app(5, _ber(0x0a, b'\0') + _octet(b'') + _octet(b'')))


def cfx_seal_normal(key, flags, seq, plain, usage, ec=0):
    """RFC 4121 wrap with confidentiality as GSSAPI applications send it:
    the encrypted data and header copy rotated by RRC = EC + 28."""
    hdr_copy = cfx_header(flags, ec, 0, seq)
    blob = krb5_encrypt(key[0], key[1], plain + b'\0' * ec + hdr_copy, usage)
    rrc = ec + 28
    rot = blob[-rrc:] + blob[:-rrc]
    return cfx_header(flags, ec, rrc, seq) + rot


def cfx_sign_normal(key, flags, seq, plain, usage):
    """RFC 4121 wrap without confidentiality: the data, then a checksum of
    the data and the header (EC is the checksum length, RRC is 0)."""
    n = krb5_cksum_len(CKSUM_FOR[key[0]])
    ck = krb5_checksum(CKSUM_FOR[key[0]], key[0], key[1], plain + cfx_header(flags, n, 0, seq), usage)
    return cfx_header(flags, n, 0, seq) + plain + ck


def sasl(token):
    return struct.pack('>I', len(token)) + token


def scenario_ldap(F):
    """LDAP SASL GSS-SPNEGO: Kerberos authentication, then a sealed and a
    signed search with their replies, decrypted with the AP-REP subkey."""
    SK_L = skey('ldap', 18, 240)
    SUB_L = skey('ldap-acc', 18, 241)
    tkt, _ = pac_ticket(LDAPS, KRBTGT, SK_L, ALICE, light_infos())
    t = F.tcp(50070, C1, DC_IP, sport=389)
    cks = gss_cksum(GSS_MUTUAL | GSS_SEQ | GSS_CONF | GSS_INTEG)
    auth = authenticator(ALICE.der(), subkey=skey('ldap-init', 18, 242), seq=0x300, cks=cks)
    t.send(True, ldap_bind_request(1, spnego_init(gss_token(0x0100, ap_req(tkt, auth, SK_L, AP_MUTUAL)))))
    rep = ap_rep(enc_ap_rep_part(subkey=SUB_L, seq=0x400), SK_L)
    t.send(False, ldap_bind_response(1, spnego_resp(gss_token(0x0200, rep))))
    seal = 0x02 | 0x04
    t.send(True, sasl(cfx_seal_normal(SUB_L, seal, 0x10, ldap_search_request(2), U_INITIATOR_SEAL)))
    t.send(False, sasl(cfx_seal_normal(SUB_L, seal | 1, 0x20, ldap_search_done(2), U_ACCEPTOR_SEAL)))
    t.send(True, sasl(cfx_sign_normal(SUB_L, 0x04, 0x11, ldap_search_request(3), 25)))
    t.send(False, sasl(cfx_sign_normal(SUB_L, 0x05, 0x21, ldap_search_done(3), 23)))
    t.fin()


def tsrequest(version=6, nego=None, auth_info=None, pubkey=None, nonce=None):
    return _seq(_ctx(0, _ber_int(version)),
                _field(1, None if nego is None else _seqof([_seq(_ctx(0, _octet(n))) for n in nego])),
                _field(2, None if auth_info is None else _octet(auth_info)),
                _field(3, None if pubkey is None else _octet(pubkey)),
                _field(5, None if nonce is None else _octet(nonce)))


def kerb_ticket_logon(ticket, cred):
    """KERB_TICKET_LOGON: type, flags, the two lengths, two pointers (not
    used), then the ticket and the KRB-CRED."""
    return (struct.pack('<IIIIQQ', 10, 3, len(ticket), len(cred), 0, 0) + ticket + cred)


def scenario_credssp(F):
    """CredSSP (decoded with Decode As, as it is carried inside TLS):
    Kerberos, a sealed public key and sealed TSCredentials of the remote
    guard kind, which hold a KERB_TICKET_LOGON."""
    SK_R = skey('rdp', 18, 250)
    SUB_R = skey('rdp-acc', 18, 251)
    tkt, _ = pac_ticket(WS01, KRBTGT, SK_R, ALICE, light_infos())
    cli = lambda pl: F.frames.append(exp_pdu(pl, 'credssp', C1, FILES_IP, 50071, 3389))
    srv = lambda pl: F.frames.append(exp_pdu(pl, 'credssp', FILES_IP, C1, 3389, 50071))
    cks = gss_cksum(GSS_MUTUAL | GSS_SEQ | GSS_CONF | GSS_INTEG)
    auth = authenticator(ALICE.der(), subkey=skey('rdp-init', 18, 252), seq=0x500, cks=cks)
    cli(tsrequest(nego=[spnego_init(gss_token(0x0100, ap_req(tkt, auth, SK_R, AP_MUTUAL)))]))
    rep = ap_rep(enc_ap_rep_part(subkey=SUB_R, seq=0x600), SK_R)
    srv(tsrequest(nego=[spnego_resp(gss_token(0x0200, rep))]))
    seal = 0x02 | 0x04
    cli(tsrequest(pubkey=cfx_seal_normal(SUB_R, seal, 0x30, b'SubjectPublicKey' * 4, U_INITIATOR_SEAL),
                           nonce=bytes(range(32))))
    srv(tsrequest(pubkey=cfx_seal_normal(SUB_R, seal | 1, 0x40, b'ServerPublicKey' * 4, U_ACCEPTOR_SEAL)))
    svc, _ = pac_ticket(FILES, KRBTGT, SK_FILES, ALICE, [(10, pac_client_info())])
    tgt_cred = krb_cred([svc], enc_krb_cred_part([krb_cred_info(SK_FILES)]), key=None)
    pkg = _seq(_ctx(0, _octet('Kerberos'.encode('utf-16-le'))),
               _ctx(1, _octet(kerb_ticket_logon(svc, tgt_cred))))
    pkg2 = _seq(_ctx(0, _octet('NTLM'.encode('utf-16-le'))), _ctx(1, _octet(b'\0' * 8)))
    creds = _seq(_ctx(0, pkg), _ctx(1, _seqof([pkg2])))
    tscred = _seq(_ctx(0, _ber_int(6)), _ctx(1, _octet(creds)))
    cli(tsrequest(auth_info=cfx_seal_normal(SUB_R, seal, 0x31, tscred, U_INITIATOR_SEAL)))


def scenario_dce16(F):
    """DCE/RPC authentication type 16 (GSS Kerberos): the AP-REQ and AP-REP
    are bare Kerberos messages in the bind and bind_ack."""
    SK_D = skey('dce16', 18, 260)
    tkt, _ = pac_ticket(DCEP, KRBTGT, SK_D, ALICE, [(10, pac_client_info())])
    t = F.tcp(50062, C1, DC_IP, sport=49664)
    auth = authenticator(ALICE.der(), subkey=skey('dce16-init', 18, 261), seq=1,
                         cks=gss_cksum(GSS_MUTUAL | GSS_SEQ | GSS_CONF | GSS_INTEG | GSS_DCE))
    body = dce_bind_body()
    pad = (-(16 + len(body))) % 4
    t.send(True, dce_pdu(11, 3, 1, body + b'\0' * pad, sec_trailer(2, pad, atype=16), ap_req(tkt, auth, SK_D, AP_MUTUAL)))
    rep = ap_rep(enc_ap_rep_part(subkey=skey('dce16-acc', 18, 262), seq=2), SK_D)
    t.send(False, dce_pdu(12, 3, 1, dce_ack_body(), sec_trailer(2, 0, atype=16), rep))
    t.send(True, dce_pdu(16, 3, 1, struct.pack('<I', 0), sec_trailer(2, 0, atype=16), ap_rep(enc_ap_rep_part(seq=3), SK_D)))
    t.fin()

# ------------------------------------------------------------------ wrong checksums
def scenario_wrongsum(F):
    """AP-REQs whose ticket PAC carries a wrong ticket checksum, and a wrong
    full PAC checksum. Both verify as 'Invalid' and warn; everything else
    in the capture verifies."""
    for n, which in enumerate(('ticket', 'full')):
        sk = skey('wrong-%s' % which, 18, 270 + n)
        tkt, _ = pac_ticket(FILES, KRBTGT, sk, ALICE, [(10, pac_client_info())], tamper=which)
        auth = authenticator(ALICE.der(), seq=30 + n)
        F.udp(ap_req(tkt, auth, sk), C1, 50080 + n, FILES_IP, 88)


def scenario_upn(F):
    """A PAC whose UPN_DNS_INFO has no SAM name and SID extension."""
    sk = skey('upn-only', 18, 271)
    infos = [(10, pac_client_info()), (12, pac_upn_dns('alice@example.test', 'EXAMPLE.TEST', flags=1))]
    tkt, _ = pac_ticket(FILES, KRBTGT, sk, ALICE, infos)
    F.udp(ap_req(tkt, authenticator(ALICE.der(), seq=33), sk), C1, 50082, FILES_IP, 88)


# ------------------------------------------------------------------ the negative capture
UNK = (18, fixed_key(18, 99))      # a key nobody has
UNK17 = (17, fixed_key(17, 99))
UNK23 = (23, fixed_key(23, 99))


def unk_ticket(sname=None, srv_key=UNK, with_pac=None):
    sk = skey('unk-ticket', 18, 275)
    az = pac_authz(with_pac) if with_pac else None
    return make_ticket(REALM, sname or KRBTGT.der(), srv_key[0], srv_key[1],
                       enc_ticket_part(sk, REALM, ALICE.der(), az)), sk


def trunc(b, n):
    return b[:max(1, len(b) * n // 100)]


def scenario_negative(F):
    """Everything that only malformed or undecryptable input reaches. Not
    for the test tree; it is used for the coverage number."""
    sp = 50100
    flags = flagbits(1, 5, 8, 9, 10, 13)
    # BUG: a bare EncASRepPart or EncTGSRepPart (the whitelist of
    # dissect_kerberos_common lets them in) reaches save_encryption_key()
    # with parent_hf_index -1 and fails an assertion in proto_registrar_get_name()
    skb = skey('neg-bare', 18, 274)
    F.udp(enc_kdc_rep_part(25, skb, 9303, flags, KRBTGT.der()), C1, sp + 90, KDC, 88)
    F.udp(enc_kdc_rep_part(26, skb, 9304, flags, KRBTGT.der()), C1, sp + 91, KDC, 88)
    # unknown address types
    body = kdc_req_body(ALICE.der(), KRBTGT.der(), 9001, [18], addrs=ADDRS_BAD)
    F.udp(as_req([pa_enc_ts(UNK)], body), C1, sp, KDC, 88)
    # AS-REP, TGS-REP, AP-REQ, AP-REP, KRB-PRIV, KRB-CRED the keys do not open
    tkt, sk = unk_ticket()
    F.udp(kdc_rep(11, None, REALM, ALICE.der(), tkt,
                  encrypt_der(18, UNK[1], enc_kdc_rep_part(25, sk, 9001, flags, KRBTGT.der()), U_ASREP)),
          KDC, 88, C1, sp)
    F.udp(kdc_rep(13, None, REALM, ALICE.der(), tkt,
                  encrypt_der(18, UNK[1], enc_kdc_rep_part(26, sk, 9001, flags, KRBTGT.der()), U_TGSREP)),
          KDC, 88, C1, sp + 1)
    auth = authenticator(ALICE.der(), seq=1, ad=authz((1, authz((143, b'\1\0\0\0')))))
    apreq = ap_req(tkt, auth, UNK)
    F.udp(apreq, C1, sp + 2, FILES_IP, 88)
    F.udp(ap_rep(enc_ap_rep_part(seq=1), UNK), FILES_IP, 88, C1, sp + 2)
    F.udp(krb_priv(enc_krb_priv_part(b'x'), UNK), C1, sp + 3, FILES_IP, 88)
    # TGS-REQ: the ticket opens nothing, so neither does the authenticator
    # or the encrypted authorization data
    body = kdc_req_body(None, FILES.der(), 9002, [18],
                        enc_authz=encrypt_der(18, UNK[1], authz((1, authz((143, b'\1\0\0\0')))), U_TGS_AD))
    ck = krb5_checksum(16, 18, UNK[1], body, U_TGS_CKSUM)
    auth = authenticator(ALICE.der(), cks=cksum(16, ck), subkey=skey('neg-sub', 18, 276))
    F.udp(tgs_req([pa_tgs_req(ap_req(tkt, auth, UNK, usage=U_TGS_AUTH))], body), C1, sp + 4, KDC, 88)
    # the same with a subkey the capture does know: authorization data usage 5 fails
    # (the ticket is known, the subkey is made up)
    skk = skey('neg-tgt', 18, 277)
    tkt_k, _ = pac_ticket(KRBTGT, KRBTGT, skk, ALICE, [(10, pac_client_info())])
    body = kdc_req_body(None, FILES.der(), 9003, [18],
                        enc_authz=encrypt_der(18, UNK[1], authz((1, authz((143, b'\1\0\0\0')))), U_TGS_AD_SUB))
    ck = krb5_checksum(16, 18, skk[1], body, U_TGS_CKSUM)
    auth = authenticator(ALICE.der(), cks=cksum(16, ck), subkey=skey('neg-sub2', 18, 278))
    F.udp(tgs_req([pa_tgs_req(ap_req(tkt_k, auth, skk, usage=U_TGS_AUTH))], body), C1, sp + 5, KDC, 88)
    # encrypted credentials in a PAC: the key is not known
    infos = [(1, pac_logon_buffer()), (2, pac_credential_info(18, UNK[1])), (10, pac_client_info())]
    sk2 = skey('neg-cred', 18, 279)
    t2, _ = pac_ticket(FILES, KRBTGT, sk2, ALICE, infos)
    F.udp(ap_req(t2, authenticator(ALICE.der(), seq=2), sk2), C1, sp + 6, FILES_IP, 88)
    # KRB-CRED with a key nobody has
    cred = krb_cred([tkt_k], enc_krb_cred_part([krb_cred_info(sk2)]), key=UNK)
    t7, _ = pac_ticket(FILES, KRBTGT, skey('neg-cred-ap', 18, 278), ALICE, [(10, pac_client_info())])
    auth = authenticator(ALICE.der(), seq=7, cks=gss_cksum(GSS_DELEG | GSS_MUTUAL, deleg=cred))
    F.udp(ap_req(t7, auth, skey('neg-cred-ap', 18, 278)), C1, sp + 7, FILES_IP, 88)
    # PAC signatures that do not verify and cannot be checked
    n = 0

    def pac_case(**kw):
        nonlocal n
        n += 1
        skn = skey('neg-pac-%d' % n, 18, 280 + n)
        infos = kw.pop('infos', [(10, pac_client_info())])
        t, _ = pac_ticket(FILES, KRBTGT, skn, ALICE, infos, **kw)
        F.udp(ap_req(t, authenticator(ALICE.der(), seq=40 + n), skn), C1, sp + 10 + n, FILES_IP, 88)
    pac_case(srv_key=UNK, verify=False)                            # Missing Server
    pac_case(kdc_key=UNK, verify=False)                            # Missing KDC, for ticket, for full
    pac_case(kdc_key=UNK, verify=False, full=False)                # Missing KDC (for ticket)
    pac_case(ticket_cktype=0x6666)                                 # checksum length fails
    pac_case(full='short')                                         # full signature too short
    pac_case(authtime='20261118120000.5Z')                         # MIT cannot decode the ticket part
    pac_case(top_level_pac=True)                                   # no PAC in an IF-RELEVANT
    pac_case(misalign=True, verify=False)                          # krb5_pac_parse fails
    pac_case(ticket_ck=False)                                      # no ticket checksum at all
    # PAC in an authenticator: there is no ticket part to check it against
    pk = [(10, pac_client_info())]
    pk6, _ = pac_ticket(FILES, KRBTGT, skey('neg-auth-pac', 18, 299), ALICE, pk)
    sk = skey('neg-ap-pac', 18, 300)
    tkt, _ = pac_ticket(FILES, KRBTGT, sk, ALICE, pk)
    pac_bytes = signed_pac(pk, (18, FILES.key(18)), (18, KRBTGT.key(18)), bytes(12), True)
    auth = authenticator(ALICE.der(), seq=3, ad=pac_authz(pac_bytes))
    F.udp(ap_req(tkt, auth, sk), C1, sp + 40, FILES_IP, 88)
    # GSS-API checksum errors: the delegation length, the extension header
    # and the extension length
    sk = skey('neg-gss', 18, 301)
    tkt, _ = pac_ticket(FILES, KRBTGT, sk, ALICE, pk)
    ok = struct.pack('<I', 16) + bytes(16)
    for n, raw in enumerate((
            ok + struct.pack('<I', GSS_DELEG) + struct.pack('<H', 1),           # < 4 bytes after flags
            ok + struct.pack('<I', GSS_DELEG) + struct.pack('<HH', 1, 900) + b'short',   # DlgLen too long
            ok + struct.pack('<I', 0) + b'\0\0\0\1\0\0',                          # incomplete extension header
            ok + struct.pack('<I', 0) + struct.pack('>II', 1, 999) + b'x')):      # extension length too long
        auth = authenticator(ALICE.der(), seq=50 + n, cks=cksum(0x8003, raw))
        F.udp(ap_req(tkt, auth, sk), C1, sp + 50 + n, FILES_IP, 88)
    # FAST that cannot be opened: the armor ticket is not known
    outer = kdc_req_body(None, KRBTGT.der(), 9100, [18], till=None)
    inner = kdc_req_body(ALICE.der(), KRBTGT.der(), 9100, [18])
    ek = challenge(UNK, UNK, b'clientchallengearmor', U_CHALLENGE_CLIENT)
    fa = fast_req(UNK, outer, [padata(PA_ENCRYPTED_CHALLENGE, ek)], inner,
                  armor_ap(tkt_k, skk, skey('neg-armor', 18, 302), MACH.der()))
    F.udp(as_req([padata(PA_FX_FAST, fa)], outer), C1, sp + 60, KDC, 88)
    fr = fast_rep(UNK, [padata(PA_ENCRYPTED_CHALLENGE, ek)], 9100, skey('neg-str', 18, 303))
    F.udp(kdc_rep(11, [padata(PA_FX_FAST, fr), padata(PA_ENCRYPTED_CHALLENGE, ek)], REALM, ALICE.der(), tkt_k,
                  encrypt_der(18, UNK[1], b'x', U_ASREP)), KDC, 88, C1, sp + 60)
    # a TGS-REQ in FAST with no armor and no TGS-REQ: nothing to derive a key from
    fa = fast_req(UNK, outer, [pa_pac_options()], inner)
    F.udp(tgs_req([padata(PA_FX_FAST, fa)], outer), C1, sp + 61, KDC, 88)
    # PA-FX-FAST that is not an armored request
    F.udp(as_req([padata(PA_FX_FAST, b'\xa1\x00')], outer), C1, sp + 62, KDC, 88)
    # sealed DCE/RPC stubs with a key the capture lacks, and with a key
    # of another enctype
    dce_neg(F)
    # not Kerberos on port 88; Kerberos version 4 on port 88; unknown
    # application tag; truncated messages
    F.udp(b'\x30\x03\x02\x01\x05', C1, sp + 70, KDC, 88)
    F.udp(b'\x04\x02' + b'alice\0' + b'\0' * 20, C1, sp + 71, KDC, 88)
    F.udp(_app(31, _seq(_ctx(0, _ber_int(5)))), C1, sp + 72, KDC, 88)
    body = kdc_req_body(ALICE.der(), KRBTGT.der(), 9200, [18], addrs=ADDRS_OK)
    msg = as_req([pa_enc_ts((18, ALICE.key(18))), pa_pac_request(True)], body)
    for k, pct in enumerate((15, 45, 80)):
        F.udp(trunc(msg, pct), C1, sp + 73 + k, KDC, 88)
    tkt, sk = unk_ticket()
    ap = ap_req(tkt, authenticator(ALICE.der(), seq=4), UNK)
    F.udp(trunc(ap, 70), C1, sp + 80, FILES_IP, 88)
    # PA-DATA that does not match its type
    F.udp(as_req([padata(PA_ETYPE_INFO2, b'\x30\x03\x02\x01\x01'), padata(PA_PAC_REQUEST, b'\x02\x01\x01'),
                  padata(PA_PW_SALT, b''), padata(250, b'\x04\x00')], body), C1, sp + 81, KDC, 88)
    # an AD-TOKEN-RESTRICTIONS in the form [MS-KILE] shows (one SEQUENCE)
    sk = skey('neg-restr', 18, 304)
    t3, _ = pac_ticket(FILES, KRBTGT, sk, ALICE, pk, extra_ad=[
        (141, _seq(_ctx(0, _ber_int(0)), _ctx(1, _octet(bytes(16)))))])
    F.udp(ap_req(t3, authenticator(ALICE.der(), seq=5), sk), C1, sp + 82, FILES_IP, 88)
    # TCP: reserved bit of the record mark, a record too large for the dissector,
    # a record of garbage
    t = F.tcp(50101, C1, KDC)
    t.send(True, rm(msg, 0x80000000))
    t.send(False, rm(b'\x6e\x03\x30\x01\x00'))
    t.send(True, struct.pack('>I', 0x00b00000) + b'\x6a\x10')
    t.send(True, struct.pack('>I', 6) + b'\xff\x00\x00\x00\x00\x00')
    t.fin()


def dce_neg(F):
    """DCE/RPC with Kerberos where the sealed stubs cannot be opened."""
    SK_D = skey('dceneg', 18, 310)
    tkt, _ = pac_ticket(DCEP, KRBTGT, SK_D, ALICE, [(10, pac_client_info())])
    t = F.tcp(50063, C1, DC_IP, sport=49664)
    cks = gss_cksum(GSS_MUTUAL | GSS_SEQ | GSS_CONF | GSS_INTEG | GSS_DCE)
    auth = authenticator(ALICE.der(), subkey=skey('dce-neg-init', 18, 311), seq=0x100, cks=cks)
    init = spnego_init(gss_token(0x0100, ap_req(tkt, auth, SK_D, AP_MUTUAL)))
    body = dce_bind_body()
    pad = (-(16 + len(body))) % 4
    t.send(True, dce_pdu(11, 7, 1, body + b'\0' * pad, sec_trailer(6, pad), init))
    sub = skey('dce-neg-acc', 18, 312)
    rep = ap_rep(enc_ap_rep_part(subkey=sub, seq=0x200), SK_D)
    t.send(False, dce_pdu(12, 7, 1, dce_ack_body(), sec_trailer(6, 0), spnego_resp(gss_token(0x0200, rep))))
    for call_id, (key, ec, hs) in enumerate(((UNK, 16, True), (sub, 0, True), (sub, 16, False),
                                              ((17, fixed_key(17, 5)), 16, True)), 2):
        plain = b'sealed stub that cannot be opened.....'[:32]
        flags = 0x06
        rh = struct.pack('<IHH', len(plain), 0, 7)
        trailer = sec_trailer(6, 0)
        total = 24 + len(plain) + 8 + 60 + ec
        hdr = struct.pack('<BBBB4sHHI', 5, 0, 0, 3, bytes([0x10, 0, 0, 0]), total, 60 + ec, call_id)
        token, sealed = cfx_dce_seal(key, flags, ec, 0x1000 + call_id, plain, (hdr + rh) if hs else None,
                                     trailer if hs else None, U_INITIATOR_SEAL)
        if key is sub and ec == 0:
            # a token too small to be a DCE token: the callback gives up
            token = token[:16 + 20]
            hdr = struct.pack('<BBBB4sHHI', 5, 0, 0, 3, bytes([0x10, 0, 0, 0]), 24 + len(plain) + 8 + len(token), len(token), call_id)
        t.send(True, hdr + rh + sealed + trailer + token)
    t.fin()

# ------------------------------------------------------------------ requests, replies, bare structures
def scenario_misc(F):
    """Request and reply pairing (the response time statistics), messages
    with no partner, and the bare ASN.1 structures Wireshark accepts on
    the Kerberos port."""
    sp = 50090
    C3 = (192, 0, 2, 12)
    SK = skey('misc-tgt', 18, 320)
    tgt, _ = pac_ticket(KRBTGT, KRBTGT, SK, ALICE, [(10, pac_client_info())])
    body = kdc_req_body(None, FILES.der(), 9301, [18])
    ck = krb5_checksum(16, 18, SK[1], body, U_TGS_CKSUM)
    apreq = ap_req(tgt, authenticator(ALICE.der(), cks=cksum(16, ck)), SK, usage=U_TGS_AUTH)
    F.udp(tgs_req([pa_tgs_req(apreq)], body), C3, sp, KDC, 88)
    F.udp(krb_error(7, sname=FILES.der(), crealm=REALM, cname=ALICE.der(),
                    etext='Server not found in Kerberos database'), KDC, 88, C3, sp)
    # an error that answers nothing, then two requests in a row
    F.udp(krb_error(60, etext='generic error'), KDC, 88, C3, sp + 1)
    abody = kdc_req_body(ALICE.der(), KRBTGT.der(), 9302, [18])
    F.udp(as_req([pa_pac_request(True)], abody), C3, sp + 2, KDC, 88)
    F.udp(as_req([pa_pac_request(False)], abody), C3, sp + 2, KDC, 88)
    F.udp(tgs_req([pa_tgs_req(apreq)], body), C3, sp + 2, KDC, 88)
    # bare structures
    sk = skey('misc-bare', 18, 321)
    flags = flagbits(1, 5, 8, 9, 10, 13)
    F.udp(tgt, C3, sp + 3, KDC, 88)
    F.udp(authenticator(ALICE.der(), seq=9, subkey=skey('misc-sub', 18, 322)), C3, sp + 3, KDC, 88)
    F.udp(enc_ticket_part(sk, REALM, ALICE.der(), None), C3, sp + 3, KDC, 88)
    F.udp(enc_ap_rep_part(subkey=skey('misc-sub2', 18, 323), seq=5), C3, sp + 3, KDC, 88)
    F.udp(enc_krb_priv_part(b'bare private data'), C3, sp + 3, KDC, 88)
    F.udp(enc_krb_cred_part([krb_cred_info(sk, pname=ALICE.der())]), C3, sp + 3, KDC, 88)

def credssp_neg(F):
    """KERB_TICKET_LOGON blobs of every wrong shape, in sealed TSCredentials."""
    SK_R = skey('rdp-neg', 18, 330)
    SUB_R = skey('rdp-neg-acc', 18, 331)
    tkt, _ = pac_ticket(WS01, KRBTGT, SK_R, ALICE, [(10, pac_client_info())])
    cli = lambda pl: F.frames.append(exp_pdu(pl, 'credssp', C1, FILES_IP, 50072, 3389))
    srv = lambda pl: F.frames.append(exp_pdu(pl, 'credssp', FILES_IP, C1, 3389, 50072))
    cks = gss_cksum(GSS_MUTUAL | GSS_SEQ | GSS_CONF | GSS_INTEG)
    auth = authenticator(ALICE.der(), subkey=skey('rdp-neg-init', 18, 332), seq=0x500, cks=cks)
    cli(tsrequest(nego=[spnego_init(gss_token(0x0100, ap_req(tkt, auth, SK_R, AP_MUTUAL)))]))
    rep = ap_rep(enc_ap_rep_part(subkey=SUB_R, seq=0x600), SK_R)
    srv(tsrequest(nego=[spnego_resp(gss_token(0x0200, rep))]))
    svc, _ = pac_ticket(FILES, KRBTGT, SK_FILES, ALICE, [(10, pac_client_info())])
    cred = krb_cred([svc], enc_krb_cred_part([krb_cred_info(SK_FILES)]), key=None)
    seal = 0x06
    n = 0x50
    for logon in (b'\0' * 20,                                              # shorter than 32 octets
                  struct.pack('<IIIIQQ', 10, 0, 0, 0, 0, 0),             # no service ticket
                  struct.pack('<IIIIQQ', 10, 0, len(svc) + 3, 0, 0, 0) + svc + b'\0\0\0',   # wrong ticket length
                  struct.pack('<IIIIQQ', 10, 0, len(svc), 0, 0, 0) + svc,                  # no TGT
                  struct.pack('<IIIIQQ', 10, 0, len(svc), len(cred) + 5, 0, 0) + svc + cred):    # wrong TGT length
        pkg = _seq(_ctx(0, _octet('Kerberos'.encode('utf-16-le'))), _ctx(1, _octet(logon)))
        tscred = _seq(_ctx(0, _ber_int(6)), _ctx(1, _octet(_seq(_ctx(0, pkg)))))
        n += 1
        cli(tsrequest(auth_info=cfx_seal_normal(SUB_R, seal, n, tscred, U_INITIATOR_SEAL)))


def scenario_negative2(F):
    sp = 50200
    pk = [(10, pac_client_info())]
    n = 0

    def pac_case(**kw):
        nonlocal n
        n += 1
        skn = skey('neg2-pac-%d' % n, 18, 340 + n)
        infos = kw.pop('infos', pk)
        t, _ = pac_ticket(FILES, KRBTGT, skn, ALICE, infos, **kw)
        F.udp(ap_req(t, authenticator(ALICE.der(), seq=60 + n), skn), C1, sp + n, FILES_IP, 88)
    pac_case(srv_cktype=0x6666, verify=False)                      # unknown server checksum type
    pac_case(ticket_cklen=6)                                       # krb5_c_verify_checksum fails
    pac_case(full='badtype')                                       # krb5_c_checksum_length fails (full)
    pac_case(top_level_pac=True, bad_if_relevant=True)             # undecodable IF-RELEVANT beside the PAC
    pac_case(infos=pk + [(16, b'\1\2\3'), (19, b'\1\2\3')], ticket_ck=False, full=False)  # signature too short
    # PW-SALT: empty, and twelve octets in a request
    body = kdc_req_body(ALICE.der(), KRBTGT.der(), 9400, [18])
    F.udp(as_req([padata(PA_PW_SALT, b'')], body), C1, sp + 20, KDC, 88)
    F.udp(as_req([padata(PA_PW_SALT, struct.pack('<III', 0xC000006A, 0, 1))], body), C1, sp + 21, KDC, 88)
    # FAST armor of an unknown type
    outer = kdc_req_body(None, KRBTGT.der(), 9401, [18], till=None)
    inner = kdc_req_body(ALICE.der(), KRBTGT.der(), 9401, [18])
    arm = _seq(_ctx(0, _ber_int(0)), _ctx(1, _octet(b'armor')))
    F.udp(as_req([padata(PA_FX_FAST, fast_req(UNK, outer, [], inner, arm))], outer), C1, sp + 22, KDC, 88)
    # padata types that other dissectors decode (PKINIT, S4U with a certificate)
    F.udp(as_req([padata(14, b'\x30\x00'), padata(15, b'\x30\x03\x80\x01\x00'), padata(16, b'\x30\x03\x80\x01\x00'),
                  padata(130, b'\x30\x00')],
                 body), C1, sp + 23, KDC, 88)
    F.udp(kdc_rep(11, [padata(15, b'\x30\x00'), padata(17, b'\x30\x03\x80\x01\x00')], REALM, ALICE.der(),
                  unk_ticket()[0], encrypt_der(18, UNK[1], b'x', U_ASREP)), KDC, 88, C1, sp + 24)
    # an AP-REP with subkeys of enctypes libkrb5 does not have: the key
    # search for sealed DCE/RPC data meets them
    SK_B = skey('neg2-bogus', 18, 360)
    tkt, _ = pac_ticket(FILES, KRBTGT, SK_B, ALICE, pk)
    F.udp(ap_req(tkt, authenticator(ALICE.der(), seq=1), SK_B), C1, sp + 30, FILES_IP, 88)
    for et in (1, 2, 3, 5, 7, 48):
        F.udp(ap_rep(enc_ap_rep_part(subkey=(et, bytes(range(8, 16))), seq=1), SK_B), FILES_IP, 88, C1, sp + 30)
    credssp_neg(F)
    dce_neg2(F)


def dce_neg2(F):
    """Sealed DCE/RPC data whose token is too short for the DCE style."""
    SK_D = skey('dceneg2', 18, 370)
    tkt, _ = pac_ticket(DCEP, KRBTGT, SK_D, ALICE, [(10, pac_client_info())])
    t = F.tcp(50064, C1, DC_IP, sport=49664)
    cks = gss_cksum(GSS_MUTUAL | GSS_SEQ | GSS_CONF | GSS_INTEG | GSS_DCE)
    auth = authenticator(ALICE.der(), subkey=skey('dce-neg2-init', 18, 371), seq=0x100, cks=cks)
    init = spnego_init(gss_token(0x0100, ap_req(tkt, auth, SK_D, AP_MUTUAL)))
    body = dce_bind_body()
    pad = (-(16 + len(body))) % 4
    t.send(True, dce_pdu(11, 3, 1, body + b'\0' * pad, sec_trailer(6, pad), init))
    sub = skey('dce-neg2-acc', 18, 372)
    rep = ap_rep(enc_ap_rep_part(subkey=sub, seq=0x200), SK_D)
    t.send(False, dce_pdu(12, 3, 1, dce_ack_body(), sec_trailer(6, 0), spnego_resp(gss_token(0x0200, rep))))
    for call_id, tail in enumerate((12, 36, 50), 2):
        tok = cfx_header(0x06, 0, 0, 0x500 + call_id) + bytes(range(tail))
        plain = bytes(32)
        rh = struct.pack('<IHH', len(plain), 0, 7)
        hdr = struct.pack('<BBBB4sHHI', 5, 0, 0, 3, bytes([0x10, 0, 0, 0]),
                          24 + len(plain) + 8 + len(tok), len(tok), call_id)
        t.send(True, hdr + rh + plain + sec_trailer(6, 0) + tok)
    t.fin()

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_cfg(out)
    F = Cap()
    marks = []
    for fn in (scenario_basic, scenario_fast, scenario_tcp, scenario_padata, scenario_dce, scenario_dce16,
               scenario_ap, scenario_ldap, scenario_credssp, scenario_misc, scenario_wrongsum, scenario_upn):
        start = len(F.frames)
        fn(F)
        marks.append((fn.__name__[9:], start + 1, len(F.frames)))
    write_pcapng(os.path.join(out, 'kerberos_coverage.pcapng'), F.frames, kerberos_keylog())
    write_pcapng(os.path.join(out, 'kerberos-coverage-nokeys.pcapng'), F.frames)
    N = Cap()
    scenario_negative(N)
    scenario_negative2(N)
    write_pcapng(os.path.join(out, 'kerberos-coverage-malformed.pcapng'), N.frames,
                 [kerberos_keylog(), b'', b'   \n# only a comment\n',
                  b'18 ' + ALICE.key(18).hex().encode() + b'  \n17  ' + ALICE.key(17).hex().encode()])
    for name, a, b in marks:
        print('%-10s frames %d-%d' % (name, a, b))
    print('main %d frames, malformed %d frames' % (len(F.frames), len(N.frames)))


if __name__ == '__main__':
    main()
