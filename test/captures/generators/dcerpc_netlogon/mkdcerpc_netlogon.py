#!/usr/bin/env python3
# Generates test/captures/dcerpc_netlogon_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""mkdcerpc_netlogon.py <outdir>: synthetic captures for the NETLOGON
DCE/RPC dissector (epan/dissectors/packet-dcerpc-netlogon.c).

Every packet is built with struct. The NDR stubs are written by a small
encoder (class W) that mirrors the order in which the hand-written
dissector reads them: a pointer met outside deferred pointer processing
is "top level" (a REF pointer has no referent id and its pointee follows
at once, a unique pointer's pointee follows its referent id at once);
pointers met while a pointee is dissected are deferred, depth first.

Addresses are from 192.0.2.0/24. The secure channel connections on
192.0.2.73 and .74 carry verifiers with no session key. A further
connection (192.0.2.75) does negotiate a session key: its
ServerAuthenticate credentials are computed from the NT password
SchannelCover, which main() writes to cfg/ntlmssp_creds, and its
verifiers and sealed stubs are encrypted with that key (AES-128 and
RC4, and the zero key of NetrServerAuthenticateKerberos). The
connection on 192.0.2.76 encrypts netr_CryptPassword and the
OpaqueBuffer of NetrLogonSendToSam with the same password's AES and
STRONGKEY session keys, and sends a buffer the DES key cannot decrypt.
One UDP Kerberos Ticket (192.0.2.87 to 192.0.2.77) carries a PAC
with logon, S4U and device buffers, which are the NETLOGON PAC
helpers. It is only the Ticket, not a Kerberos exchange. The main
capture is pcapng and carries both long-term keys in a decryption
secrets block, so the ticket and the TICKET_INFO blobs decrypt with
no keytab and no Kerberos preference. The malformed capture ends with
a NetrServerAuthenticateKerberos reply whose request never created a
session.

Writes dcerpc_netlogon-coverage.pcapng and
dcerpc_netlogon-coverage-malformed.pcap.
"""

import ctypes
import os
import struct
import sys

UUID_NETLOGON = '12345678-1234-abcd-ef00-01234567cffb'
UUID_NDR = '8a885d04-1ceb-11c9-9fe8-08002b104860'
UUID_NDR64 = '71710533-beba-4937-8319-b5dbef9ccc36'


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
    """pcapng with an Ethernet interface. secrets, if given, is a
    Kerberos key log and is written in a decryption secrets block
    before the first packet."""
    shb = struct.pack('<IHHQ', 0x1A2B3C4D, 1, 0, 0xFFFFFFFFFFFFFFFF)
    shb += struct.pack('<HH', 0, 0)
    idb = struct.pack('<HHI', 1, 0, 262144)
    idb += struct.pack('<HH', 0, 0)
    blocks = [_pcapng_block(0x0A0D0D0A, shb), _pcapng_block(0x00000001, idb)]
    if secrets:
        data = secrets if isinstance(secrets, bytes) else secrets.encode()
        dsb = struct.pack('<II', 0x4B524235, len(data)) + data
        blocks.append(_pcapng_block(0x0000000A, dsb))
    for i, fr in enumerate(frames):
        ts = (1700000000 + i // 10) * 1000000 + 100000 * (i % 10)
        epb = struct.pack('<IIIII', 0, (ts >> 32) & 0xFFFFFFFF, ts & 0xFFFFFFFF,
                          len(fr), len(fr))
        epb += fr
        epb += b'\0' * ((4 - len(fr) % 4) % 4)
        epb += struct.pack('<HH', 0, 0)
        blocks.append(_pcapng_block(0x00000006, epb))
    with open(path, 'wb') as f:
        f.write(b''.join(blocks))


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


# ------------------------------------------------------------------ DCE/RPC
class RPC:
    def __init__(self, tcp, le=True, ndr64=False):
        self.tcp, self.le, self.ndr64 = tcp, le, ndr64
        self.e = '<' if le else '>'
        self.call_id = 0

    def uuid_bytes(self, u):
        h = u.replace('-', '')
        a, b, c = int(h[0:8], 16), int(h[8:12], 16), int(h[12:16], 16)
        return struct.pack(self.e + 'IHH', a, b, c) + bytes.fromhex(h[16:])

    def pdu(self, ptype, body, call_id, flags=0x03, auth=None):
        """auth: (auth_type, level, value) for a sec_trailer after body."""
        drep = bytes([0x10 if self.le else 0x00, 0, 0, 0])
        a, alen = b'', 0
        if auth:
            atype, level, value = auth[:3]
            ctx = auth[3] if len(auth) > 3 else 0
            pad = (-(16 + len(body))) % 4
            a = b'\0' * pad + struct.pack(self.e + 'BBBBI', atype, level, pad, 0, ctx) + value
            alen = len(value)
        hdr = struct.pack(self.e + 'BBBB', 5, 0, ptype, flags) + drep
        hdr += struct.pack(self.e + 'HHI', 16 + len(body) + len(a), alen, call_id)
        return hdr + body + a

    def bind(self, auth=None):
        self.call_id += 1
        ts = (UUID_NDR64, 1) if self.ndr64 else (UUID_NDR, 2)
        body = struct.pack(self.e + 'HHI', 4280, 4280, 0) + struct.pack(self.e + 'B3x', 1)
        body += struct.pack(self.e + 'HBx', 0, 1) + self.uuid_bytes(UUID_NETLOGON)
        body += struct.pack(self.e + 'I', 1)
        body += self.uuid_bytes(ts[0]) + struct.pack(self.e + 'I', ts[1])
        self.tcp.send(True, self.pdu(11, body, self.call_id, auth=auth[0] if auth else None))
        sec = b'49157\0'
        body = struct.pack(self.e + 'HHI', 4280, 4280, 0x12345) + struct.pack(self.e + 'H', len(sec)) + sec
        body += b'\0' * ((-(16 + len(body))) % 4)
        body += struct.pack(self.e + 'B3x', 1) + struct.pack(self.e + 'HH', 0, 0)
        body += self.uuid_bytes(ts[0]) + struct.pack(self.e + 'I', ts[1])
        self.tcp.send(False, self.pdu(12, body, self.call_id, auth=auth[1] if auth else None))

    def frags(self, ptype, stub, hdr, maxfrag):
        parts = [stub[i:i + maxfrag] for i in range(0, len(stub), maxfrag)] or [b'']
        out = b''
        for i, p in enumerate(parts):
            flags = (0x01 if i == 0 else 0) | (0x02 if i == len(parts) - 1 else 0)
            out += self.pdu(ptype, hdr(len(stub)) + p, self.call_id, flags)
        return out

    def request_pdu(self, opnum, stub, auth=None):
        return self.pdu(0, struct.pack(self.e + 'IHH', len(stub), 0, opnum) + stub, self.call_id, auth=auth)

    def response_pdu(self, stub, auth=None):
        return self.pdu(2, struct.pack(self.e + 'IHBB', len(stub), 0, 0, 0) + stub, self.call_id, auth=auth)

    def call(self, opnum, req, resp, maxfrag=1 << 20):
        self.call_id += 1
        self.tcp.send(True, self.frags(0, req, lambda n: struct.pack(self.e + 'IHH', n, 0, opnum), maxfrag))
        if resp is not None:
            self.tcp.send(False, self.frags(2, resp, lambda n: struct.pack(self.e + 'IHBB', n, 0, 0, 0), maxfrag))


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


def ace(atype, flags, mask, sid):
    body = struct.pack('<I', mask) + sid_bytes(sid)
    return struct.pack('<BBH', atype, flags, 4 + len(body)) + body


def acl(aces):
    body = b''.join(aces)
    return struct.pack('<BBHHH', 2, 0, 8 + len(body), len(aces), 0) + body


def secdesc():
    """Self-relative security descriptor with owner, group, SACL, DACL."""
    owner = sid_bytes(DOM + '-500')
    group = sid_bytes(DOM + '-513')
    sacl = acl([ace(2, 0xc0, 0x000f0fff, 'S-1-1-0')])
    dacl = acl([ace(0, 0x00, 0x000f1fff, DOM + '-500'),
                ace(1, 0x02, 0x00000003, 'S-1-5-32-544')])
    o_own = 20
    o_grp = o_own + len(owner)
    o_sacl = o_grp + len(group)
    o_dacl = o_sacl + len(sacl)
    hdr = struct.pack('<BBHIIII', 1, 0, 0x8014, o_own, o_grp, o_sacl, o_dacl)
    return hdr + owner + group + sacl + dacl


SECDESC = secdesc()


# ------------------------------------------------------------------ NETLOGON types
# Each n_* function writes one type the way netlogon_dissect_* reads it.
# 'r' selects the rich variant (every pointer set) or the minimal one.

def n_sec_desc_buf(w, sd):
    """lsarpc_dissect_sec_desc_buf: length, unique pointer to (length, SD)."""
    w.u32(len(sd) if sd else 0)

    def pointee():
        w.u32(len(sd))
        w.raw(sd)
    w.ptr(pointee if sd else None)


def n_logonsrv(w, s='\\\\DC1'):
    w.wstr(s)


def n_authenticator(w, cred=b'\x11' * 8, ts=1700000000):
    w.align(4)
    w.raw(cred)
    w.buf += struct.pack('<I', ts)       # ENC_TIME_SECS|ENC_LITTLE_ENDIAN


def n_validation_uas(w, r=True):
    w.wstr('Administrator' if r else None)
    for v in (7, 3, 12, 1):
        w.u32(v)
    for i in range(7):
        w.u32(1700000000 + i)            # time_t
    w.wstr('WS01' if r else None)
    w.wstr('EXAMPLE' if r else None)
    w.wstr('logon.cmd' if r else None)
    w.u32(0)


def n_logoff_uas(w):
    w.u32(3600)
    w.u16(5)


def n_identity(w, r=True, dom='EXAMPLE', acct='alice', ws='WS01'):
    w.ustr(dom if r else None)
    w.u32(0x00000820)
    w.duint32(0x0000000100000002)
    w.ustr(acct if r else None)
    w.ustr(ws if r else None)


def n_interactive(w, r=True):
    n_identity(w, r)
    w.raw(bytes(range(0x10, 0x20)))      # LM_OWF_PASSWORD
    w.raw(bytes(range(0x20, 0x30)))      # NT_OWF_PASSWORD


def n_lm_nt_hash(w, data):
    """dissect_ndr_lm_nt_hash_cb: align 4, len, size, unique ptr to a byte
    string (dissect_ndr_byte_array: max, offset, actual, bytes)."""
    w.align(4)
    w.u16(len(data) if data is not None else 0)
    w.u16(len(data) if data is not None else 0)
    w.ptr(None if data is None else (lambda: w.bytes_cvarray(data)))


def ntlmv2_response(big=False):
    """An NTLMv2 response: NTProofStr and the client blob with AV pairs."""
    avs = b''
    pairs = [(2, 'EXAMPLE'), (1, 'DC1'), (4, 'example.test'), (3, 'dc1.example.test')]
    for t, v in pairs:
        u = v.encode('utf-16-le')
        avs += struct.pack('<HH', t, len(u)) + u
    avs += struct.pack('<HHQ', 7, 8, NT1)
    avs += struct.pack('<HHI', 6, 4, 2)
    avs += struct.pack('<HH', 0, 0)
    blob = struct.pack('<BBHIQ', 1, 1, 0, 0, NT1) + bytes(range(0x40, 0x48)) + b'\0' * 4 + avs + b'\0' * 4
    if big:
        blob += b'\0' * 10300
    return bytes(range(0xa0, 0xb0)) + blob


def n_network(w, r=True, v2=False):
    if r == 'acct':
        # only the account name: the NTLMSSP state gets empty domain and host
        w.ustr(None)
        w.u32(0x00000820)
        w.duint32(3)
        w.ustr('carol')
        w.ustr(None)
    else:
        n_identity(w, r)
    w.raw(bytes.fromhex('0123456789abcdef'))     # CHALLENGE
    if r:
        n_lm_nt_hash(w, ntlmv2_response(v2 == 'big') if v2 else bytes(range(0x30, 0x48)))
        n_lm_nt_hash(w, bytes(range(0x50, 0x68)))
    else:
        n_lm_nt_hash(w, None)
        n_lm_nt_hash(w, None)


def n_generic(w, r=True):
    n_identity(w, r)
    w.ustr('Kerberos' if r else None)
    data = b'GENERIC-DATA' if r else b''
    w.u32(len(data))
    w.ptr(lambda: w.bytes_carray(data))  # embedded REF pointer


# Kerberos. libkrb5 builds the ciphertext. The keys travel in the
# capture's decryption secrets block (one line per key). A keytab and
# the decrypt preference are not required.
PAC_ETYPE = 17          # AES128-CTS-HMAC-SHA1-96, the UDP ticket
PAC_KEY = bytes(range(0x41, 0x51))
TICKET_ETYPE = 18       # AES256, the TICKET_INFO blobs inside NETLOGON
TICKET_KEY = bytes(range(0x61, 0x81))
KV5M_DATA = -1760647422
KV5M_KEYBLOCK = -1760647421
KV5M_ENC_DATA = -1760647418


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


def krb5():
    """One libkrb5 context, kept for the rest of the process."""
    k = getattr(krb5, '_k', None)
    if k is not None:
        return k
    k = ctypes.CDLL('libkrb5.so.3')
    k.krb5_init_context.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    k.krb5_init_context.restype = ctypes.c_int32
    k.krb5_get_error_message.argtypes = [ctypes.c_void_p, ctypes.c_int32]
    k.krb5_get_error_message.restype = ctypes.c_char_p
    k.krb5_pac_init.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    k.krb5_pac_init.restype = ctypes.c_int32
    k.krb5_pac_add_buffer.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_uint32, ctypes.POINTER(_KrbData)]
    k.krb5_pac_add_buffer.restype = ctypes.c_int32
    k.krb5_pac_sign.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int32,
                                ctypes.c_void_p, ctypes.POINTER(_KrbKeyblock),
                                ctypes.POINTER(_KrbKeyblock), ctypes.POINTER(_KrbData)]
    k.krb5_pac_sign.restype = ctypes.c_int32
    k.krb5_free_data_contents.argtypes = [ctypes.c_void_p, ctypes.POINTER(_KrbData)]
    k.krb5_c_encrypt_length.argtypes = [ctypes.c_void_p, ctypes.c_int32,
                                        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k.krb5_c_encrypt_length.restype = ctypes.c_int32
    k.krb5_c_encrypt.argtypes = [ctypes.c_void_p, ctypes.POINTER(_KrbKeyblock),
                                 ctypes.c_int32, ctypes.c_void_p,
                                 ctypes.POINTER(_KrbData), ctypes.POINTER(_KrbEncData)]
    k.krb5_c_encrypt.restype = ctypes.c_int32
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
    buf = ctypes.create_string_buffer(key)
    kb.contents = ctypes.cast(buf, ctypes.c_void_p)
    kb._buf = buf
    return kb


def _krb_data(blob):
    d = _KrbData()
    d.magic = KV5M_DATA
    d.length = len(blob)
    buf = ctypes.create_string_buffer(blob)
    d.data = ctypes.cast(buf, ctypes.c_void_p)
    d._buf = buf
    return d


def krb5_encrypt(etype, key, plain, usage):
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


def krb5_ticket():
    """A DER Kerberos Ticket ([APPLICATION 1]).

    The enc-part is 32 octets, the same size as before, so the frames
    that carry a TICKET_INFO do not move. It is AES256 (usage 2) of four
    zero bytes: long enough to decrypt, and not an application tag, so
    the Kerberos choice does not match and decryption does not warn.
    The key is TICKET_KEY in the capture's decryption secrets block.
    """
    def der(tag, body):
        n = len(body)
        ln = bytes([n]) if n < 0x80 else (bytes([0x81, n]) if n < 0x100 else bytes([0x82, n >> 8, n & 0xff]))
        return bytes([tag]) + ln + body

    def ctx(n, body):
        return der(0xa0 + n, body)
    gs = lambda s: der(0x1b, s.encode())
    integer = lambda v: der(0x02, bytes([v]))
    if getattr(krb5_ticket, '_cipher', None) is None:
        krb5_ticket._cipher = krb5_encrypt(TICKET_ETYPE, TICKET_KEY, b'\0\0\0\0', 2)
    if len(krb5_ticket._cipher) != 32:
        raise RuntimeError('ticket cipher is %d bytes' % len(krb5_ticket._cipher))
    sname = der(0x30, ctx(0, integer(2)) + ctx(1, der(0x30, gs('host') + gs('dc1.example.test'))))
    enc = der(0x30, ctx(0, integer(TICKET_ETYPE)) + ctx(1, integer(2)) +
              ctx(2, der(0x04, krb5_ticket._cipher)))
    tkt = der(0x30, ctx(0, integer(5)) + ctx(1, gs('EXAMPLE.TEST')) + ctx(2, sname) + ctx(3, enc))
    blob = der(0x61, tkt)
    if len(blob) != 112:
        raise RuntimeError('Kerberos ticket length %d would move later frames' % len(blob))
    return blob


def n_ticket_info(w, r=True):
    n_identity(w, r)
    w.u64(0x0003000300030001 if r else 0)
    t = krb5_ticket()
    w.u32(len(t) if r else 0)
    w.bytes_ptr(t if r else None)
    w.u32(len(t) if r else 0)
    w.bytes_ptr(t if r else None)


LEVEL_FN = {1: n_interactive, 2: n_network, 3: n_interactive, 4: n_generic,
            5: n_interactive, 6: n_network, 7: n_interactive, 8: n_ticket_info}


def n_level(w, level, r=True, v2=False):
    """netlogon_dissect_LEVEL (the pointee of the REF pointer)."""
    w.u16(level)
    w.align(4)
    fn = LEVEL_FN.get(level)
    if fn is None:
        return
    if level in (2, 6):
        w.ptr(lambda: n_network(w, r, v2))
    else:
        w.ptr(lambda: fn(w, r))


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


# ---- database deltas
def n_dummies(w, r):
    for i in range(4):
        w.ustr(('spare%d' % i) if r and i == 0 else None)
    for i in range(4):
        w.u32(0)


def n_delta_delete_user(w, r=True):
    w.wstr('bob' if r else None)
    n_dummies(w, r)


def n_delta_user(w, r=True):
    w.ustr('alice' if r else None)
    w.ustr('Alice Example' if r else None)
    w.u32(1104)
    w.u32(513)
    for s in ('\\\\fs\\home\\alice', 'H:', 'logon.cmd', 'A user', 'WS01,WS02'):
        w.ustr(s if r else None)
    w.nttime(NT1)
    w.nttime(NT1 + 1)
    # LOGON_HOURS: align 4, divisions, unique pointer to a cv array of bytes
    w.align(4)
    w.u16(168)
    w.ptr((lambda: w.cvarray(list(range(21)), w.u8)) if r else None)
    w.u16(2)
    w.u16(40)
    w.nttime(NT1 + 2)
    w.nttime(0x7fffffffffffffff)
    w.u32(0x00000210)                    # acct_ctrl
    w.raw(bytes(range(0x10, 0x20)))
    w.raw(bytes(range(0x20, 0x30)))
    w.u8(1)
    w.u8(0)
    w.u8(0)
    w.ustr('comment' if r else None)
    w.ustr('params' if r else None)
    w.u16(61)
    w.u16(1252)
    # USER_PRIVATE_INFO
    w.u8(1)
    data = b'SENSITIVE' if r else b''
    w.u32(len(data))

    def sens():
        w.u32(len(data))
        w.raw(data)
    w.ptr(sens if r else None)
    w.u32(7)
    n_sec_desc_buf(w, SECDESC if r else None)
    n_dummies(w, r)


def n_delta_domain(w, r=True):
    w.ustr('EXAMPLE' if r else None)
    w.ustr('OEM' if r else None)
    w.nttime(NT1)
    w.u16(7)
    w.u16(24)
    for i in range(4):
        w.nttime(NT1 + i)
    w.u32(4)
    n_sec_desc_buf(w, SECDESC if r else None)
    n_dummies(w, r)


def n_delta_group(w, r=True):
    w.ustr('Staff' if r else None)
    n_group_membership(w, 1105, 7)
    w.ustr('Staff group' if r else None)
    w.u32(4)
    n_sec_desc_buf(w, SECDESC if r else None)
    n_dummies(w, r)


def n_delta_rename(w, r=True):
    w.ustr('oldname' if r else None)
    w.ustr('newname' if r else None)
    n_dummies(w, r)


def n_delta_group_member(w, r=True):
    rids = [1104, 1106]
    w.ptr((lambda: w.carray(rids, w.u32)) if r else None)
    w.ptr((lambda: w.carray([7, 7], w.u32)) if r else None)
    w.u32(len(rids) if r else 0)
    for i in range(4):
        w.u32(0)


def n_delta_alias(w, r=True):
    w.ustr('Printers' if r else None)
    w.u32(1107)
    w.u32(4)
    n_sec_desc_buf(w, SECDESC if r else None)
    n_dummies(w, r)


def n_delta_alias_member(w, r=True):
    # dissect_ndr_nt_PSID_ARRAY: align, count, unique pointer to array of PSID
    sids = [DOM + '-1104', 'S-1-5-32-544']
    w.align5()
    w.u32(len(sids) if r else 0)
    w.ptr((lambda: w.carray(sids, lambda s: w_psid(w, s))) if r else None)
    if w.ndr64:
        w.align5()
    for i in range(4):
        w.u32(0)


def n_quota_limits(w):
    for v in (0x100000, 0x80000, 0x10000, 0x200000, 0x400000):
        w.u32(v)
    w.nttime(0)


def n_delta_policy(w, r=True):
    w.u32(0x80000)
    w.nttime(864000000000)
    w.u8(1)
    opts = [0, 1, 2, 3, 0, 1, 2, 3, 0]
    w.u32(len(opts) if r else 0)
    w.ptr((lambda: w.carray(opts, w.u32)) if r else None)
    w.ustr('EXAMPLE' if r else None)
    w_psid(w, DOM if r else None)
    n_quota_limits(w)
    w.nttime(NT1)
    w.nttime(NT1 - 1)
    w.u32(4)
    n_sec_desc_buf(w, SECDESC if r else None)
    n_dummies(w, r)


def n_delta_trusted_domains(w, r=True):
    w.ustr('TRUSTED' if r else None)
    dcs = ['TDC1', 'TDC2']
    w.u32(len(dcs) if r else 0)
    w.ptr((lambda: w.carray(dcs, lambda s: w.ustr(s))) if r else None)
    w.u32(4)
    n_sec_desc_buf(w, SECDESC if r else None)
    n_dummies(w, r)


def n_delta_accounts(w, r=True):
    privs = ['SeBackupPrivilege', 'SeRestorePrivilege']
    w.u32(len(privs) if r else 0)
    w.u32(1)
    w.ptr((lambda: w.carray([3, 0], w.u32)) if r else None)
    w.ptr((lambda: w.carray(privs, lambda s: w.ustr(s))) if r else None)
    n_quota_limits(w)
    w.u32(0x10)
    w.u32(4)
    n_sec_desc_buf(w, SECDESC if r else None)
    n_dummies(w, r)


def n_cipher_value(w, data):
    w.u32(len(data) if data else 0)
    w.u32(len(data) if data else 0)

    def pointee():
        w.u32(len(data))
        w.u32(0)
        w.u32(len(data))
        w.raw(data)
    w.ptr(pointee if data else None)


def n_delta_secret(w, r=True):
    n_cipher_value(w, bytes(range(0x80, 0x98)) if r else None)
    w.nttime(NT1)
    n_cipher_value(w, bytes(range(0x98, 0xa8)) if r else None)
    w.nttime(NT1 - 100)
    w.u32(4)
    n_sec_desc_buf(w, SECDESC if r else None)
    n_dummies(w, r)


DELTA_FN = {1: n_delta_domain, 2: n_delta_group, 4: n_delta_rename, 5: n_delta_user,
            7: n_delta_rename, 8: n_delta_group_member, 9: n_delta_alias, 11: n_delta_rename,
            12: n_delta_alias_member, 13: n_delta_policy, 14: n_delta_trusted_domains,
            16: n_delta_accounts, 18: n_delta_secret, 20: n_delta_delete_user,
            21: n_delta_delete_user, 22: lambda w, r: w.duint32(0x0000000100000005)}


def n_delta_enum(w, t, r=True):
    w.u16(t)
    # DELTA_ID_UNION
    w.u16(t)
    w.align(4)
    if t in (13, 14, 15, 16, 17):
        w_psid(w, (DOM + '-%d' % (2000 + t)) if r else None)
    elif t in (18, 19):
        w.wstr('G$SECRET%d' % t if r else None)
    elif 1 <= t <= 21:
        w.u32(1000 + t)
    # DELTA_UNION
    w.u16(t)
    w.align(4)
    fn = DELTA_FN.get(t)
    if fn is not None:
        w.ptr((lambda: fn(w, r)) if r is not None else None)


def n_delta_enum_array(w, types, r=True):
    w.u32(len(types))
    w.ptr(lambda: w.carray(types, lambda t: n_delta_enum(w, t, r)))


# ------------------------------------------------------------------ calls
# CALLS: list of (opnum, request writer, response writer); a writer is
# called with a fresh W.
CALLS = []
MALFORMED_CALLS = []


def call(opnum):
    def deco(fn):
        for req, resp in fn():
            CALLS.append((opnum, req, resp))
        return fn
    return deco


def auth_ref(w, cred=b'\x11' * 8):
    w.ptr(lambda: n_authenticator(w, cred), 'ref')


def auth_unique(w, present=True, cred=b'\x22' * 8):
    w.ptr((lambda: n_authenticator(w, cred)) if present else None)


@call(0)
def op_uaslogon():
    def req(w):
        n_logonsrv(w)
        w.wstr('alice', 'ref')
        w.wstr('WS01', 'ref')

    def resp(r):
        def f(w):
            w.ptr((lambda: n_validation_uas(w, r)))
            w.u32(0)
        return f
    return [(req, resp(True)), (req, resp(False))]


@call(1)
def op_uaslogoff():
    def req(w):
        n_logonsrv(w, None)
        w.wstr('alice', 'ref')
        w.wstr('WS01', 'ref')

    def resp(w):
        w.ptr(lambda: n_logoff_uas(w), 'ref')
        w.u32(0)
    return [(req, resp)]


def samlogon_req(level, r=True, v2=False, auth=True, flags=None):
    def f(w):
        n_logonsrv(w)
        w.wstr('WS01')
        auth_unique(w, auth)
        auth_unique(w, auth, b'\x33' * 8)
        w.u16(level)
        w.ptr(lambda: n_level(w, level, r, v2), 'ref')
        w.u16(3)
        if flags is not None:
            w.u32(flags)
    return f


# ---- validation (the pointee of the REF pointer)
def n_validation_generic2(w, r=True):
    data = b'VALIDATION-DATA' if r else b''
    w.u32(len(data))
    w.ptr(lambda: w.bytes_carray(data))


def n_validation(w, level, r=True, fmts=(0, 2)):
    w.u16(level)
    w.align(4)
    if level == 7:
        w.ptr(lambda: n_validation_ticket_logon(w, r, fmts))
        return
    fn = {1: n_validation_uas, 2: n_validation_sam, 3: n_validation_sam2,
          4: n_validation_generic2, 5: n_validation_generic2, 6: n_validation_sam4,
          7: n_validation_ticket_logon}.get(level)
    if fn is not None:
        w.ptr(lambda: fn(w, r))


def samlogon_resp(level, r=True, auth=True, flags=None, fmts=(0, 2)):
    def f(w):
        auth_unique(w, auth, b'\x44' * 8)
        w.ptr(lambda: n_validation(w, level, r, fmts), 'ref')
        w.u8(1)
        if flags is not None:
            w.u32(flags)
        w.u32(0)
    return f


@call(2)
def op_samlogon():
    out = []
    for level in range(1, 9):
        out.append((samlogon_req(level), samlogon_resp(min(level, 7))))
    out.append((samlogon_req(2, v2=True), samlogon_resp(6, r=False)))
    out.append((samlogon_req(1, r=False, auth=False), samlogon_resp(3, r=False, auth=False)))
    out.append((samlogon_req(9), samlogon_resp(8)))
    out.append((samlogon_req(8), samlogon_resp(7, fmts=(3, 4))))
    out.append((samlogon_req(8, r=False), samlogon_resp(7, r=False, fmts=(2, 5))))
    out.append((samlogon_req(8), samlogon_resp(7, fmts=(None, 1))))
    out.append((samlogon_req(8), samlogon_resp(7, fmts=(('bad', 2), ('bad', 3)))))
    out.append((samlogon_req(8), samlogon_resp(7, fmts=(('bad', 4), 'empty'))))
    return out


@call(3)
def op_samlogoff():
    def req(level):
        def f(w):
            n_logonsrv(w)
            w.wstr('WS01')
            auth_unique(w)
            auth_unique(w, False)
            w.u16(level)
            w.ptr(lambda: n_level(w, level), 'ref')
        return f

    def resp(w):
        auth_unique(w)
        w.u32(0xc000006d)
    return [(req(1), resp), (req(2), resp)]


# ---- claims (MS-ADTS CLAIMS_SET in an NDR32 MES blob)
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


def n_validation_ticket_logon(w, r=True, fmts=(0, 2)):
    w.u64(0x007f003f00000001 if r else 0)
    w.u32(0)
    w.u32(0)
    w.ustr('KDC' if r else None)
    w.ptr((lambda: n_validation_sam4(w, True)) if r else None)
    w.ptr((lambda: n_validation_sam4(w, False)) if r else None)
    sizes = []
    for fmt in fmts:
        # the size field comes before the pointer; compute the blob first
        sizes.append(len(claims_metadata_blob(0, fmt, r)) if fmt not in (None, 'empty') else 0)
    w.u32(sizes[0])
    w.ptr((lambda: w_claims_blob(w, fmts[0], r)) if fmts[0] is not None else None)
    w.u32(sizes[1])
    w.ptr((lambda: w_claims_blob(w, fmts[1], r)) if fmts[1] is not None else None)


# ---- borrowed LSA types (Pidl, packet-dcerpc-lsa.c), written by hand
def lsa_forest_trust_info(w, r=True):
    """lsarpc_dissect_struct_lsa_ForestTrustInformation."""
    recs = [(0, 'example.test'), (1, 'excluded.example.test'),
            (2, (DOM, 'child.example.test', 'CHILD')), (3, b'\x01\x02\x03\x04\x05')]
    if not r:
        recs = []

    def record(rec):
        t, v = rec
        w.align(8)
        w.u32(0x00000001 if t else 0)
        w.u1632(t)
        w.u64(NT1)
        w.u1632(t)                         # union level
        w.align5()
        if t in (0, 1):
            w.ustr(v)
        elif t == 2:
            w.align5()
            w.ptr(lambda: w_sid(w, v[0]))
            w.ustr(v[1])
            w.ustr(v[2])
            if w.ndr64:
                w.align5()
        else:
            w.align5()
            w.u32(len(v))
            w.ptr(lambda: w.bytes_carray(v))
            if w.ndr64:
                w.align5()
        if w.ndr64:
            w.align(8)
    w.align5()
    w.u32(len(recs))
    w.ptr((lambda: w.carray(recs, lambda rec: w.ptr(lambda: record(rec)))) if r else None)
    if w.ndr64:
        w.align5()


def n_dc_info(w, r=True):
    """DOMAIN_CONTROLLER_INFO."""
    w.wstr('\\\\dc1.example.test' if r else None)
    w.wstr('\\\\192.0.2.80' if r else None)
    w.u32(1)
    w.guid(GUID1)
    w.wstr('example.test' if r else None)
    w.wstr('example.test' if r else None)
    w.u32(0xe00003fd if r else 0x0000ffff)
    w.wstr('Default-First-Site-Name' if r else None)
    w.wstr('Branch-Site' if r else None)


def n_trust_ext(w):
    """ulongs_as_counted_string: align 4, len, size, pointer to max,
    offset, len (in 16-bit units) and, for max 8, the trust fields."""
    w.align(4)
    w.u16(16)
    w.u16(16)

    def pointee():
        w.u3264(8)
        w.u3264(0)
        w.u3264(8)
        w.u32(0x0000001d)
        w.u32(0)
        w.u32(2)
        w.u32(0x00000008)
    w.ptr(pointee)


def n_one_domain_info(w, r=True, name='EXAMPLE'):
    w.ustr(name if r else None)
    w.ustr('example.test' if r else None)
    w.ustr('example.test' if r else None)
    w.guid(GUID2)
    w.ptr((lambda: w_sid(w, DOM)) if r else None)
    if r:
        n_trust_ext(w)
    else:
        w.align(4)
        w.u16(0)
        w.u16(0)
        w.ptr(None)
    for s in ('d2', 'd3', 'd4'):
        w.ustr(s if r else None)
    for i in range(4):
        w.u32(i)


def n_lsa_policy_info(w, r=True):
    data = b'POLICY' if r else None
    w.u32(len(data) if data else 0)

    def pointee():
        w.u32(len(data))
        w.raw(data)
    w.ptr(pointee if data else None)


def n_workstation_info(w, r=True):
    n_lsa_policy_info(w, r)
    w.wstr('ws01.example.test' if r else None)
    w.wstr('Default-First-Site-Name' if r else None)
    for s in ('w1', 'w2', 'w3', 'w4'):
        w.wstr(s if r else None)
    w.ustr('10.0 (19045)' if r else None)
    w.ustr('Windows 10 Enterprise' if r else None)
    w.ustr('w5' if r else None)
    w.ustr(None)
    for i in range(4):
        w.u32(i)


def n_ds_domain_trust(w, t):
    nb, dns, flags, parent, ttype, attr, sid = t
    w.wstr(nb)
    w.wstr(dns)
    w.u32(flags)
    w.u32(parent)
    w.u32(ttype)
    w.u32(attr)
    w_psid(w, sid)
    w.guid(GUID1)


TRUSTS = [('EXAMPLE', 'example.test', 0x1d, 0, 2, 0x20, DOM),
          ('TRUSTED', 'trusted.test', 0x22, 0, 2, 0x8, DOM[:-1] + '1'),
          ('MIT', None, 0x02, 0, 3, 0x1 | 0x2 | 0x4 | 0x10 | 0x40, None)]


def ntstatus(w, v=0):
    w.u32(v)


def computer_ref(w, s='WS01'):
    w.wstr(s, 'ref')


@call(4)
def op_reqchallenge():
    def req(w):
        n_logonsrv(w)
        computer_ref(w)
        w.raw(bytes.fromhex('c1c2c3c4c5c6c7c8'))

    def resp(w):
        w.raw(bytes.fromhex('5152535455565758'))
        ntstatus(w)
    return [(req, resp)]


def auth_req(w, acct='WS01$', ctype=2, comp='WS01'):
    n_logonsrv(w)
    w.wstr(acct, 'ref')
    w.u1632(ctype)
    w.wstr(comp, 'ref')


@call(5)
def op_authenticate():
    def req(w):
        auth_req(w)
        w.ptr(lambda: w.raw(b'\x66' * 8), 'ref')

    def resp(w):
        w.raw(b'\x77' * 8)
        ntstatus(w)
    return [(req, resp)]


@call(6)
def op_passwordset():
    def req(w):
        auth_req(w)
        auth_ref(w)
        w.ptr(lambda: w.raw(bytes(range(0xe0, 0xf0))), 'ref')

    def resp(w):
        auth_ref(w)
        ntstatus(w)
    return [(req, resp)]


ALL_DELTAS = list(range(1, 23)) + [99]


@call(7)
def op_databasedeltas():
    def req(w):
        w.wstr('\\\\DC1', 'ref')
        computer_ref(w, 'BDC1')
        auth_ref(w)
        auth_ref(w, b'\x12' * 8)
        w.u32(0)
        w.ptr(lambda: w.duint32(0x0000000100000005), 'ref')
        w.u32(0xffff)

    def resp(types, r=True):
        def f(w):
            auth_ref(w)
            w.ptr(lambda: w.duint32(0x0000000100000006), 'ref')
            w.ptr(lambda: n_delta_enum_array(w, types, r))
            ntstatus(w)
        return f

    def resp_null(w):
        auth_ref(w)
        w.ptr(lambda: w.duint32(1), 'ref')
        w.ptr(None)
        ntstatus(w, 0x00000106)
    return [(req, resp(ALL_DELTAS)), (req, resp(ALL_DELTAS, False)), (req, resp_null)]


@call(8)
def op_databasesync():
    def req(w):
        w.wstr('\\\\DC1', 'ref')
        computer_ref(w, 'BDC1')
        auth_ref(w)
        auth_ref(w)
        w.u32(1)
        w.u32(0)
        w.u32(0xffff)

    def resp(w):
        auth_ref(w)
        w.u32(5)
        w.ptr(lambda: n_delta_enum_array(w, [1, 5, 13]))
        ntstatus(w)
    return [(req, resp)]


def uas_info_0(w):
    w.raw(b'COMPUTER\0\0\0\0\0\0\0\0')
    w.buf += struct.pack(w.e + 'I', 1700000000)
    w.u32(42)


@call(9)
def op_accountdeltas():
    def req(w):
        n_logonsrv(w)
        computer_ref(w, 'BDC1')
        auth_ref(w)
        auth_ref(w)
        w.ptr(lambda: uas_info_0(w), 'ref')
        w.u32(1)
        w.u32(0)
        w.u32(4096)

    def resp(w):
        auth_ref(w)
        w.ptr(lambda: w.bytes_carray(b'ACCOUNT-DELTAS'), 'ref')
        w.u32(1)
        w.u32(1)
        w.ptr(lambda: uas_info_0(w), 'ref')
        ntstatus(w)
    return [(req, resp)]


@call(10)
def op_accountsync():
    def req(w):
        n_logonsrv(w)
        computer_ref(w, 'BDC1')
        auth_ref(w)
        auth_ref(w)
        w.u32(0)
        w.u32(1)
        w.u32(4096)

    def resp(w):
        auth_ref(w)
        w.ptr(lambda: w.bytes_carray(b'ACCOUNT-SYNC'), 'ref')
        w.u32(1)
        w.u32(1)
        w.u32(2)
        w.ptr(lambda: uas_info_0(w), 'ref')
        ntstatus(w)
    return [(req, resp)]


@call(11)
def op_getdcname():
    def req(w):
        w.wstr('\\\\DC1', 'ref')
        w.wstr('EXAMPLE')

    def resp(w):
        w.wstr('\\\\DC1')
        ntstatus(w)
    return [(req, resp)]


def query_info(level, r=True):
    def f(w):
        def pointee():
            w.u32(level)
            w.align(4)
            if level == 1:
                w.ptr((lambda: (w.u32(0x80), w.u32(0))) if r else None)
            elif level == 2:
                w.ptr((lambda: (w.u32(0x80), w.u32(0), w.wstr('\\\\TDC1'), w.u32(0))) if r else None)
            elif level == 3:
                w.ptr((lambda: [w.u32(v) for v in (0x80, 0, 3, 0, 0, 0, 0)]) if r else None)
        w.ptr(pointee, 'ref')
        w.u32(0)
    return f


@call(12)
def op_logoncontrol():
    def req(level):
        def f(w):
            n_logonsrv(w)
            w.u32(9)
            w.u32(level)
        return f
    return [(req(1), query_info(1)), (req(2), query_info(2)), (req(3), query_info(3)),
            (req(4), query_info(4)), (req(1), query_info(1, False))]


@call(13)
def op_getanydcname():
    def req(w):
        n_logonsrv(w)
        w.wstr('TRUSTED')

    def resp(w):
        w.wstr(None)
        ntstatus(w, 0xc000005e)
    return [(req, resp)]


def control_data(level, r=True):
    def f(w):
        def pointee():
            w.u32(level)
            w.align(4)
            if level in (5, 6, 8):
                w.wstr(('TRUSTED' if level != 8 else 'alice') if r else None)
            elif level == 0xfffe:
                w.u32(0x00000020)
        w.ptr(pointee, 'ref')
    return f


def control2_req(fc, level, r=True):
    def f(w):
        n_logonsrv(w)
        w.u32(fc)
        w.u32(level)
        control_data(fc, r)(w)
    return f


@call(14)
def op_logoncontrol2():
    return [(control2_req(5, 2), query_info(2)), (control2_req(6, 2), query_info(2)),
            (control2_req(0xfffe, 1), query_info(1)), (control2_req(8, 3), query_info(3)),
            (control2_req(9, 1), query_info(1)), (control2_req(5, 2, False), query_info(2, False))]


def auth23_req(flags, comp='WS01'):
    def f(w):
        n_logonsrv(w)
        w.align5()
        w.wstr(comp + '$', 'ref')
        w.u1632(2)
        w.align5()
        w.wstr(comp, 'ref')
        w.raw(b'\x88' * 8)
        w.align(4)
        w.buf += struct.pack('<I', flags)   # read little endian
    return f


def auth23_resp(flags, v3=False):
    def f(w):
        w.raw(b'\x99' * 8)
        w.buf += struct.pack('<I', flags)
        w.align(4)
        if v3:
            w.u32(1104)
        ntstatus(w)
    return f


FLAGS_ALL = 0xffffffff
FLAGS_AES = 0x612fffff
FLAGS_STRONG = 0x000047ff
FLAGS_DES = 0x000001ff


@call(15)
def op_authenticate2():
    return [(auth23_req(FLAGS_ALL), auth23_resp(FLAGS_ALL))]


@call(16)
def op_databasesync2():
    def req(w):
        w.wstr('\\\\DC1', 'ref')
        computer_ref(w, 'BDC1')
        auth_ref(w)
        auth_ref(w)
        w.u32(0)
        w.u16(1)
        w.u32(0)
        w.u32(0xffff)

    def resp(w):
        auth_ref(w)
        w.u32(3)
        w.ptr(lambda: n_delta_enum_array(w, [2, 8, 9, 12]))
        ntstatus(w)
    return [(req, resp)]


@call(17)
def op_databaseredo():
    def req(w):
        w.wstr('\\\\DC1', 'ref')
        computer_ref(w, 'BDC1')
        auth_ref(w)
        auth_ref(w)
        w.ptr(lambda: w.bytes_carray(b'CHANGELOG-ENTRY'), 'ref')
        w.u32(15)

    def resp(w):
        auth_ref(w)
        w.ptr(lambda: n_delta_enum_array(w, [14, 16, 18]))
        ntstatus(w)
    return [(req, resp)]


@call(18)
def op_logoncontrol2ex():
    return [(control2_req(5, 2), query_info(2)), (control2_req(0xfffe, 3), query_info(3))]


@call(19)
def op_enumtrusteddomains():
    def req(w):
        n_logonsrv(w)

    def resp(w):
        names = b'TRUSTED\0OTHER\0\0'

        def multi():
            w.u32(len(names))
            w.ptr(lambda: w.carray(list(names), w.u8))
        w.ptr(multi, 'ref')
        ntstatus(w)
    return [(req, resp)]


@call(20)
def op_dsrgetdcname():
    def req(r):
        def f(w):
            n_logonsrv(w)
            w.wstr('example.test' if r else None)
            w.ptr((lambda: w.guid(GUID1)) if r else None)
            w.ptr((lambda: w.guid(GUID2)) if r else None)
            w.u32(0xc003fff1 if r else 0)
        return f

    def resp(r):
        def f(w):
            w.ptr((lambda: n_dc_info(w, r)) if r is not None else None)
            ntstatus(w, 0 if r is not None else 0xc000005e)
        return f
    return [(req(True), resp(True)), (req(False), resp(False)), (req(True), resp(None))]


@call(21)
def op_getcapabilities():
    def req(level):
        def f(w):
            w.wstr('\\\\DC1', 'ref')
            w.wstr('WS01')
            auth_ref(w)
            auth_ref(w)
            w.u32(level)
        return f

    def resp(level):
        def f(w):
            auth_ref(w)

            def caps():
                w.u32(level)
                w.align(4)
                if level in (1, 2):
                    w.u32(0x612fffff)
            w.ptr(caps, 'ref')
            ntstatus(w)
        return f
    return [(req(1), resp(1)), (req(2), resp(2)), (req(3), resp(3))]


@call(22)
def op_setservicebits():
    def req(w):
        n_logonsrv(w)
        w.u32(0x2000)
        w.u32(0x2000)

    def resp(w):
        ntstatus(w)
    return [(req, resp)]


@call(23)
def op_gettrustrid():
    def req(w):
        n_logonsrv(w)
        w.wstr('example.test')

    def resp(w):
        w.ptr(lambda: w.u32(1104))
        ntstatus(w)
    return [(req, resp)]


@call(24)
def op_computeserverdigest():
    def req(w):
        n_logonsrv(w)
        w.u32(1104)
        w.bytes_ptr(b'MESSAGE-TO-DIGEST')
        w.u32(17)

    def resp(w):
        w.ptr(lambda: w.raw(bytes(range(0xd0, 0xe0))))
        ntstatus(w)
    return [(req, resp)]


@call(25)
def op_computeclientdigest():
    def req(w):
        n_logonsrv(w)
        w.wstr('example.test')
        w.bytes_ptr(b'MESSAGE')
        w.u32(7)

    def resp(w):
        w.ptr(lambda: w.raw(bytes(range(0xc0, 0xd0))))
        ntstatus(w)
    return [(req, resp)]


@call(26)
def op_authenticate3():
    return [(auth23_req(FLAGS_ALL), auth23_resp(FLAGS_ALL, True)),
            (auth23_req(0), auth23_resp(0, True))]


@call(27)
def op_dsrgetdcnameex():
    def req(w):
        n_logonsrv(w)
        w.wstr('example.test')
        w.ptr(lambda: w.guid(GUID1))
        w.wstr('Default-First-Site-Name')
        w.u32(0x40000010)

    def resp(w):
        w.ptr(lambda: n_dc_info(w))
        ntstatus(w)
    return [(req, resp)]


@call(28)
def op_dsrgetsitename():
    def req(w):
        n_logonsrv(w)

    def resp(w):
        w.ptr(lambda: w.cvstring('Default-First-Site-Name'))
        ntstatus(w)
    return [(req, resp)]


def workstation_buffer(level, r=True):
    def f(w):
        if w.ndr64:
            w.align5()
        w.u32(level)
        if w.ndr64:
            w.align5()
        if level in (1, 2):
            w.ptr((lambda: n_workstation_info(w, r)) if r is not None else None)
    return f


def domain_information(level, r=True):
    def f(w):
        if w.ndr64:
            w.align5()
        w.u32(level)
        if w.ndr64:
            w.align5()
        if level == 1:
            def dinfo():
                n_one_domain_info(w, r)
                n = 2 if r else 0
                w.u32(n)
                w.ptr((lambda: w.carray(['TRUSTED', 'OTHER'], lambda s: n_one_domain_info(w, True, s))) if r else None)
                n_lsa_policy_info(w, r)
                w.ustr('ws01.example.test' if r else None)
                for s in ('x2', 'x3', 'x4'):
                    w.ustr(s if r else None)
                for i in range(4):
                    w.u32(i)
            w.ptr(dinfo)
        elif level == 2:
            w.ptr(lambda: n_lsa_policy_info(w, r))
    return f


@call(29)
def op_getdomaininfo():
    def req(level, r=True):
        def f(w):
            w.wstr('\\\\DC1', 'ref')
            w.wstr('WS01')
            auth_ref(w)
            auth_ref(w)
            w.u32(level)
            w.ptr(lambda: workstation_buffer(level, r)(w), 'ref')
        return f

    def resp(level, r=True):
        def f(w):
            auth_ref(w)
            w.ptr(lambda: domain_information(level, r)(w), 'ref')
            ntstatus(w)
        return f
    return [(req(1), resp(1)), (req(2), resp(2)), (req(1, False), resp(1, False)),
            (req(1, None), resp(3))]


def crypt_password(w, kind):
    """netr_CryptPassword: 512 octets and the password length. 'plain'
    is a cleartext buffer with the password version, 'plainnov' one
    without, 'enc' an (opaque) encrypted buffer."""
    if kind == 'enc':
        w.raw(bytes((i * 37 + 11) & 0xff for i in range(512)))
        w.buf += struct.pack(w.e + 'I', 0x9e3779b1)
        return
    pw = 'S3cret-Passw0rd'.encode('utf-16-le' if w.le else 'utf-16-be')
    conf_len = 512 - len(pw)
    conf = bytearray((i * 13 + 5) & 0xff for i in range(conf_len))
    if kind == 'plain':
        conf[conf_len - 12:] = struct.pack(w.e + 'III', 0, 3, 0x02231968)
    w.raw(bytes(conf) + pw)
    w.buf += struct.pack(w.e + 'I', len(pw))


@call(30)
def op_passwordset2():
    def req(kind):
        def f(w):
            auth_req(w)
            auth_ref(w)
            crypt_password(w, kind)
        return f

    def resp(w):
        auth_ref(w)
        ntstatus(w)
    return [(req('plain'), resp), (req('plainnov'), resp), (req('enc'), resp)]


@call(31)
def op_passwordget():
    def req(w):
        n_logonsrv(w)
        w.wstr('BDC1$')
        w.u1632(4)
        w.wstr('BDC1')
        auth_ref(w)

    def resp(w):
        auth_ref(w)
        w.ptr(lambda: w.raw(bytes(range(0x40, 0x50))), 'ref')
        ntstatus(w)
    return [(req, resp)]


@call(32)
def op_sendtosam():
    def req(data):
        def f(w):
            n_logonsrv(w)
            computer_ref(w, 'RODC1')
            auth_ref(w)
            w.ptr(lambda: w.bytes_carray(data), 'ref')
            w.u32(len(data))
        return f

    def resp(w):
        auth_ref(w)
        ntstatus(w)
    return [(req(bytes(range(0x30, 0x50))), resp), (req(b'\x01\x02\x03'), resp)]


def sockaddr_req(addrs):
    def f(w):
        n_logonsrv(w)
        w.u32(len(addrs))

        def one(a):
            w.ptr(lambda: w.bytes_carray(a))
            w.u32(len(a))
        w.ptr(lambda: w.carray(addrs, one), 'ref')
    return f


SA_IN = struct.pack('<HH', 2, 0) + bytes([192, 0, 2, 70]) + bytes(8)
SA_IN6 = struct.pack('<HHI', 0x17, 0, 0) + bytes.fromhex('20010db8000000000000000000000070') + bytes(4)
SA_OTHER = struct.pack('<HH', 0x11, 0) + bytes(12)


def site_names_resp(names):
    def f(w):
        def arr():
            w.u32(len(names))
            w.ptr(lambda: w.carray(names, lambda s: w.ustr(s)))
        w.ptr(lambda: w.ptr(arr), 'ref')
        ntstatus(w)
    return f


@call(33)
def op_addresstositenames():
    return [(sockaddr_req([SA_IN]), site_names_resp(['Default-First-Site-Name'])),
            (sockaddr_req([SA_IN6]), site_names_resp(['Branch-Site'])),
            (sockaddr_req([SA_OTHER]), site_names_resp([None]))]


@call(34)
def op_dsrgetdcnameex2():
    def req(w):
        n_logonsrv(w)
        w.wstr('WS01$')
        w.u32(0x80)
        w.wstr('example.test')
        w.ptr(lambda: w.guid(GUID1))
        w.wstr('Default-First-Site-Name')
        w.u32(0x40001000)

    def resp(w):
        w.ptr(lambda: n_dc_info(w))
        ntstatus(w)
    return [(req, resp)]


@call(35)
def op_gettimeserviceparentdomain():
    def req(w):
        n_logonsrv(w)

    def resp(w):
        w.wstr('example.test')
        w.ptr(lambda: w.u32(1))
        ntstatus(w)
    return [(req, resp)]


def trusts_resp(trusts):
    def f(w):
        w.u32(len(trusts))
        w.ptr((lambda: w.carray(trusts, lambda t: n_ds_domain_trust(w, t))) if trusts else None)
        ntstatus(w)
    return f


@call(36)
def op_enumtrusteddomainsex():
    def req(w):
        n_logonsrv(w)
    return [(req, trusts_resp(TRUSTS)), (req, trusts_resp([]))]


@call(37)
def op_addresstositenamesex():
    def resp(w):
        def arr():
            sites = ['Default-First-Site-Name', 'Branch-Site']
            subnets = ['192.0.2.0/24', None]
            w.u32(len(sites))
            w.ptr(lambda: w.carray(sites, lambda s: w.ustr(s)))
            w.ptr(lambda: w.carray(subnets, lambda s: w.ustr(s)))
        w.ptr(lambda: w.ptr(arr), 'ref')
        ntstatus(w)
    return [(sockaddr_req([SA_IN]), resp)]


@call(38)
def op_getdcsitecoverage():
    def req(w):
        n_logonsrv(w)

    def resp(w):
        def names():
            s = ['Default-First-Site-Name', 'Branch-Site']
            w.u32(len(s))
            w.ptr(lambda: w.carray(s, lambda x: w.ustr(x)))
        w.ptr(names)
        ntstatus(w)
    return [(req, resp)]


def samlogonex_req(level, r=True, flags=0x2):
    def f(w):
        w.wstr('\\\\DC1')
        w.wstr('WS01')
        w.u16(level)
        w.ptr(lambda: n_level(w, level, r), 'ref')
        w.u16(6)
        w.u32(flags)
    return f


def samlogonex_resp(level, r=True, flags=0x2):
    def f(w):
        w.ptr(lambda: n_validation(w, level, r), 'ref')
        w.u8(1)
        w.u32(flags)
        ntstatus(w)
    return f


@call(39)
def op_samlogonex():
    return [(samlogonex_req(2), samlogonex_resp(6)),
            (samlogonex_req(8), samlogonex_resp(7)),
            (samlogonex_req(4, False, 0x3c), samlogonex_resp(5, False, 0x3c))]


@call(40)
def op_dsrenumeratedomaintrusts():
    def req(w):
        n_logonsrv(w)
        w.u32(0x3f)
    return [(req, trusts_resp(TRUSTS))]


@call(41)
def op_deregisterdnshostrecords():
    def req(w):
        n_logonsrv(w)
        w.wstr('example.test')
        w.ptr(lambda: w.guid(GUID1))
        w.ptr(lambda: w.guid(GUID2))
        w.wstr('dc2.example.test', 'ref')

    def resp(w):
        ntstatus(w)
    return [(req, resp)]


@call(42)
def op_trustpasswordsget():
    def req(w):
        auth_req(w, 'BDC1$', 6, 'BDC1')
        auth_ref(w)

    def resp(w):
        auth_ref(w)
        w.ptr(lambda: w.raw(bytes(range(0x50, 0x60))), 'ref')
        w.ptr(lambda: w.raw(bytes(range(0x60, 0x70))), 'ref')
        ntstatus(w)
    return [(req, resp)]


@call(43)
def op_dsrgetforesttrustinfo():
    def req(w):
        n_logonsrv(w)
        w.wstr('trusted.test')
        w.u32(1)

    def resp(r):
        def f(w):
            w.ptr(lambda: lsa_forest_trust_info(w, r))
            w.u32(0)
        return f
    return [(req, resp(True)), (req, resp(False))]


@call(44)
def op_netrgetforesttrustinfo():
    def req(w):
        n_logonsrv(w)
        computer_ref(w, 'DC2')
        auth_ref(w)
        w.u32(0)

    def resp(w):
        auth_ref(w)
        w.ptr(lambda: lsa_forest_trust_info(w))
        ntstatus(w)
    return [(req, resp)]


@call(45)
def op_samlogonwithflags():
    return [(samlogon_req(1, flags=0x1), samlogon_resp(3, flags=0x1)),
            (samlogon_req(6, flags=0x2), samlogon_resp(6, flags=0x2)),
            (samlogon_req(5, flags=0), samlogon_resp(2, flags=0))]


@call(46)
def op_servergettrustinfo():
    def req(w):
        auth_req(w, 'TRUSTED$', 2, 'DC1')
        auth_ref(w)

    def resp(r):
        def f(w):
            auth_ref(w)
            w.ptr(lambda: w.raw(bytes(range(0x50, 0x60))), 'ref')
            w.ptr(lambda: w.raw(bytes(range(0x60, 0x70))), 'ref')

            def gen():
                attrs = [0x8, 0x20]
                w.u32(len(attrs))
                w.ptr(lambda: w.carray(attrs, w.u32))
                strs = ['one', 'two']
                w.u32(len(strs))
                w.ptr(lambda: w.carray(strs, lambda s: w.ustr(s)))
            w.ptr(gen if r else (lambda: (w.u32(0), w.ptr(None), w.u32(0), w.ptr(None))))
            ntstatus(w)
        return f
    MALFORMED_CALLS.append((46, req, resp(True)))
    return [(req, resp(False))]


@call(48)
def op_updatereadonlydns():
    """DsrUpdateReadOnlyServerDnsRecords: no dissector for the stub."""
    def req(w):
        w.raw(b'\x00' * 16)

    def resp(w):
        w.raw(b'\x00' * 8)
    return [(req, resp)]


@call(54)
def op_chainsetclientattributes():
    def req(w):
        w.wstr('\\\\DC1', 'ref')
        w.wstr('RODC1', 'ref')
        w.wstr('WS01', 'ref')
        auth_ref(w)
        auth_ref(w)
        w.u32(1)
        w.u32(1)

    def resp(w):
        auth_ref(w)
        w.u32(1)
        ntstatus(w)
    return [(req, resp)]


@call(59)
def op_authenticatekerberos():
    def req(w):
        n_logonsrv(w)
        w.align5()
        w.wstr('WS02$', 'ref')
        w.u1632(2)
        w.align5()
        w.wstr('WS02', 'ref')
        w.align(4)
        w.buf += struct.pack('<I', FLAGS_AES)

    def resp(w):
        w.buf += struct.pack('<I', FLAGS_AES)
        w.align(4)
        w.u32(1105)
        ntstatus(w)
    return [(req, resp)]


# ------------------------------------------------------------------ captures
def stubs(req, resp, le, ndr64):
    w = W(le, ndr64)
    req(w)
    r = W(le, ndr64)
    resp(r)
    return bytes(w.buf), bytes(r.buf)


def connection(frames, cport, le, ndr64, calls, cip, sip, extras=None, cut=False):
    tcp = TCP(frames, cport, cip=cip, sip=sip)
    rpc = RPC(tcp, le, ndr64)
    rpc.bind()
    for opnum, req, resp in calls:
        q, a = stubs(req, resp, le, ndr64)
        if cut:
            q, a = q[:len(q) * 2 // 3], a[:len(a) * 2 // 3]
        rpc.call(opnum, q, a)
    if extras:
        extras(rpc)
    tcp.fin()


def mscldap_name(name):
    return b''.join(bytes([len(x)]) + x.encode() for x in name.split('.')) + b'\0'


def nl_auth_message(e, mtype, flags):
    """NL_AUTH_MESSAGE: type, flags and the names the flags select."""
    b = struct.pack(e + 'II', mtype, flags)
    if flags & 1:
        b += b'EXAMPLE\0'
    if flags & 2:
        b += b'WS01\0'
    if flags & 4:
        b += mscldap_name('example.test')
    if flags & 8:
        b += mscldap_name('ws01.example.test')
    if flags & 0x10:
        b += mscldap_name('WS01')
    return b


def nl_auth_signature(signalg, sealalg, flags, seq, digest, nonce=None):
    """NL_AUTH_SIGNATURE / NL_AUTH_SHA2_SIGNATURE with arbitrary values."""
    b = struct.pack('<HHHH', signalg, sealalg, 0xffff, flags) + seq + digest
    if nonce is not None:
        b += nonce
    return b


# The NT password the dissector must be given (cfg/ntlmssp_creds) for the
# keyed secure channel. Nothing else in the capture matches it.
NT_PASSWORD = 'SchannelCover'

SIGN_MD5, SIGN_SHA256 = 0x0077, 0x0013
SEAL_NONE, SEAL_RC4, SEAL_AES = 0xffff, 0x007a, 0x001a
AUTH_INTEGRITY, AUTH_PRIVACY = 5, 6

_gcry = None


def gcrypt():
    """libgcrypt, initialised the way the dissector's ciphers are."""
    global _gcry
    if _gcry is not None:
        return _gcry
    g = ctypes.CDLL('libgcrypt.so.20')
    g.gcry_check_version.argtypes = [ctypes.c_char_p]
    g.gcry_check_version.restype = ctypes.c_char_p
    g.gcry_control.argtypes = [ctypes.c_int, ctypes.c_int]
    g.gcry_control.restype = ctypes.c_int
    g.gcry_cipher_open.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_int,
                                   ctypes.c_int, ctypes.c_uint]
    g.gcry_cipher_open.restype = ctypes.c_uint
    for name in ('gcry_cipher_setkey', 'gcry_cipher_setiv'):
        fn = getattr(g, name)
        fn.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
        fn.restype = ctypes.c_uint
    for name in ('gcry_cipher_encrypt', 'gcry_cipher_decrypt'):
        fn = getattr(g, name)
        fn.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                       ctypes.c_char_p, ctypes.c_size_t]
        fn.restype = ctypes.c_uint
    g.gcry_cipher_close.argtypes = [ctypes.c_void_p]
    g.gcry_md_get_algo_dlen.argtypes = [ctypes.c_int]
    g.gcry_md_get_algo_dlen.restype = ctypes.c_uint
    g.gcry_md_hash_buffer.argtypes = [ctypes.c_int, ctypes.c_char_p,
                                      ctypes.c_char_p, ctypes.c_size_t]
    g.gcry_md_open.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_int, ctypes.c_uint]
    g.gcry_md_open.restype = ctypes.c_uint
    g.gcry_md_setkey.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    g.gcry_md_setkey.restype = ctypes.c_uint
    g.gcry_md_write.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    g.gcry_md_read.argtypes = [ctypes.c_void_p, ctypes.c_int]
    g.gcry_md_read.restype = ctypes.POINTER(ctypes.c_ubyte)
    g.gcry_md_close.argtypes = [ctypes.c_void_p]
    if not g.gcry_check_version(b'1.8.0'):
        raise RuntimeError('libgcrypt >= 1.8.0 is required')
    g.gcry_control(37, 0)  # GCRYCTL_DISABLE_SECMEM
    g.gcry_control(38, 0)  # GCRYCTL_INITIALIZATION_FINISHED
    _gcry = g
    return g


def _gcry_crypt(algo, mode, key, iv, data):
    g = gcrypt()
    hd = ctypes.c_void_p()
    err = g.gcry_cipher_open(ctypes.byref(hd), algo, mode, 0)
    if err:
        raise RuntimeError('gcry_cipher_open %s' % err)
    try:
        if iv is not None:
            err = g.gcry_cipher_setiv(hd, iv, len(iv))
            if err:
                raise RuntimeError('gcry_cipher_setiv %s' % err)
        err = g.gcry_cipher_setkey(hd, key, len(key))
        if err:
            raise RuntimeError('gcry_cipher_setkey %s' % err)
        out = ctypes.create_string_buffer(len(data))
        err = g.gcry_cipher_encrypt(hd, out, len(data), data, len(data))
        if err:
            raise RuntimeError('gcry_cipher_encrypt %s' % err)
        return out.raw
    finally:
        g.gcry_cipher_close(hd)


def aes_cfb8_encrypt(key, iv, data):
    return _gcry_crypt(7, 12, key, iv, data)  # AES, CFB8


def rc4_crypt(key, data):
    return _gcry_crypt(301, 4, key, None, data)  # ARCFOUR, stream


def des_ecb_7(data, key56):
    """crypt_des_ecb: expand a 7-octet key and encrypt one block."""
    k = key56
    key64 = bytes([
        k[0],
        ((k[0] << 7) | (k[1] >> 1)) & 0xff,
        ((k[1] << 6) | (k[2] >> 2)) & 0xff,
        ((k[2] << 5) | (k[3] >> 3)) & 0xff,
        ((k[3] << 4) | (k[4] >> 4)) & 0xff,
        ((k[4] << 3) | (k[5] >> 5)) & 0xff,
        ((k[5] << 2) | (k[6] >> 6)) & 0xff,
        (k[6] << 1) & 0xff,
    ])
    return _gcry_crypt(302, 1, key64, None, data)  # DES, ECB


def md4(data):
    g = gcrypt()
    out = ctypes.create_string_buffer(g.gcry_md_get_algo_dlen(301))
    g.gcry_md_hash_buffer(301, out, data, len(data))
    return out.raw


def hmac_buf(algo, key, data):
    g = gcrypt()
    hd = ctypes.c_void_p()
    err = g.gcry_md_open(ctypes.byref(hd), algo, 2)  # GCRY_MD_FLAG_HMAC
    if err:
        raise RuntimeError('gcry_md_open %s' % err)
    try:
        err = g.gcry_md_setkey(hd, key, len(key))
        if err:
            raise RuntimeError('gcry_md_setkey %s' % err)
        g.gcry_md_write(hd, data, len(data))
        p = g.gcry_md_read(hd, algo)
        n = g.gcry_md_get_algo_dlen(algo)
        return bytes(p[:n])
    finally:
        g.gcry_md_close(hd)


def nt_hash(password=NT_PASSWORD):
    return md4(password.encode('utf-16-le'))


def session_aes(nth, client, server):
    """AES session key and the ServerAuthenticate credential for it."""
    key = hmac_buf(8, nth, client + server)[:16]  # SHA-256, truncated
    cred = aes_cfb8_encrypt(key, b'\0' * 16, server)
    return key, cred


def session_strong(nth, client, server):
    """STRONGKEY (MD5 + DES) session key and credential."""
    # MD5(zeros || client || server), then HMAC-MD5 over that with the NT hash.
    g = gcrypt()
    md5 = ctypes.create_string_buffer(16)
    block = b'\0' * 4 + client + server
    g.gcry_md_hash_buffer(1, md5, block, len(block))
    key = hmac_buf(1, nth, md5.raw)
    step = des_ecb_7(server, key[:7])
    cred = des_ecb_7(step, key[7:14])
    return key, cred


def session_des(nth, client, server):
    """DES session key (no AES, no STRONGKEY) and credential."""
    c = int.from_bytes(client, 'little')
    s = int.from_bytes(server, 'little')
    total = ((c + s) & 0xffffffff) | ((((c >> 32) + (s >> 32)) & 0xffffffff) << 32)
    summed = total.to_bytes(8, 'little')
    step = des_ecb_7(summed, nth[:7])
    key8 = des_ecb_7(step, nth[9:16])
    key = key8 + b'\0' * 8
    step = des_ecb_7(server, key[:7])
    cred = des_ecb_7(step, key[7:14])
    return key, cred


def secchan_connection(frames, cport, cip, sip, le=True):
    """A bind with the SEC_CHAN (68) auth type and NL_AUTH_MESSAGEs, then
    requests and responses with secure channel verifiers. No session key
    is known for these addresses, so nothing is decrypted."""
    tcp = TCP(frames, cport, cip=cip, sip=sip)
    rpc = RPC(tcp, le, False)
    e = rpc.e
    rpc.bind(auth=((68, 5, nl_auth_message(e, 0, 0x1f)), (68, 5, nl_auth_message(e, 1, 0) + b'\0' * 4)))

    def stub(fn):
        w = W(le, False)
        fn(w)
        return bytes(w.buf)
    caps_req = [c for c in CALLS if c[0] == 21][0]
    q, a = stub(caps_req[1]), stub(caps_req[2])
    # The fix "Dissect every secure channel verifier": two requests, each
    # with a verifier, in one TCP segment.
    pdus = b''
    for seq in (0x11, 0x22):
        rpc.call_id += 1
        sig = nl_auth_signature(0x0077, 0xffff, 0, struct.pack('<Q', seq),
                                bytes(range(0xa0 + seq % 16, 0xa8 + seq % 16)), bytes(range(8)))
        pdus += rpc.request_pdu(21, q, auth=(68, 5, sig))
    tcp.send(True, pdus)
    resp = b''
    for i, cid in enumerate((rpc.call_id - 1, rpc.call_id)):
        sig = nl_auth_signature(0x0077, 0xffff, 0x0080 if i else 0, struct.pack('<Q', 0x33 + i),
                                bytes(range(0x10, 0x18)), bytes(range(0x20, 0x28)))
        p = rpc.pdu(2, struct.pack(e + 'IHBB', len(a), 0, 0, 0) + a, cid, auth=(68, 5, sig))
        resp += p
    tcp.send(False, resp)
    # HMAC-SHA256 / AES-128 signature without the confounder (integrity)
    rpc.call_id += 1
    sig = nl_auth_signature(0x0013, 0xffff, 0, struct.pack('<Q', 0x44), b'\x55' * 8)
    tcp.send(True, rpc.request_pdu(21, q, auth=(68, 5, sig)))
    tcp.send(False, rpc.response_pdu(a, auth=(68, 5, nl_auth_signature(0x0013, 0xffff, 0, struct.pack('<Q', 0x45), b'\x56' * 8))))
    # Privacy level: the stub is sealed (opaque here), RC4 and AES-128
    for signalg, sealalg in ((0x0077, 0x007a), (0x0013, 0x001a)):
        rpc.call_id += 1
        sealed = bytes((i * 29 + 3) & 0xff for i in range(len(q)))
        tcp.send(True, rpc.request_pdu(21, sealed, auth=(68, 6, nl_auth_signature(
            signalg, sealalg, 0, b'\x61' * 8, b'\x62' * 8, b'\x63' * 8))))
        sealed = bytes((i * 31 + 7) & 0xff for i in range(len(a)))
        tcp.send(False, rpc.response_pdu(sealed, auth=(68, 6, nl_auth_signature(
            signalg, sealalg, 0, b'\x64' * 8, b'\x65' * 8, b'\x66' * 8))))
    tcp.fin()


def alter_context_nl_auth(rpc):
    """An alter context with SEC_CHAN NL_AUTH_MESSAGEs and no requests
    after it: with a session key known for the addresses (the zero key of
    NetrServerAuthenticateKerberos) the schannel state is set up, but no
    verifier or sealed data follows, so nothing is decrypted."""
    rpc.call_id += 1
    e = rpc.e
    body = struct.pack(e + 'HHI', 4280, 4280, 0x12345) + struct.pack(e + 'B3x', 1)
    body += struct.pack(e + 'HBx', 1, 1) + rpc.uuid_bytes(UUID_NETLOGON) + struct.pack(e + 'I', 1)
    body += rpc.uuid_bytes(UUID_NDR) + struct.pack(e + 'I', 2)
    rpc.tcp.send(True, rpc.pdu(14, body, rpc.call_id, auth=(68, 5, nl_auth_message(e, 0, 0x3))))
    body = struct.pack(e + 'HHI', 4280, 4280, 0x12345) + struct.pack(e + 'H', 0) + b'\0\0'
    body += struct.pack(e + 'B3x', 1) + struct.pack(e + 'HH', 0, 0)
    body += rpc.uuid_bytes(UUID_NDR) + struct.pack(e + 'I', 2)
    rpc.tcp.send(False, rpc.pdu(15, body, rpc.call_id, auth=(68, 5, nl_auth_message(e, 1, 0))))


def le_extras(rpc):
    """Calls only in the little endian NDR32 connection, after
    NetrServerAuthenticateKerberos (the last of CALLS) has given the
    addresses a (zero) session key."""
    def do(opnum, req, resp, maxfrag=1 << 20):
        q, a = stubs(req, resp, True, False)
        rpc.call(opnum, q, a, maxfrag)
    # NETWORK_INFO with only an account name, and a 10 kB NTLMv2 response
    # in fragmented PDUs
    do(2, samlogon_req(2, r='acct'), samlogon_resp(2, r=False))
    do(2, samlogon_req(2, v2='big'), samlogon_resp(2, r=False), maxfrag=4000)
    # a cleartext netr_CryptPassword now that a key is known
    auth_req_pw = [c for c in CALLS if c[0] == 30][0]
    do(30, auth_req_pw[1], auth_req_pw[2])
    do(30, passwordset2_version_req, auth_req_pw[2])
    # a new challenge after an authenticated one
    reqchal = [c for c in CALLS if c[0] == 4][0]
    do(4, reqchal[1], reqchal[2])
    do(15, auth23_req(FLAGS_STRONG), auth23_resp(FLAGS_STRONG))
    do(26, auth23_req(FLAGS_DES), auth23_resp(FLAGS_DES, True))
    alter_context_nl_auth(rpc)


def passwordset2_version_req(w):
    """A cleartext netr_CryptPassword with NL_PASSWORD_VERSION. The
    dissector looks for the version 12 octets before the password but at
    that offset from the start of the stub, not of the buffer (an
    observation, see the README); the markers are put at both places."""
    auth_req(w)
    auth_ref(w)
    start = len(w.buf)
    # 16 characters: the version is then 4-aligned in the stub, as the
    # dissector reads it with dissect_ndr_uint32
    pw = 'S3cret-Passw0rd!'.encode('utf-16-le')
    conf_len = 512 - len(pw)
    buf = bytearray((i * 13 + 5) & 0xff for i in range(512))
    voff = conf_len - 12
    buf[voff - start:voff - start + 12] = struct.pack('<III', 0, 0, 0x02231968)
    buf[conf_len - 12:conf_len] = struct.pack('<III', 0, 3, 0x02231968)
    buf[conf_len:] = pw
    w.raw(bytes(buf))
    w.buf += struct.pack('<I', len(pw))


def seal_key(session_key):
    return bytes(b ^ 0xf0 for b in session_key)


def encrypt_sequence(session_key, aes, seq, checksum):
    """Ciphertext of the 8-octet sequence, as uncrypt_sequence reverses it."""
    plain = struct.pack('<Q', seq)
    if aes:
        return aes_cfb8_encrypt(session_key, checksum + checksum, plain)
    step = hmac_buf(1, session_key, b'\0' * 4)
    key = hmac_buf(1, step, checksum)
    return rc4_crypt(key, plain)


def encrypt_privacy(session_key, aes, seq, confounder, stub):
    """Encrypted confounder and stub, as dissect_packet_data decrypts them.

    AES-CFB8 decrypts the confounder and then the stub without resetting,
    so the stub's keystream starts eight octets in. RC4 resets between
    the two, so each is a fresh keystream.
    """
    ekey = seal_key(session_key)
    seq_b = struct.pack('<Q', seq)
    if aes:
        blob = aes_cfb8_encrypt(ekey, seq_b + seq_b, confounder + stub)
        return blob[:8], blob[8:]
    step = hmac_buf(1, ekey, b'\0' * 4)
    key = hmac_buf(1, step, seq_b)
    return rc4_crypt(key, confounder), rc4_crypt(key, stub)


def schannel_exchange(rpc, ctx, level, aes, session_key, seq, checksum, nonce, plain):
    """One GetCapabilities request and its response on a secure channel.

    plain is (request stub, response stub). With a non-zero session key
    and packet privacy, both stubs are sealed so the dissector decrypts
    them back. A zero session key leaves the stubs in the clear: the
    seal key is refused and the plaintext still dissects.
    """
    signalg = SIGN_SHA256 if aes else SIGN_MD5
    sealalg = SEAL_NONE if level == AUTH_INTEGRITY else (SEAL_AES if aes else SEAL_RC4)
    if level == AUTH_PRIVACY and any(session_key):
        conf = nonce if nonce is not None else b'\0' * 8
        enc_seq = encrypt_sequence(session_key, aes, seq, checksum)
        enc_conf_q, q = encrypt_privacy(session_key, aes, seq, conf, plain[0])
        enc_seq_r = encrypt_sequence(session_key, aes, seq + 1, checksum)
        enc_conf_r, r = encrypt_privacy(session_key, aes, seq + 1, conf, plain[1])
        nq = enc_conf_q if nonce is not None else None
        nr = enc_conf_r if nonce is not None else None
        sig_q = nl_auth_signature(signalg, sealalg, 0, enc_seq, checksum, nq)
        sig_r = nl_auth_signature(signalg, sealalg, 0, enc_seq_r, checksum, nr)
    else:
        q, r = plain
        enc_seq = encrypt_sequence(session_key, aes, seq, checksum)
        enc_seq_r = encrypt_sequence(session_key, aes, seq + 1, checksum)
        sig_q = nl_auth_signature(signalg, sealalg, 0, enc_seq, checksum, nonce)
        sig_r = nl_auth_signature(signalg, sealalg, 0, enc_seq_r, checksum, nonce)
    rpc.call_id += 1
    rpc.tcp.send(True, rpc.request_pdu(21, q, auth=(68, level, sig_q, ctx)))
    rpc.tcp.send(False, rpc.response_pdu(r, auth=(68, level, sig_r, ctx)))


def kerberos_call(comp, flags):
    def req(w):
        n_logonsrv(w)
        w.align5()
        w.wstr(comp + '$', 'ref')
        w.u1632(2)
        w.align5()
        w.wstr(comp, 'ref')
        w.align(4)
        w.buf += struct.pack('<I', flags)

    def resp(w):
        w.buf += struct.pack('<I', flags)
        w.align(4)
        w.u32(1105)
        ntstatus(w)
    return req, resp


def challenge_call(comp, client, server):
    def req(w):
        n_logonsrv(w)
        computer_ref(w, comp)
        w.raw(client)

    def resp(w):
        w.raw(server)
        ntstatus(w)
    return req, resp


def authenticate_call(comp, flags, cred, v3=False):
    return auth23_req(flags, comp), auth23_resp_cred(flags, cred, v3)


def auth23_resp_cred(flags, cred, v3=False):
    def f(w):
        w.raw(cred)
        w.buf += struct.pack('<I', flags)
        w.align(4)
        if v3:
            w.u32(1104)
        ntstatus(w)
    return f


def do_call(rpc, opnum, req, resp):
    q, a = stubs(req, resp, True, False)
    rpc.call(opnum, q, a)


def keyed_schannel_connection(frames, cport, cip, sip):
    """Every secure channel cipher the dissector implements.

    Two NetrServerAuthenticateKerberos calls leave a zero session key,
    one with the AES flag and one without, so uncrypt_sequence runs both
    ways and get_seal_key refuses the key. Then ServerAuthenticate2/3
    with credentials of NT_PASSWORD install a real AES key, a STRONGKEY
    and a DES key. The verifiers after each of those are HMAC-SHA256 or
    HMAC-MD5 at integrity, and AES-128 or RC4 at privacy. Integrity is
    sent with and without a confounder. RC4 privacy is too; AES privacy
    is only sent with one, because a missing confounder is decrypted as
    eight zero ciphertext bytes rather than as eight zero plaintext bytes.
    """
    nth = nt_hash()
    aes_c, aes_s = struct.pack('<Q', 0x1111111111111111), struct.pack('<Q', 0x2222222222222222)
    md5_c, md5_s = struct.pack('<Q', 0x3333333333333333), struct.pack('<Q', 0x4444444444444444)
    des_c, des_s = struct.pack('<Q', 0x5555555555555555), struct.pack('<Q', 0x6666666666666666)
    aes_key, aes_cred = session_aes(nth, aes_c, aes_s)
    md5_key, md5_cred = session_strong(nth, md5_c, md5_s)
    des_key, des_cred = session_des(nth, des_c, des_s)
    if not any(aes_key) or not any(md5_key) or not any(des_key):
        raise RuntimeError('a derived session key is all zeros')

    tcp = TCP(frames, cport, cip=cip, sip=sip)
    rpc = RPC(tcp, True, False)
    rpc.bind()
    caps = [c for c in CALLS if c[0] == 21][0]
    plain = stubs(caps[1], caps[2], True, False)
    nonce = bytes(range(0x80, 0x88))
    digest = bytes(range(0x90, 0x98))

    # Zero session key, AES flag, then the same with no AES flag.
    do_call(rpc, 59, *kerberos_call('SCHZAES', FLAGS_AES))
    schannel_exchange(rpc, 1, AUTH_INTEGRITY, True, b'\0' * 16, 0x101, digest, nonce, plain)
    schannel_exchange(rpc, 1, AUTH_PRIVACY, True, b'\0' * 16, 0x102, digest, nonce, plain)
    do_call(rpc, 59, *kerberos_call('SCHZMD5', FLAGS_STRONG))
    schannel_exchange(rpc, 2, AUTH_INTEGRITY, False, b'\0' * 16, 0x201, digest, nonce, plain)
    schannel_exchange(rpc, 2, AUTH_PRIVACY, False, b'\0' * 16, 0x202, digest, nonce, plain)

    # Real keys. Each auth context is first used after its authenticate,
    # so it copies that session key and those flags.
    do_call(rpc, 4, *challenge_call('SCHAES', aes_c, aes_s))
    do_call(rpc, 15, *authenticate_call('SCHAES', FLAGS_AES, aes_cred))
    schannel_exchange(rpc, 3, AUTH_INTEGRITY, True, aes_key, 0x301, digest, nonce, plain)
    schannel_exchange(rpc, 3, AUTH_INTEGRITY, True, aes_key, 0x302, digest, None, plain)
    schannel_exchange(rpc, 3, AUTH_PRIVACY, True, aes_key, 0x303, digest, nonce, plain)

    do_call(rpc, 4, *challenge_call('SCHMD5', md5_c, md5_s))
    do_call(rpc, 15, *authenticate_call('SCHMD5', FLAGS_STRONG, md5_cred))
    schannel_exchange(rpc, 4, AUTH_INTEGRITY, False, md5_key, 0x401, digest, nonce, plain)
    schannel_exchange(rpc, 4, AUTH_PRIVACY, False, md5_key, 0x402, digest, nonce, plain)
    schannel_exchange(rpc, 4, AUTH_PRIVACY, False, md5_key, 0x403, digest, None, plain)

    do_call(rpc, 4, *challenge_call('SCHDES', des_c, des_s))
    do_call(rpc, 26, *authenticate_call('SCHDES', FLAGS_DES, des_cred, True))
    schannel_exchange(rpc, 5, AUTH_INTEGRITY, False, des_key, 0x501, digest, nonce, plain)
    schannel_exchange(rpc, 5, AUTH_PRIVACY, False, des_key, 0x502, digest, nonce, plain)
    tcp.fin()


def session_key_crypt(session_key, aes, data):
    """prepare_session_key_cipher: AES-128-CFB8 with a zero IV, or RC4
    of the whole buffer with the session key itself."""
    if aes:
        return aes_cfb8_encrypt(session_key, b'\0' * 16, data)
    return rc4_crypt(session_key, data)


def crypt_password_blob(session_key, aes, pw_len, password=b''):
    """516 octets as netlogon_dissect_netr_CryptPassword decrypts them.

    password sits at the end of the 512-octet buffer and pw_len is the
    uint32 after it. A length above 500 or with bit 0 set is what makes
    the dissector try to decrypt. session_key None leaves the bytes as
    they are, for a key the dissector has no cipher for.
    """
    buf = bytearray(516)
    if password:
        buf[512 - len(password):512] = password
    struct.pack_into('<I', buf, 512, pw_len & 0xffffffff)
    if session_key is None:
        return bytes(buf)
    return session_key_crypt(session_key, aes, bytes(buf))


def opaque_blob(session_key, aes, size, declared):
    """OpaqueBuffer plaintext: the uint32 at offset 4 must equal
    size - 8 or the dissector reports the key unusable."""
    buf = bytearray(size)
    buf[8:16] = b'OPAQUE!!'
    struct.pack_into('<I', buf, 4, declared & 0xffffffff)
    if session_key is None:
        return bytes(buf)
    return session_key_crypt(session_key, aes, bytes(buf))


def passwordset2_req(blob):
    def f(w):
        auth_req(w, acct='PW$', comp='PW')
        auth_ref(w)
        w.raw(blob)
    return f


def passwordset2_resp(w):
    auth_ref(w)
    ntstatus(w)


def sendtosam_req(data):
    def f(w):
        n_logonsrv(w)
        computer_ref(w, 'PW')
        auth_ref(w)
        w.ptr(lambda: w.bytes_carray(data), 'ref')
        w.u32(len(data))
    return f


def sendtosam_resp(w):
    auth_ref(w)
    ntstatus(w)


def buffer_key_connection(frames, cport, cip, sip):
    """Session-key decryption of netr_CryptPassword and OpaqueBuffer.

    A verifier sits between ServerReqChallenge and ServerAuthenticate2.
    On the first pass that reply has not set auth_fd_num yet, so the
    lookup skips the entry. On the second pass the frame number is still
    before auth_fd_num and find_global_netlogon_auth_vars stops there.
    AES and STRONGKEY then decrypt a real buffer and one whose plaintext
    length is unusable. DES has neither flag, so prepare_session_key_cipher
    fails and the buffers stay encrypted.
    """
    nth = nt_hash()
    aes_c = struct.pack('<Q', 0x1010101010101010)
    aes_s = struct.pack('<Q', 0x2020202020202020)
    md5_c = struct.pack('<Q', 0x3030303030303030)
    md5_s = struct.pack('<Q', 0x4040404040404040)
    des_c = struct.pack('<Q', 0x5050505050505050)
    des_s = struct.pack('<Q', 0x6060606060606060)
    aes_key, aes_cred = session_aes(nth, aes_c, aes_s)
    md5_key, md5_cred = session_strong(nth, md5_c, md5_s)
    des_key, des_cred = session_des(nth, des_c, des_s)
    if not any(aes_key) or not any(md5_key) or not any(des_key):
        raise RuntimeError('a derived session key is all zeros')

    tcp = TCP(frames, cport, cip=cip, sip=sip)
    rpc = RPC(tcp, True, False)
    rpc.bind()
    caps = [c for c in CALLS if c[0] == 21][0]
    plain = stubs(caps[1], caps[2], True, False)
    nonce = bytes(range(0x80, 0x88))
    digest = bytes(range(0x90, 0x98))
    pw = 'Cover-Passw0rd'.encode('utf-16-le')

    do_call(rpc, 4, *challenge_call('PWAES', aes_c, aes_s))
    schannel_exchange(rpc, 1, AUTH_INTEGRITY, True, b'\0' * 16, 0x601, digest, nonce, plain)
    do_call(rpc, 15, *authenticate_call('PWAES', FLAGS_AES, aes_cred))
    do_call(rpc, 30, passwordset2_req(crypt_password_blob(aes_key, True, len(pw), pw)), passwordset2_resp)
    do_call(rpc, 30, passwordset2_req(crypt_password_blob(aes_key, True, 1)), passwordset2_resp)
    do_call(rpc, 32, sendtosam_req(opaque_blob(aes_key, True, 24, 16)), sendtosam_resp)
    do_call(rpc, 32, sendtosam_req(opaque_blob(aes_key, True, 24, 0)), sendtosam_resp)

    do_call(rpc, 4, *challenge_call('PWMD5', md5_c, md5_s))
    do_call(rpc, 15, *authenticate_call('PWMD5', FLAGS_STRONG, md5_cred))
    do_call(rpc, 30, passwordset2_req(crypt_password_blob(md5_key, False, len(pw), pw)), passwordset2_resp)
    do_call(rpc, 32, sendtosam_req(opaque_blob(md5_key, False, 24, 16)), sendtosam_resp)

    do_call(rpc, 4, *challenge_call('PWDES', des_c, des_s))
    do_call(rpc, 26, *authenticate_call('PWDES', FLAGS_DES, des_cred, True))
    do_call(rpc, 30, passwordset2_req(crypt_password_blob(None, False, 0x80000001)), passwordset2_resp)
    do_call(rpc, 32, sendtosam_req(opaque_blob(None, False, 16, 8)), sendtosam_resp)
    tcp.fin()


def kerberos_reply_without_vars(frames, cport, cip, sip):
    """NetrServerAuthenticateKerberos reply with no auth vars.

    The request is only the opnum header, so it is recorded and then
    throws before create_global_netlogon_auth_vars. The reply is intact,
    and find_tmp_netlogon_auth_vars returns NULL.
    """
    tcp = TCP(frames, cport, cip=cip, sip=sip)
    rpc = RPC(tcp, True, False)
    rpc.bind()
    rpc.call_id += 1
    rpc.tcp.send(True, rpc.request_pdu(59, b''))
    _, resp = kerberos_call('NOVARS', FLAGS_AES)
    w = W(True, False)
    resp(w)
    rpc.tcp.send(False, rpc.response_pdu(bytes(w.buf)))
    tcp.fin()


def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def _ber(tag, body):
    return bytes([tag]) + _ber_len(len(body)) + body


def _ber_int(v):
    length = max(1, (v.bit_length() + 8) // 8)
    return _ber(0x02, v.to_bytes(length, 'big'))


def _ber_ctx(n, body):
    return _ber(0xa0 | n, body)


def _gstring(s):
    return _ber(0x1b, s.encode('ascii'))


def _octet(b):
    return _ber(0x04, b)


def _seq(body):
    return _ber(0x30, body)


def _app(n, body):
    return _ber(0x60 | n, body)


def _principal(name_type, parts):
    names = b''.join(_gstring(p) for p in parts)
    return _seq(_ber_ctx(0, _ber_int(name_type)) + _ber_ctx(1, _seq(names)))


def _mes_header(body):
    """16-octet NDR MES header. The second byte is the drep Wireshark keeps."""
    return struct.pack('<BBHII', 1, 0x10, 8, 0xcccccccc, len(body)) + b'\0\0\0\0'


def pac_logon_buffer():
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
        w.ustr('cifs/files.coverage.test')
        w.u32(1)
        w.ptr(lambda: w.carray(['host/ws01.coverage.test'], lambda s: w.ustr(s)))
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


def sign_pac(blobs):
    """Server and KDC checksums (types 6 and 7) over buffers 1, 11 and 14.

    krb5_pac_sign must not add a ticket checksum (16) or a full checksum
    (19): verifying those without the right key is a warning.
    """
    k = krb5()
    pac = ctypes.c_void_p()
    _krb_check(k, k.krb5_pac_init(k._ctx, ctypes.byref(pac)), 'pac_init')
    held = []
    for typ, blob in blobs:
        d = _krb_data(blob)
        held.append(d)
        _krb_check(k, k.krb5_pac_add_buffer(k._ctx, pac, typ, ctypes.byref(d)),
                   'add_buffer %s' % typ)
    kb = _keyblock(PAC_ETYPE, PAC_KEY)
    out = _KrbData()
    _krb_check(k, k.krb5_pac_sign(k._ctx, pac, 0, None, ctypes.byref(kb),
                                  ctypes.byref(kb), ctypes.byref(out)), 'pac_sign')
    signed = ctypes.string_at(out.data, out.length)
    k.krb5_free_data_contents(k._ctx, ctypes.byref(out))
    count = struct.unpack_from('<I', signed)[0]
    types = [struct.unpack_from('<I', signed, 8 + 16 * i)[0] for i in range(count)]
    if 16 in types or 19 in types or not {1, 11, 14} <= set(types):
        raise RuntimeError('unexpected PAC buffer types %s' % types)
    return signed


def kerberos_keylog():
    """One long-term key per line: an encryption type and a hex key.

    The AES128 key opens the PAC ticket. The AES256 key opens the
    TICKET_INFO blobs, which are decrypted too once any key log is
    present. Empty lines and comments are ignored.
    """
    return (
        '# encryption-type hex-key\n'
        'aes128-cts-hmac-sha1-96 %s\n'
        'aes256-cts-hmac-sha1-96 %s\n' % (PAC_KEY.hex(), TICKET_KEY.hex())
    ).encode()


def pac_ticket():
    """One Ticket, APPLICATION 1. Nothing around it: no AS-REQ, no reply.

    The enc-part (usage 2) decrypts to EncTicketPart APPLICATION 3.
    Its authorization-data type 128 is the PAC. That is the whole
    Kerberos PDU; the NETLOGON helpers are the point of the packet."""
    pac = sign_pac([(1, pac_logon_buffer()), (11, pac_s4u_buffer()),
                    (14, pac_device_buffer())])
    flags = _ber(0x03, b'\x00' + struct.pack('>I', 0x40e00000))
    skey = _seq(_ber_ctx(0, _ber_int(PAC_ETYPE)) + _ber_ctx(1, _octet(b'\x11' * 16)))
    transited = _seq(_ber_ctx(0, _ber_int(0)) + _ber_ctx(1, _octet(b'')))
    ad = _seq(_seq(_ber_ctx(0, _ber_int(128)) + _ber_ctx(1, _octet(pac))))
    body = (_ber_ctx(0, flags) + _ber_ctx(1, skey) +
            _ber_ctx(2, _gstring('COVERAGE.TEST')) +
            _ber_ctx(3, _principal(1, ['alice'])) +
            _ber_ctx(4, transited) +
            _ber_ctx(5, _ber(0x18, b'20261101000000Z')) +
            _ber_ctx(7, _ber(0x18, b'20261102000000Z')) +
            _ber_ctx(10, ad))
    plain = _app(3, _seq(body))
    cipher = krb5_encrypt(PAC_ETYPE, PAC_KEY, plain, 2)
    enc = _seq(_ber_ctx(0, _ber_int(PAC_ETYPE)) + _ber_ctx(1, _ber_int(1)) +
               _ber_ctx(2, _octet(cipher)))
    tkt = (_ber_ctx(0, _ber_int(5)) +
           _ber_ctx(1, _gstring('COVERAGE.TEST')) +
           _ber_ctx(2, _principal(2, ['krbtgt', 'COVERAGE.TEST'])) +
           _ber_ctx(3, enc))
    return _app(1, _seq(tkt))


def udp_datagram(payload, sport, dport, sip, dip):
    """One UDP/IPv4/Ethernet frame. sip and dip are 4-tuples."""
    sip, dip = bytes(sip), bytes(dip)
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
    ph = sip + dip + struct.pack('>BBH', 0, 17, len(udp) + len(payload))
    udp = udp[:6] + struct.pack('>H', csum(ph + udp + payload)) + udp[8:]
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp) + len(payload),
                     0, 0x4000, 64, 17, 0, sip, dip)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    eth = bytes.fromhex('020000000070') + bytes.fromhex('020000000087') + b'\x08\x00'
    return eth + ip + udp + payload


def write_ntlmssp_creds(out):
    """The NT password the keyed secure channel is derived from."""
    path = os.path.join(out, 'cfg', 'ntlmssp_creds')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write('# NT password for the keyed NETLOGON secure channel.\n')
        f.write('# -o \'uat:ntlmssp_creds:"Type","Value"\'\n')
        f.write('"NT Password","%s"\n' % NT_PASSWORD)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_ntlmssp_creds(out)
    frames = []
    connection(frames, 50001, True, False, CALLS, (192, 0, 2, 70), (192, 0, 2, 80), le_extras)
    connection(frames, 50002, False, False, CALLS, (192, 0, 2, 71), (192, 0, 2, 81))
    connection(frames, 50003, True, True, CALLS, (192, 0, 2, 72), (192, 0, 2, 82))
    secchan_connection(frames, 50004, (192, 0, 2, 73), (192, 0, 2, 83))
    secchan_connection(frames, 50005, (192, 0, 2, 74), (192, 0, 2, 84), le=False)
    keyed_schannel_connection(frames, 50006, (192, 0, 2, 75), (192, 0, 2, 85))
    buffer_key_connection(frames, 50007, (192, 0, 2, 76), (192, 0, 2, 86))
    # The PAC helpers run only from the Kerberos dissector. One Ticket
    # on new addresses, so frames 1-790 stay put.
    frames.append(udp_datagram(pac_ticket(), 88, 50008, (192, 0, 2, 87), (192, 0, 2, 77)))
    write_pcapng(os.path.join(out, 'dcerpc_netlogon-coverage.pcapng'), frames,
                 kerberos_keylog())
    frames = []
    MALFORMED_CALLS.append((2, samlogon_req(8), samlogon_resp(7, fmts=('trunc', 'trunc'))))
    connection(frames, 50101, True, False, MALFORMED_CALLS, (192, 0, 2, 90), (192, 0, 2, 91))
    # every call again with its stubs cut short
    connection(frames, 50102, True, False, CALLS, (192, 0, 2, 92), (192, 0, 2, 93), cut=True)
    kerberos_reply_without_vars(frames, 50103, (192, 0, 2, 94), (192, 0, 2, 95))
    write_pcap(os.path.join(out, 'dcerpc_netlogon-coverage-malformed.pcap'), frames)


if __name__ == '__main__':
    main()
