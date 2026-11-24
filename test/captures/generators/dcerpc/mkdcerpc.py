#!/usr/bin/env python3
# Generates test/captures/dcerpc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic DCE/RPC coverage captures for packet-dcerpc.c.

usage: mkdcerpc.py <outdir>

Writes dcerpc-coverage.pcap (clean) and dcerpc-coverage-malformed.pcap.
Every packet is built with struct; addresses are from the documentation
ranges (192.0.2.0/24, 2001:db8::/32) and locally administered MACs.
"""

import struct
import sys
import uuid as uuidmod

# ---------------------------------------------------------------- pcap

class Pcap:
    def __init__(self):
        self.frames = []

    def add(self, frame):
        self.frames.append(frame)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, fr in enumerate(self.frames):
                caplen = len(fr)
                if isinstance(fr, tuple):       # (frame, snapshot length)
                    fr, caplen = fr
                f.write(struct.pack('<IIII', 1700000000 + i // 10,
                                    100000 * (i % 10), caplen, len(fr)))
                f.write(fr[:caplen])


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def mac(n):
    return bytes([2, 0, 0, 0, 0, n])


def eth(src, dst, etype, payload):
    return mac(dst) + mac(src) + struct.pack('>H', etype) + payload


def ipv4(src, dst, proto, payload):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0, 0x4000,
                     64, proto, 0, bytes(src), bytes(dst))
    return ip[:10] + struct.pack('>H', csum(ip)) + ip[12:] + payload


class TCP:
    """One TCP connection with a handshake; seq/ack kept per side."""

    def __init__(self, cap, cport, sport, cip=(192, 0, 2, 10),
                 sip=(192, 0, 2, 20), cmac=1, smac=2):
        self.cap = cap
        self.c = (bytes(cip), cport, cmac)
        self.s = (bytes(sip), sport, smac)
        self.cseq = 0x10000000 + cport * 7
        self.sseq = 0x20000000 + cport * 11
        self.seg(True, b'', 0x02)
        self.cseq += 1
        self.seg(False, b'', 0x12)
        self.sseq += 1
        self.seg(True, b'', 0x10)

    def seg(self, from_client, payload, flags=0x18):
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        seq = self.cseq if from_client else self.sseq
        ack = self.sseq if from_client else self.cseq
        if flags == 0x02:
            ack = 0
        opts = struct.pack('>BBHBB', 2, 4, 1460, 4, 2) + b'\x01\x01' if flags & 0x02 else b''
        tcp = struct.pack('>HHIIBBHHH', src[1], dst[1], seq, ack,
                          (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        ph = src[0] + dst[0] + struct.pack('>BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('>H', csum(ph + tcp + payload)) + tcp[18:]
        self.cap.add(eth(src[2], dst[2], 0x0800, ipv4(src[0], dst[0], 6, tcp + payload)))
        if from_client:
            self.cseq += len(payload)
        else:
            self.sseq += len(payload)

    def c2s(self, data):
        self.seg(True, data)

    def s2c(self, data):
        self.seg(False, data)

    def fin(self):
        self.seg(True, b'', 0x11)
        self.cseq += 1
        self.seg(False, b'', 0x11)
        self.sseq += 1
        self.seg(True, b'', 0x10)


def udp(cap, src, dst, sport, dport, payload, smac, dmac):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = bytes(src) + bytes(dst) + struct.pack('>BBH', 0, 17, len(u))
    u = u[:6] + struct.pack('>H', csum(ph + u) or 0xffff) + u[8:]
    cap.add(eth(smac, dmac, 0x0800, ipv4(src, dst, 17, u)))


# ---------------------------------------------------------------- UUIDs

NDR32 = '8a885d04-1ceb-11c9-9fe8-08002b104860'
NDR64 = '71710533-beba-4937-8319-b5dbef9ccc36'
BTFN = '6cb71c2c-9812-4540-0300-000000000000'
WINREG = ('338cd001-2244-31f1-aaaa-900038001003', 1, 0)
SRVSVC = ('4b324fc8-1670-01d3-1278-5a47bf6ee188', 3, 0)
DRSUAPI = ('e3514235-4b06-11d1-ab04-00c04fc2dcd2', 4, 0)
EPM = ('e1af8308-5d1f-11c9-91a4-08002b14a0fa', 3, 0)
BUDB = ('eb814e2a-0099-11ca-8678-02608c2ea96e', 4, 0)
UNKNOWN_IF = ('12345678-9abc-def0-1234-56789abcdef0', 2, 1)
ODD_TS = '0badc0de-1111-2222-3333-444455556666'


def uuid_bytes(u, le=True):
    x = uuidmod.UUID(u)
    return x.bytes_le if le else x.bytes


# ---------------------------------------------------------------- NDR

class NDR:
    """NDR stub builder; offsets are relative to the start of the stub."""

    def __init__(self, le=True, ndr64=False):
        self.b = bytearray()
        self.e = '<' if le else '>'
        self.n64 = ndr64

    def align(self, n):
        while len(self.b) % n:
            self.b.append(0)
        return self

    def sa(self):
        """Start of a structure or union arm with pointers."""
        return self.align(8 if self.n64 else 4)

    def se(self):
        """End of such a structure: NDR64 pads it to 8."""
        return self.align(8) if self.n64 else self

    def raw(self, data):
        self.b += data
        return self

    def u8(self, v):
        self.b += struct.pack('B', v)
        return self

    def u16(self, v):
        self.align(2)
        self.b += struct.pack(self.e + 'H', v)
        return self

    def u32(self, v):
        self.align(4)
        self.b += struct.pack(self.e + 'I', v)
        return self

    def u64(self, v):
        self.align(8)
        self.b += struct.pack(self.e + 'Q', v)
        return self

    def nttime(self, v):
        self.align(8 if self.n64 else 4)
        self.b += struct.pack(self.e + 'Q', v)
        return self

    def u3264(self, v):
        return self.u64(v) if self.n64 else self.u32(v)

    def ptr(self, v):
        return self.u3264(v)

    def handle(self, n=1):
        self.align(4)
        self.b += struct.pack(self.e + 'I', 0) + uuid_bytes(
            '%08x-0000-4000-8000-0000000000%02x' % (0x1000 + n, n), self.e == '<')
        return self

    def wchars(self, s):
        self.align(2)
        for ch in s:
            self.b += struct.pack(self.e + 'H', ord(ch))
        return self

    def cvwstr(self, s, nul=True, maxc=None):
        """Conformant varying UTF-16 string."""
        t = s + ('\0' if nul else '')
        self.u3264(maxc if maxc is not None else len(t))
        self.u3264(0)
        self.u3264(len(t))
        return self.wchars(t)

    def bytes(self):
        return bytes(self.b)


def ndr(le=True, ndr64=False):
    return NDR(le, ndr64)


# ---------------------------------------------------------------- CO

PFC_FIRST = 0x01
PFC_LAST = 0x02
PFC_SIGN = 0x04
PFC_OBJ = 0x80


class CO:
    """Connection-oriented DCE/RPC PDUs over some byte stream."""

    def __init__(self, send_c, send_s, le=True, ndr64=False, drep=None):
        self.send_c = send_c
        self.send_s = send_s
        self.le = le
        self.e = '<' if le else '>'
        self.ndr64 = ndr64
        self.drep = drep if drep is not None else bytes([0x10 if le else 0x00, 0, 0, 0])
        self.call_id = 0

    def n(self):
        return NDR(self.le, self.ndr64)

    def uuid(self, u):
        return uuid_bytes(u, self.le)

    def auth(self, atype, level, cred, pad=0, ctx=0):
        return struct.pack(self.e + 'BBBBI', atype, level, pad, 0, ctx) + cred

    def pdu(self, ptype, body, call_id, flags=PFC_FIRST | PFC_LAST, auth=b'',
            minor=0, frag_len=None, auth_len=None):
        if auth_len is None:
            auth_len = len(auth) - 8 if auth else 0
        if frag_len is None:
            frag_len = 16 + len(body) + len(auth)
        hdr = struct.pack('BBBB', 5, minor, ptype, flags) + self.drep
        hdr += struct.pack(self.e + 'HHI', frag_len, auth_len, call_id)
        return hdr + body + auth

    def ctx_item(self, ctx_id, iface, trans):
        b = struct.pack(self.e + 'HBx', ctx_id, len(trans)) + self.uuid(iface[0])
        if self.le:
            b += struct.pack(self.e + 'HH', iface[1], iface[2])
        else:
            b += struct.pack(self.e + 'HH', iface[2], iface[1])
        for t, v in trans:
            b += self.uuid(t) + struct.pack(self.e + 'I', v)
        return b

    def bind_body(self, ctxs, assoc=0):
        b = struct.pack(self.e + 'HHIB3x', 5840, 5840, assoc, len(ctxs))
        for c in ctxs:
            b += self.ctx_item(*c)
        return b

    def bind(self, ctxs, call_id=None, ptype=11, auth=b'', flags=PFC_FIRST | PFC_LAST):
        if call_id is None:
            self.call_id += 1
            call_id = self.call_id
        return self.pdu(ptype, self.bind_body(ctxs), call_id, flags, auth)

    def bind_ack(self, results, call_id, ptype=12, secaddr=b'49152\0', auth=b'',
                 flags=PFC_FIRST | PFC_LAST, assoc=0x53f0):
        b = struct.pack(self.e + 'HHIH', 5840, 5840, assoc, len(secaddr)) + secaddr
        b += b'\0' * ((-(16 + len(b))) % 4)
        b += struct.pack(self.e + 'B3x', len(results))
        for res, reason, trans in results:
            b += struct.pack(self.e + 'HH', res, reason)
            b += self.uuid(trans[0]) + struct.pack(self.e + 'I', trans[1])
        return self.pdu(ptype, b, call_id, flags, auth)

    def request(self, call_id, opnum, stub, ctx=0, flags=PFC_FIRST | PFC_LAST,
                obj=None, auth=b'', alloc=None):
        b = struct.pack(self.e + 'IHH', len(stub) if alloc is None else alloc, ctx, opnum)
        if obj:
            flags |= PFC_OBJ
            b += self.uuid(obj)
        return self.pdu(0, b + stub, call_id, flags, auth)

    def response(self, call_id, stub, ctx=0, flags=PFC_FIRST | PFC_LAST, auth=b'',
                 alloc=None, cancel=0):
        b = struct.pack(self.e + 'IHBB', len(stub) if alloc is None else alloc, ctx, cancel, 0)
        return self.pdu(2, b + stub, call_id, flags, auth)

    def fault(self, call_id, status, stub=b'', ctx=0, fflags=0, flags=PFC_FIRST | PFC_LAST,
              auth=b''):
        b = struct.pack(self.e + 'IHBBII', len(stub), ctx, 0, fflags, status, 0)
        return self.pdu(3, b + stub, call_id, flags, auth)

    # convenience: one request/response pair on a TCP-like transport
    def call(self, opnum, req, resp, ctx=0, obj=None, auth_req=b'', auth_resp=b''):
        self.call_id += 1
        self.send_c(self.request(self.call_id, opnum, req, ctx, obj=obj, auth=auth_req))
        if resp is not None:
            self.send_s(self.response(self.call_id, resp, ctx, auth=auth_resp))
        return self.call_id


def tcp_co(cap, cport, sport, le=True, ndr64=False, drep=None, **kw):
    t = TCP(cap, cport, sport, **kw)
    return t, CO(t.c2s, t.s2c, le, ndr64, drep)


# ---------------------------------------------------------------- WINREG stubs

REF = 0x00020000


def wr_string(n, s, ref):
    """winreg_String: name_len, name_size, [unique] name, then the string."""
    n.sa()
    if s is None:
        return n.u16(0).u16(0).ptr(0).se()
    ln = (len(s) + 1) * 2
    n.u16(ln).u16(ln).ptr(ref).se()
    return n.cvwstr(s)


def wr_openhklm_req(n):
    return n.ptr(REF).u16(0x5c).u32(0x02000000).bytes()


def wr_handle_resp(n, h, status=0):
    return n.handle(h).u32(status).bytes()


def wr_openkey_req(n, h, name):
    n.handle(h)
    wr_string(n, name, REF)
    return n.u32(0).u32(0x00020019).bytes()


def wr_queryvalue_req(n, h, name, size):
    n.handle(h)
    wr_string(n, name, REF)                      # [ref] value_name (no id)
    n.ptr(REF + 4).u32(0)                        # type
    n.ptr(REF + 8).u3264(size).u3264(0).u3264(0)  # data, empty
    n.ptr(REF + 12).u32(size)                    # data_size
    n.ptr(REF + 16).u32(0)                       # data_length
    return n.bytes()


def wr_queryvalue_resp(n, rtype, data, size=None):
    size = len(data) if size is None else size
    n.ptr(REF).u32(rtype)
    n.ptr(REF + 4).u3264(size).u3264(0).u3264(len(data)).raw(data)
    n.ptr(REF + 8).u32(size)
    n.ptr(REF + 12).u32(len(data))
    return n.u32(0).bytes()


def wr_enumkey_req(n, h, idx):
    n.handle(h).u32(idx)
    n.sa().u16(0).u16(512).ptr(REF).se().u3264(256).u3264(0).u3264(0)  # name, empty
    n.ptr(REF + 4)                                            # keyclass
    n.sa().u16(0).u16(512).ptr(0).se()
    n.ptr(REF + 8).nttime(0)                                   # last_changed_time
    return n.bytes()


def wr_enumkey_resp(n, name, cls):
    ln = (len(name) + 1) * 2
    n.sa().u16(ln).u16(512).ptr(REF).se()
    n.u3264(256).u3264(0).u3264(len(name) + 1).wchars(name + '\0')
    n.ptr(REF + 4)
    lc = (len(cls) + 1) * 2
    n.sa().u16(lc).u16(lc).ptr(REF + 8).se().u3264(len(cls) + 1).u3264(0).u3264(len(cls) + 1).wchars(cls + '\0')
    n.ptr(REF + 12).nttime(0x01d9000000000000)
    return n.u32(0).bytes()


def wr_closekey(n, h, status=None):
    n.handle(h)
    if status is not None:
        n.u32(status)
    return n.bytes()


def wr_qmv_req(n, h, names):
    """QueryMultipleValues: values_in array of QueryMultipleValue, each with
    a nested ve_valuename pointer to a winreg_ValNameBuf (two levels of
    deferred pointers)."""
    k = len(names)
    n.handle(h)
    n.u3264(k).u3264(0).u3264(k)                 # values_in [ref] array
    for i in range(k):
        n.sa().ptr(0x1000 + i).u32(0).u32(0).u32(1).se()  # ve_valuename, len, offset, type
    for i, s in enumerate(names):
        ln = (len(s) + 1) * 2
        n.sa().u16(ln).u16(ln).ptr(0x80000 + i).se()
        n.u3264(len(s) + 1).u3264(0).u3264(len(s) + 1).wchars(s + '\0')
    n.u32(k)                                     # num_values
    n.ptr(0)                                     # buffer
    n.u32(64)                                    # [ref] buffer_size
    return n.bytes()


def wr_getversion_resp(n, v=5):
    return n.u32(v).u32(0).bytes()


def wr_setvalue_req(n, h, name, data):
    n.handle(h)
    wr_string(n, name, REF)
    n.u32(3)                                     # REG_BINARY
    n.u3264(len(data)).raw(data)                 # [ref,size_is(size)] data
    return n.u32(len(data)).bytes()


def wr_status(n, status=0):
    return n.u32(status).bytes()


# ---------------------------------------------------------------- SRVSVC stubs

def sv_unc(n, name='\\\\SERVER'):
    return n.ptr(REF).cvwstr(name)


def sv_shareenum_req(n):
    sv_unc(n)
    n.sa().u32(1).u32(1).sa().ptr(REF + 4).se()  # level, union arm, ctr1
    n.sa().u32(0).ptr(0).se()                    # count, array
    n.u32(0xffffffff)                            # max_buffer
    n.ptr(REF + 8).u32(0)                        # resume_handle
    return n.bytes()


def sv_shareenum_resp(n, shares):
    n.sa().u32(1).u32(1).sa().ptr(REF).se()      # level, union arm, ctr1
    n.sa().u32(len(shares)).ptr(REF + 4).se()    # count, array
    n.u3264(len(shares))
    for i, (name, stype, comment) in enumerate(shares):
        n.sa().ptr(REF + 8 + 8 * i).u32(stype).ptr(REF + 12 + 8 * i).se()
    for name, stype, comment in shares:
        n.cvwstr(name)
        n.cvwstr(comment)
    n.u32(len(shares))                           # totalentries
    n.ptr(REF + 0x100).u32(0)                    # resume_handle
    return n.u32(0).bytes()


def sv_diskenum_req(n):
    sv_unc(n)
    n.u32(0)                                     # level
    n.sa().u32(0).ptr(0).se()                    # info: count, disks
    n.u32(26)                                    # maxlen
    n.ptr(REF + 4).u32(0)                        # resume_handle
    return n.bytes()


def sv_diskenum_resp(n, disks):
    n.sa().u32(len(disks)).ptr(REF).se()
    n.u3264(len(disks)).u3264(0).u3264(len(disks))
    for d in disks:
        n.u3264(0).u3264(len(d) + 1).wchars(d + '\0')
    n.u32(len(disks))                            # totalentries
    n.ptr(REF + 4).u32(0)                        # resume_handle
    return n.u32(0).bytes()


# ---------------------------------------------------------------- other stubs

SIG = bytes.fromhex('8ae3137102f43671')         # verification trailer signature


def vtrailer(le=True, ptype=0, call_id=0, ctx=0, opnum=0, extra=True, iface=WINREG, ts=NDR32):
    """[MS-RPCE] 2.2.2.13 verification trailer with every command."""
    e = '<'
    b = SIG
    b += struct.pack(e + 'HHI', 0x0001, 4, 1)                     # bitmask
    pc = uuid_bytes(iface[0]) + struct.pack(e + 'I', 1) + uuid_bytes(ts) + struct.pack(e + 'I', 2)
    b += struct.pack(e + 'HH', 0x0002, len(pc)) + pc               # pcontext
    drep = bytes([0x10 if le else 0, 0, 0, 0])
    h2 = struct.pack(e + 'BBH', ptype, 0, 0) + drep
    de = '<' if le else '>'
    h2 += struct.pack(de + 'IHH', call_id, ctx, opnum)
    last = 0x4000 if not extra else 0
    b += struct.pack(e + 'HH', 0x8003 | last, len(h2)) + h2        # header2, must
    if extra:
        b += struct.pack(e + 'HH', 0x4007, 3) + b'xyz' + b'\0'     # unknown, odd
    return b


def epm_tower(port=49152, iface=WINREG):
    floors = [
        (b'\x0d' + uuid_bytes(iface[0]) + struct.pack('<H', iface[1]), struct.pack('<H', iface[2])),
        (b'\x0d' + uuid_bytes(NDR32) + struct.pack('<H', 2), struct.pack('<H', 0)),
        (b'\x0b', struct.pack('<H', 0)),
        (b'\x07', struct.pack('>H', port)),
        (b'\x09', bytes([192, 0, 2, 20])),
    ]
    t = struct.pack('<H', len(floors))
    for lhs, rhs in floors:
        t += struct.pack('<H', len(lhs)) + lhs + struct.pack('<H', len(rhs)) + rhs
    return t


def epm_map_req(n, dup=False):
    tw = epm_tower(0)
    n.ptr(1).raw(uuid_bytes('00000000-0000-0000-0000-000000000000', n.e == '<'))
    n.ptr(1 if dup else 2)
    if not dup:
        n.u3264(len(tw)).u32(len(tw)).raw(tw)
    n.handle(0).u32(4)
    return n.bytes()


def epm_map_resp(n, towers, ids):
    n.handle(9).u32(len(towers))
    n.u3264(4).u3264(0).u3264(len(ids))
    for i in ids:
        n.ptr(i)
    for tw in towers:
        n.u3264(len(tw)).u32(len(tw)).raw(tw)
    return n.u32(0).bytes()


# NTLMSSP messages (no real credentials: the challenge and responses are
# made-up bytes, nothing can be derived from them)

def ntlm_negotiate():
    return b'NTLMSSP\0' + struct.pack('<II', 1, 0xe2088297) + struct.pack('<HHI', 0, 0, 0) * 2 + \
        bytes([10, 0, 0x63, 0x45, 0, 0, 0, 15])


def ntlm_challenge():
    target = 'SYNTH'.encode('utf-16-le')
    av = struct.pack('<HH', 2, len(target)) + target + struct.pack('<HH', 0, 0)
    off = 56
    b = b'NTLMSSP\0' + struct.pack('<I', 2)
    b += struct.pack('<HHI', len(target), len(target), off)
    b += struct.pack('<I', 0xe2898215) + bytes(range(1, 9)) + b'\0' * 8
    b += struct.pack('<HHI', len(av), len(av), off + len(target))
    b += bytes([10, 0, 0x63, 0x45, 0, 0, 0, 15])
    return b + target + av


def ntlm_authenticate():
    dom = 'SYNTH'.encode('utf-16-le')
    user = 'user'.encode('utf-16-le')
    ws = 'WS'.encode('utf-16-le')
    lm = b'\0' * 24
    nt = b'\x11' * 16 + struct.pack('<BBHIQ', 1, 1, 0, 0, 0) + b'\x22' * 8 + b'\0' * 4 + \
        struct.pack('<HH', 0, 0) + b'\0' * 4
    key = b'\x33' * 16
    off = 88
    fields = [lm, nt, dom, user, ws, key]
    b = b'NTLMSSP\0' + struct.pack('<I', 3)
    o = off
    hdrs = b''
    for f in fields:
        hdrs += struct.pack('<HHI', len(f), len(f), o)
        o += len(f)
    b += hdrs[:40] + hdrs[40:] + struct.pack('<I', 0xe2888215)
    b += bytes([10, 0, 0x63, 0x45, 0, 0, 0, 15]) + b'\0' * 16
    assert len(b) == off
    return b + b''.join(fields)


def ntlm_verifier(seq):
    return struct.pack('<I', 1) + struct.pack('<Q', 0x0102030405060708 + seq) + struct.pack('<I', seq)


# ================================================================ main capture

def sec_winreg_le(cap):
    """WINREG over TCP (heuristic), NDR32 little endian, with NDR64 and
    bind time feature negotiation contexts, every CO PDU type and the
    fragment, desegmentation and verification trailer paths."""
    t, r = tcp_co(cap, 50001, 49152)
    r.send_c(r.bind([(0, WINREG, [(NDR32, 2)]),
                     (1, WINREG, [(NDR64, 1)]),
                     (2, WINREG, [(BTFN, 1)]),
                     (3, WINREG, [(NDR64, 1), (NDR32, 2)])]))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2)), (0, 0, (NDR64, 1)),
                         (3, 3, ('00000000-0000-0000-0000-000000000000', 0)),
                         (2, 2, ('00000000-0000-0000-0000-000000000000', 0))], 1))
    r.call(2, wr_openhklm_req(r.n()), wr_handle_resp(r.n(), 1))
    r.call(15, wr_openkey_req(r.n(), 1, 'SOFTWARE\\Synthetic'), wr_handle_resp(r.n(), 2))
    r.call(17, wr_queryvalue_req(r.n(), 2, 'Version', 16),
           wr_queryvalue_resp(r.n(), 1, 'v1.0\0'.encode('utf-16-le'), 16))
    r.call(9, wr_enumkey_req(r.n(), 2, 0), wr_enumkey_resp(r.n(), 'SubKey', 'Class'))
    # dcerpc_ptrlist_cubic reproducer with a small N: nested deferred
    # pointers in an array (QueryMultipleValues)
    r.call(29, wr_qmv_req(r.n(), 2, ['Value%d' % i for i in range(16)]), None)
    # NDR64 on context 1 of the same connection
    n64 = NDR(True, True)
    r.call(17, wr_queryvalue_req(n64, 2, 'Ndr64', 8),
           wr_queryvalue_resp(NDR(True, True), 4, struct.pack('<I', 0x12345678), 8), ctx=1)
    # object UUID
    r.call(26, r.n().handle(2).bytes(), wr_getversion_resp(r.n()),
           obj='a1b2c3d4-0000-1111-2222-333344445555')
    # unknown opnum
    r.call(99, b'\x01\x02\x03\x04', b'\x00\x00\x00\x00')
    # verification trailer after the stub
    r.call_id += 1
    stub = r.n().handle(2).bytes()
    r.send_c(r.request(r.call_id, 26, stub + vtrailer(True, 0, r.call_id, 0, 26)))
    r.send_s(r.response(r.call_id, wr_getversion_resp(r.n())))
    # fragmented request (first, middle, last) and fragmented response
    r.call_id += 1
    stub = wr_setvalue_req(r.n(), 2, 'Blob', bytes(i & 0xff for i in range(2400)))
    parts = [stub[0:1000], stub[1000:2000], stub[2000:]]
    for i, p in enumerate(parts):
        fl = (PFC_FIRST if i == 0 else 0) | (PFC_LAST if i == 2 else 0)
        r.send_c(r.request(r.call_id, 22, p, flags=fl, alloc=len(stub)))
    r.send_s(r.response(r.call_id, wr_status(r.n())))
    r.call_id += 1
    r.send_c(r.request(r.call_id, 17, wr_queryvalue_req(r.n(), 2, 'Big', 3000)))
    stub = wr_queryvalue_resp(r.n(), 3, bytes((7 * i) & 0xff for i in range(3000)))
    parts = [stub[0:1200], stub[1200:2400], stub[2400:]]
    for i, p in enumerate(parts):
        fl = (PFC_FIRST if i == 0 else 0) | (PFC_LAST if i == 2 else 0)
        r.send_s(r.response(r.call_id, p, flags=fl, alloc=len(stub)))
    # one PDU in two TCP segments (desegmentation)
    r.call_id += 1
    p = r.request(r.call_id, 15, wr_openkey_req(r.n(), 1, 'SOFTWARE\\Split'))
    t.c2s(p[:30])
    t.c2s(p[30:])
    r.send_s(r.response(r.call_id, wr_handle_resp(r.n(), 3)))
    # fault with stub data and the extended error flag
    r.call_id += 1
    r.send_c(r.request(r.call_id, 16, r.n().handle(3).u16(0).u16(0).ptr(0).bytes()))
    r.send_s(r.fault(r.call_id, 0x1c010003, b'\x05\x00\x00\x00', fflags=0x01))
    # fragmented fault: first, middle and last fragment
    r.call_id += 1
    r.send_c(r.request(r.call_id, 26, r.n().handle(3).bytes()))
    for i, p in enumerate([b'\xaa' * 8, b'\xbb' * 8, b'\xcc' * 8]):
        fl = (PFC_FIRST if i == 0 else 0) | (PFC_LAST if i == 2 else 0)
        r.send_s(r.fault(r.call_id, 0x000006f7, p, flags=fl))
    # alter context to SRVSVC on context 4, then calls on it
    r.call_id += 1
    r.send_c(r.bind([(4, SRVSVC, [(NDR32, 2)])], r.call_id, ptype=14))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2))], r.call_id, ptype=15, secaddr=b''))
    r.call(15, sv_shareenum_req(r.n()),
           sv_shareenum_resp(r.n(), [('IPC$', 0x80000003, 'Remote IPC'),
                                     ('data', 0, 'Data share'),
                                     ('print$', 0, 'Printer drivers')]), ctx=4)
    r.call(23, sv_diskenum_req(r.n()), sv_diskenum_resp(r.n(), ['C:', 'D:']), ctx=4)
    # two PDUs in one TCP segment, each way, on a non-zero context
    a = r.request(r.call_id + 1, 23, sv_diskenum_req(r.n()), ctx=4)
    b = r.request(r.call_id + 2, 23, sv_diskenum_req(r.n()), ctx=4)
    t.c2s(a + b)
    t.s2c(r.response(r.call_id + 1, sv_diskenum_resp(r.n(), ['E:']), ctx=4) +
          r.response(r.call_id + 2, sv_diskenum_resp(r.n(), ['F:']), ctx=4))
    r.call_id += 2
    # cancel and orphaned for an outstanding call
    r.call_id += 1
    r.send_c(r.request(r.call_id, 9, wr_enumkey_req(r.n(), 2, 1)))
    r.send_c(r.pdu(18, b'', r.call_id))
    r.send_c(r.pdu(19, b'', r.call_id))
    # a request on a context that was never bound, a response to an
    # unknown call
    r.send_c(r.request(r.call_id + 1, 2, wr_openhklm_req(r.n()), ctx=9))
    r.send_s(r.response(4000, wr_handle_resp(r.n(), 5)))
    r.call_id += 1
    r.call(5, wr_closekey(r.n(), 2), wr_closekey(r.n(), 0, 0))
    r.send_s(r.pdu(17, b'', 0))
    t.fin()


def sec_winreg_be(cap):
    """Big endian NDR32: WINREG and SRVSVC, a bind with EBCDIC/VAX drep
    names in the header display only."""
    t, r = tcp_co(cap, 50002, 49152, le=False)
    r.send_c(r.bind([(0, WINREG, [(NDR32, 2)]), (1, SRVSVC, [(NDR32, 2)])]))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2)), (0, 0, (NDR32, 2))], 1))
    r.call(2, wr_openhklm_req(r.n()), wr_handle_resp(r.n(), 1))
    r.call(15, wr_openkey_req(r.n(), 1, 'SOFTWARE'), wr_handle_resp(r.n(), 2))
    r.call(17, wr_queryvalue_req(r.n(), 2, 'Version', 16),
           wr_queryvalue_resp(r.n(), 4, b'\x00\x00\x00\x05', 16))
    r.call(9, wr_enumkey_req(r.n(), 2, 0), wr_enumkey_resp(r.n(), 'SubKey', 'Class'))
    r.call(29, wr_qmv_req(r.n(), 2, ['A', 'Bb']), None)
    r.call(26, r.n().handle(2).bytes(), wr_getversion_resp(r.n()),
           obj='a1b2c3d4-0000-1111-2222-333344445555')
    r.call(15, sv_shareenum_req(r.n()),
           sv_shareenum_resp(r.n(), [('IPC$', 0x80000003, 'Remote IPC')]), ctx=1)
    r.call(23, sv_diskenum_req(r.n()), sv_diskenum_resp(r.n(), ['C:']), ctx=1)
    r.call_id += 1
    r.send_c(r.request(r.call_id, 26, r.n().handle(2).bytes()))
    r.send_s(r.fault(r.call_id, 0x1c00001c, b''))
    t.fin()


def sec_winreg_ndr64(cap):
    """WINREG bound with NDR64 only."""
    t, r = tcp_co(cap, 50003, 49152, ndr64=True)
    r.send_c(r.bind([(0, WINREG, [(NDR64, 1)])]))
    r.send_s(r.bind_ack([(0, 0, (NDR64, 1))], 1))
    r.call(2, wr_openhklm_req(r.n()), wr_handle_resp(r.n(), 1))
    r.call(15, wr_openkey_req(r.n(), 1, 'SOFTWARE\\Synthetic'), wr_handle_resp(r.n(), 2))
    r.call(17, wr_queryvalue_req(r.n(), 2, 'Version', 16),
           wr_queryvalue_resp(r.n(), 1, 'v1.0\0'.encode('utf-16-le'), 16))
    r.call(9, wr_enumkey_req(r.n(), 2, 0), wr_enumkey_resp(r.n(), 'SubKey', 'Class'))
    r.call(29, wr_qmv_req(r.n(), 2, ['A', 'Bb', 'Ccc']), None)
    r.call(22, wr_setvalue_req(r.n(), 2, 'Blob', bytes(range(7))), wr_status(r.n()))
    r.call(5, wr_closekey(r.n(), 2), wr_closekey(r.n(), 0, 0))
    t.fin()


def pad16(stub):
    p = (-len(stub)) % 16
    return stub + b'\0' * p, p


def sec_ntlmssp(cap):
    """NTLMSSP packet integrity: bind/bind_ack/auth3 with header signing,
    verifiers on requests, responses, alter context, cancel, orphaned and
    fault, with auth padding."""
    t, r = tcp_co(cap, 50004, 49152)
    ctx = 0x00a1
    r.send_c(r.bind([(0, WINREG, [(NDR32, 2)])], flags=0x07,
                    auth=r.auth(10, 5, ntlm_negotiate(), ctx=ctx)))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2))], 1, flags=0x07,
                        auth=r.auth(10, 5, ntlm_challenge(), ctx=ctx)))
    r.send_c(r.pdu(16, b'\0\0\0\0', 1, flags=0x07,
                   auth=r.auth(10, 5, ntlm_authenticate(), ctx=ctx)))
    seq = 0
    for opnum, req, resp in ((2, wr_openhklm_req(r.n()), wr_handle_resp(r.n(), 1)),
                             (26, r.n().handle(1).bytes(), wr_getversion_resp(r.n())),
                             (15, wr_openkey_req(r.n(), 1, 'SOFTWARE'), wr_handle_resp(r.n(), 2))):
        r.call_id += 1
        q, p = pad16(req)
        r.send_c(r.request(r.call_id, opnum, q, auth=r.auth(10, 5, ntlm_verifier(seq), p, ctx),
                           alloc=len(req)))
        q, p = pad16(resp)
        r.send_s(r.response(r.call_id, q, auth=r.auth(10, 5, ntlm_verifier(seq), p, ctx),
                            alloc=len(resp)))
        seq += 1
    # alter context with a verifier
    r.call_id += 1
    r.send_c(r.bind([(1, SRVSVC, [(NDR32, 2)])], r.call_id, ptype=14, flags=0x07,
                    auth=r.auth(10, 5, ntlm_negotiate(), ctx=ctx)))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2))], r.call_id, ptype=15, secaddr=b'', flags=0x07,
                        auth=r.auth(10, 5, ntlm_challenge(), ctx=ctx)))
    # a request whose padding is larger than its stub (all padding)
    r.call_id += 1
    r.send_c(r.request(r.call_id, 26, b'\0' * 4, auth=r.auth(10, 5, ntlm_verifier(seq), 8, ctx)))
    # an unknown opnum (no subdissector) with auth padding, and with
    # padding as long as the stub
    r.call_id += 1
    r.send_c(r.request(r.call_id, 77, b'\x01' * 12 + b'\0' * 4,
                       auth=r.auth(10, 5, ntlm_verifier(seq), 4, ctx), alloc=12))
    r.send_s(r.response(r.call_id, b'\0' * 4, auth=r.auth(10, 5, ntlm_verifier(seq), 4, ctx)))
    r.call_id += 1
    # cancel, orphaned and fault with verifiers
    r.send_c(r.pdu(18, b'', r.call_id, auth=r.auth(10, 5, ntlm_verifier(seq + 1), 0, ctx)))
    r.send_c(r.pdu(19, b'', r.call_id, auth=r.auth(10, 5, ntlm_verifier(seq + 2), 0, ctx)))
    r.send_s(r.fault(r.call_id, 0x00000005, b'',
                     auth=r.auth(10, 5, ntlm_verifier(seq + 3), 0, ctx)))
    t.fin()


def sec_privacy(cap):
    """Packet privacy without keys: NTLMSSP sealed stubs (shown encrypted,
    also when fragmented) and an unknown authentication type."""
    t, r = tcp_co(cap, 50005, 49152)
    ctx = 7
    r.send_c(r.bind([(0, WINREG, [(NDR32, 2)])], auth=r.auth(10, 6, ntlm_negotiate(), ctx=ctx)))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2))], 1, auth=r.auth(10, 6, ntlm_challenge(), ctx=ctx)))
    r.send_c(r.pdu(16, b'\0\0\0\0', 1, auth=r.auth(10, 6, ntlm_authenticate(), ctx=ctx)))
    r.call_id += 1
    enc = bytes((i * 37 + 11) & 0xff for i in range(48))
    r.send_c(r.request(r.call_id, 2, enc, auth=r.auth(10, 6, ntlm_verifier(0), 4, ctx)))
    r.send_s(r.response(r.call_id, enc[:32], auth=r.auth(10, 6, ntlm_verifier(0), 0, ctx)))
    r.call_id += 1
    big = bytes((i * 13) & 0xff for i in range(96))
    r.send_c(r.request(r.call_id, 15, big[:48], flags=PFC_FIRST,
                       auth=r.auth(10, 6, ntlm_verifier(1), 0, ctx), alloc=96))
    r.send_c(r.request(r.call_id, 15, big[48:], flags=PFC_LAST,
                       auth=r.auth(10, 6, ntlm_verifier(2), 0, ctx), alloc=96))
    r.send_s(r.response(r.call_id, enc[:32], auth=r.auth(10, 6, ntlm_verifier(1), 0, ctx)))
    t.fin()
    # unknown authentication type 0x7f, connect and privacy levels
    t, r = tcp_co(cap, 50006, 49152)
    r.send_c(r.bind([(0, WINREG, [(NDR32, 2)])], auth=r.auth(0x7f, 2, b'\x01\x02\x03\x04')))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2))], 1, auth=r.auth(0x7f, 2, b'\x05\x06\x07\x08')))
    r.call(26, r.n().handle(1).bytes(), wr_getversion_resp(r.n()),
           auth_req=r.auth(0x7f, 2, b'\xaa' * 8), auth_resp=r.auth(0x7f, 2, b'\xbb' * 8))
    r.call(26, enc[:24], enc[:16],
           auth_req=r.auth(0x7f, 6, b'\xcc' * 8), auth_resp=r.auth(0x7f, 6, b'\xdd' * 8))
    t.fin()


def sec_unknown_iface(cap):
    """An interface without a dissector: stub data with and without a
    verification trailer, minor version 1."""
    t, r = tcp_co(cap, 50007, 49152)
    r.send_c(r.bind([(0, UNKNOWN_IF, [(NDR32, 2)])]))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2))], 1))
    r.call_id += 1
    r.send_c(r.request(r.call_id, 3, b'\x11' * 12 + vtrailer(True, 0, r.call_id, 0, 3, extra=False,
                                                             iface=UNKNOWN_IF, ts=ODD_TS)))
    r.send_s(r.response(r.call_id, b'\x22' * 8))
    r.call_id += 1
    r.send_c(r.pdu(0, struct.pack('<IHH', 4, 0, 1) + b'\x33' * 4, r.call_id, minor=1))
    r.send_s(r.pdu(2, struct.pack('<IHBB', 4, 0, 0, 0) + b'\x44' * 4, r.call_id, minor=1))
    t.fin()


# ---------------------------------------------------------------- RTS

def rts_cmd(c, e='<'):
    cookie = uuid_bytes('5ca1ab1e-0000-4000-8000-00000000c00c', e == '<')
    body = {
        0x0: struct.pack(e + 'I', 65536),
        0x1: struct.pack(e + 'II', 4096, 65536) + cookie,
        0x2: struct.pack(e + 'I', 120000),
        0x3: cookie,
        0x4: struct.pack(e + 'I', 0x40000000),
        0x5: struct.pack(e + 'I', 300000),
        0x6: struct.pack(e + 'I', 1),
        0x7: b'',
        0x8: struct.pack(e + 'I', 6) + b'\0' * 6,
        0x9: b'',
        0xA: b'',
        0xB: struct.pack(e + 'I', 0) + bytes([192, 0, 2, 10]) + b'\0' * 12,
        0xC: uuid_bytes('a550c1a7-0000-4000-8000-00000000a550', e == '<'),
        0xD: struct.pack(e + 'I', 2),
        0xE: struct.pack(e + 'I', 1024),
    }.get(c, b'')
    return struct.pack(e + 'I', c) + body


def rts_pdu(co, flags, cmds, extra=b''):
    b = struct.pack(co.e + 'HH', flags, len(cmds)) + b''.join(rts_cmd(c, co.e) for c in cmds) + extra
    return co.pdu(20, b, 0)


RTS_SEQS = [
    # flags, commands: every named RTS PDU and one unnamed per flag group
    (0x00, [6, 3, 3, 0]), (0x00, [2]), (0x00, [3]), (0x00, [7]), (0x00, [0]),
    (0x00, [0xD]), (0x00, [0xA]), (0x00, [4]), (0x00, [0, 6]), (0x00, [0xD, 0xA]),
    (0x00, [0, 0]), (0x00, [6, 0, 2]), (0x00, [6, 0, 0]), (0x00, [0xD, 6, 0, 2]),
    (0x00, [6, 0, 0, 0]), (0x00, [6, 3, 3, 4, 5, 0xC]), (0x00, [6, 3, 3, 4, 5, 6]),
    (0x00, [0, 0, 0, 0, 0]),
    (0x01, []), (0x01, [7]), (0x01, [8]), (0x01, [0]), (0x01, [0, 0]),
    (0x02, [5]), (0x02, [0xE]), (0x02, [1]), (0x02, [0]), (0x02, [0xD, 1]),
    (0x02, [0, 1]), (0x02, [0, 0, 0]),
    (0x04, [0xD]), (0x04, [0]), (0x04, [6, 3, 3, 3]), (0x04, [6, 3, 3, 0]),
    (0x04, [6, 3, 3, 3, 0]), (0x04, [6, 3, 3, 3, 3]), (0x04, [0, 0]),
    (0x0c, [6, 3, 3, 3, 0, 2]), (0x0c, [6, 3, 3, 3, 0, 0]), (0x0c, [0]),
    (0x08, [6, 3, 3, 0, 2, 0xC, 0xB]), (0x08, [6, 3, 3, 0, 2, 0xC, 0]), (0x08, [0]),
    (0x14, [6, 3, 3, 3, 4, 0, 2]), (0x14, [6, 3, 3, 3, 4, 0, 0]), (0x14, [0]),
    (0x10, [0xD, 3]), (0x10, [0xD, 0]), (0x10, [0xD, 6, 2]), (0x10, [0xD, 3, 6]),
    (0x10, [0xD, 0, 0]), (0x10, [6, 3, 3, 4, 0]), (0x10, [6, 3, 3, 4, 4]), (0x10, [0]),
    (0x20, [0xA]), (0x20, [0]), (0x20, [0, 0]),
    (0x40, []), (0x40, [0]),
    (0x80, [9]),
]


def sec_rts(cap):
    """RTS PDUs ([MS-RPCH]) over TCP: every command and every named PDU,
    little and big endian, IPv4 and IPv6 client addresses."""
    t, r = tcp_co(cap, 50008, 593)
    for i, (flags, cmds) in enumerate(RTS_SEQS):
        (t.c2s if i % 2 == 0 else t.s2c)(rts_pdu(r, flags, cmds))
    # client address IPv6, big endian
    rb = CO(t.c2s, t.s2c, le=False)
    v6 = struct.pack('>II', 0xB, 1) + bytes.fromhex('20010db8000000000000000000000010') + b'\0' * 12
    t.c2s(rb.pdu(20, struct.pack('>HH', 0, 1) + v6, 0))
    t.s2c(rts_pdu(rb, 0x10, [6, 3, 3, 4, 0]))
    t.fin()


# ---------------------------------------------------------------- transports

def sec_http(cap):
    """RPC over HTTP: RTS and a bind/bind_ack in RPC_IN_DATA/RPC_OUT_DATA
    bodies (several PDUs in one body)."""
    t = TCP(cap, 50009, 80)
    r = CO(t.c2s, t.s2c)
    body = rts_pdu(r, 0x08, [6, 3, 3, 0, 2, 0xC, 0xB]) + r.bind([(0, WINREG, [(NDR32, 2)])])
    t.c2s(b'RPC_IN_DATA /rpc/rpcproxy.dll?server.example:593 HTTP/1.1\r\n'
          b'Host: proxy.example\r\nContent-Type: application/rpc\r\n'
          b'Content-Length: %d\r\n\r\n' % len(body) + body)
    body = rts_pdu(r, 0x00, [2]) + r.bind_ack([(0, 0, (NDR32, 2))], 1) + \
        r.response(2, wr_handle_resp(r.n(), 1))
    t.s2c(b'HTTP/1.1 200 Success\r\nContent-Type: application/rpc\r\n'
          b'Content-Length: %d\r\n\r\n' % len(body) + body)
    t.fin()


def llc_netbios(cap, src, dst, payload, num):
    nb = struct.pack('<HHBBHHHBB', 14, 0xefff, 0x16, 0, 0, 0, num, 0x22, 0x11) + payload
    frame = mac(dst) + mac(src) + struct.pack('>H', 4 + len(nb)) + \
        bytes([0xf0, 0xf0, (num * 2) & 0xfe, (num * 2) & 0xfe]) + nb
    cap.add(frame)


def sec_netbios(cap):
    """DCE/RPC over NetBIOS (NBF over LLC), one PDU per frame, a request
    with the 4 octets of null padding seen over NetBIOS."""
    r = CO(None, None)
    k = [0]

    def c(p):
        k[0] += 1
        llc_netbios(cap, 0x31, 0x32, p, k[0])

    def s(p):
        k[0] += 1
        llc_netbios(cap, 0x32, 0x31, p, k[0])
    r.send_c, r.send_s = c, s
    c(r.bind([(0, WINREG, [(NDR32, 2)])]))
    s(r.bind_ack([(0, 0, (NDR32, 2))], 1, secaddr=b'\\PIPE\\winreg\0'))
    r.call_id += 1
    c(b'\0\0\0\0' + r.request(r.call_id, 2, wr_openhklm_req(r.n())))
    s(r.response(r.call_id, wr_handle_resp(r.n(), 1)))


def smb2_hdr(cmd, mid, resp=False, tree=1, sess=0x77):
    return b'\xfeSMB' + struct.pack('<HHIHHIIQIIQ', 64, 1, 0, cmd, 1, 1 if resp else 0, 0, mid,
                                    0xfeff, tree, sess) + b'\0' * 16


def nbss(b):
    return struct.pack('>I', len(b)) + b


def sec_smb2(cap):
    """DCE/RPC over an SMB2 named pipe: write/read and FSCTL_PIPE_TRANSCEIVE."""
    t = TCP(cap, 50010, 445)
    r = CO(None, None)
    fid = struct.pack('<QQ', 0x1111, 0x2222)
    bind = r.bind([(0, SRVSVC, [(NDR32, 2)])])
    w = struct.pack('<HHIQ', 49, 112, len(bind), 0) + fid + struct.pack('<IIHHI', 0, 0, 0, 0, 0)
    t.c2s(nbss(smb2_hdr(9, 5) + w + bind))
    t.s2c(nbss(smb2_hdr(9, 5, True) + struct.pack('<HHIIHH', 17, 0, len(bind), 0, 0, 0)))
    rd = struct.pack('<HBBIQ', 49, 0, 0, 1024, 0) + fid + struct.pack('<IIIHH', 0, 0, 0, 0, 0) + b'\0'
    t.c2s(nbss(smb2_hdr(8, 6) + rd))
    ack = r.bind_ack([(0, 0, (NDR32, 2))], 1, secaddr=b'\\PIPE\\srvsvc\0')
    t.s2c(nbss(smb2_hdr(8, 6, True) + struct.pack('<HBBIII', 17, 80, 0, len(ack), 0, 0) + ack))
    req = r.request(2, 23, sv_diskenum_req(r.n()))
    io = struct.pack('<HHI', 57, 0, 0x0011c017) + fid + \
        struct.pack('<IIIIIIII', 120, len(req), 0, 120, 0, 1024, 1, 0)
    t.c2s(nbss(smb2_hdr(11, 7) + io + req))
    resp = r.response(2, sv_diskenum_resp(r.n(), ['C:']))
    io = struct.pack('<HHI', 49, 0, 0x0011c017) + fid + \
        struct.pack('<IIIIII', 112, 0, 112, len(resp), 0, 0)
    t.s2c(nbss(smb2_hdr(11, 7, True) + io + resp))
    t.fin()


def sec_epm(cap):
    """EPM Map over TCP port 135: full pointers, duplicate full pointers
    at the top level and embedded, and a response pointer seen in the
    request."""
    t, r = tcp_co(cap, 50012, 135)
    r.send_c(r.bind([(0, EPM, [(NDR32, 2)])]))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2))], 1, secaddr=b'135\0'))
    tw = epm_tower(49152)
    r.call(3, epm_map_req(r.n()), epm_map_resp(r.n(), [tw, tw], [0x30001, 0x30002, 0x30001]))
    r.call(3, epm_map_req(r.n(), dup=True), epm_map_resp(r.n(), [], [1]))
    t.fin()


def sec_budb(cap):
    """BUDB (DCE/DFS) over TCP: a varying array and a varying string with a
    duplicate full pointer."""
    t, r = tcp_co(cap, 50013, 49153)
    r.send_c(r.bind([(0, BUDB, [(NDR32, 2)])]))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2))], 1))
    hdr = struct.pack('<IIII', 1, 2, 0, 0)
    r.call(16, hdr + struct.pack('<III', 1, 1, 1) + b'T' * 1024, struct.pack('<I', 0))
    r.call(4, struct.pack('<III', 0x20000, 0, 6) + b'dump1\0' + b'\0\0' +
           struct.pack('<II', 0x20000, 7), struct.pack('<I', 0))
    t.fin()


def drsuapi_list(cap, cport, n):
    """drsuapi_list_quadratic reproducer: a DsAddEntry request whose object
    list has n items linked by next_object pointers (one deferred pointer
    level per item)."""
    t, r = tcp_co(cap, cport, 49155)
    r.send_c(r.bind([(0, DRSUAPI, [(NDR32, 2)])]))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2))], 1))
    stub = r.n().handle(1).u32(2).u32(2)
    ref = 0x00020000
    for i in range(n):
        nxt = ref + 4 * (i + 1) if i < n - 1 else 0
        stub.u32(nxt).u32(0).u32(0).u32(0).u32(0)
    r.call_id += 1
    s = stub.bytes()
    chunks = [s[i:i + 4000] for i in range(0, len(s), 4000)]
    for k, c in enumerate(chunks):
        fl = (PFC_FIRST if k == 0 else 0) | (PFC_LAST if k == len(chunks) - 1 else 0)
        r.send_c(r.request(r.call_id, 17, c, flags=fl, alloc=len(s)))
    t.fin()


def sec_bind_nak(cap):
    """Bind_nak with the supported protocol versions and with a plain
    reason (both are Warning expert infos, so they are in the malformed
    capture)."""
    t, r = tcp_co(cap, 50014, 49152)
    r.send_c(r.bind([(0, WINREG, [(NDR32, 2)])]))
    r.send_s(r.pdu(13, struct.pack('<HB', 4, 2) + bytes([5, 0, 5, 1]), 1))
    r.send_c(r.bind([(0, WINREG, [(NDR32, 2)])]))
    r.send_s(r.pdu(13, struct.pack('<H', 8), 2))
    t.fin()


# ---------------------------------------------------------------- CL

ACT = '6b8c0000-0000-4000-8000-0000000000a1'


def cl_pdu(ptype, iface, opnum, seq, body, le=True, flags1=0x20, flags2=0, frag=0,
           act=ACT, boot=0x5f000000, auth_proto=0, auth=b'', serial=0, frag_len=None,
           obj='00000000-0000-0000-0000-000000000000'):
    e = '<' if le else '>'
    drep = bytes([0x10 if le else 0x00, 0, 0])
    h = struct.pack('BBBB', 4, ptype, flags1, flags2) + drep + bytes([serial >> 8])
    h += uuid_bytes(obj, le) + uuid_bytes(iface[0], le) + uuid_bytes(act, le)
    h += struct.pack(e + 'IIIHHHHHBB', boot, iface[1], seq, opnum, 0xffff, 0xffff,
                     len(body) if frag_len is None else frag_len, frag, auth_proto, serial & 0xff)
    assert len(h) == 80
    return h + body + auth


class CL:
    def __init__(self, cap, cport=49300, sport=135, cip=(192, 0, 2, 30), sip=(192, 0, 2, 40)):
        self.cap, self.cport, self.sport, self.cip, self.sip = cap, cport, sport, cip, sip

    def c(self, p):
        udp(self.cap, self.cip, self.sip, self.cport, self.sport, p, 3, 4)

    def s(self, p):
        udp(self.cap, self.sip, self.cip, self.sport, self.cport, p, 4, 3)


def sec_cl(cap):
    """Connectionless DCE/RPC over UDP: requests and responses (little and
    big endian), fragments with facks, ping/working/ack, nocall, reject,
    fault, cancel and cancel_ack, authentication verifiers."""
    u = CL(cap)
    n = NDR()
    tw = epm_tower(49152)
    req = epm_map_req(NDR())
    resp = epm_map_resp(NDR(), [tw], [0x30001])
    u.c(cl_pdu(0, EPM, 3, 1, req))
    u.c(cl_pdu(1, EPM, 3, 1, b''))                       # ping
    u.s(cl_pdu(4, EPM, 3, 1, b'', flags1=0))            # working
    u.s(cl_pdu(2, EPM, 3, 1, resp, flags1=0))
    u.c(cl_pdu(7, EPM, 3, 1, b''))                       # ack
    # big endian, server boot time unknown
    u.c(cl_pdu(0, EPM, 3, 2, epm_map_req(NDR(False)), le=False, boot=0,
               act='6b8c0000-0000-4000-8000-0000000000b2'))
    u.s(cl_pdu(2, EPM, 3, 2, epm_map_resp(NDR(False), [tw], [0x30001]), le=False, boot=0,
               flags1=0, act='6b8c0000-0000-4000-8000-0000000000b2'))
    # fragmented request with facks, fragmented response
    req = wr_setvalue_req(NDR(), 2, 'Frag', bytes(range(200)))
    parts = [req[0:100], req[100:200], req[200:]]
    for i, p in enumerate(parts):
        f1 = 0x04 | (0x02 if i == 2 else 0) | (0x08 if i == 0 else 0)
        u.c(cl_pdu(0, WINREG, 22, 3, p, flags1=f1, frag=i, serial=i))
        if i == 0:
            u.s(cl_pdu(9, WINREG, 22, 3, struct.pack('<BxHIIHH', 1, 4, 65000, 1464, 0, 2) +
                       struct.pack('<II', 1, 0), flags1=0, frag=0))
        if i == 1:
            u.s(cl_pdu(9, WINREG, 22, 3, struct.pack('<BxHIIHH', 0, 4, 65000, 1464, 1, 0),
                       flags1=0, frag=1))
    u.s(cl_pdu(9, WINREG, 22, 3, b'', flags1=0, frag=2))
    resp = wr_queryvalue_resp(NDR(), 3, bytes(range(150)))
    u.c(cl_pdu(0, WINREG, 17, 4, wr_queryvalue_req(NDR(), 2, 'Frag', 150)))
    u.s(cl_pdu(2, WINREG, 17, 4, resp[:96], flags1=0x04, frag=0))
    u.s(cl_pdu(2, WINREG, 17, 4, resp[96:], flags1=0x06, frag=1))
    # nocall with and without a body, reject and fault
    u.c(cl_pdu(1, WINREG, 26, 5, b''))
    u.s(cl_pdu(5, WINREG, 26, 5, struct.pack('<BxHIIHH', 0, 4, 65000, 1464, 0, 0), flags1=0))
    u.s(cl_pdu(5, WINREG, 26, 5, b'', flags1=0))
    u.c(cl_pdu(0, UNKNOWN_IF, 1, 6, b'\x01\x02\x03\x04'))
    u.s(cl_pdu(6, UNKNOWN_IF, 1, 6, struct.pack('<I', 0x1c010003), flags1=0))
    u.c(cl_pdu(0, WINREG, 26, 7, NDR().handle(2).bytes()))
    u.s(cl_pdu(3, WINREG, 26, 7, struct.pack('<I', 0x1c010002), flags1=0))
    # cancel and cancel_ack, with and without a body, unknown version
    u.c(cl_pdu(0, WINREG, 9, 8, wr_enumkey_req(NDR(), 2, 0)))
    u.c(cl_pdu(8, WINREG, 9, 8, struct.pack('<II', 0, 1), flags2=0x02))
    u.s(cl_pdu(10, WINREG, 9, 8, struct.pack('<IIB', 0, 1, 1) + b'\0\0\0', flags1=0))
    u.c(cl_pdu(8, WINREG, 9, 8, b''))
    u.s(cl_pdu(10, WINREG, 9, 8, b'', flags1=0))
    u.c(cl_pdu(8, WINREG, 9, 8, struct.pack('<II', 1, 2)))
    u.s(cl_pdu(10, WINREG, 9, 8, struct.pack('<II', 1, 2), flags1=0))
    # a response without its request
    u.s(cl_pdu(2, WINREG, 26, 99, wr_getversion_resp(NDR()), flags1=0))
    # authentication verifiers: Kerberos privacy and integrity, other
    u.c(cl_pdu(0, WINREG, 26, 10, NDR().handle(2).bytes(), auth_proto=1,
               auth=bytes([6, 1]) + b'\0' * 6 + b'\x5a' * 16))
    u.s(cl_pdu(2, WINREG, 26, 10, wr_getversion_resp(NDR()), flags1=0, auth_proto=1,
               auth=bytes([5, 1]) + b'\0' * 2 + b'\x5b' * 16))
    u.c(cl_pdu(0, WINREG, 26, 11, NDR().handle(2).bytes(), auth_proto=10, auth=b'\x5c' * 16))


# ================================================================ malformed

def sec_ndr64_counts(cap):
    """dcerpc_ndr64_count_assert reproducer and its siblings: NDR64 array
    counts and offsets above 2^32-1 (expert info and exception, an
    assertion before the fix)."""
    t, r = tcp_co(cap, 51001, 49152, ndr64=True)
    r.send_c(r.bind([(0, WINREG, [(NDR64, 1)])]))
    r.send_s(r.bind_ack([(0, 0, (NDR64, 1))], 1))
    # QueryValue, conformant varying array max_count 2^32 (ucvarray_core)
    stub = b'\0' * 20 + b'\0' * 4 + struct.pack('<HH', 0, 0) + b'\0' * 4
    stub += struct.pack('<QQQ', 0, 0, 0x20000)
    stub += struct.pack('<QQQ', 0x100000000, 0, 4) + b'\0' * 32
    r.call(17, stub, None)
    # the same with a large offset and a large actual count
    for i, hdr in enumerate(((16, 0x100000002, 4), (16, 0, 0x100000003))):
        stub = b'\0' * 20 + b'\0' * 4 + struct.pack('<HH', 0, 0) + b'\0' * 4
        stub += struct.pack('<QQQ', 0, 0, 0x20000) + struct.pack('<QQQ', *hdr) + b'\0' * 32
        r.call(17, stub, None)
    # OpenKey, conformant varying string actual count 2^32 (cvstring)
    stub = NDR(True, True).handle(1).sa().u16(4).u16(4).ptr(REF).se().bytes()
    stub += struct.pack('<QQQ', 2, 0, 0x100000000) + b'\0' * 16
    r.call(15, stub, None)
    t.fin()
    # BUDB over NDR64: varying string (vstring) and varying array (uvarray)
    t, r = tcp_co(cap, 51002, 49153, ndr64=True)
    r.send_c(r.bind([(0, BUDB, [(NDR64, 1)])]))
    r.send_s(r.bind_ack([(0, 0, (NDR64, 1))], 1))
    r.call(4, struct.pack('<QQQ', 0x20000, 0, 1 << 32) + b'A' * 16, None)
    r.call(16, struct.pack('<IIII', 1, 2, 0, 0) + struct.pack('<QQ', 1 << 32, 3) + b'\0' * 16, None)
    t.fin()


def sec_auth_warnings(cap):
    """Authentication data that cannot be dissected: a verifier on a PDU
    type without one, a registered type without an AUTH3 handler, an
    auth_len that does not fit."""
    t, r = tcp_co(cap, 51003, 49152)
    r.send_c(r.bind([(0, WINREG, [(NDR32, 2)])], auth=r.auth(10, 5, ntlm_negotiate())))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2))], 1, auth=r.auth(10, 5, ntlm_challenge())))
    for pt in (1, 4, 5, 6, 7, 8, 9, 10):
        r.send_c(r.pdu(pt, b'', 1, auth=r.auth(10, 5, ntlm_verifier(pt))))
    r.send_c(r.pdu(16, b'\0\0\0\0', 1, auth=r.auth(68, 5, b'\0' * 32)))
    r.send_c(r.pdu(0, struct.pack('<IHH', 4, 0, 26) + b'\0' * 20, 2, auth_len=200))
    t.fin()


def sec_cn_malformed(cap):
    """Connection-oriented malformed cases: long stub, truncated stubs,
    bad verification trailer, truncated RTS, unknown RTS command."""
    t, r = tcp_co(cap, 51004, 49152)
    r.send_c(r.bind([(0, WINREG, [(NDR32, 2)])]))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2))], 1))
    r.call(26, r.n().handle(1).bytes() + b'\xee' * 8, wr_getversion_resp(r.n()))     # long frame
    r.call(15, r.n().handle(1).u16(10).u16(10).ptr(REF).u32(5).bytes(), None)      # truncated
    # trailer signature followed by a command that runs past the end
    r.call(26, r.n().handle(1).bytes() + SIG + struct.pack('<HH', 0x0002, 40) + b'\0' * 8, None)
    # trailer with an extra command after the stub
    r.call(26, r.n().handle(1).bytes() + b'\0' * 4 + vtrailer(True, 0, 9, 0, 26, extra=False), None)
    r.send_c(rts_pdu(r, 0x00, [0xF]))                      # unknown RTS command
    r.send_c(r.pdu(20, struct.pack('<HH', 0, 1) + struct.pack('<II', 8, 1000) + b'\0' * 8, 0))
    t.fin()
    # PDUs cut short by the snapshot length: a fragment and a request
    t, r = tcp_co(cap, 51005, 49152)
    r.send_c(r.bind([(0, WINREG, [(NDR32, 2)])]))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2))], 1))
    r.call_id += 1
    stub = wr_setvalue_req(r.n(), 2, 'Cut', bytes(400))
    r.send_c(r.request(r.call_id, 22, stub[:200], flags=PFC_FIRST, alloc=len(stub)))
    t.cap.frames[-1] = (t.cap.frames[-1], 120)
    r.send_c(r.request(r.call_id, 22, stub[200:], flags=PFC_LAST, alloc=len(stub)))
    r.call_id += 1
    r.send_c(r.request(r.call_id, 26, r.n().handle(1).bytes()))
    t.cap.frames[-1] = (t.cap.frames[-1], 80)
    # a fragmented fault whose last fragment is cut short
    r.send_s(r.fault(r.call_id, 0x6f7, b'\x01' * 40, flags=PFC_FIRST))
    r.send_s(r.fault(r.call_id, 0x6f7, b'\x02' * 40, flags=PFC_LAST))
    t.cap.frames[-1] = (t.cap.frames[-1], 90)
    t.fin()


def sec_cl_malformed(cap):
    """Connectionless: truncated fragments and stubs."""
    u = CL(cap, cport=49301)
    req = wr_setvalue_req(NDR(), 2, 'Frag', bytes(range(200)))
    u.c(cl_pdu(0, WINREG, 22, 21, req[:100], flags1=0x04, frag=0))
    cap.frames[-1] = (cap.frames[-1], 150)
    u.c(cl_pdu(0, WINREG, 22, 21, req[100:], flags1=0x06, frag=1))
    cap.frames[-1] = (cap.frames[-1], 150)
    u.c(cl_pdu(0, WINREG, 26, 22, b'\0' * 8))
    u.c(cl_pdu(0, WINREG, 26, 23, b'\0' * 20, frag_len=400))
    u.c(cl_pdu(9, WINREG, 26, 23, struct.pack('<BxHIIHH', 1, 4, 65000, 1464, 0, 50)))


def sec_misc_malformed(cap):
    """A zero fragment length after a PDU, an exception inside an HTTP body
    with several PDUs, an authentication header cut short."""
    t, r = tcp_co(cap, 51007, 49152)
    r.send_c(r.bind([(0, WINREG, [(NDR32, 2)])]) + bytes([5, 0, 0, 3, 0x10, 0, 0, 0]) + b'\0' * 8)
    t.fin()
    t = TCP(cap, 51008, 80)
    r = CO(t.c2s, t.s2c)
    body = r.bind([(0, WINREG, [(NDR32, 2)])]) + r.pdu(11, struct.pack('<HHIB3x', 1, 1, 0, 5), 2)
    body += r.bind([(0, WINREG, [(NDR32, 2)])], 3)
    t.c2s(b'RPC_IN_DATA /rpc/rpcproxy.dll HTTP/1.1\r\nContent-Type: application/rpc\r\n'
          b'Content-Length: %d\r\n\r\n' % len(body) + body)
    t.fin()
    t, r = tcp_co(cap, 51009, 49152)
    r.send_c(r.bind([(0, WINREG, [(NDR32, 2)])]))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2))], 1))
    p = r.request(2, 26, r.n().handle(1).bytes(), auth=r.auth(10, 5, ntlm_verifier(0)))
    r.send_c(p)
    cap.frames[-1] = (cap.frames[-1], len(cap.frames[-1]) - 20)
    t.fin()


# ---------------------------------------------------------------- more interfaces

WINSPOOL = ('76f03f96-cdfd-44fc-a22c-64950a001209', 1, 0)
MESSENGER = ('5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc', 1, 0)
CONV = ('333a2276-0000-0000-0d00-00809c000000', 3, 0)


def cvstr8(n, s):
    t = s.encode() + b'\0'
    return n.u3264(len(t)).u3264(0).u3264(len(t)).raw(t)


def sec_more_cn(cap):
    """More NDR helpers: byte arrays and 64-bit integers (WINSPOOL), char
    strings (MESSENGER, also EBCDIC), NULL and NDR64 full pointers (EPM),
    an unnamed transfer syntax, a reused call ID."""
    t, r = tcp_co(cap, 50016, 49152)
    r.send_c(r.bind([(0, WINSPOOL, [(NDR32, 2)]), (1, MESSENGER, [(NDR32, 2)]),
                     (2, WINREG, [(ODD_TS, 1)])]))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2)), (0, 0, (NDR32, 2)), (2, 2, (ODD_TS, 1))], 1))
    # AsyncSetJob: unique pointer to a byte array, then a NULL one
    r.call(2, r.n().handle(4).u32(17).ptr(REF).u32(6).u32(0).u32(6).raw(b'JOBCTR').align(4)
           .u32(3).bytes(), wr_status(r.n()))
    r.call(2, r.n().handle(4).u32(18).ptr(0).u32(4).bytes(), wr_status(r.n()))
    # AsyncCorePrinterDriverInstalled: GUID, FILETIME and a uint64
    n = r.n().ptr(REF).cvwstr('\\\\PRINTSRV').cvwstr('Windows x64')
    n.align(4).raw(uuid_bytes('4d36e979-e325-11ce-bfc1-08002be10318')).nttime(0x01d0000000000000)
    n.u64(0x000a000000004a61)
    r.call(65, n.bytes(), r.n().u32(1).u32(0).bytes())
    # NetrSendMessage: three char strings
    n = r.n()
    cvstr8(n, 'SERVER')
    cvstr8(n.align(4), 'client')
    cvstr8(n.align(4), 'hello')
    r.call(0, n.bytes(), r.n().u32(0).bytes(), ctx=1)
    # the same call ID twice
    r.call_id -= 1
    r.call(0, n.bytes(), r.n().u32(0).bytes(), ctx=1)
    t.fin()
    # EBCDIC character set
    t, r = tcp_co(cap, 50017, 49152, drep=bytes([0x11, 0, 0, 0]))
    r.send_c(r.bind([(0, MESSENGER, [(NDR32, 2)])]))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2))], 1))
    n = r.n()
    for s in ('SERVER', 'CLIENT', 'HI'):
        t8 = s.encode('cp500') + b'\0'
        n.align(4).u32(len(t8)).u32(0).u32(len(t8)).raw(t8)
    r.call(0, n.bytes(), r.n().u32(0).bytes())
    t.fin()
    # EPM: NULL object, NULL tower pointer in the response, then NDR64
    t, r = tcp_co(cap, 50018, 135)
    r.send_c(r.bind([(0, EPM, [(NDR32, 2)])]))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2))], 1, secaddr=b'135\0'))
    tw = epm_tower(49152)
    n = r.n().ptr(0).ptr(2).u32(len(tw)).u32(len(tw)).raw(tw).align(4).handle(0).u32(4)
    r.call(3, n.bytes(), epm_map_resp(r.n(), [tw], [0, 0x30001]))
    t.fin()
    t, r = tcp_co(cap, 50019, 135, ndr64=True)
    r.send_c(r.bind([(0, EPM, [(NDR64, 1)])]))
    r.send_s(r.bind_ack([(0, 0, (NDR64, 1))], 1, secaddr=b'135\0'))
    r.call(3, epm_map_req(r.n()), epm_map_resp(r.n(), [tw], [0x30001]))
    t.fin()


def sec_heur_reject(cap):
    """TCP and UDP payloads that the DCE/RPC heuristics reject."""
    t = TCP(cap, 50020, 7777)
    for b in (bytes([5, 2, 0, 3]) + b'\x10\0\0\0' + b'\x10\0\0\0\0\0\0\0',   # minor 2
              bytes([5, 0, 21, 3]) + b'\x10\0\0\0' + b'\x10\0\0\0\0\0\0\0',  # type 21
              bytes([5, 0, 0, 3]) + b'\x12\0\0\0' + b'\x10\0\0\0\0\0\0\0',   # drep
              bytes([5, 0, 0, 3]) + b'\x10\x04\0\0' + b'\x10\0\0\0\0\0\0\0',  # float
              bytes([5, 0, 0, 3]) + b'\x10\0\0\0' + b'\x08\0\0\0\0\0\0\0'):  # frag_len
        t.c2s(b)
    t.fin()
    u = CL(cap, cport=49302, sport=7778)
    good = cl_pdu(1, WINREG, 0, 1, b'')
    for b in (bytes([4, 11]) + good[2:],                    # type 11
              good[:3] + bytes([0x04]) + good[4:],          # flags2
              good[:4] + bytes([0x12]) + good[5:],          # drep
              good[:5] + bytes([4]) + good[6:]):            # float
        u.c(b)


def smb1(cmd, mid, words, data, resp=False):
    h = b'\xffSMB' + struct.pack('<BIBHH8sHHHHH', cmd, 0, 0x98 if resp else 0x18, 0x4807, 0,
                                 b'\0' * 8, 0, 0x0801, 0x1234, 0x0800, mid)
    return nbss(h + struct.pack('<B', len(words) // 2) + words + struct.pack('<H', len(data)) + data)


def sec_smb(cap):
    """DCE/RPC over SMB1 TransactNmPipe and over SMB2 writes and reads,
    with a PDU split over two SMB2 writes and a short tail."""
    t = TCP(cap, 50021, 445)
    r = CO(None, None)

    def trans(mid, pdu):
        words = struct.pack('<HHHHBBHIHHHHHBBHH', 0, len(pdu), 0, 1024, 0, 0, 0, 0, 0,
                            0, 76, len(pdu), 76, 2, 0, 0x0026, 0x4001)
        t.c2s(smb1(0x25, mid, words, b'\\PIPE\\\0' + b'\0\0' + pdu))

    def trans_resp(mid, pdu):
        words = struct.pack('<HHHHHHHHHBB', 0, len(pdu), 0, 0, 56, 0, len(pdu), 56, 0, 0, 0)
        t.s2c(smb1(0x25, mid, words, b'\0' + pdu, True))
    trans(1, r.bind([(0, WINREG, [(NDR32, 2)])]))
    trans_resp(1, r.bind_ack([(0, 0, (NDR32, 2))], 1, secaddr=b'\\PIPE\\winreg\0'))
    trans(2, r.request(2, 2, wr_openhklm_req(r.n())))
    trans_resp(2, r.response(2, wr_handle_resp(r.n(), 1)))
    t.fin()
    t = TCP(cap, 50022, 445)
    fid = struct.pack('<QQ', 0x3333, 0x4444)

    def write(mid, data):
        w = struct.pack('<HHIQ', 49, 112, len(data), 0) + fid + struct.pack('<IIHHI', 0, 0, 0, 0, 0)
        t.c2s(nbss(smb2_hdr(9, mid) + w + data))
        t.s2c(nbss(smb2_hdr(9, mid, True) + struct.pack('<HHIIHH', 17, 0, len(data), 0, 0, 0)))
    bind = r.bind([(0, SRVSVC, [(NDR32, 2)])])
    write(10, bind[:40])
    write(11, bind[40:])
    req = r.request(2, 23, sv_diskenum_req(r.n()))
    write(12, req + req[:8])
    t.fin()


def sec_conv(cap):
    """CONV callbacks over UDP: 32-bit time_t, also "no time"."""
    u = CL(cap, cport=49303, sport=49304)
    act = uuid_bytes('6b8c0000-0000-4000-8000-0000000000c1')
    for seq, boot in ((40, 0x60000000), (41, 0xffffffff)):
        u.s(cl_pdu(0, CONV, 0, seq, act + struct.pack('<I', boot), act='6b8c0000-0000-4000-8000-0000000000c2'))
        u.c(cl_pdu(2, CONV, 0, seq, struct.pack('<II', 7, 0), flags1=0,
                   act='6b8c0000-0000-4000-8000-0000000000c2'))


NETLOGON = ('12345678-1234-abcd-ef00-01234567cffb', 1, 0)


def sec_netlogon_smb2_compound(cap):
    """A conformant array dissected as one block (NETLOGON), an SMB2
    compound whose second write holds only the start of a PDU header, and
    a UDP datagram too short for connectionless DCE/RPC."""
    t, r = tcp_co(cap, 50023, 49152)
    r.send_c(r.bind([(0, NETLOGON, [(NDR32, 2)])]))
    r.send_s(r.bind_ack([(0, 0, (NDR32, 2))], 1))
    n = r.n().ptr(REF).cvwstr('\\\\DC1').u32(5).ptr(REF + 4).u32(8).raw(b'DIGESTME').u32(1)
    r.call(24, n.bytes(), r.n().ptr(REF).raw(b'\x5d' * 16).u32(0).bytes())
    t.fin()
    t = TCP(cap, 50024, 445)
    fid = struct.pack('<QQ', 0x5555, 0x6666)
    rr = CO(None, None)
    bind = rr.bind([(0, SRVSVC, [(NDR32, 2)])])
    req = rr.request(2, 23, sv_diskenum_req(rr.n()))

    def wmsg(mid, data, nxt):
        w = struct.pack('<HHIQ', 49, 112, len(data), 0) + fid + struct.pack('<IIHHI', 0, 0, 0, 0, 0)
        h = bytearray(smb2_hdr(9, mid))
        m = h + w + data
        if nxt:
            m += b'\0' * ((-len(m)) % 8)
            struct.pack_into('<I', m, 20, len(m))
        return bytes(m)
    t.c2s(nbss(wmsg(20, bind, True) + wmsg(21, req[:8], False)))
    t.c2s(nbss(wmsg(22, req[8:16], False)))
    t.c2s(nbss(wmsg(23, req[16:], False)))
    t.fin()
    udp(cap, (192, 0, 2, 30), (192, 0, 2, 40), 49305, 7779, b'\x04\x00short', 3, 4)
    udp(cap, (192, 0, 2, 30), (192, 0, 2, 40), 49305, 7779, b'\x07' + b'Z' * 99, 3, 4)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    cap = Pcap()
    sec_winreg_le(cap)
    sec_winreg_be(cap)
    sec_winreg_ndr64(cap)
    sec_ntlmssp(cap)
    sec_privacy(cap)
    sec_unknown_iface(cap)
    sec_epm(cap)
    sec_budb(cap)
    drsuapi_list(cap, 50015, 100)
    sec_rts(cap)
    sec_http(cap)
    sec_netbios(cap)
    sec_smb2(cap)
    sec_smb(cap)
    sec_more_cn(cap)
    sec_heur_reject(cap)
    sec_netlogon_smb2_compound(cap)
    sec_cl(cap)
    sec_conv(cap)
    cap.write(out + '/dcerpc-coverage.pcap')
    print('dcerpc-coverage.pcap', len(cap.frames), 'frames')

    cap = Pcap()
    sec_ndr64_counts(cap)
    drsuapi_list(cap, 51006, 300)
    sec_bind_nak(cap)
    sec_auth_warnings(cap)
    sec_cn_malformed(cap)
    sec_cl_malformed(cap)
    sec_misc_malformed(cap)
    cap.write(out + '/dcerpc-coverage-malformed.pcap')
    print('dcerpc-coverage-malformed.pcap', len(cap.frames), 'frames')


if __name__ == '__main__':
    main()
