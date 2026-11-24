#!/usr/bin/env python3
# Generates test/captures/dcerpc_mapi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""mkmapi.py <outdir>: write dcerpc_mapi-coverage.pcap and
dcerpc_mapi-coverage-malformed.pcap, synthetic MAPI (EMSMDB) traffic over
connection-oriented DCE/RPC on TCP for the MAPI dissector
(packet-dcerpc-mapi.c, generated from epan/dissectors/pidl/mapi/).

Every packet is built here with struct; nothing comes from a real network.
The ROP and AUX payloads come from ropgen.py and mapi_spec.json (see
extract_spec.py)."""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
from ropgen import rop, rop_ids, aux_block, lz77_compress  # noqa: E402

UUID_MAPI = 'a4f1db00-ca47-1067-b31f-00dd010662da'
VER_MAPI = (0, 82)
UUID_NDR = '8a885d04-1ceb-11c9-9fe8-08002b104860'
UUID_NDR64 = '71710533-beba-4937-8319-b5dbef9ccc36'
TS = 1700000000


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
            f.write(struct.pack('<IIII', TS + i // 10, 100000 * (i % 10), len(fr), len(fr)))
            f.write(fr)


class TCP:
    """One TCP connection with handshake; segments of at most 1460 octets."""
    def __init__(self, frames, cport, sport=49155, cip=(192, 0, 2, 50), sip=(192, 0, 2, 60)):
        self.frames = frames
        self.c = (bytes(cip), cport)
        self.s = (bytes(sip), sport)
        self.cseq, self.sseq = 0x10000000 + cport * 7, 0x20000000 + cport * 11
        self.seg(True, b'', 0x02)
        self.cseq += 1
        self.seg(False, b'', 0x12)
        self.sseq += 1
        self.seg(True, b'', 0x10)

    def send(self, from_client, payload):
        for i in range(0, len(payload), 1460):
            self.seg(from_client, payload[i:i + 1460])

    def seg(self, from_client, payload, flags=0x18):
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        seq = self.cseq if from_client else self.sseq
        ack = self.sseq if from_client else self.cseq
        if flags == 0x02:
            ack = 0
        opts = struct.pack('>BBH', 2, 4, 1460) if flags & 0x02 else b''
        tcp = struct.pack('>HHIIBBHHH', src[1], dst[1], seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        ph = src[0] + dst[0] + struct.pack('>BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('>H', csum(ph + tcp + payload)) + tcp[18:]
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 0, 0x4000, 64, 6, 0,
                         src[0], dst[0])
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        mc, ms = bytes.fromhex('020000000050'), bytes.fromhex('020000000060')
        eth = (ms + mc) if from_client else (mc + ms)
        self.frames.append(eth + b'\x08\x00' + ip + tcp + payload)
        if from_client:
            self.cseq += len(payload)
        else:
            self.sseq += len(payload)

    def fin(self):
        self.seg(True, b'', 0x11)
        self.cseq += 1
        self.seg(False, b'', 0x11)
        self.sseq += 1
        self.seg(True, b'', 0x10)


class RPC:
    """CO DCE/RPC on one TCP connection, MAPI bound with NDR or NDR64."""
    def __init__(self, tcp, le=True, ndr64=False):
        self.tcp, self.le, self.ndr64 = tcp, le, ndr64
        self.e = '<' if le else '>'
        self.call_id = 0

    def uuid_bytes(self, u):
        h = u.replace('-', '')
        return struct.pack(self.e + 'IHH', int(h[0:8], 16), int(h[8:12], 16), int(h[12:16], 16)) + bytes.fromhex(h[16:])

    def pdu(self, ptype, body, call_id, flags=0x03):
        drep = bytes([0x10 if self.le else 0x00, 0, 0, 0])
        return struct.pack('BBBB', 5, 0, ptype, flags) + drep + struct.pack(self.e + 'HHI', 16 + len(body), 0, call_id) + body

    def bind(self):
        self.call_id += 1
        ts = (UUID_NDR64, 1) if self.ndr64 else (UUID_NDR, 2)
        body = struct.pack(self.e + 'HHI', 5840, 5840, 0) + struct.pack(self.e + 'B3x', 1)
        body += struct.pack(self.e + 'HBx', 0, 1) + self.uuid_bytes(UUID_MAPI)
        body += struct.pack(self.e + 'HH', VER_MAPI[0], VER_MAPI[1])
        body += self.uuid_bytes(ts[0]) + struct.pack(self.e + 'I', ts[1])
        self.tcp.send(True, self.pdu(11, body, self.call_id))
        sec = b'49155\0'
        body = struct.pack(self.e + 'HHI', 5840, 5840, 0x12345) + struct.pack(self.e + 'H', len(sec)) + sec
        body += b'\0' * ((-(16 + len(body))) % 4)
        body += struct.pack(self.e + 'B3x', 1) + struct.pack(self.e + 'HH', 0, 0)
        body += self.uuid_bytes(ts[0]) + struct.pack(self.e + 'I', ts[1])
        self.tcp.send(False, self.pdu(12, body, self.call_id))

    def call(self, opnum, req, resp):
        self.call_id += 1
        self.tcp.send(True, self.pdu(0, struct.pack(self.e + 'IHH', len(req), 0, opnum) + req, self.call_id))
        if resp is not None:
            self.tcp.send(False, self.pdu(2, struct.pack(self.e + 'IHBB', len(resp), 0, 0, 0) + resp, self.call_id))


class Stub:
    """An NDR stub body (offsets are relative to the stub start)."""
    def __init__(self, le=True, ndr64=False):
        self.b = bytearray()
        self.e = '<' if le else '>'
        self.ndr64 = ndr64

    def align(self, n):
        self.b += bytes((-len(self.b)) % n)

    def u8(self, v):
        self.b += struct.pack('B', v)

    def u16(self, v):
        self.align(2)
        self.b += struct.pack(self.e + 'H', v)

    def u32(self, v):
        self.align(4)
        self.b += struct.pack(self.e + 'I', v)

    def u3264(self, v):
        if self.ndr64:
            self.align(8)
            self.b += struct.pack(self.e + 'Q', v)
        else:
            self.u32(v)

    def ptr(self, v=0x00020000):
        self.u3264(v)

    def policy(self, n=1):
        self.align(4)
        self.b += struct.pack(self.e + 'I', 0) + bytes([n]) * 16

    def raw(self, b):
        self.b += b

    def cvstring(self, s):
        data = s.encode() + b'\0'
        self.u3264(len(data))
        self.u3264(0)
        self.u3264(len(data))
        self.raw(data)

    def version(self, v):
        self.raw(struct.pack('<HHH', *v))   # normalize_version reads LE

    def bytes(self):
        return bytes(self.b)


def xor(b):
    return bytes(x ^ 0xA5 for x in b)


def hdr_ext(payload, mode='plain', flags=None, le=True):
    """RPC_HEADER_EXT and the payload in the form mode."""
    e = '<' if le else '>'
    if mode == 'plain':
        body, fl = payload, 0x0004
    elif mode == 'xor':
        body, fl = xor(payload), 0x0006
    elif mode == 'lz77':
        body, fl = lz77_compress(payload), 0x0005
    else:
        raise ValueError(mode)
    if flags is not None:
        fl = flags
    return struct.pack(e + 'HHHH', 0, fl, len(body), len(payload)) + body


def rop_buffer(rops, le=True, pad_to=64, handles=None):
    """ropSize, the ROPs, handles.  The ROPs are built at offset 2; one
    that aligns fields gets RopNone (0x00) octets before it so that it
    starts at 2 mod 8 again."""
    e = '<' if le else '>'
    body = b''
    for r in rops:
        b, align = (r, True) if not isinstance(r, tuple) else r
        if align:
            body += bytes((-len(body)) % 8)
        body += b
    out = struct.pack(e + 'H', 2 + len(body)) + body
    hs = handles if handles is not None else [0x00000001, 0xffffffff]
    out += b''.join(struct.pack(e + 'I', h) for h in hs)
    while len(out) < pad_to:
        out += struct.pack(e + 'I', 0xffffffff)
    return out


# ------------------------------------------------------------ the calls
def connect_req(s, ex, dn, ver, aux=None):
    s.cvstring(dn)
    for v in (0, 0x42, 0x8000, 1252, 0x409, 0x409, 0xffffffff):
        s.u32(v)
    s.u16(1)
    s.version(ver)
    s.u32(0)                      # pullTimeStamp
    if ex:
        auxin(s, aux)
        s.u32(0x1008)


def connect_resp(s, ex, aux=None, null_prefix=False):
    s.policy(2)
    for v in (60000, 6, 10000, 0x1234):
        s.u32(v)
    if null_prefix:
        s.ptr(0)
    else:
        s.ptr(0x00020000)
        s.cvstring('/o=Example/ou=Exchange Administrative Group/cn=Configuration')
    s.ptr(0x00020004)
    s.cvstring('Example User')
    s.version((15, 0x8000 | 1497, 2))
    s.version((0x0800, 4417, 0))
    s.u32(0x5f5e100)
    if ex:
        if aux is None:
            s.u3264(0)
            s.u3264(0)
            s.u3264(0)
            s.u32(0)
        else:
            s.u3264(len(aux))
            s.u3264(0)
            s.u3264(len(aux))
            s.raw(aux)
            s.u32(len(aux))
    s.u32(0)                      # WERROR


def auxin(s, aux):
    """rgbAuxIn: AuxInfo (auxInSize, RPC_HEADER_EXT, AUX blocks), cbAuxIn."""
    if aux is None:
        aux = hdr_ext(b'')
    s.align(4)
    s.u32(len(aux))
    s.raw(aux)
    s.align(4)
    s.u32(len(aux))


def rpcext_req(s, rgb, aux, ext2, flags=0):
    s.policy(3)
    s.u32(flags)
    s.u3264(len(rgb))
    s.raw(rgb)
    s.align(4)
    s.u32(len(rgb))
    s.u32(0x40000)
    auxin(s, aux)
    if ext2:
        s.u32(0x1008)


def rpcext_resp(s, rgb, k, ext2, aux=None, actual=None):
    s.policy(3)
    s.u32(0)
    s.u3264(k)                    # max count: the array count in the ROPs
    s.u3264(0)
    s.u3264(len(rgb) if actual is None else actual)
    s.raw(rgb)
    s.align(4)
    s.u32(len(rgb))
    if ext2:
        if aux is None:
            s.u3264(0)
            s.u3264(0)
            s.u3264(0)
            s.u32(0)
        else:
            s.u3264(len(aux))
            s.u3264(0)
            s.u3264(len(aux))
            s.raw(aux)
            s.align(4)
            s.u32(len(aux))
    s.u32(1500)                   # pulTransTime
    s.u32(0)


def ecdorpc_req(s, rop_bytes, handles=(1, 2)):
    inner = struct.pack('<H', 2 + len(rop_bytes)) + rop_bytes + b''.join(struct.pack('<I', h) for h in handles)
    s.policy(4)
    s.u32(0x8000)
    s.u32(0)
    s.u32(len(inner))
    s.raw(xor(inner))
    s.u16(len(inner))
    s.u16(0x8000)


def ecdorpc_resp(s, rop_bytes, handles=(1,)):
    inner = struct.pack('<H', 2 + len(rop_bytes)) + rop_bytes + b''.join(struct.pack('<I', h) for h in handles)
    s.policy(4)
    s.u32(len(inner))
    s.u32(0)
    s.u32(len(inner))
    s.raw(xor(inner))
    s.u16(len(inner))
    s.u32(0)


# ------------------------------------------------------------ payloads
import subprocess
import tempfile

TSHARK = os.environ.get('TSHARK', 'tshark')


def gen_rops(request, k, le=True, ndr64=False, max_variants=10):
    """Candidate variants of every ROP, until the arms stop growing."""
    covered = set()
    out = []           # (ropid, (bytes, needs_align), ended, overrun, arms)
    for rid in rop_ids(request):
        same = 0
        for seed in range(max_variants):
            g = rop(rid, request, k=k, le=le, ndr64=ndr64, seed=seed)
            new = not g.arms <= covered
            covered |= g.arms
            out.append((rid, (bytes(g.buf), g.needs_align), g.ended, g.overrun, frozenset(g.arms)))
            same = 0 if new else same + 1
            if same >= 2:
                break
    return out


def probe(cands, k, request, cfgdir):
    """Dissect each candidate ROP alone in an EcDoRpcExt2 call and keep
    those that decode cleanly as exactly that ROP (then a RopRelease
    marker).  Returns the clean candidates with their arm sets."""
    F = []
    t = TCP(F, 50099)
    r = RPC(t)
    r.bind()
    exp = {}
    for rid, b, ended, over, arms in cands:
        if over:
            continue
        if request:
            s = Stub()
            rpcext_req(s, hdr_ext(rop_buffer([b, (b'\x01\x00\x00', False)])), None, True)
            r.call(11, s.bytes(), None)
        else:
            s = Stub()
            rpcext_req(s, hdr_ext(rop_buffer([(b'\x01\x00\x00', False)])), None, True)
            s2 = Stub()
            rpcext_resp(s2, hdr_ext(rop_buffer([b, (b'\x01', False)])), k, True)
            r.call(11, s.bytes(), s2.bytes())
        exp[len(F)] = (rid, ended, arms, b)
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tf:
        write_pcap(tf.name, F)
        path = tf.name
    field = 'mapi.RopInput.RopId' if request else 'mapi.RopOutput.RopId'
    out = subprocess.run(
        ['timeout', '-s', 'KILL', '120', TSHARK, '-r', path,
         '-Tfields', '-eframe.number', '-e' + field, '-e_ws.malformed', '-e_ws.expert.severity'],
        capture_output=True, text=True, env=dict(os.environ, WIRESHARK_CONFIG_DIR=cfgdir)).stdout
    os.unlink(path)
    clean = []
    for line in out.splitlines():
        f = (line.split('\t') + ['', '', ''])[:4]
        n = int(f[0])
        if n not in exp:
            continue
        rid, ended, arms, b = exp[n]
        ids = f[1].split(',') if f[1] else []
        want = ['0x%02x' % rid] + ([] if ended else ['0x01'])
        if ids == want and not f[2] and not f[3]:
            clean.append((rid, b, ended, arms))
    return clean


def select(clean):
    """Greedy: keep variants until every arm seen is covered."""
    allarms = set()
    for _, _, _, arms in clean:
        allarms |= arms
    chosen, cov = [], set()
    for rid, b, ended, arms in clean:
        if not arms <= cov:
            chosen.append((rid, b, ended, arms))
            cov |= arms
    return chosen, allarms, cov


def pack_buffers(rops, limit=700):
    """Group ROPs into buffers; a ROP that swallows the rest goes last."""
    bufs, cur, size = [], [], 0
    for rid, b, ended, arms in rops:
        cur.append(b)
        size += len(b[0])
        if ended or size > limit:
            bufs.append(cur)
            cur, size = [], 0
    if cur:
        bufs.append(cur)
    return bufs


AUX_V1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
          0x13, 0x14, 0x15, 0x17]
AUX_V2 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
          0x13, 0x14, 0x15, 0x17]


def aux_payload(blocks, le=True):
    """AUX blocks in one buffer; (version, type) pairs, offsets kept."""
    out = b''
    for i, (ver, typ) in enumerate(blocks):
        b, g = aux_block(ver, typ, seed=i, base=len(out), le=le)
        out += b
        if g.ended:               # a remaining-blob block swallows the rest
            break
    return out


def clientinfo_repro(le=True):
    """AUX_PERF_CLIENTINFO whose offsets are, per [MS-OXCRPC] 2.2.2.16,
    relative to its own AUX_HEADER (the dissector reads them as absolute
    into the whole AuxInfo buffer, 8 octets too early).  mapi_*.py repro."""
    e = '<' if le else '>'
    mach = 'HOSTNAME'.encode('utf-16-le') + b'\0\0'
    user = 'user'.encode('utf-16-le') + b'\0\0'
    mac = bytes.fromhex('020000000077')
    base = 4 + 28
    o_m = base
    o_u = o_m + len(mach)
    o_mac = o_u + len(user)
    fixed = struct.pack(e + 'IH', 1000000, 1)
    fixed += struct.pack(e + '9H', o_m, o_u, 0, 0, 0, 0, 0, 6, o_mac)
    fixed += struct.pack(e + 'HH', 1, 0)
    body = fixed + mach + user + mac
    ci = struct.pack(e + 'HBB', 4 + len(body), 1, 2) + body
    return struct.pack(e + 'HBBHH', 8, 1, 1, 0x1111, 0x2222) + ci


def lz77_bomb(n=64):
    """A <=64 KiB Plain LZ77 stream: one literal then n back-references of
    ~16 MiB each.  With the branch fix the decompressor caps the whole
    output at 16 MiB and returns nothing; without it, gigabytes.  (repro
    mapi_lz77_bomb.py)"""
    L = 16 * 1024 * 1024 - 3
    toks = [('lit', b'A')] + [('m', i) for i in range(n)]
    out = b''
    for g in range(0, len(toks), 32):
        grp = toks[g:g + 32]
        flags = 0
        body = b''
        for k, (kind, v) in enumerate(grp):
            if kind == 'lit':
                body += v
            else:
                flags |= 1 << (31 - k)
                if v % 2 == 0:
                    body += struct.pack('<HBBHI', 7, 0xFF, 0xFF, 0, L)
                else:
                    body += struct.pack('<HBHI', 7, 0xFF, 0, L)
        if len(grp) < 32:
            flags |= (1 << (32 - len(grp))) - 1
        out += struct.pack('<I', flags) + body
    if len(toks) % 32 == 0:
        out += struct.pack('<I', 0xFFFFFFFF)
    return out


def make_malformed(outdir):
    """Paths reached only by malformed input: exceptions and the branch
    reproducers.  Not added to the tree; used for coverage only."""
    F = []
    t = TCP(F, 50101)
    r = RPC(t)
    r.bind()

    # The two branch reproducers.
    # EcDoRpcExt rgbIn: RopSyncUploadStateStreamContinue, StreamDataSize
    # 0xFFFFFFFF.  With the fix tvb_ensure_bytes_exist64 throws (before,
    # the size moved the offset back and a phantom ROP was decoded).
    rops = struct.pack('<BBBI', 0x76, 0, 0, 0xFFFFFFFF) + struct.pack('<BBB', 0x01, 0, 0)
    payload = struct.pack('<H', 2 + len(rops)) + rops
    s = Stub()
    rpcext_req(s, struct.pack('<HHHH', 0, 4, len(payload), len(payload)) + payload, None, False)
    r.call(9, s.bytes(), None)

    # EcDoRpcExt rgbIn: the LZ77 decompression bomb.
    comp = lz77_bomb(64)
    s = Stub()
    rpcext_req(s, struct.pack('<HHHH', 0, 0x0005, len(comp), 16) + comp, None, False)
    r.call(9, s.bytes(), None)

    # LZ77 stream whose first token is a back-reference with no output yet
    # (match_off > produced bytes -> do_uncompress fails).
    bad_off = struct.pack('<IH', 0x80000000, 8)
    s = Stub()
    rpcext_req(s, struct.pack('<HHHH', 0, 0x0005, len(bad_off), 64) + bad_off, None, True)
    r.call(11, s.bytes(), None)

    # LZ77 stream with one match longer than the 16 MiB output cap.
    big = struct.pack('<I', 0x40000000) + b'A' + struct.pack('<HBBHI', 7, 0xFF, 0xFF, 0, 16 * 1024 * 1024 + 100)
    s = Stub()
    rpcext_req(s, struct.pack('<HHHH', 0, 0x0005, len(big), 64) + big, None, True)
    r.call(11, s.bytes(), None)

    # Nested RES_AND restriction (RopGetSearchCriteria reply, array count
    # 1): the dissector recurses with no depth guard; a short buffer runs
    # out and throws (a long one overflows the C stack - see README, kept
    # out of every capture).
    rop_b = b'\x31' + (bytes([0]) + struct.pack('<H', 1)) * 40 + bytes([0]) + struct.pack('<H', 0)
    s = Stub()
    rpcext_req(s, hdr_ext(rop_buffer([(b'\x01\x00\x00', False)])), None, True)
    s2 = Stub()
    rpcext_resp(s2, hdr_ext(rop_buffer([(rop_b, False)])), 1, True)
    r.call(11, s.bytes(), s2.bytes())

    # RopSynchronizationConfigure request: RestrictionData is a
    # "remaining" blob that consumes the rest of the ROP buffer, so the
    # SynchronizationExtraFlags/PropertyTags after it read past the end.
    rop_b = bytes([0x70, 1, 2, 3, 1, 0, 0]) + b'restriction-data-bytes'
    s = Stub()
    rpcext_req(s, hdr_ext(rop_buffer([(rop_b, False)])), None, True)
    r.call(11, s.bytes(), None)

    # AUX_TYPE_OSVERSIONINFO: Reserved_1 is a "remaining" blob, so the
    # ServicePack fields after it read past the end of the AUX buffer.
    av = aux_payload([(1, 0x16)])
    s = Stub()
    rpcext_req(s, hdr_ext(rop_buffer([(b'\x01\x00\x00', False)])),
               hdr_ext(av), True)
    r.call(11, s.bytes(), None)

    # RPC_HEADER_EXT flag branches that return without a payload and leave
    # the rest of the buffer undissected (a "Long frame"): not Last
    # (0x0001), Compressed+XorMagic (0x0007) and an unknown flag (0x0008).
    body = rop_buffer([(b'\x01\x00\x00', False)])
    for fl in (0x0001, 0x0007, 0x0008):
        s = Stub()
        rpcext_req(s, hdr_ext(body, flags=fl), None, True)
        r.call(11, s.bytes(), None)

    # RPC_HEADER_EXT with compressedSize past the end of the stub.
    s = Stub()
    rpcext_req(s, struct.pack('<HHHH', 0, 4, 0x4000, 0x4000) + b'\x10\x00short', None, True)
    r.call(11, s.bytes(), None)

    # A truncated obfuscated EcDoRpc request (pdu_len past the buffer).
    inner = struct.pack('<H', 0x4000) + b'\xfe' + b'\x01' * 8
    s = Stub()
    s.policy(4)
    s.u32(0x8000)
    s.u32(0)
    s.u32(len(inner))
    s.raw(xor(inner))
    s.u16(len(inner))
    s.u16(0x8000)
    r.call(2, s.bytes(), None)

    t.fin()
    write_pcap(os.path.join(outdir, 'dcerpc_mapi-coverage-malformed.pcap'), F)
    print('malformed: %d frames' % len(F))


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    F = []
    M = []

    # -- 1. EcDoConnect, EcDoConnectEx and the small calls (port 50001)
    t = TCP(F, 50001)
    r = RPC(t)
    r.bind()
    s = Stub()
    connect_req(s, False, '/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=user1',
                (15, 0x8000 | 1497, 2))
    s2 = Stub()
    connect_resp(s2, False)
    r.call(0, s.bytes(), s2.bytes())
    # older client version (build without the high bit), NULL DN prefix
    s = Stub()
    connect_req(s, False, '/o=Example/cn=user2', (11, 8000, 0))
    s2 = Stub()
    connect_resp(s2, False, null_prefix=True)
    r.call(0, s.bytes(), s2.bytes())
    # EcDoConnectEx with AUX in (plain) and AUX out (plain and LZ77)
    ai = aux_payload([(1, 1), (1, 2), (1, 0x0a), (1, 0x0b), (1, 0x17)])
    ao = aux_payload([(1, 3), (1, 4), (1, 5), (1, 0x0a), (1, 0x17)])
    s = Stub()
    connect_req(s, True, '/o=Example/cn=user1', (15, 0x8000 | 1497, 2), aux=hdr_ext(ai))
    s2 = Stub()
    connect_resp(s2, True, aux=hdr_ext(ao, 'lz77'))
    r.call(10, s.bytes(), s2.bytes())
    s = Stub()
    connect_req(s, True, '/o=Example/cn=user3', (12, 6000, 1), aux=hdr_ext(ai, 'xor'))
    s2 = Stub()
    connect_resp(s2, True, aux=hdr_ext(ao))
    r.call(10, s.bytes(), s2.bytes())
    s = Stub()
    connect_req(s, True, '/o=Example/cn=user4', (16, 0x8000 | 10, 3), aux=None)
    s2 = Stub()
    connect_resp(s2, True, aux=None)
    r.call(10, s.bytes(), s2.bytes())
    # EcDoConnectEx with the AUX_PERF_CLIENTINFO offset reproducer
    # (mapi_aux_clientinfo_offset.py): decodes, offsets read 8 octets early
    s = Stub()
    connect_req(s, True, '/o=Example/cn=user5', (15, 0x8000 | 1497, 2),
                aux=hdr_ext(clientinfo_repro()))
    s2 = Stub()
    connect_resp(s2, True, aux=None)
    r.call(10, s.bytes(), s2.bytes())
    # EcGetMoreRpc
    s = Stub()
    s.policy(2)
    s.u3264(32)
    s.u3264(0)
    s.u3264(8)
    s.raw(b'moredata')
    s.u16(8)
    s.u16(32)
    s2 = Stub()
    s2.policy(2)
    s2.u3264(32)
    s2.u3264(0)
    s2.u3264(6)
    s2.raw(b'\x01\x02\x03\x04\x05\x06')
    s2.u16(6)
    s2.u32(0)
    r.call(3, s.bytes(), s2.bytes())
    # EcRRegisterPushNotification / EcRUnregisterPushNotification
    s = Stub()
    s.policy(2)
    s.u32(1)
    ctx = b'notify-context'
    s.u3264(len(ctx))
    s.raw(ctx)
    s.u16(len(ctx))
    s.u32(0x0000ffff)
    cb = struct.pack('>HH4s8x', 2, 2000, bytes([192, 0, 2, 50]))
    s.u3264(len(cb))
    s.raw(cb)
    s.u16(len(cb))
    s2 = Stub()
    s2.policy(2)
    s2.u32(0x77)
    s2.u32(0)
    r.call(4, s.bytes(), s2.bytes())
    s = Stub()
    s.policy(2)
    s.u32(1)
    s.u32(0x77)
    s2 = Stub()
    s2.policy(2)
    s2.u32(0)
    r.call(5, s.bytes(), s2.bytes())
    # EcDummyRpc
    s2 = Stub()
    s2.u32(0)
    r.call(6, b'', s2.bytes())
    # EcRGetDCName / EcRNetGetDCName
    s = Stub()
    s.policy(2)
    s.cvstring('EXAMPLE')
    s2 = Stub()
    s2.policy(2)
    s2.raw(b'dc1.example.com\0')
    s2.u32(0)
    r.call(7, s.bytes(), s2.bytes())
    s = Stub()
    s.cvstring('EXAMPLE')
    s2 = Stub()
    s2.raw(b'dc2.example.com\0')
    s2.u32(0)
    r.call(8, s.bytes(), s2.bytes())
    # EcDoAsyncConnect, EcDoAsyncWait, EcDoAsyncConnectEx
    s = Stub()
    s.policy(2)
    s2 = Stub()
    s2.policy(5)
    s2.u32(0)
    r.call(12, s.bytes(), s2.bytes())
    s = Stub()
    s.policy(5)
    s.u32(0)
    s2 = Stub()
    s2.u32(1)
    s2.u32(0)
    r.call(13, s.bytes(), s2.bytes())
    s = Stub()
    s.policy(2)
    s2 = Stub()
    s2.policy(6)
    s2.u32(0)
    r.call(14, s.bytes(), s2.bytes())
    # EcDoDisconnect
    s = Stub()
    s.policy(2)
    s2 = Stub()
    s2.policy(0)
    s2.u32(0)
    r.call(1, s.bytes(), s2.bytes())
    t.fin()

    # -- 2. every ROP request in EcDoRpcExt2 / EcDoRpcExt (port 50002)
    cfg = os.path.join(HERE, 'cfg')
    modes = ['plain', 'xor', 'lz77']
    t = TCP(F, 50002)
    r = RPC(t)
    r.bind()
    req_clean = probe(gen_rops(True, 0), 0, True, cfg)
    reqs, req_arms, _ = select(req_clean)
    # every AUX_HEADER type of both versions (0x16 OSVERSIONINFO is a
    # remaining-blob with trailing fields, malformed, so only in the
    # malformed capture), in groups so no remaining-blob is mid-buffer.
    v1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x17]
    v2 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x17]
    aux_cycle = []
    for base in (v1, v2):
        ver = 1 if base is v1 else 2
        for j in range(0, len(base), 5):
            aux_cycle.append(aux_payload([(ver, ty) for ty in base[j:j + 5]]))
    aux_cycle += [
        aux_payload([(1, 0x7f)]),                    # unknown type -> default arm
        aux_payload([(2, 0x7e)]),
        aux_payload([(3, 0)]),                       # unknown AUX version
    ]
    for i, buf in enumerate(pack_buffers(reqs)):
        ext2 = i % 3 != 2
        mode = modes[i % 3]
        s = Stub()
        aux = hdr_ext(aux_cycle[i % len(aux_cycle)], modes[(i + 1) % 3]) if i % 2 == 0 else None
        rpcext_req(s, hdr_ext(rop_buffer(buf), mode), aux, ext2)
        s2 = Stub()
        rpcext_resp(s2, hdr_ext(rop_buffer([(bytes(rop(0x01, False, k=0).buf), False)])), 0, ext2,
                    aux=hdr_ext(aux_cycle[(i + 3) % len(aux_cycle)], modes[(i + 2) % 3]) if ext2 and i % 2 else None)
        r.call(11 if ext2 else 9, s.bytes(), s2.bytes())
    # every AUX group, in rgbAuxIn (request) and rgbAuxOut (response),
    # cycling plain/xor/lz77 and EcDoRpcExt/Ext2
    trivial_in = hdr_ext(rop_buffer([(b'\x01\x00\x00', False)]))
    for i, ag in enumerate(aux_cycle):
        ext2 = i % 2 == 0
        s = Stub()
        rpcext_req(s, trivial_in, hdr_ext(ag, modes[i % 3]), ext2)
        s2 = Stub()
        rpcext_resp(s2, hdr_ext(rop_buffer([(bytes(rop(0x01, False, k=0).buf), False)])), 0, ext2,
                    aux=hdr_ext(ag, modes[(i + 1) % 3]) if ext2 else None)
        r.call(11 if ext2 else 9, s.bytes(), s2.bytes())
    t.fin()

    # -- 3. every ROP response in EcDoRpcExt2 / EcDoRpcExt (port 50003).
    #       The ROP array element count is the stale NDR max_count (= k),
    #       so probe each k and place each reply with the k it needs.
    t = TCP(F, 50003)
    r = RPC(t)
    r.bind()
    resp_clean = []
    for k in (0, 1, 2):
        resp_clean += [(k,) + c for c in probe(gen_rops(False, k), k, False, cfg)]
    resp_arms = set()
    chosen = []
    cov = set()
    for k, rid, b, ended, arms in resp_clean:
        resp_arms |= arms
        if not arms <= cov:
            chosen.append((k, rid, b, ended))
            cov |= arms
    for i, (k, rid, b, ended) in enumerate(chosen):
        ext2 = i % 3 != 2
        mode = modes[i % 3]
        s = Stub()
        rpcext_req(s, hdr_ext(rop_buffer([(bytes(rop(0x01, True, k=0).buf), False)])), None, ext2)
        s2 = Stub()
        rpcext_resp(s2, hdr_ext(rop_buffer([b]), mode), k, ext2)
        r.call(11 if ext2 else 9, s.bytes(), s2.bytes())
    t.fin()

    # -- 4. EcDoRpc (opnum 2), obfuscated (XOR 0xA5) single-ROP buffers.
    #       mapi_request holds one EcDoRpcMapiRequest (opnum + body), not a
    #       ROP loop, so one ROP per call.  Covers mapi_deobfuscate and the
    #       request/response PDU and handle parsing.
    t = TCP(F, 50004)
    r = RPC(t)
    r.bind()
    sample_ids = [0x01, 0x02, 0x03, 0x07, 0x15, 0x29, 0x2b, 0x32, 0x4f, 0xfe, 0x55, 0x76]
    by_id = {}
    for rid, b, ended, arms in reqs:
        by_id.setdefault(rid, b)
    for rid in sample_ids:
        if rid not in by_id:
            continue
        s = Stub()
        ecdorpc_req(s, by_id[rid][0], handles=(1, 2))
        s2 = Stub()
        ecdorpc_resp(s2, bytes(rop(0x01, False, k=0).buf), handles=(1,))
        r.call(2, s.bytes(), s2.bytes())
    t.fin()

    # -- 5. NDR64 and big-endian binds.  EcDoConnectEx on both (NDR64
    #       exercises the 8-octet conformance/alignment paths; big endian
    #       the other byte order).  ROP calls (RPC_HEADER_EXT, ROP buffers,
    #       AUX) only on big endian, where the field layout matches NDR;
    #       the hand-built NDR64 ROP stubs do not align cleanly.
    for port, le, ndr64 in ((50005, True, True), (50006, False, False)):
        t = TCP(F, port)
        r = RPC(t, le=le, ndr64=ndr64)
        r.bind()
        s = Stub(le=le, ndr64=ndr64)
        connect_req(s, True, '/o=Example/cn=user64', (15, 0x8000 | 1497, 2),
                    aux=hdr_ext(aux_payload([(1, 1), (1, 2), (1, 0x0b)], le=le), 'plain', le=le))
        s2 = Stub(le=le, ndr64=ndr64)
        connect_resp(s2, True, aux=hdr_ext(aux_payload([(1, 3), (1, 5)], le=le), 'lz77', le=le))
        r.call(10, s.bytes(), s2.bytes())
        if not ndr64:
            sample = [c for c in reqs if c[0] in (0x01, 0x02, 0x03, 0x07, 0xfe, 0x15, 0x55)]
            for i, buf in enumerate(pack_buffers(sample)):
                s = Stub(le=le, ndr64=ndr64)
                rpcext_req(s, hdr_ext(rop_buffer(buf), modes[i % 3], le=le),
                           hdr_ext(aux_payload([(1, 1), (2, 7)], le=le), modes[i % 3], le=le), True)
                s2 = Stub(le=le, ndr64=ndr64)
                rpcext_resp(s2, hdr_ext(rop_buffer([(bytes(rop(0x01, False, le=le, ndr64=ndr64, k=0).buf), False)]),
                                        modes[(i + 1) % 3], le=le), 0, True)
                r.call(11, s.bytes(), s2.bytes())
        t.fin()

    pcap_main = os.path.join(outdir, 'dcerpc_mapi-coverage.pcap')
    write_pcap(pcap_main, F)
    print('main: %d frames' % len(F))
    print('req arms %d covered; resp arms %d covered' % (len(req_arms), len(resp_arms)))
    allr = set(x for x in rop_ids(True))
    seen_req = {c[0] for c in reqs}
    print('req ropids covered %d/%d; missing %s' % (
        len(seen_req), len(allr), sorted(hex(x) for x in allr - seen_req)))
    seen_resp = {c[1] for c in chosen}
    allp = set(rop_ids(False))
    print('resp ropids covered %d/%d; missing %s' % (
        len(seen_resp), len(allp), sorted(hex(x) for x in allp - seen_resp)))

    # ---- malformed capture: exception paths + the branch reproducers
    make_malformed(outdir)


if __name__ == '__main__':
    main()
