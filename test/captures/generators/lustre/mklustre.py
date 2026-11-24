#!/usr/bin/env python3
# Generates test/captures/lustre_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic Lustre coverage captures for epan/dissectors/packet-lustre.c.
Lustre messages travel in LNet PUT messages over TCP port 988 (the LNet dissector
hands them to Lustre by portal index).  Every packet is built with struct; nothing
comes from a real network.

Usage: mklustre.py <outdir>
Writes lustre-coverage.pcap (main), lustre-coverage-malformed.pcap and frames.txt
(frame numbers of the main capture).
"""
import struct

MAGIC_V1 = 0x0BD00BD0
MAGIC_V2 = 0x0BD00BD3
REQ, ERR, REP = 4711, 4712, 4713
CLI = (192, 0, 2, 1)
SRV = (192, 0, 2, 2)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


IPID = [0]


def ip4(src, dst, proto, payload):
    IPID[0] += 1
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), IPID[0], 0x4000, 64, proto, 0,
                    bytes(src), bytes(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + payload


def eth(payload, src=1, dst=2, ethertype=0x0800):
    return bytes([2, 0, 0, 0, 0, dst, 2, 0, 0, 0, 0, src]) + struct.pack('!H', ethertype) + payload


def tcp(sport, dport, seq, payload, ack=1, flags=0x18):
    return struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack, 5 << 4, flags, 65535, 0, 0) + payload


def write_pcap(fn, frames, linktype=1):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def ptlrpc_body(pb_type, opc, status=0, version=2, jobid=None, handle=0x1111, xid=1, flags=0):
    b = struct.pack('<Q', handle) + struct.pack('<IIII', pb_type, version, opc, status)
    b += struct.pack('<QQQQ', xid, 0, 0, 0) + struct.pack('<IIIIII', flags, 0, 1, 30, 0, 0)
    b += struct.pack('<Q', 0)
    b += b'\0' * 32 + b'\0' * 32
    assert len(b) == 152
    if jobid is not None:
        b += jobid.ljust(32, b'\0')
    return b


def msg_v2(buflens, bufs, trailer=b'', magic=MAGIC_V2, bufcount=None):
    h = struct.pack('<IIIIIIII', len(buflens) if bufcount is None else bufcount, 0, magic, 0, 0, 0, 0, 0)
    h += b''.join(struct.pack('<I', l) for l in buflens)
    if len(buflens) & 1:
        h += b'\0' * 4
    return h + b''.join(bufs) + trailer


def lnet_put(match, ptl, payload, msgtype=1):
    m = struct.pack('<IIQQ', 0xc1, 0, 0, 0)               # ksock header: LNET message
    m += struct.pack('<IHH', 0x0200000a, 0, 2) * 2         # dst/src nid
    m += struct.pack('<IIII', 12345, 12345, msgtype, len(payload))
    m += b'\0' * 16 + struct.pack('<QQII', match, 0, ptl, 0)
    assert len(m) == 96
    return m + payload


class Tcp:
    """One TCP connection to the LNet acceptor port 988; frames collected in a list."""
    def __init__(self, frames, cport=1023):
        self.f = frames
        self.cport = cport
        self.cseq = 1
        self.sseq = 1

    def to_server(self, payload):
        self.f.append(eth(ip4(CLI, SRV, 6, tcp(self.cport, 988, self.cseq, payload, ack=self.sseq)), src=1, dst=2))
        self.cseq += len(payload)

    def to_client(self, payload):
        self.f.append(eth(ip4(SRV, CLI, 6, tcp(988, self.cport, self.sseq, payload, ack=self.cseq)), src=2, dst=1))
        self.sseq += len(payload)


def lnet_frame(match, ptl, msg, is_req, conn=None, _state={}):
    """A single Ethernet frame holding an LNet PUT carrying msg."""
    payload = lnet_put(match, ptl, msg)
    key = is_req
    seq = _state.get(key, 1)
    _state[key] = seq + len(payload)
    if is_req:
        return eth(ip4(CLI, SRV, 6, tcp(1023, 988, seq, payload)), src=1, dst=2)
    return eth(ip4(SRV, CLI, 6, tcp(988, 1023, seq, payload)), src=2, dst=1)

# ------------------------------------------------------------------ helpers
def u16(*v): return struct.pack('<%dH' % len(v), *v)
def u32(*v): return struct.pack('<%dI' % len(v), *v)
def u64(*v): return struct.pack('<%dQ' % len(v), *v)
def Z(n): return bytes(n)
def pad8(b): return b + bytes((-len(b)) % 8)
def S(s, n=None):
    b = s.encode() + b'\0'
    return pad8(b) if n is None else b.ljust(n, b'\0')

def fid(seq=0x200000401, oid=0x1, ver=0): return u64(seq) + u32(oid, ver)
def handle(cookie=0x1122334455667788): return u64(cookie)

# ---- fixed size structures (zero unless it matters)
def obdo(valid=0x1, oid=0x10): return u64(valid) + u64(oid, 0) + Z(208 - 24)   # ost_body is the obdo, 208 bytes
CAPA = Z(120)
MDT_BODY = Z(216)
def mdt_body(valid=0x1, size=4096): return fid() + fid(0x200000402, 2) + handle() + u64(valid, size) + Z(216 - 56)
STATFS = Z(144)
QUOTACTL = Z(112)

def lock_desc(lr_type, name=(0, 0, 0, 0), req=1, granted=1):
    d = u32(lr_type, 0) + u64(*name) + u32(req, granted)
    if lr_type == 11:        # extent
        d += u64(0, 0xffffffffffffffff, 7) + Z(8)
    elif lr_type == 13:      # inodebits
        d += u64(0x3f, 0x1) + Z(16)
    elif lr_type in (10, 12, 0):
        d += u64(1, 2, 3) + u32(0, 99)
    else:
        return d             # unknown lock type: the policy data is not consumed
    return d

def ldlm_request(lr_type=13, name=(0x200000401, 1, 0, 0), flags=0, count=2, req=2, granted=2):
    return (u32(flags, count) + lock_desc(lr_type, name, req, granted)
            + b''.join(handle(0xabc0 + i) for i in range(max(2, count))))

def ldlm_reply(lr_type=13, name=(0x200000401, 1, 0, 0), flags=0):
    return u32(flags, 0) + lock_desc(lr_type, name) + handle(0x77) + u64(0, 0)

def connect_data(version=0x02100000, flags=0x4000000001):
    d = u64(flags) + u32(version, 100, 3, 4194304) + u64(0x3f)
    if version < 0x02013900:
        d += u32(1, 2)
    elif version < 0x02083300:
        d += bytes([12, 20]) + u16(8) + Z(4)
    else:
        d += bytes([12, 20]) + u16(8) + u32(1024)
    d += u64(0x1234) + u32(1, 0x20, 65536, 7) + u64(1 << 40)
    if version >= 0x02010000:
        d += u16(8) + Z(6) + u64(0x1) + Z(104)
    return d

def lov_v1(stripes=2, magic=0x0BD10BD0, pattern=1, pool=None):
    if magic == 0x0BD10BD0:
        d = u32(magic, pattern) + u64(0x11, 0x22) + u32(1048576) + u16(stripes, 3)
    else:
        d = u32(magic, pattern) + u64(0x11, 0x22) + u32(1048576) + u16(stripes, 3) + S(pool or 'pool1', 16)
    for i in range(stripes):
        d += u64(0x100 + i, 0x200) + u32(1, i)
    return d

def lmv_md(count=2, magic=0x0CD20CD0, hash_=2):
    d = u32(magic, count, 1, hash_, 7) + Z(20) + S('lmvpool', 16)
    if magic == 0x0CD20CD0:
        d += b''.join(fid(0x200000500 + i, 1) for i in range(count))
    return d

def lmv_user_md(count=2, magic=0x0CD30CD0, objects=True):
    d = u32(magic, count, 0, 2, 1) + bytes([3, 1]) + Z(10) + S('lumpool', 16)
    if objects:
        for i in range(count):
            d += fid(0x200000600 + i, 1) + u32(0, i)
    return d

def llog_hdr(length, idx, typ, rid=0): return u32(length, idx, typ, rid)
def llog_tail(length, idx): return u32(length, idx)

def llogd_body(): return Z(48)
def lquota_id(): return fid() + Z(0)  # lu_fid only; id is the same 16 bytes
def quota_body(): return Z(112)
def seq_range(): return u64(0x200000400, 0x2000007ff) + u32(0, 1) + Z(0)
def eadata(n=16): return pad8(bytes(range(n)))

# ------------------------------------------------------------------ messages
FRAMES = []          # main capture
DESC = []            # (first frame, last frame, text)
MB = [0x7000]


def send(frames, opc, typ, bufs, match, ptl=None, status=0, version=2, jobid=None, magic=MAGIC_V2,
         flags=0, xid=1):
    """One Lustre message in an LNet PUT; bufs are the buffers after the ptlrpc body.  A buffer
    is bytes (its length is the buffer length) or (bytes, buffer length)."""
    body = ptlrpc_body(typ, opc, status, version=version, jobid=jobid, flags=flags, xid=xid)
    lens = [len(body)]
    data = [body]
    for b in bufs:
        if isinstance(b, tuple):
            data.append(b[0])
            lens.append(b[1])
        else:
            data.append(b)
            lens.append(len(b))
    msg = msg_v2(lens, data, magic=magic)
    frames.append(lnet_frame(match, ptl or (12 if typ == REQ else 10), msg, typ == REQ))


def call(opc, req, rep=None, text=None, frames=None, rep_type=REP, **kw):
    """A request and its reply (same LNet match bits)."""
    frames = FRAMES if frames is None else frames
    MB[0] += 1
    first = len(frames) + 1
    send(frames, opc, REQ, req, MB[0], **kw)
    if rep is not None:
        send(frames, opc, rep_type, rep, MB[0])
    if frames is FRAMES:
        DESC.append((first, len(frames), text or 'opcode %d' % opc))
    return MB[0]


def rr(op): return u32(op) + Z(132)
def uuid40(name): return name.encode().ljust(40, b'\0')
NAME = S('file.txt')
SEC = S('security.selinux')
DATA16 = eadata(16)
LLOGCK = (Z(64), 48)
ACL = Z(16)
INTENT = lambda v: u64(v)

def build_main():
    F = FRAMES
    # ---- OST (portal 6 is OST_REQUEST; the dissector is registered for 12 and others)
    call(1, [obdo(0x3, 0x1234), CAPA], [obdo(0x3, 0x1234)], 'OST_GETATTR')
    call(2, [obdo(), CAPA], [obdo()], 'OST_SETATTR')
    call(3, [obdo(), Z(24 * 2), Z(16 * 4), CAPA], [obdo()], 'OST_READ')
    call(4, [obdo(), Z(24 * 2), Z(16 * 4), CAPA], [obdo(), Z(16)], 'OST_WRITE')
    call(5, [obdo()], [obdo()], 'OST_CREATE')
    call(6, [obdo(), ldlm_request(), CAPA], [obdo()], 'OST_DESTROY')
    call(7, [S('last_id')], [u64(1)], 'OST_GET_INFO')
    call(8, [uuid40('lustre-OST0000_UUID'), uuid40('client-uuid'), handle(), connect_data(0x02100000)],
         [connect_data(0x02100000)], 'OST_CONNECT, version 2.16')
    call(8, [uuid40('lustre-OST0001_UUID'), uuid40('client-uuid'), handle(), connect_data(0x02013000)],
         [connect_data(0x02013000)], 'OST_CONNECT, version 2.1.48 (older flags layout)')
    call(8, [uuid40('lustre-OST0002_UUID'), uuid40('client-uuid'), handle(), connect_data(0x02050000)],
         [connect_data(0x02050000)], 'OST_CONNECT, version 2.5')
    call(8, [uuid40('lustre-OST0003_UUID'), uuid40('client-uuid'), handle(), connect_data(0x01080000)],
         [connect_data(0x01080000)], 'OST_CONNECT, version 1.8 (short connect data)')
    call(9, [], [], 'OST_DISCONNECT, no buffers')
    call(9, [b''], [b''], 'OST_DISCONNECT, empty buffer')
    call(10, [obdo(), CAPA], [obdo()], 'OST_PUNCH')
    call(11, [b''], [b''], 'OST_OPEN (obsolete, no data)')
    call(12, [b''], [b''], 'OST_CLOSE (obsolete, no data)')
    call(0, [b''], [b''], 'OST_REPLY (obsolete)')
    call(13, [b''], [STATFS], 'OST_STATFS')
    call(16, [obdo(), CAPA], [obdo()], 'OST_SYNC')
    call(17, [S('key'), S('value')], [b''], 'OST_SET_INFO')
    call(18, [QUOTACTL], [b''], 'OST_QUOTACHECK (obsolete)')
    call(19, [QUOTACTL], [QUOTACTL], 'OST_QUOTACTL')
    call(20, [Z(32)], [Z(32)], 'OST_QUOTA_ADJUST_QUNIT (obsolete)')
    call(21, [obdo(), u32(0x1ADF1CE0) + Z(28), Z(32)], [obdo()], 'OST_LADVISE')

    # ---- MDS
    lov = lov_v1(2)
    call(33, [mdt_body(), CAPA], [mdt_body(), lov, ACL, CAPA, CAPA], 'MDS_GETATTR, LOV V1 layout')
    call(34, [mdt_body(), CAPA, NAME], [mdt_body(), lov_v1(3, 0x0BD30BD0), ACL, CAPA, CAPA],
         'MDS_GETATTR_NAME, LOV V3 layout with pool')
    call(33, [mdt_body(), CAPA], [mdt_body(), lmv_md(2), ACL, CAPA, CAPA], 'MDS_GETATTR, LMV layout')
    call(33, [mdt_body(), CAPA], [mdt_body(), lmv_md(2, 0x0CD40CD0), ACL, CAPA, CAPA],
         'MDS_GETATTR, LMV stripe object (no FIDs)')
    call(33, [mdt_body(), CAPA], [mdt_body(), Z(40), ACL, CAPA, CAPA], 'MDS_GETATTR, layout of unknown magic')
    call(35, [Z(24), rr(0), CAPA, Z(96)], [mdt_body(), lov, LLOGCK, CAPA, CAPA], 'MDS_CLOSE')
    call(37, [mdt_body(), CAPA], [mdt_body()], 'MDS_READPAGE')
    call(38, [uuid40('lustre-MDT0000_UUID'), uuid40('client-uuid'), handle(), connect_data()],
         [connect_data()], 'MDS_CONNECT')
    call(38, [uuid40('lustre-MDT0000_UUID'), uuid40('client-uuid'), handle(), connect_data()],
         [connect_data()], 'MDS_CONNECT, error reply', rep_type=ERR)
    call(39, [b''], [b''], 'MDS_DISCONNECT')
    call(40, [mdt_body(), S('ROOT')], [mdt_body(), CAPA], 'MDS_GET_ROOT')
    call(41, [b''], [STATFS], 'MDS_STATFS')
    call(44, [mdt_body(), CAPA], [mdt_body()], 'MDS_SYNC')
    call(45, [mdt_body()], [b''], 'MDS_DONE_WRITING (obsolete)')
    call(46, [S('key'), S('value')], [b''], 'MDS_SET_INFO')
    call(47, [QUOTACTL], [b''], 'MDS_QUOTACHECK (obsolete)')
    call(48, [QUOTACTL], [QUOTACTL], 'MDS_QUOTACTL')
    call(49, [mdt_body(), CAPA, S('user.attr'), eadata(16)], [mdt_body(), eadata(16)], 'MDS_GETXATTR')
    call(50, [mdt_body()], [b''], 'MDS_SETXATTR (obsolete)')
    call(54, [mdt_body(), CAPA], [mdt_body(), Z(32)], 'MDS_HSM_STATE_GET')
    call(55, [mdt_body(), CAPA, Z(24)], [b''], 'MDS_HSM_STATE_SET')
    call(56, [mdt_body(), CAPA], [mdt_body(), Z(24)], 'MDS_HSM_ACTION')
    # the hsm_progress flags and errval are 16 bit ("Lustre: Use length 2 for the HSM progress flags and errval")
    prog = fid() + u64(0xc0ffee) + u64(0, 4096) + u16(0x1234, 0x0056) + u32(0) + u64(77, 0)
    assert len(prog) == 64
    call(57, [mdt_body(), prog], [b''], 'MDS_HSM_PROGRESS (flags 0x1234, errval 0x56)')
    call(58, [mdt_body(), Z(24), Z(64), DATA16], [b''], 'MDS_HSM_REQUEST')
    call(59, [mdt_body(), (pad8(u32(1, 2, 3)), 12)], [b''], 'MDS_HSM_CT_REGISTER')
    call(60, [mdt_body()], [b''], 'MDS_HSM_CT_UNREGISTER')
    call(61, [mdt_body(), Z(8), CAPA, CAPA, ldlm_request()], [b''], 'MDS_SWAP_LAYOUTS')
    call(62, [mdt_body(), Z(32), CAPA, CAPA], [mdt_body(), Z(32), Z(16)], 'MDS_RMFID')

    # ---- MDS_REINT, every sub-opcode
    ck = (Z(32), 24)
    ioe = Z(24)
    call(36, [rr(1), CAPA, ioe, DATA16, ck, ldlm_request()],
         [mdt_body(), lov, ACL, CAPA, CAPA], 'MDS_REINT REINT_SETATTR')
    call(36, [rr(2), CAPA, NAME, DATA16, ldlm_request(), SEC, DATA16],
         [mdt_body(), CAPA], 'MDS_REINT REINT_CREATE')
    call(36, [rr(3), CAPA, CAPA, NAME, ldlm_request()], [mdt_body()], 'MDS_REINT REINT_LINK')
    call(36, [rr(4), CAPA, NAME, ldlm_request()], [mdt_body(), lov, ck, CAPA, CAPA], 'MDS_REINT REINT_UNLINK')
    call(36, [rr(5), CAPA, CAPA, NAME, S('newname'), ldlm_request()],
         [mdt_body(), lov, ck, CAPA, CAPA], 'MDS_REINT REINT_RENAME')
    call(36, [rr(6), CAPA, CAPA, NAME, DATA16, SEC, DATA16],
         [mdt_body(), lov, ACL, CAPA, CAPA], 'MDS_REINT REINT_OPEN')
    call(36, [rr(7), CAPA, S('user.attr'), DATA16, ldlm_request()], [mdt_body()], 'MDS_REINT REINT_SETXATTR')
    call(36, [rr(8)], [mdt_body()], 'MDS_REINT REINT_RMENTRY')
    call(36, [rr(9), CAPA, CAPA, NAME, SEC, ldlm_request(), ioe, Z(96)],
         [mdt_body(), lov, ck, CAPA, CAPA], 'MDS_REINT REINT_MIGRATE')

    # ---- LDLM
    plain = ldlm_request(10, (0x200000401, 0, 0, 0))
    call(101, [ldlm_request(13)], [ldlm_reply(13), lov], 'LDLM_ENQUEUE without intent, LOV layout as LVB')
    call(101, [ldlm_request(11)], [ldlm_reply(11), Z(40)], 'LDLM_ENQUEUE extent lock, reply LVB of unknown magic')
    call(101, [ldlm_request(12, count=4)], [ldlm_reply(12)], 'LDLM_ENQUEUE flock lock with 4 handles')
    call(101, [ldlm_request(0)], [ldlm_reply(0)], 'LDLM_ENQUEUE without lock type')
    call(102, [ldlm_request(13)], [ldlm_reply(13)], 'LDLM_CONVERT')
    call(103, [ldlm_request(13)], [b''], 'LDLM_CANCEL')
    call(104, [ldlm_request(13)], [b''], 'LDLM_BL_CALLBACK')
    call(105, [ldlm_request(11), Z(56)], [b''], 'LDLM_CP_CALLBACK')
    call(106, [ldlm_request(10, (1, 5, 0, 0)), Z(64)], [Z(16)], 'LDLM_GL_CALLBACK, barrier descriptor')
    call(106, [ldlm_request(10, (1, 0, 0, 0)), Z(64)], [Z(16)], 'LDLM_GL_CALLBACK, quota descriptor')
    call(106, [ldlm_request(10, (1, 3, 0, 0)), Z(64)], [Z(16)], 'LDLM_GL_CALLBACK, other descriptor')
    call(107, [S('key'), S('value')], [b''], 'LDLM_SET_INFO')
    # intents
    it = lambda v: u64(v)
    def enq(opc_intent, reqbufs, repbufs, text, lr_type=13):
        call(101, [ldlm_request(lr_type), it(opc_intent)] + reqbufs, [ldlm_reply(lr_type)] + repbufs, text)
    mdtb = mdt_body()
    enq(3, [rr(0), CAPA, CAPA, NAME, DATA16, SEC, DATA16], [mdtb, lov, ACL, CAPA, CAPA, Z(16), DATA16],
        'LDLM_ENQUEUE intent open|create')
    enq(1, [rr(0), CAPA, CAPA, NAME, DATA16, SEC, DATA16], [mdtb, lov, ACL, CAPA, CAPA, Z(16), DATA16],
        'LDLM_ENQUEUE intent open')
    enq(2, [rr(0), CAPA, NAME, DATA16, SEC, DATA16, S('selinux')],
        [mdtb, lov, ACL, CAPA, DATA16, lmv_user_md(2), DATA16], 'LDLM_ENQUEUE intent create')
    enq(8, [mdtb, CAPA, NAME], [mdtb, lov, ACL, CAPA, DATA16, lmv_user_md(2, objects=False), DATA16],
        'LDLM_ENQUEUE intent getattr')
    enq(16, [mdtb, CAPA, NAME], [mdtb, lov, ACL], 'LDLM_ENQUEUE intent lookup (default reply)')
    enq(32, [rr(0), CAPA, NAME], [mdtb, lov, ACL], 'LDLM_ENQUEUE intent unlink')
    enq(0x400, [u32(1, 0) + u64(0, 0xffffffff) + Z(0), DATA16], [lov], 'LDLM_ENQUEUE intent layout')
    enq(0x80, [mdtb, CAPA], [mdtb, lov, ACL, Z(24), Z(16), Z(8)],
        'LDLM_ENQUEUE intent getxattr')
    enq(0x800, [quota_body()], [lov, quota_body()], 'LDLM_ENQUEUE intent quota dqacq')
    enq(0x1000, [quota_body()], [lov, quota_body()], 'LDLM_ENQUEUE intent quota conn')
    enq(4, [rr(0)], [mdtb, lov, ACL], 'LDLM_ENQUEUE intent readdir (default)')

    # ---- MGS
    call(250, [uuid40('MGS'), uuid40('client-uuid'), handle(), connect_data()], [connect_data()], 'MGS_CONNECT')
    call(251, [b''], [b''], 'MGS_DISCONNECT')
    call(252, [b''], [b''], 'MGS_EXCEPTION')
    mti = u32(1, 2, 3, 4, 2, 0) + Z(64) + S('lustre-OST0000', 64) + Z(40) + u64(0x200000a, 0x200000b) + Z(30 * 8)
    call(253, [mti], [mti], 'MGS_TARGET_REG, two NIDs')
    call(254, [b''], [b''], 'MGS_TARGET_DEL')
    call(255, [S('param=value')], [b''], 'MGS_SET_INFO')
    def mcb(t): return Z(64) + Z(8) + u16(t) + bytes([0, 0]) + Z(4)
    call(256, [mcb(0)], [Z(16)], 'MGS_CONFIG_READ type config')
    call(256, [mcb(4)], [Z(16)], 'MGS_CONFIG_READ type nodemap')

    # ---- OBD
    call(400, [b''], [b''], 'OBD_PING')
    call(401, [(Z(64), 48)], [b''], 'OBD_LOG_CANCEL')
    call(402, [b''], [b''], 'OBD_QC_CALLBACK (obsolete)')
    call(403, [Z(64)], [Z(64)], 'OBD_IDX_READ')

    # ---- LLOG
    call(501, [llogd_body(), S('catalog'), mdt_body()], [llogd_body()], 'LLOG_ORIGIN_HANDLE_CREATE')
    call(502, [llogd_body()], [llogd_body()], 'LLOG_ORIGIN_HANDLE_NEXT_BLOCK, no records')
    call(503, [llogd_body()], [llog_hdr_block()], 'LLOG_ORIGIN_HANDLE_READ_HEADER')
    call(504, [b''], [b''], 'LLOG_ORIGIN_HANDLE_WRITE_REC (obsolete)')
    call(505, [b''], [b''], 'LLOG_ORIGIN_HANDLE_CLOSE')
    call(506, [Z(40)], [b''], 'LLOG_ORIGIN_CONNECT')
    call(507, [b''], [b''], 'LLOG_CATINFO (obsolete)')
    call(508, [llogd_body()], [llogd_body()], 'LLOG_ORIGIN_HANDLE_PREV_BLOCK')
    call(509, [llogd_body()], [llogd_body()], 'LLOG_ORIGIN_HANDLE_DESTROY')

    # ---- quota, seq, fld, out update, lfsck
    call(601, [quota_body()], [quota_body()], 'QUOTA_DQACQ')
    call(602, [b''], [b''], 'QUOTA_DQREL')
    call(700, [(pad8(u32(1)), 4), seq_range()], [seq_range()], 'SEQ_QUERY')
    call(801, [b''], [b''], 'SEC_CTX_INIT (not decoded)')
    call(900, [(pad8(u32(1)), 4), seq_range()], [seq_range()], 'FLD_QUERY')
    call(901, [seq_range()], [Z(24)], 'FLD_READ')
    upd = out_update()
    call(1000, upd + [Z(8) * 2], [obj_update_reply()], 'OUT_UPDATE')
    call(1101, [Z(96)], [b''], 'LFSCK_NOTIFY')
    call(1102, [Z(96)], [Z(16)], 'LFSCK_QUERY')

    # ---- more variants of the same messages
    lov_short = lov_v1(2)[:28] + u16(3, 3) + lov_v1(2)[32:]            # says 3 stripes, holds 2
    call(33, [mdt_body(), CAPA], [mdt_body(), lov_short, ACL, CAPA, CAPA], 'MDS_GETATTR, stripe count larger than the stripes present')
    call(54, [mdt_body(), CAPA], [mdt_body(), Z(48)], 'MDS_HSM_STATE_GET, user state with extra info')
    enq(0x2341, [rr(0)], [mdtb, lov, ACL], 'LDLM_ENQUEUE intent open|trunc|exec|pin|setxattr (Info column)')
    call(101, [ldlm_request(13, count=0), it(0x4)], [ldlm_reply(13)], 'LDLM_ENQUEUE, lock count 0 (two handles)')
    lfsck = u32(1, 2, 3, 1, 1000) + u16(1, 2) + u16(3, 4) + u32(5) + fid() + fid() + u32(6) + Z(28)
    assert len(lfsck) == 96
    call(1102, [lfsck], [Z(16)], 'LFSCK_QUERY, speed limit variant')
    call(35, [Z(24), rr(0), CAPA, Z(96)], [mdt_body(), lov_v1(3, 0x0BD30BD0), (Z(64), 48), CAPA, CAPA], 'MDS_CLOSE, V3 layout')
    call(36, [rr(6), CAPA, CAPA, NAME, DATA16, SEC, DATA16], [mdt_body(), lmv_md(1), ACL, CAPA, CAPA], 'MDS_REINT REINT_OPEN, LMV in the reply', version=3, jobid=b'job.1')

    # ---- optional buffers sent with zero length (buffers that are not used are empty in real traffic)
    E = b''
    call(6, [obdo(), E, E], [obdo()], 'OST_DESTROY, empty DLM request and capability')
    call(35, [E, rr(0), E, E], [mdt_body(), E, E, E, E], 'MDS_CLOSE, empty ioepoch, capability, close data, layout')
    call(33, [mdt_body(), E], [mdt_body(), E, E, E, E], 'MDS_GETATTR, empty optional buffers')
    call(54, [mdt_body(), E], [mdt_body(), E], 'MDS_HSM_STATE_GET, empty user state')
    call(55, [mdt_body(), E, E], [E], 'MDS_HSM_STATE_SET, empty state')
    call(56, [mdt_body(), E], [mdt_body(), E], 'MDS_HSM_ACTION, empty action')
    call(58, [mdt_body(), Z(24), E, E], [E], 'MDS_HSM_REQUEST, empty item array and data')
    call(61, [mdt_body(), E, E, E, E], [E], 'MDS_SWAP_LAYOUTS, empty buffers')
    call(62, [mdt_body(), E, E, E], [mdt_body(), E, E], 'MDS_RMFID, empty fid array')
    call(36, [rr(1), E, E, E, E, E], [E], 'MDS_REINT REINT_SETATTR, empty buffers')
    call(101, [E, E, E], [E, E], 'LDLM_ENQUEUE, empty buffers')
    call(101, [ldlm_request(13), E, E], [ldlm_reply(13)], 'LDLM_ENQUEUE, empty intent')
    call(106, [E, E], [E], 'LDLM_GL_CALLBACK, empty buffers')
    call(105, [ldlm_request(13), E], [E], 'LDLM_CP_CALLBACK, empty LVB')
    call(106, [ldlm_request(10, (1, 5, 0, 0)), E], [E], 'LDLM_GL_CALLBACK, empty descriptor')
    call(403, [E], [E], 'OBD_IDX_READ, empty')
    call(501, [E, E, E], [E], 'LLOG_ORIGIN_HANDLE_CREATE, empty')
    call(506, [E], [E], 'LLOG_ORIGIN_CONNECT, empty')
    call(503, [E], [E], 'LLOG_ORIGIN_HANDLE_READ_HEADER, empty')
    call(601, [E], [E], 'QUOTA_DQACQ, empty')
    call(700, [(pad8(u32(1)), 4), E], [E], 'SEQ_QUERY, empty range')
    call(1000, [E, E], [E], 'OUT_UPDATE, empty')
    call(1102, [E], [E], 'LFSCK_QUERY, empty')
    call(20, [E], [E], 'OST_QUOTA_ADJUST_QUNIT, empty (obsolete)')
    call(105, [ldlm_request(13), E], [E], 'LDLM_CP_CALLBACK, empty')
    call(61, [mdt_body(), Z(8), E, E, E], [E], 'MDS_SWAP_LAYOUTS, empty capabilities and DLM request')
    call(101, [ldlm_request(13), it(0x400), E, E], [ldlm_reply(13), E], 'LDLM_ENQUEUE intent layout, empty buffers')
    call(101, [ldlm_request(13), it(0x800), E], [ldlm_reply(13), E, E], 'LDLM_ENQUEUE intent quota, empty buffers')

    # ---- message variants
    call(1, [obdo(), CAPA], [obdo()], 'OST_GETATTR, ptlrpc body version 3 with a job id',
         version=3, jobid=b'job.12345')
    # version 1 message (obsolete): the header only
    v1 = (u64(0x1111) + u32(0x0BD00BD0, 4711, 0x00010000, 1) + u64(1, 0, 0) + u32(0, 0, 0, 3)
          + u32(0, 0, 0) + Z(4))
    MB[0] += 1
    first = len(F) + 1
    F.append(lnet_frame(MB[0], 12, v1, True))
    DESC.append((first, first, 'Lustre message version 1 (obsolete)'))


def nid(ip=0x0200000a, iface=0, typ=2): return u32(ip) + u16(iface, typ)


def lcfg(cmd, bufs):
    """struct lustre_cfg: header, buffer lengths (padded to 8) and the buffers (each padded to 8)."""
    h = u32(1, cmd, 0, 0) + nid() + u32(0) + u32(len(bufs)) + b''.join(u32(len(b)) for b in bufs)
    h = pad8(h)
    return h + b''.join(pad8(b) for b in bufs)


def changelog_rec(flags, typ, name=b'', rename=False, jobid=False, extra=False):
    d = u16(len(name), flags) + u32(typ) + u64(7, 6, 1700000000)
    d += (u32(1) + Z(12)) if typ == 0 else fid()
    d += fid()
    if flags & 0x2000: d += fid() + fid()
    if flags & 0x4000: d += S('job', 32)
    if flags & 0x8000: d += u64(1)
    return d + name


def llog_records():
    """Records of every type the dissector can parse in a block, each with a length that matches
    what is parsed (the buffer ends with a record of length 0)."""
    OP = 0x10600000
    out = b''
    def rec(typ, body, idx=1):
        total = 16 + len(body) + 8
        return llog_hdr(total, idx, typ) + body + llog_tail(total, idx)
    out += rec(OP | 0x00000, b'', 1)                              # pad record
    out += rec(OP | 0x00f00, fid() + Z(24), 2)                    # OST_SZ_REC
    out += rec(OP | 0x10000 | (36 << 8) | 4, Z(16), 3)            # MDS_UNLINK_REC
    out += rec(OP | 0x90000 | (36 << 8) | 4, fid() + Z(24), 4)    # MDS_UNLINK64_REC
    out += rec(OP | 0x10000 | (36 << 8) | 1, Z(24), 5)            # MDS_SETATTR_REC
    out += rec(OP | 0x40000, Z(16) + Z(24), 7)                    # LLOG_GEN_REC
    out += rec(OP | 0x4553b, Z(20) + Z(12), 8)                    # LLOG_LOGID_MAGIC
    out += rec(OP | 0x60000, changelog_rec(0, 1, b'file1234'), 9)        # CHANGELOG_REC
    out += rec(OP | 0x60000, changelog_rec(0xe000, 8, b'newname1'), 10)  # with rename, jobid, extra flags
    out += rec(OP | 0x60000, changelog_rec(0, 0), 11)                      # CL_MARK
    marker = u32(1, 2, 0x10600, 0) + u64(1700000000, 0) + S('lustre-MDT0000', 64) + S('comment', 64)
    out += rec(OP | 0x20000, lcfg(0x00cf010, [marker]), 12)       # OBD_CFG_REC, LCFG_MARKER
    out += rec(OP | 0x20000, lcfg(0x00cf003, [S('lov', 8), Z(88)]), 13)    # LCFG_SETUP with two buffers
    out += rec(OP | 0x20000, lcfg(0x00cf001, [S('osc', 8), S('uuid', 8)]), 14)   # LCFG_ATTACH, default branch
    out += rec(OP | 0x90000 | (36 << 8) | 1, Z(16) + Z(20), 6)    # MDS_SETATTR64_REC (60 bytes, so last)
    out += u32(0)
    return pad8(out)


def llog_hdr_block():
    # llog_log_hdr: rec hdr (16), 8, 4, 4, 4, flags 4, 4, uuid 40, 4, then bitmap words, tail 8
    length = 16 + 8 + 4 + 4 + 4 + 4 + 4 + 40 + 4 + 16 + 8
    return (llog_hdr(length, 0, 0x10645539) + Z(8) + u32(0, 0, 0, 0x3, 0) + uuid40('target_uuid') + u32(0)
            + Z(16) + llog_tail(length, 0))


def out_update():
    param = u16(8) + Z(6) + Z(8)
    obj = u16(1, 1) + u32(16, 0, 0) + u64(0) + fid() + param
    inline = u32(0xBDDE0002) + u16(1, 0) + obj
    hdr = u32(0xBDDF0001, 1, len(inline), 4096) + inline
    return [hdr]


def obj_update_reply():
    res = u32(0) + u16(8, 0) + Z(8)
    return u32(0x00BD0002) + u16(1, 0) + u16(16) + res + Z(0)



def malformed():
    F = []
    mb = [0x9000]
    def c(opc, req, rep=None, rep_type=REP, **kw):
        mb[0] += 1
        send(F, opc, REQ, req, mb[0], **kw)
        if rep is not None:
            send(F, opc, rep_type, rep, mb[0])
    def raw(msg, req=True):
        mb[0] += 1
        F.append(lnet_frame(mb[0], 12 if req else 10, msg, req))
    # opcodes that nobody handles, in every opcode class
    for opc in (14, 15, 22, 42, 43, 52, 5000, 0x7fff):
        c(opc, [b''], [b''])
    c(51, [b''], [b''])                                           # MDS_WRITEPAGE
    c(801, [Z(8)], [b''])
    # the reply carries another opcode than the request
    mb[0] += 1
    send(F, 33, REQ, [mdt_body(), CAPA], mb[0])
    send(F, 99, REP, [mdt_body()], mb[0])
    # bad magic
    raw(msg_v2([152], [ptlrpc_body(REQ, 33)], magic=0x12345678))
    # MDS_GET_INFO: the 4 octet value length after the key is not consumed (LNet reports leftover)
    c(53, [S('fid2path'), pad8(u32(4096))], [Z(24)])
    # reproducers (lustre_state_passes.py): the sub-opcode of a REINT reply depends on the
    # last request with the same match bits, so the reply decodes differently in the second pass
    mb[0] += 1
    send(F, 36, REQ, [rr(2), CAPA], mb[0])
    send(F, 36, REP, [b'', Z(72)], mb[0])
    send(F, 36, REQ, [rr(8)], mb[0])
    # a lock type nobody knows (the policy data is not consumed)
    c(103, [ldlm_request(99)], [b''])
    # wrong buffer lengths
    c(36, [(rr(6), 120), CAPA, CAPA, NAME, DATA16, SEC, DATA16])                 # rec_reint of another size
    c(33, [mdt_body(), CAPA], [mdt_body(), (lov_v1(2), 90), ACL, CAPA, CAPA])    # lov length mismatch
    call(101, [ldlm_request(13), u64(8), mdt_body(), CAPA, NAME], [ldlm_reply(13), mdt_body(), lov_v1(2), ACL, CAPA, DATA16, (lmv_user_md(2), 70), DATA16], frames=F)
    c(54, [mdt_body(), CAPA], [mdt_body(), (Z(32), 16)])                         # hsm user state too short
    c(55, [mdt_body(), CAPA, (Z(24), 8)])                                        # hsm state set too short
    c(21, [obdo(), u32(0x11111111) + Z(28), Z(32)], [obdo()])                    # ladvise bad magic
    # intent with a wrong length and a layout intent with a wrong length
    call(101, [ldlm_request(13), (u64(0x400), 4), (u32(1, 0) + u64(0, 0xffff), 20), DATA16], [ldlm_reply(13)], frames=F)
    # out update with wrong magics and lengths
    upd = out_update()[0]
    c(1000, [(upd, len(upd) + 8), Z(16)], [(obj_update_reply(), len(obj_update_reply()) + 8)])
    bad = u32(0x11111111) + upd[4:]
    c(1000, [bad, Z(16)], [u32(0x22222222) + obj_update_reply()[4:]])
    c(1000, [(upd, len(upd)), (Z(16), 12)], [obj_update_reply()])
    c(1000, [(u32(0x11111111) + u32(1, 8, 4096) + Z(8), 36), Z(8)], [b''])
    inline_bad = u32(0x11111111) + u16(1, 0) + Z(8)
    c(1000, [u32(0xBDDF0001, 1, len(inline_bad), 0) + inline_bad, Z(8)], [b''])
    # llog records: the loop stops at a record of length 0, which is not consumed, so LNet reports
    # the unused rest of the message as a length mismatch whenever a record is parsed
    c(502, [llogd_body()], [llogd_body(), llog_records()])
    c(502, [llogd_body()], [llogd_body(), (llog_hdr_block() + Z(8), len(llog_hdr_block()))])
    # llog records the dissector cannot parse completely (bad length, obsolete, not implemented)
    OP = 0x10600000
    def rec(typ, body, idx=1, total=None):
        total = 16 + len(body) + 8 if total is None else total
        return llog_hdr(total, idx, typ) + body + llog_tail(total, idx)
    for typ, body in ((OP | 0x1000, Z(8)), (OP | 0x30000, Z(8)), (OP | 0x50000, Z(8)),
                      (OP | 0x70000, Z(8)), (OP | 0x80000, Z(8)), (OP | 0xa0000, Z(8)),
                      (OP | 0x77777, Z(8)), (OP | 0x00f00, Z(8))):
        c(502, [llogd_body()], [llogd_body(), pad8(rec(typ, body) + u32(0))])
    # a llog header whose buffer length differs from the length in the header
    c(503, [llogd_body()], [(llog_hdr_block(), len(llog_hdr_block()) + 8)])
    # buffers that do not fit: truncated messages
    for n in (3, 7, 100, 151, 200):
        m = msg_v2([152, 216, 120], [ptlrpc_body(REQ, 33), mdt_body(), CAPA])
        raw(m[:n + 32])
    raw(msg_v2([152, 216, 120], [ptlrpc_body(REQ, 33), mdt_body(), CAPA], bufcount=3)[:60])
    raw(b'\x00' * 20)                                           # shorter than the magic number offset
    # a reply that is an error
    c(36, [rr(6), CAPA, CAPA, NAME, DATA16, SEC, DATA16], [b''], rep_type=ERR)
    return F


def main():
    import os, sys
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build_main()
    write_pcap(os.path.join(out, 'lustre-coverage.pcap'), FRAMES)
    with open(os.path.join(out, 'frames.txt'), 'w') as f:
        for a, b, t in DESC:
            f.write('%s %s\n' % ('%d' % a if a == b else '%d-%d' % (a, b), t))
    try:
        malformed
    except NameError:
        return
    write_pcap(os.path.join(out, 'lustre-coverage-malformed.pcap'), malformed())


if __name__ == '__main__':
    main()
