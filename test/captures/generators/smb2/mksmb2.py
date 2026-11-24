#!/usr/bin/env python3
# Generates test/captures/smb2_coverage.pcap.gz, smb2_redirect_loop.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-smb2.c (SMB2/3).

Usage: mksmb2.py <outdir> [-v]
Writes smb2-coverage.pcap (main), smb2-coverage-malformed.pcap and the
small reproducers of the fixes as frames of the main capture.
Everything is built with struct; addresses are 192.0.2.0/24.  No keys,
no authentication blobs, no ciphertext: encrypted frames carry random
looking octets and fail to decrypt, signatures are random octets.
"""
import os
import struct
import sys
import uuid

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv

# ---------------------------------------------------------------- pcap ---


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip4(proto, payload, src, dst):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0,
                     bytes([192, 0, 2, src]), bytes([192, 0, 2, dst]))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ip + payload


def eth(payload, src, dst, etype=0x0800):
    return bytes.fromhex('02000000000%x02000000000%x' % (dst & 15, src & 15)) + struct.pack('!H', etype) + payload


def tcp_seg(payload, src, dst, sport, dport, seq, ack, flags=0x18):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    return eth(ip4(6, t, src, dst), src, dst)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + i, (i * 1000) % 1000000, len(fr), len(fr)) + fr)


def nbss(smb):
    return b'\x00' + struct.pack('>I', len(smb))[1:] + smb


LOG = []


class Conn:
    """one TCP connection client -> server:445 with tracked sequence numbers"""

    def __init__(self, frames, c=10, s=11, cport=49200, sport=445):
        self.frames, self.c, self.s, self.cp, self.sp = frames, c, s, cport, sport
        self.cs, self.ss = 1000, 5000

    def syn(self):
        f = self.frames
        f.append(tcp_seg(b'', self.c, self.s, self.cp, self.sp, self.cs, 0, 0x02))
        f.append(tcp_seg(b'', self.s, self.c, self.sp, self.cp, self.ss, self.cs + 1, 0x12))
        f.append(tcp_seg(b'', self.c, self.s, self.cp, self.sp, self.cs + 1, self.ss + 1, 0x10))
        self.cs += 1
        self.ss += 1

    def c2s(self, payload):
        for i in range(0, max(len(payload), 1), 32000):
            p = payload[i:i + 32000]
            self.frames.append(tcp_seg(p, self.c, self.s, self.cp, self.sp, self.cs, self.ss))
            self.cs += len(p)

    def s2c(self, payload):
        for i in range(0, max(len(payload), 1), 32000):
            p = payload[i:i + 32000]
            self.frames.append(tcp_seg(p, self.s, self.c, self.sp, self.cp, self.ss, self.cs))
            self.ss += len(p)

    def rep(self, side, smb):
        if self.frames is globals().get('main'):
            LOG.append((self.cp, self.sp, self.c, self.s, side, smb))
        (self.c2s if side == 'c' else self.s2c)(nbss(smb))


# ------------------------------------------------------------ constants ---
NEGOTIATE, SESSION_SETUP, LOGOFF, TREE_CONNECT, TREE_DISCONNECT, CREATE, CLOSE, FLUSH, READ, WRITE, \
    LOCK, IOCTL, CANCEL, ECHO, FIND, NOTIFY, GETINFO, SETINFO, BREAK, SRV_NOTIFY = range(20)

F_RESP, F_ASYNC, F_CHAIN, F_SIGNED = 1, 2, 4, 8
F_DFS, F_REPLAY = 0x10000000, 0x20000000

STATUS_PENDING = 0x103
STATUS_MORE_PROCESSING = 0xc0000016
STATUS_NO_MORE_FILES = 0x80000006
STATUS_BUFFER_OVERFLOW = 0x80000005
STATUS_NOTIFY_ENUM_DIR = 0x10c
STATUS_CANCELLED = 0xc0000120
STATUS_ACCESS_DENIED = 0xc0000022
STATUS_NOT_FOUND = 0xc0000225
STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034
STATUS_STOPPED_ON_SYMLINK = 0x8000002d
STATUS_BAD_NETWORK_NAME = 0xc00000cc
STATUS_INVALID_PARAMETER = 0xc000000d
STATUS_FILE_CLOSED = 0xc0000128
STATUS_BUFFER_TOO_SMALL = 0xc0000023
STATUS_INFO_LENGTH_MISMATCH = 0xc0000004
STATUS_SHARING_VIOLATION = 0xc0000043
STATUS_USER_SESSION_DELETED = 0xc0000203
STATUS_NETWORK_NAME_DELETED = 0xc00000c9


def u16s(s):
    return s.encode('utf-16-le')


def pad(b, n=8):
    return b + b'\0' * ((-len(b)) % n)


def guid(s):
    return uuid.UUID(s).bytes_le


def hdr(cmd, mid, flags=0, sesid=0, tid=0, status=0, credit=1, charge=0, nxt=0, aid=None, chseq=0):
    if flags & F_RESP:
        w = struct.pack('<I', status)
    else:
        w = struct.pack('<HH', chseq, 0)
    if aid is not None:
        flags |= F_ASYNC
        mid2 = struct.pack('<Q', aid)
    else:
        mid2 = struct.pack('<II', 0, tid)
    return b'\xfeSMB' + struct.pack('<HH', 64, charge) + w + struct.pack('<HHIIQ', cmd, credit, flags, nxt, mid) + \
        mid2 + struct.pack('<Q', sesid) + b'\0' * 16


def sign(h, sig=b'\xa5' * 16):
    return h[:48] + sig + h[64:]


SES, TID = 0x4000000012345678, 7
FID = bytes.fromhex('0123456789abcdef') + struct.pack('<Q', 0x1111222233334444)
FID2 = bytes.fromhex('fedcba9876543210') + struct.pack('<Q', 0x5555666677778888)
WILD = b'\xff' * 16
SHARE = '\\\\server.example.com\\Share'

# ------------------------------------------------------------ builders ---
# every function returns the body of the command (after the 64 octet header)


def buf(fixed_len, data, align=1):
    """offset (from header start) of a buffer following the fixed part"""
    return 64 + fixed_len


def negotiate_ctx(typ, data):
    return pad(struct.pack('<HHI', typ, len(data), 0) + data)


def ctx_preauth(salt=b'\x11' * 32, algs=(1,)):
    return negotiate_ctx(1, struct.pack('<HH', len(algs), len(salt)) + b''.join(struct.pack('<H', a) for a in algs) + salt)


def ctx_enc(ciphers=(2, 1)):
    return negotiate_ctx(2, struct.pack('<H', len(ciphers)) + b''.join(struct.pack('<H', c) for c in ciphers))


def ctx_comp(algs=(1, 2, 3, 4, 5), flags=1):
    return negotiate_ctx(3, struct.pack('<HHI', len(algs), 0, flags) + b''.join(struct.pack('<H', a) for a in algs))


def ctx_netname(n='server.example.com'):
    return negotiate_ctx(5, u16s(n))


def ctx_transport(flags=1):
    return negotiate_ctx(6, struct.pack('<I', flags))


def ctx_rdma(tr=(1, 2)):
    return negotiate_ctx(7, struct.pack('<HHI', len(tr), 0, 0) + b''.join(struct.pack('<H', t) for t in tr))


def ctx_signing(algs=(2, 1, 0)):
    return negotiate_ctx(8, struct.pack('<H', len(algs)) + b''.join(struct.pack('<H', a) for a in algs))


def ctx_posix():
    return negotiate_ctx(0x100, guid('93AD2550-9CB4-11E7-B423-83DE968BCD7C'))


def ctx_unknown():
    return negotiate_ctx(0x77, b'\x01\x02\x03\x04')


def neg_req(dialects=(0x0202, 0x0210, 0x0300, 0x0302, 0x0311), ctxs=None, secmode=1, caps=0x7f,
            ncc_override=None, nco_override=None):
    ctxs = ctxs or []
    d = b''.join(struct.pack('<H', x) for x in dialects)
    fixed = 36
    base = 64 + fixed + len(d)
    ctxo = (base + 7) & ~7
    body = struct.pack('<HHHHI16s', 36, len(dialects), secmode, 0, caps, guid('11111111-2222-3333-4444-555555555555'))
    if ctxs:
        body += struct.pack('<IHH', ctxo if nco_override is None else nco_override,
                            len(ctxs) if ncc_override is None else ncc_override, 0)
    else:
        body += struct.pack('<IHH', nco_override or 0, ncc_override or 0, 0) if (nco_override or ncc_override) else struct.pack('<Q', 0)
    out = body + d
    if ctxs:
        out = pad(out, 8) if (64 + len(out)) % 8 else out
        # contexts start at an 8 aligned offset from the header start
        out += b'\0' * (ctxo - (64 + len(out)))
        out += b''.join(ctxs)
    return out


def spnego_init():
    """SPNEGO NegTokenInit with only a mechanism list (no token, no credentials)"""
    mech = bytes.fromhex('060a2b06010401823702020a')       # NTLMSSP OID, only announced
    mlist = b'\x30' + bytes([len(mech)]) + mech
    mt = b'\xa0' + bytes([len(mlist)]) + mlist
    ni = b'\x30' + bytes([len(mt)]) + mt
    na = b'\xa0' + bytes([len(ni)]) + ni
    oid = bytes.fromhex('06062b0601050502')
    inner = oid + na
    return b'\x60' + bytes([len(inner)]) + inner


def neg_rep(dialect=0x0311, ctxs=None, secmode=3, caps=0x7f, blob=None, maxt=8388608, status_ctx_override=None,
            nco_override=None):
    ctxs = ctxs or []
    blob = spnego_init() if blob is None else blob
    secoff = 64 + 64
    body = struct.pack('<HHHH16sIIIIQQHH', 65, secmode, dialect,
                       len(ctxs) if status_ctx_override is None else status_ctx_override,
                       guid('99999999-8888-7777-6666-555555555555'), caps, maxt, maxt, maxt,
                       132000000000000000, 131000000000000000, secoff, len(blob))
    ctxo = (secoff + len(blob) + 7) & ~7
    body += struct.pack('<I', (ctxo if ctxs else 0) if nco_override is None else nco_override)
    body += blob
    if ctxs:
        body += b'\0' * (ctxo - (64 + len(body)))
        body += b''.join(ctxs)
    return body


def ses_req(blob=None, prev=0, flags=0, secmode=1, caps=0, channel=0):
    blob = spnego_init() if blob is None else blob
    return struct.pack('<HBBIIHHQ', 25, flags, secmode, caps, channel, 64 + 24, len(blob), prev) + blob


def ses_rep(sflags=0, blob=b''):
    return struct.pack('<HHHH', 9, sflags, 64 + 8, len(blob)) + blob


def logoff_req():
    return struct.pack('<HH', 4, 0)


logoff_rep = logoff_req


def tcon_req(path=SHARE, flags=0):
    p = u16s(path)
    return struct.pack('<HHHH', 9, flags, 64 + 8, len(p)) + p


def tcon_rep(stype=1, sflags=0x00000800, caps=0, access=0x001f01ff):
    return struct.pack('<HBBIII', 16, stype, 0, sflags, caps, access)


def tdis_req():
    return struct.pack('<HH', 4, 0)


tdis_rep = tdis_req


def error_rep(ctxs=b'', count=0, data=b'', bytecount=None):
    if not ctxs and not data:
        return struct.pack('<HBBI', 9, 0, 0, 0) + b'\0'
    d = ctxs or data
    return struct.pack('<HBBI', 9, count, 0, len(d) if bytecount is None else bytecount) + d


def create_ctx(name, data, nxt=0):
    """one CREATE_CONTEXT; name bytes, data bytes; nxt is NextEntryOffset (0 for the last)"""
    nameoff = 16
    dataoff = (nameoff + len(name) + 7) & ~7
    c = struct.pack('<IHHHHI', nxt, nameoff, len(name), 0, dataoff if data else 0, len(data))
    c += name + b'\0' * (dataoff - nameoff - len(name)) + data
    return pad(c)


def create_ctxs(items):
    """items: list of (name, data); chains them with NextEntryOffset"""
    out = b''
    for i, (n, d) in enumerate(items):
        c = create_ctx(n, d)
        if i != len(items) - 1:
            c = struct.pack('<I', len(c)) + c[4:]
        out += c
    return out


def create_req(name='dir\\file.txt', access=0x12019f, attrs=0x80, share=7, disp=1, opts=0x40, oplock=0xff,
               ctxs=b'', imp=2, flags=0):
    n = u16s(name)
    nlen = len(n)
    nameoff = 64 + 56
    # create contexts follow the name, 8 aligned
    ctxoff = ((nameoff + nlen + 7) & ~7) if ctxs else 0
    body = struct.pack('<HBBIQQIIIIIHHII', 57, 0, oplock, imp, flags, 0, access, attrs, share, disp, opts,
                       nameoff, nlen, ctxoff, len(ctxs))
    if not n and not ctxs:
        return body + b'\0'
    body += n
    if ctxs:
        body += b'\0' * (ctxoff - (nameoff + nlen)) + ctxs
    return body


T0 = 132000000000000000


def create_rep(fid=FID, oplock=0, action=1, ctxs=b'', flags=0, attrs=0x20, eof=100, alloc=4096, name=None):
    ctxoff = (64 + 88) if ctxs else 0
    body = struct.pack('<HBBIQQQQQQII', 89, oplock, flags, action, T0, T0 + 1, T0 + 2, T0 + 3, alloc, eof, attrs, 0)
    body += fid + struct.pack('<II', ctxoff, len(ctxs))
    return body + (ctxs if ctxs else b'\0')


def close_req(fid=FID, flags=0):
    return struct.pack('<HHI', 24, flags, 0) + fid


def close_rep(flags=0, attrs=0x20):
    return struct.pack('<HHIQQQQQQI', 60, flags, 0, T0 if flags else 0, T0 + 1 if flags else 0, T0 + 2 if flags else 0,
                       T0 + 3 if flags else 0, 4096 if flags else 0, 100 if flags else 0, attrs if flags else 0)


def flush_req(fid=FID):
    return struct.pack('<HHI', 24, 0, 0) + fid


def flush_rep():
    return struct.pack('<HH', 4, 0)


def read_req(fid=FID, length=4096, offset=0, flags=0, minc=0, channel=0, remaining=0, rci=b'', padding=0x50):
    rcioff = (64 + 48) if rci else 0
    return struct.pack('<HBBIQ16sIIIHH', 49, padding, flags, length, offset, fid, minc, channel, remaining, rcioff,
                       len(rci)) + (rci if rci else b'\0')


def read_rep(data, remaining=0, flags=0):
    return struct.pack('<HBBIII', 17, 0x50, 0, len(data), remaining, flags) + data


def write_req(data, fid=FID, offset=0, channel=0, remaining=0, wci=b'', flags=0, dataoff=None):
    d = 64 + 48
    wcioff = (d + len(data)) if wci else 0
    return struct.pack('<HHIQ16sIIHHI', 49, d if dataoff is None else dataoff, len(data), offset, fid, channel,
                       remaining, wcioff, len(wci), flags) + data + wci


def write_rep(count, remaining=0, wci_off=0, wci_len=0):
    return struct.pack('<HHIIHH', 17, 0, count, remaining, wci_off, wci_len) + b'\0'


def lock_req(locks, fid=FID, seq=0):
    return struct.pack('<HHI16s', 48, len(locks), seq, fid) + b''.join(
        struct.pack('<QQII', o, l, f, 0) for o, l, f in locks)


def lock_rep():
    return struct.pack('<HH', 4, 0)


def echo_req():
    return struct.pack('<HH', 4, 0)


echo_rep = echo_req
cancel_req = echo_req


def find_req(cls=0x25, flags=0, index=0, fid=FID, pattern='*', outlen=65536):
    p = u16s(pattern)
    return struct.pack('<HBBI16sHHI', 33, cls, flags, index, fid, 64 + 32, len(p), outlen) + (p if p else b'\0')


def find_rep(data):
    return struct.pack('<HHI', 9, 64 + 8, len(data)) + (data if data else b'\0')


def notify_req(fid=FID, flags=0, outlen=4096, filt=0xfff):
    return struct.pack('<HHI16sII', 32, flags, outlen, fid, filt, 0)


def notify_rep(data=b''):
    return struct.pack('<HHI', 9, 64 + 8 if data else 0, len(data)) + (data if data else b'\0')


def getinfo_req(itype, cls, outlen=65536, inbuf=b'', addl=0, flags=0, fid=FID):
    inoff = (64 + 40) if inbuf else 0
    return struct.pack('<HBBIHHIII16s', 41, itype, cls, outlen, inoff, 0, len(inbuf), addl, flags, fid) + (
        inbuf if inbuf else b'\0')


def getinfo_rep(data):
    return struct.pack('<HHI', 9, 64 + 8, len(data)) + (data if data else b'\0')


def setinfo_req(itype, cls, data, addl=0, fid=FID):
    return struct.pack('<HBBIHHI16s', 33, itype, cls, len(data), 64 + 32, 0, addl, fid) + data


def setinfo_rep():
    return struct.pack('<H', 2)


def ioctl_req(code, indata=b'', maxout=65536, outdata=b'', fid=FID, flags=1, maxin=0):
    inoff = (64 + 56) if indata else 0
    outoff = (64 + 56 + len(indata)) if outdata else 0
    return struct.pack('<HHI16sIIIIIIII', 57, 0, code, fid, inoff, len(indata), maxin, outoff, len(outdata), maxout,
                       flags, 0) + indata + outdata


def ioctl_rep(code, outdata=b'', indata=b'', fid=FID, flags=0):
    inoff = (64 + 48) if indata else 0
    outoff = (64 + 48 + len(indata)) if outdata else 0
    return struct.pack('<HHI16sIIIIII', 49, 0, code, fid, inoff, len(indata), outoff, len(outdata), flags, 0) + \
        indata + outdata


def break_oplock(fid=FID, level=1):
    return struct.pack('<HBBI16s', 24, level, 0, 0, fid)


def break_lease_ack(key=b'L' * 16, state=3, flags=0, dur=0):
    return struct.pack('<HHI16sIQ', 36, 0, flags, key, state, dur)


def break_lease_notify(key=b'L' * 16, cur=7, new=3, flags=1, epoch=2, reason=0, amask=0, smask=0):
    return struct.pack('<HHI16sIIIII', 44, epoch, flags, key, cur, new, reason, amask, smask)


def srv_notify(ntype=1, extra=b'\0\0\0\0'):
    return struct.pack('<HH', 4, 0) + struct.pack('>I', ntype) + extra

# ------------------------------------------------- info levels (FSCC) ---
def ft(n=0):
    return struct.pack('<Q', T0 + n)


def sid(sub=(32, 544), auth=5):
    return struct.pack('<BB', 1, len(sub)) + auth.to_bytes(6, 'big') + b''.join(struct.pack('<I', x) for x in sub)


def fi_basic(attrs=0x20):
    return ft(0) + ft(1) + ft(2) + ft(3) + struct.pack('<II', attrs, 0)


def fi_standard():
    return struct.pack('<QQIBBH', 4096, 100, 1, 0, 0, 0)


def fi_internal():
    return struct.pack('<Q', 0x123456789a)


def fi_name(name):
    n = u16s(name)
    return struct.pack('<I', len(n)) + n


def fi_all(name='\\dir\\file.txt'):
    return fi_basic() + fi_standard() + fi_internal() + struct.pack('<I', 0) + struct.pack('<I', 0x1f01ff) + \
        struct.pack('<Q', 0) + struct.pack('<I', 0) + struct.pack('<I', 1) + fi_name(name)


def fi_rename(name='newdir\\new.txt', replace=1, root=0):
    n = u16s(name)
    return struct.pack('<B7xQI', replace, root, len(n)) + n


def fi_ea(items):
    """items: (name bytes, value bytes, flags)"""
    out = b''
    for i, (n, v, f) in enumerate(items):
        e = struct.pack('<BBH', f, len(n), len(v)) + n + b'\0' + v
        nxt = 0 if i == len(items) - 1 else len(pad(struct.pack('<I', 0) + e, 4))
        out += pad(struct.pack('<I', nxt) + e, 4) if nxt else struct.pack('<I', 0) + e
    return out


def fi_stream(items):
    out = b''
    for i, (n, size, alloc) in enumerate(items):
        nb = u16s(n)
        rec = struct.pack('<IIQQ', 0, len(nb), size, alloc) + nb
        if i != len(items) - 1:
            rec = pad(rec)
            rec = struct.pack('<I', len(rec)) + rec[4:]
        out += rec
    return out


def fi_pipe(): return struct.pack('<II', 1, 0)
def fi_pipe_local(): return struct.pack('<IIIIIIIIII', 1, 0, 255, 1, 4096, 0, 4096, 4096, 3, 1)
def fi_pipe_remote(): return struct.pack('<QI', 0, 0)
def fi_compression(): return struct.pack('<QHBBB3x', 100, 2, 12, 0, 0)
def fi_network_open(): return ft(0) + ft(1) + ft(2) + ft(3) + struct.pack('<QQII', 4096, 100, 0x20, 0)
def fi_attr_tag(): return struct.pack('<II', 0x400, 0xa000000c)


def fi_posix(perms=0o100644, nlinks=1):
    return ft(0) + ft(1) + ft(2) + ft(3) + struct.pack('<QQIQIIIII', 100, 4096, 0x20, 0x1234, 0x802, 0, nlinks,
                                                       0xa000001d, perms) + sid((21, 1, 2, 1000)) + sid((21, 1, 2, 100))


FS_VOLUME = struct.pack('<QIIH', T0, 0xcafe, 8, 0) + u16s('LABEL')[:8]
FS_SIZE = struct.pack('<QQII', 1000000, 500000, 8, 512)
FS_DEVICE = struct.pack('<II', 7, 0x20)
FS_ATTR = struct.pack('<III', 0x8f, 255, 8) + u16s('NTFS')
FS_CONTROL = struct.pack('<QQQQQII', 1, 2, 3, 4, 5, 0x1d, 0)
FS_FULLSIZE = struct.pack('<QQQII', 1000000, 500000, 400000, 8, 512)
FS_OBJECTID = b'\x12' * 16 + b'\0' * 48
FS_POSIX = struct.pack('<IIQQQQQQ', 4096, 4096, 1000, 500, 400, 100000, 50000, 0x1234)


def dirent(cls, name, nxt, attrs=0x20, short=b'', fid=0x1234, reparse=False):
    nb = u16s(name)
    a = 0x400 if reparse else attrs
    common = struct.pack('<II', nxt, 7) + ft(0) + ft(1) + ft(2) + ft(3) + struct.pack('<QQI', 100, 4096, a)
    if cls == 1:
        return common + struct.pack('<I', len(nb)) + nb
    if cls == 2:
        return common + struct.pack('<II', len(nb), 0xa000000c if reparse else 0) + nb
    if cls == 3:
        sh = short.ljust(24, b'\0')
        return common + struct.pack('<IIBB', len(nb), 0, len(short), 0) + sh + nb
    if cls == 12:
        return struct.pack('<III', nxt, 7, len(nb)) + nb
    if cls == 0x25:
        sh = short.ljust(24, b'\0')
        return common + struct.pack('<IIBB', len(nb), 0, len(short), 0) + sh + struct.pack('<HQ', 0, fid) + nb
    if cls == 0x26:
        return common + struct.pack('<IIIQ', len(nb), 0, 0, fid) + nb
    if cls == 0x64:
        return struct.pack('<II', nxt, 7) + fi_posix()[:0] + ft(0) + ft(1) + ft(2) + ft(3) + \
            struct.pack('<QQIQIIIII', 100, 4096, a, 0x1234, 0x802, 0, 1, 0, 0o40755) + sid((21, 1, 2, 1000)) + \
            sid((21, 1, 2, 100)) + struct.pack('<I', len(nb)) + nb
    raise ValueError(cls)


def dirents(cls, names, **kw):
    out = b''
    for i, n in enumerate(names):
        e = dirent(cls, n, 0, **kw)
        if i != len(names) - 1:
            e = pad(e)
            e = struct.pack('<I', len(e)) + e[4:]
        out += e
    return out


# a self relative security descriptor: owner, group, DACL with ACEs
def acl(aces, rev=2):
    body = b''.join(aces)
    return struct.pack('<BBHHH', rev, 0, 8 + len(body), len(aces), 0) + body


def ace(typ, mask, s, flags=0):
    return struct.pack('<BBHI', typ, flags, 8 + len(s), mask) + s


def sec_desc(owner=True, group=True, dacl=True, sacl=False):
    o = sid((32, 544))
    g = sid((18,))
    d = acl([ace(0, 0x1f01ff, sid((18,))), ace(1, 0x2, sid((32, 544)), 3),
             ace(2, 0x1, sid((18,)), 0xc0)])
    sa = acl([ace(2, 0x1, sid((18,)), 0xc0)])
    parts = []
    off = 20
    oo = go = do = so = 0
    if owner:
        oo = off; off += len(o); parts.append(o)
    if group:
        go = off; off += len(g); parts.append(g)
    if sacl:
        so = off; off += len(sa); parts.append(sa)
    if dacl:
        do = off; off += len(d); parts.append(d)
    ctrl = 0x8004 | (0x10 if sacl else 0)
    return struct.pack('<BBHIIII', 1, 0, ctrl, oo, go, so, do) + b''.join(parts)


def quota_entries(n=2):
    out = b''
    for i in range(n):
        s = sid((21, 1, 2, 1000 + i))
        e = struct.pack('<IIQQQQ', 0, len(s), T0, 5000, 100000, 200000) + s
        if i != n - 1:
            e = pad(e)
            e = struct.pack('<I', len(e)) + e[4:]
        out += e
    return out


def quota_query(single=0, restart=1, sids=None, start=None):
    if sids:
        lst = b''
        for i, s in enumerate(sids):
            e = struct.pack('<II', 0, len(s)) + s
            if i != len(sids) - 1:
                e = pad(e, 4)
                e = struct.pack('<I', len(e)) + e[4:]
            lst += e
        return struct.pack('<BBHIII', single, restart, 0, len(lst), 0, 0) + lst
    if start:
        return struct.pack('<BBHIII', single, restart, 0, 0, len(start), 0) + start
    return struct.pack('<BBHIII', single, restart, 0, 0, 0, 0)


# ---------------------------------------------------------- FSCTL data ---
def rng(o, l): return struct.pack('<QQ', o, l)


def fsctl_odx_token():
    return struct.pack('>IHH', 0xffff0001, 0, 8) + b'\x5a' * 8 + b'\0' * 496


def fsctl_offload_read_in(): return struct.pack('<IIIIQQ', 32, 0, 600, 0, 0, 65536)
def fsctl_offload_read_out(): return struct.pack('<IIQ', 528, 0, 65536) + fsctl_odx_token()
def fsctl_offload_write_in(): return struct.pack('<IIQQQ', 544, 0, 0, 65536, 0) + fsctl_odx_token()
def fsctl_offload_write_out(): return struct.pack('<IIQ', 16, 0, 65536)


def fsctl_pipe_wait(name='srvsvc', timeout=True):
    n = u16s(name)
    return struct.pack('<QIBB', 5000000, len(n), 1 if timeout else 0, 0) + n


def fsctl_netif(addr_kinds):
    out = b''
    for i, k in enumerate(addr_kinds):
        if k == 4:
            sa = struct.pack('<HH4s', 2, 0, bytes([192, 0, 2, 40 + i])) + b'\0' * 8
            sa = sa + b'\0' * (128 - len(sa))
            sa = struct.pack('<HH4s', 2, 0, bytes([192, 0, 2, 40 + i])) + b'\0' * 120
        elif k == 6:
            sa = struct.pack('<HHI16sI', 23, 0, 0, bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [i + 1]), 0) + b'\0' * 98
        else:
            sa = struct.pack('<H', k) + b'\0' * 126
        rec = struct.pack('<IIIIQ', 0, i + 1, [0, 1, 2, 3][i % 4], 0, [100_000_000, 1_000_000_000, 10_000_000_000, 500, 5000][i % 5]) + sa
        if i != len(addr_kinds) - 1:
            rec = struct.pack('<I', len(rec)) + rec[4:]
        out += rec
    return out


def fsctl_validate_neg_in(dialects=(0x0202, 0x0302, 0x0311)):
    return struct.pack('<I16sHH', 0x7f, guid('11111111-2222-3333-4444-555555555555'), 1, len(dialects)) + \
        b''.join(struct.pack('<H', d) for d in dialects)


def fsctl_validate_neg_out(dialect=0x0311):
    return struct.pack('<I16sHH', 0x7f, guid('99999999-8888-7777-6666-555555555555'), 3, dialect)


def fsctl_validate_neg_224_in(): return struct.pack('<I16sHH', 0x7f, b'\x11' * 16, 1, 0x0300)
def fsctl_validate_neg_224_out(): return struct.pack('<I16sHH', 0x7f, b'\x22' * 16, 3, 0x0300)


def fsctl_snapshots(n=2):
    names = [u16s('@GMT-2026.01.%02d-10.00.00' % (i + 1)) + b'\0\0' for i in range(n)]
    arr = b''.join(names) + b'\0\0'
    return struct.pack('<III', n, n, len(arr)) + arr


def fsctl_objectid(): return b'\x12' * 16 + b'\x34' * 16 + b'\x56' * 16 + b'\x78' * 16


def fsctl_sqos(in_=True, ver=0x0101):
    common = struct.pack('<HHI', ver, 0, 0x1f) + b'\x01' * 16 + b'\x02' * 16 + b'\x03' * 16
    if in_:
        h, n = u16s('host'), u16s('node')
        base = len(common) + 8 + 8 + 4 + 4 + 8 * 4 + (16 if ver > 0x0100 else 0)
        fixed = common + struct.pack('<QQ', 1000, 2000) + struct.pack('<HH', base, len(h)) + struct.pack('<HH', base + len(h), len(n)) \
            + struct.pack('<QQQQ', 1, 2, 3, 4)
        if ver > 0x0100:
            fixed += struct.pack('<QQ', 5, 6)
        # offsets in the structure are relative to the start of the structure
        return fixed + h + n
    out = common + struct.pack('<IIQQII', 1000, 2, 3000, 100, 4096, 0)
    if ver > 0x0100:
        out += struct.pack('<Q', 7)
    return out


def fsctl_file_regions_in(): return struct.pack('<QQII', 0, 4096, 1, 0)
def fsctl_file_regions_out(): return struct.pack('<IIII', 0, 2, 2, 0) + struct.pack('<QQII', 0, 4096, 1, 0) + \
    struct.pack('<QQII', 4096, 8192, 2, 0)


def fsctl_copychunk_in(n=2):
    return b'\x77' * 24 + struct.pack('<II', n, 0) + b''.join(struct.pack('<QQII', i * 4096, i * 4096, 4096, 0) for i in range(n))


def fsctl_copychunk_out(): return struct.pack('<III', 1, 0, 4096)


def fsctl_resume_key_out(): return b'\x66' * 24 + struct.pack('<I', 0)


def fsctl_reparse(tag, data=b'', guid_=True):
    g = b'' if (tag & 0x80000000) else b'\x44' * 16
    return struct.pack('<IHH', tag, len(data), 0) + g + data


def reparse_symlink(sub='\\??\\C:\\target', prt='C:\\target', flags=1):
    s, p = u16s(sub), u16s(prt)
    return struct.pack('<HHHHI', 0, len(s), len(s), len(p), flags) + s + p


def reparse_mount(sub='\\??\\Volume{1234}\\', prt='D:'):
    s, p = u16s(sub), u16s(prt)
    return struct.pack('<HHHH', 0, len(s), len(s) + 2, len(p)) + s + b'\0\0' + p


def fsctl_ntfs_volume_data():
    return struct.pack('<QQQQQIIIIQQQQQ', 0x1234, 1000, 500, 250, 10, 512, 4096, 1024, 0, 1, 2, 3, 4, 5)


def fsctl_dup_extents(fid=FID2): return fid + struct.pack('<QQQ', 0, 0, 4096)


def fsctl_dfs_ex(names=('\\server\\share',), site=None):
    items = list(names) + ([site] if site else [])
    data = b''.join(struct.pack('<H', len(u16s(n))) + u16s(n) for n in items)
    return struct.pack('<HHI', 3, 1 if site else 0, len(data)) + data


def fsctl_integrity_get(): return struct.pack('<HHIII', 1, 0, 1, 65536, 4096)
def fsctl_integrity_set(): return struct.pack('<HHI', 1, 0, 1)
def fsctl_integrity_set_ex(): return struct.pack('<BBHIB7s', 1, 0, 0, 1, 1, b'\0' * 7)


def fsctl_refs_snapshot(op=1, name='snap'):
    n = u16s(name)
    d = struct.pack('<IHH16s', op, len(n), 8, b'\0' * 16) + n
    if op == 3:
        d += struct.pack('<QII', 0, 0, 0)
    return d


def fsctl_svhdx():
    # RSVD tunnel operation header, CHECK_CONNECTION_STATUS (another dissector's data)
    return struct.pack('<IIQ', 0x02001003, 0, 1)


def rdma_xform_blob(channel=1, descs=1, transforms=1):
    t = b''
    for i in range(transforms):
        sig, nonce = b'\x5a' * 16, b'\xa5' * 12
        x = struct.pack('<HHHH', 1, len(sig), len(nonce), 0) + sig + nonce
        t += pad(x)
    d = b''.join(struct.pack('<QII', 0x1000 * (i + 1), 0x2000 + i, 4096) for i in range(descs))
    return struct.pack('<HHIHHI', 16 + len(t), len(d), channel, transforms, 0, 0) + t + d


def dcerpc_bind(callid=1, uuid_='4b324fc8-1670-01d3-1278-5a47bf6ee188', ver=3):
    ctx = struct.pack('<HBB', 0, 1, 0) + guid(uuid_) + struct.pack('<I', ver) + \
        guid('8a885d04-1ceb-11c9-9fe8-08002b104860') + struct.pack('<I', 2)
    body = struct.pack('<HHIBBBB', 4280, 4280, 0, 1, 0, 0, 0) + ctx
    fl = 16 + len(body)
    return struct.pack('<BBBBBBBBHHI', 5, 0, 11, 3, 0x10, 0, 0, 0, fl, 0, callid) + body


def dcerpc_bind_ack(callid=1):
    addr = b'\\PIPE\\srvsvc\0'
    body = struct.pack('<HHIH', 4280, 4280, 0x1234, len(addr)) + addr
    body += b'\0' * ((-len(body)) % 4)
    body += struct.pack('<BBBB', 1, 0, 0, 0) + struct.pack('<HH', 0, 0) + guid('8a885d04-1ceb-11c9-9fe8-08002b104860') + \
        struct.pack('<I', 2)
    fl = 16 + len(body)
    return struct.pack('<BBBBBBBBHHI', 5, 0, 12, 3, 0x10, 0, 0, 0, fl, 0, callid) + body


# ------------------------------------------------ compression encoders ---
def lz77_encode(tokens):
    """MS-XCA plain LZ77: tokens are ('L', byte) or ('M', offset, length)"""
    out = bytearray()
    flags_pos = None
    count = 0
    flags = 0
    nibble_pos = None

    def start():
        nonlocal flags_pos, count, flags
        flags_pos = len(out)
        out.extend(b'\0\0\0\0')
        count = 0
        flags = 0

    def finish(fill):
        nonlocal flags
        f = flags << (32 - count)
        if fill:
            f |= (1 << (32 - count)) - 1
        out[flags_pos:flags_pos + 4] = struct.pack('<I', f)

    start()
    for t in tokens:
        if count == 32:
            finish(False)
            start()
        if t[0] == 'L':
            flags <<= 1
            out.append(t[1])
        else:
            _, off, ln = t
            flags = (flags << 1) | 1
            m = ln - 3
            if m < 7:
                out.extend(struct.pack('<H', ((off - 1) << 3) | m))
            else:
                out.extend(struct.pack('<H', ((off - 1) << 3) | 7))
                r = m - 7
                nib = r if r < 15 else 15
                if nibble_pos is None:
                    nibble_pos = len(out)
                    out.append(nib)
                else:
                    out[nibble_pos] |= nib << 4
                    nibble_pos = None
                if r >= 15:
                    if r - 15 < 255:
                        out.append(r - 15)
                    else:
                        out.append(255)
                        out.extend(struct.pack('<H', m))
        count += 1
    if count == 32:
        finish(False)
        start()
    finish(True)
    if nibble_pos is not None:
        pass
    return bytes(out)


def lz77_tokens_for(data):
    """greedy tokens: literals plus matches for repeats of the previous bytes"""
    toks = []
    i = 0
    while i < len(data):
        best = None
        for off in (1, 2, 4, 8, 16, 64):
            if off <= i:
                ln = 0
                while i + ln < len(data) and ln < 700 and data[i + ln] == data[i + ln - off]:
                    ln += 1
                if ln >= 3 and (best is None or ln > best[1]):
                    best = (off, ln)
        if best:
            toks.append(('M', best[0], best[1]))
            i += best[1]
        else:
            toks.append(('L', data[i]))
            i += 1
    return toks


def lz77(data):
    return lz77_encode(lz77_tokens_for(data))


def lznt1(data):
    out = b''
    for c in range(0, len(data), 4096):
        chunk = data[c:c + 4096]
        # compressed chunk with literals and simple matches
        body = bytearray()
        i = 0
        while i < len(chunk):
            flagpos = len(body)
            body.append(0)
            flags = 0
            for bit in range(8):
                if i >= len(chunk):
                    break
                m = None
                if i >= 1:
                    ln = 0
                    while i + ln < len(chunk) and ln < 3 + 15 and chunk[i + ln] == chunk[i + ln - 1]:
                        ln += 1
                    if ln >= 3:
                        m = (1, ln)
                if m:
                    pos = i - 1
                    lmask, oshift = 0x0fff, 12
                    while pos >= 0x10:
                        lmask >>= 1
                        oshift -= 1
                        pos >>= 1
                    if m[1] - 3 <= lmask:
                        flags |= 1 << bit
                        body.extend(struct.pack('<H', ((m[0] - 1) << oshift) | (m[1] - 3)))
                        i += m[1]
                        continue
                body.append(chunk[i])
                i += 1
            body[flagpos] = flags
        out += struct.pack('<H', 0xb000 | (len(body) - 1)) + bytes(body)
    return out


def lznt1_raw(data):
    """chunks stored without compression"""
    out = b''
    for c in range(0, len(data), 4096):
        chunk = data[c:c + 4096]
        out += struct.pack('<H', 0x3000 | (len(chunk) - 1)) + chunk
    return out


def lz77huff(data, matches=False):
    """MS-XCA LZ77+Huffman with all 512 symbols at length 9 (code == symbol)"""
    table = b'\x99' * 256
    syms = []          # (symbol, extra_bits_value, extra_bits_count)
    i = 0
    while i < len(data):
        if matches and i >= 8:
            ln = 0
            while i + ln < len(data) and ln < 14 + 3 and data[i + ln] == data[i + ln - 8]:
                ln += 1
            if ln >= 3:
                # offset 8: nbits=3, extra=0 (offset = 8 + 0)
                syms.append((256 + (3 << 4) + (ln - 3), 0, 3))
                i += ln
                continue
        syms.append((data[i], 0, 0))
        i += 1
    syms.append((256, 0, 0))
    bits = ''
    for s, e, n in syms:
        bits += format(s, '09b')
        if n:
            bits += format(e, '0%db' % n)
    # simulate the reader to find how many 16 bit words it consumes by the EOF symbol
    # (EOF is decoded after its 9 bits; refills happen when fewer than 16 bits remain)
    last = len(bits)
    words = 2
    have = 32
    consumed = 0
    # bits consumed after all symbols (match offset bits are skipped after the symbol)
    while consumed < last:
        consumed += 1
        have -= 1
        if have < 16:
            words += 1
            have += 16
    bits += '0' * (words * 16 - len(bits))
    out = bytearray()
    for w in range(words):
        out += struct.pack('<H', int(bits[w * 16:(w + 1) * 16], 2))
    return table + bytes(out)


# --------------------------------------------------- transform headers ---
def comp_hdr(orig_size, alg, uncompressed_prefix, compressed, flags=0):
    return b'\xfcSMB' + struct.pack('<IHHI', orig_size, alg, flags, len(uncompressed_prefix)) + \
        uncompressed_prefix + compressed


def chain_payload(alg, data, orig=None, flags=0):
    """COMPRESSION_PAYLOAD_HEADER + payload (orig is the original size for LZ based algorithms)"""
    if alg in (1, 2, 3):
        return struct.pack('<HHII', alg, flags, len(data) + 4, orig) + data
    return struct.pack('<HHI', alg, flags, len(data)) + data


def pattern_v1(byte, times):
    return struct.pack('<BBHI', byte, 0, 0, times)


def chained(orig_size, payloads):
    return b'\xfcSMB' + struct.pack('<I', orig_size) + b''.join(payloads)


def transform_hdr(plain_len, sesid=SES, flags=1, nonce=b'\x42' * 16, sig=b'\x99' * 16, body=None):
    body = body if body is not None else bytes((i * 37 + 11) & 0xff for i in range(plain_len))
    return b'\xfdSMB' + sig + nonce + struct.pack('<IHHQ', len(body), 0, flags, sesid) + body


# ============================================================ scenario ===
main = []
marks = []


def mark(name):
    marks.append((len(main) + 1, name))


class Sess:
    """request/response exchanges on one connection"""

    def __init__(self, conn, ses=SES, tid=TID, signed=False):
        self.c, self.ses, self.tid, self.signed = conn, ses, tid, signed
        self.mid = 0
        self.credit = 1

    def next_mid(self, n=1):
        m = self.mid
        self.mid += n
        return m

    def req(self, cmd, body, tid=None, ses=None, flags=0, mid=None, charge=0, nxt=0, aid=None, send=True,
            signed=None):
        m = self.next_mid() if mid is None else mid
        h = hdr(cmd, m, flags | (F_SIGNED if (self.signed if signed is None else signed) else 0),
                self.ses if ses is None else ses, self.tid if tid is None else tid, 0, 1, charge, nxt, aid)
        if (self.signed if signed is None else signed):
            h = sign(h)
        data = h + body
        if send:
            self.c.rep('c', data)
        return m, data

    def rsp(self, cmd, mid, body, status=0, tid=None, ses=None, flags=0, credit=1, aid=None, nxt=0, send=True):
        h = hdr(cmd, mid, F_RESP | flags, self.ses if ses is None else ses, self.tid if tid is None else tid,
                status, credit, 0, nxt, aid)
        data = h + body
        if send:
            self.c.rep('s', data)
        return data

    def x(self, cmd, rq, rs, status=0, tid=None, ses=None, rflags=0, **kw):
        m, _ = self.req(cmd, rq, tid=tid, ses=ses, **kw)
        self.rsp(cmd, m, rs, status=status, tid=tid, ses=ses, flags=rflags)
        return m


def negotiate(s, dialects, ctxs_req, dialect, ctxs_rep, **kw):
    s.x(NEGOTIATE, neg_req(dialects, ctxs_req), neg_rep(dialect, ctxs_rep, **kw), tid=0, ses=0)


def logon(s, ses=SES, sflags=0, secmode=1):
    m, _ = s.req(SESSION_SETUP, ses_req(), ses=0, tid=0)
    s.rsp(SESSION_SETUP, m, ses_rep(0, spnego_init()), status=STATUS_MORE_PROCESSING, ses=ses, tid=0)
    m, _ = s.req(SESSION_SETUP, ses_req(secmode=secmode), ses=ses, tid=0)
    s.rsp(SESSION_SETUP, m, ses_rep(sflags), ses=ses, tid=0)


def tree(s, path=SHARE, tid=TID, stype=1, sflags=0x800, caps=0, access=0x1f01ff, flags=0):
    s.x(TREE_CONNECT, tcon_req(path, flags), tcon_rep(stype, sflags, caps, access), tid=0, rflags=0)
    # the response carries the new tree id
    return tid


def tree_x(s, path, tid, **kw):
    m, _ = s.req(TREE_CONNECT, tcon_req(path, kw.get('flags', 0)), tid=0)
    s.rsp(TREE_CONNECT, m, tcon_rep(kw.get('stype', 1), kw.get('sflags', 0x800), kw.get('caps', 0),
                                    kw.get('access', 0x1f01ff)), tid=tid)


def opn(s, name, fid=FID, ctxs_rq=b'', ctxs_rp=b'', tid=None, **kw):
    s.x(CREATE, create_req(name, ctxs=ctxs_rq, **kw), create_rep(fid, ctxs=ctxs_rp), tid=tid)


def cls(s, fid=FID, flags=0, tid=None):
    s.x(CLOSE, close_req(fid, flags), close_rep(flags), tid=tid)


def gi(s, itype, cls_, data, fid=FID, **kw):
    s.x(GETINFO, getinfo_req(itype, cls_, fid=fid, **kw), getinfo_rep(data))


def si_(s, itype, cls_, data, fid=FID, addl=0):
    s.x(SETINFO, setinfo_req(itype, cls_, data, addl, fid), setinfo_rep())


def ioc(s, code, indata=b'', outdata=b'', rin=b'', rout=b'', fid=FID, status=0, **kw):
    s.x(IOCTL, ioctl_req(code, indata, fid=fid, **kw), ioctl_rep(code, rout, rin, fid=fid), status=status)


# ---------------------------------------------------------------------
# connection A: SMB 3.1.1
A = Conn(main, 10, 11, 49200)
sa = Sess(A)
mark('A: negotiate 3.1.1 with every negotiate context')
negotiate(sa, (0x0202, 0x0210, 0x0300, 0x0302, 0x0311),
          [ctx_preauth(), ctx_enc((2, 1, 4, 3)), ctx_comp(), ctx_netname(), ctx_transport(), ctx_rdma(), ctx_signing(),
           ctx_posix(), ctx_unknown()],
          0x0311, [ctx_preauth(), ctx_enc((2,)), ctx_comp((1, 5)), ctx_rdma((1,)), ctx_signing((2,)), ctx_posix()],
          caps=0x7f)
mark('A: session setup (two legs), tree connects')
logon(sa, sflags=0)
tree_x(sa, '\\\\server.example.com\\IPC$', 8, stype=2, sflags=0x30, caps=0x8, access=0x1f01ff)
tree_x(sa, SHARE, TID, stype=1, sflags=0x0000d800 | 0x30, caps=0x7f, access=0x00120089)
sa.tid = TID

# ---- create with contexts, close, all create contexts -----------------
LK = b'LEASEKEY' * 2
CG = b'CREATEGUID123456'
ctx_rq_all = create_ctxs([
    (b'ExtA', fi_ea([(b'user.attr', b'value', 0), (b'second', b'', 0x80)])),
    (b'SecD', sec_desc()),
    (b'AlSi', struct.pack('<Q', 1 << 20)),
    (b'MxAc', ft(5)),
    (b'DHnQ', b'\0' * 16),
    (b'DH2Q', struct.pack('<II', 60000, 2) + b'\0' * 8 + CG),
    (b'TWrp', ft(9)),
    (b'QFid', b''),
    (b'RqLs', LK + struct.pack('<IIQ', 7, 0, 0)),
    (uuid.UUID('6aa6bc45-a7ef-4af7-9008-fa462e144d74').bytes_le, struct.pack('<HH', 20, 0) + b'\xaa' * 16),
    (uuid.UUID('b7d082b9-563b-4f07-a07b-524a8116a010').bytes_le, struct.pack('<HHIQQ', 24, 0, 0, 1, 2)),
    (bytes.fromhex('93AD25509CB411E7B42383DE968BCD7C'), struct.pack('<I', 0o644)),
    (b'AAPL', struct.pack('<IIQQ', 1, 0, 7, 0x1d)),
    (uuid.UUID('9ecfcb9c-c104-43e6-980e-158da1f6ec83').bytes_le,
     struct.pack('<IB3x16sIIQH', 2, 1, b'\x0a' * 16, 1, 2, 77, 8) + b'host-name'.ljust(126, b'\0') +
     struct.pack('<IIIIQ', 1, 5, 512, 4096, 1 << 30)),
    (uuid.UUID('9ecfcb9c-c104-43e6-980e-158da1f6ec83').bytes_le,
     struct.pack('<IB3x16sIIQH', 1, 0, b'\x0a' * 16, 1, 2, 77, 4) + b'host'.ljust(126, b'\0')),
])
ctx_rp_all = create_ctxs([
    (b'MxAc', struct.pack('>I', 0) + struct.pack('<I', 0x1f01ff)),
    (b'QFid', b'\x01' * 8 + b'\x02' * 8 + b'\0' * 16),
    (b'RqLs', LK + struct.pack('<IIQ', 7, 0, 0)),
    (b'RqLs', LK + struct.pack('<IIQ16sHH', 7, 4, 0, b'\x09' * 16, 5, 0)),
    (b'DH2Q', struct.pack('<II', 60000, 2)),
    (b'DHnQ', b'\0' * 8),
    (bytes.fromhex('93AD25509CB411E7B42383DE968BCD7C'), struct.pack('<III', 1, 0xa000000c, 0o644) + sid((21, 1, 2, 1000)) + sid((21, 1, 2, 100))),
    (b'AAPL', struct.pack('<IIQ', 1, 0, 7) + struct.pack('<Q', 0x1d) + struct.pack('<Q', 0x5) + struct.pack('<Q', 7) + struct.pack('<II', 0, 8)[:8]),
])
mark('A: create with every request create context, response with contexts')
sa.x(CREATE, create_req('dir\\file.txt', ctxs=ctx_rq_all, share=7, opts=0x40 | 0x1000), create_rep(FID, ctxs=ctx_rp_all, oplock=0xff))
# the wildcard FID of related operations after the create is used below in compounds
gi(sa, 1, 4, fi_basic())
mark('A: getinfo/setinfo file info levels')
for lvl, data in [(4, fi_basic()), (5, fi_standard()), (6, fi_internal()), (7, struct.pack('<I', 0)), (8, struct.pack('<I', 0x1f01ff)),
                  (14, struct.pack('<Q', 0)), (16, struct.pack('<I', 0)), (17, struct.pack('<I', 3)), (18, fi_all()),
                  (21, fi_name('SHORT~1.TXT')), (22, fi_stream([('::$DATA', 100, 4096), (':ads:$DATA', 5, 8)])),
                  (23, fi_pipe()), (24, fi_pipe_local()), (25, fi_pipe_remote()), (28, fi_compression()),
                  (34, fi_network_open()), (35, fi_attr_tag()), (48, fi_name('\\dir\\file.txt')), (100, fi_posix()),
                  (15, fi_ea([(b'user.attr', b'value', 0), (b'two', b'2', 0x80)])), (99, b'\x01\x02\x03\x04')]:
    gi(sa, 1, lvl, data)
gi(sa, 1, 15, fi_ea([(b'user.attr', b'value', 0)]), addl=0, flags=1 | 2 | 4, inbuf=struct.pack('<IB', 0, 9) + b'user.attr\0')
for lvl, data in [(4, fi_basic(0x80)), (10, fi_rename()), (11, fi_rename('hardlink.txt', 0)), (13, b'\x01'), (14, struct.pack('<Q', 4096)),
                  (16, struct.pack('<I', 2)), (19, struct.pack('<Q', 1 << 20)), (20, struct.pack('<Q', 1 << 19)),
                  (23, fi_pipe()), (28, struct.pack('<H', 2)), (15, fi_ea([(b'new', b'1', 0)]))]:
    si_(sa, 1, lvl, data)
mark('A: getinfo/setinfo file system, security, quota info')
for lvl, data in [(1, FS_VOLUME), (3, FS_SIZE), (4, FS_DEVICE), (5, FS_ATTR), (6, FS_CONTROL), (7, FS_FULLSIZE), (8, FS_OBJECTID),
                  (100, FS_POSIX), (9, b'\x01' * 28)]:
    gi(sa, 2, lvl, data)
si_(sa, 2, 6, FS_CONTROL)
si_(sa, 2, 8, FS_OBJECTID)
gi(sa, 3, 0, sec_desc(sacl=True), addl=0xf)
gi(sa, 3, 0, sec_desc(), addl=0x80)
si_(sa, 3, 0, sec_desc(), addl=0x7)
gi(sa, 4, 0, quota_entries(), inbuf=quota_query(sids=[sid((21, 1, 2, 1000)), sid((21, 1, 2, 1001))]))
gi(sa, 4, 0, quota_entries(1), inbuf=quota_query(start=sid((21, 1, 2, 1000)), single=1))
gi(sa, 4, 0, quota_entries(1), inbuf=quota_query())
si_(sa, 4, 0, quota_entries())
gi(sa, 9, 1, b'\x00\x01\x02')
si_(sa, 9, 1, b'\x00\x01\x02')
mark('A: getinfo errors and buffer problems')
sa.x(GETINFO, getinfo_req(1, 5), error_rep(), status=STATUS_INFO_LENGTH_MISMATCH)
m, _ = sa.req(GETINFO, getinfo_req(2, 5, outlen=16))
sa.rsp(GETINFO, m, getinfo_rep(FS_ATTR), status=STATUS_BUFFER_OVERFLOW)
m, _ = sa.req(GETINFO, getinfo_req(1, 18, outlen=4))
sa.rsp(GETINFO, m, struct.pack('<HHII', 9, 0, 0, 200), status=STATUS_BUFFER_TOO_SMALL)
sa.x(SETINFO, setinfo_req(1, 13, b'\x01'), error_rep(), status=STATUS_ACCESS_DENIED)

# ---- find -------------------------------------------------------------
mark('A: find with every information class, no more files, patterns')
dfid = FID2
sa.x(CREATE, create_req('dir', attrs=0x10, opts=1, access=0x100081, disp=1), create_rep(dfid, attrs=0x10))
names = ['.', '..', 'file1.txt', 'file2.txt', u'späce name.txt']
for c in (1, 2, 3, 12, 0x25, 0x26, 0x64):
    sa.x(FIND, find_req(c, 1, 0, dfid, '*'), find_rep(dirents(c, names, short=u16s('FILE~1.TXT'))))
    sa.x(FIND, find_req(c, 0, 0, dfid, '*'), error_rep(), status=STATUS_NO_MORE_FILES)
sa.x(FIND, find_req(0x25, 2 | 1, 0, dfid, '*.txt'), find_rep(dirents(0x25, ['file1.txt'], reparse=True)))
sa.x(FIND, find_req(0x25, 4, 3, dfid, ''), find_rep(dirents(0x25, ['x'])))
sa.x(FIND, find_req(0x25, 0x10, 0, dfid, '*'), find_rep(dirents(0x25, ['x'])))
sa.x(FIND, find_req(0x02, 1, 0, dfid, '*'), find_rep(dirents(2, ['a', 'b'], reparse=True)))
sa.x(FIND, find_req(0x26, 1, 0, dfid, '*'), find_rep(dirents(0x26, ['a', 'b'], reparse=True)))
sa.x(FIND, find_req(0x03, 1, 0, dfid, '*'), find_rep(dirents(3, ['a', 'b'], reparse=True)))
sa.x(FIND, find_req(0x7f, 1, 0, dfid, '*'), find_rep(b'\x01\x02\x03\x04\x05\x06\x07\x08'))
sa.x(FIND, find_req(0x25, 1, 0, dfid, '*'), error_rep(), status=STATUS_INVALID_PARAMETER)
cls(sa, dfid)

# ---- ioctl ---------------------------------------------------------------
mark('A: ioctls (requests and responses)')
ioc(sa, 0x00060194, indata=struct.pack('<H', 4) + u16s('\\server\\share') + b'\0\0', rout=b'')
sa.x(IOCTL, ioctl_req(0x00060194, struct.pack('<H', 4) + u16s('\\server\\share') + b'\0\0', fid=WILD),
     ioctl_rep(0x00060194, struct.pack('<HHI', 0, 0, 0)[:0] + b'\x00\x00\x00\x00', fid=WILD), status=0)
ioc(sa, 0x000601B0, indata=fsctl_dfs_ex(), rout=b'\0' * 4, fid=WILD)
ioc(sa, 0x000601B0, indata=fsctl_dfs_ex(site='site1'), rout=b'\0' * 4, fid=WILD)
ioc(sa, 0x000940CF, indata=rng(0, 1 << 20), rout=rng(0, 4096) + rng(8192, 4096))
ioc(sa, 0x00094264, indata=fsctl_offload_read_in(), rout=fsctl_offload_read_out())
ioc(sa, 0x00098268, indata=fsctl_offload_write_in(), rout=fsctl_offload_write_out())
ioc(sa, 0x00140078, indata=b'', rout=fsctl_resume_key_out())
ioc(sa, 0x001440F2, indata=fsctl_copychunk_in(), rout=fsctl_copychunk_out())
ioc(sa, 0x001480F2, indata=fsctl_copychunk_in(1), rout=fsctl_copychunk_out())
ioc(sa, 0x001401D4, indata=struct.pack('<II', 5000, 0), rout=b'')
ioc(sa, 0x001401FC, indata=b'', rout=fsctl_netif([4, 6, 99, 4, 6]), fid=WILD)
ioc(sa, 0x00140200, indata=fsctl_validate_neg_224_in(), rout=fsctl_validate_neg_224_out(), fid=WILD)
ioc(sa, 0x00140204, indata=fsctl_validate_neg_in(), rout=fsctl_validate_neg_out(), fid=WILD)
ioc(sa, 0x00144064, indata=b'', rout=fsctl_snapshots(2))
ioc(sa, 0x000900A4, indata=fsctl_reparse(0xa000000c, reparse_symlink()), rout=b'')
ioc(sa, 0x000900A8, indata=b'', rout=fsctl_reparse(0xa000000c, reparse_symlink()))
ioc(sa, 0x000900A8, indata=b'', rout=fsctl_reparse(0xa0000003, reparse_mount()))
ioc(sa, 0x000900A8, indata=b'', rout=fsctl_reparse(0xa000001d, struct.pack('<I', 1) + u16s('target')[:0] + b'/usr/target'))
ioc(sa, 0x000900A8, indata=b'', rout=fsctl_reparse(0xa000001d, struct.pack('<I', 2) + b'/usr/target2'))
ioc(sa, 0x000900A8, indata=b'', rout=fsctl_reparse(0xa000001d, struct.pack('<I', 9) + b'zz'))
ioc(sa, 0x000900A8, indata=b'', rout=fsctl_reparse(0x80000023, b''))
ioc(sa, 0x000900A8, indata=b'', rout=fsctl_reparse(0x80000025, b''))
ioc(sa, 0x000900A8, indata=b'', rout=fsctl_reparse(0x80001234, b'\x01\x02'))
ioc(sa, 0x000900A8, indata=b'', rout=fsctl_reparse(0x00000001, b'\x01\x02'))
ioc(sa, 0x000900A8, indata=b'', rout=fsctl_reparse(0x80000024, b''))
for typ, rest in ((0x14b4e4c, u16s('target')), (0x524843, struct.pack('<II', 4, 5)), (0x4b4c42, struct.pack('<II', 8, 9)),
                  (0x4f464946, b''), (0x4b434f53, b''), (0x77, b'')):
    ioc(sa, 0x000900A8, indata=b'', rout=fsctl_reparse(0x80000014, struct.pack('<Q', typ) + rest))
ioc(sa, 0x0009009C, indata=b'', rout=fsctl_objectid())
ioc(sa, 0x000900c0, indata=b'', rout=fsctl_objectid())
ioc(sa, 0x000900c4, indata=b'\x01', rout=b'')
ioc(sa, 0x000900c4, indata=b'', rout=b'')
ioc(sa, 0x00098098, indata=fsctl_objectid(), rout=b'')
ioc(sa, 0x000980BC, indata=fsctl_objectid()[16:], rout=b'')
ioc(sa, 0x000980C8, indata=rng(4096, 4096), rout=b'')
ioc(sa, 0x0009003C, indata=b'', rout=struct.pack('<H', 2))
ioc(sa, 0x0009C040, indata=struct.pack('<H', 2), rout=b'')
ioc(sa, 0x00090300, indata=b'', rout=struct.pack('<II', 1, 2))
ioc(sa, 0x00090304, indata=fsctl_svhdx(), rout=fsctl_svhdx())
ioc(sa, 0x00090364, indata=fsctl_svhdx(), rout=fsctl_svhdx())
ioc(sa, 0x00090350, indata=fsctl_sqos(True), rout=fsctl_sqos(False))
ioc(sa, 0x00090350, indata=fsctl_sqos(True, 0x0100), rout=fsctl_sqos(False, 0x0100))
ioc(sa, 0x00090284, indata=fsctl_file_regions_in(), rout=fsctl_file_regions_out())
ioc(sa, 0x0009027c, indata=b'', rout=fsctl_integrity_get())
ioc(sa, 0x0009C280, indata=fsctl_integrity_set(), rout=b'')
ioc(sa, 0x00090380, indata=fsctl_integrity_set_ex(), rout=b'')
ioc(sa, 0x00090064, indata=b'', rout=fsctl_ntfs_volume_data())
ioc(sa, 0x00090440, indata=fsctl_refs_snapshot(1), rout=b'')
ioc(sa, 0x00090440, indata=fsctl_refs_snapshot(3), rout=b'')
ioc(sa, 0x00098344, indata=fsctl_dup_extents(FID2), rout=b'')
ioc(sa, 0x00110018, indata=fsctl_pipe_wait('srvsvc'), rout=b'', fid=WILD)
ioc(sa, 0x00110018, indata=fsctl_pipe_wait('lsarpc', False), rout=b'', fid=WILD)
ioc(sa, 0x00090000 | 0x1234, indata=b'\x01\x02\x03', rout=b'\x04\x05')   # unknown ioctl
ioc(sa, 0, indata=b'', rout=b'')                                       # no function
ioc(sa, 0x000940CF, indata=rng(0, 1), rout=b'', status=STATUS_BUFFER_OVERFLOW)
sa.x(IOCTL, ioctl_req(0x000940CF, rng(0, 1)), error_rep(), status=STATUS_ACCESS_DENIED)
mark('A: ioctl with the buffer order output before input')
m, _ = sa.req(IOCTL, struct.pack('<HHI16sIIIIIIII', 57, 0, 0x000940CF, FID, 64 + 56 + 16, 16, 0, 64 + 56, 16, 65536, 1, 0) + rng(0, 9) + rng(0, 5))
sa.rsp(IOCTL, m, ioctl_rep(0x000940CF, rng(0, 4096), b''))
m, _ = sa.req(IOCTL, ioctl_req(0x000940CF, rng(0, 5)))
rp = struct.pack('<HHI16sIIIIII', 49, 0, 0x000940CF, FID, 64 + 48 + 16, 16, 64 + 48, 16, 0, 0) + rng(0, 7) + rng(8, 9)
sa.rsp(IOCTL, m, rp)

# ---- pipe ---------------------------------------------------------------------
mark('A: named pipe on IPC$: DCE/RPC bind split in two writes and two reads (pipe reassembly)')
PFID = bytes.fromhex('1111111111111111') + bytes.fromhex('2222222222222222')
sa.x(CREATE, create_req('srvsvc', access=0x12019f, share=7, disp=1, opts=0), create_rep(PFID), tid=8)
b = dcerpc_bind()
sa.x(WRITE, write_req(b[:30], fid=PFID), write_rep(30), tid=8)
sa.x(WRITE, write_req(b[30:], fid=PFID, offset=30), write_rep(len(b) - 30), tid=8)
ba = dcerpc_bind_ack()
sa.x(READ, read_req(PFID, 4096), read_rep(ba[:20]), tid=8)
sa.x(READ, read_req(PFID, 4096), read_rep(ba[20:]), tid=8)
sa.x(IOCTL, ioctl_req(0x0011c017, dcerpc_bind(2), fid=PFID, maxout=4096),
     ioctl_rep(0x0011c017, dcerpc_bind_ack(2), b'', fid=PFID), tid=8)
sa.x(WRITE, write_req(dcerpc_bind(3), fid=PFID), write_rep(len(dcerpc_bind(3))), tid=8)
sa.x(READ, read_req(PFID, 4096), read_rep(dcerpc_bind_ack(3)), tid=8)
cls(sa, PFID, tid=8)

# ---- read / write -----------------------------------------------------------------
mark('A: read and write variants')
sa.x(READ, read_req(FID, 4096), read_rep(b'R' * 100))
sa.x(READ, read_req(FID, 65536, 100, flags=1), read_rep(b'R' * 4096, remaining=0))
sa.x(READ, read_req(FID, 4096, 8, flags=2, minc=10, remaining=100), read_rep(b'R' * 10))
sa.x(READ, read_req(FID, 0, 0), read_rep(b''), status=0)
sa.x(READ, read_req(FID, 4096, 1 << 33), error_rep(), status=0xc0000011)       # END_OF_FILE
sa.x(READ, read_req(FID, 4096, 0, channel=1, rci=struct.pack('<QII', 0x1000, 0x2000, 4096)), read_rep(b''),)
sa.x(READ, read_req(FID, 4096, 0, channel=2, rci=struct.pack('<QII', 0x1000, 0x2000, 4096) * 2), read_rep(b''))
sa.x(READ, read_req(FID, 4096, 0, channel=3), read_rep(b'R' * 20))
sa.x(READ, read_req(FID, 4096, 0, channel=9, rci=b'\x01\x02'), read_rep(b'R' * 20))
# read response with an RDMA transform: Flags=1, data is a transform descriptor
sa.x(READ, read_req(FID, 4096), read_rep(rdma_xform_blob(1, 2, 2), flags=1))
sa.x(READ, read_req(FID, 4096), read_rep(rdma_xform_blob(0, 0, 0), flags=1))
sa.x(WRITE, write_req(b'W' * 200), write_rep(200))
sa.x(WRITE, write_req(b'W' * 200, offset=200, flags=1 | 2), write_rep(200, remaining=0))
sa.x(WRITE, write_req(b'', channel=1, remaining=4096, wci=struct.pack('<QII', 0x1000, 0x2000, 4096)), write_rep(4096, wci_off=0, wci_len=0))
sa.x(WRITE, write_req(b'', channel=2, remaining=4096, wci=struct.pack('<QII', 0x1000, 0x2000, 4096) * 3), write_rep(4096))
sa.x(WRITE, write_req(b'', channel=3, remaining=4096, wci=rdma_xform_blob(1, 1, 1)), write_rep(4096))
sa.x(WRITE, write_req(b'', channel=3, remaining=4096, wci=rdma_xform_blob(2, 2, 0)), write_rep(4096))
sa.x(WRITE, write_req(b'W' * 10), error_rep(), status=0xc000007f)        # DISK_FULL
sa.x(WRITE, write_req(b'W' * 10), write_rep(10, 5, 8, 16))
mark('A: flush, lock, echo')
sa.x(FLUSH, flush_req(), flush_rep())
sa.x(LOCK, lock_req([(0, 100, 2)], seq=0x15), lock_rep())
sa.x(LOCK, lock_req([(0, 100, 1), (200, 100, 3), (400, 100, 4)], seq=0x2a), lock_rep())
sa.x(LOCK, lock_req([(0, 100, 5)]), error_rep(), status=0xc0000054)      # LOCK_NOT_GRANTED
sa.x(ECHO, echo_req(), echo_rep())
sa.x(ECHO, echo_req(), echo_rep(), tid=0)

# ---- error responses -----------------------------------------------------
mark('A: error responses: symlink, share redirect, buffer too small, error contexts')


def symlink_err(sub='\\??\\C:\\target', prt='C:\\target', unparsed=0):
    s, p = u16s(sub), u16s(prt)
    d = struct.pack('<IIIHHHHHHI', 28 + len(s) + len(p) - 4 + 4, 0x4c4d5953, 0xa000000c, 12 + len(s) + len(p), unparsed,
                    0, len(s), len(s), len(p), 1)
    return d + s + p


def redirect_err(name='server2.example.com'):
    n = u16s(name)
    ips = struct.pack('<HH4s', 2, 445, bytes([192, 0, 2, 99])) + struct.pack('<HHI16sI', 23, 445, 0, b'\x20\x01' + b'\0' * 14, 0)[:26]
    if os.environ.get('SMB2_NO_REDIRECT_IPS'):
        # variant for tools/fuzz-test.sh: the IP list loop of the share redirect error is
        # bounded by 50000 items per packet, which aborts the fuzzer (see README, bug 1)
        return struct.pack('<IIIIHHI', 24, 3, 0, len(n), 0, 1, 0) + n
    return struct.pack('<IIIIHHI', 24, 3, 0, len(n), 0, 1, 2) + ips + n


def err_ctx(ident, data):
    return pad(struct.pack('<II', len(data), ident) + data)


m, _ = sa.req(CREATE, create_req('link\\file'))
sa.rsp(CREATE, m, error_rep(data=symlink_err(unparsed=10)), status=STATUS_STOPPED_ON_SYMLINK)
m, _ = sa.req(CREATE, create_req('link2'))
sa.rsp(CREATE, m, error_rep(data=symlink_err()), status=STATUS_STOPPED_ON_SYMLINK)
sa.x(CREATE, create_req('missing'), error_rep(), status=STATUS_OBJECT_NAME_NOT_FOUND)
sa.x(CREATE, create_req('denied'), error_rep(), status=STATUS_ACCESS_DENIED)
m, _ = sa.req(CREATE, create_req('big'))
sa.rsp(CREATE, m, struct.pack('<HBBI', 9, 0, 0, 4) + struct.pack('<I', 100), status=STATUS_BUFFER_TOO_SMALL)
rc = err_ctx(0x72645253, redirect_err())
m, _ = sa.req(TREE_CONNECT, tcon_req('\\\\other.example.com\\Share'), tid=0)
sa.rsp(TREE_CONNECT, m, error_rep(ctxs=rc, count=1), status=STATUS_BAD_NETWORK_NAME, tid=0)
m, _ = sa.req(TREE_CONNECT, tcon_req('\\\\other.example.com\\Share'), tid=0)
sa.rsp(TREE_CONNECT, m, error_rep(ctxs=err_ctx(0x77, b'\x01\x02\x03'), count=1), status=STATUS_BAD_NETWORK_NAME, tid=0)
m, _ = sa.req(TREE_CONNECT, tcon_req('\\\\other.example.com\\Share'), tid=0)
sa.rsp(TREE_CONNECT, m, error_rep(ctxs=rc + err_ctx(0x77, b'\x01\x02\x03\x04\x05\x06'), count=2), status=STATUS_BAD_NETWORK_NAME, tid=0)
m, _ = sa.req(TREE_CONNECT, tcon_req('\\\\other.example.com\\Share'), tid=0)
sa.rsp(TREE_CONNECT, m, error_rep(data=rc), status=STATUS_BAD_NETWORK_NAME, tid=0)
m, _ = sa.req(CLOSE, close_req(FID2))
sa.rsp(CLOSE, m, error_rep(), status=STATUS_FILE_CLOSED)
m, _ = sa.req(READ, read_req(FID2, 10))
sa.rsp(READ, m, error_rep(), status=STATUS_FILE_CLOSED)
m, _ = sa.req(WRITE, write_req(b'x', fid=FID2))
sa.rsp(WRITE, m, error_rep(), status=STATUS_FILE_CLOSED)
m, _ = sa.req(IOCTL, ioctl_req(0x00090000, b''))
sa.rsp(IOCTL, m, error_rep(), status=STATUS_BUFFER_TOO_SMALL)
m, _ = sa.req(NOTIFY, notify_req(FID2))
sa.rsp(NOTIFY, m, error_rep(), status=STATUS_FILE_CLOSED)
m, _ = sa.req(FIND, find_req(0x25, 1, 0, FID2))
sa.rsp(FIND, m, error_rep(), status=STATUS_FILE_CLOSED)
m, _ = sa.req(LOCK, lock_req([(0, 1, 2)], fid=FID2))
sa.rsp(LOCK, m, error_rep(), status=STATUS_FILE_CLOSED)
m, _ = sa.req(FLUSH, flush_req(FID2))
sa.rsp(FLUSH, m, error_rep(), status=STATUS_FILE_CLOSED)
m, _ = sa.req(SESSION_SETUP, ses_req(), ses=0, tid=0)
sa.rsp(SESSION_SETUP, m, ses_rep(0, b''), status=0xc000006d, ses=0, tid=0)
m, _ = sa.req(ECHO, echo_req())
sa.rsp(ECHO, m, error_rep(), status=STATUS_USER_SESSION_DELETED)
m, _ = sa.req(LOGOFF, logoff_req(), ses=0x77, tid=0)
sa.rsp(LOGOFF, m, error_rep(), status=STATUS_USER_SESSION_DELETED, ses=0x77, tid=0)
m, _ = sa.req(TREE_DISCONNECT, tdis_req(), tid=99)
sa.rsp(TREE_DISCONNECT, m, error_rep(), status=STATUS_NETWORK_NAME_DELETED, tid=99)
m, _ = sa.req(0x21, b'\x04\0\0\0')
sa.rsp(0x21, m, b'\x04\0\0\0')

# ---- notify, async, cancel ---------------------------------------------------------
mark('A: change notify with STATUS_PENDING, async responses and cancels')


def notify_data(items):
    out = b''
    for i, (act, name) in enumerate(items):
        n = u16s(name)
        e = struct.pack('<III', 0, act, len(n)) + n
        if i != len(items) - 1:
            e = pad(e, 4)
            e = struct.pack('<I', len(e)) + e[4:]
        out += e
    return out


AID = 0x1000
# 1: pending, then the final response with data
m1, _ = sa.req(NOTIFY, notify_req(FID, flags=1, filt=0x1ff))
sa.rsp(NOTIFY, m1, error_rep(), status=STATUS_PENDING, aid=AID + 1)
sa.x(ECHO, echo_req(), echo_rep())
sa.rsp(NOTIFY, m1, notify_rep(notify_data([(1, 'new.txt'), (2, 'old.txt'), (3, 'mod.txt'), (4, 'a'), (5, 'b'), (0x77, 'c')])),
       aid=AID + 1)
# 2: pending, cancelled by AsyncId (message id 0), STATUS_CANCELLED
m2, _ = sa.req(NOTIFY, notify_req(FID))
sa.rsp(NOTIFY, m2, error_rep(), status=STATUS_PENDING, aid=AID + 2)
sa.req(CANCEL, cancel_req(), aid=AID + 2, mid=0)
sa.rsp(NOTIFY, m2, error_rep(), status=STATUS_CANCELLED, aid=AID + 2)
# 3: cancelled by message id without a pending response
m3, _ = sa.req(NOTIFY, notify_req(FID))
sa.req(CANCEL, cancel_req(), mid=m3)
sa.rsp(NOTIFY, m3, error_rep(), status=STATUS_CANCELLED)
# 4: pending, cancelled by the message id, cancelled response
m4, _ = sa.req(READ, read_req(FID, 10))
sa.rsp(READ, m4, error_rep(), status=STATUS_PENDING, aid=AID + 4)
sa.req(CANCEL, cancel_req(), mid=m4)
sa.rsp(READ, m4, error_rep(), status=STATUS_CANCELLED, aid=AID + 4)
# 5: a cancel with an AsyncId that nothing is pending for, then ENUM_DIR
sa.req(CANCEL, cancel_req(), aid=AID + 9, mid=0)
m5, _ = sa.req(NOTIFY, notify_req(FID, outlen=4))
sa.rsp(NOTIFY, m5, notify_rep(), status=STATUS_NOTIFY_ENUM_DIR)
# 6: lock pending then granted
m6, _ = sa.req(LOCK, lock_req([(0, 5, 2)]))
sa.rsp(LOCK, m6, error_rep(), status=STATUS_PENDING, aid=AID + 6)
sa.rsp(LOCK, m6, lock_rep(), aid=AID + 6)
# 7: the interim response to a request that is cancelled before the final response, which is the success response
m7, _ = sa.req(NOTIFY, notify_req(FID))
sa.rsp(NOTIFY, m7, error_rep(), status=STATUS_PENDING, aid=AID + 7)
sa.req(CANCEL, cancel_req(), aid=AID + 7, mid=0)
sa.rsp(NOTIFY, m7, notify_rep(notify_data([(1, 'x')])), aid=AID + 7)
# 8: server to client notification and breaks
mark('A: oplock and lease breaks, server to client notification')
sa.rsp(BREAK, 0xffffffffffffffff, struct.pack('<HBBI16s', 24, 1, 0, 0, FID), ses=0, tid=0)
sa.x(BREAK, break_oplock(FID, 1), struct.pack('<HBBI16s', 24, 1, 0, 0, FID))
sa.rsp(BREAK, 0xffffffffffffffff, break_lease_notify(), ses=0, tid=0)
sa.x(BREAK, break_lease_ack(), struct.pack('<HHI16sIQ', 36, 0, 0, b'L' * 16, 3, 0))
sa.x(BREAK, break_lease_ack(state=1, flags=0), struct.pack('<HHI16sIQ', 36, 0, 0, b'L' * 16, 1, 0))
sa.rsp(BREAK, 0xffffffffffffffff, break_lease_notify(cur=3, new=0, flags=0), ses=0, tid=0)
sa.x(BREAK, struct.pack('<H', 99) + b'\0' * 30, struct.pack('<H', 99) + b'\0' * 30)
sa.rsp(SRV_NOTIFY, 0xffffffffffffffff, srv_notify(1), ses=SES, tid=0)
sa.rsp(SRV_NOTIFY, 0xffffffffffffffff, srv_notify(9, b'\0' * 8), ses=SES, tid=0)

# ---- compound requests and responses ------------------------------------------------------
mark('A: compound requests and responses (related operations with the wildcard file id)')


def compound(side, items):
    """items: list of (cmd, mid, body, flags, status); returns a single PDU of chained commands"""
    out = b''
    for i, (cmd, mid, body, fl, st) in enumerate(items):
        last = i == len(items) - 1
        msg = pad(hdr(cmd, mid, fl | (0 if i == 0 else F_CHAIN) | (F_RESP if side == 's' else 0), SES, TID, st) + body)
        if not last:
            msg = msg[:20] + struct.pack('<I', len(msg)) + msg[24:]
        else:
            msg = msg[:len(msg)]
        out += msg
    return out


mc = sa.next_mid(3)
sa.c.rep('c', compound('c', [(CREATE, mc, create_req('comp.txt'), 0, 0), (GETINFO, mc + 1, getinfo_req(1, 4, fid=WILD), 0, 0),
                           (CLOSE, mc + 2, close_req(WILD, 1), 0, 0)]))
sa.c.rep('s', compound('s', [(CREATE, mc, create_rep(FID2), 0, 0), (GETINFO, mc + 1, getinfo_rep(fi_basic()), 0, 0),
                           (CLOSE, mc + 2, close_rep(1), 0, 0)]))
mc = sa.next_mid(2)
sa.c.rep('c', compound('c', [(WRITE, mc, write_req(b'compound', FID), 0, 0), (FLUSH, mc + 1, flush_req(WILD), 0, 0)]))
sa.c.rep('s', compound('s', [(WRITE, mc, write_rep(8), 0, 0), (FLUSH, mc + 1, error_rep(), 0, STATUS_ACCESS_DENIED)]))
# compound with a pending interim response
mc = sa.next_mid(2)
sa.c.rep('c', compound('c', [(ECHO, mc, echo_req(), 0, 0), (NOTIFY, mc + 1, notify_req(WILD), 0, 0)]))
sa.c.rep('s', compound('s', [(ECHO, mc, echo_rep(), 0, 0), (NOTIFY, mc + 1, error_rep(), 0, STATUS_PENDING)]))
# unrelated compound with a signed first command
mc = sa.next_mid(2)
sa.c.rep('c', compound('c', [(ECHO, mc, echo_req(), F_SIGNED, 0), (ECHO, mc + 1, echo_req(), 0, 0)]))
sa.c.rep('s', compound('s', [(ECHO, mc, echo_rep(), 0, 0), (ECHO, mc + 1, echo_rep(), 0, 0)]))

# ---- close, tree disconnect, logoff ------------------------------------------------------------
mark('A: close with attributes, tree disconnect, logoff')
cls(sa, FID, 1)
sa.x(TREE_DISCONNECT, tdis_req(), tdis_rep(), tid=8)
sa.x(TREE_DISCONNECT, tdis_req(), tdis_rep())
sa.x(LOGOFF, logoff_req(), logoff_rep(), tid=0)

# ============ other connections: compression, transforms, dialects ============
def conn_setup(cport, dialect, ctxs_rep=None, ses=None, signed=False, caps=0x7f, ctxs_rq=None, dialects=None):
    ses = ses or (0x5000000000000000 | cport)
    c = Conn(main, 10, 11, cport)
    s = Sess(c, ses=ses, signed=signed)
    negotiate(s, dialects or (0x0202, 0x0210, 0x0300, 0x0302, 0x0311) if dialect >= 0x0311 else (0x0202, 0x0210, dialect),
              ctxs_rq if dialect >= 0x0311 else [], dialect, ctxs_rep or [], caps=caps)
    logon(s, ses=ses)
    tree_x(s, SHARE, TID)
    s.tid = TID
    return c, s


# ---- connection C: compression transform ---------------------------------------------
mark('C: 3.1.1 connection with compressed messages (LZ77, LZ77+Huffman, LZNT1, Pattern_V1, chained)')
cc, sc = conn_setup(49210, 0x0311, [ctx_preauth(), ctx_comp((1, 2, 3, 4)), ctx_enc((2,))],
                    ctxs_rq=[ctx_preauth(), ctx_comp(), ctx_enc((2, 1))])
opn(sc, 'compressed.bin', FID)
data1 = bytes((i // 7) & 0xff for i in range(1500)) + b'a' * 600 + bytes(range(256)) * 2
m, rq = sc.req(READ, read_req(FID, len(data1)))
plain = hdr(READ, m, F_RESP, sc.ses, TID) + read_rep(data1)
PRE = 80


def comp_msg(alg, enc_fn, prefix=PRE, msg=plain, flags=0, **kw):
    pre, body = msg[:prefix], msg[prefix:]
    return comp_hdr(len(body), alg, pre, enc_fn(body, **kw), flags)


cc.rep('s', comp_msg(2, lz77))
m, rq = sc.req(READ, read_req(FID, 3000))
plain2 = hdr(READ, m, F_RESP, sc.ses, TID) + read_rep(b'b' * 3000)
cc.rep('s', comp_msg(3, lz77huff, msg=plain2))
m, rq = sc.req(READ, read_req(FID, 3000))
plain3 = hdr(READ, m, F_RESP, sc.ses, TID) + read_rep(bytes((i * 3) & 0x3f for i in range(3000)))
cc.rep('s', comp_msg(3, lz77huff, msg=plain3, matches=True))
m, rq = sc.req(READ, read_req(FID, 3000))
plain4 = hdr(READ, m, F_RESP, sc.ses, TID) + read_rep(b'c' * 3000 + bytes(range(100)))
cc.rep('s', comp_msg(1, lznt1, msg=plain4))
m, rq = sc.req(READ, read_req(FID, 3000))
plain5 = hdr(READ, m, F_RESP, sc.ses, TID) + read_rep(bytes(range(200)) * 10)
cc.rep('s', comp_msg(1, lznt1_raw, msg=plain5))
# compressed request (write)
m, rq = sc.req(WRITE, write_req(b'w' * 2000), send=False)
cc.rep('c', comp_hdr(len(rq) - 112, 2, rq[:112], lz77(rq[112:])))
sc.rsp(WRITE, m, write_rep(2000))
# whole message compressed (offset 0)
m, rq = sc.req(READ, read_req(FID, 100))
plain6 = hdr(READ, m, F_RESP, sc.ses, TID) + read_rep(b'd' * 100)
cc.rep('s', comp_hdr(len(plain6), 2, b'', lz77(plain6)))
mark('C: chained compression payloads')
m, rq = sc.req(READ, read_req(FID, 5000))
body = b'e' * 3000
plain7 = hdr(READ, m, F_RESP, sc.ses, TID) + read_rep(body)
head, rest = plain7[:80], plain7[80:]
cc.rep('s', chained(len(plain7), [
    chain_payload(0, head, flags=1),
    chain_payload(2, lz77(rest), orig=len(rest), flags=0)]))
m, rq = sc.req(READ, read_req(FID, 5000))
plain8 = hdr(READ, m, F_RESP, sc.ses, TID) + read_rep(b'\xaa' * 256)
cc.rep('s', chained(len(plain8), [
    chain_payload(0, plain8[:80 + 0], flags=1),
    chain_payload(4, pattern_v1(0xaa, 256), flags=0)]))
m, rq = sc.req(READ, read_req(FID, 5000))
tail = bytes(range(256)) * 4
plain9 = hdr(READ, m, F_RESP, sc.ses, TID) + read_rep(b'\x11' * 100 + b'\x22' * 50 + tail)
cc.rep('s', chained(len(plain9), [
    chain_payload(0, plain9[:80], flags=1),
    chain_payload(4, pattern_v1(0x11, 100), flags=1),
    chain_payload(4, pattern_v1(0x22, 50), flags=1),
    chain_payload(1, lznt1(tail), orig=len(tail), flags=1),
    chain_payload(0, b'', flags=0)]))
m, rq = sc.req(READ, read_req(FID, 5000))
plain10 = hdr(READ, m, F_RESP, sc.ses, TID) + read_rep(b'h' * 700)
cc.rep('s', chained(len(plain10), [
    chain_payload(0, plain10[:80], flags=1),
    chain_payload(3, lz77huff(b'h' * 700), orig=700, flags=0)]))
mark('C: compression that fails: unknown algorithm, wrong size, too big, bad data (the fix: 16 MiB per frame)')
cc.rep('s', comp_hdr(100, 9, plain[:80], b'\x01' * 20))                 # unknown algorithm
cc.rep('s', comp_hdr(1234, 2, plain[:80], lz77(b'x' * 100)))             # size mismatch
cc.rep('s', comp_hdr(100, 2, plain[:80], b'\xff' * 12))                  # bad stream
cc.rep('s', comp_hdr(100, 3, plain[:80], b'\x01' * 100))                 # bad Huffman table
cc.rep('s', comp_hdr(100, 1, plain[:80], b'\xff\xff\x01\x02'))           # bad LZNT1
cc.rep('s', comp_hdr(0x7fffffff, 2, plain[:80], lz77(b'x' * 10)))        # larger than the limit
cc.rep('s', chained(100, [chain_payload(9, b'\0' * 8, flags=1), chain_payload(0, b'abc')]))
cc.rep('s', chained(100, [chain_payload(2, lz77(b'x' * 10), orig=0x7fffffff, flags=1), chain_payload(0, b'abc')]))
cc.rep('s', chained(100, [chain_payload(2, b'\xff' * 12, orig=100, flags=1), chain_payload(0, b'abc')]))
# the reproducer: chained Pattern_V1 payloads of 16 MiB each; the second one in a PDU and further PDUs are refused
pb = chained(0, [chain_payload(4, pattern_v1(0x41, 1 << 24), flags=1), chain_payload(4, pattern_v1(0x42, 1 << 24))])
cc.c2s(nbss(pb) * 3)
cc.rep('s', comp_hdr(0xffffff, 2, plain[:80], lz77(b'x' * 10)))

# ---- connections D1-D4: 3.1.1 with each cipher; encrypted frames (garbage, decryption fails) ----
mark('D: SMB 3.1.1 connections negotiating each cipher, encrypted (transform header) messages that cannot be decrypted')
for i, cipher in enumerate((1, 2, 3, 4)):
    cd, sd = conn_setup(49220 + i, 0x0311, [ctx_preauth(), ctx_enc((cipher,))], ctxs_rq=[ctx_preauth(), ctx_enc((cipher, 2))])
    cd.rep('c', transform_hdr(80 + 20 * i, sesid=sd.ses))
    cd.rep('s', transform_hdr(200 + i, sesid=sd.ses))
    cd.rep('c', transform_hdr(60, flags=0, sesid=sd.ses))
    if i == 0:
        cd.rep('c', transform_hdr(100, sesid=sd.ses) + transform_hdr(100, sesid=sd.ses))        # two transform messages in one PDU
        cd.rep('c', transform_hdr(100, sesid=0x7777))                # no such session
        cd.rep('c', transform_hdr(0, body=b'', sesid=sd.ses))
        cd.rep('s', transform_hdr(0, body=b'\0' * 70, sesid=sd.ses))
# the reproducer of the offset wrap (OriginalMessageSize larger than the PDU)
mark('D: transform header with an OriginalMessageSize larger than the data (offset wrapped, now clamped)')
ce = Conn(main, 10, 11, 49230)
for size in (0xFFFFFFFF,):
    th = b'\xfdSMB' + b'\x11' * 16 + b'\xfdSMB' + b'\x22' * 12 + struct.pack('<IHHQ', size, 0, 1, 0x1234)
    ce.rep('c', th + b'\x33' * 64)
# dialect 3.0 and 3.0.2: CCM, no negotiate contexts
mark('D2: SMB 3.0 and 3.0.2 connections with transform headers')
for i, d in enumerate((0x0300, 0x0302)):
    cd, sd = conn_setup(49240 + i, d)
    cd.rep('c', transform_hdr(120, sesid=sd.ses))
    cd.rep('s', transform_hdr(150, sesid=sd.ses))

# ---- other dialects ---------------------------------------------------------------------
mark('E: SMB 2.0.2 connection with signed messages and priority/DFS/replay flags')
cf, sf = conn_setup(49250, 0x0202, signed=True)
opn(sf, 'old.txt', FID)
sf.x(READ, read_req(FID, 100), read_rep(b'x' * 100))
sf.x(WRITE, write_req(b'y' * 10), write_rep(10))
m, _ = sf.req(READ, read_req(FID, 100), flags=0x20 | F_DFS | F_REPLAY)       # priority 2
sf.rsp(READ, m, read_rep(b'x' * 100), flags=0x40)
sf.x(ECHO, echo_req(), echo_rep(), signed=False)
cls(sf, FID)
sf.x(LOGOFF, logoff_req(), logoff_rep(), tid=0)
mark('F: SMB 2.1 connection with leases and multi credit requests')
cg, sg = conn_setup(49260, 0x0210)
lease1 = create_ctxs([(b'RqLs', LK + struct.pack('<IIQ', 3, 0, 0))])
sg.x(CREATE, create_req('lease.txt', ctxs=lease1, oplock=0xff), create_rep(FID, ctxs=create_ctxs([(b'RqLs', LK + struct.pack('<IIQ', 3, 0, 0))]), oplock=0xff))
m, _ = sg.req(READ, read_req(FID, 1 << 20), charge=16)
sg.rsp(READ, m, read_rep(b'z' * 1000))
sg.rsp(BREAK, 0xffffffffffffffff, break_lease_notify(), ses=0, tid=0)
sg.x(BREAK, break_lease_ack(), struct.pack('<HHI16sIQ', 36, 0, 0, b'L' * 16, 3, 0))
cls(sg, FID)
mark('G: wildcard negotiate response (0x02ff), and a connection captured after the negotiate')
ch = Conn(main, 10, 11, 49270)
sh = Sess(ch)
sh.x(NEGOTIATE, neg_req((0x0202, 0x0210)), neg_rep(0x02ff), tid=0, ses=0)
sh.x(NEGOTIATE, neg_req((0x0202, 0x0210, 0x0300, 0x0302, 0x0311), [ctx_preauth()]), neg_rep(0x0210), tid=0, ses=0)
ci = Conn(main, 12, 11, 49271)
si2 = Sess(ci, ses=0x99, tid=0x5)
si2.x(CREATE, create_req('nonegotiate.txt'), create_rep(FID))
si2.x(READ, read_req(FID, 10), read_rep(b'0123456789'))
si2.x(CLOSE, close_req(FID), close_rep())

# ---- TCP level: NBSS PDUs split over segments, several PDUs in a segment, port 139 -------------
mark('H: NBSS PDU split over two and three TCP segments, several PDUs in one segment')
cj, sj = conn_setup(49280, 0x0210)
opn(sj, 'seg.txt', FID)
m, rq = sj.req(READ, read_req(FID, 3000), send=False)
cj.c2s(nbss(rq)[:30])
cj.c2s(nbss(rq)[30:])
rp = sj.rsp(READ, m, read_rep(b'S' * 3000), send=False)
pdu = nbss(rp)
cj.s2c(pdu[:2])
cj.s2c(pdu[2:1000])
cj.s2c(pdu[1000:])
m1, rq1 = sj.req(ECHO, echo_req(), send=False)
m2, rq2 = sj.req(ECHO, echo_req(), send=False)
cj.c2s(nbss(rq1) + nbss(rq2))
cj.s2c(nbss(sj.rsp(ECHO, m1, echo_rep(), send=False)) + nbss(sj.rsp(ECHO, m2, echo_rep(), send=False))[:10])
cj.s2c(nbss(sj.rsp(ECHO, m2, echo_rep(), send=False))[10:])
cls(sj, FID)

mark('I: SMB2 over NetBIOS (TCP 139) after a session request')
ck = Conn(main, 10, 11, 49290, 139)


def nbss_type(t, payload):
    return bytes([t]) + struct.pack('>I', len(payload))[1:] + payload


def nb_name(n):
    out = b'\x20'
    for ch in n.ljust(15).upper().encode() + b'\x20':
        out += bytes([0x41 + (ch >> 4), 0x41 + (ch & 15)])
    return out + b'\0'


ck.c2s(nbss_type(0x81, nb_name('SERVER') + nb_name('CLIENT')))
ck.s2c(nbss_type(0x82, b''))
sk = Sess(ck)
negotiate(sk, (0x0202, 0x0210), [], 0x0210, [])
ck.c2s(nbss_type(0x85, b''))
logon(sk)
tree_x(sk, SHARE, TID)
sk.tid = TID
sk.x(ECHO, echo_req(), echo_rep())

# ================ more branches: share root, duplicates, contexts, errors ================
mark('J: operations on the share root (empty file name)')
cl = Conn(main, 10, 11, 49300)
sl = Sess(cl, ses=0x5000000000000000 | 49300)
negotiate(sl, (0x0300, 0x0302, 0x0311), [ctx_preauth()], 0x0311, [ctx_preauth()])
logon(sl, ses=sl.ses)
tree_x(sl, SHARE, TID, flags=7)
sl.tid = TID
RFID = bytes.fromhex('a1a2a3a4a5a6a7a8') + bytes.fromhex('b1b2b3b4b5b6b7b8')
sl.x(CREATE, create_req('', access=0x100081, attrs=0, opts=1, disp=1), create_rep(RFID, attrs=0x10))
gi(sl, 1, 5, fi_standard(), fid=RFID)
sl.x(FIND, find_req(0x25, 1, 0, RFID, '*'), find_rep(dirents(0x25, ['a.txt'])))
sl.x(READ, read_req(RFID, 10), error_rep(), status=0xc00000ba)
sl.x(WRITE, write_req(b'x', fid=RFID), error_rep(), status=0xc00000ba)
sl.x(FLUSH, flush_req(RFID), flush_rep())
sl.x(LOCK, lock_req([(0, 1, 2)], fid=RFID), error_rep(), status=0xc00000ba)
si_(sl, 1, 13, b'\x01', fid=RFID)
sl.x(IOCTL, ioctl_req(0x000900A8, b'', fid=RFID), ioctl_rep(0x000900A8, fsctl_reparse(0xa000000c, reparse_symlink()), b'', fid=RFID))
sl.x(NOTIFY, notify_req(RFID), notify_rep(notify_data([(1, 'x')])))
sl.x(CLOSE, close_req(RFID, 1), close_rep(1))

mark('J: duplicated create request (retransmission), delete on close, close of a deleted file')
for nm, opts, attrs, fid in (('del.txt', 0x1040, 0x80, bytes.fromhex('c1c2c3c4c5c6c7c8') + bytes.fromhex('d1d2d3d4d5d6d7d8')),
                             ('deldir', 0x1001, 0x10, bytes.fromhex('e1e2e3e4e5e6e7e8') + bytes.fromhex('f1f2f3f4f5f6f7f8'))):
    m, rq = sl.req(CREATE, create_req(nm, opts=opts, attrs=attrs, access=0x110080, share=7))
    sl.rsp(CREATE, m, create_rep(fid, attrs=attrs if attrs != 0x80 else 0x20))
    sl.c.rep('c', rq)               # the request is sent again (same message id) after the response
    sl.rsp(CREATE, m, create_rep(fid))
    sl.x(CLOSE, close_req(fid, 1), close_rep(1))
mark('J: duplicated request before the response')
m, rq = sl.req(ECHO, echo_req())
sl.c.rep('c', rq)
sl.rsp(ECHO, m, echo_rep())

mark('J: create contexts: durable handle reconnect, v2 reconnect, replies, empty data, AAPL variants')
cx = create_ctxs([(b'DHnC', FID), (b'MxAc', b''), (b'QFid', b'\x01\x02\x03\x04')])
cy = create_ctxs([(b'DH2C', FID + CG + struct.pack('<I', 2)), (b'RqLs', LK + struct.pack('<IIQ', 3, 0, 0))])
cz = create_ctxs([(b'AAPL', struct.pack('<IIQ', 2, 0, 0x1234)), (b'DHnQ', b'\0' * 16)])
cz2 = create_ctxs([(b'AAPL', struct.pack('<IIQQ', 1, 0, 7, 0x7))])
for nm, c in (('r1', cx), ('r2', cy), ('r3', cz), ('r4', cz2)):
    sl.x(CREATE, create_req(nm, ctxs=c), create_rep(FID2, ctxs=b''))
    sl.x(CLOSE, close_req(FID2), close_rep())
rp1 = create_ctxs([(b'MxAc', b''), (b'DHnQ', b'\0' * 8)])
mdl = u16s('MacModel')
pth = u16s('/share/path')
rp2 = create_ctxs([(b'AAPL', struct.pack('<IIII', 2, 0, 0, len(pth)) + pth),
                   (b'AAPL', struct.pack('<IIQ', 7, 0, 0))])
rp3 = create_ctxs([(b'AAPL', struct.pack('<IIQQQ', 1, 0, 7, 0x7, 0x7) + struct.pack('<II', 0, len(mdl)) + mdl),
                   (b'AAPL', struct.pack('<IIQ', 1, 0, 0x0)),
                   (b'AAPL', struct.pack('<IIQQ', 1, 0, 0x2, 0x7)),
                   (b'AAPL', struct.pack('<IIQQ', 1, 0, 0x1, 0x1))])
for nm, c in (('s1', rp1), ('s2', rp2), ('s3', rp3)):
    sl.x(CREATE, create_req(nm), create_rep(FID2, ctxs=c))
    sl.x(CLOSE, close_req(FID2), close_rep())

mark('J: security info class with an unknown level, getinfo on an unopened file, responses without requests')
sl.x(CREATE, create_req('sec.txt'), create_rep(FID))
gi(sl, 3, 1, b'\x01\x02\x03\x04')
si_(sl, 3, 1, b'\x01\x02\x03\x04')
si_(sl, 2, 99, b'\x01\x02\x03\x04')
si_(sl, 1, 99, b'\x01\x02\x03\x04')
cls(sl, FID)
cm = Conn(main, 13, 11, 49310)
sm = Sess(cm, ses=0x5000000000000000 | 49310)
sm.mid = 40
sm.rsp(GETINFO, 41, getinfo_rep(fi_basic()))
sm.rsp(CREATE, 42, create_rep(FID, ctxs=b''))
sm.rsp(READ, 43, read_rep(b'late'))
sm.rsp(CLOSE, 44, close_rep(1))
sm.rsp(IOCTL, 45, ioctl_rep(0x000940CF, rng(0, 4096)))
sm.rsp(NOTIFY, 46, error_rep(), status=STATUS_CANCELLED, aid=0x55)
sm.rsp(NOTIFY, 47, notify_rep(notify_data([(1, 'zz')])))
sm.rsp(WRITE, 48, write_rep(3))
sm.rsp(FIND, 49, find_rep(dirents(0x25, ['q'])))
# a cancel by AsyncId before the interim response, while no async table exists
sm.req(NOTIFY, notify_req(FID), mid=51)
sm.req(CANCEL, cancel_req(), mid=0, aid=0x57)
sm.rsp(NOTIFY, 51, error_rep(), status=STATUS_PENDING, aid=0x57)
sm.rsp(NOTIFY, 51, error_rep(), status=STATUS_CANCELLED, aid=0x57)
# an interim response and the cancelled response, the cancel itself is not in the capture
sm.req(NOTIFY, notify_req(FID), mid=53)
sm.rsp(NOTIFY, 53, error_rep(), status=STATUS_PENDING, aid=0x59)
sm.rsp(NOTIFY, 53, error_rep(), status=STATUS_CANCELLED, aid=0x59)
# the usual order: request, interim response, cancel by AsyncId, cancelled
sm.req(NOTIFY, notify_req(FID), mid=50)
sm.rsp(NOTIFY, 50, error_rep(), status=STATUS_PENDING, aid=0x56)
sm.req(CANCEL, cancel_req(), mid=0, aid=0x56)
sm.rsp(NOTIFY, 50, error_rep(), status=STATUS_CANCELLED, aid=0x56)
# cancel carrying both the message id and an AsyncId, after the interim response
sm.req(NOTIFY, notify_req(FID), mid=52)
sm.rsp(NOTIFY, 52, error_rep(), status=STATUS_PENDING, aid=0x58)
sm.req(CANCEL, cancel_req(), mid=52, aid=0x58)
sm.rsp(NOTIFY, 52, error_rep(), status=STATUS_CANCELLED, aid=0x58)

mark('J: error responses with the full structure, negotiate error, share flags')
sl.x(TREE_CONNECT, tcon_req('\\\\x\\y'), tcon_rep(1, 0, 0, 0x1f01ff), status=STATUS_ACCESS_DENIED, tid=0)
sl.x(CREATE, create_req('es'), create_rep(FID, ctxs=b''), status=STATUS_SHARING_VIOLATION)
sl.x(READ, read_req(FID, 1), read_rep(b'1'), status=0xc0000011)
sl.x(NEGOTIATE, neg_req((0x0302, 0x0311), [ctx_preauth()]), error_rep(), status=0xc00000bb, tid=0, ses=0)
sl.x(ECHO, echo_req(), error_rep(), status=STATUS_USER_SESSION_DELETED)
for sfl in (0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x30000, 0x30, 0x0300):
    pass
tree_x(sl, '\\\\server\\a', 21, stype=3, sflags=0x1 | 0x4 | 0x8000, caps=0x1 | 0x2)
tree_x(sl, '\\\\server\\b', 22, stype=1, sflags=0x2 | 0x10 | 0x20 | 0x100 | 0x400, caps=0x4 | 0x8 | 0x10 | 0x20)
tree_x(sl, '\\\\server\\c', 23, stype=1, sflags=0x1000 | 0x2000 | 0x4000 | 0x800, caps=0x40)
sl.x(TREE_DISCONNECT, tdis_req(), tdis_rep(), tid=21)
sl.x(TREE_DISCONNECT, tdis_req(), tdis_rep(), tid=22)
sl.x(TREE_DISCONNECT, tdis_req(), tdis_rep(), tid=23)

mark('J: ioctls with data in the direction the function does not use')
for code, junk_in, junk_out in [(0x00090300, b'\0' * 8, None), (0x001401FC, b'\0' * 8, None), (0x00144064, b'\0' * 8, None),
                                (0x000900c0, b'\0' * 8, None), (0x0009003C, b'\0' * 8, None), (0x00090350, None, None),
                                (0x000900c4, None, b'\0' * 8), (0x001401D4, None, b'\0' * 8), (0x0009C040, None, b'\0' * 8),
                                (0x0009C280, None, b'\0' * 8), (0x00090380, None, b'\0' * 8), (0x00090440, None, b'\0' * 8),
                                (0x00098098, None, b'\0' * 8), (0x000980BC, None, b'\0' * 8), (0x000980C8, None, b'\0' * 8),
                                (0x00098344, None, b'\0' * 8), (0x000900A4, None, b'\0' * 8), (0x000900A8, b'\0' * 8, None),
                                (0x00140078, b'\0' * 8, None), (0x00090284, None, None)]:
    if junk_in is not None:
        sl.x(IOCTL, ioctl_req(code, junk_in, fid=WILD), ioctl_rep(code, b'', b'', fid=WILD))
    if junk_out is not None:
        sl.x(IOCTL, ioctl_req(code, b'', outdata=junk_out, fid=WILD), ioctl_rep(code, junk_out, b'', fid=WILD))

mark('J: compression budget (16 MiB per frame): the second payload is refused')
pb2 = chained(0, [chain_payload(4, pattern_v1(0x41, 1 << 24), flags=1), chain_payload(0, b'abcdefgh')])
pb3 = chained(0, [chain_payload(4, pattern_v1(0x41, 8 << 20), flags=1), chain_payload(2, lz77(b'xyz'), orig=9 << 20)])
cc.rep('s', comp_hdr(0xffffff, 2, plain[:80], lz77(b'x' * 10)))
cc.c2s(nbss(pb2) + nbss(pb3))

mark('K: more branches: break error, AAPL unknown command, invalid timewarp token, share junk')
sl.x(BREAK, break_oplock(FID, 1), error_rep(), status=STATUS_FILE_CLOSED)
sl.x(CREATE, create_req('tw', ctxs=create_ctxs([(b'AAPL', struct.pack('<IIQ', 9, 0, 0)), (b'TWrp', b'\xff' * 8)])), create_rep(FID2))
sl.x(CLOSE, close_req(FID2), close_rep())
sl.x(IOCTL, ioctl_req(0x000601B0, b'', outdata=b'\0' * 8, fid=WILD), ioctl_rep(0x000601B0, b'\0' * 8, b'', fid=WILD))
sl.x(IOCTL, ioctl_req(0x00090064, b'\0' * 8, fid=WILD), ioctl_rep(0x00090064, fsctl_ntfs_volume_data(), b'', fid=WILD))
mark('K: a connection with a single pending request that is cancelled (the async table goes away)')
co = Conn(main, 10, 11, 49320)
so = Sess(co, ses=0x5000000000000000 | 49320)
negotiate(so, (0x0302, 0x0311), [ctx_preauth()], 0x0311, [ctx_preauth()])
so.req(NOTIFY, notify_req(FID), mid=so.next_mid())
so.rsp(NOTIFY, 1, error_rep(), status=STATUS_PENDING, aid=0x60)
so.rsp(NOTIFY, 1, error_rep(), status=STATUS_CANCELLED, aid=0x60)
mark('K: NBSS session messages that are not SMB2')
co.c2s(nbss(b'\x01\x02'))
co.c2s(nbss(b'XSMB' + b'\0' * 40))
co.s2c(nbss(b''))
co.c2s(nbss(b'\xfeSM'))

mark('K: create context chain whose first element is longer than 64 KiB (NextEntryOffset above 0xffff, the fix)')
big_ctx = create_ctx(b'Zzzz', b'\0' * 0x10000)
ctx_big = struct.pack('<I', len(big_ctx)) + big_ctx[4:] + create_ctx(b'MxAc', ft(3))
sl.x(CREATE, create_req('bigctx', ctxs=ctx_big), create_rep(FID2, ctxs=create_ctxs([(b'MxAc', struct.pack('>I', 0) + struct.pack('<I', 0x1f01ff))])))
sl.x(CLOSE, close_req(FID2), close_rep())

write_pcap(os.path.join(OUT, 'smb2-coverage.pcap'), main)
if VERBOSE:
    print(len(main), 'frames')
    for n, f in marks:
        print(n, f)

# =====================================================================================
# the malformed capture: damaged messages and paths only invalid data reaches
mal = []
mmarks = []


def mmark(name):
    mmarks.append((len(mal) + 1, name))


import random as _random

mmark('M: transform headers whose OriginalMessageSize is larger than the data')
me = Conn(mal, 10, 11, 50000)
for size in (0xFFFFFFE0, 0x80000000, 0x7FFFFFFF, 0x1000, 100):
    th = b'\xfdSMB' + b'\x11' * 16 + b'\xfdSMB' + b'\x22' * 12 + struct.pack('<IHHQ', size, 0, 1, 0x1234)
    me.rep('c', th + b'\x33' * 64)

mmark('M: negotiate with the contexts of a dialect that has none, reserved fields set, bad context offsets')
mc_ = Conn(mal, 10, 11, 50001)
ms = Sess(mc_)
ms.x(NEGOTIATE, neg_req((0x0202, 0x0300), [], ncc_override=3, nco_override=0x100), neg_rep(0x0300, [], status_ctx_override=2, nco_override=0x90), tid=0, ses=0)
ms.x(NEGOTIATE, neg_req((0x0311,), [ctx_preauth()], nco_override=0x20), neg_rep(0x0311, [ctx_preauth()], nco_override=0x20), tid=0, ses=0)
mm = Conn(mal, 10, 11, 50002)
mn = Sess(mm)
mn.x(NEGOTIATE, neg_req((0x0302,), [ctx_preauth()]), neg_rep(0x0302, [], status_ctx_override=1, nco_override=0x80), tid=0, ses=0)
mn.x(CREATE, create_req('x'), error_rep(ctxs=err_ctx(0x77, b'\0' * 4), count=2), status=STATUS_BAD_NETWORK_NAME)
mn.x(CREATE, create_req('x'), struct.pack('<HBBI', 9, 3, 0, 0) + b'\0', status=STATUS_BAD_NETWORK_NAME)
mn.x(CREATE, create_req('x'), struct.pack('<HBBI', 9, 1, 0, 0) + b'\0', status=STATUS_ACCESS_DENIED)

mmark('M: getinfo input buffer problems, create contexts in the wrong direction, contexts with bad lengths')
mg = Conn(mal, 10, 11, 50003)
mgs = Sess(mg, ses=0x77)
mgs.x(NEGOTIATE, neg_req((0x0311,), [ctx_preauth()]), neg_rep(0x0311, [ctx_preauth()]), tid=0, ses=0)
mgs.x(CREATE, create_req('f'), create_rep(FID))
for off, ln in ((0x20, 8), (64 + 40, 0xfffff0), (0, 0)):
    q = struct.pack('<HBBIHHIII16s', 41, 4, 0, 4096, off, 0, ln, 0, 0, FID) + b'\0' * 16
    mgs.x(GETINFO, q, getinfo_rep(quota_entries(1)))
q = struct.pack('<HBBIHHIII16s', 41, 4, 0, 4096, 0, 0, 0, 0, 0, FID) + b'\0'
mgs.x(GETINFO, q, getinfo_rep(quota_entries(1)))
bad_rq = create_ctxs([(b'ExtA', fi_ea([(b'a', b'b', 0)])), (b'SecD', sec_desc()), (b'AlSi', struct.pack('<Q', 1)), (b'TWrp', ft(1)),
                      (b'DHnC', FID), (b'DH2C', FID + CG + struct.pack('<I', 0)), (b'RqLs', LK + b'\0' * 10),
                      (uuid.UUID('6aa6bc45-a7ef-4af7-9008-fa462e144d74').bytes_le, struct.pack('<HH', 20, 0) + b'\xaa' * 16),
                      (uuid.UUID('b7d082b9-563b-4f07-a07b-524a8116a010').bytes_le, struct.pack('<HHIQQ', 24, 0, 0, 1, 2)),
                      (b'QFid', b'\x01' * 32)])
mgs.x(CREATE, create_req('g'), create_rep(FID2, ctxs=bad_rq))
mgs.x(CREATE, create_req('g', ctxs=create_ctxs([(b'RqLs', LK + b'\0' * 10)])), create_rep(FID2))
mgs.x(IOCTL, ioctl_req(0x000940CF, rng(0, 1)), struct.pack('<HHI16sIIIIII', 49, 0, 0x000940CF, FID, 0x7fff, 100, 0x7fff, 100, 0, 0) + b'\0' * 8)
mgs.x(READ, read_req(FID, 10), struct.pack('<HBBIII', 17, 0x7f, 0, 100, 0, 0) + b'\0' * 4)
mgs.x(GETINFO, getinfo_req(1, 4), struct.pack('<HHI', 9, 0x7f, 100) + b'\0' * 4)
mgs.x(FIND, find_req(0x25, 1, 0, FID), struct.pack('<HHI', 9, 0x7f, 100) + b'\0' * 4)
mgs.x(CREATE, struct.pack('<HBBIQQIIIIIHHII', 57, 0, 0xff, 2, 0, 0, 0x12019f, 0x80, 7, 1, 0x40, 0x7fff, 40, 0, 0) + b'\0' * 8, create_rep(FID2))
mgs.x(WRITE, write_req(b'x' * 8, channel=1, wci=struct.pack('<QII', 1, 2, 3)), write_rep(8))
m_, rq_ = mgs.req(WRITE, write_req(b'x' * 8), send=False)
mg.rep('c', rq_[:112] + b'')
mmark('M: directory entries and notifications with offsets that go backwards')
for c in (1, 2, 3, 12, 0x25, 0x26, 0x64):
    e = dirent(c, 'aaa', 0)
    e2 = struct.pack('<I', 0xfffffff0) + e[4:]
    mgs.x(FIND, find_req(c, 1, 0, FID), find_rep(e2 + e))
    e3 = struct.pack('<I', 0x7ffffff0) + e[4:]
    mgs.x(FIND, find_req(c, 1, 0, FID), find_rep(e3 + e))
mgs.x(NOTIFY, notify_req(FID), notify_rep(struct.pack('<III', 0xfffffff0, 1, 2) + u16s('a') + b'\0' * 40))
mgs.x(IOCTL, ioctl_req(0x001401FC), ioctl_rep(0x001401FC, struct.pack('<I', 0xfffffff0) + b'\0' * 140))
mgs.x(GETINFO, getinfo_req(1, 15), getinfo_rep(struct.pack('<IBBH', 0xfffffff0, 0, 3, 2) + b'abc\0xx' + b'\0' * 20))
mgs.x(GETINFO, getinfo_req(1, 22), getinfo_rep(struct.pack('<IIQQ', 0xfffffff0, 4, 1, 1) + b'\0' * 8 + b'\0' * 40))

mgs.x(CREATE, create_req('x'), struct.pack('<HBBI', 9, 3, 0, 0) + b'\0', status=STATUS_BAD_NETWORK_NAME)
mgs.x(CREATE, create_req('x'), struct.pack('<HBBI', 9, 1, 0, 0) + b'\0', status=STATUS_ACCESS_DENIED)
mmark('M: share redirect error with addresses of an unknown family (the loop over the addresses stops at the count)')
cr = Conn(mal, 10, 11, 50100)
sr = Sess(cr)
negotiate(sr, (0x0311,), [ctx_preauth()], 0x0311, [ctx_preauth()])
nm_ = u16s('srv')
ips_ = b''.join(struct.pack('<HH4s', 0, 445, b'\xc0\0\x02\x63') + b'\0' * 4 for _ in range(5))
ctxd = struct.pack('<IIIIHHI', 24, 3, 0, len(nm_), 0, 1, 5) + ips_ + nm_
m_, _ = sr.req(CREATE, create_req('x'))
sr.rsp(CREATE, m_, error_rep(ctxs=pad(struct.pack('<II', len(ctxd), 0x72645253) + ctxd), count=1), status=STATUS_BAD_NETWORK_NAME)

# bug 1: a huge address count over addresses that do not fit the 8 or 26 octets the dissector steps over:
# the offset moves back and forth and the loop runs for 2^32 iterations (a hang without a protocol tree,
# an abort after 50000 items with one).  Not part of the malformed capture used by runcov.sh.
hang = []
for i, (cnt, fam, n) in enumerate([(0xffffffff, 2, 3), (0xffffffff, 23, 2), (0xffffffff, 0, 2), (0x7fffffff, 3, 300)]):
    cr = Conn(hang, 10, 11, 50100 + i)
    sr = Sess(cr)
    negotiate(sr, (0x0311,), [ctx_preauth()], 0x0311, [ctx_preauth()])
    ips_ = b''.join(struct.pack('<HH4s', fam, 445, b'\xc0\0\x02\x63') + b'\0' * 4 for _ in range(n))
    ctxd = struct.pack('<IIIIHHI', 24, 3, 0, len(nm_), 0, 1, cnt) + ips_ + nm_
    m_, _ = sr.req(CREATE, create_req('x'))
    sr.rsp(CREATE, m_, error_rep(ctxs=pad(struct.pack('<II', len(ctxd), 0x72645253) + ctxd), count=1), status=STATUS_BAD_NETWORK_NAME)
write_pcap(os.path.join(OUT, 'smb2-redirect-hang.pcap'), hang)

mmark('M: long chains: create contexts, network interfaces, directory entries (dissection depth)')
chain = b''
for i in range(700):
    c = create_ctx(b'ExtA', b'')
    chain += struct.pack('<I', len(c)) + c[4:]
mgs.x(CREATE, create_req('chain', ctxs=chain), create_rep(FID2))
nif = b''
for i in range(700):
    rec = struct.pack('<IIIIQ', 0x98, i + 1, 1, 0, 1000000000) + struct.pack('<HH4s', 2, 0, bytes([192, 0, 2, 1])) + b'\0' * 120
    nif += rec
mgs.x(IOCTL, ioctl_req(0x001401FC), ioctl_rep(0x001401FC, nif))
ents = b''
for i in range(3000):
    e = struct.pack('<III', 16, 7, 0) + b'\0' * 4
    ents += e
mgs.x(FIND, find_req(12, 1, 0, FID), find_rep(ents))

mmark('M: compression: nested compression, bad decompressed header, chained payload longer than the data, huge sizes')
mcm = Conn(mal, 10, 11, 50004)
msm = Sess(mcm, ses=0x78)
inner = comp_hdr(10, 2, b'', lz77(b'x' * 10))
mcm.rep('s', comp_hdr(len(inner), 2, b'', lz77(inner)))
mcm.rep('s', comp_hdr(30, 2, b'', lz77(b'ZZZZ' * 5 + b'0123456789')))
mcm.rep('s', comp_hdr(60, 2, b'', lz77(b'\xfeSMB' + b'\0' * 59)))
mcm.rep('s', chained(100, [struct.pack('<HHI', 0, 1, 0x1000000 + 5) + b'abc']))
mcm.rep('s', chained(100, [struct.pack('<HHII', 2, 1, 0x1000000 + 5, 10) + b'abc']))
mcm.rep('s', chained(100, [struct.pack('<HHI', 4, 0, 8) + pattern_v1(0x44, 0xffffffff)]))
mcm.rep('s', chained(100, [struct.pack('<HHI', 4, 1, 8) + pattern_v1(0x44, 1 << 24), struct.pack('<HHI', 4, 0, 8) + pattern_v1(0x44, 1)]))
mcm.rep('s', b'\xfcSMB' + struct.pack('<IHHI', 100, 2, 0, 0xffffffff) + b'\0' * 20)
mcm.rep('s', b'\xfcSMB' + struct.pack('<IHHI', 100, 2, 0, 200) + b'\0' * 20)
mcm.rep('s', b'\xfcSMB' + struct.pack('<IHHI', 100, 9, 0, 0))
mcm.rep('s', b'\xfcSMB' + struct.pack('<I', 100) + struct.pack('<HHI', 2, 1, 10))
mcm.rep('s', b'\xfdSMB' + b'\0' * 20)
mcm.rep('s', b'\xfeSMB' + b'\0' * 20)
mcm.rep('s', b'\xfeSMB' + struct.pack('<HHIHHIIQIIQ16s', 64, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, b'\0' * 16)[:10])

mmark('M: every command and direction cut short at several lengths, and with single field values changed')
rng_ = _random.Random(34)
mt = Conn(mal, 10, 11, 50005)
mts = Sess(mt, ses=0x79)
mts.x(NEGOTIATE, neg_req((0x0311,), [ctx_preauth()]), neg_rep(0x0311, [ctx_preauth()]), tid=0, ses=0)
bodies = {
    SESSION_SETUP: (ses_req(), ses_rep(0, spnego_init())), TREE_CONNECT: (tcon_req(), tcon_rep()),
    CREATE: (create_req('abc', ctxs=create_ctxs([(b'MxAc', ft(1)), (b'RqLs', LK + struct.pack('<IIQ', 3, 0, 0))])), create_rep(FID, ctxs=ctx_rp_all)),
    CLOSE: (close_req(), close_rep(1)), FLUSH: (flush_req(), flush_rep()), READ: (read_req(), read_rep(b'x' * 20)),
    WRITE: (write_req(b'y' * 20), write_rep(20)), LOCK: (lock_req([(0, 1, 2), (3, 4, 5)]), lock_rep()),
    IOCTL: (ioctl_req(0x00094264, fsctl_offload_read_in(), outdata=b'12345678'), ioctl_rep(0x00094264, fsctl_offload_read_out(), b'')),
    FIND: (find_req(0x25), find_rep(dirents(0x25, ['a', 'b']))), NOTIFY: (notify_req(), notify_rep(notify_data([(1, 'a'), (2, 'bb')]))),
    GETINFO: (getinfo_req(1, 18), getinfo_rep(fi_all())), SETINFO: (setinfo_req(1, 10, fi_rename()), setinfo_rep()),
    BREAK: (break_lease_ack(), break_lease_notify()), ECHO: (echo_req(), echo_rep()), CANCEL: (cancel_req(), cancel_req()),
    LOGOFF: (logoff_req(), logoff_rep()), TREE_DISCONNECT: (tdis_req(), tdis_rep()), SRV_NOTIFY: (srv_notify(), srv_notify()),
}
extra_bodies = [(GETINFO, getinfo_req(1, c), getinfo_rep(d)) for c, d in
                ((4, fi_basic()), (5, fi_standard()), (22, fi_stream([('::$DATA', 1, 2), (':x:$DATA', 3, 4)])), (15, fi_ea([(b'a', b'b', 0), (b'cc', b'dd', 0x80)])),
                 (100, fi_posix()), (24, fi_pipe_local()), (28, fi_compression()), (34, fi_network_open()))]
extra_bodies += [(GETINFO, getinfo_req(2, c), getinfo_rep(d)) for c, d in
                 ((1, FS_VOLUME), (5, FS_ATTR), (6, FS_CONTROL), (7, FS_FULLSIZE), (100, FS_POSIX))]
extra_bodies += [(GETINFO, getinfo_req(3, 0), getinfo_rep(sec_desc(sacl=True))),
                 (GETINFO, getinfo_req(4, 0, inbuf=quota_query(sids=[sid((21, 1, 2, 1000))])), getinfo_rep(quota_entries(2)))]
extra_bodies += [(IOCTL, ioctl_req(c, i), ioctl_rep(c, o)) for c, i, o in
                 ((0x001401FC, b'', fsctl_netif([4, 6])), (0x00140204, fsctl_validate_neg_in(), fsctl_validate_neg_out()),
                  (0x00144064, b'', fsctl_snapshots(2)), (0x00090350, fsctl_sqos(True), fsctl_sqos(False)),
                  (0x00090284, fsctl_file_regions_in(), fsctl_file_regions_out()), (0x001440F2, fsctl_copychunk_in(), fsctl_copychunk_out()),
                  (0x000900A8, b'', fsctl_reparse(0xa000000c, reparse_symlink())), (0x000900A8, b'', fsctl_reparse(0xa0000003, reparse_mount())),
                  (0x000601B0, fsctl_dfs_ex(site='s'), b'\0' * 8), (0x00110018, fsctl_pipe_wait(), b''),
                  (0x00090440, fsctl_refs_snapshot(3), b''), (0x00098268, fsctl_offload_write_in(), fsctl_offload_write_out()))]
extra_bodies += [(CREATE, create_req('abc', ctxs=ctx_rq_all), create_rep(FID, ctxs=ctx_rp_all))]
all_bodies = [(c, rq, rp) for c, (rq, rp) in bodies.items()] + extra_bodies
for cmd, rq, rp in all_bodies:
    for body, resp in ((rq, False), (rp, True)):
        full = (hdr(cmd, 1, F_RESP if resp else 0, 0x79, TID, 0) + body)
        cuts = {len(full) - 1, 65, 66, 68, 72, 80, len(full) // 2, len(full) - 8, len(full) - 20}
        for cut in sorted(cuts):
            if 4 < cut < len(full):
                mt.rep('s' if resp else 'c', full[:cut])
        for _ in range(3):
            b = bytearray(full)
            for _ in range(rng_.randrange(1, 4)):
                p = rng_.randrange(64, len(b)) if len(b) > 64 else 0
                b[p:p + 4] = struct.pack('<I', rng_.choice([0, 0xffffffff, 0x7fffffff, 0x80000000, 0x10000, rng_.getrandbits(32), 0xfffffff0]))[:len(b[p:p + 4])]
            mt.rep('s' if resp else 'c', bytes(b))

mmark('M: the main conversations again with damaged messages (a few per conversation)')
seen = {}
for seed in (1, 2, 3):
    rr = _random.Random(100 + seed)
    conns = {}
    for cp, sp, c_, s_, side, smb in LOG:
        key = (cp, sp)
        if key not in conns:
            conns[key] = Conn(mal, c_, s_, cp + 2000 * seed, sp)
        cn = conns[key]
        pdu = bytearray(smb)
        if rr.random() < 0.10 and len(pdu) > 8:
            op = rr.choice(('cut', 'flip', 'field', 'zero'))
            if op == 'cut':
                pdu = pdu[:rr.randrange(5, len(pdu))]
            elif op == 'flip':
                for _ in range(rr.randrange(1, 5)):
                    pdu[rr.randrange(4, len(pdu))] ^= 1 << rr.randrange(8)
            elif op == 'field':
                p = rr.randrange(4, max(5, len(pdu) - 4))
                pdu[p:p + 4] = struct.pack('<I', rr.choice([0xffffffff, 0x7fffffff, 0x10000, 0xfffffff0, 0x100]))[:len(pdu[p:p + 4])]
            else:
                p = rr.randrange(4, len(pdu))
                pdu[p:p + 8] = b'\0' * len(pdu[p:p + 8])
        cn.rep(side, bytes(pdu))

write_pcap(os.path.join(OUT, 'smb2-coverage-malformed.pcap'), mal)
if VERBOSE:
    print(len(mal), 'malformed frames')
    for n, f in mmarks:
        print(n, f)
