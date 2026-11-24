#!/usr/bin/env python3
# Generates test/captures/smb_common_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the synthetic SMB1 coverage captures for packet-smb.c.
# Usage: mksmb.py <outdir>   (writes smb-coverage.pcap and
# smb-coverage-malformed.pcap).  Everything is built with struct; the
# addresses are documentation addresses, nothing comes from a network.
# No keys, passwords or ciphertext are produced: password fields are empty.
import struct
import sys
import os

MAC_C = bytes.fromhex('020000000011')
MAC_S = bytes.fromhex('020000000012')
IP_C = bytes([198, 51, 100, 1])
IP_S = bytes([198, 51, 100, 2])
U16 = lambda *a: struct.pack('<%dH' % len(a), *a)
U32 = lambda *a: struct.pack('<%dI' % len(a), *a)
U64 = lambda *a: struct.pack('<%dQ' % len(a), *a)
U8 = lambda *a: bytes(a)
NT = 0x01d0000000000000      # an NT time, fixed

SCENARIOS = []


def scenario(f):
    SCENARIOS.append(f)
    return f
CAPS = {}


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Cap:
    def __init__(self, name):
        self.name = name
        self.f = open(name, 'wb')
        self.f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        self.t = 1700000000
        self.n = 0
        self.record = None

    def raw(self, frame):
        self.n += 1
        self.t += 1
        self.f.write(struct.pack('<IIII', self.t, 0, len(frame), len(frame)))
        self.f.write(frame)

    def close(self):
        self.f.close()


class Conn:
    """A TCP connection client:cport <-> server:sport with NBSS framing."""

    def __init__(self, cap, cport, sport=445, uni=False, ipc=False):
        self.cap, self.cport, self.sport = cap, cport, sport
        self.seq = {True: 1000, False: 70000}
        self.mid = 0
        self.uni = uni
        self.uid = 0x0800
        self.pid = 0x1234
        self.tid = 1
        self.flags2 = 0xc001 if uni else 0x4001
        self.ipid = 1
        self.tcp(True, b'', 0x02)
        self.tcp(False, b'', 0x12)
        self.tcp(True, b'', 0x10)

    def tcp(self, to_server, payload, flags=0x18):
        if to_server:
            src, dst, sp, dp, ms, md = IP_C, IP_S, self.cport, self.sport, MAC_C, MAC_S
        else:
            src, dst, sp, dp, ms, md = IP_S, IP_C, self.sport, self.cport, MAC_S, MAC_C
        seq = self.seq[to_server]
        ack = self.seq[not to_server]
        self.seq[to_server] += len(payload) + (1 if flags & 3 else 0)
        # an ACK bit-only packet must not carry data; flags 0x18 = PSH|ACK
        opts = b'\x02\x04\x05\xb4' if flags & 2 else b''
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack if flags & 0x10 else 0,
                          (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        self.ipid += 1
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         self.ipid, 0x4000, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.cap.raw(md + ms + b'\x08\x00' + ip + tcp + payload)

    # --- SMB construction -------------------------------------------------
    def hdr(self, cmd, reply, mid=None, tid=None, pid=None, uid=None,
            flags2=None, status=0, flags=None, ecls=None):
        if flags is None:
            flags = 0x18 | (0x80 if reply else 0)
        f2 = self.flags2 if flags2 is None else flags2
        if f2 & 0x4000:
            st = struct.pack('<I', status)
        else:
            st = struct.pack('<BBH', ecls or 0, 0, status & 0xffff)
        return (b'\xffSMB' + bytes([cmd]) + st + bytes([flags]) + struct.pack('<H', f2) +
                struct.pack('<H', 0) + b'\0' * 8 + struct.pack('<H', 0) +
                struct.pack('<HHHH', self.tid if tid is None else tid,
                            self.pid if pid is None else pid,
                            self.uid if uid is None else uid,
                            self.mid if mid is None else mid))

    def smb(self, cmd, reply, words=b'', data=b'', wc=None, bc=None, **kw):
        """data may be bytes, or a list of bytes/str: str items are encoded
        as ASCII or UTF-16LE (aligned to the SMB start) with a terminator."""
        h = self.hdr(cmd, reply, **kw)
        if wc is None:
            assert len(words) % 2 == 0, (cmd, len(words))
            wc = len(words) // 2
        uni = (kw.get('flags2') or self.flags2) & 0x8000
        base = 32 + 1 + len(words) + 2
        if isinstance(data, (list, tuple)):
            out = b''
            for it in data:
                if isinstance(it, str):
                    if uni:
                        if (base + len(out)) % 2:
                            out += b'\0'
                        out += it.encode('utf-16le') + b'\0\0'
                    else:
                        out += it.encode('latin-1') + b'\0'
                else:
                    out += it
            data = out
        return h + bytes([wc]) + words + struct.pack('<H', len(data) if bc is None else bc) + data

    def send(self, to_server, *pdus):
        """One TCP segment with all PDUs NBSS framed."""
        out = b''
        for p in pdus:
            if self.cap.record is not None:
                self.cap.record.append((to_server, p))
            out += struct.pack('!BBH', 0, (len(p) >> 16) & 1, len(p) & 0xffff) + p
        self.tcp(to_server, out)

    def nextmid(self):
        self.mid += 1
        return self.mid

    def rr(self, cmd, rwords=b'', rdata=b'', qwords=b'', qdata=b'', status=0,
           qkw=None, rkw=None, **kw):
        """Request + response pair with a fresh MID, two TCP segments."""
        self.nextmid()
        a = dict(kw); a.update(qkw or {})
        b = dict(kw); b.update(rkw or {})
        self.send(True, self.smb(cmd, False, qwords, qdata, **a))
        self.send(False, self.smb(cmd, True, rwords, rdata, status=status, **b))


B4 = b'\x04'
def p4(s):    # buffer format 4 + string, marker handled by smb() as str
    return [B4, s]


def session_setup_nt(c, extsec=False):
    """Negotiate + Session Setup + Tree Connect AndX with empty passwords."""
    c.nextmid()
    c.send(True, c.smb(0x72, False, b'', [b'\x02PC NETWORK PROGRAM 1.0\0', b'\x02LANMAN1.0\0',
                                         b'\x02LM1.2X002\0', b'\x02NT LM 0.12\0', b'\x02SMB 2.002\0']))
    if extsec:
        words = U16(3) + U8(3) + U16(50, 1) + U32(16644, 65536, 0xabcd, 0x8000e3fd) + U64(NT) + U16(0) + U8(0)
        guid = bytes(range(16))
        c.send(False, c.smb(0x72, True, words, guid + (spnego_init() if extsec == 'spnego' else b'')))
    else:
        words = U16(3) + U8(3) + U16(50, 1) + U32(16644, 65536, 0xabcd, 0x0000e3fd) + U64(NT) + U16(0) + U8(8)
        c.send(False, c.smb(0x72, True, words, bytes(8) + 'WORKGROUP'.encode('utf-16le') + b'\0\0' + 'SRV'.encode('utf-16le') + b'\0\0'))


def der(tag, body):
    n = len(body)
    return bytes([tag]) + (bytes([n]) if n < 128 else bytes([0x81, n])) + body


def spnego_init():
    """negTokenInit offering NTLMSSP (no tokens, no credentials)."""
    ntlm = der(6, bytes.fromhex('2b06010401823702020a'))
    init = der(0xa0, der(0x30, der(0xa0, der(0x30, ntlm))))
    return der(0x60, der(6, bytes.fromhex('2b0601050502')) + init)


def ss_andx_req(c, extsec=False, andx=0xff, andxoff=0, blob=b''):
    caps = 0x8000d4 | (0x80000000 if extsec else 0)
    if extsec:
        words = U8(andx, 0) + U16(andxoff) + U16(16644, 50, 1) + U32(0xabcd) + U16(len(blob)) + U32(0) + U32(caps)
        data = [blob, 'Unix', 'Samba']
    else:
        words = U8(andx, 0) + U16(andxoff) + U16(16644, 50, 1) + U32(0xabcd) + U16(0, 0) + U32(0) + U32(caps)
        data = ['guest', 'WORKGROUP', 'Unix', 'Samba']
    return c.smb(0x73, False, words, data, uid=0)


def ss_andx_resp(c, extsec=False, andx=0xff, andxoff=0, blob=b'', uid=0x0800, status=0, action=1):
    if extsec:
        words = U8(andx, 0) + U16(andxoff) + U16(action, len(blob))
        data = [blob, 'Unix', 'Samba', 'WORKGROUP']
    else:
        words = U8(andx, 0) + U16(andxoff) + U16(action)
        data = ['Unix', 'Samba', 'WORKGROUP']
    return c.smb(0x73, True, words, data, uid=uid, status=status)


def tcx_req(c, path, service='?????', andx=0xff, andxoff=0, flags=0x0008, pw=b'\0'):
    words = U8(andx, 0) + U16(andxoff, flags, len(pw))
    return c.smb(0x75, False, words, [pw, path, service])


def tcx_resp(c, tid, service='A:', fs='NTFS', andx=0xff, andxoff=0, optional=0x0001, access=(0x1f01ff, 0x1f01ff), wc=7):
    words = U8(andx, 0) + U16(andxoff, optional)
    if wc == 7:
        words += U32(*access)
    return c.smb(0x75, True, words, [service.encode() + b'\0', fs], tid=tid)


def conn_setup(c, path, extsec=False, tid=None, service='?????', rservice='A:', fs='NTFS'):
    session_setup_nt(c, extsec)
    c.nextmid()
    c.send(True, ss_andx_req(c, extsec, blob=(b'NTLMSSP\0' + U32(1) + U32(0xe2088297) + bytes(16)) if extsec else b''))
    c.send(False, ss_andx_resp(c, extsec, blob=b'' if extsec else b''))
    c.nextmid()
    c.send(True, tcx_req(c, path, service))
    c.send(False, tcx_resp(c, c.tid if tid is None else tid, rservice, fs))


def basic_files(c, fid0=0x4000):
    """Core protocol file commands, request/response pairs."""
    fid = fid0
    nm = r'\dir\file.txt'
    rr = c.rr
    rr(0x00, qdata=[B4, r'\newdir'])
    rr(0x01, qdata=[B4, r'\newdir'])
    rr(0x10, qdata=[B4, r'\dir'])
    rr(0x02, qwords=U16(0x42, 0x16), qdata=[B4, nm],
       rwords=U16(fid) + U16(0x20) + U32(1700000000, 12345) + U16(2))
    rr(0x03, qwords=U16(0x20) + U32(1700000000), qdata=[B4, r'\dir\created.txt'], rwords=U16(fid + 1))
    rr(0x0f, qwords=U16(0x20) + U32(1700000000), qdata=[B4, r'\dir\new.txt'], rwords=U16(fid + 2))
    rr(0x0e, qwords=U16(0x20) + U32(1700000000), qdata=[B4, r'\dir'], rwords=U16(fid + 3), rdata=[B4, r'\dir\t0001.tmp'])
    rr(0x08, qdata=[B4, nm], rwords=U16(0x20) + U32(1700000000, 12345) + bytes(10))
    rr(0x09, qwords=U16(0x20) + U32(1700000000) + bytes(10), qdata=[B4, nm])
    rr(0x06, qwords=U16(0x16), qdata=[B4, r'\dir\gone.txt'])
    rr(0x07, qwords=U16(0x16), qdata=[B4, nm, B4, r'\dir\renamed.txt'])
    rr(0x29, qwords=U16(0, 0, 3), qdata=[nm, r'\dir\copy.txt'], rwords=U16(1))
    rr(0x2a, qwords=U16(0, 0, 3), qdata=[nm, r'\dir\moved.txt'], rwords=U16(1))
    rr(0x05, qwords=U16(fid))
    rr(0x12, qwords=U16(fid, 0) + U32(100), rwords=U32(100))
    rr(0x0a, qwords=U16(fid, 10) + U32(0) + U16(10), rwords=U16(10) + bytes(8), rdata=[b'\x01', U16(10), b'0123456789'])
    rr(0x0b, qwords=U16(fid, 10) + U32(0) + U16(10), qdata=[b'\x01', U16(10), b'abcdefghij'], rwords=U16(10))
    rr(0x13, qwords=U16(fid, 10) + U32(0) + U16(10), rwords=U16(10) + bytes(8), rdata=[b'\x01', U16(10), b'0123456789'])
    rr(0x14, qwords=U16(fid, 10) + U32(0) + U16(10), qdata=[b'\x01', U16(10), b'abcdefghij'], rwords=U16(10))
    rr(0x0c, qwords=U16(fid) + U32(10, 0))
    rr(0x0d, qwords=U16(fid) + U32(10, 0))
    rr(0x22, qwords=U16(fid) + U16(0x1234, 0x5678) * 3)
    rr(0x23, qwords=U16(fid), rwords=U16(0x1234, 0x5678) * 3 + U32(12345, 16384) + U16(0x20))
    None
    rr(0x2c, qwords=U16(fid, 10) + U32(0, 0x1234abcd), qdata=[b'\x00', b'abcdefghij'], rwords=U16(10))
    rr(0x11)
    rr(0x04, qwords=U16(fid) + U32(0x5000))
    rr(0x31, qwords=U16(fid + 1) + U32(0x5000))
    rr(0x2b, qwords=U16(1), rwords=U16(1), qdata=b'echo', rdata=b'echo')
    rr(0x80, rwords=U16(1024, 8, 512, 10000, 0))
    rr(0x81, qwords=U16(20, 0x10), qdata=[B4, r'\dir\*', b'\x05', U16(0)],
       rwords=U16(1), rdata=[b'\x05', U16(43), bytes(21), b'\x20', U32(1700000000, 5), b'FILE.TXT\0\0\0\0\0'])
    rr(0x82, qwords=U16(20, 0x10), qdata=[B4, r'\dir\*', b'\x05', U16(0)],
       rwords=U16(1), rdata=[b'\x05', U16(43), bytes(21), b'\x20', U32(1700000000, 5), b'FILE.TXT\0\0\0\0\0'])
    rr(0x83, qwords=U16(20, 0x10), qdata=[B4, r'\dir\*', b'\x05', U16(0)],
       rwords=U16(1), rdata=[b'\x05', U16(43), bytes(21), b'\x20', U32(1700000000, 5), b'FILE.TXT\0\0\0\0\0'])
    rr(0x84, qwords=U16(20, 0x10), qdata=[B4, b'', b'\x05', U16(21), bytes(21)],
       rwords=U16(0), rdata=[b'\x05', U16(1), b'\0'])
    rr(0x34, qwords=U16(7))
    rr(0x35, qwords=U16(7))
    rr(0xc0, qwords=U16(0, 1), qdata=[B4, 'job1'], rwords=U16(fid + 5))
    rr(0xc1, qwords=U16(fid + 5, 5), qdata=[b'\x01', U16(5), b'print'])
    rr(0xc2, qwords=U16(fid + 5, 0))
    rr(0xc3, qwords=U16(10, 0), rwords=U16(1, 0), rdata=[b'\x01', U16(28), bytes(28)])
    rr(0xd4, rdata=[B4, 'HOST'])
    rr(0xd0, qdata=[B4, 'from', B4, 'to', b'\x01', U16(5), b'hello'])
    rr(0xd1, qdata=[B4, 'from', B4, 'to', b'\x01', U16(5), b'hello'])
    rr(0xd2, qdata=[B4, 'fwd'])
    rr(0xd3, qdata=[B4, 'fwd'])
    rr(0xd5, qdata=[B4, 'from', B4, 'to'], rwords=U16(3))
    rr(0xd7, qwords=U16(3), qdata=[b'\x01', U16(5), b'text!'])
    rr(0xd6, qwords=U16(3))

@scenario
def sc_basic(outdir):
    cap = Cap(os.path.join(outdir, 'smb-coverage.pcap'))
    CAPS['main'] = cap
    cap.record = []
    c = Conn(cap, 40001)
    conn_setup(c, r'\\SRV\SHARE')
    basic_files(c)
    andx_files(c)
    trans2_all(c)
    trans_family(c)
    eo_files(c)
    session_variants(cap)
    misc_variants(cap)
    repro_frames(cap)
    extras(cap)
    other_transports(cap)


ANDX_CMDS = (0x24, 0x2d, 0x2e, 0x2f, 0x73, 0x74, 0x75, 0xa2)


def chain(c, reply, parts, **kw):
    """One SMB holding several AndX commands.  parts = [(cmd, words, data)];
    for the AndX commands words[0:4] (cmd, reserved, offset) is filled in.
    data may use str items (see Conn.smb)."""
    first = parts[0][0]
    h = c.hdr(first, reply, **kw)
    uni = (kw.get('flags2') or c.flags2) & 0x8000
    out = h
    for i, (cmd, words, data) in enumerate(parts):
        wc_at = len(out)
        if isinstance(data, (list, tuple)):
            d = b''
            base = wc_at + 1 + len(words) + 2
            for it in data:
                if isinstance(it, str):
                    if uni:
                        if (base + len(d)) % 2:
                            d += b'\0'
                        d += it.encode('utf-16le') + b'\0\0'
                    else:
                        d += it.encode('latin-1') + b'\0'
                else:
                    d += it
            data = d
        body = bytes([len(words) // 2]) + words + U16(len(data)) + data
        if cmd in ANDX_CMDS and i + 1 < len(parts):
            nxt = wc_at + len(body)
            body = body[:1] + bytes([parts[i + 1][0], 0]) + U16(nxt) + body[5:]
        elif cmd in ANDX_CMDS:
            body = body[:1] + b'\xff\0\0\0' + body[5:]
        out += body
    return out


def andx_files(c, fid=0x5000):
    """Open/Read/Write/Locking AndX, NT Create AndX, chains."""
    # Open AndX (wc 15) and extended (wc 19)
    rq = lambda: U8(0xff, 0) + U16(0) + U16(0x0007, 0x42, 0x16, 0x20) + U32(1700000000) + U16(0x11) + U32(0, 0, 0)
    c.nextmid()
    c.send(True, c.smb(0x2d, False, rq(), [r'\dir\open.txt']))
    c.send(False, c.smb(0x2d, True, U8(0xff, 0) + U16(0, fid, 0x20) + U32(1700000000, 12345) + U16(2, 0, 0, 1) + U32(0) + U16(0),
                         b''))
    c.nextmid()
    c.send(True, c.smb(0x2d, False, rq(), [r'\dir\open2.txt']))
    c.send(False, c.smb(0x2d, True, U8(0xff, 0) + U16(0, fid + 1, 0x20) + U32(1700000000, 12345) + U16(2, 0, 0, 1) + U32(0) + U16(0) +
                         U32(0x1f01ff, 0x1f01ff), b''))
    # Read AndX wc 10 and 12, data in response (dataoffset 60)
    for wc12 in (False, True):
        c.nextmid()
        w = U8(0xff, 0) + U16(0) + U16(fid) + U32(0) + U16(20, 20) + U32(0) + U16(20)
        if wc12:
            w += U32(0)
        c.send(True, c.smb(0x2e, False, w, b''))
        data = b'ABCDEFGHIJKLMNOPQRST'
        w = U8(0xff, 0) + U16(0) + U16(0, 0, 0, 20, 32 + 1 + 24 + 2 + 1) + U32(0) + bytes(6)
        c.send(False, c.smb(0x2e, True, w, b'\0' + data))
    # Write AndX wc 12 and 14
    for wc14 in (False, True):
        c.nextmid()
        data = b'0123456789012345'
        w = U8(0xff, 0) + U16(0) + U16(fid) + U32(0, 0) + U16(0, 0, 0, 16, 32 + 1 + (28 if wc14 else 24) + 2 + 1)
        if wc14:
            w += U32(0)
        c.send(True, c.smb(0x2f, False, w, b'\0' + data))
        c.send(False, c.smb(0x2f, True, U8(0xff, 0) + U16(0, 16, 0, 0, 0), b''))
    # Write AndX with MESSAGE_START and RAW on an unseen TID (pipe write with length prefix)
    c.nextmid()
    pw = U32(0) + U16(0)
    c.send(True, c.smb(0x2f, False, U8(0xff, 0) + U16(0) + U16(fid) + U32(0, 0) + U16(0x000c, 0, 0, 8, 32 + 1 + 24 + 2 + 1),
                        b'\0' + U16(6) + b'abcdef', tid=9))
    c.send(False, c.smb(0x2f, True, U8(0xff, 0) + U16(0, 6, 0, 0, 0), b'', tid=9))
    # Open AndX responses: directory, pipe, extended
    for i, (attr, ftype, wc19) in enumerate(((0x10, 0, False), (0x20, 2, False), (0x20, 1, True), (0x20, 0, True))):
        c.nextmid()
        c.send(True, c.smb(0x2d, False, rq(), [r'\dir\o%d' % i]))
        w = U8(0xff, 0) + U16(0, fid + 10 + i, attr) + U32(1700000000, 12345) + U16(2, ftype, 0, 1) + U32(0) + U16(0)
        if wc19:
            w += U32(0x1f01ff, 0x120089)
        c.send(False, c.smb(0x2d, True, w, b''))
    c.rr(0x29, qwords=U16(0, 0, 3), qdata=[r'\dir\file.txt', r'\dir\copy2.txt'], rwords=U16(0), rdata=[B4, r'\dir\failed.txt'], status=0xc0000022)
    c.rr(0x2a, qwords=U16(0, 0, 3), qdata=[r'\dir\file.txt', r'\dir\moved2.txt'], rwords=U16(0), rdata=[B4, r'\dir\failed.txt'], status=0xc0000022)
    # Locking AndX: normal, large file, shared, cancel, oplock change; unlocks and locks
    for lt, nun, nlk in ((0, 1, 1), (0x10, 1, 2), (0x01, 0, 2), (0x12, 2, 0), (0x08, 0, 1), (0x04, 1, 0), (0x02, 0, 0)):
        c.nextmid()
        one = lambda i: (U16(0x1234) + U16(0) + U64(100 * i, 10)) if lt & 0x10 else (U16(0x1234) + U32(100 * i, 10))
        locks = b''.join(one(i) for i in range(nun + nlk))
        c.send(True, c.smb(0x24, False, U8(0xff, 0) + U16(0, fid) + U8(lt, 0) + U32(1000) + U16(nun, nlk), locks))
        c.send(False, c.smb(0x24, True, U8(0xff, 0) + U16(0), b''))
    # oplock break notification from the server (mid 0xffff) and the client's acknowledgement
    c.send(False, c.smb(0x24, False, U8(0xff, 0) + U16(0, fid) + U8(0x02, 1) + U32(0) + U16(0, 0), b'', mid=0xffff, pid=0xffff, tid=1, uid=0))
    c.nextmid()
    c.send(True, c.smb(0x24, False, U8(0xff, 0) + U16(0, fid) + U8(0x02, 1) + U32(0) + U16(0, 0), b''))
    c.send(False, c.smb(0x24, True, U8(0xff, 0) + U16(0), b''))
    # NT Create AndX
    for ext in (False, True):
        c.nextmid()
        name = r'\dir\nt%d.txt' % ext
        w = U8(0xff, 0) + U16(0) + U8(0) + U16(len(name) + 1) + U32(0x16, 0, 0x12019f) + U64(0) + U32(0x80, 3, 1, 0x40, 2) + U8(0)
        c.send(True, c.smb(0xa2, False, w, [name]))
        w = U8(0xff, 0) + U16(0) + U8(1) + U16(fid + 2 + ext) + U32(1) + U64(NT, NT, NT, NT) + U32(0x80) + U64(4096, 100) + U16(0, 0) + U8(0)
        if ext:
            w += b'\x11' * 16 + U64(0x1234) + U32(0x1f01ff, 0x120089)
            c.send(False, c.smb(0xa2, True, w, b'', wc=42))
        else:
            c.send(False, c.smb(0xa2, True, w, b''))
    # NT Cancel, NT Rename
    c.nextmid()
    c.send(True, c.smb(0xa4, False, b'', b''))
    c.rr(0xa5, qwords=U16(0x16, 4), qdata=[B4, r'\dir\a.txt', B4, r'\dir\b.txt'])
    # chain: NT Create AndX -> Write AndX -> Read AndX -> Locking AndX -> Close
    c.nextmid()
    name = r'\dir\chain.txt'
    ncw = U8(0xff, 0) + U16(0) + U8(0) + U16(len(name) + 1) + U32(0x16, 0, 0x12019f) + U64(0) + U32(0x80, 3, 1, 0x40, 2) + U8(0)
    wrw = U8(0xff, 0) + U16(0) + U16(fid + 9) + U32(0, 0) + U16(0, 0, 0, 4, 0)
    rdw = U8(0xff, 0) + U16(0) + U16(fid + 9) + U32(0) + U16(4, 4) + U32(0) + U16(4)
    lkw = U8(0xff, 0) + U16(0, fid + 9, 0, 0) + U32(0) + U16(0, 0)
    c.send(True, chain(c, False, [(0xa2, ncw, [name]), (0x2f, wrw, b'\0abcd'), (0x2e, rdw, b''), (0x24, lkw, b'')]))
    r1 = U8(0xff, 0) + U16(0) + U8(1) + U16(fid + 9) + U32(1) + U64(NT, NT, NT, NT) + U32(0x80) + U64(4096, 100) + U16(0, 0) + U8(0)
    r2 = U8(0xff, 0) + U16(0, 4, 0, 0, 0)
    r3 = U8(0xff, 0) + U16(0) + U16(0, 0, 0, 4, 0) + U32(0) + bytes(6)
    r4 = U8(0xff, 0) + U16(0)
    c.send(False, chain(c, True, [(0xa2, r1, b''), (0x2f, r2, b''), (0x2e, r3, b'\0wxyz'), (0x24, r4, b'')]))
    # Logoff AndX chained to a Session Setup AndX
    c.nextmid()
    ssw = U8(0xff, 0) + U16(0) + U16(16644, 50, 1) + U32(0xabcd) + U16(0, 0) + U32(0) + U32(0xd4)
    c.send(True, chain(c, False, [(0x74, U8(0xff, 0) + U16(0), b''), (0x73, ssw, ['guest', 'WORKGROUP', 'Unix', 'Samba'])]))
    c.send(False, chain(c, True, [(0x74, U8(0xff, 0) + U16(0), b''), (0x73, U8(0xff, 0) + U16(0, 1), ['Unix', 'Samba', 'WORKGROUP'])]))
    # session logoff chain: Logoff AndX
    c.rr(0x74, qwords=U8(0xff, 0) + U16(0), rwords=U8(0xff, 0) + U16(0))


def _layout(c, uni, base0, name, params, data, align):
    """Offsets of name, params and data relative to the SMB start."""
    nm = b''
    if name is False:
        pass
    elif name is not None:
        if uni:
            if base0 % 2:
                nm += b'\0'
            nm += name.encode('utf-16le') + b'\0\0'
        else:
            nm += name.encode('latin-1') + b'\0'
    else:
        nm = b'\0' if not uni else b'\0\0'
    po = base0 + len(nm)
    pad1 = (-po) % align
    po += pad1
    od = po + len(params)
    pad2 = (-od) % align
    od += pad2
    body = nm + b'\0' * pad1 + params + b'\0' * pad2 + data
    return po, od, body


def trans_req(c, cmd, setup=b'', params=b'', data=b'', name=None, tpc=None, tdc=None,
              flags=0, timeout=1000, mpc=64, mdc=4096, **kw):
    """Primary Transaction / Transaction2 request."""
    uni = (kw.get('flags2') or c.flags2) & 0x8000
    sc = len(setup) // 2
    wc = 14 + sc
    base = 32 + 1 + 2 * wc + 2
    po, od, body = _layout(c, uni, base, name, params, data, 4)
    words = U16(len(params) if tpc is None else tpc, len(data) if tdc is None else tdc, mpc, mdc) + U8(0, 0) + \
        U16(flags) + U32(timeout) + U16(0) + U16(len(params), po, len(data), od if data else 0) + U8(sc, 0) + setup
    return c.hdr(cmd, False, **kw) + bytes([wc]) + words + U16(len(body)) + body


def trans_resp(c, cmd, setup=b'', params=b'', data=b'', tpc=None, tdc=None, pd=0, dd=0, **kw):
    uni = (kw.get('flags2') or c.flags2) & 0x8000
    sc = len(setup) // 2
    wc = 10 + sc
    base = 32 + 1 + 2 * wc + 2
    po, od, body = _layout(c, uni, base, False, params, data, 4)
    words = U16(len(params) if tpc is None else tpc, len(data) if tdc is None else tdc, 0) + \
        U16(len(params), po, pd, len(data), od, dd) + U8(sc, 0) + setup
    return c.hdr(cmd, True, **kw) + bytes([wc]) + words + U16(len(body)) + body


def trans_sec(c, cmd, tpc, tdc, params=b'', pd=0, data=b'', dd=0, fid=0, **kw):
    """Transaction (0x26) / Transaction2 (0x33) secondary request."""
    uni = (kw.get('flags2') or c.flags2) & 0x8000
    wc = 9 if cmd == 0x33 else 8
    base = 32 + 1 + 2 * wc + 2
    po, od, body = _layout(c, 0, base, False, params, data, 4)
    words = U16(tpc, tdc, len(params), po, pd, len(data), od if data else 0, dd)
    if cmd == 0x33:
        words += U16(fid)
    return c.hdr(cmd, False, **kw) + bytes([wc]) + words + U16(len(body)) + body


def interim(c, cmd, **kw):
    return c.hdr(cmd, True, **kw) + b'\0' + U16(0)


def nt_req(c, sub, setup=b'', params=b'', data=b'', tpc=None, tdc=None, **kw):
    sc = len(setup) // 2
    wc = 19 + sc
    base = 32 + 1 + 2 * wc + 2
    po, od, body = _layout(c, 0, base, False, params, data, 4)
    words = U8(sc and 0 or 0) + U16(0) + U32(len(params) if tpc is None else tpc, len(data) if tdc is None else tdc,
                                            0x400, 0x10000, len(params), po, len(data), od if data else 0) + \
        U8(sc) + U16(sub) + setup
    assert len(words) == 2 * wc, (len(words), wc)
    return c.hdr(0xa0, False, **kw) + bytes([wc]) + words + U16(len(body)) + body


def nt_resp(c, sub, setup=b'', params=b'', data=b'', tpc=None, tdc=None, pd=0, dd=0, **kw):
    sc = len(setup) // 2
    wc = 18 + sc
    base = 32 + 1 + 2 * wc + 2
    po, od, body = _layout(c, 0, base, False, params, data, 4)
    words = bytes(3) + U32(len(params) if tpc is None else tpc, len(data) if tdc is None else tdc,
                           len(params), po, pd, len(data), od if data else 0, dd) + U8(sc) + setup
    assert len(words) == 2 * wc, (len(words), wc)
    return c.hdr(0xa0, True, **kw) + bytes([wc]) + words + U16(len(body)) + body


def nt_sec(c, tpc, tdc, params=b'', pd=0, data=b'', dd=0, **kw):
    wc = 18
    base = 32 + 1 + 2 * wc + 2
    po, od, body = _layout(c, 0, base, False, params, data, 4)
    words = bytes(3) + U32(tpc, tdc, len(params), po, pd, len(data), od if data else 0, dd) + U8(0)
    assert len(words) == 2 * wc, (len(words), wc)
    return c.hdr(0xa1, False, **kw) + bytes([wc]) + words + U16(len(body)) + body


def t2(c, sub, qp=b'', qd=b'', rp=b'', rd=b'', fid=None, status=0, qkw=None, rkw=None):
    """Transaction2 request and response, each in its own segment."""
    c.nextmid()
    c.send(True, trans_req(c, 0x32, U16(sub), qp, qd, **(qkw or {})))
    c.send(False, trans_resp(c, 0x32, b'', rp, rd, status=status, **(rkw or {})))


def ustr(c, s, nul=False):
    """A string in the connection's character set (no terminator unless nul)."""
    b = s.encode('utf-16le') if c.uni else s.encode('latin-1')
    return b + ((b'\0\0' if c.uni else b'\0') if nul else b'')


T8 = U64(NT)
BASIC = T8 * 4 + U32(0x20, 0)
GEALIST = U32(10) + U8(4) + b'user\0'
EALIST = U32(16) + U8(0, 4) + U16(3) + b'user\0' + b'val'
STD = U64(4096, 100) + U32(1) + U8(0, 1) + U16(0)


def ff2_entry(c, level, name, last, resume=False, short='SHORT~1.TXT'):
    n = ustr(c, name)
    sh = (short.encode('utf-16le') + bytes(24))[:24]
    if level == 1:
        e = (U32(0x11111111) if resume else b'') + U32(0x12345678) * 3 + U32(100, 4096) + U16(0x20) + U8(len(n)) + n + b'\0' * (2 if c.uni else 1)
        return e
    if level in (2, 3):
        e = (U32(0x11111111) if resume else b'') + U32(0x12345678) * 3 + U32(100, 4096) + U16(0x20) + (U32(0) if level == 2 else EALIST) + U8(len(n)) + n + b'\0'
        return e
    if level == 0x103:
        e = U32(0, 1, len(n)) + n
    elif level == 0x101:
        e = U32(0, 1) + T8 * 4 + U64(100, 4096) + U32(0x20, len(n)) + n
    elif level in (0x102, 0x105):
        e = U32(0, 1) + T8 * 4 + U64(100, 4096) + U32(0x20, len(n), 0) + n
    elif level == 0x104:
        e = U32(0, 1) + T8 * 4 + U64(100, 4096) + U32(0x20, len(n), 0) + U8(len(short) * 2, 0) + sh + n
    elif level == 0x106:
        e = U32(0, 1) + T8 * 4 + U64(100, 4096) + U32(0x20, len(n), 0) + U8(len(short) * 2, 0) + sh + U16(0) + U64(0x1234) + n
    elif level == 0x202:
        e = U32(0, 1) + U64(100, 4096) + T8 * 3 + U64(1000, 1000) + U32(1) + U64(8, 1, 0x4321, 0o644, 1) + n + (b'\0\0' if c.uni else b'\0')
    elif level == 0x20b:
        e = U32(0, 1) + U64(100, 4096) + T8 * 3 + U64(1000, 1000) + U32(1) + U64(8, 1, 0x4321, 0o644, 1) + T8 + U32(0x20, 0x20) + U32(len(n)) + n + b'\0\0'
    else:
        raise ValueError(level)
    if level >= 0x101 and level != 0x202 and level != 0x20b:
        pass
    return e


def ff2_data(c, level, names, resume=False):
    out = b''
    for i, nm in enumerate(names):
        e = ff2_entry(c, level, nm, i == len(names) - 1, resume)
        if level >= 0x101:
            if i != len(names) - 1:
                e += b'\0' * ((-len(e)) % 8)
                e = U32(len(e)) + e[4:]
            else:
                e = U32(0) + e[4:]
        out += e
    return out


def trans2_all(c):
    p = c.nextmid
    # OPEN2
    t2(c, 0, U16(0x0007, 0x42, 0x20, 0x20) + U32(1700000000) + U16(1) + U32(0) + bytes(10) + ustr(c, r'\dir\open2.txt', True),
       EALIST, U16(0x6001, 0x20) + U32(1700000000, 100) + U16(2, 0, 0, 1) + U32(0) + U16(0) + U32(0), b'open2 data')
    # FIND_FIRST2 / FIND_NEXT2 with every info level
    sid = 0x40
    for level in (1, 2, 3, 0x101, 0x102, 0x103, 0x104, 0x105, 0x106, 0x202, 0x20b):
        sid += 1
        resume = level in (1, 2)
        flags = (0x0004 if resume else 0) | 0x0002 | 0x0008
        names = ['a.txt', 'Second file.doc'] if level != 3 else ['x']
        d = ff2_data(c, level, names, resume)
        t2(c, 1, U16(0x16, 100, flags, level) + U32(0) + ustr(c, r'\dir\*', True), b'',
           U16(sid, len(names), 1 if level != 1 else 0, 0, 0), d)
        t2(c, 2, U16(sid, 100, level) + U32(0x11111111) + U16(flags) + ustr(c, 'a.txt', True), GEALIST if level == 3 else b'',
           U16(len(names), 1, 0, 0), d)
    # FIND_FIRST2 with an unknown level, EAs from list data
    t2(c, 1, U16(0x16, 100, 0, 0x0777) + U32(0) + ustr(c, r'\dir\*', True), b'', U16(0x55, 1, 1, 0, 0), bytes(40))
    t2(c, 1, U16(0x16, 100, 0, 3) + U32(0) + ustr(c, r'\dir\*', True), GEALIST,
       U16(0x56, 1, 1, 0, 0), ff2_data(c, 3, ['x']))
    # QUERY_FS_INFO levels
    volname = ustr(c, 'LABEL')
    qfsi = {
        1: U32(1, 8, 100000, 50000) + U16(512),
        2: U32(0x1234abcd) + U8(len(volname)) + volname + b'\0\0',
        0x101: U32(len(volname)) + volname,
        1001: U32(len(volname)) + volname,
        0x102: T8 + U32(0x1234abcd, len('LABEL') * 2) + U16(0) + 'LABEL'.encode('utf-16le'),
        1002: T8 + U32(0x1234abcd, len('LABEL') * 2) + U16(0) + 'LABEL'.encode('utf-16le'),
        0x103: U64(1000, 500) + U32(8, 512),
        1003: U64(1000, 500) + U32(8, 512),
        0x104: U32(7, 0x20),
        1004: U32(7, 0x20),
        0x105: U32(0x3, 255, 8) + 'NTFS'.encode('utf-16le'),
        1005: U32(0x3, 255, 8) + 'NTFS'.encode('utf-16le'),
        1006: bytes(48),
        1007: U64(1000, 500, 400) + U32(8, 512),
        1008: bytes(16) + bytes(48),
        0x200: U64(0x1000, 0, 1, 2, 3, 4, 5),
        0x202: U64(1000, 1000) + U32(0, 0, 1) + bytes(16) + U64(0),
        0x301: U64(NT, NT, NT) + U32(1, 512, 2) + b'F' * 32 + U32(1, 2, 3, 4, 0x1f),
        0x777: bytes(20),
    }
    for lv, d in qfsi.items():
        t2(c, 3, U16(lv), b'', b'', d)
    # SET_FS_INFO
    t2(c, 4, U16(0, 0x203), ntlmssp_negotiate(), U16(0), ntlmssp_negotiate())
    t2(c, 4, U16(0, 1006), bytes(48), U16(0))
    t2(c, 4, U16(0, 0x777), bytes(8), U16(0))
    # QUERY_PATH_INFO / QUERY_FILE_INFO levels
    nm = ustr(c, r'\dir\file.txt')
    allinfo = BASIC + STD + U64(0x1234) + U32(0, 0x1f01ff) + U64(0) + U32(0, 3) + U32(len(nm)) + nm
    stream = U32(40 + 0, 2 * len('::$DATA'), 0)[:12]
    streams = (U32(0, 2 * 7) + U64(100, 4096) + '::$DATA'.encode('utf-16le') + bytes(0))
    streams = U32(len(streams) + (-len(streams)) % 8 + 0, 14) + streams[8:]
    streams += b'\0' * ((-len(streams)) % 8)
    streams2 = U32(0, 14) + U64(100, 4096) + '::$DATA'.encode('utf-16le')
    streams = streams + streams2
    qpi = {
        1: U32(0x12345678) * 3 + U32(100, 4096) + U16(0x20),
        2: U32(0x12345678) * 3 + U32(100, 4096) + U16(0x20) + U32(0),
        3: EALIST,
        4: EALIST,
        6: U8(0) * 4,
        0x101: BASIC, 1004: BASIC,
        0x102: STD, 1005: STD,
        1006: U64(0x1234),
        0x103: U32(0), 1007: U32(0),
        0x104: U32(len(nm)) + nm, 1009: U32(len(nm)) + nm,
        0x108: U32(len(nm)) + nm, 1021: U32(len(nm)) + nm,
        1014: U64(0), 1016: U32(0), 1017: U32(3), 1019: U64(4096), 1020: U64(100),
        0x107: allinfo, 1018: allinfo,
        0x109: streams, 1022: streams,
        1024: U32(0, 0, 255, 1, 4096, 0, 4096, 0, 1, 0)[:40],
        1025: U32(0, 0, 0, 0),
        0x10b: U64(100) + U16(0) + U8(0, 0, 0) + bytes(3), 1028: U64(100) + U16(0) + U8(0, 0, 0) + bytes(3),
        1034: T8 * 4 + U64(4096, 100) + U32(0x20, 0),
        1035: U32(0x20, 0),
        0x200: U64(100, 4096) + T8 * 3 + U64(1000, 1000) + U32(1) + U64(8, 1, 0x4321, 0o644, 1),
        0x201: ustr(c, '/target', True),
        0x202: U32(0),
        0x204: U16(1, 6, 0) + b''.join(U8(t, 7) + U64(0x1234) for t in (1, 4, 2, 8, 0x10, 0x20)),
        0x205: U32(0),
        0x206: U32(0x10, 0x10),
        0x207: U64(0o755),
        0x208: U16(0, 0) + U64(0, 10) + U32(1234),
        0x20b: U64(100, 4096) + T8 * 3 + U64(1000, 1000) + U32(1) + U64(8, 1, 0x4321, 0o644, 1) + T8 + U32(0x20, 0x20),
        1011: bytes(24), 1010: bytes(24),
        0x777: bytes(30),
    }
    for lv, d in qpi.items():
        t2(c, 5, U16(lv) + U32(0) + ustr(c, r'\dir\file.txt', True), b'\0' * 4 if lv == 0x101 else b'', U16(0), d)
        t2(c, 7, U16(0x6001, lv), b'\0' * 4 if lv == 0x101 else b'', U16(0), d)
    # SET_PATH_INFO / SET_FILE_INFO levels
    ren = U8(1, 0, 0, 0) + U32(0, len(nm)) + nm
    spi = {
        1: U32(0x12345678) * 3 + U32(100, 4096) + U16(0x20),
        2: EALIST,
        4: EALIST,
        0x101: BASIC, 1004: BASIC,
        0x102: U8(1), 1013: U8(1),
        0x103: U64(4096), 1019: U64(4096),
        0x104: U64(100), 1020: U64(100),
        0x200: T8 * 0 + U64(100, 4096) + T8 * 3 + U64(1000, 1000) + U32(1) + U64(8, 1, 0x4321, 0o644, 1),
        0x201: ustr(c, '/target', True),
        0x202: ustr(c, '/target', True),
        0x204: U16(1, 6, 0) + b''.join(U8(t, 7) + U64(0x1234) for t in (1, 4, 2, 8, 0x10, 0x20)),
        0x205: U32(0),
        0x206: U32(0x10, 0x10),
        0x208: U16(0, 0) + U64(0, 10) + U32(1234),
        0x209: U32(0x1, 0x2, 0o644) + U64(0)[:0] + bytes(0),
        0x20a: U32(0x1),
        0x20b: U64(100, 4096) + T8 * 3 + U64(1000, 1000) + U32(1) + U64(8, 1, 0x4321, 0o644, 1) + T8 + U32(0x20, 0x20),
        1010: ren, 1014: U64(0), 1016: U32(0), 1023: U32(0, 0), 1025: U32(0, 0, 0, 0),
        1029: U32(0), 1032: bytes(16), 1039: U32(0), 1040: U32(0),
        0x777: bytes(10),
    }
    for lv, d in spi.items():
        t2(c, 6, U16(lv) + U32(0) + ustr(c, r'\dir\file.txt', True), d, U16(0), b'x' if lv == 0x101 else b'')
        t2(c, 8, U16(0x6001, lv, 0, 0), d, U16(0), b'y' if lv == 0x101 else b'')
    # FIND_NOTIFY_FIRST/NEXT, CREATE_DIRECTORY, FSCTL, IOCTL2, SESSION_SETUP
    t2(c, 0x0b, U16(0x16, 5, 0x0001) + U32(0) + ustr(c, r'\dir', True), b'match', U16(3, 1, 0), bytes(8))
    t2(c, 0x0c, U16(3, 5), b'monitor', U16(1, 0), bytes(4))
    t2(c, 0x0d, U32(0) + ustr(c, r'\dir\sub', True), EALIST, U16(0), b'dirdata')
    t2(c, 0x09, b'fsctlparams', b'fsctl', b'rp', b'fsctl reply')
    t2(c, 0x0a, b'ioctlparams', b'ioctl', b'rp', b'ioctl reply')
    t2(c, 0x0e, b'ss', b'ssdata', b'rp', b'ssreply')
    t2(c, 0x0f, b'', b'', b'', b'')
    t2(c, 0x11, ustr(c, r'\SRV\SHARE\dfs', True), b'', b'', b'reply')
    # long names (Info column shows "[See Packet Detail]"), FIND_NEXT2 with no name
    longn = '\\' + 'verylongdirectoryname' * 3 + '\\file.txt'
    t2(c, 0, U16(0x0007, 0x42, 0x20, 0x20) + U32(1700000000) + U16(1) + U32(0) + bytes(10) + ustr(c, longn, True), b'', U16(0x6002, 0x20) + U32(1700000000, 100) + U16(2, 0, 0, 1) + U32(0) + U16(0) + U32(0))
    t2(c, 1, U16(0x16, 100, 0, 0x104) + U32(0) + ustr(c, longn, True), b'', U16(0x57, 0, 1, 0, 0), b'')
    t2(c, 2, U16(0x57, 100, 0x104) + U32(0) + U16(0) + ustr(c, '', True), b'', U16(0, 1, 0, 0), b'')
    t2(c, 2, U16(0x57, 100, 0x104) + U32(0) + U16(0) + ustr(c, longn, True), b'', U16(0, 1, 0, 0), b'')
    t2(c, 5, U16(0x101) + U32(0) + ustr(c, longn, True), b'', U16(0), BASIC)
    t2(c, 6, U16(0x101) + U32(0) + ustr(c, longn, True), BASIC, U16(0))
    t2(c, 0x0b, U16(0x16, 5, 0x0001) + U32(0) + ustr(c, longn, True), b'', U16(3, 1, 0), bytes(8))
    t2(c, 0x0d, U32(0) + ustr(c, longn, True), b'', U16(0))
    t2(c, 0x11, ustr(c, longn, True), b'', b'', b'')
    # requests whose parameters are too short to carry the information level
    for sub in (1, 3, 4, 5, 7):
        t2(c, sub, b'', b'', U16(0, 0, 0, 0, 0) if sub == 1 else U16(0), BASIC)
    # a response whose request was not captured
    for sub in (1, 5):
        c.nextmid()
        c.send(False, trans_resp(c, 0x32, b'', U16(0, 0, 0, 0, 0) if sub == 1 else U16(0), BASIC))
    # Transaction2 request without the setup word (no subcommand)
    c.nextmid()
    c.send(True, trans_req(c, 0x32, b'', U16(0x101), b''))
    c.send(False, trans_resp(c, 0x32, b'', U16(0), BASIC))
    # DFS
    t2(c, 0x10, U16(3) + ustr(c, r'\SRV\SHARE\dfs', True), b'', b'', dfs_resp(c))
    t2(c, 0x10, U16(1) + ustr(c, r'\SRV\SHARE\dfs1', True), b'', b'', dfs_resp(c, 1))
    t2(c, 0x11, ustr(c, r'\SRV\SHARE\dfs', True), U16(3, 0x12, 1, 0) + ustr(c, 'node', True), b'', b'')


def dfs_resp(c, ver=None):
    def S(s):
        return s.encode('utf-16le') + b'\0\0'
    out = b''
    for v in ([ver] if ver else [2, 3, 4, 3]):
        namelist = (v == 3 and out != b'')
        if v == 1:
            ent = U16(1, 0, 1, 0)
            ent = U16(1, 8 + 2 * 12, 1, 0) + S('\\SRV\\SHARE')
            out += ent
            continue
        out += b'\xaa'  # placeholder, replaced below
        out = out[:-1]
    # entries built with strings after all fixed parts
    entries = []
    def fixed(v, nl):
        if v == 2:
            return 22
        if v in (3, 4):
            return 8 + (4 + 6 + 0 if nl else 4 + 6 + 16)
    vers = [ver] if ver else [2, 3, 4, 3]
    if ver == 1:
        body = U16(1, 8 + 24, 1, 0) + S('\\SRV\\SHARE\\a')
        return U16(10, 1) + U32(3) + body
    nls = [False, False, False, True]
    sizes = [fixed(v, nl) for v, nl in zip(vers, nls)]
    strpos = sum(sizes)
    strings = b''
    blobs = []
    pos = 0
    for v, nl, sz in zip(vers, nls, sizes):
        def off(s):
            nonlocal strings
            o = strpos + len(strings) - pos
            strings += S(s)
            return o
        if v == 2:
            e = U16(2, sz, 0, 0) + U32(5, 300) + U16(off(r'\SRV\SHARE'), off(r'\SRV\SHARE'), off(r'\SRV2\SHARE'))
        elif nl:
            dom = off('DOMAIN')
            exp = off('exp1')
            off('exp2')
            e = U16(v, sz, 0, 2) + U32(300) + U16(dom, 2, exp)
            e += bytes(sz - len(e))
        else:
            e = U16(v, sz, 0, 0) + U32(300) + U16(off(r'\SRV\SHARE'), off(r'\SRV\SHARE'), off(r'\SRV2\SHARE')) + bytes(range(16))
        blobs.append(e)
        pos += sz
    return U16(10, len(vers)) + U32(3) + b''.join(blobs) + strings


def sid(auth=5, subs=(32, 544)):
    return bytes([1, len(subs)]) + auth.to_bytes(6, 'big') + U32(*subs)


def secdesc():
    o, g = sid(), sid(5, (21, 1, 2, 3, 1000))
    dacl_ace = U8(0, 0) + U16(8 + len(o)) + U32(0x1f01ff) + o
    dacl = U8(2, 0) + U16(8 + len(dacl_ace), 1, 0) + dacl_ace
    sacl_ace = U8(2, 0xc0) + U16(8 + len(g)) + U32(0x1f01ff) + g
    sacl = U8(2, 0) + U16(8 + len(sacl_ace), 1, 0) + sacl_ace
    base = 20
    return (U8(1, 0) + U16(0x8014 | 0x10) + U32(base, base + len(o), base + len(o) + len(g),
            base + len(o) + len(g) + len(sacl)) + o + g + sacl + dacl)


def dcerpc_bind(callid=1):
    uuid = bytes.fromhex('c84f324b7016d30112785a47bf6ee188')
    xfer = bytes.fromhex('045d888aeb1cc9119fe808002b104860')
    body = U16(4280, 4280) + U32(0) + U8(1, 0, 0, 0) + U16(0, 1) + uuid + U16(3, 0) + xfer + U32(2)
    return U8(5, 0, 11, 3) + U8(0x10, 0, 0, 0) + U16(16 + len(body), 0) + U32(callid) + body


def dcerpc_bind_ack(callid=1):
    xfer = bytes.fromhex('045d888aeb1cc9119fe808002b104860')
    port = b'\\PIPE\\srvsvc\0'
    body = U16(4280, 4280) + U32(0x1234) + U16(len(port)) + port
    body += b'\0' * ((-len(body)) % 4) + U8(1, 0, 0, 0) + U16(0, 0) + xfer + U32(2)
    return U8(5, 0, 12, 3) + U8(0x10, 0, 0, 0) + U16(16 + len(body), 0) + U32(callid) + body


def nt_create(c, name, fid, mid_start=None, isdir=0, ftype=0):
    c.nextmid()
    w = U8(0xff, 0) + U16(0) + U8(0) + U16(len(name) + 1) + U32(0x16, 0, 0x12019f) + U64(0) + U32(0x80, 3, 1, 0x40, 2) + U8(0)
    c.send(True, c.smb(0xa2, False, w, [name]))
    w = U8(0xff, 0) + U16(0) + U8(1) + U16(fid) + U32(1) + U64(NT, NT, NT, NT) + U32(0x10 if isdir else 0x80) + U64(4096, 100) + U16(ftype, 0) + U8(isdir)
    c.send(False, c.smb(0xa2, True, w, b''))


def trans_family(c):
    """Transaction (pipes, mailslots), multipart transactions, NT Transact."""
    fid = 0x7000
    # an IPC$ tree and a pipe opened with NT Create AndX
    c.tid = 5
    c.nextmid()
    c.send(True, tcx_req(c, r'\\SRV\IPC$', 'IPC', pw=b'\0'))
    None
    c.send(False, c.smb(0x75, True, U8(0xff, 0) + U16(0, 1) + U32(0x1f01ff, 0), [b'IPC\0', ''], tid=5))
    nt_create(c, r'\srvsvc', fid, ftype=2)
    # DCE/RPC bind through Write AndX / Read AndX on the pipe (IPC$)
    bind = dcerpc_bind()
    c.nextmid()
    w = U8(0xff, 0) + U16(0) + U16(fid) + U32(0, 0) + U16(0, 0, 0, len(bind), 32 + 1 + 24 + 2 + 1)
    c.send(True, c.smb(0x2f, False, w, b'\0' + bind))
    c.send(False, c.smb(0x2f, True, U8(0xff, 0) + U16(0, len(bind), 0, 0, 0), b''))
    c.nextmid()
    ack = dcerpc_bind_ack()
    w = U8(0xff, 0) + U16(0) + U16(fid) + U32(0) + U16(1024, 0) + U32(0) + U16(0)
    c.send(True, c.smb(0x2e, False, w, b''))
    w = U8(0xff, 0) + U16(0) + U16(0, 0, 0, len(ack), 32 + 1 + 24 + 2 + 1) + U32(0) + bytes(6)
    c.send(False, c.smb(0x2e, True, w, b'\0' + ack))
    # Write (core) with data on the pipe, Read response
    c.rr(0x0b, qwords=U16(fid, len(bind)) + U32(0) + U16(0), qdata=[b'\x01', U16(len(bind)), bind], rwords=U16(len(bind)))
    c.rr(0x0a, qwords=U16(fid, 1024) + U32(0) + U16(0), rwords=U16(len(ack)) + bytes(8), rdata=[b'\x01', U16(len(ack)), ack])
    # Transaction on the pipe: TransactNmPipe with a DCE/RPC bind
    for sub, setup, data, rdata in (
            (0, U16(0x26, fid), bind, ack),
            (1, U16(0x54, 0), b'', b''),
            (2, U16(0x53, 0), b'', b''),
            (3, U16(0x23, fid), b'', bytes(6)),
            (4, U16(0x21, fid), b'', U16(0x0100)),
            (5, U16(0x01, fid), U16(0x8000), b''),
            (6, U16(0x22, fid), b'', bytes(16)),
            (7, U16(0x11, fid), b'', b'raw'),
            (8, U16(0x31, fid), b'abc', U16(3)),
            (9, U16(0x99, fid), b'', b''),
            (10, b'', b'', b'')):
        c.nextmid()
        nm = r'\PIPE\srvsvc' if sub < 10 else r'\PIPE\LANMAN'
        c.send(True, trans_req(c, 0x25, setup, b'', data, name=nm))
        c.send(False, trans_resp(c, 0x25, b'', b'', rdata))
    # LANMAN-style pipe transaction with parameters
    c.nextmid()
    c.send(True, trans_req(c, 0x25, b'', U16(0) + b'WrLeh\0B13BWz\0' + U16(1, 0xffff), b'', name=r'\PIPE\LANMAN'))
    c.send(False, trans_resp(c, 0x25, b'', U16(0, 0, 0, 0), b''))
    # Mailslot (one way, broadcast style), mailslot and unknown names
    c.nextmid()
    ms = U8(1) + b'HOST1\0' + bytes(8)
    c.send(True, (trans_req(c, 0x25, U16(1, 0, 2), b'', U8(1, 0) + U32(0) + U16(0) + b'HOST1\0\0\0\0\0\0\0\0\0\0\0\0' + bytes(16), name=r'\MAILSLOT\BROWSE', flags=2,
                     mid=0, pid=0, uid=0, tid=0)))
    c.nextmid()
    c.send(True, trans_req(c, 0x25, U16(1, 0, 2), b'', b'hello', name=r'\MAILSLOT\OTHER', flags=2))
    c.nextmid()
    c.send(True, trans_req(c, 0x25, U16(5, 6), b'pp', b'dd', name=r'\OTHER\NAME'))
    c.send(False, trans_resp(c, 0x25, U16(7), b'qq', b'rr'))
    # an empty-name transaction response with no request seen
    c.send(False, trans_resp(c, 0x25, b'', b'p', b'd', mid=0x7777))
    # Transaction with disconnect-TID flag and no-response flag
    c.nextmid()
    c.send(True, trans_req(c, 0x25, U16(0x26, fid), b'', bind, name=r'\PIPE\\', flags=1))
    c.send(False, trans_resp(c, 0x25, b'', b'', ack))

    # --- multi-part Transaction2 requests (secondary requests) --------
    c.tid = 1
    def mp_t2(sub, params, data, split, ack_interim=True):
        c.nextmid()
        mid = c.mid
        tdc = len(data)
        c.send(True, trans_req(c, 0x32, U16(sub), params, data[:split[0]], tdc=tdc))
        c.send(False, interim(c, 0x32))
        pos = split[0]
        for n in split[1:]:
            c.send(True, trans_sec(c, 0x33, len(params), tdc, b'', 0, data[pos:pos + n], pos, fid=0x6001))
            pos += n
        c.send(False, trans_resp(c, 0x32, b'', U16(0), b''))
    mp_t2(8, U16(0x6001, 1004, 0, 0), BASIC + bytes(80), (48, 40, 32))
    mp_t2(6, U16(1004) + U32(0) + ustr(c, r'\dir\file.txt', True), BASIC + bytes(60), (44, 56))
    # a secondary request without a primary
    c.nextmid()
    c.send(True, trans_sec(c, 0x33, 4, 40, b'', 0, b'x' * 40, 0, fid=0x6001))
    # --- multi-part Transaction requests (pipe write in two parts) ----
    c.nextmid()
    big = dcerpc_bind() + bytes(100)
    c.send(True, trans_req(c, 0x25, U16(0x26, fid), b'', big[:60], name=r'\PIPE\\', tdc=len(big)))
    c.send(False, interim(c, 0x25))
    c.send(True, trans_sec(c, 0x26, 0, len(big), b'', 0, big[60:], 60))
    c.send(False, trans_resp(c, 0x25, b'', b'', ack))
    # --- multi-part Transaction2 responses ---------------------------
    for sub, qp, full in ((7, U16(0x6001, 1018), None), (5, U16(1018) + U32(0) + ustr(c, r'\dir\file.txt', True), None)):
        c.nextmid()
        allinfo = BASIC + STD + U64(0x1234) + U32(0, 0x1f01ff) + U64(0) + U32(0, 3) + U32(len(ustr(c, 'x.txt'))) + ustr(c, 'x.txt')
        c.send(True, trans_req(c, 0x32, U16(sub), qp, b''))
        c.send(False, trans_resp(c, 0x32, b'', U16(0), allinfo[:50], tdc=len(allinfo), tpc=2))
        c.send(False, trans_resp(c, 0x32, b'', b'', allinfo[50:], tdc=len(allinfo), tpc=2, dd=50))
    # response parts out of order / second part only
    c.nextmid()
    c.send(True, trans_req(c, 0x32, U16(7), U16(0x6001, 1018), b''))
    c.send(False, trans_resp(c, 0x32, b'', U16(0), allinfo[:40], tdc=len(allinfo), tpc=2))
    c.send(False, trans_resp(c, 0x32, b'', b'', allinfo[40:90], tdc=len(allinfo), tpc=2, dd=40))
    c.send(False, trans_resp(c, 0x32, b'', b'', allinfo[90:], tdc=len(allinfo), tpc=2, dd=90))
    # multi-part Transaction response (pipe read)
    c.nextmid()
    c.send(True, trans_req(c, 0x25, U16(0x26, fid), b'', bind, name=r'\PIPE\\'))
    c.send(False, trans_resp(c, 0x25, b'', b'', ack[:30], tdc=len(ack)))
    c.send(False, trans_resp(c, 0x25, b'', b'', ack[30:], tdc=len(ack), dd=30))

    # --- NT Transact ---------------------------------------------------
    nt_family(c)


def nt_family(c):
    fid = 0x7100
    nt_create(c, r'\dir\ntfile', fid)
    nt_create(c, r'\dir\ntdir', fid + 1, isdir=1)
    sd = secdesc()
    name = ustr(c, r'\dir\ntt.txt')
    for ext in (False, True):
        # NT CREATE through NT Transact
        ea = EALIST if ext else b''
        params = U32(0x16, 0, 0x12019f) + U64(0) + U32(0x80, 3, 1, 0x40) + U32(len(sd), len(ea), len(name), 2) + U8(0) + name
        c.nextmid()
        c.send(True, nt_req(c, 1, U16(0), params, sd + ea))
        rp = U8(1, 1 if ext else 0) + U16(fid + 2 + ext) + U32(1, 0) + U64(NT, NT, NT, NT) + U32(0x80) + U64(4096, 100) + U16(0, 0) + U8(0)
        if ext:
            rp += b'\x22' * 16 + U64(0x4321) + U32(0x1f01ff, 0x120089)
        c.send(False, nt_resp(c, 1, U16(0), rp, b''))
    # IOCTL / FSCTL
    for fn, data, rdata in ((0x900a8, b'', bytes(24)), (0x98000, b'', b''), (0x60194, U16(3) + 'x'.encode('utf-16le') + b'\0\0', bytes(8)),
                            (0x900c0, b'', b'')):
        for isfs in (1, 0):
            c.nextmid()
            c.send(True, nt_req(c, 2, U32(fn) + U16(fid) + U8(isfs, 1), b'', data))
            c.send(False, nt_resp(c, 2, U16(len(rdata)), b'ioc!', rdata))
    # SET_SECURITY_DESC on a file and on a directory
    for f in (fid, fid + 1):
        c.nextmid()
        c.send(True, nt_req(c, 3, U16(0), U16(f, 0) + U32(7), sd))
        c.send(False, nt_resp(c, 3, U16(0), b'ssd!', b''))
        c.nextmid()
        c.send(True, nt_req(c, 6, U16(0), U16(f, 0) + U32(7), b''))
        c.send(False, nt_resp(c, 6, U16(0), U32(len(sd)), sd))
    # security descriptor calls on a FID never seen
    c.nextmid()
    c.send(True, nt_req(c, 3, b'', U16(0x7fff, 0) + U32(7), sd))
    c.send(False, nt_resp(c, 3, b'', b'', b''))
    c.nextmid()
    c.send(True, nt_req(c, 6, b'', U16(0x7fff, 0) + U32(7), b''))
    c.send(False, nt_resp(c, 6, b'', U32(len(sd)), sd))
    # NOTIFY_CHANGE (request, response with entries)
    c.nextmid()
    c.send(True, nt_req(c, 4, U32(0x17f) + U16(fid + 1) + U8(1, 0), b'nt', b''))
    ent = lambda nxt, act, n: U32(nxt, act, len(n)) + n
    n1, n2 = ustr(c, 'a.txt'), ustr(c, 'bb.txt')
    e1 = ent(0, 1, n1)
    e1 += b'\0' * ((-len(e1)) % 4)
    e1 = U32(len(e1)) + e1[4:]
    rp = e1 + ent(0, 4, n2)
    c.send(False, nt_resp(c, 4, U16(0), rp, b''))
    # a second notify answered with a zero next offset and padding oddities
    c.nextmid()
    c.send(True, nt_req(c, 4, U32(0x1) + U16(fid + 1) + U8(0, 0), b'', b''))
    c.send(False, nt_resp(c, 4, b'', ent(0, 3, n1) + b'\0\0', b''))
    c.nextmid()
    c.send(True, nt_req(c, 4, U32(0x1) + U16(fid + 1) + U8(0, 0), b'', b''))
    c.send(False, nt_resp(c, 4, b'', b'', b'', status=0x0000010c))
    # RENAME (undocumented), quota get/set
    c.nextmid()
    c.send(True, nt_req(c, 5, U16(1), b'abcd', b'efgh'))
    c.send(False, nt_resp(c, 5, U16(1), b'ren!', b'rdata'))
    qs = sid(5, (21, 1, 2, 3, 500))
    c.nextmid()
    c.send(True, nt_req(c, 7, U16(0), U16(fid, 1) + U32(0, 0, 0)[:8], U32(0, len(qs)) + qs))
    q1 = U32(0, len(qs)) + T8 + U64(100, 200, 300) + qs
    c.send(False, nt_resp(c, 7, U16(0), U32(len(q1)), q1))
    c.nextmid()
    q2 = U32(len(q1) + 0, len(qs)) + T8 + U64(100, 200, 300) + qs
    c.send(True, nt_req(c, 8, U16(0), U16(fid, 0), q1 + b'\0' * 8))
    c.send(False, nt_resp(c, 8, U16(0), b'sq!!', b''))
    # NT Transact response without its request
    c.send(False, nt_resp(c, 6, U16(0), U32(len(sd)), sd, mid=0x6666))
    c.send(False, nt_resp(c, 2, U16(8), b'pp', b'dd', mid=0x6667))
    # unknown NT Transact function
    c.nextmid()
    c.send(True, nt_req(c, 99, U16(1), b'pp', b'dd'))
    c.send(False, nt_resp(c, 99, U16(1), b'pp', b'dd'))
    # multi-part NT Transact (set security descriptor) with secondaries
    c.nextmid()
    sdp = sd + bytes(64)
    c.send(True, nt_req(c, 3, b'', U16(fid, 0) + U32(7), sdp[:len(sd) + 8], tdc=len(sdp)))
    c.send(False, c.hdr(0xa0, True) + b'\0' + U16(0))
    c.send(True, nt_sec(c, 6, len(sdp), b'', 0, sdp[len(sd) + 8:], len(sd) + 8))
    c.send(False, nt_resp(c, 3, b'', b'', b''))
    # multi-part NT Transact response (query security descriptor)
    c.nextmid()
    c.send(True, nt_req(c, 6, b'', U16(fid, 0) + U32(7), b''))
    sdp = sd + bytes(64)
    c.send(False, nt_resp(c, 6, b'', U32(len(sd)), sdp[:len(sd) + 4], tdc=len(sdp), tpc=4))
    c.send(False, nt_resp(c, 6, b'', b'', sdp[len(sd) + 4:], tdc=len(sdp), tpc=4, dd=len(sd) + 4))
    # NT Cancel for an outstanding request, then its response with an error
    c.nextmid()
    mid = c.mid
    c.send(True, nt_req(c, 4, U32(0x1) + U16(fid + 1) + U8(0, 0), b'', b''))
    c.send(True, c.smb(0xa4, False, b'', b'', mid=mid))
    c.send(False, nt_resp(c, 4, b'', b'', b'', status=0xc0000120))


def ntlmssp_negotiate():
    # NEGOTIATE_MESSAGE without domain/workstation (message framing only)
    return b'NTLMSSP\0' + U32(1, 0xe2088297) + U16(0, 0) + U32(0) + U16(0, 0) + U32(0) + bytes(8)


def ntlmssp_challenge_shell(c):
    # CHALLENGE_MESSAGE shell: the 8 byte server challenge field is zero
    tn = 'SRV'.encode('utf-16le')
    return (b'NTLMSSP\0' + U32(2) + U16(len(tn), len(tn)) + U32(56) + U32(0xe2898215) + bytes(8) + bytes(8) +
            U16(0, 0) + U32(56 + len(tn)) + bytes(8) + tn)


def nbss_conn(c139):
    pass


def session_variants(cap):
    # ---- A: old dialects, Core / LANMAN, ASCII, port 139 with NBSS session setup ----
    c = Conn(cap, 40011, 139)
    pad = b'\x20' + b'EOEDFEEECACACACACACACACACACACACA' + b'\0'
    called = pad
    c.tcp(True, struct.pack('!BBH', 0x81, 0, 68) + called + b'\x20' + b'FEEFFEEFEEEFEEEFEEEFEEEFEEEFEEEF'[:32] + b'\0')
    c.tcp(False, struct.pack('!BBH', 0x82, 0, 0))
    c.tcp(True, struct.pack('!BBH', 0x85, 0, 0))
    c.tcp(False, struct.pack('!BBH', 0x85, 0, 0))
    c.nextmid()
    c.send(True, c.smb(0x72, False, b'', [b'\x02PC NETWORK PROGRAM 1.0\0', b'\x02MICROSOFT NETWORKS 3.0\0', b'\x02LANMAN1.0\0', b'\x02LM1.2X002\0']))
    # LANMAN dialect: wc=13, user level security with challenge
    w = U16(3, 3, 4096, 50, 1, 1) + U32(0xabcd) + U16(0x1234, 0x2345) + U16(0, 8, 0)
    # wc=13: dialect, secmode, maxbuf, maxmpx, maxvcs, rawmode, sesskey(4), time, date, tz, challenge len, reserved(2) -> 2+2*5+4+2*2+... fix below
    w = U16(3, 3, 4096, 50, 1, 1) + U32(0xabcd) + U16(0x2345, 0x1234, 0) + U16(8, 0)
    assert len(w) == 26, len(w)
    c.send(False, c.smb(0x72, True, w, bytes(8) + b'WORKGROUP\0'))
    # share-level security, no challenge, dialect index out of range
    c.nextmid()
    c.send(True, c.smb(0x72, False, b'', [b'\x02PC NETWORK PROGRAM 1.0\0']))
    c.send(False, c.smb(0x72, True, U16(5), b''))
    # Core protocol selected: wc=1
    c.nextmid()
    c.send(True, c.smb(0x72, False, b'', [b'\x02PC NETWORK PROGRAM 1.0\0']))
    c.send(False, c.smb(0x72, True, U16(0), b''))
    # no dialect chosen (0xffff) and an odd word count
    c.nextmid()
    c.send(True, c.smb(0x72, False, b'', [b'\x02XENIX CORE\0']))
    c.send(False, c.smb(0x72, True, U16(0xffff), b''))
    c.nextmid()
    c.send(True, c.smb(0x72, False, b'', [b'\x02XENIX CORE\0']))
    c.send(False, c.smb(0x72, True, U16(0) + U16(1, 2), b'', wc=3))
    c.nextmid()
    c.send(True, c.smb(0x72, False, b'', [b'\x02XENIX CORE\0']))
    c.send(False, c.smb(0x72, True, b'', b'', wc=0))
    # Session Setup AndX LANMAN (wc=10): password of 0 length, then with a password length field
    c.nextmid()
    w = U8(0xff, 0) + U16(0) + U16(4096, 50, 1) + U32(0xabcd) + U16(0) + U32(0)
    assert len(w) == 20
    c.send(True, c.smb(0x73, False, w, ['jdoe', 'WORKGROUP', 'Unix', 'LANMAN'], uid=0))
    c.send(False, c.smb(0x73, True, U8(0xff, 0) + U16(0, 0), ['Unix', 'Samba', 'WORKGROUP']))
    # Tree Connect (core 0x70) with password and service; old style responses
    c.nextmid()
    c.send(True, c.smb(0x70, False, b'', [B4, r'\\SRV\SHARE', B4, 'secret', B4, 'A:']))
    c.send(False, c.smb(0x70, True, U16(4096, 7), b'', tid=7))
    c.tid = 7
    # file ops on the core tree
    c.rr(0x08, qdata=[B4, r'\f'], rwords=U16(0x20) + U32(1700000000, 12345) + bytes(10))
    c.nextmid()
    c.send(True, c.smb(0x71, False))
    c.send(False, c.smb(0x71, True))
    # DOS-style error responses (no NT status)
    c.tid = 7
    c.nextmid()
    c.send(True, c.smb(0x08, False, b'', [B4, r'\missing'], flags2=0x0001))
    c.send(False, c.smb(0x08, True, b'', b'', flags2=0x0001, ecls=1, status=2))
    c.nextmid()
    c.send(True, c.smb(0x06, False, U16(0x16), [B4, r'\missing'], flags2=0x0001))
    c.send(False, c.smb(0x06, True, b'', b'', flags2=0x0001, ecls=2, status=0xffff))
    c.nextmid()
    c.send(True, c.smb(0x06, False, U16(0x16), [B4, r'\missing'], flags2=0x0001))
    c.send(False, c.smb(0x06, True, b'', b'', flags2=0x0001, ecls=3, status=1))
    c.nextmid()
    c.send(True, c.smb(0x06, False, U16(0x16), [B4, r'\missing'], flags2=0x0001))
    c.send(False, c.smb(0x06, True, b'', b'', flags2=0x0001, ecls=0xff, status=1))
    # NT status errors
    for st in (0xc0000034, 0xc000006d, 0x80000005, 0x00000103, 0xc0000016, 0xdeadbeef):
        c.nextmid()
        c.send(True, c.smb(0x08, False, b'', [B4, r'\missing']))
        c.send(False, c.smb(0x08, True, b'', b'', status=st))
    # core raw / mpx commands
    fid = 0x4100
    c.rr(0x02, qwords=U16(0x42, 0x16), qdata=[B4, r'\raw'], rwords=U16(fid, 0x20) + U32(1700000000, 12345) + U16(2))
    c.rr(0x1a, qwords=U16(fid) + U32(0) + U16(1024, 0) + U32(0) + U16(0))
    c.rr(0x1a, qwords=U16(fid) + U32(0) + U16(1024, 0) + U32(0) + U16(0) + U32(0))
    c.rr(0x1b, qwords=U16(fid) + U32(0) + U16(100, 0) + bytes(6),
         rwords=U32(0) + U16(10, 0, 0, 0, 10, 32 + 1 + 16 + 2 + 1), rdata=b'\0' + b'0123456789')
    c.rr(0x1d, qwords=U16(fid, 100, 0) + U32(0, 1000) + U16(0x0001) + U32(0) + U16(10, 32 + 1 + 24 + 2 + 1), qdata=b'\0' + b'0123456789',
         rwords=U16(10))
    c.rr(0x1e, qwords=U16(fid, 100, 0) + U32(0, 1000) + U16(0x0003) + U32(0x1) + U16(10, 32 + 1 + 24 + 2 + 1), qdata=b'\0' + b'0123456789',
         rwords=U32(1))
    c.send(True, c.smb(0x1c, False))
    c.send(True, c.smb(0x1f, False))
    c.send(False, c.smb(0x20, True, U16(10)))
    c.send(True, c.smb(0x27, False))
    c.send(True, c.smb(0x28, False))
    c.send(True, c.smb(0x21, False))
    c.send(True, c.smb(0x15, False))
    c.send(True, c.smb(0xd8, False))
    c.send(True, c.smb(0xd9, False))
    c.send(True, c.smb(0xda, False))
    c.send(True, c.smb(0x9a, False, U16(1), b'ab'))
    c.send(False, c.smb(0x9a, True, U16(1), b'ab'))
    # Close and logoff with a keep alive and session message
    c.tcp(True, struct.pack('!BBH', 0x00, 0, 0))

    # ---- B: NT LM 0.12 without extended security, NTLM wc=13 session setup ----
    c = Conn(cap, 40012, 445, uni=True)
    session_setup_nt(c, False)
    zero24 = bytes(24)
    v2 = bytes(16) + U32(0x0101) + U32(0) + T8 + bytes(8) + U32(0) + U16(2, 8) + 'DOM'.encode('utf-16le')[:6] + U16(0, 0) + U32(0)
    for lm, nt_, acct in ((zero24, zero24, 'user'), (b'', b'', ''), (zero24, bytes(16) + v2[16:], 'user2')):
        c.nextmid()
        w = U8(0xff, 0) + U16(0) + U16(16644, 50, 1) + U32(0xabcd) + U16(len(lm), len(nt_)) + U32(0) + U32(0x80d4)
        c.send(True, c.smb(0x73, False, w, [lm, nt_, acct, 'DOM', 'Windows 2000 2195', 'Windows 2000 5.0'], uid=0))
        c.send(False, c.smb(0x73, True, U8(0xff, 0) + U16(0, 1), ['Windows 2000 2195', 'Windows 2000 5.0', 'DOM']))
    c.nextmid()
    c.send(True, tcx_req(c, r'\\SRV\SHARE', 'A:', pw=b'\0\0'))
    c.send(False, tcx_resp(c, 3, 'A:', 'NTFS'))
    c.tid = 3
    c.rr(0x08, qdata=[B4, r'\f'], rwords=U16(0x20) + U32(1700000000, 12345) + bytes(10))
    # tree connect AndX response in wc=3 form (no access rights), flags
    c.nextmid()
    c.send(True, tcx_req(c, r'\\SRV\PRINT', 'LPT1:', flags=0x0001, pw=b'\0\0'))
    c.send(False, c.smb(0x75, True, U8(0xff, 0) + U16(0, 0), [b'LPT1:\0', ''], tid=4))
    c.nextmid()
    c.send(True, tcx_req(c, r'\\SRV\COMM', 'COMM', flags=0x0004, pw=b'\0\0'))
    c.send(False, c.smb(0x75, True, U8(0xff, 0) + U16(0, 0x0010 | 0x000c), [b'COMM\0', 'NTFS'], tid=5))
    c.nextmid()
    c.send(True, c.smb(0x71, False, tid=4))
    c.send(False, c.smb(0x71, True, tid=4))
    c.rr(0x74, qwords=U8(0xff, 0) + U16(0), rwords=U8(0xff, 0) + U16(0))

    # ---- D: extended security with a SPNEGO negTokenInit in the negotiate response ----
    c = Conn(cap, 40014, 445, uni=True)
    session_setup_nt(c, 'spnego')
    c.nextmid()
    c.send(True, ss_andx_req(c, True, blob=spnego_init()))
    c.send(False, ss_andx_resp(c, True, blob=spnego_init(), status=0xc0000016, action=0))

    # ---- C: extended security ----
    c = Conn(cap, 40013, 445, uni=True)
    session_setup_nt(c, True)
    c.nextmid()
    c.send(True, ss_andx_req(c, True, blob=ntlmssp_negotiate()))
    c.send(False, ss_andx_resp(c, True, blob=ntlmssp_challenge_shell(c), status=0xc0000016, action=0))
    c.nextmid()
    # chained Session Setup AndX -> Tree Connect AndX -> Open AndX
    ssw = U8(0xff, 0) + U16(0) + U16(16644, 50, 1) + U32(0xabcd) + U16(0) + U32(0) + U32(0x800000d4)
    tcw = U8(0xff, 0) + U16(0, 8, 1)
    c.send(True, chain(c, False, [(0x73, ssw, [b'', 'Unix', 'Samba']), (0x75, tcw, [b'\0', r'\\SRV\SHARE', 'A:'])], uid=0))
    c.send(False, chain(c, True, [(0x73, U8(0xff, 0) + U16(0, 1, 0), ['Unix', 'Samba']),
                                  (0x75, U8(0xff, 0) + U16(0, 1) + U32(0x1f01ff, 0x1f01ff), [b'A:\0', 'NTFS'])]))
    # Session Setup AndX request with ext security length larger than the data (kept short but valid)
    c.nextmid()
    c.send(True, c.smb(0x72, False, b'', [b'\x02NT LM 0.12\0']))
    w = U16(0) + U8(3) + U16(50, 1) + U32(16644, 65536, 0xabcd, 0x8000e3fd) + U64(NT) + U16(0) + U8(0)
    c.send(False, c.smb(0x72, True, w, bytes(range(16)), wc=17) )
    # unicode flags with odd offset names, DOS-error replies
    c.rr(0x08, qdata=[B4, r'\u'], rwords=U16(0x20) + U32(1700000000, 12345) + bytes(10))


# ==== separate-capture scenarios: SMB over other transports =================


def hdr_conn(cap, uni=False):
    """A Conn used only to build SMB headers (no TCP handshake)."""
    c = Conn.__new__(Conn)
    c.cap, c.cport, c.sport = cap, 0, 0
    c.seq = {True: 0, False: 0}
    c.mid, c.uni, c.uid, c.pid, c.tid = 0, uni, 0x0800, 0x1234, 1
    c.flags2 = 0xc001 if uni else 0x4001
    c.ipid = 1
    return c


def eth_frame(cap, dst, src, etype, payload):
    cap.raw(dst + src + struct.pack('!H', etype) + payload)


def ipx_pkt(dsock, ssock, data, to_server=True):
    n_c = bytes.fromhex('00000001')
    n_s = bytes.fromhex('00000002')
    dnet, snet = (n_s, n_c) if to_server else (n_c, n_s)
    dn, sn = (MAC_S, MAC_C) if to_server else (MAC_C, MAC_S)
    ln = 30 + len(data)
    return (struct.pack('!HHBB', 0xffff, ln, 0, 4) + dnet + dn + struct.pack('!H', dsock) +
            snet + sn + struct.pack('!H', ssock) + data)


def nb_name(name, typ=0x20):
    n = name.ljust(15)[:15].encode() + bytes([typ])
    return b'\x20' + bytes(0 for b in b'')[:0] + bytes(sum(([65 + (b >> 4), 65 + (b & 15)] for b in n), [])) + b'\0'


def other_transports(cap):
    c = hdr_conn(cap)
    # SMB over IPX: server, redirector and messenger sockets
    for sock, cmd, rep in ((0x0550, 0x2b, False), (0x0552, 0x2b, True), (0x0554, 0xd0, False)):
        c.mid += 1
        if cmd == 0x2b:
            pdu = c.smb(0x2b, rep, U16(1), b'echo')
        else:
            pdu = c.smb(0xd0, False, b'', [B4, 'from', B4, 'to', b'\x01', U16(5), b'hello'])
        eth_frame(cap, MAC_S if not rep else MAC_C, MAC_C if not rep else MAC_S, 0x8137,
                  ipx_pkt(sock, 0x4000, pdu, not rep))
    # SMB over TPKT/COTP on TCP 102 (the cotp heuristic)
    t = Conn(cap, 40021, 102)
    for to_server in (True, False):
        c.mid += 1
        pdu = c.smb(0x2b, not to_server, U16(1), b'echo')
        data = b'\x02\xf0\x80' + pdu
        t.tcp(to_server, struct.pack('!BBH', 3, 0, 4 + len(data)) + data)
    # NetBIOS datagram (UDP 138) carrying a mailslot write (broadcast style)
    ms = trans_req(c, 0x25, U16(1, 0, 2), b'', U8(1, 0) + U32(0) + U16(0) + b'HOST1\0\0\0\0\0\0\0\0\0\0\0\0' + bytes(16),
                   name=r'\MAILSLOT\BROWSE', flags=2, mid=0, pid=0, uid=0, tid=0)
    nbds = struct.pack('!BBH4sHHH', 0x11, 0x0a, 0x1234, IP_C, 138, 14 + 68 + len(ms) - 14 + 0, 0)
    nbds = struct.pack('!BBH', 0x11, 0x02, 0x1234) + IP_C + struct.pack('!HHH', 138, 68 + len(ms), 0) + nb_name('HOST1', 0) + nb_name('WORKGROUP', 0x1d) + ms
    udp = struct.pack('!HHHH', 138, 138, 8 + len(nbds), 0) + nbds
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 5, 0x4000, 64, 17, 0, IP_C, IP_S)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth_frame(cap, MAC_S, MAC_C, 0x0800, ip + udp)


def eo_files(c):
    """Writes and reads that build files for Export Objects (chunk handling)."""
    def create(name, fid, eof):
        c.nextmid()
        w = U8(0xff, 0) + U16(0) + U8(0) + U16(len(name) + 1) + U32(0x16, 0, 0x12019f) + U64(0) + U32(0x80, 3, 1, 0x40, 2) + U8(0)
        c.send(True, c.smb(0xa2, False, w, [name]))
        w = U8(0xff, 0) + U16(0) + U8(1) + U16(fid) + U32(1) + U64(NT, NT, NT, NT) + U32(0x80) + U64(4096, eof) + U16(0, 0) + U8(0)
        c.send(False, c.smb(0xa2, True, w, b''))

    def wx(fid, off, data, tid=None):
        c.nextmid()
        kw = {} if tid is None else {'tid': tid}
        w = U8(0xff, 0) + U16(0) + U16(fid) + U32(off & 0xffffffff, 0) + U16(0, 0, 0, len(data), 64) + U32(off >> 32)
        c.send(True, c.smb(0x2f, False, w, b'\0' + data, **kw))
        c.send(False, c.smb(0x2f, True, U8(0xff, 0) + U16(0, len(data) & 0xffff, 0, 0, 0), b'', **kw))

    def rx(fid, off, data, tid=None):
        c.nextmid()
        kw = {} if tid is None else {'tid': tid}
        w = U8(0xff, 0) + U16(0) + U16(fid) + U32(off & 0xffffffff) + U16(len(data), len(data)) + U32(0) + U16(0) + U32(off >> 32)
        c.send(True, c.smb(0x2e, False, w, b'', **kw))
        w = U8(0xff, 0) + U16(0) + U16(0, 0, 0, len(data), 32 + 1 + 24 + 2 + 1) + U32(0) + bytes(6)
        c.send(False, c.smb(0x2e, True, w, b'\0' + data, **kw))

    f = 0x7300
    create(r'\export\big.bin', f, 1000)
    wx(f, 0, b'A' * 100)            # start of the first free chunk
    wx(f, 400, b'B' * 100)          # inside: splits the free chunk
    wx(f, 350, b'C' * 100)          # overlaps the end of a free chunk
    wx(f, 100, b'D' * 250)          # covers a free chunk exactly (first in list)
    wx(f, 500, b'E' * 100)          # start of the last free chunk
    rx(f, 600, b'F' * 400)          # read response: removes the last free chunk
    wx(f, 1500, b'G' * 100)         # beyond the file length: new free chunk, bigger buffer
    wx(f, 1000, b'')                # empty chunk
    wx(f, 1200, b'H' * 50)          # inside the new free chunk
    wx(f, 1250, b'I' * 250)         # adjacent, shrinks from the start
    wx(f, 0, b'J' * 1600)           # covers everything
    # a second file with the removal of a middle free chunk
    f = 0x7301
    create(r'\export\mid.bin', f, 900)
    wx(f, 0, b'a' * 100)
    wx(f, 200, b'b' * 100)
    wx(f, 400, b'c' * 100)
    wx(f, 600, b'd' * 100)
    wx(f, 150, b'e' * 400)          # removes middle free chunks, prev set
    # offsets beyond what can be held in memory (4 GiB and an overflowing sum)
    f = 0x7302
    create(r'\export\huge.bin', f, 0)
    wx(f, 0x1_0000_0000, b'x' * 20)
    f = 0x7303
    create(r'\export\wrap.bin', f, 0)
    wx(f, 0xffff_ffff_ffff_ff00, b'y' * 0x200)
    # a file written through a TID that was never connected, and a read on an unknown FID
    wx(0x7304, 0, b'z' * 10, tid=0x0123)
    rx(0x7305, 0, b'w' * 10, tid=0x0124)
    # a directory FID that must not be exported
    nt_create(c, r'\export\dir', 0x7306, isdir=1)
    wx(0x7306, 0, b'q' * 10)


def misc_variants(cap):
    # ---- E: negotiate responses without a request, LANMAN 1.0 and padding variants ----
    c = Conn(cap, 40015, 445, uni=True)
    c.nextmid()
    w = U16(1, 3, 4096, 50, 1, 1) + U32(0xabcd) + U16(0x2345, 0x1234, 0) + U16(0, 0)
    c.send(False, c.smb(0x72, True, w, bytes(8) + b'WORKGROUP\0', mid=1))      # chl = 0, challenge in the byte count
    c.nextmid()
    w = U16(1) + U8(1) + U16(50, 1) + U32(16644, 65536, 0xabcd, 0x0000e3fd) + U64(NT) + U16(0) + U8(8)
    c.send(False, c.smb(0x72, True, w, bytes(8) + b'\0' + 'WORKGROUP'.encode('utf-16le') + b'\0\0' + 'SRV'.encode('utf-16le') + b'\0\0', mid=2))
    c.nextmid()
    w = U16(20) + U8(1) + U16(50, 1) + U32(16644, 65536, 0xabcd, 0x0000e3fd) + U64(NT) + U16(0) + U8(8)
    c.send(False, c.smb(0x72, True, w, bytes(8), mid=3))                       # dialect index out of range, no domain
    # ---- F: several SMBs in one TCP segment ----
    c = Conn(cap, 40016, 445)
    session_setup_nt(c, False)
    mids = [c.nextmid() for _ in range(4)]
    reqs = [c.smb(0x2b, False, U16(1), b'one', mid=mids[0]),
            trans_req(c, 0x32, U16(3), U16(0x103), b'', mid=mids[1]),
            c.smb(0x08, False, b'', [B4, r'\x'], mid=mids[2]),
            trans_req(c, 0x32, U16(5), U16(0x107) + U32(0) + b'\\y\0', b'', mid=mids[3])]
    c.send(True, *reqs)
    resps = [c.smb(0x2b, True, U16(1), b'one', mid=mids[0]),
             trans_resp(c, 0x32, b'', b'', U64(1000, 500) + U32(8, 512), mid=mids[1]),
             c.smb(0x08, True, U16(0x20) + U32(1700000000, 12345) + bytes(10), b'', mid=mids[2]),
             trans_resp(c, 0x32, b'', U16(0), BASIC, mid=mids[3])]
    c.send(False, *resps)
    # a Transaction2 that opens the batch (first PDU of the segment is a Trans2)
    mids = [c.nextmid() for _ in range(2)]
    c.send(True, trans_req(c, 0x32, U16(3), U16(0x103), b'', mid=mids[0]), c.smb(0x2b, False, U16(1), b'two', mid=mids[1]))
    c.send(False, trans_resp(c, 0x32, b'', b'', U64(1000, 500) + U32(8, 512), mid=mids[0]), c.smb(0x2b, True, U16(1), b'two', mid=mids[1]))
    # a TCP segment that holds an SMB with trailing bytes after the NBSS PDU
    c.nextmid()
    c.send(True, c.smb(0x2b, False, U16(1), b'tail') )
    # retransmission of a request with the same MID before the response
    c.nextmid()
    q = c.smb(0x08, False, b'', [B4, r'\dup'])
    c.send(True, q)
    c.send(True, q)
    c.send(False, c.smb(0x08, True, U16(0x20) + U32(1700000000, 12345) + bytes(10), b''))
    # response with a command that differs from the outstanding request's command
    c.nextmid()
    c.send(True, c.smb(0x08, False, b'', [B4, r'\dup']))
    c.send(False, c.smb(0x2b, True, U16(1), b'x'))
    # second response to a request already answered
    c.send(False, c.smb(0x2b, True, U16(1), b'x'))


def repro_frames(cap):
    """The reproducers of the bugs fixed by 'SMB: Fix NT Create AndX, two-pass state
    and quadratic FID lookups' that decode cleanly."""
    # -- TID table: an unmapped TID must not take over another share's name, and a re-used
    #    TID must not change the earlier frames (wmem_tree_lookup32_le / replaced entry).
    c = Conn(cap, 40031)
    c.tid = 0
    c.nextmid()
    c.send(True, tcx_req(c, r'\\SRV\SHAREA'))
    c.send(False, c.smb(0x75, True, U8(0xff, 0) + U16(0, 1) + U32(0x1f01ff, 0), [b'A:\0', 'NTFS'], tid=0x0800))
    c.nextmid()
    c.send(True, c.smb(0x2b, False, U16(1), b'', tid=0x0805))
    c.send(False, c.smb(0x2b, True, U16(1), b'', tid=0x0805))
    c.nextmid()
    c.send(True, c.smb(0x2b, False, U16(1), b'', tid=0x0800))
    c.send(False, c.smb(0x2b, True, U16(1), b'', tid=0x0800))
    c.nextmid()
    c.send(True, tcx_req(c, r'\\SRV\SHAREB'))
    c.send(False, c.smb(0x75, True, U8(0xff, 0) + U16(0, 1) + U32(0x1f01ff, 0), [b'A:\0', 'NTFS'], tid=0x0800))
    c.nextmid()
    c.send(True, c.smb(0x2b, False, U16(1), b'', tid=0x0800))
    c.send(False, c.smb(0x2b, True, U16(1), b'', tid=0x0800))
    # -- Create New response without its request (FID with no request info)
    c.send(False, c.smb(0x0f, True, U16(0x4001), b'', tid=0x0800, mid=77))
    c.send(False, c.smb(0x0a, True, U16(4) + bytes(8), [b'\x01', U16(4), b'data'], tid=0x0800, mid=78))
    # -- NT Create AndX with the extended response (wc 42): plain and followed by an AndX Close-style command
    def nc_req(mid, name):
        w = U8(0xff, 0) + U16(0) + U8(0) + U16(len(name)) + U32(0x16, 0, 0x12019f) + U64(0) + U32(0x80, 3, 1, 0x40, 2) + U8(0)
        return c.smb(0xa2, False, w, [name], tid=0x0800, mid=mid)

    def nc_resp(mid, fid, andx=0xff, andxoff=0, tail=b''):
        w = U8(andx, 0) + U16(andxoff) + U8(1) + U16(fid) + U32(1) + U64(NT, NT, NT, NT) + U32(0x80) + U64(4096, 100) + U16(0, 0) + U8(0)
        w += b'\x11' * 16 + U64(0x1234) + U32(0x1f01ff, 0x120089)
        return c.smb(0xa2, True, w, b'', wc=42, tid=0x0800, mid=mid) + tail
    c.send(True, nc_req(91, 'dir\\file.txt\0'))
    c.send(False, nc_resp(91, 0x4a01))
    first = nc_resp(92, 0x4a02)
    c.send(True, nc_req(92, 'other.txt\0'))
    c.send(False, nc_resp(92, 0x4a02, andx=0x04, andxoff=len(first), tail=b'\0' + U16(0)))
    # -- Trans2 request matched through the primaries table: request, interim, secondary, final response
    c.nextmid()
    c.send(True, trans_req(c, 0x32, U16(3), U16(0x103), b'', tid=0x0800))
    c.send(False, interim(c, 0x32, tid=0x0800))
    c.send(True, trans_sec(c, 0x33, 2, 0, b'', 0, b'', 0, tid=0x0800))
    c.send(False, trans_resp(c, 0x32, b'', b'', U64(1000, 500) + U32(8, 512), tid=0x0800))
    # -- Two SMBs in one TCP segment, the first a Trans2 with more data to follow
    m1, m2 = c.nextmid(), c.nextmid()
    r1 = trans_req(c, 0x32, U16(8), U16(0x1234, 0x0102) + b'\0\0', b'\x01' * 10, tdc=100, mid=m1, tid=0x0800)
    r2 = trans_req(c, 0x32, U16(3), U16(0x0103), b'', mid=m2, tid=0x0800)
    c.send(True, r1, r2)
    # -- Mac QUERY_FS_INFO: the Backup Time must advance the offset
    c.nextmid()
    c.send(True, trans_req(c, 0x32, U16(3), U16(0x0301), b'', tid=0x0800))
    d = U64(NT + 1, NT + 2, NT + 3) + U32(0x11111111, 0x22222222, 0x33333333) + b'F' * 32 + U32(0x44, 0x55, 0x66, 0x77, 0x1f)
    c.send(False, trans_resp(c, 0x32, b'', b'', d, tid=0x0800))


@scenario
def sc_malformed(outdir):
    """Paths only malformed input reaches; not added to the tree."""
    cap = Cap(os.path.join(outdir, 'smb-coverage-malformed.pcap'))
    CAPS['malformed'] = cap
    recorded = CAPS['main'].record
    CAPS['main'].record = None
    # --- 1. every PDU of the main capture, truncated, with a huge byte count and with a wrong word count
    c = Conn(cap, 41001)
    for to_server, pdu in recorded:
        if len(pdu) < 36:
            continue
        wc = pdu[32]
        muts = [pdu[:max(33, len(pdu) * 2 // 3)]]
        if 33 + 2 * wc + 2 <= len(pdu):
            muts.append(pdu[:33 + 2 * wc] + b'\xff\xff' + pdu[33 + 2 * wc + 2:])
        if wc < 255:
            muts.append(pdu[:32] + bytes([wc + 1]) + pdu[33:])
        for m in muts:
            c.send(to_server, m)
    # --- 2. hand made cases
    c = Conn(cap, 41002)
    session_setup_nt(c, False)
    # Trans2 secondary with data count + displacement larger than the total data count
    # (the bytes-until-total-data-count counter used to wrap)
    c.nextmid()
    c.send(True, trans_req(c, 0x32, U16(8), U16(0x1234, 0x0102) + b'\0\0', b'\x01' * 10, tdc=100))
    c.send(False, interim(c, 0x32))
    c.send(True, trans_sec(c, 0x33, 6, 100, b'', 0, b'B' * 10, 95, fid=0x1234))
    # secondary requests without a primary, with a wrong word count and for all three commands
    c.send(True, c.smb(0x26, False, U16(1)))
    c.send(True, c.smb(0x33, False, U16(1, 2, 3)))
    c.send(True, nt_sec(c, 4, 4, b'ab', 0, b'cd', 0, mid=0x5151))
    c.send(True, trans_sec(c, 0x26, 2, 2, b'ab', 0, b'cd', 0, mid=0x5152))
    # unknown POSIX ACE type and an ACL with a count larger than the data
    c.nextmid()
    c.send(True, trans_req(c, 0x32, U16(5), U16(0x204) + U32(0) + b'\\x\0', b''))
    c.send(False, trans_resp(c, 0x32, b'', U16(0), U16(1, 3, 0) + U8(0x77, 7) + U64(1)))
    c.nextmid()
    c.send(True, trans_req(c, 0x32, U16(5), U16(0x204) + U32(0) + b'\\x\0', b''))
    c.send(False, trans_resp(c, 0x32, b'', U16(0), U16(1, 60000, 0) + U8(1, 7) + U64(1)))
    # FIND_FIRST2 whose entries make no progress (unknown level and an empty names entry)
    for lvl in (0x103, 0x101, 1):
        c.nextmid()
        c.send(True, trans_req(c, 0x32, U16(1), U16(0x16, 100, 0, lvl) + U32(0) + b'\\*\0', b''))
        c.send(False, trans_resp(c, 0x32, b'', U16(0x40, 1000, 1, 0, 0), bytes(12)))
    # a pipe write with MESSAGE_START and RAW whose byte count is too small for the length prefix
    c.nextmid()
    c.send(True, c.smb(0x2f, False, U8(0xff, 0) + U16(0) + U16(0x1234) + U32(0, 0) + U16(0x000c, 0, 0, 0, 59), b'', tid=9))
    # AndX command chains that point backwards or at themselves
    c.nextmid()
    w = U8(0x2f, 0) + U16(32 + 1)
    w += U16(0x1234) + U32(0, 0) + U16(0, 0, 0, 0, 0)
    c.send(True, c.smb(0x2f, False, w, b''))
    c.nextmid()
    nm = r'\self'
    w = U8(0xa2, 0) + U16(32 + 1) + U8(0) + U16(len(nm) + 1) + U32(0x16, 0, 0x12019f) + U64(0) + U32(0x80, 3, 1, 0x40, 2) + U8(0)
    c.send(True, c.smb(0xa2, False, w, [nm]))
    c.nextmid()
    c.send(True, c.smb(0x73, False, U8(0x75, 0) + U16(5) + U16(16644, 50, 1) + U32(0xabcd) + U16(0, 0) + U32(0) + U32(0xd4), ['', '', '', '']))
    c.nextmid()
    c.send(False, c.smb(0x74, True, U8(0x74, 0) + U16(33), b''))
    c.nextmid()
    c.send(False, c.smb(0x75, True, U8(0x75, 0) + U16(33, 1), [b'A:\0', 'NTFS']))
    c.nextmid()
    c.send(False, c.smb(0x2e, True, U8(0x2e, 0) + U16(33) + U16(0, 0, 0, 0, 0) + U32(0) + bytes(6), b''))
    c.nextmid()
    c.send(False, c.smb(0x2d, True, U8(0x2d, 0) + U16(33) + U16(1, 0x20) + U32(1700000000, 12345) + U16(2, 0, 0, 1) + U32(0) + U16(0), b''))
    c.nextmid()
    c.send(False, c.smb(0x24, True, U8(0x24, 0) + U16(33), b''))
    # a header that is too short, a wrong marker, and an SMB with no words at all
    c.send(True, b'\xffSMB\x72' + bytes(10))
    c.send(True, b'\xffSMX' + bytes(40))
    c.send(True, c.hdr(0x72, False))
    c.send(True, c.hdr(0x2b, False) + b'\x01')
    # DFS referrals whose expanded names point back into the entry itself (bounded size)
    refs = b''.join(U16(3, 18, 0, 2) + U32(0) + U16(0, 0xffff, 2) for _ in range(300))
    c.nextmid()
    c.send(True, trans_req(c, 0x32, U16(0x10), U16(3) + '\\DFS'.encode('utf-16le') + b'\0\0', b'', flags2=0xc001))
    c.send(False, trans_resp(c, 0x32, b'', b'', U16(0, 300, 0, 0) + refs, flags2=0xc001))
    # many Create New responses without requests (the FID table must stay linear)
    batch = []
    for i in range(1500):
        batch.append(c.smb(0x0f, True, U16((i % 0xfffe) + 1), b'', mid=i & 0xffff))
        if len(batch) == 50:
            c.send(False, *batch)
            batch = []
    c.send(False, *batch)
    # many files for Export Objects (the file list walk must stay cheap)
    batch = []
    for i in range(1200):
        w = U16((i % 0xfffe) + 1, 4) + U32(0) + U16(0)
        batch.append(c.smb(0x0b, False, w, [b'\x01', U16(4), b'DATA'], tid=1 + i // 0xfffe, mid=i & 0xffff))
        if len(batch) == 50:
            c.send(True, *batch)
            batch = []
    c.send(True, *batch)
    # an exported file written 4 GiB further on after it exists: a later chunk exports uninitialised memory
    eo_oom(cap)


def extras(cap):
    c = Conn(cap, 40017, 445)
    conn_setup(c, r'\\SRV\SHARE')
    # Tree Disconnect, then use of the unmapped TID
    c.nextmid()
    c.send(True, tcx_req(c, r'\\SRV\TMP'))
    c.send(False, c.smb(0x75, True, U8(0xff, 0) + U16(0, 1) + U32(0x1f01ff, 0), [b'A:\0', 'NTFS'], tid=0x0900))
    c.nextmid()
    c.send(True, c.smb(0x71, False, tid=0x0900))
    c.send(False, c.smb(0x71, True, tid=0x0900))
    c.nextmid()
    c.send(True, c.smb(0x2b, False, U16(1), b'late', tid=0x0900))
    c.send(False, c.smb(0x2b, True, U16(1), b'late', tid=0x0900))
    c.tid = 1
    # one long AndX chain: TCX -> Open -> Read -> Write -> Locking -> Logoff
    c.nextmid()
    nm = r'\dir\chain2.txt'
    tcw = U8(0xff, 0) + U16(0, 8, 1)
    opw = U8(0xff, 0) + U16(0) + U16(7, 0x42, 0x16, 0x20) + U32(1700000000) + U16(0x11) + U32(0, 0, 0)
    rdw = U8(0xff, 0) + U16(0) + U16(0x5a5a) + U32(0) + U16(4, 4) + U32(0) + U16(4)
    wrw = U8(0xff, 0) + U16(0) + U16(0x5a5a) + U32(0, 0) + U16(0, 0, 0, 4, 0)
    lkw = U8(0xff, 0) + U16(0, 0x5a5a) + U8(0, 0) + U32(0xffffffff) + U16(0, 0)
    lgw = U8(0xff, 0) + U16(0)
    c.send(True, chain(c, False, [(0x75, tcw, [b'\0', r'\\SRV\SHARE', 'A:']), (0x2d, opw, [nm]), (0x2e, rdw, b''),
                                  (0x2f, wrw, b'\0abcd'), (0x24, lkw, b''), (0x74, lgw, b'')]))
    c.send(False, chain(c, True, [(0x75, U8(0xff, 0) + U16(0, 1) + U32(0x1f01ff, 0), [b'A:\0', 'NTFS']),
                                  (0x2d, U8(0xff, 0) + U16(0, 0x5a5a, 0x20) + U32(1700000000, 100) + U16(2, 0, 0, 1) + U32(0) + U16(0), b''),
                                  (0x2e, U8(0xff, 0) + U16(0) + U16(0, 0, 0, 4, 0) + U32(0) + bytes(6), b'\0wxyz'),
                                  (0x2f, U8(0xff, 0) + U16(0, 4, 0, 0, 0), b''),
                                  (0x24, U8(0xff, 0) + U16(0), b''), (0x74, U8(0xff, 0) + U16(0), b'')]))
    # times and dates: unspecified, "never", invalid DOS date
    c.rr(0x08, qdata=[B4, r'\t0'], rwords=U16(0x20) + U32(0, 12345) + bytes(10))
    c.rr(0x08, qdata=[B4, r'\tf'], rwords=U16(0x20) + U32(0xffffffff, 12345) + bytes(10))
    c.rr(0x02, qwords=U16(0x42, 0x16), qdata=[B4, r'\t1'], rwords=U16(0x4300, 0x20) + U32(0xffffffff, 12345) + U16(2))
    c.rr(0x03, qwords=U16(0x20) + U32(0), qdata=[B4, r'\t2'], rwords=U16(0x4301))
    c.rr(0x22, qwords=U16(0x4300) + U16(0xffff, 0xffff, 0, 0, 0x0000, 0x0001))
    c.rr(0x22, qwords=U16(0x4300) + U16(0x0000, 0x0000, 0x2d1f, 0xffff, 0x7fff, 0xbf7d))
    c.rr(0x22, qwords=U16(0x4300) + U16(0x1234, 0x0000, 0x0123, 0x0000, 0xf9bf, 0x0000))
    # timeouts of the special values -1, -2 and a reserved negative value
    for tmo in (0xffffffff, 0xfffffffe, 0xfffffff0, 0, 1000):
        c.nextmid()
        c.send(True, trans_req(c, 0x32, U16(3), U16(0x103), b'', timeout=tmo))
        c.send(False, trans_resp(c, 0x32, b'', b'', U64(1000, 500) + U32(8, 512)))
        c.nextmid()
        c.send(True, c.smb(0x24, False, U8(0xff, 0) + U16(0, 0x5a5a) + U8(0, 0) + U32(tmo) + U16(0, 0), b''))
        c.send(False, c.smb(0x24, True, U8(0xff, 0) + U16(0), b''))
    for tmo in (0xffffffff, 0xfffffffe, 0xfffffff0):
        c.rr(0x1a, qwords=U16(0x5a5a) + U32(0) + U16(1024, 0) + U32(tmo) + U16(0))
        c.rr(0x1d, qwords=U16(0x5a5a, 100, 0) + U32(0, tmo) + U16(0x0001) + U32(0) + U16(10, 32 + 1 + 24 + 2 + 1), qdata=b'\0' + b'0123456789', rwords=U16(10))
    # Find with a resume key, FIND_FIRST2 level 3 with resume keys
    key = b'\x01' + b'FILE    TXT' + bytes(9)
    c.rr(0x82, qwords=U16(20, 0x10), qdata=[B4, r'\dir\*', b'\x05', U16(21), key + b'\0' * 0][:2] + [b'\x05', U16(21), b'\0' + b'FILE    TXT' + bytes(9)],
         rwords=U16(1), rdata=[b'\x05', U16(43), bytes(21), b'\x20', U32(1700000000, 5), b'FILE.TXT\0\0\0\0\0'])
    c.rr(0x84, qwords=U16(20, 0x10), qdata=[B4, b'', b'\x05', U16(21), b'\0' + b'FILE    TXT' + bytes(9)],
         rwords=U16(0), rdata=[b'\x05', U16(1), b'\0'])
    flags = 0x0004 | 0x0002
    t2(c, 1, U16(0x16, 100, flags, 3) + U32(0) + ustr(c, r'\dir\*', True), GEALIST, U16(0x61, 1, 1, 0, 0), ff2_data(c, 3, ['x'], True))
    t2(c, 2, U16(0x61, 100, 3) + U32(0x11111111) + U16(flags) + ustr(c, 'x', True), GEALIST, U16(1, 1, 0, 0), ff2_data(c, 3, ['x'], True))
    # Info Standard with an invalid DOS date and time
    d = U32(0x00000000, 0x2d1f1234, 0xffffffff) + U32(100, 4096) + U16(0x20) + U8(1) + b'z\0'
    t2(c, 5, U16(1) + U32(0) + ustr(c, r'\dir\file.txt', True), b'', U16(0), d)
    # a Locking AndX/NT Create AndX that have an AndX chain after them
    c.nextmid()
    nm = r'\dir\chain3.txt'
    ncw = U8(0xff, 0) + U16(0) + U8(0) + U16(len(nm) + 1) + U32(0x16, 0, 0x12019f) + U64(0) + U32(0x80, 7, 1, 0x40, 2) + U8(0)
    c.send(True, chain(c, False, [(0xa2, ncw, [nm]), (0x24, lkw, b'')]))
    c.send(False, chain(c, True, [(0xa2, U8(0xff, 0) + U16(0) + U8(1) + U16(0x5a5b) + U32(1) + U64(NT, NT, NT, NT) + U32(0x80) + U64(4096, 100) + U16(0, 0) + U8(0), b''),
                                  (0x24, U8(0xff, 0) + U16(0), b'')]))


def eo_oom(cap):
    """An existing exported file that is then written 4 GiB further on."""
    c = Conn(cap, 40018)
    conn_setup(c, r'\\SRV\SHARE')
    name = r'\export\grow.bin'
    c.nextmid()
    w = U8(0xff, 0) + U16(0) + U8(0) + U16(len(name) + 1) + U32(0x16, 0, 0x12019f) + U64(0) + U32(0x80, 3, 1, 0x40, 2) + U8(0)
    c.send(True, c.smb(0xa2, False, w, [name]))
    w = U8(0xff, 0) + U16(0) + U8(1) + U16(0x7400) + U32(1) + U64(NT, NT, NT, NT) + U32(0x80) + U64(4096, 0) + U16(0, 0) + U8(0)
    c.send(False, c.smb(0xa2, True, w, b''))
    for off in (0, 0x1_0000_0000, 20):
        c.nextmid()
        w = U8(0xff, 0) + U16(0) + U16(0x7400) + U32(off & 0xffffffff, 0) + U16(0, 0, 0, 10, 64) + U32(off >> 32)
        c.send(True, c.smb(0x2f, False, w, b'\0' + b'x' * 10))
        c.send(False, c.smb(0x2f, True, U8(0xff, 0) + U16(0, 10, 0, 0, 0), b''))


# ==== MAIN ====
def main(outdir):
    for f in SCENARIOS:
        f(outdir)
    for cap in CAPS.values():
        cap.close()


if __name__ == '__main__':
    main(sys.argv[1])
