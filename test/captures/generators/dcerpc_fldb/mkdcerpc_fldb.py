#!/usr/bin/env python3
# Generates test/captures/dcerpc_fldb_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the FLDB DCE/RPC dissector
(packet-dcerpc-fldb.c, DCE/DFS Fileset Location Database, hand-written).

The client calls every opnum (0-28) of the FLDB interface
(4d37f2dd-ed43-0000-02c0-37cf2e000001 version 4.0) and the server
answers each: connection-oriented DCE/RPC over TCP in little and big
endian, and connectionless DCE/RPC over UDP (as DCE/DFS clients use it).
The DCE/RPC heuristics find the PDUs, so no Decode As is needed. Every
packet is built from scratch with struct; no captured traffic is used.

The dissector reads fixed layouts; the stubs follow what it reads (see
README.md), including its gaps (the volume name of a vldbentry is
skipped as 110 octets, GetEntryByName requests start with 4 skipped
octets, GetSiteInfo responses skip 48 octets before the principal).

Usage: mkdcerpc_fldb.py <output directory>

Writes:
  dcerpc_fldb-coverage.pcap            every opnum, every flag bit, a
                                       cell name longer than 114 octets
  dcerpc_fldb-coverage-malformed.pcap  stubs cut short, a principal
                                       name length of 256 or more
"""

import os
import struct
import sys
import uuid

UUID_FLDB = '4d37f2dd-ed43-0000-02c0-37cf2e000001'
VER_FLDB = (4, 0)
UUID_NDR = '8a885d04-1ceb-11c9-9fe8-08002b104860'
UUID_NDR64 = '71710533-beba-4937-8319-b5dbef9ccc36'


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 10, 100000 * (i % 10), len(fr), len(fr)))
            f.write(fr)


class TCP:
    """One TCP connection with a handshake; seq/ack kept per side."""
    def __init__(self, frames, cport, sport=49155,
                 cip=(192, 0, 2, 50), sip=(192, 0, 2, 60)):
        self.frames = frames
        self.c = (bytes(cip), cport, 0x10000000 + cport * 7)
        self.s = (bytes(sip), sport, 0x20000000 + cport * 11)
        self.cseq, self.sseq = self.c[2], self.s[2]
        self.seg(True, b'', 0x02)
        self.cseq += 1
        self.seg(False, b'', 0x12)
        self.sseq += 1
        self.seg(True, b'', 0x10)

    def seg(self, from_client, payload, flags=0x18):
        # segments of at most the MSS (1460); TCP reassembles the PDU
        while len(payload) > 1460:
            self.seg(from_client, payload[:1460], 0x10)
            payload = payload[1460:]
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
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 0, 0x4000, 64, 6, 0, src[0], dst[0])
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


# ---------------------------------------------------------------- DCE/RPC
class RPC:
    def __init__(self, tcp, le=True, ndr64=False, uuid=UUID_FLDB, ver=VER_FLDB):
        self.tcp, self.le, self.ndr64 = tcp, le, ndr64
        self.e = '<' if le else '>'
        self.call_id = 0
        self.uuid, self.ver = uuid, ver

    def uuid_bytes(self, u):
        h = u.replace('-', '')
        a, b, c = int(h[0:8], 16), int(h[8:12], 16), int(h[12:16], 16)
        return struct.pack(self.e + 'IHH', a, b, c) + bytes.fromhex(h[16:])

    def pdu(self, ptype, body, call_id, flags=0x03):
        drep = bytes([0x10 if self.le else 0x00, 0, 0, 0])
        hdr = struct.pack(self.e + 'BBBB', 5, 0, ptype, flags) + drep
        hdr += struct.pack(self.e + 'HHI', 16 + len(body), 0, call_id)
        return hdr + body

    def bind(self):
        self.call_id += 1
        ts = (UUID_NDR64, 1) if self.ndr64 else (UUID_NDR, 2)
        body = struct.pack(self.e + 'HHI', 4280, 4280, 0) + struct.pack(self.e + 'B3x', 1)
        body += struct.pack(self.e + 'HBx', 0, 1) + self.uuid_bytes(self.uuid)
        body += struct.pack(self.e + 'I', self.ver[0] | (self.ver[1] << 16))
        body += self.uuid_bytes(ts[0]) + struct.pack(self.e + 'I', ts[1])
        self.tcp.seg(True, self.pdu(11, body, self.call_id))
        sec = b'49155\0'
        body = struct.pack(self.e + 'HHI', 4280, 4280, 0x12345) + struct.pack(self.e + 'H', len(sec)) + sec
        body += b'\0' * ((-(16 + len(body))) % 4)
        body += struct.pack(self.e + 'B3x', 1) + struct.pack(self.e + 'HH', 0, 0)
        body += self.uuid_bytes(ts[0]) + struct.pack(self.e + 'I', ts[1])
        self.tcp.seg(False, self.pdu(12, body, self.call_id))

    def call(self, opnum, req, resp):
        self.call_id += 1
        body = struct.pack(self.e + 'IHH', len(req), 0, opnum) + req
        self.tcp.seg(True, self.pdu(0, body, self.call_id))
        if resp is not None:
            body = struct.pack(self.e + 'IHBB', len(resp), 0, 0, 0) + resp
            self.tcp.seg(False, self.pdu(2, body, self.call_id))


# ---------------------------------------------------------------- DCE/RPC CL
class CL:
    """Connectionless DCE/RPC over UDP: request/response pairs that share
    an activity, with increasing sequence numbers."""
    def __init__(self, frames, le=True, cport=40000,
                 cip=(192, 0, 2, 50), sip=(192, 0, 2, 60)):
        self.frames, self.le = frames, le
        self.e = '<' if le else '>'
        self.cport = cport
        self.c, self.s = bytes(cip), bytes(sip)
        self.seq = 0
        self.act = '6b8c0000-0000-4000-8000-%012x' % cport

    def uuid_bytes(self, u):
        return uuid.UUID(u).bytes_le if self.le else uuid.UUID(u).bytes

    def udp(self, from_client, payload):
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        sp, dp = (self.cport, 135) if from_client else (135, self.cport)
        u = struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 0, 0, 64, 17, 0, src, dst)
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        mc, ms = bytes.fromhex('020000000050'), bytes.fromhex('020000000060')
        eth = (ms + mc) if from_client else (mc + ms)
        self.frames.append(eth + b'\x08\x00' + ip + u)

    def pdu(self, ptype, opnum, stub, fragnum=0, frag=0):
        """frag: 0 unfragmented, 1 a fragment, 2 the last fragment"""
        drep = b'\x10\x00\x00' if self.le else b'\x00\x00\x00'
        # 0x08 no fack; 0x02 last fragment, 0x04 fragment
        flags1 = 0x08 if ptype == 0 else 0x0a
        if frag:
            flags1 = (flags1 & ~0x02) | 0x04 | (0x02 if frag == 2 else 0)
        hdr = struct.pack('BBBB', 4, ptype, flags1, 0) + drep + b'\x00'
        hdr += b'\x00' * 16 + self.uuid_bytes(UUID_FLDB) + self.uuid_bytes(self.act)
        hdr += struct.pack(self.e + 'IIIHHHHH', 1, VER_FLDB[0], self.seq, opnum,
                           0xffff, 0xffff, len(stub), fragnum)
        hdr += b'\x00\x00'
        return hdr + stub

    def send(self, from_client, ptype, opnum, stub):
        """stubs over 1392 octets go in fragments that fit an Ethernet
        frame; DCE/RPC reassembles them"""
        if len(stub) <= 1392:
            self.udp(from_client, self.pdu(ptype, opnum, stub))
            return
        chunks = [stub[i:i + 1392] for i in range(0, len(stub), 1392)]
        for i, c in enumerate(chunks):
            self.udp(from_client, self.pdu(ptype, opnum, c, i, 2 if i == len(chunks) - 1 else 1))

    def call(self, opnum, req, resp):
        self.seq += 1
        self.send(True, 0, opnum, req)
        if resp is not None:
            self.send(False, 2, opnum, resp)


# ---------------------------------------------------------------- FLDB
class Stub:
    def __init__(self, e):
        self.e = e
        self.b = bytearray()

    def align(self, n):
        self.b += b'\0' * ((-len(self.b)) % n)

    def u8(self, v):
        self.b += bytes([v])

    def u16(self, v):
        self.align(2)
        self.b += struct.pack(self.e + 'H', v)

    def u32(self, v):
        self.align(4)
        self.b += struct.pack(self.e + 'I', v & 0xffffffff)

    def raw(self, data, size):
        self.b += data.ljust(size, b'\0')[:size]

    def guid(self, s):
        self.align(4)
        h = s.replace('-', '')
        self.b += struct.pack(self.e + 'IHH', int(h[0:8], 16), int(h[8:12], 16),
                              int(h[12:16], 16)) + bytes.fromhex(h[16:])

    def bytes(self):
        return bytes(self.b)


def netaddr(s, atype=0, port=0, ip=(0, 0, 0, 0)):
    """afsNetAddr: type, then 14 octets (port, IPv4 address in octets 1-5);
    with type 0 the octets are skipped"""
    s.u16(atype)
    s.raw(bytes([0, port]) + bytes(ip), 14)


def flags_entry(n):
    """the values that make a vldbentry reach every branch"""
    return dict(name=b'user.alice', vtype=3, nservers=2,
                addrs=[(2, 23, (192, 0, 2, 10)), (2, 0, (192, 0, 2, 11))] + [(0, 0, (0, 0, 0, 0))] * 14,
                parts=[1, 2] + [0] * 14,
                siteflags=[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80000000, 0x8000007f] + [0] * 7,
                latency=[300, 0] * 8,
                princ=[b'hosts/fs1/self', b'hosts/fs2/self'] + [b''] * 14,
                owner=['00000000-0000-0000-0000-0000000000%02x' % i for i in range(16)],
                objid=['11111111-2222-3333-4444-5555555555%02x' % i for i in range(16)],
                volids=[(0, 536870913 + i) for i in range(8)],
                voltypes=[1, 2, 4, 0, 0, 0, 0, 0],
                clone=(0, 536870920), afsflags=0x3ffff,
                lat=(600, 1200, 30, 300, 7200, 1700000000),
                spares=(1, 2, 3, 4), locker=b'admin', charspares=b'spare chars')


def zero_entry():
    """a vldbentry that takes the "zero" side of every branch"""
    return dict(name=b'', vtype=0, nservers=0,
                addrs=[(0, 0, (0, 0, 0, 0))] * 16, parts=[0] * 16, siteflags=[0] * 16,
                latency=[0] * 16, princ=[b''] * 16,
                owner=['00000000-0000-0000-0000-000000000000'] * 16,
                objid=['00000000-0000-0000-0000-000000000000'] * 16,
                volids=[(0, 0)] * 8, voltypes=[0] * 8, clone=(0, 0), afsflags=0,
                lat=(0, 0, 0, 0, 0, 0), spares=(0, 0, 0, 0), locker=b'', charspares=b'')


def vldbentry(s, v):
    """the dissector shows 114 octets of name but skips 110"""
    s.raw(v['name'], 110)
    s.u32(v['vtype'])
    s.u32(v['nservers'])
    for a in v['addrs']:
        netaddr(s, *a)
    for x in v['parts']:
        s.u32(x)
    for x in v['siteflags']:
        s.u32(x)
    for x in v['latency']:
        s.u32(x)
    for x in v['princ']:
        s.raw(x, 64)
    for g in v['owner']:
        s.guid(g)
    for g in v['objid']:
        s.guid(g)
    for hi, lo in v['volids']:
        s.u32(hi)
        s.u32(lo)
    for x in v['voltypes']:
        s.u32(x)
    s.u32(v['clone'][0])
    s.u32(v['clone'][1])
    s.u32(v['afsflags'])
    for x in v['lat']:
        s.u32(x)
    for x in v['spares']:
        s.u32(x)
    s.raw(v['locker'], 64)
    s.raw(v['charspares'], 50)


CELL_NAME = b'dce.cell.' + b'x' * 100 + b'.example.com'   # 121 octets


def vlconf_cell(s, name=CELL_NAME, nserv=2):
    s.raw(name, 128)
    s.u32(0)
    s.u32(0x2a)
    s.u32(nserv)
    for i in range(64):
        if i < nserv:
            netaddr(s, 2, 0, (192, 0, 2, 10 + i))
        else:
            netaddr(s)
    for i in range(64):
        s.raw(b'fs%d.example.com' % (i + 1) if i < nserv else b'', 64)
    for x in (1, 2, 3, 4, 5):
        s.u32(x)


ST_OK = 0
ST_NOENT = 676372485        # FLDB: no such entry
ST_UNKNOWN = 0x1234


def fldb_calls(rpc, le):
    e = '<' if le else '>'

    def S():
        return Stub(e)

    def st(v=ST_OK):
        s = S()
        s.u32(v)
        return s.bytes()

    full = flags_entry(0)
    zero = zero_entry()
    part = dict(full, afsflags=0x1ff)      # no SERVER_REESTABLISH
    # 0 GetEntryByID
    q = S()
    for x in (0, 536870913, 0):
        q.u32(x)
    r = S()
    vldbentry(r, full)
    rpc.call(0, q.bytes(), r.bytes())
    # 1 GetEntryByName (4 skipped octets, then the name size and name)
    for nm, entry, status in ((b'user.alice', part, ST_OK), (b'', zero, ST_NOENT)):
        q = S()
        q.u32(0x00020000)
        q.u32(len(nm))
        q.b += nm
        r = S()
        vldbentry(r, entry)
        r.u32(status)
        rpc.call(1, q.bytes(), r.bytes())
    # 2 Probe
    rpc.call(2, b'', b'')
    # 3 GetCellInfo, with a cell name longer than 114 octets
    r = S()
    vlconf_cell(r)
    rpc.call(3, b'', r.bytes())
    # 4 GetNextServersByID
    r = S()
    r.u32(7)
    vldbentry(r, full)
    r.u32(1)
    rpc.call(4, b'', r.bytes())
    # 6 GetSiteInfo
    for addr, status in (((2, 0, (192, 0, 2, 10)), ST_OK), ((0, 0, (0, 0, 0, 0)), ST_UNKNOWN)):
        q = S()
        netaddr(q, *addr)
        r = S()
        netaddr(r, *addr)
        r.b += b'\0' * 48
        r.raw(b'hosts/fs1/self', 64)
        r.guid('00000000-0000-0000-0000-000000000001')
        r.guid('11111111-2222-3333-4444-555555555501')
        for x in (100, 3, 0, 2, 3, 4, 5):
            r.u32(x)
        r.u32(status)
        rpc.call(6, q.bytes(), r.bytes())
    # 13 CreateEntry
    q = S()
    vldbentry(q, full)
    rpc.call(13, q.bytes(), st())
    # 14 DeleteEntry
    q = S()
    for x in (0, 536870913, 0, 0):
        q.u32(x)
    rpc.call(14, q.bytes(), st(ST_NOENT))
    # 16 ReplaceEntry
    q = S()
    for x in (0, 536870913, 0):
        q.u32(x)
    vldbentry(q, zero)
    rpc.call(16, q.bytes(), st())
    # 17 SetLock, 18 ReleaseLock
    q = S()
    for x in (0, 536870913, 0x1, 2):
        q.u32(x)
    rpc.call(17, q.bytes(), st())
    q = S()
    for x in (0, 536870913, 0x1, 2):
        q.u32(x)
    rpc.call(18, q.bytes(), st(ST_NOENT))
    # 19 ListEntry
    q = S()
    q.u32(0)
    q.u32(0)
    r = S()
    r.u32(1)
    r.u32(1)
    vldbentry(r, part)
    rpc.call(19, q.bytes(), r.bytes())
    # 26 GetNewVolumeIds (no response dissector)
    q = S()
    q.u32(4)
    netaddr(q, 2, 0, (192, 0, 2, 10))
    rpc.call(26, q.bytes(), b'')
    # opnums without request and response dissectors
    for op in (5, 7, 8, 9, 10, 11, 12, 15, 20, 21, 22, 23, 24, 25, 27, 28):
        rpc.call(op, b'', b'')


def main_frames():
    F = []
    for cport, le in ((50001, True), (50002, False)):
        t = TCP(F, cport)
        rpc = RPC(t, le)
        rpc.bind()
        fldb_calls(rpc, le)
        if cport == 50001:
            # an opnum the interface does not have
            rpc.call(29, b'\0' * 8, b'')
        t.fin()
    fldb_calls(CL(F, True, 40001), True)
    return F


def malformed_frames():
    F = []
    t = TCP(F, 50101)
    rpc = RPC(t)
    rpc.bind()
    e = '<'
    # GetEntryByName with a principal name length of 256 and more: the
    # fix throws (before it, only the Info column noted it)
    for size in (256, 0xffffffff):
        q = Stub(e)
        q.u32(0)
        q.u32(size)
        q.b += b'name'
        rpc.call(1, q.bytes(), None)
    # GetEntryByName with a name longer than the stub
    q = Stub(e)
    q.u32(0)
    q.u32(100)
    q.b += b'abc'
    rpc.call(1, q.bytes(), None)
    # GetEntryByID response cut in the vldbentry
    r = Stub(e)
    vldbentry(r, flags_entry(0))
    rpc.call(0, b'\0' * 12, r.bytes()[:600])
    # GetCellInfo response cut in the host names
    r = Stub(e)
    vlconf_cell(r)
    rpc.call(3, b'', r.bytes()[:2000])
    # GetSiteInfo request cut in the address
    rpc.call(6, b'\x02\x00\x00', None)
    # SetLock request and reply without the status
    rpc.call(17, b'\0' * 8, b'')
    t.fin()
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dcerpc_fldb-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'dcerpc_fldb-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
