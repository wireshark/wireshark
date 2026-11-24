#!/usr/bin/env python3
# Generates test/captures/nvme_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic NVMe coverage captures (NVMe over TCP, port 4420).

usage: mknvme.py <outdir>
writes nvme-coverage.pcap (decodes cleanly, no warnings or errors) and
nvme-coverage-malformed.pcap (truncated or lying structures).
All payloads are generated from a fixed seed; nothing is captured.
"""
import os
import random
import struct
import sys

HOST_MAC = bytes.fromhex('020000000011')
CTRL_MAC = bytes.fromhex('020000000012')
HOST_IP = bytes([192, 0, 2, 11])
CTRL_IP = bytes([192, 0, 2, 12])
CPORT = 4420


def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Cap:
    """A pcap with any number of NVMe/TCP connections (one per host port)."""
    def __init__(self):
        self.pkts = []
        self.seq = {}

    def add(self, port, to_ctrl, payload):
        k = (port, to_ctrl)
        self.seq.setdefault((port, True), 1000)
        self.seq.setdefault((port, False), 5000)
        src_ip, dst_ip = (HOST_IP, CTRL_IP) if to_ctrl else (CTRL_IP, HOST_IP)
        sp, dp = (port, CPORT) if to_ctrl else (CPORT, port)
        tcp = struct.pack('!HHIIBBHHH', sp, dp, self.seq[k],
                          self.seq[(port, not to_ctrl)], 5 << 4, 0x18, 65535, 0, 0)
        ph = src_ip + dst_ip + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        c = _csum(ph + tcp + payload)
        tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
        self.seq[k] += len(payload)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         1, 0, 64, 6, 0, src_ip, dst_ip)
        ip = ip[:10] + struct.pack('!H', _csum(ip)) + ip[12:]
        eth = (CTRL_MAC + HOST_MAC if to_ctrl else HOST_MAC + CTRL_MAC) + b'\x08\x00'
        self.pkts.append(eth + ip + tcp + payload)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
                f.write(p)


def sqe(opcode, cid, nsid=None, cdw10=0, cdw11=0, cdw12=0, cdw13=0, cdw14=0, cdw15=0,
        sgl=None, flags=0, mptr=0):
    if nsid is None:
        nsid = 1
    b = bytearray(64)
    b[0] = opcode
    b[1] = flags
    struct.pack_into('<HI', b, 2, cid, nsid)
    struct.pack_into('<Q', b, 16, mptr)
    if sgl is not None:
        b[24:40] = sgl
    struct.pack_into('<IIIIII', b, 40, cdw10, cdw11, cdw12, cdw13, cdw14, cdw15)
    return bytes(b)


def sgl_desc(dtype, sub=0, addr=0, length=0, key=0):
    """16 byte SGL descriptor of the given type."""
    ident = (dtype << 4) | sub
    if dtype == 4:      # keyed data block: addr(8) len(3) key(4) id(1)
        return struct.pack('<Q', addr) + length.to_bytes(3, 'little') + \
            struct.pack('<I', key) + bytes([ident])
    return struct.pack('<QI', addr, length) + b'\0\0\0' + bytes([ident])


def cmd_pdu(s, data=b'', hlen=72):
    hdr = struct.pack('<BBBBI', 0x04, 0, 72, 72 if data else 0, 72 + len(data))
    return hdr + s + data


def c2h_pdu(cid, data, off=0, flags=0x04):
    hdr = struct.pack('<BBBBI', 0x07, flags, 24, 24, 24 + len(data))
    return hdr + struct.pack('<HHII4s', cid, 0, off, len(data), b'\0' * 4) + data


def h2c_pdu(cid, data, off=0, flags=0x04):
    hdr = struct.pack('<BBBBI', 0x06, flags, 24, 24, 24 + len(data))
    return hdr + struct.pack('<HHII4s', cid, 0, off, len(data), b'\0' * 4) + data


def rsp_pdu(cid, dw0=0, status=0, dw1=0, sqhd=0, sqid=0):
    cqe = struct.pack('<IIHHHH', dw0, dw1, sqhd, sqid, cid, status)
    return struct.pack('<BBBBI', 0x05, 0, 24, 0, 24) + cqe


def st(sct=0, sc=0, m=0, dnr=0):
    return (sc << 1) | (sct << 9) | (m << 14) | (dnr << 15)


class Gen:
    OPTS = ()

    def __init__(self, cap, port, seed):
        self.c = cap
        self.port = port
        self.r = random.Random(seed)
        self.cid = 0x100

    def rnd(self, n, p=0.12):
        r = self.r
        return bytes((r.getrandbits(8) or 1) if r.random() < p else 0 for _ in range(n))

    def nextcid(self):
        self.cid = (self.cid + 1) & 0xffff
        return self.cid

    def cmd(self, s, inline=b''):
        self.c.add(self.port, True, cmd_pdu(s, inline))

    def c2h(self, cid, data, off=0):
        self.c.add(self.port, False, c2h_pdu(cid, data, off))

    def h2c(self, cid, data, off=0):
        self.c.add(self.port, True, h2c_pdu(cid, data, off))

    def rsp(self, cid, dw0=0, status=0, **kw):
        self.c.add(self.port, False, rsp_pdu(cid, dw0, status, **kw))

    def xact(self, s, data=None, inline=b'', h2c=None, dw0=0, status=0, **kw):
        """command [+ inline data] [+ H2CData] [+ C2HData] + response"""
        cc = struct.unpack_from('<H', s, 2)[0]
        self.cmd(s, inline)
        if h2c is not None:
            self.h2c(cc, h2c)
        if data is not None:
            self.c2h(cc, data)
        self.rsp(cc, dw0, status, **kw)


def le16(*v):
    return b''.join(struct.pack('<H', x) for x in v)


def le32(*v):
    return b''.join(struct.pack('<I', x) for x in v)


def le64(*v):
    return b''.join(struct.pack('<Q', x) for x in v)


def put(buf, off, data):
    buf[off:off + len(data)] = data
    return buf


def fabric(cid, fctype, extra=b'', sgl=None):
    s = bytearray(64)
    s[0] = 0x7f
    struct.pack_into('<H', s, 2, cid)
    s[4] = fctype
    if sgl is not None:
        s[24:40] = sgl
    s[40:40 + len(extra)] = extra
    return bytes(s)


def connect_cmd(cid, qid, sqsize=31, cattr=0, kato=0, recfmt=0):
    return fabric(cid, 1, struct.pack('<HHHBBI', recfmt, qid, sqsize, cattr, 0, kato),
                  sgl=sgl_desc(0, 1, 0, 1024))


def connect_data(g, hostnqn, subnqn, cntlid=0xffff):
    d = bytearray(1024)
    d[0:16] = bytes(range(16))
    struct.pack_into('<H', d, 16, cntlid)
    d[256:256 + len(subnqn)] = subnqn
    d[512:512 + len(hostnqn)] = hostnqn
    return bytes(d)


def build_main(cap):
    ADM, IOQ, NOCONN, DISC = 40001, 40002, 40003, 40004
    g = Gen(cap, ADM, 1)
    r = g.r
    subnqn = b'nqn.2014-08.org.nvmexpress:uuid:00000000-0000-4000-8000-000000000001'
    hostnqn = b'nqn.2014-08.org.nvmexpress:uuid:00000000-0000-4000-8000-0000000000aa'

    # ---- admin queue: Fabrics Connect, properties --------------------------
    cc = g.nextcid()
    g.xact(connect_cmd(cc, 0, kato=10000, cattr=3), inline=connect_data(g, hostnqn, subnqn),
           dw0=0x00010002)
    for off in (0, 8, 0x14, 0x1c, 0x20, 0x30, 0x38, 0x3c, 0x40, 0x48, 0x50, 0x1000):
        for attr in (0, 1):
            g.xact(fabric(g.nextcid(), 4, bytes([attr, 0, 0, 0]) + struct.pack('<I', off)),
                   dw0=r.getrandbits(32), dw1=r.getrandbits(32))
    g.xact(fabric(g.nextcid(), 4, bytes([1, 0, 0, 0]) + le32(0)), dw0=0, dw1=0)      # CAP, CSS 0
    g.xact(fabric(g.nextcid(), 4, bytes([1, 0, 0, 0]) + le32(0)), dw0=0, dw1=0x40 << 5)
    for off in (0x14, 0x1c, 0x20, 0x30):
        g.xact(fabric(g.nextcid(), 0, bytes([1, 0, 0, 0]) + le32(off) + le64(r.getrandbits(64))))
        g.xact(fabric(g.nextcid(), 0, bytes([0, 0, 0, 0]) + le32(off) + le32(r.getrandbits(32))))
    g.xact(fabric(g.nextcid(), 8, sgl=sgl_desc(0, 1, 0, 100)), status=0)       # auth send
    g.xact(fabric(g.nextcid(), 6, sgl=sgl_desc(0, 1, 0, 100)), status=0)       # auth receive
    g.xact(fabric(g.nextcid(), 5), status=0)                                   # disconnect
    for ft in (0x22, 0x80):                                                   # unknown fabrics types
        g.xact(fabric(g.nextcid(), ft, g.rnd(24)))
    g.xact(connect_cmd(g.nextcid(), 0), inline=connect_data(g, hostnqn, subnqn),
           status=st(1, 0x80, dnr=1))
    g.xact(connect_cmd(g.nextcid(), 0), inline=connect_data(g, hostnqn, subnqn),
           status=st(1, 0x82))
    for sct, sc in ((0, 1), (0, 0x82), (1, 6), (1, 0x80), (2, 2), (3, 1), (7, 5), (4, 0)):
        g.xact(fabric(g.nextcid(), 4, bytes([0, 0, 0, 0]) + le32(0x1c)), status=st(sct, sc, m=1))

    # ---- admin queue: misc commands --------------------------------------
    g.xact(sqe(0x18, g.nextcid()))                                  # keep alive
    g.xact(sqe(0x0c, g.nextcid(), cdw10=0xffffff), dw0=0x00010102)  # AER
    for aet, aei in ((0, 0), (0, 3), (0, 9), (1, 0), (1, 2), (1, 7), (2, 0), (2, 3), (2, 0xf0),
                     (2, 0x77), (3, 1), (4, 1), (6, 0), (6, 2), (6, 9), (7, 0)):
        g.xact(sqe(0x0c, g.nextcid()), dw0=aet | (aei << 8) | (r.randrange(0x20) << 16))
    for opc in (0x00, 0x01, 0x04, 0x05, 0x08, 0x0d, 0x10, 0x11, 0x14, 0x15, 0x20, 0x21, 0x24,
                0x7c, 0x7d, 0x80, 0x84, 0xc0, 0xff):
        g.xact(sqe(opc, g.nextcid(), cdw10=r.getrandbits(32), cdw11=r.getrandbits(32),
                   cdw12=r.getrandbits(32), cdw13=r.getrandbits(32),
                   cdw14=r.getrandbits(32), cdw15=r.getrandbits(32)))
    for opc in (0x0d, 0x04, 0xc1):                                    # C2HData for unhandled opcodes
        g.xact(sqe(opc, g.nextcid()), data=g.rnd(64))
    g.xact(sqe(0x10, g.nextcid(), cdw10=0xff1234), status=st(0, 1, dnr=1))        # fw commit
    g.xact(sqe(0x11, g.nextcid(), cdw10=0x200, cdw11=0x400), h2c=g.rnd(2048))     # fw download
    g.xact(sqe(0x14, g.nextcid(), cdw10=0x1), dw0=0)                              # self test
    g.xact(sqe(0x14, g.nextcid(), cdw10=0xf), dw0=0)
    g.xact(sqe(0x15, g.nextcid(), cdw10=0x10000fc3, cdw14=0x1f))                 # lockdown
    g.xact(sqe(0x80, g.nextcid(), cdw10=0x2f5))                                   # format
    g.xact(sqe(0x84, g.nextcid(), cdw10=0x00ff0182, cdw11=0x1234))               # sanitize
    g.xact(sqe(0x84, g.nextcid(), cdw10=0x2, cdw11=0))
    g.xact(sqe(0x84, g.nextcid(), cdw10=0x5))
    g.xact(sqe(0x81, g.nextcid(), cdw10=0xb0, cdw11=0x3))                         # format NVM
    g.xact(sqe(0x0a, g.nextcid(), cdw10=0xff))                                    # unknown fid
    g.xact(sqe(0x09, g.nextcid(), cdw10=0xfe))
    g.xact(sqe(0x09, g.nextcid(), cdw10=0xc5), status=st(0, 0x0d))

    # ---- Identify ---------------------------------------------------------
    ctrl = bytearray(g.rnd(4096, 0.5))
    put(ctrl, 4, b'SN0123456789012345 6'[:20])
    put(ctrl, 24, b'Synthetic NVMe Controller'.ljust(40))
    put(ctrl, 64, b'1.0'.ljust(8))
    ctrl[72] = 6; ctrl[77] = 5
    ctrl[111] = 1
    put(ctrl, 520, le16(0x00bf))
    for cns in (0, 1, 2, 3, 4, 8, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x7f):
        for ln in (4096,):
            body = bytearray(g.rnd(4096, 0.08))
            body[25] = 3; body[82] = 2
            body = bytes(body)
            g.xact(sqe(0x06, g.nextcid(), nsid=r.choice((0, 1, 0xffffffff)), cdw10=cns | (r.getrandbits(16) << 16),
                       cdw11=r.getrandbits(32), cdw14=r.getrandbits(32)), data=body)
    # capacity fields in all units (128 bit values, repeated 8-byte pattern)
    for k in (0, 5, 15, 25, 35, 45, 55, 62):
        pat = struct.pack('<Q', 1 << k)
        body = bytearray(pat * 512)
        body[25] = 3; body[82] = 2
        body = bytes(body)
        for cns in (0, 1):
            g.xact(sqe(0x06, g.nextcid(), cdw10=cns), data=body)
        for lid in (0x02, 0x09):
            g.xact(sqe(0x02, g.nextcid(), cdw10=lid | (0x3ff << 16)), data=pat * 64)
    # a hand built namespace, controller identifiers
    ns = bytearray(4096)
    put(ns, 0, le64(0x100000, 0x100000, 0x80000))
    ns[25] = 3; ns[26] = 1; ns[82] = 2
    for i in range(8):
        put(ns, 128 + 4 * i, struct.pack('<I', (9 + i) << 16 | (i * 8)))
    g.xact(sqe(0x06, g.nextcid(), cdw10=0), data=bytes(ns))
    ns[25] = 63; ns[82] = 5                                  # more than 64 formats: warn, malformed only
    g.xact(sqe(0x06, g.nextcid(), cdw10=0x08), data=bytes(4096))
    g.xact(sqe(0x06, g.nextcid(), cdw10=0x02), data=le32(1, 2, 3, 0x1000, 0xffffffff, 0) + bytes(100))
    g.xact(sqe(0x06, g.nextcid(), cdw10=0x03),
           data=bytes([1, 8, 0, 0]) + bytes(range(8)) + bytes([2, 16, 0, 0]) + bytes(range(16)) +
           bytes([3, 16, 0, 0]) + bytes(16) + bytes([4, 17, 0, 0]) + bytes(17) +
           bytes([5, 4, 0, 0]) + bytes(4) + bytes([0, 0, 0, 0]) + bytes(40))
    g.xact(sqe(0x06, g.nextcid(), cdw10=0x03), data=bytes([1, 8, 0, 0]) + bytes(8) + bytes(4))
    g.xact(sqe(0x06, g.nextcid(), cdw10=0x13), data=le16(5, 1, 2, 3, 4, 5) + bytes(40))
    g.xact(sqe(0x06, g.nextcid(), cdw10=0x12), data=le16(0) + bytes(30))
    g.xact(sqe(0x06, g.nextcid(), cdw10=0x13), data=b'\x01')              # short: header only
    sec = bytearray(32 + 4 * 32)
    sec[0] = 3
    for i in range(3):
        put(sec, 32 + 32 * i, le16(i + 1, 1) + bytes([1, 0, 0, 0]) + le16(2, 4, 6))
    g.xact(sqe(0x06, g.nextcid(), cdw10=0x15), data=bytes(sec))
    gran = bytearray(32 + 5 * 16)
    gran[4] = 3
    for i in range(4):
        put(gran, 32 + 16 * i, le64(0x1000 * (i + 1), 0x2000 * (i + 1)))
    g.xact(sqe(0x06, g.nextcid(), cdw10=0x16), data=bytes(gran))
    uu = bytearray(32 * 5)
    for i in range(1, 4):
        uu[32 * i] = i
        put(uu, 32 * i + 16, bytes([i] * 16))
    g.xact(sqe(0x06, g.nextcid(), cdw10=0x17), data=bytes(uu))
    nvs = bytearray(128 + 128 * 3)
    nvs[0] = 3
    for i in range(3):
        put(nvs, 128 + 128 * i, le16(i + 1, 1) + bytes(4) + le32(100, 200) + bytes([1] * 16) + bytes([2] * 16))
    g.xact(sqe(0x06, g.nextcid(), cdw10=0x04), data=bytes(nvs))
    g.xact(sqe(0x06, g.nextcid(), cdw10=0x14), data=g.rnd(96, 0.6))
    g.xact(sqe(0x06, g.nextcid(), cdw10=0x01), data=b'\0' * 40)                   # short controller
    g.xact(sqe(0x06, g.nextcid(), cdw10=0x00), data=b'\0' * 40)

    # ---- Get Log Page -------------------------------------------------------
    lids = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
            0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x70, 0x80, 0x81, 0x82, 0xbf, 0xc0]
    for lid in lids:
        for lpo in (0, 64):
            ln = 520 if lpo == 0 else 200
            g.xact(sqe(0x02, g.nextcid(), cdw10=lid | (0x3ff << 16) | (r.getrandbits(3) << 8),
                       cdw11=r.getrandbits(16) << 16, cdw12=lpo, cdw14=r.getrandbits(32)),
                   data=g.rnd(ln, 0.08))
    for lid in (0x00, 0x05, 0x12, 0x13, 0x14, 0x10):                  # record aligned windows
        for lpo in (0, 16, 1020, 1028, 2048):
            g.xact(sqe(0x02, g.nextcid(), cdw10=lid | (0xff << 16), cdw12=lpo),
                   data=g.rnd(600, 0.1))
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x03 | (0x3ff << 16), cdw12=0xfffffff8, cdw13=0xffffffff),
           data=g.rnd(64))
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x01 | (0xffff << 16), cdw11=0xffff), data=g.rnd(64))
    # self test log with several results
    stl = bytes([0x11, 0, 0, 0]) + b''.join(bytes([i | 0x10 if i % 2 else i, 0x0f if i == 3 else i, 1, 0])
                                            + le64(i * 1000) + le32(1, 0xab) + bytes([1, 2, 3, 4, 5, 6, 7, 8]) for i in range(4))[:]
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x06 | (0x3ff << 16)), data=stl)
    # ANA: header + three groups with NSIDs
    ana = le64(7) + le16(3) + bytes(6)
    for gid, nns in ((1, 2), (2, 0), (3, 3)):
        ana += struct.pack('<IIQB15s', gid, nns, 5, gid & 3, bytes(15)) + le32(*range(1, nns + 1))
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x0c | (0x3ff << 16)), data=ana)
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x0c | (0x3ff << 16), cdw12=16), data=ana[16:])
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x0c | (0x3ff << 16), cdw12=32), data=ana[32:])
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x0c | (0x3ff << 16), cdw12=0), data=ana[:20])
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x0c | (0x3ff << 16), cdw12=0), data=ana[:40])
    # discovery log: rdma and tcp entries
    def dle(trtype, svc, nqn, addr):
        d = bytearray(1024)
        d[0] = trtype; d[1] = 1; d[2] = 2; d[3] = 3
        put(d, 4, le16(1, 0xffff, 128)); put(d, 10, le16(1))
        put(d, 32, svc.ljust(32, b'\0')); put(d, 256, nqn); put(d, 512, addr)
        if trtype == 1:
            d[768] = 1; d[769] = 1; d[770] = 1; put(d, 776, le16(0xffff))
        elif trtype == 3:
            d[768] = 2
        return bytes(d)
    dl = le64(5, 3) + le16(1) + bytes(1006)
    dl += dle(1, b'4420', subnqn, b'192.0.2.12') + dle(3, b'4421', subnqn, b'192.0.2.13') + dle(2, b'4422', subnqn, b'x')
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x70 | (0x3ff << 16)), data=dl)
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x70 | (0x3ff << 16), cdw12=1024), data=dl[1024:])
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x70 | (0x3ff << 16), cdw12=2048), data=dl[2048:])
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x70 | (0x3ff << 16), cdw12=1100), data=dl[1100:1500])
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x70 | (0x3ff << 16), cdw12=8), data=dl[8:1024])
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x70 | (0x3ff << 16)), data=dl[:20])
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x70 | (0x3ff << 16)), data=dl[:1030])
    # EOM
    for ndesc, ds in ((2, 128), (3, 64), (1, 256)):
        hdr = bytearray(64)
        put(hdr, 0, le32(0)); struct.pack_into('<I', hdr, 20, 32 + ds)   # see report
        struct.pack_into('<H', hdr, 24, ndesc)
        body = bytes(hdr)
        for i in range(ndesc):
            d = bytearray(ds)
            d[0] = 0x80 | i
            put(d, 4, le16(3, 4, 5, 6, 2, 3)); put(d, 16, le32(4))
            d[32:38] = b'.:*#*:'
            d[38:42] = bytes([1, 2, 3, 4])
            body += bytes(d)
        g.xact(sqe(0x02, g.nextcid(), cdw10=0x19 | (0x3ff << 16)), data=body)
    # window shapes that reach the clamps
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x0f | (0x3ff << 16), cdw12=8), data=b'\x01')
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x0f | (0x3ff << 16), cdw12=0), data=le64(2) + le16(5, 6, 7))
    for lpo in (16, 32, 60):
        g.xact(sqe(0x02, g.nextcid(), cdw10=0x80 | (0x3ff << 16), cdw12=lpo), data=bytes(100))
    for scope, lst in ((0, [0x06, 0x02, 0xc1]), (2, [0x01, 0x02, 0x99]), (3, [1, 2])):
        g.xact(sqe(0x02, g.nextcid(), cdw10=0x14 | (0x3ff << 16)),
               data=bytes([scope, 0, 0, len(lst)] + lst) + bytes(8))
    g.xact(sqe(0x09, g.nextcid(), cdw10=0x0c), inline=g.rnd(300, 0.3))
    g.xact(sqe(0x09, g.nextcid(), cdw10=0x13), inline=g.rnd(600, 0.1))
    g.xact(sqe(0x09, g.nextcid(), cdw10=0x16), inline=g.rnd(600, 0.1))
    g.xact(sqe(0x82, g.nextcid(), cdw10=0, cdw11=4096), data=bytes(6) + struct.pack('>H', 500) + bytes([0, 1, 2]))
    g.xact(sqe(0x82, g.nextcid(), cdw10=1 << 8, cdw11=4096), data=bytes(2) + struct.pack('>H', 900) + b'abc')
    # reservation notification, sanitize, lockdown, lba status, ...
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x80 | (0x3ff << 16)), data=le64(1) + bytes([1, 2, 0]) + bytes(3) + le32(1) + bytes(40))
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x81 | (0x3ff << 16)), data=le16(0x1234, 3) + le32(1) + bytes(50))
    for lpo in (0, 16, 32, 64, 112, 4096):
        g.xact(sqe(0x02, g.nextcid(), cdw10=0x0e | (0x3ff << 16), cdw12=lpo),
               data=le32(1, 2, 3, 4, 5, 6) + bytes(r.getrandbits(8) | 1 for _ in range(150)))
    lbas = le32(2, 1) + le64(0) [:8]
    lbs = bytearray(16)
    put(lbs, 0, le32(0x100, 2)); put(lbs, 8, le16(5, 0)); put(lbs, 12, le16(7, 1))
    body = bytes(lbs)
    for i in range(3):
        body += le64(0x1000 * (i + 1)) + le64(64) + le64(1 << 62)
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x0e | (0x3ff << 16)), data=body)
    # Persistent Event, MI, lockdown
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x14 | (0xff << 16)), data=le32(1) + bytes(400))
    # ---- Features ---------------------------------------------------------
    fids = list(range(1, 0x26)) + [0x78, 0x79, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85,
                                   0xc0, 0xc7, 0xff]
    for fid in fids:
        for sel in ((0, 1, 2, 3) if fid == 1 else (r.randrange(4),)):
            g.xact(sqe(0x0a, g.nextcid(), cdw10=fid | (sel << 8), cdw11=r.getrandbits(8),
                       cdw14=r.getrandbits(8)), dw0=r.getrandbits(32))
        g.xact(sqe(0x09, g.nextcid(), cdw10=fid | (r.getrandbits(1) << 31), cdw11=r.getrandbits(32),
                   cdw12=r.getrandbits(16), cdw13=r.getrandbits(8)),
               dw0=r.getrandbits(32), status=r.choice((0, 0, st(0, 0x0d), st(1, 0x14))))
    for fid in (0x01, 0x0d, 0x16, 0x1d, 0x1e, 0x20, 0x84, 0xc0):    # unstructured transfer data
        g.xact(sqe(0x09, g.nextcid(), cdw10=fid), inline=g.rnd(64, 0.3))
        g.xact(sqe(0x0a, g.nextcid(), cdw10=fid), data=g.rnd(64, 0.3))
        g.xact(sqe(0x09, g.nextcid(), cdw10=fid), h2c=g.rnd(64, 0.3))
    g.xact(sqe(0x09, g.nextcid(), cdw10=0x07, cdw11=0x00030002), dw0=0x00030002)
    g.xact(sqe(0x0a, g.nextcid(), cdw10=0x07), dw0=0x00030002)
    # set features with structured data
    lbart = b''.join(bytes([i % 5, 3]) + bytes(14) + le64(i * 100, 100) + bytes([i] * 16) + bytes(16)
                     for i in range(3))
    g.xact(sqe(0x09, g.nextcid(), cdw10=0x03, cdw11=2), inline=lbart)
    g.xact(sqe(0x0a, g.nextcid(), cdw10=0x03), data=lbart)
    g.xact(sqe(0x09, g.nextcid(), cdw10=0x0c, cdw11=1), inline=g.rnd(256, 0.5))
    g.xact(sqe(0x09, g.nextcid(), cdw10=0x0e), inline=le64(1700000000000) [:6] + bytes(2))
    g.xact(sqe(0x0a, g.nextcid(), cdw10=0x0e), data=le64(1700000000000)[:6] + bytes([3, 0]))
    g.xact(sqe(0x09, g.nextcid(), cdw10=0x13), inline=g.rnd(512, 0.5))
    g.xact(sqe(0x09, g.nextcid(), cdw10=0x16), inline=bytes([1, 2, 0xff, 1]) + g.rnd(508, 0.5))
    g.xact(sqe(0x09, g.nextcid(), cdw10=0x16), inline=g.rnd(512, 0.3))
    for fid in (0x7d, 0x7e, 0x7f):
        md = bytes([3, 0]) + b''.join(struct.pack('<HH', et, len(v)) + v for et, v in
                                       ((1, b'host'), (2, b'os 1.0'), (3, b''), (5, b'driver'), (0x7f, b'x')))
        g.xact(sqe(0x09, g.nextcid(), cdw10=fid | (1 << 8)), inline=md)
        g.xact(sqe(0x0a, g.nextcid(), cdw10=fid), data=md)
        g.xact(sqe(0x09, g.nextcid(), cdw10=fid), inline=b'\x01')
        g.xact(sqe(0x09, g.nextcid(), cdw10=fid), inline=bytes([9, 0]) + le16(1, 100) + b'ab')
    # ---- Security ---------------------------------------------------------
    for secp, spsp in ((0, 0), (0, 1), (0, 5), (0xea, 0), (0xea, 3)):
        dw10 = (secp << 24) | (spsp << 8)
        if secp == 0 and spsp == 0:
            sdata = bytes(6) + struct.pack('>H', 4) + bytes([0, 1, 2, 0xef])
        elif secp == 0 and spsp == 1:
            sdata = bytes(2) + struct.pack('>H', 6) + b'abcdef'
        else:
            sdata = g.rnd(64)
        g.xact(sqe(0x82, g.nextcid(), cdw10=dw10, cdw11=4096), data=sdata)
        g.xact(sqe(0x81, g.nextcid(), cdw10=dw10, cdw11=len(sdata)), inline=sdata)
        g.xact(sqe(0x81, g.nextcid(), cdw10=dw10, cdw11=len(sdata)), h2c=sdata)
        g.xact(sqe(0x81, g.nextcid(), cdw10=dw10, cdw11=0), inline=sdata)
    g.xact(sqe(0x82, g.nextcid(), cdw10=0, cdw11=4096), data=bytes(7))
    g.xact(sqe(0x82, g.nextcid(), cdw10=1 << 8, cdw11=4096), data=bytes(3))
    g.xact(sqe(0x82, g.nextcid(), cdw10=0xea << 24, cdw11=4096), data=b'')
    # SGL descriptor flavours and PSDT bits
    for dt, sub in ((0, 0), (0, 1), (0, 0xf), (1, 0), (2, 0), (3, 0), (4, 0), (4, 0xf), (5, 0), (7, 1), (0xf, 0)):
        g.xact(sqe(0x18, g.nextcid(), flags=0x40, sgl=sgl_desc(dt, sub, 0x1122334455667788, 4096, 0xdeadbeef)))
    g.xact(sqe(0x06, g.nextcid(), cdw10=1, flags=0xc3, sgl=sgl_desc(4, 0, 1 << 40, 4096, 77), mptr=0x1000),
           data=bytes(ctrl))
    # a command whose CQE never arrives, and a response with no command
    g.cmd(sqe(0x18, g.nextcid()))
    g.rsp(0x7777)
    g.c2h(0x7778, g.rnd(32))
    g.h2c(0x7779, g.rnd(32))

    # ---- I/O queue ---------------------------------------------------------
    g.port = IOQ
    cc = g.nextcid()
    g.xact(connect_cmd(cc, 1, cattr=0), inline=connect_data(g, hostnqn, subnqn, 1), dw0=0x00010003)
    for opc in (0x00, 0x01, 0x02, 0x04, 0x05, 0x08, 0x09, 0x0c, 0x0d, 0x0e, 0x11, 0x15, 0x7f, 0x80, 0xc1, 0xff):
        nl = r.randrange(0, 16)
        dw12 = nl | (r.getrandbits(4) << 26) | (r.getrandbits(1) << 30) | (r.getrandbits(1) << 31)
        s = sqe(opc, g.nextcid(), cdw10=r.getrandbits(32), cdw11=r.getrandbits(32), cdw12=dw12,
                cdw13=r.getrandbits(8) | (r.getrandbits(2) << 4), cdw14=r.getrandbits(32), cdw15=r.getrandbits(32),
                sgl=sgl_desc(r.choice((0, 4)), 0, 0x4000, 8192, 0x55))
        if opc in (0x02, 0x01):
            g.xact(s, data=g.rnd(512, 0.5) if opc == 2 else None, inline=g.rnd(512, 0.5) if opc == 1 else b'')
            g.xact(sqe(opc, g.nextcid(), cdw12=7 | (0xf << 26)), h2c=g.rnd(512, 0.5))
        else:
            g.xact(s)
    g.xact(sqe(0x02, g.nextcid(), cdw10=100, cdw12=0xffff), data=g.rnd(100), status=st(2, 0x81))
    g.xact(sqe(0x01, g.nextcid(), cdw10=100, cdw12=0xffff), status=st(0, 0x80, dnr=1))
    g.cmd(sqe(0x02, g.nextcid()))
    g.rsp(0x4444, status=st(1, 2))

    # ---- queue never connected: opcode picks the queue type ---------------
    g.port = NOCONN
    g.xact(sqe(0x02, 3, nsid=1, cdw12=7), data=g.rnd(64))
    g.xact(sqe(0x01, 4, nsid=1, cdw12=7), inline=g.rnd(64))

    # ---- stand-alone second pass over an admin queue without connect ------
    g.port = DISC
    g.xact(sqe(0x18, 1))
    g.xact(sqe(0x06, 2, cdw10=1), data=bytes(ctrl))
    g.xact(sqe(0x06, 0, cdw10=1), data=bytes(ctrl))
    g.xact(sqe(0x02, 0, cdw10=0x70 | (0x3ff << 16)), data=dl)


def build_repro(cap):
    """Reproducers of the bugs fixed on the branch."""
    # data_responses key shape: C2HData with CID 0 in frame 3, then CID 3
    g = Gen(cap, 40005, 11)
    g.cmd(sqe(0x02, 0))
    g.cmd(sqe(0x02, 3))
    g.c2h(0, bytes([0xaa] * 16))
    g.c2h(3, bytes([0xaa] * 16))
    g.rsp(0); g.rsp(3)
    # keyed SGL descriptor whose address looks like an H2CData key
    g = Gen(cap, 40006, 12)
    g.cmd(sqe(0x01, 5))
    g.h2c(5, bytes([0x55] * 16))
    g.cmd(sqe(0x01, 7, sgl=sgl_desc(4, 0, (5 << 32) | 2, 512, 0x1234)))
    g.rsp(5); g.rsp(7)
    # self test log index, RAB / MDTS shifts of 64 and more, large NUMD
    g = Gen(cap, 40007, 13)
    g.xact(sqe(0x18, 0x50))
    stl = bytes([0, 0, 0, 0]) + b''.join(bytes([0x10 + i]) + bytes(27) for i in range(3))
    g.xact(sqe(0x02, 1, cdw10=0x06 | (0x3ff << 16)), data=stl)
    idc = bytearray(4096)
    idc[72] = 200; idc[77] = 100
    g.xact(sqe(0x06, 2, cdw10=0x01), data=bytes(idc))
    idc[72] = 63; idc[77] = 0
    g.xact(sqe(0x06, 3, cdw10=0x01), data=bytes(idc))
    g.xact(sqe(0x02, 4, cdw10=0x02 | (0xffff << 16), cdw11=0xffff), data=bytes(512))
    # ANA header followed by a descriptor that carries fewer NSIDs than it declares
    g.xact(sqe(0x02, 5, cdw10=0x0c | (0x3ff << 16)),
           data=struct.pack('<QH6s', 1, 1, b'\0' * 6) +
           struct.pack('<IIQB15s', 0x77, 4, 2, 1, b'\0' * 15) + le32(0x101, 0x102))
    # Supported and Effects page longer than 2 KiB
    g.xact(sqe(0x02, 6, cdw10=0x05 | (0x3ff << 16)), data=bytes(2100))


def build_malformed(cap):
    g = Gen(cap, 41001, 7)
    r = g.r
    g.xact(sqe(0x18, 1))
    # more LBA formats than the list holds
    ns = bytearray(4096); ns[25] = 63; ns[82] = 5
    g.xact(sqe(0x06, 2, cdw10=0), data=bytes(ns))
    ns = bytearray(4096); ns[25] = 255; ns[82] = 255
    g.xact(sqe(0x06, 3, cdw10=0x08), data=bytes(ns))
    # transport length larger than the data
    cid = 4
    g.cmd(sqe(0x06, cid, cdw10=1))
    hdr = struct.pack('<BBBBI', 0x07, 0x04, 24, 24, 24 + 64)
    g.c.add(g.port, False, hdr + struct.pack('<HHII4s', cid, 0, 0, 4096, bytes(4)) + bytes(64))
    g.rsp(cid)
    cid = 5
    g.cmd(sqe(0x02, cid, cdw10=0x02 | (0x3ff << 16)))
    g.c.add(g.port, False, hdr[:0] + struct.pack('<BBBBI', 0x07, 0x04, 24, 24, 24 + 64) +
            struct.pack('<HHII4s', cid, 0, 0, 100000, bytes(4)) + bytes(64))
    g.rsp(cid)
    # log page windows that start in the middle of a record
    for lid in (0x00, 0x05, 0x12, 0x13):
        for lpo in (4 + 0, 0x1002, 1026):
            g.xact(sqe(0x02, g.nextcid(), cdw10=lid | (0xff << 16), cdw12=lpo | 1),
                   data=g.rnd(400))
    for lid in (0x12, 0x13, 0x00):
        g.xact(sqe(0x02, g.nextcid(), cdw10=lid | (0xff << 16), cdw12=2), data=g.rnd(400))
    # EOM that claims more descriptors than it holds
    for nd in (5, 1, 60000):
        hdr2 = bytearray(64)
        struct.pack_into('<I', hdr2, 20, 96)
        struct.pack_into('<H', hdr2, 24, nd)
        for ln in (0, 10, 100, 200):
            g.xact(sqe(0x02, g.nextcid(), cdw10=0x19 | (0x1f << 16)), data=bytes(hdr2) + g.rnd(ln))
            g.xact(sqe(0x02, g.nextcid(), cdw10=0x19 | (0x3ff << 16)), data=bytes(hdr2) + g.rnd(ln))
    # TCG security protocols with random data
    for secp in (1, 2):
        for spsp in (0, 1, 5):
            dw10 = (secp << 24) | (spsp << 8)
            g.xact(sqe(0x82, g.nextcid(), cdw10=dw10, cdw11=4096), data=g.rnd(200))
            g.xact(sqe(0x81, g.nextcid(), cdw10=dw10, cdw11=100), inline=g.rnd(100))
    # random payloads for every structure
    for cns in range(0x18):
        for ln in (3, 40, 100, 600, 4096):
            g.xact(sqe(0x06, g.nextcid(), cdw10=cns), data=g.rnd(ln, 0.9))
    for lid in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0a, 0x0b, 0x0c, 0x0e, 0x0f, 0x12, 0x13, 0x14, 0x19, 0x70, 0x80, 0x81):
        for lpo in (0, 4, 100, 1000, 4096):
            for ln in (3, 20, 70, 530):
                g.xact(sqe(0x02, g.nextcid(), cdw10=lid | (0x3ff << 16), cdw12=lpo), data=g.rnd(ln, 0.9))
    for fid in (3, 0x0c, 0x0e, 0x13, 0x16, 0x7d, 0x7e, 0x7f):
        for ln in (1, 5, 60, 70):
            g.xact(sqe(0x09, g.nextcid(), cdw10=fid), inline=g.rnd(ln, 0.9))
    # lpo overflow
    g.xact(sqe(0x02, g.nextcid(), cdw10=0x02 | (0xff << 16), cdw12=0xfffffff8, cdw13=0xffffffff), data=g.rnd(64))
    # truncated PDUs: capture ends in the middle of a command
    g.cmd(sqe(0x18, g.nextcid()))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    c = Cap()
    build_main(c)
    build_repro(c)
    # The committed capture has the namespace ID of every command capsule with opcode 0x18
    # (Keep Alive) set to 0 by a later edit, which left the TCP checksum of those frames
    # as it was.  Do the same.
    for k, p in enumerate(c.pkts):
        if len(p) >= 70 and p[54] == 4 and p[62] == 0x18:
            c.pkts[k] = p[:66] + bytes(4) + p[70:]
    c.write(os.path.join(out, 'nvme-coverage.pcap'))
    print('main frames:', len(c.pkts))
    m = Cap()
    build_malformed(m)
    m.write(os.path.join(out, 'nvme-coverage-malformed.pcap'))
    print('malformed frames:', len(m.pkts))


main()
