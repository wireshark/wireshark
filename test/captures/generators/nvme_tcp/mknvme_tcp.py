#!/usr/bin/env python3
# Generates test/captures/nvme_tcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-nvme-tcp.c (NVMe/TCP transport).

    python3 mknvme_tcp.py <outdir> [-v]

writes nvme-tcp-coverage.pcap (decodes cleanly) and
nvme-tcp-coverage-malformed.pcap.  All addresses are made up
(192.0.2.0/24, 02:00:00:00:00:xx).  -v prints the frame ranges.

Every NVMe/TCP PDU type is built with struct.  The PDU header and data
digests are CRC32C values computed here (no keys, no crypto).
"""
import struct
import sys

HOST_MAC = bytes.fromhex('020000000001')
CTRL_MAC = bytes.fromhex('020000000002')
HOST_IP = bytes([192, 0, 2, 1])
CTRL_IP = bytes([192, 0, 2, 2])


# ------------------------------------------------------------------ crc32c
def _mk_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0x82F63B78 if c & 1 else 0)
        t.append(c)
    return t


_T = _mk_table()


def crc32c(data):
    c = 0xffffffff
    for b in data:
        c = _T[(c ^ b) & 0xff] ^ (c >> 8)
    return c ^ 0xffffffff


def digest(data, endian='<'):
    return struct.pack(endian + 'I', crc32c(data))


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


FRAMES = []
MARKS = []


def mark(name):
    MARKS.append((len(FRAMES) + 1, name))


class Conn:
    """one TCP connection host:hport -> controller:cport"""

    def __init__(self, hport, cport=4420, frames=None):
        self.hport, self.cport = hport, cport
        self.seq = {True: 1000 + hport, False: 5000 + hport}
        self.frames = FRAMES if frames is None else frames

    def raw(self, to_ctrl, payload, flags=0x18):
        src_ip, dst_ip = (HOST_IP, CTRL_IP) if to_ctrl else (CTRL_IP, HOST_IP)
        sp, dp = (self.hport, self.cport) if to_ctrl else (self.cport, self.hport)
        s, a = self.seq[to_ctrl], self.seq[not to_ctrl]
        if not flags & 0x10:
            a = 0
        opt = b'\x02\x04\xff\xd7\x04\x02\x01\x01' if flags & 2 else b''
        tcp = struct.pack('!HHIIBBHHH', sp, dp, s, a, (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt
        ph = src_ip + dst_ip + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        ph = src_ip + dst_ip + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        self.seq[to_ctrl] += len(payload) + (1 if flags & 3 else 0)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 1, 0,
                         64, 6, 0, src_ip, dst_ip)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        eth = (CTRL_MAC + HOST_MAC if to_ctrl else HOST_MAC + CTRL_MAC) + b'\x08\x00'
        self.frames.append(eth + ip + tcp + payload)

    def handshake(self):
        self.raw(True, b'', 0x02)
        self.raw(False, b'', 0x12)
        self.raw(True, b'', 0x10)

    def send(self, to_ctrl, pdu):
        self.raw(to_ctrl, pdu)

    def split(self, to_ctrl, pdu, cuts):
        """one PDU over several TCP segments"""
        p = 0
        for c in list(cuts) + [len(pdu)]:
            self.raw(to_ctrl, pdu[p:c])
            p = c


# --------------------------------------------------------------------- PDUs
F_HDGST, F_DDGST, F_LAST, F_SUCCESS = 1, 2, 4, 8


def pdu(ptype, flags, hlen, psh, data=b'', pdo=None, hdgst=False, ddgst=False,
        bad_hdgst=False, bad_ddgst=False, endian='<'):
    """common header + PSH (padded to hlen) [+ hdgst] [+ data [+ ddgst]]"""
    if hdgst:
        flags |= F_HDGST
    if ddgst and data:
        flags |= F_DDGST
    head_len = hlen
    hd = 4 if hdgst else 0
    if pdo is None:
        pdo = (hlen + hd) if data else 0
    plen = hlen + hd + len(data) + (4 if (ddgst and data) else 0)
    hdr = struct.pack('<BBBBI', ptype, flags, hlen, pdo, plen)
    body = psh.ljust(hlen - 8, b'\0')
    out = hdr + body
    if hdgst:
        d = digest(out, endian)
        if bad_hdgst:
            d = bytes(b ^ 0xff for b in d)
        out += d
    out += data
    if ddgst and data:
        d = digest(data, endian)
        if bad_ddgst:
            d = bytes(b ^ 0xff for b in d)
        out += d
    return out


def icreq(pfv=0, hpda=0, dgst=0, maxr2t=3, **kw):
    return pdu(0, 0, 128, struct.pack('<HBBI', pfv, hpda, dgst, maxr2t), **kw)


def icresp(pfv=0, cpda=0, dgst=0, maxdata=0x20000, **kw):
    return pdu(1, 0, 128, struct.pack('<HBBI', pfv, cpda, dgst, maxdata), **kw)


def termreq(h2c, fes, fei=0, data=b'', plen=None):
    t = 2 if h2c else 3
    psh = struct.pack('<HI', fes, fei)
    p = pdu(t, 0, 24, psh, data)
    if plen is not None:
        # HLEN 8 so that PLEN - HLEN does not wrap
        p = p[:2] + b'\x08' + p[3:4] + struct.pack('<I', plen) + p[8:]
    return p


def sqe(opcode, cid, nsid=1, sgl=None, cdw10=0, cdw11=0, cdw12=0, cdw13=0,
        cdw14=0, cdw15=0, extra=None):
    b = bytearray(64)
    b[0] = opcode
    struct.pack_into('<H', b, 2, cid)
    struct.pack_into('<I', b, 4, nsid)
    if sgl is not None:
        b[24:40] = sgl
    struct.pack_into('<IIIIII', b, 40, cdw10, cdw11, cdw12, cdw13, cdw14, cdw15)
    for off, v in (extra or {}).items():
        b[off:off + len(v)] = v
    return bytes(b)


def sgl_inline(n):
    """SGL Data Block, offset sub type"""
    return struct.pack('<Q', 0) + n.to_bytes(4, 'little') + b'\0\0\0' + b'\x01'


def sgl_tcp(n):
    """Transport SGL Data Block, transport specific sub type"""
    return struct.pack('<Q', 0) + n.to_bytes(4, 'little') + b'\0\0\0' + b'\x5a'


def sgl_keyed(addr, n, key):
    return struct.pack('<Q', addr) + n.to_bytes(3, 'little') + struct.pack('<I', key) + b'\x40'


def cmd_pdu(s, data=b'', **kw):
    return _cmd(s, data, **kw)


def _cmd(s, data=b'', hdgst=False, ddgst=False, pdo=None, **kw):
    # the 64 byte SQE is the PSH of the 72 byte header
    return pdu(4, 0, 72, s, data, hdgst=hdgst, ddgst=ddgst, pdo=pdo, **kw)


def cqe(cid, dw0=0, dw1=0, sqhd=0, sqid=0, status=0):
    return struct.pack('<IIHHHH', dw0, dw1, sqhd, sqid, cid, status)


def rsp_pdu(cid, dw0=0, dw1=0, status=0, sqid=0, **kw):
    return pdu(5, 0, 24, cqe(cid, dw0, dw1, 0, sqid, status), **kw)


def data_pdu(ptype, cid, data, off=0, total=None, ttag=0, flags=F_LAST, **kw):
    psh = struct.pack('<HHII4s', cid, ttag, off, len(data), b'\0' * 4)
    return pdu(ptype, flags, 24, psh, data, pdo=None, **kw)


def c2h_pdu(cid, data, **kw):
    return data_pdu(7, cid, data, **kw)


def h2c_pdu(cid, data, **kw):
    return data_pdu(6, cid, data, **kw)


def r2t_pdu(cid, ttag, off, length):
    return pdu(9, 0, 24, struct.pack('<HHII4s', cid, ttag, off, length, b'\0' * 4))


def fill(n, seed=1):
    return bytes(((seed * 37 + i * 7 + (i >> 3)) & 0xff) for i in range(n))


def connect_data(subnqn=b'nqn.2014-08.org.example:subsys1', hostnqn=b'nqn.2014-08.org.example:host1', cntlid=0xffff):
    d = bytes(range(16)) + struct.pack('<H', cntlid) + b'\0' * 238
    d += subnqn.ljust(256, b'\0') + hostnqn.ljust(256, b'\0') + b'\0' * 256
    return d


def fabric(fctype, cid, extra=None, sgl=None):
    e = {4: bytes([fctype])}
    e.update(extra or {})
    return sqe(0x7f, cid, nsid=0, sgl=sgl, extra=e)


def connect_sqe(cid, qid, sqsize=31, kato=0, sgl=None, cattr=0):
    return fabric(1, cid, {40: struct.pack('<HHHBB', 0, qid, sqsize, cattr, 0),
                           48: struct.pack('<I', kato)}, sgl=sgl)


def propget(cid, off, size8=False):
    return fabric(4, cid, {40: bytes([1 if size8 else 0]), 44: struct.pack('<I', off)})


def propset(cid, off, val, size8=False):
    return fabric(0, cid, {40: bytes([1 if size8 else 0]), 44: struct.pack('<I', off),
                           48: struct.pack('<Q', val)})


# ------------------------------------------------------------ identify data
def ident_ctrl():
    d = bytearray(4096)
    struct.pack_into('<HH', d, 0, 0x1b36, 0x1b36)
    d[4:24] = b'SYNTH0001'.ljust(20)
    d[24:64] = b'Synthetic NVMe controller'.ljust(40)
    d[64:72] = b'1.0'.ljust(8)
    d[72] = 6
    d[73:76] = b'\x00\xa0\x98'
    d[77] = 5
    struct.pack_into('<HH', d, 78, 1, 0xffff)
    struct.pack_into('<I', d, 80, 0x00010400)
    d[256:258] = struct.pack('<H', 0x7)
    d[512] = 0x66
    d[513] = 0x44
    struct.pack_into('<H', d, 514, 128)
    struct.pack_into('<I', d, 516, 1024)
    d[768:768 + 31] = b'nqn.2014-08.org.example:subsys1'
    return bytes(d)


def ident_ns():
    d = bytearray(4096)
    struct.pack_into('<QQQ', d, 0, 1 << 20, 1 << 20, 1 << 19)
    d[25] = 0
    d[26] = 0
    d[128:132] = struct.pack('<HBB', 0, 9, 0)
    return bytes(d)


def nslist(n):
    d = bytearray(4096)
    for i in range(n):
        struct.pack_into('<I', d, i * 4, i + 1)
    return bytes(d)


# ------------------------------------------------------------------- build
def build():
    # ---- connection 1: admin queue, no digests, fabrics commands
    c = Conn(40001)
    mark('admin queue: handshake, ICReq/ICResp, Fabrics Connect with data, '
         'Property Get/Set (all property offsets and sizes), Fabrics commands')
    c.handshake()
    c.send(True, icreq())
    c.send(False, icresp())
    cdata = connect_data()
    c.send(True, _cmd(connect_sqe(1, 0, sqsize=31, kato=30000, sgl=sgl_inline(1024),
                                  cattr=0x0f), cdata))
    c.send(False, rsp_pdu(1, dw0=0x00010001, dw1=0, status=0))
    c.send(True, _cmd(propget(2, 0x00, True)))
    c.send(False, rsp_pdu(2, dw0=0x0200003c, dw1=0x00000020))
    c.send(True, _cmd(propget(3, 0x08)))
    c.send(False, rsp_pdu(3, dw0=0x00010400))
    c.send(True, _cmd(propget(4, 0x14)))
    c.send(False, rsp_pdu(4, dw0=0x00460001))
    c.send(True, _cmd(propget(5, 0x1c)))
    c.send(False, rsp_pdu(5, dw0=1))
    c.send(True, _cmd(propget(6, 0x20)))
    c.send(False, rsp_pdu(6, dw0=0))
    c.send(True, _cmd(propget(7, 0x30, False)))      # not a known property
    c.send(False, rsp_pdu(7, dw0=0xdeadbeef, status=0x2))
    c.send(True, _cmd(propget(8, 0x38, True)))       # unknown, 8 byte
    c.send(False, rsp_pdu(8, dw0=0x11, dw1=0x22))
    c.send(True, _cmd(propset(9, 0x14, 0x00460001)))
    c.send(False, rsp_pdu(9))
    c.send(True, _cmd(propset(10, 0x20, 0x4e564d65)))
    c.send(False, rsp_pdu(10))
    c.send(True, _cmd(propset(11, 0x44, 0x1234, True)))
    c.send(False, rsp_pdu(11, status=0x6))
    c.send(True, _cmd(fabric(5, 12, {41: b'\x01', 42: b'\x02', 43: b'\xea', 44: struct.pack('<I', 64)},
                             sgl=sgl_inline(64)), fill(64, 2)))     # Authentication Send
    c.send(False, rsp_pdu(12))
    c.send(True, _cmd(fabric(6, 13, {41: b'\x01', 43: b'\xea', 44: struct.pack('<I', 64)},
                             sgl=sgl_tcp(64))))            # Authentication Receive
    c.send(False, rsp_pdu(13))
    c.send(True, _cmd(fabric(0x77, 14)))                    # unknown fabrics command
    c.send(False, rsp_pdu(14, dw0=0x1234567890 & 0xffffffff, dw1=7, status=0x1))
    c.send(True, _cmd(fabric(8, 15, {40: struct.pack('<H', 0)})))    # Disconnect
    c.send(False, rsp_pdu(15))

    mark('admin queue: Identify (controller, namespace, namespace list), '
         'Get Log Page, Get/Set Features, Keep Alive, AER, Create IO queues')
    c.send(True, _cmd(sqe(0x06, 20, nsid=0, cdw10=1, sgl=sgl_tcp(4096))))
    c.send(False, c2h_pdu(20, ident_ctrl()))
    c.send(False, rsp_pdu(20))
    c.send(True, _cmd(sqe(0x06, 21, nsid=1, cdw10=0, sgl=sgl_tcp(4096))))
    c.send(False, c2h_pdu(21, ident_ns()))
    c.send(False, rsp_pdu(21))
    c.send(True, _cmd(sqe(0x06, 22, nsid=0, cdw10=2, sgl=sgl_tcp(4096))))
    c.send(False, c2h_pdu(22, nslist(3)))
    c.send(False, rsp_pdu(22))
    c.send(True, _cmd(sqe(0x02, 23, nsid=0xffffffff, cdw10=0x01 | (0x7f << 16), sgl=sgl_tcp(512))))
    c.send(False, c2h_pdu(23, fill(512, 3)))
    c.send(False, rsp_pdu(23))
    c.send(True, _cmd(sqe(0x02, 24, nsid=0xffffffff, cdw10=0x02 | (0x7f << 16), sgl=sgl_tcp(512))))
    c.send(False, c2h_pdu(24, bytes(512)))
    c.send(False, rsp_pdu(24))
    c.send(True, _cmd(sqe(0x02, 25, nsid=0xffffffff, cdw10=0x03 | (0x3f << 16), sgl=sgl_tcp(256))))
    c.send(False, c2h_pdu(25, fill(256, 4)))
    c.send(False, rsp_pdu(25))
    c.send(True, _cmd(sqe(0x0a, 26, nsid=0, cdw10=0x07, sgl=sgl_tcp(0))))     # Get Features number of queues
    c.send(False, rsp_pdu(26, dw0=0x001f001f))
    c.send(True, _cmd(sqe(0x09, 27, nsid=0, cdw10=0x07, cdw11=0x001f001f)))   # Set Features
    c.send(False, rsp_pdu(27, dw0=0x001f001f))
    c.send(True, _cmd(sqe(0x18, 28, nsid=0)))                                # Keep Alive
    c.send(False, rsp_pdu(28))
    c.send(True, _cmd(sqe(0x0c, 29, nsid=0)))                                # Async Event Request
    c.send(True, _cmd(sqe(0x05, 30, nsid=0, cdw10=0x001f0001, cdw11=3)))     # Create IO CQ
    c.send(False, rsp_pdu(30))
    c.send(True, _cmd(sqe(0x01, 31, nsid=0, cdw10=0x001f0001, cdw11=0x00010001)))  # Create IO SQ
    c.send(False, rsp_pdu(31))
    c.send(False, rsp_pdu(29, dw0=0x00010101))                               # AER completes
    c.send(False, rsp_pdu(29))                                               # second CQE for a completed command
    # Set Features with data inline and a data digest-less capsule
    c.send(True, _cmd(sqe(0x09, 32, nsid=1, cdw10=0x03, sgl=sgl_inline(64)), fill(64, 5)))
    c.send(False, rsp_pdu(32))

    # ---- connection 2: I/O queue 1 with header and data digests
    c = Conn(40002)
    mark('I/O queue 1 with header and data digests: Connect with digests, '
         'Read/Write/Flush/Compare/Dataset Management/Write Zeroes, C2HData '
         '(single, split, SUCCESS flag), R2T and H2CData, inline data')
    c.handshake()
    c.send(True, icreq(dgst=3, hpda=1))
    c.send(False, icresp(dgst=3, cpda=1))
    c.send(True, _cmd(connect_sqe(0, 1, sgl=sgl_inline(1024)), cdata, hdgst=True, ddgst=True))
    c.send(False, rsp_pdu(0, dw0=0x00010001, hdgst=True, sqid=1))
    # read, one C2HData with the SUCCESS flag (no response PDU)
    c.send(True, _cmd(sqe(0x02, 1, cdw10=0, cdw12=7, sgl=sgl_tcp(4096)), hdgst=True))
    c.send(False, c2h_pdu(1, fill(512, 6), flags=F_LAST | F_SUCCESS, hdgst=True, ddgst=True))
    # read, three C2HData PDUs and a response
    c.send(True, _cmd(sqe(0x02, 2, cdw10=8, cdw12=15, sgl=sgl_tcp(8192)), hdgst=True))
    for i in range(3):
        c.send(False, c2h_pdu(2, fill(256, 7 + i), off=i * 256, total=768,
                              flags=(F_LAST if i == 2 else 0), hdgst=True, ddgst=True))
    c.send(False, rsp_pdu(2, hdgst=True, sqid=1))
    # one C2HData PDU over three TCP segments
    c.send(True, _cmd(sqe(0x02, 3, cdw10=64, cdw12=7, sgl=sgl_tcp(4096)), hdgst=True))
    big = c2h_pdu(3, fill(1024, 9), hdgst=True, ddgst=True)
    c.split(False, big, [10, 400])
    c.send(False, rsp_pdu(3, hdgst=True, sqid=1))
    # write with R2T and two H2CData
    c.send(True, _cmd(sqe(0x01, 4, cdw10=128, cdw12=7, sgl=sgl_tcp(1024)), hdgst=True))
    c.send(False, r2t_pdu(4, 5, 0, 512))
    c.send(True, h2c_pdu(4, fill(512, 10), ttag=5, hdgst=True, ddgst=True, flags=0))
    c.send(False, r2t_pdu(4, 6, 512, 512))
    c.send(True, h2c_pdu(4, fill(512, 11), ttag=6, off=512, total=512, hdgst=True, ddgst=True))
    c.send(False, rsp_pdu(4, hdgst=True, sqid=1))
    # write with in-capsule data and digests
    c.send(True, _cmd(sqe(0x01, 5, cdw10=256, cdw12=0, sgl=sgl_inline(512)), fill(512, 12),
                      hdgst=True, ddgst=True))
    c.send(False, rsp_pdu(5, hdgst=True, sqid=1))
    # in-capsule data with header digest only
    c.send(True, _cmd(sqe(0x01, 6, cdw10=300, cdw12=0, sgl=sgl_inline(512)), fill(512, 13),
                      hdgst=True))
    c.send(False, rsp_pdu(6, hdgst=True, sqid=1))
    for cid, op in ((7, 0x00), (8, 0x05), (9, 0x09), (10, 0x08), (11, 0x0c), (12, 0x04)):
        c.send(True, _cmd(sqe(op, cid, cdw10=1000, cdw12=3, sgl=sgl_tcp(0)), hdgst=True))
        c.send(False, rsp_pdu(cid, hdgst=True, sqid=1, status=0x0 if op != 0x04 else 0x2))
    # Dataset Management with a range list sent as in-capsule data
    c.send(True, _cmd(sqe(0x09, 13, cdw10=0, cdw11=4, sgl=sgl_inline(16)),
                      struct.pack('<IIQ', 0, 8, 100), hdgst=True, ddgst=True))
    c.send(False, rsp_pdu(13, hdgst=True, sqid=1))
    # a command whose response arrives twice, and responses and data PDUs
    # that match no command
    c.send(True, _cmd(sqe(0x02, 14, cdw12=0, sgl=sgl_tcp(512)), hdgst=True))
    c.send(False, rsp_pdu(14, hdgst=True, sqid=1))
    c.send(False, rsp_pdu(14, hdgst=True, sqid=1))
    c.send(False, rsp_pdu(99, hdgst=True, sqid=1))
    c.send(False, c2h_pdu(98, fill(32, 1), hdgst=True))
    c.send(True, h2c_pdu(97, fill(32, 2), hdgst=True))
    # H2CData and C2HData for a Fabrics command
    c.send(True, _cmd(propget(15, 0x08), hdgst=True))
    c.send(True, h2c_pdu(15, fill(16, 3), hdgst=True))
    c.send(False, c2h_pdu(15, fill(16, 4), hdgst=True))
    c.send(False, rsp_pdu(15, dw0=0x10400, hdgst=True, sqid=1))
    # header digest only, with a header-digest PDU split after the header
    c.send(True, _cmd(sqe(0x02, 16, cdw12=0, sgl=sgl_tcp(512)), hdgst=True))
    c.split(False, c2h_pdu(16, fill(256, 4), hdgst=True, ddgst=True), [8, 24, 28])
    c.send(False, rsp_pdu(16, hdgst=True, sqid=1))

    # ---- connection 3: port 8009 (discovery), termination requests, ICReq variants
    c = Conn(40003, 8009)
    mark('port 8009: ICReq/ICResp variants, Termination Requests (every '
         'FES, with and without data), Kickstart Discovery PDUs and a PDU type above the known ones, a Discovery Get Log Page')
    c.handshake()
    c.send(True, icreq(pfv=0, hpda=31, dgst=1, maxr2t=0))
    c.send(False, icresp(pfv=0, cpda=31, dgst=2, maxdata=0xfffc))
    c.send(True, icreq(pfv=1, hpda=0, dgst=2, maxr2t=0xffffffff))
    c.send(False, termreq(False, 1, 0x0000000c, fill(24, 1)))      # Invalid PDU Header Field
    c.send(True, termreq(True, 1, 0x00000002, fill(24, 2)))
    c.send(False, termreq(False, 2, 0))                              # PDU Sequence Error
    c.send(True, termreq(True, 2, 0, fill(24, 3)))
    c.send(False, termreq(False, 3, 0x0badc0de, fill(72, 4)))     # Header Digest Error
    c.send(True, termreq(True, 3, 0x12345678, fill(72, 5)))
    c.send(False, termreq(False, 4, 0, b''))
    c.send(True, termreq(True, 5, 0, b''))
    c.send(False, termreq(False, 6, 0x00000004, fill(24, 6)))      # Unsupported Parameter
    c.send(True, termreq(True, 6, 0x00000008, fill(24, 7)))
    c.send(False, termreq(False, 0, 0, b''))                       # Reserved
    c.send(True, termreq(True, 0x77, 0xabcdef01, b''))
    # Kickstart Discovery Request / Response (not decoded, shown as data)
    c.send(True, pdu(0xa, 0, 24, struct.pack('<HHII', 0, 0, 0, 0)))
    c.send(False, pdu(0xb, 0, 24, struct.pack('<HHII', 0, 0, 0, 0), fill(16, 8)))
    # PDU types above 0xb are rejected by the heuristic, an unknown type
    # that passes it cannot be sent: 0xc is above NVMET_MAX_PDU_TYPE
    c.send(True, pdu(0xc, 0, 24, b'\0' * 16))
    # a Discovery connection: Connect on the admin queue, Get Log Page
    # (discovery log) as C2HData
    c.send(True, _cmd(connect_sqe(1, 0, sgl=sgl_inline(1024)), connect_data(b'nqn.2014-08.org.nvmexpress.discovery')))
    c.send(False, rsp_pdu(1, dw0=0x00010001))
    dlog = struct.pack('<QQQ', 1, 1, 0).ljust(1024, b'\0')
    c.send(True, _cmd(sqe(0x02, 2, nsid=0, cdw10=0x70 | (0xff << 16), sgl=sgl_tcp(1024))))
    c.send(False, c2h_pdu(2, dlog))
    c.send(False, rsp_pdu(2))

    # ---- connection 4: two PDUs in one segment, PDUs split at odd places
    c = Conn(40004)
    mark('stream handling: two and three PDUs in one TCP segment, a PDU split '
         'after 3 octets and in the middle of the SQE, a connection that starts '
         'mid-PDU and a connection that does not look like NVMe/TCP')
    c.handshake()
    c.raw(True, icreq() + _cmd(connect_sqe(1, 0, sgl=sgl_inline(1024)), cdata))
    c.raw(False, icresp() + rsp_pdu(1, dw0=0x00010001))
    c.raw(True, _cmd(sqe(0x18, 2, nsid=0)) + _cmd(sqe(0x18, 3, nsid=0)) + _cmd(sqe(0x18, 4, nsid=0)))
    c.raw(False, rsp_pdu(2) + rsp_pdu(3) + rsp_pdu(4))
    c.split(True, _cmd(sqe(0x06, 5, nsid=0, cdw10=1, sgl=sgl_tcp(4096))), [3, 30])
    c.raw(False, c2h_pdu(5, ident_ctrl())[:2000])
    c.raw(False, c2h_pdu(5, ident_ctrl())[2000:] + rsp_pdu(5))
    # stream that starts in the middle of a PDU (no connection setup seen)
    c = Conn(40005)
    c.raw(True, _cmd(sqe(0x02, 1, cdw12=0, sgl=sgl_tcp(512)))[20:])
    c.raw(True, _cmd(sqe(0x02, 2, cdw12=0, sgl=sgl_tcp(512))))
    # the heuristic rejects: fewer than 8 octets, HLEN below 8, PLEN below 8
    c = Conn(40007)
    c.raw(True, bytes([0x04, 0x00, 0x48, 0x00, 0x48]))
    c = Conn(40008)
    c.raw(True, bytes([0x04, 0x00, 0x04, 0x00]) + struct.pack('<I', 72) + fill(64, 1))
    c = Conn(40009)
    c.raw(True, bytes([0x04, 0x00, 0x48, 0x00]) + struct.pack('<I', 4) + fill(64, 1))
    # a stream that is not NVMe/TCP at all (TLS looking record)
    c = Conn(40006)
    c.raw(True, b'\x16\x03\x01\x00\x20' + fill(32, 1))
    c.raw(False, b'\x16\x03\x03\x00\x20' + fill(32, 2))

    # ---- fixed bugs (reproducers) ----
    mark('reproducer: C2HData with command ID 0 and later command ID N '
         '(nvme-tcp_tree_key_collision): the data_responses key shape')
    c = Conn(40010)
    c.handshake()
    c.send(True, _cmd(sqe(0x02, 0, cdw12=0)))
    c.send(True, _cmd(sqe(0x02, 3, cdw12=0)))
    c.send(False, c2h_pdu(0, fill(16, 1)))
    c.send(False, c2h_pdu(3, fill(16, 2)))
    c.send(False, rsp_pdu(0))
    c.send(False, rsp_pdu(3))
    mark('reproducer: H2CData request tree and keyed SGL (nvme-tcp_data_req_collision)')
    c = Conn(40011)
    c.handshake()
    c.send(True, _cmd(sqe(0x01, 3, cdw12=0)))
    c.send(True, h2c_pdu(3, fill(16, 1)))
    c.send(True, _cmd(sqe(0x01, 5, cdw12=0, sgl=sgl_keyed(0x00000003_00000002, 0x1000, 0x1234))))
    c.send(False, rsp_pdu(3))
    c.send(False, rsp_pdu(5))
    mark('keyed SGL descriptors with matching data requests')
    c = Conn(40012)
    c.handshake()
    c.send(True, _cmd(sqe(0x01, 1, cdw12=0, sgl=sgl_keyed(0x1000, 0x200, 0x77))))
    c.send(True, _cmd(sqe(0x01, 2, cdw12=0, sgl=sgl_keyed(0x2000, 0x200, 0x78))))
    c.send(True, h2c_pdu(1, fill(32, 1)))
    c.send(True, h2c_pdu(2, fill(32, 2)))
    c.send(False, rsp_pdu(1))
    c.send(False, rsp_pdu(2))


def build_malformed():
    global FRAMES, MARKS
    FRAMES, MARKS = [], []
    cdata = connect_data()
    port = [41000]

    def conn(admin_first=True):
        port[0] += 1
        c = Conn(port[0])
        c.handshake()
        if admin_first:
            c.send(True, icreq())
        return c

    mark('Termination Requests whose PLEN is shorter than the 24 octet header '
         '(one connection each, the frame ends at PLEN): the error expert info')
    for h2c, plen in ((False, 8), (True, 16), (False, 23), (True, 9)):
        c = conn()
        c.send(h2c, termreq(h2c, 1, 0, plen=plen)[:plen])
    mark('PLEN shorter than HLEN plus the header digest (incapsulated data size wraps), '
         'DDGST flag with no room for data (data of exactly four octets, and a cut PDU)')
    c = conn()
    p = _cmd(sqe(0x18, 2, nsid=0), hdgst=True)
    c.send(True, p[:4] + struct.pack('<I', 40) + p[8:])
    c = conn()
    p = _cmd(sqe(0x18, 2, nsid=0))
    c.send(True, p[:4] + struct.pack('<I', 40) + p[8:48])   # PLEN below HLEN: unknown data
    c = conn()
    p = _cmd(sqe(0x01, 4, cdw12=0, sgl=sgl_inline(4)), b'abcd', ddgst=True)
    c.send(True, p)
    c = conn()
    p = _cmd(sqe(0x01, 3, cdw12=0, sgl=sgl_inline(4)), b'abcd', ddgst=True)
    c.send(True, p[:4] + struct.pack('<I', 76) + p[8:76])
    mark('bad header and data digests (flagged with the check preferences), '
         'digests in big endian byte order')
    c = conn()
    c.send(True, _cmd(sqe(0x01, 5, cdw12=0, sgl=sgl_inline(64)), fill(64, 1), hdgst=True,
                      ddgst=True, bad_hdgst=True, bad_ddgst=True))
    c.send(False, rsp_pdu(5, hdgst=True, bad_hdgst=True))
    c.send(True, _cmd(sqe(0x01, 6, cdw12=0, sgl=sgl_inline(64)), fill(64, 2), hdgst=True,
                      ddgst=True, endian='>'))
    c.send(False, rsp_pdu(6, hdgst=True, endian='>'))
    mark('truncated PDUs (capture shorter than PLEN) in the middle of the '
         'capsule, C2HData data and CQE')
    c = conn(False)
    c.send(True, _cmd(connect_sqe(1, 0, sgl=sgl_inline(1024)), cdata))
    c.send(False, rsp_pdu(1))
    c.send(True, _cmd(sqe(0x06, 2, nsid=0, cdw10=1)))
    c.send(False, c2h_pdu(2, fill(100, 1))[:60])
    c.send(False, rsp_pdu(2)[:12])
    c = conn()
    c.send(True, _cmd(sqe(0x01, 7, cdw12=0, sgl=sgl_inline(64)), fill(64, 3))[:50])
    c = conn()
    c.send(True, bytes([0x0f, 0, 24, 0]) + struct.pack('<I', 24) + b'\0' * 16)
    c.send(False, pdu(7, 4, 24, struct.pack('<HHII', 77, 0, 0, 5000), b'x' * 16))
    c = conn()
    # C2HData whose data length is more than the PDU carries, for a pending command
    c.send(True, _cmd(sqe(0x02, 9, cdw12=0, sgl=sgl_tcp(512))))
    c.send(False, c2h_pdu(9, fill(32, 1))[:8] + struct.pack('<HHII4s', 9, 0, 0, 5000, b'\0' * 4) + fill(32, 1))
    mark('reproducer (unfixed observation): queue id guessed per pass, nvme-tcp_qid_two_pass')
    c = Conn(41990)
    c.handshake()
    c.send(True, _cmd(sqe(0x02, 1, cdw12=0)))
    c.send(True, _cmd(connect_sqe(7, 0)))
    c.send(False, rsp_pdu(1))
    c.send(False, rsp_pdu(7))


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 100, (i % 100) * 1000, len(p), len(p)))
            f.write(p)


def report(name):
    for i, (n, s) in enumerate(MARKS):
        e = MARKS[i + 1][0] - 1 if i + 1 < len(MARKS) else len(FRAMES)
        print('%s %d-%d: %s' % (name, n, e, s))


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    build()
    write_pcap(out + '/nvme-tcp-coverage.pcap', FRAMES)
    if '-v' in sys.argv:
        report('main')
    print('main: %d frames' % len(FRAMES))
    build_malformed()
    write_pcap(out + '/nvme-tcp-coverage-malformed.pcap', FRAMES)
    if '-v' in sys.argv:
        report('malformed')
    print('malformed: %d frames' % len(FRAMES))
