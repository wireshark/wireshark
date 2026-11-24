#!/usr/bin/env python3
# Generates test/captures/nvme_rdma_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-nvme-rdma.c (NVMe over RDMA, InfiniBand).

    python3 mknvme_rdma.py <outdir> [-v]

writes nvme-rdma-coverage.pcap (decodes cleanly) and
nvme-rdma-coverage-malformed.pcap.  All addresses are made up
(192.0.2.0/24, 02:00:00:00:00:xx).  -v prints the frame ranges.

The frames are RoCE v2 (UDP 4791) over Ethernet.  The RDMA CM exchange
(REQ with an IP CM service id for TCP port 4420, REP, RTU) creates the
InfiniBand conversations that packet-nvme-rdma.c needs; the NVMe commands
travel in RC SEND, the data in RDMA READ/WRITE.  Only struct is used.
"""
import struct
import sys

MAC1 = bytes.fromhex('020000000001')
MAC2 = bytes.fromhex('020000000002')
IP4A = bytes([192, 0, 2, 1])
IP4B = bytes([192, 0, 2, 2])
IP4C = bytes([192, 0, 2, 3])
ICRC = b'\x00' * 4

FRAMES = []
MARKS = []


def mark(name):
    MARKS.append((len(FRAMES) + 1, name))


def fill(n, seed=1):
    return bytes(((seed * 37 + i * 7 + (i >> 3)) & 0xff) for i in range(n))


# ------------------------------------------------------------ IB headers
RC_SEND_FIRST, RC_SEND_MIDDLE, RC_SEND_LAST, RC_SEND_ONLY = 0, 1, 2, 4
RC_WRITE_FIRST, RC_WRITE_MIDDLE, RC_WRITE_LAST, RC_WRITE_ONLY = 6, 7, 8, 10
RC_READ_REQ = 12
RC_READ_RESP_FIRST, RC_READ_RESP_MIDDLE, RC_READ_RESP_LAST, RC_READ_RESP_ONLY = 13, 14, 15, 16
RC_ACK = 17
RC_SEND_ONLY_INVAL = 23
UD_SEND_ONLY = 100


def bth(op, dqp, psn=0, pad=0):
    return (struct.pack('>BBHB', op, pad << 4, 0xffff, 0) + dqp.to_bytes(3, 'big')
            + b'\x00' + psn.to_bytes(3, 'big'))


def reth(va, rkey, ln):
    return struct.pack('>QII', va, rkey, ln)


def aeth(synd=0, msn=1):
    return bytes([synd]) + msn.to_bytes(3, 'big')


def ieth(v=0x55aa55aa):
    return struct.pack('>I', v)


def deth(sqp, qkey=0x80010000):
    return struct.pack('>IB', qkey, 0) + sqp.to_bytes(3, 'big')


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def rr4(ibpart, src=IP4A, dst=IP4B):
    """RoCE v2 over IPv4: BTH ... payload ICRC"""
    payload = ibpart + ICRC
    u = struct.pack('>HHHH', 49152, 4791, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return MAC2 + MAC1 + struct.pack('>H', 0x0800) + ip + u


def E(frame):
    FRAMES.append(frame)


# ----------------------------------------------------------------- CM MADs
def mad(cls, method, attr, tid, data, status=0):
    h = struct.pack('>BBBBHHQHHI', 1, cls, 1, method, status, 0, tid, attr, 0, 0)
    return h + data.ljust(232, b'\0')[:232]


def ud_mad(m, dqp=1, sqp=1):
    return bth(UD_SEND_ONLY, dqp) + deth(sqp) + m


def cm_req(comm_id, sid, qpn, llid, rlid, lgid, rgid, priv=b''):
    d = bytearray(232)
    struct.pack_into('>I', d, 0, comm_id)
    struct.pack_into('>Q', d, 8, sid)
    struct.pack_into('>Q', d, 16, 0x0002c90300aabbcc)
    struct.pack_into('>I', d, 28, 0x80010000)
    d[32:35] = qpn.to_bytes(3, 'big')
    d[35] = 0x10
    d[39] = 0x10
    d[43] = 0x1f
    d[44:47] = (0x000100).to_bytes(3, 'big')
    struct.pack_into('>H', d, 48, 0xffff)
    d[50] = 0x40
    d[51] = 0x73
    struct.pack_into('>HH', d, 52, llid, rlid)
    d[56 + 12:56 + 16] = lgid
    d[72 + 12:72 + 16] = rgid
    d[88:90] = b'\x00\x01'
    d[140:140 + len(priv)] = priv
    return bytes(d)


def ipcm_priv(sip, dip, consumer=b'', sport=0x1234):
    """IP CM private data (36 octets) + 56 octets of consumer data"""
    p = bytes([0x00, 4 << 4]) + struct.pack('>H', sport)
    p += b'\0' * 12 + sip + b'\0' * 12 + dip
    return p + consumer.ljust(56, b'\0')


def cm_rep(local_id, remote_id, qpn, priv=b''):
    d = bytearray(232)
    struct.pack_into('>II', d, 0, local_id, remote_id)
    struct.pack_into('>I', d, 8, 0x80010000)
    d[12:15] = qpn.to_bytes(3, 'big')
    d[20:23] = (0x000200).to_bytes(3, 'big')
    d[24] = 0x10
    d[25] = 0x10
    d[26] = 0x6c
    d[27] = 0x03
    struct.pack_into('>Q', d, 28, 0x0002c90300ddeeff)
    d[36:36 + len(priv)] = priv
    return bytes(d)


def cm_rtu(local_id, remote_id, priv=b''):
    return struct.pack('>II', local_id, remote_id) + priv.ljust(224, b'\0')


def cm_rej(local_id, remote_id, reason=10, priv=b''):
    return (struct.pack('>IIBBH', local_id, remote_id, 1, 0x08, reason) + b'\0' * 72
            + priv.ljust(148, b'\0'))


def cm_dreq(local_id, remote_id, qpn, priv=b''):
    return struct.pack('>II', local_id, remote_id) + qpn.to_bytes(3, 'big') + b'\0' + priv.ljust(220, b'\0')


def cm_drsp(local_id, remote_id, priv=b''):
    return struct.pack('>II', local_id, remote_id) + priv.ljust(224, b'\0')


CM_REQ, CM_REJ, CM_REP, CM_RTU, CM_DREQ, CM_DRSP = 0x10, 0x12, 0x13, 0x14, 0x15, 0x16
SID_IPCM_TCP = 0x0000000001060000        # IP CM: prefix 0x01, TCP, port in the low 16 bits
SID_IPCM_UDP = 0x0000000001110000        # IP CM, UDP


def cm(attr, tid, data):
    return ud_mad(mad(7, 3, attr, tid, data), 1, 1)


def nvme_req_priv(qid, hrq=128, hsq=127, cntlid=0xffff, recfmt=0):
    return struct.pack('<HHHHH', recfmt, qid, hrq, hsq, cntlid).ljust(32, b'\0')


def nvme_rep_priv(crq=128, recfmt=0):
    return struct.pack('<HH', recfmt, crq).ljust(32, b'\0')


def nvme_rej_priv(status, recfmt=0):
    return struct.pack('<HH', recfmt, status)


# --------------------------------------------------------------------- NVMe
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


def sgl_keyed(addr, n, key):
    return struct.pack('<Q', addr) + n.to_bytes(3, 'little') + struct.pack('<I', key) + b'\x40'


def fabric(fctype, cid, extra=None, sgl=None):
    e = {4: bytes([fctype])}
    e.update(extra or {})
    return sqe(0x7f, cid, nsid=0, sgl=sgl, extra=e)


def connect_sqe(cid, qid, sgl, sqsize=127, kato=0):
    return fabric(1, cid, {40: struct.pack('<HHHBB', 0, qid, sqsize, 0, 0),
                           48: struct.pack('<I', kato)}, sgl=sgl)


def propget(cid, off, size8=False):
    return fabric(4, cid, {40: bytes([1 if size8 else 0]), 44: struct.pack('<I', off)})


def propset(cid, off, val, size8=False):
    return fabric(0, cid, {40: bytes([1 if size8 else 0]), 44: struct.pack('<I', off),
                           48: struct.pack('<Q', val)})


def cqe(cid, dw0=0, dw1=0, sqhd=0, sqid=0, status=0):
    return struct.pack('<IIHHHH', dw0, dw1, sqhd, sqid, cid, status)


def connect_data(subnqn=b'nqn.2014-08.org.example:subsys1', hostnqn=b'nqn.2014-08.org.example:host1', cntlid=0xffff):
    d = bytes(range(16)) + struct.pack('<H', cntlid) + b'\0' * 238
    d += subnqn.ljust(256, b'\0') + hostnqn.ljust(256, b'\0') + b'\0' * 256
    return d


def ident_ns():
    d = bytearray(4096)
    struct.pack_into('<QQQ', d, 0, 1 << 20, 1 << 20, 1 << 19)
    d[128:132] = struct.pack('<HBB', 0, 9, 0)
    return bytes(d)


def ident_ctrl():
    d = bytearray(4096)
    struct.pack_into('<HH', d, 0, 0x1b36, 0x1b36)
    d[4:24] = b'SYNTH0001'.ljust(20)
    d[24:64] = b'Synthetic NVMe controller'.ljust(40)
    d[64:72] = b'1.0'.ljust(8)
    d[72] = 6
    d[77] = 5
    struct.pack_into('<I', d, 80, 0x00010400)
    d[512] = 0x66
    d[513] = 0x44
    d[768:768 + 31] = b'nqn.2014-08.org.example:subsys1'
    return bytes(d)


# ---------------------------------------------------------------- sessions
class Session:
    """one RC connection: client (host) a, server (controller) b"""

    def __init__(self, tid, qp_a, qp_b, qid, port=4420, a=IP4A, b=IP4B, sid=None,
                 priv=None, rep_priv=None):
        self.tid, self.qa, self.qb, self.a, self.b = tid, qp_a, qp_b, a, b
        self.sid = SID_IPCM_TCP | port if sid is None else sid
        self.ca, self.cb = tid * 2, tid * 2 + 1
        self.priv = nvme_req_priv(qid) if priv is None else priv
        self.rep_priv = nvme_rep_priv() if rep_priv is None else rep_priv
        self.hpsn = 0x100      # host PSN
        self.cpsn = 0x500      # controller PSN
        self.qid = qid

    def connect(self):
        E(rr4(cm(CM_REQ, self.tid, cm_req(self.ca, self.sid, self.qa, 0x11, 0x22, self.a, self.b,
                                         priv=ipcm_priv(self.a, self.b, self.priv))), self.a, self.b))
        E(rr4(cm(CM_REP, self.tid, cm_rep(self.cb, self.ca, self.qb, priv=self.rep_priv)), self.b, self.a))
        E(rr4(cm(CM_RTU, self.tid, cm_rtu(self.ca, self.cb)), self.a, self.b))

    def disconnect(self):
        E(rr4(cm(CM_DREQ, self.tid, cm_dreq(self.ca, self.cb, self.qb)), self.a, self.b))
        E(rr4(cm(CM_DRSP, self.tid, cm_drsp(self.cb, self.ca)), self.b, self.a))

    # host to controller (client_to_server)
    def host_send(self, data, op=RC_SEND_ONLY):
        pre = ieth() if op == RC_SEND_ONLY_INVAL else b''
        E(rr4(bth(op, self.qb, self.hpsn) + pre + data, self.a, self.b))
        self.hpsn += 1

    def read_resp(self, data, psn, op=RC_READ_RESP_ONLY):
        h = bth(op, self.qb, psn)
        if op in (RC_READ_RESP_FIRST, RC_READ_RESP_LAST, RC_READ_RESP_ONLY):
            h += aeth()
        E(rr4(h + data, self.a, self.b))

    # controller to host
    def ctrl_send(self, data, op=RC_SEND_ONLY):
        pre = ieth() if op == RC_SEND_ONLY_INVAL else b''
        E(rr4(bth(op, self.qa, self.cpsn) + pre + data, self.b, self.a))
        self.cpsn += 1

    def read_req(self, addr, key, ln):
        psn = self.cpsn
        E(rr4(bth(RC_READ_REQ, self.qa, psn) + reth(addr, key, ln), self.b, self.a))
        self.cpsn += max(1, (ln + 1023) // 1024)
        return psn

    def write(self, addr, key, data, mtu=1024):
        """RDMA WRITE of data (ONLY, or FIRST/MIDDLE/LAST)"""
        n = len(data)
        if n <= mtu:
            E(rr4(bth(RC_WRITE_ONLY, self.qa, self.cpsn) + reth(addr, key, n) + data, self.b, self.a))
            self.cpsn += 1
            return
        parts = [data[i:i + mtu] for i in range(0, n, mtu)]
        for i, p in enumerate(parts):
            op = RC_WRITE_FIRST if i == 0 else (RC_WRITE_LAST if i == len(parts) - 1 else RC_WRITE_MIDDLE)
            h = bth(op, self.qa, self.cpsn) + (reth(addr, key, n) if i == 0 else b'')
            E(rr4(h + p, self.b, self.a))
            self.cpsn += 1

    def host_read_data(self, addr, key, data, mtu=1024):
        """the controller RDMA READs data from the host: request + response"""
        psn = self.read_req(addr, key, len(data))
        parts = [data[i:i + mtu] for i in range(0, len(data), mtu)] or [b'']
        for i, p in enumerate(parts):
            if len(parts) == 1:
                op = RC_READ_RESP_ONLY
            else:
                op = RC_READ_RESP_FIRST if i == 0 else (
                    RC_READ_RESP_LAST if i == len(parts) - 1 else RC_READ_RESP_MIDDLE)
            self.read_resp(p, psn + i, op)
        return psn


def build():
    cdata = connect_data()

    # ---- session 1: admin queue
    s = Session(0x10, 0x000a10, 0x000b10, 0)
    mark('admin queue: CM REQ (IP CM, TCP port 4420, NVMe/RDMA private data) / REP / RTU, '
         'Fabrics Connect with data read by the controller (RDMA READ request and response over '
         'three packets), Property Get/Set, Authentication, unknown Fabrics command')
    s.connect()
    s.host_send(connect_sqe(1, 0, sgl_keyed(0x7f0000, 1024, 0x1111), kato=30000))
    s.host_read_data(0x7f0000, 0x1111, cdata)
    s.ctrl_send(cqe(1, dw0=0x00010001))
    for cid, (off, v8) in enumerate(((0x00, True), (0x08, False), (0x14, False),
                                     (0x1c, False), (0x20, False), (0x30, False)), 2):
        s.host_send(propget(cid, off, v8))
        s.ctrl_send(cqe(cid, dw0=0x0200003c, dw1=0x20 if v8 else 0))
    s.host_send(propset(8, 0x14, 0x00460001))
    s.ctrl_send(cqe(8))
    s.host_send(propset(9, 0x20, 0x4e564d65))
    s.ctrl_send(cqe(9))
    s.host_send(propset(10, 0x38, 0x1234, True))
    s.ctrl_send(cqe(10, status=0x6))
    s.host_send(fabric(5, 11, {41: b'\x01', 43: b'\xea', 44: struct.pack('<I', 64)},
                       sgl=sgl_keyed(0x7f1000, 64, 0x2222)))
    s.host_read_data(0x7f1000, 0x2222, fill(64, 1))
    s.ctrl_send(cqe(11))
    s.host_send(fabric(6, 12, {41: b'\x01', 43: b'\xea', 44: struct.pack('<I', 64)}))
    s.ctrl_send(cqe(12), RC_SEND_ONLY_INVAL)
    s.host_send(fabric(0x77, 13))
    s.ctrl_send(cqe(13, dw0=7, status=1))
    s.host_send(fabric(8, 14))
    s.ctrl_send(cqe(14))

    mark('admin queue: Identify (RDMA WRITE in four packets, in one packet), Get Log Page, '
         'Get/Set Features, Keep Alive, AER, Create IO queues, Set Features with data read by the controller')
    s.host_send(sqe(0x06, 20, nsid=0, cdw10=1, sgl=sgl_keyed(0x10000, 4096, 0x1001)))
    s.write(0x10000, 0x1001, ident_ctrl())
    s.ctrl_send(cqe(20))
    s.host_send(sqe(0x06, 21, nsid=1, cdw10=0, sgl=sgl_keyed(0x20000, 4096, 0x1002)))
    s.write(0x20000, 0x1002, ident_ns())
    s.ctrl_send(cqe(21), RC_SEND_ONLY_INVAL)
    s.host_send(sqe(0x02, 22, nsid=0xffffffff, cdw10=0x02 | (0x7f << 16),
                    sgl=sgl_keyed(0x30000, 512, 0x1003)))
    s.write(0x30000, 0x1003, bytes(512))
    s.ctrl_send(cqe(22))
    s.host_send(sqe(0x0a, 23, nsid=0, cdw10=0x07))
    s.ctrl_send(cqe(23, dw0=0x001f001f))
    s.host_send(sqe(0x09, 24, nsid=0, cdw10=0x07, cdw11=0x001f001f))
    s.ctrl_send(cqe(24, dw0=0x001f001f))
    s.host_send(sqe(0x18, 25, nsid=0))
    s.ctrl_send(cqe(25))
    s.host_send(sqe(0x0c, 26, nsid=0))
    s.host_send(sqe(0x05, 27, nsid=0, cdw10=0x001f0001, cdw11=3))
    s.ctrl_send(cqe(27))
    s.host_send(sqe(0x01, 28, nsid=0, cdw10=0x001f0001, cdw11=0x00010001))
    s.ctrl_send(cqe(28))
    s.ctrl_send(cqe(26, dw0=0x00010101))
    s.ctrl_send(cqe(26))                      # second CQE for a completed command
    s.host_send(sqe(0x09, 29, nsid=1, cdw10=0x03, sgl=sgl_keyed(0x40000, 64, 0x1004)))
    s.host_read_data(0x40000, 0x1004, fill(64, 5))
    s.ctrl_send(cqe(29))
    s.host_send(sqe(0x06, 30, nsid=0, cdw10=2, sgl=sgl_keyed(0x50000, 4096, 0x1005)))
    s.write(0x50000, 0x1005, bytes(4096), mtu=1500)

    mark('unmatched transfers and odd packets: RDMA READ request and WRITE that match no command, '
         'READ response with no request, SEND shorter than a command, CQE-sized SEND of another '
         'length, SEND FIRST to both sides, a CQE with no command')
    s.read_req(0xdead0000, 0x9999, 512)
    E(rr4(bth(RC_WRITE_ONLY, s.qa, 0x777) + reth(0xdead0000, 0x9999, 16) + fill(16, 1), s.b, s.a))
    s.read_resp(fill(32, 2), 0x6666)                      # response to nothing
    s.host_send(fill(40, 3))                                # SEND shorter than an SQE
    s.ctrl_send(fill(20, 4))                                # SEND that is not CQE sized
    s.ctrl_send(fill(24, 5), RC_SEND_ONLY_INVAL)
    s.host_send(fill(70, 6), RC_SEND_FIRST)                 # not a SEND ONLY: unknown data
    s.ctrl_send(fill(70, 7), RC_SEND_FIRST)
    s.ctrl_send(cqe(0x99))                                  # CQE for no command
    E(rr4(bth(RC_ACK, s.qb, 0x777) + aeth(), s.a, s.b))     # an ACK: no payload
    E(rr4(bth(RC_WRITE_MIDDLE, s.qa, 0x778) + fill(32, 8), s.b, s.a))    # MIDDLE with no FIRST
    E(rr4(bth(RC_WRITE_LAST, s.qa, 0x779) + fill(32, 9), s.b, s.a))
    s.disconnect()

    # ---- session 2: I/O queue 1
    s = Session(0x20, 0x000a20, 0x000b20, 1)
    mark('I/O queue 1: CM, Connect, Read with RDMA WRITE (only, first/middle/last), Write with RDMA '
         'READ (single response, three responses, 1500 octet MTU), Flush, Compare, '
         'Dataset Management, Write Zeroes, response with invalidate, interleaved transfers')
    s.connect()
    s.host_send(connect_sqe(1, 1, sgl_keyed(0x8f0000, 1024, 0x3111)))
    s.host_read_data(0x8f0000, 0x3111, cdata)
    s.ctrl_send(cqe(1, dw0=0x00010001, sqid=1))
    s.host_send(sqe(0x02, 2, cdw10=0, cdw12=0, sgl=sgl_keyed(0x100000, 512, 0x4001)))
    s.write(0x100000, 0x4001, fill(512, 3))
    s.ctrl_send(cqe(2, sqid=1))
    s.host_send(sqe(0x02, 3, cdw10=8, cdw12=7, sgl=sgl_keyed(0x110000, 4096, 0x4002)))
    s.write(0x110000, 0x4002, fill(4096, 4))
    s.ctrl_send(cqe(3, sqid=1), RC_SEND_ONLY_INVAL)
    s.host_send(sqe(0x01, 4, cdw10=64, cdw12=7, sgl=sgl_keyed(0x120000, 512, 0x4003)))
    s.host_read_data(0x120000, 0x4003, fill(512, 5))
    s.ctrl_send(cqe(4, sqid=1))
    s.host_send(sqe(0x01, 5, cdw10=64, cdw12=15, sgl=sgl_keyed(0x130000, 3000, 0x4004)))
    s.host_read_data(0x130000, 0x4004, fill(3000, 6))
    s.ctrl_send(cqe(5, sqid=1))
    s.host_send(sqe(0x01, 6, cdw10=64, cdw12=15, sgl=sgl_keyed(0x140000, 4096, 0x4005)))
    s.host_read_data(0x140000, 0x4005, fill(4096, 7), mtu=1500)
    s.ctrl_send(cqe(6, sqid=1))
    for cid, op in ((7, 0x00), (8, 0x05), (9, 0x09), (10, 0x08), (11, 0x0c), (12, 0x04)):
        s.host_send(sqe(op, cid, cdw10=1000, cdw12=3))
        s.ctrl_send(cqe(cid, sqid=1, status=0x2 if op == 0x04 else 0))
    # two commands in flight: the transfers are in the order of the command
    s.host_send(sqe(0x01, 13, cdw10=64, cdw12=7, sgl=sgl_keyed(0x150000, 512, 0x4006)))
    s.host_send(sqe(0x02, 14, cdw10=64, cdw12=7, sgl=sgl_keyed(0x160000, 2048, 0x4007)))
    s.write(0x160000, 0x4007, fill(2048, 8))
    s.host_read_data(0x150000, 0x4006, fill(512, 9))
    s.ctrl_send(cqe(14, sqid=1))
    s.ctrl_send(cqe(13, sqid=1))
    # a command repeated with an identical keyed descriptor
    s.host_send(sqe(0x02, 15, cdw10=64, cdw12=7, sgl=sgl_keyed(0x170000, 512, 0x4008)))
    s.write(0x170000, 0x4008, fill(512, 10))
    s.ctrl_send(cqe(15, sqid=1))
    s.disconnect()

    # ---- session 3: connection rejected, CM variants
    mark('RDMA CM: a REQ rejected with NVMe/RDMA reject data, REP and REQ with other record '
         'formats, an RTU, DREQ and DRSP, a REQ for another port and another service id')
    s = Session(0x30, 0x000a30, 0x000b30, 0)
    E(rr4(cm(CM_REQ, s.tid, cm_req(s.ca, s.sid, s.qa, 0x11, 0x22, s.a, s.b,
                                    priv=ipcm_priv(s.a, s.b, nvme_req_priv(0, recfmt=7)))), s.a, s.b))
    E(rr4(cm(CM_REJ, s.tid, cm_rej(s.cb, s.ca, 28, priv=nvme_rej_priv(0x01))), s.b, s.a))
    s = Session(0x31, 0x000a31, 0x000b31, 0, a=IP4C, rep_priv=nvme_rep_priv(64, recfmt=3))
    s.connect()
    s.host_send(propget(1, 0x08))
    s.ctrl_send(cqe(1, dw0=0x10400))
    s.disconnect()
    # a REQ that is not for the NVMe port, then traffic on it: not NVMe/RDMA
    s = Session(0x32, 0x000a32, 0x000b32, 0, port=4421)
    s.connect()
    s.host_send(sqe(0x18, 1, nsid=0))
    s.ctrl_send(cqe(1))
    # service id of an IP CM UDP service, not TCP
    s = Session(0x33, 0x000a33, 0x000b33, 0, sid=SID_IPCM_UDP | 4420)
    s.connect()
    s.host_send(sqe(0x18, 1, nsid=0))
    s.ctrl_send(cqe(1))
    # a connection whose first RC packet comes from the controller (capture
    # started late): the queue id comes from the other direction's CM data
    mark('first packet of the connection from the controller, a CM REP and RTU with no REQ')
    s = Session(0x34, 0x000a34, 0x000b34, 1)
    s.connect()
    s.ctrl_send(cqe(0x40, sqid=1))
    s.host_send(sqe(0x18, 0x41, nsid=0))
    s.ctrl_send(cqe(0x41, sqid=1))
    s.disconnect()
    # a REP and an RTU for a connection whose REQ is not in the capture
    E(rr4(cm(CM_REP, 0x7001, cm_rep(0x71, 0x70, 0x000b50, priv=nvme_rep_priv())), IP4C, bytes([192, 0, 2, 9])))
    E(rr4(cm(CM_RTU, 0x7001, cm_rtu(0x70, 0x71)), bytes([192, 0, 2, 9]), IP4C))
    # RC traffic to a QP that has no connection
    E(rr4(bth(RC_SEND_ONLY, 0x000fff, 1) + sqe(0x18, 1, nsid=0), IP4A, IP4B))
    E(rr4(bth(RC_SEND_ONLY, 0x000ffe, 1) + cqe(1), IP4B, IP4A))


def build_malformed():
    global FRAMES, MARKS
    FRAMES, MARKS = [], []
    cdata = connect_data()
    s = Session(0x40, 0x000c10, 0x000d10, 0)
    mark('truncated frames: CM private data cut short, truncated command, CQE and RDMA data')
    # the REQ cut inside the NVMe/RDMA private data
    req = rr4(cm(CM_REQ, s.tid, cm_req(s.ca, s.sid, s.qa, 0x11, 0x22, s.a, s.b,
                                        priv=ipcm_priv(s.a, s.b, s.priv))), s.a, s.b)
    E(req[:len(req) - 60])
    s.connect()
    s.host_send(connect_sqe(1, 0, sgl_keyed(0x7f0000, 1024, 0x1111)))
    s.host_read_data(0x7f0000, 0x1111, cdata)
    s.ctrl_send(cqe(1, dw0=0x00010001))
    # Identify with the WRITE data cut short, then a command cut inside the SQE
    s.host_send(sqe(0x06, 2, nsid=0, cdw10=1, sgl=sgl_keyed(0x10000, 4096, 0x1001)))
    E(rr4(bth(RC_WRITE_ONLY, s.qa, s.cpsn) + reth(0x10000, 0x1001, 4096) + ident_ctrl()[:400], s.b, s.a)[:200])
    s.host_send(sqe(0x18, 3, nsid=0)[:63])
    s.ctrl_send(cqe(3))
    # a CQE one octet short
    s.host_send(sqe(0x18, 4, nsid=0))
    s.ctrl_send(cqe(4)[:15])
    # REP and REJ private data cut short
    t = Session(0x41, 0x000c20, 0x000d20, 0)
    E(rr4(cm(CM_REQ, t.tid, cm_req(t.ca, t.sid, t.qa, 0x11, 0x22, t.a, t.b,
                                    priv=ipcm_priv(t.a, t.b, t.priv))), t.a, t.b))
    rep = rr4(cm(CM_REP, t.tid, cm_rep(t.cb, t.ca, t.qb, priv=t.rep_priv)), t.b, t.a)
    E(rep[:len(rep) - 190])
    # a second REQ + REJ with cut private data
    u = Session(0x42, 0x000c30, 0x000d30, 0)
    E(rr4(cm(CM_REQ, u.tid, cm_req(u.ca, u.sid, u.qa, 0x11, 0x22, u.a, u.b,
                                    priv=ipcm_priv(u.a, u.b, u.priv))), u.a, u.b))
    rej = rr4(cm(CM_REJ, u.tid, cm_rej(u.cb, u.ca, 28, priv=nvme_rej_priv(0x01))), u.b, u.a)
    E(rej[:len(rej) - 140])


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
    write_pcap(out + '/nvme-rdma-coverage.pcap', FRAMES)
    if '-v' in sys.argv:
        report('main')
    print('main: %d frames' % len(FRAMES))
    build_malformed()
    write_pcap(out + '/nvme-rdma-coverage-malformed.pcap', FRAMES)
    if '-v' in sys.argv:
        report('malformed')
    print('malformed: %d frames' % len(FRAMES))
