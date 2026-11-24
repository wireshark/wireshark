#!/usr/bin/env python3
# Generates test/captures/infiniband_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for the InfiniBand dissector (packet-infiniband.c).

    python3 mkinfiniband.py <outdir> [-v]

writes infiniband-coverage.pcapng (every frame decodes cleanly) and
infiniband-coverage-malformed.pcapng.  All addresses are made up
(192.0.2.0/24, 2001:db8::/32, 02:00:00:00:00:xx).  -v prints the frame
ranges of each section.

pcapng interfaces: 0 Ethernet (RRoCE over UDP 4791 and RoCE v1,
ethertype 0x8915), 1 ERF (linktype 197; INFINIBAND records, which start
with the LRH, and INFINIBAND_LINK records).
"""
import os
import struct
import sys

# ---------------------------------------------------------------- pcapng
LT_ETH, LT_ERF = 1, 197


def _blk(btype, body):
    pad = (-len(body)) % 4
    tl = 12 + len(body) + pad
    return struct.pack('<II', btype, tl) + body + b'\0' * pad + struct.pack('<I', tl)


class Pcapng:
    def __init__(self):
        self.frames = []     # (ifid, data)
        self.marks = []

    def add(self, ifid, data, orig=None):
        self.frames.append((ifid, bytes(data), orig))
        return len(self.frames)

    def add_erf(self, data):
        return self.add(1, data)

    def add_lrh(self, data):
        """a packet that starts with the LRH, as an ERF INFINIBAND record"""
        return self.add(1, erf(21, data))

    def mark(self, name):
        self.marks.append((len(self.frames) + 1, name))

    def write(self, path):
        out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in (LT_ETH, LT_ERF):
            out += _blk(1, struct.pack('<HHI', lt, 0, 65535))
        for i, (ifid, d, orig) in enumerate(self.frames):
            ts = (1700000000 + i) * 1000000
            out += _blk(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff,
                                       len(d), orig or len(d)) + d)
        with open(path, 'wb') as f:
            f.write(out)

    def report(self, name):
        for i, (n, s) in enumerate(self.marks):
            e = self.marks[i + 1][0] - 1 if i + 1 < len(self.marks) else len(self.frames)
            print('%s %d-%d: %s' % (name, n, e, s))


# -------------------------------------------------------------- addresses
MAC1 = bytes.fromhex('020000000001')
MAC2 = bytes.fromhex('020000000002')
IP4A = bytes([192, 0, 2, 1])
IP4B = bytes([192, 0, 2, 2])
IP4C = bytes([192, 0, 2, 3])
IP6A = bytes.fromhex('20010db8000000000000000000000001')
IP6B = bytes.fromhex('20010db8000000000000000000000002')
GIDA = bytes.fromhex('fe80000000000000020000fffe000001')
GIDB = bytes.fromhex('fe80000000000000020000fffe000002')
ICRC = b'\x00' * 4
VCRC = b'\x00' * 2


def fill(n, seed=1):
    return bytes(((seed * 37 + i * 7 + (i >> 2)) & 0xff) | 1 for i in range(n))


# ------------------------------------------------------------ IB headers
# opcodes
RC_SEND_FIRST, RC_SEND_MIDDLE, RC_SEND_LAST, RC_SEND_LAST_IMM = 0, 1, 2, 3
RC_SEND_ONLY, RC_SEND_ONLY_IMM = 4, 5
RC_WRITE_FIRST, RC_WRITE_MIDDLE, RC_WRITE_LAST, RC_WRITE_LAST_IMM = 6, 7, 8, 9
RC_WRITE_ONLY, RC_WRITE_ONLY_IMM, RC_READ_REQ = 10, 11, 12
RC_READ_RESP_FIRST, RC_READ_RESP_MIDDLE, RC_READ_RESP_LAST, RC_READ_RESP_ONLY = 13, 14, 15, 16
RC_ACK, RC_ATOMIC_ACK, RC_CMP_SWAP, RC_FETCH_ADD = 17, 18, 19, 20
RC_SEND_LAST_INVAL, RC_SEND_ONLY_INVAL, RC_FLUSH, RC_ATOMIC_WRITE = 22, 23, 28, 29
UD_SEND_ONLY, UD_SEND_ONLY_IMM = 100, 101

# header sequence per opcode: letters
#  R=RDETH D=DETH T=RETH I=IMMDT A=AETH K=ATOMICACKETH E=ATOMICETH
#  V=IETH F=FETH P=payload
SEQ = {}
for _op in (0, 1, 2, 4, 7, 8, 14):
    SEQ[_op] = 'P'
for _op in (3, 5, 9):
    SEQ[_op] = 'IP'
for _op in (6, 10, 29):
    SEQ[_op] = 'TP'
SEQ[11] = 'TIP'
SEQ[12] = 'T'
for _op in (13, 15, 16):
    SEQ[_op] = 'AP'
SEQ[17] = 'A'
SEQ[18] = 'AK'
SEQ[19] = SEQ[20] = 'E'
SEQ[22] = SEQ[23] = 'VP'
SEQ[28] = 'FT'
# UC
for _op in (32, 33, 34, 36, 39, 40):
    SEQ[_op] = 'P'
for _op in (35, 37, 41):
    SEQ[_op] = 'IP'
for _op in (38, 42):
    SEQ[_op] = 'TP'
SEQ[43] = 'TIP'
# RD (these opcodes are all handled as DCT: 8 more octets after the BTH)
for _op in (64, 65, 66, 68, 71, 72):
    SEQ[_op] = 'RDP'
for _op in (67, 69, 73):
    SEQ[_op] = 'RDIP'
for _op in (70, 74):
    SEQ[_op] = 'RDTP'
SEQ[75] = 'RDTIP'
SEQ[76] = 'RDT'
for _op in (77, 79, 80):
    SEQ[_op] = 'RAP'
SEQ[78] = 'RP'
SEQ[81] = 'RA'
SEQ[82] = 'RAK'
SEQ[83] = SEQ[84] = 'RDE'
SEQ[92] = 'RFT'
SEQ[93] = 'RTP'
SEQ[100] = 'DP'
SEQ[101] = 'DIP'


def bth(op, dqp, psn=0, se=0, mig=0, pad=0, tver=0, pkey=0xffff, ack=0, dct=None):
    b = struct.pack('>BBHB', op, (se << 7) | (mig << 6) | (pad << 4) | tver, pkey, 0)
    b += dqp.to_bytes(3, 'big') + bytes([ack << 7]) + psn.to_bytes(3, 'big')
    if (op >> 5) == 2:
        # DCT: 8 more octets (DC access key, DCT number)
        b += dct if dct is not None else struct.pack('>QQ', 0, 0)[:8]
    return b


def rdeth(ee=0x123456):
    return b'\x00' + ee.to_bytes(3, 'big')


def deth(sqp, qkey=0x80010000):
    return struct.pack('>IB', qkey, 0) + sqp.to_bytes(3, 'big')


def reth(va=0x1000, rkey=0xdeadbeef, ln=4096):
    return struct.pack('>QII', va, rkey, ln)


def atomiceth():
    return struct.pack('>QIQQ', 0x2000, 0x11223344, 0x5555, 0x6666)


def aeth(synd=0, msn=1):
    return bytes([synd]) + msn.to_bytes(3, 'big')


def atomicacketh():
    return struct.pack('>Q', 0x7777777777)


def immdt(v=0x01020304):
    return struct.pack('>I', v)


def ieth(v=0x55aa55aa):
    return struct.pack('>I', v)


def feth(v=0x80000000):
    return struct.pack('>I', v)


def ib_headers(op, sqp=0x300, payload=b'', imm=None, synd=0):
    seq = SEQ.get(op)
    if seq is None:
        return b''
    out = b''
    for c in seq:
        out += {'R': rdeth, 'D': lambda: deth(sqp), 'T': reth, 'I': immdt, 'A': lambda: aeth(synd),
                'K': atomicacketh, 'E': atomiceth, 'V': ieth, 'F': feth, 'P': lambda: b''}[c]()
    if seq.endswith('P'):
        out += payload
    return out


# --------------------------------------------------------------- framing
def eth(payload, etype, src=MAC1, dst=MAC2):
    return dst + src + struct.pack('>H', etype) + payload


def udp(payload, sport=49152, dport=4791):
    return struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload


def ip4(payload, src=IP4A, dst=IP4B, proto=17):
    return struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, src, dst) + payload


def ip6(payload, src=IP6A, dst=IP6B, proto=17):
    return struct.pack('>IHBB16s16s', 0x60000000, len(payload), proto, 64, src, dst) + payload


def rr4(ibpart, src=IP4A, dst=IP4B):
    """RRoCE v2 over IPv4: BTH ... payload ICRC"""
    return eth(ip4(udp(ibpart + ICRC), src, dst), 0x0800)


def udp6(payload, src, dst, sport=49152, dport=4791):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = src + dst + struct.pack('>IBBBB', len(u), 0, 0, 0, 17) + u
    if len(ph) % 2:
        ph += b'\0'
    c = sum(struct.unpack('>%dH' % (len(ph) // 2), ph))
    while c >> 16:
        c = (c & 0xffff) + (c >> 16)
    c = (~c) & 0xffff or 0xffff
    return u[:6] + struct.pack('>H', c) + u[8:]


def rr6(ibpart, src=IP6A, dst=IP6B):
    return eth(ip6(udp6(ibpart + ICRC, src, dst), src, dst), 0x86dd)


def grh(payload_len, sgid=GIDA, dgid=GIDB, nxt=0x1B, tc=0x2a, flow=0x12345, hop=64):
    return struct.pack('>IHBB16s16s', (6 << 28) | (tc << 20) | flow, payload_len, nxt, hop, sgid, dgid)


def roce1(ibpart, sgid=GIDA, dgid=GIDB, nxt=0x1B):
    """RoCE v1: GRH + BTH ... payload ICRC"""
    body = ibpart + ICRC
    return eth(grh(len(body), sgid, dgid, nxt) + body, 0x8915)


def lrh(body_len, slid, dlid, lnh, vl=0, sl=0, lver=0, pktlen=None):
    """body_len: octets after the LRH up to and including the ICRC"""
    if pktlen is None:
        pktlen = (8 + body_len + 3) // 4
    return struct.pack('>BBHHH', (vl << 4) | lver, (sl << 4) | lnh, dlid, pktlen & 0x7ff, slid)


def lrh_local(ibpart, slid=0x11, dlid=0x22, vl=0, sl=1):
    body = ibpart + ICRC
    return lrh(len(body), slid, dlid, 2, vl, sl) + body + VCRC


def lrh_global(ibpart, slid=0x11, dlid=0x22, vl=0, sgid=GIDA, dgid=GIDB, nxt=0x1B):
    body = grh(len(ibpart) + 4, sgid, dgid, nxt) + ibpart + ICRC
    return lrh(len(body), slid, dlid, 3, vl) + body + VCRC


def erf(rtype, data, wlen=None):
    wlen = len(data) if wlen is None else wlen
    rlen = 16 + len(data)
    return struct.pack('>QBBHHH', 0x6000000000000000, rtype, 0, rlen, 0, wlen) + data


# ------------------------------------------------------------------- MAD
def mad(cls, method, attr, tid, data, status=0, cspec=0, mod=0, ver=1, clsver=1):
    h = struct.pack('>BBBBHHQHHI', ver, cls, clsver, method, status, cspec, tid, attr, 0, mod)
    return h + data.ljust(232, b'\0')[:232]


def ud_mad(m, dqp=1, sqp=1):
    return bth(UD_SEND_ONLY, dqp) + deth(sqp) + m


def smp_data(attr_bytes, mkey=0x1122334455667788):
    """SMP data: M_Key, 32 reserved, 64 octet attribute"""
    return struct.pack('>Q', mkey) + b'\0' * 32 + attr_bytes.ljust(64, b'\0')


def dr_data(attr_bytes, mkey=0x1122334455667788):
    return (struct.pack('>QHH', mkey, 0x0005, 0x0006) + b'\0' * 28 + attr_bytes.ljust(64, b'\0')
            + fill(64, 3) + fill(64, 4))


def sa_data(attr_bytes, rmpp_type=0, comp=0xdeadbeefcafe0001):
    r = struct.pack('>BBBB', 1, rmpp_type, 0x13, 0) + struct.pack('>II', 0x11, 0x22)
    return r + struct.pack('>QHHQ', 0x0123456789abcdef, 8, 0, comp) + attr_bytes.ljust(200, b'\0')


# ----------------------------------------------------------------- CM
def cm_req(comm_id, sid, qpn, llid, rlid, lgid, rgid, ipcm_ver=None, priv=b'', v4=True):
    d = bytearray(232)
    struct.pack_into('>I', d, 0, comm_id)
    struct.pack_into('>Q', d, 8, sid)
    struct.pack_into('>Q', d, 16, 0x0002c90300aabbcc)     # CA GUID
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
    if v4:
        d[56 + 12:56 + 16] = lgid
        d[72 + 12:72 + 16] = rgid
    else:
        d[56:72] = lgid
        d[72:88] = rgid
    d[88:90] = b'\x00\x01'
    d[140:140 + len(priv)] = priv
    return bytes(d)


def ipcm_priv(ipv, sip, dip, sport=0x1234, consumer=b''):
    """IP CM private data (36 octets) + 56 octets of consumer data"""
    p = bytes([0x00, ipv << 4]) + struct.pack('>H', sport)
    if ipv == 4:
        p += b'\0' * 12 + sip + b'\0' * 12 + dip
    else:
        p += sip + dip
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
SID_PLAIN = 0x0000000000000abc           # not an IP CM service id


def cm(attr, tid, data):
    return ud_mad(mad(7, 3, attr, tid, data), 1, 1)


# ------------------------------------------------------------- SMP attrs
def bytes_be(*fields):
    return b''.join(fields)


def trap_notice(trap, issuer=0x0012, toggle=1, count=5, generic=True, nbytes=54, seed=5):
    n = bytes([0x80 | 0x01 if generic else 0x01]) + b'\x00\x00\x00' + struct.pack('>H', trap)
    n += struct.pack('>HH', issuer, ((toggle & 1) << 15) | count)
    return n + fill(nbytes, seed)


TRAPS = [64, 65, 66, 67, 68, 69, 128, 129, 130, 131, 144, 145, 256, 257, 258, 259, 300]

SM_ATTRS = [0x0010, 0x0011, 0x0012, 0x0014, 0x0015, 0x0016, 0x0017, 0x0018, 0x0019, 0x001A,
            0x001B, 0x001C, 0x0020, 0x0030, 0x0031, 0x0099]
SA_ATTRS = [0x0001, 0x0002, 0x0003, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017,
            0x0018, 0x0019, 0x00F3, 0x0020, 0x0030, 0x0031, 0x0033, 0x0035, 0x0036, 0x0038,
            0x0039, 0x003A, 0x003B, 0x0099]


def multipath(sg, dg):
    d = bytearray(fill(200, 9))
    d[0:3] = b'\x80\x12\x34'
    # SGIDCount and DGIDCount are octets 15 and 16
    d[15] = sg
    d[16] = dg
    return bytes(d)



# ---------------------------------------------------- hash collision helper
_M = (1 << 64) - 1


def _H(h, data):
    """the hash of add_address_to_hash64() (wmem_strong_hash / djb-like loop)"""
    for b in data:
        h = (h + b) & _M
        h = (h + (h << 10)) & _M
        h ^= h >> 6
    return h


def _unxs(y):
    x = y
    for _ in range(12):
        x = y ^ (x >> 6)
    return x


def _Hinv(target, data):
    inv = pow(1025, -1, 1 << 64)
    h = target
    for b in reversed(data):
        h = _unxs(h)
        h = (h * inv) & _M
        h = (h - b) & _M
    return h


# ================================================================ build
def build():
    cap = Pcapng()
    out = cap

    def E(frame):
        cap.add(0, frame)

    # ---------------------------------------------- 1. opcode sweep RRoCE v4
    cap.mark('RRoCE v4: every opcode (RC, UC, UD, RD/DCT) with its header sequence')
    qp = 0x000400
    psn = 0
    ops = [o for o in sorted(SEQ) if o != 85]
    for op in ops:
        psn += 1
        pay = b'pay%02d-' % op + fill(30, op)
        # SEND FIRST, MIDDLE, LAST and LAST INVALIDATE are only used inside
        # the SMB Direct reassembly below (and in the malformed capture):
        # the RPC-over-RDMA heuristic keeps state for them and asserts on a
        # second pass
        if op in (0, 1, 2, 22):
            continue
        E(rr4(bth(op, qp + op, psn, se=(op & 1), mig=1, pad=(op & 3)) + ib_headers(op, payload=pay)))
    # AETH syndromes: ack, RNR NAK, reserved, NAK with each error code
    cap.mark('AETH syndromes (ACK credits, RNR NAK timers, reserved, NAK codes)')
    for synd in (0x1f, 0x00, 0x20 | 0x05, 0x40 | 0x03, 0x60 | 0x01, 0x60 | 0x00, 0x60 | 0x02,
                 0x60 | 0x03, 0x60 | 0x04, 0x60 | 0x09, 0x3f):
        psn += 1
        E(rr4(bth(RC_ACK, qp, psn, ack=1) + aeth(synd, 7)))
    for synd in (0x1f, 0x43):
        psn += 1
        E(rr4(bth(RC_READ_RESP_ONLY, qp, psn) + aeth(synd, 8) + b'readdata' + fill(24, 5)))
    # DCT: opcode 0x55 with the SE bit clear (DC connect, DCCETH) and set
    cap.mark('DCT connect (opcode 0x55): DCCETH with SE clear, plain payload with SE set')
    E(rr4(bth(85, qp, 1, se=0) + b'\x01' * 16 + b'dct-connect-payload-xx'))
    E(rr4(bth(85, qp, 2, se=1) + b'dct-resync-like-payload'))
    # unknown opcodes (vendor specific header sequence), BTH version, pkey
    cap.mark('Unknown opcodes (vendor header sequence), BTH version 1, other P_Key')
    E(rr4(bth(0x1e, qp, 1) + fill(24, 8)))
    E(rr4(bth(0xff, qp, 2, tver=1, pkey=0x8001) + fill(21, 9)))

    # ---------------------------------------------- 2. RC send payloads
    cap.mark('RC payload dispatch: eth-over-IB heuristic, Mellanox EoIB heuristic, data')
    # IPv4/UDP over IB (etype 0x0800), ARP, unknown ethertype, reserved != 0, short payload
    inner_udp = ip4(udp(b'inner-udp-payload', 5000, 5001), IP4A, IP4C)
    arp = struct.pack('>HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, MAC1, IP4A, b'\0' * 6, IP4B)
    E(rr4(bth(UD_SEND_ONLY, 0x000500, 1) + deth(0x000501) + struct.pack('>HH', 0x0800, 0) + inner_udp))
    E(rr4(bth(UD_SEND_ONLY, 0x000500, 2) + deth(0x000501) + struct.pack('>HH', 0x0806, 0) + arp))
    E(rr4(bth(UD_SEND_ONLY, 0x000500, 3) + deth(0x000501) + struct.pack('>HH', 0x88b5, 0) + b'unknown-etype-data'))
    E(rr4(bth(UD_SEND_ONLY, 0x000500, 4) + deth(0x000501) + struct.pack('>HH', 0x0800, 1) + inner_udp))
    E(rr4(bth(UD_SEND_ONLY, 0x000500, 5) + deth(0x000501) + b'\x08\x00'))
    # Mellanox EoIB: version bits 0xC0 in the first octet; complete frame / fragment
    ethframe = eth(inner_udp, 0x0800)
    E(rr4(bth(UD_SEND_ONLY, 0x000500, 6) + deth(0x000501) + struct.pack('>HH', 0xC000 | 0x0340, 0x0001) + ethframe))
    E(rr4(bth(UD_SEND_ONLY, 0x000500, 7) + deth(0x000501) + struct.pack('>HH', 0xC000 | 0x0020, 0x0002) + ethframe[:30]))
    E(rr4(bth(UD_SEND_ONLY, 0x000500, 8) + deth(0x000501) + struct.pack('>HH', 0xC000 | 0x0005, 0x0003) + ethframe[:30]))
    E(rr4(bth(RC_SEND_ONLY, 0x000500, 9) + struct.pack('>HH', 0xC000, 0x0001) + b'\xff' * 40))
    E(rr4(bth(RC_SEND_ONLY, 0x000500, 10) + b'twenty octet payload'))
    E(rr4(bth(UD_SEND_ONLY, 0x000500, 12) + deth(0x000501) + b'\xc0\x01\x02'))
    # a plain payload for the Decode As table
    E(rr4(bth(RC_SEND_ONLY, 0x000500, 11) + b'plain RC send payload for Decode As'))

    # ---------------------------------------------- 3. management datagrams
    cap.mark('Subnet management (LID routed): every attribute, methods, all traps')
    tid = 0x1000
    for i, attr in enumerate(SM_ATTRS):
        tid += 1
        meth = (0x01, 0x02, 0x81, 0x05, 0x07, 0x33)[i % 6]
        d = smp_data(fill(64, attr & 0xff))
        E(rr4(ud_mad(mad(1, meth, attr, tid, d, mod=i), 0, 0)))
    for t in TRAPS:
        tid += 1
        E(rr4(ud_mad(mad(1, 0x05, 0x0002, tid, smp_data(trap_notice(t))), 0, 0)))
    # PortInfo etc. with all bits set / clear
    for attr in SM_ATTRS:
        tid += 1
        E(rr4(ud_mad(mad(1, 0x81, attr, tid, smp_data(b'\xff' * 64)), 0, 0)))
        tid += 1
        E(rr4(ud_mad(mad(1, 0x01, attr, tid, smp_data(b'\x00' * 64)), 0, 0)))
    cap.mark('Subnet management (directed route)')
    for i, attr in enumerate(SM_ATTRS):
        tid += 1
        meth = (0x01, 0x02, 0x81, 0x05, 0x07)[i % 5]
        E(rr4(ud_mad(mad(0x81, meth, attr, tid, dr_data(fill(64, attr & 0xff)), cspec=0x8000 | i), 0, 0)))
    E(rr4(ud_mad(mad(0x81, 0x05, 0x0002, tid + 1, dr_data(trap_notice(259))), 0, 0)))
    cap.mark('Subnet administration: every attribute and method, every RMPP type')
    for i, attr in enumerate(SA_ATTRS):
        tid += 1
        meth = (0x01, 0x81, 0x02, 0x06, 0x86, 0x12, 0x92, 0x13, 0x14, 0x94, 0x15, 0x95, 0x33)[i % 13]
        d = sa_data(multipath(1, 1) if attr == 0x003A else fill(200, attr & 0xff), rmpp_type=i % 6)
        E(rr4(ud_mad(mad(3, meth, attr, tid, d, cspec=i), 1, 1)))
    for t in TRAPS[:6] + [259]:
        tid += 1
        E(rr4(ud_mad(mad(3, 0x06, 0x0002, tid, sa_data(trap_notice(t))), 1, 1)))
    for sg, dg in ((0, 0), (1, 1), (2, 3), (3, 2)):
        tid += 1
        E(rr4(ud_mad(mad(3, 0x14, 0x003A, tid, sa_data(multipath(sg, dg))), 1, 1)))
    for attr in SA_ATTRS:
        if attr == 0x003A:
            continue
        tid += 1
        E(rr4(ud_mad(mad(3, 0x81, attr, tid, sa_data(b'\xff' * 200, rmpp_type=1)), 1, 1)))
    cap.mark('Performance management: ClassPortInfo, PortCounters, PortCountersExtended, other')
    for attr in (0x0001, 0x0012, 0x001D, 0x0099):
        for meth in (0x01, 0x81):
            tid += 1
            E(rr4(ud_mad(mad(4, meth, attr, tid, fill(232, attr & 0xff)), 1, 1)))
    cap.mark('Other management classes: BM, DEV_MGT, SNMP, vendor, application, reserved')
    for cls in (5, 6, 8, 0x09, 0x0a, 0x0f, 0x30, 0x40, 0x4f, 0x10, 0x20, 0x2f):
        tid += 1
        E(rr4(ud_mad(mad(cls, 1, 0x0001, tid, fill(232, cls)), 1, 1)))
    cap.mark('Reserved management classes (the RESERVED item is 256 octets after the MAD header, so these frames carry 24 more octets)')
    for cls in (0x00, 0x02, 0x50, 0x60, 0x80, 0x82, 0xff):
        tid += 1
        E(rr4(ud_mad(mad(cls, 1, 0x0001, tid, fill(232, cls)), 1, 1) + fill(24, cls)))
    cap.mark('Management datagram with the QP only in the source (DETH) or destination')
    E(rr4(bth(UD_SEND_ONLY, 0x000600, 1) + deth(1) + mad(4, 1, 0x0012, 0x2001, fill(232, 1))))
    E(rr4(bth(UD_SEND_ONLY, 0, 2) + deth(0x000601) + mad(1, 1, 0x0015, 0x2002, smp_data(fill(64, 3)))))

    # ---------------------------------------------- 4. connection management
    cap.mark('CM over RRoCE v4: IP CM (IPv4) REQ/REP/RTU, RC data, DREQ/DREP')
    cm_session(E, rr4, IP4A, IP4B, 0x4001, 0x000710, 0x000720, SID_IPCM_TCP | 0x1389,
               ip_cm=(4, IP4A, IP4B), v4=True, lids=(0x11, 0x22))
    cap.mark('CM over RRoCE v6: IP CM (IPv6)')
    cm_session(E, rr6, IP6A, IP6B, 0x4002, 0x000730, 0x000740, SID_IPCM_TCP | 0x1f90,
               ip_cm=(6, IP6A, IP6B), v4=False, lids=(0x33, 0x44))
    cap.mark('CM over RoCE v1 (GRH): non-IP service id, REJ of a second request')
    cm_session(E, roce1, GIDA, GIDB, 0x4003, 0x000750, 0x000760, SID_PLAIN,
               ip_cm=None, v4=False, lids=(0x55, 0x66), reject=True)
    cap.mark('CM: REP without a REQ, RTU/DREQ/DREP/REJ without a connection, other attributes')
    E(rr4(cm(CM_REP, 0x5001, cm_rep(1, 2, 0x000770))))
    E(rr4(cm(CM_RTU, 0x5002, cm_rtu(1, 2))))
    E(rr4(cm(CM_DREQ, 0x5003, cm_dreq(1, 2, 0x000770))))
    E(rr4(cm(CM_DRSP, 0x5004, cm_drsp(1, 2))))
    E(rr4(cm(CM_REJ, 0x5005, cm_rej(1, 2))))
    for attr in (0x0001, 0x0011, 0x0017, 0x0018, 0x0019, 0x001a):
        E(rr4(cm(attr, 0x5100 + attr, fill(232, attr))))
    cap.mark('CM REQ retransmitted: the connection is replaced')
    for k in range(2):
        E(rr4(cm(CM_REQ, 0x5200, cm_req(0x77, SID_PLAIN, 0x000780, 0x77, 0x78, IP4A, IP4B))))
    E(rr4(cm(CM_REP, 0x5200, cm_rep(0x78, 0x77, 0x000790))))

    # ---------------------------------------------- 5. RC send reassembly (SMB Direct)
    cap.mark('RC Send reassembly: SMB Direct data messages in FIRST/MIDDLE/LAST')
    rc_reassembly(E)

    # ---------------------------------------------- 6. RoCE v1, RRoCE v6, GRH
    cap.mark('RoCE v1 (ethertype 0x8915): RC and UD frames, GRH next header not IBA')
    for op in (RC_SEND_ONLY, RC_ACK, RC_WRITE_ONLY, UD_SEND_ONLY, 36):
        E(roce1(bth(op, 0x000800, 1) + ib_headers(op, payload=b'roce-v1-payload-bytes')))
    E(eth(grh(24, nxt=0x11) + b'\xaa' * 24, 0x8915))
    cap.mark('RRoCE over IP protocol 254 (no UDP; reached with Decode As ip.proto 254)')
    for op in (RC_SEND_ONLY, UD_SEND_ONLY):
        E(eth(ip4(bth(op, 0x000820, 1) + ib_headers(op, payload=b'rroce-over-ip-proto') + ICRC, IP4A, IP4B, 254), 0x0800))
    cap.mark('RRoCE v6 frames')
    for op in (RC_SEND_ONLY, UD_SEND_ONLY, RC_ACK):
        E(rr6(bth(op, 0x000810, 1) + ib_headers(op, payload=b'rroce-v6-payload')))

    # ---------------------------------------------- 7. LRH frames
    cap.mark('LRH (ERF INFINIBAND records): local, global, IPv6 and raw next headers')
    for op in (RC_SEND_ONLY, RC_ACK, RC_WRITE_ONLY, UD_SEND_ONLY, 36, 64, 100):
        cap.add_lrh(lrh_local(bth(op, 0x000900, 1) + ib_headers(op, payload=b'lrh-local-payload!')))
    for vl in (0, 15):
        cap.add_lrh(lrh_local(ud_mad(mad(4, 1, 0x0012, 0x6001, fill(232, 2)), 1, 1), vl=vl))
    cap.add_lrh(lrh_local(ud_mad(mad(1, 1, 0x0015, 0x6002, smp_data(fill(64, 2))), 0, 0), vl=15))
    cap.add_lrh(lrh_global(bth(RC_SEND_ONLY, 0x000901, 2) + b'lrh-global-payload-bytes'))
    cap.add_lrh(lrh_global(bth(UD_SEND_ONLY, 0x000902, 3) + deth(0x000903) + b'ud-global-payload!!'))
    cap.add_lrh(lrh_global(b'\xbb' * 20, nxt=0x11))
    ipv6pkt = ip6(udp6(b'ipv6-over-ib', IP6A, IP6B, 6000, 6001), IP6A, IP6B)
    body = ipv6pkt
    cap.add_lrh(lrh(len(body), 0x11, 0x22, 1) + body + VCRC)
    body = struct.pack('>HH', 0, 0x0800) + inner_udp
    cap.add_lrh(lrh(len(body), 0x11, 0x22, 0) + body + VCRC)
    body = struct.pack('>HH', 0, 0x88b5) + b'raw ethertype data'
    cap.add_lrh(lrh(len(body), 0x11, 0x22, 0) + body + VCRC)

    # ---------------------------------------------- 8. ERF
    cap.mark('ERF INFINIBAND and INFINIBAND_LINK records (flow control and link packets)')
    cap.add_erf(erf(21, lrh_local(bth(RC_SEND_ONLY, 0x000a00, 1) + b'erf-infiniband-payload')))
    # link packets (8 octets here; the label code reads an LRH-sized header):
    # op 0/1 flow control, reserved operands handed to the data dissector
    for b0 in (0x00, 0x10, 0x20, 0x70):
        cap.add_erf(erf(25, bytes([b0, 0x10, 0x34, 0x56, 0x78, 0x9a, 0x00, 0x00])))
    ibmad = lambda cls, attr: bth(UD_SEND_ONLY, 1) + deth(1) + mad(cls, 1, attr, 0x7001, smp_data(fill(64, 1)))
    for cls, attr in ((1, 0x0015), (3, 0x0011), (0x09, 1), (0x10, 1), (0x00, 1), (0x03, 0x0012), (7, 0x10)):
        lnk = bytes([0xf0, 0x02, 0x00, 0x22, 0x00, 0x00, 0x00, 0x11]) + ibmad(cls, attr)
        cap.add_erf(erf(25, lnk + ICRC + VCRC))
    # a link packet laid out like a global route packet (GRH, then BTH)
    lnk = bytes([0x00, 0x03, 0x00, 0x22, 0x00, 0x00, 0x00, 0x11]) + grh(40, nxt=0x1B) + bth(RC_SEND_ONLY, 0x40) + ib_headers(RC_SEND_ONLY, payload=b'link-global-pay')
    cap.add_erf(erf(25, lnk))
    lnk = bytes([0x00, 0x03, 0x00, 0x22, 0x00, 0x00, 0x00, 0x11]) + grh(40, nxt=0x11) + b'\0' * 8
    cap.add_erf(erf(25, lnk))
    lnk = bytes([0x00, 0x01, 0x00, 0x22, 0x00, 0x00, 0x00, 0x11]) + b'\0' * 12
    cap.add_erf(erf(25, lnk))
    lnk = bytes([0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x11]) + b'\0' * 12
    cap.add_erf(erf(25, lnk))
    # link packets laid out like a local route packet, one per opcode (the
    # label code walks the same header sequences as the dissector)
    for op in sorted(SEQ) + [85, 0x1e]:
        lnk = bytes([0x00, 0x02, 0x00, 0x22, 0x00, 0x00, 0x00, 0x11]) + bth(op, 0x40, se=(0 if op == 85 else op & 1)) + ib_headers(op, payload=b'link-pay')
        cap.add_erf(erf(25, lnk + ICRC))

    # ---------------------------------------------- 9. reproducers of the fixes
    cap.mark('Fix: CM REP over IPv6 whose (TransactionID, destination) hash equals that of an IPv4 REQ (uninitialised GID bytes)')
    tid_req = 0x1122334455667788
    key = _H(tid_req, IP4A)
    tid_rep = _Hinv(key, IP6A)
    assert _H(tid_rep, IP6A) == key
    E(rr4(cm(CM_REQ, tid_req, cm_req(0x91, SID_PLAIN, 0x000100, 0x0011, 0x0022, IP4A, IP4B)), IP4A, IP4B))
    E(rr6(cm(CM_REP, tid_rep, cm_rep(0x92, 0x91, 0x000200)), IP6B, IP6A))
    E(rr6(bth(RC_SEND_ONLY, 0x000100, 1) + b'hello world! over ipv6' + fill(4, 1), IP6B, IP6A))
    E(rr6(bth(RC_SEND_ONLY, 0x000200, 1) + b'hello again! over ipv6' + fill(4, 2), IP6A, IP6B))
    E(rr4(bth(RC_SEND_ONLY, 0x000200, 1) + b'hello over ipv4 to the responder qp' + fill(4, 3), IP4A, IP4B))
    cap.mark('Fix: RC send reassembly of an SMB Direct stream that never completes (the visited flag was cleared on every pass)')
    smbd0 = struct.pack('<HHHHIII', 1, 1, 0, 0, 0, 0, 0)
    E(rr4(bth(RC_SEND_ONLY, 0x000b00, 0) + smbd0, IP4B, IP4C))
    E(rr4(bth(RC_SEND_FIRST, 0x000b00, 1) + b'A' * 256, IP4B, IP4C))
    E(rr4(bth(RC_SEND_MIDDLE, 0x000b00, 2) + b'B' * 256, IP4B, IP4C))
    cap.mark('Fix: SMP Notice trap 259 (DataValid and SWLIDADDR are 16 bit fields)')
    det = (struct.pack('>HHHH', 0x1234, 0x0021, 0x0022, 0x8001) + bytes([0x35]) + (0x000411).to_bytes(3, 'big')
           + b'\0' + (0x000422).to_bytes(3, 'big') + GIDA + GIDB + struct.pack('>H', 0xbeef) + bytes([7]))
    E(rr4(ud_mad(mad(1, 0x05, 0x0002, 0xa001, smp_data(trap_notice(259)[:10] + det)), 0, 0)))
    return cap


def cm_session(E, wrap, a, b, tid, qp_a, qp_b, sid, ip_cm, v4, lids, reject=False):
    la, lb = lids
    priv = ipcm_priv(ip_cm[0], ip_cm[1], ip_cm[2], consumer=b'consumer-private-data') if ip_cm else b'rdma-cm-private'
    comm_a, comm_b = tid * 2, tid * 2 + 1
    kw = dict(v4=v4)
    ga, gb = (a, b) if v4 else (a, b)
    E(wrap(cm(CM_REQ, tid, cm_req(comm_a, sid, qp_a, la, lb, ga, gb, priv=priv, **kw)), a, b))
    E(wrap(cm(CM_REP, tid, cm_rep(comm_b, comm_a, qp_b, priv=b'reply-private')), b, a))
    E(wrap(cm(CM_RTU, tid, cm_rtu(comm_a, comm_b, priv=b'rtu-private')), a, b))
    # RC traffic in both directions, UD from the client QP with a DETH source QP
    E(wrap(bth(RC_SEND_ONLY, qp_b, 1) + b'client to server over rc' + fill(20, 1), a, b))
    E(wrap(bth(RC_SEND_ONLY, qp_a, 1) + b'server to client over rc' + fill(20, 2), b, a))
    E(wrap(bth(RC_SEND_ONLY_IMM, qp_b, 2) + immdt() + b'only-imm-' + fill(20, 3), a, b))
    E(wrap(bth(RC_SEND_LAST_IMM, qp_b, 3) + immdt() + b'last-imm-' + fill(20, 4), a, b))
    if reject:
        E(wrap(cm(CM_REQ, tid + 1, cm_req(comm_a + 100, sid, qp_a + 1, la, lb, ga, gb, priv=priv, **kw)), a, b))
        E(wrap(cm(CM_REJ, tid + 1, cm_rej(comm_b + 100, comm_a + 100, 28, priv=b'reject-private')), b, a))
    E(wrap(cm(CM_DREQ, tid, cm_dreq(comm_a, comm_b, qp_b, priv=b'dreq-private')), a, b))
    E(wrap(cm(CM_DRSP, tid, cm_drsp(comm_b, comm_a, priv=b'drsp-private')), b, a))
    E(wrap(bth(RC_SEND_ONLY, qp_b, 4) + b'after the disconnect' + fill(8, 3), a, b))


def rc_reassembly(E):
    """SMB Direct data messages: an unfragmented message, then one split over
    FIRST, MIDDLE, MIDDLE and LAST (reassembled by the InfiniBand dissector),
    a ONLY message after it and a second fragmented message."""
    qp = 0x000a10
    sid = SID_PLAIN
    a, b = IP4A, IP4B
    wrap = lambda ib, s=a, d=b: rr4(ib, s, d)
    E(wrap(cm(CM_REQ, 0x8001, cm_req(0x81, 0x445, 0x000a20, 0x11, 0x22, a, b, priv=b'smbd-private'))))
    E(wrap(cm(CM_REP, 0x8001, cm_rep(0x82, 0x81, qp, priv=b'smbd-reply')), b, a))
    E(wrap(cm(CM_RTU, 0x8001, cm_rtu(0x81, 0x82)), a, b))

    def smbd(data, remaining=0):
        return struct.pack('<HHHHIIII', 255, 255, 0, 0, remaining, 24, len(data), 0) + data
    msg = smbd(b'smb-direct-reassembly-test-data' + fill(300, 7))
    # unfragmented
    E(wrap(bth(RC_SEND_ONLY, qp, 1) + smbd(b'short smbd data'), a, b))
    # fragmented in four parts
    parts = [msg[:100], msg[100:180], msg[180:260], msg[260:]]
    E(wrap(bth(RC_SEND_FIRST, qp, 2) + parts[0], a, b))
    E(wrap(bth(RC_SEND_MIDDLE, qp, 3) + parts[1], a, b))
    E(wrap(bth(RC_SEND_MIDDLE, qp, 4) + parts[2], a, b))
    E(wrap(bth(RC_SEND_LAST, qp, 5) + parts[3], a, b))
    E(wrap(bth(RC_SEND_ONLY, qp, 6) + smbd(b'after the fragments'), a, b))
    # second one, with immediate data on the last fragment
    msg2 = smbd(b'second-fragmented-message' + fill(120, 2))
    E(wrap(bth(RC_SEND_FIRST, qp, 7) + msg2[:70], a, b))
    E(wrap(bth(RC_SEND_LAST_IMM, qp, 8) + immdt() + msg2[70:], a, b))
    # FIRST + LAST INVALIDATE (IETH), then ONLY_IMM and ONLY_INVAL messages
    msg3 = smbd(b'third-fragmented-message' + fill(90, 3))
    E(wrap(bth(RC_SEND_FIRST, qp, 11) + msg3[:60], a, b))
    E(wrap(bth(RC_SEND_LAST_INVAL, qp, 12) + ieth() + msg3[60:], a, b))
    E(wrap(bth(RC_SEND_ONLY_IMM, qp, 13) + immdt() + smbd(b'only with immediate data'), a, b))
    E(wrap(bth(RC_SEND_ONLY_INVAL, qp, 14) + ieth() + smbd(b'only with invalidate'), a, b))
    # a fragment that is not an SMB Direct header, never completed
    E(wrap(bth(RC_SEND_FIRST, qp, 9) + b'\xfe' * 40, a, b))
    E(wrap(bth(RC_WRITE_ONLY, qp, 10) + reth() + b'write after reassembly', a, b))
    # a session that never saw a CM exchange: the first SMB Direct message
    # creates the conversation data
    q2 = 0x000a50
    c, d = IP4C, IP4B
    E(wrap(bth(RC_SEND_ONLY, q2, 1) + smbd(b'no cm first message'), c, d))
    n2 = smbd(b'no-cm-fragmented-message' + fill(100, 5))
    E(wrap(bth(RC_SEND_FIRST, q2, 2) + n2[:60], c, d))
    E(wrap(bth(RC_SEND_LAST, q2, 3) + n2[60:], c, d))


# ----------------------------------------------------------- malformed
def build_malformed():
    cap = Pcapng()
    E = lambda f: cap.add(0, f)
    cap.mark('LRH packet length larger than the frame; payload shorter than the CRC')
    cap.add_lrh(lrh(24, 0x11, 0x22, 2, pktlen=0x7ff) + bth(RC_SEND_ONLY, 0x40, 1) + b'payload' + ICRC + VCRC)
    E(rr4(bth(RC_SEND_ONLY, 0x40, 1))[:-4 - 2])
    cap.mark('RC SEND FIRST/MIDDLE/LAST/LAST INVALIDATE on their own queue pairs (RPC-over-RDMA keeps state for them: the second pass differs and asserts); empty RC send (RPC-over-RDMA reads past the end)')
    for op in (RC_SEND_FIRST, RC_SEND_MIDDLE, RC_SEND_LAST, RC_SEND_LAST_INVAL):
        E(rr4(bth(op, 0x40 + op, 1) + ib_headers(op, payload=b'rc send fragment ' + fill(20, 1))))
    E(rr4(bth(RC_SEND_ONLY, 0x50, 1)))
    cap.mark('Frames cut inside the headers')
    for n in (5, 12, 16, 20, 30):
        E(rr4(bth(RC_WRITE_ONLY, 0x40, 1) + reth() + b'x' * 8)[:42 + n])
    cap.mark('Management datagrams cut short')
    m = rr4(ud_mad(mad(1, 1, 0x0015, 0x9001, smp_data(fill(64, 1))), 0, 0))
    for n in (20, 60, 100, 200):
        E(m[:42 + 20 + n])
    m = rr4(ud_mad(mad(3, 1, 0x0011, 0x9002, sa_data(fill(200, 1))), 1, 1))
    for n in (10, 40, 120):
        E(m[:42 + 20 + n])
    m = rr4(cm(CM_REQ, 0x9003, cm_req(1, SID_IPCM_TCP | 80, 0x40, 1, 2, IP4A, IP4B,
                                      priv=ipcm_priv(4, IP4A, IP4B))))
    for n in (30, 120, 180):
        E(m[:42 + 20 + n])
    m = rr4(cm(CM_REP, 0x9004, cm_rep(1, 2, 0x40)))
    E(m[:42 + 20 + 100])
    cap.mark('Management datagrams of every class that are shorter than 256 octets (the class parsers return)')
    for cls, attr in ((1, 0x15), (0x81, 0x15), (3, 0x11), (4, 0x12), (5, 1), (6, 1), (7, 0x10), (8, 1),
                      (0x09, 1), (0x10, 1), (0x00, 1)):
        E(rr4(ud_mad(mad(cls, 1, attr, 0x9100 + cls, fill(232, 1)), 1, 1)[:20 + 100]))
    cap.mark('SA MultiPathRecord with 255 source and destination GIDs')
    E(rr4(ud_mad(mad(3, 0x14, 0x003A, 0x9200, sa_data(multipath(255, 255))), 1, 1)))
    cap.mark('Link packets that look like a route packet with a header cut short')
    for b1 in (0x02, 0x03):
        cap.add_erf(erf(25, bytes([0x00, b1, 0x00, 0x22, 0x00, 0x00, 0x00, 0x11])))
    cap.mark('Frames cut in the eth-over-IB and EoIB payloads, link packets, LRH IPv6')
    inner = ip4(udp(b'inner-udp-payload', 5000, 5001), IP4A, IP4C)
    E(rr4(bth(UD_SEND_ONLY, 0x40, 1) + deth(0x41) + struct.pack('>HH', 0x0800, 0) + inner[:14])[:-4])
    E(rr4(bth(UD_SEND_ONLY, 0x40, 1) + deth(0x41) + struct.pack('>HH', 0x0800, 0) + inner)[:-4 - 12])
    E(rr4(bth(UD_SEND_ONLY, 0x40, 2) + deth(0x41) + struct.pack('>HH', 0xC000, 1) + eth(inner, 0x0800)[:20]))
    cap.add_erf(erf(25, bytes([0xf0, 0x02, 0x00, 0x22, 0x00, 0x00, 0x00, 0x11]) + bth(UD_SEND_ONLY, 1) + deth(1) + mad(1, 1, 0x0015, 1, b'')[:100]))
    cap.add_erf(erf(25, bytes([0x00, 0x03, 0x00, 0x22, 0x00, 0x00, 0x00, 0x11]) + grh(40, nxt=0x1B)[:20]))
    cap.add_erf(erf(25, bytes([0x00, 0x02, 0x00])))
    cap.add_lrh(lrh(20, 0x11, 0x22, 1) + b'\x60\x00\x00\x00' + VCRC)
    cap.add_lrh(lrh(20, 0x11, 0x22, 0) + b'\x00\x00' + VCRC)
    cap.add_lrh(lrh(4, 0x11, 0x22, 3) + b'\x60' * 10)
    return cap


if __name__ == '__main__':
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    verbose = '-v' in sys.argv
    c = build()
    c.write(os.path.join(outdir, 'infiniband-coverage.pcapng'))
    if verbose:
        print('main: %d frames' % len(c.frames))
        c.report('main')
    m = build_malformed()
    m.write(os.path.join(outdir, 'infiniband-coverage-malformed.pcapng'))
    if verbose:
        print('malformed: %d frames' % len(m.frames))
        m.report('malformed')
