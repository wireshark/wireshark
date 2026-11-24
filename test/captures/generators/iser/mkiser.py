#!/usr/bin/env python3
# Generates test/captures/iser_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for the iSER dissector (packet-iser.c).

    python3 mkiser.py <outdir> [-v]

writes iser-coverage.pcapng (every frame decodes cleanly) and
iser-coverage-malformed.pcapng.  All addresses are made up
(192.0.2.0/24, 2001:db8::/32, 02:00:00:00:00:xx).  -v prints the frame
ranges of each section.

iSER (iSCSI Extensions for RDMA) is reached by default through the
InfiniBand dissector (RRoCE, UDP 4791, and RoCE v1): the connection's
service id (0x0000000001060CBC: IP CM, TCP, port 3260) makes the iSER
heuristics (infiniband.payload and infiniband.mad.cm.private) accept the
RC sends and the private data of the CM messages.
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




# ====================================================================== iSER
SID_ISER = 0x0000000001060CBC          # IP CM, TCP, port 3260
ISER_CTRL, ISER_HELLO, ISER_HELLOREPLY = 0x10, 0x20, 0x30
WSV, RSV, REJ = 0x08, 0x04, 0x01


def bhs(opcode, flags=0x80, ahs=0, dsl=0, lun=0, itt=1, rest=b'', cdb=b''):
    """48 octet iSCSI basic header segment"""
    h = bytes([opcode, flags, 0, 0, ahs]) + dsl.to_bytes(3, 'big') + struct.pack('>Q', lun)
    h += struct.pack('>I', itt)
    body = (rest + cdb).ljust(48 - len(h), b'\0')
    return (h + body)[:48]


def iser_ctrl(flags=0, wstag=0, wva=0, rstag=0, rva=0, pdu=None, tail=b''):
    """iSER header (28 octets: flags byte, 3 reserved, write STag/VA, read STag/VA) + iSCSI PDU"""
    h = bytes([ISER_CTRL | flags, 0, 0, 0]) + struct.pack('>IQIQ', wstag, wva, rstag, rva)
    return h + (pdu if pdu is not None else bhs(0x00)) + tail


def iser_hello(ird=16, vers=0xaa, pad=48):
    return bytes([ISER_HELLO, vers]) + struct.pack('>H', ird) + b'\0' * (28 - 4) + fill(pad, 2)


def iser_helloreply(ord_=8, flags=0, vers=0xaa, pad=48):
    return bytes([ISER_HELLOREPLY | flags, vers]) + struct.pack('>H', ord_) + b'\0' * (28 - 4) + fill(pad, 3)


PDUS = [
    bhs(0x40, 0x80, itt=0x10, rest=struct.pack('>IIII', 0xffffffff, 1, 1, 0)),                      # NOP-Out
    bhs(0x01, 0xc1, lun=0x0001000000000000, itt=0x11,
        rest=struct.pack('>IIII', 512, 2, 1, 0), cdb=b'\x12\x00\x00\x00\x24\x00'),                 # SCSI Command (Inquiry)
    bhs(0x03, 0x87, itt=0x12, rest=b'\0' * 8 + struct.pack('>HHIII', 1, 0, 1, 0, 0)),               # Login request
    bhs(0x04, 0x80, itt=0x13, rest=struct.pack('>IIII', 0xffffffff, 2, 1, 0)),                      # Text request
    bhs(0x06, 0x80, itt=0x14, rest=struct.pack('>IIII', 0, 3, 1, 0)),                               # Logout request
    bhs(0x21, 0x80, itt=0x11, rest=struct.pack('>IIII', 0, 1, 2, 3)),                               # SCSI Response
    bhs(0x20, 0x80, itt=0x10, rest=struct.pack('>IIII', 0xffffffff, 4, 2, 0)),                      # NOP-In
    bhs(0x23, 0x80, itt=0x12, rest=b'\0' * 8 + struct.pack('>HHIII', 1, 0, 1, 0, 0)),               # Login response
]


def iser_session(E, wrap, a, b, tid, qp_a, qp_b, v4, lids, port=3260, reject=False):
    sid = 0x0000000001060000 | port
    comm_a, comm_b = tid * 2, tid * 2 + 1
    la, lb = lids
    # IP CM private data (36 octets) then 56 octets of consumer data: too short for iSER
    ipv = 4 if v4 else 6
    priv = ipcm_priv(ipv, a, b, sport=0x4000, consumer=iser_hello(pad=20)[:56])
    E(wrap(cm(CM_REQ, tid, cm_req(comm_a, sid, qp_a, la, lb, a, b, priv=priv, v4=v4)), a, b))
    E(wrap(cm(CM_REP, tid, cm_rep(comm_b, comm_a, qp_b, priv=iser_helloreply())), b, a))
    E(wrap(cm(CM_RTU, tid, cm_rtu(comm_a, comm_b, priv=iser_hello())), a, b))
    psn = 0
    # iSER Hello and HelloReply as ordinary messages
    for flags in (0, REJ):
        psn += 1
        E(wrap(bth(RC_SEND_ONLY, qp_a, psn) + iser_helloreply(flags=flags), b, a))
    psn += 1
    E(wrap(bth(RC_SEND_ONLY, qp_b, psn) + iser_hello(ird=0xffff), a, b))
    # control PDUs with every flag combination and iSCSI PDU types
    for i, pdu in enumerate(PDUS):
        flags = (0, WSV, RSV, WSV | RSV)[i % 4]
        psn += 1
        src, dst, q = (a, b, qp_b) if i % 2 == 0 else (b, a, qp_a)
        E(wrap(bth(RC_SEND_ONLY, q, psn) + iser_ctrl(flags, 0x1234 * (flags & WSV > 0), 0x7000 + i,
                                                       0x5678 * (flags & RSV > 0), 0x8000 + i, pdu), src, dst))
    # with data segment
    psn += 1
    E(wrap(bth(RC_SEND_ONLY, qp_b, psn) + iser_ctrl(WSV | RSV, 0xaabbccdd, 0x123456789a, 0x11223344, 0x555555555555,
                                                      PDUS[1], tail=b'data segment ' + fill(40, 4)), a, b))
    if reject:
        psn += 1
        E(wrap(cm(CM_REQ, tid + 1, cm_req(comm_a + 100, sid, qp_a + 1, la, lb, a, b, priv=priv, v4=v4)), a, b))
        E(wrap(cm(CM_REJ, tid + 1, cm_rej(comm_b + 100, comm_a + 100, 28, priv=iser_helloreply(flags=REJ))), b, a))
    E(wrap(cm(CM_DREQ, tid, cm_dreq(comm_a, comm_b, qp_b, priv=iser_hello())), a, b))
    E(wrap(cm(CM_DRSP, tid, cm_drsp(comm_b, comm_a, priv=iser_helloreply())), b, a))


def build():
    cap = Pcapng()
    E = lambda f: cap.add(0, f)

    cap.mark('RRoCE v4: iSER connection on port 3260: CM with HelloReply in the REP, Hello and HelloReply messages, control PDUs')
    iser_session(E, rr4, IP4A, IP4B, 0x1001, 0x000100, 0x000200, True, (0x11, 0x22))
    cap.mark('RRoCE v6: iSER connection (IPv6 IP CM)')
    iser_session(E, rr6, IP6A, IP6B, 0x1002, 0x000110, 0x000210, False, (0x33, 0x44))
    cap.mark('RoCE v1 (GRH): iSER connection with a rejected second request')
    iser_session(E, roce1, GIDA, GIDB, 0x1003, 0x000120, 0x000220, False, (0x55, 0x66), reject=True)

    cap.mark('Not iSER: invalid iSER headers on an iSER connection (iser_heur_true reproducer: the heuristic claimed them), '
             'a payload shorter than the iSER and iSCSI headers')
    a, b = IP4A, IP4C
    tid = 0x1004
    E(rr4(cm(CM_REQ, tid, cm_req(0x2008, SID_ISER, 0x000130, 0x77, 0x88, a, b, priv=ipcm_priv(4, a, b))), a, b))
    E(rr4(cm(CM_REP, tid, cm_rep(0x2009, 0x2008, 0x000230)), b, a))
    inv = []
    # invalid control flag combinations, reserved opcodes and bad hello versions
    for flags in (0x01, 0x02, 0x03, 0x05, 0x0a, 0x0f):
        inv.append(bytes([ISER_CTRL | flags]) + b'\xee' * 99)
    for first in (0x00, 0x40, 0x50, 0xf0, 0x80):
        inv.append(bytes([first]) + b'\xee' * 99)
    for vers in (0x00, 0x0a, 0xa0, 0xab, 0xba):
        inv.append(bytes([ISER_HELLO, vers]) + b'\xee' * 98)
        inv.append(bytes([ISER_HELLOREPLY, vers]) + b'\xee' * 98)
    for i, pl in enumerate(inv):
        E(rr4(bth(RC_SEND_ONLY, 0x000230, 1 + i) + pl, a, b))
    # shorter than 76 octets
    E(rr4(bth(RC_SEND_ONLY, 0x000230, 40) + iser_ctrl()[:75], a, b))
    E(rr4(bth(RC_SEND_ONLY, 0x000230, 41) + iser_hello()[:60], a, b))
    cap.mark('Not iSER: service id of another upper layer protocol, another TCP port, no connection')
    # same IP CM / TCP service id but port 3261 (outside the default range)
    tid = 0x1005
    E(rr4(cm(CM_REQ, tid, cm_req(0x3008, 0x0000000001060CBD, 0x000140, 0x99, 0xaa, IP4A, IP4B, priv=ipcm_priv(4, IP4A, IP4B))), IP4A, IP4B))
    E(rr4(cm(CM_REP, tid, cm_rep(0x3009, 0x3008, 0x000240, priv=iser_helloreply())), IP4B, IP4A))
    E(rr4(bth(RC_SEND_ONLY, 0x000240, 1) + iser_ctrl(), IP4A, IP4B))
    # IP CM service id of another protocol number (0x12)
    tid = 0x1006
    E(rr4(cm(CM_REQ, tid, cm_req(0x3108, 0x0000000001120CBC, 0x000150, 0x99, 0xaa, IP4A, IP4B, priv=ipcm_priv(4, IP4A, IP4B))), IP4A, IP4B))
    E(rr4(cm(CM_REP, tid, cm_rep(0x3109, 0x3108, 0x000250, priv=iser_helloreply())), IP4B, IP4A))
    E(rr4(bth(RC_SEND_ONLY, 0x000250, 1) + iser_ctrl(), IP4A, IP4B))
    # non IP CM service id
    tid = 0x1007
    E(rr4(cm(CM_REQ, tid, cm_req(0x3208, 0x00000000000a0b0c, 0x000160, 0x99, 0xaa, IP4A, IP4B)), IP4A, IP4B))
    E(rr4(cm(CM_REP, tid, cm_rep(0x3209, 0x3208, 0x000260, priv=iser_helloreply())), IP4B, IP4A))
    E(rr4(bth(RC_SEND_ONLY, 0x000260, 1) + iser_ctrl(), IP4A, IP4B))
    E(rr4(bth(RC_SEND_ONLY, 0x000ffe, 1) + iser_ctrl(), IP4C, IP4A))

    cap.mark('Fix: CM REQ over IPv4 followed by a REP over IPv6 with the same hash key; the iSER Hello over IPv4 to the '
             'responder QP is only recognised when the connection keeps its IPv4 addresses')
    tid_req = 0x1122334455667788
    key = _H(tid_req, IP4A)
    tid_rep = _Hinv(key, IP6A)
    assert _H(tid_rep, IP6A) == key
    E(rr4(cm(CM_REQ, tid_req, cm_req(0x91, SID_ISER, 0x000100, 0x0011, 0x0022, IP4A, IP4B, priv=ipcm_priv(4, IP4A, IP4B))), IP4A, IP4B))
    E(rr6(cm(CM_REP, tid_rep, cm_rep(0x92, 0x91, 0x000200)), IP6B, IP6A))
    E(rr4(bth(RC_SEND_ONLY, 0x000200, 1) + iser_hello(), IP4A, IP4B))
    E(rr6(bth(RC_SEND_ONLY, 0x000200, 1) + iser_hello(), IP6A, IP6B))
    return cap


def build_malformed():
    cap = Pcapng()
    E = lambda f: cap.add(0, f)
    a, b = IP4A, IP4B
    tid = 0x1101
    E(rr4(cm(CM_REQ, tid, cm_req(0x4008, SID_ISER, 0x000150, 0x11, 0x22, a, b, priv=ipcm_priv(4, a, b))), a, b))
    E(rr4(cm(CM_REP, tid, cm_rep(0x4009, 0x4008, 0x000250)), b, a))
    cap.mark('iSER over Decode As (heuristics off) with short and invalid headers (needs -d infiniband,iser)')
    for pl in (iser_ctrl()[:10], iser_hello()[:20], bytes([0x13]) + b'\xee' * 99, bytes([ISER_HELLO, 0x00]) + b'\0' * 80):
        E(rr4(bth(RC_SEND_ONLY, 0x000250, 1) + pl, a, b))
    cap.mark('IP CM service id of UDP (0x0111...): the SDP heuristic (bit 0x10000 of the service id) takes the CM private data and the RC send')
    E(rr4(cm(CM_REQ, 0x1102, cm_req(0x4108, 0x0000000001110CBC, 0x000160, 0x11, 0x22, a, b, priv=ipcm_priv(4, a, b))), a, b))
    E(rr4(cm(CM_REP, 0x1102, cm_rep(0x4109, 0x4108, 0x000260, priv=iser_helloreply())), b, a))
    E(rr4(bth(RC_SEND_ONLY, 0x000260, 1) + iser_ctrl(), a, b))
    cap.mark('iSER control PDU with a cut iSCSI header')
    E(rr4(bth(RC_SEND_ONLY, 0x000250, 2) + iser_ctrl(pdu=bhs(0x01)[:40], tail=b'')[:70], a, b))
    return cap


if __name__ == '__main__':
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    verbose = '-v' in sys.argv
    c = build()
    c.write(os.path.join(outdir, 'iser-coverage.pcapng'))
    if verbose:
        print('main: %d frames' % len(c.frames))
        c.report('main')
    m = build_malformed()
    m.write(os.path.join(outdir, 'iser-coverage-malformed.pcapng'))
    if verbose:
        print('malformed: %d frames' % len(m.frames))
        m.report('malformed')
