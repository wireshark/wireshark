#!/usr/bin/env python3
# Generates test/captures/infiniband_sdp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for the InfiniBand SDP dissector (packet-infiniband_sdp.c).

    python3 mksdp.py <outdir> [-v]

writes infiniband_sdp-coverage.pcapng (every frame decodes cleanly) and
infiniband_sdp-coverage-malformed.pcapng.  All addresses are made up
(192.0.2.0/24, 2001:db8::/32, 02:00:00:00:00:xx).  -v prints the frame
ranges of each section.

SDP (Sockets Direct Protocol) is reached by default through the InfiniBand
dissector (RRoCE, UDP 4791, and RoCE v1): the CM REQ and REP carry the SDP
Hello and HelloAck in their private data (infiniband.mad.cm.private
heuristic) and the connection's service id (0x00000000_0001PPPP) makes the
payload heuristic (infiniband.payload) accept the RC sends.
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




# ====================================================================== SDP
SDP_SID = 0x0000000000010000          # 0x0000000000010000 | port
MIDS = {
    'Hello': 0x00, 'HelloAck': 0x01, 'DisConn': 0x02, 'AbortConn': 0x03, 'SendSm': 0x04,
    'RdmaWrCompl': 0x05, 'RdmaRdCompl': 0x06, 'ModeChange': 0x07, 'SrcAvailCancel': 0x08,
    'SinkAvailCancel': 0x09, 'SinkCancelAck': 0x0a, 'ChRcvBuf': 0x0b, 'ChRcvBufAck': 0x0c,
    'SuspComm': 0x0d, 'SuspCommAck': 0x0e, 'SinkAvail': 0xfd, 'SrcAvail': 0xfe, 'Data': 0xff,
}
# MIDs that carry a 48 octet header behind the BSDH
HDR48 = {0x01, 0x05, 0x06, 0x07, 0x0b, 0x0c, 0x0d, 0xfd, 0xfe}


def bsdh(mid, flags=0, bufs=0x20, length=None, mseq=0x1001, mseqack=0x4001, body=b''):
    if length is None:
        length = 16 + len(body)
    return struct.pack('>BBHIII', mid, flags, bufs, length, mseq, mseqack)


def hello_hdr(ipv=4, cap=0x3, src=IP4A, dst=IP4B, port=5000, maxadv=0x1f, ext=0x0102):
    """52 octets as the dissector reads them (the item says 48)"""
    def v(ip):
        return (b'\0' * 12 + ip) if len(ip) == 4 else ip
    return (bytes([0x10, (ipv << 4) | cap, 0, maxadv]) + struct.pack('>IIH', 0x8000, 0x4000, port)
            + b'\0\0' + v(src) + v(dst) + b'\0\0' + struct.pack('>H', ext))


def sdp_msg(mid, seed=1, flags=0, mseq=0x1001, mseqack=0x4001, extra=b'', **hello_kw):
    if mid == 0x00:
        body = hello_hdr(**hello_kw)
    elif mid in HDR48:
        body = fill(48, seed)
    elif mid == 0xff:
        body = extra or b'sdp stream data ' + fill(40, seed)
        return bsdh(mid, flags, mseq=mseq, mseqack=mseqack, body=body) + body
    else:
        body = b''
    return bsdh(mid, flags, mseq=mseq, mseqack=mseqack, body=body) + body + extra


def sdp_session(E, wrap, a, b, tid, qp_a, qp_b, port, v4, lids, tag):
    """CM REQ with a Hello, REP with a HelloAck, RTU, one RC message of every
    MID in each direction, DREQ/DREP"""
    sid = SDP_SID | port
    comm_a, comm_b = tid * 2, tid * 2 + 1
    la, lb = lids
    hello = sdp_msg(0x00, ipv=4 if v4 else 6, src=a, dst=b, port=port)
    E(wrap(cm(CM_REQ, tid, cm_req(comm_a, sid, qp_a, la, lb, a, b, priv=hello, v4=v4)), a, b))
    E(wrap(cm(CM_REP, tid, cm_rep(comm_b, comm_a, qp_b, priv=sdp_msg(0x01, 3, mseq=0x1001, mseqack=0x4001))), b, a))
    E(wrap(cm(CM_RTU, tid, cm_rtu(comm_a, comm_b)), a, b))
    mseq = 0x1001
    for name, mid in MIDS.items():
        mseq += 1
        # Hello and HelloAck also travel as ordinary messages
        E(wrap(bth(RC_SEND_ONLY, qp_b, mseq) + sdp_msg(mid, mid + 1, flags=mid & 7, mseq=mseq, mseqack=mseq + 0x3000,
                                                      src=a, dst=b, ipv=4 if v4 else 6), a, b))
        E(wrap(bth(RC_SEND_ONLY, qp_a, mseq) + sdp_msg(mid, mid + 9, flags=(mid >> 1) & 7, mseq=mseq, mseqack=mseq + 0x3001,
                                                      src=b, dst=a, ipv=4 if v4 else 6), b, a))
    E(wrap(cm(CM_DREQ, tid, cm_dreq(comm_a, comm_b, qp_b)), a, b))
    E(wrap(cm(CM_DRSP, tid, cm_drsp(comm_b, comm_a)), b, a))


def build():
    cap = Pcapng()
    E = lambda f: cap.add(0, f)

    cap.mark('RRoCE v4: SDP connection on port 5000: Hello in the CM REQ, HelloAck in the REP, every MID in both directions, DREQ/DREP')
    sdp_session(E, rr4, IP4A, IP4B, 0x1001, 0x000100, 0x000200, 5000, True, (0x11, 0x22), 'v4')
    cap.mark('RRoCE v6: SDP connection on port 5001 (IPv6 Hello)')
    sdp_session(E, rr6, IP6A, IP6B, 0x1002, 0x000110, 0x000210, 5001, False, (0x33, 0x44), 'v6')
    cap.mark('RoCE v1 (GRH): SDP connection on port 5002')
    sdp_session(E, roce1, GIDA, GIDB, 0x1003, 0x000120, 0x000220, 5002, False, (0x55, 0x66), 'v1')

    cap.mark('Flag bits, MID values in the reserved and experimental ranges, boundary values')
    # a new connection kept open: flags, length, buffers, odd MIDs
    a, b = IP4A, IP4C
    tid = 0x1004
    sid = SDP_SID | 0xffff
    E(rr4(cm(CM_REQ, tid, cm_req(0x2008, sid, 0x000130, 0x77, 0x88, a, b, priv=sdp_msg(0x00, port=0xffff, cap=0x1, maxadv=0))), a, b))
    E(rr4(cm(CM_REP, tid, cm_rep(0x2009, 0x2008, 0x000230, priv=sdp_msg(0x01, 4))), b, a))
    E(rr4(cm(CM_RTU, tid, cm_rtu(0x2008, 0x2009)), a, b))
    for flags in (0x00, 0x01, 0x02, 0x04, 0x07, 0xf8, 0xff):
        E(rr4(bth(RC_SEND_ONLY, 0x000230, 1) + sdp_msg(0xff, flags=flags, mseq=0xffffffff, mseqack=0, extra=b'flags ' + fill(8, flags)), a, b))
    for mid in (0x0f, 0x10, 0x3f, 0x40, 0x41, 0x7f, 0x80, 0x81, 0xfc):
        E(rr4(bth(RC_SEND_ONLY, 0x000230, 2) + bsdh(mid, 0, mseq=mid) + fill(20, mid), a, b))
    # Hello variants: IP version 4 and 6, capability bits, maxadverts
    for cap_bits in (0x0, 0x1, 0x2, 0x3):
        E(rr4(bth(RC_SEND_ONLY, 0x000230, 3) + sdp_msg(0x00, ipv=4, cap=cap_bits, maxadv=cap_bits * 40), a, b))
    E(rr4(bth(RC_SEND_ONLY, 0x000230, 4) + sdp_msg(0x00, ipv=6, src=IP6A, dst=IP6B, port=1, ext=0xffff), a, b))
    # a Data message with a length field of 16 (header only) and a longer one with a payload that is not text
    E(rr4(bth(RC_SEND_ONLY, 0x000230, 6) + bsdh(0xff, 0, length=16) + fill(10, 3), a, b))
    E(rr4(bth(RC_SEND_ONLY, 0x000230, 7) + bsdh(0xff, 0, length=4096) + fill(1000, 3), a, b))
    # SDP in the RC sends of other opcodes
    E(rr4(bth(RC_SEND_ONLY_IMM, 0x000230, 8) + immdt() + sdp_msg(0x02), a, b))
    E(rr4(bth(RC_WRITE_ONLY, 0x000230, 9) + reth() + sdp_msg(0xff), a, b))

    cap.mark('Not SDP: a payload of 16 octets that is no known MID, a connection with another service id, no connection')
    E(rr4(bth(RC_SEND_ONLY, 0x000230, 11) + fill(16, 1), a, b))
    # connection with a non SDP service id (the iSER one)
    tid = 0x1005
    E(rr4(cm(CM_REQ, tid, cm_req(0x3008, 0x0000000001060CBC, 0x000140, 0x99, 0xaa, IP4A, IP4B)), IP4A, IP4B))
    E(rr4(cm(CM_REP, tid, cm_rep(0x3009, 0x3008, 0x000240)), IP4B, IP4A))
    E(rr4(bth(RC_SEND_ONLY, 0x000240, 1) + sdp_msg(0xff, extra=b'not sdp, service id differs' + fill(8, 1)), IP4A, IP4B))
    E(rr4(bth(RC_SEND_ONLY, 0x000140, 1) + sdp_msg(0x02), IP4B, IP4A))
    # no connection at all
    E(rr4(bth(RC_SEND_ONLY, 0x000fff, 1) + sdp_msg(0xff, extra=b'no connection ' + fill(16, 1)), IP4C, IP4A))

    # --------------------------------------------- reproducers of the fixes
    cap.mark('Fix: MID ranges and ModeChange header (frames of the first connection and the reserved MIDs above)')
    E(rr4(bth(RC_SEND_ONLY, 0x000230, 12) + sdp_msg(0x07, 7, mseq=3), a, b))
    E(rr4(bth(RC_SEND_ONLY, 0x000230, 13) + bsdh(0x20, 0) + fill(30, 1), a, b))
    E(rr4(bth(RC_SEND_ONLY, 0x000230, 14) + bsdh(0x50, 0) + fill(30, 1), a, b))
    E(rr4(bth(RC_SEND_ONLY, 0x000230, 15) + bsdh(0xa0, 0) + fill(30, 1), a, b))
    return cap


def build_malformed():
    cap = Pcapng()
    E = lambda f: cap.add(0, f)
    a, b = IP4A, IP4B
    tid = 0x1101
    E(rr4(cm(CM_REQ, tid, cm_req(0x4008, SDP_SID | 6000, 0x000150, 0x11, 0x22, a, b, priv=sdp_msg(0x00, port=6000))), a, b))
    E(rr4(cm(CM_REP, tid, cm_rep(0x4009, 0x4008, 0x000250, priv=sdp_msg(0x01, 4))), b, a))
    cap.mark('Payloads shorter than the BSDH (RPC-over-RDMA reads past 15 octets)')
    E(rr4(bth(RC_SEND_ONLY, 0x000250, 1) + fill(15, 1), a, b))
    cap.mark('Headers cut short: Hello with 40 octets, a 48 octet header type with 30 octets')
    E(rr4(bth(RC_SEND_ONLY, 0x000250, 1) + sdp_msg(0x00, port=6000)[:40], a, b))
    for mid in (0x01, 0x05, 0x06, 0x07, 0x0b, 0x0c, 0x0d, 0xfd, 0xfe):
        E(rr4(bth(RC_SEND_ONLY, 0x000250, 2) + bsdh(mid) + fill(14, mid), a, b))
    cap.mark('Hello in a CM REQ private data that is cut short (frame ends inside the private data)')
    m = rr4(cm(CM_REQ, 0x1102, cm_req(0x4108, SDP_SID | 6001, 0x000160, 0x11, 0x22, a, b, priv=sdp_msg(0x00, port=6001))), a, b)
    E(m[:42 + 20 + 12 + 140 + 40])
    return cap


if __name__ == '__main__':
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    verbose = '-v' in sys.argv
    c = build()
    c.write(os.path.join(outdir, 'infiniband_sdp-coverage.pcapng'))
    if verbose:
        print('main: %d frames' % len(c.frames))
        c.report('main')
    m = build_malformed()
    m.write(os.path.join(outdir, 'infiniband_sdp-coverage-malformed.pcapng'))
    if verbose:
        print('malformed: %d frames' % len(m.frames))
        m.report('malformed')
