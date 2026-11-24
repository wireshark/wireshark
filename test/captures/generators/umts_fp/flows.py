# Helper module for the umts_fp capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Flow generators for the FP-over-UDP heuristics.  Each generator takes a
# seed (the synthetic transport block bytes depend on it: MAC, RLC and RRC
# decode them) and returns a list of (payload, reverse) UDP datagrams of one
# flow.  search.py picks seeds for which the whole stack decodes cleanly.
from fplib import bitpack, fp_ctl, fp_data, fp_edch, random, struct

FLOWS = {}
ONEPASS = set()      # flows whose first datagram is only framed by a later one: -2 differs by design

def flow_gen(fn):
    FLOWS[fn.__name__] = fn
    return fn

def onepass(fn):
    ONEPASS.add(fn.__name__)
    return fn

def um_pdu(sn, sdu, size):
    """RLC UM PDU of 'size' octets holding one complete SDU: E=1, LI = SDU length (E=1), LI 0x7f
    (padding), SDU, padding"""
    pdu = bytes([((sn & 0x7f) << 1) | 1, (len(sdu) << 1) | 1, 0x7f << 1]) + sdu
    assert len(pdu) <= size
    return pdu + bytes(size - len(pdu))

def am_sdu_pdu(sn, sdu, size, poll=0):
    """RLC AM PDU of 'size' octets holding one complete SDU (HE=01, LI, LI padding)"""
    pdu = bytes([0x80 | (sn >> 5), ((sn & 0x1f) << 3) | (poll << 2) | 1, (len(sdu) << 1) | 1, 0x7f << 1]) + sdu
    assert len(pdu) <= size
    return pdu + bytes(size - len(pdu))

def rb(rnd, n):
    return bytes(rnd.randrange(256) for _ in range(n))

def tb148(rnd, sn, ct=1):
    """4 bit C/T + 18 octet RLC UM PDU = 148 bits (19 octets)"""
    return bitpack([(4, ct), (144, int.from_bytes(um_pdu(sn, rb(rnd, rnd.randrange(3, 12)), 18), 'big'))])

@flow_gen
def dch(seed):
    rnd = random.Random(seed)
    out = []
    # DL data (24 octets): framed as DCH
    out.append((fp_data(bytes([1, 0x01]), tb148(rnd, 0)), False))
    # UL data (26): TB, QE, CRCI byte
    out.append((fp_data(bytes([2, 0x01]), tb148(rnd, 0) + bytes([0x55, 0x00])), True))
    out.append((fp_data(bytes([3, 0x01]), tb148(rnd, 1)), False))
    # control frames on the framed flow: DL sync, timing adjustment, UL sync
    out.append((fp_ctl(1, bytes([4])), False))
    out.append((fp_ctl(2, bytes([5, 0x01, 0x23])), True))
    out.append((fp_data(bytes([4, 0x00])), False))        # DL, no TB
    out.append((fp_data(bytes([5, 0x00]), b'\x00\x00'), True))   # UL, no TB: QE + CRCI
    return out

@flow_gen
def fach1(seed):
    rnd = random.Random(seed)
    tctf = rnd.choice([0x40, 0x50, 0x5f, 0x80, 0x60, 0x6a, 0x00, 0x11, 0xc0, 0xd5, 0x00, 0x00])
    tb = bytes([tctf]) + rb(rnd, 44)
    out = [(fp_data(bytes([7, 0x01, 0x00]), tb), False)]
    return out

@flow_gen
def fach2(seed):
    rnd = random.Random(seed)
    out = []
    tb = bytes([0x40]) + rb(rnd, 20)
    out.append((fp_data(bytes([9, 0x01, 0x00]), bytes([0x00]) + rb(rnd, 20)), False))          # 4 + 21 + 2 = 27
    tb2 = (bytes([0x00]) + rb(rnd, 20)) + (bytes([0x00]) + rb(rnd, 20))
    out.append((fp_data(bytes([10, 0x02, 0x00]), tb2), False))        # 4 + 42 + 2 = 48
    return out

@flow_gen
def rach(seed):
    rnd = random.Random(seed)
    out = []
    # 28 octets: 4 + 21 (168 bits) + CRCI byte + 2; TCTF 00 = CCCH
    tb = bytes([rnd.choice([0x00, 0x10, 0x20]) | (rnd.randrange(16))]) + rb(rnd, 20)
    out.append((fp_data(bytes([11, 0x00, 0x00]), tb + b'\x00'), True))
    # 52 octets: 4 + 45 (360 bits) + CRCI + 2; TCTF 01 = DCCH over RACH
    tb = bytes([0x40 | rnd.randrange(64)]) + rb(rnd, 44)
    out.append((fp_data(bytes([12, 0x01, 0x00]), tb + b'\x00'), True))
    return out

@flow_gen
@onepass
def pch_pi_tb(seed):
    """PI bitmap of 18 bits first, then a TB-only frame and frames with both"""
    rnd = random.Random(seed)
    out = []
    out.append((fp_data(bytes([0x00, 0x21, 0x00]), bytes([0xa0, 0x41, 0xc0])), False))
    out.append((fp_data(bytes([0x01, 0x20, 0x01]), bytes([0x40]) + rb(rnd, 9)), False))
    out.append((fp_data(bytes([0x02, 0x21, 0x01]), bytes([0xa0, 0x41, 0xc0, 0x40]) + rb(rnd, 9)), False))
    return out

@flow_gen
@onepass
def pch_tb_pi(seed):
    """TB first (10 octets, no PI), then 36 bit PI bitmap"""
    rnd = random.Random(seed)
    out = []
    out.append((fp_data(bytes([0x00, 0x20, 0x01]), bytes([0x40]) + rb(rnd, 9)), False))
    out.append((fp_data(bytes([0x01, 0x21, 0x00]), bytes([0xa0, 0x41, 0xc0, 0x11, 0x22])), False))
    out.append((fp_data(bytes([0x02, 0x20, 0x00]), b''), False))
    return out

@flow_gen
@onepass
def pch_pi72(seed):
    """72 bit bitmap, TB of 30 octets in the same frame as a bitmap"""
    rnd = random.Random(seed)
    out = []
    out.append((fp_data(bytes([0x00, 0x21, 0x00]), bytes(range(0xa0, 0xa9))), False))
    out.append((fp_data(bytes([0x01, 0x21, 0x01]), bytes(range(0xa0, 0xa9)) + bytes([0x40]) + rb(rnd, 29)), False))
    out.append((fp_data(bytes([0x02, 0x20, 0x01]), bytes([0x40]) + rb(rnd, 29)), False))
    return out

@flow_gen
@onepass
def pch_pi144(seed):
    """144 bit bitmap with the low CFN bits set (PCH, not DCH)"""
    rnd = random.Random(seed)
    out = []
    out.append((fp_data(bytes([0x00, 0x31, 0x00]), bytes([0x80 | i for i in range(18)])), False))
    out.append((fp_data(bytes([0x01, 0x20, 0x01]), bytes([0x40]) + rb(rnd, 9)), False))
    return out

def hs1_hdr(seq, pdulen_bits, npdus, buf, flags=0):
    return bytes([(seq << 4) | 3, (pdulen_bits >> 5) & 0xff, ((pdulen_bits & 0x1f) << 3) | flags, npdus]) + struct.pack('>H', buf)

@flow_gen
def hsdsch1(seed):
    rnd = random.Random(seed)
    out = []
    sn = list(range(100))
    for k, (plen, n) in enumerate([(336, 2), (656, 1)]):
        pdus = b''
        for i in range(n):
            # 4 bit padding + the MAC-d PDU (an RLC AM PDU), byte padded
            am = am_sdu_pdu(sn.pop(0), rb(rnd, rnd.randrange(3, plen // 8 - 5)), plen // 8)
            pdus += bitpack([(4, 0), (plen, int.from_bytes(am, 'big'))])
        out.append((fp_data(hs1_hdr(k, plen, n, 100 + k), pdus), False))
    return out

def hs2_blocks(blocks):
    """HS-DSCH type 2 PDU block headers; blocks = [(pdu_len, n, lchid)]"""
    f = []
    for i, (ln, n, lch) in enumerate(blocks):
        if i % 2 == 0:
            f += [(11, ln), (1, 0), (4, n)]
            if i == len(blocks) - 1:
                f += [(4, lch), (4, 0)]
            else:
                f += [(4, lch)]
        else:
            f += [(11, ln), (1, 0), (4, n), (4, lch)]
    return bitpack(f)

@flow_gen
def hsdsch2(seed):
    rnd = random.Random(seed)
    out = []
    sn = {}
    # LCHID field 8 and 10 are lchid 9 and 11: PS DTCH over AM (clean IPv4 SDUs)
    for k, blocks in enumerate([[(42, 1, 8)], [(40, 2, 8), (36, 1, 10)], [(38, 1, 10), (38, 1, 8), (40, 1, 10)]]):
        hdr = bytes([(k << 4) | 2, len(blocks) << 3, 0x00]) + struct.pack('>H', 50) + hs2_blocks(blocks)
        pl = b''
        for ln, n, lch in blocks:
            for i in range(n):
                s_ = sn.setdefault(lch, [])
                pl += am_sdu_pdu(len(s_), icmp_sdu(rnd), ln)
                s_.append(1)
        out.append((fp_data(hdr, pl), False))
    return out

@flow_gen
def unknown_ctl(seed):
    """control frame first: the flow is framed with an unknown channel"""
    rnd = random.Random(seed)
    out = [(fp_ctl(1, bytes([3])), False), (fp_ctl(2, bytes([4, 0, 5])), True)]
    return out

def icmp_sdu(rnd):
    """IPv4 + ICMP echo request (28 octets): a clean SDU for a PS DTCH"""
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 28, rnd.randrange(65536), 0, 64, 1, 0, bytes([10, 9, 0, 1]), bytes([10, 9, 0, 2]))
    k = sum(struct.unpack('>10H', ip))
    while k >> 16:
        k = (k & 0xffff) + (k >> 16)
    ip = ip[:10] + struct.pack('>H', ~k & 0xffff) + ip[12:]
    icmp = struct.pack('>BBHHH', 0, 0, 0, 1, rnd.randrange(65536))
    k = sum(struct.unpack('>4H', icmp))
    while k >> 16:
        k = (k & 0xffff) + (k >> 16)
    return ip + icmp[:2] + struct.pack('>H', ~k & 0xffff) + icmp[4:]

def edch_frame(fsn, cfn, subframes, rnd, sn, size=42, ddi_ok=True):
    """subframes: list of (subframe number, [(ddi, n_macd)]); one TSN octet and n MAC-d PDUs
    per MAC-es PDU"""
    hdr = bytes([fsn & 0xf, len(subframes) - 1, cfn])
    pl = b''
    for sfn, pdus in subframes:
        fields = [(8, sfn & 7), (4, len(pdus))]
        for ddi, n in pdus:
            fields += [(6, ddi), (6, n)]
        hdr += bitpack(fields) if (4 + 12 * len(pdus)) % 8 == 0 else bitpack(fields)
    for sfn, pdus in subframes:
        for ddi, n in pdus:
            pl += bytes([rnd.randrange(64)])
            for i in range(n):
                pl += am_sdu_pdu(sn.pop(0), icmp_sdu(rnd), size)
    return fp_edch(hdr, pl)

@flow_gen
def edch1(seed):
    rnd = random.Random(seed)
    out = []
    sn = list(range(100))
    out.append((edch_frame(1, 10, [(0, [(1, 1)])], rnd, sn), True))            # 1 subframe, 1 MAC-es PDU, 1 MAC-d
    out.append((edch_frame(2, 11, [(1, [(2, 2)])], rnd, sn), True))
    out.append((edch_frame(3, 12, [(2, [(3, 1), (4, 1)]), (3, [(5, 1)])], rnd, sn), True))
    out.append((fp_ctl(1, bytes([4])), False))
    return out
