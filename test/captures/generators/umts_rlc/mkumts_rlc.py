#!/usr/bin/env python3
# Generates test/captures/umts_rlc_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic UMTS RLC captures (epan/dissectors/packet-umts_rlc.c).

Usage: mkumts_rlc.py <outdir>
Writes umts_rlc-coverage.pcapng and umts_rlc-coverage-malformed.pcapng.

Two ways reach RLC:
 * Exported PDU records (interface 0, link type 252) naming fp_hint carry an
   FP Hint header, AAL2/ATM header and FP DCH frame; FP, MAC and RLC then use
   the per-frame info of the hint.  This works at default preferences.
 * RLC over UDP: UDP datagrams (interface 1, Ethernet) that start with the
   signature "umts-rlc" and carry optional tags (channel type, mode, direction,
   U-RNTI, radio bearer id, LI size) before the PDU.  The heuristic dissector
   "rlc_udp" is disabled by default (--enable-heuristic rlc_udp).
"""
import struct
import sys
import os
import json
from umtslib import (
    am_pdu, am_sdu, ATM, bits, data, DCH, exp_pdu, fp_frame, hint, ip_checksum, ipv4_udp,
    rb_entry, tf4, um_pdu, um_sdu, write_pcapng,
)

out = sys.argv[1] if len(sys.argv) > 1 else '.'
UOFF = 0
SEEDS = {}
_sf = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'seeds.json')
if os.path.exists(_sf):
    SEEDS = json.load(open(_sf))

main, mal, names, BUILDERS = [], [], [], []
SPANS = {}      # name -> (first frame, last frame) of the main capture

# RLC modes (enum rlc_mode) and UDP framing values
TM, UM, AM = 0, 1, 2
PCCH, CCCH, DCCH, PSDTCH, CTCH, BCCH = 1, 2, 3, 4, 5, 6
UNK, DCCH_, PS, CS = 0, 1, 2, 3     # content values of the hint


def eth_udp(payload, sport=50000, dport=50001):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0x1000, 0, 64, 17, 0,
                     bytes((192, 0, 2, 10)), bytes((192, 0, 2, 20)))
    ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
    return b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00' + ip + udp


def rlc_udp(payload, channel=None, mode=None, uplink=None, urnti=None, rbid=None, li_size=None, extra=b''):
    """RLC-over-UDP framing (dissect_rlc_heur); uplink: True/False/None"""
    b = b'umts-rlc'
    if channel is not None:
        b += bytes([0x02, channel])
    if mode is not None:
        b += bytes([0x03, mode])
    if uplink is not None:
        b += bytes([0x04, 0 if uplink else 1])
    if urnti is not None:
        b += bytes([0x05]) + struct.pack('>I', urnti + UOFF)
    if rbid is not None:
        b += bytes([0x06, rbid])
    if li_size is not None:
        b += bytes([0x07, li_size])
    return b + extra + bytes([0x01]) + payload


def U(pdu, **tags):
    return (1, eth_udp(rlc_udp(pdu, **tags)))


def H(hintpdu, up=False):
    return (0, exp_pdu('fp_hint', hintpdu, 1 if up else None))


def R(urnti, rlc=0, content=0, rbid=0, ctmux=0, ciph=0, deciph=0):
    return rb_entry(urnti + UOFF if urnti else 0, rlc, content, rbid, ctmux, ciph, deciph)


def hdch(mode, payload, urnti, rb=2, content=DCCH_, ctmux=0, ciph=0, deciph=0, up=False):
    """a DCH FP frame with one transport block through FP Hint"""
    tb, nb = bits(*(([(rb - 1, 4)]) if ctmux else []), payload)
    hdr = bytes([21, 0])
    pl = tb + (b'\x00\x00' if up else b'')
    return H(hint(ATM, DCH, b'\x01' + tf4(1, 1, len(tb) * 8) + b'\x01' + R(urnti, mode, content, rb, ctmux, ciph, deciph),
                  fp_frame(hdr, pl)), up)


def add(name, fn, lst=None, noseed=False):
    """fn(seed) -> one record or a list of records (interface, packet);
    noseed: the frames do not depend on the seed (not part of the seed search)"""
    if lst is None:
        lst = main
    if lst is main:
        names.append(name)
        if not noseed:
            BUILDERS.append((name, fn))
    first = len(lst) + 1
    r = fn(SEEDS.get(name, 0))
    lst.extend(r if isinstance(r, list) else [r])
    if lst is main:
        SPANS[name] = (first, len(lst))


def rrc(n, sd):
    return data(n, sd)


# unique U-RNTIs for every sequence
_u = [0x1000]


def un():
    _u[0] += 1
    return _u[0]


# ------------------------------------------------------------ SUFI / control PDU builders
def status_pdu(*sufis):
    """RLC AM STATUS control PDU: D/C 0, type 0, then the SUFIs from bit 4"""
    spec = [(0, 1), (0, 3)]
    for s in sufis:
        spec += s
    return bits(*spec)[0]


def piggy(*sufis):
    """the status of a piggybacked STATUS: 4 spare bits, then the SUFIs"""
    spec = [(0, 4)]
    for s in sufis:
        spec += s
    return bits(*spec)[0]


NOMORE = [(0, 4)]
def ACK(lsn): return [(2, 4), (lsn, 12)]
def WINDOW(w): return [(1, 4), (w, 12)]
def LIST(pairs): return [(3, 4), (len(pairs), 4)] + [x for sn, l in pairs for x in ((sn, 12), (l, 4))]
def BITMAP(fsn, bm): return [(4, 4), (len(bm) - 1, 4), (fsn, 12), bytes(bm)]
def RLIST(fsn, cws): return [(5, 4), (len(cws), 4), (fsn, 12)] + [(c, 4) for c in cws]
def MRW(sns, n): return [(6, 4), (len(sns), 4)] + [(s, 12) for s in sns] + [(n, 4)]
def MRW_ACK(n, sn): return [(7, 4), (n, 4), (sn, 12)]
def POLL(sn): return [(8, 4), (sn, 12)]


def reset_pdu(typ, rsn, hfn, r1=0):
    return bits((0, 1), (typ, 3), (rsn, 1), (r1, 3), (hfn, 20))[0]


# ============================================================ RLC over UDP: channel types
# TM: PCCH, BCCH, UL CCCH, PS DTCH, unspecified channel
add('u_pcch', lambda sd: U(rrc(8, sd), channel=PCCH))
add('u_bcch', lambda sd: U(rrc(10, sd), channel=BCCH))
add('u_ccch_ul', lambda sd: U(rrc(8, sd), channel=CCCH, uplink=True))
add('u_ps_tm', lambda sd: U(ipv4_udp(8, sd), channel=PSDTCH, mode=TM, urnti=un(), rbid=9))
add('u_unk_tm', lambda sd: U(data(6, sd), mode=TM, urnti=un(), rbid=3))
# UM: DL CCCH, CTCH (BMC), DCCH uplink and downlink, PS DTCH, unspecified
add('u_ccch_dl', lambda sd: U(um_sdu(0, rrc(8, sd)), channel=CCCH, uplink=False, urnti=un()))
add('u_ctch', lambda sd: U(um_sdu(0, rrc(8, sd)), channel=CTCH, urnti=un()))
add('u_dcch_um_ul', lambda sd: U(um_sdu(0, rrc(6, sd)), channel=DCCH, mode=UM, uplink=True, urnti=un(), rbid=1))
add('u_dcch_um_dl', lambda sd: U(um_sdu(0, rrc(6, sd)), channel=DCCH, mode=UM, uplink=False, urnti=un(), rbid=1))
add('u_ps_um', lambda sd: U(um_sdu(0, ipv4_udp(8, sd)), channel=PSDTCH, mode=UM, urnti=un(), rbid=9))
add('u_unk_um', lambda sd: U(um_sdu(0, data(8, sd)), mode=UM, urnti=un(), rbid=3))
# AM: DCCH uplink and downlink, PS DTCH, unspecified
add('u_dcch_am_ul', lambda sd: U(am_sdu(0, rrc(6, sd)), channel=DCCH, mode=AM, uplink=True, urnti=un(), rbid=2))
add('u_dcch_am_dl', lambda sd: U(am_sdu(0, rrc(6, sd)), channel=DCCH, mode=AM, uplink=False, urnti=un(), rbid=2))
add('u_ps_am', lambda sd: U(am_sdu(0, ipv4_udp(8, sd)), channel=PSDTCH, mode=AM, urnti=un(), rbid=9))
add('u_unk_am', lambda sd: U(am_sdu(0, data(8, sd)), mode=AM, urnti=un(), rbid=3))
# a frame with a tag after the others; the default U-RNTI (1) when there is none
add('u_default_ueid', lambda sd: U(am_sdu(0, data(8, sd)), mode=AM, rbid=3))
add('u_li_size', lambda sd: U(am_sdu(0, data(8, sd)), mode=AM, rbid=3, urnti=un(), li_size=1))

# ============================================================ UM reassembly (unspecified channel)
def um_seq(sd):
    u = un()
    kw = dict(mode=UM, urnti=u, rbid=3, uplink=True)
    d = data(40, sd)
    return [
        # SDU 1 (4 octets) complete, start of SDU 2 (3 octets)
        U(um_pdu(0, d[0:7], lis=(0x7c, 4)), **kw),
        # SDU 2 completed (2 octets), start of SDU 3 (3 octets)
        U(um_pdu(1, d[7:12], lis=(2,)), **kw),
        # SDU 3 ends (the previous PDU completes it, LI 0), the rest is padding
        U(um_pdu(2, d[12:20], lis=(0x00, 0x7f)), **kw),
        # a new SDU and another PDU with it complete in one PDU
        U(um_pdu(3, d[20:24], lis=(0x7c, 4)), **kw),
        # the same SN again within 5 s is a duplicate
        U(um_pdu(3, d[20:24], lis=(0x7c, 4)), **kw),
    ]


add('um_seq', um_seq)


def mal_um_seq(sd):
    """LI values that leave fragments behind: 0x7d, 0x7e (segment in UM), a fragment without LI"""
    u = un()
    kw = dict(mode=UM, urnti=u, rbid=3, uplink=True)
    d = data(40, sd)
    return [
        U(um_pdu(0, d[0:8], lis=(0x7d,)), **kw),
        U(um_pdu(1, d[8:14], lis=(0x7e,)), **kw),
        U(um_pdu(2, d[14:20]), **kw),
    ]


add('mal_um_seq', mal_um_seq, lst=mal)


def um_split(sd):
    """one SDU over three PDUs (reassembled in the last), SN 0, 1, 2"""
    u = un()
    kw = dict(channel=DCCH, mode=UM, urnti=u, rbid=1, uplink=False)
    d = rrc(6, sd)
    return [
        U(um_pdu(0, d[0:2], lis=(0x7c,)), **kw),
        U(um_pdu(1, d[2:4]), **kw),
        U(um_pdu(2, d[4:6], lis=(2,)), **kw),
    ]


add('um_split', um_split)


def um15_seq(sd):
    """UM with 15 bit LIs (UDP tag): special values 0x7ffc, 0x7ffd, 0x7ffa, 0x0000, 0x7fff and ordinary LIs"""
    u = un()
    kw = dict(mode=UM, urnti=u, rbid=3, li_size=2)
    d = data(60, sd)

    def p(sn, payload, lis):
        h = bytes([((sn & 0x7f) << 1) | 1])
        for i, li in enumerate(lis):
            h += struct.pack('>H', (li << 1) | (1 if i < len(lis) - 1 else 0))
        return h + payload
    return [
        U(p(0, d[0:8], (0x7ffc, 5)), **kw),            # new SDU, 5 octet SDU, 3 octets remaining
        U(p(1, d[8:16], (3, 0x7fff)), **kw),           # ends it (3 octets), padding
        U(p(2, d[16:24], (0x7ffc, 3, 0x7fff)), **kw),  # new SDU, 3 octets, padding
        U(p(3, d[24:32], (0x7ffa,)), **kw),            # exactly one SDU minus the last byte
    ]


add('um15_seq', um15_seq)


def mal_um15(sd):
    u = un()
    kw = dict(mode=UM, urnti=u, rbid=3, li_size=2)
    d = data(30, sd)

    def p(sn, payload, lis):
        h = bytes([((sn & 0x7f) << 1) | 1])
        for i, li in enumerate(lis):
            h += struct.pack('>H', (li << 1) | (1 if i < len(lis) - 1 else 0))
        return h + payload
    return [U(p(0, d[0:8], (0x7ffd,)), **kw),          # exactly one SDU
            U(p(9, d[32:39], (0x7ffc, 3, 4)), **kw),   # two SDUs after the start marker
            U(p(3, d[0:8], (0x7ffb,)), **kw),          # previous PDU contains the last segment (minus last byte)
            U(p(1, d[8:16], (0x7ffe,)), **kw),         # segment in UM
            U(p(2, d[16:24], (0x0000,)), **kw)]


add('mal_um15', mal_um15, lst=mal)


def um_wrap(sd):
    """SN 0..127 on one channel, then the SDU of SN 127 continues in SN 0 (the SN wraps)"""
    u = un()
    kw = dict(mode=UM, urnti=u, rbid=3, uplink=True)
    recs = []
    d = data(8, sd)
    for sn in range(0, 127):
        recs.append(U(um_sdu(sn, d[:4]), **kw))
    recs.append(U(um_pdu(127, d[:4]), **kw))                # starts an SDU
    recs.append(U(um_pdu(0, d[4:8], lis=(4,)), **kw))       # wrap: completes it
    return recs


add('um_wrap', um_wrap, noseed=True)

# ============================================================ AM reassembly (unspecified channel and DCCH)
def am_split(sd):
    u = un()
    kw = dict(channel=DCCH, mode=AM, urnti=u, rbid=2, uplink=True)
    d = rrc(6, sd)
    return [U(am_pdu(0, d[0:3], p=1), **kw),           # first part, poll bit
            U(am_pdu(1, d[3:6], he=2), **kw)]          # last octet ends the SDU


add('am_split', am_split)


def am_li(sd):
    u = un()
    kw = dict(mode=AM, urnti=u, rbid=3)
    d = data(40, sd)
    return [
        U(am_pdu(0, d[0:7], lis=(4,)), **kw),              # SDU1 (4) complete, 3 octets of SDU2
        U(am_pdu(1, d[7:12], lis=(2,)), **kw),             # SDU2 completed, 3 octets of SDU3
        U(am_pdu(2, d[12:20], lis=(0x7f,), he=1), **kw),   # padding only (keeps the SN)
        U(am_pdu(3, d[20:23], lis=(3,), he=1), **kw),      # SDU3 completed
        U(am_pdu(4, d[24:31], lis=(3, 7), he=1), **kw),    # two SDUs
        U(am_pdu(5, d[32:36], he=2), **kw),                # a complete SDU, last octet ends it
        U(am_pdu(5, d[32:36], he=2), **kw),                # duplicate of SN 5
    ]


add('am_li', am_li)


def am_piggy(sd):
    u = un()
    kw = dict(mode=AM, urnti=u, rbid=3, uplink=False)
    return [
        U(am_pdu(0, piggy(ACK(7)), lis=(0x7e,), he=1), **kw),
        U(am_pdu(1, piggy(WINDOW(100), LIST([(5, 0), (9, 3)]), ACK(20)), lis=(0x7e,), he=1), **kw),
        U(am_pdu(2, piggy(BITMAP(10, [0xa5, 0x5a]), RLIST(30, [2, 5, 1, 3]), POLL(11)), lis=(0x7e,), he=1), **kw),
    ]


add('am_piggy', am_piggy)


def am_li15(sd):
    u = un()
    kw = dict(mode=AM, urnti=u, rbid=3, li_size=2)
    d = data(40, sd)
    u2 = un()
    return [
        U(am_pdu(0, d[0:5], lis=(5,), he=1, li15=True), **kw),
        U(am_pdu(1, d[8:12], lis=(0x7fff,), he=1, li15=True), **kw),   # 15 bit padding
        U(am_pdu(2, d[16:24], he=2), **kw),
        # the 15 bit piggyback marker, alone on a channel
        U(am_pdu(0, piggy(ACK(5)), lis=(0x7ffe,), he=1, li15=True), mode=AM, urnti=u2, rbid=3, li_size=2),
    ]


add('am_li15', am_li15)


def am_variable(sd):
    """LI size by the PDU size (variable): a PDU longer than 126 octets uses 15 bit LIs"""
    u = un()
    d = data(150, sd)
    kw = dict(mode=AM, urnti=u, rbid=3, li_size=0)
    return [U(am_pdu(0, d[0:130], lis=(130,), he=1, li15=True), **kw)]


add('am_variable', am_variable)


# ============================================================ AM control PDUs
def am_ctrl(sd):
    u = un()
    kw = dict(mode=AM, urnti=u, rbid=3, uplink=True)
    return [
        U(status_pdu(NOMORE), **kw),
        U(status_pdu(ACK(100)), **kw),
        U(status_pdu(WINDOW(512), ACK(101)), **kw),
        U(status_pdu(LIST([(10, 0), (20, 5), (30, 15)]), ACK(40)), **kw),
        U(status_pdu(BITMAP(50, [0xff, 0x0f, 0xf0]), ACK(60)), **kw),
        U(status_pdu(RLIST(70, [0x4, 0x5]), ACK(80)), **kw),                 # one distance codeword
        U(status_pdu(RLIST(90, [0x1, 0x6, 0x3]), ACK(100)), **kw),           # an error burst
        U(status_pdu(MRW([111], 2), MRW_ACK(1, 112)), **kw),
        U(status_pdu(MRW([120, 130, 140], 3), ACK(150)), **kw),
        U(status_pdu(MRW([], 4), POLL(160)), **kw),                          # MRW without SN_MRW fields
        U(reset_pdu(1, 0, 0x12345), **kw),
        U(reset_pdu(2, 1, 0xabcde), **kw),
    ]


add('am_ctrl', am_ctrl)


# ============================================================ preference and special cases through FP Hint (default preferences)
add('h_dch_um', lambda sd: hdch(UM, um_sdu(0, rrc(6, sd)), un(), rb=1))
add('h_dch_am', lambda sd: hdch(AM, am_sdu(0, rrc(6, sd)), un(), rb=2, ctmux=1))
add('h_dch_ps_am', lambda sd: hdch(AM, am_sdu(0, ipv4_udp(8, sd)), un(), rb=9, content=PS))
add('h_dch_tm', lambda sd: hdch(TM, ipv4_udp(8, sd), un(), rb=9, content=PS))
add('h_dch_ul_am', lambda sd: hdch(AM, am_sdu(0, rrc(6, sd)), un(), rb=3, up=True))
add('h_dch_ul_um', lambda sd: hdch(UM, um_sdu(0, rrc(6, sd)), un(), rb=1, up=True))
add('h_dch_ciphered', lambda sd: hdch(AM, am_sdu(0, data(10, sd)), un(), rb=2, ciph=1))
add('h_dch_ciphered_um', lambda sd: hdch(UM, um_pdu(0, data(10, sd), lis=(0x7c, 8)), un(), rb=2, ciph=1))
add('h_dch_deciphered', lambda sd: hdch(AM, am_sdu(0, data(10, sd)), un(), rb=2, ciph=1, deciph=1))
# a PDU with a 15 bit LI (the hint says "variable": more than 126 octets)
add('h_dch_long_am', lambda sd: hdch(AM, am_pdu(0, ipv4_udp(120, sd), lis=(148,), he=1, li15=True), un(), rb=9, content=PS))
add('h_dch_long_um', lambda sd: hdch(UM, bytes([1]) + struct.pack('>HH', (0x7ffc << 1) | 1, 148 << 1) + ipv4_udp(120, sd), un(), rb=9, content=PS))

# RRC securityModeComplete, then PDUs of the same UE on other radio bearers (the fixed ciphering table index)
UC = [0x00abcd00]
add('rb_cipher_setup', lambda sd: [U(bytes([0x80, 0x02, 0x50, 0x00]), channel=DCCH, mode=AM, uplink=True, urnti=UC[0], rbid=2),
                                    U(bytes([0x80, 0x02, 0x50, 0x00]), channel=DCCH, mode=AM, uplink=True, urnti=UC[0], rbid=250),
                                    U(bytes([0x80, 0x02, 0x50, 0x00]), channel=DCCH, mode=AM, uplink=True, urnti=UC[0], rbid=31),
                                    U(bytes([0x80, 0x02, 0x50, 0x00]), channel=DCCH, mode=AM, uplink=True, urnti=UC[0], rbid=30)])
# the same through FP Hint: RB id 31 is the last radio bearer id
add('h_rb31', lambda sd: [hdch(AM, bytes([0x80, 0x02, 0x50, 0x00]), 0x00abcd01, rb=2, up=True),
                          hdch(AM, bytes([0x80, 0x02, 0x50, 0x00]), 0x00abcd01, rb=31, up=True)])

def smc_cipher(sd):
    """RRC SecurityModeCommand (UEA1, activation of RB 3 at SN 0) for a UE, then
    RLC AM PDUs of that UE: the ones of RB 3 are ciphered according to RRC"""
    u = un()
    smc = bits((0, 1), (16, 5), (0, 1), (0, 1), (0b100, 3), (0, 2), (0x0001, 16), (0x0001, 16),
               (0b01, 2), (0, 1), (1, 1), (0, 5), (2, 5), (0, 12), (0, 1))[0]
    dl = dict(channel=DCCH, mode=AM, uplink=False, urnti=u)
    return [U(am_sdu(0, smc), rbid=2, **dl),
            U(am_pdu(0, data(8, sd), he=2), rbid=3, **dl),       # ciphered (RB 3, SN >= 0)
            U(am_pdu(1, data(8, sd), he=2), rbid=3, **dl),
            U(am_pdu(0, data(8, sd), he=2), rbid=4, **dl),       # other RB: not ciphered
            U(am_pdu(0, data(8, sd), he=2), rbid=250, **dl),     # RB id beyond the table (the fixed index)
            U(am_pdu(0, data(8, sd), he=2), rbid=31, **dl),
            ]


add('smc_cipher', smc_cipher)


# two TBs of different UEs in one DCH frame (the second UE id 0 uses the lookup of the reproducer)
def two_tbs(sd):
    um = um_pdu(0, ipv4_udp(8, sd), lis=(36,))     # SN 0, one LI (the length of the IP packet)
    bl = len(um) * 8
    chan = bytes([2]) + tf4(1, 1, bl) + tf4(2, 1, bl) + bytes([2]) + R(0x2234, UM, PS, 9) + R(0, UM, PS, 9)
    fp = fp_frame(bytes([21, 0, 0]), um + um)
    return H(hint(ATM, DCH, chan, fp))


add('h_two_tbs', two_tbs)


# ============================================================ malformed capture: error paths
def mal_li(sd):
    u = un()
    kw = dict(mode=UM, urnti=u, rbid=3, uplink=True)
    ka = dict(mode=AM, urnti=u, rbid=3, uplink=True)
    ka15 = dict(mode=AM, urnti=un(), rbid=3, uplink=True, li_size=2)
    d = data(40, sd)
    return [
        U(um_pdu(0, d[:20], lis=tuple(range(1, 18))), **kw),          # 17 LIs: too many
        U(um_pdu(1, d[:4], lis=(100,)), mode=UM, urnti=un(), rbid=3),  # LI beyond the PDU
        U(am_pdu(0, d[:8], lis=(0x7c,), he=1), **ka),                  # UM only LI in AM
        U(am_pdu(0, d[:8], lis=(0x7ffc,), he=1, li15=True), **ka15),
        U(am_pdu(1, d[:4], he=3), **ka),                               # reserved header extension
        U(am_pdu(2, d[:8], lis=(0x7d,), he=1), **ka),                  # UM only LI in AM
        U(am_pdu(0, d[:8], lis=(0x7ffa,), he=1, li15=True), mode=AM, urnti=un(), rbid=3, uplink=True, li_size=2),
        U(am_pdu(0, d[:8], lis=(0x7ffd,), he=1, li15=True), mode=AM, urnti=un(), rbid=3, uplink=True, li_size=2),
    ]


add('mal_li', mal_li, lst=mal)


def mal_ctrl(sd):
    kw = dict(mode=AM, urnti=un(), rbid=3, uplink=True)
    return [
        U(status_pdu(LIST([])), **kw),                 # LIST without entries
        U(status_pdu(RLIST(10, [0x4])), **kw),         # last codeword even
        U(status_pdu([(9, 4)]), **kw),                 # unknown SUFI type
        U(reset_pdu(1, 0, 0x12345, r1=1), **kw),       # reserved bits
        U(bits((0, 1), (5, 3), (0, 4))[0], **kw),      # unknown control PDU type
    ]


add('mal_ctrl', mal_ctrl, lst=mal)


def mal_udp(sd):
    d = data(8, sd)
    return [
        (1, eth_udp(rlc_udp(d, mode=AM, extra=b'\x42'))),          # unknown tag
        (1, eth_udp(rlc_udp(d))),                                  # neither channel type nor mode
        (1, eth_udp(rlc_udp(d, channel=9, mode=AM, urnti=un()))),   # unknown channel type
    ]


add('mal_udp', mal_udp, lst=mal)


def mal_noinfo(sd):
    pdu = am_sdu(0, data(6, sd))
    return [(0, exp_pdu('rlc.dcch', pdu)), (0, exp_pdu('rlc.ps_dtch', pdu))]   # no FP / RLC per-frame info


add('mal_noinfo', mal_noinfo, lst=mal)


def mal_reasm(sd):
    ka = dict(mode=AM, uplink=True, rbid=3)
    d = data(20, sd)
    u1, u2, u3, u4, u5 = un(), un(), un(), un(), un()
    return [
        # SN 1 is missing for the SDU that ends in SN 2
        U(am_pdu(0, d[0:4]), urnti=u1, **ka),
        U(am_pdu(2, d[4:8], he=2), urnti=u1, **ka),
        # an SN far away from the unfinished one: the channel gives up
        U(am_pdu(0, d[0:4]), urnti=u2, **ka),
        U(am_pdu(3000, d[4:8], he=2), urnti=u2, **ka),
        U(am_pdu(1, d[4:8], he=2), urnti=u2, **ka),
        # a fragment that is never finished
        U(am_pdu(0, d[0:4]), urnti=u3, **ka),
        U(am_pdu(1, d[4:8]), urnti=u3, **ka),
        # a fragment far away from an unfinished sequence without end
        U(am_pdu(0, d[0:4]), urnti=u4, **ka),
        U(am_pdu(2500, d[4:8]), urnti=u4, **ka),
        # UM: a start marker (LI 0x7c) without the end of the SDU: a lingering end point
        U(um_pdu(0, d[0:6], lis=(0x7c,)), mode=UM, urnti=un(), rbid=3, uplink=True),
        # the same UM SN again after more than 5 s (not a duplicate): the channel gives up
        U(um_pdu(0, d[0:6]), mode=UM, urnti=u5, rbid=3, uplink=True),
        U(um_pdu(0, d[6:12]), mode=UM, urnti=u5, rbid=3, uplink=True),
        U(um_pdu(1, d[6:12]), mode=UM, urnti=u5, rbid=3, uplink=True),
    ]


add('mal_reasm', mal_reasm, lst=mal)


def mal_rrc(sd):
    # an SDU that is not valid RRC: the exception of RRC is shown by RLC and dissection goes on
    return [U(am_sdu(0, data(6, 0)), channel=DCCH, mode=AM, uplink=True, urnti=un(), rbid=2),
            U(um_sdu(0, data(6, 0)), channel=DCCH, mode=UM, uplink=True, urnti=un(), rbid=1)]


add('mal_rrc', mal_rrc, lst=mal)

# header only PDUs (shown with rlc.header_only_mode)
add('mal_header_only', lambda sd: [U(am_pdu(0, b'', he=0), mode=AM, urnti=un(), rbid=3),
                                   U(um_pdu(0, b'', lis=(0x7c,)), mode=UM, urnti=un(), rbid=3)], lst=mal)

# ============================================================ limits (the fixes of this batch)
LIM_CH = 1030        # distinct UM channels (the fix stops reassembly tables at 1024)
LIM_DUP = 1030       # AM PDUs with one SN on one channel (the fix caps the history at 1024)


def lim_dup(sd):
    u = un()
    return [U(am_pdu(0, data(4, 0), he=2), mode=AM, urnti=u, rbid=3, uplink=True) for _ in range(LIM_DUP)]


def lim_channels(sd):
    return [U(um_sdu(0, data(4, 0)), mode=UM, urnti=0x40000 + i, rbid=3, uplink=True) for i in range(LIM_CH)]


add('lim_dup', lim_dup, noseed=True)
add('lim_channels', lim_channels, noseed=True)

if os.environ.get('CAND'):
    cand, cnames = [], []
    for seed in range(int(os.environ['CAND'])):
        UOFF = seed * 0x100
        for name, fn in BUILDERS:
            r = fn(seed)
            for rec in (r if isinstance(r, list) else [r]):
                cand.append(rec)
                cnames.append([name, seed])
    write_pcapng(os.path.join(out, 'cand.pcapng'), cand, 1000)
    json.dump(cnames, open(os.path.join(out, 'cand.json'), 'w'))
    sys.exit(0)


# ------------------------------------------------------------ DCT2000 .out log (for the coverage number only)
# "rlc" primitives of a DCT2000 log call "rlc.dch_unknown" for radio bearers 1-15 (and rlc.ccch / rlc.ctch for 18 / 21),
# which nothing else can reach
def dct2000(path):
    lines = []
    t = [0]

    def prim(rb, mode, pdu, ue=7, direction='s', li=1):
        tl = bytes([0x72, 0, 0, 0, ue, 0xa2, 1, rb])
        d = bytes([0xc1]) + tl + b'\x41' + bytes([len(pdu)]) + pdu
        t[0] += 10
        lines.append('ctx.1/rlc/1,%d,%d %s tm %d.%04d l $%s' % (li, mode, direction, t[0] // 10000, t[0] % 10000, d.hex()))
    body = data(6, 3)
    ip = ipv4_udp(8, 0)
    # TM, UM, AM, UM and AM flagged as ciphered, on radio bearers 3, 4, 5, 6 and 7 (DCCH/PS DTCH unknown), both directions
    prim(3, 1, body, ue=7)
    prim(4, 2, um_sdu(0, body), ue=8)
    prim(5, 3, am_sdu(0, body), ue=9, direction='r')
    prim(6, 4, um_sdu(0, body), ue=10)
    prim(7, 5, am_sdu(0, body), ue=11, direction='r')
    prim(4, 2, um_sdu(1, ip), ue=8, li=2)
    prim(5, 3, am_sdu(1, ip), ue=9, direction='r', li=2)
    prim(18, 2, um_sdu(0, rrc(8, 0)), ue=12)                       # CCCH
    prim(21, 2, um_sdu(0, rrc(8, 0)), ue=13)                       # CTCH
    prim(30, 2, um_sdu(0, body), ue=14)                            # not handled by RLC
    with open(path, 'w') as f:
        f.write('Session Transcript (format 5)\nOctober 31, 2026     10:00:00.0000\n')
        for l in lines:
            f.write(l + '\n')


dct2000(os.path.join(out, 'umts_rlc-coverage-dct2000.out'))

write_pcapng(os.path.join(out, 'umts_rlc-coverage.pcapng'), main, 1000)
write_pcapng(os.path.join(out, 'umts_rlc-coverage-malformed.pcapng'), mal, 6000000)   # 6 s apart: the same SN is no duplicate
json.dump(names, open(os.path.join(out, 'names.json'), 'w'))
json.dump([len(main), len(mal)], open(os.path.join(out, 'counts.json'), 'w'))
json.dump(SPANS, open(os.path.join(out, 'spans.json'), 'w'))
print(len(main), len(mal))
