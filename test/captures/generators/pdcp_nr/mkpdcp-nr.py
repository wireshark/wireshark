#!/usr/bin/env python3
# Generates test/captures/pdcp_nr_coverage.pcap.gz, pdcp_nr_dct2000.out.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the PDCP-NR dissector
(packet-pdcp-nr.c).

The dissector needs configuration info from a lower layer. The UDP
framing of the PDCP-NR wiki page is used: UDP payload "pdcp-nr" + plane
+ tags + PDU. A heuristic dissector recognises it; it is disabled by
default (--enable-heuristic pdcp_nr_udp). Every packet is built from
scratch with struct (nothing comes from a real network; addresses are
192.0.2.1 and 192.0.2.2). A small Catapult DCT2000 text file only reaches
the key string setters (see build_dct).

RRC payloads of the signalling frames were found by trial (random bytes
that the nr-rrc dissector decodes cleanly); the SecurityModeCommand
messages were found the same way. No key is configured anywhere and no
ciphertext is produced: after a SecurityModeCommand with ciphering the
payload of later signalling PDUs is simply shown as data.

Usage: mkpdcp-nr.py <output directory> [-v]   (-v prints frame ranges)

Writes:
  pdcp-nr-coverage.pcap            main capture (UDP framing)
  pdcp-nr-coverage-malformed.pcap  paths only bad input reaches
  pdcp-nr-dct2000.out              DCT2000 text file (key string setters)
"""

import os
import struct
import sys

# ------------------------------------------------------------ pcap


def ip_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp_frame(payload, i, sport=40000, dport=40001):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), (i + 1) & 0xffff,
                     0, 64, 17, 0, bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + struct.pack('>H', ip_csum(ip)) + ip[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + udp


def write_pcap(path, payloads):
    with open(path, 'wb') as out:
        out.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(payloads):
            eth = udp_frame(p, i)
            out.write(struct.pack('<IIII', 1700000000 + i, 0, len(eth), len(eth)) + eth)


# ------------------------------------------------------------ inner IP


def ipv4_udp(payload=b'abcd', sport=5000, dport=5001):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 7, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    ip = ip[:10] + struct.pack('>H', ip_csum(ip)) + ip[12:]
    return ip + udp


def ipv6_udp(payload=b'abcd', sport=5000, dport=5001):
    src = bytes([0x20, 1, 0x0d, 0xb8] + [0] * 11 + [1])
    dst = bytes([0x20, 1, 0x0d, 0xb8] + [0] * 11 + [2])
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = src + dst + struct.pack('>IBBBB', len(udp), 0, 0, 0, 17)
    ck = ip_csum(pseudo + udp[:6] + b'\0\0' + udp[8:]) or 0xffff
    udp = udp[:6] + struct.pack('>H', ck) + udp[8:]
    return struct.pack('>IHBB', 0x60000000, len(udp), 17, 64) + src + dst + udp


# ------------------------------------------------------------ framing

T_SEQ, T_DIR, T_BTYPE, T_BID, T_UEID, T_ROHC, T_IPV, T_CIDINC, T_LARGE, \
    T_MODE, T_RND, T_UDPCK, T_PROF, T_MACI, T_SDAP, T_CIPHOFF = range(2, 18)
DCCH, BCH, DLSCH, CCCH, PCCH = 1, 2, 3, 4, 5
UL, DL = 0, 1
SIG, USER = 1, 2


def hdr(plane=SIG, seq=None, d=None, bt=None, bid=None, ueid=None, rohc=False,
        ipv=None, cidinc=False, large=False, mode=None, rnd=False,
        udpck=False, prof=None, maci=False, sdap=None, ciphoff=False):
    """UDP framing header up to and including the payload tag."""
    t = b''
    if seq is not None:
        t += bytes([T_SEQ, seq])
    if d is not None:
        t += bytes([T_DIR, d])
    if bt is not None:
        t += bytes([T_BTYPE, bt])
    if bid is not None:
        t += bytes([T_BID, bid])
    if ueid is not None:
        t += bytes([T_UEID]) + struct.pack('>H', ueid)
    if rohc:
        t += bytes([T_ROHC])
    if ipv is not None:
        t += bytes([T_IPV, ipv])
    if cidinc:
        t += bytes([T_CIDINC])
    if large:
        t += bytes([T_LARGE])
    if mode is not None:
        t += bytes([T_MODE, mode])
    if rnd:
        t += bytes([T_RND])
    if udpck:
        t += bytes([T_UDPCK])
    if prof is not None:
        t += bytes([T_PROF]) + struct.pack('>H', prof)
    if maci:
        t += bytes([T_MACI])
    if sdap is not None:
        t += bytes([T_SDAP, sdap])
    if ciphoff:
        t += bytes([T_CIPHOFF])
    return b'pdcp-nr' + bytes([plane]) + t + b'\x01'


class Cap:
    def __init__(self):
        self.frames = []
        self.sections = []

    def sec(self, name):
        self.sections.append((len(self.frames) + 1, name))

    def add(self, header, pdu):
        self.frames.append(header + pdu)


# RRC messages (found by trial, see header)
R = {k: bytes.fromhex(v) for k, v in dict(
    mib='5d04c6', si='373e', paging='0558',
    dl_setup='3dba', dl_reject='163b',
    ul_reestreq='42167a385286', ul_resumereq='2a7122873ee8',
    ul_setupreq='145c8a42d884', ul_sireq='78a76084',
    ul_resumereq1='15c90b999b772b4f', c1_resumereq1='01ea47e48c1ee410',
    dl_reconf='05aa', dl_release='1772', dl_reest='1850', dl_infotr='2936',
    dl_countchk='3bb3', dl_capenq='33b8', dl_resume='0de3c8a6',
    dl_mobility='4722', dl_uereq='51d1',
    ul_setupcompl='11f8b5', ul_reconfcompl='0d102f', ul_infotr='3e8c',
    ul_measrep='04d7', ul_smcompl='2c0f', ul_smfail='3063',
    ul_capinfo='4bcd08', ul_reestcompl='1fa9', ul_resumecompl='2771',
    ul_countresp='51adca', ul_failinfo='65740d',
).items()}


def smc(ciph, integ):
    """DL-DCCH SecurityModeCommand with the given algorithms (found by
    trial: 0x20, 0x08 + 0x80 * ciphering + 0x08 * integrity)."""
    v = 0x0800 + ciph * 0x80 + integ * 0x08
    return bytes([0x20, v >> 8, v & 0xff])


def com(rrc, sn=1):
    """Signalling PDU on a common channel: the signalling plane always has
    the 12 bit SN header; there is no MAC-I."""
    return struct.pack('>H', sn) + rrc


def srb(sn, rrc, mac=b'\0\0\0\0'):
    """Signalling PDU on a DCCH bearer: 12 bit SN, RRC, MAC-I."""
    return struct.pack('>H', sn & 0xfff) + rrc + mac


def u12(sn, extra=b''):
    return struct.pack('>H', 0x8000 | sn) + extra


def u18(sn):
    return struct.pack('>I', 0x800000 | sn)[1:]


def build_main():
    c = Cap()
    A = c.add

    # --- Common channels: no sequence number tag, so no PDCP header -----
    c.sec('common channels')
    A(hdr(SIG, d=DL, bt=BCH), com(R['mib']))
    A(hdr(SIG, d=DL, bt=DLSCH), com(R['si']))
    A(hdr(SIG, d=DL, bt=PCCH), com(R['paging']))
    A(hdr(SIG, d=DL, bt=CCCH, ueid=10), com(R['dl_setup'], 2))
    A(hdr(SIG, d=DL, bt=CCCH, ueid=10), com(R['dl_reject'], 3))
    for sn, k in enumerate(('ul_reestreq', 'ul_resumereq', 'ul_setupreq', 'ul_sireq')):
        A(hdr(SIG, d=UL, bt=CCCH, ueid=10), com(R[k], sn))
    # 8 octet UL-CCCH PDUs (after the header) are UL-CCCH1 messages
    A(hdr(SIG, d=UL, bt=CCCH, ueid=10), com(R['ul_resumereq1']))
    A(hdr(SIG, d=UL, bt=CCCH, ueid=10), com(R['c1_resumereq1']))
    # bearer type without an RRC dissector: data
    A(hdr(SIG, d=DL, bt=9), com(R['mib']))
    A(hdr(SIG, d=DL), com(R['mib']))
    # the same with the SN length given explicitly (12)
    A(hdr(SIG, seq=12, d=UL, bt=CCCH, ueid=10), com(R['ul_reestreq'], 3))

    # --- DCCH signalling, with SecurityModeCommand ---------------------
    c.sec('DCCH signalling, UE 1 NEA2/NIA2')
    cnt = {}

    def sig(ueid, d, rrc, bid=1, mac=b'\0\0\0\0', sn=None):
        key = (ueid, d, bid)
        if sn is None:
            sn = cnt.get(key, 0)
        cnt[key] = sn + 1
        A(hdr(SIG, d=d, bt=DCCH, bid=bid, ueid=ueid), srb(sn, rrc, mac))

    sig(1, UL, R['ul_setupcompl'])
    sig(1, DL, R['dl_reconf'])
    sig(1, DL, smc(2, 2))
    sig(1, UL, R['ul_smcompl'])
    # ciphered from here: payload is shown as data, MAC-I is not checked
    sig(1, DL, R['dl_reconf'], mac=bytes.fromhex('a1b2c3d4'))
    sig(1, UL, R['ul_reconfcompl'], mac=bytes.fromhex('0badf00d'))
    sig(1, DL, R['dl_infotr'], mac=bytes.fromhex('11223344'))
    sig(1, UL, R['ul_infotr'], mac=bytes.fromhex('55667788'))
    sig(1, DL, R['dl_release'], bid=2, mac=bytes.fromhex('99aabbcc'))
    # re-keying
    sig(1, DL, smc(1, 1), mac=bytes.fromhex('01020304'))
    sig(1, UL, R['ul_smcompl'], mac=bytes.fromhex('05060708'))
    sig(1, DL, R['dl_countchk'], mac=bytes.fromhex('090a0b0c'))

    c.sec('DCCH signalling, other UEs and algorithms')
    for ueid, (ci, ii) in {2: (1, 1), 3: (3, 3), 4: (0, 0), 6: (2, 0), 7: (0, 2)}.items():
        sig(ueid, UL, R['ul_setupcompl'])
        sig(ueid, DL, smc(ci, ii))
        sig(ueid, UL, R['ul_smcompl'], mac=bytes.fromhex('13579bdf') if ii else b'\0\0\0\0')
        sig(ueid, DL, R['dl_infotr'], mac=bytes.fromhex('2468ace0') if ii else b'\0\0\0\0')
    # no security at all: MAC-I must be zero (NIA0)
    for k, d in (('ul_measrep', UL), ('dl_capenq', DL), ('ul_capinfo', UL),
                 ('dl_release', DL), ('ul_countresp', UL), ('dl_mobility', DL),
                 ('ul_failinfo', UL), ('dl_resume', DL), ('ul_resumecompl', UL),
                 ('dl_uereq', DL), ('ul_reestcompl', UL)):
        sig(8, d, R[k])
    sig(8, UL, R['ul_infotr'], bid=2)
    # SecurityModeCommand, SecurityModeFailure
    sig(8, DL, smc(2, 2))
    sig(8, UL, R['ul_smfail'])
    sig(8, DL, R['dl_infotr'])
    # UE 9 is ciphered (NEA2): the NR dissector does not decode even a
    # UL-CCCH message of a ciphered UE as RRC (see README, observations)
    sig(9, UL, R['ul_setupcompl'])
    sig(9, DL, smc(2, 2))
    sig(9, UL, R['ul_smcompl'])
    sig(9, DL, R['dl_infotr'], mac=bytes.fromhex('0a0b0c0d'))
    A(hdr(SIG, d=UL, bt=CCCH, ueid=9), com(R['ul_reestreq']))
    sig(9, DL, R['dl_reest'], mac=bytes.fromhex('0a0b0c0e'))
    # UE 7 has NEA0/NIA2, so the RRC messages stay readable:
    # RRCReestablishmentRequest (UL-CCCH): the next DL PDU is not deciphered
    A(hdr(SIG, d=UL, bt=CCCH, ueid=7), com(R['ul_reestreq']))
    sig(7, DL, R['dl_reest'], mac=bytes.fromhex('0a0b0c0e'))
    # a second SecurityModeCommand is dissected (no ciphering yet): the
    # settings of the UE are updated; a SecurityModeFailure takes the UE
    # back to its previous settings, then a third one is completed
    sig(7, DL, smc(1, 1), mac=bytes.fromhex('0a0b0c0f'))
    sig(7, UL, R['ul_smfail'], mac=bytes.fromhex('0a0b0c10'))
    sig(7, DL, R['dl_infotr'], mac=bytes.fromhex('0a0b0c11'))
    sig(7, DL, smc(3, 3), mac=bytes.fromhex('0a0b0c12'))
    sig(7, UL, R['ul_smcompl'], mac=bytes.fromhex('0a0b0c13'))
    sig(7, DL, R['dl_infotr'], mac=bytes.fromhex('0a0b0c14'))
    # signalling header only (nothing captured after it)
    A(hdr(SIG, d=UL, bt=DCCH, bid=1, ueid=8), struct.pack('>H', 99))

    # --- User plane data --------------------------------------------------
    c.sec('user plane data PDUs')
    ip4 = ipv4_udp(b'hello pdcp')
    ip6 = ipv6_udp(b'hello pdcp')
    for ueid, snl, mk in ((20, 12, u12), (21, 18, u18)):
        for d in (UL, DL):
            for sn, payload in enumerate((ip4, ip6, b'plain data', b'\x10\x20')):
                A(hdr(USER, seq=snl, d=d, bt=DCCH, bid=3, ueid=ueid), mk(sn) + payload)
    # SDAP header after the PDCP header (UL: D/C + QFI, DL: RDI, RQI, QFI)
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=22, sdap=1), u12(0) + bytes([0x85]) + ip4)
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=22, sdap=1), u12(1) + bytes([0x05]) + ip4)
    A(hdr(USER, seq=12, d=DL, bt=DCCH, bid=3, ueid=22, sdap=2), u12(0) + bytes([0xc9]) + ip6)
    A(hdr(USER, seq=18, d=DL, bt=DCCH, bid=3, ueid=22, sdap=3), u18(1) + bytes([0x40 | 3]) + ip4)
    A(hdr(USER, seq=18, d=UL, bt=DCCH, bid=3, ueid=22, sdap=3), u18(1) + bytes([0x80 | 3]) + b'raw')
    # MAC-I at the end of a DRB PDU (NIA0: zero)
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=23, maci=True), u12(0) + ip4 + b'\0\0\0\0')
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=23, maci=True, sdap=1),
      u12(1) + bytes([0x01]) + ip4 + b'\0\0\0\0')
    # ciphering disabled for this bearer
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=4, ueid=23, ciphoff=True), u12(0) + ip4)
    # the same for a UE that has ciphering from SecurityModeCommand
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=4, ueid=1, ciphoff=True), u12(0) + ip4)
    # header only
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=21), bytes([0x80, 5]))
    # SN length that is not 12 or 18: data is not decoded
    A(hdr(USER, seq=5, d=UL, bt=DCCH, bid=3, ueid=21), bytes([0x85]) + ip4)
    # signalling-plane UE on user bearer security (default NEA0)

    # --- Sequence flows -----------------------------------------------------
    c.sec('sequence number flows')
    for sn in (4094, 4095, 0, 1, 5, 2, 100, 101, 100):
        A(hdr(USER, seq=12, d=DL, bt=DCCH, bid=3, ueid=30), u12(sn, ip4))
    for sn in (4094, 4095, 0, 1, 5, 2, 100, 101, 100):
        A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=30), u12(sn, ip4))
    for sn in (262142, 262143, 0, 40, 41, 40):
        A(hdr(USER, seq=18, d=UL, bt=DCCH, bid=3, ueid=31), u18(sn) + ip4)
        A(hdr(USER, seq=18, d=DL, bt=DCCH, bid=3, ueid=31), u18(sn) + ip4)
    for sn in (4094, 4095, 0, 1, 7, 2, 3):
        A(hdr(SIG, d=UL, bt=DCCH, bid=1, ueid=32), srb(sn, R['ul_infotr']))
    for sn in (0, 1, 2):
        A(hdr(SIG, d=DL, bt=DCCH, bid=2, ueid=32), srb(sn, R['dl_infotr']))
    # a flow on a UE that has security from SecurityModeCommand
    for sn in (0, 1, 3):
        A(hdr(USER, seq=12, d=DL, bt=DCCH, bid=3, ueid=1), u12(sn, ip4))
        A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=2), u12(sn, ip4))

    # --- Control PDUs -----------------------------------------------------
    c.sec('control PDUs')
    # status report (type 0): reserved + FMC + bitmap
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=40),
      bytes([0x00]) + struct.pack('>I', 100) + bytes([0xa5, 0x0f, 0xff]))
    A(hdr(USER, seq=18, d=DL, bt=DCCH, bid=3, ueid=40),
      bytes([0x00]) + struct.pack('>I', 70000) + bytes([0x00, 0xff]))
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=40),
      bytes([0x00]) + struct.pack('>I', 4095))                  # no bitmap
    # longest bitmap the buffer takes
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=40),
      bytes([0x00]) + struct.pack('>I', 7) + bytes([0xff] * 40))
    # interspersed ROHC feedback (type 1), EHC (2), UDC (3)
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=41, rohc=True, mode=2, prof=1, ipv=4),
      bytes([0x10, 0xf4, 0x01, 0x02, 0x03]))
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=41), bytes([0x10, 0xfe, 0x01, 0x02]))
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=41), bytes([0x20, 0x00]))
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=41), bytes([0x30]))
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=41), bytes([0xb0 & 0x30]))
    # SN gap report (type 4) with and without a bitmap
    A(hdr(USER, seq=12, d=DL, bt=DCCH, bid=3, ueid=42),
      bytes([0x40]) + struct.pack('>I', 500) + bytes([0xc3, 0x3c]))
    A(hdr(USER, seq=12, d=DL, bt=DCCH, bid=3, ueid=42), bytes([0x40]) + struct.pack('>I', 501))
    A(hdr(USER, seq=12, d=DL, bt=DCCH, bid=3, ueid=42),
      bytes([0x40]) + struct.pack('>I', 7) + bytes([0xff] * 40))
    # reserved control PDU types 5 and 7 (6 is in the malformed capture:
    # the first octet 0x60 looks like an IPv6 header to the payload code)
    for t in (5, 7):
        A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=43), bytes([t << 4, 0, 1]))

    # --- ROHC -----------------------------------------------------------------
    c.sec('ROHC compressed data')
    for prof in (0, 1, 2, 3, 4, 6, 7, 8, 0x101, 0x102, 0x103, 0x104, 0x1234):
        A(hdr(USER, seq=12, d=DL, bt=DCCH, bid=3, ueid=46, rohc=True, mode=3, prof=prof,
              ipv=4, cidinc=True, large=False, rnd=False, udpck=True),
          u12(prof & 0xfff, bytes([0xfd, prof & 0xff, 0x00, 0x00])))
    for mode in (0, 1, 2, 3, 9):
        A(hdr(USER, seq=18, d=UL, bt=DCCH, bid=3, ueid=47, rohc=True, mode=mode, prof=1,
              ipv=6, large=True, rnd=True, udpck=False),
          u18(mode) + bytes([0xfc, 0x01, 0x00]))

    # --- Plane that is neither signalling nor user plane ------------------------
    c.sec('invalid plane')
    A(hdr(3, d=UL, bt=DCCH, bid=1, ueid=48), bytes([0x00, 0x11, 0x22]))

    c.sec('heuristic framing errors')
    A(hdr(USER, d=UL, bt=DCCH, bid=3, ueid=49), bytes([0x80, 0x01]))               # no SN length
    A(b'pdcp-nr' + bytes([SIG, 0x42, 0x01]), b'\x00\x01\x02')                      # unknown tag

    c.sec('fix: unsupported SN length')
    # signalling PDU on a CCCH bearer with SN length 9: the header is read
    # as 12 bits, sequence analysis is skipped
    A(hdr(SIG, seq=9, d=UL, bt=CCCH, ueid=60), com(R['ul_reestreq'], 3))
    A(hdr(SIG, seq=31, d=DL, bt=CCCH, ueid=60), com(R['dl_reject'], 4))
    return c


def build_malformed():
    c = Cap()
    A = c.add
    c.sec('malformed')
    # the original reproducer of the unsupported SN length (RRC does not
    # decode the made-up payload)
    A(b'pdcp-nr' + bytes([SIG, T_SEQ, 9, T_BTYPE, CCCH, 1]), bytes.fromhex('000300112233445566'))
    # reserved bits: signalling header, data headers, control PDUs
    A(hdr(SIG, d=UL, bt=DCCH, bid=1, ueid=1), bytes([0xf0, 0x01]) + R['ul_infotr'] + b'\0\0\0\0')
    A(hdr(SIG, d=UL, bt=DCCH, bid=1, ueid=1), srb(2, R['ul_infotr'], bytes.fromhex('11223344')))
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=2), bytes([0xf0, 0x01]) + ipv4_udp())
    A(hdr(USER, seq=18, d=UL, bt=DCCH, bid=3, ueid=2), bytes([0xfc, 0, 1]) + ipv4_udp())
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=2), bytes([0x0f]) + struct.pack('>I', 5) + b'\xff')
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=2), bytes([0x1f, 1, 2, 3]))
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=2), bytes([0x2f, 0xff]))
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=2), bytes([0x3f]))
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=2), bytes([0x4f]) + struct.pack('>I', 5) + b'\xff')
    # control PDU type 6: the payload starts with 0x60 and goes to IPv6
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=2), bytes([0x60, 0, 1]))
    # MAC-I that does not match NIA0
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=2, maci=True), u12(0) + ipv4_udp() + bytes.fromhex('01020304'))
    # truncated PDUs
    A(hdr(SIG, d=UL, bt=DCCH, bid=1, ueid=3), bytes([0x00]))
    A(hdr(SIG, d=UL, bt=DCCH, bid=1, ueid=3), bytes([0x00, 0x01, 0xaa]))
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=3), bytes([0x80]))
    A(hdr(USER, seq=18, d=UL, bt=DCCH, bid=3, ueid=3), bytes([0x80, 0x00]))
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=3), bytes([0x00]))
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=3), bytes([0x00, 0, 0]))
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=3), bytes([0x20]))
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=3), bytes([0x40, 0, 0]))
    A(hdr(USER, seq=12, d=UL, bt=DCCH, bid=3, ueid=3, maci=True), u12(0) + b'\1')
    # truncated framing header
    A(b'pdcp-nr' + bytes([SIG, T_SEQ]), b'')
    A(b'pdcp-nr' + bytes([SIG, T_UEID, 0]), b'')
    # RRC payloads that do not decode
    A(hdr(SIG, d=UL, bt=CCCH, ueid=4), bytes([0xff, 0xff]))
    A(hdr(SIG, d=DL, bt=BCH), bytes([0xff]))
    return c


# ------------------------------------------------------------ DCT2000


def build_dct():
    """The only way DCT2000 reaches PDCP-NR is the RRC primitive that
    carries key strings (placeholders): the setters run and nothing is
    configured or deciphered. The frames decode as DCT2000 RRC."""
    out = 'Session Transcript (format 5)\nOctober 31, 2026     10:00:00.0000\n'
    key1 = '00112233445566778899aabbccddeeff'
    key2 = 'ffeeddccbbaa99887766554433221100'

    def prim(ueid):
        body = bytes([0x12, 0x03]) + ueid.to_bytes(2, 'big') + bytes([0x00, 0x01, 0x01])
        sm = bytes([0x01, 0x01, 0x21, 0x00])
        sm += bytes([0x02, 0x13, 0x80, 0x01, 0x02, 0x81, 0x10]) + bytes.fromhex(key1)
        sm += bytes([0x03, 0x13, 0x80, 0x01, 0x02, 0x81, 0x10]) + bytes.fromhex(key2)
        body += bytes([0x30, len(sm)]) + sm
        return bytes([0x05, len(body)]) + body

    def prim_only(ueid):
        sm = bytes([0x01, 0x01, 0x21, 0x00])
        sm += bytes([0x03, 0x13, 0x80, 0x01, 0x02, 0x81, 0x10]) + bytes.fromhex(key2)
        body = bytes([0x12, 0x03]) + ueid.to_bytes(2, 'big') + bytes([0x00, 0x01, 0x01])
        body += bytes([0x30, len(sm)]) + sm
        return bytes([0x05, len(body)]) + body

    t = 1
    bodies = [prim(u) for u in range(1, 5)]
    # a UE whose first key is the integrity key
    bodies += [prim_only(5), prim(5)]
    # more keys than the table holds for one UE: the extra ones are ignored
    bodies += [prim(6)] * 18
    for body in bodies:
        out += 'ctx.1/rrc_r15_5g/1 s tm 0.%04d l $%s\n' % (t, body.hex())
        t += 1
    return out


def main():
    outdir = sys.argv[1]
    verbose = '-v' in sys.argv
    os.makedirs(outdir, exist_ok=True)
    for name, c in (('pdcp-nr-coverage', build_main()),
                    ('pdcp-nr-coverage-malformed', build_malformed())):
        write_pcap(os.path.join(outdir, name + '.pcap'), c.frames)
        if verbose:
            print(name, len(c.frames), 'frames')
            ends = [s for s, _ in c.sections[1:]] + [len(c.frames) + 1]
            for (s, n), e in zip(c.sections, ends):
                print('  %d-%d %s' % (s, e - 1, n))
    with open(os.path.join(outdir, 'pdcp-nr-dct2000.out'), 'w') as f:
        f.write(build_dct())


if __name__ == '__main__':
    main()
