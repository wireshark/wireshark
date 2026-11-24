#!/usr/bin/env python3
# Generates test/captures/pdcp_lte_coverage.pcap.gz, pdcp_lte_dct2000.out.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the PDCP-LTE dissector
(packet-pdcp-lte.c).

The dissector needs configuration info from a lower layer. Two framings
that need no other protocol are used, both built from scratch with
struct (nothing comes from a real network; addresses are 192.0.2.1 and
192.0.2.2):

  * the UDP framing of the PDCP-LTE wiki page: UDP payload "pdcp-lte" +
    fixed fields + tags + PDU. A heuristic dissector recognises it; it is
    disabled by default (--enable-heuristic pdcp_lte_udp).
  * Catapult DCT2000 text files (pdcp_r8_lte ports), which attach the
    same info by default.

RRC payloads of the signalling frames were found by trial (random bytes
that the lte-rrc dissector decodes cleanly); the SecurityModeCommand
messages are built bit by bit. No key is configured anywhere and no
ciphertext is produced: after a SecurityModeCommand with ciphering the
payload of later signalling PDUs is simply shown as data.

Usage: mkpdcp-lte.py <output directory> [-v]   (-v prints frame ranges)

Writes:
  pdcp-lte-coverage.pcap            main capture (UDP framing)
  pdcp-lte-coverage-malformed.pcap  paths only bad input reaches
  pdcp-lte-dct2000.out              DCT2000 text file (default route)
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

T_SEQ, T_DIR, T_CHAN, T_BCCH, T_ROHC_IPV, T_CIDINC, T_LARGE, T_MODE, T_RND, \
    T_UDPCK, T_PROF, T_CHID, T_UEID = 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
DCCH, BCCH, CCCH, PCCH, DCCH_NB, BCCH_NB, CCCH_NB, PCCH_NB = range(1, 9)
UL, DL = 0, 1
SIG, USER = 1, 2


def hdr(plane=SIG, nohdr=0, rohc=0, seq=None, d=None, chan=None, bcch=None,
        ueid=None, chid=None, ipv=None, cidinc=None, large=None, mode=None,
        rnd=None, udpck=None, prof=None):
    """UDP framing header up to and including the payload tag."""
    t = b''
    if seq is not None:
        t += bytes([T_SEQ, seq])
    if d is not None:
        t += bytes([T_DIR, d])
    if chan is not None:
        t += bytes([T_CHAN, chan])
    if bcch is not None:
        t += bytes([T_BCCH, bcch])
    if ipv is not None:
        t += bytes([T_ROHC_IPV]) + struct.pack('>H', ipv)
    if cidinc is not None:
        t += bytes([T_CIDINC, cidinc])
    if large is not None:
        t += bytes([T_LARGE, large])
    if mode is not None:
        t += bytes([T_MODE, mode])
    if rnd is not None:
        t += bytes([T_RND, rnd])
    if udpck is not None:
        t += bytes([T_UDPCK, udpck])
    if prof is not None:
        t += bytes([T_PROF]) + struct.pack('>H', prof)
    if chid is not None:
        t += bytes([T_CHID]) + struct.pack('>H', chid)
    if ueid is not None:
        t += bytes([T_UEID]) + struct.pack('>H', ueid)
    return b'pdcp-lte' + bytes([nohdr, plane, rohc]) + t + b'\x01'


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
    mib='232ef1', si='39d1', paging='0a2f',
    ul_connreq='5ede61a634a9', ul_reestreq='3e19', ul_resumereq='b59cf6a15ef6',
    ul_earlyreq='c7c8553ac4',
    dl_setup='75ca', dl_reject='5882', dl_reest='0940', dl_reestrej='3400',
    dl_earlycompl='893192',
    dl_reconf='25ed0335', dl_release='2b5a5244', dl_infotr='0fd9',
    dl_capenq='38bd', dl_countchk='45cb', dl_resume='66ba020d',
    ul_setupcompl='253936b1', ul_reconfcompl='1654', ul_infotr='4dd6',
    ul_measrep='0b8b', ul_smcompl='2d559fa3', ul_smfail='357c',
    ul_capinfo='3fa8', ul_countresp='510c',
    # NB-IoT
    nb_mib='3b107aa1', nb_si='39d1', nb_paging='0be9',
    nb_ul_req='3e19', nb_ul_resumereq='5abb', nb_ul_reestreq='1dbd',
    nb_dl_setup='36318f', nb_dl_reject='2469', nb_dl_reest='0940',
    nb_dl_reestrej='1480',
    nb_dl_release='25ed0335', nb_dl_infotr='0fd9', nb_dl_capenq='45cb',
    nb_ul_setupcompl='11045a53', nb_ul_reconfcompl='059294',
    nb_ul_infotr='357c', nb_ul_smcompl='1899', nb_ul_smfail='253936b1',
).items()}


def bits(*parts):
    s = ''.join(parts)
    s += '0' * (-len(s) % 8)
    return bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))


def smc(ciph, integ, txid=0):
    """DL-DCCH SecurityModeCommand-r8 with the given algorithms."""
    return bits('0', '0110', format(txid, '02b'), '0', '000', '0', '0',
                format(ciph, '03b'), '0', format(integ, '03b'))


def u18(sn):
    return struct.pack('>I', 0x800000 | sn)[1:]


def dcch(sn, rrc, mac=b'\0\0\0\0'):
    return bytes([sn & 0x1f]) + rrc + mac


def build_main():
    c = Cap()
    A = c.add

    # --- Common channels: no PDCP header, no MAC-I ---------------------
    c.sec('common channels')
    A(hdr(SIG, 1, chan=BCCH, bcch=1, d=DL), R['mib'])
    A(hdr(SIG, 1, d=DL, chan=BCCH, bcch=2), R['si'])
    A(hdr(SIG, 1, d=DL, chan=PCCH), R['paging'])
    A(hdr(SIG, 1, d=UL, chan=CCCH, ueid=10), R['ul_connreq'])
    A(hdr(SIG, 1, d=UL, chan=CCCH, ueid=10), R['ul_reestreq'])
    A(hdr(SIG, 1, d=UL, chan=CCCH, ueid=10), R['ul_resumereq'])
    A(hdr(SIG, 1, d=DL, chan=CCCH, ueid=10), R['dl_setup'])
    A(hdr(SIG, 1, d=DL, chan=CCCH, ueid=10), R['dl_reject'])
    A(hdr(SIG, 1, d=DL, chan=CCCH, ueid=10), R['dl_reest'])
    A(hdr(SIG, 1, d=DL, chan=CCCH, ueid=10), R['dl_reestrej'])
    A(hdr(SIG, 1, d=DL, chan=CCCH, ueid=10), R['dl_earlycompl'])
    A(hdr(SIG, 1, d=UL, chan=CCCH, ueid=10), R['ul_earlyreq'])
    # BCCH with no transport type: no RRC dissector, shown as data
    A(hdr(SIG, 1, d=DL, chan=BCCH), R['mib'])
    # unknown channel type: data
    A(hdr(SIG, 1, d=DL, chan=9), R['mib'])

    c.sec('NB-IoT channels')
    A(hdr(SIG, 1, d=DL, chan=BCCH_NB, bcch=1), R['nb_mib'])
    A(hdr(SIG, 1, d=DL, chan=BCCH_NB, bcch=2), R['nb_si'])
    A(hdr(SIG, 1, d=DL, chan=PCCH_NB), R['nb_paging'])
    A(hdr(SIG, 1, d=UL, chan=CCCH_NB, ueid=11), R['nb_ul_req'])
    A(hdr(SIG, 1, d=UL, chan=CCCH_NB, ueid=11), R['nb_ul_resumereq'])
    A(hdr(SIG, 1, d=UL, chan=CCCH_NB, ueid=11), R['nb_ul_reestreq'])
    A(hdr(SIG, 1, d=DL, chan=CCCH_NB, ueid=11), R['nb_dl_setup'])
    A(hdr(SIG, 1, d=DL, chan=CCCH_NB, ueid=11), R['nb_dl_reject'])
    A(hdr(SIG, 1, d=DL, chan=CCCH_NB, ueid=11), R['nb_dl_reest'])
    A(hdr(SIG, 1, d=DL, chan=CCCH_NB, ueid=11), R['nb_dl_reestrej'])
    # NB-IoT dedicated: PDCP header, no MAC-I
    for i, (d, k) in enumerate([(UL, 'nb_ul_setupcompl'), (DL, 'nb_dl_infotr'),
                                (UL, 'nb_ul_infotr'), (DL, 'nb_dl_capenq'),
                                (UL, 'nb_ul_reconfcompl'), (DL, 'nb_dl_release')]):
        A(hdr(SIG, 0, d=d, chan=DCCH_NB, ueid=11, chid=1), bytes([i // 2]) + R[k])
    # NB-IoT dedicated PDU with only the header byte
    A(hdr(SIG, 0, d=UL, chan=DCCH_NB, ueid=11, chid=1), bytes([3]))

    # --- Signalling plane on DCCH, with SecurityModeCommand ------------
    c.sec('DCCH signalling, UE 1 EEA2/EIA2')
    ul = {1: 0, 2: 0}
    dl = {1: 0, 2: 0}

    def sig(ueid, d, rrc, chid=1, mac=b'\0\0\0\0', sn=None):
        tab = ul if d == UL else dl
        if sn is None:
            sn = tab[chid]
        tab[chid] = sn + 1
        A(hdr(SIG, 0, d=d, chan=DCCH, ueid=ueid, chid=chid), dcch(sn, rrc, mac))

    def fresh():
        ul[1] = ul[2] = dl[1] = dl[2] = 0

    fresh()
    sig(1, UL, R['ul_setupcompl'])
    sig(1, DL, R['dl_reconf'])
    sig(1, DL, smc(2, 2))
    sig(1, UL, R['ul_smcompl'])
    # now ciphered: payload shown as data, MAC-I not checked (no key)
    sig(1, DL, R['dl_reconf'], mac=bytes.fromhex('a1b2c3d4'))
    sig(1, UL, R['ul_reconfcompl'], mac=bytes.fromhex('0badf00d'))
    sig(1, DL, R['dl_infotr'], mac=bytes.fromhex('11223344'))
    sig(1, UL, R['ul_infotr'], mac=bytes.fromhex('55667788'))
    sig(1, DL, R['dl_release'], chid=2, mac=bytes.fromhex('99aabbcc'))
    # a second SecurityModeCommand: ciphered, so shown as data only
    sig(1, DL, smc(1, 1), mac=bytes.fromhex('01020304'))
    sig(1, UL, R['ul_smcompl'], mac=bytes.fromhex('05060708'))
    sig(1, DL, R['dl_countchk'], mac=bytes.fromhex('090a0b0c'))

    c.sec('DCCH signalling, other UEs and algorithms')
    fresh()
    for ueid, (ci, ii) in {2: (1, 1), 3: (3, 3), 4: (0, 0), 6: (2, 0), 7: (0, 2)}.items():
        fresh()
        sig(ueid, UL, R['ul_setupcompl'])
        sig(ueid, DL, smc(ci, ii))
        sig(ueid, UL, R['ul_smcompl'], mac=bytes.fromhex('13579bdf') if ii else b'\0\0\0\0')
        sig(ueid, DL, R['dl_infotr'], mac=bytes.fromhex('2468ace0') if ii else b'\0\0\0\0')
    # no security at all: MAC-I must be zero (EIA0)
    fresh()
    for k, d in (('ul_measrep', UL), ('dl_capenq', DL), ('ul_capinfo', UL),
                 ('dl_release', DL), ('ul_countresp', UL)):
        sig(8, d, R[k])
    sig(8, UL, R['ul_infotr'], chid=2)
    # SecurityModeFailure, SecurityModeCommand after it
    sig(8, DL, smc(2, 2))
    sig(8, UL, R['ul_smfail'])
    # only the PDCP header byte captured
    A(hdr(SIG, 0, d=UL, chan=DCCH, ueid=8, chid=1), bytes([9]))
    # signalling reserved bits are checked in the malformed capture
    # no-header signalling PDU: shown as data
    A(hdr(SIG, 1, d=UL, chan=DCCH, ueid=8, chid=1), R['ul_infotr'] + b'\0\0\0\0')

    # --- User plane data, every SN length ------------------------------
    c.sec('user plane data PDUs')
    ip4 = ipv4_udp(b'hello pdcp')
    ip6 = ipv6_udp(b'hello pdcp')
    for ueid, snl, hdrfn in ((20, 7, lambda sn: bytes([0x80 | sn])),
                             (21, 12, lambda sn: struct.pack('>H', 0x8000 | sn)),
                             (22, 15, lambda sn: struct.pack('>H', 0x8000 | sn)),
                             (23, 18, lambda sn: u18(sn))):
        for d in (UL, DL):
            for sn, payload in enumerate((ip4, ip6, b'plain data', b'\x10\x20')):
                A(hdr(USER, 0, seq=snl, d=d, chan=DCCH, ueid=ueid, chid=3),
                  hdrfn(sn) + payload)
    # SN 18: polling bit set
    A(hdr(USER, 0, seq=18, d=DL, chan=DCCH, ueid=23, chid=3),
      bytes([0xc0, 0, 4]) + ip4)
    # user plane PDU with only the header
    A(hdr(USER, 0, seq=12, d=UL, chan=DCCH, ueid=21, chid=3), bytes([0x80, 5]))
    # SN length not handled for user plane data (5): data is not decoded
    A(hdr(USER, 0, seq=5, d=UL, chan=DCCH, ueid=21, chid=3), bytes([0x85]) + ip4)
    # No-header PDUs (SDU only)
    A(hdr(USER, 1, seq=12, d=DL, chan=DCCH, ueid=24, chid=4), ip4)
    A(hdr(USER, 1, seq=12, d=UL, chan=DCCH, ueid=24, chid=4), ip6)

    # --- Sequence flows (analysis is a preference) ----------------------
    c.sec('sequence number flows')
    # 12 bit DL on UE 30: rollover, missing, repeated
    for sn in (4094, 4095, 0, 1, 5, 2, 100, 101, 100):
        A(hdr(USER, 0, seq=12, d=DL, chan=DCCH, ueid=30, chid=3),
          struct.pack('>H', 0x8000 | sn) + ip4)
    # 7, 15 and 18 bit rollover/missing
    for sn in (126, 127, 0, 5):
        A(hdr(USER, 0, seq=7, d=UL, chan=DCCH, ueid=31, chid=3), bytes([0x80 | sn]) + ip4)
    for sn in (32766, 32767, 0, 9):
        A(hdr(USER, 0, seq=15, d=UL, chan=DCCH, ueid=32, chid=3),
          struct.pack('>H', 0x8000 | sn) + ip4)
    for sn in (262142, 262143, 0, 40):
        A(hdr(USER, 0, seq=18, d=UL, chan=DCCH, ueid=33, chid=3),
          u18(sn) + ip4)
    # signalling flow with gaps, wrap and repeat on UE 34 (SRB1, SRB2)
    for sn in (30, 31, 0, 1, 7, 2, 3):
        A(hdr(SIG, 0, d=UL, chan=DCCH, ueid=34, chid=1), dcch(sn, R['ul_infotr']))
    for sn in (0, 1):
        A(hdr(SIG, 0, d=DL, chan=DCCH, ueid=34, chid=2), dcch(sn, R['dl_infotr']))

    # --- User plane control PDUs ----------------------------------------
    c.sec('status reports')
    # PDCP status report (control PDU type 0), 12 bit: FMS + bitmap
    A(hdr(USER, 0, seq=12, d=UL, chan=DCCH, ueid=40, chid=3),
      struct.pack('>H', 0x0000 | 100) + bytes([0xa5, 0x0f, 0xff]))
    A(hdr(USER, 0, seq=12, d=UL, chan=DCCH, ueid=40, chid=3),
      struct.pack('>H', 4095))           # FMS only, no bitmap
    # 15 bit
    A(hdr(USER, 0, seq=15, d=UL, chan=DCCH, ueid=41, chid=3),
      b'\x00' + struct.pack('>H', 20000) + bytes([0xf0, 0x81]))
    A(hdr(USER, 0, seq=15, d=UL, chan=DCCH, ueid=41, chid=3),
      b'\x00' + struct.pack('>H', 3))
    # 18 bit (and 7 bit, which uses the same format)
    A(hdr(USER, 0, seq=18, d=DL, chan=DCCH, ueid=42, chid=3),
      struct.pack('>I', 200000)[1:] + bytes([0x55, 0xaa, 0x00, 0xff]))
    A(hdr(USER, 0, seq=18, d=DL, chan=DCCH, ueid=42, chid=3),
      struct.pack('>I', 262143)[1:])
    A(hdr(USER, 0, seq=7, d=DL, chan=DCCH, ueid=42, chid=4),
      struct.pack('>I', 77)[1:] + bytes([0x80]))
    # longest bitmap the buffer takes
    A(hdr(USER, 0, seq=12, d=UL, chan=DCCH, ueid=40, chid=3),
      struct.pack('>H', 7) + bytes([0xff] * 40))

    c.sec('ROHC feedback, LWA, reserved control types')
    # ROHC feedback (type 1): follows the control PDU type byte
    A(hdr(USER, 0, rohc=1, seq=12, d=UL, chan=DCCH, ueid=43, chid=3, mode=2, prof=1, ipv=4),
      bytes([0x10]) + bytes([0xf4, 0x01, 0x02, 0x03]))
    A(hdr(USER, 0, rohc=0, seq=12, d=UL, chan=DCCH, ueid=43, chid=3),
      bytes([0x10]) + bytes([0xfe, 1, 2, 3]))
    # LWA status report (type 2), 12 / 15 / 18 bit
    A(hdr(USER, 0, seq=12, d=DL, chan=DCCH, ueid=44, chid=3),
      bytes([0x20, 0x10, 0x20, 0x00, 0x05, 0x00, 0x00]))
    A(hdr(USER, 0, seq=15, d=DL, chan=DCCH, ueid=44, chid=3),
      bytes([0x20, 0x00, 0x10, 0x00, 0x20, 0x00, 0x05, 0x00]))
    A(hdr(USER, 0, seq=18, d=DL, chan=DCCH, ueid=44, chid=3),
      bytes([0x20, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x05]))
    # LWA end-marker (type 3), 12 / 15 / 18 bit
    A(hdr(USER, 0, seq=12, d=DL, chan=DCCH, ueid=44, chid=3),
      bytes([0x30, 0x77]))
    A(hdr(USER, 0, seq=15, d=DL, chan=DCCH, ueid=44, chid=3),
      bytes([0x30, 0x12, 0x34]))
    A(hdr(USER, 0, seq=18, d=DL, chan=DCCH, ueid=44, chid=3),
      bytes([0x30, 0x01, 0x23, 0x45]))
    # reserved control PDU types 4-7
    for t in (4, 5, 6, 7):
        A(hdr(USER, 0, seq=12, d=UL, chan=DCCH, ueid=45, chid=3), bytes([t << 4, 0]))

    # --- ROHC compressed user plane -------------------------------------
    c.sec('ROHC compressed data')
    for prof in (0, 1, 2, 3, 4, 6, 7, 8, 0x101, 0x102, 0x103, 0x104, 0x1234):
        A(hdr(USER, 0, rohc=1, seq=12, d=DL, chan=DCCH, ueid=46, chid=3,
              mode=3, prof=prof, ipv=4, cidinc=1, large=0, rnd=0, udpck=1),
          struct.pack('>H', 0x8000 | prof & 0xfff) + bytes([0xfd, prof & 0xff, 0x00, 0x00]))
    for mode in (0, 1, 2, 3, 9):
        A(hdr(USER, 0, rohc=1, seq=7, d=UL, chan=DCCH, ueid=47, chid=3,
              mode=mode, prof=1, ipv=6, large=1, rnd=1, udpck=0),
          bytes([0x80 | mode]) + bytes([0xfc, 0x01, 0x00]))

    # --- Plane that is neither signalling nor user plane -----------------
    c.sec('invalid plane')
    A(hdr(3, 0, d=UL, chan=DCCH, ueid=48, chid=1), bytes([0x00, 0x11, 0x22]))

    # --- Framing errors (warnings, nothing is dissected) ---------------------
    c.sec('heuristic framing errors, other UDP')
    A(b'not a pdcp frame, just UDP data', b'')
    A(hdr(USER, 0, d=UL, chan=DCCH, ueid=49, chid=3), bytes([0x80, 0x01]))      # no SN length
    A(b'pdcp-lte' + bytes([0, SIG, 0, 0x42, 0x01]), b'\x00\x01\x02')           # unknown tag
    # the reproducer of the fix: signalling PDU with an SN length of 9
    c.sec('fix: unsupported SN length')
    A(b'pdcp-lte' + bytes([0, SIG, 0, T_SEQ, 9, T_DIR, UL, T_CHAN, DCCH, T_UEID, 0, 61, 1]),
      bytes([0x03]) + R['ul_infotr'] + b'\0\0\0\0')
    A(b'pdcp-lte' + bytes([0, SIG, 0, T_SEQ, 9, T_DIR, DL, T_CHAN, DCCH, T_UEID, 0, 60, 1]),
      bytes([0x00]) + R['dl_infotr'] + b'\0\0\0\0')
    return c


def build_malformed():
    c = Cap()
    A = c.add
    c.sec('malformed')
    # the original reproducer of the unsupported SN length: the MAC-I
    # does not match EIA0
    A(b'pdcp-lte' + bytes([0, SIG, 0, T_SEQ, 9, T_CHAN, DCCH, 1]),
      bytes.fromhex('0300112233445566'))
    # reserved bits in signalling header, MAC-I that does not match EIA0
    A(hdr(SIG, 0, d=UL, chan=DCCH, ueid=1, chid=1), bytes([0xe1]) + R['ul_infotr'] + b'\0\0\0\0')
    A(hdr(SIG, 0, d=UL, chan=DCCH, ueid=1, chid=1), bytes([0x02]) + R['ul_infotr'] + bytes.fromhex('11223344'))
    # user plane reserved bits (12, 15, 18 bit data; status/LWA control)
    A(hdr(USER, 0, seq=12, d=UL, chan=DCCH, ueid=2, chid=3), struct.pack('>H', 0xf000 | 1) + ipv4_udp())
    A(hdr(USER, 0, seq=18, d=UL, chan=DCCH, ueid=2, chid=3), bytes([0xfc, 0, 1]) + ipv4_udp())
    A(hdr(USER, 0, seq=12, d=UL, chan=DCCH, ueid=2, chid=3), struct.pack('>H', 0x0f00 | 5))
    A(hdr(USER, 0, seq=15, d=UL, chan=DCCH, ueid=2, chid=3), struct.pack('>H', 0x0fff) + bytes([0xff]))
    A(hdr(USER, 0, seq=18, d=UL, chan=DCCH, ueid=2, chid=3), bytes([0x0c, 0, 5]) + bytes([0xff]))
    A(hdr(USER, 0, seq=15, d=UL, chan=DCCH, ueid=2, chid=3), bytes([0x2f, 0x80, 0x10, 0x80, 0x20, 0x80, 0x05, 0x00]))
    A(hdr(USER, 0, seq=18, d=UL, chan=DCCH, ueid=2, chid=3), bytes([0x2c, 0, 5, 0, 0, 0xf0, 0, 0x10, 0]))
    A(hdr(USER, 0, seq=12, d=UL, chan=DCCH, ueid=2, chid=3), bytes([0x30 | 0x08, 0x01]))
    A(hdr(USER, 0, seq=15, d=UL, chan=DCCH, ueid=2, chid=3), bytes([0x3f, 0x01, 0x02]))
    A(hdr(USER, 0, seq=18, d=UL, chan=DCCH, ueid=2, chid=3), bytes([0x3c, 0x01, 0x02, 0x03]))
    # status report with reserved bits (15 bit)
    A(hdr(USER, 0, seq=15, d=UL, chan=DCCH, ueid=2, chid=3), bytes([0x0f, 0x80, 0x01, 0xff]))
    # truncated PDUs
    A(hdr(SIG, 0, d=UL, chan=DCCH, ueid=3, chid=1), bytes([0x00, 0x01]))
    A(hdr(USER, 0, seq=12, d=UL, chan=DCCH, ueid=3, chid=3), bytes([0x80]))
    A(hdr(USER, 0, seq=18, d=UL, chan=DCCH, ueid=3, chid=3), bytes([0x80, 0x00]))
    A(hdr(USER, 0, seq=12, d=UL, chan=DCCH, ueid=3, chid=3), bytes([0x00]))
    A(hdr(USER, 0, seq=12, d=DL, chan=DCCH, ueid=3, chid=3), bytes([0x20, 0x01]))
    A(hdr(USER, 0, seq=12, d=DL, chan=DCCH, ueid=3, chid=3), bytes([0x30]))
    # signalling PDU on DCCH shorter than the MAC-I
    A(hdr(SIG, 0, d=UL, chan=DCCH, ueid=3, chid=1), bytes([0x00, 0xaa, 0xbb]))
    # truncated framing header
    A(b'pdcp-lte' + bytes([0, SIG, 0, T_SEQ]), b'')
    A(b'pdcp-lte' + bytes([0, SIG, 0, T_UEID, 0]), b'')
    # RRC payloads that do not decode
    A(hdr(SIG, 1, d=UL, chan=CCCH, ueid=4), bytes([0xff, 0xff]))
    A(hdr(SIG, 1, d=DL, chan=BCCH, bcch=1), bytes([0xff]))
    return c


# ------------------------------------------------------------ DCT2000


def dct_line(proto, outhdr, hexdata, t, direction='s', ctx='lte.1'):
    return '%s/%s/%s %s tm 0.%04d l $%s\n' % (ctx, proto, ','.join(str(x) for x in [1] + list(outhdr)),
                                              direction, t, hexdata)


def dct_pdu(opcode, ue_tag, extra, pdu):
    """RLC-style wrapper used by DCT2000 pdcp_r8_lte: opcode, UE_Id_LCId
    or Cell_LCId tag, optional MUI, data tag, PDCP PDU."""
    return bytes([opcode]) + ue_tag + extra + b'\x41' + pdu


def ue_tag(ueid, srb=None, drb=None):
    if srb is not None:
        return bytes([0x10, 5]) + struct.pack('>H', ueid) + bytes([0, 1, srb])
    return bytes([0x10, 5]) + struct.pack('>H', ueid) + bytes([1, 1, drb])


def cell_tag(chan, ueid=None, bcch=None):
    t = bytes([0x1a, 0]) + struct.pack('>H', 1) + bytes([chan])
    if chan == BCCH:
        t += bytes([1, bcch])
    elif chan == CCCH:
        t += bytes([2]) + struct.pack('>H', ueid)
    return t[:1] + bytes([len(t) - 2]) + t[2:]


def build_dct():
    out = 'Session Transcript (format 5)\nOctober 31, 2026     10:00:00.0000\n'
    t = [1]

    def L(proto, outhdr, data):
        nonlocal out
        out += dct_line(proto, outhdr, data.hex(), t[0])
        t[0] += 1

    # outhdr: no_header, plane, seqnum_len, rohc, ip_version, cid_inc,
    # large_cid, mode, rnd, udp_checksum, profile, ah_length, gre_checksum
    sigh = [0, 1, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    # dedicated signalling, UL and DL, AM, with MUI
    mui = bytes([0x35, 2, 0, 7, 1])
    L('pdcp_r8_lte', sigh, dct_pdu(0x60, ue_tag(1, srb=1), mui, dcch(0, R['ul_setupcompl'])))
    L('pdcp_r8_lte', sigh, dct_pdu(0x61, ue_tag(1, srb=1), mui, dcch(0, smc(2, 2))))
    L('pdcp_r8_lte', sigh, dct_pdu(0x60, ue_tag(1, srb=1), mui, dcch(1, R['ul_smcompl'])))
    L('pdcp_r8_lte', sigh, dct_pdu(0x61, ue_tag(1, srb=2), bytes([0x45, 1, 0]) + mui, dcch(0, R['dl_reconf'], bytes.fromhex('01020304'))))
    L('pdcp_r8_lte', sigh, dct_pdu(0x70, ue_tag(2, srb=1), b'', dcch(0, R['ul_setupcompl'])))
    L('pdcp_r8_lte', sigh, dct_pdu(0x71, ue_tag(2, srb=1), b'', dcch(0, R['dl_infotr'])))
    # common channels (TM): BCCH (BCH, DL-SCH), CCCH, PCCH
    comh = [1, 1, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    L('pdcp_r8_lte', comh, dct_pdu(0x81, cell_tag(BCCH, bcch=1), b'', R['mib']))
    L('pdcp_r8_lte', comh, dct_pdu(0x81, cell_tag(BCCH, bcch=2), b'', R['si']))
    L('pdcp_r8_lte', comh, dct_pdu(0x81, cell_tag(PCCH), b'', R['paging']))
    L('pdcp_r8_lte', comh, dct_pdu(0x80, cell_tag(CCCH, ueid=5), b'', R['ul_connreq']))
    L('pdcp_r8_lte', comh, dct_pdu(0x81, cell_tag(CCCH, ueid=5), b'', R['dl_setup']))
    # user plane on a DRB, 12 and 18 bit SN, and a status report
    for snl, mk in ((12, lambda sn: struct.pack('>H', 0x8000 | sn)),
                    (18, lambda sn: u18(sn)),
                    (7, lambda sn: bytes([0x80 | sn]))):
        uh = [0, 2, snl, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        L('pdcp_r9_lte', uh, dct_pdu(0x70, ue_tag(3, drb=1), b'', mk(1) + ipv4_udp(b'dct2000')))
        L('pdcp_r9_lte', uh, dct_pdu(0x71, ue_tag(3, drb=1), b'', mk(2) + ipv6_udp(b'dct2000')))
    # ROHC configured DRB
    rh = [0, 2, 12, 1, 4, 0, 0, 2, 0, 0, 1, 0, 0]
    L('pdcp_r10_lte', rh, dct_pdu(0x71, ue_tag(4, drb=2), b'', struct.pack('>H', 0x8000 | 9) + bytes([0xfd, 1, 0, 0])))
    # DRB, status report
    uh = [0, 2, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    L('pdcp_r8_lte', uh, dct_pdu(0x70, ue_tag(3, drb=1), b'', struct.pack('>H', 50) + bytes([0xaa])))
    # unknown channel type tag: dissection stops
    L('pdcp_r8_lte', sigh, bytes([0x61, 0x77, 0x00, 0x41, 0x00, 0x01]))
    # reproducer of the fix: signalling PDU with SN length 9
    bad = [0, 1, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    L('pdcp_r8_lte', bad, bytes.fromhex('601005000100010135020007014100100000000000'))
    L('pdcp_r8_lte', bad, dct_pdu(0x60, ue_tag(1, srb=1), mui, dcch(1, R['ul_infotr'])))
    # key placeholders for the key leak fix (RRC Data_Req_UE_SM carrying
    # a cipher and an integrity key string; only the setters run, no key
    # is configured as a preference and nothing is deciphered)
    key1 = '00112233445566778899aabbccddeeff'
    key2 = 'ffeeddccbbaa99887766554433221100'

    def prim(ueid):
        body = bytes([0x12, 0x03]) + ueid.to_bytes(2, 'big') + bytes([0x00, 0x01, 0x01])
        sm = bytes([0x01, 0x01, 0x21, 0x00])
        sm += bytes([0x02, 0x13, 0x80, 0x01, 0x02, 0x81, 0x10]) + bytes.fromhex(key1)
        sm += bytes([0x03, 0x13, 0x80, 0x01, 0x02, 0x81, 0x10]) + bytes.fromhex(key2)
        body += bytes([0x30, len(sm)]) + sm
        return bytes([0x05, len(body)]) + body

    def prim_only(ueid, which):
        sm = bytes([0x01, 0x01, 0x21, 0x00])
        sm += bytes([0x03, 0x13, 0x80, 0x01, 0x02, 0x81, 0x10]) + bytes.fromhex(key2)
        body = bytes([0x12, 0x03]) + ueid.to_bytes(2, 'big') + bytes([0x00, 0x01, 0x01])
        body += bytes([0x30, len(sm)]) + sm
        return bytes([0x05, len(body)]) + body

    for ueid in range(1, 4):
        out += '%s/%s/1 s tm 0.%04d l $%s\n' % ('lte.1', 'rrc_r8_lte', t[0], prim(ueid).hex())
        t[0] += 1
    # a UE whose first key is the integrity key, then a full primitive
    for body in (prim_only(10, 'i'), prim(10)):
        out += '%s/%s/1 s tm 0.%04d l $%s\n' % ('lte.1', 'rrc_r8_lte', t[0], body.hex())
        t[0] += 1
    # more keys than the table holds for one UE (32): the extra ones are ignored
    for i in range(18):
        out += '%s/%s/1 s tm 0.%04d l $%s\n' % ('lte.1', 'rrc_r8_lte', t[0], prim(11).hex())
        t[0] += 1
    return out


def main():
    outdir = sys.argv[1]
    verbose = '-v' in sys.argv
    os.makedirs(outdir, exist_ok=True)
    for name, c in (('pdcp-lte-coverage', build_main()),
                    ('pdcp-lte-coverage-malformed', build_malformed())):
        write_pcap(os.path.join(outdir, name + '.pcap'), c.frames)
        if verbose:
            print(name, len(c.frames), 'frames')
            ends = [s for s, _ in c.sections[1:]] + [len(c.frames) + 1]
            for (s, n), e in zip(c.sections, ends):
                print('  %d-%d %s' % (s, e - 1, n))
    with open(os.path.join(outdir, 'pdcp-lte-dct2000.out'), 'w') as f:
        f.write(build_dct())


if __name__ == '__main__':
    main()
