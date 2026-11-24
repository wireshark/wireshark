#!/usr/bin/env python3
# Generates test/captures/dct2000_coverage.out.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Catapult DCT2000 dissector
(epan/dissectors/packet-catapult-dct2000.c).

Everything is built from scratch here (struct for the binary payloads,
text for the .out lines); nothing comes from a real test system or network.

Usage: mkdct2000.py <output directory>

Writes:
  catapult-dct2000-coverage.out        the main capture: a Catapult DCT2000
                                       .out text log read by
                                       wiretap/catapult_dct2000.c
  catapult-dct2000-coverage-malformed.out
                                       .out lines that end in an exception or
                                       an error expert info, and the lines
                                       that store a PDCP key (PDCP leaks the
                                       key string)
  catapult-dct2000-coverage-exported.pcap
                                       Exported PDU records (LINKTYPE 252) that
                                       name the "dct2000" dissector: the only
                                       way to reach the record checks that a
                                       .out file cannot produce (unknown
                                       encapsulation byte, ATM/ISDN/PPP without
                                       a DCT2000 pseudo-header, a short
                                       timestamp, a non-numeric FP variant)
"""

import os
import struct
import sys

# --------------------------------------------------------------------------
# CRCs used by UMTS FP (wsutil/crc7.c, crc11.c, crc16.c)


def crc7(data):
    reg = 0
    for b in data:
        reg ^= b
        for _ in range(8):
            reg = ((reg << 1) ^ 0x8a) if reg & 0x80 else (reg << 1)
            reg &= 0xff
    return reg >> 1


def crc16_8005(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x8005) if crc & 0x8000 else (crc << 1)
            crc &= 0xffff
    return crc


def aal2(fp):
    """The ATM dissector skips 4 octets (side, length, UUI) before FP."""
    return bytes([0, len(fp), 0, 0]) + fp


def fp_control(frame):
    """FP control frame: CRC7 over the frame with only the FT bit kept."""
    frame = bytes([1]) + frame
    return aal2(bytes([(crc7(frame) << 1) | 1]) + frame[1:])


def fp_data(header_rest, payload, payload_crc):
    """FP data frame: header CRC7 over the header after the first octet."""
    out = bytes([crc7(header_rest) << 1]) + header_rest + payload
    if payload_crc:
        out += struct.pack('>H', crc16_8005(payload))
    return aal2(out)


# --------------------------------------------------------------------------
# Bit packing for the hand-encoded PER messages


def bits(spec):
    """spec: list of (value, nbits); returns bytes, zero padded."""
    s = ''.join(format(v, '0%db' % n) if n else '' for v, n in spec)
    s += '0' * (-len(s) % 8)
    return bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))


# LTE RRC (36.331), UPER
LTE_UL_CCCH = bits([(0, 1), (1, 1), (0, 1), (1, 1), (0x123456789a, 40), (3, 3), (0, 1)])  # RRCConnectionRequest
LTE_DL_CCCH = bits([(0, 1), (2, 2), (0, 1), (0, 2), (0, 1), (5, 4)])                      # RRCConnectionReject
LTE_UL_DCCH = bits([(0, 1), (2, 4), (0, 2), (0, 1), (0, 1)])                              # RRCConnectionReconfigurationComplete
LTE_DL_DCCH = bits([(0, 1), (5, 4), (1, 2), (0, 1), (0, 2), (0, 3), (1, 2)])              # RRCConnectionRelease
LTE_PCCH = bits([(0, 1), (0, 4)])                                                         # Paging, empty
LTE_BCCH_BCH = bytes.fromhex('a00a00')                                                    # MasterInformationBlock
LTE_BCCH_DL_SCH = bits([(1, 1)])                                                          # messageClassExtension
# NR RRC (38.331), UPER
NR_UL_CCCH = bits([(0, 1), (0, 2), (1, 1), (0x12345678, 39), (3, 4), (0, 1)])             # RRCSetupRequest, 6 octets
NR_UL_CCCH1 = bits([(0, 1), (0, 2), (0x1122334455, 40), (0xabcd, 16), (1, 4), (0, 1)])     # RRCResumeRequest1, 8 octets
NR_UL_DCCH = bits([(0, 1), (1, 4), (0, 2), (0, 1), (0, 2)])                               # RRCReconfigurationComplete
NR_DL_DCCH = bits([(0, 1), (2, 4), (0, 2), (0, 1), (0, 6)])                               # RRCRelease
NR_DL_CCCH = bits([(0, 1), (0, 2), (0, 1), (0, 3)])                                       # RRCReject
NR_PCCH = bits([(0, 1), (0, 1), (0, 3)])                                                  # Paging, empty
NR_BCCH_BCH = bytes.fromhex('000000')                                                     # MIB
NR_BCCH_DL_SCH = bits([(1, 1)])                                                           # messageClassExtension

# NBAP AuditRequiredIndication with no IEs (APER)
NBAP_AUDIT_REQUIRED = bytes.fromhex('0001400003000000')

# NAS
NAS_EPS_EMM_STATUS = bytes.fromhex('076011')
NAS_5GS_5GMM_STATUS = bytes.fromhex('7e00646f')


# --------------------------------------------------------------------------
# Network-layer payloads


def ip_checksum(hdr):
    if len(hdr) % 2:
        hdr += b'\0'
    s = sum(struct.unpack('>%dH' % (len(hdr) // 2), hdr))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(proto, payload, src=(10, 0, 0, 1), dst=(10, 0, 0, 2)):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                      bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack('>H', ip_checksum(hdr)) + hdr[12:]
    return hdr + payload


def udp(sport, dport, payload, src=(10, 0, 0, 1), dst=(10, 0, 0, 2)):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, len(hdr) + len(payload))
    cs = ip_checksum(pseudo + hdr + payload) or 0xffff
    return hdr[:6] + struct.pack('>H', cs) + payload


_qid = [0x1000]


def dns_response(name='example.test', qid=None):
    if qid is None:
        _qid[0] += 1
        qid = _qid[0]
    q = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0'
    return struct.pack(">HHHHHH", qid, 0x8180, 1, 0, 0, 0) + q + struct.pack('>HH', 1, 1)


def igmp_query():
    m = bytearray.fromhex('1164000000000000')
    m[2:4] = struct.pack('>H', ip_checksum(bytes(m)))
    return bytes(m)


def eth(payload, ethertype=0x0800):
    return bytes.fromhex('020000000002') + bytes.fromhex('020000000001') + \
        struct.pack('>H', ethertype) + payload


def diameter_dwr():
    def avp(code, data):
        ln = 8 + len(data)
        return struct.pack('>IBBH', code, 0x40, ln >> 16, ln & 0xffff) + data + b'\0' * (-ln % 4)
    avps = avp(264, b'dct.example.test') + avp(296, b'example.test')
    ln = 20 + len(avps)
    return struct.pack('>BBHBBHIII', 1, ln >> 16, ln & 0xffff, 0x80, 0, 280, 0, 0x1111, 0x2222) + avps


GTPV2_ECHO = bytes.fromhex('40010009000001000300010005')

SIP_OPTIONS = (b'OPTIONS sip:node@example.test SIP/2.0\r\n'
               b'Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n'
               b'From: <sip:a@example.test>;tag=1\r\nTo: <sip:node@example.test>\r\n'
               b'Call-ID: 1@10.0.0.1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n')

# --------------------------------------------------------------------------
# .out writer


class Out:
    def __init__(self):
        self.lines = []
        self.t = 0
        self.notes = []

    def _ts(self):
        self.t += 10
        return '%d.%04d' % (self.t // 10000, self.t % 10000)

    def note(self, text):
        self.notes.append((len(self.lines) + 1, text))

    def pkt(self, proto, data, variant='1', outhdr=None, direction='s', ctx='ctx', port=1,
            aal=None):
        head = '%s.%d/%s/%s' % (ctx, port, proto, variant)
        if outhdr is not None:
            head += ',' + ','.join(str(v) for v in outhdr)
        if aal is not None:
            head += '$%s/' % aal
        if isinstance(data, str):
            data = bytes.fromhex(data)
        self.lines.append('%s %s tm %s l $%s' % (head, direction, self._ts(), data.hex()))

    def comment(self, text, ctx='ctx'):
        self.lines.append('%s/////  tm %s l $%s' % (ctx, self._ts(), text))

    def sprint(self, text, ctx='ctx'):
        self.lines.append('%s///// tm %s %s' % (ctx, self._ts(), text))

    def write(self, path):
        with open(path, 'w') as f:
            f.write('Session Transcript (format 5)\n')
            f.write('October 31, 2026     10:00:00.0000\n')
            for line in self.lines:
                f.write(line + '\n')


# --------------------------------------------------------------------------
# DCT2000 primitive headers


def sec_params(cell_group=False, crypt=True, crypt_key=True, int_key=True):
    """Data_Req_UE_SM SecurityMode params: uplink and downlink mode, then
    (tag 0x21) an optional cell group or cryptParams and the auth params."""
    if cell_group:
        # The dissector reads the octet after the cell group value as the
        # auth params length, then skips two octets to the algorithm.
        rest = bytes([0x25, 1, 0, 0x01, 1, 2])
    else:
        inner = b''
        if crypt:
            c = bytes([0x01, 1, 2])               # cipher algorithm
            if crypt_key:
                c += bytes([0x03, 16]) + bytes(range(0x10, 0x20))
            inner = bytes([0x02, len(c)]) + c
        a = bytes([0x01, 1, 2])                   # integrity algorithm
        if int_key:
            a += bytes([0x03, 16]) + bytes(range(0x20, 0x30))
        rest = inner + bytes([0x04, len(a)]) + a
    p = bytes([1, 1, 0x21, len(rest)]) + rest
    return bytes([0x24, len(p)]) + p


def pdcp_lte_hdr(opcode, chan, pdu, mui=False, discard=False):
    if chan[0] == 'ue':
        body = bytes([0x10, 5]) + struct.pack('>H', chan[1]) + bytes([chan[2], 1, chan[3]])
    else:
        body = bytes([0x1a, 3]) + struct.pack('>HB', chan[1], chan[2]) + chan[3]
    if mui:
        body += bytes([0x35, 2, 0x00, 0x07])
        if opcode in (0x60, 0x61):
            body += b'\x01'                   # CNF
    if discard:
        body += bytes([0x45, 1, 1])
    body += b'\x41' + pdu
    return bytes([opcode]) + body


def rlc_umts_prim(opcode, tlvs, data):
    return bytes([opcode]) + tlvs + b'\x41' + bytes([len(data)]) + data


def ipprim(cmd, tlvs, data):
    data_tag = 0x34 if cmd in (0x23, 0x24) else 0x48
    return bytes([cmd]) + tlvs + bytes([data_tag]) + data


def tlv(tag, value):
    return bytes([tag, len(value)]) + value


# --------------------------------------------------------------------------
# Main capture


def build_main():
    o = Out()

    # ---- Encapsulations set by wiretap ----
    o.note('board-port encapsulations: ip, sctp, igmp, ethernet, isdn_l2, isdn_l3, ppp, '
           'SSCOP, frame relay, MTP2, NBAP')
    o.pkt('ip', ipv4(17, udp(1234, 53, dns_response())))
    o.pkt('sctp', ipv4(132, struct.pack('>HHII', 2905, 2905, 1, 0)), direction='r')
    o.pkt('igmp', ipv4(2, igmp_query()))
    o.pkt('ethernet', eth(ipv4(17, udp(1234, 53, dns_response('eth.example.test')))))
    o.pkt('isdn_l2', '00017f', direction='s')                 # LAPD SABME
    o.pkt('isdn_l2', '02017f', direction='r')
    o.pkt('isdn_l3', 'ff0001010008020001050401', direction='r')  # first octet skipped
    o.pkt('ppp', 'ff03c021010100040000', direction='s')
    o.pkt('ppp', 'ff03c021020100040000', direction='r')
    o.pkt('saalnni_sscop', '0000000001000001')
    o.pkt('saaluni_sscop', '000000000a000001', direction='r')
    o.pkt('frelay_l2', '0401' + '03cc' + ipv4(17, udp(1, 2, b'fr')).hex())
    o.pkt('ss7_mtp2', 'ffff00')
    o.pkt('nbap', NBAP_AUDIT_REQUIRED)
    o.pkt('nbap_r4', NBAP_AUDIT_REQUIRED, direction='r')
    o.pkt('nbap_sscfuni_r5', NBAP_AUDIT_REQUIRED)

    # ---- FP over ATM AAL2 ----
    o.note('UMTS FP over AAL2: fp (R99), fp_r4..fp_r8; every outhdr shape')
    aal = '001002000008'
    dl_sync = fp_control(bytes([3, 0x10]))            # DL synchronisation, CFN 16
    common_dl_node_sync = fp_control(bytes([6]) + b'\x00\x10\x00')
    # R99 DCH data frame: 1 channel, TF size 16 bits, 1 TB, payload CRC
    # (no TBs: the UMTS MAC dissector has no per-frame info for DCT2000 logs)
    o.pkt('fp', fp_data(bytes([0x05, 0x01]), b'', True), variant='1',
          outhdr=[12, 2, 1, 0, 1, 16, 0], direction='s', aal=aal)          # downlink
    o.pkt('fp', fp_data(bytes([0x06, 0x01]), b'\x10', True), variant='1',
          outhdr=[12, 2, 1, 0, 1, 16, 0], direction='r', aal=aal)          # uplink, QE + CRCI
    o.pkt('fp', dl_sync, variant='1', outhdr=[0, 2, 0, 0, 1, 16, 1], aal=aal)   # channel 0 -> DCH
    o.pkt('fp_r4', dl_sync, variant='2', outhdr=[12, 1, 0, 0, 2, 8, 16, 1, 2], aal=aal)
    o.pkt('fp_r5', common_dl_node_sync, variant='1', outhdr=[13, 1, 0, 0, 0], aal=aal)  # HS-DSCH pre-R7
    for v in ('1', '2', '3', '513'):
        o.pkt('fp_r6', dl_sync, variant=v, outhdr=[12, 2, 0, 0, 1, 16, 1], aal=aal, direction='r')
    o.pkt('fp_r7', common_dl_node_sync, variant='1', outhdr=[13, 1, 0, 1, 0, 0, 0], aal=aal)  # MAC-ehs
    o.pkt('fp_r7', common_dl_node_sync, variant='1', outhdr=[13, 1, 0, 0, 0, 0, 0], aal=aal, direction='r')
    o.pkt('fp_r7', dl_sync, variant='1', outhdr=[12, 2, 0, 1, 0, 3, 8, 8], aal=aal)  # fewer TF/TB values than channels
    o.pkt('fp_r8', dl_sync, variant='1', outhdr=[17, 1, 0, 0, 0, 1, 2, 1, 2, 336, 148, 1], aal=aal)  # E-DCH
    o.pkt('fp_r8', dl_sync, variant='1', outhdr=[17, 1, 0, 0, 0, 1, 3, 1], aal=aal, direction='r')    # DDIs missing
    o.pkt('fp_r6', dl_sync, variant='1', outhdr=[17, 2, 0, 0, 1, 1, 5, 336], aal=aal)  # E-DCH, R6
    o.pkt('fp_r7', common_dl_node_sync, variant='1', outhdr=[21, 1, 0, 0, 0, 1, 8, 1], aal=aal)  # E-DCH common
    o.pkt('fp_r6', common_dl_node_sync, variant='1', outhdr=[3, 2, 0, 0, 1, 168, 1], aal=aal)  # FACH
    o.note('FP outhdr counts far above the caps (bounded by the fix): control frames decode')
    o.pkt('fp_r6', dl_sync, variant='1',
          outhdr=[12, 2, 0, 4294967295, 4294967295] + [4294967295] * 8, aal=aal)
    o.pkt('fp_r8', dl_sync, variant='1', outhdr=[17, 1, 0, 0, 0, 1, 4000, 1, 2], aal=aal)
    o.pkt('fp_r6', dl_sync, variant='1', outhdr=[12, 2, 0, 0, 2147483648, 16, 600], aal=aal)

    # ---- UMTS RLC ----
    o.note('UMTS RLC primitives (rlc, rlc_r4..rlc_r9): every tag, rbid and mode')
    am_status = bytes.fromhex('00')          # AM STATUS, SUFI NO_MORE
    tlvs_full = (bytes([0x72, 0, 0, 0, 7]) +           # UE Id
                 bytes([0xa2, 1, 3]) +                    # RBID 3
                 bytes([0xc4, 0xc5, 0xf7]) +              # CRC ok/error, clear tx buffer
                 tlv(0x42, b'\x00\x10') + tlv(0x49, b'\x10\x00') + tlv(0x47, b'\x01') +
                 tlv(0x4e, b'\x02') + tlv(0x4c, b'\x01') + tlv(0x43, b'\x05') +
                 tlv(0x46, b'\x01') + tlv(0xc2, b'\x00') + tlv(0x99, b'\x00\x00'))
    o.pkt('rlc', rlc_umts_prim(0xc0, tlvs_full, am_status), outhdr=[1, 3])
    ue_rb = lambda rb: bytes([0x72, 0, 0, 0, 7, 0xa2, 1, rb])
    for name, mode, rb in (('rlc_r4', 1, 5), ('rlc_r5', 2, 15), ('rlc_r6', 4, 2),
                           ('rlc_r7', 5, 4), ('rlc_r8', 3, 21), ('rlc_r9', 3, 30)):
        # UM: SN 0, one 7-bit LI, a complete 2 octet SDU
        data = am_status if mode in (3, 5) else bytes.fromhex('0104abcd')
        o.pkt(name, rlc_umts_prim(0xc1, ue_rb(rb), data), outhdr=[1, mode], direction='r')
    # CCCH-id: rbid 18; downlink CCCH is UM: SN 0, LI 1, DL-CCCH-Message spare1
    o.pkt('rlc_r6', rlc_umts_prim(0xc1, ue_rb(1) + bytes([0x22, 1, 0]), bytes.fromhex('010270')),
          outhdr=[1, 2], direction='s')
    o.pkt('rlc_r6', rlc_umts_prim(0xc0, ue_rb(3), am_status), outhdr=[1, 9])  # unknown mode
    o.pkt('rlc_r6', rlc_umts_prim(0xc0, ue_rb(3), am_status), outhdr=[1])     # one outhdr value
    o.pkt('rlc_r6', rlc_umts_prim(0xc0, bytes([0xa2, 1, 3]), am_status), outhdr=[1, 3])  # no UE Id
    o.pkt('rlc_r6', '0500', outhdr=[1, 3])                                  # not a data primitive

    # ---- LTE MAC ----
    o.note('LTE MAC (mac_r8/r9/r10_lte): every outhdr length')
    pad = bytes.fromhex('1f')                  # padding-only subheader
    # radio, rntiType, dir, subframe, predef, rnti, ueid, length, ...
    o.pkt('mac_r8_lte', pad, outhdr=[0, 3, 1, 4, 0, 1001, 1, 1])
    o.pkt('mac_r8_lte', pad, outhdr=[0, 3, 1, 4, 0, 1001, 1, 1, 0])
    o.pkt('mac_r9_lte', pad, outhdr=[0, 3, 1, 4, 0, 1001, 1, 1, 0, 1])          # DL CRC
    o.pkt('mac_r9_lte', pad, outhdr=[0, 3, 0, 4, 0, 1001, 1, 1, 0, 1], direction='r')  # UL, CRC ignored
    o.pkt('mac_r10_lte', pad,
          outhdr=[0, 3, 1, 5, 0, 1001, 1, 1, 0, 1, 1, 2, 3, 4, 1, 0, 6, 1, 3, 1, 7, 100, 0, 1, 2])
    o.pkt('mac_r10_lte', pad,
          outhdr=[0, 3, 1, 5, 0, 1001, 1, 1, 0, 1, 1, 2, 3, 4, 0, 0, 6, 1])        # DL, 18 values
    o.pkt('mac_r10_lte', pad,
          outhdr=[0, 3, 1, 5, 0, 1001, 1, 1, 0, 1, 1, 2, 3, 4, 0, 0, 6, 1, 3, 1])  # DL, 20 values
    o.pkt('mac_r10_lte', pad,
          outhdr=[0, 3, 0, 6, 0, 1001, 1, 1, 0, 1, 2, 5, 4, 3, 0, 7], direction='r')   # UL, 16 values
    o.pkt('mac_r10_lte', pad,
          outhdr=[0, 3, 0, 6, 0, 1001, 1, 1, 0, 1, 2, 5, 4, 3, 0, 1, 0, 7, 200, 0, 0, 1, 2],
          direction='r')                                                           # UL, all values
    o.pkt('mac_r10_lte', pad,
          outhdr=[0, 3, 0, 6, 0, 1001, 1, 1, 0, 1, 2, 5, 4, 3, 0], direction='r')  # UL, 15 values
    o.pkt('mac_r8_lte', '00', outhdr=[0, 2, 1, 4, 1, 2, 0, 1])                # predefined data

    # ---- LTE RLC ----
    o.note('LTE RLC (rlc_r8/r9/r10_lte)')
    o.pkt('rlc_r8_lte', '0040', outhdr=[4, 1, 1, 10, 1, 4, 1, 2])          # AM STATUS
    o.pkt('rlc_r9_lte', '0040', outhdr=[4, 0, 1, 10, 2, 4, 1, 2], direction='r')
    o.pkt('rlc_r10_lte', '0040', outhdr=[4, 1, 1, 10, 1, 4, 2, 2])

    # ---- LTE PDCP ----
    o.note('LTE PDCP primitives (pdcp_r8/r9/r10_lte): opcodes, channel tags, MUI, discard')
    srb = b'\x00' + LTE_UL_DCCH + b'\x00\x00\x00\x00'      # SN 0, UL-DCCH, MAC-I
    srb_dl = b'\x01' + LTE_DL_DCCH + b'\x00\x00\x00\x00'
    drb = lambda: bytes([0x80, 0x01]) + ipv4(17, udp(1234, 53, dns_response('pdcp.example.test')))
    sp = [0, 1, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]            # signalling plane, 5-bit SN
    up = [0, 2, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]           # user plane, 12-bit SN
    o.pkt('pdcp_r8_lte', pdcp_lte_hdr(0x60, ('ue', 1, 0, 1), srb, mui=True), outhdr=sp)
    o.pkt('pdcp_r8_lte', pdcp_lte_hdr(0x61, ('ue', 1, 0, 1), srb_dl, mui=True), outhdr=sp, direction='r')
    o.pkt('pdcp_r9_lte', pdcp_lte_hdr(0x70, ('ue', 1, 1, 1), drb(), mui=True, discard=True), outhdr=up)
    o.pkt('pdcp_r9_lte', pdcp_lte_hdr(0x71, ('ue', 1, 1, 1), drb()), outhdr=up, direction='r')
    o.pkt('pdcp_r10_lte', pdcp_lte_hdr(0x80, ('cell', 1, 3, b'\x02\x00\x01'), LTE_UL_CCCH),
          outhdr=[1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    o.pkt('pdcp_r10_lte', pdcp_lte_hdr(0x81, ('cell', 1, 2, b'\x01\x02'), LTE_BCCH_DL_SCH),
          outhdr=[1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], direction='r')
    o.pkt('pdcp_r10_lte', pdcp_lte_hdr(0x81, ('cell', 1, 4, b''), LTE_PCCH),
          outhdr=[1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], direction='r')
    o.pkt('pdcp_r8_lte', bytes([0x60, 0x10, 5, 0, 1, 7, 1, 1]), outhdr=sp)   # unknown channel tag
    o.pkt('pdcp_r8_lte', bytes([0x60, 0x77, 0, 0]), outhdr=sp)               # unknown header tag
    o.pkt('pdcp_r8_lte', bytes([0x62, 0, 0]), outhdr=sp)                     # data confirm

    # ---- NAS ----
    o.note('NAS RRC (LTE and 5G NR) and NAS S1AP primitives')
    def nas_rrc(op, extra, nas):
        body = bytes([0x01, 0, 0, 0, 7]) + extra + bytes([0x50, len(nas)]) + nas
        return bytes([op, len(body)]) + body
    o.pkt('nas_rrc_r8_lte', nas_rrc(0x02, b'', NAS_EPS_EMM_STATUS), direction='r')
    o.pkt('nas_rrc_r9_lte', nas_rrc(0x03, b'', NAS_EPS_EMM_STATUS))
    o.pkt('nas_rrc_r10_lte', nas_rrc(0x06, bytes([0x02, 1, 3, 0x03, 1, 1]), NAS_EPS_EMM_STATUS))
    o.pkt('nas_rrc_r13_lte', nas_rrc(0x08, bytes([0x04, 1, 2]), NAS_EPS_EMM_STATUS), direction='r')
    o.pkt('nas_rrc_r15_5gnr', nas_rrc(0x03, b'', NAS_5GS_5GMM_STATUS))
    o.pkt('nas_rrc_r8_lte', bytes([0x01, 0x01, 0x00]))                              # no NAS body
    def nas_s1ap(op, tag, nas):
        body = bytes([0x01, 4, 0, 0, 0, 9]) + struct.pack('>HH', tag, len(nas)) + nas
        return bytes([op, len(body)]) + body
    o.pkt('nas_s1ap_r15_5gnr', nas_s1ap(0, 0x21, NAS_5GS_5GMM_STATUS))
    o.pkt('nas_s1ap_r15_5gnr', nas_s1ap(1, 0x21, NAS_5GS_5GMM_STATUS), direction='r')
    o.pkt('nas_s1ap_r15_5gnr', nas_s1ap(1, 0x30, b'\x00'), direction='r')     # not a NAS PDU tag
    o.pkt('nas_s1ap_r15_5gnr', '0500')                                        # opcode > Data-Ind

    # ---- LTE / NR RRC ----
    o.note('LTE RRC (all protocol names) and NR RRC primitives: opcodes, channels, carrier '
           'fields, security mode params')
    lte_names = ['rrc_r8_lte', 'rrcpdcpprim_r8_lte', 'rrc_r9_lte', 'rrcpdcpprim_r9_lte',
                 'rrc_r10_lte', 'rrc_r11_lte', 'rrc_r12_lte', 'rrc_r13_lte', 'rrc_r15_lte',
                 'rrc_r16_lte', 'rrcpdcpprim_r15_lte']
    lte_msgs = [
        (0x00, ('ue', 1, 0, 1), LTE_UL_DCCH, 's'),
        (0x04, ('ue', 2, 1, 1), LTE_UL_DCCH, 'r'),
        (0x02, ('ue', 1, 0, 1), LTE_DL_DCCH, 's'),
        (0x03, ('cell', 1, 3, b'\x02\x00\x05'), LTE_DL_CCCH, 'r'),
        (0x00, ('cell', 1, 3, b'\x02\x00\x05'), LTE_UL_CCCH, 's'),
        (0x03, ('cell', 1, 4, b''), LTE_PCCH, 'r'),
        (0x03, ('cell', 1, 2, b'\x01\x01'), LTE_BCCH_BCH, 'r'),
        (0x03, ('cell', 1, 2, b'\x01\x02'), LTE_BCCH_DL_SCH, 'r'),
        (0x07, ('ue', 1, 0, 1), LTE_DL_DCCH, 'r'),
        (0x00, ('cell', 1, 1, b''), LTE_UL_DCCH, 's'),        # DCCH by cell: no UL handle
    ]
    for i, (op, chan, msg, d) in enumerate(lte_msgs):
        o.pkt(lte_names[i % len(lte_names)], _rrc(op, chan, msg, b'', carrier=(i % 2 == 0)),
              direction=d)
    for name in lte_names[len(lte_msgs):]:
        o.pkt(name, _rrc(0x02, ('ue', 3, 0, 2), LTE_DL_DCCH, b''), direction='r')
    o.pkt('rrc_r9_lte', _rrc(0x02, ('cell', 1, 1, b''), LTE_DL_DCCH, b''), direction='r')  # DL DCCH via cell
    o.pkt('rrc_r9_lte', _rrc(0x02, ('cell', 1, 9, b''), LTE_DL_DCCH, b''), direction='r')  # unknown channel
    o.pkt('rrc_r9_lte', _rrc(0x00, ('cell', 1, 9, b''), LTE_UL_DCCH, b''))                 # unknown UL channel
    # Data_Req_UE_SM with security mode params. Params that carry a key are in
    # the malformed file: PDCP leaks the stored key string.
    o.pkt('rrc_r10_lte', _rrc(0x05, ('ue', 5, 0, 1), LTE_UL_DCCH, b'',
                              sm=sec_params(crypt_key=False, int_key=False)))
    o.pkt('rrc_r10_lte', _rrc(0x05, ('ue', 6, 0, 1), LTE_UL_DCCH, b'',
                              sm=sec_params(cell_group=True)))
    o.pkt('rrc_r10_lte', _rrc(0x05, ('ue', 7, 0, 1), LTE_UL_DCCH, b'',
                              sm=bytes([0x24, 2, 0, 0])))                   # modes only
    o.pkt('rrc_r10_lte', _rrc(0x02, ('ue', 1, 0, 1), None, b''), direction='r')   # no data tag
    o.pkt('rrc_r10_lte', _rrc(0x02, ('ue', 1, 0, 1), None, b'\x55'), direction='r')  # other tag
    o.pkt('rrc_r10_lte', _rrc(0x02, ('ue', 1, 5, 1), None, b''), direction='r')   # unknown channel tag
    o.pkt('rrc_r10_lte', bytes([0x02, 2, 0x99, 0]), direction='r')                # unknown header tag
    o.pkt('rrc_r10_lte', bytes([0x09, 0]), direction='r')                         # unknown opcode
    nr_msgs = [
        (0x00, ('ue', 1, 0, 1), NR_UL_DCCH, 's'),
        (0x03, ('ue', 1, 1, 1), NR_DL_DCCH, 'r'),
        (0x00, ('cell', 1, 3, b'\x02\x00\x05'), NR_UL_CCCH, 's'),
        (0x00, ('cell', 1, 3, b'\x02\x00\x05'), NR_UL_CCCH1, 's'),
        (0x03, ('cell', 1, 3, b'\x02\x00\x05'), NR_DL_CCCH, 'r'),
        (0x03, ('cell', 1, 4, b''), NR_PCCH, 'r'),
        (0x03, ('cell', 1, 2, b'\x01\x01'), NR_BCCH_BCH, 'r'),
        (0x03, ('cell', 1, 2, b'\x01\x02'), NR_BCCH_DL_SCH, 'r'),
    ]
    for i, (op, chan, msg, d) in enumerate(nr_msgs):
        o.pkt(('rrc_r15_5g', 'rrc_r16_5g')[i % 2], _rrc(op, chan, msg, b''), direction=d)
    o.pkt('rrc_r15_5g', _rrc(0x05, ('ue', 8, 0, 1), NR_UL_DCCH, b'',
                             sm=sec_params(crypt_key=False, int_key=False)))
    o.pkt('rrc_r16_5g', _rrc(0x05, ('ue', 9, 0, 1), NR_UL_DCCH, b'',
                             sm=sec_params(crypt=False, int_key=False)))

    # ---- CCPRI ----
    o.note('CCPRI (LTE): request and indication, data and no data tag')
    lapb = bytes.fromhex('013f')
    o.pkt('ccpri_r8_lte', bytes([1, 0, 9, 0, 1, 3, 2]) + struct.pack('>H', len(lapb)) + lapb)
    o.pkt('ccpri_r9_lte', bytes([2, 0, 10, 0, 1, 0, 3, 2]) + struct.pack('>H', len(lapb)) + lapb,
          direction='r')
    o.pkt('ccpri_r9_lte', bytes([1, 0, 4, 0, 1, 3, 9]))

    # ---- Other unhandled protocols ----
    o.note('xml, tty, sipprim, an unknown protocol, raw SIP')
    o.pkt('xml', b'<?xml version="1.0"?><dct><node id="1"/></dct>')
    o.pkt('tty', b'first line\r\nsecond line\r\n')
    o.pkt('tty', b'only line')
    o.pkt('tty', b'\x01\x02binary\r\n', direction='r')
    o.pkt('sipprim', '0102030405')
    o.pkt('unknown_proto', '00112233')
    o.pkt('sip', SIP_OPTIONS.replace(b'branch=z9hG4bK1', b'branch=z9hG4bK2'))  # no primitive: needs
                                                     # use_protocol_name_as_dissector_name

    # ---- IPPrim ----
    o.note('IPPrim heuristic: UDP/TCP request/indication, IPv4/IPv6 remote and local '
           'addresses, ports, conn_id, address TLVs of length 8 and 12 (fix)')
    v4a, v4b = bytes([10, 1, 1, 1]), bytes([10, 1, 1, 2])
    v6a = bytes.fromhex('20010db8000000000000000000000001')
    v6b = bytes.fromhex('20010db8000000000000000000000002')
    port = lambda p: struct.pack('>H', p)
    o.pkt('dns', ipprim(0x23, tlv(0x31, v4b + port(53)) + tlv(0x32, v4a) + tlv(0x33, port(3333)),
                        dns_response('ipprim.example.test')))
    o.pkt('dns', ipprim(0x24, tlv(0x31, v4b + port(53)) + tlv(0x32, v4a) + tlv(0x33, port(3333)),
                        dns_response('ipprim.example.test', 0x4321)), direction='r')
    o.pkt('dns', ipprim(0x23, tlv(0x31, v6b + port(53)) + tlv(0x32, v6a) + tlv(0x33, port(3333)),
                        dns_response('v6.example.test')))
    o.pkt('dns', ipprim(0x24, tlv(0x31, v6b) + tlv(0x32, v6a), dns_response('v6.example.test')),
          direction='r')
    o.pkt('diameter_rx', ipprim(0x45, tlv(0x31, v4b + port(3868)) + tlv(0x32, v4a) +
                                tlv(0x33, port(4000)) + tlv(0x36, port(17)), diameter_dwr()))
    o.pkt('diameter', ipprim(0x46, tlv(0x31, v4b + port(3868)) + tlv(0x36, port(17)),
                             diameter_dwr()), direction='r')
    o.pkt('gtpv2_r8', ipprim(0x23, tlv(0x31, v4b + port(2123)) + tlv(0x32, v4a) +
                             tlv(0x33, port(2123)), GTPV2_ECHO))
    o.pkt('sip', ipprim(0x23, tlv(0x31, v4b + port(5060)) + tlv(0x32, v4a) + tlv(0x33, port(5060)),
                        SIP_OPTIONS))
    o.pkt('dns', ipprim(0x23, tlv(0x31, v4b + port(53)) + tlv(0x32, b'\x01\x02') +
                        tlv(0x33, b'\x01') + tlv(0x31, b'\x01\x02') + tlv(0x77, b'\x00'),
                        dns_response()))                                     # ignored TLVs
    o.note('IPPrim remote address TLV of length 8 and 12: not used as an address (fix)')
    o.pkt('dns', ipprim(0x23, tlv(0x31, v4b + v4b) + tlv(0x32, v4a) + tlv(0x33, port(3333)),
                        dns_response('len8.example.test')))
    o.pkt('dns', ipprim(0x24, tlv(0x31, v4b * 3 + port(53)) + tlv(0x32, v4a),
                        dns_response('len12.example.test')), direction='r')
    o.pkt('dns', ipprim(0x23, tlv(0x31, v4b), b'\x00'))                  # no data tag found
    o.pkt('noproto', ipprim(0x23, tlv(0x31, v4b + port(9)) + tlv(0x32, v4a), b'\x00\x01\x02'))

    # ---- SCTPPrim ----
    o.note('SCTPPrim heuristic: variant 1 and variant 3 (DataInd, SendDataReq)')
    def v1():
        return (bytes([0x01, 2, 0, 1, 0x0a, 2]) + port(53) + bytes([0x1e, 2, 0, 1, 0x0d, 2, 0, 0,
                0x09, 4]) + v4b + bytes([0x1d, 4, 0, 0, 0, 0, 0x0c, 4, 0, 0, 0, 0x2e, 0x19]) +
                dns_response('sctpprim.example.test'))
    b = v1()
    o.pkt('dns', bytes([0x04, len(b)]) + b)
    b = v1()
    o.pkt('dns', bytes([0x62, 0x81, len(b)]) + b, direction='r')
    b = v1()
    o.pkt('dns', bytes([0x62, 0x82, 0, len(b)]) + b, direction='r')
    q = dns_response('sctpprim.example.test')
    v3ind = (struct.pack('>HHHH', 0x6200, 0, 5, 53) + struct.pack('>HH', 0x0900, 8) + v4b +
             bytes(12) + struct.pack('>HH', 0x1900, len(q)) + q)
    o.pkt('dns', v3ind, direction='r')
    q = dns_response('sctpprim.example.test')
    v3ind6 = (struct.pack('>HHHH', 0x6200, 0, 5, 53) + struct.pack('>HH', 0x0900, 32) + v6b +
              bytes(12) + struct.pack('>HH', 0x1900, len(q)) + q)
    o.pkt('dns', v3ind6, direction='r')
    q = dns_response('sctpprim.example.test')
    v3req = (struct.pack('>HHHH', 0x0400, 0, 0x2400, 5) + struct.pack('>HH', 0x0900, 8) + v4b +
             struct.pack('>HH', 0x0a00, 53) + struct.pack('>HH', 0x0d00, 1) +
             struct.pack('>HH', 0x0c00, 8) + bytes(4) + struct.pack('>HH', 0x0b00, 4) + bytes(2) +
             struct.pack('>HH', 0x1900, len(q)) + q)
    o.pkt('dns', v3req)
    q = dns_response('sctpprim.example.test')
    v3req2 = (struct.pack('>HHHH', 0x0400, 0, 0x2400, 5) + struct.pack('>HH', 0x0c00, 8) +
              bytes(4) + struct.pack('>HH', 0x1900, len(q)) + q)
    o.pkt('dns', v3req2)
    # Shapes the heuristics reject (shown as unparsed data)
    o.pkt('dns', struct.pack('>HHHH', 0x6200, 0, 5, 53) + struct.pack('>HH', 0x0a00, 8) + bytes(16))
    o.pkt('dns', struct.pack('>HHHH', 0x6200, 0, 5, 53) + struct.pack('>HH', 0x0900, 10) + bytes(16))
    o.pkt('dns', struct.pack('>HHHH', 0x6200, 0, 5, 53) + struct.pack('>HH', 0x0900, 8) + bytes(8))
    o.pkt('dns', struct.pack('>HHHH', 0x6200, 0, 5, 53) + struct.pack('>HH', 0x0900, 8) + bytes(4) +
          bytes(12) + struct.pack('>HH', 0x1a00, 0) + bytes(4))
    o.pkt('dns', struct.pack('>HHHH', 0x0400, 0, 0x2500, 5) + bytes(8))
    o.pkt('dns', struct.pack('>HHHH', 0x0400, 0, 0x2400, 5) + struct.pack('>HH', 0x0900, 10) + bytes(16))
    o.pkt('dns', struct.pack('>HHHH', 0x0400, 0, 0x2400, 5) + struct.pack('>HH', 0x0e00, 2) + bytes(16))
    o.pkt('dns', struct.pack('>HHHH', 0x0400, 0, 0x2400, 5) + struct.pack('>HH', 0x0c00, 8) +
          bytes(4) + struct.pack('>HH', 0x1a00, 0) + bytes(4))
    o.pkt('dns', struct.pack('>HHHH', 0x0400, 0, 0x2400, 5) + struct.pack('>HH', 0x0d00, 1) +
          struct.pack('>HH', 0x0d00, 0))                        # ends before the payload type
    o.pkt('dns', bytes([0x04, 4, 0x01, 2, 0, 1]))               # variant 1 ends before data
    o.pkt('dns', struct.pack('>HHHH', 0x0500, 0, 0, 0))
    o.pkt('dns', bytes([0x04, 10, 0x55, 2, 0, 0, 0, 0, 0, 0, 0, 0]))

    # ---- protocol name lookups ----
    o.note('look_for_dissector() name mapping (payloads that are not primitives)')
    for name in ('s1ap', 'x2ap_r10', 'xnap_r1', 'ngap_r1', 'gtpv2_r9', 'diameter_s6a',
                 'tbcp', 'xcap_caps', 'soap', 'mm1', 'mm3', 'mm7', 'iuup_rtp_r5', 'sipt',
                 'nbap_sctp_r5', 'dhcpv4', 'wimax', 'sabp_r6', 'wtp', 'gtp_r99', 'fp_r6'):
        variant = '771' if name == 'fp_r6' else '1'     # 256*3+3: FP over UDP (IPPrim)
        outhdr = [12, 2, 0, 0, 1, 16, 1] if name == 'fp_r6' else None
        o.pkt(name, '0000', variant=variant, outhdr=outhdr)

    # ---- Comments ----
    o.note('comments: RACH preamble out-of-band LTE MAC event (SRs and >> ERR are in the malformed file)')
    o.comment('plain comment line')
    o.comment('>> RACH Preamble Request [CarrierId=0] [LTE UE = 3] [RAPID = 12] [Attempt = 1]')
    o.comment('>> Schedule Requests (2)  [CarrierId=0][UE=1][RNTI=101]')   # second entry missing
    o.comment('>> something else')
    o.note('comments: logged NR MAC PDUs, odd hex length and no $ (fix)')
    o.comment('NRMAC PDU: direction=1 rntiType=5 rnti=8495 ueid=1 SN=0  SFN=0 length=2 $3f00')
    o.comment('L1_App: NRMAC PDU: direction=1 rntiType=2 rnti=65534 ueid=1 SN=1  SFN=2 length=0 $')
    for rt in (3, 4, 9):
        o.comment('NRMAC PDU: direction=1 rntiType=%d rnti=%d ueid=1 SN=0  SFN=0 length=2 $3f00'
                  % (rt, 100 + rt))
    o.comment('NRMAC PDU: direction=1 rntiType=6 rnti=106 ueid=1 SN=0  SFN=0 length=1 $00')
    o.comment('NRMAC PDU: direction=1 rntiType=5 rnti=65535 ueid=1 SN=0  SFN=0 length=2 $3f00')
    o.comment('NRMAC PDU: direction=1 rntiType=5 rnti=8495 ueid=1 SN=0  SFN=0 length=2 $3f003')
    o.comment('NRMAC PDU: direction=1 rntiType=5 rnti=8495 ueid=1 SN=0  SFN=0 length=2 $3fZZ')
    o.comment('NRMAC PDU: direction=1 rntiType=2 rnti=65534 ueid=1 SN=0  SFN=0 length=0')
    o.note('comments: NRUP PDUs (padded, odd hex length)')
    o.comment('NRUP PDU: $1000000001')
    o.comment('NRUP PDU: $100000000123')
    o.comment('NRUP PDU: $10000000012')
    o.note('comments: NR PDCP key lines without "key: " (fix); lines with a key are in the '
           'malformed file')
    k = ' '.join(['30'] * 16)
    o.comment('NRPDCP: RRCPRIM:ueId=   2;setThreadAuthKey: RRC id=1 alg 2 KEY= ' + k)
    o.comment('NRPDCP: RRCPRIM:ueId=   2;setThreadAuthKey: UP id=1 alg 2 KEY= ' + k)
    o.comment('NRPDCP: RRCPRIM:ueId=   2;setThreadCryptKey: RRC id=1 alg 2 KEY= ' + k)
    o.comment('NRPDCP: RRCPRIM:ueId=   2;setThreadCryptKey: UP id=1 alg 2 KEY= ' + k)
    o.comment('NRPDCP: other;setThreadAuthKey: nothing')
    o.comment('NRPDCP: other;setThreadCryptKey: nothing')
    o.note('comments: RawTraffic Ethernet frames, odd hex length (fix)')
    frame = lambda: eth(ipv4(17, udp(1234, 53, dns_response('raw.example.test'))))
    o.comment('RawTraffic: Interface: 1 r $' + frame().hex())
    o.comment('RawTraffic: Interface: 2 s $' + frame().hex() + '0')
    o.sprint('sprint line from the test script')
    return o


def _rrc(op, chan, msg, extra, carrier=True, sm=None):
    if chan[0] == 'ue':
        body = bytes([0x12, 5]) + struct.pack('>H', chan[1]) + bytes([chan[2], 1, chan[3]])
    else:
        body = bytes([0x1a, 3]) + struct.pack('>HB', chan[1], chan[2]) + chan[3]
    if carrier:
        body += bytes([0x1e, 1, 0, 0x20, 1, 1, 0x22, 1, 0])
    if op == 0x07:
        body += b'\x00'                   # 1 byte MAC
    if sm is not None:
        body += sm
    body += extra
    if msg is not None:
        body += bytes([0xaa, len(msg)]) + msg
    return bytes([op, len(body)]) + body


# --------------------------------------------------------------------------
# Malformed .out


def build_malformed():
    o = Out()
    aal = '001002000008'
    dl_sync = fp_control(bytes([3, 0x10]))
    o.note('lines that store a PDCP key (LTE and NR RRC security params, NR key comments): '
           'clean, but packet-pdcp-lte.c and packet-pdcp-nr.c leak the key string')
    o.pkt('rrc_r10_lte', _rrc(0x05, ('ue', 4, 0, 1), LTE_UL_DCCH, b'', sm=sec_params()))
    o.pkt('rrc_r15_5g', _rrc(0x05, ('ue', 8, 0, 1), NR_UL_DCCH, b'', sm=sec_params()))
    o.pkt('rrc_r16_5g', _rrc(0x05, ('ue', 9, 0, 1), NR_UL_DCCH, b'', sm=sec_params(crypt=False)))
    k = ' '.join(['30'] * 16)
    o.comment('NRPDCP: RRCPRIM:ueId=   1;setThreadAuthKey: RRC id=1 alg 2 key: ' + k)
    o.comment('NRPDCP: RRCPRIM:ueId=   1;setThreadAuthKey: UP id=1 alg 2 key: ' + k)
    o.comment('NRPDCP: RRCPRIM:ueId=   1;setThreadCryptKey: RRC id=1 alg 2 key: ' + k)
    o.comment('NRPDCP: RRCPRIM:ueId=   1;setThreadCryptKey: UP id=1 alg 2 key: ' + k)
    o.note('fp_r9: unknown FP release (fix: expert info instead of an assert)')
    o.pkt('fp_r9', dl_sync, variant='1', outhdr=[12, 2, 0, 0, 1, 16, 1], aal=aal)
    o.note('FP data frame with huge counts (fix: bounded, the FP dissector throws)')
    o.pkt('fp_r6', fp_data(bytes([0x05, 0x01]), b'\xa5\x5a', True), variant='1',
          outhdr=[12, 2, 0, 4294967295, 4294967295] + [4294967295] * 8, aal=aal)
    o.note('FP with fewer than 5 outhdr values, fpiur_r5: no FP info (error)')
    o.pkt('fp_r6', dl_sync, variant='1', outhdr=[12, 2], aal=aal)
    o.pkt('fpiur_r5', fp_control(bytes([6]) + b'\x00\x10\x00'), variant='1', outhdr=[15, 1],
          aal=aal)
    o.note('MAC-NR C-RNTI comment without $ (fix): empty PDU, MAC-NR throws')
    o.comment('NRMAC PDU: direction=1 rntiType=5 rnti=8495 ueid=1 SN=0  SFN=0 length=0')
    o.note('RawTraffic comment without $: empty frame, Ethernet throws')
    o.comment('RawTraffic: Interface: 1 r')
    o.note('NRUP PDU comment without $ (fix)')
    o.comment('NRUP PDU: no payload here')
    o.note('Scheduling Requests and an SR failure (MAC-LTE error experts), >> ERR comment, CCPRI indication with an error status')
    o.comment('>> Schedule Requests (3)  [CarrierId=0][UE=1][RNTI=101] [UE=2][RNTI=102] [UE=3][RNTI=103]')
    o.comment('>> Schedule Requests (1)  [CarrierId=0][UE=5][RNTI=105]')
    o.comment('>> Schedule Requests (3)  [CarrierId=0][UE=6][RNTI=106] [UE=7][RNTI=107] [bad]')
    o.comment('>> INFO (inst 1) MAC:    [UE = 4]    SR failed (CRNTI=104)')
    o.comment('>> ERR something failed')
    o.pkt('ccpri_r8_lte', bytes([2, 0, 10, 0, 1, 5, 3, 2, 0, 2, 0x01, 0x3f]), direction='r')
    o.note('truncated primitives')
    o.pkt('rrc_r8_lte', bytes([0x00, 5, 0x12, 5, 0]))
    o.pkt('pdcp_r8_lte', bytes([0x60, 0x10]), outhdr=[0, 1, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    o.pkt('ccpri_r8_lte', bytes([1, 0]))
    o.pkt('nas_rrc_r8_lte', bytes([0x02]))
    o.pkt('nas_s1ap_r15_5gnr', bytes([0x00]))
    o.pkt('rlc', bytes([0xc0, 0x72]), outhdr=[1, 3])
    o.pkt('dns', bytes([0x23, 0x31, 16]) + bytes(4))
    o.pkt('dns', struct.pack('>HHHH', 0x0400, 0, 0x2400, 5) + struct.pack('>HH', 0x0c00, 8))
    o.pkt('rrc_r10_lte', bytes([0x05, 10, 0x12, 5, 0, 1, 0, 1, 1, 0x24, 8, 1]))
    return o


# --------------------------------------------------------------------------
# Exported PDU pcap (LINKTYPE_WIRESHARK_UPPER_PDU)


def exp_pdu_record(payload, name=b'dct2000'):
    tag = struct.pack('>HH', 12, len(name)) + name     # not padded
    return tag + struct.pack('>HH', 0, 0) + payload


def dct2000_stub(proto, data, encap, direction=0, variant=b'1', outhdr=b'', ts=b'0.0010',
                 ctx=b'ctx', port=1):
    return (ctx + b'\0' + bytes([port]) + ts + b'\0' + proto + b'\0' + variant + b'\0' +
            outhdr + b'\0' + bytes([direction, encap]) + data)


def write_pcap(path, records):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 252))
        for i, rec in enumerate(records):
            f.write(struct.pack('<IIII', 1793440800 + i, 0, len(rec), len(rec)))
            f.write(rec)


def build_exported():
    aal_fp = fp_control(bytes([3, 0x10]))
    recs = [
        # Clean: no DCT2000 pseudo-header available
        dct2000_stub(b'ppp', bytes.fromhex('ff03c021010100040000'), 4, direction=0),
        dct2000_stub(b'ppp', bytes.fromhex('ff03c021020100040000'), 4, direction=1),
        dct2000_stub(b'isdn_l2', bytes.fromhex('00017f'), 17),
        dct2000_stub(b'fp_r6', aal_fp, 14, outhdr=b'12,2,0,0,1,16,1'),
        dct2000_stub(b'ethernet', eth(ipv4(17, udp(1234, 53, dns_response('exp.example.test')))), 1),
        # Error expert infos / malformed
        dct2000_stub(b'ethernet', b'\x00\x01', 0x55),                      # unknown encap
        dct2000_stub(b'fp_r6', aal_fp, 14, variant=b'x1', outhdr=b'12,2,0,0,1,16,1'),
        dct2000_stub(b'comment', b'short timestamp', 0, ts=b'1.0'),
        b'ctx',                                                           # truncated stub
    ]
    return [exp_pdu_record(r) for r in recs]


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    m = build_main()
    m.write(os.path.join(outdir, 'catapult-dct2000-coverage.out'))
    bad = build_malformed()
    bad.write(os.path.join(outdir, 'catapult-dct2000-coverage-malformed.out'))
    write_pcap(os.path.join(outdir, 'catapult-dct2000-coverage-exported.pcap'), build_exported())
    for path, o in (('main', m), ('malformed', bad)):
        print('%s: %d frames' % (path, len(o.lines)))
        for frame, text in o.notes:
            print('  %4d  %s' % (frame, text))


if __name__ == '__main__':
    main()
