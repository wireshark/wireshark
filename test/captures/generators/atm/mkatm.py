#!/usr/bin/env python3
# Generates test/captures/atm_coverage.pcapng.gz, atm_coverage_sniffer.enc.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ATM dissector (packet-atm.c).

Every packet is built from scratch with struct; nothing comes from a real
network.

Usage: mkatm.py <output directory>

Writes:
  atm-coverage.pcapng          main capture, four interfaces:
                                 0 SunATM (LINKTYPE_SUNATM 123)
                                 1 ERF (LINKTYPE_ERF 197)
                                 2 Exported PDU (LINKTYPE_WIRESHARK_UPPER_PDU 252)
                                 3 Ethernet (L2TPv3 ATM pseudowire, MPLS ATM
                                   pseudowires)
  atm-coverage-sniffer.enc     DOS Sniffer (ngsniffer) ATM capture: raw cells
                               with HEC (AAL1, AAL3/4, OAM, user AAL), every
                               traffic type and subtype the format can carry,
                               AAL5 trailer data from the pseudo-header
  atm-coverage-malformed.pcapng  paths that end in an exception or an error
                               expert info
  atm-coverage-netxray.cap     Sniffer Pro (NetXRay 2.x) ATM capture with
                               "reassembly failed" PDUs (error expert info)
  atm-coverage-visual.vnf      Visual Networks ATM capture (AAL2 with the
                               4-octet AAL2 header, AAL1/AAL3/4 PDUs)

The MPLS frames need Decode As, see MPLS_LABELS below and the README.
"""

import os
import struct
import sys

# --------------------------------------------------------------------------
# Constants from wiretap/wtap.h

AAL_UNKNOWN, AAL_1, AAL_2, AAL_3_4, AAL_5, AAL_USER, AAL_SIGNALLING, AAL_OAMCELL = range(8)

# MPLS labels and the pseudowire dissector each one is decoded as
MPLS_LABELS = {
    100: 'mplspwatm11_or_aal5pdu',
    101: 'mplspwatmaal5sdu',
    102: 'mplspwatmn1cw',
}


def u8(v):  return struct.pack('>B', v)
def u16(v): return struct.pack('>H', v)
def u32(v): return struct.pack('>I', v)


# --------------------------------------------------------------------------
# Checksums

def _crc32_mpeg2(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) if crc & 0x80000000 else (crc << 1)
            crc &= 0xFFFFFFFF
    return crc


def aal5_pdu(payload, uu=0, cpi=0, good_crc=True, pad_to_cells=True, length=None, pad=None):
    """AAL5 CPCS-PDU: payload, padding, UU, CPI, length, CRC-32."""
    if pad is None:
        pad = (-(len(payload) + 8)) % 48 if pad_to_cells else 0
    body = payload + b'\0' * pad + u8(uu) + u8(cpi) + u16(len(payload) if length is None else length)
    crc = (~_crc32_mpeg2(body)) & 0xFFFFFFFF
    if not good_crc:
        crc ^= 0x5A5A5A5A
    return body + u32(crc)


_CRC10 = []
for _i in range(256):
    _a = _i << 2
    for _ in range(8):
        _a <<= 1
        if _a & 0x400:
            _a ^= 0x633
    _CRC10.append(_a & 0x3FF)


def crc10(data):
    acc = 0
    for b in data:
        acc = ((acc << 8) & 0x3FF) ^ _CRC10[(acc >> 2) & 0xFF] ^ b
    return acc


def with_crc10(cell46, top6=0, good=True):
    """46 octets + 6 bits + CRC-10 = a 48-octet cell payload whose CRC-10
    over all 48 octets is 0 (as the dissector checks)."""
    assert len(cell46) == 46
    for c in range(1024):
        tail = u16((top6 << 10) | c)
        if crc10(cell46 + tail) == 0:
            break
    else:
        raise ValueError('no crc10')
    if not good:
        c ^= 0x155
    return cell46 + u16((top6 << 10) | c)


def hec(hdr4):
    crc = 0
    for b in hdr4:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc ^ 0x55


def uni_header(vpi, vci, pt=0, clp=0, gfc=0):
    return bytes([(gfc << 4) | (vpi >> 4), ((vpi & 0xF) << 4) | (vci >> 12),
                  (vci >> 4) & 0xFF, ((vci & 0xF) << 4) | (pt << 1) | clp])


def cell(vpi, vci, payload48, pt=0, clp=0, gfc=0, hec_flip=0, with_hec=True):
    h = uni_header(vpi, vci, pt, clp, gfc)
    if with_hec:
        h5 = h + u8(hec(h))
        # flip bits of the 40-bit header to make HEC errors
        v = int.from_bytes(h5, 'big') ^ hec_flip
        h = v.to_bytes(5, 'big')
    assert len(payload48) == 48
    return h + payload48


def ip_checksum(hdr):
    if len(hdr) % 2:
        hdr += b'\0'
    s = sum(struct.unpack('>%dH' % (len(hdr) // 2), hdr))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ipv4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    bytes(src), bytes(dst))
    h = h[:10] + u16(ip_checksum(h)) + h[12:]
    return h + payload


def udp4(src, dst, sport, dport, data, ident=1):
    u = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    return ipv4(src, dst, 17, u, ident)


def ipv6_udp(sport, dport, data):
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    u = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    pseudo = src + dst + u32(len(u)) + b'\0\0\0' + u8(17)
    u = u[:6] + u16(ip_checksum(pseudo + u) or 0xFFFF) + u[8:]
    return struct.pack('>IHBB', 0x60000000, len(u), 17, 64) + src + dst + u


A = (10, 1, 0, 1)
B = (10, 1, 0, 2)


def ip_payload(n=1, data=b'atm coverage'):
    return udp4(A, B, 40000 + n, 9, data, n)   # UDP discard


SNAP_IP = bytes.fromhex('aaaa03000000') + u16(0x0800)
MAC1 = bytes.fromhex('020000000001')
MAC2 = bytes.fromhex('020000000002')


def eth_frame(payload, dst=MAC2, src=MAC1, ethertype=0x0800):
    return dst + src + u16(ethertype) + payload


# --------------------------------------------------------------------------
# SNMP (ILMI) BER

def ber(tag, content):
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    else:
        ln = bytes([0x82]) + u16(n)
    return bytes([tag]) + ln + content


def ilmi_pdu(pdu_tag, req_id, oid, value=b'\x05\x00'):
    vb = ber(0x30, ber(0x06, oid) + value)
    pdu = ber(pdu_tag, ber(0x02, bytes([req_id])) + ber(0x02, b'\0') + ber(0x02, b'\0') + ber(0x30, vb))
    return ber(0x30, ber(0x02, b'\0') + ber(0x04, b'ILMI') + pdu)


# atmfMySystemIdentifier-ish OID under the ATM Forum enterprise (1.3.6.1.4.1.353.2.1.1.0)
ILMI_OID = bytes.fromhex('2b06010401826102010100')


# --------------------------------------------------------------------------
# LANE LE Control

LE_OPS = {
    'CONFIGURE_REQUEST': 0x0001, 'CONFIGURE_RESPONSE': 0x0101,
    'JOIN_REQUEST': 0x0002, 'JOIN_RESPONSE': 0x0102,
    'READY_QUERY': 0x0003, 'READY_IND': 0x0103,
    'REGISTER_REQUEST': 0x0004, 'REGISTER_RESPONSE': 0x0104,
    'UNREGISTER_REQUEST': 0x0005, 'UNREGISTER_RESPONSE': 0x0105,
    'ARP_REQUEST': 0x0006, 'ARP_RESPONSE': 0x0106,
    'FLUSH_REQUEST': 0x0007, 'FLUSH_RESPONSE': 0x0107,
    'NARP_REQUEST': 0x0008, 'TOPOLOGY_REQUEST': 0x0009,
    'VERIFY_REQUEST': 0x000A, 'VERIFY_RESPONSE': 0x010A,
}

ATM_ADDR1 = bytes.fromhex('47000580ffe1000000f21a2b3c020000000001') + b'\x00'
ATM_ADDR2 = bytes.fromhex('47000580ffe1000000f21a2b3c020000000002') + b'\x00'
assert len(ATM_ADDR1) == 20


def lan_dest(tag, mac=MAC1, rd=0x1234):
    if tag == 1:
        return u16(1) + mac
    if tag == 2:
        return u16(2) + b'\0' * 4 + struct.pack('<H', rd)
    return u16(tag) + b'\0' * 6


def tlv(tlv_type, value):
    return u32(tlv_type) + u8(len(value)) + value


ATMF = 0x00A03E    # OUI_ATM_FORUM
ALL_TLVS = [(ATMF << 8) | i for i in list(range(0x01, 0x14)) + [0x2B, 0x2C, 0x2D]]


def le_control(opcode, status=0, trans=1, lecid=0, flags=0, body=b'', tlvs=b''):
    hdr = u16(0xFF00) + u8(1) + u8(1) + u16(opcode)
    if opcode in (0x0003, 0x0103):
        return hdr + b'\0' * 102      # READY frames are padded to 108
    return hdr + u16(status) + u32(trans) + u16(lecid) + u16(flags) + body + tlvs


def cfg_join_body(src_tag=1, dst_tag=0, lan_type=1, max_frame=1, num_tlvs=0, name=b'elan1', name_size=None):
    if name_size is None:
        name_size = len(name)
    return (lan_dest(src_tag, MAC1) + lan_dest(dst_tag, MAC2) + ATM_ADDR1 + u8(lan_type)
            + u8(max_frame) + u8(num_tlvs) + u8(name_size) + ATM_ADDR2
            + name[:32].ljust(32, b'\0'))


def reg_body(num_tlvs=0, src_tag=1, dst_tag=0):
    return (lan_dest(src_tag, MAC1) + lan_dest(dst_tag, MAC2) + ATM_ADDR1 + b'\0\0'
            + u8(num_tlvs) + b'\0' * 53)


def arp_body(num_tlvs=0, src_tag=1, dst_tag=1):
    return (lan_dest(src_tag, MAC1) + lan_dest(dst_tag, MAC2) + ATM_ADDR1 + b'\0\0'
            + u8(num_tlvs) + b'\0' + ATM_ADDR2 + b'\0' * 32)


def verify_body(num_tlvs=0):
    return b'\0' * 38 + u8(num_tlvs) + b'\0' + ATM_ADDR2 + b'\0' * 32


def flush_body(src_tag=0, dst_tag=1):
    return lan_dest(src_tag, MAC1) + lan_dest(dst_tag, MAC2) + ATM_ADDR1 + b'\0' * 4 + ATM_ADDR2 + b'\0' * 32


def all_tlvs():
    out = b''
    for i, t in enumerate(ALL_TLVS):
        out += tlv(t, u16(10 + i) if i % 3 else u32(1000 + i))
    out += tlv(0x00ABCDEF, b'\x01\x02\x03')     # unknown TLV type
    return out, len(ALL_TLVS) + 1


def le_control_frames():
    """(description, LE Control frame) for every opcode and option."""
    t, n = all_tlvs()
    fr = []
    fr.append(('LE_CONFIGURE_REQUEST', le_control(0x0001, flags=0x0002,
               body=cfg_join_body(1, 0, 1, 1, 0, b'', 0))))
    fr.append(('LE_CONFIGURE_RESPONSE all TLVs', le_control(0x0101, status=0, flags=0x0002,
               body=cfg_join_body(1, 2, 1, 2, n, b'engineering'), tlvs=t)))
    fr.append(('LE_CONFIGURE_RESPONSE long name', le_control(0x0101, status=20,
               body=cfg_join_body(2, 1, 2, 3, 0, b'N' * 32, 40))))
    fr.append(('LE_JOIN_REQUEST', le_control(0x0002, flags=0x0286, trans=2,
               body=cfg_join_body(1, 0, 0, 4, 1, b'elan1'), tlvs=tlv(ALL_TLVS[16], bytes(4)))))
    fr.append(('LE_JOIN_RESPONSE', le_control(0x0102, status=0, flags=0x028a, trans=2, lecid=5,
               body=cfg_join_body(1, 0, 1, 1, 0, b'elan1'))))
    for st in (1, 2, 4, 5, 6, 7, 8, 9, 10, 21, 22, 24, 99):
        fr.append(('LE_JOIN_RESPONSE status %d' % st, le_control(0x0102, status=st, trans=3,
                   body=cfg_join_body(5, 0, 7, 9, 0, b'x'))))
    fr.append(('READY_QUERY', le_control(0x0003)))
    fr.append(('READY_IND', le_control(0x0103)))
    fr.append(('LE_REGISTER_REQUEST', le_control(0x0004, trans=4, lecid=5,
               body=reg_body(1), tlvs=tlv(ALL_TLVS[16], bytes([10, 1, 0, 1])))))
    fr.append(('LE_REGISTER_RESPONSE', le_control(0x0104, trans=4, lecid=5, body=reg_body(0))))
    fr.append(('LE_UNREGISTER_REQUEST', le_control(0x0005, trans=5, lecid=5, body=reg_body(0, 2, 1))))
    fr.append(('LE_UNREGISTER_RESPONSE', le_control(0x0105, trans=5, lecid=5, body=reg_body(0))))
    fr.append(('LE_ARP_REQUEST', le_control(0x0006, flags=0x0001, trans=6, lecid=5,
               body=arp_body(1), tlvs=tlv(ALL_TLVS[19], ATM_ADDR1))))
    fr.append(('LE_ARP_RESPONSE', le_control(0x0106, trans=6, lecid=5, body=arp_body(0, 1, 2))))
    fr.append(('LE_NARP_REQUEST', le_control(0x0008, trans=7, lecid=5, body=arp_body(0, 0, 1))))
    fr.append(('LE_FLUSH_REQUEST', le_control(0x0007, trans=8, lecid=5, body=flush_body(0, 1))))
    fr.append(('LE_FLUSH_RESPONSE', le_control(0x0107, trans=8, lecid=5, body=flush_body(2, 1))))
    fr.append(('LE_TOPOLOGY_REQUEST', le_control(0x0009, flags=0x0100, trans=9, body=b'\0' * 92)))
    fr.append(('LE_VERIFY_REQUEST', le_control(0x000A, trans=10, lecid=5,
               body=verify_body(1), tlvs=tlv(ALL_TLVS[17], b'\0\0\0\1'))))
    fr.append(('LE_VERIFY_RESPONSE', le_control(0x010A, trans=10, lecid=5, body=verify_body(0))))
    fr.append(('unknown request opcode', le_control(0x00FE, trans=11, body=b'\0' * 92)))
    fr.append(('unknown response opcode', le_control(0x01FE, status=2, trans=11, body=b'\0' * 92)))
    return fr


def lane_data(payload, lecid=5):
    return u16(lecid) + payload


def tr_frame(payload):
    # 802.5: AC, FC, dst, src, then LLC SNAP
    return b'\x10\x40' + MAC2 + MAC1 + SNAP_IP + payload


# --------------------------------------------------------------------------
# SSCOP (signalling AAL) PDUs, trailer at the end

def sscop_bgn(nsq=1, nmr=100, uu=b''):
    pad = (-len(uu)) % 4
    return uu + b'\0' * pad + u32(nsq) + u8((pad << 6) | 0x01) + struct.pack('>I', nmr)[1:]


def sscop_poll(ns=5, nps=7):
    return u32(nps) + u8(0x0A) + struct.pack('>I', ns)[1:]


def sscop_end():
    return u8(0x03) + b'\0\0\0'


# --------------------------------------------------------------------------
# pcapng writer

class Pcapng:
    def __init__(self):
        self.out = bytearray()
        self.ifaces = []
        shb = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
        self._block(0x0A0D0D0A, shb)
        self.ts = 1700000000 * 1000000
        self.count = 0
        self.notes = []

    def _block(self, btype, body):
        body += b'\0' * ((-len(body)) % 4)
        total = 12 + len(body)
        self.out += struct.pack('<II', btype, total) + body + struct.pack('<I', total)

    def iface(self, linktype, snaplen=65535):
        self._block(0x00000001, struct.pack('<HHI', linktype, 0, snaplen))
        self.ifaces.append(linktype)
        return len(self.ifaces) - 1

    def packet(self, ifid, data, note=None, extra=0):
        self.ts += 1000
        self.count += 1
        if note:
            self.notes.append((self.count, note))
        body = struct.pack('<IIIII', ifid, self.ts >> 32, self.ts & 0xFFFFFFFF, len(data),
                           len(data) + extra) + data
        self._block(0x00000006, body)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(self.out)


def sunatm(flags, vpi, vci, payload, channel=0):
    """SunATM pseudo-header: flags (0x80 = DTE->DCE, low nibble = type), VPI, VCI."""
    return u8((0x80 if channel == 0 else 0) | flags) + u8(vpi) + u16(vci) + payload


def erf(rtype, payload, flags=0, sub=None, extra=0):
    """ERF record (no extension headers); 'sub' is the 4-octet MC/AAL2 header.
    'extra' octets of the PDU were not captured."""
    body = (u32(sub) if sub is not None else b'') + payload
    rlen = 16 + len(body)
    return (struct.pack('<Q', 0x5F5E10000000000)
            + struct.pack('>BBHHH', rtype, flags, rlen, 0, len(payload) + extra) + body)


def erf_atm_hdr(vpi, vci, pt=0, clp=0):
    return u32((vpi << 20) | (vci << 4) | (pt << 1) | clp)


def exp_pdu(tags, payload):
    out = b''
    for t, v in tags:
        out += struct.pack('>HH', t, len(v)) + v
    return out + struct.pack('>HH', 0, 0) + payload


def eth_ip(proto, payload, src=A, dst=B, smac=MAC1, dmac=MAC2, ident=1):
    return eth_frame(ipv4(src, dst, proto, payload, ident), dmac, smac)


def l2tpv3_avp(atype, value, mandatory=True):
    return u16((0x8000 if mandatory else 0) | (6 + len(value))) + u16(0) + u16(atype) + value


def l2tpv3_control(ccid, ns, nr, avps):
    length = 12 + len(avps)
    return u32(0) + u16(0xC803) + u16(length) + u32(ccid) + u16(ns) + u16(nr) + avps


def mpls(label, payload, ttl=64):
    return eth_frame(u32((label << 12) | (1 << 8) | ttl) + payload, ethertype=0x8847)


# --------------------------------------------------------------------------
# Cells

def oam_payload(oam_type, func, good=True, fill=0x6A):
    return with_crc10(bytes([(oam_type << 4) | func]) + bytes([fill]) * 45, good=good)


def aal1_payload(sn, data=0x11):
    csi = (sn >> 3) & 1
    seq = sn & 7
    # SNP: CRC-3 + parity, any value is shown as is
    return bytes([(csi << 7) | (seq << 4) | 0x05]) + bytes([data]) * 47


def aal34_payload(st, sn, mid, li=44, good=True):
    hdr = u16((st << 14) | (sn << 10) | mid)
    info = bytes(range(44))
    return with_crc10(hdr + info, top6=li, good=good)


# --------------------------------------------------------------------------
# Main capture

def build_main(outdir):
    p = Pcapng()
    SUN = p.iface(123)
    ERF = p.iface(197)
    EXP = p.iface(252)
    ETH = p.iface(1)

    # ---- SunATM: LANE LE Control, every opcode, both directions ----------
    for i, (desc, f) in enumerate(le_control_frames()):
        p.packet(SUN, sunatm(0x01, 0, 32 + (i % 3), f, channel=i % 2), 'SunATM LANE ' + desc)
    # LANE 802.3 data (pseudo-header says LANE, data is not FF00)
    p.packet(SUN, sunatm(0x01, 0, 40, lane_data(eth_frame(ip_payload(2)))), 'SunATM LANE 802.3')
    # LLC multiplexed
    p.packet(SUN, sunatm(0x02, 1, 100, SNAP_IP + ip_payload(3)), 'SunATM LLC/SNAP IPv4')
    # ILMI get-request and get-response
    p.packet(SUN, sunatm(0x05, 0, 16, ilmi_pdu(0xA0, 1, ILMI_OID)), 'SunATM ILMI GetRequest')
    p.packet(SUN, sunatm(0x05, 0, 16, ilmi_pdu(0xA2, 1, ILMI_OID, ber(0x04, b'switch1')), channel=1),
             'SunATM ILMI GetResponse')
    # Q.2931 signalling over SSCOP, and an unknown type on VPI 0 VCI 5
    p.packet(SUN, sunatm(0x06, 0, 5, sscop_bgn()), 'SunATM signalling SSCOP BGN')
    p.packet(SUN, sunatm(0x00, 0, 5, sscop_poll(), channel=1), 'SunATM VPI 0 VCI 5 SSCOP POLL')
    # AAL5 with unknown traffic type (MARS 0x03, IFMP 0x04, raw 0x00):
    # the heuristics in dissect_reassembled_pdu()
    heur = [
        ('PPP', b'\x00\x21' + ip_payload(4)),
        ('VC-mux bridged Ethernet', b'\x00\x00' + eth_frame(ip_payload(5))),
        ('FR 2-octet header, NLPID IPv4', b'\x18\x41\x03\xcc' + ip_payload(6)),
        ('FR 2-octet header, NLPID IPv6', b'\x18\x41\x03\x8e' + ipv6_udp(1, 9, b'v6 over fr')),
        ('FR 2-octet header, SNAP', b'\x18\x41\x03\x00\x80\x00\x00\x00\x08\x00' + ip_payload(7)),
        ('FR 4-octet header, NLPID IPv4', b'\x18\x40\x00\x01\x03\xcc' + ip_payload(8)),
        ('FR 4-octet header, NLPID IPv6', b'\x18\x40\x00\x01\x03\x8e' + ipv6_udp(2, 9, b'v6 over fr')),
        ('FR 4-octet header, SNAP', b'\x18\x40\x00\x01\x03\x00\x80\x00\x00\x00\x08\x00' + ip_payload(9)),
        ('IPv4', ip_payload(10)),
        ('IPv6', ipv6_udp(3, 9, b'raw v6')),
        ('no match', bytes(range(0x81, 0x99))),
        ('FR-like but no NLPID match', b'\x18\x41\x03\x77\x03\x55\x00\x00' + bytes(8)),
        ('7 octets', b'\x12\x34\x56\x78\x9a\xbc\xde'),
        ('AA but not SNAP', b'\xaa\x00\x03' + bytes(13)),
        ('AA AA but not SNAP', b'\xaa\xaa\x00' + bytes(13)),
        ('FR 2-octet header, NLPID 0 but not SNAP', b'\x18\x41\x03\x00\x81' + bytes(11)),
        ('FR 4-octet header, NLPID 0 but not SNAP', b'\x18\x40\x00\x01\x03\x00\x81' + bytes(9)),
    ]
    for i, (desc, data) in enumerate(heur):
        p.packet(SUN, sunatm((0x03, 0x04, 0x00)[i % 3], 2, 200 + i, data, channel=i % 2),
                 'SunATM AAL5 unknown type: ' + desc)

    # ---- ERF: untruncated AAL5 PDUs with trailer -------------------------
    def erf_aal5(vpi, vci, pdu, flags=0, note=None, rtype=4, sub=None):
        p.packet(ERF, erf(rtype, erf_atm_hdr(vpi, vci) + pdu, flags, sub), note)

    erf_aal5(1, 100, aal5_pdu(SNAP_IP + ip_payload(20)), note='ERF AAL5 LLC/SNAP, trailer, padding, good CRC')
    erf_aal5(1, 100, aal5_pdu(SNAP_IP + ip_payload(21), good_crc=False), 1, note='ERF AAL5 LLC/SNAP, bad CRC')
    payload88 = SNAP_IP + ip_payload(22, b'x' * (88 - 8 - 28))
    assert len(payload88) == 88
    erf_aal5(1, 100, aal5_pdu(payload88, uu=0x12, cpi=0), 2,
             note='ERF AAL5 two cells, no padding')
    erf_aal5(1, 100, SNAP_IP + ip_payload(23) + b'\0' * 4 + u32(0),
             note='ERF AAL5 trailer length 0 (no trailer)')
    erf_aal5(1, 100, SNAP_IP + ip_payload(24) + u16(0) + u16(1000) + u32(0), 3,
             note='ERF AAL5 trailer length too large')
    erf_aal5(1, 100, aal5_pdu(SNAP_IP + ip_payload(25), pad=60, pad_to_cells=False),
             note='ERF AAL5 more than 47 octets of padding')
    # LANE (guessed from the contents), LE Control and 802.3, with trailer
    erf_aal5(1, 32, aal5_pdu(le_control_frames()[4][1]), note='ERF AAL5 LANE LE_JOIN_RESPONSE')
    erf_aal5(1, 40, aal5_pdu(lane_data(eth_frame(ip_payload(26)))), 1, note='ERF AAL5 LANE 802.3')
    erf_aal5(0, 16, aal5_pdu(ilmi_pdu(0xA1, 2, ILMI_OID)), note='ERF AAL5 ILMI GetNextRequest')
    erf_aal5(0, 5, aal5_pdu(sscop_bgn(uu=b'\x09\x03\x80\x00\x00')), note='ERF AAL5 signalling SSCOP BGN')
    # The branch's AAL5 trailer fix: PDUs shorter than the 8-octet trailer.
    # They are guessed as signalling (less than 16 octets) and go to SSCOP.
    erf_aal5(1, 100, b'\x11\x22\x33' + sscop_end(), note='ERF AAL5 7-octet PDU (short trailer reproducer)')
    erf_aal5(1, 100, sscop_end(), note='ERF AAL5 4-octet PDU (short trailer reproducer)')
    # MC AAL5
    erf_aal5(1, 101, aal5_pdu(SNAP_IP + ip_payload(27)), note='ERF MC AAL5', rtype=9, sub=0x00000001)
    # Cut short by the snapshot length: no trailer to look at
    cut = aal5_pdu(SNAP_IP + ip_payload(28, b'y' * 40))
    p.packet(ERF, erf(4, erf_atm_hdr(1, 100) + cut[:44], extra=len(cut) - 44), 'ERF AAL5 cut short by the snapshot length',
             extra=len(cut) - 44)
    # AAL2 (CID in the AAL2 / MC header)
    erf_aal5(1, 300, b'\x07\x08\x09\x0a' * 5, note='ERF AAL2 CID 9', rtype=18, sub=0x09000000)
    erf_aal5(1, 301, b'\x01\x02\x03\x04' * 5, 1, note='ERF MC AAL2 CID 42', rtype=12, sub=0x2A000000)

    # ---- ERF: raw cells (no HEC) ------------------------------------------
    def erf_cell(vpi, vci, pt, payload48, flags=0, note=None, rtype=3, sub=None):
        p.packet(ERF, erf(rtype, erf_atm_hdr(vpi, vci, pt) + payload48, flags, sub), note)

    for ft in (0, 1, 4, 8, 15):
        erf_cell(1, 100, 4, oam_payload(1, ft), note='ERF cell OAM F5 segment FM type %d' % ft)
    for ft in (0, 1, 2, 9):
        erf_cell(1, 100, 5, oam_payload(2, ft), 1, note='ERF cell OAM F5 end-to-end PM type %d' % ft)
    for ft in (0, 1, 3):
        erf_cell(1, 100, 4, oam_payload(8, ft), note='ERF cell OAM activation/deactivation type %d' % ft)
    erf_cell(1, 100, 5, oam_payload(15, 3), note='ERF cell OAM unknown type')
    erf_cell(1, 3, 0, oam_payload(1, 8), 2, note='ERF cell OAM F4 segment (VCI 3)')
    erf_cell(1, 4, 2, oam_payload(1, 4), 3, note='ERF cell OAM F4 end-to-end (VCI 4, PT 2)')
    erf_cell(1, 100, 4, oam_payload(1, 0, good=False), note='ERF cell OAM bad CRC-10')
    erf_cell(1, 100, 0, bytes(range(48)), note='ERF cell user data')
    erf_cell(1, 3, 1, bytes(range(48)), note='ERF cell VCI 3 PT 1 (not OAM)')
    erf_cell(1, 100, 6, bytes(48), note='ERF cell resource management (PT 6)')
    erf_cell(1, 100, 4, oam_payload(1, 1), note='ERF MC ATM cell OAM', rtype=7, sub=0x00010001)

    # ---- Exported PDU: the ATM handles without a pseudo-header ------------
    lane_payload = b'\xff\x00' + bytes(range(0x40))
    p.packet(EXP, exp_pdu([(14, b'atm.aal5.type'), (32, u32(3))], lane_payload),
             'Exported PDU atm.aal5.type 3 (LANE), no pseudo-header (reproducer)')
    for name in (b'atm_untruncated', b'atm_truncated', b'atm_pw_untruncated', b'atm_pw_truncated',
                 b'atm_pw_oam_cell'):
        p.packet(EXP, exp_pdu([(12, name)], lane_payload),
                 'Exported PDU %s, no pseudo-header (reproducer)' % name.decode())
    p.packet(EXP, exp_pdu([(14, b'atm.aal5.type'), (32, u32(4))], ilmi_pdu(0xA0, 3, ILMI_OID)),
             'Exported PDU atm.aal5.type 4 (ILMI)')
    p.packet(EXP, exp_pdu([(12, b'atm_oam_cell')], cell(0, 3, oam_payload(1, 0))),
             'Exported PDU atm_oam_cell')

    # ---- L2TPv3 over IP: ATM pseudowire, OAM cell and AAL5 SDU -----------
    C = (10, 2, 0, 1)
    D = (10, 2, 0, 2)
    MAC3 = bytes.fromhex('020000000003')
    MAC4 = bytes.fromhex('020000000004')
    sccrq = l2tpv3_control(0, 0, 0, l2tpv3_avp(0, u16(1)) + l2tpv3_avp(61, u32(0x11111111)))
    p.packet(ETH, eth_ip(115, sccrq, C, D, MAC3, MAC4, 1), 'L2TPv3 SCCRQ')
    icrq = l2tpv3_control(0x22222222, 1, 1, l2tpv3_avp(0, u16(10)) + l2tpv3_avp(63, u32(0x1000))
                          + l2tpv3_avp(68, u16(0x0002)) + l2tpv3_avp(69, u16(2)))
    p.packet(ETH, eth_ip(115, icrq, C, D, MAC3, MAC4, 2), 'L2TPv3 ICRQ, PW type AAL5, ATM sublayer')
    oam = u32(0x1000) + bytes([0x08, 0, 0, 1]) + cell(2, 50, oam_payload(1, 8), pt=5)
    p.packet(ETH, eth_ip(115, oam, D, C, MAC4, MAC3, 3), 'L2TPv3 ATM OAM cell')
    sdu = u32(0x1000) + bytes([0x00, 0, 0, 2]) + SNAP_IP + ip_payload(30)
    p.packet(ETH, eth_ip(115, sdu, D, C, MAC4, MAC3, 4), 'L2TPv3 ATM AAL5 SDU')

    # ---- MPLS ATM pseudowires (Decode As, see MPLS_LABELS) ----------------
    pdu = aal5_pdu(SNAP_IP + ip_payload(31))
    p.packet(ETH, mpls(100, bytes([0, 0, 0, 0x80]) + pdu), 'MPLS PW ATM AAL5 PDU mode')
    pdu2 = aal5_pdu(SNAP_IP + ip_payload(32), good_crc=False)
    p.packet(ETH, mpls(100, bytes([0, 0, 0, 0x80]) + pdu2), 'MPLS PW ATM AAL5 PDU mode, bad CRC')
    p.packet(ETH, mpls(101, bytes([0, 0, 0, 0]) + SNAP_IP + ip_payload(33)), 'MPLS PW ATM AAL5 SDU mode')
    p.packet(ETH, mpls(101, bytes([0x08, 0, 0, 0]) + uni_header(3, 60, 4) + oam_payload(1, 1)),
             'MPLS PW ATM AAL5 SDU mode, OAM admin cell')
    p.packet(ETH, mpls(102, bytes([0, 0, 0, 0]) + uni_header(3, 61, 5) + oam_payload(2, 0)),
             'MPLS PW ATM N:1 with CW, OAM cell')
    p.packet(ETH, mpls(102, bytes([0, 0, 0, 0]) + uni_header(3, 4, 0) + oam_payload(8, 1)
                       + uni_header(3, 62, 4) + oam_payload(1, 4)),
             'MPLS PW ATM N:1 with CW, two OAM cells (F4, F5)')

    p.write(os.path.join(outdir, 'atm-coverage.pcapng'))
    return p


# --------------------------------------------------------------------------
# DOS Sniffer (ngsniffer) ATM capture

class Sniffer:
    def __init__(self):
        self.out = bytearray(b'TRSNIFF data    \x1a')
        # version record: maj 4, min 0, time, date, type 4, network 10 (ATM),
        # format 1 (uncompressed), timeunit 1, no compression
        dosdate = ((2024 - 1980) << 9) | (1 << 5) | 1
        vers = struct.pack('<hhhhbBbBbbhh', 4, 0, 0, dosdate, 4, 10, 1, 1, 0, 0, 0, 0)
        self.out += struct.pack('<HHH', 1, len(vers), 0) + vers
        self.t = 0
        self.count = 0
        self.notes = []

    def frame(self, data, aal_type, hl=0, apphl=0, vpi=0, vci=0, channel=0, cells=0,
              raw=False, u2u=0, t_len=0, chksum=0, note=None):
        self.t += 100000
        self.count += 1
        if note:
            self.notes.append((self.count, note))
        status = 0x100 if raw else 0
        atm = struct.pack('<IHHIBBHHHHHII', status, u2u, t_len, 0, aal_type | hl, apphl, 0,
                          vpi, vci, channel, cells, 0, 0)
        atm = atm[:8] + struct.pack('>I', chksum) + atm[12:]
        f4 = struct.pack('<HHBBhbbhhh', self.t & 0xFFFF, (self.t >> 16) & 0xFFFF, (self.t >> 32) & 0xFF,
                         0, len(data), 0, 0, len(data), 0, 0) + atm
        assert len(f4) == 16 + 32, len(f4)
        rec = f4 + data
        self.out += struct.pack('<HHH', 8, len(rec), 0) + rec

    def write(self, path):
        self.out += struct.pack('<HHH', 3, 0, 0)
        with open(path, 'wb') as f:
            f.write(self.out)


ATT_AAL_UNKNOWN, ATT_AAL1, ATT_AAL3_4, ATT_AAL5, ATT_AAL_USER, ATT_AAL_SIGNALLING, ATT_OAMCELL = range(7)
ATT_HL = {'unknown': 0x00, 'llcmx': 0x10, 'vcmx': 0x20, 'lane': 0x30, 'ilmi': 0x40,
          'fr': 0x50, 'spans': 0x60, 'ipsilon': 0x70, 'other': 0x80}


def build_sniffer(outdir):
    s = Sniffer()
    # AAL1 cells: HEC correct, single-bit errors, an uncorrectable error
    for sn in range(8):
        s.frame(cell(1, 70, aal1_payload(sn)), ATT_AAL1, vpi=1, vci=70, raw=True, channel=sn % 2,
                note='AAL1 cell SN %d' % sn)
    for bit in (0, 7, 8, 20, 31, 32, 39):
        s.frame(cell(1, 70, aal1_payload(bit & 7), hec_flip=1 << bit), ATT_AAL1, vpi=1, vci=70, raw=True,
                note='AAL1 cell, HEC error in one bit (%d)' % bit)
    s.frame(cell(1, 70, aal1_payload(0), hec_flip=0x0300000000), ATT_AAL1, vpi=1, vci=70, raw=True,
            note='AAL1 cell, uncorrectable HEC error')
    s.frame(cell(1, 70, aal1_payload(1), gfc=5, clp=1), ATT_AAL1, vpi=1, vci=70, raw=True,
            note='AAL1 cell, GFC 5, CLP 1')
    # AAL3/4 cells: BOM, COM, EOM, SSM; good and bad CRC-10
    for i, st in enumerate((2, 0, 0, 1, 3)):
        s.frame(cell(1, 80, aal34_payload(st, i, 17, 44 if st in (2, 0) else 20)), ATT_AAL3_4,
                vpi=1, vci=80, raw=True, note='AAL3/4 cell ST %d' % st)
    s.frame(cell(1, 80, aal34_payload(3, 9, 18, 30, good=False)), ATT_AAL3_4, vpi=1, vci=80, raw=True,
            note='AAL3/4 cell bad CRC-10')
    # OAM cells: user AAL on F4/F5, unknown AAL, explicit OAM AAL
    s.frame(cell(1, 3, oam_payload(1, 0)), ATT_AAL_USER, vpi=1, vci=3, raw=True, note='User AAL F4 OAM cell')
    s.frame(cell(1, 90, oam_payload(1, 1), pt=5), ATT_AAL_UNKNOWN, vpi=1, vci=90, raw=True,
            note='Unknown AAL F5 OAM cell')
    s.frame(cell(1, 90, bytes(range(48))), ATT_AAL_USER, vpi=1, vci=90, raw=True, note='User AAL data cell')
    s.frame(cell(1, 90, oam_payload(2, 2)), ATT_OAMCELL, vpi=1, vci=90, raw=True, note='OAM AAL cell')
    s.frame(cell(1, 90, bytes(48)), ATT_AAL5, hl=ATT_HL['llcmx'], vpi=1, vci=90, raw=True,
            note='AAL5 single cell')
    s.frame(cell(1, 90, bytes(48)), ATT_AAL_SIGNALLING, vpi=1, vci=90, raw=True, note='Signalling AAL cell')

    # AAL5 PDUs (truncated encapsulation: no trailer in the data)
    def pdu(data, hl, apphl=0, note=None, **kw):
        s.frame(data, ATT_AAL5, hl=ATT_HL[hl], apphl=apphl, note=note, **kw)

    pdu(SNAP_IP + ip_payload(40), 'llcmx', vpi=1, vci=100, cells=2, u2u=0x0102, t_len=36, chksum=0xDEADBEEF,
        note='AAL5 LLC/SNAP, trailer from the pseudo-header')
    pdu(SNAP_IP + ip_payload(41), 'llcmx', vpi=1, vci=100, channel=1, note='AAL5 LLC/SNAP, no cell count')
    for sub in (0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 14, 15):
        data = b'\0\0' + eth_frame(ip_payload(50 + sub)) if sub in (1, 7) else bytes(range(20))
        pdu(data, 'vcmx', sub, vpi=1, vci=110 + sub, channel=2, note='AAL5 VC multiplexed subtype %d' % sub)
    for sub, data in ((2, lane_data(eth_frame(ip_payload(70)))),
                      (3, lane_data(tr_frame(ip_payload(71)))),
                      (4, lane_data(eth_frame(ip_payload(72), dst=bytes.fromhex('01005e000001')))),
                      (5, lane_data(tr_frame(ip_payload(73)))),
                      (0, lane_data(bytes(range(30)))),
                      (9, lane_data(bytes(range(30)))),
                      (1, le_control(0x0103))):
        pdu(data, 'lane', sub, vpi=0, vci=40 + sub, note='AAL5 LANE subtype %d' % sub)
    pdu(ilmi_pdu(0xA3, 4, ILMI_OID, ber(0x02, b'\x05')), 'ilmi', vpi=0, vci=16, note='AAL5 ILMI SetRequest')
    pdu(b'\x18\x41\x03\xcc' + ip_payload(74), 'fr', vpi=1, vci=120, note='AAL5 Frame Relay')
    pdu(bytes(range(24)), 'spans', vpi=1, vci=121, note='AAL5 FORE SPANS')
    for sub in (0, 1, 2, 3, 7):
        pdu(ip_payload(75 + sub), 'ipsilon', sub, vpi=1, vci=130 + sub, note='AAL5 Ipsilon subtype %d' % sub)
    pdu(ip_payload(80), 'unknown', vpi=1, vci=140, note='AAL5 unknown type, IPv4')
    pdu(ip_payload(81), 'other', vpi=1, vci=141, note='AAL5 undefined higher-layer type')
    # other AALs as PDUs
    s.frame(sscop_poll(), ATT_AAL_SIGNALLING, vpi=0, vci=5, note='Signalling AAL SSCOP POLL')
    s.frame(sscop_poll(), ATT_AAL_UNKNOWN, vpi=0, vci=5, note='Unknown AAL on VPI 0 VCI 5 (signalling)')
    s.frame(bytes(range(47)), ATT_AAL1, vpi=1, vci=70, note='AAL1 PDU (not a raw cell)')
    s.frame(bytes(range(44)), ATT_AAL3_4, vpi=1, vci=80, note='AAL3/4 PDU (not a raw cell)')
    s.frame(bytes(range(40)), ATT_AAL_UNKNOWN, vpi=1, vci=150, note='Unknown AAL PDU')
    s.frame(bytes(range(40)), ATT_AAL_USER, vpi=1, vci=151, note='User AAL PDU')
    s.frame(bytes(range(48)), 9, vpi=1, vci=152, note='Undefined AAL code')
    s.write(os.path.join(outdir, 'atm-coverage-sniffer.enc'))
    return s


# --------------------------------------------------------------------------
# Visual Networks ATM capture

def build_visual(outdir):
    recs = []
    notes = []

    def rec(category, vpi, vci, data, cells=1, info=0, note=''):
        atm = struct.pack('>HHBBHIII', vpi, vci, info, category, cells, len(data), 0, 0)
        recs.append((atm, data))
        notes.append(note)

    rec(0x02, 1, 300, b'\x09\x00\x00\x00' + bytes(range(20)), note='AAL2 with AAL2 header')
    rec(0x01, 1, 70, bytes(range(47)), note='AAL1 PDU')
    rec(0x03, 1, 80, bytes(range(44)), info=1, note='AAL3/4 PDU')
    rec(0x05, 1, 100, SNAP_IP + ip_payload(90), note='AAL5 LLC/SNAP')
    rec(0x0A, 1, 100, oam_payload(1, 0), note='OAM')
    rec(0x00, 1, 160, bytes(16), note='unknown category')
    body = b''
    offsets = []
    off = 192
    for i, (atm, data) in enumerate(recs):
        hdr = struct.pack('<IHHIBB6s', i * 10, len(data), len(atm) + len(data), 0, 0, 0, b'')
        offsets.append(off)
        body += hdr + atm + data
        off += len(hdr) + len(atm) + len(data)
    fhdr = struct.pack('<4sIIHHHHIH102s64s', b'\x05VNF', len(recs), 1700000000, 37, 65535, 1, 1,
                       155520000, 0, b'', b'atm coverage')
    assert len(fhdr) == 192, len(fhdr)
    index = b''.join(struct.pack('<I', o) for o in offsets)
    with open(os.path.join(outdir, 'atm-coverage-visual.vnf'), 'wb') as f:
        f.write(fhdr + body + index)
    return notes


# --------------------------------------------------------------------------
# NetXRay 2.x ATM capture with reassembly errors

def build_netxray(outdir):
    recs = b''
    n = 0

    def rec(data, x0, err=False, raw=False, vpi=1, vci=100, channel=0):
        nonlocal recs, n
        xxx = bytearray(28)
        xxx[0] = x0
        xxx[8] = 0x01 if err else 0
        xxx[9] = 0x04 if raw else 0
        xxx[11] = vpi
        xxx[12:14] = struct.pack('<H', vci)
        xxx[15] = 0x10 if channel else 0
        recs += struct.pack('<IIHH', n * 1000, 0, len(data), len(data)) + bytes(xxx) + data
        n += 1

    rec(SNAP_IP + ip_payload(100), 0x50, err=True)
    rec(aal5_pdu(SNAP_IP + ip_payload(101)), 0x50, err=True, channel=1)
    rec(aal5_pdu(SNAP_IP + ip_payload(102)), 0x50)
    rec(aal5_pdu(sscop_poll()), 0x51, vpi=0, vci=5)
    rec(aal5_pdu(sscop_poll()), 0x51, err=True, vpi=0, vci=5)
    rec(cell(1, 3, oam_payload(1, 0)), 0x00, raw=True, err=True)
    hdr = bytearray(128)
    hdr[0:4] = b'XCP\0'
    hdr[4:12] = b'002.002\0'
    struct.pack_into('<IIIII', hdr, 12, 1700000000, n, 0, 128, 128 + len(recs))
    hdr[44] = 8           # network type 9 (ATM) - 1
    hdr[45] = 0
    hdr[48] = 0           # timeunit
    hdr[84] = 15          # CAPTYPE_ATM
    with open(os.path.join(outdir, 'atm-coverage-netxray.cap'), 'wb') as f:
        f.write(bytes(hdr) + recs)


# --------------------------------------------------------------------------
# Malformed capture

def build_malformed(outdir):
    p = Pcapng()
    SUN = p.iface(123)
    ERF = p.iface(197)
    ETH = p.iface(1)
    t, n = all_tlvs()
    # LE Control frames cut short at each stage
    full = le_control(0x0101, flags=2, body=cfg_join_body(1, 2, 1, 1, n, b'elan'), tlvs=t)
    for cut in (3, 5, 7, 12, 18, 30, 60, 100, 110, 140):
        p.packet(SUN, sunatm(0x01, 0, 32, full[:cut]), 'LE_CONFIGURE_RESPONSE cut at %d' % cut)
    for op, body in ((0x0004, reg_body(3)), (0x0006, arp_body(3)), (0x000A, verify_body(3)),
                     (0x0007, flush_body()[:40]), (0x0009, b'\0' * 20)):
        p.packet(SUN, sunatm(0x01, 0, 33, le_control(op, body=body)), 'LE Control 0x%04x short' % op)
    p.packet(SUN, sunatm(0x01, 0, 32, le_control(0x0003)[:4]), 'READY_QUERY short')
    p.packet(SUN, sunatm(0x01, 0, 34, b'\x00'), 'LANE 802.3 one octet')
    # ILMI garbage
    p.packet(SUN, sunatm(0x05, 0, 16, b'\x30\x82\xff\xff\x02'), 'ILMI bad BER')
    # Short cells
    p.packet(ERF, erf(3, erf_atm_hdr(1, 100, 4) + b'\x10\x00'), 'ERF OAM cell too short')
    p.packet(ERF, erf(3, erf_atm_hdr(1, 100, 0)[:3]), 'ERF cell header too short')
    p.packet(ERF, erf(4, erf_atm_hdr(1, 100) + b'\x42'), 'ERF AAL5 1 octet')
    p.packet(ERF, erf(4, erf_atm_hdr(1, 100) + b'\x00\x05\x11\x22\x33\x44'), 'ERF AAL5 6 octets')
    p.packet(ERF, erf(4, erf_atm_hdr(1, 100) + b'\x00\x01\x99'), 'ERF AAL5 3 octets')
    # MPLS PW AAL5 SDU admin cell mode with two OAM cells (second does not
    # fill the columns) and an N:1 cell cut short
    p.packet(ETH, mpls(101, bytes([0x08, 0, 0, 0]) + uni_header(3, 60, 4) + oam_payload(1, 1)
                       + uni_header(3, 60, 4) + oam_payload(1, 0)),
             'MPLS PW AAL5 SDU two admin cells')
    p.packet(ETH, mpls(102, bytes([0, 0, 0, 0]) + uni_header(3, 61, 5) + oam_payload(2, 0)[:20]),
             'MPLS PW N:1 short OAM cell')
    p.packet(ETH, mpls(100, bytes([0, 0, 0, 0x80]) + aal5_pdu(SNAP_IP + ip_payload(110))[:30]),
             'MPLS PW AAL5 PDU short')
    p.write(os.path.join(outdir, 'atm-coverage-malformed.pcapng'))
    return p


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    m = build_main(outdir)
    s = build_sniffer(outdir)
    build_visual(outdir)
    build_netxray(outdir)
    mal = build_malformed(outdir)
    if os.environ.get('MKATM_NOTES'):
        for name, obj in (('main', m), ('sniffer', s), ('malformed', mal)):
            for num, note in obj.notes:
                print('%s %3d %s' % (name, num, note))


if __name__ == '__main__':
    main()
