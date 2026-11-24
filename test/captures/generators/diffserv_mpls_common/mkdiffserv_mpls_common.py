#!/usr/bin/env python3
# Generates test/captures/diffserv_mpls_common_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Diff-Serv MPLS helper
(packet-diffserv-mpls-common.c, RFC 3270 and RFC 3140).

The helper has no protocol of its own: RSVP (DIFFSERV object, class 65)
and LDP (Diff-Serv TLV 0x0901) call dissect_diffserv_mpls_common() for
every E-LSP MAP entry (EXP and PHBID) and for the L-LSP PSC. Both
callers are reached by default: RSVP as IP protocol 46, LDP on TCP port
646. Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mkdiffserv_mpls_common.py <output directory>

Writes:
  diffserv-mpls-common-coverage.pcap            RSVP Path messages with
                                                E-LSP and L-LSP DIFFSERV
                                                objects, LDP Label
                                                Mapping messages with
                                                E-LSP and L-LSP Diff-Serv
                                                TLVs; PHBIDs of both RFC
                                                3140 forms, bit 14 set
                                                and clear
  diffserv-mpls-common-coverage-malformed.pcap  E-LSP MAP counts past
                                                the end of the object or
                                                TLV, a cut PSC
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
V4_A = bytes([192, 0, 2, 1])
V4_B = bytes([192, 0, 2, 2])
V4_C = bytes([198, 51, 100, 7])


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, l4, src=V4_A, dst=V4_B, smac=MAC_A, dmac=MAC_B):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 1, 0x4000, 64,
                     proto, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return dmac + smac + b'\x08\x00' + ip + l4


# PHBID values (RFC 3140)
def phb_dscp(dscp, bit14=0):
    """Case 1: DSCP in the top six bits, bit 15 clear."""
    return (dscp << 10) | (bit14 << 1)


def phb_code(code, bit14=0):
    """Case 2: 12 bit PHB id code, bit 15 set."""
    return (code << 4) | (bit14 << 1) | 1


# E-LSP MAP list: (EXP, PHBID), covering both PHBID forms and bit 14
E_MAPS = [
    (0, phb_dscp(0)),            # default PHB
    (1, phb_dscp(10)),           # AF11
    (2, phb_dscp(18)),           # AF21
    (3, phb_dscp(26, 1)),        # AF31, set of PHBs
    (4, phb_dscp(34)),           # AF41
    (5, phb_dscp(46)),           # EF
    (6, phb_code(0x123)),        # standards action PHB id code
    (7, phb_code(0xabc, 1)),     # set of PHBs, not standards action
]


def map_entries(maps):
    return b''.join(struct.pack('!HH', exp & 7, phbid) for exp, phbid in maps)


# ---------------------------------------------------------------- RSVP

def rsvp_obj(cls, ctype, data):
    return struct.pack('!HBB', 4 + len(data), cls, ctype) + data


def rsvp_msg(msgtype, objs):
    body = b''.join(objs)
    hdr = struct.pack('!BBHBBH', 0x10, msgtype, 0, 64, 0, 8 + len(body))
    m = hdr + body
    return m[:2] + struct.pack('!H', csum(m)) + m[4:]


def rsvp_path(tunnel_id, lsp_id, diffserv):
    objs = [
        # SESSION, LSP_TUNNEL_IPv4: end point, reserved, tunnel ID, ext ID
        rsvp_obj(1, 7, V4_C + struct.pack('!HH', 0, tunnel_id) + V4_A),
        # RSVP_HOP, IPv4: hop address, LIH
        rsvp_obj(3, 1, V4_A + struct.pack('!I', 0)),
        # TIME_VALUES: refresh period 30 s
        rsvp_obj(5, 1, struct.pack('!I', 30000)),
        # LABEL_REQUEST without label range, L3PID IPv4
        rsvp_obj(19, 1, struct.pack('!HH', 0, 0x0800)),
        # SESSION_ATTRIBUTE: setup/hold priority, flags, name
        rsvp_obj(207, 7, struct.pack('!BBBB', 7, 7, 0, 4) + b'ds-1'),
        diffserv,
        # SENDER_TEMPLATE, LSP_TUNNEL_IPv4: sender, reserved, LSP ID
        rsvp_obj(11, 7, V4_A + struct.pack('!HH', 0, lsp_id)),
        # SENDER_TSPEC, IntServ token bucket
        # (version, length 7 words, service 1, parameter 127, 5 words)
        rsvp_obj(12, 2, struct.pack('!HH', 0, 7) + struct.pack('!BBH', 1, 0, 6) +
                 struct.pack('!BBH', 127, 0, 5) +
                 struct.pack('!fffII', 125000.0, 1000.0, 125000.0, 64, 1500)),
    ]
    return ipv4(46, rsvp_msg(1, objs), V4_A, V4_C)


def diffserv_elsp(maps, mapnb=None):
    n = len(maps) if mapnb is None else mapnb
    return rsvp_obj(65, 1, struct.pack('!I', n & 15) + map_entries(maps))


def diffserv_llsp(psc):
    return rsvp_obj(65, 2, struct.pack('!HH', 0, psc))


# ---------------------------------------------------------------- LDP

class Tcp:
    """One TCP connection from A:sport to B:646 over IPv4."""
    def __init__(self, sport, dport=646):
        self.sport, self.dport = sport, dport
        self.seq = 1000

    def seg(self, payload):
        tcp = struct.pack('!HHIIBBHHH', self.sport, self.dport, self.seq, 5000,
                          5 << 4, 0x18, 65535, 0, 0) + payload
        pseudo = V4_A + V4_B + struct.pack('!xBH', 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp)) + tcp[18:]
        self.seq += len(payload)
        return ipv4(6, tcp)


def ldp_tlv(tlvtype, data, u=0, f=0):
    return struct.pack('!HH', (u << 15) | (f << 14) | tlvtype, len(data)) + data


def ldp_msg(msgtype, msgid, tlvs):
    body = struct.pack('!I', msgid) + b''.join(tlvs)
    return struct.pack('!HH', msgtype, len(body)) + body


def ldp_pdu(msgs):
    body = V4_A + struct.pack('!H', 0) + b''.join(msgs)
    return struct.pack('!HH', 1, len(body)) + body


def fec_prefix(prefix, plen):
    nb = (plen + 7) // 8
    return ldp_tlv(0x0100, struct.pack('!BHB', 2, 1, plen) + prefix[:nb])


def label_mapping(msgid, label, prefix, diffserv):
    return ldp_msg(0x0400, msgid, [fec_prefix(prefix, 24),
                                   ldp_tlv(0x0200, struct.pack('!I', label)),
                                   diffserv])


def ldp_elsp(maps, mapnb=None):
    n = len(maps) if mapnb is None else mapnb
    # T = 0 (E-LSP), reserved, MAPnb
    return ldp_tlv(0x0901, struct.pack('!I', n & 15) + map_entries(maps))


def ldp_llsp(psc):
    # T = 1 (L-LSP), reserved, PSC
    return ldp_tlv(0x0901, struct.pack('!HH', 0x8000, psc))


# ---------------------------------------------------------------- captures

def main_frames():
    f = []
    # 1: RSVP Path, E-LSP with all eight EXP values
    f.append(rsvp_path(1, 1, diffserv_elsp(E_MAPS)))
    # 2: RSVP Path, E-LSP with one MAP entry (singular)
    f.append(rsvp_path(2, 1, diffserv_elsp([(5, phb_dscp(46))])))
    # 3: RSVP Path, L-LSP, PSC as DSCP (AF1x class, set of PHBs)
    f.append(rsvp_path(3, 1, diffserv_llsp(phb_dscp(10, 1))))
    # 4: RSVP Path, L-LSP, PSC as PHB id code
    f.append(rsvp_path(4, 1, diffserv_llsp(phb_code(0x456))))
    # 5: RSVP Path, E-LSP without MAP entries
    f.append(rsvp_path(5, 1, diffserv_elsp([])))
    t = Tcp(40646)
    net = bytes([10, 1, 0, 0])
    # 6: LDP Label Mapping, E-LSP with all eight EXP values
    f.append(t.seg(ldp_pdu([label_mapping(1, 100, net, ldp_elsp(E_MAPS))])))
    # 7: LDP, two Label Mappings in one PDU: L-LSP with DSCP and PHB id code
    f.append(t.seg(ldp_pdu([
        label_mapping(2, 101, bytes([10, 2, 0, 0]), ldp_llsp(phb_dscp(18))),
        label_mapping(3, 102, bytes([10, 3, 0, 0]), ldp_llsp(phb_code(0xfff, 1))),
    ])))
    # 8: LDP Label Mapping, E-LSP with two MAP entries
    f.append(t.seg(ldp_pdu([label_mapping(4, 103, bytes([10, 4, 0, 0]),
                                          ldp_elsp(E_MAPS[5:7]))])))
    return f


def malformed_frames():
    f = []
    # 1: RSVP E-LSP, MAPnb 3 with one entry as the last object (RSVP
    # does not bound the MAP entries by the object length, so in the
    # middle of a message they would be read from the next objects)
    f.append(ipv4(46, rsvp_msg(1, [diffserv_elsp(E_MAPS[:1], 3)]), V4_A, V4_C))
    # 2: RSVP L-LSP with the PSC cut to one octet (object length 7)
    f.append(ipv4(46, rsvp_msg(1, [rsvp_obj(65, 2, b'\x00\x00\x28')]), V4_A, V4_C))
    t = Tcp(40647)
    # 3: LDP E-LSP, MAPnb 15 with two entries
    f.append(t.seg(ldp_pdu([label_mapping(11, 200, bytes([10, 9, 0, 0]),
                                          ldp_elsp(E_MAPS[:2], 15))])))
    # 4: LDP L-LSP with only the T bit and reserved field (length 2)
    f.append(t.seg(ldp_pdu([ldp_msg(0x0400, 12, [
        fec_prefix(bytes([10, 8, 0, 0]), 24), ldp_tlv(0x0901, b'\x80\x00')])])))
    return f


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(outdir, 'diffserv-mpls-common-coverage.pcap'), main_frames())
    pcap(os.path.join(outdir, 'diffserv-mpls-common-coverage-malformed.pcap'),
         malformed_frames())


if __name__ == '__main__':
    main()
