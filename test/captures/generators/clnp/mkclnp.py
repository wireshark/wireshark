#!/usr/bin/env python3
# Generates test/captures/clnp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the ISO 8473 CLNP dissector
(packet-clnp.c).

CLNP NPDUs are carried in IEEE 802.3 frames with LLC SAP 0xFE (OSI
network layer) and in IPv4 with protocol 80 (ISO-IP, RFC 1070); both
reach the "osi" dissector, which hands NLPID 0x81 (and 0x00, the
inactive subset) to CLNP. Every packet is built from scratch with
struct; no captured traffic is used.

Usage: mkclnp.py <output directory>

Writes:
  clnp-coverage.pcap            every NPDU type, checksums present and
                                absent, options, the NSAP selector paths
                                (transport, IDRP, data), segmentation and
                                reassembly, error reports and the nested
                                error report reproducer
  clnp-coverage-malformed.pcap  every header length check, bad checksums,
                                truncated headers
"""

import os
import struct
import sys

MAC_DST = bytes.fromhex('020000000002')
MAC_SRC = bytes.fromhex('020000000001')
IP_SRC = (192, 0, 2, 1)
IP_DST = (198, 51, 100, 2)

# NSAPs (20 octets, ISO 6523-ICD 0005 style, last octet = NSEL)
def nsap(sysid, nsel):
    return bytes.fromhex('47000580ffff000000000100010000') + bytes([0x00]) \
        + struct.pack('>I', sysid)[1:] + bytes([nsel])

NSAP_A = lambda nsel: nsap(0x0a0b0c, nsel)
NSAP_B = lambda nsel: nsap(0x0d0e0f, nsel)

DT, MD, ER, ERQ, ERP = 0x1c, 0x1d, 0x01, 0x1e, 0x1f
F_SEG, F_MORE, F_ERR = 0x80, 0x40, 0x20


def csum16(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def fletcher(hdr, pos):
    """ISO 8473 checksum: hdr has zero at pos, pos+1 (0-based)."""
    c0 = c1 = 0
    for b in hdr:
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    n = pos + 1
    L = len(hdr)
    x = ((L - n) * c0 - c1) % 255
    y = ((L - n + 1) * (-c0) + c1) % 255
    return (x or 255), (y or 255)


def clnp(ntype, data=b'', dst=None, src=None, ttl=30, options=b'', seg=None,
         cksum=True, version=1, seglen=None, hdrlen=None, totlen=None):
    """seg = (du_id, offset, total_length or None for auto)"""
    dst = NSAP_B(0x21) if dst is None else dst
    src = NSAP_A(0x21) if src is None else src
    addr = bytes([len(dst)]) + dst + bytes([len(src)]) + src
    segpart = b''
    if seg is not None:
        du, off, tot = seg
        segpart = struct.pack('>HHH', du, off, tot or 0)
    hl = 9 + len(addr) + len(segpart) + len(options)
    if seg is not None and seg[2] is None:
        segpart = struct.pack('>HHH', seg[0], seg[1], hl + len(data))
    sl = hl + len(data) if seglen is None else seglen
    h = bytes([0x81, hl if hdrlen is None else hdrlen, version, ttl, ntype]) \
        + struct.pack('>HH', sl, 0) + addr + segpart + options
    if cksum:
        x, y = fletcher(h[:hl], 7)
        h = h[:7] + bytes([x, y]) + h[9:]
    return h + data


def with_cksum(pdu, value):
    return pdu[:7] + struct.pack('>H', value) + pdu[9:]


# Options (ISO 8473 7.5)
OPT_QOS_GU = b'\xc3\x01\xd5'          # globally unique QoS, some bits set
OPT_QOS_SRC = b'\xc3\x01\x40'         # source address specific
OPT_PRIO = b'\xcd\x01\x05'
OPT_PRIO_BAD = b'\xcd\x01\x0f'        # above the maximum (14)
OPT_PAD = b'\xcc\x03\x00\x00\x00'
OPT_SEC_GU = b'\xc5\x03\xc0\x01\x02'  # globally unique security
OPT_SEC_SRC = b'\xc5\x02\x40\x07'
OPT_ROUTE_EMPTY = b'\xcb\x08\x00\x03' + b'\x00' * 6     # nothing recorded yet
OPT_ROUTE_FULL = b'\xcb\x02\x01\xff'                    # recording terminated
OPT_ROUTE_ONE = b'\xcb\x07\x00\x09\x04\x49\x00\x01\x02' # one NET recorded
OPT_ADDR_MASK = b'\xe1\x03\x49\x00\x01'
OPT_SNPA_MASK = b'\xe2\x02\xff\x00'
OPT_ESCT = b'\xc6\x02\x00\x3c'


def rfd(cls_code, field):
    return bytes([0xc1, 2, cls_code, field])


def cltp_ud(data, tsap_d=b'\x00\x01', tsap_s=b'\x00\x02'):
    var = b'\xc2' + bytes([len(tsap_d)]) + tsap_d + b'\xc1' + bytes([len(tsap_s)]) + tsap_s
    return bytes([1 + len(var), 0x40]) + var + data


def cotp_cr(dref=0, sref=0x1234, cls=0):
    var = b'\xc1\x02\x00\x01\xc2\x02\x00\x02\xc0\x01\x0a'
    return bytes([6 + len(var), 0xe0]) + struct.pack('>HHB', dref, sref, cls << 4) + var


def idrp_keepalive(seq=1):
    return struct.pack('>BHBIIBB', 0x85, 30, 4, seq, seq - 1, 5, 5) + b'\x00' * 16


def llc_frame(pdu):
    llc = b'\xfe\xfe\x03' + pdu
    return MAC_DST + MAC_SRC + struct.pack('>H', len(llc)) + llc


def ip_frame(pdu, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(pdu), ident, 0,
                      64, 80, 0, bytes(IP_SRC), bytes(IP_DST))
    hdr = hdr[:10] + struct.pack('>H', csum16(hdr)) + hdr[12:]
    return MAC_DST + MAC_SRC + b'\x08\x00' + hdr + pdu


def nested_er(nest=600):
    """clnp_er_recursion.py: 600 error reports nested in each
    other's Discarded PDU (11 octet headers without addresses)."""
    p = b''
    for _ in range(nest):
        p = struct.pack('>BBBBBHHBB', 0x81, 11, 1, 0x20, 0x01, 11 + len(p), 0, 0, 0) + p
    return p


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            if isinstance(fr, tuple):
                p, caplen = fr
            else:
                p, caplen = fr, len(fr)
            f.write(struct.pack('<IIII', 1700000000 + i, 0, caplen, len(p)))
            f.write(p[:caplen])


def main_frames():
    F = []
    data = b'CLNP coverage test data'
    # 1: DT, segmentation permitted but not segmented, error report wanted,
    #    checksum, options; CLTP UD to NSEL 0x21
    F.append(llc_frame(clnp(F_SEG | F_ERR | DT, cltp_ud(data), seg=(1, 0, None),
                            options=OPT_QOS_GU + OPT_PRIO + OPT_PAD + OPT_SEC_GU)))
    # 2: DT without segmentation, no checksum, COTP CR
    F.append(llc_frame(clnp(DT, cotp_cr(), cksum=False, ttl=31,
                            options=OPT_QOS_SRC + OPT_SEC_SRC + OPT_PRIO_BAD)))
    # 3: DT to NSEL 0x00 carrying IDRP
    F.append(llc_frame(clnp(DT, idrp_keepalive(), dst=NSAP_B(0x00), src=NSAP_A(0x00),
                            options=OPT_PRIO)))
    # 4: DT to NSEL 0x00, not IDRP -> data
    F.append(llc_frame(clnp(DT, b'\x01\x02\x03\x04', dst=NSAP_B(0x00), src=NSAP_A(0x00))))
    # 5: DT to NSEL 0x22 -> data (transport only with a preference)
    F.append(llc_frame(clnp(DT, cltp_ud(b'nsel 22'), dst=NSAP_B(0x22), src=NSAP_A(0x22),
                            options=OPT_ROUTE_ONE)))
    # 6: DT to NSEL 0x21 that is not a transport PDU (LI 0) -> data
    F.append(llc_frame(clnp(DT, b'\x00\x00\x00\x00', options=OPT_ADDR_MASK + OPT_SNPA_MASK + OPT_ESCT)))
    # 7: DT with a header only, no data
    F.append(llc_frame(clnp(DT | F_ERR, b'')))
    # 8: MD (multicast data) with CLTP
    F.append(llc_frame(clnp(MD, cltp_ud(b'multicast'))))
    # 9-10: Echo request and response
    F.append(llc_frame(clnp(ERQ | F_ERR, b'echo request data', options=OPT_PRIO)))
    F.append(llc_frame(clnp(ERP, b'echo response data', ttl=1)))
    # 11: unknown NPDU type 0x05
    F.append(llc_frame(clnp(0x05, b'unknown type')))
    # 12: inactive subset (NLPID 0x00) with a CLTP UD
    F.append(llc_frame(b'\x00' + cltp_ud(b'inactive')))
    # 13: version 2 -> data
    F.append(llc_frame(clnp(DT, b'version 2', version=2)))
    # 14-16: one DT segmented in three (data unit 100), in order, checksums
    payload = cltp_ud(bytes(range(120)))
    parts = [payload[0:48], payload[48:96], payload[96:]]
    total = None
    off = 0
    for i, part in enumerate(parts):
        more = F_MORE if i < len(parts) - 1 else 0
        hl = len(clnp(DT, b'', seg=(100, 0, 0)))
        tot = hl + len(payload)
        F.append(llc_frame(clnp(F_SEG | more | DT, part, seg=(100, off, tot), ttl=40)))
        off += len(part)
    # 17-18: data unit 101 in two segments, second segment first, no checksum
    payload2 = cltp_ud(b'out of order ' * 6)
    a, b = payload2[:40], payload2[40:]
    hl = len(clnp(DT, b'', seg=(101, 0, 0)))
    tot = hl + len(payload2)
    F.append(llc_frame(clnp(F_SEG | DT, b, seg=(101, len(a), tot), cksum=False)))
    F.append(llc_frame(clnp(F_SEG | F_MORE | DT, a, seg=(101, 0, tot), cksum=False)))
    # 19: a derived PDU with no data at offset 8 (not reassembled)
    F.append(llc_frame(clnp(F_SEG | F_MORE | DT, b'', seg=(102, 8, 100))))
    # 20: the first segment of data unit 103, the rest never arrives
    F.append(llc_frame(clnp(F_SEG | F_MORE | DT, cltp_ud(b'first only'), seg=(103, 0, 200))))
    # 21: ER: the discarded PDU is a whole DT (header and data)
    disc = clnp(F_SEG | F_ERR | DT, cltp_ud(b'discarded'), seg=(7, 0, None),
                src=NSAP_B(0x21), dst=NSAP_A(0x21))
    F.append(llc_frame(clnp(ER, disc, options=rfd(0x80 | 0x01, 0x10) + OPT_QOS_GU)))
    # 22: ER without a discarded PDU
    F.append(llc_frame(clnp(ER, b'', options=rfd(0xa0, 0))))
    # 23: ER whose discarded PDU is an echo request, lifetime expired
    disc = clnp(ERQ | F_ERR, b'ping', src=NSAP_B(0x21), dst=NSAP_A(0x21))
    F.append(llc_frame(clnp(ER, disc, options=rfd(0xa1, 3))))
    # 24: ER carrying an ER carrying a DT (two levels)
    inner = clnp(DT | F_ERR, b'xyz', src=NSAP_B(0x21), dst=NSAP_A(0x21))
    mid = clnp(ER, inner, options=rfd(0xb0, 0), src=NSAP_B(0x21), dst=NSAP_A(0x21))
    F.append(llc_frame(clnp(ER, mid, options=rfd(0xc0, 0))))
    # 25: CLNP over IPv4 protocol 80 (ISO-IP), CLTP
    F.append(ip_frame(clnp(DT, cltp_ud(b'iso-ip'), options=OPT_PRIO), ident=25))
    return F


def malformed_frames():
    F = []
    # 1: header length 8 (< fixed part)
    F.append(llc_frame(clnp(DT, b'x', hdrlen=8, cksum=False)))
    # 2: PDU length < header length
    F.append(llc_frame(clnp(DT, b'x', seglen=20, cksum=False)))
    # 3: header length 9 (no destination address length)
    F.append(llc_frame(bytes([0x81, 9, 1, 30, DT]) + struct.pack('>HH', 9, 0)))
    # 4: destination address longer than the header
    F.append(llc_frame(bytes([0x81, 12, 1, 30, DT]) + struct.pack('>HH', 12, 0) + b'\x05\x49\x00'))
    # 5: no source address length
    F.append(llc_frame(bytes([0x81, 12, 1, 30, DT]) + struct.pack('>HH', 12, 0) + b'\x02\x49\x00' + b'\x00'))
    # 6: source address longer than the header
    F.append(llc_frame(bytes([0x81, 14, 1, 30, DT]) + struct.pack('>HH', 14, 0) + b'\x02\x49\x00\x04\x49\x00'))
    # 7: segmentation permitted, no room for the segmentation part
    F.append(llc_frame(bytes([0x81, 15, 1, 30, F_SEG | DT]) + struct.pack('>HH', 15, 0)
                       + b'\x02\x49\x00\x02\x49\x00' + b'\x00'))
    # 8: total length < segment length
    F.append(llc_frame(clnp(F_SEG | DT, b'abcdef', seg=(5, 0, 20))))
    # 9: bad checksum, not segmented
    F.append(llc_frame(with_cksum(clnp(DT, cltp_ud(b'bad')), 0x1234)))
    # 10: bad checksum on a later segment (not reassembled)
    F.append(llc_frame(with_cksum(clnp(F_SEG | F_MORE | DT, b'segment', seg=(9, 16, 200)), 0x0101)))
    # 11: header cut short by the frame (reported length < header length)
    pdu = clnp(DT, b'')
    F.append(llc_frame(pdu[:30]))
    # 12: checksum present, header cut short by the snapshot length
    fr = llc_frame(clnp(DT, cltp_ud(b'snap')))
    F.append((fr, 17 + 30))
    # 13: ER whose discarded PDU is a truncated header
    disc = clnp(DT, b'')[:20]
    F.append(llc_frame(clnp(ER, disc, options=rfd(0x00, 0))))
    # 14: ER with an unknown error class in the reason for discard
    F.append(llc_frame(clnp(ER, b'', options=rfd(0xf0, 0))))
    # 15: header with no options (header ends after the addresses) -> note
    F.append(llc_frame(clnp(DT, b'\x00', cksum=False)))
    # 16: PDU length past the end of the frame (data shorter than claimed)
    F.append(llc_frame(clnp(DT, cltp_ud(b'short'), seglen=200)))
    # 17: segment of data unit 100 overlapping with conflicting data
    F.append(llc_frame(clnp(F_SEG | F_MORE | DT, b'A' * 16, seg=(50, 0, 80), cksum=False)))
    F.append(llc_frame(clnp(F_SEG | F_MORE | DT, b'B' * 16, seg=(50, 0, 80), cksum=False)))
    # 19-20: record of route "nothing recorded yet" and "recording
    # terminated" (packet-osi-options.c walks from the start of the packet)
    F.append(llc_frame(clnp(DT, b'r', options=OPT_ROUTE_EMPTY)))
    F.append(llc_frame(clnp(DT, b'r', options=OPT_ROUTE_FULL)))
    # 21: reproducer: 600 nested error reports (clnp_er_recursion), over
    # ISO-IP. Without a tree the nesting stops with clnp.too_deep; with a
    # tree the tree depth limit (2 levels per error report) is hit first.
    F.append(ip_frame(nested_er(), ident=21))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'clnp-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'clnp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
