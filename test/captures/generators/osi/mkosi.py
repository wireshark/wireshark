#!/usr/bin/env python3
# Generates test/captures/osi_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the OSI network layer dispatcher (packet-osi.c) coverage captures.

Usage: mkosi.py <outdir>
Writes
  osi-coverage.pcapng            one capture with several link types (Ethernet,
                                 PPP, Cisco HDLC, BSD loopback, Juniper)
  osi-coverage-malformed.pcapng  error paths (not added to the tree)
Nothing comes from a real network.

The OSI dissector is reached by default through LLC SAP 0xFE, PPP protocol
0x0023, Cisco HDLC protocol 0x00FE, the BSD loopback family ISO (7), GRE
protocol 0x00FE, IP protocol 80 and the Juniper link types. OSI over TPKT is
only reached by Decode As (tcp.port, "osi_tpkt"); its frames are in the
capture and are plain TCP data without it.
"""
import os
import struct
import sys

MAC_DST = bytes.fromhex('020000000002')
MAC_SRC = bytes.fromhex('020000000001')
IP_SRC = (192, 0, 2, 1)
IP_DST = (198, 51, 100, 2)


def csum16(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def nsap(sysid, nsel):
    return bytes.fromhex('47000580ffff000000000100010000') + bytes([0x00]) \
        + struct.pack('>I', sysid)[1:] + bytes([nsel])


def fletcher_hdr(hdr, pos):
    c0 = c1 = 0
    for b in hdr:
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    n = pos + 1
    L = len(hdr)
    x = ((L - n) * c0 - c1) % 255
    y = ((L - n + 1) * (-c0) + c1) % 255
    return (x or 255), (y or 255)


def clnp(data=b'DATA-0123456789', nsel=0x22):
    dst, src = nsap(0x0d0e0f, nsel), nsap(0x0a0b0c, nsel)
    addr = bytes([len(dst)]) + dst + bytes([len(src)]) + src
    hl = 9 + len(addr)
    h = bytes([0x81, hl, 1, 30, 0x1c]) + struct.pack('>HH', hl + len(data), 0) + addr
    x, y = fletcher_hdr(h, 7)
    h = h[:7] + bytes([x, y]) + h[9:]
    return h + data


def fix_iso(pdu, pos, start=0):
    """Set the two octets at pos so that the ISO 8473 sums over pdu[start:] are zero."""
    t = pdu[start:]
    p = pos - start
    c0 = c1 = 0
    for b in t:
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    L = len(t)
    x = ((L - p - 1) * c0 - c1) % 255
    y = (-c0 - x) % 255
    return pdu[:pos] + bytes([x or 255, y or 255]) + pdu[pos + 2:]


def cotp_dt_checksum(data):
    t = bytes([8, 0xf0, 0x12, 0x34, 0x80, 0xc3, 2, 0, 0]) + data
    return fix_iso(t, 7)


def ipv4_icmp(payload=b'abcdefgh'):
    icmp = struct.pack('>BBHHH', 15, 0, 0, 1, 1) + payload     # information request, no matching reply needed
    icmp = icmp[:2] + struct.pack('>H', csum16(icmp)) + icmp[4:]
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(icmp), 7, 0, 64, 1, 0, bytes(IP_SRC), bytes(IP_DST))
    return hdr[:10] + struct.pack('>H', csum16(hdr)) + hdr[12:] + icmp


def ipv6_icmp(payload=b''):
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    icmp = struct.pack('>BBHI', 133, 0, 0, 0) + payload        # router solicitation
    ph = src + dst + struct.pack('>IBBBB', len(icmp), 0, 0, 0, 58)
    icmp = icmp[:2] + struct.pack('>H', csum16(ph + icmp)) + icmp[4:]
    return struct.pack('>IHBB16s16s', 0x60000000, len(icmp), 58, 255, src, dst) + icmp


def eth(pdu, etype):
    return MAC_DST + MAC_SRC + struct.pack('>H', etype) + pdu


def llc(pdu):
    p = b'\xfe\xfe\x03' + pdu
    return eth(p, len(p))


def ip4(payload, proto):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 3, 0, 64, proto, 0, bytes(IP_SRC), bytes(IP_DST))
    return eth(hdr[:10] + struct.pack('>H', csum16(hdr)) + hdr[12:] + payload, 0x0800)


def tcp(payload, sport, dport, seq, ack=1):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 5 << 4, 0x18, 65535, 0, 0) + payload
    ph = bytes(IP_SRC) + bytes(IP_DST) + struct.pack('>BBH', 0, 6, len(t))
    t = t[:16] + struct.pack('>H', csum16(ph + t)) + t[18:]
    return ip4(t, 6)


def tpkt(p):
    return struct.pack('>BBH', 3, 0, 4 + len(p)) + p


# ---------------------------------------------------------------- IS-IS with checksums

def osi_checksum(data, off_check):
    """The value osi_check_and_get_checksum() computes for the octets at off_check."""
    L = len(data)
    discard = False
    c0 = c1 = 0
    p = 0
    block = off_check // 5803
    rem = L
    while rem != 0:
        seglen = rem
        if block == 0:
            seglen = off_check % 5803
            discard = True
        elif seglen > 5803:
            seglen = 5803
        block -= 1
        for i in range(seglen):
            c0 += data[p]
            p += 1
            c1 += c0
        if discard:
            p += 2
            c1 += 2 * c0
            rem -= 2
            discard = False
        c0 %= 255
        c1 %= 255
        rem -= seglen
    factor = (L - off_check) * c0
    x = factor - c0 - c1
    y = c1 - factor - 1
    if x < 0:
        x -= 1
    if y > 0:
        y += 1
    # C's % truncates toward zero
    x = int(abs(x) % 255) * (1 if x >= 0 else -1)
    y = int(abs(y) % 255) * (1 if y >= 0 else -1)
    if x == 0:
        x = 0xff
    if y == 0:
        y = 1
    return ((x << 8) | (y & 0xff)) & 0xffff


def isis_clv(t, v):
    return bytes([t, len(v)]) + v


SYS = bytes.fromhex('0a0b0c0d0e0f')


def isis_hdr(hdrlen, ptype):
    return bytes([0x83, hdrlen, 1, 0, ptype, 1, 0, 0])


def isis_with_checksum(pdu, clv_pos, covered_start=0):
    """pdu has zero octets at clv_pos; fill in the checksum for the covered part."""
    data = pdu[covered_start:]
    v = osi_checksum(data, clv_pos - covered_start)
    return pdu[:clv_pos] + struct.pack('>H', v) + pdu[clv_pos + 2:]


def iih_lan(with_checksum=True):
    clvs = isis_clv(1, bytes([0x03, 0x49, 0x00, 0x01]))
    ck = isis_clv(12, b'\0\0') if with_checksum else b''
    body = bytes([1]) + SYS + struct.pack('>HH', 30, 0) + bytes([64]) + SYS + bytes([1])
    pdu = isis_hdr(27, 15) + body + clvs + ck
    pdu = pdu[:17] + struct.pack('>H', len(pdu)) + pdu[19:]
    if with_checksum:
        pos = len(pdu) - 2
        pdu = isis_with_checksum(pdu, pos)
    return pdu


def csnp(with_checksum=True):
    ent = struct.pack('>H', 1000) + SYS + bytes([0, 0]) + struct.pack('>IH', 5, 0x1234)
    clvs = isis_clv(9, ent)
    ck = isis_clv(12, b'\0\0') if with_checksum else b''
    body = struct.pack('>H', 0) + SYS + bytes([0]) + SYS + bytes([0, 0]) + SYS + bytes([0xff, 0xff])
    pdu = isis_hdr(33, 24) + body + clvs + ck
    pdu = pdu[:8] + struct.pack('>H', len(pdu)) + pdu[10:]
    if with_checksum:
        pdu = isis_with_checksum(pdu, len(pdu) - 2)
    return pdu


def lsp(pad_clvs=0, seq=1):
    clvs = isis_clv(1, bytes([0x03, 0x49, 0x00, 0x01]))
    for _ in range(pad_clvs):
        clvs += isis_clv(8, bytes(255))
    body = struct.pack('>HH', 0, 1200) + SYS + bytes([0, 0]) + struct.pack('>IH', seq, 0) + bytes([0x01])
    pdu = isis_hdr(27, 20) + body + clvs
    pdu = pdu[:8] + struct.pack('>H', len(pdu)) + pdu[10:]
    # the LSP checksum covers the PDU from the LSP ID (offset 12); it is at offset 24
    pdu = pdu[:24] + b'\0\0' + pdu[26:]
    v = osi_checksum(pdu[12:], 24 - 12)
    return pdu[:24] + struct.pack('>H', v) + pdu[26:]


def esis_ish():
    net = bytes.fromhex('49000100aa0000bb')
    body = bytes([len(net)]) + net
    h = bytes([0x82, 9 + len(body), 1, 0, 0x04, 0, 30, 0, 0]) + body
    x, y = fletcher_hdr(h, 7)
    return h[:7] + bytes([x, y]) + h[9:]


# ---------------------------------------------------------------- pcapng

def pad4(b):
    return b + bytes(-len(b) % 4)


class Pcapng:
    def __init__(self):
        shb = struct.pack('<IIHHq', 0x1a2b3c4d, 0, 1, 0, -1)
        shb = struct.pack('<III', 0x0a0d0d0a, 12 + len(shb) - 4, 0x1a2b3c4d)[:4] + struct.pack('<I', 28) + struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1) + struct.pack('<I', 28)
        self.out = bytearray(shb)
        self.ifaces = {}
        self.n = 0

    def iface(self, linktype):
        if linktype not in self.ifaces:
            blk = struct.pack('<IIHHI', 1, 20, linktype, 0, 0) + struct.pack('<I', 20)
            self.out += blk
            self.ifaces[linktype] = len(self.ifaces)
        return self.ifaces[linktype]

    def add(self, linktype, data, caplen=None):
        i = self.iface(linktype)
        full = len(data)
        data = data if caplen is None else data[:caplen]
        pd = pad4(data)
        ln = 32 + len(pd)
        ts = 1700000000 * 1000000 + self.n * 1000000
        self.n += 1
        self.out += struct.pack('<IIIIIII', 6, ln, i, ts >> 32, ts & 0xffffffff, len(data), full) + pd + struct.pack('<I', ln)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(self.out)


ETH, PPP, CHDLC, NULL, JUNIPER_ETHER = 1, 9, 104, 0, 178


def juniper(proto, payload):
    return b'MGC' + bytes([0x02]) + struct.pack('<I', proto) + payload


def main_frames():
    c = clnp()
    F = []
    # Ethernet, LLC SAP 0xFE: CLNP (NLPID in the PDU), ES-IS, IS-IS IIH/CSNP/LSP with checksums,
    # a jumbo LSP (checksum over more than 5803 octets), IP and IPv6 (NLPID not part of the PDU),
    # ES-IS over X.25 and IDRP (data), an unknown NLPID
    F.append((ETH, llc(c)))
    F.append((ETH, llc(esis_ish())))
    F.append((ETH, llc(iih_lan())))
    F.append((ETH, llc(iih_lan(False))))
    F.append((ETH, llc(csnp())))
    F.append((ETH, llc(lsp())))
    F.append((PPP, bytes([0xff, 0x03, 0x00, 0x23]) + lsp(pad_clvs=24, seq=2)))
    F.append((ETH, llc(b'\xcc' + ipv4_icmp())))
    F.append((ETH, llc(b'\x8e' + ipv6_icmp())))
    F.append((ETH, llc(b'\x8a' + bytes(range(16)))))
    F.append((ETH, llc(b'\x85' + bytes(range(16)))))
    F.append((ETH, llc(b'\x99' + bytes(range(16)))))
    # the other carriers of the OSI dissector
    F.append((PPP, bytes([0xff, 0x03, 0x00, 0x23]) + c))
    F.append((CHDLC, bytes([0x0f, 0x00, 0xfe, 0xfe]) + c))
    F.append((NULL, struct.pack('<I', 7) + c))
    F.append((ETH, ip4(struct.pack('>HH', 0, 0x00fe) + c, 47)))        # GRE
    F.append((ETH, ip4(c, 80)))                                         # IP protocol 80
    F.append((JUNIPER_ETHER, juniper(10, c)))                           # CLNP, NLPID in the PDU
    F.append((JUNIPER_ETHER, juniper(201, b'\xcc' + ipv4_icmp())))      # OSI, NLPID not part of the PDU
    F.append((JUNIPER_ETHER, juniper(33, b'\x99' + bytes(8))))          # MPLS->CLNP, unknown NLPID
    F.append((JUNIPER_ETHER, juniper(201, b'\x8e' + ipv6_icmp())))
    # a COTP DT TPDU of 6100 octets with an ISO 8073 checksum (checksummed in blocks of 5803 octets),
    # over IP protocol 39 (carried to COTP by default)
    F.append((ETH, ip4(cotp_dt_checksum((bytes(range(256)) * 24)[:6100]), 39)))
    # TPKT carrying OSI (reached by Decode As on tcp.port): whole, and split over two segments
    F.append((ETH, tcp(tpkt(c), 8102, 8102, 1000)))
    t2 = tpkt(clnp(b'second PDU, in two segments'))
    F.append((ETH, tcp(t2[:30], 8102, 8102, 1000 + len(tpkt(c)))))
    F.append((ETH, tcp(t2[30:], 8102, 8102, 1000 + len(tpkt(c)) + 30)))
    return F


def malformed_frames():
    c = clnp()
    F = []
    # IS-IS with bad checksums: IIH, CSNP and LSP, truncated LSP that cannot be verified
    h = bytearray(iih_lan()); h[-1] ^= 0x55
    F.append((ETH, llc(bytes(h))))
    h = bytearray(csnp()); h[-1] ^= 0x55
    F.append((ETH, llc(bytes(h))))
    h = bytearray(lsp()); h[25] ^= 0x55
    F.append((ETH, llc(bytes(h))))
    F.append((PPP, bytes([0xff, 0x03, 0x00, 0x23]) + lsp(pad_clvs=24, seq=3), 3000))   # truncated: checksum cannot be verified
    # ES-IS with a bad checksum
    h = bytearray(esis_ish()); h[8] ^= 0x55
    F.append((ETH, llc(bytes(h))))
    # TPKT with a bad version
    F.append((ETH, tcp(b'\x04\x00\x00\x08' + c[:4], 8102, 8102, 9000)))
    # a one-octet OSI PDU, empty Juniper payloads
    F.append((ETH, llc(b'\x81')))
    F.append((ETH, llc(b'\x82\x03')))
    F.append((JUNIPER_ETHER, juniper(10, b'\x81')))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    for name, frames in (('osi-coverage.pcapng', main_frames()), ('osi-coverage-malformed.pcapng', malformed_frames())):
        p = Pcapng()
        for fr in frames:
            p.add(*fr)
        p.write(os.path.join(out, name))


if __name__ == '__main__':
    main()
