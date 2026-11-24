#!/usr/bin/env python3
# Generates test/captures/enip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EtherNet/IP dissector
(packet-enip.c): the encapsulation over TCP and UDP 44818, the Common
Packet Format items, request/response matching, CIP connection tracking
(Forward Open/Close, class 0/1 I/O on UDP 2222, class 3 SendUnitData,
concurrent connections), the CIP object attributes and services that
packet-enip.c defines (TCP/IP Interface, Ethernet Link, QoS, DLR, PRP/HSR,
LLDP Management and Data Table, CIP Security, EtherNet/IP Security,
Certificate Management, Ingress Egress), the DLR protocol (ethertype
0x80E1) and the ODVA LLDP TLVs.

The CIP layer itself (packet-cip.c) has its own coverage capture; here it
is only the carrier. Every packet is built from scratch with struct; no
captured traffic is used. Addresses are from the documentation ranges and
locally administered MAC addresses. The Pre-Shared Keys attribute of the
EtherNet/IP Security object only carries placeholder bytes; nothing here
handles keys.

Usage: mkenip.py <output directory>

Writes:
  enip-coverage.pcap            the main capture
  enip-coverage-malformed.pcap  attributes cut short, CPF items that are
                                too short (the reproducers of the CPF
                                length fix), items longer than the data
"""

import os
import struct
import sys

from ciplib import (CLI_IP, SRV_IP, CLI_MAC, SRV_MAC, ENIP_PORT, IO_PORT, SESSION,  # noqa: E402
                    csum, TcpStream, udp_frame, write_pcap, u8, u16, u32, u64,
                    sstr, cstr, cls, inst, att, cpt, ekey, req, rsp,
                    fwd_open, fwd_open_rsp, fwd_close, fwd_close_rsp, cc_packet)

# ---------------------------------------------------------------- framing


def encap(cmd, data, session=SESSION, status=0, context=0, options=0):
    return struct.pack('<HHIIQI', cmd, len(data), session, status, context, options) + data


def cpf(*items):
    """Common Packet Format: item count and (type, data) items."""
    out = u16(len(items))
    for t, d in items:
        out += u16(t) + u16(len(d)) + d
    return out


def srrd(items, iface=0, timeout=0):
    return u32(iface) + u16(timeout) + cpf(*items)


def sockaddr(port, ip, family=2):
    return struct.pack('>HH4s', family, port, bytes(ip)) + bytes(8)


def ip6(src, dst, nh, payload):
    return struct.pack('!IHBB16s16s', 0x60000000, len(payload), nh, 64, src, dst) + payload


def eth6(src_mac, dst_mac, payload):
    return dst_mac + src_mac + b'\x86\xdd' + payload


CLI_IP6 = bytes.fromhex('20010db8000000000000000000000010')
SRV_IP6 = bytes.fromhex('20010db8000000000000000000000020')


class Tcp6Stream:
    """TCP over IPv6 between CLI_IP6:cport and SRV_IP6:44818."""

    def __init__(self, cport, cseq=7000, sseq=9000):
        self.cport = cport
        self.seq = {True: cseq, False: sseq}

    def frame(self, from_client, payload, flags=0x18):
        if from_client:
            src, dst, sport, dport, smac, dmac = CLI_IP6, SRV_IP6, self.cport, ENIP_PORT, CLI_MAC, SRV_MAC
        else:
            src, dst, sport, dport, smac, dmac = SRV_IP6, CLI_IP6, ENIP_PORT, self.cport, SRV_MAC, CLI_MAC
        seq, ack = self.seq[from_client], self.seq[not from_client]
        self.seq[from_client] = seq + len(payload)
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
        pseudo = src + dst + struct.pack('!IxxxB', len(tcp) + len(payload), 6)
        c = csum(pseudo + tcp + payload)
        tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
        return eth6(smac, dmac, ip6(src, dst, 6, tcp + payload))


def udp6_frame(src, dst, sport, dport, payload, smac=CLI_MAC, dmac=SRV_MAC):
    hdr = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
    pseudo = src + dst + struct.pack('!IxxxB', 8 + len(payload), 17)
    c = csum(pseudo + hdr + payload) or 0xffff
    hdr = hdr[:6] + struct.pack('!H', c)
    return eth6(smac, dmac, ip6(src, dst, 17, hdr + payload))


class Cap:
    def __init__(self):
        self.frames = []
        self.labels = []
        self.ctx = 0x1000
        self.tcp = TcpStream(50000, 100000, 500000)
        self.ident = 1

    def add(self, frame, label):
        self.frames.append(frame)
        self.labels.append(label)

    def t(self, from_client, payload, label, stream=None):
        self.add((stream or self.tcp).frame(from_client, payload), label)

    def pair(self, request, response, label, stream=None, items_req=(), items_rsp=()):
        """SendRRData request/response pair with its own sender context;
        items_* are extra CPF items after the Unconnected Data item."""
        self.ctx += 1
        st = stream or self.tcp
        self.t(True, encap(0x6F, srrd([(0, b''), (0xB2, request)] + list(items_req)),
                           context=self.ctx), label + ' (request)', st)
        if response is not None:
            self.t(False, encap(0x6F, srrd([(0, b''), (0xB2, response)] + list(items_rsp)),
                                context=self.ctx), label + ' (response)', st)

    def sud(self, from_client, connid, seq, cip, label, stream=None, extra=()):
        self.t(from_client, encap(0x70, srrd([(0xA1, u32(connid)), (0xB1, u16(seq) + cip)] + list(extra))),
               label, stream)

    def udp(self, src, dst, sport, dport, payload, label, rev=False):
        smac, dmac = (SRV_MAC, CLI_MAC) if rev else (CLI_MAC, SRV_MAC)
        self.ident += 1
        self.add(udp_frame(src, dst, sport, dport, payload, smac, dmac, ident=self.ident), label)

    def io(self, from_client, connid, seq32, data, label, dst=None, extra=()):
        payload = cpf((0x8002, u32(connid) + u32(seq32)), (0xB1, data), *extra)
        if from_client:
            self.udp(CLI_IP, dst or SRV_IP, IO_PORT, IO_PORT, payload, label)
        else:
            self.udp(SRV_IP, dst or CLI_IP, IO_PORT, IO_PORT, payload, label, rev=True)


# ---------------------------------------------------------------- CIP data

def gal(c, i, attrs):
    return req(0x03, cls(c) + inst(i), u16(len(attrs)) + b''.join(u16(a) for a in attrs))


def gal_rsp(items):
    """items: list of (attribute, data); status 0 for each."""
    return rsp(0x03, u16(len(items)) + b''.join(u16(a) + u16(0) + d for a, d in items))


def sal(c, i, items):
    return req(0x04, cls(c) + inst(i), u16(len(items)) + b''.join(u16(a) + d for a, d in items))


def sal_rsp(attrs):
    return rsp(0x04, u16(len(attrs)) + b''.join(u16(a) + u16(0) for a in attrs))


def gaa(c, i):
    return req(0x01, cls(c) + inst(i))


def padded_epath_uint(path):
    """Padded EPATH with a UINT size in words."""
    return u16(len(path) // 2) + path


def padded_epath_usint(path):
    return u8(len(path) // 2) + path


def cip_string(s):
    """CIP STRING (UINT length) padded to an even length."""
    b = cstr(s)
    return b + (b'\0' if len(s) % 2 else b'')


MAC_A = bytes.fromhex('02000000aa01')
MAC_B = bytes.fromhex('02000000aa02')


def ip_le(a):
    return bytes(reversed(bytes(a)))


def arp_pdu():
    return struct.pack('>HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, MAC_A, bytes([192, 0, 2, 20]),
                       bytes(6), bytes([192, 0, 2, 20]))


def class_attrs(n_inst=1):
    """Common class attributes 1-7."""
    return [(1, u16(2)), (2, u16(n_inst)), (3, u16(n_inst)),
            (4, u16(2) + u16(8) + u16(9)), (5, u16(1) + u16(0x4C)),
            (6, u16(7)), (7, u16(17))]


def port_admin(attribute_version=True):
    ports = [('EtherNet/IP', 44818, 6, 1, 0x01), ('CIP I/O', 2222, 17, 1, 0x03), ('', 80, 6, 0, 0x00)]
    out = u8(len(ports))
    for name, num, proto, state, capab in ports:
        if attribute_version:
            out += sstr(name)
        out += u16(num) + u8(proto) + u8(state)
        if attribute_version:
            out += u8(capab)
    return out


def protocol_admin(attribute_version=True):
    protos = [('HTTP', 1, 1, 0x01), ('SNMP', 2, 0, 0x02)]
    out = u8(len(protos))
    for name, num, state, capab in protos:
        if attribute_version:
            out += sstr(name)
        out += u16(num) + u8(state)
        if attribute_version:
            out += u8(capab)
    return out


TCPIP = [
    (1, u32(0x000000F2)),
    (2, u32(0x000000F5)),
    (3, u32(0x00000012)),
    (4, padded_epath_uint(cls(0xF6) + inst(1))),
    (5, ip_le((192, 0, 2, 20)) + ip_le((255, 255, 255, 0)) + ip_le((192, 0, 2, 1))
        + ip_le((192, 0, 2, 53)) + ip_le((0, 0, 0, 0)) + cip_string('example.com')),
    (6, cip_string('plc-1')),
    (7, u16(100) + u32(1000)),
    (8, u8(1)),
    (9, u8(1) + u8(0) + u16(32) + ip_le((239, 192, 1, 0))),
    (10, u8(1)),
    (11, u8(0) + MAC_B + bytes(28)),
    (12, u8(0)),
    (13, u16(120)),
    (14, port_admin()),
    (15, protocol_admin()),
    (16, u16(3)),
    (17, u32(1000)),
]

ELINK = [
    (1, u32(100)),
    (2, u32(0x0000001F)),
    (3, MAC_A),
    (4, b''.join(u32(1000 + k) for k in range(11))),
    (5, b''.join(u32(k) for k in range(12))),
    (6, u16(0x0002) + u16(100)),
    (7, u8(2)),
    (8, u8(1)),
    (9, u8(1)),
    (10, sstr('Port 1')),
    (11, u32(0x0000000F) + u8(3) + u16(10) + u8(0) + u16(100) + u8(1) + u16(1000) + u8(1)),
    (12, b''.join(u64(1 << k) for k in range(8))),
    (13, b''.join(u64(k) for k in range(6))),
    (14, u32(7)),
    (15, u32(2)),
    (16, u8(1) + u8(5)),
    (17, u8(1)),
]

QOS = [(1, u8(1))] + [(a, u8(a * 2)) for a in range(2, 16)]

DLR = [
    (1, u8(1)), (2, u8(0)), (3, u8(1)),
    (4, u8(1) + u8(5) + u32(400) + u32(1960) + u16(0)),
    (5, u16(3)),
    (6, ip_le((192, 0, 2, 31)) + MAC_A),
    (7, ip_le((192, 0, 2, 32)) + MAC_B),
    (8, u16(2)),
    (10, ip_le((192, 0, 2, 30)) + MAC_A),
    (11, u8(5)),
    (12, u32(0x000000E3)),
    (13, u8(1) + u8(3) + u32(2000) + u32(5000) + u8(1)),
    (14, u8(2)),
    (15, ip_le((192, 0, 2, 33)) + MAC_B),
    (16, u8(3)),
    (17, u16(1)),
    (18, u16(2)),
    (19, u8(1)),
]
DLR_PARTICIPANTS = ip_le((192, 0, 2, 31)) + MAC_A + ip_le((192, 0, 2, 32)) + MAC_B

PRP = [(1, u8(1)), (2, u16(1)), (3, sstr('node-a')), (4, sstr('v1.0')), (5, MAC_A)]

LLDP_MGMT = [
    (1, u16(11) + bytes([0x05, 0x02])),
    (2, u16(30)),
    (3, u8(4)),
    (4, u16(0x0001)),
    (5, u32(12345)),
]

LLDP_TBL = [
    (1, u16(1)),
    (2, MAC_A),
    (3, sstr('eth0')),
    (4, u16(120)),
    (5, u16(0x0014) + u16(0x0010)),
    (6, u8(2) + bytes([192, 0, 2, 20]) + bytes([198, 51, 100, 20])),
    (7, u16(1) + u16(12) + u16(34) + u8(2) + u8(5) + u32(0x11223344)),
    (8, u8(1) + u8(1) + u8(0) + u8(2)),
    (9, u32(4567)),
    (10, u16(9)),
    (11, u8(1) + u8(3)),
]

CIPSEC = [(1, u8(3)), (2, u16(0x0003))]

CERT_PATH = cls(0x5F) + inst(1)
EIPSEC = [
    (1, u8(2)),
    (2, u32(0x00000001)),
    (3, u8(2) + struct.pack('>HH', 0xC0AE, 0x00AE)),
    (4, u8(1) + struct.pack('>H', 0xC0AE)),
    # one Pre-Shared Key entry with an identity and placeholder bytes
    (5, u8(1) + u8(4) + b'psk1' + u8(4) + bytes(4) + u8(1)),
    (6, u8(1) + padded_epath_usint(CERT_PATH)),
    (7, u8(2) + padded_epath_usint(CERT_PATH) + padded_epath_usint(cls(0x5F) + inst(2))),
    (8, u8(0)),
    (9, u8(1)), (10, u8(0)), (11, u8(1)),
    (12, u8(1) + padded_epath_usint(cls(0x5F) + inst(3))),
    (13, u8(0)),
    (14, u16(0)),
    (15, u16(12)),
    (17, u8(1)),
]

CERT_CLASS = class_attrs(2) + [
    (8, u32(0x00000001)),
    (9, u8(2) + sstr('Default') + padded_epath_usint(CERT_PATH)
        + sstr('Vendor') + padded_epath_usint(cls(0x5F) + inst(2))),
    (10, u32(0x00000003)),
]
CERT_INST = [
    (1, sstr('Default')),
    (2, u8(2)),
    (3, u8(1) + padded_epath_usint(cls(0x37) + inst(1))),
    (4, u8(1) + padded_epath_usint(cls(0x37) + inst(2))),
    (5, u8(1)),
]

INGRESS_CLASS = class_attrs(2) + [
    (8, u16(2) + u16(44818) + u16(44818) + u16(2221) + u16(2222)),
    (9, u16(1) + u16(2222) + u16(2222)),
    (10, u32(4096)),
    (11, u32(5)),
]
INGRESS_INST = [
    (1, u16(2) + sstr('permit tcp any 44818') + sstr('deny all')),
    (2, u16(0)),
]


def gaa_data(items, cls_id, inst_id):
    """The attributes of a Get_Attributes_All response, in table order
    (only those with a GAA index, see enip_attribute_vals)."""
    order = GAA_ORDER[(cls_id, inst_id == 0)]
    d = dict(items)
    return b''.join(d[a] for a in order)


# The attributes with a GAA index >= 0 in enip_attribute_vals, in order
GAA_ORDER = {
    (0xF5, False): [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17],
    (0xF5, True): [1, 2, 3, 4, 5, 6, 7],
    (0xF6, False): list(range(1, 16)),
    (0xF6, True): [1, 2, 3, 4, 5, 6, 7],
    (0x48, True): [1, 2, 3, 4, 5, 6, 7],
    (0x47, False): [1, 2],
    (0x47, True): [1, 2, 3, 4, 5, 6, 7],
    (0x56, False): [1, 2, 3, 4, 5],
    (0x57, False): [1],
    (0x109, False): [1, 2, 3, 4, 5],
    (0x10A, False): list(range(1, 12)),
    (0x5D, False): [1, 2],
    (0x5E, False): [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17],
    (0x5F, True): [1, 2, 6, 7, 8, 9, 10],
    (0x5F, False): [1, 2, 3, 4, 5],
    (0x63, True): [1, 2, 3, 6, 7, 8, 9, 10, 11],
    (0x63, False): [1, 2],
}


# ---------------------------------------------------------------- main capture

def build_main():
    c = Cap()
    ctx = c.ctx

    # ------------------------------------------------ encapsulation commands (TCP)
    c.t(True, encap(0x65, u16(1) + u16(0), session=0), 'Register Session (request)')
    c.t(False, encap(0x65, u16(1) + u16(0)), 'Register Session (response)')
    c.t(True, encap(0x04, b'', context=1), 'List Services (request)')
    c.t(False, encap(0x04, cpf((0x100, u16(1) + u16(0x0120) + b'Communications\0\0')), context=1),
        'List Services (response)')
    ident = (u16(1) + sockaddr(44818, SRV_IP) + u16(1) + u16(12) + u16(34) + bytes([3, 5])
             + u16(0x0030) + u32(0x11223344) + sstr('Example Adapter') + u8(3))
    secinfo = u16(0x0003) + u8(3) + u8(2) + u8(0x05)
    c.t(True, encap(0x63, b'', context=2), 'List Identity (request)')
    c.t(False, encap(0x63, cpf((0x0C, ident), (0x86, secinfo), (0x87, u32(1))), context=2),
        'List Identity (response, identity, CIP security and capability items)')
    c.t(True, encap(0x64, b'', context=3), 'List Interfaces (request)')
    c.t(False, encap(0x64, cpf(), context=3), 'List Interfaces (response, no items)')
    c.t(True, encap(0x00, b'\x01\x02\x03\x04', session=0), 'NOP with data')
    c.t(True, encap(0xAB, b'\xde\xad\xbe\xef'), 'Unknown command')
    c.t(False, encap(0x6F, srrd([(0, b''), (0xB2, b'')]), status=0x65, context=4),
        'SendRRData with an empty Unconnected Data item and an error status')

    # ------------------------------------------------ encapsulation over UDP 44818
    c.udp(CLI_IP, (192, 0, 2, 255), 50100, ENIP_PORT, encap(0x63, b'', session=0, context=0x0010_0000_0000),
          'List Identity broadcast (UDP request)')
    c.udp(SRV_IP, CLI_IP, ENIP_PORT, 50100, encap(0x63, cpf((0x0C, ident)), session=0, context=0x0010_0000_0000),
          'List Identity (UDP response)', rev=True)
    c.udp(CLI_IP, SRV_IP, ENIP_PORT, ENIP_PORT, encap(0x63, b'', session=0), 'List Identity between two 44818 ports')
    c.udp(SRV_IP, CLI_IP, ENIP_PORT, ENIP_PORT, encap(0x63, cpf((0x0C, ident)), session=0),
          'List Identity response between two 44818 ports (not classified)', rev=True)
    c.udp(CLI_IP, SRV_IP, 50101, ENIP_PORT, encap(0x04, b''), 'List Services (UDP request)')
    c.udp(SRV_IP, CLI_IP, ENIP_PORT, 50101, encap(0x04, cpf((0x100, u16(1) + u16(0x0120) + b'Communications\0\0'))),
          'List Services (UDP response)', rev=True)
    c.udp(CLI_IP, SRV_IP, 50102, ENIP_PORT, b'\x63\x00', 'UDP payload shorter than 4 octets (not ENIP)')

    # ------------------------------------------------ CIP object attributes
    tables = [
        (0xF5, 1, TCPIP, 'TCP/IP Interface'),
        (0xF6, 1, ELINK, 'Ethernet Link'),
        (0x48, 1, QOS, 'QoS'),
        (0x47, 1, DLR, 'DLR'),
        (0x56, 1, PRP, 'PRP/HSR'),
        (0x57, 1, [(1, u32(2))], 'PRP/HSR Nodes Table'),
        (0x109, 1, LLDP_MGMT, 'LLDP Management'),
        (0x10A, 1, LLDP_TBL, 'LLDP Data Table'),
        (0x5D, 1, CIPSEC, 'CIP Security'),
        (0x5E, 1, EIPSEC, 'EtherNet/IP Security'),
        (0x5F, 1, CERT_INST, 'Certificate Management'),
        (0x5F, 0, CERT_CLASS, 'Certificate Management class'),
        (0x63, 1, INGRESS_INST, 'Ingress Egress'),
        (0x63, 0, INGRESS_CLASS, 'Ingress Egress class'),
    ]
    for cl, i, items, name in tables:
        c.pair(gal(cl, i, [a for a, _ in items]), gal_rsp(items), name + ' Get_Attribute_List')
        if (cl, i == 0) in GAA_ORDER:
            c.pair(gaa(cl, i), rsp(0x01, gaa_data(items, cl, i)), name + ' Get_Attributes_All')
    for cl, name in ((0xF5, 'TCP/IP'), (0xF6, 'Ethernet Link'), (0x48, 'QoS'), (0x47, 'DLR')):
        c.pair(gal(cl, 0, [1, 2, 3, 4, 5, 6, 7]), gal_rsp(class_attrs()), name + ' class attributes')
        c.pair(gaa(cl, 0), rsp(0x01, b''.join(d for _, d in class_attrs())), name + ' class Get_Attributes_All')
    # Attributes that need the whole response: participants list, last
    # conflict with an ARP PDU, LLDP values in their reserved ranges
    c.pair(req(0x0E, cls(0x47) + inst(1) + att(9)), rsp(0x0E, DLR_PARTICIPANTS),
           'DLR Ring Protocol Participants List')
    c.pair(req(0x0E, cls(0x47) + inst(1) + att(9)), rsp(0x0E, b''),
           'DLR Ring Protocol Participants List, empty')
    c.pair(req(0x0E, cls(0xF5) + inst(1) + att(11)), rsp(0x0E, u8(1) + MAC_B + arp_pdu()),
           'TCP/IP Last Conflict Detected with an ARP PDU')
    c.pair(req(0x0E, cls(0x10A) + inst(1) + att(8)), rsp(0x0E, u8(1) + u8(0) + u8(1) + u8(7)),
           'LLDP Additional Ethernet Capabilities, reserved fragment size')
    c.pair(req(0x0E, cls(0x10A) + inst(1) + att(11)), rsp(0x0E, u8(5) + u8(1)),
           'LLDP T1S PHY Configuration, reserved mode')
    c.pair(req(0x0E, cls(0x109) + inst(1) + att(1)), rsp(0x0E, u16(0)),
           'LLDP Enable with an empty array')
    c.pair(req(0x0E, cls(0xF5) + inst(1) + att(6)), rsp(0x0E, cip_string('plc')),
           'TCP/IP Host Name, odd length (padded)')
    # Set_Attribute_List with the LLDP attributes followed by another
    # attribute: the reproducer of the LLDP attribute length fix
    c.pair(sal(0x10A, 1, [(5, u16(0x11) + u16(0x22)), (10, u16(0x4242))]), sal_rsp([5, 10]),
           'Set_Attribute_List LLDP Data Table: System Capabilities, Position ID')
    c.pair(sal(0x109, 1, [(1, u16(3) + bytes([0x05])), (2, u16(0x001E))]), sal_rsp([1, 2]),
           'Set_Attribute_List LLDP Management: LLDP Enable, msgTxInterval')
    lldp_items = [(a, d) for a, d in LLDP_TBL if a in (6, 7, 8, 9, 11)] + [(10, u16(0x4343))]
    c.pair(sal(0x10A, 1, lldp_items), sal_rsp([a for a, _ in lldp_items]),
           'Set_Attribute_List LLDP Data Table: every handler, then Position ID')
    c.pair(req(0x10, cls(0xF5) + inst(1) + att(13), u16(60)), rsp(0x10), 'TCP/IP Set_Attribute_Single')

    # ------------------------------------------------ ENIP object services
    services = [
        (req(0x4B, cls(0x47) + inst(1)), rsp(0x4B), 'DLR Verify_Fault_Location'),
        (req(0x4C, cls(0x47) + inst(1)), rsp(0x4C), 'DLR Clear_Rapid_Faults'),
        (req(0x4D, cls(0x47) + inst(1)), rsp(0x4D), 'DLR Restart_Sign_On'),
        (req(0x4E, cls(0x47) + inst(1)), rsp(0x4E), 'DLR Clear_Gateway_Partial_Fault'),
        (req(0x4B, cls(0x5D) + inst(1)), rsp(0x4B), 'CIP Security Begin_Config'),
        (req(0x4C, cls(0x5D) + inst(1)), rsp(0x4C), 'CIP Security Kick_Timer'),
        (req(0x4D, cls(0x5D) + inst(1)), rsp(0x4D), 'CIP Security End_Config'),
        (req(0x4E, cls(0x5D) + inst(1)), rsp(0x4E), 'CIP Security Object_Cleanup'),
        (req(0x4B, cls(0x5E) + inst(1)), rsp(0x4B), 'EtherNet/IP Security Begin_Config'),
        (req(0x4C, cls(0x5E) + inst(1)), rsp(0x4C), 'EtherNet/IP Security Kick_Timer'),
        (req(0x4D, cls(0x5E) + inst(1), u16(0x0001) + u16(10)), rsp(0x4D), 'EtherNet/IP Security Apply_Config'),
        (req(0x4D, cls(0x5E) + inst(1), u16(0x0002) + u16(0)), rsp(0x4D, b'\x00\x00'),
         'EtherNet/IP Security Apply_Config, response with data'),
        (req(0x4E, cls(0x5E) + inst(1)), rsp(0x4E), 'EtherNet/IP Security Abort_Config'),
        (req(0x08, cls(0x5F) + inst(0), sstr('NewCert')), rsp(0x08, u16(3)), 'Certificate Management Create'),
        (req(0x4B, cls(0x5F) + inst(1), b''.join(sstr(s) for s in
                                                ('device', 'Example', 'Unit', 'Town', 'State', 'US',
                                                 'dev@example.com', '0001'))),
         rsp(0x4B, padded_epath_usint(cls(0x37) + inst(5))), 'Certificate Management Create CSR (8 names)'),
        (req(0x4B, cls(0x5F) + inst(1), b''.join(sstr(s) for s in
                                                ('device', 'Example', 'Unit', 'Town', 'State', 'US',
                                                 'dev@example.com', '0001', 'extra'))),
         rsp(0x4B, padded_epath_usint(cls(0x37) + inst(6))), 'Certificate Management Create CSR (9 names)'),
        (req(0x4C, cls(0x5F) + inst(1), u16(1)), rsp(0x4C, b'\x00\x00'), 'Certificate Management Verify_Certificate'),
        (req(0x4B, cls(0x63) + inst(0), u32(6) + u32(1) + u16(2)
             + u16(1) + u16(1) + sstr('permit udp any 2222') + u16(0)
             + u16(2) + u16(0) + u16(1) + sstr('deny all')),
         rsp(0x4B, b'\x00\x00'), 'Ingress Egress Set_Rules'),
        (req(0x4C, cls(0xF5) + inst(1), port_admin(False)), rsp(0x4C, b'\x00\x00'), 'TCP/IP Set_Port_Admin_State'),
        (req(0x4D, cls(0xF5) + inst(1), protocol_admin(False)), rsp(0x4D, b'\x00\x00'),
         'TCP/IP Set_Protocol_Admin_State'),
    ]
    for rq, rs, label in services:
        c.pair(rq, rs, label)
    # A request that is never answered, a response on another interface
    # handle (not CIP), an unknown and an empty CPF item
    c.ctx += 1
    c.t(True, encap(0x6F, srrd([(0, b''), (0xB2, gaa(0xF5, 1))]), context=c.ctx), 'Request without a response')
    c.ctx += 1
    c.t(True, encap(0x6F, srrd([(0, b''), (0xB2, b'\x01\x02\x03\x04')], iface=0x1234), context=c.ctx),
        'SendRRData on a vendor interface handle (not CIP)')
    c.t(True, encap(0x6F, srrd([(0, b''), (0x99, b'\xaa\xbb'), (0x88, b'')]), context=c.ctx + 1),
        'SendRRData with an unknown and an empty item')
    c.ctx += 1

    # ------------------------------------------------ connections
    mr_path = cls(2) + inst(1)
    # Class 3 to the Message Router, with sockaddr items (not Forward Open)
    c.pair(fwd_open(0x80000001, 0x00010001, 0x0101, mr_path, ot_params=0x43F4, to_params=0x43F4, ttt=0xA3),
           fwd_open_rsp(0x80000001, 0x00010001, 0x0101), 'Forward Open class 3 (Message Router)')
    c.sud(True, 0x80000001, 1, req(0x0E, cls(0xF5) + inst(1) + att(6)), 'Class 3 request (Host Name)')
    c.sud(False, 0x00010001, 1, rsp(0x0E, cip_string('plc-1')), 'Class 3 response')
    c.sud(True, 0x80000001, 2, gaa(0xF6, 1), 'Class 3 request with a sockaddr item',
          extra=[(0x8000, sockaddr(2222, CLI_IP))])
    c.sud(False, 0x00010001, 2, rsp(0x01, gaa_data(ELINK, 0xF6, 1)), 'Class 3 response (Ethernet Link GAA)')
    c.sud(True, 0x7777, 4, gaa(1, 1), 'SendUnitData on an unknown connection (CIP by default)')
    c.pair(fwd_close(0x0101, mr_path), fwd_close_rsp(0x0101), 'Forward Close class 3')
    # Class 3 to an assembly (implicit)
    c.pair(fwd_open(0x80000002, 0x00010002, 0x0102, cls(4) + inst(1) + cpt(0x65), ttt=0xA3),
           fwd_open_rsp(0x80000002, 0x00010002, 0x0102), 'Forward Open class 3 (assembly)')
    c.sud(True, 0x80000002, 1, b'\x01\x02\x03\x04', 'Class 3 data to an assembly')
    c.sud(False, 0x00010002, 1, b'\x05\x06', 'Class 3 data from an assembly')

    # Class 1 point to point O->T, multicast T->O; the request carries an
    # O->T sockaddr item, the response a T->O one (multicast group)
    io_path = ekey(4) + cls(4) + inst(1) + cpt(0x96) + cpt(0x64)
    c.pair(fwd_open(0x80000003, 0x00010003, 0x0103, io_path, ot_params=0x4814, to_params=0x2814, ttt=0x01),
           fwd_open_rsp(0x80000003, 0x00010003, 0x0103),
           'Forward Open class 1 with sockaddr items',
           items_req=[(0x8000, sockaddr(2222, (0, 0, 0, 0)))],
           items_rsp=[(0x8001, sockaddr(2222, (239, 192, 1, 1)))])
    for k in range(3):
        c.io(True, 0x80000003, k + 1, u16(k + 1) + u32(1) + bytes(range(16)), 'Class 1 I/O O->T')
        c.io(False, 0x00010003, k + 1, u16(k + 1) + bytes(range(16, 32)), 'Class 1 I/O T->O (multicast)',
             dst=(239, 192, 1, 1))
    c.pair(fwd_close(0x0103, io_path), fwd_close_rsp(0x0103), 'Forward Close class 1')
    # Class 1 with a fixed O->T size of 2: a heartbeat
    c.pair(fwd_open(0x80000004, 0x00010004, 0x0104, cls(4) + inst(1) + cpt(0xC6) + cpt(0x65),
                    ot_params=0x4802, to_params=0x4808, ttt=0x01),
           fwd_open_rsp(0x80000004, 0x00010004, 0x0104), 'Forward Open class 1 input only (heartbeat)')
    c.io(True, 0x80000004, 1, u16(1), 'Class 1 heartbeat O->T')
    c.io(False, 0x00010004, 1, u16(1) + bytes(6), 'Class 1 I/O T->O')
    # Class 0
    c.pair(fwd_open(0x80000005, 0x00010005, 0x0105, cls(4) + inst(2) + cpt(0x70) + cpt(0x71),
                    ot_params=0x4806, to_params=0x4806, ttt=0x00),
           fwd_open_rsp(0x80000005, 0x00010005, 0x0105), 'Forward Open class 0')
    c.io(True, 0x80000005, 1, b'\x11\x22\x33\x44\x55\x66', 'Class 0 I/O O->T')
    c.io(False, 0x00010005, 1, b'\x77\x88\x99\xaa\xbb\xcc', 'Class 0 I/O T->O')
    # Motion axis connection (cip.io.iface table: CIP Motion)
    c.pair(fwd_open(0x80000006, 0x00010006, 0x0106, ekey(4) + cls(0x42) + inst(1) + cpt(2), ttt=0x01,
                    ot_params=0x4A00 | 20, to_params=0x4A00 | 20),
           fwd_open_rsp(0x80000006, 0x00010006, 0x0106), 'Forward Open motion axis')
    c.io(True, 0x80000006, 1, u16(1) + bytes([0x02, 0x00, 0x00, 0x00]) + bytes(16), 'Motion I/O O->T')
    # Concurrent connection: CC packets, one with no data (a heartbeat),
    # and one followed by a further CPF item (decoded from the right
    # offset since the CPF length fix)
    hops = u8(1) + u8(0) + bytes([1, 0x01, 3])
    ccseg = bytes([0x5F, (len(hops) + 2) // 2 + (len(hops) % 2)]) + u16(0x0002) + hops + (b'\0' if len(hops) % 2 else b'')
    cc_path = ccseg + cls(4) + inst(1) + cpt(0x98) + cpt(0x66)
    c.pair(fwd_open(0x80000008, 0x00010008, 0x0108, cc_path, ot_params=0x4814, to_params=0x2814,
                    ttt=0x01, service=0x5C, cc_version=1),
           fwd_open_rsp(0x80000008, 0x00010008, 0x0108, service=0x5C), 'Concurrent Forward Open')
    c.io(True, 0x80000008, 1, cc_packet(1, u16(1) + u32(1) + b'\x11\x22'), 'Concurrent connection I/O O->T')
    c.io(False, 0x00010008, 1, cc_packet(1, u16(1) + b'\x33\x44'), 'Concurrent connection I/O T->O')
    c.io(True, 0x80000008, 3, cc_packet(3, u16(3) + u32(1) + b'\x55\x66'),
         'Concurrent connection I/O followed by a sockaddr item',
         extra=[(0x8000, sockaddr(2222, CLI_IP))])
    c.pair(fwd_close(0x0108, cc_path, service=0x5E), fwd_close_rsp(0x0108, service=0x5E),
           'Concurrent Forward Close')
    # Class 0 concurrent connection: a CC packet without data is a heartbeat
    c.pair(fwd_open(0x8000000A, 0x0001000A, 0x010B, cc_path, ot_params=0x4814, to_params=0x2814,
                    ttt=0x00, service=0x5C, cc_version=1),
           fwd_open_rsp(0x8000000A, 0x0001000A, 0x010B, service=0x5C), 'Concurrent Forward Open class 0')
    c.io(True, 0x8000000A, 1, cc_packet(1, b''), 'Concurrent connection class 0 without data (heartbeat)')
    c.io(False, 0x0001000A, 1, cc_packet(1, b'\x01\x02'), 'Concurrent connection class 0 T->O')
    # Null Forward Open (no connection)
    c.pair(fwd_open(0, 0, 0x0109, cls(4) + inst(1), ot_params=0, to_params=0, ttt=0x01),
           fwd_open_rsp(0, 0, 0x0109), 'Null Forward Open')
    # I/O on a connection that was never opened
    c.io(True, 0x12121212, 1, b'\x01\x02\x03\x04', 'I/O on an unknown connection')
    # Class 1 with a variable O->T size: two octets are not a heartbeat;
    # an empty connection path
    c.pair(fwd_open(0x8000000B, 0x0001000B, 0x010C, b'', ot_params=0x4A02, to_params=0x4A08, ttt=0x01),
           fwd_open_rsp(0x8000000B, 0x0001000B, 0x010C), 'Forward Open class 1, variable size, no path')
    c.io(True, 0x8000000B, 1, u16(1), 'Class 1 I/O O->T, sequence count only (variable size)')
    # T->O data sent to another port than 2222: found by the source port
    c.udp(SRV_IP, CLI_IP, IO_PORT, 50555, cpf((0x8002, u32(0x0001000B) + u32(1)), (0xB1, u16(1) + bytes(8))),
          'Class 1 I/O T->O to port 50555', rev=True)
    # I/O between hosts without any conversation, and with a UDP
    # conversation (from an unconnected message) but no connections
    o1, o2, o3, o4 = (198, 51, 100, 1), (198, 51, 100, 2), (198, 51, 100, 3), (198, 51, 100, 4)
    c.udp(o1, o2, IO_PORT, IO_PORT, cpf((0x8002, u32(0x0A0A0A0A) + u32(1)), (0xB1, b'\x01\x02')),
          'I/O between hosts without a conversation')
    c.udp(o3, o4, IO_PORT, IO_PORT, cpf((0x8003, u16(0) + u32(0x77) + u32(0) + req(0x0E, cls(1) + inst(1) + att(1)))),
          'Unconnected message over UDP without a response')
    c.udp(o3, o4, IO_PORT, IO_PORT, cpf((0x8002, u32(0x0B0B0B0B) + u32(1)), (0xB1, b'\x01\x02')),
          'I/O on a conversation without connections')
    # Forward Close of a connection that was never opened
    c.pair(fwd_close(0x0EEE, cls(4) + inst(1), vendor=0x4321), fwd_close_rsp(0x0EEE, vendor=0x4321),
           'Forward Close of an unknown connection')
    # SendUnitData: the response side using the O->T connection ID, on a
    # TCP connection without any CIP connection, between two 44818 ports
    c.pair(fwd_open(0x8000000C, 0x0001000C, 0x010D, mr_path, ot_params=0x43F4, to_params=0x43F4, ttt=0xA3),
           fwd_open_rsp(0x8000000C, 0x0001000C, 0x010D), 'Forward Open class 3 (second)')
    c.sud(True, 0x8000000C, 1, gaa(1, 1), 'Class 3 request')
    c.sud(False, 0x8000000C, 1, rsp(0x01, b''), 'Class 3 response with the O->T connection ID')
    sx = TcpStream(50002, 210000, 610000)
    c.sud(True, 0x8000000C, 9, gaa(1, 1), 'SendUnitData on a TCP connection without CIP connections', stream=sx)
    s44 = TcpStream(44818, 220000, 620000)
    c.sud(True, 0x8000000C, 10, gaa(1, 1), 'SendUnitData between two 44818 ports', stream=s44)
    # Unconnected message over UDP (CPF item 0x8003) request and response
    ucmm_req = u16(0x0000) + u32(0x55AA0001) + u32(0) + req(0x0E, cls(0xF6) + inst(1) + att(3))
    ucmm_rsp = u16(0x8000) + u32(0x55AA0001) + u32(0) + rsp(0x0E, MAC_A)
    c.udp(CLI_IP, SRV_IP, IO_PORT, IO_PORT, cpf((0x8003, ucmm_req)), 'Unconnected message over UDP (request)')
    c.udp(SRV_IP, CLI_IP, IO_PORT, IO_PORT, cpf((0x8003, ucmm_rsp)), 'Unconnected message over UDP (response)',
          rev=True)
    # Class 1 over IPv6 (conversation with an IPv6 address)
    s6 = Tcp6Stream(50010)
    c.ctx += 1
    c.t(True, encap(0x6F, srrd([(0, b''), (0xB2, fwd_open(0x80000009, 0x00010009, 0x010A, cls(4) + inst(3)
                                                          + cpt(0x67) + cpt(0x68), ot_params=0x4806,
                                                          to_params=0x4806, ttt=0x01))]), context=c.ctx),
        'Forward Open class 1 over IPv6 (request)', s6)
    c.t(False, encap(0x6F, srrd([(0, b''), (0xB2, fwd_open_rsp(0x80000009, 0x00010009, 0x010A))]), context=c.ctx),
        'Forward Open class 1 over IPv6 (response)', s6)
    c.add(udp6_frame(CLI_IP6, SRV_IP6, IO_PORT, IO_PORT,
                     cpf((0x8002, u32(0x80000009) + u32(1)), (0xB1, u16(1) + u32(1) + b'\x01\x02'))),
          'Class 1 I/O over IPv6 O->T')

    # ------------------------------------------------ TCP segmentation
    st = TcpStream(50001, 200000, 600000)
    c.ctx += 1
    pdu = encap(0x6F, srrd([(0, b''), (0xB2, gaa(0xF6, 1))]), context=c.ctx)
    rsp_pdu = encap(0x6F, srrd([(0, b''), (0xB2, rsp(0x01, gaa_data(ELINK, 0xF6, 1)))]), context=c.ctx)
    c.t(True, pdu, 'Request in one segment', st)
    c.t(False, rsp_pdu[:40], 'Response, first segment', st)
    c.t(False, rsp_pdu[40:], 'Response, second segment (reassembled)', st)
    two = encap(0x65, u16(1) + u16(0), session=0) + encap(0x66, b'')
    c.t(True, two, 'Register and Unregister Session in one segment', st)
    c.t(True, b'\x00', 'One octet TCP payload (keep-alive, not ENIP)', st)

    # ------------------------------------------------ DLR (ethertype 0x80E1)
    def dlr(frame_type, body, seq):
        hdr = bytes([1, 1, frame_type, 1]) + bytes([192, 0, 2, 40]) + struct.pack('>I', seq)
        d = hdr + body
        d += bytes(max(0, 46 - len(d)))
        return bytes.fromhex('01214c000001') + MAC_A + b'\x80\xe1' + d
    dlr_frames = [
        (1, bytes([1, 5]) + struct.pack('>II', 400, 1960) + bytes(20)),
        (2, bytes(30)),
        (3, bytes([1]) + bytes(29)),
        (4, bytes([0x83]) + bytes(29)),
        (5, bytes(30)),
        (6, bytes([2]) + bytes(29)),
        (7, struct.pack('>H', 2) + MAC_A + bytes([192, 0, 2, 41]) + MAC_B + bytes([192, 0, 2, 42]) + bytes(8)),
        (7, struct.pack('>H', 3) + (MAC_A + bytes([192, 0, 2, 41])) * 3),
        (8, bytes([1, 3]) + struct.pack('>II', 2000, 5000) + bytes([1]) + bytes(19)),
        (9, bytes([1]) + bytes(29)),
        (10, bytes(34)),
        (0x20, bytes(30)),
    ]
    for k, (ft, body) in enumerate(dlr_frames):
        c.add(dlr(ft, body, 100 + k), 'DLR frame type %d' % ft)

    # ------------------------------------------------ LLDP with ODVA TLVs
    def tlv(t, v):
        return struct.pack('>H', (t << 9) | len(v)) + v
    odva = b'\x00\x21\x6c'
    lldp = (tlv(1, b'\x04' + MAC_A) + tlv(2, b'\x07' + b'port1') + tlv(3, struct.pack('>H', 120))
            + tlv(127, odva + b'\x01' + u16(1) + u16(12) + u16(34) + bytes([3, 5]) + u32(0x11223344))
            + tlv(127, odva + b'\x02' + MAC_A)
            + tlv(127, odva + b'\x03' + b'Port A')
            + tlv(127, odva + b'\x09' + struct.pack('>HHH', 1, 12, 34) + bytes([3, 5]) + struct.pack('>I', 0x11223344))
            + tlv(127, odva + b'\x04' + u16(3))
            + tlv(0, b''))
    c.add(bytes.fromhex('0180c200000e') + MAC_A + b'\x88\xcc' + lldp, 'LLDP with ODVA TLVs')

    # ------------------------------------------------ Start DTLS (last on its UDP conversation)
    c.udp(CLI_IP, SRV_IP, 50103, ENIP_PORT, encap(0xC8, b''), 'Start DTLS (request)')
    c.udp(SRV_IP, CLI_IP, ENIP_PORT, 50103, encap(0xC8, b''), 'Start DTLS (response)', rev=True)
    c.t(False, encap(0x66, b''), 'Unregister Session')
    del ctx
    return c


# ---------------------------------------------------------------- malformed capture

def build_malformed():
    c = Cap()
    c.tcp = TcpStream(51000, 300000, 700000)
    # The reproducers of "ENIP: Check CPF item lengths ...": an Unconnected
    # Message over UDP item of 9 octets, a Connected Data item of 1 octet,
    # a concurrent connection item shorter than its header and CRC
    cip = req(0x0E, cls(1) + inst(1) + att(1))
    ucmm = struct.pack('<HII', 0, 0x11223344, 0)
    c.udp(CLI_IP, SRV_IP, IO_PORT, IO_PORT,
          u16(2) + u16(0x8003) + u16(9) + ucmm + cip + u16(0) + u16(0), 'UCMM item of 9 octets')
    c.t(True, encap(0x70, u32(0) + u16(0) + u16(2) + u16(0xA1) + u16(4) + u32(0x01020304)
                    + u16(0xB1) + u16(1) + u16(7) + cip), 'Connected Data item of 1 octet')
    hops = u8(1) + u8(0) + bytes([1, 0x01, 3])
    ccseg = bytes([0x5F, (len(hops) + 2) // 2 + 1]) + u16(0x0002) + hops + b'\0'
    cc_path = ccseg + cls(4) + inst(1) + cpt(0x98) + cpt(0x66)
    c.pair(fwd_open(0x80000101, 0x00010101, 0x0201, cc_path, ot_params=0x4814, to_params=0x2814,
                    ttt=0x01, service=0x5C, cc_version=1),
           fwd_open_rsp(0x80000101, 0x00010101, 0x0201, service=0x5C), 'Concurrent Forward Open')
    c.io(True, 0x80000101, 1, u16(1) + u16(8) + u32(1), 'Concurrent connection item without its CRC',
         extra=[(0x8000, sockaddr(2222, CLI_IP))])
    c.io(True, 0x80000101, 2, u16(1) + u16(8) + u32(2), 'Concurrent connection item without its CRC, at the end')
    # Connected data item whose data is missing
    c.udp(CLI_IP, SRV_IP, IO_PORT, IO_PORT, u16(2) + u16(0x8002) + u16(8) + u32(0x0C0C0C0C) + u32(3)
          + u16(0xB1) + u16(4), 'Connected data item without data')
    # Get_Attribute_List responses whose last attribute has no data
    for cl, a in ((0x5E, 3), (0x5E, 4), (0x5E, 5), (0x5E, 6), (0x10A, 6)):
        c.pair(gal(cl, 1, [a]), rsp(0x03, u16(1) + u16(a) + u16(0)),
               'Get_Attribute_List class 0x%x attribute %d without data' % (cl, a))
    # Class 3 connection to the Message Router: a connected data item with
    # only the sequence count (CIP is called with no data)
    c.pair(fwd_open(0x80000103, 0x00010103, 0x0203, cls(2) + inst(1), ot_params=0x43F4, to_params=0x43F4, ttt=0xA3),
           fwd_open_rsp(0x80000103, 0x00010103, 0x0203), 'Forward Open class 3')
    c.sud(True, 0x80000103, 1, b'', 'Class 3 sequence count only')
    # Safety connection (CIP Safety dissector); the I/O packet has no
    # valid safety CRC, so the CIP Safety dissector reports errors
    unid = u32(0x01020304) + u16(5) + u32(0x00000010)
    sseg = (u8(2) + u8(0) + u32(0x11223344) + u32(5000) + u16(9000) + u32(20000) + u16(0x4803) + unid + unid
            + u16(4) + u16(4) + u16(100) + u8(2) + u8(1) + u16(10) + u32(0xAABBCCDD) + u32(0x00020001)
            + u16(7) + u16(8))
    sseg = bytes([0x50, (len(sseg) + 1) // 2]) + sseg + (b'\0' if len(sseg) % 2 else b'')
    spath = sseg + cls(0x3A) + inst(1) + cpt(0x80)
    c.pair(fwd_open(0x80000007, 0x00010007, 0x0107, spath, ot_params=0x4806, to_params=0x2806, ttt=0x01),
           fwd_open_rsp(0x80000007, 0x00010007, 0x0107,
                        app=u16(1) + u16(0x1234) + u32(0x55667788) + u16(0x0107) + u16(10) + u16(20)),
           'Forward Open safety')
    c.io(False, 0x00010007, 1, u16(1) + bytes([0x01, 0x22, 0x33, 0x44, 0x55, 0x66]), 'Safety I/O T->O')
    # Attributes cut short (every length check)
    short = [
        (0xF5, 1), (0xF5, 2), (0xF5, 3), (0xF5, 5), (0xF5, 7), (0xF5, 9), (0xF5, 11),
        (0xF6, 2), (0xF6, 3), (0xF6, 4), (0xF6, 5), (0xF6, 6),
        (0x47, 4), (0x47, 6), (0x47, 7), (0x47, 9), (0x47, 10), (0x47, 12), (0x47, 13), (0x47, 15),
        (0x5E, 2), (0x5E, 3), (0x5E, 4), (0x5E, 5), (0x5E, 6), (0x5E, 7), (0x5E, 8), (0x5E, 12),
        (0x109, 4), (0x10A, 5), (0x10A, 6), (0x10A, 7), (0x10A, 8), (0x10A, 9), (0x10A, 11),
    ]
    for cl, a in short:
        data = b'' if (cl, a) in ((0x5E, 3), (0x5E, 4), (0x5E, 5), (0x5E, 6), (0x5E, 7), (0x5E, 8),
                                 (0x5E, 12), (0x10A, 6)) else b'\x01'
        if (cl, a) == (0x47, 9):
            data = bytes(7)
        c.pair(req(0x0E, cls(cl) + inst(1) + att(a)), rsp(0x0E, data), 'class 0x%x attribute %d cut short' % (cl, a))
    c.pair(req(0x0E, cls(0x5F) + inst(0) + att(8)), rsp(0x0E, b'\x01'), 'Certificate capability flags cut short')
    # Pre-Shared Keys with sizes larger than the attribute
    c.pair(req(0x0E, cls(0x5E) + inst(1) + att(5)), rsp(0x0E, u8(1) + u8(20) + b'ab'), 'PSK identity too long')
    c.pair(req(0x0E, cls(0x5E) + inst(1) + att(5)), rsp(0x0E, u8(1) + u8(1) + b'a' + u8(30) + b'b'),
           'PSK too long')
    # CPF: fewer octets than an item header, item longer than the data
    c.t(True, encap(0x6F, u32(0) + u16(0) + u16(3) + u16(0) + u16(0) + b'\x01'), 'CPF item count larger than the data')
    c.t(True, encap(0x6F, u32(0) + u16(0) + u16(1) + u16(0x99) + u16(40) + b'\x01\x02'), 'CPF item longer than the data')
    # Encapsulation header cut short (UDP) and a List Identity item cut short
    c.udp(CLI_IP, SRV_IP, 50200, ENIP_PORT, b'\x63\x00\x00\x00\x00', 'encapsulation header cut short')
    c.udp(SRV_IP, CLI_IP, ENIP_PORT, 50200, encap(0x63, cpf((0x0C, u16(1) + bytes(10)))), 'identity item cut short',
          rev=True)
    # DLR frame cut short
    c.add(bytes.fromhex('01214c000001') + MAC_A + b'\x80\xe1' + bytes([1, 1, 7, 1]), 'DLR frame cut short')
    # Forward Open reply on TCP port 2221 (decoded as ENIP by runcov.sh
    # with Decode As): I/O defaults to port 2221
    s2221 = TcpStream(51001, 400000, 800000, sport=2221)
    c.ctx += 1
    c.t(True, encap(0x6F, srrd([(0, b''), (0xB2, fwd_open(0x80000102, 0x00010102, 0x0202, cls(4) + inst(1)
                                                          + cpt(0x65) + cpt(0x66), ot_params=0x4806,
                                                          to_params=0x4806, ttt=0x01))]), context=c.ctx),
        'Forward Open on TCP 2221 (request)', s2221)
    c.t(False, encap(0x6F, srrd([(0, b''), (0xB2, fwd_open_rsp(0x80000102, 0x00010102, 0x0202))]), context=c.ctx),
        'Forward Open on TCP 2221 (response)', s2221)
    return c


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    m = build_main()
    write_pcap(os.path.join(out, 'enip-coverage.pcap'), m.frames)
    with open(os.path.join(out, 'enip-coverage.frames.txt'), 'w') as f:
        for i, l in enumerate(m.labels):
            f.write('%d\t%s\n' % (i + 1, l))
    b = build_malformed()
    write_pcap(os.path.join(out, 'enip-coverage-malformed.pcap'), b.frames)
    with open(os.path.join(out, 'enip-coverage-malformed.frames.txt'), 'w') as f:
        for i, l in enumerate(b.labels):
            f.write('%d\t%s\n' % (i + 1, l))


if __name__ == '__main__':
    main()
