#!/usr/bin/env python3
# Generates test/captures/cdp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Cisco Discovery Protocol
dissector (packet-cdp.c).

CDP is carried in IEEE 802.3 frames with an LLC/SNAP header (OUI
00:00:0c, PID 0x2000) to 01:00:0c:cc:cc:cc. The PDU is a version, a TTL,
a 16 bit checksum (the Internet checksum, with Cisco's quirk for odd
lengths) and a list of type/length/value records whose length includes
the 4 octet TLV header. Every packet is built from scratch with struct;
no captured traffic is used.

Usage: mkcdp.py <output directory>

Writes:
  cdp-coverage.pcap            every TLV the dissector knows (Cisco and HP
                               ones), the address, EnergyWise and power
                               sub-structures, the Port ID length heuristic,
                               odd length checksums, and the reproducers of
                               the fixes on the branch
  cdp-coverage-malformed.pcap  bad checksums, invalid EnergyWise TLVs and
                               TLVs too short for their fixed fields
"""

import os
import struct
import sys

SRC_MAC = bytes.fromhex('020000000001')
CDP_MAC = bytes.fromhex('01000ccccccc')


def tlv(t, v):
    return struct.pack('>HH', t, 4 + len(v)) + v


def raw_tlv(t, length, v=b''):
    """A TLV with an explicit length field (may disagree with the value)."""
    return struct.pack('>HH', t, length) + v


def inet_sum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s >> 16) + (s & 0xffff)
    return ~s & 0xffff


def cdp_checksum(pdu):
    """The CDP checksum: for an odd length the last octet is put in the low
    octet of the last big endian word, and if it has the high bit set both
    octets of that word are decremented (packet-cdp.c lines 326-338)."""
    if len(pdu) % 2:
        last = pdu[-1]
        hi, lo = 0, last
        if lo & 0x80:
            lo -= 1
            hi = 0xff
        data = pdu[:-1] + bytes([hi, lo])
    else:
        data = pdu
    return inet_sum(data)


def cdp(tlvs, version=2, ttl=180, good=True):
    body = b''.join(tlvs)
    pdu = struct.pack('>BBH', version, ttl, 0) + body
    c = cdp_checksum(pdu) if good else 0x1234
    return pdu[:2] + struct.pack('>H', c) + pdu[4:]


def frame(payload, pid=0x2000):
    llc = bytes([0xaa, 0xaa, 0x03, 0, 0, 0x0c]) + struct.pack('>H', pid) + payload
    return CDP_MAC + SRC_MAC + struct.pack('>H', len(llc)) + llc


# Address records (dissect_address_tlv)
def addr(ptype, proto, address, alen=None):
    if alen is None:
        alen = len(address)
    return struct.pack('>BB', ptype, len(proto)) + proto + struct.pack('>H', alen) + address


SNAP = bytes.fromhex('aaaa03000000')
ADDR_IPV4 = addr(1, b'\xcc', bytes([192, 0, 2, 10]))
ADDR_IPV6 = addr(2, SNAP + b'\x86\xdd', bytes.fromhex('20010db8000000000000000000000001'))
# NLPID CLNP with a 20 octet NSAP (shown as bytes)
ADDR_CLNP = addr(1, b'\x81', bytes(range(0x39, 0x39 + 20)))
# NLPID IP with a 16 octet address (not 4: shown as bytes)
ADDR_IP16 = addr(1, b'\xcc', bytes(16))
# 802.2 with SNAP and an Ethertype that is not IPv6 (IPv4)
ADDR_SNAP_IP = addr(2, SNAP + b'\x08\x00', bytes([198, 51, 100, 7]))
# 802.2 with SNAP and Ethertype IPv6 but a 4 octet address
ADDR_SNAP_V6_SHORT = addr(2, SNAP + b'\x86\xdd', bytes([1, 2, 3, 4]))
# 802.2 with a protocol that is not SNAP
ADDR_8022_OTHER = addr(2, bytes.fromhex('e0e003'), bytes([0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7]))
# Unknown protocol type, empty address
ADDR_UNKNOWN_EMPTY = addr(9, b'\x01\x02', b'')
# 802.2 with SNAP and Ethertype 0 (etypeid 0 is skipped)
ADDR_SNAP_ZERO = addr(2, SNAP + b'\x00\x00', b'\xaa\xbb')


def addresses(t, records, count=None, extra=b''):
    if count is None:
        count = len(records)
    return tlv(t, struct.pack('>I', count) + b''.join(records) + extra)


def nrgyz_tlv(t, v):
    return struct.pack('>II', t, 8 + len(v)) + v


def energywise(subtlvs, length=None, num=None):
    table = b''.join(subtlvs)
    if length is None:
        length = len(table)
    if num is None:
        num = len(subtlvs)
    hdr = (bytes(range(1, 21))                    # encrypted data
           + struct.pack('>II', 7, 1234)          # seen sequence, sequence
           + b'WS-C3750X-48P\0\0\0'               # model number (16)
           + b'\0\0'                              # unknown pad
           + b'V02'                               # hardware version id
           + b'FDO1234X5YZ'                       # serial number (11)
           + bytes(8)                             # unknown values
           + struct.pack('>HH', length, num))
    return tlv(0x001d, hdr + table)


def cluster_hello():
    v = (bytes.fromhex('00000c') + struct.pack('>H', 0x0112)
         + bytes([10, 0, 0, 1]) + bytes([10, 0, 0, 2])
         + bytes([1, 2, 3, 4])                    # version, sub-version, status, unknown
         + bytes.fromhex('020000000aaa') + bytes.fromhex('020000000bbb')
         + b'\x00' + struct.pack('>H', 1))
    return tlv(0x0008, v)


def main_frames():
    M = []
    # 1: a typical switch: Device ID, addresses (IPv4 and IPv6), Port ID,
    #    capabilities (every bit), software version on several lines,
    #    platform, cluster management hello, VTP domain, native VLAN, full
    #    duplex, trust bitmap, untrusted CoS, system name, system OID,
    #    management addresses, location, MTU, power and spare pair PoE.
    M.append(cdp([
        tlv(0x0001, b'switch-1.example.net'),
        addresses(0x0002, [ADDR_IPV4, ADDR_IPV6]),
        tlv(0x0003, b'GigabitEthernet1/0/1'),
        tlv(0x0004, struct.pack('>I', 0x7ff)),
        tlv(0x0005, b'Cisco IOS Software, C3750E Software\nTechnical Support\r\nCopyright (c) 1986-2026\n'),
        tlv(0x0006, b'cisco WS-C3750X-48P'),
        cluster_hello(),
        tlv(0x0009, b'vtp-domain'),
        tlv(0x000a, struct.pack('>H', 1)),
        tlv(0x000b, b'\x01'),
        tlv(0x0012, b'\x00'),
        tlv(0x0013, b'\x05'),
        tlv(0x0014, b'switch-1'),
        tlv(0x0015, bytes.fromhex('060c2b060104010901010101')),
        addresses(0x0016, [ADDR_IPV4]),
        tlv(0x0017, b'\x00Building 1, Room 101'),
        tlv(0x0011, struct.pack('>I', 1500)),
        tlv(0x0010, struct.pack('>H', 15400)),
        tlv(0x001f, b'\x0f'),
    ]))
    # 2: an IP phone: VoIP VLAN reply and query in both forms, power
    #    requested and available with two values each, half duplex
    M.append(cdp([
        tlv(0x0001, b'SEP0200000000AA'),
        tlv(0x0003, b'Port 1'),
        tlv(0x0004, struct.pack('>I', 0x490)),
        tlv(0x000e, b'\x01' + struct.pack('>H', 100)),
        tlv(0x000e, b'\x20\x00'),
        tlv(0x000f, b'\x01' + struct.pack('>H', 200)),
        tlv(0x000f, b'\x20\x00'),
        tlv(0x000b, b'\x00'),
        tlv(0x0019, struct.pack('>HHII', 1, 2, 12950, 6300)),
        tlv(0x001a, struct.pack('>HHII', 1, 2, 15400, 6300)),
    ]))
    # 3: power TLVs with no values, too short for the values (< 8), and with
    #    two octets left after the values; capabilities and spare PoE too
    #    short for a value; an unknown Hello protocol
    M.append(cdp([
        tlv(0x0001, b'phone-2'),
        tlv(0x0019, struct.pack('>HH', 3, 4)),
        tlv(0x001a, struct.pack('>HH', 3, 4)),
        tlv(0x0019, struct.pack('>H', 5)),
        tlv(0x001a, struct.pack('>H', 5)),
        tlv(0x0019, struct.pack('>HHI', 6, 7, 7000) + b'\xee\xee'),
        tlv(0x001a, struct.pack('>HHI', 6, 7, 7000) + b'\xee\xee'),
        tlv(0x0004, b'\x01\x02'),
        tlv(0x001f, b''),
        tlv(0x0008, bytes.fromhex('00000c') + struct.pack('>H', 0x0200) + b'hello-data'),
    ]))
    # 4: ODR: default gateway (length 8) and a prefix list with two prefixes
    M.append(cdp([
        tlv(0x0001, b'odr-hub'),
        tlv(0x0007, bytes([192, 0, 2, 1])),
        tlv(0x0007, bytes([198, 51, 100, 0, 24, 203, 0, 113, 0, 25])),
    ]))
    # 5: every address form: CLNP NSAP, NLPID IP with a 16 octet address,
    #    802.2 SNAP IPv4, SNAP IPv6 with a 4 octet address, 802.2 non-SNAP,
    #    an unknown protocol type with an empty address, SNAP Ethertype 0;
    #    management addresses with none; then addresses whose count is
    #    larger than the records present (stops at the end of the TLV)
    M.append(cdp([
        tlv(0x0001, b'router-3'),
        addresses(0x0002, [ADDR_CLNP, ADDR_IP16, ADDR_SNAP_IP, ADDR_SNAP_V6_SHORT,
                           ADDR_8022_OTHER, ADDR_UNKNOWN_EMPTY, ADDR_SNAP_ZERO]),
        addresses(0x0016, []),
        addresses(0x0002, [ADDR_IPV4], count=3),
        addresses(0x0016, [ADDR_IPV4], count=2),
    ]))
    # 6: address records cut short inside the TLV (dissect_address_tlv's
    #    truncation checks; no exception): only the protocol type; protocol
    #    shorter than its length; protocol length past the end with no
    #    octets left; no room for the address length; address shorter than
    #    its length; address length past the end with no octets left
    M.append(cdp([
        tlv(0x0001, b'router-4'),
        addresses(0x0002, [b'\x01'], count=1),
        addresses(0x0002, [b'\x02\x08\xaa\xaa\x03'], count=1),
        addresses(0x0016, [b'\x02\x08'], count=1),
        addresses(0x0002, [b'\x01\x01\xcc\x00'], count=1),
        addresses(0x0016, [b'\x01\x01\xcc\x00\x04\xc0\x00'], count=1),
        addresses(0x0002, [b'\x01\x01\xcc\x00\x04'], count=1),
    ]))
    # 7: EnergyWise with role, domain, name, reply-to, an unknown sub-TLV
    #    with data and an empty one
    M.append(cdp([
        tlv(0x0001, b'switch-5'),
        energywise([
            nrgyz_tlv(7, b'role-a\0'),
            nrgyz_tlv(8, b'energy-domain'),
            nrgyz_tlv(9, b'switch-5'),
            nrgyz_tlv(0x17, struct.pack('>HH', 0, 43440) + bytes([192, 0, 2, 50])
                      + struct.pack('>H', 43441) + bytes([192, 0, 2, 51])),
            nrgyz_tlv(0x30, b'\x01\x02\x03'),
            nrgyz_tlv(0x31, b''),
        ]),
    ]))
    # 8: HP access point TLVs (0x1000-0x100D), an empty and a named SSID
    M.append(cdp([
        tlv(0x0001, b'hp-ap-1'),
        tlv(0x1000, b'02:00:00:00:00:aa'),
        tlv(0x1001, b'SG12345678'),
        tlv(0x1002, b''),
        tlv(0x1002, b'example-ssid'),
        tlv(0x1003, b'6'),
        tlv(0x1006, b'161'),
        tlv(0x1007, b'80'),
        tlv(0x1008, b'02:00:00:00:00:ab'),
        tlv(0x1009, b'36'),
        tlv(0x100a, b'AP'),
        tlv(0x100b, b'Monitor'),
        tlv(0x100c, b'802.11g'),
        tlv(0x100d, b'802.11a'),
    ]))
    # 9: named types without a dedicated case (External Port-ID, Port
    #    Unidirectional), unknown types with and without data, a TLV type 0
    M.append(cdp([
        tlv(0x0001, b'switch-6'),
        tlv(0x0018, b'ext-port'),
        tlv(0x001b, b'\x01'),
        tlv(0x00ff, b'\xde\xad\xbe\xef'),
        tlv(0x00fe, b''),
        tlv(0x0000, b'\x00'),
    ], version=1, ttl=0))
    # 10: Port ID whose next octet is neither 0x00 nor 0x10: the dissector
    #     takes the length as 3 octets short (real_length = length + 3)
    M.append(cdp([
        tlv(0x0001, b'switch-7'),
        tlv(0x0003, b'Fa0/1') + b'XYZ',
        tlv(0x0001, b'after'),
    ]))
    # 11: Port ID followed by an HP TLV (next octet 0x10) and by the end of
    #     the packet (fewer than length + 3 octets left)
    M.append(cdp([
        tlv(0x0003, b'Fa0/2'),
        tlv(0x1003, b'11'),
        tlv(0x0003, b'Fa0/3'),
    ]))
    # 12-13: odd lengths for Cisco's checksum quirk, last octet below and
    #        above 0x80
    M.append(cdp([tlv(0x0001, b'odd-1')]))
    M.append(cdp([tlv(0x0001, b'odd2'), tlv(0x0012, b'\xb2')]))
    # 14: reproducer cdp_tlv_issues frame 1 (fixed on the branch): an
    #     unknown TLV of length 4 followed by Device ID; with a tree the
    #     dissection used to stop at the short TLV
    M.append(cdp([raw_tlv(0x00ff, 4), tlv(0x0001, b'sw-one')]))
    # 15: reproducer cdp_tlv_issues frame 2 (fixed on the branch): an IP
    #     prefix TLV of length 6; the remaining length used to wrap and
    #     the following TLVs were read as prefixes until the end of the
    #     packet. Now no prefix is shown; the two octets left are read as
    #     the next TLV header (length 1 < 4) and the rest goes to data.
    M.append(cdp([raw_tlv(0x0007, 6, b'\xc0\x00'), tlv(0x0001, b'sw-two')]))
    # 16: a TLV with a length below 4 ends the TLV list; the rest is data
    M.append(cdp([tlv(0x0001, b'switch-8'), raw_tlv(0x0001, 2), b'trailing data']))
    return M


def malformed_frames():
    B = []
    # 1: bad checksum
    B.append(cdp([tlv(0x0001, b'bad-checksum')], good=False))
    # 2: EnergyWise sub-TLV with a length below 8
    B.append(cdp([energywise([struct.pack('>II', 7, 4)], length=8)]))
    # 3: EnergyWise table length larger than the sub-TLVs (octets left)
    B.append(cdp([energywise([nrgyz_tlv(9, b'name')], length=12 + 8, num=1)
                  + bytes(8)]))
    # 4: EnergyWise sub-TLV length past the table length
    B.append(cdp([energywise([nrgyz_tlv(9, b'name-long')], length=12)]))
    # 5: EnergyWise TLV shorter than its fixed header
    B.append(cdp([tlv(0x001d, bytes(20))]))
    # 6: Protocol Hello shorter than OUI and protocol ID (length - 9 < 0)
    B.append(cdp([tlv(0x0008, bytes.fromhex('00000c'))]))
    # 7: cluster management Hello cut short
    B.append(cdp([tlv(0x0008, bytes.fromhex('00000c0112') + bytes(4))]))
    # 8: Location TLV with no location octet (length - 5 < 0)
    B.append(cdp([tlv(0x0017, b'')]))
    # 9: Native VLAN, MTU, Power TLVs with no value
    B.append(cdp([tlv(0x000a, b''), tlv(0x0011, b''), tlv(0x0010, b'')]))
    # 10: Device ID TLV longer than the packet
    B.append(cdp([raw_tlv(0x0001, 200, b'short')]))
    # 11: a TLV header cut short
    B.append(cdp([tlv(0x0001, b'x'), b'\x00\x05']))
    # 12: VoIP VLAN reply and query with one octet
    B.append(cdp([tlv(0x000e, b'\x01')]))
    B.append(cdp([tlv(0x000f, b'\x01')]))
    # 14: Addresses TLV without the address count
    B.append(cdp([tlv(0x0002, b'')]))
    # 15: header only, cut in the checksum
    B.append(b'\x02\xb4\x00')
    return [frame(p) for p in B]


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'cdp-coverage.pcap'), [frame(p) for p in main_frames()])
    write_pcap(os.path.join(out, 'cdp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
