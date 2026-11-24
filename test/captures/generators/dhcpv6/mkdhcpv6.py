#!/usr/bin/env python3
# Generates test/captures/dhcpv6_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate synthetic DHCPv6 coverage captures (packet-dhcpv6.c).
# Usage: mkdhcpv6.py <outdir>
# Writes dhcpv6-coverage.pcap (clean) and dhcpv6-coverage-malformed.pcap.
# Every packet is built with struct; addresses are from the documentation
# ranges (2001:db8::/32, 192.0.2.0/24, 02:00:00:... MACs).
import os
import struct
import sys

# ---------------------------------------------------------------- framing

CLI = bytes.fromhex('20010db8000000000000000000000001')
SRV = bytes.fromhex('20010db8000000000000000000000002')
RLY = bytes.fromhex('20010db8000000000000000000000003')


def a6(last):
    return bytes.fromhex('20010db8000000000000000000000000')[:14] + struct.pack('!H', last)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def eth(payload, ethertype, to_server):
    c = b'\x02\x00\x00\x00\x00\x01'
    s = b'\x02\x00\x00\x00\x00\x02'
    return (s + c if to_server else c + s) + struct.pack('!H', ethertype) + payload


def ip6(src, dst, nh, payload):
    return struct.pack('!IHBB', 0x60000000, len(payload), nh, 64) + src + dst + payload


def udp6(payload, sport, dport, src=CLI, dst=SRV):
    ulen = 8 + len(payload)
    u = struct.pack('!HHHH', sport, dport, ulen, 0) + payload
    c = csum(src + dst + struct.pack('!IxxxB', ulen, 17) + u) or 0xffff
    u = u[:6] + struct.pack('!H', c) + u[8:]
    return eth(ip6(src, dst, 17, u), 0x86dd, dport == 547)


def tcp6(payload, sport, dport, seq, ack, flags, src, dst):
    o = b'\x02\x04\x05\xa0\x01\x01\x04\x02' if flags & 0x02 else b''   # MSS on SYN
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(o) // 4) << 4, flags, 65535, 0, 0) + o + payload
    c = csum(src + dst + struct.pack('!IxxxB', len(t), 6) + t)
    t = t[:16] + struct.pack('!H', c) + t[18:]
    return eth(ip6(src, dst, 6, t), 0x86dd, dport == 547)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


# ---------------------------------------------------------------- DHCPv6

def opt(code, data=b''):
    return struct.pack('!HH', code, len(data)) + data


def msg(mtype, xid, *opts):
    return struct.pack('!I', (mtype << 24) | xid) + b''.join(opts)


def relay(mtype, hops, link, peer, *opts):
    return struct.pack('!BB', mtype, hops) + link + peer + b''.join(opts)


def dn(*names):
    """Encode domain names; a name ending in '.' is root-terminated."""
    out = b''
    for name in names:
        fq = name.endswith('.')
        for lab in name.rstrip('.').split('.'):
            out += bytes([len(lab)]) + lab.encode()
        if fq:
            out += b'\0'
    return out


def to_srv(payload):
    return udp6(payload, 546, 547, CLI, SRV)


def to_cli(payload):
    return udp6(payload, 547, 546, SRV, CLI)


MAC = b'\x02\x00\x00\x00\x00\x01'
DUID_LLT = struct.pack('!HHI', 1, 1, 700000000) + MAC
DUID_EN = struct.pack('!HI', 2, 9) + b'\x0c\xc0\x84\xd3\x03\x00\x09\x12'
DUID_LL = struct.pack('!HH', 3, 1) + MAC
DUID_UUID = struct.pack('!H', 4) + bytes(range(16))
CID = opt(1, DUID_LLT)
SID = opt(2, DUID_LL)


def iaaddr(addr, *sub):
    return opt(5, addr + struct.pack('!II', 3600, 7200) + b''.join(sub))


def ia_na(iaid, *sub):
    return opt(3, struct.pack('!III', iaid, 1800, 2880) + b''.join(sub))


def status(code, text=b''):
    return opt(13, struct.pack('!H', code) + text)


# DHCPv4 DISCOVER for DHCPv4-over-DHCPv6
def dhcpv4_discover():
    b = struct.pack('!BBBBIHH', 1, 1, 6, 0, 0x12345678, 0, 0x8000)
    b += b'\0' * 16 + MAC + b'\0' * 10 + b'\0' * 64 + b'\0' * 128
    b += b'\x63\x82\x53\x63' + b'\x35\x01\x01' + b'\x37\x03\x01\x03\x06' + b'\xff'
    return b


# --------------------------------------------------------- CableLabs (4491)

def cl(code, data=b''):
    return struct.pack('!HH', code, len(data)) + data


def vendor_cl(*subs):
    return opt(17, struct.pack('!I', 4491) + b''.join(subs))


def ccc(code, data):
    return struct.pack('!HH', code, len(data)) + data


# ================================================================ main

def main_frames():
    F = []
    notes = []

    def add(fr, note):
        F.append(fr)
        notes.append(note)

    # --- 1-9: a full four-message exchange plus Confirm/Renew/Rebind
    add(to_srv(msg(1, 0x000001, CID, opt(6, struct.pack('!6H', 23, 24, 39, 56, 82, 17)),
                   opt(8, struct.pack('!H', 0)), ia_na(1), opt(14),
                   opt(39, b'\x00' + dn('host.example.com.')),
                   opt(16, struct.pack('!I', 4491) + struct.pack('!H', 5) + b'docsis'),
                   opt(15, struct.pack('!H', 3) + b'abc' + struct.pack('!H', 2) + b'xy'),
                   opt(61, struct.pack('!HH', 7, 16)), opt(62, b'\x01\x03\x10'))),
        'Solicit')
    add(to_cli(msg(2, 0x000001, SID, CID, opt(7, b'\xff'),
                   ia_na(1, iaaddr(a6(0x100), status(0, b'ok'))),
                   opt(39, b'\x00' + dn('host.example.com.')),
                   opt(23, a6(0x53) + a6(0x54)), opt(24, dn('example.com.', 'example.net.')),
                   opt(82, struct.pack('!I', 3600)), opt(83, struct.pack('!I', 3600)))),
        'Advertise')
    add(to_srv(msg(3, 0x000002, CID, SID, ia_na(1, iaaddr(a6(0x100))),
                   opt(8, struct.pack('!H', 150)), opt(39, b'\x01' + dn('host.example.com.')))),
        'Request')
    add(to_cli(msg(7, 0x000002, SID, CID, ia_na(1, iaaddr(a6(0x100))),
                   opt(39, b'\x03' + dn('host.example.com.')), status(0))),
        'Reply')
    add(to_srv(msg(4, 0x000003, CID, ia_na(1, iaaddr(a6(0x100))))), 'Confirm')
    add(to_srv(msg(5, 0x000004, CID, SID, ia_na(1, iaaddr(a6(0x100))),
                   opt(39, b'\x04' + dn('host.example.com.')))), 'Renew')
    add(to_srv(msg(6, 0x000005, CID, ia_na(1, iaaddr(a6(0x100))),
                   opt(39, b'\x00'))), 'Rebind, empty FQDN')
    add(to_srv(msg(8, 0x000006, CID, SID, ia_na(1, iaaddr(a6(0x100))))), 'Release')
    add(to_srv(msg(9, 0x000007, CID, SID, ia_na(1, iaaddr(a6(0x100))))), 'Decline')

    # --- 10-14: Reconfigure, Information-request and friends
    add(to_cli(msg(10, 0x000008, SID, CID, opt(19, b'\x05'),
                   opt(11, struct.pack('!BBB', 3, 1, 0) + struct.pack('!Q', 1) +
                       b'realm' + struct.pack('!I', 7) + b'\0' * 16))),
        'Reconfigure with AUTH realm/key id/opaque data')
    add(to_srv(msg(11, 0x000009, CID, opt(6, struct.pack('!3H', 23, 24, 31)), opt(20),
                   opt(11, struct.pack('!BBB', 2, 2, 0) + struct.pack('!Q', 2) + b'\0' * 8))),
        'Information-request with Reconfigure Accept, AUTH info')
    add(to_srv(msg(18, 0x00000a, SID)), 'Reconfigure-request')
    add(to_cli(msg(19, 0x00000a, CID)), 'Reconfigure-reply')
    add(to_srv(msg(99, 0x00000b, CID)), 'unknown message type 99')

    # --- 15-17: DUID variants
    add(to_srv(msg(11, 0x000010, opt(1, DUID_EN), opt(2, DUID_UUID),
                   opt(53, struct.pack('!HI', 2, 9)))),
        'DUID-EN, DUID-UUID, Relay-ID DUID-EN without identifier')
    add(to_srv(msg(11, 0x000011, opt(1, struct.pack('!HHI', 1, 6, 1)),
                   opt(2, struct.pack('!HHI', 1, 32, 2) + b'\x80\0\0\x48\xfe\x80\0\x01'),
                   opt(53, struct.pack('!HH', 3, 6) + MAC))),
        'DUID-LLT without address, DUID-LLT InfiniBand, DUID-LL IEEE 802 (type 6)')
    add(to_srv(msg(11, 0x000012, opt(1, struct.pack('!HH', 3, 1)), opt(2, struct.pack('!HH', 3, 32) + b'\1\2\3\4'),
                   opt(53, struct.pack('!H', 9) + b'\xaa\xbb'), opt(16, struct.pack('!I', 311)))),
        'DUID-LL without address, DUID-LL non-ether, unknown DUID type, Vendor Class without data')

    # --- 18-22: addresses, IA_TA/IA_PD/IA_LL, unicast
    add(to_cli(msg(7, 0x000013, SID, CID,
                   opt(4, struct.pack('!I', 2) + iaaddr(a6(0x200))),
                   opt(25, struct.pack('!III', 3, 1800, 2880) +
                       opt(26, struct.pack('!IIB', 3600, 7200, 48) + a6(0)[:6] + b'\0' * 10 +
                           opt(67, b'\x40\x12') + status(0))),
                   opt(12, SRV))),
        'IA_TA (obsoleted), IA_PD/IAPREFIX/PD_EXCLUDE, UNICAST (obsoleted)')
    add(to_cli(msg(7, 0x000014, SID, CID,
                   opt(138, struct.pack('!III', 4, 1800, 2880) +
                       opt(139, struct.pack('!HH', 1, 6) + MAC + struct.pack('!II', 1, 3600) + status(0)) +
                       opt(139, struct.pack('!HH', 32, 4) + b'\1\2\3\4' + struct.pack('!II', 0, 60))))),
        'IA_LL with LLADDR (ether and other)')
    add(to_srv(msg(36, 0x000015, CID, iaaddr(a6(0x300)),
                   opt(39, b'\x01' + dn('reg.example.com.')))),
        'Address Registration Inform')
    add(to_cli(msg(37, 0x000015, SID, CID, iaaddr(a6(0x300)), opt(148))),
        'Address Registration Reply, ADDR_REG_ENABLE')
    add(to_srv(msg(4, 0x000016, CID, opt(39, b'\x00' + dn('host.example.com.')))),
        'Client FQDN in Confirm (bad message type, warning)')

    # --- 23-24: Client FQDN flag variants in server messages
    add(to_cli(msg(2, 0x000017, SID, opt(39, b'\x02' + dn('a.example.com.')))), 'FQDN server O bit, S=0')
    add(to_cli(msg(7, 0x000018, SID, opt(39, b'\x04' + dn('host')))), 'FQDN server N bit, partial name')

    # --- 25-28: name and address options
    add(to_cli(msg(7, 0x000020, SID,
                   opt(21, dn('sip.example.com.', 'sip2.example.com.')),
                   opt(22, a6(0x21)), opt(27, a6(0x27)), opt(28, a6(0x28)),
                   opt(29, dn('nis.example.com.')), opt(30, dn('nisp.example.com.')),
                   opt(31, a6(0x31) + a6(0x32)), opt(32, struct.pack('!I', 86400)),
                   opt(33, dn('bcmcs.example.com.')), opt(34, a6(0x34)),
                   opt(40, a6(0x40)), opt(41, b'EST5EDT4,M3.2.0/02:00,M11.1.0/02:00'),
                   opt(42, b'Europe/Zurich'), opt(52, a6(0x52)), opt(88, a6(0x88) + a6(0x89)))),
        'name/address list options')
    add(to_cli(msg(7, 0x000021, SID,
                   opt(24, dn('org.')),
                   opt(36, b'\x00US\x01\x02CA'),
                   opt(49, dn('hnid.example.com.')), opt(50, opt(71, b'\x40' + a6(0)) + opt(72, a6(0x72))),
                   opt(69, opt(73, dn('ha.example.com.'))), opt(70, opt(72, a6(0x70))),
                   opt(51, dn('lost.example.com.')),
                   opt(59, b'tftp://[2001:db8::2]/boot.efi'),
                   opt(60, struct.pack('!H', 13) + b'root=/dev/sda' + struct.pack('!H', 2) + b'ro'),
                   opt(64, dn('aftr.example.com.')), opt(103, b'https://portal.example.com/'),
                   opt(112, b'https://mud.example.com/device'),
                   opt(145, dn('home.example.com.')),
                   opt(146, b'\x00\x01' + dn('fwd.example.com.')),
                   opt(147, b'\x00\x00' + dn('rev.example.com.')))),
        'TLD (warning), geoconf, MIP6, boot file, AFTR, captive portal, MUD URL, homenet')
    add(to_cli(msg(7, 0x000022, SID,
                   opt(54, struct.pack('!HH', 1, 32) + a6(0x541) + a6(0x542) + struct.pack('!HH', 2, 16) + a6(0x543)),
                   opt(55, struct.pack('!HH', 1, 17) + dn('mos.example.com.')),
                   opt(56, struct.pack('!HH', 1, 16) + a6(0x123) + struct.pack('!HH', 2, 16) +
                       bytes.fromhex('ff050000000000000000000000000101') +
                       struct.pack('!HH', 3, 17) + dn('ntp.example.com.') + struct.pack('!HH', 4, 2) + b'\0\0'),
                   opt(79, struct.pack('!H', 1) + MAC))),
        'MoS address/FQDN, NTP server suboptions, client link-layer address')
    add(to_cli(msg(7, 0x000023, SID,
                   opt(68, b'\x00vpn-blue'), opt(81, b'\x01\x07alice'),
                   opt(111, struct.pack('!3H', 96, 95, 64)),
                   opt(135, struct.pack('!H', 547)),
                   opt(144, struct.pack('!HH', 1, 17) + dn('dns.example.com.')),
                   opt(200, b'\xde\xad'), opt(10))),
        'VSS NVT, RADIUS, S46 priority, relay port, DNR ADN-only (chat), unknown options')
    add(to_cli(msg(7, 0x000024, SID,
                   opt(68, b'\x01' + b'\0\0\0\1\0\0\2'), opt(144,
                       struct.pack('!HH', 2, 17) + dn('dns.example.com.') + struct.pack('!H', 32) + a6(0x531) + a6(0x532) +
                       struct.pack('!HH', 1, 3) + b'\x02h2' + struct.pack('!HHH', 3, 2, 443) +
                       struct.pack('!HH', 7, 16) + b'/dns-query{?dns}'))),
        'VSS VPN-ID, DNR with addresses and SvcParams')
    add(to_cli(msg(7, 0x000025, SID, opt(68, b'\xfe'), opt(68, b'\xff'), opt(68, b'\x02xyz'),
                   opt(79, struct.pack('!H', 32) + b'\1\2\3\4'), opt(79, struct.pack('!H', 1)))),
        'VSS all/global/unknown type, client link-layer address non-ether and empty')

    # --- 31-32: softwires
    rule = opt(89, struct.pack('!BBB', 1, 16, 24) + bytes([192, 0, 2, 0]) + b'\x38' + a6(0)[:7] +
               opt(93, struct.pack('!BBH', 6, 8, 0x3400)))
    rule0 = opt(89, struct.pack('!BBB', 0, 0, 32) + bytes([192, 0, 2, 1]) + b'\x40' + a6(0)[:8])
    add(to_cli(msg(7, 0x000030, SID,
                   opt(94, rule + opt(90, a6(0x90))),
                   opt(95, rule0 + opt(91, b'\x40' + a6(0)[:8])),
                   opt(96, opt(90, a6(0x90)) +
                       opt(92, bytes([192, 0, 2, 9]) + b'\x80' + a6(0x92) + opt(93, struct.pack('!BBH', 0, 0, 0)))))),
        'S46 MAP-E/MAP-T/LW4o6 containers')
    add(to_cli(msg(7, 0x000031, SID, opt(91, b'\x00'), opt(92, bytes([192, 0, 2, 10]) + b'\x00'))),
        'S46 DMR and V4V6BIND with zero prefix length')

    # --- 33-34: DHCPv4 over DHCPv6
    add(to_srv(msg(20, 0x000040, opt(87, dhcpv4_discover()))), 'DHCPv4-query')
    add(to_cli(msg(21, 0x000040, opt(87, dhcpv4_discover()))), 'DHCPv4-response')

    # --- 35-36: failover options (RFC 8156)
    add(to_cli(msg(7, 0x000050, SID,
                   opt(114, b'\x01'), opt(115, b'\x00\x01'), opt(116, b'\x01\x02'),
                   opt(117, dn('host.example.com.')), opt(118, dn('example.com.')),
                   opt(119, b'\x00\x0f'), opt(120, struct.pack('!I', 1000)),
                   opt(121, struct.pack('!I', 10)), opt(122, struct.pack('!I', 3600)),
                   opt(123, struct.pack('!I', 1)), opt(124, struct.pack('!I', 2)),
                   opt(125, struct.pack('!I', 3)), opt(126, struct.pack('!I', 4)),
                   opt(127, struct.pack('!HH', 1, 0)), opt(128, struct.pack('!I', 30)),
                   opt(129, struct.pack('!I', 5) + b'\0' * 8), opt(130, b'pair-a'),
                   opt(131, b'\x07'), opt(132, b'\x02'), opt(133, struct.pack('!I', 6)),
                   opt(134, struct.pack('!I', 7)))),
        'failover options')

    # --- Leasequery over UDP
    add(to_srv(msg(14, 0x000060, CID, opt(44, b'\x01' + a6(0) + iaaddr(a6(0x100)) + opt(6, struct.pack('!H', 46))))),
        'Leasequery by-address')
    add(to_cli(msg(15, 0x000060, SID, CID,
                   opt(45, CID + iaaddr(a6(0x100)) + opt(46, struct.pack('!I', 60))),
                   opt(47, a6(0x47) + b'relaymsg'), opt(48, a6(0x481) + a6(0x482)))),
        'Leasequery-reply')
    add(to_cli(msg(16, 0x000061, SID)), 'Leasequery-done')
    add(to_cli(msg(17, 0x000061, SID, opt(45, CID))), 'Leasequery-data')

    # --- Relays
    inner = msg(1, 0x000070, CID, opt(8, b'\0\0'))
    r0 = relay(12, 0, RLY, CLI, opt(18, b'eth0\x00' + MAC), opt(9, inner))
    add(udp6(relay(12, 1, a6(0), RLY,
                   opt(18, b'eth1'), opt(37, struct.pack('!I', 9) + b'remote-1'),
                   opt(38, b'subscriber-1'), opt(43, struct.pack('!H', 18)),
                   opt(135, struct.pack('!H', 1547)), opt(66, opt(36, b'\x00US')),
                   opt(9, r0)), 547, 547, RLY, SRV),
        'two nested Relay-forw')
    rr0 = relay(13, 0, RLY, CLI, opt(18, b'eth0\x00' + MAC[:2]), opt(9, msg(2, 0x000070, SID, CID)))
    add(udp6(relay(13, 1, a6(0), RLY, opt(18, b'eth1'), opt(9, rr0)), 547, 547, SRV, RLY),
        'two nested Relay-reply')
    add(udp6(relay(12, 40, a6(0), RLY,
                   opt(9, relay(12, 40, RLY, CLI, opt(9, inner)))), 547, 547, RLY, SRV),
        'hop count above limit, not decremented, inner hop count not zero (warnings)')

    # --- CableLabs vendor options
    add(to_srv(msg(1, 0x000080, CID, vendor_cl(
        cl(1, struct.pack('!5H', 32, 33, 34, 37, 38)), cl(2, b'ECM'), cl(3, b'ECM:EMTA\0'),
        cl(4, b'SN0001'), cl(5, b'HW1'), cl(6, b'SW1'), cl(7, b'BR1'), cl(8, b'\x00\x10\x95'),
        cl(9, b'MODEL'), cl(10, b'VENDOR'), cl(35, b'\x01\x01\x01' + b'\x02\x02\x03\x01' + b'\x05\x03\x01\x02\x03'),
        cl(36, MAC), cl(1026, MAC), cl(1027, b'\x01\x02\x03'), cl(1025, b'\x01\x02\x03\x00\x02\x02\x01\x00\x09\x01\x07'),
        cl(1025), cl(2172, struct.pack('!I', 42)), cl(2172, b'\x01'), cl(99, b'zz')))),
        'CableLabs CM options, TLV5 modem capabilities')
    add(to_srv(msg(1, 0x000081, CID, vendor_cl(
        cl(2, b'EDVA'), cl(8, b'001095'), cl(35, b'\x01\x01\x02' + b'\x0b\x04\x01\x02\x03\x04'),
        cl(39, b'\x01'), cl(39, b'\x02'), cl(39, b'\x06'), cl(39, b'\x09')))),
        'CableLabs EDVA TLV5, IP preference values')
    add(to_srv(msg(1, 0x000082, CID, vendor_cl(cl(2, b'EPS'), cl(35, b'\x01\x01\x01')),
                   vendor_cl(cl(2), cl(35, b'\x01\x01\x01')))),
        'CableLabs other/empty device type with TLV5')
    add(to_cli(msg(7, 0x000083, SID, vendor_cl(
        cl(32, a6(0x320) + a6(0x321)), cl(33, b'cm.cfg'), cl(34, a6(0x340)), cl(37, a6(0x370)),
        cl(38, struct.pack('!i', -18000)), cl(61, a6(0x610)), cl(32, b'\0' * 5),
        cl(2170, ccc(1, bytes([192, 0, 2, 1])) + ccc(2, bytes([192, 0, 2, 2])) + ccc(9, b'\0')),
        cl(2171, ccc(1, b'pri-dss') + ccc(2, b'sec-dss') + ccc(3, b'\x00' + dn('prov.example.com.')) +
           ccc(3, b'\x01' + a6(0x31) + a6(0x32)) + ccc(4, struct.pack('!III', 10, 20, 3)) +
           ccc(5, struct.pack('!III', 10, 20, 3)) + ccc(6, dn('REALM.EXAMPLE.COM.')) +
           ccc(7, b'\x01') + ccc(8, b'\x0a') + ccc(9, b'\x00\x03') + ccc(20, b'\0'))))),
        'CableLabs servers, CCC and CCCv6 sub-options')
    add(to_cli(msg(7, 0x000084, SID, vendor_cl(
        cl(2171, ccc(3, b'\x02\0') + ccc(4, b'\0') + ccc(5, b'\0') + ccc(8, b'\x3c') + ccc(6, b''))))),
        'CCCv6 invalid prov. server type, short Kerberos timers, timer > 30 (warnings)')
    add(to_cli(msg(7, 0x000085, SID,
                   opt(17, struct.pack('!I', 9) + struct.pack('!HH', 1, 3) + b'abc' + struct.pack('!HH', 2, 0)),
                   opt(17, struct.pack('!I', 311)))),
        'Vendor options of an enterprise without a sub-dissector')

    # --- reproducers of the bugs fixed in "DHCPv6: Fix several sub-option length and offset errors"
    v1 = struct.pack('!I', 4491) + struct.pack('!HH', 1, 2) + b'\x00\x20' + struct.pack('!HH', 2, 0)
    v2 = struct.pack('!I', 4491) + struct.pack('!HH', 1, 0)
    add(to_cli(b'\x07\x00\x00\x01' + opt(17, v1)), 'repro: CableLabs last sub-option (Device Type) shown')
    add(to_cli(b'\x07\x00\x00\x02' + opt(17, v2)), 'repro: CableLabs 8-byte option is not bogus')
    cccv6 = struct.pack('!HH', 3, 17) + b'\x01' + bytes.fromhex('20010db8000000000000000000000053')
    clv = struct.pack('!HH', 2171, len(cccv6)) + cccv6
    add(to_cli(b'\x07\x00\x00\x01' + opt(17, struct.pack('!I', 4491) + clv + struct.pack('!HH', 2, 0))),
        'repro: CCCv6 provisioning server IPv6 address shown')
    add(to_cli(b'\x07\x00\x00\x01' + opt(24, b'\x03foo\x03bar')), 'repro: partial name foo.bar')
    add(to_cli(b'\x07\x00\x00\x02' + opt(24, b'\x01a\x02bb\x03ccc')), 'repro: partial name a.bb.ccc')
    dns = opt(23, bytes.fromhex('20010db8000000000000000000000053') * 3)
    add(to_cli(b'\x07\x00\x00\x01' + opt(54, struct.pack('!HH', 1, 0)) + dns),
        'repro: MoS address sub-option of length 0, DNS option after it')

    # --- Bulk leasequery over TCP port 547
    def pdu(mtype, tid, *opts):
        body = struct.pack('!BBH', mtype, 0, tid) + b''.join(opts)
        return struct.pack('!H', len(body)) + body

    cs, ss = 1000, 5000
    cport = 40547

    def c2s(data, flags=0x18):
        nonlocal cs
        fr = tcp6(data, cport, 547, cs, ss, flags, CLI, SRV)
        cs += len(data) + (1 if flags & 0x03 else 0)
        return fr

    def s2c(data, flags=0x18):
        nonlocal ss
        fr = tcp6(data, 547, cport, ss, cs, flags, SRV, CLI)
        ss += len(data) + (1 if flags & 0x03 else 0)
        return fr

    syn = tcp6(b'', cport, 547, cs - 1, 0, 0x02, CLI, SRV)
    add(syn, 'TCP SYN')
    add(tcp6(b'', 547, cport, ss - 1, cs, 0x12, SRV, CLI), 'TCP SYN/ACK')
    add(tcp6(b'', cport, 547, cs, ss, 0x10, CLI, SRV), 'TCP ACK')
    add(c2s(pdu(14, 1, CID, opt(44, b'\x04' + a6(0) + opt(6, struct.pack('!H', 45)))) +
            pdu(14, 2, CID, opt(44, b'\x03' + a6(0) + opt(53, struct.pack('!HI', 2, 9)))) +
            pdu(14, 3, CID, opt(44, b'\x02' + a6(0) + CID))),
        'bulk: three Leasequery PDUs in one segment')
    big = pdu(15, 1, SID, opt(45, CID + iaaddr(a6(0x100)) + opt(46, struct.pack('!I', 60)) +
                              opt(47, a6(0x47) + b'\0' * 20)),
              opt(100, struct.pack('!I', 1000)), opt(101, struct.pack('!I', 900)), opt(102, struct.pack('!I', 1100)))
    add(s2c(big[:20]), 'bulk: Leasequery-reply, first part')
    add(s2c(big[20:]), 'bulk: Leasequery-reply, second part (reassembled)')
    add(s2c(pdu(17, 1, opt(45, opt(1, DUID_LL) + iaaddr(a6(0x101)))) + pdu(16, 1, status(0))),
        'bulk: Leasequery-data and Leasequery-done in one segment')
    return F, notes


# ================================================================ malformed

def malformed_frames():
    F = []

    def add(p, to_server=False):
        F.append(to_srv(p) if to_server else to_cli(p))

    r = lambda *o: msg(7, 0x0000ee, *o)
    # reproducers that report an error with the fix
    cccv6 = struct.pack('!HH', 3, 16) + b'\x01' + bytes.fromhex('20010db8000000000000000000000053')[:15]
    clv = struct.pack('!HH', 2171, len(cccv6)) + cccv6
    add(b'\x07\x00\x00\x01' + opt(17, struct.pack('!I', 4491) + clv + struct.pack('!HH', 2, 0)))
    add(b'\x07\x00\x00\x01' + opt(16, struct.pack('!I', 9) + b'X') + opt(7, b'\xff') +
        opt(13, b'\x00\x00' + b'NEXT-OPTION-TEXT'))
    add(b'\x07\x00\x00\x01' + opt(17, struct.pack('!I', 9) + struct.pack('!HH', 1, 6) + b'AB') +
        opt(7, b'\x01') + opt(13, b'\x00\x00' + b'0123456789abcdef0123'))
    add(b'\x07\x00\x00\x01' + opt(15, struct.pack('!H', 4) + b'ab') + opt(7, b'\x01') + opt(13, b'\x00\x00ZZZZ'))
    add(b'\x07\x00\x00\x02' + opt(56, struct.pack('!HH', 1, 4) + b'\x00' * 4) + opt(13, b'\x00\x00' + b'Y' * 16))

    # each "malformed option" / length check
    for code, data in [
            (1, b'\x00'), (2, struct.pack('!HH', 1, 1)), (2, struct.pack('!HH', 2, 9)),
            (2, struct.pack('!HH', 3, 1)[:3]), (2, struct.pack('!H', 4) + b'\0' * 4),
            (15, b'\x00'), (56, b'\0\0'), (56, struct.pack('!HH', 1, 0) + b'\0\0'),
            (56, struct.pack('!HH', 2, 4) + b'\0' * 4), (56, struct.pack('!HH', 3, 9) + b'\0' * 4),
            (89, b'\0' * 7), (89, b'\0\0\x21' + b'\0' * 5), (89, b'\0\0\x20\0\0\0\0\x81'),
            (90, b'\0' * 4), (91, b''), (91, b'\x81' + b'\0' * 16), (92, b'\0' * 4), (92, b'\0' * 4 + b'\x81'),
            (93, b'\0\0\0'), (93, b'\x10\0\0\0'), (93, b'\0\x11\0\0'),
            (3, b'\0' * 11), (138, b'\0' * 11), (25, b'\0' * 11), (4, b'\0\0'), (5, b'\0' * 23),
            (139, b'\0' * 11), (139, struct.pack('!HH', 1, 6) + b'\0' * 8),
            (7, b''), (8, b'\0'), (9, b''), (11, b'\0' * 10),
            (11, struct.pack('!BBB', 3, 1, 0) + b'\0' * 8 + b'R' * 300 + b'\0' * 20),
            (12, b'\0' * 15), (16, b'\0\0\0'), (17, b'\0\0\0'), (17, struct.pack('!I', 9) + b'\0\0'),
            (18, b''), (19, b''), (20, b'\0'), (22, b'\0' * 15), (23, b'\0' * 15), (88, b'\0' * 15),
            (27, b'\0' * 15), (28, b'\0' * 15), (31, b'\0' * 15), (32, b'\0'), (34, b'\0' * 15),
            (37, b'\0\0\0'), (38, b''), (39, b''), (40, b'\0' * 15), (44, b'\0' * 16), (46, b''),
            (47, b'\0' * 15), (48, b'\0' * 15), (52, b'\0' * 15), (49, b''), (71, b'\0' * 16),
            (72, b'\0' * 15), (73, b''), (60, struct.pack('!H', 9) + b'ab'), (62, b'\0\0'), (61, b''),
            (61, b'\0\0\0'), (54, b'\0\0'), (54, struct.pack('!HH', 1, 16)), (54, struct.pack('!HH', 1, 4) + b'\0' * 4),
            (55, b'\0'), (55, struct.pack('!HH', 1, 9)), (81, b''), (145, b''), (146, b'\0\0'), (147, b'\0\0'),
            (68, b''), (68, b'\x01\0'), (68, b'\xfe\0'), (26, b'\0' * 24), (67, b'\0'), (67, b'\0' * 18),
            (114, b''), (115, b''), (117, b''), (118, b''), (119, b''), (120, b''), (121, b''), (122, b''),
            (123, b''), (124, b''), (125, b''), (126, b''), (127, b''), (128, b''), (129, b'\0'),
            (131, b''), (132, b''), (133, b''), (134, b''), (135, b''), (79, b'\0'),
            (144, b'\0' * 5), (144, struct.pack('!HH', 0, 9) + b'ab'), (144, struct.pack('!HH', 0, 0) + b'\0'), (144, struct.pack('!HH', 0, 2) + b'\x01a\0'),
            (144, struct.pack('!HHH', 0, 0, 3) + b'\0\0\0'), (144, struct.pack('!HHH', 0, 0, 32) + b'\0' * 16),
            (144, struct.pack('!HHH', 0, 0, 16) + b'\0' * 16),
            ]:
        add(r(opt(code, data)))
    # domain name errors
    for d in [b'\x00', b'\x40abc', b'\x03ab', dn('example.com.') + b'\x03foo', b'\x03com\x00\x01x\x40',
              (b'\x3f' + b'a' * 63) * 4 + b'\x00', b'\x03abc\x05de', (b'\x3f' + b'a' * 63) * 4 + b'\x03abc']:
        add(r(opt(24, d)))
    add(msg(1, 0x0000ef, opt(39, b'\x05' + dn('host.example.com.'))), True)
    add(msg(7, 0x0000ef, opt(39, b'\x05' + dn('host.example.com.'))))
    # CableLabs errors
    add(r(vendor_cl(cl(8, b'\0\0'), cl(36, b'\0'), cl(1026, b'\0'),
                    cl(2170, ccc(1, b'\0') + ccc(2, b'\0')),
                    cl(2171, ccc(9, b'\0') + ccc(1, b'x' * 35) + ccc(2, b'x' * 35) + ccc(3, b'') + ccc(3, b'\x01\0') +
                       ccc(7, b'') + ccc(8, b'') + ccc(9, b'\0')))))
    add(r(opt(17, struct.pack('!I', 4491) + b'\0\0')))
    add(r(vendor_cl(cl(9, b'x' * 40))[:-20]))
    # truncated option header / data
    add(b'\x07\x00\x00\x01\x00\x07')
    add(b'\x07\x00\x00\x01' + struct.pack('!HH', 13, 40) + b'\0\0')
    add(b'\x07')
    # Malformed-group warnings: Bulk Leasequery query type over UDP and a
    # message type that Bulk Leasequery does not allow
    add(msg(14, 0x000061, CID, opt(44, b'\x05' + a6(0) + opt(37, struct.pack('!I', 9) + b'rid'))), True)
    F.append(tcp6(struct.pack('!HBBH', 12, 1, 0, 4) + opt(14) + opt(14), 40549, 547, 1, 1, 0x18, CLI, SRV))
    # bulk leasequery truncated
    F.append(tcp6(struct.pack('!HBBH', 30, 14, 0, 1) + struct.pack('!HH', 44, 40), 40548, 547, 1, 1, 0x18, CLI, SRV))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames, notes = main_frames()
    write_pcap(os.path.join(out, 'dhcpv6-coverage.pcap'), frames)
    write_pcap(os.path.join(out, 'dhcpv6-coverage-malformed.pcap'), malformed_frames())
    if '-v' in sys.argv:
        for i, n in enumerate(notes):
            print(i + 1, n)


if __name__ == '__main__':
    main()
