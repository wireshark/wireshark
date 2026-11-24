#!/usr/bin/env python3
# Generates test/captures/radius_dict_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic RADIUS dictionary coverage material.

Usage: mkradius_dict.py <outdir>

Writes into <outdir>:
  radius_dict_coverage.pcap            main capture: RADIUS over UDP whose
                                       attributes (vendor, TLV, VALUE names,
                                       all value types) are defined by the
                                       personal dictionary cfg/radius/
  radius_dict_coverage_malformed.pcap  frames that only reach error paths
  cfg/radius/                          personal dictionary for the main capture
                                       (the test class writes the same files)
  cfg-<name>/radius/                   hostile and extra dictionaries

Everything is generated; nothing comes from a real network.
"""
import os
import struct
import sys

# ---------------------------------------------------------------------------
# Dictionaries
# ---------------------------------------------------------------------------

MAIN_DICT = '''\
# Personal RADIUS dictionary for the coverage capture
VENDOR Dict-Vendor      55555
VENDOR Dict-Vendor-2-2  55556  format=2,2
VENDOR Dict-Vendor-4-0  55557  format=4,0
VENDOR Dict-Vendor-Flg  55558  format=1,1,c
VENDOR Dict-Vendor-Hex  0xD9FE format=1,2
VENDOR Dict-Vendor-Evs1 55561
VENDOR Dict-Vendor-Evs2 55562
VENDOR Dict-Vendor-Evs3 55563
VENDOR Dict-Vendor-Evs4 55564
VENDOR Dict-Vendor-Evs5 55565
VENDOR Dict-Vendor-Evs6 55566
VENDOR Dict-Vendor-First 55570
VENDOR Dict-Vendor-Second 55570 format=1,1
VENDOR b 55571
VENDOR NoFormat 55572 format=
$INCLUDE dictionary.part
'''

PART_DICT = '''\
# Included relative to the directory of the including file
ATTRIBUTE Dict-Integer      103  integer
VALUE     Dict-Integer      Low     1
VALUE     Dict-Integer      Mid     2
VALUE     Dict-Integer      High    0x10
ATTRIBUTE Dict-Byte         104  byte
ATTRIBUTE Dict-Short        105  short
ATTRIBUTE Dict-Signed       106  signed
VALUE     Dict-Signed       Minus-One 4294967295
ATTRIBUTE Dict-String       107  string
ATTRIBUTE Dict-Octets       108  octets[8]
ATTRIBUTE Dict-Ipaddr       109  ipaddr
ATTRIBUTE Dict-Ipv6addr     110  ipv6addr
ATTRIBUTE Dict-Ipv6prefix   111  ipv6prefix
ATTRIBUTE Dict-Ipxnet       112  ipxnet
ATTRIBUTE Dict-Date         113  date
ATTRIBUTE Dict-Abinary      114  abinary
ATTRIBUTE Dict-Ether        115  ether
ATTRIBUTE Dict-Ifid         116  ifid
ATTRIBUTE Dict-Combo-Ip     117  combo-ip
ATTRIBUTE Dict-Tlv          118  tlv
ATTRIBUTE Dict-Tagged       119  integer has_tag
ATTRIBUTE Dict-Enc-1        120  string encrypt=1
ATTRIBUTE Dict-Enc-2        121  string encrypt=2,has_tag
ATTRIBUTE Dict-Concat       122  octets concat
ATTRIBUTE Dict-Vsa          103.1 vsa
ATTRIBUTE Dict-Hex-Code     0xBF integer
ATTRIBUTE Dict.Dot-Name     192  integer
ATTRIBUTE Dict/Slash        193  integer
ATTRIBUTE Dict-First-Name   194  integer
ATTRIBUTE Dict-Second-Name  194  string
ATTRIBUTE a                 195  integer
VALUE     a                 one     1
ATTRIBUTE b                 196  integer
ATTRIBUTE Dict-Weird-Type   197  weirdtype
ATTRIBUTE Dict-Param        198  integer foo=bar
ATTRIBUTE Dict-Old-Vsa      1    integer Dict-Vendor

BEGIN-TLV Dict-Tlv
ATTRIBUTE Dict-Tlv-Integer  1  integer
VALUE     Dict-Tlv-Integer  Seven 7
ATTRIBUTE Dict-Tlv-String   2  string
ATTRIBUTE Dict-Tlv-Ipaddr   3  ipaddr
ATTRIBUTE Dict-Tlv-Sub      4  tlv
BEGIN-TLV Dict-Tlv-Sub
ATTRIBUTE Dict-Tlv-Sub-Int  1  integer
ATTRIBUTE Dict-Tlv-Sub-Sub  2  tlv
BEGIN-TLV Dict-Tlv-Sub-Sub
ATTRIBUTE Dict-Tlv-Deep     1  string
END-TLV Dict-Tlv-Sub-Sub
END-TLV Dict-Tlv-Sub
END-TLV Dict-Tlv

BEGIN-VENDOR Dict-Vendor
ATTRIBUTE Dv-Integer   1  integer
VALUE     Dv-Integer   One   1
VALUE     Dv-Integer   Two   2
ATTRIBUTE Dv-String    2  string
ATTRIBUTE Dv-Ipaddr    3  ipaddr
ATTRIBUTE Dv-Tlv       4  tlv
BEGIN-TLV Dv-Tlv
ATTRIBUTE Dv-Tlv-Integer 1 integer
ATTRIBUTE Dv-Tlv-String  2 string
ATTRIBUTE Dv-Tlv-Inner   3 tlv
BEGIN-TLV Dv-Tlv-Inner
ATTRIBUTE Dv-Tlv-Inner-Int 1 integer
END-TLV Dv-Tlv-Inner
END-TLV Dv-Tlv
ATTRIBUTE Dv-Octets    5  octets
ATTRIBUTE Dv-Ipv6      6  ipv6addr
END-VENDOR Dict-Vendor

BEGIN-VENDOR Dict-Vendor-2-2
ATTRIBUTE D22-Integer  1  integer
ATTRIBUTE D22-String   2  string
END-VENDOR Dict-Vendor-2-2

BEGIN-VENDOR Dict-Vendor-4-0
ATTRIBUTE D40-Integer  1  integer
END-VENDOR Dict-Vendor-4-0

BEGIN-VENDOR Dict-Vendor-Flg
ATTRIBUTE Dfl-Octets   1  octets
ATTRIBUTE Dfl-String   2  string
END-VENDOR Dict-Vendor-Flg

BEGIN-VENDOR Dict-Vendor-Hex
ATTRIBUTE Dhx-Integer  0x10 integer
END-VENDOR Dict-Vendor-Hex

BEGIN-VENDOR Dict-Vendor-Evs1 format=Extended-Vendor-Specific-1
ATTRIBUTE Dev1-Integer 1  integer
ATTRIBUTE Dev1-String  2  string
END-VENDOR Dict-Vendor-Evs1
BEGIN-VENDOR Dict-Vendor-Evs2 format=Extended-Vendor-Specific-2
ATTRIBUTE Dev2-Integer 1  integer
END-VENDOR Dict-Vendor-Evs2
BEGIN-VENDOR Dict-Vendor-Evs3 format=Extended-Vendor-Specific-3
ATTRIBUTE Dev3-Integer 1  integer
END-VENDOR Dict-Vendor-Evs3
BEGIN-VENDOR Dict-Vendor-Evs4 format=Extended-Vendor-Specific-4
ATTRIBUTE Dev4-Integer 1  integer
END-VENDOR Dict-Vendor-Evs4
BEGIN-VENDOR Dict-Vendor-Evs5 format=Extended-Vendor-Specific-5
ATTRIBUTE Dev5-Integer 1  integer
END-VENDOR Dict-Vendor-Evs5
BEGIN-VENDOR Dict-Vendor-Evs6 format=Extended-Vendor-Specific-6
ATTRIBUTE Dev6-Integer 1  integer
END-VENDOR Dict-Vendor-Evs6

BEGIN-VENDOR Dict-Vendor-Second
ATTRIBUTE Dsc-Integer  1  integer
END-VENDOR Dict-Vendor-Second
BEGIN-VENDOR b
ATTRIBUTE b-Integer    1  integer
END-VENDOR b
$INCLUDE sub/dictionary.sub
'''

SUB_DICT = '''\
# A second level include, then back to the including file (no trailing
# newline on the last line: the definition is dropped)
ATTRIBUTE Dict-Sub-Integer 199 integer
VALUE     Dict-Sub-Integer Sub-One 1
ATTRIBUTE Dict-Sub-String  247 string'''

# Extra and hostile configurations (name -> {filename: content})
def chain(n):
    lines = ['ATTRIBUTE Chain 103 tlv\n', 'BEGIN-TLV Chain\nATTRIBUTE Xy 1 tlv\nEND-TLV Chain\n']
    lines += ['BEGIN-TLV Xy\nATTRIBUTE Xy 1 tlv\nEND-TLV Xy\n'] * n
    return ''.join(lines)

EXTRA_CFGS = {
    # the review's reproducers
    'rloop': {'dictionary': 'ATTRIBUTE Loop-Attr 240 integer\n$INCLUDE dictionary\n'},
    'rpartial': {'dictionary': 'VENDOR NoId\nATTRIBUTE NoId-Attr\nATTRIBUTE NoType-Attr 241\n'
                               'VALUE NoNum-Attr Foo\n$INCLUDE part2\n',
                 'part2': 'ATTRIBUTE Eof-Attr 242 string'},
    'rdot': {'dictionary': 'ATTRIBUTE Bad..Name 243 integer\nATTRIBUTE .Lead 244 integer\n'
                           'ATTRIBUTE Trail. 245 integer\n'},
    'rchain': {'dictionary': chain(30)},
    # TLV nesting exactly at the limit (8 levels below the attribute) and over it
    'rtlv8': {'dictionary': 'ATTRIBUTE T0 103 tlv\n' + ''.join(
        'BEGIN-TLV T%d\nATTRIBUTE T%d 1 tlv\n' % (i, i + 1) for i in range(0, 8)) +
        ''.join('END-TLV T%d\n' % i for i in range(8, 0, -1))},
    'rtlv9': {'dictionary': 'ATTRIBUTE T0 103 tlv\n' + ''.join(
        'BEGIN-TLV T%d\nATTRIBUTE T%d 1 tlv\n' % (i, i + 1) for i in range(0, 9)) +
        ''.join('END-TLV T%d\n' % i for i in range(9, 0, -1))},
    # BEGIN-TLV nested as deep as the include stack allows, then too deep
    'rtlvstack': {'dictionary': 'ATTRIBUTE T0 103 tlv\n' + ''.join(
        'BEGIN-TLV T%d\nATTRIBUTE T%d 1 tlv\n' % (i, i + 1) for i in range(0, 12))},
    # END-TLV without BEGIN-TLV
    'rendtlv': {'dictionary': 'ATTRIBUTE Before-Attr 240 integer\nEND-TLV Nothing\nATTRIBUTE After-Attr 241 integer\n'},
    # errors: unknown vendor, unknown parent attribute, include that cannot be
    # opened, absolute include, junk, bad vendor format
    'rerrors': {'dictionary':
        'ATTRIBUTE Bad-Vendor 240 integer No-Such-Vendor trailing junk here\n'
        'ATTRIBUTE After-Junk 241 integer\n'
        'BEGIN-TLV No-Such-Parent\nATTRIBUTE Orphan 1 integer\nEND-TLV No-Such-Parent\n'
        'ATTRIBUTE Orphan-2 1 integer No-Such-Parent\n'
        '$INCLUDE does-not-exist\n'
        'VENDOR Fmt-Vendor 55600 format=3,1\n'
        'VENDOR Fmt-Vendor2 55601 format=1,3\n'
        'VENDOR Fmt-Vendor3 55602 format=1,1,x\n'
        'BEGIN-VENDOR Fmt-Vendor\nBEGIN-VENDOR Fmt-Vendor2\nEND-VENDOR Fmt-Vendor2\n'
        'BEGIN-VENDOR Fmt-Vendor3 format=Extended-Vendor-Specific-9\n'
        'END-VENDOR Fmt-Vendor3\n'
        'VALUE Undefined-Attr Foo 1\n'
        'VALUE After-Junk Two 0x2\n'
        'WRONGKEYWORD foo bar\n'
        'ATTRIBUTE Fine-Attr 242 integer\n'},
    # nothing but comments and blank lines
    'rcomments': {'dictionary': '# only comments\n\n   \n\t# indented\n'},
    # the dictionary file is missing in the personal directory
    'rmissing': {},
}

# ---------------------------------------------------------------------------
# Capture writer
# ---------------------------------------------------------------------------

class Pcap:
    def __init__(self):
        self.frames = []
        self.ts = 1700000000

    def add(self, data):
        self.ts += 1
        self.frames.append((self.ts, data))

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for ts, d in self.frames:
                f.write(struct.pack('<IIII', ts, 0, len(d), len(d)) + d)


def ip_checksum(h):
    s = 0
    for i in range(0, len(h), 2):
        s += (h[i] << 8) + h[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Radius:
    """Builds RADIUS packets over UDP in a pcap."""

    def __init__(self, pcap):
        self.p = pcap
        self.ident = 0
        self.rid = 0

    def send(self, code, avps, rid=None, sport=40000, dport=1812, req_auth=False, to_server=True):
        if rid is None:
            self.rid = (self.rid + 1) & 0xff
            rid = self.rid
        body = b''.join(avps)
        # a fixed made-up authenticator
        auth = bytes((rid * 7 + i * 13) & 0xff for i in range(16))
        pkt = struct.pack('>BBH', code, rid, 20 + len(body)) + auth + body
        udp = struct.pack('>HHHH', sport, dport, 8 + len(pkt), 0) + pkt
        self.ident += 1
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), self.ident, 0x4000, 64, 17, 0,
                         bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
        ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
        self.p.add(bytes([2, 0, 0, 0, 0, 2]) + bytes([2, 0, 0, 0, 0, 1]) + b'\x08\x00' + ip + udp)
        return rid


def avp(t, v):
    return struct.pack('>BB', t, 2 + len(v)) + v


def vsa(vendor, vtype, value, tsz=1, lsz=1, flags=None):
    """A Vendor-Specific attribute with a single vendor attribute."""
    hdr = {1: struct.pack('>B', vtype), 2: struct.pack('>H', vtype),
           4: struct.pack('>I', vtype)}[tsz]
    n = tsz + lsz + (1 if flags is not None else 0) + len(value)
    if lsz == 1:
        hdr += struct.pack('>B', n)
    elif lsz == 2:
        hdr += struct.pack('>H', n)
    if flags is not None:
        hdr += struct.pack('>B', flags)
    return avp(26, struct.pack('>I', vendor) + hdr + value)


def tlv(t, v):
    return struct.pack('>BB', t, 2 + len(v)) + v


def evs(ext, vendor, vtype, value):
    """Extended-Vendor-Specific-N: type, length, extended type 26, vendor,
    vendor type, value."""
    body = struct.pack('>BI', 26, vendor) + struct.pack('>B', vtype) + value
    return struct.pack('>BB', ext, 2 + len(body)) + body


def u32(n):
    return struct.pack('>I', n)


def build_main(path):
    p = Pcap()
    r = Radius(p)
    # 1: every value type of the dictionary, with VALUE names and lengths
    r.send(1, [
        avp(1, b'alice'),
        avp(103, u32(2)), avp(103, u32(16)), avp(103, u32(99)),
        avp(103, struct.pack('>Q', 1 << 40)), avp(103, b'\x01\x02\x03'), avp(103, b'\x05'),
        avp(103, b'\x01\x02'), avp(103, b'\x01\x02\x03\x04\x05'),
        avp(104, b'\x07'), avp(105, struct.pack('>H', 300)),
        avp(106, struct.pack('>i', -5)), avp(106, u32(0xffffffff)), avp(106, struct.pack('>q', -9)),
        avp(106, b'\x80'), avp(106, b'\xff\xfe'), avp(106, b'\xff\xff\xfd'), avp(106, b'12345'),
        avp(107, b'a string'),
        avp(108, bytes(range(8))),
        avp(109, bytes([192, 0, 2, 7])),
        avp(110, bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [1])),
        avp(111, bytes([0, 64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1])),
        avp(112, u32(0x1234abcd)),
        avp(113, u32(1700000000)),
        avp(114, bytes(range(10))),
        avp(115, bytes([0, 1, 2, 3, 4, 5])),
        avp(116, bytes(range(8))),
        avp(117, bytes([10, 0, 0, 1])),
        avp(117, bytes([0xfe, 0x80] + [0] * 13 + [1])),
        avp(119, b'\x05' + u32(1)), avp(119, b'\x3f\x00'),
        avp(122, b'part1'), avp(122, b'part2'),
        avp(0xbf, u32(1)), avp(192, u32(2)), avp(193, u32(3)),
        avp(194, b'renamed attribute'),
        avp(195, u32(1)), avp(196, u32(2)),
        avp(197, b'\xaa\xbb'), avp(198, u32(4)),
        avp(199, u32(1)),
    ])
    # 2: the same attributes with the wrong lengths
    r.send(4, [
        avp(109, b'\x01\x02\x03'), avp(110, b'\x01'), avp(112, b'\x01'), avp(113, b'\x01'),
        avp(115, b'\x01'), avp(117, b'\x01\x02\x03'),
        avp(111, b'\x00'), avp(111, bytes([1, 64, 0x20, 1])), avp(111, bytes([0, 200, 0x20, 1])),
        avp(111, bytes([0, 8] + [0x20] * 17)),
        avp(108, b''), avp(104, b''), avp(119, b'\x05'),
        avp(120, b''),
    ])
    # 3: TLVs: top level (nested three deep), vendor TLV
    r.send(2, [
        avp(118, tlv(1, u32(7)) + tlv(1, u32(8)) + tlv(2, b'tlv string') + tlv(3, bytes([192, 0, 2, 1])) +
            tlv(4, tlv(1, u32(5)) + tlv(2, tlv(1, b'deep'))) + tlv(9, b'unknown tlv')),
        avp(118, b''),
        vsa(55555, 4, tlv(1, u32(1)) + tlv(2, b'vtlv') + tlv(3, tlv(1, u32(3)))),
    ])
    # 4: vendor formats, with and without dictionary entries
    r.send(4, [
        vsa(55555, 1, u32(1)), vsa(55555, 1, u32(2)), vsa(55555, 1, u32(77)),
        vsa(55555, 2, b'vendor string'), vsa(55555, 3, bytes([10, 1, 1, 1])),
        vsa(55555, 5, b'\x01\x02'), vsa(55555, 6, bytes([0xfe, 0x80] + [0] * 13 + [2])),
        vsa(55555, 99, b'unknown vendor attribute'),
        vsa(55556, 1, u32(10), 2, 2), vsa(55556, 2, b'two two', 2, 2),
        vsa(55557, 1, u32(11), 4, 0),
        vsa(55558, 1, b'frag1', 1, 1, 0x80), vsa(55558, 1, b'frag2', 1, 1, 0x80),
        vsa(55558, 1, b'last', 1, 1, 0x00), vsa(55558, 2, b'flags only', 1, 1, 0x00),
        vsa(0xd9fe, 0x10, u32(12), 1, 2),
        vsa(55570, 1, u32(13)), vsa(55571, 1, u32(14)),
        vsa(777777, 1, b'unknown vendor'),
        vsa(55555, 1, u32(1)) + vsa(55556, 1, u32(2), 2, 2),
    ])
    # 5: extended vendor specific attributes
    r.send(1, [
        evs(241, 55561, 1, u32(1)), evs(241, 55561, 2, b'evs one string'),
        evs(242, 55562, 1, u32(2)), evs(243, 55563, 1, u32(3)),
        evs(244, 55564, 1, u32(4)),
        avp(26, u32(55555) + b'\x01\x06' + u32(5)),
    ])
    # 6: the old vendor attribute form
    r.send(2, [avp(26, u32(55555) + struct.pack('>BB', 1, 6) + u32(9))])
    r.send(11, [avp(1, b'challenge'), avp(103, u32(1))])
    r.send(3, [avp(18, b'rejected'), avp(103, u32(2))])
    p.write(path)
    return len(p.frames)


def build_malformed(path):
    p = Pcap()
    r = Radius(p)
    r.send(1, [
        avp(26, u32(55555)),                              # vendor id only
        avp(26, u32(55555) + b'\x01'),                     # VSA header cut off
        avp(26, u32(55555) + b'\x01\x01'),                 # VSA length below its header
        avp(26, b'\x00\x01'),                              # no room for the vendor id
        avp(26, u32(55556) + b'\x00\x01\x00\x03'),         # 2/2 header, length too short
        avp(118, b'\x01'),                                 # TLV header cut off
        avp(118, b'\x01\x01'),                             # TLV length < 2
        avp(118, b'\x01\x09\x00'),                         # TLV length past the attribute
        avp(118, tlv(4, b'\x01')),                         # nested TLV cut off
        avp(241, b''),                                     # extended attribute without type
        avp(245, b'\x1a'),                                 # long extended without more flags
    ])
    # AVP cut off in the packet
    pkt_avps = avp(1, b'x') + b'\x67\x20abc'
    r.send(1, [pkt_avps])
    # a TLV chain deeper than the dictionary has
    deep = tlv(9, b'x')
    for _ in range(12):
        deep = tlv(4, deep)
    r.send(2, [avp(118, deep)])
    p.write(path)
    return len(p.frames)


def write_cfg(base, name, files):
    d = os.path.join(base, name, 'radius') if name else os.path.join(base, 'radius')
    os.makedirs(d, exist_ok=True)
    for fn, text in files.items():
        path = os.path.join(d, fn)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(text)


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    write_cfg(os.path.join(out, 'cfg'), '', {
        'dictionary': MAIN_DICT, 'dictionary.part': PART_DICT,
        os.path.join('sub', 'dictionary.sub'): SUB_DICT})
    for name, files in EXTRA_CFGS.items():
        write_cfg(out, 'cfg-' + name, files)
    # an include with an absolute path (the directory of later relative
    # includes is the directory of that file) and one that fails to open
    ab = os.path.abspath(os.path.join(out, 'cfg', 'radius'))
    write_cfg(out, 'cfg-rabs', {
        'dictionary': 'ATTRIBUTE Abs-Before 240 integer\n$INCLUDE %s/sub/dictionary.sub\n'
                      'ATTRIBUTE Abs-After 241 integer\n$INCLUDE %s/dictionary.part\n' % (ab, ab)})
    n = build_main(os.path.join(out, 'radius_dict_coverage.pcap'))
    m = build_malformed(os.path.join(out, 'radius_dict_coverage_malformed.pcap'))
    print('main: %d frames, malformed: %d frames' % (n, m))


if __name__ == '__main__':
    main()
