#!/usr/bin/env python3
# Generates test/captures/lacp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the LACP coverage captures. Usage: mklacp.py <outdir> [-v].
Synthetic data only (addresses 02:00:00:00:00:xx, locally administered)."""
import struct
import sys

SLOW_MAC = bytes.fromhex('0180c2000002')
SRC1 = bytes.fromhex('020000000001')
SRC2 = bytes.fromhex('020000000002')
ETH_SLOW = 0x8809
ETH_VLACP = 0x8103


def eth(dst, src, etype, payload):
    return dst + src + struct.pack('!H', etype) + payload


def actor(tlv_type=1, tlv_len=20, sysprio=0x8000, sysid=SRC1, key=1,
          portprio=0x8000, port=1, state=0x3d, rsv=b'\0\0\0'):
    return (struct.pack('!BBH', tlv_type, tlv_len, sysprio) + sysid +
            struct.pack('!HHHB', key, portprio, port, state) + rsv)


def collector(tlv_type=3, tlv_len=16, delay=0, rsv=b'\0' * 12):
    return struct.pack('!BBH', tlv_type, tlv_len, delay) + rsv


def lacpdu(version=1, a=None, p=None, c=None, extra=b'', term=b'\0\0',
           pad=True):
    """LACPDU after the slow protocols subtype octet. pad: fill to the
    fixed 109 octets (without the subtype)."""
    a = a if a is not None else actor(1)
    p = p if p is not None else actor(2, sysid=SRC2, key=2, port=2)
    c = c if c is not None else collector()
    b = bytes([version]) + a + p + c + extra + term
    if pad and len(b) < 109:
        b += b'\0' * (109 - len(b))
    return b


def slow(body, src=SRC1, subtype=1):
    return eth(SLOW_MAC, src, ETH_SLOW, bytes([subtype]) + body)


def tlv(t, n, fill=0x55):
    return bytes([t, n]) + bytes([fill]) * (n - 2)


def hp_irf(domain=1, mac=SRC1, switch=1, port=2):
    """HP IRF MAD extra data after the pad: 0x64, rest-of-length, ..."""
    b = b'\x64\x00' + b'\x00\x00' + struct.pack('!H', domain) + mac
    b += b'\x00' * 8 + struct.pack('!HH', switch, port) + b'\x00\x00'
    return bytes([0x64, len(b) - 2]) + b[2:]


def main():
    out = sys.argv[1]
    flags = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
    main_fr = []      # (frame, caplen or None)

    # 1-2: plain LACPDU v1 from each system, in sync/collecting/distributing
    main_fr.append((slow(lacpdu()), None))
    main_fr.append((slow(lacpdu(a=actor(1, sysid=SRC2, key=2, port=2),
                                p=actor(2, sysid=SRC1, key=1, port=1)),
                         src=SRC2), None))
    # 3-10: one state flag at a time in the actor, a different one in the partner
    for i, f in enumerate(flags):
        main_fr.append((slow(lacpdu(a=actor(1, state=f, port=10 + i),
                                    p=actor(2, state=flags[(i + 3) % 8], sysid=SRC2, key=2, port=20 + i))), None))
    # 11-12: all flags set and no flag set
    main_fr.append((slow(lacpdu(a=actor(1, state=0xff), p=actor(2, state=0x00, sysid=SRC2))), None))
    main_fr.append((slow(lacpdu(a=actor(1, state=0x00), p=actor(2, state=0xff, sysid=SRC2))), None))
    # 13-14: other priorities, keys and ports, non-zero reserved bytes and delay
    main_fr.append((slow(lacpdu(a=actor(1, sysprio=0xffff, key=0xffff, portprio=0xffff, port=0xffff, rsv=b'\x01\x02\x03'),
                                p=actor(2, sysprio=1, sysid=SRC2, key=0, portprio=1, port=0),
                                c=collector(delay=0x1234, rsv=bytes(range(12))))), None))
    main_fr.append((slow(lacpdu(version=2)), None))
    # 15-16: LACPv2 style: extra TLVs (port algorithm, port conversation ID digest, a short TLV)
    main_fr.append((slow(lacpdu(version=2, extra=tlv(4, 6, 0x01))), None))
    main_fr.append((slow(lacpdu(version=2, extra=tlv(4, 6) + tlv(5, 18) + tlv(6, 2))), None))
    # 17: TLVs make the LACPDU longer than the fixed size: no pad
    main_fr.append((slow(lacpdu(version=2, extra=tlv(4, 60) + tlv(7, 20)), ), None))
    # 18: Ethernet trailer after the padded LACPDU (not claimed by LACP)
    main_fr.append((slow(lacpdu() + b'\xaa\xbb\xcc\xdd'), None))
    # 19: a trailer that starts with 0x64 but whose length does not match (not HP)
    main_fr.append((slow(lacpdu() + b'\x64\x09\x00\x00\x00\x00\x00'), None))
    # 20-21: HP IRF MAD data after the pad
    main_fr.append((slow(lacpdu() + hp_irf()), None))
    main_fr.append((slow(lacpdu() + hp_irf(domain=0xbeef, mac=SRC2, switch=5, port=8), src=SRC2), None))
    # 22: a 0x64 trailer with exactly 2 octets left (length_remaining > 2 fails)
    main_fr.append((slow(lacpdu() + b'\x64\x00'), None))
    # 23: the reproducer of the fix: snaplen-truncated frame with a trailer
    # (the LACP tvb used to be shrunk below the bytes already dissected)
    full = slow(lacpdu() + b'\xaa' * 40)
    main_fr.append((full, 14 + 1 + 120))
    # 24: truncated HP data, no trailer attributed to LACP
    full = slow(lacpdu() + hp_irf())
    main_fr.append((full, 14 + 1 + 112))
    # 25-28: vLACP (ethertype 0x8103): LACP magic, marker magic, with trailer, HP-like
    main_fr.append((eth(SLOW_MAC, SRC1, ETH_VLACP, b'\x01' + lacpdu()), None))
    main_fr.append((eth(SLOW_MAC, SRC2, ETH_VLACP, b'\x02' + lacpdu()), None))
    main_fr.append((eth(SLOW_MAC, SRC1, ETH_VLACP, b'\x01' + lacpdu() + b'\x00' * 6), None))
    main_fr.append((eth(SLOW_MAC, SRC1, ETH_VLACP, b'\x01' + lacpdu() + hp_irf()), None))

    mal = []
    # not padded at all (terminator only): the dissector pads past the end
    mal.append((slow(lacpdu(pad=False)), None))
    # a 0x64 trailer of HP shape (length matches) but cut short
    mal.append((slow(lacpdu() + b'\x64\x05\x00\x00\x00\x00\x00'), None))
    # wrong TLV types and lengths (error expert infos)
    mal.append((slow(lacpdu(a=actor(5, 20))), None))
    mal.append((slow(lacpdu(a=actor(1, 21))), None))
    mal.append((slow(lacpdu(p=actor(1, 20, sysid=SRC2))), None))
    mal.append((slow(lacpdu(p=actor(2, 19, sysid=SRC2))), None))
    mal.append((slow(lacpdu(c=collector(2, 16))), None))
    mal.append((slow(lacpdu(c=collector(3, 15))), None))
    # the terminator has a length of 1 (not 0, and below 2: loop stops)
    mal.append((slow(lacpdu(term=b'\x00\x01')), None))
    # an extra TLV chain that never reaches a terminator (runs past the end)
    mal.append((slow(lacpdu(version=2, extra=tlv(4, 2), term=b'', pad=False)[:109]), None))
    # TLV whose length skips past the end of the frame
    mal.append((slow(lacpdu(version=2, extra=b'\x04\xf0', term=b'', pad=False)), None))
    # terminator type with a length of 4 (loop ends, length not 0)
    mal.append((slow(lacpdu(term=b'\x00\x04')), None))
    # truncated in the actor, the partner, the collector and the version
    full = lacpdu()
    for n in (1, 5, 25, 45, 60):
        mal.append((slow(full[:n]), None))
    # vLACP truncated
    mal.append((eth(SLOW_MAC, SRC1, ETH_VLACP, b'\x01\x01\x01\x14'), None))
    # an empty LACPDU (not even the version)
    mal.append((eth(SLOW_MAC, SRC1, ETH_SLOW, b'\x01'), None))

    def write(path, frames):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, (fr, caplen) in enumerate(frames):
                cap = fr if caplen is None else fr[:caplen]
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(cap), len(fr)))
                f.write(cap)

    write(out + '/lacp-coverage.pcap', main_fr)
    write(out + '/lacp-coverage-malformed.pcap', mal)
    if '-v' in sys.argv:
        print('main frames: 1-%d, malformed: %d' % (len(main_fr), len(mal)))


main()
