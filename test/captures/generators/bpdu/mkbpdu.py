#!/usr/bin/env python3
# Generates test/captures/bpdu_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the STP dissector (packet-bpdu.c).

STP, RSTP, MSTP (IEEE 802.1s format, the message-count Version 3 Length
and the Cisco/alternative MSTI format), SPB (Version 4), Cisco PVST+ and
Rapid PVST+, over LLC SAP 0x42, ethertype 0x8181 and the Cisco SNAP PIDs,
and the GARP destination addresses that are handed to GMRP/GVRP. Every
packet is built from scratch with struct; no captured traffic is used.

Usage: mkbpdu.py <output directory>

Writes:
  bpdu-coverage.pcap            the main capture (frames listed in README.md)
  bpdu-coverage-malformed.pcap  warnings, errors and exceptions
  bpdu-coverage-extra.pcapng    coverage only: Cisco HDLC and Linux cooked
                                (no Ethernet destination) interfaces, and the
                                >64 KiB SPB Version 4 offset reproducer of
                                bpdu_v4len_wrap.py
"""

import os
import struct
import sys

STP_MAC = bytes.fromhex('0180c2000000')
PVST_MAC = bytes.fromhex('01000ccccccd')
SRC = bytes.fromhex('020000000001')
LLC_STP = b'\x42\x42\x03'


def mac(n):
    return b'\x02\x00\x00\x00\x00' + bytes([n])


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def pcapng(path, interfaces, frames):
    """interfaces: list of linktypes; frames: list of (interface, data)."""
    def block(btype, body):
        body += b'\0' * (-len(body) % 4)
        n = 12 + len(body)
        return struct.pack('<II', btype, n) + body + struct.pack('<I', n)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in interfaces:
        out += block(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                    len(fr), len(fr)) + fr)
    with open(path, 'wb') as f:
        f.write(out)


def llc_frame(payload, dst=STP_MAC, src=SRC, llc=LLC_STP):
    """IEEE 802.3 frame with a length field and an LLC header."""
    return dst + src + struct.pack('>H', len(llc) + len(payload)) + llc + payload


def snap_frame(pid, payload, dst=PVST_MAC):
    return llc_frame(payload, dst=dst, llc=b'\xaa\xaa\x03\x00\x00\x0c' + struct.pack('>H', pid))


def eth2_frame(etype, payload, dst=STP_MAC):
    return dst + SRC + struct.pack('>H', etype) + payload


def bridge_id(prio, n):
    return struct.pack('>H', prio) + mac(n)


def common(version, btype, flags, root=(0x8000, 1), cost=0, bridge=(0x8000, 2),
           port=0x8001, age=0, maxage=20, hello=2, fwd=15):
    """The 35 octets shared by Configuration, RST, MST and SPT BPDUs."""
    return (struct.pack('>HBBB', 0, version, btype, flags) + bridge_id(*root) +
            struct.pack('>I', cost) + bridge_id(*bridge) +
            struct.pack('>HHHHH', port, age * 256, maxage * 256, hello * 256, fwd * 256))


def conf(flags=0, **kw):
    return common(0, 0x00, flags, **kw)


def tcn():
    return struct.pack('>HBB', 0, 0, 0x80)


def rst(flags, version=2, v1len=0, **kw):
    return common(version, 0x02, flags, **kw) + bytes([v1len])


def mst_fixed(v3len, selector=0, name=b'SYNTH-REGION', rev=7,
              cist_cost=200000, cist_bridge=(0x7001, 3), hops=20):
    """Octets 36..101 of an MST BPDU in the IEEE 802.1s layout."""
    return (struct.pack('>HB', v3len, selector) + name.ljust(32, b'\0') +
            struct.pack('>H', rev) + bytes(range(0x10, 0x20)) +
            struct.pack('>I', cist_cost) + bridge_id(*cist_bridge) + bytes([hops]))


def alt_fixed(selector, name=b'ALT-REGION', rev=3, cist_bridge=(0x6002, 4),
              cist_cost=300000, hops=19):
    """Octets 36..101 in the alternative layout (Version 3 Length 0, the
    format selector holds the length, CIST bridge id before the cost)."""
    return (struct.pack('>HB', 0, selector) + name.ljust(32, b'\0') +
            struct.pack('>H', rev) + bytes(range(0x20, 0x30)) +
            bridge_id(*cist_bridge) + struct.pack('>I', cist_cost) + bytes([hops]))


def msti(flags, prio, mstid, root_n, cost, bprio, pprio, hops):
    """IEEE 802.1s MSTI Configuration Message, 16 octets."""
    return (bytes([flags]) + struct.pack('>H', (prio << 12) | mstid) + mac(root_n) +
            struct.pack('>I', cost) + bytes([bprio << 4, pprio << 4, hops]))


def alt_msti(mstid, flags, prio, root_n, cost, bprio, bridge_n, port, hops):
    """Alternative-format MSTI message, 26 octets."""
    return (struct.pack('>HB', mstid, flags) +
            struct.pack('>H', (prio << 12) | mstid) + mac(root_n) +
            struct.pack('>I', cost) +
            struct.pack('>H', (bprio << 12) | mstid) + mac(bridge_n) +
            struct.pack('>HB', port, hops))


def spt_ext(v4len=85, name=b'SPT-REGION', rev=9, agree=0x3d, fmt=0x21, conv=0x43,
            edges=5):
    """Version 4 Length and the SPT extension (aux MCID and agreement data)."""
    body = (bytes([1]) + name.ljust(32, b'\0') + struct.pack('>H', rev) +
            bytes(range(0x40, 0x50)) +                  # aux MCID, 51 octets
            bytes([agree, 0, fmt, conv]) + struct.pack('>H', edges) + b'\0' * 8 +
            bytes(range(0x60, 0x74)))                   # agreement digest
    assert len(body) == 85
    return struct.pack('>H', v4len) + body


def pvst_tlv(t, value):
    return struct.pack('>HH', t, len(value)) + value


def gvrp():
    # Protocol ID 1, VID attribute: JoinIn VID 10, LeaveAll, end marks.
    return (struct.pack('>HB', 1, 1) + bytes([4, 2]) + struct.pack('>H', 10) +
            bytes([2, 0]) + b'\0\0')


def gmrp():
    # Protocol ID 1, Group Membership JoinEmpty 01:00:5e:00:00:01, end marks.
    return (struct.pack('>HB', 1, 1) + bytes([8, 1]) + bytes.fromhex('01005e000001') +
            b'\0\0')


def main_frames():
    F = []
    # 1-3: STP Configuration (TC + TCACK, plain) and TCN
    F.append(llc_frame(conf(0x81, root=(0x8000 | 10, 1), cost=4, port=0x8002, age=1)))
    F.append(llc_frame(conf(0x00)))
    F.append(llc_frame(tcn()))
    # 4-7: RSTP, each port role, all flags across them
    F.append(llc_frame(rst(0x7d, root=(0x1000 | 1, 5), cost=20000)))   # designated, agreement, fwd, lrn, TC
    F.append(llc_frame(rst(0x88)))                                      # root, TCACK
    F.append(llc_frame(rst(0x06)))                                      # alternate/backup, proposal
    F.append(llc_frame(rst(0x00)))                                      # unknown role 0
    # 8: MSTP, IEEE 802.1s, three MSTIs
    m = (msti(0x7c, 8, 1, 6, 20000, 8, 8, 19) + msti(0x0e, 9, 2, 7, 0, 9, 1, 18) +
         msti(0x88, 0xf, 4094, 8, 4000, 0xf, 0xf, 1))
    F.append(llc_frame(rst(0x3c, version=3) + mst_fixed(64 + len(m)) + m))
    # 9: MSTP, no MSTI
    F.append(llc_frame(rst(0x7d, version=3) + mst_fixed(64)))
    # 10: MSTP, Version 3 Length 2 (a count of MSTI messages, not octets)
    m = msti(0x7c, 8, 11, 9, 100, 8, 8, 20) + msti(0x7c, 8, 12, 9, 200, 8, 8, 20)
    F.append(llc_frame(rst(0x3c, version=3) + mst_fixed(2) + m))
    # 11: alternative MSTI format reproducer (bpdu_alt_msti.py): MSTID 1, root 0x8001
    b = rst(0x3c, version=3, root=(0x8000, 1)) + alt_fixed(64 + 26, name=b'SYNTH',
                                                          cist_bridge=(0x8000, 3),
                                                          cist_cost=0, hops=20)
    b += alt_msti(1, 0x7c, 8, 4, 20000, 8, 5, 0x8002, 20) + b'\0'
    F.append(llc_frame(b))
    # 12: alternative format, two MSTIs (MSTID 5, 4094)
    b = rst(0x3c, version=3) + alt_fixed(64 + 52)
    b += (alt_msti(5, 0x7c, 9, 10, 1000, 9, 11, 0x9001, 18) +
          alt_msti(4094, 0x0e, 0xf, 12, 2000, 0xf, 13, 0xf0ff, 17)) + b'\0'
    F.append(llc_frame(b))
    # 13: Version 3 Length 0 and a length that does not match the selector:
    #     unknown MSTI format, no MSTIs, extra octets left as data
    F.append(llc_frame(rst(0x3c, version=3) + mst_fixed(0, selector=0) + b'\0' * 8))
    # 14: version 3 with Version 1 Length not 0: treated as RSTP
    F.append(llc_frame(rst(0x3c, version=3, v1len=1) + b'\0'))
    # 15: version 3 shorter than 102 octets: treated as RSTP
    F.append(llc_frame(rst(0x3c, version=3) + b'\0' * 40))
    # 16: SPB, one MSTI and the SPT extension
    m = msti(0x7c, 8, 1, 6, 20000, 8, 8, 19)
    F.append(llc_frame(rst(0x7d, version=4) + mst_fixed(64 + 16) + m + spt_ext()))
    # 17: SPB, no MSTI, Version 4 Length below 53 (no SPT extension)
    F.append(llc_frame(rst(0x3c, version=4) + mst_fixed(64) + struct.pack('>H', 40) + b'\0' * 40))
    # 18: SPB with only 104 octets: no Version 4 Length
    F.append(llc_frame(rst(0x3c, version=4) + mst_fixed(64) + b'\0\0'))
    # 19: SPB with the unknown MSTI format (Version 3 Length 0) and the SPT extension
    F.append(llc_frame(rst(0x3c, version=4) + mst_fixed(0) + spt_ext(agree=0x02)))
    # 20: SPB with the message-count Version 3 Length (1) and the SPT extension
    m = msti(0x7c, 8, 21, 6, 500, 8, 8, 19)
    F.append(llc_frame(rst(0x3c, version=4) + mst_fixed(1) + m + spt_ext(agree=0x10)))
    # 21-23: ethertype 0x8181 (STP, RSTP, MSTP)
    F.append(eth2_frame(0x8181, conf(0x01)))
    F.append(eth2_frame(0x8181, rst(0x3c)))
    F.append(eth2_frame(0x8181, rst(0x3c, version=3) + mst_fixed(64 + 16) +
                        msti(0x7c, 8, 1, 6, 20000, 8, 8, 19)))
    # 24-26: Cisco SNAP PIDs handled as plain STP (RLQ request, RLQ response, VLAN bridge)
    F.append(snap_frame(0x0108, conf(0x00)))
    F.append(snap_frame(0x0109, conf(0x00, cost=19)))
    F.append(snap_frame(0x010c, conf(0x00, port=0x8003)))
    # 27: PVST+ Configuration BPDU, Originating VLAN 100
    F.append(snap_frame(0x010b, conf(0x00, root=(0x8000 | 100, 1)) + b'\0' +
                        pvst_tlv(0, struct.pack('>H', 100))))
    # 28: Rapid PVST+, Originating VLAN 200
    F.append(snap_frame(0x010b, rst(0x3c, root=(0x8000 | 200, 1)) +
                        pvst_tlv(0, struct.pack('>H', 200))))
    # 29: PVST+ with an unknown TLV (comment) before the Originating VLAN TLV
    F.append(snap_frame(0x010b, conf(0x00) + b'\0' + pvst_tlv(7, b'\xde\xad') +
                        pvst_tlv(0, struct.pack('>H', 300))))
    # 30-33: GARP destinations: GMRP, GVRP (01-80-C2-00-00-21 and -0D), unknown GARP app
    F.append(llc_frame(gmrp(), dst=bytes.fromhex('0180c2000020')))
    F.append(llc_frame(gvrp(), dst=bytes.fromhex('0180c2000021')))
    F.append(llc_frame(gvrp(), dst=bytes.fromhex('0180c200000d')))
    F.append(llc_frame(gvrp(), dst=bytes.fromhex('0180c200002a')))
    # 34: 01-80-C2-00-00-0E (not GARP) is STP
    F.append(llc_frame(conf(0x00), dst=bytes.fromhex('0180c200000e')))
    return F


def malformed_frames():
    F = []
    # 1: unknown protocol version 1 (warning)
    F.append(llc_frame(common(1, 0x00, 0)))
    # 2: unknown BPDU type 0x55 (warning), data
    F.append(llc_frame(struct.pack('>HBB', 0, 0, 0x55) + b'\x01\x02\x03'))
    # 3: PVST+ without TLV room (truncated, origvlan missing)
    F.append(snap_frame(0x010b, conf(0x00) + b'\0'))
    # 4: PVST+ TLV length past the end
    F.append(snap_frame(0x010b, conf(0x00) + b'\0' + struct.pack('>HH', 0, 10) + b'\0\1'))
    # 5: PVST+ Originating VLAN TLV with length 3
    F.append(snap_frame(0x010b, conf(0x00) + b'\0' + pvst_tlv(0, b'\0\1\2')))
    # 6: Rapid PVST+ with only an unknown TLV (origvlan missing)
    F.append(snap_frame(0x010b, rst(0x3c) + pvst_tlv(9, b'\1\2\3\4')))
    # 7: truncated Configuration BPDU
    F.append(llc_frame(conf(0x00)[:20]))
    # 8: truncated MSTI (Version 3 Length promises 3 MSTIs, one present)
    F.append(llc_frame(rst(0x3c, version=3) + mst_fixed(64 + 48) +
                       msti(0x7c, 8, 1, 6, 0, 8, 8, 19)))
    # 9: SPB with the SPT extension cut short
    F.append(llc_frame(rst(0x3c, version=4) + mst_fixed(64) + spt_ext()[:30]))
    # 10: version 5 RST/MST (warning), treated as MST with an SPT extension
    F.append(llc_frame(rst(0x3c, version=5) + mst_fixed(64) + spt_ext()))
    # 11: only the BPDU type byte present (short)
    F.append(llc_frame(b'\0\0'))
    return F


def v4len_wrap_frame():
    """bpdu_v4len_wrap.py: Version 3 Length 65535 in a >64 KiB
    frame; the Version 4 Length is at 102 + 65471 (not wrapped to 37)."""
    v3 = 65535
    total = v3 - 64
    m = (b'\x00' + struct.pack('>H6s', 0x8001, mac(4)) + b'\0\0\0\0' + b'\x80\x80\x14') * ((total + 15) // 16)
    b = rst(0x3c, version=4) + mst_fixed(v3, name=b'SYNTH', rev=0, cist_cost=0,
                                          cist_bridge=(0x8000, 3))
    b += m
    b = b[:102 + total] + spt_ext() + b'\0' * 40
    return eth2_frame(0x8181, b)


def sll(payload, proto):
    # Linux cooked v1: packet type 0 (to us), ARPHRD_ETHER, addr len 6
    return struct.pack('>HHH8sH', 0, 1, 6, SRC + b'\0\0', proto) + payload


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    pcap(os.path.join(out, 'bpdu-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'bpdu-coverage-malformed.pcap'), malformed_frames())
    # interfaces: 0 Cisco HDLC (104), 1 Linux cooked (113), 2 Ethernet
    chdlc = b'\x8f\x00\x42\x42'
    extra = [
        (0, chdlc + conf(0x00)),
        (0, chdlc + rst(0x3c, version=3) + mst_fixed(64 + 16) + msti(0x7c, 8, 1, 6, 0, 8, 8, 19)),
        (1, sll(LLC_STP + conf(0x00), 0x0004)),
        (1, sll(rst(0x3c), 0x8181)),
        (2, v4len_wrap_frame()),
    ]
    pcapng(os.path.join(out, 'bpdu-coverage-extra.pcapng'), [104, 113, 1], extra)


if __name__ == '__main__':
    main()
