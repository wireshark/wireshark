#!/usr/bin/env python3
# Generates test/captures/netlink_psample_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the psample (packet sampling, Generic Netlink) coverage captures.

Usage: mkpsample.py <outdir>
Writes netlink-psample-coverage.pcap (LINKTYPE_NETLINK, 253) and
netlink-psample-coverage-malformed.pcapng.
Everything is built with struct; nothing comes from a real network.
"""
import os
import struct
import sys

# ---- helpers (pcap/pcapng writers and netlink builders) ----------------
ARPHRD_NETLINK = 824
NETLINK_GENERIC = 16
GENL_ID_CTRL = 0x10
NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLM_F_DUMP = 0x300
NLA_F_NESTED = 0x8000
NLA_F_NET_BYTEORDER = 0x4000
FAMILY_ID = 0x23
FAMILY_NAME = b'psample'


def pcap(fn, pkts, linktype=253):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(p), len(p)))
            f.write(p)


def pcapng(fn, pkts):
    """pkts: list of (linktype, bytes); one interface per link type."""
    def blk(t, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    ifs = {}
    for lt, _ in pkts:
        if lt not in ifs:
            ifs[lt] = len(ifs)
            out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (lt, p) in enumerate(pkts):
        ts = 1700000000 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifs[lt], ts >> 32, ts & 0xffffffff, len(p), len(p)) + p)
    with open(fn, 'wb') as f:
        f.write(out)


def sll(proto=NETLINK_GENERIC):
    return struct.pack('>HHH8sH', 4, ARPHRD_NETLINK, 0, b'\0' * 8, proto)


class Enc:
    def __init__(self, big=False):
        self.e = '>' if big else '<'

    def attr(self, t, payload=b'', flags=0):
        l = 4 + len(payload)
        return struct.pack(self.e + 'HH', l, t | flags) + payload + b'\0' * ((4 - l % 4) % 4)

    def u8(self, t, v, flags=0):
        return self.attr(t, struct.pack('B', v), flags)

    def u16(self, t, v, flags=0):
        return self.attr(t, struct.pack(self.e + 'H', v), flags)

    def u32(self, t, v, flags=0):
        return self.attr(t, struct.pack(self.e + 'I', v), flags)

    def u64(self, t, v, flags=0):
        return self.attr(t, struct.pack(self.e + 'Q', v), flags)

    def s(self, t, v, flags=0):
        return self.attr(t, v + b'\0', flags)

    def nlmsg(self, mtype, payload, flags=NLM_F_REQUEST, seq=1, pid=0):
        return struct.pack(self.e + 'IHHII', 16 + len(payload), mtype, flags, seq, pid) + payload

    def genl(self, cmd, attrs=b'', version=1):
        return struct.pack(self.e + 'BBH', cmd, version, 0) + attrs

    def frame(self, mtype, cmd, attrs=b'', **kw):
        return sll() + self.nlmsg(mtype, self.genl(cmd, attrs), **kw)


def newfamily(e, fid, name, **kw):
    """CTRL_CMD_NEWFAMILY (1) telling the dissector fid -> name."""
    return e.frame(GENL_ID_CTRL, 1, e.u16(1, fid) + e.s(2, name), **kw)
# ---- end helpers --------------------------------------------------------

def csum(b):
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4_udp(sport=5000, dport=5001, data=b'drop-me!'):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                    bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + udp


def ipv6_udp(data=b'drop-v6'):
    src, dst = bytes(range(1, 17)), bytes(range(17, 33))
    udp = struct.pack('>HHHH', 5000, 5001, 8 + len(data), 0) + data
    pseudo = src + dst + struct.pack('>IBBBB', len(udp), 0, 0, 0, 17)
    pad = b'\0' if len(udp) % 2 else b''
    udp = udp[:6] + struct.pack('>H', csum(pseudo + udp + pad)) + udp[8:]
    return struct.pack('>IHBB', 0x60000000, len(udp), 17, 64) + src + dst + udp


def eth(ethertype, payload):
    return bytes.fromhex('020000000002020000000001') + struct.pack('>H', ethertype) + payload


LE = Enc()
BE = Enc(True)

CMD_SAMPLE, CMD_GET_GROUP, CMD_NEW_GROUP, CMD_DEL_GROUP = range(4)
(A_IIFINDEX, A_OIFINDEX, A_ORIGSIZE, A_SAMPLE_GROUP, A_GROUP_SEQ, A_SAMPLE_RATE, A_DATA,
 A_GROUP_REFCOUNT, A_TUNNEL, A_PAD, A_OUT_TC, A_OUT_TC_OCC, A_LATENCY, A_TIMESTAMP,
 A_PROTO) = range(15)
ETH_P_IP, ETH_P_IPV6, ETH_P_802_2, ETH_P_ALL, ETH_P_CAN = 0x0800, 0x86dd, 0x0004, 0x0003, 0x000c
LLC = b'\x0a\x0a\x03\x00'


def t(cmd, attrs=b'', e=LE, **kw):
    return e.frame(FAMILY_ID, cmd, attrs, **kw)


def sample(e=LE, proto=ETH_P_IP, data=None, extra=b''):
    """A PSAMPLE_CMD_SAMPLE message in the order the kernel sends it."""
    if data is None:
        data = eth(ETH_P_IP, ipv4_udp())
    return (e.u16(A_IIFINDEX, 3) + e.u16(A_OIFINDEX, 4) + e.u32(A_ORIGSIZE, len(data) + 60) +
            e.u32(A_SAMPLE_GROUP, 5) + e.u32(A_GROUP_SEQ, 100) + e.u32(A_SAMPLE_RATE, 1000) +
            e.u16(A_PROTO, proto) + extra + e.attr(A_DATA, data))


def main_frames():
    f = [newfamily(LE, FAMILY_ID, FAMILY_NAME)]                                      # 1
    # 2: a sample with Ethernet data and every optional attribute
    f.append(t(CMD_SAMPLE, sample(extra=LE.u16(A_OUT_TC, 3) + LE.u64(A_OUT_TC_OCC, 4096) +
                                  LE.u64(A_LATENCY, 123456) +
                                  LE.u64(A_TIMESTAMP, 1700000000123456789) +
                                  LE.u32(A_GROUP_REFCOUNT, 2) + LE.u32(A_PAD, 0) +
                                  LE.attr(A_TUNNEL, LE.u32(1, 7) + LE.u32(2, 8), NLA_F_NESTED)),
               pid=55))
    # 3-5: group commands
    f.append(t(CMD_GET_GROUP, flags=NLM_F_REQUEST | NLM_F_DUMP))
    f.append(t(CMD_NEW_GROUP, LE.u32(A_SAMPLE_GROUP, 5) + LE.u32(A_GROUP_REFCOUNT, 1) +
               LE.u32(A_GROUP_SEQ, 0), pid=55))
    f.append(t(CMD_DEL_GROUP, LE.u32(A_SAMPLE_GROUP, 5) + LE.u32(A_GROUP_REFCOUNT, 0), pid=55))
    # 6: IPv6 in an Ethernet frame
    f.append(t(CMD_SAMPLE, sample(proto=ETH_P_IPV6, data=eth(ETH_P_IPV6, ipv6_udp())), pid=55))
    # 7: protocol 802.2 is treated as Ethernet (802.3 frame with LLC)
    f.append(t(CMD_SAMPLE, sample(proto=ETH_P_802_2, data=eth(4, LLC)), pid=55))
    # 8: protocol 3 (ETH_P_ALL) stays 3, which is Ethernet in the sll.ltype table
    f.append(t(CMD_SAMPLE, sample(proto=ETH_P_ALL), pid=55))
    # 9: a protocol that is a Linux SLL type of its own: a CAN frame
    can = struct.pack('<IB3x8s', 0x123, 8, bytes(range(8)))
    f.append(t(CMD_SAMPLE, sample(proto=ETH_P_CAN, data=can), pid=55))
    # 10: protocol with no dissector (Data), and data before the protocol (protocol 0)
    f.append(t(CMD_SAMPLE, sample(proto=0x0099, data=bytes(range(20))), pid=55))
    f.append(t(CMD_SAMPLE, LE.attr(A_DATA, bytes(range(12))) + LE.u16(A_PROTO, ETH_P_IP), pid=55))
    # 12: attributes of the wrong length (the reproducers of "Netlink psample: Check
    # TIMESTAMP and PROTO lengths"): shown as raw data, the next attribute stays intact
    f.append(t(CMD_SAMPLE, LE.u32(A_TIMESTAMP, 0x11223344) + LE.u32(A_SAMPLE_GROUP, 9) +
               LE.u32(A_PROTO, ETH_P_IP) + LE.u32(A_GROUP_SEQ, 10) +
               LE.attr(A_TIMESTAMP) + LE.attr(A_PROTO, b'\x08') + LE.u16(A_OUT_TC, 1) +
               LE.u64(A_TIMESTAMP, 5 * 1000000000 + 6) + LE.u32(A_SAMPLE_RATE, 11),
               pid=55))
    # 13: unknown attribute types (15 and up), unknown command, empty data
    f.append(t(CMD_SAMPLE, LE.attr(15, b'\x01') + LE.attr(77, b'abc') + LE.attr(A_DATA) +
               LE.u32(A_ORIGSIZE, 0), pid=55))
    f.append(t(9, LE.u32(A_SAMPLE_GROUP, 5)))
    # 15: flags: nested, and network byte order
    f.append(t(CMD_SAMPLE, LE.attr(A_ORIGSIZE, struct.pack('>I', 1500), NLA_F_NET_BYTEORDER) +
               LE.attr(A_SAMPLE_RATE, struct.pack('>I', 77), NLA_F_NET_BYTEORDER) +
               LE.attr(A_OUT_TC_OCC, struct.pack('>Q', 4242), NLA_F_NET_BYTEORDER) +
               LE.attr(A_PROTO, struct.pack('>H', ETH_P_IP), NLA_F_NET_BYTEORDER) +
               LE.attr(A_IIFINDEX, struct.pack('<H', 9), NLA_F_NESTED) +
               LE.attr(A_DATA, eth(ETH_P_IP, ipv4_udp(data=b'flags'))), pid=55))
    # 16: big endian message
    f.append(t(CMD_SAMPLE, sample(e=BE, extra=BE.u64(A_TIMESTAMP, 1700000002000000009) +
                                  BE.u16(A_OUT_TC, 7) + BE.u64(A_LATENCY, 99)), e=BE, pid=55))
    # 17: two messages in one packet
    f.append(sll() + LE.nlmsg(FAMILY_ID, LE.genl(CMD_NEW_GROUP, LE.u32(A_SAMPLE_GROUP, 6)), seq=5, pid=1) +
             LE.nlmsg(FAMILY_ID, LE.genl(CMD_DEL_GROUP), seq=6, pid=1))
    return f


def malformed():
    f = [(253, newfamily(LE, FAMILY_ID, FAMILY_NAME))]
    # Fixed width fields with the wrong length: the field type refuses them
    for atype, size in ((A_IIFINDEX, 4), (A_OIFINDEX, 1), (A_ORIGSIZE, 2), (A_SAMPLE_GROUP, 8),
                        (A_GROUP_SEQ, 2), (A_SAMPLE_RATE, 1), (A_GROUP_REFCOUNT, 2),
                        (A_OUT_TC, 4), (A_OUT_TC_OCC, 4), (A_LATENCY, 4)):
        f.append((253, t(CMD_SAMPLE, LE.attr(atype, bytes(size)))))
    # Data that is not what the protocol says
    f.append((253, t(CMD_SAMPLE, LE.u16(A_PROTO, ETH_P_IP) + LE.attr(A_DATA, b'\x01\x02\x03'))))
    f.append((253, t(CMD_SAMPLE, LE.u16(A_PROTO, ETH_P_CAN) + LE.attr(A_DATA, b'\x01\x02\x03'))))
    # attribute lengths: below the header size, beyond the message, trailing bytes
    f.append((253, t(CMD_SAMPLE, LE.u32(A_ORIGSIZE, 1) + struct.pack('<HH', 3, A_DATA) + b'\0\0\0\0')))
    f.append((253, t(CMD_SAMPLE, LE.u32(A_ORIGSIZE, 1) + struct.pack('<HH', 400, A_DATA) + b'abcd')))
    f.append((253, t(CMD_SAMPLE, LE.u32(A_ORIGSIZE, 1) + b'\0\0')))
    # message length field larger than the data, below the header size, short genl header
    p = LE.genl(CMD_SAMPLE, LE.u32(A_ORIGSIZE, 1))
    f.append((253, sll() + struct.pack('<IHHII', 16 + len(p) + 40, FAMILY_ID, 1, 1, 0) + p))
    f.append((253, sll() + struct.pack('<IHHII', 8, FAMILY_ID, 1, 1, 0) + p))
    f.append((253, sll() + struct.pack('<IHHII', 18, FAMILY_ID, 1, 1, 0) + b'\x01\x01'))
    return f


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    pcap(os.path.join(out, 'netlink-psample-coverage.pcap'), main_frames())
    pcapng(os.path.join(out, 'netlink-psample-coverage-malformed.pcapng'), malformed())


if __name__ == '__main__':
    main()
