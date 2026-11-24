#!/usr/bin/env python3
# Generates test/captures/aruba_ubt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic Aruba UBT (User Based Tunneling) coverage captures.
# UBT is carried in Aruba PAPI (UDP port 8211), PAPI port 15560.
# Every packet is built with struct; nothing comes from a real network.
# Usage: mkaruba_ubt.py <outdir>
import os
import struct
import sys

def _ip_csum(h):
    s = sum(struct.unpack('!%dH' % (len(h)//2), h))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def udp_frame(payload, src=(192,0,2,1), dst=(192,0,2,2)):
    udp = struct.pack('!HHHH', 8211, 8211, 8+len(payload), 0) + payload
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(udp), 1, 0, 64, 17, 0, bytes(src), bytes(dst))
    iph = iph[:10] + struct.pack('!H', _ip_csum(iph)) + iph[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + iph + udp

def papi(dport, sport, payload, seq=1):
    return struct.pack('!HH4s4sHHHHHHHH', 0x4972, 2, bytes([192,0,2,2]), bytes([192,0,2,1]),
                       0, 0, dport, sport, 0, len(payload), seq, 0) + b'\x00'*16 + payload

def write_pcap(out, frames):
    with open(out, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000+i, 0, len(fr), len(fr)) + fr)
    print(out, len(frames))

UBT = 15560
SWMAC = bytes.fromhex('020000000010')
H = lambda v: struct.pack('!H', v)
B = lambda v: bytes([v])

def tlv(t, v): return struct.pack('!BH', t, len(v)) + v

def ubt(msgtype, tlvs=(), seq=7, plen=0):
    """UBT header: packet length, message type, switch MAC (except for
    User Bootstrap ACK and Switch Keepalive ACK), sequence number."""
    h = struct.pack('!II', plen, msgtype)
    if msgtype not in (12, 16):
        h += SWMAC
    return h + struct.pack('!I', seq) + b''.join(tlvs)

def ipaddr(kind, addr=None):
    """20 octet IP address: type, padding, address (IPv4 + 12 octets
    padding or IPv6), as the dissector decodes it."""
    if kind == 2:
        return H(2) + H(0) + bytes(addr or (192,0,2,50)) + b'\x00'*12
    if kind == 10:
        return H(10) + H(0) + bytes.fromhex(addr or '20010db8000000000000000000000050')
    return H(kind) + b'\x00'*18

UAC = [ipaddr(2, (10,0,0,1)), ipaddr(10, '20010db8000000000000000000000a01'),
       ipaddr(0)] + [ipaddr(2, (10,0,0,i)) for i in range(4, 13)]

def nodelist(uacs=UAC, extra=b''):
    return (b'cluster-one'.ljust(32, b'\x00') + B(1) + B(0xff) + B(0) + B(len(uacs))
            + b''.join(uacs) + extra)

def bucketmap(extra=b'', uacs=UAC):
    return (struct.pack('!Q', 0x0000018b2f3c4d5e) + b'bucketmap-identifier-0123456789ab\x00'[:33]
            + bytes(i % 3 for i in range(256))           # active map
            + bytes((i + 1) % 3 for i in range(256))     # standby map
            + bytes(i % 2 for i in range(256))           # L2 connect
            + B(3) + b''.join(uacs) + extra)

def to_ubt(payload, seq): return udp_frame(papi(UBT, 8211, payload, seq))
def from_ubt(payload, seq):
    return udp_frame(papi(8211, UBT, payload, seq), src=(192,0,2,2), dst=(192,0,2,1))

def main_frames():
    F = []
    # 1-2: Switch Bootstrap and ACK
    F.append(to_ubt(ubt(1, [tlv(1, H(0x1234)), tlv(2, b'KB.16.10.0001'), tlv(4, B(1)),
                            tlv(5, ipaddr(2)), tlv(6, H(30)), tlv(9, B(1)), tlv(10, H(1500)),
                            tlv(21, b'switch-1'), tlv(23, H(64))], seq=1), 1))
    F.append(from_ubt(ubt(2, [tlv(15, B(1)), tlv(5, ipaddr(10)), tlv(12, B(0))], seq=1), 2))
    # 3-4: Controller Nodelist and ACK
    F.append(from_ubt(ubt(3, [tlv(13, nodelist())], seq=2), 3))
    F.append(to_ubt(ubt(4, [tlv(15, B(0))], seq=2), 4))
    # 5-6: Controller Bucketmap and ACK
    F.append(from_ubt(ubt(5, [tlv(14, bucketmap())], seq=3), 5))
    F.append(to_ubt(ubt(6, [tlv(15, B(1))], seq=3), 6))
    # 7-10: Failover, Unbootstrap: server IP of every type
    F.append(to_ubt(ubt(7, [tlv(17, ipaddr(2, (192,0,2,60)))], seq=4), 7))
    F.append(from_ubt(ubt(8, [tlv(17, ipaddr(10)), tlv(15, B(1))], seq=4), 8))
    F.append(to_ubt(ubt(9, [tlv(17, ipaddr(0))], seq=5), 9))
    F.append(from_ubt(ubt(10, [tlv(15, B(1))], seq=5), 10))
    # 11-12: User Bootstrap (user flags, every auth method) and ACK (no switch MAC)
    for i, am in enumerate((2, 3, 4, 6, 9)):
        F.append(to_ubt(ubt(11, [tlv(3, H(0x100 + i)), tlv(7, bytes.fromhex('00000c00000%d' % i)),
                                 tlv(8, H(100 + i)), tlv(9, B(0x1f if i == 0 else 0x0a)),
                                 tlv(11, b'employee'), tlv(18, B(am)), tlv(19, b'user%d' % i),
                                 tlv(20, b'1/1/%d' % i), tlv(16, H(0x77)),
                                 tlv(22, H(10) + H(20) + H(30))], seq=10 + i), 11 + i))
    F.append(from_ubt(ubt(12, [tlv(3, H(0x100)), tlv(15, B(1)), tlv(9, B(0x10))], seq=10), 16))
    # User Unbootstrap and ACK
    F.append(to_ubt(ubt(13, [tlv(3, H(0x100)), tlv(7, bytes.fromhex('00000c000000')), tlv(12, B(4))], seq=20), 17))
    F.append(from_ubt(ubt(14, [tlv(15, B(1))], seq=20), 18))
    # Keepalive (ends after the sequence number) and its ACK (no switch MAC)
    F.append(to_ubt(ubt(15, [], seq=21), 19))
    F.append(from_ubt(ubt(16, [tlv(15, B(1))], seq=21), 20))
    # Heartbeat request and ACK
    F.append(to_ubt(ubt(17, [tlv(6, H(30))], seq=22), 21))
    F.append(from_ubt(ubt(18, [tlv(15, B(1))], seq=22), 22))
    # Silent VLAN message and ACK
    F.append(to_ubt(ubt(19, [tlv(22, H(5) + H(6))], seq=23), 23))
    F.append(from_ubt(ubt(20, [tlv(15, B(1))], seq=23), 24))
    # Undefined message types 0 and 99, TLV type 0, unknown TLV type,
    # SAC and server IP of an invalid type (warnings), unassigned SAC IP
    F.append(to_ubt(ubt(0, [tlv(0, b'\x01\x02'), tlv(5, ipaddr(0))], seq=24), 25))
    F.append(to_ubt(ubt(99, [tlv(99, b'what?'), tlv(5, ipaddr(7)), tlv(17, ipaddr(7))], seq=25), 26))
    # Node list with an invalid UAC IP type (warning)
    F.append(from_ubt(ubt(3, [tlv(13, nodelist([ipaddr(7)] + UAC[1:]))], seq=26), 27))
    # Zero length GRE key, user key and status
    F.append(to_ubt(ubt(1, [tlv(1, b''), tlv(3, b''), tlv(15, b''), tlv(23, b'')], seq=27), 28))
    # Reproducers (ubt_tlv_fixed_len.py): SAC IPv4 address in 8 octets,
    # then Username and User Port Name; Silent Client VLANs with two VLANs,
    # then Username
    hdr = struct.pack('!II', 0, 11) + SWMAC + struct.pack('!I', 7)
    F.append(to_ubt(hdr + tlv(5, H(2) + H(0) + bytes([192,0,2,7])) + tlv(19, b'alice') + tlv(20, b'port1'), 29))
    F.append(to_ubt(hdr + tlv(22, H(10) + H(20)) + tlv(19, b'bob'), 30))
    # TLVs longer than their fixed decoding: the tail is skipped and the
    # next TLV decoded (SAC IP, server IP, node list, bucket map)
    F.append(to_ubt(ubt(11, [tlv(5, ipaddr(2, (192,0,2,8)) + b'\xee'*4), tlv(19, b'carol'),
                             tlv(17, ipaddr(10) + b'\xee'*6), tlv(20, b'port2')], seq=31), 31))
    F.append(from_ubt(ubt(3, [tlv(13, nodelist(extra=b'\xee'*8)), tlv(19, b'dave')], seq=32), 32))
    F.append(from_ubt(ubt(5, [tlv(14, bucketmap(extra=b'\xee'*5)), tlv(19, b'erin')], seq=33), 33))
    # Bucket map with an invalid UAC IP type (warning)
    F.append(from_ubt(ubt(5, [tlv(14, bucketmap(uacs=UAC[:11] + [ipaddr(7)]))], seq=34), 34))
    return F

def malformed_frames():
    F = []
    hdr = struct.pack('!II', 0, 11) + SWMAC + struct.pack('!I', 7)
    # Short SAC IP address as the last TLV: fixed decoding runs off the end
    F.append(to_ubt(hdr + tlv(5, H(2) + H(0) + bytes([192,0,2,7])), 1))
    F.append(to_ubt(hdr + tlv(5, H(10) + H(0)), 2))
    F.append(to_ubt(hdr + tlv(5, H(0)), 3))
    F.append(to_ubt(hdr + tlv(5, H(7)), 4))
    F.append(to_ubt(hdr + tlv(17, H(2)), 5))
    F.append(to_ubt(hdr + tlv(17, H(10)), 6))
    F.append(to_ubt(hdr + tlv(17, H(0)), 7))
    F.append(to_ubt(hdr + tlv(17, H(7)), 8))
    # Short node list, bucket map, silent client VLANs as the last TLV
    F.append(to_ubt(hdr + tlv(13, b'cluster'), 9))
    F.append(to_ubt(hdr + tlv(14, b'\x00'*20), 10))
    F.append(to_ubt(hdr + tlv(22, b''), 11))
    # TLV length past the end of the packet
    # A message without TLVs (Keepalive ACK): the TLV header item at the
    # end of the data throws
    F.append(from_ubt(ubt(16, [], seq=21), 12))
    F.append(to_ubt(hdr + struct.pack('!BH', 19, 100) + b'short', 13))
    # Integers longer than 4 octets (error expert info), zero length MAC
    F.append(to_ubt(hdr + tlv(1, b'\x00'*6) + tlv(7, b''), 14))
    # Truncated header (no sequence number), half a TLV header
    F.append(to_ubt(struct.pack('!II', 0, 1) + SWMAC, 15))
    F.append(to_ubt(hdr + b'\x13\x00', 16))
    return F

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'aruba_ubt-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'aruba_ubt-coverage-malformed.pcap'), malformed_frames())
