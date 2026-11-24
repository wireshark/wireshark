#!/usr/bin/env python3
# Generates test/captures/aruba_papi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic Aruba PAPI coverage captures (UDP port 8211).
# Every packet is built with struct; nothing comes from a real network.
# Usage: mkaruba_papi.py <outdir>
import os
import struct
import sys

def _ip_csum(h):
    s = sum(struct.unpack('!%dH' % (len(h)//2), h))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def udp_frame(payload, sport=8211, dport=8211, src=(192,0,2,1), dst=(192,0,2,2)):
    udp = struct.pack('!HHHH', sport, dport, 8+len(payload), 0) + payload
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(udp), 1, 0, 64, 17, 0, bytes(src), bytes(dst))
    iph = iph[:10] + struct.pack('!H', _ip_csum(iph)) + iph[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + iph + udp

def papi(dport, sport, payload, version=2, ptype=0, seq=1, code=0, size=None):
    """PAPI header: 32 octets (v2), plus two IPv6 addresses for v3."""
    if size is None:
        size = len(payload)
    h = struct.pack('!HH4s4sHHHHHHHH', 0x4972, version, bytes([192,0,2,2]), bytes([192,0,2,1]),
                    0, 0, dport, sport, ptype, size, seq, code) + bytes(range(16))
    if version == 3:
        h += bytes.fromhex('20010db8000000000000000000000002') + bytes.fromhex('20010db8000000000000000000000001')
    return h + payload

def write_pcap(out, frames):
    with open(out, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000+i, 0, len(fr), len(fr)) + fr)
    print(out, len(frames))

LICMGR = 8389
UBT = 15560

def ltlv(t, v):
    return struct.pack('!HH', t, len(v)) + v

def licmgr(tlvs, pad=b'\x00\x00\x00\x00', plen=None):
    body = b''.join(tlvs)
    return struct.pack('!H', len(body) if plen is None else plen) + body + pad

def u32(v): return struct.pack('!I', v)

def debug_items():
    d = b''
    d += b'\x00' + struct.pack('!H', 11) + b'debug text!'       # text
    d += b'\x01' + bytes.fromhex('0a0b0c0d0e0f')                 # 48 bits
    d += b'\x02' + b'\x2a'                                       # 8 bits
    d += b'\x03' + struct.pack('!H', 0x1234)                     # 16 bits
    d += b'\x04' + u32(0xdeadbeef)                               # 32 bits
    d += b'\x05' + bytes([198,51,100,9])                         # IPv4
    d += b'\x06'                                                 # unknown (warning)
    d += b'\x07' + struct.pack('!H', 0x5678)                     # 16 bits
    d += b'\x08' + struct.pack('!H', 5) + b'\x01\x02\x03\x04\x05' # bytes
    d += b'\x09' + struct.pack('!Q', 0x0102030405060708)         # 64 bits
    return d

def main_frames():
    F = []
    all_tlvs = [
        ltlv(1, bytes([10,1,2,3])),                  # IP address
        ltlv(2, b'CN0123456789'),                    # serial number (12 octets)
        ltlv(3, b'controller-1'),                    # hostname
        ltlv(4, b'\x00\x01'),                        # not in the switch
        ltlv(5, bytes.fromhex('00000c123456')),      # MAC address
    ] + [ltlv(t, u32(1000 + t)) for t in range(7, 17)] + [
        ltlv(17, b'webcc-key'), ltlv(18, u32(18)), ltlv(19, u32(19)),
        ltlv(99, b'unknown'),                        # Unknown Type
    ]
    # 1: License Manager to its port, every TLV type, with padding
    F.append(udp_frame(papi(LICMGR, 8222, licmgr(all_tlvs))))
    # 2: License Manager answer: found by the source port
    F.append(udp_frame(papi(8222, LICMGR, licmgr([ltlv(7, u32(64)), ltlv(12, u32(3))]), seq=2),
                       src=(192,0,2,2), dst=(192,0,2,1)))
    # 3: v3 header (IPv6 addresses) with a License Manager payload
    F.append(udp_frame(papi(LICMGR, 8222, licmgr([ltlv(3, b'v6-controller')], pad=b'\x00'*8), version=3, seq=3)))
    # 4: v3 header, payload for an unknown port -> data
    F.append(udp_frame(papi(8212, 8213, b'fastpath data', version=3, ptype=3, seq=4)))
    # 5: reproducer, packet type 8 (was shown in octal as 10)
    F.append(udp_frame(papi(1, 8211, b'', ptype=8, seq=5)))
    # 6: reproducer, serial number shorter than 32 octets, followed by a
    #    hostname (with trailing padding, see the README)
    lic = ltlv(2, b'SN123456') + ltlv(3, b'host')
    F.append(udp_frame(papi(LICMGR, 8211, struct.pack('!H', len(lic)) + lic + b'\x00'*4, seq=6)))
    # 7: payload laid out as experimental "debug" items (data at default
    #    preferences, decoded with papi.experimental_decode)
    F.append(udp_frame(papi(8217, 8216, debug_items(), seq=7, ptype=0x10)))
    # 8: UBT carried in PAPI (to port 15560): Switch Keepalive
    ubt = struct.pack('!II', 0, 15) + bytes.fromhex('02000000aa01') + u32(9)
    F.append(udp_frame(papi(UBT, 8211, ubt, seq=8)))
    # 9: UDP 8211 data without the PAPI magic: rejected
    F.append(udp_frame(b'\x12\x34not papi at all'))
    # 10: v2, empty payload, ephemeral/last service port names
    F.append(udp_frame(papi(65535, 8999, b'', seq=10, ptype=0xffff, code=7)))
    return F

def malformed_frames():
    F = []
    # Original reproducer: License Manager TLVs end with the packet (no
    # padding): the padding item at the end of the tvb throws
    lic = ltlv(2, b'SN123456') + ltlv(3, b'host')
    F.append(udp_frame(papi(LICMGR, 8211, struct.pack('!H', len(lic)) + lic)))
    # Payload length past the end of the packet
    F.append(udp_frame(papi(LICMGR, 8211, licmgr([ltlv(3, b'x')], pad=b'', plen=200))))
    # TLV longer than the data
    F.append(udp_frame(papi(LICMGR, 8211, struct.pack('!H', 10) + struct.pack('!HH', 2, 100) + b'abcdef')))
    # IP address TLV with length 0 at the end
    F.append(udp_frame(papi(LICMGR, 8211, struct.pack('!H', 4) + struct.pack('!HH', 1, 0))))
    # Truncated v2 header
    F.append(udp_frame(papi(1, 2, b'')[:20]))
    # v3 header without the IPv6 addresses
    F.append(udp_frame(papi(1, 2, b'').replace(b'\x00\x02', b'\x00\x03', 1)))
    # Debug items running past the end (text, bytes, 64 bits)
    F.append(udp_frame(papi(8217, 8216, b'\x00\x00\x40short')))
    F.append(udp_frame(papi(8217, 8216, b'\x08\x00\x40short')))
    F.append(udp_frame(papi(8217, 8216, b'\x09\x01\x02')))
    # License Manager with empty payload (experimental decode eats it too)
    F.append(udp_frame(papi(LICMGR, 8211, b'')))
    return F

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'aruba_papi-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'aruba_papi-coverage-malformed.pcap'), malformed_frames())
