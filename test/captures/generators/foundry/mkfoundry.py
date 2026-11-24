#!/usr/bin/env python3
# Generates test/captures/foundry_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Foundry Discovery Protocol (FDP) captures.

Usage: mkfoundry.py <outdir>
Writes foundry-coverage.pcap and foundry-coverage-malformed.pcap.
FDP is carried in 802.3 + LLC/SNAP frames with OUI 00:e0:52 (Foundry) and
PID 0x2000 to the multicast address 01:e0:52:cc:cc:cc.
"""
import struct
import sys
import os

out = sys.argv[1] if len(sys.argv) > 1 else '.'

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            p, cap = fr if isinstance(fr, tuple) else (fr, None)
            c = p if cap is None else p[:cap]
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(c), len(p)))
            f.write(c)

DST = bytes.fromhex('01e052cccccc')
def frame(payload, src=b'\x00\x0c\x29\x00\x00\x01', pid=0x2000, oui=b'\x00\xe0\x52'):
    llc = b'\xaa\xaa\x03' + oui + struct.pack('>H', pid) + payload
    return DST + src + struct.pack('>H', len(llc)) + llc

def tlv(t, v, l=None):
    return struct.pack('>HH', t, 4 + len(v) if l is None else l) + v

def hdr(version=2, hold=180, csum=0x1234):
    return struct.pack('>BBH', version, hold, csum)

def net(ips, unknown=b'\x01\x02\x03\x04\x05\x06\x07', iplen=None):
    body = unknown + struct.pack('>H', 4 * len(ips) if iplen is None else iplen)
    body += b''.join(bytes(i) for i in ips)
    return tlv(2, body)

def vlanmap(vlans, nbytes=None):
    n = nbytes if nbytes is not None else (max(vlans) + 7) // 8 if vlans else 0
    b = bytearray(n)
    for v in vlans:
        b[(v - 1) // 8] |= 1 << ((v - 1) % 8)
    return tlv(0x0101, bytes(b))

def tag(native, ttype, extra=b''):
    return tlv(0x0102, struct.pack('>HH', native, ttype) + extra)

main, mal = [], []
# 1 a complete advertisement with every known TLV type
main.append(frame(hdr() + tlv(1, b'switch-1') + net([(10, 0, 0, 1), (10, 0, 1, 1)])
                  + tlv(3, b'ethernet 1/1/1') + tlv(4, b'router') + tlv(5, b'FastIron 08.0.30')
                  + tlv(6, b'ICX6450-48') + vlanmap([1, 2, 10, 100, 4094]) + tag(1, 0x8100)))
# 2 unknown TLV types, with and without data
main.append(frame(hdr(1, 90, 0) + tlv(7, b'\xde\xad\xbe\xef') + tlv(0x9999, b'') + tlv(0x0103, b'\x00' * 9)))
# 3 string TLVs with no data (length 4) and with unprintable characters
main.append(frame(hdr() + tlv(1, b'') + tlv(3, b'') + tlv(5, b'v1\x01\x02\r\n\xc3\xa9"x')))
# 4 Net? with no address, one address, address block with stray octets
main.append(frame(hdr() + net([]) + net([(192, 0, 2, 1)]) + net([(1, 1, 1, 1), (2, 2, 2, 2), (3, 3, 3, 3)])
                  + tlv(2, b'\x00' * 7 + b'\x00\x06' + bytes((9, 9, 9, 9, 8, 8)))))
# 5 Net? length exactly 13 (the minimum)
main.append(frame(hdr() + tlv(2, b'\xaa' * 7 + b'\x00\x00', l=13)))
# 6 port tag: the minimum length 8 and with trailing bytes
main.append(frame(hdr() + tag(100, 0x8100) + tag(200, 0x9100, b'\x01\x02\x03\x04\x05')))
# 7 VLAN map: empty, a single byte, 512 bytes with every VLAN
main.append(frame(hdr() + vlanmap([]) + vlanmap([1, 8]) + vlanmap(list(range(1, 2049)))))
# 8 only the header
main.append(frame(hdr(3, 10, 0xffff)))
# 9 a different source address and holdtime 0
main.append(frame(hdr(2, 0, 0xabcd) + tlv(1, b'sw-2') + tlv(3, b'ethernet 1/2/4'), src=b'\x00\x0c\x29\x00\x00\x02'))
# 10 another Foundry PID is not FDP (llc.foundry_pid dispatch fails)
main.append(frame(b'\x01\x02\x03\x04', pid=0x1234))

# ---- malformed
# fix: Net? TLV shorter than its fixed part (length 12 and 5)
mal.append(frame(hdr() + tlv(2, b'\x00' * 8, l=12)))
mal.append(frame(hdr() + tlv(2, b'\x00' * 3, l=7)))
# fix: Tag TLV shorter than its fixed part (length 7 and 4)
mal.append(frame(hdr() + tlv(0x0102, b'\x00' * 3, l=7)))
mal.append(frame(hdr() + tlv(0x0102, b'', l=4)))
# invalid TLV lengths: 0, 3 and beyond the data
mal.append(frame(hdr() + tlv(1, b'abcd', l=0)))
mal.append(frame(hdr() + tlv(1, b'abcd', l=3)))
mal.append(frame(hdr() + tlv(1, b'abcd', l=500)))
# a valid TLV followed by too few octets for a TLV header
mal.append(frame(hdr() + tlv(1, b'ok') + b'\x00\x01'))
mal.append(frame(hdr() + tlv(1, b'ok') + b'\x00'))
# header cut short
mal.append(frame(hdr()[:3]))
mal.append(frame(hdr()[:1]))
# captured length cuts a VLAN map and a string TLV short
vm = frame(hdr() + vlanmap(list(range(1, 400))))
mal.append((vm, len(vm) - 20))
st = frame(hdr() + tlv(1, b'a-long-device-name-here'))
mal.append((st, len(st) - 10))
# truncated LLC/SNAP before the PID
mal.append(DST + b'\x00\x0c\x29\x00\x00\x01' + struct.pack('>H', 6) + b'\xaa\xaa\x03\x00\xe0\x52')

write_pcap(os.path.join(out, 'foundry-coverage.pcap'), main)
write_pcap(os.path.join(out, 'foundry-coverage-malformed.pcap'), mal)
print(len(main), len(mal))
