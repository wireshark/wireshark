#!/usr/bin/env python3
# Generates test/captures/zep_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the ZEP coverage captures: mkzep.py <outdir>.
ZEP runs over UDP port 17754 (registered by default)."""
import struct
import sys
import os

def crc16(data):
    # IEEE 802.15.4 FCS (CRC-16/KERMIT)
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc

def mac_data(seq, payload=b'\x01\x02\x03\x04'):
    # data frame, short addresses, with FCS
    f = struct.pack('<HBHHH', 0x8841, seq, 0x1234, 0xffff, 0x0001) + payload
    return f + struct.pack('<H', crc16(f))

def mac_ack(seq):
    f = struct.pack('<HB', 0x0002, seq)
    return f + struct.pack('<H', crc16(f))

def mac_nofcs(seq, payload=b'ZEP!'):
    # frame followed by the two CC24xx metadata bytes (RSSI, CRC ok + LQI)
    f = struct.pack('<HBHHH', 0x8841, seq, 0x1234, 0xffff, 0x0001) + payload
    return f + b'\xe0\xc8'

def udp(payload, sport=40001, dport=17754, ident=1):
    src, dst = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + 8 + len(payload), ident, 0, 64, 17, 0, src, dst)
    ck = sum(struct.unpack('>10H', ip)); ck = (ck & 0xffff) + (ck >> 16); ck = (ck & 0xffff) + (ck >> 16)
    ip = ip[:10] + struct.pack('>H', ~ck & 0xffff) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + u + payload

def v1(chan, dev, lqi_mode, lqi, mac, reserved=b'\0' * 8, length=None):
    # "EX" ver chan dev(2) lqimode lqi reserved(7) len  (16 octets)
    n = len(mac) if length is None else length
    h = b'EX' + b'\x01' + bytes([chan]) + struct.pack('>H', dev) + bytes([lqi_mode])
    h += bytes([lqi]) + reserved[:7] + bytes([n])
    assert len(h) == 16
    return h + mac

def v2(typ, chan, dev, lqi_mode, lqi, ts_sec, ts_frac, seq, mac, ver=2, reserved=b'\0' * 10, length=None):
    n = len(mac) if length is None else length
    h = b'EX' + bytes([ver, typ, chan]) + struct.pack('>H', dev) + bytes([lqi_mode, lqi])
    h += struct.pack('>III', ts_sec, ts_frac, seq)
    h += reserved[:10] + bytes([n])
    assert len(h) == 32, len(h)
    return h + mac

def v2ack(seq, typ=2):
    return b'EX' + bytes([2, typ]) + struct.pack('>I', seq)

def write_pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(fr), len(fr)))
            f.write(fr)

def main(out):
    good = []
    # v1, mode bit clear: LQI shown, CC24xx metadata (the LQI fix)
    good.append(v1(11, 1, 0, 200, mac_nofcs(1)))
    # v1, mode bit set (CRC): reserved field only, IEEE 802.15.4 with FCS
    good.append(v1(12, 2, 1, 0, mac_data(2)))
    # v1, LQI mode, nonzero reserved bytes, empty payload behind the header
    good.append(v1(26, 300, 0, 77, mac_nofcs(3, b''), reserved=b'\x11\x22\x33\x44\x55\x66\x77\x88'))
    # v2 data, CRC mode and LQI mode
    good.append(v2(1, 15, 7, 1, 0, 3900000000, 0x80000000, 1, mac_data(4)))
    good.append(v2(1, 16, 8, 0, 255, 3900000001, 0x40000000, 2, mac_nofcs(5)))
    # v2 type 0 (not data, not ack: dissected like data)
    good.append(v2(0, 17, 9, 1, 0, 3900000002, 0, 3, mac_ack(6)))
    # v2 ack and an ack with another sequence number
    good.append(v2ack(1))
    good.append(v2ack(0xfffffffe))
    # version 3 is dissected like v2
    good.append(v2(1, 18, 10, 1, 0, 3900000003, 5, 4, mac_data(7), ver=3))
    # length byte with the upper bit set (masked by 0x7f)
    m = mac_data(8)
    good.append(v2(1, 19, 11, 1, 0, 3900000004, 6, 5, m, length=len(m) | 0x80))
    # largest IEEE frame (127 octets, the ZEP maximum)
    good.append(v2(1, 20, 12, 1, 0, 3900000005, 7, 6, mac_data(9, bytes(range(116)))))
    write_pcap(os.path.join(out, 'zep-coverage.pcap'), [udp(p, ident=i + 1) for i, p in enumerate(good)])

    bad = []
    bad.append(b'EX\x02')                                    # shorter than the ACK length
    bad.append(b'XX\x02\x01' + b'\0' * 28)                   # wrong preamble
    bad.append(b'EX\x01' + b'\0' * 9)                        # v1 below the header length
    bad.append(b'EX\x02\x01' + b'\0' * 12)                   # v2 data type, header short
    bad.append(v1(11, 1, 0, 1, mac_nofcs(1), length=2))      # length smaller than the payload: not ZEP
    bad.append(v2(1, 11, 1, 1, 0, 1, 1, 1, mac_data(1), length=3))
    bad.append(v1(11, 1, 1, 1, b'\x01'))                     # IEEE frame too short for 802.15.4
    bad.append(v2(1, 11, 1, 0, 1, 1, 1, 1, b''))            # empty IEEE frame
    bad.append(v2ack(1)[:7])                                 # 7 octets (below ACK length)
    write_pcap(os.path.join(out, 'zep-coverage-malformed.pcap'), [udp(p, ident=100 + i) for i, p in enumerate(bad)])

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
