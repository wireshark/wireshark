#!/usr/bin/env python3
# Generates test/captures/dect_mitel_rfp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DECT-MITEL-RFP dissector
(packet-dect-mitel-rfp.c).

DECT-MITEL-RFP is the TCP protocol between a Mitel OMM and its DECT base
stations (RFPs), on TCP port 16321 by default. Each message has a big
endian 2 octet type and 2 octet length; the dissector decodes one message
per TCP segment. Type 0x0301 (ETH) carries a DECT-MITEL-ETH message.
Every packet is built from scratch with struct; no captured traffic is
used. Addresses are from the documentation ranges (192.0.2.0/24,
2001:db8::/32) and the credentials in SYS-PASSWD are made up.

Usage: mkdect_mitel_rfp.py <output directory>

Writes:
  dect-mitel-rfp-coverage.pcap            every message type with every
                                          decoded field and value,
                                          MEDIA-DTMF with every key, the
                                          DTMF reproducer, every SYNC
                                          payload type, ETH messages
  dect-mitel-rfp-coverage-malformed.pcap  messages cut short
"""

import os
import struct
import sys

MAC_RFP = bytes.fromhex('020000000002')
MAC_OMM = bytes.fromhex('020000000001')
IP_OMM = bytes([192, 0, 2, 1])
IP_RFP = bytes([192, 0, 2, 2])
RFP_PORT = 16321


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Tcp:
    """One TCP connection OMM (client) <-> RFP port 16321, with sequence
    numbers kept per direction so TCP analysis stays quiet."""

    def __init__(self, sport=40000):
        self.sport = sport
        self.seq = {True: 1000, False: 5000}   # key: from the OMM

    def frame(self, payload, from_omm=True, flags=0x18):
        src, dst = (IP_OMM, IP_RFP) if from_omm else (IP_RFP, IP_OMM)
        sp, dp = (self.sport, RFP_PORT) if from_omm else (RFP_PORT, self.sport)
        seq = self.seq[from_omm]
        ack = self.seq[not from_omm]
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 5 << 4, flags, 65535, 0, 0)
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         1, 0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.seq[from_omm] = (seq + len(payload)) & 0xffffffff
        smac, dmac = (MAC_OMM, MAC_RFP) if from_omm else (MAC_RFP, MAC_OMM)
        return dmac + smac + b'\x08\x00' + ip + tcp + payload


def msg(mtype, body, length=None):
    if length is None:
        length = len(body)
    return struct.pack('>HH', mtype, length) + body


def ip6(last):
    return bytes.fromhex('20010db8000000000000000000000000')[:15] + bytes([last])


def zpad(s, n):
    return s + bytes(n - len(s))


def media(mtype, handle, body=b''):
    return msg(mtype, struct.pack('>H', handle) + body)


def tone(k):
    return struct.pack('<12H', 350 + k, 440 + k, 480 + k, 620 + k,
                       100, 110, 120, 130, 500 + k, 3 + k, 0, 1)


def sync(stype, payload, length=None):
    if length is None:
        length = len(payload)
    return msg(0x0302, struct.pack('>HB', stype, length) + payload)


def nwk_dlc(nwk):
    return bytes([0x01, 0x03, (len(nwk) << 2) | 1]) + nwk


# Message types without a decoder in the dissector
UNDECODED = [0x0104, 0x0106, 0x010b, 0x010c, 0x010d, 0x010f, 0x0110, 0x0111,
             0x0112, 0x0113, 0x0115, 0x0119, 0x0121, 0x0122, 0x0123, 0x0124,
             0x0125, 0x0126,
             0x0401, 0x0402, 0x0403, 0x0404, 0x0405, 0x0406, 0x0407, 0x0408,
             0x0409, 0x040e, 0x0501, 0x0600, 0x0601, 0x0602, 0x0603, 0x0604,
             0x0605, 0x0700, 0x0701, 0x0702, 0x0800, 0x0801]
# MEDIA types that only have the handle
MEDIA_HANDLE_ONLY = [0x020a, 0x020c, 0x020d, 0x020e, 0x020f, 0x0210, 0x0211,
                     0x0212, 0x0213]
SYNC_UNDECODED = [0x7d0e, 0x7d0f, 0x7d17, 0x7d1a, 0x7d1b, 0x7d1c, 0x7d20,
                  0x7d21, 0x7d22, 0x7d23, 0x7d24, 0x7d25, 0x7d26, 0x7d27,
                  0x7d29, 0x7d2f, 0x7d32, 0x7d33]
DTMF_KEYS = b'0123456789*#ABCD'


def main_messages():
    """(from_omm, payload) for every frame of the main capture."""
    M = []
    O, R = True, False
    # --- SYS-INIT and authentication ---
    init = struct.pack('>I', 0x000c) + bytes(4)            # model RFP36
    init += bytes.fromhex('020000aabbcc') + bytes(6)        # MAC address
    init += struct.pack('>I', 0x00008738)                   # every capability
    init += bytes(range(64))                                 # AES encrypted data
    init += struct.pack('>I', 0x00080000) + bytes(20)       # protocol
    init += zpad(b'SIP-DECT 8.1SP1-FA27', 32) + bytes(112)  # software version
    init += bytes(range(0xf0, 0x100))                        # signature
    M.append((R, msg(0x0120, init)))                                       # 1
    auth = bytes(7) + bytes.fromhex('0102030405060708') + bytes(8) + bytes.fromhex('1112131415161718')
    M.append((O, msg(0x012d, auth)))                                        # 2
    M.append((R, msg(0x012d, auth)))                                        # 3
    # --- CONTROL ---
    M.append((R, msg(0x0001, struct.pack('>HH', 0x0120, 0))))              # 4 ACK
    for k, reason in enumerate(list(range(0x04000000, 0x04000008)) + [0x05000000]):
        M.append((R, msg(0x0002, struct.pack('>HHI', 0x0201, k, reason))))  # 5-13 NACK
    M.append((O, msg(0x0003, struct.pack('>II', 123456, 789))))            # 14 HEARTBEAT
    # --- SYS ---
    M.append((O, msg(0x0101, bytes([0xb8, 0x68, 64, 3, 5]))))              # 15 IP-OPTIONS
    for color in range(9):                                                  # 16-24 LED
        M.append((O, msg(0x0102, bytes([color % 3, color]))))
    M.append((O, msg(0x0105, bytes([30]))))                                 # 25 HEARTBEAT-INTERVAL
    M.append((O, msg(0x0107, ip6(0x10) + struct.pack('>H', 514))))         # 26 SYSLOG
    M.append((O, msg(0x0108, bytes([8, 4]))))                               # 27 MAX-CHANNELS
    M.append((O, msg(0x0109, ip6(0x20) + struct.pack('>H', 80))))          # 28 HTTP-SET
    pw = bytes([1, 0]) + zpad(b'root', 65) + zpad(b'example-root-pw', 65) \
        + zpad(b'admin', 65) + zpad(b'example-admin-pw', 65)
    M.append((O, msg(0x010a, pw)))                                          # 29 PASSWD
    M.append((R, msg(0x010e, ip6(0x30) + struct.pack('>I', 12))))          # 30 RPING
    url = b'tftp://192.0.2.1/core.rfp\x00'
    M.append((R, msg(0x0116, url)))                                         # 31 CORE-DUMP
    M.append((O, msg(0x0117, struct.pack('>IIII', 1700000000, 500, 1700000001, 250))))  # 32 VSNTP
    M.append((O, msg(0x0134, struct.pack('>I', 0x80000000 | 1440) + bytes(range(16)))))  # 33 query
    M.append((R, msg(0x0134, struct.pack('>I', 720) + bytes(range(16, 32)))))           # 34
    # 35-74: types without a decoder
    for t in UNDECODED:
        M.append((O, msg(t, bytes([0xde, 0xad]))))
    # 75: unknown type, 76: no body at all
    M.append((O, msg(0x7777, b'\x01\x02')))
    M.append((O, msg(0x0121, b'')))
    # --- MEDIA ---
    h = 0x0101
    M.append((O, media(0x0200, h, bytes([0x01, 0x02]) + struct.pack('>I', 0x0000a5a5))))  # 77 OPEN
    # 78: CONF with every codec type and an unknown one
    codecs = b''.join(bytes([t, 0x10 + t, 8]) for t in range(6))
    conf = bytes(2) + bytes([0x01, 0x01, 6]) + codecs
    conf = zpad(conf, 56)
    conf += bytes([0x21, 0]) + struct.pack('<H', 0x1234) + bytes(4)
    conf += struct.pack('>HH', 3000, 3001)
    conf += bytes([192, 0, 2, 3]) + struct.pack('>HH', 4000, 4001)
    conf += bytes([192, 0, 2, 4]) + struct.pack('>HH', 5000, 5001)
    M.append((O, media(0x0201, h, conf)))
    # 79: CONF whose codec count goes past the MCEI (17 codecs fit)
    conf2 = bytes(2) + bytes([0x00, 0x00, 200]) + bytes([4, 0, 16]) * 17
    conf2 += bytes([0x22, 0]) + struct.pack('<H', 0x0042) + bytes(4) + bytes(20)
    M.append((O, media(0x0201, h + 1, conf2)))
    M.append((O, media(0x0202, h, bytes(2))))                               # 80 CLOSE
    for d in range(5):                                                      # 81-85 START
        M.append((O, media(0x0203, h, bytes([d, 0]) + struct.pack('<I', 20 * d) + bytes([d & 1]))))
    M.append((O, media(0x0204, h, bytes([3]))))                             # 86 STOP
    stats = struct.pack('<I', 61) + struct.pack('>IIIIII', 3000, 480000, 2990, 478400, 10, 2500) \
        + bytes([192, 0, 2, 5])
    M.append((R, media(0x0205, h, stats)))                                  # 87 STATISTICS
    red = bytes(2) + struct.pack('>HH', 6000, 6001) + bytes([192, 0, 2, 6]) \
        + struct.pack('>HHI', 7000, 7001, 100)
    M.append((O, media(0x0206, h, red)))                                    # 88 REDIRECT-START
    M.append((O, media(0x0207, h, bytes([1]))))                             # 89 REDIRECT-STOP
    M.append((O, media(0x0208, h, bytes([0x21]))))                          # 90 RESTART
    # 91-106: MEDIA-DTMF with every key and direction
    for k, key in enumerate(DTMF_KEYS):
        M.append((R, media(0x0209, h, struct.pack('<H', 40 + 10 * k) + bytes([key, k % 4]))))
    # 107: the reproducer (dect_mitel_rfp_dtmf_assert.py)
    M.append((O, msg(0x0209, struct.pack('!H', 0x0001) + struct.pack('<H', 100) + b'5' + b'\x00')))
    M.append((O, media(0x020b, h, bytes([2, 0]) + bytes(4))))               # 108 TONE, no entries
    M.append((O, media(0x020b, h, bytes([1, 3]) + bytes(4) + tone(0) + tone(1) + tone(2))))  # 109
    # 110-118: MEDIA types with only the handle
    for t in MEDIA_HANDLE_ONLY:
        M.append((O, media(t, h)))
    # --- SYNC ---
    M.append((O, sync(0x7d15, bytes([1]))))                                 # 119 FREQ_CTRL_MODE_IND
    M.append((R, sync(0x7d16, bytes([1]) + struct.pack('>HH', 12, 34))))    # 120 FREQ_CTRL_MODE_CFM
    M.append((O, sync(0x7d18, struct.pack('>H', 1234))))                    # 121 SET_FREQUENCY
    M.append((O, sync(0x7d1d, struct.pack('>H', 7))))                       # 122 START_MAC_SLAVE_MODE_IND
    M.append((O, sync(0x7d1e, bytes([2]))))                                 # 123 SYSTEM_SEARCH_IND
    M.append((R, sync(0x7d1f, bytes([3]) + b''.join(struct.pack('>HH', 1 + i, 0x40 + i) for i in range(3)))))  # 124
    M.append((R, sync(0x7d1f, bytes([0]))))                                 # 125 no items
    M.append((R, sync(0x7d2c, bytes([2]) + struct.pack('>HHBB', 1, 10, 0x50, 1)
                      + struct.pack('>HHBB', 2, 20, 0x60, 0))))           # 126 PHASE_OFS_WITH_RSSI_IND
    M.append((O, sync(0x7d15, b'')))                                        # 127 length 0
    for t in SYNC_UNDECODED:                                                # 128-145
        M.append((R, sync(t, bytes([0x01]))))
    M.append((R, sync(0x7dff, bytes([0x01]))))                              # 146 unknown
    # --- ETH: DECT-MITEL-ETH messages without the length field ---
    M.append((R, msg(0x0301, bytes([0x78, 0x01, 0x04, 0x05, 0x92, 0x34, 0x56, 0x78, 0x9a]))))  # 147 RFPc READY_IND
    M.append((R, msg(0x0301, bytes([0x7a, 0x01, 0x21, 0x00, 0x01, 0x23, 0x02]))))              # 148 MAC_CON_IND
    nwk = nwk_dlc(bytes([0x03, 0x5a]))
    M.append((O, msg(0x0301, bytes([0x79, 0x05, 0x21, 0x01, len(nwk)]) + nwk)))                # 149 LC_DATA_REQ
    M.append((O, msg(0x0301, bytes([0x7a, 0x02, 0x21]))))                                      # 150 MAC_DIS_REQ
    return M


def malformed_messages():
    M = []
    O = True
    M.append((O, b'\x01'))                                       # type cut short
    M.append((O, b'\x00\x01\x00'))                               # length cut short
    for t, n in ((0x0001, 2), (0x0002, 6), (0x0003, 4), (0x0101, 3), (0x0102, 1),
                 (0x0105, 0), (0x0107, 10), (0x0108, 1), (0x0109, 10), (0x010a, 100),
                 (0x010e, 18), (0x0117, 10), (0x0120, 100), (0x012d, 20), (0x0134, 8)):
        M.append((O, msg(t, bytes(n))))
    M.append((O, msg(0x0116, b'abc', length=40)))               # CORE-DUMP past the end
    M.append((O, msg(0x0200, b'\x00')))                          # MEDIA handle cut short
    for t, n in ((0x0200, 3), (0x0201, 20), (0x0201, 60), (0x0202, 1), (0x0203, 3),
                 (0x0204, 0), (0x0205, 10), (0x0206, 8), (0x0207, 0), (0x0208, 0),
                 (0x0209, 2), (0x020b, 1)):
        M.append((O, media(t, 1, bytes(n))))
    M.append((O, media(0x020b, 1, bytes([0, 2]) + bytes(4) + tone(0))))   # one of two tones
    M.append((O, msg(0x0302, b'\x7d')))                                    # SYNC type cut short
    M.append((O, msg(0x0302, b'\x7d\x15')))                                # length missing
    for t in (0x7d15, 0x7d16, 0x7d18, 0x7d1d, 0x7d1e, 0x7d1f, 0x7d2c):
        M.append((O, sync(t, b'', length=4)))
    M.append((O, sync(0x7d1f, bytes([3, 0, 1, 0, 2]))))
    M.append((O, sync(0x7d2c, bytes([2, 0, 1, 0, 2, 3, 4]))))
    M.append((O, msg(0x0301, b'')))                                        # ETH without contents
    # MEDIA-DTMF without the direction, and a key that is not a DTMF key
    M.append((O, media(0x0209, 1, struct.pack('<H', 1) + b'7')))
    return M


def frames(messages):
    t = Tcp()
    return [t.frame(p, o) for o, p in messages]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'dect-mitel-rfp-coverage.pcap'), frames(main_messages()))
    pcap(os.path.join(out, 'dect-mitel-rfp-coverage-malformed.pcap'), frames(malformed_messages()))


if __name__ == '__main__':
    main()
