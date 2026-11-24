#!/usr/bin/env python3
# Generates test/captures/z21_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Z21 (Roco/Fleischmann Z21 LAN protocol) coverage captures.
Usage: mkz21.py <outdir> [-v]   (writes z21-coverage.pcap and
z21-coverage-malformed.pcap; -v prints the frame numbers)."""
import struct
import socket
import sys
import os


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp_pkt(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
    s = socket.inet_aton(src)
    d = socket.inet_aton(dst)
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, s, d)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return (b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + udp)


def write_pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def pdu(cmd, data=b''):
    """A LAN PDU: length (LE) + 2 byte header + data. cmd is the on-wire
    header as a big-endian 16-bit number (0x1000 = 10 00)."""
    return struct.pack('<H', 4 + len(data)) + struct.pack('>H', cmd) + data


def xbus(xh, db0=None, data=b'', bad=False, raw_cmd=0x4000):
    """An X-BUS PDU with XOR checksum."""
    body = bytes([xh]) + (bytes([db0]) if db0 is not None else b'') + data
    x = 0
    for b in body:
        x ^= b
    if bad:
        x ^= 0x55
    return pdu(0x4000, body + bytes([x]))


C = ('192.0.2.1', 40000)   # client
S = ('192.0.2.2', 21105)   # command station
frames = []
ranges = []


def req(p, port=21105):
    frames.append(udp_pkt(p, 40000, port))


def rsp(p, port=21105):
    frames.append(udp_pkt(p, port, 40000, '192.0.2.2', '192.0.2.1'))


def mark(name, start):
    ranges.append((name, start, len(frames)))


def le16(v):
    return struct.pack('<H', v)


def be16(v):
    return struct.pack('>H', v)


def build_main():
    global frames, ranges
    frames = []
    ranges = []
    n = len(frames) + 1
    # --- plain (non X-BUS) commands
    req(pdu(0x1000))                                   # GET_SERIAL_NUMBER request
    rsp(pdu(0x1000, struct.pack('<I', 0x00c0ffee)))    # reply with serial
    rsp(pdu(0x1000, b'\x01\x02'))                      # odd length: data dump
    req(pdu(0x1A00))                                   # GET_HWINFO
    rsp(pdu(0x1A00, struct.pack('<II', 0x200, 0x143)))  # Z21a, fw 1.43
    rsp(pdu(0x1A00, struct.pack('<II', 0x211, 0x140)))
    rsp(pdu(0x1A00, struct.pack('<II', 0x999, 0x120)))  # unknown type
    req(pdu(0x3000))                                   # LOGOFF
    mark('serial, hwinfo, logoff', n)
    n = len(frames) + 1
    req(pdu(0x5000, struct.pack('<I', 0x00000100)))    # SET_BROADCASTFLAGS
    req(pdu(0x5000, struct.pack('<I', 0xffffffff)))    # all flags
    req(pdu(0x5100))                                   # GET_BROADCASTFLAGS
    rsp(pdu(0x5100, struct.pack('<I', 0x00010003)))
    req(pdu(0x6000, be16(3)))                          # GET_LOCOMODE
    rsp(pdu(0x6000, be16(3) + b'\x01'))                # reply, MM
    req(pdu(0x6100, be16(0x2003) + b'\x00'))           # SET_LOCOMODE, DCC
    mark('broadcast flags, loco mode', n)
    n = len(frames) + 1
    # --- system state
    ss = (struct.pack('<hhhh', 120, 5, 118, 31) + struct.pack('<HH', 16500, 16400)
          + b'\x01\x02\x00' + b'\x00')
    rsp(pdu(0x8400, ss))                                # capabilities 0
    ss2 = (struct.pack('<hhhh', -3, 0, 2, -12) + struct.pack('<HH', 18000, 17900)
           + b'\x0f\x1f\x00' + b'\xff')
    rsp(pdu(0x8400, ss2))                               # all state bits, all caps
    ss3 = (struct.pack('<hhhh', 0, 0, 0, 20) + struct.pack('<HH', 0, 0)
           + b'\x00\x00\x00' + b'\x13')
    rsp(pdu(0x8400, ss3))
    req(pdu(0x8500))                                    # SYSTEMSTATE_GETDATA
    mark('system state', n)
    n = len(frames) + 1
    # --- R-BUS, RailCom
    req(pdu(0x8100, b'\x00'))                           # RMBUS_GETDATA group 0
    rsp(pdu(0x8000, b'\x01' + bytes(range(10))))        # RMBUS_DATACHANGED
    req(pdu(0x8200, b'\x07'))                           # RMBUS_PROGRAMMODULE
    rsp(pdu(0x8800, le16(3) + struct.pack('<IH', 1000, 2) + b'\x00\x03\x20\x02\x00'))
    req(pdu(0x8900, b'\x00' + le16(3)))                 # RAILCOM_GETDATA
    mark('R-BUS and RailCom', n)
    n = len(frames) + 1
    # --- LocoNet
    rsp(pdu(0xA000, b'\xb5\x03\x40\x1c'))               # LOCONET_Z21_RX
    rsp(pdu(0xA100, b'\xa0\x01\x40\x1e'))               # LOCONET_Z21_TX
    req(pdu(0xA200, b'\xbf\x00\x03\x43'))               # LOCONET_FROM_LAN
    req(pdu(0xA300, be16(3)[::-1]))                     # DISPATCH_ADDR request
    rsp(pdu(0xA300, le16(3) + b'\x01'))                 # reply with result
    req(pdu(0xA400, b'\x80' + le16(100)))               # DETECTOR request
    rsp(pdu(0xA400, b'\x81' + le16(100) + b'\x01\x02\x03'))   # reply
    mark('LocoNet', n)
    n = len(frames) + 1
    # --- boosters, CAN, decoders, zLink
    req(pdu(0xB200, b'\x01\x00'))                       # BOOSTER_SET_POWER
    req(pdu(0xB800))                                    # BOOSTER_GET_DESCRIPTION
    rsp(pdu(0xB800, b'Booster One'.ljust(32, b'\x00')))
    rsp(pdu(0xB800, b'\xff' + b'\x00' * 31))            # empty name
    req(pdu(0xB900, b'Booster Two'.ljust(32, b'\x00')))  # SET_DESCRIPTION
    rsp(pdu(0xBA00, bytes(range(24))))                  # BOOSTER_SYSTEMSTATE_DATACHANGED
    req(pdu(0xBB00))                                    # BOOSTER_SYSTEMSTATE_GETDATA
    req(pdu(0xC400, b'\x01' + le16(7)))                 # CAN_DETECTOR request
    rsp(pdu(0xC400, le16(7) + le16(0x1234) + b'\x02\x01' + le16(300) + le16(600)))
    req(pdu(0xC800, le16(7)))                           # CAN_DEVICE_GET_DESCRIPTION
    rsp(pdu(0xC800, le16(7) + b'CanBooster'.ljust(16, b'\x00')))
    req(pdu(0xC900, le16(7) + b'NewName'.ljust(16, b'\x00')))
    rsp(pdu(0xCA00, le16(7) + le16(1) + struct.pack('<H', 0x001f)
            + le16(18000) + le16(1500)))                # CAN booster state, all bits
    rsp(pdu(0xCA00, le16(8) + le16(2) + struct.pack('<H', 0)
            + le16(0) + le16(0)))
    req(pdu(0xCB00, le16(7) + b'\x01'))                 # CAN_BOOSTER_SET_TRACKPOWER
    for c in (0xCC00, 0xCD00, 0xCE00, 0xCF00):          # fast clock: no decoder
        req(pdu(c, b'\x01\x02\x03'))
    req(pdu(0xD800))                                    # DECODER_GET_DESCRIPTION
    rsp(pdu(0xD800, b'Switch Decoder'.ljust(32, b'\x00')))
    rsp(pdu(0xD800, b'\xff' + b'\x00' * 31))
    req(pdu(0xD900, b'Signal Decoder'.ljust(32, b'\x00')))
    rsp(pdu(0xDA00, bytes(range(40))))                  # DECODER_SYSTEMSTATE_DATACHANGED
    req(pdu(0xDB00))
    req(pdu(0xE800, b'\x06'))                           # ZLINK_GET_HWINFO request
    rsp(pdu(0xE800, b'\x06' + le16(0x0301) + b'\x01\x02' + le16(7)
            + b'02-00-00-00-00-05'.ljust(18, b'\x00')
            + b'zLinkName'.ljust(33, b'\x00') + b'\xaa'))
    mark('booster, CAN, fast clock, decoder, zLink', n)
    n = len(frames) + 1
    # --- X-BUS
    req(xbus(0x21, 0x21))                               # GET_VERSION
    rsp(xbus(0x63, 0x21, b'\x30\x12'))                  # reply
    req(xbus(0x21, 0x24))                               # GET_STATUS
    rsp(xbus(0x62, 0x22, b'\x12'))                      # STATUS_CHANGED
    rsp(xbus(0x62, 0x22, b'\x00'))
    req(xbus(0x21, 0x80))                               # TRACK_POWER_OFF
    req(xbus(0x21, 0x81))                               # TRACK_POWER_ON
    rsp(xbus(0x61, 0x00))
    rsp(xbus(0x61, 0x01))
    rsp(xbus(0x61, 0x02))
    rsp(xbus(0x61, 0x08))
    rsp(xbus(0x61, 0x12))
    rsp(xbus(0x61, 0x13))
    rsp(xbus(0x61, 0x82))
    rsp(xbus(0x81, 0x00))                               # BC_STOPPED
    req(xbus(0x80))                                     # SET_STOP (one byte)
    req(xbus(0xf1, 0x0a))                               # firmware version request
    rsp(xbus(0xf3, 0x0a, b'\x01\x43'))                  # reply
    req(xbus(0x7e, 0x7e, b'\x01'))                      # unknown X-BUS command
    mark('X-BUS system commands', n)
    n = len(frames) + 1
    # loco commands
    req(xbus(0xe3, 0xf0, be16(0xc003)))                 # GET_LOCO_INFO (long address)
    li = [be16(3) + b'\x04\x80\x10\x01\x02',            # no extension bytes
          be16(4) + b'\x02\x05\x41\x00\x00\x08',        # + F21..F28
          be16(5) + b'\x00\x85\x58\xff\xff\xaa\x07',    # + F29..F31
          be16(6) + b'\x04\x7f\x00\x00\x00\x00\x00\xde\xad']   # + extensions
    for d in li:
        rsp(xbus(0xef, None, d))                        # LOCO_INFO (one byte cmd)
    req(xbus(0xe4, 0x10, be16(3) + b'\x85'))            # DRIVE 14, forward
    req(xbus(0xe4, 0x12, be16(0xc0c8) + b'\x05'))       # DRIVE 28, reverse
    req(xbus(0xe4, 0x13, be16(0xc0c8) + b'\xff'))       # DRIVE 128
    req(xbus(0xe4, 0xf8, be16(3) + b'\x41'))            # SET_LOCO_FUNCTION on
    req(xbus(0xe4, 0xf8, be16(3) + b'\x9f'))            # toggle
    req(xbus(0xe5, 0x5f, be16(3) + b'\x01\x02'))        # SET_LOCO_BINARY_STATE
    req(xbus(0xe3, 0x44, be16(3)))                      # PURGE_LOCO
    req(xbus(0x92, None, be16(3)))                      # SET_LOCO_E_STOP
    mark('X-BUS loco commands', n)
    n = len(frames) + 1
    # accessories
    req(xbus(0x43, None, be16(10)))                     # GET_TURNOUT_INFO
    rsp(xbus(0x43, None, be16(10) + b'\x01'))           # TURNOUT_INFO
    req(xbus(0x53, None, be16(10) + b'\xa9'))           # SET_TURNOUT
    req(xbus(0x53, None, be16(11) + b'\x80'))
    req(xbus(0x44, None, be16(20) + b'\x00'))           # GET_EXT_ACCESSORY_INFO
    rsp(xbus(0x44, None, be16(20) + b'\x05\x00'))       # EXT_ACCESSORY_INFO
    req(xbus(0x54, None, be16(20) + b'\x05\x00'))       # SET_EXT_ACCESSORY
    mark('X-BUS accessories', n)
    n = len(frames) + 1
    # CV and registers
    req(xbus(0x23, 0x11, be16(0)))                      # CV_READ CV1
    req(xbus(0x24, 0x12, be16(28) + b'\x03'))           # CV_WRITE
    rsp(xbus(0x64, 0x14, be16(28) + b'\x03'))           # CV_RESULT
    req(xbus(0x22, 0x11, b'\x05'))                      # DCC_READ_REGISTER
    req(xbus(0x23, 0x12, b'\x05\x77'))                  # DCC_WRITE_REGISTER
    req(xbus(0x24, 0xff, b'\x00\x05\x77'))              # MM_WRITE_BYTE
    # POM: loco (E6 30) with DB3 operation: read, write bit, write byte, none
    req(xbus(0xe6, 0x30, be16(3) + bytes([0xe4, 28])))           # read byte
    req(xbus(0xe6, 0x30, be16(3) + bytes([0xe8, 28, 0x0d])))      # write bit
    req(xbus(0xe6, 0x30, be16(3) + bytes([0xec, 28, 0x55])))      # write byte
    req(xbus(0xe6, 0x30, be16(3) + bytes([0xe0, 28, 0x00])))             # other
    req(xbus(0xe6, 0x31, be16(3) + bytes([0xe4, 28])))                   # accessory read
    req(xbus(0xe6, 0x31, be16(3) + bytes([0xe8, 28, 0x0d])))             # write bit
    req(xbus(0xe6, 0x31, be16(3) + bytes([0xec, 28, 0x55])))             # write byte
    req(xbus(0xe6, 0x31, be16(3) + bytes([0xe0, 28, 0x00])))             # other
    mark('X-BUS CV, registers, POM', n)
    n = len(frames) + 1
    # invalid checksum (warning), two PDUs in one datagram, port 21106
    req(xbus(0x21, 0x24, bad=True))
    frames.append(udp_pkt(xbus(0x21, 0x21) + pdu(0x1000) + pdu(0x3000),
                          40000, 21105))
    req(pdu(0x1000), port=21106)
    mark('bad checksum, several PDUs per datagram, port 21106', n)
    return frames


def build_malformed():
    global frames, ranges
    frames = []
    ranges = []
    n = 1
    # unknown command: not claimed by the heuristic-less PDU check
    req(pdu(0x7700, b'\x01\x02\x03\x04'))
    # length longer than the datagram, and shorter than the minimum
    req(struct.pack('<H', 40) + b'\x10\x00' + b'\x00' * 4)
    req(struct.pack('<H', 3) + b'\x10\x00\x00')
    req(b'\x04')                                       # shorter than the minimum
    # truncated PDUs whose length is right but the content is short
    req(pdu(0x8400, b'\x00\x01'))                     # system state cut short
    req(xbus(0xe4, 0x13, b'\x00')[:6] )
    req(pdu(0xE800, b'\x06\x01\x03\x01'))             # zLink cut short
    req(pdu(0xB800, b'short'))                        # booster name cut short
    req(pdu(0xD800, b'short'))
    req(pdu(0x8000, b'\x01\x02'))                     # R-BUS data cut short
    req(pdu(0x8800, b'\x01\x02'))
    req(pdu(0xBA00, b'\x01'))
    req(pdu(0xCA00, b'\x01\x00'))
    req(pdu(0xC400, b'\x01\x00' + b'\x01' * 4))       # CAN reply cut short
    req(pdu(0xC800, le16(1) + b'x' * 3))
    # the loco info with extension and POM cut short
    req(xbus(0xe6, 0x30, be16(3) + bytes([0xec]))[:9])
    req(xbus(0xef, None, be16(3) + b'\x04\x80')[:8])
    # a length field of 4 with a command that wants data
    req(pdu(0x6000))
    req(pdu(0xA300))
    req(pdu(0xA400, b'\x80'))
    req(pdu(0xB200))
    req(pdu(0xCB00, le16(5)))
    req(pdu(0xDA00, b''))
    return frames


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    write_pcap(os.path.join(out, 'z21-coverage.pcap'), build_main())
    if '-v' in sys.argv:
        for name, a, b in ranges:
            print('%3d-%3d  %s' % (a, b, name))
        print(len(frames), 'frames')
    write_pcap(os.path.join(out, 'z21-coverage-malformed.pcap'), build_malformed())
    if '-v' in sys.argv:
        print(len(frames), 'malformed frames')
