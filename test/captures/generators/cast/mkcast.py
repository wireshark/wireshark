#!/usr/bin/env python3
# Generates test/captures/cast_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Cast Client Control
Protocol dissector (packet-cast.c).

CAST runs on TCP port 4224, registered by default. Each message is a
little endian header (data length, marker 0, message ID) followed by
fixed size fields. Every packet is built from scratch with struct; no
captured traffic is used.

Usage: mkcast.py <output directory>

Writes:
  cast-coverage.pcap            every message ID the dissector knows and an
                                unknown one, a 1560 octet
                                UpdateCapabilities message in two segments,
                                several messages in one segment, a message
                                whose header is split over two segments,
                                and a connection that does not start with
                                a CAST header
  cast-coverage-malformed.pcap  the PDU length overflow reproducer (data
                                length 0xFFFFFFF8, three segments), data
                                length 0xFFFFFFF7, messages shorter than
                                their fields, segments shorter than the
                                header, data length 0..3
"""

import os
import struct
import sys

MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')
IP_C = bytes([192, 0, 2, 10])      # the phone
IP_S = bytes([198, 51, 100, 20])   # the call manager
PORT = 4224


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def ip_frame(src, dst, proto, l4, ident):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0, 64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    smac, dmac = (MAC_C, MAC_S) if src == IP_C else (MAC_S, MAC_C)
    return dmac + smac + b'\x08\x00' + ip + l4


def tcp_frame(sport, dport, payload, seq, ack, src, dst, flags=0x18, ident=1):
    # SYNs carry an MSS option (a SYN without options looks like a scanner)
    opts = struct.pack('>BBHBBBB', 2, 4, 1460, 4, 2, 1, 1) if flags & 0x02 else b''
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags,
                      65535, 0, 0) + opts
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 6, len(tcp) + len(payload))
    c = csum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack('>H', c) + tcp[18:]
    return ip_frame(src, dst, 6, tcp + payload, ident)


class Conn:
    """One TCP connection with a three way handshake."""

    def __init__(self, frames, cport):
        self.f = frames
        self.cport = cport
        self.cseq = 1000
        self.sseq = 5000
        self.add(True, b'', 0x02)
        self.add(False, b'', 0x12)
        self.add(True, b'', 0x10)

    def add(self, from_client, data, flags=0x18):
        if from_client:
            fr = tcp_frame(self.cport, PORT, data, self.cseq, self.sseq if flags != 0x02 else 0,
                           IP_C, IP_S, flags, ident=len(self.f) + 1)
            self.cseq += len(data) + (1 if flags & 0x03 else 0)
        else:
            fr = tcp_frame(PORT, self.cport, data, self.sseq, self.cseq, IP_S, IP_C, flags,
                           ident=len(self.f) + 1)
            self.sseq += len(data) + (1 if flags & 0x03 else 0)
        self.f.append(fr)
        return len(self.f)

    def close(self):
        self.add(True, b'', 0x11)
        self.add(False, b'', 0x11)
        self.add(True, b'', 0x10)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)




# CAST messages ----------------------------------------------------------

def u32(*vals):
    return b''.join(struct.pack('<I', v) for v in vals)


def ip(a, b, c, d):
    # The dissector reads IPv4 addresses as little endian 32 bit values
    return struct.pack('<I', (a << 24) | (b << 16) | (c << 8) | d)


def text(s, n):
    s = s.encode()
    return s + b'\0' * (n - len(s))


def msg(mid, body=b''):
    return struct.pack('<III', 4 + len(body), 0, mid) + body


NAME = 40   # StationMaxNameSize
DIRNUM = 24  # StationMaxDirnumSize


def update_capabilities():
    b = u32(2, 1, 0, 1)                              # video/data caps, RTP format, custom
    for i in range(6):                               # customPictureFormat[6]
        b += u32(352 + i, 288 + i, 1, 0, 1001)
    b += u32(1, 768, 2)                              # confResources
    for i in range(4):                               # serviceResource[4]
        b += u32(2) + u32(*[(i + j) % 11 for j in range(5)]) + u32(i, 4, 2, 0)
    for i in range(10):                              # vidCaps[10]
        b += u32(100 + i % 3, 1 + i % 3, 2)
        for t in range(4):                           # levelPreference[4]
            b += u32(t, 1 + (i + t) % 6, 384000, 64000, 1, t)
        b += u32(1, 0)                               # h261 / h263 / vieo
    for i in range(5):                               # dataCaps[5]
        b += u32(105 if i % 2 else 106, 3, 0, 64000)
    assert len(b) == 1548
    return msg(0x03, b)


def open_receive_channel():
    b = u32(7001, 9001, 4, 1, 4242, 0, 0, 1)         # conf, party, cap, line, call, rfc, pt, creator
    b += u32(20, 1)                                  # msPacket/bitRate, echo/pictureFormatCount
    b += u32(1, 2, 2, 1, 3, 1, 4, 2, 6, 1)           # pictureFormat[5] (also g723BitRate)
    b += u32(3)                                      # confServiceNum
    b += u32(1, 0)                                   # h261 / h263 / vieo
    assert len(b) == 92
    return msg(0x05, b)


def open_receive_channel_ack():
    return msg(0x06, u32(0) + ip(192, 0, 2, 10) + u32(20000, 9001, 4242))


def start_transmission():
    b = u32(7001, 9001, 101) + ip(198, 51, 100, 30) + u32(20002, 4242, 0, 0, 0xb8)
    b += u32(384000, 2)                              # bitRate, pictureFormatCount
    b += u32(2, 1, 3, 1, 1, 2, 4, 3, 5, 4)           # pictureFormat[5]
    b += u32(3)                                      # confServiceNum
    b += u32(1, 0)                                   # h261 / h263 / vieo
    assert len(b) == 96
    return msg(0x08, b)


def misc_command(cmd):
    b = u32(7001, 9001, 4242, cmd)
    b += u32(1, 2, 3, 4, 5, 6, 7, 8, 9)              # union, 36 octets
    assert len(b) == 52
    return msg(0x0A, b)


def call_info():
    b = text('Alice', NAME) + text('1001', DIRNUM) + text('Bob', NAME) + text('2002', DIRNUM)
    b += u32(1, 4242, 2)                             # line, call id, OutBoundCall
    b += text('Carol', NAME) + text('3003', DIRNUM)
    b += text('Dave', NAME) + text('4004', DIRNUM)
    b += u32(0, 1)                                   # redirect reasons
    b += text('1001', DIRNUM) + text('2002', DIRNUM) + text('3003', DIRNUM) + text('4004', DIRNUM)
    b += u32(1, 2, 0xa5)                             # instance, Authenticated, PI bits
    return msg(0x10, b)


def remote_info(mid):
    b = text('Conference room phone', NAME) + text('8f3c2a10-0000-4000-8000-000000000001', NAME)
    b += ip(192, 0, 2, 10)
    if mid == 0x91:
        b += text('5005', NAME)
    return msg(mid, b)


def main_frames():
    F = []
    c = Conn(F, 52000)                                                   # 1-3
    # 4-5: keep alive version and its ACK
    c.add(True, msg(0x01, u32(3)))
    c.add(False, msg(0x02, u32(3)))
    # 6-7: UpdateCapabilities (1560 octets) in two segments
    m = update_capabilities()
    c.add(True, m[:1000])
    c.add(True, m[1000:])
    # 8: EmptyCapabilities, KeepAlive and RequestAllCallStates in one segment
    c.add(True, msg(0x04) + msg(0x00) + msg(0x0F))
    # 9: OpenMultiMediaReceiveChannel
    c.add(False, open_receive_channel())
    # 10: its ACK
    c.add(True, open_receive_channel_ack())
    # 11: StartMultiMediaTransmission
    c.add(False, start_transmission())
    # 12: MiscellaneousCommand (videoFastUpdatePicture) and
    # FlowControlCommand
    c.add(False, misc_command(1) + msg(0x0B, u32(7001, 9001, 4242, 256000)))
    # 13: MiscellaneousCommand with an unknown command type
    c.add(True, misc_command(9))
    # 14: CallState and RequestCallState, 15: CallInfo
    c.add(False, msg(0x0D, u32(5, 1, 4242, 0, 4, 1)) + msg(0x0E, u32(4242)))
    c.add(False, call_info())
    # 16: RequestCallInfo, CallFocus, MakeCall
    c.add(True, msg(0x11, u32(1)) + msg(0x12, u32(1, 4242))
          + msg(0x13, text('2002', DIRNUM)))
    # 17: Answer and the stream messages, then the first 2 octets of HangUp
    hang = msg(0x14, u32(1))
    c.add(True, msg(0x15, u32(1)) + msg(0x41) + msg(0x47, u32(4)) + msg(0x43) + msg(0x44)
          + msg(0x45) + msg(0x46) + msg(0x42) + hang[:2])
    # 18: the rest of HangUp (the header is reassembled) and KeepAliveACK
    c.add(True, hang[2:] + msg(0x40))
    # 19: Close and Stop of the media channels, ClearConference
    c.add(False, msg(0x07, u32(7001, 9001, 4242)) + msg(0x09, u32(7001, 9001, 4242))
          + msg(0x0C, u32(7001, 3)))
    # 20: RemoteRequest and 21: RemoteResponse
    c.add(False, remote_info(0x90))
    c.add(True, remote_info(0x91))
    # 22-23: the protocol messages without fields (in 22 with some opaque data)
    c.add(True, b''.join(msg(mid, b'\x01\x02\x03\x04') for mid in
                         (0x50, 0x51, 0x60, 0x61, 0x62, 0x70, 0x71, 0x74, 0x75, 0x80)))
    c.add(False, b''.join(msg(mid) for mid in
                          (0xA0, 0xA1, 0xA4, 0xA5, 0xB0, 0xB1, 0xB4, 0xB5, 0xC0, 0xC1,
                           0xC4, 0xC5, 0xCC, 0xD0, 0xD1)))
    # 24: an unknown message ID
    c.add(True, msg(0x1234, b'unknown'))
    # 25-27: FIN
    c.close()
    # 28-34: a second connection whose first segment (31) is not a CAST message
    # (marker not 0): the dissector rejects it and TCP shows the payload
    c = Conn(F, 52001)
    c.add(True, b'HELO cast-coverage\r\n')
    c.close()
    return F


def malformed_frames():
    F = []
    seq = [1000]

    def seg(sport, payload, s=None):
        s = seq[0] if s is None else s
        F.append(tcp_frame(sport, PORT, payload, s, 1, IP_C, IP_S, ident=len(F) + 1))
        seq[0] = s + len(payload)

    # 1-3: the reproducer (cast_pdu_len_overflow.py) cut to
    # three 1400 octet segments: data length 0xFFFFFFF8 wrapped the PDU
    # length to 0, so every later segment was added to the same PDU. With
    # the fix the PDU length is 1, shorter than the header: malformed in
    # the first segment, and the later segments are dissected on their own
    first = struct.pack('<III', 0xFFFFFFF8, 0, 0) + b'A' * (1400 - 12)
    seq[0] = 1000
    seg(40000, first)
    seg(40000, b'B' * 1400)
    seg(40000, b'B' * 1400)
    # 4-5: data length 0xFFFFFFF7 (PDU length 0xFFFFFFFF, no wrap): TCP
    # waits for more data
    seq[0] = 1000
    seg(40001, struct.pack('<III', 0xFFFFFFF7, 0, 0) + b'A' * 100)
    seg(40001, b'B' * 100)
    # 6: OpenMultiMediaReceiveChannel with a data length of 20: the fields
    # run past the end of the PDU
    seq[0] = 1000
    seg(40002, struct.pack('<III', 20, 0, 5) + u32(1, 2, 3, 4))
    # 7-8: CallInfo cut short, UpdateCapabilities cut short
    seg(40002, struct.pack('<III', 50, 0, 0x10) + b'x' * 46)
    seg(40002, struct.pack('<III', 100, 0, 0x03) + b'\0' * 96)
    # 9-10: a segment of 6 octets that starts a message: dissect_cast() reads
    # the marker past the end (exception instead of asking for more data)
    seq[0] = 1000
    m = msg(0x01, u32(3))
    seg(40003, m[:6])
    seg(40003, m[6:])
    # 11: data length 2 (less than the message ID)
    seq[0] = 1000
    seg(40004, struct.pack('<II', 2, 0) + b'\0\0')
    # 12: a 3 octet segment
    seq[0] = 1000
    seg(40005, b'\x08\x00\x00')
    # 13-33: every known message with only the header (fields missing)
    seq[0] = 1000
    for mid in (0x01, 0x02, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x47, 0x90, 0x91):
        seg(40006, msg(mid))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'cast-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'cast-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
