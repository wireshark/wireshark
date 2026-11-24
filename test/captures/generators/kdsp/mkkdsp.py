#!/usr/bin/env python3
# Generates test/captures/kdsp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the KDSP (Kismet Drone/Server Protocol) coverage captures.

Usage: mkkdsp.py <outdir>

  kdsp-coverage.pcap            a TCP stream to port 2502 with every
                                command, TCP reassembly, 802.11 and
                                radiotap payloads
  kdsp-coverage-malformed.pcap  header length mismatch, payload without
                                a link type, truncated messages, unknown
                                command
Synthetic: built with struct only.
"""
import os
import struct
import sys

CMAC = bytes.fromhex('020000000002')
SMAC = bytes.fromhex('020000000001')
SENTINEL = 0xdecafbad
PORT = 2502

CMD_NULL, HELLO, STRING, CAPPACKET, CHANNELSET, SOURCE, REPORT = range(7)
CPT_FLAG, FCS_FLAG, GPS_FLAG, RADIO_FLAG = 0x80000000, 4, 2, 1
D_UUID, D_LEN, D_SEC, D_USEC, D_DLT = 0x10, 0x08, 0x04, 0x02, 0x01


def csum(b):
    if len(b) & 1:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class Conn:
    """One TCP connection; frames() collects the packets."""

    def __init__(self, cport=41000, sport=PORT, cip=(192, 0, 2, 1), sip=(192, 0, 2, 2)):
        self.cport, self.sport = cport, sport
        self.cip, self.sip = bytes(cip), bytes(sip)
        self.cseq, self.sseq = 1000, 5000
        self.out = []

    def seg(self, from_client, data=b'', flags=0x18):
        if from_client:
            sp, dp, s, a, src, dst = self.cport, self.sport, self.cseq, self.sseq, self.cip, self.sip
        else:
            sp, dp, s, a, src, dst = self.sport, self.cport, self.sseq, self.cseq, self.sip, self.cip
        opts = struct.pack('!BBH', 2, 4, 1460) + b'\x04\x02\x01\x03\x03\x07\x01\x01' if flags & 0x02 else b''
        tcp = struct.pack('!HHIIBBHHH', sp, dp, s, a if flags & 0x10 else 0, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + data
        pseudo = src + dst + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), len(self.out) + 1, 0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        macs = (CMAC + SMAC) if from_client else (SMAC + CMAC)
        self.out.append(macs + b'\x08\x00' + ip + tcp)
        adv = len(data) + (1 if flags & 0x03 else 0)
        if from_client:
            self.cseq += adv
        else:
            self.sseq += adv

    def handshake(self):
        self.seg(True, flags=0x02)
        self.seg(False, flags=0x12)
        self.seg(True, flags=0x10)

    def close(self):
        self.seg(True, flags=0x11)
        self.seg(False, flags=0x11)
        self.seg(True, flags=0x10)


def pdu(cmd, body, length=None):
    return struct.pack('!III', SENTINEL, cmd, len(body) if length is None else length) + body


def s(txt, n):
    return txt.encode().ljust(n, b'\0')


UUID = bytes(range(16))


def hello():
    return pdu(HELLO, struct.pack('!I', 4) + s('Kismet-2011-03-R1', 32) + s('drone-host', 32))


def string(msg, flags=0):
    m = msg.encode()
    return pdu(STRING, struct.pack('!II', flags, len(m)) + m)


def beacon():
    fc = struct.pack('<HH', 0x0080, 0)
    addrs = bytes.fromhex('ffffffffffff') + bytes.fromhex('0a0b0c0d0e0f') * 2
    body = struct.pack('<HHQHH', 0, 0, 0, 100, 0x0401)
    body = struct.pack('<Q', 123456789) + struct.pack('<HH', 100, 0x0401)
    tags = b'\x00\x04kdsp' + b'\x01\x04\x82\x84\x8b\x96' + b'\x03\x01\x06'
    return fc + addrs + struct.pack('<H', 0x0010) + body + tags


def radiotap(inner):
    # version 0, pad 0, length 8, present = 0
    return struct.pack('<BBHI', 0, 0, 8, 0) + inner


def radio_hdr():
    return struct.pack('!HIHHhhIIIhh', 30, 0x1ff, 5, 2437, -50, -92, 1, 2, 54, 200, 40)


def gps_hdr():
    return (struct.pack('!HIH', 68, 0x3f, 3) + b''.join(bytes([i]) * 12 for i in range(1, 6)))


def cpt_hdr(bitmap, payload_len, dlt, uuid=True, ts=3, wrong_len=0):
    b = 6
    if bitmap & D_UUID: b += 16
    if bitmap & D_LEN: b += 2
    if bitmap & D_SEC: b += 8
    if bitmap & D_USEC: b += 8
    if bitmap & D_DLT: b += 4
    h = struct.pack('!HI', b + wrong_len, bitmap)
    if bitmap & D_UUID: h += UUID
    if bitmap & D_LEN: h += struct.pack('!H', payload_len)
    if bitmap & D_SEC: h += struct.pack('!Q', 1700000000)
    if bitmap & D_USEC: h += struct.pack('!Q', 123456)
    if bitmap & D_DLT: h += struct.pack('!I', dlt)
    return h


def cappacket(flags, dbitmap=None, payload=b'', dlt=105, fcs=0x01020304, offset=0, wrong_len=0,
              reported=None):
    body = struct.pack('!II', flags, offset)
    if flags & FCS_FLAG:
        body += struct.pack('!I', fcs)
    if flags & RADIO_FLAG:
        body += radio_hdr()
    if flags & GPS_FLAG:
        body += gps_hdr()
    if flags & CPT_FLAG:
        body += cpt_hdr(dbitmap, len(payload) if reported is None else reported, dlt, wrong_len=wrong_len)
    return pdu(CAPPACKET, body + payload)


def channelset(entries, bitmap=0x1ff, cmd=1):
    data = b''
    for e in entries:
        if e[0] == 'c':
            data += struct.pack('!HHHH', e[1], e[2], 0, 0)
        else:
            data += struct.pack('!HHHH', 0x8000 | e[1], e[2], e[3], e[4])
    data = data.ljust(2046, b'\0')
    body = (struct.pack('!HI', 2 + 4 + 16 + 2 * 4 + 2046 + 4 - 2, bitmap) + UUID
            + struct.pack('!HHHH', cmd, 6, 3, len(entries)) + data
            + struct.pack('!HH', 5, 250))
    return pdu(CHANNELSET, body)


def source():
    body = (struct.pack('!HI', 75, 0xff) + UUID + struct.pack('!H', 0)
            + s('wlan0 source', 16) + s('wlan0', 16) + s('mac80211', 16)
            + struct.pack('!BHH', 1, 250, 5))
    return pdu(SOURCE, body)


def report():
    return pdu(REPORT, struct.pack('!HI', 29, 0xf) + UUID + struct.pack('!BII', 1, 1700000000, 5000))


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def main(out):
    c = Conn()
    c.handshake()
    c.seg(False, hello())
    c.seg(False, string('Drone starting'))
    c.seg(False, pdu(CMD_NULL, b''))
    c.seg(False, source())
    c.seg(False, report())
    # CAPPACKET: 802.11 payload with only the capture data (time, length, DLT)
    w = beacon()
    c.seg(False, cappacket(CPT_FLAG, D_LEN | D_SEC | D_USEC | D_DLT, w))
    # with a UUID, seconds only
    c.seg(False, cappacket(CPT_FLAG, D_UUID | D_LEN | D_SEC | D_DLT, w))
    # microseconds only
    c.seg(False, cappacket(CPT_FLAG, D_LEN | D_USEC | D_DLT, w))
    # radiotap payload with FCS, radio and GPS headers
    c.seg(False, cappacket(CPT_FLAG | FCS_FLAG | RADIO_FLAG | GPS_FLAG,
                           D_UUID | D_LEN | D_SEC | D_USEC | D_DLT, radiotap(w), dlt=127))
    # no timestamp at all, DLT unknown (nothing dissects the payload)
    c.seg(False, cappacket(CPT_FLAG, D_LEN | D_DLT, w, dlt=1))
    # a capture packet without the capture header and a header without payload
    c.seg(False, cappacket(FCS_FLAG | RADIO_FLAG, offset=40))
    c.seg(False, cappacket(CPT_FLAG, D_DLT, b'', dlt=105))
    # CHANNELSET with channels and ranges; the 2092 byte message is split in two
    cs = channelset([('c', 1, 200), ('c', 6, 300), ('r', 36, 64, 4, 1), ('c', 11, 100), ('r', 100, 140, 4, 2)])
    c.seg(True, cs[:1000])
    c.seg(True, cs[1000:])
    # Another one with the header split from the rest, and no entries
    cs2 = channelset([], cmd=4)
    c.seg(True, cs2[:5])
    c.seg(True, cs2[5:1500])
    c.seg(True, cs2[1500:])
    # Two messages in one segment
    c.seg(False, string('first') + report())
    # A message that completes in a segment with the start of the next
    r = source()
    c.seg(False, r[:40])
    c.seg(False, r[40:] + string('tail'))
    # Command that echoes the largest string
    c.seg(False, string('x' * 1200, 0xffffffff))
    c.close()
    pcap(os.path.join(out, 'kdsp-coverage.pcap'), c.out)

    m = Conn(cport=41001)
    m.handshake()
    # unknown command
    m.seg(False, pdu(9, b'\0' * 8))
    # CPT header length does not match the flags
    m.seg(False, cappacket(CPT_FLAG, D_LEN | D_SEC | D_DLT, w, wrong_len=4))
    # a payload length, but no DLT
    m.seg(False, cappacket(CPT_FLAG, D_LEN, w))
    # payload without a payload length
    m.seg(False, cappacket(CPT_FLAG, D_DLT, w))
    # payload length larger than the message
    m.seg(False, cappacket(CPT_FLAG, D_LEN | D_DLT, w, reported=500))
    # truncated messages
    # an empty string message
    m.seg(False, string('', 1))
    # a capture header with a payload length and a link type but no payload
    m.seg(False, cappacket(CPT_FLAG, D_LEN | D_DLT, b'', dlt=105))
    m.seg(False, pdu(HELLO, b'\0' * 10))
    m.seg(False, pdu(STRING, b'\0' * 3))
    m.seg(False, pdu(CAPPACKET, b'\0' * 4))
    m.seg(False, pdu(CAPPACKET, struct.pack('!II', CPT_FLAG | FCS_FLAG | RADIO_FLAG | GPS_FLAG, 0) + b'\0' * 10))
    m.seg(False, pdu(CHANNELSET, b'\0' * 40))
    m.seg(False, pdu(SOURCE, b'\0' * 20))
    m.seg(False, pdu(REPORT, b'\0' * 12))
    # a ridiculous number of channels (the data item is only 2046 octets)
    big = channelset([('c', 1, 1)])
    m.seg(False, big[:12 + 2 + 4 + 16 + 6] + b'\xff\xff' + big[12 + 2 + 4 + 16 + 8:])
    # sentinel, command and a length of 0xffffffff (never completes)
    m.seg(False, struct.pack('!III', SENTINEL, 1, 0xffffffff) + b'abc')
    pcap(os.path.join(out, 'kdsp-coverage-malformed.pcap'), m.out)


if __name__ == '__main__':
    main(sys.argv[1])
