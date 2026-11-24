#!/usr/bin/env python3
# Generates test/captures/gsm_cbch_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the GSM CBCH coverage captures.  Usage: mkgsm_cbch.py <outdir>
# Everything is synthetic (documentation addresses 192.0.2.0/24).
# CBCH blocks are carried in GSMTAP (UDP 4729, type 1 = Um, sub-type 0x0f
# = CBCH), which reaches the gsm_cbch dissector by default.
import os
import struct
import socket
import sys

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

def udp_frame(payload, sport=4729, dport=4729, src='192.0.2.1', dst='192.0.2.2'):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00' + ip + udp

def gsmtap(type_, sub_type, payload, arfcn=0, ts=0, fn=0):
    return struct.pack('!BBBBHbbIBBBB', 2, 4, type_, ts, arfcn, 0, 0, fn,
                       sub_type, 0, 0, 0) + payload

def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

class Cap:
    def __init__(self):
        self.frames = []
        self.fn = 0
    def block(self, octet, data22):
        assert len(data22) <= 22
        data22 = data22 + b'\x2b' * (22 - len(data22))
        self.frames.append(udp_frame(gsmtap(1, 0x0f, bytes([octet]) + data22, fn=self.fn)))
        self.fn += 51
    def raw(self, payload):
        self.frames.append(udp_frame(gsmtap(1, 0x0f, payload, fn=self.fn)))
        self.fn += 51
    def message(self, payload, sched=False, lpd=1):
        """Send payload (multiple of 22 octets) as blocks, last-block flag on the
        final one."""
        blocks = [payload[i:i + 22] for i in range(0, len(payload), 22)]
        for n, b in enumerate(blocks):
            seq = (0x08 if sched else 0) if n == 0 else n
            o = (lpd << 5) | seq | (0x10 if n == len(blocks) - 1 else 0)
            self.block(o, b)

def cb_page(serial, msgid, dcs, text):
    body = text.encode('ascii')
    # 7 bit packing is not needed for the coverage; any 82 octets will do
    body = body + b'\r' * (82 - len(body))
    return struct.pack('>HHBB', serial, msgid, dcs, 0x11) + body

def sched(begin, end, new, mdts, others=b'', length=88):
    """Schedule message: type/begin, spare/end, 6 octets bitmap of new
    slots (slot numbers 1..48), one MDT per new slot (bytes), others."""
    bm = bytearray(6)
    for s in new:
        s -= 1
        bm[s // 8] |= 0x80 >> (s % 8)
    p = bytes([begin, end]) + bytes(bm) + mdts + others
    p += b'\x40' * (length - len(p))
    p = p[:length]
    assert len(p) == length, len(p)
    return p

def build(outdir):
    clean = Cap()
    # 1: ordinary 4 block CB message, then a 2 block one (last block flag
    # on the second block) and a 1 block one
    clean.message(cb_page(0x1234, 0x0001, 0x0f, 'Test page one'))
    clean.message(cb_page(0x2234, 0x0002, 0x01, 'Test page two')[:44])
    clean.message(cb_page(0x3234, 0x0003, 0x11, 'Test page three')[:22])
    # 2: a scheduling message with every kind of new-slot descriptor
    #    slot1 MDT1 (msg 0x105), slot2 repeat of slot 1, slot3 repeat of
    #    non-existent slot 0, slot4 forward reference, slot5 free optional,
    #    slot6 free advised, slot7 MDT1; the other slots follow: slot 3 and
    #    4 (which the new-slot loop did not fill) and 8 and up
    mdts = bytes([0x81, 0x05, 0x01, 0x00, 0x07, 0x40, 0x41, 0xff, 0xff])
    others = bytes([0x88, 0x07,        # slot 3: MDT1 msg 0x0807
                    0x01,              # slot 4: repeat of slot 1
                    0x0f,              # slot 8: apparent forward reference
                    0x82, 0x01,        # slot 9: MDT1 msg 0x0201
                    0x02,              # slot 10: repeat of slot 2
                    0x41, 0x40])       # slot 11, 12: free slots
    clean.message(sched(1, 60, [1, 2, 3, 4, 5, 6, 7], mdts, others), sched=True)
    # 3: scheduling message in two blocks only (44 octets)
    clean.message(sched(2, 20, [3, 4], bytes([0x80, 0x10, 0x01]), bytes([0x40] * 20), length=44), sched=True)
    # 4: a scheduling message in one block that ends in an MDT 1 octet, so
    #    the second octet of the MDT is missing
    clean.message(sched(1, 40, [], b'', bytes([0x40] * 13 + [0x80]), length=22), sched=True)
    # 5: scheduling messages the dissector ignores: begin 0, begin 49 and
    #    a type field other than 0
    clean.message(sched(0, 5, [1], bytes([0x80, 0x01])), sched=True)
    clean.message(sched(49, 60, [1], bytes([0x80, 0x01])), sched=True)
    clean.message(sched(0x41, 5, [1], bytes([0x80, 0x01])), sched=True)
    # 6: fix reproducer: End Slot with the spare bits set (0xc5) must be
    #    treated like 5
    clean.message(sched(1, 0xc5, [1], bytes([0x80, 0x01], ), bytes([0x40] * 4)), sched=True)
    # 7: reassembly: blocks 1 and 2 of a message arrive twice (a repeated
    #    block is a retransmission), the first block last
    p = cb_page(0x4234, 0x0004, 0x0f, 'Out of order')
    blocks = [p[i:i + 22] for i in range(0, 88, 22)]
    clean.block(0x20 | 0x01, blocks[1])
    clean.block(0x20 | 0x02, blocks[2])
    clean.block(0x20 | 0x00, blocks[0])
    clean.block(0x20 | 0x03 | 0x10, blocks[3])
    # 8: second block of one message repeated before the first message ended
    clean.block(0x20 | 0x00, blocks[0])
    clean.block(0x20 | 0x01, blocks[1])
    clean.block(0x20 | 0x01, blocks[1])
    clean.block(0x20 | 0x02, blocks[2])
    clean.block(0x20 | 0x03 | 0x10, blocks[3])

    # 9: the NULL message and a reserved sequence number (expert notes)
    clean.block(0x20 | 0x0f, b'')
    clean.block(0x20 | 0x05, b'\x01\x02')

    bad = Cap()
    # NULL message (sequence number 0xf) and reserved sequence numbers
    bad.block(0x2f, b'')
    bad.block(0x24, b'\x01\x02')
    bad.block(0x2e, b'\x01\x02')
    # Link protocol discriminators other than 1
    bad.block(0x00, b'\xaa' * 22)
    bad.block(0x40, b'\xaa' * 22)
    bad.block(0x60, b'\xaa' * 22)
    # schedule: End Slot < Begin Slot (warning) and begin slot 0 / 49
    bad.message(sched(5, 3, [1], bytes([0x80, 0x01])), sched=True)
    bad.message(sched(10, 0xc2, [1], bytes([0x80, 0x01])), sched=True)
    # reserved MDT in the new slots (the dissector does not step over it)
    # and in the other slots
    bad.message(sched(1, 12, [1, 2], bytes([0x50, 0x50]), bytes([0x51])), sched=True)
    # Schedule with MDT octets running over the end of the message
    bad.message(sched(1, 48, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22], bytes([0x80] * 22), length=22), sched=True)
    bad.message(sched(1, 48, [1], b'\x80'), sched=True)
    # truncated blocks
    bad.raw(bytes([0x31]))
    bad.raw(bytes([0x30, 1, 2, 3]))
    bad.raw(bytes([0x28, 1, 2, 3]))
    # a block missing in the middle, then a block of another message
    bad.block(0x20 | 0x00, b'a' * 22)
    bad.block(0x20 | 0x02, b'b' * 22)
    bad.block(0x20 | 0x13, b'c' * 22)
    bad.block(0x20 | 0x00, b'a' * 22)
    bad.block(0x20 | 0x00 | 0x10, b'a' * 22)
    write_pcap(os.path.join(outdir, 'gsm_cbch-coverage.pcap'), clean.frames)
    write_pcap(os.path.join(outdir, 'gsm_cbch-coverage-malformed.pcap'), bad.frames)
    print(len(clean.frames), len(bad.frames))

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
