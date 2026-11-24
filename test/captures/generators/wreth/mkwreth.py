#!/usr/bin/env python3
# Generates test/captures/wreth_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic WRETH (WSE remote ethernet, ethertype 0xAAAA) captures.
Usage: mkwreth.py <outdir>.  Everything is built with struct."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import w12pcap

def hdr(size, func, fid=0, err=0, frag=0, retry=0):
    return struct.pack('<HHHHHBB', 0x0002, size, func, fid, err, frag, retry)
# first two bytes on the wire are 02 00 (ntohs == 0x0200)
def pkt(func, payload=b'', size=None, fid=1, err=0, frag=0, retry=0):
    return hdr(len(payload) if size is None else size, func, fid, err, frag, retry) + payload
def frame(p):
    return w12pcap.eth(0xAAAA, p)

def mailbox(codef, status=0, nb=0, card=1, chan=2):
    return struct.pack('<HHHIHHHHHHHHHIHHIHIH', codef, status & 0xffff, 0x1234, 0x11223344,
        1, 50, 2, 3, card, chan, 4, nb, 5, 0x0000A000, 6, 128, 0x55667788, 2, 0xdeadbeef, 0)
def mail(codef, status=0, data=b'', nb=None, frag=0, dest=7, **kw):
    nb = len(data) if nb is None else nb
    body = struct.pack('<HI', dest, 0) + mailbox(codef, status, nb, **kw) + data
    return pkt(6, body, frag=frag)
def master_info():
    return struct.pack('<BBBB', 2, 1, 3, 1) + b'WSE_PROTOCOL\0\0\0\0' + struct.pack('<BHH', 8, 1, 250)
def equip_info():
    d = struct.pack('<BBBBBBHH', 1, 0, 2, 3, 4, 5, 100, 200) + bytes(10)
    d += struct.pack('<HHH', 11, 12, 13) + bytes(4)
    d += b'DLLITEM\0\0\0\0\0\0\0'[:14] + b'EQUIPMENT_NAME\0\0'
    d += bytes(2)
    d += b''.join(struct.pack('<H', 100 + i) for i in range(45))
    return d

def main_frames():
    f = []
    f.append(pkt(1))                                   # ident question
    f.append(pkt(1, b'1.2.3\0' + struct.pack('<HHHB', 1000, 2, 0x4321, 0) + b'\x02\x00\x00\x00\x00\x09', fid=2))
    f.append(pkt(1, b'1.2.3\0' + struct.pack('<HHHB', 1000, 2, 0x4321, 1) + b'\x02\x00\x00\x00\x00\x09', fid=3))
    f.append(pkt(2, struct.pack('<HH', 2, 30)))        # connect
    f.append(pkt(3))                                   # ack
    for code in range(0, 11):                          # nack with each error code and size 0
        f.append(pkt(4, err=code))
    for code in (1, 5, 9, 77):
        f.append(pkt(4, b'\x02\x00\x00\x00\x00\x09', err=code))
    f.append(pkt(5))                                   # disconnect
    f.append(pkt(7, struct.pack('<H', 500)))           # blinky
    f.append(pkt(8))                                   # get value question
    f.append(pkt(8, b'\x05'))                          # get value response
    f.append(pkt(9, b'\x01', size=0))                  # set value
    f.append(pkt(10, struct.pack('<H', 1)))            # boost
    f.append(pkt(10, struct.pack('<H', 0)))
    f.append(pkt(99))                                  # unknown function code, no handler
    # Mail
    f.append(mail(0x1002, 0, master_info()))
    f.append(mail(0x1079, 1, equip_info()))
    f.append(mail(0x0106, 2, b'\x01\x02\x03\x04'))      # default data
    f.append(mail(0x9601, 3, b''))                     # nb == 0, no data
    f.append(mail(0xB001, 40, b'\0' * 8, nb=8))
    f.append(mail(0xC000, 10, b'\0' * 4))
    f.append(mail(0xA001, -11, b'\0' * 4))             # negative status
    f.append(mail(0x4242, 0x33, b'x' * 4))             # unknown codef, unknown status
    f.append(mail(0x1002, 0, master_info(), frag=1))   # first fragment
    # second fragment: only continuation data after retry byte
    f.append(pkt(6, b'\0' * 20 + b'tail', frag=2, retry=1))
    f.append(pkt(6, b'\x01\x02', frag=2))
    # Repeats with a retry flag
    f.append(pkt(8, b'\x01', retry=3))
    # Frames whose size field does not fit the function: the dissector
    # only reports them in the Info column (they are not malformed)
    f.append(hdr(0, 3, frag=3) + bytes(4))                 # invalid fragmented byte
    for func, size in ((1, 5), (2, 3), (3, 1), (4, 2), (5, 1), (7, 4), (8, 9), (10, 3)):
        f.append(pkt(func, bytes(max(size, 4)), size=size))
    f.append(pkt(9, b'\x01', size=3))                      # invalid set value size
    return [frame(x) for x in f]

def malformed_frames():
    f = []
    # not the WRETH subtype: dissector returns without decoding
    f.append(frame(b'\x03\x00' + bytes(14)))
    f.append(frame(pkt(1, b'ab', size=19)))                # truncated ident response
    f.append(frame(pkt(6, b'\0' * 10)))                    # truncated mail
    f.append(frame(pkt(6, b'\0' * 30)))                    # truncated mail header
    f.append(frame(pkt(2, b'\x02', size=4)))               # truncated connect
    f.append(frame(b'\x02\x00'))                           # truncated header
    f.append(frame(b'\x02\x00\x00\x00\x03\x00\x01\x00\x00\x00\x00\x00'))  # only 12 bytes: ack fine
    f.append(frame(pkt(4, b'\x01\x02', size=6)))           # nack, short MAC
    f.append(frame(pkt(6, mailbox(0x1002, 0, 5)[:40] )))
    # master info truncated
    f.append(frame(pkt(6, struct.pack('<HI', 7, 0) + mailbox(0x1002, 0, 5) + b'\x01\x02\x03')))
    f.append(frame(pkt(6, struct.pack('<HI', 7, 0) + mailbox(0x1079, 0, 5) + b'\x01\x02\x03')))
    return f

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    mf = main_frames()
    w12pcap.write(os.path.join(out, 'wreth-coverage.pcap'), mf)
    w12pcap.write(os.path.join(out, 'wreth-coverage-malformed.pcap'), malformed_frames())
    print(len(mf), 'main frames,', len(malformed_frames()), 'malformed frames')
