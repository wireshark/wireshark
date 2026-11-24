#!/usr/bin/env python3
# Generates test/captures/ms-mms_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MS-MMS coverage captures: mkms-mms.py <outdir> [-v]"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from k11lib import Conn, exported_pdu, pcapng_write, udp

TS, TC = 3, 4          # direction: to server, to client

def u16(s): return s.encode('utf-16-le')
def pad8(b): return b + b'\0' * ((8 - len(b) % 8) % 8)

def cmd(cid, direction, payload=b'', seq=0, proto=b'MMS ', sig=0xb00bface, l1=None, l2=None, exact=False):
    if not exact:
        payload = pad8(payload)
    P = len(payload)
    total = 40 + P
    l2 = (P + 8) // 8 if l2 is None else l2
    return (b'\x01\0\0\0' + struct.pack('<II', sig, total - 16 if l1 is None else l1) + proto +
            struct.pack('<I', l2) + struct.pack('<I', seq) + struct.pack('<d', seq * 0.5) +
            struct.pack('<I', l2) + struct.pack('<HH', cid, direction) + payload)

def dat(seq, ptype, flag, body=b'', length=None):
    n = 8 + len(body) if length is None else length
    return struct.pack('<IBBH', seq, ptype, flag, n) + body

def build():
    main, mal, notes = [], [], []
    def mark(t): notes.append((len(main) + 1, t))
    CIP, SIP = '192.0.2.1', '192.0.2.2'
    c = Conn(50000, 1755, isn_c=100, isn_s=900)
    main += c.syn()
    mark('commands to the server: connect info, transport info (UDP, TCP, other protocol, no match), file request, start, stop, cancel, header request, timing test, timer test, MBR selector, others')
    main.append(c.cs(cmd(0x01, TS, struct.pack('<III', 0, 0xf0f0ffff, 0) + u16('NSPlayer/9.0.0.2980; {abcd-1234}'), seq=0)))
    main.append(c.cs(cmd(0x02, TS, struct.pack('<IIIII', 0x00000001, 0x00040003, 0, 0, 0) + u16('\\\\192.0.2.1\\UDP\\5004'), seq=1)))
    main.append(c.cs(cmd(0x02, TS, struct.pack('<IIIII', 1, 0x00040003, 0, 0, 0) + u16('\\\\192.0.2.1\\TCP\\5005'), seq=2)))
    main.append(c.cs(cmd(0x02, TS, struct.pack('<IIIII', 1, 0x00040003, 0, 0, 0) + u16('\\\\192.0.2.1\\XYZ\\5006'), seq=3)))
    main.append(c.cs(cmd(0x02, TS, struct.pack('<IIIII', 1, 0x00040003, 0, 0, 0) + u16('no address here'), seq=4)))
    main.append(c.cs(cmd(0x02, TS, struct.pack('<IIIII', 1, 0x00040003, 0, 0, 0) + u16('\\\\192.0.2.1\\UDP\\5004'), seq=5)))  # again: conversation exists
    main.append(c.cs(cmd(0x05, TS, struct.pack('<IIII', 1, 0x00040003, 0, 0) + u16('\\media\\clip.wmv'), seq=6)))
    main.append(c.cs(cmd(0x07, TS, struct.pack('<II', 0x00000001, 0x00040003) + b'\0' * 40, seq=7)))
    main.append(c.cs(cmd(0x09, TS, struct.pack('<II', 1, 0x00040003), seq=8)))
    main.append(c.cs(cmd(0x0d, TS, struct.pack('<II', 1, 0x00040003), seq=9)))
    main.append(c.cs(cmd(0x15, TS, struct.pack('<II', 1, 0x00040003) + b'\0' * 32 + struct.pack('<I', 2), seq=10)))
    main.append(c.cs(cmd(0x18, TS, struct.pack('<II', 1, 0x00040003), seq=11)))
    main.append(c.cs(cmd(0x1b, TS, struct.pack('<II', 1, 0x00040003), seq=12)))
    main.append(c.cs(cmd(0x33, TS, struct.pack('<IHHH', 1, 0xffff, 1, 2), seq=13)))
    for i, cid in enumerate((0x03, 0x1a, 0x28, 0x30, 0x32, 0x99)):
        main.append(c.cs(cmd(cid, TS, b'\0' * 16, seq=14 + i)))
    mark('commands to the client: server info (error codes, strings), timing response, media details, header response, transport ack, others')
    for err in (0, 0xC00D001A, 0xC00D000E, 0x80070005, 0x12345678):
        main.append(c.sc(cmd(0x01, TC, struct.pack('<II', err, 0x00040003) + b'\0' * 32 +
                             struct.pack('<IIII', 10, 6, 9, 6) + u16('9.0.0.2980\0') + u16('Tool 1\0') + u16('http://x/\0') + u16('Basic\0'), seq=20)))
    main.append(c.sc(cmd(0x01, TC, struct.pack('<II', 0, 0x00040003) + b'\0' * 32 + struct.pack('<IIII', 1, 0, 1, 1) + u16('\0') + u16('\0') + u16('\0'), seq=21)))
    main.append(c.sc(cmd(0x15, TC, struct.pack('<IIIIII', 0, 0x00040003, 5, 0, 0, 0x42424242), seq=22)))
    for res, idx, live in ((1, 0, 1), (2, 0x80, 2), (3, 0, 0x42), (9, 0x55, 0x77)):
        main.append(c.sc(cmd(0x06, TC, struct.pack('<IIIII', 0, 0x00040003, res, 0, 0) + bytes([0, 0, idx, live]) +
                             struct.pack('<IIIIIIII', 0, 0, 120, 0, 0, 0, 0, 1024), seq=23)))
    main.append(c.sc(cmd(0x11, TC, struct.pack('<IIII', 0, 2, 0, 0), seq=24)))
    main.append(c.sc(cmd(0x02, TC, struct.pack('<III', 1, 0x00040003, 4) + u16('\\\\192.0.2.1\\UDP\\5004'), seq=25)))
    for i, cid in enumerate((0x03, 0x05, 0x0a, 0x1e, 0x20, 0x21, 0x99)):
        main.append(c.sc(cmd(cid, TC, b'\0' * 16, seq=26 + i)))
    main.append(c.sc(cmd(0x05, 7, b'\0' * 8, seq=40)))              # unknown direction
    main.append(c.sc(cmd(0x05, TC, b'\0' * 8, seq=41, proto=b'XYZ ')))   # protocol name is not MMS
    mark('commands split over TCP segments (cut in the length field, in the header, in the payload)')
    for first in (6, 10, 30, 50):
        m = cmd(0x01, TS, struct.pack('<III', 0, 0xf0f0ffff, 0) + u16('NSPlayer/9.0'), seq=50)
        main.append(c.cs(m[:first]))
        main.append(c.cs(m[first:]))
    main.append(c.cs(cmd(0x09, TS, struct.pack('<II', 1, 0x00040003), seq=51) + cmd(0x0d, TS, struct.pack('<II', 1, 0x00040003), seq=52)))
    mark('TCP data packets from the server: every flag value, desegmentation, rejected packets')
    for fl in (0x00, 0x04, 0x08, 0x0c, 0x10):
        main.append(c.sc(dat(1000 + fl, 0x44, fl, b'media data' * 4)))
    d = dat(2000, 0x44, 0x04, b'X' * 92)
    main.append(c.sc(d[:60]))
    main.append(c.sc(d[60:]))
    main.append(c.sc(dat(2001, 0x44, 0x0c, b'', length=7)))          # packet length < 8: rejected
    main.append(c.sc(dat(2002, 0x44, 0x55, b'zzzzzzzz')))            # unknown flag: rejected
    main.append(c.sc(b'abc'))                                        # too short
    mark('data on the conversations set up by the transport info: UDP 5004 and TCP 5005 to the client, UDP resend request to port 1755')
    main.append(udp(1755, 5004, dat(1, 0x44, 0x00, b'udp media' * 3), SIP, CIP))
    main.append(udp(1755, 5004, dat(2, 0x44, 0x05, b'udp media' * 3), SIP, CIP))
    main.append(udp(1755, 5004, dat(3, 0x44, 0x05, b'', length=7), SIP, CIP))
    cd = Conn(6000, 5005, src=SIP, dst=CIP, isn_c=300, isn_s=700)
    main.append(cd.cs(dat(7, 0x44, 0x0c, b'tcp media' * 3)))
    main.append(cd.cs(dat(8, 0x44, 0x04, b'tcp media' * 3)))
    main.append(udp(5004, 1755, struct.pack('<IIHH', 0xa0, 0x1234, 1, 0) + struct.pack('<III', 5, 6, 7), CIP, SIP))
    main.append(udp(5004, 1755, struct.pack('<IIHH', 0xa0, 0x1234, 1, 0), CIP, SIP))
    main.append(udp(5004, 1755, struct.pack('<IIHH', 0xa0, 0x1234, 1, 0) + b'\1\2', CIP, SIP))
    mark('Exported PDU msmms: a data packet in a 65,556 octet frame (the length found was truncated to 16 bits)')
    exp = []
    exp.append(exported_pdu('msmms', dat(77, 0x44, 0x00, b'\0' * 92, length=100) + b'\0' * 65456))
    exp.append(exported_pdu('msmms', dat(78, 0x44, 0x00, b'\0' * 92, length=100)))
    exp.append(exported_pdu('msmms', cmd(0x05, TC, b'\0' * 8, seq=79)))
    # ---- malformed
    cm = Conn(50001, 1755, isn_c=1100, isn_s=1900)
    mal += cm.syn()
    st = struct.pack('<II', 1, 0x00040003)
    for cid in (0x01, 0x02, 0x05, 0x07, 0x09, 0x0d, 0x15, 0x18, 0x1b, 0x33):
        mal.append(cm.cs(cmd(cid, TS, b'', seq=1, exact=True)))      # no command parameters at all
    for cid in (0x01, 0x15, 0x06, 0x11, 0x02):
        mal.append(cm.sc(cmd(cid, TC, b'', seq=2, exact=True)))
    mal.append(cm.cs(cmd(0x02, TS, st + b'\0' * 8, seq=3, exact=True)))     # string length underflows
    mal.append(cm.cs(cmd(0x01, TS, st, seq=3, exact=True)))
    mal.append(cm.cs(cmd(0x05, TS, st + b'\0' * 4, seq=3, exact=True)))
    mal.append(cm.sc(cmd(0x02, TC, st, seq=3, exact=True)))
    mal.append(cm.sc(cmd(0x01, TC, struct.pack('<II', 0, 0) + b'\0' * 32 + struct.pack('<IIII', 0x7fffffff, 1, 1, 1), seq=3)))
    mal.append(cm.sc(cmd(0x01, TC, struct.pack('<II', 0, 0) + b'\0' * 32 + struct.pack('<IIII', 2, 0x7fffffff, 1, 1) + u16('ab'), seq=3)))
    mal.append(cm.sc(cmd(0x01, TC, struct.pack('<II', 0, 0) + b'\0' * 32 + struct.pack('<IIII', 1, 1, 0x7fffffff, 1) + u16('ab'), seq=3)))
    mal.append(cm.sc(cmd(0x01, TC, struct.pack('<II', 0, 0) + b'\0' * 32 + struct.pack('<IIII', 1, 1, 1, 0x7fffffff) + u16('abc'), seq=3)))
    mal.append(cm.cs(cmd(0x01, TS, b'', seq=4, l1=0x7fffff)))             # length longer than the data
    mal.append(cm.cs(b'\x01\0\0\0' + struct.pack('<II', 0xb00bface, 0)))   # cut after the length: asks for more data
    mal.append(udp(1755, 5004, b'\x01\x02\x03', SIP, CIP))
    mal.append(udp(1755, 1755, b'short', SIP, CIP))
    # UDP data to the conversation port with a short body, and data with length > frame
    mal.append(udp(1755, 5004, dat(4, 0x44, 0, b'x' * 8, length=200), SIP, CIP))
    return main, exp, mal, notes

if __name__ == '__main__':
    out = sys.argv[1]
    main, exp, mal, notes = build()
    pcapng_write(os.path.join(out, 'ms-mms-coverage.pcapng'), [(1, main), (252, exp)])
    pcapng_write(os.path.join(out, 'ms-mms-coverage-malformed.pcapng'), [(1, mal)])
    if '-v' in sys.argv:
        print('main', len(main), '+ exp', len(exp), 'malformed', len(mal))
        for n, t in notes: print(n, t)
