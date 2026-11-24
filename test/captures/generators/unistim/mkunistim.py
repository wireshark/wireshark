#!/usr/bin/env python3
# Generates test/captures/unistim_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the UNISTIM coverage captures.

Usage: mkunistim.py <outdir> [-v]

UNISTIM has no port or heuristic registration, so it is reached with
Decode As (udp.port 5000, "unistim"); the captures use UDP 5000 <-> 5001
(and 5000 <-> 5002 for the phone-to-switch direction).  Writes
unistim-coverage.pcap and unistim-coverage-malformed.pcap.

unistim_table.txt lists "address command length variant packable" for every
manager command: the (length, variant) pairs for which the message
decodes with exactly one message and no error.  It was found with
search.py/select.py by trying lengths 0-48 of four kinds of bodies
(random, 00/ff/55/aa, text, small values) with tshark; the bodies are
regenerated here with unistimlib.body().
"""
import os
import struct
import sys
from unistimlib import frame, MANAGERS, message, payload, write_pcap

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH = {0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x11, 0x16, 0x17, 0x19, 0x1a, 0x1e}
NAMES = {0x09: 'expansion module', 0x11: 'broadcast', 0x16: 'audio', 0x17: 'display',
         0x19: 'key/indicator', 0x1a: 'basic', 0x1e: 'network'}


def table():
    rows = []
    for l in open(os.path.join(HERE, 'unistim_table.txt')):
        a, c, L, v, p = map(int, l.split())
        rows.append((a, c, L, v, p))
    return rows


def build():
    fr, ranges = [], []
    seq = [1]

    def add(label, pkts):
        s = len(fr) + 1
        fr.extend(pkts)
        ranges.append((label, s, len(fr)))

    def sw(msgs, pay=1, rtype=2):
        # from the switch (NI) to the phone
        seq[0] += 1
        return frame(payload(msgs, seq[0], pay), 5000, 5001)

    def ph(msgs, termid=0xc0000201):
        # from the phone (IT) to the switch, always with the terminal ID
        seq[0] += 1
        return frame(payload(msgs, seq[0], 2, termid), 5001, 5000, src=(192, 0, 2, 20), dst=(192, 0, 2, 10))

    rows = table()
    # 1. every manager command, one message per frame is not needed: the
    # messages of one manager are packed into frames of up to ~1200 octets
    groups, solo = {}, {}
    for a, c, L, v, p in rows:
        (groups if p else solo).setdefault(a, []).append(message(a, c, L, v))
    for a in sorted(set(groups) | set(solo)):
        name = NAMES.get(a & 0x7f if a & 0x80 else a, NAMES.get(a, 'expansion module'))
        phone = a >= 0x80
        pk, cur = [], []
        n = 0
        for m in groups.get(a, []):
            if n + len(m) > 1200:
                pk.append(cur); cur, n = [], 0
            cur.append(m); n += len(m)
        if cur:
            pk.append(cur)
        pk.extend([x] for x in solo.get(a, []))    # these read to the end of the packet
        add('%s manager %s (0x%02x): every command' % (name, 'phone' if phone else 'switch', a),
            [ph(x) if phone else sw(x) for x in pk])
    return fr, ranges, seq, sw, ph, add


def build_all():
    fr, ranges, seq, sw, ph, add = build()
    m = message
    # 2. expansion modules 2-6 (the same handler, other command addresses)
    exp = [r for r in table() if r[0] == 0x09 and r[4]]
    add('expansion module 2-6 manager switch/phone addresses',
        [sw([message(0x0a + i, c, L, v) for (a, c, L, v, p) in exp[:6]]) for i in range(5)] +
        [ph([message(0x8a + i, c, L, v) for (a, c, L, v, p) in [r for r in table() if r[0] == 0x89 and r[4]][:4]]) for i in range(5)])
    # 3. RUDP types, payload types, sequence numbers
    add('RUDP ACK and NAK (padded to 6 octets), NULL, free form and unknown payload types, reset sequence number',
        [frame(struct.pack('!IBB', 0x10, 1, 0), 5000, 5001), frame(struct.pack('!IBB', 0x11, 0, 0), 5001, 5000),
         frame(struct.pack('!IBB', 0x12, 2, 0), 5000, 5001), frame(struct.pack('!IBB', 0xffffffff, 2, 0xff), 5000, 5001),
         frame(struct.pack('!IBB', 0xffffffff, 2, 1), 5000, 5001),
         frame(struct.pack('!IBB', 1, 2, 0x55), 5000, 5001),     # unknown payload: not UNISTIM
         frame(struct.pack('!IBB', 1, 7, 0), 5000, 5001)])           # unknown RUDP type: not UNISTIM
    # 4. UFTP
    add('UFTP: connection request/details/granted/denied, flow control, data block, unknown command',
        [frame(struct.pack('!IBB', 20 + i, 2, 3) + b, 5000, 5001) for i, b in enumerate([
            b'\x80', b'\x81' + struct.pack('!HB', 512, 4) + b'firmware.bin', b'\x00', b'\x01', b'\x82',
            b'\x02' + bytes(range(64)), b'\x03'])])
    # 5. messages: length 3 in a payload with terminal ID, unknown manager address, several messages
    ms = [m(0x16, 0x30, 19, 0), m(0x17, 0x1f, 4, 2), m(0x1a, 0x07, 4, 1), m(0x19, 0x06, 2, 1)]
    add('several messages in one payload, with and without terminal ID, unknown manager addresses',
        [sw(ms), ph([m(0x9a, 0x0b, 4, 1), m(0x99, 0x01, 1, 0), m(0x96, 0x07, 3, 1)]),
         sw([bytes([0x20, 5, 1, 2, 3]), bytes([0x77, 3, 9])]),
         sw([bytes([0x20, 4, 0xaa, 0xbb])], pay=1)])
    # 6. open audio stream with the far end: RTP and RTCP conversations; key presses
    def open_stream(far=True, ip=(192, 0, 2, 30), rtp=6000, rtcp=6001):
        b = bytes([1, 2, 0x0d, 0x0d, 20, 0xb8, 3]) + b'\0\0\0\0' + struct.pack('!HHHH', 5004, 5005, rtp, rtcp)
        if far:
            b += bytes(ip)
        return bytes([0x16, 3 + len(b), 0x30]) + b
    add('Open Audio Stream with and without a far end address (RTP/RTCP conversations)',
        [sw([open_stream(True)]), sw([open_stream(False)]),
         sw([open_stream(True, (192, 0, 2, 31), 7000, 7001)])])
    # RTP and RTCP in the conversations set up above
    def rtp(seqn, ssrc=0x11223344):
        return struct.pack('!BBHII', 0x80, 0, seqn, seqn * 160, ssrc) + bytes([0xff] * 160)
    rtcp = struct.pack('!BBHI', 0x80, 201, 1, 0x11223344)
    add('RTP and RTCP to the far end of the first stream (decoded through the UNISTIM conversation)',
        [frame(rtp(i), 5004, 6000, dst=(192, 0, 2, 30)) for i in range(3)] +
        [frame(rtcp, 5005, 6001, dst=(192, 0, 2, 30))])
    # 7. key presses and hook state of the phone (tap info), long key sequence
    keys = [m(0x99, 0x00, 1, 0)]
    keypress = lambda k, st: bytes([0x99, 4, 0x00, (st << 6) | k])
    add('phone key presses and hook switches',
        [ph([keypress(k, 1) for k in range(10)] + [keypress(k, 2) for k in range(10)]),
         ph([bytes([0x96, 3, 0x00]), bytes([0x96, 3, 0x01])]),
         ph([bytes([0x99, 3, 0x03])])])
    # 8. fix reproducers: UNISTIM payload type 1 and 2 with tap info (address copies, VoIP Calls tap),
    # query network configuration element, short payloads
    add('the fixed leak paths (payload type 1 and 2 with messages, 1000 packets worth are in the review reproducer)',
        [sw([open_stream(False)]) for _ in range(8)] + [ph([m(0x9a, 0x0b, 4, 1)], termid=0xc0000200 + i) for i in range(8)])
    add('Query Network Configuration Element (element field at the element octet, fix)',
        [sw([bytes([0x1e, 4, 0x0d, e]) for e in range(0, 16)])])
    return fr, ranges


def build_malformed():
    fr = []
    m = message
    # length 0-2 in a message: error expert info
    for L in (0, 1, 2):
        fr.append(frame(payload([bytes([0x16, L, 0x30])]), 5000, 5001))
    # message declared longer than the packet, cut in the middle of fields
    for a, c, L in ((0x16, 0x30, 19), (0x17, 0x1f, 8), (0x1e, 0x0e, 30), (0x1a, 0x07, 9), (0x99, 0x00, 1)):
        full = m(a, c, L, 1)
        for cut in (3, 5, len(full) - 1):
            fr.append(frame(payload([full[:cut]]), 5000, 5001))
    # messages whose length is shorter than the data decoded
    fr.append(frame(payload([bytes([0x16, 4, 0x30, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20])]), 5000, 5001))
    fr.append(frame(payload([bytes([0x00, 3, 0x30])]), 5000, 5001))     # address 0 consumes nothing
    # a 5 octet ACK/NAK (sequence number and type only, what a real RUDP
    # ACK looks like) is rejected by the length check of the fix; it is shown as UDP data
    fr.append(frame(struct.pack('!IB', 0x10, 1), 5000, 5001))
    fr.append(frame(struct.pack('!IB', 0x11, 0), 5000, 5001))
    # too short for the RUDP check, UFTP truncated
    fr.append(frame(b'\0\0\0\1\2', 5000, 5001))
    fr.append(frame(struct.pack('!IBB', 1, 2, 3) + b'\x81\x02', 5000, 5001))
    fr.append(frame(payload([bytes([0x16, 0x20, 0x30, 1, 2])], pay=2, termid=1)[:11], 5000, 5001))
    # candidates the search rejected: every manager command with a body that
    # is too short or too long for its fields
    from unistimlib import commands
    cmds = commands()
    for fn, addrs in MANAGERS.items():
        for c in cmds[fn]:
            for L in (0, 1, 7):
                fr.append(frame(payload([message(addrs[0], c, L, 3)]), 5000, 5001))
            fr.append(frame(payload([message(addrs[0], c, 2, 1) + message(addrs[0], c, 40, 0)]), 5000, 5001))
    return fr


if __name__ == '__main__':
    out = sys.argv[1]
    frames, ranges = build_all()
    write_pcap(os.path.join(out, 'unistim-coverage.pcap'), frames)
    write_pcap(os.path.join(out, 'unistim-coverage-malformed.pcap'), build_malformed())
    if '-v' in sys.argv:
        for l, a, b in ranges:
            print('%d-%d: %s' % (a, b, l))
        print('total', len(frames))
