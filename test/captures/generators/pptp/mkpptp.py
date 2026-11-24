#!/usr/bin/env python3
# Generates test/captures/pptp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the PPTP coverage captures. Usage: mkpptp.py <outdir> [-v].
Synthetic data only (addresses from 192.0.2.0/24)."""
import struct
import sys

MAGIC = 0x1A2B3C4D


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(map(int, a.split('.')))


class Flow:
    """One TCP connection to port 1723 with sequence tracking."""
    def __init__(self, cli, srv, cport=40000, sport=1723):
        self.cli, self.srv, self.cport, self.sport = cli, srv, cport, sport
        self.seq = {0: 1000, 1: 5000}

    def frame(self, d, payload, flags=0x18):
        src, dst = (self.cli, self.srv) if d == 0 else (self.srv, self.cli)
        sp, dp = (self.cport, self.sport) if d == 0 else (self.sport, self.cport)
        seq, ack = self.seq[d], self.seq[1 - d]
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 5 << 4, flags, 8192, 0, 0)
        pseudo = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        c = csum(pseudo + tcp + payload)
        tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
        seg = tcp + payload
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(seg), 0, 0, 64, 6, 0, ip4(src), ip4(dst))
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        eth = (b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' if d == 0
               else b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02') + b'\x08\x00'
        self.seq[d] = (seq + len(payload) + (1 if flags & 3 else 0)) & 0xffffffff
        return eth + ip + seg


def s64(s):
    return s.encode() + b'\0' * (64 - len(s))


def hdr(mtype, body, length=None, cookie=MAGIC, msgtype=1):
    n = 12 + len(body) if length is None else length
    return struct.pack('!HHIHH', n, msgtype, cookie, mtype, 0) + body


def cntrl(ver=0x0100, res=0, err=0, fr=3, br=3, ch=16, fw=0x0401, host='pac.example', vendor='Example Vendor'):
    return struct.pack('!HBBIIHH', ver, res, err, fr, br, ch, fw) + s64(host) + s64(vendor)


def cntrl_req(ver=0x0100, fr=3, br=3, ch=16, fw=0x0401, host='pns.example', vendor='Example Vendor'):
    return struct.pack('!HHIIHH', ver, 0, fr, br, ch, fw) + s64(host) + s64(vendor)


def out_req(cid=1, ser=7, minb=300, maxb=100000000, br=2, fr=2, win=64, dly=0, plen=11,
            phone='5551234567', sub=''):
    return struct.pack('!HHIIIIHHHH', cid, ser, minb, maxb, br, fr, win, dly, plen, 0) + s64(phone) + s64(sub)


def out_reply(cid=2, peer=1, res=1, err=0, cause=0, spd=56000, win=32, dly=1, chan=3):
    return struct.pack('!HHBBHIHHI', cid, peer, res, err, cause, spd, win, dly, chan)


def in_req(cid=3, ser=9, br=1, chan=2, dedl=7, dingl=7, dialed='5550000', dialing='5559999', sub='x'):
    return struct.pack('!HHIIHH', cid, ser, br, chan, dedl, dingl) + s64(dialed) + s64(dialing) + s64(sub)


def in_reply(cid=4, peer=3, res=1, err=0, win=16, dly=2):
    return struct.pack('!HHBBHHH', cid, peer, res, err, win, dly, 0)


def in_conn(peer=4, spd=64000, win=16, dly=2, fr=1):
    return struct.pack('!HHIHHI', peer, 0, spd, win, dly, fr)


def build():
    frames = []
    marks = []

    def note(label):
        marks.append((len(frames) + 1, label))

    cli, srv = '192.0.2.1', '192.0.2.2'
    f = Flow(cli, srv)
    frames.append(f.frame(0, b'', 0x02))
    frames.append(f.frame(1, b'', 0x12))
    frames.append(f.frame(0, b'', 0x10))
    note('connection and Start-Control-Connection exchange')
    frames.append(f.frame(0, hdr(1, cntrl_req())))
    frames.append(f.frame(1, hdr(2, cntrl(res=1))))
    note('Echo and Outgoing/Incoming call setup')
    frames.append(f.frame(0, hdr(5, struct.pack('!I', 0x01020304))))
    frames.append(f.frame(1, hdr(6, struct.pack('!IBBH', 0x01020304, 1, 0, 0))))
    frames.append(f.frame(0, hdr(7, out_req())))
    frames.append(f.frame(1, hdr(8, out_reply())))
    frames.append(f.frame(1, hdr(9, in_req())))
    frames.append(f.frame(0, hdr(10, in_reply())))
    frames.append(f.frame(1, hdr(11, in_conn())))
    note('Set-Link-Info, WAN-Error-Notify, Call-Clear, Disconnect-Notify')
    frames.append(f.frame(0, hdr(15, struct.pack('!HHII', 2, 0, 0xffffffff, 0x000a0000))))
    frames.append(f.frame(1, hdr(14, struct.pack('!HHIIIIII', 2, 0, 1, 2, 3, 4, 5, 6)[:4 + 24])))
    frames.append(f.frame(0, hdr(12, struct.pack('!HH', 1, 0))))
    frames.append(f.frame(1, hdr(13, struct.pack('!HBBHH', 2, 3, 0, 5, 0) + s64('stats: 12 frames'))))
    note('Stop-Control-Connection')
    frames.append(f.frame(0, hdr(3, struct.pack('!BBH', 3, 0, 0))))
    frames.append(f.frame(1, hdr(4, struct.pack('!BBH', 1, 0, 0))))
    frames.append(f.frame(0, b'', 0x11))
    frames.append(f.frame(1, b'', 0x11))
    frames.append(f.frame(0, b'', 0x10))

    # Every value string of the result, error, reason and framing fields,
    # on a second connection so that the first one stays plain.
    g = Flow(cli, srv, cport=40001)
    note('second connection: every result, error, reason, framing and bearer value')
    frames.append(g.frame(0, b'', 0x02))
    frames.append(g.frame(1, b'', 0x12))
    frames.append(g.frame(0, b'', 0x10))
    for res in (1, 2, 3, 4, 5, 9):
        for fr, br in ((1, 1), (2, 2), (3, 3), (0, 0)):
            frames.append(g.frame(1, hdr(2, cntrl(res=res, err=res % 7, fr=fr, br=br, ver=0x0100 if res < 5 else 0x0200))))
    for r in (1, 2, 3, 4, 9):
        frames.append(g.frame(0, hdr(3, struct.pack('!BBH', r, 0, 0))))
    for r in (1, 2, 9):
        frames.append(g.frame(1, hdr(4, struct.pack('!BBH', r, r % 7, 0))))
    for r in (1, 2, 9):
        frames.append(g.frame(1, hdr(6, struct.pack('!IBBH', 77, r, r, 0))))
    for r in range(1, 9):
        frames.append(g.frame(1, hdr(8, out_reply(res=r, err=r % 8, cause=r))))
    for r in (1, 2, 3, 4):
        frames.append(g.frame(0, hdr(10, in_reply(res=r, err=r))))
    for r in (1, 2, 3, 4, 5, 8):
        frames.append(g.frame(0, hdr(13, struct.pack('!HBBHH', 7, r, r, r, 0) + s64('call %d' % r))))
    for e in range(0, 8):
        frames.append(g.frame(0, hdr(2, cntrl(res=1, err=e))))
    for br in (1, 2, 3, 4):
        for fr in (1, 2, 3, 4):
            frames.append(g.frame(0, hdr(7, out_req(br=br, fr=fr, cid=br * 10 + fr))))
    note('long strings filling the 64 octet fields, non-ASCII bytes')
    frames.append(g.frame(0, hdr(1, cntrl_req(host='h' * 64, vendor='v' * 64))))
    frames.append(g.frame(0, hdr(7, out_req(phone='9' * 64, sub='s' * 64, plen=64))))
    frames.append(g.frame(0, hdr(9, in_req(dialed='d' * 64, dialing='n' * 64, sub='s' * 64, dedl=64, dingl=64))))
    frames.append(g.frame(1, hdr(13, struct.pack('!HBBHH', 7, 1, 0, 0, 0) + b'\xe4\xf6\xfc' + b'a' * 61)))
    note('incorrect magic cookie, unknown control message types, management message type')
    frames.append(g.frame(0, hdr(5, struct.pack('!I', 5), cookie=0xdeadbeef)))
    frames.append(g.frame(0, hdr(5, struct.pack('!I', 6), cookie=0)))
    frames.append(g.frame(0, hdr(0, b'\0' * 8)))
    frames.append(g.frame(0, hdr(16, b'\x01\x02\x03\x04\x05\x06\x07\x08')))
    frames.append(g.frame(0, hdr(200, b'\0' * 4, msgtype=2)))
    frames.append(g.frame(0, hdr(5, struct.pack('!I', 9), msgtype=2)))
    frames.append(g.frame(0, hdr(5, struct.pack('!I', 9), msgtype=7)))
    note('length field that is not the message length')
    frames.append(g.frame(0, hdr(5, struct.pack('!I', 9), length=40)))
    frames.append(g.frame(0, hdr(5, struct.pack('!I', 9), length=2)))
    frames.append(g.frame(0, hdr(12, struct.pack('!HH', 1, 0)) + b'trailing'))
    # Segments from the same direction retransmitted and a second message
    # in the same segment (the dissector shows the first one only).
    note('two messages in one segment')
    frames.append(g.frame(0, hdr(5, struct.pack('!I', 11)) + hdr(5, struct.pack('!I', 12))))
    return frames, marks


def build_malformed():
    frames = []
    f = Flow('192.0.2.3', '192.0.2.4', cport=41000)
    frames.append(f.frame(0, b'\x00\x10'))                        # cut in the header
    frames.append(f.frame(0, struct.pack('!HHIH', 12, 1, MAGIC, 1)))  # cut before the reserved field
    frames.append(f.frame(0, struct.pack('!HHI', 12, 1, MAGIC)))      # cut before the control type
    for t in range(1, 16):
        full = {1: cntrl_req(), 2: cntrl(), 3: struct.pack('!BBH', 1, 0, 0), 4: struct.pack('!BBH', 1, 0, 0),
                5: struct.pack('!I', 1), 6: struct.pack('!IBBH', 1, 1, 0, 0), 7: out_req(), 8: out_reply(),
                9: in_req(), 10: in_reply(), 11: in_conn(), 12: struct.pack('!HH', 1, 0),
                13: struct.pack('!HBBHH', 1, 1, 0, 0, 0) + s64('x'), 14: struct.pack('!HHIIIIII', 1, 0, 1, 2, 3, 4, 5, 6),
                15: struct.pack('!HHII', 1, 0, 1, 2)}[t]
        # cut each message type in the middle of its body
        frames.append(f.frame(0, hdr(t, full[:max(1, len(full) // 2)])))
        # and one octet short
        frames.append(f.frame(0, hdr(t, full[:-1])))
    return frames


def write_pcap(name, frames):
    with open(name, 'wb') as fh:
        fh.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            fh.write(struct.pack('<IIII', i, 0, len(fr), len(fr)))
            fh.write(fr)


if __name__ == '__main__':
    out = sys.argv[1]
    frames, marks = build()
    write_pcap(out + '/pptp-coverage.pcap', frames)
    write_pcap(out + '/pptp-coverage-malformed.pcap', build_malformed())
    if '-v' in sys.argv:
        for n, l in marks:
            print(n, l)
        print(len(frames), 'frames')
