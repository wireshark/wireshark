#!/usr/bin/env python3
# AppleMIDI coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""AppleMIDI (packet-applemidi.c) and its hand-off to RTP-MIDI.

Usage: mkapplemidi.py [<output directory>]

Writes:
  applemidi-coverage.pcap            every command, control and data
                                     ports, RTP-MIDI after the session
                                     set-up, the heuristic's rejections,
                                     and further cases that decode cleanly
  applemidi-coverage-malformed.pcap  truncated packets (exceptions)

The heuristic is disabled by default: dissect with
--enable-heuristic applemidi_udp.

Every packet is built here; nothing comes from a real network. Hosts use
documentation addresses (192.0.2.0/24, 2001:db8::/32) and locally
administered MAC addresses.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from capgen import eth, ip4, ipv4, ipv6, udp, write_pcap  # noqa: E402

MAC1 = bytes.fromhex('020000000001')
MAC2 = bytes.fromhex('020000000002')


def ip6(last):
    return bytes.fromhex('20010db8') + b'\0' * 11 + bytes([last])


class Pcap:
    def __init__(self):
        self.frames = []
        self.notes = []

    def note(self, text):
        self.notes.append((len(self.frames) + 1, text))

    def udp(self, src, dst, sport, dport, payload):
        """src/dst: dotted IPv4 strings or IPv6 byte strings (16 octets)."""
        seg = udp(payload, sport, dport, src=src, dst=dst)
        if isinstance(src, str):
            ip = ipv4(seg, 17, src=src, dst=dst, ident=len(self.frames) & 0xffff)
            etype = 0x0800
            s, d = ip4(src), ip4(dst)
        else:
            ip = ipv6(seg, 17, src=src, dst=dst)
            etype = 0x86dd
            s, d = src, dst
        # MAC follows the address so each host keeps its MAC
        smac, dmac = (MAC1, MAC2) if s < d else (MAC2, MAC1)
        self.frames.append(eth(ip, etype, dst=dmac, src=smac))

    def write(self, path):
        write_pcap(path, self.frames, ts=lambda i: (1700000000 + i // 10, (i % 10) * 100000))


# ---------------------------------------------------------------------------
# AppleMIDI

def am(cmd, body=b''):
    return b'\xff\xff' + cmd + body


def session(cmd, token, ssrc, name=None, version=2):
    body = struct.pack('!III', version, token, ssrc)
    if name is not None:
        body += name
    return am(cmd, body)


def ck(ssrc, count, ts=(0, 0, 0), extra=b''):
    return am(b'CK', struct.pack('!IB3sQQQ', ssrc, count, b'\0\0\0', *ts) + extra)


def rs(ssrc, seq, extra=b''):
    return am(b'RS', struct.pack('!II', ssrc, seq) + extra)


def rl(ssrc, limit, extra=b''):
    return am(b'RL', struct.pack('!II', ssrc, limit) + extra)


# ---------------------------------------------------------------------------
# RTP-MIDI (RFC 6295)

def rtp(seq, ts, ssrc, payload, pt=97, marker=0):
    return struct.pack('!BBHII', 0x80, (marker << 7) | pt, seq, ts, ssrc) + payload


def cmdsec(cmds, journal=None, z=False, p=False):
    """cmds: the command list as bytes (delta times already included)."""
    flags = (0x40 if journal is not None else 0) | (0x20 if z else 0) | (0x10 if p else 0)
    if len(cmds) <= 15:
        hdr = bytes([flags | len(cmds)])
    else:
        hdr = struct.pack('!H', 0x8000 | (flags << 8) | len(cmds))
    return hdr + cmds + (journal or b'')


def chan_journal(chan, chapters):
    """chapters: dict letter -> bytes, in the order P C M W N E T A."""
    order = 'PCMWNETA'
    toc = 0
    body = b''
    for i, letter in enumerate(order):
        if letter in chapters:
            toc |= 0x80 >> i
            body += chapters[letter]
    length = 3 + len(body)
    hdr = (chan << 19) | (length << 8) | toc
    return struct.pack('!I', hdr)[1:] + body


def sys_journal(chapters):
    """chapters: dict letter -> bytes, in the order D V Q F X."""
    order = 'DVQFX'
    toc = 0
    body = b''
    for i, letter in enumerate(order):
        if letter in chapters:
            toc |= 0x4000 >> i
            body += chapters[letter]
    return struct.pack('!H', toc | (2 + len(body))) + body


def journal(checkpoint, sysj=None, chans=(), single=False):
    flags = (0x80 if single else 0) | (0x40 if sysj else 0) | (0x20 if chans else 0)
    flags |= max(len(chans) - 1, 0)
    return bytes([flags]) + struct.pack('!H', checkpoint) + (sysj or b'') + b''.join(chans)


def main(outdir):
    cap = Pcap()
    bad = Pcap()

    A, B, C = '192.0.2.1', '192.0.2.2', '192.0.2.3'
    SA, SB = 0xaabbccdd, 0x11223344
    TOK = 0x5eed0001

    # ---- Session 1: IPv4, control port 5004, data port 5005 ------------
    cap.note('session 1 (IPv4): IN/OK on the control port 5004')
    cap.udp(A, B, 5004, 5004, session(b'IN', TOK, SA, b'Alice MacBook\0'))
    cap.udp(B, A, 5004, 5004, session(b'OK', TOK, SB, b"Bob's Studio\0"))
    cap.note('session 1: IN/OK on the data port 5005')
    cap.udp(A, B, 5005, 5005, session(b'IN', TOK, SA, b'Alice MacBook\0'))
    cap.udp(B, A, 5005, 5005, session(b'OK', TOK, SB, b"Bob's Studio\0"))
    cap.note('session 1: CK with count 0, 1, 2 on the data port')
    cap.udp(A, B, 5005, 5005, ck(SA, 0, (0x1000, 0, 0)))
    cap.udp(B, A, 5005, 5005, ck(SB, 1, (0x1000, 0x1100, 0)))
    cap.udp(A, B, 5005, 5005, ck(SA, 2, (0x1000, 0x1100, 0x1180)))

    cap.note('session 1: RTP-MIDI on the data port, both directions')
    seq_a, seq_b = 1, 100
    ts = 1000

    def midi_a(payload, marker=0):
        nonlocal seq_a, ts
        cap.udp(A, B, 5005, 5005, rtp(seq_a, ts, SA, payload, marker=marker))
        seq_a += 1
        ts += 50

    def midi_b(payload):
        nonlocal seq_b, ts
        cap.udp(B, A, 5005, 5005, rtp(seq_b, ts, SB, payload))
        seq_b += 1
        ts += 50

    # Note On, short header
    midi_a(cmdsec(bytes([0x90, 0x3c, 0x40])), marker=1)
    # Note Off, then a running status Note Off after a delta time
    midi_a(cmdsec(bytes([0x80, 0x3c, 0x00, 0x05, 0x3e, 0x00])))
    # Note On with velocity 0, Poly aftertouch, Control Change
    midi_a(cmdsec(bytes([0x91, 0x40, 0x00, 0x00, 0xa1, 0x40, 0x22, 0x00, 0xb1, 0x07, 0x64])))
    # Program Change, Channel Pressure, Pitch Bend, with Z flag (delta
    # before the first command) and a two-octet delta time
    midi_a(cmdsec(bytes([0x0a, 0xc2, 0x05, 0x81, 0x00, 0xd2, 0x30, 0x00, 0xe2, 0x00, 0x40]), z=True))
    # Long header (B flag): many Control Changes, bank select and RPN
    cc = bytes([0xb3, 0x00, 0x01]) + b''.join(bytes([0x00, 0xb3, n, v]) for n, v in
               ((0x20, 0x02), (0x65, 0x00), (0x64, 0x00), (0x06, 0x02), (0x26, 0x00),
                (0x40, 0x7f), (0x40, 0x00), (0x79, 0x00), (0x7b, 0x00)))
    midi_a(cmdsec(cc))
    # SysEx (identity request), then a three-octet delta time and a
    # Note On with the P flag
    midi_b(cmdsec(bytes([0xf0, 0x7e, 0x7f, 0x06, 0x01, 0xf7, 0x82, 0x80, 0x00, 0x94, 0x45, 0x50]), p=True))
    # SysEx: universal real time (master volume) and a manufacturer one
    midi_b(cmdsec(bytes([0xf0, 0x7f, 0x7f, 0x04, 0x01, 0x00, 0x7f, 0xf7,
                         0x00, 0xf0, 0x43, 0x10, 0x4c, 0x00, 0x00, 0x7e, 0x00, 0xf7])))
    # System common: MTC quarter frame, song position, song select, tune request
    midi_a(cmdsec(bytes([0xf1, 0x21, 0x00, 0xf2, 0x10, 0x00, 0x00, 0xf3, 0x05, 0x00, 0xf6])))
    # System real time: clock, start, continue, stop, active sensing, reset
    midi_a(cmdsec(bytes([0xf8, 0x00, 0xfa, 0x00, 0xfb, 0x00, 0xfc, 0x00, 0xfe, 0x00, 0xff])))
    # Commands with a channel journal (P, C, W, N, E, T, A)
    cj = chan_journal(0, {
        'P': bytes([0x05, 0x80, 0x02]),
        'C': bytes([0x01, 0x07, 0x64, 0x40, 0x81]),
        'W': bytes([0x00, 0x40]),
        'N': bytes([0x02, 0x77]) + bytes([0x3c, 0x40, 0x3e, 0x00]) + bytes([0x80]),
        'E': bytes([0x00, 0x3c, 0x81]),
        'T': bytes([0x30]),
        'A': bytes([0x00, 0x3c, 0x22]),
    })
    midi_a(cmdsec(bytes([0x90, 0x3c, 0x40]), journal(seq_a - 3, chans=[cj])))
    # Journal only (no commands): system journal (D with reset, tune
    # request and song select, V, Q, F) and two channel journals
    sj = sys_journal({
        'D': bytes([0x70, 0x01, 0x01, 0x05]),
        'V': bytes([0x03]),
        'Q': bytes([0x41]),
        'F': bytes([0x40, 0x01, 0x02, 0x03, 0x04]),
    })
    cj1 = chan_journal(1, {'W': bytes([0x10, 0x40])})
    cj2 = chan_journal(9, {'N': bytes([0x01, 0xf0, 0x24, 0x7f])})
    midi_b(cmdsec(b'', journal(seq_b - 1, sysj=sj, chans=[cj1, cj2], single=True)))

    cap.note('session 1: RS and RL on the control port, unknown command once established')
    cap.udp(B, A, 5004, 5004, rs(SB, (seq_a - 1)))
    cap.udp(A, B, 5004, 5004, rl(SA, 31250))
    cap.udp(A, B, 5004, 5004, am(b'ZZ', b'\x01\x02\x03\x04'))
    cap.udp(B, A, 5004, 5004, am(b'XX'))
    cap.note('session 1: CK, RS, RL with trailing data')
    cap.udp(A, B, 5005, 5005, ck(SA, 2, (1, 2, 3), extra=b'\xde\xad'))
    cap.udp(B, A, 5004, 5004, rs(SB, 0x0001ffff, extra=b'\xbe\xef'))
    cap.udp(A, B, 5004, 5004, rl(SA, 0, extra=b'\x00'))
    cap.note('session 1: BY on both ports, without and with a name')
    cap.udp(A, B, 5005, 5005, session(b'BY', TOK, SA))
    cap.udp(A, B, 5004, 5004, session(b'BY', TOK, SA, b'Alice MacBook\0'))

    # ---- Session 2: rejected invitation ----------------------------------
    cap.note('session 2: IN, then NO (Invitation Rejected)')
    cap.udp(C, B, 5004, 5004, session(b'IN', TOK + 1, 0x33333333, b'Carol\0'))
    cap.udp(B, C, 5004, 5004, session(b'NO', TOK + 1, SB, b"Bob's Studio\0"))

    # ---- Session 3: initiated by the other side with NO first -----------
    cap.note('session 3: each command starting a conversation (heuristic accepts NO, OK, BY, CK, RS, RL)')
    for port, payload in ((6000, session(b'NO', 1, 2)), (6002, session(b'OK', 1, 2, b'x\0')),
                          (6004, session(b'BY', 1, 2)), (6006, ck(SA, 0)),
                          (6008, rs(SA, 7)), (6010, rl(SA, 9600))):
        cap.udp(A, C, port, port, payload)

    # ---- Review reproducers: names -----------------------------------------
    cap.note('reproducer applemidi_name.py: normal name, name without NUL, invalid UTF-8 name with data after the NUL')
    cap.udp(A, B, 5010, 5010, session(b'IN', 0x11223344, 0xaabbccdd, b'peer\0'))
    cap.udp(A, B, 5006, 5006, session(b'IN', 0x11223344, 0xaabbccdd, b'peer'))
    cap.udp(A, B, 5008, 5008, session(b'IN', 0x11223344, 0xaabbccdd, b'\x80\x80\x80\x80\x00tail'))
    cap.note('names: UTF-8 name, empty name (only the NUL), invalid UTF-8 without NUL')
    cap.udp(C, A, 5012, 5012, session(b'IN', 2, 3, 'Studio Köln ♫\0'.encode()))
    cap.udp(C, A, 5014, 5014, session(b'IN', 2, 3, b'\0'))
    cap.udp(C, A, 5016, 5016, session(b'IN', 2, 3, b'ab\xff\xfe'))

    # ---- Review reproducer: session on one port --------------------------
    cap.note('reproducer applemidi_session.py: IN, OK, RTP-MIDI on the same port, CK, RS, RL, unknown')
    D, E = '192.0.2.5', '192.0.2.6'
    cap.udp(D, E, 5004, 5004, session(b'IN', 1, 0xaabbccdd, b'A\0'))
    cap.udp(E, D, 5004, 5004, session(b'OK', 1, 0x11111111, b'B\0'))
    cap.udp(D, E, 5004, 5004, rtp(1, 1000, 0xaabbccdd, bytes([0x03, 0x90, 0x3c, 0x40])))
    cap.udp(D, E, 5004, 5004, ck(0xaabbccdd, 2, (1, 2, 3)))
    cap.udp(D, E, 5004, 5004, rs(0xaabbccdd, 0x00010005))
    cap.udp(D, E, 5004, 5004, rl(0xaabbccdd, 31250))
    cap.udp(D, E, 5004, 5004, am(b'ZZ', b'\x01\x02'))

    # ---- Session 4: IPv6 ---------------------------------------------------
    cap.note('session 4 (IPv6): IN/OK on both ports, RTP-MIDI both ways, CK, BY')
    V1, V2 = ip6(1), ip6(2)
    cap.udp(V1, V2, 5004, 5004, session(b'IN', 0xcafe, 0x66666666, b'v6 initiator\0'))
    cap.udp(V2, V1, 5004, 5004, session(b'OK', 0xcafe, 0x77777777, b'v6 responder\0'))
    cap.udp(V1, V2, 5005, 5005, session(b'IN', 0xcafe, 0x66666666, b'v6 initiator\0'))
    cap.udp(V2, V1, 5005, 5005, session(b'OK', 0xcafe, 0x77777777, b'v6 responder\0'))
    cap.udp(V1, V2, 5005, 5005, ck(0x66666666, 0, (5, 0, 0)))
    cap.udp(V1, V2, 5005, 5005, rtp(10, 0, 0x66666666, cmdsec(bytes([0x95, 0x30, 0x60]))))
    cap.udp(V2, V1, 5005, 5005, rtp(20, 0, 0x77777777, cmdsec(bytes([0xb5, 0x01, 0x10]))))
    cap.udp(V1, V2, 5004, 5004, session(b'BY', 0xcafe, 0x66666666))

    # ---- Not AppleMIDI: the heuristic says no -----------------------------
    cap.note('not AppleMIDI: 3 octets, 0xffff with an unknown command, no signature')
    cap.udp(A, C, 7000, 7000, b'\xff\xff\x49')
    cap.udp(A, C, 7002, 7002, am(b'FO', b'\x00\x00\x00\x02'))
    cap.udp(A, C, 7004, 7004, b'\xfe\xffIN' + b'\x00' * 12)

    # ---- Malformed --------------------------------------------------------
    bad.note('session on one port (applemidi_session.py frames 1, 8, 9): IN, truncated CK, one octet')
    bad.udp(D, E, 5004, 5004, session(b'IN', 1, 0xaabbccdd, b'A\0'))
    bad.udp(D, E, 5004, 5004, am(b'CK', b'\x00'))
    bad.udp(D, E, 5004, 5004, b'\xff')
    bad.note('truncated IN, RS, RL, CK as the first packet')
    bad.udp(A, B, 5020, 5020, am(b'IN', b'\x00\x00\x00\x02\x00'))
    bad.udp(A, B, 5022, 5022, am(b'RS', b'\x00\x00\x00\x01\x00\x01'))
    bad.udp(A, B, 5024, 5024, am(b'RL', b'\x00\x00'))
    bad.udp(A, B, 5026, 5026, ck(SA, 2)[:30])
    bad.note('two octets in an established conversation')
    bad.udp(A, B, 5020, 5020, b'\xff\xff')

    os.makedirs(outdir, exist_ok=True)
    cap.write(os.path.join(outdir, 'applemidi-coverage.pcap'))
    bad.write(os.path.join(outdir, 'applemidi-coverage-malformed.pcap'))
    for name, p in (('applemidi-coverage.pcap', cap), ('applemidi-coverage-malformed.pcap', bad)):
        print(name, len(p.frames), 'frames')
        for n, text in p.notes:
            print('  %4d  %s' % (n, text))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
