#!/usr/bin/env python3
# Aeron coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Aeron (packet-aeron.c): publishers send Setup, Data, Pad and heartbeat
frames over UDP unicast and multicast (IPv4 and IPv6) and subscribers
answer with Status Messages, NAKs and RTT frames.

Usage: mkaeron.py [<output directory>]

Writes:
  aeron-coverage.pcap            every frame type, the sequence and stream
                                 analysis cases (retransmissions, keepalives,
                                 out-of-order data, window full and resize,
                                 term change), fragmented message reassembly
                                 (in order, out of order, orphans), small
                                 instances that cross the NAK, retransmission
                                 and orphan limits, and the reproducers of
                                 the Error frame and next offset fixes
  aeron-coverage-malformed.pcap  paths that end in an error expert info or an
                                 exception (not committed; the last frames
                                 build a 16 MiB message)

Aeron has no well known port: dissect with
-d udp.port==40456,aeron -o aeron.sequence_analysis:TRUE
-o aeron.stream_analysis:TRUE -o aeron.reassemble_fragments:TRUE
(the preferences matter: without them none of the analysis runs). Every
packet is built here; nothing comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import eth, ipv4, ipv6, udp, write_pcap  # noqa: E402

PORT = 40456            # the subscriber's port (the one to Decode As)
PUB_PORT = 40455        # the publisher's source port
PUB4, SUB4 = '192.0.2.1', '192.0.2.2'
SUB4B = '192.0.2.3'
MC4_DATA, MC4_CTRL = '233.252.0.1', '233.252.0.2'   # RFC 5771 documentation range
PUB6, SUB6 = '2001:db8::1', '2001:db8::2'
MC6_DATA, MC6_CTRL = 'ff0e::1', 'ff0e::2'

PAD, DATA, NAK, SM, ERR, SETUP, RTT, RES, EXT = 0, 1, 2, 3, 4, 5, 6, 7, 0xffff
B, E, S, BE = 0x80, 0x40, 0x20, 0xc0


# ---------------------------------------------------------------- frames

def rnd(n):
    return (n + 31) & ~31


def data(session, stream, term, off, payload=b'', flags=BE, frame_length=None, reserved=0):
    """A data frame; the datagram carries it padded to 32 bytes."""
    fl = 32 + len(payload) if frame_length is None else frame_length
    f = struct.pack('<IBBHIIIIQ', fl, 0, flags, DATA, off, session, stream, term, reserved) + payload
    return f + b'\0' * (rnd(len(f)) - len(f))


def heartbeat(session, stream, term, off):
    return struct.pack('<IBBHIIII', 0, 0, BE, DATA, off, session, stream, term)


def pad(session, stream, term, off, frame_length, flags=BE, fill=True):
    f = struct.pack('<IBBHIIII', frame_length, 0, flags, PAD, off, session, stream, term)
    return f + (b'\0' * (rnd(frame_length) - len(f)) if fill else b'')


def setup(session, stream, init_term, term, term_length, mtu=1408, ttl=0, off=0):
    return struct.pack('<IBBHIIIIIIII', 40, 0, 0, SETUP, off, session, stream, init_term, term,
                       term_length, mtu, ttl)


def nak(session, stream, term, off, length):
    return struct.pack('<IBBHIIIII', 28, 0, 0, NAK, session, stream, term, off, length)


def sm(session, stream, term, completed, window, receiver=0x1122334455667788, flags=0,
       feedback=b'', frame_length=None):
    fl = 36 + len(feedback) if frame_length is None else frame_length
    return struct.pack('<IBBHIIIIIQ', fl, 0, flags, SM, session, stream, term, completed, window,
                       receiver) + feedback


def sm_setup(session, stream, term, window=0, receiver=0x1122334455667788):
    return sm(session, stream, term, 0, window, receiver, flags=0x80)


def rtt(session, stream, reply=False, echo=1000, delta=50, receiver=0x1122334455667788,
        frame_length=40):
    return struct.pack('<IBBHIIQQQ', frame_length, 0, 0x80 if reply else 0, RTT, session, stream,
                       echo, delta, receiver)


def err(offending, text, code=1, frame_length=None):
    fl = 12 + len(offending) + len(text) if frame_length is None else frame_length
    return struct.pack('<IBBHI', fl, 0, code, ERR, len(offending)) + offending + text


def basic(frame_length, typ, flags=0, version=0):
    """A frame with only the basic header, for types the dissector stops at."""
    return struct.pack('<IBBH', frame_length, version, flags, typ) + b'\0' * 8


# ---------------------------------------------------------------- datagrams

class Cap:
    def __init__(self):
        self.frames = []
        self.n = 0

    def _add(self, frame):
        self.frames.append(frame)

    def pkt(self, payload, src=PUB4, dst=SUB4, sport=PUB_PORT, dport=PORT):
        """One UDP datagram. payload may be a list of frames."""
        if isinstance(payload, (list, tuple)):
            payload = b''.join(payload)
        self.n += 1
        seg = udp(payload, sport, dport, src=src, dst=dst)
        v6 = ':' in src
        mcast = dst.startswith('ff') if v6 else int(dst.split('.')[0]) >= 224
        if mcast:
            dmac = '33:33:00:00:00:%02x' % int(dst.rsplit(':', 1)[-1] or '0', 16) if v6 else \
                '01:00:5e:7c:00:%02x' % int(dst.rsplit('.', 1)[-1])
        else:
            dmac = '02:00:00:00:00:02' if dst in (SUB4, SUB6) else '02:00:00:00:00:01'
        smac = '02:00:00:00:00:01' if src in (PUB4, PUB6) else '02:00:00:00:00:02'
        if v6:
            self._add(eth(ipv6(seg, 17, src, dst), 0x86dd, dst=dmac, src=smac))
        else:
            self._add(eth(ipv4(seg, 17, src, dst, ident=self.n, ttl=16 if mcast else 64),
                          0x0800, dst=dmac, src=smac))

    # publisher -> subscriber, subscriber -> publisher, over each transport
    def p(self, payload):
        self.pkt(payload)

    def s(self, payload):
        self.pkt(payload, src=SUB4, dst=PUB4, sport=PORT, dport=PUB_PORT)


def build():
    ok, bad = Cap(), Cap()
    c = ok

    # ================================================================ A
    # unicast, IPv4: session 0x1001, stream 1001, term length 4096. The
    # frames are 32 byte aligned: a frame of 32 + n bytes takes rnd(32 + n)
    # of the term.
    SE, ST, T0 = 0x1001, 1001, 0x5000
    TL = 4096
    c.p([setup(SE, ST, T0, T0, TL)])
    c.s([sm_setup(SE, ST, T0)])
    c.s([sm(SE, ST, T0, 0, 2048)])
    c.p([data(SE, ST, T0, 0, b'A' * 100)])                    # 132 -> 160
    c.p([data(SE, ST, T0, 160, b'B' * 200)])                  # 232 -> 256
    c.p([data(SE, ST, T0, 416, b'C' * 992, flags=B)])         # begin of a fragmented message
    c.p([data(SE, ST, T0, 1440, b'D' * 992, flags=0)])        # middle
    c.p([data(SE, ST, T0, 2464, b'E' * 500, flags=E)])        # end: 3 fragments, 2484 bytes
    c.s([sm(SE, ST, T0, 3008, 2048)])                         # receiver caught up
    c.s([sm(SE, ST, T0, 3008, 2048)])                         # keepalive SM
    c.s([sm(SE, ST, T0, 3008, 1024)])                         # window resized
    c.s([sm(SE, ST, T0, 2464, 1024)])                         # completed position went back
    c.p([heartbeat(SE, ST, T0, 3008)])                        # heartbeat: keepalive
    c.p([data(SE, ST, T0, 3008, frame_length=0, flags=0)])    # zero length data frame
    c.p([data(SE, ST, T0, 3008, b'F' * 800)])                 # 832 -> 3840
    c.p([data(SE, ST, T0, 3840, b'G' * 128)])                 # 160 -> 4000
    c.p([pad(SE, ST, T0, 4000, 96)])                          # pad to the end of the term
    c.p([data(SE, ST, T0 + 1, 0, b'H' * 100, flags=BE | S)])  # new term (end of stream flag)
    c.s([sm(SE, ST, T0 + 1, 0, 64)])                          # window full
    c.p([data(SE, ST, T0 + 1, 160, b'I' * 300)])              # 332 -> 352
    c.p([data(SE, ST, T0 + 1, 512, b'J' * 300)])              # 332 -> 352 -> 864
    c.s([nak(SE, ST, T0 + 1, 160, 704)])                      # the receiver asks for both again
    c.p([data(SE, ST, T0 + 1, 160, b'I' * 300)])              # retransmission
    c.p([data(SE, ST, T0 + 1, 512, b'J' * 300)])              # retransmission
    c.p([data(SE, ST, T0 + 1, 160, b'I' * 300)])              # the same retransmission again
    c.p([data(SE, ST, T0 + 1, 512, b'J' * 300)])              # the last frame again
    c.s([sm(SE, ST, T0 + 1, 864, 4096)])
    c.p([data(SE, ST, T0 + 1, 512, b'J' * 300)])              # the last frame again, receiver there
    c.p([data(SE, ST, T0 + 1, 1280, b'K' * 100)])             # a gap: out-of-order
    c.s([nak(SE, ST, T0 + 1, 864, 416)])                      # NAK of the gap
    c.p([data(SE, ST, T0 + 1, 864, b'L' * 300)])              # fills the gap (352 -> 1216)
    c.s([sm(SE, ST, T0 + 2, 0, 4096)])                        # SM in a term without data
    c.s([rtt(SE, ST), ])                                      # RTT request
    c.p([rtt(SE, ST, reply=True)])                            # RTT reply
    c.s([nak(SE, ST + 1, 0x77, 0, 64)])                       # NAK for a stream not seen yet
    c.p([data(SE, ST, T0 + 1, 1280, b'K' * 100) + err(b'\x12\x34\x56\x78', b'Invalid frame')])

    # several frames in one datagram: setup and data, three data frames, a
    # trailing frame of an unknown type, zero padding after the last frame
    c.p([setup(0x1002, ST, T0, T0, TL), data(0x1002, ST, T0, 0, b'a' * 32)])
    c.p([data(0x1002, ST, T0, 64, b'b' * 32, flags=B), data(0x1002, ST, T0, 128, b'c' * 32, flags=0),
         data(0x1002, ST, T0, 192, b'd' * 32, flags=E)])
    c.p([data(0x1002, ST, T0, 256, b'e' * 10), basic(32, RES)])
    c.p([data(0x1002, ST, T0, 288, b'f' * 10), basic(32, EXT), b'\0' * 64])
    c.p([data(0x1002, ST, T0, 320, b'g' * 10), b'\0' * 96])

    # reproducer of the Error frame fix: an Error frame that is not first in
    # the datagram (the offending header and the text come from the right
    # bytes); and of the next offset fix: data before the Setup that gives
    # the term length. The frames are in their own session.
    c.p([data(0x11, 0x22, 0x33, 0x100) + err(b'HDR!', b'error-text')])
    c.p([data(0x11, 0x22, 0x33, 0, payload=b'P' * 32, frame_length=64)])
    c.p([setup(0x11, 0x22, 0x33, 0x33, 0x10000)])
    c.p([data(0x11, 0x22, 0x33, 0x40, b'Q' * 32)])
    # an Error frame alone, with and without an offending header and text
    c.p([err(b'', b'')])
    c.p([err(b'OFFENDING-HEADER-OF-AN-EARLIER-FRAME', b'', code=2)])
    c.p([err(b'', b'only text', code=3)])
    c.pkt(err(b'v6', b'error over IPv6'), src=PUB6, dst=SUB6)

    # ================================================================ B
    # reassembly (session 0x3003, stream 3003, term length 64 KiB)
    SE, ST, T0 = 0x3003, 3003, 0x100
    TL = 65536
    c.p([setup(SE, ST, T0, T0, TL)])
    c.s([sm_setup(SE, ST, T0)])
    # message 1, in order, one fragment per datagram: offsets 0 1024 2048
    c.p([data(SE, ST, T0, 0, b'1' * 992, flags=B)])
    c.p([data(SE, ST, T0, 1024, b'2' * 992, flags=0)])
    c.p([data(SE, ST, T0, 2048, b'3' * 200, flags=E)])        # -> 2304
    # message 2, the end arrives before the middle: an orphan that is
    # attached when the middle arrives
    c.p([data(SE, ST, T0, 2304, b'4' * 992, flags=B)])        # -> 3328
    c.p([data(SE, ST, T0, 4352, b'6' * 200, flags=E)])
    c.p([data(SE, ST, T0, 3328, b'5' * 992, flags=0)])        # -> 4352, then the orphan
    # message 3 in one datagram, three frames
    c.p([data(SE, ST, T0, 4608, b'7' * 480, flags=B), data(SE, ST, T0, 5120, b'8' * 480, flags=0),
         data(SE, ST, T0, 5632, b'9' * 100, flags=E)])
    # retransmissions of the parts of message 3: start of a complete message,
    # a middle fragment that is already part of a message, its end
    c.p([data(SE, ST, T0, 4608, b'7' * 480, flags=B)])
    c.p([data(SE, ST, T0, 5120, b'8' * 480, flags=0)])
    c.p([data(SE, ST, T0, 5632, b'9' * 100, flags=E)])
    # message 4: begin, then a middle fragment retransmitted before the
    # message is complete, then a fragment that lies inside the first one
    # (not at the next expected offset and not already stored)
    c.p([data(SE, ST, T0, 5792, b'a' * 480, flags=B)])        # -> 6304
    c.p([data(SE, ST, T0, 6304, b'b' * 480, flags=0)])        # -> 6816
    c.p([data(SE, ST, T0, 6304, b'b' * 480, flags=0)])        # again: already have it
    c.p([data(SE, ST, T0, 5824, b'x' * 100, flags=0)])        # inside the first fragment: orphan
    c.p([data(SE, ST, T0, 6816, b'c' * 100, flags=E)])        # completes message 4
    # a message that begins at an offset above an existing one, then one
    # below it (out of order)
    c.p([data(SE, ST, T0, 10080, b'z' * 96, flags=B)])
    c.p([data(SE, ST, T0, 8192, b'y' * 96, flags=B)])
    c.p([data(SE, ST, T0, 8320, b'y' * 100, flags=E)])
    # an end and a middle fragment without a start: orphans that stay orphans
    c.p([data(SE, ST, T0, 11968, b'o' * 100, flags=E)])
    c.p([data(SE, ST, T0, 14016, b'o' * 100, flags=0)])
    # a message begin and a middle fragment in one datagram, then the end
    c.p([data(SE, ST, T0, 16384, b'm' * 96, flags=B), data(SE, ST, T0, 16512, b'm' * 96, flags=0)])
    c.p([data(SE, ST, T0, 16640, b'm' * 100, flags=E)])
    # a message that continues in the next term
    c.p([data(SE, ST, T0, 65376, b'n' * 96, flags=B)])
    c.p([data(SE, ST, T0 + 1, 0, b'n' * 100, flags=E)])
    c.p([pad(SE, ST, T0 + 1, 160, 64, fill=True)])

    # ================================================================ C
    # many NAKs, then many retransmissions (session 0x4004): limits of 100
    # NAKs per term and 100 retransmissions per NAK. 102 data frames, 101 NAKs
    # (the 101st is not tracked), 101 retransmissions of frames that are not
    # the last one (the 101st is not recorded with the NAKs).
    SE, ST, T0 = 0x4004, 4004, 0x200
    c.p([setup(SE, ST, T0, T0, 0x1000000)])
    c.s([sm_setup(SE, ST, T0)])
    NDATA, NLIM = 102, 101
    for i in range(0, NDATA, 10):
        c.p([data(SE, ST, T0, 64 * j, b'.' * 32) for j in range(i, min(i + 10, NDATA))])
    for i in range(0, NLIM, 10):
        c.s([nak(SE, ST, T0, 0, 0xffffffff) for j in range(i, min(i + 10, NLIM))])
    for i in range(0, NLIM, 10):
        c.p([data(SE, ST, T0, 64 * j, b'.' * 32) for j in range(i, min(i + 10, NLIM))])

    # ================================================================ D
    # many orphans (session 0x5005): a limit of 256 orphan fragments per term
    SE, ST, T0 = 0x5005, 5005, 0x300
    c.p([setup(SE, ST, T0, T0, 0x1000000)])
    OLIM = 258
    for i in range(0, OLIM, 10):
        c.p([data(SE, ST, T0, 128 * j + 192, b"o" * 32, flags=0) for j in range(i, min(i + 10, OLIM))])
    # and now a message the orphans do not belong to still reassembles
    c.p([data(SE, ST, T0, 0, b'p' * 32, flags=B)])
    c.p([data(SE, ST, T0, 64, b'p' * 32, flags=E)])

    # ================================================================ E
    # multicast, IPv4 (data group odd, control group even), two receivers
    SE, ST, T0 = 0x6006, 6006, 0x400
    c.pkt(setup(SE, ST, T0, T0, 4096), dst=MC4_DATA)
    c.pkt(sm_setup(SE, ST, T0, window=2048), src=SUB4, dst=MC4_CTRL, sport=PORT, dport=PORT)
    c.pkt(data(SE, ST, T0, 0, b'M' * 100), dst=MC4_DATA, dport=PORT)
    c.pkt(sm(SE, ST, T0, 160, 2048, receiver=1), src=SUB4, dst=MC4_CTRL, sport=PORT, dport=PORT)
    c.pkt(sm(SE, ST, T0, 160, 2048, receiver=2), src=SUB4B, dst=MC4_CTRL, sport=PORT, dport=PORT)
    c.pkt(data(SE, ST, T0, 160, b'N' * 100), dst=MC4_DATA, dport=PORT)
    c.pkt(sm(SE, ST, T0, 320, 2048, receiver=1), src=SUB4, dst=MC4_CTRL, sport=PORT, dport=PORT)
    c.pkt(sm(SE, ST, T0, 160, 4096, receiver=2), src=SUB4B, dst=MC4_CTRL, sport=PORT, dport=PORT)
    c.pkt(nak(SE, ST, T0, 0, 160), src=SUB4B, dst=MC4_CTRL, sport=PORT, dport=PORT)
    c.pkt(data(SE, ST, T0, 0, b'M' * 100), dst=MC4_DATA, dport=PORT)

    # multicast, IPv6
    SE, ST, T0 = 0x7007, 7007, 0x500
    c.pkt(setup(SE, ST, T0, T0, 4096), src=PUB6, dst=MC6_DATA, dport=PORT)
    c.pkt(sm_setup(SE, ST, T0), src=SUB6, dst=MC6_CTRL, sport=PORT, dport=PORT)
    c.pkt(data(SE, ST, T0, 0, b'V' * 100), src=PUB6, dst=MC6_DATA, dport=PORT)
    c.pkt(sm(SE, ST, T0, 160, 2048), src=SUB6, dst=MC6_CTRL, sport=PORT, dport=PORT)

    # unicast, IPv6
    SE, ST, T0 = 0x8008, 8008, 0x600
    c.pkt(setup(SE, ST, T0, T0, 4096), src=PUB6, dst=SUB6)
    c.pkt(sm_setup(SE, ST, T0), src=SUB6, dst=PUB6, sport=PORT, dport=PUB_PORT)
    c.pkt(data(SE, ST, T0, 0, b'W' * 100), src=PUB6, dst=SUB6)
    c.pkt(sm(SE, ST, T0, 160, 2048), src=SUB6, dst=PUB6, sport=PORT, dport=PUB_PORT)
    c.pkt(nak(SE, ST, T0, 0, 160), src=SUB6, dst=PUB6, sport=PORT, dport=PUB_PORT)

    # a message whose middle fragment arrives before its start (session
    # 0xf00f): the orphan is older than the message it joins
    SE, ST, T0 = 0xf00f, 15, 0x900
    c.p([setup(SE, ST, T0, T0, 65536)])
    c.p([data(SE, ST, T0, 224, b'q' * 96, flags=0)])
    c.p([data(SE, ST, T0, 96, b'q' * 96, flags=B)])
    c.p([data(SE, ST, T0, 352, b'q' * 100, flags=E)])

    # fragments that are not a multiple of 32 bytes long (session 0x1010): the
    # next fragment starts at the rounded offset; and a retransmission of the
    # last frame while the receiver is behind (pacing) and when it caught up
    SE, ST, T0 = 0x1010, 16, 0xa00
    c.p([setup(SE, ST, T0, T0, 65536)])
    c.p([data(SE, ST, T0, 0, b'u' * 1000, flags=B)])           # 1032 -> 1056
    c.p([data(SE, ST, T0, 1056, b'u' * 1000, flags=0)])
    c.p([data(SE, ST, T0, 2112, b'u' * 200, flags=E)])
    c.s([sm(SE, ST, T0, 0, 8192)])
    c.p([data(SE, ST, T0, 2368, b'v' * 100)])
    c.p([data(SE, ST, T0, 2368, b'v' * 100)])                  # pacing retransmission
    c.s([sm(SE, ST, T0, 2528, 8192)])
    c.p([data(SE, ST, T0, 2368, b'v' * 100)])                  # idle retransmission

    # ================================================================ malformed
    c = bad
    SE, ST, T0 = 0x9009, 9009, 0x700
    c.p([setup(SE, ST, T0, T0, 4096)])
    c.p([setup(SE, ST, T0, T0, 4096)[:36] + b'\0' * 4])
    c.p([struct.pack('<IBBHIIIIIIII', 36, 0, 0, SETUP, 0, SE, ST, T0, T0, 4096, 1408, 0)])    # setup length
    c.p([data(SE, ST, T0, 0, b'x' * 8, frame_length=20)])                                    # data length
    c.p([pad(SE, ST, T0, 64, 20)])                                                            # pad length
    c.p([nak(SE, ST, T0, 0, 10)[:24] + struct.pack('<I', 0) + b'\0' * 8][0:32])
    c.p([struct.pack('<IBBHIIIII', 32, 0, 0, NAK, SE, ST, T0, 0, 10) + b'\0' * 8])            # NAK length
    c.p([sm(SE, ST, T0, 0, 100, frame_length=32) + b'\0' * 4])                                # SM length
    c.p([rtt(SE, ST, frame_length=48) + b'\0' * 8])                                           # RTT length
    c.p([struct.pack('<IBBHI', 8, 0, 1, ERR, 4) + b'abcd'])                                   # error length
    c.p([err(b'abcd', b'text', frame_length=400)])
    c.p([err(b'abcd', b'text', frame_length=0xffffffff)])
    c.p([struct.pack('<IBBHIIIIQ', 32, 0, BE, DATA, 0, SE, ST, T0, 0)[:20]])                  # cut data frame
    c.p([struct.pack('<IBBHIIII', 0x80000000, 0, BE, PAD, 64, SE, ST, T0)])
    c.p([struct.pack('<IBBHIIIIQ', 0x80000040, 0, BE, DATA, 64, SE, ST, T0, 0)])
    c.p([struct.pack('<IBBH', 0xffffffff, 0, 0, NAK) + b'\0' * 28])
    c.p([heartbeat(SE, ST, T0, 0)[:16]])
    c.p([data(SE, ST, T0, 0, b'x' * 100, frame_length=1000)])                                 # frame longer than datagram
    c.p([b'\x01\x00'])
    c.p([b'\x08\0\0\0'])
    # a term length of zero, then data: the position arithmetic overflows
    c.p([setup(0xa00a, ST, T0, T0, 0)])
    c.p([data(0xa00a, ST, T0, 0xffffffe0, b'x' * 64)])
    c.p([data(0xa00a, ST, T0, 0xffffff00, b'x' * 400)])
    c.p([data(0xa00a, ST, T0, 0, b'x' * 32), data(0xa00a, ST, T0, 0xffffffe0, b'x' * 32)])
    c.p([data(0xa00a, ST, T0, 0xffffffff, b'x' * 32)])
    # a data frame with a frame length of 0xfffffff0 whose rounding overflows
    c.p([struct.pack('<IBBHIIIIQ', 0xfffffff0, 0, BE, DATA, 0, 0xa00a, ST, T0, 0)])
    # a datagram of one byte; an RTT frame of 2 GiB; a pad frame whose end
    # overflows the position; data whose expected next position overflows
    c.p([b'\x01'])
    c.p([rtt(SE, ST, frame_length=0x80000000)])
    c.p([pad(0xc00c, ST, T0, 0xffffff00, 0x7fffffe0, fill=False)])
    c.p([setup(0xd00d, ST, T0, T0, 0xffffffff)])
    c.p([data(0xd00d, ST, T0, 0x7fffffe0, b'x' * 32)])
    c.p([struct.pack('<IBBHIIIIQ', 0x7fffffe0, 0, BE, DATA, 0, 0xd00d, ST, T0, 0)])
    # frames the heuristic refuses: a version other than 0, an unknown type,
    # a pad frame at offset 0 and a short data frame; with Decode As these
    # are dissected as far as they go
    c.p([struct.pack('<IBBH', 40, 1, 0, SETUP) + b'\0' * 36])
    c.p([struct.pack('<IBBH', 40, 0, 0, 9) + b'\0' * 36])
    c.p([pad(SE, ST, T0, 0, 64)])
    c.p([struct.pack('<IBBH', 8, 0, 0, DATA) + b'\0' * 8])
    # the 16 MiB limit of a reassembled message: 255 fragments of 65440 bytes,
    # then the last fragment (an orphan until the one before it arrives, whose
    # addition to the message fails), then one more middle fragment at the
    # same offset (whose direct addition fails)
    SE, ST, T0 = 0xb00b, 12, 0x800
    c.p([setup(SE, ST, T0, T0, 0x40000000)])
    PL = 65440
    fl = 32 + PL

    def big(i, flags):
        return struct.pack('<IBBHIIIIQ', fl, 0, flags, DATA, i * rnd(fl), SE, ST, T0, 0) + b'\0' * PL

    for i in range(255):
        c.p([big(i, B if i == 0 else 0)])
    c.p([big(256, E)])
    c.p([big(255, 0)])
    c.p([big(256, 0)])
    return ok.frames, bad.frames


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(outdir, exist_ok=True)
    ok, bad = build()
    ts = lambda i: (1700000000 + i // 100, (i % 100) * 10000)  # noqa: E731
    write_pcap(os.path.join(outdir, 'aeron-coverage.pcap'), ok, ts=ts)
    write_pcap(os.path.join(outdir, 'aeron-coverage-malformed.pcap'), bad, ts=ts)
    print(len(ok), len(bad))


if __name__ == '__main__':
    main()
