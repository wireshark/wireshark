#!/usr/bin/env python3
# Generates test/captures/hartip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the HART-IP dissector
(packet-hartip.c).

HART-IP runs over TCP and UDP port 5094. An 8 octet header (version,
message type, message id, status, transaction id, total length) is
followed by a body: session initiate (host type and inactivity timer),
session close, keep alive, error codes, or a pass-through HART frame
(preambles, delimiter, address, command, length, response code, device
status, data, checksum) whose data is decoded for a number of HART
commands. On UDP a session initiate makes the dissector follow the
server's reply port through a conversation. Every packet is built from
scratch with struct; no captured traffic is used.

Usage: mkhartip.py <output directory>

Writes:
  hartip-coverage.pcap            TCP and UDP sessions: session
                                  initiate/close, keep alive, errors and
                                  NAKs, pass-through for commands
                                  0 1 2 3 6 7 8 9 11-22 31 33 38 48 77
                                  178 203 at every body size, long and
                                  short addresses, expansion bytes, a
                                  PDU split over three TCP segments,
                                  several PDUs per segment/datagram
  hartip-coverage-malformed.pcap  lengths past the end, a length below
                                  the header size, truncated headers and
                                  bodies, a non HART-IP first PDU
"""

import os
import struct
import sys

# ---------------------------------------------------------------- network
MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([10, 0, 0, 1])
IP_B = bytes([10, 0, 0, 2])


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def ip4(proto, payload, src, dst):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0, 0x4000, 64,
                      proto, 0, src, dst)
    s = sum(struct.unpack('>10H', hdr))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    hdr = hdr[:10] + struct.pack('>H', (~s) & 0xffff) + hdr[12:]
    return hdr + payload


def eth_ip(proto, payload, to_b):
    if to_b:
        return MAC_B + MAC_A + b'\x08\x00' + ip4(proto, payload, IP_A, IP_B)
    return MAC_A + MAC_B + b'\x08\x00' + ip4(proto, payload, IP_B, IP_A)


def udp(sport, dport, payload, to_b):
    return eth_ip(17, struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload, to_b)


class Tcp:
    """One TCP connection, A is the client."""

    def __init__(self, cport, sport):
        self.cport, self.sport = cport, sport
        self.seq = {True: 1000, False: 5000}

    def seg(self, payload, to_b, flags=0x18):
        s, d = (self.cport, self.sport) if to_b else (self.sport, self.cport)
        me, other = self.seq[to_b], self.seq[not to_b]
        hdr = struct.pack('>HHIIBBHHH', s, d, me, other, 0x50, flags, 65535, 0, 0)
        self.seq[to_b] += len(payload)
        return eth_ip(6, hdr + payload, to_b)


# --------------------------------------------------------------- HART-IP
def hip(mtype, mid, txid, body=b'', status=0, version=1, length=None):
    if length is None:
        length = 8 + len(body)
    return struct.pack('>BBBBHH', version, mtype, mid, status, txid, length) + body


REQ, RSP, PUB, ERR, NAK = 0, 1, 2, 3, 15
INIT, CLOSE, KEEP, PT = 0, 1, 2, 3


def chk(b):
    x = 0
    for c in b:
        x ^= c
    return bytes([x])


def pt(delim, cmd, data=b'', rsp=None, addr=None, expansion=b'', npre=5,
       length=None, checksum=True):
    """Pass-through body: preambles, delimiter, address, expansion
    bytes, command, length, [response code, device status], data and a
    checksum. 'rsp' is (code, status) for ACK/BACK frames."""
    if addr is None:
        addr = bytes([0x01]) if not (delim & 0x80) else bytes.fromhex('26 12 34 56 78')
    out = b'\xff' * npre + bytes([delim]) + addr + expansion + bytes([cmd])
    n = len(data) + (2 if rsp is not None else 0)
    out += bytes([n if length is None else length])
    if rsp is not None:
        out += bytes(rsp)
    out += data
    if checksum:
        out += chk(out)
    return out


STX_S, STX_L, ACK_S, ACK_L, BACK_S, BACK_L = 0x02, 0x82, 0x06, 0x86, 0x01, 0x81


def f32(v):
    return struct.pack('>f', v)


def ts(ms32):
    return struct.pack('>I', ms32)


def pack_ascii(s, n):
    """Pack n bytes of 6 bit characters (4 per 3 octets)."""
    s = (s + ' ' * 64)[:n * 4 // 3]
    vals = [ord(c) & 0x3f for c in s]
    out = b''
    for i in range(0, len(vals), 4):
        a, b, c, d = vals[i:i + 4]
        out += bytes([(a << 2) | (b >> 4), ((b & 0xf) << 4) | (c >> 2), ((c & 3) << 6) | d])
    return out[:n]


def cmd0_data(n):
    full = (bytes([254]) + struct.pack('>H', 0x2606) + bytes([5, 7, 1, 2, 3, 0x10])
            + bytes.fromhex('a1b2c3') + bytes([5, 4]) + struct.pack('>H', 7) + bytes([0x40])
            + struct.pack('>H', 0x26) + struct.pack('>H', 0x1234) + bytes([1]))
    return full[:n]


def cmd9_data(slots):
    d = bytes([0x80])
    for s in range(slots):
        d += bytes([s, 1, 39]) + f32(20.5 + s) + bytes([0xc0])
    return d + ts(32000 * 3661 + 32 * 123)


def cmd33_data(slots):
    d = b''
    for s in range(slots):
        d += bytes([s, 39]) + f32(1.5 * (s + 1))
    return d


def cmd203_data(n_slots, tstamp=96000):
    d = struct.pack('>HBB', 1, n_slots, 0x80) + ts(tstamp)
    for s in range(n_slots):
        d += struct.pack('>HB', s, 0x40)
    return d


CMD48_FULL = bytes(range(0x10, 0x10 + 25))


def cmd77(rsp, long_emb, cmd_inner, inner_data, bytecount=None):
    d = bytes([1, 2])
    if not rsp:
        d += bytes([5])
    d += bytes([0x82 if long_emb else 0x02])
    d += bytes.fromhex('26 11 22 33 44') if long_emb else bytes([3])
    d += bytes([cmd_inner])
    bc = len(inner_data) if bytecount is None else bytecount
    d += bytes([bc]) + inner_data
    return d


def cmd178(subs, count=None):
    d = bytes([len(subs) if count is None else count])
    for cmdno, body in subs:
        d += struct.pack('>HBB', cmdno, len(body) + 1, 0) + body
    return d


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    main_frames = []
    mal = []

    # ------------------------------------------------------------ TCP
    t = Tcp(49152, 5094)
    tx = [0]

    def nt():
        tx[0] += 1
        return tx[0]

    def req(body_mid, body=b'', mtype=REQ, **kw):
        return hip(mtype, body_mid, nt(), body, **kw)

    def send(c, to_b=True, tcp=t):
        main_frames.append(tcp.seg(c, to_b))

    # session initiate: request (primary host, 15 minute timer), response,
    # a short body that is shown as data
    send(hip(REQ, INIT, nt(), bytes([1]) + struct.pack('>I', 900000)))
    send(hip(RSP, INIT, tx[0], bytes([1]) + struct.pack('>I', 900000)), False)
    send(hip(REQ, INIT, nt(), bytes([0, 0, 1])))
    send(hip(RSP, INIT, tx[0], bytes([0]) + struct.pack('>I', 60000), status=0), False)
    # keep alive (no data note), keep alive with a body (unexpected)
    send(hip(REQ, KEEP, nt()))
    send(hip(RSP, KEEP, tx[0], b'\x00\x01'), False)
    send(hip(PUB, KEEP, nt(), b'\x42'), False)
    # error and NAK messages with one octet and with a longer body
    for code in (0, 1, 2, 9):
        send(hip(ERR, INIT, nt(), bytes([code]), status=code), False)
    send(hip(NAK, PT, nt(), bytes([2]), status=2), False)
    send(hip(ERR, KEEP, nt(), b'\x01\x02\x03'), False)
    send(hip(NAK, CLOSE, nt(), b''), False)

    # pass-through, requests and responses, one frame per command
    def ptreq(cmd, data=b'', delim=STX_S, **kw):
        send(hip(REQ, PT, nt(), pt(delim, cmd, data, **kw)))

    def ptrsp(cmd, data=b'', delim=ACK_S, code=0, status=0x40, **kw):
        send(hip(RSP, PT, tx[0], pt(delim, cmd, data, rsp=(code, status), **kw)), False)

    # command 0 / 11 / 21 at every size and both address types
    for n in (11, 12, 13, 16, 17, 18, 21, 22, 23):
        ptreq(0, delim=STX_L)
        ptrsp(0, cmd0_data(n), delim=ACK_L)
    ptreq(11, b'MYTAG', delim=STX_L)
    ptrsp(11, cmd0_data(22), delim=ACK_L)
    ptreq(21, b'\x00')
    ptrsp(21, cmd0_data(12))
    # commands 1, 2, 3 (also at the size boundaries), 6/7, 8
    ptreq(1)
    ptrsp(1, bytes([39]) + f32(21.25))
    ptrsp(1, bytes([39, 0, 0, 0]))
    ptreq(2)
    ptrsp(2, f32(12.0) + f32(50.0))
    ptrsp(2, f32(12.0))
    ptreq(3)
    ptrsp(3, f32(8.0) + bytes([39]) + f32(21.0) + bytes([39]) + f32(22.0)
          + bytes([39]) + f32(23.0) + bytes([39]) + f32(24.0))
    ptrsp(3, f32(8.0) + bytes([39]) + f32(21.0))
    ptreq(6, bytes([2, 1]))
    ptrsp(6, bytes([2, 1]))
    ptrsp(7, bytes([3, 0]))
    ptrsp(7, bytes([3]))
    ptrsp(8, bytes([64, 65, 66, 67]))
    ptrsp(8, bytes([64, 65]))
    # command 9 with 1..8 slots plus the timestamp; 0 -> not decoded
    for slots in range(1, 9):
        ptrsp(9, cmd9_data(slots), delim=ACK_L)
    ptrsp(9, ts(0)[:3] + bytes([0] * 9))
    ptrsp(9, bytes([0x80, 0, 1, 39]) + f32(1.0) + bytes([0xc0]) + ts(0))
    # strings: 12/17 message, 13/18 tag+descriptor+date, 22 long tag
    ptreq(12)
    ptrsp(12, pack_ascii('HELLO WORLD MESSAGE 12345 ABCDEFGH', 24))
    ptrsp(17, pack_ascii('ANOTHER MESSAGE', 24))
    ptrsp(12, bytes(10))
    ptrsp(13, pack_ascii('TAG-001', 6) + pack_ascii('DESCRIPTOR ABC', 12) + bytes([5, 11, 99]))
    ptrsp(18, pack_ascii('TAG-002', 6) + pack_ascii('DESC', 12) + bytes([31, 12, 100]))
    ptrsp(13, bytes(10))
    ptrsp(22, b'LONG TAG 0123456789ABCDEFGHIJKLMN')
    ptrsp(22, b'short')
    ptreq(20)
    # 14, 15, 16/19, 38, 33
    ptrsp(14, bytes([0xaa, 0xbb, 0xcc, 39]) + f32(100.0) + f32(-10.0) + f32(0.5))
    ptrsp(14, bytes(5))
    ptrsp(15, bytes([0, 1, 39]) + f32(100.0) + f32(0.0) + f32(0.25) + bytes([250, 0, 0]))
    ptrsp(15, bytes(5))
    ptrsp(16, bytes([1, 2, 3]))
    ptrsp(19, bytes([4, 5, 6]))
    ptrsp(16, bytes([1]))
    ptrsp(38, struct.pack('>H', 321))
    ptrsp(38, bytes([1]))
    for slots in range(1, 5):
        ptrsp(33, cmd33_data(slots))
    ptrsp(33, bytes(4))
    ptreq(33, bytes([1, 2, 3, 4]))
    # command 48 at every size, the fix reproducers are 24 and 25
    for n in (5, 6, 8, 9, 12, 13, 14, 24, 25):
        ptrsp(48, CMD48_FULL[:n], delim=ACK_L)
    ptreq(48, delim=STX_L)
    # command 31 wrapping 203 and another command
    ptreq(31, struct.pack('>H', 64386))
    for n in (0, 1, 2, 3, 4, 5, 6):
        ptrsp(31, struct.pack('>H', 64386) + cmd203_data(n))
    ptrsp(31, struct.pack('>H', 64386) + cmd203_data(0, 0)[:4])
    ptrsp(31, struct.pack('>H', 64386) + bytes(3))
    ptrsp(31, struct.pack('>H', 64386) + cmd203_data(2, 0))
    ptrsp(31, struct.pack('>H', 1234) + bytes([1, 2, 3]))
    ptrsp(31, struct.pack('>H', 1234))
    ptrsp(31, bytes([1]))
    ptrsp(203, cmd203_data(6))
    # command 77 requests and responses, short/long embedded address
    ptreq(77, cmd77(False, False, 1, b''), delim=STX_L)
    ptreq(77, cmd77(False, True, 3, b'\x00\x20', bytecount=2))
    ptrsp(77, cmd77(True, False, 1, bytes([0, 0x40]) + f32(1.0), bytecount=6), delim=ACK_L)
    ptrsp(77, cmd77(True, True, 3, bytes([0, 0x40, 1, 2, 3]), bytecount=5))
    ptrsp(77, cmd77(True, False, 1, bytes([0, 0x40]), bytecount=2))
    ptrsp(77, cmd77(True, False, 1, bytes([0]), bytecount=1))
    ptrsp(77, cmd77(True, False, 1, bytes([0, 0x40, 9]), bytecount=40))
    ptrsp(77, bytes([1, 2, 3, 4, 5]))
    # command 178 with sub commands 3, 9, 48 and other ones
    ptrsp(178, cmd178([(3, f32(8.0) + bytes([39]) + f32(21.0) + bytes([39]) + f32(22.0)
                        + bytes([39]) + f32(23.0) + bytes([39]) + f32(24.0)),
                       (9, cmd9_data(1)),
                       (48, CMD48_FULL[:9]),
                       (48, CMD48_FULL[:25]),
                       (99, bytes([7, 8, 9]))]), delim=ACK_L)
    ptrsp(178, cmd178([(3, bytes(5)), (9, bytes(3))]))
    ptrsp(178, cmd178([(48, CMD48_FULL[:6])], count=3))
    ptrsp(178, cmd178([]) + bytes(3))
    ptrsp(178, bytes([1, 0, 3]))
    ptrsp(178, cmd178([(3, b'')]))
    ptrsp(178, cmd178([(3, bytes(1))], count=1)[:-1] + bytes([0]))
    # unknown command: payload as bytes
    ptrsp(250, bytes([1, 2, 3, 4]))
    ptreq(250, bytes([1, 2, 3, 4]))
    # delimiters, addresses, preambles, expansion bytes
    ptreq(1, delim=BACK_S)
    ptrsp(1, bytes([39]) + f32(1.0), delim=BACK_S)
    ptrsp(1, bytes([39]) + f32(2.0), delim=BACK_L)
    ptreq(1, delim=0x02 | 0x20, expansion=b'\x77')
    ptreq(1, delim=0x82 | 0x40, expansion=b'\x77\x88')
    ptreq(1, delim=0x02 | 0x60, expansion=b'\x77\x88\x99')
    ptreq(1, delim=0x02 | 0x08)
    ptreq(1, npre=0)
    ptreq(1, npre=20)
    # a long address delimiter with only 3 octets after it
    send(hip(REQ, PT, nt(), b'\xff\xff' + bytes([0x82, 1, 2, 3])))
    # a delimiter only, preambles only, and a bare command
    send(hip(REQ, PT, nt(), b'\xff\xff\xff\xff'))
    send(hip(REQ, PT, nt(), bytes([0xff, 0x02])))
    send(hip(REQ, PT, nt(), bytes([0xff, 0x02, 5])))
    send(hip(REQ, PT, nt(), bytes([0xff, 0x02, 5, 1])))
    send(hip(REQ, PT, nt(), bytes([0xff, 0x02, 5, 1, 0])))
    send(hip(RSP, PT, tx[0], bytes([0xff, 0x06, 5, 1, 2])), False)
    send(hip(RSP, PT, tx[0], bytes([0xff, 0x06, 5, 1, 2, 0])), False)
    send(hip(RSP, PT, tx[0], bytes([0xff, 0x06, 5, 1, 2, 0, 0x40])), False)
    send(hip(RSP, PT, tx[0], bytes([0xff, 0x06, 5, 1, 2, 0, 0x40, 0xcc])), False)
    # pass-through with an empty body
    send(hip(REQ, PT, nt()))

    # several PDUs in one segment; the later ones may have any id/type,
    # which only the first PDU's check excludes (default message id case)
    two = (hip(REQ, KEEP, nt()) + hip(REQ, 7, nt(), b'\x01\x02')
           + hip(9, KEEP, nt(), b'xyz') + hip(REQ, PT, nt(), pt(STX_S, 1)))
    send(two)
    # one PDU split over three segments (reassembly), then a PDU that
    # starts in the middle of the last segment
    big = hip(RSP, PT, nt(), pt(ACK_L, 9, cmd9_data(8), rsp=(0, 0x40)))
    cut1, cut2 = 11, 60
    send(big[:cut1], False)
    send(big[cut1:cut2], False)
    send(big[cut2:] + hip(REQ, KEEP, nt()), False)
    # session close
    send(hip(REQ, CLOSE, nt()))
    send(hip(RSP, CLOSE, tx[0], b'\x00'), False)

    # a second connection with a message whose length field is exactly
    # the header, to take the empty-body route
    t2 = Tcp(49153, 5094)
    main_frames.append(t2.seg(hip(REQ, INIT, 1, bytes([1]) + struct.pack('>I', 1000)), True))
    main_frames.append(t2.seg(hip(RSP, INIT, 1, bytes([1]) + struct.pack('>I', 1000)), False))
    main_frames.append(t2.seg(hip(PUB, PT, 2, pt(BACK_S, 3, f32(1.0) + f32(2.0) + bytes(2), rsp=(0, 0))), False))

    # ------------------------------------------------------------ UDP
    cp, sp, sp2 = 50000, 5094, 5095
    # session initiate to the well known port; the reply comes from
    # another port and the conversation sends later traffic to the
    # HART-IP dissector
    main_frames.append(udp(cp, sp, hip(REQ, INIT, 1, bytes([1]) + struct.pack('>I', 600000)), True))
    main_frames.append(udp(sp2, cp, hip(RSP, INIT, 1, bytes([1]) + struct.pack('>I', 600000)), False))
    # on a port nothing is registered for
    main_frames.append(udp(cp, sp2, hip(REQ, PT, 2, pt(STX_S, 1)), True))
    main_frames.append(udp(sp2, cp, hip(RSP, PT, 2, pt(ACK_S, 1, bytes([39]) + f32(3.5), rsp=(0, 0x40))), False))
    # second session initiate from the same client port (conversation
    # already there) and one from another client port
    main_frames.append(udp(cp, sp, hip(REQ, INIT, 3, bytes([0]) + struct.pack('>I', 600000)), True))
    main_frames.append(udp(50001, sp, hip(REQ, INIT, 1, bytes([1]) + struct.pack('>I', 1000)), True))
    main_frames.append(udp(sp2, 50001, hip(RSP, INIT, 1, bytes([1]) + struct.pack('>I', 1000)), False))
    main_frames.append(udp(50001, sp2, hip(REQ, KEEP, 2), True))
    # reproducer of the fix: three PDUs in one datagram (the offset of
    # the third was wrong), the first request carries command 48 with a
    # 24 octet body (the fix) in the second
    pdus = (hip(REQ, KEEP, 11)
            + hip(RSP, PT, 12, pt(ACK_L, 48, CMD48_FULL[:24], rsp=(0, 0x40)))
            + hip(RSP, PT, 13, pt(ACK_S, 1, bytes([39]) + f32(7.0), rsp=(0, 0x40))))
    main_frames.append(udp(sp2, cp, pdus, False))
    # a datagram with a trailing PDU with unknown ids, and trailing octets
    # shorter than a header
    main_frames.append(udp(sp2, cp, hip(RSP, KEEP, 14) + hip(RSP, 9, 15, b'ab') + b'\x01\x02', False))
    # well known port, no session initiate
    main_frames.append(udp(51000, sp, hip(REQ, 2, 20), True))
    main_frames.append(udp(sp, 51000, hip(ERR, KEEP, 20, b'\x01'), False))
    main_frames.append(udp(51000, sp, hip(REQ, PT, 21, pt(STX_L, 0)), True))
    main_frames.append(udp(sp, 51000, hip(RSP, PT, 21, pt(ACK_L, 0, cmd0_data(22), rsp=(0, 0)))
                           + hip(REQ, CLOSE, 22), False))

    pcap(os.path.join(out, 'hartip-coverage.pcap'), main_frames)

    # ------------------------------------------------------ malformed
    port = [49200]

    def m(c, to_b=True):
        # every segment on its own connection so that a request for more
        # data by one does not swallow the next
        port[0] += 1
        mal.append(Tcp(port[0], 5094).seg(c, to_b))

    # length points past the end of the segment (the stream just ends)
    m(hip(REQ, PT, 1, pt(STX_S, 1), length=200)[:30])
    # length below the header size
    m(hip(REQ, KEEP, 2, b'', length=4))
    m(hip(REQ, KEEP, 3, b'', length=0))
    # first PDU that is not HART-IP (message type / id unknown)
    m(hip(9, KEEP, 4))
    m(hip(REQ, 9, 5))
    m(b'\x01\x00\x03')
    m(hip(REQ, PT, 6, pt(STX_S, 1))[:-4])
    # UDP forms
    mal.append(udp(50100, 5094, hip(REQ, PT, 1, pt(STX_S, 1), length=100), True))
    mal.append(udp(50100, 5094, hip(REQ, KEEP, 2, b'', length=4), True))
    mal.append(udp(50100, 5094, hip(REQ, KEEP, 3, b'', length=0) + hip(REQ, KEEP, 4), True))
    mal.append(udp(50100, 5094, hip(9, KEEP, 5), True))
    mal.append(udp(50100, 5094, hip(REQ, 9, 6), True))
    mal.append(udp(50100, 5094, b'\x01\x00', True))
    mal.append(udp(50100, 5094, b'\x01', True))
    mal.append(udp(50100, 5094, hip(REQ, KEEP, 7)[:6], True))
    mal.append(udp(50100, 5094, hip(REQ, PT, 8, pt(STX_S, 1))[:-3], True))
    # truncated bodies of the other message types
    mal.append(udp(50100, 5094, hip(REQ, INIT, 9, b'\x01\x00\x00\x00\x00')[:11], True))
    # a command whose data is shorter than the body claims (cmd 77
    # with the embedded byte count past the data)
    mal.append(udp(50100, 5094, hip(RSP, PT, 10, pt(ACK_S, 77, cmd77(True, True, 3, b'\x00\x40\x01', bytecount=60), rsp=(0, 0))), False))
    # a 5-octet long address with the segment ending inside it
    mal.append(udp(50100, 5094, hip(REQ, PT, 11, bytes([0xff, 0x82, 1, 2, 3, 4, 5]))[:-2], True))
    # command 178 count past the data
    mal.append(udp(50100, 5094, hip(RSP, PT, 12, pt(ACK_S, 178, bytes([200, 0, 3, 5, 0, 1, 2, 3, 4]), rsp=(0, 0))), False))
    pcap(os.path.join(out, 'hartip-coverage-malformed.pcap'), mal)


main()
