#!/usr/bin/env python3
# Generates test/captures/slsk_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the SoulSeek dissector (packet-slsk.c).

Usage: mkslsk.py <output directory>

SoulSeek messages (length, code, body; all little endian) are dissected
on TCP ports 2234, 2240 and 5534. Every message code of the dissector is
built here from its format string (i integer, b byte, s string), with the
list structures filled in; the shared file list (5), the file search
result (9) and the folder contents response (37) are zlib compressed.
Every packet is built with struct and zlib; nothing is captured.

Writes:
  slsk-coverage.pcap            valid messages (client to server on port
                                2234 and back; peer messages on 2240)
  slsk-coverage-malformed.pcap  invalid zlib data, short or unknown
                                messages, trailing data
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
import zlib
from pcaplib import pcap, TcpConn


def I(n):
    return struct.pack('<I', n)


def B(n):
    return bytes([n])


def S(t):
    t = t.encode() if isinstance(t, str) else t
    return I(len(t)) + t


def M(code, *fields):
    """Message: length, code and fields."""
    body = I(code) + b''.join(fields)
    return I(len(body)) + body


def MB(first, *fields):
    """Message whose first field is one octet (Peer Init, Pierce Fw, Distributed Search)."""
    body = B(first) + b''.join(fields)
    return I(len(body)) + body


def attrs(n):
    return I(n) + b''.join(I(k) + I(128 * (k + 1)) for k in range(n))


def fileent(name, nattr=2):
    return B(1) + S(name) + I(123456) + I(0) + S('mp3') + attrs(nattr)


def shared_list():
    d = I(2)
    d += S('music\\rock') + I(2) + fileent('a.mp3', 3) + fileent('b.mp3', 0)
    d += S('music\\jazz') + I(1) + fileent('c.flac', 1)
    return d


def search_result(user=''):
    d = S(user) + I(77) + I(2) + fileent('x.mp3') + fileent('y.ogg', 1)
    d += B(1) + I(4096) + I(3)
    return d


def folder_contents():
    d = I(55) + S('music\\rock') + I(1) + S('music\\rock') + I(2) + fileent('a.mp3') + fileent('b.mp3', 0)
    return d


def userlist(room='room1'):
    """Join room / privileged user list structure (codes 14 and 67)."""
    b = S(room) + I(2) + S('alice') + S('bob')
    b += I(2) + I(2) + I(1)                                     # statuses
    b += I(2) + b''.join(I(k) for k in range(10))               # 2 users x 5 integers
    b += I(2) + I(0) + I(3)                                     # slots full
    return b


def main(out):
    c = TcpConn(50000, 2234)
    c.handshake()
    p = TcpConn(50001, 2240, isn_c=3000, isn_s=9000)
    p.handshake()
    srv = lambda m: c.send(m, client=False)
    cli = lambda m: c.send(m, client=True)
    # ---- server messages ----------------------------------------------------------
    cli(M(1, S('alice'), S('secret'), I(181)))                         # Login request
    srv(M(1, B(1), S('Welcome'), bytes([192, 0, 2, 7])))               # reply, success, IP
    srv(M(1, B(0), S('Bad password')))                                  # reply, failure
    cli(M(2, I(2234)))                                                  # Set Wait Port
    cli(M(3, S('bob')))                                                 # Get Peer Address
    srv(M(3, S('bob'), bytes([192, 0, 2, 8]), I(2240)))
    cli(M(5, S('bob')))                                                 # User exists
    srv(M(5, S('bob'), B(1)))
    cli(M(7, S('bob')))                                                 # Get User Status
    srv(M(7, S('bob'), I(2)))
    srv(M(13, S('room1'), S('bob'), S('hello')))                        # Say ChatRoom
    cli(M(13, S('room1'), S('hi')))
    cli(M(14, S('room1')))                                              # Join room
    srv(M(14, userlist()))                                              # user list
    srv(M(14, S('room2'), I(0), I(0), I(0), I(0)))                      # empty lists
    srv(M(14, S('room3'), I(3), S('u1'), S('u2')))                      # counts larger than the data
    cli(M(15, S('room1')))                                              # Leave room
    srv(M(16, S('room1'), S('bob'), I(10), I(11), I(12), I(13), I(14), I(15), I(16)))   # user joined
    srv(M(17, S('room1'), S('bob')))                                    # user left
    cli(M(18, I(4), S('bob'), S('P')))                                  # Connect to peer: P, F, D, other
    cli(M(18, I(4), S('bob'), S('F')))
    cli(M(18, I(4), S('bob'), S('D')))
    cli(M(18, I(4), S('bob'), S('X')))
    cli(M(18, I(4), S('bob'), S('PP')))
    srv(M(18, S('bob'), S('P'), bytes([192, 0, 2, 8]), I(2240), I(4)))   # server to client
    cli(M(22, S('bob'), S('message')))                                  # Message user
    srv(M(22, I(5), I(1700000000), S('bob'), S('message')))
    cli(M(23, I(5)))                                                    # Message user ack
    cli(M(26, I(77), S('pink floyd')))                                  # File search
    cli(M(28, I(2)))                                                    # Set status
    cli(M(32))                                                          # Ping (no body)
    cli(M(34, S('bob'), I(12345)))
    cli(M(35, I(100), I(1000)))                                         # Shared files and folders
    cli(M(36, S('bob')))                                                # Get user stats
    srv(M(36, S('bob'), I(100), I(5), I(0), I(200), I(30)))
    cli(M(40, S('bob'), I(2)))                                          # Queued downloads (isi)
    # ---- recommendation and ranking lists ---------------------------------------------
    cli(M(54))
    cli(M(67))
    srv(M(54, I(2), S('jazz'), I(10), S('rock'), I(-3 & 0xffffffff)))
    srv(M(54, I(0)))
    srv(M(56, I(2), S('alice'), I(1000), S('bob'), I(900)))
    cli(M(56))
    cli(M(57, S('bob')))
    srv(M(57, S('bob'), I(2), S('jazz'), S('rock')))                  # user recommendations
    srv(M(57, S('bob'), I(2)))                                          # count without data
    srv(M(58, S('admin'), I(2), S('cmd1'), S('cmd2')))
    cli(M(60, S('bob'), I(7), I(2)))
    srv(M(62, S('room9')))
    srv(M(63, S('room9')))
    cli(M(64))
    srv(M(64, I(2), S('room1'), S('room2'), I(2), I(10), I(20)))       # room list
    srv(M(64, I(0)))
    cli(M(65, I(7), S('bob'), S('file.mp3'), I(1), I(2), I(3), B(1)))
    cli(M(66, S('Admin message')))
    srv(M(67, userlist('room4')))
    srv(M(68, S('bob'), I(1), I(2), I(3), I(4), S('tunnel')))
    cli(M(69))
    srv(M(69, I(2), S('vip1'), S('vip2')))
    srv(M(71, B(1)))
    cli(M(73, I(1)))
    cli(M(83, I(1)))
    cli(M(84, I(50)))
    srv(M(86, I(120)))
    srv(M(87, I(60)))
    srv(M(88, I(10)))
    srv(M(90, I(5)))
    cli(M(91, S('bob')))
    cli(M(92))
    srv(M(92, I(30)))
    srv(M(93, B(3), I(1), S('alice'), I(99), S('pink floyd')))        # embedded distributed search
    cli(M(100, B(1)))
    srv(M(102, I(2), S('parent1'), bytes([192, 0, 2, 9]), I(2234), S('parent2'), bytes([192, 0, 2, 10]), I(2235)))
    srv(M(102, I(2), S('parent1'), bytes([192, 0, 2, 9]), I(2234)))     # second entry missing
    srv(M(103, I(5), S('wishlist')))
    srv(M(104, I(1)))
    cli(M(110))
    srv(M(110, I(2), S('alice'), I(5), S('carol'), I(3)))
    cli(M(111, S('jazz')))
    srv(M(111, S('jazz'), I(2), S('blues'), I(4), S('swing'), I(2)))
    cli(M(112, S('jazz')))
    srv(M(112, S('jazz'), I(2), S('alice'), S('bob')))
    cli(M(1001, I(4), S('bob')))
    srv(M(1001, I(4)))
    cli(M(52, S('jazz')))
    cli(M(51, S('jazz')))
    cli(M(50, S('jazz')))
    srv(M(50, S('jazz'), I(3)))
    srv(M(50, S('alice'), S('jazz')))
    cli(M(55))
    cli(M(42, S('file.mp3')))
    cli(M(43, S('file.mp3')))
    cli(M(44, S('file.mp3'), I(7)))
    cli(M(46, S('file.mp3')))
    # ---- zlib compressed messages ------------------------------------------------------
    srv(M(5, zlib.compress(shared_list())))
    srv(M(5, zlib.compress(I(0))))
    srv(M(5, zlib.compress(I(1) + S('dir') + I(1) + B(1) + S('f') + I(1) + I(2))))       # file cut short
    srv(M(9, zlib.compress(search_result())))
    srv(M(37, zlib.compress(folder_contents())))
    srv(M(37, zlib.compress(I(1) + S('d') + I(1))))
    n1 = len(c.frames)
    # ---- peer connection on port 2240 ----------------------------------------------------
    p.send(MB(1, S('alice'), S('P'), I(4)))                            # Peer Init: P, F, D, X
    p.send(MB(1, S('alice'), S('F'), I(4)))
    p.send(MB(1, S('alice'), S('D'), I(4)))
    p.send(MB(1, S('alice'), S('X'), I(4)), client=False)
    p.send(MB(0, I(4)))                                                # Pierce Fw
    p.send(MB(3, I(1), S('alice'), I(99), S('pink floyd')))            # distributed search
    p.send(M(4))                                                       # Get shared file list
    p.send(M(5, zlib.compress(shared_list())), client=False)           # shared file list
    p.send(M(9, zlib.compress(search_result())), client=False)         # file search result
    p.send(M(15))                                                      # User info request
    p.send(M(16, S('description'), B(0), I(10), I(2), B(1)), client=False)                  # user info reply, no picture
    p.send(M(16, S('description'), B(1), S('PICTURE'), I(10), I(2), B(1)), client=False)    # with picture
    p.send(M(36, I(5), S('folder')))                                   # folder contents request
    p.send(M(37, zlib.compress(folder_contents())), client=False)
    p.send(M(40, I(0), I(7), S('file.mp3')))                           # transfer request, download
    p.send(M(40, I(1), I(7), S('file.mp3'), I(123456), I(0)))          # upload
    p.send(M(41, I(7), B(1), I(123456), I(0)), client=False)           # transfer response: allowed with size
    p.send(M(41, I(7), B(1)), client=False)                            # allowed, no size
    p.send(M(41, I(7), B(0), S('Queued')), client=False)               # not allowed
    p.send(M(999999, I(1)))                                            # unknown message code
    # a message in two segments and two messages in one segment
    m = M(14, userlist('split'))
    p.send(m[:10])
    p.send(m[10:])
    p.send(M(32) + M(32) + M(2, I(2234)))
    frames = c.frames + p.frames
    pcap(os.path.join(out, 'slsk-coverage.pcap'), frames)
    print('%d frames: server connection (port 2234) 1-%d, peer connection (port 2240) %d-%d' %
          (len(frames), n1, n1 + 1, len(frames)))

    # ---- malformed -----------------------------------------------------------------------
    q = TcpConn(50002, 2234, isn_c=1, isn_s=1)
    q.handshake()
    q.send(M(5, b'this is not zlib data at all'), client=False)
    q.send(M(9, b'this is not zlib data at all'), client=False)
    q.send(M(37, b'this is not zlib data at all'), client=False)
    q.send(M(1, S('alice')))                                            # login request without password
    q.send(M(1, B(1)))
    q.send(M(2))                                                        # no port
    q.send(M(3, S('bob'), bytes([1, 2, 3])))                            # trailing / wrong data
    q.send(M(14, S('r'), I(1)))
    q.send(M(18, I(1), S('bob'), S('Q'), B(1)))                        # trailing data
    q.send(M(32, b'extra bytes'))                                       # data after a bodyless message
    q.send(M(41, I(7), B(1), I(1)))                                     # response with a partial size
    q.send(M(93, B(3), I(1), S('alice'), I(99)))                       # truncated embedded search
    q.send(MB(2, I(1), S('alice'), I(99), S('pink floyd')))            # looks like a distributed search, byte is not 3
    q.send(MB(5, S('a'), S('b'), I(1)))                                # byte is not 1
    q.send(MB(9, I(1)))                                                # byte is not 0
    q.send(M(93, B(4), I(1), S('alice'), I(99), S('pink floyd')))      # embedded message of another type
    q.send(M(65, S('bob'), I(7), S('file.mp3'), S('x'), I(1), I(2), I(3)))   # isissiii: 16 octets are added for 12
    q.send(M(9, zlib.compress(search_result('alice'))))                  # user name is read as 4 raw octets
    q.send(M(9, zlib.compress(S('') + I(1) + I(1) + B(1) + S('f'))))                      # cut short
    q.send(M(41, I(7), B(0), I(1)))                                     # iibi: matches no format
    q.send(M(67, I(0)))                                                 # matches no format
    # list counts larger than the data that follows
    for code in (54, 56, 64, 69, 102, 110):
        q.send(M(code, I(3)))
        q.send(M(code, I(3), S('a'), I(1)))
    for code in (57, 58, 111, 112):
        q.send(M(code, S('x'), I(3)))
        q.send(M(code, S('x'), I(3), S('a')))
    for code in (14, 67):
        q.send(M(code, S('room'), I(2), S('a')))
        q.send(M(code, S('room'), I(1), S('a'), I(3), I(1)))
        q.send(M(code, S('room'), I(1), S('a'), I(1), I(1), I(3), I(1)))
        q.send(M(code, S('room'), I(1), S('a'), I(1), I(1), I(1), I(1), I(1), I(1), I(1), I(1), I(1), I(3), I(1)))
    for body in (I(3) + S('d') + I(1),                                           # directory without its file count
                 I(1) + S('d') + I(2) + fileent('a', 0),                          # second file missing
                 I(1) + S('d') + I(1) + B(1) + S('f') + I(1) + I(2) + S('mp3') + I(3) + I(0) + I(1)):   # attributes missing
        q.send(M(5, zlib.compress(body)))
    for body in (S('') + I(1) + I(2) + fileent('a', 0),
                 S('') + I(1) + I(1) + B(1) + S('f') + I(1) + I(2) + S('mp3') + I(3) + I(0) + I(1)):
        q.send(M(9, zlib.compress(body)))
    for body in (I(1) + S('d') + I(2) + S('d') + I(1),
                 I(1) + S('d') + I(1) + S('d') + I(2) + fileent('a', 0),
                 I(1) + S('d') + I(1) + S('d') + I(1) + B(1) + S('f') + I(1) + I(2) + S('mp3') + I(3) + I(0) + I(1)):
        q.send(M(37, zlib.compress(body)))
    q.send(M(60))
    q.send(M(0))
    q.send(MB(0xff, b''))
    q.send(I(0xffff0000) + I(3))                                       # huge length
    pcap(os.path.join(out, 'slsk-coverage-malformed.pcap'), q.frames)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
