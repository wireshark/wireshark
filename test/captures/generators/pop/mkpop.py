#!/usr/bin/env python3
# Generates test/captures/pop_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the POP coverage captures. Usage: mkpop.py <outdir> [-v]
# POP is registered on TCP port 110 (default), so no Decode As is needed.
import os
import sys
from pcaplib import Tcp, write_pcap

MSG1 = (b'From: alice@example.com\r\nTo: bob@example.com\r\nSubject: first\r\n'
        b'Date: Mon, 02 Nov 2026 10:00:00 +0000\r\nMessage-ID: <1@example.com>\r\n\r\nHello Bob.\r\n')
MSG2 = (b'From: carol@example.com\r\nTo: bob@example.com\r\nSubject: second\r\n'
        b'MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nSecond message body.\r\n.\r\n')

def split(b, n):
    return [b[i:i + n] for i in range(0, len(b), n)]

def session(port, fn):
    t = Tcp(port, 110)
    F = []
    c = lambda d: F.append(t.c2s(d if isinstance(d, bytes) else d.encode()))
    s = lambda d: F.append(t.s2c(d if isinstance(d, bytes) else d.encode()))
    fn(c, s)
    return F

def main_frames():
    F, marks = [], []
    def mark(n): marks.append((n, len(F) + 1))
    mark('session 1: greeting, USER, PASS (credentials), STAT, LIST, UIDL (split response), RETR over three segments (reassembled and decoded as IMF), TOP, NOOP, an -ERR, QUIT')
    def s1(c, s):
        s('+OK POP3 server ready <1896.697170952@example.com>\r\n')
        c('USER alice\r\n'); s('+OK\r\n')
        c('USER again\r\n'); s('-ERR already given\r\n')
        c('PASS s3cret\r\n'); s('+OK maildrop locked and ready\r\n')
        c('STAT\r\n'); s('+OK 2 320\r\n')
        c('LIST\r\n'); s('+OK 2 messages (320 octets)\r\n1 120\r\n2 200\r\n.\r\n')
        c('UIDL\r\n'); s('+OK\r\n1 whqtswO00WBw418f9t5JxYwZ\r\n'); s('2 QhdPYR:00WBw1Ph7x7\r\n.\r\n')
        total = len(MSG1)
        c('RETR 1\r\n'); s('+OK %d octets\r\n' % total)
        for part in split(MSG1, (total + 2) // 3): s(part)
        c('top 2 0\r\n'); s('+OK %d octets\r\n' % len(MSG2))
        for part in split(MSG2, 70): s(part)
        c('NOOP\r\n'); s('+OK\r\n')
        c('DELE 7\r\n'); s('-ERR no such message\r\n')
        c('XFOO\r\n'); s('-ERR unknown command\r\n')
        c('RETR 3\r\n'); s('-ERR no such message\r\n')
        c('LIST 1\r\n'); s('+OK 1 120\r\n')
        c('QUIT\r\n'); s('+OK bye\r\n')
    F += session(40001, s1)
    mark('session 2: PASS before USER, a RETR that fits one response segment, a response that is neither +OK nor -ERR')
    def s2(c, s):
        s('+OK ready\r\n')
        c('PASS early\r\n'); s('-ERR USER first\r\n')
        c('RETR 1\r\n'); s('+OK %d octets\r\n' % len(MSG1)); s(MSG1)
        c('CAPA\r\n'); s('+OK Capability list follows\r\nTOP\r\nUSER\r\nSTLS\r\n.\r\n')
        c('STAT\r\nNOOP\r\n'); s('garbage without an indicator\r\n')
        c('QUIT\r\n'); s('+OK')
    F += session(40002, s2)
    mark('session 3: STLS, TLS is started after the +OK')
    def s3(c, s):
        s('+OK ready\r\n')
        c('STLS\r\n'); s('+OK Begin TLS negotiation\r\n')
    F += session(40003, s3)
    mark('session 4: STLS refused, then USER with an empty argument')
    def s4(c, s):
        s('+OK ready\r\n')
        c('STLS\r\n'); s('-ERR not available\r\n')
        c('USER\r\n'); s('-ERR\r\n')
        c('USER  \r\n'); s('+OK\r\n')
    F += session(40004, s4)
    return F, marks

def malformed_frames():
    F = []
    def s5(c, s):
        s('+OK ready\r\n')
        c('RETR 1\r\n'); s('+OK message follows\r\n')              # no length: expert error
        s(MSG1)
        c('TOP 1 1\r\n'); s('+OK 5 octets\r\n')
        s(b'abc')                                                  # fragment shorter than the announced length
        s(b'abcdefghij')                                           # more than announced
        c('RETR 2\r\n'); s('+OK \r\n')                              # a +OK with nothing after the blank
    F += session(40005, s5)
    return F

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    F, marks = main_frames()
    write_pcap(os.path.join(out, 'pop-coverage.pcap'), F)
    M = malformed_frames()
    write_pcap(os.path.join(out, 'pop-coverage-malformed.pcap'), M)
    if '-v' in sys.argv:
        for n, s_ in marks: print(s_, n)
        print(len(F), 'frames', len(M), 'malformed frames')
