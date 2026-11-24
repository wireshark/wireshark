#!/usr/bin/env python3
# Generates test/captures/syslog_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Syslog coverage captures. Usage: mksyslog.py <outdir> [-v]
Writes syslog-coverage.pcap (main) and syslog-coverage-malformed.pcap.
UDP port 514 is registered by default. Syslog over TCP (octet counting
framing, RFC 6587) is only reachable through Decode As ("syslog"):
the TCP frames use port 10514 and the tests/runcov.sh pass
-d tcp.port==10514,syslog. Everything is synthetic (192.0.2.0/24)."""
import os
import sys
from pcaplib import TcpFlow, udp, write_pcap

def u(msg, sport=40000):
    return udp(sport, 514, msg if isinstance(msg, bytes) else msg.encode())

def frame(msg):
    """RFC 6587 octet counting frame."""
    return b'%d ' % len(msg) + msg

def main_frames():
    F = []; R = {}
    def add(name, fr):
        R[name] = len(F) + 1; F.append(fr)
    # RFC 5424 (RFC examples and variations)
    add('5424-bom', u(b'<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - \xef\xbb\xbf\'su root\' failed for lonvick on /dev/pts/8'))
    add('5424-nobom', u('<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It\'s time to make the do-nuts.'))
    add('5424-sd', u(b'<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] \xef\xbb\xbfAn application event log entry...'))
    add('5424-sd2', u('<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][examplePriority@32473 class="high"]'))
    add('5424-sd-then-msg', u('<165>1 2003-10-11T22:14:15.003Z host app 1 ID1 [a@1 k="v"][b@1 x="y" z="w"] message text'))
    add('5424-sd-noparams', u('<14>1 2020-01-02T03:04:05Z host app 2 ID2 [empty@1 ] text'))
    add('5424-sd-nameonly', u('<14>1 2020-01-02T03:04:05Z host app 2 ID2 [nameonly] text'))
    add('5424-sd-noeq', u('<14>1 2020-01-02T03:04:05Z host app 2 ID2 [a@1 noequalsign] text'))
    add('5424-sd-noquote', u('<14>1 2020-01-02T03:04:05Z host app 2 ID2 [a@1 k=unquoted] text'))
    add('5424-sd-onequote', u('<14>1 2020-01-02T03:04:05Z host app 2 ID2 [a@1 k="open] text'))
    add('5424-sd-badstart', u('<14>1 2020-01-02T03:04:05Z host app 2 ID2 notsd text'))
    add('5424-sd-unterminated', u('<14>1 2020-01-02T03:04:05Z host app 2 ID2 [a@1 k="v" text'))
    add('5424-sd-at-end', u('<14>1 2020-01-02T03:04:05Z host app 2 ID2 [a@1 k="v"]'))
    add('5424-empty-ts', u('<14>1  host app 2 ID2 - msg'))
    add('5424-nil-all', u('<14>1 - - - - - - msg'))
    add('5424-short', u('<14>1 2020-01-02T03:04:05Z host'))
    add('5424-ts-only', u('<14>1 2020-01-02T03:04:05Z'))
    add('5424-host-app', u('<14>1 2020-01-02T03:04:05Z host app'))
    add('5424-host-app-pid', u('<14>1 2020-01-02T03:04:05Z host app 77'))
    add('5424-host-app-pid-id', u('<14>1 2020-01-02T03:04:05Z host app 77 ID9'))
    add('5424-no-pri', u('1 2020-01-02T03:04:05Z host app 2 ID2 - no priority'))
    # RFC 3164
    add('3164', u("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"))
    add('3164-nopri', u('Oct 11 22:14:15 mymachine sshd[1234]: Accepted publickey'))
    add('3164-tag32', u('<13>Oct 11 22:14:15 host ' + 'a' * 31 + ' msg'))
    add('3164-nohost', u('<13>Oct 11 22:14:15 '))
    add('3164-nontimestamp', u('<13>This is some text that is not a timestamp at all'))
    add('3164-short', u('<13>short message'))
    add('plain', u('no priority and no timestamp, long enough to count as plain text'))
    # PRI variants
    for p in (0, 1, 7, 8, 15, 16, 23, 24, 31, 38, 79, 87, 95, 104, 111, 120, 128, 129, 135, 136, 143, 151, 159, 167, 175, 183, 191, 192, 200, 255, 999):
        add('pri%d' % p, u('<%d>Oct 11 22:14:15 host app: priority %d' % (p, p)))
    add('pri4digits', u('<1234>Oct 11 22:14:15 host app: four digit priority'))
    add('pri-nogt', u('<13Oct 11 22:14:15 host app: missing close'))
    add('pri-empty', u('<>Oct 11 22:14:15 host app: empty priority'))
    # SS7 MSU in LOCAL0.DEBUG (pri 135)
    msu = bytes.fromhex('85' '01002000' '0500' '10' '00')   # ISUP RLC, CIC 5, no optional parameters
    add('msu', u('<135>Oct 11 22:14:15 itp1 msu=' + msu.hex()))
    add('msu-odd', u('<135>Oct 11 22:14:15 itp1 msu=' + msu.hex() + 'a'))
    add('msu-badhex', u('<135>Oct 11 22:14:15 itp1 msu=zz11'))
    add('msu-empty', u('<135>Oct 11 22:14:15 itp1 msu='))
    add('msu-other-level', u('<134>Oct 11 22:14:15 itp1 msu=' + msu.hex()))
    add('msu-nomarker', u('<135>Oct 11 22:14:15 itp1 no marker here'))
    # Octet counting framing in UDP, including the reproducer of the fix
    m = b'<13>1 2003-10-11T22:14:15.003Z host app - - - '
    m98 = m + b'x' * (98 - len(m))
    add('framed-repro-98', u(b'98 ' + m98))
    add('framed-small', u(frame(b'<14>1 2020-01-02T03:04:05Z host app 2 ID2 - framed')))
    add('framed-9', u(frame(b'<13>hello')))
    add('framed-nomsg-pri', u(frame(b'plain framed text without priority')))
    add('digits-nospace', u('123abc and some more text to make it long enough'))
    add('zero-lead', u('0 <13>zero length prefix is not framing'))
    # Octet counting framing over TCP (Decode As), port 10514
    fl = TcpFlow(41000, 10514)
    F += fl.handshake(); R['tcp-handshake'] = len(F) - 2
    msgs = [b'<34>1 2003-10-11T22:14:15.003Z mymachine su - ID47 - \'su root\' failed',
            b'<165>1 2003-10-11T22:14:15.003Z host app 5 ID1 [a@1 k="v"] second']
    add('tcp-two-in-one', fl.c2s(frame(msgs[0]) + frame(msgs[1])))
    big = b'<14>1 2020-01-02T03:04:05Z host app 2 ID2 - ' + b'B' * 3000
    fr = frame(big)
    add('tcp-split-1', fl.c2s(fr[:1000]))
    add('tcp-split-2', fl.c2s(fr[1000:2500]))
    add('tcp-split-3', fl.c2s(fr[2500:]))
    add('tcp-repro-98', fl.c2s(b'98 ' + m98))
    long5 = b'<14>Oct 11 22:14:15 host app: ' + b'L' * 10020
    fr = frame(long5)
    add('tcp-5digit-1', fl.c2s(fr[:4000]))
    add('tcp-5digit-2', fl.c2s(fr[4000:9000]))
    add('tcp-5digit-3', fl.c2s(fr[9000:]))
    add('tcp-unframed', fl.c2s(b'<13>Oct 11 22:14:15 host app: not framed, newline delimited\n'))
    add('tcp-unframed-2', fl.c2s(b'<13>Oct 11 22:14:15 host app: second line\n'))
    add('tcp-framed-3164', fl.s2c(frame(b'<30>Oct 11 22:14:15 host app[99]: reply direction')))
    F += fl.fin()
    return F, R

def malformed_frames():
    F = []; R = {}
    def add(name, fr):
        R[name] = len(F) + 1; F.append(fr)
    add('pri-only', u('<13>'))
    add('lt-only', u('<'))
    add('digits-only-pri', u('<13'))
    add('3164-tag-unterminated', u('<13>Oct 11 22:14:15 host abcdef'))
    add('3164-ts-truncated', u('<13>Oct 11 22:14'))   # msg_len <= 15 -> only message
    add('3164-hostname-only', u('<13>Oct 11 22:14:15 hostonly'))
    add('5424-version-only', u('<13>1 '))
    add('5424-sd-cut', u('<13>1 2020-01-02T03:04:05Z host app 1 ID [a@1 k="v'))
    add('5424-sd-nil-cut', u('<13>1 2020-01-02T03:04:05Z host app 1 ID -'))
    add('5424-sd-empty', u('<13>1 2020-01-02T03:04:05Z host app 1 ID '))
    add('framed-short', u('50 <13>too short for the announced length'))
    add('framed-digits-only', u('12345 '))
    add('framed-digit-cut', u('5'))
    fl = TcpFlow(41001, 10514)
    F += fl.handshake()
    add('tcp-framed-cut', fl.c2s(b'500 <13>Oct 11 22:14:15 host app: announced 500 but only this'))
    add('tcp-framed-fin', fl.c2s(b'', flags=0x11))
    # The MSG-LEN header split over two segments is not reassembled: the
    # first segment (one digit, no space yet) is taken for an unframed message
    fl = TcpFlow(41002, 10514)
    F += fl.handshake()
    hs = frame(b'<14>1 2020-01-02T03:04:05Z host app 2 ID2 - xy')
    add('tcp-header-split-1', fl.c2s(hs[:1]))
    add('tcp-header-split-2', fl.c2s(hs[1:]))
    return F, R

if __name__ == '__main__':
    out = sys.argv[1]
    F, R = main_frames()
    write_pcap(os.path.join(out, 'syslog-coverage.pcap'), F)
    G, RM = malformed_frames()
    write_pcap(os.path.join(out, 'syslog-coverage-malformed.pcap'), G)
    if '-v' in sys.argv:
        print(len(F), R); print(len(G), RM)
