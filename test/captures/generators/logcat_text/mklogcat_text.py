#!/usr/bin/env python3
# Generates test/captures/logcat_text_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the Logcat Text coverage captures. Usage: mklogcat_text.py <outdir>

logcat_text-coverage.pcap: Exported PDU frames naming one of the seven
"logcat_text_*" dissectors (brief, tag, process, time, thread, threadtime,
long), with the record the logcat text file reader produces (the line with
its newline and a terminating NUL).
textfiles/<format>.log: text files of every format for the real file
reader (runcov.sh).
"""
import os
import struct
import sys

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    tags = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0)
    return tags + payload

def pcap(path, pkts, linktype=252):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

PRIOS = 'IVDWEF'
TIMES = ['01-02 03:04:05.678', '12-31 23:59:59.999', '06-15 12:00:00.000',
         '02-29 00:00:01.001', '07-04 09:08:07.006', '11-11 11:11:11.111']

def rec(line):
    return line.encode() + b'\n\0'

def frames():
    """list of (dissector, bytes)"""
    out = []
    def add(d, line):
        out.append(('logcat_text_' + d, rec(line) if isinstance(line, str) else line))
    for i, p in enumerate(PRIOS):
        t = TIMES[i]
        add('brief', '%s/ActivityManager(%5d): Start proc %d:com.example/u0a%d' % (p, 1000 + i, i, i))
        add('tag', '%s/WifiService: scan result %d' % (p, i))
        add('process', '%s(%5d) process message %d  ()' % (p, 200 + i, i))
        add('time', '%s %s/SurfaceFlinger(%5d): vsync %d' % (t, p, 300 + i, i))
        add('thread', '%s(%5d:%5d) thread message %d' % (p, 400 + i, 500 + i, i))
        add('threadtime', '%s %5d %5d %s Binder: transaction %d' % (t, 600 + i, 700 + i, p, i))
        add('long', '[ %s %5d:%5d %s/Choreographer ]\nSkipped %d frames!\n' % (t, 800 + i, 900 + i, p, i))
    # "beginning of" lines (the special format) for every dissector
    for d in ('brief', 'tag', 'process', 'time', 'thread', 'threadtime', 'long'):
        add(d, '--------- beginning of main')
    add('brief', '--------- beginning of /system')
    # Empty message, message and tag with non-ASCII (valid UTF-8) and with
    # characters that look like separators
    add('brief', 'I/Empty(   42): ')
    add('tag', 'W/Empty: ')
    add('process', 'D(   42) ')
    add('brief', 'I/Täg(   43): mässage ☃ snowman')
    add('tag', 'E/Täg: 日本語')
    add('time', '01-02 03:04:05.678 I/Tag: with(   1): colon: and (  2): again(  3): x')
    add('brief', 'V/a/b(   44): tag with a slash: and text (  5): more')
    add('tag', 'D/Tag: a: b: c')
    add('thread', 'I(    1:    2) message with (  3:  4) inside')
    add('threadtime', '01-02 03:04:05.678     1     2 I Tag: message: with: colons')
    add('long', '[ 01-02 03:04:05.678     1:    2 I/Tag ]\nline one\nline two\n')
    add('long', '[ 01-02 03:04:05.678  1234: 5678 E/Tag with spaces ]\nmessage\n')
    # Same pid and tag in several records
    for i in range(3):
        add('brief', 'I/Repeat(   99): repeat %d' % i)
    # records that the reader would not hand over with a NUL but a shorter text
    add('brief', b'D/NoNewline(  7): no newline and no NUL')
    return out

def bad_frames():
    out = []
    def add(d, data):
        out.append(('logcat_text_' + d, data))
    # Lines that do not match the format of the dissector (token count)
    for d in ('brief', 'tag', 'process', 'time', 'thread', 'threadtime', 'long'):
        add(d, b'this line has no recognisable format\n\0')
    add('brief', b'I/Tag: tag format given to brief\n\0')
    add('time', b'I/Tag(  1): brief format given to time\n\0')
    add('threadtime', b'01-02 03:04:05.678 I/Tag(  1): time format\n\0')
    add('long', b'[ 01-02 03:04:05.678  1: 2 I/Tag ]\n')   # no message line
    # Invalid UTF-8 (the offsets of the sanitised copy run past the frame)
    add('brief', b'I/' + b'\xff' * 20 + b'(  123): hello')
    add('threadtime', b'01-02 03:04:05.678  1  2 W \xfe\xfe\xfe\xfe: msg')
    add('long', b'[ 01-02 03:04:05.678  1: 2 E/tag ]\nlog line \xff\xfe')
    add('tag', b'W/\xc3: bad lead byte')
    add('process', b'E(   5) \xff\xff\xff\xff\xff\xff')
    add('time', b'01-02 03:04:05.678 I/\x80\x80\x80(  1): x')
    return out

def main(out):
    pcap(os.path.join(out, 'logcat_text-coverage.pcap'),
         [exp_pdu(d, p) for d, p in frames()])
    pcap(os.path.join(out, 'logcat_text-coverage-malformed.pcap'),
         [exp_pdu(d, p) for d, p in bad_frames()])
    os.makedirs(os.path.join(out, 'textfiles'), exist_ok=True)
    for d in ('brief', 'tag', 'process', 'time', 'thread', 'threadtime', 'long'):
        with open(os.path.join(out, 'textfiles', d + '.log'), 'wb') as f:
            for dd, p in frames():
                if dd == 'logcat_text_' + d:
                    f.write(p.rstrip(b'\0') if d != 'long' else p.rstrip(b'\0') + b'\n')
    print(len(frames()), len(bad_frames()))

main(sys.argv[1])
