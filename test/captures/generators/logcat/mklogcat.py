#!/usr/bin/env python3
# Generates test/captures/logcat_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the Logcat coverage captures. Usage: mklogcat.py <outdir>

logcat-coverage.pcap: Exported PDU frames naming "logcat" (the way the
logcat file reader and Export PDU hand records to the dissector) with
binary logger entries of version 1 and 2, plus logcat-coverage-tcp.pcap with two TCP
frames that need "Decode As" tcp.port 5037 -> logcat (runcov.sh does that).
logcat-coverage.logcat: the version 1 entries as a logcat binary file.
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

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def tcp_eth(payload, sport=40000, dport=5037, seq=1):
    src = bytes([192,0,2,1]); dst = bytes([192,0,2,2])
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 0x50, 0x18, 65535, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + tcp

def v1(prio, tag, msg, pid=100, tid=101, sec=1700000000, nsec=123456789,
       length=None, padding=0, nul=True):
    """version 1 entry: length, padding, pid, tid, sec, nsec, payload"""
    body = bytes([prio]) + tag + b'\0' + msg + (b'\0' if nul else b'')
    if length is None:
        length = len(body)
    return struct.pack('<HHiiii', length, padding, pid, tid, sec, nsec) + body

def v2(prio, tag, msg, pid=100, tid=101, sec=1700000000, nsec=5, euid=1000,
       length=None, hdr=24, nul=True):
    """version 2 entry: length, header size 24, pid, tid, sec, nsec, euid"""
    body = bytes([prio]) + tag + b'\0' + msg + (b'\0' if nul else b'')
    if length is None:
        length = len(body)
    return struct.pack('<HHiiiii', length, hdr, pid, tid, sec, nsec, euid) + body

def main(out):
    f = []
    # Version 1, every priority (0-8) and one beyond the table
    for prio in range(10):
        f.append(v1(prio, b'ActivityManager', b'priority %d message' % prio,
                    pid=1000 + prio, tid=2000 + prio, sec=1700000000 + prio))
    # Version 2 (header size 24, euid)
    for prio in (2, 3, 4, 5, 6, 7):
        f.append(v2(prio, b'SurfaceFlinger', b'v2 priority %d' % prio,
                    pid=300 + prio, euid=10000 + prio))
    # Multi-line messages: the Info column shows one line, the Log
    # subtree has one line per text line (data-text-lines); CR and LF
    f.append(v1(6, b'AndroidRuntime', b'FATAL EXCEPTION: main\nProcess: com.example, PID: 4321\n'
                b'java.lang.RuntimeException: boom\r\n\tat com.example.Main.run(Main.java:10)\r\n'))
    f.append(v2(6, b'AndroidRuntime', b'second\nthird\r\nfourth'))
    # Empty message with the terminating NUL, and no message at all
    f.append(v1(4, b'Empty', b''))
    f.append(v1(4, b'NoMessage', b'', nul=False))
    f.append(v2(4, b'Empty2', b''))
    # Empty tag
    f.append(v1(3, b'', b'message with empty tag'))
    # Non-ASCII and invalid UTF-8 in tag and message
    f.append(v1(4, 'Täg'.encode(), 'mässage ☃ snowman'.encode()))
    f.append(v1(4, b'Bad\xff\xfetag', b'bad \xff\xfe\xfd utf-8'))
    # A version 2 header size (24) in a version 1 entry whose payload is too
    # short for it: detected as version 1
    f.append(v1(4, b'Looks', b'like v2', padding=24))
    # Message without the terminating NUL (it ends with the frame), and a
    # length field smaller than the data: the message is cut short and the
    # rest of the frame is not dissected
    f.append(v1(4, b'NoNul', b'message ends with the frame', nul=False))
    f.append(v1(4, b'Trail', b'short length', length=1 + 6 + 13 - 3) + b'tail')
    # Tag longer than the payload length (expert info, no log)
    f.append(v1(4, b'T' * 40, b'x', length=10))
    # The reproducers of "Logcat: Fix quadratic newline replacement and
    # length handling": large messages made of newlines (and CR) and
    # of letters (baseline)
    big = 65535 - 1 - 2
    f.append(v1(4, b'T', b'\n' * (big - 1), length=65535 - 1))
    f.append(v1(4, b'T', b'\r\n' * ((big - 1) // 2), length=65535 - 1))
    f.append(v1(4, b'T', b'A' * (big - 1), length=65535 - 1))
    # Same tag and message in many frames (the source address is the tag)
    for i in range(3):
        f.append(v1(5, b'WifiService', b'scan %d' % i, sec=1700000100 + i))
    pkts = [exp_pdu('logcat', x) for x in f]
    pcap(os.path.join(out, 'logcat-coverage.pcap'), pkts)
    # TCP stream on port 5037 (adb), needs Decode As
    tcp = [tcp_eth(v1(4, b'adb', b'over tcp', pid=1, tid=1), seq=1),
           tcp_eth(v2(5, b'adb', b'v2 over tcp', pid=1, tid=1), seq=1000)]
    pcap(os.path.join(out, 'logcat-coverage-tcp.pcap'), tcp, linktype=1)
    # binary file of version 1 entries
    with open(os.path.join(out, 'logcat-coverage.logcat'), 'wb') as fh:
        for prio in range(2, 8):
            fh.write(v1(prio, b'FileTag', b'file entry %d' % prio, sec=1700000000 + prio))
    # Malformed: exceptions
    bad = []
    bad.append(v1(4, b'T', b'hdr only')[:10])                # header truncated
    bad.append(v1(4, b'T', b'x')[:20])                       # no priority
    bad.append(v1(4, b'NoNulTag', b'', nul=False)[:-1])      # tag without NUL
    bad.append(v1(4, b'T', b'msg', length=200))              # length beyond frame
    bad.append(v2(4, b'T', b'msg', length=200))
    bad.append(v2(4, b'T', b'msg')[:26])                     # v2 header truncated
    bad.append(v1(4, b'Tag', b'msg', length=1))              # length smaller than the tag
    pcap(os.path.join(out, 'logcat-coverage-malformed.pcap'), [exp_pdu('logcat', x) for x in bad])
    print(len(pkts), len(bad))

main(sys.argv[1])
