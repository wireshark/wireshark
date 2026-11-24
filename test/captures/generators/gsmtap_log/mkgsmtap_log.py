#!/usr/bin/env python3
# Generates test/captures/gsmtap_log_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic GSMTAP_LOG coverage captures.

GSMTAP type 0x10 (libosmocore logging) over UDP port 4729 (registered by
default) carries an 84 octet log record header and the message text.
Usage: mkgsmtap_log.py <output directory>
Writes gsmtap_log-coverage.pcap and gsmtap_log-coverage-malformed.pcap.
Everything is built with struct; nothing comes from a real network.
"""
import os
import socket
import struct
import sys

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def udp_frame(payload, sport=45123, dport=4729, src='192.0.2.1', dst='192.0.2.2'):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ps = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 17, len(udp))
    udp = udp[:6] + struct.pack('>H', csum(ps + udp) or 0xffff) + udp[8:]
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + udp

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)

def gsmtap(type_, payload, sub_type=0, arfcn=0, ts=0, fn=0, hdrlen_words=4):
    return struct.pack('>BBBBHbBIBBBB', 2, hdrlen_words, type_, ts, arfcn, 0, 0,
                       fn, sub_type, 0, 0, 0) + payload

def padded(s, n):
    return s.encode()[:n].ljust(n, b'\0')

def record(ident, pid, level, subsys, fname, line, text, sec=1700000000, usec=123456,
           raw_text=None):
    body = struct.pack('>II', sec, usec) + padded(ident, 16) + struct.pack('>IB', pid, level)
    body += b'\0\0\0' + padded(subsys, 16) + padded(fname, 32) + struct.pack('>I', line)
    return body + (raw_text if raw_text is not None else text.encode())

def log_frame(*a, **kw):
    return udp_frame(gsmtap(0x10, record(*a, **kw)))

def main_frames():
    f = []
    # frames 1-5: every log level the dissector names
    for lvl, name in ((1, 'DEBUG'), (3, 'INFO'), (5, 'NOTICE'), (7, 'ERROR'), (8, 'FATAL')):
        f.append(log_frame('osmo-bts-trx', 1000 + lvl, lvl, 'DL1C', 'l1_if.c', 100 + lvl,
                           '%s message from the BTS\n' % name, usec=lvl * 1000))
    # 6: a level the value string does not know
    f.append(log_frame('osmo-bsc', 77, 2, 'DRSL', 'abis_rsl.c', 3141, 'level 2 is unnamed\n'))
    # 7: empty message
    f.append(log_frame('osmo-msc', 1, 3, 'DMM', 'gsm_04_08.c', 1, ''))
    # 8: identifier and subsystem fill all 16 octets, file name all 32 (no NUL)
    f.append(log_frame('0123456789abcdef', 4000000000, 5, 'ABCDEFGHIJKLMNOP',
                       'f' * 30 + '.c', 4294967295, 'full width fields'))
    # 9: long message, with an embedded NUL and trailing NUL padding
    f.append(log_frame('osmo-pcu', 2, 7, 'DPCU', 'pcu_main.cpp', 42, '',
                       raw_text=(b'X' * 300) + b'\0abc\0\0\0'))
    # 10: message with non-ASCII bytes and control characters
    f.append(log_frame('osmo-sgsn', 3, 1, 'DGPRS', 'gprs_llc.c', 9, '',
                       raw_text=b'tab\there \x01\x02 caf\xc3\xa9 \xff\xfe\n'))
    # 11: the same log record behind a longer GSMTAP header (hdr_len 6 words)
    f.append(udp_frame(gsmtap(0x10, b'\xde\xad\xbe\xef\x00\x00\x00\x00' +
                              record('osmo-hlr', 5, 3, 'DDB', 'db.c', 5, 'longer GSMTAP header'),
                              hdrlen_words=6)))
    # 12: UDP source port 4729 as well (osmocom tools use it for both)
    f.append(udp_frame(gsmtap(0x10, record('osmo-stp', 6, 3, 'DLSS7', 'xua.c', 6, 'port 4729')),
                       sport=4729))
    # 13: log record on a GSMTAP header with channel/ARFCN fields filled
    f.append(udp_frame(gsmtap(0x10, record('osmo-mgw', 7, 3, 'DLMGCP', 'mgcp.c', 7, 'with ARFCN'),
                              sub_type=0x0b, arfcn=0x4011, ts=3, fn=123456)))
    return f

def malformed_frames():
    full = record('osmo-bts', 1, 3, 'DL1C', 'l1.c', 5, 'text')
    # every cut inside the 84 octet record header: after the time stamp,
    # identifier, pid, level, pad, subsystem, file name, line number
    return [udp_frame(gsmtap(0x10, full[:n])) for n in (0, 4, 8, 20, 24, 25, 28, 40, 60, 80, 83)]

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'gsmtap_log-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'gsmtap_log-coverage-malformed.pcap'), malformed_frames())

main()
