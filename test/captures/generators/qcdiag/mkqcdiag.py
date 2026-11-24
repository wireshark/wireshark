#!/usr/bin/env python3
# Generates test/captures/qcdiag_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the QCDIAG coverage captures. Usage: mkqcdiag.py <outdir>
All frames are Ethernet/IPv4/UDP 4729 (GSMTAP, type 0x11 QC_DIAG)."""
import struct
import sys
import os

def ip_csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def udp_frame(payload, n, dport=4729, sport=40000):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    iph = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), n + 1, 0, 64, 17, 0,
                      bytes([192,0,2,1]), bytes([192,0,2,2]))
    iph = iph[:10] + struct.pack('!H', ip_csum(iph)) + iph[12:]
    return bytes([2,0,0,0,0,2, 2,0,0,0,0,1]) + b'\x08\x00' + iph + udp

def gsmtap(diag):
    return struct.pack('!BBBBHbbIBBBB', 2, 4, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0) + diag

def write_pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def qc_log(code, data, ts=0, more=0):
    rec = struct.pack('<HHQ', 12 + len(data), code, ts) + data
    return struct.pack('<BBH', 0x10, more, len(rec)) + rec

def hdr(op, res=b'\0\0\0'):
    return struct.pack('<B3sI', 115, res, op)

def main(out):
    good, bad = [], []
    G = lambda d: good.append(d)
    B = lambda d: bad.append(d)
    # --- main capture ---
    # frame 1/2: version request/response
    G(bytes([0]))
    G(bytes([0]) + b'Mar  1 2020' + b'12:34:56' + b'Apr 10 2020' + b'01:02:03' + b'V1.2.3  '
      + bytes([0x40, 0x05, 0x11]) + struct.pack('<H', 0x0102) + bytes([2]) + bytes([1, 0x23]))
    G(bytes([1]))                                   # ESN request
    G(bytes([1]) + struct.pack('<I', 0x12345678))   # ESN response
    G(bytes([16, 0]))                               # log request
    G(bytes([19]) + b'\x01\x02\x03')                # bad cmd
    G(bytes([20]) + b'\x04\x05')                    # bad parm
    G(bytes([21]) + b'\x06')                        # bad len
    G(bytes([24]) + b'\x07\x08')                    # bad mode
    G(bytes([27]))                                  # markov reset (response form)
    G(bytes([28]))                                  # diag version request
    G(bytes([28]) + struct.pack('<H', 8))           # diag version response
    G(bytes([29]))                                  # timestamp request
    G(bytes([29]) + struct.pack('<Q', 0x0000123456789abc))   # timestamp response
    G(bytes([29]) + struct.pack('<Q', 0xffffffffffffffff))   # reproducer: huge timestamp (UB cast)
    G(bytes([36]) + struct.pack('<Q', 0x0000000100000000))   # parm set response
    G(bytes([41]) + struct.pack('<H', 4))           # mode change
    G(bytes([41]) + struct.pack('<H', 2))
    # subsystem dispatcher: request (4 bytes) and responses
    G(bytes([75, 0x04]) + struct.pack('<H', 0x0001))
    G(bytes([75, 0x0b]) + struct.pack('<H', 0x0002) + b'payload')
    G(bytes([75, 0xfe]) + struct.pack('<H', 0x0003) + b'\x01\x02')      # unknown subsystem
    G(bytes([75, 0x08]) + struct.pack('<H', 0x0004))                    # WCDMA? request
    # log configuration
    G(hdr(0))                                                           # disable req
    G(hdr(0) + struct.pack('<I', 0))                                    # disable resp
    G(hdr(1))                                                           # id ranges req
    G(hdr(1) + struct.pack('<I', 0) + b''.join(struct.pack('<I', v) for v in
        (0, 0x100, 0x1c2, 0, 0x10, 0, 0, 0, 0x200, 0, 0, 0, 0, 0, 0, 0x300)))   # ranges (fixed)
    G(hdr(1) + struct.pack('<I', 1) + struct.pack('<I', 0x103) + struct.pack('<I', 0x104))
    G(hdr(2))                                                           # valid mask (no decoder)
    G(hdr(5) + b'\0\0')                                                 # unknown operation
    mask = bytes([0x05, 0, 0x80, 0xff, 0x01])
    G(hdr(3) + struct.pack('<II', 5, len(mask) * 8 - 8 + 1) + mask)    # set mask request
    G(hdr(3) + struct.pack('<III', 0, 4, 12) + bytes([0x03, 0x10]))    # set mask response
    G(hdr(4) + struct.pack('<I', 5))                                    # get mask request
    G(hdr(4) + struct.pack('<II', 5, 24) + bytes([1, 0, 0x40]))         # get mask response
    # log on demand request/response
    G(bytes([120]) + struct.pack('<H', 0x412f))
    G(bytes([120]) + struct.pack('<HB', 0x412f, 0) )
    for st in (1, 2, 3, 4):
        G(bytes([120]) + struct.pack('<HB', 0x5000 + st, st))
    G(bytes([123]) + b'loop' * 4)                                       # protocol loopback
    G(bytes([124]))                                                     # ext build id request
    G(bytes([124, 2, 0, 0]) + struct.pack('<II', 0x10002000, 0x20003000) + b'SWREV-1.0\0MODEL-X\0')
    G(bytes([124, 1, 0, 0]) + struct.pack('<II', 1, 2) + b'\0\0')       # both empty
    G(bytes([124, 0, 0, 0]) + struct.pack('<II', 1, 2) + b'swrev only\0nomodelnul')
    G(bytes([124, 0, 0, 0]) + struct.pack('<II', 1, 2) + b'nonul')
    # custom (DIAG_MAX_F = 0xff) messages
    G(bytes([255, 16]))                                                 # custom request
    G(bytes([255, 0]) + b'hello\nworld\n')
    G(bytes([255, 29, 0, 0]) + b'text line 1\ntext line 2\n')
    G(bytes([255, 200, 0, 0]) + b'unknown cmd text\n')
    G(bytes([255]) + qc_log(0x4125, b"\x05"))                            # custom log
    # unknown top-level commands go to the table (no dissector) -> data
    G(bytes([0x7e, 1, 2, 3]))
    G(bytes([2]) + b'peek')
    # Get Log responses: qcdiag_log handles these (separate capture)
    G(qc_log(0x4125, b'\x01', ts=0x0000100000000123))
    G(qc_log(0xffff, b'\xaa\xbb'))                                      # unknown logcode
    # --- reproducers of fixed bugs (see README) ---
    # F-ranges: log config ID ranges read as 4-byte values
    G(hdr(1) + struct.pack('<I', 0) + b''.join(struct.pack('<I', 0x100 + i) for i in range(4)))
    # set mask request whose last item bit count is large but mask present
    G(hdr(3) + struct.pack('<II', 3, 0x10) + b'\x01\x02')
    # --- malformed capture ---
    B(bytes([75, 0x04]))                                                # subsys len 2
    B(bytes([75, 0x04, 0x01]))                                          # subsys len 3
    B(hdr(3) + struct.pack('<III', 0, 1, 0xffffffff) + b'\x01\x02\x04')
    B(hdr(3) + struct.pack('<III', 0, 1, 0xfffffff0) + b'\0' * 2000)
    B(bytes([0]) + b'A' * 47)                                           # truncated verno response
    B(bytes([255, 16]) + b'x' * 0)                                      # custom len 2 (request)
    B(bytes([255]))                                                     # custom len 1
    B(bytes([16]))                                                      # log len 1
    B(bytes([1, 0x12]))                                                 # esn truncated
    B(bytes([36]))                                                      # parm set "request" form
    B(bytes([36, 1, 2, 3]))                                             # parm set short response
    B(bytes([41]))                                                      # mode change no data
    B(bytes([120, 0x12]))                                               # log on demand truncated
    B(bytes([115, 0, 0, 0]))                                            # log config truncated
    B(bytes([115, 0, 0, 0, 1]))                                         # log config op, no body
    B(bytes([115, 0, 0, 0, 3, 0, 0, 0] ))                               # setmask truncated
    B(bytes([115, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0]))                    # getmask req
    B(bytes([115, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]))
    B(bytes([29]) + b'\x01\x02')                                        # ts truncated
    B(bytes([28, 1]))                                                   # diag ver truncated
    B(bytes([124, 0]))                                                  # ext build truncated
    B(bytes([75]))
    B(bytes([75, 8, 1]))
    B(bytes([16, 0, 2]) )
    B(qc_log(0x4125, b'')[:12])
    os.makedirs(out, exist_ok=True)
    write_pcap(os.path.join(out, 'qcdiag-coverage.pcap'), [udp_frame(gsmtap(d), i) for i, d in enumerate(good)])
    write_pcap(os.path.join(out, 'qcdiag-coverage-malformed.pcap'), [udp_frame(gsmtap(d), i) for i, d in enumerate(bad)])
    print(len(good), len(bad))

main(sys.argv[1] if len(sys.argv) > 1 else '.')
