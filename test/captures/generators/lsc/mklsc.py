#!/usr/bin/env python3
# Generates test/captures/lsc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic LSC (Pegasus Lightweight Stream Control) coverage captures.
# Usage: mklsc.py <outdir>.  Writes lsc-coverage.pcap and
# lsc-coverage-malformed.pcap.  LSC has no registered port: the captures use
# UDP and TCP port 5000, which has to be decoded with
#   -d udp.port==5000,lsc_udp  and  -d tcp.port==5000,lsc_tcp
# (the dissector registers for Decode As only).  Synthetic addresses only.
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
CLI, SRV = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
MACC, MACS = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
PORT = 5000

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(src, dst, proto, l4, ident):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0, 64, proto, 0, src, dst)
    return ip[:10] + struct.pack('!H', csum(ip)) + ip[12:] + l4

def udp(to_server, payload, ident, sport=41000):
    src, dst, m = (CLI, SRV, MACS + MACC) if to_server else (SRV, CLI, MACC + MACS)
    sp, dp = (sport, PORT) if to_server else (PORT, sport)
    u = struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
    ph = src + dst + struct.pack('!BBH', 0, 17, len(u))
    u = u[:6] + struct.pack('!H', csum(ph + u) or 0xffff) + u[8:]
    return m + b'\x08\x00' + ip4(src, dst, 17, u, ident)

class Tcp:
    def __init__(self, sport=41001):
        self.sport = sport
        self.cseq, self.sseq, self.id = 1000, 5000, 1000
    def seg(self, to_server, payload):
        if to_server:
            src, dst, sp, dp, seq, ack, m = CLI, SRV, self.sport, PORT, self.cseq, self.sseq, MACS + MACC
            self.cseq += len(payload)
        else:
            src, dst, sp, dp, seq, ack, m = SRV, CLI, PORT, self.sport, self.sseq, self.cseq, MACC + MACS
            self.sseq += len(payload)
        t = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, 0x50, 0x18, 65535, 0, 0) + payload
        ph = src + dst + struct.pack('!BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
        self.id += 1
        return m + b'\x08\x00' + ip4(src, dst, 6, t, self.id)

def pcap(fname, frames, linktype=1):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

# message builders: version, transaction id, op code, status, stream handle
def hdr(tid, op, stream, status=0, ver=1):
    return struct.pack('>BBBBI', ver, tid, op, status, stream)
def status(tid, stream=1000):          return hdr(tid, 0x03, stream)
def reset(tid, stream=1000):           return hdr(tid, 0x04, stream)
def pause(tid, stop, stream=1000):     return hdr(tid, 0x01, stream) + struct.pack('>i', stop)
def resume(tid, start, num, den, stream=1000):
    return hdr(tid, 0x02, stream) + struct.pack('>ihH', start, num, den)
def jump(tid, start, stop, num, den, op=0x05, stream=1000):
    return hdr(tid, op, stream) + struct.pack('>iihH', start, stop, num, den)
def play(tid, start, stop, num, den, stream=1000):
    return jump(tid, start, stop, num, den, op=0x06, stream=stream)
def reply(tid, op, st, cur, num, den, mode, stream=1000):
    return hdr(tid, op, stream, st) + struct.pack('>ihHB', cur, num, den, mode)

fr = []
n = [0]
def U(to_server, p):
    n[0] += 1
    fr.append(udp(to_server, p, n[0]))

# --- UDP, one message per datagram
U(True, status(1))                                  #  LSC_STATUS
U(True, reset(2))                                   #  LSC_RESET
U(True, pause(3, 90000))                            #  LSC_PAUSE
U(True, resume(4, 5000, 2, 1))                      #  LSC_RESUME
U(True, jump(5, 0, -1, 1, 1))                       #  LSC_JUMP, stop -1
U(True, play(6, 1000, 2000, -2, 1))                 #  LSC_PLAY, negative scale
U(False, reply(1, 0x83, 0x00, 1234, 1, 1, 0x03))    #  STATUS_REPLY, OK, transport mode
U(False, reply(2, 0x84, 0x00, 0, 0, 1, 0x00))       #  RESET_REPLY, open mode
U(False, reply(3, 0x81, 0x01, 90000, 1, 1, 0x01))   #  PAUSE_REPLY, pause mode
U(False, reply(4, 0x82, 0x04, 5000, 2, 1, 0x02))    # RESUME_REPLY, search transport
U(False, reply(5, 0x85, 0x05, 0, 1, 1, 0x04))       # JUMP_REPLY
U(False, reply(6, 0x86, 0x10, 1000, -2, 1, 0x05))   # PLAY_REPLY
U(False, reply(7, 0x40, 0x40, 99999, 1, 1, 0x07))   # LSC_DONE, end of stream
U(False, reply(8, 0x83, 0x77, 1, 1, 1, 0x06))       # unknown status code, mode 6
U(False, reply(9, 0x83, 0x00, 1, 1, 1, 0x20))       # unknown mode
U(True, hdr(10, 0x50, 1000))                        # unknown op code, minimum length
U(True, hdr(11, 0x50, 1000) + bytes(4))             # unknown op code, too long
U(True, pause(12, 1) + bytes(2))                    # pause, too long
U(True, status(13) + bytes(2))                      # status, too long
U(False, reply(14, 0x83, 0, 1, 1, 1, 3) + bytes(3)) # reply, too long
# --- TCP: stream reassembly with tcp_dissect_pdus
t = Tcp()
tc = lambda p: fr.append(t.seg(True, p))
ts = lambda p: fr.append(t.seg(False, p))
tc(status(1) + pause(2, 4000))                      # two PDUs in one segment
ts(reply(1, 0x83, 0x00, 77, 1, 1, 0x03) + reply(2, 0x81, 0x00, 4000, 1, 1, 0x01))   # two replies
r = resume(3, 100, 1, 1)
tc(r[:10])                                          # resume, first part
tc(r[10:])                                          # resume, rest
p = play(4, 0, 60000, 1, 1)
tc(p[:1])                                           # one octet of a play
tc(p[1:])                                           # the rest
ts(reply(3, 0x82, 0x00, 100, 1, 1, 0x03) + reply(4, 0x86, 0x00, 0, 1, 1, 0x03)[:9])   # reply and a start of the next
ts(reply(4, 0x86, 0x00, 0, 1, 1, 0x03)[9:])         # rest of it
tc(hdr(5, 0x60, 1000) + status(6))                  # unknown op code PDU followed by a status
tc(jump(7, 0, 5000, 1, 1) + reset(8) + jump(9, 5000, 0, 1, 1, stream=2000))   # three PDUs
ts(reply(7, 0x40, 0x00, 5000, 1, 1, 0x07))          # LSC_DONE over TCP
for i, code in enumerate([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x20, 0x21, 0x30, 0x31, 0x32]):
    ts(reply(20 + i, 0x83, code, 0, 1, 1, i % 8))   # every remaining status code, every mode
pcap(os.path.join(OUT, 'lsc-coverage.pcap'), fr)

bad = []
n[0] = 100
def B(p, to_server=True):
    n[0] += 1
    bad.append(udp(to_server, p, n[0], sport=41002))
B(hdr(15, 0x83, 0xffffffff))                         # reply op code with only 8 octets (too short for a reply)
B(b'\x01\x01\x03')                                   # less than 8 octets: not LSC
B(status(1)[:7])                                     # 7 octets
B(pause(1, 5)[:10])                                  # pause cut inside the stop NPT
B(resume(1, 5, 1, 1)[:13])                           # resume cut inside the scale
B(jump(1, 0, 1, 1, 1)[:17])                          # jump cut
B(play(1, 0, 1, 1, 1)[:8])                           # play with no operands
B(reply(1, 0x83, 0, 1, 1, 1, 3)[:12], False)         # reply cut inside the NPT
B(reply(1, 0x86, 0, 1, 1, 1, 3)[:16], False)         # reply without the mode
B(reply(1, 0x40, 0, 1, 1, 1, 3)[:9], False)          # DONE cut
t2 = Tcp(sport=41003)
bad.append(t2.seg(True, status(1)[:2]))              # TCP: two octets only (needs more data)
bad.append(t2.seg(True, status(1)[2:] + pause(2, 3)[:8]))   # rest of it plus a truncated pause
pcap(os.path.join(OUT, 'lsc-coverage-malformed.pcap'), bad)
print(len(fr), len(bad))
