#!/usr/bin/env python3
# Generates test/captures/tftp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the TFTP coverage captures. Usage: mktftp.py <outdir>
All packets are built with struct; nothing comes from a real network."""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

CIP, SIP = (192, 0, 2, 1), (192, 0, 2, 2)
CMAC = b'\x02\x00\x00\x00\x00\x01'; SMAC = b'\x02\x00\x00\x00\x00\x02'

def udp_frame(src, dst, sport, dport, payload):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(pseudo + u) or 0xffff
    u = u[:6] + struct.pack('!H', c) + u[8:]
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0, bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    macs = (SMAC, CMAC) if src == CIP else (CMAC, SMAC)
    return macs[0] + macs[1] + b'\x08\x00' + h + u

def write(fn, frames):
    with open(os.path.join(OUT, fn), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(fr), len(fr)))
            f.write(fr)

def req(op, name, mode=b'octet', opts=()):
    b = struct.pack('!H', op) + name + b'\0' + mode + b'\0'
    for k, v in opts:
        b += k + b'\0' + v + b'\0'
    return b
def data(blk, payload): return struct.pack('!HH', 3, blk) + payload
def ack(blk, extra=b''): return struct.pack('!HH', 4, blk) + extra
def err(code, msg): return struct.pack('!HH', 5, code) + msg + b'\0'
def oack(opts):
    return struct.pack('!H', 6) + b''.join(k + b'\0' + v + b'\0' for k, v in opts)
def info(opts):
    return struct.pack('!H', 255) + b''.join(k + b'\0' + v + b'\0' for k, v in opts)
def pat(tag, n):
    return bytes((i * 13 + tag) & 0xff for i in range(n))

class Conv:
    """A client port, the server port 69 and a server transfer port."""
    def __init__(self, frames, cport, sport=None, dport=69):
        self.f = frames; self.c = cport; self.s = sport or (cport + 1000); self.d = dport
    def req(self, payload):          # client to the well known port
        self.f.append(udp_frame(CIP, SIP, self.c, self.d, payload))
    def c2s(self, payload):          # client to the transfer port
        self.f.append(udp_frame(CIP, SIP, self.c, self.s, payload))
    def s2c(self, payload):          # server transfer port to client
        self.f.append(udp_frame(SIP, CIP, self.s, self.c, payload))

main = []
F = main

# --- A: read with options, windowsize and a 100 octet block size (frames 1-12)
FA = pat(1, 250)
c = Conv(F, 2001)
c.req(req(1, b'boot.img', b'octet', [(b'blksize', b'100'), (b'tsize', b'0'), (b'windowsize', b'2'),
                                        (b'timeout', b'3'), (b'vendorext', b'x')]))
c.s2c(oack([(b'blksize', b'100'), (b'tsize', b'250'), (b'windowsize', b'2')]))
c.c2s(ack(0))
c.s2c(data(1, FA[:100])); c.s2c(data(2, FA[100:200]))
c.c2s(ack(2))
c.s2c(data(3, FA[200:]))
c.c2s(ack(3))

# --- B: write request, netascii, upper case option names (13-19)
FB = pat(2, 522)
c = Conv(F, 2002)
c.req(req(2, b'up.cfg', b'netascii', [(b'WINDOWSIZE', b'1'), (b'TSIZE', b'522')]))
c.s2c(ack(0))
c.c2s(data(1, FB[:512])); c.s2c(ack(1))
c.c2s(data(2, FB[512:])); c.s2c(ack(2))

# --- C: Windows Deployment Services style dynamic windowing (20-37)
FC = pat(3, 16 * 5 + 7)
c = Conv(F, 2003)
c.req(req(1, b'wds.wim', b'octet', [(b'msftwindow', b'31416'), (b'blksize', b'16'), (b'tsize', b'0')]))
c.s2c(oack([(b'blksize', b'16'), (b'msftwindow', b'27182')]))
c.c2s(ack(0, b'\x04'))
c.s2c(data(1, FC[0:16])); c.s2c(data(2, FC[16:32]))
c.c2s(ack(2, b'\x04'))                       # same as the first window size, no change
c.s2c(data(3, FC[32:48])); c.s2c(data(4, FC[48:64]))
c.c2s(ack(4, b'\x08'))                       # the window size changes
c.s2c(data(5, FC[64:80])); c.s2c(data(6, FC[80:]))
c.c2s(ack(6))                                # no window size octet
c.c2s(ack(6, b'\x01'))                       # final ACK: its size is ignored

# --- C2: the same for a write: the window octets are in the server's ACKs
c = Conv(F, 2013)
c.req(req(2, b'wdsup.bin', b'octet', [(b'msftwindow', b'31416'), (b'blksize', b'16')]))
c.s2c(oack([(b'blksize', b'16'), (b'msftwindow', b'27182')]))
c.s2c(ack(0, b'\x04'))                       # first octet differs from the unknown size: a change
c.s2c(ack(1, b'\x04'))
c.s2c(ack(2, b'\x08'))                       # another change
c.s2c(data(3, b'short'))                     # the last block
c.s2c(ack(3, b'\x02'))                       # ignored: the last block was seen

# --- C3: a file that another dissector (ARINC 615A, by the heuristic list) claims
c = Conv(F, 2014)
c.req(req(1, b'FMC_L.LUI'))
c.s2c(data(1, struct.pack('!I', 9) + b'A2' + b'\x00\x01' + b'\0'))

# --- D: transfer size probes (38-45)
c = Conv(F, 2004)
c.req(req(1, b'probe1', b'octet', [(b'tsize', b'0')]))
c.s2c(oack([(b'tsize', b'1000')]))
c.s2c(err(8, b'Option negotiation failed'))              # likely a tsize probe (the client's own
                                                         # packets to the server port are plain UDP, see README)
c = Conv(F, 2005)
c.req(req(1, b'probe2', b'octet', [(b'tsize', b'0')]))
c.s2c(data(1, pat(4, 512)))                              # server ignored the options
c.s2c(err(0, b'closing'))                                # likely a tsize probe too
c = Conv(F, 2006)
c.req(req(1, b'probe3', b'octet'))
c.s2c(oack([(b'blksize', b'512')]))
c.s2c(err(0, b'no tsize requested'))                     # an ordinary error

# --- E: error codes (46-56)
c = Conv(F, 2007)
c.req(req(1, b'missing.txt'))
for code, msg in [(1, b'File not found'), (2, b'Access violation'), (3, b'Disk full'),
                  (4, b'Illegal operation'), (5, b'Unknown transfer ID'), (6, b'File exists'),
                  (7, b'No such user'), (8, b'Bad options'), (99, b'Unassigned code'), (0, b'')]:
    c.s2c(err(code, msg))

# --- F: option values out of range (57-70)
c = Conv(F, 2008)
c.req(req(1, b'range.bin', b'octet', [(b'windowsize', b'0'), (b'msftwindow', b'1'),
                                        (b'windowsize', b'70000'), (b'WindowSize', b'8')]))
c.s2c(oack([(b'blksize', b'4')]))                 # too small: expert info, block size stays 512
c.s2c(oack([(b'blksize', b'65465')]))             # too large
c.s2c(oack([(b'windowsize', b'0')]))
c.s2c(oack([(b'windowsize', b'70000')]))
c.s2c(oack([(b'msftwindow', b'1')]))
c.s2c(oack([(b'msftwindow', b'27182')]))
c.s2c(data(1, pat(5, 512))); c.s2c(data(2, pat(5, 3)))
c.s2c(oack([(b'blksize', b'1024')]))              # after the transfer started: ignored, expert info
c.c2s(ack(2))
c.req(req(1, b'range.bin', b'octet', [(b'msftwindow', b'31416')]))   # a second request, same ports

# --- G: block number wrap, blocksize 8 from the OACK (71-79)
c = Conv(F, 2009)
c.req(req(1, b'wrap.bin', b'octet', [(b'blksize', b'8')]))
c.s2c(oack([(b'blksize', b'8')]))
c.s2c(data(1, pat(6, 8)))
c.s2c(data(65534, pat(6, 8)))                     # a gap: blocks are missing
c.s2c(data(65535, pat(6, 8)))                     # about to wrap
c.s2c(data(0, pat(6, 8)))                         # block 65536
c.s2c(data(1, pat(6, 8)))                         # block 65537
c.s2c(data(2, pat(6, 3)))                         # last
c.c2s(ack(2))

# --- H: unknown opcode and information messages inside a transfer (80-85)
c = Conv(F, 2010)
c.req(req(1, b'misc.txt'))
c.s2c(struct.pack('!H', 7) + b'unknown opcode payload')
c.s2c(info([(b'blksize', b'1000'), (b'tsize', b'5')]))
c.c2s(info([(b'windowsize', b'3')]))
c.s2c(data(1, b'misc'))

# --- I: heuristic on a port other than 69 (86-91)
c = Conv(F, 5000, 5100, 4000)
c.req(req(1, b'heur.txt', b'NetAscii'))
c.s2c(data(1, b'hello heuristic'))
c.c2s(ack(1))
c = Conv(F, 5001, 5101, 4000)
c.req(req(2, b'heur-up.txt', b'mail', [(b'tsize', b'3')]))
c.s2c(ack(0))
c.c2s(data(1, b'abc'))
# requests the heuristic rejects (plain UDP): unknown mode, odd number of
# zeros, a control octet in the name, no zero at all
c = Conv(F, 5002, 5102, 4000)
c.req(req(1, b'bad.txt', b'bogus'))
c.req(struct.pack('!H', 1) + b'name\0octet')
c.req(struct.pack('!H', 1) + b'na\x01me\0octet\0')
c.req(struct.pack('!H', 1) + b'nameoctet')

# --- J: the server keeps using port 69 (92-97)
c = Conv(F, 2011, 69, 69)
c.req(req(1, b'same69.txt'))
c.s2c(data(1, pat(7, 512)))
c.c2s(ack(1))
c.s2c(data(2, pat(7, 100)))
c.c2s(ack(2))
# DATA and ACK to port 69 without any request
F.append(udp_frame(CIP, SIP, 2012, 69, ack(5)))
F.append(udp_frame(SIP, CIP, 69, 2099, data(3, b'orphan')))

# --- K: Export Objects: a file over many blocks, a single block file,
# a file that ends on a block boundary (empty last block), a transfer with
# missing blocks (no object) and the reproducers of the bugs fixed on the
# branch.
FK = pat(8, 512 * 3 + 100)
c = Conv(F, 2020)
c.req(req(1, b'dir/multi.bin'))
for i in range(4):
    c.s2c(data(i + 1, FK[512 * i:512 * (i + 1)]))
    c.c2s(ack(i + 1))
c = Conv(F, 2021)
c.req(req(1, b'single.txt'))
c.s2c(data(1, b'one block file\n'))
c = Conv(F, 2022)
c.req(req(2, b'exact.bin'))
c.s2c(ack(0))
c.c2s(data(1, pat(9, 512))); c.c2s(data(2, b''))
c = Conv(F, 2023)
c.req(req(1, b'gap.bin'))
c.s2c(data(1, pat(10, 512))); c.s2c(data(3, pat(10, 512))); c.s2c(data(4, pat(10, 5)))
# bug: block 1 retransmitted after the last block (invalid free with -2)
c = Conv(F, 2024)
c.req(req(1, b'badfree.bin'))
c.s2c(data(1, pat(11, 512))); c.s2c(data(2, pat(11, 100))); c.s2c(data(1, pat(11, 512)))
# bug: a second, larger block 1 after a one block file (assertion)
c = Conv(F, 2025)
c.req(req(1, b'assert.bin'))
c.s2c(data(1, pat(12, 100))); c.s2c(data(1, pat(12, 512)))

# --- L: reassembly with tftp.defragment (needs the preference): a file of
# four blocks in a transfer of its own
c = Conv(F, 2030)
c.req(req(1, b'frag.bin'))
for i in range(3):
    c.s2c(data(i + 1, pat(13, 512)))
c.s2c(data(4, pat(13, 77)))

# --- M: TFTP over TURN: ChannelData messages on UDP port 3478 (the "tftp_stun" heuristic)
def chan(payload, ch=0x4001):
    pad = (4 - len(payload) % 4) % 4
    return struct.pack('!HH', ch, len(payload)) + payload + b'\0' * pad
def turn(c2s, payload, ch=0x4001):
    if c2s:
        F.append(udp_frame(CIP, SIP, 50001, 3478, chan(payload, ch)))
    else:
        F.append(udp_frame(SIP, CIP, 3478, 50001, chan(payload, ch)))
turn(True, req(1, b'turn.txt', b'octet', [(b'tsize', b'0')]))
turn(False, oack([(b'tsize', b'12')]))
turn(True, ack(0))
turn(False, data(1, b'over turn!!!!'))
turn(True, ack(1))
turn(True, req(2, b'turn-up.txt'))
turn(False, ack(0))
turn(True, info([(b'x', b'y')]))
turn(False, err(1, b'not found'))
turn(False, err(3, b'disk full'))
# not TFTP: unknown opcode, bad request, error with an unknown code, too short
turn(True, struct.pack('!H', 9) + b'abcdef')
turn(True, req(1, b'bad', b'bogus'))
turn(True, err(77, b'weird'))
turn(True, b'\x00\x04\x00')
write('tftp-coverage.pcap', main)
n_main = len(main)

# ---------------------------------------------------------------- malformed
mal = []
F = mal
# truncated messages on port 69 / in a transfer
c = Conv(F, 4001)
c.req(req(1, b'trunc.txt'))
c.s2c(b'\x00\x03\x00')                      # DATA without a full block number
c.s2c(b'\x00\x04\x00')                      # ACK cut off
c.s2c(b'\x00\x05\x00\x01')                  # ERROR without the message
c.s2c(b'\x00\x06blksize')                   # OACK option without a zero
c.s2c(b'\x00\x06blksize\0')                 # option without a value
c.s2c(b'\x00\x06blksize\x0010')             # unterminated value
c.s2c(b'\x00\x01')                          # request without a name
c.s2c(b'\x00\x02name\0')                    # request without a mode
c.s2c(b'\x00\x01name\0octet\0tsize')        # request with an option without a value
c.s2c(b'\x00')                              # one octet
c = Conv(F, 4002)
c.req(req(1, b'ack-trunc'))
c.s2c(oack([(b'msftwindow', b'27182')]))
c.c2s(b'\x00\x04\x00\x05')                  # ACK with window size absent
c.s2c(data(1, b'x'))
# nested heuristic: TURN ChannelData with a truncated TFTP message
F.append(udp_frame(CIP, SIP, 50002, 3478, chan(b'\x00\x05\x00\x01ab')))
F.append(udp_frame(CIP, SIP, 50002, 3478, chan(b'\x00\x03\x00\x01')))
write('tftp-coverage-malformed.pcap', mal)
print(n_main, len(mal))
