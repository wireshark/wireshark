#!/usr/bin/env python3
# Generates test/captures/midi_network_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the Network MIDI 2.0 coverage captures. Usage: mkmidi_network.py <outdir>
Every packet is built with struct; nothing comes from a real network."""
import struct
import sys
import os

def cmd(code, words, body=b''):
    """One NMP command: code, payload length in 32 bit words, 2 command
    specific bytes plus the rest of the payload in body."""
    return struct.pack('BB', code, words) + body

def nm(s, n):            # name padded to n words
    return s.ljust(n * 4, b'\0')

def pad(b):
    return b + b'\0' * (-len(b) % 4)

def ip_udp(payload, sport, dport, src, dst):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                       bytes(src), bytes(dst)) + udp

A = (192, 0, 2, 1); B = (192, 0, 2, 2)
H = b'MIDI'

def inv(name, caps, pid):
    n = (len(name) + 3) // 4
    body = bytes([n, caps]) + nm(name, n) + pad(pid)
    return cmd(0x01, (len(body) - 2) // 4, body)

def inv_auth(code, user=b''):
    body = b'\0\0' + bytes(range(32)) + pad(user)
    return cmd(code, (len(body) - 2) // 4, body)

def inv_reply(code, name, pid, authstate=None, nonce=b'0123456789abcdef'):
    n = (len(name) + 3) // 4
    if authstate is None:
        body = bytes([n, 0]) + nm(name, n) + pad(pid)
    else:
        body = bytes([n, authstate]) + nonce + nm(name, n) + pad(pid)
    return cmd(code, (len(body) - 2) // 4, body)

def ping(code, pid):
    return cmd(code, 1, b'\0\0' + struct.pack('>I', pid))

def retr_req(seq, cnt):
    return cmd(0x80, 1, struct.pack('>HHH', seq, cnt, 0))

def retr_err(err, seq):
    return cmd(0x81, 1, bytes([err, 0]) + struct.pack('>HH', seq, 0))

def reset(code):
    return cmd(code, 0, b'\0\0')

def nak(reason, hdr_code, hdr_pl, hdr_data, msg=b''):
    body = bytes([reason, 0, hdr_code, hdr_pl]) + hdr_data + pad(msg)
    return cmd(0x8f, (len(body) - 2) // 4, body)

def bye(reason, msg=b''):
    body = bytes([reason, 0]) + pad(msg)
    return cmd(0xf0, (len(body) - 2) // 4, body)

def ump(seq, *words):
    body = struct.pack('>H', seq) + b''.join(struct.pack('>I', w) for w in words)
    # words are not 32 bit aligned relative to the 2 byte sequence number:
    # NMP pads with 2 bytes so the payload is a whole number of words
    body += b'\0' * ((-len(body)) % 4)
    return cmd(0xff, (len(body) - 2) // 4, body) if len(body) % 4 == 2 else cmd(0xff, (len(body) - 2 + 3) // 4, body)

def ump_cmd(seq, words):
    """UMP Data: seq number, then the UMP words. The payload is the 2
    byte sequence number plus the words (a multiple of 4 bytes), so the
    payload length in words is len(words)."""
    body = struct.pack('>H', seq) + b''.join(struct.pack('>I', w) for w in words)
    return struct.pack('BB', 0xff, len(words)) + body

main = []   # (time, sport, dport, src, dst, payload)
def add(t, payload, sport=5673, dport=5673, src=A, dst=B):
    main.append((t, sport, dport, src, dst, payload))

# 1-7 invitation handshake
add(1, H + inv(b'Synth 1', 0x03, b'PID-0001'))
add(2, H + inv(b'Controller', 0x00, b''), src=B, dst=A)
add(3, H + inv_auth(0x02), src=A, dst=B)
add(4, H + inv_auth(0x03, b'alice'), src=A, dst=B)
add(5, H + inv_reply(0x12, b'Synth 1', b'PID-0001', authstate=0), src=B, dst=A)
add(6, H + inv_reply(0x13, b'Synth 1', b'', authstate=2), src=B, dst=A)
add(7, H + inv_reply(0x10, b'Synth 1', b'PID-0001'), src=B, dst=A)
add(8, H + inv_reply(0x11, b'Synth 1', b''), src=B, dst=A)
# 9-15 pings: request, reply, same id again, reply, reply without
# request, request without reply
add(10, H + ping(0x20, 0x12345678))
add(12, H + ping(0x21, 0x12345678), src=B, dst=A)
add(14, H + ping(0x20, 0x12345678))
add(17, H + ping(0x21, 0x12345678), src=B, dst=A)
add(18, H + ping(0x21, 0xdeadbeef), src=B, dst=A)
add(19, H + ping(0x20, 0x0badf00d))
# 16-17 retransmit and reset
add(20, H + retr_req(7, 3), src=B, dst=A)
add(21, H + retr_err(0, 7), src=A, dst=B)
add(22, H + retr_err(1, 8), src=A, dst=B)
add(23, H + reset(0x82), src=A, dst=B)
add(24, H + reset(0x83), src=B, dst=A)
# NAKs naming each kind of header
for i, (cc, pl, data) in enumerate([
        (0xff, 1, b'\x00\x05'), (0x01, 2, bytes([3, 1])),
        (0x10, 2, bytes([3, 0])), (0x11, 2, bytes([3, 0])),
        (0x12, 5, bytes([3, 1])), (0x13, 5, bytes([3, 1])),
        (0x80, 1, b'\x00\x07'), (0x81, 1, bytes([1, 0])),
        (0x8f, 1, bytes([2, 0])), (0xf0, 0, bytes([1, 0])),
        (0x02, 8, b'\0\0'), (0x20, 1, b'\0\0'), (0x82, 0, b'\0\0'),
        (0xf1, 0, b'\0\0'), (0x55, 1, b'\xaa\xbb')]):
    add(25 + i, H + nak([0, 1, 2, 3, 0x20][i % 5], cc, pl, data, b'bad command' if i % 2 == 0 else b''), src=B, dst=A)
# NAK with exactly a 6 byte payload and no message
add(40, H + cmd(0x8f, 1, bytes([0, 0, 0x20, 1, 0, 0])), src=B, dst=A)
# Bye with and without message, bye reply
add(40, H + bye(0x01), src=A, dst=B)
add(41, H + bye(0x40, b'too many sessions'), src=B, dst=A)
add(42, H + bye(0x99), src=B, dst=A)
add(43, H + cmd(0xf1, 0, b'\0\0'), src=A, dst=B)
# UMP data: one of each message type
add(44, H + ump_cmd(1, [0x00000000]))                          # utility NOOP
add(45, H + ump_cmd(2, [0x00100123, 0x00200456]))              # JR clock, JR timestamp
add(46, H + ump_cmd(3, [0x10F80000, 0x10FA0000, 0x10FC0000]))  # system real time
add(47, H + ump_cmd(4, [0x20903C64, 0x20803C00, 0x20B00740, 0x20C00500, 0x20E00040]))  # MIDI 1.0
add(48, H + ump_cmd(5, [0x30160304, 0x05060708, 0x30260102, 0x03040506]))  # SysEx7
add(49, H + ump_cmd(6, [0x40903C00, 0xC0000000, 0x40803C00, 0x00000000, 0x40B00700, 0x80000000]))  # MIDI 2.0
add(50, H + ump_cmd(7, [0x50010102, 0x03040506, 0x07080910, 0x11121314]))  # SysEx8
add(51, H + ump_cmd(8, [0xD0100001, 0x00000000, 0x00000000, 0x00000000]))  # flex data
add(52, H + ump_cmd(9, [0xF0000101, 0x00000001, 0, 0]))        # stream: endpoint discovery
add(53, H + ump_cmd(10, [0x60000000, 0x80000000, 0x00000000]))  # reserved types
# several commands in one packet, and an unknown command (the
# conversation already has the dissector from the heuristic)
add(54, H + ping(0x20, 0x11111111) + ump_cmd(11, [0x20903C64]) + reset(0x82))
add(55, H + cmd(0x55, 0, b'\x01\x02') + cmd(0x56, 1, b'\x01\x02\x03\x04\x05\x06'))
# an invitation reply whose name length covers the whole payload
add(56, H + inv(b'LongName' * 4, 0x01, b''))

# malformed capture
mal = []
def madd(t, payload, sport=5674, dport=5674):
    mal.append((t, sport, dport, A, B, payload))
# the reproducers of the fix: payload_length shorter than the fields
madd(1, H + bytes([0x01, 1, 2, 0]) + b'abcdefgh' + b'\0' * 8)
madd(2, H + bytes([0x03, 0, 0, 0]) + b'\x11' * 40)
madd(3, H + bytes([0x12, 1, 1, 0]) + b'\x22' * 30)
madd(4, H + bytes([0x8f, 0, 1, 0]) + bytes([0x20, 0, 0, 0]) + b'\0' * 8)
madd(5, H + bytes([0x20, 1, 0, 0]) + b'\x12\x34\x56\x78')
madd(6, H + bytes([0x21, 1, 0, 0]) + b'\x12\x34\x56\x78')
madd(7, H + bytes([0x20, 1, 0, 0]) + b'\x12\x34\x56\x78')
# further short commands
madd(8, H + bytes([0x02, 0, 0, 0]) + b'\x11' * 40)
madd(9, H + bytes([0x13, 0, 3, 0]) + b'\x22' * 30)
madd(10, H + bytes([0x10, 0, 1, 0]) + b'\x22' * 30)
madd(11, H + bytes([0x20, 0]) + b'\0' * 8)
madd(12, H + bytes([0x21, 0]) + b'\0' * 8)
madd(13, H + bytes([0x80, 0]) + b'\0' * 8)
madd(14, H + bytes([0x81, 0]) + b'\0' * 8)
madd(15, H + bytes([0x8f, 0]) + b'\0' * 8)
madd(16, H + bytes([0x01, 0]) + b'\0' * 8)
madd(17, H + bytes([0x01, 0, 255, 0]))
# ping reply short, followed by a good command
madd(18, H + bytes([0x20, 0]) + ping(0x20, 5))
# commands longer than the datagram, truncated UMP, bye longer than data
madd(19, H + bytes([0xf0, 20, 1, 0]) + b'bye')
madd(20, H + bytes([0xff, 4, 0, 1]) + struct.pack('>IIII', 0xF0000101, 1, 0, 0))
madd(21, H + bytes([0xff, 1, 0, 1]) + struct.pack('>I', 0x40903C00))
madd(22, H + bytes([0xff, 2, 0, 1]) + struct.pack('>II', 0x50010102, 0x03040506))
madd(24, H + ump_cmd(1, [0x30020102, 0x00000000, 0x30160304, 0x05060708, 0x30320a0b, 0x00000000]))
madd(23, H + bytes([0x20, 1, 0, 0]) + b'\x12')

# the heuristic rejects these (unknown first command, short, no signature);
# with Decode As on UDP port 5700 the first is dissected as NetMIDI2
madd(25, H + bytes([0x55, 0, 1, 2]), 5700, 5700)
madd(26, H + bytes([0x20, 1, 0]), 5701, 5701)
madd(27, b'XXXX' + bytes([0x20, 1, 0, 0, 0, 0, 0, 0]), 5702, 5702)

def write(path, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for t, sp, dp, s, d, p in pkts:
            fr = (bytes([0x02, 0, 0, 0, 0, d[3]]) + bytes([0x02, 0, 0, 0, 0, s[3]]) + b'\x08\x00'
                  + ip_udp(p, sp, dp, s, d))
            f.write(struct.pack('<IIII', 1000000 + t, 0, len(fr), len(fr)) + fr)

out = sys.argv[1]
write(os.path.join(out, 'midi-network-coverage.pcap'), main)
write(os.path.join(out, 'midi-network-coverage-malformed.pcap'), mal)
