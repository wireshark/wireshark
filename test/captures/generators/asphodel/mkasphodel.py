#!/usr/bin/env python3
# Generates test/captures/asphodel_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Asphodel dissector
(packet-asphodel.c).

All packets are built from scratch with struct; no captured traffic is
used. A host (10.0.0.1) broadcasts Asphodel inquiries on UDP port 5760,
devices (10.0.0.2-10.0.0.6) answer from port 5760, and the host then
talks to them over TCP port 5760.

Usage: mkasphodel.py <output directory>

Writes:
  asphodel-coverage.pcap            inquiries, every kind of response,
                                    and TCP sessions with every message
                                    type, reassembly and the remote
                                    parameter length reproducer
  asphodel-coverage-malformed.pcapng truncated responses (exceptions) and,
                                    as Exported PDUs, inquiries too short
                                    for the UDP heuristic

The UDP heuristic ("asphodel_inquiry") is disabled by default, so
dissect with --enable-heuristic asphodel_inquiry.
"""

import os
import struct
import sys

PORT = 5760
HOST = (10, 0, 0, 1)
BCAST = (255, 255, 255, 255)
DEV_A = (10, 0, 0, 2)   # plain device, no radio
DEV_B = (10, 0, 0, 3)   # radio, remote sizes differ from device sizes
DEV_C = (10, 0, 0, 4)   # radio, every buffer size too small
DEV_D = (10, 0, 0, 5)   # response too short
DEV_E = (10, 0, 0, 6)   # also sends an inquiry from port 5760

def mac(ip):
    if ip == BCAST:
        return b'\xff' * 6
    return b'\x02\x00\x00\x00\x00' + bytes([ip[3]])


def ip_checksum(hdr):
    if len(hdr) % 2:
        hdr += b'\0'
    s = sum(struct.unpack('>%dH' % (len(hdr) // 2), hdr))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self, linktype=1):
        self.frames = []
        self.linktype = linktype

    def ip(self, proto, src, dst, l4):
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), len(self.frames) & 0xffff,
                         0x4000, 64, proto, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
        self.frames.append(mac(dst) + mac(src) + b'\x08\x00' + ip + l4)

    def udp(self, src, sport, dst, dport, payload):
        hdr = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(payload))
        ck = ip_checksum(pseudo + hdr + payload) or 0xffff
        hdr = hdr[:6] + struct.pack('>H', ck)
        self.ip(17, src, dst, hdr + payload)

    def tcp(self, src, sport, dst, dport, seq, ack, flags, payload=b''):
        opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''   # MSS on SYN
        hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(hdr) + len(payload))
        hdr = hdr[:16] + struct.pack('>H', ip_checksum(pseudo + hdr + payload)) + hdr[18:]
        self.ip(6, src, dst, hdr + payload)

    def raw(self, data):
        self.frames.append(data)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, self.linktype)]
        t = 1700000000
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', t + i // 100, (i % 100) * 10000, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


class TcpStream:
    """A TCP connection from the host to a device, with handshake."""
    def __init__(self, cap, cport, dev):
        self.cap, self.cport, self.dev = cap, cport, dev
        self.cseq, self.sseq = 1000 + cport, 7000 + cport
        cap.tcp(HOST, cport, dev, PORT, self.cseq, 0, 0x02)
        cap.tcp(dev, PORT, HOST, cport, self.sseq, self.cseq + 1, 0x12)
        self.cseq += 1
        self.sseq += 1
        cap.tcp(HOST, cport, dev, PORT, self.cseq, self.sseq, 0x10)

    def host(self, *datas):
        for data in datas:
            self.cap.tcp(HOST, self.cport, self.dev, PORT, self.cseq, self.sseq, 0x18, data)
            self.cseq += len(data)

    def device(self, *datas):
        for data in datas:
            self.cap.tcp(self.dev, PORT, HOST, self.cport, self.sseq, self.cseq, 0x18, data)
            self.sseq += len(data)

    def close(self):
        self.cap.tcp(HOST, self.cport, self.dev, PORT, self.cseq, self.sseq, 0x11)
        self.cseq += 1
        self.cap.tcp(self.dev, PORT, HOST, self.cport, self.sseq, self.cseq, 0x11)
        self.sseq += 1
        self.cap.tcp(HOST, self.cport, self.dev, PORT, self.cseq, self.sseq, 0x10)


def split(data, *cuts):
    out, last = [], 0
    for c in cuts:
        out.append(data[last:c])
        last = c
    return out + [data[last:]]


# --------------------------------------------------------------------------
# Asphodel encoding

DEVICE_CMD, DEVICE_STREAM, REMOTE_CMD, REMOTE_STREAM, REMOTE_NOTIFY = 0, 1, 2, 3, 6
RF_POWER, RADIO, REMOTE, BOOTLOADER = 1, 2, 4, 8


def inquiry(version=0x0210, ident=b'Asphodel\0'):
    return struct.pack('>H', version) + ident


def cstr(s):
    return s.encode() + b'\0'


def response(serial, ptype, inc=402, out=402, stream=40, board_rev=3,
             board_type='WMRTCP', build_info='abc123-release', build_date='2026-01-02',
             tag1='Tag one', tag2='', remote=None, tcp_version=1, connected=0):
    """The UDP response to an inquiry. inc/out are the device's command
    buffer sizes (the parameter length plus 2). remote is (incoming,
    outgoing, stream packet length) and is sent when ptype has RADIO."""
    d = struct.pack('>BBHHHB', tcp_version, connected, inc, out, stream, ptype)
    d += cstr(serial) + bytes([board_rev]) + cstr(board_type) + cstr(build_info)
    d += cstr(build_date) + cstr(tag1) + cstr(tag2)
    if remote is not None:
        d += struct.pack('>HHH', *remote)
    return d


def msg(mtype, body=b''):
    """A TCP message: length (type + body), type, body."""
    return struct.pack('>HB', 1 + len(body), mtype) + body


def cmd(mtype, seq, code, params=b''):
    return msg(mtype, bytes([seq, code]) + params)


def noop():
    return b'\0\0'


# --------------------------------------------------------------------------

def main_capture(path):
    c = Pcap()
    HP = 50000   # the host's inquiry port

    # 1: inquiry, broadcast
    c.udp(HOST, HP, BCAST, PORT, inquiry())
    # 2: response from a plain device (no radio): one TCP conversation
    c.udp(DEV_A, PORT, HOST, HP, response('WM12345', RF_POWER | BOOTLOADER,
                                          inc=402, out=258, stream=32,
                                          tag1='Bench', tag2='Rack 3'))
    # 3: the remote parameter length reproducer: a radio whose remote
    # buffer sizes (incoming 130, outgoing 66, stream 20) differ from its
    # own (incoming 402, outgoing 258, stream 40). Before the fix the
    # remote values were read from offsets 2 and 4 (the device sizes).
    c.udp(DEV_B, PORT, HOST, HP, response('WMR99', RADIO | REMOTE, inc=402, out=258,
                                          stream=40, board_type='WMRTCP-RADIO',
                                          tag1='Radio', tag2='Remote host',
                                          remote=(130, 66, 20), connected=1))
    # 4: radio with every buffer size too small (2 and 1): four bad
    # parameter length warnings; no user tags
    c.udp(DEV_C, PORT, HOST, HP, response('WMR0', RADIO, inc=2, out=1, stream=0,
                                          tag1='', tag2='', remote=(2, 0, 0)))
    # 5: a response shorter than 16 octets: not dissected
    c.udp(DEV_D, PORT, HOST, HP, b'\x01\x00\x01\x92\x01\x92\x00\x20\x00WM1\0')
    # 6: device E sends an inquiry from port 5760 ...
    c.udp(DEV_E, PORT, BCAST, PORT, inquiry())
    # 7: ... so its own response finds a UDP conversation and no TCP
    # conversation is set up for it
    c.udp(DEV_E, PORT, HOST, HP, response('WM55', 0, tag1='E', tag2='e'))
    # 8, 9: UDP to 5760 that the heuristic rejects (too short, no name)
    c.udp(HOST, 50001, BCAST, PORT, b'\x02\x10Asph')
    c.udp(HOST, 50001, BCAST, PORT, b'\x02\x10Notphodel\0')

    # TCP session with device A: every message type and reassembly
    s = TcpStream(c, 40000, DEV_A)
    s.host(noop())                                            # No op
    s.host(cmd(DEVICE_CMD, 1, 0x00))                          # no params
    s.device(cmd(DEVICE_CMD, 1, 0x00, b'\x02\x10'))           # params
    s.host(cmd(DEVICE_CMD, 2, 0x01))
    s.device(cmd(DEVICE_CMD, 2, 0x01, b'\x03' + b'WMRTCP\0'))
    s.host(cmd(DEVICE_CMD, 3, 0x0B, struct.pack('>I', 0x100)))  # READ_NVM
    # error replies: error code only, error code and params, and too
    # short for the error code
    s.device(cmd(DEVICE_CMD, 3, 0xFF, b'\x05'))
    s.host(cmd(DEVICE_CMD, 4, 0x77))                          # unknown command
    s.device(cmd(DEVICE_CMD, 4, 0xFF, b'\x03\x77'))
    s.host(cmd(DEVICE_CMD, 5, 0x0D))
    s.device(cmd(DEVICE_CMD, 5, 0xFF))
    # too short for a command: type only, type and sequence
    s.host(msg(DEVICE_CMD))
    s.host(msg(DEVICE_CMD, b'\x06'))
    # stream data, and a stream message with no data
    s.device(msg(DEVICE_STREAM, bytes(range(32))))
    s.device(msg(DEVICE_STREAM))
    # several messages in one segment
    s.host(cmd(DEVICE_CMD, 7, 0x20) + noop() + cmd(DEVICE_CMD, 8, 0x21, b'\x00'))
    s.device(cmd(DEVICE_CMD, 7, 0x20, b'\x02\x01') + cmd(DEVICE_CMD, 8, 0x21, b'\x00\x01'))
    # one message over three segments, and one split inside its length
    big = cmd(DEVICE_CMD, 9, 0xFC, bytes((i * 7) & 0xff for i in range(380)))
    s.host(*split(big, 100, 250))
    big2 = cmd(DEVICE_CMD, 9, 0xFC, bytes((i * 7) & 0xff for i in range(380)))
    s.device(*split(big2, 1, 200))
    # an unknown message type
    s.host(msg(5, b'\x01\x02\x03'))
    s.close()

    # TCP session with device B (radio): remote commands, remote stream
    # data and notifications
    s = TcpStream(c, 40001, DEV_B)
    s.host(cmd(DEVICE_CMD, 1, 0x91))                          # START_RADIO_SCAN
    s.device(cmd(DEVICE_CMD, 1, 0x91))
    s.host(cmd(DEVICE_CMD, 2, 0x93, struct.pack('>I', 99)))   # CONNECT_RADIO
    s.device(cmd(DEVICE_CMD, 2, 0x93))
    s.device(msg(REMOTE_NOTIFY, struct.pack('>IB', 99, RF_POWER | REMOTE | BOOTLOADER)))
    s.host(cmd(REMOTE_CMD, 3, 0x01))
    s.device(cmd(REMOTE_CMD, 3, 0x01, b'\x01WMR\0'))
    s.host(cmd(REMOTE_CMD, 4, 0xA6))
    s.device(cmd(REMOTE_CMD, 4, 0xFF, b'\x09'))
    s.device(msg(REMOTE_STREAM, bytes(range(20))))
    s.device(msg(REMOTE_STREAM))
    s.device(msg(REMOTE_NOTIFY))                              # disconnect
    s.device(msg(REMOTE_NOTIFY, b'\x00\x00'))                 # bad length
    s.close()

    c.write(path)
    return c


def epdu(dissector, payload):
    tag = dissector.encode()
    pad = (-len(tag)) % 4
    return struct.pack('>HH', 12, len(tag) + pad) + tag + b'\0' * pad + b'\0\0\0\0' + payload


def malformed_capture(path):
    c = Pcap()
    HP = 50000
    c.udp(HOST, HP, BCAST, PORT, inquiry())
    # a second inquiry from the same port, with an older version. The
    # port's conversation sends it to the response dissector first, which
    # turns it down (shorter than 16 octets); then the heuristic finds it
    # and the inquiry dissector finds the conversation already there.
    # Only the first pass shows the response dissector's empty "Asphodel
    # Response" item (the second pass goes straight to the heuristic), so
    # this frame is kept out of the main capture.
    c.udp(HOST, HP, BCAST, PORT, inquiry(0x0103))
    # a second inquiry from the same port, long enough (16 octets) for the
    # response dissector that the first one set up for the port: it is
    # dissected as a response and throws
    c.udp(HOST, HP, BCAST, PORT, inquiry(0x0103, b'Asphodel\0extra'))
    full = response('WMR7', RADIO, remote=(130, 66, 20))
    # radio flag but the remote sizes are missing / cut in the middle
    c.udp(DEV_A, PORT, HOST, HP, full[:-6])
    c.udp(DEV_B, PORT, HOST, HP, full[:-3])
    # the strings end with the packet
    c.udp(DEV_C, PORT, HOST, HP, response('WM1', 0)[:20])
    # Exported PDUs (a second interface): the inquiry dissector called by
    # name with no data, a one octet and a two octet inquiry (the UDP
    # heuristic needs 11)
    epdus = [epdu('asphodel_inquiry', data) for data in (b'', b'\x02', b'\x02\x10')]
    write_pcapng(path, [(1, f) for f in c.frames] + [(252, f) for f in epdus])


def write_pcapng(path, frames):
    """frames: (linktype, data); one interface per link type."""
    def block(btype, body):
        body += b'\0' * ((-len(body)) % 4)
        n = 12 + len(body)
        return struct.pack('<II', btype, n) + body + struct.pack('<I', n)
    links = sorted({lt for lt, _ in frames})
    out = [block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))]
    for lt in links:
        out.append(block(1, struct.pack('<HHI', lt, 0, 262144)))
    t = 1700000000 * 1000000
    for i, (lt, f) in enumerate(frames):
        ts = t + i * 10000
        out.append(block(6, struct.pack('<IIIII', links.index(lt), ts >> 32, ts & 0xffffffff,
                                        len(f), len(f)) + f))
    with open(path, 'wb') as fh:
        fh.write(b''.join(out))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture(os.path.join(out, 'asphodel-coverage.pcap'))
    malformed_capture(os.path.join(out, 'asphodel-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main()
