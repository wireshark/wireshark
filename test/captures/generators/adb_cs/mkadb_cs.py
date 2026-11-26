#!/usr/bin/env python3
# ADB client-server and ADB service coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Android Debug Bridge client-server protocol (packet-adb_cs.c) between an
adb client (192.0.2.1) and the adb server (192.0.2.2, TCP port 5037), and the
services it carries (packet-adb_service.c). One capture serves both
dissectors: adb_service is only called from adb_cs and adb.

Usage: mkadb_cs.py [<output directory>]

Writes:
  adb_cs-coverage.pcapng            host:version (also split over segments),
                                    device lists, host:transport, shell
                                    (stdin and stdout), logcat in both
                                    spellings with entries split over
                                    segments, framebuffer in five pixel
                                    formats, track-jdwp, sync, jdwp, root,
                                    remount, tcpip, usb, FAIL replies, data
                                    without a request, a connection to a
                                    port that is not the server port, and an
                                    Exported PDU frame for adb_service
  adb_cs-coverage-malformed.pcapng  incomplete messages, a logcat entry that
                                    is too long, requests shorter than their
                                    length

Port 5037 is not claimed by default (and 5038 is a second port that is
decoded as ADB CS but is not the server port), so dissect with
  -d tcp.port==5037,adb_cs -d tcp.port==5038,adb_cs
  -o adb_service.framebuffer_more_details:TRUE   (pixel details)

Every packet is built here; nothing comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import TcpFlow, exported_pdu, LINKTYPE_WIRESHARK_UPPER_PDU  # noqa: E402
from usbgen import Pcapng, LT_ETH  # noqa: E402

SERVER = 5037
C, S = 0, 1


def req(service):
    """A client request: 4 hex digits of length and the service."""
    s = service.encode() if isinstance(service, str) else service
    return b'%04x' % len(s) + s


def okay(data=b''):
    return b'OKAY' + data


def fail(reason, length=None):
    r = reason.encode()
    return b'FAIL' + b'%04x' % (len(r) if length is None else length) + r


def hexlen(data):
    return b'%04x' % len(data) + data


def cuts(blob, *points):
    out, prev = [], 0
    for p in points:
        out.append(blob[prev:p])
        prev = p
    out.append(blob[prev:])
    return [c for c in out if c]


class Capture:
    def __init__(self):
        self.w = Pcapng()
        self.eth = self.w.idb(LT_ETH)
        self.exp = self.w.idb(LINKTYPE_WIRESHARK_UPPER_PDU)
        self.next_port = 41000

    def conn(self, server_port=SERVER, handshake=True):
        self.next_port += 1
        return Conn(self, self.next_port, server_port, handshake)

    def write(self, path):
        self.w.write(path)


class Conn:
    def __init__(self, cap, sport, dport, handshake):
        self.cap = cap
        self.flow = TcpFlow(sport=sport, dport=dport)
        if handshake:
            for fr in self.flow.handshake():
                cap.w.pkt(cap.eth, fr)

    def send(self, who, blob, *points):
        for part in cuts(blob, *points):
            fr = self.flow.send(part) if who == C else self.flow.recv(part)
            self.cap.w.pkt(self.cap.eth, fr)

    def close(self):
        for fr in self.flow.close():
            self.cap.w.pkt(self.cap.eth, fr)


def logcat_v1(prio, tag, text, pid=100, tid=101, sec=1700000000, nsec=1000):
    payload = bytes([prio]) + tag.encode() + b'\0' + text.encode() + b'\0'
    return struct.pack('<HHIIII', len(payload), 0, pid, tid, sec, nsec) + payload


def logcat_v2(prio, tag, text, pid=100, tid=101, sec=1700000000, nsec=1000, euid=1000):
    payload = bytes([prio]) + tag.encode() + b'\0' + text.encode() + b'\0'
    return struct.pack('<HHIIIII', len(payload), 24, pid, tid, sec, nsec, euid) + payload


def crlf(b):
    """What a tty does to the stream of a shell service."""
    return b.replace(b'\n', b'\r\n')


def fb_header(bpp, size, width, height, red, blue, green, alpha, version=1):
    """The 13 words of the framebuffer service; each colour is (offset, length)."""
    return struct.pack('<13I', version, bpp, size, width, height, red[0], red[1],
                       blue[0], blue[1], green[0], green[1], alpha[0], alpha[1])


SERIAL = b'0123456789ABCDEF'


def build(path_main, path_bad):
    cap = Capture()
    main(cap)
    cap.write(path_main)
    bad = Capture()
    malformed(bad)
    bad.write(path_bad)


def transport(c, serial=SERIAL):
    c.send(C, req(b'host:transport:' + serial))
    c.send(S, okay())


def main(cap):
    # ---- host:version
    c = cap.conn()
    c.send(C, req('host:version'))
    c.send(S, okay(hexlen(b'0029')))
    c.close()
    # the same with every part in a segment of its own, so that the version
    # continues the length that was seen in an earlier frame
    c = cap.conn()
    c.send(C, req('host:version'), 4)
    c.send(S, okay(hexlen(b'0029')), 4, 8)
    # a second version request on the connection after one that was split
    c.send(C, req('host:version'))
    c.send(S, okay(hexlen(b'0030')))
    c.close()
    # the version in a segment with the length and a short remainder
    c = cap.conn()
    c.send(C, req('host:version'))
    c.send(S, okay(hexlen(b'0029')), 8)
    c.close()

    # ---- device lists
    c = cap.conn()
    c.send(C, req('host:devices'))
    c.send(S, okay(hexlen(SERIAL + b'\tdevice\n' + b'FEDCBA9876543210\toffline\n')))
    c.close()
    c = cap.conn()
    c.send(C, req('host:devices-l'))
    c.send(S, okay(hexlen(SERIAL + b'\tdevice usb:1-1 product:sdk model:Synthetic device:gen\n')))
    c.close()
    c = cap.conn()
    c.send(C, req('host:track-devices'))
    c.send(S, okay(hexlen(SERIAL + b'\tdevice\n')))
    c.send(S, hexlen(SERIAL + b'\toffline\n'))
    # a devices message with more text than its length says: warning
    c.send(S, hexlen(b'x') + b'extra text')
    c.close()
    # states, serial number, device path, connect, disconnect, forwards
    for service, answer in ((b'host:get-state', b'device'),
                            (b'host:get-serialno', SERIAL),
                            (b'host:get-devpath', b'usb:1-1'),
                            (b'host:connect:192.0.2.9:5555', b'connected to 192.0.2.9:5555'),
                            (b'host:disconnect:192.0.2.9:5555', b'disconnected 192.0.2.9:5555')):
        c = cap.conn()
        c.send(C, req(service))
        c.send(S, okay(hexlen(answer)))
        c.close()
    # the service name starts with connect: after a transport
    c = cap.conn()
    c.send(C, req(b'connect:192.0.2.10'))
    c.send(S, okay(hexlen(b'connected')))
    c.send(C, req(b'disconnect:192.0.2.10'))
    c.send(S, okay(hexlen(b'0123')))
    c.send(S, hexlen(b'x') + b'more than a result')
    c.close()
    c = cap.conn()
    c.send(C, req('host:list-forward'))
    c.send(S, okay(hexlen(SERIAL + b' tcp:8000 tcp:9000\n')))
    c.close()

    # ---- shell: stdin and stdout, in both directions on one connection
    c = cap.conn()
    transport(c)
    c.send(C, req('shell:ls /sdcard'))
    c.send(S, okay())
    c.send(S, b'Alarms\r\nDCIM\r\nDownload\r\n')
    c.send(S, b'Music\r\n')
    c.close()
    c = cap.conn()
    transport(c)
    c.send(C, req('shell:'))
    c.send(S, okay())
    c.send(C, b'ls -l\n')
    c.send(S, b'ls -l\r\ntotal 0\r\n')
    c.send(C, b'exit\n')
    c.close()
    # a service request split between the length and the string
    c = cap.conn()
    transport(c)
    c.send(C, req('shell:getprop ro.build.version.sdk'), 4)
    c.send(S, okay(b'34\r\n'))
    c.close()

    # ---- logcat in both spellings
    stream = (logcat_v1(4, 'Tag', 'first entry') +
              logcat_v2(5, 'ActivityManager', 'second entry\nwith two lines') +
              logcat_v1(6, 'E', 'third entry') +
              logcat_v2(3, 'Debug', 'fourth entry') +
              logcat_v1(2, 'Verbose', 'fifth entry'))
    c = cap.conn()
    transport(c)
    c.send(C, req('shell:logcat -B'))
    c.send(S, okay())
    c.send(S, crlf(stream))
    # an entry split inside its header, inside its payload and between a CR
    # and the LF that follows it
    e1 = crlf(logcat_v1(4, 'Split', 'header cut'))
    e2 = crlf(logcat_v2(4, 'Split2', 'payload cut\nline two'))
    c.send(S, e1[:2])
    c.send(S, e1[2:] + e2[:40])
    c.send(S, e2[40:])
    e3 = crlf(logcat_v1(5, 'Cr', 'line\nwith cr lf\n'))
    cr = e3.index(b'\r')
    c.send(S, e3[:cr + 1])
    c.send(S, e3[cr + 1:])
    # the LF is the last octet of a segment
    e4 = crlf(logcat_v1(5, 'Last', 'ends with an LF\n'))
    c.send(S, e4)
    c.send(S, logcat_v1(4, 'Tail', 'after'))
    # a segment that ends with the LF of a CR LF
    e6 = crlf(logcat_v1(5, 'LfEnd', 'one\ntwo'))
    k = e6.index(b'\r\n') + 2
    c.send(S, e6[:k])
    c.send(S, e6[k:])
    # a segment of a single octet, which the stream consumes one by one
    e5 = logcat_v1(4, 'One', 'x')
    for i in range(0, 4):
        c.send(S, e5[i:i + 1])
    c.send(S, e5[4:])
    c.close()
    c = cap.conn()
    transport(c)
    c.send(C, req('shell:export ANDROID_LOG_TAGS="" ; exec logcat -B'))
    c.send(S, okay())
    c.send(S, logcat_v1(4, 'Tag', 'second spelling') + logcat_v1(4, 'T2', 'again')[:10])
    c.send(S, logcat_v1(4, 'T2', 'again')[10:])
    c.close()

    # ---- framebuffer: five pixel formats
    pix565 = b''.join(struct.pack('<H', (r << 11) | (g << 5) | b)
                      for r, g, b in ((31, 0, 0), (0, 63, 0), (0, 0, 31), (31, 63, 31)))
    formats = (
        # RGB565, odd number of octets: the last one is a fragment
        (fb_header(16, 9, 3, 1, (11, 5), (0, 5), (5, 6), (0, 0)), pix565 + b'\x55', 'rgb565'),
        # RGBA8888 and RGBX8888
        (fb_header(32, 16, 2, 2, (0, 8), (16, 8), (8, 8), (24, 8)),
         bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]), 'rgba'),
        (fb_header(32, 8, 2, 1, (0, 8), (16, 8), (8, 8), (24, 0)),
         bytes([1, 2, 3, 0, 5, 6, 7, 0]), 'rgbx'),
        # BGRA with the alpha channel in the first octet, and a partial pixel
        (fb_header(32, 7, 1, 1, (16, 8), (0, 8), (8, 8), (24, 8)), bytes([1, 2, 3, 4, 5, 6, 7]), 'bgra'),
        # RGB888: three octets per pixel, last pixel incomplete
        (fb_header(24, 8, 2, 1, (0, 8), (16, 8), (8, 8), (0, 0)),
         bytes([1, 2, 3, 4, 5, 6, 7, 8]), 'rgb888'),
        # 1 bit per colour: no detail
        (fb_header(8, 4, 2, 2, (5, 2), (0, 2), (2, 3), (0, 0)), bytes([1, 2, 3, 4]), 'other'),
    )
    for header, pixels, _ in formats:
        c = cap.conn()
        transport(c)
        c.send(C, req('framebuffer:'))
        c.send(S, okay())
        c.send(S, header + pixels)
        c.close()
    # the header and the pixel data in separate segments, the pixels in
    # three, and a second screenshot on the same connection
    c = cap.conn()
    transport(c)
    c.send(C, req('framebuffer:'))
    c.send(S, okay())
    hdr = fb_header(32, 64, 4, 4, (0, 8), (16, 8), (8, 8), (24, 8))
    c.send(S, hdr)
    c.send(S, bytes(range(24)))
    c.send(S, bytes(range(24, 48)))
    c.send(S, bytes(range(48, 64)))
    c.send(C, req('framebuffer:'))
    c.send(S, okay())
    c.send(S, fb_header(16, 4, 2, 1, (11, 5), (0, 5), (5, 6), (0, 0)) + pix565[:4])
    c.send(S, b'')
    c.close()
    # ---- track-jdwp
    c = cap.conn()
    transport(c)
    c.send(C, req('track-jdwp'))
    c.send(S, okay())
    c.send(S, hexlen(b'1234\n5678\n'))
    c.send(S, hexlen(b''))
    c.send(S, hexlen(b'42') + b'trailing text')
    c.close()
    c = cap.conn()
    transport(c)
    c.send(C, req('jdwp:1234'))
    c.send(S, okay())
    c.send(C, b'JDWP-Handshake')
    c.send(S, b'JDWP-Handshake')
    c.close()
    c = cap.conn()
    transport(c)
    c.send(C, req('sync:'))
    c.send(S, okay())
    c.send(C, b'STAT\x08\x00\x00\x00/sdcard')
    c.send(S, b'STAT\xed\x41\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00')
    c.close()
    # services with a text result
    for service, answer in ((b'root:', b'restarting adbd as root\n'),
                            (b'remount:', b'remount succeeded\n'),
                            (b'tcpip:5555', b'restarting in TCP mode port: 5555\n'),
                            (b'usb:', b'restarting in USB mode\n')):
        c = cap.conn()
        transport(c)
        c.send(C, req(service))
        c.send(S, okay())
        c.send(S, answer)
        c.send(S, b'')
        c.close()
    # a service that has no decoding, and one with the server answering
    # with no data at all
    c = cap.conn()
    c.send(C, req('host:kill'))
    c.send(S, okay())
    c.send(C, b'unrelated')
    c.send(S, b'\x00\x01')
    c.close()

    # ---- FAIL replies
    c = cap.conn()
    c.send(C, req('host:transport:NOSUCHDEVICE'))
    c.send(S, fail('device \'NOSUCHDEVICE\' not found'))
    c.close()
    # FAIL with the reason in a following segment, and a reason longer than
    # the length
    c = cap.conn()
    c.send(C, req('host:transport:ANOTHER'))
    c.send(S, fail('unknown host service', length=0x10), 8)
    c.send(C, req('host:version'))
    c.send(S, fail('device offline'))
    c.close()
    # FAIL with no reason
    c = cap.conn()
    c.send(C, req('shell:ls'))
    c.send(S, b'FAIL0000')
    c.close()
    # a status that is neither OKAY nor FAIL
    c = cap.conn()
    c.send(C, req('host:version'))
    c.send(S, b'WHAT0004003a')
    c.close()

    # ---- data without a request, in both directions, and an adb server
    # that speaks first
    c = cap.conn()
    c.send(S, b'OKAY')
    c.send(C, b'hello?')
    c.send(S, b'ABCD')
    c.send(C, b'0003abc')
    c.send(C, b'000ahost:other')
    c.send(S, okay(b'x'))
    c.close()
    # a request of a few octets, a request with a length that is not
    # followed by the service
    c = cap.conn(handshake=False)
    c.send(C, b'00')
    c.send(C, b'0005')
    c.send(C, b'hello')
    c.send(S, b'OKAY')
    c.send(C, b'more stuff')
    c.send(S, b'OKAY')

    # ---- a port that is decoded as ADB CS but is not the server port
    c = cap.conn(server_port=5038)
    c.send(C, req('host:version'))
    c.send(S, okay(hexlen(b'0029')))
    c.close()

    # ---- Exported PDU frame for adb_service with no ADB data
    cap.w.pkt(cap.exp, exported_pdu(b'\x00\x01\x02', proto='adb_service'))

    late(cap)


def late(cap):
    """Frames that used to throw; appended so that earlier frame numbers stay."""
    # an empty device list in track-devices (the server sends 0000 when the
    # last device goes away)
    c = cap.conn()
    c.send(C, req('host:track-devices'))
    c.send(S, okay(hexlen(SERIAL + b'\tdevice\n')))
    c.send(S, hexlen(b''))
    c.close()
    # empty results
    for service in (b'host:get-state', b'host:get-serialno'):
        c = cap.conn()
        c.send(C, req(service))
        c.send(S, okay())
        c.send(S, hexlen(b''))
        c.close()
    # the client sends data on a framebuffer connection
    c = cap.conn()
    transport(c)
    c.send(C, req('framebuffer:'))
    c.send(S, okay())
    c.send(S, fb_header(16, 4, 2, 1, (11, 5), (0, 5), (5, 6), (0, 0)) + b'\0\0\0\0')
    c.send(C, b'\x01\x02\x03')
    c.close()
    # framebuffer header shorter than 52 octets
    c = cap.conn()
    transport(c)
    c.send(C, req('framebuffer:'))
    c.send(S, okay())
    c.send(S, fb_header(16, 4, 2, 1, (11, 5), (0, 5), (5, 6), (0, 0))[:30])
    c.close()
    # an LF alone after a segment that ended with CR
    c = cap.conn()
    transport(c)
    c.send(C, req('shell:logcat -B'))
    c.send(S, okay())
    c.send(S, b'\x05\x00\x00\x00' + b'\r')
    c.send(S, b'\n')
    c.close()


def malformed(cap):
    c = cap.conn()
    c.send(C, req('host:version'))
    # the version is cut
    c.send(S, okay(hexlen(b'0029')[:6]))
    c.close()
    # a logcat entry that is longer than the maximum
    c = cap.conn()
    transport(c)
    c.send(C, req('shell:logcat -B'))
    c.send(S, okay())
    c.send(S, struct.pack('<HHIIII', 9000, 0, 1, 2, 3, 4) + b'x' * 100)
    c.send(S, struct.pack('<HHIIIII', 6000, 24, 1, 2, 3, 4, 5) + b'x' * 100)
    # the request is shorter than its length says
    c = cap.conn()
    c.send(C, b'0020host:version')
    c.send(C, b'000c')
    c.send(C, b'short')
    c.close()
    # a result that is cut: the length is larger than the remaining data
    c = cap.conn()
    c.send(C, req('host:devices'))
    c.send(S, b'OKAY00')
    c.close()
    c = cap.conn()
    c.send(C, req('host:get-state'))
    c.send(S, b'OKAY0005')
    c.close()
    c = cap.conn()
    c.send(C, req('host:transport:SERIAL'))
    c.send(S, b'FAIL00')
    c.close()
    # a request with a length of 5 and 3 octets of service, a service
    # name that begins with hex digits
    c = cap.conn()
    c.send(C, b'0005xyz')
    c.send(C, b'abcde')
    c.send(C, b'000bhost:other')
    c.close()
    # a pass-through of a very long request length
    c = cap.conn()
    c.send(C, b'ffffhost:version')
    c.close()


if __name__ == '__main__':
    out_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out_dir, exist_ok=True)
    build(os.path.join(out_dir, 'adb_cs-coverage.pcapng'),
          os.path.join(out_dir, 'adb_cs-coverage-malformed.pcapng'))
