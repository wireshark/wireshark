#!/usr/bin/env python3
# ADB coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Android Debug Bridge transport protocol (packet-adb.c) over TCP port 5555
and over USB bulk endpoints.

Usage: mkadb.py [<output directory>]

Writes:
  adb-coverage.pcapng            two interfaces: Ethernet with three ADB
                                 connections over TCP (host 192.0.2.1,
                                 device 192.0.2.2, port 5555) and a USB bus
                                 (Linux usbmon, 64 octet header) with an ADB
                                 interface; CNXN, AUTH, OPEN, OKAY, WRTE,
                                 CLSE, SYNC, payloads split over TCP
                                 segments and bulk transfers, services
  adb-coverage-malformed.pcapng  CRC error, payload longer than the data
                                 length, a data length that is never reached,
                                 a cut header, two commands in one segment
  adb-coverage-nointerface.pcap  three frames in a classic pcap file (records
                                 without an interface id)

Neither TCP port 5555 nor the USB interface is claimed by default, so
dissect with
  -d tcp.port==5555,adb -d usb.protocol==0xff4201,adb

Every packet is built here; nothing comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import TcpFlow, write_pcap  # noqa: E402
from usbgen import (BULK, Bus, Pcapng, LT_ETH, LT_USB_LINUX_MM, cfg_desc, dev_desc,  # noqa: E402
                    ep_desc, if_desc, string_desc, langid_desc)

A_SYNC = 0x434e5953
A_CLSE = 0x45534c43
A_WRTE = 0x45545257
A_AUTH = 0x48545541
A_CNXN = 0x4e584e43
A_OPEN = 0x4e45504f
A_OKAY = 0x59414b4f

ADB_PORT = 5555
HOST_TO_DEV, DEV_TO_HOST = 0, 1

# 2 interfaces: TCP/Ethernet and USB
CAPS = {}


def adb_sum(data):
    return sum(data) & 0xffffffff


def msg(cmd, arg0, arg1, data=b'', crc=None, magic=None, length=None):
    """A 24 octet ADB header followed by data."""
    if crc is None:
        crc = adb_sum(data) if data else 0
    if magic is None:
        magic = cmd ^ 0xffffffff
    if length is None:
        length = len(data)
    return struct.pack('<6I', cmd, arg0, arg1, length, crc, magic) + data


def cuts(blob, *points):
    """Split blob at the given offsets."""
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
        self.usb = self.w.idb(LT_USB_LINUX_MM)
        self.bus = Bus(self.w, 'mm', self.usb, bus=1)

    def tcp_conn(self, sport, handshake=True, dport=ADB_PORT):
        return Conn(self, sport, dport, handshake)

    def write(self, path):
        self.w.write(path)


class Conn:
    """A TCP connection; host is the client (port sport), the device
    listens on port 5555."""

    def __init__(self, cap, sport, dport, handshake):
        self.cap = cap
        self.flow = TcpFlow(sport=sport, dport=dport)
        if handshake:
            for fr in self.flow.handshake():
                cap.w.pkt(cap.eth, fr)

    def seg(self, direction, payload):
        fr = self.flow.send(payload) if direction == HOST_TO_DEV else self.flow.recv(payload)
        self.cap.w.pkt(self.cap.eth, fr)

    def send(self, direction, blob, *points):
        """Send blob as TCP segments, cut at the given offsets."""
        for part in cuts(blob, *points):
            self.seg(direction, part)

    def close(self):
        for fr in self.flow.close():
            self.cap.w.pkt(self.cap.eth, fr)


def logcat_v1(prio, tag, text, pid=100, tid=101, sec=1700000000, nsec=1000):
    payload = bytes([prio]) + tag.encode() + b'\0' + text.encode() + b'\0'
    return struct.pack('<HHIIII', len(payload), 0, pid, tid, sec, nsec) + payload


def logcat_v2(prio, tag, text, pid=100, tid=101, sec=1700000000, nsec=1000, euid=1000):
    payload = bytes([prio]) + tag.encode() + b'\0' + text.encode() + b'\0'
    return struct.pack('<HHIIIII', len(payload), 24, pid, tid, sec, nsec, euid) + payload


def build(path_main, path_bad, path_pcap):
    main = Capture()
    tcp_session(main)
    usb_session(main)
    after_command(main)
    main.write(path_main)

    bad = Capture()
    malformed(bad)
    bad.write(path_bad)

    # a classic pcap file has no interface id in its records
    frames = []
    flow = TcpFlow(sport=42000, dport=ADB_PORT)
    frames.append(flow.send(msg(A_OPEN, 1, 0, b'shell:ls\0')))
    frames.append(flow.recv(msg(A_OKAY, 5, 1)))
    frames.append(flow.recv(msg(A_WRTE, 5, 1, b'a\r\n')))
    write_pcap(path_pcap, frames)


# ---------------------------------------------------------------- TCP

def tcp_session(cap):
    # ---- connection 1: handshake, authentication, shell, logcat, sync
    c = cap.tcp_conn(40000)
    H, D = HOST_TO_DEV, DEV_TO_HOST
    # CNXN: version 1.0.0x0001, max data 256 KiB; header and banner in one
    # segment, and from the device in two.
    c.send(H, msg(A_CNXN, 0x01000001, 0x00040000, b'host::features=shell_v2,cmd\0'))
    c.send(D, msg(A_CNXN, 0x01000001, 4096,
                  b'device::ro.product.name=sdk;ro.product.model=Synthetic;features=cmd,shell_v2\0'), 24)
    # AUTH: token from the device, signature from the host (header and
    # payload in separate segments), a second token, then the public key in
    # three segments, and an unknown AUTH type
    c.send(D, msg(A_AUTH, 1, 0, bytes(range(20))))
    c.send(H, msg(A_AUTH, 2, 0, bytes((i * 7) & 0xff for i in range(256))), 24)
    c.send(D, msg(A_AUTH, 1, 0, bytes(range(20, 40))))
    key = (b'QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' * 40)[:1200] + b' user@host\0'
    c.send(H, msg(A_AUTH, 3, 0, key), 24, 600, 1000)
    c.send(D, msg(A_AUTH, 9, 0, b''))
    c.send(D, msg(A_CNXN, 0x01000001, 4096, b'device::features=cmd\0'))

    # shell service: OPEN from the host, OKAY from the device, data both ways
    c.send(H, msg(A_OPEN, 1, 0, b'shell:ls /sdcard\0'))
    c.send(D, msg(A_OKAY, 5, 1))
    c.send(D, msg(A_WRTE, 5, 1, b'a.txt\r\nb.txt\r\n'))
    c.send(H, msg(A_OKAY, 1, 5))
    c.send(H, msg(A_WRTE, 1, 5, b'echo hello\n'), 24)
    c.send(D, msg(A_OKAY, 5, 1))
    c.send(D, msg(A_WRTE, 5, 1, b'hello\r\n'), 24)
    c.send(H, msg(A_OKAY, 1, 5))
    # a write in three segments: header, 10 octets, the rest (reassembled)
    c.send(H, msg(A_WRTE, 1, 5, b'cat /proc/cpuinfo; cat /proc/meminfo\n'), 24, 34)
    c.send(D, msg(A_OKAY, 5, 1))
    c.send(H, msg(A_CLSE, 1, 5))
    c.send(D, msg(A_CLSE, 5, 1))

    # logcat service; the stream is carried by WRTE messages from the device
    c.send(H, msg(A_OPEN, 2, 0, b'shell:logcat -B\0'), 24)
    c.send(D, msg(A_OKAY, 6, 2))
    log = (logcat_v1(4, 'Tag', 'first line') + logcat_v2(5, 'ActivityManager', 'second line\nwith a newline') +
           logcat_v1(6, 'E', 'third'))
    c.send(D, msg(A_WRTE, 6, 2, log))
    c.send(H, msg(A_OKAY, 2, 6))
    # one entry cut in the middle of the payload, across two messages
    e = logcat_v1(3, 'Dalvik', 'a log entry that is split between two messages')
    c.send(D, msg(A_WRTE, 6, 2, e[:30]))
    c.send(H, msg(A_OKAY, 2, 6))
    c.send(D, msg(A_WRTE, 6, 2, e[30:] + logcat_v1(4, 'T', 'next')))
    c.send(H, msg(A_OKAY, 2, 6))
    # a message of 5000 octets sent over three TCP segments, reassembled and
    # handed to the service as a whole
    big = b''.join(logcat_v1(4, 'Big', 'line %04d ' % i + 'x' * 40) for i in range(60))
    c.send(D, msg(A_WRTE, 6, 2, big), 24, 1500, 3000)
    c.send(H, msg(A_OKAY, 2, 6))
    c.send(H, msg(A_CLSE, 2, 6))
    c.send(D, msg(A_CLSE, 6, 2))

    # a sync service, a jdwp service and a service that is not known
    c.send(H, msg(A_OPEN, 3, 0, b'sync:\0'))
    c.send(D, msg(A_OKAY, 7, 3))
    c.send(H, msg(A_WRTE, 3, 7, b'STAT\x08\x00\x00\x00/sdcard'))
    c.send(D, msg(A_OKAY, 7, 3))
    c.send(D, msg(A_WRTE, 7, 3, b'STAT\xed\x41\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00'))
    c.send(H, msg(A_OKAY, 3, 7))
    c.send(H, msg(A_CLSE, 3, 7))
    c.send(D, msg(A_CLSE, 7, 3))
    c.send(H, msg(A_OPEN, 4, 0, b'jdwp:1234\0'))
    c.send(D, msg(A_OKAY, 8, 4))
    c.send(H, msg(A_WRTE, 4, 8, b'JDWP-Handshake'))
    c.send(D, msg(A_OKAY, 8, 4))
    c.send(D, msg(A_WRTE, 8, 4, b'JDWP-Handshake'))
    c.send(H, msg(A_OKAY, 4, 8))
    c.send(H, msg(A_OPEN, 5, 0, b'tcpip:5555\0'))
    c.send(D, msg(A_OKAY, 9, 5))
    c.send(D, msg(A_WRTE, 9, 5, b'restarting in TCP mode port: 5555\n'))
    c.send(H, msg(A_OKAY, 5, 9))
    c.send(H, msg(A_OPEN, 6, 0, b'foo:bar\0'))
    c.send(D, msg(A_OKAY, 10, 6))
    c.send(D, msg(A_WRTE, 10, 6, b'\x01\x02\x03\x04'))
    c.send(H, msg(A_OKAY, 6, 10))
    c.send(H, msg(A_SYNC, 1, 42))
    c.send(D, msg(A_SYNC, 0, 43))
    # an OPEN whose service string comes in a second segment
    c.send(H, msg(A_OPEN, 7, 0, b'root:\0'), 24)
    c.send(D, msg(A_OKAY, 11, 7))
    c.send(D, msg(A_WRTE, 11, 7, b'restarting adbd as root\n'))
    c.send(H, msg(A_CLSE, 7, 11))
    c.send(D, msg(A_CLSE, 11, 7))
    # writes and closes on ids that were never opened: shown as raw data
    c.send(H, msg(A_WRTE, 77, 88, b'raw payload'))
    c.send(D, msg(A_OKAY, 88, 77))
    c.send(H, msg(A_CLSE, 77, 88))

    # an OKAY from the host for ids that were never opened
    c.send(H, msg(A_OKAY, 99, 98))
    # a valid checksum is not an error
    c.send(H, msg(A_WRTE, 77, 88, b'ok sum', crc=adb_sum(b'ok sum')))
    c.close()

    # ---- connection 2 (port 40001): reproducer of the second pass: a WRTE
    # that promises 24 octets, followed by 24 octets that look like an OPEN
    c2 = cap.tcp_conn(40001, handshake=False)
    c2.send(H, msg(A_WRTE, 1, 2, length=24))
    c2.send(H, struct.pack('<6I', A_OPEN, 0x6c656873, 0x3a, 0, 0, A_OPEN ^ 0xffffffff))

    # ---- connection 3 (port 40002): the device speaks first, a service is
    # opened with a payload that follows in the next segment, the OPEN has
    # arg1 set and a write is continued after the local id is reused
    c3 = cap.tcp_conn(40002, handshake=False)
    c3.send(D, msg(A_CNXN, 0x01000001, 65536, b'device::\0'))
    c3.send(H, msg(A_OPEN, 3, 0, b'shell:id\0'), 24)
    c3.send(D, msg(A_OKAY, 12, 3))
    c3.send(D, msg(A_WRTE, 12, 3, b'uid=0(root)\n'))
    c3.send(H, msg(A_CLSE, 3, 12))
    c3.send(D, msg(A_CLSE, 12, 3))
    # the local id 3 is used again for another service on the same connection
    c3.send(H, msg(A_OPEN, 3, 0, b'shell:pwd\0'))
    c3.send(D, msg(A_OKAY, 13, 3))
    c3.send(D, msg(A_WRTE, 13, 3, b'/\n'))
    c3.send(H, msg(A_CLSE, 3, 13))
    # an OKAY from the host for a remote id before the device answered
    c3.send(H, msg(A_OKAY, 3, 13))


# ---------------------------------------------------------------- USB

def usb_session(cap):
    bus = cap.bus
    dev = 5
    desc = dev_desc(cls=0, sub=0, proto=0, vid=0x18d1, pid=0x4ee7, bcd=0x0200)
    cfg = cfg_desc(if_desc(0, 0, 2, 0xff, 0x42, 0x01) +
                   ep_desc(0x81, 2, 512) + ep_desc(0x01, 2, 512))
    bus.enumerate(dev, desc, cfg, [langid_desc(0x0409), string_desc('Synthetic'),
                                   string_desc('ADB device'), string_desc('0123456789ABCDEF')])
    OUT, IN = 0x01, 0x81

    def out(blob, *points):
        for part in cuts(blob, *points):
            bus.xfer(dev, OUT, BULK, data=part)

    def inn(blob, *points):
        for part in cuts(blob, *points):
            bus.xfer(dev, IN, BULK, data=part)

    out(msg(A_CNXN, 0x01000001, 0x00040000, b'host::features=shell_v2\0'), 24)
    inn(msg(A_CNXN, 0x01000001, 4096, b'device::ro.product.name=usbdev;features=shell_v2\0'), 24)
    inn(msg(A_AUTH, 1, 0, bytes(range(20))))
    out(msg(A_AUTH, 2, 0, bytes(range(256)) * 2), 24, 300)
    out(msg(A_OPEN, 1, 0, b'shell:getprop ro.build.version.sdk\0'), 24)
    inn(msg(A_OKAY, 5, 1))
    inn(msg(A_WRTE, 5, 1, b'34\r\n'), 24)
    out(msg(A_OKAY, 1, 5))
    out(msg(A_CLSE, 1, 5))
    inn(msg(A_CLSE, 5, 1))
    # logcat over USB with an entry split between two bulk transfers
    out(msg(A_OPEN, 2, 0, b'shell:export ANDROID_LOG_TAGS="" ; exec logcat -B\0'), 24)
    inn(msg(A_OKAY, 6, 2))
    e = logcat_v2(4, 'usb', 'a log entry over USB, split over two WRTE messages')
    inn(msg(A_WRTE, 6, 2, logcat_v2(3, 'usb', 'complete') + e[:40]), 24)
    out(msg(A_OKAY, 2, 6))
    inn(msg(A_WRTE, 6, 2, e[40:]), 24)
    out(msg(A_OKAY, 2, 6))
    # a service message in two bulk transfers after its header: the
    # reassembled data is handed to the service
    inn(msg(A_WRTE, 6, 2, logcat_v2(2, 'usb', 'assembled from two transfers') + logcat_v1(2, 'usb', 'x')),
        24, 60)
    out(msg(A_OKAY, 2, 6))
    # a second device address with its own conversation
    dev2 = 6
    bus.enumerate(dev2, desc, cfg, [langid_desc(0x0409), string_desc('Synthetic'),
                                    string_desc('ADB device'), string_desc('FEDCBA9876543210')])
    bus.xfer(dev2, OUT, BULK, data=msg(A_CNXN, 0x01000001, 4096, b'host::\0'))
    bus.xfer(dev2, IN, BULK, data=msg(A_CNXN, 0x01000001, 4096, b'device::\0'))
    bus.xfer(dev2, OUT, BULK, data=msg(A_OPEN, 1, 0, b'shell:true\0'))
    bus.xfer(dev2, IN, BULK, data=msg(A_OKAY, 5, 1))
    bus.xfer(dev2, IN, BULK, data=msg(A_WRTE, 5, 1, b'done\n'))


# ---------------------------------------------------------------- frames after a command

def after_command(cap):
    H, D = HOST_TO_DEV, DEV_TO_HOST
    # frames after a complete command that are not commands: the first pass
    # takes the data length of the previous command, the second pass does
    # not, both passes show them as data
    c = cap.tcp_conn(40003)
    c.send(H, msg(A_WRTE, 77, 88, b'raw payload'))
    c.send(D, msg(A_OKAY, 88, 77, magic=0x12345678))
    c.send(H, b'abc')
    c.send(H, b'\x00' * 24)
    c.send(H, struct.pack('<6I', 0x44444444, 1, 2, 0, 0, 0xbbbbbbbb) + b'tail')


# ---------------------------------------------------------------- malformed

def malformed(cap):
    H, D = HOST_TO_DEV, DEV_TO_HOST
    c = cap.tcp_conn(41000)
    c.send(H, msg(A_OPEN, 1, 0, b'shell:ls\0'))
    c.send(D, msg(A_OKAY, 5, 1))
    # wrong checksum
    c.send(D, msg(A_WRTE, 5, 1, b'abc', crc=0x12345))
    c.send(H, msg(A_OKAY, 1, 5))
    # the payload is longer than the data length
    c.send(H, msg(A_WRTE, 1, 5, b'1234', length=2))
    c.send(D, msg(A_OKAY, 5, 1))
    c.send(H, msg(A_WRTE, 1, 5, b'hello'), 24)
    c.send(H, b'more payload than announced')
    # logcat entry longer than the maximum
    c.send(H, msg(A_OPEN, 2, 0, b'shell:logcat -B\0'))
    c.send(D, msg(A_OKAY, 6, 2))
    c.send(D, msg(A_WRTE, 6, 2, struct.pack('<HHIIII', 9000, 0, 1, 2, 3, 4) + b'\0' * 100))
    # a write whose data length is large and never completes
    c.send(H, msg(A_WRTE, 1, 5, b'x' * 10, length=100000))
    c.send(H, b'y' * 100)
    # header that is cut in the capture
    c.send(D, msg(A_OKAY, 5, 1)[:18])
    # two commands in one segment: the second is shown as payload of the first
    c.send(H, msg(A_WRTE, 3, 13, b'x') + msg(A_OKAY, 3, 13))


if __name__ == '__main__':
    out_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out_dir, exist_ok=True)
    build(os.path.join(out_dir, 'adb-coverage.pcapng'),
          os.path.join(out_dir, 'adb-coverage-malformed.pcapng'),
          os.path.join(out_dir, 'adb-coverage-nointerface.pcap'))
