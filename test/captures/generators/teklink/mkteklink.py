#!/usr/bin/env python3
# Generates test/captures/teklink_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the Tektronix TEKLINK dissector
(packet-teklink.c), an ONC RPC program (0x20400034, version 1) for
Tektronix TLA logic analyzers.

The RPC calls and replies travel over UDP (and TCP) on a port chosen by the
portmapper; Wireshark recognises RPC by its heuristic dissectors, which are
enabled by default, so no Decode As is needed. A reply is only dissected as
TEKLINK when the call was seen.

Usage: mkteklink.py <output directory>

Writes:
  teklink-coverage.pcap            a call and a reply for every procedure
                                   of the table, procedures without
                                   dissector, values past the end of the
                                   value strings and procedure numbers
                                   above 255 (reproducer of the 8 bit
                                   procedure field review item)
  teklink-coverage-malformed.pcap  calls and replies cut inside the
                                   arguments
"""

import struct
import sys
import os

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip4(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(map(int, src.split('.')))
    d = bytes(map(int, dst.split('.')))
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def eth(payload, ethertype=0x0800, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack('>H', ethertype) + payload


def udp(sport, dport, payload, rev=False):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    if rev:
        return eth(ip4(17, u, src='192.0.2.2', dst='192.0.2.1'), src=MAC_B, dst=MAC_A)
    return eth(ip4(17, u))


def tcp(sport, dport, seq, ack, payload, flags=0x18, rev=False):
    t = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 8192, 0, 0) + payload
    if rev:
        return eth(ip4(6, t, src='192.0.2.2', dst='192.0.2.1'), src=MAC_B, dst=MAC_A)
    return eth(ip4(6, t))


def pcapng(path, linktypes, frames):
    """frames: list of (interface index, bytes)."""
    def block(btype, body):
        pad = (-len(body)) % 4
        total = 12 + len(body) + pad
        return struct.pack('<II', btype, total) + body + b'\0' * pad + struct.pack('<I', total)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += block(1, struct.pack('<HHI', lt, 0, 65535))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    with open(path, 'wb') as f:
        f.write(out)


def usbhdr(urb_id, typ, xfer, ep, length, caplen, setup=b'\0' * 8, dev=1, bus=1,
           flag_setup=None, flag_data=0):
    """64-byte usbmon header (DLT 220). typ 'S' submit or 'C' complete."""
    if flag_setup is None:
        flag_setup = ord('-')
    return struct.pack('<QBBBBHBBqiiII8siiII', urb_id, ord(typ), xfer, ep, dev, bus,
                       flag_setup, flag_data, 0, 0, 0 if typ == 'C' else -115,
                       length, caplen, setup, 0, 0, 0, 0)


def usb_descriptor(urb, vid, pid, dev=1):
    """Two frames: GET DESCRIPTOR (device) submit and complete."""
    setup = struct.pack('<BBHHH', 0x80, 6, 0x0100, 0, 18)
    s = usbhdr(urb, 'S', 2, 0x80, 18, 0, setup, dev=dev, flag_setup=0, flag_data=ord('<'))
    desc = struct.pack('<BBHBBBBHHHBBBB', 18, 1, 0x0200, 0, 0, 0, 64, vid, pid, 0x0100, 0, 0, 0, 1)
    c = usbhdr(urb, 'C', 2, 0x80, 18, 18, setup, dev=dev, flag_setup=ord('-')) + desc
    return [s, c]


def usb_bulk_out(urb, data, ep=0x02, dev=1):
    return usbhdr(urb, 'S', 3, ep, len(data), len(data), dev=dev) + data


def usb_bulk_in(urb, data, ep=0x81, dev=1):
    return usbhdr(urb, 'C', 3, ep, len(data), len(data), dev=dev) + data

PROGRAM = 0x20400034


def xs(s):
    """XDR string."""
    b = s.encode() if isinstance(s, str) else s
    return struct.pack('>I', len(b)) + b + b'\0' * ((-len(b)) % 4)


def u(*vals):
    return b''.join(struct.pack('>I', v) for v in vals)


def rpc_call(xid, proc, args=b'', vers=1, prog=PROGRAM):
    return struct.pack('>IIIIII', xid, 0, 2, prog, vers, proc) + bytes(16) + args


def rpc_reply(xid, results=b''):
    return struct.pack('>IIIIII', xid, 1, 0, 0, 0, 0) + results


class Stream:
    def __init__(self, sport=700, dport=1234):
        self.frames = []
        self.xid = 0x1000
        self.sport = sport
        self.dport = dport

    def call(self, proc, args=b'', reply=None, reply_only=False, **kw):
        self.xid += 1
        self.frames.append(udp(self.sport, self.dport, rpc_call(self.xid, proc, args, **kw)))
        if reply is not None:
            self.frames.append(udp(self.dport, self.sport, rpc_reply(self.xid, reply), rev=True))


def main_frames():
    s = Stream()
    # 1: TLAFrameOpen: a number and three strings; reply: three numbers
    s.call(1, u(1) + xs('tla') + xs('operator') + xs('host-a'), u(0, 5, 6))
    # 2: TLAFrameClose
    s.call(2, u(0), u(0))
    # 3: GetSoftwareVersion: no arguments, reply 2 numbers and 2 strings
    s.call(3, b'', u(0, 4) + xs('TLA 5.3.1') + xs('Windows 2000'))
    # 4: GetInfo: reply with locked, type TLA715 (0x14), strings
    s.call(4, u(0, 0), u(1, 2, 0x14, 4) + xs('serial') + xs('lab 3') +
           xs('alice') + xs('host-b') + xs('last'))
    # 5: VtcIdent
    s.call(5, b'', u(0x1234, 0x5678))
    # 6: VtcOutEn: destination 12 (TTLTRIG0), enable on; reply is void
    s.call(7, u(12, 1), b'')
    # 7: VtcOutEn with destination 99 (unknown) and enable off
    s.call(7, u(99, 0), b'')
    # 8: VtcMap: APPSIG0 -> XBAR2, and unknown source 26 (XXX) and VCC
    s.call(8, u(0, 21), b'')
    s.call(8, u(27, 24), b'')
    s.call(8, u(200, 200), b'')
    # 9: VtcOutSetup: dst 3, enable on, polarity invert, feedback on
    s.call(9, u(3, 1, 1, 1), b'')
    s.call(9, u(24, 0, 0, 0), b'')
    s.call(9, u(0x30, 5, 7, 9), b'')
    # 10: VtcClk: dst 5, clock source CPUCLK, edge rise, synch; unknowns
    s.call(10, u(5, 3, 1, 1), b'')
    s.call(10, u(6, 0, 0, 0), b'')
    s.call(10, u(77, 8, 9, 10), b'')
    # 11: VtcMode: dst, edge, unknown long, mode
    s.call(11, u(2, 1, 0xdead, 7), b'')
    s.call(11, u(24, 0, 0, 0), b'')
    s.call(11, u(55, 6, 0, 55), b'')
    # 12: VtcRes
    s.call(12, u(9), b'')
    s.call(12, u(31), b'')
    # 13: VtcHardRes (no arguments, void reply)
    s.call(13, b'', b'')
    # 14: VtcSigStatAll
    s.call(14, b'', u(0x00ff00ff, 0x0f0f0f0f))
    # 20, 21: VtlZMode, VtlSpinBits
    s.call(20, b'', u(1))
    s.call(21, b'', u(0x80))
    # 65: unknown procedure with a command and five numbers; every command
    for cmd in (0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 9):
        s.call(65, u(cmd, 1, 2, 3, 4, 5), u(0))
    # procedures with a name but no dissector (15, 16, 30, 50) and unknown
    s.call(15, u(1, 2), u(3))
    s.call(16, b'', b'')
    s.call(30, b'abcd', b'efgh')
    s.call(54, u(1), u(2))
    # reproducer of the procedure field review: procedure number 0x1234
    # does not fit the 8 bit field (shown as "Unknown (4660)")
    s.call(0x1234, u(1), u(2))
    # a call of another version
    s.call(1, u(1) + xs('a') + xs('b') + xs('c'), u(0, 0, 0), vers=2)
    # a call without a reply and a reply without a call
    s.call(5, b'')
    s.frames.append(udp(1234, 700, rpc_reply(0x7777, u(1, 2)), rev=True))
    return s.frames


def malformed_frames():
    s = Stream(sport=1022, dport=4001)
    # calls with too few arguments, replies too short
    s.call(1, u(1) + xs('tla'), u(0, 5))            # call cut, reply cut
    s.call(8, u(3), b'')                            # VtcMap needs 8 octets
    s.call(9, u(3, 1, 1), b'')
    s.call(10, u(3, 1), b'')
    s.call(11, u(3), b'')
    s.call(7, b'\0\0', b'')
    s.call(12, b'', b'')
    s.call(65, u(1, 2), u(0))
    s.call(4, u(1), u(1, 2, 3))
    s.call(3, b'', u(1, 2) + b'\0\0\0\xff' + b'ab')  # string longer than data
    return s.frames


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'teklink-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'teklink-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
