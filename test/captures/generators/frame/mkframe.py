#!/usr/bin/env python3
# Generates test/captures/frame_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Frame dissector
(packet-frame.c), which runs for every record of every capture file.

The dissector's own code is mostly about what a capture file carries
around the packets, so the main capture is a pcapng file with:
  * interface names and descriptions, an unnamed interface, link-layer
    types with a pseudo header that sets the direction (MTP2, LAPD,
    Bluetooth H4 with direction, PPP with direction),
  * process information blocks (the Wireshark custom block and the
    legacy Darwin block) and packets that name processes,
  * every packet option: comments (single line, multi-line, longer than
    max_comment_lines), flags, hashes of every type, verdicts of every
    type, packet id, queue, drop count, process and thread ids, custom
    string and binary options and the Darwin options,
  * a second section, simple packet blocks (no time stamp), systemd
    journal export blocks and custom blocks.

Every record is built with struct; no captured traffic is used.

Usage: mkframe.py <output directory>

Writes:
  frame-coverage.pcapng            the capture above
  frame-coverage-bluetooth.pcapng  Bluetooth H4 with direction (coverage only)
  frame-coverage-visual-chdlc.vwr  Cisco HDLC with a pseudo header (Visual)
  frame-coverage-visual-lapb.vwr   LAPB with a pseudo header (Visual)
  frame-coverage-malformed.pcap    time stamps and lengths out of range
"""
import os
import struct
import sys
import socket

LE = '<'


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload


def udp(sp, dp, payload):
    return struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload


def eth_ip(payload=b'frame test'):
    return (bytes([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]) + b'\x08\x00'
            + ip4(17, udp(1000, 2000, payload)))


def pad4(b):
    return b + b'\0' * ((-len(b)) % 4)


def opt(code, val=b''):
    return struct.pack(LE + 'HH', code, len(val)) + pad4(val)


def endopt():
    return struct.pack(LE + 'HH', 0, 0)


def block(btype, body):
    body = pad4(body)
    n = 12 + len(body)
    return struct.pack(LE + 'II', btype, n) + body + struct.pack(LE + 'I', n)


def shb(comment=None):
    o = b''
    if comment:
        o = opt(1, comment) + endopt()
    return block(0x0A0D0D0A, struct.pack(LE + 'IHHq', 0x1A2B3C4D, 1, 0, -1) + o)


def idb(linktype, name=None, descr=None):
    o = b''
    if name:
        o += opt(2, name.encode())
    if descr:
        o += opt(3, descr.encode())
    if o:
        o += endopt()
    return block(1, struct.pack(LE + 'HHI', linktype, 0, 0) + o)


def epb(ifc, pkt, ts, opts=b'', origlen=None):
    ol = len(pkt) if origlen is None else origlen
    body = struct.pack(LE + 'IIIII', ifc, ts >> 32, ts & 0xffffffff, len(pkt), ol) + pad4(pkt)
    if opts:
        body += opts + endopt()
    return block(6, body)


def spb(pkt):
    return block(3, struct.pack(LE + 'I', len(pkt)) + pad4(pkt))


def pib_ws(pid, name=None, path=None, cmdline=None, ppid=None, uid=None, user=None,
           uuid=None, start=None):
    """Wireshark custom block, entry type 3: process information"""
    o = b''
    if name is not None:
        o += opt(2, name.encode())
    if path is not None:
        o += opt(3, path.encode())
    if cmdline is not None:
        o += opt(4, cmdline)
    if ppid is not None:
        o += opt(5, struct.pack(LE + 'I', ppid))
    if uid is not None:
        o += opt(6, struct.pack(LE + 'I', uid))
    if user is not None:
        o += opt(7, user.encode())
    if uuid is not None:
        o += opt(8, uuid)
    if start is not None:
        o += opt(9, struct.pack(LE + 'Q', start))
    o += endopt()
    entry = struct.pack(LE + 'I', pid) + o
    body = struct.pack(LE + 'III', 32622, 3, len(entry)) + pad4(entry)
    return block(0x00000BAD, body)


def pib_darwin(pid, name=None, uuid=None):
    o = b''
    if name:
        o += opt(2, name.encode())
    if uuid:
        o += opt(4, uuid)
    o += endopt()
    return block(0x80000001, struct.pack(LE + 'I', pid) + o)


def custom_block(pen, data, copy=True):
    return block(0x00000BAD if copy else 0x40000BAD, struct.pack(LE + 'I', pen) + data)


PKT = eth_ip()
T0 = 1700000000 * 1000000


def main(out):
    d = shb(b'synthetic frame coverage capture')
    d += idb(1, 'eth0', 'first test interface')          # 0
    d += idb(1)                                          # 1: unnamed
    d += idb(139, 'mtp2')                                # 2: MTP2 with pseudo header
    d += idb(177, 'lapd')                                # 3: LAPD
    d += idb(1, 'unused')                                # 4
    d += idb(204, 'ppp')                                 # 5: PPP with direction
    d += idb(2, 'noenc')                                 # 6: link-layer type without a dissector
    # process information blocks
    uuid = bytes(range(16))
    d += pib_ws(1234, 'testd', '/usr/sbin/testd', b'/usr/sbin/testd\0--flag\0value', 1, 1000,
                'tester', uuid, 1699999990 * 1000000000)
    d += pib_ws(77, 'bare')
    d += pib_darwin(4321, 'darwind', uuid)
    n = [0]

    def ts():
        n[0] += 1
        return T0 + n[0] * 250000

    def pkt(opts=b'', ifc=0, p=PKT):
        return epb(ifc, p, ts(), opts)

    # 1 plain
    d += pkt()
    # 2 comments: single line, multi-line, more lines than max_comment_lines (10)
    d += pkt(opt(1, b'a single line comment'))
    d += pkt(opt(1, b'first\nsecond\nthird'))
    d += pkt(opt(1, b''.join(b'line %d\n' % i for i in range(1, 16))) + opt(1, b'x\ny\n'))
    # 5 flags: inbound, outbound, unknown; every reception type; fcs length; errors
    d += pkt(opt(2, struct.pack(LE + 'I', 0x1)))
    d += pkt(opt(2, struct.pack(LE + 'I', 0x2 | (1 << 2) | (4 << 5) | 0xff000000)), p=PKT + bytes(4))
    d += pkt(opt(2, struct.pack(LE + 'I', 0x0 | (2 << 2))))
    d += pkt(opt(2, struct.pack(LE + 'I', 0x3 | (3 << 2) | (4 << 2))))
    # 9 hashes of each type, an empty one and a long one
    for t, ln in ((0, 1), (1, 1), (2, 4), (3, 16), (4, 20), (5, 4), (9, 3)):
        d += pkt(opt(3, bytes([t]) + bytes(range(ln))))
    d += pkt(opt(3, bytes([2, 0xaa, 0xbb, 0xcc, 0xdd])) + opt(3, bytes([0, 0xcc])))
    # 17 verdicts: hardware, eBPF TC, eBPF XDP, unknown, several at once
    d += pkt(opt(7, b'\x00' + b'\x11\x22'))
    d += pkt(opt(7, b'\x01' + struct.pack(LE + 'q', -5)))
    d += pkt(opt(7, b'\x02' + struct.pack(LE + 'q', 2)))
    d += pkt(opt(7, b'\x05' + b'unk'))
    d += pkt(opt(7, b'\x01' + struct.pack(LE + 'q', 1)) + opt(7, b'\x02' + struct.pack(LE + 'q', 3)))
    # 22 queue, packet id, drop count
    d += pkt(opt(6, struct.pack(LE + 'I', 3)) + opt(5, struct.pack(LE + 'Q', 0x1122334455667788))
             + opt(4, struct.pack(LE + 'Q', 12)))
    # 23 processes: known with full info, known name only, unknown pid, pid 0, tid 0,
    # several processes, a Darwin process
    d += pkt(opt(8, struct.pack(LE + 'II', 1234, 99)))
    d += pkt(opt(8, struct.pack(LE + 'II', 77, 0)))
    d += pkt(opt(8, struct.pack(LE + 'II', 5555, 5)))
    d += pkt(opt(8, struct.pack(LE + 'II', 0, 7)))
    d += pkt(opt(8, struct.pack(LE + 'II', 1234, 1)) + opt(8, struct.pack(LE + 'II', 77, 2)))
    d += pkt(opt(8, struct.pack(LE + 'II', 4321, 3)))
    # 29 custom options: string and binary, copy and no-copy, with PEN 32473 (documentation)
    d += pkt(opt(2988, struct.pack(LE + 'I', 32473) + b'copyable string')
             + opt(2989, struct.pack(LE + 'I', 32473) + b'\x01\x02\x03')
             + opt(19372, struct.pack(LE + 'I', 32473) + b'no copy string')
             + opt(19373, struct.pack(LE + 'I', 32473) + b'\xaa\xbb'))
    # 30 Darwin options (indexes of the process information blocks): process, service code, effective process, metadata flags, flow id
    d += pkt(opt(32769, struct.pack(LE + 'I', 2)) + opt(32770, struct.pack(LE + 'I', 1))
             + opt(32771, struct.pack(LE + 'I', 0)) + opt(32772, struct.pack(LE + 'I', 0x5))
             + opt(32773, struct.pack(LE + 'I', 77)))
    # 31 the interface without a name; frame shorter than captured
    d += pkt(ifc=1)
    # 32-37 pseudo headers: MTP2 (sent, annex A, link number), LAPD, PPP
    d += pkt(ifc=2, p=struct.pack('>BBH', 1, 0, 3) + bytes([0x00, 0x00, 0x00]))
    d += pkt(ifc=2, p=struct.pack('>BBH', 0, 0, 7) + bytes([0x00, 0x00, 0x00]))
    sll = struct.pack('>HHH', 3, 0, 1) + bytes([1] + [0] * 7) + struct.pack('>H', 0x0030)
    d += pkt(ifc=3, p=sll + bytes([0x00, 0x01, 0x3f]))
    sll = struct.pack('>HHH', 0, 0, 1) + bytes([0] * 8) + struct.pack('>H', 0x0030)
    d += pkt(ifc=3, p=sll + bytes([0x00, 0x01, 0x3f]))
    d += pkt(ifc=5, p=bytes([1]) + bytes([0xff, 0x03, 0x00, 0x21]) + ip4(17, udp(1, 2, b'ppp')))
    d += pkt(ifc=5, p=bytes([0]) + bytes([0xff, 0x03, 0x00, 0x21]) + ip4(17, udp(1, 2, b'ppp')))
    # 40 packet with all options together
    d += pkt(opt(1, b'combined\ncomment') + opt(2, struct.pack(LE + 'I', 0x1)) + opt(3, b'\x03' + bytes(16))
             + opt(7, b'\x01' + struct.pack(LE + 'q', 9)) + opt(6, struct.pack(LE + 'I', 1))
             + opt(8, struct.pack(LE + 'II', 1234, 1)))
    # captured length shorter than the original length
    d += epb(0, PKT[:40], ts(), b'', origlen=len(PKT))
    # simple packet block: no time stamp, no interface options
    d += spb(PKT)
    # systemd journal export entries
    d += block(9, b'__REALTIME_TIMESTAMP=1700000100000000\nMESSAGE=hello from the journal\n_PID=42\n\n')
    d += block(9, b'__REALTIME_TIMESTAMP=1700000101000000\nPRIORITY=3\nMESSAGE=second entry\n\n')
    # a Sysdig/Falco event block (version 2): generic syscall enter event
    ev = struct.pack(LE + 'QQIHI', 1700000102 * 10**9, 1234, 22 + 4 + 4 + 4, 1, 2) + struct.pack(LE + 'HH', 2, 2) \
        + struct.pack(LE + 'HH', 3, 5)
    d += block(0x216, struct.pack(LE + 'H', 0) + ev)
    # custom blocks, with an unknown PEN: copy allowed and not allowed
    d += custom_block(32473, b'custom block data\0\0\0', True)
    d += custom_block(32473, b'no copy', False)
    # a record of a link-layer type without a dissector
    d += pkt(ifc=6, p=b'payload of an unknown encapsulation')
    # second section with its own interfaces and process information
    d += shb()
    d += idb(1, 'eth1', 'second section')
    d += pib_ws(1234, 'otherd', '/usr/sbin/otherd', None, 2, 0, 'root')
    d += pkt(opt(8, struct.pack(LE + 'II', 1234, 4)))
    d += pkt()
    d += spb(PKT)
    open(os.path.join(out, 'frame-coverage.pcapng'), 'wb').write(d)

    # Bluetooth H4 with direction pseudo header: the HCI dissectors show
    # more in the second pass (request/response), so it is a separate
    # capture that is only used for the coverage number.
    d = shb() + idb(201, 'bt')
    d += epb(0, struct.pack('>I', 0) + bytes([0x01, 0x03, 0x0c, 0x00]), T0)
    d += epb(0, struct.pack('>I', 1) + bytes([0x04, 0x05, 0x04, 0x00, 0x01, 0x00, 0x13]), T0 + 1000)
    open(os.path.join(out, 'frame-coverage-bluetooth.pcapng'), 'wb').write(d)

    # Visual Networks files with a direction pseudo header
    def visual(path, media, frames):
        hdr = b'\x05VNF' + struct.pack('<IIHHHHIH', len(frames), 1700000000, media, 1518, 0, 1, 64000, 0)
        hdr += b'\0' * 102 + b'synthetic'.ljust(64, b'\0')
        body = b''
        for i, (x, st) in enumerate(frames):
            body += struct.pack('<IHHIBB6s', i * 10, len(x) + 2, len(x), st, 0, 0, b'\0' * 6) + x
        open(path, 'wb').write(hdr + body)
    visual(os.path.join(out, 'frame-coverage-visual-chdlc.vwr'), 22,
           [(b'\x0f\x00\x08\x00' + ip4(17, udp(1, 2, b'chdlc')), 0x40),
            (b'\x0f\x00\x08\x00' + ip4(17, udp(1, 2, b'chdlc')), 0)])
    visual(os.path.join(out, 'frame-coverage-visual-lapb.vwr'), 16,
           [(bytes([0x01, 0x3f]), 0x40), (bytes([0x03, 0x73]), 0)])

    # malformed: a nanosecond pcap with an invalid fraction, caplen > len
    m = struct.pack('<IHHiIII', 0xa1b23c4d, 2, 4, 0, 0, 65535, 1)
    for ns, caplen, olen in ((2000000000, len(PKT), len(PKT)), (5, len(PKT), len(PKT) - 10)):
        m += struct.pack('<IIII', 1700000000, ns, caplen, olen) + PKT
    open(os.path.join(out, 'frame-coverage-malformed.pcap'), 'wb').write(m)


if __name__ == '__main__':
    main(sys.argv[1])
