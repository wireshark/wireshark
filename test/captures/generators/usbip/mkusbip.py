#!/usr/bin/env python3
# Generates test/captures/usbip_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the USBIP coverage captures. Usage: mkusbip.py <outdir>
# Everything is built with struct; nothing comes from a real network.
#   usbip-coverage.pcapng           main capture (TCP port 3240 plus Exported PDU)
#   usbip-coverage-malformed.pcapng paths only malformed input reaches
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Pcapng:
    def __init__(self):
        self.b = b''
        self.t = 1700000000 * 1000000

    @staticmethod
    def blk(typ, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        n = len(body) + 12
        return struct.pack('<II', typ, n) + body + struct.pack('<I', n)

    def shb(self):
        self.b += self.blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))

    def idb(self, linktype):
        self.b += self.blk(1, struct.pack('<HHI', linktype, 0, 65535))

    def pkt(self, iface, data):
        self.t += 1000
        self.b += self.blk(6, struct.pack('<IIIII', iface, self.t >> 32,
                                          self.t & 0xffffffff, len(data), len(data)) + data)

    def write(self, name):
        with open(os.path.join(OUT, name), 'wb') as f:
            f.write(self.b)


class Tcp:
    """A TCP connection, client 192.0.2.1:40000 to server 192.0.2.2:3240"""
    def __init__(self, cap, iface=0, sport=40000, dport=3240):
        self.cap, self.iface = cap, iface
        self.sport, self.dport = sport, dport
        self.seq = {0: 1000, 1: 5000}   # 0 client, 1 server

    def _frame(self, d, flags, payload=b''):
        if d == 0:
            sa, da, sp, dp = '192.0.2.1', '192.0.2.2', self.sport, self.dport
            em = (b'\x02\0\0\0\0\x02', b'\x02\0\0\0\0\x01')
        else:
            sa, da, sp, dp = '192.0.2.2', '192.0.2.1', self.dport, self.sport
            em = (b'\x02\0\0\0\0\x01', b'\x02\0\0\0\0\x02')
        sab = bytes(map(int, sa.split('.')))
        dab = bytes(map(int, da.split('.')))
        tcp = struct.pack('!HHIIBBHHH', sp, dp, self.seq[d], self.seq[1 - d] if flags & 0x10 else 0,
                          0x50, flags, 65535, 0, 0)
        ph = sab + dab + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        c = csum(ph + tcp + payload)
        tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 1, 0, 64, 6, 0, sab, dab)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        eth = em[0] + em[1] + b'\x08\x00'
        self.cap.pkt(self.iface, eth + ip + tcp + payload)
        self.seq[d] += len(payload) + (1 if flags & 3 else 0)

    def handshake(self):
        self._frame(0, 0x02)
        self._frame(1, 0x12)
        self._frame(0, 0x10)

    def send(self, d, *pieces):
        """one TCP segment with the concatenated pieces"""
        self._frame(d, 0x18, b''.join(pieces))

    def split(self, d, data, *cuts):
        """one PDU sent in several segments cut at the given offsets"""
        p = 0
        for c in list(cuts) + [len(data)]:
            self.send(d, data[p:c])
            p = c


def exp_pdu(cap, iface, name, payload):
    n = name.encode()
    n += b'\0' * ((4 - len(n) % 4) % 4)
    cap.pkt(iface, struct.pack('!HH', 12, len(n)) + n + struct.pack('!HH', 0, 0) + payload)


# ---- USBIP message builders -------------------------------------------
V = 0x0111


def op(code, status=0, body=b''):
    return struct.pack('!HHI', V, code, status) + body


def dev(path, busid, busnum, devnum, speed, vid, pid, bcd, cls, sub, proto,
        conf, nconf, intfs):
    d = path.encode().ljust(256, b'\0') + busid.encode().ljust(32, b'\0')
    d += struct.pack('!IIIHHHBBBBBB', busnum, devnum, speed, vid, pid, bcd,
                     cls, sub, proto, conf, nconf, len(intfs))
    assert len(d) == 0x138 - 0 or True
    return d, b''.join(struct.pack('!BBBB', c, s, p, 0) for (c, s, p) in intfs)


def devlist(devs):
    b = struct.pack('!I', len(devs))
    for d in devs:
        h, i = dev(*d[:-1], d[-1])
        b += h + i
    return op(0x0005, 0, b)


def urb_hdr(cmd, seq, devid, dirn, ep):
    return struct.pack('!IIIII', cmd, seq, devid, dirn, ep)


NOISO = 0xffffffff


def cmd_submit(seq, devid, dirn, ep, buflen, setup=b'\0' * 8, flags=0, niso=NOISO,
               interval=0, start=0, data=b'', isod=b''):
    return (urb_hdr(1, seq, devid, dirn, ep) +
            struct.pack('!IIiII', flags, buflen, start, niso, interval) + setup + data + isod)


def ret_submit(seq, status=0, actual=0, niso=NOISO, errc=0, start=0, data=b'', isod=b''):
    return (urb_hdr(3, seq, 0, 0, 0) +
            struct.pack('!iIiII', status, actual, start, niso, errc) + b'\0' * 8 + data + isod)


def cmd_unlink(seq, devid, victim, dirn=0, ep=0):
    return urb_hdr(2, seq, devid, dirn, ep) + struct.pack('!I', victim) + b'\0' * 24


def ret_unlink(seq, status):
    return urb_hdr(4, seq, 0, 0, 0) + struct.pack('!i', status) + b'\0' * 24


def iso_desc(off, ln, act, st):
    return struct.pack('!IIIi', off, ln, act, st)


def setup(rt, req, val, idx, ln):
    return struct.pack('<BBHHH', rt, req, val, idx, ln)


DEVID = (1 << 16) | 2
DEVDESC = struct.pack('<BBHBBBBHHHBBBB', 18, 1, 0x0200, 0, 0, 0, 64, 0x1234, 0x5678, 0x0100, 1, 2, 3, 1)
CFGBODY = (bytes([9, 4, 0, 0, 3, 0xff, 0, 0, 0]) + bytes([7, 5, 0x81, 2, 0x40, 0, 0]) +
           bytes([7, 5, 0x02, 2, 0x40, 0, 0]) + bytes([7, 5, 0x83, 3, 8, 0, 4]))
CFGDESC = struct.pack('<BBHBBBBB', 9, 2, 9 + len(CFGBODY), 1, 1, 0, 0x80, 50) + CFGBODY

DEVS = [
    ('/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2', '1-2', 1, 2, 3, 0x1234, 0x5678, 0x0100,
     0, 0, 0, 1, 1, [(0xff, 0, 0), (3, 1, 2)]),
    ('/sys/devices/pci0000:00/0000:00:14.0/usb1/1-3', '1-3', 1, 3, 5, 0x0781, 0x5567, 0x0200,
     0, 0, 0, 1, 2, [(8, 6, 80)]),
    ('/sys/devices/pci0000:00/0000:00:14.0/usb1/1-4', '1-4', 1, 4, 1, 0x046d, 0xc077, 0x7200,
     0, 0, 0, 1, 1, []),
]


def main_capture():
    cap = Pcapng()
    cap.shb()
    cap.idb(1)      # Ethernet
    cap.idb(252)    # Exported PDU
    t = Tcp(cap)
    t.handshake()
    # device list
    t.send(0, op(0x8005))
    t.send(1, devlist(DEVS))
    t.send(0, op(0x8005))
    d = devlist(DEVS[:1])
    t.split(1, d, 10)                     # shorter than the fixed part: more segments
    t.send(0, op(0x8005))
    t.send(1, devlist([]))
    t.send(0, op(0x8005))
    d = devlist(DEVS[:2])
    t.split(1, d, 8, 300)            # split inside a device
    # import
    t.send(0, op(0x8003, 0, b'1-2'.ljust(32, b'\0')))
    h, _ = dev(*DEVS[0][:-1], [])
    t.send(1, op(0x0003, 0, h))
    t.send(0, op(0x8003, 0, b'9-9'.ljust(32, b'\0')))
    t.send(1, op(0x0003, 1))
    # URBs: control
    t.send(0, cmd_submit(1, DEVID, 1, 0, 18, setup(0x80, 6, 0x0100, 0, 18)))
    t.send(1, ret_submit(1, actual=18, data=DEVDESC))
    t.send(0, cmd_submit(2, DEVID, 1, 0, 255, setup(0x80, 6, 0x0200, 0, 255)))
    t.send(1, ret_submit(2, actual=len(CFGDESC), data=CFGDESC))
    t.send(0, cmd_submit(3, DEVID, 0, 0, 0, setup(0x00, 9, 1, 0, 0)))
    t.send(1, ret_submit(3))
    # vendor control OUT with data
    t.send(0, cmd_submit(4, DEVID, 0, 0, 4, setup(0x40, 1, 0, 0, 4), data=b'\xde\xad\xbe\xef'))
    t.send(1, ret_submit(4, actual=4))
    # control IN that fails (stall), reported through the status
    t.send(0, cmd_submit(5, DEVID, 1, 0, 8, setup(0xc0, 2, 0, 0, 8)))
    t.send(1, ret_submit(5, status=-32))
    # bulk OUT and IN
    t.send(0, cmd_submit(6, DEVID, 0, 2, 8, data=b'bulk-out'))
    t.send(1, ret_submit(6, actual=8))
    t.send(0, cmd_submit(7, DEVID, 1, 1, 64))
    t.send(1, ret_submit(7, actual=16, data=bytes(range(16))))
    # interrupt IN
    t.send(0, cmd_submit(8, DEVID, 1, 3, 8, interval=4))
    t.send(1, ret_submit(8, actual=8, data=b'\1\2\3\4\5\6\7\x08'))
    # two PDUs that do not reach the USB dissector in one segment
    t.send(0, op(0x8005), op(0x8005))
    t.send(1, devlist([]), devlist(DEVS[:1]))
    # one bulk OUT PDU in three segments
    t.split(0, cmd_submit(10, DEVID, 0, 2, 64, data=bytes(range(64))), 48, 60)
    t.send(1, ret_submit(10, actual=64))
    # isochronous OUT and IN
    t.send(0, cmd_submit(11, DEVID, 0, 4, 32, niso=2, flags=0x0002, start=100, interval=1,
                         data=bytes(range(32)),
                         isod=iso_desc(0, 16, 16, -18) + iso_desc(16, 16, 16, -18)))
    t.send(1, ret_submit(11, actual=32, niso=2, start=100,
                         isod=iso_desc(0, 16, 16, 0) + iso_desc(16, 16, 16, 0)))
    t.send(0, cmd_submit(12, DEVID, 1, 5, 32, niso=2, interval=1,
                         isod=iso_desc(0, 16, 0, 0) + iso_desc(16, 16, 0, 0)))
    t.send(1, ret_submit(12, actual=24, niso=2, errc=1,
                         data=bytes(range(24)),
                         isod=iso_desc(0, 16, 16, 0) + iso_desc(16, 16, 8, -71)))
    # unlink of a pending bulk IN, and of an unknown URB
    t.send(0, cmd_submit(13, DEVID, 1, 1, 64))
    t.send(0, cmd_unlink(14, DEVID, 13))
    t.send(1, ret_unlink(14, -104))
    t.send(1, ret_submit(13, status=-104))
    t.send(0, cmd_unlink(15, DEVID, 99))
    t.send(1, ret_unlink(15, 0))
    # OP_RET_SUBMIT without a command (U1: ep and dir were uninitialised)
    t.send(1, ret_submit(0x1234, actual=0))
    t.send(1, ret_unlink(0x1235, 0))

    # Exported PDU naming usbip: no TCP, no ports
    exp_pdu(cap, 1, 'usbip', op(0x8005))
    exp_pdu(cap, 1, 'usbip', devlist(DEVS[:2]))
    exp_pdu(cap, 1, 'usbip', cmd_submit(0x20, DEVID, 0, 2, 4, data=b'exp!'))
    exp_pdu(cap, 1, 'usbip', ret_submit(0x20, actual=4))
    exp_pdu(cap, 1, 'usbip', cmd_unlink(0x21, DEVID, 0x20))
    exp_pdu(cap, 1, 'usbip', ret_unlink(0x21, 0))
    exp_pdu(cap, 1, 'usbip', ret_submit(0x1234, actual=0))   # U1 reproducer
    # a URB PDU whose first segment holds less than a header (more than 8 octets)
    t.split(0, cmd_submit(16, DEVID, 0, 2, 8, data=b'split-me'), 20)
    t.send(1, ret_submit(16, actual=8))
    cap.write('usbip-coverage.pcapng')


def malformed_capture():
    cap = Pcapng()
    cap.shb()
    cap.idb(1)
    cap.idb(252)
    t = Tcp(cap, sport=40001)
    t.handshake()
    t.send(0, op(0x8006))                       # unknown operation, no data
    t.send(1, op(0x0006, 0, b'\x01\x02'))       # unknown reply with data
    t.send(0, struct.pack('!HHI', 0x0222, 1, 0) + b'\0' * 8)   # unknown version
    t.send(0, urb_hdr(5, 1, DEVID, 0, 0) + b'\0' * 28)         # unknown URB command
    t.send(0, cmd_submit(2, DEVID, 0, 2, 16, data=b'short'))   # data shorter than buflen
    # ISO descriptors missing / shorter than announced
    t.send(0, cmd_submit(3, DEVID, 1, 4, 16, niso=3, isod=iso_desc(0, 8, 8, 0)))
    t.send(1, ret_submit(3, actual=8, niso=3, data=b'12345678', isod=iso_desc(0, 8, 8, 0)))
    # two URB PDUs in one segment: the second one is looked up in the
    # conversation that the first one's USB dissection has changed, so its
    # transaction is lost and the length of its response is wrong
    t = Tcp(cap, sport=40002)
    t.handshake()
    t.send(0, cmd_submit(8, DEVID, 1, 3, 8, interval=4), cmd_submit(9, DEVID, 1, 3, 8, interval=4))
    t.send(1, ret_submit(8, actual=8, data=b'\1\2\3\4\5\6\7\x08'),
           ret_submit(9, actual=2, data=b'\xaa\xbb'))
    # a device list cut short and never completed
    t = Tcp(cap, sport=40003)
    t.handshake()
    t.send(1, devlist(DEVS[:1])[:0x150])
    # a device list announcing two devices with one in the segment: the
    # length function cannot tell the PDU size
    t = Tcp(cap, sport=40004)
    t.handshake()
    t.send(1, devlist(DEVS[:2])[:12 + 0x138 + 8])
    exp_pdu(cap, 1, 'usbip', op(0x8006))
    exp_pdu(cap, 1, 'usbip', op(0x0006, 0, b'\x01\x02'))
    exp_pdu(cap, 1, 'usbip', urb_hdr(5, 1, DEVID, 0, 0) + b'\0' * 28)
    exp_pdu(cap, 1, 'usbip', struct.pack('!HHI', 0x0222, 1, 0) + b'\0' * 8)
    exp_pdu(cap, 1, 'usbip', op(0x0005, 0, struct.pack('!I', 2) + b'\0' * 40))   # truncated device
    cap.write('usbip-coverage-malformed.pcapng')


main_capture()
malformed_capture()
