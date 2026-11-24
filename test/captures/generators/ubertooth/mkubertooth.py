#!/usr/bin/env python3
# Generates test/captures/ubertooth_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Ubertooth coverage captures: mkubertooth.py <outdir>

ubertooth-coverage.pcap            an Ubertooth One (1d50:6002) on Linux usbmon
ubertooth-coverage-malformed.pcap  responses that do not fit, truncated frames
Link type 220 (LINKTYPE_USB_LINUX_MMAPPED). The device is recognised from
the vendor and product id in its device descriptor, as in a real capture.
"""
import os
import random
import struct
import sys

rnd = random.Random(6001)
BUS = 1


class Cap:
    def __init__(self, dev=2):
        self.recs = []
        self.id = 0x2000
        self.t = 0
        self.dev = dev

    def _rec(self, urb_id, typ, xfer, ep, setup, data, urb_len, status=0):
        self.t += 1
        if setup is not None:
            flag_setup, setup_b = b'\x00', setup
        else:
            flag_setup, setup_b = b'-', b'\x00' * 8
        flag_data = b'\x00' if data else b'<'
        hdr = struct.pack('<QcBBBHcc', urb_id, typ, xfer, ep, self.dev, BUS, flag_setup, flag_data)
        hdr += struct.pack('<qiiII', 1700000000, self.t, status, urb_len, len(data))
        hdr += setup_b
        hdr += struct.pack('<iiII', 0, 0, 0, 0)
        assert len(hdr) == 64
        self.recs.append(hdr + data)

    def control(self, setup, resp=b'', out_data=b'', complete=None):
        if complete is None:
            # the completion of an OUT command has no data: the dissector reports it
            # as an unexpected response (see README), so the main capture omits it
            complete = bool(setup[0] & 0x80)
        self.id += 1
        wlen = struct.unpack('<H', setup[6:8])[0]
        ep = 0x80 if setup[0] & 0x80 else 0x00
        self._rec(self.id, b'S', 2, ep, setup, out_data, wlen)
        if complete:
            self._rec(self.id, b'C', 2, ep, None, resp, len(resp))

    def bulk_in(self, data, ep=0x82):
        self.id += 1
        self._rec(self.id, b'S', 3, ep, None, b'', 1024)
        self._rec(self.id, b'C', 3, ep, None, data, len(data))

    def enumerate(self, vid=0x1d50, pid=0x6002):
        dd = struct.pack('<BBHBBBBHHHBBBB', 18, 1, 0x0200, 0xff, 0, 0, 64, vid, pid, 0x0100, 1, 2, 0, 1)
        self.control(bytes([0x80, 6, 0, 1, 0, 0, 18, 0]), dd)

    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 220))
            for i, r in enumerate(self.recs):
                f.write(struct.pack('<IIII', 1700000000 + i, 0, len(r), len(r)) + r)


def setup(cmd, wvalue=0, windex=0, wlength=0, dir_in=False):
    return struct.pack('<BBHHH', 0xc0 if dir_in else 0x40, cmd, wvalue & 0xffff, windex & 0xffff, wlength)


def rb(n):
    return bytes(rnd.getrandbits(8) for _ in range(n))


def rx_packet(ptype, status=0x00, channel=39, clock100=123456, payload=b'', state=None, ns=17):
    """64 octet Ubertooth USB Rx packet."""
    if ptype == 5:
        body = bytes([ptype, state]) + payload
        return body + bytes(64 - len(body))
    hdr = struct.pack('<BBBBIBBBBH', ptype, status, channel, ns, clock100, 0xd0, 0xb0, 0xc0, 12, 0)
    body = hdr + payload
    return body + bytes(64 - len(body))


def ble_crc(pdu, init=0x555555):
    """BLE CRC-24 (polynomial 0x00065b, bits of each octet fed LSB first) in
    the form Wireshark compares: the on-air octets are the state with the bits
    of each octet reversed."""
    state = init
    for cur in pdu:
        for i in range(8):
            fb = ((state >> 23) & 1) ^ ((cur >> i) & 1)
            state = (state << 1) & 0xffffff
            if fb:
                state ^= 0x00065b
    rev = lambda b: int('{:08b}'.format(b)[::-1], 2)
    return bytes(rev(b) for b in state.to_bytes(3, 'big'))


def le_adv(addr=b'\x01\x02\x03\x04\x05\x06', ad=b'\x02\x01\x06\x03\x09UB'):
    pdu = bytes([0x40, 6 + len(ad)]) + addr + ad
    return b'\xd6\xbe\x89\x8e' + pdu + ble_crc(pdu)


def l2cap_conn_param_update(ident, interval=(6, 12), latency=0, timeout=100):
    """L2CAP LE signaling channel (CID 5): Connection Parameter Update Request."""
    sig = bytes([0x12, ident]) + struct.pack('<HHHHH', 8, interval[0], interval[1], latency, timeout)
    return struct.pack('<HH', len(sig), 5) + sig


def le_data(aa=0x5065a1b7, payload=l2cap_conn_param_update(1), llid=2):
    return struct.pack('<I', aa) + bytes([llid, len(payload)]) + payload + b'\x11\x22\x33'


def spectrum_packet(base=2402, n=16):
    body = bytearray(rb(14))
    body[0] = 4
    for i in range(n):
        body += struct.pack('>Hb', base + i, -90 + i * 3)
    body += b'\0\0'
    return bytes(body[:64]).ljust(64, b'\0')


def build():
    c = Cap()
    c.enumerate()
    # Commands that carry their arguments in the setup packet (wValue, wIndex)
    for cmd, vals in (
            (4, (0, 1, 2)), (6, (0, 1)), (8, (1, 0)), (10, (0, 1)),
            (12, (2402, 2441, 2480)), (17, (0, 1)), (19, (1, 0)), (23, (0, 1, 2, 7)),
            (29, (0x0003, 0x0007, 0x0107)), (34, (0xffce, 0x0010)), (36, (0xffc4, 0x0005)),
            (42, (100,)), (48, (0, 1)), (59, (0, 1, 2, 9)), (60, (0, 1, 2, 9)),
            (1, (0, 5, 65535))):
        for v in vals:
            c.control(setup(cmd, v, rnd.getrandbits(16)))
    # Spectrum analyzer: lower and upper frequency
    c.control(setup(27, 2400, 2483))
    # Commands that carry their data after the setup packet
    c.control(setup(38, 0, 0, 6), out_data=b'\x00\x11\x22\x33\x44\x55')
    c.control(setup(39, 0, 0, 4), out_data=struct.pack('<I', 0x1234))
    c.control(setup(40, 0, 0, 4), out_data=struct.pack('<I', 0x00ab12cd))
    c.control(setup(44, 0, 0, 4), out_data=struct.pack('<I', 0x8e89bed6))
    c.control(setup(51, 0, 0, 10), out_data=b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f')
    c.control(setup(54, 0, 0, 6), out_data=b'\xaa\xbb\xcc\xdd\xee\xff')
    c.control(setup(56, 0, 0, 6), out_data=b'\x66\x55\x44\x33\x22\x11')
    # Commands without parameters (a response would be an error)
    for cmd in (0, 2, 13, 20, 21, 24, 25, 26, 30, 31, 45, 50, 52, 61, 255):
        c.control(setup(cmd, 0, 0, 0))
    regs = list(range(0x00, 0x2e)) + [0x0a, 0x09, 0x60, 0x68, 0x70]
    # Write Register: every CC2400 register. The dissector reads one 16 bit
    # argument more than the setup packet holds (see README), so a data stage
    # of two octets keeps the request from being truncated.
    regs = list(range(0x00, 0x2e)) + [0x0a, 0x09, 0x60, 0x68, 0x70]
    for r in regs:
        c.control(setup(58, r, int.from_bytes(rb(2), 'big'), 2), out_data=b'\x00\x00')
    # Commands answered with data
    def get(cmd, resp, wlen=None, wvalue=0, windex=0):
        c.control(setup(cmd, wvalue, windex, len(resp) if wlen is None else wlen, dir_in=True), resp)
    for cmd in (3, 5, 7, 9):
        get(cmd, bytes([1]))
        get(cmd, bytes([0]))
        get(cmd, bytes([5]))
    get(11, struct.pack('<H', 2441))
    get(14, b'\x00' + bytes(range(16)))
    get(14, b'\x01')
    get(15, b'\x00' + struct.pack('<I', 0x2500102b))
    get(15, b'\x02')
    for cmd in (16, 18):
        get(cmd, bytes([1]))
        get(cmd, bytes([0]))
    for v in (0, 1, 2, 9):
        get(22, bytes([v]))
    for v in (0, 3, 7):
        get(28, bytes([v]))
    get(32, bytes([1, 3, 10, 4, 10]))
    get(32, bytes([0, 0, 0, 0, 0]))
    get(33, b'\x00\x00\x0a' + b'2012-10-R1')
    get(33, b'\x00\x00\x00')
    for v in (0, 1, 2, 3, 4, 9):
        get(35, bytes([v]))
    get(37, bytes([0xc4]))
    get(37, bytes([5]))
    get(41, bytes([0x42]))
    get(43, struct.pack('<I', 0x8e89bed6))
    get(46, b'\x01\x02')
    get(47, bytes([1]))
    get(47, bytes([0]))
    ci = b'ubertooth 2012-10-R1 (gcc 4.8)'
    get(55, bytes([len(ci)]) + ci)
    # Read Register: every CC2400 register
    for r in regs:
        get(53, int.from_bytes(rb(2), 'big').to_bytes(2, 'big'), wvalue=r)
    # Poll (49), Jam Mode (59) and Ego (60) answered with a Rx packet or one octet
    for cmd in (49, 59, 60):
        get(cmd, b'\x00', wlen=64)
    get(49, rx_packet(0, payload=rb(50)), wlen=64)
    get(49, rx_packet(1, payload=le_adv()), wlen=64)
    get(49, rx_packet(1, payload=le_adv(ad=b'\x02\x01\x06\x0d\x09UbertoothOne\x03\x19\x80\x00')), wlen=64)
    get(49, rx_packet(1, payload=le_data()), wlen=64)
    get(49, rx_packet(1, payload=le_data(payload=l2cap_conn_param_update(2, (24, 40), 4, 300), llid=2)), wlen=64)
    get(49, rx_packet(1, payload=le_data(payload=b'\x02\x13', llid=3)), wlen=64)
    get(49, rx_packet(1, payload=le_data(payload=b'', llid=1)), wlen=64)
    get(49, rx_packet(2, payload=rb(50)), wlen=64)
    get(49, rx_packet(3, payload=rb(50)), wlen=64)
    get(49, rx_packet(4, payload=rb(50)), wlen=64)
    get(49, rx_packet(6, payload=rb(50)), wlen=64)
    get(59, rx_packet(6, payload=rb(50)), wlen=64)
    get(60, rx_packet(1, payload=le_adv()), wlen=64)
    for st, pl in ((0, struct.pack('<I', 0x8e89bed6)), (1, b'\x12\x34\x56'), (2, struct.pack('<H', 24)),
                   (3, b'\x07'), (9, b'')):
        get(49, rx_packet(5, state=st, payload=pl), wlen=64)
    # Rx Symbols (1): a bulk transfer of three Rx packets, then Stop (21)
    c.control(setup(1, 3, 0))
    c.bulk_in(rx_packet(0, payload=rb(50)) + rx_packet(0, status=0xfe, channel=78, payload=rb(50))
              + rx_packet(1, status=0x3f, payload=rb(50)))
    c.bulk_in(rx_packet(5, state=0, payload=struct.pack('<I', 0x12345678)))
    c.control(setup(21, 0, 0, 0))
    c.bulk_in(rx_packet(0, payload=rb(50)))
    # Spectrum analyzer (27): bulk transfers of spectrum packets
    c.control(setup(27, 2402, 2480))
    c.bulk_in(spectrum_packet(2402) + spectrum_packet(2418))
    c.bulk_in(spectrum_packet(2434))
    c.control(setup(21, 0, 0, 0))

    # ---- malformed / error ----
    m = Cap()
    m.enumerate()
    m.control(setup(0, 0, 0, 0))
    # Write Register requests (their setup packet is one argument short, so the
    # dissector throws after the register fields): every CC2400 register
    regs = list(range(0x00, 0x2e)) + [0x0a, 0x09, 0x60, 0x68, 0x70]
    for r in regs:
        m.control(setup(58, r, int.from_bytes(rb(2), 'big'), 0))
    # completions of OUT commands: an unexpected response (error), and Jam Mode /
    # Ego / Poll completions that throw
    for cmd in (4, 12, 38, 58, 1, 59, 60, 49, 27):
        m.control(setup(cmd, 1, 0, 0), complete=True)
    # responses to commands that have none (error) with and without data
    for cmd in (0, 12, 21 + 0, 38, 58, 1):
        m.control(setup(cmd, 0, 0, 0, dir_in=True), b'')
        m.control(setup(cmd, 0, 0, 4, dir_in=True), b'\x01\x02\x03\x04')
    # responses with trailing data
    for cmd, resp in ((3, b'\x01\x02\x03'), (11, b'\x01\x02\x03'), (14, b'\x01\x00'), (15, b'\x00' * 3),
                      (32, bytes(7)), (47, b'\x01\x02'), (53, bytes(4)), (35, b'\x01\x01\x01'),
                      (33, b'\x00\x00\x03abcdef'), (55, b'\x02abcdef'), (49, b'\x00\x01')):
        m.control(setup(cmd, 0, 0, len(resp), dir_in=True), resp)
    # requests with data they do not use (warning), and a short request
    m.control(setup(0, 0, 0, 4), out_data=b'\x01\x02\x03\x04')
    m.control(setup(38, 0, 0, 8), out_data=b'\x00\x11\x22\x33\x44\x55\x66\x77')
    m.control(setup(44, 0, 0, 5), out_data=b'\x00\x11\x22\x33\x44')
    m.control(setup(51, 0, 0, 12), out_data=bytes(12))
    # responses that cut off their fields (exceptions)
    for cmd, resp in ((11, b'\x01'), (14, b'\x00\x01\x02'), (15, b'\x00\x01'), (32, b'\x01\x02'),
                      (33, b'\x00'), (33, b'\x00\x00\x09ab'), (43, b'\x01\x02'), (46, b'\x01'),
                      (53, b'\x01'), (55, b'\x09ab'), (49, rx_packet(1, payload=le_adv())[:20]),
                      (49, rx_packet(0)[:30])):
        m.control(setup(cmd, 0, 0, 64, dir_in=True), resp)
    # LE packet whose BTLE length does not fit the 50 data octets
    big = rx_packet(1, payload=b'\xd6\xbe\x89\x8e\x00\x3f' + rb(44))
    m.control(setup(49, 0, 0, 64, dir_in=True), big)
    # a bulk Rx transfer that ends inside a packet, and a Spectrum one
    m.control(setup(1, 3, 0))
    m.bulk_in(rx_packet(0, payload=rb(50))[:40])
    m.bulk_in(rx_packet(5, state=3)[:3])
    m.control(setup(27, 2402, 2480))
    m.bulk_in(spectrum_packet(2402)[:50])
    # a third device that never sent a command: its bulk response is unknown
    d = Cap(dev=4)
    d.enumerate()
    d.bulk_in(rx_packet(0, payload=rb(50)))
    m.recs += d.recs
    return c, m


c, m = build()
out = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
c.write(os.path.join(out, 'ubertooth-coverage.pcap'))
m.write(os.path.join(out, 'ubertooth-coverage-malformed.pcap'))
print(len(c.recs), len(m.recs))
