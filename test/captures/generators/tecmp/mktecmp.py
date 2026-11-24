#!/usr/bin/env python3
# Generates test/captures/tecmp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the TECMP dissector (packet-tecmp.c,
Technically Enhanced Capture Module Protocol of Technica Engineering).

TECMP runs directly over Ethernet with ethertype 0x99FE. A 12 octet header
(device id, counter, version, message type, data type, reserved, flags)
is followed by the payload of the message type: control messages, device
status, bus status, configuration (CM status), log streams and replay data
(entries of a 16 octet header and data of the given data type), counter
events and time synchronisation events.

Usage: mktecmp.py <output directory>

Writes:
  tecmp-coverage.pcap            every message type, every data type of the
                                 log stream and the replay data, status
                                 messages of every device type
  tecmp-coverage-malformed.pcap  length mismatches, header CRC and cycle
                                 repetition warnings, cut messages, the
                                 nested TECMP in Ethernet recursion
                                 reproducer, ASAM CMP detection
  cfg-uat/                       device, interface and control message UAT
                                 files for runcov.sh
  cfg-uat-bad/, cfg-uat-bad2/    the same with rejected records
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


def pcapng(path, linktypes, frames, names=None):
    """frames: list of (interface index, bytes); names: optional if_name
    option of every interface."""
    def block(btype, body):
        pad = (-len(body)) % 4
        total = 12 + len(body) + pad
        return struct.pack('<II', btype, total) + body + b'\0' * pad + struct.pack('<I', total)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for k, lt in enumerate(linktypes):
        opts = b''
        if names and names[k]:
            nm = names[k].encode()
            opts = struct.pack('<HH', 2, len(nm)) + nm + b'\0' * ((-len(nm)) % 4)
            opts += struct.pack('<HH', 0, 0)
        out += block(1, struct.pack('<HHI', lt, 0, 65535) + opts)
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

ETHERTYPE = 0x99FE

CTRL, STATUS_DEV, STATUS_BUS, LOG, CFG, REPLAY, COUNTER, TIMESYNC = 0x00, 0x01, 0x02, 0x03, 0x04, 0x0A, 0x0B, 0x0C

T_CAN, T_CANFD, T_LIN, T_FR = 0x0002, 0x0003, 0x0004, 0x0008
T_GPIO, T_ILAS, T_RS232, T_ANALOG, T_ANALOG_ALT = 0x000A, 0x000E, 0x0010, 0x0020, 0x0028
T_ETH, T_ETH_RAW, T_ETH_10M, T_I2C = 0x0080, 0x0081, 0x0082, 0x0104


def hdr(dev, msgtype, dtype, counter=1, version=3, flags=0, res=0):
    return struct.pack('>HHBBHHH', dev, counter, version, msgtype, dtype, res, flags)


def entry(iface, payload, ts=1700000000000000000, dflags=0, length=None):
    if length is None:
        length = len(payload)
    return struct.pack('>IQHH', iface, ts, length, dflags) + payload


def frame(dev, msgtype, dtype, entries, **kw):
    if isinstance(entries, bytes):
        entries = [entries]
    return eth(hdr(dev, msgtype, dtype, **kw) + b''.join(entries), ETHERTYPE)


def inner_eth(payload=b'tecmp tunnel payload'):
    """An Ethernet/IPv4/UDP frame carried in Ethernet data. TECMP hands the
    data to the Ethernet dissector "eth_withfcs": a 4 octet FCS follows."""
    return udp(1234, 5678, payload) + b'\x00\x00\x00\x00\xfe'[:4]


# --- data of the data types ---

def can(cid, data, crc=b'\x12\x34'):
    return struct.pack('>IB', cid, len(data)) + data + crc


def lin(lid, data, chk=0xab, length=None):
    if length is None:
        length = len(data)
    return bytes([lid, length]) + data + bytes([chk])


def fr(cycle, fid, data, tail=b''):
    return struct.pack('>BHB', cycle, fid, len(data)) + data + tail


def analog(samples):
    return b''.join(struct.pack('>h', s) for s in samples)


def analog_alt(flags, unit, interval, offset, scalar, samples, dt=0):
    body = struct.pack('>HBBIff', flags, 0, unit, interval, offset, scalar)
    fmt = '>h' if dt == 0 else '>i'
    return body + b''.join(struct.pack(fmt, s) for s in samples)


def vendor_dev(sw=(1, 2, 3), hw=(2, 0x0a), fill=50, ovf=0, size=4, life=3000000000,
               volt=(12, 34), temps=b'\x2a', extra=b''):
    return (b'\0' + bytes(sw) + bytes(hw) + bytes([fill, ovf]) + struct.pack('>IQ', size, life)
            + bytes(volt) + temps + extra)


def status(dev, msgtype, vendor, dtype, vendor_data, rest=b'', serial=0x01020304, vdl=None,
           version=1, iface=0xff, ts=1700000010000000000, devid=None):
    if vdl is None:
        vdl = len(vendor_data) if msgtype != STATUS_BUS else 0
    if devid is None:
        devid = dev
    body = bytes([vendor, version, dtype, 0]) + struct.pack('>HHI', vdl, devid, serial)
    if msgtype == STATUS_BUS:
        body += rest
    else:
        body += vendor_data
    return eth(hdr(dev, msgtype, 0) + entry(iface, body, ts=ts, length=len(body)), ETHERTYPE)


def bus_entries(iface_base, count, vdata):
    """Entries of a bus status message: interface id, messages, errors and
    the vendor data of every entry (list or one string)."""
    out = b''
    for i in range(count):
        vd = vdata[i] if isinstance(vdata, list) else vdata
        out += struct.pack('>III', iface_base + i, 1000 * (i + 1), i) + vd
    return out


def main_frames():
    F = []
    T = 1700000000000000000
    # ---- log stream: CAN data
    F.append(frame(0x0041, LOG, T_CAN, entry(0x10, can(0x123, bytes(range(8))), T, 0x4000)))
    F.append(frame(0x0041, LOG, T_CAN, [
        entry(0x10, can(0x80000000 | 0x1abcdef, b'\x01\x02', crc=b''), T + 1000, 0x0004),
        entry(0x11, can(0x7ff, b'', crc=b'\xaa\xbb'), T + 2000, 0x0002),          # RTR
        entry(0x11, can(0x001, b'\xff' * 8), T + 3000, 0x0009)]))                 # error + ACK
    F.append(frame(0x0041, LOG, T_CAN, entry(0x12, can(0x321, b'\x55', crc=b''), T, 0x80f0)))
    # all CAN data flags and the sync bit of the timestamp (async, reserved)
    F.append(frame(0x0041, LOG, T_CAN, entry(0x13, can(0x100, b'\x00'), (T | (3 << 62)), 0xffff)))
    # ---- CAN FD data (crc17 for up to 16 octets of data, crc21 above)
    F.append(frame(0x0042, LOG, T_CANFD, entry(0x20, can(0x234, bytes(range(12)), crc=b'\x01\x02\x03'), T, 0x0030)))
    F.append(frame(0x0042, LOG, T_CANFD, entry(0x20, can(0x80000234, bytes(range(32)), crc=b'\x04\x05\x06'), T, 0x01f2)))
    F.append(frame(0x0042, LOG, T_CANFD, entry(0x20, can(0x235, bytes(range(8)), crc=b''), T, 0x4002)))
    # ---- LIN (the length counts the data, the checksum follows)
    F.append(frame(0x0031, LOG, T_LIN, entry(0x30, lin(0x2a | 0x40, b'\x01\x02\x03\x04'), T, 0x4000)))
    F.append(frame(0x0031, LOG, T_LIN, [
        entry(0x30, lin(0x3c, b'', chk=0), T, 0x2000),
        entry(0x31, lin(0x01, b'\xaa', chk=0x55), T, 0xe3f0)]))
    # ---- FlexRay: header CRC and frame CRC follow the data in log streams
    F.append(frame(0x0043, LOG, T_FR, entry(0x40, fr(5, 0x12, bytes(8), tail=b'\x01\x23\x04\x05\x06'), T, 0x0804)))
    F.append(frame(0x0043, LOG, T_FR, entry(0x41, fr(63, 0x7ff, bytes(4), tail=b'\x07\xff\xff\xff\xff'), T, 0x3e3f)))  # NF set: data
    F.append(frame(0x0043, LOG, T_FR, entry(0x41, fr(1, 1, b'', tail=b''), T, 0x0000)))
    # ---- GPIO
    for n in (1, 2, 3, 4):
        F.append(frame(0x0044, LOG, T_GPIO, entry(0x50, bytes([0xa5, 0x5a, 0xff, 0x01][:n]), T, 0xc000)))
    # ---- ILaS
    F.append(frame(0x007a, LOG, T_ILAS, entry(0x60, bytes([5]) + struct.pack('>H', 0x1234) + b'\x01\x02\x03'
                                              + bytes(range(7)) + b'\xca\xfe', T, 0x2003)))
    # ---- RS-232 ASCII text lines
    F.append(frame(0x0041, LOG, T_RS232, entry(0x70, b'Hello\r\nWorld\r\n', T, 0x4003)))
    # ---- analog samples: every factor and unit
    for k, flags in enumerate((0x0000, 0x0084 | 0x0001, 0x0108 | 0x2, 0x018c, 0x0010 | 0x0020, 0x0014, 0x001c)):
        F.append(frame(0x0050, LOG, T_ANALOG, entry(0x80 + k, analog([100, -100, 32767, -32768]), T, 0x8000 | flags)))
    F.append(frame(0x0050, LOG, T_ANALOG, entry(0x88, analog([1, 2, 3]) + b'\x7f', T, 0x0000)))   # odd octet
    # ---- analog (alternative format): INT16 and INT32, known and unknown units
    for k, (unit, dt) in enumerate(((0x10, 0), (0x04, 1), (0x0e, 0), (0x99, 1), (0x17, 0), (0x99, 0))):
        F.append(frame(0x0051, LOG, T_ANALOG_ALT,
                       entry(0x90 + k, analog_alt(dt | (0x80 if k == 2 else 0), unit, 1000, 0, 1,
                                                  [10, -10, 20], dt=dt), T, 0)))
    # ---- Ethernet
    F.append(frame(0x0061, LOG, T_ETH, entry(0xa0, inner_eth(), T, 0x4000)))
    # raw: preamble, SFD 0xD5 (original) and an Ethernet frame
    F.append(frame(0x0062, LOG, T_ETH_RAW, entry(0xa1, b'\x55' * 7 + b'\xd5' + inner_eth(b'raw'), T, 0x0000)))
    #   SMD (not the original SFD): shown as an Ethernet frame item but not decoded
    F.append(frame(0x0062, LOG, T_ETH_RAW, entry(0xa1, b'\x55' * 7 + b'\x07' + b'\xde\xad' * 10, T, 0x0000)))
    #   preamble only, preamble and SFD only, unknown SFD, no preamble
    F.append(frame(0x0062, LOG, T_ETH_RAW, [
        entry(0xa1, b'\x55' * 7, T, 0), entry(0xa1, b'\x55' * 7 + b'\xd5', T, 0),
        entry(0xa1, b'\x55' * 7 + b'\x00\x01\x02', T, 0), entry(0xa1, b'\x01\x02\x03', T, 0)]))
    # 10BASE-T1S: beacon timestamp and an Ethernet frame
    F.append(frame(0x0072, LOG, T_ETH_10M, entry(0xa2, struct.pack('>Q', T - 1000) + inner_eth(b'10m'), T, 0x6000)))
    F.append(frame(0x0072, LOG, T_ETH_10M, entry(0xa2, struct.pack('>Q', T + 5000) + inner_eth(b'10m'), T, 0x1000)))
    # ---- I2C: 7 bit write, read, repeated start in the middle, 10 bit write and read
    i2c = [
        bytes([0xa0, 1, 0x11, 1, 0x22, 1, 0x33, 2]),                       # 7 bit write 0x50, ACK + STOP at the end
        bytes([0xa1, 1, 0x44, 1]),                                       # 7 bit read
        bytes([0xa0, 3]),                                                # 7 bit address, ACK + repeated start
        bytes([0xa0, 1, 0x55, 5]),                                       # NACK + repeated start after data
        bytes([0xf2, 1, 0x34, 1, 0x66, 1, 0x77, 1]),                     # 10 bit write 0x234
        bytes([0xf2, 1, 0x34, 3, 0xf3, 1, 0x88, 1, 0x99, 4]),             # 10 bit read (repeated start, same address)
        bytes([0xf2, 3]),                                                # 10 bit: repeated start after the first byte
        bytes([0xf2, 1, 0x34, 5]),                                       # 10 bit: NACK + repeated start after the address
        bytes([0xf2, 1, 0x34, 3, 0xa0, 1]),                              # 10 bit: repeated start with another address
        bytes([0xf2, 1, 0x34, 3, 0xf3, 3]),                              # 10 bit read: repeated start after the read address
    ]
    for k, p in enumerate(i2c):
        F.append(frame(0x0063, LOG, T_I2C, entry(0xb0 + k, p, T, 0)))
    # ---- data types without a decoder
    for dt in (0x0001, 0x0007, 0x0011, 0x0012, 0x0021, 0x00a0, 0x0101, 0x0102, 0x0103, 0x0106,
               0x0200, 0x0201, 0x0202, 0x0400, 0xa000, 0xb000, 0x0000, 0x1234):
        F.append(frame(0x0041, LOG, dt, entry(0xc0, b'\x01\x02\x03\x04\x05', T, 0xe000)))
    # data length 0 and a zero entry as padding after an entry
    F.append(frame(0x0041, LOG, T_CAN, [entry(0x10, b'', T), entry(0, b'', 0)]))
    F.append(frame(0x0041, LOG, T_CAN, [entry(0x10, can(0x101, b'\x01\x02'), T), bytes(16)]))
    F.append(frame(0x0041, LOG, T_CAN, [entry(0x10, can(0x102, b'\x03\x04'), T), bytes(5)]))   # short trailer
    # a user defined device ID (0xff..) is TECMP, not ASAM CMP
    F.append(frame(0xff10, LOG, T_CAN, entry(0x10, can(0x103, b'\x05'), T)))
    # ---- replay data (TX flags)
    F.append(frame(0x0041, REPLAY, T_CAN, entry(0x10, can(0x123, bytes(range(8))), T, 0x00e2)))
    F.append(frame(0x0042, REPLAY, T_CANFD, entry(0x20, can(0x234, bytes(range(16)), crc=b''), T, 0x01f0)))
    F.append(frame(0x0031, REPLAY, T_LIN, entry(0x30, lin(0x2a, b'\x01\x02'), T, 0x00c3)))
    F.append(frame(0x0043, REPLAY, T_FR, entry(0x40, fr(5, 0x12, bytes(8), tail=bytes([4, 0x01, 0x23])), T, 0x0800)))
    for rep in (1, 2, 4, 8, 16, 32, 64):
        F.append(frame(0x0043, REPLAY, T_FR, entry(0x41, fr(rep, 0x10, bytes(4), tail=bytes([rep, 0x00, 0x10])), T, 0x0c00)))
    F.append(frame(0x0041, REPLAY, T_RS232, entry(0x70, b'AT\r\n', T, 0x4003)))
    F.append(frame(0x0050, REPLAY, T_ANALOG, entry(0x80, analog([5, 6]), T, 0x8014)))
    F.append(frame(0x0061, REPLAY, T_ETH, entry(0xa0, inner_eth(b'replay'), T, 0)))
    F.append(frame(0x0062, REPLAY, T_ETH_RAW, entry(0xa1, b'\x55' * 7 + b'\xd5' + inner_eth(b'replay raw'), T, 0)))
    # ---- control messages
    F.append(frame(0x0041, CTRL, 0, entry(0, struct.pack('>HH', 0x0041, 0x0002) + b'', T, 0)))          # logger ready, no data
    F.append(frame(0x0041, CTRL, 0, entry(0, struct.pack('>HH', 0x0041, 0x0002) + b'\x01\x02', T, 0)))  # logger ready, unparsed bytes
    F.append(frame(0x0041, CTRL, 0, entry(0, struct.pack('>HH', 0x0041, 0x00e0) + bytes([50, 1, 4, 10, 20, 30, 40]), T, 0)))   # CAN replay fill level
    F.append(frame(0x0041, CTRL, 0, entry(0, struct.pack('>HH', 0x0041, 0x00e0) + bytes([0, 0, 0]), T, 0)))
    for st in (0, 1, 2, 3, 4, 5, 6, 7, 99):
        F.append(frame(0x0043, CTRL, 0, entry(0, struct.pack('>HHIB', 0x0043, 0x00e1, 0x40, st), T, 0)))  # FlexRay POC state
    F.append(frame(0x0072, CTRL, 0, entry(0, struct.pack('>HHIBBH', 0x0072, 0x00e2, 0x41, 0x03, 0, 0x001f), T, 0)))
    F.append(frame(0x0072, CTRL, 0, entry(0, struct.pack('>HHIBBH', 0x0072, 0x00e2, 0x41, 0x00, 0, 0x0000) + b'\xaa', T, 0)))
    F.append(frame(0x0072, CTRL, 0, entry(0, struct.pack('>HH', 0x0072, 0xbeef) + b'\x01\x02\x03', T, 0)))  # unknown ID
    # ---- status device: Technica vendor data of the device types
    #      (software and hardware version, buffer, lifecycle, voltage, temperature)
    D = 0x0c
    F.append(status(0x0030, STATUS_DEV, D, 0x02, vendor_dev()))
    F.append(status(0x0040, STATUS_DEV, D, 0x04, vendor_dev(temps=b'\x7f\x80')))        # chassis max, silicon not available
    F.append(status(0x0060, STATUS_DEV, D, 0x06, vendor_dev(temps=b'\x80\x7f', life=5, ovf=1)))  # chassis NA, silicon max
    F.append(status(0x0061, STATUS_DEV, D, 0x07, vendor_dev(temps=b'\xf6\xec', fill=100)))        # negative temperatures
    F.append(status(0x0080, STATUS_DEV, D, 0x08, vendor_dev(temps=b'')))              # no temperature
    F.append(status(0x00c0, STATUS_DEV, D, 0x40, vendor_dev(temps=b'\x20\x30', extra=
                                                           struct.pack('>HHIIII', 77, 0x000f, 1, 2, 3, 4))))
    F.append(status(0x00c1, STATUS_DEV, D, 0x48, vendor_dev(temps=b'\x20\x30', extra=
                                                           struct.pack('>HHIIII', 78, 0x0000, 5, 6, 7, 8))))
    F.append(status(0x0090, STATUS_DEV, 0x01, 0x0a, b'\x01\x02\x03'))                 # another vendor
    F.append(status(0x0090, STATUS_DEV, D, 0x0a, b''))                                # no vendor data
    # ---- status bus (entries counted from 1; the vendor data depends on the device type and entry)
    F.append(status(0x0030, STATUS_BUS, D, 0x02, b'', rest=bus_entries(0x100, 3, b''), vdl=0))     # LIN Combo names
    F.append(status(0x0040, STATUS_BUS, D, 0x04, b'', rest=bus_entries(0x200, 2, b'\x01\x04\x00\x00'), vdl=4))
    F.append(status(0x0060, STATUS_BUS, D, 0x06, b'', rest=bus_entries(0x300, 2, b'\x00\x05\x00\x10'), vdl=4))
    F.append(status(0x0061, STATUS_BUS, D, 0x07, b'', rest=bus_entries(0x300, 1, b'\x01\x03\xff\xff'), vdl=4))
    F.append(status(0x0080, STATUS_BUS, D, 0x08, b'', rest=bus_entries(0x400, 2, b'\x01\x02'), vdl=2))
    F.append(status(0x0090, STATUS_BUS, D, 0x0a, b'', rest=bus_entries(0x500, 2, b'\x01'), vdl=1))
    F.append(status(0x0091, STATUS_BUS, D, 0x42, b'', rest=bus_entries(0x600, 2, b'\x01\x02\x00\x07'), vdl=4))  # not named
    t1s = struct.pack('>BBIBBHHHHHH', 3, 0, 1234, 4, 0, 0, 11, 12, 13, 14, 15)
    F.append(status(0x0072, STATUS_BUS, D, 0x0c, b'', rest=bus_entries(0x700, 2, t1s), vdl=len(t1s)))
    F.append(status(0x007a, STATUS_BUS, D, 0x0e, b'', rest=bus_entries(0x800, 4, b''), vdl=0))    # ILaS: no parameters
    F.append(status(0x007a, STATUS_BUS, D, 0x0e, b'', rest=bus_entries(0x810, 6, t1s), vdl=len(t1s)))  # ILaS entries 1-4 and 5, 6
    serdes_gmsl = bus_entries(0x900, 14, b'\x05\x00')
    F.append(status(0x00c0, STATUS_BUS, D, 0x40, b'', rest=serdes_gmsl, vdl=2))               # GMSL: I2C, GPIO, streams
    serdes_asaml = bus_entries(0xa00, 9, b'\x07\x00')
    F.append(status(0x00c1, STATUS_BUS, D, 0x48, b'', rest=serdes_asaml, vdl=2))              # ASAML
    F.append(status(0x00c1, STATUS_BUS, D, 0x48, b'', rest=bus_entries(0xa10, 10, b'\x03\x00'), vdl=2))   # more than the known interfaces
    F.append(status(0x0030, STATUS_BUS, 0x01, 0x02, b'', rest=bus_entries(0xb00, 1, b'\x01\x02'), vdl=2))  # other vendor
    F.append(status(0x0030, STATUS_BUS, D, 0x02, b'', rest=b'\x00' * 5, vdl=0))                 # entry cut (less than 12 octets)
    # ---- configuration of the CM (segments of the configuration file)
    cfgv = struct.pack('>BBHIHHH', 1, 0, 9, 1000, 4, 2, 6) + b'config'
    F.append(status(0x0030, CFG, D, 0x02, cfgv))
    cfgv2 = struct.pack('>BBHIHHH', 1, 0, 9, 1000, 4, 3, 100) + b'short segment'
    F.append(status(0x0030, CFG, D, 0x02, cfgv2))                                              # segment shorter than its length
    F.append(status(0x0030, CFG, 0x01, 0x02, b'\x01\x02\x03'))                                  # other vendor
    F.append(status(0x0030, CFG, D, 0x02, b''))                                                 # none
    # ---- counter events and time synchronisation events
    F.append(frame(0x0041, COUNTER, 0, entry(0, struct.pack('>HHHH', 0x0041, 0x0010, 100, 105), T, 0)))
    F.append(frame(0x0041, TIMESYNC, 0, entry(0, struct.pack('>HHHBB', 0x0041, 0x0010, 0, 1, 7), T, 0)))
    F.append(frame(0x0041, TIMESYNC, 0, entry(0, struct.pack('>HHHBB', 0x0041, 0x0011, 0, 0, 0xff), T, 0)))
    # ---- flags and versions of the header, unknown message types
    F.append(frame(0x0041, LOG, T_CAN, entry(0x10, can(0x400, b'\x01'), T), flags=0x800f, counter=0xffff, version=4))
    F.append(frame(0x0041, 0x77, 0, b'\x01\x02\x03\x04'))                                       # unknown message type
    return F


def malformed_frames():
    F = []
    T = 1700000000000000000
    # CAN data whose length byte is longer than the data: length mismatch
    F.append(frame(0x0041, LOG, T_CAN, entry(0x10, struct.pack('>IB', 0x123, 8) + b'\x01\x02', T)))
    # LIN: length longer than the data
    F.append(frame(0x0031, LOG, T_LIN, entry(0x30, bytes([0x10, 5]) + b'\x01\x02', T)))
    # FlexRay: length longer than the data, header CRC above 0x7ff, replay
    # cycle repetition not a power of two
    F.append(frame(0x0043, LOG, T_FR, entry(0x40, struct.pack('>BHB', 1, 2, 9) + b'\x01', T)))
    F.append(frame(0x0043, LOG, T_FR, entry(0x40, fr(5, 0x12, bytes(8), tail=b'\xff\xff\x04\x05\x06'), T, 0)))
    F.append(frame(0x0043, REPLAY, T_FR, entry(0x40, fr(3, 0x12, bytes(8), tail=bytes([3, 0xff, 0xff])), T, 0)))
    F.append(frame(0x0043, REPLAY, T_FR, entry(0x40, fr(3, 0x12, bytes(8), tail=bytes([0, 0x01, 0x02])), T, 0)))
    # entry whose length is past the end of the frame
    F.append(frame(0x0041, LOG, T_CAN, entry(0x10, can(0x123, b'\x01\x02'), T, length=60)))
    # LIN with a length but no checksum
    F.append(frame(0x0031, LOG, T_LIN, entry(0x30, bytes([0x10, 2]) + b'\x01\x02', T)))
    # ILaS cut, GPIO with length 0, I2C cut in an address
    F.append(frame(0x0044, LOG, T_ILAS, entry(0x60, b'\x01\x02\x03', T)))
    F.append(frame(0x0044, LOG, T_GPIO, entry(0x50, b'', T)))
    F.append(frame(0x0063, LOG, T_I2C, entry(0xb0, bytes([0xf2, 1]), T)))
    F.append(frame(0x0063, LOG, T_I2C, entry(0xb0, bytes([0xa0]), T)))
    # I2C with a padding octet at the end: the padding is read as the
    # address of another operation that is cut
    F.append(frame(0x0063, LOG, T_I2C, entry(0xb0, bytes([0xa0, 1, 0x12, 1, 0x34]), T)))
    # analog alternative format cut in the header
    F.append(frame(0x0051, LOG, T_ANALOG_ALT, entry(0x90, b'\x00\x00\x00', T)))
    # 10BASE-T1S Ethernet without beacon timestamp, Ethernet entry cut
    F.append(frame(0x0072, LOG, T_ETH_10M, entry(0xa2, b'\x01\x02\x03', T)))
    F.append(frame(0x0061, LOG, T_ETH, entry(0xa0, inner_eth()[:20], T)))
    # reproducer of the pkt_len fix: an Ethernet entry too short for an
    # Ethernet header (the frame length must stay 47)
    F.append(eth(hdr(0x0030, LOG, T_ETH, counter=1) + entry(1, b'\x02\x00\x00\x00\x00'), ETHERTYPE))
    # control messages cut, status messages cut
    F.append(frame(0x0041, CTRL, 0, entry(0, struct.pack('>HH', 0x0041, 0x00e1) + b'\x01\x02', T, 0)))
    F.append(frame(0x0072, CTRL, 0, entry(0, struct.pack('>HH', 0x0072, 0x00e2) + b'\x01\x02\x03\x04\x05', T, 0)))
    F.append(eth(hdr(0x0030, STATUS_DEV, 0) + b'\x00' * 20, ETHERTYPE))
    F.append(eth(hdr(0x0030, STATUS_BUS, 0) + b'\x00' * 40, ETHERTYPE))
    F.append(eth(hdr(0x0030, CFG, 0) + b'\x00' * 30, ETHERTYPE))
    F.append(eth(hdr(0x0041, COUNTER, 0) + b'\x00' * 20, ETHERTYPE))
    F.append(eth(hdr(0x0041, TIMESYNC, 0) + b'\x00' * 20, ETHERTYPE))
    # header cut: shorter than the 12 octets
    F.append(eth(hdr(0x0041, LOG, T_CAN)[:9], ETHERTYPE))
    # device status: vendor data cut
    F.append(status(0x0030, STATUS_DEV, 0x0c, 0x02, vendor_dev()[:12]))
    # ASAM CMP (the first octet is not 0 and not 0xff): the ASAM CMP
    # dissector gets the frame
    F.append(eth(bytes([1, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x01, 0x00, 0, 0, 0, 0, 0, 0]) + bytes(20), ETHERTYPE))
    # recursion: TECMP carrying Ethernet carrying TECMP ... past the limit
    # of the Ethertype dissector (about 160 levels)
    cur = eth(b'\x00' * 8, ETHERTYPE)
    for lvl in range(175):
        cur = eth(hdr(0x0030, LOG, T_ETH) + entry(1, cur), ETHERTYPE)
    F.append(cur)
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcap(os.path.join(out, 'tecmp-coverage.pcap'), main_frames())
    pcap(os.path.join(out, 'tecmp-coverage-malformed.pcap'), malformed_frames())
    d = os.path.join(out, 'cfg-uat')
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'TECMP_device_identifiers'), 'w') as f:
        f.write('"41","Logger A"\n"30","LIN CM"\n"c1","SerDes ASAML"\n')
    with open(os.path.join(d, 'TECMP_interface_identifiers'), 'w') as f:
        f.write('"10","CAN 1","1"\n"11","CAN 2","2"\n"20","CAN FD 1","3"\n"30","LIN 1","4"\n'
                '"31","LIN 2","5"\n"40","FlexRay A","6"\n"41","FlexRay B","7"\n'
                '"100","Bus entry 1","0"\n"200","Bus entry 2","0"\n')
    with open(os.path.join(d, 'TECMP_control_message_identifiers'), 'w') as f:
        f.write('"beef","Vendor Control Message"\n"2","Renamed Logger Ready"\n')
    # UAT files with records that are rejected: an ID that does not fit 16
    # bits or 32 bits, an empty name, a bus ID above 16 bits
    d = os.path.join(out, 'cfg-uat-bad')
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'TECMP_device_identifiers'), 'w') as f:
        f.write('"10000","Too large"\n')
    with open(os.path.join(d, 'TECMP_interface_identifiers'), 'w') as f:
        f.write('"10","","1"\n')
    with open(os.path.join(d, 'TECMP_control_message_identifiers'), 'w') as f:
        f.write('"10000","Too large"\n')
    # the next record of each file is only read when the first is valid
    d = os.path.join(out, 'cfg-uat-bad2')
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'TECMP_device_identifiers'), 'w') as f:
        f.write('"41",""\n')
    with open(os.path.join(d, 'TECMP_interface_identifiers'), 'w') as f:
        f.write('"11","Bus too large","10000"\n')
    with open(os.path.join(d, 'TECMP_control_message_identifiers'), 'w') as f:
        f.write('"2",""\n')


if __name__ == '__main__':
    main()
