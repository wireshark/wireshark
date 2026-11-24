#!/usr/bin/env python3
# Generates test/captures/asam_cmp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic ASAM CMP coverage captures (packet-asam-cmp.c).
# Usage: mkasam_cmp.py <outdir>
# Writes asam_cmp-coverage.pcap (main, Ethernet linktype) and
# asam_cmp-coverage-malformed.pcap. Every packet is built with struct;
# nothing comes from a real network.
#
# ASAM CMP has no default EtherType or port; dissect with
#   -d ethertype==0x99fe,asam-cmp -d udp.port==50000,asam-cmp
import os
import struct
import sys

ETH_DST = bytes.fromhex("020000000001")
ETH_SRC = bytes.fromhex("020000000002")
CMP_ETYPE = 0x99fe
CMP_UDP_PORT = 50000

# ---------------------------------------------------------------- CMP ----

seqs = {}


def cmp_hdr(msg_type, dev=0x0102, stream=1, seq=None):
    if seq is None:
        seq = seqs.get((dev, stream), 0)
        seqs[(dev, stream)] = (seq + 1) & 0xffff
    return struct.pack(">BBHBBH", 1, 0, dev, msg_type, stream, seq)


TS = [1_700_000_000_000_000_000]


def ts():
    TS[0] += 1_234_567
    return TS[0]


def data_msg(ptype, payload, iface=0x10, flags=0, length=None):
    if length is None:
        length = len(payload)
    return struct.pack(">QIBBH", ts(), iface, flags, ptype, length) + payload


def tx_msg(ptype, payload, iface=0x10, flags=0, opts=0, deadline=0, length=None):
    if length is None:
        length = len(payload)
    return struct.pack(">QIIIBBH", ts(), deadline, iface, opts, flags, ptype, length) + payload


def ctrl_msg(ptype, payload, flags=0, length=None):
    if length is None:
        length = len(payload)
    return struct.pack(">QIBBH", ts(), 0, flags, ptype, length) + payload


def status_msg(ptype, payload, flags=0, vendor=0, length=None):
    if length is None:
        length = len(payload)
    return struct.pack(">QHHBBH", ts(), 0, vendor, flags, ptype, length) + payload


def vendor_msg(ptype, payload, flags=0, vendor=0x1234, length=None):
    if length is None:
        length = len(payload)
    return struct.pack(">QHHBBH", ts(), 0, vendor, flags, ptype, length) + payload


# Data message payloads
def can(flags=0, id_=0, crc=0, err_pos=0, dlc=None, data=b""):
    if dlc is None:
        dlc = len(data)
    return struct.pack(">HHIIHBB", flags, 0, id_, crc, err_pos, dlc, len(data)) + data


def lin(flags=0, pid=0, checksum=0, data=b""):
    return struct.pack(">HHBBBB", flags, 0, pid, 0, checksum, len(data)) + data


def flexray(flags=0, hcrc=0x123, fid=5, cycle=1, fcrc=b"\x01\x02\x03", data=b"", dlen=None):
    if dlen is None:
        dlen = len(data)
    return struct.pack(">HHHHB3sBB", flags, 0, hcrc, fid, cycle, fcrc, 0, dlen) + data


def digital(pins, trigger=None, samples=None, interval=1000, flags_extra=0):
    flags = flags_extra
    body = b""
    if trigger is not None:
        flags |= 1
        body += struct.pack(">BBH", trigger[0], trigger[1], 0)
    if samples is not None:
        flags |= 2
        body += struct.pack(">IB", interval, len(samples)) + b"".join(samples)
    return struct.pack(">HBB", flags, 0, pins) + body


def uart(cl, chars):
    return struct.pack(">HHH", cl, 0, len(chars)) + b"".join(struct.pack(">H", c) for c in chars)


def analog(dt, unit, offset, scalar, samples=b"", interval=10):
    return struct.pack(">HBBIff", dt, 0, unit, interval, offset, scalar) + samples


def ethm(frame, flags=0, length=None):
    if length is None:
        length = len(frame)
    return struct.pack(">HHH", flags, 0, length) + frame


def spi(cipo, copi):
    return struct.pack(">HHH", 0, 0, len(cipo)) + cipo + struct.pack(">H", len(copi)) + copi


def i2c(flags, addr, entries):
    return struct.pack(">HHHH", flags, 0, addr, len(entries)) + b"".join(struct.pack(">H", e) for e in entries)


def gige(data):
    return struct.pack(">HHH", 0, 0, len(data)) + data


def mipi(dt, flags=0, data=None, short=0x1234, vci=0x05, ecc=0x2a, cs=0xbeef):
    hdr = struct.pack(">HHHHBBBBH", flags, 0, 7, 9, dt, vci, 0, ecc, cs)
    if (dt & 0x3f) <= 0x0f:
        return hdr + struct.pack(">H", short)
    return hdr + struct.pack(">H", len(data)) + data


def raw_eth(data, flags=0):
    return struct.pack(">HHH", flags, 0, len(data)) + data


def t1s(symbols, flags=0):
    return struct.pack(">HH", flags, len(symbols)) + symbols


def a2b(data, flags=0x0001, up=0x1234, down=0x5678, general=0x0123456789abcdef):
    return struct.pack(">HHHHQH", flags, 0, up, down, general, len(data)) + data


def link_state(flags, status):
    return struct.pack(">HBB", flags, status, 0)


def vendor_data(vid, ptype, data):
    return struct.pack(">HH", vid, ptype) + data


# ----------------------------------------------------- inner frames ----

def ip_udp(src, dst, sport, dport, payload):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes(src), bytes(dst))
    s = sum(struct.unpack(">10H", ip))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack(">H", ~s & 0xffff) + ip[12:]
    return ip + udp


def eth(etype, payload, dst=ETH_DST, src=ETH_SRC):
    return dst + src + struct.pack(">H", etype) + payload


INNER_ETH = eth(0x0800, ip_udp((192, 0, 2, 1), (192, 0, 2, 2), 1234, 5678, b"inner-udp-payload"))

# ------------------------------------------------------------ pcap -----


def write_pcap(path, frames, linktype=1):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        t = 1_700_000_000
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", t + i // 100, (i % 100) * 10000, len(fr), len(fr)))
            f.write(fr)


def pad60(fr):
    return fr + b"\0" * max(0, 60 - len(fr))


# ------------------------------------------------------------ main -----

main = []      # (description, frame)
malformed = []


def add(desc, cmp, pad=True, lst=None):
    fr = eth(CMP_ETYPE, cmp)
    if pad:
        fr = pad60(fr)
    (main if lst is None else lst).append((desc, fr))


def add_udp(desc, cmp, lst=None):
    fr = eth(0x0800, ip_udp((10, 0, 0, 1), (10, 0, 0, 2), 50001, CMP_UDP_PORT, cmp))
    (main if lst is None else lst).append((desc, fr))


D = 1   # capture data message
C = 2   # control
S = 3   # status
T = 4   # transmit data
V = 0xff

# --- CAN ---------------------------------------------------------------
add("CAN 11 bit id, CRC supported, 8 data bytes",
    cmp_hdr(D) + data_msg(1, can(id_=0x123 << 18, crc=0x80001234, data=b"\x11\x22\x33\x44\x55\x66\x77\x88")))
add("CAN 29 bit id with RTR and error flags (error frame)",
    cmp_hdr(D) + data_msg(1, can(flags=0x03ff | 0xc000, id_=0x80000000 | 0x40000000 | 0x1abcdef, crc=0x80000001, err_pos=17, data=b"\x01\x02")))
add("CAN 11 bit id 0x7ff with ERR id bit, CRC supported",
    cmp_hdr(D) + data_msg(1, can(id_=0x20000000 | (0x7ff << 18), crc=0x80000042, data=b"\xaa")))
add("CAN with no data (DLC 0)",
    cmp_hdr(D) + data_msg(1, can(id_=0x10 << 18, crc=0x80000000)))
add("CAN transmit, transmit flags",
    cmp_hdr(T) + tx_msg(1, can(flags=0xffff, id_=0x456 << 18, crc=0x80000000, data=b"\x99" * 4), deadline=5000, flags=0x01))
add("CAN on interface 0x20 (no name, unknown bus id)",
    cmp_hdr(D) + data_msg(1, can(id_=0x321 << 18, data=b"\x01\x02\x03"), iface=0x20))

# --- CAN FD ------------------------------------------------------------
add("CAN FD 11 bit, DLC 8 (17 bit CRC), BRS ESI",
    cmp_hdr(D) + data_msg(2, can(flags=0x3000, id_=0x234 << 18, crc=0xc0e1ffff, dlc=8, data=bytes(range(8)))))
add("CAN FD 29 bit, DLC 15 (21 bit CRC), 64 data bytes, error flags",
    cmp_hdr(D) + data_msg(2, can(flags=0x0001, id_=0x80000000 | 0x40000000 | 0x1234567, crc=0xc1ffffff, dlc=15, data=bytes(range(64)))))
add("CAN FD with no data",
    cmp_hdr(D) + data_msg(2, can(id_=0x1 << 18, dlc=0)))
add("CAN FD transmit",
    cmp_hdr(T) + tx_msg(2, can(flags=0xffff, id_=0x7ff << 18, dlc=12, data=b"\x55" * 24)))

# --- LIN ---------------------------------------------------------------
add("LIN frame id 0x10, 4 data bytes, all error flags",
    cmp_hdr(D) + data_msg(3, lin(flags=0x01ff, pid=0x50, checksum=0x77, data=b"\x01\x02\x03\x04")))
add("LIN go-to-sleep (id 0x3c, first byte 0)",
    cmp_hdr(D) + data_msg(3, lin(pid=0x3c, data=b"\x00\xff\xff\xff\xff\xff\xff\xff")))
add("LIN header only (no data)",
    cmp_hdr(D) + data_msg(3, lin(pid=0x11)))
add("LIN transmit with wake up duration",
    cmp_hdr(T) + tx_msg(3, lin(flags=0x03ff, pid=0x22, data=b"\x01\x02"), opts=0x00640000))

# --- FlexRay -----------------------------------------------------------
add("FlexRay frame, payload, channel B, sync/startup",
    cmp_hdr(D) + data_msg(4, flexray(flags=0x0018 | 0x0200 | 0x0100, data=b"\x10\x20\x30\x40\x50\x60")))
add("FlexRay null frame (NF), payload length not dissected",
    cmp_hdr(D) + data_msg(4, flexray(flags=0x0004, data=b"\0\0\0\0")))
add("FlexRay transmit, send cyclically",
    cmp_hdr(T) + tx_msg(4, flexray(flags=0x07ff, data=b"\xab\xcd"), opts=0x02040000))
add("FlexRay with no data",
    cmp_hdr(D) + data_msg(4, flexray()))

# --- Digital -----------------------------------------------------------
add("Digital, trigger (rising) and 3 samples, 8 pins",
    cmp_hdr(D) + data_msg(5, digital(8, trigger=(1, 3), samples=[b"\xa5", b"\x5a", b"\xff"])))
add("Digital, samples only, 16 pins",
    cmp_hdr(D) + data_msg(5, digital(16, samples=[b"\x12\x34", b"\x56\x78"])))
add("Digital, 24 pins, falling trigger",
    cmp_hdr(D) + data_msg(5, digital(24, trigger=(0, 1), samples=[b"\x01\x02\x03"])))
add("Digital, 32 pins",
    cmp_hdr(D) + data_msg(5, digital(32, samples=[b"\xde\xad\xbe\xef", b"\x01\x02\x03\x04"])))
add("Digital, 40 pins (pins above 32 skipped)",
    cmp_hdr(D) + data_msg(5, digital(40, samples=[b"\x99\x11\x22\x33\x44"])))
add("Digital, 0 pins, 5 samples of 0 bytes; trigger only frame",
    cmp_hdr(D) + data_msg(5, digital(0, samples=[b""] * 5)) + data_msg(5, digital(4, trigger=(1, 0))))
add("Digital, no trigger, no samples, reserved flags",
    cmp_hdr(D) + data_msg(5, digital(8, flags_extra=0xfffc)))

# --- UART --------------------------------------------------------------
add("UART CL8, printable, control, 0x00 and errors",
    cmp_hdr(D) + data_msg(6, uart(3, [0x41, 0x42, 0x0d, 0x0a, 0x00, 0xe000 | 0x7a, 0x7f])))
add("UART CL7",
    cmp_hdr(D) + data_msg(6, uart(2, [0x48, 0x69])))
add("UART CL5, CL6, CL9 (not shown as text)",
    cmp_hdr(D) + data_msg(6, uart(0, [0x1f])) + data_msg(6, uart(1, [0x3f])) + data_msg(6, uart(4, [0x1ff])))
add("UART no characters",
    cmp_hdr(D) + data_msg(6, uart(3, [])))

# --- Analog ------------------------------------------------------------
add("Analog INT16, unit A, 3 samples",
    cmp_hdr(D) + data_msg(7, analog(0, 0x04, 0.5, 0.25, struct.pack(">hhh", 100, -100, 32767))))
add("Analog INT32, unit unknown, 2 samples and a trailing odd byte",
    cmp_hdr(D) + data_msg(7, analog(1, 0xee, -1.0, 2.0, struct.pack(">ii", 7, -8) + b"\x01")))
add("Analog INT16 exactly one sample (last sample shown), unknown unit; INT32 in kg",
    cmp_hdr(D) + data_msg(7, analog(0, 0xee, 0.0, 1.0, struct.pack(">h", 42)))
    + data_msg(7, analog(1, 0x03, 0.0, 0.5, struct.pack(">i", 1000))))
add("Analog reserved data types 2 and 3",
    cmp_hdr(D) + data_msg(7, analog(2, 0x02, 0.0, 1.0, b"\0" * 4)) + data_msg(7, analog(3, 0x03, 0.0, 1.0, b"\0" * 4)))

# --- Ethernet ----------------------------------------------------------
add("Ethernet capture: IPv4/UDP frame, error flags",
    cmp_hdr(D) + data_msg(8, ethm(INNER_ETH, flags=0x01ff), flags=0x10))
add("Ethernet transmit, FCS sending",
    cmp_hdr(T) + tx_msg(8, ethm(INNER_ETH, flags=0x0002)))
add("Ethernet with zero length",
    cmp_hdr(D) + data_msg(8, ethm(b"")))
nested = eth(CMP_ETYPE, cmp_hdr(D, dev=0x0a0a) + data_msg(1, can(id_=0x55 << 18, data=b"\x01")))
add("Ethernet carrying ASAM CMP again (one level)",
    cmp_hdr(D) + data_msg(8, ethm(nested)))

# --- SPI, I2C, GigE ----------------------------------------------------
add("SPI CIPO and COPI",
    cmp_hdr(D) + data_msg(9, spi(b"abc", b"de")))
add("SPI empty CIPO and COPI",
    cmp_hdr(D) + data_msg(9, spi(b"", b"")))
add("I2C read, 10 bit address, start/stop, 3 entries",
    cmp_hdr(D) + data_msg(10, i2c(0x003f, 0x0350, [0x0101, 0x0002, 0x01ff])))
add("I2C no entries",
    cmp_hdr(D) + data_msg(10, i2c(0, 0x50, [])))
add("GigE Vision payload",
    cmp_hdr(D) + data_msg(11, gige(b"gige-vision-data")))
add("GigE Vision empty",
    cmp_hdr(D) + data_msg(11, gige(b"")))

# --- MIPI CSI-2 --------------------------------------------------------
add("MIPI CSI-2 short packet (frame start), all flags",
    cmp_hdr(D) + data_msg(12, mipi(0x00, flags=0x007f)))
add("MIPI CSI-2 long packet (RAW8)",
    cmp_hdr(D) + data_msg(12, mipi(0x2a, data=b"pixeldata!")))
add("MIPI CSI-2 transmit, short and long",
    cmp_hdr(T) + tx_msg(12, mipi(0x03, flags=0xffff)) + tx_msg(12, mipi(0x1e, data=b"yuv")))

# --- Raw Ethernet ------------------------------------------------------
add("Raw Ethernet, preamble + SFD + frame",
    cmp_hdr(D) + data_msg(13, raw_eth(b"\x55" * 7 + b"\xd5" + INNER_ETH)))
add("Raw Ethernet, preamble + SMD-S0 + mPacket",
    cmp_hdr(D) + data_msg(13, raw_eth(b"\x55" * 7 + b"\xe6" + b"mpacket")))
add("Raw Ethernet, preamble only; preamble + SFD only; preamble + unknown SFD; no preamble",
    cmp_hdr(D) + data_msg(13, raw_eth(b"\x55" * 6))
    + data_msg(13, raw_eth(b"\x55" * 7 + b"\xd5"))
    + data_msg(13, raw_eth(b"\x55" * 7 + b"\x42" + b"xx"))
    + data_msg(13, raw_eth(b"\x01\x02\x03")))
add("Raw Ethernet, empty",
    cmp_hdr(D) + data_msg(13, raw_eth(b"")))

# --- 10BASE-T1S, A2B, link state, vendor -------------------------------
add("10BASE-T1S symbols",
    cmp_hdr(D) + data_msg(14, t1s(b"\x01\x02\x03\x04\x05", flags=0x000f)))
add("A2B with data",
    cmp_hdr(D) + data_msg(15, a2b(b"\xab\xcd\xef")))
add("A2B empty, all flags",
    cmp_hdr(D) + data_msg(15, a2b(b"", flags=0xffff, general=0xffffffffffffffff)))
add("Link state capture (up, link error)",
    cmp_hdr(D) + data_msg(0xfe, link_state(0x0001, 1)))
add("Link state transmit (down)",
    cmp_hdr(T) + tx_msg(0xfe, link_state(0xffff, 0)))
add("Vendor data message",
    cmp_hdr(D) + data_msg(0xff, vendor_data(0x1234, 0x0007, b"vendor-data")))
add("Unknown data payload type 0x77",
    cmp_hdr(D) + data_msg(0x77, b"unknown!"))

# --- Common flags / segmentation ---------------------------------------
seg_data = bytes(range(32))
add("Segmented CAN FD: first segment (seg=1), recalc/insync",
    cmp_hdr(D) + data_msg(2, can(id_=0x99 << 18, dlc=13, data=seg_data), flags=0x04 | 0x01 | 0x02))
add("Segmented: intermediary segment (seg=2), overflow and error in payload",
    cmp_hdr(D) + data_msg(0xff, vendor_data(0x1234, 1, b"middle"), flags=0x08 | 0x20 | 0x40))
add("Segmented: last segment (seg=3), dir on interface",
    cmp_hdr(D) + data_msg(0xff, vendor_data(0x1234, 1, b"last"), flags=0x0c | 0x10 | 0x80))
add("Transmit segmented, relative deadline, LIN header only; FlexRay transmit default opts",
    cmp_hdr(T) + tx_msg(3, lin(pid=0x05), flags=0x0c | 0x01 | 0x02 | 0xf0, opts=0xffffffff)
    + tx_msg(9, spi(b"x", b"y"), opts=0x12345678))
add("Several data messages in one packet (CAN, LIN, Ethernet)",
    cmp_hdr(D) + data_msg(1, can(id_=0x111 << 18, data=b"\x01")) + data_msg(3, lin(pid=0x12, data=b"\x01"))
    + data_msg(8, ethm(INNER_ETH)))
add("Data message then Ethernet padding (payload type 0 ends the packet)",
    cmp_hdr(D) + data_msg(9, spi(b"", b"")) + b"\0" * 20, pad=False)

# --- Control messages --------------------------------------------------
add("Control: Data Sink Ready",
    cmp_hdr(C) + ctrl_msg(1, struct.pack(">H", 0x0102), flags=0x03))
add("Control: User Event",
    cmp_hdr(C) + ctrl_msg(0xfe, struct.pack(">I", 0xdeadbeef), flags=0x0c))
add("Control: Vendor specific with data, then Data Sink Ready (fixed length)",
    cmp_hdr(C) + ctrl_msg(0xff, b"\x00\x01\x00\x02" + b"VVVVVV") + ctrl_msg(1, b"\x0a\x0b"))
add("Control: Vendor specific without data, then Data Sink Ready",
    cmp_hdr(C) + ctrl_msg(0xff, b"\x00\x01\x00\x02") + ctrl_msg(1, b"\x0a\x0b"))
add("Control: unknown type with and without payload",
    cmp_hdr(C) + ctrl_msg(0x55, b"zz") + ctrl_msg(0x56, b""))
add("Control: then padding",
    cmp_hdr(C) + ctrl_msg(0xfe, b"\0\0\0\1") + b"\0" * 16, pad=False)

# --- Status messages ---------------------------------------------------
cm = struct.pack(">QQIHBBBB", 3725 * 10**9 + 5, 0x0011223344556677, 0x06fe0001, 37, 0x20, 0, 0, 0x3f)
cm += struct.pack(">H", 7) + b"Gateway\0" + struct.pack(">H", 4) + b"SN42"
cm += struct.pack(">H", 3) + b"1.0\0" + struct.pack(">H", 5) + b"2.1.0\0" + struct.pack(">H", 3) + b"vnd"
add("Status: Capture Module, odd strings padded, vendor data",
    cmp_hdr(S) + status_msg(1, cm, flags=0x03, vendor=0x1234))
cm0 = struct.pack(">QQIHBBBB", 0, 0, 0, 0, 0, 0, 0, 0) + b"\0" * 10
add("Status: Capture Module with empty strings and no vendor data",
    cmp_hdr(S) + status_msg(1, cm0))


def iface(iid, itype, streams=b"", vdata=b"", feat=0xffffffff, status=1):
    e = struct.pack(">IIIIIIIBBHIH", iid, 100, 50, 1, 2, 3, 4, itype, status, 0, feat, len(streams)) + streams
    e += b"\0" * (len(streams) % 2)
    e += struct.pack(">H", len(vdata)) + vdata
    return e


ifs = b""
for i, t in enumerate((1, 2, 3, 4, 8, 0x0d, 0x0e, 0xfe, 0x05, 0x77)):
    ifs += iface(0x10 if i == 0 else 0x100 + i, t,
                 streams=bytes(range(1, 1 + (i % 4))), vdata=b"vd" if i == 2 else b"")
add("Status: Interface, every interface type, stream ids (odd/even/none), vendor data",
    cmp_hdr(S) + status_msg(2, ifs))
add("Status: Interface, entry with vendor data of 4 bytes, named interface",
    cmp_hdr(S) + status_msg(2, iface(0x10, 1, streams=b"\x01\x02", vdata=b"abcd")))
add("Status: Configuration",
    cmp_hdr(S) + status_msg(3, b"<config/>\0\0\0"))
add("Status: Configuration, empty",
    cmp_hdr(S) + status_msg(3, b""))
add("Status: Data Lost Event",
    cmp_hdr(S) + status_msg(4, struct.pack(">HHBBHH", 1, 0x0102, 0, 3, 100, 105)))
add("Status: Time Sync Lost Event",
    cmp_hdr(S) + status_msg(5, struct.pack(">HHBB", 2, 0x0102, 0x07, 0)))
add("Status: Vendor specific, and empty",
    cmp_hdr(S) + status_msg(0xff, b"vend") + status_msg(0xff, b""))
add("Status: unknown type",
    cmp_hdr(S) + status_msg(0x77, b"zzzz") + status_msg(0x78, b""))

# --- Vendor messages, unknown message type, header only ----------------
add("Vendor-defined message with and without payload",
    cmp_hdr(V) + vendor_msg(1, b"vvvv") + vendor_msg(2, b""))
add("Unknown message type 0x05",
    cmp_hdr(0x05) + b"\x01" * 20)
add("CMP header only (no message)",
    cmp_hdr(D))
add("Device 0x0303 (no name), stream 7",
    cmp_hdr(D, dev=0x0303, stream=7) + data_msg(1, can(id_=0x1 << 18, data=b"\x01")))

# --- UDP transport -----------------------------------------------------
add_udp("UDP port 50000: CAN data message",
        cmp_hdr(D, stream=2) + data_msg(1, can(id_=0x77 << 18, data=b"\x01\x02")))
add_udp("UDP port 50000: Status Capture Module",
        cmp_hdr(S, stream=2) + status_msg(1, cm))

# --- Nesting -----------------------------------------------------------
# Ethernet in CMP in Ethernet ... 300 levels; the dissector stops before
# the tree depth limit with asam-cmp.expert.too_deep (a warning).
NEST = 300
inner = eth(CMP_ETYPE, cmp_hdr(D, seq=0) + data_msg(9, spi(b"", b"")))
for _ in range(NEST):
    inner = eth(CMP_ETYPE, cmp_hdr(D, seq=0) + data_msg(8, ethm(inner)))
main.append(("Ethernet nested %d levels (too_deep warning)" % NEST, inner))

# ------------------------------------------------------- malformed -----
M = malformed
add("Truncated CMP header", b"\x01\x00\x01", lst=M, pad=False)
add("Transmit data message with only 16 bytes", cmp_hdr(T) + b"\x01" * 16, lst=M, pad=False)
add("Data message payload length past the packet",
    cmp_hdr(D) + data_msg(9, spi(b"a", b"b"), length=200), lst=M, pad=False)
add("CAN data length past the payload",
    cmp_hdr(D) + data_msg(1, struct.pack(">HHIIHBB", 0, 0, 1, 0, 0, 8, 64) + b"\x01"), lst=M, pad=False)
add("Digital 40 pins with short sample",
    cmp_hdr(D) + data_msg(5, digital(40, samples=[b"\x01\x02"])), lst=M, pad=False)
add("MIPI word count past payload",
    cmp_hdr(D) + data_msg(12, mipi(0x2a, data=b"x")[:-3] + b"\x00\x40x"), lst=M, pad=False)
add("10BASE-T1S length past payload",
    cmp_hdr(D) + data_msg(14, struct.pack(">HH", 0, 50) + b"\x01"), lst=M, pad=False)
add("Ethernet length past payload",
    cmp_hdr(D) + data_msg(8, struct.pack(">HHH", 0, 0, 100) + b"\x01" * 10), lst=M, pad=False)
add("FlexRay null frame with data length past payload (data msg length mismatch)",
    cmp_hdr(D) + data_msg(4, flexray(flags=0x0004, dlen=200)), lst=M, pad=False)
add("UART count past payload",
    cmp_hdr(D) + data_msg(6, struct.pack(">HHH", 3, 0, 20) + b"\x00\x41"), lst=M, pad=False)
add("Control user event payload length 1",
    cmp_hdr(C) + ctrl_msg(0xfe, b"\0", length=1) + b"\0\0\0\0", lst=M, pad=False)
add("Control vendor ctrl msg payload 6 past packet",
    cmp_hdr(C) + ctrl_msg(0xff, b"\0\1\0\2", length=10), lst=M, pad=False)
add("Status CM truncated strings",
    cmp_hdr(S) + status_msg(1, cm[:40], length=len(cm)), lst=M, pad=False)
add("Status CM with payload length shorter than content (length mismatch)",
    cmp_hdr(S) + status_msg(1, cm, length=8), lst=M, pad=False)
add("Status interface with stream id count past packet",
    cmp_hdr(S) + status_msg(2, iface(1, 1)[:36] + struct.pack(">H", 300) + b"\0\0"), lst=M, pad=False)
add("Status TSLE truncated",
    cmp_hdr(S) + status_msg(5, b"\0\1", length=4) + b"\0" * 10, lst=M, pad=False)
add("Control message truncated header (16 bytes, payload length past end)",
    cmp_hdr(C) + ctrl_msg(1, b"", length=40), lst=M, pad=False)
add("Vendor message payload past end",
    cmp_hdr(V) + vendor_msg(1, b"", length=40), lst=M, pad=False)
add("Raw Ethernet length past payload",
    cmp_hdr(D) + data_msg(13, struct.pack(">HHH", 0, 0, 50) + b"\x55" * 4), lst=M, pad=False)
add("Analog data msg with header cut short",
    cmp_hdr(D) + data_msg(7, b"\0\0\0\1"), lst=M, pad=False)
add("I2C entry count past payload",
    cmp_hdr(D) + data_msg(10, struct.pack(">HHHH", 0, 0, 1, 9) + b"\x00\x01"), lst=M, pad=False)
add("SPI CIPO length past payload",
    cmp_hdr(D) + data_msg(9, struct.pack(">HHH", 0, 0, 40) + b"ab"), lst=M, pad=False)
add("GigE length past payload",
    cmp_hdr(D) + data_msg(11, struct.pack(">HHH", 0, 0, 40) + b"ab"), lst=M, pad=False)
add("A2B length past payload",
    cmp_hdr(D) + data_msg(15, a2b(b"")[:-2] + b"\x00\x30"), lst=M, pad=False)
add("Vendor ctrl msg payload length 0 (length mismatch)",
    cmp_hdr(C) + ctrl_msg(0xff, b"", length=0) + b"\0\1\0\2" + b"\x01" * 12, lst=M, pad=False)

# Expert infos in the Malformed group (warnings), kept out of the main capture
add("CAN 11 bit, CRC not supported but not zero (warning), ERR id bit",
    cmp_hdr(D) + data_msg(1, can(id_=0x20000000 | (0x7ff << 18), crc=0x00000042, data=b"\xaa")), lst=M)
add("Control: Vendor specific with payload length 2 (length mismatch warning)",
    cmp_hdr(C) + ctrl_msg(0xff, b"\x00\x01\x00\x02", length=2) + b"\x01\x02", lst=M)
add("Control: Data Sink Ready with payload length 0 (length mismatch warning)",
    cmp_hdr(C) + ctrl_msg(1, b"", length=0) + b"\x01\x02", lst=M)
add("Status: Data Lost Event with payload length 0 (length mismatch warning)",
    cmp_hdr(S) + status_msg(4, b"", length=0) + b"\x01" * 10, lst=M)

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    write_pcap(os.path.join(out, "asam_cmp-coverage.pcap"), [f for _, f in main])
    write_pcap(os.path.join(out, "asam_cmp-coverage-malformed.pcap"), [f for _, f in malformed])
    if "-l" in sys.argv:
        for name, lst in (("main", main), ("malformed", malformed)):
            print(name)
            for i, (d, f) in enumerate(lst, 1):
                print("%4d %6d %s" % (i, len(f), d))
