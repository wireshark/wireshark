#!/usr/bin/env python3
# Generates the ixveriwave captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the IxVeriWave coverage captures (synthetic, struct only).

Usage: mkixveriwave.py <outdir>

The IxVeriWave dissector is reached through the .vwr file reader
(WTAP_ENCAP_IXVERIWAVE), which turns the records of a VeriWave capture
into the metadata headers the dissector decodes. The reader picks the
record layout (FPGA version) from the first frame of a file, so there is
one file per layout:

  ixveriwave-coverage.vwr         OCTO (S3, "FPGA version >= 48") WLAN:
                                  receive and transmit frames of every PLCP
                                  type, RF records and RF + receive records
  ixveriwave-coverage-s2.vwr      series II WLAN (legacy, HT, VHT)
  ixveriwave-coverage-s1.vwr      series I WLAN (OFDM and CCK)
  ixveriwave-coverage-eth.vwr     series II Ethernet (vVW510024)
  ixveriwave-coverage-eth1.vwr    series I Ethernet (vVW510012)
  ixveriwave-coverage-malformed.vwr  records the dissector cannot
                                  decode completely

The frames are made up (random fields from a fixed seed on top of valid
802.11 and Ethernet frames); nothing comes from a real network.
"""
import os
import random
import struct
import sys
import zlib

COMMAND_RX, COMMAND_TX, COMMAND_RF, COMMAND_RFRX = 0x21, 0x31, 0x38, 0x39


# ---------------------------------------------------------------- frames

def mac(n):
    return bytes([2, 0, 0, 0, 0, n])


def csum(b):
    if len(b) & 1:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(l4, proto=17, src=(192, 0, 2, 1), dst=(192, 0, 2, 2), ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0, 64, proto, 0, bytes(src), bytes(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + l4


def udp(payload, sport=1000, dport=2000):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


_tcp_seq = [1]


def tcp(payload=b'', sport=1000, dport=80, flags=0x18):
    seq = _tcp_seq[0]
    _tcp_seq[0] += len(payload)
    return struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 5 << 4, flags, 8192, 0, 0) + payload


def icmp_echo(payload=b'ixveriwave'):
    m = struct.pack('!BBHHH', 8, 0, 0, 1, 1) + payload
    return m[:2] + struct.pack('!H', csum(m)) + m[4:]


def icmp_unreach(payload=b'x'):
    """An ICMP timestamp request (no response tracking, no error type)."""
    m = struct.pack('!BBHHHIII', 13, 0, 0, 1, 1, 1000, 0, 0) + payload
    return m[:2] + struct.pack('!H', csum(m)) + m[4:]


def eth_frame(l3, vlan=None, a=1, b=2):
    f = mac(b) + mac(a)
    if vlan is not None:
        f += struct.pack('!HH', 0x8100, vlan)
    return f + struct.pack('!H', 0x0800) + l3


def signature(flow_id, seq, ts, n=16):
    """The VeriWave payload signature: 0xdd, a 24 bit flow id, the
    sequence number and the 32 bit timestamp."""
    s = bytearray(n)
    s[0] = 0xdd
    s[1:4] = struct.pack('<I', flow_id)[:3]
    s[4] = seq
    s[5:9] = struct.pack('<I', ts)
    s[15] = 0xe2
    return bytes(s)


def seqctl(n):
    return struct.pack('<H', (n & 0xfff) << 4)


def wlan_beacon(n=1, ssid=b'ixveriwave'):
    h = b'\x80\x00\x00\x00' + b'\xff' * 6 + mac(1) + mac(1) + seqctl(n)
    b = struct.pack('<QHH', 1000 * n, 100, 0x0431) + bytes([0, len(ssid)]) + ssid
    return h + b + b'\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24\x03\x01\x06'


def wlan_probe_req(n=1):
    h = b'\x40\x00\x00\x00' + b'\xff' * 6 + mac(2) + b'\xff' * 6 + seqctl(n)
    return h + b'\x00\x00' + b'\x01\x04\x02\x04\x0b\x16'


def wlan_qos_data(l3, n=1, to_ds=True, flags=0):
    fc = bytes([0x88, (0x01 if to_ds else 0x02) | flags])
    h = fc + b'\x2c\x00' + mac(1) + mac(2) + mac(3) + seqctl(n) + b'\x00\x00'
    return h + b'\xaa\xaa\x03\x00\x00\x00\x08\x00' + l3


def wlan_data(l3, n=1):
    h = b'\x08\x01\x2c\x00' + mac(1) + mac(2) + mac(3) + seqctl(n)
    return h + b'\xaa\xaa\x03\x00\x00\x00\x08\x00' + l3


def wlan_null(n=1):
    return b'\x48\x01\x2c\x00' + mac(1) + mac(2) + mac(1) + seqctl(n)


def wlan_ack():
    return b'\xd4\x00\x00\x00' + mac(2)


def wlan_rts():
    return b'\xb4\x00\x00\x00' + mac(1) + mac(2)


def wlan_cts():
    return b'\xc4\x00\x00\x00' + mac(2)


def wlan_auth(n=1):
    return b'\xb0\x00\x00\x00' + mac(1) + mac(2) + mac(1) + seqctl(n) + struct.pack('<HHH', 0, 1, 0)


def wlan_deauth(n=1):
    return b'\xc0\x00\x00\x00' + mac(2) + mac(1) + mac(1) + seqctl(n) + b'\x03\x00'


def wlan_frames():
    u = ipv4(udp(b'x' * 40))
    return [
        wlan_beacon(1), wlan_probe_req(2), wlan_qos_data(u, 3), wlan_data(u, 4),
        wlan_null(5), wlan_ack(), wlan_rts(), wlan_cts(), wlan_auth(6), wlan_deauth(7),
        wlan_qos_data(ipv4(udp(b'downlink data', 3000, 4000)), 8, to_ds=False),
        wlan_qos_data(ipv4(icmp_unreach(), 1), 9),
    ]


# --------------------------------------------------------------- records

def corey(v):
    """A 64 bit value in "Corey-endian" form."""
    return struct.pack('>II', v & 0xffffffff, (v >> 32) & 0xffffffff)


def rec_hdr(cmd, size, fpga=0, mode=0):
    h = bytearray(16)
    h[0] = cmd
    h[1] = mode << 4
    h[8] = fpga
    h[10:12] = struct.pack('>H', size)
    return bytes(h)


def record(cmd, body, fpga=0, mode=0):
    return rec_hdr(cmd, len(body), fpga, mode) + body


def cpmsg():
    """A control message record (skipped by the reader)."""
    h = bytearray(16)
    h[0] = 0xc1
    h[10:12] = struct.pack('>H', 20)
    return bytes(h) + bytes(20)


def cpmsg_fe():
    h = bytearray(16)
    h[0] = 0xfe
    h[14:16] = struct.pack('>H', 8)
    return bytes(h) + bytes(8)


def pad4(b):
    return b + bytes(-len(b) % 4)


def vht_plcp(rng, group_id=None, bw=None):
    """16 bytes of PLCP of a VHT frame: L-SIG (3), VHT-SIG-A1 (3), A2 (3),
    B (4) and 3 spare. SU frames have a group id of 0 or 63."""
    if group_id is None:
        group_id = rng.choice([0, 63, 0, 63, 5, 20])
    if bw is None:
        bw = rng.randrange(0, 4)
    r = lambda n: bytes(rng.getrandbits(8) for _ in range(n))
    a1 = bytes([bw | (rng.getrandbits(1) << 3) | ((group_id & 0xf) << 4),
                ((group_id >> 4) & 3) | (rng.getrandbits(6) << 2), rng.getrandbits(8)])
    return r(3) + a1 + r(3) + r(4) + r(3)


# S3 (OCTO) ---------------------------------------------------------------

def s3_trailer(rng, start, end, flowseq, flowid, valid=True):
    t = bytearray(48)
    t[0:8] = corey(start)
    t[8:16] = corey(end)
    t[16:20] = struct.pack('>I', rng.choice([0, 0, 0x2, 0x4, 0x8, 0x10, rng.getrandbits(16)]))
    t[20:22] = struct.pack('>H', rng.getrandbits(16) | (0x8000 if valid else 0))
    t[22:24] = struct.pack('>H', rng.choice([0, 0x0004, 0x0008, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x8000,
                                             rng.getrandbits(16)]))
    t[24:28] = struct.pack('>I', rng.getrandbits(32))
    t[28:30] = struct.pack('>H', rng.getrandbits(16))
    t[32] = flowseq
    t[33:36] = flowid.to_bytes(3, 'big')
    t[36:40] = struct.pack('>I', rng.getrandbits(32))
    t[41] = rng.getrandbits(8)
    return bytes(t)


def s3_rec(rng, cmd, plcp, frame, mode=0, rf=None, start=1_000_000_000, dur=50_000, gap=1000, vht=(None, None)):
    """One OCTO record (RX 0x21 / TX 0x31 / RFRX 0x39 with a 100 byte RF block)."""
    if plcp == 0:
        l1p1 = rng.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14]) | rng.choice([0, 0x40])
    elif plcp in (1, 2):
        l1p1 = rng.randrange(0, 32) | rng.choice([0, 0x40])
    elif plcp == 3:
        l1p1 = rng.randrange(0, 10) | (rng.randrange(0, 4) << 4) | rng.choice([0, 0x40])
    else:
        l1p1 = rng.getrandbits(8)
    l1p2 = plcp | (rng.randrange(0, 6) << 4) | rng.choice([0, 0, 0x80])
    rssi = [rng.choice([0xc0, 0xd0, 0xe3, 0x10, 0x64, 0x80 | rng.randrange(1, 100)]) for _ in range(4)]
    if rng.random() < 0.5:
        rssi[1:] = [100, 100, 100]
    l1c = rng.getrandbits(8)
    bm = bytearray(rng.getrandbits(8) for _ in range(4))
    bm[0] = (bm[0] & 0x9f) | rng.choice([0, 0x20, 0x40, 0x60])
    plcp16 = bytes(rng.getrandbits(8) for _ in range(16))
    if plcp == 3:
        plcp16 = vht_plcp(rng, *vht)
    fcs = struct.pack('<I', zlib.crc32(frame))
    if mode == 3:
        # the reader strips the 4 bytes of "FCS" (junk) of reduced records
        msdu = len(frame) + 8
        data = frame + fcs + b'\x01\x02\x03\x04'
    else:
        msdu = len(frame) + 4
        data = frame + fcs
    stats = (bytes([l1p1, l1p2, rng.getrandbits(8), rng.getrandbits(8)]) + bytes(rssi) + bytes([l1c])
             + msdu.to_bytes(3, 'big') + bytes(bm) + plcp16)
    trailer = s3_trailer(rng, start, start + dur, rng.getrandbits(8), rng.getrandbits(24))
    body = (rf or b'') + stats + data + trailer
    return record(cmd, body, 48, mode)


def rf_block(rng, valid=(1, 1, 1, 1), rfid=1, ff=None):
    """The 100 byte RF block: four ports of 24 bytes after 4 bytes. The
    low bit of the second byte of each port's context is the "valid" bit."""
    b = bytearray(100)
    b[0] = rfid
    for p in range(4):
        base = 4 + p * 24
        for off in (0, 2, 4, 6, 8, 10, 12, 14, 18):
            v = rng.getrandbits(16) if rng.random() > 0.15 else 0
            b[base + off:base + off + 2] = struct.pack('>H', v)
        # context: the low bit of the second byte is the "valid" bit; the low
        # two bits of the first byte are the frame format (0 is legacy)
        hi = (rng.getrandbits(8) & 0xfc) | rng.randrange(4)
        lo = (rng.getrandbits(8) & 0xfe) | valid[p]
        if hi == 0 and lo == 0:
            lo = 0x80
        b[base + 6:base + 8] = bytes([hi, lo])
    return bytes(b)


def build_rf_only(rng):
    """RF only records (command 3): the dissector reads the time header that
    these records do not have and runs off the end."""
    out = [s3_rec(rng, COMMAND_RX, 1, wlan_beacon(1))]
    for valid in ((1, 1, 1, 1), (0, 1, 0, 1)):
        out.append(record(COMMAND_RF, rf_block(rng, valid, rfid=rng.randrange(0, 5)), 48))
    return b''.join(out)


def build_s3(rng):
    out = [cpmsg(), cpmsg_fe()]
    frames = wlan_frames()
    t = 1_700_000_000_000_000_000 // 1  # ns
    t = 1_000_000_000
    i = 0
    # receive and transmit frames of every PLCP type, several of each
    for cmd in (COMMAND_RX, COMMAND_TX):
        for plcp in (0, 1, 2, 3, 0, 1, 2, 3, 0, 3, 5):
            for rep in range(3):
                fr = frames[i % len(frames)]
                i += 1
                mode = 3 if (rep == 2 and plcp in (0, 3)) else 0
                out.append(s3_rec(rng, cmd, plcp, fr, mode=mode, start=t))
                t += 80_000 + rng.getrandbits(14)
    # frames that start before the previous one ended (negative IFG)
    for k in range(2):
        out.append(s3_rec(rng, COMMAND_RX, 1, frames[0], start=t, dur=200_000))
        out.append(s3_rec(rng, COMMAND_RX, 1, frames[1], start=t + 1000, dur=1000))
        t += 400_000
    # VHT frames of every bandwidth, single user (group id 0 and 63) and
    # multi user (5)
    for group in (0, 63, 5):
        for bw in range(4):
            out.append(s3_rec(rng, rng.choice([COMMAND_RX, COMMAND_TX]), 3, frames[i % len(frames)],
                              start=t, vht=(group, bw)))
            i += 1
            t += 90_000
    # the end of the frame before its start
    out.append(s3_rec(rng, COMMAND_RX, 0, frames[0], start=t, dur=-50_000))
    t += 400_000
    # RF records
    for n in range(32):
        valid = tuple((n >> k) & 1 for k in range(4))
        # RF + receive
        out.append(s3_rec(rng, COMMAND_RFRX, [0, 1, 2, 3][n % 4], frames[i % len(frames)],
                          rf=rf_block(rng, valid, rfid=n), start=t))
        i += 1
        t += 90_000
    # Reproducer of "IxVeriWave: Fix legacy_type precedence": the legacy type
    # is bit 2 of the byte at offset 33 of the RF header (frame format 0).
    # With the bit set the PFE is in units of 20.981 Hz (CCK), clear 19.073 Hz
    # (OFDM). The PFE of port A is 1000 in both.
    for b61 in (0x04, 0x00):
        rf = bytearray(rf_block(rng, (1, 1, 1, 1), rfid=9))
        rf[8:10] = struct.pack('>H', 1000)
        rf[60:62] = bytes([1, b61])
        out.append(s3_rec(rng, COMMAND_RFRX, 0, frames[0], rf=bytes(rf), start=t))
        t += 90_000
    return b''.join(out)


# S2 (series II WLAN) ------------------------------------------------------

def s2_rec(rng, cmd, plcp, frame, start, dur=40_000, ttl_sig=False, info=None, errors=None, raw=False):
    """Stats header (8), PLCP (12), MPDU, padding, 48 byte trailer."""
    if plcp == 0:
        l1p1 = rng.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]) | rng.choice([0, 0x40])
    elif plcp in (1, 2):
        l1p1 = rng.randrange(0, 32) | rng.choice([0, 0x40])
    else:
        l1p1 = rng.randrange(0, 10) | (rng.randrange(0, 4) << 4) | rng.choice([0, 0x40])
    l1p2 = plcp | (rng.randrange(0, 6) << 4)
    if plcp == 3 and not raw:
        # the dissector skips 17 bytes (PLCP and L1 info of a VHT frame)
        # before the MAC frame; the reader does not provide them
        frame = bytes([rng.getrandbits(8)]) + vht_plcp(rng) + frame
    msdu = len(frame) + 4
    plcp12 = bytearray(rng.getrandbits(8) for _ in range(12))
    plcp12[0] = rng.getrandbits(8)
    if info is not None and info & 0xfc00:
        # aggregation flags: the HT length comes from the PLCP bytes 4 and 5
        plcp12[4:6] = struct.pack('<H', rng.randrange(100, 6000))
    hdr = (bytes([l1p1, l1p2, rng.choice([0xd0, 0xe0, 0x30, 0x64, 0x9c]), msdu & 0xff, (msdu >> 8) & 0x1f, 0])
           + struct.pack('>H', rng.getrandbits(16)))
    t = bytearray(s3_trailer(rng, start, start + dur, rng.getrandbits(8), rng.getrandbits(24)))
    if info is not None:
        t[22:24] = struct.pack('>H', info)
    if errors is not None:
        t[16:20] = struct.pack('>I', errors)
    data = pad4(frame + b'\x01\x02\x03\x04')
    # the detection of the layout wants record size = msdu + padding + 68
    body = hdr + bytes(plcp12) + data + bytes(t)
    assert len(body) == msdu + (-msdu % 4) + 68, (len(body), msdu)
    return record(cmd, body, 0)


def ipv4_ttl(l4, proto, ttl):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 1, 0, ttl, proto, 0,
                    bytes((192, 0, 2, 1)), bytes((192, 0, 2, 2)))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:] + l4


def sig_frames_wlan():
    """Data frames with 0xdd at byte 42 (the IP TTL), where the reader looks
    for the VeriWave payload signature of a WLAN frame."""
    u = udp(signature(0x123456, 7, 0x1000, 40) + b'x' * 40)
    return [wlan_qos_data(ipv4_ttl(u, 17, 0xdd), 21), wlan_data(ipv4_ttl(u, 17, 0xdd), 22)]


def build_s2(rng):
    out = []
    frames = wlan_frames() + sig_frames_wlan()
    big = wlan_qos_data(ipv4(udp(b'v' * 180)), 30)
    t = 2_000_000_000
    i = 0
    infos = [0, 0x0001, 0x0400, 0x0c00, 0x1400, 0x2000, 0x6000, 0xa000, 0x0002, 0x0004]
    for cmd in (COMMAND_RX, COMMAND_TX):
        for plcp in (0, 1, 2, 3, 0, 1, 2, 3):
            fr = big if plcp == 3 else frames[i % len(frames)]
            i += 1
            out.append(s2_rec(rng, cmd, plcp, fr, t, info=infos[i % len(infos)],
                              errors=rng.choice([0, 0x1, 0x2, 0x4, 0x8, 0x1f00, 0x400, 0xffff])))
            t += 70_000
    # VHT with a non-zero HT length (aggregation) uses the PLCP bytes
    for info in (0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x8000, 0x0c00):
        out.append(s2_rec(rng, COMMAND_RX, 3, big, t, info=info))
        out.append(s2_rec(rng, COMMAND_TX, 3, big, t + 100_000, info=info))
        t += 300_000
    # frames with a signature, receive: the latency is set
    for fr in sig_frames_wlan():
        out.append(s2_rec(rng, COMMAND_RX, 0, fr, t))
        t += 100_000
    # the end of the frame before its start
    out.append(s2_rec(rng, COMMAND_RX, 0, frames[0], t, dur=-50_000))
    return b''.join(out)


def build_malformed_s2(rng):
    """A transmitted VHT frame with an MSDU length of 4 (a null data packet,
    no MPDU): the dissector skips 17 bytes that are not there."""
    t = 5_000_000_000
    out = [s2_rec(rng, COMMAND_RX, 0, wlan_beacon(1), t)]
    out.append(s2_rec(rng, COMMAND_TX, 3, b'', t + 100_000, raw=True))
    out.append(s2_rec(rng, COMMAND_RX, 3, b'', t + 200_000, raw=True))
    return b''.join(out)


# S1 (series I WLAN) ---------------------------------------------------------

def s1_rec(rng, rx, ofdm, frame, start, dur=30_000, info=0, errors=0, ttl_sig=False):
    if ofdm:
        plcp = bytes([rng.choice([0x0b, 0x0f, 0x0a, 0x0e, 0x09, 0x0d, 0x08, 0x0c]), 0, 0, 0])
        mtype = 2
    else:
        plcp = bytes([rng.choice([0x0a, 0x14, 0x37, 0x6e, 0x00]), 0, 0, 0, 0, 0])
        mtype = rng.choice([0, 1])
    mtype |= 0x08 if rx else 0
    octets = len(plcp) + len(frame) + 4
    data = pad4(plcp + frame + b'\x01\x02\x03\x04')
    t = bytearray(64)
    t[1] = mtype
    t[2:4] = struct.pack('>H', rng.getrandbits(10))
    t[4] = rng.getrandbits(8)
    t[5:8] = rng.getrandbits(24).to_bytes(3, 'big')
    t[8:10] = struct.pack('>H', octets)
    t[10:12] = struct.pack('>H', errors)
    t[16:20] = struct.pack('>I', 0x01000010)
    t[21] = rng.choice([0x30, 0xb0, 0x64, 0xe0])
    t[24:32] = corey(start)
    t[32:40] = corey(start + dur)
    t[40:44] = struct.pack('>I', rng.getrandbits(32))
    t[44:48] = struct.pack('>I', 0)
    t[54:56] = struct.pack('>H', info)
    body = data + bytes(t)
    assert len(body) == octets + (-octets % 4) + 64
    return record(COMMAND_RX if rx else COMMAND_TX, body, 0)


def build_s1(rng):
    out = []
    frames = wlan_frames() + sig_frames_wlan()
    t = 3_000_000_000
    i = 0
    for rx in (True, False):
        for ofdm in (True, False):
            for rep in range(6):
                info = [0, 1, 2, 4, 0x400, 0x2000][rep]
                err = [0, 0x2, 0x1f00, 0x400, 0x4, 0x8][rep]
                out.append(s1_rec(rng, rx, ofdm, frames[i % len(frames)], t, info=info, errors=err))
                i += 1
                t += 60_000
    for fr in sig_frames_wlan():
        out.append(s1_rec(rng, True, True, fr, t))
        t += 60_000
    out.append(s1_rec(rng, True, True, frames[0], t, dur=-30_000))
    return b''.join(out)


# Ethernet ------------------------------------------------------------------

def eth_frames():
    sigp = signature(0x00abcd, 9, 0x2000, 24)
    return {
        'udp': eth_frame(ipv4(udp(sigp + b'u' * 16))),
        'tcp': eth_frame(ipv4(tcp(sigp + b't' * 16), 6)),
        'icmp': eth_frame(ipv4(icmp_unreach(sigp), 1)),
        'igmp': eth_frame(ipv4(b'\x11\x64\xee\x9b\x00\x00\x00\x00', 2)),
        'raw': eth_frame(ipv4(b'rawip' + bytes(20), 99)),
        'vlan_udp': eth_frame(ipv4(udp(sigp + b'v' * 16)), vlan=100),
    }


FRAME_TYPE_I = {'tcp': 0x40, 'udp': 0x10, 'icmp': 0x20, 'igmp': 0x80, 'raw': 0, 'vlan_udp': 0x10 | 0x00200000}
FRAME_TYPE_II = {'tcp': 0x01000000, 'udp': 0x00100000, 'icmp': 0x1000, 'igmp': 0x10000, 'raw': 0,
                 'vlan_udp': 0x00100000}


def eth2_rec(rng, rx, kind, frame, start, dur=1000, flow_valid=True, errors=0, info=0):
    msdu = len(frame) + 4
    t = bytearray(48)
    t[0:2] = struct.pack('>H', msdu)
    t[2:4] = struct.pack('>H', rng.getrandbits(14) | rng.choice([0, 0x4000, 0x8000]))
    t[4:12] = corey(start)
    t[12:20] = corey(start + dur)
    t[22:24] = struct.pack('>H', errors)
    valid = (0x8000 if flow_valid else 0) | (0x4000 if kind == 'vlan_udp' else 0) | rng.choice([0, 0x1000])
    t[24:26] = struct.pack('>H', valid)
    t[26:28] = struct.pack('>H', info)
    t[28:32] = struct.pack('>I', FRAME_TYPE_II[kind])
    t[32:34] = struct.pack('>H', rng.getrandbits(16))
    t[36] = 9
    t[37:40] = (0x00abcd).to_bytes(3, 'big')
    t[40:44] = struct.pack('>I', rng.getrandbits(32))
    body = pad4(frame + b'\x01\x02\x03\x04') + bytes(t)
    return record(COMMAND_RX if rx else COMMAND_TX, body, 0)


def eth1_rec(rng, rx, kind, frame, start, dur=1000, flow_valid=True, errors=0, info=0):
    msdu = len(frame) + 4
    t = bytearray(44)
    t[0] = 0x40 if flow_valid else 0
    t[1] = rng.choice([0, 1, 2, 3, 4, 5])
    t[2:4] = struct.pack('>H', rng.getrandbits(10))
    t[4] = 9
    t[5:8] = (0x00abcd).to_bytes(3, 'big')
    t[8:10] = struct.pack('>H', msdu)
    t[10:12] = struct.pack('>H', errors)
    t[12:14] = struct.pack('>H', rng.getrandbits(16))
    t[16:20] = struct.pack('>I', FRAME_TYPE_I[kind])
    t[20:28] = corey(start)
    t[28:36] = corey(start + dur)
    t[36:40] = struct.pack('>I', rng.getrandbits(32))
    t[40:42] = struct.pack('>H', info)
    body = pad4(frame + b'\x01\x02\x03\x04') + bytes(t)
    return record(COMMAND_RX if rx else COMMAND_TX, body, 0)


def build_eth(rng, make):
    out = []
    frames = eth_frames()
    t = 4_000_000_000
    for rx in (True, False):
        frames = eth_frames()
        for kind, fr in frames.items():
            errs = rng.choice([0, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0xffff])
            out.append(make(rng, rx, kind, fr, t, errors=errs, info=rng.choice([0, 1, 2, 3, 0xffff])))
            t += 2000
    # no valid flow: no signature, no latency
    out.append(make(rng, True, 'udp', frames['udp'], t, flow_valid=False))
    t += 2000
    # end before the start
    frames = eth_frames()
    out.append(make(rng, True, 'tcp', frames['tcp'], t, dur=0))
    t += 2000
    # a frame that starts before the previous one ended
    out.append(make(rng, False, 'icmp', frames['icmp'], t - 1500))
    t += 5000
    # the end of the frame before its start
    out.append(make(rng, True, 'udp', frames['udp'], t, dur=-1000))
    return b''.join(out)


# ------------------------------------------------------------------ main

def write(out, name, data):
    with open(os.path.join(out, name), 'wb') as f:
        f.write(data)


def main(out):
    # one generator per file: a change to one does not move the others
    write(out, 'ixveriwave-coverage.vwr', build_s3(random.Random(26)))
    write(out, 'ixveriwave-coverage-malformed.vwr', build_rf_only(random.Random(27)))
    write(out, 'ixveriwave-coverage-s2.vwr', build_s2(random.Random(28)))
    write(out, 'ixveriwave-coverage-malformed-s2.vwr', build_malformed_s2(random.Random(29)))
    write(out, 'ixveriwave-coverage-s1.vwr', build_s1(random.Random(30)))
    write(out, 'ixveriwave-coverage-eth.vwr', build_eth(random.Random(31), eth2_rec))
    write(out, 'ixveriwave-coverage-eth1.vwr', build_eth(random.Random(32), eth1_rec))


if __name__ == '__main__':
    main(sys.argv[1])
