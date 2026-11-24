# Generates test/captures/vcdu_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import os
import struct
import sys

def esc(b):
    """EyeSDN escaping: 0xff and 0xfe become 0xfe and the value - 2."""
    out = bytearray()
    for c in b:
        if c in (0xff, 0xfe):
            out += bytes([0xfe, c - 2])
        else:
            out.append(c)
    return bytes(out)


def eyesdn(path, records):
    """records: (encap, uton, channel, payload)."""
    with open(path, 'wb') as f:
        f.write(b'EyeSDN')
        for i, (encap, uton, channel, payload) in enumerate(records):
            hdr = struct.pack('>I', 1000 * i)[1:] + struct.pack('>Q', 1700000000 + i)[3:]
            hdr += bytes([channel, (encap << 1) | uton]) + struct.pack('>H', len(payload))
            f.write(b'\xff' + esc(hdr + payload))


def pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 10, 100000 * (i % 10), len(fr), len(fr)))
            f.write(fr)


def exppdu(name, payload):
    """Exported PDU frame (linktype 252) naming a dissector."""
    b = name.encode()
    b += b'\0' * ((4 - len(b) % 4) % 4)
    return struct.pack('>HH', 12, len(b)) + b + struct.pack('>HH', 0, 0) + payload


def inet_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ether(payload, etype=0x0800, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01'):
    return dst + src + struct.pack('>H', etype) + payload


def ip4(proto, src, dst, payload, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                      bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    hdr = hdr[:10] + struct.pack('>H', inet_csum(hdr)) + hdr[12:]
    return hdr + payload


def udp(sport, dport, payload):
    return struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, seq, ack, flags, payload=b'', win=8192):
    return struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, win, 0, 0) + payload


def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return (~crc) & 0xffffffff


def sctp(sport, dport, vtag, chunks):
    body = b''.join(chunks)
    hdr = struct.pack('>HHII', sport, dport, vtag, 0)
    c = crc32c(hdr + body)
    return hdr[:8] + struct.pack('<I', c) + body


def sctp_data(tsn, sid, ssn, ppid, data, flags=3):
    ln = 16 + len(data)
    ch = struct.pack('>BBHIHHI', 0, flags, ln, tsn, sid, ssn, ppid) + data
    return ch + b'\0' * ((4 - ln % 4) % 4)


def sctp_init(tag, chunk_type=1):
    return struct.pack('>BBHIIHHI', chunk_type, 0, 20, tag, 65535, 4, 4, 1000)




def pcapng(path, linktypes, frames):
    """frames: (interface id, data). Writes SHB, one IDB per link type, EPBs."""
    def blk(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)
    out = blk(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    for lt in linktypes:
        out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifid, data) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)
#!/usr/bin/env python3
"""Generate the synthetic captures for the VCDU dissector (packet-vcdu.c).

VCDU (Virtual Channel Data Unit, with the SMEX ground header) has no
registered port: it is reached through Decode As on UDP or an Exported PDU
that names "vcdu".  The main capture is a pcapng file with two interfaces:
Exported PDU (linktype 252) for the VCDUs and Ethernet for three UDP
datagrams to port 10000, which need "-d udp.port==10000,vcdu".  Packets are
built from scratch with struct; addresses are from 192.0.2.0/24.

Usage: mkvcdu.py <output directory>

Writes:
  vcdu-coverage.pcapng            every SMEX flag value, CCSDS channels (fill,
                                  continuation, one and several packets) and
                                  bitstream channels (data, anomaly, fill)
  vcdu-coverage-malformed.pcapng  a pointer too close to the end, the largest
                                  Julian day, cut-short frames
"""

# (frame sync, data direction, data class) names are only value strings.


def smex(gsc=1, version=0, framelen=100, rs_en=0, rs_err=0, crc_en=0, crc_err=0,
         mcs_en=0, mcs_err=0, inv=0, sync=2, ddir=0, dclass=2, pb5=1, jday=1,
         secs=0, msec=0):
    flags = (rs_en << 7) | (rs_err << 6) | (crc_en << 5) | (crc_err << 4) | \
        (mcs_en << 3) | (mcs_err << 2) | inv
    b = struct.pack('>QH', gsc, 0)
    b += struct.pack('>H', (version << 14) | framelen)
    b += bytes([flags, (sync << 6) | (ddir << 5) | dclass])
    b += struct.pack('>I', (pb5 << 31) | (jday << 17) | secs)
    b += struct.pack('>H', msec << 6)
    assert len(b) == 20
    return b


def vcduhdr(version=0, spid=0x35, vcid=1, seq=1, replay=0):
    return struct.pack('>H', (version << 14) | (spid << 6) | vcid) + struct.pack('>I', seq)[1:] \
        + bytes([replay])


def ccsds_pkt(apid, total, seq=1, typ=0, sec=1):
    """A CCSDS space packet of `total` octets with a secondary header."""
    first = (typ << 12) | (sec << 11) | apid
    hdr = struct.pack('>HHH', first, 0xc000 | seq, total - 7)
    sechdr = struct.pack('>IB', 0x12345678, 0x40) + bytes([0x00]) + b'\0\0\0\0'
    return (hdr + sechdr + bytes(range(total - 16)))[:total]


def vcdu(mpdu, body, sm=None, vh=None, size=None):
    d = (sm or smex()) + (vh or vcduhdr()) + struct.pack('>H', mpdu) + body
    if size and len(d) < size:
        d += b'\0' * (size - len(d))
    return d


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    F = []

    def add(d):
        F.append((1, exppdu('vcdu', d)))

    # 1-2: reproducer of the fix (version 1, Julian day 1, CCSDS channel, all fill)
    add(smex(framelen=100, jday=1) + vcduhdr(version=1, vcid=1) + struct.pack('>H', 0x7fe) + b'\0' * 16)
    # (the same frame the review used: version 1 shows as 1, day 1 as 1996/283... )
    add(vcdu(0x7ff, b'\xaa' * 40, vh=vcduhdr(version=2, vcid=2)))      # continuation
    add(vcdu(0x7fe, b'\xff' * 40, vh=vcduhdr(version=3, vcid=3)))      # all fill
    # FHP too close to the end of the VCDU (a warning)
    add(vcdu(0x0050, b'\x01' * 20))
    # bitstream channels: default 12-19 and 63; LBP all data, anomaly, all fill, a pointer
    for vc, lbp in ((12, 0x3fff), (13, 0x07ff), (14, 0x3ffe), (15, 0x0100), (19, 0x0000), (63, 0x3fff)):
        add(vcdu(lbp, b'\x55' * 40, vh=vcduhdr(vcid=vc, seq=vc)))
    # a channel that is not a bitstream channel with the same pointers
    add(vcdu(0x3fff & 0x7ff, b'\x55' * 40, vh=vcduhdr(vcid=11)))
    add(vcdu(0x3ffe & 0x7ff, b'\x55' * 40, vh=vcduhdr(vcid=20)))
    # SMEX header: every flag, data inversion 0-3, sync 0-3, direction, class
    for inv in range(4):
        add(vcdu(0x7fe, b'\0' * 20, sm=smex(inv=inv, sync=inv, ddir=inv & 1, dclass=inv + 1, rs_en=inv & 1,
                                            crc_en=(inv >> 1) & 1)))
    add(vcdu(0x7fe, b'\0' * 20, sm=smex(rs_en=1, rs_err=1, crc_en=1, crc_err=1, mcs_en=1, mcs_err=1,
                                        inv=3, sync=3, ddir=1, dclass=4, pb5=0)))
    add(vcdu(0x7fe, b'\0' * 20, sm=smex(rs_en=0, rs_err=1, crc_en=0, crc_err=1, mcs_en=0, mcs_err=1,
                                        dclass=0, pb5=0)))
    add(vcdu(0x7fe, b'\0' * 20, sm=smex(dclass=3)))
    add(vcdu(0x7fe, b'\0' * 20, sm=smex(dclass=31, version=3, framelen=0x3fff)))
    # ground receipt time: day 0, a leap year, the largest day that stays below 2038
    for jday, secs, msec in ((0, 0, 0), (1, 86399, 999), (200, 3600, 500), (366, 12345, 1), (3000, 43200, 250),
                             (9000, 1, 1), (12000, 131071, 999)):
        add(vcdu(0x7fe, b'\0' * 20, sm=smex(jday=jday, secs=secs, msec=msec, gsc=jday * 1000 + 7)))
    # spacecraft ids and VCDU sequence numbers, the replay flag
    for sp, vc, seq, rp in ((0x00, 0, 0, 0), (0xff, 63, 0xffffff, 0x80), (0x35, 5, 123456, 1)):
        add(vcdu(0x7fe, b'\0' * 12, vh=vcduhdr(spid=sp, vcid=vc, seq=seq, replay=rp)))
    # a VCDU that is just the headers and the pointer
    add(vcdu(0x7fe, b''))
    # UDP datagrams to port 10000 (Decode As): a CCSDS channel, a bitstream channel, fill
    k = 0
    for mp, vc, body in ((0x0020, 1, b'\0' * 30), (0x3fff, 12, b'\x42' * 30),
                         (0x7fe, 2, b'\0' * 20)):
        k += 1
        d = vcdu(mp, body, vh=vcduhdr(vcid=vc))
        F.append((0, ether(ip4(17, '192.0.2.10', '192.0.2.11', udp(40000 + k, 10000, d), 100 + k))))
    pcapng(os.path.join(out, 'vcdu-coverage.pcapng'), [1, 252], F)

    # malformed: an enormous Julian day (signed overflow in the time), cut-short frames
    F = []
    # CCSDS packets: FHP 0 with one packet that fills the unit; the loop calls the
    # CCSDS dissector once more past the last packet (an empty tvb: malformed)
    p = ccsds_pkt(0x123, 60)
    add(vcdu(0x0000, p + b'\0' * 8, size=0))
    # a packet that continues in the next VCDU: the CCSDS length error
    # FHP 0 with two packets
    add(vcdu(0x0000, ccsds_pkt(0x124, 40) + ccsds_pkt(0x125, 60, seq=2) + b'\0' * 40))
    # a continuation fragment first, packet at FHP 10
    add(vcdu(0x000a, b'\xee' * 10 + ccsds_pkt(0x126, 50, typ=1) + b'\0' * 60))
    # three packets, type 1 (payload) and type 0, two APIDs
    add(vcdu(0x0000, ccsds_pkt(0x127, 30, typ=1) + ccsds_pkt(0x128, 30) + ccsds_pkt(0x129, 30, typ=1) + b'\0' * 60))
    add(vcdu(0x0000, ccsds_pkt(0x400, 120)[:60]))
    add(vcdu(0x7fe, b'\0' * 20, sm=smex(jday=16383, secs=131071, msec=1023)))
    add(vcdu(0x7fe, b'\0' * 20, sm=smex(jday=15000, secs=1, msec=1000)))
    add(vcdu(0x7fe, b'\0' * 20, sm=smex(jday=16383)))
    add(smex()[:19])
    add(smex() + vcduhdr()[:4])
    add(smex() + vcduhdr())
    add(smex() + vcduhdr() + b'\x00')
    # FHP pointing outside the frame: the CCSDS packet is cut off
    add(vcdu(0x0000, ccsds_pkt(0x300, 200)[:40], size=0))
    add(vcdu(0x0000, ccsds_pkt(0x301, 40)[:30] + b'\0' * 40))
    # a packet whose length is shorter than its headers
    add(vcdu(0x0000, struct.pack('>HHH', 0x0800 | 0x302, 0xc001, 2) + b'\0' * 60))
    pcapng(os.path.join(out, 'vcdu-coverage-malformed.pcapng'), [1, 252], F)


main()
