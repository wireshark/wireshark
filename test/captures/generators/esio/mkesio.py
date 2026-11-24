#!/usr/bin/env python3
# Generates test/captures/esio_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build the synthetic ESIO (SAIA Ether-S-I/O) coverage captures.
# Usage: mkesio.py <outdir>
# ESIO runs over UDP port 6060, registered by default.
import os
import struct
import sys

def write_pcap(fn, frames, linktype=1):
    with open(fn, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(fr), len(fr)) + fr)

def ip_udp(payload, sport, dport, src, dst):
    s = bytes(int(x) for x in src.split(".")); d = bytes(int(x) for x in dst.split("."))
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, s, d)
    return ip + udp

def eth(payload, src=1, dst=2):
    return (bytes.fromhex("0200000000%02x" % dst) + bytes.fromhex("0200000000%02x" % src)
            + b"\x08\x00" + payload)

PLC = "192.0.2.10"   # master (PLC)
RIO = "192.0.2.20"   # remote I/O station

def udp(pl, frm=PLC, to=RIO):
    return eth(ip_udp(pl, 6060, 6060, frm, to), 1 if frm == PLC else 2, 2 if frm == PLC else 1)

def hdr(tlg_type, tid, body_len, version=0):
    return b"ESIO" + struct.pack(">HHHH", tlg_type, version, 12 + body_len, tid)

def transfer(tlg_id, src, xfers, flags=0, nbr=None):
    body = struct.pack(">IIBB", tlg_id, src, len(xfers) if nbr is None else nbr, flags)
    for xid, dest, data in xfers:
        body += struct.pack(">IIH", xid, dest, len(data)) + data
    return body

def status(src, rio_sts, lost, diag, flags, sts_type=1, size=8):
    return struct.pack(">HHIBBBB", sts_type, size, src, rio_sts, lost, diag, flags)

def main(out):
    f = []
    # 1: data transfer telegram, one transfer of 4 data bytes
    b = transfer(1, 1, [(10, 20, bytes([1, 2, 3, 4]))])
    f.append(udp(hdr(1, 1, len(b)) + b))
    # 2: data transfer telegram with three transfers (the reproducer of
    #    "ESIO: Use a separate counter for the data bytes of a transfer";
    #    before the fix only the first transfer was decoded)
    b = transfer(0x11, 0x22, [(100 + k, 200 + k, bytes([0xA0 + k] * 2)) for k in range(3)])
    f.append(udp(hdr(1, 7, len(b)) + b))
    # 3: data transfer telegram, two transfers of different lengths, one empty, flags set
    b = transfer(3, 5, [(30, 40, b""), (31, 41, bytes(range(1, 9)))], flags=0x81)
    f.append(udp(hdr(1, 3, len(b)) + b))
    # 4: data transfer telegram with no transfers (padded so that the Info
    #    column's destination ID at offset 26 exists)
    b = transfer(4, 6, []) + b"\x00" * 8
    f.append(udp(hdr(1, 4, len(b)) + b))
    # 5: status telegram from the RIO, nothing lost
    b = status(20, 1, 0, 0, 0x00)
    f.append(udp(hdr(2, 5, len(b)) + b, RIO, PLC))
    # 6: status telegram, 3 telegrams lost (a note expert info), diag and flags
    b = status(20, 2, 3, 0x55, 0xA5)
    f.append(udp(hdr(2, 6, len(b)) + b, RIO, PLC))
    # 7: status telegram of status type 0 (None)
    b = status(21, 0, 0, 0, 0, sts_type=0, size=0)
    f.append(udp(hdr(2, 7, len(b)) + b, RIO, PLC))
    # 8: telegram type 0 (reserved): header only, plus padding
    f.append(udp(hdr(0, 8, 8) + b"\x00" * 8))
    # 9-14: not ESIO, the dissector rejects them (shown as UDP data)
    good = hdr(2, 9, 12) + status(20, 1, 0, 0, 0)
    f.append(udp(good[:19]))                          # 9: shorter than 20
    f.append(udp(b"ESIX" + good[4:]))                 # 10: wrong magic
    f.append(udp(good[:4] + b"\x01" + good[5:]))      # 11: type high byte
    f.append(udp(good[:5] + b"\x03" + good[6:]))      # 12: type 3
    f.append(udp(good[:6] + b"\x01" + good[7:]))      # 13: version high byte
    f.append(udp(good[:7] + b"\x01" + good[8:]))      # 14: version 1
    write_pcap(os.path.join(out, "esio-coverage.pcap"), f)

    m = []
    # 1: transfer whose data length runs past the end of the packet
    b = transfer(1, 1, [(10, 20, b"\x01\x02")])
    b = b[:-4] + struct.pack(">H", 200) + b"\x01\x02"
    m.append(udp(hdr(1, 1, len(b)) + b))
    # 2: transfer count 5 with only one transfer present
    b = transfer(2, 2, [(10, 20, b"\x01")], nbr=5)
    m.append(udp(hdr(1, 2, len(b)) + b))
    # 3: status telegram cut after 20 octets
    m.append(udp((hdr(2, 3, 12) + status(20, 1, 1, 0, 0))[:20], RIO, PLC))
    # 4: transfer telegram of exactly 20 octets (Info column reads beyond)
    m.append(udp(hdr(1, 4, 8) + struct.pack(">II", 1, 2)))
    write_pcap(os.path.join(out, "esio-coverage-malformed.pcap"), m)

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
