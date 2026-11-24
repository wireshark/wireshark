#!/usr/bin/env python3
# Generates test/captures/etv_coverage.pcap.gz, etv_short_section.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the ETV (ETV-AM DII/DDB section) coverage captures.
Usage: mketv.py <outdir>.  Everything is synthetic.
Ethernet/IPv4/UDP carrying MPEG-2 TS packets (reached by the default
"MP2T over UDP" heuristic); the TS payload is a private section with
table id 0xE3 (DII) or 0xE4 (DDB) which mpeg_sect hands to ETV; ETV
passes the remainder to the DSM-CC section dissector."""
import struct
import sys
import os

def crc32_mpeg2(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04c11db7) & 0xffffffff if crc & 0x80000000 else (crc << 1) & 0xffffffff
    return crc

def write_pcap(name, pkts):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def ip_sum(h):
    s = sum(struct.unpack('>10H', h))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def udp_frame(payload, sport=40000, dport=5004):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([239, 1, 1, 1]))
    ip = ip[:10] + struct.pack('>H', ip_sum(ip)) + ip[12:]
    eth = bytes.fromhex('01005e010101') + bytes.fromhex('020000000001') + b'\x08\x00'
    return eth + ip + udp

cc = {}
def ts_packets(pid, section, first_pointer=0):
    """Split section bytes into TS packets of one PID (pusi on the first)."""
    out = []
    data = bytes([first_pointer]) + section
    pusi = True
    while data:
        chunk, data = data[:184], data[184:]
        chunk += b'\xff' * (184 - len(chunk))
        c = cc.get(pid, 0); cc[pid] = (c + 1) & 15
        hdr = struct.pack('>BHB', 0x47, (0x4000 if pusi else 0) | pid, 0x10 | c)
        out.append(hdr + chunk)
        pusi = False
    return out

def etv_section(tid, filt, payload, reserved2=0, ssi=0, rsv=4, length=None, crc_ok=True):
    """payload is the inner (DSM-CC section) bytes, ending in 4 octets
    that ETV treats as part of the inner tvb."""
    body = struct.pack('>HB', filt, reserved2) + payload
    sl = len(body) + 4 + 0 if length is None else length
    # section_length counts everything after the length field, incl. CRC
    sl_real = 3 + len(body) + 4 - 3 + 0
    if length is None:
        sl = len(body) + 4 + 0
    hdr = struct.pack('>BH', tid, (ssi << 15) | (rsv << 12) | sl)
    sec = hdr + body
    crc = crc32_mpeg2(sec)
    if not crc_ok:
        crc ^= 0x1234
    return sec + struct.pack('>I', crc)

def dsmcc_section(tid, msg, ssi=0):
    sl = len(msg) + 9
    hdr = struct.pack('>BHHBBB', tid, (ssi << 15) | 0x3000 | sl, 0x0001, 0xc1, 0, 0)
    return hdr + msg + struct.pack('>I', 0xdeadbeef)

def dsmcc_hdr(msgid, txid, adapt=b'', download=False):
    return struct.pack('>BBHIBBH', 0x11, 3, msgid, txid, 0xff, len(adapt), 0) + adapt

def dii(modules=1, info=b'/a/b', priv=b'auth', dlid=0x1234):
    m = b''
    for i in range(modules):
        m += struct.pack('>HIBB', i + 1, 1000 * (i + 1), 1, len(info)) + info
    body = struct.pack('>IHBBII', dlid, 4066, 1, 0, 0x100, 0x200) + struct.pack('>H', 0) \
        + struct.pack('>H', modules) + m + struct.pack('>H', len(priv)) + priv
    return dsmcc_hdr(0x1002, 0x80000001) + body

def ddb(data, module=1, block=0):
    return dsmcc_hdr(0x1003, 0x1234) + struct.pack('>HBBH', module, 1, 0xff, block) + data

def dii_section(**kw):
    return etv_section(0xe3, 0xfbfb, dsmcc_section(0x3c, dii(**kw.pop('d', {}))), **kw)

def ddb_section(data, filt=1, tid=0xe4, **kw):
    return etv_section(tid, filt, dsmcc_section(0x3c, ddb(data)), **kw)

def frame(pid, sections, pointer=0):
    ts = []
    for s in sections:
        ts += ts_packets(pid, s)
    return udp_frame(b''.join(ts))

main = []
# 1 DII, 1 module; 2 DII with 3 modules; 3 DII with an adaptation header
main.append(frame(0x100, [dii_section()]))
main.append(frame(0x100, [dii_section(d=dict(modules=3, info=b'/mod', priv=b'etv:'))]))
main.append(frame(0x100, [etv_section(0xe3, 0xfbfb, dsmcc_section(0x3c, dsmcc_hdr(0x1001, 5, adapt=b'\x01\xff\x00\x01\x00\x02\xab\xcd') + dii()[12:]))]))
# DII, no private data, no module info
main.append(frame(0x100, [dii_section(d=dict(modules=0, info=b'', priv=b''))]))
# 5 DDB, filter 1; 6 DDB filter 0xfbef; 7 DDB filter 0x1234
main.append(frame(0x101, [ddb_section(bytes(range(32)), filt=1)]))
main.append(frame(0x101, [ddb_section(b'\xaa' * 40, filt=0xfbef)]))
main.append(frame(0x101, [ddb_section(b'', filt=0x1234)]))
# 8 DDB spread over 4 TS packets in one frame (reassembly in mp2t)
main.append(frame(0x102, [ddb_section(bytes(i & 255 for i in range(600)), filt=2)]))
# 9,10 section split across two UDP frames
big = ddb_section(bytes((i * 7) & 255 for i in range(380)), filt=3)
pk = ts_packets(0x103, big)
main.append(udp_frame(pk[0]))
main.append(udp_frame(b''.join(pk[1:])))
# 11 two sections (DII + DDB) in one TS packet sequence on different PIDs
main.append(udp_frame(b''.join(ts_packets(0x104, dii_section()) + ts_packets(0x105, ddb_section(b'xyz', filt=9)))))
# 12 DDB with maximum length that passes the 1021 limit
main.append(frame(0x106, [ddb_section(bytes(i & 255 for i in range(1021 - 7 - 9 - 4 - 4 - 12 - 6 - 0)), filt=4)]))
# 13 DSM-CC with other table id (nothing dissected inside), 14 user-network type 2 (session)
main.append(frame(0x107, [etv_section(0xe4, 5, dsmcc_section(0x3a, b'\x01\x02\x03\x04'))]))
main.append(frame(0x107, [etv_section(0xe4, 6, dsmcc_section(0x3b, struct.pack('>BBH', 0x11, 1, 0) + b'\0' * 8))]))

bad = []
# 1-3 reproducers: section_length 0, 3, 6 (and 7 as control)
for sl in (0, 3, 6):
    for tid in (0xe3, 0xe4):
        body = struct.pack('>BH', tid, 0x4000 | sl) + (struct.pack('>HB', 0xfbfb if tid == 0xe3 else 1, 0) + bytes(range(1, 21)))[:sl]
        bad.append(frame(0x200, [body]))
# control: section_length 7 (an empty DSM-CC part; DSM-CC throws)
bad.append(frame(0x200, [struct.pack('>BH', 0xe3, 0x4007) + struct.pack('>HB', 0xfbfb, 0) + b'\0' * 4]))
# ssi set, reserved bits wrong, both protocols
bad.append(frame(0x201, [dii_section(ssi=1)]))
bad.append(frame(0x201, [ddb_section(b'abcd', ssi=1)]))
bad.append(frame(0x201, [dii_section(rsv=0)]))
bad.append(frame(0x201, [ddb_section(b'abcd', rsv=7)]))
# wrong filter info
bad.append(frame(0x202, [etv_section(0xe3, 0x1234, dsmcc_section(0x3c, dii()))]))
bad.append(frame(0x202, [ddb_section(b'abcd', filt=0)]))
bad.append(frame(0x202, [ddb_section(b'abcd', filt=0xfbf0)]))
bad.append(frame(0x202, [ddb_section(b'abcd', filt=0xffff)]))
# reserved2 non-zero
bad.append(frame(0x203, [etv_section(0xe3, 0xfbfb, dsmcc_section(0x3c, dii()), reserved2=1)]))
bad.append(frame(0x203, [ddb_section(b'abcd', reserved2=0x80)]))
# bad CRC
bad.append(frame(0x204, [ddb_section(b'abcd', crc_ok=False)]))
# section_length above 1021 (spread over packets)
bad.append(frame(0x205, [ddb_section(bytes(1100), filt=7)]))
bad.append(frame(0x205, [etv_section(0xe3, 0xfbfb, dsmcc_section(0x3c, dii(priv=bytes(1050))))]))
# section longer than the data in a TS packet (truncated section in last packet)
pk = ts_packets(0x206, ddb_section(bytes(400), filt=8))
bad.append(udp_frame(pk[0]))
# DSM-CC header claims more than present
bad.append(frame(0x207, [etv_section(0xe4, 5, dsmcc_section(0x3c, dsmcc_hdr(0x1003, 1)[:10]))]))

out = sys.argv[1]
write_pcap(os.path.join(out, 'etv-coverage.pcap'), main)
write_pcap(os.path.join(out, 'etv-coverage-malformed.pcap'), bad)
print(len(main), len(bad))
# Small capture with only the reproducers of "ETV: Reject sections shorter
# than the fixed header" (the first 6 frames of the malformed capture).
write_pcap(os.path.join(out, 'etv-short-section.pcap'), bad[:6])
