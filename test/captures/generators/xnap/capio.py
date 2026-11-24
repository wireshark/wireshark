# Helper module for the xnap capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""pcap/SCTP/IP helpers (shared by mkx2ap.py and mkxnap.py)."""
import struct

def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return (~crc) & 0xffffffff

def sctp_packet(chunks, sport, dport, vtag):
    body = b''.join(chunks)
    hdr = struct.pack('>HHII', sport, dport, vtag, 0)
    c = crc32c(hdr + body)
    return struct.pack('>HHI', sport, dport, vtag) + struct.pack('<I', c) + body

def data_chunk(payload, tsn, ppid, sid=0, ssn=0, flags=3):
    clen = 16 + len(payload)
    c = struct.pack('>BBHIHHI', 0, flags, clen, tsn, sid, ssn, ppid) + payload
    return c + b'\x00' * ((4 - clen % 4) % 4)

def init_chunk(ctype, tag, tsn, a_rwnd=65535, ostreams=2, istreams=2):
    # INIT (1) / INIT-ACK (2): params omitted except none; INIT-ACK needs a state cookie
    p = struct.pack('>IIHHI', tag, a_rwnd, ostreams, istreams, tsn)
    if ctype == 2:
        p += struct.pack('>HH', 7, 8) + b'COOK'
    return struct.pack('>BBH', ctype, 0, 4 + len(p)) + p

def simple_chunk(ctype, body=b'', flags=0):
    return struct.pack('>BBH', ctype, flags, 4 + len(body)) + body

def ipv4(payload, src, dst, proto=132, ident=1):
    s = bytes(map(int, src.split('.'))); d = bytes(map(int, dst.split('.')))
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident & 0xffff, 0, 64, proto, 0, s, d)
    c = sum(struct.unpack('>10H', h)); c = (c & 0xffff) + (c >> 16); c = (c & 0xffff) + (c >> 16)
    return h[:10] + struct.pack('>H', ~c & 0xffff) + h[12:] + payload

def eth(payload, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    return dst + src + b'\x08\x00' + payload

def write_pcap(fn, pkts, t0=1700000000):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', t0 + i // 1000, (i % 1000) * 1000, len(p), len(p)))
            f.write(p)

def lenenc(n):
    if n < 128:
        return bytes([n])
    assert n < 16384, n
    return struct.pack('>H', 0x8000 | n)

def pdu(kind, proc, crit, body):
    """APER X2AP/XnAP-PDU: kind 0 initiating, 1 successful, 2 unsuccessful"""
    c = {'reject': 0, 'ignore': 1, 'notify': 2}[crit]
    return bytes([kind << 5, proc, c << 6]) + lenenc(len(body)) + body
