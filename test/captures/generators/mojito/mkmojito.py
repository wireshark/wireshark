#!/usr/bin/env python3
# Generates test/captures/mojito_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Mojito coverage captures.  Usage: mkmojito.py <outdir> [-v]
Mojito (the LimeWire DHT) runs over UDP on any port; its UDP heuristic is
enabled by default, so no Decode As is needed.  The messages use a Gnutella
header (message ID, function 68, version, little endian payload length).
Frames that the heuristic rejects (payload length below the header, as the
fix allows) are decoded with Decode As in runcov.sh and the test.
Writes mojito-coverage.pcap and mojito-coverage-malformed.pcap."""
import struct
import sys
import os

def pcap(name, pkts):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            wire = len(p)
            if isinstance(p, tuple):
                p, wire = p
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), wire))
            f.write(p)

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

SRC = bytes([192, 0, 2, 1]); DST = bytes([192, 0, 2, 2])
ipid = [0]
PORT = 7500
def frame(payload, sport=PORT, dport=PORT):
    ln = 8 + len(payload)
    ph = SRC + DST + struct.pack('>BBH', 0, 17, ln)
    u = struct.pack('>HHHH', sport, dport, ln, 0)
    u = struct.pack('>HHHH', sport, dport, ln, csum(ph + u + payload) or 0xffff) + payload
    ipid[0] += 1
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), ipid[0], 0, 64, 17, 0, SRC, DST)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + h + u

def addr4(ip=(10, 1, 2, 3), port=6346):
    return bytes([4]) + bytes(ip) + struct.pack('>H', port)
def addr6(port=6347):
    return bytes([16]) + bytes.fromhex('20010db8000000000000000000000001') + struct.pack('>H', port)

KUID = bytes(range(20))
def kuid(n): return bytes([n]) * 20

def contact(vendor=b'LIME', ver=(1, 2), k=KUID, addr=None):
    return vendor + bytes(ver) + k + (addr if addr is not None else addr4())

def msg(opcode, body=b'', *, origaddr=None, plen=None, mid=bytes(range(16)), fdht=68,
        flags=0, inst=7, ext=0):
    hdr_rest = (bytes([opcode]) + contact(addr=origaddr if origaddr is not None else addr4())
                + bytes([inst, flags]) + struct.pack('>H', ext))
    payload = hdr_rest + body
    n = len(payload) if plen is None else plen
    return mid + bytes([fdht]) + bytes([1, 0]) + struct.pack('<I', n) + payload

def dhtvalue(vtype=b'TEST', ver=(1, 0), value=b'hello', creator=None):
    return (contact(k=kuid(9), addr=creator) + kuid(0x33) + vtype + bytes(ver)
            + struct.pack('>H', len(value)) + value)

def main():
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    pk, marks = [], []
    def add(p, label):
        pk.append(p); marks.append((len(pk), label))
    add(frame(msg(1)), 'PING REQUEST (no opcode data)')
    add(frame(msg(1, b'\x00\x00', flags=0x03, inst=0)), 'PING REQUEST with 2 octets of data, shutdown and firewalled flags')
    add(frame(msg(2, addr4((192, 0, 2, 7), 4000) + bytes([1, 0x20]))), 'PING RESPONSE: external address IPv4, DHT size 1 octet')
    add(frame(msg(2, addr6() + bytes([2, 0x01, 0x00]))), 'PING RESPONSE: external address IPv6, DHT size 2 octets')
    add(frame(msg(2, addr4() + bytes([3, 1, 2, 3]))), 'PING RESPONSE: DHT size 3 octets')
    add(frame(msg(2, addr4() + bytes([4, 0, 1, 0, 0]))), 'PING RESPONSE: DHT size 4 octets')
    add(frame(msg(3, bytes([4]) + b'\xaa\xbb\xcc\xdd' + bytes([2]) + dhtvalue() + dhtvalue(b'LONG', (2, 1), b'x' * 30, addr6()))),
        'STORE REQUEST: security token and 2 DHT values (IPv4 and IPv6 creator)')
    add(frame(msg(3, bytes([0]) + bytes([0]))), 'STORE REQUEST: no token, no values')
    add(frame(msg(4, bytes([2]) + kuid(1) + kuid(2) + struct.pack('>HH', 1, 2) + b'ok'
                  + kuid(3) + kuid(4) + struct.pack('>HH', 2, 0))), 'STORE RESPONSE: 2 status codes (primary and secondary KUID)')
    add(frame(msg(4, bytes([0]))), 'STORE RESPONSE: no status codes')
    add(frame(msg(5, KUID)), 'FIND NODE REQUEST')
    add(frame(msg(6, bytes([3]) + b'tok' + bytes([2]) + contact(b'LIME', (1, 0), kuid(5), addr4((10, 0, 0, 5), 1000))
                  + contact(b'GTKG', (2, 3), kuid(6), addr6(2000)))), 'FIND NODE RESPONSE: 2 contacts (IPv4 and IPv6)')
    add(frame(msg(6, bytes([0]) + bytes([0]))), 'FIND NODE RESPONSE: no token, no contacts')
    add(frame(msg(7, KUID + bytes([2]) + kuid(7) + kuid(8) + b'TEST')), 'FIND VALUE REQUEST: 2 secondary KUIDs')
    add(frame(msg(7, KUID + bytes([0]) + b'ANY!')), 'FIND VALUE REQUEST: no secondary KUIDs')
    add(frame(msg(8, struct.pack('>I', 12) + bytes([2]) + dhtvalue() + dhtvalue(b'BIGV', (3, 3), b'y' * 20)
                  + bytes([2]) + kuid(11) + kuid(12))), 'FIND VALUE RESPONSE: request load, 2 DHT values, 2 secondary KUIDs')
    add(frame(msg(8, struct.pack('>I', 0) + bytes([0]) + bytes([0]))), 'FIND VALUE RESPONSE: empty')
    add(frame(msg(9, b'\x01\x02\x03')), 'STATS REQUEST (DEPRECATED) with data')
    add(frame(msg(10)), 'STATS RESPONSE (DEPRECATED) without data')
    add(frame(msg(10, b'stats-data' * 3)), 'STATS RESPONSE (DEPRECATED) with data')
    add(frame(msg(77, b'\xde\xad\xbe\xef')), 'unknown opcode 77 with data')
    add(frame(msg(77)), 'unknown opcode 77 without data')
    add(frame(msg(1), 40001, 40002), 'PING REQUEST on other ports (heuristic)')
    # Payload length below the header: only reachable by Decode As (the
    # heuristic needs length + 23 == frame length).  This is the fix for
    # "Mojito: Do not wrap the opcode data length".
    f = msg(1, plen=10)
    add(frame(f, 9777, 9777), 'REPRODUCER (length wrap): payload length 10, Decode As udp.port==9777,mojito')
    f = msg(1, plen=0)
    add(frame(f, 9778, 9778), 'payload length 0, Decode As udp.port==9778,mojito (same fix, zero)')
    # heuristic needs 61 captured octets: a frame truncated to 60 octets of UDP payload
    full = msg(1)
    add(frame((full[:60]), PORT, PORT), 'truncated to 60 octets: not decoded by the heuristic')
    pcap(os.path.join(out, 'mojito-coverage.pcap'), pk)
    if verbose:
        for n, l in marks:
            print(n, l)
        print(len(pk), 'frames')

    pk, marks = [], []
    add(frame(msg(2, addr4() + bytes([5, 1, 2, 3, 4, 5]))), 'PING RESPONSE: DHT size 5 octets (unsupported big integer)')
    add(frame(msg(2, addr4() + bytes([0]))), 'PING RESPONSE: DHT size 0 octets')
    add(frame(msg(2, bytes([7]) + b'\x00' * 8)), 'PING RESPONSE: unknown address version')
    add(frame(msg(3, bytes([1, 0xaa, 1]) + contact(addr=bytes([9, 1, 2, 3, 4, 0, 1])) )), 'STORE REQUEST: contact with unknown address version')
    add(frame(msg(3, bytes([0, 1]) + dhtvalue()[:60])), 'STORE REQUEST: DHT value cut short')
    add(frame(msg(4, bytes([1]) + kuid(1) + b'\x00\x01\x00')), 'STORE RESPONSE: primary KUID only (no secondary, 3 octets left)')
    add(frame(msg(4, bytes([1]) + kuid(1) + struct.pack('>HH', 1, 0))), 'STORE RESPONSE: status code without secondary KUID (read as secondary)')
    add(frame(msg(6, bytes([0, 1]) + contact(addr=bytes([3, 1, 2, 3, 4, 0, 1])))), 'FIND NODE RESPONSE: contact with unknown address version')
    add(frame(msg(6, bytes([0, 5]) + contact())), 'FIND NODE RESPONSE: contact count larger than the data')
    add(frame(msg(7, KUID + bytes([200]))), 'FIND VALUE REQUEST: 200 secondary KUIDs claimed')
    add(frame(msg(8, struct.pack('>I', 1) + bytes([1]) + dhtvalue(addr6())[:40])), 'FIND VALUE RESPONSE: DHT value cut short')
    add(frame(msg(8, struct.pack('>I', 1) + bytes([1]) + dhtvalue(creator=bytes([9, 1, 2, 3, 4, 0, 1])))), 'FIND VALUE RESPONSE: DHT value whose creator has an unknown address version')
    add(frame(msg(1, origaddr=addr6())), 'PING REQUEST with an IPv6 originating contact (header is 12 octets longer than 38)')
    add(frame(msg(1, origaddr=bytes([9, 1, 2, 3, 4, 0, 1]))), 'originating contact with an unknown address version')
    add(frame(msg(5, KUID, plen=10), 9777, 9777), 'FIND NODE REQUEST with payload length 10 (Decode As)')
    add(frame(msg(2, plen=1), 9777, 9777), 'PING RESPONSE with payload length 1 (Decode As)')
    add(frame(msg(1)[:30], 9777, 9777), 'cut inside the header (Decode As)')
    add(frame(msg(1, plen=0xFFFFFFF0) + b'', 9777, 9777), 'payload length 0xFFFFFFF0 (Decode As)')
    add(frame(msg(1, plen=0xFFFFFFFF), 9779, 9779), 'payload length 0xFFFFFFFF (heuristic: 64-bit compare)')
    pcap(os.path.join(out, 'mojito-coverage-malformed.pcap'), pk)
    if verbose:
        for n, l in marks:
            print('M', n, l)
        print(len(pk), 'malformed frames')

main()
