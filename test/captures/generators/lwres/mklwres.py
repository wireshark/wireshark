#!/usr/bin/env python3
# Generates test/captures/lwres_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic lightweight resolver (lwres) coverage captures for
epan/dissectors/packet-lwres.c.  lwres has no default port (it needs
Decode As on a UDP port, 921 is what lwresd used), so the captures use UDP
port 921 on the loopback addresses 127.0.0.1.  Every packet is built with
struct; nothing comes from a real network.

Usage: mklwres.py <outdir>
Writes lwres-coverage.pcap (main) and lwres-coverage-malformed.pcap
(Ethernet link type).  Dissect with -d udp.port==921,lwres.
"""
import os
import struct
import sys

PORT = 921
RESPONSE = 0x0001
NOOP, ADDRSBYNAME, NAMEBYADDR, RDATABYNAME = 0, 0x00010001, 0x00010002, 0x00010003
T_A, T_NS, T_MX, T_SRV = 1, 2, 15, 33


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


IPID = [0]


def udp_frame(payload, response=False, sport=40000):
    src, dst = ((127, 0, 0, 1), (127, 0, 0, 1))
    s, d = (sport, PORT)
    if response:
        s, d = d, s
    u = struct.pack('>HHHH', s, d, 8 + len(payload), 0) + payload
    IPID[0] += 1
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), IPID[0], 0x4000, 64, 17, 0, bytes(src), bytes(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    mac = bytes(6)
    return mac + mac + b'\x08\x00' + h + u


def pkt(opcode, body, response=False, result=0, serial=0x1234, version=0, authtype=0, authlen=0,
        recvlen=4096, length=None):
    total = 28 + len(body)
    h = struct.pack('>IHHIIIIHH', total if length is None else length, version,
                    RESPONSE if response else 0, serial, opcode, result, recvlen, authtype, authlen)
    return h + body


def name(n):
    return n.encode() + b'\0'


def dns(n):
    out = b''
    for label in n.split('.'):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b'\0'


# The dissector adds the address string with the length of the text ("192.0.2.10", 10 octets) to
# a 4 octet address, and the "getnamebyaddr parameters" subtree with a length that includes the
# 28 octets of the header: frames that end in those items need slack after them to decode.
SLACK12 = bytes(12)
SLACK28 = bytes(28)


def main_frames():
    F = []

    def add(p, response=False):
        F.append(udp_frame(p, response))

    # Noop request / response (data of 4 octets after the length)
    add(pkt(NOOP, struct.pack('>H', 4) + b'ping' + b'\0\0'))
    add(pkt(NOOP, struct.pack('>H', 4) + b'pong' + b'\0\0', response=True), True)
    # getaddrsbyname: request, response with aliases and addresses
    add(pkt(ADDRSBYNAME, struct.pack('>IIH', 0, 3, 11) + name('example.com')))
    body = struct.pack('>IHHH', 0, 2, 3, 11) + name('example.com')
    for a in ('www.example.com', 'ftp.example.com'):
        body += struct.pack('>H', len(a)) + name(a)
    for ip in ((192, 0, 2, 10), (192, 0, 2, 11), (198, 51, 100, 7)):
        body += struct.pack('>IH', 2, 4) + bytes(ip)
    add(pkt(ADDRSBYNAME, body + SLACK12, response=True), True)
    # no aliases, no addresses
    add(pkt(ADDRSBYNAME, struct.pack('>IHHH', 0, 0, 0, 7) + name('lonely'), response=True), True)
    # getnamebyaddr: request, response with aliases
    add(pkt(NAMEBYADDR, struct.pack('>IIH', 0, 2, 4) + bytes((192, 0, 2, 10)) + SLACK28))
    body = struct.pack('>IHH', 0, 2, 11) + b'example.com'
    for a in ('a.example.com', 'b.example.com'):
        body += struct.pack('>H', len(a)) + name(a)
    add(pkt(NAMEBYADDR, body, response=True), True)
    add(pkt(NAMEBYADDR, struct.pack('>IHH', 0, 0, 4) + b'host', response=True), True)
    # getrdatabyname request for every type
    for t in (T_A, T_NS, T_MX, T_SRV):
        add(pkt(RDATABYNAME, struct.pack('>IHHH', 0, 1, t, 11) + name('example.com')))

    def rdata(t, nrdatas, records, realname='example.com', ttl=3600, nsigs=0):
        # the SRV, MX and NS record subtrees are added with the offset of the records as their
        # length, so those responses need as much slack after the records as the offset says
        body = (struct.pack('>IHHIHHH', 0, 1, t, ttl, nrdatas, nsigs, len(realname))
                + name(realname) + records)
        off = 28 + 18 + len(realname) + 1
        body += bytes(max(0, 2 * off + 8 - (28 + len(body))))
        return pkt(RDATABYNAME, body, response=True)
    # A records
    add(rdata(T_A, 2, b''.join(struct.pack('>H', 4) + bytes(ip) for ip in ((192, 0, 2, 1), (192, 0, 2, 2)))), True)
    # SRV records (the last name of each type is compressed)
    srv = b''
    for pri, w, port, n in ((10, 5, 5060, '_sip.example.com'), (20, 1, 5061, 'backup.example.com')):
        d = dns(n)
        srv += struct.pack('>HHHH', 8 + len(d), pri, w, port) + d
    srv += struct.pack('>HHHH', 10, 30, 7, 389) + b'\xc0\x02' + dns('ptr.example.com')   # compressed name: the pointer is relative to the start of the name field
    add(rdata(T_SRV, 3, srv), True)
    # MX records
    mx = b''
    for pri, n in ((10, 'mail.example.com'), (20, 'mail2.example.com')):
        d = dns(n)
        mx += struct.pack('>HH', 4 + len(d), pri) + d
    mx += struct.pack('>HH', 6, 30) + b'\xc0\x02' + dns('ptr.example.com')
    add(rdata(T_MX, 3, mx), True)
    # NS records
    ns = b''
    for n in ('ns1.example.com', 'ns2.example.com'):
        d = dns(n)
        ns += struct.pack('>H', 2 + len(d)) + d
    ns += struct.pack('>H', 4) + b'\xc0\x02' + dns('ptr.example.com')
    add(rdata(T_NS, 3, ns), True)
    # a type that is not decoded (TXT), and no records at all
    add(rdata(16, 1, b'\x00\x05\x04text'), True)
    add(rdata(T_A, 0, b''), True)
    # failures: only the header is decoded
    for res in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 99):
        add(pkt(ADDRSBYNAME, b'', response=True, result=res, serial=0x2000 + res), True)
    # opcode nobody knows, with the response flag clear and set, version 1, auth fields
    add(pkt(0x00010004, b'\0' * 8))
    add(pkt(0x00010004, b'\0' * 8, response=True), True)
    add(pkt(NOOP, struct.pack('>H', 2) + b'xx', version=1, authtype=1, authlen=0, recvlen=0))
    return F


def malformed_frames():
    F = []

    def add(p, response=False):
        F.append(udp_frame(p, response))

    # too short for the header
    add(b'\0' * 10)
    add(b'\0' * 27)
    # noop: the data after the length is shorter than the length says
    add(pkt(NOOP, struct.pack('>H', 100) + b'ab'))
    # requests and responses cut inside their fixed part and inside names
    for op in (ADDRSBYNAME, NAMEBYADDR, RDATABYNAME):
        add(pkt(op, b'\0\0\0'))
        add(pkt(op, b'\0\0\0', response=True), True)
    add(pkt(ADDRSBYNAME, struct.pack('>IIH', 0, 3, 200) + b'short'))
    add(pkt(RDATABYNAME, struct.pack('>IHHH', 0, 1, 1, 200) + b'short'))
    # response with counts larger than the data
    body = struct.pack('>IHHH', 0, 50, 50, 5) + name('abcde')
    add(pkt(ADDRSBYNAME, body, response=True), True)
    add(pkt(NAMEBYADDR, struct.pack('>IHH', 0, 50, 4) + b'host', response=True), True)
    add(pkt(NAMEBYADDR, struct.pack('>IHH', 0, 1, 200) + b'host', response=True), True)
    # rdata response with record counts larger than the data and bad names
    for t in (T_A, T_SRV, T_MX, T_NS):
        add(pkt(RDATABYNAME, struct.pack('>IHHIHHH', 0, 1, t, 60, 50, 0, 1) + b'x\0' + b'\0\x04\x01\x02', response=True), True)
        add(pkt(RDATABYNAME, struct.pack('>IHHIHHH', 0, 1, t, 60, 1, 0, 1) + b'x\0' + struct.pack('>HHHH', 20, 1, 2, 3)
                + b'\xc0\x10' * 3, response=True), True)
    # a compression pointer loop in a name
    loop = struct.pack('>HHHH', 10, 1, 2, 3) + b'\xc0\x00'   # a pointer to itself
    add(pkt(RDATABYNAME, struct.pack('>IHHIHHH', 0, 1, T_SRV, 60, 1, 0, 1) + b'x\0' + loop, response=True), True)
    # real name length beyond the packet
    add(pkt(RDATABYNAME, struct.pack('>IHHIHHH', 0, 1, T_A, 60, 1, 0, 60000) + b'x\0', response=True), True)
    # header claims a length unrelated to the datagram
    add(pkt(NOOP, struct.pack('>H', 2) + b'xx', length=0xffffffff))
    return F


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'lwres-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'lwres-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
