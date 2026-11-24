#!/usr/bin/env python3
# Generates test/captures/db_lsp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the DB-LSP dissector
(packet-db-lsp.c, Dropbox LAN sync).

DB-LSP runs on TCP port 17500 (the LAN sync protocol, TLS-like records:
a type octet, magic 0x0301, a big endian length and the value; type
0x80 has two extra octets before the magic) and DB-LSP-DISC on UDP port
17500 (the discovery broadcasts, JSON that the heuristic JSON dissector
takes, or else shown as text). A configuration record (type 0x16) with
op 0x0B carries an X.509 certificate 10 octets into the value (op,
three 24 bit lengths).

Every packet is built from scratch with struct; no captured traffic is
used. The certificate is a synthetic one built here (it is not signed
by anything).

Usage: mkdb_lsp.py <output directory>

Writes:
  db-lsp-coverage.pcap            discovery broadcasts (JSON and text),
                                  a TCP connection with a certificate,
                                  other configuration records, data,
                                  an unknown type, type 0x80, records
                                  split over segments and several in one
                                  segment, an unknown magic, a type 0x80
                                  record whose length is past the end,
                                  the reproducer of "DB-LSP: Show a
                                  certificate message shorter than 10
                                  octets as a value"
  db-lsp-coverage-malformed.pcap  a certificate record whose certificate
                                  is cut short, records cut at the end
                                  of the capture
"""

import json
import os
import struct
import sys

PORT = 17500


# ---------------------------------------------------------------- BER

def ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, *vals):
    val = b''.join(vals)
    return bytes([tag]) + ber_len(len(val)) + val


def oid_enc(s):
    p = [int(x) for x in s.split('.')]
    out = bytearray()
    for a in [p[0] * 40 + p[1]] + p[2:]:
        enc = [a & 0x7f]
        a >>= 7
        while a:
            enc.insert(0, 0x80 | (a & 0x7f))
            a >>= 7
        out += bytes(enc)
    return bytes(out)


def OID(s):
    return tlv(0x06, oid_enc(s))


def SEQ(*v):
    return tlv(0x30, *v)


def SET(*v):
    return tlv(0x31, *v)


def name(cn):
    return SEQ(SET(SEQ(OID('2.5.4.6'), tlv(0x13, b'AU'))),
               SET(SEQ(OID('2.5.4.10'), tlv(0x0c, b'Example LAN Sync'))),
               SET(SEQ(OID('2.5.4.3'), tlv(0x0c, cn.encode()))))


def certificate():
    alg = SEQ(OID('1.2.840.10045.4.3.2'))               # ecdsa-with-SHA256
    spki = SEQ(SEQ(OID('1.2.840.10045.2.1'), OID('1.2.840.10045.3.1.7')),
               tlv(0x03, b'\x00\x04' + bytes(range(64))))
    tbs = SEQ(tlv(0xa0, tlv(0x02, b'\x02')),             # v3
              tlv(0x02, b'\x01\x23\x45\x67'),
              alg, name('dropbox-ca'),
              SEQ(tlv(0x17, b'260101000000Z'), tlv(0x17, b'361231235959Z')),
              name('host-1'), spki)
    sig = tlv(0x03, b'\x00' + SEQ(tlv(0x02, b'\x01' * 32), tlv(0x02, b'\x02' * 32)))
    return SEQ(tbs, alg, sig)


# ------------------------------------------------------- frames

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])


def ipv4(src, dst, proto, payload, ident=1):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, src, dst)
    return ip[:10] + struct.pack('!H', csum(ip)) + ip[12:] + payload


def udp_broadcast(payload, sport=PORT):
    src, dst = IP_A, bytes([192, 0, 2, 255])
    udp = struct.pack('!HHHH', sport, PORT, 8 + len(payload), 0) + payload
    ph = src + dst + struct.pack('!BBH', 0, 17, len(udp))
    udp = udp[:6] + struct.pack('!H', csum(ph + udp) or 0xffff) + udp[8:]
    return b'\xff' * 6 + MAC_A + b'\x08\x00' + ipv4(src, dst, 17, udp)


class Conn:
    """A TCP connection with sequence numbers kept for both sides."""

    def __init__(self, frames, cport):
        self.F = frames
        self.cport = cport
        self.seq = {True: 1000, False: 5000}

    def _pkt(self, from_client, flags, payload=b''):
        sport, dport = (self.cport, PORT) if from_client else (PORT, self.cport)
        src, dst = (IP_A, IP_B) if from_client else (IP_B, IP_A)
        smac, dmac = (MAC_A, MAC_B) if from_client else (MAC_B, MAC_A)
        seq, ack = self.seq[from_client], self.seq[not from_client]
        opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''   # MSS, SACK perm
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack if flags & 0x10 else 0,
                          (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
        self.seq[from_client] = (seq + len(payload) + (1 if flags & 0x03 else 0)) & 0xffffffff
        self.F.append(dmac + smac + b'\x08\x00' + ipv4(src, dst, 6, tcp))

    def open(self):
        self._pkt(True, 0x02)
        self._pkt(False, 0x12)
        self._pkt(True, 0x10)

    def send(self, from_client, payload):
        self._pkt(from_client, 0x18, payload)

    def close(self):
        self._pkt(True, 0x11)
        self._pkt(False, 0x11)
        self._pkt(True, 0x10)


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1793491200 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)


# ------------------------------------------------------- DB-LSP records

def record(rtype, value, magic=0x0301, length=None, extra=None):
    hdr = bytes([rtype])
    if extra is not None:
        hdr += extra
    return hdr + struct.pack('>HH', magic, len(value) if length is None else length) + value


def u24(n):
    return struct.pack('>I', n)[1:]


def cert_value(cert):
    """op 0x0B, then (as in a TLS Certificate message) the message
    length, the certificate list length, the certificate length."""
    return b'\x0b' + u24(len(cert) + 6) + u24(len(cert) + 3) + u24(len(cert)) + cert


def discovery():
    return json.dumps({'host_int': 211184270, 'version': [2, 0],
                       'displayname': '', 'port': PORT,
                       'namespaces': [50488023, 11717482, 1031437]},
                      separators=(', ', ': ')).encode()


def main_frames():
    F = []
    # 1-2: discovery: JSON (heuristic) and text
    F.append(udp_broadcast(discovery()))
    F.append(udp_broadcast(b'Dropbox LAN sync discovery: not JSON'))

    c = Conn(F, 51000)
    c.open()                                                        # 3-5
    cert = certificate()
    c.send(False, record(0x16, cert_value(cert)))                   # 6: certificate
    c.send(True, record(0x16, b'\x01' + b'\x03\x03' + bytes(32)))   # 7: config, op 1 (value)
    c.send(True, record(0x17, b'\xaa' * 48))                        # 8: data
    c.send(False, record(0x15, b'\x02\x28'))                        # 9: unknown type (alert)
    c.send(True, record(0x80, b'\x01\x02\x03\x04', extra=b'\x00\x10'))  # 10: type 0x80
    # 11: three records in one segment
    c.send(False, record(0x17, b'\x01' * 5) + record(0x17, b'\x02' * 6) + record(0x16, b'\x0e'))
    # 12-13: a data record split over two segments (reassembly)
    big = record(0x17, bytes(range(256)) * 4)
    c.send(True, big[:300])
    c.send(True, big[300:])
    # 14: a record whose magic is not 0x0301 (the rest of the segment)
    c.send(False, b'\x16\x03\x03\x00\x02\x0e\x00')
    # 15: type 0x80 whose length is past the end of the segment
    c.send(True, record(0x80, b'\x00' * 4, length=200, extra=b'\x00\x10'))
    # 16: the reproducer: a certificate op whose length is 3 (< 10),
    # followed by 20 zero octets (an unknown record), as in
    # dblsp_cert_underflow.py
    c.send(True, b'\x16\x03\x01\x00\x03\x0b' + b'\x00' * 20)
    c.close()                                                       # 17-19
    return F


def malformed_frames():
    F = []
    c = Conn(F, 51001)
    c.open()
    cert = certificate()
    # a certificate record whose length covers only half the certificate
    v = cert_value(cert)
    c.send(False, record(0x16, v[:len(v) // 2]))
    # a certificate whose inner lengths are wrong (shorter than the BER)
    c.send(False, record(0x16, b'\x0b' + bytes(9) + cert[:20] + b'\x00' * 5))
    # a configuration record of length 0 (the op is read past it), a
    # certificate op with length 10 (an empty certificate)
    c.send(False, record(0x16, b''))
    c.send(False, record(0x16, b'\x0b' + bytes(9)))
    # a record cut short by the end of the capture (never completed)
    c.send(True, record(0x17, b'\x00' * 100)[:40])
    F.append(udp_broadcast(b'{"host_int": 1, "port": '))       # broken JSON -> text
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'db-lsp-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'db-lsp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
