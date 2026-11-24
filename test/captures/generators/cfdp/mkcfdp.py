#!/usr/bin/env python3
# Generates test/captures/cfdp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CCSDS File Delivery
Protocol dissector (packet-cfdp.c).

CFDP has no port of its own. dissect_cfdp() is reached through Decode As
on a UDP port (here 5234, -d udp.port==5234,cfdp) or as CCSDS Space
Packet APID 2045; dissect_cfdp_as_subtree() is reached by default from
the Bundle Protocol version 6 dissector, for a bundle on UDP port 4556
whose source and destination SSPs are 64 and 65 (packet-bpv6.c). Every
packet is built from scratch with struct; no captured traffic is used.

Usage: mkcfdp.py <output directory>

Writes:
  cfdp-coverage.pcap            every PDU type, every TLV and every proxy
                                message, every entity ID and sequence
                                number size, CRC, the reproducer frames of
                                the fix, bundles with CFDP payloads
  cfdp-coverage-malformed.pcap  bad entity ID lengths (only possible in
                                a proxy put request), PDUs cut short,
                                lengths past the end
"""

import os
import struct
import sys

SENDER = (192, 0, 2, 1)
RECEIVER = (198, 51, 100, 2)
CFDP_PORT = 5234
BUNDLE_PORT = 4556


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []

    def udp(self, payload, sport=CFDP_PORT, dport=CFDP_PORT, reverse=False):
        src, dst = (RECEIVER, SENDER) if reverse else (SENDER, RECEIVER)
        hdr = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(payload))
        c = csum(pseudo + hdr + payload) or 0xffff
        l4 = hdr[:6] + struct.pack('>H', c) + payload
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), len(self.frames) + 1,
                         0x4000, 64, 17, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        eth = (bytes.fromhex('020000000002') + bytes.fromhex('020000000001')) if not reverse \
            else (bytes.fromhex('020000000001') + bytes.fromhex('020000000002'))
        self.frames.append(eth + b'\x08\x00' + ip + l4)

    def cfdp(self, pdu, reverse=False):
        self.udp(pdu, reverse=reverse)

    def bundle(self, pdu):
        self.udp(bpv6(pdu), BUNDLE_PORT, BUNDLE_PORT)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
        t = 1792000000
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', t + i, 0, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


# --------------------------------------------------------------------------
# Bundle Protocol version 6 (RFC 5050), CBHE, SSPs 64 -> 65 (CFDP)

def sdnv(v):
    out = [v & 0x7f]
    v >>= 7
    while v:
        out.append(0x80 | (v & 0x7f))
        v >>= 7
    return bytes(reversed(out))


_seq = [0]


def bpv6(payload):
    _seq[0] += 1
    rest = b''.join(sdnv(v) for v in (
        2, 65,          # destination ipn:2.65
        1, 64,          # source ipn:1.64
        0, 0,           # report-to dtn:none
        0, 0,           # custodian dtn:none
        830000000,      # creation timestamp
        _seq[0],        # sequence number
        3600,           # lifetime
        0))             # dictionary length 0: CBHE
    primary = b'\x06' + sdnv(0x10) + sdnv(len(rest)) + rest
    block = b'\x01' + sdnv(0x08) + sdnv(len(payload)) + payload
    return primary + block


# --------------------------------------------------------------------------
# CFDP

def be(v, n):
    return v.to_bytes(n, 'big')


def cfdp(data, file_data=False, toward_sender=False, unack=False, crc=None,
         ent_len=1, seq_len=1, src=0x01, seq=0x02, dst=0x03, data_len=None):
    """A CFDP PDU (version 1). data is the PDU data field (directive code
    and parameters, or offset and file data). crc: a 16 bit value to
    append (the CRC flag is set and the data length counts it)."""
    b0 = 0x20 | (0x10 if file_data else 0) | (0x08 if toward_sender else 0) \
        | (0x04 if unack else 0) | (0x02 if crc is not None else 0)
    body = data + (struct.pack('>H', crc) if crc is not None else b'')
    if data_len is None:
        data_len = len(body)
    hdr = bytes([b0]) + struct.pack('>H', data_len) + bytes([((ent_len - 1) << 4) | (seq_len - 1)])
    return hdr + be(src, ent_len) + be(seq, seq_len) + be(dst, ent_len) + body


def lv(s):
    if isinstance(s, str):
        s = s.encode()
    return bytes([len(s)]) + s


def tlv(t, v):
    return bytes([t, len(v)]) + v


def fs_req(action, name1, name2=b''):
    """Filestore request TLV value."""
    return bytes([action << 4]) + lv(name1) + lv(name2)


def fs_resp(action, status, name1, name2=b'', msg=b''):
    """Filestore response TLV value."""
    return bytes([(action << 4) | status]) + lv(name1) + lv(name2) + lv(msg)


def msg(proxy_type, value):
    """Message To User TLV carrying a reserved CFDP message ("cfdp")."""
    return tlv(0x02, b'cfdp' + bytes([proxy_type]) + value)


def eof(cond=0, checksum=0x11223344, size=1000, tlvs=b''):
    return bytes([0x04, cond << 4]) + struct.pack('>II', checksum, size) + tlvs


def finished(cond=0, end_sys=1, incomplete=0, fstat=2, tlvs=b''):
    return bytes([0x05, (cond << 4) | (end_sys << 3) | (incomplete << 2) | fstat]) + tlvs


def ack(dircode=4, subtype=0, cond=0, tstat=1):
    return bytes([0x06, (dircode << 4) | subtype, (cond << 4) | tstat])


def metadata(src='src.txt', dst='dst.txt', size=1000, seg=0, tlvs=b''):
    return bytes([0x07, seg << 7]) + struct.pack('>I', size) + lv(src) + lv(dst) + tlvs


def nak(start=0, end=1000, segs=()):
    return bytes([0x08]) + struct.pack('>II', start, end) + b''.join(struct.pack('>II', a, b) for a, b in segs)


def prompt(keep_alive=0):
    return bytes([0x09, keep_alive << 7])


def keep_alive(progress=500):
    return bytes([0x0c]) + struct.pack('>I', progress)


def file_data(off, data):
    return struct.pack('>I', off) + data


def reproducer():
    """cfdp_small.py: EOF with a fault location TLV, and a
    Metadata PDU with Remote Status Report Responses, a Proxy Filestore
    Response and a flow label TLV."""
    def hdr(data):
        return bytes([0x20]) + struct.pack('!H', len(data)) + bytes([0x00, 0x01, 0x02, 0x03]) + data
    e = bytes([0x04, 0x10]) + struct.pack('!II', 0x11223344, 100) + bytes([0x06, 1, 0x05])
    msg_stat = b'cfdp' + bytes([0x21]) + struct.pack('!H', 0x0000) + bytes([0x07, 0x09])
    msg_fs = b'cfdp' + bytes([0x08, 0x00, 1, ord('a'), 0, 0])
    meta = bytes([0x07, 0x00]) + struct.pack('!I', 100) + bytes([1, ord('s'), 1, ord('d')])
    meta += bytes([0x02, len(msg_stat)]) + msg_stat
    meta += bytes([0x02, len(msg_fs)]) + msg_fs
    meta += bytes([0x05, 2, 0xaa, 0xbb])
    meta += bytes([0x02, len(msg_stat)]) + msg_stat
    return hdr(e), hdr(meta)


def main_capture():
    c = Pcap()
    # 1-2: the reproducer of the fix
    r1, r2 = reproducer()
    c.cfdp(r1)
    c.cfdp(r2)

    # 3-10: Metadata with every TLV type (one transaction, sender -> receiver)
    c.cfdp(cfdp(metadata('/data/report.bin', '/ground/report.bin', 4096)))
    c.cfdp(cfdp(metadata('a', 'b', 10, seg=1, tlvs=(
        tlv(0x00, fs_req(0, 'new.txt'))
        + tlv(0x00, fs_req(2, 'old.txt', 'renamed.txt'))
        + tlv(0x00, b'')                      # empty filestore request
        + tlv(0x04, bytes([0x51]))            # fault handler override
        + tlv(0x05, b'\x01\x02\x03')          # flow label
        + tlv(0x02, b'hello user')            # plain message to user
        + bytes([0x03])))))                   # unknown TLV type
    # Proxy operations, part 1
    c.cfdp(cfdp(metadata('', '', 0, tlvs=(
        msg(0x00, lv(be(0x2a, 2)) + lv('remote/src') + lv('remote/dst'))   # proxy put request
        + msg(0x01, lv(b'proxied msg'))                                    # proxy message to user
        + msg(0x02, lv(fs_req(5, 'newdir')))                               # proxy filestore request
        + msg(0x03, bytes([0x83]))                                         # proxy fault handler override
        + msg(0x04, bytes([0x01]))                                         # proxy transmission mode
        + msg(0x06, bytes([0x01]))                                         # proxy segmentation control
        + msg(0x07, bytes([0x07]))                                         # proxy put response
        + msg(0x08, lv(fs_resp(1, 1, 'gone.txt', b'', b'no file')))       # proxy filestore response
        + msg(0x09, b'')                                                   # proxy put cancel
        + msg(0x0A, bytes([0x10]) + be(0x0102, 2) + be(0x07, 1))           # originating transaction ID
        ))))
    # Proxy operations, part 2: directory listing, remote status/suspend/resume
    c.cfdp(cfdp(metadata('', '', 0, tlvs=(
        msg(0x10, lv('/data') + lv('/data/listing.txt'))
        + msg(0x11, bytes([0x80]) + lv('/data') + lv('/data/listing.txt'))
        + msg(0x20, bytes([0x21]) + be(0x0a0b, 3) + be(0x1234, 2) + lv('status.txt'))
        + msg(0x21, struct.pack('>H', 0x5100 | 0x0011) + be(0x0a0b, 2) + be(0x1234, 2))
        + msg(0x30, bytes([0x00]) + be(0x0a, 1) + be(0x12, 1))
        + msg(0x31, struct.pack('>H', 0xa000 | 0x0071) + be(0x0102030405060708, 8) + be(0x99, 2))
        + msg(0x38, bytes([0x13]) + be(0x0a0b, 2) + be(0x12345678, 4))
        + msg(0x39, struct.pack('>H', 0x2000 | 0x0000) + be(0x0a, 1) + be(0x12, 1))
        + msg(0x7f, b'')                                                   # unknown proxy type
        ))))
    # Proxy flow label: the dissector shows the label over the TLV length
    # without stepping over it, so the label octets are read as TLV types
    # (0x03 is an unknown type and skipped) and enough octets must follow
    c.cfdp(cfdp(metadata('', '', 0, tlvs=(
        msg(0x05, b'\x03\x03')
        + tlv(0x02, b'trailing message to user')))))
    # A message to user that does not start with "cfdp"
    c.cfdp(cfdp(metadata('x', 'y', 1, tlvs=tlv(0x02, b'CFDPnotreserved'))))
    # Filestore response status codes: every action code (0-8) and 9;
    # the last TLV ends exactly at the end of the PDU
    resp = b''
    for a in range(10):
        resp += tlv(0x01, fs_resp(a, 1 if a < 9 else 0, 'f%d' % a, 'g' if a in (2, 3, 4) else b'',
                                  b'msg' if a == 0 else b''))
    c.cfdp(cfdp(finished(0, 1, 0, 2, tlvs=resp)), reverse=True)
    # 10: Finished with an empty filestore response, a type 0 TLV, an
    # unknown TLV type and fault location TLVs (the last one empty, at the
    # end of the PDU)
    c.cfdp(cfdp(finished(5, 0, 1, 1, tlvs=(
        bytes([0x01, 0x00])
        + bytes([0x00, 0x01, 0x00])
        + b'\x09'
        + tlv(0x06, be(0x0a0b, 2))
        + tlv(0x06, b'')))), reverse=True)
    # 11-12: File data PDUs
    c.cfdp(cfdp(file_data(0, b'The quick brown fox jumps over the lazy dog'), file_data=True))
    c.cfdp(cfdp(file_data(43, b''), file_data=True, unack=True))

    # 14-20: EOF (every condition code, with and without fault location)
    for cond in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 14, 15, 10):
        c.cfdp(cfdp(eof(cond, 0xdeadbeef, 4096 + cond,
                        tlv(0x06, be(0x0a0b, 2)) if cond in (1, 8) else b'')))
    c.cfdp(cfdp(eof(0, 0, 0, bytes([0x01]) + b'\x00')))   # EOF with another TLV type
    # ACK of EOF and of Finished, every transaction status
    for d, sub, cond, ts in ((4, 0, 0, 0), (4, 0, 1, 1), (5, 1, 0, 2), (5, 1, 15, 3), (9, 0, 0, 1)):
        c.cfdp(cfdp(ack(d, sub, cond, ts), toward_sender=(d == 4)), reverse=(d == 4))
    # NAK with and without segment requests
    c.cfdp(cfdp(nak(0, 4096, ((0, 100), (200, 300))), toward_sender=True), reverse=True)
    c.cfdp(cfdp(nak(0, 0), toward_sender=True), reverse=True)
    # Prompt (NAK and Keep Alive), Keep Alive
    c.cfdp(cfdp(prompt(0)))
    c.cfdp(cfdp(prompt(1)))
    c.cfdp(cfdp(keep_alive(2048), toward_sender=True), reverse=True)
    # Reserved directive codes
    c.cfdp(cfdp(bytes([0x0a, 0x00, 0x00])))
    c.cfdp(cfdp(bytes([0x00])))

    # Header variants: every entity ID and sequence number length, CRC
    for n in range(1, 9):
        c.cfdp(cfdp(prompt(n & 1), ent_len=n, seq_len=9 - n,
                    src=int.from_bytes(bytes(range(1, n + 1)), 'big'),
                    seq=int.from_bytes(bytes(range(0x11, 0x11 + 9 - n)), 'big'),
                    dst=int.from_bytes(bytes(range(0x21, 0x21 + n)), 'big')))
    c.cfdp(cfdp(eof(0, 0x01020304, 77), crc=0xbeef))
    c.cfdp(cfdp(file_data(4096, b'with crc'), file_data=True, crc=0x1234, unack=True))
    c.cfdp(cfdp(metadata('c', 'd', 5, tlvs=tlv(0x05, b'\xff')), crc=0x0102))
    # Extra octets after the PDU go to the data dissector
    c.cfdp(cfdp(keep_alive(1)) + b'\xca\xfe\xba\xbe')

    # CFDP in bundles (dissect_cfdp_as_subtree)
    c.bundle(cfdp(metadata('bundle-src', 'bundle-dst', 64, tlvs=(
        tlv(0x04, bytes([0x23])) + msg(0x09, b'')))))
    c.bundle(cfdp(file_data(0, b'bundle file data'), file_data=True))
    c.bundle(cfdp(eof(0, 0xaabbccdd, 16, tlv(0x06, be(1, 1)))))
    c.bundle(cfdp(finished(0, 1, 0, 2, tlvs=tlv(0x06, be(1, 1)))))
    c.bundle(cfdp(ack(5, 1, 0, 2), toward_sender=True))
    c.bundle(cfdp(prompt(1), crc=0x4242))
    c.bundle(cfdp(keep_alive(16), toward_sender=True))
    c.bundle(cfdp(bytes([0x0b]), ent_len=2, seq_len=4))         # reserved directive code
    return c


def malformed_capture():
    c = Pcap()
    # 1: a remote status report request whose flags give an entity ID of
    # 8 octets and a sequence number of 8 octets, cut short
    c.cfdp(cfdp(metadata('', '', 0, tlvs=msg(0x20, bytes([0x77]) + b'\x01'))))
    # 2: a PDU header shorter than its ID lengths
    c.cfdp(bytes([0x20, 0x00, 0x05, 0x77, 0x01, 0x02]))
    # 3: data length past the end (EOF cut short)
    c.cfdp(cfdp(eof(0, 1, 2)[:4], data_len=10))
    # 4: Metadata with a file name length past the end
    c.cfdp(cfdp(bytes([0x07, 0x00]) + struct.pack('>I', 1) + b'\x40ab'))
    # 5: Metadata with a filestore request whose names run past the end
    c.cfdp(cfdp(metadata('a', 'b', 1, tlvs=bytes([0x00, 0x05, 0x00, 0x20, 0x61]))))
    # 6: a message to user TLV longer than the PDU
    c.cfdp(cfdp(metadata('a', 'b', 1, tlvs=bytes([0x02, 0x30]) + b'cfdp\x01\x20abc')))
    # 7: NAK with a data length below the fixed part
    c.cfdp(cfdp(bytes([0x08]) + b'\x00' * 8, data_len=5))
    # 8: file data PDU with a data length of 2 (shorter than the offset)
    c.cfdp(cfdp(b'\x00\x00', file_data=True))
    # 9: Finished with a filestore response cut short
    c.cfdp(cfdp(finished(tlvs=bytes([0x01, 0x10, 0x00, 0x08, 0x61]))))
    # 10: the proxy flow label at the end of the PDU (its item runs past
    # the end, observation 1)
    c.cfdp(cfdp(metadata('', '', 0, tlvs=msg(0x05, b'\x03\x03'))))
    # 11: a Finished PDU whose last filestore response has a message
    # length past the end
    c.cfdp(cfdp(finished(tlvs=tlv(0x01, fs_resp(0, 0, 'x')[:-1] + b'\x05'))))
    # 12: a bundle with a CFDP PDU cut short
    c.bundle(cfdp(eof(0, 1, 2))[:12])
    # 13: a bundle with a file data PDU and a data length past the end
    c.bundle(cfdp(file_data(0, b'abc'), file_data=True, data_len=40))
    # 14: a 2 octet UDP payload
    c.cfdp(b'\x20\x00')
    # 15-16: a NAK (not decoded in bundles) and a reserved directive with a
    # parameter in a bundle: the rest is shown with the full data length
    # (observation 2)
    c.bundle(cfdp(nak(0, 16, ((0, 8),)), toward_sender=True))
    c.bundle(cfdp(bytes([0x0b, 0x00]), ent_len=2, seq_len=4))
    # 17: proxy put requests with destination entity ID lengths 0 and 9
    # (the only "Wrong length for the entity ID" errors a packet can give)
    c.cfdp(cfdp(metadata('', '', 0, tlvs=(
        msg(0x00, lv(b'') + lv('s') + lv('d'))
        + msg(0x00, lv(bytes(range(1, 10))) + lv('s') + lv('d'))))))
    return c


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(os.path.join(out, 'cfdp-coverage.pcap'))
    malformed_capture().write(os.path.join(out, 'cfdp-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
