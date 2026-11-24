#!/usr/bin/env python3
# Generates test/captures/cmpp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the CMPP dissector
(packet-cmpp.c, China Mobile Point to Point).

All packets are built from scratch with struct; no captured traffic is
used. An SP (10.0.0.1) talks CMPP to an ISMG (10.0.0.2) on the CMPP TCP
ports 7890, 7900, 7930 and 9168, which are registered by default.

Usage: mkcmpp.py <output directory>

Writes:
  cmpp-coverage.pcap            every command (CONNECT, SUBMIT, DELIVER,
                                a status report, the responses, the
                                commands without a body decoder), several
                                PDUs in one segment, PDUs over several
                                segments, segments the heuristics refuse,
                                and the reproducer of "CMPP: Fix the
                                timestamp, ISMG code and Source ID"
  cmpp-coverage-malformed.pcap  bodies cut short by Total_Length, a
                                message length past the end
"""

import os
import struct
import sys

SP = (10, 0, 0, 1)
ISMG = (10, 0, 0, 2)


# --------------------------------------------------------------------------
# pcap writer (Ethernet / IPv4 / TCP)

def ip_checksum(hdr):
    if len(hdr) % 2:
        hdr += b'\0'
    s = sum(struct.unpack('>%dH' % (len(hdr) // 2), hdr))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []

    def tcp(self, sport, dport, seq, ack, flags, payload=b'', src=SP, dst=ISMG):
        opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''
        hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 6, len(hdr) + len(payload))
        hdr = hdr[:16] + struct.pack('>H', ip_checksum(pseudo + hdr + payload)) + hdr[18:]
        l4 = hdr + payload
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), len(self.frames) & 0xffff,
                         0x4000, 64, 6, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('>H', ip_checksum(ip)) + ip[12:]
        if src == SP:
            eth = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
        else:
            eth = b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02' + b'\x08\x00'
        self.frames.append(eth + ip + l4)

    def write(self, path):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)]
        t = 1700000000
        for i, f in enumerate(self.frames):
            out.append(struct.pack('<IIII', t + i // 100, (i % 100) * 10000, len(f), len(f)) + f)
        with open(path, 'wb') as fh:
            fh.write(b''.join(out))


class TcpStream:
    """A TCP connection from the SP to the ISMG with correct sequence
    numbers."""
    def __init__(self, cap, cport, sport=7890, handshake=True):
        self.cap, self.cport, self.sport = cap, cport, sport
        self.cseq, self.sseq = 1000 + cport, 5000 + cport
        if handshake:
            cap.tcp(cport, sport, self.cseq, 0, 0x02)
            cap.tcp(sport, cport, self.sseq, self.cseq + 1, 0x12, src=ISMG, dst=SP)
            self.cseq += 1
            self.sseq += 1
            cap.tcp(cport, sport, self.cseq, self.sseq, 0x10)

    def sp(self, *datas):
        """Send each argument as one TCP segment from the SP."""
        for data in datas:
            self.cap.tcp(self.cport, self.sport, self.cseq, self.sseq, 0x18, data)
            self.cseq += len(data)

    def ismg(self, *datas):
        for data in datas:
            self.cap.tcp(self.sport, self.cport, self.sseq, self.cseq, 0x18, data,
                         src=ISMG, dst=SP)
            self.sseq += len(data)

    def close(self):
        self.cap.tcp(self.cport, self.sport, self.cseq, self.sseq, 0x11)
        self.cseq += 1
        self.cap.tcp(self.sport, self.cport, self.sseq, self.cseq, 0x11, src=ISMG, dst=SP)
        self.sseq += 1
        self.cap.tcp(self.cport, self.sport, self.cseq, self.sseq, 0x10)


def split(data, *cuts):
    out, last = [], 0
    for c in cuts:
        out.append(data[last:c])
        last = c
    return out + [data[last:]]


# --------------------------------------------------------------------------
# CMPP encoding

CONNECT, CONNECT_RESP = 0x00000001, 0x80000001
TERMINATE, TERMINATE_RESP = 0x00000002, 0x80000002
SUBMIT, SUBMIT_RESP = 0x00000004, 0x80000004
DELIVER, DELIVER_RESP = 0x00000005, 0x80000005
QUERY, QUERY_RESP = 0x00000006, 0x80000006
CANCEL, CANCEL_RESP = 0x00000007, 0x80000007
ACTIVE_TEST, ACTIVE_TEST_RESP = 0x00000008, 0x80000008


def pdu(cmd, seq, body=b''):
    return struct.pack('>III', 12 + len(body), cmd, seq) + body


def ostr(s, n):
    if isinstance(s, str):
        s = s.encode()
    assert len(s) <= n
    return s.ljust(n, b'\0')


def msg_id(month, day, hour, minute, second, ismg, seq):
    """64 bit Msg_Id: month 4, day 5, hour 5, minute 6, second 6 bits,
    ISMG code 22 bits, sequence 16 bits."""
    v = (month << 60) | (day << 55) | (hour << 50) | (minute << 44) | (second << 38) | \
        (ismg << 16) | seq
    return struct.pack('>Q', v)


def connect(seq, src, version, ts):
    return pdu(CONNECT, seq, ostr(src, 6) + bytes(range(16)) + bytes([version]) +
               struct.pack('>I', ts))


def connect_resp(seq, status, version):
    return pdu(CONNECT_RESP, seq, struct.pack('>I', status) + bytes(range(16, 32)) +
               bytes([version]))


def submit(seq, mid, pk_total, pk_number, reg, level, service, fee_usertype, fee_term,
           fee_term_type, pid, udhi, fmt, msg_src, fee_type, fee_code, valid, at, src_id,
           dests, dest_type, content, link):
    b = mid + bytes([pk_total, pk_number, reg, level]) + ostr(service, 10)
    b += bytes([fee_usertype]) + ostr(fee_term, 32) + bytes([fee_term_type, pid, udhi, fmt])
    b += ostr(msg_src, 6) + ostr(fee_type, 2) + ostr(fee_code, 6) + ostr(valid, 17)
    b += ostr(at, 17) + ostr(src_id, 21) + bytes([len(dests)])
    b += b''.join(ostr(d, 32) for d in dests)
    b += bytes([dest_type, len(content)]) + content + ostr(link, 20)
    return pdu(SUBMIT, seq, b)


def submit_resp(seq, mid, result):
    return pdu(SUBMIT_RESP, seq, mid + struct.pack('>I', result))


def deliver(seq, mid, dest, service, pid, udhi, fmt, src_term, src_type, content, link):
    b = mid + ostr(dest, 21) + ostr(service, 10) + bytes([pid, udhi, fmt])
    b += ostr(src_term, 32) + bytes([src_type, 0, len(content)]) + content + ostr(link, 20)
    return pdu(DELIVER, seq, b)


def report(mid, stat, submit_time, done_time, dest, smsc_seq):
    return mid + ostr(stat, 7) + ostr(submit_time, 10) + ostr(done_time, 10) + \
        ostr(dest, 32) + struct.pack('>I', smsc_seq)


def deliver_report(seq, mid, dest, service, src_term, src_type, rep, link):
    b = mid + ostr(dest, 21) + ostr(service, 10) + bytes([0, 0, 0])
    b += ostr(src_term, 32) + bytes([src_type, 1, len(rep)]) + rep + ostr(link, 20)
    return pdu(DELIVER, seq, b)


def deliver_resp(seq, mid, result):
    return pdu(DELIVER_RESP, seq, mid + struct.pack('>I', result))


# --------------------------------------------------------------------------
# The reproducer of "CMPP: Fix the timestamp, ISMG code and Source ID"
# (cmpp_small_fixes.py), byte for byte.

def repro_pdus():
    pk = []
    # CONNECT with timestamp 0xFFFFFFFF
    pk.append(pdu(CONNECT, 1, b"SP0001" + b"\0" * 16 + b"\x30" + struct.pack(">I", 0xFFFFFFFF)))
    # SUBMIT_RESP with Msg_Id: month 1 day 2 hour 3 min 4 sec 5, ISMG 123456, seq 7
    mid = (1 << 60) | (2 << 55) | (3 << 50) | (4 << 44) | (5 << 38) | (123456 << 16) | 7
    pk.append(pdu(SUBMIT_RESP, 2, struct.pack(">QI", mid, 0)))
    # SUBMIT with 21-byte Src_Id
    b = struct.pack(">Q", mid) + bytes([1, 1, 0, 0]) + b"SVC0000000" + b"\x00" + b"\0" * 32 + \
        b"\x00\x00\x00\x00" + b"SP0001" + b"01" + b"000000" + b"\0" * 17 + b"\0" * 17 + \
        b"10690000123456789AB" + b"CD" + b"\x01" + b"13800000000".ljust(32, b"\0") + \
        b"\x00" + b"\x02" + b"hi" + b"\0" * 20
    pk.append(pdu(SUBMIT, 3, b))
    return pk


def main_capture():
    cap = Pcap()

    # Stream 1, port 7890: a full session with every decoded command
    s = TcpStream(cap, 40001, 7890)
    s.sp(connect(1, '901234', 0x30, 1101120000))                  # CMPP 3.0
    s.ismg(connect_resp(1, 0, 0x30))
    mid1 = msg_id(11, 1, 12, 30, 45, 0x2ABCDE, 1)
    s.sp(submit(2, b'\0' * 8, 1, 1, 1, 9, 'SVCWEATHER', 3, '13900000001', 1, 0, 0, 15,
                '901234', '02', '000010', '261101123000032+', '261101120500032+',
                '1069012345', ['13800000001', '13800000002', '13800000003'], 0,
                'Hello CMPP'.encode(), 'LINK0001'))
    s.ismg(submit_resp(2, mid1, 0))
    # A status report for the submitted message
    rep = report(mid1, 'DELIVRD', '2611011230', '2611011231', '13800000001', 42)
    s.ismg(deliver_report(100, msg_id(11, 1, 12, 31, 2, 0x2ABCDE, 2), '1069012345',
                          'SVCWEATHER', '13800000001', 0, rep, 'LINK0001'))
    s.sp(deliver_resp(100, msg_id(11, 1, 12, 31, 2, 0x2ABCDE, 2), 0))
    # A mobile originated message (UCS2), with a fake terminal type
    s.ismg(deliver(101, msg_id(12, 31, 23, 59, 59, 0x3FFFFF, 0xFFFF), '1069012345',
                   'SVCNEWS', 0, 0, 8, '13800000004', 1, 'News'.encode('utf-16-be'), 'L2'))
    s.sp(deliver_resp(101, msg_id(12, 31, 23, 59, 59, 0x3FFFFF, 0xFFFF), 9))
    s.sp(pdu(ACTIVE_TEST, 3))
    s.ismg(pdu(ACTIVE_TEST_RESP, 3, b'\0'))
    s.sp(pdu(TERMINATE, 4))
    s.ismg(pdu(TERMINATE_RESP, 4))
    s.close()

    # Stream 2, port 7900: a rejected CONNECT (version 2.0), every other
    # submit result, and commands without a body decoder
    s = TcpStream(cap, 40002, 7900)
    s.sp(connect(1, 'SP0002', 0x20, 101000000))
    s.ismg(connect_resp(1, 4, 0x30))
    s.sp(connect(2, 'SP0002', 0x30, 1231235959))
    s.ismg(connect_resp(2, 7, 0x30))                 # unknown status
    for r in (1, 13, 99):
        s.ismg(submit_resp(10 + r, msg_id(1, 2, 3, 4, 5, 6, r), r))
    s.sp(pdu(QUERY, 20, b'20261101' + b'\0' + b'SVCWEATHER' + b'\0' * 8))
    s.ismg(pdu(QUERY_RESP, 20, b'20261101' + b'\0' * 43))
    s.sp(pdu(CANCEL, 21, msg_id(1, 2, 3, 4, 5, 6, 7)))
    s.ismg(pdu(CANCEL_RESP, 21, b'\0\0\0\0'))
    # Several PDUs in one segment
    s.sp(pdu(ACTIVE_TEST, 22) + pdu(ACTIVE_TEST, 23) +
         submit(24, b'\0' * 8, 2, 1, 0, 0, 'SVC', 0, '', 0, 0x40, 1, 4, 'SP0002', '01',
                '000000', '', '', '10690002', ['13800000009'], 1, bytes(range(1, 9)), ''))
    s.ismg(pdu(ACTIVE_TEST_RESP, 22, b'\0') + pdu(ACTIVE_TEST_RESP, 23, b'\0') +
           submit_resp(24, msg_id(1, 2, 3, 4, 5, 6, 8), 0))
    # A SUBMIT over three segments, a DELIVER over two
    sub = submit(25, b'\0' * 8, 1, 1, 0, 1, 'SVCLONG', 1, '', 0, 0, 0, 0, 'SP0002', '03',
                 '000500', '', '', '10690002', [], 0, b'x' * 140, 'LINK0003')
    s.sp(*split(sub, 20, 100))
    dl = deliver(26, msg_id(2, 28, 0, 0, 0, 1, 1), '10690002', 'SVCLONG', 0, 0, 3,
                 '13800000005', 0, b'card', '')
    s.ismg(*split(dl, 60))
    # The fixed header in one segment, the body in the next, and a PDU
    # whose end shares a segment with the start of the next PDU
    a = pdu(ACTIVE_TEST, 27)
    sr = submit_resp(28, msg_id(3, 3, 3, 3, 3, 3, 3), 5)
    s.ismg(pdu(ACTIVE_TEST_RESP, 27, b'\0'))
    s.sp(a + sr[:14], sr[14:])
    # A valid PDU followed by an unknown command in the same segment
    s.sp(pdu(ACTIVE_TEST, 29) + pdu(0x00000003, 30, b'\0' * 4))
    # A PDU followed by the first 8 octets of the next fixed header (with
    # TCP reassembly off the second PDU is handed over shorter than the
    # header)
    a = pdu(ACTIVE_TEST, 32)
    s.sp(pdu(ACTIVE_TEST, 31) + a[:8], a[8:])
    s.close()

    # Stream 3, port 7930: route commands without a decoder
    s = TcpStream(cap, 40003, 7930)
    for i, (c, r) in enumerate(((0x10, 0x80000010), (0x11, 0x80000011), (0x12, 0x80000012),
                                (0x13, 0x80000013), (0x14, 0x80000014), (0x15, 0x80000015),
                                (0x16, 0x80000016), (0x17, 0x80000017), (0x09, 0x80000009))):
        s.sp(pdu(c, 50 + i, b'\x01\x02\x03\x04'))
        s.ismg(pdu(r, 50 + i, b'\0\0\0\0'))
    s.close()

    # Stream 4, port 9168: segments the heuristics refuse (shown as data)
    s = TcpStream(cap, 40004, 9168)
    s.sp(b'\x00\x00\x00\x0c\x00\x00')                      # shorter than the header
    s.sp(pdu(0x00000003, 1))                               # unknown command
    s.sp(struct.pack('>III', 8, ACTIVE_TEST, 2))           # length below 12
    s.sp(struct.pack('>III', 1001, SUBMIT, 3) + b'\0' * 20)  # length above 1000
    s.close()

    # Stream 5, port 7890: the reproducer, one PDU per segment
    s = TcpStream(cap, 40005, 7890, handshake=False)
    r = repro_pdus()
    s.sp(r[0])
    s.ismg(r[1])
    s.sp(r[2])
    return cap


def malformed_capture():
    cap = Pcap()
    s = TcpStream(cap, 41001, 7890, handshake=False)
    # Bodies cut short by Total_Length
    s.sp(pdu(CONNECT, 1, b'SP'))
    s.ismg(pdu(CONNECT_RESP, 1, b'\0\0'))
    s.sp(pdu(SUBMIT, 2, b'\0' * 8))
    s.ismg(pdu(SUBMIT_RESP, 2, b'\0' * 4))
    s.ismg(pdu(DELIVER, 3, b'\0' * 30))
    s.sp(pdu(DELIVER_RESP, 3, b'\0' * 9))
    # Ten destinations, only one present
    b = submit(4, b'\0' * 8, 1, 1, 0, 0, 'S', 0, '', 0, 0, 0, 0, '', '', '', '', '', '',
               ['1'], 0, b'', '')[12:]
    i = b.index(b'\x01' + b'1'.ljust(32, b'\0'))
    s.sp(pdu(SUBMIT, 4, b[:i] + b'\x0a' + b[i + 1:i + 33]))
    # A message length past the end
    b = deliver(5, b'\0' * 8, '', '', 0, 0, 0, '', 0, b'', '')[12:]
    s.ismg(pdu(DELIVER, 5, b[:-21] + b'\xff'))
    # A status report cut short
    b = deliver_report(6, b'\0' * 8, '', '', '', 0, b'\0' * 20, '')[12:]
    s.ismg(pdu(DELIVER, 6, b[:-20]))
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(os.path.join(out, 'cmpp-coverage.pcap'))
    malformed_capture().write(os.path.join(out, 'cmpp-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
