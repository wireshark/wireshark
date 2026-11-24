#!/usr/bin/env python3
# Generates test/captures/ltp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic LTP (RFC 5326) coverage captures for
epan/dissectors/packet-ltp.c.  Every packet is built with struct; nothing
comes from a real network.

Usage: mkltp.py <outdir>
Writes ltp-coverage.pcap (main) and ltp-coverage-malformed.pcap (error
paths and the UDP heuristic frames, which need the ltp_udp heuristic
enabled).
"""
import os
import struct
import sys

A = (192, 0, 2, 1)
B = (192, 0, 2, 2)
MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')


def sdnv(v):
    out = [v & 0x7f]
    v >>= 7
    while v:
        out.append(0x80 | (v & 0x7f))
        v >>= 7
    return bytes(reversed(out))


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


IPID = [0]


def udp_frame(payload, a_to_b=True, sport=1113, dport=1113):
    src, dst = (A, B) if a_to_b else (B, A)
    mac_s, mac_d = (MAC_A, MAC_B) if a_to_b else (MAC_B, MAC_A)
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    IPID[0] += 1
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), IPID[0], 0x4000, 64, 17, 0,
                    bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return mac_d + mac_s + b'\x08\x00' + h + u


# ------------------------------------------------------------ bundles

def v6_primary(dict_bytes, offs, flags=0x10, ts=700000000, seq=1, life=3600):
    body = (b''.join(sdnv(o) for o in offs) + sdnv(ts) + sdnv(seq) + sdnv(life)
            + sdnv(len(dict_bytes)) + dict_bytes)
    return bytes([6]) + sdnv(flags) + sdnv(len(body)) + body


def v6_bundle(data, seq=1):
    d = b'dtn\0//node2/app\0//node1/app\0none\0//node1/\0'
    # offsets: dst scheme/ssp, src scheme/ssp, rpt scheme/ssp, cust scheme/ssp
    offs = (0, 4, 0, 16, 0, 28, 0, 33)
    d = b'dtn\0' + b'//node2/app\0' + b'//node1/app\0' + b'none\0' + b'//node1/\0'
    offs = (0, 4, 0, 16, 0, 28, 0, 33)
    pay = bytes([1]) + sdnv(0x08) + sdnv(len(data)) + data
    return v6_primary(d, offs, seq=seq) + pay


def crc16_x25(data):
    crc = 0xffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xffff


def v7_bundle(payload=b'data'):
    prim = bytes.fromhex('89' '07' '00' '01' '82028201' '02' '82028201' '01' '820100'
                         '820000' '1a0036ee80' '42')
    crc = crc16_x25(prim + b'\0\0')
    return (b'\x9f' + prim + struct.pack('!H', crc)
            + bytes.fromhex('85' '01' '01' '00' '00') + bytes([0x40 + len(payload)])
            + payload + b'\xff')


def cbor_bstr(b):
    assert len(b) < 24 or len(b) < 256
    if len(b) < 24:
        return bytes([0x40 + len(b)]) + b
    return bytes([0x58, len(b)]) + b


# ------------------------------------------------------------ segments

def hdr(typ, orig, sess, nh=0, nt=0, ver=0):
    return bytes([(ver << 4) | typ]) + sdnv(orig) + sdnv(sess) + bytes([(nh << 4) | nt])


def ext(tag, val):
    return bytes([tag]) + sdnv(len(val)) + val


def data_seg(typ, orig, sess, csid, off, data, chkp=None, rpt=None, hx=(), tx=(),
             length=None):
    s = hdr(typ, orig, sess, len(hx), len(tx))
    s += b''.join(ext(t, v) for t, v in hx)
    s += sdnv(csid) + sdnv(off) + sdnv(len(data) if length is None else length)
    if typ in (1, 2, 3):
        s += sdnv(chkp if chkp is not None else 1) + sdnv(rpt if rpt is not None else 0)
    s += data
    s += b''.join(ext(t, v) for t, v in tx)
    return s


def report(orig, sess, rpt, chkp, ub, lb, claims, count=None):
    s = hdr(8, orig, sess) + sdnv(rpt) + sdnv(chkp) + sdnv(ub) + sdnv(lb)
    s += sdnv(len(claims) if count is None else count)
    for o, l in claims:
        s += sdnv(o) + sdnv(l)
    return s


def report_ack(orig, sess, rpt):
    return hdr(9, orig, sess) + sdnv(rpt)


def cancel(typ, orig, sess, reason=0):
    return hdr(typ, orig, sess) + bytes([reason])


def cancel_ack(typ, orig, sess):
    return hdr(typ, orig, sess)


# ------------------------------------------------------------ captures

def main_frames():
    F = []

    def u(payload, a_to_b=True, **kw):
        F.append(udp_frame(payload, a_to_b, **kw))

    # Session 1/1: red block, client service 1 (bundle protocol, BPv6),
    # two segments reassembled into the block, then report and ack.
    b1 = v6_bundle(b'Hello over LTP red block')
    u(data_seg(0, 1, 1, 1, 0, b1[:25]))
    u(data_seg(3, 1, 1, 1, 25, b1[25:], chkp=1, rpt=0))
    u(report(1, 1, 1, 1, len(b1), 0, [(0, len(b1))]), a_to_b=False)
    u(report_ack(1, 1, 1))

    # Session 1/2: red data with reception gaps, reports, retransmissions.
    u(data_seg(1, 1, 2, 1, 0, b'A' * 10, chkp=1))
    u(data_seg(1, 1, 2, 1, 20, b'C' * 10, chkp=2))
    u(report(1, 2, 5, 2, 40, 0, [(0, 10), (20, 10)]), a_to_b=False)
    u(data_seg(1, 1, 2, 1, 10, b'B' * 10, chkp=3, rpt=5))
    # retransmission of the first segment (range seen before)
    u(data_seg(0, 1, 2, 1, 0, b'A' * 10))
    # report with overlapping claims (the second claim starts before the
    # end of the first: no gap), a claim of length zero
    u(report(1, 2, 6, 3, 40, 0, [(0, 25), (10, 30)]), a_to_b=False)
    # repeated report (same ranges for report 5: retransmission)
    u(report(1, 2, 5, 2, 40, 0, [(0, 10), (20, 10)]), a_to_b=False)
    u(report_ack(1, 2, 5))
    u(report_ack(1, 2, 5))          # duplicate acknowledgement
    u(report_ack(1, 2, 99))         # acknowledgement of an unknown report
    u(report(1, 2, 9, 0, 40, 0, [(0, 40)]), a_to_b=False)   # asynchronous
    u(report(1, 2, 10, 77, 40, 30, [(0, 5)]), a_to_b=False)  # unknown checkpoint
    # trailing gap only, lower bound > 0, no claims at all
    u(report(1, 2, 11, 3, 100, 60, []), a_to_b=False)
    # data with a report serial number nobody sent
    u(data_seg(2, 1, 2, 1, 40, b'D' * 4, chkp=4, rpt=55))
    # serial numbers above 32 bits (CCSDS warning)
    u(data_seg(1, 1, 2, 1, 50, b'E' * 4, chkp=1 << 33, rpt=1 << 34))

    # Session 2/1: green block, client service 5 (BPv7), two segments.
    b7 = v7_bundle(b'green bundle')
    u(data_seg(4, 2, 1, 5, 0, b7[:20]))
    u(data_seg(7, 2, 1, 5, 20, b7[20:]))
    # undefined green types, no client service dissector (CSID 3, CFDP)
    u(data_seg(5, 2, 2, 3, 0, b'cfdp bytes'))
    u(data_seg(6, 2, 3, 3, 0, b'more bytes'))
    # Session 2/4: green EOB in one segment (no reassembly needed).
    u(data_seg(7, 2, 4, 5, 0, b7))

    # Session 3/1: service data aggregation (CSID 2): two bundles.
    sda = sdnv(1) + v6_bundle(b'sda one', 2) + sdnv(1) + v6_bundle(b'sda two', 3)
    u(data_seg(7, 3, 1, 2, 0, sda))
    # CSID 1: two bundles concatenated (non-interoperable warning)
    u(data_seg(7, 3, 2, 1, 0, v6_bundle(b'cat one', 4) + v6_bundle(b'cat two', 5)))
    # CSID 4: BPv7 bundles in CBOR byte strings
    u(data_seg(7, 3, 3, 4, 0, cbor_bstr(v7_bundle(b'one')) + cbor_bstr(v7_bundle(b'two'))))

    # Session 204/1 (an engine ID over 127 makes the 4 octet
    # cancel acknowledgements long enough for LTP_MIN_DATA_BUFFER): cancellations.
    u(cancel(12, 204, 1, 1))
    u(cancel_ack(13, 204, 1), a_to_b=False)
    u(cancel(12, 204, 1, 2))              # repeated cancel
    u(cancel_ack(13, 204, 1), a_to_b=False)
    u(cancel(14, 204, 2, 3), a_to_b=False)
    u(cancel_ack(15, 204, 2))
    u(cancel_ack(15, 204, 3))             # no cancel segment before it
    u(cancel(12, 204, 4, 4))              # never acknowledged
    u(cancel(14, 204, 5, 5), a_to_b=False)
    u(cancel(14, 204, 6, 0x42), a_to_b=False)   # unknown reason code

    # Header and trailer extensions.
    u(data_seg(3, 5, 1, 3, 0, b'ext data', hx=((0, b'\x01\x02\x03'), (1, b'cookie')),
               tx=((0, b'MAC'), (1, b'\x00'))))
    # Reproducers (ltp_*.py)
    # CSID 0xFFFFFFFF and 2^40: no client service dissector
    u(data_seg(3, 6, 1, 0xFFFFFFFF, 0, b'ABCD'))
    u(data_seg(3, 6, 2, 1 << 40, 0, b'ABCD'))
    # retransmission, then trailer extension followed by another segment,
    # then two segments in one datagram
    u(data_seg(0, 7, 1, 1, 0, b'ABCD'))
    u(data_seg(0, 7, 1, 1, 0, b'ABCD'))
    u(data_seg(0, 7, 2, 1, 0, b'WXYZ', tx=((1, b'TT'),)) + data_seg(0, 7, 3, 1, 0, b'EFGH'))
    u(data_seg(0, 7, 4, 1, 0, b'IJKL') + data_seg(3, 7, 5, 1, 0, b'MNOP'))
    # undefined control segment types
    u(hdr(10, 208, 1))
    u(hdr(11, 208, 1))
    # a report acknowledgement and a report in one datagram
    u(report_ack(1, 1, 1) + report(1, 3, 21, 1, 10, 0, [(0, 10)]))
    # a report claiming a range before the data for it is sent, then the
    # data (the claim refers only to frames up to the report), and a data
    # segment without data (empty range) while reports exist
    u(report(1, 2, 12, 4, 260, 200, [(0, 60)]), a_to_b=False)
    u(data_seg(1, 1, 2, 1, 200, b'F' * 60, chkp=5))
    u(data_seg(1, 1, 2, 1, 300, b'', chkp=6))
    return F


def malformed_frames():
    F = []

    def u(payload, a_to_b=True, **kw):
        F.append(udp_frame(payload, a_to_b, **kw))

    # too short for LTP (4 bytes): not dissected
    u(b'\x00\x01\x01\x00')
    # report claim count impossibly large
    u(report(1, 30, 1, 1, 10, 0, [(0, 10)], count=1000), a_to_b=False)
    # SDA recursion: the sub-service is SDA again
    u(data_seg(7, 31, 1, 2, 0, sdnv(2) + sdnv(1) + v6_bundle(b'x')))
    # SDA with a sub-service nobody handles
    u(data_seg(7, 31, 2, 2, 0, sdnv(9) + b'junk'))
    # control segments (types 10/11) after a segment: the minimum length
    # check looks at the whole datagram, so the next 'segment' throws
    u(hdr(10, 8, 1) + b'\x00')
    # client service data that is not a bundle
    u(data_seg(7, 31, 3, 1, 0, b'this is not a bundle at all'))
    # CSID 4 data that is not a byte string
    u(data_seg(7, 31, 4, 4, 0, b'\x01\x02\x03'))
    # CSID 4 with a byte string that is not a bundle
    u(data_seg(7, 31, 5, 4, 0, cbor_bstr(b'xyz')))
    # CSID 5 with data that is not a bundle
    u(data_seg(7, 31, 6, 5, 0, b'not bpv7'))
    # CSID 5 with a bundle followed by bytes that are not part of it: the
    # client service decodes less than the block (partial decode error)
    u(data_seg(7, 31, 7, 5, 0, v7_bundle(b'trailing') + b'\x00\x01\x02\x03'))
    # truncated data segments
    u(hdr(0, 32, 1) + sdnv(1))                       # no offset
    u(hdr(0, 32, 2) + sdnv(1) + sdnv(0))             # no length
    u(hdr(3, 32, 3) + sdnv(1) + sdnv(0) + sdnv(4))   # no checkpoint number
    u(hdr(3, 32, 4) + sdnv(1) + sdnv(0) + sdnv(4) + sdnv(1))   # no report number
    u(data_seg(0, 32, 5, 1, 0, b'ABCD', length=40))  # length beyond the datagram
    # an unterminated SDNV (continuation bit set on the last byte)
    u(hdr(0, 32, 6) + b'\x81\x82\x83\x84')
    # extensions with lengths beyond the datagram
    u(hdr(0, 33, 1, nh=1) + bytes([0]) + sdnv(1 << 40) + b'xx')
    u(hdr(0, 33, 2, nt=1) + sdnv(1) + sdnv(0) + sdnv(2) + b'ab' + bytes([0]) + sdnv(1 << 40))
    u(hdr(0, 33, 3, nh=2) + ext(0, b'x'))             # second extension missing
    # report segments cut short
    u(hdr(8, 34, 1) + sdnv(1) + sdnv(1) + sdnv(10) + sdnv(0) + sdnv(1) + sdnv(0))
    u(hdr(8, 34, 2) + sdnv(1))
    # report with upper bound below lower bound (huge length)
    u(report(1, 34, 3, 1, 0, 10, [(0, 1)]), a_to_b=False)
    # reception claim with a huge offset and length
    u(report(1, 34, 4, 1, 100, 0, [(1 << 62, 1 << 62), (0, 1)]), a_to_b=False)
    u(report(1, 34, 5, 1, 100, 50, [(0, 0), (0, 0)]), a_to_b=False)
    # claims running to the end of the 64 bit range
    u(report(1, 34, 6, 1, 100, 0, [((1 << 64) - 2, 1), (0, 1)]), a_to_b=False)
    # report acknowledgement without a serial number, cancel without reason
    u(hdr(9, 35, 1))
    u(hdr(12, 35, 2))
    # version 1 segment
    u(data_seg(3, 36, 1, 1, 0, b'ABCD')[:0] + bytes([0x13]) + data_seg(3, 36, 1, 1, 0, b'ABCD')[1:])
    # overlapping reassembly, conflicting data
    u(data_seg(0, 37, 1, 1, 0, b'AAAAAAAA'))
    u(data_seg(0, 37, 1, 1, 4, b'BBBBBBBB'))
    u(data_seg(3, 37, 1, 1, 2, b'CCCC', chkp=1))
    # EOB twice, beyond the first block
    u(data_seg(3, 38, 1, 1, 0, b'ABCDEFGH'))
    u(data_seg(3, 38, 1, 1, 100, b'ABCDEFGH'))
    # green data, EOB first and then more data
    u(data_seg(7, 38, 2, 5, 8, b'tail'))
    u(data_seg(4, 38, 2, 5, 0, b'head'))
    # Frames for the ltp_udp heuristic (UDP port 5000, only dissected
    # with the heuristic enabled): valid datagram, one that is not LTP
    # and one with a segment running past the end of the datagram.
    b1 = v6_bundle(b'heuristic')
    F.append(udp_frame(data_seg(7, 40, 1, 1, 0, b1), sport=5000, dport=5001))
    F.append(udp_frame(data_seg(0, 40, 2, 1, 0, b'ABCD', length=100) , sport=5000, dport=5001))
    F.append(udp_frame(b'GET / HTTP/1.1\r\nHost: x\r\n\r\n', sport=5000, dport=5001))
    F.append(udp_frame(data_seg(0, 40, 3, 1, 0, b'ABCD') + b'\x00', sport=5000, dport=5001))
    F.append(udp_frame(data_seg(0, 40, 4, 1, 0, b'ABCD') + data_seg(0, 40, 5, 1, 0, b'EFGH'),
                       sport=5000, dport=5001))
    F.append(udp_frame(b'\x00\x01\x02', sport=5000, dport=5001))
    F.append(udp_frame(hdr(0, 40, 6, nh=1) + bytes([0]) + sdnv(1 << 40) + b'xx',
                       sport=5000, dport=5001))
    return F


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'ltp-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'ltp-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
