# Generates test/captures/v150fw_coverage.pcap.gz
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


#!/usr/bin/env python3
"""Generate the synthetic captures for the V.150.1 state signalling event
dissector (packet-v150fw.c).

The dissector is registered as the RTP dynamic payload type "v150fw", so a
real trace reaches it the way this one does: a SIP INVITE / 200 OK exchange
carries SDP with "a=rtpmap:97 v150fw/8000", SDP sets up the RTP conversation
and the RTP packets with payload type 97 are handed to v150fw.  Every packet
is built from scratch with struct; addresses are from 192.0.2.0/24.

Usage: mkv150fw.py <output directory>

Writes:
  v150fw-coverage.pcap            SIP + SDP, then RTP carrying every event ID,
                                  reason ID code and extension layout
  v150fw-coverage-malformed.pcap  SSE payloads cut short
"""

A, B = '192.0.2.1', '192.0.2.2'
MAC_A = b'\x02\0\0\0\0\x01'
MAC_B = b'\x02\0\0\0\0\x02'


def sip_sdp(first_line, src, dst, rtp_ip, rtp_port, extra=''):
    sdp = ('v=0\r\no=- 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n'
           'm=audio %d RTP/AVP 0 97\r\na=rtpmap:0 PCMU/8000\r\n'
           'a=rtpmap:97 v150fw/8000\r\n' % (rtp_ip, rtp_ip, rtp_port))
    hdr = (first_line + '\r\nVia: SIP/2.0/UDP %s:5060;branch=z9hG4bK1\r\n'
           'From: <sip:alice@192.0.2.1>;tag=1\r\nTo: <sip:bob@192.0.2.2>%s\r\n'
           'Call-ID: v150fw-1@192.0.2.1\r\nCSeq: 1 INVITE\r\n'
           'Contact: <sip:%s:5060>\r\nContent-Type: application/sdp\r\n'
           'Content-Length: %d\r\n\r\n' % (src, extra, src, len(sdp)))
    return (hdr + sdp).encode()


def rtp(seq, pt, payload, marker=0, ssrc=0x11223344):
    return struct.pack('>BBHII', 0x80, (marker << 7) | pt, seq, 160 * seq, ssrc) + payload


def sse(event, frb, extb, ric, info, ext=b''):
    return bytes([(event << 2) | (frb << 1) | extb, ric]) + struct.pack('>H', info) + ext


def frame(src, dst, sp, dp, payload, ident):
    macs = (MAC_A, MAC_B) if src == A else (MAC_B, MAC_A)
    return ether(ip4(17, src, dst, udp(sp, dp, payload), ident), dst=macs[1], src=macs[0])


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    f = []
    n = [0]

    def add(src, dst, sp, dp, payload):
        n[0] += 1
        f.append(frame(src, dst, sp, dp, payload, n[0]))

    # 1-2: SIP: the INVITE offers A:20000, the 200 OK answers with B:30000
    add(A, B, 5060, 5060, sip_sdp('INVITE sip:bob@192.0.2.2 SIP/2.0', A, B, A, 20000))
    add(B, A, 5060, 5060, sip_sdp('SIP/2.0 200 OK', B, A, B, 30000, ';tag=2'))
    seq = [100, 200]

    def a2b(payload, pt=97):
        add(A, B, 20000, 30000, rtp(seq[0], pt, payload)); seq[0] += 1

    def b2a(payload, pt=97):
        add(B, A, 30000, 20000, rtp(seq[1], pt, payload)); seq[1] += 1

    # 3: a voice packet (PCMU) is not an SSE
    a2b(b'\xff' * 160, pt=0)
    # 4-10: every event ID in the table, with RIC NULL
    for ev in (0, 1, 2, 3, 4, 5, 6):
        a2b(sse(ev, 0, 0, 0, 0))
    # 11-12: reserved and vendor events, force response bit set
    b2a(sse(7, 1, 0, 0, 0))
    b2a(sse(40, 1, 0, 0, 0))
    # 13-52: every reason ID code from 0 to 39, from either side
    for ric in range(0, 40):
        (a2b if ric & 1 else b2a)(sse(3, 0, 0, ric, 0 if ric not in (1, 2, 18, 20) else 0))
    # reserved and vendor reason ID codes
    a2b(sse(1, 0, 0, 40, 0x1234))
    b2a(sse(1, 0, 0, 127, 0))
    a2b(sse(1, 0, 0, 128, 0xbeef))
    b2a(sse(1, 0, 0, 255, 0))
    # CM and JM: available modulations, one bit set each and all set
    for ric in (1, 2):
        for bit in range(16):
            a2b(sse(2, 0, 0, ric, 1 << bit))
        b2a(sse(2, 0, 0, ric, 0xffff))
    # timeout with each type and vendor info
    for ty in range(5):
        a2b(sse(3, 0, 0, 18, (ty << 8) | (0x10 * ty)))
    # timeout 0x0205: the reproducer of the field fix (type 2, vendor 5)
    b2a(sse(3, 1, 0, 18, 0x0205))
    # cleardown with each type and the reserved octet
    for ty in range(9):
        a2b(sse(3, 0, 0, 20, (ty << 8) | ty))
    b2a(sse(3, 1, 0, 20, 0x0400))
    # extension: reserved/length word then the cleardown vendor tag and info
    a2b(sse(3, 0, 1, 20, 0x0100, struct.pack('>H', 0x0002) + bytes([0xa5, 0x5a])))
    # extension on another RIC: the remaining octets as bytes
    b2a(sse(3, 0, 1, 16, 0, struct.pack('>H', 0x0803) + b'\x01\x02\x03'))
    a2b(sse(3, 0, 1, 1, 0xffff, struct.pack('>H', 0xf800) + b'\xaa' * 20))
    # extension bit set but only the 4 octet header: no extension is shown
    b2a(sse(3, 0, 1, 17, 0))
    # extension with exactly the length word and no further octets
    a2b(sse(3, 0, 1, 17, 0, struct.pack('>H', 0)))
    # an SSE with more octets than the header and no extension bit
    b2a(sse(2, 0, 0, 5, 0, b'trailing'))
    pcap(os.path.join(out, 'v150fw-coverage.pcap'), 1, f)

    # malformed: SSE payloads shorter than the 4 octet header
    f = []
    n[0] = 0
    add(A, B, 5060, 5060, sip_sdp('INVITE sip:bob@192.0.2.2 SIP/2.0', A, B, A, 20000))
    add(B, A, 5060, 5060, sip_sdp('SIP/2.0 200 OK', B, A, B, 30000, ';tag=2'))
    seq = [300, 400]
    a2b(b'\x04')
    b2a(b'\x04\x12')
    a2b(b'\x04\x12\x02')
    b2a(sse(3, 0, 1, 20, 0x0100, b'\x00\x02\xa5'))  # vendor info cut short
    pcap(os.path.join(out, 'v150fw-coverage-malformed.pcap'), 1, f)


main()
