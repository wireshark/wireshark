#!/usr/bin/env python3
# Generates test/captures/bfcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BFCP dissector (packet-bfcp.c).

Binary Floor Control Protocol (RFC 8855). BFCP has no port of its own; the
dissector is reached through an SDP "m=application <port> UDP/BFCP" media
description (which registers a UDP conversation), through Decode As
(tcp.port / udp.port), or through the bfcp_tcp / bfcp_udp heuristics, which
are disabled by default. Every packet is built from scratch with struct; no
captured traffic is used.

Usage: mkbfcp.py <output directory>

Writes:
  bfcp-coverage.pcap            SIP INVITE / 200 OK with UDP/BFCP SDP, the
                                zero padding reproducer, every primitive and
                                attribute over UDP (BFCPv2, also with R and F
                                bits and fragments), non-BFCP datagrams on the
                                BFCP conversation, and BFCPv1 over TCP port
                                5071 (needs -d tcp.port==5071,bfcp or the
                                bfcp_tcp heuristic)
  bfcp-coverage-malformed.pcap  attribute length below 2, truncated
                                attributes, nesting past the tree depth limit
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])
BFCP_UDP_PORT = 5070
BFCP_TCP_PORT = 5071


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, payload, src, dst, ident=1):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                     64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return ip + payload


def eth(dst, src, payload):
    return dst + src + b'\x08\x00' + payload


def udp_frame(payload, sport, dport, fwd=True, ident=1, cksum=True):
    src, dst = (IP_A, IP_B) if fwd else (IP_B, IP_A)
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
    if cksum:
        pseudo = struct.pack('>4s4sBBH', src, dst, 0, 17, 8 + len(payload))
        c = csum(pseudo + hdr + payload) or 0xffff
        hdr = hdr[:6] + struct.pack('>H', c)
    ip = ipv4(17, hdr + payload, src, dst, ident)
    return eth(MAC_B, MAC_A, ip) if fwd else eth(MAC_A, MAC_B, ip)


def tcp_frame(payload, sport, dport, seq, ack, flags, fwd=True, ident=1):
    src, dst = (IP_A, IP_B) if fwd else (IP_B, IP_A)
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''  # MSS on SYN
    hdr = struct.pack('>HHIIBBHHH', sport, dport, seq, ack,
                      (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 6, len(hdr) + len(payload))
    c = csum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack('>H', c) + hdr[18:]
    ip = ipv4(6, hdr + payload, src, dst, ident)
    return eth(MAC_B, MAC_A, ip) if fwd else eth(MAC_A, MAC_B, ip)


# BFCP --------------------------------------------------------------------

def attr(t, val, m=1, pad=True):
    """A BFCP attribute: type<<1|M, length (without padding), value, and
    zero padding to a multiple of 4 octets when pad is set."""
    a = bytes([(t << 1) | m, 2 + len(val)]) + val
    if pad:
        a += b'\0' * (-len(a) % 4)
    return a


def u16(t, v, m=1):
    return attr(t, struct.pack('>H', v), m)


def BENEFICIARY_ID(v, m=1): return u16(1, v, m)
def FLOOR_ID(v, m=1): return u16(2, v, m)
def FLOOR_REQUEST_ID(v, m=1): return u16(3, v, m)
def PRIORITY(p, m=1): return u16(4, p << 13, m)
def REQUEST_STATUS(st, qpos, m=1): return attr(5, bytes([st, qpos]), m)
def ERROR_INFO(s, m=1): return attr(7, s, m)
def PART_PROV_INFO(s, m=1): return attr(8, s, m)
def STATUS_INFO(s, m=1): return attr(9, s, m)
def USER_DISPLAY_NAME(s, m=1): return attr(12, s, m)
def USER_URI(s, m=1): return attr(13, s, m)


def ERROR_CODE(code, details=b'', m=1):
    return attr(6, bytes([code]) + details, m)


def SUPPORTED_ATTRIBUTES(types, m=1):
    return attr(10, bytes((t << 1) for t in types), m)


def SUPPORTED_PRIMITIVES(prims, m=1):
    return attr(11, bytes(prims), m)


def grouped(t, hdr16, inner, m=1):
    """A grouped attribute: its length covers the header and all included
    attributes with their padding."""
    return bytes([(t << 1) | m, 4 + len(inner)]) + struct.pack('>H', hdr16) + inner


def BENEFICIARY_INFORMATION(bid, inner, m=1): return grouped(14, bid, inner, m)
def FLOOR_REQUEST_INFORMATION(frid, inner, m=1): return grouped(15, frid, inner, m)
def REQUESTED_BY_INFORMATION(rid, inner, m=1): return grouped(16, rid, inner, m)
def FLOOR_REQUEST_STATUS(fid, inner, m=1): return grouped(17, fid, inner, m)
def OVERALL_REQUEST_STATUS(frid, inner, m=1): return grouped(18, frid, inner, m)


def bfcp(prim, attrs=b'', ver=2, r=False, conf=1001, tid=1, uid=1,
         frag=None, plen=None):
    """A BFCP message. frag=(offset, length) sets the F bit and adds the
    fragment fields; plen then gives the total payload length (4 octet
    units) of the whole message."""
    first = (ver << 5) | (0x10 if r else 0) | (0x08 if frag else 0)
    if plen is None:
        plen = (len(attrs) + 3) // 4
    hdr = struct.pack('>BBHIHH', first, prim, plen, conf, tid, uid)
    if frag:
        hdr += struct.pack('>HH', *frag)
    return hdr + attrs


# SIP / SDP ---------------------------------------------------------------

def sdp(ip, port, setup):
    return ('v=0\r\n'
            'o=- 1 1 IN IP4 %s\r\n'
            's=-\r\n'
            'c=IN IP4 %s\r\n'
            't=0 0\r\n'
            'm=application %d UDP/BFCP *\r\n'
            'a=setup:%s\r\n'
            'a=floorctrl:c-s\r\n'
            'a=confid:1001\r\n'
            'a=userid:1\r\n'
            'a=floorid:5 mstrm:10\r\n' % (ip, ip, port, setup)).encode()


def sip(start, ip_from, body, cseq='1 INVITE'):
    hdrs = (start + '\r\n'
            'Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-bfcp-1\r\n'
            'From: <sip:alice@example.com>;tag=a1\r\n'
            'To: <sip:bob@example.org>%s\r\n'
            'Call-ID: bfcp-coverage-1@example.com\r\n'
            'CSeq: %s\r\n'
            'Contact: <sip:%s:5060>\r\n'
            'Content-Type: application/sdp\r\n'
            'Content-Length: %d\r\n\r\n'
            % ('' if start.startswith('INVITE') else ';tag=b1', cseq,
               ip_from, len(body)))
    return hdrs.encode() + body


# Zero padding reproducer (bfcp_zero_pad.py), byte for byte ---

def zero_pad_repro():
    a1 = attr(2, b'\x00\x05', pad=False) + b'\x00\x00\x00\x00' + attr(1, b'\x00\x07', pad=False) + \
        attr(13, b'sip:a', pad=False) + b'\x00'
    a2 = attr(2, b'\x00\x05', pad=False) + attr(1, b'\x00\x07', pad=False) + \
        attr(13, b'sip:a', pad=False) + b'\x00'

    def msg(attrs, plen=None):
        if plen is None:
            plen = (len(attrs) + 3) // 4
            attrs += b'\0' * (plen * 4 - len(attrs))
        return struct.pack('>BBHIHH', 0x20, 1, plen, 1, 1, 1) + attrs
    # The reproducer's UDP checksum is 0.
    return [udp_frame(msg(a2), 5070, 5070, cksum=False),
            udp_frame(msg(a1), 5070, 5070, cksum=False),
            udp_frame(msg(a1, 0xffff), 5070, 5070, cksum=False)]


# Main capture ------------------------------------------------------------

def floor_request_information(frid=0x11, granted=False):
    st = 3 if granted else 1
    return FLOOR_REQUEST_INFORMATION(frid,
        OVERALL_REQUEST_STATUS(frid,
            REQUEST_STATUS(st, 0 if granted else 2) +
            STATUS_INFO(b'ok, queued'))         # length 12, no padding
        + FLOOR_REQUEST_STATUS(5,
            REQUEST_STATUS(st, 1) +
            STATUS_INFO(b'fl'))                 # length 4
        + BENEFICIARY_INFORMATION(7,
            USER_DISPLAY_NAME(b'Bob Smith ') + # length 12
            USER_URI(b'sip:bob@b.org'))         # length 15 + 1 pad
        + REQUESTED_BY_INFORMATION(9,
            USER_DISPLAY_NAME(b'Chair Carl') +  # length 12
            USER_URI(b'sip:carl@c.org'))       # length 16
        + PRIORITY(4)
        + PART_PROV_INFO(b'please!!!!', m=0))  # length 12


def main_udp():
    """BFCPv2 over the SDP negotiated UDP conversation (port 5070)."""
    msgs = []

    def add(prim, attrs=b'', fwd=True, **kw):
        kw.setdefault('r', not fwd)
        msgs.append((bfcp(prim, attrs, **kw), fwd))

    # Hello / HelloAck with the supported primitives and attributes.
    add(11, tid=1)
    add(12, SUPPORTED_PRIMITIVES(range(1, 18)) +           # length 19, pad 1
        SUPPORTED_ATTRIBUTES(range(1, 19)), fwd=False, tid=1)  # length 20
    add(12, SUPPORTED_PRIMITIVES([1, 2, 3, 4, 11, 12]) +  # length 8, no pad
        SUPPORTED_ATTRIBUTES([1, 2, 3, 4, 5]), fwd=False, tid=2)  # length 7
    # FloorRequest (1) with every simple attribute a client sends.
    add(1, FLOOR_ID(5) + BENEFICIARY_ID(7, m=0) +
        PART_PROV_INFO(b'I would like to talk') +  # length 22, pad 2
        PRIORITY(2), tid=3)
    add(4, floor_request_information(0x11), fwd=False, tid=3)
    add(14, tid=3, r=False)
    # FloorRequestQuery (3) and the status with the grant.
    add(3, FLOOR_REQUEST_ID(0x11), tid=4)
    add(4, floor_request_information(0x11, granted=True), fwd=False, tid=4)
    # UserQuery / UserStatus.
    add(5, BENEFICIARY_ID(7), tid=5)
    add(6, BENEFICIARY_INFORMATION(7,
            USER_DISPLAY_NAME(b'Bo') + USER_URI(b'sip:bob@b.org'))
        + floor_request_information(0x11, granted=True), fwd=False, tid=5)
    # FloorQuery / FloorStatus / FloorStatusAck.
    add(7, FLOOR_ID(5) + FLOOR_ID(6, m=0), tid=6)
    add(8, FLOOR_ID(5) + floor_request_information(0x11, granted=True)
        + floor_request_information(0x12), fwd=False, tid=6)
    add(15, tid=6, r=False)
    # ChairAction / ChairActionAck.
    add(9, FLOOR_REQUEST_INFORMATION(0x12,
            FLOOR_REQUEST_STATUS(5, REQUEST_STATUS(4, 0)) +
            STATUS_INFO(b'Denied by chair')), tid=7)  # length 17, pad 3
    add(10, fwd=False, tid=7)
    # FloorRelease (2) and the Released status.
    add(2, FLOOR_REQUEST_ID(0x11), tid=8)
    add(4, FLOOR_REQUEST_INFORMATION(0x11,
            OVERALL_REQUEST_STATUS(0x11, REQUEST_STATUS(6, 0))),
        fwd=False, tid=8)
    # Error with every code: without details, with details (unknown
    # attributes) and padding, and ERROR-INFO text with each padding.
    for code in range(1, 15):
        add(13, ERROR_CODE(code), fwd=False, tid=20 + code, r=True)
    add(13, ERROR_CODE(4, bytes([20 << 1, 21 << 1])) +   # length 5, pad 3
        ERROR_INFO(b'unknown mandatory attr'), fwd=False, tid=40)  # 24, pad 0
    add(13, ERROR_CODE(4, bytes([20 << 1, 21 << 1, 22 << 1, 23 << 1, 24 << 1])) +  # 8
        ERROR_INFO(b'x'), fwd=False, tid=41)  # length 3, pad 1
    add(13, ERROR_CODE(3, b'\x2a') + ERROR_INFO(b'Unknown primitive'),  # 4; 19 pad 1
        fwd=False, tid=42)
    # Strings without padding and with each amount of padding, a request
    # status of every value, and an unknown attribute type and type 0.
    add(4, FLOOR_REQUEST_INFORMATION(0x13,
            OVERALL_REQUEST_STATUS(0x13, REQUEST_STATUS(0, 0)) +
            OVERALL_REQUEST_STATUS(0x13, REQUEST_STATUS(2, 0)) +
            OVERALL_REQUEST_STATUS(0x13, REQUEST_STATUS(5, 0)) +
            OVERALL_REQUEST_STATUS(0x13, REQUEST_STATUS(7, 0)) +
            OVERALL_REQUEST_STATUS(0x13, REQUEST_STATUS(8, 0)))
        + STATUS_INFO(b'ab')               # length 4
        + STATUS_INFO(b'abc')              # length 5, pad 3
        + USER_DISPLAY_NAME(b'abcd')       # 6, pad 2
        + USER_URI(b'sip:x@y.z.')          # 12
        + PART_PROV_INFO(b'ab')            # 4
        + ERROR_INFO(b'abcdef')            # 8
        + attr(20, b'\x01\x02\x03\x04\x05\x06')  # unknown type 20, length 8
        + attr(0, b'\xaa\xbb'),            # type 0 with M set
        fwd=False, tid=50)
    # The grouped attribute budget leaves out the padding of the included
    # attributes (packet-bfcp.c:504): with 3 padding octets in the
    # BENEFICIARY-INFORMATION the PRIORITY after it is shown inside it.
    add(4, FLOOR_REQUEST_INFORMATION(0x14,
            BENEFICIARY_INFORMATION(8, USER_DISPLAY_NAME(b'Eve')) +  # 5, pad 3
            PRIORITY(3)), fwd=False, tid=51)
    # Goodbye / GoodbyeAck.
    add(16, tid=60)
    add(17, fwd=False, tid=60)
    return msgs


def fragments():
    """A UserStatus split into three fragments on attribute boundaries
    (F bit, RFC 8855 section 6.2.3), and a fragmented FloorStatus request
    (F without R). The dissector shows each fragment; it does not
    reassemble."""
    whole = (BENEFICIARY_INFORMATION(7,
                USER_DISPLAY_NAME(b'Bobby Bobsson') +  # 15, pad 1
                USER_URI(b'sip:bobby@example.com.'))  # 24
             + floor_request_information(0x21, granted=True)
             + FLOOR_ID(5))
    a = BENEFICIARY_INFORMATION(7,
            USER_DISPLAY_NAME(b'Bobby Bobsson') +
            USER_URI(b'sip:bobby@example.com.'))
    b = floor_request_information(0x21, granted=True)
    c = FLOOR_ID(5)
    assert whole == a + b + c
    assert len(a) % 4 == 0 and len(b) % 4 == 0
    plen = len(whole) // 4
    out = []
    off = 0
    for part in (a, b, c):
        out.append((bfcp(6, part, r=True, tid=70, plen=plen,
                         frag=(off, len(part) // 4)), False))
        off += len(part) // 4
    req = FLOOR_ID(5) + FLOOR_ID(6) + FLOOR_ID(7)
    out.append((bfcp(7, req[:8], tid=71, plen=3, frag=(0, 2)), True))
    out.append((bfcp(7, req[8:], tid=71, plen=3, frag=(2, 1)), True))
    return out


def not_bfcp():
    """Datagrams on the BFCP conversation that fail the dissector's check:
    returned to UDP and shown as data."""
    return [
        b'\x40\x01\x00\x00\x00\x00',                       # shorter than 12
        b'\x60\x01\x00\x00\x00\x00\x00\x01\x00\x01\x00\x01',  # version 3
        b'\x40\x00\x00\x00\x00\x00\x00\x01\x00\x01\x00\x01',  # primitive 0
        b'\x40\x12\x00\x00\x00\x00\x00\x01\x00\x01\x00\x01',  # primitive 18
        b'\x40\x13\x00\x00\x00\x00\x00\x01\x00\x01\x00\x01',  # primitive 19
    ]


def main_tcp():
    """BFCPv1 over TCP (RFC 8855 section 6.2 reliable transport), one
    message per segment."""
    cp, sp = 40071, BFCP_TCP_PORT
    cseq, sseq = 1000, 5000
    frames = [tcp_frame(b'', cp, sp, cseq, 0, 0x02),
              tcp_frame(b'', sp, cp, sseq, cseq + 1, 0x12, fwd=False),
              tcp_frame(b'', cp, sp, cseq + 1, sseq + 1, 0x10)]
    cseq += 1
    sseq += 1
    msgs = [
        (bfcp(11, ver=1, tid=101, conf=2002, uid=3), True),
        (bfcp(12, SUPPORTED_PRIMITIVES(range(1, 18)) +
              SUPPORTED_ATTRIBUTES(range(1, 19)), ver=1, r=True, tid=101,
              conf=2002, uid=3), False),
        (bfcp(1, FLOOR_ID(9) + PRIORITY(1), ver=1, tid=102, conf=2002, uid=3), True),
        (bfcp(4, floor_request_information(0x31), ver=1, r=True, tid=102,
              conf=2002, uid=3), False),
        (bfcp(14, ver=1, tid=102, conf=2002, uid=3), True),
        (bfcp(2, FLOOR_REQUEST_ID(0x31), ver=1, tid=103, conf=2002, uid=3), True),
        (bfcp(4, FLOOR_REQUEST_INFORMATION(0x31,
              OVERALL_REQUEST_STATUS(0x31, REQUEST_STATUS(6, 0))),
              ver=1, r=True, tid=103, conf=2002, uid=3), False),
        (bfcp(16, ver=1, tid=104, conf=2002, uid=3), True),
        (bfcp(17, ver=1, r=True, tid=104, conf=2002, uid=3), False),
    ]
    for m, fwd in msgs:
        if fwd:
            frames.append(tcp_frame(m, cp, sp, cseq, sseq, 0x18))
            cseq += len(m)
        else:
            frames.append(tcp_frame(m, sp, cp, sseq, cseq, 0x18, fwd=False))
            sseq += len(m)
    frames += [tcp_frame(b'', cp, sp, cseq, sseq, 0x11),
               tcp_frame(b'', sp, cp, sseq, cseq + 1, 0x11, fwd=False),
               tcp_frame(b'', cp, sp, cseq + 1, sseq + 1, 0x10)]
    return frames


def main_capture():
    frames = [
        udp_frame(sip('INVITE sip:bob@example.org SIP/2.0', '192.0.2.1',
                      sdp('192.0.2.1', BFCP_UDP_PORT, 'actpass')), 5060, 5060),
        udp_frame(sip('SIP/2.0 200 OK', '192.0.2.2',
                      sdp('192.0.2.2', BFCP_UDP_PORT, 'active')), 5060, 5060,
                  fwd=False),
    ]
    frames += zero_pad_repro()
    ident = 10
    for m, fwd in main_udp() + fragments():
        frames.append(udp_frame(m, BFCP_UDP_PORT, BFCP_UDP_PORT, fwd, ident))
        ident += 1
    for m in not_bfcp():
        frames.append(udp_frame(m, BFCP_UDP_PORT, BFCP_UDP_PORT, True, ident))
        ident += 1
    frames += main_tcp()
    return frames


# Malformed capture -------------------------------------------------------

def malformed_capture():
    msgs = [
        # Attribute length 0 and 1: "Attribute length is too small".
        bfcp(1, bytes([2 << 1 | 1, 0, 0, 5])),
        bfcp(1, FLOOR_ID(5) + bytes([1 << 1 | 1, 1, 0, 7])),
        # A grouped attribute with length 1.
        bfcp(4, bytes([15 << 1 | 1, 1, 0, 0x11])),
        # Attributes cut short by the end of the datagram.
        bfcp(1, bytes([2 << 1 | 1, 4, 0]), plen=1),
        bfcp(1, bytes([13 << 1 | 1, 40]) + b'sip:', plen=10),
        bfcp(4, FLOOR_REQUEST_INFORMATION(0x11, b'')[:3], plen=1),
        bfcp(13, bytes([6 << 1 | 1, 20, 4]) + b'\x28', plen=6),
        bfcp(12, bytes([11 << 1 | 1, 30, 1, 2, 3]), plen=8),
        bfcp(12, bytes([10 << 1 | 1, 30, 2, 4, 6]), plen=8),
        bfcp(4, bytes([20 << 1, 40, 1, 2]), plen=10),
        # ERROR-CODE with length 2 (smaller than its fixed part).
        bfcp(13, bytes([6 << 1 | 1, 2]) + FLOOR_ID(5)),
    ]
    # Each level claims 252 octets, so the budget covers the next level.
    deep = b''
    for i in range(520):
        deep += bytes([15 << 1 | 1, 0xfc]) + struct.pack('>H', i & 0xffff)
    deep += FLOOR_ID(5)
    msgs.append(bfcp(4, deep))  # nested past the tree depth limit
    frames = [udp_frame(m, BFCP_UDP_PORT, BFCP_UDP_PORT, True, 200 + i)
              for i, m in enumerate(msgs)]
    return frames


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bfcp-coverage.pcap'), main_capture())
    write_pcap(os.path.join(out, 'bfcp-coverage-malformed.pcap'), malformed_capture())


if __name__ == '__main__':
    main()
