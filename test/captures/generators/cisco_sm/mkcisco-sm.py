#!/usr/bin/env python3
# Generates test/captures/cisco_sm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Cisco Session
Management dissector (packet-cisco-sm.c, filter name "sm").

SM is carried by RUDP (Reliable UDP, packet-rudp.c), which has no
default port: dissect with -d udp.port==8003,rudp (RUDP calls SM for
everything after its header). A message starts with a 32 bit SM message
type; PDU messages (0x8000) carry a protocol type and a protocol
specific part: SS7 backhaul (any other protocol type), RUDP BSM v1 /
Q.931 (0x0004), EISUP (0x0100, 0x0122) and the reverse engineered
protocols 0x0101 and 0x0114 with an embedded SDP body. Every packet is
built from scratch with struct; no captured traffic is used.

Usage: mkcisco-sm.py <output directory>
Writes:
  cisco-sm-coverage.pcap            every session message type, every
                                    PDU protocol and every PDU message
                                    type with a dedicated decode
  cisco-sm-coverage-malformed.pcap  truncated messages and lengths past
                                    the end
"""
import os
import struct
import sys

PORT = 8003
CLIENT = (192, 0, 2, 1)
SERVER = (192, 0, 2, 2)


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ipv4(proto, payload, src, dst, ident):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                      64, proto, 0, bytes(src), bytes(dst))
    return hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:] + payload


def udp_frame(sport, dport, data, src, dst, ident):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(data), 0)
    pseudo = struct.pack('>4s4sBBH', bytes(src), bytes(dst), 0, 17, 8 + len(data))
    c = csum(pseudo + hdr + data) or 0xffff
    u = hdr[:6] + struct.pack('>H', c) + data
    return (bytes.fromhex('020000000002020000000001') + b'\x08\x00'
            + ipv4(17, u, src, dst, ident))


def rudp(seq, sm, ack=0, flags=0x40):
    """RUDP header: flags (ACK), header length 6, sequence, ack, checksum."""
    return struct.pack('>BBBBH', flags, 6, seq & 0xff, ack & 0xff, 0) + sm


def sm_session(msg_type, extra=b''):
    return struct.pack('>I', msg_type) + extra


def sm_pdu(protocol, msg_type, data=b'', msg_id=1, channel=0, bearer=0, length=None):
    """PDU with the SS7 backhaul / BSM v1 layout: message ID, message type,
    channel, bearer, length, data."""
    if length is None:
        length = len(data)
    return (struct.pack('>IH', 0x8000, protocol)
            + struct.pack('>HHHHH', msg_id, msg_type, channel, bearer, length) + data)


def sm_eisup(protocol, data, length=None):
    """Protocol 0x0100 / 0x0122: length and an EISUP message."""
    if length is None:
        length = len(data)
    return struct.pack('>IHH', 0x8000, protocol, length) + data


def sm_x101(protocol, tag, body=b'', ip=(10, 1, 2, 3), context=12345, msg_id=7):
    """Protocol 0x0101 / 0x0114: length, IP address, context, message id,
    tag; tag 0x01ac is followed by a length and an SDP body."""
    rest = bytes(ip) + struct.pack('>IBH', context, msg_id, tag)
    if tag == 0x01ac:
        rest += struct.pack('>H', len(body)) + body
    return struct.pack('>IHH', 0x8000, protocol, len(rest)) + rest


def u32(v):
    return struct.pack('>I', v)


SDP = (b'v=0\r\n'
       b'o=- 1 1 IN IP4 192.0.2.10\r\n'
       b's=-\r\n'
       b'c=IN IP4 192.0.2.10\r\n'
       b't=0 0\r\n'
       b'm=audio 49170 RTP/AVP 0\r\n')

# Q.931 SETUP, call reference 1, Bearer capability (speech, 64 kbit/s,
# circuit mode, A-law)
Q931_SETUP = bytes.fromhex('08010105' '04038090a3')
# Q.931 RELEASE COMPLETE, call reference 1 from the destination side
Q931_RELEASE_COMPLETE = bytes.fromhex('0801815a')

# MTP3 (ITU): SIO (national network, SI 1 = maintenance), routing label
# DPC 1, OPC 2, SLS 0, then an SLTM (H0/H1 0x11) with a 4 octet test
# pattern
MTP3_SLTM = bytes.fromhex('81') + struct.pack('<I', 1 | (2 << 14)) + bytes.fromhex('1140aabbccdd')
# The matching SLTA (H0/H1 0x21) from DPC 2 back to 1
MTP3_SLTA = bytes.fromhex('81') + struct.pack('<I', 2 | (1 << 14)) + bytes.fromhex('2140aabbccdd')


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def frames_from(msgs):
    F = []
    for i, (to_server, sm) in enumerate(msgs):
        src, dst = (CLIENT, SERVER) if to_server else (SERVER, CLIENT)
        sport, dport = (PORT, PORT)
        F.append(udp_frame(sport, dport, rudp(i + 1, sm, ack=i), src, dst, i + 1))
    return F


def main_frames():
    M = []
    # 1-10: session messages Start .. Q_RESET Response, 11: reserved type
    for t in range(10):
        M.append((t % 2 == 0, sm_session(t)))
    M.append((True, sm_session(0x20)))
    # SS7 backhaul (protocol 0x0001)
    P = 0x0001
    M += [
        # 12-13: Connect Request / Confirm, alignment types
        (True, sm_pdu(P, 0x06, u32(0x04), channel=1)),
        (False, sm_pdu(P, 0x07, u32(0x03), channel=1)),
        # 14-15: MSU Request / Indication, MTP3 SLTM / SLTA
        (True, sm_pdu(P, 0x10, MTP3_SLTM, msg_id=2, channel=1)),
        (False, sm_pdu(P, 0x11, MTP3_SLTA, msg_id=2, channel=1)),
        # 16-17: Disconnect Confirm / Indication, backhaul reason codes
        (False, sm_pdu(P, 0x0b, u32(0x00), channel=1)),
        (False, sm_pdu(P, 0x0c, u32(0x25), channel=1)),
        # 18: Retrieval Request (BSN), 19: Retrieval Confirm with BSN,
        # 20: Retrieval Confirm, request for MSUs (no BSN)
        (True, sm_pdu(P, 0x12, u32(0x01), channel=1)),
        (False, sm_pdu(P, 0x13, u32(0x01) + u32(127), channel=1)),
        (False, sm_pdu(P, 0x13, u32(0x02), channel=1)),
        # 21-22: LSC Request / Confirm, LSC state types
        (True, sm_pdu(P, 0x20, u32(0x0a), channel=1)),
        (False, sm_pdu(P, 0x21, u32(0x0b), channel=1)),
        # 23-24: LSC Indication, congestion (0x02) and physical layer up
        # (0x04) with a link down cause
        (False, sm_pdu(P, 0x22, u32(0x02) + u32(0x03), channel=1)),
        (False, sm_pdu(P, 0x22, u32(0x04) + u32(0x01), channel=1)),
        # 25: LSC Indication, protocol error (0x06) with a cause code
        (False, sm_pdu(P, 0x22, u32(0x06) + u32(0x02), channel=1)),
        # 26: LSC Indication, link is aligned (0x07), no further code
        (False, sm_pdu(P, 0x22, u32(0x07), channel=1)),
        # 27: Statistic Request
        (True, sm_pdu(P, 0x44, u32(0x01), channel=1)),
        # 28: Configuration Request (no dedicated decode): data
        (True, sm_pdu(P, 0x40, b'config', channel=2, bearer=3)),
        # 29: Status Request with length 0 (nothing follows)
        (True, sm_pdu(P, 0x42, b'', channel=2)),
        # 30: an unknown message type: data
        (True, sm_pdu(0x0002, 0x99, b'\x01\x02', msg_id=0xffff, channel=0xffff,
                      bearer=0xffff)),
    ]
    # RUDP BSM v1 (protocol 0x0004)
    P = 0x0004
    M += [
        # 31-32: MSU Request / Indication carry Q.931
        (True, sm_pdu(P, 0x10, Q931_SETUP, msg_id=3, channel=5, bearer=1)),
        (False, sm_pdu(P, 0x11, Q931_RELEASE_COMPLETE, msg_id=3, channel=5, bearer=1)),
        # 33: Connect Request with data: data
        (True, sm_pdu(P, 0x06, u32(0x04), channel=5)),
        # 34: Status Request with length 0
        (True, sm_pdu(P, 0x42, b'', channel=5)),
    ]
    M += [
        # 35-36: protocols 0x0100 and 0x0122, an EISUP message as data
        (True, sm_eisup(0x0100, b'\x01\x02\x03\x04eisup')),
        (False, sm_eisup(0x0122, b'\x05\x06eisup-122')),
        # 37: protocol 0x0100 with an empty EISUP message
        (True, sm_eisup(0x0100, b'')),
        # 38-39: protocols 0x0101 and 0x0114 with an SDP body (tag 0x01ac)
        (True, sm_x101(0x0101, 0x01ac, SDP)),
        (False, sm_x101(0x0114, 0x01ac, SDP, ip=(10, 3, 2, 1), context=54321, msg_id=8)),
        # 40-41: protocols 0x0101 and 0x0114 with another tag
        (True, sm_x101(0x0101, 0x0001)),
        (False, sm_x101(0x0114, 0x0002)),
    ]
    return frames_from(M)


def malformed_frames():
    M = [
        # 1: shorter than the SM message type
        (True, b'\x00\x00'),
        # 2: PDU without a protocol type
        (True, struct.pack('>I', 0x8000)),
        # 3: SS7 backhaul PDU cut in the header
        (True, sm_pdu(0x0001, 0x06, u32(4))[:12]),
        # 4: SS7 backhaul length past the end, Connect Request without
        # the alignment type
        (True, sm_pdu(0x0001, 0x06, b'', length=4)),
        # 5: Retrieval Confirm with BSN, BSN missing
        (True, sm_pdu(0x0001, 0x13, u32(1), length=8)),
        # 6: LSC Indication protocol error, cause code missing
        (True, sm_pdu(0x0001, 0x22, u32(6), length=8)),
        # 7: MSU Indication with a cut MTP3 message
        (True, sm_pdu(0x0001, 0x11, MTP3_SLTA[:3])),
        # 8: BSM v1 PDU cut in the header
        (True, sm_pdu(0x0004, 0x10, Q931_SETUP)[:10]),
        # 9: BSM v1 Q.931 length past the end
        (True, sm_pdu(0x0004, 0x10, Q931_SETUP, length=100)),
        # 10: EISUP without the length
        (True, struct.pack('>IH', 0x8000, 0x0100)),
        # 11: EISUP length past the end
        (True, sm_eisup(0x0122, b'abc', length=50)),
        # 12: protocol 0x0101 cut after the IP address
        (True, sm_x101(0x0101, 0x01ac, SDP)[:12]),
        # 13: protocol 0x0114 cut before the SDP length
        (True, sm_x101(0x0114, 0x01ac, SDP)[:19]),
        # 14: protocol 0x0101 SDP length past the end
        (True, sm_x101(0x0101, 0x01ac, SDP)[:30]),
    ]
    return frames_from(M)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'cisco-sm-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'cisco-sm-coverage-malformed.pcap'), malformed_frames())


if __name__ == '__main__':
    main()
