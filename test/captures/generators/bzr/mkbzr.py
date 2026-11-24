#!/usr/bin/env python3
# Generates test/captures/bzr_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Bazaar smart protocol
dissector (packet-bzr.c).

Bazaar runs on TCP port 4155. A message is a protocol version line, a
length prefixed bencode header and body parts: 's' (prefixed bencode
structure), 'b' (prefixed bytes), 'o' (one octet, the result) and 'e'
(end). Every packet is built from scratch with struct; no captured
traffic is used.

Usage: mkbzr.py <output directory>

Writes:
  bzr-coverage.pcap             requests and responses with bencode headers,
                                structures, bytes and 'o' results, two
                                messages in one segment, messages spread
                                over several segments (also cut inside the
                                version line), an unknown part kind
  bzr-coverage-malformed.pcapng the body offset reproducer (TCP and
                                Exported PDU), header and body lengths that
                                wrap, a "\\r\\n" version line, truncated
                                messages, messages without an end marker or
                                version line end via Exported PDU
"""

import os
import struct
import sys

MAC_C = bytes.fromhex('020000000001')
MAC_S = bytes.fromhex('020000000002')
IP_C = bytes([192, 0, 2, 1])
IP_S = bytes([198, 51, 100, 2])
PORT = 4155
VERSION = b'bzr message 3 (bzr 1.6)\n'


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def tcp_frame(sport, dport, payload, seq, ack, src, dst, flags=0x18, ident=1):
    # SYNs carry an MSS option (a SYN without options looks like a scanner)
    opts = struct.pack('>BBHBBBB', 2, 4, 1460, 4, 2, 1, 1) if flags & 0x02 else b''
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags,
                      65535, 0, 0) + opts
    pseudo = struct.pack('>4s4sBBH', src, dst, 0, 6, len(tcp) + len(payload))
    c = csum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack('>H', c) + tcp[18:]
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), ident, 0,
                     64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    smac, dmac = (MAC_C, MAC_S) if src == IP_C else (MAC_S, MAC_C)
    return dmac + smac + b'\x08\x00' + ip + tcp + payload


class Conn:
    """One TCP connection between a client port and port 4155, with a
    three way handshake, so sequence numbers are tracked from the start."""

    def __init__(self, frames, cport):
        self.f = frames
        self.cport = cport
        self.cseq = 1000
        self.sseq = 5000
        self.add(True, b'', 0x02)
        self.add(False, b'', 0x12)
        self.add(True, b'', 0x10)

    def add(self, from_client, data, flags=0x18):
        if from_client:
            fr = tcp_frame(self.cport, PORT, data, self.cseq, self.sseq if flags != 0x02 else 0,
                           IP_C, IP_S, flags, ident=len(self.f) + 1)
            self.cseq += len(data) + (1 if flags & 0x03 else 0)
        else:
            fr = tcp_frame(PORT, self.cport, data, self.sseq, self.cseq, IP_S, IP_C, flags,
                           ident=len(self.f) + 1)
            self.sseq += len(data) + (1 if flags & 0x03 else 0)
        self.f.append(fr)
        return len(self.f)

    def close(self):
        self.add(True, b'', 0x11)
        self.add(False, b'', 0x11)
        self.add(True, b'', 0x10)


# bencode encoders -----------------------------------------------------------

def bstr(s):
    if isinstance(s, str):
        s = s.encode()
    return b'%d:' % len(s) + s


def bint(i):
    return b'i%de' % i


def blist(*items):
    return b'l' + b''.join(items) + b'e'


def bdict(*pairs):
    return b'd' + b''.join(bstr(k) + v for k, v in pairs) + b'e'


# bzr message parts ------------------------------------------------------------

def prefixed(b):
    return struct.pack('>I', len(b)) + b


def s(b):
    return b's' + prefixed(b)


def b(data):
    return b'b' + prefixed(data)


def o(c):
    return b'o' + c


def msg(header, *parts, version=VERSION):
    return version + prefixed(header) + b''.join(parts) + b'e'


HDR_REQ = bdict(('Software version', bstr('2.7.0')), ('context', bstr('bzr-coverage')))
HDR_RESP = bdict(('Software version', bstr('2.7.0')))


# pcap / pcapng writers --------------------------------------------------------

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def pcapng_block(btype, body):
    body += b'\0' * ((-len(body)) % 4)
    n = 12 + len(body)
    return struct.pack('<II', btype, n) + body + struct.pack('<I', n)


def write_pcapng(path, frames):
    """frames: (interface, data); interface 0 is Ethernet, 1 Exported PDU."""
    with open(path, 'wb') as f:
        f.write(pcapng_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        f.write(pcapng_block(1, struct.pack('<HHI', 1, 0, 262144)))
        f.write(pcapng_block(1, struct.pack('<HHI', 252, 0, 262144)))
        for i, (ifc, p) in enumerate(frames):
            ts = (1700000000 + i) * 1000000
            f.write(pcapng_block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                                len(p), len(p)) + p))


def exported_pdu(payload, name=b'bzr'):
    padded = name + b'\0' * (4 - len(name) % 4)
    return struct.pack('>HH', 12, len(padded)) + padded + struct.pack('>HH', 0, 0) + payload


# frames ---------------------------------------------------------------------

def main_frames():
    F = []

    # Connection 1 (frames 1-3 handshake)
    c = Conn(F, 40001)
    # 4: request: header dictionary, request tuple, end
    c.add(True, msg(HDR_REQ, s(blist(bstr('BzrDir.open_2.1'), bstr('/srv/repo/')))))
    # 5: response: success result, response tuple
    c.add(False, msg(HDR_RESP, o(b'S'), s(blist(bstr('yes'), bstr('no')))))
    # 6: request with bytes in its body (Repository.insert_stream style)
    c.add(True, msg(HDR_REQ, s(blist(bstr('Repository.get_stream'), bstr('/srv/repo/'),
                                     bstr('2a'))),
                    b(b'search-recipe\nancestry-of\nrev-1\n')))
    # 7: response with two byte chunks, then a structure trailer
    c.add(False, msg(HDR_RESP, o(b'S'), s(blist(bstr('ok'))), b(bytes(range(64))), b(b''),
                     s(bdict(('error', bint(0))))))
    # 8: error response
    c.add(False, msg(HDR_RESP, o(b'E'), s(blist(bstr('nosuchfile'), bstr('/srv/repo/x')))))
    # 9: two complete messages in one segment
    c.add(True, msg(HDR_REQ, s(blist(bstr('hello')))) +
          msg(HDR_REQ, s(blist(bstr('Branch.get_config_file'), bstr('trunk/')))))
    # 10: two responses in one segment
    c.add(False, msg(HDR_RESP, o(b'S'), s(blist(bstr('ok'), bstr('2')))) +
          msg(HDR_RESP, o(b'S'), s(blist(bstr('ok'))), b(b'[DEFAULT]\nnick = trunk\n')))
    # 11-13: one request spread over three segments, the first cut inside
    # the version line, the second inside a bytes part
    big = msg(HDR_REQ, s(blist(bstr('Repository.insert_stream_1.19'), bstr('/srv/repo/'),
                                bstr(''))),
              b(b'B' * 300), b(b'C' * 200))
    c.add(True, big[:10])
    c.add(True, big[10:200])
    c.add(True, big[200:])
    # 14-15: a response whose first segment ends after the version line and
    # the header length prefix (the header itself is in the next segment)
    r = msg(HDR_RESP, o(b'S'), s(blist(bstr('ok'))))
    c.add(False, r[:len(VERSION) + 4])
    c.add(False, r[len(VERSION) + 4:])
    # 16-17: a complete message followed by the start of the next one in
    # the same segment, the rest in the next segment
    m1 = msg(HDR_REQ, s(blist(bstr('Branch.last_revision_info'), bstr('trunk/'))))
    m2 = msg(HDR_REQ, s(blist(bstr('Repository.get_revision_graph'), bstr('/srv/repo/'))),
             b(b'rev-2\n'))
    c.add(True, m1 + m2[:40])
    c.add(True, m2[40:])
    # 18: response with an unknown part kind ('x') and a single octet part
    # that is neither 'S' nor 'E'
    c.add(False, msg(HDR_RESP, b'x', o(b'?'), s(blist(bstr('ok')))))
    # 19: a message with an empty header and no body parts
    c.add(True, msg(b''))
    # 20: a message with only the end marker after a list header, and a
    # nested structure body (list of dictionaries)
    c.add(False, msg(blist(bstr('header-as-list'), bint(3)),
                     s(blist(bdict(('revno', bint(42)), ('revid', bstr('rev-42'))),
                             bdict(('revno', bint(-1)), ('revid', bstr(''))))),
                     o(b'S')))
    c.close()

    # Connection 2: a message longer than one segment carried in five
    # segments, the bytes part split several times
    c = Conn(F, 40002)
    big = msg(HDR_REQ, s(blist(bstr('Repository.insert_stream'), bstr('/srv/big/'))),
              b(bytes(i & 0xff for i in range(3000))))
    for i in range(0, len(big), 700):
        c.add(True, big[i:i + 700])
    c.add(False, msg(HDR_RESP, o(b'S'), s(blist(bstr('ok')))))
    c.close()
    return F


def malformed_frames():
    F = []
    E = lambda data: F.append((0, data))
    X = lambda data: F.append((1, exported_pdu(data)))

    def tcp(port, data):
        E(tcp_frame(port, PORT, data, 1000, 1, IP_C, IP_S, ident=len(F) + 1))

    # 1: the reproducer bzr_body_loop.py over TCP: a "\r\n"
    # version line and an 's' part with length 0xfffffffb
    tcp(41001, b'X\r\n' + struct.pack('!I', 0) + b'o' + b's' + struct.pack('!I', 0xfffffffb)
        + b'e')
    # 2: the Exported PDU variant (bzr_body_loop_exppdu.pcap)
    X(b'X\n' + struct.pack('!I', 0) + b's' + struct.pack('!I', 0xfffffffb))
    # 3: a 'b' part with length 0xfffffffc (wraps to the same offset)
    X(VERSION + prefixed(b'') + b'b' + struct.pack('!I', 0xfffffffc) + b'e')
    # 4: header length 0xfffffffc over TCP: get_bzr_pdu_len() gives up and
    # the segment is desegmented forever (nothing dissected)
    tcp(41002, VERSION + struct.pack('!I', 0xfffffffc) + b'e')
    # 5: the same via Exported PDU: the header runs past the end
    X(VERSION + struct.pack('!I', 0xfffffffc) + b'e')
    # 6: an 's' part longer than the message, via TCP with an end marker
    # counted inside it
    tcp(41003, VERSION + prefixed(b'') + b's' + struct.pack('!I', 0xfffffff0) + b'e')
    # 7: Exported PDU without a line end: nothing but the protocol item
    X(b'bzr message 3 no newline')
    # 8: Exported PDU, a complete message and a second one without an end
    # marker (dissected as the rest of the data)
    X(msg(HDR_REQ, s(blist(bstr('hello')))) + VERSION + prefixed(HDR_REQ) + s(blist(bstr('x'))))
    # 9: Exported PDU, a message cut inside the header
    X(VERSION + prefixed(HDR_REQ)[:10])
    # 10: Exported PDU, a "\r\n" version line (the PDU length is one octet
    # off, so the body starts one octet early)
    X(b'bzr message 3 (bzr 1.6)\r\n' + prefixed(HDR_REQ) + s(blist(bstr('hello'))) + b'e')
    # 11: invalid bencode in the header (error expert from bencode)
    X(msg(b'i12x', s(b'q')))
    # 12: TCP, a "\r\n" version line followed by a valid message: the PDU
    # boundary is one octet off
    tcp(41004, b'bzr message 3 (bzr 1.6)\r\n' + prefixed(HDR_REQ) + s(blist(bstr('hello')))
        + b'e' + msg(HDR_REQ))
    # 13-14: TCP, a message whose first segment ends inside the header
    # length prefix: get_bzr_pdu_len() reads the 4 octet prefix past the
    # end of the segment and throws instead of asking for more data
    # (README observation 1)
    r = msg(HDR_RESP, o(b'S'), s(blist(bstr('ok'))))
    cut = len(VERSION) + 2
    E(tcp_frame(PORT, 41005, r[:cut], 7000, 1, IP_S, IP_C, ident=13))
    E(tcp_frame(PORT, 41005, r[cut:], 7000 + cut, 1, IP_S, IP_C, ident=14))
    # 15-16: the same with the cut inside the length prefix of a body part
    r = msg(HDR_REQ, s(blist(bstr('hello'))), b(b'data'))
    cut = len(VERSION) + 4 + len(HDR_REQ) + 3
    E(tcp_frame(41006, PORT, r[:cut], 8000, 1, IP_C, IP_S, ident=15))
    E(tcp_frame(41006, PORT, r[cut:], 8000 + cut, 1, IP_C, IP_S, ident=16))
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'bzr-coverage.pcap'), main_frames())
    write_pcapng(os.path.join(out, 'bzr-coverage-malformed.pcapng'), malformed_frames())


if __name__ == '__main__':
    main()
