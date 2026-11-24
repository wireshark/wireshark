#!/usr/bin/env python3
# Generates test/captures/ipdc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the IPDC coverage captures (synthetic traffic only).
Usage: mkipdc.py <outdir> [-v]"""
# ---- helpers (synthetic traffic only; documentation addresses) ----
import struct
import sys
import os

def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def _ip4(a):
    return bytes(int(x) for x in a.split('.'))

_ETH = bytes.fromhex('020000000002') + bytes.fromhex('020000000001')

def eth_ip(src, dst, proto, seg, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(seg), ident, 0x4000, 64, proto, 0, _ip4(src), _ip4(dst))
    h = h[:10] + struct.pack('!H', _csum(h)) + h[12:]
    return _ETH + b'\x08\x00' + h + seg

def tcp(src, dst, sport, dport, seq, ack, payload, flags=0x18):
    opt = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''
    hdr = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt
    pseudo = _ip4(src) + _ip4(dst) + struct.pack('!BBH', 0, 6, len(hdr) + len(payload))
    hdr = hdr[:16] + struct.pack('!H', _csum(pseudo + hdr + payload)) + hdr[18:]
    return eth_ip(src, dst, 6, hdr + payload)

def udp(src, dst, sport, dport, payload):
    seg = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth_ip(src, dst, 17, seg)

class Tcp:
    """One TCP connection; send() appends a data frame from the client
    ('c') or the server ('s') and tracks the sequence numbers."""
    def __init__(self, frames, c, s, cport, sport, handshake=True):
        self.f, self.c, self.s, self.cp, self.sp = frames, c, s, cport, sport
        self.cseq, self.sseq = 1000, 5000
        if handshake:
            self.f.append(tcp(c, s, cport, sport, self.cseq, 0, b'', 0x02)); self.cseq += 1
            self.f.append(tcp(s, c, sport, cport, self.sseq, self.cseq, b'', 0x12)); self.sseq += 1
            self.f.append(tcp(c, s, cport, sport, self.cseq, self.sseq, b'', 0x10))
    def send(self, who, data):
        if who == 'c':
            self.f.append(tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, data))
            self.cseq += len(data)
        else:
            self.f.append(tcp(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, data))
            self.sseq += len(data)
    def fin(self):
        self.f.append(tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, b'', 0x11))

def write_pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            orig = len(fr)
            if isinstance(fr, tuple):
                fr, orig = fr
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(fr), orig))
            f.write(fr)

def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def write_pcapng(path, linktypes, frames):
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(path, 'wb').write(out)

def exp_tlv(tag, val):
    return struct.pack('!HH', tag, len(val)) + val

def exported_pdu(name, payload):
    return exp_tlv(12, name.encode()) + struct.pack('!HH', 0, 0) + payload

CL, SV = '192.0.2.10', '192.0.2.20'      # gateway, softswitch
LABELS = []

def mark(frames, text):
    LABELS.append((len(frames) + 1, text))

# tag number lists by type, from ipdc_tag_types[] of packet-ipdc.c
UINT = [1, 4, 7, 13, 21, 28, 32, 34, 40, 41, 44, 49, 50, 54, 55, 56, 57, 59, 62, 64, 70, 94, 96, 103, 104,
        113, 115, 124, 126, 145, 146, 147, 148, 149, 150, 151, 152, 153, 157, 158, 159, 160, 161, 166, 167,
        194, 195, 254]
ASCII = [2, 3, 5, 24, 25, 51, 52, 61]
BYTE = [10, 12, 20, 23, 36, 38, 39, 42, 43, 45, 53, 60, 73, 74, 101, 102, 106, 114, 116, 117, 118, 119, 120,
        123, 125, 134, 144, 163, 164, 165, 176, 177, 193]
IPA = [27, 58, 93, 95, 105]
OCTET = [37, 178, 179]
CODES = [0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x09, 0x0a, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x41, 0x42,
         0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x51, 0x53, 0x55, 0x56, 0x61, 0x62, 0x63, 0x64,
         0x71, 0x72, 0x73, 0x74, 0x79, 0x7a, 0x7d, 0x7e, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
         0x91, 0x92, 0xf0, 0xff]

def tag(t, val):
    return bytes([t, len(val)]) + val

def pdu(nr, ns, tid, code, tags=b'', end=True, proto=1, extra=b''):
    """An IPDC PDU: r, s, flags and 10 bit length, protocol id, transaction id
    size and id, message code and the tags. The length counts everything
    after the first four octets."""
    body = bytes([proto, 4]) + struct.pack('!IH', tid, code) + tags + (b'\x00' if end else b'') + extra
    return bytes([nr, ns]) + struct.pack('!H', len(body)) + body

def ack(nr, ns):
    return bytes([nr, ns, 0, 0])

Q931 = bytes.fromhex('080101' '05' '04038090a3' '18018a')   # SETUP with a bearer capability and a channel id

def main():
    out = sys.argv[1]
    frames = []
    t = Tcp(frames, CL, SV, 44000, 6668)
    mark(frames, 'acknowledgement and message codes')
    t.send('c', ack(0, 1))
    tid = 0x100
    for i in range(0, len(CODES), 4):
        data = b''
        for c in CODES[i:i + 4]:
            tid += 1
            data += pdu(i & 0xff, 1 + (c & 7), tid, c, tag(0x01, b'\x02') + tag(0x02, b'gw1'))
        t.send('c' if i % 8 == 0 else 's', data)
    t.send('c', pdu(1, 1, 0xdead, 0x0123, tag(0x01, b'\x02')))        # message code that is not defined
    mark(frames, 'tags by type')
    # unsigned integers and bytes: lengths 1-4, defined and undefined enumerations
    t.send('c', pdu(2, 1, 0x200, 0x01,
                    tag(0x01, b'\x01') + tag(0x01, b'\x4d') +              # known / unknown enumeration
                    tag(0x04, b'\x01\x02') + tag(0x07, b'\x01\x02\x03') + tag(0x0d, b'\x01\x02\x03\x04') +
                    tag(0x15, b'\x01\x02\x03\x04\x05') +                    # more than 4 octets: ignored
                    tag(0x1c, b'') +                                         # empty: value 0
                    tag(0x0a, b'\x03') + tag(0x0a, b'\xff') + tag(0x0c, b'\x00\x01')))
    # every UINT, BYTE and ASCII tag
    for group, mk in ((UINT, lambda x: b'\x01'), (BYTE, lambda x: b'\x01'),
                      (ASCII, lambda x: b'text'), (UINT, lambda x: b'\x00\x10\x00')):
        for i in range(0, len(group), 12):
            tags = b''.join(tag(x, mk(x)) for x in group[i:i + 12])
            t.send('c', pdu(3, 1, 0x300 + i, 0x02, tags))
    t.send('c', pdu(3, 2, 0x310, 0x02, tag(0x02, b'') + tag(0x03, b'x' * 255) + tag(0x05, b'ctl\r\n')))
    # IP addresses: 4 octets, 6 octets (with a port), another length (warning)
    ip = b''.join(tag(x, bytes([192, 0, 2, x & 0x7f])) for x in IPA)
    t.send('c', pdu(4, 1, 0x400, 0x03, ip))
    t.send('c', pdu(4, 2, 0x401, 0x03, tag(0x1b, bytes([192, 0, 2, 7, 0x1a, 0x0c])) + tag(0x3a, bytes([192, 0, 2, 8, 0, 80]))))
    t.send('c', pdu(4, 3, 0x402, 0x03, tag(0x1b, bytes([192, 0, 2, 7, 1])) + tag(0x5d, b'') + tag(0x5f, bytes(8))))
    # line and channel status arrays: every defined status, one undefined
    t.send('c', pdu(5, 1, 0x500, 0x04,
                    tag(0x21, bytes([0, 1, 2, 3, 4, 5, 6, 9])) + tag(0x23, bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 99])) +
                    tag(0x21, b'') + tag(0x23, b'')))
    # encoding types: one octet, two octets, undefined
    t.send('c', pdu(5, 2, 0x501, 0x05,
                    tag(0x6f, b'\x00') + tag(0x70, b'\x08') + tag(0x6f, b'\x12\x07') + tag(0x70, b'\x60\x01') +
                    tag(0x6f, b'\x04') + tag(0x70, b'\x61') + tag(0x6f, b'\x55')))
    # Q.931 inside a tag
    t.send('c', pdu(6, 1, 0x600, 0x41, tag(0xa2, Q931) + tag(0x01, b'\x01')))
    # octets (TBD type) and unknown tags
    t.send('c', pdu(6, 2, 0x601, 0x42, tag(0x25, b'\x01\x02\x03') + tag(0xb2, b'\x01\x02') + tag(0xb3, b'') + tag(0x06, b'\xaa\xbb') + tag(0xee, b'abc')))
    # the end of the tags is not at the end of the data
    t.send('c', pdu(6, 3, 0x602, 0x43, tag(0x01, b'\x02'), extra=b'trailing octets'))
    t.send('c', pdu(6, 4, 0x603, 0x43, b'', end=True))               # no tags at all
    mark(frames, 'segmentation')
    two = pdu(7, 1, 0x700, 0x01, tag(0x02, b'first')) + pdu(7, 2, 0x701, 0x01, tag(0x02, b'second'))
    t.send('c', two)
    big = pdu(7, 3, 0x702, 0x01, b''.join(tag(0x02, b'segment %d' % i) for i in range(30)))
    t.send('c', big[:3])                                              # not even the length
    t.send('c', big[3:20])
    t.send('c', big[20:])
    t.send('c', ack(8, 0) + pdu(8, 1, 0x800, 0x01, tag(0x02, b'after an ack')))
    t.fin()
    write_pcap(os.path.join(out, 'ipdc-coverage.pcap'), frames)
    n_main = len(frames)

    # ---- malformed capture ----
    frames = []
    t = Tcp(frames, CL, SV, 45000, 6668)
    mark(frames, 'MALFORMED capture')
    t.send('c', pdu(1, 1, 1, 0x01, tag(0x02, b'no end of tags'), end=False))            # tags run to the end of the PDU
    t.send('c', pdu(1, 2, 2, 0x01, tag(0x02, b'abc')[:-1] + b'\x20', end=False))        # tag length past the end
    t.send('c', pdu(1, 3, 3, 0x01, bytes([0x02])))                                     # tag without a length
    t.send('c', pdu(1, 4, 4, 0x01, tag(0xa2, Q931[:3]) ))                             # truncated Q.931
    t.send('c', bytes([1, 5]) + struct.pack('!H', 6) + bytes([1, 4, 0, 0, 0, 1]))     # PDU shorter than the header
    t.send('c', bytes([1, 6]) + struct.pack('!H', 1) + b'\x01')                       # length 1
    t.send('c', pdu(1, 7, 7, 0x01, tag(0x1b, bytes([1, 2, 3, 4])), end=False)[:-2])    # IP address tag cut short
    t.send('c', pdu(1, 8, 8, 0x01, tag(0x21, bytes([0, 1, 2])), end=False)[:-2])       # status array cut short
    t.send('c', pdu(1, 9, 9, 0x01, tag(0x6f, b'\x01\x02\x03')))                       # encoding type with 3 octets
    t.send('c', pdu(1, 10, 10, 0x01, tag(0x01, b'\x01\x02\x03\x04\x05\x06') + tag(0x25, b'')))
    write_pcap(os.path.join(out, 'ipdc-coverage-malformed.pcap'), frames)
    if '-v' in sys.argv:
        for n, s in LABELS:
            print(n, s)
        print('main frames', n_main, 'malformed frames', len(frames))

main()
