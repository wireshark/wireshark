#!/usr/bin/env python3
# Generates test/captures/pppoe_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the PPPoE coverage captures. Usage: mkpppoe.py <outdir> [-v].
Synthetic data only (documentation addresses and made-up names)."""
import struct
import sys

CLI = b'\x02\x00\x00\x00\x00\x01'
AC = b'\x02\x00\x00\x00\x00\x02'
BCAST = b'\xff' * 6

VER = 0x11


def eth(dst, src, etype, payload):
    return dst + src + struct.pack('!H', etype) + payload


def pppoe(code, sid, body, length=None, ver=VER):
    n = len(body) if length is None else length
    return bytes([ver, code]) + struct.pack('!HH', sid, n) + body


def tag(t, data=b'', length=None):
    return struct.pack('!HH', t, len(data) if length is None else length) + data


def sub(t, data=b'', length=None):
    return bytes([t, len(data) if length is None else length]) + data


def vendor_dslf(*subs):
    return tag(0x0105, struct.pack('!I', 3561) + b''.join(subs))


def ppp(proto, data):
    return struct.pack('!H', proto) + data


def lcp(code, ident, data=b''):
    return struct.pack('!BBH', code, ident, 4 + len(data)) + data


IPV4 = bytes([0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2]) + \
    struct.pack('!HHHH', 1000, 2000, 8, 0)

BIG = bytes([0x45, 0, 0, 78, 0, 1, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2]) + \
    struct.pack('!HHHH', 1000, 2000, 58, 0) + bytes(range(50))

CODES = {'PADI': 0x09, 'PADO': 0x07, 'PADR': 0x19, 'PADS': 0x65, 'PADT': 0xa7,
         'PADG': 0x0a, 'PADC': 0x0b, 'PADQ': 0x0c, 'PADM': 0xd3, 'PADN': 0xd4}


class Cap:
    def __init__(self):
        self.frames = []     # (interface, bytes, origlen)
        self.marks = []

    def note(self, label):
        self.marks.append((len(self.frames) + 1, label))

    def d(self, code, body, sid=0, dst=BCAST, src=CLI, length=None, ver=VER):
        c = CODES[code] if isinstance(code, str) else code
        self.frames.append((0, eth(dst, src, 0x8863, pppoe(c, sid, body, length, ver)), None))

    def s(self, body, sid=0x1234, length=None, dst=AC, src=CLI, code=0, ver=VER, pad=b'', origlen=None):
        data = eth(dst, src, 0x8864, pppoe(code, sid, body, length, ver)) + pad
        self.frames.append((0, data, origlen))

    def s51(self, body, sid=0x1234, length=None):
        self.frames.append((1, pppoe(0, sid, body, length), None))


def build():
    c = Cap()
    c.note('discovery: PADI, PADO, PADR, PADS with the common tags')
    c.d('PADI', tag(0x0101) + tag(0x0103, b'\x01\x02\x03\x04'))
    c.d('PADO', tag(0x0101, b'internet') + tag(0x0102, b'ac-one') + tag(0x0104, b'\xaa\xbb\xcc') +
        tag(0x0103, b'\x01\x02\x03\x04'), dst=CLI, src=AC)
    c.d('PADR', tag(0x0101, b'internet') + tag(0x0103, b'\x01\x02\x03\x04') + tag(0x0104, b'\xaa\xbb\xcc'), dst=AC)
    c.d('PADS', tag(0x0101, b'internet') + tag(0x0103, b'\x01\x02\x03\x04'), sid=0x1234, dst=CLI, src=AC)
    c.note('other discovery codes: PADT, PADG, PADC, PADQ, PADM, PADN, unknown codes, session code in discovery')
    c.d('PADT', b'', sid=0x1234, dst=AC)
    c.d('PADT', tag(0x0203, b'bye'), sid=0x1234, dst=CLI, src=AC)
    c.d('PADG', tag(0x0108, b'\x00\x05') + tag(0x0106, b'\x00\x10\x00\x20'), sid=0x1234)
    c.d('PADC', tag(0x0108, b'\x00\x05') + tag(0x0106, b'\x00\x10\x00\x20'), sid=0x1234, dst=CLI, src=AC)
    c.d('PADQ', tag(0x0107, struct.pack('!HBBHHH', 0, 10, 20, 30, 1000, 2000)), sid=0x1234)
    c.d('PADM', tag(0x0111, b'http://example.invalid/') + tag(0x0112, b'welcome'), sid=0x1234, dst=CLI, src=AC)
    c.d('PADN', tag(0x0121, b'\xc0\x00\x02\x00\xff\xff\xff\x00\xc0\x00\x02\x01'), sid=0x1234, dst=CLI, src=AC)
    c.d(0x42, tag(0x0101, b'x'))
    c.d(0x00, tag(0x0101, b'x'), sid=0x1234)
    c.d('PADI', b'')
    c.note('every tag of the base protocol')
    c.d('PADI', tag(0x0101, b'svc') + tag(0x0102, b'ac') + tag(0x0103, b'\x11\x22') + tag(0x0104, b'\x33') +
        tag(0x0110, b'\x00\x00\x00\x07') + tag(0x0120, b'\x05\xd4') + tag(0x0121, b'\x01\x02\x03\x04') +
        tag(0x0111, b'url') + tag(0x0112, b'msg'))
    c.d('PADO', tag(0x0201, b'no such service') + tag(0x0202, b'ac failed') + tag(0x0203, b'generic'), dst=CLI, src=AC)
    c.d('PADO', tag(0x0102, b'') + tag(0x0101, b''), dst=CLI, src=AC)
    c.note('Credits: 4 octets and other lengths; Sequence Number and Credit Scale Factor: right and wrong lengths')
    c.d('PADG', tag(0x0106, b'\x00\x01\x00\x02') + tag(0x0108, b'\x00\x01') + tag(0x0109, b'\x00\x80'), sid=1)
    c.d('PADG', tag(0x0106, b'\x01\x02\x03'), sid=1)
    c.d('PADG', tag(0x0106, b''), sid=1)
    c.d('PADG', tag(0x0106, b'\x00\x01\x00\x02\x00\x03'), sid=1)
    c.note('Metrics: the four scales of the current and the maximum data rate, other lengths')
    for cdr in range(4):
        for mdr in range(4):
            rsv = (cdr << 1) | (mdr << 3) | (1 if cdr == 0 else 0)
            c.d('PADQ', tag(0x0107, struct.pack('!HBBHHH', rsv, 1 + cdr, 2 + mdr, 100 * cdr + mdr, 1500, 2500)), sid=2)
    c.d('PADQ', tag(0x0107, b'\x01\x02\x03'), sid=2)
    c.d('PADQ', tag(0x0107, b''), sid=2)
    c.note('Vendor-Specific: lengths 0-4, other vendor, the DSLF sub-tags')
    c.d('PADI', tag(0x0105, b'\x00'))
    c.d('PADI', tag(0x0105, b'\x00\x00\x0d\xe9'))
    c.d('PADI', tag(0x0105, b'\x00\x00\x00\x09\xde\xad\xbe\xef'))
    c.d('PADI', tag(0x0105, b'\x00\x00\x0d\xe9', 8) + b'')   # length larger than the data: see malformed
    c.frames.pop()
    c.d('PADI', vendor_dslf(sub(1, b'circuit-7/0/1'), sub(2, b'remote-id'),
                            sub(0x81, struct.pack('!I', 1000)), sub(0x82, struct.pack('!I', 20000)),
                            sub(0x83, struct.pack('!I', 64)), sub(0x84, struct.pack('!I', 128)),
                            sub(0x85, struct.pack('!I', 2000)), sub(0x86, struct.pack('!I', 40000)),
                            sub(0x87, struct.pack('!I', 3000)), sub(0x88, struct.pack('!I', 50000)),
                            sub(0x89, struct.pack('!I', 32)), sub(0x8a, struct.pack('!I', 32)),
                            sub(0x8b, struct.pack('!I', 8)), sub(0x8c, struct.pack('!I', 4)),
                            sub(0x8d, struct.pack('!I', 16)), sub(0x8e, struct.pack('!I', 12)),
                            sub(0x90, b'\x00\x01\x05')))
    for dl, e1, e2 in ((0, 0, 1), (1, 1, 2), (1, 2, 3), (1, 3, 4), (0, 0, 5), (0, 0, 6), (0, 0, 7), (0, 0, 8), (2, 4, 9)):
        c.d('PADI', vendor_dslf(sub(0x90, bytes([dl, e1, e2]))))
    c.note('DSLF unknown sub-tags and a vendor tag followed by another tag')
    c.d('PADI', vendor_dslf(sub(0x99, b'\x01\x02'), sub(0x98, b''), sub(2, b'z')))
    c.d('PADI', vendor_dslf(sub(1, b'')) + tag(0x0101, b'after'))
    c.note('reproducer of the unknown tag data offset fix, unknown tags, End-Of-List, tags after it')
    c.d('PADI', tag(0x0101) + tag(0x0199, b'ABC'))
    c.d('PADI', tag(0x0199) + tag(0x0300, b'\x00\x01') + tag(0x0101, b'x'))
    c.d('PADI', tag(0x0101, b'before') + tag(0x0000) + tag(0x0101, b'ignored'))
    c.d('PADI', tag(0x0101, b'tail') + b'\x00')
    c.note('session frames: LCP, IPCP, IPv6CP, IPv4 over PPP, in both directions')
    sid = 0x1234
    c.s(ppp(0xc021, lcp(1, 1, b'\x01\x04\x05\xd4')), sid=sid)
    c.s(ppp(0xc021, lcp(2, 1, b'\x01\x04\x05\xd4')), sid=sid, dst=CLI, src=AC)
    c.s(ppp(0x8021, lcp(1, 1, b'\x03\x06\xc0\x00\x02\x01')), sid=sid)
    c.s(ppp(0x8057, lcp(1, 1, b'\x01\x0a\x00\x01\x02\x03\x04\x05\x06\x07')), sid=sid)
    c.s(ppp(0x0021, IPV4), sid=sid)
    c.s(ppp(0x0021, IPV4), sid=sid, dst=CLI, src=AC)
    c.note('session length handling: padding, trailing 4 octets, LCP padding')
    c.s(ppp(0xc021, lcp(9, 3, b'\x00\x00\x00\x00')), sid=sid, pad=b'\x00' * 4)
    c.s(ppp(0x0021, IPV4), sid=sid, pad=b'\xde\xad\xbe\xef')
    c.s(ppp(0x0021, IPV4), sid=sid, length=len(ppp(0x0021, IPV4)) + 40)
    c.s(ppp(0xc021, lcp(9, 4, b'\x00\x00\x00\x00')), sid=sid, pad=b'\x00' * 16, length=14)
    c.s(ppp(0x8021, lcp(1, 2)), sid=sid, pad=b'\x00' * 20, length=8)
    c.s(ppp(0x8057, lcp(1, 2)), sid=sid, pad=b'\x00' * 20, length=8)
    c.s(ppp(0xc021, lcp(9, 5, b'\x00\x00\x00\x00')), sid=sid, pad=b'\x00' * 3)
    c.s(ppp(0x0021, BIG), sid=sid)
    c.s(ppp(0x0021, BIG), sid=sid, pad=b'\x00' * 4)
    c.note('session with the Credits tag first (4 octets and other lengths), then PPP')
    c.s(tag(0x0106, b'\x00\x10\x00\x20') + ppp(0x0021, IPV4), sid=sid)
    c.s(tag(0x0106, b'\x01\x02') + b'\x00\x00' + ppp(0xc021, lcp(9, 6, b'\x00\x00\x00\x00')), sid=sid)
    c.note('session frames of a captured length shorter than the frame, other PPPoE versions and session codes')
    c.s(ppp(0x0021, IPV4 + b'\x00' * 80), sid=sid, origlen=14 + 6 + 2 + len(IPV4) + 80)
    c.frames[-1] = (0, c.frames[-1][1][:14 + 6 + 2 + 12], len(c.frames[-1][1]))
    c.s(ppp(0x0021, IPV4), sid=sid, ver=0x12)
    c.s(ppp(0x0021, IPV4), sid=sid, code=0x09)
    c.s(ppp(0x0021, IPV4), sid=0)
    c.note('PPPoE session frames of the PPP-over-Ethernet link-layer type (51), starting at the PPPoE header')
    c.s51(ppp(0xc021, lcp(9, 7, b'\x00\x00\x00\x00')))
    c.s51(ppp(0x0021, IPV4))
    c.s51(tag(0x0106, b'\x00\x01\x00\x02') + ppp(0x0021, IPV4))
    return c


def build_malformed():
    c = Cap()
    c.s(ppp(0x0021, BIG), sid=0x1234, length=len(ppp(0x0021, BIG)) + 40)
    c.d('PADG', tag(0x0108, b'\x01') + tag(0x0109, b'\x01\x02\x03'), sid=1)
    c.d('PADG', tag(0x0108, b'') + tag(0x0109, b''), sid=1)
    c.d('PADG', tag(0x0108, b'\x01\x02\x03\x04'), sid=1)
    c.d('PADI', vendor_dslf(sub(1, b'x' * 70), sub(2, b'y' * 64), sub(0x81, b'\x00\x00'), sub(0x82, b'\x00' * 6),
                            sub(0x90, b'\x00\x01'), sub(0x90, b'\x00\x01\x05\x06')))
    c.d('PADI', vendor_dslf(sub(0x83, b'\x00\x00\x00\x40'), sub(0x84, b'\x00\x00\x00\x40'), sub(0x89, b'\x00\x00\x00\x01'),
                            sub(0x8a, b'\x00'), sub(0x8b, b'\x00\x00\x00\x01'), sub(0x8c, b'\x00\x00\x00\x01'),
                            sub(0x8d, b'\x00'), sub(0x8e, b'\x00'), sub(0x85, b'\x00'), sub(0x86, b'\x00'),
                            sub(0x87, b'\x00'), sub(0x88, b'\x00'), sub(0x83, b'\x00'), sub(0x84, b'\x00')))
    c.s(ppp(0x0021, IPV4), length=len(ppp(0x0021, IPV4)) - 5)
    c.s(tag(0x0106, b'\x00\x10\x00\x20\x00\x30') + ppp(0xc021, lcp(9, 6, b'\x00\x00\x00\x00')))
    c.d('PADI', b'', length=0)
    c.d('PADI', tag(0x0101, b'abc', length=30))                       # tag length beyond the frame
    c.d('PADI', tag(0x0102, b'abc', length=30))
    c.d('PADI', tag(0x0105, b'\x00\x00\x0d\xe9', length=9))           # vendor tag longer than the data
    c.d('PADI', tag(0x0105, b'\x00\x00\x0d\xe9') + sub(0x81, b'\x00\x00\x00', length=4))
    c.d('PADI', tag(0x0105, b'\x00\x00\x0d\xe9') + sub(1, b'ab', length=20))
    c.d('PADI', tag(0x0105, b'\x00\x00\x0d\xe9') + sub(0x90, b'\x00', length=3))
    c.d('PADI', tag(0x0106, b'\x00\x01', length=4))
    c.d('PADI', tag(0x0107, b'\x00\x01\x02\x03\x04\x05\x06\x07', length=10))
    c.d('PADI', tag(0x0108, b'\x01', length=2))
    c.d('PADI', tag(0x0199, b'ab', length=9))
    c.d('PADI', b'\x01\x01\x00')                                       # tag header cut
    c.d('PADI', tag(0x0101, b'x'), length=200)                         # payload length beyond the frame
    c.frames.append((0, eth(BCAST, CLI, 0x8863, b'\x11\x09'), None))   # header cut
    c.frames.append((0, eth(BCAST, CLI, 0x8863, b'\x11\x09\x00\x00\x00'), None))
    c.frames.append((0, eth(AC, CLI, 0x8864, b'\x11\x00\x12'), None))  # session header cut
    c.s(b'', length=0)
    c.s(b'\x00', length=1)
    c.s(tag(0x0106, b'\x00\x01\x00\x02')[:6], length=6)               # credits tag cut
    c.s(tag(0x0106, b'\x00\x01\x00\x02', length=50) + b'\xc0\x21', length=50)
    return c


def write_pcapng(name, cap):
    def block(btype, body):
        pad = (-len(body)) % 4
        n = 12 + len(body) + pad
        return struct.pack('<II', btype, n) + body + b'\0' * pad + struct.pack('<I', n)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    used = sorted({f[0] for f in cap.frames})
    dlt = {0: 1, 1: 51}
    idx = {}
    for i, f in enumerate(used):
        idx[f] = i
        out += block(1, struct.pack('<HHI', dlt[f], 0, 65535))
    for n, (ifc, data, orig) in enumerate(cap.frames):
        ts = n * 1000
        out += block(6, struct.pack('<IIIII', idx[ifc], 0, ts, len(data), orig or len(data)) + data)
    with open(name, 'wb') as fh:
        fh.write(out)


if __name__ == '__main__':
    out = sys.argv[1]
    c = build()
    write_pcapng(out + '/pppoe-coverage.pcapng', c)
    write_pcapng(out + '/pppoe-coverage-malformed.pcapng', build_malformed())
    if '-v' in sys.argv:
        for n, l in c.marks:
            print(n, l)
        print(len(c.frames), 'frames')
