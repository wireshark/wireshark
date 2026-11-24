#!/usr/bin/env python3
# Generates test/captures/matter_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Matter dissector
(packet-matter.c): UDP port 5540 messages (unsecured session with every
header combination, secured sessions with placeholder bytes for the
ciphertext and MIC, message privacy) and the Matter TLV decoder
(Exported PDU "matter.tlv"). No keys: encrypted payload decoding does not
exist in the dissector and no ciphertext is produced.

Usage: mkmatter.py <output directory> [-v]
Writes matter-coverage.pcapng (main) and matter-coverage-malformed.pcapng.
"""
import struct
import sys

LT_ETH = 1
LT_EXPPDU = 252


def pcapng(path, frames, extra_lt=()):
    """frames: list of (interface, bytes). Interface 0 is Ethernet, 1 is
    Exported PDU, 2.. the link types in extra_lt. 10 ms per frame."""
    def block(btype, body):
        pad = (4 - len(body) % 4) % 4
        body += b'\0' * pad
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)

    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in (LT_ETH, LT_EXPPDU) + tuple(extra_lt):
        out += block(1, struct.pack('<HHI', lt, 0, 262144))
    t0 = 1700000000 * 1000000
    for i, (ifc, data) in enumerate(frames):
        ts = t0 + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(s):
    return bytes(int(x) for x in s.split('.'))


def mac(addr):
    return bytes([2, 0]) + ip4(addr)


IDENT = [0]


def ipv4(proto, payload, src, dst):
    IDENT[0] += 1
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), IDENT[0] & 0xffff,
                      0x4000, 64, proto, 0, ip4(src), ip4(dst))
    hdr = hdr[:10] + struct.pack('!H', csum(hdr)) + hdr[12:]
    return mac(dst) + mac(src) + b'\x08\x00' + hdr + payload


def udp(payload, src, sport, dst, dport):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    u = u[:6] + struct.pack('!H', c) + u[8:]
    return (0, ipv4(17, u, src, dst))


class TCP:
    """A TCP connection; c2s()/s2c() return frames carrying data."""

    def __init__(self, cli, cport, srv, sport):
        self.cli, self.cport, self.srv, self.sport = cli, cport, srv, sport
        self.cseq, self.sseq = 1000, 5000

    def seg(self, payload, to_server, flags=0x18, seq=None):
        if to_server:
            src, sp, dst, dp = self.cli, self.cport, self.srv, self.sport
            s, a = self.cseq, self.sseq
        else:
            src, sp, dst, dp = self.srv, self.sport, self.cli, self.cport
            s, a = self.sseq, self.cseq
        if seq is not None:
            s = seq
        opts = b''
        if flags & 0x02:
            opts = b'\x02\x04\x05\xb4'
            if not flags & 0x10:
                a = 0
        t = struct.pack('!HHIIBBHHH', sp, dp, s & 0xffffffff, a & 0xffffffff,
                        (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
        return (0, ipv4(6, t, src, dst))

    def handshake(self):
        f = [self.seg(b'', True, 0x02)]
        self.cseq += 1
        f.append(self.seg(b'', False, 0x12))
        self.sseq += 1
        f.append(self.seg(b'', True, 0x10))
        return f

    def c2s(self, payload):
        f = self.seg(payload, True)
        self.cseq += len(payload)
        return f

    def s2c(self, payload):
        f = self.seg(payload, False)
        self.sseq += len(payload)
        return f


def exported_pdu(proto_name, payload):
    name = proto_name.encode()
    pad = (4 - len(name) % 4) % 4
    tags = struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad
    tags += struct.pack('!HH', 0, 0)
    return (1, tags + payload)


def u16(v): return struct.pack('<H', v)
def u32(v): return struct.pack('<I', v)
def u64(v): return struct.pack('<Q', v)
def b16(v): return struct.pack('>H', v)
def b32(v): return struct.pack('>I', v)
# ---- end of prelude ----

# ------------------------------------------------------------ Matter

def msg(flags=0x00, sid=0, secflags=0x00, counter=1, src=None, dnode=None,
        dgroup=None, rest=b''):
    """Matter message header. flags bit 2 = source ID, bits 0-1 = DSIZ."""
    if src is not None:
        flags |= 0x04
    if dnode is not None:
        flags = (flags & ~3) | 1
    if dgroup is not None:
        flags = (flags & ~3) | 2
    b = bytes([flags]) + u16(sid) + bytes([secflags]) + u32(counter)
    if src is not None:
        b += u64(src)
    if dnode is not None:
        b += u64(dnode)
    if dgroup is not None:
        b += u16(dgroup)
    return b + rest


def exch(flags, opcode, xid, proto, vendor=None, ack=None, ext=None, app=b''):
    """Protocol payload (unsecured session)."""
    if vendor is not None:
        flags |= 0x10
    if ack is not None:
        flags |= 0x02
    if ext is not None:
        flags |= 0x08
    b = bytes([flags, opcode]) + u16(xid)
    if vendor is not None:
        b += u16(vendor)
    b += u16(proto)
    if ack is not None:
        b += u32(ack)
    if ext is not None:
        b += u16(len(ext)) + ext
    return b + app


# ------------------------------------------------------------ TLV

def tl(control, tag=None, data=b''):
    b = bytes([control])
    if tag is not None:
        b += bytes([tag])
    return b + data


def sint(v, size, tag=None):
    return tl({1: 0x00, 2: 0x01, 4: 0x02, 8: 0x03}[size] | (0x20 if tag is not None else 0), tag,
              v.to_bytes(size, 'little', signed=True))


def uint(v, size, tag=None):
    return tl({1: 0x04, 2: 0x05, 4: 0x06, 8: 0x07}[size] | (0x20 if tag is not None else 0), tag,
              v.to_bytes(size, 'little'))


def octets(d, lensize, tag=None):
    c = {1: 0x10, 2: 0x11, 4: 0x12, 8: 0x13}[lensize] | (0x20 if tag is not None else 0)
    return tl(c, tag, len(d).to_bytes(lensize, 'little') + d)


def container(kind, items, tag=None):
    c = {'s': 0x15, 'a': 0x16, 'l': 0x17}[kind] | (0x20 if tag is not None else 0)
    return tl(c, tag, b''.join(items) + b'\x18')


A = '192.0.2.10'
B = '192.0.2.20'


def main_frames():
    f = []

    def um(p, sport=49152, dport=5540, src=A, dst=B):
        f.append(udp(p, src, sport, dst, dport))

    # Unsecured session: all header combinations
    um(msg(counter=1, src=0x1122334455667788,
           rest=exch(0x05, 0x20, 0x1234, 0x0000, app=b'\x15\x24\x00\x01\x18')))
    um(msg(counter=2, dnode=0x8877665544332211,
           rest=exch(0x02, 0x10, 0x1234, 0x0000, ack=1)), src=B, dst=A)
    um(msg(counter=3, dgroup=0xFF01,
           rest=exch(0x05, 0x30, 0x0001, 0x0001, app=b'ping')))
    um(msg(counter=4, src=0x0102030405060708, dnode=0x0807060504030201,
           rest=exch(0x01, 0x21, 0x0002, 0x0000, ack=3)))
    um(msg(counter=5, src=0x1, dgroup=0x0005,
           rest=exch(0x0D, 0x22, 0x0003, 0x0000, ack=4, ext=b'\xde\xad\xbe\xef\x00\x01',
                     app=b'\x15\x18')))
    # Vendor protocol, vendor and ack, secured extensions, no application payload
    um(msg(counter=6, rest=exch(0x04, 0x01, 0x4321, 0x0042, vendor=0xFFF1, app=b'\x01\x02\x03')))
    um(msg(counter=7, rest=exch(0x1F, 0x02, 0x4322, 0x0043, vendor=0x115A, ack=6,
                                  ext=b'', app=b'')))
    um(msg(counter=8, rest=exch(0x08, 0x00, 0x0000, 0x0000, ext=b'\x01' * 40, app=b'')))
    # Version bits and DSIZ value 3 (reserved: no destination parsed)
    um(msg(flags=0x10, counter=9, rest=exch(0x00, 0x00, 5, 0)))
    um(msg(flags=0x03, counter=10, rest=exch(0x00, 0x00, 6, 0)))
    # Message exactly the minimum length (8 bytes): payload cut short is an
    # exception, so give the exchange header its 6 octets
    um(msg(counter=11, rest=exch(0x00, 0x00, 7, 0)))
    # Secured sessions: unicast, group, control, extensions; 8 octets of
    # ciphertext and a 16 octet MIC (placeholder bytes)
    mic = bytes(range(0xA0, 0xB0))
    ct = bytes(range(0x30, 0x40))
    um(msg(sid=0x1234, counter=12, rest=ct + mic))
    um(msg(sid=0x1234, secflags=0x00, counter=13, src=0x0A0B0C0D0E0F1011, rest=ct[:5] + mic), src=B, dst=A)
    um(msg(sid=0x4321, secflags=0x01, counter=14, dgroup=0x0001, rest=ct + mic))
    um(msg(sid=0x4321, secflags=0x41, counter=15, src=0x42, dgroup=0x0002, rest=mic))
    um(msg(sid=0x0000, secflags=0x20, counter=16, rest=ct + mic))   # extensions flag, session 0 (not unsecured)
    um(msg(sid=0x0001, secflags=0x02, counter=17, rest=ct + mic))   # reserved session type
    um(msg(sid=0x0001, secflags=0x61, counter=18, rest=ct + mic))
    # Message privacy: encrypted header; 4 octets, +8 source, +8 node, +2 group
    ph = bytes(range(0x50, 0x70))
    um(bytes([0x00]) + u16(0x2222) + b'\x80' + ph[:4] + ct + mic)
    um(bytes([0x04]) + u16(0x2222) + b'\x80' + ph[:12] + ct + mic)
    um(bytes([0x01]) + u16(0x2222) + b'\x80' + ph[:12] + ct + mic)
    um(bytes([0x05]) + u16(0x2222) + b'\x80' + ph[:20] + ct + mic)
    um(bytes([0x02]) + u16(0x2222) + b'\xc1' + ph[:6] + ct + mic)
    um(bytes([0x06]) + u16(0x2222) + b'\xa1' + ph[:14] + ct + mic)
    # A different port needs Decode As (runcov.sh); same payload over 5540
    # from another client
    um(msg(counter=19, rest=exch(0x05, 0x20, 9, 0, app=b'x' * 200)), sport=49153)

    # Exported PDU matter.tlv: every element type that is supported
    def tlv(*items):
        f.append(exported_pdu('matter.tlv', b''.join(items)))

    tlv(container('s', [
        sint(-1, 1, 1), sint(-300, 2, 2), sint(-70000, 4, 3), sint(-(1 << 40), 8, 4),
        uint(255, 1, 5), uint(65535, 2, 6), uint(0xFFFFFFFF, 4, 7), uint(1 << 60, 8, 8),
        tl(0x28, 9), tl(0x29, 10), tl(0x34, 11),
        octets(b'\x01\x02\x03', 1, 12), octets(b'\xaa' * 300, 2, 13),
        octets(b'\xbb' * 5, 4, 14), octets(b'\xcc' * 4, 8, 15),
    ]))
    tlv(sint(5, 1), sint(5, 2), sint(5, 4), sint(5, 8),
        uint(5, 1), uint(5, 2), uint(5, 4), uint(5, 8),
        tl(0x08), tl(0x09), tl(0x14), octets(b'abc', 1), octets(b'', 2))
    # nested containers: array of lists of structures
    tlv(container('s', [
        container('a', [container('l', [container('s', [uint(1, 1, 0)], 1), uint(2, 2)], None),
                        container('l', [], None)], 1),
        container('l', [uint(3, 4, 2), container('a', [sint(-3, 1), tl(0x14)])], 2),
    ]), uint(0xdead, 2), container('a', []))
    # a tag-less element after End of Container at the top level and a
    # lone End of Container (control 0x18)
    tlv(b'\x18')
    tlv(uint(7, 1), b'\x18', uint(8, 1))
    return f


def malformed_frames():
    f = []

    def um(p, sport=49152, dport=5540, src=A, dst=B):
        f.append(udp(p, src, sport, dst, dport))

    # Reproducer of "Matter: Check the length of a secured payload":
    # secured message with fewer than 16 octets after the header
    um(msg(sid=0x1234, counter=1, rest=b'ABCD'))
    um(msg(sid=0x1234, counter=2, rest=b''))
    um(msg(sid=0x1234, counter=3, rest=b'x' * 15))
    # Shorter than the minimum header: not Matter (returns 0)
    um(b'\x00\x00\x00\x00\x00\x00\x00')
    # Unsecured payload shorter than the exchange header; header cut short
    um(msg(counter=4, rest=b'\x00\x01'))
    um(msg(counter=5, rest=b''))
    um(msg(counter=6, rest=bytes([0x02, 0x01, 0x00, 0x00, 0x00, 0x00])))      # ACK counter cut
    um(msg(counter=7, rest=bytes([0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05])))  # secured ext length cut
    um(msg(counter=8, rest=bytes([0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 1, 2])))  # ext past end
    um(msg(counter=9, rest=bytes([0x10, 0x01, 0x00, 0x00, 0x00, 0x00])))      # vendor id cut
    # Message header cut short: source, destination, privacy header
    um(bytes([0x04]) + u16(0) + b'\x00' + u32(10) + b'\x01\x02')
    um(bytes([0x01]) + u16(0) + b'\x00' + u32(11) + b'\x01\x02\x03')
    um(bytes([0x02]) + u16(0) + b'\x00' + u32(12) + b'\x01')
    um(bytes([0x00]) + u16(0x10) + b'\x80' + b'\x01\x02\x03\x04')           # privacy: no payload
    um(bytes([0x05]) + u16(0x10) + b'\x80' + b'\x01\x02\x03\x04\x05\x06')   # privacy header cut short

    def tlv(*items):
        f.append(exported_pdu('matter.tlv', b''.join(items)))

    # TLV: unsupported tag forms, unsupported element types, truncations
    tlv(bytes([0x40 | 0x04]) + b'\x01\x00' + b'\x05')            # common profile tag 2 octets
    tlv(bytes([0x60 | 0x04]) + b'\x01\x00\x00\x00\x05')
    tlv(bytes([0xE0 | 0x04]) + b'\x01' * 9)
    tlv(bytes([0x0A]) + b'\x00\x00\x80\x3f')                      # float: unsupported
    tlv(bytes([0x0C]) + b'\x03abc')                               # UTF-8 string: unsupported
    tlv(bytes([0x19]))
    tlv(bytes([0x38 | 0x00]))                                     # reserved with tag
    tlv(container('s', [bytes([0x0B]) + b'\x00' * 8]))            # unsupported inside a structure
    tlv(bytes([0x24, 0x01]), bytes([0x25]))                       # short: uint16 cut
    tlv(bytes([0x25, 0x01]))
    tlv(bytes([0x10, 0x10]) + b'abc')                             # octet string longer than data
    tlv(bytes([0x13]) + u64(1 << 40) + b'abc')                    # absurd 8 octet length
    tlv(bytes([0x12]) + u32(0xFFFFFFFF) + b'abc')
    tlv(bytes([0x04]))                                            # integer without value
    tlv(bytes([0x24]))                                            # tag missing
    tlv(bytes([0x15]) * 3)                                        # nested structures never closed
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    mf = main_frames()
    pcapng(out + '/matter-coverage.pcapng', mf)
    xf = malformed_frames()
    pcapng(out + '/matter-coverage-malformed.pcapng', xf)
    if '-v' in sys.argv:
        print('main frames', len(mf), 'malformed frames', len(xf))


main()
