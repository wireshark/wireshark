# Generates test/captures/vines_coverage.pcapng.gz
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


def tcp(sport, dport, seq, ack, flags, payload=b'', win=8192, opts=b''):
    return struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, win, 0, 0) + opts + payload


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




def pcapng(path, linktypes, frames):
    """frames: (interface id, data). Writes SHB, one IDB per link type, EPBs."""
    def blk(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)
    out = blk(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    for lt in linktypes:
        out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifid, data) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)
#!/usr/bin/env python3
"""Generate the synthetic captures for the Banyan VINES dissectors
(packet-vines.c: Vines FRP, LLC, IP, Echo, IPC, SPP, ARP, RTP/SRTP, ICP).

Vines IP is reached the way a real trace reaches it: Ethernet type 0x0bad,
802.2 LLC with SAP 0xbc, PPP protocol 0x0035, ARCNET protocol 247, Vines
FRP in IP protocol 83 and in UDP port 573 (source and destination port
573); Vines Echo by Ethernet type 0x0baf or LLC type 0xbb.  Every packet
is built from scratch with struct; Vines addresses are 4 octet network
number plus 2 octet subnetwork number (fictional).

Usage: mkvines.py <output directory>

Writes:
  vines-coverage.pcapng            Ethernet (all the Vines protocols and
                                   their message types), PPP, ARCNET and IP
                                   interfaces
  vines-coverage-malformed.pcapng  runts, a nested ICP/IP chain, lengths
                                   that do not fit
"""

HOST1 = bytes([0x00, 0x00, 0x00, 0x01, 0x00, 0x01])
HOST2 = bytes([0x00, 0x00, 0x00, 0x02, 0x00, 0x02])
BCAST = b'\xff' * 6
MAC1, MAC2 = b'\x02\0\0\0\0\x01', b'\x02\0\0\0\0\x02'


def vip(proto, payload, tctl=0x02, dst=HOST2, src=HOST1, length=None, chk=0xffff):
    """Vines IP datagram: checksum, length, transport control, protocol, dst, src."""
    ln = 18 + len(payload) if length is None else length
    return struct.pack('>HHBB', chk, ln, tctl, proto) + dst + src + payload


def eth(payload, etype=0x0bad):
    return MAC2 + MAC1 + struct.pack('>H', etype) + payload


def llc(payload, ptype, dsap=0xbc):
    data = bytes([dsap, dsap, 0x03, ptype]) + payload
    return MAC2 + MAC1 + struct.pack('>H', len(data)) + data


def ipc(sport, dport, ptype, ctl=0, lid=0, rid=0, seq=0, ack=0, last=0, data=b''):
    if ptype == 0:
        return struct.pack('>HHBB', sport, dport, ptype, ctl) + data
    return struct.pack('>HHBBHHHHH', sport, dport, ptype, ctl, lid, rid, seq, ack, last) + data


def spp(sport, dport, ptype, ctl, lid, rid, seq, ack, win, data=b''):
    return struct.pack('>HHBBHHHHH', sport, dport, ptype, ctl, lid, rid, seq, ack, win) + data


def smb_negotiate():
    hdr = b'\xffSMB' + bytes([0x72]) + struct.pack('<I', 0) + bytes([0x18]) + struct.pack('<H', 0xc853) + \
        struct.pack('<H', 0) + b'\0' * 8 + struct.pack('<HHHHH', 0, 0, 0xfffe, 0, 1)
    dialects = b'\x02NT LM 0.12\x00'
    return hdr + bytes([0]) + struct.pack('<H', len(dialects)) + dialects


def machine(addr, metric, ntype, mtype, ctype):
    return addr + struct.pack('>HBBB', metric, ntype, mtype, ctype)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    F = []     # (interface, frame)

    def add(d, ifid=0):
        F.append((ifid, d))

    def v(proto, payload, **kw):
        add(eth(vip(proto, payload, **kw)))

    # --- reproducers of the fix, first: ICP with transport control 0 (the protocol is
    # the octet after it), SPP carrying SMB (same output with and without a tree),
    # SRTP redirect with the destination sequence number 0xdeadbeef
    v(6, struct.pack('>HH', 1, 7), tctl=0x00)
    v(2, spp(0x0201, 0x0202, 1, 0x60, 1, 2, 3, 4, 5, data=smb_negotiate()))
    srtp_redirect = bytes([0, 1, 3, 2, 0, 0, 6, 0]) + HOST1 + struct.pack('>HBB', 10, 2, 0) + struct.pack('>I', 0xdeadbeef) + \
        HOST2 + struct.pack('>HBB', 20, 2, 0) + struct.pack('>I', 0x11223344) + bytes(range(0xa0, 0xa6))
    v(5, srtp_redirect, tctl=0x05)

    # --- IPC: datagram, data, error (every error code), disconnect, probe, ack, unknown
    v(1, ipc(0x1001, 0x1002, 0, data=b'datagram payload'))
    v(1, ipc(0x1001, 0x1002, 1, ctl=0xf0, lid=1, rid=2, seq=3, ack=4, last=5, data=b'user data'))
    v(1, ipc(0x1001, 0x1002, 1, ctl=0x0f, lid=1, rid=2, seq=4, ack=4, last=0, data=b'more data'))
    for code in (151, 152, 157, 160, 167, 168):
        v(1, ipc(0x1001, 0x1002, 2, ctl=0x60, lid=1, rid=2, seq=5, ack=5, last=code))
    for t in (3, 4, 5, 9):
        v(1, ipc(0x1001, 0x1002, t, ctl=0x20 + t, lid=3, rid=4, seq=6, ack=6, last=0))
    # --- SPP
    for t in (0, 1, 2, 3, 4, 5, 8):
        v(2, spp(0x2001, 0x2002, t, 0x10 * t, 10, 11, 100 + t, 200 + t, 1024))
    v(2, spp(0x2001, 0x2002, 1, 0x00, 10, 11, 1, 1, 4096, data=b'not SMB, plain data'))
    v(2, spp(0x2001, 0x2002, 1, 0x00, 10, 11, 1, 1, 4096))
    # --- ARP: non-sequenced (versions 0, 2) and sequenced (version 1)
    for t in (0, 1, 2):
        v(4, struct.pack('>H', t))
    v(4, struct.pack('>H', 3) + HOST2)
    v(4, struct.pack('>H', 9))
    v(4, struct.pack('>H', 3 + 0x0200) + HOST1 + b'\0\0')
    for t in (0, 1, 2):
        v(4, bytes([1, t]) + HOST1 + struct.pack('>IH', 0x01020304, 5))
    v(4, bytes([1, 3]) + HOST2 + struct.pack('>IH', 0x05060708, 25))
    v(4, bytes([1, 7]) + HOST2 + struct.pack('>IH', 1, 0xffff), dst=BCAST, tctl=0x40 | 0x30 | 3)
    # --- RTP, non-sequenced
    mt = 0x07
    v(5, bytes([1, 2, 0, mt]), tctl=0x05, dst=BCAST)                                # request, no entries
    v(5, bytes([2, 2, 1, mt]) + struct.pack('>IH', 0x01000000, 3) + struct.pack('>IH', 0x02000000, 0xffff), dst=BCAST)
    v(5, bytes([4, 1, 0, 0]))                                                       # reinitialize
    v(5, bytes([9, 1, 0, 0]) + struct.pack('>IH', 7, 7))                            # unknown operation
    for op, lal, srl in ((3, 6, 2), (6, 4, 0), (3, 0, 3), (3, 0, 0)):
        gw = bytes(range(0xa0, 0xa0 + lal)) + bytes(range(0xc0, 0xc0 + srl))
        v(5, bytes([op, 2, 0, mt]) + struct.pack('>HBB', 1, lal, srl) + machine(HOST1, 7, 2, 7, 1) + b'\0' +
          machine(HOST2, 9, 1, 3, 0) + b'\0' + gw)
    # --- SRTP
    sr = lambda op, rest, flags=0x03: bytes([0, 1, op, 2, flags, 0]) + rest
    v(5, sr(1, bytes([0x01])), tctl=0x05)                                           # request
    v(5, sr(1, bytes([0x02])))
    for itype in (0, 1, 2, 9):
        entries = b''
        for k, metric in enumerate((5, 0xffff, 0)):
            entries += struct.pack('>IHIBB', 0x03000000 + k, metric, 77 + k, 0x0f if k == 0 else 0x00, 0)
        v(5, sr(2, bytes([itype, 0x1f]) + struct.pack('>HHIH', 0x1234, 0x0010, 0xaabbccdd, 12) + entries, flags=0xe0),
          dst=BCAST, tctl=0x40 | 0x30)
    v(5, sr(2, bytes([0, 0xe0]) + struct.pack('>HHIH', 1, 2, 3, 4)))              # no entries
    v(5, sr(3, bytes([6, 2]) + HOST1 + struct.pack('>HBB', 3, 1, 0xff) + struct.pack('>I', 99) + HOST2 +
            struct.pack('>HBB', 4, 2, 0) + struct.pack('>I', 100) + bytes(range(6)) + b'\x81\x82', flags=0x01))
    v(5, sr(3, bytes([4, 0]) + HOST1 + struct.pack('>HBB', 3, 1, 0xff) + struct.pack('>I', 99) + HOST2 +
            struct.pack('>HBB', 4, 2, 0) + struct.pack('>I', 100) + bytes(range(4))))
    v(5, sr(4, b''))
    v(5, sr(7, b'\0\0'))
    # --- ICP: exception notification (several codes), metric, unknown, nested VIP datagram
    orig = vip(2, spp(0x2001, 0x2002, 1, 0, 1, 2, 3, 4, 5, data=b'x' * 4))[:40]
    for code in (151, 157, 1, 0):
        v(6, struct.pack('>HH', 0, code) + orig, tctl=0x00 if code == 0 else 0x02)
    v(6, struct.pack('>HH', 1, 33) + orig)
    v(6, struct.pack('>HH', 7, 0) + orig)
    v(6, struct.pack('>HH', 1, 1) + vip(6, struct.pack('>HH', 1, 2) + vip(1, ipc(1, 2, 0, data=b'x' * 12))))
    # --- unknown VIP protocol, broadcast and non-broadcast transport control values
    v(99, b'unknown protocol')
    for tctl in (0x00, 0x1f, 0x40, 0x60, 0x7f, 0xff, 0x80):
        v(1, ipc(1, 2, 0, data=b'tctl test data'), tctl=tctl)
        v(1, ipc(1, 2, 0, data=b'tctl test data'), tctl=tctl, dst=BCAST)
    # padding after the VIP datagram (the length field is shorter than the frame)
    v(1, ipc(1, 2, 0, data=b'padded datagram!'), length=18 + 6 + 16)
    add(eth(vip(1, ipc(1, 2, 0, data=b'padded datagram!')) + b'\0' * 14))
    # --- Echo, by Ethernet type and by LLC type
    add(eth(b'echo request data', 0x0baf))
    add(llc(b'echo over llc', 0xbb))
    # --- LLC with Vines IP, and an unknown Vines LLC type
    add(llc(vip(1, ipc(1, 2, 0, data=b'ip over llc!!')), 0xba))
    add(llc(vip(6, struct.pack('>HH', 1, 9) + orig), 0xba))
    add(llc(b'something else', 0x77))
    # --- FRP in IP protocol 83 and in UDP port 573 (source = destination)
    for flags, seq in ((0x01, 0), (0x02, 1), (0x03, 2), (0x00, 255)):
        frp = bytes([flags, seq]) + vip(1, ipc(1, 2, 0, data=b'ip proto 83 FRP'))
        add(ether(ip4(83, '192.0.2.50', '192.0.2.51', frp, 1 + seq)))
    for flags in (0x03, 0x01):
        frp = bytes([flags, 7]) + vip(1, ipc(1, 2, 0, data=b'udp port 573 FRP'))
        add(ether(ip4(17, '192.0.2.50', '192.0.2.51', udp(573, 573, frp), 20 + flags)))
    # UDP port 573 with other source port: not Vines (the dissector declines), flags above 3: declines
    add(ether(ip4(17, '192.0.2.50', '192.0.2.51', udp(5000, 573, b'\x03\x00' + vip(1, ipc(1, 2, 0, data=b'x' * 12))), 30)))
    add(ether(ip4(17, '192.0.2.50', '192.0.2.51', udp(573, 573, b'\x13\x00' + vip(1, ipc(1, 2, 0, data=b'x' * 12))), 31)))
    # an empty datagram from and to port 573: no octet to check the flags of
    add(ether(ip4(17, '192.0.2.50', '192.0.2.51', udp(573, 573, b''), 32)))
    # --- PPP (linktype 9) and ARCNET BSD (linktype 7)
    add(b'\xff\x03\x00\x35' + vip(1, ipc(1, 2, 0, data=b'vines over ppp')), 1)
    add(b'\xff\x03\x00\x35' + vip(6, struct.pack('>HH', 1, 3) + orig), 1)
    add(bytes([0x11, 0x22, 247, 0, 0, 0]) + vip(1, ipc(1, 2, 0, data=b'vines on arcnet')), 2)
    pcapng(os.path.join(out, 'vines-coverage.pcapng'), [1, 9, 7], F)

    # --- malformed
    F = []
    v(1, b'\x00\x01')                                  # IPC shorter than the 16 octet header
    v(1, ipc(1, 2, 0, data=b'short vip len'), length=10)   # VIP length smaller than its header
    v(1, ipc(1, 2, 0, data=b'123'))                    # datagram shorter than 16 octets
    v(2, b'\x00' * 10)                                 # SPP shorter than 16
    v(4, b'')                                          # ARP with nothing
    v(4, bytes([1, 3]) + HOST1)                        # sequenced ARP cut short
    v(4, struct.pack('>H', 3) + HOST1[:3])
    v(5, b'')
    v(5, bytes([1, 2]))
    v(5, bytes([3, 2, 0, 7, 0, 1, 6, 2]) + b'\0' * 5)  # redirect cut inside the machine info
    v(5, bytes([2, 2, 0, 7]) + b'\0' * 5)              # entry cut short
    v(5, bytes([0, 1, 2, 2, 3, 0, 1, 0x1f, 0, 1]))     # SRTP update cut short
    v(5, bytes([0, 1, 2]))
    v(5, bytes([0, 1, 3, 2, 1, 0, 6, 2]) + HOST1)
    v(6, b'\x00')
    v(6, struct.pack('>HH', 0, 151))                   # ICP without the original datagram
    v(6, struct.pack('>HH', 0, 151) + b'\0' * 10)
    add(eth(b'\x00' * 4))                              # VIP shorter than its header
    add(eth(vip(1, ipc(1, 2, 0, data=b'x' * 12), length=0xffff)))
    add(eth(vip(1, ipc(1, 2, 0, data=b'x' * 12), length=40)))
    add(llc(b'', 0xba))
    add(llc(b'', 0xbc))
    add(bytes([0x08, 0x01]) + b'', 1)
    add(b'\xff\x03\x00\x35' + b'\x00', 1)
    add(b'\xff\x03\x00\x35', 1)
    add(bytes([0x11, 0x22, 247]), 2)
    add(ether(ip4(83, '192.0.2.50', '192.0.2.51', b'\x03', 70)))
    add(ether(ip4(83, '192.0.2.50', '192.0.2.51', b'\x03\x00\x00', 71)))
    # nested ICP -> Vines IP -> ICP chain, 700 levels (the core dissection depth limit stops it)
    inner = b''
    for i in range(700):
        inner = vip(6, struct.pack('>HH', 1, 1) + inner, tctl=0x00)
    add(eth(inner))
    pcapng(os.path.join(out, 'vines-coverage-malformed.pcapng'), [1, 9, 7], F)


main()
