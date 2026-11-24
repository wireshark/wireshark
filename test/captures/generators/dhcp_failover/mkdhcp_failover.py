#!/usr/bin/env python3
# Generates test/captures/dhcp_failover_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic DHCP failover (DHCPFO, TCP port 647) coverage captures.

Usage: mkdhcp_failover.py <outdir>

Writes dhcp_failover-coverage.pcap (clean) and
dhcp_failover-coverage-malformed.pcap. Every packet is built with struct;
addresses are from the documentation ranges (192.0.2.0/24, 198.51.100.0/24).
"""
import os
import struct
import sys

T0 = 1700000000


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


class Tcp:
    """A TCP connection with correct sequence and acknowledgement numbers,
    so the TCP dissector adds no analysis expert infos."""

    def __init__(self, frames, cli, srv, cport, sport=647):
        self.frames = frames
        self.ep = {0: (ip4(cli), cport, b'\x02\x00\x00\x00\x00\x01'),
                   1: (ip4(srv), sport, b'\x02\x00\x00\x00\x00\x02')}
        # No handshake or FIN: the TCP dissector would add chat expert
        # infos for them.
        self.seq = {0: 1000, 1: 5000}

    def seg(self, d, payload, flags=0x18):
        (sa, sp, smac), (da, dp, dmac) = self.ep[d], self.ep[1 - d]
        ack = self.seq[1 - d] if flags != 0x02 else 0
        if flags == 0x02:
            ackflag = 0
        else:
            ackflag = 0x10
        tcp = struct.pack('!HHIIBBHHH', sp, dp, self.seq[d], ack, 5 << 4,
                          flags | ackflag, 65535, 0, 0) + payload
        pseudo = sa + da + struct.pack('!xBH', 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0x4000,
                         64, 6, 0, sa, da)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.frames.append(dmac + smac + b'\x08\x00' + ip + tcp)
        self.seq[d] += len(payload)

    def send(self, d, *pdus):
        self.seg(d, b''.join(pdus))

    def fin(self):
        pass


def opt(code, data):
    return struct.pack('!HH', code, len(data)) + data


def u8(v):
    return struct.pack('!B', v)


def u16(v):
    return struct.pack('!H', v)


def u32(v):
    return struct.pack('!I', v)


def utf16(s):
    return s.encode('utf-16-le')


def msg(mtype, opts=b'', poffset=12, xid=1, extra=b'', length=None, t=T0):
    """A DHCPFO message: length, type, payload offset, time, xid,
    additional header bytes, options. poffset 8 is the Microsoft
    (draft) value; the header is then 12 octets anyway."""
    body = extra + opts
    if length is None:
        length = 12 + len(body)
    return struct.pack('!HBBII', length, mtype, poffset, t, xid) + body


def clean(frames):
    # --- Connection 1: IETF draft style (payload offset 12) ---
    c = Tcp(frames, '192.0.2.1', '192.0.2.2', 40001)
    # Connect with every connection option.
    c.send(0, msg(5, opt(22, b'rel-ietf')            # relationship-name, ASCII
                  + opt(15, u32(3600))                # MCLT
                  + opt(14, u32(100))                 # max-unacked-BNDUPD
                  + opt(19, u32(60))                  # receive-timer
                  + opt(20, u8(1))                    # protocol-version
                  + opt(27, u8(1))                    # TLS-request
                  + opt(11, bytes(range(32)))         # hash-bucket-assignment
                  + opt(28, b'isc-dhcpd')             # vendor-class, ASCII
                  + opt(29, b'\x00\x01\x02\x03')      # vendor-option
                  + opt(17, u8(1) + bytes(16))        # message-digest HMAC-MD5 (opaque)
                  + opt(23, u8(1)),                   # server-flag STARTUP
                  xid=0x101))
    # Connect acknowledge.
    c.send(1, msg(6, opt(22, b'rel-ietf')
                  + opt(15, u32(3600))
                  + opt(26, u8(0))                    # TLS-reply
                  + opt(21, u8(0))                    # reject-reason Reserved
                  + opt(16, b'connected')             # message
                  + opt(23, u8(0)),                   # server-flag NONE
                  xid=0x101))
    # State messages: every server state, one unknown, one unknown flag.
    for st in list(range(1, 12)) + [99]:
        c.send(0, msg(10, opt(24, u8(st)) + opt(25, u32(T0 - 100))
                      + opt(23, u8(st == 99 and 7 or 0)), xid=0x200 + st))
    # Binding update with every binding option.
    c.send(0, msg(3, opt(2, ip4('198.51.100.10'))      # assigned-IP-address
                  + opt(3, u8(2))                     # binding-status ACTIVE
                  + opt(4, b'\x01client-id')          # client-identifier
                  + opt(5, b'\x01\x02\x00\x5e\x00\x53\x01')  # client hw address, Ethernet
                  + opt(13, u32(T0 + 3600))           # lease-expiration-time
                  + opt(18, u32(T0 + 7200))           # potential-expiration-time
                  + opt(6, u32(T0 - 10))              # client-last-transaction-time
                  + opt(9, b'\x00\x03ftd')            # FTDDNS
                  + opt(8, b'\x37\x03\x01\x03\x06')   # request-option
                  + opt(7, b'\x33\x04\x00\x00\x0e\x10')  # reply-option
                  + opt(12, u16(0x4000))              # IP-flags (BOOTP)
                  + opt(10, u8(1))                    # delayed-service-parameter
                  + opt(30, b'host-ib')               # Infoblox client hostname
                  + opt(31, utf16('ietf31'))          # unnamed in IETF style
                  + opt(99, b'\xde\xad'),             # unknown option
                  xid=0x301))
    # Binding acknowledge, every binding status and one unknown.
    for bs in list(range(1, 8)) + [42]:
        c.send(1, msg(4, opt(2, ip4('198.51.100.10')) + opt(3, u8(bs)),
                      xid=0x400 + bs))
    # Binding acknowledge with every reject reason and one unknown.
    for rr in list(range(0, 22)) + [254, 200]:
        c.send(1, msg(4, opt(2, ip4('198.51.100.11')) + opt(21, u8(rr)),
                      xid=0x500 + rr))
    # Pool request and response.
    c.send(0, msg(1, xid=0x601))
    c.send(1, msg(2, opt(1, u32(250)), xid=0x601))
    # Update request, done, request all, contact, disconnect, unknown type.
    c.send(0, msg(7, xid=0x701))
    c.send(1, msg(8, xid=0x701))
    c.send(0, msg(9, xid=0x702))
    c.send(1, msg(11, xid=0x703))
    c.send(0, msg(13, xid=0x704))
    # TLS request/reply with every value and unknown values.
    for v in (0, 2, 9):
        c.send(0, msg(5, opt(27, u8(v)), xid=0x800 + v))
    for v in (1, 9):
        c.send(1, msg(6, opt(26, u8(v)), xid=0x810 + v))
    # Additional header bytes (payload offset 16).
    c.send(0, msg(11, opt(16, b'extra'), poffset=16, extra=b'\xaa\xbb\xcc\xdd', xid=0x901))
    # Bogus payload offsets: below 12 (not 8), beyond the length.
    c.send(0, msg(11, poffset=10, xid=0x902))
    c.send(0, msg(11, poffset=20, xid=0x903))
    # Two PDUs in one segment.
    c.send(1, msg(11, xid=0xa01), msg(11, opt(16, b'second'), xid=0xa02))
    # One PDU split over three segments (reassembly).
    big = msg(3, opt(2, ip4('198.51.100.12')) + opt(3, u8(1))
              + opt(16, b'reassembled ' * 10), xid=0xa03)
    c.send(0, big[:1])
    c.send(0, big[1:40])
    c.send(0, big[40:])
    # Reproducers of the fix: Microsoft UTF-16 options 31, 32, 35, 40 with
    # length 0 and 1 (format_text() got (size_t)-1 before the fix).
    c.send(0, msg(3, opt(31, b'') + opt(32, b'') + opt(35, b'') + opt(40, b''),
                  xid=0xb01))
    c.send(0, msg(3, opt(31, b'A') + opt(32, b'B') + opt(35, b'C') + opt(40, b'D'),
                  xid=0xb02))
    # Disconnect.
    c.send(0, msg(12, opt(21, u8(17)) + opt(16, b'bye'), xid=0xc01))
    c.fin()

    # --- Connection 2: Microsoft style, autodetected (payload offset 8) ---
    m = Tcp(frames, '192.0.2.11', '192.0.2.12', 40002)
    m.send(0, msg(5, opt(22, utf16('rel-ms'))          # relationship-name UTF-16
                  + opt(15, u32(3600))
                  + opt(20, u8(1))
                  + opt(28, utf16('MSFT 5.0'))         # vendor-class UTF-16
                  + opt(17, u8(2) + bytes(32)),       # message-digest Microsoft (opaque)
                  poffset=8, xid=0x1001))
    m.send(1, msg(6, opt(22, utf16('rel-ms')), poffset=8, xid=0x1001))
    # Binding update with every Microsoft option. The UTF-16 strings of
    # options 31, 32, 35 and 40 have no terminating NUL: the whole string
    # is shown since the fix (the last character was cut before).
    m.send(0, msg(3, opt(2, ip4('198.51.100.20'))
                  + opt(3, u8(2))
                  + opt(5, struct.pack('<I', 0xc6336400)  # scope 198.51.100.0, reversed
                        + b'\x01\x02\x00\x5e\x00\x53\x02')
                  + opt(12, u8(0x05))                 # IP-flags, one octet
                  + opt(30, struct.pack('<II', 0xc6336400, 0xc633ff00))  # scope ID list
                  + opt(31, utf16('client1'))         # client name
                  + opt(32, utf16('Test client'))     # client description
                  + opt(33, ip4('255.255.255.0'))     # client subnet mask
                  + opt(34, ip4('192.0.2.12'))        # server IP
                  + opt(35, utf16('dhcp2.example')) # server name
                  + opt(36, u8(1))                    # client type DHCP
                  + opt(37, u8(3))                    # NAP status PROBATION
                  + opt(38, u32(123456))              # NAP probation
                  + opt(39, u8(1))                    # NAP capable
                  + opt(40, utf16('policy-a'))        # matched policy
                  + opt(41, u32(0x00000102))          # extended address state
                  + opt(42, b'\x01'),                 # unknown option
                  poffset=8, xid=0x1101))
    # Strings with a terminating NUL.
    m.send(0, msg(3, opt(31, utf16('client2\0')) + opt(32, utf16('desc\0'))
                  + opt(35, utf16('srv\0')) + opt(40, utf16('pol\0')),
                  poffset=8, xid=0x1102))
    # Every client type and NAP status, and unknown ones.
    for ct, ns in ((0, 0), (2, 1), (3, 2), (4, 9), (0x64, 0), (50, 0)):
        m.send(0, msg(3, opt(36, u8(ct)) + opt(37, u8(ns)) + opt(39, u8(0)),
                      poffset=8, xid=0x1200 + ct))
    # The reproducers again, named as Microsoft options.
    m.send(0, msg(3, opt(31, b'') + opt(32, b'') + opt(35, b'') + opt(40, b''),
                  poffset=8, xid=0x1301))
    m.send(0, msg(3, opt(31, b'A') + opt(32, b'B') + opt(35, b'C') + opt(40, b'D'),
                  poffset=8, xid=0x1302))
    m.send(1, msg(4, opt(2, ip4('198.51.100.20')) + opt(3, u8(2)),
                  poffset=8, xid=0x1101))
    m.fin()


def malformed(frames):
    c = Tcp(frames, '192.0.2.21', '192.0.2.22', 40003)
    # Wrong lengths of every fixed-length option (bad length expert info).
    for code in (2, 10, 1, 21, 15, 13, 18, 6, 25, 24, 23, 14, 19, 12, 20, 27,
                 26, 33, 34, 36, 37, 38, 39, 41):
        c.send(0, msg(3, opt(code, b'\x01\x02\x03'), xid=0x2000 + code))
    c.send(0, msg(3, opt(5, b'\x01'), xid=0x2105))     # hw address too short
    c.send(0, msg(3, opt(17, b''), xid=0x2117))        # digest too short
    c.send(0, msg(3, opt(17, b'\x07abc'), xid=0x2118))  # digest type not allowed
    c.send(0, msg(3, opt(12, b'\x01\x02'), xid=0x2112, poffset=8))  # MS IP flags 2 octets
    c.send(0, msg(3, opt(5, b'\x01\x02\x03'), poffset=8, xid=0x2106))  # MS hw too short
    # Option longer than the message.
    c.send(0, msg(3, struct.pack('!HH', 16, 10) + b'abcd', xid=0x2201))
    # Scope ID list not a multiple of 4.
    c.send(0, msg(3, opt(30, b'\x01\x02\x03\x04\x05\x06'), poffset=8, xid=0x2202))
    c.fin()
    c = Tcp(frames, '192.0.2.21', '192.0.2.22', 40004)
    # Length below the header size.
    c.send(0, struct.pack('!HBBII', 11, 11, 12, T0, 0x2301))
    c.fin()
    c = Tcp(frames, '192.0.2.21', '192.0.2.22', 40005)
    c.send(0, struct.pack('!HBB', 4, 11, 12) + b'\x00\x00\x00\x00')
    c.fin()


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', T0 + i, 0, len(fr), len(fr)))
            f.write(fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    f = []
    clean(f)
    write_pcap(os.path.join(out, 'dhcp_failover-coverage.pcap'), f)
    g = []
    malformed(g)
    write_pcap(os.path.join(out, 'dhcp_failover-coverage-malformed.pcap'), g)
    print(len(f), len(g))


if __name__ == '__main__':
    main()
