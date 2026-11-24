# Generates test/captures/vssmonitoring_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ---- common helpers (copied into each generator) ----
import struct
import os
import sys
import gzip

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def pcap_write(fname, pkts, linktype=1, t0=1700000000):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            olen = None
            if isinstance(p, tuple):
                if len(p) == 3:
                    p, ts, olen = p
                else:
                    p, ts = p
            else:
                ts = t0 + i
            f.write(struct.pack('<IIII', ts, 0, len(p), olen or len(p)))
            f.write(p)

def eth(payload, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01', et=0x0800):
    f = dst + src + struct.pack('!H', et) + payload
    return f + b'\0' * max(0, 60 - len(f))

def ip4(proto, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2), ttl=64, ident=1, flags_frag=0, tos=0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, tos, 20 + len(payload), ident, flags_frag, ttl, proto, 0,
                    bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def ip6(nh, payload, src=bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\1', dst=bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\2', hlim=64):
    return struct.pack('!IHBB', 0x60000000, len(payload), nh, hlim) + src + dst + payload

def udp(sport, dport, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    return u[:6] + struct.pack('!H', c) + u[8:]

def tcp(sport, dport, seq, ack, flags, payload=b'', src=(192, 0, 2, 1), dst=(192, 0, 2, 2), win=65535):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, win, 0, 0) + payload
    ph = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(t))
    return t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    tags = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
    tags += struct.pack('>HH', 0, 0)
    return tags + payload

def rtp(pt, seq, ts, ssrc, payload, marker=0):
    return struct.pack('!BBHII', 0x80, (marker << 7) | pt, seq, ts, ssrc) + payload

def gz(path, gzpath):
    with open(path, 'rb') as f:
        d = f.read()
    with open(gzpath, 'wb') as g:
        g.write(gzip.compress(d, 9, mtime=0))

# ---- VSS Monitoring Ethernet trailer (heuristic on eth.trailer) ----
BASE = 1700000000

def vss_ts(secs, nsecs, clk=0):
    return struct.pack('!II', secs, (clk << 30) | nsecs)

PAYLOAD = b'0123456789abcdefghij'

def frame4(trailer, i=0):
    u = udp(5000 + i, 6000, PAYLOAD)
    return eth(ip4(17, u, ident=100 + i) + trailer)

def frame6(trailer):
    u = struct.pack('!HHHH', 5000, 6000, 8 + len(PAYLOAD), 0) + PAYLOAD
    S = bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\1'
    D = bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\2'
    c = csum(S + D + struct.pack('!IBBBB', len(u), 0, 0, 0, 17) + u)
    u = u[:6] + struct.pack('!H', c) + u[8:]
    return eth(ip6(17, u) + trailer, et=0x86dd)

def frame_vlan(trailer):
    u = udp(5000, 6000, PAYLOAD)
    p = struct.pack('!HH', 0x0064, 0x0800) + ip4(17, u) + trailer
    return eth(p, et=0x8100)

def build(outdir):
    main = []
    ok = []          # frames that must be dissected by default
    main.append(frame4(vss_ts(100, 123456789, 0)))                        # 1 timestamp only, local clock
    main.append(frame4(vss_ts(3600, 999999999, 1) + b'\x07'))             # 2 timestamp + 1-byte port, NTP
    main.append(frame4(vss_ts(200, 1, 2) + b'\xde\xad\xbe\xef'))          # 3 timestamp + FCS, GPS
    main.append(frame4(vss_ts(1, 0, 3) + b'\xde\xad\xbe\xef' + b'\xfe'))  # 4 timestamp + FCS + port, PTP
    # timestamps that look like wall clock times near the capture time
    main.append(frame4(vss_ts(BASE + 4 + 86400, 500, 1) + b'\x10'))        # 5 a day ahead
    main.append(frame4(vss_ts(BASE + 5 - 86400, 500, 2) + b'\x11'))        # 6 a day behind
    main.append(frame4(vss_ts(BASE + 6 + 2592000, 7, 3)))                  # 7 exactly 30 days ahead
    main.append(frame4(vss_ts(BASE + 7 - 2592000, 7, 0)))                  # 8 exactly 30 days behind
    # frames that are not VSS Monitoring trailers (rejected)
    main.append(frame4(vss_ts(0, 5, 0)))                                   # 9 seconds zero
    main.append(frame4(struct.pack('!II', 100, 0x3fffffff)))               # 10 nanoseconds too large
    main.append(frame4(vss_ts(BASE + 10 + 2592001, 7, 0)))                  # 11 more than 30 days ahead
    main.append(frame4(vss_ts(BASE + 11 - 2592001, 7, 0)))                 # 12 more than 30 days behind
    main.append(frame4(vss_ts(100, 5, 0) + b'\0' * 6))                     # 13 14 bytes: too long
    main.append(frame4(b'\xaa\xbb\xcc' + b'\0' * 8))                       # 14 11 bytes: 3 mod 4
    main.append(frame4(b'\x05'))                                           # 15 port stamp only
    main.append(frame4(b'\x00\x05'))                                       # 16 two byte port stamp only
    main.append(frame4(vss_ts(100, 5, 0) + b'\x00\x09'))                   # 17 timestamp + two byte port stamp
    main.append(frame4(b'\x01\x02\x03\x04'))                               # 18 four bytes, no timestamp
    main.append(frame4(b'\x01\x02\x03\x04\x05'))                           # 19 five bytes: port stamp + 4
    # other lower layers
    main.append(frame6(vss_ts(300, 42, 1) + b'\x21'))                      # 20 IPv6
    main.append(frame_vlan(vss_ts(400, 43, 2)))                            # 21 802.1Q
    main.append(frame4(vss_ts(500, 44, 3) + b'\x22', i=21))                # 22
    pcap_write(os.path.join(outdir, 'vssmonitoring-coverage.pcap'), main)

    # the malformed capture: packets the heuristic must handle without help
    mal = []
    # runt trailer on a minimum size frame (padding): zeros are not a trailer
    mal.append(eth(ip4(17, udp(5000, 6000, b'x'))))
    # eth.trailer with a timestamp but a UDP length that hides it
    mal.append(frame4(vss_ts(100, 5, 0))[:-3])
    pcap_write(os.path.join(outdir, 'vssmonitoring-coverage-malformed.pcap'), mal)
    gz(os.path.join(outdir, 'vssmonitoring-coverage.pcap'), os.path.join(outdir, 'vssmonitoring_coverage.pcap.gz'))

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
