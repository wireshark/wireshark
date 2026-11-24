# Generates test/captures/vtp_coverage.pcap.gz
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
            if isinstance(p, tuple):
                p, ts = p
            else:
                ts = t0 + i
            f.write(struct.pack('<IIII', ts, 0, len(p), len(p)))
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

# ---- VTP: Ethernet 802.3 + LLC/SNAP (OUI 00000c, PID 0x2003) ----
def llc_vtp(vtp, dst=b'\x01\x00\x0c\xcc\xcc\xcc', src=b'\x00\x1b\x2b\x00\x00\x01'):
    p = b'\xaa\xaa\x03\x00\x00\x0c\x20\x03' + vtp
    f = dst + src + struct.pack('!H', len(p)) + p
    return f + b'\0' * max(0, 60 - len(f))

def dom(name):
    return name.encode().ljust(32, b'\0')

def summary(ver=2, followers=1, domain='lab', rev=7, updater=(10, 0, 0, 1), ts=b'990101123456',
            digest=bytes(range(16))):
    return (struct.pack('!BBBB', ver, 1, followers, len(domain)) + dom(domain) +
            struct.pack('!I', rev) + bytes(updater) + ts + digest)

def vlan_info(vid, name, vtype=1, status=0, mtu=1500, idx=None, tlvs=b'', length=None):
    nl = len(name)
    padded = name.encode().ljust(4 * ((nl + 3) // 4), b'\0')
    body = struct.pack('!BBHHI', status, vtype, 0, 0, 0)[:0]
    body = struct.pack('!BBBHHI', status, vtype, nl, vid, mtu, 0x100000 + vid if idx is None else idx)
    total = 1 + len(body) + len(padded) + len(tlvs) if length is None else length
    return struct.pack('!B', total) + body + padded + tlvs

def tlv(t, vals=None, length=None, raw=b''):
    data = b''.join(struct.pack('!H', v) for v in (vals or [])) + raw
    return struct.pack('!BB', t, len(data) // 2 if length is None else length) + data

def subset(seq=1, domain='lab', rev=7, infos=b'', ver=2):
    return struct.pack('!BBBB', ver, 2, seq, len(domain)) + dom(domain) + struct.pack('!I', rev) + infos

def request(domain='lab', start=0x0001, ver=2):
    return struct.pack('!BBBB', ver, 3, 0, len(domain)) + dom(domain) + struct.pack('!H', start)

def join(domain='lab', first=1, last=64, bitmap=b'\xaa\x55\xff\x00\x01\x80\x00\x00', ver=2):
    return struct.pack('!BBBB', ver, 4, 0, len(domain)) + dom(domain) + struct.pack('!HH', first, last) + bitmap

def build(outdir):
    main = []
    # summary advertisements: v1, v2 (followers), v3, valid and invalid timestamps
    main.append(llc_vtp(summary(ver=1, followers=0, domain='lab', rev=1)))
    main.append(llc_vtp(summary(ver=2, followers=3, domain='campus-core', rev=0x01020304)))
    main.append(llc_vtp(summary(ver=3, followers=0, domain='x' * 32, rev=0xffffffff,
                                ts=b'abcdefabcdef')))
    main.append(llc_vtp(summary(ver=2, followers=1, domain='', rev=0, ts=b'000000000000')))
    # subset advertisements
    tl_all = (tlv(1, [0x0123]) + tlv(2, [0x000f]) + tlv(3, [1]) + tlv(4, [0x0064]) +
              tlv(5, [0x0065]) + tlv(6, [1]) + tlv(7, [2]) + tlv(8, [7]) + tlv(9, [5]) + tlv(10, [1]))
    infos = (vlan_info(1, 'default', 1, 0, 1500) +
             vlan_info(2, 'fddi-default', 2, 1, 1500) +
             vlan_info(1002, 'trcrf-default', 3, 0, 4472, tlvs=tl_all) +
             vlan_info(1003, 'token-ring-default', 4, 0, 4472) +
             vlan_info(1005, 'trbrf-default', 5, 0, 4472, tlvs=tlv(7, [1]) + tlv(3, [3])) +
             vlan_info(10, 'a', 1) + vlan_info(11, 'abcd', 1) + vlan_info(12, 'abcde', 1))
    main.append(llc_vtp(subset(1, 'lab', 7, infos)))
    # other values of the enumerations, an unknown TLV and an empty TLV
    tl2 = (tlv(3, [1]) + tlv(3, [2]) + tlv(6, [2]) + tlv(7, [1]) + tlv(10, [2]) +
           tlv(0x42, raw=b'\xde\xad\xbe\xef') + tlv(0x55, length=0))
    main.append(llc_vtp(subset(2, 'lab', 8, vlan_info(100, 'vlan100', 1, 0, 1500, tlvs=tl2))))
    # every known TLV type with two words (bad length: one is expected)
    bad = b''.join(tlv(t, [1, 2]) for t in range(1, 11))
    main.append(llc_vtp(subset(3, 'lab', 9, vlan_info(200, 'badtlv', 1, 0, 1500, tlvs=bad))))
    main.append(llc_vtp(subset(4, 'lab', 9, b'')))
    # advertisement request
    main.append(llc_vtp(request('lab', 1)))
    main.append(llc_vtp(request('campus-core', 0x03e9, ver=1)))
    # join / prune
    main.append(llc_vtp(join('lab', 1, 64)))
    main.append(llc_vtp(join('lab', 1000, 1007, bitmap=b'\xff')))
    main.append(llc_vtp(join('lab', 0, 0, bitmap=b'')))
    # unknown code
    main.append(llc_vtp(struct.pack('!BBBB', 2, 9, 0, 3) + dom('lab') + b'\0' * 8))
    main.append(llc_vtp(summary(ver=2, followers=0, domain='lab', rev=99), src=b'\x00\x1b\x2b\x00\x00\x02'))
    pcap_write(os.path.join(outdir, 'vtp-coverage.pcap'), main)

    mal = []
    # VLAN info length zero: the loop stops
    mal.append(llc_vtp(subset(5, 'lab', 9, b'\x00' * 24)))
    # declared VLAN information length larger than the data
    mal.append(llc_vtp(subset(6, 'lab', 9, vlan_info(7, 'cut', 1, 0, 1500, tlvs=tlv(1, [1]), length=60))))
    # TLV length running past the end
    mal.append(llc_vtp(subset(7, 'lab', 9, vlan_info(8, 'run', 1, 0, 1500, tlvs=tlv(0x77, length=200)))))
    # summary advertisement too short for the Info column (revision at offset 36)
    mal.append(llc_vtp(struct.pack('!BBBB', 2, 1, 0, 3) + dom('lab')[:20]))
    mal.append(llc_vtp(struct.pack('!BBBB', 2, 2, 1, 3) + b'lab'))
    mal.append(llc_vtp(b'\x02\x03'))
    mal.append(llc_vtp(b'\x02\x04' + b'\0' * 4))
    pcap_write(os.path.join(outdir, 'vtp-coverage-malformed.pcap'), mal)
    gz(os.path.join(outdir, 'vtp-coverage.pcap'), os.path.join(outdir, 'vtp_coverage.pcap.gz'))

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
