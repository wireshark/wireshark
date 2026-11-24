#!/usr/bin/env python3
# Generates test/captures/udp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the UDP / UDP-Lite coverage captures. Usage: mkudp.py <outdir> [-v]

Everything is built with struct; addresses come from 192.0.2.0/24,
198.51.100.0/24 and 2001:db8::/32. udp-coverage.pcapng has two interfaces:
Ethernet (1) and Exported PDU (252); udp-coverage-malformed.pcapng the same.
"""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv

# ---- helpers -----------------------------------------------------------

def ip4(s):
    return bytes(int(x) for x in s.split('.'))

def ip6(s):
    import socket
    return socket.inet_pton(socket.AF_INET6, s)

def fold(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return s

def csum(b):
    return (~fold(b)) & 0xffff

def pseudo(src, dst, proto, length):
    if len(src) == 4:
        return src + dst + struct.pack('>BBH', 0, proto, length)
    return src + dst + struct.pack('>II', length, proto)

def udp_csum(src, dst, udp, proto=17, cov=None):
    """Checksum of the datagram `udp` (checksum field must be 0)."""
    n = len(udp) if cov is None else cov
    c = csum(pseudo(src, dst, proto, len(udp)) + udp[:n])
    return c if c else 0xffff

def partial_csum(src, dst, proto, length):
    return fold(pseudo(src, dst, proto, length))

def udp(sp, dp, payload, src=None, dst=None, ck='ok', length=None):
    """UDP datagram. ck: 'ok' valid, 'zero', 'bad', 'partial', or an int."""
    ln = 8 + len(payload) if length is None else length
    hdr = struct.pack('>HHHH', sp, dp, ln, 0)
    d = hdr + payload
    if ck == 'zero':
        v = 0
    elif ck == 'ok':
        v = udp_csum(src, dst, d)
    elif ck == 'bad':
        v = udp_csum(src, dst, d) ^ 0x5a5a or 0x1111
    elif ck == 'partial':
        v = partial_csum(src, dst, 17, ln)
    else:
        v = ck
    return struct.pack('>HHHH', sp, dp, ln, v) + payload

def udplite(sp, dp, payload, src, dst, cov, ck='ok'):
    hdr = struct.pack('>HHHH', sp, dp, cov, 0)
    d = hdr + payload
    n = len(d) if cov == 0 else min(cov, len(d))
    if ck == 'ok':
        v = udp_csum(src, dst, d, proto=136, cov=n)
    elif ck == 'zero':
        v = 0
    else:
        v = ck
    return struct.pack('>HHHH', sp, dp, cov, v) + payload

MAC_A = b'\x02\0\0\0\0\x01'
MAC_B = b'\x02\0\0\0\0\x02'

def ipv4(src, dst, proto, payload, ident=1, flags_off=0, ttl=64, tos=0, totlen=None):
    tl = 20 + len(payload) if totlen is None else totlen
    h = struct.pack('>BBHHHBBH4s4s', 0x45, tos, tl, ident, flags_off, ttl, proto, 0, src, dst)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def ipv6(src, dst, nh, payload, plen=None, hlim=64):
    pl = len(payload) if plen is None else plen
    return struct.pack('>IHBB', 0x60000000, pl, nh, hlim) + src + dst + payload

def eth(ethertype, payload, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack('>H', ethertype) + payload

def e4(src, dst, proto, payload, **kw):
    return eth(0x0800, ipv4(src, dst, proto, payload, **kw))

def e6(src, dst, nh, payload, **kw):
    return eth(0x86dd, ipv6(src, dst, nh, payload, **kw))

# ---- pcapng ------------------------------------------------------------

def blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def opt(code, val):
    pad = (-len(val)) % 4
    return struct.pack('<HH', code, len(val)) + val + b'\0' * pad

def pcapng(fn, frames, base_ts=1700000000, step=1000):
    """frames: list of (iface, data[, caplen])."""
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1) +
              opt(4, b'mkudp.py') + opt(0, b''))
    out += blk(1, struct.pack('<HHI', 1, 0, 262144) + opt(9, b'\x06') + opt(0, b''))
    out += blk(1, struct.pack('<HHI', 252, 0, 262144) + opt(9, b'\x06') + opt(0, b''))
    t = base_ts * 1000000
    for f in frames:
        iface, data = f[0], f[1]
        cap = f[2] if len(f) > 2 else len(data)
        ts = f[3] if len(f) > 3 else None
        t += step * 1000 if ts is None else ts
        out += blk(6, struct.pack('<IIIII', iface, t >> 32, t & 0xffffffff, cap, len(data)) + data[:cap])
    with open(os.path.join(OUT, fn), 'wb') as f:
        f.write(out)

def tag(t, v):
    pad = (-len(v)) % 4
    return struct.pack('>HH', t, len(v) + pad) + v + b'\0' * pad

def exppdu(name, payload, tags=b''):
    return tag(12, name.encode()) + tags + struct.pack('>HH', 0, 0) + payload

# ---- payloads ----------------------------------------------------------

def dns_query(tid=0x1234, name=b'\x07example\x03com\x00'):
    return struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0) + name + struct.pack('>HH', 1, 1)

def dns_response(tid=0x1234, name=b'\x07example\x03com\x00'):
    return (struct.pack('>HHHHHH', tid, 0x8180, 1, 1, 0, 0) + name + struct.pack('>HH', 1, 1) +
            b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 300, 4) + ip4('93.184.216.34'))

def ntp(mode=3):
    return bytes([0x20 | mode, 0, 6, 0xec]) + b'\0' * 44

def stun_req(txid=b'0123456789ab'):
    return struct.pack('>HHI', 1, 0, 0x2112A442) + txid

def knx_search(port=3671):
    hpai = struct.pack('>BB4sH', 8, 1, ip4('192.0.2.50'), port)
    return struct.pack('>BBHH', 6, 0x10, 0x0201, 6 + len(hpai)) + hpai

def knx_disc():
    hpai = struct.pack('>BB4sH', 8, 1, ip4('192.0.2.50'), 3671)
    return struct.pack('>BBHH', 6, 0x10, 0x0209, 6 + 2 + len(hpai)) + b'\x01\x00' + hpai

def icmp(typ, code, inner_ip, unused=0):
    h = struct.pack('>BBHI', typ, code, 0, unused) + inner_ip
    return h[:2] + struct.pack('>H', csum(h)) + h[4:]

# ---- addresses ---------------------------------------------------------

A4 = ip4('192.0.2.10'); B4 = ip4('192.0.2.20'); R4 = ip4('198.51.100.7')
T4 = ip4('192.0.2.30'); SELF4 = ip4('192.0.2.5')
A6 = ip6('2001:db8::10'); B6 = ip6('2001:db8::20')

main = []
marks = {}
def add(name, frame, iface=0, cap=None, ts=None):
    main.append((iface, frame) if cap is None and ts is None else (iface, frame, cap if cap is not None else len(frame), ts))
    marks.setdefault(name, []).append(len(main))

# ---- main capture ------------------------------------------------------
# DNS over IPv4: valid checksums, two directions (timestamps, delta)
add('dns', e4(A4, B4, 17, udp(53123, 53, dns_query(), A4, B4)))
add('dns', e4(B4, A4, 17, udp(53, 53123, dns_response(), B4, A4), ident=2))
# zero checksum over IPv4 (ignored), unknown port: Data
add('zero4', e4(A4, B4, 17, udp(40000, 40001, b'hello world', ck='zero'), ident=3))
# empty payload, with Ethernet padding
add('empty', e4(A4, B4, 17, udp(40000, 40001, b'', A4, B4), ident=4) + b'\0' * 18)
# length smaller than the IP payload (trailing bytes ignored)
p = b'abcdefghijklmnopqrstuvwx'
add('shortlen', e4(A4, B4, 17, udp(40002, 40003, p[:12], A4, B4) + p[12:], ident=5))
# source port 0, same address on both sides (direction taken from the ports)
add('port0', e4(A4, B4, 17, udp(0, 40004, b'port zero', A4, B4), ident=6))
add('self', e4(SELF4, SELF4, 17, udp(5000, 6000, b'to self', SELF4, SELF4), ident=7))
add('self', e4(SELF4, SELF4, 17, udp(6000, 5000, b'from self', SELF4, SELF4), ident=8))
# partial checksum (checksum offload): pseudo header sum in the field
add('partial', e4(A4, B4, 17, udp(40005, 40006, b'offloaded', A4, B4, ck='partial'), ident=9))
# a DNS query on ports nobody registered (Decode As reaches it), and NTP
# where only the higher port is registered
add('dnsother', e4(A4, B4, 17, udp(40050, 40051, dns_query(0x4321), A4, B4), ident=10))
add('ntphigh', e4(A4, B4, 17, udp(100, 123, ntp(3), A4, B4), ident=11))
# IPv6: NTP with a valid checksum
add('ntp6', e6(A6, B6, 17, udp(40123, 123, ntp(3), A6, B6)))
add('ntp6', e6(B6, A6, 17, udp(123, 40123, ntp(4), B6, A6)))
# jumbogram: Hop-by-Hop with the jumbo payload option, UDP length 0
big = bytes((i * 7) & 0xff for i in range(256)) * 257          # 65792 octets
jl = 8 + len(big)
hbh = struct.pack('>BBBBI', 17, 0, 0xc2, 4, 8 + jl)
u = struct.pack('>HHHH', 40130, 40131, 0, 0) + big
ck = udp_csum(A6, B6, struct.pack('>HHHH', 40130, 40131, 0, 0) + big)
u = struct.pack('>HHHH', 40130, 40131, 0, ck) + big
add('jumbo', e6(A6, B6, 0, hbh + u, plen=0))
# traceroute: probes, an ICMP time exceeded and port unreachable (UDP in an error packet)
pr = []
for i, dp in enumerate((33435, 33436, 33437)):
    u = udp(40010 + i, dp, b'traceroute probe %d' % i, T4, R4)
    ip = ipv4(T4, R4, 17, u, ident=100 + i, ttl=1 + i)
    pr.append(ip)
    add('probe', eth(0x0800, ip))
add('icmp', e4(ip4('192.0.2.1'), T4, 1, icmp(11, 0, pr[0][:28]), ident=110))
add('icmp', e4(R4, T4, 1, icmp(3, 3, pr[2][:28]), ident=111))
# a second error packet for the same flow extends the error conversation
add('icmp', e4(R4, T4, 1, icmp(3, 3, pr[2][:28]), ident=113))
# a source port in the traceroute range
add('trsrc', e4(A4, B4, 17, udp(33440, 40007, b'src in range', A4, B4), ident=112))
# TFTP: request to port 69, data from a new port: the conversation dissector
tc, ts_ = ip4('192.0.2.11'), ip4('192.0.2.21')
add('tftp', e4(tc, ts_, 17, udp(51000, 69, b'\0\x01file.txt\0octet\0', tc, ts_), ident=120))
add('tftp', e4(ts_, tc, 17, udp(50000, 51000, b'\0\x03\0\x01' + b'tftp data block', ts_, tc), ident=121))
add('tftp', e4(tc, ts_, 17, udp(51000, 50000, b'\0\x04\0\x01', tc, ts_), ident=122))
# STUN on a port nobody registered: found by the heuristic dissector
add('stunheur', e4(A4, B4, 17, udp(41000, 41001, stun_req(), A4, B4), ident=130))
add('stunheur', e4(B4, A4, 17, udp(41001, 41000, stun_req(b'ba9876543210'), B4, A4), ident=131))
# STUN on its port, two PDUs in one datagram, and KNXnet/IP (udp_dissect_pdus users)
add('stun', e4(A4, B4, 17, udp(41002, 3478, stun_req() + stun_req(b'zyxwvutsrqpo'), A4, B4), ident=132))
add('knx', e4(A4, B4, 17, udp(41003, 3671, knx_search() + knx_search() + knx_disc(), A4, B4), ident=133))
# fragmented IPv4 datagram (reassembled by IP): 3000 octets of payload
payload = bytes((i * 11) & 0xff for i in range(3000))
u = udp(41010, 41011, payload, A4, B4)
add('frag', e4(A4, B4, 17, u[:1480], ident=140, flags_off=0x2000))
add('frag', e4(A4, B4, 17, u[1480:], ident=140, flags_off=1480 // 8))
# truncated capture: the checksum cannot be verified
u = udp(41020, 41021, b'x' * 200, A4, B4)
f = e4(A4, B4, 17, u, ident=150)
add('trunc', f, cap=80)
# UDP-Lite: partial coverage, whole datagram (0) and full coverage; IPv4 and IPv6
pl_ = b'UDP-Lite payload bytes!!'
add('lite', e4(A4, B4, 136, udplite(41030, 41031, pl_, A4, B4, 12), ident=160))
add('lite', e4(A4, B4, 136, udplite(41030, 41031, pl_, A4, B4, 0), ident=161))
add('lite', e4(A4, B4, 136, udplite(41030, 41031, pl_, A4, B4, 8 + len(pl_)), ident=162))
add('lite6', e6(A6, B6, 136, udplite(41032, 41033, pl_, A6, B6, 16)))
add('lite6', e6(A6, B6, 136, udplite(41032, 41033, pl_, A6, B6, 0)))
# Exported PDU naming "udp": no IP addresses, non-zero and zero checksums
add('exp', exppdu('udp', udp(40000, 40001, b'hello', ck=0x1234)), iface=1)
add('exp', exppdu('udp', udp(40002, 40003, b'zero checksum', ck='zero')), iface=1)
add('exp', exppdu('udp', udp(40123, 123, ntp(3), ck=0x4321)), iface=1)
# ---- process information: UDP flow followed by an IPFIX record (CACE process
# fields); udp.process_info shows it in the UDP tree -----------------------
CACE = 32622
def ipfix_tmpl(tid, fields):
    body = b''
    for fid, ln, ent in fields:
        if ent:
            body += struct.pack('>HHI', 0x8000 | fid, ln, ent)
        else:
            body += struct.pack('>HH', fid, ln)
    return struct.pack('>HHHH', 2, 4 + 4 + len(body), tid, len(fields)) + body

def ipfix_msg(sets, seq=0):
    body = b''.join(sets)
    return struct.pack('>HHIII', 10, 16 + len(body), 1700000000, seq, 0) + body

fields = [(0, 4, CACE), (1, 4, CACE), (4, 2, CACE), (5, 2, CACE), (8, 4, CACE),
          (9, 4, CACE), (10, 1, CACE), (11, 1, CACE)]
tmpl = ipfix_tmpl(257, fields)
def rec(la, ra, lp, rp, uid, pid, un, cmd):
    r = la + ra + struct.pack('>HHII', lp, rp, uid, pid)
    r += bytes([len(un)]) + un + bytes([len(cmd)]) + cmd
    return r
def dset(tid, recs):
    body = b''.join(recs)
    pad = (-(4 + len(body))) % 4
    return struct.pack('>HH', tid, 4 + len(body) + pad) + body + b'\0' * pad
pi = []
lh, rh = ip4('192.0.2.40'), ip4('192.0.2.41')
pi.append((0, e4(lh, rh, 17, udp(42000, 42001, b'process flow', lh, rh), ident=1)))
pi.append((0, e4(rh, lh, 17, udp(42001, 42000, b'reply', rh, lh), ident=2)))
ex = ip4('192.0.2.99'); col = ip4('192.0.2.98')
ipf = ipfix_msg([tmpl, dset(257, [rec(lh, rh, 42000, 42001, 1000, 4321, b'alice', b'/usr/bin/dnsprobe'),
                                   rec(rh, lh, 42001, 42000, 0, 99, b'root', b'daemon'),
                                   rec(ip4('192.0.2.77'), rh, 1, 2, 5, 6, b'nobody', b'noflow')])])
pi.append((0, e4(ex, col, 17, udp(40500, 4739, ipf, ex, col), ident=3)))
pi.append((0, e4(lh, rh, 17, udp(42000, 42001, b'again', lh, rh), ident=4)))
pi.append((0, e4(rh, lh, 17, udp(42001, 42000, b'again', rh, lh), ident=5)))
for f in pi:
    add('process', f[1])

pcapng('udp-coverage.pcapng', main)

# ---- malformed capture ---------------------------------------------------
mal = []
def m(frame, iface=0, cap=None):
    mal.append((iface, frame) if cap is None else (iface, frame, cap))
    return len(mal)
mm = {}
# bad checksums (errors when udp.check_checksum is on)
mm['badck'] = m(e4(A4, B4, 17, udp(40000, 40001, b'bad checksum', A4, B4, ck='bad'), ident=1))
mm['badck6'] = m(e6(A6, B6, 17, udp(40000, 40001, b'bad checksum', A6, B6, ck='bad')))
# IPv6 zero checksum is illegal (ignored with udp.ignore_ipv6_zero_checksum)
mm['zero6'] = m(e6(A6, B6, 17, udp(40000, 40001, b'zero over ipv6', ck='zero')))
# length < 8, length > IP payload
mm['len4'] = m(e4(A4, B4, 17, udp(40000, 40001, b'short', A4, B4, length=4), ident=2))
mm['len0v4'] = m(e4(A4, B4, 17, udp(40000, 40001, b'zero length', A4, B4, length=0), ident=3))
mm['lenbig'] = m(e4(A4, B4, 17, udp(40000, 40001, b'long length', A4, B4, length=200), ident=4))
mm['lenbig_dns'] = m(e4(A4, B4, 17, udp(40010, 53, dns_query(), A4, B4, length=300), ident=5))
# length zero over IPv6 but the payload is shorter than 65536 (not a jumbogram)
mm['len0v6'] = m(e6(A6, B6, 17, udp(40000, 40001, b'not a jumbogram', length=0, ck=0x4444)))
# UDP-Lite: coverage < 8, coverage > length, zero checksum
mm['liteck0'] = m(e4(A4, B4, 136, udplite(41030, 41031, pl_, A4, B4, 12, ck='zero'), ident=6))
mm['litecov4'] = m(e4(A4, B4, 136, udplite(41030, 41031, pl_, A4, B4, 4, ck=0x1111), ident=7))
mm['litecov99'] = m(e4(A4, B4, 136, udplite(41030, 41031, pl_, A4, B4, 99, ck=0x1111), ident=8))
mm['litebad'] = m(e4(A4, B4, 136, udplite(41030, 41031, pl_, A4, B4, 12, ck=0x2222), ident=9))
# KNXnet/IP: PDU length shorter than the header (bounds error), a PDU that
# runs past the end, a PDU with a truncated service, and a zero length
mm['knx_short'] = m(e4(A4, B4, 17, udp(41003, 3671, struct.pack('>BBHH', 6, 0x10, 0x0201, 3), A4, B4), ident=10))
mm['knx_trunc'] = m(e4(A4, B4, 17, udp(41003, 3671, knx_search() + struct.pack('>BBHH', 6, 0x10, 0x0201, 14) + b'\x08\x01', A4, B4), ident=11))
mm['knx_zero'] = m(e4(A4, B4, 17, udp(41003, 3671, knx_search() + struct.pack('>BBHH', 6, 0x10, 0x0201, 0), A4, B4), ident=12))
# udp.length bigger than captured, truncated frame, IPv4 fragment alone
u = udp(41040, 41041, b'y' * 100, A4, B4)
mm['trunc'] = m(e4(A4, B4, 17, u, ident=13), cap=60)
# UDP header truncated to 6 octets
mm['hdr6'] = m(e4(A4, B4, 17, udp(41050, 41051, b'z', A4, B4)[:6], ident=14))
# ICMP error with a UDP header whose length is bad (in an error packet)
inner = ipv4(T4, R4, 17, struct.pack('>HHHH', 40020, 33438, 4, 0), ident=15)
mm['icmp_bad'] = m(e4(R4, T4, 1, icmp(3, 3, inner[:28]), ident=16))
# ICMP error with an UDP header cut after 4 octets
inner = ipv4(T4, R4, 17, struct.pack('>HHHH', 40021, 53, 8, 0), ident=17)
mm['icmp_short'] = m(e4(R4, T4, 1, icmp(3, 3, inner[:24]), ident=18))
# STUN PDUs that throw while the datagram loop goes on: an attribute longer
# than the message, and a message cut short
stun_attr = struct.pack('>HHI', 1, 8, 0x2112A442) + b'0123456789ab' + struct.pack('>HH', 6, 100) + b'abcd'
mm['stun_attr'] = m(e4(A4, B4, 17, udp(41002, 3478, stun_req() + stun_attr + stun_req(b'zyxwvutsrqpo'), A4, B4), ident=19))
mm['stun_cut'] = m(e4(A4, B4, 17, udp(41002, 3478, struct.pack('>HHI', 1, 60, 0x2112A442) + b'0123456789ab' + struct.pack('>HH', 6, 40) + b'abcd', A4, B4), ident=20))
# Exported PDU "udp" with a short header
mm['exp_short'] = m(exppdu('udp', b'\x9c\x40\x9c'), iface=1)
mm['exp_bad'] = m(exppdu('udp', udp(40000, 40001, b'bad', length=3, ck=0x1234)), iface=1)
mm['exp_udplite'] = m(exppdu('udplite', udplite(40000, 40001, b'lite', b'', b'', 99, ck=0x1234)), iface=1)
pcapng('udp-coverage-malformed.pcapng', mal)

if VERBOSE:
    print(marks)
    print(mm)
    print('main', len(main), 'malformed', len(mal))
