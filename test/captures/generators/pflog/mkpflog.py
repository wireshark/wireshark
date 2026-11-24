#!/usr/bin/env python3
# Generates test/captures/pflog_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-pflog.c. usage: mkpflog.py <outdir>
#
# OpenBSD pf log headers: link type 117 (PFLOG) and, for the pre 3.4 header,
# link type 17 (OLD_PFLOG). The header layouts are those of OpenBSD 3.4
# (length 45), 3.8 (61, with uid/pid) and 4.9 (100, with addresses).
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from lib import (
    epb, exp_pdu, gz, idb, ip4, ip6, ipv4, ipv6, shb, udp6_payload, udp_payload, write_pcap,
    write_pcapng,
)

out = sys.argv[1]
AF_INET, AF_INET6_BSD, AF_INET6_FREEBSD, AF_INET6_DARWIN = 2, 24, 28, 30

def name(s, n=16): return s.encode().ljust(n, b'\0')

def pflog(length, af, action=0, reason=0, ifname='em0', ruleset='', rulenr=1, subrule=0xffffffff,
          direction=1, ids=(1000, 4321, 7, 8), end='<', rewritten=0,
          saddr=None, daddr=None, sport=1234, dport=80, payload=b''):
    h = struct.pack('BBBB', length, af, action, reason) + name(ifname) + name(ruleset)
    h += struct.pack('>Ii', rulenr, subrule - (1 << 32) if subrule >= 1 << 31 else subrule)
    if length >= 61:
        h += struct.pack(end + 'iiii', *ids)
    h += bytes((direction,))
    if length >= 100:
        saddr = saddr or ip4('192.0.2.1').ljust(16, b'\0')
        daddr = daddr or ip4('192.0.2.2').ljust(16, b'\0')
        h += bytes((rewritten, 0, 0)) + saddr + daddr + struct.pack('>HH', sport, dport)
    else:
        h += b'\0\0\0'
    return h.ljust((length + 3) & ~3, b'\0') + payload

v4 = ipv4(17, udp_payload(1234, 80, b'hello'))
v6 = ipv6(17, udp6_payload(1234, 80, b'hello6'))
frames = []
# the three header lengths with IPv4
frames.append(pflog(45, AF_INET, payload=v4))
frames.append(pflog(61, AF_INET, payload=v4))
frames.append(pflog(100, AF_INET, payload=v4))
# a header length between the sizes (taken as the 3.8 layout)
frames.append(pflog(72, AF_INET, payload=v4))
# every address family with the 100 byte header: IPv6 variants and unknown
for af in (AF_INET6_BSD, AF_INET6_FREEBSD, AF_INET6_DARWIN):
    sa = ip6('2001:db8::1'); da = ip6('2001:db8::2')
    frames.append(pflog(100, af, saddr=sa, daddr=da, payload=v6))
frames.append(pflog(100, 99, saddr=b'\x01' * 16, daddr=b'\x02' * 16, payload=b'unknown family payload'))
frames.append(pflog(61, 99, payload=b'unknown family'))
frames.append(pflog(45, AF_INET6_BSD, payload=v6))
# every action (the names depend on the build's OS: only the common ones
# are named) and a range of reasons
for action in range(0, 17):
    frames.append(pflog(100, AF_INET, action=action, reason=action % 18, rulenr=action, subrule=action, payload=v4))
for reason in range(0, 18):
    frames.append(pflog(61, AF_INET, action=1, reason=reason, ruleset='anchor/test', payload=v4))
# directions
for d in range(0, 5):
    frames.append(pflog(100, AF_INET, direction=d, payload=v4))
# long interface and ruleset names (16 bytes, no terminating NUL)
frames.append(pflog(100, AF_INET, ifname='abcdefghijklmnop', ruleset='0123456789abcdef', payload=v4))
# the same big-endian ids and the rule number -1
frames.append(pflog(61, AF_INET, ids=(-1, -2, 3, 4), rulenr=0xfffffff0, subrule=0xffffffff, payload=v4))
# header with no payload (unknown family)
frames.append(pflog(100, 99))
# the pre 3.4 header (below) has link type 17 only on OpenBSD builds of the
# tools, so it goes into the main capture as Exported PDU frames naming "pflog-old"
main_frames = list(frames)

# little-endian uid/pid (the preference id_endian = little), same data
fl = [pflog(61, AF_INET, ids=(1000, 4321, 7, 8), end='<', payload=v4),
      pflog(61, AF_INET, ids=(-1, 0x12345678, 7, 8), end='<', payload=v4)]
write_pcap(out + '/pflog-coverage-le.pcap', fl, 117)

# pre 3.4 header: af(4) ifname(16) rnr(2) reason(2) action(2) dir(2)
def old(af, rnr=3, reason=0, action=0, direction=0, payload=b''):
    return struct.pack('>I', af) + name('xl0') + struct.pack('>HHHH', rnr, reason, action, direction) + payload
fo = [old(AF_INET, payload=v4), old(AF_INET, action=1, direction=1, reason=5, payload=v4),
      old(AF_INET6_BSD, payload=v6), old(99, payload=b'unknown family'),
      old(AF_INET, rnr=0xffff, action=3, direction=7, reason=20, payload=v4), old(99)]
blocks = [shb(), idb(117), idb(252)]
blocks += [epb(f, 0) for f in main_frames]
blocks += [epb(exp_pdu('pflog-old', f), 1) for f in fo]
write_pcapng(out + '/pflog-coverage.pcapng', blocks)

# little-endian uid/pid (the preference id_endian = little), same data
fl = [pflog(61, AF_INET, ids=(1000, 4321, 7, 8), end='<', payload=v4),
      pflog(61, AF_INET, ids=(-1, 0x12345678, 7, 8), end='<', payload=v4)]
write_pcap(out + '/pflog-coverage-le.pcap', fl, 117)

# malformed: short header lengths (error), truncated headers and payloads
mal = [pflog(0, AF_INET, payload=v4), pflog(44, AF_INET, payload=v4), pflog(20, AF_INET),
       pflog(61, AF_INET, payload=v4)[:30], pflog(100, AF_INET, payload=v4)[:70],
       pflog(100, AF_INET, payload=v4)[:104], pflog(45, AF_INET)[:10], b'', b'\x2d',
       pflog(255, AF_INET, payload=v4), pflog(100, AF_INET, payload=v4[:10])]
write_pcap(out + '/pflog-coverage-malformed.pcap', mal, 117)
mo = [shb(), idb(252)]
for f in (old(AF_INET, payload=v4)[:20], old(AF_INET)[:5], b'', old(AF_INET, payload=v4)[:30]):
    mo.append(epb(exp_pdu('pflog-old', f), 0))
write_pcapng(out + '/pflog-coverage-old-malformed.pcapng', mo)
gz(out + '/pflog-coverage.pcapng')
print('ok')
