#!/usr/bin/env python3
# Generates test/captures/pgm_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-pgm.c. usage: mkpgm.py <outdir>
#
# PGM (RFC 3208) over IP protocol 113, and over UDP (ports 3055-3056, which
# the pgm.udp.port preference has to name). Every packet type, every option,
# IPv4 and IPv6 addresses, checksums.
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from lib import csum, eth, gz, ip4, ip6, ipv4, ipv6, udp, write_pcap

out = sys.argv[1]
GSI = bytes.fromhex('0a0b0c0d0e0f')
SPM, ODATA, RDATA, NAK, NNAK, NCF, POLL, POLR, ACK, ACK2 = 0x00, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x01, 0x02, 0x0b, 0x0d
OPT, NETSIG, VARLEN, PARITY = 0x01, 0x02, 0x40, 0x80

def nla(afi, v6=False):
    if afi == 1: return struct.pack('!HH', 1, 0) + ip4('192.0.2.77')
    if afi == 2: return struct.pack('!HH', 2, 0) + ip6('2001:db8::77')
    return struct.pack('!HH', afi, 0) + b'\x00' * 4

def pgm(typ, body=b'', opts=0, options=b'', tsdulen=0, sport=7500, dport=7501, cksum='ok', payload=b''):
    h = struct.pack('!HHBBH', sport, dport, typ, opts, 0) + GSI + struct.pack('!H', tsdulen) + body
    if options:
        h += struct.pack('!BBH', 0, 4, 4 + len(options)) + options
    h += payload
    if cksum == 'ok':
        c = csum(h)
    elif cksum == 'zero':
        c = 0
    else:
        c = cksum
    return h[:6] + struct.pack('!H', c) + h[8:]

def opt(typ, body, end=False, length=None, opx=0):
    '''One option: type (END bit), length, opx, then the body (reserved byte first)'''
    ln = 3 + len(body) if length is None else length
    return bytes((typ | (0x80 if end else 0), ln, opx)) + body

def spm(afi=1, **k): return pgm(SPM, struct.pack('!III', 1, 100, 200) + nla(afi), **k)
def odata(payload=b'payload', sqn=5, **k): return pgm(ODATA, struct.pack('!II', sqn, 100), payload=payload, tsdulen=len(payload), **k)
def rdata(payload=b'repair', sqn=6, **k): return pgm(RDATA, struct.pack('!II', sqn, 100), payload=payload, tsdulen=len(payload), **k)
def nak(typ=NAK, a=1, b=1, **k): return pgm(typ, struct.pack('!I', 9) + nla(a) + nla(b), **k)
def poll(sub=0, afi=1, **k): return pgm(POLL, struct.pack('!IHH', 3, 2, sub) + nla(afi) + struct.pack('!III', 100, 0x55, 0xff), **k)
def polr(**k): return pgm(POLR, struct.pack('!IHH', 3, 2, 0), **k)
def ack(typ=ACK, **k): return pgm(typ, struct.pack('!II', 12, 0xfffffffe), **k)

frames = []
def IP(p, src='192.0.2.10', dst='224.0.1.1'): frames.append(eth(ipv4(113, p, src, dst), 0x0800, dst=b'\x01\x00\x5e\x00\x01\x01'))
def IP6(p): frames.append(eth(ipv6(113, p, '2001:db8::10', 'ff0e::1'), 0x86dd))
def UDP(p, port=3055): frames.append(udp(port, port, p, '192.0.2.10', '224.0.1.1'))

# every packet type; SPM, NAK and POLL with IPv4 and IPv6 NLAs
IP(spm(1)); IP(spm(2))
IP(odata()); IP(rdata())
IP(nak(NAK, 1, 1)); IP(nak(NAK, 2, 2)); IP(nak(NNAK, 1, 2)); IP(nak(NCF, 2, 1))
IP(poll(0, 1)); IP(poll(1, 2)); IP(poll(7, 1))
IP(polr()); IP(ack(ACK)); IP(ack(ACK2))
# an unknown type
IP(pgm(0x0f, b'\0' * 8))
# checksum: zero in a non-data packet (not present), data with a checksum
IP(spm(1, cksum='zero'))
# main options bits
for o in (OPT, NETSIG, VARLEN, PARITY, NETSIG | VARLEN | PARITY, 0x3c):
    IP(odata(opts=o))
# options of the data packets
lenopt = lambda *os: b''.join(os)
JOIN = opt(0x03, b'\0' + struct.pack('!I', 77))
PRM = opt(0x08, bytes((3,)) + struct.pack('!I', 16))
PRM2 = opt(0x08, bytes((1,)) + struct.pack('!I', 8))
PRM3 = opt(0x08, bytes((0,)) + struct.pack('!I', 8))
PRM4 = opt(0x08, bytes((4,)) + struct.pack('!I', 8))
GRP = opt(0x09, b'\0' + struct.pack('!I', 5))
NAKL = lambda n: opt(0x02, b'\0' + b''.join(struct.pack('!I', 100 + i) for i in range(n)))
CCD4 = opt(0x12, b'\0' + struct.pack('!IHH', 12345, 1, 0) + ip4('192.0.2.5'))
CCD6 = opt(0x12, b'\0' + struct.pack('!IHH', 12345, 2, 0) + ip6('2001:db8::5'))
CCDX = opt(0x12, b'\0' + struct.pack('!IHH', 12345, 9, 0) + b'\0' * 4)
CCF4 = opt(0x13, b'\0' + struct.pack('!IHH', 12345, 1, 500) + ip4('192.0.2.5'))
CCF6 = opt(0x13, b'\0' + struct.pack('!IHH', 12345, 2, 500) + ip6('2001:db8::5'))
CCFX = opt(0x13, b'\0' + struct.pack('!IHH', 12345, 9, 500) + b'\0' * 4)
IVL = opt(0x04, b'\0' + struct.pack('!II', 100, 200))
RNG = opt(0x05, b'\0' + struct.pack('!II', 100, 200))
RED4 = opt(0x07, b'\0' + struct.pack('!HH', 1, 0) + ip4('192.0.2.6'))
RED6 = opt(0x07, b'\0' + struct.pack('!HH', 2, 0) + ip6('2001:db8::6'))
REDX = opt(0x07, b'\0' + struct.pack('!HH', 9, 0) + b'\0' * 4)
FRAG = opt(0x01, b'\0' + struct.pack('!III', 1, 2, 3000))
SYN = opt(0x0d, b'\0'); FIN = opt(0x0e, b'\0'); RST = opt(0x0f, b'\0')
TGS = opt(0x0a, b'\0' + struct.pack('!I', 32))
UNK = opt(0x33, b'\1\2\3\4\5')
END = lambda o: o[:0] + bytes((o[0] | 0x80,)) + o[1:]
for o in (JOIN, PRM, PRM2, PRM3, PRM4, GRP, NAKL(1), NAKL(8), NAKL(9), NAKL(17), NAKL(62), CCD4, CCD6, CCDX, CCF4, CCF6, CCFX,
          IVL, RNG, RED4, RED6, REDX, FRAG, SYN, FIN, RST, TGS, UNK):
    IP(odata(opts=OPT, options=o))
# several options in one packet, the last one with the END bit
IP(odata(opts=OPT, options=JOIN + FRAG + END(UNK)))
IP(rdata(opts=OPT | PARITY, options=PRM + GRP + NAKL(3) + END(TGS)))
IP(spm(1, opts=OPT, options=CCD4 + CCF6 + END(RED6)))
IP(nak(NAK, 1, 1, opts=OPT, options=NAKL(4) + END(IVL)))
IP(ack(opts=OPT, options=END(RNG)))
IP(poll(0, 1, opts=OPT, options=END(JOIN)))
IP(polr(opts=OPT, options=END(SYN)))
# options after an END option are not decoded
IP(odata(opts=OPT, options=END(JOIN) + FRAG))
# IPv6 transport
IP6(odata(payload=b'six')); IP6(spm(2))
# UDP encapsulation (needs the pgm.udp.port preference)
UDP(spm(1)); UDP(odata(), 3056); UDP(nak(NAK, 1, 1)); UDP(rdata())
write_pcap(out + '/pgm-coverage.pcap', frames)

# malformed: bad checksum (error), bad options (warnings), bad AFI (warnings), short packets
mal = []
def M(p): mal.append(eth(ipv4(113, p, '192.0.2.10', '224.0.1.1')))
M(odata(cksum=0x1234)); M(spm(1, cksum=0xffff)); M(odata(cksum='zero'))
M(spm(9)); M(nak(NAK, 9, 1)); M(nak(NAK, 1, 9)); M(poll(0, 9))
M(spm(1, opts=OPT, options=b'\x03\x04\x00\x00'))                       # option and header too short
# options area errors
def raw_opts(body, opts=OPT, typ=ODATA, first=0, olen=4):
    h = struct.pack('!HHBBH', 1, 2, typ, opts, 0) + GSI + struct.pack('!H', 0) + struct.pack('!II', 1, 2)
    h += struct.pack('!BBH', first, olen, 4 + len(body)) + body
    return h[:6] + struct.pack('!H', csum(h)) + h[8:]
M(raw_opts(b'', first=0x03))                                          # first option is not Length
M(pgm(ODATA, struct.pack('!II', 1, 2), opts=OPT) + b'')               # options bit but no options
h = pgm(ODATA, struct.pack('!II', 1, 2), opts=OPT) + struct.pack('!BBH', 0, 4, 3)
M(h)                                                                  # total length < 4
M(raw_opts(b'\x03\x08', olen=4))                                      # remaining length < option header
M(raw_opts(opt(0x03, b'\0' + struct.pack('!I', 1), length=3)))        # option length < 4
M(raw_opts(opt(0x03, b'\0' + struct.pack('!I', 1), length=200)))      # option longer than the total
for t, n in ((0x03, 4), (0x08, 4), (0x09, 4), (0x12, 4), (0x13, 4), (0x04, 4), (0x05, 4), (0x07, 4), (0x01, 4)):
    M(raw_opts(bytes((t, 4, 0, 0)) + b'\0' * 12))                     # too short for the option (len 4)
M(raw_opts(opt(0x02, b'')))                                           # NAK list with no entries (len 3 is < 4 -> invalid)
M(raw_opts(bytes((0x02, 4, 0, 0))))                                   # NAK list with no entries
M(raw_opts(bytes((0x02, 255, 0, 0)) + b'\x01' * 251))                 # NAK list of 62 entries (largest)
M(raw_opts(bytes((0x02, 9, 0, 0)) + b'\x01\x02\x03\x04\x05')[:-3])   # NAK list cut in the middle
for cut in (0, 4, 10, 16, 17, 18, 19, 20, 24, 28, 32, 36, 40):
    M(spm(2, opts=OPT, options=CCD6 + END(RED6))[:cut])
    M(nak(NAK, 2, 2)[:cut])
    M(poll(0, 2)[:cut])
M(b'\x00' * 17)
write_pcap(out + '/pgm-coverage-malformed.pcap', mal)
gz(out + '/pgm-coverage.pcap')
print('ok')
