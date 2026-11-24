#!/usr/bin/env python3
# Generates test/captures/cosine_coverage.txt.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate a synthetic CoSine IPNOS L2 debug trace that exercises the
CoSine dissector (packet-cosine.c) and the wiretap reader that is the
only source of its packets (wiretap/cosine.c).

The trace is the text a CoSine IPSX prints with "layer-2 apply ...
pkt-log-profile": a header line per packet, with a date and time when it
goes to a control blade and without when it goes to a PE,

  2000-2-1,18:20:17.0:  l2-tx (PPP:3/7/1:100), Length:16, Pro:0, Off:0, Pri:0, RM:0, Err:0 [0x4000, 0x0]
          00 D0 D8 D2 FF 03 C0 21  09 29 00 08 6B 60 84 AA

followed by a hex dump of 16 octets per line. The interface name before
the first colon selects the encapsulation (ETH, PPP, ATM, PPoATM, FR,
PPoFR, HDLC, TEST, anything else); the dissector shows the pseudo-header
fields and hands the packet, after a channel handle or SAR header, to
Ethernet, PPP in HDLC framing, LLC, Cisco HDLC or Frame Relay. Every
packet is built from scratch with struct; no captured traffic is used.

Usage: mkcosine.py <output directory>

Writes:
  cosine_coverage.txt       every encapsulation, both directions, both
                            header formats, console noise between records
  malformed/*.txt           reader error paths (coverage only)
"""

import os
import struct
import sys


def ip_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(src, dst, proto, payload, ident=1):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 255,
                      proto, 0, bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack('>H', ip_csum(hdr)) + hdr[12:]
    return hdr + payload


def icmp_echo(ident, seq, data, reply=False):
    h = struct.pack('>BBHHH', 0 if reply else 8, 0, 0, ident, seq) + data
    return h[:2] + struct.pack('>H', ip_csum(h)) + h[4:]


def udp(sport, dport, data):
    return struct.pack('>HHHH', sport, dport, 8 + len(data), 0) + data


A = (20, 20, 20, 34)
B = (20, 20, 20, 43)
PING = icmp_echo(3, 1, bytes(range(0x10, 0x30)))
PONG = icmp_echo(3, 1, bytes(range(0x10, 0x30)), reply=True)
# UDP to the discard port (no reply expected)
DISCARD = udp(40000, 9, b'synthetic CoSine trace')

MAC1 = bytes.fromhex('0200000000a1')
MAC2 = bytes.fromhex('0200000000b2')


def fcs16(data):
    cs = 0xffff
    for b in data:
        cs ^= b
        for _ in range(8):
            cs = (cs >> 1) ^ 0x8408 if cs & 1 else cs >> 1
    return cs ^ 0xffff


def lcp(code, ident, opts):
    return struct.pack('>BBH', code, ident, 4 + len(opts)) + opts


def ppp_hdlc(proto, payload):
    """PPP in HDLC-like framing as the ppp_hdlc dissector expects it
    (address, control, protocol, payload, FCS-16)."""
    f = b'\xff\x03' + struct.pack('>H', proto) + payload
    return f + struct.pack('<H', fcs16(f))


MAGIC = struct.pack('>BBI', 5, 6, 0x6b6084aa)


def records():
    """List of (header fields, packet octets, data lines override)."""
    R = []

    def rec(direction, ifname, data, date='2002-5-10,20:1:31.4', pro=0, off=0,
            pri=0, rm=0, err=0, codes=(0x4000, 0x0), length=None, lines=None,
            sep='\n'):
        R.append(dict(direction=direction, ifname=ifname, data=data, date=date,
                      pro=pro, off=off, pri=pri, rm=rm, err=err, codes=codes,
                      length=len(data) if length is None else length,
                      lines=lines, sep=sep))

    # 1-2: Ethernet, ICMP echo request and reply, to a control blade
    rec('l2-tx', 'ETH:3/1/1:10',
        MAC2 + MAC1 + b'\x08\x00' + ipv4(A, B, 1, PING),
        date='2002-5-10,20:1:31.4', pro=1, off=14, pri=3, codes=(0x4070, 0x801))
    rec('l2-rx', 'ETH:3/1/1:10',
        MAC1 + MAC2 + b'\x08\x00' + ipv4(B, A, 1, PONG),
        date='2002-5-10,20:1:31.5', pro=1, off=14, pri=3, codes=(0x4071, 0x30801))
    # 3-4: PPP, LCP Configure-Request and -Ack (4 octet channel handle);
    # 3 follows the dump of 2 directly, without an empty line
    rec('l2-tx', 'PPP:3/7/1:100',
        b'\x00\xd0\xd8\xd2' + ppp_hdlc(0xc021, lcp(1, 0x29, MAGIC)),
        date='2002-5-10,20:1:31.6', sep='')
    rec('l2-rx', 'PPP:3/7/1:100',
        b'\x00\xd0\xd8\xd2' + ppp_hdlc(0xc021, lcp(2, 0x29, MAGIC)),
        date='2002-5-10,20:1:31.7', codes=(0x4001, 0x30000))
    # 5: PPP, an IPv4 UDP datagram with 500 octets of data (Pro, Off, Pri set)
    big = udp(40000, 9, bytes(i & 0xff for i in range(500)))
    rec('l2-tx', 'PPP:3/7/1:100',
        b'\x00\xd0\xd8\xd2' + ppp_hdlc(0x0021, ipv4(A, B, 17, big, ident=0x27)),
        date='2002-5-10,20:1:31.8', pro=1, off=8, pri=7, codes=(0x4070, 0x801))
    # 6: ATM, 16 octet SAR header, LLC/SNAP IPv4 UDP (to a PE: no date)
    sar = bytes.fromhex('000000640000000000000000000000aa')
    rec('l2-tx', 'ATM:3/2/1:32',
        sar + b'\xaa\xaa\x03\x00\x00\x00\x08\x00' + ipv4(A, B, 17, DISCARD), date=None,
        rm=1)
    # 7: PPPoATM: SAR header, LLC encapsulated PPP (NLPID 0xcf), LCP Echo
    rec('l2-rx', 'PPoATM:3/2/1:33',
        sar + b'\xfe\xfe\x03\xcf' + b'\xc0\x21' + lcp(9, 1, b'\x6b\x60\x84\xaa'),
        date=None, codes=(0x4001, 0x30000))
    # 8: Frame Relay, DLCI 100, NLPID IPv4 UDP
    rec('l2-tx', 'FR:3/7/1:1',
        b'\x00\x00\x00\x64' + b'\x18\x41\x03\xcc' + ipv4(A, B, 17, DISCARD),
        date='2002-5-10,20:1:32.0', err=2)
    # 9: PPPoFR, DLCI 100, NLPID PPP, LCP Configure-Request
    rec('l2-rx', 'PPoFR:3/7/1:2',
        b'\x00\x00\x00\x65' + b'\x18\x51\x03\xcf' + b'\xc0\x21' + lcp(1, 2, MAGIC),
        date='2002-5-10,20:1:32.1', codes=(0x4001, 0x30000))
    # 10-11: Cisco HDLC, transmit (2 octet channel handle) IPv4 UDP and receive
    # (4 octet channel handle) SLARP keepalive
    rec('l2-tx', 'HDLC:3/4/1:5',
        b'\x00\x05' + b'\x0f\x00\x08\x00' + ipv4(A, B, 17, DISCARD),
        date='2002-5-10,20:1:33.0')
    slarp = struct.pack('>IIIH', 2, 10, 9, 0xffff) + b'\x00\x01\x02\x03'
    rec('l2-rx', 'HDLC:3/4/1:5',
        b'\x00\x00\x00\x05' + b'\x8f\x00\x80\x35' + slarp,
        date='2002-5-10,20:1:33.1', codes=(0x4001, 0x30000))
    # 12: TEST interface, shown as data
    rec('l2-tx', 'TEST:1/1/1:1', bytes(range(24)), date='2002-5-10,20:1:34.0')
    # 13: an interface name the reader does not know (unknown encapsulation)
    rec('l2-rx', 'SONET:3/5/1:7', bytes(range(0x80, 0xa0)), date=None,
        codes=(0x4001, 0x30000))
    # 14: length not a multiple of 16: the last dump line is short
    rec('l2-tx', 'ETH:3/1/1:10',
        MAC2 + MAC1 + b'\x08\x06' + struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1)
        + MAC1 + bytes(A) + bytes(6) + bytes(B), date='2002-5-10,20:1:35.0')
    # 15: a header claiming 40 octets with one dump line, then an empty
    # line: 16 octets captured of 40
    rec('l2-rx', 'TEST:1/1/1:1', bytes(range(0x40, 0x50)), length=40,
        date='2002-5-10,20:1:36.0', codes=(0x4001, 0x30000))
    # 16: a record after an empty line only
    rec('l2-tx', 'TEST:1/1/1:1', b'\x01\x02\x03\x04', date='2002-5-10,20:1:37.0')
    # 17: zero length packet (no dump lines)
    rec('l2-tx', 'TEST:1/1/1:1', b'', date='2002-5-10,20:1:38.0')
    return R


def hexdump(data):
    out = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        h = ' '.join('%02X' % b for b in chunk[:8])
        if len(chunk) > 8:
            h += '  ' + ' '.join('%02X' % b for b in chunk[8:])
        out.append('          ' + h + '\n')
    return ''.join(out)


def header(r):
    h = '%s (%s), Length:%d, Pro:%d, Off:%d, Pri:%d, RM:%d, Err:%d [0x%x, 0x%x]' % (
        r['direction'], r['ifname'], r['length'], r['pro'], r['off'], r['pri'],
        r['rm'], r['err'], r['codes'][0], r['codes'][1])
    if r['date']:
        h = r['date'] + ':  ' + h
    return h + '\n'


NOISE = [
    'IPNOS: CONFIG VPN(200) VR(3.3.3.3)# diags\n',
    'ipnos diags: Control (1/0) :: layer-2 create 2 32 32 100 100 0\n',
    'ipnos diags: Control (1/0) :: layer-2 apply 3 0x0701 100 0 2\n',
    'Successfully applied packet-log-profile on LI\n',
    'vpn 200 : [max tries 1, timeout 5 seconds, data length 500 bytes, ttl 255]\n',
    'ping #1 ok, RTT 0.010 seconds\n',
    '[finished]\n',
]


def trace():
    out = ''.join(NOISE[:4])
    for i, r in enumerate(records()):
        if i:
            out += r['sep']
            if r['sep'] and i % 3 == 0:
                out += NOISE[4 + i % 3]
        out += header(r) + hexdump(r['data'])
    out += '\n' + NOISE[6]
    return out


def malformed():
    """Reader error paths: name -> trace text."""
    good = ('2002-5-10,20:1:31.4:  l2-tx (TEST:1/1/1:1), Length:4, Pro:0, Off:0, '
            'Pri:0, RM:0, Err:0 [0x4000, 0x0]\n          01 02 03 04\n\n')
    M = {}
    # not a CoSine trace: no l2-tx/l2-rx in the first 200 lines
    M['cosine-notmine.txt'] = 'hello\n' * 210 + good
    # a short line and the end of the file before 200 lines
    M['cosine-tiny.txt'] = 'hi\n'
    # control blade header without the code values
    M['cosine-nocodes.txt'] = good + (
        '2002-5-10,20:1:31.5:  l2-rx (TEST:1/1/1:1), Length:4, Pro:0, Off:0, '
        'Pri:0, RM:0, Err:0\n          01 02 03 04\n')
    # PE header that does not parse
    M['cosine-badpe.txt'] = good + 'l2-rx garbage\n          01 02 03 04\n'
    # negative length
    M['cosine-neglen.txt'] = good + (
        'l2-rx (TEST:1/1/1:1), Length:-4, Pro:0, Off:0, Pri:0, RM:0, Err:0 '
        '[0x4000, 0x0]\n')
    # length above the maximum packet size
    M['cosine-hugelen.txt'] = good + (
        'l2-rx (TEST:1/1/1:1), Length:999999999, Pro:0, Off:0, Pri:0, RM:0, '
        'Err:0 [0x4000, 0x0]\n          01 02 03 04\n')
    # dump line without hex numbers
    M['cosine-badhex.txt'] = good + (
        'l2-rx (TEST:1/1/1:1), Length:4, Pro:0, Off:0, Pri:0, RM:0, Err:0 '
        '[0x4000, 0x0]\n          zz zz zz zz\n')
    # file ends inside the dump
    M['cosine-short.txt'] = good + (
        'l2-rx (TEST:1/1/1:1), Length:40, Pro:0, Off:0, Pri:0, RM:0, Err:0 '
        '[0x4000, 0x0]\n          01 02 03 04 05 06 07 08  09 0A 0B 0C 0D 0E 0F 10\n')
    # a direction that is neither l2-tx nor l2-rx (the magic is later in
    # the line): the reader leaves the direction of the previous record,
    # first in a file where it is zero, then after an l2-rx record
    hdlc = '          00 05 0F 00 08 00 45 00\n'
    M['cosine-direction.txt'] = (
        'l2-tz (HDLC:3/4/1:5), Length:8, Pro:0, Off:0, Pri:0, RM:0, Err:0 '
        '[0x4000, 0x0] l2-tx\n' + hdlc + '\n'
        'l2-rx (HDLC:3/4/1:5), Length:8, Pro:0, Off:0, Pri:0, RM:0, Err:0 '
        '[0x4000, 0x0]\n          00 00 00 05 0F 00 08 00\n\n'
        'l2-tz (HDLC:3/4/1:5), Length:8, Pro:0, Off:0, Pri:0, RM:0, Err:0 '
        '[0x4000, 0x0] l2-tx\n' + hdlc + '\n')
    # more octets in the dump lines than the header length
    M['cosine-overlong.txt'] = (
        'l2-tx (TEST:1/1/1:1), Length:18, Pro:0, Off:0, Pri:0, RM:0, Err:0 '
        '[0x4000, 0x0]\n'
        '          01 02 03 04 05 06 07 08  09 0A 0B 0C 0D 0E 0F 10\n'
        '          11 12 13 14 15 16 17 18  19 1A 1B 1C 1D 1E 1F 20\n\n')
    # a header line after a prompt on the same line (as in the example
    # in wiretap/cosine.c): the record is found, but the header does not
    # parse
    M['cosine-prompt.txt'] = good + (
        'IPNOS: CONFIG VPN(200) VR(3.3.3.3)# 2002-5-10,20:1:31.8:  l2-tx '
        '(TEST:1/1/1:1), Length:4, Pro:0, Off:0, Pri:0, RM:0, Err:0 [0x4000, 0x0]\n'
        '          01 02 03 04\n')
    # fractions of three and nine digits: the reader takes the digits as
    # centiseconds, and csec * 10000000 overflows an int (nanoseconds
    # beyond one second)
    M['cosine-csec.txt'] = (
        '2002-5-10,20:1:31.999:  l2-tx (TEST:1/1/1:1), Length:4, Pro:0, Off:0, '
        'Pri:0, RM:0, Err:0 [0x4000, 0x0]\n          01 02 03 04\n\n'
        '2002-5-10,20:1:31.123456789:  l2-tx (TEST:1/1/1:1), Length:4, Pro:0, '
        'Off:0, Pri:0, RM:0, Err:0 [0x4000, 0x0]\n          01 02 03 04\n\n')
    # truncated payloads for every encapsulation (shorter than the
    # channel handle or SAR header)
    short = ''
    for name in ('ATM', 'PPoATM', 'PPP', 'FR', 'PPoFR', 'HDLC', 'ETH'):
        for d in ('l2-tx', 'l2-rx'):
            short += ('%s (%s:1/1/1:1), Length:1, Pro:0, Off:0, Pri:0, RM:0, '
                      'Err:0 [0x4000, 0x0]\n          01\n\n' % (d, name))
    M['cosine-shortpayload.txt'] = short
    return M


def exported_pdu():
    """Exported PDU (link type 252) naming the cosine dissector: no CoSine
    pseudo-header, the only way to reach the default cases."""
    def tag(t, v):
        return struct.pack('>HH', t, len(v)) + v + b'\0' * ((-len(v)) % 4)
    pdu = tag(12, b'cosine') + struct.pack('>HH', 0, 0) + bytes(range(0x20))
    return (struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 252)
            + struct.pack('<IIII', 1, 0, len(pdu), len(pdu)) + pdu)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    with open(os.path.join(out, 'cosine_coverage.txt'), 'w') as f:
        f.write(trace())
    md = os.path.join(out, 'malformed')
    os.makedirs(md, exist_ok=True)
    for name, text in malformed().items():
        with open(os.path.join(md, name), 'w') as f:
            f.write(text)
    with open(os.path.join(md, 'cosine-exported-pdu.pcap'), 'wb') as f:
        f.write(exported_pdu())


if __name__ == '__main__':
    main()
