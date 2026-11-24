#!/usr/bin/env python3
# Generates test/captures/ax25_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic AX.25 captures (LINKTYPE_AX25) for packet-ax25.c.
# Every packet is built with struct; nothing comes from a real network.
# Usage: mkax25.py <outdir>
import os
import struct
import sys

LINKTYPE_AX25 = 3


def write_pcap(fn, linktype, pkts):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)


def call(cs, ssid=0, last=False, c=False):
    '''An AX.25 address: six shifted characters (space padded) and the
    SSID octet with the C (or H) bit and the end-of-address bit.'''
    cs = cs.ljust(6)[:6]
    s = 0x60 | ((ssid & 0xf) << 1) | (0x80 if c else 0) | (1 if last else 0)
    return bytes(ord(ch) << 1 for ch in cs) + bytes([s])


def ax25(ctl, info=b'', pid=None, dst='N0DST', dst_ssid=0, src='N0SRC', src_ssid=0,
         via=(), resp=False, ver1=None):
    '''An AX.25 frame. resp selects the v2 response C bits; ver1 = 'zero'
    or 'one' sets both C bits the same (version 1, "V?.?").'''
    if ver1 == 'zero':
        dc, sc = False, False
    elif ver1 == 'one':
        dc, sc = True, True
    else:
        dc, sc = (False, True) if resp else (True, False)
    a = call(dst, dst_ssid, c=dc) + call(src, src_ssid, last=not via, c=sc)
    for i, v in enumerate(via):
        name, ssid, h = v
        a += call(name, ssid, last=(i == len(via) - 1), c=h)
    p = bytes([ctl]) if isinstance(ctl, int) else ctl
    if pid is not None:
        p += bytes([pid])
    return a + p + info


def ip_cksum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, payload, src='44.0.0.1', dst='44.0.0.2', ident=1):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', ip_cksum(h)) + h[12:]
    return h + payload


def ipv6(nh, payload):
    src = bytes.fromhex('20010db8000000000000000000000001')
    dst = bytes.fromhex('20010db8000000000000000000000002')
    return struct.pack('!IHBB', 0x60000000, len(payload), nh, 64) + src + dst + payload


def udp(sport, dport, data):
    return struct.pack('!HHHH', sport, dport, 8 + len(data), 0) + data


def main(outdir):
    P = []          # main capture
    M = []          # malformed capture
    T = b'hello from the coverage capture'

    # 1-4: command, response and both version 1 combinations of the C bits
    P.append(ax25(0x03, b'v2 command', pid=0xF0))
    P.append(ax25(0x03, b'v2 response', pid=0xF0, resp=True))
    P.append(ax25(0x03, b'v1 both clear', pid=0xF0, ver1='zero'))
    P.append(ax25(0x03, b'v1 both set', pid=0xF0, ver1='one'))

    # 5-13: 1 to 8 digipeaters (Via 1 .. Via 8), then 9 (only 8 are shown)
    digis = [('DIGI%d' % (i + 1), i, i % 2 == 0) for i in range(9)]
    for n in range(1, 10):
        P.append(ax25(0x03, b'via %d' % n, pid=0xF0, via=digis[:n]))

    # 14-25: S frames RR, RNR, REJ, SREJ as command, command with poll,
    # response with final; n(r) 0..7
    nr = 0
    for st in (0x00, 0x04, 0x08, 0x0C):
        for resp, pf in ((False, 0), (False, 0x10), (True, 0x10)):
            P.append(ax25(0x01 | st | pf | (nr << 5), resp=resp))
            nr = (nr + 1) % 8

    # 26-43: U frames, commands and responses, with and without P/F
    P.append(ax25(0x2F))                                   # SABM
    P.append(ax25(0x3F))                                   # SABM, P
    P.append(ax25(0x6F))                                   # SABME
    P.append(ax25(0x7F))                                   # SABME, P
    P.append(ax25(0x43))                                   # DISC
    P.append(ax25(0x53))                                   # DISC, P
    P.append(ax25(0x63, resp=True))                        # UA
    P.append(ax25(0x73, resp=True))                        # UA, F
    P.append(ax25(0x0F, resp=True))                        # DM
    P.append(ax25(0x1F, resp=True))                        # DM, F
    P.append(ax25(0x87, b'\x2f\x00\x01', resp=True))       # FRMR with its 3 octets
    P.append(ax25(0xAF, bytes.fromhex('8280000302002008080000000000')))  # XID with parameters
    P.append(ax25(0xBF, bytes.fromhex('82800000'), resp=True))           # XID response, F
    P.append(ax25(0xE3, b'test pattern'))                  # TEST
    P.append(ax25(0xF3, b'test pattern', resp=True))       # TEST response, F
    P.append(ax25(0x13, b'UI with poll, no PID'))          # UI with P: not "information"
    P.append(ax25(0x03, b'UI response', pid=0xF0, resp=True))
    P.append(ax25(0xCF))                                   # SNRME, a U type AX.25 does not use

    # 44-63: I frames, one for each PID in the table and an unknown one
    def I(ns, nr, pf=0):
        return (nr << 5) | pf | (ns << 1)
    x25_data = bytes([0x10, 0x01, 0x00]) + b'rose payload'
    netrom = (call('N0SRC', 0) + call('N0DST', 0, last=True) +
              bytes([7, 1, 2, 3, 4, 0x05]) + b'net/rom info')
    flexnet = bytes(range(0x41, 0x41 + 45)) + b'flexnet data'
    arp = (struct.pack('!HHBBH', 3, 0x0800, 7, 4, 1) + call('N0SRC', 0) + bytes([44, 0, 0, 1]) +
           call('', 0) + bytes([44, 0, 0, 2]))
    P.append(ax25(I(0, 0), x25_data, pid=0x01))
    P.append(ax25(I(1, 0), b'\x45vj compressed', pid=0x06))
    P.append(ax25(I(2, 0), b'vj uncompressed', pid=0x07))
    P.append(ax25(I(3, 0), b'\x01\x02segment', pid=0x08))
    P.append(ax25(I(4, 0), b'texnet', pid=0xC3))
    P.append(ax25(I(5, 0), b'lqp', pid=0xC4))
    P.append(ax25(I(6, 0), b'appletalk', pid=0xCA))
    P.append(ax25(I(7, 0), b'aarp', pid=0xCB))
    P.append(ax25(I(0, 1), ipv4(17, udp(1024, 7, b'echo me')), pid=0xCC))
    P.append(ax25(I(1, 1), arp, pid=0xCD))
    P.append(ax25(I(2, 1), flexnet, pid=0xCE))
    P.append(ax25(I(3, 1), netrom, pid=0xCF))
    P.append(ax25(I(4, 1), b'plain text in an I frame', pid=0xF0))
    P.append(ax25(I(5, 1), b'\x01escaped', pid=0xFF))
    P.append(ax25(I(6, 1), b'unknown pid', pid=0x55))
    P.append(ax25(I(7, 1, 0x10), b'I with poll', pid=0xF0))
    P.append(ax25(I(0, 2, 0x10), b'I as response', pid=0xF0, resp=True))
    P.append(ax25(I(1, 2), b'', pid=0xF0))              # empty information field
    # AX.25 over IP (IP protocol 93, AXIP) inside an AX.25 IP frame, IPv4 and IPv6
    inner = ax25(0x03, T, pid=0xF0, dst='CQ', src='AXIP', src_ssid=5)
    P.append(ax25(I(2, 2), ipv4(93, inner, ident=2), pid=0xCC))
    inner = ax25(I(0, 0), b'axip over ipv6', pid=0xF0, dst='N1DST', src='N1SRC', via=[('RELAY', 1, True)])
    P.append(ax25(I(3, 2), ipv6(93, inner), pid=0xCC))

    # 64-68: address characters
    # The reproducer from ax25_addr_ctrl.py: the destination
    # octets shift to NUL, 0x01 and 0x0d (shown as periods), source NOCALL-0
    dst = bytes([0x00, 0x02, 0x1a, 0x40, 0x40, 0x40, 0xe0])
    src = bytes([0x9c, 0x9e, 0x86, 0x82, 0x98, 0x98, 0x61])
    P.append(dst + src + b'\x03\xf0' + b'hi')
    # A space inside the callsign: the address ends at the first space
    P.append(ax25(0x03, b'embedded space', pid=0xF0, dst='AB CD', src='N0SRC'))
    # Six character callsigns, digits, SSID 15
    P.append(ax25(0x03, b'ssid 15', pid=0xF0, dst='ABCDEF', dst_ssid=15, src='123456', src_ssid=15))
    # Lower case and punctuation (not valid callsign characters, printable)
    P.append(ax25(0x03, b'lower case', pid=0xF0, dst='abc-!', src='x_y'))
    # An empty callsign (all spaces), as broadcast tools sometimes send
    P.append(ax25(0x03, b'empty callsign', pid=0xF0, dst='', src='N0SRC'))

    # Malformed capture
    M.append((call('N0DST') + call('N0SRC', last=True))[:13])            # address cut short
    M.append(call('N0DST', c=True) + call('N0SRC', last=True))           # no control field
    M.append(call('N0DST', c=True) + call('N0SRC', last=True) + b'\x00') # I frame, no PID
    # ax25_capdis_noend.py: no end-of-address bit at all
    M.append(call('NOCALL', 0, c=True) + call('N0CALL', 1, last=False) + b'\x00')
    # A via address cut short
    M.append(call('N0DST', c=True) + call('N0SRC') + call('DIGI')[:4])
    # IP protocol 93 carrying a truncated AX.25 frame
    M.append(ax25(I(4, 2), ipv4(93, call('N0DST') + call('N0'), ident=3), pid=0xCC))

    write_pcap(os.path.join(outdir, 'ax25-coverage.pcap'), LINKTYPE_AX25, P)
    write_pcap(os.path.join(outdir, 'ax25-coverage-malformed.pcap'), LINKTYPE_AX25, M)
    print('ax25-coverage.pcap: %d frames, ax25-coverage-malformed.pcap: %d frames' % (len(P), len(M)))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
