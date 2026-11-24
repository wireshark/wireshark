#!/usr/bin/env python3
# Generates test/captures/sndcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-sndcp.c (SNDCP of GPRS). Usage: mksndcp.py <outdir>
# SNDCP is reached through GSMTAP (UDP 4729): type 9 (Gb SNDCP) directly and
# type 8 (Gb LLC) with LLC UI frames on SAPI 3, 5, 9 and 11.
import os
import struct
import sys
from pcaplib import (Pcap, eth, ip4, udp, gsmtap, llc_gprs_ui, GSMTAP_GB_LLC, GSMTAP_GB_SNDCP)

DLT_EN10MB = 1

def sn_hdr(nsapi, f, t, m, x=0):
    return bytes([(x << 7) | (f << 6) | (t << 5) | (m << 4) | nsapi])

def first_ack(nsapi, npdu, data, m=0, comp=0, x=0):
    return sn_hdr(nsapi, 1, 0, m, x) + bytes([comp, npdu]) + data

def first_unack(nsapi, npdu, data, m=0, comp=0, seg=0, x=0):
    return sn_hdr(nsapi, 1, 1, m, x) + bytes([comp]) + struct.pack('!H', (seg << 12) | npdu) + data

def next_unack(nsapi, npdu, seg, data, m=0):
    return sn_hdr(nsapi, 0, 1, m) + struct.pack('!H', (seg << 12) | npdu) + data

def next_ack(nsapi, data, m=0):
    return sn_hdr(nsapi, 0, 0, m) + data

def ipv4_udp(payload, sport=2000, dport=9999, src='10.0.0.1', dst='10.0.0.2'):
    return ip4(17, udp(payload, sport, dport), src, dst)

def main(out):
    p = Pcap(DLT_EN10MB)
    count = [0]
    def send_sndcp(sndcp, sport=3100):
        count[0] += 1
        p.add(eth(ip4(17, udp(gsmtap(GSMTAP_GB_SNDCP, sndcp), sport, 4729), ident=count[0]), 0x0800))
    def send_llc(sapi, nu, sndcp, sport=3101):
        count[0] += 1
        p.add(eth(ip4(17, udp(gsmtap(GSMTAP_GB_LLC, llc_gprs_ui(sapi, nu, sndcp)), sport, 4729), ident=count[0]), 0x0800))

    pkt = ipv4_udp(b'GPRS payload')
    # 1-2: first segments without more, acknowledged and unacknowledged mode
    send_sndcp(first_ack(5, 3, pkt))
    send_sndcp(first_unack(6, 1, pkt))
    # 3-5: compressed N-PDUs: data compression, protocol compression, both
    send_sndcp(first_ack(5, 4, pkt, comp=0x10))
    send_sndcp(first_unack(7, 2, pkt, comp=0x01))
    send_sndcp(first_ack(8, 5, pkt, comp=0x23))
    # 6-8: every NSAPI value in a short unacknowledged N-PDU, X bit set, 0 and PTM-M
    for nsapi, x in ((0, 0), (1, 0), (2, 0), (3, 1), (4, 0), (9, 0), (10, 0), (11, 0), (12, 0), (13, 0), (14, 0), (15, 1)):
        send_sndcp(first_unack(nsapi, 10 + nsapi, pkt, x=x))
    # unacknowledged mode, N-PDU in three segments (first, middle, last)
    big = ipv4_udp(bytes(range(64)))
    npdu = 20
    send_sndcp(first_unack(5, npdu, big[:30], m=1, seg=0))
    send_sndcp(next_unack(5, npdu, 1, big[30:60], m=1))
    send_sndcp(next_unack(5, npdu, 2, big[60:], m=0))
    # two segments
    npdu = 21
    send_sndcp(first_unack(6, npdu, big[:40], m=1, seg=0))
    send_sndcp(next_unack(6, npdu, 1, big[40:], m=0))
    # out of order: last, first, middle
    npdu = 22
    send_sndcp(next_unack(7, npdu, 2, big[50:], m=0))
    send_sndcp(first_unack(7, npdu, big[:25], m=1, seg=0))
    send_sndcp(next_unack(7, npdu, 1, big[25:50], m=1))
    # acknowledged mode with segments: the dissector cannot join them
    send_sndcp(first_ack(5, 6, big[:30], m=1))
    send_sndcp(next_ack(5, big[30:], m=0))
    send_sndcp(next_ack(5, big[30:], m=1))
    # a segment without payload
    send_sndcp(next_unack(5, 30, 1, b'', m=1))
    # the same N-PDU numbers in a second flow (other addresses)
    count[0] += 1
    p.add(eth(ip4(17, udp(gsmtap(GSMTAP_GB_SNDCP, first_unack(5, 20, big[:30], m=1)), 3100, 4729),
                 src='192.0.2.9', dst='192.0.2.10', ident=count[0]), 0x0800))
    count[0] += 1
    p.add(eth(ip4(17, udp(gsmtap(GSMTAP_GB_SNDCP, next_unack(5, 20, 1, big[30:], m=0)), 3100, 4729),
                 src='192.0.2.9', dst='192.0.2.10', ident=count[0]), 0x0800))
    # LLC UI frames on every SNDCP SAPI
    send_llc(3, 1, first_ack(5, 40, pkt))
    send_llc(5, 2, first_unack(6, 41, pkt))
    send_llc(9, 3, first_ack(7, 42, big[:30], m=1))
    send_llc(11, 4, first_unack(8, 43, pkt, comp=0x11))
    # the reproducer of "SNDCP: Do not pass a NULL tvb to IP after
    # reassembly": the unacknowledged mode N-PDU 7 is reassembled in frame
    # N+1 and holds an IPv4/UDP/GSMTAP/SNDCP packet with the same N-PDU number
    inner_sndcp = first_unack(5, 7, b'INNERDATA', m=0, seg=1)[:0] + sn_hdr(5, 0, 1, 0) + struct.pack('!H', (1 << 12) | 7) + b'INNERDATA'
    inner_ip = ip4(17, udp(gsmtap(GSMTAP_GB_SNDCP, inner_sndcp), 4729, 4729), '192.0.2.1', '192.0.2.2')
    send_sndcp(first_unack(5, 7, inner_ip[:20], m=1, seg=0), sport=4729)
    send_sndcp(next_unack(5, 7, 1, inner_ip[20:], m=0), sport=4729)
    p.write(os.path.join(out, 'sndcp-coverage.pcap'))

    m = Pcap(DLT_EN10MB)
    def msend(sndcp):
        count[0] += 1
        m.add(eth(ip4(17, udp(gsmtap(GSMTAP_GB_SNDCP, sndcp), 3100, 4729), ident=count[0]), 0x0800))
    msend(b'\x40')                               # first segment, no compression octet
    msend(b'\x40\x00')                           # acknowledged mode, no N-PDU octet
    msend(b'\x60\x00')                           # unacknowledged mode, N-PDU field cut off
    msend(b'\x60\x00\x00')
    msend(b'\x20')                               # not first, unacknowledged, no N-PDU field
    msend(first_ack(5, 3, pkt[:12]))             # IP header truncated
    msend(first_ack(5, 3, b'\x45'))
    m.write(os.path.join(out, 'sndcp-coverage-malformed.pcap'))

main(sys.argv[1] if len(sys.argv) > 1 else '.')
