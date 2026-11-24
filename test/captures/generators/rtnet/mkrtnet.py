#!/usr/bin/env python3
# Generates test/captures/rtnet_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the RTnet (RTmac, TDMA, RTcfg) coverage captures. Usage: mkrtnet.py <outdir>"""
import sys
import os
import struct
from pcaplib import eth, ip4, ipv4, mac, PcapNg, udp

RTMAC, RTCFG = 0x9021, 0x9022
T_TDMA, T_TDMA_V1 = 0x0001, 0x9031

def rtmac(typ, ver, flags, payload=b''):
    return struct.pack('>HBB', typ, ver, flags) + payload

def tdma(msg, body=b'', ver=1):
    return struct.pack('>HH', ver, msg) + body

def q(v): return struct.pack('>Q', v)
def i(v): return struct.pack('>I', v)
def h(v): return struct.pack('>H', v)

def v1msg(msg, body=b''):
    return struct.pack('>I', msg) + body

def rtcfg(vers_id, body=b''):
    return bytes([vers_id]) + body

def ipudp(payload=b'rtnet data'):
    return ipv4(udp(payload, 1234, 5678), 17, '10.1.0.1', '10.1.0.2')

ARP = bytes.fromhex('0001080006040001') + mac(1) + ip4('10.1.0.1') + b'\0' * 6 + ip4('10.1.0.2')

def main(out):
    p = PcapNg()
    def f(etype, payload, src=1, dst=2):
        p.add(eth(payload, etype, src, dst))
    # ---- RTmac version 2 with TDMA
    f(RTMAC, rtmac(T_TDMA, 2, 0, tdma(0x0000, i(7) + q(1000) + q(900), 2)[:0] + struct.pack('>HH', 2, 0) + i(7) + q(1000) + q(1500)))  # xmit - sched < 0
    f(RTMAC, rtmac(T_TDMA, 2, 0, struct.pack('>HH', 2, 0) + i(8) + q(5000) + q(4000)))                    # > 0
    f(RTMAC, rtmac(T_TDMA, 2, 0, struct.pack('>HH', 2, 0x10) + q(123456789) + i(3) + q(987654321)))      # request calibration
    f(RTMAC, rtmac(T_TDMA, 2, 0, struct.pack('>HH', 2, 0x11) + q(100) + q(200) + q(150)))                 # reply calibration, xmit - rcv < 0 ...
    f(RTMAC, rtmac(T_TDMA, 2, 0, struct.pack('>HH', 2, 0x11) + q(100) + q(200) + q(300)))                 # other sign
    f(RTMAC, rtmac(T_TDMA, 2, 0, struct.pack('>HH', 2, 0x7777) + b'\1\2\3\4'))                           # unknown TDMA message
    f(RTMAC, rtmac(T_TDMA, 2, 0xfe, struct.pack('>HH', 2, 0) + i(9) + q(10) + q(10)))                    # reserved flags set
    # ---- RTmac version 2, not TDMA and not tunnelled: data
    f(RTMAC, rtmac(0x1234, 2, 0, b'opaque payload'))
    # ---- RTmac version 2 with the tunnel flag: IPv4, ARP, an unknown ethertype, nested RTmac
    f(RTMAC, rtmac(0x0800, 2, 1, ipudp()))
    f(RTMAC, rtmac(0x0806, 2, 1, ARP))
    f(RTMAC, rtmac(0x6666, 2, 1, b'unknown ethertype'))
    f(RTMAC, rtmac(RTMAC, 2, 1, rtmac(T_TDMA, 2, 0, struct.pack('>HH', 2, 0) + i(1) + q(2) + q(3))))
    f(RTMAC, rtmac(RTMAC, 2, 1, rtmac(0x0800, 2, 1, ipudp(b'tunnel in tunnel'))))
    f(RTMAC, rtmac(0x0800, 2, 0xff, ipudp(b'reserved flags and tunnel')))
    # ---- RTmac version 1 with TDMA-V1 messages
    def v1(msg, body=b''):
        f(RTMAC, rtmac(T_TDMA_V1, 1, 0x55, v1msg(msg, body)))
    v1(0x10)                                                       # notify master
    v1(0x11, struct.pack('<IQ', 77, 0x1122334455667788))           # request test
    v1(0x12, struct.pack('<IQ', 77, 0x8877665544332211))           # ack test
    v1(0x13, bytes([3, 0]) + h(1500) + i(2000))                    # request conf
    v1(0x14, bytes([3, 0]) + h(1500) + i(2000))                    # ack conf
    v1(0x15, bytes([3, 0, 0, 0]))                                  # ack ack conf
    v1(0x16, bytes([0, 0, 0, 0]))                                  # station list, none
    v1(0x16, bytes([3, 0, 0, 0]) + b''.join(ip4('10.1.0.%d' % n) + bytes([n, 0, 0, 0]) for n in (1, 2, 3)))
    v1(0x17, i(500))                                               # request change offset
    v1(0x18, q(0x0102030405060708))                                # start of frame
    v1(0x99, b'\xde\xad')                                          # unknown TDMA-V1 message
    # ---- RTmac version 1 with a type that is not TDMA-V1: ethertype lookup, else data
    f(RTMAC, rtmac(0x0800, 1, 0, ipudp(b'v1 tunnel')))
    f(RTMAC, rtmac(0x0806, 1, 0, ARP))
    f(RTMAC, rtmac(0x4321, 1, 0, b'v1 unknown type'))
    # ---- RTmac version 3 (not 1) without tunnel flag and unknown type
    f(RTMAC, rtmac(T_TDMA, 3, 0, struct.pack('>HH', 3, 0) + i(1) + q(2) + q(3)))
    # ---- Reproducer of "RTnet: Bound nesting of tunneled RTmac headers": version 2, tunnel flag and type 0x9021
    # repeated; the dissector stops after 5 RTmac headers and passes the rest to data (600 headers pass the
    # default limit of 500 layers, which the unfixed dissector hit as a "Dissector bug")
    f(RTMAC, rtmac(RTMAC, 2, 1) * 600 + b'end of nested headers')
    f(RTMAC, rtmac(RTMAC, 1, 0) * 7 + b'end of nested v1 headers')
    # ---- RTcfg
    def cfg(vid, body=b'', src=1):
        f(RTCFG, rtcfg(vid, body), src=src)
    def ver(v, mid): return (v << 5) | mid
    cfg(ver(0, 0), bytes([0x00]) + bytes([4]) + h(0))                                # S1 config, MAC, no data
    cfg(ver(0, 0), bytes([0x00]) + bytes([4]) + h(6) + b'config')                    # S1 config, MAC, data
    cfg(ver(0, 0), bytes([0x01]) + ip4('10.1.0.5') + ip4('10.1.0.1') + bytes([8]) + h(4) + b'\1\2\3\4')   # S1 config, IP
    cfg(ver(0, 1), bytes([0x00]) + bytes([0x03, 5]))                                 # new announce, MAC
    cfg(ver(0, 1), bytes([0x01]) + ip4('10.1.0.5') + bytes([0x01, 9]))               # new announce, IP, flags
    cfg(ver(0, 1), bytes([0x01]) + ip4('10.1.0.6') + bytes([0xfe, 9]))
    cfg(ver(0, 2), bytes([0x00, 0x02, 0]))                                           # reply announce, MAC
    cfg(ver(0, 2), bytes([0x01]) + ip4('10.1.0.5') + bytes([0x03, 0]))               # reply announce, IP
    cfg(ver(0, 3), bytes([0x04]) + i(3) + h(100) + i(10) + b'stage 2 config data')   # S2 config with data
    cfg(ver(0, 3), bytes([0x00]) + i(0) + h(0) + i(0))                               # S2 config, none
    cfg(ver(0, 3), bytes([0xfa]) + i(2) + h(50) + i(4) + b'abcd')                    # reserved flag bits
    cfg(ver(0, 4), i(0) + b'fragment data')                                          # S2 fragment
    cfg(ver(0, 4), i(1000) + b'second fragment')
    cfg(ver(0, 5), i(2048))                                                          # ack
    cfg(ver(0, 6))                                                                   # ready
    cfg(ver(0, 7))                                                                   # heartbeat
    cfg(ver(0, 8), bytes([0x00]) + mac(5) + b'\0' * 26)                              # dead station, MAC
    cfg(ver(0, 8), bytes([0x01]) + ip4('10.1.0.5') + mac(5) + b'\0' * 26)            # dead station, IP
    cfg(ver(1, 9))                                                                   # version 1, unknown message
    cfg(ver(0, 0x1f))
    # ---- RTcfg dead station on a link layer whose source address is not an Ethernet address
    # (Linux cooked capture with an unknown ARPHRD type); RTmac and RTcfg are found by the SLL protocol field
    def sll(proto, payload, hatype=0x0301):
        return struct.pack('>HHH', 0, hatype, 8) + b'\2\0\0\0\0\1\0\0' + struct.pack('>H', proto) + payload
    p.add(sll(RTCFG, rtcfg(ver(0, 8), bytes([0x00]) + mac(5) + b'\0' * 26)), lt=113)
    p.add(sll(RTCFG, rtcfg(ver(0, 8), bytes([0x01]) + ip4('10.1.0.7') + b'\1' * 32)), lt=113)
    p.add(sll(RTMAC, rtmac(T_TDMA, 2, 0, struct.pack('>HH', 2, 0x10) + q(1) + i(2) + q(3))), lt=113)
    p.write(os.path.join(out, 'rtnet-coverage.pcapng'))

    m = PcapNg()
    def mf(etype, payload):
        m.add(eth(payload, etype))
    mf(RTMAC, b'\x00\x01\x02')                                                # truncated RTmac header
    mf(RTMAC, rtmac(T_TDMA, 2, 0, b'\x00\x02'))                               # TDMA without message id
    mf(RTMAC, rtmac(T_TDMA, 2, 0, struct.pack('>HH', 2, 0) + i(7) + q(1)))   # sync cut
    mf(RTMAC, rtmac(T_TDMA, 2, 0, struct.pack('>HH', 2, 0x10) + q(1)))       # request calibration cut
    mf(RTMAC, rtmac(T_TDMA, 2, 0, struct.pack('>HH', 2, 0x11) + q(1) + q(2))) # reply calibration cut
    mf(RTMAC, rtmac(T_TDMA_V1, 1, 0, b'\0\0'))                                # TDMA-V1 message cut
    mf(RTMAC, rtmac(T_TDMA_V1, 1, 0, v1msg(0x11, b'\0\0\0\0')))
    mf(RTMAC, rtmac(T_TDMA_V1, 1, 0, v1msg(0x13, b'\3')))
    mf(RTMAC, rtmac(T_TDMA_V1, 1, 0, v1msg(0x16, bytes([200, 0, 0, 0]) + b'\1' * 12)))   # station count too large
    mf(RTMAC, rtmac(T_TDMA_V1, 1, 0, v1msg(0x18, b'\0\0')))
    mf(RTMAC, rtmac(T_TDMA_V1, 1, 0, v1msg(0x17, b'\0')))
    mf(RTMAC, rtmac(T_TDMA_V1, 1, 0, v1msg(0x15, b'\0')))
    mf(RTMAC, rtmac(T_TDMA_V1, 1, 0, v1msg(0x14, b'\0')))
    mf(RTMAC, rtmac(T_TDMA_V1, 1, 0, v1msg(0x12, b'\0')))
    mf(RTCFG, b'')                                                            # empty RTcfg
    mf(RTCFG, rtcfg(0x00))                                                    # S1 config without address type
    mf(RTCFG, rtcfg(0x00, b'\x01' + b'\0' * 5))                               # S1 config, IP cut
    mf(RTCFG, rtcfg(0x00, b'\x00\x04\x00\x20' + b'ab'))                       # config length larger than data
    mf(RTCFG, rtcfg(0x01, b'\x01\0'))                                         # announce cut
    mf(RTCFG, rtcfg(0x02))
    mf(RTCFG, rtcfg(0x03, b'\0\0\0'))
    mf(RTCFG, rtcfg(0x04, b'\0'))
    mf(RTCFG, rtcfg(0x05, b'\0'))
    mf(RTCFG, rtcfg(0x08, b'\x00' + b'\0' * 10))                              # dead station, hw address cut
    m.add(struct.pack('>HHH', 0, 0x0301, 8) + b'\2\0\0\0\0\1\0\0' + struct.pack('>H', RTCFG) + rtcfg(0x08, b'\x00' + b'\0' * 10), lt=113)
    m.write(os.path.join(out, 'rtnet-coverage-malformed.pcapng'))

main(sys.argv[1])
