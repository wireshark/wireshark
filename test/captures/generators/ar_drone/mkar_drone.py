#!/usr/bin/env python3
# AR Drone coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Parrot AR Drone AT commands over UDP port 5556 (packet-ar_drone.c).

Usage: mkar_drone.py [<output directory>]

Writes:
  ar_drone-coverage.pcap            every command, every PCMD direction,
                                    several commands per packet, cases
                                    that decode cleanly, packets the
                                    heuristic and the dissector turn down
  ar_drone-coverage-malformed.pcap  each missing delimiter (error expert
                                    infos)

No UDP port is registered for AR Drone by default and its heuristic is
disabled: dissect with -d udp.port==5556,ar_drone or with
--enable-heuristic ar_drone_udp.

Every packet is built here; nothing comes from a real network. Hosts use
documentation addresses (192.0.2.0/24, 2001:db8::/32) and locally
administered MAC addresses.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from capgen import eth, ipv4, ipv6, udp, write_pcap  # noqa: E402

MAC1 = bytes.fromhex('020000000001')
MAC2 = bytes.fromhex('020000000002')

CTL = '192.0.2.10'     # controller (phone, tablet)
DRONE = '192.0.2.1'    # the drone
AT_PORT = 5556


def ip6(last):
    return bytes.fromhex('20010db8') + b'\0' * 11 + bytes([last])


class Pcap:
    def __init__(self):
        self.frames = []
        self.notes = []

    def note(self, text):
        self.notes.append((len(self.frames) + 1, text))

    def udp(self, payload, src=CTL, dst=DRONE, sport=AT_PORT, dport=AT_PORT):
        if isinstance(payload, str):
            payload = payload.encode()
        seg = udp(payload, sport, dport, src=src, dst=dst)
        if isinstance(src, str):
            ip = ipv4(seg, 17, src=src, dst=dst, ident=len(self.frames) & 0xffff)
            etype = 0x0800
        else:
            ip = ipv6(seg, 17, src=src, dst=dst)
            etype = 0x86dd
        self.frames.append(eth(ip, etype, dst=MAC2, src=MAC1))

    def write(self, path):
        write_pcap(path, self.frames, ts=lambda i: (1700000000 + i // 30, (i % 30) * 30000))


def f2i(x):
    """A float as the signed integer the AT commands send."""
    return struct.unpack('<i', struct.pack('<f', x))[0]


TAKEOFF, LAND, EMERGENCY = 290718208, 290717696, 290717952

# One complete command of each kind, used for the missing delimiter cases
SAMPLES = {
    'PCMD': 'AT*PCMD=10,1,%d,%d,%d,%d\r' % (f2i(0.5), f2i(-0.25), f2i(0.1), f2i(-0.75)),
    'REF': 'AT*REF=11,%d\r' % TAKEOFF,
    'CONFIG_IDS': 'AT*CONFIG_IDS=12,"d2e081a3","be27e2e4","d87f7e0c"\r',
    'ANIM': 'AT*ANIM=13,3,2\r',
    'FTRIM': 'AT*FTRIM=14\r',
    'CONFIG': 'AT*CONFIG=15,"control:altitude_max","3000"\r',
    'LED': 'AT*LED=16,2,%d,3\r' % f2i(2.0),
    'COMWDG': 'AT*COMWDG=17\r',
    'CTRL': 'AT*CTRL=18,5,0\r',
}


def main(outdir):
    cap = Pcap()
    bad = Pcap()
    seq = 1

    def s():
        nonlocal seq
        seq += 1
        return seq - 1

    # ---- A flight ---------------------------------------------------------
    cap.note('session set-up: CONFIG_IDS, CONFIG, CTRL with each mode, FTRIM')
    cap.udp('AT*CONFIG_IDS=%d,"d2e081a3","be27e2e4","d87f7e0c"\r' % s())
    cap.udp('AT*CONFIG=%d,"general:navdata_demo","TRUE"\r' % s())
    cap.udp('AT*CTRL=%d,4,0\r' % s())
    cap.udp('AT*CTRL=%d,5,0\r' % s())
    cap.udp('AT*CTRL=%d,6,0\r' % s())
    cap.udp('AT*CTRL=%d,0,0\r' % s())           # unknown mode
    cap.udp('AT*CTRL=%d,4,1048576\r' % s())     # firmware update size
    cap.udp('AT*FTRIM=%d\r' % s())
    cap.note('REF: emergency, take off, COMWDG, LED, ANIM')
    cap.udp('AT*REF=%d,%d\r' % (s(), EMERGENCY))
    cap.udp('AT*REF=%d,%d\r' % (s(), TAKEOFF))
    cap.udp('AT*COMWDG=%d\r' % s())
    cap.udp('AT*LED=%d,2,%d,3\r' % (s(), f2i(2.0)))
    cap.udp('AT*ANIM=%d,3,2\r' % s())

    cap.note('PCMD: every direction of roll, pitch, gaz and yaw')
    for v in (0.0, 0.5, -0.5):
        x = f2i(v)
        cap.udp('AT*PCMD=%d,1,%d,%d,%d,%d\r' % (s(), x, x, x, x))
    # "-0..." (negative zero) is NO CHANGE too
    cap.udp('AT*PCMD=%d,1,-0,-0,-0,-0\r' % s())
    # Hover: flag 0, every value 0
    cap.udp('AT*PCMD=%d,0,0,0,0,0\r' % s())
    # Mixed directions in one command
    cap.udp('AT*PCMD=%d,1,%d,%d,%d,%d\r' % (s(), f2i(-0.2), f2i(0.3), f2i(-1.0), f2i(1.0)))
    cap.note('PCMD: empty values have no direction (each field once, then all)')
    cap.udp('AT*PCMD=2,1,,0,0,0\r')
    cap.udp('AT*PCMD=%d,1,0,,0,0\r' % s())
    cap.udp('AT*PCMD=%d,1,0,0,,0\r' % s())
    cap.udp('AT*PCMD=%d,1,0,0,0,\r' % s())
    cap.udp('AT*PCMD=%d,,,,,\r' % s())

    cap.note('several commands per packet, as the controller sends them')
    cap.udp('AT*REF=%d,%d\rAT*PCMD=%d,1,0,%d,0,0\rAT*FTRIM=%d\r'
            % (s(), TAKEOFF, s(), f2i(-1.0), s()))
    cap.udp('AT*PCMD=%d,1,%d,0,0,0\rAT*REF=%d,%d\rAT*COMWDG=%d\r'
            % (s(), f2i(0.1), s(), TAKEOFF, s()))
    cap.udp(''.join(SAMPLES[k] for k in ('PCMD', 'REF', 'CONFIG_IDS', 'ANIM', 'FTRIM',
                                         'CONFIG', 'LED', 'COMWDG', 'CTRL')))
    cap.udp('AT*CONFIG_IDS=%d,"d2e081a3","be27e2e4","d87f7e0c"\rAT*CONFIG=%d,"video:video_channel","1"\r'
            % (s(), s()))
    cap.note('trailing data: 3 octets, text that is not AT*, an unknown command, a command without "="')
    cap.udp('AT*COMWDG=%d\r\n\0\0' % s())        # \n\0\0: too short for another command
    cap.udp('AT*REF=%d,%d\rgarbage\r' % (s(), LAND))
    cap.udp('AT*REF=%d,%d\rAT*FOO=1,2\rAT*COMWDG=9\r' % (s(), LAND))
    cap.udp('AT*FTRIM=%d\rAT*COMWDG\r' % s())

    cap.note('more cases, from port 40000')
    cap.udp('AT*REF=1,290718208\rAT*PCMD=2,1,0,-1082130432,0,0\rAT*FTRIM=3\r', sport=40000)
    cap.udp('AT*REF=1,290718208\rX=1\r', sport=40000)     # '=' at the second command + 1
    cap.udp('AT*COMWDG=5\r=AAAA\r', sport=40000)          # '=' at the second command + 0
    cap.udp('AT*FOO=1,2\r', sport=40000)                   # unknown first command
    cap.udp('AT*CTRL=7,4,0\r', sport=40000)

    cap.note('land, IPv6')
    cap.udp('AT*REF=%d,%d\r' % (s(), LAND))
    cap.udp('AT*REF=%d,%d\rAT*PCMD=%d,0,0,0,0,0\r' % (s(), LAND, s()), src=ip6(10), dst=ip6(1))

    cap.note('turned down by the dissector (and the heuristic): short, not AT*, no "=", empty name, AT*PCMD_MAG')
    cap.udp('AT*')
    cap.udp('ATX*REF=1,2\r')
    cap.udp('AT*COMWDG\r')
    cap.udp('AT*=1\r')
    # AR Drone 2.0 PCMD_MAG: taken as a PCMD
    cap.udp('AT*PCMD_MAG=%d,1,0,0,0,0,0,0\r' % s())
    cap.note('not on port 5556, for the heuristic: known command, unknown command, no "="')
    cap.udp('AT*REF=%d,%d\r' % (s(), LAND), sport=40001, dport=40002)
    cap.udp('AT*FOO=1\r', sport=40001, dport=40002)
    cap.udp('AT*REF\r', sport=40001, dport=40002)

    # ---- Missing delimiters ---------------------------------------------
    bad.note('each command cut before each of its delimiters (error expert infos)')
    for name, cmd in SAMPLES.items():
        start = cmd.index('=') + 1
        for i, c in enumerate(cmd):
            if i >= start and c in ',\r':
                bad.udp(cmd[:i])
    bad.note('CONFIG without the CR')
    bad.udp('AT*CONFIG=1,"general:navdata_demo","TRUE"', sport=40000)
    bad.note('a complete REF, then a PCMD without the CR')
    bad.udp('AT*REF=1,0\rAT*PCMD=2,1,0,0,0,0')

    os.makedirs(outdir, exist_ok=True)
    cap.write(os.path.join(outdir, 'ar_drone-coverage.pcap'))
    bad.write(os.path.join(outdir, 'ar_drone-coverage-malformed.pcap'))
    for name, p in (('ar_drone-coverage.pcap', cap), ('ar_drone-coverage-malformed.pcap', bad)):
        print(name, len(p.frames), 'frames')
        for n, text in p.notes:
            print('  %4d  %s' % (n, text))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
