#!/usr/bin/env python3
# Generates test/captures/gift_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-gift.c.  Usage: mkgift.py <outdir> [-v]"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import util as u

def main_frames():
    o = []
    c = u.Conn(o, 41000, 1213)
    C = c.send; S = c.recv
    S(b'ATTACH server(giFT) version(0.11.8);\n')
    C(b'ATTACH client(demo) version(0.1);\n')
    S(b'ITEM(1) total(3) ;\n')
    C(b'SEARCH(1) query(synthetic test) realm(audio);\n')
    S(b'ITEM(1)\n'
      b'  user(192.0.2.99) node(192.0.2.99:1214) availability(1) size(1234567) url(OpenFT://192.0.2.99:1216/x.ogg) file(x.ogg);\n')
    S(b'ITEM(1);\r\n')
    C(b'STATS;\n')
    C(b'SHARE action(sync);\r\n')
    S(b'ITEM;\n')
    C(b'BYE\n')
    # lines with unusual first tokens
    C(b'\n')                         # empty line
    C(b'\r\n')
    C(b'   leading blanks only(arg)\n')
    C(b'trailing ')                  # token then space, no newline
    S(b'x\n')
    S(b' \n')
    S(b'ONLYTOKEN')
    S(b'multi(1)\nsecond line(2)\nthird\n')
    S(b'cmd with\ttab\x01\x7f\xff and non-ASCII \xc3\xa9\n')
    C(b'A' * 400 + b'(' + b'b' * 400 + b')\n')   # long line
    C(b'ADDSOURCE user(x) hash(MD5:0123456789abcdef) size(10) url(http://192.0.2.5/a);\n')
    C(b'DELSOURCE user(x) hash(MD5:0123456789abcdef) url(http://192.0.2.5/a);\n')
    C(b'TRANSFER(5) action(cancel);\n')
    S(b'ADDDOWNLOAD(5) hash(MD5:0123456789abcdef) size(10) file(a.bin);\n')
    S(b'CHGDOWNLOAD(5) state(Active) transmit(5) total(10);\n')
    S(b'DELDOWNLOAD(5);\n')
    c.fin()
    # a second client, and a response from a server on a non-default port
    # reached by the default port as source (server to client direction)
    c2 = u.Conn(o, 1213, 41001, caddr='192.0.2.9', saddr='192.0.2.3', handshake=False)
    c2.send(b'ATTACH client(x);\n')
    c2.recv(b'ATTACH server(y);\n')
    return o

def mal_frames():
    o = []
    # both ports 1213: match_uint equals the destination port in one direction
    c = u.Conn(o, 1213, 1213)
    c.send(b'ATTACH both(ports);\n')
    c.recv(b'ITEM(1);\n')
    # truncated captured payload (snaplen shorter than the line)
    f = u.tcp(41002, 1213, 100, b'SEARCH(1) query(cut short)' + b'x' * 50)
    o.append(f[:len(f) - 40])
    return o

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m = main_frames()
    u.write_pcap(os.path.join(out, 'gift-coverage.pcap'), m)
    u.gz(os.path.join(out, 'gift-coverage.pcap'))
    mm = mal_frames()
    u.write_pcap(os.path.join(out, 'gift-coverage-malformed.pcap'), mm)
    if '-v' in sys.argv:
        print(len(m), len(mm))
