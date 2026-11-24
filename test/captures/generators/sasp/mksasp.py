#!/usr/bin/env python3
# Generates test/captures/sasp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SASP coverage captures: mksasp.py <outdir> [-v].  All data is synthetic."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from c17lib import Cap, Tcp

def ip6(n):
    return b'\x20\x01\x0d\xb8' + b'\0' * 11 + bytes([n])

def memdata(n, port=80, proto=6, label=b'', typ=0x3010):
    body = struct.pack('>BH', proto, port) + ip6(n) + bytes([len(label)]) + label
    return struct.pack('>HH', typ, 4 + len(body)) + body

def grpdata(uid=b'lb1', name=b'grp1', typ=0x3011):
    body = bytes([len(uid)]) + uid + bytes([len(name)]) + name
    return struct.pack('>HH', typ, 4 + len(body)) + body

def grp_mem(members, uid=b'lb1', name=b'grp1'):
    g = grpdata(uid, name)
    body = struct.pack('>H', len(members)) + g + b''.join(members)
    return struct.pack('>HH', 0x4010, 4 + len(body)) + body

def wtentry(n, state=1, flags=0x0f, weight=100, label=b''):
    return memdata(n, label=label) + struct.pack('>HHBBH', 0x3012, 10, state, flags, weight)

def grp_wt(entries, uid=b'lb1', name=b'grp1'):
    g = grpdata(uid, name)
    body = struct.pack('>H', len(entries)) + g + b''.join(entries)
    return struct.pack('>HH', 0x4011, 4 + len(body)) + body

def memstate(n, state=1, quiesce=0, label=b''):
    return memdata(n, label=label) + struct.pack('>HHBB', 0x3013, 6, state, quiesce)

def grp_ms(members, uid=b'lb1', name=b'grp1'):
    g = grpdata(uid, name)
    body = struct.pack('>H', len(members)) + g + b''.join(members)
    return struct.pack('>HH', 0x4012, 4 + len(body)) + body

def pdu(mtype, body, mid=1, hdrtype=0x2010):
    return struct.pack('>HHBIIH', hdrtype, 13, 1, 15 + len(body), mid, mtype) + body

def sized(body):
    return struct.pack('>H', 2 + len(body)) + body

def reg_req(groups, lb=1):
    return pdu(0x1010, sized(bytes([lb]) + struct.pack('>H', len(groups)) + b''.join(groups)), 1)
def dereg_req(groups, reason=0, lb=0, mid=5):
    return pdu(0x1020, sized(bytes([lb, reason]) + struct.pack('>H', len(groups)) + b''.join(groups)), mid)
def reply(mtype, code, mid):
    return pdu(mtype, sized(bytes([code])), mid)
def wt_req(grps, mid=9):
    return pdu(0x1030, sized(struct.pack('>H', len(grps)) + b''.join(grps)), mid)
def wt_rep(entries, code=0, interval=60, mid=9):
    return pdu(0x1035, sized(bytes([code]) + struct.pack('>HH', interval, len(entries)) + b''.join(entries)), mid)
def send_wt(entries, mid=12):
    return pdu(0x1040, sized(struct.pack('>H', len(entries)) + b''.join(entries)), mid)
def setlb_req(uid=b'lb1', health=0x7f, flags=7, mid=14):
    return pdu(0x1050, sized(bytes([len(uid)]) + uid + bytes([health, flags])), mid)
def setms_req(groups, lb=0, mid=16):
    return pdu(0x1060, sized(bytes([lb]) + struct.pack('>H', len(groups)) + b''.join(groups)), mid)

def main(out, verbose=False):
    c = Cap(1)
    t = Tcp(c, 40000, 3860)
    c.mark('Registration request, two groups with members (IPv6 addresses, labels), one TCP segment')
    t.c2s(reg_req([grp_mem([memdata(1, 80, 6, b'web1'), memdata(2, 53, 17)]),
                   grp_mem([memdata(3, 8080, 6, b'app')], b'lb2', b'grp2')]))
    c.mark('Registration replies with every response code')
    for i, code in enumerate((0, 0x10, 0x11, 0x40, 0x44, 0x45, 0x50, 0x51, 0x61, 0x77)):
        t.s2c(reply(0x1015, code, 1 + i))
    c.mark('Deregistration requests: no reason, learned and purposeful, no reason (reproducer of the static first_flag fix)')
    t.c2s(dereg_req([grp_mem([memdata(1)])], reason=0))
    t.c2s(dereg_req([grp_mem([memdata(1)])], reason=1, lb=1))
    t.c2s(dereg_req([grp_mem([memdata(2)])], reason=0))
    c.mark('Deregistration replies')
    for i, code in enumerate((0, 0x41, 0x42, 0x43, 0x44, 0x46, 0x51, 0x61)):
        t.s2c(reply(0x1025, code, 5 + i))
    c.mark('Get weights request and replies')
    t.c2s(wt_req([grpdata(), grpdata(b'lb2', b'grp2')]))
    t.s2c(wt_rep([grp_wt([wtentry(1, 1, 0x01, 10), wtentry(2, 2, 0x06, 20), wtentry(3, 0, 0x08, 30, b'x')]),
                  grp_wt([wtentry(4, 3, 0, 0)], b'lb2', b'grp2')]))
    for code in (0, 0x10, 0x11, 0x42, 0x43, 0x46, 0x51):
        t.s2c(wt_rep([], code))
    c.mark('Send weights requests')
    t.c2s(send_wt([grp_wt([wtentry(1, 1, 0x0f, 65535), wtentry(2, 1, 0x00, 1)])]))
    t.c2s(send_wt([]))
    c.mark('Set LB state requests and replies')
    t.c2s(setlb_req(b'lb1', 0x7f, 7))
    t.c2s(setlb_req(b'lb-two', 0x00, 1))
    t.c2s(setlb_req(b'', 0x40, 0))
    for code in (0, 0x10, 0x11, 0x51, 0x99):
        t.s2c(reply(0x1055, code, 14))
    c.mark('Set member state requests and replies')
    t.c2s(setms_req([grp_ms([memstate(1, 1, 1), memstate(2, 0, 0, b'n')]), grp_ms([memstate(3)], b'lb2', b'g2')], lb=1))
    t.c2s(setms_req([]))
    for code in (0, 0x10, 0x11, 0x41, 0x42, 0x43, 0x44, 0x46, 0x50, 0x51):
        t.s2c(reply(0x1065, code, 16))
    c.mark('Messages split over TCP segments (reassembly) and several messages in one segment')
    big = reg_req([grp_mem([memdata(i, 1000 + i, 6, b'host%d' % i) for i in range(1, 9)])], lb=0)
    t.c2s(big[:30]); t.c2s(big[30:70]); t.c2s(big[70:])
    a = reply(0x1015, 0, 40); b = reply(0x1025, 0x41, 41)
    t.s2c(a + b)
    t.s2c(a[:10]); t.s2c(a[10:] + b)
    c.mark('Second client on the same server port')
    t2 = Tcp(c, 40001, 3860, '192.0.2.5', '192.0.2.2')
    t2.c2s(wt_req([grpdata(b'x', b'y')], mid=77))
    t2.s2c(wt_rep([grp_wt([wtentry(9, 1, 0x0b, 5)], b'x', b'y')], mid=77))

    m = Cap(1)
    tm = Tcp(m, 40002, 3860)
    m.mark('Invalid header type and unknown message type (error expert infos)')
    tm.c2s(pdu(0x1010, sized(b'\0\0\0'), hdrtype=0x2011))
    tm.c2s(pdu(0x1099, b'\0\0\0\0'))
    m.mark('Truncated members and labels, counts that are too large (exceptions)')
    tm.c2s(reg_req([grp_mem([memdata(1, label=b'abcdef')])])[:-3])
    p = bytearray(dereg_req([grp_mem([memdata(1)]), grp_mem([memdata(2)])]))
    struct.pack_into('>H', p, 15 + 4, 5)
    tm.c2s(bytes(p))
    for typ in (0x1030, 0x1035, 0x1040, 0x1050, 0x1060):
        tm.c2s(pdu(typ, b'\0\x08\0\x05' + b'\0' * 3))
    tm.c2s(pdu(0x1015, b''))
    tm.c2s(pdu(0x1010, sized(b'\x01\xff\xff')))

    c.write(os.path.join(out, 'sasp-coverage.pcap'))
    m.write(os.path.join(out, 'sasp-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
