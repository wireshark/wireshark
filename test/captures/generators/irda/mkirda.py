#!/usr/bin/env python3
# Generates test/captures/irda_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic IrDA / IrLAP / IrLMP / IAP / TTP / IrCOMM / SIR
coverage captures.

Usage: mkirda.py <outdir>

Writes irda-coverage.pcapng (valid traffic) and
irda-coverage-malformed.pcapng (paths only malformed input reaches).
The pcapng files have several interfaces: Linux IrDA (linktype 144),
Linux cooked (113), Ethernet (SIR over TCP port 6417) and Exported PDU
(252).  Everything is built with struct; nothing is captured from a
network.
"""
import os
import socket
import struct
import sys

LT_ETHERNET, LT_SLL, LT_IRDA, LT_EXPDU = 1, 113, 144, 252

IN, OUT, LOG, MISSED = 0x0000, 0x0004, 0x0100, 0x0101


# ------------------------------------------------------------ pcapng
class Pcapng:
    def __init__(self):
        self.idbs = []          # linktypes
        self.blocks = []

    @staticmethod
    def _block(btype, body):
        body += b'\0' * ((-len(body)) % 4)
        total = 12 + len(body)
        return struct.pack('<II', btype, total) + body + struct.pack('<I', total)

    def iface(self, lt):
        if lt not in self.idbs:
            self.idbs.append(lt)
        return self.idbs.index(lt)

    def add(self, lt, data, ts=None):
        i = self.iface(lt)
        n = len(self.blocks)
        usec = 1600000000 * 1000000 + n * 150000 if ts is None else ts
        self.blocks.append((i, usec, data))

    def write(self, fn):
        out = self._block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in self.idbs:
            out += self._block(1, struct.pack('<HHI', lt, 0, 262144))
        for i, usec, d in self.blocks:
            body = struct.pack('<IIIII', i, usec >> 32, usec & 0xffffffff, len(d), len(d)) + d
            out += self._block(6, body)
        with open(fn, 'wb') as f:
            f.write(out)


# ------------------------------------------------------------ TCP for SIR
def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


class Stream:
    def __init__(self, cport, sport):
        self.cport, self.sport = cport, sport
        self.cseq, self.sseq = 100, 900
        self.ipid = 1
        self.out = []

    def _frame(self, c2s, payload, flags):
        cip, sip = '192.0.2.10', '192.0.2.20'
        if c2s:
            sp, dp, seq, ack, s, d = self.cport, self.sport, self.cseq, self.sseq, cip, sip
            mac = b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01'
        else:
            sp, dp, seq, ack, s, d = self.sport, self.cport, self.sseq, self.cseq, sip, cip
            mac = b'\x02\0\0\0\0\x01' + b'\x02\0\0\0\0\x02'
        opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 2 else b''
        if flags == 0x02:
            ack = 0
        tcp = struct.pack('!HHIIBBHHH', sp, dp, seq, ack, ((20 + len(opts)) // 4) << 4,
                          flags, 65535, 0, 0) + opts + payload
        ph = socket.inet_aton(s) + socket.inet_aton(d) + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), self.ipid, 0, 64, 6, 0,
                         socket.inet_aton(s), socket.inet_aton(d))
        self.ipid += 1
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        self.out.append(mac + b'\x08\x00' + ip + tcp)
        adv = len(payload) + (1 if flags & 3 else 0)
        if c2s:
            self.cseq += adv
        else:
            self.sseq += adv

    def handshake(self):
        self._frame(True, b'', 0x02)
        self._frame(False, b'', 0x12)
        self._frame(True, b'', 0x10)

    def send(self, c2s, payload):
        self._frame(c2s, payload, 0x18)


# ------------------------------------------------------------ IrDA builders
def irda_rec(pkttype, data):
    """Linux IrDA (SLL like) header: packet type, 12 octets, protocol 0x0017."""
    return struct.pack('!H', pkttype) + b'\0' * 12 + struct.pack('!H', 0x17) + data


def circuit(addr, cmd):
    return ((addr << 1) | (1 if cmd else 0)) & 0xff


def i_ctl(ns, nr, pf=0):
    return ((nr & 7) << 5) | (pf << 4) | ((ns & 7) << 1)


def s_ctl(kind, nr, pf=0):
    return ((nr & 7) << 5) | (pf << 4) | (kind << 2) | 0x01       # 0 RR 1 RNR 2 REJ 3 SREJ


def u_ctl(mod, pf=1):
    return mod | 0x03 | (0x10 if pf else 0)


SNRM, UA, DISC, XID_CMD, XID_RSP, TEST, UI, SIM, FRMR = 0x80, 0x60, 0x40, 0x2c, 0xac, 0xe0, 0x00, 0x04, 0x84


def lap(cid, ctl, payload=b''):
    return bytes([cid, ctl]) + payload


def lmp_data(dlsap, slsap, payload=b''):
    return bytes([dlsap & 0x7f, slsap & 0x7f]) + payload


def lmp_ctl(dlsap, slsap, opcode, extra=b''):
    return bytes([0x80 | dlsap, slsap, opcode]) + extra


CONNECT_CMD, CONNECT_CNF, DISCONNECT, ACCESSMODE_CMD, ACCESSMODE_CNF = 1, 0x81, 2, 3, 0x83


def param(pi, pv):
    return bytes([pi, len(pv)]) + pv


def negotiation():
    return (param(0x01, b'\x3f') + param(0x82, b'\x0f') + param(0x83, b'\x3f')
            + param(0x84, b'\x7f') + param(0x85, b'\xff') + param(0x86, b'\xff')
            + param(0x08, b'\xff') + param(0x55, b'\x01\x02'))


def xid_info(saddr, daddr, flags, slot, version, hints=b'', charset=None, name=b'', cmd=True):
    b = b'\x01' + struct.pack('<II', saddr, daddr) + bytes([flags, slot, version])
    b += hints
    if charset is not None:
        b += bytes([charset]) + name
    return b


# IAS
def ias_req(cls, attr, op=4, flags=0x80):
    c, a = cls.encode(), attr.encode()
    return bytes([flags | op, len(c)]) + c + bytes([len(a)]) + a


def ias_res(op=4, ret=0, entries=(), list_len=None, flags=0x80):
    b = bytes([flags | op, ret])
    if ret == 0 and op == 4:
        b += struct.pack('!H', len(entries) if list_len is None else list_len)
        b += b''.join(entries)
    return b


def e_missing(oid=1):
    return struct.pack('!HB', oid, 0)


def e_int(v, oid=1):
    return struct.pack('!HBI', oid, 1, v)


def e_seq(data, oid=1):
    return struct.pack('!HBH', oid, 2, len(data)) + data


def e_str(s, charset=0, oid=1):
    b = s.encode()
    return struct.pack('!HBBB', oid, 3, charset, len(b)) + b


def ircomm_params():
    return (param(0x00, b'\x0f') + param(0x01, b'\x03') + param(0x02, b'COM1')
            + param(0x00, b'\x00') + param(0x01, b'\x00') + param(0x77, b'\x01\x02\x03'))


# ------------------------------------------------------------ SIR
def crc16(d):
    crc = 0xffff
    for b in d:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return (~crc) & 0xffff


def sir_frame(lapdata, preamble=b'', bad=False, escape=True):
    fcs = crc16(lapdata) ^ (0x1234 if bad else 0)
    body = lapdata + struct.pack('<H', fcs)
    if escape:
        esc = b''
        for c in body:
            if c in (0xc0, 0xc1, 0x7d):
                esc += bytes([0x7d, c ^ 0x20])
            else:
                esc += bytes([c])
        body = esc
    return preamble + b'\xc0' + body + b'\xc1'


def expdu(name, payload):
    n = name.encode()
    return (struct.pack('!HH', 12, (len(n) + 3) & ~3) + n + b'\0' * ((-len(n)) % 4)
            + struct.pack('!HH', 0, 0) + payload)


# ------------------------------------------------------------ main capture
MARKS = []


def build_main(pc):
    def irda(pkt, data):
        pc.add(LT_IRDA, irda_rec(pkt, data))

    def mark(name):
        MARKS.append((name, len(pc.blocks) + 1))

    C, R = circuit(1, True), circuit(1, False)           # 0x03 command, 0x02 response

    mark('log messages')
    irda(LOG, b'IrDA: irlap_connect_indication()\n')
    irda(LOG, b'IrDA: second to last newline\nx')
    irda(LOG, b'IrDA: no newline at all')
    irda(LOG, b'\n')
    irda(MISSED, b'')

    mark('IrLAP discovery (XID)')
    bc = circuit(0x7f, True)                              # 0xff broadcast, command
    bcr = circuit(0x7f, False)
    irda(OUT, lap(bc, u_ctl(XID_CMD), xid_info(0x11223344, 0xffffffff, 0x01, 0, 0)))
    irda(OUT, lap(bc, u_ctl(XID_CMD), xid_info(0x11223344, 0xffffffff, 0x03, 5, 0)))
    irda(OUT, lap(bc, u_ctl(XID_CMD), xid_info(0x11223344, 0xffffffff, 0x04, 0xff, 0,
                                               b'\x04\x20', 0, b'Laptop')))
    hints_all = b'\xff\xff\x00'                           # three octets of hints
    irda(IN, lap(bcr, u_ctl(XID_RSP), xid_info(0x55667788, 0x11223344, 0x00, 0, 0,
                                               b'\xff\xff\x00', 1, b'Phone \xe4')))
    irda(IN, lap(bcr, u_ctl(XID_RSP), xid_info(0x55667788, 0x11223344, 0, 0, 0,
                                               b'\xff\x07', 0, b'Everything')))
    irda(IN, lap(bcr, u_ctl(XID_RSP), xid_info(0x55667788, 0x11223344, 0, 0, 0,
                                               b'\x00', 0, b'')))              # hints, no name
    irda(IN, lap(bcr, u_ctl(XID_RSP), xid_info(0x55667788, 0x11223344, 0, 0, 0)))  # no info
    irda(IN, lap(bcr, u_ctl(XID_RSP), xid_info(0x55667788, 0x11223344, 0, 0, 0,
                                               b'\x04', 0)))                   # charset, no name
    for cs, nm in ((2, b'Caf\xe9'), (3, b'\xa1x'), (4, b'\xa1x'), (5, b'\xb0x'), (6, b'\xc1x'),
                   (7, b'\xc1x'), (8, b'\xe0x'), (9, b'\xd0x'),
                   (0xff, 'Unicodé'.encode('utf-16-be')), (0x42, b'unknown')):
        irda(IN, lap(bcr, u_ctl(XID_RSP), xid_info(0x55667788, 0x11223344, 0, 0, 0,
                                                   b'\x04', cs, nm)))

    mark('IrLAP connection setup, U and S frames')
    irda(OUT, lap(C, u_ctl(SNRM), struct.pack('<II', 0x11223344, 0x55667788) + bytes([0x02 << 1])
                  + negotiation()))
    irda(OUT, lap(C, u_ctl(SNRM), struct.pack('<II', 0x11223344, 0x55667788) + bytes([0x02])
                  + param(0x01, b'\xff\x01') + param(0x82, b'\x00') + param(0x83, b'\x00')
                  + param(0x84, b'\x00') + param(0x85, b'\x00') + param(0x86, b'\x00')
                  + param(0x08, b'\x00')))
    irda(OUT, lap(C, u_ctl(SNRM), struct.pack('<II', 0x11223344, 0x55667788) + bytes([0x02])
                  + b''.join(param(0x70 + (i % 8), b'\x01') for i in range(40))))   # > 32 params
    irda(IN, lap(R, u_ctl(SNRM), struct.pack('<II', 0x55667788, 0x11223344) + bytes([0x02])
                 + negotiation()))                       # SNRM response form
    irda(IN, lap(R, u_ctl(UA), struct.pack('<II', 0x55667788, 0x11223344) + negotiation()))
    irda(IN, lap(R, u_ctl(UA)))
    irda(OUT, lap(C, u_ctl(DISC)))
    irda(IN, lap(R, u_ctl(0x40)))                         # RD
    irda(OUT, lap(C, u_ctl(TEST), b'test data'))
    irda(OUT, lap(C, u_ctl(UI), b'ui data'))
    irda(OUT, lap(C, u_ctl(SIM)))
    irda(OUT, lap(C, u_ctl(FRMR), b'\x01\x02\x03'))
    irda(OUT, lap(C, u_ctl(0x0c)))                        # SARM / DM
    for kind in range(4):
        irda(OUT, lap(C, s_ctl(kind, 3, 1)))
        irda(IN, lap(R, s_ctl(kind, 2, 0)))

    irda(OUT, lap(circuit(0, True), u_ctl(UA)))                    # NULL address
    irda(IN, lap(circuit(0, False), u_ctl(UA)))
    irda(IN, lap(circuit(0x7f, False), u_ctl(UA)))                 # broadcast

    mark('IrLMP')
    lmp = lambda cid, ns, nr, payload: irda(OUT if cid & 1 else IN, lap(cid, i_ctl(ns, nr), payload))
    lmp(C, 0, 0, lmp_ctl(0x10, 0x11, CONNECT_CMD, b'\x00'))
    lmp(R, 0, 1, lmp_ctl(0x11, 0x10, CONNECT_CNF, b'\x00'))
    lmp(C, 1, 1, lmp_ctl(0x10, 0x11, CONNECT_CMD))                 # no reserved octet
    lmp(R, 1, 2, lmp_ctl(0x11, 0x10, CONNECT_CNF))
    lmp(C, 2, 2, lmp_ctl(0x10, 0x11, ACCESSMODE_CMD, b'\x00\x01'))
    lmp(R, 2, 3, lmp_ctl(0x11, 0x10, ACCESSMODE_CNF, b'\x00\x01'))
    lmp(C, 3, 3, lmp_ctl(0x10, 0x11, ACCESSMODE_CMD, b'\x00\x00'))
    lmp(R, 3, 4, lmp_ctl(0x11, 0x10, ACCESSMODE_CNF, b'\x01\x00'))
    lmp(C, 4, 4, lmp_ctl(0x10, 0x11, DISCONNECT, b'\x01'))
    lmp(R, 4, 5, lmp_ctl(0x11, 0x10, DISCONNECT, b'\x05'))
    lmp(C, 5, 5, lmp_ctl(0x10, 0x11, 0x55))                        # unknown opcode
    lmp(C, 6, 5, lmp_ctl(0x00, 0x10, CONNECT_CMD, b'\x00'))        # to the IAS
    lmp(R, 5, 7, lmp_ctl(0x10, 0x00, CONNECT_CNF, b'\x00'))
    lmp(C, 7, 5, lmp_data(0x30, 0x31, b'no conversation, plain data'))
    lmp(C, 0, 0, lmp_data(0x70, 0x70, b'connectionless'))

    mark('IAP')
    # a query for a class without attribute dissectors and a string result
    lmp(C, 0, 0, lmp_data(0x00, 0x10, ias_req('Device', 'DeviceName')))
    lmp(R, 0, 1, lmp_data(0x10, 0x00, ias_res(entries=[e_str('Phone')])))
    # IrCOMM Parameters, octet sequence with every parameter, then wrong type
    lmp(C, 1, 1, lmp_data(0x00, 0x10, ias_req('IrDA:IrCOMM', 'Parameters')))
    lmp(R, 1, 2, lmp_data(0x10, 0x00, ias_res(entries=[e_seq(ircomm_params())])))
    lmp(C, 2, 2, lmp_data(0x00, 0x10, ias_req('IrDA:IrCOMM', 'Parameters')))
    lmp(R, 2, 3, lmp_data(0x10, 0x00, ias_res(entries=[e_int(5)])))               # not an octet seq
    # TinyTP LsapSel: IrCOMM cooked on LSAP 0x15
    lmp(C, 3, 3, lmp_data(0x00, 0x10, ias_req('IrDA:IrCOMM', 'IrDA:TinyTP:LsapSel')))
    lmp(R, 3, 4, lmp_data(0x10, 0x00, ias_res(entries=[e_int(0x15)])))
    # LMP connect to it with a TTP parameter octet, data with and without more bit,
    # data after the disconnect
    lmp(C, 4, 4, lmp_ctl(0x15, 0x12, CONNECT_CMD, b'\x00' + b'\x80\x00'))
    lmp(R, 4, 5, lmp_ctl(0x12, 0x15, CONNECT_CNF, b'\x00' + b'\x05'))
    lmp(C, 5, 5, lmp_data(0x15, 0x12, b'\x0a' + b'\x03\x01\x02\x03' + b'user data'))
    lmp(R, 5, 6, lmp_data(0x12, 0x15, b'\x80' + b'\x00' + b'more data'))
    lmp(C, 6, 6, lmp_data(0x15, 0x12, b'\x00' + b'\x00'))                           # control only
    lmp(C, 7, 6, lmp_ctl(0x15, 0x12, DISCONNECT, b'\x01'))
    # IrLPT LsapSel (both spellings): raw IrCOMM on LSAP 0x20 and 0x21
    lmp(C, 0, 7, lmp_data(0x00, 0x10, ias_req('IrLPT', 'IrDA:IrLMP:LsapSel')))
    lmp(R, 6, 1, lmp_data(0x10, 0x00, ias_res(entries=[e_int(0x20)])))
    lmp(C, 1, 7, lmp_data(0x20, 0x11, b'hello'))
    lmp(R, 7, 2, lmp_data(0x11, 0x20, b'x'))
    lmp(R, 0, 2, lmp_ctl(0x11, 0x20, CONNECT_CNF, b'\x00' + b'raw connect payload'))
    lmp(C, 2, 1, lmp_data(0x00, 0x10, ias_req('IrLPT', 'IrDA:IrLMP:LSAPSel')))
    lmp(R, 1, 3, lmp_data(0x10, 0x00, ias_res(entries=[e_int(0x21)])))
    lmp(C, 3, 1, lmp_data(0x21, 0x11, b'again'))
    # the same LSAP announced again (second conversation entry), then data
    lmp(C, 2, 1, lmp_data(0x00, 0x10, ias_req('IrLPT', 'IrDA:IrLMP:LsapSel')))
    lmp(R, 1, 3, lmp_data(0x10, 0x00, ias_res(entries=[e_int(0x20)])))
    lmp(C, 3, 1, lmp_data(0x20, 0x11, b'third announcement'))
    lmp(C, 2, 1, lmp_data(0x00, 0x10, ias_req('IrLPT', 'IrDA:IrLMP:LsapSel')))
    lmp(R, 1, 3, lmp_data(0x10, 0x00, ias_res(entries=[e_int(0x20)])))
    lmp(R, 3, 3, lmp_data(0x11, 0x20, b'fourth announcement'))
    lmp(C, 3, 1, lmp_data(0x20, 0x11, b'and data'))
    # invalid LSAP values: 0, 0x70-ish out of range, and a string
    for ent in (e_int(0), e_int(0x80), e_str('x'), e_missing()):
        lmp(C, 4, 1, lmp_data(0x00, 0x10, ias_req('IrLPT', 'IrDA:IrLMP:LsapSel')))
        lmp(R, 2, 5, lmp_data(0x10, 0x00, ias_res(entries=[ent])))
    for ent in (e_int(0), e_str('x')):
        lmp(C, 4, 1, lmp_data(0x00, 0x10, ias_req('IrDA:IrCOMM', 'IrDA:TinyTP:LsapSel')))
        lmp(R, 2, 5, lmp_data(0x10, 0x00, ias_res(entries=[ent])))
    # an empty string value and an attribute of an unknown type
    lmp(C, 4, 1, lmp_data(0x00, 0x10, ias_req('IrLPT', 'IrDA:IrLMP:LsapSel')))
    lmp(R, 2, 5, lmp_data(0x10, 0x00, ias_res(entries=[e_str('')])))
    lmp(R, 2, 5, lmp_data(0x10, 0x00, ias_res(entries=[struct.pack('!HB', 1, 9) + b'\0\0'])))
    # empty IAP requests and results
    lmp(C, 4, 1, lmp_data(0x00, 0x10, b''))
    lmp(R, 2, 5, lmp_data(0x10, 0x00, b''))
    # return codes and result shapes
    lmp(C, 5, 1, lmp_data(0x00, 0x10, ias_req('NoSuchClass', 'x')))
    lmp(R, 3, 6, lmp_data(0x10, 0x00, ias_res(ret=1)))
    lmp(C, 6, 1, lmp_data(0x00, 0x10, ias_req('Device', 'NoSuchAttr')))
    lmp(R, 4, 7, lmp_data(0x10, 0x00, ias_res(ret=2)))
    for ret in (3, 10, 0xff, 0x44):
        lmp(R, 4, 7, lmp_data(0x10, 0x00, ias_res(ret=ret)))
    lmp(C, 7, 1, lmp_data(0x00, 0x10, ias_req('Device', 'Many')))
    lmp(R, 5, 0, lmp_data(0x10, 0x00, ias_res(entries=[e_int(7, 1), e_seq(b'\x01\x02\x03', 2),
                                                      e_str('abc', 1, 3), e_missing(4)])))
    lmp(R, 6, 0, lmp_data(0x10, 0x00, ias_res(entries=[e_missing()])))
    lmp(R, 6, 0, lmp_data(0x10, 0x00, ias_res(entries=[e_seq(b'\xaa\xbb')])))
    lmp(R, 6, 0, lmp_data(0x10, 0x00, ias_res(entries=[e_str('', 0xff)])))
    lmp(R, 6, 0, lmp_data(0x10, 0x00, ias_res(entries=[e_int(1, i) for i in range(1, 41)])))
    lmp(R, 6, 0, lmp_data(0x10, 0x00, ias_res(entries=[e_int(1)]) + b'trailing'))
    # other IAP operations (no decoder): request and result as data
    lmp(C, 0, 0, lmp_data(0x00, 0x10, bytes([0x81, 0x01, 0x02])))
    lmp(R, 0, 1, lmp_data(0x10, 0x00, bytes([0x82, 0x00, 0x00, 0x01])))
    lmp(C, 0, 0, lmp_data(0x00, 0x10, bytes([0x41, 0x05])))          # ack bit
    # a 70 octet class name (capped at 60)
    lmp(C, 1, 0, lmp_data(0x00, 0x10, ias_req('C' * 60, 'A' * 40)))
    # a query, a second query that replaces it for the results that follow
    lmp(C, 2, 0, lmp_data(0x00, 0x10, ias_req('Device', 'DeviceName')))
    lmp(C, 3, 0, lmp_data(0x00, 0x11, ias_req('IrLPT', 'IrDA:IrLMP:LsapSel')))
    lmp(R, 1, 5, lmp_data(0x11, 0x00, ias_res(entries=[e_int(0x22)])))
    lmp(R, 2, 5, lmp_data(0x11, 0x00, ias_res(entries=[e_str('two')])))
    lmp(C, 1, 0, lmp_data(0x22, 0x13, b'on lsap 0x22'))
    lmp(C, 4, 0, lmp_data(0x00, 0x11, ias_req('IrDA:IrCOMM', 'Parameters')))
    lmp(R, 3, 5, lmp_data(0x11, 0x00, ias_res(entries=[e_seq(param(0x00, b'\x02'))])))
    # reproducer of the one pass / two pass difference: list length 0 with an entry
    lmp(C, 5, 1, lmp_data(0x00, 0x14, ias_req('IrLPT', 'IrDA:IrLMP:LsapSel')))
    lmp(R, 7, 5, lmp_data(0x14, 0x00, ias_res(entries=[e_int(0x23)], list_len=0)))
    lmp(C, 6, 1, lmp_data(0x23, 0x15, b'after the empty list'))

    mark('IrCOMM, SIR and IrDA through Exported PDU, SLL and TCP')
    pc.add(LT_EXPDU, expdu('ircomm_raw', b'x'))
    pc.add(LT_EXPDU, expdu('ircomm_raw', b'raw user data'))
    pc.add(LT_EXPDU, expdu('ircomm_cooked', bytes([0]) + b'user data only'))
    pc.add(LT_EXPDU, expdu('ircomm_cooked', bytes([3]) + b'\x01\x02\x03' + b'u'))
    pc.add(LT_EXPDU, expdu('ircomm_cooked', bytes([3]) + b'\x01\x02\x03'))
    pc.add(LT_EXPDU, expdu('ircomm_cooked', bytes([0])))
    pc.add(LT_EXPDU, expdu('ircomm_cooked', b''))
    pc.add(LT_EXPDU, expdu('ircomm_raw', b''))
    lapdata = lap(C, i_ctl(0, 0), lmp_data(0x30, 0x31, b'hello'))
    pc.add(LT_EXPDU, expdu('irda', lapdata))
    pc.add(LT_EXPDU, expdu('sir', sir_frame(lapdata)))
    sll = struct.pack('!HHH8sH', 0, 0x30b, 6, b'\x02\0\0\0\0\x01\0\0', 0x17) + lapdata
    pc.add(LT_SLL, sll)
    pc.add(LT_SLL, struct.pack('!HHH8sH', 4, 0x30b, 6, b'\x02\0\0\0\0\x01\0\0', 0x17)
           + lap(bc, u_ctl(XID_CMD), xid_info(1, 2, 0, 0, 0, b'\x04', 0, b'sll')))

    st = Stream(40000, 6417)
    st.handshake()
    f = sir_frame(lapdata)
    st.send(True, f)                                                   # plain
    st.send(True, sir_frame(lapdata, preamble=b'\xff\xff\xff'))        # preamble
    st.send(True, sir_frame(lap(C, i_ctl(1, 0), lmp_data(0x30, 0x31, bytes([0xc0, 0xc1, 0x7d, 0x20])))))
    st.send(True, sir_frame(lapdata, escape=False) + sir_frame(lap(C, s_ctl(0, 1, 1))))   # two frames
    st.send(False, sir_frame(lap(R, u_ctl(UA))))
    pdu = sir_frame(lap(C, i_ctl(2, 0), lmp_data(0x30, 0x31, b'a SIR frame split over segments')))
    st.send(True, pdu[:7])
    st.send(True, pdu[7:])
    pdu = sir_frame(lap(C, i_ctl(3, 0), lmp_data(0x30, 0x31, b'the preamble is split too')),
                    preamble=b'\xff\xff')
    st.send(True, pdu[:1])
    st.send(True, pdu[1:])
    st.send(True, b'\xc0' + lap(C, s_ctl(1, 1, 0)) + struct.pack('<H', crc16(lap(C, s_ctl(1, 1, 0)))))
    st.send(True, b'\xc1' + sir_frame(lap(C, s_ctl(2, 1, 0))))          # EOF, then a whole frame
    for fr in st.out:
        pc.add(LT_ETHERNET, fr)
    return st


def build_malformed(pc):
    C, R = circuit(1, True), circuit(1, False)
    bc = circuit(0x7f, True)
    # IrLAP: control octet missing, XID cut short at every field
    pc.add(LT_IRDA, irda_rec(OUT, bytes([C])))
    pc.add(LT_IRDA, irda_rec(OUT, b''))
    xid = lap(bc, u_ctl(XID_CMD), xid_info(1, 2, 0, 0, 0, b'\x04', 0, b'name'))
    for cut in (3, 6, 10, 12, 14, 16, 18):
        pc.add(LT_IRDA, irda_rec(OUT, xid[:cut]))
    # service hints without a named bit set: the hints string is not
    # terminated (packet-irda.c, dissect_xid; stack over-read)
    pc.add(LT_IRDA, irda_rec(IN, lap(circuit(0x7f, False), u_ctl(XID_RSP),
           xid_info(0x55667788, 0x11223344, 0, 0, 0, b'\x80\x00', 0, b'x'))))
    pc.add(LT_IRDA, irda_rec(IN, lap(circuit(0x7f, False), u_ctl(XID_RSP),
           xid_info(0x55667788, 0x11223344, 0, 0, 0, b'\x80\x08', 0, b'y'))))
    # hints with the extension bit set to the end of the packet
    pc.add(LT_IRDA, irda_rec(OUT, lap(bc, u_ctl(XID_CMD), xid_info(1, 2, 0, 0, 0, b'\xff\xff'))))
    # SNRM / UA cut inside the addresses and a parameter that is too long
    snrm = lap(C, u_ctl(SNRM), struct.pack('<II', 1, 2) + b'\x04' + negotiation())
    for cut in (4, 9, 11, 13, len(snrm) - 1):
        pc.add(LT_IRDA, irda_rec(OUT, snrm[:cut]))
    pc.add(LT_IRDA, irda_rec(IN, lap(R, u_ctl(UA), struct.pack('<II', 1, 2) + b'\x01\x20\x01')))
    pc.add(LT_IRDA, irda_rec(IN, lap(R, u_ctl(UA), b'\x01\x02')))
    # IrLMP / IAP cut short
    for pl in (b'', b'\x10', b'\x90\x11', b'\x90\x11\x01', b'\x90\x11\x03\x00'):
        pc.add(LT_IRDA, irda_rec(OUT, lap(C, i_ctl(0, 0), pl)))
    pc.add(LT_IRDA, irda_rec(OUT, lap(C, i_ctl(0, 0), lmp_data(0x00, 0x10, bytes([0x84, 5, 65])))))
    pc.add(LT_IRDA, irda_rec(OUT, lap(C, i_ctl(0, 0), lmp_data(0x00, 0x10, bytes([0x84, 1, 65, 9, 66])))))
    for pl in (bytes([0x84, 0]), bytes([0x84, 0, 0, 1]), bytes([0x84, 0, 0, 1, 0, 1, 1, 0, 0]),
               bytes([0x84, 0, 0, 1, 0, 1, 2, 0, 9, 1]), bytes([0x84, 0, 0, 1, 0, 1, 3, 0, 9, 1])):
        pc.add(LT_IRDA, irda_rec(IN, lap(R, i_ctl(0, 0), lmp_data(0x10, 0x00, pl))))
    # an IAP result with an attribute length that wraps (0xfffe): small fix 2
    pc.add(LT_IRDA, irda_rec(IN, lap(R, i_ctl(0, 0), lmp_data(0x10, 0x00,
           bytes([0x84, 0, 0, 1, 0, 1, 2, 0xff, 0xfe, 1, 2])))))
    # IrCOMM
    pc.add(LT_EXPDU, expdu('ircomm_cooked', bytes([20, 1, 2])))
    pc.add(LT_EXPDU, expdu('ircomm_cooked', bytes([255])))
    # a TTP/IrCOMM conversation whose data is too short
    pc.add(LT_IRDA, irda_rec(OUT, lap(C, i_ctl(0, 0), lmp_data(0x00, 0x10, ias_req('IrDA:IrCOMM', 'IrDA:TinyTP:LsapSel')))))
    pc.add(LT_IRDA, irda_rec(IN, lap(R, i_ctl(0, 0), lmp_data(0x10, 0x00, ias_res(entries=[e_int(0x16)])))))
    pc.add(LT_IRDA, irda_rec(OUT, lap(C, i_ctl(0, 0), lmp_data(0x16, 0x12, b'\x00\x7f'))))
    pc.add(LT_IRDA, irda_rec(OUT, lap(C, i_ctl(0, 0), lmp_data(0x16, 0x12, b''))))
    # SIR: bad checksum (error expert info), frames of 0 and 1 octets
    pc.add(LT_EXPDU, expdu('sir', sir_frame(lap(C, i_ctl(0, 0), lmp_data(0x30, 0x31, b'bad fcs')), bad=True)))
    pc.add(LT_EXPDU, expdu('sir', b'\xc0\xc1'))
    pc.add(LT_EXPDU, expdu('sir', b'\xc0\x01\xc1'))
    pc.add(LT_EXPDU, expdu('sir', b'\xc0\x7d\xc1'))
    pc.add(LT_EXPDU, expdu('sir', b'\xff\xff'))                  # no BOF
    pc.add(LT_EXPDU, expdu('sir', b'\xc0abc'))                   # BOF, no EOF
    # IrDA reached through Exported PDU / SLL with no data
    pc.add(LT_EXPDU, expdu('irda', b''))
    pc.add(LT_SLL, struct.pack('!HHH8sH', 0, 0x30b, 6, b'\x02\0\0\0\0\x01\0\0', 0x17))
    # a log record with a pseudo header and a missed-message record with data
    pc.add(LT_IRDA, irda_rec(MISSED, b'lost'))
    # I1 reproducer variants: the entry of an empty list, with a short value
    pc.add(LT_IRDA, irda_rec(IN, lap(R, i_ctl(0, 0), lmp_data(0x10, 0x00,
           ias_res(entries=[e_int(0x23)], list_len=5)))))


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(outdir, exist_ok=True)
    pc = Pcapng()
    build_main(pc)
    pc.write(os.path.join(outdir, 'irda-coverage.pcapng'))
    for name, first in MARKS:
        print('first frame %4d: %s' % (first, name))
    pm = Pcapng()
    build_malformed(pm)
    pm.write(os.path.join(outdir, 'irda-coverage-malformed.pcapng'))


if __name__ == '__main__':
    main()
