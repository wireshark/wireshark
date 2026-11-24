#!/usr/bin/env python3
# Generates test/captures/uci_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
'''Generate the UCI coverage captures (synthetic).

usage: mkuci.py OUTDIR [-v]

UCI (UWB Command Interface, FiRa) is reached on TCP port 7000 (registered
by default, with a preference for the port) and as the link layer type
FIRA_UCI (LINKTYPE 299), where every packet is one UCI packet. The captures
are pcapng with an Ethernet interface and a FIRA_UCI interface.
Writes uci-coverage.pcapng and uci-coverage-malformed.pcapng.
'''
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))
















from u9lib import Pcapng, Tcp

HOST = [192, 0, 2, 1]
UWBS = [192, 0, 2, 2]
UCI_LT = 299

sections = []

CMD, RSP, NTF = 1, 2, 3


def uci(mt, gid, oid, payload=b'', pbf=0):
    return bytes([(mt << 5) | (pbf << 4) | gid, oid, 0, len(payload)]) + bytes(payload)


def le(n, size):
    return n.to_bytes(size, 'little')


def params(plist):
    '''count + (id, len, value) items'''
    return bytes([len(plist)]) + b''.join(bytes([i, len(v)]) + bytes(v) for i, v in plist)


class Gen:
    def __init__(self):
        self.pc = Pcapng([1, UCI_LT])
        self.tcp = None

    def sec(self, name):
        sections.append([name, len(self.pc) + 1, None])

    def end(self):
        sections[-1][2] = len(self.pc)

    def raw(self, pdu):
        '''A packet of the FIRA_UCI link type'''
        return self.pc.add(pdu, 1)

    def conn(self, port=7000, client=50123):
        self.tcp = Tcp(HOST, UWBS, client, port)
        for f in self.tcp.handshake():
            self.pc.add(f, 0)

    def send(self, d, data, flags=0x18):
        self.pc.add(self.tcp.seg(d, data, flags), 0)

    def close(self):
        for f in self.tcp.close():
            self.pc.add(f, 0)


STATUS = list(range(0x0B)) + list(range(0x11, 0x1A)) + list(range(0x20, 0x28)) + [0x7F, 0xFF]
CAPS = list(range(0x12)) + [0x12, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0x55]
APPCFG = list(range(0x36)) + [0xA0, 0xA1, 0xA3, 0xA4, 0xA5, 0xA6, 0xE3, 0xE4, 0xE5, 0xF0]


def meas(mode, nlos=0, i=0):
    '''one ranging measurement of 31 octets'''
    mac = bytes([0x12, 0x34]) if mode == 0 else bytes(range(0x10, 0x18))
    pad = 12 if mode == 0 else 6
    return (mac + bytes([0, nlos]) + le(150 + i, 2) + le(0xFFF0, 2) + bytes([90]) + le(10, 2) + bytes([80])
            + le(0xFFF1, 2) + bytes([70]) + le(11, 2) + bytes([60]) + bytes([3 + i]) + bytes(pad))


def range_ntf(seq, session, count, mode, mtype=1, interval=200):
    body = (le(seq, 4) + le(session, 4) + bytes([0]) + le(interval, 4) + bytes([mtype, 0, mode])
            + bytes(8) + bytes([count]))
    for i in range(count):
        body += meas(mode, i % 4, i)
    return body


def build_pdus():
    '''(name, pdu) pairs used for the link-layer frames and the TCP streams'''
    P = []
    # Core
    P.append(uci(CMD, 0, 0x00, [0]))
    P.append(uci(RSP, 0, 0x00, [0]))
    for st in (1, 2, 0xFF, 7):
        P.append(uci(NTF, 0, 0x01, [st]))
    P.append(uci(CMD, 0, 0x02))
    ver = lambda a, b, c: le((a & 0xFF) | ((b & 0xF) << 8) | ((c & 0xF) << 12), 2)
    P.append(uci(RSP, 0, 0x02, bytes([0]) + ver(1, 0, 0) + ver(1, 1, 0) + ver(2, 0, 1) + ver(1, 2, 3)
                 + bytes([4]) + b'\x01\x02\x03\x04'))
    P.append(uci(RSP, 0, 0x02, bytes([0]) + ver(1, 0, 0) * 4 + bytes([0])))
    P.append(uci(CMD, 0, 0x03))
    P.append(uci(RSP, 0, 0x03, bytes([0]) + params([(c, bytes([1, 2, 3])[:1 + c % 3]) for c in CAPS[:14]])))
    P.append(uci(RSP, 0, 0x03, bytes([0]) + params([(c, bytes([c])) for c in CAPS[14:]])))
    P.append(uci(RSP, 0, 0x03, bytes([0, 0])))
    P.append(uci(CMD, 0, 0x05, bytes([2, 0, 1])))
    P.append(uci(CMD, 0, 0x05, bytes([0])))
    P.append(uci(RSP, 0, 0x05, bytes([0]) + params([(0, [1]), (1, [0])])))
    P.append(uci(RSP, 0, 0x05, bytes([0]) + params([])))
    P.append(uci(CMD, 0, 0x04, params([(1, [1])])))
    P.append(uci(CMD, 0, 0x04, params([])))
    P.append(uci(RSP, 0, 0x04, bytes([0, 2, 0, 0, 1, 4])))
    P.append(uci(RSP, 0, 0x04, bytes([0, 0])))
    for st in STATUS:
        P.append(uci(NTF, 0, 0x07, [st]))
    # Session config
    sid = 0x11223344
    P.append(uci(CMD, 1, 0x00, le(sid, 4) + bytes([0])))
    P.append(uci(CMD, 1, 0x00, le(sid + 1, 4) + bytes([1])))
    P.append(uci(CMD, 1, 0x00, le(sid + 2, 4) + bytes([0xA0])))
    P.append(uci(RSP, 1, 0x00, [0]))
    P.append(uci(CMD, 1, 0x01, le(sid, 4)))
    P.append(uci(RSP, 1, 0x01, [0x11]))
    for stt in range(4):
        P.append(uci(NTF, 1, 0x02, le(sid, 4) + bytes([stt, 0])))
    P.append(uci(CMD, 1, 0x03, le(sid, 4) + params([(i, bytes([i % 7, 1])[:1 + i % 2]) for i in APPCFG[:20]])))
    for k in range(20, len(APPCFG), 18):
        P.append(uci(CMD, 1, 0x03, le(sid, 4) + params([(i, b'\x01\x02\x03\x04\x05\x06') for i in APPCFG[k:k + 18]])))
    P.append(uci(CMD, 1, 0x03, le(sid, 4) + params([])))
    P.append(uci(RSP, 1, 0x03, bytes([0, 2, 0, 0, 5, 4])))
    P.append(uci(RSP, 1, 0x03, bytes([4, 0])))
    P.append(uci(CMD, 1, 0x04, le(sid, 4) + bytes([3, 0, 1, 0xA3])))
    P.append(uci(CMD, 1, 0x04, le(sid, 4) + bytes([0])))
    P.append(uci(RSP, 1, 0x04, bytes([0]) + params([(0, [1]), (8, le(2400, 2)), (0xA3, [1, 2, 3])])))
    P.append(uci(RSP, 1, 0x04, bytes([0]) + params([])))
    P.append(uci(CMD, 1, 0x05))
    P.append(uci(RSP, 1, 0x05, bytes([0, 3])))
    P.append(uci(CMD, 1, 0x06, le(sid, 4)))
    P.append(uci(RSP, 1, 0x06, bytes([0, 2])))
    for action in (0, 1):
        P.append(uci(CMD, 1, 0x07, le(sid, 4) + bytes([action, 2]) + le(0x0101, 2) + le(7, 4) + le(0x0202, 2) + le(8, 4)))
    P.append(uci(CMD, 1, 0x07, le(sid, 4) + bytes([0, 0])))
    P.append(uci(RSP, 1, 0x07, [0]))
    P.append(uci(NTF, 1, 0x07, le(sid, 4) + bytes([6, 2]) + le(0x0101, 2) + le(7, 4) + bytes([0])
                 + le(0x0202, 2) + le(8, 4) + bytes([0x17])))
    P.append(uci(NTF, 1, 0x07, le(sid, 4) + bytes([6, 0])))
    # Ranging session control
    P.append(uci(CMD, 2, 0x00, le(sid, 4)))
    P.append(uci(RSP, 2, 0x00, [0]))
    P.append(uci(NTF, 2, 0x00, range_ntf(1, sid, 1, 0)))
    P.append(uci(NTF, 2, 0x00, range_ntf(2, sid, 2, 1, mtype=2)))
    P.append(uci(NTF, 2, 0x00, range_ntf(3, sid, 0, 0)))
    P.append(uci(NTF, 2, 0x00, range_ntf(4, sid, 7, 0)))
    P.append(uci(CMD, 2, 0x01, le(sid, 4)))
    P.append(uci(RSP, 2, 0x01, [0]))
    P.append(uci(CMD, 2, 0x03, le(sid, 4)))
    P.append(uci(RSP, 2, 0x03, bytes([0]) + le(12345, 4)))
    # Unknown opcodes, data control, test and vendor groups (and message types 0, 4-7)
    for gid in (0, 1, 2, 3, 0x0D, 4, 5, 6, 7, 8, 9, 0x0A, 0x0B, 0x0C, 0x0E, 0x0F):
        for mt in (CMD, RSP, NTF):
            P.append(uci(mt, gid, 0x3E, [1, 2]))
    for gid in (0, 1, 2):
        P.append(uci(0, gid, 0x3E))
        P.append(uci(4, gid, 0x3E))
    P.append(uci(7, 0x0E, 0x01, [9]))
    # packet boundary flag set, reserved bits in the opcode octet
    P.append(uci(CMD, 0, 0x02, pbf=1))
    P.append(bytes([0x20, 0xC2, 0x55, 0]))
    return P


def build_main(g):
    P = build_pdus()
    g.sec('FIRA_UCI link type: every message, one UCI packet per frame')
    for p in P:
        g.raw(p)
    g.end()

    g.sec('TCP port 7000: handshake, several PDUs in a segment, PDUs split over segments')
    g.conn()
    g.send(0, uci(CMD, 0, 0x02))
    g.send(1, uci(RSP, 0, 0x02, bytes([0]) + bytes(8) + bytes([0])))
    g.send(0, uci(CMD, 0, 0x00, [0]) + uci(CMD, 1, 0x05) + uci(CMD, 0, 0x03))
    g.send(1, uci(RSP, 0, 0x00, [0]) + uci(RSP, 1, 0x05, bytes([0, 3])))
    cmd = uci(CMD, 1, 0x00, le(0x55, 4) + bytes([0]))
    g.send(0, cmd[:2])                                  # header split
    g.send(0, cmd[2:])
    ntf = uci(NTF, 2, 0x00, range_ntf(9, 0x55, 3, 0))
    g.send(1, ntf[:20])                                 # payload split
    g.send(1, ntf[20:50])
    g.send(1, ntf[50:] + uci(NTF, 0, 0x01, [1]))        # end of one PDU and a whole PDU
    g.send(0, uci(CMD, 2, 0x00, le(0x55, 4)))
    g.send(1, uci(RSP, 2, 0x00, [0]))
    g.close()
    g.end()

    g.sec('TCP port 7001: UCI only with the preference uci.tcp.port:7001')
    g.conn(port=7001, client=50124)
    g.send(0, uci(CMD, 0, 0x02))
    g.send(1, uci(RSP, 0, 0x00, [0]))
    g.close()
    g.end()


def build_malformed(g):
    g.sec('Truncated packets (link type FIRA_UCI)')
    g.raw(bytes([0x20, 0x00]))                                  # header cut short
    g.raw(bytes([0x20, 0x00, 0, 5, 0]))                         # payload shorter than the length
    g.raw(bytes([0x40, 0x02, 0, 9, 0]))                         # Core Get Device Info Rsp, short
    g.raw(uci(RSP, 0, 0x02, bytes([0, 1, 2, 3])))
    g.raw(uci(RSP, 0, 0x02, bytes([0]) + bytes(8) + bytes([5, 1])))   # vendor info longer than the packet
    g.raw(uci(RSP, 0, 0x03, bytes([0, 2, 0, 3, 1])))            # capability parameter longer than the packet
    g.raw(uci(RSP, 0, 0x03, bytes([0, 5])))                     # count without parameters
    g.raw(uci(CMD, 0, 0x05, bytes([3, 0])))
    g.raw(uci(RSP, 0, 0x05, bytes([0, 2, 0, 1])))
    g.raw(uci(RSP, 0, 0x04, bytes([0, 2, 0])))
    g.raw(uci(CMD, 1, 0x00, bytes([1, 2])))
    g.raw(uci(CMD, 1, 0x03, le(1, 4) + bytes([2, 0, 9, 1])))
    g.raw(uci(RSP, 1, 0x03, bytes([0, 3, 0, 0])))
    g.raw(uci(RSP, 1, 0x04, bytes([0, 2, 0, 8, 2])))
    g.raw(uci(CMD, 1, 0x07, le(1, 4) + bytes([0, 2]) + le(1, 2)))
    g.raw(uci(NTF, 1, 0x07, le(1, 4) + bytes([6, 2, 1, 2, 3])))
    g.raw(uci(NTF, 2, 0x00, range_ntf(1, 1, 2, 0)[:-31]))      # fewer measurements than the count
    g.raw(uci(NTF, 2, 0x00, range_ntf(1, 1, 1, 0)[:30]))
    g.raw(uci(NTF, 2, 0x00, range_ntf(1, 1, 1, 1)[:-5]))
    g.raw(uci(RSP, 2, 0x03, bytes([0, 1])))
    g.end()
    g.sec('TCP: PDU never completed, stray octets')
    g.conn(client=50130)
    g.send(0, uci(CMD, 0, 0x00, [0])[:3])
    g.send(0, b'\x01', 0x11)
    g.end()


def main():
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    g = Gen()
    build_main(g)
    g.pc.write(os.path.join(out, 'uci-coverage.pcapng'))
    if verbose:
        print('main: %d frames' % len(g.pc))
        for n, a, b in sections:
            print('  %4d-%4d %s' % (a, b, n))
    del sections[:]
    m = Gen()
    build_malformed(m)
    m.pc.write(os.path.join(out, 'uci-coverage-malformed.pcapng'))
    if verbose:
        print('malformed: %d frames' % len(m.pc))
        for n, a, b in sections:
            print('  %4d-%4d %s' % (a, b, n))


if __name__ == '__main__':
    main()
