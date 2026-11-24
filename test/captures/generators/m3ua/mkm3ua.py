#!/usr/bin/env python3
# Generates test/captures/m3ua_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic M3UA coverage captures.

Usage: mkm3ua.py <outdir>

M3UA (RFC 4666) over SCTP port 2905 / PPID 3, and over TCP port 2905.
Frames 1-S (see the printed ranges) are RFC 4666 messages that decode
cleanly at the default version. They are followed by TCP frames (framing:
two PDUs in one segment, a PDU split over two segments) and by messages
in the draft 5, 6 and 7 formats, which are dissected with
-o m3ua.version:draft-5 / draft-6 / draft-7. The last frames are the
reproducer of the nesting depth check (a Routing Key nested 30 levels).
Nothing comes from a real network.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from sslib import Sctp, Tcp, write_pcap, mtp3_sltm  # noqa: E402

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
PORT, PPID = 2905, 3


def param(tag, value=b''):
    p = struct.pack('!HH', tag, 4 + len(value)) + value
    return p + b'\0' * ((-len(p)) % 4)


def msg(cls, typ, params=b'', ver=1):
    return struct.pack('!BBBBI', ver, 0, cls, typ, 8 + len(params)) + params


def u32(v):
    return struct.pack('!I', v)


def pc(mask, code):
    return bytes([mask]) + struct.pack('!I', code)[1:]


# a valid SCCP UDT (class 0, called and calling SSN 1, an SCCP management SSA message as data)
UDT = bytes.fromhex('0900030507 024201 024201 05 0106010000'.replace(' ', ''))
# the same with point codes in the addresses is not needed; ANSI-like UDT
UDT_ANSI = bytes.fromhex('0900030a0f 0543c0c0c008 0543c1c1c106 03aabbcc'.replace(' ', ''))


def pdata(opc, dpc, si, ni, mp, sls, payload):
    return struct.pack('!IIBBBB', opc, dpc, si, ni, mp, sls) + payload


class V:
    """Parameter tags of one version."""

    def __init__(self, **tags):
        self.__dict__.update(tags)


RFC = V(info=0x0004, rc=0x0006, diag=0x0007, hb=0x0009, tmt=0x000b, err=0x000c, status=0x000d,
        aspid=0x0011, apc=0x0012, corr=0x0013, na=0x0200, cause=0x0204, cong=0x0205,
        concerned=0x0206, rk=0x0207, regres=0x0208, deregres=0x0209, lrk=0x020a, dpc=0x020b,
        si=0x020c, opc=0x020e, circ=0x020f, pdata=0x0210, regst=0x0212, deregst=0x0213)


def main():
    s = Sctp(PORT, PPID, cport=2905)
    frames, ranges = [], []

    def add(payload, rev=False, sess=None):
        frames.append((sess or s).frame(payload, rev))

    def mark(name, start):
        ranges.append((name, start + 1, len(frames)))

    T = RFC
    # ---- MGMT
    st = len(frames)
    for i, code in enumerate([1, 3, 4, 5, 6, 7, 9, 0x0d, 0x0e, 0x0f, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                              0x19, 0x1a, 2, 0x99]):
        add(msg(0, 0, param(T.err, u32(code)) + param(T.rc, u32(i)) + param(T.diag, b'\x01\x02\x03\x04\x05')), i % 2)
    add(msg(0, 0, param(T.err, u32(7)) + param(T.apc, pc(0, 5) + pc(1, 6))), True)
    add(msg(0, 0, param(T.err, u32(0x14)) + param(T.diag, b'')))
    for typ, info in [(1, 1), (1, 2), (1, 3), (1, 4), (1, 9), (2, 1), (2, 2), (2, 3), (2, 7), (7, 1)]:
        add(msg(0, 1, param(T.status, struct.pack('!HH', typ, info)) + param(T.aspid, u32(5)) +
                param(T.rc, u32(1) + u32(2)) + param(T.info, b'status')))
    add(msg(0, 7))
    mark('ERR and NTFY', st)

    # ---- transfer: DATA with every service indicator, standard heuristics
    st = len(frames)
    add(msg(1, 1, param(T.na, u32(1)) + param(T.rc, u32(1)) +
            param(T.pdata, pdata(1, 2, 3, 2, 0, 1, UDT)) + param(T.corr, u32(9))))
    add(msg(1, 1, param(T.rc, u32(1)) + param(T.pdata, pdata(2, 1, 3, 2, 1, 2, UDT))), True)
    add(msg(1, 1, param(T.pdata, pdata(0x1234, 0x0abc, 0, 0, 0, 3, b'\x11\x05'))))
    add(msg(1, 1, param(T.pdata, pdata(5, 6, 1, 3, 0, 4, mtp3_sltm()[5:]))), True)
    add(msg(1, 1, param(T.pdata, pdata(5, 6, 5, 2, 3, 5, b'\x01\x00\x10\x00'))))
    add(msg(1, 1, param(T.pdata, pdata(0x010203, 0x040506, 3, 0, 2, 6, UDT_ANSI))), True)
    add(msg(1, 1, param(T.pdata, pdata(0x00ffffff, 0x00ffff00, 11, 1, 0, 7, b'\x00\x01\x02\x03'))))
    # ni 0 (international): Q.708 analysis of the point codes
    add(msg(1, 1, param(T.pdata, pdata(0x1400 + 0x01, 0x2e00 + 0x02, 3, 0, 0, 0, UDT))))
    mark('DATA with SI 0, 1, 3, 5, 11, network indicators and point codes', st)

    # ---- SSNM
    st = len(frames)
    for typ in (1, 2, 4, 5, 6):                          # DUNA DAVA SCON DUPU DRST
        add(msg(2, typ, param(T.na, u32(2)) + param(T.rc, u32(3)) +
                param(T.apc, pc(0, 100) + pc(8, 200)) + param(T.info, b'ssnm info') +
                param(T.concerned, pc(0, 77)) + param(T.cong, b'\x00\x00\x00\x02') +
                param(T.cause, struct.pack('!HH', 1, 3)) + param(T.aspid, u32(1))), typ % 2 == 0)
    add(msg(2, 3, param(T.rc, u32(3)) + param(T.apc, pc(0, 100)) + param(T.info, b'audit')))   # DAUD
    for cause in range(0, 4):
        for user in (3, 5, 9, 0x0f, 99):
            add(msg(2, 5, param(T.apc, pc(0, 100)) + param(T.cause, struct.pack('!HH', cause, user))), True)
    for lvl in range(0, 5):
        add(msg(2, 4, param(T.apc, pc(0, 100)) + param(T.cong, bytes([0, 0, 0, lvl]))))
    add(msg(2, 9))
    mark('SSNM: DUNA, DAVA, DAUD, SCON, DUPU, DRST and their parameters', st)

    # ---- ASPSM / ASPTM
    st = len(frames)
    add(msg(3, 1, param(T.aspid, u32(1)) + param(T.info, b'M3UA ASP up')))
    add(msg(3, 4, param(T.aspid, u32(1)) + param(T.info, b'')), True)
    add(msg(3, 2, param(T.info, b'going down')))
    add(msg(3, 5), True)
    add(msg(3, 3, param(T.hb, b'beat-0123456789')))
    add(msg(3, 6, param(T.hb, b'beat-0123456789')), True)
    add(msg(3, 3, param(T.hb, b'')))
    add(msg(3, 9))
    for mode in (1, 2, 3, 99):
        add(msg(4, 1, param(T.tmt, u32(mode)) + param(T.rc, u32(1) + u32(2) + u32(3))))
    add(msg(4, 3, param(T.tmt, u32(1)) + param(T.rc, u32(1))), True)
    add(msg(4, 2, param(T.rc, u32(1)) + param(T.info, b'inactive')))
    add(msg(4, 4, param(T.rc, u32(1))), True)
    add(msg(4, 9))
    mark('ASPSM and ASPTM', st)

    # ---- RKM
    st = len(frames)
    rk = (param(T.lrk, u32(1)) + param(T.rc, u32(10)) + param(T.tmt, u32(2)) + param(T.na, u32(1)) +
          param(T.dpc, pc(0, 0x0102)) + param(T.si, b'\x03\x05\x09') +
          param(T.opc, pc(0, 7) + pc(0, 8) + pc(1, 9)) +
          param(T.circ, pc(0, 7) + b'\x00\x01\x00\x1f' + pc(0, 8) + b'\x00\x20\x00\x3f'))
    add(msg(9, 1, param(T.rk, rk)))
    add(msg(9, 1, param(T.rk, rk) + param(T.rk, param(T.lrk, u32(2)) + param(T.dpc, pc(0, 5)))))
    for status in range(0, 14):
        res = param(T.lrk, u32(1)) + param(T.regst, u32(status)) + param(T.rc, u32(10))
        add(msg(9, 2, param(T.regres, res)), True)
    add(msg(9, 2, param(T.regres, res) + param(T.regres, res)), True)
    add(msg(9, 3, param(T.rc, u32(10) + u32(11))))
    for status in range(0, 7):
        dres = param(T.rc, u32(10)) + param(T.deregst, u32(status))
        add(msg(9, 4, param(T.deregres, dres)), True)
    add(msg(9, 4, param(T.deregres, dres) + param(T.deregres, dres)), True)
    add(msg(9, 1, param(0x7777, b'\x01\x02\x03') + param(0x7778, b'')))     # unknown parameters
    add(msg(9, 9))
    add(msg(5, 1, param(T.rc, u32(1))))                                      # unknown message class
    # standalone status parameters outside their messages
    add(msg(9, 2, param(T.regst, u32(0)) + param(T.deregst, u32(1))), True)
    mark('RKM: routing keys, registration and deregistration with results', st)

    # nested routing keys / results (30 levels), maximum nesting that stays below the tree limit
    st = len(frames)
    nest = param(T.lrk, u32(7))
    for _ in range(30):
        nest = param(T.rk, nest)
    add(msg(9, 1, nest))
    nest = param(T.regst, u32(0))
    for i in range(10):
        nest = param(T.regres if i % 2 == 0 else T.deregres, nest)
    add(msg(9, 2, nest), True)
    mark('nested routing key / results', st)
    last_sctp = len(frames)

    # ---- M3UA over TCP port 2905
    st = len(frames)
    tcp = Tcp(PORT, cport=40001)
    a = msg(3, 1, param(T.aspid, u32(1)))
    b = msg(3, 4, param(T.aspid, u32(1)))
    c = msg(1, 1, param(T.rc, u32(1)) + param(T.pdata, pdata(1, 2, 3, 2, 0, 1, UDT)))
    frames.append(tcp.frame(b'', flags=0x02))
    frames.append(tcp.frame(a))
    frames.append(tcp.frame(b, True))
    frames.append(tcp.frame(a + c))                        # two PDUs in one segment
    frames.append(tcp.frame(c[:11]))                       # header split, PDU over three segments
    frames.append(tcp.frame(c[11:30]))
    frames.append(tcp.frame(c[30:] + b))
    frames.append(tcp.frame(msg(0, 0, param(T.err, u32(7))), True))
    mark('M3UA over TCP: PDUs in one segment and PDUs over several segments', st)
    last_tcp = len(frames)

    # ---- draft versions: each has its own parameter tags
    def draft(tags, name, ver_msgs):
        st = len(frames)
        sv = Sctp(PORT, PPID, cport=2906 + len(ranges))
        for payload, rev in ver_msgs:
            frames.append(sv.frame(payload, rev))
        mark(name, st)

    # draft 5
    v5 = dict(na=1, pdata=3, info=4, apc=5, rc=6, diag=7, hb=8, cause=9, reason=10, tmt=11, err=12,
              status=13, cong=14)
    m = []
    for i, code in enumerate(range(1, 10)):
        m.append((msg(0, 0, param(v5['err'], u32(code)) + param(v5['rc'], u32(1)) + param(v5['diag'], b'\x01\x02\x03')), i % 2))
    for typ, info in [(1, 1), (1, 2), (1, 3), (1, 4), (2, 1), (2, 2), (2, 3), (3, 1)]:
        m.append((msg(0, 1, param(v5['status'], struct.pack('!HH', typ, info)) + param(v5['info'], b'v5')), 0))
    m.append((msg(1, 1, param(v5['na'], u32(1)) + param(v5['pdata'], pdata(1, 2, 3, 2, 0, 1, UDT))), 0))
    m.append((msg(1, 1, param(v5['pdata'], pdata(1, 2, 1, 0, 0, 1, b''))), 1))
    for typ in (1, 2, 3, 4, 5, 6):
        m.append((msg(2, typ, param(v5['na'], u32(1)) + param(v5['apc'], pc(0, 100) + pc(0, 101)) +
                      param(v5['rc'], u32(1)) + param(v5['cause'], struct.pack('!HH', 1, 3)) +
                      param(v5['cong'], b'\x00\x00\x00\x01') + param(v5['info'], b'x')), typ % 2))
    for mode in (1, 2, 3, 4, 5):
        m.append((msg(4, 1, param(v5['tmt'], u32(mode)) + param(v5['rc'], u32(1))), 0))
    for reason in (0, 1, 2, 3):
        m.append((msg(3, 2, param(v5['reason'], u32(reason))), 0))
    m.append((msg(3, 3, param(v5['hb'], b'beat')), 0))
    m.append((msg(3, 1, param(0x7777, b'\x01\x02\x03\x04\x05')), 0))
    m.append((msg(3, 1, param(0x7778, b'')), 0))
    m.append((msg(9, 1, param(0x7779, b'')), 0))
    draft(v5, 'draft 5 (-o m3ua.version:draft-5)', m)
    last_v5 = len(frames)

    # draft 6
    v6 = dict(na=1, pdata1=2, pdata2=3, info=4, apc=5, rc=6, diag=7, hb=8, cause=9, reason=10, tmt=11,
              err=12, status=13, cong=14, concerned=15, rk=16, regres=17, deregres=18, lrk=19, dpc=20,
              si=21, ssn=22, opc=23, circ=24, regsres=25, deregsres=26)
    m = []
    for i, code in enumerate(range(1, 12)):
        m.append((msg(0, 0, param(v6['err'], u32(code)) + param(v6['rc'], u32(1))), i % 2))
    for typ, info in [(1, 1), (1, 2), (1, 3), (1, 4), (2, 1), (2, 2), (2, 3), (3, 1)]:
        m.append((msg(0, 1, param(v6['status'], struct.pack('!HH', typ, info)) + param(v6['info'], b'v6')), 0))
    m.append((msg(1, 1, param(v6['pdata1'], pdata(1, 2, 3, 2, 0, 1, UDT))), 0))
    m.append((msg(1, 1, param(v6['pdata2'], b'\x0a' + pdata(1, 2, 3, 2, 0, 1, UDT))), 1))
    for typ in (1, 2, 3, 4, 5, 6):
        m.append((msg(2, typ, param(v6['na'], u32(1)) + param(v6['apc'], pc(0, 100)) + param(v6['rc'], u32(1)) +
                      param(v6['cause'], struct.pack('!HH', 1, 3)) + param(v6['cong'], b'\x00\x00\x00\x01') +
                      param(v6['concerned'], pc(0, 7))), typ % 2))
    for mode in (1, 2, 3, 4, 5):
        m.append((msg(4, 1, param(v6['tmt'], u32(mode)) + param(v6['rc'], u32(1))), 0))
    m.append((msg(3, 3, param(v6['hb'], b'beat')), 0))
    m.append((msg(3, 2, param(v6['reason'], u32(1))), 0))
    rk6 = (param(v6['lrk'], u32(1)) + param(v6['rc'], u32(5)) + param(v6['tmt'], u32(1)) + param(v6['na'], u32(1)) +
           param(v6['dpc'], pc(0, 9)) + param(v6['si'], b'\x03\x05') + param(v6['ssn'], b'\x06\x07\x08') +
           param(v6['opc'], pc(0, 1) + pc(0, 2)) + param(v6['circ'], pc(0, 1) + b'\x00\x01\x00\x02'))
    m.append((msg(9, 1, param(v6['rk'], rk6)), 0))
    m.append((msg(9, 2, param(v6['regres'], u32(1) + u32(0) + u32(5))), 1))
    m.append((msg(9, 2, param(v6['regsres'], param(v6['regres'], u32(1) + u32(3) + u32(5)))), 1))
    m.append((msg(9, 4, param(v6['deregres'], u32(5) + u32(0))), 1))
    m.append((msg(9, 4, param(v6['deregsres'], param(v6['deregres'], u32(5) + u32(4)))), 1))
    m.append((msg(9, 1, param(0x7777, b'\x01\x02\x03')), 0))
    draft(v6, 'draft 6 (-o m3ua.version:draft-6)', m)
    last_v6 = len(frames)

    # draft 7
    v7 = dict(na=0x80, pdata1=0x81, pdata2=0x82, info=4, apc=0x83, rc=6, diag=7, hb=9, cause=0x84,
              reason=0x0a, tmt=0x0b, err=0x0c, status=0x0d, cong=0x85, concerned=0x86, rk=0x87,
              regres=0x88, deregres=0x89, lrk=0x8a, dpc=0x8b, si=0x8c, ssn=0x8d, opc=0x8e, circ=0x8f,
              regsres=0x90, deregsres=0x91)
    m = []
    for i, code in enumerate(range(1, 14)):
        m.append((msg(0, 0, param(v7['err'], u32(code)) + param(v7['rc'], u32(1))), i % 2))
    for typ, info in [(1, 1), (1, 2), (1, 3), (1, 4), (2, 1), (2, 2), (2, 3), (3, 1)]:
        m.append((msg(0, 1, param(v7['status'], struct.pack('!HH', typ, info)) + param(v7['info'], b'v7')), 0))
    m.append((msg(1, 1, param(v7['pdata1'], pdata(1, 2, 3, 2, 0, 1, UDT))), 0))
    m.append((msg(1, 1, param(v7['pdata2'], b'\x0a' + pdata(1, 2, 3, 2, 0, 1, UDT))), 1))
    for typ in (1, 2, 3, 4, 5, 6):
        m.append((msg(2, typ, param(v7['na'], u32(1)) + param(v7['apc'], pc(0, 100)) + param(v7['rc'], u32(1)) +
                      param(v7['cause'], struct.pack('!HH', 1, 3)) + param(v7['cong'], b'\x00\x00\x00\x01') +
                      param(v7['concerned'], pc(0, 7))), typ % 2))
    for mode in (1, 2, 3):
        m.append((msg(4, 1, param(v7['tmt'], u32(mode)) + param(v7['rc'], u32(1))), 0))
    m.append((msg(3, 3, param(v7['hb'], b'beat')), 0))
    m.append((msg(3, 2, param(v7['reason'], u32(1))), 0))
    rk7 = (param(v7['lrk'], u32(1)) + param(v7['rc'], u32(5)) + param(v7['tmt'], u32(1)) + param(v7['na'], u32(1)) +
           param(v7['dpc'], pc(0, 9)) + param(v7['si'], b'\x03\x05') + param(v7['ssn'], b'\x06\x07\x08') +
           param(v7['opc'], pc(0, 1) + pc(0, 2)) + param(v7['circ'], pc(0, 1) + b'\x00\x01\x00\x02'))
    m.append((msg(9, 1, param(v7['rk'], rk7)), 0))
    m.append((msg(9, 2, param(v7['regres'], u32(1) + u32(0) + u32(5))), 1))
    m.append((msg(9, 2, param(v7['regsres'], param(v7['regres'], u32(1) + u32(3) + u32(5)))), 1))
    m.append((msg(9, 4, param(v7['deregres'], u32(5) + u32(0))), 1))
    m.append((msg(9, 4, param(v7['deregsres'], param(v7['deregres'], u32(5) + u32(4)))), 1))
    m.append((msg(9, 1, param(0x7777, b'\x01\x02\x03')), 0))
    draft(v7, 'draft 7 (-o m3ua.version:draft-7)', m)
    last_v7 = len(frames)
    write_pcap(os.path.join(OUT, 'm3ua-coverage.pcap'), frames)

    # ---- malformed capture
    mal = []
    s2 = Sctp(PORT, PPID, cport=2905)
    # the reproducer of the nesting depth check (Routing Key nested about 3000 levels)
    p = param(T.lrk, u32(7))
    for _ in range(3000):
        p = struct.pack('!HH', T.rk, 4 + len(p)) + p
        if len(p) > 65000:
            break
    mal.append(s2.frame(msg(9, 1, p)))
    good = msg(1, 1, param(T.rc, u32(1)) + param(T.pdata, pdata(1, 2, 3, 2, 0, 1, UDT)))
    for n in (3, 8, 10, 14, 20, 30, len(good) - 3):
        mal.append(s2.frame(good[:n]))
    for tag, ln in ((T.err, 2), (T.status, 5), (T.pdata, 12), (T.pdata, 4), (T.cause, 5), (T.cong, 6),
                    (T.concerned, 5), (T.dpc, 5), (T.opc, 7), (T.circ, 9), (T.apc, 6), (T.rc, 7)):
        mal.append(s2.frame(msg(0, 0, struct.pack('!HH', tag, ln) + b'\0' * max(0, ln - 4))))
    mal.append(s2.frame(msg(0, 0, struct.pack('!HH', T.err, 200) + b'\0' * 4)))
    mal.append(s2.frame(msg(1, 1, param(T.pdata, pdata(1, 2, 3, 2, 0, 1, b'')[:10]))))
    mal.append(s2.frame(msg(1, 1, param(T.pdata, pdata(1, 2, 3, 0, 0, 0, b'')))))     # empty SCCP payload
    write_pcap(os.path.join(OUT, 'm3ua-coverage-malformed.pcap'), mal)
    for r in ranges:
        print(r)
    print('total', len(frames), 'malformed', len(mal), 'sctp<=', last_sctp, 'tcp<=', last_tcp,
          'v5<=', last_v5, 'v6<=', last_v6, 'v7<=', last_v7)


if __name__ == '__main__':
    main()
