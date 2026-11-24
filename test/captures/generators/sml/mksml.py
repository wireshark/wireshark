#!/usr/bin/env python3
# Generates test/captures/sml_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the SML (Smart Message Language, smart
meters) dissector (packet-sml.c).

Usage: mksml.py <output directory>

SML files start with the escape sequence 1b1b1b1b and version 01010101,
hold messages (lists of 6 elements with a CRC16) and end with 1b1b1b1b 1a,
padding and a file CRC16. SML has no default port or heuristic: the
captures use Exported PDU frames that name the "sml" dissector (reached
by default), plus UDP 7259 and TCP 7259 frames that need Decode As
(the udp.port / tcp.port preferences). Every packet is built with struct;
nothing is captured.

Writes:
  sml-coverage.pcapng            Exported PDU (interface 0), Ethernet
                                 (interface 1)
  sml-coverage-malformed.pcapng  the reproducers of the two endless loops
                                 fixed on the branch and invalid lists,
                                 types and lengths
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from pcaplib import exported_pdu, LT_ETH, LT_EXPORTED_PDU, pcapng, TcpConn, udp

ESC = bytes.fromhex('1b1b1b1b')
VER = bytes.fromhex('01010101')
OPT = b'\x01'


def tl(kind, n):
    """Type/length octets of an SML element with n data octets (list: n entries)."""
    if kind == 7:
        if n < 15:
            return bytes([0x70 | n])
        return bytes([0xf0 | (n >> 4), n & 0xf])
    total = n + 1
    if total < 16:
        return bytes([(kind << 4) | total])
    total = n + 2
    return bytes([0x80 | (kind << 4) | (total >> 4), total & 0xf])


def OS(b):
    b = b.encode() if isinstance(b, str) else b
    return tl(0, len(b)) + b


def U(v, n):
    return tl(6, n) + v.to_bytes(n, 'big')


def Sg(v, n):
    return tl(5, n) + (v & ((1 << (8 * n)) - 1)).to_bytes(n, 'big')


def U8(v): return U(v, 1)
def U16(v): return U(v, 2)
def U32(v): return U(v, 4)
def U64(v): return U(v, 8)
def I8(v): return Sg(v, 1)
def I16(v): return Sg(v, 2)
def I32(v): return Sg(v, 4)
def I64(v): return Sg(v, 8)
def BOOL(v): return b'\x42' + bytes([1 if v else 0])


def L(*items):
    return tl(7, len(items)) + b''.join(items)


def crc16(data):
    """CRC-16/X-25 (as crc16_ccitt_tvb_offset)."""
    crc = 0xffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xffff


def T_sec(v=1000):
    return L(U8(1), U32(v))


def T_ts(v=1700000000):
    return L(U8(2), U32(v))


def T_local(v=1700000000, off=60, season=0):
    return L(U8(3), L(U32(v), I16(off), I16(season)))


def msg(tag, body, trans=b'\x00\x01', group=0, crc=True, cut_tag=False, abort=0, crc8=False, badcrc=False):
    """A message: list of 6 with transaction id, group, abort flag, body, CRC, end."""
    if cut_tag:
        mt = L(U32(tag), body)             # u32 message type tag ("zero cutting")
    else:
        mt = L(U16(tag), body)
    m = tl(7, 6) + OS(trans) + U8(group) + U8(abort) + mt
    # the CRC covers the message from its list header up to (not including) the CRC type octet
    if crc8:                               # CRC with zero cutting: one octet, type 0x62
        c = crc16(m)
        return m + b'\x62' + bytes([c & 0xff]) + b'\x00'
    c = crc16(m)
    if badcrc:
        c ^= 0x00ff
    return m + b'\x63' + struct.pack('<H', c) + b'\x00'


def sml_file(msgs, pad=0, crc_ok=True):
    body = ESC + VER + b''.join(msgs) + b'\x00' * pad + ESC + b'\x1a' + bytes([pad])
    c = crc16(body)
    if not crc_ok:
        c ^= 0x1234
    return body + struct.pack('<H', c)


# --- message bodies -----------------------------------------------------------------
def pv_value_for_das():
    return L(U8(1), OS('v'))


def open_req():
    return L(OPT, OS('client'), OS('file1'), OS('server01'), OS('user'), OS('pass'), U8(1))


def open_req_min():
    return L(OS('\x08'), OS('c'), OS('f'), OPT, OPT, OPT, OPT)


def open_res(time=None):
    return L(OPT, OS('client'), OS('file1'), OS('server01'), time if time is not None else OPT, U8(1))


def close(sig=None):
    return L(OS(sig) if sig else OPT)


def treepath():
    return L(OS(b'\x81\x81\xc7\x82\x03\xff'), OS(b'\x01\x00\x01\x08\x00\xff'))


def prof_req(time_a=None, time_b=None, objs=None, das=None, raw=True):
    return L(OS('server01'), OS('user'), OS('pass'), BOOL(raw),
             time_a if time_a is not None else OPT, time_b if time_b is not None else OPT,
             treepath(), objs if objs is not None else OPT, das if das is not None else OPT)


def value_variants():
    return [OS('abc'), U32(123456), I16(-5), BOOL(True), U8(7), OPT]


def getlist_res(values=None, client=True, time=True, gw=True):
    values = values or [U32(1)]
    ent = lambda v, t: L(OS(b'\x01\x00\x01\x08\x00\xff'), U(0x10, 1), t, U8(30), I8(-1), v, OPT)
    entries = [ent(v, T_sec(i) if i % 2 == 0 else OPT) for i, v in enumerate(values)]
    return L(OS('client') if client else OPT, OS('server01'), OS('list1'), T_sec() if time else OPT,
             tl(7, len(entries)) + b''.join(entries), OS('sig') if gw else OPT, T_ts() if gw else OPT)


def proc_param_res(tree):
    return L(OS('server01'), treepath(), tree)


def tree_entry(name, pv, child):
    return L(OS(name), pv, child)


def main(out):
    exp = lambda payload: (0, exported_pdu('sml', payload))
    fr = []
    # --- session ----------------------------------------------------------------
    fr.append(exp(sml_file([msg(0x0100, open_req())])))
    fr.append(exp(sml_file([msg(0x0100, open_req_min()), msg(0x0101, open_res(T_ts()))])))
    fr.append(exp(sml_file([msg(0x0101, open_res()), msg(0x0200, close()), msg(0x0201, close('signature'))])))
    fr.append(exp(sml_file([msg(0x0100, open_req(), cut_tag=True)], pad=2)))
    # --- profile requests -------------------------------------------------------------
    fr.append(exp(sml_file([msg(0x0300, prof_req(T_sec(), T_ts(), L(OS('o1'), OS('o2')), None))])))
    fr.append(exp(sml_file([msg(0x0300, prof_req(T_local(), T_sec(5), None, None, raw=False))])))
    fr.append(exp(sml_file([msg(0x0400, prof_req(None, None, L(OS('obj')), None))])))
    fr.append(exp(sml_file([msg(0x0300, prof_req(T_sec(), None, L(OS('o1')), L(OS('das'), pv_value_for_das(), OPT)))])))
    # --- profile pack response --------------------------------------------------------
    hdr = L(L(OS(b'\x01\x00\x01\x08\x00\xff'), U8(30), I8(-1)), L(OS(b'\x01\x00\x02\x08\x00\xff'), OPT, OPT))
    per = L(L(T_sec(100), U32(0), L(L(U32(5), OPT), L(OS('v'), OS('sig'))), OS('psig')),
            L(T_ts(), OPT, L(L(I32(-7), OPT)), OPT))
    fr.append(exp(sml_file([msg(0x0301, L(OS('server01'), T_sec(), U32(900), treepath(), hdr, per, OS('raw'), OS('profsig')))])))
    fr.append(exp(sml_file([msg(0x0301, L(OS('server01'), T_ts(), U32(900), treepath(), hdr, per, OPT, OPT))])))
    # --- profile list response ----------------------------------------------------------
    pl = L(L(OS('obj1'), U8(30), I8(0), U32(10), OPT), L(OS('obj2'), OPT, OPT, OS('txt'), OS('vs')))
    fr.append(exp(sml_file([msg(0x0401, L(OS('server01'), T_sec(), U32(900), treepath(), T_ts(), U32(0), pl, OS('raw'), OS('psig')))])))
    fr.append(exp(sml_file([msg(0x0401, L(OS('server01'), T_sec(), U32(900), treepath(), OPT, OPT, pl, OPT, OPT))])))
    # --- get list -------------------------------------------------------------------
    fr.append(exp(sml_file([msg(0x0700, L(OS('client'), OS('server01'), OS('user'), OS('pass'), OS('1-0:99.1.0*255')))])))
    fr.append(exp(sml_file([msg(0x0700, L(OPT, OPT, OPT, OPT, OPT))])))
    fr.append(exp(sml_file([msg(0x0701, getlist_res([U32(1), OS('text'), I64(-1), BOOL(False), OPT]))])))
    lv = [L(U8(1), T_sec(77)),                                    # list type time
          L(U8(2), L(T_ts(), OPT, U32(5))),                        # timestamped value
          L(U8(3), L(U8(1), L(I8(-3), U8(0x1b)))),                  # cosem scaler/unit
          L(U8(2), L(T_sec(), U8(0), OS('xy'))),                    # timestamped value, string value
          L(U8(2), L(T_ts(), OPT, OPT)),                             # timestamped value, no value
          L(U8(2), L(T_local(), U8(1), U16(77)))]                   # local timestamp
    fr.append(exp(sml_file([msg(0x0701, getlist_res(lv, client=False))])))
    fr.append(exp(sml_file([msg(0x0701, getlist_res([U32(2)], time=False, gw=False)), msg(0x0200, close(), crc8=True)])))
    # --- procedure parameters -------------------------------------------------------------
    fr.append(exp(sml_file([msg(0x0500, L(OS('server01'), OS('user'), OS('pass'), treepath(), OS('attr')))])))
    fr.append(exp(sml_file([msg(0x0500, L(OPT, OPT, OPT, treepath(), OPT))])))
    pv_value = L(U8(1), OS('value'))
    pv_period = L(U8(2), L(OS('obj'), U8(30), I8(0), U32(3), OS('vsig')))
    pv_time = L(U8(4), T_ts())
    pv_list = L(U8(5), L(OS('obj'), U(0x12, 1), T_sec(), U8(30), I8(0), OS('v'), OS('vs')))
    child = L(L(OS('c1'), pv_value, OPT), L(OS('c2'), OPT, OPT))
    one_child = L(L(OS('only'), pv_time, OPT))
    t1 = L(OS('root'), pv_value, child)
    fr.append(exp(sml_file([msg(0x0501, proc_param_res(t1))])))
    fr.append(exp(sml_file([msg(0x0501, proc_param_res(L(OS('root'), pv_period, one_child)))])))
    fr.append(exp(sml_file([msg(0x0501, proc_param_res(L(OS('root'), pv_time, OPT)))])))
    fr.append(exp(sml_file([msg(0x0501, proc_param_res(L(OS('root'), pv_list, OPT)))])))
    fr.append(exp(sml_file([msg(0x0501, proc_param_res(L(OS('root'), OPT, OPT)))])))
    fr.append(exp(sml_file([msg(0x0600, L(OS('server01'), OS('user'), OS('pass'), treepath(), t1))])))
    fr.append(exp(sml_file([msg(0x0600, L(OPT, OPT, OPT, treepath(), L(OS('r'), OPT, OPT)))])))
    # --- a tuple entry (23 elements, 0xf1 0x07) as procParValue
    triple = lambda k: U8(30) + I8(-k) + U32(1000 + k)
    tuple_entry = tl(7, 23) + OS('server01') + T_sec(5) + OPT + triple(1) + triple(2) + triple(3) + OS('sig1') + \
        triple(4) + triple(5) + triple(6) + OS('sig2')
    fr.append(exp(sml_file([msg(0x0501, proc_param_res(L(OS('root'), L(U8(3), tuple_entry), OPT)))])))
    # --- attention -----------------------------------------------------------------------
    fr.append(exp(sml_file([msg(0xff01, L(OS('server01'), OS(b'\x81\x81\xc7\xc7\xc7\xc7'), OS('error text'), OPT))])))
    fr.append(exp(sml_file([msg(0xff01, L(OPT, OS(b'\x81\x81\xc7\xc7\x01\x02'), OPT, OPT))])))
    fr.append(exp(sml_file([msg(0xff01, L(OS('server01'), OS(b'\x81\x81\xc7\xc7\xc7\xc7'), OPT, L(L(OS('c'), OPT, OPT))))])))
    # --- several files in one PDU, and a file with a bad file CRC ------------------------
    fr.append(exp(sml_file([msg(0x0100, open_req())]) + sml_file([msg(0x0200, close())])))
    fr.append(exp(sml_file([msg(0x0200, close())], crc_ok=False)))
    n1 = len(fr)
    # --- UDP 7259 and TCP 7259 (Decode As) ----------------------------------------------
    f = sml_file([msg(0x0100, open_req()), msg(0x0701, getlist_res()), msg(0x0200, close())])
    fr.append((1, udp(f, 40000, 7259)))
    c = TcpConn(40001, 7259)
    c.handshake()
    k1 = next(i for i in range(20, len(f)) if f[i - 1] != 0)      # a cut that does not end in a zero octet
    k2 = next(i for i in range(k1 + 40, len(f)) if f[i - 1] != 0)
    c.send(f[:k1])
    c.send(f[k1:k2])
    c.send(f[k2:])
    # a segment that ends exactly at the end of a message, and one that ends in a zero octet inside a message
    m1 = msg(0x0100, open_req())
    f2 = sml_file([m1, msg(0x0201, close('sig')), msg(0x0200, close())])
    c.send(f2[:8 + len(m1)])
    c.send(f2[8 + len(m1):])
    f3 = sml_file([msg(0x0100, open_req(), trans=b'\x00\x00\x00\x00'), msg(0x0200, close())])
    kz = next(i for i in range(20, len(f3)) if f3[i - 1] == 0 and f3[i - 4] != 0x63 and f3[i - 3] != 0x62)
    c.send(f3[:kz])
    c.send(f3[kz:])
    c.send(sml_file([msg(0x0200, close())]) + sml_file([msg(0x0200, close())]))
    fr += [(1, x) for x in c.frames]
    pcapng(os.path.join(out, 'sml-coverage.pcapng'), fr, (LT_EXPORTED_PDU, LT_ETH))
    print('%d frames: Exported PDU 1-%d; UDP/TCP (Decode As) %d-%d' % (len(fr), n1, n1 + 1, len(fr)))

    # --- malformed -------------------------------------------------------------------------
    ml = []
    # reproducer of "SML: Fix endless loops": AttentionRes attentionNo moving the offset back
    hdr = ESC + VER
    mh = bytes.fromhex('76 0200 6200 6200 72 63 ff01 73 01')
    m0 = mh + bytes.fromhex('07000000000000') + bytes.fromhex('01 01 630000 00')
    q = len(hdr) + len(mh) + 7
    a1 = len(hdr) + len(m0) + len(mh)
    v = (q - a1) & 0xffffffff
    nib = '%08x' % v
    alen = bytes([0x80 | int(ch, 16) for ch in nib[:-1]]) + bytes([int(nib[-1], 16)])
    ml.append(exp(hdr + m0 + mh + alen + b'\x00' * 8))
    # reproducer: length byte 0x00 and a list count of 0xffffffff (zero advance)
    zm = bytes.fromhex('76 0200 6200 6200 72 63 0300 7f') + bytes.fromhex('01 01 01 01 01 01') + \
        bytes.fromhex('ff 8f 8f 8f 8f 8f 8f 0f') + b'\x00' * 16
    ml.append(exp(hdr + zm))
    ml.append(exp(sml_file([msg(0xff01, L(OS('server01'), OS(b'\x81\x81\xc7\xc7'), OS('error text'), OPT))])))   # unknown attentionNo
    ml.append(exp(sml_file([msg(0x0200, close(), badcrc=True)])))                # bad message CRC (with sml.crc)
    # structural errors
    ml.append(exp(ESC + b'\x02\x02\x02\x02' + b'abc'))                         # version 2 not supported
    ml.append(exp(ESC + VER + b'\x75' + bytes(10) + ESC + b'\x1a\x00\x00\x00'))   # list of 5 elements
    ml.append(exp(sml_file([msg(0x0aaa, open_req())])))                          # unknown message type
    ml.append(exp(ESC + VER + tl(7, 6) + OS('t') + U8(0) + U8(0) + L(U8(1), OPT)))   # message type length
    m = msg(0x0200, close())
    ml.append(exp(ESC + VER + m[:-1] + b'\x05' + ESC + b'\x1a\x00\x00\x00'))     # bad end of message
    m = msg(0x0200, close())
    ml.append(exp(ESC + VER + m[:-4] + b'\x64\x00\x00\x00\x00' + ESC + b'\x1a\x00\x00\x00'))   # crc length
    ml.append(exp(ESC + VER + m + b'\x00\x00' + b'\x1c\x1c\x1c\x1c\x1a\x00\x00\x00'))    # bad escape end
    ml.append(exp(ESC + VER + m))                                                # file cut after a message
    ml.append(exp(ESC + VER))
    ml.append(exp(b'\x76\x00'))
    ml.append(exp(b'\x00\x00\x00\x00'))                                          # not SML
    # invalid lists and counts in message bodies
    bad = [(0x0300, L(OS('s'), OPT, OPT, OPT, OPT, OPT, OS('notalist'), OPT, OPT)),
           (0x0300, L(OS('s'), OPT, OPT, OPT, OPT, OPT, L(), OPT, OPT)),
           (0x0300, L(OS('s'), OPT, OPT, OPT, OPT, OPT, treepath(), OS('x'), OPT)),
           (0x0300, L(OS('s'), OPT, OPT, OPT, OPT, OPT, treepath(), L(), OPT)),
           (0x0300, L(OS('s'), OPT, OPT, OPT, OPT, OPT, treepath(), OPT, OS('x'))),
           (0x0301, L(OS('s'), T_sec(), U32(1), OS('x'), OPT, OPT, OPT, OPT)),
           (0x0301, L(OS('s'), T_sec(), U32(1), L(), OPT, OPT, OPT, OPT)),
           (0x0301, L(OS('s'), T_sec(), U32(1), treepath(), OS('x'), OPT, OPT, OPT)),
           (0x0301, L(OS('s'), T_sec(), U32(1), treepath(), L(), OPT, OPT, OPT)),
           (0x0301, L(OS('s'), T_sec(), U32(1), treepath(), L(L(OS('a'), OPT, OPT)), OS('x'), OPT, OPT)),
           (0x0301, L(OS('s'), T_sec(), U32(1), treepath(), L(L(OS('a'), OPT, OPT)), L(), OPT, OPT)),
           (0x0301, L(OS('s'), T_sec(), U32(1), treepath(), L(L(OS('a'), OPT, OPT)),
                      L(L(T_sec(), OPT, OS('x'), OPT)), OPT, OPT)),
           (0x0301, L(OS('s'), T_sec(), U32(1), treepath(), L(L(OS('a'), OPT, OPT)),
                      L(L(T_sec(), OPT, L(), OPT)), OPT, OPT)),
           (0x0401, L(OS('s'), T_sec(), U32(1), OS('x'), OPT, OPT, OPT, OPT, OPT)),
           (0x0401, L(OS('s'), T_sec(), U32(1), L(), OPT, OPT, OPT, OPT, OPT)),
           (0x0401, L(OS('s'), T_sec(), U32(1), treepath(), OPT, OPT, OS('x'), OPT, OPT)),
           (0x0401, L(OS('s'), T_sec(), U32(1), treepath(), OPT, OPT, L(), OPT, OPT)),
           (0x0701, L(OS('s'), OPT, OPT, OS('x'), OPT, OPT)),
           (0x0701, L(OS('s'), OPT, OPT, L(), OPT, OPT)),
           (0x0500, L(OS('s'), OPT, OPT, OS('x'), OPT)),
           (0x0500, L(OS('s'), OPT, OPT, L(), OPT)),
           (0x0501, L(OS('s'), OS('x'), OPT)),
           (0x0501, L(OS('s'), L(), OPT)),
           (0x0501, L(OS('s'), treepath(), OS('x'))),
           (0x0600, L(OS('s'), OPT, OPT, OS('x'), OPT)),
           (0x0600, L(OS('s'), OPT, OPT, L(), OPT)),
           (0x0600, L(OS('s'), OPT, OPT, treepath(), OS('x'))),
           (0xff01, L(OS('s'), OS('abc'), OPT, OS('x'))),
           (0xff01, L(OS('s'), OS('abc'), OPT, L())),
           (0x0501, proc_param_res(L(OS('r'), L(U8(9), OPT), OPT))),                  # invalid procParValue
           (0x0501, proc_param_res(L(OS('r'), OS('x'), OPT))),                        # procParValue is not a list
           (0x0501, proc_param_res(L(OS('r'), L(U8(3), OPT), OPT))),                  # tuple that is not 0xf1 0x07
           (0x0501, proc_param_res(L(OS('r'), OPT, OS('childs')))),                   # child list is a string
           (0x0501, proc_param_res(L(OS('r'), OPT, L()))),                            # empty child list
           (0x0501, proc_param_res(L(OS('r'), OPT, L(OS('x'))))),                     # child entry is not a list of 3
           (0x0501, proc_param_res(L(OS('r'), OPT, tl(7, 1) + L(OS('c'), OPT, OPT)))),    # child list with 0x71
           (0x0701, getlist_res([L(OS('x'), OPT)])),
           (0x0501, proc_param_res(L(OS('r'), OPT, L(OS('x'), OS('y'))))),          # tree_Entry that is not a list of 3
           (0x0700, L(OPT, OPT)),
           (0x0701, L(OPT, OS('s'), OPT, OPT, tl(7, 1) + L(OS('o'), OPT, OPT, OPT, OPT, L(U8(9), OPT), OPT), OPT, OPT)),    # list type invalid
           (0x0701, L(OPT, OS('s'), OPT, OPT, tl(7, 1) + L(OS('o'), OPT, OPT, OPT, OPT, L(U8(3), L(U8(9), OPT)), OPT), OPT, OPT)),   # cosem value invalid
           (0x0701, L(OPT, OS('s'), OPT, OPT, tl(7, 1) + L(OS('o'), OPT, OPT, OPT, OPT, L(U8(1), L(U8(9), OPT)), OPT), OPT, OPT)),   # time type invalid
           ]
    for tag, body in bad:
        ml.append(exp(sml_file([msg(tag, body)])))
    # message type with a long list count and tl octets cut short
    ml.append(exp(ESC + VER + b'\x76\x82'))
    pcapng(os.path.join(out, 'sml-coverage-malformed.pcapng'), ml, (LT_EXPORTED_PDU, LT_ETH))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
