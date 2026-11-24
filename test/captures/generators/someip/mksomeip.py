#!/usr/bin/env python3
# Generates test/captures/someip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic SOME/IP captures and a payload dissector configuration.
Usage: mksomeip.py <outdir>

Writes someip-coverage.pcap, someip-coverage-malformed.pcap and the UAT
files of the payload dissector under <outdir>/cfg-uat (used by runcov.sh;
the test class creates the same files from its own copy)."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from pcaplib_s9 import Stream, write_pcap, udp_pkt

A = '192.0.2.10'
B = '192.0.2.11'
UDP_PORT = 30501
TCP_PORT = 30502
SVC = 0x2000
CLIENT = 0x0100


def someip(service, method, client, session, payload, mtype=0x00, rc=0, iver=1, pver=1, length=None):
    if length is None:
        length = 8 + len(payload)
    return struct.pack('>HHIHHBBBB', service, method, length, client, session,
                       pver, iver, mtype, rc) + payload


def tp_seg(service, method, client, session, offset, more, data, mtype=0x20, iver=1):
    """A SOME/IP-TP segment: 4 octets TP header (offset in units of 16) then data."""
    hdr = struct.pack('>I', (offset & 0xfffffff0) | (1 if more else 0))
    return someip(service, method, client, session, hdr + data, mtype=mtype, iver=iver)


# ------------------------------------------------------------------ UAT config
def q(v):
    if v is True:
        return '"TRUE"'
    if v is False:
        return '"FALSE"'
    if isinstance(v, int):
        return '"%d"' % v
    return '"%s"' % v


def hx(v):
    return '"%x"' % v


def row(*cols):
    return ','.join(cols) + '\n'


B_U8, B_U16, B_U32, B_U64, B_I8, B_I16, B_I32, B_I64, B_F32, B_F64, B_U16L = range(1, 12)
BASE_TYPES = [
    (B_U8, 'uint8', 'uint8', True, 8), (B_U16, 'uint16', 'uint16', True, 16),
    (B_U32, 'uint32', 'uint32', True, 32), (B_U64, 'uint64', 'uint64', True, 64),
    (B_I8, 'int8', 'int8', True, 8), (B_I16, 'int16le', 'int16', False, 16),
    (B_I32, 'int32', 'int32', True, 32), (B_I64, 'int64', 'int64', True, 64),
    (B_F32, 'float32', 'float32', True, 32), (B_F64, 'float64', 'float64', True, 64),
    (B_U16L, 'uint16le', 'uint16', False, 16),
]
# strings: id, name, encoding, dynamic, max_length, length_of_length, big_endian, pad_to
STRINGS = [
    (1, 'fixed4', 'ascii', False, 4, 0, True, 0),
    (2, 'dyn16', 'utf-8', True, 100, 16, True, 0),
    (3, 'u16be32', 'utf-16', True, 100, 32, True, 0),
    (4, 'u16le8', 'utf-16', True, 100, 8, False, 0),
    (5, 'dyn8', 'ascii', True, 100, 8, True, 0),
]
# arrays: id, name, data_type, id_ref, filter, [(lower, upper, length_of_length, pad_to) per dimension]
ARRAYS = [
    (1, 'dynu8', 1, B_U8, 'arr_dynu8', [(0, 20, 16, 0)]),
    (2, 'static3u16', 1, B_U16, 'arr_static3', [(3, 3, 0, 0)]),
    (3, 'dyn2d', 1, B_U8, 'arr_dyn2d', [(0, 10, 8, 0), (0, 10, 8, 0)]),
    (4, 'static2d', 1, B_U8, 'arr_static2d', [(2, 2, 0, 0), (2, 2, 0, 0)]),
    (5, 'badstatic', 1, B_U8, 'arr_badstatic', [(1, 3, 0, 0)]),
    (6, 'arrstruct', 4, 1, 'arr_struct', [(0, 5, 32, 0)]),
    (7, 'dynlimited', 1, B_U8, 'arr_limited', [(2, 3, 8, 0)]),
    (9, 'arrstr', 2, 2, 'arr_str', [(0, 5, 16, 0)]),
    (10, 'mixed2d', 1, B_U8, 'arr_mixed', [(2, 2, 0, 0), (0, 5, 8, 0)]),
    (11, 'arr24', 1, B_U8, 'arr_24', [(0, 5, 24, 0)]),
]
# structs: id, name, length_of_length, pad_to, wtlv, [(name, data_type, id_ref, filter)]
STRUCTS = [
    (1, 'S1', 0, 0, False, [('a', 1, B_U8, 's1_a'), ('b', 1, B_U16, 's1_b'), ('c', 2, 1, 's1_c')]),
    (2, 'S2', 32, 0, False, [('x', 1, B_U8, 's2_x'), ('inner', 4, 1, 's2_inner'), ('arr', 3, 1, 's2_arr')]),
    (3, 'S3w', 0, 0, True, [('s_u8', 1, B_U8, 's3_u8'), ('s_u16', 1, B_U16, 's3_u16')]),
    (5, 'S5badlol', 24, 0, False, [('z', 1, B_U8, 's5_z')]),
]
# unions: id, name, length_of_length, length_of_type, pad_to, [(type_id, name, data_type, id_ref, filter)]
UNIONS = [
    (1, 'U1', 32, 8, 0, [(1, 'asU8', 1, B_U8, 'u1_u8'), (2, 'asStr', 2, 2, 'u1_str'), (3, 'asStruct', 4, 1, 'u1_struct')]),
    (2, 'U2', 16, 16, 0, [(1, 'asU16', 1, B_U16, 'u2_u16')]),
    (3, 'U3bad', 24, 8, 0, [(1, 'x', 1, B_U8, 'u3_x')]),
    (4, 'U4', 8, 32, 0, [(1, 'asU8', 1, B_U8, 'u4_u8')]),
    (5, 'U5badtype', 16, 24, 0, [(1, 'x', 1, B_U8, 'u5_x')]),
]
# typedefs: id, name, data_type, id_ref
TYPEDEFS = [
    (1, 'td_u32', 1, B_U32), (2, 'td_struct', 4, 1), (3, 'td_str', 2, 2), (4, 'td_arr', 3, 1),
    (5, 'td_nested', 6, 1), (6, 'td_union', 5, 2), (7, 'td_enum', 7, 1), (8, 'td_bf', 8, 1),
]
# enums: id, name, data_type, id_ref, [(value, name)]
ENUMS = [(1, 'E1', 1, B_U8, [(0, 'ZERO'), (1, 'ONE'), (0xff, 'ALL')]),
         (2, 'E2', 1, B_U16, [(0x100, 'BIG')])]
# bitfields: id, name, bits, [(bit, name, filter)]
BITFIELDS = [
    (1, 'BF8', 8, [(0, 'b0', 'bf8_b0'), (3, 'b3', 'bf8_b3'), (7, 'b7', 'bf8_b7')]),
    (2, 'BF16', 16, [(0, 'lo', 'bf16_lo'), (15, 'hi', 'bf16_hi')]),
    (3, 'BF32', 32, [(31, 'top', 'bf32_top'), (4, 'mid', 'bf32_mid')]),
    (4, 'BF64', 64, [(63, 'top', 'bf64_top'), (0, 'bot', 'bf64_bot')]),
]
# parameter lists: (service, method, version, msgtype, wtlv, [(name, data_type, id_ref, filter)])
M1 = [('p_u8', 1, B_U8, 'm1_u8'), ('p_u16', 1, B_U16, 'm1_u16'), ('p_u32', 1, B_U32, 'm1_u32'),
      ('p_u64', 1, B_U64, 'm1_u64'), ('p_i8', 1, B_I8, 'm1_i8'), ('p_i16', 1, B_I16, 'm1_i16'),
      ('p_i32', 1, B_I32, 'm1_i32'), ('p_i64', 1, B_I64, 'm1_i64'), ('p_f32', 1, B_F32, 'm1_f32'),
      ('p_f64', 1, B_F64, 'm1_f64'), ('p_u16le', 1, B_U16L, 'm1_u16le'), ('p_fixed4', 2, 1, 'm1_fixed4'),
      ('p_enum', 7, 1, 'm1_enum'), ('p_bf8', 8, 1, 'm1_bf8'), ('p_bf16', 8, 2, 'm1_bf16'),
      ('p_bf32', 8, 3, 'm1_bf32'), ('p_bf64', 8, 4, 'm1_bf64'), ('p_enum2', 7, 2, 'm1_enum2')]
PARAMS = [
    (SVC, 1, 1, 0x00, False, M1),
    (SVC, 2, 1, 0x00, False, [('p_dyn16', 2, 2, 'm2_dyn16'), ('p_u16be', 2, 3, 'm2_u16be'),
                              ('p_u16le', 2, 4, 'm2_u16le'), ('p_dyn8', 2, 5, 'm2_dyn8')]),
    (SVC, 3, 1, 0x00, False, [('p_dynu8', 3, 1, 'm3_dynu8'), ('p_static3', 3, 2, 'm3_static3'),
                              ('p_dyn2d', 3, 3, 'm3_dyn2d'), ('p_static2d', 3, 4, 'm3_static2d'),
                              ('p_arrstruct', 3, 6, 'm3_arrstruct'), ('p_arrstr', 3, 9, 'm3_arrstr')]),
    (SVC, 4, 1, 0x00, False, [('p_s1', 4, 1, 'm4_s1'), ('p_s2', 4, 2, 'm4_s2')]),
    (SVC, 5, 1, 0x00, False, [('p_u1a', 5, 1, 'm5_u1a'), ('p_u1b', 5, 1, 'm5_u1b'),
                              ('p_u1c', 5, 1, 'm5_u1c'), ('p_u2', 5, 2, 'm5_u2')]),
    (SVC, 6, 1, 0x00, False, [('p_td_u32', 6, 1, 'm6_u32'), ('p_td_struct', 6, 2, 'm6_struct'),
                              ('p_td_str', 6, 3, 'm6_str'), ('p_td_arr', 6, 4, 'm6_arr'),
                              ('p_td_nested', 6, 5, 'm6_nested'), ('p_td_union', 6, 6, 'm6_union'),
                              ('p_td_enum', 6, 7, 'm6_enum'), ('p_td_bf', 6, 8, 'm6_bf')]),
    (SVC, 7, 1, 0x00, True, [('w_u8', 1, B_U8, 'm7_u8'), ('w_u16', 1, B_U16, 'm7_u16'),
                             ('w_u32', 1, B_U32, 'm7_u32'), ('w_u64', 1, B_U64, 'm7_u64'),
                             ('w_str', 2, 2, 'm7_str'), ('w_struct', 4, 3, 'm7_struct'),
                             ('w_arr', 3, 1, 'm7_arr'), ('w_union', 5, 1, 'm7_union'),
                             ('w_bf', 8, 1, 'm7_bf'), ('w_enum', 7, 1, 'm7_enum'),
                             ('w_td_str', 6, 3, 'm7_tdstr'), ('w_str4', 2, 2, 'm7_str4'),
                             ('w_struct4', 4, 2, 'm7_struct4'), ('w_arr4', 3, 1, 'm7_arr4'),
                             ('w_str8', 2, 5, 'm7_str8')]),
    (SVC, 8, 1, 0x80, False, [('r_u8', 1, B_U8, 'm8_u8'), ('r_u32', 1, B_U32, 'm8_u32')]),
    (SVC, 9, 1, 0x00, False, [('c_nostr', 2, 6, 'm9_nostr')]),
    (SVC, 10, 1, 0x00, False, [('c_badunion', 5, 3, 'm10_badunion')]),
    (SVC, 11, 1, 0x00, False, [('c_badarr', 3, 5, 'm11_badarr')]),
    (SVC, 12, 1, 0x00, False, [('c_badstruct', 4, 5, 'm12_badstruct')]),
    (SVC, 13, 1, 0x00, False, [('c_limited', 3, 7, 'm13_limited')]),
    (SVC, 14, 1, 0x00, True, [('c_nulltypedef', 6, 0x99, 'm14_nulltd')]),
    (SVC, 15, 1, 0x00, False, [('c_unknown_type_ref', 1, 0x77, 'm15_unk'), ('c_str_missing', 2, 0x77, 'm15_str'),
                               ('c_arr_missing', 3, 0x77, 'm15_arr'), ('c_struct_missing', 4, 0x77, 'm15_struct'),
                               ('c_union_missing', 5, 0x77, 'm15_union'), ('c_td_missing', 6, 0x77, 'm15_td'),
                               ('c_enum_missing', 7, 0x77, 'm15_enum'), ('c_bf_missing', 8, 0x77, 'm15_bf')]),
    (SVC, 16, 1, 0x00, True, [('w_s', 2, 2, 'm16_str'), ('w_t', 6, 1, 'm16_td')]),
    (SVC, 17, 1, 0x00, False, [('c_arr24', 3, 11, 'm17_arr24')]),
    (SVC, 18, 1, 0x00, False, [('c_union_lot32', 5, 4, 'm18_union')]),
    (SVC, 19, 1, 0x00, False, [('c_union_lot24', 5, 5, 'm19_union')]),
    (SVC, 20, 1, 0x00, True, [('w_miss_str', 2, 0x77, 'm20_str')]),
    (SVC, 21, 1, 0x00, True, [('w_miss_arr', 3, 0x77, 'm21_arr')]),
    (SVC, 22, 1, 0x00, True, [('w_miss_struct', 4, 0x77, 'm22_struct')]),
    (SVC, 23, 1, 0x00, True, [('w_miss_union', 5, 0x77, 'm23_union')]),
]


def uat_files():
    f = {}
    hdr = '# This file is automatically generated, DO NOT MODIFY.\n'
    f['SOMEIP_service_identifiers'] = hdr + row(q('2000'), q('TestService'))
    f['SOMEIP_method_event_identifiers'] = hdr + ''.join(
        row(q('2000'), q('%04x' % m), q('method%d' % m)) for m in (1, 2, 3, 0x8001))
    f['SOMEIP_eventgroup_identifiers'] = hdr + row(q('2000'), q('0001'), q('Events'))
    f['SOMEIP_client_identifiers'] = hdr + row(q('2000'), q('0100'), q('Tester'))
    f['SOMEIP_parameter_base_types'] = hdr + ''.join(
        row(hx(i), q(n), q(t), q(be), q(bl), q(bl)) for i, n, t, be, bl in BASE_TYPES)
    f['SOMEIP_parameter_strings'] = hdr + ''.join(
        row(hx(i), q(n), q(e), q(d), q(m), q(l), q(be), q(p)) for i, n, e, d, m, l, be, p in STRINGS)
    s = ''
    for i, n, dt, ref, flt, dims in ARRAYS:
        for k, (lo, up, ll, pad) in enumerate(dims):
            s += row(hx(i), q(n), q(dt), hx(ref), q(len(dims)), q(flt), q(k), q(lo), q(up), q(ll), q(pad))
    f['SOMEIP_parameter_arrays'] = hdr + s
    s = ''
    for i, n, ll, pad, wtlv, items in STRUCTS:
        for k, (nm, dt, ref, flt) in enumerate(items):
            s += row(hx(i), q(n), q(ll), q(pad), q(wtlv), q(len(items)), q(k), q(nm), q(dt), hx(ref), q(flt))
    f['SOMEIP_parameter_structs'] = hdr + s
    s = ''
    for i, n, ll, lt, pad, items in UNIONS:
        for (tid, tn, dt, ref, flt) in items:
            s += row(hx(i), q(n), q(ll), q(lt), q(pad), q(len(items)), q(tid), q(tn), q(dt), hx(ref), q(flt))
    f['SOMEIP_parameter_unions'] = hdr + s
    f['SOMEIP_parameter_typedefs'] = hdr + ''.join(row(hx(i), q(n), q(dt), hx(ref)) for i, n, dt, ref in TYPEDEFS)
    s = ''
    for i, n, dt, ref, vals in ENUMS:
        for v, vn in vals:
            s += row(hx(i), q(n), q(dt), hx(ref), q(len(vals)), hx(v), q(vn))
    f['SOMEIP_parameter_enums'] = hdr + s
    s = ''
    for i, n, bits, items in BITFIELDS:
        for bn, name, flt in items:
            s += row(hx(i), q(n), q(bits), q(len(items)), q(bn), q(name), q(flt))
    f['SOMEIP_parameter_bitfields'] = hdr + s
    s = ''
    for svc, meth, ver, mt, wtlv, items in PARAMS:
        for k, (nm, dt, ref, flt) in enumerate(items):
            s += row(hx(svc), hx(meth), q(ver), hx(mt), q(wtlv), q(len(items)), q(k), q(nm), q(dt), hx(ref), q(flt))
    f['SOMEIP_parameter_list'] = hdr + s
    return f


# ---------------------------------------------------------------- payloads
def s16(b):
    return struct.pack('>H', len(b)) + b


S1_BYTES = b'\x01\x02\x03WXYZ'
PAY = {}
PAY[1] = (b'\x12' + struct.pack('>H', 0x3456) + struct.pack('>I', 0x789abcde)
          + struct.pack('>Q', 0x0102030405060708) + b'\xfe' + struct.pack('<h', -3)
          + struct.pack('>i', -4) + struct.pack('>q', -5) + struct.pack('>f', 1.5)
          + struct.pack('>d', 2.25) + struct.pack('<H', 0x0102) + b'ABCD' + b'\x01'
          + b'\x89' + struct.pack('>H', 0x8001) + struct.pack('>I', 0x80000010)
          + struct.pack('>Q', 0x8000000000000001) + struct.pack('>H', 0x100) + b'\xaa\xbb')
PAY[2] = (s16(b'hello\x01world') + struct.pack('>I', 6) + 'Hi!'.encode('utf-16-be')
          + b'\x04' + 'Hi'.encode('utf-16-le') + b'\x03abc')
PAY[3] = (s16(b'\x01\x02\x03') + struct.pack('>HHH', 1, 2, 3)
          + b'\x07' + b'\x02\xaa\xbb' + b'\x03\xcc\xdd\xee'
          + bytes([1, 2, 3, 4])
          + struct.pack('>I', 14) + S1_BYTES + S1_BYTES
          + s16(s16(b'ab') + s16(b'c')))
PAY[4] = (S1_BYTES + struct.pack('>I', 12) + b'\x09' + S1_BYTES + s16(b'\x0a\x0b'))
PAY[5] = (struct.pack('>I', 1) + b'\x01' + b'\x55'
          + struct.pack('>I', 6) + b'\x02' + s16(b'abcd')
          + struct.pack('>I', 7) + b'\x03' + S1_BYTES
          + struct.pack('>H', 2) + struct.pack('>H', 1) + struct.pack('>H', 0x1234))
PAY[6] = (struct.pack('>I', 0xdeadbeef) + S1_BYTES + s16(b'typedef string') + s16(b'\x01\x02')
          + struct.pack('>I', 7) + struct.pack('>H', 2) + struct.pack('>H', 1) + struct.pack('>H', 0x4321)
          + b'\xff' + b'\x05')
PAY[7] = (b'\x00\x00' + b'\x11'
          + b'\x10\x01' + b'\x22\x33'
          + b'\x20\x02' + struct.pack('>I', 0x44556677)
          + b'\x30\x03' + struct.pack('>Q', 0x8899aabbccddeeff)
          + b'\x60\x04' + s16(b'abc')
          + b'\x60\x05' + s16(b'\x00\x00\x77' + b'\x10\x01\x88\x99')
          + b'\x50\x06' + b'\x03\xaa\xbb\xcc'
          + b'\x00\x08' + b'\x81'
          + b'\x00\x09' + b'\x01'
          + b'\x60\x0a' + s16(b'td')
          + b'\x40\x0b' + s16(b'wt4')
          + b'\x40\x0c' + struct.pack('>I', 12) + b'\x09' + S1_BYTES + s16(b'\x0a\x0b')   # struct S2, lol 32
          + b'\x40\x0d' + s16(b'\x01\x02\x03')                                        # array, lol 16
          + b'\x40\x0e' + b'\x03abc'                                                      # string, lol 8
          + b'\x10\x14' + b'\xde\xad')                              # unknown id 20 -> unparsed
PAY[8] = b'\x07' + struct.pack('>I', 1)


def build_main():
    pkts = []
    ip = [1]

    def udp(src, dst, sp, dp, msg):
        ip[0] += 1
        pkts.append(udp_pkt(src, dst, sp, dp, msg, ip[0]))

    sess = [0]

    def sn():
        sess[0] += 1
        return sess[0]

    # --- plain SOME/IP over UDP: every message type, return codes, names
    mtypes = [0x00, 0x01, 0x02, 0x80, 0x81, 0x40, 0x41, 0x42, 0xc0, 0xc1]
    for mt in mtypes:
        udp(B, A, 40001, UDP_PORT, someip(0x1234, 0x0001, 0x0100, sn(), b'\x01\x02\x03\x04', mtype=mt))
    for rc in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x20):
        udp(A, B, UDP_PORT, 40001, someip(0x1234, 0x0001, 0x0100, sn(), b'', mtype=0x81, rc=rc))
    # unknown message type, interface version 2, header only, odd lengths
    udp(B, A, 40001, UDP_PORT, someip(0x1234, 0x0001, 0x0100, sn(), b'\x00', mtype=0x1f, iver=2))
    udp(B, A, 40001, UDP_PORT, someip(0x1234, 0x0002, 0x0100, sn(), b''))
    # names from the UATs (service 0x2000, methods 1-3 and 0x8001, client 0x0100)
    udp(B, A, 40001, UDP_PORT, someip(SVC, 0x8001, 0x0000, sn(), b'\x00' * 3, mtype=0x02))
    # several messages in one datagram
    udp(B, A, 40001, UDP_PORT, someip(0x1234, 0x0010, 0x0100, sn(), b'one')
        + someip(0x1234, 0x0011, 0x0100, sn(), b'two!') + someip(0x1234, 0x0012, 0x0100, sn(), b''))
    # --- SOME/IP-TP: three segments in order, a request whose segments arrive out of
    # order, a response in one segment (no more segments), notification TP
    data = bytes(range(40))
    s_tp = sn()
    udp(B, A, 40001, UDP_PORT, tp_seg(0x1234, 0x0020, 0x0100, s_tp, 0, True, data[0:16]))
    udp(B, A, 40001, UDP_PORT, tp_seg(0x1234, 0x0020, 0x0100, s_tp, 16, True, data[16:32]))
    udp(B, A, 40001, UDP_PORT, tp_seg(0x1234, 0x0020, 0x0100, s_tp, 32, False, data[32:40]))
    s_tp = sn()
    udp(A, B, UDP_PORT, 40001, tp_seg(0x1234, 0x0021, 0x0100, s_tp, 16, False, data[16:24], mtype=0xa0))
    udp(A, B, UDP_PORT, 40001, tp_seg(0x1234, 0x0021, 0x0100, s_tp, 0, True, data[0:16], mtype=0xa0))
    udp(A, B, UDP_PORT, 40001, tp_seg(0x1234, 0x0022, 0x0000, sn(), 0, False, b'single', mtype=0x22))
    udp(A, B, UDP_PORT, 40001, tp_seg(0x1234, 0x0023, 0x0100, sn(), 0, False, b'', mtype=0xa1))
    # TP segments of different sessions interleaved
    sa, sb = sn(), sn()
    udp(B, A, 40001, UDP_PORT, tp_seg(0x1234, 0x0024, 0x0100, sa, 0, True, data[0:16]))
    udp(B, A, 40001, UDP_PORT, tp_seg(0x1234, 0x0024, 0x0100, sb, 0, True, data[0:16]))
    udp(B, A, 40001, UDP_PORT, tp_seg(0x1234, 0x0024, 0x0100, sb, 16, False, data[16:20]))
    udp(B, A, 40001, UDP_PORT, tp_seg(0x1234, 0x0024, 0x0100, sa, 16, False, data[16:24]))

    # --- payload dissector (needs the UATs, plain payload otherwise)
    udp(B, A, 40001, UDP_PORT, someip(SVC, 1, CLIENT, sn(), PAY[1]))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 2, CLIENT, sn(), PAY[2]))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 3, CLIENT, sn(), PAY[3]))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 4, CLIENT, sn(), PAY[4]))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 5, CLIENT, sn(), PAY[5]))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 6, CLIENT, sn(), PAY[6]))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 7, CLIENT, sn(), PAY[7]))
    udp(A, B, UDP_PORT, 40001, someip(SVC, 8, CLIENT, sn(), PAY[8], mtype=0x80))
    # a message with a configured method but another version or type has no list
    udp(B, A, 40001, UDP_PORT, someip(SVC, 1, CLIENT, sn(), PAY[1], iver=2))
    # method without a parameter list
    udp(B, A, 40001, UDP_PORT, someip(SVC, 0x7777, CLIENT, sn(), PAY[7]))

    # --- TCP: messages split over segments, several in one segment
    s = Stream(B, 40100, A, TCP_PORT)
    s.hs()
    s.send(someip(0x1234, 0x0003, 0x0100, sn(), b'tcp request'))
    s.recv(someip(0x1234, 0x0003, 0x0100, sess[0], b'tcp response', mtype=0x80))
    m = someip(0x1234, 0x0004, 0x0100, sn(), bytes(range(48)))
    s.send(m[:5])
    s.send(m[5:20])
    s.send(m[20:])
    s.recv(someip(0x1234, 0x0005, 0x0100, sn(), b'x', mtype=0x80)
           + someip(0x1234, 0x8002, 0, sn(), b'y', mtype=0x02) + someip(0x1234, 0x8003, 0, sn(), b'', mtype=0x02))
    # a message followed by the start of the next in the same segment
    m1 = someip(0x1234, 0x0006, 0x0100, sn(), b'first')
    m2 = someip(0x1234, 0x0007, 0x0100, sn(), b'second message')
    s.send(m1 + m2[:11])
    s.send(m2[11:])
    # payload messages over TCP (payload dissector)
    s.send(someip(SVC, 1, CLIENT, sn(), PAY[1]))
    pkts += s.pkts

    # a union with a 32 bit type field
    udp(B, A, 40001, UDP_PORT, someip(SVC, 18, CLIENT, sn(), b'\x01' + struct.pack('>I', 1) + b'\x55'))

    write_pcap('someip-coverage.pcap', pkts)


def build_malformed():
    pkts = []
    ip = [1000]

    def udp(src, dst, sp, dp, msg):
        ip[0] += 1
        pkts.append(udp_pkt(src, dst, sp, dp, msg, ip[0]))

    sn_ = [5000]

    def sn():
        sn_[0] += 1
        return sn_[0]

    # headers: length < 8, protocol version 2, length beyond the data, wrapped length
    udp(B, A, 40001, UDP_PORT, someip(0x1234, 1, 0x0100, sn(), b'\x00' * 4, length=4))
    udp(B, A, 40001, UDP_PORT, someip(0x1234, 1, 0x0100, sn(), b'\x00' * 4, pver=2))
    udp(B, A, 40001, UDP_PORT, someip(0x1234, 1, 0x0100, sn(), b'\x00' * 4, length=200))
    udp(B, A, 40001, UDP_PORT, someip(0x1234, 1, 0x0100, sn(), b'\x00' * 4, length=0xfffffff8))
    udp(B, A, 40001, UDP_PORT, someip(0x1234, 1, 0x0100, sn(), b'', length=0xffffffff))
    udp(B, A, 40001, UDP_PORT, struct.pack('>HHI', 0x1234, 1, 8) + b'\x00\x01')    # header cut short
    # TP: overlapping segments with different data, a segment beyond the first with length not
    # a multiple of 16 in the middle, too short for the TP header
    st = sn()
    udp(B, A, 40001, UDP_PORT, tp_seg(0x1234, 0x0030, 0x0100, st, 0, True, bytes(range(16))))
    udp(B, A, 40001, UDP_PORT, tp_seg(0x1234, 0x0030, 0x0100, st, 0, True, bytes(range(1, 17))))
    udp(B, A, 40001, UDP_PORT, tp_seg(0x1234, 0x0030, 0x0100, st, 16, True, bytes(range(5))))
    udp(B, A, 40001, UDP_PORT, tp_seg(0x1234, 0x0030, 0x0100, st, 32, False, bytes(range(5))))
    udp(B, A, 40001, UDP_PORT, someip(0x1234, 0x0031, 0x0100, sn(), b'\x00\x01', mtype=0x20))
    udp(B, A, 40001, UDP_PORT, someip(0x1234, 0x0031, 0x0100, sn(), b'', mtype=0x20))
    # reserved bits set in the TP header and the maximum offset
    udp(B, A, 40001, UDP_PORT, someip(0x1234, 0x0032, 0x0100, sn(), struct.pack('>I', 0xfffffff6) + b'xx', mtype=0x20))
    # a DTLS looking datagram (content type 22, version 0xfefd, length matches)
    dtls = (b'\x16\xfe\xfd' + b'\x00\x01' + b'\x00' * 6 + struct.pack('>H', 10) + b'\x00' * 10)
    udp(B, A, 40001, UDP_PORT, dtls)
    udp(B, A, 40009, 30509, dtls)
    # payload dissector: truncated and malformed payloads for the configured methods
    udp(B, A, 40001, UDP_PORT, someip(SVC, 1, CLIENT, sn(), PAY[1][:5]))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 1, CLIENT, sn(), PAY[1][:46]))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 1, CLIENT, sn(), b''))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 2, CLIENT, sn(), struct.pack('>H', 50) + b'short'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 2, CLIENT, sn(), b'\x00'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 2, CLIENT, sn(), s16(b'ok') + struct.pack('>I', 100)))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 2, CLIENT, sn(), s16(b'ok') + struct.pack('>I', 2) + b'ab' + b''))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 3, CLIENT, sn(), struct.pack('>H', 30) + b'abc'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 3, CLIENT, sn(), s16(b'\x01\x02\x03') + struct.pack('>HHH', 1, 2, 3)
                                       + b'\x30' + b'\x02\xaa'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 3, CLIENT, sn(), s16(b'') + struct.pack('>H', 1)))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 4, CLIENT, sn(), S1_BYTES + struct.pack('>I', 100) + b'x'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 4, CLIENT, sn(), S1_BYTES + b'\x00\x01'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 5, CLIENT, sn(), struct.pack('>I', 1) + b'\x09' + b'\x55'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 5, CLIENT, sn(), b'\x00\x00'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 5, CLIENT, sn(), struct.pack('>I', 1) + b'\x01\x55'
                                       + struct.pack('>I', 1) + b'\x01\x55' + struct.pack('>I', 1) + b'\x01\x55'
                                       + b'\x00\x02\x00'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 6, CLIENT, sn(), PAY[6][:20]))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 6, CLIENT, sn(), b''))
    # bitfield truncated
    udp(B, A, 40001, UDP_PORT, someip(SVC, 1, CLIENT, sn(), PAY[1][:len(PAY[1]) - 2 - 2 - 8 - 4 - 1]))
    # WTLV: malformed tags, types 4 with unusable config, truncated values
    udp(B, A, 40001, UDP_PORT, someip(SVC, 7, CLIENT, sn(), b'\x00'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 7, CLIENT, sn(), b'\x60\x04\xff\xff' + b'abc'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 7, CLIENT, sn(), b'\x60\x07' + s16(b'\x01\x55')))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 7, CLIENT, sn(), b'\x40\x00' + b'\x01\x02'))   # type 4 on a base type
    udp(B, A, 40001, UDP_PORT, someip(SVC, 7, CLIENT, sn(), b'\x40\x0c' + struct.pack('>I', 3) + b'abc'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 7, CLIENT, sn(), b'\x70\x04' + struct.pack('>I', 3) + b'abc'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 7, CLIENT, sn(), b'\x40\x0d' + b'\x00\x03' + b'\x01\x02\x03'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 7, CLIENT, sn(), b'\x40\x0e' + b'\x00\x03' + b'\x01\x02\x03'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 7, CLIENT, sn(), b'\x40\xff' + b'\x00\x03' + b'\x01\x02\x03'))  # unknown id
    # the reproducer of the NULL dereference fixed by "SOMEIP: Fix NULL dereference for a
    # missing typedef reference": a WTLV tag of wire type 4 for a typedef whose reference does not exist
    udp(B, A, 40001, UDP_PORT, someip(SVC, 14, CLIENT, sn(), struct.pack('>H', 0x4000) + b'\x02AB'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 16, CLIENT, sn(), b'\x40\x00' + s16(b'ab')))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 16, CLIENT, sn(), b'\x40\x01' + s16(b'ab')))
    # configuration errors
    for meth in (9, 10, 11, 12, 13):
        udp(B, A, 40001, UDP_PORT, someip(SVC, meth, CLIENT, sn(), b'\x00\x05abcde\x00\x00\x00\x00\x01\x02\x03\x04'))
    # dynamic array limits: too few and too many elements
    udp(B, A, 40001, UDP_PORT, someip(SVC, 13, CLIENT, sn(), b'\x01\xaa'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 13, CLIENT, sn(), b'\x05\xaa\xbb\xcc\xdd\xee'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 15, CLIENT, sn(), b'\x00' * 20))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 12, CLIENT, sn(), b'\x00\x01'))                 # struct, lol 24, too short
    udp(B, A, 40001, UDP_PORT, someip(SVC, 17, CLIENT, sn(), b'\x00\x00\x02\x01\x02'))       # array, lol 24
    udp(B, A, 40001, UDP_PORT, someip(SVC, 19, CLIENT, sn(), b'\x00\x01\x00\x00\x01\x55'))   # union, type 24
    udp(B, A, 40001, UDP_PORT, someip(SVC, 20, CLIENT, sn(), b'\x40\x00\x00\x01\x02'))      # WTLV 4, missing string
    udp(B, A, 40001, UDP_PORT, someip(SVC, 21, CLIENT, sn(), b'\x40\x00\x00\x01\x02'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 22, CLIENT, sn(), b'\x40\x00\x00\x01\x02'))
    udp(B, A, 40001, UDP_PORT, someip(SVC, 23, CLIENT, sn(), b'\x40\x00\x00\x01\x02'))
    # a DTLS looking datagram shorter than a SOME/IP header
    udp(B, A, 40001, UDP_PORT, b'\x16\xfe\xfd' + b'\x00\x01' + b'\x00' * 6 + struct.pack('>H', 2) + b'\x00\x00')
    # TCP: garbage in the stream, a length beyond the segment end
    s = Stream(B, 40101, A, TCP_PORT)
    s.hs()
    s.send(b'\x00\x00\x00\x00garbage that is no SOME/IP message at all')
    s.send(someip(0x1234, 3, 0x0100, sn(), b'ok'))
    s.send(someip(0x1234, 3, 0x0100, sn(), b'zzzz', length=1000))
    s.send(someip(0x1234, 3, 0x0100, sn(), b'abcd', pver=7)[:15])
    pkts += s.pkts
    write_pcap('someip-coverage-malformed.pcap', pkts)


# Invalid rows of the UAT tables: one row each, loaded by runcov.sh in its own
# configuration directory to reach the checks of the update callbacks.
BAD_UAT = [
    ('SOMEIP_service_identifiers', '"ffff","x"'), ('SOMEIP_service_identifiers', '"10000","x"'),
    ('SOMEIP_service_identifiers', '"1234",""'),
    ('SOMEIP_method_event_identifiers', '"ffff","1","x"'), ('SOMEIP_method_event_identifiers', '"10000","1","x"'),
    ('SOMEIP_method_event_identifiers', '"1234","ffff","x"'), ('SOMEIP_method_event_identifiers', '"1234","10000","x"'),
    ('SOMEIP_method_event_identifiers', '"1234","1",""'),
    ('SOMEIP_eventgroup_identifiers', '"10000","1","x"'), ('SOMEIP_eventgroup_identifiers', '"1234","10000","x"'),
    ('SOMEIP_eventgroup_identifiers', '"1234","1",""'),
    ('SOMEIP_client_identifiers', '"10000","1","x"'), ('SOMEIP_client_identifiers', '"1234","10000","x"'),
    ('SOMEIP_client_identifiers', '"1234","1",""'),
    ('SOMEIP_parameter_list', '"10000","1","1","0","FALSE","1","0","n","1","1","f"'),
    ('SOMEIP_parameter_list', '"2000","10000","1","0","FALSE","1","0","n","1","1","f"'),
    ('SOMEIP_parameter_list', '"2000","1","256","0","FALSE","1","0","n","1","1","f"'),
    ('SOMEIP_parameter_list', '"2000","1","1","100","FALSE","1","0","n","1","1","f"'),
    ('SOMEIP_parameter_list', '"2000","1","1","0","FALSE","1","0","","1","1","f"'),
    ('SOMEIP_parameter_list', '"2000","1","1","0","FALSE","1","1","n","1","1","f"'),
    ('SOMEIP_parameter_list', '"2000","1","1","0","FALSE","1","0","n","9","1","f"'),
    ('SOMEIP_parameter_list', '"2000","1","1","0","FALSE","1","0","n","1","1",""'),
    ('SOMEIP_parameter_list', '"2000","1","1","0","FALSE","1","0","n","1","1","a.b"'),
    ('SOMEIP_parameter_list', '"2000","1","1","0","FALSE","1","0","n","1","1","a b"'),
    ('SOMEIP_parameter_list', '"2000","1","1","0","FALSE","1","0","n","1","1","a\\001b"'),
    ('SOMEIP_parameter_base_types', '"1","","uint8","TRUE","8","8"'), ('SOMEIP_parameter_base_types', '"1","n","","TRUE","8","8"'),
    ('SOMEIP_parameter_base_types', '"1","n","uint8","TRUE","16","8"'), ('SOMEIP_parameter_base_types', '"1","n","uint16","TRUE","8","16"'),
    ('SOMEIP_parameter_base_types', '"1","n","uint32","TRUE","16","32"'), ('SOMEIP_parameter_base_types', '"1","n","uint64","TRUE","64","32"'),
    ('SOMEIP_parameter_base_types', '"1","n","uint24","TRUE","24","24"'),
    ('SOMEIP_parameter_base_types', '"1","n","int8","TRUE","16","8"'), ('SOMEIP_parameter_base_types', '"1","n","int16","TRUE","8","16"'),
    ('SOMEIP_parameter_base_types', '"1","n","int32","TRUE","16","32"'), ('SOMEIP_parameter_base_types', '"1","n","int64","TRUE","64","32"'),
    ('SOMEIP_parameter_base_types', '"1","n","int24","TRUE","24","24"'),
    ('SOMEIP_parameter_base_types', '"1","n","float32","TRUE","64","32"'), ('SOMEIP_parameter_base_types', '"1","n","float64","TRUE","32","64"'),
    ('SOMEIP_parameter_base_types', '"1","n","complex","TRUE","32","32"'),
    ('SOMEIP_parameter_strings', '"1","","ascii","FALSE","4","0","TRUE","0"'),
    ('SOMEIP_parameter_strings', '"1","n","ascii","TRUE","4","24","TRUE","0"'),
    ('SOMEIP_parameter_arrays', '"1","","1","1","1","f","0","0","1","0","0"'),
    ('SOMEIP_parameter_arrays', '"1","n","1","1","1","f","1","0","1","0","0"'),
    ('SOMEIP_parameter_arrays', '"1","n","1","1","1","","0","0","1","0","0"'),
    ('SOMEIP_parameter_arrays', '"1","n","1","1","1","a b","0","0","1","0","0"'),
    ('SOMEIP_parameter_arrays', '"1","n","9","1","1","f","0","0","1","0","0"'),
    ('SOMEIP_parameter_arrays', '"1","n","3","1","1","f","0","0","1","0","0"'),
    ('SOMEIP_parameter_structs', '"1","","0","0","FALSE","1","0","n","1","1","f"'),
    ('SOMEIP_parameter_structs', '"1","S","0","0","FALSE","1","0","","1","1","f"'),
    ('SOMEIP_parameter_structs', '"1","S","0","0","FALSE","1","0","n","1","1",""'),
    ('SOMEIP_parameter_structs', '"1","S","0","0","FALSE","1","0","n","1","1","a b"'),
    ('SOMEIP_parameter_structs', '"1","S","0","0","FALSE","1","1","n","1","1","f"'),
    ('SOMEIP_parameter_structs', '"1","S","0","0","FALSE","1","0","n","9","1","f"'),
    ('SOMEIP_parameter_structs', '"1","S","0","0","FALSE","1","0","n","4","1","f"'),
    ('SOMEIP_parameter_unions', '"1","","8","8","0","1","1","t","1","1","f"'),
    ('SOMEIP_parameter_unions', '"1","U","8","8","0","1","1","t","1","1","a b"'),
    ('SOMEIP_parameter_unions', '"1","U","8","8","0","1","1","","1","1","f"'),
    ('SOMEIP_parameter_unions', '"1","U","8","8","0","1","1","t","9","1","f"'),
    ('SOMEIP_parameter_unions', '"1","U","8","8","0","1","1","t","5","1","f"'),
    ('SOMEIP_parameter_typedefs', '"1","n","9","1"'), ('SOMEIP_parameter_typedefs', '"1","n","6","1"'),
    ('SOMEIP_parameter_enums', '"1","","1","1","1","0","v"'), ('SOMEIP_parameter_enums', '"1","E","1","1","1","0",""'),
    ('SOMEIP_parameter_enums', '"1","E","1","1","0","0","v"'), ('SOMEIP_parameter_enums', '"1","E","9","1","1","0","v"'),
    ('SOMEIP_parameter_enums', '"1","E","7","1","1","0","v"'),
    ('SOMEIP_parameter_bitfields', '"1","","8","1","0","b","f"'), ('SOMEIP_parameter_bitfields', '"1","B","7","1","0","b","f"'),
    ('SOMEIP_parameter_bitfields', '"1","B","8","0","0","b","f"'), ('SOMEIP_parameter_bitfields', '"1","B","8","1","8","b","f"'),
    ('SOMEIP_parameter_bitfields', '"1","B","8","1","0","","f"'),
]

if __name__ == '__main__':
    out = sys.argv[1]
    os.chdir(out)
    os.makedirs('cfg-uat', exist_ok=True)
    for name, text in uat_files().items():
        with open(os.path.join('cfg-uat', name), 'w') as fh:
            fh.write(text)
    with open('bad-uat-cases.txt', 'w') as fh:
        for name, text in BAD_UAT:
            fh.write(name + '\t' + text + '\n')
    build_main()
    build_malformed()
