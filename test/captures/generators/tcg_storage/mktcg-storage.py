#!/usr/bin/env python3
# Generates test/captures/tcg_storage_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the TCG Storage dissector
(packet-tcg-storage.c).

Usage: mktcg-storage.py <output directory>

The dissector is reached only through NVMe: Security Send / Security
Receive admin commands (SECP 01h and 02h) carry the TCG structures, and
packet-nvme.c hands the payload to the "nvme.security.secp" table. The
commands travel as NVMe-MI admin messages (MCTP over Linux cooked capture,
DLT 113), which is how the test captures of the tree reach NVMe. Every
packet is built with struct (helpers in nvmemi_lib.py were copied from
tools/gen-nvme-mi-test-capture.py); nothing is captured.

Writes:
  tcg-storage-coverage.pcapng            Level 0 Discovery with every feature
                                         descriptor, ComPackets with every
                                         token class, ComID management
  tcg-storage-coverage-malformed.pcapng  truncated and over-long structures,
                                         reserved tokens, out of range status
"""
import os
import struct
import sys
from nvmemi_lib import (
    admin_request_payload, admin_resp_with_data, epb, idb, make_packet, NVME_MI_TYPE_ADMIN, shb,
)

NVME_AQ_OPC_SECURITY_SEND = 0x81
NVME_AQ_OPC_SECURITY_RECV = 0x82


def security_cdw10(secp, spsp):
    return ((secp & 0xff) << 24) | ((spsp & 0xffff) << 8)


# ---------------------------------------------------------------- Level 0
def feat(code, version, data, minor=0, length=None):
    return (struct.pack('>HBB', code, ((version & 0x0f) << 4) | (minor & 0x0f),
                        len(data) if length is None else length) + data)


def l0(feats, rev=1, length=None, major=0):
    hdr = (struct.pack('>IHH', 44 + len(feats) if length is None else length, major, rev)
           + b'\0' * 8 + bytes(range(32)))
    return hdr + feats


def f_tper(flags=0x7d, n=12):
    return feat(0x0001, 1, bytes([flags]) + b'\0' * (n - 1))


def f_locking(flags=0xff, n=12):
    return feat(0x0002, 1, bytes([flags]) + b'\0' * (n - 1))


def f_geometry(align=1, n=32):
    d = (bytes([align]) + b'\0' * 7 + struct.pack('>IQQ', 512, 8, 0x1234)) + b'\0' * (n - 28)
    return feat(0x0003, 1, d[:n])


def f_siis(rev=0x20, flags=0x07, n=12):
    return feat(0x0005, 1, bytes([rev, flags]) + b'\0' * (n - 2))


def f_ssc1(code, base=0x1000, num=1, flags=0x01, n=12):
    return feat(code, 1, (struct.pack('>HHB', base, num, flags) + b'\xaa' * 7)[:n])


def f_sum(n=12, objs=3, flags=0x07):
    return feat(0x0201, 1, (struct.pack('>IB', objs, flags) + b'\0' * 7)[:n])


def f_datastore(n=16):
    return feat(0x0202, 1, (struct.pack('>HHII', 0, 8, 0x100000, 4096) + b'\0' * 4)[:n])


def f_opal2(code=0x0203, minor=2, n=16, flags=0x01):
    d = struct.pack('>HHBHHBB', 0x1000, 1, flags, 4, 8, 1, 0) + b'\0' * 5
    return feat(code, 2, (d + b'\0' * 16)[:n], minor=minor)


def f_lite(code, n=12):
    d = struct.pack('>HH', 0x2000, 1) + b'\x55' * 5 + bytes([1, 0, 0xee])
    return feat(code, 1, (d + b'\0' * 16)[:n])


def f_bsid(n=12, f1=0x03, f2=0x01):
    return feat(0x0402, 1, (bytes([f1, f2]) + b'\0' * 10)[:n])


def f_cnl(n=16, f1=0x07):
    d = bytes([f1]) + b'\0' * 3 + struct.pack('>III', 100, 40, 8)
    return feat(0x0403, 1, (d + b'\0' * 16)[:n])


def f_drm(n=32, mech=0x27, fmt=0x15, flags=0x03):
    d = (bytes([0, flags, mech, fmt]) + struct.pack('>HHH', 10, 20, 30) + b'\0' * 4
         + struct.pack('>H', 600) + b'\0' * 16)
    return feat(0x0404, 2, d[:n])


# ---------------------------------------------------------------- tokens
def uid(b):
    return bytes([0xa8]) + b


def tiny(v):
    return bytes([v & 0x3f])


def tiny_signed(v):
    return bytes([0x40 | (v & 0x3f)])


def short_uint(v, w):
    return bytes([0x80 | w]) + v.to_bytes(w, 'big')


def short_int(v, w):
    return bytes([0x90 | w]) + v.to_bytes(w, 'big', signed=True)


def short_bytes(d, cont=False):
    return bytes([0xa0 | (0x10 if cont else 0) | len(d)]) + d


def medium_bytes(d, cont=False):
    n = len(d)
    return bytes([0xd0 | (0x08 if cont else 0) | (n >> 8) & 7, n & 0xff]) + d


def medium_int(v, w, signed=False):
    n = w
    return bytes([0xc0 | (0x08 if signed else 0) | (n >> 8) & 7, n & 0xff]) + \
        v.to_bytes(w, 'big', signed=signed)


def long_int(v, w, signed=False):
    return bytes([0xe0 | (1 if signed else 0)]) + struct.pack('>I', w)[1:] + \
        v.to_bytes(w, 'big', signed=signed)


def long_bytes(d, cont=False):
    return bytes([0xe2 | (1 if cont else 0)]) + struct.pack('>I', len(d))[1:] + d


SL, EL, SN, EN, CALL, EOD, ES, STX, ETX, EMPTY = (bytes([x]) for x in
                                                   (0xf0, 0xf1, 0xf2, 0xf3, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xff))
SMUID = bytes.fromhex('00000000000000ff')
STARTSESSION = bytes.fromhex('000000000000ff02')
SYNCSESSION = bytes.fromhex('000000000000ff03')
PROPERTIES = bytes.fromhex('000000000000ff01')
ADMINSP = bytes.fromhex('0000020500000001')
LOCKINGSP = bytes.fromhex('0000020500000002')
THISSP = bytes.fromhex('0000000000000001')
GET = bytes.fromhex('0000000600000016')
SET = bytes.fromhex('0000000600000017')
AUTH = bytes.fromhex('000000060000001c')
RANGE1 = bytes.fromhex('0000080200030001')
CPIN = bytes.fromhex('0000000b00008402')


def status_list(st=0):
    return EOD + SL + tiny(st) + tiny(0) + tiny(0) + EL


def call(inv, meth, params):
    return CALL + uid(inv) + uid(meth) + SL + params + EL


def subpacket(tokens, kind=0, pad=True, length=None):
    p = (-len(tokens)) % 4 if pad else 0
    return (b'\0' * 6 + struct.pack('>HI', kind, len(tokens) if length is None else length)
            + tokens + b'\0' * p)


def packet(payload, tsn=0x1001, hsn=1, seq=1, acktype=0, ack=0, length=None):
    return struct.pack('>IIIHHII', tsn, hsn, seq, 0, acktype, ack,
                       len(payload) if length is None else length) + payload


def compacket(payload, comid=0x1000, ext=0, outstanding=0, mint=0, length=None, pad=b''):
    return struct.pack('>IHHIII', 0, comid, ext, outstanding, mint,
                       len(payload) if length is None else length) + payload + pad


def cp(tokens, tsn=0x1001, hsn=1, **kw):
    return compacket(packet(subpacket(tokens), tsn=tsn, hsn=hsn), **kw)


# ---------------------------------------------------------------- frames
class Cap:
    def __init__(self):
        self.pk = []
        self.tag = 0

    def _t(self):
        self.tag = (self.tag + 1) & 7
        return self.tag

    def recv(self, secp, spsp, data):
        t = self._t()
        self.pk.append(make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                                   admin_request_payload(NVME_AQ_OPC_SECURITY_RECV, ctrl_id=1, flags=0,
                                                         cns=security_cdw10(secp, spsp), dlen=len(data),
                                                         cdw11=len(data)), tag=t))
        self.pk.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0, admin_resp_with_data(data), tag=t))

    def send(self, secp, spsp, data):
        t = self._t()
        self.pk.append(make_packet(True, NVME_MI_TYPE_ADMIN, 0,
                                   admin_request_payload(NVME_AQ_OPC_SECURITY_SEND, ctrl_id=1, flags=0,
                                                         cns=security_cdw10(secp, spsp), dlen=len(data),
                                                         cdw11=len(data)) + data, tag=t))
        self.pk.append(make_packet(False, NVME_MI_TYPE_ADMIN, 0, admin_resp_with_data(b''), tag=t))

    def write(self, path):
        d = shb() + idb()
        for i, p in enumerate(self.pk):
            d += epb(p, 1709380800 * 1000000 + i * 1000000)
        open(path, 'wb').write(d)
        return len(self.pk)


def main(out):
    c = Cap()
    # -------------------------------------------------- Level 0 Discovery
    c.recv(1, 1, l0(f_tper() + f_locking() + f_geometry() + f_siis() + f_ssc1(0x0100) + f_ssc1(0x0200)))
    c.recv(1, 1, l0(f_sum() + f_datastore() + f_opal2() + f_lite(0x0301) + f_lite(0x0302) + f_lite(0x0303)))
    c.recv(1, 1, l0(f_opal2(0x0304, minor=0) + f_bsid() + f_cnl() + f_drm()
                    + feat(0xc001, 3, b'\1\2\3\4\5\6\7\x08') + feat(0x0999, 1, b'\0' * 4)
                    + feat(0x0405, 1, b'\xa5' * 12) + feat(0xffff, 0, b'')))
    # all flags clear, other bit patterns
    c.recv(1, 1, l0(f_tper(0) + f_locking(0) + f_geometry(0) + f_siis(0x10, 0) + f_ssc1(0x0100, flags=0)
                    + f_ssc1(0x0200, flags=0) + f_sum(objs=0, flags=0) + f_opal2(minor=0, flags=0)
                    + f_bsid(f1=0, f2=0) + f_cnl(f1=0) + f_drm(mech=0, fmt=0, flags=0)))
    c.recv(1, 1, l0(f_tper(0xff) + f_locking(0x55) + f_siis(0x20, 0x06) + f_bsid(f1=0x01, f2=0)
                    + f_cnl(f1=0x02) + f_cnl(f1=0x04) + f_drm(mech=0x18, fmt=0x2a) + f_sum(flags=0x01)
                    + f_sum(flags=0x02) + f_sum(flags=0x04)))
    # descriptors that are valid but shorter or longer than the usual layout
    c.recv(1, 1, l0(f_ssc1(0x0100, n=4) + f_ssc1(0x0200, n=4) + f_cnl(n=12) + f_drm(n=4) + f_drm(n=12)
                    + f_drm(n=16) + f_drm(n=20) + f_geometry(n=28) + f_geometry(n=36)
                    + f_opal2(n=12) + f_opal2(n=20) + f_tper(n=16) + f_locking(n=16) + f_siis(n=16)
                    + f_ssc1(0x0100, n=16) + f_sum(n=16) + f_datastore(n=20) + f_lite(0x0301, n=16)
                    + f_bsid(n=16) + f_cnl(n=20) + f_drm(n=36)))
    # an empty feature list and a discovery with Length shorter than the data
    c.recv(1, 1, l0(b''))
    c.recv(1, 1, l0(f_tper() + f_locking(), length=44 + 16) + b'\0' * 32)
    c.send(1, 1, bytes(range(16)))                       # ComID 0001h has no send payload
    c.recv(1, 1, l0(f_tper() + f_locking()) + b'\0' * 64)       # trailing padding after the structure
    # -------------------------------------------------- ComPackets and tokens
    c.send(1, 0x1000, cp(call(SMUID, PROPERTIES,
                              SN + short_bytes(b'HostProperties') + SL + SN + short_bytes(b'MaxComPacketSize')
                              + short_uint(2048, 2) + EN + SN + short_bytes(b'MaxPacketSize') + short_uint(2028, 2)
                              + EN + EL + EN) + EOD + SL + tiny(0) + tiny(0) + tiny(0) + EL))
    c.recv(1, 0x1000, cp(CALL + uid(SMUID) + uid(bytes.fromhex('000000000000ff77')) + SL + tiny(1) + EL
                         + status_list(0), tsn=0, hsn=0))
    c.send(1, 0x1000, cp(call(SMUID, STARTSESSION, tiny(1) + uid(ADMINSP) + tiny(1)) + status_list(0), tsn=0, hsn=0))
    c.recv(1, 0x1000, cp(call(SMUID, SYNCSESSION, tiny(1) + short_uint(0x1001, 2)) + status_list(0), tsn=0, hsn=1))
    # every status the table names
    for st in (0x01, 0x03, 0x0c, 0x12, 0x3f, 0x20):
        c.recv(1, 0x1000, cp(call(THISSP, GET, SL + SN + tiny(3) + tiny(4) + EN + EL) + status_list(st)))
    # Get/Set on named objects, Authenticate, GenKey, Next: UID name lookup
    for inv, meth in ((LOCKINGSP, GET), (RANGE1, SET), (CPIN, AUTH), (ADMINSP, bytes.fromhex('0000000600000803')),
                      (SMUID, bytes.fromhex('0000000600000601')), (THISSP, bytes.fromhex('000000060000000d')),
                      (bytes.fromhex('0000000900010001'), bytes.fromhex('0000000600000008')),
                      (bytes.fromhex('0000080400000000'), bytes.fromhex('0000000600000202')),
                      (bytes.fromhex('1234567890abcdef'), bytes.fromhex('0123456789abcdef'))):
        c.send(1, 0x1000, cp(call(inv, meth, SN + tiny(0) + tiny(1) + EN) + status_list(0)))
    # integers: tiny signed, short signed, medium/long, wide, continued bytes
    toks = (SL + tiny_signed(-5) + tiny_signed(7) + tiny(63) + short_int(-2, 1) + short_int(-300, 2)
            + short_int(5, 4) + short_int(-1, 8) + short_uint(0xffffffffffffffff, 8) + short_uint(0, 0)
            + short_uint(0x123456789abcdef012, 9) + short_uint(1, 15) + short_bytes(b'x' * 15)
            + short_bytes(b'cont', cont=True) + short_bytes(b'', cont=False)
            + medium_bytes(b'M' * 40) + medium_bytes(b'C' * 20, cont=True) + medium_int(1234, 2)
            + medium_int(-7, 3, signed=True) + medium_int(5, 12) + long_int(0x1122334455, 5)
            + long_int(-129, 2, signed=True) + long_bytes(b'L' * 33) + long_bytes(b'Q' * 9, cont=True)
            + long_int(1, 16) + EL)
    c.recv(1, 0x1000, cp(call(THISSP, GET, toks) + status_list(0)))
    # Empty atoms, transactions and end of session
    c.send(1, 0x1000, cp(STX + EMPTY + CALL + EMPTY + uid(LOCKINGSP) + EMPTY + uid(GET) + SL + EMPTY + tiny(1) + EL
                         + EOD + EMPTY + SL + tiny(0) + tiny(0) + tiny(0) + EL + ETX + ES))
    # a status list that closes without an integer, then more atoms: no status shown
    c.recv(1, 0x1000, cp(call(THISSP, GET, tiny(1)) + EOD + SL + SL + EL + tiny(5) + EL + tiny(6)))
    c.recv(1, 0x1000, cp(call(THISSP, GET, tiny(1)) + EOD + SL + SN + tiny(1) + EN + EL))
    c.recv(1, 0x1000, cp(call(THISSP, GET, tiny(1)) + EOD + SL + EL + tiny(5)))           # empty status list
    c.recv(1, 0x1000, compacket(packet(subpacket(tiny(1) + tiny(2) + tiny(3), pad=False)), pad=b'\0'))   # last pad missing
    c.recv(1, 0x1000, cp(call(THISSP, GET, tiny(1)) + EOD + SL + short_uint(0x0c, 1) + tiny(0) + EL))
    c.recv(1, 0x1000, cp(call(THISSP, GET, tiny(1)) + EOD + SL + medium_int(0x05, 2) + EL))
    c.recv(1, 0x1000, cp(call(THISSP, GET, tiny(1)) + EOD + SL + short_int(-1, 1) + tiny(0) + EL))
    # a Call that is not followed by two UIDs (not a method), end list without a start
    c.send(1, 0x1000, cp(CALL + tiny(1) + uid(GET) + EL + EL + EN + CALL + uid(SMUID) + tiny(1)))
    c.send(1, 0x1000, cp(CALL + uid(SMUID) + short_bytes(b'seven!!') + CALL + uid(SMUID) + uid(GET) + uid(SET)))
    # nested lists deeper than the 32 levels the dissector tracks, closed afterwards
    deep = SL * 40 + tiny(1) + EL * 40
    c.send(1, 0x1000, cp(deep))
    c.send(1, 0x1000, cp(SN * 33 + tiny(9) + EN * 5 + SL * 3 + EL))
    # unterminated lists
    c.send(1, 0x1000, cp(SL + SN + tiny(1)))
    # packets: several packets, several subpackets, credit control, unknown kind, zero-length
    sp = (subpacket(call(THISSP, GET, tiny(1)) + status_list(0))
          + subpacket(struct.pack('>I', 0x1234), kind=0x8001)
          + subpacket(struct.pack('>I', 0x1234) + b'extra!', kind=0x8001, pad=True)
          + subpacket(b'\xde\xad\xbe\xef\x01', kind=0x0005)
          + subpacket(b'', kind=0)
          + subpacket(tiny(1) + tiny(2) + tiny(3), kind=0))
    pk = packet(sp, tsn=0x1001, hsn=0x20, seq=7, acktype=1, ack=6) + \
        packet(subpacket(tiny(9)), tsn=0x1002, hsn=0x21, seq=8, acktype=2, ack=7) + \
        packet(b'', tsn=0, hsn=0, seq=0, acktype=0)
    c.send(1, 0x1000, compacket(pk, comid=0x1000, ext=0x0003, outstanding=100, mint=512, pad=b'\0' * 24))
    c.recv(1, 0x1000, compacket(b'', comid=0x1000, ext=1))            # empty ComPacket
    c.recv(1, 0x1001, cp(call(THISSP, GET, tiny(1)) + status_list(0), comid=0x1001))
    c.recv(1, 0x0002, cp(tiny(1), comid=0x0002))                       # SPSP other than 0001h and 1000h
    # -------------------------------------------------- SECP 02h
    c.send(2, 0x1000, struct.pack('>HHI', 0x1000, 0, 1) + b'\0' * 8)           # VERIFY COMID VALID
    c.send(2, 0x1000, struct.pack('>HHI', 0x1000, 0, 2))                       # STACK RESET, exactly 8 octets
    c.send(2, 0x1000, struct.pack('>HHI', 0x1000, 0, 7) + b'\0' * 16)          # unknown request code
    c.recv(2, 0x1000, struct.pack('>HHIHH', 0x1000, 0, 1, 0, 4) + b'\0' * 4)
    c.recv(2, 0x1000, struct.pack('>HHIHH', 0x1000, 0, 2, 0, 4) + b'\0' * 4)
    c.recv(2, 0x1000, struct.pack('>HHIHH', 0x1000, 0, 2, 0, 0))               # no data after the header
    c.recv(2, 0x1000, struct.pack('>HHIHH', 0x1000, 0, 9, 0, 8) + b'\xaa' * 8)
    c.send(2, 0x0004, b'\0' * 16)                                              # TPer Reset
    c.send(2, 0x0004, b'')                                                     # TPer Reset, no payload
    c.recv(2, 0x0000, struct.pack('>HH', 0x1000, 1) + b'\0' * 4)               # GET COMID
    c.recv(2, 0x0000, struct.pack('>HH', 0, 0))                                # none assigned, exactly 4
    c.send(2, 0x0000, struct.pack('>HHI', 0, 0, 1))                            # send to ComID 0 (ComID mgmt)
    n = c.write(os.path.join(out, 'tcg-storage-coverage.pcapng'))
    print('main capture: %d frames' % n)

    # ---------------------------------------------------------------- malformed
    m = Cap()
    good_l0 = l0(f_tper() + f_locking())
    m.recv(1, 1, good_l0[:30])                                  # shorter than the 48 octet header
    m.recv(1, 1, l0(f_tper(), length=4000))                     # Length past the end
    m.recv(1, 1, l0(f_tper() + b'\xff\xff'))                    # tail shorter than a descriptor header
    m.recv(1, 1, l0(feat(0x0002, 1, b'\x03' + b'\0' * 11, length=13)))   # unaligned length
    m.recv(1, 1, l0(feat(0x0002, 1, b'\x03' * 12, length=200)))          # length past the end
    shorts = (0x0001, 0x0002, 0x0003, 0x0005, 0x0100, 0x0200, 0x0201, 0x0202, 0x0203, 0x0301, 0x0302,
              0x0303, 0x0304, 0x0402, 0x0403, 0x0404)
    for code in shorts:
        m.recv(1, 1, l0(feat(code, 1, b'')))                    # no data: truncated
    for code, n in ((0x0003, 8), (0x0005, 1), (0x0100, 2), (0x0201, 4), (0x0202, 8), (0x0203, 8), (0x0301, 8),
                    (0x0402, 1), (0x0403, 8), (0x0404, 3)):
        m.recv(1, 1, l0(feat(code, 1, b'\x11' * n)))
    # ComPacket
    m.recv(1, 0x1000, cp(tiny(1))[:12])                         # shorter than the ComPacket header
    m.recv(1, 0x1000, compacket(packet(subpacket(tiny(1))), length=900))
    m.recv(1, 0x1000, compacket(packet(subpacket(tiny(1)))) + b'')
    m.recv(1, 0x1000, compacket(b'\x01\x02\x03\x04\x05'))       # fewer octets than a packet header
    m.recv(1, 0x1000, compacket(packet(subpacket(tiny(1)), length=500)))
    m.recv(1, 0x1000, compacket(packet(b'\x01\x02\x03')))      # packet payload shorter than a subpacket header
    m.recv(1, 0x1000, compacket(packet(subpacket(tiny(1) * 8, length=300))))   # subpacket length past the end
    m.recv(1, 0x1000, compacket(packet(subpacket(b'\x01\x02', kind=0x8001))))     # credit control too short
    # tokens
    for t in (b'\xf4', b'\xf5', b'\xf6', b'\xf7', b'\xfd', b'\xfe', b'\xe4', b'\xef'):
        m.recv(1, 0x1000, cp(tiny(1) + t + tiny(2)))
    m.recv(1, 0x1000, cp(tiny(1) + b'\xe0\x00'))                # long atom header cut
    m.recv(1, 0x1000, cp(tiny(1) + b'\xd0'))                    # medium atom header cut
    m.recv(1, 0x1000, cp(tiny(1) + b'\xaf\x01\x02'))            # short byte atom clamped
    m.recv(1, 0x1000, cp(tiny(1) + b'\x85\x01'))                # short integer atom clamped
    m.recv(1, 0x1000, cp(tiny(1) + b'\xe0\x00\x01\x00abc'))     # long atom clamped
    m.recv(1, 0x1000, cp(call(THISSP, GET, tiny(1)) + EOD + SL + short_uint(0x1234, 2) + tiny(5) + tiny(0) + EL))
    m.recv(1, 0x1000, cp(call(THISSP, GET, tiny(1)) + EOD + SL + short_uint(0x123456, 3) + EL))
    # ComID management
    m.send(2, 0x1000, b'\x10\x00\x00')                          # shorter than the request header
    m.recv(2, 0x1000, struct.pack('>HHI', 0x1000, 0, 2) + b'\0' * 2)    # shorter than the response header
    m.recv(2, 0x0000, b'\x10\x00')                              # GET COMID shorter than four
    n = m.write(os.path.join(out, 'tcg-storage-coverage-malformed.pcapng'))
    print('malformed capture: %d frames' % n)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
