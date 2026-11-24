#!/usr/bin/env python3
# Generates test/captures/btsdp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Bluetooth SDP dissector
(packet-btsdp.c).

The captures are Bluetooth HCI H4 with pseudo-header (link type 201): an
HCI Connection Complete event opens connection handle 1 (remote
11:22:33:44:55:66), then L2CAP connections to PSM 1 (SDP) carry every SDP
PDU, profile records with every attribute decoder the dissector has, all
data element types, and continued responses reassembled across
continuation states. Every packet is built from scratch with struct; no
captured traffic is used, and the addresses are made up.

Usage: mkbtsdp.py <output directory>

Writes:
  btsdp-coverage.pcap            the main capture (frame ranges in README)
  btsdp-coverage-malformed.pcap  truncated and inconsistent PDUs
  btsdp-coverage-nodir.pcap      H4 without pseudo-header (link type 187):
                                 no direction; SDP by Decode As on the CID
  btsdp-coverage-exported.pcap   SDP in an Exported PDU frame (no L2CAP
                                 data below), for the coverage run only
"""

import os
import struct
import sys

SENT, RECV = 0, 1
HANDLE = 0x0001
BD_ADDR = bytes.fromhex('665544332211')      # little endian 11:22:33:44:55:66

# L2CAP channels: (local CID, remote CID)
SDP_OUT = (0x0040, 0x0041)   # we query the remote SDP server
SDP_IN = (0x0042, 0x0070)    # the remote queries our SDP server
FTP_CHAN = (0x0044, 0x0045)  # dynamic PSM of the remote FTP record (OBEX)

PSM_FTP = 0x1007
PSM_LOCAL = 0x1009

UUID_BASE = bytes.fromhex('00000000' '00001000800000805F9B34FB')


# ---------------------------------------------------------------- writers

def write_pcap(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for usec, data, caplen in frames:
            if caplen is None:
                caplen = len(data)
            f.write(struct.pack('<IIII', usec // 1000000, usec % 1000000,
                                caplen, len(data)))
            f.write(data[:caplen])


class Capture:
    """Frames 10 ms apart."""

    def __init__(self, start=1700000000 * 1000000):
        self.t = start
        self.frames = []

    def add(self, data, gap=10000, caplen=None):
        self.t += gap
        self.frames.append((self.t, data, caplen))
        return len(self.frames)

    def next(self):
        return len(self.frames) + 1


# ---------------------------------------------------------------- HCI/L2CAP

def h4(direction, ptype, payload):
    return struct.pack('>I', direction) + bytes([ptype]) + payload


def hci_conn_complete():
    ev = struct.pack('<BH6sBB', 0, HANDLE, BD_ADDR, 1, 0)
    return h4(RECV, 0x04, bytes([0x03, len(ev)]) + ev)


def acl(direction, cid, payload):
    l2 = struct.pack('<HH', len(payload), cid) + payload
    a = struct.pack('<HH', (HANDLE & 0x0fff) | 0x2000, len(l2)) + l2
    return h4(direction, 0x02, a)


def l2cap_connect(cap, psm, chan, ident):
    lcid, rcid = chan
    cap.add(acl(SENT, 1, struct.pack('<BBHHH', 0x02, ident, 4, psm, lcid)))
    cap.add(acl(RECV, 1, struct.pack('<BBHHHHH', 0x03, ident, 8, rcid, lcid, 0, 0)))


def l2cap_connect_in(cap, psm, chan, ident):
    """The remote device connects to one of our PSMs."""
    lcid, rcid = chan
    cap.add(acl(RECV, 1, struct.pack('<BBHHH', 0x02, ident, 4, psm, rcid)))
    cap.add(acl(SENT, 1, struct.pack('<BBHHHHH', 0x03, ident, 8, lcid, rcid, 0, 0)))


def on_chan(direction, chan, payload):
    lcid, rcid = chan
    return acl(direction, rcid if direction == SENT else lcid, payload)


# ---------------------------------------------------------------- data elements

def de(type_, size_index, value=b''):
    return bytes([(type_ << 3) | size_index]) + value


def de_var(type_, value, width=1):
    """String/sequence/alternative/URL with an 8, 16 or 32 bit length."""
    if width == 1:
        return de(type_, 5, bytes([len(value)]) + value)
    if width == 2:
        return de(type_, 6, struct.pack('>H', len(value)) + value)
    return de(type_, 7, struct.pack('>I', len(value)) + value)


def nil():
    return b'\x00'


def u8(v):
    return de(1, 0, struct.pack('>B', v))


def u16(v):
    return de(1, 1, struct.pack('>H', v))


def u32(v):
    return de(1, 2, struct.pack('>I', v))


def u64(v):
    return de(1, 3, struct.pack('>Q', v))


def u128(b):
    return de(1, 4, b)


def i8(v):
    return de(2, 0, struct.pack('>b', v))


def i16(v):
    return de(2, 1, struct.pack('>h', v))


def i32(v):
    return de(2, 2, struct.pack('>i', v))


def i64(v):
    return de(2, 3, struct.pack('>q', v))


def uuid16(v):
    return de(3, 1, struct.pack('>H', v))


def uuid32(v):
    return de(3, 2, struct.pack('>I', v))


def uuid128(b):
    return de(3, 4, b)


def uuid128_sig(v):
    """A 16-bit UUID spelled out on the Bluetooth base UUID."""
    return uuid128(struct.pack('>I', v) + UUID_BASE[4:])


def text(s, width=1):
    return de_var(4, s.encode() if isinstance(s, str) else s, width)


def boolean(v):
    return de(5, 0, bytes([1 if v else 0]))


def seq(*items, width=1):
    return de_var(6, b''.join(items), width)


def alt(*items, width=1):
    return de_var(7, b''.join(items), width)


def url(s, width=1):
    return de_var(8, s.encode(), width)


def record(*pairs):
    """An attribute list: (id, value) pairs."""
    return seq(*[u16(a) + v for a, v in pairs], width=2)


def records(*recs):
    return seq(*recs, width=2)


def cls(*uuids):
    return (0x0001, seq(*[uuid16(u) for u in uuids]))


def handle(h):
    return (0x0000, u32(h))


def pdl(*protos):
    return (0x0004, seq(*[seq(*p) for p in protos]))


def l2cap_pdl(psm, *more):
    return pdl((uuid16(0x0100), u16(psm)), *more)


def profile(uuid, version):
    return (0x0009, seq(seq(uuid16(uuid), u16(version))))


def name(s):
    return (0x0100, text(s))


# ---------------------------------------------------------------- SDP PDUs

def sdp_pdu(pdu_id, tid, params, plen=None):
    if plen is None:
        plen = len(params)
    return struct.pack('>BHH', pdu_id, tid, plen) + params


def cont(state=b''):
    return bytes([len(state)]) + state


def pattern(*uuids):
    return seq(*[u if isinstance(u, bytes) else uuid16(u) for u in uuids])


def all_attrs():
    return seq(u32(0x0000FFFF))


class Sdp:
    """SDP transactions on one L2CAP channel. client is the direction of
    the requests (SENT: we ask the remote, RECV: the remote asks us)."""

    def __init__(self, cap, chan, client=SENT, tid=0):
        self.cap = cap
        self.chan = chan
        self.client = client
        self.server = RECV if client == SENT else SENT
        self.tid = tid

    def req(self, pdu_id, params, tid=None, caplen=None):
        if tid is None:
            self.tid += 1
            tid = self.tid
        return self.cap.add(on_chan(self.client, self.chan, sdp_pdu(pdu_id, tid, params)),
                            caplen=caplen)

    def rsp(self, pdu_id, params, tid=None, caplen=None, plen=None):
        if tid is None:
            tid = self.tid
        return self.cap.add(on_chan(self.server, self.chan, sdp_pdu(pdu_id, tid, params, plen)),
                            caplen=caplen)

    # Service Search
    def ss_req(self, pat, maxcount=16, state=b'', tid=None):
        return self.req(0x02, pat + struct.pack('>H', maxcount) + cont(state), tid)

    def ss_rsp(self, total, handles, state=b'', tid=None):
        p = struct.pack('>HH', total, len(handles))
        p += b''.join(struct.pack('>I', h) for h in handles)
        return self.rsp(0x03, p + cont(state), tid)

    # Service Attribute
    def sa_req(self, rec, ids, maxbytes=0xFFFF, state=b'', tid=None):
        return self.req(0x04, struct.pack('>IH', rec, maxbytes) + ids + cont(state), tid)

    def sa_rsp(self, chunk, state=b'', tid=None):
        return self.rsp(0x05, struct.pack('>H', len(chunk)) + chunk + cont(state), tid)

    # Service Search Attribute
    def ssa_req(self, pat, ids=None, maxbytes=0xFFFF, state=b'', tid=None):
        if ids is None:
            ids = all_attrs()
        return self.req(0x06, pat + struct.pack('>H', maxbytes) + ids + cont(state), tid)

    def ssa_rsp(self, chunk, state=b'', tid=None):
        return self.rsp(0x07, struct.pack('>H', len(chunk)) + chunk + cont(state), tid)


# ---------------------------------------------------------------- records

def generic_record():
    """Every universal attribute (0x0000-0x000D, 0x0100-0x0102) on a
    custom 128-bit service class."""
    custom = bytes.fromhex('0123456789abcdef0011223344556677')
    return record(
        handle(0x00010010),
        (0x0001, seq(uuid128(custom), uuid16(0x1101), uuid32(0x00001201))),
        (0x0002, u32(0x00000007)),
        (0x0003, uuid128(bytes.fromhex('fedcba98765432100011223344556677'))),
        pdl((uuid16(0x0100), u16(0x0003)),
            (uuid16(0x0003), u8(5)),
            (uuid16(0x0008),)),
        (0x0005, seq(uuid16(0x1002), uuid32(0x12345678))),
        (0x0006, seq(u16(0x656e), u16(0x006a), u16(0x0100),
                     u16(0x6672), u16(0x006a), u16(0x0110))),
        (0x0007, u32(3600)),
        (0x0008, u8(0xff)),
        (0x0009, seq(seq(uuid16(0x1101), u16(0x0102)),
                     seq(uuid16(0x1201), u16(0x0100)))),
        (0x000A, url('http://example.com/doc')),
        (0x000B, url('http://example.com/exe')),
        (0x000C, url('http://example.com/icon.png')),
        (0x000D, seq(seq(seq(uuid16(0x0100), u16(0x1011)), seq(uuid16(0x0008))),
                     seq(seq(uuid16(0x0100), u16(0x1013)),
                         seq(uuid16(0x0017), u16(0x0104))))),
        name('Generic Service'),
        (0x0101, text('Every universal attribute')),
        (0x0102, text('Example Provider')),
    )


def types_record():
    """Attributes without a decoder of their own: every data element type
    and size."""
    return record(
        handle(0x00010011),
        (0x0001, seq(uuid128(bytes.fromhex('a0a1a2a3a4a5a6a7a8a9aaabacadaeaf')))),
        (0x0300, nil()),
        (0x0301, u8(200)),
        (0x0302, u16(0xBEEF)),
        (0x0303, u32(0xDEADBEEF)),
        (0x0304, u64(0x0123456789ABCDEF)),
        (0x0305, i8(-5)),
        (0x0306, i16(-300)),
        (0x0307, i32(-70000)),
        (0x0308, i64(-5000000000)),
        (0x0309, uuid16(0x1105)),
        (0x030A, uuid32(0x0000110A)),
        (0x030B, uuid32(0x89ABCDEF)),
        (0x030C, uuid128_sig(0x110B)),
        (0x030D, uuid128(bytes.fromhex('00112233445566778899aabbccddeeff'))),
        (0x030E, text('short string')),
        (0x030F, text('string with 16-bit length', width=2)),
        (0x0310, text('string with 32-bit length', width=4)),
        (0x0311, text('')),
        (0x0312, boolean(True)),
        (0x0313, boolean(False)),
        (0x0314, seq(u8(1), seq(u16(2), text('nested')), alt(u8(3), u16(4)))),
        (0x0315, seq(u8(9), width=2)),
        (0x0316, seq(u16(0x1234), width=4)),
        (0x0317, alt(text('first'), text('second'))),
        (0x0318, alt(u8(1), width=2)),
        (0x0319, url('http://example.com/')),
        (0x031A, url('http://example.com/16', width=2)),
        (0x031B, de(9, 1, b'\x12\x34')),               # reserved type 9
        (0x031C, seq()),                               # empty sequence
        (0x031D, u128(bytes(range(0xf0, 0x100)))),
    )


def did_records():
    """Device ID records: Vendor ID Source 1 (Bluetooth SIG), 2 (USB
    Implementer's Forum) and an unknown source."""
    def did(h, source, vendor, product):
        return record(
            handle(h), cls(0x1200),
            (0x0200, u16(0x0103)),
            (0x0201, u16(vendor)),
            (0x0202, u16(product)),
            (0x0203, u16(0x0123)),
            (0x0204, boolean(h == 0x00010020)),
            (0x0205, u16(source)),
            (0x0206, u16(0x0042)),       # not a DID attribute
        )
    return [did(0x00010020, 1, 0x000F, 0x1234),
            did(0x00010021, 2, 0x046D, 0xC52B),
            did(0x00010022, 3, 0x1111, 0x2222)]


def hdp_records():
    """Health Device Profile: a source with Data Exchange Specification
    0x01 (IEEE 11073-20601) and a sink without it."""
    src = record(
        handle(0x00010030), cls(0x1401, 0x1400),
        l2cap_pdl(0x1001, (uuid16(0x001E), u16(0x0100))),
        (0x000D, seq(seq(seq(uuid16(0x0100), u16(0x1003)), seq(uuid16(0x001F))))),
        (0x0200, seq(seq(u8(1), u16(0x1004), u8(0x00), text('Pulse Oximeter')),
                     seq(u8(2), u16(0x1007), u8(0x01), text('Blood Pressure')))),
        (0x0301, u8(0x01)),
        (0x0302, u8(0x1E)),
    )
    sink = record(
        handle(0x00010031), cls(0x1402),
        (0x0200, seq(seq(u8(3), u16(0x1068), u8(0x01), text('Thermometer')))),
        (0x0302, u8(0x02)),
    )
    # Data Exchange Specification as a 16-bit 0x0001: the only encoding
    # the 2-octet lookup of the dissector takes as IEEE 11073-20601
    hdp = record(
        handle(0x00010032), cls(0x1400),
        (0x0200, seq(seq(u8(4), u16(0x100F), u8(0x00), text('Scale')))),
        (0x0301, u16(0x0001)),
    )
    return [src, sink, hdp]


def profile_records_1():
    """Audio, telephony and simple profiles."""
    return [
        record(handle(0x00010040), cls(0x110B),
               l2cap_pdl(0x0019, (uuid16(0x0019), u16(0x0103))),
               profile(0x110D, 0x0103), (0x0311, u16(0x000F))),
        record(handle(0x00010041), cls(0x110A), (0x0311, u16(0x000F))),
        record(handle(0x00010042), cls(0x110D), (0x0311, u16(0x0003))),
        record(handle(0x00010043), cls(0x110E), (0x0311, u16(0x03CF))),
        record(handle(0x00010044), cls(0x110F, 0x110E), (0x0311, u16(0x0041))),
        record(handle(0x00010045), cls(0x110C), (0x0311, u16(0x01FF))),
        record(handle(0x00010046), cls(0x1108, 0x1203), (0x0302, boolean(True))),
        record(handle(0x00010047), cls(0x1131), (0x0302, boolean(False))),
        record(handle(0x00010048), cls(0x1104), (0x0301, seq(u8(1), u8(3), u8(5), u8(7), u8(0x42)))),
        record(handle(0x00010049), cls(0x1109), (0x0311, u8(0x02))),
        record(handle(0x0001004A), cls(0x111E), (0x0311, u16(0x003F))),
        record(handle(0x0001004B), cls(0x111F),
               pdl((uuid16(0x0100),), (uuid16(0x0003), u8(3))),
               (0x0301, u8(0x01)), (0x0311, u16(0x003F))),
        record(handle(0x0001004C), cls(0x1111),
               (0x0302, boolean(True)), (0x0303, boolean(False)),
               (0x0304, boolean(True)), (0x0305, boolean(False))),
        record(handle(0x0001004D), cls(0x1103),
               (0x0305, boolean(True)), (0x0306, text('+++'))),
        record(handle(0x0001004E), cls(0x1135), (0x0200, u16(0x0000))),
        record(handle(0x0001004F), cls(0x1136), (0x0200, u16(0x0001))),
    ]


def profile_records_2():
    """Object exchange profiles (GOEP L2CAP PSMs)."""
    return [
        record(handle(0x00010050), cls(0x112F),
               pdl((uuid16(0x0100),), (uuid16(0x0003), u8(19)), (uuid16(0x0008),)),
               (0x0200, u16(0x1005)), (0x0314, u8(0x0F)), (0x0317, u32(0x000003FF))),
        record(handle(0x00010051), cls(0x1130), (0x0314, u8(0x01))),
        record(handle(0x00010052), cls(0x1106),
               pdl((uuid16(0x0100),), (uuid16(0x0003), u8(10)), (uuid16(0x0008),)),
               (0x0200, u16(PSM_FTP))),
        record(handle(0x00010053), cls(0x1132),
               (0x0200, u16(0x1015)), (0x0315, u8(0)), (0x0316, u8(0x0F)),
               (0x0317, u32(0x0000007F))),
        record(handle(0x00010054), cls(0x1134), (0x0315, u8(1)), (0x0316, u8(0x02))),
        record(handle(0x00010055), cls(0x1133), (0x0200, u16(0x1017)), (0x0317, u32(0x00000003))),
        record(handle(0x00010056), cls(0x1105),
               (0x0200, u16(0x1019)), (0x0303, seq(u8(1), u8(2), u8(3), u8(4), u8(5), u8(6), u8(0xFF)))),
        record(handle(0x00010057), cls(0x111B),
               (0x0200, u16(0x101B)), (0x0310, u8(0x0F)), (0x0311, u16(0x01FF)),
               (0x0312, u32(0x00016FFF)), (0x0313, u64(1 << 33))),
        record(handle(0x00010058), cls(0x111A), (0x0310, u8(0x01))),
        record(handle(0x00010059), cls(0x111D), (0x0200, u16(0x101D)), (0x0312, u32(0x00001001))),
        record(handle(0x0001005A), cls(0x111C), (0x0200, u16(0x101F)), (0x0312, u32(0x000007E1))),
        record(handle(0x0001005B), cls(0x113C), (0x0315, u8(2)), (0x0317, u32(0x0000007F))),
        record(handle(0x0001005C), cls(0x113D), (0x0315, u8(3)), (0x0317, u32(0x00000002))),
        record(handle(0x0001005D), cls(0x113A),
               (0x0200, u64(0x0000000000FFFFFF)), (0x0201, u64(0x00000000000FFFFF)),
               (0x0202, u16(0x0007))),
        record(handle(0x0001005E), cls(0x113B), (0x0202, u16(0x0001))),
    ]


def profile_records_3():
    """Printing, imaging, networking and WAP profiles."""
    bpp = [
        (0x0350, text('application/vnd.pwg-xhtml-print+xml:0.95')),
        (0x0352, u128(bytes(range(16)))),
        (0x0354, text('image/jpeg:')),
        (0x0356, boolean(True)),
        (0x0358, text('MFG:Example;MDL:Printer;')),
        (0x035A, text('Example Printer')),
        (0x035C, text('Room 1')),
        (0x035E, boolean(False)),
        (0x0360, text('envelope')),
        (0x0362, u16(210)),
        (0x0364, u16(297)),
        (0x0366, boolean(True)),
        (0x0368, text('application/vnd.pwg-xhtml-print+xml:1.0')),
        (0x0370, boolean(True)),
        (0x0372, boolean(False)),
        (0x0374, url('http://printer.example/ref')),
        (0x0376, url('http://printer.example/direct')),
        (0x037A, text('Printer device')),
    ]
    return [
        record(handle(0x00010060), cls(0x1118), *bpp),
        record(handle(0x00010061), cls(0x1119), (0x0356, boolean(False))),
        record(handle(0x00010062), cls(0x1122), (0x035A, text('BPP'))),
        record(handle(0x00010063), cls(0x1123), (0x0362, u16(100))),
        record(handle(0x00010064), cls(0x1121),
               (0x0368, text('application/xhtml+xml')),
               (0x0378, url('http://printer.example/admin'))),
        record(handle(0x00010065), cls(0x1126),
               (0x0300, text('MFG:Example;CMD:PCL;')), (0x0302, text('HCRP printer')),
               (0x0304, text('Friendly')), (0x0306, text('Hall'))),
        record(handle(0x00010066), cls(0x1125), (0x0302, text('HCRP'))),
        record(handle(0x00010067), cls(0x1127), (0x0304, text('Scanner'))),
        record(handle(0x00010068), cls(0x1117),
               pdl((uuid16(0x0100), u16(0x000F)),
                   (uuid16(0x000F), u16(0x0100), seq(u16(0x0800), u16(0x0806), u16(0x86DD)))),
               (0x030A, u16(0x0001)), (0x030D, text('10.0.0.0/8')),
               (0x0200, text('192.168.0.0/16')), (0x030E, text('fe80::/10'))),
        record(handle(0x00010069), cls(0x1116),
               (0x030A, u16(0x0002)), (0x030B, u16(0x0005)), (0x030C, u32(10000000)),
               (0x030D, text('172.16.0.0/12')), (0x0200, text('10.1.0.0/16')),
               (0x030E, text('2001:db8::/32'))),
        record(handle(0x0001006A), cls(0x1115), (0x030A, u16(0x0000))),
        record(handle(0x0001006B), cls(0x1113),
               (0x0306, u32(0x0A000001)), (0x0307, u8(0x02)),
               (0x0308, text('http://wap.example/')), (0x0309, u8(0x03))),
        record(handle(0x0001006C), cls(0x1114), (0x0307, u8(0x01))),
        record(handle(0x0001006D), cls(0x1112, 0x1203),
               pdl((uuid16(0x0100), u16(0x001F)), (uuid16(0x0007), u16(0x0001), u16(0x0010)))),
    ]


def hid_record(h, with_class=True):
    attrs = [handle(h)]
    if with_class:
        attrs.append(cls(0x1124))
    attrs += [
        l2cap_pdl(0x0011, (uuid16(0x0011),)),
        (0x000D, seq(seq(seq(uuid16(0x0100), u16(0x0013)), seq(uuid16(0x0011))))),
        (0x0006, seq(u16(0x656e), u16(0x006a), u16(0x0100))),
        name('Keyboard'),
        (0x0200, u16(0x0100)),
        (0x0201, u16(0x0111)),
        (0x0202, u8(0x40)),
        (0x0203, u8(33)),
        (0x0204, boolean(True)),
        (0x0205, boolean(True)),
        (0x0206, seq(seq(u8(0x22), text(bytes.fromhex('05010906a101050719e029e7150025019508750181029501750881010507190029651500256595067508810091c0')),
                         ), seq(u8(0x23), text(b'\x01\x02')))),
        (0x0207, seq(seq(u16(0x0409), u16(0x0100)), seq(u16(0x0407), u16(0x0110)))),
        (0x0208, boolean(False)),
        (0x0209, boolean(True)),
        (0x020A, boolean(True)),
        (0x020B, u16(0x0101)),
        (0x020C, u16(3200)),
        (0x020D, boolean(False)),
        (0x020E, boolean(True)),
        (0x020F, u16(800)),
        (0x0210, u16(3200)),
        (0x0211, u8(1)),                     # not a HID attribute
    ]
    return record(*attrs)


def chunks(data, n):
    """Split data into n nearly equal pieces."""
    size = (len(data) + n - 1) // n
    return [data[i:i + size] for i in range(0, len(data), size)]


# ---------------------------------------------------------------- main capture

def main_capture():
    cap = Capture()
    marks = {}
    cap.add(hci_conn_complete())
    l2cap_connect(cap, 0x0001, SDP_OUT, 1)
    s = Sdp(cap, SDP_OUT)

    # Service Search
    marks['service search'] = cap.next()
    s.ss_req(pattern(0x1124), 10)
    s.ss_rsp(2, [0x00010000, 0x00010001])
    # Continued Service Search: two handles, then one more
    marks['continued service search'] = cap.next()
    s.ss_req(pattern(uuid32(0x00001105), uuid128_sig(0x1105)), 2)
    s.ss_rsp(3, [0x00010002, 0x00010003], state=b'\x00\x02')
    s.ss_req(pattern(uuid32(0x00001105), uuid128_sig(0x1105)), 2, state=b'\x00\x02')
    s.ss_rsp(3, [0x00010004])
    s.ss_req(pattern(uuid128(bytes.fromhex('0123456789abcdef0011223344556677')), 0x0100), 5)
    s.ss_rsp(0, [])

    # Service Attribute: the HID record found above (the search UUID names
    # the requested attributes), then one without a ServiceClassIDList
    marks['service attribute'] = cap.next()
    s.sa_req(0x00010000, seq(u32(0x00000001), u16(0x0206), u32(0x02000210)))
    s.sa_rsp(hid_record(0x00010000))
    s.sa_req(0x00010001, all_attrs())
    s.sa_rsp(hid_record(0x00010001, with_class=False))
    # A record handle nobody searched for: generic attribute names
    s.sa_req(0x00010010, seq(u16(0x0100), u32(0x00000004)))
    s.sa_rsp(generic_record())
    # ... and a record without a ServiceClassIDList: no service UUID at all
    s.sa_req(0x00010012, seq(u16(0x0100)))
    s.sa_rsp(record(name('Nameless')))

    # Continued Service Attribute response in three parts with 16-octet
    # continuation states
    marks['continued service attribute'] = cap.next()
    data = types_record()
    parts = chunks(data, 3)
    st1 = bytes.fromhex('5101020304050607 08090a0b0c0d0e0f'.replace(' ', ''))
    st2 = bytes.fromhex('5201020304050607 08090a0b0c0d0e0f'.replace(' ', ''))
    s.sa_req(0x00010011, all_attrs(), maxbytes=len(parts[0]))
    s.sa_rsp(parts[0], state=st1)
    s.sa_req(0x00010011, all_attrs(), maxbytes=len(parts[1]), state=st1)
    s.sa_rsp(parts[1], state=st2)
    s.sa_req(0x00010011, all_attrs(), maxbytes=len(parts[2]), state=st2)
    s.sa_rsp(parts[2])

    # Service Search Attribute with the profile records
    marks['generic and types records'] = cap.next()
    s.ssa_req(pattern(0x1002))
    s.ssa_rsp(records(generic_record(), types_record()))
    marks['DID records'] = cap.next()
    s.ssa_req(pattern(0x1200), seq(u16(0x0201), u16(0x0202), u32(0x02030205)))
    s.ssa_rsp(records(*did_records()))
    # A DID record with a single attribute (the search UUID makes it DID)
    s.ssa_req(pattern(0x1200), seq(u16(0x0201)))
    s.ssa_rsp(records(record((0x0201, u16(0x000F)))))
    marks['HDP records'] = cap.next()
    s.ssa_req(pattern(0x1400))
    s.ssa_rsp(records(*hdp_records()))
    marks['profile records 1'] = cap.next()
    s.ssa_req(pattern(0x0100, 0x1203))
    s.ssa_rsp(records(*profile_records_1()))
    marks['profile records 2'] = cap.next()
    s.ssa_req(pattern(0x0008), seq(u32(0x0000FFFF), u16(0x0317)))
    s.ssa_rsp(records(*profile_records_2()))
    marks['profile records 3'] = cap.next()
    s.ssa_req(pattern(uuid128_sig(0x0100)))
    s.ssa_rsp(records(*profile_records_3()))

    # Continued Service Search Attribute response in three parts with
    # multi-octet continuation states
    marks['continued service search attribute'] = cap.next()
    data = records(hid_record(0x00010070), *hdp_records())
    parts = chunks(data, 3)
    st1 = bytes.fromhex('a1a2a3a4a5a6')
    st2 = bytes.fromhex('b1b2b3b4b5b6b7b8b9babbbcbdbe')
    s.ssa_req(pattern(0x1124), maxbytes=len(parts[0]))
    s.ssa_rsp(parts[0], state=st1)
    s.ssa_req(pattern(0x1124), maxbytes=len(parts[1]), state=st1)
    s.ssa_rsp(parts[1], state=st2)
    s.ssa_req(pattern(0x1124), maxbytes=len(parts[2]), state=st2)
    s.ssa_rsp(parts[2])

    # Two interleaved continued transactions whose 8-octet continuation
    # states differ only in the last octet
    marks['interleaved continuations'] = cap.next()
    data_a = records(*did_records())
    data_b = records(*hdp_records())
    pa = chunks(data_a, 2)
    pb = chunks(data_b, 2)
    st_a = bytes.fromhex('0000000000000001')
    st_b = bytes.fromhex('0000000000000002')
    s.ssa_req(pattern(0x1200), maxbytes=len(pa[0]))
    s.ssa_rsp(pa[0], state=st_a)
    s.ssa_req(pattern(0x1400), maxbytes=len(pb[0]))
    s.ssa_rsp(pb[0], state=st_b)
    s.ssa_req(pattern(0x1200), maxbytes=len(pa[1]), state=st_a)
    s.ssa_rsp(pa[1])
    s.ssa_req(pattern(0x1400), maxbytes=len(pb[1]), state=st_b)
    s.ssa_rsp(pb[1])

    # Error response and an unknown PDU
    marks['error response'] = cap.next()
    s.sa_req(0x0001FFFF, all_attrs())
    s.rsp(0x01, struct.pack('>H', 0x0002))
    s.req(0x08, b'\x01\x02')

    # The remote device queries our SDP server: our record on a dynamic
    # PSM; the remote connects to it
    marks['remote queries us'] = cap.next()
    l2cap_connect_in(cap, 0x0001, SDP_IN, 2)
    r = Sdp(cap, SDP_IN, client=RECV, tid=0x100)
    r.ssa_req(pattern(0x1105))
    r.ssa_rsp(records(record(handle(0x00020000), cls(0x1105),
                             pdl((uuid16(0x0100),), (uuid16(0x0003), u8(9)), (uuid16(0x0008),)),
                             (0x0200, u16(PSM_LOCAL)), name('OBEX Object Push'))))

    # Connect to the FTP record's GOEP L2CAP PSM: an OBEX Connect
    marks['FTP PSM'] = cap.next()
    l2cap_connect(cap, PSM_FTP, FTP_CHAN, 3)
    cap.add(on_chan(SENT, FTP_CHAN, struct.pack('>BHBBH', 0x80, 7, 0x10, 0, 0x2000)))
    return cap, marks


# ---------------------------------------------------------------- malformed

def malformed_capture():
    cap = Capture()
    cap.add(hci_conn_complete())
    l2cap_connect(cap, 0x0001, SDP_OUT, 1)
    s = Sdp(cap, SDP_OUT)

    # btsdp_attr_id_list_wrap.py: the attribute range element
    # is longer than the AttributeIDList
    s.req(0x04, struct.pack('>IH', 0x00010000, 0x03f0) + b'\x35\x02\x0a\x00\x00' + b'\x00')
    # btsdp_svcclass_search_loop.py: ServiceClassIDList with a
    # 32-bit length that wraps
    inner = b'\x1f' + struct.pack('>I', 0xfffffffb)
    attrs = u16(0x0001) + b'\x1f' + struct.pack('>I', 0xfffffffb) + inner
    alist = b'\x36' + struct.pack('>H', len(attrs)) + attrs
    s.rsp(0x05, struct.pack('>H', len(alist)) + alist + b'\x00', tid=1)
    # btsdp_did_quadratic.py with 200 filler attributes
    head = u16(0x0001) + seq(uuid16(0x1200))
    body = head + b''.join(u16(0x1000 + i) + b'\x00' for i in range(200))
    alist = b'\x36' + struct.pack('>H', len(body)) + body
    s.rsp(0x05, struct.pack('>H', len(alist)) + alist + b'\x00', tid=1)

    # No continuation state; a continuation state longer than 17 octets
    s.req(0x02, pattern(0x1101) + struct.pack('>H', 1))
    s.rsp(0x03, struct.pack('>HHI', 1, 1, 0x00010000) + cont(bytes(18)))
    # Continuation state length 17 (more than 16) with only one octet
    s.req(0x02, pattern(0x1101) + struct.pack('>H', 1) + b'\x11\x00')
    # Data element longer than the PDU
    s.req(0x02, b'\x35\x20' + uuid16(0x1101) + struct.pack('>H', 1) + b'\x00')
    s.rsp(0x05, struct.pack('>H', 8) + seq(u16(0x0100), text('abc' * 20))[:8] + b'\x00')
    # HDP supported feature without the optional description: the next
    # entry is taken as the description, the last runs off the end
    s.ssa_req(pattern(0x1401))
    s.ssa_rsp(records(record(handle(0x0001009A), cls(0x1401),
                             (0x0200, seq(seq(u8(1), u16(0x1004), u8(0)))),
                             (0x0301, u8(1)))))
    # An unsigned integer in the search pattern (not a UUID)
    s.ssa_req(pattern(u8(7), 0x1101))
    s.ssa_rsp(records(record(handle(0x0001009F), cls(0x1101))))
    # A data element whose 32-bit length wraps the offset
    s.req(0x02, b'\x35\x05' + b'\x27\xff\xff\xff\xff' + struct.pack('>H', 1) + b'\x00')
    # Truncated PDUs of every type
    for pdu_id, params in ((0x01, b'\x00'),
                           (0x02, pattern(0x1101)),
                           (0x03, struct.pack('>HH', 2, 2) + b'\x00\x01'),
                           (0x04, struct.pack('>IH', 1, 0x100)),
                           (0x05, struct.pack('>H', 20) + b'\x36\x00'),
                           (0x06, pattern(0x1101) + b'\x00'),
                           (0x07, struct.pack('>H', 20) + b'\x36\x00\x10')):
        cap.add(on_chan(SENT if pdu_id % 2 == 0 else RECV, SDP_OUT,
                        sdp_pdu(pdu_id, 0x200 + pdu_id, params, 0x40)))
    cap.add(on_chan(SENT, SDP_OUT, b'\x02\x00'))
    # Attribute values shorter than their decoders need, one per decoder
    short = record(handle(0x0001009B), cls(0x1124),
                   (0x0206, seq(seq(u8(0x22)))),
                   (0x0207, seq(seq(u16(0x0409)))))
    s.ssa_req(pattern(0x1124))
    s.ssa_rsp(records(short))
    s.ssa_req(pattern(0x1001))
    s.ssa_rsp(records(record(handle(0x0001009C), (0x0006, seq(u16(0x656e))))))
    s.ssa_req(pattern(0x1001))
    s.ssa_rsp(records(record(handle(0x0001009D), (0x0009, seq(seq(uuid16(0x1101)))))))
    s.ssa_req(pattern(0x1001))
    s.ssa_rsp(records(record(handle(0x0001009E), (0x0004, seq(seq(uuid16(0x0100), u8(1)))))))
    return cap


def nodir_capture():
    """H4 without pseudo-header: no direction. SDP on CID 0x0040 by Decode As."""
    cap = Capture()
    pdu = sdp_pdu(0x02, 1, pattern(0x1101) + struct.pack('>H', 1) + b'\x00')
    l2 = struct.pack('<HH', len(pdu), 0x0040) + pdu
    cap.add(b'\x02' + struct.pack('<HH', HANDLE | 0x2000, len(l2)) + l2)
    return cap


def exported_capture():
    cap = Capture()
    nm = b'btsdp'
    tlv = struct.pack('>HH', 12, len(nm)) + nm + struct.pack('>HH', 0, 0)
    cap.add(tlv + sdp_pdu(0x02, 1, pattern(0x1101) + struct.pack('>H', 1) + b'\x00'))
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    cap, marks = main_capture()
    write_pcap(os.path.join(out, 'btsdp-coverage.pcap'), 201, cap.frames)
    write_pcap(os.path.join(out, 'btsdp-coverage-malformed.pcap'), 201, malformed_capture().frames)
    write_pcap(os.path.join(out, 'btsdp-coverage-nodir.pcap'), 187, nodir_capture().frames)
    write_pcap(os.path.join(out, 'btsdp-coverage-exported.pcap'), 252, exported_capture().frames)
    for k, v in marks.items():
        print(v, k)


if __name__ == '__main__':
    main()
