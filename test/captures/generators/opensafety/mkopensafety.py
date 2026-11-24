#!/usr/bin/env python3
# Generates the opensafety captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the openSAFETY dissector
(packet-opensafety.c).

openSAFETY frames are built from scratch with struct: a frame 1 (address,
message id, length, counter low byte, payload, CRC8 or CRC16) followed by
a frame 2 (address xor safety domain, message id, counter high byte,
target address, payload, CRC), whose first six octets are xor-ed with the
SCM UDID for SSDO and SPDO messages. The CRCs are computed here with a
bitwise implementation of the three polynomials (0x2F, 0x755B, 0x5935);
no keys or encryption are involved (the SCM UDID is a plain identifier).

Usage: mkopensafety.py <output directory>

Writes:
  opensafety-coverage.pcap             UDP 9877 (direct and with the UDP
                                       transport header), UDP 8755
                                       (SercosIII/UDP), Powerlink PRes and
                                       PReq, SercosIII over Ethernet and
                                       Modbus/TCP; SNMT, SSDO (also slim),
                                       SPDO, reassembly of segmented SSDOs
  opensafety-coverage-frame2first.pcap UDP packets with frame 2 before
                                       frame 1 (needs -o opensafety.network_
                                       udp_frame_first:TRUE), including the
                                       reproducers of the fixed bugs
  opensafety-coverage-malformed.pcap   bad CRCs, no SCM UDID, unknown types,
                                       SPDO node 0, truncated frames
  opensafety-coverage-pnio.pcap        PROFINET RT with an SPDO (needs the
                                       disabled heuristic opensafety_pn_io)
  opensafety-coverage-mbtcp-be.pcap    Modbus/TCP with big endian word coding
"""

import os
import struct
import sys

UDID = bytes.fromhex('0a1b2c3d4e5f')
ZERO6 = bytes(6)
MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IPA = bytes((192, 0, 2, 1))
IPB = bytes((192, 0, 2, 2))


# ---------------------------------------------------------------- CRCs

def _crc_table(width, poly):
    top = 1 << (width - 1)
    mask = (1 << width) - 1
    t = []
    for i in range(256):
        c = i << (width - 8)
        for _ in range(8):
            c = ((c << 1) ^ poly) & mask if c & top else (c << 1) & mask
        t.append(c)
    return t


_T8 = _crc_table(8, 0x2F)
_T755B = _crc_table(16, 0x755B)
_T5935 = _crc_table(16, 0x5935)


def crc8(b):
    c = 0
    for x in b:
        c = _T8[x ^ c]
    return c


def crc16(b, poly=0x755B):
    t = _T755B if poly == 0x755B else _T5935
    c = 0
    for x in b:
        c = ((c << 8) & 0xffff) ^ t[((c >> 8) ^ x) & 0xff]
    return c


def crc_bytes(b, n, poly=0x755B):
    """CRC8 (n octets in the payload <= 8) or CRC16 little endian."""
    return bytes([crc8(b)]) if n <= 8 else struct.pack('<H', crc16(b, poly))


# ----------------------------------------------------------- frame builders

SSDO_REQ, SSDO_RESP, SLIM_REQ, SLIM_RESP = 0xE0, 0xE4, 0xE8, 0xEC
SNMT_REQ_UDID, SNMT_RESP_UDID, SNMT_ASSIGN_SADR, SNMT_SADR_ASSIGNED = 0xA0, 0xA4, 0xA8, 0xAC
SNMT_SVC_REQ, SNMT_SVC_RESP, SNMT_RESET_GUARD = 0xB0, 0xB4, 0xBC
SPDO_DATA, SPDO_TREQ, SPDO_TRESP, SPDO_RES = 0xC0, 0xC8, 0xD0, 0xD8


def build(addr, msgid, ct, data, taddr, sdn=1, tr=0, udid=UDID, slim=False,
          id2=None, bad1=False, bad2=False, f2first=False, crc2poly=None, pad=True, crc1poly=None):
    """One openSAFETY frame (frame 1 + frame 2) as bytes.

    addr/taddr: 10 bit node addresses; sdn: safety domain xor-ed into the
    frame 2 address; tr: the top six bits of the last octet of the
    frame 2 header; udid: the 6 octets xor-ed onto the first octets of
    frame 2 (zeros for SNMT)."""
    n = len(data)
    f1 = bytes([addr & 0xff, (msgid & 0xfc) | ((addr >> 8) & 3), n, ct & 0xff]) + data
    poly = crc1poly or (0x5935 if slim else 0x755B)
    c1 = crc_bytes(f1, n, poly)
    if bad1:
        c1 = bytes([c1[0] ^ 0x55]) + c1[1:]
    f1 += c1
    a2 = addr ^ sdn
    hdr = bytes([a2 & 0xff, ((msgid if id2 is None else id2) & 0xfc) | ((a2 >> 8) & 3),
                 (ct >> 8) & 0xff, taddr & 0xff, ((taddr >> 8) & 3) | (tr & 0xfc)])
    body = hdr + (b'' if slim else data)
    p2 = crc2poly or 0x755B
    if slim:
        c2 = bytes([crc8(body)]) if n <= 8 else struct.pack('<H', crc16(body, p2))
    else:
        c2 = crc_bytes(body, n, p2)
    if bad2:
        c2 = bytes([c2[0] ^ 0x33]) + c2[1:]
    full = bytearray(body + c2)
    # xor the first six octets with the SCM UDID (slim frames: the first
    # five and the low octet of the CRC, which is octet 5)
    for i in range(min(6, len(full))):
        full[i] ^= udid[i]
    f2 = bytes(full)
    if f2first:
        # findSafetyFrame() scans only while 10 octets remain behind the
        # second octet of frame 1 and demands 2 * length < remaining + 11:
        # frames with a payload of < 6 or > 15 octets need trailing padding
        if isinstance(pad, int) and not isinstance(pad, bool):
            return f2 + f1 + bytes(pad)
        return f2 + f1 + (bytes(max(10 - n, n - 15, 8 if slim else 0, 0)) if pad else b'')
    return f1 + f2


def snmt(msgid, db, taddr=0x10, addr=3, ct=1, sdn=1, **kw):
    return build(addr, msgid, ct, db, taddr, sdn=sdn, udid=ZERO6, **kw)


def ssdo_data(sacmd, idx=0, sub=0, extra=b'', initiate=None):
    ini = bool(sacmd & 0x24) if initiate is None else initiate
    d = bytes([sacmd])
    if ini:
        d += struct.pack('<HB', idx, sub)
    return d + extra


def ssdo(resp, sacmd, idx=0, sub=0, extra=b'', server=5, client=0x40, ct=1,
         tr=0, slim=False, sdn=1, **kw):
    """SSDO request/response. In both cases frame 1 carries the address
    of the receiver and frame 2 that of the sender."""
    data = ssdo_data(sacmd, idx, sub, extra)
    if resp:
        mid = SLIM_RESP if slim else SSDO_RESP
        addr, taddr = client, server
    else:
        mid = SLIM_REQ if slim else SSDO_REQ
        addr, taddr = server, client
    return build(addr, mid, ct, data, taddr, sdn=sdn, tr=tr, slim=slim, **kw)


def spdo(mid, node, ct, data, taddr=0, flags=0, conn=True, sdn=1, **kw):
    """flags: bit 0x20 = 40 bit counter available, 0x10 = used (the
    feature flags are the top bits of the TR octet, shifted by 2)."""
    return build(node, mid | (4 if conn else 0), ct, data, taddr, sdn=sdn,
                 tr=(flags << 2) & 0xfc, **kw)


def ext_par_set(parset, version, saddr, payload, tstamp=0x12345678, crc=0xdeadbeef, length=None):
    return (struct.pack('<BBHIII', parset, version, saddr,
                        len(payload) if length is None else length, crc, tstamp) + payload)


def par_entry(idx, sub, data):
    return struct.pack('<HBI', idx, sub, len(data)) + data


# ----------------------------------------------------------- packet wrappers

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Cap:
    def __init__(self):
        self.frames = []
        self.ipid = 1
        self.seq = {}

    def raw(self, data):
        self.frames.append(bytes(data))

    def ip(self, proto, payload, src=IPA, dst=IPB):
        self.ipid += 1
        h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), self.ipid, 0, 64, proto, 0, src, dst)
        h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
        return h + payload

    def eth(self, payload, et=0x0800, src=MAC_A, dst=MAC_B):
        return dst + src + struct.pack('>H', et) + payload

    def udp(self, payload, dport=9877, sport=40000, **kw):
        u = struct.pack('>HHHH', sport, dport, (8 + len(payload)) & 0xffff, 0) + payload
        self.raw(self.eth(self.ip(17, u)))

    def tcp(self, payload, dport=502, sport=41000, to_server=True):
        src, dst = (IPA, IPB) if to_server else (IPB, IPA)
        sp, dp = (sport, dport) if to_server else (dport, sport)
        k = (sp, dp)
        seq = self.seq.get(k, 1000 if to_server else 50000)
        self.seq[k] = seq + len(payload)
        ack = self.seq.get((dp, sp), 50000 if to_server else 1000)
        t = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 0x50, 0x18, 65535, 0, 0) + payload
        self.raw(self.eth(self.ip(6, t, src, dst)))

    def write(self, path, linktype=1):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
            for i, fr in enumerate(self.frames):
                cap = len(fr)
                if isinstance(fr, tuple):      # (data, captured length): a truncated record
                    fr, cap = fr
                f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, cap, len(fr)))
                f.write(fr[:cap])


def transport(frames, counter=1, sender=0x11223344, dp=7, typ=1):
    return struct.pack('<BBHIHH', 1, typ, counter, sender, dp, len(frames)) + frames


# EPL
MN = 240
MC_PRES = bytes.fromhex('01111e000004')


def epl_pres(src, payload, state=0xFD, size=None):
    body = bytes((4, 255, src)) + struct.pack('<BBBBBH', state, 0x01, 0, 0x20, 0,
                                               len(payload) if size is None else size) + payload
    return MC_PRES, bytes((2, 0, 0, 0, 0, src)), body


def epl_preq(cn, payload):
    body = bytes((3, cn, MN)) + struct.pack('<BBBBBH', 0, 0x01, 0, 0x20, 0, len(payload)) + payload
    return bytes((2, 0, 0, 0, 0, cn)), bytes((2, 0, 0, 0, 0, MN)), body


def spdo_list():
    """SPDO frames: every message type, 8/16 bit CRC, connection valid bit,
    40 bit counter flags, time request and response."""
    return [
        spdo(SPDO_DATA, 0x10, 1, bytes((1, 2, 3, 4))),
        spdo(SPDO_DATA, 0x10, 2, b'\x01', conn=False),  # connection valid bit clear
        spdo(SPDO_DATA, 0x11, 0x123, bytes(8), flags=0x20),  # 40 bit available
        spdo(SPDO_DATA, 0x12, 0x222, bytes(2)),
        spdo(SPDO_TREQ, 0x13, 3, bytes((9, 8)), taddr=0x21, flags=0x30),  # time request
        spdo(SPDO_TREQ, 0x13, 3, bytes((9, 8)), taddr=0x2ff, flags=0x30, sdn=7),
        spdo(SPDO_TRESP, 0x14, 4, bytes(12), taddr=0x22, flags=0x0),  # time response, CRC16
        spdo(SPDO_TRESP, 0x15, 5, bytes(3), taddr=0x23),
        spdo(SPDO_DATA, 0x16, 6, bytes(range(20))),  # CRC16 frame
        spdo(SPDO_DATA, 0x17, 7, bytes(range(40)), conn=False),
        spdo(SPDO_DATA, 0x18, 0x7, b'', ),  # no payload
        spdo(SPDO_DATA, 0x100, 0x7, bytes(2)),  # a 9 bit node address
        spdo(SPDO_DATA, 0x19, 0x7, bytes(5), flags=0x30, taddr=0x66),  # 40 bit used
        spdo(SPDO_DATA, 0x19, 0x8, bytes(5), flags=0x30, taddr=0x66, id2=0xc8),  # 40 bit used, id mismatch tolerated
        spdo(SPDO_RES, 0x1a, 1, bytes(2)),  # reserved id: skipped
    ]


def zero_crc1(addr, mid, data, taddr, poly=0x755B, **kw):
    """A frame whose frame 1 CRC is zero, see the special case in
    findSafetyFrame(). The counter and the last two payload octets are
    chosen to cancel the CRC: the CRC is linear over GF(2), so this is a
    small linear system."""
    n = len(data)
    bits = 8 if n <= 8 else 16

    def crcof(x):
        ct, l1, l2 = x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff
        d = data[:-2] + bytes([l2, l1])
        f1 = bytes([addr & 0xff, (mid & 0xfc) | ((addr >> 8) & 3), n, ct]) + d
        return crc8(f1) if n <= 8 else crc16(f1, poly)

    base = crcof(0)
    cols = [crcof(1 << i) ^ base for i in range(24)]
    # equations: sum(cols[j] * x_j) = base; row-reduce an augmented matrix
    rows = []
    for bit in range(bits):
        r = 0
        for j in range(24):
            if (cols[j] >> bit) & 1:
                r |= 1 << j
        rows.append(r | (((base >> bit) & 1) << 24))
    pivots = []
    for col in range(24):
        sel = next((i for i in range(len(pivots), bits) if (rows[i] >> col) & 1), None)
        if sel is None:
            continue
        k = len(pivots)
        rows[k], rows[sel] = rows[sel], rows[k]
        for i in range(bits):
            if i != k and (rows[i] >> col) & 1:
                rows[i] ^= rows[k]
        pivots.append(col)
    x = 0
    for k, col in enumerate(pivots):
        if (rows[k] >> 24) & 1:
            x |= 1 << col
    assert crcof(x) == 0
    ct, l1, l2 = x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff
    return build(addr, mid, ct, data[:-2] + bytes([l2, l1]), taddr, **kw)


# --------------------------------------------------------------- captures

def main_capture(path):
    c = Cap()
    udp = c.udp
    CT = [0]

    def nct():
        CT[0] += 1
        return CT[0]

    # ---- frame 1: SNMT "SN assign UDID SCM" teaches the SCM UDID
    udp(snmt(SNMT_SVC_REQ, b'\x0e' + UDID))

    # ---- SNMT
    udp(snmt(SNMT_REQ_UDID, b''))                                   # length 0, frame length 11
    udp(snmt(SNMT_RESP_UDID, b'\x00' + bytes.fromhex('0200000000aa')))
    udp(snmt(SNMT_ASSIGN_SADR, b'\x00' + bytes.fromhex('0200000000bb')))
    udp(snmt(SNMT_SADR_ASSIGNED, b'\x00' + bytes.fromhex('0200000000cc')))
    udp(snmt(SNMT_SVC_REQ, b'\x00'))                                # SN set to pre Operational
    udp(snmt(SNMT_SVC_REQ, b'\x02' + struct.pack('<I', 0x5f5e1000)))  # SN set to Operational + timestamp
    udp(snmt(SNMT_SVC_REQ, b'\x04'))                                # SCM set to Stop
    udp(snmt(SNMT_SVC_REQ, b'\x06'))                                # SCM set to Operational
    udp(snmt(SNMT_SVC_REQ, b'\x08'))                                # SCM guard SN
    udp(snmt(SNMT_SVC_REQ, b'\x0a' + struct.pack('<HH', 0x123, 0x234)))  # assign additional SADR
    udp(snmt(SNMT_SVC_REQ, b'\x10' + bytes.fromhex('0102030405')))  # assign initial CT
    udp(snmt(SNMT_SVC_REQ, b'\x20'))                                # unknown service
    udp(snmt(SNMT_SVC_REQ, b'\x0e' + UDID))                         # assign UDID again (same value)
    udp(snmt(SNMT_SVC_REQ, b'\x0e' + bytes(6)))                     # all zero UDID is ignored
    udp(snmt(SNMT_SVC_RESP, b'\x01'))                               # SN status pre Operational
    udp(snmt(SNMT_SVC_RESP, b'\x03'))                               # SN status Operational
    udp(snmt(SNMT_SVC_RESP, b'\x05' + struct.pack('<HH', 0x123, 0x234)))  # assigned additional SADR
    udp(snmt(SNMT_SVC_RESP, b'\x09'))                               # SN busy
    udp(snmt(SNMT_SVC_RESP, b'\x0f' + UDID))                        # SN assigned UDID SCM
    udp(snmt(SNMT_SVC_RESP, b'\x11' + bytes.fromhex('0a0b0c0d0e')))  # acknowledge initial CT
    udp(snmt(SNMT_SVC_RESP, b'\x04'))                               # SCM stop (response, receiver only)
    udp(snmt(SNMT_SVC_RESP, b'\x06'))                               # SCM op (response)
    for grp, code in ((0, 0), (1, 0), (2, 5), (3, 1), (4, 0), (9, 7)):
        udp(snmt(SNMT_SVC_RESP, b'\x07' + bytes((grp, code))))      # SN Fail, every error group
    udp(snmt(SNMT_SVC_RESP, b'\x07' + bytes((5, 0x12))))            # SN Fail, additional parameter (set 3)
    udp(snmt(SNMT_SVC_RESP, b'\x07' + bytes((5, 0xf3))))            # ... full parameter set
    udp(snmt(SNMT_SVC_RESP, b'\x0c' + bytes((2, 0))))               # SN Acknowledge, normal
    udp(snmt(SNMT_SVC_RESP, b'\x0c' + bytes((0, 3))))               # ... device group, vendor code
    udp(snmt(SNMT_SVC_RESP, b'\x0c' + bytes((5, 0x21))))            # ... additional parameter missing
    udp(snmt(SNMT_SVC_REQ, b'\x07' + bytes((1, 0))))                # SN Fail as a request
    udp(snmt(SNMT_RESET_GUARD, b''))                                # SN reset guarding SCM
    udp(snmt(SNMT_SVC_REQ, b'\x00', addr=0x2c5, taddr=0x3ff, sdn=0x123))  # 10 bit addresses, big domain

    # ---- SSDO, expedited
    udp(ssdo(False, 0x20, 0x1018, 6))                               # upload initiate request, DVI parameter checksum
    udp(ssdo(True, 0x20, 0x1018, 6, struct.pack('<III', 0x01020304, 0xaabbccdd, 0x11223344), ct=1))
    udp(ssdo(True, 0x20, 0x1018, 7, struct.pack('<I', 0x5f5e1000), ct=2))        # parameter timestamp
    udp(ssdo(True, 0x20, 0x1018, 1, struct.pack('<I', 0x1234), ct=3))            # vendor id (named subindex)
    udp(ssdo(True, 0x20, 0x1000, 0, struct.pack('<I', 0x1234), ct=4))            # no subindex
    udp(ssdo(False, 0x20, 0x12ff, 3, ct=0x1234))                                 # unnamed index, large counter
    udp(ssdo(False, 0x21, 0x1400, 2, struct.pack('<H', 0x55), ct=5))             # download expedited with data
    udp(ssdo(True, 0x21, 0x1400, 2, ct=5))                                       # its response (no data)
    udp(ssdo(False, 0x21, 0x1018, 6, struct.pack('<III', 1, 2, 3), ct=6))        # download of the checksums
    udp(ssdo(False, 0x21, 0x1018, 7, struct.pack('<I', 0x77), ct=7))
    udp(ssdo(False, 0x31, 0x1800, 1, bytes(2), ct=8))                            # toggle bit set
    udp(ssdo(True, 0x30, 0xc000, 1, bytes(4), ct=9))
    udp(ssdo(True, 0x22, 0x1c00, 1, bytes(4), ct=10, tr=0x3c))                   # preload response with queue size
    udp(ssdo(True, 0x23, 0x1c00, 1, ct=11, tr=0x3c))                             # preload download response
    udp(ssdo(True, 0x0a, extra=bytes(6), ct=12, tr=0xc0, server=0x64))                        # preload, error flag (0x30 not set)
    udp(ssdo(True, 0x0a, extra=bytes(6), ct=12, tr=0xfc, server=0x65))                        # preload, last successful request
    udp(ssdo(True, 0x0b, extra=b'x', ct=13, tr=0xf0, server=0x66))
    udp(ssdo(False, 0x04, 0x1018, 1, struct.pack('<I', 0x06020000)))             # abort, request
    udp(ssdo(True, 0x24, 0x1018, 1, struct.pack('<I', 0x05040001)))              # abort + initiate (no index)
    udp(ssdo(True, 0x04, 0, 0, struct.pack('<I', 0x08000020)))                   # abort, no initiate
    udp(ssdo(True, 0x04, 0, 0, struct.pack('<I', 0x12345678)))                   # unknown abort code
    udp(ssdo(True, 0x28, 0x1800, 1, struct.pack('<I', 10) + bytes(range(5)), ct=20, server=0x60))  # first segment alone
    udp(ssdo(True, 0x48, extra=bytes(range(7)), ct=22, server=0x61))             # end segment without a start
    udp(ssdo(True, 0x08, extra=bytes(range(7)), ct=21, server=0x62))             # middle segment
    udp(ssdo(False, 0x49, extra=bytes(4), ct=23, server=0x63))
    udp(ssdo(True, 0x20, 0x1018, 6, b'', ct=30, server=0x41))                    # initiate response without data
    udp(ssdo(False, 0x21, 0x1018, 6, bytes(12), ct=31, server=0x41, client=0x42, sdn=0x321))

    # ---- SSDO, segmented transfers (reassembly)
    ps = (par_entry(0x1400, 1, bytes.fromhex('0102'))
          + par_entry(0x1400, 0, bytes(4))                                       # subindex 0
          + par_entry(0x1800, 1, bytes((0x10, 0x02, 0x34, 0x12)))                # RxSPDO mapping
          + par_entry(0xc000, 2, bytes((0x08, 0x01, 0x78, 0x56)))                # TxSPDO mapping
          + par_entry(0x1018, 6, struct.pack('<IIII', 0x5f5e1000, 1, 2, 3))      # DVI checksum list
          + par_entry(0x1018, 7, struct.pack('<I', 0x5f5e2000))                  # DVI timestamp
          + par_entry(0x1c00, 3, bytes(range(9)))
          + par_entry(0x1200, 2, bytes(2))
          + par_entry(0x1018, 6, struct.pack('<I', 0x44332211)))
    ps += (par_entry(0x1401, 1, bytes(2))                                        # indexes inside the ranges
           + par_entry(0x1801, 2, bytes((0x20, 0x03, 0x56, 0x34)))
           + par_entry(0xc001, 1, bytes((0x04, 0x05, 0x9a, 0x78)))
           + par_entry(0x1c01, 2, bytes(3)))
    ps += par_entry(0x1400, 4, bytes(5000 // 100))                               # fills the last chunk
    ps += b'\x00\x14\x05\x20\x00\x00\x00'                                        # truncated entry (loop ends)
    seg = 40
    chunks = [ps[i:i + seg] for i in range(0, len(ps), seg)]
    ct = 100
    udp(ssdo(False, 0x29, 0x101a, 0, struct.pack('<I', len(ps)) + chunks[0], ct=ct))
    for i, ch in enumerate(chunks[1:-1], 1):
        udp(ssdo(False, 0x09, extra=ch, ct=ct + i))
    udp(ssdo(False, 0x49, extra=chunks[-1], ct=ct + len(chunks) - 1))            # reassembled parameter set
    # a parameter set whose last entry declares 3 more octets than follow (the loop stops)
    ps2 = par_entry(0x1400, 1, bytes(2)) + b'\x00\x14\x02' + struct.pack('<I', 7) + bytes(4)
    udp(ssdo(False, 0x29, 0x101a, 0, struct.pack('<I', len(ps2)) + ps2[:10], ct=150, server=0x4b))
    udp(ssdo(False, 0x49, extra=ps2[10:], ct=151, server=0x4b))
    # upload of an extended parameter set (header and data), response frames
    ext = ext_par_set(2, 3, 0x41, bytes(range(60)))
    ch = [ext[i:i + 30] for i in range(0, len(ext), 30)]
    ct = 200
    udp(ssdo(True, 0x28, 0x101b, 0, struct.pack('<I', len(ext)) + ch[0], ct=ct))
    for i, x in enumerate(ch[1:-1], 1):
        udp(ssdo(True, 0x08, extra=x, ct=ct + i))
    udp(ssdo(True, 0x48, extra=ch[-1], ct=ct + len(ch) - 1))                     # "Header & Data"
    # extended parameter set with a 272 octet payload (the length field
    # does not fit eight bits: fixed field type)
    ext = ext_par_set(2, 3, 0x42, bytes((i * 11) & 0xff for i in range(272)), crc=0x0a0b0c0d, tstamp=0x5f5e1000)
    udp(ssdo(True, 0x28, 0x101b, 0, struct.pack('<I', len(ext)) + ext[:100], ct=500, server=0x4a))
    udp(ssdo(True, 0x08, extra=ext[100:200], ct=501, server=0x4a))
    udp(ssdo(True, 0x48, extra=ext[200:], ct=502, server=0x4a))
    # extended parameter set, header only (16 octets)
    ext = ext_par_set(1, 2, 0x42, b'', length=0)
    udp(ssdo(False, 0x29, 0x101b, 0, struct.pack('<I', 16) + ext[:6], ct=300))
    udp(ssdo(False, 0x49, extra=ext[6:], ct=301))
    # extended parameter set recognised by parset 1/version 1 (index 0x0101)
    ext = ext_par_set(1, 1, 0x43, bytes(20), length=20)
    udp(ssdo(False, 0x29, 0x101b, 0, struct.pack('<I', 36) + ext[:10], ct=310, server=0x44))
    udp(ssdo(False, 0x49, extra=ext[10:], ct=311, server=0x44))
    # upload of the parameter checksums (upload end segment, multiple of 4)
    up = struct.pack('<IIIII', 0x5f5e1000, 0x11111111, 0x22222222, 0x33333333, 0x44444444)
    udp(ssdo(True, 0x28, 0x1018, 6, struct.pack('<I', len(up)) + up[:4], ct=320, server=0x45))
    udp(ssdo(True, 0x48, extra=up[4:], ct=321, server=0x45))
    # a segmented transfer with a long payload (CRC16 frames)
    big = par_entry(0x1400, 1, bytes((i * 7) & 0xff for i in range(120))) + \
        par_entry(0x1c00, 2, bytes((i * 5) & 0xff for i in range(150)))
    ch = [big[i:i + 100] for i in range(0, len(big), 100)]
    udp(ssdo(False, 0x29, 0x1000, 1, struct.pack('<I', len(big)) + ch[0][:80], ct=400, server=0x46))
    udp(ssdo(False, 0x09, extra=ch[0][80:] + ch[1][:60], ct=401, server=0x46))
    udp(ssdo(False, 0x09, extra=ch[1][60:] + ch[2][:20], ct=402, server=0x46))
    udp(ssdo(False, 0x49, extra=ch[2][20:], ct=403, server=0x46))
    # segments with the toggle bit (16 octets: an extended parameter set header)
    udp(ssdo(False, 0x39, 0x1000, 2, struct.pack('<I', 16) + bytes(8), ct=410, server=0x47))
    udp(ssdo(False, 0x59, extra=bytes(8), ct=411, server=0x47))

    # frame 1 with a zero CRC (8 and 16 bit)
    udp(zero_crc1(0x30, SSDO_REQ, bytes((0x20, 0x18, 0x10, 0x01)), 0x40))
    udp(zero_crc1(0x30, SSDO_RESP, bytes((0x20, 0x18, 0x10, 0x01)) + bytes(range(8)), 0x40))

    # ---- slim SSDO
    udp(ssdo(False, 0x20, 0x1018, 1, slim=True, ct=1))
    udp(ssdo(True, 0x20, 0x1018, 1, struct.pack('<I', 0x1234), slim=True, ct=2))
    udp(ssdo(False, 0x21, 0x1400, 1, bytes(3), slim=True, ct=3))
    udp(ssdo(True, 0x04, 0, 0, struct.pack('<I', 0x05040001), slim=True, ct=4))  # slim abort
    udp(ssdo(False, 0x29, 0x1000, 3, struct.pack('<I', 40) + bytes(2), slim=True, ct=5, server=0x48))
    udp(ssdo(True, 0x2a, 0x1018, 6, struct.pack('<I', 5), slim=True, ct=6, tr=0x40, server=0x49))
    udp(ssdo(True, 0x20, 0x1000, 4, bytes(12), slim=True, ct=7, sdn=0x10))       # CRC16 slim frame 1
    udp(ssdo(False, 0x21, 0x1000, 4, bytes(16), slim=True, ct=8, crc2poly=0x5935))

    # ---- SPDO (carried over Powerlink PRes below; over UDP they are only
    # dissected with classify_transport off)
    SP = spdo_list()

    # ---- UDP transport header (version, type, counter, sender, datapoint, length)
    udp(transport(ssdo(False, 0x20, 0x1018, 1, ct=21) + ssdo(True, 0x20, 0x1018, 1, bytes(4), ct=21), counter=2, typ=2))
    udp(transport(snmt(SNMT_SVC_REQ, b'\x00'), counter=4, typ=0))
    udp(transport(bytes(13), counter=3))                                       # transport header, no openSAFETY frame

    # ---- several openSAFETY frames in one UDP packet
    udp(snmt(SNMT_SVC_REQ, b'\x00') + ssdo(False, 0x20, 0x1018, 1) + snmt(SNMT_SVC_REQ, b'\x08'))
    udp(b'\x00\x01\x02' + ssdo(False, 0x20, 0x1018, 2, ct=2) + bytes(5) + ssdo(False, 0x20, 0x1018, 3, ct=3) + b'\xee\xdd')

    # ---- non openSAFETY UDP data on the port
    udp(bytes(range(10)))                                                      # shorter than 11 octets
    udp(bytes(24))                                                             # no frame: only the transport header
    udp(spdo(SPDO_DATA, 0x20, 30, bytes(2)))                                   # SPDO over UDP: rejected (acyclic)
    udp(spdo(SPDO_DATA, 0x20, 30, bytes(2)), dport=8755)                       # SercosIII/UDP port, rejected too
    udp(ssdo(False, 0x20, 0x1018, 1, ct=31), dport=8755)                       # accepted via the SercosIII/UDP port
    udp(snmt(SNMT_SVC_REQ, b'\x00'), dport=8755)

    # ---- Powerlink (PRes / PReq carry SPDOs only, cyclic data)
    def epl(t):
        dst, src, body = t
        c.raw(dst + src + b'\x88\xab' + body)
    for i, f in enumerate(SP):
        epl(epl_pres(1 + i, f))
    epl(epl_pres(31, SP[0] + SP[3]))
    epl(epl_pres(32, SP[0] + bytes(3) + SP[3] + b'\xff' * 4))              # gap data and trailing data
    epl(epl_preq(33, SP[4]))
    epl(epl_pres(34, ssdo(False, 0x20, 0x1018, 1, ct=42)))                      # SSDO in cyclic data: skipped
    epl(epl_pres(35, snmt(SNMT_SVC_REQ, b'\x00')))                              # SNMT in cyclic data: skipped
    epl(epl_pres(36, SP[0] + ssdo(False, 0x20, 0x1018, 1, ct=42)))              # one skipped, one dissected

    # ---- SercosIII over Ethernet (MDT with phase CP3/CP4, telegram number != 0, bit 0x20 set)
    def siii(typ, phase, payload):
        c.raw(bytes.fromhex('010019000000') + MAC_A + b'\x88\xcd' + bytes((typ, phase)) + bytes(4) + payload)
    siii(0x21, 4, SP[0])
    siii(0x23, 3, SP[0] + SP[3])
    siii(0x21, 4, ssdo(False, 0x20, 0x1018, 1, ct=51))                         # SSDO in cyclic data: skipped
    siii(0x61, 4, bytes(20))                                                   # AT with no openSAFETY data
    siii(0x01, 4, SP[0])                                                       # bit 0x20 clear

    # ---- Modbus/TCP, a function code the Modbus dissector does not know
    def mbap(tid, unit, func, data):
        return struct.pack('>HHHBB', tid, 0, len(data) + 2, unit, func) + data
    c.tcp(mbap(1, 1, 0x41, SP[0]), to_server=True)
    c.tcp(mbap(1, 1, 0x41, ssdo(True, 0x20, 0x1018, 1, bytes(4), ct=61)), to_server=False)
    c.tcp(mbap(2, 1, 0x41, snmt(SNMT_SVC_REQ, b'\x00') + SP[3] + ssdo(False, 0x20, 0x1018, 2)), to_server=True)
    c.tcp(mbap(3, 1, 0x41, bytes(30)), to_server=True)                         # not openSAFETY: plain Modbus data
    c.tcp(mbap(4, 1, 0x41, SP[8] + SP[9] + bytes(2) + SP[2]), to_server=True)
    c.write(path)
    return c


def frame2first_capture(path):
    c = Cap()
    udp = c.udp
    udp(snmt(SNMT_SVC_REQ, b'\x0e' + UDID, f2first=True))                     # teach the UDID (frame 2 first)
    udp(snmt(SNMT_SVC_REQ, b'\x00', f2first=True))
    udp(snmt(SNMT_SADR_ASSIGNED, b'\x00' + bytes.fromhex('0200000000cc'), f2first=True))  # UDID item offset
    udp(snmt(SNMT_RESP_UDID, b'\x00' + bytes.fromhex('0200000000dd'), f2first=True))
    udp(snmt(SNMT_SVC_RESP, b'\x0f' + UDID, f2first=True))
    udp(ssdo(False, 0x20, 0x1018, 1, ct=1, f2first=True))
    udp(ssdo(True, 0x20, 0x1018, 6, struct.pack('<III', 1, 2, 3), ct=2, f2first=True))
    udp(ssdo(False, 0x21, 0x1400, 2, struct.pack('<H', 0x55), ct=3, f2first=True))
    udp(ssdo(True, 0x04, 0, 0, struct.pack('<I', 0x05040001), ct=4, f2first=True))
    # SPDO payload with frame 1 at offset > 0: payload read from the right place (fix)
    udp(spdo(SPDO_DATA, 0x10, 1, bytes((0xa1, 0xa2, 0xa3, 0xa4)), f2first=True))
    udp(spdo(SPDO_TREQ, 0x11, 2, bytes((0xb1, 0xb2)), taddr=0x20, f2first=True))
    udp(spdo(SPDO_TRESP, 0x12, 3, bytes(range(0xc0, 0xcc)), taddr=0x21, f2first=True))
    udp(spdo(SPDO_DATA, 0x13, 4, bytes(range(30)), f2first=True))
    # slim SSDO in frame 2 first mode
    udp(ssdo(False, 0x20, 0x1018, 1, slim=True, ct=5, f2first=True))
    udp(ssdo(True, 0x20, 0x1018, 1, struct.pack('<I', 0x1234), slim=True, ct=6, f2first=True))
    udp(ssdo(True, 0x20, 0x1000, 4, bytes(12), slim=True, ct=7, f2first=True))
    # a slim SSDO whose frame length (19) makes the first guess of the frame 1 position
    # look like a normal frame (octet 12 is 4 = (19 - 11) / 2, octet 11 is no frame id):
    # the second look checks the CRC (at offset 33, hence the padding) and finds the slim frame
    udp(ssdo(True, 0x20, 0x0418, 1, bytes(4), slim=True, ct=9, f2first=True, pad=16))
    # the longest frames the mode can find: frame 1 starts at offset 128
    # (findFrame1Position() takes the frame length as an uint8_t)
    pay = bytes((i * 3) & 0xff for i in range(117))
    udp(ssdo(False, 0x21, 0x1000, 9, pay, ct=9, f2first=True))
    udp(ssdo(True, 0x20, 0x1000, 9, pay, ct=10, f2first=True))
    udp(spdo(SPDO_DATA, 0x14, 6, bytes(range(121)), f2first=True))
    udp(spdo(SPDO_TRESP, 0x15, 7, bytes(range(100, 221)), taddr=0x30, f2first=True))
    # two frames in one packet (the dissector skips one octet after a frame)
    udp(spdo(SPDO_DATA, 0x10, 5, bytes(3), f2first=True, pad=False) + b'\x00' + spdo(SPDO_DATA, 0x11, 5, bytes(3), f2first=True))
    # the reproducer of the quadratic rescan: a CRC-valid frame 1 candidate
    # (SSDO, length 0, rejected later) at the end of a 65000 octet payload
    for ct in range(1, 256):
        f1 = bytes([5, 0xE0, 0, ct])
        if crc8(f1):
            break
    cand = f1 + bytes([crc8(f1)]) + bytes(6)
    udp(bytes(65000 - len(cand)) + cand)
    c.write(path)
    return c


def malformed_capture(path):
    c = Cap()
    udp = c.udp
    # no SCM UDID known yet: SSDO/SPDO frame 2 cannot be checked
    udp(ssdo(False, 0x20, 0x1018, 1, ct=1))
    udp(spdo(SPDO_DATA, 0x10, 1, bytes(4)))
    udp(ssdo(True, 0x24, 0x1018, 1, struct.pack('<I', 0x05040001)))
    # an SNMT frame with a bad CRC in frame 2 / different IDs
    udp(snmt(SNMT_SVC_REQ, b'\x0e' + bytes.fromhex('020000000099')))        # teaches a different UDID
    udp(ssdo(False, 0x20, 0x1018, 1, ct=2))                                  # now frame 2 does not decode (UDID mismatch)
    udp(spdo(SPDO_DATA, 0x10, 2, bytes(4)))
    # frame 2 CRC wrong
    udp(snmt(SNMT_SVC_REQ, b'\x00', bad2=True))
    udp(snmt(SNMT_SVC_REQ, b'\x0e' + UDID))
    udp(ssdo(False, 0x20, 0x1018, 1, ct=3, bad2=True))
    udp(spdo(SPDO_DATA, 0x10, 3, bytes(4), bad2=True))
    udp(spdo(SPDO_DATA, 0x10, 3, bytes(12), bad2=True))
    udp(ssdo(False, 0x20, 0x1018, 1, ct=3, slim=True, bad2=True))
    # frame 1 CRC wrong: not a frame at all
    udp(ssdo(False, 0x20, 0x1018, 1, ct=4, bad1=True))
    # SPDO node address 0 and > 1024
    udp(spdo(SPDO_DATA, 0, 4, bytes(4)))
    udp(spdo(SPDO_DATA, 0x3ff, 4, bytes(4)))
    # an SPDO whose frame 1 is protected with the slim SSDO CRC16
    udp(build(0x10, SPDO_DATA | 4, 5, bytes(12), 0, crc1poly=0x5935))
    udp(spdo(SPDO_DATA, 0x10, 6, bytes(4), id2=0xd0))                      # frame 2 id does not match frame 1
    # SNMT with different frame IDs in frame 1 and frame 2
    udp(snmt(SNMT_SVC_REQ, b'\x00', id2=0xa0))
    # unknown message id 0x80..0x9c, 0xf0..: rejected by the type tests
    udp(build(5, 0x80, 1, bytes(2), 1, udid=ZERO6))
    udp(build(5, 0xa0 | 0x1c, 1, bytes(2), 1, udid=ZERO6))                    # 0xbc reset guard with data
    udp(build(5, 0xf0, 1, bytes(2), 1, udid=ZERO6))
    udp(build(5, 0xb8, 1, bytes(2), 1, udid=ZERO6))                           # SNMT range, id unknown
    udp(build(5, 0xd8, 1, bytes(2), 1))                                      # SPDO reserved
    # parameter set with an unknown index (< 0x1000) and an extended parameter set whose length differs
    ps = par_entry(0x0100, 1, bytes(4)) + par_entry(0x1400, 1, bytes(2))
    udp(ssdo(False, 0x29, 0x101a, 0, struct.pack('<I', len(ps)) + ps[:6], ct=100, server=0x50))
    udp(ssdo(False, 0x49, extra=ps[6:], ct=101, server=0x50))
    ext = ext_par_set(1, 1, 0x41, bytes(40), length=33)
    udp(ssdo(False, 0x29, 0x101b, 0, struct.pack('<I', len(ext)) + ext[:6], ct=110, server=0x51))
    udp(ssdo(False, 0x49, extra=ext[6:30], ct=111, server=0x51))
    udp(ssdo(False, 0x49, extra=ext[30:], ct=112, server=0x51))
    # a parameter set whose data runs past the end (loop breaks), one with only part of a header
    ps = par_entry(0x1400, 1, bytes(2)) + struct.pack('<HBI', 0x1400, 2, 0x100) + bytes(3)
    udp(ssdo(False, 0x29, 0x101a, 0, struct.pack('<I', len(ps)) + ps[:6], ct=120, server=0x52))
    udp(ssdo(False, 0x49, extra=ps[6:], ct=121, server=0x52))
    ps = par_entry(0x1400, 1, bytes(2)) + b'\x00\x14'
    udp(ssdo(False, 0x29, 0x101a, 0, struct.pack('<I', len(ps)) + ps[:6], ct=130, server=0x53))
    udp(ssdo(False, 0x49, extra=ps[6:], ct=131, server=0x53))
    # a reassembled payload of 4 octets: dissect_opensafety_ssdo_payload() reads a 32 bit
    # length at offset 4 before it looks at the size (exception)
    udp(ssdo(False, 0x39, 0x1000, 2, struct.pack('<I', 4) + bytes(2), ct=410, server=0x70))
    udp(ssdo(False, 0x59, extra=bytes(2), ct=411, server=0x70))
    # segment whose length leaves no room for the header (segmented initiate with 3 octets)
    d = bytes([0x29]) + struct.pack('<HB', 0x1000, 1)
    udp(build(0x54, SSDO_REQ, 140, d, 0x40))
    # abort with too little data (throws)
    udp(build(0x54, SSDO_RESP, 141, bytes([0x04, 0, 0, 0]), 0x40))
    # frames that stop short of the second frame
    full = ssdo(False, 0x20, 0x1018, 1, ct=5)
    udp(full[:len(full) - 3])
    udp(full[:12])
    full = spdo(SPDO_DATA, 0x10, 7, bytes(4))
    udp(full[:len(full) - 2])
    # a bad CRC in an otherwise good frame in the middle of a packet
    udp(spdo(SPDO_DATA, 0x10, 8, bytes(3)) + bytes(30) + spdo(SPDO_DATA, 0x11, 8, bytes(3), bad2=True))
    # frame 2 first mode (opensafety.network_udp_frame_first): slim SSDOs at the very
    # end read their frame 2 CRC past the payload, frames longer than 121 octets
    # are not found (uint8_t frame length), short frames without padding are not found
    udp(ssdo(True, 0x20, 0x1018, 1, struct.pack('<I', 0x1234), slim=True, ct=6, f2first=True, pad=False))
    udp(ssdo(False, 0x21, 0x1000, 9, bytes(range(130)), ct=9, f2first=True))
    udp(ssdo(False, 0x21, 0x1000, 9, bytes(range(5)), ct=9, f2first=True, pad=False))
    c.write(path)
    return c


def spdo_udp_capture(path):
    """SPDOs over UDP: only dissected with opensafety.classify_transport off."""
    c = Cap()
    c.udp(snmt(SNMT_SVC_REQ, b'\x0e' + UDID))
    for i, f in enumerate(spdo_list()):
        c.udp(f)
    c.udp(spdo_list()[0], dport=8755)
    c.udp(transport(spdo_list()[3]))
    c.udp(spdo_list()[0] + spdo_list()[1] + spdo_list()[3])
    c.udp(b'\x00\x01' + spdo_list()[0] + bytes(5) + spdo_list()[3] + b'\xee')
    c.write(path)
    return c


def pnio_capture(path):
    c = Cap()
    # PROFINET RT class 1 (frame id 0xc000) with an SPDO as cyclic data
    sp = spdo(SPDO_DATA, 0x10, 70, bytes(4))
    for fid, pay in ((0xc000, sp), (0xc001, sp + sp), (0xc002, bytes(20))):
        data = pay + bytes(max(0, 40 - len(pay)))
        c.raw(MAC_B + MAC_A + b'\x88\x92' + struct.pack('>H', fid) + data + struct.pack('>HBB', 100, 0x35, 0))
    c.write(path)
    return c


def mbtcp_be_capture(path):
    """Modbus/TCP where the openSAFETY frame is word swapped."""
    def swap(b):
        b = bytearray(b + (b'\0' if len(b) % 2 else b''))
        for i in range(0, len(b), 2):
            b[i], b[i + 1] = b[i + 1], b[i]
        return bytes(b)
    c = Cap()
    # the whole Modbus data (after the function code) is swapped
    def mbap(tid, data):
        return struct.pack('>HHHBB', tid, 0, len(data) + 2, 1, 0x41) + data
    fr = spdo(SPDO_DATA, 0x10, 80, bytes(4))
    c.tcp(mbap(1, swap(fr)), to_server=True)
    c.tcp(mbap(2, swap(ssdo(False, 0x20, 0x1018, 1, ct=81))), to_server=True)
    c.tcp(mbap(3, swap(fr + b'\x00')), to_server=False)
    c.tcp(mbap(4, bytes(20)), to_server=True)
    c.tcp(mbap(5, swap(fr)), to_server=True)
    c.frames[-1] = (c.frames[-1], len(c.frames[-1]) - 4)         # truncated record: the swap is skipped
    c.write(path)
    return c


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    main_capture(os.path.join(out, 'opensafety-coverage.pcap'))
    frame2first_capture(os.path.join(out, 'opensafety-coverage-frame2first.pcap'))
    malformed_capture(os.path.join(out, 'opensafety-coverage-malformed.pcap'))
    pnio_capture(os.path.join(out, 'opensafety-coverage-pnio.pcap'))
    spdo_udp_capture(os.path.join(out, 'opensafety-coverage-spdo-udp.pcap'))
    mbtcp_be_capture(os.path.join(out, 'opensafety-coverage-mbtcp-be.pcap'))


if __name__ == '__main__':
    main()
