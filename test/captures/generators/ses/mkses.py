#!/usr/bin/env python3
# Generates test/captures/ses_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for the SES (ISO 8327-1 session) and CLSES
dissectors (packet-ses.c).

Usage: mkses.py <outdir>

Writes ses-coverage.pcapng (clean) and ses-coverage-malformed.pcapng.  SES is
reached through the COTP heuristic list (TPKT, TCP port 102); CLSES through
the CLTP heuristic list of COTP over IP protocol 39.  Everything is built with
struct; nothing comes from a real network.
"""
import struct
import sys
import os

# ---------------------------------------------------------------- SPDU parts

def li(n):
    return bytes([n]) if n < 255 else b'\xff' + struct.pack('>H', n)


def pi(t, v=b''):
    """Parameter (PI) or parameter group (PGI): type, length, value."""
    return bytes([t]) + li(len(v)) + v


def spdu(t, params=b''):
    return bytes([t]) + li(len(params)) + params


# parameter type numbers
CONN_ID, ACCEPT_ITEM, CALLED_REF, CALLING_REF, COMMON_REF, ADD_REF = 1, 5, 9, 10, 11, 12
SYNC_TYPE, TOKEN_ITEM, TRANSPORT_DISC, PROTO_OPT, SESS_REQ, TSDU_MAX = 15, 16, 17, 19, 20, 21
VERSION, INIT_SERIAL, PREPARE_TYPE, ENCLOSURE, TOKEN_SETTING, RESYNC_TYPE = 22, 23, 24, 25, 26, 27
LINKING, ACTIVITY_ID, SERIAL, REFLECT, REASON = 33, 41, 42, 49, 50
CALLING_SEL, CALLED_SEL, SECOND_RESYNC, SECOND_SERIAL, SECOND_INIT, UPPER_LIMIT = 51, 52, 53, 54, 55, 56
LARGE_INIT, LARGE_SECOND_INIT, DATA_OVERFLOW, USER_DATA, EXT_USER_DATA = 57, 58, 60, 193, 194

# presentation PPDUs: only what is needed to keep the PRES layer clean
CP = bytes.fromhex('31 05 a0 03 80 01 01')            # CP-type, mode selector only
CPA = bytes.fromhex('31 05 a0 03 80 01 01')
SIMPLE = lambda b: b'\x40' + li(len(b)) + b            # simply-encoded-data
def FULL(b):
    pdv = b'\x02\x01\x03\x81' + li(len(b)) + b
    seq = b'\x30' + li(len(pdv)) + pdv
    return b'\x61' + li(len(seq)) + seq


def tpkt_cotp(s):
    d = b'\x02\xf0\x80' + s
    return b'\x03\x00' + struct.pack('>H', 4 + len(d)) + d


# --------------------------------------------------------------- IP / TCP

def csum(b):
    if len(b) % 2:
        b += b'\0'
    t = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while t >> 16:
        t = (t & 0xFFFF) + (t >> 16)
    return (~t) & 0xFFFF


def ip_pkt(src, dst, proto, payload, ident=1):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0, bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return bytes([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]) + b'\x08\x00' + ip + payload


def tcp_seg(src, dst, sp, dp, seq, ack, flags, payload=b''):
    opt = b'\x02\x04\x05\xb4' if flags == 2 else b''
    if flags == 2:
        ack = 0
    tcp = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt + payload
    tcp = tcp[:16] + struct.pack('>H', csum(bytes(src) + bytes(dst) + struct.pack('>BBH', 0, 6, len(tcp)) + tcp)) + tcp[18:]
    return ip_pkt(src, dst, 6, tcp)


class Stream:
    def __init__(self, out, a=(10, 0, 0, 1), b=(10, 0, 0, 2), sp=49500, dp=102):
        self.out, self.a, self.b, self.sp, self.dp = out, a, b, sp, dp
        self.sc, self.ss = 1000, 5000
        self._send(0, b'', 2)
        self._send(1, b'', 0x12)
        self._send(0, b'', 0x10)

    def _send(self, side, payload, flags=0x18):
        if side == 0:
            self.out.append(tcp_seg(self.a, self.b, self.sp, self.dp, self.sc, self.ss, flags, payload))
            self.sc += max(len(payload), 1 if flags & 3 else 0)
        else:
            self.out.append(tcp_seg(self.b, self.a, self.dp, self.sp, self.ss, self.sc, flags, payload))
            self.ss += max(len(payload), 1 if flags & 3 else 0)

    def c(self, s):
        self._send(0, tpkt_cotp(s))

    def s(self, s):
        self._send(1, tpkt_cotp(s))

    def raw_c(self, b):
        self._send(0, b)

    def close(self):
        self._send(0, b'', 0x11)
        self._send(1, b'', 0x11)
        self._send(0, b'', 0x10)


def exp_pdu(payload, name='ses'):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload


def pcapng(fname, frames):
    """frames: list of (interface, bytes); interface 0 = Ethernet, 1 = Exported PDU."""
    def blk(t, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += blk(1, struct.pack('<HHI', 1, 0, 65535))
    out += blk(1, struct.pack('<HHI', 252, 0, 65535))
    for i, (ifc, d) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xFFFFFFFF, len(d), len(d)) + d)
    with open(fname, 'wb') as f:
        f.write(out)


# ------------------------------------------------------------------- main

def clean():
    F = []
    X = []
    st = Stream(F)
    big = bytes(range(256)) + bytes(60)                 # 316 bytes: 3 byte length form

    # CONNECT with every connect parameter, the connection identifier group
    # and the extended length form
    conn_id = pi(CONN_ID, pi(CALLED_REF, b'CALLED') + pi(CALLING_REF, b'CALLING') +
                 pi(COMMON_REF, b'COMMON-REF') + pi(ADD_REF, b'\x01\x02\x03'))
    st.c(spdu(13,
              conn_id +
              pi(PROTO_OPT, b'\x01') +
              pi(TSDU_MAX, struct.pack('>HH', 65528, 65528)) +
              pi(VERSION, b'\x03') +
              pi(INIT_SERIAL, b'000001') +
              pi(TOKEN_SETTING, b'\xff') +
              pi(SESS_REQ, struct.pack('>H', 0x0ffe)) +
              pi(CALLING_SEL, b'\x00\x01') +
              pi(CALLED_SEL, b'\x00\x02') +
              pi(USER_DATA, CP)))
    # CONNECT whose parameter group is long enough for the 3 byte length form
    st.c(spdu(13, pi(CONN_ID, pi(CALLED_REF, big)) + pi(SESS_REQ, struct.pack('>H', 0x0001))))
    # CONNECT with a long parameter inside a PI
    st.c(spdu(13, pi(CALLING_REF, big) + pi(PROTO_OPT, b'\x00')))
    # empty reference parameters (length 0), and unknown parameter types
    st.c(spdu(13, pi(CALLED_REF) + pi(CALLING_REF) + pi(COMMON_REF) + pi(ADD_REF) + pi(INIT_SERIAL) +
              pi(ACTIVITY_ID) + pi(SERIAL) + pi(CALLING_SEL) + pi(CALLED_SEL) + pi(SECOND_SERIAL) +
              pi(SECOND_INIT) + pi(LARGE_INIT) + pi(LARGE_SECOND_INIT) + pi(0x99, b'xyz')))
    # ACCEPT with an accept item group and token item
    st.s(spdu(14,
              pi(CONN_ID, pi(CALLED_REF, b'CALLED') + pi(COMMON_REF, b'C')) +
              pi(ACCEPT_ITEM, pi(PROTO_OPT, b'\x00') + pi(TSDU_MAX, struct.pack('>HH', 8192, 8192)) +
                 pi(VERSION, b'\x02') + pi(TOKEN_ITEM, b'\x55') + pi(SESS_REQ, struct.pack('>H', 0x1fff))) +
              pi(TOKEN_SETTING, b'\x00') +
              pi(INIT_SERIAL, b'1') +
              pi(CALLING_SEL, b'\x00\x01') + pi(CALLED_SEL, b'\x00\x02') +
              pi(USER_DATA, CPA)))
    # a group inside a group (invalid but decoded as an item)
    st.s(spdu(14, pi(ACCEPT_ITEM, pi(ACCEPT_ITEM, b'\x01') + pi(USER_DATA, b'\x01') + pi(EXT_USER_DATA, b'\x02') +
                     pi(CONN_ID, b'\x03') + pi(LINKING, b'\x04') + pi(0x99, b'\x05') + pi(TOKEN_ITEM, b'\x01'))))
    # ACCEPT with extended user data, then data overflow items
    st.s(spdu(14, pi(VERSION, b'\x01') + pi(EXT_USER_DATA, CPA)))
    # CONNECT DATA OVERFLOW, OVERFLOW ACCEPT
    st.c(spdu(15, pi(PROTO_OPT, b'\x01') + pi(VERSION, b'\x02') + pi(ENCLOSURE, b'\x03') + pi(DATA_OVERFLOW, b'\x01')))
    st.s(spdu(16, pi(TSDU_MAX, struct.pack('>HH', 1024, 1024)) + pi(VERSION, b'\x02')))
    # REFUSE with every reason code, with and without user data
    for r in (0, 1, 2, 129, 130, 131, 132, 133, 134, 200):
        st.s(spdu(12, pi(TRANSPORT_DISC, b'\x01') + pi(SESS_REQ, struct.pack('>H', 1)) + pi(VERSION, b'\x02') +
                  pi(REASON, bytes([r]))))
    st.s(spdu(12, pi(REASON, b'\x02')))
    # FINISH, DISCONNECT, NOT FINISHED, ABORT, ABORT ACCEPT
    st.c(spdu(9, pi(TRANSPORT_DISC, b'\x01') + pi(USER_DATA, b'\x40\x01\x01')))
    st.s(spdu(10, pi(USER_DATA, b'\x40\x01\x02')))
    st.s(spdu(8))
    st.c(spdu(25, pi(TRANSPORT_DISC, b'\x15')))
    st.s(spdu(25, pi(TRANSPORT_DISC, b'\x0a')))
    st.c(spdu(26))
    # transport disconnect options: every bit pattern (including user abort)
    st.c(spdu(25, pi(TRANSPORT_DISC, b'\x05')))
    st.c(spdu(25, pi(TRANSPORT_DISC, b'\x00')))

    # give tokens + data transfer with enclosure item and user information
    st.c(b'\x01\x00' + spdu(1, pi(ENCLOSURE, b'\x03')) + SIMPLE(b'payload one'))
    # GT + DT without enclosure
    st.c(b'\x01\x00' + spdu(1) + SIMPLE(b'payload two'))
    # PLEASE TOKENS (category 0), alone and followed by a data transfer
    st.c(b'\x02\x00')
    st.c(b'\x02\x00' + spdu(1) + SIMPLE(b'three'))
    st.c(b'\x02\x00' + spdu(9))
    # data transfer sequences: beginning, middle, end (reassembly), twice
    for n in (1, 2):
        part = SIMPLE(b'segmented application data %d' % n + bytes(range(40)))
        a, b, c = part[:20], part[20:41], part[41:]
        st.c(b'\x01\x00' + spdu(1, pi(ENCLOSURE, b'\x01')) + a)
        st.c(b'\x01\x00' + spdu(1, pi(ENCLOSURE, b'\x00')) + b)
        st.c(b'\x01\x00' + spdu(1, pi(ENCLOSURE, b'\x02')) + c)
    # beginning + end only (two segments)
    part = SIMPLE(b'two segments')
    st.s(b'\x01\x00' + spdu(1, pi(ENCLOSURE, b'\x01')) + part[:10])
    st.s(b'\x01\x00' + spdu(1, pi(ENCLOSURE, b'\x02')) + part[10:])
    # only the end bit (no user information) in a lone SPDU, reserved bits
    st.s(spdu(1, pi(ENCLOSURE, b'\xfe')))
    # typed data, expedited data, capability data: the T.125 heuristic of COTP takes these first byte
    # values over TCP, so they are sent as Exported PDU frames that name the ses dissector
    X.append(spdu(33, pi(ENCLOSURE, b'\x03')) + SIMPLE(b'typed data'))
    X.append(spdu(5) + SIMPLE(b'expedited'))
    X.append(spdu(61, pi(USER_DATA, SIMPLE(b'capability'))))
    X.append(spdu(62))
    # sync / activity / resync / token SPDUs
    X.append(spdu(7, pi(PREPARE_TYPE, b'\x01')))
    X.append(spdu(41, pi(SERIAL, b'000012') + pi(SYNC_TYPE, b'\x00')))
    X.append(spdu(42, pi(SERIAL, b'000013')))
    X.append(spdu(41, pi(SERIAL, b'000014')))
    st.c(spdu(49, pi(SYNC_TYPE, b'\x01') + pi(SERIAL, b'000014')))
    st.s(spdu(53, pi(SERIAL, b'000015') + pi(RESYNC_TYPE, b'\x02') + pi(TOKEN_SETTING, b'\x00')))
    st.c(spdu(53, pi(SECOND_RESYNC, b'\x01') + pi(SECOND_SERIAL, b'000016') + pi(SECOND_INIT, b'000017') +
              pi(UPPER_LIMIT, b'\x00\x00\x00\x10') + pi(LARGE_INIT, b'000018') + pi(LARGE_SECOND_INIT, b'000019')))
    st.s(spdu(34, pi(SERIAL, b'000020')))
    st.c(spdu(45, pi(ACTIVITY_ID, b'\x00\x01\x02\x03\x04\x05')))
    st.c(spdu(29, pi(LINKING, pi(CALLED_REF, b'L')) + pi(ACTIVITY_ID, b'\x01') + pi(REFLECT, b'\x09')))
    st.c(spdu(57, pi(REASON, b'\x01')))
    st.s(spdu(58))
    st.c(spdu(48, pi(REASON, b'\x02')))
    st.c(spdu(21))
    st.s(spdu(22))
    st.c(spdu(50, pi(SERIAL, b'1')))
    # token SPDU with the data token item
    st.c(spdu(8, pi(TOKEN_ITEM, b'\x11')))
    # every token item bit
    st.c(spdu(8, pi(TOKEN_ITEM, b'\xff')))
    # every enclosure / version / protocol option / token setting value
    st.c(spdu(8, pi(VERSION, b'\x00') + pi(PROTO_OPT, b'\xff') + pi(TOKEN_SETTING, b'\xaa') + pi(SESS_REQ, b'\xff\xff')))
    # an ACCEPT whose accept item group holds an enclosure item with only the end bit
    st.s(spdu(14, pi(ACCEPT_ITEM, pi(ENCLOSURE, b'\x02'))))
    # COTP data that is not an SPDU: unknown type, Give Tokens followed by an unknown type, an
    # S7comm-like start with an unknown parameter, a length beyond the data, a bad second SPDU
    st.c(b'\x99\x00')
    st.c(b'\x01\x00\x99\x00')
    st.c(b'\x32\x00\xee')
    st.c(b'\x0d\x20\x00')
    st.c(b'\x09\x00\x99')
    st.close()

    # ---- a second connection without reassembly (desegment pref off in runcov)
    # ---- CLSES: unit data over COTP/CLTP on IP protocol 39
    def cltp(spdu_bytes, tsaps=True):
        v = b'\xc1\x02\x00\x01\xc2\x02\x00\x02' if tsaps else b''
        return bytes([1 + len(v), 0x40]) + v + spdu_bytes
    s, d = (10, 0, 1, 1), (10, 0, 1, 2)
    F.append(ip_pkt(s, d, 39, cltp(spdu(64)), 100))
    F.append(ip_pkt(s, d, 39, cltp(spdu(64, pi(CALLING_SEL, b'\x00\x01') + pi(CALLED_SEL, b'\x00\x02'))), 101))
    return F, X


def malformed():
    F = []
    st = Stream(F, sp=49600)
    # wrong lengths for fixed length parameters
    for t, v in ((TOKEN_ITEM, b'\x01\x02'), (TRANSPORT_DISC, b''), (PROTO_OPT, b'\x01\x02'), (SESS_REQ, b'\x01'),
                 (TSDU_MAX, b'\x01\x02'), (VERSION, b'\x01\x02'), (ENCLOSURE, b''), (TOKEN_SETTING, b'\x01\x02'),
                 (REASON, b'')):
        st.c(spdu(8, pi(t, v)))
    # parameter length does not fit: top level and inside a group
    st.c(spdu(8, bytes([VERSION, 9, 1])))
    st.c(b'\x08\x04' + bytes([VERSION, 0xff, 0, 1]))
    st.c(spdu(8, pi(CONN_ID, bytes([CALLED_REF, 9, 1, 2]))))
    st.c(b'\x08\x05' + pi(CONN_ID, b'')[:2] + bytes([CALLED_REF, 0xff, 0]))
    st.c(spdu(8, pi(CONN_ID, bytes([CALLED_REF, 0xff, 0]))))
    st.c(spdu(8, bytes([VERSION])))                   # type without a length
    # a 3 octet length form that does not fit in what is left of the parameters / group
    st.c(b'\x08\x02' + bytes([VERSION, 0xff]) + b'\x08\x00')
    st.c(spdu(8, pi(CONN_ID, bytes([CALLED_REF, 0xff])) + b'\x00\x01'))
    # an accept item group that holds a parameter longer than the group
    st.c(spdu(14, pi(ACCEPT_ITEM, bytes([VERSION, 5, 1])) + b'\x00\x00\x00\x00\x00\x00'))
    # truncated SPDUs
    st.c(b'\x0d')
    st.c(b'\x0d\x20\x01')
    st.c(b'\x01\x00\x01')
    s, d = (10, 0, 1, 1), (10, 0, 1, 2)
    F.append(ip_pkt(s, d, 39, bytes([1, 0x40]) + spdu(64) + b'\x01\x02\x03\x04\x05', 102))
    # data transfer sequence with a beginning only (never completed)
    st.c(b'\x01\x00' + spdu(1, pi(ENCLOSURE, b'\x01')) + b'\x40\x03abc')
    # a segment with a bad presentation PPDU and a single segment of garbage
    st.c(b'\x01\x00' + spdu(1, pi(ENCLOSURE, b'\x03')) + b'\xff\xff\xff\xff\xff')
    st.c(spdu(13, pi(USER_DATA, b'\xde\xad\xbe\xef\x00\x01')))
    st.c(spdu(25, pi(USER_DATA, b'\x01\x02')))
    st.c(spdu(12, pi(REASON, b'\x02\x01\x02\x03\x04\x05')))
    # unknown SPDU type after a valid one
    st.c(spdu(9) + b'\x77\x00')
    st.c(spdu(9) + b'\x0a\x05\x01')
    st.close()
    return F


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    F, X = clean()
    pcapng(os.path.join(out, 'ses-coverage.pcapng'), [(0, f) for f in F] + [(1, exp_pdu(x)) for x in X])
    pcapng(os.path.join(out, 'ses-coverage-malformed.pcapng'), [(0, f) for f in malformed()])
