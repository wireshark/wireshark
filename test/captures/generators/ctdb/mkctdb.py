#!/usr/bin/env python3
# Generates test/captures/ctdb_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Samba CTDB (cluster
TDB) dissector (packet-ctdb.c).

CTDB nodes talk over TCP (port 4379 by convention). The dissector has no
port registered by default; its TCP heuristic (enabled by default)
recognises a PDU by the magic "CTDB" (big endian) or "BDTC" (little
endian) at offset 4. Every PDU is one TCP segment: a 32 octet header
(length, magic, version, generation, opcode, destination and source
node, request id) and an opcode specific body.

Every packet is built from scratch with struct; nothing comes from a
real network.

Usage: mkctdb.py <output directory>

Writes:
  ctdb-coverage.pcap            every opcode, both byte orders, call and
                                dmaster transactions, every control the
                                dissector decodes and some it does not,
                                request/response matching, payloads
                                the heuristic rejects, the reproducer
                                frames of
                                ctdb_req_control_twopass.py
  ctdb-coverage-malformed.pcap  truncated PDUs, lengths past the end,
                                too many nodes in a node map
"""

import os
import struct
import sys

def csum16(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Pcap:
    def __init__(self):
        self.frames = []
        self.t = 1700000000

    def add(self, frame):
        self.frames.append((self.t, frame))
        self.t += 1

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for t, fr in self.frames:
                f.write(struct.pack('<IIII', t, 0, len(fr), len(fr)) + fr)


class Conn:
    """A TCP connection between a client and a server; keeps sequence
    numbers so that TCP analysis has nothing to complain about."""
    def __init__(self, cap, cport, sport, cip=(192, 0, 2, 1), sip=(192, 0, 2, 2)):
        self.cap, self.cport, self.sport = cap, cport, sport
        self.cip, self.sip = bytes(cip), bytes(sip)
        self.cseq, self.sseq = 1000, 5000
        self.handshake()

    def frame(self, from_client, flags, payload):
        if from_client:
            src, dst, sp, dp, seqn, ack = self.cip, self.sip, self.cport, self.sport, self.cseq, self.sseq
        else:
            src, dst, sp, dp, seqn, ack = self.sip, self.cip, self.sport, self.cport, self.sseq, self.cseq
        if flags & 0x02:
            # SYN: no ACK number unless SYN/ACK; MSS option 65000 so that
            # TCP does not note segments as longer than the MSS.
            if not flags & 0x10:
                ack = 0
            opts = struct.pack('>BBHBBBB', 2, 4, 65000, 1, 1, 4, 2)
        else:
            opts = b''
        tcp = struct.pack('>HHIIBBHHH', sp, dp, seqn, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts + payload
        ph = src + dst + struct.pack('>BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('>H', csum16(ph + tcp)) + tcp[18:]
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('>H', csum16(ip)) + ip[12:]
        mac_c, mac_s = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
        eth = (mac_s + mac_c if from_client else mac_c + mac_s) + b'\x08\x00'
        self.cap.add(eth + ip + tcp)
        n = len(payload) + (1 if flags & 0x03 else 0)
        if from_client:
            self.cseq += n
        else:
            self.sseq += n

    def handshake(self):
        self.cseq -= 1
        self.sseq -= 1
        c, s = self.cseq, self.sseq
        # SYN, SYN/ACK, ACK
        self.frame(True, 0x02, b'')
        self.frame(False, 0x12, b'')
        self.frame(True, 0x10, b'')

    def send(self, from_client, data, split=None):
        """Send data, optionally split at the given offsets."""
        cuts = [0] + list(split or []) + [len(data)]
        for a, b in zip(cuts, cuts[1:]):
            self.frame(from_client, 0x18, data[a:b])

    def c(self, data, split=None):
        self.send(True, data, split)

    def s(self, data, split=None):
        self.send(False, data, split)


def rfc2510(ptype, body):
    return struct.pack('>IB', 1 + len(body), ptype) + body


def draft10(ptype, body, flags=0):
    return struct.pack('>IBBB', 3 + len(body), 10, flags, ptype) + body


def http_req(body, ctype, path='/pkix/'):
    h = 'POST %s HTTP/1.1\r\nHost: ca.example\r\n' % path
    if ctype:
        h += 'Content-Type: %s\r\n' % ctype
    h += 'Content-Length: %d\r\n\r\n' % len(body)
    return h.encode() + body


def http_rsp(body, ctype):
    h = 'HTTP/1.1 200 OK\r\n'
    if ctype:
        h += 'Content-Type: %s\r\n' % ctype
    h += 'Content-Length: %d\r\nCache-Control: no-cache\r\n\r\n' % len(body)
    return h.encode() + body

# ---------------------------------------------------------------- captures


# ---------------------------------------------------------------- CTDB

REQ_CALL, REPLY_CALL, REQ_DMASTER, REPLY_DMASTER = 0, 1, 2, 3
REPLY_ERROR, REQ_MESSAGE, REQ_CONTROL, REPLY_CONTROL, REQ_KEEPALIVE = 4, 5, 7, 8, 9

PROCESS_EXISTS, STATISTICS, GET_RECMODE = 0, 1, 15
GET_RECMASTER, FREEZE, THAW, GET_NODEMAP = 31, 33, 34, 91

LOCKING_TDB = 0x42fe72c5
NOTIFY_TDB = 0x435d3410


class Ctdb:
    """Builds CTDB PDUs in one byte order."""
    def __init__(self, le=True, generation=7):
        self.e = '<' if le else '>'
        self.magic = b'BDTC' if le else b'CTDB'
        self.generation = generation

    def p(self, fmt, *v):
        return struct.pack(self.e + fmt, *v)

    def hdr(self, opcode, dst, src, reqid, body, length=None):
        total = 32 + len(body) if length is None else length
        return (self.p('I', total) + self.magic +
                self.p('IIIIII', 1, self.generation, opcode, dst, src, reqid) + body)

    def req_call(self, dst, src, reqid, key, data, flags=0, dbid=LOCKING_TDB,
                 callid=0, hopcount=0):
        body = self.p('IIIIII', flags, dbid, callid, hopcount, len(key), len(data)) + key + data
        return self.hdr(REQ_CALL, dst, src, reqid, body)

    def reply_call(self, dst, src, reqid, status, data):
        return self.hdr(REPLY_CALL, dst, src, reqid, self.p('II', status, len(data)) + data)

    def req_dmaster(self, dst, src, reqid, dmaster, key, data, rsn, dbid=LOCKING_TDB):
        # dbid, 4 octets of alignment, rsn (8), dmaster, keylen, datalen
        body = self.p('IIQIII', dbid, 0, rsn, dmaster, len(key), len(data)) + key + data
        return self.hdr(REQ_DMASTER, dst, src, reqid, body)

    def reply_dmaster(self, dst, src, reqid, key, data, rsn, dbid=LOCKING_TDB):
        body = self.p('IIQII', dbid, 0, rsn, len(key), len(data)) + key + data
        return self.hdr(REPLY_DMASTER, dst, src, reqid, body)

    def req_control(self, dst, src, reqid, ctrl, data=b'', srvid=0, clientid=0, flags=0):
        # opcode, 4 octets of alignment, srvid (8), client id, flags, datalen
        body = self.p('IIQIII', ctrl, 0, srvid, clientid, flags, len(data)) + data
        return self.hdr(REQ_CONTROL, dst, src, reqid, body)

    def reply_control(self, dst, src, reqid, status, data=b'', error=b''):
        body = self.p('III', status, len(data), len(error)) + data + error
        return self.hdr(REPLY_CONTROL, dst, src, reqid, body)

    def nodemap(self, nodes):
        out = self.p('I', len(nodes))
        for vnn, flags, ip in nodes:
            # struct sockaddr_in: family, port, address, zero padding
            out += self.p('II', vnn, flags) + struct.pack('<H', 2) + struct.pack('>H', 4379) + bytes(ip) + bytes(8)
        return out


def reproducer_frames():
    """ctdb_req_control_twopass.py: two REQ_CONTROL with the
    same (reqid, src, dst) and different control opcodes, as two TCP
    segments without a handshake (ctdb_common.tcp_pkt)."""
    def tcp_pkt(src, dst, sport, dport, seq, payload):
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 0x50, 0x18, 65535, 0, 0) + payload
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, bytes(src), bytes(dst))
        ip = ip[:10] + struct.pack('!H', csum16(ip)) + ip[12:]
        ph = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack('!H', csum16(ph + tcp)) + tcp[18:]
        return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + tcp
    c = Ctdb(le=True, generation=1)
    p1 = c.req_control(2, 1, 1, PROCESS_EXISTS, struct.pack('<I', 1234))
    p2 = c.req_control(2, 1, 1, GET_RECMODE)
    a, b = [192, 0, 2, 1], [192, 0, 2, 2]
    return [tcp_pkt(a, b, 50123, 50124, 1, p1), tcp_pkt(a, b, 50123, 50124, 1 + len(p1), p2)]


NODE0, NODE1, NODE2 = (192, 0, 2, 10), (192, 0, 2, 11), (192, 0, 2, 12)


def main_capture():
    cap = Pcap()
    # Node 1 (client side) and node 0 over port 4379, little endian.
    c = Conn(cap, 40001, 4379, NODE1, NODE0)
    L = Ctdb(le=True)
    # A call that needs the record: REQ_CALL with IMMEDIATE, the dmaster
    # migration (REQ_DMASTER to the lmaster, REPLY_DMASTER back) and the
    # REPLY_CALL.
    c.c(L.req_call(0, 1, 100, b'brlock-key-0001', b'call data', flags=1,
                   dbid=LOCKING_TDB, callid=1, hopcount=0))
    c.s(L.req_dmaster(2, 0, 100, 1, b'brlock-key-0001', b'record', rsn=0x10))
    c.c(L.reply_dmaster(1, 0, 100, b'brlock-key-0001', b'record', rsn=0x11))
    c.s(L.reply_call(1, 0, 100, 0, b'result'))
    # A second call without IMMEDIATE, an unnamed database, empty key and
    # data, and a REPLY_CALL with status -1.
    c.c(L.req_call(0, 1, 101, b'', b'', flags=0, dbid=0x12345678, callid=0, hopcount=3))
    c.s(L.reply_call(1, 0, 101, 0xffffffff, b''))
    # Controls the dissector decodes, each answered.
    c.c(L.req_control(0, 1, 200, PROCESS_EXISTS, struct.pack('<I', 4711), srvid=0xf0000000000000a1, clientid=0x1001))
    c.s(L.reply_control(1, 0, 200, 0))
    c.c(L.req_control(0, 1, 201, PROCESS_EXISTS, struct.pack('<I', 4712)))
    c.s(L.reply_control(1, 0, 201, 1, error=b'no such process'))
    c.c(L.req_control(0, 1, 202, GET_RECMODE))
    c.s(L.reply_control(1, 0, 202, 0))
    c.c(L.req_control(0, 1, 203, GET_RECMODE))
    c.s(L.reply_control(1, 0, 203, 1))
    c.c(L.req_control(0, 1, 204, GET_RECMODE))
    c.s(L.reply_control(1, 0, 204, 5))
    c.c(L.req_control(0, 1, 205, GET_RECMASTER))
    c.s(L.reply_control(1, 0, 205, 2))
    c.c(L.req_control(0, 1, 206, GET_NODEMAP))
    c.s(L.reply_control(1, 0, 206, 0, L.nodemap([(0, 0, NODE0), (1, 0, NODE1), (2, 0x2, NODE2)])))
    c.c(L.req_control(0, 1, 207, GET_NODEMAP))
    c.s(L.reply_control(1, 0, 207, 0, L.nodemap([])))
    # Controls in the table without a decoder (FREEZE, THAW), one not in
    # the table (STATISTICS) and an unknown opcode, with data and error.
    c.c(L.req_control(0, 1, 208, FREEZE, flags=1))
    c.s(L.reply_control(1, 0, 208, 0))
    c.c(L.req_control(0, 1, 209, THAW, b'\x01\x00\x00\x00'))
    c.s(L.reply_control(1, 0, 209, 0, b'\x00' * 4, b'thawed'))
    c.c(L.req_control(0, 1, 210, STATISTICS))
    c.s(L.reply_control(1, 0, 210, 0, bytes(range(32))))
    c.c(L.req_control(0, 1, 211, 999, b'opaque'))
    c.s(L.reply_control(1, 0, 211, 0xffffffff, b'', b'unknown control'))
    # A reply whose request is not in the capture (shown as header only).
    c.s(L.reply_control(1, 0, 299, 0, b'\x01\x02\x03\x04'))
    # The other opcodes: REPLY_ERROR, REQ_MESSAGE, REQ_KEEPALIVE, an
    # unknown opcode (header only).
    c.s(L.hdr(REPLY_ERROR, 1, 0, 102, L.p('III', 1, 5, 0) + b'error'))
    c.c(L.hdr(REQ_MESSAGE, 0, 1, 103, L.p('QI', 0xf000000000000001, 4) + b'ping'))
    c.c(L.hdr(REQ_KEEPALIVE, 0, 1, 104, b''))
    c.s(L.hdr(42, 1, 0, 105, b''))
    # Big endian node 2 talking to node 0.
    c = Conn(cap, 40002, 4379, NODE2, NODE0)
    B = Ctdb(le=False, generation=9)
    c.c(B.req_call(0, 2, 300, b'notify-key', b'x', flags=1, dbid=NOTIFY_TDB, callid=2, hopcount=1))
    c.s(B.req_dmaster(1, 0, 300, 2, b'notify-key', b'', rsn=0x100, dbid=NOTIFY_TDB))
    c.c(B.reply_dmaster(2, 1, 300, b'notify-key', b'', rsn=0x101, dbid=NOTIFY_TDB))
    c.s(B.reply_call(2, 0, 300, 0, b'ok'))
    c.c(B.req_control(0, 2, 400, PROCESS_EXISTS, struct.pack('>I', 99)))
    c.s(B.reply_control(2, 0, 400, 0))
    c.c(B.req_control(0, 2, 401, GET_NODEMAP))
    c.s(B.reply_control(2, 0, 401, 0, B.nodemap([(0, 0, NODE0), (2, 1, NODE2)])))
    c.c(B.req_control(0, 2, 402, GET_RECMASTER))
    c.s(B.reply_control(2, 0, 402, 0))
    # A request id that is reused: the reply goes to the later request,
    # and on every pass each request keeps its own opcode (the fix).
    c = Conn(cap, 40003, 4379, NODE1, NODE0)
    c.c(L.req_control(0, 1, 500, PROCESS_EXISTS, struct.pack('<I', 5000)))
    c.c(L.req_control(0, 1, 500, GET_RECMODE))
    c.s(L.reply_control(1, 0, 500, 1))
    # Payloads the heuristic rejects (shorter than 8 octets, no magic).
    c = Conn(cap, 40004, 4379, NODE1, NODE0)
    c.c(b'hello')
    c.s(b'not a CTDB packet')
    for fr in reproducer_frames():
        cap.add(fr)
    return cap


def malformed_capture():
    cap = Pcap()
    c = Conn(cap, 50001, 4379, NODE1, NODE0)
    L = Ctdb(le=True)
    # Truncated header and truncated bodies of every opcode.
    c.c(L.req_call(0, 1, 1, b'k', b'd')[:20])
    c.c(L.req_call(0, 1, 2, b'k', b'd')[:40])
    c.c(L.reply_call(1, 0, 2, 0, b'')[:36])
    c.c(L.req_dmaster(0, 1, 3, 1, b'k', b'd', rsn=1)[:44])
    c.c(L.reply_dmaster(0, 1, 3, b'k', b'd', rsn=1)[:44])
    c.c(L.req_control(0, 1, 4, PROCESS_EXISTS, b'\x01\x00\x00\x00')[:40])
    c.c(L.req_control(0, 1, 5, PROCESS_EXISTS))            # no pid
    c.s(L.reply_control(1, 0, 5, 0)[:38])
    # Key, data and error lengths past the end of the PDU.
    c.c(L.req_call(0, 1, 6, b'key', b'')[:-1])
    c.c(L.hdr(REQ_CALL, 0, 1, 7, L.p('IIIIII', 0, 0, 0, 0, 0xffffffff, 0)))
    c.c(L.hdr(REQ_CALL, 0, 1, 8, L.p('IIIIII', 0, 0, 0, 0, 0, 0x7fffffff)))
    c.c(L.hdr(REPLY_CALL, 1, 0, 8, L.p('II', 0, 1000) + b'short'))
    c.c(L.req_control(0, 1, 9, GET_NODEMAP))
    c.s(L.reply_control(1, 0, 9, 0, b'', b'') + L.p('I', 100))  # datalen 0, data follows
    # A node map that claims more nodes than are present, and one with
    # more than 500 nodes (expert info, dissection stops).
    c.c(L.req_control(0, 1, 10, GET_NODEMAP))
    c.s(L.reply_control(1, 0, 10, 0, L.p('I', 3) + L.nodemap([(0, 0, NODE0)])[4:]))
    c.c(L.req_control(0, 1, 11, GET_NODEMAP))
    c.s(L.reply_control(1, 0, 11, 0, L.p('I', 501)))
    # Data and error lengths past the end in REQ/REPLY_CONTROL.
    c.c(L.req_control(0, 1, 12, FREEZE)[:-4] + L.p('I', 64))
    c.c(L.req_control(0, 1, 13, FREEZE))
    c.s(L.hdr(REPLY_CONTROL, 1, 0, 13, L.p('III', 0, 0, 50) + b'err'))
    return cap


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main_capture().write(os.path.join(out, 'ctdb-coverage.pcap'))
    malformed_capture().write(os.path.join(out, 'ctdb-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
