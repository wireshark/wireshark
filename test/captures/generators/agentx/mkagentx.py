#!/usr/bin/env python3
# AgentX coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""AgentX (packet-agentx.c, RFC 2741): a subagent (10.0.0.2) talks to a master
agent (10.0.0.1) on TCP port 705.

Usage: mkagentx.py [<output directory>]

Writes:
  agentx-coverage.pcap            every PDU type, both byte orders, the
                                  non-default context, every varbind type,
                                  every response error and close reason,
                                  OID prefixes (also above 127) and PDUs
                                  split over and packed into TCP segments
  agentx-coverage-malformed.pcap  paths that end in an exception

Every packet is built here; nothing comes from a real network.
"""

import os
import struct
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))

from capgen import eth, ipv4, tcp, write_pcap  # noqa: E402

AGENTX_PORT = 705
MASTER = (10, 0, 0, 1)
SUBAGENT = (10, 0, 0, 2)
SYN_OPTIONS = bytes.fromhex('020405b404020101')  # MSS, SACK permitted

# PDU types
(OPEN, CLOSE, REGISTER, UNREGISTER, GET, GETNEXT, GETBULK, TESTSET, COMMITSET,
 UNDOSET, CLEANUPSET, NOTIFY, PING, IDXALLOC, IDXDEALLOC, ADDCAPS, REMCAPS,
 RESPONSE) = range(1, 19)

# header flags
F_REGISTER, F_NEWINDEX, F_ANYINDEX, F_CONTEXT, F_NBO = 0x01, 0x02, 0x04, 0x08, 0x10

# varbind types
INT, OSTR, NULL, OID, IPADDR, COUNTER32, GAUGE32, TIMETICK, OPAQUE, COUNTER64 = \
    2, 4, 5, 6, 64, 65, 66, 67, 68, 70
NOSUCHOBJ, NOSUCHINST, ENDOFMIB = 128, 129, 130


class Pcap:
    def __init__(self):
        self.frames = []

    def tcp(self, sport, dport, seq, ack, flags, payload=b'', src=SUBAGENT, dst=MASTER):
        seg = tcp(payload, sport, dport, seq=seq, ack=ack, flags=flags,
                  options=SYN_OPTIONS if flags & 0x02 else b'', src=bytes(src), dst=bytes(dst))
        ip = ipv4(seg, 6, src=bytes(src), dst=bytes(dst), ident=len(self.frames) & 0xffff,
                  flags_frag=0x4000)
        self.frames.append(eth(ip, 0x0800, dst='02:00:00:00:00:02', src='02:00:00:00:00:01'))

    def write(self, path):
        write_pcap(path, self.frames, ts=lambda i: (1700000000 + i // 100, (i % 100) * 10000))


class TcpStream:
    """A TCP connection from the subagent to the master agent."""
    def __init__(self, cap, cport):
        self.cap, self.cport = cap, cport
        self.cseq, self.sseq = 1000 + cport, 5000 + cport
        cap.tcp(cport, AGENTX_PORT, self.cseq, 0, 0x02)
        cap.tcp(AGENTX_PORT, cport, self.sseq, self.cseq + 1, 0x12, src=MASTER, dst=SUBAGENT)
        self.cseq += 1
        self.sseq += 1
        cap.tcp(cport, AGENTX_PORT, self.cseq, self.sseq, 0x10)

    def sub(self, *datas):
        """Each argument is one TCP segment from the subagent."""
        for data in datas:
            self.cap.tcp(self.cport, AGENTX_PORT, self.cseq, self.sseq, 0x18, data)
            self.cseq += len(data)

    def master(self, *datas):
        for data in datas:
            self.cap.tcp(AGENTX_PORT, self.cport, self.sseq, self.cseq, 0x18, data,
                         src=MASTER, dst=SUBAGENT)
            self.sseq += len(data)


# ---------------------------------------------------------------------------
# AgentX encoding. nbo selects the byte order of the whole PDU.

class Enc:
    def __init__(self, nbo=True):
        self.nbo = nbo
        self.e = '>' if nbo else '<'

    def u8(self, v):
        return struct.pack('B', v)

    def u16(self, v):
        return struct.pack(self.e + 'H', v)

    def u32(self, v):
        return struct.pack(self.e + 'I', v)

    def u64(self, v):
        return struct.pack(self.e + 'Q', v)

    def oid(self, subids, prefix=0, include=0):
        return (struct.pack('BBBB', len(subids), prefix, include, 0) +
                b''.join(self.u32(x) for x in subids))

    def ostr(self, v):
        if isinstance(v, str):
            v = v.encode()
        return self.u32(len(v)) + v + b'\0' * (-len(v) % 4)

    def varbind(self, vtype, name, value=None, prefix=0):
        out = self.u16(vtype) + b'\0\0' + self.oid(name, prefix)
        if vtype == OID:
            out += self.oid(value)
        elif vtype in (OSTR, IPADDR, OPAQUE):
            out += self.ostr(value)
        elif vtype in (INT, COUNTER32, GAUGE32, TIMETICK):
            out += self.u32(value)
        elif vtype == COUNTER64:
            out += self.u64(value)
        return out

    def pdu(self, ptype, payload, flags=0, sid=1, tid=0, pid=1):
        if self.nbo:
            flags |= F_NBO
        return (struct.pack('BBBB', 1, ptype, flags, 0) + self.u32(sid) + self.u32(tid) +
                self.u32(pid) + self.u32(len(payload)) + payload)


def body_pdus(x, ctx=False):
    """One PDU of every type (and of every shape the dissector has a branch
    for) in the byte order of x, as (subagent PDUs, master PDUs)."""
    fl = F_CONTEXT if ctx else 0
    c = x.ostr('ctx-a') if ctx else b''
    sa = []
    ma = []
    sid = 7 if ctx else 1

    def add(lst, ptype, payload, flags=0, **kw):
        lst.append(x.pdu(ptype, payload, flags | fl, sid=sid, **kw))

    if not ctx:
        # Open has no context field
        sa.append(x.pdu(OPEN, bytes([5, 0, 0, 0]) + x.oid([1, 2, 3], prefix=0) +
                        x.ostr('example subagent'), sid=0))
    sa.append(x.pdu(OPEN, bytes([0, 0, 0, 0]) + x.oid([]) + x.ostr(''), sid=0, pid=2))
    ma.append(x.pdu(RESPONSE, x.u32(100) + x.u16(0) + x.u16(0), sid=sid, pid=1))
    # Register: with and without the upper bound, instance registration
    add(sa, REGISTER, c + bytes([10, 127, 0, 0]) + x.oid([1, 2, 3, 4], prefix=2, include=1))
    add(sa, REGISTER, c + bytes([10, 127, 4, 0]) + x.oid([1, 2, 3, 4, 5]) + x.u32(255),
        flags=F_REGISTER)
    add(sa, UNREGISTER, c + bytes([0, 127, 0, 0]) + x.oid([1, 2, 3, 4], prefix=2))
    add(sa, UNREGISTER, c + bytes([0, 127, 4, 0]) + x.oid([1, 2, 3, 4, 5]) + x.u32(255))
    # Get, GetNext (exact and ranges), GetBulk
    rng = x.oid([1, 3, 6, 1, 2], include=1) + x.oid([1, 3, 6, 1, 3])
    add(ma, GET, c + x.oid([1, 3, 6, 1, 2, 1], prefix=0) + x.oid([]) + x.oid([1, 3, 6, 1, 4]) + x.oid([]))
    add(ma, GETNEXT, c + rng + rng)
    add(ma, GETBULK, c + x.u16(1) + x.u16(10) + rng + x.oid([1, 3, 6, 1, 4, 1], prefix=0) + x.oid([]))
    # Set transaction: TestSet with every varbind type, then the rest
    vbs = (x.varbind(INT, [1, 1], 7) + x.varbind(OSTR, [1, 2], 'text') +
           x.varbind(NULL, [1, 3]) + x.varbind(OID, [1, 4], [1, 3, 6, 1, 4, 1, 99]) +
           x.varbind(IPADDR, [1, 5], bytes([192, 0, 2, 5])) +
           x.varbind(COUNTER32, [1, 6], 0xfffffff0) + x.varbind(GAUGE32, [1, 7], 4000000000) +
           x.varbind(TIMETICK, [1, 8], 123456) + x.varbind(OPAQUE, [1, 9], b'\x01\x02\x03') +
           x.varbind(COUNTER64, [1, 10], 0x0123456789abcdef) + x.varbind(NOSUCHOBJ, [1, 11]) +
           x.varbind(NOSUCHINST, [1, 12]) + x.varbind(ENDOFMIB, [1, 13]) +
           x.varbind(99, [1, 14]))
    add(ma, TESTSET, c + vbs, tid=5)
    for t in (COMMITSET, UNDOSET, CLEANUPSET):
        add(ma, t, b'', tid=5)
    add(sa, NOTIFY, c + x.varbind(TIMETICK, [1, 3, 6, 1, 2, 1, 1, 3, 0], 1000, prefix=0) +
        x.varbind(OID, [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0], [1, 3, 6, 1, 4, 1, 99, 0, 1]))
    add(ma, PING, c)
    add(sa, IDXALLOC, c + x.varbind(INT, [1, 3, 6, 1, 4, 1, 99, 1], 0), flags=F_NEWINDEX)
    add(sa, IDXALLOC, c + x.varbind(OSTR, [1, 3, 6, 1, 4, 1, 99, 2], 'idx'), flags=F_ANYINDEX)
    add(sa, IDXDEALLOC, c + x.varbind(INT, [1, 3, 6, 1, 4, 1, 99, 1], 5))
    add(sa, ADDCAPS, c + x.oid([1, 3, 6, 1, 4, 1, 99, 5]) + x.ostr('capability description'))
    add(sa, REMCAPS, c + x.oid([1, 3, 6, 1, 4, 1, 99, 5]))
    # Response: with varbinds of several types
    add(sa, RESPONSE, x.u32(5000) + x.u16(0) + x.u16(0) + vbs, pid=3)
    return sa, ma


def coverage_packets(cap):
    # Network byte order, default context
    s = TcpStream(cap, 40001)
    x = Enc(True)
    sa, ma = body_pdus(x)
    for p in sa[:3]:
        s.sub(p)
    s.master(ma[0])
    for p in sa[3:]:
        s.sub(p)
    for p in ma[1:]:
        s.master(p)
    # Close with every reason
    for reason in range(1, 7):
        s.sub(x.pdu(CLOSE, bytes([reason, 0, 0, 0])))
    s.sub(x.pdu(CLOSE, bytes([99, 0, 0, 0])))
    # Every response error
    errors = list(range(0, 19)) + list(range(256, 266)) + [999]
    for i, e in enumerate(errors):
        s.master(x.pdu(RESPONSE, x.u32(i * 1000) + x.u16(e) + x.u16(0), pid=100 + i))
    # A PDU type that is not defined
    s.sub(x.pdu(99, b'\0' * 8))

    # Little-endian PDUs with a non-default context
    s = TcpStream(cap, 40002)
    x = Enc(False)
    sa, ma = body_pdus(x, ctx=True)
    for p in sa:
        s.sub(p)
    for p in ma:
        s.master(p)
    sa, ma = body_pdus(x)
    s.sub(*sa[:4])
    s.master(*ma[:3])

    # TCP segmentation: several PDUs in one segment, one PDU over three
    # segments, a PDU split inside the header
    s = TcpStream(cap, 40003)
    x = Enc(True)
    vb = x.varbind(OSTR, [1, 3, 6, 1, 2, 1, 1, 1, 0], 'a longer description of the system')
    r1 = x.pdu(RESPONSE, x.u32(1) + x.u16(0) + x.u16(0) + vb, pid=11)
    r2 = x.pdu(RESPONSE, x.u32(2) + x.u16(0) + x.u16(0) + vb, pid=12)
    r3 = x.pdu(RESPONSE, x.u32(3) + x.u16(0) + x.u16(0) + vb, pid=13)
    s.master(r1 + r2)
    s.master(r3[:10], r3[10:25], r3[25:])
    s.master(r1[:21 - 1], r1[20:] + r2[:7], r2[7:])

    # The varbinds of this Response-PDU and Notify-PDU have different
    # lengths; the subtrees must be as long as their own varbind. The OID
    # prefix 200 is unsigned.
    s = TcpStream(cap, 40004)
    x = Enc(True)
    vbs = (x.varbind(INT, [1, 2, 3], 7, prefix=2) + x.varbind(INT, [4, 5], 8, prefix=2) +
           x.varbind(INT, [6], 9, prefix=200))
    s.sub(x.pdu(NOTIFY, vbs, tid=2, pid=3))
    s.master(x.pdu(RESPONSE, struct.pack('>IHH', 100, 0, 0) + vbs, tid=2, pid=3))


def malformed_packets(cap):
    x = Enc(True)
    # Header only: the payload of the PDU is missing
    s = TcpStream(cap, 41001)
    s.sub(x.pdu(OPEN, b'')[:20])
    # An OID that claims more sub-identifiers than it has
    s.sub(x.pdu(GET, bytes([20, 0, 0, 0]) + x.u32(1)))
    # Varbind with a truncated octet string
    s.sub(x.pdu(NOTIFY, x.u16(OSTR) + b'\0\0' + x.oid([1, 2]) + x.u32(100) + b'abc'))
    # Close and Open too short
    s.sub(x.pdu(CLOSE, b'\x01'))
    s.sub(x.pdu(OPEN, b'\x01\0'))
    # Register with a context length past the PDU
    s.sub(x.pdu(REGISTER, x.u32(1000) + b'ab', flags=F_CONTEXT))
    # A PDU with payload length 0xffffff
    s.sub(struct.pack('>BBBBIIII', 1, GET, F_NBO, 0, 1, 1, 1, 0xffffff))
    # A payload length past the 2^24 limit of the PDU length handler
    s2 = TcpStream(cap, 41002)
    s2.sub(struct.pack('>BBBBIIII', 1, GET, F_NBO, 0, 1, 1, 1, 0x1000000))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    cap = Pcap()
    coverage_packets(cap)
    cap.write(os.path.join(out, 'agentx-coverage.pcap'))
    bad = Pcap()
    malformed_packets(bad)
    bad.write(os.path.join(out, 'agentx-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
