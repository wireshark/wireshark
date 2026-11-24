#!/usr/bin/env python3
# Generates test/captures/smp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the SMP (Session Multiplex Protocol,
"MARS" of Microsoft SQL Server) dissector (packet-smp.c).

Usage: mksmp.py <output directory>

SMP has no port of its own. By default it is reached through TDS: on TCP
1433 the TDS dissector hands PDUs whose first octet is 0x53 ('S') to the
"smp_tds" dissector. The second connection (TCP 5100) is only dissected
with Decode As (tcp.port 5100 -> smp), which also reaches the
"smp.payload" table. Every packet is built with struct.

Writes:
  smp-coverage.pcap            both connections (frames 1-N: TDS route,
                               then port 5100)
  smp-coverage-malformed.pcap  SMP PDUs with a short length field, a
                               header cut short and data past the PDU
"""
import os
import struct
import sys
from pcaplib import pcap, TcpConn

SYN, ACK, FIN, DATA = 1, 2, 4, 8


def smp(flags, sid, seq, wndw, data=b'', length=None, smid=0x53):
    ln = 16 + len(data) if length is None else length
    return struct.pack('<BBHIII', smid, flags, sid, ln, seq, wndw) + data


def tds(ptype, body, status=1, spid=0, pid=1):
    return struct.pack('>BBHHBB', ptype, status, 8 + len(body), spid, pid, 0) + body


def prelogin():
    # VERSION token and terminator, 6 octets of version
    return tds(0x12, bytes.fromhex('00 0006 0006 ff') + bytes.fromhex('0f 00 07 d0 00 00'))


def prelogin_resp():
    return tds(4, bytes.fromhex('00 0006 0006 ff') + bytes.fromhex('10 00 00 00 00 00'))


def batch(sql):
    u = sql.encode('utf-16-le')
    return tds(1, struct.pack('<IIIH', 22, 18, 2, 0) [:0] + struct.pack('<IIHQ', 22, 18, 2, 0)[:18] + u)


def main(out):
    c = TcpConn(50000, 1433)
    c.handshake()
    c.send(prelogin())
    c.send(prelogin_resp(), client=False)
    # SMP session 0: SYN, SYN+ACK back
    c.send(smp(SYN, 0, 0, 4))
    c.send(smp(SYN | ACK, 0, 0, 4), client=False)
    # data with a TDS payload, both directions
    c.send(smp(DATA, 0, 1, 4, prelogin()))
    c.send(smp(DATA, 0, 1, 4, prelogin_resp()), client=False)
    c.send(smp(ACK, 0, 2, 5))
    # a second session, plain ACK, and a DATA PDU with no data (length 16)
    c.send(smp(SYN, 1, 0, 4))
    c.send(smp(DATA, 1, 1, 4))
    # two SMP PDUs in one segment
    c.send(smp(DATA, 0, 2, 5, prelogin()) + smp(ACK, 0, 3, 5))
    # one PDU spanning two segments (reassembled)
    pdu = smp(DATA, 1, 2, 5, prelogin())
    c.send(pdu[:20])
    c.send(pdu[20:])
    # a PDU whose header is split after 3 octets
    pdu = smp(DATA, 0, 4, 5, prelogin())
    c.send(pdu[:3])
    c.send(pdu[3:])
    c.send(smp(FIN, 1, 3, 5))
    c.send(smp(FIN | ACK, 0, 5, 5), client=False)
    c.send(smp(SYN | ACK | FIN | DATA, 7, 0xffffffff, 0xffffffff))   # all flags, no data
    n1 = len(c.frames)

    # second connection: Decode As tcp.port 5100 -> smp, payload not decoded
    d = TcpConn(50001, 5100, isn_c=70000, isn_s=90000)
    d.handshake()
    d.send(smp(SYN, 0, 0, 4))
    d.send(smp(DATA, 0, 1, 4, b'\x01\x02\x03\x04\x05\x06\x07\x08'))
    d.send(smp(DATA, 0, 2, 4, prelogin()))                                       # TDS only with Decode As smp.payload
    d.send(smp(ACK, 0, 4, 4), client=False)
    d.send(b'\x54' + b'\0' * 20)                                                 # not SMP (first octet)
    frames = c.frames + d.frames
    pcap(os.path.join(out, 'smp-coverage.pcap'), frames)
    print('frames 1-%d TDS route (port 1433), %d-%d port 5100 (Decode As)' %
          (n1, n1 + 1, len(frames)))

    # malformed: one connection per case, because a PDU that claims more
    # data than it has absorbs the rest of the stream
    mf = []
    cases = [smp(DATA, 0, 1, 4, b'abcd', length=4),                  # length < 16
             smp(DATA, 0, 1, 4, b'abcd', length=0),
             smp(DATA, 0, 1, 4, b'abcdefgh', length=0xffffff00),     # huge length
             smp(DATA, 0, 2, 4, b'select', length=16 + 6 + 100),     # fragmented (length > data)
             smp(DATA, 0, 3, 4, b'\xaa' * 20, length=16 + 12),       # length < data
             smp(SYN, 0, 1, 4)[:12]]                                 # header cut short
    for i, pdu in enumerate(cases):
        m = TcpConn(50010 + i, 5100, isn_c=1, isn_s=1)
        m.handshake()
        m.send(pdu)
        mf += m.frames
    pcap(os.path.join(out, 'smp-coverage-malformed.pcap'), mf)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
