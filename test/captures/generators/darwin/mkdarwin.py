#!/usr/bin/env python3
# Generates test/captures/darwin_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Darwin dissector
(packet-darwin.c, Apple Darwin pcapng packet metadata).

The Darwin metadata is not part of the packet: it comes from options of
the pcapng Enhanced Packet Block (EPB) and from legacy Darwin Process
Info Blocks (DPIB, block type 0x80000001). The EPB options (codes
32769-32778, values little-endian whatever the section byte order) are
handed by the frame dissector to packet-darwin.c through the
"pcapng_packet_block_option" table; the frame dissector then calls the
"darwin" dissector, which adds the process information (the process ID
and name from the DPIB the EPB refers to, and the effective process)
and the Darwin metadata (flags, service class, flow ID, trace tag, drop
reason, line and function, compression generation count) to the frame
tree.

Every block is built from scratch with struct; no captured traffic is
used. The packets are small UDP datagrams between documentation
addresses.

Usage: mkdarwin.py <output directory>

Writes:
  darwin-coverage.pcapng            five DPIBs (with and without a name,
                                    two with the same process ID) and
                                    EPBs with every Darwin option alone
                                    and in combination, every flag,
                                    service classes, drop reasons of
                                    every component and domain kind
  darwin-coverage-malformed.pcapng  an EPB referring to a DPIB that does
                                    not exist
"""

import os
import struct
import sys

OPT_PIB_ID = 32769
OPT_SVC_CODE = 32770
OPT_EPIB_ID = 32771
OPT_MD_FLAGS = 32772
OPT_FLOW_ID = 32773
OPT_TRACE_TAG = 32774
OPT_DROP_REASON = 32775
OPT_DROP_LINE = 32776
OPT_DROP_FUNC = 32777
OPT_COMP_GENCNT = 32778


def pad4(b):
    return b + b'\x00' * (-len(b) % 4)


def opt(code, value):
    return struct.pack('<HH', code, len(value)) + pad4(value)


def opts(*o):
    if not o:
        return b''
    return b''.join(o) + struct.pack('<HH', 0, 0)


def u32(code, v):
    return opt(code, struct.pack('<I', v))


def u16(code, v):
    return opt(code, struct.pack('<H', v))


def block(btype, body):
    body = pad4(body)
    n = len(body) + 12
    return struct.pack('<II', btype, n) + body + struct.pack('<I', n)


def shb():
    return block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
                 + opts(opt(4, b'mkdarwin.py (synthetic)')))


def idb():
    return block(1, struct.pack('<HHI', 1, 0, 262144))


def dpib(pid, name=None, uuid=None):
    o = []
    if name is not None:
        o.append(opt(2, name.encode()))
    if uuid is not None:
        o.append(opt(4, uuid))
    return block(0x80000001, struct.pack('<I', pid) + opts(*o))


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def udp_frame(n):
    payload = b'darwin %d' % n
    src, dst = bytes([192, 0, 2, 1]), bytes([198, 51, 100, 1])
    udp = struct.pack('!HHHH', 50000 + n, 40000, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), n, 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + udp


class Writer:
    def __init__(self):
        self.out = shb() + idb()
        self.n = 0

    def add(self, b):
        self.out += b

    def epb(self, *o):
        self.n += 1
        data = udp_frame(self.n)
        ts = (1793491200 + self.n) * 1000000
        self.out += block(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff, len(data), len(data))
                          + pad4(data) + opts(*o))


def reason(component, domain, code):
    return (component << 24) | (domain << 16) | code


def main_capture():
    w = Writer()
    # DPIB 0-4: named, named, no name, named with a UUID, and one with
    # the same process ID as DPIB 1
    w.add(dpib(100, 'Safari'))
    w.add(dpib(200, 'nsurlsessiond'))
    w.add(dpib(300))
    w.add(dpib(400, 'mDNSResponder', bytes(range(16))))
    w.add(dpib(200, 'nsurlsessiond'))

    # 1: no Darwin options at all
    w.epb()
    # process information
    w.epb(u32(OPT_PIB_ID, 0))                                    # 2: proc only
    w.epb(u32(OPT_PIB_ID, 0), u32(OPT_EPIB_ID, 0))              # 3: effective == proc
    w.epb(u32(OPT_PIB_ID, 0), u32(OPT_EPIB_ID, 1))              # 4: named effective
    w.epb(u32(OPT_PIB_ID, 2))                                    # 5: proc without name
    w.epb(u32(OPT_PIB_ID, 2), u32(OPT_EPIB_ID, 3))              # 6: unnamed proc, named eproc
    w.epb(u32(OPT_PIB_ID, 0), u32(OPT_EPIB_ID, 2))              # 7: unnamed effective
    w.epb(u32(OPT_PIB_ID, 1), u32(OPT_EPIB_ID, 4))              # 8: other DPIB, same pid
    w.epb(u32(OPT_EPIB_ID, 3))                                   # 9: effective only
    # metadata, each item alone (so each is the first item)
    w.epb(u32(OPT_MD_FLAGS, 0x8000003f))                         # 10: every flag + reserved
    w.epb(u32(OPT_MD_FLAGS, 0))                                  # 11: no flag
    w.epb(u32(OPT_MD_FLAGS, 0x15))                               # 12: CRN... mix
    w.epb(u32(OPT_SVC_CODE, 0x0000))                             # 13: BE
    w.epb(u32(OPT_SVC_CODE, 0x0320))                             # 14: VO
    w.epb(u32(OPT_SVC_CODE, 0x0123))                             # 15: unknown class
    w.epb(u32(OPT_FLOW_ID, 0xdeadbeef))                          # 16
    w.epb(u16(OPT_TRACE_TAG, 0xabcd))                            # 17
    w.epb(u32(OPT_COMP_GENCNT, 7))                               # 18
    # drops
    w.epb(opt(OPT_DROP_FUNC, b'fsw_rx_ring_enqueue'),            # 19: func:line reason, Skywalk fsw
          u16(OPT_DROP_LINE, 1234), u32(OPT_DROP_REASON, reason(1, 1, 2)))
    w.epb(u16(OPT_DROP_LINE, 77))                                # 20: line only
    w.epb(opt(OPT_DROP_FUNC, b'tcp_input'))                      # 21: func only
    w.epb(u32(OPT_DROP_REASON, reason(2, 1, 1)))                 # 22: BSD TCP
    w.epb(u32(OPT_DROP_REASON, reason(2, 10, 1)))                # 23: BSD bridge
    w.epb(u32(OPT_DROP_REASON, reason(1, 5, 1)))                 # 24: Skywalk AQM
    w.epb(u32(OPT_DROP_REASON, reason(1, 2, 0x3333)))            # 25: Skywalk netif, unknown code
    w.epb(u32(OPT_DROP_REASON, reason(2, 0x55, 1)))              # 26: BSD, unknown domain
    w.epb(u32(OPT_DROP_REASON, 0))                               # 27: unspecified (component 0)
    w.epb(u32(OPT_DROP_REASON, reason(3, 1, 1)))                 # 28: unknown component
    # everything at once, then pairs that put each item after another
    w.epb(u32(OPT_PIB_ID, 0), u32(OPT_EPIB_ID, 1),               # 29
          u32(OPT_MD_FLAGS, 0x22), u32(OPT_SVC_CODE, 0x0384), u32(OPT_FLOW_ID, 0x1234),
          u16(OPT_TRACE_TAG, 0x42), opt(OPT_DROP_FUNC, b'ip_output'),
          u16(OPT_DROP_LINE, 99), u32(OPT_DROP_REASON, reason(2, 3, 1)),
          u32(OPT_COMP_GENCNT, 3))
    w.epb(u32(OPT_SVC_CODE, 0x00C8), u16(OPT_TRACE_TAG, 1))      # 30: svc; trace
    w.epb(u32(OPT_FLOW_ID, 5), u32(OPT_DROP_REASON, reason(2, 7, 1)))   # 31: flow; drop
    w.epb(u16(OPT_TRACE_TAG, 2), u32(OPT_COMP_GENCNT, 9))        # 32: trace; gencnt
    w.epb(u32(OPT_PIB_ID, 3), u32(OPT_SVC_CODE, 0x0190), u32(OPT_FLOW_ID, 6))  # 33: proc + svc; flow
    return w.out


def malformed_capture():
    w = Writer()
    w.add(dpib(100, 'Safari'))
    # 1: an EPB referring to DPIB 9, which does not exist (process ID
    # -1, no name; tshark logs a warning)
    w.epb(u32(OPT_PIB_ID, 9), u32(OPT_EPIB_ID, 8))
    return w.out


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    with open(os.path.join(out, 'darwin-coverage.pcapng'), 'wb') as f:
        f.write(main_capture())
    with open(os.path.join(out, 'darwin-coverage-malformed.pcapng'), 'wb') as f:
        f.write(malformed_capture())


if __name__ == '__main__':
    main()
