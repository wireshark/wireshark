#!/usr/bin/env python3
# Generates test/captures/m2ua_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic M2UA coverage captures.

Usage: mkm2ua.py <outdir>

M2UA (RFC 3331) over SCTP port 2904 and PPID 2: every message class and
type, every parameter (also the nested Link Key, Registration Result and
Deregistration Result parameters), Protocol Data 1 and 2 carrying MTP3
messages, and the draft-7 Protocol Data 1 tag (0x000e, decoded as such
with -o m2ua.protocol_data_1_tag:draft-7). Includes the reproducer of the
nesting depth check (a deeply nested Link Key parameter). Nothing comes
from a real network.
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from sslib import Sctp, write_pcap, mtp3_sltm, mtp3_coo  # noqa: E402

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
PORT, PPID = 2904, 2


def param(tag, value=b''):
    p = struct.pack('!HH', tag, 4 + len(value)) + value
    return p + b'\0' * ((-len(p)) % 4)


def msg(cls, typ, params=b'', ver=1):
    return struct.pack('!BBBBI', ver, 0, cls, typ, 8 + len(params)) + params


def u32(v):
    return struct.pack('!I', v)


def iid(v=1):
    return param(0x0001, u32(v))


def main():
    s = Sctp(PORT, PPID, cport=2904)
    frames, ranges = [], []

    def add(payload, rev=False):
        frames.append(s.frame(payload, rev))

    def mark(name, start):
        ranges.append((name, start + 1, len(frames)))

    # ---- MGMT: ERR with every error code, NTFY with every status
    st = len(frames)
    for i, code in enumerate(list(range(1, 18)) + [99]):
        add(msg(0, 0, param(0x000c, u32(code)) + iid(i) + param(0x0007, b'\xde\xad\xbe\xef\x01')), i % 2 == 1)
    add(msg(0, 0, param(0x000c, u32(7)) + param(0x0007, b'')), True)
    for typ, info in [(1, 1), (1, 2), (1, 3), (1, 4), (1, 9), (2, 1), (2, 2), (2, 3), (2, 7), (7, 1)]:
        add(msg(0, 1, param(0x000d, struct.pack('!HH', typ, info)) + param(0x0011, u32(5)) + param(0x0004, b'status')))
    add(msg(0, 7))
    mark('ERR and NTFY', st)

    # ---- ASPSM
    st = len(frames)
    add(msg(3, 1, param(0x0011, u32(1)) + param(0x0004, b'M2UA ASP up')))
    add(msg(3, 4, param(0x0011, u32(1))), True)
    add(msg(3, 2, param(0x0004, b'going down')))
    add(msg(3, 5), True)
    add(msg(3, 3, param(0x0009, b'beat-0123456789')))
    add(msg(3, 6, param(0x0009, b'beat-0123456789')), True)
    add(msg(3, 3, param(0x0009, b'')))
    add(msg(3, 9))
    mark('ASPSM: UP, DOWN, BEAT and acks', st)

    # ---- ASPTM, interface identifier forms
    st = len(frames)
    for mode in (1, 2, 3, 99):
        add(msg(4, 1, param(0x000b, u32(mode)) + iid(mode)))
    add(msg(4, 3, param(0x000b, u32(1)) + iid(1)), True)
    add(msg(4, 3, param(0x000b, u32(2)) + param(0x0008, struct.pack('!IIII', 1, 10, 20, 30)), ), True)
    add(msg(4, 2, param(0x0003, b'iface-1') + param(0x0004, b'text id')))
    add(msg(4, 4, param(0x0003, b'a')), True)
    add(msg(4, 2, param(0x0008, b'')))
    add(msg(4, 9))
    mark('ASPTM with traffic modes and interface identifier forms (int, text, range)', st)

    # ---- MAUP, data
    st = len(frames)
    for i in range(3):
        add(msg(6, 1, iid(i + 1) + param(0x0300, mtp3_sltm(2, 1, i, b'DATA%d' % i))), i % 2 == 1)
    add(msg(6, 1, iid(1) + param(0x0301, b'\x0a' + mtp3_coo(2, 1, 1, 77)) ))
    add(msg(6, 1, iid(1) + param(0x0301, b'\x0a' + mtp3_sltm(1, 2, 3, b'LI2')) + param(0x0013, u32(77))), True)
    add(msg(6, 15, iid(1) + param(0x0013, u32(77))))                  # DATA_ACK
    mark('MAUP DATA: protocol data 1 and 2, correlation id, DATA_ACK', st)

    st = len(frames)
    for typ in (2, 3, 4, 5, 6):                                        # ESTAB_REQ ... REL_IND
        add(msg(6, typ, iid(typ)), typ % 2 == 1)
    for i, state in enumerate(range(0, 11)):                           # STATE_REQ, every state
        add(msg(6, 7, iid(1) + param(0x0302, u32(state))))
    for i, state in enumerate([0, 1]):
        add(msg(6, 8, iid(1) + param(0x0302, u32(state))), True)
    for ev in (1, 2, 3, 4, 9):
        add(msg(6, 9, iid(1) + param(0x0303, u32(ev))), True)          # STATE_IND
    for lvl in (0, 1, 2, 3, 9):
        add(msg(6, 14, iid(1) + param(0x0304, u32(lvl)) + param(0x0305, u32(3 - lvl % 4))), True)   # CONG_IND
    for act in (1, 2, 3):
        add(msg(6, 10, iid(1) + param(0x0306, u32(act)) + param(0x0307, u32(1234))))               # DATA_RETR_REQ
    for res in (0, 1, 2):
        add(msg(6, 11, iid(1) + param(0x0306, u32(1)) + param(0x0308, u32(res)) + param(0x0307, u32(55))), True)
    add(msg(6, 12, iid(1) + param(0x0300, mtp3_sltm())), True)
    add(msg(6, 13, iid(1)), True)
    add(msg(6, 77, iid(1)))                                            # unknown MAUP type
    mark('MAUP: establish, release, state, congestion, data retrieval', st)

    # ---- IIM: registration with link keys
    st = len(frames)
    lk = param(0x030a, u32(11)) + param(0x030b, struct.pack('!HH', 0, 7)) + param(0x030c, struct.pack('!HH', 0, 9))
    add(msg(10, 1, param(0x0309, lk)))
    add(msg(10, 1, param(0x0309, lk) + param(0x0309, lk + param(0x0004, b'second key'))))
    res = param(0x030e, u32(0)) + iid(5) + param(0x030a, u32(11))
    for status in range(0, 9):
        res = param(0x030e, u32(status)) + iid(5) + param(0x030a, u32(11))
        add(msg(10, 2, param(0x030d, res)), True)
    add(msg(10, 2, param(0x030d, res) + param(0x030d, res)), True)
    add(msg(10, 3, iid(5) + iid(6)))
    for status in range(0, 6):
        dres = iid(5) + param(0x0310, u32(status))
        add(msg(10, 4, param(0x030f, dres)), True)
    add(msg(10, 1, param(0x7777, b'\x01\x02\x03') + param(0x7778, b'')))      # unknown parameters
    add(msg(10, 9))
    mark('IIM: registration/deregistration with link keys and results', st)

    # ---- nested parameters, draft 7 tag, unknown class
    st = len(frames)
    nest = param(0x0001, u32(7))
    for _ in range(20):
        nest = param(0x0309, nest)
    add(msg(10, 1, nest))
    add(msg(99, 1, iid(1)))                                                       # unknown class
    add(msg(6, 1, iid(1) + param(0x000e, mtp3_sltm(2, 1, 1, b'DR07'))))           # draft 7 data tag
    mark('nested link keys (20 levels), unknown class, draft-7 protocol data tag (frame %d)' % len(frames), st)
    draft7 = len(frames)

    # ---- reproducer of the nesting depth check (~3000 levels); the nested
    # parameter ends up at depth 500 in the tree, the generic depth guard
    # stops the rest. This one raises an exception in the dissector (the
    # generic dissection-depth limit), so it is in the malformed capture only.
    write_pcap(os.path.join(OUT, 'm2ua-coverage.pcap'), frames)

    # ---- malformed capture
    mal = []
    s2 = Sctp(PORT, PPID, cport=2904)
    p = struct.pack('!HHI', 0x0001, 8, 7)
    for _ in range(3000):
        p = struct.pack('!HH', 0x0309, 4 + len(p)) + p
        if len(p) > 65000:
            break
    mal.append(s2.frame(msg(10, 1, p)))
    good = msg(6, 1, iid(1) + param(0x0300, mtp3_sltm()))
    for n in (3, 8, 10, 14, 20, len(good) - 3):
        mal.append(s2.frame(good[:n]))
    mal.append(s2.frame(msg(0, 0, struct.pack('!HH', 0x000c, 2))))
    mal.append(s2.frame(msg(0, 0, struct.pack('!HH', 0x000c, 200) + b'\0' * 4)))
    mal.append(s2.frame(msg(0, 1, struct.pack('!HHH', 0x000d, 6, 1))))
    mal.append(s2.frame(msg(6, 1, struct.pack('!HHB', 0x0301, 5, 0x0a))))
    mal.append(s2.frame(msg(6, 1, struct.pack('!HH', 0x0301, 4))))
    mal.append(s2.frame(msg(4, 1, struct.pack('!HH', 0x0008, 12) + b'\0' * 8)))
    mal.append(s2.frame(msg(0, 0, struct.pack('!HH', 0x0004, 3))))
    mal.append(s2.frame(msg(6, 1, iid(1) + param(0x0300, b''))))      # empty protocol data
    write_pcap(os.path.join(OUT, 'm2ua-coverage-malformed.pcap'), mal)
    for r in ranges:
        print(r)
    print(len(frames), len(mal), 'draft7 frame', draft7)


if __name__ == '__main__':
    main()
