#!/usr/bin/env python3
# Generates test/captures/msgpack_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MsgPack coverage captures: mkmsgpack.py <outdir> [-v]
MsgPack has no port of its own; the frames are Exported PDU frames naming
the dissector "msgpack" (and "dxl", which calls it with field labels)."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from k11lib import exported_pdu, pcapng_write, udp

def arr(items): return (bytes([0x90 | len(items)]) if len(items) < 16 else b'\xdc' + struct.pack('!H', len(items))) + b''.join(items)
def mp(items): return (bytes([0x80 | len(items) // 2]) if len(items) < 32 else b'\xde' + struct.pack('!H', len(items) // 2)) + b''.join(items)
def fixstr(s): return bytes([0xa0 | len(s)]) + s
def e(p): return exported_pdu('msgpack', p)

def build():
    main, mal, notes = [], [], []
    def mark(t): notes.append((len(main) + 1, t))
    mark('scalars: nil, booleans, fixints, uint/int 8-64, float 32/64')
    for p in (b'\xc0', b'\xc2', b'\xc3', b'\x00', b'\x7f', b'\xe0', b'\xff',
              b'\xcc\xfe', b'\xcd\x12\x34', b'\xce\x12\x34\x56\x78', b'\xcf' + struct.pack('!Q', 2**64 - 1),
              b'\xd0\x80', b'\xd1\xff\x00', b'\xd2\x80\x00\x00\x00', b'\xd3' + struct.pack('!q', -2**63),
              b'\xca' + struct.pack('!f', 1.5), b'\xcb' + struct.pack('!d', -2.25)):
        main.append(e(p))
    mark('strings and binary: fixstr, str 8/16/32, bin 8/16/32 (empty and not)')
    for p in (b'\xa0', fixstr(b'hello'), b'\xd9\x03abc', b'\xd9\x00', b'\xda\x00\x04abcd', b'\xdb\x00\x00\x00\x03xyz',
              b'\xc4\x02\x01\x02', b'\xc5\x00\x03abc', b'\xc6\x00\x00\x00\x01Z', b'\xc4\x00'):
        main.append(e(p))
    mark('arrays and maps: fix, 16, 32; nested; nesting up to the limit of 32')
    main.append(e(arr([])))
    main.append(e(arr([b'\x01'])))
    main.append(e(arr([b'\x01', fixstr(b'two'), b'\xc3'])))
    main.append(e(b'\xdc\x00\x02\x01\x02'))
    main.append(e(b'\xdd\x00\x00\x00\x02\x01\x02'))
    main.append(e(mp([])))
    main.append(e(mp([fixstr(b'k'), b'\x01'])))
    main.append(e(mp([fixstr(b'a'), arr([b'\x01', b'\x02']), fixstr(b'b'), mp([fixstr(b'c'), b'\xc0'])])))
    main.append(e(b'\xde\x00\x01\xa1k\x05'))
    main.append(e(b'\xdf\x00\x00\x00\x01\xa1k\x05'))
    d = b'\x01'
    for _ in range(31):
        d = arr([d])
    main.append(e(d))                      # 31 levels of arrays: inside the limit
    d = b'\x01'
    for i in range(31):
        d = mp([fixstr(b'n'), d]) if i % 2 else arr([d])
    main.append(e(d))
    mark('extensions: fixext 1/2/4/8/16, ext 8/16/32')
    for p in (b'\xd4\x01A', b'\xd5\x02AB', b'\xd6\xff' + b'ABCD', b'\xd7\x05' + b'A' * 8, b'\xd8\x7f' + b'A' * 16,
              # ext 8/16/32 in the order the dissector reads them (type, then length; the
              # specification has the length first, see README)
              b'\xc7\x07\x03xyz', b'\xc8\x08\x00\x02ab', b'\xc9\x09\x00\x00\x00\x01Q', b'\xc7\x01\x00'):
        main.append(e(p))
    mal.append(e(b'\xc7\x03\x07xyz'))   # ext 8 as in the specification (length first)
    mark('unsupported type 0xc1 (warning), more bytes after the first object')
    main.append(e(b'\xc1'))
    main.append(e(b'\x01\x02\x03'))
    mark('DXL events (EPDU dxl): the eight MsgPack objects with field labels')
    ev = (b'\x00\x02' + fixstr(b'msgid') + fixstr(b'client') + fixstr(b'broker') + arr([fixstr(b'b1'), fixstr(b'b2')]) +
          arr([fixstr(b'c1')]) + mp([fixstr(b'k'), b'\xcc\x05', fixstr(b'l'), arr([b'\x01', b'\xe1'])]) + fixstr(b'/reply') + b'\xc0')
    main.append(exported_pdu('dxl', ev))
    main.append(exported_pdu('dxl', b'\x00\x02' + b'\xa1a' * 3 + b'\x90' + b'\x90' + b'\xc4\x02\x01\x02' + b'\xa0' + b'\xd9\x04abcd'))
    main.append(exported_pdu('dxl', b'\x00\x00'))     # DXL request: unsupported, error expert? (warn)
    # ---- malformed / reproducers
    mal.append(e(b'\xdd\xff\xff\xff\xff\xc1'))        # c1 loop reproducer: now ends at the end of the data
    mal.append(e(b'\xdd\xff\xff\xff\xff\xc1' * 2))
    mal.append(e(b'\x91' * 100))                      # past the nesting limit: warning
    mal.append(e(b'\x91' * 65000))                    # recursion reproducer
    mal.append(e(b'\x81' * 100))                      # nested maps
    for p in (b'\xcc', b'\xcd\x01', b'\xce\x01\x02', b'\xcf\x01', b'\xd3', b'\xca\x00', b'\xcb\x00\x00',
              b'\xa5ab', b'\xd9\x05ab', b'\xda\x00', b'\xdb\x00\x00\x01', b'\xdb\xff\xff\xff\xff' + b'x',
              b'\xc4\x05ab', b'\xc5\x00\x09a', b'\xc6\x00\x00\x00', b'\x93\x01', b'\xdc\x00\x05\x01',
              b'\x82\x01\x02', b'\xde\x00\x02\x01\x02', b'\xd4\x01', b'\xd8\x01ab', b'\xc7\x05\x01ab',
              b'\xc8\x00', b'\xc9\x00\x00\x00\xff\x01', b''):
        mal.append(e(p))
    mal.append(exported_pdu('dxl', b'\x00\x02' + b'\xa1a'))    # DXL event cut after the first object
    mal.append(exported_pdu('dxl', b''))
    # UDP, decoded with Decode As udp.port==4000,msgpack (runcov.sh)
    udp_frames = [udp(4000, 4000, b'\x92\x01\xa2hi'), udp(4000, 4000, b'\xdd\xff\xff\xff\xff\xc1'),
                  udp(4000, 4000, b'\x91' * 5000)]
    return main, mal, udp_frames, notes

if __name__ == '__main__':
    out = sys.argv[1]
    main, mal, udpf, notes = build()
    pcapng_write(os.path.join(out, 'msgpack-coverage.pcapng'), [(252, main)])
    pcapng_write(os.path.join(out, 'msgpack-coverage-malformed.pcapng'), [(252, mal), (1, udpf)])
    if '-v' in sys.argv:
        print('main', len(main), 'malformed', len(mal) + len(udpf))
        for n, t in notes: print(n, t)
