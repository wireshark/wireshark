#!/usr/bin/env python3
# Generates test/captures/netmon_coverage.cap
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic NetMon 2.1 capture file with NetMon 802.11 capture headers.
# Usage: mknetmon.py <outdir> [-v]
# Writes netmon-coverage.cap and netmon-coverage-malformed.cap; struct only.
# The "NetMon 802.11" dissector is reached by the per-packet network type 6
# of a NetMon 2.x file (WTAP_ENCAP_IEEE_802_11_NETMON), no Decode As needed.
import struct
import sys
import os

MAGIC = b'GMBU'
A1 = bytes.fromhex('020000000001')
A2 = bytes.fromhex('020000000002')
A3 = bytes.fromhex('020000000003')
def null_data(seq=1, to_ds=True):
    return bytes([0x48, 0x01 if to_ds else 0x02, 0, 0]) + A1 + A2 + A3 + struct.pack('<H', seq << 4)
def ack():
    return bytes.fromhex('d4000000') + A1

def netmon_file(name, frames, network=6, minor=1):
    '''frames: list of packet bytes (each gets a 2.1 trailer with network)'''
    recs = []
    off = 128
    offsets = []
    body = b''
    for i, fr in enumerate(frames):
        net = network
        if isinstance(fr, tuple):
            fr, net = fr
        offsets.append(off + len(body))
        body += struct.pack('<QII', i * 1000, len(fr), len(fr)) + fr + struct.pack('<H', net)
    ft_off = 128 + len(body)
    table = b''.join(struct.pack('<I', o) for o in offsets)
    hdr = MAGIC + struct.pack('<BBH8H10I', minor, 2, 1, 2026, 11, 5, 6, 12, 0, 0, 0,
                              ft_off, len(table), 0, 0, 0, 0, 0, 0, 0, 0)
    hdr = hdr.ljust(128, b'\0')
    with open(name, 'wb') as f:
        f.write(hdr + body + table)

OP_STA, OP_AP, OP_STA_EXT, OP_MON = 1, 2, 4, 0x80000000
def nm(op=OP_STA_EXT, flags=0, phy=6, chan=6, rssi=-45, rate=108, ts=0x1122334455667788,
       version=2, length=32, extra=b'', body=None):
    h = struct.pack('<BHII', version, length, op & 0xffffffff, flags)
    h += struct.pack('<IIiB', phy, chan, rssi, rate)
    h += struct.pack('<Q', ts)
    assert len(h) == 32
    h += extra
    return h + (null_data() if body is None else body)

def build(outdir, verbose=False):
    fr = []; notes = []
    def add(label, f):
        fr.append(f); notes.append(label)
    # operation modes: station, AP, extensible station, monitor and none
    for label, op in (('STA', OP_STA), ('AP', OP_AP), ('STA_EXT', OP_STA_EXT),
                      ('MON', OP_MON), ('MON|STA_EXT', OP_MON | OP_STA_EXT),
                      ('all', OP_STA | OP_AP | OP_STA_EXT | OP_MON), ('none', 0)):
        add('op mode ' + label, nm(op=op))
    # PHY types 0-8 and an unknown one, with a channel number 6 (2.4 GHz for
    # 11b/11g) or 36 (5 GHz for 11a)
    for phy in range(0, 10):
        add('phy %d chan 6' % phy, nm(phy=phy, chan=6, rate=2 if phy in (2, 5) else 108))
    add('11a chan 36', nm(phy=4, chan=36, rate=108))
    add('11b chan 11', nm(phy=5, chan=11, rate=22))
    add('11g chan 1', nm(phy=6, chan=1, rate=12))
    add('11n chan 6 (no frequency)', nm(phy=7, chan=6, rate=130))
    add('11ac chan 36 (no frequency)', nm(phy=8, chan=36, rate=130))
    # channel field: 0 unknown, < 1000 channel, >= 1000 centre frequency
    add('chan 0', nm(chan=0))
    add('freq 2437 MHz', nm(phy=6, chan=2437))
    add('freq 5180 MHz', nm(phy=4, chan=5180))
    add('freq 1000 MHz (no channel)', nm(phy=6, chan=1000))
    add('freq 4000000 (no channel)', nm(phy=6, chan=4000000))
    add('chan 999', nm(phy=6, chan=999))
    # RSSI and data rate: 0 means unknown
    add('rssi 0', nm(rssi=0))
    add('rssi -100', nm(rssi=-100))
    add('rssi positive', nm(rssi=20))
    add('rate 0', nm(rate=0))
    add('rate 1 (0.5 Mb/s)', nm(rate=1))
    add('rate 11 (5.5 Mb/s)', nm(rate=11))
    add('rate 255', nm(rate=255))
    # receive flags 0xffffffff: no PHY information, 13 bytes skipped
    add('flags 0xffffffff', nm(flags=0xffffffff))
    add('flags 1', nm(flags=1))
    # timestamp extremes
    add('timestamp 0', nm(ts=0))
    add('timestamp max', nm(ts=0xffffffffffffffff))
    # header longer than the fixed part; versions other than 2 and
    # lengths below the minimum are skipped
    add('length 40', nm(length=40, extra=b'\xaa' * 8))
    add('length 64', nm(length=64, extra=b'\xbb' * 32))
    add('version 1 (skipped)', nm(version=1))
    add('version 3 (skipped)', nm(version=3, length=32))
    add('version 0 length 36', nm(version=0, length=36, extra=b'\0' * 4))
    add('version 2 length 31 (skipped)', nm(length=31, body=b'')[:31] + null_data())
    # other 802.11 frames behind the header
    add('ack', nm(body=ack()))
    add('null from DS', nm(body=null_data(5, False)))
    add('mon: ack', nm(op=OP_MON, body=ack()))
    add('mon: null from DS', nm(op=OP_MON, body=null_data(6, False)))
    netmon_file(os.path.join(outdir, 'netmon-coverage.cap'), fr)

    mal = []
    mal.append(nm()[:20])                         # truncated header
    mal.append(nm(body=b''))                       # header only
    mal.append(nm(body=b'\x48\x01\x00'))           # truncated 802.11
    mal.append(nm(length=200))                     # length beyond the packet
    mal.append(nm(op=OP_MON, length=33)[:33])      # header, 1 byte
    mal.append(b'\x02')                            # one byte
    mal.append(nm(version=7, length=0))            # skipped, whole packet
    netmon_file(os.path.join(outdir, 'netmon-coverage-malformed.cap'), mal)
    if verbose:
        for i, n in enumerate(notes, 1):
            print(i, n)
        print('main frames:', len(fr), 'malformed frames:', len(mal))

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    build(out, '-v' in sys.argv)
