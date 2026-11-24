#!/usr/bin/env python3
# Generates test/captures/dmx_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic DMX coverage captures.

DMX has no port or link-layer type of its own; captures carry it as
Exported PDUs (LINKTYPE_WIRESHARK_UPPER_PDU, 252) naming the "dmx"
dissector, which is how Wireshark itself exports it.
Usage: mkdmx.py <outdir>
"""
import struct
import sys
import os

def exported_pdu(dissector, data):
    name = dissector.encode()
    pad = (4 - len(name) % 4) % 4
    tags = struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad + struct.pack('!HH', 0, 0)
    return tags + data

def write_pcap(path, frames, linktype=252):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def dmx(data):
    return exported_pdu('dmx', data)

def sip(byte_count, fields, reserved=b'', trailer=b'', bad=False):
    # fields: control, prev_cksum, seq, universe, proc_level, sw_ver,
    # packet_len, nr_packets, dev1..dev5
    body = struct.pack('!BBHBBBBHHHHHHH', byte_count, *fields) + reserved
    cks = (0xcf + sum(body)) & 0xff
    if bad:
        cks ^= 0x5a
    return b'\xcf' + body + bytes([cks]) + trailer

def main_frames():
    f = []
    # 1: 512 channel levels (full universe), every value 0-255 twice:
    #    percent display including "FL" for 255.
    f.append(dmx(b'\x00' + bytes(range(256)) * 2))
    # 2: 24 channels (not a multiple of some column counts).
    f.append(dmx(b'\x00' + bytes((i * 11) & 0xff for i in range(24))))
    # 3: 1 channel.
    f.append(dmx(b'\x00' + b'\xff'))
    # 4: no channel data at all.
    f.append(dmx(b'\x00'))
    # 5: text frame.
    f.append(dmx(b'\x17' + bytes([1, 20]) + b'Hello DMX text page'))
    # 6: text frame with page/line length only.
    f.append(dmx(b'\x17' + bytes([0, 0])))
    # 7: test frame, 512 x 0x55: data correct (the reproducer of the fix).
    f.append(dmx(b'\x55' + b'\x55' * 512))
    # 8: test frame, right size, one wrong value.
    f.append(dmx(b'\x55' + b'\x55' * 300 + b'\x00' + b'\x55' * 211))
    # 9: test frame, short.
    f.append(dmx(b'\x55' + b'\x55' * 16))
    # 10: SIP, byte_count = 22 (no reserved), good checksum.
    fields = (0x01, 0x1234, 7, 1, 2, 3, 513, 1, 0x0101, 0x0202, 0x0303, 0x0404, 0x0505)
    f.append(dmx(sip(22, fields)))
    # 11: SIP with 4 reserved octets and a trailer after the checksum.
    f.append(dmx(sip(26, fields, reserved=b'\xaa\xbb\xcc\xdd', trailer=b'\x01\x02\x03')))
    # 12: SIP with byte_count 0 (below the header length, no reserved).
    f.append(dmx(sip(0, (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))))
    # 13: unknown start code: data.
    f.append(dmx(b'\x91' + b'\xde\xad\xbe\xef'))
    # 14: the third frame of the reproducer: 513 slots.
    f.append(dmx(b'\x00' + bytes(range(256)) * 2 + b'\xff'))
    return f

def malformed_frames():
    f = []
    # 1: SIP with a bad checksum (error expert info).
    fields = (0x01, 0x1234, 7, 1, 2, 3, 513, 1, 1, 2, 3, 4, 5)
    f.append(dmx(sip(22, fields, bad=True)))
    # 2: SIP, byte count 0 and a short body (reproducer frame 2).
    f.append(dmx(b'\xcf' + bytes(23)))
    # 3: SIP header cut short.
    f.append(dmx(b'\xcf' + bytes(5)))
    # 4: text frame without line length.
    f.append(dmx(b'\x17\x01'))
    # 5: empty: no start code.
    f.append(dmx(b''))
    # 6: SIP with byte_count past the end.
    f.append(dmx(sip(200, fields)))
    return f

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'dmx-coverage.pcap'), main_frames())
    write_pcap(os.path.join(out, 'dmx-coverage-malformed.pcap'), malformed_frames())
