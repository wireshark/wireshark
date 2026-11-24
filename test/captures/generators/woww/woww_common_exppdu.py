# Helper module for the woww capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Shared helper: write an Exported PDU (linktype 252) pcap naming the "woww" dissector.
import struct

def tlv(tag, val):
    return struct.pack('>HH', tag, len(val)) + val

def exppdu(payload, sport, dport):
    hdr = tlv(12, b'woww')
    hdr += tlv(20, bytes([192, 0, 2, 1])) + tlv(21, bytes([192, 0, 2, 2]))
    hdr += tlv(24, struct.pack('>I', 2))  # EXP_PDU_PT_TCP
    hdr += tlv(25, struct.pack('>I', sport)) + tlv(26, struct.pack('>I', dport))
    hdr += struct.pack('>HH', 0, 0)
    return hdr + payload

def write_pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 0x7fffffff, 252))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', i + 1, 0, len(fr), len(fr)))
            f.write(fr)

def server_msg(opcode, body):
    # server->client: 2-byte BE size (excluding itself), 2-byte LE opcode
    return struct.pack('>H', len(body) + 2) + struct.pack('<H', opcode) + body

def client_msg(opcode, body):
    # client->server: 2-byte BE size, 4-byte LE opcode
    return struct.pack('>H', len(body) + 4) + struct.pack('<I', opcode) + body
