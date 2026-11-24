# Helper module for the awdl capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
def pcap(fn, frames, linktype=105):
    with open(fn,'wb') as f:
        f.write(struct.pack('<IHHiIII',0xa1b2c3d4,2,4,0,0,65535,linktype))
        for i,fr in enumerate(frames):
            f.write(struct.pack('<IIII',i,0,len(fr),len(fr))+fr)
def action(tlvs):
    hdr = bytes([0xd0,0,0,0])+bytes.fromhex('ffffffffffff')+bytes.fromhex('020000000001')+bytes.fromhex('020000000002')+b'\x00\x00'
    awdl = bytes([0x7f,0x00,0x17,0xf2, 8,0x10,0,0])+struct.pack('<II',100,50)
    return hdr+awdl+tlvs
def tlv(t,v):
    return struct.pack('<BH',t,len(v))+v
