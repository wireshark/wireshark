# Helper module for the ieee1609dot2 capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
import zlib
def pcap(name, frames, linktype=1, t0=1700000000):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            if isinstance(fr, tuple):
                fr, olen = fr
            else:
                olen = len(fr)
            f.write(struct.pack('<IIII', t0 + i, 0, len(fr), olen))
            f.write(fr)
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff
def ip4(src, dst, proto, payload, ttl=64, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, ttl, proto, 0,
                    bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload
def udp(sp, dp, payload):
    return struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload
def mac(s): return bytes.fromhex(s.replace(':', ''))
def eth(dst, src, etype, payload):
    return mac(dst) + mac(src) + struct.pack('!H', etype) + payload

def pcapng(path, frames, ifaces=(1,), t0=1700000000):
    """frames: list of (interface index, bytes) (or (ifc, bytes, origlen));
    ifaces: link-layer types, one IDB each (1 Ethernet, 252 Exported PDU)."""
    def block(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        ln = 12 + len(body)
        return struct.pack('<II', btype, ln) + body + struct.pack('<I', ln)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in ifaces:
        opts = b''
        if isinstance(lt, tuple):      # (linktype, fcs length) -> if_fcslen option
            lt, fcs = lt
            opts = struct.pack('<HH', 13, 1) + bytes([fcs, 0, 0, 0]) + struct.pack('<HH', 0, 0)
        out += block(1, struct.pack('<HHI', lt, 0, 262144) + opts)
    for i, fr in enumerate(frames):
        ifc, data = fr[0], fr[1]
        olen = fr[2] if len(fr) > 2 else len(data)
        ts = (t0 * 1000000) + i * 10000
        out += block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(data), olen) + data)
    with open(path, 'wb') as f:
        f.write(out)

def exported_pdu(proto_name, payload, ifc=0):
    name = proto_name.encode()
    pad = (4 - len(name) % 4) % 4
    tags = struct.pack('!HH', 12, len(name) + pad) + name + b'\0' * pad
    tags += struct.pack('!HH', 0, 0)
    return (ifc, tags + payload)
