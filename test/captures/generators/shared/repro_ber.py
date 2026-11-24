# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Shared helpers for the g2 H.248 reproducers (synthetic data only).
import struct

def L(n):
    if n < 0x80: return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b

def tlv(tag, *parts):
    c = b''.join(parts)
    return bytes([tag]) + L(len(c)) + c

def prop(pkgd, *values):
    """PropertyParm: name [0] PkgdName, value [1] SEQUENCE OF OCTET STRING"""
    return tlv(0x30, tlv(0x80, pkgd), tlv(0xA1, *[tlv(0x04, v) for v in values]))

def media_desc(*props):
    # mediaDescriptor [0] { termStateDescr [0] { propertyParms [0] {...} } }
    return tlv(0xA0, tlv(0xA0, tlv(0xA0, *props)))

def signal(signame, *sigpars):
    # SignalRequest signal [0] { signalName [0], sigParList [6] }
    return tlv(0xA0, tlv(0x80, signame), tlv(0xA6, *sigpars))

def sigpar(name_tlv, *values):
    return tlv(0x30, name_tlv, tlv(0xA1, *[tlv(0x04, v) for v in values]))

def term_id(tid=b'\x01\x02', wild=b''):
    return tlv(0x30, tlv(0xA0, wild), tlv(0x81, tid))

def add_req(descs, terms=None, cmdtag=0xA0):
    if terms is None: terms = [term_id()]
    amm = tlv(cmdtag, tlv(0xA0, *terms), tlv(0xA1, *descs))
    return tlv(0x30, tlv(0xA0, amm))       # CommandRequest { command [0] { addReq } }

def action_req(ctx, cmds):
    return tlv(0x30, tlv(0x80, ctx.to_bytes(4, 'big')), tlv(0xA3, *cmds))

def trans_req(trx, actions):
    return tlv(0xA0, tlv(0x80, trx.to_bytes(4, 'big')), tlv(0xA1, *actions))

def megaco(transactions, version=2):
    msg = tlv(0x80, bytes([version])) + tlv(0xA1, tlv(0x83, b'mg')) + \
          tlv(0xA2, tlv(0xA1, *transactions))
    return tlv(0x30, tlv(0xA1, msg))

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def udp_frame(payload, sport=2945, dport=2945, src='192.0.2.1', dst='192.0.2.2'):
    import socket
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    eth = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
    return eth + ip + udp

def write_pcap(name, payloads):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(payloads):
            fr = udp_frame(p)
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)
