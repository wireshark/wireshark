# Helper module for the s1ap capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Minimal pcap writers for group s5 reproducers (synthetic addresses only).
import struct

def _hdr(linktype):
    return struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype)

def _rec(i, data):
    return struct.pack('<IIII', 1700000000 + i, 0, len(data), len(data)) + data

def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def udp_frame(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, s, d)
    ip = ip[:10] + struct.pack('!H', _csum(ip)) + ip[12:]
    eth = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
    return eth + ip + udp

def write_udp(path, payloads, sport, dport):
    with open(path, 'wb') as f:
        f.write(_hdr(1))
        for i, p in enumerate(payloads):
            f.write(_rec(i, udp_frame(p, sport, dport)))

def exported_pdu(dissector, payload):
    name = dissector.encode()
    tag = struct.pack('!HH', 12, len(name)) + name
    return tag + struct.pack('!HH', 0, 0) + payload

def write_exported(path, dissector, payloads):
    with open(path, 'wb') as f:
        f.write(_hdr(252))
        for i, p in enumerate(payloads):
            f.write(_rec(i, exported_pdu(dissector, p)))

def per_len(n):
    """Aligned PER unconstrained length determinant (< 16K)."""
    if n < 128:
        return bytes([n])
    return struct.pack('!H', 0x8000 | n)

def ie(ie_id, value, crit=1):
    """ProtocolIE-Field: id (0..65535), criticality, open-type value."""
    return struct.pack('!H', ie_id) + bytes([crit << 6]) + per_len(len(value)) + value

def initiating(proc, msg_value, crit=1):
    """xxAP-PDU initiatingMessage (CHOICE idx 0), procedureCode 0..255."""
    return b'\x00' + bytes([proc]) + bytes([crit << 6]) + per_len(len(msg_value)) + msg_value

def container(ies, prefix=b'\x00'):
    """SEQUENCE {ext bit [, opt bits], ProtocolIE-Container (0..65535)}."""
    return prefix + struct.pack('!H', len(ies)) + b''.join(ies)
