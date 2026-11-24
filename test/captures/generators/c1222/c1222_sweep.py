#!/usr/bin/env python3
# Helper module for the c1222 capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# C12.22 over UDP/1153: sweep of EPSEM services with edge-case lengths,
# cleartext/ciphertext-with-auth crypto paths and odd AP-title encodings.
import struct
import sys
def ber_len(n):
    if n < 0x80: return bytes([n])
    b = n.to_bytes((n.bit_length()+7)//8, 'big')
    return bytes([0x80 | len(b)]) + b
def tlv(tag, body, longform=False):
    if longform:
        return bytes([tag, 0x84]) + struct.pack('!I', len(body)) + body
    return bytes([tag]) + ber_len(len(body)) + body
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff
def udp4(payload, sport=50000, dport=1153):
    udp = struct.pack('!HHHH', sport, dport, 8+len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(udp), 1, 0, 64, 17, 0,
                     bytes([192,0,2,1]), bytes([192,0,2,2]))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00' + ip + udp
AUTH = tlv(0xac, tlv(0xa2, tlv(0xa0, tlv(0xa1, b'\x80\x01\x02\x81\x04\x48\xf3\xd0\x61'))))
def msg(epsem, called=b'\x80\x02\x7b\x04', calling=b'\x80\x03\x7b\xc1\x75',
        auth=AUTH, ui_long=False, extra=b''):
    ui = tlv(0xbe, tlv(0x28, tlv(0x81, epsem)), longform=ui_long)
    body = tlv(0xa2, called) + tlv(0xa4, b'\x02\x01\x03') + tlv(0xa6, calling) + \
           tlv(0xa8, b'\x02\x01\x03') + auth + extra + ui
    return tlv(0x60, body)
mac = b'\x11\x22\x33\x44'
pkts = []
clear = [
    b'\x03\x53\x02\xaa\xbb\xcc',              # AUTHENTICATE: *length == auth_len -> wrap
    b'\x00\x20\x30\x00\x01',                  # zero-length service
    b'\x06\x40\x00\x07\x00\x00\xcc\x00\x00',  # FULL_WRITE table 7 tblsize 0 -> tblsize-3 wraps
    b'\x07\x40\x00\x07\x00\x01\xaa\xcc',      # FULL_WRITE table 7 tblsize 1
    b'\x01\x50',                              # LOGON truncated
    b'\x09\x4f\x00\x01\x00\x00\x00\x00\x00\xff', # PARTIAL WRITE huge size
    b'\x84\xff\xff\xff\xff\x30',              # 4-byte BER length (huge)
    b'\x85\x01\x00\x00\x00\x00\x30',          # 5-byte BER length (rejected by ber_len_ok?)
    b'\x02\x6b\x00',                          # negotiate 11 rates truncated
    b'\x05\x71\x01\x02\x03\x04',              # timing setup
]
for e in clear:
    pkts.append(msg(b'\x80' + e))
    pkts.append(msg(b'\x90' + e))            # ED class flag
# cleartext with authentication, various sizes
for n in range(0, 9):
    pkts.append(msg(b'\x84' + b'\x02\x30\x00\x01'[:n] + mac[:max(0, n-4)]))
    pkts.append(msg(b'\x84' + bytes(n) ))
# ciphertext with authentication, tiny and normal
for n in range(0, 9):
    pkts.append(msg(b'\x88' + bytes(range(n))))
pkts.append(msg(b'\x88' + bytes(range(40)) + mac))
# AP titles: absolute, long relative, long-form length, missing
pkts.append(msg(b'\x84\x02\x30\x00' + mac, called=b'\x06\x03\x2a\x03\x04'))
pkts.append(msg(b'\x84\x02\x30\x00' + mac, called=b'\x80' + ber_len(250) + bytes([1])*250))
pkts.append(msg(b'\x84\x02\x30\x00' + mac, called=b'\x80\x81\x05' + b'\x01'*5))
pkts.append(msg(b'\x84\x02\x30\x00' + mac, called=b'\x80\x00'))
pkts.append(msg(b'\x84\x02\x30\x00' + mac, calling=b'\x80\x00'))
pkts.append(msg(b'\x84\x02\x30\x00' + mac, ui_long=True))
pkts.append(msg(b'\x84\x02\x30\x00' + mac, auth=b''))
pkts.append(msg(b'\x84\x02\x30\x00' + mac, auth=tlv(0xac, tlv(0xa2, tlv(0xa0, tlv(0xa1, b'\x80\x00\x81\x00'))))))
pkts.append(msg(b'\x84\x02\x30\x00' + mac, auth=tlv(0xac, tlv(0xa2, tlv(0xa0, tlv(0xa1, b'\x80\x05' + b'\x02'*5 + b'\x81\x10' + b'\x00'*16))))))
pkts.append(msg(b'\x84' + bytes(range(256))*2 + mac, extra=tlv(0xa1, b'\x06\x03\x2a\x03\x04')))
pkts.append(msg(b'\x84\x02\x30\x00' + mac, extra=tlv(0x8b, b'\x2a\x03\x04'*60)))
# epsem with user-information length 0x7e so total length crosses 1->2 byte boundary
pkts.append(msg(b'\x84' + b'\x00'*(0x7e-2-2-1-4) + mac))
out = sys.argv[1] if len(sys.argv) > 1 else 'c1222_sweep.pcap'
with open(out, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
    for i, p in enumerate(pkts):
        p = udp4(p)
        f.write(struct.pack('<IIII', i+1, 0, len(p), len(p)) + p)
print(len(pkts), 'packets')
