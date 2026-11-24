#!/usr/bin/env python3
# Generates test/captures/bacnet_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the BACnet NPDU dissector
(packet-bacnet.c, protocol "bacnet").

Every packet is built from scratch with struct; no captured traffic is used.
The NPDUs are carried in BVLC over UDP port 47808 (BACnet/IP, IPv4 and IPv6),
in 802.2 LLC (SAP 0x82) and in BACnet MS/TP frames wrapped in the Cimetrics
LLC/SNAP encapsulation (including a COBS-encoded extended data frame), so
the whole capture is Ethernet (linktype 1).

Usage: mkbacnet.py <output directory> [-v]

Writes:
  bacnet-coverage.pcap            every network layer message type, every
                                  DLEN/SLEN branch, control bits, the
                                  security wrapper (plain, encrypted, with
                                  authentication data), every security
                                  message, proprietary and reserved messages,
                                  and the two reproducers fixed on the branch
  bacnet-coverage-malformed.pcap  truncated NPDUs and security messages
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
IP_A = bytes([192, 0, 2, 1])
IP_B = bytes([192, 0, 2, 2])
IP6_A = bytes.fromhex('20010db8000000000000000000000001')
IP6_B = bytes.fromhex('20010db8000000000000000000000002')
PORT = 47808


# Link and transport layers ------------------------------------------------

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s >> 16) + (s & 0xffff)
    return ~s & 0xffff


def eth(etype, payload, dst=MAC_B, src=MAC_A):
    return dst + src + struct.pack('>H', etype) + payload


def ipv4_udp(payload, sport=PORT, dport=PORT, src=IP_A, dst=IP_B, ident=1):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = src + dst + struct.pack('>BBH', 0, 17, len(udp))
    c = csum(pseudo + udp) or 0xffff
    udp = udp[:6] + struct.pack('>H', c) + udp[8:]
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), ident, 0,
                      64, 17, 0, src, dst)
    hdr = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    return eth(0x0800, hdr + udp)


def ipv6_udp(payload, sport=PORT, dport=PORT, src=IP6_A, dst=IP6_B):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = src + dst + struct.pack('>IxxxB', len(udp), 17)
    c = csum(pseudo + udp) or 0xffff
    udp = udp[:6] + struct.pack('>H', c) + udp[8:]
    hdr = struct.pack('>IHBB', 0x60000000, len(udp), 17, 64) + src + dst
    return eth(0x86dd, hdr + udp)


def bvlc4(npdu, function=0x0a, ident=1):
    """BACnet/IP (Annex J). 0x0a Original-Unicast-NPDU, 0x0b
    Original-Broadcast-NPDU, 0x04 Forwarded-NPDU (with the B/IP address of
    the originating device)."""
    extra = b''
    if function == 0x04:
        extra = bytes([192, 0, 2, 9]) + struct.pack('>H', PORT)
    return ipv4_udp(struct.pack('>BBH', 0x81, function, 4 + len(extra) + len(npdu))
                    + extra + npdu, ident=ident)


def bvlc6(npdu, function=0x01):
    """BACnet/IPv6 (Annex U). 0x01 Original-Unicast (virtual source and
    destination), 0x02 Original-Broadcast and 0x0c Distribute-Broadcast
    (virtual source), 0x08 Forwarded-NPDU (virtual source, original
    address and port)."""
    if function == 0x01:
        extra = b'\x00\x00\x01\x00\x00\x02'
    elif function in (0x02, 0x0c):
        extra = b'\x00\x00\x01'
    elif function == 0x08:
        extra = b'\x00\x00\x01' + IP6_A + struct.pack('>H', PORT)
    else:
        raise ValueError(function)
    return ipv6_udp(struct.pack('>BBH', 0x82, function, 4 + len(extra) + len(npdu))
                    + extra + npdu)


def llc(npdu):
    """IEEE 802.3 frame with 802.2 LLC, DSAP/SSAP 0x82 (BACnet), UI."""
    data = b'\x82\x82\x03' + npdu
    return eth(len(data), data)


def crc8_mstp(data):
    crc = 0xff
    for b in data:
        c = crc ^ b
        c = c ^ (c << 1) ^ (c << 2) ^ (c << 3) ^ (c << 4) ^ (c << 5) ^ (c << 6) ^ (c << 7)
        crc = (c & 0xfe) ^ ((c >> 8) & 1)
    return ~crc & 0xff


def crc16_x25(data):
    crc = 0xffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return ~crc & 0xffff


def crc32k_byte(b, crc):
    for _ in range(8):
        if (b & 1) ^ (crc & 1):
            crc = (crc >> 1) ^ 0xEB31D82E
        else:
            crc >>= 1
        b >>= 1
    return crc


def cobs_encode(data, mask=0x55):
    out = bytearray([0])
    code_pos, code = 0, 1
    for b in data:
        if b == 0:
            out[code_pos] = code
            code_pos, code = len(out), 1
            out.append(0)
        else:
            out.append(b)
            code += 1
            if code == 0xff:
                out[code_pos] = code
                code_pos, code = len(out), 1
                out.append(0)
    out[code_pos] = code
    return bytes(x ^ mask for x in out)


def mstp(npdu, ftype=0x06, dst=0x02, src=0x01):
    """BACnet MS/TP frame without preamble. Frame types 5/6 carry the NPDU
    followed by CRC-16; 0x20/0x21 (extended) carry it COBS-encoded with an
    encoded CRC-32K (Clause 9 / Annex T)."""
    if ftype in (0x20, 0x21):
        enc = cobs_encode(npdu)
        crc = 0xffffffff
        for b in enc:
            crc = crc32k_byte(b, crc)
        enc_crc = cobs_encode(struct.pack('<I', ~crc & 0xffffffff))
        assert len(enc_crc) == 5
        body = enc + enc_crc
        length = len(body) - 2
        hdr = struct.pack('>BBBH', ftype, dst, src, length)
        return hdr + bytes([crc8_mstp(hdr)]) + body
    hdr = struct.pack('>BBBH', ftype, dst, src, len(npdu))
    return (hdr + bytes([crc8_mstp(hdr)]) + npdu
            + struct.pack('<H', crc16_x25(npdu)))


def cimetrics(frame):
    """MS/TP frame in the Cimetrics U+4 LLC/SNAP encapsulation
    (OUI 00-10-90, PID 1): 16 bit delta time, 8 bit value, MS/TP frame."""
    data = (b'\xaa\xaa\x03\x00\x10\x90\x00\x01' + struct.pack('<HB', 10, 0)
            + frame)
    return eth(len(data), data)


# BACnet NPDU --------------------------------------------------------------

WHO_IS = b'\x10\x08'
I_AM = bytes.fromhex('1000c4020000012201e09100210f')
# Confirmed ReadProperty(device,1 object-name), invoke ID 1
READ_PROP = bytes.fromhex('00050c0c0c020000011977')
DATA_NOT_REPLY = 0x06
DATA_REPLY = 0x05


def npdu(control=0x00, dnet=None, dadr=None, snet=None, sadr=None, hop=255,
         msg=None, body=b'', version=1):
    """Build an NPDU. dadr/sadr are the address octets (DLEN/SLEN is their
    length); msg is the network layer message type (sets bit 7)."""
    out = bytearray([version, 0])
    if dnet is not None:
        control |= 0x20
        out += struct.pack('>HB', dnet, len(dadr)) + dadr
    if snet is not None:
        control |= 0x08
        out += struct.pack('>HB', snet, len(sadr)) + sadr
    if dnet is not None:
        out.append(hop)
    if msg is not None:
        control |= 0x80
        out.append(msg)
    out[1] = control
    return bytes(out) + body


def net(msg, body=b'', **kw):
    return npdu(msg=msg, body=body, **kw)


SIG = bytes(range(0xa0, 0xb0))      # 16 octet signature


def wrapper(control=0x00, dadr=b'', sadr=b'', auth=None, key_rev=1,
            key_id=0x0102, src_dev=0x000101, msg_id=0x11223344,
            ts=0x5f000000, dst_dev=0x000202, dnet=5, snet=6):
    """Security wrapper header up to the service data (Clause 24.3).
    auth = (mechanism, user id, role, data) adds the authentication
    fields and sets the control bit. Encrypted wrappers stop after the
    time stamp: the rest is opaque."""
    if auth is not None:
        control |= 0x10
    out = struct.pack('>BBH', control, key_rev, key_id)
    out += struct.pack('>I', src_dev)[1:] + struct.pack('>II', msg_id, ts)
    if control & 0x40:
        return out
    out += struct.pack('>I', dst_dev)[1:]
    out += struct.pack('>HB', dnet, len(dadr)) + dadr
    out += struct.pack('>HB', snet, len(sadr)) + sadr
    if auth is not None:
        mech, uid, role, data = auth
        out += struct.pack('>BHB', mech, uid, role)
        if mech != 0:
            out += struct.pack('>H', len(data)) + data
    return out


def secmsg(msg, service, encrypted=False, **kw):
    """A network layer security message: wrapper, service data, signature."""
    if encrypted:
        return net(msg, wrapper(control=0x40 | kw.pop('control', 0), **kw)
                   + bytes([0xe5] * 12) + SIG)
    return net(msg, wrapper(**kw) + service + SIG)


def secpay(payload, net_msg=False, extra=b'', **kw):
    """Security-Payload: wrapper, payload length, payload, [extra], signature."""
    control = kw.pop('control', 0) | (0x80 if net_msg else 0)
    return net(0x0b, wrapper(control=control, **kw)
               + struct.pack('>H', len(payload)) + payload + extra + SIG)


def u32(v):
    return struct.pack('>I', v)


# Captures -----------------------------------------------------------------

def main_frames():
    F = []

    def add(desc, frame):
        F.append((desc, frame))

    # --- APDUs, control bits, DNET/SNET variants (BVLC/IPv4) ---
    add('APDU Who-Is, control 0x00', bvlc4(npdu(body=WHO_IS)))
    add('APDU I-Am, Original-Broadcast', bvlc4(npdu(body=I_AM), function=0x0b))
    add('APDU ReadProperty, expecting reply, priority urgent',
        bvlc4(npdu(control=0x05, body=READ_PROP)))
    add('APDU Who-Is, priority critical equipment',
        bvlc4(npdu(control=0x02, body=WHO_IS)))
    add('APDU Who-Is, priority life safety (0x03)',
        bvlc4(npdu(control=0x03, body=WHO_IS)))
    add('APDU Who-Is, both reserved control bits set',
        bvlc4(npdu(control=0x50, body=WHO_IS)))
    add('APDU Who-Is, unknown version 2', bvlc4(npdu(body=WHO_IS, version=2)))
    add('DLEN 0 (broadcast on DNET 65535), hop count 255',
        bvlc4(npdu(dnet=0xffff, dadr=b'', body=WHO_IS)))
    add('DLEN 1 (MS/TP DADR 0x23), hop count 254',
        bvlc4(npdu(dnet=10, dadr=b'\x23', hop=254, body=WHO_IS)))
    add('DLEN 2 (other MAC)', bvlc4(npdu(dnet=11, dadr=b'\x12\x34', body=WHO_IS)))
    add('DLEN 3 (other MAC)', bvlc4(npdu(dnet=12, dadr=b'\x01\x02\x03', body=WHO_IS)))
    add('DLEN 6 (Ethernet DADR)',
        bvlc4(npdu(dnet=13, dadr=bytes.fromhex('00a0c8123456'), body=WHO_IS)))
    # The reproducer of bacnet_dlen_ge7.py, byte for byte
    add('DLEN 7 reproducer (bacnet_dlen_ge7.pcap): hop count 255 then Who-Is',
        bvlc4(bytes([0x01, 0x20, 0x00, 0x05, 0x07]) + bytes([0xaa] * 7)
              + bytes([0xff]) + WHO_IS))
    add('DLEN 18 (invalid, stepped over), hop count 7',
        bvlc4(npdu(dnet=14, dadr=bytes(range(1, 19)), hop=7, body=WHO_IS)))
    add('SLEN 0 (invalid)', bvlc4(npdu(snet=20, sadr=b'', body=I_AM)))
    add('SLEN 1 (MS/TP SADR)', bvlc4(npdu(snet=21, sadr=b'\x05', body=I_AM)))
    add('SLEN 2 (other MAC)', bvlc4(npdu(snet=22, sadr=b'\xab\xcd', body=I_AM)))
    add('SLEN 5 (other MAC)', bvlc4(npdu(snet=23, sadr=b'\x01\x02\x03\x04\x05', body=I_AM)))
    add('SLEN 6 (Ethernet SADR)',
        bvlc4(npdu(snet=24, sadr=bytes.fromhex('00a0c8abcdef'), body=I_AM)))
    add('SLEN 7 (invalid, stepped over)',
        bvlc4(npdu(snet=25, sadr=bytes([0xbb] * 7), body=I_AM)))
    add('DNET/DLEN 6 and SNET/SLEN 1, hop count 9, ReadProperty expecting reply',
        bvlc4(npdu(control=0x04, dnet=30, dadr=bytes.fromhex('00a0c8000030'),
                   snet=31, sadr=b'\x07', hop=9, body=READ_PROP)))
    add('DNET/DLEN 8 and SNET/SLEN 9 (both invalid, stepped over), hop count 3',
        bvlc4(npdu(dnet=32, dadr=bytes([0xd1] * 8), snet=33, sadr=bytes([0x51] * 9),
                   hop=3, body=WHO_IS)))

    # --- Network layer messages ---
    add('Who-Is-Router-To-Network, no DNET', bvlc4(net(0x00), function=0x0b))
    add('Who-Is-Router-To-Network, DNET 7', bvlc4(net(0x00, struct.pack('>H', 7))))
    add('I-Am-Router-To-Network, DNETs 1 2 3',
        bvlc4(net(0x01, struct.pack('>HHH', 1, 2, 3)), function=0x0b))
    add('I-Could-Be-Router-To-Network, DNET 40, performance 10',
        bvlc4(net(0x02, struct.pack('>HB', 40, 10))))
    for reason in range(8):
        add('Reject-Message-To-Network, reason %d, DNET %d' % (reason, 50 + reason),
            bvlc4(net(0x03, struct.pack('>BH', reason, 50 + reason))))
    add('Router-Busy-To-Network, DNETs 60 61',
        bvlc4(net(0x04, struct.pack('>HH', 60, 61))))
    add('Router-Busy-To-Network, no DNET (all networks)', bvlc4(net(0x04)))
    add('Router-Available-To-Network, DNET 62 and one odd trailing octet (Data)',
        bvlc4(net(0x05, struct.pack('>HB', 62, 0x99))))
    add('Initialize-Routing-Table, 0 ports (query)', bvlc4(net(0x06, b'\x00')))
    add('Initialize-Routing-Table, 2 ports (port info 0 and 3 octets)',
        bvlc4(net(0x06, b'\x02' + struct.pack('>HBB', 70, 1, 0)
                  + struct.pack('>HBB', 71, 2, 3) + b'abc')))
    add('Initialize-Routing-Table-Ack, 1 port (port info 2 octets)',
        bvlc4(net(0x07, b'\x01' + struct.pack('>HBB', 72, 3, 2) + b'\x01\x02')))
    add('Initialize-Routing-Table-Ack, port count 3 but 1 port present',
        bvlc4(net(0x07, b'\x03' + struct.pack('>HBB', 73, 4, 0))))
    add('Establish-Connection-To-Network, DNET 80, termination time 60',
        bvlc4(net(0x08, struct.pack('>HB', 80, 60))))
    add('Disconnect-Connection-To-Network, DNET 81',
        bvlc4(net(0x09, struct.pack('>H', 81))))
    add('What-Is-Network-Number', bvlc4(net(0x12), function=0x0b))
    add('Network-Number-Is, network 82, configured',
        bvlc4(net(0x13, struct.pack('>HB', 82, 1)), function=0x0b))
    add('Network-Number-Is, network 83, learned',
        bvlc4(net(0x13, struct.pack('>HB', 83, 0))))
    add('Reserved message type 0x14 with 3 octets of data',
        bvlc4(net(0x14, b'\x01\x02\x03')))
    add('Reserved message type 0x7f, no data', bvlc4(net(0x7f)))
    add('Vendor proprietary message 0x80, vendor 7, 4 octets of data',
        bvlc4(net(0x80, struct.pack('>H', 7) + b'\xde\xad\xbe\xef')))
    add('Vendor proprietary message 0xff, vendor 260, no data',
        bvlc4(net(0xff, struct.pack('>H', 260))))
    add('Routed Who-Is-Router-To-Network: DLEN 0, SLEN 6, hop 255, expecting reply',
        bvlc4(net(0x00, struct.pack('>H', 90), control=0x04, dnet=0xffff, dadr=b'',
                  snet=91, sadr=bytes.fromhex('00a0c8000091'))))

    # --- Security wrapper and security messages ---
    add('Challenge-Request (not challenged, original message ID/time stamp)',
        bvlc4(secmsg(0x0a, b'\x00' + u32(0x01020304) + u32(0x5f000001))))
    add('Challenge-Request, challenged, wrapper with DADR 1 and SADR 6, trusted/secured-by-router bits',
        bvlc4(secmsg(0x0a, b'\x01' + u32(0x0a0b0c0d) + u32(0x5f000002),
                     control=0x0f, dadr=b'\x09',
                     sadr=bytes.fromhex('00a0c8000001'))))
    add('Challenge-Request, encrypted (Data)', bvlc4(secmsg(0x0a, b'', encrypted=True)))
    # The reproducer of bacnet_secpay_len.py, byte for byte
    secpay_repro = (bytes([0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 1,
                           0, 0, 0, 0, 0x00, 0x00, 0x02, 0x00, 0x05, 0x00,
                           0x00, 0x06, 0x00]) + struct.pack('>H', 2) + WHO_IS
                    + bytes([0x55] * 16))
    add('Security-Payload reproducer (bacnet_secpay_len.pcap): Who-Is inside',
        bvlc4(bytes([0x01, 0x80, 0x0b]) + secpay_repro))
    add('Security-Payload, I-Am, payload length shorter than the data (rest cut off)',
        bvlc4(secpay(I_AM, extra=b'\xee\xee\xee')))
    add('Security-Payload, authentication mechanism 0 (no data), I-Am',
        bvlc4(secpay(I_AM, auth=(0, 0x1234, 3, b''))))
    add('Security-Payload, authentication mechanism 1 with 5 octets of data, DADR 2, SADR 1, Who-Is',
        bvlc4(secpay(WHO_IS, auth=(1, 0x4321, 7, b'authd'), dadr=b'\x12\x34',
                     sadr=b'\x05', control=0x0c)))
    add('Security-Payload, network message: Who-Is-Router-To-Network DNET 100',
        bvlc4(secpay(net(0x00, struct.pack('>H', 100)), net_msg=True)))
    inner = secpay(WHO_IS, msg_id=0x55667788)
    add('Security-Payload, network message: nested Security-Payload with Who-Is',
        bvlc4(secpay(inner, net_msg=True)))
    add('Security-Payload, encrypted (Data)',
        bvlc4(net(0x0b, wrapper(control=0x40) + bytes([0xe5] * 20) + SIG)))
    add('Security-Payload, encrypted network message (Data)',
        bvlc4(net(0x0b, wrapper(control=0xc0) + bytes([0xe5] * 20) + SIG)))
    orig = u32(0x01020304) + u32(0x5f000003)
    for code, params, name in (
            (0x00, b'', 'success'),
            (0x06, u32(0x5f001000), 'badTimestamp (expected time stamp)'),
            (0x07, b'\x01\x02', 'cannotUseKey (algorithm, key id)'),
            (0x0e, b'\x02\x01\x03\x02\x04', 'incorrectKey (2 keys)'),
            (0x0f, b'\x03\x04', 'invalidKeyData'),
            (0x15, b'\x09', 'tooManyKeys'),
            (0x16, b'\x05' + struct.pack('>H', 260), 'unknownAuthenticationType'),
            (0x17, b'\x05\x06', 'unknownKey'),
            (0x18, b'\x07', 'unknownKeyRevision'),
            (0x19, b'', 'unknownSourceMessage'),
            (0x40, b'', 'unknown code 0x40')):
        add('Security-Response, %s' % name,
            bvlc4(secmsg(0x0c, bytes([code]) + orig + params)))
    add('Security-Response, encrypted (Data)', bvlc4(secmsg(0x0c, b'', encrypted=True)))
    add('Request-Key-Update',
        bvlc4(secmsg(0x0d, b'\x01' + u32(0x5f000000) + u32(0x60000000)
                     + b'\x02' + u32(0x5f100000) + u32(0x60100000) + b'\x03')))
    add('Request-Key-Update, encrypted (Data)', bvlc4(secmsg(0x0d, b'', encrypted=True)))
    key = lambda algo, kid, data: bytes([algo, kid, len(data)]) + data
    add('Update-Keyset, control 0xd8: set 1 and set 2 times and parameters (2 keys each)',
        bvlc4(secmsg(0x0e, b'\xd8'
                     + b'\x01' + u32(0x5f000000) + u32(0x60000000)
                     + b'\x02' + key(1, 1, b'K1-one') + key(2, 2, b'K1-two')
                     + b'\x02' + u32(0x5f200000) + u32(0x60200000)
                     + b'\x02' + key(1, 3, b'K2-one') + key(3, 4, b'K2-2'))))
    add('Update-Keyset, control 0x25: clear set 1 and set 2, remove keys',
        bvlc4(secmsg(0x0e, b'\x25')))
    add('Update-Keyset, control 0x42: set 1 parameters (1 key), more follows',
        bvlc4(secmsg(0x0e, b'\x42\x01' + key(4, 5, b'\x00\x11\x22\x33'))))
    add('Update-Keyset, control 0x90: set 1 and set 2 times only',
        bvlc4(secmsg(0x0e, b'\x90' + b'\x05' + u32(1) + u32(2)
                     + b'\x06' + u32(3) + u32(4))))
    add('Update-Keyset, encrypted (Data)', bvlc4(secmsg(0x0e, b'', encrypted=True)))
    add('Update-Distribution-Key',
        bvlc4(secmsg(0x0f, b'\x04\x01\x07' + bytes([8]) + b'DISTKEY!')))
    add('Update-Distribution-Key, encrypted (Data)', bvlc4(secmsg(0x0f, b'', encrypted=True)))
    add('Request-Master-Key, 3 algorithms',
        bvlc4(secmsg(0x10, b'\x03\x00\x01\x02')))
    add('Request-Master-Key, encrypted (Data)', bvlc4(secmsg(0x10, b'', encrypted=True)))
    add('Set-Master-Key',
        bvlc4(secmsg(0x11, b'\x01\x02' + bytes([6]) + b'MASTER')))
    add('Set-Master-Key, encrypted (Data)', bvlc4(secmsg(0x11, b'', encrypted=True)))

    # --- Other parents ---
    add('BVLC/IPv4 Forwarded-NPDU, I-Am', bvlc4(npdu(body=I_AM), function=0x04))
    add('BVLC/IPv6 Original-Unicast-NPDU, Who-Is', bvlc6(npdu(body=WHO_IS), 0x01))
    add('BVLC/IPv6 Original-Broadcast-NPDU, I-Am', bvlc6(npdu(body=I_AM), 0x02))
    add('BVLC/IPv6 Forwarded-NPDU, Who-Is-Router-To-Network',
        bvlc6(net(0x00), 0x08))
    add('BVLC/IPv6 Distribute-Broadcast-To-Network, Who-Is',
        bvlc6(npdu(body=WHO_IS), 0x0c))
    add('802.2 LLC SAP 0x82, Who-Is', llc(npdu(body=WHO_IS)))
    add('802.2 LLC SAP 0x82, I-Am-Router-To-Network DNET 5',
        llc(net(0x01, struct.pack('>H', 5))))
    add('MS/TP (Cimetrics) BACnet Data Not Expecting Reply, I-Am',
        cimetrics(mstp(npdu(body=I_AM), DATA_NOT_REPLY)))
    add('MS/TP (Cimetrics) BACnet Data Expecting Reply, ReadProperty',
        cimetrics(mstp(npdu(control=0x04, body=READ_PROP), DATA_REPLY, dst=1, src=2)))
    add('MS/TP (Cimetrics) BACnet Extended Data Not Expecting Reply (COBS), routed I-Am',
        cimetrics(mstp(npdu(snet=0x0101, sadr=b'\x00\x00\x01\x00\x00', body=I_AM),
                       0x21)))
    return F


def malformed_frames():
    F = []

    def add(desc, frame):
        F.append((desc, frame))

    add('NPDU of one octet (control missing)', bvlc4(b'\x01'))
    add('DNET cut short', bvlc4(b'\x01\x20\x00'))
    add('DLEN 6 but 2 DADR octets', bvlc4(b'\x01\x20\x00\x05\x06\x01\x02'))
    add('DLEN 1 with no DADR', bvlc4(b'\x01\x20\x00\x05\x01'))
    add('DLEN 3 with 1 DADR octet', bvlc4(b'\x01\x20\x00\x05\x03\x01'))
    add('DLEN 9 with 2 DADR octets', bvlc4(b'\x01\x20\x00\x05\x09\x01\x02'))
    add('SNET cut short', bvlc4(b'\x01\x08\x00'))
    add('SLEN 6 with 1 octet', bvlc4(b'\x01\x08\x00\x05\x06\x01'))
    add('SLEN 1 with no SADR', bvlc4(b'\x01\x08\x00\x05\x01'))
    add('SLEN 4 with 1 octet', bvlc4(b'\x01\x08\x00\x05\x04\x01'))
    add('SLEN 8 with 1 octet', bvlc4(b'\x01\x08\x00\x05\x08\x01'))
    add('Hop count missing', bvlc4(b'\x01\x20\x00\x05\x00'))
    add('Message type missing', bvlc4(b'\x01\x80'))
    add('I-Could-Be-Router cut short', bvlc4(net(0x02, b'\x00\x01')))
    add('Reject-Message cut short', bvlc4(net(0x03, b'\x01\x00')))
    add('Initialize-Routing-Table without port count', bvlc4(net(0x06)))
    add('Initialize-Routing-Table port cut short', bvlc4(net(0x06, b'\x01\x00\x01\x02')))
    add('Initialize-Routing-Table port info length past the end',
        bvlc4(net(0x06, b'\x01\x00\x01\x02\x20abc')))
    add('Establish-Connection cut short', bvlc4(net(0x08, b'\x00\x01')))
    add('Disconnect-Connection cut short', bvlc4(net(0x09, b'\x00')))
    add('Network-Number-Is cut short', bvlc4(net(0x13, b'\x00\x01')))
    add('Proprietary message without vendor ID', bvlc4(net(0x90, b'\x01')))
    add('Security wrapper shorter than its fixed header', bvlc4(net(0x0a, b'\x00\x01\x00')))
    add('Security wrapper DLEN past the end', bvlc4(net(0x0a, wrapper()[:20] + b'\x30')))
    add('Security wrapper shorter than the signature (length underflow)',
        bvlc4(net(0x0a, wrapper())))
    add('Encrypted wrapper shorter than the signature',
        bvlc4(net(0x0a, wrapper(control=0x40) + b'\x01\x02')))
    add('Security wrapper authentication data length past the end',
        bvlc4(net(0x0a, wrapper(auth=(1, 1, 1, b''))[:-2] + b'\x10\x00' + SIG)))
    add('Challenge-Request service data cut short', bvlc4(secmsg(0x0a, b'\x00\x01')))
    add('Security-Payload length past the end',
        bvlc4(net(0x0b, wrapper() + struct.pack('>H', 100) + WHO_IS + SIG)))
    add('Security-Payload without the length field', bvlc4(net(0x0b, wrapper() + SIG)))
    add('Security-Payload network message, inner NPDU cut short',
        bvlc4(secpay(b'\x01', net_msg=True)))
    nest = net(0x00)
    for i in range(600):
        nest = secpay(nest, net_msg=True)
    add('Security-Payload nested 600 deep (dissection depth limit)', bvlc4(nest))
    add('Security-Response cut short', bvlc4(secmsg(0x0c, b'\x00\x01')))
    add('Security-Response badTimestamp without expected time stamp',
        bvlc4(secmsg(0x0c, b'\x06' + bytes(8))))
    add('Security-Response cannotUseKey without key', bvlc4(secmsg(0x0c, b'\x07' + bytes(8))))
    add('Security-Response incorrectKey count without keys',
        bvlc4(secmsg(0x0c, b'\x0e' + bytes(8))))
    add('Security-Response incorrectKey, 1 key and 1 extra octet',
        bvlc4(secmsg(0x0c, b'\x0e' + bytes(8) + b'\x05\x01\x02\x03')))
    add('Security-Response unknownAuthenticationType cut short',
        bvlc4(secmsg(0x0c, b'\x16' + bytes(8) + b'\x01')))
    add('Security-Response unknownKeyRevision cut short', bvlc4(secmsg(0x0c, b'\x18' + bytes(8))))
    add('Security-Response tooManyKeys cut short', bvlc4(secmsg(0x0c, b'\x15' + bytes(8))))
    add('Request-Key-Update cut short', bvlc4(secmsg(0x0d, b'\x01\x02')))
    add('Update-Keyset without control', bvlc4(secmsg(0x0e, b'')))
    add('Update-Keyset set 1 times cut short', bvlc4(secmsg(0x0e, b'\x80\x01')))
    add('Update-Keyset set 1 parameters without key count', bvlc4(secmsg(0x0e, b'\x40')))
    add('Update-Keyset set 1 key data length past the end',
        bvlc4(secmsg(0x0e, b'\x40\x01\x01\x02\x30ab')))
    add('Update-Keyset set 2 times cut short', bvlc4(secmsg(0x0e, b'\x10\x01')))
    add('Update-Keyset set 2 parameters without key count', bvlc4(secmsg(0x0e, b'\x08')))
    add('Update-Keyset set 2 key data length past the end',
        bvlc4(secmsg(0x0e, b'\x08\x01\x01\x02\x30ab')))
    add('Update-Distribution-Key cut short', bvlc4(secmsg(0x0f, b'\x01\x02')))
    add('Update-Distribution-Key data length past the end',
        bvlc4(secmsg(0x0f, b'\x01\x02\x03\x40ab')))
    add('Request-Master-Key without count', bvlc4(secmsg(0x10, b'')))
    add('Request-Master-Key count 5 with 2 algorithms', bvlc4(secmsg(0x10, b'\x05\x01\x02')))
    add('Set-Master-Key cut short', bvlc4(secmsg(0x11, b'\x01')))
    add('Set-Master-Key data length past the end', bvlc4(secmsg(0x11, b'\x01\x02\x40ab')))
    add('Secure-BVLL (BVLC 0x0c), encrypted wrapper',
        ipv4_udp(struct.pack('>BBH', 0x81, 0x0c, 4 + 11 + 4 + 16)
                 + wrapper(control=0x40) + b'\xe5' * 4 + SIG))
    return F


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, (_, p) in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(p), len(p)) + p)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    verbose = '-v' in sys.argv
    for name, frames in (('bacnet-coverage.pcap', main_frames()),
                         ('bacnet-coverage-malformed.pcap', malformed_frames())):
        write_pcap(os.path.join(out, name), frames)
        if verbose:
            print(name)
            for i, (desc, _) in enumerate(frames, 1):
                print('  %3d %s' % (i, desc))


if __name__ == '__main__':
    main()
