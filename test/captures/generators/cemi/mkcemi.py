#!/usr/bin/env python3
# Generates test/captures/cemi_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the KNX cEMI (Common External
Message Interface) dissector (packet-cemi.c).

cEMI frames are carried in KNXnet/IP over UDP port 3671: link layer and
transport layer frames in ROUTING_INDICATION (0x0530), management frames
in DEVICE_CONFIGURATION_REQUEST (0x0310) after a connection header.
KNX Data Security (A_DataSecurity) telegrams are built with AES-CCM as
KNX specifies it, with the key 00 01 .. 0F (for "-o kip.key_1"), or with
the tool keys and group keys of test/keys/knx_keyring.xml (B0 .. BF for
devices 1.1.1-1.1.4, A0 .. AF for group 1/7/131). Every packet is built
from scratch with struct (and the cryptography module for AES); no
captured traffic is used.

Usage: mkcemi.py <output directory>

Writes:
  cemi-coverage.pcap            every message code, additional info type,
                                control field bit, TPCI and APCI service,
                                management message, property range form,
                                and individually addressed Data Security
                                telegrams (data, sync) that decrypt with
                                the key 00..0F or the keyring
  cemi-coverage-malformed.pcap  truncated and inconsistent frames (KNX/IP
                                error expert infos), group addressed Data
                                Security telegrams (warning without a
                                keyring), the original group addressed
                                reproducers, sequence numbers and senders
                                the keyring rejects
"""

import os
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SRC = (192, 0, 2, 1)
DST = (192, 0, 2, 2)
PORT = 3671

KEY0 = bytes(range(16))                          # -o kip.key_1:00 01 .. 0F
KEY_TOOL = bytes(range(0xB0, 0xC0))              # keyring device tool key
KEY_GA = bytes(range(0xA0, 0xB0))                # keyring group 1/7/131 key


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def udp_frame(payload, ident):
    u = struct.pack('>HHHH', PORT, PORT, 8 + len(payload), 0) + payload
    pseudo = struct.pack('>4s4sBBH', bytes(SRC), bytes(DST), 0, 17, len(u))
    c = csum(pseudo + u) or 0xffff
    u = u[:6] + struct.pack('>H', c) + u[8:]
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), ident, 0, 64, 17, 0,
                     bytes(SRC), bytes(DST))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + u


def knxip(service, body):
    return struct.pack('>BBHH', 6, 0x10, service, 6 + len(body)) + body


def routing(cemi):
    return knxip(0x0530, cemi)


def config_req(cemi, seq=0):
    return knxip(0x0310, bytes([4, 1, seq & 0xff, 0]) + cemi)


def ia(text):
    a, b, c = (int(x) for x in text.split('.'))
    return (a << 12) | (b << 8) | c


def ga(text):
    a, b, c = (int(x) for x in text.split('/'))
    return (a << 11) | (b << 8) | c


def ldata(tpdu, mc=0x29, ai=b'', ctrl1=0xBC, ctrl2=0x60, sa=ia('1.1.10'), da=ia('1.1.20')):
    """An L_Data frame; tpdu starts with the TPCI octet."""
    return (bytes([mc, len(ai)]) + ai + bytes([ctrl1, ctrl2]) + struct.pack('>HH', sa, da)
            + bytes([len(tpdu) - 1]) + tpdu)


def lgroup(tpdu, **kw):
    kw.setdefault('ctrl2', 0xE0)
    kw.setdefault('da', ga('2/1/2'))
    return ldata(tpdu, **kw)


def tdata(tpdu, mc=0x4A, ai=b''):
    return bytes([mc, len(ai)]) + ai + bytes(6) + bytes([len(tpdu) - 1]) + tpdu


def simple(ac, ad=0, data=b'', tpci=0x00):
    return bytes([tpci | (ac >> 2), ((ac & 3) << 6) | ad]) + data


def ext(ax, data=b'', tpci=0x00):
    return bytes([tpci | (ax >> 8), ax & 0xff]) + data


def rng(ne, sx):
    return struct.pack('>H', (ne << 12) | sx)


def mprop(mc, ot, oi, pid, ne=None, sx=None, data=b''):
    m = bytes([mc]) + struct.pack('>HBB', ot, oi, pid)
    if ne is not None:
        m += rng(ne, sx)
    return m + data


def pidext(ot, oi, pid):
    return struct.pack('>H', ot) + bytes([oi >> 4, ((oi & 0xF) << 4) | (pid >> 8), pid & 0xff])


# KNX Data Security ---------------------------------------------------------

def aes(key, block):
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(block) + e.finalize()


def cbc_mac(key, a, p, b0):
    mac = aes(key, b0)
    data = struct.pack('>H', len(a)) + a + p
    data += bytes(-len(data) % 16)
    for i in range(0, len(data), 16):
        mac = aes(key, bytes(x ^ y for x, y in zip(data[i:i + 16], mac)))
    return mac


def datasec(key, scf, apdu, sa, da, ctrl2, seq, mc=0x29, ai=b'', tpci=0x00, bad_mac=False):
    """An L_Data frame with an A_DataSecurity APDU. apdu (TPCI, APCI and
    data of the embedded telegram) is authenticated (scf & 0x30 == 0) or
    authenticated and encrypted (0x10)."""
    seqb = seq.to_bytes(6, 'big')
    sab, dab = struct.pack('>H', sa), struct.pack('>H', da)
    tpci_apci = bytes([tpci | 0x03, 0xF1])
    p = apdu if scf & 0x30 == 0x10 else b''
    a = bytes([scf]) + (b'' if p else apdu)
    b0 = seqb + sab + dab + bytes([0, ctrl2 & 0x8F]) + tpci_apci + bytes([0, len(p)])
    mac = cbc_mac(key, a, p, b0)[:4]
    if bad_mac:
        mac = bytes([mac[0] ^ 0xFF]) + mac[1:]
    ctr0 = seqb + sab + dab + bytes([0, 0, 0, 0, 1, 0])
    s0 = aes(key, ctr0)
    out = apdu
    if p:
        ks = s0[4:]
        ctr = bytearray(ctr0)
        while len(ks) < len(apdu):
            ctr[15] += 1
            ks += aes(key, bytes(ctr))
        out = bytes(x ^ y for x, y in zip(apdu, ks))
    mac_enc = bytes(x ^ y for x, y in zip(mac, s0[:4]))
    return ldata(tpci_apci + bytes([scf]) + seqb + out + mac_enc, mc=mc, ai=ai, ctrl2=ctrl2,
                 sa=sa, da=da)


def datasec_sync(scf, seq, f2, f3, mac=b'', sa=ia('1.2.1'), da=ia('1.2.2')):
    return ldata(bytes([0x03, 0xF1, scf]) + seq + f2 + f3 + mac, sa=sa, da=da)


# ---------------------------------------------------------------------------

AI_ALL = (bytes([1, 2, 0x12, 0x34])                  # PL medium info
          + bytes([2, 7, 0x02, 1, 2, 3, 4, 5, 6])     # RF medium info
          + bytes([3, 1, 0x00])                       # busmonitor status
          + bytes([4, 2, 0x01, 0x00])                 # relative timestamp
          + bytes([5, 4, 0, 0, 0x10, 0])              # time delay until sending
          + bytes([6, 4, 0, 1, 0, 0])                 # extended relative timestamp
          + bytes([7, 2, 0x11, 0x22])                 # BiBat info
          + bytes([0xFE, 3, 0xAA, 0xBB, 0xCC]))       # unknown type


def main_frames():
    F = []

    def R(cemi):
        F.append(routing(cemi))
        return len(F)

    def C(cemi):
        F.append(config_req(cemi, len(F)))
        return len(F)

    marks = {}

    # --- Message codes and the link layer ---------------------------------
    marks['link'] = len(F) + 1
    R(lgroup(simple(2, 1)))                               # L_Data.ind GroupValueWrite $01
    R(lgroup(simple(2, 1), mc=0x11, ctrl1=0xB0))          # L_Data.req
    R(lgroup(simple(2, 1), mc=0x2E))                      # L_Data.con
    R(lgroup(simple(0), ai=AI_ALL))                       # every additional info type
    # Ctrl1: extended frame, repeat on error, system broadcast, ack
    # wanted, unconfirmed, every priority; Ctrl2: hop counts, extended
    # frame format
    for c1, c2 in ((0x03, 0x05), (0x34, 0xF0), (0xB8, 0x80), (0xB4, 0xD0)):
        R(lgroup(simple(0), ctrl1=c1, ctrl2=c2))
    R(bytes([0x2B, 0x03, 3, 1, 0x00]) + bytes.fromhex('bc11010a02e1008155'))
    R(bytes([0x2D, 0x04, 4, 2, 0x00, 0x10]) + bytes.fromhex('bc11010a02e1008155'))
    R(bytes([0x10, 0x00]) + bytes.fromhex('bc11010a02e1008155'))
    R(bytes([0x2F, 0x00]) + bytes.fromhex('bc11010a02e1008155'))
    R(bytes([0x2B, 0x00]))                                # L_Busmon.ind without data
    # L_PollData.req / .con (no NPDU: the rest is data)
    R(bytes([0x13, 0x00, 0xF0, 0x60]) + struct.pack('>HH', ia('1.1.10'), ia('1.1.30')) + b'\x03')
    R(bytes([0x25, 0x00, 0xF0, 0x60]) + struct.pack('>HH', ia('1.1.30'), ia('1.1.10'))
      + b'\x03\x01\x02\x03')
    # T_Data_Individual / T_Data_Connected
    R(tdata(simple(12), mc=0x4A))
    R(tdata(simple(13, 0, b'\x07\xb0'), mc=0x94))
    R(tdata(simple(8, 2, b'\x01\x00'), mc=0x41))
    R(tdata(simple(9, 2, b'\x01\x00\xaa\xbb'), mc=0x89))

    # --- Transport layer --------------------------------------------------
    marks['tl'] = len(F) + 1
    R(ldata(b'\x80'))                                     # T_Connect
    R(ldata(b'\x81'))                                     # T_Disconnect
    R(ldata(b'\xC6'))                                     # T_ACK seq 1
    R(ldata(b'\xCB'))                                     # T_NAK seq 2
    R(ldata(simple(8, 4, b'\x01\x00', tpci=0x4C)))        # numbered data seq 3

    # --- Simple application services -------------------------------------
    marks['al'] = len(F) + 1
    R(lgroup(simple(0)))                                  # GroupValueRead
    R(lgroup(simple(1, 0x15)))                            # GroupValueResp $15
    R(lgroup(simple(1, 0, b'\x0c\x1a')))                  # GroupValueResp with data octets
    R(lgroup(simple(2, 0, b'\x41\x20\x00\x00')))          # GroupValueWrite with data octets
    R(lgroup(simple(3, 0, struct.pack('>H', ia('1.1.40'))), da=0))   # IndAddrWrite
    R(lgroup(simple(4), da=0))                            # IndAddrRead
    R(lgroup(simple(5), da=0))                            # IndAddrResp
    R(ldata(simple(6, 1, b'\x08', tpci=0x40)))            # AdcRead #1 N=8
    R(ldata(simple(6, 2, b'\x01', tpci=0x44)))            # AdcRead #2 N=1
    R(ldata(simple(7, 1, b'\x08\x01\x23', tpci=0x48)))    # AdcResp
    R(ldata(simple(8, 1, b'\x01\x00', tpci=0x4C)))        # MemRead 1 byte
    R(ldata(simple(9, 3, b'\x01\x00\xaa\xbb\xcc', tpci=0x40)))  # MemResp 3 bytes
    R(ldata(simple(10, 2, b'\x01\x10\x11\x22', tpci=0x44)))     # MemWrite
    R(ldata(simple(11, 3, b'\x01\x02')))                  # UserMsg #3
    R(ldata(simple(12, 0, tpci=0x48)))                    # DevDescrRead #0
    R(ldata(simple(12, 2, tpci=0x4C)))                    # DevDescrRead #2
    R(ldata(simple(13, 0, b'\x07\xb0', tpci=0x40)))       # DevDescrResp #0
    R(ldata(simple(13, 2, b'\x01\x02\x03', tpci=0x44)))   # DevDescrResp #2
    R(ldata(simple(14, 2)))                               # Restart (6 bit data 2)
    R(ldata(simple(15, 4, b'\x01')))                      # Escape #4

    # --- Extended application services -----------------------------------
    marks['ax'] = len(F) + 1
    P = lambda ax, data=b'', tpci=0x40: R(ldata(ext(ax, data, tpci)))
    # A_SystemNetworkParameter (broadcast to individual address 0.0.0)
    R(lgroup(ext(0x1C8, struct.pack('>HH', 0, 51 << 4) + b'\x01'), ctrl1=0xA0, da=0))
    R(lgroup(ext(0x1C9, struct.pack('>HH', 11, 52 << 4) + b'\x01\x02'), ctrl1=0xA0, da=0))
    R(lgroup(ext(0x1CA, struct.pack('>HH', 2, 300 << 4) + b'\x01'), ctrl1=0xA0, da=0))
    # A_PropertyExtValue / A_PropertyExtDescription / A_FunctionPropertyExt
    P(0x1CC, pidext(17, 1, 51) + b'\x01\x00\x01')
    P(0x1CD, pidext(17, 1, 51) + b'\x02\x00\x05' + b'\x01\x02\x03\x04')
    P(0x1CE, pidext(9, 2, 52) + b'\x01\x00\x01' + b'\xAA')
    P(0x1CF, pidext(9, 2, 52) + b'\x01\x00\x01' + b'\x00')
    P(0x1D0, pidext(0, 1, 1) + b'\x01\x00\x01' + b'\x55')
    P(0x1D2, pidext(0, 1, 1) + b'\x00\x00')
    P(0x1D3, pidext(0, 1, 1) + b'\x00\x00' + struct.pack('>HH', 7, 1) + b'\x84\x00\x05\x32')
    P(0x1D3, pidext(2, 1, 900) + b'\x10\x03' + struct.pack('>HH', 0, 0) + b'\x25\x00\x01\x30')
    P(0x1D4, pidext(6, 1, 51) + b'\x00\x01')
    P(0x1D5, pidext(7, 1, 51))
    P(0x1D6, pidext(8, 1, 51) + b'\x00\x01\x02')
    # A_MemoryExt
    P(0x1FB, b'\x02\x01\x00\x00\xAA\xBB')
    P(0x1FC, b'\x00\x01\x00\x00')
    P(0x1FC, b'\xF1\x01\x00\x00')
    P(0x1FD, b'\x01\x01\x00\x00')
    P(0x1FE, b'\x00\x01\x00\x00\xAA')
    # A_UserMemory, A_UserManufacturerInfo
    P(0x2C0, b'\x11\x00\x10')
    P(0x2C1, b'\x02\x00\x10\x01\x02')
    P(0x2C2, b'\x01\x00\x10\x01')
    P(0x2C4, b'\x01\x00\x10\x01\x01')
    P(0x2C5)
    P(0x2C6, b'\x00\x01\x02')
    # A_FunctionProperty
    P(0x2C7, b'\x01\x33\x00\x01')
    P(0x2C8, b'\x01\x02')
    P(0x2C9, b'\x01\x33\x00\x01')
    # A_Restart
    P(0x380, tpci=0x00)
    P(0x381, b'\x01\x00', tpci=0x00)
    P(0x3A1, b'\x00\x00\x00', tpci=0x00)
    # A_Router (obsolete), A_MemoryBit
    P(0x3C0)
    P(0x3C1, b'\x01\x01\x00')
    P(0x3C2, b'\x02\x01\x00\xAA\xBB')
    P(0x3C3, b'\x01\x01\x00\xAA')
    P(0x3C8, b'\x04\x02\x00')
    P(0x3C9, b'\x01\x02\x00\xAA')
    P(0x3CA, b'\x01\x02\x00\xAA')
    P(0x3CD)
    P(0x3CE, b'\x00')
    P(0x3CF, b'\x01')
    P(0x3D0, b'\x01\x02\x00\x01\x01')
    # A_Authorize, A_Key
    P(0x3D1, b'\x00\xFF\xFF\xFF\xFF')
    P(0x3D1, b'\x03\x11\x22\x33\x44')
    P(0x3D2, b'\x02')
    P(0x3D3, b'\x01\x11\x22\x33\x44')
    P(0x3D4, b'\x01')
    # A_PropertyValue (ranges: 1 at 1, 3 at 5; responses with 2 octets at
    # index 0, an error (0 elements), 2 elements, 1 element of 3 octets)
    P(0x3D5, b'\x00\x01' + rng(1, 1))
    P(0x3D5, b'\x01\x33' + rng(3, 5))
    P(0x3D6, b'\x00\x01' + rng(1, 0) + b'\x00\x02')
    P(0x3D6, b'\x00\x01' + rng(0, 1) + b'\x07')
    P(0x3D6, b'\x01\x33' + rng(2, 1) + b'\x01\x02\x03\x04')
    P(0x3D6, b'\x01\x33' + rng(1, 1) + b'\x01\x02\x03')
    P(0x3D7, b'\x01\x33' + rng(1, 1) + b'\x01')
    # A_PropertyDescription (by PID, by index, responses)
    P(0x3D8, b'\x00\x01\x00')
    P(0x3D8, b'\x00\x00\x02')
    P(0x3D9, b'\x00\x01\x00' + b'\x04\x00\x01\x30')
    P(0x3D9, b'\x00\x33\x05' + b'\xBE\x00\x0A\x33')
    # A_NetworkParameter, A_GroupPropValue (OT specific PID names)
    R(lgroup(ext(0x3DA, struct.pack('>H', 1) + b'\x33' + b'\x01'), ctrl1=0xA0, da=0))
    R(lgroup(ext(0x3DB, struct.pack('>H', 6) + b'\x33' + b'\x01\x02'), ctrl1=0xA0, da=0))
    R(lgroup(ext(0x3E4, struct.pack('>H', 11) + b'\x33' + b'\x05')))
    R(lgroup(ext(0x3E8, struct.pack('>H', 7) + b'\x33')))
    R(lgroup(ext(0x3E9, struct.pack('>H', 8) + b'\x33' + b'\x01')))
    R(lgroup(ext(0x3EA, struct.pack('>H', 9) + b'\x33' + b'\x01')))
    R(lgroup(ext(0x3EB, struct.pack('>H', 17) + b'\x33' + b'\x01')))
    R(lgroup(ext(0x3EB, struct.pack('>H', 0) + b'\xC8' + b'\x01')))
    R(lgroup(ext(0x3EB, struct.pack('>H', 3) + b'\x33' + b'\x01')))
    # A_IndividualAddressSerialNumber, A_DomainAddressSerialNumber
    SN = bytes.fromhex('00fa12345678')
    R(lgroup(ext(0x3DC, SN), ctrl1=0xA0, da=0))
    R(lgroup(ext(0x3DD, SN + struct.pack('>H', 0x0000) + b'\x00\x00'), ctrl1=0xA0, da=0))
    R(lgroup(ext(0x3DE, SN + struct.pack('>H', ia('1.1.50')) + b'\x00\x00\x00\x00'),
             ctrl1=0xA0, da=0))
    R(lgroup(ext(0x3EC, SN), ctrl1=0xA0, da=0))
    R(lgroup(ext(0x3ED, SN + b'\x00\x01'), ctrl1=0xA0, da=0))
    R(lgroup(ext(0x3EE, SN + b'\x00\x01'), ctrl1=0xA0, da=0))
    # Services without parameters dissected (data only)
    R(lgroup(ext(0x3E0, b'\x00\x01'), ctrl1=0xA0, da=0))   # DomAddrWrite
    R(lgroup(ext(0x3E1), ctrl1=0xA0, da=0))                # DomAddrRead
    R(lgroup(ext(0x3E2, b'\x00\x01'), ctrl1=0xA0, da=0))   # DomAddrResp
    R(lgroup(ext(0x3E3, b'\x00\x01\x00\x01\x02'), ctrl1=0xA0, da=0))
    P(0x3E5, b'\x01\x00')
    P(0x3E6, b'\x01\x00\x0a\x02')
    P(0x3E7, b'\x01\x00\x0a\x02')
    P(0x3F0, b'\x00\x01')

    # --- Data Security (individually addressed, key 00..0F) --------------
    marks['ds'] = len(F) + 1
    A, B = ia('1.2.1'), ia('1.2.2')
    # The reproducers cemi_datasec_auth_valid.py with an
    # individual destination: authentication only (GroupValueWrite $01),
    # authentication and confidentiality ($00), authentication only with
    # 14 data octets
    R(datasec(KEY0, 0x00, b'\x00\x81', A, B, 0x60, 1))
    R(datasec(KEY0, 0x10, b'\x00\x80', A, B, 0x60, 1))
    R(datasec(KEY0, 0x00, b'\x00\x80' + bytes(range(1, 15)), A, B, 0x60, 1))
    # The reproducer cemi_datasec_auth_overread.py with an
    # individual destination: authentication only, 12, 120 and 240
    # octets that are not a valid MAC
    for n in (12, 120, 240):
        R(ldata(bytes([0x03, 0xF1, 0x00]) + bytes(6) + b'\x41' * n, sa=A, da=B))
    # Tool access, longer encrypted payloads (several counter blocks), a
    # PropExtValueWriteCon inside, system broadcast SCF
    R(datasec(KEY0, 0x90, ext(0x1CE, pidext(17, 1, 51) + b'\x01\x00\x01' + bytes(range(32)),
                                   tpci=0x40), A, B, 0x60, 2, tpci=0x40))
    R(datasec(KEY0, 0x80, ext(0x3D5, b'\x00\x01' + rng(1, 1), tpci=0x44), A, B, 0x60, 3,
              tpci=0x44))
    R(datasec(KEY0, 0x18, simple(13, 0, b'\x07\xb0'), A, B, 0x60, 4))
    R(datasec(KEY0, 0x10, simple(1, 0, b'\x01\x02'), A, B, 0x60, 5, ai=bytes([3, 1, 0])))
    # Wrong MAC, reserved security mode (SCF 0x20), data under the tool key
    # of keyring device 1.1.1 (dest IA) and from keyring device 1.1.2
    # (source IA, sequence number above the keyring's 34567)
    R(datasec(KEY0, 0x10, b'\x00\x81', A, B, 0x60, 6, bad_mac=True))
    R(ldata(bytes([0x03, 0xF1, 0x20]) + bytes(6) + b'\x00\x81\x01\x02\x03\x04', sa=A, da=B))
    R(datasec(KEY_TOOL, 0x10, simple(12, 0), ia('1.2.3'), ia('1.1.1'), 0x60, 7))
    R(datasec(KEY_TOOL, 0x10, simple(13, 0, b'\x07\xb0'), ia('1.1.2'), ia('1.2.9'), 0x60, 40000))
    # Sync request (with MAC) and sync responses (with and without MAC)
    R(datasec_sync(0x12, bytes(6), bytes.fromhex('00fa12345678'), bytes(range(6)), b'\x11\x22\x33\x44'))
    R(datasec_sync(0x13, bytes(range(6)), (100).to_bytes(6, 'big'), (200).to_bytes(6, 'big'),
                   b'\x11\x22\x33\x44', sa=B, da=A))
    R(datasec_sync(0x9b, bytes(range(6)), (100).to_bytes(6, 'big'), (200).to_bytes(6, 'big'),
                   sa=B, da=A))

    # --- Management (DEVICE_CONFIGURATION_REQUEST) -----------------------
    marks['mgmt'] = len(F) + 1
    C(mprop(0xFC, 0, 1, 56, 1, 1))                         # M_PropRead.req
    C(mprop(0xFB, 0, 1, 56, 1, 1, b'\x00\xFE'))            # M_PropRead.con
    C(mprop(0xFB, 0, 1, 56, 0, 1, b'\x07'))                # M_PropRead.con error
    C(mprop(0xFB, 11, 1, 51, 2, 1, b'\x01\x02\x03\x04'))   # 2 elements
    C(mprop(0xFB, 8, 2, 52, 1, 0, b'\x00\x05'))            # element count
    C(mprop(0xF6, 8, 1, 52, 1, 1, b'\x00'))                # M_PropWrite.req
    C(mprop(0xF5, 8, 1, 52, 1, 1))                         # M_PropWrite.con
    C(mprop(0xF5, 8, 1, 52, 1, 1, b'\x05'))                # M_PropWrite.con error
    C(mprop(0xF7, 1, 1, 51, 3, 2, b'\x01\x02\x03'))        # M_PropInfo.ind
    C(mprop(0xF7, 300, 1, 200, 1, 1, b'\x01'))             # unknown OT and PID
    C(mprop(0xF8, 17, 1, 51) + b'\x00\x01')                # M_FuncPropCmd.req
    C(mprop(0xF9, 17, 1, 52) + b'\x00')                    # M_FuncPropRead.req
    C(mprop(0xFA, 17, 1, 52) + b'\x00\x01\x02')            # M_FuncProp.con
    C(b'\xF1')                                             # M_Reset.req
    C(b'\xF0')                                             # M_Reset.ind
    return F, marks


def malformed_frames():
    F = []

    def R(cemi):
        F.append(routing(cemi))

    def C(cemi):
        F.append(config_req(cemi, len(F)))

    # cEMI framing errors
    R(b'')                                                 # no message code
    R(b'\x77\x00\x01')                                     # unknown message code
    R(b'\x29')                                             # no additional info length
    R(b'\x29\x10\x01\x02')                                 # additional info cut short
    R(b'\x29\x03\x01')                                     # info element without length
    R(b'\x29\x04\x01\x05\x00\x00')                         # info element cut short
    R(b'\x29\x02\x01\x00')                                 # info element of length 0
    R(b'\x29\x00')                                         # no Ctrl1
    R(b'\x29\x00\xBC')                                     # no Ctrl2
    R(b'\x29\x00\xBC\xE0\x11')                             # source cut short
    R(b'\x29\x00\xBC\xE0\x11\x01\x0A')                     # destination cut short
    R(b'\x29\x00\xBC\xE0\x11\x01\x0A\x02')                 # no NPDU length
    R(b'\x29\x00\xBC\xE0\x11\x01\x0A\x02\x05\x00\x80')     # NPDU length mismatch
    R(b'\x29\x00\xBC\xE0\x11\x01\x0A\x02\x00')             # no TPCI
    R(b'\x29\x00\xBC\xE0\x11\x01\x0A\x02\x00\x00')         # no APCI
    R(b'\x4A\x00\x00\x00\x00')                             # T_Data reserved cut short
    R(b'\x4A\x00\x00\x00\x00\x01\x00\x00\x01\x00\x80')     # T_Data reserved not zero
    R(tdata(b'\xC6'))                                      # T_Data with numbered control
    R(ldata(b'\x80\x00'))                                  # control packet with data
    R(ldata(b'\x04\x00'))                                  # sequence number, unnumbered
    # Application layer errors
    R(lgroup(simple(2, 1, b'\x01')))                       # 6 bit data and data octets
    R(lgroup(simple(0, 0, b'\x01')))                       # GroupValueRead with data
    R(ldata(simple(8, 1, b'\x01')))                        # MemRead address cut short
    R(ldata(simple(6, 1)))                                 # AdcRead without count
    for ax, data in ((0x1FD, b'\x01'), (0x2C0, b'\x01'), (0x3C1, b'\x01'),
                     (0x3D1, b''), (0x3D5, b''), (0x3D5, b'\x00'), (0x3D5, b'\x00\x01\x10'),
                     (0x3D5, b'\x00\x01' + rng(0, 1)), (0x3D5, b'\x00\x01' + rng(2, 0)),
                     (0x3D5, b'\x00\x01' + rng(1, 1) + b'\x01'),
                     (0x3D6, b'\x00\x01' + rng(0, 1) + b'\x01\x02'),
                     (0x3D6, b'\x00\x01' + rng(1, 0) + b'\x01'),
                     (0x3D6, b'\x00\x01' + rng(3, 1) + b'\x01\x02'),
                     (0x3D8, b'\x00\x01'), (0x3D9, b'\x00\x01\x00\x01'), (0x3DA, b'\x00'), (0x3DC, b'\x00\x01'),
                     (0x3DD, bytes(6)), (0x1C8, b'\x00'), (0x1C8, b'\x00\x00\x00'),
                     (0x1C8, b'\x00\x00\x03\x31'), (0x1CC, b'\x00\x00\x00'),
                     (0x1CC, pidext(0, 1, 1) + b'\x01'), (0x1D2, pidext(0, 1, 1)),
                     (0x1D2, pidext(0, 1, 1) + b'\x00'),
                     (0x1D3, pidext(0, 1, 1) + b'\x00\x00\x00'),
                     (0x1D3, pidext(0, 1, 1) + b'\x00\x00' + bytes(4) + b'\x00'),
                     (0x3F1, b'\x10' + bytes(6)),
                     (0x3F1, b'\x12' + bytes(12)),
                     (0x3F1, b'\x12' + bytes(18) + b'\x01\x02')):
        R(ldata(ext(ax, data, 0x40)))
    # Management errors
    C(b'\xFC\x00')                                         # object type cut short
    C(b'\xFC\x00\x00')                                     # no object instance
    C(b'\xFC\x00\x00\x01')                                 # no PID
    C(b'\xFC\x00\x00\x01\x01\x10')                         # range cut short
    C(mprop(0xFC, 0, 1, 56, 1, 1, b'\x00'))                # data in a read request
    C(mprop(0xF6, 0, 1, 56, 0, 1, b'\x00'))                # 0 elements in a write
    C(mprop(0xF6, 0, 1, 56, 1, 0, b'\x00'))                # index 0 needs 2 octets
    C(mprop(0xF6, 0, 1, 56, 2, 0, b'\x00\x01'))            # 2 elements at index 0
    C(mprop(0xF6, 0, 1, 56, 3, 1, b'\x00\x01'))            # not a multiple of 3
    C(mprop(0xF5, 0, 1, 56, 1, 1, b'\x00\x01'))            # write con with 2 octets
    C(b'\xF1\x00')                                         # data after M_Reset.req
    # Group addressed Data Security: without a keyring the group address is
    # unknown (warning). The original reproducers
    # cemi_datasec_auth_valid.py (key 00..0F) and
    # cemi_datasec_auth_overread.py; telegrams to keyring group 1/7/131
    # from its sender 1.1.1 (key A0..AF, sequence number above 45678) and
    # from 1.1.2 (not a sender), and from keyring device 1.1.4 with a
    # sequence number below the keyring's 12345
    G = ga('2/1/2')
    R(datasec(KEY0, 0x00, b'\x00\x81', ia('1.1.1'), G, 0xE0, 1))
    R(datasec(KEY0, 0x10, b'\x00\x80', ia('1.1.1'), G, 0xE0, 1))
    R(datasec(KEY0, 0x00, b'\x00\x80' + bytes(range(1, 15)), ia('1.1.1'), G, 0xE0, 1))
    for n in (12, 120, 240):
        R(lgroup(bytes([0x03, 0xF1, 0x00]) + bytes(6) + b'\x41' * n, sa=ia('1.1.1'), da=G))
    R(datasec(KEY_GA, 0x10, simple(2, 1), ia('1.1.1'), ga('1/7/131'), 0xE0, 50000))
    R(datasec(KEY_GA, 0x10, simple(2, 1), ia('1.1.2'), ga('1/7/131'), 0xE0, 50000))
    R(datasec(KEY_TOOL, 0x10, simple(12, 0), ia('1.1.4'), ia('1.2.9'), 0x60, 100))
    # A Data Security telegram whose decrypted telegram is itself a Data
    # Security telegram, nested 3 deep
    inner = b'\x00\x81'
    for i in range(3):
        t = datasec(KEY0, 0x10, inner, ia('1.2.1'), ia('1.2.2'), 0x60, 10 + i)
        inner = t[9:]          # TPCI, APCI, SCF, SeqNr, payload, MAC
    R(t)
    return F


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, payload in enumerate(frames):
            fr = udp_frame(payload, i + 1)
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    frames, marks = main_frames()
    write_pcap(os.path.join(out, 'cemi-coverage.pcap'), frames)
    write_pcap(os.path.join(out, 'cemi-coverage-malformed.pcap'), malformed_frames())
    print('main: %d frames %s' % (len(frames), marks))


if __name__ == '__main__':
    main()
