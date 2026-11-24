#!/usr/bin/env python3
# Generates test/captures/gsmtap_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the synthetic GSMTAP coverage captures.

GSMTAP v2 over UDP port 4729 (registered by default), one frame for every
dispatch target of packet-gsmtap.c: Um channels (CCCH, RACH, LAPDm
channels with and without SACCH L1 header, PACCH and PDTCH RLC/MAC blocks of
every length, PTCCH, CBCH, voice), SIM, Abis, TETRA, WiMAX bursts, GB LLC
and SNDCP, GMR-1, UMTS RRC (every sub type), LTE RRC (every sub type), LTE
MAC framed, Qualcomm DIAG, LTE NAS, E1/T1 (every sub type), GSM RLP.
The payloads of the table ROWS were picked by trying candidate payloads
with tshark and keeping the first that decodes without a malformed packet
or expert info; the RLC/MAC blocks are pseudo-random bits behind a correct
MAC header (as in the CSN.1 capture).
Usage: mkgsmtap.py <output directory>
Writes gsmtap-coverage.pcapng (Ethernet and LINKTYPE_GSMTAP_UM interfaces) and
gsmtap-coverage-malformed.pcapng.
Everything is built with struct; nothing comes from a real network.
"""
import os
import random
import socket
import struct
import sys

UL = 0x4000
PCS = 0x8000

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def udp_frame(payload, sport=45123, dport=4729, src='192.0.2.1', dst='192.0.2.2'):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ps = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 17, len(udp))
    udp = udp[:6] + struct.pack('>H', csum(ps + udp) or 0xffff) + udp[8:]
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + udp

def write_pcapng(path, frames):
    """frames: list of (interface, bytes); interface 0 is Ethernet,
    interface 1 LINKTYPE_GSMTAP_UM (217, GSMTAP without UDP)."""
    def block(btype, body):
        body += b'\0' * ((-len(body)) % 4)
        total = 12 + len(body)
        return struct.pack('<II', btype, total) + body + struct.pack('<I', total)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', 1, 0, 65535))
    out += block(1, struct.pack('<HHI', 217, 0, 65535))
    t = 1700000000 * 1000000
    for i, (ifid, data) in enumerate(frames):
        ts = t + i * 1000
        out += block(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff,
                                    len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)

def gsmtap(type_, sub_type, payload, arfcn=17, ts=0, sub=0, fn=0, sig=-60, snr=20,
           ant=0, words=4, version=2, extra=b''):
    hdr = struct.pack('>BBBBHbBIBBBB', version, words, type_, ts, arfcn, sig, snr,
                      fn, sub_type, ant, sub, 0)
    return hdr + extra + payload

# (key, GSMTAP type, sub type, ARFCN field, payload)
ROWS = [
    ('um_bcch', 0x01, 0x01, 0x0011, '49061b000062f2100001c803042845006504002b2b2b2b'),
    ('um_ccch', 0x01, 0x02, 0x0011, '49061b000062f2100001c803042845006504002b2b2b2b'),
    ('um_agch', 0x01, 0x04, 0x0011, '49061b000062f2100001c803042845006504002b2b2b2b'),
    ('um_pch', 0x01, 0x05, 0x0011, '49061b000062f2100001c803042845006504002b2b2b2b'),
    ('um_rach', 0x01, 0x03, 0x4011, '00'),
    ('um_sdcch', 0x01, 0x06, 0x0011, '0103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_sdcch_ul', 0x01, 0x06, 0x4011, '0103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_sdcch_acch', 0x01, 0x86, 0x0011, '05010103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_sdcch_acch_ul', 0x01, 0x86, 0x4011, '05010103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_sdcch4', 0x01, 0x07, 0x0011, '0103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_sdcch4_ul', 0x01, 0x07, 0x4011, '0103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_sdcch4_acch', 0x01, 0x87, 0x0011, '05010103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_sdcch4_acch_ul', 0x01, 0x87, 0x4011, '05010103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_sdcch8', 0x01, 0x08, 0x0011, '0103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_sdcch8_ul', 0x01, 0x08, 0x4011, '0103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_sdcch8_acch', 0x01, 0x88, 0x0011, '05010103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_sdcch8_acch_ul', 0x01, 0x88, 0x4011, '05010103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_tchf', 0x01, 0x09, 0x0011, '0103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_tchf_ul', 0x01, 0x09, 0x4011, '0103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_tchf_acch', 0x01, 0x89, 0x0011, '05010103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_tchf_acch_ul', 0x01, 0x89, 0x4011, '05010103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_tchh', 0x01, 0x0a, 0x0011, '0103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_tchh_ul', 0x01, 0x0a, 0x4011, '0103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_tchh_acch', 0x01, 0x8a, 0x0011, '05010103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_tchh_acch_ul', 0x01, 0x8a, 0x4011, '05010103012b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_cbch52', 0x01, 0x0c, 0x0011, '2291d8cd'),
    ('um_cbch51', 0x01, 0x0f, 0x0011, '2291d8cd'),
    ('um_ptcch_ul', 0x01, 0x0e, 0x4011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_unknown', 0x01, 0x00, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_unknown2', 0x01, 0x12, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('um_bcch_acch', 0x01, 0x81, 0x0011, '010249061b000062f2100001c803042845006504002b2b2b2b'),
    ('voice_f_0', 0x01, 0x10, 0x0011, '000000000000000000000000000000'),
    ('voice_f_1', 0x01, 0x10, 0x0011, '010000000000000000000000000000'),
    ('voice_f_2', 0x01, 0x10, 0x0011, '020000000000000000000000000000'),
    ('voice_f_3', 0x01, 0x10, 0x0011, '030000000000000000000000000000'),
    ('voice_f_4', 0x01, 0x10, 0x0011, '040000000000000000000000000000'),
    ('voice_f_5', 0x01, 0x10, 0x0011, '050000000000000000000000000000'),
    ('voice_f_6', 0x01, 0x10, 0x0011, '060000000000000000000000000000'),
    ('voice_f_7', 0x01, 0x10, 0x0011, '070000000000000000000000000000'),
    ('voice_f_8', 0x01, 0x10, 0x0011, '080000000000000000000000000000'),
    ('voice_f_9', 0x01, 0x10, 0x0011, '090000000000000000000000000000'),
    ('voice_f_10', 0x01, 0x10, 0x0011, '0a0000000000000000000000000000'),
    ('voice_f_11', 0x01, 0x10, 0x0011, '0b0000000000000000000000000000'),
    ('voice_f_12', 0x01, 0x10, 0x0011, '0c0000000000000000000000000000'),
    ('voice_f_13', 0x01, 0x10, 0x0011, '0d0000000000000000000000000000'),
    ('voice_h_0', 0x01, 0x11, 0x0011, '000000000000000000000000000000'),
    ('burst', 0x03, 0x06, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('sim_0', 0x04, 0x00, 0x0000, 'a0a40000023f009000'),
    ('sim_1', 0x04, 0x01, 0x0000, '3b00'),
    ('sim_2', 0x04, 0x02, 0x0000, 'a0b0000004deadbeef9000'),
    ('sim_3', 0x04, 0x03, 0x0000, 'a0a40000023f009000'),
    ('sim_4', 0x04, 0x04, 0x0000, 'a0f2000016000000000000000000000000000000000000000000009000'),
    ('sim_5', 0x04, 0x05, 0x0000, 'a0c0000002abcd9000'),
    ('sim_6', 0x04, 0x06, 0x0000, 'a0b201040201029000'),
    ('sim_7', 0x04, 0x07, 0x0000, 'a0a40000023f009000'),
    ('sim_8', 0x04, 0x08, 0x0000, 'a0a40000026f079000'),
    ('abis', 0x02, 0x00, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('tetra_0', 0x05, 0x00, 0x0011, '00000000000000000000000000000000'),
    ('tetra_1', 0x05, 0x01, 0x0011, '00000000000000000000000000000000'),
    ('tetra_2', 0x05, 0x02, 0x0011, '00000000000000000000000000000000'),
    ('tetra_3', 0x05, 0x03, 0x0011, '00000000000000000000000000000000'),
    ('tetra_4', 0x05, 0x04, 0x0011, '00000000000000000000000000000000'),
    ('tetra_5', 0x05, 0x05, 0x0011, '00000000000000000000000000000000'),
    ('tetra_6', 0x05, 0x06, 0x0011, '00000000000000000000000000000000'),
    ('tetra_7', 0x05, 0x07, 0x0011, '00000000000000000000000000000000'),
    ('tetra_8', 0x05, 0x08, 0x0011, '00000000000000000000000000000000'),
    ('tetra_9', 0x05, 0x09, 0x0011, '00000000000000000000000000000000'),
    ('tetra_burst', 0x06, 0x01, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('wimax_10', 0x07, 0x10, 0x0011, '0000000000000000'),
    ('wimax_11', 0x07, 0x11, 0x0011, '0000000000000000'),
    ('wimax_12', 0x07, 0x12, 0x0011, '0000000000000000'),
    ('wimax_13', 0x07, 0x13, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('wimax_14', 0x07, 0x14, 0x0011, '0000000000000000'),
    ('wimax_15', 0x07, 0x15, 0x0011, '0000000000000000'),
    ('wimax_16', 0x07, 0x16, 0x0011, '0000000000000000'),
    ('wimax_0', 0x07, 0x00, 0x0011, '0000000000000000'),
    ('llc', 0x08, 0x00, 0x0011, 'c001'),
    ('sndcp', 0x09, 0x00, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_0', 0x0a, 0x00, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_1', 0x0a, 0x01, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_2', 0x0a, 0x02, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_3', 0x0a, 0x03, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_4', 0x0a, 0x04, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_5', 0x0a, 0x05, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_6', 0x0a, 0x06, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_7', 0x0a, 0x07, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_8', 0x0a, 0x08, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_9', 0x0a, 0x09, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_a', 0x0a, 0x0a, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_10', 0x0a, 0x10, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_12', 0x0a, 0x12, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_13', 0x0a, 0x13, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_14', 0x0a, 0x14, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_15', 0x0a, 0x15, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_16', 0x0a, 0x16, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_18', 0x0a, 0x18, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_1a', 0x0a, 0x1a, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('gmr1_1b', 0x0a, 0x1b, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('umts_rlc', 0x0b, 0x00, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('rrc_0', 0x0c, 0x00, 0x0011, '00000000000000000000000000000000'),
    ('rrc_1', 0x0c, 0x01, 0x0011, '00000000000000000000000000000000'),
    ('rrc_2', 0x0c, 0x02, 0x0011, '00000000000000000000000000000000'),
    ('rrc_3', 0x0c, 0x03, 0x0011, '00000000000000000000000000000000'),
    ('rrc_4', 0x0c, 0x04, 0x0011, '00000000000000000000000000000000'),
    ('rrc_5', 0x0c, 0x05, 0x0011, '00000000000000000000000000000000'),
    ('rrc_6', 0x0c, 0x06, 0x0011, '00000000000000000000000000000000'),
    ('rrc_7', 0x0c, 0x07, 0x0011, '00000000000000000000000000000000'),
    ('rrc_8', 0x0c, 0x08, 0x0011, '00000000000000000000000000000000'),
    ('rrc_9', 0x0c, 0x09, 0x0011, '00000000000000000000000000000000'),
    ('rrc_10', 0x0c, 0x0a, 0x0011, '00000000000000000000000000000000'),
    ('rrc_11', 0x0c, 0x0b, 0x0011, '0000000000000000000000000000000000000000000000000000000000000000'),
    ('rrc_12', 0x0c, 0x0c, 0x0011, '00000000000000000000000000000000'),
    ('rrc_13', 0x0c, 0x0d, 0x0011, '00000000000000000000000000000000'),
    ('rrc_14', 0x0c, 0x0e, 0x0011, '00000000000000000000000000000000'),
    ('rrc_15', 0x0c, 0x0f, 0x0011, '00000000000000000000000000000000'),
    ('rrc_16', 0x0c, 0x10, 0x0011, '00000000000000000000000000000000'),
    ('rrc_18', 0x0c, 0x12, 0x0011, '00000000000000000000000000000000'),
    ('rrc_19', 0x0c, 0x13, 0x0011, '00000000000000000000000000000000'),
    ('rrc_20', 0x0c, 0x14, 0x0011, '00000000000000000000000000000000'),
    ('rrc_21', 0x0c, 0x15, 0x0011, '00000000000000000000000000000000'),
    ('rrc_22', 0x0c, 0x16, 0x0011, '00000000000000000000000000000000'),
    ('rrc_23', 0x0c, 0x17, 0x0011, '00000000000000000000000000000000'),
    ('rrc_24', 0x0c, 0x18, 0x0011, '00000000000000000000000000000000'),
    ('rrc_25', 0x0c, 0x19, 0x0011, '0000000000000000000000000000000000000000000000000000000000000000'),
    ('rrc_26', 0x0c, 0x1a, 0x0011, '00000000000000000000000000000000'),
    ('rrc_27', 0x0c, 0x1b, 0x0011, '00000000000000000000000000000000'),
    ('rrc_28', 0x0c, 0x1c, 0x0011, '00000000000000000000000000000000'),
    ('rrc_29', 0x0c, 0x1d, 0x0011, '00000000000000000000000000000000'),
    ('rrc_30', 0x0c, 0x1e, 0x0011, '00000000000000000000000000000000'),
    ('rrc_31', 0x0c, 0x1f, 0x0011, '047303c1'),
    ('rrc_32', 0x0c, 0x20, 0x0011, '00000000000000000000000000000000'),
    ('rrc_33', 0x0c, 0x21, 0x0011, '00000000000000000000000000000000'),
    ('rrc_34', 0x0c, 0x22, 0x0011, '00000000000000000000000000000000'),
    ('rrc_35', 0x0c, 0x23, 0x0011, '00000000000000000000000000000000'),
    ('rrc_36', 0x0c, 0x24, 0x0011, '00000000000000000000000000000000'),
    ('rrc_37', 0x0c, 0x25, 0x0011, '0000000000000000000000000000000000000000000000000000000000000000'),
    ('rrc_38', 0x0c, 0x26, 0x0011, '00000000000000000000000000000000'),
    ('rrc_39', 0x0c, 0x27, 0x0011, '00000000000000000000000000000000'),
    ('rrc_40', 0x0c, 0x28, 0x0011, '00000000000000000000000000000000'),
    ('rrc_42', 0x0c, 0x2a, 0x0011, '00000000000000000000000000000000'),
    ('rrc_43', 0x0c, 0x2b, 0x0011, '00000000000000000000000000000000'),
    ('rrc_44', 0x0c, 0x2c, 0x0011, '00000000000000000000000000000000'),
    ('rrc_45', 0x0c, 0x2d, 0x0011, '00000000000000000000000000000000'),
    ('rrc_46', 0x0c, 0x2e, 0x0011, '00000000000000000000000000000000'),
    ('rrc_47', 0x0c, 0x2f, 0x0011, '00000000000000000000000000000000'),
    ('rrc_48', 0x0c, 0x30, 0x0011, '00000000000000000000000000000000'),
    ('rrc_49', 0x0c, 0x31, 0x0011, '00000000000000000000000000000000'),
    ('rrc_50', 0x0c, 0x32, 0x0011, '00000000000000000000000000000000'),
    ('rrc_51', 0x0c, 0x33, 0x0011, '0000000000000000000000000000000000000000000000000000000000000000'),
    ('rrc_52', 0x0c, 0x34, 0x0011, '00000000000000000000000000000000'),
    ('rrc_53', 0x0c, 0x35, 0x0011, '00000000000000000000000000000000'),
    ('rrc_54', 0x0c, 0x36, 0x0011, '00000000000000000000000000000000'),
    ('rrc_55', 0x0c, 0x37, 0x0011, '00000000000000000000000000000000'),
    ('rrc_56', 0x0c, 0x38, 0x0011, '00000000000000000000000000000000'),
    ('rrc_57', 0x0c, 0x39, 0x0011, '00000000000000000000000000000000'),
    ('rrc_58', 0x0c, 0x3a, 0x0011, '00000000000000000000000000000000'),
    ('rrc_59', 0x0c, 0x3b, 0x0011, '00000000000000000000000000000000'),
    ('rrc_60', 0x0c, 0x3c, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('rrc_61', 0x0c, 0x3d, 0x0011, '00000000000000000000000000000000'),
    ('rrc_62', 0x0c, 0x3e, 0x0011, '00000000000000000000000000000000'),
    ('rrc_63', 0x0c, 0x3f, 0x0011, '00000000000000000000000000000000'),
    ('rrc_64', 0x0c, 0x40, 0x0011, '00000000000000000000000000000000'),
    ('rrc_65', 0x0c, 0x41, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_0', 0x0d, 0x00, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_1', 0x0d, 0x01, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_2', 0x0d, 0x02, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_3', 0x0d, 0x03, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_4', 0x0d, 0x04, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_5', 0x0d, 0x05, 0x0011, '0000000000000000000000000000000000000000000000000000000000000000'),
    ('lterrc_6', 0x0d, 0x06, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_7', 0x0d, 0x07, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_8', 0x0d, 0x08, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_9', 0x0d, 0x09, 0x0011, '0000000000000000000000000000000000000000000000000000000000000000'),
    ('lterrc_10', 0x0d, 0x0a, 0x0011, '0000000000000000000000000000000000000000000000000000000000000000'),
    ('lterrc_11', 0x0d, 0x0b, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_12', 0x0d, 0x0c, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_13', 0x0d, 0x0d, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_14', 0x0d, 0x0e, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_15', 0x0d, 0x0f, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('lterrc_16', 0x0d, 0x10, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_17', 0x0d, 0x11, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_18', 0x0d, 0x12, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_19', 0x0d, 0x13, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_20', 0x0d, 0x14, 0x0011, '0000000000000000000000000000000000000000000000000000000000000000'),
    ('lterrc_21', 0x0d, 0x15, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_22', 0x0d, 0x16, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_23', 0x0d, 0x17, 0x0011, '00000000000000000000000000000000'),
    ('lterrc_24', 0x0d, 0x18, 0x0011, '00000000000000000000000000000000'),
    ('ltemac', 0x0e, 0x00, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('ltemacf', 0x0f, 0x00, 0x0011, '010003020001011f'),
    ('qcdiag', 0x11, 0x00, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('ltenas_1b', 0x12, 0x01, 0x0011, '170000000001075e'),
    ('ltenas_0', 0x12, 0x00, 0x0011, '5f1670a9821bc729'),
    ('ltenas_2', 0x12, 0x02, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('ltenas_3', 0x12, 0x03, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_0', 0x13, 0x00, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_0_ul', 0x13, 0x00, 0x4011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_1', 0x13, 0x01, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_1_ul', 0x13, 0x01, 0x4011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_2', 0x13, 0x02, 0x0011, '2291d8cd'),
    ('e1t1_2_ul', 0x13, 0x02, 0x4011, '2291d8cd'),
    ('e1t1_3', 0x13, 0x03, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_3_ul', 0x13, 0x03, 0x4011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_4', 0x13, 0x04, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_4_ul', 0x13, 0x04, 0x4011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_5', 0x13, 0x05, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_5_ul', 0x13, 0x05, 0x4011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_6', 0x13, 0x06, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_6_ul', 0x13, 0x06, 0x4011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_7', 0x13, 0x07, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_7_ul', 0x13, 0x07, 0x4011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_8', 0x13, 0x08, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_8_ul', 0x13, 0x08, 0x4011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_9', 0x13, 0x09, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_9_ul', 0x13, 0x09, 0x4011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_10', 0x13, 0x0a, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_10_ul', 0x13, 0x0a, 0x4011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_11', 0x13, 0x0b, 0x0011, '0000'),
    ('e1t1_11_ul', 0x13, 0x0b, 0x4011, '0000'),
    ('e1t1_12', 0x13, 0x0c, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_12_ul', 0x13, 0x0c, 0x4011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_13', 0x13, 0x0d, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('e1t1_13_ul', 0x13, 0x0d, 0x4011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
    ('rlp', 0x14, 0x00, 0x0011, 'f91f0a5874'),
    ('type_unknown', 0x30, 0x00, 0x0011, '2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b'),
]

PAYLOAD = dict((r[0], bytes.fromhex(r[4])) for r in ROWS)

# ---------------------------------------------------------------- RLC/MAC

class Bits:
    def __init__(self):
        self.s = ''
    def put(self, v, n):
        if n:
            self.s += format(v & ((1 << n) - 1), '0%db' % n)
        return self
    def putbits(self, s):
        self.s += s
        return self
    def __len__(self):
        return len(self.s)
    def bytes(self, total):
        s = self.s
        spare = ''.join(format(0x2b, '08b') for _ in range(total))
        s = s + spare[len(s):]
        return int(s, 2).to_bytes(total, 'big')

def rand_bits(rng, n, p):
    return ''.join('1' if rng.random() < p else '0' for _ in range(n))

def rlcmac_payload(kind, mt, seed, p, length):
    """Block of the given kind whose body is pseudo-random with probability
    p of a 1 bit behind a correct MAC header (see the CSN.1 capture)."""
    rng = random.Random('%s/%d/%d/%s/%d' % (kind, mt, seed, p, length))
    b = Bits()
    if kind == 'dl':
        b.put(1, 2).put(rng.randrange(4), 2).put(rng.randrange(2), 1).put(rng.randrange(8), 3)
        b.put(mt, 6)
    elif kind == 'ul':
        b.put(1, 2).put(0, 5).put(rng.randrange(2), 1).put(mt, 6)
    elif kind in ('dldata', 'uldata'):
        b.put(0, 2)
    elif kind == 'prach':
        b.putbits(['011111', '000', '111111001', '110111'][mt])
    b.putbits(rand_bits(rng, length * 8 - len(b), p))
    return b.bytes(length)

# (kind, message type, seed, probability, length)
RLCMAC = [
    ('dl', 1, 0, 0.1, 23), ('dl', 2, 4, 0.3, 23), ('dl', 10, 2, 0.2, 23),
    ('ul', 4, 1, 0.2, 64), ('ul', 1, 0, 0.5, 23), ('ul', 12, 1, 0.3, 23),
    ('dldata', 0, 0, 0.1, 23), ('dldata', 0, 1, 0.1, 34), ('dldata', 0, 1, 0.1, 40),
    ('dldata', 0, 0, 0.1, 54), ('dldata', 0, 0, 0.3, 10), ('uldata', 0, 3, 0.1, 23), ('uldata', 0, 1, 0.1, 34),
    ('uldata', 0, 0, 0.1, 40), ('uldata', 0, 0, 0.1, 54),
    ('egprs_dl', 0, 0, 0.5, 27), ('egprs_dl', 0, 3, 0.3, 33), ('egprs_dl', 0, 0, 0.1, 42),
    ('egprs_dl', 0, 0, 0.1, 49), ('egprs_dl', 0, 3, 0.1, 60), ('egprs_dl', 0, 7, 0.3, 61),
    ('egprs_dl', 0, 2, 0.1, 78), ('egprs_dl', 0, 1, 0.1, 79), ('egprs_dl', 0, 8, 0.5, 118),
    ('egprs_dl', 0, 9, 0.5, 119), ('egprs_dl', 0, 3, 0.3, 142), ('egprs_dl', 0, 1, 0.5, 143),
    ('egprs_dl', 0, 0, 0.1, 154), ('egprs_dl', 0, 2, 0.1, 155),
    ('egprs_ul', 0, 1, 0.3, 33), ('egprs_ul', 0, 0, 0.3, 42), ('egprs_ul', 0, 0, 0.1, 49),
    ('egprs_ul', 0, 0, 0.1, 61), ('egprs_ul', 0, 1, 0.1, 78), ('egprs_ul', 0, 0, 0.1, 79),
    ('egprs_ul', 0, 8, 0.5, 119), ('egprs_ul', 0, 0, 0.3, 142), ('egprs_ul', 0, 7, 0.3, 143),
    ('egprs_ul', 0, 0, 0.5, 154), ('egprs_ul', 0, 1, 0.1, 155),
    ('prach', 0, 0, 0.3, 2), ('prach', 1, 0, 0.3, 2), ('prach', 2, 0, 0.3, 2),
]

# ---------------------------------------------------------------- frames

SI3 = PAYLOAD['um_bcch']

def rlcmac_frames(base_fn):
    f = []
    for n, sel in enumerate(RLCMAC):
        kind = sel[0]
        pl = rlcmac_payload(*sel)
        if kind in ('dl', 'ul'):
            f.append(gsmtap(1, 0x0b, pl, arfcn=17 | (UL if kind == 'ul' else 0),
                            ts=n % 8, sub=n % 4, fn=base_fn + n))
        else:
            up = kind in ('uldata', 'egprs_ul', 'prach')
            f.append(gsmtap(1, 0x0d, pl, arfcn=17 | (UL if up else 0),
                            ts=n % 8, sub=n % 4, fn=base_fn + n))
    return [udp_frame(x) for x in f]

def main_frames():
    f = []
    i = 0
    for key, t, st, arfcn, pl in ROWS:
        i += 1
        # vary the radio fields and the PCS flag so that all of them are shown
        f.append(udp_frame(gsmtap(t, st, bytes.fromhex(pl), arfcn=arfcn | (PCS if i % 17 == 0 else 0),
                                  ts=i % 8, sub=i % 4, fn=1000 + i, sig=-110 + i % 90,
                                  snr=i % 40, ant=i % 3)))
    f += rlcmac_frames(5000)
    # PTCCH/D: 16 timing advance values and the padding
    f.append(udp_frame(gsmtap(1, 0x0e, bytes(range(0, 64, 4)) + b'\x2b' * 7, ts=7, fn=6000)))
    # a log record, handed to GSMTAP_LOG by the gsmtap.type table
    f.append(udp_frame(gsmtap(0x10, 0, b'\0' * 4 + struct.pack('>I', 5) + b'osmo-bts'.ljust(16, b'\0') +
                              struct.pack('>IB', 1, 3) + b'\0' * 3 + b'DL1C'.ljust(16, b'\0') +
                              b'l1.c'.ljust(32, b'\0') + struct.pack('>I', 9) + b'hello')))
    # reproducer of "GSMTAP: Reject too short header lengths": header length
    # octet 0x44 = 272 bytes, behind which the BCCH block follows (the
    # 8 bit variable wrapped to 16 before the fix and decoded filler as data)
    f.append(udp_frame(gsmtap(1, 1, SI3, words=0x44, extra=bytes(range(256)))))
    # a header of 20 octets with 4 extra octets
    f.append(udp_frame(gsmtap(1, 1, SI3, words=5, extra=b'\xde\xad\xbe\xef')))
    # unknown versions (warning)
    f.append(udp_frame(gsmtap(1, 1, SI3, version=1)))
    f.append(udp_frame(gsmtap(1, 1, SI3, version=3)))
    f = [(0, x) for x in f]
    # LINKTYPE_GSMTAP_UM (217): GSMTAP without Ethernet, IP and UDP
    f.append((1, gsmtap(1, 1, SI3)))
    f.append((1, gsmtap(1, 0x0d, rlcmac_payload('egprs_dl', 0, 3, 0.3, 33), fn=7000)))
    f.append((1, gsmtap(1, 0x06, PAYLOAD['um_sdcch'], arfcn=17 | UL, fn=7001)))
    return f

def malformed_frames():
    f = []
    # reproducer frames of the header length fix: 0x44 with a short frame,
    # 0 words, 1 word, 3 words (all below the 16 octet minimum except 0x44)
    for w in (0x44, 0x00, 0x01, 0x03):
        f.append(udp_frame(gsmtap(1, 1, SI3, words=w)))
    g = gsmtap(1, 1, SI3)
    for n in (1, 2, 3, 4, 6, 7, 8, 12, 13, 14, 15):
        f.append(udp_frame(g[:n]))
    # SACCH without the 2 octet L1 header, voice and PTCCH/D that are too short
    f.append(udp_frame(gsmtap(1, 0x86, b'\x05')))
    f.append(udp_frame(gsmtap(1, 0x10, b'')))
    f.append(udp_frame(gsmtap(1, 0x0e, b'\x00' * 10)))
    f.append(udp_frame(gsmtap(1, 0x0e, b'')))
    f.append(udp_frame(gsmtap(5, 5, b'')))
    f.append(udp_frame(gsmtap(4, 0, b'\xa0\xa4')))
    f.append(udp_frame(gsmtap(0x13, 1, b'\x01')))
    return [(0, x) for x in f]

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcapng(os.path.join(out, 'gsmtap-coverage.pcapng'), main_frames())
    write_pcapng(os.path.join(out, 'gsmtap-coverage-malformed.pcapng'), malformed_frames())

main()
