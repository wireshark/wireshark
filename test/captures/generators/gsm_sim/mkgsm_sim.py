#!/usr/bin/env python3
# Generates test/captures/gsm_sim_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-gsm_sim.c (GSM SIM / UICC APDUs, ISO 7816-4,
TS 51.011 and TS 102 221).
Usage: mkgsm_sim.py <outdir> [-v]

The capture is pcapng with two interfaces:
  0: Ethernet; GSMTAP (UDP 4729) type SIM, sub-type APDU: "SIMtrace" style
     frames that hold the command followed by the response and status word
     (dissector "gsm_sim");
  1: Exported PDU (linktype 252) naming "gsm_sim.command" and
     "gsm_sim.response": command and response APDUs in separate frames, as
     other dissectors (MBIM, BT SAP) hand them over.
Authentication (INS 0x88, RUN GSM ALGORITHM / AUTHENTICATE) and the CHV
(PIN/PUK) commands with codes are left out on purpose; see the README."""
import struct
import sys
import socket

def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def pcapng(path, idbs, frames):
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in idbs:
        out += _blk(1, struct.pack('<HHI', lt, 0, 65535))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(path, 'wb').write(out)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def eth_udp(payload, sport=4729, dport=4729):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0,
                    socket.inet_aton('192.0.2.1'), socket.inet_aton('192.0.2.2'))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + h + u

def gsmtap_sim(payload, sub=0):
    # GSMTAP type 4 (SIM); sub-type 0 = APDU, 1 = ATR
    hdr = struct.pack('>BBBBHbbIBBBB', 2, 4, 4, 0, 0, 0, 0, 0, sub, 0, 0, 0)
    return hdr + payload

def exported_pdu(dissector, payload):
    name = dissector.encode()
    name += b'\0' * ((-len(name)) % 4)
    return struct.pack('>HH', 12, len(name)) + name + struct.pack('>HH', 0, 0) + payload

# ----- APDU helpers
def cmd(ins, p1=0, p2=0, data=None, le=None, cla=0xA0, ext=False):
    b = bytes([cla, ins, p1, p2])
    if ext:
        if data:
            b += b'\0' + struct.pack('>H', len(data)) + data
            if le is not None:
                b += struct.pack('>H', le)
        elif le is not None:
            b += b'\0' + struct.pack('>H', le)
        return b
    if data:
        b += bytes([len(data)]) + data
        if le is not None:
            b += bytes([le])
    elif le is not None:
        b += bytes([le])
    return b

def sw(v): return struct.pack('>H', v)

# ----- TLV helpers
def tlv(tag, val):
    t = tag if isinstance(tag, bytes) else bytes([tag])
    n = len(val)
    l = bytes([n]) if n < 0x80 else (bytes([0x81, n]) if n < 0x100 else bytes([0x82]) + struct.pack('>H', n))
    return t + l + val

def fcp(*items, tag=0x62):
    return tlv(tag, b''.join(items))

def prop(*items):
    return tlv(0xA5, b''.join(items))

def disp_text(text=b'\x04Hi'):
    return tlv(0xD0, tlv(0x81, b'\x01\x21\x80') + tlv(0x82, b'\x81\x02') + tlv(0x8D, text))

def event_download():
    return tlv(0xD6, tlv(0x99, b'\x05') + tlv(0x82, b'\x82\x81'))

def timer_expiration(form):
    inner = tlv(0x82, b'\x82\x81') + tlv(0xA4, b'\x01') + tlv(0xA5, b'\x00\x00\x01')
    return bytes([0xD7, 0x80 + form]) + len(inner).to_bytes(form, 'big') + inner

def main():
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    frames, notes = [], []
    bad, badnotes = [], []

    def add(kind, note, payload, to_bad=False):
        if kind == 'tap':          # SIMtrace style: command + response in one frame
            fr = (0, eth_udp(gsmtap_sim(payload)))
        elif kind == 'cmd':
            fr = (1, exported_pdu('gsm_sim.command', payload))
        elif kind == 'rsp':
            fr = (1, exported_pdu('gsm_sim.response', payload))
        elif kind == 'tlv':
            fr = (1, exported_pdu('gsm_sim.bertlv', payload))
        elif kind == 'atr':
            fr = (0, eth_udp(gsmtap_sim(payload, 1)))
        if to_bad:
            bad.append(fr); badnotes.append((len(bad), note))
        else:
            frames.append(fr); notes.append((len(frames), note))

    sections = []
    # ================= A: SIMtrace style frames over GSMTAP =================
    sections.append(('GSMTAP SIM frames (command + response in one frame)', 1))
    def tap(note, c, resp=b'', status=0x9000):
        if len(c) == 4:
            c += b'\x00'      # a TPDU header always has P3
        add('tap', note, c + resp + sw(status))

    # SELECT variants (P3 = Lc, data, then the response)
    tap('SELECT MF by file id', cmd(0xA4, 0, 0, b'\x3f\x00'), b'', 0x9f16)
    tap('SELECT DF.GSM by file id', cmd(0xA4, 0, 0, b'\x7f\x20'), b'', 0x9f16)
    tap('SELECT EF by file id', cmd(0xA4, 0, 4, b'\x6f\x07'), b'', 0x9000)
    tap('SELECT unknown file id', cmd(0xA4, 0, 0, b'\x12\x34'), b'', 0x9404)
    tap('SELECT parent DF', cmd(0xA4, 3, 0, b'', None), b'', 0x9000)
    tap('SELECT parent DF with data', cmd(0xA4, 3, 0, b'\x00\x00'), b'', 0x9000)
    tap('SELECT by AID', cmd(0xA4, 4, 0, bytes.fromhex('a0000000871002')), b'', 0x9000)
    tap('SELECT by AID, session control termination', cmd(0xA4, 4, 0x40, bytes.fromhex('a0000000871002')), b'', 0x9000)
    tap('SELECT by absolute path', cmd(0xA4, 8, 4, b'\x3f\x00\x7f\x20\x6f\x07'), b'', 0x9000)
    tap('SELECT by relative path', cmd(0xA4, 9, 4, b'\x7f\x10\x6f\x3a'), b'', 0x9000)
    tap('SELECT child DF', cmd(0xA4, 1, 0, b'\x7f\x20'), b'', 0x9000)
    tap('SELECT with P3 = 1', cmd(0xA4, 0, 0, b'\x3f'), b'', 0x6700)
    tap('SELECT with P3 = 0', cmd(0xA4, 0, 0, b''), b'', 0x6700)
    for p1, p2 in ((0, 0x0c), (0, 0x04), (4, 0x04), (4, 0x80)):
        tap('SELECT P1=%02x P2=%02x' % (p1, p2), cmd(0xA4, p1, p2, b'\x3f\x00' if p1 == 0 else b'\xa0\x00\x00'), b'', 0x9000)
    # STATUS
    tap('STATUS', cmd(0xF2, 0, 0, None, 0x16), b'', 0x9000)
    tap('STATUS, application initialized', cmd(0xF2, 1, 0, None, 0), b'', 0x9000)
    tap('STATUS, terminate application', cmd(0xF2, 2, 0x0c, None, 0), b'', 0x9000)
    tap('STATUS without Le', cmd(0xF2, 0, 0), b'', 0x9000)
    # READ / UPDATE BINARY
    tap('READ BINARY offset', cmd(0xB0, 0x01, 0x23, None, 4), bytes.fromhex('11223344'), 0x9000)
    tap('READ BINARY with SFI', cmd(0xB0, 0x87, 0x05, None, 9), bytes(9), 0x9000)
    tap('READ BINARY SFI 0x04 ', cmd(0xB0, 0x84, 0x00, None, 2), bytes(2), 0x9000)
    tap('UPDATE BINARY', cmd(0xD6, 0x00, 0x00, bytes.fromhex('aabbcc')), b'', 0x9000)
    tap('UPDATE BINARY with SFI', cmd(0xD6, 0x8b, 0x02, bytes.fromhex('0102')), b'', 0x9000)
    # READ / UPDATE RECORD
    for p2 in (0x02, 0x03, 0x04, 0x00):
        tap('READ RECORD mode %02x' % p2, cmd(0xB2, 1, p2, None, 5), bytes(range(5)), 0x9000)
    tap('UPDATE RECORD', cmd(0xDC, 2, 4, bytes(5)), b'', 0x9000)
    # SEARCH RECORD
    tap('SEARCH RECORD simple', cmd(0xA2, 1, 0x04, b'\xff\x00'), b'', 0x9000)
    tap('SEARCH RECORD record id', cmd(0xA2, 1, 0x00, b'\x01'), b'', 0x9000)
    tap('SEARCH RECORD enhanced, offset', cmd(0xA2, 1, 0x06, b'\x00\x01\x05\xaa'), b'', 0x9000)
    tap('SEARCH RECORD enhanced, value', cmd(0xA2, 1, 0x06, b'\x04\x01\x05\xaa'), b'', 0x9000)
    tap('SEARCH RECORD enhanced, first byte with bit 0x04', cmd(0xA2, 1, 0x0e, b'\x0c\x00\x01'), b'', 0x9000)
    # INCREASE, CHV queries (Lc 0: no codes), invalidate etc.
    tap('INCREASE', cmd(0x32, 0, 0, None, 3), b'', 0x9000)
    for ins in (0x20, 0x24, 0x26, 0x28, 0x2C):
        tap('CHV command %02x (no code)' % ins, cmd(ins, 0, 1, None), b'', 0x9804)
    for ins in (0x04, 0x44, 0xFA):
        tap('INS %02x (not parsed further)' % ins, cmd(ins, 0, 0, None), b'', 0x9000)
    # MANAGE CHANNEL
    tap('MANAGE CHANNEL open', cmd(0x70, 0x00, 0x00, None, 1), b'\x01', 0x9000)
    tap('MANAGE CHANNEL open channel 2', cmd(0x70, 0x00, 0x02, None, 0), b'', 0x9000)
    tap('MANAGE CHANNEL close', cmd(0x70, 0x80, 0x01), b'', 0x9000)
    tap('MANAGE CHANNEL unknown operation', cmd(0x70, 0x40, 0x03), b'', 0x6a86)
    # TERMINAL PROFILE, TERMINAL RESPONSE, TERMINAL CAPABILITY, ENVELOPE, FETCH
    tap('TERMINAL PROFILE, 3 bytes', cmd(0x10, 0, 0, bytes.fromhex('ffff03')), b'', 0x9000)
    tap('TERMINAL PROFILE, 39 bytes', cmd(0x10, 0, 0, bytes((i * 37 + 5) & 0xff for i in range(39))), b'', 0x9000)
    tap('TERMINAL PROFILE, 45 bytes', cmd(0x10, 0, 0, bytes((0xff - i) & 0xff for i in range(45))), b'', 0x9000)
    tap('TERMINAL PROFILE, 1 byte', cmd(0x10, 0, 0, b'\x00'), b'', 0x9000)
    tap('TERMINAL RESPONSE', cmd(0x14, 0, 0, bytes.fromhex('810301210082028281830100')), b'', 0x9000)
    tap('TERMINAL CAPABILITY', cmd(0xAA, 0, 0, tlv(0xA9, tlv(0x80, b'\x01\x32\x0a') + tlv(0x81, b'\x01') + tlv(0x82, b'\x01') + tlv(0x83, b'\x1f') + tlv(0x84, b'\x01') + tlv(0x85, b'\x01\x02') + tlv(0x80, b''))), b'', 0x9000)
    tap('TERMINAL CAPABILITY, wrong tag', cmd(0xAA, 0, 0, tlv(0xAB, b'\x01')), b'', 0x9000)
    tap('ENVELOPE event download', cmd(0xC2, 0, 0, event_download()), b'', 0x9000)
    tap('ENVELOPE timer expiration', cmd(0xC2, 0, 0, tlv(0xD7, tlv(0x82, b'\x82\x81') + tlv(0xA4, b'\x01') + tlv(0xA5, b'\x00\x00\x01'))), b'', 0x9000)
    tap('ENVELOPE unknown tag', cmd(0xC2, 0, 0, bytes.fromhex('d3 07 02 02 01 81 90 01 01'.replace(' ', ''))), b'', 0x9000)
    tap('ENVELOPE, two TLVs', cmd(0xC2, 0, 0, event_download() + bytes.fromhex('d3 04 82 02 01 81'.replace(' ', ''))), b'', 0x9000)
    tap('FETCH proactive command', cmd(0x12, 0, 0, None, len(disp_text())), disp_text(), 0x9000)
    tap('FETCH with 0x91 status', cmd(0x12, 0, 0, None, 5), tlv(0xD0, tlv(0x81, b'\x01\x05\x00')), 0x9100 | 0x0f)
    tap('GET RESPONSE', cmd(0xC0, 0, 0, None, 0x16), bytes(0x16), 0x9000)
    tap('GET IDENTITY', cmd(0x78, 0, 0, None, 8), bytes(8), 0x9000)
    tap('GET DATA', cmd(0xCA, 0x00, 0x5c, None, 4), bytes(4), 0x9000)
    # SUSPEND UICC
    tap('SUSPEND UICC suspend', cmd(0x76, 0, 0, bytes([1, 2, 1, 10]), 0), bytes([1, 10]) + bytes(4), 0x9000)
    tap('SUSPEND UICC resume', cmd(0x76, 1, 0, bytes(range(1, 9))), b'', 0x9000)
    # STORE DATA
    tap('STORE DATA, last block', cmd(0xE2, 0x91, 0x00, bytes(range(10))), b'', 0x9000)
    tap('STORE DATA, more blocks', cmd(0xE2, 0x10, 0x01, bytes(range(10))), b'', 0x9000)
    tap('STORE DATA, last block 2', cmd(0xE2, 0x90, 0x02, bytes(range(5))), b'', 0x9000)
    # generic default path (INS not handled in dissect_gsm_apdu)
    for ins in (0xCB, 0xDB, 0x84, 0x73, 0x75, 0x7A, 0x7C, 0xE0, 0xE4, 0xE6, 0xE8, 0xFE, 0x55):
        tap('generic INS %02x' % ins, cmd(ins, 1, 2, None, 4), bytes(4), 0x9000)
    tap('generic INS with data', cmd(0xE0, 1, 2, bytes(6)), b'', 0x9000)
    # class bytes
    for cla in (0x00, 0x80, 0xA0, 0xC0, 0x40, 0x44, 0x60, 0x03, 0x4f, 0x7f, 0x83):
        tap('CLA %02x' % cla, cmd(0xF2, 0, 0, None, 0, cla=cla), b'', 0x9000)
    # status words
    for s in (0x9000, 0x9100, 0x911c, 0x9e10, 0x9f20, 0x9200, 0x920a, 0x9210, 0x6100, 0x6110, 0x6700, 0x6710, 0x6c10, 0x6c00, 0x6d00, 0x6e00, 0x6f00, 0x6985, 0x6a82, 0x6b00, 0x9804, 0x9808, 0x9840, 0x9400, 0x9404, 0x9408, 0x9802, 0x9810, 0x9000, 0x1234, 0x6283, 0x6300):
        tap('status word %04x' % s, cmd(0xB0, 0, 0, None, 0), b'', s)
    # response data on a command the dissector shows as generic data
    tap('READ BINARY with long response', cmd(0xB0, 0, 0, None, 0), bytes(range(256)), 0x9000)
    # reproducers of the BER length fix: FCP whose inner TLV uses the long
    # length form (82 81 02 ...) and the same with the short form
    tap('SELECT, FCP with an inner TLV in the long length form (reproducer)', bytes([0x00, 0xA4, 0x00, 0x04, 0x00]),
        bytes([0x62, 0x09, 0x82, 0x81, 0x02, 0x41, 0x21, 0x83, 0x02, 0x3F, 0x00]), 0x9000)
    tap('SELECT, the same with the short length form', bytes([0x00, 0xA4, 0x00, 0x04, 0x00]),
        bytes([0x62, 0x08, 0x82, 0x02, 0x41, 0x21, 0x83, 0x02, 0x3F, 0x00]), 0x9000)
    # GSMTAP ATR frame (the ATR dissector, not this one)
    add('atr', 'ATR', bytes.fromhex('3b9f96801fc78031a073be21136743200718000001a5'))
    sim_end_tap = len(frames)

    # ================= B: command and response in separate frames =================
    sections.append(('Exported PDU gsm_sim.command / gsm_sim.response', len(frames) + 1))
    def pair(note, c, r):
        add('cmd', note + ' (command)', c)
        add('rsp', note + ' (response)', r)
    # SELECT with FCP responses
    pair('SELECT MF', cmd(0xA4, 0, 4, b'\x3f\x00', 0x20),
         fcp(tlv(0x82, b'\x78\x21'), tlv(0x83, b'\x3f\x00'), tlv(0x84, b'\xa0\x00\x00\x00\x87'),
             prop(tlv(0x80, b'\x71'), tlv(0x81, b'\x03\x20\x0a'), tlv(0x82, b'\x04'), tlv(0x83, b'\x00\x01\x02'),
                  tlv(0x84, b'\x80'), tlv(0x85, b'\x00\x10'), tlv(0x86, b'\x00\x20'), tlv(0x87, b'\x01'),
                  tlv(0x88, b'\x44'), tlv(0x89, b'\x01\x02'), tlv(0x8a, b'\x03'), tlv(0x8b, b'\x04'),
                  tlv(0x80, b''), tlv(0x8c, b'\x01\x02\x03'), tlv(0x81, b'\xaa\xbb\xcc')),
             tlv(0x8a, b'\x05'), tlv(0x8b, b'\x6f\x06\x01'), tlv(0x8c, b'\x03\x01\x02'), tlv(0xab, b'\x01\x02'),
             tlv(0xc6, b'\x90\x01\x40'), tlv(0x88, b'\x01'), tlv(0x80, b'\x00\x20'), tlv(0x81, b'\x00\x40'), tlv(0x99, b'\x01\x02\x03'), tlv(0x8a, b''))
         + sw(0x9000))
    pair('SELECT EF with record structure', cmd(0xA4, 0, 4, b'\x6f\x3a', 0),
         fcp(tlv(0x82, b'\x02\x21\x00\x1c\x0a'), tlv(0x83, b'\x6f\x3a'), tlv(0x80, b'\x01\x18'), tlv(0x88, b'\x07'),
             tlv(0x8a, b'\x05'), prop(tlv(0x80, b'\x11'))) + sw(0x9000))
    pair('SELECT DF', cmd(0xA4, 0, 4, b'\x7f\x10', 0),
         fcp(tlv(0x82, b'\x38\x21'), tlv(0x83, b'\x7f\x10')) + sw(0x9000))
    pair('SELECT ADF (FCI tag 6f)', cmd(0xA4, 4, 4, bytes.fromhex('a000000087 1002'.replace(' ', '')), 0),
         fcp(tlv(0x82, b'\x78\x21'), tlv(0x84, bytes.fromhex('a0000000871002')), tag=0x6f) + sw(0x9000))
    pair('SELECT BER-TLV structure', cmd(0xA4, 0, 4, b'\x6f\x01', 0),
         fcp(tlv(0x82, b'\x39\x21\x00\x00\x00'), tlv(0x83, b'\x6f\x01')) + sw(0x9000))
    pair('SELECT file descriptor with RFU bit', cmd(0xA4, 0, 4, b'\x6f\x02', 0),
         fcp(tlv(0x82, b'\xc1'), tlv(0x82, b'\x41\x21'), tlv(0x82, b'\x01')) + sw(0x9000))
    pair('SELECT with unknown top tag (data)', cmd(0xA4, 0, 4, b'\x6f\x03', 0), bytes.fromhex('ab01cd') + sw(0x9000))
    pair('SELECT, FCP with the extended length forms',
         cmd(0xA4, 0, 4, b'\x6f\x04', 0),
         fcp(tlv(0x80, bytes(200)), tlv(b'\x9f\x01', b'\x01\x02'), tlv(0x83, b'\x6f\x04')) + sw(0x9000))
    pair('SELECT, FCP with SGP.22 ISD-R template (0xe0) and SGP.32 (0xe1)',
         cmd(0xA4, 4, 4, bytes.fromhex('a0000005591010ffffffff8900000100'), 0),
         fcp(tlv(0x84, bytes.fromhex('a0000005591010ffffffff8900000100')),
             tlv(0xe0, tlv(0x82, b'\x02\x02\x00') + tlv(0x03, b'\x06\x40')),
             tlv(0xe1, tlv(0x80, b'\x06\xc0'))) + sw(0x9000))
    pair('SELECT, FCP with an empty top level template', cmd(0xA4, 0, 4, b'\x6f\x05', 0), bytes.fromhex('6200') + sw(0x9000))
    pair('STATUS', cmd(0xF2, 0, 0, None, 0x20),
         fcp(tlv(0x82, b'\x78\x21'), tlv(0x84, b'\xa0\x00')) + sw(0x9000))
    # SW 61xx then GET RESPONSE: reassembly
    sel_fcp = fcp(tlv(0x82, b'\x78\x21'), tlv(0x83, b'\x3f\x00'), tlv(0x84, b'\xa0\x00\x00\x00\x87\x10\x02'), tlv(0x8a, b'\x05'))
    pair('SELECT answered with 61xx', cmd(0xA4, 0, 0, b'\x3f\x00'), sel_fcp[:10] + sw(0x6100 | (len(sel_fcp) - 10)))
    pair('GET RESPONSE completes the SELECT', cmd(0xC0, 0, 0, None, len(sel_fcp) - 10), sel_fcp[10:] + sw(0x9000))
    # three-part GET RESPONSE chain
    pair('SELECT answered with 61xx (3 parts)', cmd(0xA4, 0, 0, b'\x7f\x20'), sel_fcp[:8] + sw(0x6110))
    pair('GET RESPONSE 1', cmd(0xC0, 0, 0, None, 16), sel_fcp[8:16] + sw(0x6108))
    pair('GET RESPONSE 2', cmd(0xC0, 0, 0, None, 8), sel_fcp[16:] + sw(0x9000))
    pair('GET RESPONSE without a preceding command in the capture', cmd(0xC0, 0, 0, None, 4), bytes(4) + sw(0x9000))
    pair('response with 61xx and no further GET RESPONSE', cmd(0xB0, 0, 0, None, 0), bytes(4) + sw(0x6104))
    # reads, updates and so on in the non-SIMtrace form
    pair('READ BINARY', cmd(0xB0, 0, 0, None, 8), bytes(range(8)) + sw(0x9000))
    pair('READ BINARY extended length', cmd(0xB0, 0, 0, None, 300, ext=True), bytes(20) + sw(0x9000))
    pair('UPDATE BINARY', cmd(0xD6, 0, 2, bytes(6)), sw(0x9000))
    pair('UPDATE BINARY extended length', cmd(0xD6, 0x82, 2, bytes(300), ext=True), sw(0x9000))
    pair('READ RECORD', cmd(0xB2, 3, 4, None, 0x1c), bytes(0x1c) + sw(0x9000))
    pair('UPDATE RECORD', cmd(0xDC, 3, 4, bytes(8)), sw(0x9000))
    pair('SEARCH RECORD', cmd(0xA2, 1, 0x04, b'\xaa\xbb', 0), bytes([1, 2, 3]) + sw(0x9000))
    pair('SEARCH RECORD enhanced search', cmd(0xA2, 1, 0x06, b'\x00\x01\x05\xaa\xbb', 0), bytes([1, 2, 3]) + sw(0x9000))
    pair('SEARCH RECORD extended length', cmd(0xA2, 1, 0x04, b'\xaa' * 260, 0, ext=True), bytes([1]) + sw(0x9000))
    pair('SELECT extended length', cmd(0xA4, 4, 4, bytes(range(0xa0, 0xa0 + 30)) , 0, ext=True), sw(0x6a82))
    pair('SELECT by path with Le', cmd(0xA4, 8, 4, b'\x3f\x00\x7f\x10', 0x20), sw(0x6700))
    pair('STATUS extended length', cmd(0xF2, 0, 0, None, 0x100, ext=True), sw(0x9000))
    pair('INVALIDATE', cmd(0x04, 0, 0, None), sw(0x9000))
    pair('MANAGE CHANNEL open', cmd(0x70, 0, 0, None, 1), b'\x02' + sw(0x9000))
    pair('MANAGE CHANNEL open with channel number (response does not repeat it)', cmd(0x70, 0, 3, None, 0), bytes([3]) + sw(0x9000))
    pair('MANAGE CHANNEL close', cmd(0x70, 0x80, 2), sw(0x9000))
    pair('TERMINAL PROFILE', cmd(0x10, 0, 0, bytes((i * 11) & 0xff for i in range(30))), sw(0x9110))
    pair('TERMINAL PROFILE long', cmd(0x10, 0, 0, bytes(range(41, 82))), sw(0x9000))
    pair('TERMINAL RESPONSE', cmd(0x14, 0, 0, bytes.fromhex('810301210082028281830100')), sw(0x9000))
    pair('TERMINAL CAPABILITY', cmd(0xAA, 0, 0, tlv(0xA9, tlv(0x80, b'\x01\x32\x0a') + tlv(0x83, b'\x07') + tlv(0x99, b'\x01'))), sw(0x9000))
    pair('ENVELOPE', cmd(0xC2, 0, 0, event_download(), 0), bytes([0x90]) + sw(0x9000))
    pair('ENVELOPE with 0x81 length form', cmd(0xC2, 0, 0, timer_expiration(1)), sw(0x9000))
    pair('ENVELOPE with 0x82 length form', cmd(0xC2, 0, 0, timer_expiration(2)), sw(0x9000))
    pair('ENVELOPE with 0x83 length form', cmd(0xC2, 0, 0, timer_expiration(3)), sw(0x9000))
    pair('FETCH', cmd(0x12, 0, 0, None, len(disp_text())), disp_text() + sw(0x9000))
    pair('FETCH proactive command with 0x81 length', cmd(0x12, 0, 0, None, 0), disp_text(b'\x04' + b'x' * 130) + sw(0x9000))
    pair('SUSPEND UICC', cmd(0x76, 0, 0, bytes([1, 2, 1, 10]), 0), bytes([1, 10]) + bytes(4) + sw(0x9000))
    pair('SUSPEND UICC, short response', cmd(0x76, 0, 0, bytes([1, 2, 1, 10]), 0), b'\x01' + sw(0x9000))
    pair('SUSPEND UICC resume', cmd(0x76, 1, 0, bytes(range(1, 9))), sw(0x9000))
    pair('GET IDENTITY', cmd(0x78, 0, 0, None, 4), bytes(4) + sw(0x9000))
    pair('GET DATA', cmd(0xCA, 0x00, 0x5c, None, 4), bytes(4) + sw(0x9000))
    pair('generic INS', cmd(0xE4, 0, 0, None), sw(0x9000))
    pair('generic INS with data', cmd(0xFE, 0, 0, bytes(5)), sw(0x9000))
    pair('generic INS with Le only', cmd(0x84, 0, 0, None, 8), bytes(8) + sw(0x9000))
    pair('generic INS extended length', cmd(0xE0, 0, 0, bytes(300), ext=True), sw(0x9000))
    pair('generic INS extended length Le', cmd(0xCB, 0, 0, None, 0x200, ext=True), bytes(5) + sw(0x9000))
    # STORE DATA in several blocks, reassembled
    blocks = [bytes((i * 3 + b) & 0xff for i in range(40)) for b in range(3)]
    pair('STORE DATA block 0 (more blocks)', cmd(0xE2, 0x10, 0x00, blocks[0]), sw(0x9000))
    pair('STORE DATA block 1 (more blocks)', cmd(0xE2, 0x10, 0x01, blocks[1]), sw(0x9000))
    pair('STORE DATA block 2 (last block)', cmd(0xE2, 0x90, 0x02, blocks[2], 0), bytes(5) + sw(0x9000))
    pair('STORE DATA single block', cmd(0xE2, 0x90, 0x00, blocks[0], 0), bytes(3) + sw(0x9000))
    pair('STORE DATA single block, P1 with BER-TLV bits', cmd(0xE2, 0x92, 0x00, tlv(0xBF, b'\x01') , 0), bytes(3) + sw(0x9000))
    pair('STORE DATA block, no Le', cmd(0xE2, 0x80, 0x03, b'\x01\x02'), sw(0x9000))
    # responses without a command, and one with only a status word
    add('rsp', 'response without a command in the capture', bytes([1, 2, 3]) + sw(0x9000))
    add('rsp', 'status word only', sw(0x6a82))
    pair('command answered with a status word only', cmd(0xA4, 0, 4, b'\x6f\x77', 0), sw(0x6a82))
    pair('command with no response frame, then another', cmd(0xF2, 0, 0, None, 0x20), sw(0x6f00))
    add('cmd', 'command without a response', cmd(0xB0, 0, 0, None, 4))
    add('cmd', 'command: short, no P3', bytes([0xA0, 0xF2, 0, 0]))
    pair('SELECT, proprietary information: clock stop not allowed, no frequency', cmd(0xA4, 0, 4, b'\x6f\x08', 0),
         fcp(tlv(0x83, b'\x6f\x08'), prop(tlv(0x80, b'\x70'), tlv(0x81, b'\x03\x20\xff'))) + sw(0x9000))
    pair('generic INS with data and Le', cmd(0xDB, 1, 2, bytes(4), 8), bytes(8) + sw(0x9000))
    # BER-TLV dissector called directly
    add('tlv', 'BER-TLV: proactive command', disp_text())
    add('tlv', 'BER-TLV: proactive command with the 0x81 length form', disp_text(b'\x04' + b'y' * 130))
    add('tlv', 'BER-TLV: event download and unknown', event_download() + bytes.fromhex('d9 03 01 02 03'))
    pcapng(out + '/gsm_sim-coverage.pcapng', [1, 252], frames)

    # ================= malformed =================
    def addbad(kind, note, payload):
        add(kind, note, payload, True)
    addbad('tap', 'SELECT cut after the header', cmd(0xA4, 0, 0, b'\x3f\x00')[:6] + b'\x90\x00')
    addbad('tap', 'only 6 octets', bytes([0xa0, 0xa4, 0, 0, 2, 0x3f]) )
    addbad('tap', 'SELECT by path with an odd path', cmd(0xA4, 8, 4, b'\x3f\x00\x7f') + sw(0x9000))
    addbad('tap', 'UPDATE BINARY with Lc longer than the data', bytes([0xa0, 0xd6, 0, 0, 20, 1, 2]) + sw(0x9000))
    addbad('tap', 'TERMINAL CAPABILITY, template cut', bytes([0xa0, 0xaa, 0, 0, 6, 0xa9, 0x10, 0x80, 0x03, 1, 2]) + sw(0x9000))
    addbad('tap', 'SUSPEND UICC, short', bytes([0xa0, 0x76, 0, 0, 2, 1, 2]) + sw(0x9000))
    addbad('tap', 'ENVELOPE with a length longer than the data', bytes([0xa0, 0xc2, 0, 0, 4, 0xd6, 0x20, 1, 2]) + sw(0x9000))
    addbad('tap', 'ENVELOPE BER-TLV length byte missing', bytes([0xa0, 0xc2, 0, 0, 1, 0xd6]) + sw(0x9000))
    addbad('tap', 'TERMINAL PROFILE with Lc longer than the data', bytes([0xa0, 0x10, 0, 0, 40, 1, 2, 3]) + sw(0x9000))
    addbad('tap', 'SEARCH RECORD without data', bytes([0xa0, 0xa2, 1, 4, 0]) + sw(0x9000))
    addbad('tap', 'SEARCH RECORD enhanced, short', bytes([0xa0, 0xa2, 1, 6, 1, 0]) + sw(0x9000))
    addbad('tap', 'STORE DATA with Lc longer than the data', bytes([0xa0, 0xe2, 0x90, 0, 30, 1]) + sw(0x9000))
    addbad('tap', 'SELECT by AID longer than the data', bytes([0xa0, 0xa4, 4, 0, 16, 0xa0, 0]) + sw(0x9000))
    addbad('tap', 'four octets only', bytes([0xa0, 0xa4, 0, 0]))
    addbad('cmd', 'command: four octets', bytes([0xa0, 0xf2, 0, 0]))
    addbad('cmd', 'command: three octets', bytes([0xa0, 0xf2, 0]))
    addbad('cmd', 'command: SELECT Lc longer than the data', bytes([0xa0, 0xa4, 0, 0, 20, 0x3f, 0]))
    addbad('cmd', 'command: UPDATE RECORD Lc longer than the data', bytes([0xa0, 0xdc, 1, 4, 20, 1, 2]))
    addbad('cmd', 'command: extended length cut', bytes([0xa0, 0xd6, 0, 0, 0, 0x01, 0x00, 1, 2]))
    addbad('cmd', 'command: TERMINAL RESPONSE Lc longer than the data', bytes([0xa0, 0x14, 0, 0, 12, 0x81]))
    addbad('cmd', 'command: SUSPEND UICC short', bytes([0xa0, 0x76, 0, 0, 2, 1, 2]))
    addbad('cmd', 'command: ENVELOPE with a BER-TLV length longer than the data', bytes([0xa0, 0xc2, 0, 0, 4, 0xd6, 0x20, 1, 2]))
    addbad('cmd', 'command: SEARCH RECORD without data', bytes([0xa0, 0xa2, 1, 4, 0]))
    addbad('cmd', 'INCREASE with data (unknown bytes warning)', cmd(0x32, 0, 0, b'\x00\x00\x01'))
    addbad('cmd', 'unknown bytes after the APDU', cmd(0x32, 0, 0, None, 3) + b'\x01\x02')
    addbad('cmd', 'UPDATE BINARY extended length with Le (unknown bytes)', cmd(0xD6, 0, 2, bytes(260), 0, ext=True))
    addbad('tap', 'no P3 (SIMtrace)', bytes([0xA0, 0xE4, 0x00, 0x00]) + sw(0x9000))
    addbad('rsp', 'FCP: BER length with five length octets', bytes.fromhex('6208 80 85 00 00 00 00 aa 01 02') + sw(0x9000))
    addbad('rsp', 'response: one octet', b'\x90')
    addbad('rsp', 'response: empty', b'')
    addbad('rsp', 'response truncated FCP', bytes.fromhex('6220 82 02 78') + sw(0x9000))
    addbad('rsp', 'response FCP with proprietary information cut', bytes.fromhex('6208 a5 20 80 01') + sw(0x9000))
    # SELECT then a response whose FCP is cut inside a TLV
    addbad('cmd', 'SELECT before a cut FCP', cmd(0xA4, 0, 4, b'\x3f\x00', 0))
    addbad('rsp', 'FCP: tag with extended tag bytes cut', bytes.fromhex('6205 9f 81') + sw(0x9000))
    addbad('rsp', 'FCP: length byte missing', bytes.fromhex('6201 82') + sw(0x9000))
    addbad('rsp', 'FCP: long length form cut', bytes.fromhex('6203 82 82 00') + sw(0x9000))
    addbad('cmd', 'FETCH before a cut BER-TLV', cmd(0x12, 0, 0, None, 5))
    addbad('rsp', 'FETCH response: BER-TLV length longer than the data', bytes.fromhex('d0 40 81 03') + sw(0x9000))
    addbad('rsp', 'FETCH response: tag only', bytes.fromhex('d0') + sw(0x9000))
    addbad('cmd', 'SUSPEND before a short response', cmd(0x76, 0, 0, bytes([1, 2, 1, 10]), 0))
    addbad('rsp', 'SUSPEND response of two octets of data', b'\x01\x02' + sw(0x9000))
    addbad('tlv', 'BER-TLV: length longer than the data', bytes.fromhex('d0 20 81 03'))
    addbad('tlv', 'BER-TLV: tag only', bytes.fromhex('d0'))
    addbad('tlv', 'BER-TLV: 0x83 length cut', bytes.fromhex('d1 83 00'))
    pcapng(out + '/gsm_sim-coverage-malformed.pcapng', [1, 252], bad)
    if verbose:
        for name, first in sections:
            print('section from frame %d: %s' % (first, name))
        for n, t in notes: print(n, t)
        print('--- malformed')
        for n, t in badnotes: print(n, t)
    print(len(frames), 'frames,', len(bad), 'malformed;', ', '.join('%s from %d' % (n.split(' ')[0], f) for n, f in sections))

main()
