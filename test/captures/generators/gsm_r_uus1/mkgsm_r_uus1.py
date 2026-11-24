#!/usr/bin/env python3
# Generates test/captures/gsm_r_uus1_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic captures for packet-gsm_r_uus1.c (GSM-R User-to-User Signalling 1).
Usage: mkgsm_r_uus1.py <outdir> [-v]

The capture is pcapng with two interfaces:
  0: Ethernet; GSMTAP (UDP 4729) type Abis (2) carrying GSM DTAP call control
     messages (SETUP, RELEASE COMPLETE) whose User-user IE has protocol
     discriminator 0 (user specific), which the dissector claims by default
     (preference gsm-r-uus1.dissect_gsm_a_u2u, on by default);
  1: LAPD (linktype 203) SAPI 0 carrying Q.931 messages whose User-user IE has
     protocol discriminator 0; GSM-R UUS1 gets them from the Q.931 heuristic
     list "q931_user" only with the preference gsm-r-uus1.dissect_q931_u2u."""
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

def gsmtap(payload, gtype=2, sub=0, ts=1, arfcn=0):
    hdr = struct.pack('>BBBBHbbIBBBB', 2, 4, gtype, ts, arfcn, -60, 20, 0, sub, 0, 0, 0)
    return hdr + payload

def lapd(sapi, tei, payload, cr=0):
    return bytes([(sapi << 2) | (cr << 1), (tei << 1) | 1, 0x03]) + payload

def bits(fields):
    v = 0; n = 0
    for val, w in fields:
        assert 0 <= val < (1 << w), (val, w)
        v = (v << w) | val; n += w
    assert n % 8 == 0
    return v.to_bytes(n // 8, 'big')

def bcd(digits):
    d = [int(c) if c != 'F' else 15 for c in digits]
    if len(d) % 2: d.append(15)
    return bytes((d[i + 1] << 4) | d[i] for i in range(0, len(d), 2))

# --- UUS1 elements
def pfn(digits):
    b = bcd(digits) if digits else b''
    return bytes([5, len(b)]) + b

def chpc_fwd(tag=2, t_dur=36000, t_rel=6000, prio=3, cause=0x11, gref='12345678'):
    return bytes([tag, 13]) + t_dur.to_bytes(3, 'little') + struct.pack('<I', t_rel) + bytes([prio, cause]) + bcd(gref)

def chpc_collect(tag=2, cause=0):
    return bytes([tag, cause])

def elda(lat=(48, 30, 1234, 1), lon=(11, 22, 4321, 0), height=200, speed=5, heading=9, t=7, dist=1000, scale=1, spare=0, tag=6):
    body = bits([(lat[0], 7), (lat[1], 6), (lat[2], 13), (lat[3], 1),
                 (lon[0], 8), (lon[1], 6), (lon[2], 13), (lon[3], 1),
                 (height, 13), (speed, 6), (heading, 6), (t, 11), (dist, 14), (scale, 2), (spare, 5)])
    assert len(body) == 14
    return bytes([tag, 14]) + body

def epfn(data): return bytes([9, len(data)]) + data
def text(data): return bytes([10, len(data)]) + data
def dsd(digits):
    b = bcd(digits)
    return bytes([11, len(b)]) + b
def alert(gref='87654321'):
    return bytes([12, 4]) + bcd(gref)

def dtap_cc(msgtype, uu, discr=0, extra=b''):
    # DTAP call control (PD 3, transaction identifier 0)
    ie = bytes([0x7E, len(uu) + 1, discr]) + uu if uu is not None else b''
    return bytes([0x03, msgtype]) + extra + ie

def q931(msgtype, uu, discr=0):
    ie = bytes([0x7E, len(uu) + 1, discr]) + uu
    return bytes([0x08, 0x01, 0x01, msgtype]) + ie

def main():
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    frames, notes = [], []
    bad, badnotes = [], []

    def add_dtap(note, uu, msgtype=0x05, discr=0, to_bad=False, extra=b''):
        fr = (0, eth_udp(gsmtap(dtap_cc(msgtype, uu, discr, extra))))
        if to_bad:
            bad.append(fr); badnotes.append((len(bad), note))
        else:
            frames.append(fr); notes.append((len(frames), note))

    def add_q931(note, uu, msgtype=0x05, discr=0, to_bad=False):
        fr = (1, lapd(0, 0, q931(msgtype, uu, discr)))
        if to_bad:
            bad.append(fr); badnotes.append((len(bad), note))
        else:
            frames.append(fr); notes.append((len(frames), note))

    sections = []
    sections.append(('GSM A DTAP (default preferences)', 1))
    # every element on its own
    add_dtap('PFN with digits', pfn('1234567'))
    add_dtap('PFN with a filler digit', pfn('98765'))
    add_dtap('PFN without a number (length 0)', pfn(''))
    add_dtap('PFN, 14 digits', pfn('12345678901234'))
    add_dtap('CHPC tag 2 forward (length 13)', chpc_fwd(2))
    add_dtap('CHPC tag 3 forward, other priorities and causes', chpc_fwd(3, 1, 2, 5, 0x03, '00000001'))
    for prio in (0, 1, 2, 3, 4, 5, 6, 7, 9):
        add_dtap('CHPC priority %d' % prio, chpc_fwd(2, 100 * prio, 10 * prio, prio, 1 << (prio % 8)))
    add_dtap('CHPC cause bits all set', chpc_fwd(2, 0xffffff, 0xffffffff, 7, 0xff, '99999999'))
    for cause in (0, 1, 2, 0x42, 0x7f, 0x80, 0x81, 0xff):
        add_dtap('CHPC collecting network device, cause 0x%02x' % cause, bytes([3, cause]), msgtype=0x2a)
    add_dtap('CHPC collect tag 2', bytes([2, 0]), msgtype=0x2a)
    add_dtap('eLDA tag 6', elda())
    add_dtap('eLDA tag 7, southern and western hemisphere', elda(lat=(89, 59, 5999, 0), lon=(179, 59, 8191, 1), tag=7))
    add_dtap('eLDA tag 8, maximum values', elda(lat=(127, 63, 8191, 1), lon=(255, 63, 8191, 1), height=8191, speed=63, heading=63, t=2047, dist=16383, scale=3, spare=31, tag=8))
    add_dtap('eLDA, minimum values', elda(lat=(0, 0, 0, 0), lon=(0, 0, 0, 0), height=0, speed=0, heading=0, t=0, dist=0, scale=0))
    for scale in (0, 1, 2, 3):
        add_dtap('eLDA scale %d' % scale, elda(scale=scale, height=150 + scale, speed=10 + scale, heading=36 - scale, t=100 + scale, dist=500 * scale))
    add_dtap('ePFN', epfn(b'\x01\x02\x03\x04'))
    add_dtap('ePFN, empty', epfn(b''))
    add_dtap('text string', text(b'\x00Hello'))
    add_dtap('text string, empty', text(b''))
    add_dtap('DSD alarm', dsd('4711'))
    add_dtap('DSD alarm, 12 digits', dsd('123456789012'))
    add_dtap('alert controller', alert('11223344'))
    add_dtap('alert controller, other group reference', alert('00000099'))
    # several elements in one message, and an unknown element ends the decoding
    add_dtap('PFN and eLDA', pfn('555') + elda())
    add_dtap('PFN, CHPC, DSD alarm and alert controller', pfn('42') + chpc_fwd() + dsd('7') + alert())
    add_dtap('all elements in a row', pfn('1') + chpc_fwd(3) + bytes([2, 0x80]) + elda() + epfn(b'\xaa') + text(b'x') + dsd('9') + alert())
    add_dtap('element followed by an unknown element', pfn('123') + bytes([0x77, 1, 2, 3]))
    add_dtap('unknown element first (tag 0x55, reproducer of the heuristic fix)', bytes([0x55, 1, 2, 3]))
    add_dtap('unknown element tag 1', bytes([1, 0]))
    # reproducers of the fix for the eLDA bit offset (two eLDA elements: the second one is at offset 16)
    add_dtap('eLDA at offset 0 and 16 (reproducer of the bit offset fix)', elda(height=200, speed=5, heading=9, t=7, dist=1000, scale=1) +
             elda(lat=(1, 2, 3, 0), lon=(4, 5, 6, 1), height=300, speed=7, heading=11, t=70, dist=2000, scale=2))
    add_dtap('eLDA heading 630 (all ones)', bytes([6, 14]) + b'\xff' * 14)
    # other GSM-R messages and protocol discriminators
    add_dtap('RELEASE COMPLETE with PFN', pfn('31'), msgtype=0x2a)
    add_dtap('SETUP with another protocol discriminator (not GSM-R)', pfn('123'), discr=4)
    add_dtap('SETUP with IA5 user-user', b'hello', discr=4)
    add_dtap('SETUP without user-user', None)
    sections.append(('Q.931 (needs gsm-r-uus1.dissect_q931_u2u:TRUE)', len(frames) + 1))
    add_q931('Q.931 SETUP with PFN', pfn('1234'))
    add_q931('Q.931 SETUP with CHPC forward', chpc_fwd())
    add_q931('Q.931 RELEASE COMPLETE with CHPC collect', bytes([3, 0]), msgtype=0x5a)
    add_q931('Q.931 SETUP with eLDA', elda())
    add_q931('Q.931 SETUP with alert controller and DSD alarm', alert() + dsd('5'))
    add_q931('Q.931 SETUP, unknown tag 0x55 (reproducer of the heuristic fix)', bytes([0x55, 1, 2, 3]))
    add_q931('Q.931 SETUP, valid PFN (reproducer of the heuristic fix)', bytes([5, 2, 0x21, 0x43]))
    add_q931('Q.931 SETUP, protocol discriminator IA5', b'text', discr=4)
    pcapng(out + '/gsm_r_uus1-coverage.pcapng', [1, 203], frames)

    # --- malformed capture
    add_dtap('PFN length longer than the message', bytes([5, 20, 0x12]), to_bad=True)
    add_dtap('PFN cut after the tag', bytes([5]), to_bad=True)
    add_dtap('CHPC forward cut', bytes([2, 13, 1, 2, 3]), to_bad=True)
    add_dtap('CHPC collect cut after the tag', bytes([3]), to_bad=True)
    add_dtap('eLDA cut', bytes([6, 14, 1, 2, 3, 4, 5]), to_bad=True)
    add_dtap('eLDA cut after the tag', bytes([6]), to_bad=True)
    add_dtap('ePFN length longer than the message', bytes([9, 30, 1]), to_bad=True)
    add_dtap('text length longer than the message', bytes([10, 30, 1]), to_bad=True)
    add_dtap('DSD alarm length longer than the message', bytes([11, 30, 0x12]), to_bad=True)
    add_dtap('alert controller cut', bytes([12, 4, 1, 2]), to_bad=True)
    add_dtap('alert controller cut after the tag', bytes([12]), to_bad=True)
    add_dtap('DSD cut after the tag', bytes([11]), to_bad=True)
    add_q931('Q.931 PFN cut', bytes([5, 9, 1]), to_bad=True)
    add_q931('Q.931 eLDA cut', bytes([6, 14, 1]), to_bad=True)
    pcapng(out + '/gsm_r_uus1-coverage-malformed.pcapng', [1, 203], bad)
    if verbose:
        for name, first in sections:
            print('section from frame %d: %s' % (first, name))
        for n, t in notes: print(n, t)
        print('--- malformed')
        for n, t in badnotes: print(n, t)
    print(len(frames), 'frames,', len(bad), 'malformed;', ', '.join('%s from %d' % (n.split(' ')[0], f) for n, f in sections))

main()
