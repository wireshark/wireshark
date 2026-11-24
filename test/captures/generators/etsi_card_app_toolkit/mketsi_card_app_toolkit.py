#!/usr/bin/env python3
# Generates test/captures/etsi_card_app_toolkit_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the ETSI Card Application Toolkit (etsi_cat) coverage captures.
Usage: mketsi_card_app_toolkit.py <outdir>.  Everything is synthetic.

GSMTAP (UDP 4729, type SIM, sub type APDU) carries SIMtrace style frames:
command APDU, response data and status word in one packet.  gsm_sim hands
the BER-TLV of FETCH (proactive command 0xD0), TERMINAL RESPONSE (0x14)
and ENVELOPE (0xD1, 0xD6, 0xD7) to etsi_cat."""
import struct
import sys
import os

def write_pcap(name, pkts):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def ip_sum(h):
    s = sum(struct.unpack('>10H', h))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def gsmtap(payload, sub=0):
    # version 2, header length 4 words, type 4 (SIM)
    hdr = struct.pack('>BBBBHbbIBBBB', 2, 4, 4, 0, 0, 0, 0, 0, sub, 0, 0, 0)
    return hdr + payload

def udp_frame(payload, sport=40000, dport=4729):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([127, 0, 0, 1]), bytes([127, 0, 0, 1]))
    ip = ip[:10] + struct.pack('>H', ip_sum(ip)) + ip[12:]
    eth = bytes.fromhex('000000000000') * 2 + b'\x08\x00'
    return eth + ip + udp

def tlv_len(n, form=0):
    if form == 1 or n > 255 and form == 0 and False:
        return bytes([0x81, n])
    if form == 2:
        return bytes([0x82]) + struct.pack('>H', n)
    if form == 3:
        return bytes([0x83]) + struct.pack('>I', n)[1:]
    if n >= 0x81 and form == 0:
        return bytes([0x81, n])
    return bytes([n])

def ct(tag, val=b'', form=0, cr=True):
    """Comprehension TLV."""
    t = (tag | 0x80) if cr and tag < 0x7f else tag
    if tag >= 0x7f:
        return bytes([0x7f]) + struct.pack('>H', 0x8000 | tag if cr else tag) + tlv_len(len(val), form) + val
    return bytes([t]) + tlv_len(len(val), form) + val

def cmd(nr, typ, qual):
    return ct(0x01, bytes([nr, typ, qual]))

def dev(src, dst):
    return ct(0x02, bytes([src, dst]))

def sim(ins, body, sw=b'\x90\x00', p1=0, p2=0, cla=0x80):
    """SIMtrace style frame carrying one APDU."""
    if ins == 0x12:     # FETCH: Le in the command, data in the response
        apdu = bytes([cla, ins, p1, p2, len(body)]) + body + sw
    else:
        apdu = bytes([cla, ins, p1, p2, len(body)]) + body + sw
    return udp_frame(gsmtap(apdu))

def bertlv(tag, body, form=0):
    return bytes([tag]) + tlv_len(len(body), form) + body

def fetch(body, form=0):     # proactive command
    return sim(0x12, bertlv(0xd0, body, form), sw=b'\x90\x00')
def tresp(body):
    return sim(0x14, body, sw=b'\x90\x00')
def env(tag, body, form=0):
    return sim(0xc2, bertlv(tag, body, form), sw=b'\x90\x00')

# ---------------------------------------------------------------- helpers
SMS_SUBMIT = bytes.fromhex('01000581214365' '0000' '04d4f29c0e')   # SMS-SUBMIT "Test"
SMS_DELIVER = bytes.fromhex('0405812143650000' '0000000000000000' '04d4f29c0e')
def plmn(mcc, mnc):
    m = '%03d' % mcc
    n = '%02d' % mnc if mnc < 100 else '%03d' % mnc
    d = [int(c) for c in m] + [int(c) for c in n]
    if len(n) == 2:
        return bytes([d[0] | d[1] << 4, d[2] | 0xf0, d[3] | d[4] << 4])
    return bytes([d[0] | d[1] << 4, d[2] | d[5] << 4, d[3] | d[4] << 4])

main = []
bad = []
# zero bit patterns: MeasurementReport with measurement identity 1 etc. (UTRAN) / report-r8 (E-UTRAN)
RRC = {1: bytes(4), 4: bytes(8), 5: bytes(6), 9: bytes(12)}

# ---------------------------------------------------------------- 1. proactive commands
# DISPLAY TEXT with every text coding, alpha id with both codings, duration, icon id
for enc, txt in ((0x00, bytes.fromhex('d4f29c0e')), (0x04, b'Hello 8bit'), (0x08, 'UCS2'.encode('utf-16-be')),
                 (0x0c, b'x'), (0xf0, bytes.fromhex('d4f29c0e')), (0xf4, b'class 8bit'), (0xf8, b'y'), (0x44, b'z')):
    main.append(fetch(cmd(1, 0x21, 0x80) + dev(0x81, 0x02) + ct(0x0d, bytes([enc]) + txt) + ct(0x04, bytes([0x01, 0x0a]))))
main.append(fetch(cmd(2, 0x21, 0x01) + dev(0x81, 0x02) + ct(0x0d, b'') + ct(0x05, b'Alpha7') + ct(0x04, bytes([0, 5]))))
main.append(fetch(cmd(3, 0x21, 0x00) + dev(0x81, 0x82) + ct(0x05, bytes([0x80, 0x00, 0x41, 0x00, 0x42])) + ct(0x05, b'')))
# GET INKEY / SELECT ITEM with items, tone, language
main.append(fetch(cmd(4, 0x24, 0x00) + dev(0x81, 0x82) + ct(0x05, b'Menu') + ct(0x0f, b'\x01Item one') + ct(0x0f, b'\x02' + bytes([0x80, 0x00, 0x58])) + ct(0x0f, b'')))
main.append(fetch(cmd(5, 0x20, 0x00) + dev(0x81, 0x03) + ct(0x0e, b'\x01') + ct(0x0e, b'') + ct(0x04, bytes([2, 3]))))
# SETUP CALL: address (all TON/NPI), subaddress, DTMF, language
main.append(fetch(cmd(6, 0x10, 0x00) + dev(0x81, 0x83) + ct(0x05, b'Call') + ct(0x06, bytes([0x91, 0x21, 0x43, 0x65, 0xf7]))
                  + ct(0x08, b'\x12\x34') + ct(0x2c, b'\x12\x34\x5f') + ct(0x2d, b'en')))
main.append(fetch(cmd(7, 0x10, 0x01) + dev(0x81, 0x83) + ct(0x06, bytes([0xa1, 0x21])) + ct(0x06, b'') + ct(0x2c, b'') + ct(0x08, b'')))
# SEND SHORT MESSAGE (packing flag) with SMS TPDU, then SEND SS / USSD style
main.append(fetch(cmd(8, 0x13, 0x01) + dev(0x81, 0x83) + ct(0x05, b'Msg') + ct(0x06, bytes([0x91, 0x21, 0x43])) + ct(0x0b, SMS_SUBMIT)))
main.append(fetch(cmd(9, 0x13, 0x00) + dev(0x81, 0x83) + ct(0x0b, SMS_DELIVER)))
# POLL INTERVAL / timer management
main.append(fetch(cmd(10, 0x27, 0x00) + dev(0x81, 0x82) + ct(0x24, b'\x01') + ct(0x25, bytes([0x21, 0x43, 0x65]))))
for q in (1, 2, 3):
    main.append(fetch(cmd(10 + q, 0x27, q) + dev(0x81, 0x82) + ct(0x24, bytes([q])) + ct(0x25, bytes([0x00, 0x30, 0x00]))))
# REFRESH qualifiers
for q in (0, 1, 2, 3, 4, 5, 6, 7):
    main.append(fetch(cmd(20 + q, 0x01, q) + dev(0x81, 0x82)))
# LOCAL INFO qualifiers 0..9 (qualifier 2 = NMR, handled below)
for q in (0, 1, 3, 4, 5, 6, 7, 8, 9, 0x0a, 0x0b):
    main.append(fetch(cmd(30 + q, 0x26, q) + dev(0x81, 0x82)))
# SET UP EVENT LIST: ordinary events, then IMS events with IARI/IMPU/status
main.append(fetch(cmd(40, 0x05, 0x00) + dev(0x81, 0x82) + ct(0x19, bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x09, 0x0a, 0x0f, 0x10, 0x12, 0x13, 0x15]))))
main.append(fetch(cmd(41, 0x05, 0x00) + dev(0x81, 0x82) + ct(0x19, bytes([0x17, 0x18]))
                  + ct(0x76, b'urn:urn-7:3gpp-application.ims.iari.rcs.chat') + ct(0x77, b'\x80\x0dsip:a@b.example\x80\x03sip') + ct(0x77, b'\x81\x01x')
                  + ct(0x78, b'200') + ct(0x78, b'999')))
main.append(fetch(cmd(42, 0x05, 0x00) + dev(0x81, 0x82) + ct(0x19, b'') + ct(0x76, b'ignored') + ct(0x77, b'x') + ct(0x78, b'200')))
# OPEN CHANNEL: all bearer descriptions, buffer, transport, other address, DNS server, APN
bd_csd = ct(0x35, bytes([0x01, 0x07, 0x00, 0x01]))
bd_gprs = ct(0x35, bytes([0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x02]))
bd_utran = ct(0x35, bytes([0x09, 0x03, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x01, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x02]))
bd_0a = ct(0x35, bytes([0x0a]))
bd_eps = ct(0x35, bytes([0x0b, 0x01, 0x07, 0x00, 0x03, 0x02, 0x05, 0x01, 0x02]) + b'\x21')   # QoS then PDP type
bd_def = ct(0x35, bytes([0x03, 0xaa, 0xbb]))
bd_def1 = ct(0x35, bytes([0x03]))
apn = ct(0x47, b'\x07example\x03com')
for i, bd in enumerate((bd_csd, bd_gprs, bd_utran, bd_0a, bd_eps, bd_def, bd_def1)):
    main.append(fetch(cmd(50 + i, 0x40, 0x03) + dev(0x81, 0x82) + ct(0x05, b'Open') + bd + ct(0x39, b'\x05\x78')
                      + ct(0x47, b'\x07example\x03com') + ct(0x3e, b'\x21\x0a\x00\x00\x01') + ct(0x3c, b'\x02\x01\xbb')
                      + ct(0x40, b'\x21\x08\x08\x08\x08') + ct(0x39, b'\x05\x78')))
main.append(fetch(cmd(60, 0x40, 0x01) + dev(0x81, 0x82) + bd_gprs + ct(0x3e, b'\x57' + bytes(range(1, 17))) + ct(0x3c, b'\x01\x1f\x90')
                  + ct(0x40, b'\x57' + bytes(range(16, 0, -1))) + ct(0x3c, b'\x01')))
main.append(fetch(cmd(61, 0x40, 0x01) + dev(0x81, 0x82) + ct(0x3e, b'\x00') + ct(0x40, b'\x00') + ct(0x3e, b'\x21\x01\x02\x03\x04')))
# CLOSE CHANNEL / RECEIVE DATA / SEND DATA qualifiers, display params outside of OPEN CHANNEL (tag 0x40 ignored)
main.append(fetch(cmd(62, 0x43, 0x01) + dev(0x81, 0x21) + ct(0x40, b'\x21\x01\x02\x03\x04')))
main.append(fetch(cmd(63, 0x43, 0x00) + dev(0x81, 0x21)))
main.append(fetch(cmd(64, 0x42, 0x00) + dev(0x81, 0x21)))
main.append(fetch(cmd(65, 0x41, 0x00) + dev(0x81, 0x21)))
main.append(fetch(cmd(66, 0x44, 0x00) + dev(0x81, 0x21)))
# RUN AT COMMAND, LAUNCH BROWSER, TIMING ADVANCE etc
main.append(fetch(cmd(70, 0x34, 0x00) + dev(0x81, 0x82) + ct(0x28, b'AT+CGMI') + ct(0x29, b'OK')))
main.append(fetch(cmd(71, 0x15, 0x00) + dev(0x81, 0x82) + ct(0x2f, bytes.fromhex('A000000009') + bytes.fromhex('0001') + bytes.fromhex('0049') + b'\x01\x02\x03' + b'\xaa\xbb')))
main.append(fetch(cmd(72, 0x15, 0x00) + dev(0x81, 0x82) + ct(0x2f, bytes.fromhex('A000000087') + bytes.fromhex('1002') + bytes.fromhex('FFFF') + b'\x01\x02\x03')))
main.append(fetch(cmd(73, 0x15, 0x00) + dev(0x81, 0x82) + ct(0x2f, bytes.fromhex('A000000343') + bytes.fromhex('1002') + bytes.fromhex('FFFF') + b'\x01\x02\x03')))
main.append(fetch(cmd(74, 0x15, 0x00) + dev(0x81, 0x82) + ct(0x2f, bytes.fromhex('A000000412') + bytes.fromhex('1002') + bytes.fromhex('FFFF') + b'\x01\x02\x03')))
# length encodings: 0x81, 0x82, 0x83 for both the BER-TLV and the comp TLV
main.append(fetch(cmd(75, 0x21, 0x00) + dev(0x81, 0x02) + ct(0x0d, b'\x04' + b'A' * 150), form=0))
main.append(fetch(cmd(76, 0x21, 0x00) + dev(0x81, 0x02) + ct(0x0d, b'\x04text', form=2), form=2))
main.append(fetch(cmd(77, 0x21, 0x00) + dev(0x81, 0x02) + ct(0x0d, b'\x04text', form=3), form=3))
main.append(fetch(cmd(78, 0x21, 0x00) + dev(0x81, 0x02) + ct(0x0d, b'\x04text', form=1), form=1))
# extended tag (0x7f + 2 octets), unknown tag, unknown device identities
main.append(fetch(cmd(79, 0x21, 0x00) + dev(0x81, 0x02) + ct(0x1ff, b'\x01\x02') + ct(0x55, b'\x01') + ct(0x7e, b'')))
for src, dst in ((0x01, 0x81), (0x02, 0x81), (0x03, 0x81), (0x10, 0x81), (0x11, 0x81), (0x21, 0x81), (0x32, 0x81), (0x82, 0x81), (0x83, 0x81), (0xf0, 0xf1)):
    main.append(fetch(cmd(80, 0x21, 0x00) + dev(src, dst)))
main.append(fetch(cmd(81, 0x21, 0x00) + ct(0x02, b'\x81') + ct(0x01, b'\x01\x21') + ct(0x04, b'\x01') + ct(0x13, b'') + ct(0x0e, b'')))
# unknown command types
for t in (0x00, 0x02, 0x03, 0x11, 0x12, 0x14, 0x22, 0x23, 0x25, 0x28, 0x30, 0x31, 0x32, 0x33, 0x35, 0x45, 0x60, 0x62, 0x70, 0x7f):
    main.append(fetch(cmd(82, t, 0x00) + dev(0x81, 0x82)))
# location information (5, 7, 9 octets), IMEI, IMEISV, location status, access technology, bearer, date/time, timing advance, RAI, TAI, PLMN list, broadcast, update type, EPS PDN
loci = plmn(262, 1) + b'\x12\x34'
main.append(fetch(cmd(90, 0x26, 0x00) + dev(0x81, 0x82) + ct(0x13, loci) + ct(0x13, loci + b'\xab\xcd') + ct(0x13, loci + b'\xab\xcd\xef\x01')
                  + ct(0x14, bytes.fromhex('1a32547610325476')) + ct(0x62, bytes.fromhex('3a32547610325476f1'))
                  + ct(0x1b, b'\x00\x01\x02\x03') + ct(0x3f, b'\x00\x01\x02\x03\x04\x05\x08') + ct(0x32, b'\x01\x02\x03\x04')))
main.append(fetch(cmd(91, 0x26, 0x03) + dev(0x81, 0x82) + ct(0x26, bytes.fromhex('62300114352180')) + ct(0x26, bytes.fromhex('62300114352108'))
                  + ct(0x26, bytes.fromhex('623001143521ff')) + ct(0x2e, b'\x00\x05') + ct(0x25, bytes.fromhex('214365'))))
main.append(fetch(cmd(92, 0x26, 0x0a) + dev(0x81, 0x82) + ct(0x73, plmn(262, 1) + b'\x12\x34\x56') + ct(0x74, b'\x00') + ct(0x7d, plmn(262, 1) + b'\x12\x34')
                  + ct(0x79, plmn(262, 1) + plmn(310, 410) + plmn(1, 1)) + ct(0x79, b'') + ct(0x7a, b'\x01\x02\x03\x04') + ct(0x7a, b'\x02')))
main.append(fetch(cmd(93, 0x40, 0x03) + dev(0x81, 0x82) + ct(0x7c, bytes.fromhex('11'))))
main.append(fetch(cmd(93, 0x40, 0x03) + dev(0x81, 0x82) + ct(0x7c, bytes.fromhex('21'))))
# fixes: address / broadcast network information with length 0 followed by device identity, PLMN list with two entries
main.append(fetch(cmd(94, 0x13, 0x00) + ct(0x06, b'') + ct(0x7a, b'') + dev(0x81, 0x83)))
main.append(fetch(cmd(95, 0x40, 0x01) + dev(0x81, 0x82) + ct(0x35, b'\x0b') + ct(0x35, b'') + ct(0x39, b'\x01\x00')))
main.append(fetch(cmd(96, 0x26, 0x00) + dev(0x81, 0x82) + ct(0x79, plmn(262, 1) + plmn(310, 410) + plmn(208, 1))))
# UTRAN bearer (PDP type at offset 17) is covered by the OPEN CHANNEL frames above

# ---------------------------------------------------------------- 2. terminal responses
results = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
           0x27, 0x28, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x38, 0x39, 0x3a, 0x3c, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x60]
for r in results:
    extra = {0x20: b'\x01', 0x26: b'\x01', 0x38: b'\x01', 0x39: b'\x01', 0x3a: b'\x01', 0x3c: b'\x01'}.get(r, b'')
    main.append(tresp(cmd(1, 0x21, 0x80) + dev(0x82, 0x81) + ct(0x03, bytes([r]) + extra)))
for r, x in ((0x20, 0x00), (0x20, 0x02), (0x26, 0x00), (0x26, 0x02), (0x38, 0x00), (0x38, 0x02), (0x39, 0x00), (0x39, 0x02), (0x3a, 0x00), (0x3a, 0x04), (0x3c, 0x00)):
    main.append(tresp(cmd(2, 0x21, 0x80) + dev(0x82, 0x81) + ct(0x03, bytes([r, x]))))
# TR for GET INKEY with text, item id, timer, location info
main.append(tresp(cmd(4, 0x24, 0x00) + dev(0x82, 0x81) + ct(0x03, b'\x00') + ct(0x0f, b'\x02')))
main.append(tresp(cmd(11, 0x27, 0x01) + dev(0x82, 0x81) + ct(0x03, b'\x00') + ct(0x24, b'\x01') + ct(0x25, bytes.fromhex('214365'))))
main.append(tresp(cmd(30, 0x26, 0x00) + dev(0x82, 0x81) + ct(0x03, b'\x00') + ct(0x13, loci + b'\xab\xcd') + ct(0x14, bytes.fromhex('1a32547610325476'))))
main.append(tresp(cmd(31, 0x26, 0x03) + dev(0x82, 0x81) + ct(0x03, b'\x00') + ct(0x26, bytes.fromhex('62300114352180')) + ct(0x25, bytes.fromhex('214365'))))

# Network measurement results: proactive command (qualifier 2) then the terminal response.
# GERAN (default): RR measurement results of 16 octets
nmr = bytes([0x3f, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])
main.append(fetch(cmd(100, 0x26, 0x02) + dev(0x81, 0x82)))
main.append(tresp(cmd(100, 0x26, 0x02) + dev(0x82, 0x81) + ct(0x03, b'\x00') + ct(0x16, nmr)))
# The reproducer of the transaction fix: the measurement qualifier E-UTRAN (5) in a terminal response
# must not change how its NMR is decoded (GERAN, as in the first pass)
main.append(fetch(cmd(101, 0x26, 0x02) + dev(0x81, 0x82)))
main.append(tresp(cmd(101, 0x26, 0x02) + dev(0x82, 0x81) + ct(0x03, b'\x00') + ct(0x16, nmr) + ct(0x69, b'\x05')))
# UTRAN and E-UTRAN measurement qualifiers in the proactive command, decoded with RRC
for n, q in ((102, 1), (103, 4), (104, 5), (105, 9), (106, 0), (107, 0x0b)):
    main.append(fetch(cmd(n, 0x26, 0x02) + dev(0x81, 0x82) + ct(0x69, bytes([q]))))
    main.append(tresp(cmd(n, 0x26, 0x02) + dev(0x82, 0x81) + ct(0x03, b'\x00') + ct(0x16, RRC.get(q, nmr))))
# terminal response without a matching proactive command, and with another qualifier
main.append(tresp(cmd(110, 0x26, 0x02) + dev(0x82, 0x81) + ct(0x16, nmr)))
main.append(tresp(cmd(100, 0x26, 0x03) + dev(0x82, 0x81) + ct(0x16, nmr)))

# ---------------------------------------------------------------- 3. envelopes
main.append(env(0xd1, dev(0x83, 0x81) + ct(0x06, bytes([0x91, 0x21, 0x43])) + ct(0x0b, SMS_DELIVER)))
main.append(env(0xd6, ct(0x19, b'\x00') + dev(0x82, 0x81) + ct(0x1b, b'\x00') + ct(0x13, loci + b'\xab\xcd')))
main.append(env(0xd6, ct(0x19, b'\x17') + dev(0x82, 0x81) + ct(0x76, b'urn:iari') + ct(0x78, b'180')))
main.append(env(0xd6, ct(0x19, b'\x0a') + dev(0x82, 0x81) + ct(0x2d, b'de')))
main.append(env(0xd6, ct(0x19, b'\x12') + dev(0x82, 0x81) + ct(0x3f, b'\x03') + ct(0x2e, b'\x00\x01')))
main.append(env(0xd7, dev(0x82, 0x81) + ct(0x24, b'\x01') + ct(0x25, bytes.fromhex('214365'))))
main.append(env(0xd6, ct(0x19, b'\x14') + dev(0x82, 0x81) + ct(0x73, plmn(262, 1) + b'\x12\x34\x56') + ct(0x74, b'\x01')))
# other BER-TLV tags are only named by gsm_sim (nothing passed to etsi_cat)
main.append(env(0xd3, dev(0x01, 0x81) + ct(0x10, b'\x01')))
main.append(env(0xd5, dev(0x82, 0x81)))

# ---------------------------------------------------------------- malformed
bad.append(fetch(cmd(1, 0x21, 0x80) + dev(0x81, 0x02) + b'\x8d\x10\x04ab'))        # TLV longer than the PDU
bad.append(fetch(cmd(1, 0x21, 0x80) + dev(0x81, 0x02) + b'\x8d'))                  # tag without length
bad.append(fetch(cmd(1, 0x21, 0x80) + b'\xff\x00'))                                # extended tag cut
bad.append(fetch(cmd(1, 0x21, 0x80) + b'\xff\x01'))
bad.append(fetch(b'\x81\x02\x01\x21'))                                              # command details too short for the type
bad.append(fetch(cmd(2, 0x40, 0x01) + ct(0x39, b'\x01') ))                         # buffer size with one octet
bad.append(fetch(cmd(2, 0x40, 0x01) + ct(0x3e, b'\x21\x01')))                      # other address cut
bad.append(fetch(cmd(2, 0x40, 0x01) + ct(0x3e, b'\x57\x01')))
bad.append(fetch(cmd(2, 0x40, 0x01) + ct(0x40, b'\x21\x01') ))
bad.append(fetch(cmd(2, 0x40, 0x01) + ct(0x40, b'\x57\x01') ))
bad.append(fetch(cmd(2, 0x40, 0x01) + ct(0x35, b'\x09\x01\x02')))                  # UTRAN bearer cut
bad.append(fetch(cmd(2, 0x40, 0x01) + ct(0x35, b'\x01\x01')))
bad.append(fetch(cmd(2, 0x40, 0x01) + ct(0x35, b'\x02\x01')))
bad.append(fetch(cmd(2, 0x26, 0x00) + ct(0x25, b'\x01')))                          # timer value cut
bad.append(fetch(cmd(2, 0x26, 0x00) + ct(0x26, b'\x01\x02')))                      # date time cut
bad.append(fetch(cmd(2, 0x26, 0x00) + ct(0x13, loci[:4])))                         # location info cut
bad.append(fetch(cmd(2, 0x26, 0x00) + ct(0x2e, b'\x01')))
bad.append(fetch(cmd(2, 0x26, 0x00) + ct(0x2f, b'\xa0\x00')))                      # AID cut
bad.append(fetch(cmd(2, 0x26, 0x00) + ct(0x79, b'\x62\xf2')))                      # PLMN list not a multiple of 3
bad.append(fetch(cmd(2, 0x26, 0x00) + ct(0x73, b'\x62\xf2')))
bad.append(fetch(cmd(2, 0x26, 0x00) + ct(0x7d, b'\x62\xf2')))
bad.append(fetch(cmd(2, 0x26, 0x00) + ct(0x7c, b'\x01')))
bad.append(fetch(cmd(2, 0x26, 0x00) + ct(0x39, b'')))
bad.append(fetch(cmd(2, 0x05, 0x00) + ct(0x19, b'\x17\x18') + ct(0x77, b'\x80\x40abc')))   # IMPU longer than the TLV
bad.append(fetch(cmd(2, 0x05, 0x00) + ct(0x19, b'\x17\x18') + ct(0x77, b'\x80')))
bad.append(fetch(cmd(2, 0x21, 0x00) + b'\x8d\x82\x00'))                             # 0x82 length cut
bad.append(fetch(cmd(2, 0x21, 0x00) + b'\x8d\x83\x00\x00'))
bad.append(fetch(cmd(2, 0x21, 0x00) + b'\x8d\x81'))
bad.append(tresp(cmd(2, 0x26, 0x02) + ct(0x16, nmr[:3])))                           # NMR with a short body (GERAN, no transaction)
bad.append(tresp(cmd(2, 0x26, 0x02) + ct(0x03, b'')))                               # empty result
bad.append(tresp(cmd(2, 0x26, 0x02) + ct(0x01, b'\x01\x26')))
bad.append(tresp(b'\x81'))
# NMR decoded as RRC with garbage in a UTRAN and an E-UTRAN transaction
for n, q in ((120, 1), (121, 5)):
    bad.append(fetch(cmd(n, 0x26, 0x02) + dev(0x81, 0x82) + ct(0x69, bytes([q]))))
    bad.append(tresp(cmd(n, 0x26, 0x02) + dev(0x82, 0x81) + ct(0x16, bytes(range(1, 20)))))
    bad.append(tresp(cmd(n, 0x26, 0x02) + dev(0x82, 0x81) + ct(0x16, b'')))
    bad.append(tresp(cmd(n, 0x26, 0x02) + dev(0x82, 0x81) + ct(0x16, b'\xff' * 40)))
# the old reproducers (zero length address and broadcast info) with data after them
bad.append(fetch(cmd(2, 0x13, 0x00) + b'\x86\x00\x82\x02\x81\x83' ))
# oversized lengths in the outer BER-TLV
bad.append(sim(0xc2, b'\xd6\x20' + dev(0x82, 0x81)))
bad.append(sim(0x12, b'\xd0'))
bad.append(sim(0x12, b'\xd0\x82\x00'))

out = sys.argv[1]
main = [m for m in main if m is not None]
write_pcap(os.path.join(out, 'etsi_card_app_toolkit-coverage.pcap'), main)
write_pcap(os.path.join(out, 'etsi_card_app_toolkit-coverage-malformed.pcap'), bad)
print(len(main), len(bad))
