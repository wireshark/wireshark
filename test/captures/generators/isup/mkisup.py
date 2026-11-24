#!/usr/bin/env python3
# Generates test/captures/isup_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the ISUP coverage captures.  Usage: mkisup.py <outdir>

isup-coverage.pcapng            main capture: ITU ISUP over MTP3 (SI 5), BICC over
                                MTP3 (SI 13), ANSI / ITU / SPIROU ISUP in SIP
                                application/isup bodies; all well-formed.
isup-coverage-malformed.pcap    malformed and odd input (MTP3).
isup-coverage-variants.pcap     national variants, dissected with -o isup.variant:...
"""
import sys
import os
import struct
from isuplib import build_msg, cic, MSGS, mtp3, oparam, pcap_write, pcapng_write, udp_sip
from selected import SEL_ITU, SEL_ANSI, SEL_JP, SEL_JP2

out = sys.argv[1]
main = []          # (interface, frame)
def itu(m, c=1, si=5):
    main.append((0, mtp3(cic(c) + m, si=si)))
def bicc(m, c=1):
    main.append((0, mtp3(struct.pack('<I', c) + m, si=13)))
def sip(m, ctype='application/isup;version=itu-t92+;base=itu-t92+'):
    main.append((1, udp_sip(m, ctype, callid=str(len(main)))))

CDPN = bytes([0x01, 0x10, 0x21, 0x43])
CGPN = bytes([0x01, 0x13, 0x21, 0x43, 0x65])
CAUSE = bytes([0x82, 0x90])
def default_msg(mt, ansi=False):
    fixed, nvar, opt = MSGS[mt]
    var = []
    if mt == 1:
        var = [CDPN] if not ansi else [bytes([0x00, 0x00]), CDPN]
    elif mt == 2:
        var = [bytes([0x00, 0x21, 0x43])]
    elif mt in (12, 33, 47):
        var = [CAUSE]
    elif mt in (23, 24, 25, 26, 27, 41, 42, 43):
        var = [bytes([0x07]) if mt in (23, 42) else bytes([0x07, 0x55])]
        if mt == 43:
            var.append(bytes([0, 1, 2, 3, 0, 1, 2, 3]))
    elif mt == 45:
        var = [bytes([0x00, 0x01, 0x02])]
    fx = bytes([0x00] * fixed)
    if mt == 1 and ansi:
        fixed_, nvar, opt = 4, 2, 1
        fx = bytes([0x00] * 4)
    return build_msg(mt, fx, var, b'' if opt else None)

# --- A. every ITU message type with default mandatory parts
for mt in sorted(MSGS):
    itu(default_msg(mt), mt)
# unknown message type, charge information and subsequent directory number (national format)
itu(bytes([49, 1, 2, 3]), 60)
itu(bytes([67, 1, 2, 3]), 61)
itu(bytes([200]), 62)
# pass along carrying a release
itu(bytes([40]) + default_msg(12), 63)

# --- B. selected optional parameters (forward transfer message)
for i, (t, b) in enumerate(SEL_ITU):
    itu(build_msg(8, b"", [], oparam(t, bytes.fromhex(b))), 3000 + (i % 1000))

# --- C. structured parameters: APM, BAT ASE, range and status, numbers
def apm(aci, user=b'', seg=0xc0, slr=None, orig=b'', dest=b'', instr=0x80, aci16=False):
    p = bytes([0x00 | (aci & 0x7f), 0x80 | (aci >> 7)]) if aci16 else bytes([0x80 | aci])
    p += bytes([instr, seg])
    if slr is not None:
        p += bytes([slr])
    if aci > 3:
        p += bytes([len(orig)]) + orig + bytes([len(dest)]) + dest
    return p + user
def apm_msg(body):
    return build_msg(65, b'', [], oparam(120, body))
def el(i, content, compat=0x80, long=False):
    L = len(content) + 1
    if long:
        return bytes([i, L & 0x7f, (L >> 7) & 0x0f, compat]) + content
    return bytes([i, 0x80 | L, compat]) + content
ADDR = bytes([0x01, 0x10, 0x21, 0x43])      # odd/even + NAI, INN + plan, digits
bat = {
    'action': el(1, b'\x01'),
    'bncid4': el(2, bytes([0xde, 0xad, 0xbe, 0xef])),
    'bncid1': el(2, b'\x7f') + el(1, b'\x01'), 'bncid2': el(2, b'\x12\x34') + el(1, b'\x01'), 'bncid3': el(2, b'\x12\x34\x56') + el(1, b'\x01'),
    'iwfa_ip4': el(3, bytes([0x35, 0x00, 0x01, 10, 0, 0, 1]) + bytes(13)),
    'iwfa_ip6': el(3, bytes([0x35, 0x00, 0x00]) + bytes(range(1, 18))),
    'iwfa_e164': el(3, bytes([0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 1, 2, 3, 4])),
    'iwfa_e164g': el(3, bytes([0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 1, 2])),
    'iwfa_other': el(3, bytes([0x39, 1, 2, 3])),
    'bnc': el(7, b'\x04'),
    'bct': el(9, b'\x01'), 'bct0': el(9, b'\x00'),
    'bcu_nonet': el(10, b'\x00' + bytes([1, 2, 3, 4])),
    'bcu_net': el(10, b'\x03abc' + bytes([1, 2, 3, 4])),
    'sig': el(11, b''),
    'brc': el(12, b'\x01'),
    'bri': el(13, bytes([1, 3, 11])),
    'sigtype': el(14, b'\x05'),
    'dur': el(15, b'\x10\x00'),
    'unk': el(0x30, b'\x01\x02\x03'),
    'report': el(6, bytes([0x01, 0x04, 0x20, 0x00, 0x05, 0x01, 0x00])),
    'bci_ipbcp': el(8, bytes([0x01, 0x20]) + b'v=0\r\nm=audio 5000 RTP/AVP 0\r\n'),
    'bci_other': el(8, bytes([0x01, 0x00]) + bytes([1, 2, 3])),
}
def codec(org, typ, cfg=b'', long=False):
    return el(5, bytes([org, typ]) + cfg, long=long)
codecs = {
    'g711a': codec(1, 1), 'g722': codec(1, 5), 'g726': codec(1, 8, b'\x02'), 'g726n': codec(1, 8),
    'g729': codec(1, 0x0b, b'\x01'), 'g729n': codec(1, 0x0c), 'g728': codec(1, 0x0a, b'\x01'),
    'g723': codec(1, 6), 'g7xx': codec(1, 0x20),
    'gsm': codec(2, 0), 'amr2': codec(2, 5, b'\x7f'), 'amr3': codec(2, 5, b'\x7f\x01'),
    'amr4': codec(2, 5, b'\x7f\x01\x81'), 'umts': codec(2, 5, b'\x7f\x01\x81'),
}
clist = el(4, codecs['g711a'] + codecs['amr4'] + codecs['gsm'])
clist2 = el(4, codec(1, 1, long=True) + codec(2, 5, b'\x7f\x01', long=True))
bats = list(bat.values()) + list(codecs.values()) + [clist, clist2, el(1, b'\x01', long=True),
        bat['action'] + bat['bncid4'] + bat['iwfa_ip4'] + clist + bat['bct']]
for i, e in enumerate(bats):
    itu(apm_msg(apm(5, e, orig=ADDR if i % 3 == 0 else b'', dest=ADDR if i % 2 == 0 else b'')), 200 + i)
    if i % 4 == 0:
        bicc(apm_msg(apm(5, e)), 300 + i)
# APM: 16 bit application context identifier, charging ASE, unknown ASE, no user info
itu(apm_msg(apm(5, b'', aci16=True)), 400)
itu(apm_msg(apm(5, bat['action'], aci16=True)), 401)
itu(apm_msg(apm(3, bytes([0xa0, 0x00]))), 402)
itu(apm_msg(apm(2, bytes([1, 2, 3]))), 403)
itu(apm_msg(apm(7, bytes([1, 2, 3]))), 404)
itu(apm_msg(apm(0x1234 & 0x3fff, bytes([1, 2, 3]), aci16=True)), 405)
# APM: segmentation, three segments and a fresh sequence (also uses SLR)
itu(apm_msg(apm(5, bat['action'], seg=0x42, slr=0x01)), 410)
itu(apm_msg(apm(5, bat['bncid4'], seg=0x01, slr=0x01)), 410)
itu(apm_msg(apm(5, bat['bct'], seg=0x00, slr=0x01)), 410)
itu(apm_msg(apm(5, b'', seg=0x41, slr=0x02)), 411)
itu(apm_msg(apm(5, bat['action'], seg=0x00, slr=0x02)), 411)

# range and status of every circuit group message, including the fixed repro
# (range octet 0xFF, which used to reach REPORT_DISSECTOR_BUG)
itu(build_msg(23, b'', [bytes([0xff])]), 450)
itu(build_msg(23, b'', [bytes([0xff, 0x00])]), 451)       # GRS, repro (range octet 0xFF + status)
itu(build_msg(24, b'\x00', [bytes([0xff, 0x01])]), 452)   # CGB, repro
for rng in (0, 1, 2, 3, 4, 7, 8, 9, 15, 30):
    nst = (rng + 1 + 7) // 8
    st = bytes([0xa5] * nst)
    itu(build_msg(24, b'\x00', [bytes([rng]) + st]), 453)
    itu(build_msg(26, b'\x01', [bytes([rng]) + st]), 454)
    itu(build_msg(41, b'', [bytes([rng]) + st]), 455)
    itu(build_msg(43, b'', [bytes([rng]), bytes([i % 4 for i in range(rng + 1)])]), 456)
for sv in range(4):
    itu(build_msg(25, bytes([sv]), [bytes([3, 0x0f])]), 457)

# calling / called numbers: nature of address, number plans, odd and even digits
for nai in (1, 2, 3, 4, 5, 0x71):
    for plan in (1, 2, 3, 4, 5):
        for odd in (0x00, 0x80):
            digits = bytes([0x21, 0x43, 0x65, 0x07]) if not odd else bytes([0x21, 0x43, 0x65])
            c = bytes([odd | nai, plan << 4]) + digits
            g = bytes([odd | nai, (plan << 4) | 0x0b]) + digits
            itu(build_msg(1, bytes([0, 0, 0, 0x0a, 0]), [c], oparam(10, g) + oparam(4, c)), 500)
for i, g in enumerate((bytes([0x05, 0x04, 0x10, 0x21, 0x43, 0x65]), bytes([0x06, 0x84, 0x10, 0x21, 0x43]), bytes([0x00, 0x01, 0x20, 0x21]))):
    itu(build_msg(8, b'', [], oparam(192, g)), 530 + i)
# tap reset: IAM with numbers followed by messages without
itu(build_msg(1, bytes([0, 0, 0, 0x0a, 0]), [CDPN], oparam(10, CGPN)), 510)
itu(build_msg(12, b'', [CAUSE], b''), 510)
itu(build_msg(9, b'', [], b''), 510)

# --- D. ANSI / ITU / SPIROU in SIP
for mt in sorted(MSGS):
    if mt in (40, 49, 67):
        continue
    sip(default_msg(mt, True), 'application/isup;version=ansi')
for i, (t, b) in enumerate(SEL_ANSI):
    sip(build_msg(8, b'', [], oparam(t, bytes.fromhex(b))), 'application/isup;version=ansi')

# ANSI specific messages in SIP: circuit reservation (+ack), validation test (+response), exit
sip(bytes([0xe9]) + build_msg(0xe9, b'', [], None)[1:], 'application/isup;version=ansi')
sip(bytes([0xea, 0x03]), 'application/isup;base=ansi')
sip(bytes([0xec]), 'application/isup;base=gr317')
sip(bytes([0xeb, 0x01, 0x0f, 0x00, 0x00]), 'application/isup;version=ansi')
sip(bytes([0xeb, 0x01, 0x0f, 0x00, 0x00]), 'application/isup;version=gr317')
sip(bytes([0xed]), 'application/isup;version=ansi')
sip(bytes([0xee, 1, 2]), 'application/isup;version=ansi')
sip(bytes([40]) + default_msg(12, True), 'application/isup;version=ansi')   # pass along
sip(bytes([49, 1, 2, 3]), 'application/isup;version=ansi')              # charge information
sip(bytes([67, 1, 2, 3]), 'application/isup;version=ansi')              # subsequent directory number
for i, c in enumerate((b'\x80', b'\x80\x90', b'\x80\x90\x01\x02', b'\xc0', b'\xc0\x85', b'\xc0\x85\x01', b'\xa0', b'\xa0\x01', b'\x00\x10')):
    sip(build_msg(12, b'', [c], b''), 'application/isup;version=ansi')
sip(build_msg(0xe0, b'', [], None), 'application/isup;version=ansi')
# calling geodetic location (ANSI optional parameter 129): LPRI is bits 4-3 of the first octet
for oct1 in (0x40, 0x04, 0x00, 0x08, 0x0c, 0x13):
    sip(build_msg(8, b'', [], oparam(129, bytes([oct1, 0x01, 0xde, 0xad, 0xbe]))), 'application/isup;version=ansi')
# ITU and SPIROU in SIP
for mt in (1, 6, 9, 12, 16, 8, 65, 40):
    sip(default_msg(mt) if mt != 40 else bytes([40]) + default_msg(12))
sip(default_msg(1), 'application/isup')
sip(default_msg(1), 'application/isup;version=spirou')
sip(default_msg(1), 'application/isup;base=spirou')
sip(bytes([0xe1, 0x01, 0x02, 0x00]), 'application/isup;version=spirou')
sip(bytes([0xe2, 0x00]), 'application/isup;version=spirou')
sip(bytes([0xe3]), 'application/isup;version=spirou')
sip(default_msg(12), 'application/isup;version=itu-t92+;base=itu-t92+')

# --- E. BICC: every message type, a few with optional parameters
for mt in sorted(MSGS):
    bicc(default_msg(mt), 1000 + mt)
bicc(bytes([40]) + default_msg(12), 1100)
for t, b in SEL_ITU[::7]:
    bicc(build_msg(8, b'', [], oparam(t, bytes.fromhex(b))), 1200)

# zero length optional parameters (ITU and ANSI), last so the frame numbers above stay put
itu(build_msg(8, b'', [], oparam(4, b'') + oparam(12, b'')), 3999)
itu(build_msg(8, b'', [], oparam(12, b'')), 3998)
sip(build_msg(8, b'', [], oparam(4, b'') + oparam(12, b'')), 'application/isup;version=ansi')
sip(build_msg(8, b'', [], oparam(12, b'')), 'application/isup;version=ansi')

# --- national variants (isup-coverage-variants.pcap, -o isup.variant:...)
var = []
def v(m, c=1):
    var.append(mtp3(cic(c) + m))
for mt in sorted(MSGS):
    v(default_msg(mt), mt)
v(bytes([0xe1, 0x05, 0x06, 0x00]))              # French charging pulse
v(bytes([0xe2, 0x00]))                          # French charging acknowledge
v(bytes([0xe8, 0x35, 0x34, 0x12, 0x07, 0x78, 0x56]))   # Israeli backward charging
v(bytes([0xe9, 0x35, 0x07, 0x78, 0x56]))        # Israeli traffic change
v(bytes([0xea]))                                # Israeli charge ack
v(bytes([0xfc]))                                # Russian clear calling line
v(bytes([0xff, 0x00]))                          # Russian ringing
v(bytes([0xff, 0x01, 0x08, 0x01, 0x12, 0x00]))  # Russian ringing with optional part
v(bytes([0xe5]))
# Japan charge information message (254): type 3 (advanced charge rate transfer)
for ext in ([0x82, 0x02], [0x02, 0x82, 0x02], [0x02, 0x02, 0x82, 0x02], [0x02, 0x02, 0x02, 0x82, 0x02],
            [0x02, 0x02, 0x02, 0x02, 0x02]):
    v(build_msg(254, bytes([3]), [bytes(ext)], b''))
v(build_msg(254, bytes([1]), [bytes([1, 2, 3])], b''))
crt = lambda *a: bytes(a)
IA5 = lambda n: bytes([0x30 + (i % 10) for i in range(n)])
for n in (0, 5, 8, 11, 14):
    v(build_msg(254, bytes([0xfe]), [bytes([0xfc, 0x7d, n]) + IA5(max(n, 5))], b''))
v(build_msg(254, bytes([0xfe]), [bytes([0xfd, 0xfd])], b''))            # extension bit set in CRIC1
v(build_msg(254, bytes([0xfe]), [bytes([0xfd, 0x7d, 5]) + IA5(5) + bytes([0x7c, 5]) + IA5(5)], b''))
v(build_msg(254, bytes([0xfe]), [bytes([0xfd, 0x7d, 14]) + IA5(14) + bytes([0xfd])], b''))
for t, b in SEL_JP:
    v(build_msg(8, b'', [], oparam(t, bytes.fromhex(b))))
for t, b in SEL_JP2:
    v(build_msg(8, b'', [], oparam(t, bytes.fromhex(b))))
# Japan: carrier information (category, length, then type/length/value triplets), POI/CA, redirect information
def jcarrier(cat, items):
    body = b''.join(bytes([t, len(d)]) + d for t, d in items)
    return bytes([cat, len(body)]) + body
CA = bytes([0x00, 0x21, 0x43, 0x65]); CAODD = bytes([0x80, 0x21, 0x43, 0x05]); CID = bytes([0x00, 0x21, 0x43])
for body in (bytes([0xfe]) + jcarrier(0xfd, [(0xfc, b'\x12'), (0xfd, CA), (0xfe, CID)]),
             bytes([0xfd]) + jcarrier(0xfb, [(0xfd, CAODD)]) + jcarrier(0xfc, [(0xfe, bytes([0x80, 0x21]))]),
             bytes([0xfd]) + jcarrier(0xfa, [(0xfc, b'\x34')]) + jcarrier(0xfe, [(0xff, b'\x01')]),
             bytes([0xfc]) + jcarrier(0xfe, [(0xfd, bytes([0x00, 0x21])), (0xfe, bytes([0x00, 0x21, 0x43, 0x65]))])):
    v(build_msg(8, b'', [], oparam(241, body)))
v(build_msg(8, b'', [], oparam(241, b'\xfe\xfd')))    # empty carrier information
for d in (bytes([0x12, 5]) + CA[:4] + b'\x00', bytes([0x12, 3]) + CID, bytes([0x34, 4]) + CAODD):
    v(build_msg(8, b'', [], oparam(238, d)))
for d in (bytes([3, 2, 0x01, 0x02, 0x81, 0x00]), bytes([3, 4, 0x01, 0x05, 0x82, 0x06]), bytes([4, 1, 0x84]), bytes([4, 2, 0x01, 0x82]), bytes([9, 2, 1, 2])):
    v(build_msg(8, b'', [], oparam(139, d)))
for d in (bytes([3, 1, 0x81]), bytes([3, 2, 0x01, 0x82]), bytes([9, 1, 0])):
    v(build_msg(8, b'', [], oparam(140, d)))
v(build_msg(8, b'', [], oparam(243, bytes([0xfe, 1, 0xfd, 2, 0xfc, 3, 0xfb, 4, 0xf0, 5]))))
v(build_msg(254, bytes([0xfe]), [bytes([0xfc, 0xfd, 0x7d, 14]) + IA5(14)], b''))   # second charge rate category
v(build_msg(254, bytes([0xfe]), [bytes([0xfc, 0xfd, 0x7d, 8]) + IA5(8)], b''))
# charge information type (250) and charge information (251) in the optional part
for typ, data in ((3, [0x02, 0x01, 0x86, 0x02]), (254, [0xfd, 0x7d, 5] + list(IA5(5))), (7, [1, 2])):
    v(build_msg(8, b'', [], oparam(250, bytes([typ])) + oparam(251, bytes(data))))

# --- ANSI MTP3 (mtp3.standard:ANSI): 24 bit point codes, 14 bit CIC
ansim = []
def a(m, c=1):
    ansim.append(bytes([5, 1, 2, 3, 4, 5, 6, 7]) + struct.pack('<H', c) + m)
for mt in sorted(MSGS):
    if mt in (40,):
        continue
    a(default_msg(mt, True), mt)
a(bytes([40]) + default_msg(12, True), 40)
a(bytes([0xea, 0x03]), 0xea)
a(bytes([0xeb, 0x01, 0x0f, 0x00, 0x00]), 0xeb)
a(bytes([0xe9, 0x00]), 0xe9)
a(bytes([0xec]), 0xec)
a(bytes([0xed]), 0xed)

# --- malformed / error input
mal = []
def m_(m, c=1, si=5):
    mal.append(mtp3(cic(c) + m, si=si))
for mt in sorted(MSGS):
    d = default_msg(mt)
    for cut in (1, 2, 3, len(d) // 2, len(d) - 1):
        if 0 < cut < len(d):
            m_(d[:cut], mt)
# optional parameter length beyond the end of the message
m_(bytes([8, 1, 0x04, 0x20, 1, 2]), 2000)
m_(bytes([8, 1]) + oparam(120, b'\x85\x80'), 2001)
# too many digits (called party, calling party, original called, redirecting numbers)
m_(build_msg(1, bytes([0, 0, 0, 0x0a, 0]), [bytes([0x01, 0x10] + [0x21] * 40)], oparam(10, bytes([0x01, 0x13] + [0x21] * 40))), 2002)
m_(build_msg(8, b'', [], oparam(10, bytes([0x01, 0x13] + [0x21] * 40)) + oparam(40, bytes([0x01, 0x13] + [0x21] * 40))), 2003)
m_(build_msg(8, b'', [], oparam(4, bytes([0x01, 0x10] + [0x21] * 40)) + oparam(11, bytes([0x01, 0x13] + [0x21] * 40))), 2004)
# empty numbers
for t in (4, 5, 10, 11, 12, 13):
    m_(build_msg(8, b'', [], oparam(t, bytes([0x01, 0x10]))), 2005)
# APM: address length 1 (the fixed -1 length), unknown codec organisation (reads past the element)
m_(apm_msg(apm(5, b'', orig=b'\x01')), 2010)
m_(apm_msg(apm(5, b'', orig=b'', dest=b'\x01')), 2011)
m_(apm_msg(apm(5, bat['action'], orig=b'\x01', dest=b'\x01')), 2012)
m_(apm_msg(apm(5, el(5, bytes([7, 1, 1, 2])))), 2013)
m_(apm_msg(apm(5, el(4, el(5, bytes([7, 1, 1, 2]))))), 2014)
m_(apm_msg(apm(5, bat['bncid1'][:3])), 2015)
# BAT ASE and APM edge cases of the review reproducer (isup_apm_bat.py)
edge = [bytes([0x02, 0x80, 0x80, 0xAA, 0xBB]), bytes([0x04, 0x88, 0x80, 0x05, 0x00, 0x05, 0x80, 0x01, 0x00, 0x00]),
        bytes([0x05, 0x80, 0x80, 0x01, 0x02]), bytes([0x06, 0x83, 0x80, 0x01, 0x02]),
        bytes([0x08, 0x81, 0x80, 0x00, 0x20, 0x41]), bytes([0x0D, 0x80, 0x80, 0x01]),
        bytes([0x03, 0x82, 0x80, 0x45, 0x00]), bytes([0x0A, 0x85, 0x80, 0x10, 0x01])]
for i, e in enumerate(edge):
    m_(apm_msg(bytes([0x85, 0x80, 0xC0, 0, 0]) + e), 2020 + i)
m_(apm_msg(bytes([0x85, 0x80, 0x42, 0x81, 0, 0, 0x01, 0x81])), 2030)
m_(apm_msg(bytes([0x85, 0x80, 0x01, 0x81, 0, 0, 0x80, 0x01])), 2030)
m_(apm_msg(bytes([0x85, 0x80, 0x00, 0x81, 0, 0, 0x02])), 2030)
m_(apm_msg(bytes([0x05])), 2031)
# range and status: status shorter than the range, range octet 0xFF with no status
m_(build_msg(24, b'\x00', [bytes([0x1f, 0x01])]), 2040)
m_(build_msg(24, b'\x00', [bytes([0xff])]), 2041)
m_(build_msg(24, b'\x00', [bytes([0x07, 1, 2, 3])]), 2042)
m_(build_msg(41, b'', [bytes([0x1f])]), 2043)
m_(build_msg(43, b'', [bytes([0x1f]), bytes([1, 2])]), 2044)
# Japan (-o isup.variant:Japan): too many digits in carrier, POI/CA and charge area information
BIG = bytes([0x00]) + bytes([0x21] * 40)
m_(build_msg(8, b'', [], oparam(241, bytes([0xfe]) + jcarrier(0xfd, [(0xfd, BIG)]))), 2060)
m_(build_msg(8, b'', [], oparam(241, bytes([0xfe]) + jcarrier(0xfd, [(0xfe, BIG)]))), 2061)
m_(build_msg(8, b'', [], oparam(238, bytes([0x12, len(BIG)]) + BIG)), 2062)
m_(build_msg(8, b'', [], oparam(253, bytes([0x01]) + bytes([0x21] * 40))), 2063)
m_(build_msg(8, b'', [], oparam(253, bytes([0x81]) + bytes([0x21] * 40))), 2064)
# pass along nesting, wrong lengths, unknown types, MTP3 service indicator with a short message
m_(bytes([40] * 40), 2050)
m_(bytes([40, 40, 40, 12]), 2051)
m_(bytes([49, 1]), 2052)
m_(bytes([0x88, 0, 0]), 2053)
m_(bytes([1]), 2054)
m_(b'', 2055)
m_(bytes([1, 0x00]), 2056)
mal.append(mtp3(b'\x01', si=5))
mal.append(mtp3(b'\x01\x00', si=13))
mal.append(mtp3(b'\x01\x00\x00\x00', si=13))
# reverse pass-along of the fixed ANSI messages
mal.append(mtp3(cic(1) + bytes([0x25, 0x00]), si=5))

if __name__ == '__main__':
    pcapng_write(os.path.join(out, 'isup-coverage.pcapng'), main)
    pcap_write(os.path.join(out, 'isup-coverage-variants.pcap'), 141, var)
    pcap_write(os.path.join(out, 'isup-coverage-ansi-mtp3.pcap'), 141, ansim)
    pcap_write(os.path.join(out, 'isup-coverage-malformed.pcap'), 141, mal)
