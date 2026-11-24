#!/usr/bin/env python3
# Generates test/captures/h221_nonstd_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the H.221 non-standard (Microsoft NetMeeting) coverage captures.
Usage: mkh221_nonstd.py <outdir> <workdir> [-v]   (run where the Wireshark
source tree is, see asnper.py)

The dissector is registered for NonStandardParameter with the H.221
identifier t35CountryCode 0xb5, extension 0, manufacturer 0x534c in H.225
(h225.nsp.h221) and H.245 (h245.nsp.h221).  Frames: H.225 RAS on UDP 1719;
a Q.931 Setup (TPKT / TCP 1720) announcing an H.245 address and H.245
NonStandardMessages on that TCP connection.  PER is produced by asnper.py
from the ASN.1 sources; nothing comes from a real network."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
import random
import asnper
from _lib import Pcap

GK, EP1, EP2 = '192.0.2.1', '192.0.2.10', '192.0.2.20'
FILES = ['h225/H323-MESSAGES.asn', 'h235/H235-SECURITY-MESSAGES.asn', 'h245/MULTIMEDIA-SYSTEM-CONTROL.asn']

def tpkt(d): return struct.pack('!BBH', 3, 0, 4 + len(d)) + d

def main(out, workdir, verbose=False):
    types = asnper.load(FILES, workdir)
    sc = asnper.Schema(types)
    rng = random.Random(221)
    ras_t, uu_t, mscm = types['RasMessage'], types['H323-UserInformation'], types['MultimediaSystemControlMessage']
    p = Pcap(); marks = []
    def mark(n): marks.append((len(p.frames) + 1, n))
    def nsp(data, t35=0xb5, ext=0, man=0x534c):
        return {'nonStandardIdentifier': ('h221NonStandard', {'t35CountryCode': t35, 't35Extension': ext, 'manufacturerCode': man}),
                'data': data}
    # codec value at offset 20 (0x0111 L&H CELP 4.8k ...), 0x0100 at 22
    def item(codec, n=24, marker=b'\x01\x00'):
        return (bytes(range(1, 21)) + codec + marker + bytes(range(100, 100 + 64)))[:n]
    cases = [
        ('L&H CELP 4.8k', item(b'\x01\x11')), ('MS-ADPCM', item(b'\x02\x00')), ('L&H CELP 8k', item(b'\x02\x11')),
        ('L&H CELP 12k', item(b'\x03\x11')), ('L&H CELP 16k', item(b'\x04\x11')), ('IMA-ADPCM', item(b'\x11\x00')),
        ('MS-GSM', item(b'\x31\x00')), ('E-AMR', item(b'\xfe\xff')), ('unknown codec value', item(b'\x99\x99')),
        ('longer item', item(b'\x01\x11', 60)),
        ('24 octets, no 0x0100 marker: non-standard data', item(b'\x01\x11', 24, b'\x00\x01')),
        ('40 octets, no marker', item(b'\x01\x11', 40, b'\xab\xcd')),
        ('23 octets: reproducer of the "Require 24 bytes" fix (threw an exception)', item(b'\x01\x11', 23)),
        ('22 octets', item(b'\x01\x11', 22)), ('10 octets', bytes(10)), ('1 octet', b'\x01'),
    ]
    def ras(data, seq, **kw):
        v = ('gatekeeperRequest', {'requestSeqNum': seq, 'protocolIdentifier': [0, 0, 8, 2250, 0, 4],
             'rasAddress': ('ipAddress', {'ip': bytes([192, 0, 2, 10]), 'port': 1719}),
             'endpointType': {'mc': False, 'undefinedNode': False}, 'nonStandardData': nsp(data, **kw)})
        return sc.encode(ras_t, v).bytes()
    mark('H.225 RAS GatekeeperRequest with the NetMeeting identifier, one frame per case')
    for i, (name, d) in enumerate(cases):
        p.udp(EP1, GK, 4000 + i, 1719, ras(d, 100 + i))
    mark('Other identifiers: another manufacturer, another country code, an object identifier')
    p.udp(EP1, GK, 4100, 1719, ras(cases[0][1], 200, man=0x1234))
    p.udp(EP1, GK, 4101, 1719, ras(cases[0][1], 201, t35=0xb4))
    v = ('gatekeeperRequest', {'requestSeqNum': 202, 'protocolIdentifier': [0, 0, 8, 2250, 0, 4],
         'rasAddress': ('ipAddress', {'ip': bytes([192, 0, 2, 10]), 'port': 1719}), 'endpointType': {'mc': False, 'undefinedNode': False},
         'nonStandardData': {'nonStandardIdentifier': ('object', [1, 3, 6, 1, 4, 1, 311, 1]), 'data': cases[0][1]}})
    p.udp(EP1, GK, 4102, 1719, sc.encode(ras_t, v).bytes())
    mark('H.245 on its own connection (announced in a Setup): NonStandardMessage with the NetMeeting identifier')
    setup = {'h323-uu-pdu': {'h323-message-body': ('setup', {
        'protocolIdentifier': [0, 0, 8, 2250, 0, 4], 'sourceInfo': {'mc': False, 'undefinedNode': False},
        'activeMC': False, 'conferenceID': bytes(16), 'conferenceGoal': ('create', None),
        'callType': ('pointToPoint', None), 'h245Address': ('ipAddress', {'ip': bytes([192, 0, 2, 10]), 'port': 11000})})}}
    u = sc.encode(uu_t, setup).bytes()
    q = bytes([8, 2, 0, 5, 5]) + bytes([0x7E]) + struct.pack('!H', len(u) + 1) + bytes([5]) + u
    p.tcp(EP1, EP2, 40001, 1720, tpkt(q))
    for i, (name, d) in enumerate(cases[:4] + cases[10:13] + cases[14:15]):
        v = ('request', ('nonStandard', {'nonStandardData': nsp(d)}))
        p.tcp(EP2, EP1, 40002, 11000, tpkt(sc.encode(mscm, v).bytes()))
    p.write(os.path.join(out, 'h221_nonstd-coverage.pcap'))
    m = Pcap()
    m.udp(EP1, GK, 4000, 1719, ras(cases[0][1], 1)[:-3])
    m.write(os.path.join(out, 'h221_nonstd-coverage-malformed.pcap'))
    if verbose:
        for (n, s), nx in zip(marks, marks[1:] + [(len(p.frames) + 1, '')]):
            print('%d-%d %s' % (n, nx[0] - 1, s))
    for i, (n, d) in enumerate(cases):
        if verbose: print('case', i, len(d), n)

if __name__ == '__main__':
    import tempfile
    args = [a for a in sys.argv[1:] if a != '-v']
    with tempfile.TemporaryDirectory() as work:
        main(args[0] if args else '.', args[1] if len(args) > 1 else work, '-v' in sys.argv)
