#!/usr/bin/env python3
# Generates test/captures/ulp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for the ULP / SUPL dissector
(epan/dissectors/packet-ulp.c, generated from epan/dissectors/asn1/ulp/).
The PDUs are random but seeded values of the ULP ASN.1 types, encoded
with asn1tools (needs: pip install asn1tools) from the ASN.1 files in
the Wireshark tree. randgen.py (next to this script) is the value
generator. Positioning payloads are valid LPP PDUs (generated the same way)
and a few hand-made RRLP PDUs.
Usage: mkulp.py <outdir> [-v] [<wireshark source dir>]"""
import os
SRCDIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', '..'))
import glob
import struct
import sys
import random

HERE = os.path.dirname(os.path.abspath(__file__))
from randgen import Gen  # local copy: optional members use Gen.optprob

VERBOSE = '-v' in sys.argv
args = [a for a in sys.argv[1:] if a != '-v']
OUT = args[0] if args else '.'
A = (args[1] if len(args) > 1 else os.path.join(SRCDIR)) + '/epan/dissectors/asn1/'

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(s):
    return bytes(int(x) for x in s.split('.'))

def ether(payload, fromc=True):
    a, b = b'\x02\0\0\0\0\x01', b'\x02\0\0\0\0\x02'
    return (b + a if fromc else a + b) + b'\x08\x00' + payload

def ipp(proto, payload, src, dst, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64,
                    proto, 0, ip4(src), ip4(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def udp(sp, dp, payload):
    return struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload

class Cap:
    def __init__(self):
        self.frames = []
    def add(self, pkt):
        self.frames.append(pkt)
        return len(self.frames)
    def mark(self, note):
        if VERBOSE:
            print(len(self.frames) + 1, note)
    def write(self, name):
        with open(os.path.join(OUT, name), 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, p in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i // 100,
                                    (i % 100) * 10000, len(p), len(p)) + p)

class Flow:
    def __init__(self, cap, cip, cport, sip, sport):
        self.cap, self.cip, self.cport, self.sip, self.sport = cap, cip, cport, sip, sport
        self.cseq, self.sseq, self.ident = 1000, 5000, 1
    def _seg(self, fromc, flags, payload=b''):
        if fromc:
            sp, dp, s, a, si, di = self.cport, self.sport, self.cseq, self.sseq, self.cip, self.sip
            self.cseq += len(payload) + (1 if flags & 3 else 0)
        else:
            sp, dp, s, a, si, di = self.sport, self.cport, self.sseq, self.cseq, self.sip, self.cip
            self.sseq += len(payload) + (1 if flags & 3 else 0)
        opts = b'\x02\x04\x05\xb4\x04\x02\x01\x03\x03\x07\x01\x01' if flags & 2 else b''
        tcp = struct.pack('!HHIIBBHHH', sp, dp, s, a if flags & 0x10 else 0,
                          (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
        self.ident += 1
        return self.cap.add(ether(ipp(6, tcp, si, di, self.ident), fromc))
    def handshake(self):
        self._seg(True, 0x02)
        self._seg(False, 0x12)
        self._seg(True, 0x10)
    def send(self, fromc, payload):
        return self._seg(fromc, 0x18, payload)

# ------------------------------------------------------------ value generation
g = Gen(sorted(glob.glob(A + 'ulp/*.asn')), 'uper', 1)
lpp = Gen(sorted(glob.glob(A + 'lpp/*.asn')), 'uper', 1)

# hand-made RRLP PDUs (RRLP-Messages): assistanceDataAck, protocolError
RRLP = [bytes.fromhex('46'), bytes.fromhex('2830'), bytes.fromhex('0e')]

def lpp_pdu(seed):
    lpp.rng.seed(seed)
    while True:
        try:
            v, b = lpp.pdu('LPP-Message')
        except Exception:
            continue
        if 1 <= len(b) <= 300:
            return b

CCS = ['46', '1', '61', '358', '49', '44', '33', '81']

def bcd(digits, pad=True, n=8):
    """Digits to n octets of BCD, low nibble first, 0xf as filler."""
    d = [int(c) for c in digits][:2 * n]
    d += [0xf] * (2 * n - len(d))
    return bytes(d[i] | (d[i + 1] << 4) for i in range(0, 2 * n, 2))

def digits(r, n):
    return ''.join(str(r.randrange(10)) for _ in range(n))

def fix_payloads(v, r):
    """Replace the random octets of the positioning payloads by decodable
    PDUs and those of IMSI, MSISDN and MDN by BCD digits."""
    if isinstance(v, dict):
        for k in list(v):
            if k == 'lPPPayload':
                v[k] = [lpp_pdu(r.randrange(10 ** 6)) for _ in v[k]]
            elif k == 'imsi' and isinstance(v[k], bytes):
                v[k] = bcd(r.choice(['001', '262', '310', '505']) + r.choice(['01', '02', '410', '99'])
                           + digits(r, 8))
            elif k == 'msisdn' and isinstance(v[k], bytes):
                v[k] = bcd(r.choice(CCS) + digits(r, r.randrange(6, 10)))
            elif k == 'mdn' and isinstance(v[k], bytes):
                v[k] = bcd(digits(r, 16))
            else:
                v[k] = fix_payloads(v[k], r)
        return v
    if isinstance(v, tuple):
        if v[0] == 'rrlpPayload':
            return ('rrlpPayload', r.choice(RRLP))
        if v[0] == 'imsi' and isinstance(v[1], bytes):
            return ('imsi', bcd(r.choice(['001', '262', '310', '505']) + r.choice(['01', '02', '410', '99'])
                                + digits(r, 8)))
        if v[0] == 'msisdn' and isinstance(v[1], bytes):
            return ('msisdn', bcd(r.choice(CCS) + digits(r, r.randrange(6, 10))))
        if v[0] == 'mdn' and isinstance(v[1], bytes):
            return ('mdn', bcd(digits(r, 16)))
        return tuple([v[0]] + [fix_payloads(x, r) for x in v[1:]])
    if isinstance(v, list):
        return [fix_payloads(x, r) for x in v]
    return v

ALTS = [m for m in g.types['UlpMessage'][1]['members'] if m]
PDU_T = g.types['ULP-PDU'][1]

def gen_pdu(alt, seed, steer=None, force=None):
    """One ULP-PDU whose message is the given UlpMessage alternative."""
    r = random.Random(seed)
    g.rng.seed(seed)
    g.optprob = (0.5, 0.75, 0.95)[seed % 3]
    g.maxdepth = (6, 8)[(seed // 3) % 2]
    # every fifth PDU steers towards a group of rarely generated members
    g.want_opt, g.want_alts, g.force = set(), set(), {}
    if seed % 5 == 0:
        alts, opts = STEER[(seed // 5) % len(STEER)]
        g.want_alts, g.want_opt = set(alts), set(opts) | {'locationId', 'position', 'cellInfo'}
        g.maxdepth = 14
        g.force = FORCE
        g.want_opt |= set(FORCE)
    if steer:
        g.want_alts, g.want_opt = set(steer[0]), set(steer[1]) | {'locationId', 'position', 'cellInfo'}
        g.maxdepth = 14
        g.force = force or {}
        g.want_opt |= set(g.force)
    last = None
    for _ in range(100):
        g.depth = 0
        try:
            v = {}
            for m in PDU_T['members']:
                if m['name'] == 'message':
                    v['message'] = (alt['name'], g.value(alt))
                else:
                    v[m['name']] = g.value(m)
            v = fix_payloads(v, r)
            v['length'] = 0
            b = g.spec.encode('ULP-PDU', v)
            v['length'] = len(b)
            b = g.spec.encode('ULP-PDU', v)
            return b
        except Exception as e:
            last = e
            continue
    raise RuntimeError('cannot generate %s: %r' % (alt['name'], last))

# CHOICE alternatives and optional members that random generation rarely reaches
STEER = [
    (['wimaxBS'], ['wimaxNMRList', 'rssi', 'relDelay', 'wimaxBsID']),
    (['lteCell'], ['measResultListEUTRA', 'cgi-Info', 'measResult', 'rsrpResult', 'rsrqResult',
                   'neighbourInformation5G', 'mcc', 'trackingAreaCode']),
    (['wcdmaCell', 'fdd'], ['cellMeasuredResultsList', 'cpich-Ec-N0', 'cpich-RSCP', 'pathloss',
                           'frequencyInfo', 'primaryCPICH-Info']),
    (['wcdmaCell', 'tdd'], ['cellMeasuredResultsList', 'proposedTGSN', 'primaryCCPCH-RSCP', 'pathloss',
                           'timeslotISCP-List', 'frequencyInfo']),
    (['uMBAreaId', 'hRPDAreaId', 'cDMAAreaId'], ['areaIdLists', 'areaIdSetType', 'geoAreaMappingList']),
    (['nrCell'], ['measuredResultsListNR', 'ta', 'cellGlobalId', 'trackingAreaCode', 'ssb-Measurements',
                 'csi-rs-Measurements', 'rsrp-Range', 'rsrq-Range', 'sinr-Range']),
]
# values at the ends of the ranges that have their own text
FORCE = {'utra-CarrierRSSI': [76, 0, 77, 30], 'primaryCCPCH-RSCP': [91, 0, 92, 40],
         'cpich-RSCP': [91, 123, 124, 90, 100], 'cpich-Ec-N0': [0, 49, 50, 20],
         'rsrqResult': [0, 34, 10], 'rsrpResult': [0, 97, 50], 'rxLev': [0, 63, 30]}
PER_ALT = int(os.environ.get('ULP_PER_ALT', '25'))
BAD = set()
if os.path.exists(os.path.join(HERE, 'bad.txt')) and not os.environ.get('ULP_NOBAD'):
    BAD = set(int(x) for x in open(os.path.join(HERE, 'bad.txt')).read().split())
pdus = []        # (alt name, bytes)
indexes = []
idx = 0
for k in range(PER_ALT):
    for ai, alt in enumerate(ALTS):
        seed = 10000 * (ai + 1) + k
        b = gen_pdu(alt, seed)
        if idx not in BAD:
            pdus.append((alt['name'], b))
            indexes.append(idx)
        idx += 1

# dedicated PDUs: the top RSRQ value (the fix of "ULP: Fix the top RSRQ range
# value ...", RSRQ 34), the top RSRP value, UMB and HRPD area ids
ALT = {a['name']: a for a in ALTS}
EXTRA = [
    ('msSUPLPOSINIT', 777000 + k, STEER[1], {'rsrqResult': [34], 'rsrpResult': [97, 0]}) for k in range(3)
] + [
    ('msSUPLPOSINIT', 778000 + k, STEER[1], {'rsrqResult': [0, 34, 33], 'rsrpResult': [96, 1]}) for k in range(2)
] + [
    ('msSUPLTRIGGEREDSTART', 779000 + k, STEER[4], {}) for k in range(4)
] + [
    ('msSUPLTRIGGEREDSTART', 780000 + k, (['lTEAreaId', 'nRAreaId', 'wLANAreaId', 'wiMAXAreaId'],
                                          STEER[4][1] + ['refCI', 'apMACAddress']), {}) for k in range(4)
] + [
    ('msSUPLPOSINIT', 781000 + k, STEER[5], {}) for k in range(3)
]
for name, seed, steer, force in EXTRA:
    b = gen_pdu(ALT[name], seed, steer, force)
    if idx not in BAD:
        pdus.append((name, b))
        indexes.append(idx)
    idx += 1

# ------------------------------------------------------------ the capture
cap = Cap()
CIP, SIP = '192.0.2.10', '198.51.100.1'

# TCP 7275: the PDUs, alternating directions, a few per segment, a few split
f = Flow(cap, CIP, 40001, SIP, 7275)
cap.mark('TCP 7275 handshake')
f.handshake()
cap.mark('TCP 7275 PDUs: one per segment')
tcp_n = len(pdus) * 3 // 4
for i, (n, b) in enumerate(pdus[:tcp_n]):
    f.send(i % 2 == 0, b)
rest = pdus[tcp_n:]
cap.mark('UDP 7275 (ulp.pdu)')
for i, (n, b) in enumerate(rest):
    cap.add(ether(ipp(17, udp(40100 + i % 7, 7275, b), CIP, SIP, i)))

# reassembly: two PDUs in one segment, a PDU in two segments, a PDU in three
# segments with the length field split, a PDU followed by the start of the next
cap.mark('TCP reassembly')
f2 = Flow(cap, CIP, 40002, SIP, 7275)
f2.handshake()
P = [b for _, b in pdus[10:20]]
f2.send(True, P[0] + P[1])
f2.send(False, P[2][:7])
f2.send(False, P[2][7:])
f2.send(True, P[3][:1])
f2.send(True, P[3][1:2])
f2.send(True, P[3][2:])
f2.send(True, P[4] + P[5][:5])
f2.send(True, P[5][5:] + P[6])
f2.send(False, P[7] + P[8] + P[9])

# HTTP (media types registered by ULP) on TCP 80 and 8080
cap.mark('HTTP with the SUPL media types')
for k, (ctype, port) in enumerate((('application/oma-supl-ulp', 80), ('application/vnd.omaloc-supl-init', 80),
                                   ('application/oma-supl-ulp', 8080))):
    h = Flow(cap, CIP, 40010 + k, SIP, port)
    h.handshake()
    body = pdus[20 + k][1]
    h.send(True, ('POST /supl HTTP/1.1\r\nHost: supl.example.invalid\r\nContent-Type: %s\r\n'
                  'Content-Length: %d\r\n\r\n' % (ctype, len(body))).encode() + body)
    body = pdus[30 + k][1]
    h.send(False, ('HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n'
                   % (ctype, len(body))).encode() + body)
cap.write('ulp-coverage.pcap')
print(len(pdus), 'PDUs', sum(len(b) for _, b in pdus), 'octets')

# ------------------------------------------------------------ malformed
mal = Cap()
m = Flow(mal, '192.0.2.12', 41001, SIP, 7275)
m.handshake()
rr = random.Random(5)
mal.mark('truncated PDUs (length field fixed up)')
for i in range(0, len(pdus), 4):
    b = pdus[i][1]
    cut = rr.randrange(3, max(4, len(b)))
    c = b[:cut]
    c = struct.pack('!H', len(c)) + c[2:]
    m.send(True, c)
mal.mark('bit flips')
for i in range(1, len(pdus), 5):
    b = bytearray(pdus[i][1])
    for _ in range(3):
        b[rr.randrange(2, len(b))] ^= 1 << rr.randrange(8)
    mal.add(ether(ipp(17, udp(41100, 7275, bytes(b)), '192.0.2.12', SIP, i)))
mal.mark('length fields 0, 1, 2 over TCP and a length that exceeds the data')
m2 = Flow(mal, '192.0.2.13', 41002, SIP, 7275)
m2.handshake()
m2.send(True, struct.pack('!H', 0) + b'\x01\x02')
m2.send(True, struct.pack('!H', 1))
m2.send(True, struct.pack('!H', 2))
m2.send(True, struct.pack('!H', 40) + b'\x00' * 6)
mal.add(ether(ipp(17, udp(41100, 7275, b'\x00'), '192.0.2.12', SIP, 7)))
mal.add(ether(ipp(17, udp(41100, 7275, b''), '192.0.2.12', SIP, 8)))
mal.write('ulp-coverage-malformed.pcap')
