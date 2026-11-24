# Generates test/captures/sgsap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# --- pcap helpers (synthetic addresses only) ---
import struct
import sys
import os

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2', ident=1, ttl=64, flags_frag=0, options=b''):
    s = bytes(map(int, src.split('.'))); d = bytes(map(int, dst.split('.')))
    ihl = 5 + len(options) // 4
    h = struct.pack('!BBHHHBBH4s4s', 0x40 | ihl, 0, ihl * 4 + len(payload), ident, flags_frag, ttl, proto, 0, s, d) + options
    return h[:10] + struct.pack('!H', csum(h)) + h[12:]

def eth(payload, ethertype=0x0800, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    return dst + src + struct.pack('!H', ethertype) + payload

def udp(sport, dport, payload, src='192.0.2.1', dst='192.0.2.2'):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(17, u, src, dst) + u)

def tcp(sport, dport, payload, seq=1, ack=1, src='192.0.2.1', dst='192.0.2.2', flags=0x18):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    return eth(ipv4(6, t, src, dst) + t)

def ipv6(nxt, payload, src='2001:db8::1', dst='2001:db8::2', hlim=64):
    import socket
    return struct.pack('!IHBB', 0x60000000, len(payload), nxt, hlim) + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)

def write(fn, pkts, linktype=1, snap=262144):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snap, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def exported_pdu(name, payload, tag=12):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('!HH', tag, len(n)) + n + b'\0' * pad + struct.pack('!HH', 0, 0) + payload

def llc_frame(payload, dsap=0xfe, ssap=0xfe, ctl=0x03, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    body = bytes([dsap, ssap, ctl]) + payload
    return dst + src + struct.pack('!H', len(body)) + body

class Flow:
    '''TCP connection with a handshake and tracked sequence numbers.'''
    def __init__(self, cport, sport, client='192.0.2.1', server='192.0.2.2', cisn=1000, sisn=5000, hs=False):
        self.cp, self.sp, self.c, self.s = cport, sport, client, server
        self.cseq, self.sseq = cisn, sisn
        self.pk = []
        if hs:
            self.pk.append(tcp(cport, sport, b'', self.cseq, 0, client, server, 0x02)); self.cseq += 1
            self.pk.append(tcp(sport, cport, b'', self.sseq, self.cseq, server, client, 0x12)); self.sseq += 1
            self.pk.append(tcp(cport, sport, b'', self.cseq, self.sseq, client, server, 0x10))
    def c2s(self, data):
        self.pk.append(tcp(self.cp, self.sp, data, self.cseq, self.sseq, self.c, self.s)); self.cseq += len(data)
    def s2c(self, data):
        self.pk.append(tcp(self.sp, self.cp, data, self.sseq, self.cseq, self.s, self.c)); self.sseq += len(data)

def tpkt(payload):
    return struct.pack('!BBH', 3, 0, 4 + len(payload)) + payload

def cotp_dt(payload, eot=True):
    return tpkt(bytes([2, 0xf0, 0x80 if eot else 0x00]) + payload)

def llc_frame(payload, dsap=0xfe, ssap=0xfe, ctl=0x03, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    body = bytes([dsap, ssap, ctl]) + payload
    return dst + src + struct.pack('!H', len(body)) + body

def _crc32c_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        t.append(c)
    return t
_CRC_T = _crc32c_table()

def crc32c(data):
    c = 0xffffffff
    for b in data:
        c = _CRC_T[(c ^ b) & 0xff] ^ (c >> 8)
    return (~c) & 0xffffffff

def sctp_data(sport, dport, payload, ppi=0, tsn=1, sid=0, ssn=0, vtag=0x11223344, src='192.0.2.1', dst='192.0.2.2', flags=3):
    '''SCTP packet with one DATA chunk (B and E flags set by default).'''
    pad = (-len(payload)) % 4
    chunk = struct.pack('!BBHIHHI', 0, flags, 16 + len(payload), tsn, sid, ssn, ppi) + payload + b'\0' * pad
    hdr = struct.pack('!HHII', sport, dport, vtag, 0)
    cs = crc32c(hdr + chunk)
    hdr = struct.pack('!HHI', sport, dport, vtag) + struct.pack('<I', cs)
    pkt = hdr + chunk
    return eth(ipv4(132, pkt, src, dst) + pkt)

def write_pcapng(fn, pkts, linktypes=(1,), snap=262144):
    '''pkts: list of (interface index, bytes). One IDB per link-layer type.'''
    def blk(t, body):
        body += b'\0' * ((-len(body)) % 4)
        return struct.pack('<II', t, 12 + len(body)) + body + struct.pack('<I', 12 + len(body))
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += blk(1, struct.pack('<HHI', lt, 0, snap))
    for i, (ifc, p) in enumerate(pkts):
        ts = 1700000000 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(p), len(p)) + p)
    open(fn, 'wb').write(out)
# --- end helpers ---
# Generator for the SGsAP coverage captures: python3 mksgsap.py <outdir>
# SGsAP runs over SCTP port 29118 (registered by default).
outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
MME, VLR = 49152, 29118

def tbcd(digits):
    d = [int(c) for c in digits]
    if len(d) % 2: d.append(0xf)
    return bytes((d[i + 1] << 4) | d[i] for i in range(0, len(d), 2))

def mobid_imsi(digits):
    d = [int(c) for c in digits]
    first = (d[0] << 4) | (8 if len(d) % 2 else 0) | 1
    rest = d[1:]
    if len(rest) % 2: rest.append(0xf)
    return bytes([first]) + bytes((rest[i + 1] << 4) | rest[i] for i in range(0, len(rest), 2))

def tlv(iei, val):
    if isinstance(val, int): val = bytes([val])
    return bytes([iei, len(val)]) + val

IMSI = tlv(0x01, mobid_imsi('262011234567890'))
IMSI14 = tlv(0x01, mobid_imsi('26201123456789'))
LAI = bytes([0x62, 0xf2, 0x10]) + struct.pack('!H', 0x1234)
LAI2 = bytes([0x13, 0x00, 0x62]) + struct.pack('!H', 0x0abc)
MMEN = tlv(0x09, b'\x03mme\x07example\x03com')
MMEN_ASCII = tlv(0x09, b'mme.epc.mnc001.mcc262.3gppnetwork.org')
VLRN = tlv(0x02, b'\x03vlr\x07example\x03com')
VLRN_ASCII = tlv(0x02, b'vlr.example.net')
TAI = bytes([0x62, 0xf2, 0x10, 0x00, 0x2a])
ECGI = bytes([0x62, 0xf2, 0x10]) + struct.pack('!I', 0x0123456)
SMS_ACK = b'\x09\x04'                          # CP-ACK
SMS_ERR = b'\x09\x10\x11'                      # CP-ERROR, cause 17

def msg(t, *els): return bytes([t]) + b''.join(els)
pk = []
def to_vlr(m, sport=MME): pk.append(sctp_data(sport, VLR, m, tsn=len(pk) + 1, src='192.0.2.1', dst='192.0.2.2'))
def to_mme(m, dport=MME): pk.append(sctp_data(VLR, dport, m, tsn=len(pk) + 1, src='192.0.2.2', dst='192.0.2.1'))

# location update (MME -> VLR) with every optional element, and the answers
to_vlr(msg(0x09, IMSI, MMEN, tlv(0x0a, 1), tlv(0x04, LAI), tlv(0x04, LAI2), tlv(0x07, 0),
           tlv(0x15, bytes.fromhex('3254761032547698ff')[:8]), tlv(0x23, TAI), tlv(0x24, ECGI),
           tlv(0x27, b'\x01\x23'), tlv(0x28, bytes([0x62, 0xf2, 0x10]))))
to_vlr(msg(0x09, IMSI14, MMEN_ASCII, tlv(0x0a, 2), tlv(0x04, LAI)))
to_mme(msg(0x0a, IMSI, tlv(0x04, LAI), tlv(0x0e, bytes([0xf4, 0x11, 0x22, 0x33, 0x44]))))
to_mme(msg(0x0a, IMSI, tlv(0x04, LAI), tlv(0x0e, mobid_imsi('262011234567890'))))
to_mme(msg(0x0a, IMSI, tlv(0x04, LAI)))
to_mme(msg(0x0b, IMSI, tlv(0x0f, 0x11), tlv(0x04, LAI)))
to_mme(msg(0x0b, IMSI, tlv(0x0f, 0x16)))
to_vlr(msg(0x0c, IMSI))                                              # TMSI reallocation complete
# paging (VLR -> MME) with every optional element
to_mme(msg(0x01, IMSI, VLRN, tlv(0x20, 1), tlv(0x03, b'\xaa\xbb\xcc\xdd'),
           tlv(0x1c, bytes([0x91, 0x21, 0x43, 0x65, 0x87])), tlv(0x04, LAI),
           tlv(0x0b, bytes([0x62, 0xf2, 0x10, 0x00, 0x07])), tlv(0x1f, 0x03), tlv(0x1e, 1),
           tlv(0x1d, bytes([0x30, 0x03, 0x80, 0x01, 0x00])), tlv(0x05, 0x02), tlv(0x06, 0x03),
           tlv(0x26, 1)))
to_mme(msg(0x01, IMSI, VLRN_ASCII, tlv(0x20, 2), tlv(0x26, 0)))
to_mme(msg(0x01, IMSI, VLRN, tlv(0x20, 0x55)))
to_vlr(msg(0x02, IMSI, tlv(0x08, 0x06)))                             # paging reject
# service request (with every optional element), abort, release
to_vlr(msg(0x06, IMSI, tlv(0x20, 1), tlv(0x15, bytes.fromhex('3254761032547698')),
           tlv(0x21, 0x40), tlv(0x22, bytes([0x57, 0x18, 0x93])), tlv(0x23, TAI),
           tlv(0x24, ECGI), tlv(0x25, 1)))
to_vlr(msg(0x06, IMSI, tlv(0x20, 2), tlv(0x25, 0)))
to_vlr(msg(0x17, IMSI))                                              # service abort
to_mme(msg(0x1b, IMSI, tlv(0x08, 0x0d)))                             # release request
to_mme(msg(0x1b, IMSI))
to_vlr(msg(0x18, IMSI, tlv(0x23, TAI), tlv(0x24, ECGI)))             # MO CSFB indication
# NAS message containers (SMS)
to_mme(msg(0x07, IMSI, tlv(0x16, SMS_ACK)))                          # downlink unitdata
to_vlr(msg(0x08, IMSI, tlv(0x16, SMS_ERR), tlv(0x15, bytes.fromhex('3254761032547698')), tlv(0x21, 0x40),
           tlv(0x22, bytes([0x57, 0x18, 0x93])), tlv(0x23, TAI), tlv(0x24, ECGI)))
to_vlr(msg(0x08, IMSI, tlv(0x16, SMS_ACK)))
# MM information
to_mme(msg(0x1a, IMSI, tlv(0x17, bytes([0x43, 0x05, 0x80, 0x41, 0x42, 0x43, 0x44, 0x45, 0x04, 0x80, 0x58, 0x59, 0x46, 0x01, 0x40,
                                          0x47, 0x07, 0x62, 0x11, 0x11, 0x20, 0x30, 0x40, 0x50]))))
# alerts, activity, detach
to_mme(msg(0x0d, IMSI)); to_vlr(msg(0x0e, IMSI)); to_vlr(msg(0x0f, IMSI, tlv(0x08, 0x0e)))
to_vlr(msg(0x10, IMSI))
to_vlr(msg(0x11, IMSI, MMEN, tlv(0x10, 1))); to_mme(msg(0x12, IMSI))
to_vlr(msg(0x13, IMSI, MMEN, tlv(0x11, 2))); to_mme(msg(0x14, IMSI))
to_vlr(msg(0x11, IMSI, MMEN, tlv(0x10, 3)))
to_vlr(msg(0x13, IMSI, MMEN, tlv(0x11, 3)))
to_mme(msg(0x1f, IMSI, tlv(0x08, 0x0e)))                             # UE unreachable
# reset
to_vlr(msg(0x15, MMEN, VLRN)); to_mme(msg(0x16, MMEN, VLRN))
to_vlr(msg(0x15, MMEN)); to_mme(msg(0x16, VLRN)); to_vlr(msg(0x15)); to_mme(msg(0x16))
# status with and without an erroneous message (decoded, nested, undecodable)
to_mme(msg(0x1d, IMSI, tlv(0x08, 0x07), tlv(0x1b, msg(0x01, IMSI, VLRN, tlv(0x20, 1)))))
to_mme(msg(0x1d, tlv(0x08, 0x0c), tlv(0x1b, msg(0x03, b'\x01\x02\x03'))))
to_mme(msg(0x1d, tlv(0x08, 0x0c), tlv(0x1b, b'\x7e\x01\x02')))
to_mme(msg(0x1d, tlv(0x08, 0x07)))
nest = msg(0x1d, tlv(0x08, 0x08))
for i in range(4):
    nest = msg(0x1d, tlv(0x08, 0x07), tlv(0x1b, nest))
to_mme(nest)
# other messages: unassigned types (element bytes only) and an unknown type
to_mme(msg(0x03, b'\x01\x02\x03\x04')); to_vlr(msg(0x19, b'')); to_mme(msg(0x1c, b'\xff'))
to_mme(msg(0x7f, b'\x00\x01'))
# the same on another SCTP connection, ports the other way round
to_vlr(msg(0x10, IMSI), sport=VLR)
write(os.path.join(outdir, 'sgsap-coverage.pcap'), pk)

# Malformed capture: missing mandatory elements, extraneous data, truncation
pk = []
to_vlr(msg(0x09, IMSI))                                              # LU request without MME name etc.
to_vlr(msg(0x08, IMSI))                                              # no NAS message container
to_mme(msg(0x02, IMSI))                                              # paging reject without cause
to_mme(msg(0x0a, IMSI, tlv(0x04, LAI), b'\xee\x01\x02'))             # extraneous data
to_vlr(msg(0x0e, IMSI, b'\x99\x99'))
to_mme(msg(0x01, IMSI))
to_vlr(msg(0x09, b'\x01\x08\x29'))                                   # IMSI element longer than the message
to_vlr(msg(0x1a, IMSI, tlv(0x17, b'\x43\x20\x80AB')))                # MM information cut short
to_vlr(msg(0x09, IMSI, MMEN, tlv(0x0a, 1), tlv(0x04, LAI), tlv(0x24, ECGI[:5])))
to_mme(msg(0x1d, tlv(0x08, 0x07), tlv(0x1b, msg(0x01, IMSI, VLRN, tlv(0x20, 1))[:12])))
to_mme(msg(0x1d, tlv(0x08, 0x07), tlv(0x1b, msg(0x09, IMSI, MMEN))))  # erroneous message with missing elements
to_vlr(msg(0x08, IMSI, tlv(0x16, b'\x09')))                          # truncated SMS
to_vlr(b'\x09')
write(os.path.join(outdir, 'sgsap-coverage-malformed.pcap'), pk)
