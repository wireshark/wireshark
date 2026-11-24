#!/usr/bin/env python3
# Generates test/captures/goose_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the GOOSE and R-GOOSE
dissector (packet-goose.c, generated from asn1/goose).  Everything is
built with struct; nothing comes from a real network.
Usage: mkgoose.py <output directory>

GOOSE runs over Ethernet (ethertype 0x88b8).  R-GOOSE is carried in a
CLTP UD TPDU over UDP (found by the CLTP-over-UDP heuristic, which looks
for the GOOSE SPDU id 0xa1 after the CLTP header).

Writes:
  goose-coverage.pcap            GOOSE PDUs with every Data type, the
                                 management PDUs (requests and responses),
                                 simulation bit combinations; R-GOOSE with
                                 and without padding and HMAC octets
  goose-coverage-malformed.pcap  length below 8, an unknown PDU tag, bad
                                 UtcTime, cut-short and oversized fields
"""
import os
import sys
import struct
import socket

def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            orig = len(fr)
            if isinstance(fr, tuple):      # (captured bytes, original length)
                fr, orig = fr
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(fr), orig))
            f.write(fr)

def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def pcapng(path, idbs, frames):
    """idbs: list of linktypes; frames: list of (idb index, bytes)"""
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

def ip4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def udp(sp, dp, payload):
    return struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload

def eth(dst, src, et, payload):
    return dst + src + struct.pack('>H', et) + payload

def tcpseg(src, dst, sp, dp, seq, ack, flags, payload=b'', ident=1, win=65535):
    """Ethernet/IPv4/TCP segment with correct checksums."""
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
    if flags == 0x02:
        ack = 0
    h = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, win, 0, 0)
    h = h[:20] + opts
    ps = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 6, len(h) + len(payload))
    c = csum(ps + h + payload)
    h = h[:16] + struct.pack('>H', c) + h[18:]
    return eth(bytes.fromhex('020000000002'), bytes.fromhex('020000000001'), 0x0800,
               ip4(src, dst, 6, h + payload, ident))

class Flow:
    """One TCP connection; client = 10.0.0.1, server = 10.0.0.2."""
    def __init__(self, cport, sport, frames, cip='10.0.0.1', sip='10.0.0.2', cseq=1000, sseq=5000):
        self.c, self.s, self.cp, self.sp, self.f = cip, sip, cport, sport, frames
        self.cseq, self.sseq = cseq, sseq
    def _send(self, from_client, flags, data=b''):
        if from_client:
            fr = tcpseg(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, flags, data)
            self.cseq += len(data) + (1 if flags & 3 else 0)
        else:
            fr = tcpseg(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, flags, data)
            self.sseq += len(data) + (1 if flags & 3 else 0)
        self.f.append(fr)
    def open(self):
        self._send(True, 0x02)
        self._send(False, 0x12)
        self._send(True, 0x10)
    def c2s(self, data): self._send(True, 0x18, data)
    def s2c(self, data): self._send(False, 0x18, data)
    def ack_c(self): self._send(True, 0x10)
    def ack_s(self): self._send(False, 0x10)
    def fin_s(self, data=b''): self._send(False, 0x19, data)
    def fin_c(self): self._send(True, 0x11)
    def close(self):
        self.fin_s(); self.fin_c(); self.ack_s()


# ---- BER
def tlv(tag, content=b''):
    n = len(content)
    if n < 0x80: l = bytes([n])
    elif n < 0x100: l = bytes([0x81, n])
    else: l = bytes([0x82]) + struct.pack('>H', n)
    return bytes([tag]) + l + content

def ber_int(v):
    n = max(1, (v.bit_length() + 8) // 8) if v >= 0 else max(1, ((~v).bit_length() + 8) // 8)
    return v.to_bytes(n, 'big', signed=True)

def utc8(secs=1700000000, frac24=0x800000, q=0x0a):
    return struct.pack('>I', secs) + frac24.to_bytes(3, 'big') + bytes([q])

def oid_bytes(s):
    p = [int(x) for x in s.split('.')]
    out = bytes([40 * p[0] + p[1]])
    for x in p[2:]:
        enc = [x & 0x7f]; x >>= 7
        while x:
            enc.insert(0, 0x80 | (x & 0x7f)); x >>= 7
        out += bytes(enc)
    return out

def data_items():
    """One of every Data choice, an array and a structure holding some."""
    return b''.join([
        tlv(0xa1, tlv(0x85, ber_int(1)) + tlv(0x85, ber_int(-2))),            # array
        tlv(0xa2, tlv(0x83, b'\x01') + tlv(0x86, ber_int(300))),               # structure
        tlv(0x83, b'\x00'),                                                     # boolean
        tlv(0x84, b'\x03\xa0'),                                                 # bit-string
        tlv(0x85, ber_int(-1000)),                                              # integer
        tlv(0x86, ber_int(65535)),                                              # unsigned
        tlv(0x87, b'\x08' + struct.pack('>f', 49.95)),                          # floating-point (single)
        tlv(0x87, b'\x0b' + struct.pack('>d', 1.5)),                            # floating-point (other)
        tlv(0x88, b'\x80\x00\xa0'),                                             # real
        tlv(0x89, b'\xde\xad\xbe\xef'),                                         # octet-string
        tlv(0x8a, b'visible'),                                                  # visible-string
        tlv(0x8c, struct.pack('>IH', 12345678, 19000)),                         # binary-time (6)
        tlv(0x8c, struct.pack('>I', 12345678)),                                 # binary-time (4)
        tlv(0x8d, ber_int(1234)),                                               # bcd
        tlv(0x8e, b'\x05\xe0'),                                                 # booleanArray
        tlv(0x8f, oid_bytes('1.0.61850.7.2')),                                  # objId
        tlv(0x90, 'mms äö string'.encode()),                           # mMSString
        tlv(0x91, utc8()),                                                      # utc-time
    ])

def goose_pdu(gocb='GCB1', ttl=2000, dat='DS1', goid='ID1', t=None, st=1, sq=0, sim=None,
              conf=1, nds=None, nentries=0, data=None):
    t = utc8() if t is None else t
    b = tlv(0x80, gocb.encode()) + tlv(0x81, ber_int(ttl)) + tlv(0x82, dat.encode())
    if goid is not None: b += tlv(0x83, goid.encode())
    b += tlv(0x84, t) + tlv(0x85, ber_int(st)) + tlv(0x86, ber_int(sq))
    if sim is not None: b += tlv(0x87, b'\xff' if sim else b'\x00')
    b += tlv(0x88, ber_int(conf))
    if nds is not None: b += tlv(0x89, b'\xff' if nds else b'\x00')
    d = data_items() if data is None else data
    b += tlv(0x8a, ber_int(nentries)) + tlv(0xab, d)
    return tlv(0x61, b)

def gse_mgmt(state, rr):
    return tlv(0x60, tlv(0x80, ber_int(state)) + rr)

def gse_pdus():
    vs = lambda tag, s: tlv(tag, s.encode())
    req = lambda c: tlv(0xa1, c)
    resp = lambda c: tlv(0xa2, c)
    out = []
    out.append(gse_mgmt(1, req(tlv(0xa1, vs(0x80, 'GCB1') + tlv(0xa1, tlv(0x02, ber_int(1)) + tlv(0x02, ber_int(70000)))))))   # getGoReference (INTEGER SEQUENCE)
    out.append(gse_mgmt(2, req(tlv(0xa2, vs(0x80, 'GCB1') + tlv(0xa1, vs(0x1a, 'ref/one') + vs(0x1a, 'ref/two'))))))          # getGOOSEElementNumber
    out.append(gse_mgmt(3, req(tlv(0xa3, vs(0x80, 'GCB2') + tlv(0xa1, tlv(0x02, ber_int(4)))))))                              # getGsReference
    out.append(gse_mgmt(4, req(tlv(0xa4, vs(0x80, 'GCB2') + tlv(0xa1, vs(0x1a, 'x/y'))))))                                    # getGSSEDataOffset
    out.append(gse_mgmt(5, resp(tlv(0x80, b''))))                                                                              # not supported
    pos = lambda results, dat=True: tlv(0xa2, (vs(0x80, 'DS1') if dat else b'') + tlv(0xa1, results))
    results = tlv(0x80, ber_int(3)) + vs(0x81, 'ref/one') + tlv(0x82, ber_int(1))
    for k in (1, 2, 3, 4):
        out.append(gse_mgmt(10 + k, resp(tlv(0xa0 + k, vs(0x80, 'GCB1') + tlv(0x81, ber_int(7)) + pos(results)))))
    out.append(gse_mgmt(20, resp(tlv(0xa1, vs(0x80, 'GCB1') + pos(results, dat=False)))))
    out.append(gse_mgmt(21, resp(tlv(0xa1, vs(0x80, 'GCB1') + tlv(0x83, ber_int(2))))))                                       # responseNegative
    return out

def goose_eth(appid, pdus, res1=0, res2=0, length=None, dst='010ccd010001', src='020000000011', vlan=None):
    body = b''.join(pdus)
    ln = 8 + len(body) if length is None else length
    h = struct.pack('>HHHH', appid, ln, res1, res2)
    et = struct.pack('>H', 0x88b8)
    if vlan is not None:
        et = struct.pack('>HHH', 0x8100, vlan, 0x88b8)
    return bytes.fromhex(dst) + bytes.fromhex(src) + et + h + body

def rgoose(apdus, spdu_num=1, iv=b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c', padding=None, hmac=None,
           cur_key=0x65000000, next_key=3600, key_id=7, version=1, payload_len=None):
    """Session header, security information and payload.  apdus: list of
    (tag, simulation, appid, pdu bytes).  The HMAC octets are a fixed
    pattern, not a computed value."""
    pl = b''
    for tag, sim, appid, pdu in apdus:
        pl += struct.pack('>BBHH', tag, sim, appid, 6 + len(pdu)) + pdu
    user = struct.pack('>I', len(pl) if payload_len is None else payload_len) + pl
    if padding is not None:
        user += bytes([0xaf, len(padding)]) + padding
    if hmac is not None:
        user += hmac
    sec = struct.pack('>IHIB', cur_key, next_key, key_id, len(iv)) + iv
    rest = struct.pack('>IIH', 0, spdu_num, version) + sec
    spdu_len = len(rest) - 4 + len(user)
    rest = struct.pack('>IIH', spdu_len, spdu_num, version) + sec
    hdr = bytes([0xa1, 2 + len(rest), 0x80, len(rest)]) + rest
    return hdr + user

def cltp(payload, params=b''):
    return bytes([1 + len(params), 0x40]) + params + payload

def udp_frame(sport, dport, payload, src='10.0.0.1', dst='10.0.0.2'):
    return eth(bytes.fromhex('020000000002'), bytes.fromhex('020000000001'), 0x0800,
               ip4(src, dst, 17, udp(sport, dport, payload)))

def build(path_main, path_bad):
    f = []
    g = goose_pdu
    f.append(goose_eth(0x1000, [g()]))                                           # every Data type
    f.append(goose_eth(0x1001, [g(goid=None, sim=True, nds=True, st=2, sq=5, ttl=0, nentries=3,
                                  data=tlv(0x83, b'\x01') + tlv(0x85, ber_int(5)))], res1=0x8000))
    f.append(goose_eth(0x1002, [g(sim=False, data=tlv(0x83, b'\x00'))], res1=0x8000))   # S bit, simulation clear: warning
    f.append(goose_eth(0x1003, [g(sim=True, data=b'')], res1=0x0000, res2=0x1234))   # simulation, S bit clear; empty allData
    f.append(goose_eth(0x1004, [g(gocb='VLAN', data=tlv(0x86, ber_int(1)))], vlan=0x2005))
    f.append(goose_eth(0x1005, [g(st=3), g(st=4, data=tlv(0x85, ber_int(7))), gse_pdus()[0]]))   # several PDUs in a frame
    f.append(goose_eth(0x1006, [g(gocb='G' * 64, dat='D' * 64, goid='I' * 64, ttl=2 ** 31 - 1, st=2 ** 32 - 1, sq=2 ** 32 - 1,
                                  conf=2 ** 32 - 1, nentries=100, data=tlv(0xa2, tlv(0xa1, tlv(0xa2, tlv(0x83, b'\x01')))))]))
    for i, m in enumerate(gse_pdus()):
        f.append(goose_eth(0x2000 + i, [m]))
    # R-GOOSE (CLTP UD TPDU over UDP port 102)
    pdu = g(data=tlv(0x85, ber_int(42)) + tlv(0x83, b'\x01'))
    f.append(udp_frame(40000, 102, cltp(rgoose([(0x81, 0, 0x3000, pdu)]))))
    f.append(udp_frame(40000, 102, cltp(rgoose([(0x81, 0, 0x3001, g(st=2))], padding=b'\0' * 6, hmac=bytes(range(16))))))
    f.append(udp_frame(40001, 102, cltp(rgoose([(0x81, 1, 0x3002, g(sim=True, st=3)), (0x81, 0, 0x3003, g(st=4))],
                                                spdu_num=2, hmac=bytes(range(32, 48))))))
    f.append(udp_frame(40001, 102, cltp(rgoose([(0x82, 0, 0x3004, b'\x60\x00' * 4)], spdu_num=3))))       # sample value tag: not decoded
    f.append(udp_frame(40002, 102, cltp(rgoose([(0x81, 0, 0x3005, g(st=5))], iv=b'', padding=b'', cur_key=0))))   # no IV, empty padding
    f.append(udp_frame(40002, 102, cltp(rgoose([(0x81, 0, 0x3006, g(st=6))], spdu_num=4),
                                        b'\xc1\x02\x00\x01\xc2\x02\x00\x02')))                              # with TSAP parameters
    f.append(udp_frame(40003, 3333, cltp(rgoose([(0x81, 0, 0x3007, gse_pdus()[4])], spdu_num=5))))       # another port (heuristic)
    pcap(path_main, f)

    m = []
    pdu = g()
    m.append(goose_eth(0x4000, [pdu], length=4))                                  # length below 8
    m.append(goose_eth(0x4001, [pdu], length=0))
    m.append(goose_eth(0x4002, [tlv(0x65, tlv(0x80, b'x'))]))                      # unknown application tag: zero length PDU
    m.append(goose_eth(0x4003, [pdu[:20]]))                                        # cut short
    m.append(goose_eth(0x4004, [g(t=b'\x00' * 7)]))                                # UtcTime of 7 octets
    m.append(goose_eth(0x4005, [g(t=b'\x00' * 9, data=tlv(0x91, b'1234'))]))       # UtcTime of 9 octets, utc-time of 4
    m.append(goose_eth(0x4006, [g(data=tlv(0x87, b'\x08\x00'))]))                  # floating point too short
    m.append(goose_eth(0x4007, [g(data=tlv(0x84, b'') + tlv(0x8f, b'') + tlv(0x8c, b'\x01'))]))   # empty bit string, object id, odd time
    m.append(goose_eth(0x4008, [pdu], length=200))                                 # length beyond the frame
    m.append(goose_eth(0x4009, [tlv(0x60, tlv(0x80, ber_int(1)) + tlv(0xa3, b'\x01\x02'))]))   # management PDU with an unknown choice
    m.append(goose_eth(0x400a, [g(sim=True)], res1=0x8000)[:30])                    # truncated header+PDU
    m.append(goose_eth(0x400b, []))                                                # header only
    # R-GOOSE
    m.append(udp_frame(41000, 102, cltp(rgoose([(0x81, 0, 0x5000, pdu)], payload_len=5000))))     # payload length beyond the data
    m.append(udp_frame(41000, 102, cltp(rgoose([(0x81, 0, 0x5001, pdu)], padding=b'\0' * 4)[:-2])))   # padding cut short
    m.append(udp_frame(41000, 102, cltp(rgoose([(0x81, 0, 0x5002, pdu)])[:-10])))                 # APDU cut short
    m.append(udp_frame(41000, 102, cltp(rgoose([(0x81, 0, 0x5003, b'\x65\x00' + bytes(30))]))))   # unknown PDU tag inside the payload
    m.append(udp_frame(41000, 102, cltp(rgoose([(0x81, 0, 0x5004, b'')]) + bytes(20))))        # empty APDU
    m.append(udp_frame(41000, 102, cltp(rgoose([(0x81, 0, 0x5005, g(t=bytes(5)))]))))           # bad UtcTime in R-GOOSE
    m.append(udp_frame(41000, 102, cltp(rgoose([(0x81, 0, 0x5006, pdu)], iv=bytes(200))[:40]))) # IV beyond the data
    m.append(udp_frame(41000, 102, cltp(b'\xa1' + bytes(10))))                                  # heuristic: too short
    pcap(path_bad, m)

if __name__ == '__main__':
    out = sys.argv[1]
    build(os.path.join(out, 'goose-coverage.pcap'), os.path.join(out, 'goose-coverage-malformed.pcap'))
