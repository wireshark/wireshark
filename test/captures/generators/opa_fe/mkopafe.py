#!/usr/bin/env python3
# Generates test/captures/opa_fe_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic Omni-Path FE (Fabric Executive) coverage capture: FE messages (24 byte header +
# one MAD) over TCP 3245-3248 (Ethernet, IPv4, TCP).  Synthetic addresses (192.0.2.0/24),
# MAD payloads from a seeded PRNG.
# Usage: mkopafe.py <outdir>
import struct
import random
import sys
import os
import zlib

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

def fill(key, n):
    r = random.Random(zlib.crc32(key.encode()))
    out = bytearray()
    for _ in range(n):
        x = r.random()
        out.append(0 if x < 0.5 else (r.randrange(1, 4) if x < 0.75 else r.randrange(256)))
    return bytes(out)

def mad_hdr(cls, method, attr, amod, tid, status=0, hop=(0, 0)):
    mid = struct.pack('>BB', *hop) if cls == 0x81 else b'\0\0'
    return struct.pack('>BBBB', 0x80, cls, 0x80, method) + struct.pack('>H', status) + mid + \
        struct.pack('>QHHI', tid, attr, 0, amod)

def rmpp(rtype, flags, seg=1, plen=0):
    return struct.pack('>BBBBII', 1, rtype, flags, 0, seg, plen)

def fe(mad, magic=0x3141, version=1, res=0, length_field=None):
    total = 24 + len(mad)
    return struct.pack('>IIIIQ', magic, total, version, total if length_field is None else length_field, res) + mad

# MADs (sizes fitted so that every record decodes completely, see opa-mad-coverage)
def sm_lid_resp(attr, amod, n, tid):
    return mad_hdr(0x01, 0x81, attr, amod, tid) + struct.pack('>Q', 0x1234) + fill('sm%d' % attr, n)

def sm_dr_resp(attr, amod, n, tid):
    return mad_hdr(0x81, 0x81, attr, amod, tid, 0, (1, 2)) + struct.pack('>QII', 0x1234, 0x11, 0x22) + \
        fill('ip', 64) + fill('rp', 64) + b'\0' * 8 + fill('dr%d' % attr, n)

def sa_resp(attr, ao, nrec, tid, flags=0x07, seg=1, last=True, method=0x92):
    data = fill('sa%d%d' % (attr, seg), ao * 8 * nrec)
    return mad_hdr(0x03, method, attr, 0, tid) + rmpp(1, flags, seg, 20 + len(data)) + \
        struct.pack('>QHHQ', 0, ao, 0, 0) + data

def pa_resp(attr, ao, nrec, tid, flags=0x07, seg=1, method=0x92):
    data = fill('pa%d%d' % (attr, seg), ao * 8 * nrec)
    return mad_hdr(0x32, method, attr, 0, tid) + rmpp(1, flags, seg, 20 + len(data)) + \
        struct.pack('>QHHQ', 0, ao, 0, 0) + data

def pm_resp(attr, amod, n, tid):
    return mad_hdr(0x04, 0x81, attr, amod, tid) + fill('pm%d' % attr, n)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return (~s) & 0xffff

class Stream:
    def __init__(self, cap, cport, sport, caddr, saddr):
        self.cap, self.cport, self.sport, self.caddr, self.saddr = cap, cport, sport, caddr, saddr
        self.cseq, self.sseq, self.ipid = 1000, 5000, 1
    def seg(self, from_client, flags, payload=b''):
        if from_client:
            sp, dp, s, a, src, dst = self.cport, self.sport, self.cseq, self.sseq, self.caddr, self.saddr
            esrc, edst = b'\x02\0\0\0\0\x01', b'\x02\0\0\0\0\x02'
        else:
            sp, dp, s, a, src, dst = self.sport, self.cport, self.sseq, self.cseq, self.saddr, self.caddr
            esrc, edst = b'\x02\0\0\0\0\x02', b'\x02\0\0\0\0\x01'
        t = struct.pack('>HHIIBBHHH', sp, dp, s, a if flags & 0x10 else 0, 0x50, flags, 65535, 0, 0) + payload
        pseudo = src + dst + struct.pack('>BBH', 0, 6, len(t))
        t = t[:16] + struct.pack('>H', csum(pseudo + t)) + t[18:]
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(t), self.ipid, 0x4000, 64, 6, 0, src, dst)
        self.ipid += 1
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        self.cap.append(esrc[:0] + edst + esrc + b'\x08\x00' + ip + t)
        adv = len(payload) + (1 if flags & 0x03 else 0)
        if from_client: self.cseq += adv
        else: self.sseq += adv
    def open(self):
        self.seg(True, 0x02); self.seg(False, 0x12); self.seg(True, 0x10)
    def close(self):
        self.seg(True, 0x11); self.seg(False, 0x11); self.seg(True, 0x10)
    def send(self, from_client, data):
        self.seg(from_client, 0x18, data)
        self.seg(not from_client, 0x10)

def blk(t, b):
    b += b'\0' * ((4 - len(b) % 4) % 4)
    return struct.pack('<II', t, len(b) + 12) + b + struct.pack('<I', len(b) + 12)

def write_pcapng(path, recs):
    with open(path, 'wb') as f:
        f.write(blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        f.write(blk(1, struct.pack('<HHI', 1, 0, 0)))
        for k, d in enumerate(recs):
            ts = 1600000000 * 10**6 + k * 1000
            f.write(blk(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xFFFFFFFF, len(d), len(d)) + d))

C, S = bytes([192, 0, 2, 10]), bytes([192, 0, 2, 20])

def build(outdir):
    recs = []
    # connection 1: TCP 3245, requests and responses of every class
    s = Stream(recs, 40001, 3245, C, S)
    s.open()
    s.send(True, fe(mad_hdr(0x01, 0x01, 0x11, 0, 1) + struct.pack('>Q', 0x1234)))           # SM Get NodeInfo
    s.send(False, fe(sm_lid_resp(0x11, 0, 48, 1)))                                           # GetResp NodeInfo
    s.send(True, fe(mad_hdr(0x81, 0x01, 0x15, 0x01000001, 2, 0, (0, 1)) + struct.pack('>QII', 0x1234, 0x11, 0x22) + fill('ip', 64) + fill('rp', 64) + b'\0' * 8))
    s.send(False, fe(sm_dr_resp(0x15, 0x01000001, 256, 2)))                                  # directed route PortInfo
    s.send(True, fe(mad_hdr(0x03, 0x12, 0x11, 0, 3) + rmpp(0, 0) + struct.pack('>QHHQ', 0, 0, 0, 0)))  # SA GetTable
    s.send(False, fe(sa_resp(0x11, 16, 3, 3)))                                               # SA NodeRecords
    s.send(False, fe(sa_resp(0x11, 16, 2, 4, flags=0x03, seg=1)))                            # RMPP first segment, never reassembled
    s.send(False, fe(sa_resp(0x11, 16, 2, 4, flags=0x05, seg=2)))                            # RMPP last segment
    s.send(True, fe(mad_hdr(0x32, 0x12, 0xA1, 0, 5) + rmpp(0, 0) + struct.pack('>QHHQ', 0, 12, 0, 0) + fill('pareq', 96)))  # PA GetTable
    s.send(False, fe(pa_resp(0xA1, 96, 2, 5)))                                               # PA GroupInfo
    s.send(False, fe(pa_resp(0xAE, 48, 2, 6)))                                                # PA VFInfo
    s.send(True, fe(mad_hdr(0x04, 0x01, 0x40, 0x01000000, 7) + fill('pmq', 8)))             # PM PortStatus Get
    s.send(False, fe(pm_resp(0x40, 0x01000000, 1280, 7)))                                    # PM PortStatus
    # two PDUs in one segment, one PDU split over three segments, a PDU with a TCP push after each
    a = fe(sm_lid_resp(0x10, 0, 64, 8))
    b = fe(sm_lid_resp(0x12, 0, 96, 9))
    s.send(False, a + b)
    big = fe(sm_lid_resp(0x15, 0x01000001, 256, 10))
    s.seg(False, 0x18, big[:10]); s.seg(True, 0x10)
    s.seg(False, 0x18, big[10:100]); s.seg(True, 0x10)
    s.seg(False, 0x18, big[100:]); s.seg(True, 0x10)
    # other header contents: another magic and header version, reserved bits set, a MAD with a status error
    s.send(False, fe(sm_lid_resp(0x10, 0, 64, 11), magic=0x4D414421, version=2, res=0x0123456789ABCDEF))
    s.send(False, fe(mad_hdr(0x01, 0x81, 0x11, 0, 12, 0x0004) + struct.pack('>Q', 0x1234) + fill('err', 48)))
    # a vendor class MAD
    s.send(True, fe(mad_hdr(0x09, 0x81, 0x1234, 7, 13) + fill('vendor', 40)))
    s.close()
    # connections on the other ports of the range
    for port in (3246, 3247, 3248):
        t = Stream(recs, 41000 + port, port, C, S)
        t.open()
        t.send(True, fe(mad_hdr(0x01, 0x01, 0x01, 0, port) + struct.pack('>Q', 0x1234)))
        t.send(False, fe(sm_lid_resp(0x01, 0, 80, port)))
        t.send(False, fe(pm_resp(0x42, 0x01000000, 2048, port + 1)))
        t.close()
    write_pcapng(os.path.join(outdir, 'opa-fe-coverage.pcapng'), recs)
    print(len(recs), 'frames')

def build_malformed(outdir):
    # paths only malformed input reaches: bogus lengths, a message without a MAD, a truncated MAD,
    # a message that never completes (one connection each: a bogus length loses the framing)
    recs = []
    cases = [
        struct.pack('>IIIIQ', 0x3141, 0, 1, 24, 0) + bytes(8),                          # length 0
        struct.pack('>IIIIQ', 0x3141, 10, 1, 10, 0) + bytes(8),                         # shorter than the header
        fe(b''),                                                                         # header only, no MAD
        fe(mad_hdr(0x01, 0x81, 0x11, 0, 20) + struct.pack('>Q', 1) + fill('trunc', 10)),  # MAD cut short
        fe(mad_hdr(0x03, 0x92, 0x11, 0, 21)[:20]),                                       # MAD header cut short
        struct.pack('>IIIIQ', 0x3141, 1000, 1, 1000, 0) + fill('never', 16),            # never completes
    ]
    for i, data in enumerate(cases):
        s = Stream(recs, 42001 + i, 3245 + i % 4, C, S)
        s.open()
        s.send(True, data)
        s.close()
    write_pcapng(os.path.join(outdir, 'opa-fe-coverage-malformed.pcapng'), recs)
    print(len(recs), 'frames (malformed)')

if __name__ == '__main__':
    build(OUT)
    build_malformed(OUT)
