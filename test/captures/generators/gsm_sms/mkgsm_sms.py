#!/usr/bin/env python3
# Generates test/captures/gsm_sms_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the GSM SMS coverage captures.  Usage: mkgsm_sms.py <outdir>
# SMS TPDUs (3GPP TS 23.040) in RP-DATA / RP-ACK / RP-ERROR (TS 24.011)
# in CP-DATA, in LAPDm I frames on an SDCCH in GSMTAP (UDP 4729), which
# reaches the dissector by default (GSMTAP -> LAPDm -> DTAP -> RP -> SMS).
# Messages in IMS (SIP MESSAGE, application/vnd.3gpp.sms) are included too.
# Everything is synthetic (documentation addresses and numbers).
import os
import struct
import socket
import sys

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

def udp_frame(payload, sport=4729, dport=4729, src='192.0.2.1', dst='192.0.2.2'):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00' + ip + udp

def gsmtap(type_, sub_type, payload, arfcn=0, ts=0, fn=0):
    return struct.pack('!BBBBHbbIBBBB', 2, 4, type_, ts, arfcn, 0, 0, fn,
                       sub_type, 0, 0, 0) + payload

def write_pcap(fn, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

# ---------------------------------------------------------------- helpers
def pack7(text, fill=0):
    """GSM 7 bit packing of plain ASCII text; `fill` zero bits first"""
    bits = 0
    nbits = fill
    out = bytearray()
    for ch in text.encode('ascii'):
        bits |= (ch & 0x7f) << nbits
        nbits += 7
        while nbits >= 8:
            out.append(bits & 0xff)
            bits >>= 8
            nbits -= 8
    if nbits:
        out.append(bits & 0xff)
    return bytes(out)

def bcd(digits):
    d = digits + ('f' if len(digits) % 2 else '')
    return bytes(int(d[i + 1] + d[i], 16) for i in range(0, len(d), 2))

def addr(digits, ton_npi=0x91):
    return bytes([len(digits), ton_npi]) + bcd(digits)

def addr_alnum(text):
    packed = pack7(text)
    return bytes([(len(text) * 7 + 3) // 4, 0xd0]) + packed

def scts(y=26, mo=11, d=5, h=18, mi=30, s=15, tz=0x08):
    """tz in quarter hours, bit 3 of the semi-octet pair holds the sign"""
    def b(v): return ((v % 10) << 4) | (v // 10)
    return bytes([b(y), b(mo), b(d), b(h), b(mi), b(s), tz])

def tz_neg(q):
    v = ((q % 10) << 4) | (q // 10)
    return v | 0x08

# user data
def ud7(text, udh=b'', pad=True):
    """(udl, bytes) for a 7 bit text with an optional UDH"""
    if udh:
        fill = (7 - (len(udh) * 8) % 7) % 7
        data = udh + pack7(text, fill)
        udl = (len(udh) * 8 + fill) // 7 + len(text)
    else:
        data = pack7(text)
        udl = len(text)
    return bytes([udl]) + data

def ud8(data, udh=b''):
    return bytes([len(udh) + len(data)]) + udh + data

def ud16(text, udh=b''):
    data = text.encode('utf-16-be')
    return bytes([len(udh) + len(data)]) + udh + data

def udh(*ies):
    body = b''.join(ies)
    return bytes([len(body)]) + body
def ie(iei, data): return bytes([iei, len(data)]) + data
def concat8(ref, total, seq): return ie(0x00, bytes([ref, total, seq]))
def concat16(ref, total, seq): return ie(0x08, struct.pack('>HBB', ref, total, seq))
def ports8(dst, src): return ie(0x04, bytes([dst, src]))
def ports16(dst, src): return ie(0x05, struct.pack('>HH', dst, src))

# TPDUs
def submit(da, ud, pid=0, dcs=0, vpf=0, vp=b'', mr=1, udhi=False, rd=0, srr=0, rp=0):
    fo = 0x01 | (rd << 2) | (vpf << 3) | (srr << 5) | (0x40 if udhi else 0) | (rp << 7)
    return bytes([fo, mr]) + da + bytes([pid, dcs]) + vp + ud

def deliver(oa, ud, pid=0, dcs=0, ts=None, udhi=False, mms=1, lp=0, sri=0, rp=0):
    fo = 0x00 | (mms << 2) | (lp << 3) | (sri << 5) | (0x40 if udhi else 0) | (rp << 7)
    return bytes([fo]) + oa + bytes([pid, dcs]) + (ts or scts()) + ud

def status_report(ra, ts1, ts2, st, mr=1, pi=None, pid=None, dcs=None, ud=None, udhi=False, mms=1, lp=0, srq=0):
    fo = 0x02 | (mms << 2) | (lp << 3) | (srq << 5) | (0x40 if udhi else 0)
    p = bytes([fo, mr]) + ra + ts1 + ts2 + bytes([st])
    if pi is not None:
        p += bytes([pi])
        if pi & 1: p += bytes([pid])
        if pi & 2: p += bytes([dcs])
        if pi & 4: p += ud
    return p

def command(da, ct=0, mn=1, data=b'', mr=2, pid=0, srr=0, udhi=False):
    fo = 0x02 | (srr << 5) | (0x40 if udhi else 0)
    return bytes([fo, mr, pid, ct, mn]) + da + bytes([len(data)]) + data

def deliver_report(pi=None, fcs=None, pid=None, dcs=None, ud=None, udhi=False):
    p = bytes([0x00 | (0x40 if udhi else 0)])
    if fcs is not None: p += bytes([fcs])
    p += bytes([pi or 0])
    if pi:
        if pi & 1: p += bytes([pid])
        if pi & 2: p += bytes([dcs])
        if pi & 4: p += ud
    return p

def submit_report(ts, pi=0, fcs=None, pid=None, dcs=None, ud=None, udhi=False):
    p = bytes([0x01 | (0x40 if udhi else 0)])
    if fcs is not None: p += bytes([fcs])
    p += bytes([pi]) + ts
    if pi & 1: p += bytes([pid])
    if pi & 2: p += bytes([dcs])
    if pi & 4: p += ud
    return p

# RP layer (TS 24.011); mt: 0/1 RP-DATA MS->N / N->MS, 2/3 RP-ACK, 4/5 RP-ERROR
_b = bcd('491720000000')
SC = bytes([1 + len(_b), 0x91]) + _b      # RP address: length in octets
def rp_data(mt, ref, tp):
    if mt == 0:     # MS to network: no originator, destination is the SC
        oa, da = b'\x00', SC
    else:
        oa, da = SC, b'\x00'
    return bytes([mt, ref]) + oa + da + bytes([len(tp)]) + tp
def rp_ack(mt, ref, tp=None):
    return bytes([mt, ref]) + (bytes([0x41, len(tp)]) + tp if tp else b'')
def rp_error(mt, ref, cause, tp=None):
    return bytes([mt, ref, 1, cause]) + (bytes([0x41, len(tp)]) + tp if tp else b'')
def rp_smma(ref): return bytes([6, ref])

def cp_data(rp):
    return bytes([0x09, 0x01, len(rp)]) + rp

class Cap:
    def __init__(self):
        self.frames = []
        self.fn = 0
        self.ns = {True: 0, False: 0}
    def l3(self, l3, up):
        """one LAPDm I frame (L3 of at most 63 octets) on an SDCCH"""
        assert len(l3) <= 63, len(l3)
        ns = self.ns[up]
        self.ns[up] = (ns + 1) % 8
        lapdm = bytes([(3 << 2) | (0 if up else 2) | 1, (ns << 1), (len(l3) << 2) | 1]) + l3
        a = 0x4000 if up else 0
        self.frames.append(udp_frame(gsmtap(1, 6, lapdm, arfcn=a, fn=self.fn)))
        self.fn += 51
    def rp(self, rp):
        up = rp[0] in (0, 2, 4, 6)
        self.l3(cp_data(rp), up)
    def data(self, mt, ref, tp):
        self.rp(rp_data(mt, ref, tp))
    def raw(self, payload):
        self.frames.append(udp_frame(gsmtap(1, 6, payload, fn=self.fn)))
        self.fn += 51
    def sip(self, rp, frm, to, cseq, branch):
        body = rp
        msg = ('MESSAGE sip:%s@ims.example.net SIP/2.0\r\n'
               'Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK%s\r\n'
               'From: <sip:%s@ims.example.net>;tag=%s\r\n'
               'To: <sip:%s@ims.example.net>\r\n'
               'Call-ID: sms%s@192.0.2.1\r\n'
               'CSeq: %d MESSAGE\r\n'
               'Content-Type: application/vnd.3gpp.sms\r\n'
               'Content-Length: %d\r\n\r\n') % (to, branch, frm, branch, to, branch, cseq, len(body))
        self.frames.append(udp_frame(msg.encode() + body, 5060, 5060))

DA = addr('46701234567')
OA = addr('46709876543')

def build(outdir):
    c = Cap()
    t = c.data
    # --- SMS-SUBMIT (MS to network, RP-DATA type 0)
    t(0, 1, submit(DA, ud7('HELLO')))
    t(0, 2, submit(addr('0701234567', 0x81), ud7('National number'), srr=1, rd=1, rp=1))
    t(0, 3, submit(addr_alnum('Alpha'), ud7('Alphanumeric destination')))
    t(0, 4, submit(addr('1234', 0xa1), ud7('Abbreviated')))
    t(0, 5, submit(addr('', 0x81), ud7('No digits')))
    # validity period formats: relative (every range), absolute, enhanced
    for i, v in enumerate((0, 11, 143, 144, 167, 168, 196, 197, 255)):
        t(0, 10 + i, submit(DA, ud7('VP'), vpf=2, vp=bytes([v])))
    t(0, 20, submit(DA, ud7('VP abs'), vpf=3, vp=scts(26, 12, 31, 23, 59, 0, 0x04)))
    t(0, 21, submit(DA, ud7('VP abs'), vpf=3, vp=scts(26, 12, 31, 23, 59, 0, tz_neg(8))))
    t(0, 22, submit(DA, ud7('VPE none'), vpf=1, vp=bytes([0x00]) + bytes(6)))
    t(0, 23, submit(DA, ud7('VPE relative'), vpf=1, vp=bytes([0x01, 0xa7]) + bytes(5)))     # fix reproducer
    t(0, 24, submit(DA, ud7('VPE seconds'), vpf=1, vp=bytes([0x42, 0x1e]) + bytes(5)))
    t(0, 25, submit(DA, ud7('VPE hms'), vpf=1, vp=bytes([0x03, 0x12, 0x30, 0x45]) + bytes(3)))
    t(0, 26, submit(DA, ud7('VPE reserved'), vpf=1, vp=bytes([0x07]) + bytes(6)))
    t(0, 27, submit(DA, ud7('VPE ext'), vpf=1, vp=bytes([0x80]) + bytes(6)))
    # --- data coding schemes and protocol identifiers
    for i, dcs in enumerate((0x00, 0x01, 0x04, 0x08, 0x0c, 0x10, 0x11, 0x14, 0x18, 0x20, 0x24, 0x28, 0x2c,
                             0x40, 0x41, 0x42, 0x43, 0x44, 0x48, 0x60, 0x80, 0x90, 0xa0, 0xb0,
                             0xc0, 0xc8, 0xd0, 0xd8, 0xe0, 0xe8, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8)):
        if dcs & 0x0c == 8 or (dcs & 0xf0) == 0xe0:
            ud = ud16('Hej')
        elif dcs & 0x0c == 4 or (dcs & 0xf0) == 0xf0 and dcs & 4:
            ud = ud8(b'bin')
        else:
            ud = ud7('Text')
        t(0, 30 + i % 200, submit(DA, ud, dcs=dcs))
    for i, pid in enumerate((0x00, 0x20, 0x21, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3a, 0x3b, 0x1f, 0x00 | 0x1f,
                             0x40, 0x41, 0x47, 0x48, 0x5e, 0x5f, 0x7c, 0x7d, 0x7f, 0x80, 0xbf, 0xc0, 0xff)):
        t(0, 80 + i, submit(DA, ud7('PID'), pid=pid))
    # --- user data headers: every information element
    ies = [
        ie(0x01, b'\x80\x05'), ie(0x01, b'\x8d\x03'), ie(0x01, b'\x01\x00'), ie(0x01, b'\x1f\x01'),       # special SMS indication
        ie(0x04, b'\x0b\x84'), ie(0x05, b'\x0b\x84\x23\xf0'), ie(0x06, b'\x3f'), ie(0x07, b'\x02'),
        ie(0x0a, b'\x00\x05\x1b\x39'), ie(0x0a, b'\x03\x04\x2a'),      # text formatting (with and without colour)
        ie(0x0b, b'\x00\x07'), ie(0x0c, b'\x01\xaa\xbb'), ie(0x0d, b'\x02\x03'), ie(0x0e, b'\x00\x11\x22\x33'),
        ie(0x0f, b'\x00\x11\x22\x33'), ie(0x10, b'\x00\x11\x22\x33'), ie(0x11, b'\x00\x11\x22\x33'),
        ie(0x12, b'\x00\x08\x08\x01\x02\x03'), ie(0x13, b'\x02'), ie(0x24, b'\x01'), ie(0x24, b'\x0d'),
        ie(0x25, b'\x01'), ie(0x25, b'\x0d'), ie(0x09, b'\x00\x01'), ie(0x14, b'abc'), ie(0x70, b'xy'),
        ie(0x20, b'\x01\x02\x03'), ie(0x21, b''), ie(0x22, b'\x01\x02\x03\x04\x05'), ie(0xc0, b'\x01'),
        ie(0x23, b'\x01'), ie(0x1f, b'\x01'), ie(0x17, b'\x01\x02'), ie(0x1a, b'\x01'),
    ]
    for i, x in enumerate(ies):
        t(0, 100 + i, submit(DA, ud7('H', udh(x)), udhi=True))
    # several IEs in one header, 8 bit and UCS2 data with a UDH
    t(0, 140, submit(DA, ud8(b'Bin', udh(ports16(5000, 5001), ie(0x07, b'\x01'))), dcs=0x04, udhi=True))
    t(0, 141, submit(DA, ud16('Hej', udh(concat8(1, 1, 1))), dcs=0x08, udhi=True))
    # fill bits for every UDH length (7 bit data)
    for n in range(0, 8):
        t(0, 150 + n, submit(DA, ud7('Fill', udh(ie(0x70, bytes(n)))), udhi=True))
    t(0, 160, submit(DA, ud7('Compressed'), dcs=0x20))
    t(0, 161, submit(DA, ud8(b'\x01\x02\x03\x04'), dcs=0x20 | 0x04))
    # ports that WSP claims
    t(0, 162, submit(DA, ud8(b'\x01\x06\x01\x83Hello', udh(ports16(2948, 9200))), dcs=0x04, udhi=True))
    t(0, 163, submit(DA, ud8(b'\x01\x06\x01\x83Hello', udh(ports8(0x40, 0x41))), dcs=0x04, udhi=True))
    # --- concatenated SMS (reassembled)
    for n, part in enumerate(('First part, ', 'second part, ', 'last part.'), 1):
        t(0, 170 + n, submit(DA, ud7(part, udh(concat8(0x42, 3, n))), udhi=True))
    for n, part in enumerate(('Part A', 'Part B'), 1):
        t(0, 175 + n, submit(DA, ud16(part, udh(concat16(0x1234, 2, n))), dcs=0x08, udhi=True))
    for n, part in enumerate((b'\x01\x06\x01', b'\x83Hello WSP'), 1):
        t(0, 180 + n, submit(DA, ud8(part, udh(concat8(0x43, 2, n), ports16(2948, 9200))), dcs=0x04, udhi=True))
    # fragments of one message arriving out of order and one with a repeated part
    t(0, 190, submit(DA, ud7('second', udh(concat8(0x44, 2, 2))), udhi=True))
    t(0, 191, submit(DA, ud7('first', udh(concat8(0x44, 2, 1))), udhi=True))
    t(0, 192, submit(DA, ud7('one', udh(concat8(0x45, 2, 1))), udhi=True))
    t(0, 193, submit(DA, ud7('one', udh(concat8(0x45, 2, 1))), udhi=True))
    t(0, 194, submit(DA, ud7('two', udh(concat8(0x45, 2, 2))), udhi=True))
    # --- SMS-DELIVER (network to MS, RP-DATA type 1)
    t(1, 1, deliver(OA, ud7('Delivered')))
    t(1, 2, deliver(OA, ud7('More'), mms=0, lp=1, sri=1, rp=1, ts=scts(tz=tz_neg(12))))
    t(1, 3, deliver(addr_alnum('Bank'), ud7('Your code is 1234'), pid=0x40, dcs=0x10, ts=scts(26, 12, 31, 23, 59, 59, tz_neg(20))))
    t(1, 4, deliver(OA, ud16('Grüße'), dcs=0x08))
    t(1, 5, deliver(OA, ud7('Voicemail'), dcs=0xc0))
    t(1, 6, deliver(OA, ud7('Voicemail', udh(ie(0x01, b'\x80\x05'))), dcs=0xd0, udhi=True))
    t(1, 7, deliver(OA, b'\x00', dcs=0xc0, pid=0x40))
    t(1, 8, deliver(OA, b'\x00', dcs=0x00))
    for n, part in enumerate(('Deliver one, ', 'deliver two, ', 'deliver three'), 1):
        t(1, 10 + n, deliver(OA, ud7(part, udh(concat8(0x50, 3, n))), udhi=True))
    for n, part in enumerate(('Dele ', 'Delf '), 1):
        t(1, 15 + n, deliver(OA, ud16(part, udh(concat16(0x5151, 2, n))), udhi=True, dcs=0x08))
    # --- SMS-STATUS-REPORT (network to MS, RP-DATA type 1)
    for i, st in enumerate((0x00, 0x01, 0x02, 0x10, 0x20, 0x21, 0x25, 0x30, 0x40, 0x41, 0x46, 0x50, 0x60, 0x65, 0x70, 0x7f, 0x80)):
        t(1, 30 + i, status_report(DA, scts(), scts(26, 11, 5, 18, 30, 20, tz_neg(4)), st, mr=i))
    t(1, 50, status_report(DA, scts(), scts(), 0x00, pi=0x00, mms=0, lp=1, srq=1))
    t(1, 51, status_report(DA, scts(), scts(), 0x00, pi=0x07, pid=0, dcs=0, ud=ud7('Info')))
    t(1, 52, status_report(DA, scts(), scts(), 0x00, pi=0x03, pid=0x40, dcs=0x04))
    t(1, 53, status_report(DA, scts(), scts(), 0x00, pi=0x07, pid=0x40, dcs=0x04, ud=ud8(b'xy', udh(ie(0x07, b'\x01'))), udhi=True))
    t(1, 54, status_report(DA, scts(), scts(), 0x00, pi=0x01, pid=0x41))
    t(1, 55, status_report(DA, scts(), scts(), 0x00, pi=0x04, ud=ud8(b'zz')))
    # --- SMS-COMMAND (MS to network, RP-DATA type 0)
    for i, ct in enumerate((0, 1, 2, 3, 4, 0x20, 0xe0)):
        t(0, 60 + i, command(DA, ct=ct, mn=3))
    t(0, 70, command(DA, ct=0, data=b'cmd data', srr=1, pid=0x40))
    # --- reports in RP-ACK / RP-ERROR
    ack = lambda mt, ref, tp=None: c.rp(rp_ack(mt, ref, tp))
    err = lambda mt, ref, cause, tp=None: c.rp(rp_error(mt, ref, cause, tp))
    ack(2, 1)
    ack(2, 2, deliver_report(pi=0x00))
    ack(2, 3, deliver_report(pi=0x07, pid=0x00, dcs=0x00, ud=ud7('ACK')))
    ack(2, 4, deliver_report(pi=0x03, pid=0x40, dcs=0x08))
    ack(2, 5, deliver_report(pi=0x05, pid=0x00, ud=ud7('ACK')))
    ack(2, 6, deliver_report(pi=0x06, dcs=0x04, ud=ud8(b'bin')))
    ack(2, 7, deliver_report(pi=0x07, pid=0x00, dcs=0x08, ud=ud16('Hej'), udhi=False))
    ack(2, 8, deliver_report(pi=0x07, pid=0x00, dcs=0x04, ud=ud8(b'ack', udh(ie(0x07, b'\x01'))), udhi=True))
    err(4, 9, 0x16, deliver_report(fcs=0xd3, pi=0x00))
    err(4, 10, 0x16, deliver_report(fcs=0x84, pi=0x07, pid=0x00, dcs=0x00, ud=ud7('ERR')))
    err(4, 11, 0x20)
    ack(3, 1, submit_report(scts(), pi=0x00))
    ack(3, 2, submit_report(scts(), pi=0x07, pid=0, dcs=0, ud=ud7('Sub')))
    ack(3, 3, submit_report(scts(), pi=0x03, pid=0x40, dcs=0x04))
    ack(3, 4, submit_report(scts(), pi=0x05, pid=0x40, ud=ud8(b'abc')))
    ack(3, 5, submit_report(scts(), pi=0x07, pid=0, dcs=0x04, ud=ud8(b'abc', udh(ie(0x07, b'\x01'))), udhi=True))
    ack(3, 6, submit_report(scts(), pi=0x01, pid=0x40))
    err(5, 7, 0x16, submit_report(scts(), fcs=0xc0, pi=0x00))
    err(5, 8, 0x16, submit_report(scts(), fcs=0xd0, pi=0x07, pid=0, dcs=0x08, ud=ud16('Err')))
    err(5, 9, 0x16, submit_report(scts(), fcs=0x80, pi=0x07, pid=0, dcs=0x00, ud=ud7('Err')))
    # reserved TPDU types and RP-SMMA
    c.data(0, 90, bytes([0x03, 0, 0]))
    c.data(1, 91, bytes([0x03, 0, 0]))
    c.rp(rp_smma(92))

    # --- SIP: SMS over IMS; three fragments with different From/To
    c.sip(rp_data(0, 1, submit(DA, ud7('IMS one, ', udh(concat8(0x60, 2, 1))), udhi=True)), '46709876543', '46701234567', 1, 'a1')
    c.sip(rp_data(0, 2, submit(DA, ud7('IMS two', udh(concat8(0x60, 2, 2))), udhi=True)), '46709876543', '46701234567', 2, 'a2')
    c.sip(rp_data(1, 3, deliver(OA, ud7('IMS deliver'))), '46701234567', '46709876543', 3, 'a3')

    # --- malformed capture
    b = Cap()
    t = b.data
    t(0, 1, submit(bytes([20, 0x91, 1, 2]), b''))                  # address cut off
    t(0, 2, submit(bytes([2, 0x91, 0x21]), b''))
    t(0, 3, bytes([0x09, 1]))
    t(0, 4, bytes([0x09, 1, 0x02, 0x91, 0x21, 0, 0, 0xaa]))      # VPF 1 with 1 octet
    t(0, 5, bytes([0x19, 1, 0x02, 0x91, 0x21, 0, 0, 0xaa, 0xbb]))   # VPF 3 short
    t(0, 6, bytes([0x11, 1, 0x02, 0x91, 0x21, 0, 0, 0xaa, 0xbb]))   # enhanced, short
    t(1, 7, bytes([0x00, 0x02, 0x91]))                              # deliver, short
    t(1, 8, bytes([0x02, 1, 0x02, 0x91, 0x21] + list(scts())))       # status report, short
    t(1, 9, bytes([0x02, 1, 0x02, 0x91, 0x21] + list(scts()) + list(scts()) + [0]))
    t(1, 10, bytes([0x02, 1, 0x02, 0x91, 0x21] + list(scts()) + [1, 2, 3]))
    t(1, 11, bytes([0x02, 1, 0x02, 0x91, 0x21] + list(scts()) + list(scts()) + [0, 0x01]))   # PI says PID, nothing follows
    t(1, 12, bytes([0x02, 1, 0x02, 0x91, 0x21] + list(scts()) + list(scts()) + [0, 0x02]))
    t(1, 13, bytes([0x02, 1, 0x02, 0x91, 0x21] + list(scts()) + list(scts()) + [0, 0x04]))
    b.rp(rp_ack(2, 14, bytes([0x00])))                             # deliver report, short
    b.rp(rp_ack(2, 15, bytes([0x00, 0x01])))                       # PI says PID, nothing follows
    b.rp(rp_ack(2, 16, bytes([0x00, 0x02])))
    b.rp(rp_ack(2, 17, bytes([0x00, 0x04])))
    b.rp(rp_ack(3, 18, bytes([0x01, 0x01]) + scts()))
    b.rp(rp_ack(3, 19, bytes([0x01, 0x02]) + scts()))
    b.rp(rp_ack(3, 20, bytes([0x01, 0x04]) + scts()))
    b.rp(rp_ack(3, 21, bytes([0x01, 0x00, 1, 2, 3])))
    # UDH with a truncated IE, IE length running over the UDH
    t(0, 22, submit(DA, bytes([5, 3, 0x00, 5, 1, 2]), udhi=True))
    t(0, 23, submit(DA, bytes([3, 4, 0x00, 5, 1, 2, 3]), udhi=True))
    t(0, 24, submit(DA, bytes([8]) + bytes([2, 0x00, 1, 0x0a, 2, 5, 6, 0x24, 0]), udhi=True))
    t(0, 25, submit(DA, ud7('x', udh(ie(0x00, b'\x01\x02'), ie(0x08, b'\x01'), ie(0x04, b'\x01'), ie(0x05, b'\x01'),
                                 ie(0x06, b''), ie(0x07, b'\x01\x02'), ie(0x01, b'\x01'), ie(0x0a, b'\x01'), ie(0x0b, b'\x01'),
                                 ie(0x0c, b'\x01'))), udhi=True))
    t(0, 26, submit(DA, ud7('x', udh(ie(0x0d, b'\x01'), ie(0x0e, b'\x01'), ie(0x0f, b'\x01'), ie(0x10, b'\x01'),
                                 ie(0x11, b'\x01'), ie(0x12, b'\x01\x02\x03'), ie(0x13, b'\x01\x02'), ie(0x24, b'\x01\x02'),
                                 ie(0x25, b'\x01\x02'))), udhi=True))
    # fragments with frag 0 / frags 1 / frag larger than frags, conflicting parts
    t(0, 27, submit(DA, ud7('zero', udh(concat8(0x70, 2, 0))), udhi=True))
    t(0, 28, submit(DA, ud7('big', udh(concat8(0x71, 2, 5))), udhi=True))
    t(0, 29, submit(DA, ud7('aaa', udh(concat8(0x72, 2, 1))), udhi=True))
    t(0, 30, submit(DA, ud7('bbb', udh(concat8(0x72, 2, 1))), udhi=True))
    t(0, 31, submit(DA, ud7('ccc', udh(concat8(0x72, 2, 2))), udhi=True))
    t(0, 32, submit(DA, ud7('ddd', udh(concat16(0x7272, 3, 1))), udhi=True))
    t(0, 33, submit(DA, ud7('eee', udh(concat16(0x7272, 3, 3))), udhi=True))
    t(0, 34, submit(DA, ud7('fff', udh(concat16(0x7272, 3, 2))), udhi=True))
    # UDL larger than the data, 8 bit UDL 255, UCS2 odd length
    t(0, 35, submit(DA, bytes([160]) + pack7('short')))
    t(0, 36, submit(DA, bytes([255]) + b'abc', dcs=0x04))
    t(0, 37, submit(DA, bytes([3]) + b'\x00\x41\x00', dcs=0x08))
    # an address of 20 digits with an alphanumeric 11 octets
    t(0, 38, submit(bytes([22, 0xd0]) + pack7('Longalphanumeric'), ud7('x')))
    # RP errors
    b.rp(bytes([0, 1]))              # RP-DATA cut off
    b.rp(bytes([0, 1, 5]))
    b.rp(bytes([1, 2, 0, 0]))
    b.rp(bytes([4, 3]))
    b.rp(bytes([4, 3, 1, 0x16, 0x41, 9, 1]))
    b.rp(bytes([2, 4, 0x41, 9]))
    write_pcap(os.path.join(outdir, 'gsm_sms-coverage.pcap'), c.frames)
    write_pcap(os.path.join(outdir, 'gsm_sms-coverage-malformed.pcap'), b.frames)
    print(len(c.frames), len(b.frames))

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
