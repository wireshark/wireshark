#!/usr/bin/env python3
# Generates test/captures/uma_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic UMA (GAN, Unlicensed Mobile Access) coverage captures.
Usage: mkuma.py <outdir> [-v]
Writes uma-coverage.pcap (clean) and uma-coverage-malformed.pcap."""
import struct
import sys
import os

VERBOSE = '-v' in sys.argv
args = [a for a in sys.argv[1:] if a != '-v']
OUT = args[0] if args else '.'

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(s):
    return bytes(int(x) for x in s.split('.'))

def ether(payload, src=b'\x02\0\0\0\0\x01', dst=b'\x02\0\0\0\0\x02'):
    return dst + src + b'\x08\x00' + payload

def ip(proto, payload, src, dst, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64,
                    proto, 0, ip4(src), ip4(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def udp(sp, dp, payload):
    return struct.pack('!HHHH', sp, dp, 8 + len(payload), 0) + payload

class Cap:
    def __init__(self):
        self.frames = []
    def add(self, pkt, note=''):
        self.frames.append((pkt, note))
        return len(self.frames)
    def mark(self, note):
        if VERBOSE:
            print(len(self.frames) + 1, note)
    def write(self, name):
        with open(os.path.join(OUT, name), 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for i, (p, _) in enumerate(self.frames):
                f.write(struct.pack('<IIII', 1700000000 + i // 100,
                                    (i % 100) * 10000, len(p), len(p)) + p)

class Flow:
    """A TCP connection with sequence tracking."""
    def __init__(self, cap, cip, cport, sip, sport):
        self.cap, self.cip, self.cport, self.sip, self.sport = cap, cip, cport, sip, sport
        self.cseq, self.sseq = 1000, 5000
        self.ident = 1
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
        return self.cap.add(ether(ip(6, tcp, si, di, self.ident),
                                  *(() if fromc else (b'\x02\0\0\0\0\x02', b'\x02\0\0\0\0\x01'))))
    def handshake(self):
        self._seg(True, 0x02)
        self._seg(False, 0x12)
        self._seg(True, 0x10)
    def send(self, fromc, payload):
        return self._seg(fromc, 0x18, payload)

# ---------------------------------------------------------------- IEs
def ie(iei, data=b'', long=False):
    if long or len(data) > 127:
        return bytes([iei, 0x80 | (len(data) >> 8), len(data) & 0xff]) + data
    return bytes([iei, len(data)]) + data

MAC = bytes.fromhex('020000aabbcc')
IMSI = bytes.fromhex('1932547698103254')       # IMSI, odd digits
TMSI = bytes.fromhex('f4a1b2c3d4')
IMEI = bytes.fromhex('3a54f6a9b1c2d3e4')
LAI = bytes.fromhex('00f110' '1234')
PLMN = bytes.fromhex('00f110')
NSTR = b'ganc.example.invalid'

# one or more example payloads per IEI that decode cleanly
IEV = {
 1: [IMSI, TMSI, IMEI, bytes.fromhex('00')],
 2: [b'\x01', b'\x02', b'\x03'],
 3: [b'\x00' + MAC, b'\x10' + MAC, b'\x01' + MAC],
 4: [b'\x12\x34'],
 5: [LAI],
 6: [b'\x00', b'\x01', b'\x02', b'\x03'],
 7: [b'\xc8\xb0', b'\x80', b'\x40\x50'],
 8: [bytes.fromhex('00' '123456' '654321'),
     bytes.fromhex('10' '123456' '654321' '0a'),
     bytes.fromhex('30' '123456' '654321' '0a' '0b' '0c' '5a'),
     bytes.fromhex('52' '123456' '654321' 'fedcba' '010203'),
     bytes.fromhex('80' '123456' '654321' '8001'),
     bytes.fromhex('90' '123456' '654321' '0001' '0a' '0b' '0c' '0d' '5a'),
     bytes.fromhex('a0' '123456' '654321' '0010' '0a' '0b' '0c' '5a')],
 9: [b'\x21' + ip4('203.0.113.5'), b'\x57' + bytes(range(16))],
 10: [NSTR],
 11: [b'\x02'],
 12: [b'\x00', b'\x01', b'\x02'],
 13: [bytes.fromhex('2c' '1a')],
 14: [bytes.fromhex('a5' '0c' '07' '85' 'ff' 'c0'), bytes.fromhex('5a' 'ff' '01' '00' '00' '00')],
 15: [bytes.fromhex('00' '00f110' '1234' '0abc'), bytes.fromhex('01' '1234' '0abc'),
      bytes.fromhex('02' '0abc')],
 16: [b'\x00\x3c'],
 17: [b'\x00', b'\x01'],
 18: [bytes.fromhex('00f110' '1234' '05')],
 19: [bytes([i]) for i in range(8)] + [b'\x09'],
 20: [b'\x00', b'\x1d', b'\x06', b'\x12', b'\x01', b'\x02'],
 21: [bytes([i]) for i in range(0, 13)],
 22: [b'\x00\x0a'], 23: [b'\x00\x14'], 24: [b'\x00\x1e'],
 25: [b'\x0b\xb9'],
 26: [bytes.fromhex('05' '18' '01'), bytes.fromhex('05' '2b'), bytes.fromhex('0b' '01')],
 27: [b'\x00', b'\x01', b'\x21'],
 28: [bytes.fromhex('57' '18' '30'), bytes.fromhex('00' '00' '00')],
 29: [b'\x00', b'\x06'],
 30: [b'\x01', b'\x00'],
 31: [b'\x00', b'\x01'],
 32: [bytes.fromhex('06' '0d' '00')],
 33: [b'\x00', b'\x01', b'\x02', b'\x04'],
 34: [bytes.fromhex('c1234567')],
 35: [b'\x00', b'\x01', b'\x7f'],
 36: [b'\x00', b'\x01'],
 37: [b'\x00\x05'],
 38: [b'\x03', b'\x25', b'\x4f'],
 39: [bytes([i]) for i in range(0, 18)],
 40: [bytes.fromhex('000000'), bytes.fromhex('0003e8'), bytes.fromhex('028f5c'),
      bytes.fromhex('028f5d'), bytes.fromhex('ffffff')],
 41: [b'\x03'],
 42: [b'This is an AP location'],
 43: [b'\x00\x0a'],
 44: [b'\x00', b'\x01'],
 45: [b'\x00', b'\x01'],
 46: [bytes(range(0x30, 0x40))],
 47: [bytes(range(0x50, 0x54))],
 48: [b'\x03'],
 49: [b'\x00', b'\x03'],
 50: [bytes([x]) for x in (0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x80, 0xa0, 0xc0, 0xe0, 0xf0)],
 51: [b'\x00', b'\x01', b'\x02', b'\x03'],
 52: [bytes.fromhex('0102030405060708')],
 53: [b'\x14', b'\x28'],
 54: [b'\x60', b'\x7f'],
 55: [bytes.fromhex('28' '00' '0a' '1f')],
 56: [bytes.fromhex('50' + '00' * 9), bytes.fromhex('20' + '00' * 5), bytes.fromhex('7f' + 'ff' * 6)],
 57: [bytes.fromhex('01' 'c0' '0102' '03')],
 58: [b'\x00', b'\x01', b'\x02'],
 59: [b'\x00', b'\x01'],
 60: [b'\x00\x28'],
 61: [b'\x00' + b'hotspot-ssid', b'\x01' + b'pan-service'],
 62: [bytes.fromhex('01' '07') + b'Home-Zn'],
 63: [b'\x00', b'\x41', b'\x82'],
 64: [bytes.fromhex('00' '00' '00')],
 65: [b'\x80', b'\x00'],
 66: [bytes.fromhex('00' '00f110' '1234' '0123456'+'7')],
 67: [b'\x00', b'\x01'],
 68: [b'\x00', b'\x01', b'\x02'],
 69: [bytes.fromhex('02' '1234' '00f110' '00f120')],
 70: [bytes.fromhex('0a141e28')],
 71: [b'\x00', b'\x01'],
 72: [bytes.fromhex('02' '0102030405')],
 73: [bytes.fromhex('00112233')],
 74: [bytes.fromhex('0102')], 75: [b'\x01'], 76: [bytes.fromhex('00000001')],
 77: [bytes.fromhex('00000002')], 78: [bytes.fromhex('0a0b')],
 96: [b'\x00' + MAC, b'\x01' + MAC],
 98: [b'unc.example.invalid'],
 105: [b'\x13\xc5'],
 106: [bytes.fromhex('0a0b0c')],
 107: [bytes.fromhex('0d0e')],
 101: [b'\x01'], 102: [b'\x01'], 113: [b'\x01'], 114: [b'\x01'],
 127: [b'\x01\x02'], 128: [b'\x01\x02\x03'], 129: [b'\x01'],
 200: [b'\x01\x02'],
}
for n in list(range(79, 96)) + list(range(108, 127)):
    IEV.setdefault(n, [b'\x01\x02\x03'])
IEV.setdefault(73, [bytes.fromhex('00112233')])

def v(iei, k=0):
    return ie(iei, IEV[iei][k % len(IEV[iei])])

# Addresses used by the conversations that the IEs set up
UNC_IP = '198.51.100.20'
GPRS_IP = '198.51.100.30'
IE97 = ie(97, b'\x21' + ip4(UNC_IP))
IE99 = ie(99, b'\x21' + ip4(GPRS_IP))
IE103 = lambda p: ie(103, struct.pack('!H', p))
IE100 = lambda p: ie(100, struct.pack('!H', p))
IE104 = lambda p: ie(104, struct.pack('!H', p))

def urr(pd, mtype, ies):
    body = bytes([pd, mtype]) + b''.join(ies)
    return struct.pack('!H', len(body)) + body

def urlc(mtype, tlli, ies):
    body = bytes([2, mtype]) + tlli + b''.join(ies)
    return struct.pack('!H', len(body)) + body

def urlc_udp(mtype, tlli, seq, ies):
    return bytes([mtype]) + tlli + struct.pack('!H', seq) + b''.join(ies)

cap = Cap()
mal = Cap()
CIP, GIP = '192.0.2.10', '198.51.100.1'
TLLI = bytes.fromhex('c0123456')

# ---------------------------------------------------------------- stream 1
f = Flow(cap, CIP, 40001, GIP, 14001)
cap.mark('TCP 14001 handshake')
f.handshake()

URR_PLAN = [
 (1, [v(1), v(3), v(4), v(5), v(6), v(7), v(19), v(68)]),
 (2, [v(9), v(10), v(2), v(69), v(11)]),
 (3, [v(12, 1)]),
 (16, [v(1, 1), v(3), v(5), v(4), v(7, 1), v(28), v(56), v(19, 1), v(68, 1), v(2), v(8, 0)]),
 (17, [v(14), v(13), v(16), v(22), v(23), v(24), v(2, 1), v(69)]),
 (18, [v(9, 1), v(10), v(11)]),
 (19, [v(21, 0), v(21, 10), v(11), v(9)]),
 (20, [v(21, 6)]),
 (21, [v(8, 1), v(18), v(61, 0), v(61, 1), v(62), v(42)]),
 (22, [v(25), v(14, 1), v(67), v(71, 1)]),
 (23, [v(72), v(15), v(66)]),
 (32, [v(46), v(47), v(30), v(45, 1)]),
 (33, [v(45), v(48), v(1, 2)]),
 (48, [v(27), v(53), v(54), v(55), v(63), v(26)]),
 (49, [v(27, 1), v(53, 1), v(38)]),
 (50, [v(27, 2)]),
 (51, [v(29)]),
 (52, [v(27, 1), v(55)]),
 (53, [v(27)]),
 (64, [v(29, 1)]),
 (65, []),
 (66, [v(29, 1)]),
 (80, [v(34), v(49, 1)]),
 (81, []),
 (82, [v(33, 1), v(33, 3)]),
 (83, [v(52), v(7, 2)]),
 (84, [v(32), v(8, 2)]),
 (85, [v(29)]),
 (96, [v(1, 1), v(50, 0), v(51, 2)]),
 (97, [v(1, 0), v(28, 1), v(56, 1), v(7), v(5)]),
 (112, [v(26, 0), v(49, 0)]),
 (113, [v(26, 1), v(50, 0xa0 and 7), v(5), v(4)]),
 (114, [v(26, 2), v(49, 1)]),
 (115, [v(29), v(19), v(59), v(58)]),
 (116, []),
 (117, [v(65), v(65, 1)]),
 (118, [v(56), v(28, 1)]),
 (119, [v(36), v(36, 1), v(35)]),
 (120, [v(70), v(106), v(107), v(8, 3)]),
 (121, [v(64)]),
 (128, [v(50, 3), v(51), v(49)]),
 (129, [v(50, 4)]),
 (130, [v(29, 0), v(12)]),
]
cap.mark('IE 104 before any GANC IP address is known: RTP source = sender of the message')
f.send(True, urr(1, 17, [IE104(15100)]))
cap.add(ether(ip(17, udp(15100, 40300, struct.pack('!BBHII', 0x80, 96, 1, 160, 0x55667788) + bytes(20)), CIP, GIP)))
cap.mark('URR messages, one per message type, one per segment')
for mt, ies in URR_PLAN:
    f.send(True, urr(1, mt, ies))
# URR_C (PD 0) copies of the discovery messages
cap.mark('URR_C (PD 0)')
for mt, ies in URR_PLAN[:6]:
    f.send(mt % 2 == 0, urr(0, mt, ies))

# one more of every IE variant, in messages that carry them
cap.mark('every IE variant (several per message)')
for iei in sorted(IEV):
    n = len(IEV[iei])
    if iei in (97, 99, 100, 103, 104, 105) or n < 1:
        continue
    ies = [v(iei, k) for k in range(n)]
    f.send(iei % 2 == 0, urr(1, 17 if iei % 3 else 16, ies))

# GPRS user data and RTP set-up before stream setup
cap.mark('IEs that set up conversations (IP address first, then ports)')
UDP_PORT = 14002
TCP_PORT = 14010
RTP_PORT = 15000
f.send(True, urr(1, 17, [IE97, IE99, IE100(UDP_PORT), IE103(TCP_PORT), IE104(RTP_PORT)]))
f.send(False, urr(1, 17, [IE104(RTP_PORT + 2), v(105)]))
# IPv6 variants: the IPv4 address is not updated; port 0 for RTP
f.send(True, urr(1, 17, [ie(97, b'\x57' + bytes(range(16))), ie(99, b'\x57' + bytes(range(16))), IE104(0)]))
# a second IE100 for the same address/port does not create a second conversation
f.send(True, urr(1, 17, [IE99, IE100(UDP_PORT)]))
# IE97 with a 4 octet value (IP address type missing)
f.send(True, urr(1, 17, [ie(97, ip4('203.0.113.9'))]))

# IE with a long length form
cap.mark('long length forms (0x80 flag)')
f.send(True, urr(1, 23, [ie(52, bytes(range(150)), long=True), ie(46, bytes(range(16)), long=True),
                          ie(42, b'x' * 300), ie(26, bytes.fromhex('05' '18' '01'), long=True)]))
f.send(True, urr(1, 23, [ie(10, b'', ), ie(98, b'')]))     # empty FQDN: note

# two PDUs in one segment, one PDU in two segments, a PDU with the header split
cap.mark('reassembly: two PDUs in one segment, PDU in 2 and 3 segments')
a = urr(1, 116, [])
b = urr(1, 115, [v(29), v(19)])
f.send(True, a + b)
big = urr(1, 21, [v(8, 1), v(18), v(61, 0), v(42), ie(52, bytes(range(100)))])
f.send(True, big[:20])
f.send(True, big[20:])
f.send(True, urr(1, 23, [v(15), v(66), ie(52, bytes(range(60)))])[:1])
rest = urr(1, 23, [v(15), v(66), ie(52, bytes(range(60)))])[1:]
f.send(True, rest[:1])
f.send(True, rest[1:])
f.send(True, b + a[:3])
f.send(True, a[3:])

# the skip indicator and an unknown protocol discriminator
cap.mark('skip indicator, unknown PD')
f.send(True, struct.pack('!H', 3) + bytes([0x11, 0x20, 0x00]))
f.send(True, struct.pack('!H', 4) + bytes([0x0f, 0x01, 0x00, 0x00]))

# ---------------------------------------------------------------- URLC over TCP
cap.mark('URLC (PD 2) over TCP, message types 1-18')
URLC_IES = [v(34), v(38), v(39), v(40, 1), v(41), v(35), v(57), v(8, 0), v(19), v(60), v(36)]
for mt in range(1, 19):
    f.send(True, urlc(mt, TLLI, [URLC_IES[mt % len(URLC_IES)], URLC_IES[(mt + 3) % len(URLC_IES)]]))
f.send(True, urlc(4, TLLI, []))

# User Data Rate values around the 32 bit overflow of the 100 multiplier
cap.mark('User Data Rate (IE 40) values')
for k in range(5):
    f.send(False, urlc(12, TLLI, [v(40, k)]))

# ---------------------------------------------------------------- URLC over UDP
cap.mark('URLC over UDP (conversation from IE 99/100)')
def udp_pkt(payload, dport=UDP_PORT, dip=GPRS_IP, sport=40100):
    return cap.add(ether(ip(17, udp(sport, dport, payload), CIP, dip)))
udp_pkt(urlc_udp(2, TLLI, 1, [v(57), v(40, 1)]))
udp_pkt(urlc_udp(6, TLLI, 2, [v(38), v(39)]))
udp_pkt(urlc_udp(7, TLLI, 3, [v(40), v(41)]))
udp_pkt(urlc_udp(2, TLLI, 4, []))
udp_pkt(urlc_udp(3, TLLI, 5, [v(39)]))      # wrong message type
udp_pkt(urlc_udp(1, TLLI, 6, []))

# ---------------------------------------------------------------- TCP on the IE 103 port
cap.mark('TCP stream to the port from IE 97/103 (conversation)')
g = Flow(cap, CIP, 40002, UNC_IP, TCP_PORT)
g.handshake()
g.send(True, urr(1, 17, [v(14), v(2)]))
g.send(False, urr(1, 116, []))

# ---------------------------------------------------------------- RTP/RTCP
cap.mark('RTP to the port from IE 104 and RTCP on the next one')
def rtp(seq, sport=RTP_PORT, sip=UNC_IP, pt=96):
    h = struct.pack('!BBHII', 0x80, pt, seq, 160 * seq, 0x11223344)
    return cap.add(ether(ip(17, udp(sport, 40200, h + bytes(20)), sip, CIP)))
rtp(1); rtp(2)
cap.add(ether(ip(17, udp(RTP_PORT + 1, 40201,
        struct.pack('!BBHI', 0x80, 201, 1, 0x11223344) + bytes(20)), UNC_IP, CIP)))

# ---------------------------------------------------------------- a stream carrying an LLC PDU
cap.mark('LLC-PDU IE with U frame, XID, UI and S frames')
h = Flow(cap, '192.0.2.11', 40003, GIP, 14001)
h.handshake()
for llc in ('01' 'ef' '0102', '01' 'ec', '01' 'e0' '0a0b', '03' 'ee', '03' 'e1', '07' 'f1',
            '03' 'c0' '0001' '0a', '01' '80' '01' '00', '01' 'a0' '0100'):
    h.send(True, urlc(1, TLLI, [ie(57, bytes.fromhex(llc) + b'\x00\x00\x00')]))

# LLC UI frame (SAPI 3) -> SNDCP SN-UNITDATA -> IP -> UDP -> UMA URLC (UDP port
# from IE 99/100): the inner UDP packet reaches the UMA conversation again
inner = ip(17, udp(40100, UDP_PORT, urlc_udp(2, TLLI, 7, [v(39), v(40, 3)])), CIP, GPRS_IP)
sndcp = bytes.fromhex('65' '00' '0001') + inner
h.send(True, urlc(1, TLLI, [ie(57, bytes.fromhex('03' 'c0' '00') + sndcp + b'\x00\x00\x00')]))
cap.write('uma-coverage.pcap')

# ================================================================ malformed
# also needs stream 1 style state
m = Flow(mal, '192.0.2.12', 40004, GIP, 14001)
m.handshake()
mal.mark('malformed')
def mw(payload):
    m.send(True, payload)
# unknown radio identity types (warning only), FQDN absent (note) tested in main
mw(urr(1, 16, [ie(3, b'\x01' + MAC), ie(96, b'\x02' + MAC)]))
# Radio Identity with ie_len 0: length -1 bytes
mw(urr(1, 16, [ie(3, b''), ie(96, b'')]))
# IE truncated: length points past the end of the PDU
mw(struct.pack('!H', 6) + bytes([1, 16, 5, 4, 0x12, 0x34]))
mw(struct.pack('!H', 5) + bytes([1, 16, 4, 40, 0x10]))
# fixed length IEs cut short
for iei in (4, 5, 14, 16, 18, 34, 40, 66, 69, 7, 9, 97, 99, 100, 103, 104, 105, 62, 61, 56, 65):
    mw(urr(1, 17, [ie(iei, b'\x01')]))
    mw(urr(1, 17, [ie(iei, b'')]))
# FT_ETHER with the wrong length (exception)
mw(urr(1, 16, [ie(3, b'\x00' + MAC[:3])]))
mw(urr(1, 16, [ie(96, b'\x00' + MAC + b'\x00\x00')]))
# service zone string longer than the IE
mw(urr(1, 21, [ie(62, bytes.fromhex('01' '40') + b'abc')]))
# URLC cut short
mw(struct.pack('!H', 4) + bytes([2, 1, 0xc0, 0x12]))
# PDU of length 1 and 0
mw(struct.pack('!H', 1) + b'\x01')
mw(struct.pack('!H', 0))
# URLC over UDP too short
mal.add(ether(ip(17, udp(40100, UDP_PORT, bytes([2, 0xc0, 0x12])), CIP, GPRS_IP)))
mal.add(ether(ip(17, udp(40100, UDP_PORT, bytes([6, 0xc0, 0x12, 0x34, 0x56, 0x00, 0x01, 40])), CIP, GPRS_IP)))
# a UDP packet with IE100 from the main capture state (stale address) isn't needed
# many levels of the same IE: a message of 600 IEs
mw(urr(1, 17, [v(2)] * 600))
mal.write('uma-coverage-malformed.pcap')
