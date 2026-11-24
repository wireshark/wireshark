#!/usr/bin/env python3
# Generates test/captures/zvt_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the ZVT coverage captures: mkzvt.py <outdir>.
ZVT (the German ECR to payment terminal protocol) has no default port:
  - TCP/IP form on port 20007: needs -o zvt.tcp.port:20007 (or Decode As);
  - serial form and the TCP/IP APDUs without TCP framing: Exported PDU
    (link type 252) naming the "zvt" dissector, as in a capture of a serial
    line converted by a tool; no option needed.
The main capture is a pcapng with both interfaces (Ethernet and Exported
PDU).  Card numbers, passwords and amounts are made up."""
import struct
import sys
import os

A, B = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
MA, MB = b'\x02\x00\x00\x00\x00\x01', b'\x02\x00\x00\x00\x00\x02'
STX, ETX, ACK, DLE, NAK = 2, 3, 6, 0x10, 0x15

def ipck(ip):
    ck = sum(struct.unpack('>10H', ip)); ck = (ck & 0xffff) + (ck >> 16); ck = (ck & 0xffff) + (ck >> 16)
    return ip[:10] + struct.pack('>H', ~ck & 0xffff) + ip[12:]

class Conn:
    def __init__(self, cport, sport):
        self.cport, self.sport = cport, sport
        self.cseq, self.sseq = 1000, 5000
        self.id = 1
    def _pkt(self, fromc, payload, seq, ack):
        if fromc:
            s, d, sp, dp, ms, md = A, B, self.cport, self.sport, MA, MB
        else:
            s, d, sp, dp, ms, md = B, A, self.sport, self.cport, MB, MA
        tcp = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 5 << 4, 0x18, 65535, 0, 0)
        self.id += 1
        ip = ipck(struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), self.id, 0, 64, 6, 0, s, d))
        return md + ms + b'\x08\x00' + ip + tcp + payload
    def c(self, payload):   # ECR -> terminal
        p = self._pkt(True, payload, self.cseq, self.sseq); self.cseq += len(payload); return p
    def s(self, payload):   # terminal -> ECR
        p = self._pkt(False, payload, self.sseq, self.cseq); self.sseq += len(payload); return p

def exp_pdu(payload, name='zvt'):
    n = name.encode() + b'\0'
    n += b'\0' * ((4 - len(n) % 4) % 4)
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload

def bcd(s):
    s = s + ('f' if len(s) % 2 else '')
    return bytes.fromhex(s)

def apdu(ctrl, payload=b'', force_long=False):
    if len(payload) < 255 and not force_long:
        return struct.pack('>H', ctrl) + bytes([len(payload)]) + payload
    return struct.pack('>H', ctrl) + b'\xff' + struct.pack('<H', len(payload)) + payload

def completion(payload=b'', neg=False, aprc=0x00):
    return bytes([0x84 if neg else 0x80, aprc]) + bytes([len(payload)]) + payload

def tlen(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return b'\x81' + bytes([n])
    return b'\x82' + struct.pack('>H', n)

def tlv(tag, val=b''):
    t = tag if isinstance(tag, bytes) else bytes([tag])
    return t + tlen(len(val)) + val

def container(seq):
    return b'\x06' + tlen(len(seq)) + seq

def crc16(data):
    # CRC-CCITT (init 0, reflected) of the serial frame, as a plain checksum
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc

def serial(ap):
    body = ap + bytes([DLE, ETX])
    return bytes([DLE, STX]) + ap + bytes([DLE, ETX]) + struct.pack('<H', crc16(ap + bytes([ETX])))

def llvar(s):      # "F0 F8" style length, then the data
    return bytes([0xf0 | (len(s) // 10), 0xf0 | (len(s) % 10)]) + s
def lllvar(s):
    return bytes([0xf0 | (len(s) // 100), 0xf0 | ((len(s) // 10) % 10), 0xf0 | (len(s) % 10)]) + s

# bitmaps
def b_amount(a): return b'\x04' + bcd('%012d' % a)
def b_cc(cc=0x0978): return b'\x49' + struct.pack('>H', cc)
def b_res(c=0): return b'\x27' + bytes([c])
def b_trace(n=123): return b'\x0b' + bcd('%06d' % n)
def b_time(t='123456'): return b'\x0c' + bcd(t)
def b_date(d='0412'): return b'\x0d' + bcd(d)
def b_exp(d='2912'): return b'\x0e' + bcd(d)
def b_tid(t='12345678'): return b'\x29' + bcd(t)
def b_cardtype(t=10): return b'\x8a' + bytes([t])

def full_status():
    return (b_res(0) + b_amount(1250) + b_trace(123) + b_time() + b_date() + b_exp() + b'\x17\x00\x01' + b'\x19\x40'
            + b'\x22' + llvar(b'\x00' * 0)[:0] + bytes([0xf0, 0xf8]) + bcd('4000123456789010')
            + b_tid() + b'\x2a' + b'CONTRACT0000001' + b'\x3a\x01\x23' + b'\x3b' + bytes(range(1, 9))
            + b'\x3c' + lllvar(b'ABCDEFG') + b_cc() + b'\x87\x00\x07' + b_cardtype(10) + b'\x8b' + llvar(b'VISA')
            + b'\x01\x05' + b'\x02\x03' + b'\x03\x00' + b'\x05\x01')

def main(out):
    # ---- TCP/IP form, port 20007: (the first element tells the interface: 0 Ethernet, 1 Exported PDU)
    fr = []
    # a capture that starts with a completion (the request is before the capture): no transaction yet
    fr.append((1, exp_pdu(completion())))
    c = Conn(40700, 20007)
    pw = b'\x12\x34\x56'
    # registration with the optional CC, service byte and a TLV container with text lines and receipt parameters
    reg_tlv = container(tlv(0x26, tlv(0x0a, b'\x06\x01') + tlv(0x0a, b'\x06\x0f')) + tlv(0x12, b'\x24') + tlv(0x27, b'\x01\x02'))
    fr.append((0, c.c(apdu(0x0600, pw + b'\x86' + struct.pack('>H', 0x0978) + b'\x03\x00' + reg_tlv))))        # 1
    fr.append((0, c.s(completion())))                                                                             # 2 positive completion
    fr.append((0, c.c(apdu(0x0601, b_amount(1250) + b_cc(0x0978) + b'\x19\x40' + b_trace(1)))))                  # 3 authorisation
    fr.append((0, c.s(apdu(0x04ff, b'\x0a\x1e' + b'\x3c' + lllvar(b'Insert card') ))))                          # 4 intermediate status
    fr.append((0, c.s(apdu(0x040f, full_status()))))                                                              # 5 status information
    fr.append((0, c.s(completion())))                                                                             # 6 completion of frame 3? (pending request)
    fr.append((0, c.s(apdu(0x061e, b'\x6c' + b_res(0x6c) + b'\x01\x14'))))                                       # 7 abort
    fr.append((0, c.c(apdu(0x0630, pw + b_trace(77) + b_amount(1)))))                                             # 8 reversal
    fr.append((0, c.s(completion(neg=True, aprc=0x6c))))                                                          # 9 negative completion
    fr.append((0, c.c(apdu(0x0631, pw + b_amount(999) + b_cc(0x0840)))))                                          # 10 refund
    fr.append((0, c.s(completion())))                                                                             # 11
    fr.append((0, c.c(apdu(0x0650, b''))))                                                                        # 12 end of day (no payload)
    fr.append((0, c.c(apdu(0x0650, b'\x01\x02\x03'))))                                                            # 13 end of day, payload shown as data
    fr.append((0, c.c(apdu(0x0670, b''))))                                                                        # 14 diagnosis
    fr.append((0, c.c(apdu(0x0693, pw))))                                                                         # 15 initialisation
    fr.append((0, c.s(apdu(0x06d1, b'\x00' + b'Text on the printer'))))                                          # 16 print line (data)
    fr.append((0, c.s(apdu(0x06d3, b'\x06' + tlen(0) + b''))))                                                    # 17 print text, empty container
    # print text with several levels of subsequences, text lines (CP437 umlauts), receipt tags
    lines = tlv(0x07, b'Zahlung \x84 \x94 \x81') + tlv(0x07, b'Betrag 12,50 EUR') + tlv(0x09, b'\x01') + tlv(0x07, b'Long text line ' * 9)
    rcpt = (tlv(b'\x1f\x07', b'\x02') + tlv(b'\x1f\x04', b'\xc3') + tlv(b'\x1f\x37', b'\x87')
            + tlv(b'\x1f\x10', b'\x01') + tlv(b'\x1f\x11', b'\x00') + tlv(b'\x1f\x12', b'\x0a'))
    pt = container(tlv(0x25, lines + tlv(0x2f, tlv(0x24, tlv(0x07, b'level three')))) + rcpt + tlv(0x40, b'\x01') + tlv(0x41, b'\x02')
                   + tlv(0x45, b'\x03') + tlv(0x60, b'\x04') + tlv(0x24, b'') + tlv(b'\x1f\x80\x01', b'\xaa'))
    fr.append((0, c.s(apdu(0x06d3, pt))))                                                                         # 18
    # a TLV with an invalid length byte after a valid one (stops the sequence, no stale length)
    fr.append((0, c.s(apdu(0x06d3, container(tlv(0x07, b'abc') + b'\x07\x83\x00\x00\x00' + b'\x07\x01X')))))     # 19
    # tags: more than 4 octets
    fr.append((0, c.s(apdu(0x06d3, container(tlv(0x07, b'ok') + b'\x1f\x81\x81\x81\x81\x01\x01\x00')))))        # 20
    # authorisation shorter than the minimum length: expert info
    fr.append((0, c.c(apdu(0x0601, b'\x19\x40\x01\x01\x00\x00'))))                                                           # 21
    # three-byte length form, an APDU in two segments and two APDUs in a segment
    big = container(tlv(0x25, b''.join(tlv(0x07, b'line %03d ' % i + b'x' * 20) for i in range(12))))
    fr.append((0, c.s(apdu(0x06d3, big))))                                                                        # 22 (length > 255)
    p = apdu(0x040f, b_res(0) + b_amount(5) + b_cc())
    fr.append((0, c.s(p[:2]))); fr.append((0, c.s(p[2:])))                                                        # 23-24 split inside the header, then rest
    p = apdu(0x040f, b_res(0) + b_trace(5))
    fr.append((0, c.s(p[:6]))); fr.append((0, c.s(p[6:])))                                                        # 25-26 split inside the payload
    p = apdu(0x06d3, big, force_long=True)
    fr.append((0, c.s(p[:4]))); fr.append((0, c.s(p[4:])))                                                        # 27-28 split in the 3-byte length
    fr.append((0, c.s(apdu(0x040f, b_res(0)) + apdu(0x040f, b_res(0) + b_trace(9)))))                              # 29 two APDUs in a segment
    fr.append((0, c.c(b'\x06\x99\x00')))                                                                          # 30 not a ZVT control field (not dissected)

    # ---- Exported PDU, serial form and bare TCP/IP APDUs
    fr.append((1, exp_pdu(serial(apdu(0x0601, b_amount(500) + b_cc() + b'\x19\x40')))))                           # 31 serial authorisation
    fr.append((1, exp_pdu(bytes([ACK]))))                                                                         # 32
    fr.append((1, exp_pdu(serial(apdu(0x040f, b_res(0) + b_amount(500) + b_cc())))))                              # 33
    fr.append((1, exp_pdu(bytes([ACK]))))                                                                         # 34
    fr.append((1, exp_pdu(bytes([NAK]))))                                                                         # 35
    fr.append((1, exp_pdu(serial(completion()))))                                                                 # 36 serial completion
    fr.append((1, exp_pdu(serial(apdu(0x0999, b'\x01\x02')))))                                                   # serial APDU with an unknown control field
    fr.append((1, exp_pdu(serial(completion(neg=True, aprc=0x01)))))                                              # its completion (no APDU info for the request)
    fr.append((1, exp_pdu(apdu(0x040f, b_res(0) + b_amount(42))))) # 37 bare APDU
    fr.append((1, exp_pdu(completion(neg=True, aprc=0x6f))))                                                      # 38 bare negative completion
    # fix: BCD with stop digits (0xf nibbles): a short or empty string is shown as it is
    fr.append((1, exp_pdu(apdu(0x040f, b'\x0c\xff\xff\xff' + b'\x0d\xff\xff' + b'\x0e\xff\xff')))) # 39
    fr.append((1, exp_pdu(apdu(0x040f, b'\x0c\x12\x3f\xff' + b'\x0d\x04\x1f' + b'\x0e\x29\xff'))))               # 40 stop digit after some digits
    fr.append((1, exp_pdu(apdu(0x040f, b'\x23\xff')))) # 41 track 2 (no length, no handler)
    fr.append((1, exp_pdu(apdu(0x040f, b'\x0b\x00\x00\x01\x2d\xff')))) # 42
    # nesting of subsequences: 3 levels and 8 levels (the limit is 8 levels: up to 8 are decoded)
    def nest(n):
        inner = tlv(0x07, b'deepest')
        for _ in range(n):
            inner = tlv(0x24, inner)
        return inner
    fr.append((1, exp_pdu(apdu(0x040f, container(nest(3))))))                                                     # 43 3 levels
    fr.append((1, exp_pdu(apdu(0x040f, container(nest(8))))))                                                     # 44 8 levels (the limit)
    fr.append((1, exp_pdu(apdu(0x040f, container(nest(2) + nest(2) + tlv(0x26, nest(2))))))) # 45 several shallow sequences, depth is restored
    write_pcapng(os.path.join(out, 'zvt-coverage.pcapng'), fr)

    bad = []
    # recursion reproducer: nesting past the limit (9 and 12 levels) and, deeper, 300 levels (stays small enough)
    bad.append((1, exp_pdu(apdu(0x040f, container(nest(9))))))
    bad.append((1, exp_pdu(apdu(0x040f, container(nest(12))))))
    bad.append((1, exp_pdu(apdu(0x040f, container(nest(300), ), force_long=True))))
    bad.append((1, exp_pdu(apdu(0x040f, container(nest(8) + nest(9) + nest(1))))))
    # TLV objects: tag or length cut short; length byte 0x80 and 0x83 (invalid)
    bad.append((1, exp_pdu(apdu(0x040f, b'\x06\x82\x00\x10' + b'\x07\x82\x00')))) # length field cut
    bad.append((1, exp_pdu(apdu(0x040f, b'\x06\x03' + b'\x1f\x81\x81')))) # tag cut
    bad.append((1, exp_pdu(apdu(0x040f, b'\x06\x82\x01\x00' + b'\x07\x03abc')))) # container longer than the APDU
    bad.append((1, exp_pdu(apdu(0x040f, b'\x06\x05' + b'\x07\x80xx'))))
    bad.append((1, exp_pdu(apdu(0x040f, b'\x06\x82\x00\x04' + b'\x07\x81\xf0x'))))
    # bitmaps and fields cut short
    bad.append((1, exp_pdu(apdu(0x040f, b'\x22\xf0\xf9\x40\x00'))))      # card number longer than the data
    bad.append((1, exp_pdu(apdu(0x040f, b'\x8b\xf0\xf9AB'))))             # card name longer than the data
    bad.append((1, exp_pdu(apdu(0x040f, b'\x3c\xf9\xf9\xf9AB'))))        # additional data longer than the data
    bad.append((1, exp_pdu(apdu(0x040f, b'\x04\x00\x00'))))              # amount cut
    bad.append((1, exp_pdu(apdu(0x040f, b'\x0c\x12'))))                  # time cut
    bad.append((1, exp_pdu(apdu(0x040f, b'\x29\x12'))))                  # terminal id cut
    bad.append((1, exp_pdu(apdu(0x0600, b'\x12\x34'))))                  # registration shorter than the password
    bad.append((1, exp_pdu(apdu(0x0693, b'\x12'))))                      # init shorter than the password
    bad.append((1, exp_pdu(apdu(0x061e, b''))))                          # abort without result code (len 0 skips payload)
    bad.append((1, exp_pdu(apdu(0x04ff, b'\x01'))))                      # intermediate status, length 1
    bad.append((1, exp_pdu(b'\x04\x0f\x20' + b'\x01' * 10)))             # APDU longer than the data (incomplete)
    bad.append((1, exp_pdu(bytes([DLE, STX, 0x04, 0x0f, 0x10] + [0] * 5))))   # serial frame with an incomplete APDU
    bad.append((1, exp_pdu(bytes([DLE, STX]) + apdu(0x040f, b_res(0)))))   # serial frame cut after the APDU (no DLE ETX CRC)
    bad.append((1, exp_pdu(bytes([DLE])))) # one octet, not ACK or NAK: not ZVT
    bad.append((1, exp_pdu(b'\x99\x99\x00')))                              # unknown control field
    bad.append((1, exp_pdu(b'\x04\x0f')))                                  # shorter than a minimal APDU
    # TCP/IP with an APDU claiming more than the segment holds (waits for more data)
    c = Conn(40703, 20007)
    # a completion followed by a request in the same segment: on the second pass the completion
    # finds the request of its own frame as the last transaction ("Response To" is its own frame)
    bad.append((0, c.c(apdu(0x0601, b_amount(1)))))
    bad.append((0, c.s(completion() + apdu(0x040f, b_res(0)))))
    c = Conn(40701, 20007)
    bad.append((0, c.s(b'\x04\x0f\xff\xff\xff' + b'\x00' * 8)))
    c = Conn(40702, 20007)
    bad.append((0, c.s(b'\x04\x0f\xff')))                                  # three-byte length cut at the length byte
    bad.append((0, c.s(b'\x00\x01\x00\x00')))
    write_pcapng(os.path.join(out, 'zvt-coverage-malformed.pcapng'), bad)

def block(btype, body):
    pad = (4 - len(body) % 4) % 4
    total = 12 + len(body) + pad
    return struct.pack('<II', btype, total) + body + b'\0' * pad + struct.pack('<I', total)

def write_pcapng(path, frames):
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += block(1, struct.pack('<HHI', 1, 0, 262144))      # interface 0: Ethernet
    out += block(1, struct.pack('<HHI', 252, 0, 262144))    # interface 1: Exported PDU
    for i, (ifid, fr) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        out += block(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    with open(path, 'wb') as f:
        f.write(out)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
