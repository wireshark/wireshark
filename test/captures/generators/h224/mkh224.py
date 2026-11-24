#!/usr/bin/env python3
# Generates test/captures/h224_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the H.224 coverage captures. Usage: mkh224.py <outdir> [-v]
H.224 is reached the way a real call reaches it: a SIP INVITE whose SDP
maps RTP payload type 100 to "H224/4800" on UDP 5004 (rtp_dyn_payload_type
"H224"), then RTP packets with payload type 100. Everything is built with
struct; nothing comes from a real network."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from _lib import Pcap

A, B = '192.0.2.10', '192.0.2.20'

def sip(body, call='c13h224'):
    h = ('INVITE sip:bob@192.0.2.20 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK%s\r\n'
         'From: <sip:alice@192.0.2.10>;tag=1\r\nTo: <sip:bob@192.0.2.20>\r\nCall-ID: %s\r\nCSeq: 1 INVITE\r\n'
         'Contact: <sip:alice@192.0.2.10>\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n'
         % (call, call, len(body)))
    return h.encode() + body

def sdp(port, pt=100):
    return ('v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n'
            'm=application %d RTP/AVP %d\r\na=rtpmap:%d H224/4800\r\n' % (port, pt, pt)).encode()

seqno = [100]
def rtp(payload, pt=100):
    seqno[0] += 1
    return struct.pack('!BBHII', 0x80, pt, seqno[0], seqno[0] * 960, 0x1234) + payload

def h224(client, flags, data=b'', dlci=0x0061, ctl=3, dta=0, sta=0):
    return struct.pack('!HBHH', dlci, ctl, dta, sta) + bytes(client) + bytes([flags]) + data

def main(out, verbose=False):
    p = Pcap(); marks = []
    def mark(n): marks.append((len(p.frames) + 1, n))
    def send(payload, sport=5004, dport=5004):
        p.udp(A, B, sport, dport, rtp(payload))

    mark('SIP INVITE with SDP (H224/4800 on UDP 5004)')
    p.udp(A, B, 5060, 5060, sip(sdp(5004)))
    mark('CME Client List Message (0x0100) with every client ID form')
    # number of clients 5: CME, FECC, extended (0x7e + id), non-standard (0x7f + 5), plain 0x20
    clients = bytes([0x00, 0x01, 0x7E, 0x42, 0x7F, 0xB5, 0x00, 0x53, 0x4C, 0x09, 0x20])
    send(h224([0x00], 0xC0, bytes([0x01, 0x00, 5]) + clients))
    send(h224([0x00], 0xC0, bytes([0x01, 0x00, 3, 0x80 | 0x7E, 0x44, 0x00, 0x01])))
    mark('CME Client List Command (0x01ff)')
    send(h224([0x00], 0xC0, bytes([0x01, 0xFF])))
    mark('CME Extra Capabilities Message (0x0200), FECC client')
    # ex caps bit + FECC id 1; presets byte; video source byte (id nibble, caps); pan/tilt/zoom/focus
    send(h224([0x00], 0xC0, bytes([0x02, 0x00, 0x81, 0x1F, 0x07, 0xF0])))             # source id 0
    send(h224([0x00], 0xC0, bytes([0x02, 0x00, 0x81, 0x00, 0x57, 0x50])))             # source id 5
    send(h224([0x00], 0xC0, bytes([0x02, 0x00, 0x01, 0xE3, 0x6F]) + b'Main camera\0' + bytes([0xA0])))  # id 6: ASCII
    send(h224([0x00], 0xC0, bytes([0x02, 0x00, 0x81, 0x10, 0xF7]) + b'\0' + bytes([0x30])))           # empty string
    mark('reproducer: video source id > 5 with an unterminated string (zero_offset was uninitialized)')
    send(h224([0x00], 0xC0, bytes([0x02, 0x00, 0x81, 0x1F, 0x67]) + b'A' * 20 + bytes([0xF0])))
    mark('Extra Capabilities Message with other client IDs (id masked)')
    send(h224([0x00], 0xC0, bytes([0x02, 0x00, 0x80 | 0x7E, 0x31])))                 # extended: fixed, 0x7e masked
    send(h224([0x00], 0xC0, bytes([0x02, 0x00, 0x80 | 0x7F, 0xB5, 0x00, 0x53, 0x4C, 0x07])))
    send(h224([0x00], 0xC0, bytes([0x02, 0x00, 0x80])))                                # CME client with ext bit
    send(h224([0x00], 0xC0, bytes([0x02, 0x00, 0x23])))                                # other standard
    mark('Extra Capabilities Command (0x02ff)')
    send(h224([0x00], 0xC0, bytes([0x02, 0xFF, 0x81])))
    send(h224([0x00], 0xC0, bytes([0x02, 0xFF, 0x7E, 0x55])))
    send(h224([0x00], 0xC0, bytes([0x02, 0xFF, 0x7F, 0xB5, 0x00, 0x53, 0x4C, 0x08])))
    mark('unknown CME message')
    send(h224([0x00], 0xC0, bytes([0x03, 0x00])))
    mark('FECC START ACTION (timeouts: 0 = 800 ms, 3, 15 and with high nibble set)')
    for act, tmo in ((0x80, 0x00), (0x7F, 0x03), (0x6A, 0x0F), (0x15, 0xA3), (0xFF, 0xF0)):
        send(h224([0x01], 0xC0, bytes([0x01, act, tmo])))
    mark('FECC CONTINUE / STOP ACTION')
    send(h224([0x01], 0xC0, bytes([0x02, 0x95])))
    send(h224([0x01], 0xC0, bytes([0x03, 0x2A])))
    mark('FECC SELECT VIDEO SOURCE / VIDEO SOURCE SWITCHED')
    send(h224([0x01], 0xC0, bytes([0x04, 0x30])))
    send(h224([0x01], 0xC0, bytes([0x05, 0x52])))
    mark('FECC STORE AS PRESET / ACTIVATE PRESET')
    send(h224([0x01], 0xC0, bytes([0x06, 0x70])))
    send(h224([0x01], 0xC0, bytes([0x07, 0xF0])))
    mark('FECC unknown message code')
    send(h224([0x01], 0xC0, bytes([0x09, 0x01])))
    mark('extended / non-standard client at the top level, other clients, header variants')
    send(h224([0x7E, 0x21], 0xC0, b'ext client data'))
    send(h224([0x7F, 0xB5, 0x00, 0x53, 0x4C, 0x09], 0xC0, b'vendor data'))
    send(h224([0x23], 0xC0, b'other'))
    send(h224([0x80 | 0x01], 0xC0, bytes([0x01, 0x80, 0x01])))           # reserved bit set: no client data decoded
    send(h224([0x00], 0x00, bytes([0x01, 0x00, 1]) + bytes([0x00]), dlci=0x00E1, ctl=0x03, dta=0x1234, sta=0x4321))
    send(h224([0x00], 0x2F, bytes([0x01, 0xFF]), dlci=0x00F1))
    send(h224([0x00], 0x5A, bytes([0x01, 0xFF]), dlci=0xFFFF))
    p.write(os.path.join(out, 'h224-coverage.pcap'))

    # Malformed: truncated headers and client data (exceptions), a client
    # list with more clients than octets.
    m = Pcap()
    m.udp(A, B, 5060, 5060, sip(sdp(5004), 'c13h224m'))
    def ms(payload):
        m.udp(A, B, 5004, 5004, rtp(payload))
    full = h224([0x00], 0xC0, bytes([0x01, 0x00, 5]) + bytes([0x00, 0x01, 0x7E, 0x42, 0x7F, 0xB5, 0x00, 0x53, 0x4C, 0x09, 0x20]))
    ms(full[:3])
    ms(full[:7])
    ms(full[:8])
    ms(full[:9])
    ms(full[:11])
    ms(h224([0x00], 0xC0, bytes([0x01, 0x00, 200])))
    ms(h224([0x00], 0xC0, bytes([0x01, 0x00, 0])))   # no clients: the Extra Capabilities bit is read beyond the end
    ms(h224([0x00], 0xC0, bytes([0x01])))
    ms(h224([0x00], 0xC0, bytes([0x02, 0x00, 0x81])))
    ms(h224([0x00], 0xC0, bytes([0x02, 0x00, 0x81, 0x1F])))
    ms(h224([0x00], 0xC0, bytes([0x02, 0x00, 0x81, 0x1F, 0x67])))
    ms(h224([0x00], 0xC0, bytes([0x02, 0x00, 0x81, 0x1F, 0x67]) + b'abc'))   # ASCII unterminated, short
    ms(h224([0x00], 0xC0, bytes([0x02, 0x00, 0x81, 0x1F, 0x67]) + b'A' * 20 + bytes([0xF0])))  # no terminator in 16
    ms(h224([0x00], 0xC0, bytes([0x02, 0x00, 0x80 | 0x7F, 0xB5])))
    ms(h224([0x00], 0xC0, bytes([0x02, 0x00, 0x80 | 0x7E])))
    ms(h224([0x7F, 0xB5, 0x00], 0xC0)[:10])
    ms(h224([0x7E], 0xC0)[:8])
    for code in (1, 2, 3, 4, 6):
        ms(h224([0x01], 0xC0, bytes([code])))
    ms(h224([0x01], 0xC0, bytes([1, 0x80])))
    ms(h224([0x01], 0xC0)[:9])
    ms(h224([0x01], 0xC0, b'')[:8])
    m.write(os.path.join(out, 'h224-coverage-malformed.pcap'))
    if verbose:
        for (n, s), nx in zip(marks, marks[1:] + [(len(p.frames) + 1, '')]):
            print('%d-%d %s' % (n, nx[0] - 1, s))

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
