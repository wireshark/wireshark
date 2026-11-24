#!/usr/bin/env python3
# Generates test/captures/srp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SRP coverage captures: mksrp.py <outdir> [-v].  All data is synthetic.

SRP (H.324 Annex C Simple Retransmission Protocol) and CCSRL are carried on
logical channel 0 of H.223. The frames are an H.223 stream (multiplex PDUs
with Golay coded headers) sent as RTP payload type 96 whose SDP rtpmap is
CLEARMODE, which Wireshark hands to H.223 (bit-swapped)."""
import os
import struct
import sys
from c17lib import Cap, udp

GOLAY = (0xC75, 0x49F, 0xD4B, 0x6E3, 0x9B3, 0xB66, 0xECC, 0x1ED, 0x3DA, 0x7B4, 0xB1D, 0xE3A)

def golay(w):
    out = 0
    for i in range(12):
        if w & (1 << i):
            out ^= GOLAY[i]
    return w | out << 12

def crc16(data):
    """CRC-16/X-25 (HDLC FCS-16), as crc16_ccitt() computes it."""
    crc = 0xffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xffff

def srp(header, body=b'', seq=None, bad=False):
    f = bytes([header]) + (bytes([seq]) if seq is not None else b'') + body
    c = crc16(f) ^ (0x5a5a if bad else 0)
    return f + struct.pack('<H', c)

def ccsrl(h245, last=True):
    return bytes([0xff if last else 0x00]) + h245

# H.245 MultimediaSystemControlMessage command / endSessionCommand / disconnect
H245_END = bytes([0x4a, 0x40])

def mux(mc, payload, end=True, hdr_error=0):
    """A level 2 MUX-PDU: Golay coded header (MC, MPL), payload, closing HDLC flag."""
    assert len(payload) < 256
    cw = golay(mc | len(payload) << 4) ^ hdr_error
    flag = 0xE14D ^ 0xFFFF if end else 0xE14D
    return struct.pack('<I', cw)[:3] + payload + struct.pack('>H', flag)

def swap(b):
    return bytes(int('{:08b}'.format(x)[::-1], 2) for x in b)

def rtp(seq, payload, pt=96, ssrc=0x11223344):
    return struct.pack('>BBHII', 0x80, pt, seq, seq * 160, ssrc) + swap(payload)

def sip(method_or_status, sdp, call='abc123', cseq='1 INVITE', ports=(49170, 'caller')):
    if sdp:
        body = ('v=0\r\no=- 1 1 IN IP4 192.0.2.%d\r\ns=-\r\nc=IN IP4 192.0.2.%d\r\nt=0 0\r\nm=audio %d RTP/AVP 96\r\na=rtpmap:96 CLEARMODE/8000\r\n'
                % (sdp[1], sdp[1], sdp[0])).encode()
    else:
        body = b''
    head = ('%s\r\nVia: SIP/2.0/UDP 192.0.2.%d:5060;branch=z9hG4bK%s\r\nFrom: <sip:a@example.org>;tag=1\r\nTo: <sip:b@example.org>%s\r\nCall-ID: %s@example.org\r\nCSeq: %s\r\n'
            % (method_or_status, 10, call, ';tag=2' if 'OK' in method_or_status else '', call, cseq)).encode()
    head += (b'Content-Type: application/sdp\r\n' if body else b'') + b'Content-Length: %d\r\n\r\n' % len(body)
    return head + body

def main(out, verbose):
    c = Cap(1)
    A, Bh = '192.0.2.10', '192.0.2.20'
    c.mark('SIP INVITE and 200 OK whose SDP offers a CLEARMODE (H.324M over RTP) payload type 96, which sets up the RTP streams')
    c.add(udp(5060, 5060, sip('INVITE sip:b@example.org SIP/2.0', (49170, 10)), A, Bh))
    c.add(udp(5060, 5060, sip('SIP/2.0 200 OK', (49180, 20)), Bh, A))
    n = [0, 0]
    def tx(p, a_to_b=True):
        if a_to_b:
            n[0] += 1
            c.add(udp(49170, 49180, rtp(n[0], p), A, Bh))
        else:
            n[1] += 1
            c.add(udp(49180, 49170, rtp(n[1], p, ssrc=0x55667788), Bh, A))
    c.mark('SRP commands carrying CCSRL and H.245 (end session command), sequence numbers 0, 1 and 255, in a complete MUX-PDU (end of SDU)')
    for s in (0, 1, 255):
        tx(mux(0, srp(0xf9, ccsrl(H245_END), seq=s)))
    c.mark('SRP response (no sequence number), NSRP response and the WNSRP command and response with sequence numbers')
    tx(mux(0, srp(0xfb)), False)
    tx(mux(0, srp(0xf7, seq=1)), False)
    tx(mux(0, srp(0xf1, ccsrl(H245_END), seq=7)))
    tx(mux(0, srp(0xf3, seq=7)), False)
    c.mark('A frame with a header octet that is not an SRP type (only the header and CRC), and a CCSRL segment that is not the last')
    tx(mux(0, srp(0x00, b'\x12\x34')))
    tx(mux(0, srp(0xf9, ccsrl(H245_END, last=False), seq=3)))
    c.mark('An SRP frame split over two MUX-PDUs (the first without the end of SDU flag), then over three')
    f = srp(0xf9, ccsrl(H245_END), seq=4)
    tx(mux(0, f[:3], end=False)); tx(mux(0, f[3:]))
    f = srp(0xf9, ccsrl(H245_END), seq=5)
    tx(mux(0, f[:1], end=False)); tx(mux(0, f[1:3], end=False)); tx(mux(0, f[3:]))
    c.mark('Two MUX-PDUs in one RTP packet, a stuffing PDU (empty payload), a MUX-PDU with a header bit error that is corrected, and a PDU for a multiplex code that is not defined')
    tx(mux(0, srp(0xf9, ccsrl(H245_END), seq=6)) + mux(0, srp(0xfb)))
    tx(mux(0, b'') + mux(0, srp(0xf9, ccsrl(H245_END), seq=8)))
    tx(mux(0, srp(0xf9, ccsrl(H245_END), seq=9), hdr_error=0x000100))
    tx(mux(5, b'\x01\x02\x03'))
    c.mark('Packets in the other direction and the start of a PDU that is not complete in the RTP packet')
    tx(mux(0, srp(0xf9, ccsrl(H245_END), seq=10)), False)
    tx(mux(0, srp(0xf9, ccsrl(H245_END), seq=11))[:6])

    m = Cap(1)
    m.add(udp(5060, 5060, sip('INVITE sip:b@example.org SIP/2.0', (49170, 10), call='m1'), A, Bh))
    m.add(udp(5060, 5060, sip('SIP/2.0 200 OK', (49180, 20), call='m1'), Bh, A))
    k = [0]
    def mtx(p):
        k[0] += 1
        m.add(udp(49170, 49180, rtp(k[0], p), A, Bh))
    m.mark('Wrong SRP CRC (expert info), an SRP frame of 1-3 octets, a header with errors that cannot be corrected, a MUX-PDU of a zero length multiplex code with data beyond MPL')
    mtx(mux(0, srp(0xf9, ccsrl(H245_END), seq=1, bad=True)))
    mtx(mux(0, b'\xf9'))
    mtx(mux(0, b'\xfb\x00'))
    mtx(mux(0, b'\xf9\x01\x02'))
    mtx(mux(0, srp(0xf9, ccsrl(H245_END), seq=2), hdr_error=0x000f0f))
    mtx(mux(0, srp(0xf9, ccsrl(b''), seq=3)))
    mtx(mux(0, srp(0xf9, ccsrl(b'\xff\xff\xff'), seq=4)))
    c.write(os.path.join(out, 'srp-coverage.pcap'))
    m.write(os.path.join(out, 'srp-coverage-malformed.pcap'))
    if verbose:
        for nn, tx_ in c.marks:
            print(nn, tx_)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
