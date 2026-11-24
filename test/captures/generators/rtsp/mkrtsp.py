#!/usr/bin/env python3
# Generates test/captures/rtsp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the RTSP coverage captures. Usage: mkrtsp.py <outdir>"""
import sys
import os
import struct
from pcaplib import Pcap, TcpStream, udp_frame

CL, SV = '10.0.0.1', '10.0.0.2'
NL = '\r\n'

def rtp(pt, seq, ts=1000, ssrc=0x11223344, payload=b'\x65\x88\x84\x00' * 4, marker=0):
    return struct.pack('>BBHII', 0x80, (marker << 7) | pt, seq, ts, ssrc) + payload

def rtcp_sr(ssrc=0x11223344):
    return struct.pack('>BBHIQIII', 0x80, 200, 6, ssrc, 0xe0000000_00000000, 90000, 10, 1000)

def msg(first, headers=(), body=b''):
    h = first + NL + ''.join(k + NL for k in headers)
    if body:
        h += 'Content-Length: %d' % len(body) + NL
    return (h + NL).encode('latin-1') + body

SDP = (
    'v=0\r\no=- 1 1 IN IP4 10.0.0.2\r\ns=Test stream\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n'
    'a=control:*\r\n'
    'm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\na=control:trackID=1\r\n'
    'm=audio 0 RTP/AVP 97\r\na=rtpmap:97 MPEG4-GENERIC/48000/2\r\na=control:trackID=2\r\n'
).encode()


class Sess:
    """One RTSP TCP connection; cseq numbering per connection."""
    def __init__(self, p, cport, sport=554):
        self.p = p
        self.t = TcpStream(p, cport, sport)
        self.cseq = 0
    def req(self, method, uri, headers=(), body=b'', cseq=True, raw=None):
        hs = list(headers)
        if cseq:
            self.cseq += 1
            hs.insert(0, 'CSeq: %d' % self.cseq)
        data = raw if raw is not None else msg('%s %s RTSP/1.0' % (method, uri), hs, body)
        self.t.c(data)
    def rep(self, code='200 OK', headers=(), body=b'', cseq=None, raw=None):
        hs = list(headers)
        hs.insert(0, 'CSeq: %d' % (self.cseq if cseq is None else cseq))
        data = raw if raw is not None else msg('RTSP/1.0 ' + code, hs, body)
        self.t.s(data)
    def exch(self, method, uri, rcode='200 OK', rheaders=(), headers=(), body=b'', rbody=b''):
        self.req(method, uri, headers, body)
        self.rep(rcode, rheaders, rbody)


def main(out):
    p = Pcap()
    U = 'rtsp://10.0.0.2/stream'
    T = 'Transport: '

    def udp_rtp(cport, sport, payload, to_client=True):
        if to_client:
            p.add(udp_frame(payload, sport, cport, SV, CL, 2, 1))
        else:
            p.add(udp_frame(payload, cport, sport, CL, SV, 1, 2))

    # ---- Session 1: a complete session over UDP transport (TCP port 554)
    s = Sess(p, 40001)
    s.exch('OPTIONS', '*', rheaders=['Public: DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE, GET_PARAMETER, SET_PARAMETER'])
    s.req('DESCRIBE', U, ['Accept: application/sdp', 'User-Agent: coverage'])
    s.rep('200 OK', ['Content-Base: ' + U + '/', 'Content-Type: application/sdp'], SDP)
    s.exch('SETUP', U + '/trackID=1', rheaders=[T + 'RTP/AVP;unicast;client_port=5000-5001;server_port=6970-6971', 'Session: 12345678;timeout=60'],
           headers=[T + 'RTP/AVP;unicast;client_port=5000-5001'])
    s.exch('SETUP', U + '/trackID=2', rheaders=[T + 'RTP/AVP/UDP;unicast;client_port=5002-5003;server_port=6972-6973', 'Session: 12345678'],
           headers=[T + 'RTP/AVP/UDP;unicast;client_port=5002-5003', 'Session: 12345678'])
    s.exch('PLAY', U + '/', rheaders=['Session: 12345678', 'Range: npt=0.000-', 'RTP-Info: url=' + U + '/trackID=1;seq=1;rtptime=1000'],
           headers=['Session: 12345678', 'Range: npt=0.000-'])
    # RTP and RTCP of the two tracks (the conversations come from the SETUP replies)
    for i in range(3):
        udp_rtp(5000, 6970, rtp(96, 100 + i, 1000 + 3000 * i, marker=i == 2))
    udp_rtp(5001, 6971, rtcp_sr())
    udp_rtp(5002, 6972, rtp(97, 7, 5000, 0x55667788, payload=b'\x00\x10\x0b\x90\x01\x02'))
    udp_rtp(5003, 6973, rtcp_sr(0x55667788))
    s.exch('GET_PARAMETER', U + '/', headers=['Session: 12345678', 'Content-Type: text/parameters'], body=b'packets_received\r\njitter\r\n',
           rheaders=['Content-Type: text/parameters'], rbody=b'packets_received: 10\r\njitter: 0\r\n')
    s.exch('SET_PARAMETER', U + '/', headers=['Session: 12345678', 'Content-Type: text/parameters'], body=b'barparam: barstuff\r\n')
    s.exch('PAUSE', U + '/', rheaders=['Session: 12345678'], headers=['Session: 12345678'])
    s.exch('TEARDOWN', U + '/', rheaders=['Session: 12345678'], headers=['Session: 12345678'])
    s.t.fin()

    # ---- Session 2: other transports in SETUP replies, port 8554
    s = Sess(p, 40002, 8554)
    U2 = 'rtsp://10.0.0.2:8554/live'
    # RTP/AVP default transport with the client port only (no server port)
    s.exch('SETUP', U2 + '/a', rheaders=[T + 'RTP/AVP;unicast;client_port=5100-5101', 'Session: AAAA0001'])
    # server port only, RTP conversation from the server address
    s.exch('SETUP', U2 + '/b', rheaders=[T + 'RTP/AVP;unicast;server_port=6980-6981', 'Session: AAAA0002'])
    # data port without the second port
    s.exch('SETUP', U2 + '/c', rheaders=[T + 'RTP/AVP;unicast;client_port=5110;server_port=6990', 'Session: AAAA0003'])
    # dest_addr variants
    s.exch('SETUP', U2 + '/d', rheaders=[T + 'RTP/AVP;unicast;dest_addr=":9";client_port=5120-5121', 'Session: AAAA0004'])
    s.exch('SETUP', U2 + '/e', rheaders=[T + 'RTP/AVP;unicast;dest_addr=":6000";client_port=5122-5123', 'Session: AAAA0005'])
    s.exch('SETUP', U2 + '/f', rheaders=[T + 'RTP/AVP;unicast;dest_addr="10.0.0.1:5130";src_addr="10.0.0.2:6130"', 'Session: AAAA0006'])
    s.exch('SETUP', U2 + '/g', rheaders=[T + 'RTP/AVP;unicast;dest_addr="10.0.0.1"', 'Session: AAAA0007'])
    # both dest_addr and src_addr: the RTP stream goes to dest_addr (fixed: src_addr overwrote it)
    s.exch('SETUP', U2 + '/h', rheaders=[T + 'RTP/AVP;unicast;dest_addr="10.0.0.9:5140";src_addr="10.0.0.8:5141"', 'Session: AAAA0008'])
    # RTP to the dest_addr address and the src_addr port (client_port from src_addr, server port from dest_addr)
    p.add(udp_frame(rtp(96, 1, 10, 0x01010101), 5130, 6130, '10.0.0.2', '10.0.0.1', 2, 1))
    p.add(udp_frame(rtp(96, 2, 20, 0x02020202), 5140, 5141, '10.0.0.2', '10.0.0.9', 2, 9))
    # unknown transport, bad ports, bad channel (warnings)
    s.exch('SETUP', U2 + '/i', rheaders=[T + 'FOO/BAR;unicast', 'Session: AAAA0009'])
    s.exch('SETUP', U2 + '/j', rheaders=[T + 'RTP/AVP;unicast;server_port=abc', 'Session: AAAA000a'])
    s.exch('SETUP', U2 + '/k', rheaders=[T + 'RTP/AVP;unicast;client_port=xyz', 'Session: AAAA000b'])
    s.exch('SETUP', U2 + '/l', rheaders=[T + 'RTP/AVP/TCP;unicast;interleaved=zz', 'Session: AAAA000c'])
    # transport over TCP without interleaving
    s.exch('SETUP', U2 + '/m', rheaders=[T + 'RTP/AVP/TCP;unicast;client_port=5150;server_port=6150', 'Session: AAAA000d'])
    # RDT: udp, with the feature level, and x-pn-tng
    s.exch('SETUP', U2 + '/n', rheaders=[T + 'x-real-rdt/udp;client_port=6970;server_port=6971', 'RDTFeatureLevel: 2', 'Session: AAAA000e'])
    s.exch('SETUP', U2 + '/o', rheaders=[T + 'x-pn-tng/udp;client_port=6972;server_port=6973', 'Session: AAAA000f'])
    # Transport header in a request (no conversation is set up)
    s.req('SETUP', U2 + '/p', [T + 'RTP/AVP;unicast;client_port=5160-5161'])
    # long Transport line (> 255 characters is cut)
    s.rep('200 OK', [T + 'RTP/AVP;unicast;client_port=5170-5171;' + 'x' * 300 + ';server_port=6170-6171', 'Session: AAAA0010'])
    s.t.fin()

    # ---- Session 3: TCP interleaved
    s = Sess(p, 40003)
    s.exch('DESCRIBE', U, rheaders=['Content-Base: ' + U + '/', 'Content-Type: application/sdp'], headers=['Accept: application/sdp'], rbody=SDP)
    s.exch('SETUP', U + '/trackID=1', rheaders=[T + 'RTP/AVP/TCP;unicast;interleaved=0-1', 'Session: BBBB0001'],
           headers=[T + 'RTP/AVP/TCP;unicast;interleaved=0-1'])
    s.exch('SETUP', U + '/trackID=2', rheaders=[T + 'RTP/AVP/TCP;unicast;interleaved=2', 'Session: BBBB0001'],
           headers=[T + 'RTP/AVP/TCP;unicast;interleaved=2', 'Session: BBBB0001'])
    s.exch('SETUP', U + '/trackID=3', rheaders=[T + 'x-real-rdt/tcp;interleaved=4', 'Session: BBBB0001'])
    s.exch('SETUP', U + '/trackID=4', rheaders=[T + 'RTP/AVP/TCP;unicast;interleaved=300-301', 'Session: BBBB0001'])
    s.exch('SETUP', U + '/trackID=5', rheaders=[T + 'RTP/AVP/TCP;unicast;interleaved=6-300', 'Session: BBBB0001'])
    s.exch('PLAY', U + '/', rheaders=['Session: BBBB0001'])
    def frame(ch, data):
        return b'$' + bytes([ch]) + struct.pack('>H', len(data)) + data
    s.t.s(frame(0, rtp(96, 1, 100, 0x0a0a0a0a)))
    s.t.s(frame(1, rtcp_sr(0x0a0a0a0a)))
    s.t.s(frame(2, rtp(97, 1, 100, 0x0b0b0b0b)))
    s.t.s(frame(9, b'unmapped channel with data'))                            # no dissector for the channel
    s.t.s(frame(7, rtp(96, 9, 900, 0x0c0c0c0c)))                              # heuristics find RTP
    # several interleaved frames and a reply in one segment
    s.t.s(frame(0, rtp(96, 2, 200, 0x0a0a0a0a)) + frame(1, rtcp_sr(0x0a0a0a0a)) + frame(2, rtp(97, 2, 200, 0x0b0b0b0b)))
    # interleaved frame split: the header in two segments, then the payload in two segments
    fr = frame(0, rtp(96, 3, 300, 0x0a0a0a0a, payload=b'\x41' * 40))
    s.t.s(fr[:2]); s.t.s(fr[2:6]); s.t.s(fr[6:30]); s.t.s(fr[30:])
    # request coming from the client while streaming (GET_PARAMETER keep-alive) and an interleaved frame from the client
    s.req('GET_PARAMETER', U + '/', ['Session: BBBB0001'])
    s.t.c(frame(1, rtcp_sr(0x0d0d0d0d)))
    s.rep('200 OK', ['Session: BBBB0001'])
    # reply followed by an interleaved frame in one segment (the body test in dissect_rtspmessage)
    s.req('GET_PARAMETER', U + '/', ['Session: BBBB0001'])
    s.t.s(msg('RTSP/1.0 200 OK', ['CSeq: %d' % s.cseq, 'Session: BBBB0001']) + frame(0, rtp(96, 4, 400, 0x0a0a0a0a)))
    s.exch('TEARDOWN', U + '/', headers=['Session: BBBB0001'])
    s.t.fin()

    # ---- Session 4: header and body reassembly, pipelining, odd headers (port 7236, Wi-Fi Display)
    s = Sess(p, 40004, 7236)
    s.req('OPTIONS', '*', ['Require: org.wfa.wfd1.0'])
    s.rep('200 OK', ['Public: org.wfa.wfd1.0, GET_PARAMETER, SET_PARAMETER'])
    # request header split over two segments
    s.cseq += 1
    full = msg('SETUP rtsp://10.0.0.2/split RTSP/1.0', ['CSeq: %d' % s.cseq, 'Transport: RTP/AVP/UDP;unicast;client_port=5200-5201'])
    s.t.c(full[:40]); s.t.c(full[40:])
    s.rep('200 OK', ['Transport: RTP/AVP/UDP;unicast;client_port=5200-5201;server_port=7200-7201', 'Session: CCCC0001'])
    # reply with a body over three segments
    s.req('DESCRIBE', 'rtsp://10.0.0.2/split')
    big = msg('RTSP/1.0 200 OK', ['CSeq: %d' % s.cseq, 'Content-Type: application/sdp', 'Content-Base: rtsp://10.0.0.2/split/'], SDP + SDP)
    k = len(big)
    s.t.s(big[:k // 3]); s.t.s(big[k // 3:2 * k // 3]); s.t.s(big[2 * k // 3:])
    # request with a body split over two segments
    s.cseq += 1
    body = b'wfd_trigger_method: SETUP\r\n'
    full = msg('SET_PARAMETER rtsp://localhost/wfd1.0 RTSP/1.0', ['CSeq: %d' % s.cseq, 'Content-Type: text/parameters'], body)
    s.t.c(full[:-10]); s.t.c(full[-10:])
    s.rep('200 OK')
    # two requests in one segment (pipelining), then two replies in one segment
    c1 = s.cseq + 1; c2 = s.cseq + 2; s.cseq += 2
    s.t.c(msg('GET_PARAMETER rtsp://10.0.0.2/a RTSP/1.0', ['CSeq: %d' % c1]) + msg('GET_PARAMETER rtsp://10.0.0.2/b RTSP/1.0', ['CSeq: %d' % c2]))
    s.t.s(msg('RTSP/1.0 200 OK', ['CSeq: %d' % c1]) + msg('RTSP/1.0 404 Not Found', ['CSeq: %d' % c2]))
    # a reply that arrives before its request is seen again (CSeq reused): response_in
    s.t.c(msg('GET_PARAMETER rtsp://10.0.0.2/a RTSP/1.0', ['CSeq: %d' % c1]))
    # methods ANNOUNCE, RECORD, REDIRECT, lowercase method
    s.exch('ANNOUNCE', 'rtsp://10.0.0.2/ann', headers=['Content-Type: application/sdp'], body=SDP)
    s.exch('RECORD', 'rtsp://10.0.0.2/ann', headers=['Session: CCCC0001', 'Range: npt=now-'])
    s.req('REDIRECT', 'rtsp://10.0.0.2/ann', ['Location: rtsp://10.0.0.3/ann', 'Range: clock=20260101T000000Z'])
    s.rep('200 OK')
    s.req('play', 'rtsp://10.0.0.2/ann', ['Session: CCCC0001'])
    s.rep('200 OK')
    # response codes: informational, redirects, client and server errors, unknown codes
    for code in ('100 Continue', '201 Created', '250 Low on Storage Space', '301 Moved Permanently', '302 Moved Temporarily',
                 '400 Bad Request', '401 Unauthorized', '404 Not Found', '454 Session Not Found', '455 Method Not Valid In This State',
                 '461 Unsupported Transport', '500 Internal Server Error', '503 Service Unavailable', '551 Option Not Support',
                 '299 Odd Success', '499 Odd Client', '777 Odd Server', '99 Broken', '650 Broken'):
        s.req('OPTIONS', '*')
        s.rep(code)
    # reply without a status code and with a non-numeric one
    s.req('OPTIONS', '*')
    s.rep(raw=('RTSP/1.0' + NL + 'CSeq: %d' % s.cseq + NL + NL).encode())
    s.req('OPTIONS', '*')
    s.rep(raw=('RTSP/1.0 2x0 Odd' + NL + 'CSeq: %d' % s.cseq + NL + NL).encode())
    s.t.fin()

    # ---- Session 5: headers (port 554)
    s = Sess(p, 40005)
    s.req('DESCRIBE', U, ['X-Vig-Msisdn: 46701234567', 'Accept: application/sdp'])
    s.rep('200 OK', ['Content-Location: rtsp://10.0.0.2/stream/loc/', 'Content-Type: Application/SDP ; charset=utf-8', 'X-Vig-Msisdn: 15551234567'], SDP)
    s.req('DESCRIBE', U + '/b')
    s.rep('200 OK', ['Content-Base: rtsp://10.0.0.2/stream/b/', 'Content-Location: rtsp://10.0.0.2/stream/loc2/', 'Content-Type: application/sdp'], SDP)
    # Content-Type: ;x (an empty media type with a parameter; fixed length underflow)
    s.req('DESCRIBE', U + '/c')
    s.rep('200 OK', ['Content-Type: ;x'], b'text body of unknown type')
    # Content-Type unknown, body shown as data; no content type at all
    s.req('DESCRIBE', U + '/d')
    s.rep('200 OK', ['Content-Type: application/x-unknown'], b'unknown media type body')
    s.req('DESCRIBE', U + '/e')
    s.rep('200 OK', [], b'body without a content type')
    # reply without Content-Length: the body runs to the end of the segment
    s.req('DESCRIBE', U + '/f')
    s.rep(raw=('RTSP/1.0 200 OK' + NL + 'CSeq: %d' % s.cseq + NL + 'Content-Type: text/plain' + NL + NL).encode() + b'plain text without a length\r\n')
    # CSeq invalid (warning), a header of the Content-Length kind with trailing spaces
    s.req('OPTIONS', '*', cseq=False, raw=msg('OPTIONS * RTSP/1.0', ['CSeq: abc']))
    s.rep('200 OK', cseq=0, raw=msg('RTSP/1.0 200 OK', ['CSeq: 99', 'Content-Length: 0']))
    # headers with continuation lines, blank values, a non-header line and a tspecial in the name
    s.req('OPTIONS', '*', ['X-Folded: first', ' second line', 'X-Empty:', 'Accept-Language:   en'])
    s.rep('200 OK', ['Server: coverage/1.0', 'Bad/Header: stops the header parsing', 'X-Not-Seen: x'])
    # text that is not RTSP in a frame to port 554 (continuation) and a response with a non-RTSP first line
    s.t.s(b'this is not rtsp but a continuation\r\n')
    s.t.c(b'\x01\x02binary garbage\r\n\r\n')
    # a reply with a body longer than Content-Length (the rest is a new message)
    s.req('GET_PARAMETER', U, ['Session: DDDD0001'])
    s.t.s(msg('RTSP/1.0 200 OK', ['CSeq: %d' % s.cseq, 'Content-Type: text/parameters', 'Content-Length: 4']) + b'abcd' + msg('RTSP/1.0 200 OK', ['CSeq: %d' % (s.cseq + 100)]))
    # a request with a body but no Content-Length: no body
    s.t.c(b'SET_PARAMETER ' + U.encode() + b' RTSP/1.0\r\nCSeq: 77\r\n\r\n')
    s.t.fin()

    p.write(os.path.join(out, 'rtsp-coverage.pcap'))

    # ===== malformed / error expert infos
    m = Pcap()
    s = Sess(m, 41001)
    # the reproducer of "RTSP: Do not abort on dest_addr without a closing quote"
    s.req('SETUP', U + '/a', [T + 'RTP/AVP;unicast;client_port=5000-5001'])
    s.rep('200 OK', ['Session: 12345', T + 'RTP/AVP;unicast;dest_addr="198.51.100.7;client_port=5000-5001'])
    # the other dest_addr and src_addr forms without the closing quote or colon
    s.req('SETUP', U + '/b')
    s.rep('200 OK', ['Session: 12345', T + 'RTP/AVP;unicast;dest_addr="198.51.100.7:5000;client_port=5000-5001'])
    s.req('SETUP', U + '/c')
    s.rep('200 OK', ['Session: 12345', T + 'RTP/AVP;unicast;src_addr="198.51.100.7:5000;client_port=5000-5001'])
    s.req('SETUP', U + '/d')
    s.rep('200 OK', ['Session: 12345', T + 'RTP/AVP;unicast;dest_addr="999.1.1.1:5000"'])
    s.req('SETUP', U + '/e')
    s.rep('200 OK', ['Session: 12345', T + 'RTP/AVP;unicast;dest_addr="999.1.1.1"'])
    s.req('SETUP', U + '/f')
    s.rep('200 OK', ['Session: 12345', T + 'RTP/AVP;unicast;src_addr="999.1.1.1:5000"'])
    s.req('SETUP', U + '/g')
    s.rep('200 OK', ['Session: 12345', T + 'RTP/AVP;unicast;dest_addr=junk'])
    # invalid Content-Length and RDTFeatureLevel
    s.req('GET_PARAMETER', U, ['Content-Length: abc'])
    s.rep('200 OK', ['Content-Length: 12x', 'RDTFeatureLevel: zz'])
    s.req('GET_PARAMETER', U)
    s.rep('200 OK', ['Content-Length: -5'])
    # header line cut at the end of the segment (exception), and a line with no colon
    s.req('OPTIONS', '*')
    s.t.s(b'RTSP/1.0 200 OK\r\nCSeq: 11\r\nSession: 123\r\nAccept')
    s.t.fin()
    # interleaved frame longer than the data, header of the next message cut
    s = Sess(m, 41003)
    s.exch('SETUP', U + '/rdt', rheaders=[T + 'x-real-rdt/tcp;interleaved=4', 'Session: EEEE0001'])
    s.t.s(b'$\x04\x00\x0c' + b'\xff\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00')    # RDT channel, not an RDT packet
    s.t.fin()
    s = Sess(m, 41002)
    s.t.s(b'$\x00\x00\x40abc')
    s.t.s(b'$\x00')
    s.t.fin()
    m.write(os.path.join(out, 'rtsp-coverage-malformed.pcap'))

main(sys.argv[1])
