#!/usr/bin/env python3
# Generates test/captures/transum_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic capture for the TRANSUM plugin (plugins/epan/transum).

Usage: mktransum.py <outdir> [-v]   writes transum-coverage.pcap and
transum-coverage-malformed.pcap.  Everything is built with struct.
"""
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


class Cap:
    def __init__(self):
        self.frames = []
        self.t = 1700000000.0
        self.ipid = 1

    def add(self, fr, dt=0.001):
        self.t += dt
        self.frames.append((self.t, fr))
        return len(self.frames)

    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            for t, fr in self.frames:
                s = int(t)
                us = int(round((t - s) * 1e6))
                f.write(struct.pack('<IIII', s, us, len(fr), len(fr)) + fr)


def eth(payload, src, dst, et=0x0800):
    return bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) + struct.pack('!H', et) + payload


def ip4(src, dst, proto, payload, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def ip6(src, dst, nxt, payload):
    return struct.pack('!IHBB16s16s', 6 << 28, len(payload), nxt, 64, src, dst) + payload


def udp_hdr(sport, dport, payload):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


def udp6(src, dst, sport, dport, payload):
    u = udp_hdr(sport, dport, payload)
    ck = csum(src + dst + struct.pack('!IxxxB', len(u), 17) + u) or 0xffff
    return u[:6] + struct.pack('!H', ck) + u[8:]


def tcp_hdr(sport, dport, seq, ack, flags, payload):
    return struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff, 5 << 4,
                       flags, 65535, 0, 0) + payload


SYN, ACK, PSH, RST, FIN = 2, 0x10, 8, 4, 1

CL = bytes([192, 0, 2, 10])
SV = bytes([198, 51, 100, 20])


class Tcp:
    """One TCP connection; tracks sequence numbers."""

    def __init__(self, cap, cport, sport, cip=CL, sip=SV, cmac=1, smac=2, v6=False):
        self.cap = cap
        self.cport = cport
        self.sport = sport
        self.cip, self.sip = cip, sip
        self.cmac, self.smac = cmac, smac
        self.cseq = 1000
        self.sseq = 5000
        self.v6 = v6

    def frame(self, c2s, seq, ack, flags, payload):
        if c2s:
            seg = tcp_hdr(self.cport, self.sport, seq, ack, flags, payload)
            src, dst, sm, dm = self.cip, self.sip, self.cmac, self.smac
        else:
            seg = tcp_hdr(self.sport, self.cport, seq, ack, flags, payload)
            src, dst, sm, dm = self.sip, self.cip, self.smac, self.cmac
        if self.v6:
            return eth(ip6(src, dst, 6, seg), sm, dm, 0x86dd)
        self.cap.ipid += 1
        return eth(ip4(src, dst, 6, seg, self.cap.ipid), sm, dm)

    def syn(self, dt=0.001):
        n = self.cap.add(self.frame(True, self.cseq, 0, SYN, b''), dt)
        self.cseq += 1
        return n

    def synack(self, dt=0.001):
        n = self.cap.add(self.frame(False, self.sseq, self.cseq, SYN | ACK, b''), dt)
        self.sseq += 1
        return n

    def ack(self, c2s, dt=0.001):
        if c2s:
            return self.cap.add(self.frame(True, self.cseq, self.sseq, ACK, b''), dt)
        return self.cap.add(self.frame(False, self.sseq, self.cseq, ACK, b''), dt)

    def handshake(self, d1=0.001, d2=0.002, d3=0.001):
        a = self.syn(d1)
        self.synack(d2)
        self.ack(True, d3)
        return a

    def send(self, c2s, data, dt=0.001, flags=PSH | ACK):
        if c2s:
            n = self.cap.add(self.frame(True, self.cseq, self.sseq, flags, data), dt)
            self.cseq += len(data)
        else:
            n = self.cap.add(self.frame(False, self.sseq, self.cseq, flags, data), dt)
            self.sseq += len(data)
        return n

    def resend(self, c2s, data, back, dt=0.001):
        """Retransmit data that was sent `back` octets (= len(data)) ago."""
        if c2s:
            return self.cap.add(self.frame(True, self.cseq - back, self.sseq, PSH | ACK, data), dt)
        return self.cap.add(self.frame(False, self.sseq - back, self.cseq, PSH | ACK, data), dt)

    def keepalive(self, c2s, data=b'', dt=0.001):
        """Keep-alive probe: sequence number one below the next one."""
        if c2s:
            return self.cap.add(self.frame(True, self.cseq - 1, self.sseq, ACK, data), dt)
        return self.cap.add(self.frame(False, self.sseq - 1, self.cseq, ACK, data), dt)

    def rst(self, c2s, dt=0.001):
        if c2s:
            return self.cap.add(self.frame(True, self.cseq, self.sseq, RST | ACK, b''), dt)
        return self.cap.add(self.frame(False, self.sseq, self.cseq, RST | ACK, b''), dt)

    def fin(self, dt=0.001):
        self.cap.add(self.frame(True, self.cseq, self.sseq, FIN | ACK, b''), dt)
        self.cseq += 1
        self.cap.add(self.frame(False, self.sseq, self.cseq, FIN | ACK, b''), dt)
        self.sseq += 1
        self.cap.add(self.frame(True, self.cseq, self.sseq, ACK, b''), dt)


def http_req(path, body=b'', cl=None):
    h = b'POST ' + path + b' HTTP/1.1\r\nHost: example.test\r\n'
    if body or cl:
        h += b'Content-Length: %d\r\n' % (len(body) if cl is None else cl)
    return h + b'\r\n' + body


def http_rsp(body):
    return (b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n' % len(body)) + body


# ---------------------------------------------------------------- DCE/RPC
def uuid(s):
    import uuid as u
    return u.UUID(s).bytes_le


NDR = uuid('8a885d04-1ceb-11c9-9fe8-08002b104860')
IFACE = uuid('12345678-1234-abcd-ef00-0123456789ab')


def cn(ptype, body, call_id, flags=3):
    return struct.pack('<BBBB4BHHI', 5, 0, ptype, flags, 0x10, 0, 0, 0,
                       16 + len(body), 0, call_id) + body


def cn_bind(ptype, call_id, ctx=5):
    body = struct.pack('<HHIB3x', 4280, 4280, 0, 1)
    body += struct.pack('<HBx', ctx, 1) + IFACE + struct.pack('<HH', 1, 0) + NDR + struct.pack('<I', 2)
    return cn(ptype, body, call_id)


def cn_bind_ack(ptype, call_id):
    body = struct.pack('<HHIHxxB3x', 4280, 4280, 0x1234, 0, 1)
    body += struct.pack('<HH', 0, 0) + NDR + struct.pack('<I', 2)
    return cn(ptype, body, call_id)


def cn_req(call_id, stub, ctx=5, flags=3, opnum=1):
    return cn(0, struct.pack('<IHH', len(stub), ctx, opnum) + stub, call_id, flags)


def cn_rsp(call_id, stub, ctx=5, flags=3):
    return cn(2, struct.pack('<IHBx', len(stub), ctx, 0) + stub, call_id, flags)


def cn_fault(call_id, ctx=5):
    return cn(3, struct.pack('<IHBxII', 0, ctx, 0, 0x1c010003, 0), call_id)


# ---------------------------------------------------------------- SMB
def nbss(b):
    return struct.pack('!I', len(b)) + b


def smb2(cmd, mid, sesid, flags=0, nxt=0, body=None, credit=1):
    if body is None:
        body = struct.pack('<HH', 4, 0)       # Echo request/response
    return b'\xfeSMB' + struct.pack('<HHIHHIIQIIQ16s', 64, 0, 0, cmd, credit, flags, nxt, mid,
                                    0, 0, sesid, b'\0' * 16) + body


def smb1(cmd, mid, wct_bytes, data, rsp=False):
    hdr = b'\xffSMB' + struct.pack('<BIBHH8sHHHHH', cmd, 0, 0x98 | (0x80 if rsp else 0), 0xc843, 0,
                                   b'\0' * 8, 0, 0, 0, 0, mid)
    return hdr + wct_bytes + struct.pack('<H', len(data)) + data


# ---------------------------------------------------------------- DNS
def dns(idn, qr, name=b'\x07example\x04test\x00', answers=0, rcode=0):
    flags = (0x8180 if qr else 0x0100) | rcode
    h = struct.pack('!HHHHHH', idn, flags, 1, answers, 0, 0)
    q = name + struct.pack('!HH', 1, 1)
    a = b''
    for i in range(answers):
        a += b'\xc0\x0c' + struct.pack('!HHIH4s', 1, 1, 60, 4, bytes([203, 0, 113, 1 + i]))
    return h + q + a


def udp4(cap, sport, dport, payload, c2s=True, dt=0.001, cip=CL, sip=SV, cm=1, sm=2):
    if c2s:
        fr = eth(ip4(cip, sip, 17, udp_hdr(sport, dport, payload), cap.ipid), cm, sm)
    else:
        fr = eth(ip4(sip, cip, 17, udp_hdr(dport, sport, payload), cap.ipid), sm, cm)
    cap.ipid += 1
    return cap.add(fr, dt)


def build_main(cap, notes):
    def note(name, first):
        notes.append((name, first))

    # ---- 1. HTTP on port 80: request, two segment response, second request
    #         in two segments, response in one; FIN
    c = Tcp(cap, 40001, 80)
    note('HTTP port 80: handshake, 1 segment request, 3 segment response, 2 segment request, missing response, retransmissions, keep-alives', 1)
    c.handshake()
    c.send(True, http_req(b'/a'), 0.010)
    c.send(False, http_rsp(b'x' * 3000)[:1400], 0.020, ACK)
    c.send(False, http_rsp(b'x' * 3000)[1400:2800], 0.003, ACK)
    c.send(False, http_rsp(b'x' * 3000)[2800:], 0.004)
    c.ack(True)
    body = b'y' * 2000
    r = http_req(b'/b', body)
    c.send(True, r[:1000], 0.050, ACK)
    c.send(True, r[1000:], 0.002)
    c.send(False, http_rsp(b'ok'), 0.015)
    c.ack(True)
    # a third request that gets no response (response missing)
    c.send(True, http_req(b'/c'), 0.100)
    # a request and response whose reply comes after a retransmission of
    # both
    c.send(True, http_req(b'/d'), 0.050)
    c.resend(True, http_req(b'/d'), len(http_req(b'/d')), 0.200)
    rr = http_rsp(b'dd')
    c.send(False, rr, 0.020)
    c.resend(False, rr, len(rr), 0.100)
    c.ack(True)
    # keep-alive probes of both sides (one with a one octet payload)
    c.keepalive(True, b'', 5.0)
    c.keepalive(False, b'', 0.001)
    c.keepalive(True, b'\x00', 0.001)
    # a normal one octet segment with ACK (not a keep-alive: orphan
    # keep-alive discard preference)
    c.send(True, b'\x00', 0.001, ACK)
    c.send(False, b'\x00', 0.001, ACK)
    c.fin()

    # ---- 2. Port 80 stream without a handshake: server first, then a
    #         response of the next stream (stream exception list)
    n = len(cap.frames) + 1
    note('Port 80 mid-stream capture: the server sends first (stream exception), then the client', n)
    c = Tcp(cap, 40002, 80)
    c.sseq = 9000
    c.cseq = 7000
    c.send(False, http_rsp(b'late'), 0.5)
    c.send(True, http_req(b'/e'), 0.010)
    c.send(False, http_rsp(b'again'), 0.010)

    # ---- 3. SMTP port 25 banner, server first with SYN: banner, EHLO etc
    n = len(cap.frames) + 1
    note('SMTP port 25: handshake, banner, EHLO, reply (response before request on the stream)', n)
    c = Tcp(cap, 40003, 25)
    c.handshake()
    c.send(False, b'220 mail.example.test ESMTP\r\n', 0.030)
    c.send(True, b'EHLO client.example.test\r\n', 0.010)
    c.send(False, b'250-mail.example.test\r\n', 0.004, ACK)
    c.send(False, b'250 8BITMIME\r\n', 0.001)
    c.send(True, b'QUIT\r\n', 0.020)
    c.send(False, b'221 Bye\r\n', 0.003)
    c.fin()

    # ---- 4. TLS on 443 with an alert from each side, and a SYN to a closed
    #         port with RST
    n = len(cap.frames) + 1
    note('TLS port 443: handshake records, application data, alerts of both sides (SSL alerts are skipped)', n)
    c = Tcp(cap, 40004, 443)
    c.handshake()
    hello = b'\x16\x03\x03' + struct.pack('!H', 4) + b'\x00\x00\x00\x00'
    c.send(True, hello, 0.010)
    c.send(False, b'\x16\x03\x03' + struct.pack('!H', 4) + b'\x0e\x00\x00\x00', 0.010)
    c.send(True, b'\x17\x03\x03' + struct.pack('!H', 8) + b'\x00' * 8, 0.010)
    c.send(False, b'\x17\x03\x03' + struct.pack('!H', 8) + b'\x00' * 8, 0.010)
    c.send(True, b'\x15\x03\x03\x00\x02\x01\x00', 0.010)
    c.send(False, b'\x15\x03\x03\x00\x02\x01\x00', 0.010)
    c.fin()

    n = len(cap.frames) + 1
    note('SYN to a closed port 9: RST; SYN, SYN/ACK to port 9001 (detected service), a SYN that is retransmitted', n)
    c = Tcp(cap, 40005, 9)
    c.syn(0.5)
    c.rst(False, 0.001)
    c = Tcp(cap, 40006, 9001)
    c.syn(0.3)
    c.cap.add(c.frame(True, c.cseq - 1, 0, SYN, b''), 1.0)     # SYN retransmitted
    c.synack(0.010)
    c.ack(True, 0.001)
    # data on a detected port that is not a service port: only the SYN
    # exchange counts
    c.send(True, b'hello\n', 0.010)
    c.send(False, b'world\n', 0.010)
    c.rst(True)
    # a second SYN on the same port with no answer (response missing)
    c = Tcp(cap, 40007, 9001)
    c.syn(0.2)
    c = Tcp(cap, 40008, 9001)
    c.syn(0.2)
    c.synack(0.01)

    # ---- 5. DCE/RPC on TCP 135 (heuristic) -> service port learned
    n = len(cap.frames) + 1
    note('DCE/RPC port 135: handshake, bind, bind_ack, request, response, a fragmented request, alter context, fault', n)
    c = Tcp(cap, 40010, 135)
    c.handshake()
    c.send(True, cn_bind(11, 1), 0.020)
    c.send(False, cn_bind_ack(12, 1), 0.004)
    c.send(True, cn_req(2, b'A' * 40), 0.010)
    c.send(False, cn_rsp(2, b'B' * 64), 0.012)
    # two fragment request: first fragment, then the last fragment
    c.send(True, cn_req(3, b'C' * 60, flags=1), 0.020)
    c.send(True, cn_req(3, b'C' * 60, flags=2), 0.002)
    c.send(False, cn_rsp(3, b'D' * 32), 0.020)
    # a request, its retransmission, the response and a second response
    # fragment of a different call
    c.send(True, cn_req(4, b'E' * 16), 0.010)
    c.resend(True, cn_req(4, b'E' * 16), len(cn_req(4, b'E' * 16)), 0.100)
    c.send(False, cn_rsp(4, b'F' * 16), 0.010)
    # alter context with the context ids 6 and 7
    c.send(True, cn_bind(14, 5, ctx=6), 0.020)
    c.send(False, cn_bind_ack(15, 5), 0.002)
    c.send(True, cn_req(6, b'G' * 8, ctx=6), 0.010)
    c.send(False, cn_fault(6, ctx=6), 0.010)
    # a request whose PDU spans two TCP segments (continuation without
    # a header), and a response with a header that is cut after the header
    rq = cn_req(7, b'H' * 1400)
    c.send(True, rq[:1000], 0.010, ACK)
    c.send(True, rq[1000:], 0.001)
    rp = cn_rsp(7, b'I' * 1400)
    c.send(False, rp[:1000], 0.010, ACK)
    c.send(False, rp[1000:], 0.001)
    # retransmission of the last response segment after the call finished
    c.resend(False, rp[1000:], len(rp[1000:]), 0.3)
    c.fin()

    # a second connection on port 135 (now a service port): data that is
    # not DCE/RPC comes first, then a bind and a call
    n2 = len(cap.frames) + 1
    c = Tcp(cap, 40012, 135)
    c.handshake()
    c.send(True, b'not dce/rpc data', 0.010)
    c.send(False, b'not dce/rpc reply', 0.010)
    c.send(True, cn_bind(11, 1), 0.020)
    c.send(False, cn_bind_ack(12, 1), 0.004)
    c.send(True, cn_req(2, b'N' * 16), 0.010)
    c.send(False, cn_rsp(2, b'O' * 16), 0.010)
    c.fin()

    # a second connection, in which the bind only appears in the middle
    # of the stream without SYN (DCE/RPC on a port that is not 135)
    n = len(cap.frames) + 1
    note('DCE/RPC on port 49664 without handshake: request with the response before it, second call', n)
    c = Tcp(cap, 40011, 49664)
    c.send(True, cn_req(1, b'J' * 16), 0.1)
    c.send(False, cn_rsp(1, b'K' * 16), 0.020)
    c.send(True, cn_req(2, b'L' * 16), 0.020)
    c.send(False, cn_rsp(2, b'M' * 16), 0.020)

    # ---- 6. SMB2 on 445
    n = len(cap.frames) + 1
    note('SMB2 port 445: handshake, echo request/response, compound (two commands in one PDU), PDUs split over segments, a response without request, a retransmission', n)
    c = Tcp(cap, 40020, 445)
    c.handshake()
    c.send(True, nbss(smb2(0x0d, 1, 0x1111)), 0.020)
    c.send(False, nbss(smb2(0x0d, 1, 0x1111, flags=1)), 0.003)
    # compound request: MessageIds 2 and 3, 72 octets aligned
    a = smb2(0x0d, 2, 0x1111, nxt=72) + b'\0' * 4
    b = smb2(0x0d, 3, 0x1111, flags=0x4)
    c.send(True, nbss(a + b), 0.010)
    a = smb2(0x0d, 2, 0x1111, flags=1, nxt=72) + b'\0' * 4
    b = smb2(0x0d, 3, 0x1111, flags=0x4 | 1)
    c.send(False, nbss(a + b), 0.010)
    # a compound request with 20 commands (more than transum keeps) and the
    # response; the last message ids repeat on the retransmitted response
    cmds = b''
    for i in range(20):
        last = i == 19
        cmds += smb2(0x0d, 20 + i, 0x1111, nxt=0 if last else 72) + (b'' if last else b'\0' * 4)
    c.send(True, nbss(cmds), 0.010)
    cmds = b''
    for i in range(20):
        last = i == 19
        cmds += smb2(0x0d, 20 + i, 0x1111, flags=1, nxt=0 if last else 72) + (b'' if last else b'\0' * 4)
    c.send(False, nbss(cmds), 0.010)
    # request in two segments, response in two segments
    q = nbss(smb2(0x0d, 4, 0x1111))
    c.send(True, q[:40], 0.010, ACK)
    c.send(True, q[40:], 0.002)
    q = nbss(smb2(0x0d, 4, 0x1111, flags=1))
    c.send(False, q[:40], 0.010, ACK)
    c.send(False, q[40:], 0.002)
    c.resend(False, q[40:], len(q[40:]), 0.1)
    # request retransmission
    q = nbss(smb2(0x0d, 5, 0x1111))
    c.send(True, q, 0.010)
    c.resend(True, q, len(q), 0.2)
    c.send(False, nbss(smb2(0x0d, 5, 0x1111, flags=1)), 0.005)
    # a new session with other ids; response first (async-style)
    c.send(False, nbss(smb2(0x0d, 9, 0x2222, flags=1)), 0.050)
    c.send(True, nbss(smb2(0x0d, 9, 0x2222)), 0.050)
    c.send(False, nbss(smb2(0x0d, 9, 0x2222, flags=1)), 0.050)
    # an SMB1 negotiate and response (smb.mid): not processed
    c.send(True, nbss(smb1(0x72, 7, b'\x00', b'\x02NT LM 0.12\x00')), 0.050)
    c.send(False, nbss(smb1(0x72, 7, b'\x00', b'', rsp=True)), 0.010)
    c.fin()

    # ---- 7. UDP: NBNS on 137 (generic UDP service port), DNS on 53
    n = len(cap.frames) + 1
    note('UDP 137 (NBNS, generic UDP service port 137-139): request, response, a second request and no response', n)
    nb = struct.pack('!HHHHHH', 0x1234, 0x0110, 1, 0, 0, 0) + b'\x20' + b'EGFDEBEEEPCACACACACACACACACACAAA' + b'\x00' + struct.pack('!HH', 0x20, 1)
    nbr = struct.pack('!HHHHHH', 0x1234, 0x8500, 0, 1, 0, 0) + b'\x20' + b'EGFDEBEEEPCACACACACACACACACACAAA' + b'\x00' + struct.pack('!HHIHH4s', 0x20, 1, 300, 6, 0, bytes([192, 0, 2, 33]))
    udp4(cap, 137, 137, nb, True, 0.5)
    udp4(cap, 137, 137, nbr, False, 0.003)
    udp4(cap, 137, 137, nb, True, 0.2)
    # a datagram service on 138 with the same endpoints in the other direction first
    udp4(cap, 138, 138, b'\x11\x02\x00\x01' + b'\0' * 30, False, 0.2, cip=CL, sip=SV)
    udp4(cap, 138, 138, b'\x11\x02\x00\x02' + b'\0' * 30, True, 0.2)
    udp4(cap, 138, 138, b'\x11\x02\x00\x03' + b'\0' * 30, True, 0.2)
    udp4(cap, 138, 138, b'\x11\x02\x00\x04' + b'\0' * 30, False, 0.2)
    # request, response, request again (generic UDP, a new pair)
    udp4(cap, 40138, 138, b'\x11\x02\x00\x05' + b'\0' * 30, True, 0.2)
    udp4(cap, 40138, 138, b'\x11\x02\x00\x06' + b'\0' * 30, False, 0.01)
    udp4(cap, 40138, 138, b'\x11\x02\x00\x07' + b'\0' * 30, True, 0.2)
    udp4(cap, 40138, 138, b'\x11\x02\x00\x08' + b'\0' * 30, False, 0.01)
    # other UDP: not a service port
    udp4(cap, 50000, 50001, b'plain datagram', True, 0.1)
    udp4(cap, 50000, 50001, b'plain reply', False, 0.1)

    n = len(cap.frames) + 1
    note('DNS UDP 53: query/response, a query with no response, a retransmitted query, a response before its query, the same ID reused after the response, an unmatched response, NXDOMAIN, two interleaved queries', n)
    udp4(cap, 41000, 53, dns(0x0001, 0), True, 0.5)
    udp4(cap, 41000, 53, dns(0x0001, 1, answers=1), False, 0.020)
    udp4(cap, 41000, 53, dns(0x0002, 0), True, 0.1)
    udp4(cap, 41000, 53, dns(0x0002, 0), True, 1.0)            # retransmitted query
    udp4(cap, 41000, 53, dns(0x0002, 1, answers=2), False, 0.030)
    udp4(cap, 41000, 53, dns(0x0002, 1, answers=2), False, 0.030)   # duplicate response
    udp4(cap, 41000, 53, dns(0x0001, 0), True, 0.1)            # ID reused: new pair
    udp4(cap, 41000, 53, dns(0x0001, 1, rcode=3), False, 0.050)
    udp4(cap, 41000, 53, dns(0x0003, 1, answers=1), False, 0.1)  # response with no query
    udp4(cap, 41000, 53, dns(0x0004, 0), True, 0.1)
    udp4(cap, 41000, 53, dns(0x0005, 0), True, 0.001)
    udp4(cap, 41000, 53, dns(0x0005, 1, answers=1), False, 0.010)
    udp4(cap, 41000, 53, dns(0x0004, 1, answers=1), False, 0.010)
    udp4(cap, 41001, 53, dns(0x0001, 0), True, 0.1)           # other client port: other stream
    # DNS from a port 53 to port 53 (both directions are "to the service")
    udp4(cap, 53, 53, dns(0x0010, 0), True, 0.1)
    # a query without a response on a stream of its own
    udp4(cap, 41002, 53, dns(0x0020, 0), True, 0.1, cip=bytes([192, 0, 2, 11]))

    # ---- 8. IPv6 TCP and UDP, ICMP and ARP
    n = len(cap.frames) + 1
    note('IPv6: TCP port 80 request and response, DNS over UDP; ICMP echo; ARP', n)
    a6 = bytes.fromhex('20010db8000000000000000000000010')
    b6 = bytes.fromhex('20010db8000000000000000000000020')
    c = Tcp(cap, 40030, 80, cip=a6, sip=b6, v6=True)
    c.handshake()
    c.send(True, http_req(b'/v6'), 0.010)
    c.send(False, http_rsp(b'v6'), 0.010)
    c.fin()
    cap.add(eth(ip6(a6, b6, 17, udp6(a6, b6, 41100, 53, dns(0x0100, 0))), 1, 2, 0x86dd), 0.1)
    cap.add(eth(ip6(b6, a6, 17, udp6(b6, a6, 53, 41100, dns(0x0100, 1, answers=1))), 2, 1, 0x86dd), 0.01)
    echo = struct.pack('!BBHHH', 8, 0, 0, 1, 1) + b'ping'
    echo = echo[:2] + struct.pack('!H', csum(echo)) + echo[4:]
    cap.add(eth(ip4(CL, SV, 1, echo, 99), 1, 2), 0.1)
    arp = struct.pack('!HHBBH6s4s6s4s', 1, 0x0800, 6, 4, 1, bytes([2, 0, 0, 0, 0, 1]), CL, b'\0' * 6, SV)
    cap.add(bytes([0xff] * 6) + bytes([2, 0, 0, 0, 0, 1]) + struct.pack('!H', 0x0806) + arp, 0.1)

    # ---- 9. a SYN/ACK without the SYN, a request on a plain port 1433 and
    #         a connection reset in the middle of a response
    n = len(cap.frames) + 1
    note('Port 25: SYN/ACK without SYN, request, response, reset; TCP segments with no payload', n)
    c = Tcp(cap, 40040, 25)
    c.synack(0.1)
    c.ack(True)
    c.send(True, b'HELO a\r\n', 0.01)
    c.send(False, b'250 ok\r\n', 0.01)
    c.send(True, b'HELO a\r\n', 0.01)
    c.rst(False, 0.01)

    # many DNS queries with distinct IDs on one stream (the quadratic
    # reproducer, a few hundred queries are enough to run the index)
    n = len(cap.frames) + 1
    note('Reproducer of the quadratic search: 300 DNS queries with distinct IDs on one UDP stream (every 3rd answered), and 40 short TCP request/response pairs on a stream', n)
    for i in range(300):
        udp4(cap, 42000, 53, dns(0x1000 + i, 0), True, 0.001, cip=bytes([192, 0, 2, 12]))
        if i % 3 == 0:
            udp4(cap, 42000, 53, dns(0x1000 + i, 1, answers=1), False, 0.001, cip=bytes([192, 0, 2, 12]))
    c = Tcp(cap, 40060, 80)
    c.handshake()
    for i in range(40):
        c.send(True, http_req(b'/q%d' % i), 0.002)
        c.send(False, http_rsp(b'r'), 0.002)
    c.fin()


def build_malformed(cap, notes):
    # truncated SMB2 header (2 octets after the protocol id), DNS packets
    # that are too short and a DCE/RPC PDU that is cut after the version
    c = Tcp(cap, 41010, 445)
    c.handshake()
    c.send(True, nbss(b'\xfeSMB\x40\x00'), 0.01)
    c.send(False, nbss(b'\xfeSMB\x40\x00'), 0.01)
    c.send(True, nbss(b'\xfeSMB' + b'\0' * 12), 0.01)
    c.send(False, nbss(b'\xfeSMB' + b'\0' * 12), 0.01)
    udp4(cap, 43000, 53, b'\x00\x01\x01', True, 0.1)
    udp4(cap, 43000, 53, b'\x00\x01\x81\x80\x00', False, 0.1)
    c = Tcp(cap, 41011, 135)
    c.handshake()
    c.send(True, b'\x05\x00\x00', 0.01)
    c.send(False, b'\x05\x00\x02\x03' + b'\0' * 8, 0.01)
    c.send(True, b'\x05\x00\x00\x03\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00', 0.01)   # truncated body
    c.send(False, cn_rsp(1, b'x' * 10)[:30], 0.01)
    # ---- the reproducer of the fixed uninitialised read: SMB2 PDUs whose
    #          header is cut right after the MessageId
    c = Tcp(cap, 40050, 445)
    c.handshake()
    for i in range(4):
        hdr = (b'\xfeSMB' + struct.pack('<HHIHHIIQ', 64, 0, 0, 0x0d, 1, 0, 0, 100 + i))[:32]
        c.send(True, nbss(hdr), 0.01)
        hdr = (b'\xfeSMB' + struct.pack('<HHIHHIIQ', 64, 0, 0, 0x0d, 1, 1, 0, 100 + i))[:32]
        c.send(False, nbss(hdr), 0.01)


if __name__ == '__main__':
    out = sys.argv[1]
    notes = []
    cap = Cap()
    build_main(cap, notes)
    cap.write(os.path.join(out, 'transum-coverage.pcap'))
    if '-v' in sys.argv:
        print(len(cap.frames), 'frames')
        for i, (nme, first) in enumerate(notes):
            nxt = notes[i + 1][1] - 1 if i + 1 < len(notes) else len(cap.frames)
            print('%d-%d: %s' % (first, nxt, nme))
    cap2 = Cap()
    build_malformed(cap2, [])
    cap2.write(os.path.join(out, 'transum-coverage-malformed.pcap'))
