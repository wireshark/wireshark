#!/usr/bin/env python3
# Generates test/captures/hislip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the HiSLIP dissector (packet-hislip.c).

HiSLIP (IVI-6.1, High-Speed LAN Instrument Protocol) runs over TCP port
4880 with a 16 octet header: prologue "HS", message type, control code,
a 32 bit message parameter and a 64 bit payload length. A session has a
synchronous and an asynchronous connection (each its own TCP connection
here); HiSLIP 2.0 adds descriptors, TLS start/end and SASL
authentication. TLS records are never generated: after a StartTLS only
plaintext "HS" frames and a frame with the wrong prologue (which is
handed to the TLS dissector as unrecognisable bytes) are used. Every
packet is built with struct; addresses are from 192.0.2.0/24.

Usage: mkhislip.py <output directory>
Writes hislip-coverage.pcap and hislip-coverage-malformed.pcap.
"""
import struct
import sys
import os

PORT = 4880

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def tcp_pkt(src, dst, sport, dport, seq, ack, payload, flags=0x18):
    opts = struct.pack('!BBH', 2, 4, 1460) if flags & 0x02 else b''
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    ps = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', csum(ps + tcp)) + tcp[18:]
    return b'\x02\0\0\0\0\x02' + b'\x02\0\0\0\0\x01' + b'\x08\x00' + ip + tcp

def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)

class Flow:
    def __init__(self, cport, sport=PORT, c=(192,0,2,1), s=(192,0,2,2), handshake=True):
        self.c, self.s, self.cp, self.sp = c, s, cport, sport
        self.cseq, self.sseq = 1000, 5000
        self.pkts = []
        if handshake:
            self.pkts.append(tcp_pkt(c, s, cport, sport, self.cseq, 0, b'', 0x02)); self.cseq += 1
            self.pkts.append(tcp_pkt(s, c, sport, cport, self.sseq, self.cseq, b'', 0x12)); self.sseq += 1
            self.pkts.append(tcp_pkt(c, s, cport, sport, self.cseq, self.sseq, b'', 0x10))
    def c2s(self, data):
        self.pkts.append(tcp_pkt(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, data)); self.cseq += len(data)
    def s2c(self, data):
        self.pkts.append(tcp_pkt(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, data)); self.sseq += len(data)

# message types
(INIT, INITR, FATAL, ERR, ALOCK, ALOCKR, DATA, DATAEND, DCCOMPLETE, DCACK, ARLC, ARLCR,
 TRIG, INTR, AINTR, AMAXMSG, AMAXMSGR, AINIT, AINITR, ADC, ASRQ, ASTAT, ASTATR, ADCACK,
 ALOCKINFO, ALOCKINFOR, GETDESC, GETDESCR, STARTTLS, ASTARTTLS, ASTARTTLSR, ENDTLS,
 AENDTLS, AENDTLSR, GETSASL, GETSASLR, AUTHSTART, AUTHEX, AUTHRES) = range(39)

def hs(mtype, cc=0, param=0, payload=b'', prologue=b'HS', length=None):
    return prologue + struct.pack('!BBIQ', mtype, cc, param, len(payload) if length is None else length) + payload

def desc(t, content):
    return struct.pack('!HB', len(content), t) + content

def sync_frames():
    """Synchronous channel of a session on port 4880 (client 40100)."""
    f = Flow(40100)
    f.c2s(hs(INIT, 0, (0x0100 << 16) | 0x5253, b'hislip0'))               # vendor R&S
    f.s2c(hs(INITR, 0x00, (0x0100 << 16) | 0x0001))                         # prefer synchronized, optional, not required
    f.c2s(hs(INIT, 0, (0x0200 << 16) | 0x4B45, b'inst0'))                  # Keithley, a second init (retransmission)
    f.c2s(hs(INIT, 0, (0x0200 << 16) | 0x4747, b'inst1'))                  # unknown vendor
    f.s2c(hs(INITR, 0x07, (0x0200 << 16) | 0x0002))                         # overlap, mandatory encryption, initial encryption
    f.c2s(hs(DATA, 0, 0xffffff00, b'*IDN?\n'))                              # RMT delivered = 0
    f.c2s(hs(DATAEND, 1, 0xffffff02, b'MEAS:VOLT?\n'))                      # RMT delivered
    f.s2c(hs(DATAEND, 1, 0xffffff02, b'KEYSIGHT,SYNTHETIC,0,1.0\n'))
    f.c2s(hs(DATA, 0, 0xffffff04, b'x' * 200))                              # payload longer than the 60 shown
    f.c2s(hs(DATAEND, 0, 0xffffff06))                                       # no payload
    f.c2s(hs(TRIG, 1, 0xffffff08))
    f.c2s(hs(INTR, 0, 0xffffff0a))
    f.s2c(hs(DCACK, 0x01, 0))
    f.s2c(hs(DCCOMPLETE, 0x00, 0))
    f.c2s(hs(DCCOMPLETE, 0x01, 0))
    f.s2c(hs(DCACK, 0x06, 0))
    f.s2c(hs(ERR, 1, 0, b'unrecognized message'))
    f.s2c(hs(ERR, 2))
    f.s2c(hs(ERR, 3))
    f.s2c(hs(ERR, 4))
    f.s2c(hs(ERR, 5))
    f.s2c(hs(ERR, 6))
    f.s2c(hs(ERR, 0x80))
    f.s2c(hs(ERR, 0, 0))
    f.s2c(hs(FATAL, 0, 0, b'unidentified'))
    for cc in (1, 2, 3, 4, 5, 6, 0x80):
        f.s2c(hs(FATAL, cc))
    f.c2s(hs(0x63, 0, 0))                                                   # unknown message type, zero parameter
    f.c2s(hs(0x63, 9, 0x1234, b'unknown payload'))                          # unknown, non-zero parameter and payload
    f.c2s(hs(ARLCR, 0, 0))                                                  # AsyncRemoteLocalResponse on the sync channel
    # HiSLIP 2.0 on the sync channel
    f.c2s(hs(GETDESC))
    f.s2c(hs(GETDESCR, 0, 0, desc(0, struct.pack('!HHH', 0x0303, 0x0304, 0x0302)) +
                             desc(1, b'TLS_AES_256_GCM_SHA384') + desc(2, b'no error') +
                             desc(3, b'\x01\x02\x03') + desc(0x80, b'vendor') + desc(1, b'')))
    f.c2s(hs(GETDESC))                                                      # second request, empty response
    f.s2c(hs(GETDESCR))
    f.c2s(hs(GETSASL))
    f.s2c(hs(GETSASLR, 0, 0, b'PLAIN SCRAM-SHA-256'))
    f.c2s(hs(AUTHSTART, 0, 0, b'PLAIN placeholder'))
    f.c2s(hs(AUTHEX, 0, 0, b'step'))
    f.s2c(hs(AUTHRES, 1, 0, b'ok'))
    f.c2s(hs(AUTHSTART, 0, 0, b'SCRAM'))
    f.s2c(hs(AUTHRES, 0, 7, b'denied'))
    # TLS: StartTLS, then plaintext HS (clears the TLS flag), then a frame
    # with the wrong prologue which is passed to the TLS dissector
    f.c2s(hs(STARTTLS))
    f.c2s(hs(DATA, 0, 0xffffff0c, b'*IDN?\n'))
    f.c2s(hs(DATA, 0, 0xffffff0e, b'after plaintext'))
    f.c2s(hs(ENDTLS))
    f.c2s(hs(DATA, 0, 0xffffff10, b'*OPC?\n', prologue=b'XS'))               # wrong prologue (reproducer hislip_tls_state)
    return f.pkts

def async_frames():
    g = Flow(40101)
    g.c2s(hs(AINIT, 0, 0x00000a1b))                                         # session id 0x0a1b
    g.s2c(hs(AINITR, 0x00, 0x00005253))                                     # no capability
    g.c2s(hs(AINIT, 0, 0x0000ffff))                                         # second init
    g.s2c(hs(AINITR, 0x01, 0x00004B45))                                     # secure connection capability (also resp_state repro)
    g.s2c(hs(AINITR, 0x01, 0x00004B45))
    g.c2s(hs(ALOCK, 1, 5000))                                               # request exclusive, timeout
    g.s2c(hs(ALOCKR, 1))                                                    # success exclusive
    g.c2s(hs(ALOCK, 1, 1000, b'sharedname'))                                # request shared
    g.s2c(hs(ALOCKR, 2))
    g.c2s(hs(ALOCK, 1, 10, b'lockname'))
    g.s2c(hs(ALOCKR, 3))
    g.c2s(hs(ALOCK, 0, 0xffffff04))                                         # release
    g.s2c(hs(ALOCKR, 0))
    g.c2s(hs(ALOCK, 0, 0xffffff06))
    g.s2c(hs(ALOCKR, 1))
    g.c2s(hs(ALOCK, 1, 20))
    g.s2c(hs(ALOCKR, 0))                                                    # request refused
    g.c2s(hs(ALOCK, 0, 0xffffff07))
    g.s2c(hs(ALOCKR, 2))                                                    # release response, shared
    g.c2s(hs(ALOCKINFO))
    g.s2c(hs(ALOCKINFOR, 1, 3))
    g.c2s(hs(ALOCKINFO))
    g.s2c(hs(ALOCKINFOR, 0, 0))
    for cc in range(8):
        g.c2s(hs(ARLC, cc, 0xffffff08 + cc))
    g.s2c(hs(ARLCR, 0x01, 0))
    g.c2s(hs(AINTR, 0, 0xffffff20))
    g.c2s(hs(AMAXMSG, 0, 0, struct.pack('!Q', 1 << 20)))
    g.s2c(hs(AMAXMSGR, 0, 0, struct.pack('!Q', 64 << 20)))
    g.c2s(hs(AMAXMSG, 0, 0, b'odd'))                                        # payload not 8 octets
    g.s2c(hs(AMAXMSGR, 0, 0, b'odd'))
    g.c2s(hs(ADC))
    g.s2c(hs(ADCACK, 0x01))
    g.s2c(hs(ASRQ, 0x40))                                                   # service request with status byte
    g.c2s(hs(ASTAT, 1, 0xffffff30))
    g.s2c(hs(ASTATR, 0x50))
    g.c2s(hs(ASTAT, 0, 0xffffff31))
    g.s2c(hs(ASTATR, 0x00))
    # TLS on the asynchronous channel
    g.c2s(hs(ASTARTTLS, 1, 0xffffff40, struct.pack('!I', 0xffffff3f)))      # last received MessageID
    g.s2c(hs(ASTARTTLSR, 0))                                                # failed
    g.c2s(hs(ASTARTTLS, 1, 0xffffff41, b'odd payload'))                     # payload not 4 octets
    g.s2c(hs(ASTARTTLSR, 1))                                                # accepted: TLS follows
    g.c2s(hs(AENDTLS, 1, 0xffffff42, struct.pack('!I', 0xffffff41)))
    g.c2s(hs(AENDTLS, 0, 0xffffff43, b'odd'))
    g.s2c(hs(AENDTLSR, 1))
    g.s2c(hs(AENDTLSR, 3))
    g.c2s(hs(ALOCKINFO))
    return g.pkts

def framing_frames():
    h = Flow(40102)
    # two PDUs in one segment, a PDU over three segments, a header split
    h.c2s(hs(DATA, 0, 0xffffff50, b'first') + hs(DATAEND, 0, 0xffffff52, b'second'))
    p = hs(DATA, 0, 0xffffff54, b'z' * 100)
    h.c2s(p[:10]); h.c2s(p[10:60]); h.c2s(p[60:])
    p = hs(DATAEND, 0, 0xffffff56, b'tail')
    h.c2s(p[:3]); h.c2s(p[3:])
    return h.pkts

def reproducer_frames():
    """hislip_resp_state and hislip_tls_state on their own connections
    (also present in the sync/async runs above)."""
    r = Flow(40103)
    r.c2s(hs(AINIT, 0, 0x5253))
    r.s2c(hs(AINITR, 1, 0x5253))
    r.s2c(hs(AINITR, 1, 0x5253))
    t = Flow(40104)
    t.c2s(hs(INIT, 0, 0x01000000 | 0x5253, b'hislip0'))
    t.s2c(hs(INITR, 0, 0x01000001))
    t.c2s(hs(STARTTLS))
    t.c2s(hs(DATA, 0, 0xffffff00, b'*IDN?\n'))
    t.c2s(b'XS' + struct.pack('!BBIQ', DATA, 0, 0, 0))
    # StartTLS followed directly by bytes that are not HiSLIP: the frame is
    # handed to the TLS dissector (placeholder bytes, not a TLS record)
    u = Flow(40105)
    u.c2s(hs(INIT, 0, 0x01000000 | 0x5253, b'hislip0'))
    u.s2c(hs(INITR, 0x06, 0x01000001))
    u.c2s(hs(STARTTLS))
    u.c2s(b'\x00\x01placeholder bytes, not a TLS record')
    u.c2s(b'\x00\x02more placeholder bytes')
    return r.pkts + t.pkts + u.pkts

def main_frames():
    return sync_frames() + async_frames() + framing_frames() + reproducer_frames()

def malformed_frames():
    F = []
    # wrong prologue on a first PDU (the conversation keeps going)
    f = Flow(41000)
    f.c2s(hs(DATA, 0, 0xffffff00, b'bad prologue', prologue=b'XX'))
    f.c2s(hs(DATA, 0, 0xffffff02, b'HS', prologue=b'HS'))
    # descriptors: content longer than the payload, trailing octets, odd TLS version list
    f.s2c(hs(GETDESCR, 0, 0, b'\x00\x10\x01abc'))
    f.s2c(hs(GETDESCR, 0, 0, desc(0, b'\x03\x03\x04') ))                  # odd number of version octets
    f.s2c(hs(GETDESCR, 0, 0, desc(1, b'info') + b'\x00\x01'))             # 2 trailing octets
    f.s2c(hs(GETDESCR, 0, 0, desc(1, b'info') + b'\x00'))                 # 1 trailing octet
    f.s2c(hs(GETDESCR, 0, 0, b'\x00\x00'))                                # too short for a header
    # payload length larger than the data (reassembly never completes)
    f.c2s(hs(DATA, 0, 0xffffff04, b'short', length=1000))
    F += f.pkts
    # 64 bit payload length truncated to 32 bits (reproducer hislip_len64)
    g = Flow(41001)
    g.c2s(hs(DATA, 0, 1, b'ABCD', length=(1 << 32) + 4) + hs(DATAEND, 0, 2, b'xyz'))
    g.s2c(hs(GETDESCR, 0, 0, struct.pack('!HB', 2, 0) + b'\x03\x03', length=0x80000000))
    F += g.pkts
    # the heuristic (disabled by default; runcov.sh enables it) on port 4881
    m = Flow(41003, 4881)
    m.c2s(hs(DATA, 0, 0xffffff00, b'heuristic'))
    m.c2s(b'HS\x06\x00\x00\x00\x00\x00')                                  # shorter than a header
    m.c2s(b'XS' + bytes(18))                                               # not HiSLIP
    m.c2s(hs(DATAEND, 0, 0xffffff02, b'more'))
    F += m.pkts
    # message-too-short cases: header cut after the type, payload cut
    k = Flow(41002)
    k.c2s(b'HS\x06\x00')
    k.c2s(hs(DATA, 0, 0, b'abc')[:18])
    F += k.pkts
    return F

if __name__ == '__main__':
    d = sys.argv[1]
    os.makedirs(d, exist_ok=True)
    pcap(os.path.join(d, 'hislip-coverage.pcap'), main_frames())
    pcap(os.path.join(d, 'hislip-coverage-malformed.pcap'), malformed_frames())
