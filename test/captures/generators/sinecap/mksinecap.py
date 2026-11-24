# Generates test/captures/sinecap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# --- pcap helpers (synthetic addresses only) ---
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

def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2', ident=1, ttl=64, flags_frag=0, options=b''):
    s = bytes(map(int, src.split('.'))); d = bytes(map(int, dst.split('.')))
    ihl = 5 + len(options) // 4
    h = struct.pack('!BBHHHBBH4s4s', 0x40 | ihl, 0, ihl * 4 + len(payload), ident, flags_frag, ttl, proto, 0, s, d) + options
    return h[:10] + struct.pack('!H', csum(h)) + h[12:]

def eth(payload, ethertype=0x0800, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    return dst + src + struct.pack('!H', ethertype) + payload

def udp(sport, dport, payload, src='192.0.2.1', dst='192.0.2.2'):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(17, u, src, dst) + u)

def tcp(sport, dport, payload, seq=1, ack=1, src='192.0.2.1', dst='192.0.2.2', flags=0x18):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    return eth(ipv4(6, t, src, dst) + t)

def ipv6(nxt, payload, src='2001:db8::1', dst='2001:db8::2', hlim=64):
    import socket
    return struct.pack('!IHBB', 0x60000000, len(payload), nxt, hlim) + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)

def write(fn, pkts, linktype=1, snap=262144):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snap, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def exported_pdu(name, payload, tag=12):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('!HH', tag, len(n)) + n + b'\0' * pad + struct.pack('!HH', 0, 0) + payload

def llc_frame(payload, dsap=0xfe, ssap=0xfe, ctl=0x03, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    body = bytes([dsap, ssap, ctl]) + payload
    return dst + src + struct.pack('!H', len(body)) + body

class Flow:
    '''TCP connection with a handshake and tracked sequence numbers.'''
    def __init__(self, cport, sport, client='192.0.2.1', server='192.0.2.2', cisn=1000, sisn=5000, hs=False):
        self.cp, self.sp, self.c, self.s = cport, sport, client, server
        self.cseq, self.sseq = cisn, sisn
        self.pk = []
        if hs:
            self.pk.append(tcp(cport, sport, b'', self.cseq, 0, client, server, 0x02)); self.cseq += 1
            self.pk.append(tcp(sport, cport, b'', self.sseq, self.cseq, server, client, 0x12)); self.sseq += 1
            self.pk.append(tcp(cport, sport, b'', self.cseq, self.sseq, client, server, 0x10))
    def c2s(self, data):
        self.pk.append(tcp(self.cp, self.sp, data, self.cseq, self.sseq, self.c, self.s)); self.cseq += len(data)
    def s2c(self, data):
        self.pk.append(tcp(self.sp, self.cp, data, self.sseq, self.cseq, self.s, self.c)); self.sseq += len(data)

def tpkt(payload):
    return struct.pack('!BBH', 3, 0, 4 + len(payload)) + payload

def cotp_dt(payload, eot=True):
    return tpkt(bytes([2, 0xf0, 0x80 if eot else 0x00]) + payload)

def llc_frame(payload, dsap=0xfe, ssap=0xfe, ctl=0x03, src=b'\x02\x00\x00\x00\x00\x01', dst=b'\x02\x00\x00\x00\x00\x02'):
    body = bytes([dsap, ssap, ctl]) + payload
    return dst + src + struct.pack('!H', len(body)) + body
# --- end helpers ---
# Generator for the SINEC AP coverage captures: python3 mksinecap.py <outdir>
# SINEC AP is a heuristic dissector on COTP data (cotp, cotp_is).
outdir = sys.argv[1] if len(sys.argv) > 1 else '.'

def ap(comcls, data=b'', protid=0, mpx=1, comcod=0x10, b4=0, b5=0, rosctr=1, sgsq=2, tact=3, tasq=4,
       spare=0, pduref=0x1234, pduid=0x5678, pdulg=None, parlg=0, datlg=None):
    n = 22 + len(data)
    if pdulg is None: pdulg = n
    if datlg is None: datlg = len(data)
    return struct.pack('!BBBBBBBBBBHHHHHH', protid, mpx, comcls, comcod, b4, b5, rosctr, sgsq, tact, tasq,
                       spare, pduref, pduid, pdulg, parlg, datlg) + data

f = Flow(41000, 102)
# ACK without data, with error class and code
f.c2s(cotp_dt(ap(0, b4=0x00, b5=0x00)))
f.s2c(cotp_dt(ap(0, b4=0x81, b5=0x05, comcod=0x20)))
# serial transfer with data (the payload goes to the data dissector)
f.c2s(cotp_dt(ap(4, b'SERIAL-TRANSFER-DATA', b4=0x11, b5=0x22, pduid=0x0001)))
f.s2c(cotp_dt(ap(4, b'', b4=0x33, b5=0x44, pduid=0x0002)))
# unknown command class
f.c2s(cotp_dt(ap(0x7f, b'xyz', b4=0x55, b5=0x66, pduid=0x0003)))
# Not SINEC AP: protocol id != 0, wrong PDU length, wrong data length, too short
f.c2s(cotp_dt(ap(4, b'abcdef', protid=1)))
f.c2s(cotp_dt(ap(4, b'abcdef', pdulg=99)))
f.c2s(cotp_dt(ap(4, b'abcdef', datlg=2)))
f.c2s(cotp_dt(ap(4)[:21]))
# a SINEC AP telegram split over two COTP TPDUs (reassembly, EOT in the last)
t = ap(4, b'0123456789' * 4, pduid=0x0004)
f.c2s(cotp_dt(t[:30], eot=False))
f.c2s(cotp_dt(t[30:], eot=True))
main = f.pk
# Inactive subset: COTP directly under the OSI NLPID 0 over LLC (cotp_is heuristic)
def llc_inactive(payload):
    return llc_frame(b'\x00' + payload)
inact = []
inact.append(llc_inactive(bytes([2, 0xf0, 0x80]) + ap(0, b4=1, b5=2, pduid=0x0010)))
inact.append(llc_inactive(bytes([2, 0xf0, 0x80]) + ap(4, b'inactive subset data', pduid=0x0011)))
write(os.path.join(outdir, 'sinecap-coverage.pcap'), main + inact)

# Second capture: the minimal telegram and a three octet payload
bad = Flow(41001, 102)
bad.c2s(cotp_dt(ap(4)))
bad.c2s(cotp_dt(b'\x00' * 3))
write(os.path.join(outdir, 'sinecap-coverage-malformed.pcap'), bad.pk)
