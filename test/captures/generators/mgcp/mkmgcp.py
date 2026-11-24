#!/usr/bin/python3
# Generates test/captures/mgcp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MGCP coverage captures. Usage: mkmgcp.py <outdir> [-v]
Writes mgcp-coverage.pcap and mgcp-coverage-malformed.pcap. Everything is
synthetic (192.0.2.0/24)."""
import struct
import sys
import os

P = struct.pack
CA = bytes([192, 0, 2, 1])     # call agent
GW = bytes([192, 0, 2, 2])     # gateway
CAMAC = bytes.fromhex('020000000001')
GWMAC = bytes.fromhex('020000000002')

def csum(b):
    if len(b) % 2:
        b += b'\0'
    t = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while t >> 16:
        t = (t & 0xffff) + (t >> 16)
    return (~t) & 0xffff

class Cap:
    def __init__(self):
        self.pkts = []
        self.ipid = 1
        self.tcp = {}
    def frame(self, src, dst, proto, l4):
        h = P('>BBHHHBBH', 0x45, 0, 20 + len(l4), self.ipid, 0, 64, proto, 0) + src + dst
        self.ipid += 1
        h = h[:10] + P('>H', csum(h)) + h[12:]
        smac, dmac = (CAMAC, GWMAC) if src == CA else (GWMAC, CAMAC)
        self.pkts.append(dmac + smac + b'\x08\x00' + h + l4)
    def udp(self, from_ca, payload, sport=None, dport=None):
        src, dst = (CA, GW) if from_ca else (GW, CA)
        if sport is None:
            sport, dport = (2727, 2427) if from_ca else (2427, 2727)
        u = P('>HHHH', sport, dport, 8 + len(payload), 0) + payload
        ps = src + dst + P('>BBH', 0, 17, len(u))
        u = u[:6] + P('>H', csum(ps + u) or 0xffff) + u[8:]
        self.frame(src, dst, 17, u)
    # TCP: the call agent connects from port 40000 to the gateway port
    def _seg(self, key, from_ca, flags, payload=b''):
        st = self.tcp[key]
        src, dst = (CA, GW) if from_ca else (GW, CA)
        sp, dp = (key[0], key[1]) if from_ca else (key[1], key[0])
        seq, ack = (st['ca'], st['gw']) if from_ca else (st['gw'], st['ca'])
        h = P('>HHIIBBHHH', sp, dp, seq, ack if flags & 0x10 else 0, 0x50, flags, 8192, 0, 0)
        ps = src + dst + P('>BBH', 0, 6, len(h) + len(payload))
        h = h[:16] + P('>H', csum(ps + h + payload)) + h[18:]
        self.frame(src, dst, 6, h + payload)
        n = len(payload) + (1 if flags & 0x03 else 0)
        if from_ca: st['ca'] += n
        else: st['gw'] += n
    def tcp_open(self, sport, dport):
        key = (sport, dport)
        self.tcp[key] = {'ca': 1000, 'gw': 5000}
        self._seg(key, True, 0x02)
        self._seg(key, False, 0x12)
        self._seg(key, True, 0x10)
        return key
    def tcp_data(self, key, from_ca, payload):
        self._seg(key, from_ca, 0x18, payload)
        self._seg(key, not from_ca, 0x10)
    def tcp_close(self, key):
        self._seg(key, True, 0x11)
        self._seg(key, False, 0x11)
        self._seg(key, True, 0x10)
    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(P('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, p in enumerate(self.pkts):
                f.write(P('<IIII', 1700000000 + i // 2, (i % 2) * 250000 + i * 1000, len(p), len(p)))
                f.write(p)

EP = 'aaln/1@gw.example.net'
SDP = (b'v=0\r\no=- 25678 753849 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\n'
       b't=0 0\r\nm=audio 3456 RTP/AVP 0 8\r\na=ptime:20\r\n')
SDP2 = (b'v=0\r\no=- 2 2 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\n'
        b't=0 0\r\nm=audio 4000 RTP/AVP 0\r\n')

def req(verb, tid, params=(), ep=EP, ver='MGCP 1.0', sdp=b'', nl='\r\n'):
    first = '%s %s %s %s' % (verb, tid, ep, ver)
    body = nl.join([first] + list(params)) + nl
    return body.encode('latin-1') + ((nl.encode() + sdp) if sdp else b'')

def rsp(code, tid, text='OK', params=(), sdp=b'', nl='\r\n'):
    body = nl.join(['%s %s %s' % (code, tid, text)] + list(params)) + nl
    return body.encode('latin-1') + ((nl.encode() + sdp) if sdp else b'')

LOCAL_OPTS = ('L:p:20, a:PCMU;PCMA, s:off, e:on, sc-rtp:rtp1, sc-rtcp:rtcp1, b:64, '
              'es-ccd:on, es-cci:on, dq-gi:1234, dq-rd:yes, dq-ri:no, dq-rr:no, k:uri:key, '
              'gc:7, fmtp:a=b, nt:IN, o-fmtp:c=d, r:on, t:b8, r-cnf:x, r-dir:y, r-sh:z, '
              'mp:1, fxr/fx:fax, zz:unknown, nocolon')
CONN_PARAMS = ('P:PS=100, OS=16000, PR=99, OR=15900, PL=2, JI=3, LA=40, PC/RPS=1, '
               'PC/ROS=2, PC/RPL=3, PC/RJI=4, X-Vendor=abc, UNK=5, nopair')
LVM = ('XRM/LVM: NLR=1,JDR=2,BLD=3,GLD=4,BD=5,GD=6,RTD=7,ESD=8,SL=9,NL=10,RERL=11,'
       'GMN=12,NSR=13,XSR=14,MLQ=15,MCQ=16,PLC=17,JBA=18,JBR=19,JBN=20,JBM=21,'
       'JBS=22,IAJ=23,XXX=1,bad')
RVM = LVM.replace('LVM', 'RVM')

def build():
    c = Cap()
    # 1: EPCF with a response
    c.udp(True, req('EPCF', 1, ['B:e:mu', 'R:L/hd(N)', 'Q:loop']))
    c.udp(False, rsp(200, 1))
    # CRCX with every kind of local connection option / SDP in the answer
    c.udp(True, req('CRCX', 2, ['C:A3C47F21456789F0', 'N:ca@[192.0.2.1]:2727', LOCAL_OPTS,
                              'M:recvonly', 'R:L/hd,L/hu', 'S:L/rg', 'X:B244', 'I:1', 'Z:aaln/2@gw', 'Z2:aaln/3@gw',
                              'E:300 - reason', 'ES:ready']))
    c.udp(False, rsp(200, 2, 'OK', ['I:FDE234C8', 'K:ack'], SDP))
    c.udp(True, req('MDCX', 3, ['C:A3C47F21456789F0', 'I:FDE234C8', 'M:sendrecv', CONN_PARAMS, 'I2:ABCDEF'], sdp=SDP2))
    c.udp(False, rsp(100, 3, 'Pending'))
    c.udp(False, rsp(200, 3, 'OK', [LVM, RVM, 'P:PS=1,OS=160']))
    c.udp(False, rsp(200, 3, 'OK', [LVM, RVM, 'P:PS=1,OS=160']))        # duplicate response
    c.udp(True, req('MDCX', 3, ['C:A3C47F21456789F0', 'I:FDE234C8', 'M:sendrecv'], sdp=SDP2))   # duplicate request
    c.udp(True, req('DLCX', 4, ['C:A3C47F21456789F0', 'I:FDE234C8', 'E:900 - Hung up']))
    c.udp(False, rsp(250, 4, 'Connection deleted', ['P:PS=1,OS=160,PR=1,OR=160,PL=0,JI=1,LA=1']))
    # RQNT with signals, observed events, digit map, vendor extensions
    c.udp(True, req('RQNT', 5, ['N:ca@[192.0.2.1]:2727', 'X:B245', 'R:L/hd(N),L/hu(N)', 'S:L/rg', 'D:(0T|00T|[1-7]xxx|8xxxxxxx|#xxxxxxx|*xx|91xxxxxxxxxx|9011x.T)',
                              'Q:process,loop', 'T:L/hd', 'X+Crit:val', 'X-Ext:val', 'X-OSMUX:1', 'X-OSMUXY:2', 'X-x:', 'DQ-RI:abc', 'dq-ri:def',
                              'F:A,R,D,S,X,N,I,T,O', 'A:a:PCMU;PCMA, v:L;S', 'B:e:mu', 'K:ack', 'C:123', 'P:PS=2']))
    c.udp(False, rsp(200, 5, 'OK'))
    c.udp(True, req('RQNT', 6, ['X:B246', 'S:L/ro', 'D:(x)']))
    c.udp(False, rsp(200, 6))
    c.udp(True, req('RQNT', 7, ['X:B247', 'S:L/bz']))
    c.udp(False, rsp(200, 7))
    c.udp(True, req('RQNT', 8, ['X:B248', 'S:']))
    c.udp(False, rsp(200, 8))
    # NTFY (gateway to call agent: the call agent port is the destination)
    c.udp(False, req('NTFY', 9, ['N:ca@[192.0.2.1]:2727', 'X:B245', 'O:L/hd'], ep=EP), 2427, 2727)
    c.udp(True, rsp(200, 9), 2727, 2427)
    c.udp(False, req('NTFY', 10, ['X:B246', 'O:L/hu(N),D/1,D/2,D/#']), 2427, 2727)
    c.udp(True, rsp(200, 10), 2727, 2427)
    # AUEP, AUCX, RSIP, MESG (not a response-matching verb), experimental verb
    c.udp(True, req('AUEP', 11, ['F:A,R,D,S,X,N,I,T,O', 'PL:L,D', 'MD:1500', 'RM:graceful', 'RD:300', 'ES:ready']))
    c.udp(False, rsp(200, 11, 'OK', ['A:a:PCMU, v:L;S', 'R:L/hd', 'ES:ready', 'T:L/hu', 'Z:aaln/1@gw']))
    c.udp(True, req('AUCX', 12, ['C:A3C47F21456789F0', 'I:FDE234C8', 'F:C,N,L,M,LC,P']))
    c.udp(False, rsp(515, 12, 'Incorrect connection-id'))
    c.udp(False, req('RSIP', 13, ['RM:restart', 'RD:0'], ep='aaln/*@gw.example.net'), 2427, 2727)
    c.udp(True, rsp(200, 13, 'OK', ['N:ca@[192.0.2.1]:2727']), 2727, 2427)
    c.udp(True, req('MESG', 14, ['X:1']))
    c.udp(True, req('XABC', 15, ['X:1']))
    c.udp(False, rsp(200, 15, 'OK'))
    c.udp(False, rsp(400, 14, 'Transient error'))
    # lower case verb and response without a request (discarded)
    c.udp(True, req('crcx', 16, ['c:1', 'l:p:10', 'm:inactive']))
    c.udp(False, rsp(500, 16, 'Endpoint unknown'))
    c.udp(False, rsp(200, 999, 'OK'))
    # piggybacked messages (dot separated), with LF and CRLF and a trailing dot
    c.udp(True, rsp(200, 20) + b'.\r\n' + req('NTFY', 21, ['X:1', 'O:L/hd']) + b'.\r\n')
    c.udp(True, req('RQNT', 22, ['X:1'], nl='\n') + b'.\n' + req('DLCX', 23, ['C:1'], nl='\n') + b'.\n' + rsp(200, 24, nl='\n'))
    c.udp(True, req('CRCX', 25, ['C:2', 'L:p:20'], sdp=SDP2) + b'\r\n.\r\n' + req('MDCX', 26, ['C:2'], sdp=SDP2))
    # parameters that are not recognised
    c.udp(True, req('RQNT', 27, ['X:1', 'Y:unknown', 'K', 'B', 'C', 'N', 'L', 'S', 'D', 'O', 'F', 'Q', 'T', 'A', 'M', 'R', 'P', 'E', 'Z', 'I', 'X',
                               'X-', 'X+', 'X-abc', 'X+abc', 'XR', 'XRMNO', 'XRM/', 'Dq', 'DQ-R', 'M2:1', 'R2', 'P2', 'E2', 'Z3', 'I3']))
    # voice metrics in the reproducer shapes (without a colon, short, empty value)
    c.udp(True, req('RQNT', 28, ['X:1', 'XRM/L']))
    c.udp(True, req('RQNT', 29, ['X:1', 'XRM/R']))
    c.udp(True, req('RQNT', 30, ['X:1', 'XRM/LVM:', 'XRM/RVM:', 'XRM/LVM:NLR=1', 'XRM/RVM:JDR=2,', 'XRM/RVM: bad=,x']))
    c.udp(True, req('RQNT', 31, ['X:1', 'XRM/LVM', 'XRM/RVM']))
    # other first-line shapes
    c.udp(True, b'RQNT 32\n')
    c.udp(True, b'RQNT 33 ep\r\n')
    c.udp(True, b'RQNT 34 ep MGCP 1.0')
    c.udp(True, b'RQNT 41 ep MGCP1.0')
    c.udp(True, b'200 35\n')
    c.udp(True, b'200 36 OK')
    c.udp(True, b'200\t37 ep\n')
    c.udp(True, req('RQNT', 38, ['X:1'], ver='MGCP 1.0 NCS 1.0'))
    # a transaction identifier that is not a number
    c.udp(True, b'RQNT abc ep MGCP 1.0\r\nX:1\r\n')
    # ports of the other directions (gateway to call agent on 2727 is above);
    # an additional message from another call agent port
    c.udp(True, req('RQNT', 40, ['X:1']), 2729, 2427)       # not dissected (no MGCP port)? source only
    main_udp = len(c.pkts)
    # TCP: gateway port 2427 with plain MGCP and with ASCII TPKT
    k = c.tcp_open(40000, 2427)
    c.tcp_data(k, True, req('CRCX', 50, ['C:5', LOCAL_OPTS[:30]], sdp=SDP2))
    c.tcp_data(k, False, rsp(200, 50, 'OK', ['I:1'], SDP))
    c.tcp_data(k, True, req('RQNT', 51, ['X:1']))
    c.tcp_data(k, False, rsp(200, 51))
    c.tcp_data(k, False, rsp(200, 51))                         # duplicate response
    c.tcp_data(k, True, req('RQNT', 51, ['X:1']))              # duplicate request
    m = req('NTFY', 52, ['X:1', 'O:L/hd'])
    c.tcp_data(k, True, b'0300' + b'%04x ' % len(m) + m)
    m = rsp(200, 52)
    c.tcp_data(k, False, b'0300' + b'%04x ' % len(m) + m)
    c.tcp_data(k, True, b'continuation-of-a-tpkt-pdu')       # not MGCP
    c.tcp_close(k)
    # gateway to call agent connection on 2727
    k = c.tcp_open(2427, 2727)
    c.tcp_data(k, True, req('RSIP', 60, ['RM:restart'], ep='aaln/*@gw'))
    c.tcp_data(k, False, rsp(200, 60))
    c.tcp_close(k)
    marks = (main_udp, len(c.pkts))

    m = Cap()
    # truncated and odd inputs (bounds)
    m.udp(True, req('RQNT', 39, ep='ep', ver='MGCP 1.0') + b'\r\nnot sdp text\r\n')
    m.udp(True, b'RQNT 1 ep MGCP 1.0\nX:1\n.\n.')
    m.udp(True, b'RQNT 1 ep MGCP 1.0\r\n' + b'L:' + b','.join([b'a:b'] * 200) + b'\r\n')
    m.udp(True, b'RQNT 1 ep MGCP 1.0\nP:PS=\xff\xfe,OS=4294967296,X-x=\xc3\xa9\nXRM/RVM:NLR=1,JDR=\xff\xfe\xfd\nL:p=\xff\xff\n')
    m.udp(True, b'RQNT 2 ep@gw MGCP 1.0\nS:' + b'\xff' * 30 + b'\nO:\n\nv=0\n')
    m.udp(True, b'200 3 OK\n\n.\n.\n200 3 OK\n.\n')
    m.udp(True, b'RQNT 4 ep MGCP 1.0\nDQ-RI:abc\nD\nI\nM\nR\nP\nE\nZ\nX')
    m.udp(True, b'RQNTX 5 ep MGCP 1.0\n')
    m.udp(True, b'12 5 ep\n')
    m.udp(True, b'1234 5 ep\n')
    m.udp(True, b'\x00\x01\x02\x03\x04\x05\x06\x07')
    m.udp(True, b'RQNT 6 ep MGCP 1.0\r\n\r\n' + b'v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 4000 RTP/AVP 0\r\n')
    m.udp(True, b'\xff' * 5)
    m.udp(True, b'RQNT 7 ep MGCP 1.0\nX:1\nXRM/LVM:' + b'A=1,' * 300 + b'\n')
    return c, m, marks

if __name__ == '__main__':
    out = sys.argv[1]
    c, m, marks = build()
    c.write(os.path.join(out, 'mgcp-coverage.pcap'))
    m.write(os.path.join(out, 'mgcp-coverage-malformed.pcap'))
    if '-v' in sys.argv:
        print('main frames %d (UDP 1-%d, TCP %d-%d); malformed %d'
              % (len(c.pkts), marks[0], marks[0] + 1, marks[1], len(m.pkts)))
