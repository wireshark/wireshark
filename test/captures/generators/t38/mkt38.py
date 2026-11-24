#!/usr/bin/env python3
# Generates the t38 captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the T.38 coverage captures.  Usage: mkt38.py <outdir>
All packets are synthetic.  A SIP INVITE / 200 OK with SDP (m=image ... udptl
t38) sets up the UDP conversations, then UDPTL packets (ALIGNED PER) carry
T.30 indicators and data in both directions.  The TCP variant (IFPPacket
with and without TPKT) needs Decode As (-d tcp.port==6000,t38)."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from berlib import gz, TcpStream, udp, write_pcap
from perlib import W

CALLER = ('192.0.2.1', 4000)
CALLEE = ('192.0.2.2', 5000)

# ---- encoders ----
PRE = True    # Pre-Corrigendum encoding of field-type (the dissector default)

def ifp(kind, value, fields=None):
    """kind 0: t30-indicator (value 0..22), kind 1: t30-data (value 0..14);
    fields: list of (field-type 0..11, data or None)"""
    w = W()
    w.bit(fields is not None)
    w.choice(kind, 2)
    n = 16 if kind == 0 else 9
    if value < n: w.enum(value, n, ext=True)
    else: w.enum(value - n, n, ext=True, extidx=True)
    if fields is not None:
        w.length(len(fields))
        for ft, data in fields:
            w.bit(data is not None)
            if PRE: w.con_int(ft, 0, 7)           # 1998 ASN.1: not extensible, eight values
            elif ft < 8: w.enum(ft, 8, ext=True)
            else: w.enum(ft - 8, 8, ext=True, extidx=True)
            if data is not None: w.octstr(data, 1, 65535)
    return w.bytes()

def udptl(seq, primary, err=('sec', [])):
    w = W()
    w.con_int(seq, 0, 65535)
    w.opentype(primary)
    if err[0] == 'sec':
        w.choice(0, 2)
        w.length(len(err[1]))
        for p in err[1]: w.opentype(p)
    else:
        w.choice(1, 2)
        w.sint(err[1]); w.length(len(err[2]))
        for d in err[2]: w.octstr(d)
    return w.bytes()

def sip_msg(first, headers, body=b''):
    h = ''.join('%s: %s\r\n' % kv for kv in headers)
    return (first + '\r\n' + h + 'Content-Length: %d\r\n\r\n' % len(body)).encode() + body

def sdp(addr, port, extra=()):
    lines = ['v=0', 'o=- 1 1 IN IP4 ' + addr, 's=-', 'c=IN IP4 ' + addr, 't=0 0',
             'm=image %d udptl t38' % port, 'a=T38FaxVersion:0', 'a=T38MaxBitRate:14400',
             'a=T38FaxRateManagement:transferredTCF', 'a=T38FaxMaxBuffer:1024',
             'a=T38FaxMaxDatagram:122', 'a=T38FaxUdpEC:t38UDPRedundancy'] + list(extra)
    return ('\r\n'.join(lines) + '\r\n').encode()

HDLC_DIS = bytes.fromhex('ffc801 00eef88080 01'.replace(' ', ''))
HDLC_DCS = bytes.fromhex('ffc841 0006c0a07a')
HDLC_CFR = bytes.fromhex('ffc821')
HDLC_MCF = bytes.fromhex('ffc831')
HDLC_DCN = bytes.fromhex('ffc85f')

def main(out):
    f = []
    ts = [0.0]
    def add(fr, dt=0.02):
        ts[0] += dt; f.append((1750000000.0 + ts[0], fr))
    # --- SIP session setup
    body = sdp('192.0.2.1', 4000)
    add(udp(5060, 5060, sip_msg('INVITE sip:fax@192.0.2.2 SIP/2.0', [
        ('Via', 'SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1'), ('From', '<sip:a@192.0.2.1>;tag=1'),
        ('To', '<sip:fax@192.0.2.2>'), ('Call-ID', 't38-test-1'), ('CSeq', '1 INVITE'),
        ('Contact', '<sip:a@192.0.2.1>'), ('Content-Type', 'application/sdp')], body)))
    body = sdp('192.0.2.2', 5000)
    add(udp(5060, 5060, sip_msg('SIP/2.0 200 OK', [
        ('Via', 'SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1'), ('From', '<sip:a@192.0.2.1>;tag=1'),
        ('To', '<sip:fax@192.0.2.2>;tag=2'), ('Call-ID', 't38-test-1'), ('CSeq', '1 INVITE'),
        ('Contact', '<sip:fax@192.0.2.2>'), ('Content-Type', 'application/sdp')], body), rev=True))
    add(udp(5060, 5060, sip_msg('ACK sip:fax@192.0.2.2 SIP/2.0', [
        ('Via', 'SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK2'), ('From', '<sip:a@192.0.2.1>;tag=1'),
        ('To', '<sip:fax@192.0.2.2>;tag=2'), ('Call-ID', 't38-test-1'), ('CSeq', '1 ACK')])))
    # --- UDPTL
    seq = {'a': 0, 'b': 0}
    def send(who, primary, err=None, seq_no=None, dup=False):
        s = seq[who] if seq_no is None else seq_no
        if seq_no is None: seq[who] += 1
        pk = udptl(s, primary, err or ('sec', []))
        if who == 'a': add(udp(4000, 5000, pk, src='192.0.2.1', dst='192.0.2.2'))
        else: add(udp(5000, 4000, pk, src='192.0.2.2', dst='192.0.2.1'), 0.02)
        return s
    # every indicator value
    for v in range(23):
        send('a' if v % 2 else 'b', ifp(0, v))
    # every t30-data value without data field, and with a data field of each type
    for v in range(15):
        send('b' if v % 2 else 'a', ifp(1, v))
    # HDLC: the answering side sends DIS in three fragments, then FCS OK in the last packet
    send('b', ifp(0, 3))                                   # v21-preamble
    send('b', ifp(1, 0, [(0, HDLC_DIS[:3])]))
    send('b', ifp(1, 0, [(0, HDLC_DIS[3:6])]), ('sec', [ifp(1, 0, [(0, HDLC_DIS[:3])])]))
    send('b', ifp(1, 0, [(0, HDLC_DIS[6:]), (2, None)]), ('sec', [ifp(1, 0, [(0, HDLC_DIS[3:6])]),
                                                             ifp(1, 0, [(0, HDLC_DIS[:3])])]))
    send('b', ifp(1, 0, [(1, None)]))                       # hdlc-sig-end
    # FCS OK and signal end in one field type
    send('a', ifp(0, 3))
    send('a', ifp(1, 0, [(0, HDLC_CFR[:2])]))
    send('a', ifp(1, 0, [(0, HDLC_CFR[2:]), (4, None)]))
    # FCS BAD, then FCS BAD with signal end: the frame is not passed to T.30
    send('a', ifp(1, 0, [(0, HDLC_DCS)]))
    send('a', ifp(1, 0, [(3, None)]))
    send('a', ifp(1, 0, [(0, HDLC_DCS)]))
    send('a', ifp(1, 0, [(5, None)]))
    # DCS in two fragments with a repeated packet (same sequence number) and FEC
    s = send('a', ifp(1, 0, [(0, HDLC_DCS[:5])]))
    send('a', ifp(1, 0, [(0, HDLC_DCS[:5])]), seq_no=s)
    send('a', ifp(1, 0, [(0, HDLC_DCS[5:])]), ('fec', 2, [b'\x01\x02\x03', b'']))
    s = send('a', ifp(1, 0, [(2, None)]))
    send('a', ifp(1, 0, [(2, None)]), seq_no=s)             # retransmission of the end
    # a lost packet in the middle of an HDLC frame
    send('b', ifp(1, 0, [(0, HDLC_DIS[:4])]))
    seq['b'] += 1
    send('b', ifp(1, 0, [(0, HDLC_DIS[6:])]))
    send('b', ifp(1, 0, [(2, None)]))
    send('b', ifp(1, 0, [(0, HDLC_DCN), (4, None)]))
    # training and image data (t4-non-ecm): fragments, then sig-end (no loss)
    send('a', ifp(0, 15))                                  # v17-14400-long-training
    for i in range(4):
        send('a', ifp(1, 8, [(6, bytes([i]) * 60)]))
    send('a', ifp(1, 8, [(7, None)]))
    # t4-non-ecm data with several fields in one packet, and with data in the sig-end field
    send('a', ifp(1, 8, [(6, b'\x11' * 30), (6, b'\x12' * 30), (6, b'\x13' * 30)]))
    send('a', ifp(1, 8, [(6, b'\x14' * 30), (7, b'\x15' * 10)]))
    # redundancy: secondary packets and FEC with several packets
    send('b', ifp(0, 1), ('sec', [ifp(0, 2), ifp(0, 3), ifp(1, 0, [(0, b'\xff\x03')]), ifp(0, 5)]))
    send('b', ifp(0, 1), ('fec', 1, [b'\xde\xad\xbe\xef']))
    send('b', ifp(0, 1), ('fec', 300, [b'\x01' * 200, b'\x02' * 300]))
    # long field data (more than 127 octets: two octet length determinant of the open type)
    send('a', ifp(1, 8, [(6, bytes(range(256)) * 2)]))
    # a long sequence of packets: close with no-signal
    send('a', ifp(0, 0)); send('b', ifp(0, 0))
    write_pcap(os.path.join(out, 't38-coverage.pcap'), f)
    gz(os.path.join(out, 't38-coverage.pcap'), os.path.join(out, 't38_coverage.pcap.gz'))

    # --- T.38 over TCP (needs Decode As): its own capture, because the dissector gives the TCP
    # conversation the UDP dissector (see README) and the second pass then differs
    f = []
    ts = [0.0]
    # (every connection carries a single PDU per direction: the dissector makes the TCP
    # conversation use the UDP dissector after the first PDU, see README)
    def tpkt(b): return struct.pack('!BBH', 3, 0, 4 + len(b)) + b
    port = [40001]
    def tcp_conn(*segs):
        s = TcpStream(port[0], 6000); port[0] += 1
        for fr in s.handshake(): add(fr)
        for who, b in segs:
            add(s.c2s(b) if who == 'c' else s.s2c(b))
    tcp_conn(('c', tpkt(ifp(0, 1))), ('s', tpkt(ifp(0, 2))))
    tcp_conn(('c', tpkt(ifp(1, 0, [(0, HDLC_DIS), (2, None)]))))
    tcp_conn(('c', ifp(0, 3)))                                       # without TPKT
    tcp_conn(('c', ifp(1, 0, [(0, HDLC_CFR)]) + ifp(1, 0, [(4, None)])))   # two IFPPackets in one segment
    tcp_conn(('c', tpkt(ifp(1, 8, [(6, b'\x55' * 20)])) + tpkt(ifp(1, 8, [(7, None)]))))   # two TPKTs in one segment
    seg = tpkt(ifp(1, 0, [(0, HDLC_DCN), (4, None)]))
    tcp_conn(('c', seg[:6]), ('c', seg[6:]))                                                # TPKT over two segments
    # a connection whose first PDU is from the server comes last: it leaves a conversation
    # for the server port that makes later connections use the UDP dissector
    tcp_conn(('s', tpkt(ifp(1, 0, [(0, HDLC_MCF), (4, None)]))))
    write_pcap(os.path.join(out, 't38-coverage-tcp.pcap'), f)
    gz(os.path.join(out, 't38-coverage-tcp.pcap'), os.path.join(out, 't38_coverage_tcp.pcap.gz'))

    # --- the 2002 (corrigendum) encoding of field-type, needs t38.use_pre_corrigendum_asn1_specification:FALSE
    global PRE
    PRE = False
    f = []
    ts = [0.0]
    body = sdp('192.0.2.1', 4000)
    add(udp(5060, 5060, sip_msg('INVITE sip:fax@192.0.2.2 SIP/2.0', [
        ('Via', 'SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1'), ('From', '<sip:a@192.0.2.1>;tag=1'),
        ('To', '<sip:fax@192.0.2.2>'), ('Call-ID', 't38-test-3'), ('CSeq', '1 INVITE'),
        ('Contact', '<sip:a@192.0.2.1>'), ('Content-Type', 'application/sdp')], body)))
    body = sdp('192.0.2.2', 5000)
    add(udp(5060, 5060, sip_msg('SIP/2.0 200 OK', [
        ('Via', 'SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1'), ('From', '<sip:a@192.0.2.1>;tag=1'),
        ('To', '<sip:fax@192.0.2.2>;tag=2'), ('Call-ID', 't38-test-3'), ('CSeq', '1 INVITE'),
        ('Contact', '<sip:fax@192.0.2.2>'), ('Content-Type', 'application/sdp')], body), rev=True))
    seq = {'a': 0, 'b': 0}
    send('b', ifp(0, 16))
    send('b', ifp(1, 9, [(8, b'\x01\x02')]))              # cm-message
    send('a', ifp(1, 9, [(9, b'\x03\x04\x05')]))          # jm-message
    send('b', ifp(1, 10, [(10, b'\x06')]))                 # ci-message
    send('b', ifp(1, 10, [(11, b'\x00\x20')]))            # v34rate
    send('a', ifp(1, 0, [(0, HDLC_DIS[:5])]))
    send('a', ifp(1, 0, [(0, HDLC_DIS[5:]), (2, None)]))
    for ft in (0, 2, 0, 4, 1, 3, 5):
        send('a', ifp(1, 8, [(ft, HDLC_CFR if ft == 0 else None)]))
    send('a', ifp(1, 8, [(6, b'\x21' * 10)]))
    send('a', ifp(1, 8, [(7, None)]))
    write_pcap(os.path.join(out, 't38-coverage-2002.pcap'), f)
    gz(os.path.join(out, 't38-coverage-2002.pcap'), os.path.join(out, 't38_coverage_2002.pcap.gz'))
    PRE = True

    # --- malformed
    m = []
    ts = [0.0]
    def addm(fr, dt=0.02):
        ts[0] += dt; m.append((1750000000.0 + ts[0], fr))
    body = sdp('192.0.2.1', 4000)
    addm(udp(5060, 5060, sip_msg('INVITE sip:fax@192.0.2.2 SIP/2.0', [
        ('Via', 'SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1'), ('From', '<sip:a@192.0.2.1>;tag=1'),
        ('To', '<sip:fax@192.0.2.2>'), ('Call-ID', 't38-test-2'), ('CSeq', '1 INVITE'),
        ('Contact', '<sip:a@192.0.2.1>'), ('Content-Type', 'application/sdp')], body)))
    body = sdp('192.0.2.2', 5000)
    addm(udp(5060, 5060, sip_msg('SIP/2.0 200 OK', [
        ('Via', 'SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1'), ('From', '<sip:a@192.0.2.1>;tag=1'),
        ('To', '<sip:fax@192.0.2.2>;tag=2'), ('Call-ID', 't38-test-2'), ('CSeq', '1 INVITE'),
        ('Contact', '<sip:fax@192.0.2.2>'), ('Content-Type', 'application/sdp')], body), rev=True))
    def ma(pk): addm(udp(4000, 5000, pk, src='192.0.2.1', dst='192.0.2.2'))
    def mb(pk): addm(udp(5000, 4000, pk, src='192.0.2.2', dst='192.0.2.1'))
    # hdlc-fcs-OK / t4-non-ecm-sig-end without any fragment data
    ma(udptl(0, ifp(1, 0, [(2, None)])))
    ma(udptl(1, ifp(1, 8, [(7, None)])))
    ma(udptl(2, ifp(1, 8, [(7, None)])))
    # several HDLC frames in one packet and a page with lost packets: their second pass differs
    # (see README)
    sq = [30]
    def mseq(who, p):
        (ma if who == 'a' else mb)(udptl(sq[0], p)); sq[0] += 1
    mseq('a', ifp(1, 0, [(0, HDLC_DCS), (2, None), (0, HDLC_MCF), (4, None)]))
    mseq('a', ifp(0, 15))
    mseq('a', ifp(1, 8, [(6, b'\xaa' * 40)]))
    sq[0] += 1
    mseq('a', ifp(1, 8, [(6, b'\xbb' * 40)]))
    sq[0] += 2
    mseq('a', ifp(1, 8, [(6, b'\xcc' * 40)]))
    mseq('a', ifp(1, 8, [(7, None)]))
    # trailing garbage after the UDPTL packet
    ma(udptl(3, ifp(0, 1)) + b'\x00\x01\x02')
    # truncated packets
    good = udptl(4, ifp(1, 0, [(0, HDLC_DIS)]), ('sec', [ifp(0, 1)]))
    for n in (1, 2, 3, 4, 5, len(good) - 3, len(good) - 1):
        ma(good[:n])
    # primary packet with a bad open type length
    ma(b'\x00\x05\x7f\x00')
    ma(b'\x00\x06\xff\xff\xff')
    # HDLC data fragments that are never completed, then a different frame
    for i in range(6):
        ma(udptl(10 + i, ifp(1, 0, [(0, bytes([i]) * 20)])))
    # empty data field
    ma(udptl(20, bytes([0x00, 0x00])))
    # more than four T.38 messages in one packet (tap info ring)
    ma(udptl(21, ifp(1, 0, [(0, b'\x01')] * 3), ('sec', [ifp(1, 0, [(0, b'\x02')])] * 5)))
    # an RTP version 2 style first octet and random bytes
    mb(b'\x80\x00\x00\x01' + b'\x00' * 12)
    mb(bytes((i * 37 + 11) & 0xff for i in range(60)))
    mb(b'\xff' * 30)
    mb(b'\x00' * 4)
    # sequence numbers that go backwards and wrap
    for sq in (65535, 0, 65534, 5, 5):
        mb(udptl(sq, ifp(1, 8, [(6, b'\x07' * 10)])))
    mb(udptl(6, ifp(1, 8, [(7, None)])))
    # TCP
    s = TcpStream(40101, 6000)
    for fr in s.handshake(): addm(fr)
    addm(s.c2s(b'\x03\x00\x00\x09\x00')); addm(s.c2s(b'\x03\x00\x00\x04'))
    addm(s.c2s(b'\x03\x00\x00\x08' + b'\xff\xff\xff\xff'))
    addm(s.c2s(b'\xff\xff\xff'))
    addm(s.c2s(b'\x00'))
    write_pcap(os.path.join(out, 't38-coverage-malformed.pcap'), m)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
