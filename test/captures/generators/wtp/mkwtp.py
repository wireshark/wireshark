#!/usr/bin/env python3
# Generates test/captures/wtp_coverage.pcap.gz, wtp_nested_concat.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic WTP captures (UDP 9201, with WSP inside).
Usage: mkwtp.py <outdir>.  Everything is built with struct."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import w12pcap

INVOKE, RESULT, ACK, ABORT, SINV, SRES, NACK = 1, 2, 3, 4, 5, 6, 7
def uv(v):
    out = [v & 0x7f]; v >>= 7
    while v:
        out.append(0x80 | (v & 0x7f)); v >>= 7
    return bytes(reversed(out))

def hdr(pdu, tid, rest=b'', ttr=False, rid=False, con=False, resp=False, extra=0):
    b0 = (0x80 if con else 0) | (pdu << 3) | (2 if ttr else 0) | (1 if rid else 0) | extra
    return bytes([b0]) + struct.pack('>H', tid | (0x8000 if resp else 0)) + rest
def invoke(tid, payload=b'', cls=2, ttr=True, rid=False, tidnew=True, up=False, ver=0, tpis=b'', resp=False):
    b3 = (ver << 6) | (0x20 if tidnew else 0) | (0x10 if up else 0) | cls
    return hdr(INVOKE, tid, bytes([b3]) + tpis, ttr=ttr, rid=rid, con=bool(tpis), resp=resp) + payload
def result(tid, payload=b'', ttr=True, rid=False, tpis=b''):
    return hdr(RESULT, tid, tpis, ttr=ttr, rid=rid, con=bool(tpis), resp=True) + payload
def ack(tid, tve=False, rid=False, tpis=b'', resp=False):
    return hdr(ACK, tid, tpis, rid=rid, con=bool(tpis), resp=resp, extra=4 if tve else 0)
def abort(tid, atype, reason, resp=False):
    return hdr(ABORT, tid, bytes([reason]), resp=resp, extra=atype)
def seg(pdu, tid, psn, payload=b'', ttr=False, rid=False, tpis=b''):
    return hdr(pdu, tid, bytes([psn]) + tpis, ttr=ttr, rid=rid, con=bool(tpis), resp=(pdu == SRES)) + payload
def nack(tid, missing, rid=False, tpis=b''):
    return hdr(NACK, tid, bytes([len(missing)]) + bytes(missing) + tpis, rid=rid, con=bool(tpis), resp=True)
def concat(*pdus):
    out = b'\x00'
    for p in pdus:
        out += bytes([len(p)]) if len(p) < 128 else struct.pack('>H', 0x8000 | len(p))
        out += p
    return out
def tpi(ttype, data=b'', cont=False, long=False):
    if long:
        return bytes([(0x80 if cont else 0) | (ttype << 3) | 4, len(data)]) + data
    return bytes([(0x80 if cont else 0) | (ttype << 3) | len(data)]) + data

# WSP (connection oriented) payloads
CAPS = b''.join([bytes([3, 0x80, 0x80 | 1, 0x01]), b''])   # placeholder, replaced below
def wsp_connect(caps=b'', headers=b''):
    return b'\x01\x10' + uv(len(caps)) + uv(len(headers)) + caps + headers
def wsp_connect_reply(sid=0x1234, caps=b'', headers=b''):
    return b'\x02' + uv(sid) + uv(len(caps)) + uv(len(headers)) + caps + headers
def wsp_get(uri, headers=b''):
    return b'\x40' + uv(len(uri)) + uri + headers
def wsp_reply(status, ctype, headers=b'', data=b''):
    ct = bytes([ctype])
    return b'\x04' + bytes([status]) + uv(len(ct) + len(headers)) + ct + headers + data
def wsp_disconnect(sid): return b'\x05' + uv(sid)

def main_frames():
    f = []
    def u(p, sport=1024, dport=9201): f.append(w12pcap.udp(p, sport=sport, dport=dport))
    def d(p): f.append(w12pcap.udp(p, sport=9201, dport=1024, src='192.0.2.2', dst='192.0.2.1'))
    caps = b''
    # a session: Invoke class 2 (Connect) -> Ack -> Result (ConnectReply) -> Ack
    u(invoke(0x1234, wsp_connect(caps=b''), cls=2))
    d(ack(0x1234, resp=True))
    d(result(0x1234, wsp_connect_reply()))
    u(ack(0x1234, tve=True))
    # a GET and its reply, with the version/TIDnew/UP flags and class 1 and 0
    u(invoke(0x1235, wsp_get(b'http://example.com/'), cls=2, tidnew=False, up=True))
    d(result(0x1235, wsp_reply(0x20, 0x80 | 0x03, data=b'<html>')))
    u(ack(0x1235, rid=True))
    u(invoke(0x1236, wsp_get(b'http://example.com/a'), cls=1, rid=True))
    u(invoke(0x1237, wsp_get(b'http://example.com/b'), cls=0, ver=1))
    u(invoke(0x1238, wsp_get(b'http://example.com/c'), cls=3, ver=3))
    # retransmission of a result
    d(hdr(RESULT, 0x1235, b'', ttr=True, rid=True, resp=True) + wsp_reply(0x20, 0x83, data=b'x'))
    # Abort: provider reasons, user reasons, both directions
    for reason in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x42):
        d(abort(0x2000 + reason, 0, reason))
    for reason in (0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0x10):
        u(abort(0x2100 + reason, 1, reason))
    u(abort(0x2200, 2, 0))            # abort type neither provider nor user
    u(abort(0x2201, 7, 0, resp=True))
    # Negative acks
    d(nack(0x3000, []))
    d(nack(0x3001, [1]))
    d(nack(0x3002, [1, 3, 4], rid=True))
    # Fragmented invoke: invoke (no trailer) + segmented invokes
    wsp = wsp_get(b'http://example.com/' + b'long/' * 12, headers=b'\x80\x80')
    parts = [wsp[:20], wsp[20:40], wsp[40:60], wsp[60:]]
    u(invoke(0x4000, parts[0], cls=2, ttr=False))
    u(seg(SINV, 0x4000, 1, parts[1]))
    u(seg(SINV, 0x4000, 2, parts[2], rid=True))
    d(nack(0x4000, [3]))
    u(seg(SINV, 0x4000, 3, parts[3], ttr=True))
    u(seg(SINV, 0x4000, 3, parts[3], ttr=True, rid=True))     # retransmitted last fragment
    d(ack(0x4000, resp=True))
    # Fragmented result
    rep = wsp_reply(0x20, 0x83, headers=b'\x8d\x85', data=b'abcdefghij' * 6)
    rp = [rep[:15], rep[15:35], rep[35:]]
    d(result(0x4001, rp[0], ttr=False))
    d(seg(SRES, 0x4001, 1, rp[1]))
    d(seg(SRES, 0x4001, 2, rp[2], ttr=True))
    u(ack(0x4001, tve=True))
    # A fragmented message where the group trailer is missing and the sequence restarts
    u(invoke(0x4002, wsp[:30], cls=2, ttr=False))
    u(seg(SINV, 0x4002, 1, wsp[30:], ttr=True))
    # Transport Protocol Items
    tp = tpi(2, b'\x01\x02') + b''                    # option: opt + value
    u(invoke(0x5000, wsp_get(b'http://e/'), tpis=tpi(2, b'\x01\x02')))
    u(invoke(0x5001, wsp_get(b'http://e/'), tpis=tpi(3, b'\x07')))
    u(invoke(0x5002, wsp_get(b'http://e/'), tpis=tpi(1, b'\xaa\xbb\xcc')))
    u(invoke(0x5003, wsp_get(b'http://e/'), tpis=tpi(0, b'\x01')))
    u(invoke(0x5004, wsp_get(b'http://e/'), tpis=tpi(4, b'\x01\x02', long=True)))
    u(invoke(0x5005, wsp_get(b'http://e/'), tpis=tpi(5, b'')))
    u(invoke(0x5006, wsp_get(b'http://e/'), tpis=tpi(6, b'\x09')))
    u(invoke(0x5007, wsp_get(b'http://e/'),
             tpis=tpi(3, b'\x02', cont=True) + tpi(2, b'\x05\x06\x07', cont=True, long=True)
                  + tpi(1, b'\x11\x22', cont=True, long=True) + tpi(5, b'')))
    d(ack(0x5008, tpis=tpi(3, b'\x04')))
    d(abort(0x5009, 0, 1)[:0] + hdr(ABORT, 0x5009, b'\x02' + tpi(2, b'\x01\x01'), con=True, extra=0))
    d(nack(0x500a, [2], tpis=tpi(2, b'\x01\x01')))
    u(result(0x500b, wsp_reply(0x20, 0x83), tpis=tpi(3, b'\x03')))
    u(seg(SINV, 0x500c, 0, wsp_get(b'http://e/'), ttr=True, tpis=tpi(3, b'\x00')))
    # Concatenated PDUs (one level): invoke + ack, three PDUs, a PDU longer than 127
    # octets (two octet length field)
    u(concat(ack(0x6000, resp=True), invoke(0x6001, wsp_get(b'http://e/x'))))
    u(concat(ack(0x6002), ack(0x6003, rid=True), abort(0x6004, 0, 8)))
    u(concat(invoke(0x6005, wsp_get(b'http://e/' + b'y' * 150)), ack(0x6006)))
    d(concat(result(0x6007, wsp_reply(0x20, 0x83, data=b'z' * 20)), nack(0x6008, [1])))
    # An unknown PDU type (8)
    u(bytes([0x40, 0x70, 0x00, 0x01, 0x02]))
    return f

def malformed_frames():
    f = []
    def u(p, dport=9201): f.append(w12pcap.udp(p, sport=1024, dport=dport))
    # Concatenated PDU nested in a concatenated PDU: error expert info (reproducer
    # of "WTP: Refuse nested concatenated PDUs"; a few levels, the first nested
    # one is refused and the rest is skipped)
    inner = ack(0x7000)
    body = concat(inner)
    for _ in range(3):
        body = concat(body)
    u(body)
    u(concat(ack(0x7001), concat(ack(0x7002), ack(0x7003))))
    # truncated PDUs
    u(bytes([0x08]))
    u(bytes([0x08, 0x12]))
    u(bytes([0x08, 0x12, 0x34]))                 # invoke without class octet
    u(bytes([0x20, 0x12, 0x34]))                 # abort without reason
    u(bytes([0x28, 0x12, 0x34]))                 # segmented invoke without psn
    u(bytes([0x38, 0x12, 0x34]))                 # nack without count
    u(bytes([0x38, 0x12, 0x34, 5, 1, 2]))        # nack with fewer entries than announced
    u(bytes([0x1a, 0x12]))                       # result with a cut TID
    u(bytes([0x98, 0x12, 0x34]))                 # ack with TPI flag, no TPI
    u(bytes([0x98, 0x12, 0x34, 0x84]))           # long TPI without length
    u(bytes([0x98, 0x12, 0x34, 0x84, 9, 1]))     # long TPI longer than the data
    u(bytes([0x00]))                             # concatenation with nothing
    u(bytes([0x00, 0x05, 0x18]))                 # sub PDU longer than the data
    u(bytes([0x00, 0x80]))                       # cut two octet length
    u(bytes([0x00, 0x00]))                       # sub PDU of length 0
    # Fragments without data (the reassembly table has nothing to add)
    u(seg(SINV, 0x4003, 0))
    u(invoke(0x4004, b'', cls=2, ttr=False))
    u(invoke(0x7100, b''))                       # class 2, trailer, no data: WSP gets nothing
    u(result(0x7101, b''))
    return f

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    mf = main_frames()
    w12pcap.write(os.path.join(out, 'wtp-coverage.pcap'), mf)
    w12pcap.write(os.path.join(out, 'wtp-coverage-malformed.pcap'), malformed_frames())
    # The reproducer of the nested concatenation fix has an error expert
    # info, so it is not part of the main capture: a separate small capture
    mal = malformed_frames()
    w12pcap.write(os.path.join(out, 'wtp-nested-concat.pcap'), mal[:2])
    print(len(mf), 'main frames,', len(malformed_frames()), 'malformed frames')
