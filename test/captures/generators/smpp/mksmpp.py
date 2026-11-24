#!/usr/bin/env python3
# Generates test/captures/smpp_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the SMPP dissector (packet-smpp.c,
Short Message Peer-to-Peer, versions 3.3 to 5.0 and the Huawei SMPP+
extensions).

Usage: mksmpp.py <output directory>

SMPP is dissected on TCP port 2775 by default and by the heuristic
"smpp_tcp"; every operation, response, optional parameter (TLV), time
format, data coding and user data header is built here. Every packet is
built with struct; nothing is captured.

Writes:
  smpp-coverage.pcapng            TCP sessions (port 2775): binds, submit,
                                  deliver, query, replace, cancel, multi,
                                  data_sm, broadcast operations and their
                                  responses, every TLV; one Exported PDU
                                  frame (interface 1)
  smpp-coverage-malformed.pcapng  truncated PDUs, bad lengths, strings
                                  without terminator, TLVs cut short
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from pcaplib import exported_pdu, LT_ETH, LT_EXPORTED_PDU, pcapng, TcpConn


def cs(s):
    return (s.encode() if isinstance(s, str) else s) + b'\0'


def pdu(cmd, status=0, seq=1, body=b''):
    return struct.pack('>IIII', 16 + len(body), cmd, status, seq) + body


def tlv(tag, value=b''):
    if isinstance(value, int):
        value = bytes([value])
    return struct.pack('>HH', tag, len(value)) + value


T_ABS = '231231235959000+'
T_REL = '000101120000000R'
T_REL0 = '000001120000000R'          # month 00: valid in SMPP, rejected by the dissector


def sm_body(service='', ston=1, snpi=1, src='491701234567', dton=1, dnpi=1, dst='491707654321',
            esm=0, proto=0, prio=0, sched='', valid='', regdel=0, replace=0, dcs=0, defmsg=0,
            text=b'hello'):
    b = cs(service) + bytes([ston, snpi]) + cs(src) + bytes([dton, dnpi]) + cs(dst)
    b += bytes([esm, proto, prio]) + cs(sched) + cs(valid)
    b += bytes([regdel, replace, dcs, defmsg, len(text)]) + text
    return b


def gsm7(text):
    """Pack GSM 7-bit default alphabet characters (ASCII subset) into octets."""
    bits, n = 0, 0
    out = bytearray()
    for ch in text.encode():
        bits |= (ch & 0x7f) << n
        n += 7
        while n >= 8:
            out.append(bits & 0xff)
            bits >>= 8
            n -= 8
    if n:
        out.append(bits & 0xff)
    return bytes(out)


def udh_concat(ref, total, seq):
    return bytes([5, 0, 3, ref, total, seq])


def main(out):
    c = TcpConn(50000, 2775)
    c.handshake()
    seq = [0]

    def req(cmd, body=b'', status=0):
        seq[0] += 1
        c.send(pdu(cmd, status, seq[0], body))
        return seq[0]

    def resp(cmd, s, body=b'', status=0):
        c.send(pdu(0x80000000 | cmd, status, s, body), client=False)

    # ---- binds ------------------------------------------------------------------
    for cmd in (0x01, 0x02, 0x09):
        s = req(cmd, cs('esme1') + cs('secret') + cs('SMPP') + bytes([0x34, 1, 1]) + cs('^49'))
        resp(cmd, s, cs('smsc') + tlv(0x0210, 0x34))
    s = req(0x01, cs('esme1') + cs('badpw') + cs('') + bytes([0x50, 0, 0]) + cs(''))
    resp(0x01, s, b'', status=0x0e)                                 # invalid password, no body
    s = req(0x09, cs('esme') + cs('') + cs('') + bytes([0x33, 0, 0]) + cs(''))
    resp(0x09, s, cs('smsc'))
    # outbind
    seq[0] += 1
    c.send(pdu(0x0b, 0, seq[0], cs('smsc') + cs('pw')), client=False)
    # ---- submit_sm and responses ----------------------------------------------------------
    s = req(0x04, sm_body(sched=T_ABS, valid=T_REL, regdel=0x1d, replace=1))
    resp(0x04, s, cs('msg-0001'))
    s = req(0x04, sm_body(service='CMT', sched='', valid='', esm=0x03))
    resp(0x04, s, cs('msg-0002'))
    s = req(0x04, sm_body(sched='231231235959000-', valid='231231235959032+'))   # time zone minus, quarter hours
    resp(0x04, s, b'', status=0x0b)                                  # invalid destination: no body
    s = req(0x04, sm_body())
    resp(0x04, s, cs('msg-0003') + tlv(0x001d, b'extra info') + tlv(0x0423, bytes([3, 0, 4])))
    for dcs in (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0d, 0x0e, 0x0f,
                0xc0, 0xc8, 0xd0, 0xd8, 0xe0, 0xe8, 0xf0, 0xf4, 0xf5, 0xfc, 0x41, 0x80):
        txt = 'ab'.encode('utf-16-be') if dcs == 0x08 else (gsm7('hi there') if dcs == 0x00 else b'Hello')
        s = req(0x05, sm_body(dcs=dcs, text=txt))
        resp(0x05, s, cs(''))
    # user data header: concatenation, 8-bit and 16-bit reference, and ports
    s = req(0x05, sm_body(esm=0x40, dcs=0x00, text=udh_concat(0x2a, 3, 1) + b'part one'))
    resp(0x05, s, cs(''))
    s = req(0x05, sm_body(esm=0x40, dcs=0x00, text=udh_concat(0x2a, 3, 2) + b'part two'))
    resp(0x05, s, cs(''))
    s = req(0x05, sm_body(esm=0x40, dcs=0x00, text=udh_concat(0x2a, 3, 3) + b'part three'))
    resp(0x05, s, cs(''))
    s = req(0x05, sm_body(esm=0x40, dcs=0x08, text=bytes([6, 8, 4, 0x43, 0x21, 1, 1]) + 'ab'.encode('utf-16-be')))
    resp(0x05, s, cs(''))
    s = req(0x05, sm_body(esm=0x40, dcs=0x04, text=bytes([6, 5, 4, 0x1f, 0x90, 0x1f, 0x91]) + b'wsp'))
    resp(0x05, s, cs(''))
    # packed 7-bit text with a UDH (fill bits)
    s = req(0x05, sm_body(esm=0x40, dcs=0x00, text=udh_concat(0x2b, 2, 1) + gsm7('x') + b'abcdefg'))
    resp(0x05, s, cs(''))
    # segmentation through SAR TLVs
    for n in (1, 2):
        s = req(0x04, sm_body(text=b'Fragment %d' % n) + tlv(0x020c, struct.pack('>H', 0x1234)) +
                tlv(0x020e, 2) + tlv(0x020f, n))
        resp(0x04, s, cs('sar-%d' % n))
    s = req(0x04, sm_body(text=b'') + tlv(0x0424, b'A long message payload ' * 4))   # message_payload
    resp(0x04, s, cs('payload'))
    s = req(0x04, sm_body(esm=0x40, dcs=0x00, text=b'') + tlv(0x0424, udh_concat(7, 2, 1) + b'in a payload'))
    resp(0x04, s, cs('payload-udh'))
    # ---- all optional parameters on submit_sm -----------------------------------------------
    tlvs = b''.join([
        tlv(0x0005, 2), tlv(0x0006, 1), tlv(0x0007, 2), tlv(0x0008, struct.pack('>H', 0x0102)),
        tlv(0x000d, 3), tlv(0x000e, 1), tlv(0x000f, 4), tlv(0x0010, 5),
        tlv(0x0017, struct.pack('>I', 3600)), tlv(0x0019, 1), tlv(0x001d, b'status text'),
        tlv(0x001e, b'receipted-id'), tlv(0x0030, 0x81), tlv(0x0201, 2), tlv(0x0202, b'\x80sub'),
        tlv(0x0203, b'\xa0dest'), tlv(0x0204, struct.pack('>H', 77)), tlv(0x0205, 9),
        tlv(0x020a, struct.pack('>H', 2948)), tlv(0x020b, struct.pack('>H', 9200)),
        tlv(0x020d, 1), tlv(0x0210, 0x34), tlv(0x0302, 0x05), tlv(0x0303, b'\x00tag'),
        tlv(0x0304, 4), tlv(0x0381, b'\x00callback'), tlv(0x0420, 1), tlv(0x0421, 0),
        tlv(0x0422, 2), tlv(0x0423, bytes([3, 0, 8])), tlv(0x0425, 1), tlv(0x0426, 1),
        tlv(0x0427, 2), tlv(0x0428, 40), tlv(0x0501, 3), tlv(0x1201, 2),
        tlv(0x1203, struct.pack('>H', 0x0102)), tlv(0x1204, 1), tlv(0x130c, 1),
        tlv(0x1380, 1), tlv(0x1383, bytes([5, 0x01])),
        tlv(0x0600, 1), tlv(0x0601, struct.pack('>BH', 2, 0x0102)), tlv(0x0602, b'ct-info'),
        tlv(0x0603, 3), tlv(0x0604, 5), tlv(0x0605, struct.pack('>BH', 2, 30)),
        tlv(0x0606, b'\x00' + b'area'), tlv(0x0607, struct.pack('>I', 3)), tlv(0x0608, 80),
        tlv(0x0609, T_ABS.encode() + b'\0'), tlv(0x060a, b'group'), tlv(0x060b, b'billing'),
        tlv(0x060d, b'srcnet'), tlv(0x060e, b'dstnet'), tlv(0x060f, b'\x01\x02\x03'),
        tlv(0x0610, b'\x04\x05'), tlv(0x0611, 1), tlv(0x0612, b'np-info'), tlv(0x0613, b'49'),
        tlv(0x130c, b''),                                          # alert_on_message_delivery without value
        tlv(0x0609, b'\0'),                                        # empty end time
        tlv(0x1fff, b'vendor specific'),                           # vendor specific
        tlv(0x0100, b'reserved'), tlv(0x0700, b''),                # unknown and empty
    ])
    s = req(0x04, sm_body() + tlvs)
    resp(0x04, s, cs('all-tlvs'))
    # ---- query_sm, replace_sm, cancel_sm ---------------------------------------------------------
    s = req(0x03, cs('msg-0001') + bytes([1, 1]) + cs('491701234567'))
    resp(0x03, s, cs('msg-0001') + cs('231231235959000+') + bytes([2, 0]))
    resp(0x03, s, cs('msg-0001') + cs('') + bytes([8, 0x45]))
    s = req(0x07, cs('msg-0001') + bytes([1, 1]) + cs('491701234567') + cs(T_ABS) + cs(T_REL) +
            bytes([1, 0, 5]) + b'newtx')
    resp(0x07, s)
    s = req(0x07, cs('msg-0001') + bytes([1, 1]) + cs('491701234567') + cs('') + cs('') + bytes([0, 0, 0]) + b'')
    resp(0x07, s)
    s = req(0x08, cs('') + cs('msg-0001') + bytes([1, 1]) + cs('491701234567') + bytes([1, 1]) + cs('491707654321'))
    resp(0x08, s)
    # ---- submit_multi ---------------------------------------------------------------------
    dlist = bytes([3]) + b'\x01' + bytes([1, 1]) + cs('491700000001') + b'\x02' + cs('distlist') + \
        b'\x01' + bytes([2, 2]) + cs('491700000002')
    multi = cs('') + bytes([1, 1]) + cs('491701234567') + dlist + bytes([0, 0, 0]) + cs(T_ABS) + cs('') + \
        bytes([0, 0, 0, 0, 5]) + b'multi'
    s = req(0x21, multi)
    resp(0x21, s, cs('multi-1') + bytes([2]) + bytes([1, 1]) + cs('491700000001') + struct.pack('>I', 0x0b) +
         bytes([1, 1]) + cs('491700000002') + struct.pack('>I', 0x0a))
    multi2 = cs('') + bytes([1, 1]) + cs('491701234567') + bytes([1]) + b'\x01' + bytes([1, 1]) + cs('49170') + \
        bytes([0, 0, 0]) + cs(T_ABS) + cs(T_REL) + bytes([0, 0, 0, 0, 2]) + b'ok'
    s = req(0x21, multi2)
    resp(0x21, s, cs('multi-3') + bytes([0]))
    s = req(0x21, cs('') + bytes([1, 1]) + cs('491701234567') + bytes([0]) + bytes([0, 0, 0]) + cs('') + cs('') +
            bytes([0, 0, 0, 0, 0]))
    resp(0x21, s, cs('multi-2') + bytes([0]))
    # ---- alert_notification ---------------------------------------------------------------------
    seq[0] += 1
    c.send(pdu(0x102, 0, seq[0], bytes([1, 1]) + cs('491701234567') + bytes([1, 1]) + cs('esme') + tlv(0x0422, 0)),
           client=False)
    # ---- data_sm ----------------------------------------------------------------------------------
    s = req(0x103, cs('') + bytes([1, 1]) + cs('491701234567') + bytes([1, 1]) + cs('491707654321') +
            bytes([0, 1, 0]) + tlv(0x0424, b'data_sm payload') + tlv(0x0005, 1))
    resp(0x103, s, cs('data-1') + tlv(0x0425, 0))
    s = req(0x103, cs('WAP') + bytes([5, 0]) + cs('wap') + bytes([1, 1]) + cs('1') + bytes([0x40, 0, 4]) +
            tlv(0x0424, bytes([6, 5, 4, 0x1f, 0x90, 0x1f, 0x91]) + b'wsp'))
    resp(0x103, s, cs('data-2'))
    # ---- broadcast ----------------------------------------------------------------------------------
    bc = cs('') + bytes([1, 1]) + cs('491701234567') + cs('bc-id-1') + bytes([1]) + cs(T_ABS) + cs(T_REL) + \
        bytes([0, 0, 0]) + tlv(0x0600, 1) + tlv(0x0606, b'\x00area') + tlv(0x0605, struct.pack('>BH', 2, 30)) + \
        tlv(0x0603, 1) + tlv(0x0601, struct.pack('>BH', 1, 2)) + tlv(0x0424, b'broadcast text')
    s = req(0x111, bc)
    resp(0x111, s, cs('bc-1') + tlv(0x0608, 90))
    s = req(0x111, cs('') + bytes([1, 1]) + cs('491701234567') + cs('bc-id-2') + bytes([0]) + cs('') + cs('') +
            bytes([0, 0, 0]) + tlv(0x0600, 1))                        # no schedule time and no validity period
    resp(0x111, s, cs('bc-2'))
    s = req(0x112, cs('bc-1') + bytes([1, 1]) + cs('491701234567') + tlv(0x0600, 1))
    resp(0x112, s, cs('bc-1') + tlv(0x0427, 2) + tlv(0x0608, 50) + tlv(0x0606, b'\x00area'))
    s = req(0x113, cs('') + cs('bc-1') + bytes([1, 1]) + cs('491701234567') + tlv(0x0606, b'\x00area'))
    resp(0x113, s)
    # ---- link keeping and teardown ----------------------------------------------------------------------
    s = req(0x15)
    resp(0x15, s)
    s = req(0x00 + 0x15)                                              # a second enquire_link, no response yet
    seq[0] += 1
    c.send(pdu(0x80000000, 0x03, seq[0]), client=False)                # generic_nack
    # a response without request, and a request with a response that has another sequence number
    c.send(pdu(0x80000004, 0, 9999, cs('orphan')), client=False)
    # ---- Huawei SMPP+ -----------------------------------------------------------------------------------
    s = req(0x01000001, b'3' + cs('smsc-addr') + bytes([1, 1]) + cs('msc-addr') + cs('491701234567') + cs('491707654321') +
            bytes([0]) + cs('sm-id') + struct.pack('>II', 4, 1001))
    resp(0x01000001, s, struct.pack('>I', 0) + bytes([1]))
    s = req(0x01000001, b'2' + cs('smsc-addr') + cs('491701234567') + cs('491707654321') + bytes([1]) + cs('sm-id') +
            struct.pack('>II', 4, 1001))
    resp(0x01000001, s, b'', status=0x08)
    s = req(0x01000002, b'3' + cs('smsc-addr') + bytes([1, 1]) + cs('msc-addr') + cs('491701234567') + cs('491707654321') +
            bytes([1]) + cs('sm-id') + struct.pack('>III', 4, 0, 1001))
    resp(0x01000002, s, struct.pack('>I', 0))
    s = req(0x01000002, b'2' + cs('smsc-addr') + cs('491701234567') + cs('491707654321') + bytes([1]) + cs('sm-id') +
            struct.pack('>III', 4, 1, 1001))
    resp(0x01000002, s, struct.pack('>I', 0))
    # ---- unbind -----------------------------------------------------------------------------------------
    s = req(0x06)
    resp(0x06, s)
    # ---- PDUs in one segment and PDUs split over two segments ------------------------------------------------------------
    c.send(pdu(0x15, 0, 70001) + pdu(0x15, 0, 70002) + pdu(0x80000015, 0, 70001), client=True)
    big = pdu(0x04, 0, 70003, sm_body(text=b'x' * 100))
    c.send(big[:30])
    c.send(big[30:])
    # an unknown command id: only seen on X.25 / over the heuristic it is rejected
    n1 = len(c.frames)
    # alert_notification on a non-default port: found by the heuristic
    h = TcpConn(50001, 9999, isn_c=500, isn_s=900)
    h.handshake()
    h.send(pdu(0x102, 0, 1, bytes([1, 1]) + cs('4917012345') + bytes([1, 1]) + cs('esme')))
    h.send(pdu(0x15, 0, 2))
    h.send(pdu(0x80000015, 0, 2), client=False)
    # a second session on port 2775 whose requests have the same sequence numbers
    d = TcpConn(50002, 2775, isn_c=7000, isn_s=8000)
    d.handshake()
    d.send(pdu(0x15, 0, 1))
    d.send(pdu(0x80000015, 0, 1), client=False)
    d.send(pdu(0x15, 0, 1))
    d.send(pdu(0x80000015, 0, 1), client=False)
    ep = exported_pdu('smpp', pdu(0x15, 0, 5))
    frames = [(0, f) for f in c.frames + h.frames + d.frames] + [(1, ep)]
    pcapng(os.path.join(out, 'smpp-coverage.pcapng'), frames, (LT_ETH, LT_EXPORTED_PDU))
    print('%d frames: main session 1-%d, heuristic port 9999 %d-%d, second session %d-%d, Exported PDU %d' % (
        len(frames), n1, n1 + 1, n1 + len(h.frames), n1 + len(h.frames) + 1,
        len(frames) - 1, len(frames)))

    # ---- malformed ------------------------------------------------------------------------------------
    m = TcpConn(50010, 2775, isn_c=1, isn_s=1)
    m.handshake()
    ms = [0]

    def mreq(cmd, body, length=None):
        ms[0] += 1
        p = pdu(cmd, 0, ms[0], body)
        if length is not None:
            p = struct.pack('>I', length) + p[4:]
        m.send(p)

    mreq(0x04, sm_body()[:10])                                         # cut inside the strings
    mreq(0x04, sm_body(text=b'abc')[:-1])                              # short message cut
    mreq(0x04, b'abc' * 5)                                             # no terminators
    mreq(0x04, sm_body() + tlv(0x0005, 1)[:3])                         # TLV header cut
    mreq(0x04, sm_body() + struct.pack('>HH', 0x0424, 200) + b'short')   # TLV longer than the PDU
    mreq(0x04, sm_body() + tlv(0x0008, b'\x01'))                       # TLV with the wrong length
    mreq(0x04, sm_body() + tlv(0x0423, b'\x01'))
    mreq(0x04, sm_body(esm=0x40, text=bytes([200, 0, 3, 1, 2, 3])))    # UDH longer than the message
    mreq(0x04, sm_body(esm=0x40, dcs=0x00, text=bytes([0])))           # UDH of length 0
    mreq(0x05, sm_body(esm=0x40, dcs=0x00, text=bytes([4, 0, 3, 1, 2]) + b'xx'))
    mreq(0x01, cs('a') + cs('b'))                                      # bind cut short
    mreq(0x03, cs('id'))
    mreq(0x21, cs('') + bytes([1, 1]) + cs('src') + bytes([200]) + b'\x01\x01\x01')   # 200 destinations, cut short
    mreq(0x21, cs('') + bytes([1, 1]) + cs('src') + bytes([2]) + b'\x07' + bytes(5))  # unknown destination flag
    mreq(0x102, bytes([1, 1]) + cs('a') + bytes([1, 1]))                # alert_notification cut
    mreq(0x103, cs('') + bytes([1, 1]) + cs('a'))                       # data_sm cut
    mreq(0x111, cs('') + bytes([1, 1]) + cs('a'))                       # broadcast_sm cut
    mreq(0x01000001, b'3' + cs('smsc'))                                 # Huawei cut
    mreq(0x04, sm_body(sched='2312312359590', valid='231231235959000x'))   # malformed time strings
    mreq(0x04, sm_body(sched='23123123595900', valid='bad'))
    mreq(0x04, sm_body(sched=T_REL0, valid=T_REL0))                     # relative time with month 00
    mreq(0x07, cs('m') + bytes([1, 1]) + cs('s') + cs(T_REL0) + cs('') + bytes([0, 0, 0]))
    mreq(0x111, cs('') + bytes([1, 1]) + cs('a') + cs('id') + bytes([1]) + cs(T_REL0) + cs(T_REL0) + bytes([0, 0, 0]))
    mreq(0x04, sm_body(), length=8)                                     # length below the minimum
    mreq(0x04, sm_body(), length=0x20000)                                # length above 64 KiB (not SMPP)
    mreq(0x04, sm_body(text=b'abc') + tlv(0x0424, b'duplicate'))      # short_message and message_payload
    m.send(b'\x00' * 10)                                               # shorter than a header
    ms[0] += 1
    m.send(pdu(0x15, 0xffff0000, ms[0]))                               # status that is not known (not SMPP)
    mreq(0x7f, b'')                                                     # unknown command id (not SMPP: heuristic declines)
    m.send(pdu(0x80000004, 0x0b, 77, cs('x')), client=False)           # response with error status: no body
    m.send(pdu(0x80000004, 0x7b, 78), client=False)                    # reserved status
    m.send(pdu(0x80000004, 0x4ff, 79), client=False)                   # vendor specific status
    m.send(pdu(0x80000004, 0x1234, 80), client=False)                  # unknown status (heuristic declines)
    m.send(pdu(0x80000003, 0, 81, cs('id')), client=False)             # query_sm_resp cut
    m.send(pdu(0x80000021, 0, 82, cs('id') + bytes([5])), client=False)  # submit_multi_resp cut
    m.send(pdu(0x80000103, 0, 83, b''), client=False)
    m.send(pdu(0x80000112, 0, 84, b''), client=False)
    m.send(pdu(0x80000001, 0, 85, b''), client=False)
    # PDU whose length field is shorter than the header it carries
    m.send(struct.pack('>IIII', 14, 0x15, 0, 3))
    # alert_notification as first PDU on other ports: the heuristic checks the address
    extra = []
    for i, body in enumerate([bytes([1, 1]) + b'\x00',                   # PDU too short (reported length < 19)
                              bytes([99, 1]) + cs('4917012345'),            # unknown TON
                              bytes([1, 99]) + cs('4917012345'),            # unknown NPI
                              bytes([1, 1]) + b'4917012345',                # address without terminator
                              bytes([1, 1]) + cs('x' * 70),                 # address of more than 65 characters
                              bytes([1, 1]) + cs('49\x01\x0270')]):         # not printable
        h = TcpConn(50020 + i, 9000 + i, isn_c=1, isn_s=1)
        h.handshake()
        h.send(pdu(0x102, 0, 1, body))
        extra += h.frames
    # Exported PDU frames: the non-TCP branch has no heuristic and dissects unknown commands too
    exp = [(1, exported_pdu('smpp', pdu(0x7f, 0, 1))), (1, exported_pdu('smpp', pdu(0x8000007f, 0, 1))),
           (1, exported_pdu('smpp', pdu(0x15, 0, 2) + b'\x00\x00\x00\x00')),
           (1, exported_pdu('smpp', pdu(0x04, 0, 3, sm_body()) + pdu(0x15, 0, 4) + pdu(0x80000015, 0, 4)))]
    pcapng(os.path.join(out, 'smpp-coverage-malformed.pcapng'), [(0, f) for f in m.frames + extra] + exp,
           (LT_ETH, LT_EXPORTED_PDU))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
