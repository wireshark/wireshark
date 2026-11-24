#!/usr/bin/env python3
# Generates test/captures/mmse_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MMSE coverage captures.  Usage: mkmmse.py <outdir> [-v]
MMS PDUs are carried the way real traffic carries them: HTTP POST
requests and 200 responses on TCP port 80 (media type
application/vnd.wap.mms-message), a multipart HTTP response whose part is an
MMS PDU (the encapsulated dissector), and WSP over UDP 9200 (the content type
by WINA value, and an unknown content type so the WSP heuristic finds it).
Writes mmse-coverage.pcap (Ethernet) and mmse-coverage-malformed.pcap."""
import struct
import sys
import os

# ---------------------------------------------------------------- framing
def pcap(name, pkts):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

CL = bytes([192, 0, 2, 10]); SV = bytes([192, 0, 2, 20])
ETH_CL = bytes.fromhex('020000000001'); ETH_SV = bytes.fromhex('020000000002')
ipid = [0]

def ip(proto, payload, src, dst):
    ipid[0] += 1
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ipid[0], 0x4000, 64, proto, 0, src, dst)
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def eth(payload, src, dst):
    return dst + src + b'\x08\x00' + payload

def tcp(src, dst, sport, dport, seq, ack, flags, data=b''):
    opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''
    h = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
    ph = src + dst + struct.pack('>BBH', 0, 6, len(h) + len(data))
    ck = csum(ph + h + data)
    h = h[:16] + struct.pack('>H', ck) + h[18:]
    return h + data

def udp(src, dst, sport, dport, data):
    ln = 8 + len(data)
    h = struct.pack('>HHHH', sport, dport, ln, 0)
    ph = src + dst + struct.pack('>BBH', 0, 17, ln)
    ck = csum(ph + h + data) or 0xffff
    return struct.pack('>HHHH', sport, dport, ln, ck) + data

# ------------------------------------------------------- MMS encodings
def text(s):             return s.encode() + b'\0'
def uintvar(n):
    out = [n & 0x7f]; n >>= 7
    while n:
        out.append(0x80 | (n & 0x7f)); n >>= 7
    return bytes(reversed(out))
def vlen(n):             return bytes([n]) if n < 31 else b'\x1f' + uintvar(n)
def longint(n, size=4):  return bytes([size]) + n.to_bytes(size, 'big')
def shortint(n):         return bytes([0x80 | n])
def estr_charset(s):     # Value-length Char-set(106, short integer) Text-string
    b = bytes([0xEA]) + text(s)
    return vlen(len(b)) + b
def estr_long_charset(s):  # char-set as a one-octet long integer
    b = bytes([1, 106]) + text(s)
    return vlen(len(b)) + b
def estr_ascii_len(s):   # Value-length followed by text without a char-set
    b = s.encode()
    return vlen(len(b)) + b
def quoted(s):           return b'\x7f' + text(s)

def pdu(ptype, *hdrs):
    return bytes([0x8C, ptype]) + b''.join(hdrs)
def H(code, val):        return bytes([code]) + val

TID = H(0x98, text('t0001'))
V10 = H(0x8D, b'\x90'); V11 = H(0x8D, b'\x91'); V12 = H(0x8D, b'\x92'); V1 = H(0x8D, b'\x9f')
FROM = H(0x89, vlen(1 + len(text('+15551234/TYPE=PLMN'))) + b'\x80' + text('+15551234/TYPE=PLMN'))
FROM_INS = H(0x89, b'\x01\x81')
FROM_LONG = H(0x89, vlen(1 + len(text('a' * 40 + '@example.org'))) + b'\x80' + text('a' * 40 + '@example.org'))
TO = H(0x97, text('+15559999/TYPE=PLMN'))
DATE = H(0x85, longint(1700000000))
MID = H(0x8B, text('msg-0001@example.org'))

# WSP multipart body: entries, headers length, data length, content-type
def part(ctype, data):
    return uintvar(len(ctype)) + uintvar(len(data)) + ctype + data
def multipart(*parts):
    return uintvar(len(parts)) + b''.join(parts)
BODY = multipart(part(b'\x83', b'Hello MMS'), part(b'\x9e', b'\xff\xd8\xff\xe0' + b'\x00' * 8))

# ---------------------------------------------------------------- PDUs
def main_pdus():
    P = []
    def add(label, b): P.append((label, b))
    add('m-send-req v1.0: from, to, cc, bcc, subject, class, priority, reports, times, size, multipart body',
        pdu(0x80, TID, V10, FROM, TO, H(0x82, text('cc@example.org')),
            H(0x81, estr_charset('bcc@example.org')), H(0x96, estr_charset('Hello')),
            H(0x8A, b'\x80'), H(0x8F, b'\x81'), H(0x86, b'\x80'), H(0x90, b'\x81'), H(0x94, b'\x80'),
            H(0x87, vlen(6) + b'\x81' + longint(3600)), H(0x88, vlen(6) + b'\x80' + longint(1800000000)),
            DATE, MID, H(0x8E, longint(1234, 2)), H(0x84, b'\xa3') + BODY))
    add('m-send-conf: response status, response text (1.0)',
        pdu(0x81, TID, V10, H(0x92, b'\x80'), H(0x93, text('OK')), MID))
    add('m-notification-ind v1.1: class text, content location, expiry, from insert address',
        pdu(0x82, TID, V11, H(0x8A, text('informational')), H(0x8E, longint(0x10000, 3)),
            H(0x88, vlen(6) + b'\x81' + longint(86400)), H(0x83, text('http://mms.example.net/m1')),
            FROM_INS, H(0x96, estr_long_charset('Subject two'))))
    add('m-notifyresp-ind: status, report allowed',
        pdu(0x83, TID, V11, H(0x95, b'\x81'), H(0x91, b'\x80')))
    add('m-retrieve-conf v1.1: retrieve status/text, reply charging, read report, forwarding info',
        pdu(0x84, TID, V11, DATE, FROM_LONG, TO, H(0x96, estr_ascii_len('plain subject')), MID,
            H(0x8A, b'\x82'), H(0x8F, b'\x82'), H(0x99, b'\x80'), H(0x9A, estr_charset('retrieved')),
            H(0x9C, b'\x80'), H(0x9D, vlen(6) + b'\x80' + longint(1800000000)),
            H(0x9D, vlen(6) + b'\x81' + longint(7200)), H(0x9E, text('rc-1')), H(0x9F, longint(256, 2)),
            H(0x90, b'\x81'),
            H(0xA0, vlen(1 + len(text('fwd@example.org'))) + shortint(2) + text('fwd@example.org')),
            H(0xA0, vlen(2 + len(text('fwd@example.org'))) + bytes([1, 3]) + text('fwd@example.org')),
            H(0xA1, vlen(1 + 5) + shortint(1) + longint(1700000000)),
            H(0x84, b'\xa3') + BODY))
    add('m-acknowledge-ind: report allowed', pdu(0x85, TID, V10, H(0x91, b'\x81')))
    add('m-delivery-ind: status', pdu(0x86, V10, MID, TO, DATE, H(0x95, b'\x82')))
    add('m-read-rec-ind: read status', pdu(0x87, V11, MID, TO, FROM, DATE, H(0x9B, b'\x80')))
    add('m-read-orig-ind: read status deleted', pdu(0x88, V11, MID, TO, FROM, DATE, H(0x9B, b'\x81')))
    add('m-forward-req: content location, cc, delivery report',
        pdu(0x89, TID, V11, TO, H(0x83, text('http://mms.example.net/m2')), H(0x82, estr_charset('c@example.org')),
            H(0x86, b'\x81'), H(0x87, vlen(6) + b'\x80' + longint(1700000100)), H(0x8F, b'\x80')))
    add('m-forward-conf', pdu(0x8A, TID, V11, H(0x92, b'\x80'), MID))
    add('m-mbox-store-req v1.2: store, flags and other 1.2 headers',
        pdu(0x8B, TID, V12, H(0x83, text('http://mms.example.net/m3')), H(0xA2, b'\x80'),
            H(0xA3, text('Draft')), H(0xA4, b'\x02\x80\x41'), H(0xA7, b'\x80')))
    add('m-mbox-store-conf: store status and text',
        pdu(0x8C, TID, V12, H(0xA5, b'\x80'), H(0xA6, text('stored')), H(0x83, text('http://mms.example.net/m3'))))
    add('m-mbox-view-req: attributes (literal header), limit',
        pdu(0x8D, TID, V12, H(0x83, text('http://mms.example.net/m3')), H(0xB3, b'\x85'),
            text('X-Attr') + text('subject'), H(0xA8, text('from')), H(0xB0, b'\x1f\x03abc')))
    add('m-mbox-view-conf with a body: totals, quotas, mbox message count',
        pdu(0x8E, TID, V12, H(0xA9, b'\x80'), H(0xAA, b'\x01\x05'), H(0xAB, b'\x80'), H(0xAC, b'\x02\x01\x02'),
            H(0xAD, longint(5, 1)), H(0x84, b'\xa3') + BODY))
    add('m-mbox-upload-req with a body', pdu(0x8F, TID, V12, H(0x83, text('http://mms.example.net/m4')),
                                           H(0x84, b'\xa3') + BODY))
    add('m-mbox-upload-conf', pdu(0x90, TID, V12, H(0x92, b'\x80'), H(0xA5, b'\x80')))
    add('m-mbox-delete-req', pdu(0x91, TID, V12, H(0x83, text('http://mms.example.net/m3'))))
    add('m-mbox-delete-conf: content location, response text and retrieve text in general form (length octet)',
        pdu(0x92, TID, V12, H(0x83, b'\x03abc'), H(0x93, b'\x02xy'), H(0x9A, b'\x01z')))
    add('m-mbox-delete-conf: general form with a uintvar length (0x1F)',
        pdu(0x92, TID, V12, H(0x83, b'\x1f\x02ab'), H(0x93, b'\x1f\x03abc'), H(0x9A, b'\x1f\x01q')))
    add('m-mbox-descr with a body', pdu(0x93, TID, V12, H(0x84, b'\xa3') + BODY))
    add('unknown message type 0x99', pdu(0x99, TID, V11))
    add('encoded strings: quoted text, empty value-length, value-length without char-set',
        pdu(0x80, TID, V1, TO, H(0x96, quoted('quoted subject')), H(0x82, b'\x00'), H(0x81, estr_ascii_len('lenasc')),
            H(0x97, b'\x01\x80'), H(0x84, b'\xa3') + BODY))
    add('long integers: 5 octets (value ignored), 1, 3 octets; short integer; date with zero length',
        pdu(0x87, V11, H(0x8E, longint(0, 5)), H(0x8E, longint(7, 1)), H(0x9F, longint(0x10203, 3)),
            H(0x85, b'\x00'), H(0x9B, b'\x80')))
    add('1.2 headers: well-known value, text, general form, uintvar general form, literal header',
        pdu(0x80, TID, V12, H(0xA2, b'\x80'), H(0xA3, text('abc')), H(0xA4, b'\x03\x01\x02\x03'),
            H(0xAD, b'\x1f\x02\x01\x02'), text('X-Custom-Header') + text('custom value'),
            H(0xB1, b'\x00'), H(0x84, b'\xa3') + BODY))
    add('retrieve-conf, multipart with several parts',
        pdu(0x84, TID, V10, DATE, H(0x84, b'\xb3') + multipart(part(b'\x83', b'one'), part(b'\x83', b'two'),
                                                               part(b'\x83', b'three'))))
    add('previously-sent-by with long-integer forwarded counts of 2, 3, 4 and 5 octets',
        pdu(0x84, TID, V11,
            H(0xA0, vlen(7) + bytes([2, 0, 5]) + text('a@x')),
            H(0xA0, vlen(8) + bytes([3, 0, 0, 6]) + text('b@x')),
            H(0xA0, vlen(9) + bytes([4, 0, 0, 0, 7]) + text('c@x')),
            H(0xA0, vlen(10) + bytes([5, 0, 0, 0, 0, 8]) + text('d@x'))))
    add('MMS 1.0 default (no version header): X-Mms-Read-Reply',
        pdu(0x80, TID, H(0x90, b'\x80'), TO))
    return P

def http_conn(pairs, sport=41000, extra=None):
    """TCP session: handshake, then request/response pairs.
    pairs: list of (req_body_or_None, rsp_body_or_None)."""
    fr = []
    cseq, sseq = 1000, 5000
    def c2s(data, flags=0x18):
        nonlocal cseq
        fr.append(eth(ip(6, tcp(CL, SV, sport, 80, cseq, sseq, flags, data), CL, SV), ETH_CL, ETH_SV))
        cseq += len(data)
    def s2c(data, flags=0x18):
        nonlocal sseq
        fr.append(eth(ip(6, tcp(SV, CL, 80, sport, sseq, cseq, flags, data), SV, CL), ETH_SV, ETH_CL))
        sseq += len(data)
    fr.append(eth(ip(6, tcp(CL, SV, sport, 80, cseq, 0, 0x02), CL, SV), ETH_CL, ETH_SV)); cseq += 1
    fr.append(eth(ip(6, tcp(SV, CL, 80, sport, sseq, cseq, 0x12), SV, CL), ETH_SV, ETH_CL)); sseq += 1
    fr.append(eth(ip(6, tcp(CL, SV, sport, 80, cseq, sseq, 0x10), CL, SV), ETH_CL, ETH_SV))
    for req, rsp in pairs:
        if req is not None:
            ctype = req[0]
            body = req[1]
            c2s(('POST /mms HTTP/1.1\r\nHost: mms.example.net\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n'
                 % (ctype, len(body))).encode() + body)
        else:
            c2s(b'GET /mms/1 HTTP/1.1\r\nHost: mms.example.net\r\n\r\n')
        ctype, body = rsp
        s2c(('HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n' % (ctype, len(body))).encode() + body)
    return fr

MMS = 'application/vnd.wap.mms-message'

def main():
    out = sys.argv[1]
    verbose = '-v' in sys.argv
    os.makedirs(out, exist_ok=True)
    pk, marks = [], []
    pdus = main_pdus()
    # pair the PDUs: even ones are POST bodies, odd ones responses
    pairs = []
    labels = []
    i = 0
    while i < len(pdus):
        req = pdus[i]
        rsp = pdus[i + 1] if i + 1 < len(pdus) else ('empty', pdu(0x81, TID, V10, H(0x92, b'\x80')))
        pairs.append(((MMS, req[1]), (MMS, rsp[1])))
        labels.append(req[0]); labels.append(rsp[0])
        i += 2
    fr = http_conn(pairs)
    pk += fr
    for k, lab in enumerate(labels):
        marks.append((4 + k // 2 * 2 + (k % 2) + 0, 'PDU %d (%s): %s' % (k + 1, 'POST' if k % 2 == 0 else '200 response', lab)))
    # multipart/mixed response with an MMS part (encapsulated dissector)
    boundary = 'xYzBoundary'
    mp = ('--%s\r\nContent-Type: %s\r\n\r\n' % (boundary, MMS)).encode() + pdu(0x84, TID, V11, DATE, FROM, TO, H(0x96, estr_charset('encapsulated'))) \
         + ('\r\n--%s--\r\n' % boundary).encode()
    start = len(pk)
    pk += http_conn([(None, ('multipart/mixed; boundary=%s' % boundary, mp))], sport=41001)
    marks.append((start + 5, 'HTTP response multipart/mixed with an MMS PDU part (m-retrieve-conf)'))
    mp2 = ('--%s\r\nContent-Type: %s\r\n\r\n' % (boundary, MMS)).encode() + pdu(0x86, V10, MID, TO, DATE, H(0x95, b'\x81')) \
          + ('\r\n--%s--\r\n' % boundary).encode()
    start = len(pk)
    pk += http_conn([((('multipart/related; boundary=%s' % boundary), mp2), (MMS, pdu(0x81, TID, V10, H(0x92, b'\x80'))))], sport=41002)
    marks.append((start + 4, 'HTTP POST multipart/related with an MMS PDU part (m-delivery-ind)'))
    # WSP over UDP 9200: reply with content type 0x3E (mms-message), and with an unknown content type (heuristic)
    def wsp_reply(tid, ctype, body, sport):
        p = bytes([tid, 0x04, 0x80]) + uintvar(len(ctype)) + ctype + body
        return eth(ip(17, udp(CL, SV, sport, 9200, p), CL, SV), ETH_CL, ETH_SV)
    pk.append(wsp_reply(1, b'\xbe', pdu(0x84, TID, V11, DATE, FROM, TO, H(0x96, estr_charset('wsp content type'))), 40000))
    marks.append((len(pk), 'WSP connectionless reply, content type mms-message (WINA 0x3E)'))
    pk.append(wsp_reply(2, text('application/x-unknown'), pdu(0x82, TID, V11, H(0x83, text('http://mms.example.net/m9'))), 40001))
    marks.append((len(pk), 'WSP connectionless reply, unknown content type: MMSE found by the heuristic'))
    pk.append(wsp_reply(3, text('application/x-unknown'), pdu(0x86, V10, MID, TO), 40002))
    marks.append((len(pk), 'WSP reply, heuristic: delivery-ind with MMS version header third'))
    pk.append(wsp_reply(4, text('application/x-unknown'), bytes([0x8C, 0x99, 0x98]) + text('t'), 40003))
    marks.append((len(pk), 'WSP reply, heuristic: unknown message type (rejected, shown as data)'))
    pk.append(wsp_reply(5, text('application/x-unknown'), bytes([0x8B, 0x80, 0x98]) + text('t'), 40004))
    marks.append((len(pk), 'WSP reply, heuristic: first octet is not the message type header (rejected)'))
    pk.append(wsp_reply(6, text('application/x-unknown'), bytes([0x8C, 0x80, 0x85]) + longint(1), 40005))
    marks.append((len(pk), 'WSP reply, heuristic: third octet neither transaction id nor version (rejected)'))
    pcap(os.path.join(out, 'mmse-coverage.pcap'), pk)
    if verbose:
        for n, l in marks:
            print(n, l)
        print(len(pk), 'frames')

    # ------------------------------------------------------ malformed
    pk, marks = [], []
    bad = []
    def b(label, body): bad.append((label, body))
    b('truncated header value: Transaction ID without terminator', bytes([0x8C, 0x80, 0x98]) + b'abc')
    b('Message-Type only', bytes([0x8C, 0x80]))
    b('truncated: Date long integer cut short', bytes([0x8C, 0x80, 0x98]) + text('t') + bytes([0x85, 4, 0, 1]))
    b('value-length beyond the end (From)', bytes([0x8C, 0x80, 0x98]) + text('t') + bytes([0x89, 30, 0x80]))
    b('uintvar length too long', bytes([0x8C, 0x80, 0x98]) + text('t') + bytes([0x89, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]))
    b('oversized uintvar in a general-form value', bytes([0x8C, 0x80, 0x98]) + text('t') + bytes([0xA3, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0, 0]))
    b('Delete-conf Content-Location with an oversized uintvar', bytes([0x8C, 0x92, 0x98]) + text('t') + bytes([0x83, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]))
    b('Encoded string: value-length longer than the data', bytes([0x8C, 0x80, 0x98]) + text('t') + bytes([0x96, 20, 0xEA]) + b'ab')
    b('Previously-Sent-By cut short', bytes([0x8C, 0x87, 0x98]) + text('t') + bytes([0xA0, 2, 0x81]))
    b('Content-Type header at the very end', bytes([0x8C, 0x80, 0x98]) + text('t') + bytes([0x84]))
    b('literal header without value', bytes([0x8C, 0x80, 0x98]) + text('t') + text('X-Name'))
    b('well-known header at the end', bytes([0x8C, 0x80, 0x98]) + text('t') + bytes([0xA2]))
    b('multipart count larger than the data', bytes([0x8C, 0x80, 0x98]) + text('t') + bytes([0x84, 0xa3, 5, 1, 1, 0x83, 0x41]))
    b('delivery time cut short', bytes([0x8C, 0x80, 0x98]) + text('t') + bytes([0x87, 3, 0x80, 1]))
    pairs = [((MMS, body), (MMS, pdu(0x81, TID, V10, H(0x92, b'\x80')))) for _, body in bad]
    fr = http_conn(pairs, sport=42000)
    pk += fr
    for k, (lab, _) in enumerate(bad):
        marks.append((4 + 2 * k, lab))
    pcap(os.path.join(out, 'mmse-coverage-malformed.pcap'), pk)
    if verbose:
        for n, l in marks:
            print('M', n, l)
        print(len(pk), 'malformed frames')

main()
