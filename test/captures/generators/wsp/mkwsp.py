#!/usr/bin/env python3
# Generates test/captures/wsp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic WSP captures (connectionless on UDP 9200 and 2948, connection
oriented inside WTP on UDP 9201).
Usage: mkwsp.py <outdir>.  Everything is built with struct."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
import w12pcap

def uv(v):
    out = [v & 0x7f]; v >>= 7
    while v:
        out.append(0x80 | (v & 0x7f)); v >>= 7
    return bytes(reversed(out))
def si(v): return bytes([0x80 | v])                      # short integer
def li(v):                                               # long integer
    n = max(1, (v.bit_length() + 7) // 8)
    return bytes([n]) + v.to_bytes(n, 'big')
def tx(s): return s.encode() + b'\0'                     # text string
def vl(data):                                            # value length + data
    return (bytes([len(data)]) if len(data) < 31 else b'\x1f' + uv(len(data))) + data
def qv(q): return uv(q)                                  # Q-value (1..1099)

# ---------------------------------------------------------------- parameters
PARAMS = {
    'q': b'\x80' + qv(81), 'q3': b'\x80' + qv(901),
    'charset': b'\x81\x84', 'charset_long': b'\x81' + li(106),
    'level': b'\x82\x91', 'level_text': b'\x82' + tx('1.3'),
    'type': b'\x83\x85', 'type_long': b'\x83\x01\x07',
    'name': b'\x85' + tx('file.txt'),
    'name_v': b'\x97' + tx('nam'), 'name_vq': b'\x97' + b'"quoted\0', 'name_vqq': b'\x97' + b'"quoted"\0',
    'filename': b'\x86' + tx('f.bin'), 'filename_v': b'\x98' + tx('f2.bin'),
    'type_text': b'\x89' + tx('text/x-foo'), 'type_short': b'\x89\x83',
    'start': b'\x8a' + tx('<s>'), 'start_v': b'\x99' + tx('<s2>'),
    'startinfo': b'\x8b' + tx('si'), 'startinfo_v': b'\x9a' + tx('si2'),
    'comment': b'\x8c' + tx('c'), 'comment_v': b'\x9b' + tx('c2'),
    'domain': b'\x8d' + tx('example.com'), 'domain_v': b'\x9c' + tx('example.org'),
    'path': b'\x8f' + tx('/p'), 'path_v': b'\x9d' + tx('/q'),
    'sec': b'\x91\x82', 'mac': b'\x92' + tx('abcd'),
    'size': b'\x96\x01\x20', 'size_short': b'\x96\x8a',
    'untyped': tx('foo') + tx('bar'), 'untyped_q': tx('foo') + b'"bar\0',
    'untyped_qq': tx('foo') + b'"bar"\0', 'untyped_int': tx('foo') + b'\x85',
}
# parameters that make the parser skip to the end of the buffer (last one only)
SKIPPERS = {'differences': b'\x87\x01', 'padding': b'\x88\x82', 'maxage': b'\x8e\x85',
            'secure': b'\x90', 'cdate': b'\x93\x04\x00\x00\x00\x01', 'mdate': b'\x94\x04\x00\x00\x00\x02',
            'rdate': b'\x95\x04\x00\x00\x00\x03', 'unknown': b'\x9f\x01'}
ALLP = b''.join(PARAMS.values())

# ------------------------------------------------------------ header values
DATE = b'\x04\x38\x00\x00\x00'        # long integer, 4 octets
DATE1 = b'\x01\x10'
def ctype_forms():
    """Content-type-value / Accept-value forms."""
    return [si(3), tx('text/x-test'), tx(''),
            vl(tx('image/png') + PARAMS['q'] + PARAMS['charset']),
            vl(si(0x14) + ALLP),
            vl(b'\x01\x08' + PARAMS['name'] + PARAMS['untyped']),
            vl(tx('text/html') + SKIPPERS['padding'])]
def accept_x_q(sample):
    return [si(sample), tx('tok'), vl(tx('tok') + qv(81)), vl(si(sample) + qv(101)), vl(b'\x01' + bytes([sample]) + qv(5))]
CRED_BASIC = vl(b'\x80' + tx('user') + tx('pw'))
CRED_TOKEN = vl(tx('Digest') + tx('realm') + tx('"r') + tx('nonce') + b'\x85')
CHAL_BASIC = vl(b'\x80' + tx('realm1'))
CHAL_TOKEN = vl(tx('Digest') + tx('realm2') + tx('nonce') + tx('n1') + tx('qop') + tx('auth'))

def text_forms(): return [tx('value'), tx('')]
H = {   # header id -> list of valid value forms
    0x00: ctype_forms(),
    0x01: accept_x_q(0x04),
    0x02: [si(0), si(1), si(2), si(3), tx('br'), vl(si(0) + qv(81)), vl(si(1)), vl(si(2) + qv(7)), vl(si(3)), vl(tx('x-gzip') + qv(5))],
    0x03: accept_x_q(0x05),
    0x04: [si(0), si(1), tx('other')],
    0x05: [si(5), li(300)],
    0x06: [si(0x40), si(0x41), si(0x60)],
    0x07: [CRED_BASIC, CRED_TOKEN],
    0x08: [si(0), si(1), si(2), si(9), si(0x0b), tx('ext'),
           vl(si(0) + si(0x25) + tx('x-field')), vl(si(7) + si(0x25)),
           vl(si(2) + si(30)), vl(si(3) + li(300)), vl(si(4) + si(9)), vl(si(0x0b) + si(9)),
           vl(tx('tok') + si(3)), vl(tx('tok') + li(7)), vl(tx('tok') + tx('text')),
           vl(b'x"quoted\0'), vl(b'x"quoted"\0'), vl(si(6)), vl(si(0x30) + si(1))],
    0x09: [si(0), tx('keep-alive')],
    0x0a: text_forms(), 0x0b: [si(0), si(1), si(2), tx('br')],
    0x0c: [si(5), tx('en'), vl(b'\x01\x05')],
    0x0d: [si(7), li(300)],
    0x0e: text_forms(),
    0x0f: [vl(bytes(range(16)))],
    0x10: [vl(uv(100) + uv(300)), vl(uv(100) + b'\x80')],
    0x11: ctype_forms(),
    0x12: [DATE], 0x13: text_forms(), 0x14: [DATE], 0x15: text_forms(), 0x16: text_forms(),
    0x17: [DATE], 0x18: text_forms(), 0x19: text_forms(),
    0x1a: [tx('"etag"'), DATE],
    0x1b: [DATE], 0x1c: text_forms(), 0x1d: [DATE],
    0x1e: [si(5), b'\x01\x20'],
    0x1f: [si(0), vl(tx('cache') + tx('x'))],
    0x20: [CHAL_BASIC, CHAL_TOKEN],
    0x21: [CRED_BASIC, CRED_TOKEN],
    0x22: [si(0x40), si(0x60), tx('PROPFIND')],
    0x23: [vl(b'\x80\x05\x0a'), vl(b'\x80\x05'), vl(b'\x81\x14')],
    0x24: text_forms(), 0x25: [si(5), tx('v'), vl(b'\x01\x02')],
    0x26: text_forms(), 0x27: [si(0), tx('gzip')],
    0x28: text_forms(), 0x29: text_forms(),
    0x2a: [si(0x13), tx('Accept'), si(1)],
    0x2b: text_forms(),
    0x2c: [si(10), si(99), vl(si(10) + tx('agent') + tx('stale text')), vl(si(14) + tx('a') + tx('t')), vl(si(99) + tx('a') + tx('t'))],
    0x2d: [CHAL_BASIC, CHAL_TOKEN],
    0x2e: [vl(si(0)), vl(si(1) + PARAMS['filename']), vl(si(2) + ALLP), vl(tx('custom') + PARAMS['name'])],
    0x2f: [si(2), si(0x1a), tx('x-wap-application:foo'), vl(b'\x01\x02'), vl(b'\x02\x80\x01')],
    0x30: text_forms(), 0x31: text_forms(),
    0x32: [si(4), tx('x-wap-application:bar'), vl(b'\x01\x03')],
    0x33: [si(0), si(1), si(0x0b), si(0x7e), vl(b'\x01\x03')],
    0x34: [si(0), si(1), si(2), si(3), si(4), si(7), si(0x10)],
    0x35: text_forms(),
    0x36: [vl(b'\x03\x01\x6a\x00')],
    0x37: [si(0x10), si(0x23), vl(si(0x10) + tx('http://ex/') + DATE1 + DATE1), vl(si(0x22) + tx('http://ex/'))],
    0x38: [si(1), tx('d'), vl(b'\x01\x01')],
    0x39: [si(1), vl(tx('trailers')), vl(si(2)), vl(si(3) + b'\x00')],
    0x3a: [si(3), tx('ETag'), vl(b'\x01\x03')],
    0x3b: accept_x_q(0x05),
    0x3c: [si(0), vl(tx('x') + qv(5)), tx('z')],
    0x3d: [si(0), si(9), tx('ext')],
    0x3e: [vl(uv(7) + uv(40))],
    0x3f: [DATE, b'\x80', b'\x01\x00'],
    0x40: [tx('<cid@x>'), b'"<cid2@x>\0', b'"<cid3@x>"\0'],
    0x41: [si(2), tx('v'), vl(b'\x01\x02')], 0x42: [si(2), tx('v'), vl(b'\x01\x02')],
    0x43: [si(0x11), tx('1.1'), vl(si(5) + si(0x12)), vl(si(2) + tx('1.2')), vl(si(1))],
    0x44: [si(0x11), vl(si(0x12) + tx('http://p/') + DATE1)],
    0x45: [vl(si(0)), vl(si(1))],
    0x46: [si(0)],
    0x47: [si(0), si(1), tx('foo')],
}
for i in range(0x48, 0x80):
    H[i] = [si(1), tx('v'), vl(b'\x01\x02')]
# Openwave header code page entries 0x00-0x22 (+ a couple of unregistered)
OW_INT = [si(1), li(300)]
OW_TEXT = [tx('v')]
OW = {0x01: ctype_forms(), 0x02: OW_INT, 0x03: OW_INT, 0x04: OW_TEXT, 0x05: OW_TEXT, 0x06: OW_INT,
      0x07: OW_INT, 0x08: OW_INT, 0x09: OW_INT, 0x0a: OW_INT, 0x0b: OW_INT, 0x0c: OW_INT, 0x0d: OW_INT,
      0x0e: OW_INT, 0x0f: OW_TEXT, 0x10: [DATE, b'\x80'], 0x11: OW_INT, 0x12: OW_TEXT, 0x13: OW_INT,
      0x14: OW_TEXT, 0x15: OW_INT, 0x16: accept_x_q(0x04), 0x17: OW_INT, 0x19: OW_INT, 0x1a: OW_INT,
      0x20: OW_INT, 0x21: OW_TEXT, 0x22: OW_INT}
for i in (0x00, 0x18, 0x1b, 0x23, 0x40):
    OW[i] = [si(1), tx('v'), vl(b'\x01\x02')]

def hdr(i, forms): return b''.join(bytes([0x80 | i]) + f for f in forms)

# ---------------------------------------------------------------- WSP PDUs
MMS = b'\x8c\x81\x8d\x90\x98x\0\x92\x80'
def tcp(payload, sport, dport, seq, src='192.0.2.1', dst='192.0.2.2'):
    import socket
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 0x50, 0x18, 8192, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(t), 2, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack('!H', w12pcap.csum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + t
def smpp_submit(wsp, seqno=1, ports=(0x0b84, 0x23f0)):
    udh = bytes([6, 5, 4]) + struct.pack('>HH', *ports)
    sm = udh + wsp
    body = (b'\0' + bytes([1, 1]) + b'12345\0' + bytes([1, 1]) + b'67890\0' + bytes([0x40, 0, 0]) + b'\0' + b'\0'
            + bytes([0, 0, 4, 0, len(sm)]) + sm)
    return struct.pack('>IIII', 16 + len(body), 4, 0, seqno) + body
def tid(n): return bytes([n & 0xff])
def get(uri, headers=b'', pdu=0x40): return bytes([pdu]) + uv(len(uri)) + uri + headers
def post(uri, ctype, headers, data, pdu=0x60):
    return bytes([pdu]) + uv(len(uri)) + uv(len(ctype) + len(headers)) + uri + ctype + headers + data
def reply(status, ctype, headers=b'', data=b''):
    return b'\x04' + bytes([status]) + uv(len(ctype) + len(headers)) + ctype + headers + data
def push(ctype, headers=b'', data=b'', pdu=0x06):
    return bytes([pdu]) + uv(len(ctype) + len(headers)) + ctype + headers + data
def connect(caps=b'', headers=b'', ver=0x10):
    return bytes([1, ver]) + uv(len(caps)) + uv(len(headers)) + caps + headers
def connect_reply(sid, caps=b'', headers=b''):
    return b'\x02' + uv(sid) + uv(len(caps)) + uv(len(headers)) + caps + headers
def resume(sid, caps=b'', headers=b''):
    return b'\x09' + uv(sid) + uv(len(caps)) + caps + headers
def cap(ident, value): return uv(len(ident) + len(value)) + ident + value
def cap_text(name, value):
    """Textual capability names are read from the length octet on, so the
    name only matches when the length octet is its first character."""
    first = ord(name[0])
    body = name[1:].encode() + b'\0' + b'\0' + value
    body += bytes(first - len(body))
    assert len(body) == first, name
    return bytes([first]) + body

def wtp_invoke(tidn, payload, cls=2):
    return bytes([0x0a]) + struct.pack('>H', tidn) + bytes([0x20 | cls]) + payload
def wtp_result(tidn, payload):
    return bytes([0x12]) + struct.pack('>H', tidn | 0x8000) + payload

def main_frames():
    f = []
    def cl(p, port=9200, n=1, **kw): f.append(w12pcap.udp(tid(n) + p, sport=1024, dport=port, **kw))
    def co(p, n=1, reply_=False):
        if reply_:
            f.append(w12pcap.udp(wtp_result(0x300 + n, p), sport=9201, dport=1024, src='192.0.2.2', dst='192.0.2.1'))
        else:
            f.append(w12pcap.udp(wtp_invoke(0x300 + n, p), sport=1024, dport=9201))
    # --- sessions: Connect (with capabilities), ConnectReply, Disconnect, Suspend, Resume
    caps = (cap(b'\x80', uv(1400)) + cap(b'\x81', uv(1400)) + cap(b'\x82', b'\xf8')
            + cap(b'\x83', b'\x03') + cap(b'\x84', b'\x04')
            + cap(b'\x85', b'\x40' + tx('PROPFIND')) + cap(b'\x86', b'\x01' + tx('page1') + b'\x02' + tx('page2'))
            + cap(b'\x87', b'\x81\x01\x02') + cap(b'\x88', uv(65536)) + cap(b'\x89', uv(65536)))
    co(connect(caps, hdr(0x11, [si(3)]) + hdr(0x29, [tx('ua')])), 1)
    co(connect_reply(0x1234, cap(b'\x80', uv(1400)) + cap(b'\x85', b'\x40\x41') + cap(b'\x86', b'\x01\x02'),
                     hdr(0x26, [tx('srv')])), 1, True)
    co(connect(b'', b''), 2)
    co(connect_reply(5), 2, True)
    # textual capability names (the dissector reads them from the length octet)
    tcaps = b''.join(cap_text(n, v) for n, v in (
        ('client-sdu-size', uv(1400)), ('server-sdu-size', uv(1400)), ('method-mor', b'\x03'),
        ('push-mor', b'\x04'), ('extended methods', b''), ('header code pages', b''),
        ('aliases', b''), ('client-message-size', uv(70000)), ('server-message-size', uv(70000))))
    co(connect(tcaps + cap_text('protocol options', b'\xf8') + cap_text('xtra-capability', b'\x01')), 3)
    co(connect(cap(b'\x82', b'\x0a') + cap(b'\x83', b'\x03'), ver=0x11), 4)
    cl(connect(caps), n=2)
    cl(b'\x05' + uv(0x1234), n=3)                 # disconnect
    co(b'\x05' + uv(0x1234), 5)
    co(b'\x08' + uv(0x1234), 6)                   # suspend
    co(resume(0x1234, cap(b'\x80', uv(1400)), hdr(0x11, [si(3)])), 7)
    co(resume(0x1234), 8)
    # --- GET and friends with all headers (one PDU per header id)
    for i in range(0x80):
        for k, form in enumerate(H[i]):
            cl(get(b'http://example.com/h%d_%d' % (i, k), hdr(i, [form])), n=i)
    # ids 0x48-0x7f are 'default' headers; also textual headers and old style X-Wap-Tod
    cl(get(b'http://example.com/text', tx('X-Custom') + tx('value') + tx('x-other') + tx('v2')), n=1)
    cl(get(b'http://example.com/oldtod', tx('x-wap.tod') + DATE), n=2)
    cl(get(b'http://example.com/oldtod0', tx('x-wap.tod') + b'\x01\x00'), n=3)
    # --- Openwave header code page (page 0x10 by shorthand, 0x7f xx long form)
    for i in sorted(OW):
        for k, form in enumerate(OW[i]):
            cl(get(b'http://example.com/ow%d_%d' % (i, k), b'\x10' + hdr(i, [form]) + b'\x7f\x01' + hdr(0x05, [si(1)])), n=i)
    cl(get(b'http://example.com/ow2', b'\x7f\x10' + hdr(0x01, ctype_forms()) + b'\x01' + hdr(0x0d, [si(1)])), n=4)
    # --- methods: Options/Head/Delete/Trace, extended get (0x50-0x5f), Put, extended post, Post
    cl(get(b'http://example.com/nohdr'), n=1)
    for pdu in (0x41, 0x42, 0x43, 0x44, 0x50, 0x5f):
        cl(get(b'http://example.com/m', hdr(0x29, [tx('x')]), pdu=pdu), n=pdu)
    form = b'a=1&b=two&c=&d'
    ct = si(0x12)
    for pdu in (0x60, 0x61, 0x70, 0x7f):
        cl(post(b'http://example.com/post', ct, hdr(0x0d, [li(len(form))]) + hdr(0x29, [tx('x')]), form, pdu=pdu), n=pdu)
    cl(post(b'http://example.com/post0', b'', b'', b''), n=1)        # headers length 0
    cl(post(b'http://example.com/ph', si(3), b'', b'plain text data'), n=2)     # media text/plain
    cl(post(b'http://example.com/pt', tx('text/x-unknown'), hdr(0x29, [tx('x')]), b'\x01\x02\x03'), n=3)
    cl(post(b'http://example.com/pl', vl(tx('text/html') + PARAMS['charset']), b'', b'<html></html>'), n=4)
    # --- Replies with all status codes, content types, and data for subdissectors
    for st in (0x10, 0x11, 0x12, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x30, 0x31, 0x32, 0x33, 0x34,
               0x35, 0x36, 0x37, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
               0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x60, 0x61, 0x62, 0x63,
               0x64, 0x65, 0x66, 0x7f):
        co(reply(st, si(3), hdr(0x0d, [li(5)]), b'hello'), st, True)
    co(reply(0x20, b'\x00'), 1, True)                       # headers length 0 -> see below
    co(b'\x04\x20\x00', 2, True)                            # no headers at all
    for ctid, data in ((0x02, b'<html>x</html>'), (0x03, b'text'), (0x08, b'<wml/>'), (0x14, b'\x03\x01\x6a\x00'),
                       (0x1d, b'GIF89a'), (0x1e, b'\xff\xd8\xff'), (0x1f, b'\x89PNG'), (0x29, b'\x03\x01\x6a\x00'),
                       (0x3e, MMS), (0x22, b'\x00')):
        co(reply(0x20, si(ctid), hdr(0x0d, [li(len(data))]), data), 0x40 + ctid, True)
    # content-type forms in a reply (textual, with parameters)
    co(reply(0x20, tx('text/x-foo'), b'', b'abc'), 0x70, True)
    co(reply(0x20, vl(tx('text/plain') + PARAMS['charset'] + PARAMS['name']), b'', b'abc'), 0x71, True)
    co(reply(0x20, vl(si(3) + ALLP), b'', b'abc'), 0x72, True)
    # --- Push, ConfirmedPush: SIR version 0 and 1, CoAP, plain data
    sir0 = b'\x00' + uv(2) + hdr(0x2f, [si(1)]) + uv(7) + b'\x80\x00\x00\x08' + b''
    sir_addr = lambda: bytes([0xc4, 0x00]) + b'\x01\xbb' + b'\xc0\xa8\x01\x01'  # ipv4 bearer+port... placeholder
    sia_hdrs = hdr(0x2f, [si(1)])
    wsp_contacts = bytes([0xc4, 0x00]) + struct.pack('>H', 9201) + bytes([192, 0, 2, 1])
    wsp_contacts += b''
    sir0 = b'\x00' + uv(len(sia_hdrs)) + sia_hdrs + uv(len(wsp_contacts)) + wsp_contacts
    other = bytes([0x44, 0x0b]) + struct.pack('>H', 9200)[:2] + bytes([10, 0, 0, 1])   # port, bearer GPRS
    other = bytes([0xc4, 0x0b]) + struct.pack('>H', 9200) + bytes([10, 0, 0, 1])
    v6 = bytes([0xd0, 0x01]) + struct.pack('>H', 9201) + bytes(range(16))
    unk = bytes([0x83, 0x77, 1, 2, 3]) + bytes([0x42]) + b'\x12\x34' + b'\x01\x02' + bytes([0x82, 0xaa, 0xbb])
    unk = bytes([0x83, 0x77, 1, 2, 3]) + bytes([0x82, 0xaa, 0xbb, 0xcc]) + bytes([0x43, 0x12, 0x34, 9, 8, 7])
    nobearer = bytes([0x05]) + b'\x01\x02\x03\x04\x05'
    sir1 = (b'\x01' + uv(len(sia_hdrs)) + sia_hdrs + uv(len(wsp_contacts + v6)) + wsp_contacts + v6
            + uv(len(other + unk + nobearer)) + other + unk + nobearer
            + uv(2) + uv(0) + uv(1) + uv(len(b'http://prov/')) + b'http://prov/' + uv(2) + b'\x01\x02\x03\x04' + b'\x05\x06\x07\x08')
    sir_odd = (b'\x00' + uv(0) + uv(0))                   # no application ids, no contact points
    sir_odd2 = (b'\x01' + uv(len(sia_hdrs)) + sia_hdrs + uv(9) + bytes([0x83, 0x00]) + b'\x01\x02\x03' + bytes([0x82, 0x01]) + b'\x01\x02'
                + uv(0) + uv(0) + uv(0) + uv(0))
    ctsia = si(0x34)
    cl(push(ctsia, b'', sir_odd), port=2948, n=4)
    cl(push(ctsia, b'', sir_odd2), port=2948, n=5)
    cl(push(ctsia, b'', sir0), port=2948, n=1)
    cl(push(ctsia, b'', sir1), port=2948, n=2)
    cl(push(tx('application/vnd.wap.sia'), b'', sir1), n=3)
    co(push(ctsia, b'', sir0, pdu=0x07), 9)
    cl(push(si(3), hdr(0x34, [si(1)]) + hdr(0x2f, [si(2)]), b'push text data'), n=4, port=2948)
    cl(push(si(0x3e), hdr(0x2f, [si(4)]), MMS, pdu=0x07), n=5, port=2948)
    # MMS messages whose content type is a multipart type or form data
    # (WSP add_post_data and add_multipart_data, called from the MMSE dissector)
    def part(ct, hdrs, data): return uv(len(ct) + len(hdrs)) + uv(len(data)) + ct + hdrs + data
    mmsh = b'\x8c\x80\x98x\0\x8d\x90\x84'
    inner = part(b'\x00', b'', b'empty type') + part(si(3), b'', b'part one') + part(si(0x3e), b'', MMS) + part(tx('text/x-foo'), hdr(0x0d, [li(3)]), b'abc')
    mp = uv(4) + inner
    cl(push(si(0x3e), b'', mmsh + si(0x23) + mp), port=2948, n=10)
    cl(push(si(0x3e), b'', mmsh + si(0x33) + uv(1) + part(si(2), b'', b'<p>')), port=2948, n=11)
    cl(push(si(0x3e), b'', mmsh + si(0x12) + b'a=1&b=two&c=&d&e=5'), port=2948, n=12)
    cl(push(si(0x3e), b'', mmsh + si(0x12) + b'&=x&z='), port=2948, n=13)
    cl(push(si(0x3e), b'', mmsh + si(0x22) + uv(0)), port=2948, n=14)
    cl(push(si(0x3e), b'', mmsh + si(0x24) + uv(1) + part(vl(tx('text/plain') + PARAMS['charset']), hdr(0x29, [tx('x')]), b'x')), port=2948, n=15)
    # CoAP: second to last byte 0xAF, last byte 0x9A, content type of one octet
    coap = b'\x40\x01\x12\x34\xb1\x30'
    cl(push(si(5), b'\xaf\x9a', coap), n=6)
    cl(push(si(3), b'', b''), n=7)
    cl(push(b'\x00', b'', b'x'), n=8)      # empty textual content type
    cl(post(b'http://example.com/pe', b'\x00', b'', b'x'), n=9)
    cl(b'\x06\x00', n=9)                   # Push with headers length 0
    # --- Redirects (conversation set up for the redirected address)
    red4 = bytes([0x03, 0x80]) + bytes([0xc4, 0x00]) + struct.pack('>H', 7777) + bytes([192, 0, 2, 77])
    def srv(p): f.append(w12pcap.udp(tid(1) + p, sport=9200, dport=1024, src='192.0.2.2', dst='192.0.2.1'))
    srv(red4)
    f.append(w12pcap.udp(tid(1) + get(b'http://example.com/redir', hdr(0x29, [tx('x')])), sport=1024, dport=7777, src='192.0.2.1', dst='192.0.2.77'))
    red6 = (bytes([0x03, 0x40]) + bytes([0xd0, 0x01]) + struct.pack('>H', 7778) + bytes(range(1, 17))
            + bytes([0x44, 0x00]) + struct.pack('>H', 7779) + bytes([203, 0, 113, 5])[:4]
            + bytes([0x00]) + bytes([0x41, 0x05]) + b'\x01\x02\x03\x04'    # no bearer/no addr; unknown bearer
            + bytes([0x84]) + bytes([0x09]) + b'\x01\x02\x03\x04' + bytes([0x42]) + b'\x01\x02' + b'\x07\xaa')
    red_odd = (bytes([0x03, 0x00]) + bytes([0x83, 0x00]) + b'\x01\x02\x03'      # IPv4 with a 3 octet address
               + bytes([0x82, 0x01]) + b'\x01\x02')                        # IPv6 with a 2 octet address
    srv(red_odd)
    srv(red6)
    red_co = bytes([0x03, 0x80]) + bytes([0xc4, 0x00]) + struct.pack('>H', 7780) + bytes([192, 0, 2, 78])
    co(red_co, 10, True)
    f.append(w12pcap.udp(wtp_invoke(0x400, get(b'http://example.com/redir2')), sport=1024, dport=7780, src='192.0.2.1', dst='192.0.2.78'))
    # --- unknown PDU type; PDU type 0 reserved
    cl(b'\x20\x00\x01', n=1)
    cl(b'\xff', n=2)
    # --- bug reproducers of the branch: Q-value 0 (invalid, shown as such) and the
    #     SEC parameter (value byte at the right offset)
    cl(get(b'http://example.com/q0', hdr(0x00, [vl(si(3) + b'\x80' + qv(0))])), n=7)
    cl(get(b'http://example.com/sec', hdr(0x00, [vl(si(3) + b'\x91\x83')])), n=8)
    return f


def malformed_frames():
    f = []
    def cl(p, port=9200, n=1): f.append(w12pcap.udp(tid(n) + p, sport=1024, dport=port))
    def co(p, n=1): f.append(w12pcap.udp(wtp_invoke(0x500 + n, p), sport=1024, dport=9201))
    def g(h, n=1): cl(get(b'http://e/', h), n=n)
    # --- generic invalid forms for every header (well-known id), both code pages
    generic = [si(0x7e), si(0x05), tx('v'), vl(b'\x03abc'), b'\x01\x05', b'\x05' + b'abcde',
               b'\x1f\x02ab', b'\x1e' + bytes(30)]
    for i in range(0x80):
        for k, form in enumerate(generic):
            g(hdr(i, [form]), n=i)
    for i in range(0x23):
        for k, form in enumerate(generic):
            g(b'\x10' + hdr(i, [form]), n=i)
    # --- invalid forms of specific headers
    g(hdr(0x00, [vl(b'\x20')]))                        # content type value that is neither text nor integer
    g(hdr(0x00, [vl(b'\x01')]))
    g(hdr(0x00, [vl(b'\x05abcd')]))                    # integer with 5 octets
    g(hdr(0x08, [vl(si(0) + b'\x01')]))                # cache-control no-cache with a non text field name
    g(hdr(0x08, [vl(si(3) + b'\x05abcde')]))
    g(hdr(0x08, [vl(b'\x05')]))
    g(hdr(0x2c, [vl(si(10) + tx('a'))]))
    g(hdr(0x2c, [vl(si(10))]))
    g(hdr(0x2c, [vl(si(7) + tx('a') + tx('b'))]))
    g(hdr(0x37, [vl(si(0x10) + b'\x01')]))
    g(hdr(0x07, [vl(b'\x80' + b'\x05')]))
    g(hdr(0x07, [vl(b'\x80' + tx('u') + b'\x05')]))
    g(hdr(0x07, [vl(b'\x05abc')]))
    g(hdr(0x20, [vl(b'\x80' + b'\x05')]))
    g(hdr(0x20, [vl(b'\x05abc')]))
    g(hdr(0x20, [vl(tx('Digest') + b'\x05')]))
    g(hdr(0x23, [vl(b'\x80')]))
    g(hdr(0x23, [vl(b'\x80\x85\x86\x87\x88\x89')]))
    g(hdr(0x23, [vl(b'\x81\x89\x89\x89\x89\x89')]))
    g(hdr(0x10, [vl(b'\x89\x89\x89\x89\x89\x89')]))
    g(hdr(0x10, [vl(uv(4) + b'\x89\x89\x89\x89\x89\x89')]))
    g(hdr(0x43, [vl(b'\x80\x05')]))
    g(hdr(0x43, [vl(b'\x05')]))
    g(hdr(0x39, [vl(tx('te') + qv(5))]))
    g(hdr(0x39, [vl(si(2) + b'\x80')]))
    g(hdr(0x2e, [vl(b'\x05abcd')]))
    g(hdr(0x02, [vl(b'\x05abcd')]))
    g(hdr(0x01, [vl(b'\x05abcd')]))
    g(hdr(0x01, [vl(si(5) + b'\x89\x89\x89\x89\x89\x89')]))
    # --- invalid parameters in a content type (one frame each)
    bad_params = [b'\x05', b'\x80' + qv(0), b'\x80' + qv(1100), b'\x80\xff\xff\xff\xff\x7f',
                  b'\x81\x05abcde', b'\x83\x05abcde', b'\x85\x05', b'\x97\x05', b'\x86\x05', b'\x98\x05',
                  b'\x89\x05', b'\x8a\x05', b'\x99\x05', b'\x8b\x05', b'\x9a\x05', b'\x8c\x05', b'\x9b\x05',
                  b'\x8d\x05', b'\x9c\x05', b'\x8f\x05', b'\x9d\x05', b'\x91\x05', b'\x92\x05', b'\x82\x05',
                  b'\x96\x05abcde', b'foo\0\x05abcde', b'\x05abcde']
    for p in bad_params:
        g(hdr(0x11, [vl(si(3) + p)]))
    for p in SKIPPERS.values():
        g(hdr(0x11, [vl(si(3) + p)]))
    # parameters in Content-Disposition / Accept-Encoding etc. end buffer
    # --- header structure errors
    g(b'\x00')                                          # zero-length textual header
    g(b'\x7f')                                          # code page shift without page
    g(tx('X-Test') + b'\x05abcde')                      # textual header with a non textual value
    g(tx('X-Test') + b'\x1f\x03abc')
    g(tx('X-Test') + b'\x1e' + bytes(30))
    g(tx('x-wap.tod') + b'\x05abcde')                   # old style tod, not a date
    g(tx('x-wap.tod') + b'\x03abc')
    g(tx('x-wap.tod') + b'\x1f\x02ab')
    g(tx('X-Test') + b'\x1f' + b'\xff\xff\xff\xff\xff')   # oversized uintvar
    g(hdr(0x00, [b'\x1f' + b'\xff\xff\xff\xff\xff\x7f']))
    g(b'\x80\x1f')                                    # header value cut
    g(b'\x80')
    g(hdr(0x2f, [b'\x04\x01']))                       # header value longer than the data
    # --- PDU level problems
    cl(b'\x01')                                         # connect cut
    cl(b'\x01\x10')
    cl(b'\x01\x10\x05')                               # capability length longer than the PDU
    cl(b'\x01\x10\xff\xff\xff\xff\x7f')
    cl(b'\x01\x10\x00\x09' + b'\x80\x01')              # header length longer than the data
    cl(b'\x01\x10\xff\xff\xff\xff\xff\xff')            # oversized uintvar
    cl(b'\x02')
    cl(b'\x09\x01\x02')
    cl(b'\x03')                                         # redirect without flags
    cl(b'\x03\x80\xc4\x00\x23')                      # redirect address cut
    cl(b'\x03\x80\xc4\x00\x23\x29\xc0\x00')
    cl(b'\x03\x80\xc4\x00\x23\x29\xc0\x00\x02')
    cl(b'\x05')
    cl(b'\x08')
    cl(b'\x04')
    cl(b'\x04\x20')
    cl(b'\x04\x20\x05\x03')                           # reply headers longer than the data
    cl(b'\x04\x20\x04\x03ab')
    cl(b'\x06')
    cl(b'\x06\x05\x03')
    cl(b'\x40')
    cl(b'\x40\x20http://too/short')
    cl(b'\x40\x05abc')
    cl(b'\x60')
    cl(b'\x60\x05\x07abc')
    cl(b'\x60\x01\x01a')
    cl(b'\x60\x01\x03a\x1f')
    cl(b'\x60\x01\x05a\x83\x80\x80\x80\x80')
    cl(post(b'http://e/', si(3), b'\x05abcde', b'x'))
    # --- capabilities
    def conn(caps): co(connect(caps), 1)
    conn(cap(b'\x05', b'\x01'))                         # invalid well-known id below 0x80
    conn(cap(b'\x8a', b'\x01'))                         # unknown well-known capability
    conn(cap(b'\x82', b'\xf8\x01'))                     # protocol options with two octets
    conn(cap(b'\x85', b'\x40'))                         # extended method without name
    conn(cap(b'\x85', b'\x40\x05'))
    conn(cap(b'\x86', b'\x01'))                         # header code page without name
    conn(cap(b'\x86', b'\x01\x05'))
    conn(uv(300) + b'\x80' + uv(5))                      # capability longer than all of them
    conn(b'\x00')
    conn(b'\xff\xff\xff\xff\xff\xff\x01')
    g(hdr(0x00, [vl(b'\x1f\x01\x02')]))
    conn(b'\x05\x80')
    conn(cap_text('xtra-capability', b'\x01'))
    conn(cap(b'\x80', b'\xff\xff\xff\xff\xff\x7f'))
    # --- SIR problems
    for sirdata in (b'', b'\x00', b'\x00\x09', b'\x00\x02\xaf\x81\x09\xc4', b'\x01\x00\x00\x00\x05\x00',
                    b'\x01\x00\x00\x00\x01\x00\x00\x05http', b'\x01\x00\x00\x00\x00\x00\x02\x01\x02\x03'):
        cl(push(si(0x34), b'', sirdata), port=2948)
    # --- multiple textual-header edge cases through WTP
    co(get(b'http://e/', hdr(0x00, [vl(si(3) + PARAMS['q'])]) + b'\x00'), 2)
    # WAP push over SMS: SMPP submit_sm with a UDH that has the WAP ports
    # (SMPP on TCP 2775 needs Decode As tcp.port==2775,smpp: the heuristic does
    # not claim it; gsm_sms_ud hands the message to WSP, to "wsp-cl" only with
    # the preference gsm_sms_ud.port_number_udh_means_wsp)
    seq = 1000
    for k, pdu in enumerate((tid(1) + push(si(3), hdr(0x34, [si(1)]), b'sms push'),
                             tid(2) + get(b'http://example.com/sms', hdr(0x29, [tx('x')])))):
        sp = smpp_submit(pdu, seqno=k + 1)
        f.append(tcp(sp, 40000, 2775, seq))
        seq += len(sp)
    return f

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    mf = main_frames()
    w12pcap.write(os.path.join(out, 'wsp-coverage.pcap'), mf)
    mal = malformed_frames()
    w12pcap.write(os.path.join(out, 'wsp-coverage-malformed.pcap'), mal)
    print(len(mf), 'main frames,', len(mal), 'malformed frames')
