#!/usr/bin/env python3
# Generates test/captures/imf_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the IMF coverage captures (synthetic traffic only).
Usage: mkimf.py <outdir> [-v]"""
import base64
# ---- helpers (synthetic traffic only; documentation addresses) ----
import struct
import sys
import os

def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def _ip4(a):
    return bytes(int(x) for x in a.split('.'))

_ETH = bytes.fromhex('020000000002') + bytes.fromhex('020000000001')

def eth_ip(src, dst, proto, seg, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(seg), ident, 0x4000, 64, proto, 0, _ip4(src), _ip4(dst))
    h = h[:10] + struct.pack('!H', _csum(h)) + h[12:]
    return _ETH + b'\x08\x00' + h + seg

def tcp(src, dst, sport, dport, seq, ack, payload, flags=0x18):
    opt = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''
    hdr = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt
    pseudo = _ip4(src) + _ip4(dst) + struct.pack('!BBH', 0, 6, len(hdr) + len(payload))
    hdr = hdr[:16] + struct.pack('!H', _csum(pseudo + hdr + payload)) + hdr[18:]
    return eth_ip(src, dst, 6, hdr + payload)

def udp(src, dst, sport, dport, payload):
    seg = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth_ip(src, dst, 17, seg)

class Tcp:
    """One TCP connection; send() appends a data frame from the client
    ('c') or the server ('s') and tracks the sequence numbers."""
    def __init__(self, frames, c, s, cport, sport, handshake=True):
        self.f, self.c, self.s, self.cp, self.sp = frames, c, s, cport, sport
        self.cseq, self.sseq = 1000, 5000
        if handshake:
            self.f.append(tcp(c, s, cport, sport, self.cseq, 0, b'', 0x02)); self.cseq += 1
            self.f.append(tcp(s, c, sport, cport, self.sseq, self.cseq, b'', 0x12)); self.sseq += 1
            self.f.append(tcp(c, s, cport, sport, self.cseq, self.sseq, b'', 0x10))
    def send(self, who, data):
        if who == 'c':
            self.f.append(tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, data))
            self.cseq += len(data)
        else:
            self.f.append(tcp(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, data))
            self.sseq += len(data)
    def fin(self):
        self.f.append(tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, b'', 0x11))

def write_pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            orig = len(fr)
            if isinstance(fr, tuple):
                fr, orig = fr
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(fr), orig))
            f.write(fr)

def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def write_pcapng(path, linktypes, frames):
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(path, 'wb').write(out)

def exp_tlv(tag, val):
    return struct.pack('!HH', tag, len(val)) + val

def exported_pdu(name, payload):
    return exp_tlv(12, name.encode()) + struct.pack('!HH', 0, 0) + payload

CL, SV = '192.0.2.10', '192.0.2.25'
LABELS = []
CRLF = b'\r\n'

def mark(frames, text):
    LABELS.append((len(frames) + 1, text))

def msg(*lines):
    return CRLF.join(lines) + CRLF

def smtp_open(frames, port=25, cport=41000):
    t = Tcp(frames, CL, SV, cport, port)
    t.send('s', b'220 mail.example.com ESMTP ready\r\n')
    t.send('c', b'EHLO client.example.com\r\n')
    t.send('s', b'250 mail.example.com\r\n')
    t.send('c', b'MAIL FROM:<alice@example.com>\r\n')
    t.send('s', b'250 OK\r\n')
    t.send('c', b'RCPT TO:<bob@example.com>\r\n')
    t.send('s', b'250 OK\r\n')
    return t

def smtp_data(t, body):
    """DATA command, 354, the message in one segment, 250."""
    t.send('c', b'DATA\r\n')
    t.send('s', b'354 go ahead\r\n')
    t.send('c', body + b'.\r\n')
    t.send('s', b'250 queued\r\n')

def ess_label():
    oid = b'\x06\x03\x2a\x03\x04'
    inner = oid + b'\x02\x01\x05' + b'\x13\x04mark'
    return base64.b64encode(b'\x31' + bytes([len(inner)]) + inner).decode()

def x411_label():
    inner = b'\x06\x03\x2a\x03\x04' + b'\x02\x01\x03'
    return base64.b64encode(b'\x31' + bytes([len(inner)]) + inner).decode()

FULL = msg(
    b'Date: Fri, 06 Nov 2026 10:00:00 +1000',
    b'From: Alice Example <alice@example.com>, bob@example.com, "Carol, C." <carol@example.com>',
    b'Sender: Alice <alice@example.com>',
    b'Reply-To: team: a@example.com, Bob <b@example.com>;, empty: ;',
    b'To: Bob <bob@example.com>, dave@example.com, Group: erin@example.com,',
    b'  Frank <frank@example.com>;',
    b'Cc: <noname@example.com>, Gina <gina@example.com',
    b'Bcc: hidden@example.com',
    b'Message-ID: <m1@example.com>',
    b'In-Reply-To: <m0@example.com>',
    b'References: <m-1@example.com> <m0@example.com>',
    b'Subject: A subject that is folded',
    b'\tover two lines',
    b'Comments: some comment',
    b'User-Agent: synthetic/1.0',
    b'Keywords: one, two',
    b'Resent-Date: Fri, 06 Nov 2026 11:00:00 +1000',
    b'Resent-From: Alice <alice@example.com>',
    b'Resent-Sender: Alice <alice@example.com>',
    b'Resent-To: bob@example.com',
    b'Resent-Cc: carol@example.com',
    b'Resent-Bcc: dave@example.com',
    b'Resent-Message-ID: <r1@example.com>',
    b'Return-Path: <alice@example.com>',
    b'Received: from client.example.com by mail.example.com; Fri, 06 Nov 2026 10:00:01 +1000',
    b'MIME-Version: 1.0',
    b'Content-ID: <c1@example.com>',
    b'Content-Description: a description',
    b'Content-Transfer-Encoding: 7bit',
    b'Autoforwarded: false',
    b'Autosubmitted: no',
    b'X400-Content-Identifier: abc',
    b'Content-Language: en',
    b'Conversion: Prohibited',
    b'Conversion-With-Loss: Prohibited',
    b'Delivery-Date: Fri, 06 Nov 2026 10:00:02 +1000',
    b'Discarded-X400-IPMS-Extensions: none',
    b'Discarded-X400-MTS-Extensions: none',
    b'DL-Expansion-History: list',
    b'Deferred-Delivery: Fri, 06 Nov 2026 12:00:00 +1000',
    b'Expires: Sat, 07 Nov 2026 10:00:00 +1000',
    b'Importance: high',
    b'Incomplete-Copy: x',
    b'Latest-Delivery-Time: Sat, 07 Nov 2026 10:00:00 +1000',
    b'Message-Type: Delivery Report',
    b'Original-Encoded-Information-Types: IA5',
    b'Originator-Return-Address: <alice@example.com>',
    b'Priority: urgent',
    b'Reply-By: Sat, 07 Nov 2026 10:00:00 +1000',
    b'Sensitivity: Personal',
    b'Supersedes: <m-2@example.com>',
    b'X400-Content-Type: P2-1988',
    b'X400-MTS-Identifier: id',
    b'X400-Originator: alice@example.com',
    b'X400-Received: by x400',
    b'X400-Recipients: bob@example.com',
    b'Delivered-To: bob@example.com',
    b'X-Mailer: synthetic mailer',
    b'Thread-Index: AcXXXX',
    b'Lines: 2',
    b'Precedence: bulk',
    b'X-MimeOLE: Produced By Synthetic',
    b'Expiry-Date: Sat, 07 Nov 2026 10:00:00 +1000',
    b'X-MS-TNEF-Correlator: 000',
    b'X-UIDL: 1234',
    b'X-Authentication-Warning: none',
    b'X-Virus-Scanned: clean',
    b'X-Original-To: bob@example.com, carol@example.com',
    b'X-Unknown-Extension: an unknown header',
    b'Empty-Value:',
    b'',
    b'First line of the body',
    b'  indented line',
    b'')

def ct_msg(ct, body, extra=()):
    return msg(b'From: Alice <alice@example.com>', b'Subject: ' + ct[:30], b'MIME-Version: 1.0',
               b'Content-Type:' + ct, *extra, b'', body)

MULTI = msg(
    b'From: Alice <alice@example.com>', b'To: bob@example.com', b'Subject: multipart',
    b'MIME-Version: 1.0', b'Content-Type:multipart/mixed; boundary="BB";;', b'',
    b'--BB', b'Content-Type: text/plain; charset=us-ascii', b'', b'Hello part',
    b'--BB', b'Content-Type: message/rfc822', b'',
    b'From: inner@example.com', b'Subject: inner message', b'', b'inner body',
    b'--BB', b'Content-Type: application/octet-stream', b'Content-Transfer-Encoding: base64', b'',
    b'AAECAwQF',
    b'--BB--', b'')

def sio(*items, eol=True):
    return msg(b'From: Alice <alice@example.com>', b'sio-label: ' + b'; '.join(items), b'', b'body') if eol else None

def main():
    out = sys.argv[1]
    frames, fx = [], []
    # ---- SMTP (TCP 25): the messages ----
    t = smtp_open(frames)
    mark(frames, 'SMTP 25: full header set, nested message, content types')
    smtp_data(t, FULL)
    smtp_data(t, MULTI)
    smtp_data(t, ct_msg(b'text/plain; charset=utf-8', b'SGVsbG8gd29ybGQ=\r\n', [b'Content-Transfer-Encoding: base64']))
    smtp_data(t, ct_msg(b'text/plain; charset=utf-8; format=flowed', b'plain text\r\n'))
    smtp_data(t, ct_msg(b'text/plain', b'content type without parameters\r\n'))
    smtp_data(t, ct_msg(b'text/html;\r\n\tcharset="utf-8"', b'<p>html</p>\r\n'))
    smtp_data(t, ct_msg(b'application/x-unknown; name=x', b'unknown media type\r\n'))
    smtp_data(t, ct_msg(b'message/rfc822; x=y', msg(b'From: n@example.com', b'Subject: nested', b'', b'nested body')))
    smtp_data(t, msg(b'From: Alice <alice@example.com>', b'Subject: no body', b'', ))
    # "Content-Type: " with a space: the type keeps the blank and is not dispatched (README)
    smtp_data(t, msg(b'From: Alice <alice@example.com>', b'Content-Type: text/plain; charset=us-ascii', b'', b'a space after the colon'))
    # three nested levels
    inner = msg(b'Subject: level 3', b'', b'innermost')
    for lv in (2, 1):
        inner = msg(b'Subject: level %d' % lv, b'Content-Type:message/rfc822; x=y', b'', inner)
    smtp_data(t, inner)
    smtp_data(t, msg(b'Subject: mailbox forms', b'From: Alice <>, <a@b', b'To: <>, :x@example.com', b'Sender: <a@b.c>', b'', b'x'))
    mark(frames, 'SMTP 25: sio-label')
    LBL = ess_label()
    half = len(LBL) // 2
    smtp_data(t, sio(b'marking="SECRET"', b'fgcolor=red', b'bgcolor=blue'))
    smtp_data(t, sio(b'marking = "TOP SECRET"', b'type=":ess"', b'label="' + LBL.encode() + b'"'))
    smtp_data(t, sio(b'type=":ess"', b'label*0="' + LBL[:half].encode() + b'"', b'label*1="' + LBL[half:].encode() + b'"'))
    smtp_data(t, sio(b'type=":x411"', b'label="' + x411_label().encode() + b'"'))
    smtp_data(t, sio(b'type=":other"', b'label="abc"', b'unknown=1', b'noequals', b'type="x"'))
    smtp_data(t, sio(b'marking="A"', b'type=":ess"', b'', b'fgcolor=', b'label=""', b'type=a', b'bgcolor= x '))
    t.send('c', b'QUIT\r\n')
    t.send('s', b'221 bye\r\n')
    # the reproducer of the quadratic scan, scaled down
    t = smtp_open(frames, cport=41001)
    mark(frames, 'SMTP 25: sio-label with 1500 items (scaled quadratic reproducer)')
    smtp_data(t, msg(b'sio-label: ' + b'a;' * 1500 + b'a', b'', b'body'))
    # ---- POP3 (TCP 110) ----
    t = Tcp(frames, CL, SV, 41002, 110)
    mark(frames, 'POP3 110: RETR')
    t.send('s', b'+OK POP3 ready\r\n')
    t.send('c', b'RETR 1\r\n')
    t.send('s', b'+OK 100 octets\r\n')
    t.send('s', MULTI + b'.\r\n')
    # ---- Exported PDU: input that SMTP does not hand over ----
    mark(fx, 'Exported PDU imf: edge cases')
    def ex(b):
        fx.append(exported_pdu('imf', b))
    ex(msg(b'From: Alice <alice@example.com>', b'sio-label: marking="SECRET"; fgcolor=red', b'', b'body'))   # the small fixes
    ex(b'no colon in this data\r\n')                       # no header at all
    ex(b'Subject: x\r\nFrom: a@b\r\n\r\n')                 # blank line, empty body
    ex(b'Subject: folded\r\n  once\r\n\tand twice\r\n\r\nbody\r\n')
    ex(b'X-Empty:    \r\n\r\nbody\r\n')                    # only blanks as the value
    write_pcapng(os.path.join(out, 'imf-coverage.pcapng'), [1, 252],
                 [(0, f) for f in frames] + [(1, f) for f in fx])
    n_main = len(frames) + len(fx)
    # ---- malformed capture ----
    fx = []
    mark(fx, 'MALFORMED capture (Exported PDU imf)')
    ex(b'Subject: x')                                      # no line end
    ex(b'Subject: x\r\n')                                  # only a header, no blank line
    ex(b'Content-Type: text/plain;\r\n\r\nbody\r\n')       # empty parameters
    ex(b'Content-Type: text/plain; charset=x\r\n')         # content type to the end
    ex(b'sio-label: type=":ess"; label="short"\r\n\r\nbody\r\n')   # not valid DER
    ex(b'sio-label: type=":x411"; label="short"\r\n\r\nbody\r\n')
    ex(msg(b'To: :a@example.com', b'', b'x'))              # group with an empty display name
    ex(msg(b'To: g:', b'', b'x'))                          # group at the end of the item
    ex(msg(b'sio-label: type="', b'', b'x')[:-3])
    ex(msg(b'sio-label: label*x=""; label*1="abcd"', b'', b'x'))
    ex(b'Subject: x\r\n\r')
    ex(b'Content-Type: a;b')
    ex(b'Content-Type: multipart/mixed; boundary=')
    ex(b'Subject:')
    ex(b':')
    write_pcapng(os.path.join(out, 'imf-coverage-malformed.pcapng'), [252], [(0, f) for f in fx])
    if '-v' in sys.argv:
        for n, s in LABELS:
            print(n, s)
        print('main frames', n_main)

main()
