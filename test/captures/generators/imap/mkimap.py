#!/usr/bin/env python3
# Generates test/captures/imap_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the IMAP coverage captures (synthetic traffic only).
Usage: mkimap.py <outdir> [-v]"""
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

CL, SV = '192.0.2.10', '192.0.2.20'
LABELS = []

def mark(frames, text):
    LABELS.append((len(frames) + 1, text))

def clienthello():
    body = (b'\x03\x03' + bytes(range(32)) + b'\x00' + b'\x00\x02\x00\x2f' + b'\x01\x00')
    hs = b'\x01' + struct.pack('!I', len(body))[1:] + body
    return b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs

MSG = (b'From: Alice <alice@example.com>\r\nTo: bob@example.com\r\n'
       b'Subject: hi\r\n\r\nHello\r\n')

def main():
    out = sys.argv[1]
    frames = []
    # ---- stream 1: a full session on TCP 143 ----
    t = Tcp(frames, CL, SV, 40001, 143)
    mark(frames, 'session 1 (143): greeting, capability, LOGIN variants')
    t.send('s', b'* OK IMAP4rev1 ready\r\n')
    t.send('c', b'a001 CAPABILITY\r\n')
    t.send('s', b'* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK done\r\n')
    # the reproducer of the LOGIN fix, unquoted and quoted password
    t.send('c', b'a002 LOGIN alice secret\r\n')
    t.send('s', b'a002 OK [CAPABILITY IMAP4rev1] Logged in\r\n')
    t.send('c', b'a003 LOGIN bob "pw"\r\n')
    t.send('s', b'a003 NO login failed\r\n')
    t.send('c', b'a004 LOGIN carol x\r\n')            # 1 octet password
    t.send('s', b'a004 BAD\r\n')
    t.send('c', b'a005 LOGIN dave\r\n')               # no password
    t.send('s', b'a005 BAD missing\r\n')
    t.send('c', b'a006 LOGIN eve ""\r\n')              # empty quoted password
    t.send('s', b'a006 NO\r\n')
    mark(frames, 'folder commands')
    for i, cmd in enumerate([b'SELECT INBOX', b'EXAMINE Drafts', b'CREATE Archive',
                             b'DELETE Old', b'RENAME Old New', b'SUBSCRIBE Lists',
                             b'UNSUBSCRIBE Lists', b'STATUS INBOX (MESSAGES)',
                             b'APPEND Sent (\\Seen) {5}', b'SEARCH ALL', b'NOOP',
                             b'LIST "" *', b'CLOSE', b'LOGOUT'], 10):
        tag = b'b%03d' % i
        t.send('c', tag + b' ' + cmd + b'\r\n')
        t.send('s', b'* 3 EXISTS\r\n' + tag + b' OK done\r\n')
    mark(frames, 'COPY (reproducer), UID commands, odd lines')
    t.send('c', b'c001 COPY 1:2 Archive\r\n')         # the COPY fix
    t.send('s', b'c001 OK copied\r\n')
    t.send('c', b'c002 COPY 3\r\n')                    # COPY without folder
    t.send('s', b'c002 OK\r\n')
    t.send('c', b'c003 UID COPY 5 Archive\r\n')
    t.send('s', b'c003 OK\r\n')
    t.send('c', b'c004 UID FETCH 1:* (FLAGS)\r\n')
    t.send('s', b'* 1 FETCH (UID 1 FLAGS (\\Seen))\r\n* 2 FETCH (UID 2 FLAGS ())\r\nc004 OK done\r\n')
    t.send('c', b'c005 UID\r\n')                       # UID without a command
    t.send('s', b'c005 BAD\r\n')
    t.send('c', b'c006\r\n')                           # tag only
    t.send('s', b'c006\r\n')
    t.send('c', b'\r\n')                               # empty line
    t.send('s', b'* \r\n')                             # '*' without tokens
    t.send('s', b'* OK\r\n')                           # one token
    t.send('c', b'c007 STARTTLS \r\n')
    mark(frames, 'STARTTLS OK and the TLS ClientHello that follows')
    t.send('s', b'c007 OK Begin TLS negotiation now\r\n')
    t.send('c', clienthello())
    # ---- stream 2: FETCH with a literal (IMF), in one frame ----
    t = Tcp(frames, CL, SV, 40002, 143)
    mark(frames, 'session 2: FETCH with literals, IMF, reassembly')
    t.send('s', b'* OK ready\r\n')
    t.send('c', b'd001 FETCH 1 BODY[]\r\n')
    t.send('s', b'* 1 FETCH (BODY[] {%d}\r\n' % len(MSG) + MSG + b')\r\nd001 OK done\r\n')
    # a literal over three segments: the line, part of the message, the rest
    t.send('c', b'd002 FETCH 2 BODY[]\r\n')
    full = b'* 2 FETCH (BODY[] {%d}\r\n' % len(MSG) + MSG + b')\r\n'
    t.send('s', full[:9])                              # no line end yet
    t.send('s', full[9:40])                            # line complete, literal missing
    t.send('s', full[40:70])
    t.send('s', full[70:] + b'd002 OK done\r\n')
    # FETCH where the closing ')' is missing, then it arrives
    t.send('c', b'd003 FETCH 3 BODY[]\r\n')
    t.send('s', b'* 3 FETCH (BODY[] {%d}\r\n' % len(MSG) + MSG)
    t.send('s', b')\r\nd003 OK done\r\n')
    # FETCH line with no '(' yet, then the rest
    t.send('c', b'd004 FETCH 4 FLAGS\r\n')
    t.send('s', b'* 4 FETCH\r\n')
    t.send('s', b'(FLAGS (\\Seen))\r\n')
    t.send('s', b'd004 OK done\r\n')
    # a sio-label message (the IMF fix), delivered as a literal
    sio = (b'From: Alice <alice@example.com>\r\n'
           b'sio-label: marking="SECRET"; fgcolor=red\r\n\r\nbody\r\n')
    t.send('c', b'd009 FETCH 11 BODY[]\r\n')
    t.send('s', b'* 11 FETCH (BODY[] {%d}\r\n' % len(sio) + sio + b')\r\nd009 OK done\r\n')
    t.fin()
    # ---- stream 3: starts with a TLS ClientHello (heuristic) ----
    t = Tcp(frames, CL, SV, 40003, 143)
    mark(frames, 'session 3: TLS on port 143 from the first frame (heuristic)')
    t.send('c', clienthello())
    t.send('s', b'\x16\x03\x03\x00\x04\x0e\x00\x00\x00')
    # ---- stream 4: the greeting is the STARTTLS OK, TLS follows later ----
    t = Tcp(frames, CL, SV, 40004, 143)
    mark(frames, 'session 4: IMAP text, then TLS (second heuristic try)')
    t.send('s', b'* OK ready\r\n')
    t.send('c', clienthello())
    # ---- stream 5: server first sends a continuation, a response w/o tag ----
    t = Tcp(frames, CL, SV, 40005, 143)
    mark(frames, 'session 5: untagged only, response with a status, retransmitted tag')
    t.send('c', b'f001 NOOP\r\n')
    t.send('c', b'f001 NOOP\r\n')                       # same tag again (second request)
    t.send('s', b'f001 OK\r\n')
    t.send('s', b'+ continue\r\n')
    t.send('s', b'* 1 EXISTS\r\n* 2 RECENT\r\n')        # only * lines: first line shown in Info
    t.send('c', b'f002 select inbox\r\n')               # lower case command
    t.send('s', b'f002 OK\r\n')
    t.send('c', b'f003 LOGIN\r\n')                      # LOGIN with no arguments
    t.send('s', b'f003 BAD\r\n')
    # a request that has trailing space after the command
    t.send('c', b'f004 SELECT \r\n')
    t.send('s', b'f004 OK\r\n')
    # a later line that is cut in the middle: reassembled
    t.send('s', b'* 7 EXISTS\r\n* 8 RECE')
    t.send('s', b'NT\r\n')
    # ---- stream 6: the first segment has fewer than 5 octets (heuristic) ----
    t = Tcp(frames, CL, SV, 40006, 143)
    mark(frames, 'session 6: first segments shorter than the heuristic length')
    t.send('s', b'\r\n')
    t.send('c', b'h1\r\n')
    t.send('s', b'h1 OK\r\n')
    write_pcap(os.path.join(out, 'imap-coverage.pcap'), frames)
    n_main = len(frames)

    # ---- malformed capture: IMAP data that makes dissect_imap throw ----
    frames = []
    t = Tcp(frames, CL, SV, 41001, 143)
    mark(frames, 'MALFORMED capture: LOGIN without arguments, quote only, unterminated line')
    t.send('c', b'g001 LOGIN alice\r\n')
    t.send('c', b'g002 LOGIN "\r\n')
    t.send('s', b'g002 BAD')                            # no line end, never completes
    # FETCH responses that never complete: each in its own connection,
    # because the reassembly swallows the rest of the stream
    for i, resp in enumerate([
            b'* 5 FETCH (BODY[] {x}\r\nh005 OK done\r\n',      # size is not a number
            b'* 6 FETCH (BODY[] {99999}\r\nh006 OK done\r\n',  # size larger than the data
            b'* 7 FETCH (BODY[] {5\r\nh007 OK done\r\n',       # no closing brace
            b'* 8 FETCH (BODY[] {5}\r\nabcde\r\nh008 OK done\r\n',  # no ')' after the literal
            b'* 9 EXISTS FETCH\r\n',                            # no '(' at all
            b'* 10 FETCH (\r\n',                                # '(' and nothing after it
            b'* 11 FETCH (BODY[] {}\r\n',                       # empty size
            b'* 12 FETCH ({3}\r\nabc',                          # literal without ')'
            b'* 1 FETCH\r\n']):
        t = Tcp(frames, CL, SV, 41010 + i, 143)
        mark(frames, 'MALFORMED: FETCH that never completes %d' % (i + 1))
        t.send('s', resp)
    write_pcap(os.path.join(out, 'imap-coverage-malformed.pcap'), frames)
    if '-v' in sys.argv:
        for n, s in LABELS:
            print(n, s)
        print('main frames', n_main, 'malformed frames', len(frames))

main()
