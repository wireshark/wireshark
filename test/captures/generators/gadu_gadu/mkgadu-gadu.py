# Generates test/captures/gadu_gadu_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# shared helpers (copied into each generator)
import struct
import socket

def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            orig = len(fr)
            if isinstance(fr, tuple):      # (captured bytes, original length)
                fr, orig = fr
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(fr), orig))
            f.write(fr)

def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def pcapng(path, idbs, frames):
    """idbs: list of linktypes; frames: list of (idb index, bytes)"""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in idbs:
        out += _blk(1, struct.pack('<HHI', lt, 0, 65535))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(path, 'wb').write(out)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def udp(sp, dp, payload):
    return struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload

def eth(dst, src, et, payload):
    return dst + src + struct.pack('>H', et) + payload

def tcpseg(src, dst, sp, dp, seq, ack, flags, payload=b'', ident=1, win=65535):
    """Ethernet/IPv4/TCP segment with correct checksums."""
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
    if flags == 0x02:
        ack = 0
    h = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, win, 0, 0)
    h = h[:20] + opts
    ps = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 6, len(h) + len(payload))
    c = csum(ps + h + payload)
    h = h[:16] + struct.pack('>H', c) + h[18:]
    return eth(bytes.fromhex('020000000002'), bytes.fromhex('020000000001'), 0x0800,
               ip4(src, dst, 6, h + payload, ident))

class Flow:
    """One TCP connection; client = 10.0.0.1, server = 10.0.0.2."""
    def __init__(self, cport, sport, frames, cip='10.0.0.1', sip='10.0.0.2', cseq=1000, sseq=5000):
        self.c, self.s, self.cp, self.sp, self.f = cip, sip, cport, sport, frames
        self.cseq, self.sseq = cseq, sseq
    def _send(self, from_client, flags, data=b''):
        if from_client:
            fr = tcpseg(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, flags, data)
            self.cseq += len(data) + (1 if flags & 3 else 0)
        else:
            fr = tcpseg(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, flags, data)
            self.sseq += len(data) + (1 if flags & 3 else 0)
        self.f.append(fr)
    def open(self):
        self._send(True, 0x02)
        self._send(False, 0x12)
        self._send(True, 0x10)
    def c2s(self, data): self._send(True, 0x18, data)
    def s2c(self, data): self._send(False, 0x18, data)
    def ack_c(self): self._send(True, 0x10)
    def ack_s(self): self._send(False, 0x10)
    def fin_s(self, data=b''): self._send(False, 0x19, data)
    def fin_c(self): self._send(True, 0x11)
    def close(self):
        self.fin_s(); self.fin_c(); self.ack_s()
import sys
import os
import zlib

def u32(*v): return struct.pack('<%dI' % len(v), *v)
def pdu(t, body=b''): return u32(t, len(body)) + body
def stz(s): return s + b'\0'
def u8str(s): return u32(len(s)) + s

XML_LIST = b'<?xml version="1.0" encoding="UTF-8"?><ContactBook><Groups><Group><Id>1</Id><Name>Friends</Name></Group></Groups><Contacts><Contact><Guid>a</Guid><GGNumber>1234</GGNumber></Contact></Contacts></ContactBook>'

def hashblock(t, extra=False):
    if t == 1:
        h = b'\x11\x22\x33\x44' + (b'\x01' * 60 if extra else b'\0' * 60)
    elif t == 2:
        h = bytes(range(20)) + (b'\x02' * 44 if extra else b'\0' * 44)
    else:
        h = bytes(range(64))
    return bytes([t]) + h

def user_data(users):
    b = u32(0, len(users))
    for uin, attrs in users:
        b += u32(uin, len(attrs))
        for name, typ, val in attrs:
            b += u32(len(name)) + name + u32(typ) + u32(len(val)) + val
    return b

def build(outdir):
    f = []
    SRV = 8074
    def sess(cport, **kw):
        fl = Flow(cport, SRV, f, **kw); fl.open(); return fl

    # --- session 1: protocol 8.0 / 10.x
    s = sess(40000)
    s.s2c(pdu(0x01, u32(0x12345678)))                                          # welcome
    s.c2s(pdu(0x31, u32(1234) + b'pl' + hashblock(2) + u32(0x02) + b'\0' * 12))  # login80, SHA1
    s.s2c(pdu(0x35, u32(1)))                                                   # login ok 80
    s.s2c(pdu(0x44, user_data([(1234, [(b'FirstName', 1, b'Jan'), (b'Nick', 1, b'jk')]), (5678, [])])))   # user data
    s.s2c(pdu(0x44, user_data([])))
    s.c2s(pdu(0x38, u32(0x02, 0) + u8str(b'my status')))                        # new status 80
    s.c2s(pdu(0x38, u32(0x04, 0) + u8str(b'')))
    s.c2s(pdu(0x78, b'\0\x04' + b'5678' + b'\x03' + b'\0\x04' + b'9999' + b'\x01'))   # notify105 (two contacts)
    s.c2s(pdu(0x7b, b'\0\x03' + b'111' + b'\x03'))                              # add notify 105
    s.c2s(pdu(0x7c, b'\0\x03' + b'111' + b'\x03'))                              # remove notify 105
    s.s2c(pdu(0x37, b'\x01\x02\x03\x04'))                                       # notify reply 80
    s.s2c(pdu(0x36, u32(5678, 0x02, 0) + b'\xc0\x00\x02\x05' + struct.pack('<HBBI', 1550, 0, 0, 0) + u8str(b'status description')))   # status 80 with description
    s.s2c(pdu(0x36, u32(5678, 0x01, 0) + b'\xc0\x00\x02\x05' + struct.pack('<HBBI', 1550, 0, 0, 0) + u8str(b'')))
    s.c2s(pdu(0x2d, u32(5678, 1, 0x08, 20, 40) + b'\0' * 20))                    # send message 80
    s.s2c(pdu(0x05, u32(2, 5678, 1)))                                          # message acknowledge
    s.s2c(pdu(0x2e, u32(5678, 2, 1700000000, 0x08, 20, 40) + b'\0' * 20))        # receive message 80
    s.c2s(pdu(0x46, u32(2)))                                                   # receive ack
    s.c2s(pdu(0x59, struct.pack('<HI', 1, 5678)))                              # typing
    s.s2c(pdu(0x59, struct.pack('<HI', 0, 5678)))
    s.c2s(pdu(0x23, u32(4))); s.s2c(pdu(0x23, u32(4) + b'\x01\x02\x03\x04\x05\x06\x07\x08'))   # dcc7 id request / reply
    s.c2s(pdu(0x20, b'\x01\x02\x03\x04\x05\x06\x07\x08' + u32(1234, 5678, 4) + stz(b'file.txt').ljust(255, b'\0')))   # dcc7 new
    s.c2s(pdu(0x25, b'\x01\x02\x03\x04\x05\x06\x07\x08' + u32(1234, 5678)))     # dcc7 abort
    z = zlib.compress(XML_LIST)
    s.c2s(pdu(0x2f, b'\x00' + z)); s.c2s(pdu(0x2f, b'\x02'))                   # userlist request 80: put (xml), get
    s.s2c(pdu(0x30, b'\x06' + z)); s.s2c(pdu(0x30, b'\x00'))                   # reply: get, put
    s.s2c(pdu(0x30, b'\x06' + b'not zlib data'))                                # decompression fails
    s.c2s(pdu(0x40, b'\x00' + u32(7) + b'\x02\x01' + z))                       # userlist 10.0 request put, xml
    s.c2s(pdu(0x40, b'\x00' + u32(7) + b'\x01\x01' + b'classic list'))         # format not xml
    s.c2s(pdu(0x40, b'\x02' + u32(7) + b'\x02\x01'))                           # get
    s.s2c(pdu(0x41, b'\x06' + u32(8) + b'\x02\x01' + z))                       # userlist 10.0 reply get, xml
    s.s2c(pdu(0x41, b'\x06' + u32(8) + b'\x01\x01' + b'classic'))
    s.s2c(pdu(0x41, b'\x00' + u32(8) + b'\x02\x01'))
    s.s2c(pdu(0x5c, u32(9)))                                                   # userlist version
    s.c2s(pdu(0x14, b'\x03' + u32(77) + stz(b'FmNumber') + stz(b'1234') + stz(b'FmStatus') + stz(b'2')))   # pubdir request
    s.c2s(pdu(0x14, b'\x03' + u32(78)))
    s.s2c(pdu(0x0e, b'\x03' + u32(77) + stz(b'FmNumber') + stz(b'1234') + stz(b'FirstName') + stz(b'Jan')))   # pubdir reply
    s.s2c(pdu(0x0e, b'\x03' + u32(78)))
    s.s2c(pdu(0x2c, b'<?xml version="1.0"?><events><event id="1"><type>28</type></event></events>'))   # xml action
    s.c2s(pdu(0x08)); s.s2c(pdu(0x07))                                         # ping / pong
    s.s2c(pdu(0x0b))                                                           # disconnecting
    s.c2s(pdu(0x07))                                                           # pong (client): named, not dissected
    s.close()

    # --- session 2: protocol < 8.0
    o = sess(40001, cseq=2000, sseq=7000)
    o.s2c(pdu(0x01, u32(0xdeadbeef)))
    o.c2s(pdu(0x0c, u32(4321) + u32(0x11223344) + u32(0x02) + u32(0x2a) + bytes([192, 0, 2, 7]) + struct.pack('<H', 1550)))   # login (< 6.0), version 0x2a
    o.s2c(pdu(0x03, b'\0\0\0\0'))                                               # login ok
    o.c2s(pdu(0x12))                                                           # list empty
    o.c2s(pdu(0x0f, u32(100) + b'\x03' + u32(200) + b'\x01'))                   # notify first: two contacts
    o.c2s(pdu(0x10, u32(300) + b'\x03'))                                        # notify last
    o.c2s(pdu(0x0d, u32(400) + b'\x03')); o.c2s(pdu(0x0e, u32(400) + b'\x03'))   # add / remove
    o.c2s(pdu(0x02, u32(0x01))); o.c2s(pdu(0x02, u32(0x04) + stz(b'away')))     # new status without / with description
    o.c2s(pdu(0x02, u32(0x0100 | 0x15) + stz(b'x')))
    o.s2c(pdu(0x0f, u32(100) + b'\x02' + bytes([192, 0, 2, 9]) + struct.pack('<HBBB', 1550, 0x2a, 0, 0)))   # status 6.0 without description
    o.s2c(pdu(0x0f, u32(100 | 0x04000000) + b'\x04' + bytes([192, 0, 2, 9]) + struct.pack('<HBBB', 1550, 0x24, 0, 0) + stz(b'descr')))
    o.s2c(pdu(0x17, u32(200) + b'\x05' + bytes([192, 0, 2, 9]) + struct.pack('<HBBB', 1550, 0x2a, 0, 0) + u32(0) + stz(b'busy')))   # status 7.7
    o.s2c(pdu(0x17, u32(200 | 0x40000000) + b'\x01' + bytes([192, 0, 2, 9]) + struct.pack('<HBBB', 1550, 0x2a, 0, 0) + u32(0)))
    o.c2s(pdu(0x0b, u32(100, 1, 0x04) + stz(b'hello')))                         # send message
    o.s2c(pdu(0x05, u32(3, 100, 1)))
    o.s2c(pdu(0x0a, u32(100, 2, 1700000000, 0x04) + stz(b'hi there') + b'\x02\x01\x00'))   # receive message
    o.c2s(pdu(0x46, u32(2)))
    o.s2c(pdu(0x08)); o.c2s(pdu(0x08))                                         # ping from the server: named
    o.s2c(pdu(0x0d))                                                           # disconnect ack
    o.s2c(pdu(0x09))                                                           # login failed
    o.close()

    # --- session 3: login 7.0 with the other hash types, login failed 8.0
    p = sess(40002, cseq=3000, sseq=6000)
    for ht, extra in ((1, False), (1, True), (2, True), (3, False)):
        p.c2s(pdu(0x19, u32(1111 | 0x04000000 | 0x40000000) + hashblock(ht, extra) + u32(0x02, 0x2a) + b'\0' + bytes([10, 1, 2, 3]) + struct.pack('<H', 1550)))
    p.s2c(pdu(0x43, u32(1)))                                                   # login 8.0 failed
    p.close()

    # --- session 4: no login seen (no conversation data)
    n = sess(40003, cseq=4000, sseq=5000)
    n.s2c(pdu(0x0a, u32(100, 2, 1700000000, 0x04) + stz(b'no login')))
    n.s2c(pdu(0x2e, u32(100, 2, 1700000000, 0x08, 20, 40) + b'\0' * 20))
    n.c2s(pdu(0x0b, u32(100, 1, 0x04) + stz(b'x')))
    n.c2s(pdu(0x2d, u32(100, 1, 0x08, 20, 40) + b'\0' * 20))
    n.close()

    # --- session 5: packets with a name but no dissection, and unknown types
    u = sess(40004, cseq=5000, sseq=4000)
    for t in (0x02, 0x07, 0x08, 0x0c, 0x11, 0x14, 0x16, 0x18, 0x1f, 0x20, 0x21, 0x22, 0x25, 0x27, 0x2a, 0x2b, 0x5a, 0x5b, 0x99):
        u.s2c(pdu(t, b'\x01\x02\x03\x04\x05'))
    for t in (0x07, 0x13, 0x15, 0x16, 0x1f, 0x21, 0x22, 0x24, 0x28, 0x29, 0x62, 0x63, 0x83, 0x99):
        u.c2s(pdu(t, b'\x01\x02\x03\x04\x05'))
    u.close()

    # --- session 6: reassembly
    r = sess(40005, cseq=6000, sseq=3000)
    m = pdu(0x0a, u32(100, 2, 1700000000, 0x04) + stz(b'a message over three segments'))
    r.s2c(m[:5]); r.s2c(m[5:20]); r.s2c(m[20:])
    r.s2c(pdu(0x07) + pdu(0x0b) + pdu(0x0d))                                    # three PDUs in one segment
    m = pdu(0x0b, u32(100, 1, 0x04) + stz(b'client message'))
    r.c2s(m + pdu(0x08)[:4]); r.c2s(pdu(0x08)[4:])                              # PDU, then a split header
    r.close()

    # --- session 7: the reproducers of the fix: text without the terminating NUL
    t = sess(40006, cseq=7000, sseq=2000)
    t.s2c(pdu(0x0a, u32(1234, 1, 0x5f000000, 4) + b'hello world'))              # message text without NUL
    t.s2c(pdu(0x36, u32(1234, 4, 0) + b'\xc0\x00\x02\x05' + struct.pack('<HBBI', 1550, 0, 0, 0) + u32(5) + b'hello'))   # status 80 description
    t.s2c(pdu(0x0f, u32(100) + b'\x04' + bytes([192, 0, 2, 9]) + struct.pack('<HBBB', 1550, 0x24, 0, 0) + b'no terminator'))
    t.c2s(pdu(0x0b, u32(100, 1, 0x04) + b'unterminated'))
    t.c2s(pdu(0x02, u32(0x05) + b'unterminated status'))
    t.close()

    # --- frames from and to port 8074: not Gadu-Gadu
    f.append(tcpseg('10.0.0.1', '10.0.0.2', 8074, 8074, 100, 1, 0x18, pdu(0x08)))
    f.append(tcpseg('10.0.0.1', '10.0.0.2', 8074, 8074, 100 + 8, 1, 0x18, pdu(0x08), ident=2))
    pcap(os.path.join(outdir, 'gadu-gadu-coverage.pcap'), f)

    # --- malformed
    mm = []
    def one(cport, from_server, body, cseq=1000, sseq=1000):
        x = Flow(cport, SRV, mm, cseq=cseq, sseq=sseq); x.open()
        (x.s2c if from_server else x.c2s)(body)
        x.close()
    one(41000, True, pdu(0x44, user_data([(1, [(b'N', 1, b'v')])]))[:-3])          # user data cut short
    one(41001, True, pdu(0x44, u32(0, 5)))                                        # five users announced, none present
    one(41002, True, pdu(0x0a, u32(1, 2, 3)))                                     # receive message cut short
    one(41003, True, pdu(0x36, u32(1, 2, 3) + b'\0' * 8))                          # status 80 cut short
    one(41004, True, pdu(0x36, u32(1234, 4, 0) + b'\xc0\x00\x02\x05' + struct.pack('<HBBI', 1550, 0, 0, 0) + u32(1000) + b'x'))   # description longer than the PDU
    one(41005, False, pdu(0x38, u32(2, 0) + u32(0xfffffff0) + b'abc'))            # new status 80: huge length
    one(41006, False, pdu(0x78, b'\0\x40' + b'short'))                            # notify105: uin longer than the PDU
    one(41007, False, pdu(0x31, u32(1, 0)))                                       # login 80 cut short
    one(41008, False, pdu(0x19, u32(1) + b'\x01' + b'\0' * 10))                   # login 70 cut short
    one(41009, False, pdu(0x20, b'\1' * 8 + u32(1, 2, 4) + b'name'))             # dcc7 new cut short
    one(41010, True, pdu(0x0e, b'\x03' + u32(1) + b'unterminated field'))         # pubdir reply without NUL
    one(41011, False, pdu(0x14, b'\x03' + u32(1) + b'unterminated field'))
    one(41012, False, pdu(0x2f, b'\x00'))                                          # userlist put without data
    one(41013, True, pdu(0x2c, b'<not xml'))                                       # broken XML action
    one(41014, True, pdu(0x01, b'\x01'))                                           # welcome cut short
    one(41015, False, pdu(0x0b, u32(1, 2)))                                        # send message cut short
    one(41016, True, u32(0x08, 0xfffffff0) + b'abc')                               # length of 4 GiB: waits for more
    one(41017, False, u32(0x08, 3) + b'ab')                                        # PDU shorter than announced
    one(41018, True, pdu(0x0f, u32(1) + b'\x04'))                                  # status 60 cut short
    one(41019, True, pdu(0x17, u32(1) + b'\x04' + b'\0' * 10))                     # status 77 cut short
    one(41020, True, pdu(0x2e, u32(1, 2, 3)))                                      # receive message 80 cut short
    one(41021, False, pdu(0x2d, u32(1, 2)))                                        # send message 80 cut short
    one(41022, True, pdu(0x05, u32(1, 2)))                                         # message ack cut short
    one(41023, False, pdu(0x46))                                                    # receive ack cut short
    one(41024, False, pdu(0x59, b'\x01'))                                           # typing cut short
    one(41025, True, pdu(0x41, b'\x06'))                                            # userlist reply 100 cut short
    one(41026, False, pdu(0x40, b'\x00'))                                           # userlist request 100 cut short
    one(41027, True, pdu(0x30))                                                     # userlist reply 80 without type
    one(41028, True, pdu(0x23, u32(4) + b'\1\2'))                                   # dcc7 id reply cut short
    one(41029, False, pdu(0x25, b'\1' * 8))                                         # dcc7 abort cut short
    one(41030, False, pdu(0x0f, u32(1) + b'\x03'))                                  # notify first: 1 octet after the uin
    one(41031, False, pdu(0x0d, u32(1)))                                            # add notify cut short
    one(41032, False, pdu(0x7b, b'\0\x03' + b'11'))                                 # add notify 105 cut short
    one(41033, False, pdu(0x0c, u32(1, 2, 3)))                                      # login cut short
    one(41034, False, pdu(0x02))                                                     # new status without status
    pcap(os.path.join(outdir, 'gadu-gadu-coverage-malformed.pcap'), mm)

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
