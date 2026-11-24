#!/usr/bin/env python3
# Generates test/captures/ftp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the FTP coverage captures (Ethernet, IPv4 and IPv6, TCP).

ftp-coverage.pcap            control and data connections of many sessions
ftp-coverage-malformed.pcap  invalid PWD replies, truncated frames and other
                             paths that need malformed input
ftp-coverage-big.pcap        about 1.2 MB of file data in one transfer, for
                             the export.maxsize preference (not for the tree)

Usage: mkftp.py <outdir>
"""
import os
import struct
import sys

CIP = '192.0.2.1'
SIP = '192.0.2.2'
CIP6 = '2001:db8::1'
SIP6 = '2001:db8::2'

clock = [1700000000 * 1000000]


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def ip6(s):
    import socket
    return socket.inet_pton(socket.AF_INET6, s)


class Cap:
    def __init__(self):
        self.frames = []

    def add(self, data, snap=None, dt=1000):
        clock[0] += dt
        self.frames.append((clock[0], data, snap))

    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for ts, d, snap in self.frames:
                cap = d if snap is None else d[:snap]
                f.write(struct.pack('<IIII', ts // 1000000, ts % 1000000, len(cap), len(d)) + cap)


class Flow:
    """One TCP connection; c() is client to server, s() server to client."""

    def __init__(self, cap, cport, sport, cip=CIP, sip=SIP, v6=False):
        self.cap = cap
        self.v6 = v6
        if v6:
            cip, sip = (cip, sip) if ':' in cip else (CIP6, SIP6)
            self.ep = {0: [ip6(cip), cport, 1000], 1: [ip6(sip), sport, 5000]}
        else:
            self.ep = {0: [bytes(map(int, cip.split('.'))), cport, 1000],
                       1: [bytes(map(int, sip.split('.'))), sport, 5000]}

    def seg(self, d, payload, dt=1000, snap=None, flags=0x18):
        a, b = self.ep[d], self.ep[1 - d]
        if flags & 2:
            # SYN: no ACK number, MSS option
            tcp = struct.pack('!HHIIBBHHH', a[1], b[1], a[2], b[2] if flags & 0x10 else 0, 7 << 4, flags, 65535, 0, 0) \
                + b'\x02\x04\x05\xb4\x04\x02\x01\x01'
        else:
            tcp = struct.pack('!HHIIBBHHH', a[1], b[1], a[2], b[2], 5 << 4, flags, 65535, 0, 0)
        a[2] = (a[2] + len(payload)) & 0xffffffff
        if self.v6:
            ip = struct.pack('!IHBB16s16s', 0x60000000, len(tcp) + len(payload), 6, 64, a[0], b[0])
            eth = bytes([2, 0, 0, 0, 0, 2 - d]) + bytes([2, 0, 0, 0, 0, 1 + d]) + b'\x86\xdd'
        else:
            ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 1, 0, 64, 6, 0, a[0], b[0])
            ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
            eth = bytes([2, 0, 0, 0, 0, 2 - d]) + bytes([2, 0, 0, 0, 0, 1 + d]) + b'\x08\x00'
        self.cap.add(eth + ip + tcp + payload, snap=snap, dt=dt)

    def open(self):
        self.seg(0, b'', flags=0x02)
        self.ep[0][2] += 1
        self.seg(1, b'', flags=0x12)
        self.ep[1][2] += 1
        self.seg(0, b'', flags=0x10)

    def c(self, text, **kw):
        self.seg(0, text if isinstance(text, bytes) else text.encode() + b'\r\n', **kw)

    def s(self, text, **kw):
        self.seg(1, text if isinstance(text, bytes) else text.encode() + b'\r\n', **kw)


def raw(f, d, b, **kw):
    f.seg(d, b, **kw)


def pasv_text(ip, port):
    return '227 Entering Passive Mode (%s,%d,%d).' % (ip.replace('.', ','), port >> 8, port & 255)


def hello(server=False):
    """Plain TLS handshake messages (no key material is used)."""
    ext = struct.pack('!HH', 0, 0)
    if not server:
        body = struct.pack('!H', 0x0303) + bytes(range(32)) + b'\0' + struct.pack('!H', 4) + \
            struct.pack('!HH', 0x009c, 0x00ff) + b'\x01\0' + struct.pack('!H', len(ext)) + ext
        hs = b'\x01' + struct.pack('!I', len(body))[1:] + body
    else:
        body = struct.pack('!H', 0x0303) + bytes(range(32, 64)) + b'\0' + struct.pack('!HB', 0x009c, 0) + \
            struct.pack('!H', len(ext)) + ext
        hs = b'\x02' + struct.pack('!I', len(body))[1:] + body
    return b'\x16\x03\x03' + struct.pack('!H', len(hs)) + hs


def build_main(cap):
    # ---- Session 1 (IPv4): login, directory handling, all transfer methods
    f = Flow(cap, 40001, 21)
    f.open()
    f.s('220-Welcome to the test FTP server')
    f.s(' this line has no response code')
    f.s('220 Ready')
    f.c('USER anonymous')
    f.s('331 Please specify the password.')
    f.c('USER ignored')                       # second USER is not used for the credentials
    f.s('331 Still need the password.')
    f.c('PASS guest@example.com')
    f.s('230 Login successful.')
    f.c('SYST')
    f.s('215 UNIX Type: L8')
    f.c('FEAT')
    f.s('211-Features:\r\n MDTM\r\n SIZE\r\n UTF8\r\n211 End\r\n')
    f.c('PWD')
    f.s('257 "/" is the current directory')
    f.c('TYPE I')
    f.s('200 Switching to Binary mode.')
    # CWD / CDUP handling and the path normalisation
    for cmd, resp in (('CWD pub', '250 Directory successfully changed.'),
                      ('CWD ./docs//v1/', '250 ok'),
                      ('CWD sub', '250 ok'),
                      ('CWD ..', '250 ok'),
                      ('CDUP', '250 ok'),
                      ('CWD .', '250 ok'),
                      ('CWD ../../../..', '250 ok'),
                      ('CWD /srv/ftp', '250 ok'),
                      ('CWD a/./b/../c', '250 ok'),
                      ('CWD /', '250 ok'),
                      ('CWD data', '250 ok'),
                      ('CWD missing', '550 Failed to change directory.'),
                      ('DELE old.txt', '250 Delete operation successful.'),
                      ('CWD /srv/ftp/', '250 ok'),
                      ('CWD x', '250 ok')):
        f.c(cmd)
        f.s(resp)
    f.c('PWD')
    f.s('257 "/srv/ftp/x" is the current directory')
    f.c('PWD')
    f.s('257 "/a""b" created')
    f.c('MKD new')
    f.s('257 "/a""b/new" created')

    # PASV download (binary file)
    f.c('PASV')
    f.s(pasv_text(SIP, 5000))
    f.c('RETR file.bin')
    d = Flow(cap, 50001, 5000)
    d.open()
    f.s('150 Opening BINARY mode data connection for file.bin (3000 bytes).')
    for i in range(3):
        d.s(bytes((i + j) & 0xff for j in range(1000)), dt=50000)
    f.s('226 Transfer complete.')

    # PASV directory listing (text); NOOP first, then LIST replaces it
    f.c('PASV')
    f.s(pasv_text(SIP, 5001))
    f.c('NOOP')
    f.s('200 NOOP ok.')
    f.c('LIST')
    d = Flow(cap, 50002, 5001)
    d.open()
    f.s('150 Here comes the directory listing.')
    d.s(b'-rw-r--r--    1 ftp      ftp          3000 Jan 01 00:00 file.bin\r\n'
        b'drwxr-xr-x    2 ftp      ftp          4096 Jan 01 00:00 sub\r\n', dt=20000)
    f.s('226 Directory send OK.')

    # PASV through NAT: the address in the reply differs from the server
    f.c('PASV')
    f.s(pasv_text('198.51.100.7', 5002))
    f.c('RETR natted.txt')
    d = Flow(cap, 50003, 5002, sip='198.51.100.7')
    d.open()
    f.s('150 Opening data connection.')
    d.s(b'line one\r\nline two\r\n', dt=10000)
    d.s(b'line three\r\n', dt=0)
    f.s('226 Transfer complete.')

    # PASV upload (STOR) split in several frames with the same timestamp
    f.c('PASV')
    f.s(pasv_text(SIP, 5003))
    f.c('STOR upload.txt')
    d = Flow(cap, 50004, 5003)
    d.open()
    f.s('150 Ok to send data.')
    d.c(b'first part of the upload\r\n', dt=5000)
    d.c(b'second part\r\n', dt=0)
    d.c(b'third part\r\n', dt=0)
    f.s('226 Transfer complete.')

    # NLST, MLSD, APPE, STOU
    for port, cmd, data in ((5004, 'NLST', b'file.bin\r\nsub\r\n'),
                            (5005, 'MLSD', b'type=file;size=3000; file.bin\r\n'),
                            (5006, 'APPE log.txt', b'appended\r\n'),
                            (5007, 'STOU', b'unique name upload\r\n')):
        f.c('PASV')
        f.s(pasv_text(SIP, port))
        f.c(cmd)
        d = Flow(cap, 50010 + port, port)
        d.open()
        f.s('150 Starting.')
        if cmd.startswith(('APPE', 'STOU')):
            d.c(data, dt=3000)
            d.c(data, dt=3000)
        else:
            d.s(data, dt=3000)
        f.s('226 Done.')
    # RETR / STOU without a file name (export object name "(MISSING)")
    for port, cmd in ((5008, 'RETR'), (5009, 'RETR ')):
        f.c('PASV')
        f.s(pasv_text(SIP, port))
        f.c(cmd)
        d = Flow(cap, 50010 + port, port)
        d.open()
        f.s('150 Starting.')
        d.s(b'nameless\r\n', dt=3000)
        f.s('226 Done.')
    # Active mode: PORT (client address) and PORT through NAT
    f.c('PORT 192,0,2,1,200,10')
    f.s('200 PORT command successful.')
    f.c('RETR active.txt')
    d = Flow(cap, 20, 51210, cip=SIP, sip=CIP)
    d.open()
    f.s('150 Opening data connection.')
    d.c(b'active mode data\r\n', dt=4000)
    f.s('226 Transfer complete.')
    f.c('PORT 198,51,100,9,200,11')
    f.s('200 PORT command successful.')
    f.c('LIST')
    d = Flow(cap, 20, 51211, cip=SIP, sip='198.51.100.9')
    d.open()
    f.s('150 Here comes the directory listing.')
    d.c(b'total 0\r\n', dt=4000)
    f.s('226 Directory send OK.')
    f.c('PORT 1,2,3')                          # not a valid PORT argument
    f.s('501 Illegal PORT command.')
    f.c('PORT')
    f.s('501 Illegal PORT command.')

    # EPSV / EPRT
    f.c('EPSV')
    f.s('229 Entering Extended Passive Mode (|||6446|)')
    f.c('RETR extended.bin')
    d = Flow(cap, 50030, 6446)
    d.open()
    f.s('150 Opening data connection.')
    d.s(b'\x00\x01\x02\x03' * 10, dt=5000)
    d.s(b'\x04\x05\x06\x07' * 10, dt=5000)
    f.s('226 Transfer complete.')
    # EPRT with the client address: the server connects from port 20 and
    # the dissector finds the data connection by the port only
    f.c('EPRT |1|192.0.2.1|51300|')
    f.s('200 EPRT command successful.')
    f.c('STOR eprt.txt')
    d = Flow(cap, 20, 51300, cip=SIP, sip=CIP)
    d.open()
    f.s('150 Ok to send data.')
    d.s(b'EPRT upload\r\n', dt=5000)
    f.s('226 Transfer complete.')
    # EPRT naming the server address: the data conversation is found
    f.c('EPRT |1|192.0.2.2|51303|')
    f.s('200 EPRT command successful.')
    f.c('RETR eprt-server.txt')
    d = Flow(cap, 20, 51303, cip=SIP, sip=CIP)
    d.open()
    f.s('150 Opening data connection.')
    d.c(b'EPRT with server address\r\n', dt=5000)
    f.s('226 Transfer complete.')
    f.c('EPRT |2|2001:db8::77|51301|')
    f.s('200 EPRT command successful.')
    f.c('EPRT !1!192.0.2.1!51302!')            # any other delimiter
    f.s('200 EPRT command successful.')
    # Invalid PASV replies
    f.c('PASV')
    f.s('227 Entering Passive Mode (1,2,3)')
    f.c('PASV')
    f.s('227')
    f.c('PASV')
    f.s('227 Entering Passive Mode 192,0,2,2,19,136 ')
    f.c('PASV')
    f.s('227 7,x,192,0,2,2,31,64')
    # odd lines
    f.c('')
    f.s('500 Empty command.')
    f.c('  LEADING')
    f.s('500 Unknown command.')
    f.c('NOOP\n')
    f.s(b'200 bare LF\n')
    f.s('22')
    f.s('220')
    f.s('2200 four digits')
    f.s('abc without a code')
    f.c('USER')
    f.s('530 Please login with USER and PASS.')
    f.c('QUIT')
    f.s('221 Goodbye.')

    # ---- Session 2: AUTH TLS (RFC 4217), the TLS handshake follows
    g = Flow(cap, 40002, 21)
    g.open()
    g.s('220 FTPS ready')
    g.c('AUTH SSL')
    g.s('234 Proceed with negotiation.')       # no AUTH TLS requested: no TLS
    g.c('AUTH TLS')
    g.s('234 Proceed with negotiation.')
    g.c(hello())
    g.s(hello(True))

    # ---- Session 3: PASS without USER and a 257 without an earlier command
    h = Flow(cap, 40003, 21)
    h.open()
    h.s('220 Ready')
    h.c('PASS secret')
    h.s('503 Login with USER first.')
    h.s('257 "/orphan" created')
    h.c('CDUP')
    h.s('250 ok')
    h.c('CWD /top')
    h.s('250 ok')
    h.c('CDUP')
    h.s('250 ok')
    h.c('CDUP')
    h.s('250 ok')
    h.c('CWD')
    h.s('250 ok')

    # ---- Session 4 (IPv6): EPSV with an IPv6 address, EPRT with IPv6
    k = Flow(cap, 40004, 21, cip=CIP6, sip=SIP6, v6=True)
    k.open()
    k.s('220 IPv6 FTP')
    k.c('USER v6user')
    k.s('331 Password?')
    k.c('PASS v6pass')
    k.s('230 ok')
    k.c('EPSV')
    k.s('229 Entering Extended Passive Mode (|||6500|)')
    k.c('LIST')
    d = Flow(cap, 50040, 6500, cip=CIP6, sip=SIP6, v6=True)
    d.open()
    k.s('150 Listing')
    d.s(b'v6 listing\r\n', dt=3000)
    k.s('226 Done')
    k.c('EPRT |2|2001:db8::2|51400|')
    k.s('200 ok')
    k.c('RETR v6.txt')
    d = Flow(cap, 20, 51400, cip=SIP6, sip=CIP6, v6=True)
    d.open()
    k.s('150 Sending')
    d.c(b'v6 file\r\n', dt=3000)
    k.s('226 Done')

    # ---- Session 5: working directory limit (reproducer of the memory problem)
    m = Flow(cap, 40005, 21)
    m.open()
    m.s('220 Ready')
    for i in range(6):
        m.c(b'CWD ' + (b'%03d' % i) + b'd' * 897 + b'\r\n')
        m.s('250 ok')
    m.c('CDUP')
    m.s('250 ok')
    m.c(b'CWD /' + b'a' * 4200 + b'\r\n')
    m.s('250 ok')
    m.c('PWD')
    m.s(b'257 "/' + b'p' * 4200 + b'" is the current directory\r\n')
    m.c('PWD')
    m.s('257 "/short" is the current directory')
    m.c('CWD ' + 'z' * 5000)
    m.s('250 ok')

    # ---- FTP-DATA on port 20 without a control connection
    o = Flow(cap, 50500, 20, cip='192.0.2.60')
    o.open()
    o.s(b'unsolicited text on port 20\r\n', dt=3000)
    o.s(b'\x00\x01 binary', dt=3000)
    o.c(b'', dt=1000)

    # ---- Frames out of time order: no rate is shown for the data stream
    q = Flow(cap, 40006, 21)
    q.open()
    q.s('220 Ready')
    q.c('PASV')
    q.s(pasv_text(SIP, 5100))
    q.c('RETR backwards.txt')
    d = Flow(cap, 50100, 5100)
    d.open()
    q.s('150 go')
    d.s(b'later in the file\r\n', dt=3000)
    d.s(b'earlier timestamp\r\n', dt=-2000)
    q.s('226 done')

    # ---- Last session: invalid EPRT / EPSV arguments. The expert infos are
    # in the Malformed group, so the tests that need clean frames stop
    # before this session.
    z = Flow(cap, 40007, 21)
    z.open()
    z.s('220 Ready')
    for req in ('EPRT |9|192.0.2.9|2000|',     # reproducer: "FTP: Bound the working directory ..." (EPRT offset)
                'EPRT |3|192.0.2.9|2000|',
                'EPRT |1|192.0.2.9|99999|',
                'EPRT |1|nonsense|2000|',
                'EPRT |2|nonsense|2000|',
                'EPRT |1||2000|',
                'EPRT |1|192.0.2.9|2000',
                'EPRT 1|192.0.2.9|2000|',
                'EPRT |x|192.0.2.9|2000|',
                'EPRT ||||',
                'EPRT  |1|192.0.2.9|2000|',    # the delimiter would be a space
                'EPRT ab'):
        z.c(req)
        z.s('501 Bad EPRT.')
    z.c('EPSV')
    z.s('229 Entering Extended Passive Mode (|||abc)\r\n' + 'x' * 40)     # reproducer, with a continuation line
    z.c('EPSV')
    z.s('229 Entering Extended Passive Mode')
    z.c('EPSV')
    z.s('229 Entering Extended Passive Mode (|||6447|')
    z.c('EPSV')
    z.s('229 Entering Extended Passive Mode (|||99999|)')
    z.c('EPSV')
    z.s('229 Entering Extended Passive Mode (||')
    z.c('EPSV')
    z.s('229 text (with) parentheses (|||6448|)')
    z.c('EPSV')
    z.s('229')


def build_malformed(cap):
    f = Flow(cap, 41001, 21)
    f.open()
    f.s('220 Ready')
    f.c('PWD')
    f.s('257 no quotes here')                   # invalid PWD reply
    f.c('PWD')
    f.s('257 "unterminated')
    f.c('PWD')
    f.s('257 ')                                 # too short to hold a path
    f.c('PWD')
    f.s('257 "')
    f.c('PWD')
    f.s('257 "/x"y')
    f.c('PWD')
    f.s('257 "/q""')                            # doubled quote, no end
    f.c('CWD /deep')
    f.s('250 ok')
    # long working directory then an invalid PWD reply
    f.c('PWD')
    f.s(b'257 "/' + b'w' * 4100 + b'" long\r\n')
    f.c('PWD')
    f.s(b'257 bad ' + b'w' * 4100 + b'\r\n')
    # export objects on a truncated frame (the reproducer for the Export Objects tap):
    # control PASV, RETR, then a data frame cut by the snaplen
    f.c('PASV')
    f.s(pasv_text(SIP, 5200))
    f.c('RETR file.bin')
    f.s('150 go')
    d = Flow(cap, 51001, 5200)
    d.open()
    d.s(b'\x00\x01\x02' * 300, snap=200)
    d.s(b'\x00\x01\x02' * 300)
    # Data connection without any data command, then one with the command
    f.c('PASV')
    f.s(pasv_text(SIP, 5010))
    d = Flow(cap, 50020, 5010)
    d.open()
    d.s(b'data without a command\r\n', dt=3000)

    # truncated PORT / EPRT / PASV frames
    f.c('PORT 192,0,2,1,200,1', snap=70)
    f.c('EPRT |1|192.0.2.1|51300|', snap=72)
    f.s('229 (|||6446|)', snap=72)
    f.s('227 (1,2,3,4,5,6)', snap=70)
    # NUL bytes in EPRT lines and responses
    f.c(b'EPRT |1|192.0.2.1\x00|51300|\r\n')
    f.s(b'229 (|||64\x0046|)\r\n')
    f.c(b'USER a\x00b\r\n')
    # 250 for a CWD after a deep path with .. past the root
    f.c('CWD ' + '../' * 50)
    f.s('250 ok')
    # a negative and a huge number in PORT, the 255 mask
    f.c('PORT 1,2,3,4,-5,6')
    f.s('200 ok')
    f.c('PORT 999,999,999,999,999,999')
    f.s('200 ok')
    # code that does not convert cleanly
    f.s('000 zero')
    f.s('999 big')


def build_big(cap):
    f = Flow(cap, 42001, 21)
    f.open()
    f.s('220 Ready')
    f.c('PASV')
    f.s(pasv_text(SIP, 5300))
    f.c('RETR big.bin')
    d = Flow(cap, 52001, 5300)
    d.open()
    f.s('150 go')
    chunk = bytes(range(256)) * 234           # 59904 bytes
    for i in range(20):
        d.s(chunk, dt=1000)
    f.s('226 done')
    f.c('PASV')
    f.s(pasv_text(SIP, 5301))
    f.c('STOR small.bin')
    d = Flow(cap, 52002, 5301)
    d.open()
    f.s('150 go')
    d.c(b'small', dt=1000)
    f.s('226 done')


out = sys.argv[1]
os.makedirs(out, exist_ok=True)
for name, fn in (('ftp-coverage.pcap', build_main), ('ftp-coverage-malformed.pcap', build_malformed),
                 ('ftp-coverage-big.pcap', build_big)):
    clock[0] = 1700000000 * 1000000
    c = Cap()
    fn(c)
    c.write(os.path.join(out, name))
