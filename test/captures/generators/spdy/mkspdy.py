#!/usr/bin/env python3
# Generates test/captures/spdy_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the SPDY coverage captures: mkspdy.py <outdir>.
Everything is built with struct and zlib; nothing comes from a real network.
The SPDY/3 header compression dictionary (the same bytes as spdy_dictionary
in packet-spdy.c) is embedded below."""
import struct
import sys
import os
import gzip
import zlib
import hashlib

DICT = bytes.fromhex(
    "000000076f7074696f6e73000000046865616400000004706f7374000000037075740000"
    "000664656c657465000000057472616365000000066163636570740000000e6163636570"
    "742d636861727365740000000f6163636570742d656e636f64696e670000000f61636365"
    "70742d6c616e67756167650000000d6163636570742d72616e6765730000000361676500"
    "000005616c6c6f770000000d617574686f72697a6174696f6e0000000d63616368652d63"
    "6f6e74726f6c0000000a636f6e6e656374696f6e0000000c636f6e74656e742d62617365"
    "00000010636f6e74656e742d656e636f64696e6700000010636f6e74656e742d6c616e67"
    "756167650000000e636f6e74656e742d6c656e67746800000010636f6e74656e742d6c6f"
    "636174696f6e0000000b636f6e74656e742d6d64350000000d636f6e74656e742d72616e"
    "67650000000c636f6e74656e742d74797065000000046461746500000004657461670000"
    "000665787065637400000007657870697265730000000466726f6d00000004686f737400"
    "00000869662d6d617463680000001169662d6d6f6469666965642d73696e63650000000d"
    "69662d6e6f6e652d6d617463680000000869662d72616e67650000001369662d756e6d6f"
    "6469666965642d73696e63650000000d6c6173742d6d6f646966696564000000086c6f63"
    "6174696f6e0000000c6d61782d666f72776172647300000006707261676d610000001270"
    "726f78792d61757468656e7469636174650000001370726f78792d617574686f72697a61"
    "74696f6e0000000572616e676500000007726566657265720000000b72657472792d6166"
    "7465720000000673657276657200000002746500000007747261696c6572000000117472"
    "616e736665722d656e636f64696e6700000007757067726164650000000a757365722d61"
    "67656e74000000047661727900000003766961000000077761726e696e67000000107777"
    "772d61757468656e746963617465000000066d6574686f64000000036765740000000673"
    "746174757300000006323030204f4b0000000776657273696f6e00000008485454502f31"
    "2e310000000375726c000000067075626c69630000000a7365742d636f6f6b6965000000"
    "0a6b6565702d616c697665000000066f726967696e313030313031323031323032323035"
    "323036333030333032333033333034333035333036333037343032343035343036343037"
    "343038343039343130343131343132343133343134343135343136343137353032353034"
    "353035323033204e6f6e2d417574686f726974617469766520496e666f726d6174696f6e"
    "323034204e6f20436f6e74656e74333031204d6f766564205065726d616e656e746c7934"
    "303020426164205265717565737434303120556e617574686f72697a656434303320466f"
    "7262696464656e343034204e6f7420466f756e6435303020496e7465726e616c20536572"
    "766572204572726f72353031204e6f7420496d706c656d656e7465643530332053657276"
    "69636520556e617661696c61626c654a616e20466562204d617220417072204d6179204a"
    "756e204a756c204175672053657074204f6374204e6f76204465632030303a30303a3030"
    "204d6f6e2c205475652c205765642c205468752c204672692c205361742c2053756e2c20"
    "474d546368756e6b65642c746578742f68746d6c2c696d6167652f706e672c696d616765"
    "2f6a70672c696d6167652f6769662c6170706c69636174696f6e2f786d6c2c6170706c69"
    "636174696f6e2f7868746d6c2b786d6c2c746578742f706c61696e2c746578742f6a6176"
    "617363726970742c7075626c6963707269766174656d61782d6167653d677a69702c6465"
    "666c6174652c73646368636861727365743d7574662d38636861727365743d69736f2d38"
    "3835392d312c7574662d2c2a2c656e713d302e")

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

class Pcap:
    def __init__(self, fn):
        self.f = open(fn, 'wb')
        self.f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        self.t = 0
        self.n = 0
        self.ipid = 1

    def close(self):
        self.f.close()

class Conn:
    """One TCP connection with its own header compressors."""
    def __init__(self, pcap, cport=40001, sport=6121, level=6):
        self.p = pcap
        self.cport, self.sport = cport, sport
        self.cip = bytes([10, 0, 0, 1]); self.sip = bytes([10, 0, 0, 2])
        self.seq = {0: 1000, 1: 5000}
        mk = lambda: zlib.compressobj(level, zlib.DEFLATED, 15, 8, zlib.Z_DEFAULT_STRATEGY, DICT)
        self.ccomp = mk()      # client SYN_STREAM header blocks
        self.scomp = mk()      # server SYN_REPLY, HEADERS and server SYN_STREAM
        self.send(True, b'', 0x02)
        self.send(False, b'', 0x12)
        self.send(True, b'', 0x10)

    def hblock(self, headers, client=True, raw=None, cut=None):
        """Compressed header block (v3: 32 bit counts and lengths)."""
        if raw is None:
            raw = struct.pack('!I', len(headers))
            for k, v in headers:
                raw += struct.pack('!I', len(k)) + k + struct.pack('!I', len(v)) + v
        if cut is not None:
            raw = raw[:cut]
        c = self.ccomp if client else self.scomp
        return c.compress(raw) + c.flush(zlib.Z_SYNC_FLUSH)

    def send(self, from_client, payload, flags=0x18):
        p = self.p
        d = 0 if from_client else 1
        src, dst = (self.cip, self.sip) if from_client else (self.sip, self.cip)
        sp, dp = (self.cport, self.sport) if from_client else (self.sport, self.cport)
        t = struct.pack('!HHIIBBHHH', sp, dp, self.seq[d], self.seq[1 - d], 0x50,
                        flags, 65535, 0, 0)
        ph = src + dst + struct.pack('!BBH', 0, 6, len(t) + len(payload))
        c = csum(ph + t + payload)
        t = t[:16] + struct.pack('!H', c) + t[18:]
        p.ipid += 1
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(t) + len(payload), p.ipid,
                         0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        mc = b'\x02\0\0\0\0\x01'; ms = b'\x02\0\0\0\0\x02'
        eth = (ms + mc if from_client else mc + ms) + b'\x08\x00'
        pkt = eth + ip + t + payload
        p.t += 1; p.n += 1
        p.f.write(struct.pack('<IIII', p.t, 0, len(pkt), len(pkt)) + pkt)
        self.seq[d] += len(payload) + (1 if flags & 3 else 0)

def ctrl(typ, flags, payload, ver=3, length=None):
    n = len(payload) if length is None else length
    return struct.pack('!HHB', 0x8000 | ver, typ, flags) + n.to_bytes(3, 'big') + payload

def data(stream, flags, payload, length=None):
    n = len(payload) if length is None else length
    return struct.pack('!IB', stream, flags) + n.to_bytes(3, 'big') + payload

SYN_STREAM, SYN_REPLY, RST_STREAM, SETTINGS, PING, GOAWAY, HEADERS, \
    WINDOW_UPDATE, CREDENTIAL = 1, 2, 3, 4, 6, 7, 8, 9, 10

def syn_stream(c, sid, headers, flags=0, assoc=0, prio=0, raw=None, cut=None, client=True):
    return ctrl(SYN_STREAM, flags, struct.pack('!IIH', sid, assoc, prio << 13) +
                c.hblock(headers, client, raw, cut))

def syn_reply(c, sid, headers, flags=0, raw=None, cut=None):
    return ctrl(SYN_REPLY, flags, struct.pack('!I', sid) + c.hblock(headers, False, raw, cut))

def headers_frame(c, sid, headers, flags=0, raw=None, cut=None):
    return ctrl(HEADERS, flags, struct.pack('!I', sid) + c.hblock(headers, False, raw, cut))

def req(host=b'example.com', path=b'/', method=b'GET', extra=()):
    return [(b':method', method), (b':path', path), (b':version', b'HTTP/1.1'),
            (b':host', host), (b':scheme', b'https')] + list(extra)

def rep(status=b'200 OK', extra=()):
    return [(b':status', status), (b':version', b'HTTP/1.1')] + list(extra)

def gz(b):
    co = zlib.compressobj(6, zlib.DEFLATED, 31)
    return co.compress(b) + co.flush()

def df(b):
    return zlib.compress(b)

HTML = b'<html><body>hello spdy</body></html>'
JSON = b'{"a": 1, "b": [1, 2, 3]}'

def main(out):
    os.makedirs(out, exist_ok=True)
    pc = Pcap(os.path.join(out, 'spdy-coverage.pcap'))
    c = Conn(pc)
    S = lambda b: c.send(True, b)      # client to server
    R = lambda b: c.send(False, b)     # server to client

    # -- settings, ping, two frames in one segment
    S(ctrl(SETTINGS, 1, struct.pack('!I', 3) +
           struct.pack('!B', 1) + (1).to_bytes(3, 'big') + struct.pack('!I', 100000) +
           struct.pack('!B', 2) + (4).to_bytes(3, 'big') + struct.pack('!I', 100) +
           struct.pack('!B', 3) + (9).to_bytes(3, 'big') + struct.pack('!I', 7)))
    R(ctrl(SETTINGS, 0, struct.pack('!I', 2) +
           struct.pack('!B', 0) + (7).to_bytes(3, 'big') + struct.pack('!I', 65536) +
           struct.pack('!B', 0) + (3).to_bytes(3, 'big') + struct.pack('!I', 50)) +
      ctrl(PING, 0, struct.pack('!I', 1)))
    S(ctrl(PING, 0, struct.pack('!I', 1)))
    # -- stream 1: GET with an HTML reply in one DATA frame, FIN
    S(syn_stream(c, 1, req(extra=[(b'accept', b'text/html')]), flags=1, prio=3))
    R(syn_reply(c, 1, rep(extra=[(b'content-type', b'text/html; charset=utf-8'),
                                  (b'content-length', str(len(HTML)).encode())])))
    R(data(1, 1, HTML))
    # -- stream 3: POST with a JSON body in three DATA frames (reassembly)
    S(syn_stream(c, 3, req(path=b'/post', method=b'POST',
                           extra=[(b'content-type', b'application/json')]), flags=2))
    S(data(3, 0, JSON[:8]))
    S(data(3, 0, JSON[8:16]))
    S(data(3, 1, JSON[16:]))
    R(syn_reply(c, 3, rep(b'201 Created')))
    # -- stream 5: gzip encoded text, one DATA frame
    S(syn_stream(c, 5, req(path=b'/gz'), flags=1))
    R(syn_reply(c, 5, rep(extra=[(b'content-type', b'TEXT/Plain ; charset=us-ascii'),
                                  (b'content-encoding', b'gzip')])))
    R(data(5, 1, gz(b'gzip compressed body ' * 20)))
    # -- stream 7: deflate encoded, three DATA frames, then an empty FIN frame
    S(syn_stream(c, 7, req(path=b'/df'), flags=1))
    R(syn_reply(c, 7, rep(extra=[(b'content-type', b'text/plain;'),
                                  (b'content-encoding', b'deflate')])))
    z = df(b''.join(hashlib.md5(b'%d' % i).digest() for i in range(8)))
    R(data(7, 0, z[:30]))
    R(data(7, 0, z[30:60]))
    R(data(7, 0, z[60:]))
    R(data(7, 1, b''))
    # -- stream 9: one DATA frame then an empty FIN frame (only one chunk)
    S(syn_stream(c, 9, req(path=b'/one'), flags=1))
    R(syn_reply(c, 9, rep(extra=[(b'content-type', b'text/html')])))
    R(data(9, 0, HTML))
    R(data(9, 1, b''))
    # -- stream 11: content encodings the dissector cannot decompress
    S(syn_stream(c, 11, req(path=b'/compress'), flags=1))
    R(syn_reply(c, 11, rep(extra=[(b'content-type', b'application/octet-stream'),
                                   (b'content-encoding', b'compress')])))
    R(data(11, 1, b'\x1f\x9d\x90abcdef'))
    S(syn_stream(c, 13, req(path=b'/badgz'), flags=1))
    R(syn_reply(c, 13, rep(extra=[(b'content-type', b'text/plain'),
                                   (b'content-encoding', b'gzip')])))
    R(data(13, 1, b'this is not gzip data at all'))
    S(syn_stream(c, 15, req(path=b'/identity'), flags=1))
    R(syn_reply(c, 15, rep(extra=[(b'content-type', b'text/html'),
                                   (b'content-encoding', b'identity')])))
    R(data(15, 1, HTML))
    # -- stream 17: unknown media type, and a reply with no content type
    S(syn_stream(c, 17, req(path=b'/png'), flags=1))
    R(syn_reply(c, 17, rep(extra=[(b'content-type', b'image/x-unknown')])))
    R(data(17, 1, b'\x89PNG\r\n\x1a\n' + b'\0' * 8))
    S(syn_stream(c, 19, req(path=b'/none'), flags=1))
    R(syn_reply(c, 19, rep(extra=[(b'x-other', b'value')])))
    R(data(19, 1, b'no content type'))
    # -- DATA on a stream that has no SYN_STREAM, partial and final
    R(data(21, 0, b'orphan one'))
    R(data(21, 1, b'orphan two'))
    # -- HEADERS (odd and even streams), server push on an even stream
    R(headers_frame(c, 1, [(b'x-trailer', b'done')]))
    R(syn_stream(c, 2, [(b':scheme', b'https'), (b':host', b'example.com'),
                        (b':path', b'/pushed'), (b':version', b'HTTP/1.1')],
                 flags=2, assoc=1, client=False))
    R(headers_frame(c, 2, [(b'x-more', b'headers')], flags=1))
    # SYN_STREAM and HEADERS for the same stream in one segment
    R(syn_stream(c, 4, [(b':path', b'/p2')], assoc=1, client=False) +
      headers_frame(c, 4, [(b'x-two', b'in one segment')]))
    R(syn_reply(c, 2, rep(extra=[(b'content-type', b'text/html')])))
    R(data(2, 1, HTML))
    # -- RST_STREAM, GOAWAY, WINDOW_UPDATE, CREDENTIAL
    S(ctrl(RST_STREAM, 0, struct.pack('!II', 5, 5)))
    S(ctrl(RST_STREAM, 0, struct.pack('!II', 7, 3)))
    R(ctrl(GOAWAY, 0, struct.pack('!II', 21, 0)))
    R(ctrl(GOAWAY, 0, struct.pack('!II', 21, 1)))
    R(ctrl(GOAWAY, 0, struct.pack('!II', 21, 11)))
    S(ctrl(WINDOW_UPDATE, 0, struct.pack('!II', 1, 65536)))
    S(ctrl(CREDENTIAL, 0, struct.pack('!H', 3) + b'\x00\x00\x00\x04proof'))
    # -- unsupported version (below 3): not decoded further
    S(ctrl(SYN_STREAM, 0, b'\x00\x00\x00\x01' + b'\x00' * 12, ver=2))
    # -- a SYN_STREAM split over three TCP segments (reassembly)
    f = syn_stream(c, 23, req(path=b'/split', extra=[(b'accept-language', b'en-US,en;q=0.8')]),
                   flags=1)
    S(f[:5]); S(f[5:30]); S(f[30:])
    R(syn_reply(c, 23, rep()))
    # frame split in the middle of the 8 byte header
    f = ctrl(PING, 0, struct.pack('!I', 2))
    S(f[:3]); S(f[3:])
    # -- the same stream ID and type again in a later frame
    S(syn_stream(c, 1, req(path=b'/again'), flags=1))
    R(syn_reply(c, 1, rep()))
    # -- many SYN_STREAMs on different streams with empty header blocks
    #    (reproducer: header blocks were kept in a global list, quadratic
    #    cost, and the first one was lost when a frame was dissected again)
    for i in range(40):
        S(syn_stream(c, 101 + 2 * i, [], flags=1))
    for i in range(10):
        R(syn_reply(c, 101 + 2 * i, [], flags=1))

    # second connection: only the first header frame, to run a separate
    # decompression state
    c2 = Conn(pc, cport=40002)
    c2.send(True, syn_stream(c2, 1, req(path=b'/first', extra=[(b'accept', b'*/*')]), flags=1))
    c2.send(False, syn_reply(c2, 1, rep(extra=[(b'content-type', b'text/html')])))
    c2.send(False, data(1, 1, HTML))

    # third connection on a port that only the heuristic claims
    c3 = Conn(pc, cport=40003, sport=9999)
    c3.send(True, ctrl(SETTINGS, 0, struct.pack('!I', 1) + struct.pack('!B', 0) +
                       (4).to_bytes(3, 'big') + struct.pack('!I', 10)))
    c3.send(False, ctrl(PING, 0, struct.pack('!I', 5)))
    c3.send(True, syn_stream(c3, 1, req(path=b'/heur'), flags=1))
    c3.send(False, syn_reply(c3, 1, rep(extra=[(b'content-type', b'text/html')])))
    c3.send(False, data(1, 1, HTML))
    c3.send(True, data(3, 1, b'\x00\x01'))
    # HTTP/1.1 Upgrade: spdy/3 on port 80; the server accepts with 101 and
    # both sides continue with SPDY (http.upgrade table)
    c4 = Conn(pc, cport=40004, sport=80)
    c4.send(True, b'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\n'
                  b'Upgrade: spdy\r\n\r\n')
    c4.send(False, b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n'
                   b'Upgrade: spdy\r\n\r\n')
    c4.send(True, syn_stream(c4, 1, req(path=b'/upgraded'), flags=1))
    c4.send(False, syn_reply(c4, 1, rep(extra=[(b'content-type', b'text/html')])))
    c4.send(False, data(1, 1, HTML))
    pc.close()

    # ---- malformed ----
    pm = Pcap(os.path.join(out, 'spdy-coverage-malformed.pcap'))
    m = Conn(pm)
    S = lambda b: m.send(True, b)
    R = lambda b: m.send(False, b)
    S(syn_stream(m, 1, req(), flags=1))
    # invalid status codes
    S(ctrl(RST_STREAM, 0, struct.pack('!II', 1, 99)))
    R(ctrl(GOAWAY, 0, struct.pack('!II', 1, 77)))
    # invalid and unhandled control frame types
    S(ctrl(11, 0, b'\0\0\0\0'))
    S(ctrl(5, 0, b'\0\0\0\0'))
    S(ctrl(300, 0, b'\0\0\0\0'))
    # SETTINGS: too short, too many entries for the length
    S(ctrl(SETTINGS, 0, b'\x00\x00'))
    S(ctrl(SETTINGS, 0, struct.pack('!I', 5) + b'\0' * 8))
    # header decompression failure on a connection of its own, and the
    # blocks that are cut inside a header entry
    m2 = Conn(pm, cport=40002)
    m2.send(True, ctrl(SYN_STREAM, 0, struct.pack('!IIH', 1, 0, 0) + b'\xff\xfe garbage not zlib'))
    m2.send(False, ctrl(SYN_REPLY, 0, struct.pack('!I', 1) + b'\x78\xbb\xff\xff'))
    m3 = Conn(pm, cport=40003)
    raw = struct.pack('!I', 2) + struct.pack('!I', 1) + b'a' + struct.pack('!I', 1) + b'b'
    # count says two entries but only one is there, then each part cut
    full = struct.pack('!I', 1) + struct.pack('!I', 4) + b'name' + struct.pack('!I', 5) + b'value'
    m3.send(True, syn_stream(m3, 1, [], raw=struct.pack('!I', 2) + full[4:], flags=1))
    m3.send(True, syn_stream(m3, 3, [], raw=full[:6], flags=1))        # name length cut
    m3.send(True, syn_stream(m3, 5, [], raw=full[:10], flags=1))       # name cut
    m3.send(True, syn_stream(m3, 7, [], raw=full[:14], flags=1))       # value length cut
    m3.send(True, syn_stream(m3, 9, [], raw=full[:20], flags=1))       # value cut
    m3.send(True, syn_stream(m3, 11, [], raw=b'\x00\x00', flags=1))    # block shorter than the count
    # frames cut short: the length says more than the segment carries
    # (reachable with TCP reassembly off), SYN_STREAM/RST_STREAM with a
    # length too small for their fields
    m4 = Conn(pm, cport=40004)
    m4.send(True, ctrl(PING, 0, struct.pack('!I', 1), length=40))
    m4.send(True, data(1, 0, b'short', length=100))
    m4.send(True, ctrl(RST_STREAM, 0, struct.pack('!I', 1)))
    m4.send(True, ctrl(GOAWAY, 0, b'\0\0\0\1'))
    m4.send(True, ctrl(WINDOW_UPDATE, 0, b'\0\0\0\1'))
    m4.send(True, ctrl(PING, 0, b''))
    m4.send(True, ctrl(SYN_STREAM, 0, b'\0\0\0\1\0\0\0\0\0'))
    m4.send(True, ctrl(SYN_REPLY, 0, b'\0\0\0'))
    # not SPDY at all on the port of the heuristic (first octet is not 0 or 0x80)
    m5 = Conn(pm, cport=40005, sport=9999)
    m5.send(True, b'GET / HTTP/1.1\r\n\r\n')
    pm.close()
    with open(os.path.join(out, 'spdy-coverage.pcap'), 'rb') as f, \
         gzip.GzipFile(os.path.join(out, 'spdy_coverage.pcap.gz'), 'wb', 9, mtime=0) as g:
        g.write(f.read())

if __name__ == '__main__':
    main(sys.argv[1])
