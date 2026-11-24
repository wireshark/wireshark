#!/usr/bin/env python3
# Generates test/captures/ipfs_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the synthetic IPFS / libp2p coverage captures.
#   mkipfs.py <outdir>  writes ipfs_coverage.pcapng (main, decodes cleanly)
#                       and ipfs_coverage_malformed.pcapng (error paths)
# All traffic is built here with struct; nothing is captured.
import os
import struct
import sys


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


class Flow:
    """One TCP connection (Ethernet/IPv4); frames collects the packets."""

    def __init__(self, cip='192.0.2.1', sip='198.51.100.2', cport=40000, sport=80):
        self.cip, self.sip, self.cport, self.sport = cip, sip, cport, sport
        self.seq = {0: 1000, 1: 5000}
        self.frames = []

    def _tcp(self, d, payload, flags=0x18):
        src, dst = (self.cip, self.sip) if d == 0 else (self.sip, self.cip)
        sp, dp = (self.cport, self.sport) if d == 0 else (self.sport, self.cport)
        ack = self.seq[1 - d] if flags & 0x10 else 0
        opt = b'\x02\x04\x05\xb4\x04\x02\x01\x01' if flags & 0x02 else b''
        tcp = struct.pack('!HHIIBBHHH', sp, dp, self.seq[d], ack,
                          (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt
        s = bytes(map(int, src.split('.')))
        t = bytes(map(int, dst.split('.')))
        ph = s + t + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        c = csum(ph + tcp + payload)
        tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                         1, 0, 64, 6, 0, s, t)
        ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
        eth = (b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01' if d == 0
               else b'\x02\0\0\0\0\x01\x02\0\0\0\0\x02') + b'\x08\x00'
        self.seq[d] = (self.seq[d] + len(payload) + (1 if flags & 3 else 0)) & 0xffffffff
        return eth + ip + tcp + payload

    def handshake(self):
        self.frames.append((1, self._tcp(0, b'', 0x02)))
        self.frames.append((1, self._tcp(1, b'', 0x12)))
        self.frames.append((1, self._tcp(0, b'', 0x10)))

    def send(self, d, payload):
        self.frames.append((1, self._tcp(d, payload)))


def write_pcapng(name, frames):
    """frames: list of (linktype, bytes); one interface per link type."""
    def blk(t, body):
        body += b'\0' * (-len(body) % 4)
        n = len(body) + 12
        return struct.pack('<II', t, n) + body + struct.pack('<I', n)
    types = sorted({lt for lt, _ in frames})
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in types:
        out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (lt, fr) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', types.index(lt), ts >> 32,
                                  ts & 0xffffffff, len(fr), len(fr)) + fr)
    with open(name, 'wb') as f:
        f.write(out)


def ws_frame(payload, opcode=2):
    n = len(payload)
    if n < 126:
        h = struct.pack('!BB', 0x80 | opcode, n)
    elif n < 65536:
        h = struct.pack('!BBH', 0x80 | opcode, 126, n)
    else:
        h = struct.pack('!BBQ', 0x80 | opcode, 127, n)
    return h + payload


def ms(token):
    b = token.encode() + b'\n'
    n = len(b)
    v = bytes([n]) if n < 0x80 else bytes([0x80 | (n & 0x7f), n >> 7])
    return v + b


HELLO = ms('/multistream/1.0.0')


def rec(n, fill=0x55):
    return struct.pack('!H', n) + bytes([fill]) * n


def ws_upgrade(flow, subproto=None):
    req = (b'GET /p2p HTTP/1.1\r\nHost: 198.51.100.2\r\nUpgrade: websocket\r\n'
           b'Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
           b'Sec-WebSocket-Version: 13\r\n')
    rsp = (b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
           b'Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n')
    if subproto:
        req += b'Sec-WebSocket-Protocol: ' + subproto + b'\r\n'
        rsp += b'Sec-WebSocket-Protocol: ' + subproto + b'\r\n'
    flow.send(0, req + b'\r\n')
    flow.send(1, rsp + b'\r\n')


def tlv(t, v):
    # the dissector does not skip padding: the length includes it
    v += b'\0' * (-len(v) % 4)
    return struct.pack('!HH', t, len(v)) + v


def pdu(name, payload, addrs=True, rev=False, pa=40000, pb=4001):
    """Exported PDU frame (link type 252) naming a dissector."""
    h = tlv(12, name)
    if addrs:
        a, b = bytes([192, 0, 2, 1]), bytes([198, 51, 100, 2])
        if rev:
            a, b, pa, pb = b, a, pb, pa
        h += (tlv(20, a) + tlv(21, b) + tlv(24, struct.pack('!I', 2)) +
              tlv(25, struct.pack('!I', pa)) + tlv(26, struct.pack('!I', pb)))
    return (252, h + struct.pack('!HH', 0, 0) + payload)


def http_req(uri, extra=b''):
    return (b'POST ' + uri + b' HTTP/1.1\r\nHost: 192.0.2.9:5001\r\n'
            b'Content-Length: 0\r\n' + extra + b'\r\n')


def http_rsp(code=b'200 OK', body=b''):
    return (b'HTTP/1.1 ' + code + b'\r\nContent-Type: application/json\r\n'
            b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)


def main_capture():
    fr = []

    # 1. WebSocket subprotocol libp2p (default): both sides offer /noise.
    f = Flow(cport=40001)
    f.handshake()
    ws_upgrade(f, b'libp2p')
    f.send(0, ws_frame(HELLO + ms('/noise')))
    f.send(1, ws_frame(HELLO + ms('/noise')))
    f.send(0, ws_frame(rec(32, 0x11)))
    f.send(1, ws_frame(rec(16, 0x22) + rec(5, 0x23)))
    f.send(0, ws_frame(rec(64, 0x33)))
    fr += f.frames

    # 2. na / ls / another protocol: the Noise offer is withdrawn.
    f = Flow(cport=40002)
    f.handshake()
    ws_upgrade(f, b'libp2p')
    f.send(0, ws_frame(HELLO + ms('/noise')))
    f.send(1, ws_frame(HELLO + ms('na') + ms('ls')))
    f.send(0, ws_frame(ms('/yamux/1.0.0')))
    f.send(1, ws_frame(ms('/yamux/1.0.0')))
    f.send(0, ws_frame(ms('/noise')))
    fr += f.frames

    # 3. Only one direction visible: the Noise transition is inferred
    #    from a complete record of at least 16 bytes.
    f = Flow(cport=40003)
    f.handshake()
    ws_upgrade(f, b'libp2p')
    f.send(0, ws_frame(HELLO + ms('/noise')))
    f.send(0, ws_frame(rec(20, 0x44)))
    f.send(0, ws_frame(rec(8, 0x45)))
    fr += f.frames

    # 4. IPFS HTTP RPC on port 5001 (handled by the postdissector).
    uris = [b'/api/v0/cat?arg=QmZLws5v55MQJmyTo2deZfp3Z1KuKa9MwyCaymTxqXXmkh',
            b'/api/v0/add?arg=a%20b&arg=c+d&pin=true&flag&arg=%41%4a&=x&arg',
            b'/api/v0/id',
            b'/api/v0/swarm/peers?verbose=true&arg=%zz&arg=%4',
            b'/api/v0/files/ls?arg=%00x&%61rg=y']
    for i, u in enumerate(uris):
        f = Flow(cip='192.0.2.9', sip='192.0.2.10', cport=41000 + i, sport=5001)
        f.handshake()
        f.send(0, http_req(u))
        f.send(1, http_rsp(b'200 OK', b'{"Peers":[]}'))
        fr += f.frames
    f = Flow(cip='192.0.2.9', sip='192.0.2.10', cport=41010, sport=5001)
    f.handshake()
    f.send(0, http_req(b'/api/v0/nothere'))
    f.send(1, http_rsp(b'500 Internal Server Error', b'{"Message":"x"}'))
    fr += f.frames
    # three pipelined requests and one outside /api/v0/ in one segment
    f = Flow(cip='192.0.2.9', sip='192.0.2.10', cport=41011, sport=5001)
    f.handshake()
    f.send(0, http_req(b'/api/v0/version') + http_req(b'/api/v0/pin/ls?arg=Qm1') +
           http_req(b'/api/v0/repo/gc') + http_req(b'/notapi'))
    f.send(1, http_rsp(b'200 OK', b'{}'))
    fr += f.frames
    # a request and a response in one frame: the response status is added
    f = Flow(cip='192.0.2.9', sip='192.0.2.10', cport=41012, sport=5001)
    f.handshake()
    f.send(0, http_req(b'/api/v0/version?number=true') + http_rsp(b'200 OK', b'{}'))
    fr += f.frames
    # plain HTTP on the API port, not IPFS
    f = Flow(cip='192.0.2.9', sip='192.0.2.10', cport=41013, sport=5001)
    f.handshake()
    f.send(0, b'GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n')
    f.send(1, http_rsp(b'404 Not Found', b'no'))
    fr += f.frames

    # 5. Exported PDU frames naming ipfs_tcp and ipfs_ws, with and
    #    without address tags.
    # (without address tags every PDU of a name shares one conversation,
    # so only ipfs_tcp uses that form; ipfs_ws gets its own ports)
    for name, addrs, pa in ((b'ipfs_tcp', False, 0), (b'ipfs_tcp', True, 40000),
                            (b'ipfs_ws', True, 40010)):
        kw = dict(pa=pa, pb=4001)
        fr.append(pdu(name, HELLO + ms('/noise'), addrs, **kw))
        fr.append(pdu(name, HELLO + ms('/noise'), addrs, rev=True, **kw))
        fr.append(pdu(name, rec(24, 0x11), addrs, **kw))
        fr.append(pdu(name, rec(16, 0x12) + rec(3, 0x13), addrs, rev=True, **kw))

    # 6. TCP to port 4001: reached with the ipfs_tcp heuristic or Decode As.
    #    A token and records split across segments (reassembly), with
    #    both sides offering /noise.
    f = Flow(cport=40100, sport=4001)
    f.handshake()
    f.send(0, HELLO + ms('/noise')[:3])
    f.send(0, ms('/noise')[3:])
    f.send(1, HELLO + ms('/noise'))
    r = rec(0x40)
    f.send(0, r[:10])
    f.send(0, r[10:] + r[:1])
    f.send(0, r[1:])
    f.send(1, r + r[:30])
    f.send(1, r[30:])
    fr += f.frames

    # 6b. One direction only, inferred transition with a record split
    #     over two segments.
    f = Flow(cport=40101, sport=4001)
    f.handshake()
    f.send(0, HELLO + ms('/noise'))
    f.send(1, HELLO)
    f.send(0, r[:10])
    f.send(0, r[10:])
    f.send(0, r[:1])
    f.send(0, r[1:])
    fr += f.frames

    # 6c. Hello, token and record header split over segments (the server
    #     speaks first, so the heuristic has claimed the conversation).
    f = Flow(cport=40102, sport=4001)
    f.handshake()
    f.send(1, HELLO + ms('/noise'))
    f.send(0, HELLO[:5])
    f.send(0, HELLO[5:] + ms('/noise')[:1])
    f.send(0, ms('/noise')[1:])
    f.send(0, b'\x00')
    f.send(0, b'\x20' + b'\x66' * 0x20)
    fr += f.frames

    # 6d. Unconfirmed traffic on the peer port (show_candidates preference).
    f = Flow(cport=40103, sport=4001)
    f.handshake()
    f.send(0, b'\x16\x03\x01' + b'\x99' * 40)
    f.send(1, b'\x16\x03\x03' + b'\x98' * 40)
    fr += f.frames

    # 7. ipfs_ws heuristic: the first WebSocket message of the frame is not
    #    libp2p and the second one is the hello (reproducer, batch 40).
    f = Flow(cport=40200)
    f.handshake()
    ws_upgrade(f)
    f.send(1, ws_frame(b'\x00\x01\x02 not libp2p junk ' * 2) + ws_frame(HELLO))
    f.send(0, ws_frame(HELLO + ms('/noise')))
    f.send(1, ws_frame(ms('/noise') + rec(32, 0xaa)))
    f.send(0, ws_frame(rec(16, 0xab)))
    fr += f.frames
    # a WebSocket peer without subprotocol that is not libp2p at all
    f = Flow(cport=40201)
    f.handshake()
    ws_upgrade(f)
    f.send(0, ws_frame(b'plain text message', 1))
    f.send(1, ws_frame(b'reply', 1))
    fr += f.frames
    return fr


def malformed_capture():
    fr = []
    # WebSocket libp2p: bad zero-length record, short, truncated varints
    f = Flow(cport=41501)
    f.handshake()
    ws_upgrade(f, b'libp2p')
    f.send(0, ws_frame(HELLO + ms('/noise')))
    f.send(1, ws_frame(HELLO + ms('/noise')))
    f.send(1, ws_frame(b'\x00\x00'))                    # zero length
    f.send(0, ws_frame(b'\x00'))                        # one byte
    f.send(1, ws_frame(b'\xff\xff' + b'\x33' * 100))    # length > data
    f.send(1, ws_frame(rec(0x30, 0x44) + b'\x00\x02\x55'))
    fr += f.frames
    g = Flow(cport=41502)
    g.handshake()
    ws_upgrade(g, b'libp2p')
    g.send(0, ws_frame(HELLO))
    g.send(0, ws_frame(b'\x80\x00'))                    # non-minimal
    g.send(0, ws_frame(b'\x80'))                        # truncated varint
    g.send(0, ws_frame(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01'))
    g.send(0, ws_frame(b'\x81\x20' + b'/' + b'a' * 4095 + b'\n'))   # 4097
    g.send(0, ws_frame(bytes([0x80, 0x20]) + b'/' + b'b' * 4094 + b'\n'))  # 4096
    g.send(0, ws_frame(b'\x01\n'))                      # empty token
    g.send(0, ws_frame(b'\x03na\n' + b'\x03ls\n' + b'\x02\x7f\n'))
    g.send(0, ws_frame(b'\x04abc\n'))                   # token not starting '/'
    g.send(0, ws_frame(b'\x04/a\x01\n'))                # control character
    g.send(0, ws_frame(b'\x04/abc'))                    # no newline
    g.send(0, ws_frame(ms('/noise') + rec(20, 0x66)))   # inferred transition
    fr += g.frames
    h = Flow(cport=41503)
    h.handshake()
    ws_upgrade(h, b'libp2p')
    h.send(0, ws_frame(HELLO + ms('/noise')))
    h.send(1, ws_frame(HELLO + ms('/noise')))
    h.send(0, ws_frame(b'\x00\x01\x77' * 300))
    fr += h.frames
    # TCP on 4001 (heuristic / Decode As): invalid framing and truncation
    f = Flow(cport=41600, sport=4001)
    f.handshake()
    f.send(0, HELLO + ms('/noise') + b'\x80')           # truncated varint
    f.send(0, b'\x01' + b'/' + b'z' * 126 + b'\n')
    f.send(0, b'\x00\x00\x00')
    fr += f.frames
    f = Flow(cport=41601, sport=4001)
    f.handshake()
    f.send(0, HELLO + ms('/noise') + b'\x00')           # inferred: header split
    f.send(0, b'\x04' + b'\x01' * 4)                    # short record: bad
    f.send(0, b'\x00\x00')
    fr += f.frames
    f = Flow(cport=41602, sport=4001)                   # truncated frame
    f.handshake()
    f.send(0, HELLO + ms('/noise'))
    f.send(0, b'\x00\x30' + b'\x01' * 0x30)
    fr += f.frames
    # ipfs_ws heuristic with a conversation and junk after it
    f = Flow(cport=41700)
    f.handshake()
    ws_upgrade(f)
    f.send(0, ws_frame(HELLO + ms('/noise')))
    f.send(1, ws_frame(b'\x00\x00'))
    f.send(0, ws_frame(b'junk'))
    fr += f.frames
    # RPC: hostile URIs
    uris = [b'/api/v0/cat?arg=%00%41%4&arg&=&&arg=%4G+x%2', b'/api/v0/?',
            b'/api/v0/', b'/api/v0/a?&&&', b'/api/v0/b?arg=' + b'%25' * 300,
            b'/api/v0/c?=arg&%61rg=%ff%fe', b'/api/v0/d?arg']
    for i, u in enumerate(uris):
        f = Flow(cip='192.0.2.9', sip='192.0.2.10', cport=41800 + i, sport=5001)
        f.handshake()
        f.send(0, http_req(u))
        f.send(1, http_rsp())
        fr += f.frames
    # Exported PDU: errors, one-byte and truncated records
    for name in (b'ipfs_tcp', b'ipfs_ws'):
        for addrs in (False, True):
            fr.append(pdu(name, HELLO + ms('/noise'), addrs))
            fr.append(pdu(name, b'\x00\x10' + b'\x11' * 16 + b'\x00\xff\x01', addrs))
            fr.append(pdu(name, b'\x00\x00', addrs))
            fr.append(pdu(name, b'\x00', addrs, rev=True))
            fr.append(pdu(name, b'\x80', addrs))
    return fr


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcapng(os.path.join(out, 'ipfs_coverage.pcapng'), main_capture())
    write_pcapng(os.path.join(out, 'ipfs_coverage_malformed.pcapng'), malformed_capture())
