#!/usr/bin/env python3
# Generates test/captures/roon_discovery_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
import sys
import os

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def ip4(a): return bytes(int(x) for x in a.split('.'))

def ip_pkt(proto, l4, src, dst, ident=1, ttl=64):
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0, ttl, proto, 0, ip4(src), ip4(dst))
    return ip[:10] + struct.pack('>H', csum(ip)) + ip[12:] + l4

ETH = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01'
def eth_wrap(ippkt, etype=0x0800, rev=False):
    mac = ETH[6:] + ETH[:6] if rev else ETH
    return mac + struct.pack('>H', etype) + ippkt

def udp_frame(payload, sport, dport, src='192.0.2.1', dst='192.0.2.2'):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth_wrap(ip_pkt(17, udp, src, dst))

class Tcp:
    '''A TCP connection that tracks sequence numbers.'''
    def __init__(self, a, ap, b, bp):
        self.a, self.ap, self.b, self.bp = a, ap, b, bp
        self.seq = {0: 1000, 1: 5000}
    def seg(self, payload, d=0, flags=0x18, advance=True):
        if d == 0: s, sp, t, tp = self.a, self.ap, self.b, self.bp
        else: s, sp, t, tp = self.b, self.bp, self.a, self.ap
        seq, ack = self.seq[d], self.seq[1 - d]
        tcp = struct.pack('>HHIIBBHHH', sp, tp, seq, ack, 0x50, flags, 8192, 0, 0) + payload
        if advance:
            self.seq[d] += len(payload) + (1 if flags & 3 else 0)
        return eth_wrap(ip_pkt(6, tcp, s, t))
    def handshake(self):
        return [self.seg(b'', 0, 0x02), self.seg(b'', 1, 0x12), self.seg(b'', 0, 0x10)]

def write_pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + i, 0, len(fr), len(fr)))
            f.write(fr)

# ---- pcapng ----
def _blk(btype, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', btype, n) + body + b'\0' * pad + struct.pack('<I', n)

def write_pcapng(name, ifaces, frames):
    '''ifaces: list of linktypes; frames: list of (iface index, data).'''
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in ifaces:
        out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifc, d) in enumerate(frames):
        ts = 1000 * 1000000 + i * 100000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(d), len(d)) + d)
    with open(name, 'wb') as f:
        f.write(out)

def exp_pdu(dissector, payload):
    '''Exported PDU (linktype 252) carrying the named dissector.'''
    n = dissector.encode()
    tag = struct.pack('>HH', 12, (len(n) + 3) // 4 * 4) + n + b'\0' * ((-len(n)) % 4)
    return tag + struct.pack('>HH', 0, 0) + payload

def tlv(k, v):
    return bytes([len(k)]) + k + b'\x00' + bytes([len(v)]) + v

def sood(kind, fields, minlen=100):
    body = b'SOOD' + struct.pack('>H', kind) + b''.join(tlv(k, v) for k, v in fields)
    while len(body) < minlen:
        body += tlv(b'pad', b'x' * 8)      # an unknown key: neither string nor boolean field
    return body

Q, R = 0x0251, 0x0252
SRV = b'd52b2cb7-02c5-48fc-981b-a10f0aadd93b'
DISC = b'd7634b85-8190-470f-aa51-6cb5538dc1b9'

def tid(n): return ('0b1c2d3e-0000-4000-8000-%012x' % n).encode()

def main():
    out = sys.argv[1]; verbose = '-v' in sys.argv
    C, S, S2, BC = '192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.255'
    f = []
    def add(p, sport, dport, src, dst): f.append(udp_frame(p, sport, dport, src, dst))
    # 1-2: query for the Roon Server on broadcast, reply with most of the string fields
    add(sood(Q, [(b'_tid', tid(1)), (b'query_service_id', SRV)]), 40000, 9003, C, BC)
    add(sood(R, [(b'_tid', tid(1)), (b'service_id', SRV), (b'name', b'core'),
                 (b'display_version', b'2.0 (build 1)'), (b'unique_id', b'u-0001'),
                 (b'http_port', b'9330'), (b'https_port', b'9331'), (b'tcp_port', b'9332'),
                 (b'tcp_port_v2', b'9333'), (b'machine_id', b'm-0001'), (b'machine_name', b'host'),
                 (b'os_version', b'Linux'), (b'config_version', b'1'), (b'device_type', b'server'),
                 (b'device_class', b'core'), (b'protocol_hash', b'abc'), (b'protocol_version', b'1'),
                 (b'raat_version', b'2'), (b'user_id', b'user'), (b'marker', b'm'),
                 (b'code_signing_keys', b'k1,k2'), (b'is_dev', b'1')]), 9003, 40000, S, C)
    # 3-4: duplicate replies of the same transaction (reproducer of the 2-pass fix)
    add(sood(R, [(b'_tid', tid(1)), (b'name', b'core')]), 9003, 40000, S, C)
    add(sood(R, [(b'_tid', tid(1)), (b'name', b'core')]), 9003, 40000, S, C)
    # 5-6: query that is never answered; its tid in upper case, reply from another host with
    #      the same upper case tid but another port: no conversation, no match
    add(sood(Q, [(b'_tid', tid(2).upper()), (b'query_service_id', SRV)]), 40001, 9003, C, BC)
    add(sood(R, [(b'_tid', tid(2).upper()), (b'name', b'x')]), 9003, 40009, S, C)
    # 7-8: query with the discovery service id: the reply comes from an ephemeral port and is
    #      found through the conversation; the reply has an upper case tid (case folded)
    add(sood(Q, [(b'_tid', tid(3)), (b'service_id', DISC.upper())]), 40002, 9003, C, S2)
    add(sood(R, [(b'_tid', tid(3).upper()), (b'service_id', DISC), (b'is_dev', b'0')]), 55555, 40002, S2, C)
    # 9-12: the other known service ids and an unknown one
    for i, sid in enumerate((b'00720724-5143-4a9b-abac-0e50cba674bb',
                             b'5a955bb8-9673-4f8d-9437-4c6b7b18fba8',
                             b'5e2042ad-9bc5-4508-be92-ff68f19bdc93',
                             b'b39fcfbc-17de-46c8-81ad-82a910747be0')):
        add(sood(Q, [(b'_tid', tid(10 + i)), (b'service_id', sid)]), 40010 + i, 9003, C, BC)
    add(sood(Q, [(b'_tid', tid(20)), (b'service_id', b'11111111-2222-3333-4444-555555555555')]),
        40020, 9003, C, BC)
    # 14: query without a service id: the name is the fallback "Unknown Roon Service"
    add(sood(Q, [(b'_tid', tid(21)), (b'name', b'nosid')]), 40021, 9003, C, BC)
    # 15: query without a tid (no tracking, so only UDP's own conversation exists), 16: reply with a
    #     tid to it: the conversation found has no Roon data
    add(sood(Q, [(b'query_service_id', SRV)]), 40022, 9003, C, BC)
    add(sood(R, [(b'_tid', tid(22)), (b'service_id', SRV)]), 9003, 40022, S, C)
    # 17: reply whose tid was never queried
    add(sood(R, [(b'_tid', tid(99)), (b'service_id', SRV)]), 9003, 40000, S, C)
    # 18: a reply to a conversation that has no Roon data (no request seen)
    add(sood(R, [(b'_tid', tid(98))]), 9003, 41999, S, '192.0.2.77')
    # 19-21: not Roon: too short, wrong marker, unknown message type
    add(b'SOOD\x02\x51' + b'short', 40030, 9003, C, BC)
    add(b'XXXX\x02\x51' + b'\0' * 100, 40031, 9003, C, BC)
    add(b'SOOD\x02\x53' + b'\0' * 100, 40032, 9003, C, BC)
    write_pcap(os.path.join(out, 'roon_discovery-coverage.pcap'), f)
    mal = []
    def madd(p, sport=40100, dport=9003): mal.append(udp_frame(p, sport, dport, C, BC))
    body = sood(Q, [(b"_tid", tid(50))], 96)
    madd(body + b'\x30key')                       # key length past the end
    madd(body + b'\x03key\x00')                   # value length missing
    madd(body + b'\x03key\x00\x40val')            # value length past the end
    madd(body + b'\x03key')                       # no terminator and length
    madd(b'SOOD\x02\x51' + b'\0' * 3)             # shorter than the minimum, truncated in the capture
    write_pcap(os.path.join(out, 'roon_discovery-coverage-malformed.pcap'), mal)
    if verbose: print('main', len(f), 'malformed', len(mal))

main()
