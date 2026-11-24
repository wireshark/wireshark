#!/usr/bin/env python3
# Generates test/captures/zabbix_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic Zabbix protocol coverage captures.
Usage: mkzabbix.py <outdir> [-v]   (writes zabbix-coverage.pcap and
zabbix-coverage-malformed.pcap; -v prints the frame ranges).
Every TCP connection holds one request and its response (or a single
packet), so the conversation flags the dissector keeps do not depend on
the pass (see README, "Two passes")."""
import json
import socket
import struct
import sys
import os
import zlib


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def tcp_pkt(payload, sport, dport, seq, ack, flags=0x18, src='192.0.2.1', dst='192.0.2.2'):
    s = socket.inet_aton(src)
    d = socket.inet_aton(dst)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    ph = s + d + struct.pack('!BBH', 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, s, d)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + tcp


def write_pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1000 + i, (i * 1000) % 1000000, len(fr), len(fr)))
            f.write(fr)


def zbx(data, flags=1, large=False, compress=False, length=None, ulength=None):
    if isinstance(data, (dict, list)):
        data = json.dumps(data, separators=(',', ':'))
    if isinstance(data, str):
        data = data.encode()
    ulen = len(data)
    if compress:
        data = zlib.compress(data)
        flags |= 2
    if large:
        flags |= 4
    ln = len(data) if length is None else length
    ul = (ulen if compress else 0) if ulength is None else ulength
    if large:
        return b'ZBXD' + bytes([flags]) + struct.pack('<QQ', ln, ul) + data
    return b'ZBXD' + bytes([flags]) + struct.pack('<II', ln, ul) + data


class Cap:
    def __init__(self):
        self.frames = []
        self.ranges = []
        self.port = 40000
        self.cur = None

    def mark(self, name):
        if self.cur:
            self.ranges.append((self.cur[0], self.cur[1], len(self.frames)))
        self.cur = (name, len(self.frames) + 1)

    def end(self):
        self.mark(None)
        self.cur = None

    def conv(self, *msgs, port=10051, client='192.0.2.1', server='192.0.2.2', seg=None,
             server_first=False):
        """msgs: payloads; even index client to server, odd the reverse.
        seg: split every message into pieces of this many octets."""
        cport = self.port
        self.port += 1
        cseq = sseq = 1000
        for i, m in enumerate(msgs):
            pieces = [m] if not seg else [m[k:k + seg] for k in range(0, len(m), seg)]
            for p in pieces:
                if (i % 2 == 0) != server_first:
                    self.frames.append(tcp_pkt(p, cport, port, cseq, sseq, 0x18, client, server))
                    cseq += len(p)
                else:
                    self.frames.append(tcp_pkt(p, port, cport, sseq, cseq, 0x18, server, client))
                    sseq += len(p)
        return cport


OK = {'response': 'success'}
FAIL = {'response': 'failed', 'info': 'cannot parse'}


def build_main():
    c = Cap()
    c.mark('active agent: active checks (host, metadata, interface, ip, port, variant, version, session, revision), responses')
    c.conv(zbx({'request': 'active checks', 'host': 'agent01', 'host_metadata': 'linux web',
                'interface': 'eth0', 'ip': '192.0.2.77', 'port': 10050, 'variant': 2,
                'version': '7.0.1', 'session': 'abcdef0123456789', 'config_revision': 5,
                'hostmap_revision': 3}),
           zbx({'response': 'success', 'config_revision': 6, 'data': [
               {'key': 'system.uptime', 'itemid': 1, 'delay': '30s'}]}))
    c.conv(zbx({'request': 'active checks', 'host': 'agent02', 'ip': '2001:db8::77', 'port': 10050}),
           zbx(FAIL))
    c.conv(zbx({'request': 'active checks', 'host': 'agent03', 'ip': 'not-an-ip', 'port': 0}),
           zbx(OK))
    c.conv(zbx({'request': 'active checks', 'host': 'agent04', 'ip': '2001:zz::1'}),
           zbx(OK))
    c.conv(zbx({'request': 'active checks'}), zbx(OK))          # no host
    # redirect response from a proxy group
    c.conv(zbx({'request': 'active checks', 'host': 'agent05', 'version': '7.0.0'}),
           zbx({'response': 'success', 'redirect': {'revision': 7, 'address': '192.0.2.9:10051'}}))
    c.mark('active agent data (Agent 2 host, Agent 1 data[0].host, no host), heartbeat, commands')
    c.conv(zbx({'request': 'agent data', 'host': 'agent06', 'session': 's1', 'version': '7.0.0',
                'variant': 2, 'data': [{'id': 1, 'itemid': 1, 'value': '1'}]}), zbx(OK))
    c.conv(zbx({'request': 'agent data', 'session': 's2',
                'data': [{'host': 'agent07', 'key': 'a', 'value': '1'}]}), zbx(OK))
    c.conv(zbx({'request': 'agent data', 'data': []}), zbx(FAIL))
    c.conv(zbx({'request': 'agent data', 'data': [{'key': 'a'}]}), zbx(OK))
    c.conv(zbx({'request': 'active check heartbeat', 'host': 'agent08', 'heartbeat_freq': 60}),
           zbx(OK))
    c.conv(zbx({'request': 'active check heartbeat'}), zbx(OK))
    c.conv(zbx({'request': 'active checks', 'host': 'agent09'}),
           zbx({'response': 'success', 'commands': [{'command': 'echo hi', 'id': 1}]}))
    c.mark('passive agent: 7.0+ JSON, pre-7.0 plain text, ZBX_NOTSUPPORTED, zabbix.stats')
    c.conv(zbx({'request': 'passive checks', 'data': [{'key': 'agent.ping', 'timeout': 3}]}),
           zbx({'version': '7.0.0', 'variant': 1, 'data': [{'value': '1'}]}), port=10050)
    c.conv(zbx({'request': 'passive checks', 'data': []}), zbx(OK), port=10050)
    c.conv(b'ZBXD\x01' + struct.pack('<II', 10, 0) + b'agent.ping',
           b'ZBXD\x01' + struct.pack('<II', 1, 0) + b'1', port=10050)
    c.conv(zbx('system.uptime'), zbx(b'ZBX_NOTSUPPORTED\0Unsupported item key.'), port=10050)
    c.conv(zbx('vfs.fs.discovery'), zbx('{"data":[{"{#FSNAME}":"/"}]}'), port=10050)   # JSON, legacy
    c.conv(zbx({'request': 'zabbix.stats', 'type': 'queue'}),
           zbx({'response': 'success', 'data': {'queue': 3}}))
    c.mark('proxy: data, config, tasks, heartbeat and the old (3.2) requests')
    c.conv(zbx({'request': 'proxy data', 'host': 'proxy01', 'session': 'x', 'version': '7.0.0',
                'clock': 1, 'ns': 2}), zbx({'response': 'success', 'upload': 'enabled'}))
    c.conv(zbx({'request': 'proxy data'}), zbx({'session': 'x', 'version': '7.0.0'}))  # passive proxy
    c.conv(zbx({'request': 'proxy data'}), zbx({'response': 'success'}))
    c.conv(zbx({'request': 'proxy data', 'clock': 3}), zbx(OK))     # neither name nor bare
    for r in ('host availability', 'history data', 'discovery data', 'auto registration'):
        c.conv(zbx({'request': r, 'host': 'proxy02', 'data': []}), zbx(OK))
    c.conv(zbx({'request': 'proxy config', 'host': 'proxy03', 'version': '6.4.0'}),
           zbx({'full_sync': 1, 'config_revision': 10, 'data': {'hosts': {}}}))
    c.conv(zbx({'request': 'proxy config', 'host': 'proxy04'}),
           zbx({'globalmacro': {'fields': ['a']}, 'hosts': {'fields': ['b']}}))   # pre 6.4
    c.conv(zbx({'request': 'proxy config', 'host': 'proxy05', 'version': '7.0.0'}),
           zbx({'data': {'hosts': {'upsert': []}}, 'config_revision': 11}))        # incremental
    c.conv(zbx({'request': 'proxy config', 'host': 'proxy06'}), zbx({'data': {}}))  # no change
    c.conv(zbx({'request': 'proxy config', 'host': 'proxy07'}), zbx({'data': [1, 2]}))
    c.conv(zbx({'request': 'proxy config', 'host': 'proxy08'}), zbx({}))
    c.conv(zbx({'request': 'proxy config', 'host': 'proxy09', 'version': '7.0.0',
                'hostmap_revision': 4}), zbx(OK))
    c.conv(zbx({'request': 'proxy config'}), zbx({'full_sync': 1, 'data': {}}))      # passive
    c.conv(zbx({'request': 'proxy config'}), zbx({'data': {'hosts': {}}}))          # passive incr
    c.conv(zbx({'request': 'proxy config'}), zbx({'session': 's', 'version': '7.0.0'}))
    c.conv(zbx({'request': 'proxy config'}), zbx(OK))
    c.conv(zbx({'request': 'proxy tasks'}), zbx({'version': '7.0.0', 'tasks': []}))
    c.conv(zbx({'request': 'proxy tasks'}), zbx(OK))
    c.conv(zbx({'request': 'proxy heartbeat', 'host': 'proxy10', 'version': '6.0.0'}), zbx(OK))
    c.conv(zbx({'request': 'proxy heartbeat', 'version': '6.0.0'}), zbx(OK))     # no host (NULL name)
    c.conv(zbx({'request': 'proxy heartbeat', 'host': 'proxy11'}), zbx(FAIL))
    c.conv(zbx({'request': 'proxy data', 'host': 'proxy12'}),
           zbx({'proxy_group': {'hostmap_revision': 12}, 'response': 'success'}))
    c.mark('sender and the frontend')
    c.conv(zbx({'request': 'sender data', 'data': [{'host': 'h1', 'key': 'k', 'value': 'v'}]}),
           zbx({'response': 'success', 'info': 'processed: 1; failed: 0'}))
    c.conv(zbx({'request': 'sender data', 'data': []}), zbx(OK))
    c.conv(zbx({'request': 'sender data'}), zbx(FAIL))
    fe = ['status.get', 'queue.get', 'history.push', 'item.test', 'alert.send', 'report.test',
          'expressions.evaluate', 'command', 'device.init', 'device.offboard', 'cep.rule.reset']
    for r in fe:
        c.conv(zbx({'request': r, 'sid': 'abc'}), zbx({'response': 'success', 'data': {}}))
    c.conv(zbx({'request': 'something.else'}), zbx(OK))                    # unknown request
    c.conv(zbx({'response': 'success'}), zbx(OK))                           # response first
    # capture started in the middle: the first Zabbix packet comes from the server
    c.conv(zbx(OK), server_first=True)
    c.mark('flags and framing: compressed, large, both, reserved bits, reassembly, two PDUs')
    big = {'request': 'agent data', 'host': 'agent10',
           'data': [{'key': 'k%d' % i, 'value': 'v' * 20} for i in range(40)]}
    c.conv(zbx(big, compress=True), zbx(OK, compress=True))
    c.conv(zbx(OK, large=True), zbx(OK, large=True))
    c.conv(zbx(big, large=True, compress=True), zbx(OK, large=True, compress=True))
    c.conv(zbx({'request': 'active checks', 'host': 'agent11'}, flags=0x81), zbx(OK, flags=0x01))
    c.conv(zbx({'request': 'active checks', 'host': 'agent12'}, compress=True),
           zbx(b'ZBXD\x03' and OK))                                          # compressed request
    c.conv(zbx({'request': 'sender data', 'data': [{'host': 'seg'}]}), zbx(OK), seg=20)
    p1 = zbx({'request': 'status.get'})
    p2 = zbx({'request': 'queue.get'})
    c.conv(p1 + p2, zbx(OK))                                                 # two PDUs, one segment
    # a length field over 1 GB (the uncompressed length here) is not dissected further (warning)
    c.conv(zbx({'request': 'status.get'}, compress=True, ulength=0x50000000), zbx(OK))
    # a PDU that starts in the middle of a segment and ends in the next
    q = zbx({'request': 'passive checks', 'data': []})
    cp = c.conv(q + q[:20], port=10050)
    c.frames.append(tcp_pkt(q[20:], cp, 10050, 1000 + len(q) + 20, 1000))
    c.frames.append(tcp_pkt(zbx({'version': '7.0.0', 'data': []}), 10050, cp, 1000,
                            1000 + 2 * len(q), 0x18, '192.0.2.2', '192.0.2.1'))
    c.end()
    return c


def build_malformed():
    c = Cap()
    c.mark('not Zabbix, truncated and invalid JSON')
    c.conv(b'ZBXD\x00' + struct.pack('<II', 4, 0) + b'abcd')               # flag bit 0 clear
    c.conv(b'ZBXD\x01\x00\x00')                                             # shorter than a header
    c.conv(b'XBZD\x01' + struct.pack('<II', 4, 0) + b'abcd')                # wrong signature
    c.conv(zbx(b''))                                                        # empty payload
    c.conv(zbx(b'{"request":'))                                             # truncated JSON
    c.conv(zbx(b'{"request":"status.get"} trailing'))
    c.conv(zbx(b'[1,2,3]'), zbx(b'"text"'))
    c.conv(zbx(b'{"request":"active checks","host":'))
    c.conv(zbx({'request': 'agent data', 'host': 5, 'data': 7}))             # wrong types
    c.conv(zbx({'request': 5}))
    c.conv(zbx({'request': 'active checks', 'host': 'a', 'port': 99999, 'ip': 3, 'variant': 'x',
                'config_revision': 'y', 'hostmap_revision': [1]}))
    c.conv(zbx('agent.version'), zbx(b'ZBX_NOTSUPPORTED'), port=10050)       # no NUL, no message
    c.conv(zbx(b'\xff\xfe\xfd', compress=False), zbx(b'ZBX_NOTSUPPORTED' + b'\0' + b'\xff' * 5))
    c.conv(zbx({'request': 'status.get'}) + b'ZBXD\x00' + struct.pack('<II', 4, 0) + b'abcd')
    c.mark('compressed with bad data, length fields')
    c.conv(b'ZBXD\x03' + struct.pack('<II', 10, 100) + b'not zlib!!')       # not zlib
    c.conv(zbx({'request': 'status.get'}, compress=True, ulength=3))          # wrong ulength
    c.conv(zbx({'request': 'status.get'}, compress=True, ulength=300))
    c.conv(zbx({'request': 'status.get'}, length=5))                          # length shorter
    c.conv(zbx({'request': 'status.get'}, length=500))                        # length past the end
    c.conv(zbx({'request': 'status.get'}, large=True, length=500))
    c.mark('packets over 1 GB (the length is not backed by data)')
    c.conv(zbx({'request': 'status.get'}, length=0x40000001))
    c.conv(zbx({'request': 'status.get'}, large=True, length=0x40000001))
    c.conv(zbx({'request': 'status.get'}, large=True, compress=True, length=10, ulength=0x50000000))
    c.conv(zbx({'request': 'status.get'}, compress=True, length=10, ulength=0x50000000))
    c.conv(zbx(OK), zbx({'request': 'status.get'}), server_first=True)    # differs with -2
    c.mark('two requests in one connection (the conversation flags carry over: README, "Two passes")')
    p = c.port
    c.port += 1
    cs = ss = 1000
    for src, js in ((0, {'request': 'proxy heartbeat'}), (1, OK),
                    (0, {'request': 'sender data', 'data': [{'host': 'h1'}]}), (1, OK)):
        d = zbx(js)
        if src == 0:
            c.frames.append(tcp_pkt(d, p, 10051, cs, ss)); cs += len(d)
        else:
            c.frames.append(tcp_pkt(d, 10051, p, ss, cs, 0x18, '192.0.2.2', '192.0.2.1')); ss += len(d)
    c.end()
    return c


if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    m = build_main()
    write_pcap(os.path.join(out, 'zabbix-coverage.pcap'), m.frames)
    if '-v' in sys.argv:
        for name, a, b in m.ranges:
            print('%3d-%3d  %s' % (a, b, name))
        print(len(m.frames), 'frames')
    x = build_malformed()
    write_pcap(os.path.join(out, 'zabbix-coverage-malformed.pcap'), x.frames)
    if '-v' in sys.argv:
        for name, a, b in x.ranges:
            print('%3d-%3d  %s' % (a, b, name))
        print(len(x.frames), 'malformed frames')
