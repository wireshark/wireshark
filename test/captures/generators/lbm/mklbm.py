#!/usr/bin/env python3
# Generates test/captures/lbm_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for lbm-coverage.pcapng (topic resolution, LBT-RM/RU/TCP transports
# that give packet-lbm.c channels, topics and transport frame lists)
# Usage: mklbm.py <outdir>
import struct
import sys
import os

def link(items, end):
    """items: list of (nhdr id, bytearray). Sets each next_hdr; returns
    (first id, bytes)."""
    if not items:
        return end, b''
    out = b''
    for k, (nid, b) in enumerate(items):
        b[0] = items[k + 1][0] if k + 1 < len(items) else end
        out += bytes(b)
    return items[0][0], out

DATA, NONE = 0x00, 0xFF
T_MSG, T_EOT, T_PRORX, T_CNTL, T_RETRANS = 0x0, 0x1, 0x2, 0x8, 0xA

def msg(typ, items, data=b'', tidx=1, sqn=1, ver=0):
    data_type = typ in (T_MSG, T_PRORX, T_RETRANS)
    first, blob = link(items, DATA if data_type else NONE)
    if data_type:
        body = blob + data
        return struct.pack('!BBHII', (ver << 4) | typ, first, 12 + len(body), tidx, sqn) + body
    return struct.pack('!BBH', (ver << 4) | typ, first, 4 + len(blob)) + blob

def ctl(items):
    return msg(T_CNTL, items)

# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------
def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipaddr(a):
    return bytes(int(x) for x in a.split('.'))

def eth_ip(proto, l4, src, dst, ident):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), ident, 0, 64, proto, 0, ipaddr(src), ipaddr(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    if dst.startswith('224.'):
        dmac = b'\x01\x00\x5e' + bytes([int(dst.split('.')[1]) & 0x7f]) + bytes(int(x) for x in dst.split('.')[2:])
    else:
        dmac = b'\x02\x00\x00\x00\x00\x02'
    return dmac + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00' + ip + l4

class Net:
    ident = 0

def udp(payload, src, dst, sport, dport):
    Net.ident += 1
    l4 = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth_ip(17, l4, src, dst, Net.ident)

class Conn:
    """Minimal TCP connection state: handshake on first use, then data with
    consistent sequence and acknowledgement numbers."""
    conns = {}

    @staticmethod
    def seg(src, sport, dst, dport, payload, flags, seq, ack):
        Net.ident += 1
        opt = struct.pack('!BBH', 2, 4, 1460) if flags & 2 else b''
        h = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt
        pseudo = ipaddr(src) + ipaddr(dst) + struct.pack('!BBH', 0, 6, len(h) + len(payload))
        h = h[:16] + struct.pack('!H', csum(pseudo + h + payload)) + h[18:]
        return eth_ip(6, h + payload, src, dst, Net.ident)

def tcp(payload, src, dst, sport, dport):
    """Returns a list of frames: (handshake if new) + the data segment."""
    key = frozenset(((src, sport), (dst, dport)))
    out = []
    st = Conn.conns.get(key)
    if st is None:
        st = {(src, sport): 1000, (dst, dport): 5000}
        Conn.conns[key] = st
        out.append(Conn.seg(src, sport, dst, dport, b'', 0x02, st[(src, sport)], 0))
        st[(src, sport)] += 1
        out.append(Conn.seg(dst, dport, src, sport, b'', 0x12, st[(dst, dport)], st[(src, sport)]))
        st[(dst, dport)] += 1
        out.append(Conn.seg(src, sport, dst, dport, b'', 0x10, st[(src, sport)], st[(dst, dport)]))
    out.append(Conn.seg(src, sport, dst, dport, payload, 0x18, st[(src, sport)], st[(dst, dport)]))
    st[(src, sport)] += len(payload)
    return out

SRC, MC = '10.0.0.1', '224.10.10.10'
RM = dict(sqn=0)

def lbtrm_pdu(lbmc, session=0x11223344, sport=14390):
    RM['sqn'] += 1
    hdr_ = struct.pack('!BBHI', 0x00, 0x00, sport, session)
    data = struct.pack('!IIBBH', RM['sqn'], 0, 0, 0, 0)
    return hdr_ + data + lbmc

def lbtrm(lbmc, session=0x11223344, sport=14390):
    return udp(lbtrm_pdu(lbmc, session, sport), SRC, MC, sport, 14400)

def tir(name, transport, idx, body, ttl=16):
    return name.encode() + b'\0' + struct.pack('!BBHI', transport, len(body), ttl, idx) + body

def lbmr_tirs(tirs):
    return struct.pack('!BBH', 0x00, 0, len(tirs)) + b''.join(tirs)

def lbmr_frame(tirs, src=SRC):
    return udp(lbmr_tirs(tirs), src, '224.9.10.11', 50100, 12965)

def tir_lbtrm(name, idx, session=0x11223344, mcast='224.10.10.10', dport=14400, sport=14390, src=SRC):
    return tir(name, 0x10, idx, ipaddr(src) + ipaddr(mcast) + struct.pack('!IHH', session, dport, sport))

def tir_tcp(name, idx, port, sid=None, ip=SRC):
    if sid is None:
        return tir(name, 0x00, idx, ipaddr(ip) + struct.pack('!H', port))
    return tir(name, 0x00, idx, ipaddr(ip) + struct.pack('!IH', sid, port))

def tlv(tag, val):
    pad = (-len(val)) % 4
    return struct.pack('!HH', tag, len(val) + pad) + val + b'\0' * pad

def exported(name, payload, extra=b''):
    return tlv(12, name.encode()) + extra + struct.pack('!HH', 0, 0) + payload

def pcapng(path, frames):
    """frames: list of (linktype, bytes)."""
    def blk(t, body):
        body += b'\0' * ((-len(body)) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    lts = sorted(set(l for l, _ in frames))
    for l in lts:
        out += blk(1, struct.pack('<HHI', l, 0, 262144))
    for i, (l, f) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += blk(6, struct.pack('<IIIII', lts.index(l), ts >> 32, ts & 0xffffffff, len(f), len(f)) + f)
    open(path, 'wb').write(out)

def pcap_classic(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, (l, fr) in enumerate(frames):
            assert l == 1
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

# ---------------------------------------------------------------------------
# Frames
# ---------------------------------------------------------------------------
CLI = '10.0.0.2'

def tir_lbtru(name, idx, port=14380, sid=None, ip=SRC):
    if sid is None:
        return tir(name, 0x01, idx, ipaddr(ip) + struct.pack('!H', port))
    return tir(name, 0x01, idx, ipaddr(ip) + struct.pack('!IH', sid, port))

def tir_misc(name, transport, idx):
    # LBT-IPC / LBT-RDMA / LBT-SMX transports (shared memory or RDMA, only
    # advertised in topic resolution)
    if transport == 0x40:
        body = struct.pack('!IIH', 0x01020304, 0x0a0b0c0d, 7)
    elif transport == 0x20:
        body = ipaddr(SRC) + struct.pack('!IH', 0x0a0b0c0e, 5000)
    else:
        body = struct.pack('!IIH', 0x01020305, 0x0a0b0c0f, 8)
    return tir(name, transport, idx, body)

def lbtru_pdu(lbmc, sqn, flags=0, ptype=0):
    return struct.pack('!BBHII', ptype, 0, flags, sqn, 0) + lbmc

def lbtrm_rx(lbmc, sqn, flags_fec=0x00):
    hdr_ = struct.pack('!BBHI', 0x00, 0x00, 14390, 0x11223344)
    data = struct.pack('!IIBBH', sqn, 0, flags_fec, 0, 0)
    return udp(hdr_ + data + lbmc, SRC, MC, 14390, 14400)

def build_main():
    F = []
    def add(label, data, lt=1):
        data = data if isinstance(data, list) else [data]
        for k, d in enumerate(data):
            F.append((label if k == len(data) - 1 else 'tcp handshake for: ' + label, lt, d))
    # Topic resolution: one topic on each transport type
    add('LBMR TIR: LBT-RM topic.rm (index 1) and topic.rm2 (index 2)', lbmr_frame([tir_lbtrm('topic.rm', 1), tir_lbtrm('topic.rm2', 2)]))
    add('LBMR TIR: LBT-RM from a second source, same index', lbmr_frame([tir_lbtrm('topic.other', 1, session=0x99887766, mcast='224.10.10.11', sport=14391, src='10.0.0.3')], src='10.0.0.3'))
    add('LBMR TIR: LBT-TCP topic.tcp (14382), with session id topic.tcpsid (14383)',
        lbmr_frame([tir_tcp('topic.tcp', 5, 14382), tir_tcp('topic.tcpsid', 6, 14383, sid=0x4242)]))
    add('LBMR TIR: LBT-RU topic.ru (14380), with session id topic.rusid (14381)',
        lbmr_frame([tir_lbtru('topic.ru', 7, 14380), tir_lbtru('topic.rusid', 8, 14381, sid=0x5151)]))
    add('LBMR TIR: LBT-IPC, LBT-RDMA, LBT-SMX topics',
        lbmr_frame([tir_misc('topic.ipc', 0x40, 9), tir_misc('topic.rdma', 0x20, 10), tir_misc('topic.smx', 0x04, 11)]))
    add('LBMR TIR: LBT-RM topic again (same index, name already known)', lbmr_frame([tir_lbtrm('topic.rm', 1)]))
    # LBT-RM data on the transport: topic names, gaps, reordering, duplicates, retransmission
    RM['sqn'] = 0
    def rmdata(label, sqn, tidx=1, data=b'rm-data', flags_fec=0x00, session=0x11223344):
        add(label, lbtrm_rx(msg(T_MSG, [], data, tidx=tidx, sqn=sqn), sqn, flags_fec))
    rmdata('LBT-RM data sqn 1 (topic.rm)', 1)
    rmdata('LBT-RM data sqn 2 (topic.rm2)', 2, tidx=2)
    rmdata('LBT-RM data sqn 5, gap', 5)
    rmdata('LBT-RM data sqn 3 out of order', 3)
    rmdata('LBT-RM data sqn 3 duplicate', 3)
    rmdata('LBT-RM data sqn 4 retransmission', 4, flags_fec=0x20)
    rmdata('LBT-RM data sqn 6, unknown topic index', 6, tidx=99)
    # same data via another source with the same topic index but a different transport
    add('LBT-RM data from the second source (topic.other)',
        udp(struct.pack('!BBHI', 0, 0, 14391, 0x99887766) + struct.pack('!IIBBH', 1, 0, 0, 0, 0) + msg(T_MSG, [], b'other', tidx=1, sqn=1),
            '10.0.0.3', '224.10.10.11', 14391, 14400))
    # LBT-RU
    ru = lambda lbmc, sqn, flags=0: udp(lbtru_pdu(lbmc, sqn, flags), SRC, CLI, 14380, 14360)
    add('LBT-RU data sqn 1 (topic.ru)', ru(msg(T_MSG, [], b'ru-data', tidx=7, sqn=1), 1))
    add('LBT-RU data sqn 2', ru(msg(T_MSG, [], b'ru-data 2', tidx=7, sqn=2), 2))
    add('LBT-RU data sqn 2 retransmission', ru(msg(T_MSG, [], b'ru-data 2', tidx=7, sqn=2), 2, 0x4000))
    add('LBT-RU data sqn 5 gap', ru(msg(T_MSG, [], b'ru-data 5', tidx=7, sqn=5), 5))
    add('LBT-RU data sqn 4 out of order', ru(msg(T_MSG, [], b'ru-data 4', tidx=7, sqn=4), 4))
    # LBT-TCP: transport (source port in the source range) and UIM streams
    def conn(label, m, a, ap, b, bp):
        add(label, tcp(m, a, b, ap, bp))
    conn('LBT-TCP client -> source 14382', ctl([(0x14, bytearray(struct.pack('!BBBB', 0, 24, 0xf0, 1) + b'\x01' * 20))]), CLI, 50010, SRC, 14382)
    conn('LBT-TCP source -> client data (topic.tcp)', msg(T_MSG, [], b'tcp-data', tidx=5, sqn=1), SRC, 14382, CLI, 50010)
    conn('LBT-TCP source -> client data 2', msg(T_MSG, [], b'tcp-data 2', tidx=5, sqn=2), SRC, 14382, CLI, 50010)
    conn('LBT-TCP second client -> source 14382', ctl([(0x14, bytearray(struct.pack('!BBBB', 0, 24, 0xf0, 1) + b'\x01' * 20))]), '10.0.0.4', 50011, SRC, 14382)
    conn('LBT-TCP source -> second client data', msg(T_MSG, [], b'tcp-data 3', tidx=5, sqn=3), SRC, 14382, '10.0.0.4', 50011)
    conn('LBT-TCP client -> source 14383 (session id)', ctl([(0x14, bytearray(struct.pack('!BBBB', 0, 24, 0xf0, 1) + b'\x01' * 20))]), CLI, 50012, SRC, 14383)
    sid = bytearray(struct.pack('!BBHI', 0, 8, 0x8000, 0x4242))
    conn('LBT-TCP source -> client data with TCP_SID (topic.tcpsid)', msg(T_MSG, [(0x6B, sid)], b'sid-data', tidx=6, sqn=1), SRC, 14383, CLI, 50012)
    conn('LBT-TCP source -> client data (topic.tcpsid)', msg(T_MSG, [], b'sid-data 2', tidx=6, sqn=2), SRC, 14383, CLI, 50012)
    conn('LBT-TCP UIM stream message (request port range)', msg(T_MSG, [], b'uim', tidx=0, sqn=1), SRC, 14391, CLI, 50013)
    conn('LBT-TCP UIM stream message reply', msg(T_MSG, [], b'uim reply', tidx=0, sqn=1), CLI, 50013, SRC, 14391)
    # LBMPDM over TCP creates a TCP channel
    pdm = struct.pack('!4sBBBBII', b'\xa7\x1c\xca\xfe', 0, 0xFF, 1, 0, 77, 16)
    conn('LBMPDM-TCP stream', pdm, SRC, 14375, CLI, 50020)
    conn('LBMPDM-TCP stream, second message', pdm, SRC, 14375, CLI, 50020)
    return F

def build_unknown_transport():
    """LBT-TCP frames for source ports without topic resolution: the channel
    is only known on the second pass, so the output differs between one and
    two passes and the frames are not part of the main capture."""
    F = []
    def add(label, data):
        for k, d in enumerate(data):
            F.append((label if k == len(data) - 1 else 'tcp handshake for: ' + label, 1, d))
    sid = lambda s: (0x6B, bytearray(struct.pack('!BBHI', 0, 8, 0x8000, s)))
    add('tcp without TIR: client -> source', tcp(ctl([(0x14, bytearray(struct.pack('!BBBB', 0, 24, 0xf0, 1) + b'\x01' * 20))]), CLI, SRC, 52000, 14386))
    add('tcp without TIR: source -> client with TCP_SID', tcp(msg(T_MSG, [sid(0x7001)], b'sid data', tidx=9, sqn=1), SRC, CLI, 14386, 52000))
    add('tcp without TIR: source -> client', tcp(msg(T_MSG, [], b'sid data 2', tidx=9, sqn=2), SRC, CLI, 14386, 52000))
    add('tcp without TIR: client -> source with TCP_SID', tcp(msg(T_MSG, [sid(0x7002)], b'client sid data', tidx=9, sqn=1), CLI, SRC, 52001, 14387))
    add('tcp without TIR: client -> source', tcp(msg(T_MSG, [], b'client data', tidx=9, sqn=2), CLI, SRC, 52001, 14387))
    add('tcp without TIR: source -> client', tcp(msg(T_MSG, [], b'source data', tidx=9, sqn=3), SRC, CLI, 14387, 52001))
    add('tcp without TIR: unknown source, data with TCP_SID', tcp(msg(T_MSG, [(0x6B, bytearray(struct.pack('!BBHI', 0, 8, 0x8000, 0x7777)))], b'no-tir', tidx=3, sqn=1), '10.0.0.5', CLI, 14384, 50014))
    return F

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    frames = build_main()
    pcapng(os.path.join(out, 'lbm-coverage.pcapng'), [(l, d) for _, l, d in frames])
    mal = build_unknown_transport()
    pcapng(os.path.join(out, 'lbm-coverage-malformed.pcapng'), [(l, d) for _, l, d in mal])
    with open(os.path.join(out, 'frames.txt'), 'w') as f:
        for i, (lab, _, d) in enumerate(frames, 1):
            f.write('main %d %s\n' % (i, lab))
        for i, (lab, _, d) in enumerate(mal, 1):
            f.write('pass-dependent %d %s\n' % (i, lab))
    print(len(frames), len(mal))

main()
