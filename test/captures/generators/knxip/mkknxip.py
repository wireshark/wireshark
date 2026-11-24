#!/usr/bin/env python3
# Generates test/captures/knxip_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the KNXnet/IP (KNX/IP) captures.
Usage: mkknxip.py <outdir>.
Writes knxip-coverage.pcap and knxip-coverage-malformed.pcap (the capture for
packet-knxip_decrypt.c is made by ../knxip_decrypt-coverage/mkknxip_decrypt.py).
No keys or valid MACs are computed: the secure frames carry placeholder bytes."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
import random
from _lib import Pcap

C, S = '192.0.2.10', '192.0.2.20'
MC = '224.0.23.12'
KP = 3671

u16 = lambda v: struct.pack('!H', v)
def ip4(s): return bytes(map(int, s.split('.')))

def hdr(svc, body=b'', hl=6, ver=0x10, total=None):
    return struct.pack('!BBHH', hl, ver, svc, (6 + len(body)) if total is None else total) + body

def hpai(ip='192.0.2.10', port=KP, proto=1, ln=8):
    return struct.pack('!BB', ln, proto) + ip4(ip) + u16(port)
HPAI_TCP = hpai('0.0.0.0', 0, 2)

def knxaddr(a, b, c): return u16((a << 12) | (b << 8) | c)

# ---- DIBs --------------------------------------------------------------
def dib(t, body): return bytes([2 + len(body), t]) + body
def dib_devinfo(medium=0x02, status=0, addr=(1, 1, 0), project=0x0011, serial=b'\x00\x01\x02\x03\x04\x05',
                mc='224.0.23.12', mac=b'\x02\x00\x00\x00\x00\x20', name=b'Test KNX IP Interface'):
    return dib(1, bytes([medium, status]) + knxaddr(*addr) + u16(project) + serial + ip4(mc) + mac + name.ljust(30, b'\0'))
def dib_supp(pairs=((2, 1), (3, 1), (4, 1), (5, 1))): return dib(2, b''.join(bytes(p) for p in pairs))
def dib_ipconfig(ip='192.0.2.20', mask='255.255.255.0', gw='192.0.2.1', caps=0x07, assign=0x01):
    return dib(3, ip4(ip) + ip4(mask) + ip4(gw) + bytes([caps, assign]))
def dib_curconfig(ip='192.0.2.20', mask='255.255.255.0', gw='192.0.2.1', dhcp='192.0.2.2', assign=0x04, res=0):
    return dib(4, ip4(ip) + ip4(mask) + ip4(gw) + ip4(dhcp) + bytes([assign, res]))
def dib_knxaddr(addrs=((1, 1, 0), (1, 1, 1), (1, 1, 2))): return dib(5, b''.join(knxaddr(*a) for a in addrs))
def dib_secfam(pairs=((4, 1), (5, 1), (9, 1))): return dib(6, b''.join(bytes(p) for p in pairs))
def dib_tunnel(apdu=254, slots=(((1, 1, 1), 0x01), ((1, 1, 2), 0x02), ((1, 1, 3), 0x04), ((1, 1, 4), 0x07))):
    return dib(7, u16(apdu) + b''.join(knxaddr(*a) + b'\x00' + bytes([f]) for a, f in slots))
def dib_ext(status=0x05, res=0, mem=0x0100, apdu=0x00fe): return dib(8, bytes([status, res]) + u16(mem) + u16(apdu))
def dib_mfr(code=0x00a5, data=b'\x01\x02\x03\x04'): return dib(0xFE, u16(code) + data)

# ---- selectors, SRPs ---------------------------------------------------
SEL_PROG = bytes([2, 1])
SEL_MAC = bytes([8, 2]) + b'\x02\x00\x00\x00\x00\x20'
def srp(t, data=b'', mandatory=True): return bytes([2 + len(data), t | (0x80 if mandatory else 0)]) + data

# ---- cEMI ----------------------------------------------------------------
CEMI_IND = bytes.fromhex('2900bce01101090101' '0081')          # L_Data.ind, GroupValueWrite 1/1/1
CEMI_REQ = bytes.fromhex('1100bce011010901' '01' '0080')       # L_Data.req
CEMI_PROPREAD = bytes.fromhex('fc000801 0a 1001'.replace(' ', ''))  # M_PropRead.req
CEMI_PROPRESP = bytes.fromhex('fb000801 0a 1001 0001'.replace(' ', ''))
CEMI_SBC = bytes.fromhex('2900b0e01101000001' '0081')

def cnhdr(ch=1, seq=0, third=0): return bytes([4, ch, seq, third])

# ---- the frames ----------------------------------------------------------
def frames():
    """list of (name, transport, direction, payload, dst) ; transport 'udp' or 'tcp'"""
    F = []
    def add(name, payload, tr='udp', d='>', dst=None):
        if tr in ('<', '>'):
            tr, d = 'udp', tr
        F.append((name, tr, d, payload, dst))

    # CORE
    add('SearchReq', hdr(0x0201, hpai('192.0.2.10', 50001)), dst=MC)
    add('SearchReq to unicast', hdr(0x0201, hpai('0.0.0.0', 0)))
    add('SearchReqExt', hdr(0x020B, hpai('192.0.2.10', 50001)), dst=MC)
    add('SearchReqExt prog', hdr(0x020B, hpai('192.0.2.10', 50001) + srp(1)), dst=MC)
    add('SearchReqExt mac', hdr(0x020B, hpai('192.0.2.10', 50001) + srp(2, b'\x02\x00\x00\x00\x00\x20')), dst=MC)
    add('SearchReqExt svc', hdr(0x020B, hpai('192.0.2.10', 50001) + srp(3, bytes([4, 1]))), dst=MC)
    add('SearchReqExt dibs', hdr(0x020B, hpai('192.0.2.10', 50001) + srp(4, bytes([1, 2, 7, 8, 0xfe]))), dst=MC)
    add('SearchReqExt all', hdr(0x020B, hpai('192.0.2.10', 50001) + srp(1, mandatory=False) +
        srp(2, b'\x02\x00\x00\x00\x00\x20') + srp(3, bytes([9, 1])) + srp(4, bytes([1, 2])) + srp(0x10, b'\x01\x02', False)), dst=MC)
    add('SearchResp', hdr(0x0202, hpai('192.0.2.20') + dib_devinfo() + dib_supp()), '>', '<')
    add('SearchResp full', hdr(0x0202, hpai('192.0.2.20') + dib_devinfo(medium=0x20, status=1, name=b'Secure IP Router') + dib_supp(((2, 2), (3, 1), (4, 2), (5, 1), (9, 1), (0x0a, 1))) +
        dib_ipconfig() + dib_curconfig() + dib_knxaddr() + dib_secfam() + dib_tunnel() + dib_ext() + dib_mfr()), '>', '<')
    add('SearchRespExt', hdr(0x020C, hpai('192.0.2.20') + dib_devinfo(medium=0x10) + dib_supp() + dib_tunnel()), '>', '<')
    add('SearchRespExt minimal', hdr(0x020C, hpai('192.0.2.20')), '>', '<')
    add('DescrReq', hdr(0x0203, hpai('192.0.2.10', 50002)))
    add('DescrResp', hdr(0x0204, dib_devinfo(medium=0x01) + dib_supp(((2, 1), (3, 1)))), '>', '<')
    add('DescrResp more', hdr(0x0204, dib_devinfo(medium=0x04, status=1) + dib_supp(((2, 1), (3, 1), (4, 1), (7, 1), (6, 1))) +
        dib_ipconfig(caps=0x01, assign=0x0f) + dib_curconfig(assign=0x08) + dib_knxaddr(((15, 15, 255),)) + dib_secfam(((4, 1),)) + dib_tunnel(slots=()) + dib_ext(status=0) + dib_mfr(data=b'')), '>', '<')
    add('DescrResp medium PL132', hdr(0x0204, dib_devinfo(medium=0x08) + dib_supp(((2, 1), (3, 1)))), '>', '<')
    add('ConnectReq tunnel', hdr(0x0205, hpai('192.0.2.10', 50003) + hpai('192.0.2.10', 50004) + bytes([4, 4, 2, 0])))
    add('ConnectReq tunnel addr', hdr(0x0205, hpai('192.0.2.10', 50003) + hpai('192.0.2.10', 50004) + bytes([6, 4, 2, 0]) + knxaddr(1, 1, 250)))
    add('ConnectReq tunnel raw', hdr(0x0205, hpai('192.0.2.10', 50003) + hpai('192.0.2.10', 50004) + bytes([4, 4, 4, 0])))
    add('ConnectReq tunnel busmon', hdr(0x0205, hpai('192.0.2.10', 50003) + hpai('192.0.2.10', 50004) + bytes([4, 4, 0x80, 0])))
    add('ConnectReq mgmt', hdr(0x0205, hpai('192.0.2.10', 50003) + hpai('192.0.2.10', 50004) + bytes([2, 3])))
    add('ConnectReq remlog', hdr(0x0205, hpai('192.0.2.10', 50003) + hpai('192.0.2.10', 50004) + bytes([2, 6])))
    add('ConnectReq remconf', hdr(0x0205, hpai('192.0.2.10', 50003) + hpai('192.0.2.10', 50004) + bytes([2, 7])))
    add('ConnectReq objsvr', hdr(0x0205, hpai('192.0.2.10', 50003) + hpai('192.0.2.10', 50004) + bytes([2, 8])))
    add('ConnectResp tunnel', hdr(0x0206, bytes([1, 0]) + hpai('192.0.2.20') + bytes([4, 4]) + knxaddr(1, 1, 250)), '>', '<')
    add('ConnectResp mgmt', hdr(0x0206, bytes([2, 0]) + hpai('192.0.2.20') + bytes([2, 3])), '>', '<')
    add('ConnectResp remlog', hdr(0x0206, bytes([3, 0]) + hpai('192.0.2.20') + bytes([2, 6])), '>', '<')
    add('ConnectResp error', hdr(0x0206, bytes([0, 0x24])), '>', '<')
    add('ConnectResp error 2', hdr(0x0206, bytes([0, 0x22])), '>', '<')
    add('ConnStateReq', hdr(0x0207, bytes([1, 0]) + hpai('192.0.2.10', 50003)))
    add('ConnStateResp', hdr(0x0208, bytes([1, 0])), '>', '<')
    add('ConnStateResp error', hdr(0x0208, bytes([1, 0x21])), '>', '<')
    add('DisconnectReq', hdr(0x0209, bytes([1, 0]) + hpai('192.0.2.10', 50003)))
    add('DisconnectResp', hdr(0x020A, bytes([1, 0])), '>', '<')
    add('DisconnectResp error', hdr(0x020A, bytes([9, 0x21])), '>', '<')
    # MANAGEMENT
    add('ConfigReq', hdr(0x0310, cnhdr(2, 0) + CEMI_PROPREAD))
    add('ConfigAck', hdr(0x0311, cnhdr(2, 0, 0)), '>', '<')
    add('ConfigReq resp', hdr(0x0310, cnhdr(2, 1) + CEMI_PROPRESP), '>', '<')
    add('ConfigAck error', hdr(0x0311, cnhdr(2, 1, 0x29)), '>', '<')
    # TUNNELING
    add('TunnelReq', hdr(0x0420, cnhdr(1, 0) + CEMI_REQ))
    add('TunnelAck', hdr(0x0421, cnhdr(1, 0, 0)), '>', '<')
    add('TunnelReq ind', hdr(0x0420, cnhdr(1, 0) + CEMI_IND), '>', '<')
    add('TunnelAck 2', hdr(0x0421, cnhdr(1, 0, 0)))
    add('TunnelAck error', hdr(0x0421, cnhdr(1, 1, 0x29)), '>', '<')
    for fid in range(1, 9):
        add('FeatureGet %d' % fid, hdr(0x0422, cnhdr(1, fid) + bytes([fid, 0])))
        add('FeatureResp %d' % fid, hdr(0x0423, cnhdr(1, fid) + bytes([fid, 0]) + u16(0x0100 + fid)), '>', '<')
        add('FeatureSet %d' % fid, hdr(0x0424, cnhdr(1, fid) + bytes([fid, 0]) + u16(0x0200 + fid)))
        add('FeatureInfo %d' % fid, hdr(0x0425, cnhdr(1, fid) + bytes([fid, 0]) + b'\x01'), '>', '<')
    add('FeatureResp error', hdr(0x0423, cnhdr(1, 9) + bytes([2, 0xf1])), '>', '<')
    add('FeatureResp error value', hdr(0x0423, cnhdr(1, 9) + bytes([2, 0xf0]) + b'\x01'), '>', '<')
    add('FeatureGet unknown', hdr(0x0422, cnhdr(1, 10) + bytes([0x42, 0])))
    add('FeatureResp not supported', hdr(0x0423, cnhdr(1, 10) + bytes([0x42, 0xf0])), '>', '<')
    # ROUTING
    add('RoutingInd', hdr(0x0530, CEMI_IND), dst=MC)
    add('RoutingLoss', hdr(0x0531, bytes([4, 0]) + u16(3)), dst=MC)
    add('RoutingBusy', hdr(0x0532, bytes([6, 0]) + u16(100) + u16(0)), dst=MC)
    add('RoutingBusy control', hdr(0x0532, bytes([6, 0]) + u16(50) + u16(0x0100)), dst=MC)
    add('RoutingSBC', hdr(0x0533, CEMI_SBC), dst=MC)
    # REMOTE DIAG AND CONFIG
    add('RemoteDiagReq', hdr(0x0740, hpai('192.0.2.10', 50005) + SEL_PROG), dst=MC)
    add('RemoteDiagReq mac', hdr(0x0740, hpai('192.0.2.10', 50005) + SEL_MAC), dst=MC)
    add('RemoteDiagResp', hdr(0x0741, SEL_MAC + dib_ipconfig() + dib_curconfig() + dib_knxaddr()), '>', '<')
    add('RemoteDiagResp prog', hdr(0x0741, SEL_PROG + dib_ipconfig() + dib_curconfig() + dib_knxaddr() + dib_devinfo()), '>', '<')
    add('RemoteConfigReq', hdr(0x0742, hpai('192.0.2.10', 50005) + SEL_MAC + dib_ipconfig(assign=0x01)), dst=MC)
    add('RemoteConfigReq addr', hdr(0x0742, hpai('192.0.2.10', 50005) + SEL_PROG + dib_knxaddr(((1, 1, 77),)) + dib_ipconfig()), dst=MC)
    add('RemoteResetReq restart', hdr(0x0743, SEL_MAC + bytes([1, 0])), dst=MC)
    add('RemoteResetReq master', hdr(0x0743, SEL_PROG + bytes([2, 0])), dst=MC)
    # Unknown service family and type (no data), unknown DIB type
    add('Unknown family', hdr(0x0a01))
    add('Unknown type', hdr(0x0299))
    add('Unknown DIB', hdr(0x0204, dib_devinfo() + dib_supp() + dib(0x42, b'\x01\x02')), '>', '<')
    # SECURE (placeholder bytes only)
    key = bytes((i * 7 + 1) & 0xff for i in range(32))
    add('SessionReq', hdr(0x0951, HPAI_TCP + key), 'tcp')
    add('SessionReq udp', hdr(0x0951, hpai('192.0.2.10', 50006) + key))
    add('SessionResp', hdr(0x0952, u16(1) + key + bytes(range(16))), 'tcp', '<')
    add('SessionResp udp', hdr(0x0952, u16(2) + key + bytes(range(16))), 'udp', '<')
    add('SessionAuth', hdr(0x0953, bytes([0, 1]) + bytes(range(16))), 'tcp')
    add('SessionStatus', hdr(0x0954, bytes([0, 0])), 'tcp', '<')
    for st in range(1, 6):
        add('SessionStatus %d' % st, hdr(0x0954, bytes([st, 0])), 'tcp', '<')
    add('SessionStatus unknown', hdr(0x0954, bytes([9, 0])), 'tcp', '<')
    for sess, tag in ((1, 0), (0, 0x1234), (0x7fff, 0xffff)):
        add('SecureWrapper %d' % sess, hdr(0x0950, u16(sess) + b'\x00\x00\x00\x00\x00\x01' + b'\x00\x01\x02\x03\x04\x05' + u16(tag) + bytes(range(48))), 'tcp')
    add('SecureWrapper udp', hdr(0x0950, u16(0) + b'\x00\x00\x00\x00\x00\x02' + b'\x00\x01\x02\x03\x04\x05' + u16(0xf001) + bytes(range(16, 64))), dst=MC)
    add('TimerNotify', hdr(0x0955, b'\x00\x00\x00\x00\x00\x10' + b'\x00\x01\x02\x03\x04\x05' + u16(0x0001) + bytes(range(16))), dst=MC)
    add('TimerNotify 2', hdr(0x0955, b'\x00\x00\x00\x00\x01\x00' + b'\x00\x01\x02\x03\x04\x05' + u16(0xffff) + bytes(range(100, 116))), dst=MC)
    return F

def build_pcap(F, path, tcp_ports=None):
    p = Pcap()
    tcp_open = {}
    nt = 0
    for name, tr, d, payload, dst in F:
        if tr == 'udp':
            if d == '>':
                p.udp(C, dst or S, 50000, KP, payload)
            else:
                p.udp(S, C, KP, 50000, payload)
        else:
            sp = 52000
            if sp not in tcp_open:
                p.tcp(C, S, sp, KP, b'', flags=0x02); p.tcp(S, C, KP, sp, b'', flags=0x12); p.tcp(C, S, sp, KP, b'', flags=0x10)
                tcp_open[sp] = 1
            if d == '>':
                p.tcp(C, S, sp, KP, payload)
            else:
                p.tcp(S, C, KP, sp, payload)
    return p

def write_trunc(p, path):
    # like Pcap.write, but frames may be (ts, data, original length): a frame captured with a short snap length
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for fr in p.frames:
            ts, d = fr[0], fr[1]
            orig = fr[2] if len(fr) > 2 else len(d)
            f.write(struct.pack('<IIII', int(ts), int((ts % 1) * 1e6), len(d), orig) + d)

def mk_main(path):
    F = frames()
    p = build_pcap(F, path)
    # Several PDUs in one UDP datagram, and in one TCP segment
    two = hdr(0x0208, bytes([1, 0])) + hdr(0x0208, bytes([2, 0x21]))
    p.udp(S, C, KP, 50000, two)
    p.udp(S, C, KP, 50000, hdr(0x0206, bytes([0, 0x24])) + hdr(0x020A, bytes([1, 0])) + hdr(0x0208, bytes([3, 0])))
    sp = 52001
    p.tcp(C, S, sp, KP, b'', flags=0x02); p.tcp(S, C, KP, sp, b'', flags=0x12); p.tcp(C, S, sp, KP, b'', flags=0x10)
    A = hdr(0x0207, bytes([1, 0]) + HPAI_TCP)
    B = hdr(0x0209, bytes([1, 0]) + HPAI_TCP)
    p.tcp(C, S, sp, KP, A + B)
    # PDU over two segments, and a header split
    p.tcp(C, S, sp, KP, A[:5])
    p.tcp(C, S, sp, KP, A[5:])
    big = hdr(0x0204, dib_devinfo() + dib_supp())
    p.tcp(S, C, KP, sp, big[:30])
    p.tcp(S, C, KP, sp, big[30:])
    # TCP connect request/response with the TCP HPAI
    p.tcp(C, S, sp, KP, hdr(0x0205, HPAI_TCP + HPAI_TCP + bytes([4, 4, 2, 0])))
    p.tcp(S, C, KP, sp, hdr(0x0206, bytes([1, 0]) + HPAI_TCP + bytes([4, 4]) + knxaddr(1, 1, 250)))
    p.tcp(C, S, sp, KP, hdr(0x0420, cnhdr(1, 0) + CEMI_REQ))
    p.tcp(S, C, KP, sp, hdr(0x0421, cnhdr(1, 0, 0)))
    p.write(path)

def mk_mal(path):
    F = frames()
    rnd = random.Random(26)
    out = []
    def u(payload, dst=None): out.append(('udp', payload))
    # header variants
    base = hdr(0x0208, bytes([1, 0]))
    for hl in (0, 1, 2, 3, 4, 5, 7, 0x20, 0xff):
        u(hdr(0x0208, bytes([1, 0]), hl=hl))
    u(hdr(0x0208, bytes([1, 0]), ver=0x20))
    u(hdr(0x0208, bytes([1, 0]), ver=0x00))
    u(hdr(0x0208, bytes([1, 0]), total=4))
    u(hdr(0x0208, bytes([1, 0]), total=200))
    u(hdr(0x0208, bytes([1, 0]), total=7))
    u(hdr(0x0208, bytes([1, 0]) + b'\x00\x00'))               # trailing data
    u(hdr(0x0999, b'\x01\x02'))                               # unknown family
    u(hdr(0x0299, b'\x01\x02'))                               # unknown service in a known family
    u(hdr(0x0599, b'\x01'))
    u(b'\x06')
    u(b'\x06\x10')
    u(b'\x06\x10\x02')
    u(b'\x06\x10\x02\x08')
    u(b'\x06\x10\x02\x08\x00')
    u(b'\x06\x10\x02\x08\x00\x06')
    u(b'\x00\x10\x02\x08\x00\x06')
    u(b'\x04\x10\x02\x08')
    u(b'\x02\x10')
    # truncation sweep: the total length follows the cut
    for name, tr, d, payload, dst in F:
        for n in range(6, len(payload)):
            u(hdr(struct.unpack('!H', payload[2:4])[0], payload[6:n]))
    # mutations of single bytes
    vals = (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x10, 0x7f, 0x80, 0xff)
    for name, tr, d, payload, dst in F:
        svc = struct.unpack('!H', payload[2:4])[0]
        body = payload[6:]
        if not body:
            continue
        for _ in range(14):
            b = bytearray(body)
            b[rnd.randrange(len(b))] = rnd.choice(vals)
            u(hdr(svc, bytes(b)))
        for _ in range(2):
            b = bytearray(body)
            for _ in range(3):
                b[rnd.randrange(len(b))] = rnd.choice(vals)
            u(hdr(svc, bytes(b)))
    # extra data after every structure
    for name, tr, d, payload, dst in F:
        svc = struct.unpack('!H', payload[2:4])[0]
        u(hdr(svc, payload[6:] + b'\x55\xaa'))
    # CRI/CRD with extra octets, tunneling information with odd and short lengths
    cr = hpai('192.0.2.10', 50003) + hpai('192.0.2.10', 50004)
    u(hdr(0x0205, cr + bytes([8, 4, 2, 0]) + knxaddr(1, 1, 250) + b'\x01\x02'))
    u(hdr(0x0205, cr + bytes([5, 4, 2, 0, 7])))
    u(hdr(0x0205, cr + bytes([3, 4, 2])))
    u(hdr(0x0205, cr + bytes([4, 4, 9, 1])))
    u(hdr(0x0205, cr + bytes([4, 4, 2, 7])))
    u(hdr(0x0205, cr + bytes([4, 9, 0, 0])))
    u(hdr(0x0205, cr + bytes([3, 3, 7])))
    u(hdr(0x0205, cr + bytes([2, 7]) ))
    u(hdr(0x0206, bytes([1, 0]) + hpai('192.0.2.20', proto=1) + bytes([4, 3, 1, 2])))
    u(hdr(0x0206, bytes([1, 0]) + hpai('192.0.2.20', proto=1) + bytes([6, 4, 1, 2, 3, 4])))
    u(hdr(0x0206, bytes([1, 0]) + hpai('192.0.2.20', proto=1) + bytes([3, 4, 1])))
    u(hdr(0x0206, bytes([1, 0]) + hpai('192.0.2.20', proto=1) + bytes([4, 9, 1, 2])))
    u(hdr(0x0206, bytes([1, 0]) + hpai('192.0.2.20', proto=1) + bytes([1, 4, 1, 2])))
    u(hdr(0x0206, bytes([1, 0]) + hpai('192.0.2.20', proto=1) + bytes([9, 4, 1, 2])))
    u(hdr(0x0204, dib_devinfo() + dib_supp() + bytes([4, 7, 0xff, 0xfe])))
    u(hdr(0x0204, dib_devinfo() + dib_supp() + bytes([3, 7, 0xfe])))
    u(hdr(0x0204, dib_devinfo() + dib_supp() + bytes([7, 7, 0xfe, 1, 2, 3, 4])))
    u(hdr(0x0204, dib_devinfo() + dib_supp() + bytes([2, 7])))
    u(hdr(0x0204, dib_devinfo(medium=0x00) + dib_supp()))
    u(hdr(0x0204, dib_devinfo(medium=0x06) + dib_supp()))
    u(hdr(0x0204, dib_devinfo() + bytes([5, 2, 2, 1, 3])))
    u(hdr(0x0204, dib_devinfo() + bytes([0, 2])))
    u(hdr(0x0204, dib_devinfo() + bytes([1])))
    # two PDUs in one datagram with an error in the second one
    good = hdr(0x0208, bytes([1, 0]))
    u(good + hdr(0x0208, bytes([1, 0]), ver=0x20))
    u(good + hdr(0x0208, bytes([1, 0]), hl=7))
    u(good + hdr(0x0208, bytes([1, 0, 0])))
    u(good + hdr(0x0208, bytes([1])))
    u(hdr(0x0208, bytes([1])) + hdr(0x0208, bytes([1, 0]), ver=0x20))
    p = Pcap()
    for tr, payload in out:
        p.udp(C, S, 50000, KP, payload)
    # captured length shorter than the PDU (snap length): total length past the data, in UDP and TCP
    cap0 = len(p.frames)
    for cut in (12, 20, 40):
        p.udp(C, S, 50000, KP, hdr(0x0205, hpai('192.0.2.10', 50003) + hpai('192.0.2.10', 50004) + bytes([4, 4, 2, 0])))
        ts, d = p.frames[-1]
        p.frames[-1] = (ts, d[:len(d) - cut], len(d))
    for cut in (1, 5):
        p.udp(C, S, 50000, KP, hdr(0x0204, dib_devinfo() + dib_supp()))
        ts, d = p.frames[-1]
        p.frames[-1] = (ts, d[:len(d) - cut], len(d))
    # TCP forms: host protocol mismatches and TCP with non-zero address
    sp = 52100
    p.tcp(C, S, sp, KP, b'', flags=0x02); p.tcp(S, C, KP, sp, b'', flags=0x12); p.tcp(C, S, sp, KP, b'', flags=0x10)
    p.tcp(C, S, sp, KP, hdr(0x0207, bytes([1, 0]) + hpai('192.0.2.10', 50003)))              # UDP HPAI over TCP
    p.tcp(C, S, sp, KP, hdr(0x0207, bytes([1, 0]) + hpai('192.0.2.10', 50003, 2)))           # TCP HPAI with address and port
    p.tcp(C, S, sp, KP, hdr(0x0207, bytes([1, 0]) + hpai('0.0.0.0', 0, 3)))                  # unknown host protocol
    p.tcp(C, S, sp, KP, hdr(0x0207, bytes([1, 1]) + hpai('0.0.0.0', 0, 2)))
    p.udp(C, S, 50000, KP, hdr(0x0207, bytes([1, 0]) + hpai('0.0.0.0', 0, 2)))               # TCP HPAI over UDP
    p.udp(C, S, 50000, KP, hdr(0x0207, bytes([1, 0]) + hpai('192.0.2.10', 50003, 1, ln=10) + b'\x00\x00'))
    p.udp(C, S, 50000, KP, hdr(0x0207, bytes([1, 0]) + hpai('192.0.2.10', 50003, 1, ln=9) + b'\x00'))
    p.udp(C, S, 50000, KP, hdr(0x0207, bytes([1, 0]) + bytes([0, 1])))
    p.udp(C, S, 50000, KP, hdr(0x0207, bytes([1, 0]) + bytes([1])))
    p.udp(C, S, 50000, KP, hdr(0x0207, bytes([1, 0]) + bytes([2, 1])))
    p.udp(C, S, 50000, KP, hdr(0x0207, bytes([1, 0]) + bytes([6, 1, 192, 0])))
    p.udp(C, S, 50000, KP, hdr(0x0207, bytes([1, 0]) + bytes([7, 1, 192, 0, 2, 10, 0xe])))
    # partial TCP segments that never complete
    p.tcp(C, S, sp, KP, hdr(0x0207, bytes([1, 0]) + HPAI_TCP)[:5])
    write_trunc(p, path)

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    mk_main(os.path.join(out, 'knxip-coverage.pcap'))
    mk_mal(os.path.join(out, 'knxip-coverage-malformed.pcap'))
