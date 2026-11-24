# Generates test/captures/iperf3_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ---- common helpers (synthetic traffic only) ----
import struct
import sys
import os

ETH_C = bytes.fromhex('020000000001')
ETH_S = bytes.fromhex('020000000002')


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


def ipv4_hdr(src, dst, proto, payload_len, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + payload_len, ident, 0x4000,
                    64, proto, 0, ip4(src), ip4(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:]


def eth(src_is_client):
    return (ETH_S + ETH_C if src_is_client else ETH_C + ETH_S) + b'\x08\x00'


def tcp_seg(src, dst, sport, dport, seq, ack, payload, flags=0x18, c2s=True):
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
    hdr = struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                      (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
    pseudo = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(hdr) + len(payload))
    c = csum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack('!H', c) + hdr[18:]
    seg = hdr + payload
    return eth(c2s) + ipv4_hdr(src, dst, 6, len(seg)) + seg


def udp_dgram(src, dst, sport, dport, payload, c2s=True):
    hdr = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
    seg = hdr + payload
    return eth(c2s) + ipv4_hdr(src, dst, 17, len(seg)) + seg


class Tcp:
    """One TCP connection; frames collects (data) in order."""
    def __init__(self, frames, c, s, cport, sport, isn_c=1000, isn_s=5000, handshake=True):
        self.f, self.c, self.s, self.cp, self.sp = frames, c, s, cport, sport
        self.sc, self.ss = isn_c, isn_s
        if handshake:
            self.f.append(tcp_seg(c, s, cport, sport, self.sc, 0, b'', 0x02))
            self.f.append(tcp_seg(s, c, sport, cport, self.ss, self.sc + 1, b'', 0x12, c2s=False))
            self.sc += 1
            self.ss += 1
            self.f.append(tcp_seg(c, s, cport, sport, self.sc, self.ss, b'', 0x10))

    def send(self, payload, c2s=True):
        if c2s:
            self.f.append(tcp_seg(self.c, self.s, self.cp, self.sp, self.sc, self.ss, payload))
            self.sc += len(payload)
        else:
            self.f.append(tcp_seg(self.s, self.c, self.sp, self.cp, self.ss, self.sc, payload, c2s=False))
            self.ss += len(payload)

    def fin(self):
        self.f.append(tcp_seg(self.c, self.s, self.cp, self.sp, self.sc, self.ss, b'', 0x11))
        self.sc += 1
        self.f.append(tcp_seg(self.s, self.c, self.sp, self.cp, self.ss, self.sc, b'', 0x11, c2s=False))
        self.ss += 1


def write_pcap(path, frames, linktype=1, snaplen=262144):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000 % 1000000, len(fr), len(fr)))
            f.write(fr)


def _blk(btype, body):
    pad = (-len(body)) % 4
    tot = 12 + len(body) + pad
    return struct.pack('<II', btype, tot) + body + b'\0' * pad + struct.pack('<I', tot)


def write_pcapng(path, linktypes, frames):
    """frames: list of (interface_index, bytes)"""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifidx, data) in enumerate(frames):
        ts = (1700000000 + i) * 1000000 + i * 1000
        out += _blk(6, struct.pack('<IIIII', ifidx, ts >> 32, ts & 0xffffffff,
                                   len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)
# ---- end common helpers ----
#!/usr/bin/env python3
"""Generate the iPerf3 coverage captures: mkiperf3.py <outdir>
Writes iperf3-coverage.pcapng (Ethernet and Exported PDU interfaces) and
iperf3-coverage-malformed.pcapng. All traffic is synthetic."""
import json

C, S = '192.0.2.30', '192.0.2.31'
LINKTYPE_EXPORTED_PDU = 252


def cookie(n):
    s = ('cookie%03d' % n).ljust(36, 'x')
    return s.encode() + b'\0'


def exp_tlv(tag, val):
    return struct.pack('!HH', tag, len(val)) + val


def exported_pdu(dissector, payload, src, dst, ptype, sport, dport):
    t = exp_tlv(12, dissector.encode()) + exp_tlv(20, ip4(src)) + exp_tlv(21, ip4(dst))
    t += exp_tlv(24, struct.pack('!I', ptype)) + exp_tlv(25, struct.pack('!I', sport))
    t += exp_tlv(26, struct.pack('!I', dport)) + struct.pack('!HH', 0, 0)
    return t + payload


def js(d):
    b = json.dumps(d, separators=(',', ':')).encode()
    return struct.pack('!I', len(b)) + b


def state(n):
    return struct.pack('!b', n)


PARAMS = {'tcp': True, 'omit': 0, 'time': 10, 'parallel': 2, 'len': 131072,
          'client_version': '3.99'}
RESULTS_C = {'cpu_util_total': 1.5, 'cpu_util_user': 0.5, 'cpu_util_system': 1.0,
             'sender_has_retransmits': 0, 'streams': [{'id': 1, 'bytes': 1000, 'retransmits': -1,
                                                       'jitter': 0, 'errors': 0, 'packets': 0}]}
RESULTS_S = {'cpu_util_total': 2.5, 'cpu_util_user': 1.5, 'cpu_util_system': 1.0,
             'sender_has_retransmits': -1, 'streams': [{'id': 1, 'bytes': 1000, 'retransmits': -1,
                                                       'jitter': 0, 'errors': 0, 'packets': 0}]}

allf = []   # (interface, bytes)


def add(frs, ifidx=0):
    for f in frs:
        allf.append((ifidx, f))


def tcp_control(cport, ck, *, split=True, mark=None):
    """A complete test: control connection plus two data connections"""
    fr = []
    t = Tcp(fr, C, S, cport, 5201)
    t.send(ck)                                           # cookie
    t.send(state(9), c2s=False)                          # PARAM_EXCHANGE
    t.send(js(PARAMS)[:4])                               # length
    t.send(js(PARAMS)[4:])                               # JSON
    t.send(state(10), c2s=False)                         # CREATE_STREAMS
    add(fr)
    # data connections: cookie, then payload
    for k in range(2):
        fr = []
        d = Tcp(fr, C, S, cport + 1 + k, 5201, isn_c=100 * k + 7)
        d.send(ck)
        d.send(bytes(range(256)) * 4)
        d.send(b'\xaa' * 700)
        d.send(b'\xbb' * 300)
        d.fin()
        add(fr)
    fr = []
    t.f = fr
    t.send(state(1), c2s=False)                          # TEST_START
    t.send(state(2), c2s=False)                          # TEST_RUNNING
    t.send(state(4))                                     # TEST_END
    t.send(state(13), c2s=False)                         # EXCHANGE_RESULTS
    t.send(js(RESULTS_C))                                # client results: length + JSON
    t.send(js(RESULTS_S), c2s=False)                     # server results
    t.send(state(14), c2s=False)                         # DISPLAY_RESULTS
    t.send(state(16))                                    # IPERF_DONE
    t.fin()
    add(fr)


tcp_control(40000, cookie(1))

# Several PDUs in one segment: state, length, JSON in one go, and the
# results exchange in a single segment each way
fr = []
ck = cookie(2)
t = Tcp(fr, C, S, 40010, 5201, isn_c=500, isn_s=900)
t.send(ck)
t.send(state(9) + js(PARAMS) + state(10), c2s=False)
t.send(state(13), c2s=False)
t.send(js(RESULTS_C) + js(RESULTS_S))
t.send(state(14) + state(16), c2s=False)
# the other state codes: unknown, access denied, server error, terminate
for code in (99, -1, -2, 11, 12, 3, 5, 6, 7, 8, 15, 0):
    t.send(state(code), c2s=False)
t.fin()
add(fr)

# 64-bit sequence numbers etc. are in the UDP part. A TCP connection whose
# first segment is not a cookie (no NUL terminator at 37): treated as a
# data connection, nothing is learned; data follows
fr = []
t = Tcp(fr, C, S, 40020, 5201, isn_c=11, isn_s=22)
t.send(b'not a cookie, but long enough to hold 37 bytes..')
t.send(b'more data' * 20)
t.send(b'reply', c2s=False)
t.fin()
add(fr)

# Exported PDU reproducers (see README). 1: a real TCP segment creates the
# TCP conversation data, then iperf3_udp is handed packets of that TCP
# conversation (it must not use the TCP data as its own).
fr = []
t = Tcp(fr, C, S, 40100, 5201, isn_c=1000, handshake=True)
t.send(cookie(3))
add(fr)
allf.append((1, exported_pdu('iperf3_udp', struct.pack('!IIQ', 1, 2, 7) + b'X' * 8,
                             C, S, 2, 40100, 5201)))
allf.append((1, exported_pdu('iperf3_udp', struct.pack('!IIQ', 1, 2, 9) + b'X' * 8,
                             C, S, 2, 40100, 5201)))
# 2: iperf3_udp is handed a packet of a TCP conversation that has no
# iperf3 data yet; the next real segment must not read it as TCP data
fr = []
t = Tcp(fr, C, S, 40102, 5201, isn_c=1000, handshake=True)
add(fr)
allf.append((1, exported_pdu('iperf3_udp', struct.pack('!IIQ', 1, 2, 0x0101010101) + b'X' * 8,
                             C, S, 2, 40102, 5201)))
fr = []
t.f = fr
t.send(b'A' * 40)
add(fr)
# the TCP dissector called from an Exported PDU on a UDP conversation
ufr = [udp_dgram(C, S, 40101, 5201, struct.pack('!IIQ', 5, 6, 1) + b'U' * 16)]
add(ufr)
allf.append((1, exported_pdu('iperf3_tcp', cookie(4), C, S, 3, 40101, 5201)))
allf.append((1, exported_pdu('iperf3_tcp', b'A' * 40, C, S, 3, 40101, 5201)))
allf.append((1, exported_pdu('iperf3_udp', struct.pack('!IIQ', 5, 6, 2) + b'U' * 16, C, S, 3, 40101, 5201)))
# no conversation at all: Exported PDU without addresses
allf.append((1, exp_tlv(12, b'iperf3_udp') + struct.pack('!HH', 0, 0) + b'\0' * 40))
allf.append((1, exp_tlv(12, b'iperf3_tcp') + struct.pack('!HH', 0, 0) + b'\0' * 40))

# ---------------------------------------------------------------- UDP
CU, SU = '192.0.2.40', '192.0.2.41'


def udp(sport, dport, payload, c2s=True):
    return udp_dgram(CU if c2s else SU, SU if c2s else CU, sport, dport, payload, c2s=c2s)


def hdr(sec, usec, seq32):
    return struct.pack('!iII', sec, usec, seq32)


ufr = []
# the connect message and reply (iperf3 sends them in host byte order)
ufr.append(udp(50000, 5201, struct.pack('<I', 0x36373839)))
ufr.append(udp(5201, 50000, struct.pack('<I', 0x39383736), c2s=False))
ufr.append(udp(50001, 5201, struct.pack('<I', 0x075bcd15)))
ufr.append(udp(5201, 50001, struct.pack('<I', 0x3ade68b1), c2s=False))
ufr.append(udp(50001, 5201, struct.pack('>I', 0x075bcd15)))
ufr.append(udp(5201, 50001, struct.pack('>I', 0x3ade68b1), c2s=False))
# 4 octets that are not the connect message: not iPerf3 (UDP data)
ufr.append(udp(50002, 5201, b'abcd'))
# data in sequence, with a gap, a repetition and a restart (out of order)
for i, seq in enumerate((1, 2, 3, 5, 6, 6, 4, 7, 8, 100, 101, 1, 2)):
    ufr.append(udp(50000, 5201, hdr(1700000000 + i // 5, 123456 + i * 1000, seq) + bytes([i]) * 1000))
# a reply direction with its own sequence
for i, seq in enumerate((1, 2, 4)):
    ufr.append(udp(5201, 50000, hdr(1700000001, 999999, seq) + b'R' * 100, c2s=False))
# length 12: no payload after the 32-bit counter
ufr.append(udp(50003, 5201, hdr(1700000010, 0, 1)))
ufr.append(udp(50003, 5201, hdr(1700000010, 500000, 2)))
# negative seconds, 16-octet datagram with a 64-bit counter (upper half zero)
ufr.append(udp(50004, 5201, struct.pack('!iIQ', -5, 250000, 1)))
ufr.append(udp(50004, 5201, struct.pack('!iIQ', -5, 250001, 2) + b'tail'))
ufr.append(udp(50004, 5201, struct.pack('!iIQ', -5, 250002, 0x100000003)))
# a 64-bit counter with a nonzero upper half
ufr.append(udp(50004, 5201, struct.pack('!iIQ', 6, 0, 0x100000004) + b'x' * 8))
# too short to be iPerf3 (5 .. 11 octets): left to the data dissector
ufr.append(udp(50005, 5201, b'12345'))
ufr.append(udp(50005, 5201, b'12345678901'))
ufr.append(udp(50005, 5201, b'1'))
add(ufr)

write_pcapng(os.path.join(sys.argv[1], 'iperf3-coverage.pcapng'), [1, LINKTYPE_EXPORTED_PDU], allf)

# ---------------------------------------------------------------- malformed
allf = []
fr = []
t = Tcp(fr, C, S, 41000, 5201, isn_c=1, isn_s=1)
t.send(cookie(10))
t.send(state(9), c2s=False)
# JSON length larger than the segment: the PDU is not reassembled
t.send(struct.pack('!I', 5000) + b'{"a":1}')
t.send(state(10), c2s=False)
t.send(b'x' * 100)
add(fr)
fr = []
t = Tcp(fr, C, S, 41001, 5201, isn_c=1, isn_s=1)
t.send(cookie(11))
t.send(state(9), c2s=False)
t.send(struct.pack('!I', 0))                            # length 0
t.send(state(13), c2s=False)
t.send(struct.pack('!I', 3) + b'{}x')
t.send(struct.pack('!I', 0xffffffff))
t.send(struct.pack('!I', 2) + b'{}')
t.send(state(4))
t.send(b'')
add(fr)
fr = []
t = Tcp(fr, C, S, 41002, 5201, isn_c=1, isn_s=1)
t.send(cookie(12)[:20])                                 # short cookie
t.send(b'y' * 10)
add(fr)
fr = []
t = Tcp(fr, C, S, 41003, 5201, isn_c=1, isn_s=1)
t.send(b'\xff' * 37)                                    # cookie without NUL: not a cookie
t.send(b'z' * 10)
t.send(b'\0' * 37)                                      # an all-zero "cookie"
add(fr)
fr = []
t = Tcp(fr, C, S, 41004, 5201, isn_c=1, isn_s=1)
t.send(b'\0')                                           # empty cookie string
t.send(state(9), c2s=False)
add(fr)
# the same cookie on a second control connection: the cookie is in the jar,
# so that connection is a data connection
fr = []
t = Tcp(fr, C, S, 41005, 5201, isn_c=1, isn_s=1)
t.send(cookie(10))
t.send(b'data' * 10)
add(fr)
ufr = []
ufr.append(udp(51000, 5201, struct.pack('!iIQ', 1, 2, 0)))               # 64-bit counter needs 16
ufr.append(udp(51000, 5201, struct.pack('!iIQ', 1, 2, 0)[:13]))
ufr.append(udp(51000, 5201, struct.pack('!iII', 1, 2, 0)))
ufr.append(udp(51001, 5201, b''))
add(ufr)
write_pcapng(os.path.join(sys.argv[1], 'iperf3-coverage-malformed.pcapng'), [1, LINKTYPE_EXPORTED_PDU], allf)
