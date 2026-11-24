# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Shared helper library for the IPMI coverage generators (copied into each
# directory).  Everything is built with struct; no real traffic is used.
import struct
import socket
import gzip
import os
import sys

def cks(b):
    return (-sum(b)) & 0xff

def csum16(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipmb(rs_sa, netfn, rq_sa, seq, cmd, data, lun=0, rq_lun=0, bad_cks1=False, bad_cks2=False):
    """IPMB message: target SA, netfn/lun, cks1, source SA, seq/lun, cmd, data, cks2."""
    h1 = bytes([rs_sa, (netfn << 2) | lun])
    c1 = cks(h1) ^ (1 if bad_cks1 else 0)
    h2 = bytes([rq_sa, ((seq & 0x3f) << 2) | rq_lun, cmd]) + bytes(data)
    c2 = cks(h2) ^ (1 if bad_cks2 else 0)
    return h1 + bytes([c1]) + h2 + bytes([c2])

def req(netfn, cmd, data=b'', seq=1, **kw):
    """Request (even NetFn) from 0x81 to 0x20."""
    return ipmb(0x20, netfn & ~1, 0x81, seq, cmd, data, **kw)

def rsp(netfn, cmd, data=b'', seq=1, cc=0, **kw):
    """Response (odd NetFn) from 0x20 to 0x81, completion code cc."""
    return ipmb(0x81, netfn | 1, 0x20, seq, cmd, bytes([cc]) + bytes(data), **kw)

def exp_pdu(payload, name):
    n = name.encode()
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload

ETH = bytes.fromhex('020000000002020000000001') + b'\x08\x00'
ETH_R = bytes.fromhex('020000000001020000000002') + b'\x08\x00'

def udp4(payload, sport=49152, dport=623, src='192.0.2.1', dst='192.0.2.2', reverse=False):
    if reverse:
        sport, dport, src, dst = dport, sport, dst, src
    s = socket.inet_aton(src); d = socket.inet_aton(dst)
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, s, d)
    ip = ip[:10] + struct.pack('>H', csum16(ip)) + ip[12:]
    return (ETH_R if reverse else ETH) + ip + udp

RMCP = bytes([0x06, 0x00, 0xff, 0x07])

def rmcp_plus(msg, payloadtype=0, session=0, seq=0, trailer=b'', oem=None):
    pt = bytes([payloadtype])
    if (payloadtype & 0x3f) == 2:
        oem = oem or (b'\x01\x02\x03\x04', b'\x05\x06')
        return RMCP + bytes([6]) + pt + oem[0] + oem[1] + struct.pack('<IIH', session, seq, len(msg)) + msg + trailer
    return RMCP + bytes([6]) + pt + struct.pack('<IIH', session, seq, len(msg)) + msg + trailer

def rmcp_v15(msg, auth=0, session=0, seq=0, trailer=b''):
    if auth == 0:
        return RMCP + bytes([0]) + struct.pack('<II', seq, session) + bytes([len(msg)]) + msg + trailer
    return RMCP + bytes([auth]) + struct.pack('<II', seq, session) + b'\xa5' * 16 + bytes([len(msg)]) + msg + trailer

def trace_block(btype, chn, data_type, proto_data, payload, secs=1000, msecs=5, dlen=None):
    b = bytes([(btype << 4) | chn]) + struct.pack('<IH', secs, msecs) + bytes([data_type]) \
        + struct.pack('<H', proto_data) + bytes([len(payload) if dlen is None else dlen]) + payload
    return b

class Cap:
    """A pcapng writer with three interfaces: Ethernet (0), Exported PDU (1),
    IPMI HPM.2 trace (2)."""
    LT = {'eth': 1, 'exp': 252, 'trace': 260, 'i2c': 209}
    def __init__(self):
        self.frames = []
        self.t = 1700000000.0
        self.used = set()
    def add(self, kind, data, dt=0.001):
        self.t += dt
        self.frames.append((kind, data, self.t))
        self.used.add(kind)
        return len(self.frames)
    # convenience wrappers; the UDP direction is derived from the NetFn
    def udp(self, ipmi, resp=None, dt=0.001, v15=False, **kw):
        if resp is None:
            resp = bool((ipmi[1] >> 2) & 1)
        w = rmcp_v15(ipmi, **kw) if v15 else rmcp_plus(ipmi, **kw)
        return self.add('eth', udp4(w, reverse=resp), dt)
    def exp(self, ipmi, name='ipmi', dt=0.001):
        return self.add('exp', exp_pdu(ipmi, name), dt)
    def trace(self, ipmi, proto=1, chn=0, flags=0, btype=0, dt=0.001, **kw):
        return self.add('trace', trace_block(btype, chn, proto, flags, ipmi, **kw), dt)
    def i2c(self, ipmi, flags=0, bus=1, event=False, dt=0.001):
        return self.add('i2c', bytes([bus | (0x80 if event else 0)]) + struct.pack('>I', flags) + ipmi, dt)
    def write_pcapng(self, path, only=None):
        kinds = [k for k in ('eth', 'exp', 'trace', 'i2c') if k in self.used]
        idx = {k: i for i, k in enumerate(kinds)}
        out = bytearray()
        def block(t, body):
            body = bytes(body)
            pad = (-len(body)) % 4
            ln = 12 + len(body) + pad
            return struct.pack('<II', t, ln) + body + b'\0' * pad + struct.pack('<I', ln)
        out += block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for k in kinds:
            out += block(1, struct.pack('<HHI', self.LT[k], 0, 262144))
        for k, d, t in self.frames:
            ts = int(round(t * 1e6))
            out += block(6, struct.pack('<IIIII', idx[k], ts >> 32, ts & 0xffffffff, len(d), len(d)) + d)
        with open(path, 'wb') as f:
            f.write(out)

def gz(path):
    with open(path, 'rb') as f:
        data = f.read()
    # reproducible: no name/mtime in the header
    import io
    buf = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=buf, compresslevel=9, mtime=0) as g:
        g.write(data)
    with open(path + '.gz', 'wb') as f:
        f.write(buf.getvalue())
