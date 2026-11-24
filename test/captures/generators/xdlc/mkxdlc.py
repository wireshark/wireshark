#!/usr/bin/env python3
# Generates test/captures/xdlc_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Common helpers: a minimal pcap writer and Ethernet/IPv4/TCP/UDP builders.
# Everything is synthetic: addresses are 10.0.0.x / 02:00:00:00:00:0x.
import os
import struct
import sys

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

class Pcap:
    def __init__(self, linktype=1):
        self.linktype = linktype
        self.pkts = []
        self.t = 0
    def add(self, data):
        self.t += 1
        self.pkts.append((self.t, bytes(data)))
    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, self.linktype))
            for t, p in self.pkts:
                f.write(struct.pack('<IIII', 1700000000 + t, 0, len(p), len(p)))
                f.write(p)
        return len(self.pkts)

def ip4(a):
    return bytes(map(int, a.split('.')))

MAC1 = b'\x02\0\0\0\0\x01'
MAC2 = b'\x02\0\0\0\0\x02'

def ip_packet(proto, src, dst, payload, ident=1):
    tot = 20 + len(payload)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot, ident, 0, 64, proto, 0, ip4(src), ip4(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ip + payload

def udp_frame(sip, dip, sport, dport, payload, smac=MAC1, dmac=MAC2):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return dmac + smac + b'\x08\x00' + ip_packet(17, sip, dip, udp)

class Tcp:
    """One TCP connection; frames are appended to a Pcap."""
    def __init__(self, pcap, cport, sport, cip='10.0.0.1', sip='10.0.0.2'):
        self.p = pcap
        self.c = (cip, cport, MAC1)
        self.s = (sip, sport, MAC2)
        self.seq = [1000, 5000]
    def _pkt(self, d, payload, flags=0x18, advance=None):
        src, dst = (self.c, self.s) if d == 0 else (self.s, self.c)
        seq = self.seq[d]
        ack = self.seq[1 - d]
        tcp = struct.pack('!HHIIBBHHH', src[1], dst[1], seq, ack, 5 << 4, flags, 65535, 0, 0)
        ph = ip4(src[0]) + ip4(dst[0]) + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + payload)) + tcp[18:]
        self.seq[d] = (seq + len(payload) + (1 if flags & 0x03 else 0)) & 0xffffffff
        self.p.add(dst[2] + src[2] + b'\x08\x00' + ip_packet(6, src[0], dst[0], tcp + payload))
    def handshake(self):
        self._pkt(0, b'', 0x02)
        self._pkt(1, b'', 0x12)
        self._pkt(0, b'', 0x10)
    def c2s(self, payload):
        self._pkt(0, payload)
    def s2c(self, payload):
        self._pkt(1, payload)
    def fin(self):
        self._pkt(0, b'', 0x11)
        self._pkt(1, b'', 0x11)
        self._pkt(0, b'', 0x10)

def llc_frame(dsap, ssap, ctrl, payload=b'', smac=MAC1, dmac=MAC2):
    body = bytes([dsap, ssap]) + ctrl + payload
    return dmac + smac + struct.pack('!H', len(body)) + body

def outdir():
    d = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(d, exist_ok=True)
    return d

# ---- pcapng ----
def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def _opt(code, val):
    return struct.pack('<HH', code, len(val)) + val + b'\0' * ((-len(val)) % 4)

class PcapNG:
    """Several interfaces; add(iface, data, flags=None) with optional epb_flags."""
    def __init__(self, linktypes=(1,)):
        self.linktypes = list(linktypes)
        self.pkts = []
        self.t = 0
    def add(self, data, iface=0, flags=None):
        self.t += 1
        self.pkts.append((iface, self.t, bytes(data), flags))
    def write(self, fn):
        out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in self.linktypes:
            out += _blk(1, struct.pack('<HHI', lt, 0, 65535))
        for iface, t, d, flags in self.pkts:
            ts = 1700000000 * 1000000 + t * 1000
            body = struct.pack('<IIIII', iface, ts >> 32, ts & 0xffffffff, len(d), len(d)) + d
            body += b'\0' * ((-len(d)) % 4)
            if flags is not None:
                body += _opt(2, struct.pack('<I', flags)) + struct.pack('<HH', 0, 0)
            out += _blk(6, body)
        with open(fn, 'wb') as f:
            f.write(out)
        return len(self.pkts)

def exported_pdu(name, payload):
    """Exported PDU (linktype 252) record naming a dissector."""
    nm = name.encode()
    pad = (-len(nm)) % 4
    tag = struct.pack('!HH', 12, len(nm) + pad) + nm + b'\0' * pad
    return tag + struct.pack('!HH', 0, 0) + payload

def gsmtap(sub_type, payload, uplink=False, gtype=0x13):
    """GSMTAP v2 header (16 octets) for E1/T1 line traces."""
    arfcn = 0x4000 if uplink else 0
    return struct.pack('!BBBBHBBIBBBB', 2, 4, gtype, 0, arfcn, 0, 0, 0, sub_type, 0, 0, 0) + payload


# ---- xDLC control field helper: reached through LLC (extended), LAPB over Ethernet
# (basic) and X.75 over GSMTAP (basic, with command/response by direction) ----
# the 32 values under the modifier mask 0xEC
MODIFIERS = sorted({m & 0xEC for m in range(0x100)})
ETHERTYPE_LAPBETHER = 0x6000   # ETHERTYPE_DEC, handled as LAPB over Ethernet

def u_ctl(mod, pf=0):
    return bytes([0x03 | mod | (pf << 4)])

def s_ext(ftype, nr, pf=0):
    return struct.pack('<H', 0x01 | ftype | (pf << 8) | (nr << 9))

def i_ext(ns, nr, pf=0):
    return struct.pack('<H', (ns << 1) | (pf << 8) | (nr << 9))

def llc(cmd, ctl, payload=b'', dsap=0x30, ssap=0x30):
    return llc_frame(dsap, ssap | (0 if cmd else 1), ctl, payload)

def lapbether(addr, ctl, payload=b''):
    body = bytes([addr]) + ctl + payload
    return MAC2 + MAC1 + struct.pack('!H', ETHERTYPE_LAPBETHER) + struct.pack('<H', len(body)) + body

def build(outdir):
    n = PcapNG([1, 107])
    # --- extended operation through LLC type 2 (frames 1-...) ---
    for cmd in (True, False):
        # every U modifier, with the P/F bit alternating
        for k, mod in enumerate(MODIFIERS):
            n.add(llc(cmd, u_ctl(mod, k & 1)))
        # S frames: RR, RNR, REJ, SREJ with N(R) up to 127 and the P/F bit
        for ft in (0x00, 0x04, 0x08, 0x0C):
            n.add(llc(cmd, s_ext(ft, 5, 0)))
            n.add(llc(cmd, s_ext(ft, 127, 1)))
        # I frames: N(S) and N(R) up to 127, P bit, with data
        n.add(llc(cmd, i_ext(0, 0, 0), b'data 0'))
        n.add(llc(cmd, i_ext(77, 100, 1), b'data 77'))
        n.add(llc(cmd, i_ext(127, 127, 0), b'data 127'))
    # --- basic operation: LAPB over Ethernet (direction unknown, so all frames are commands) ---
    for addr in (0x01, 0x03, 0x07, 0x0F):
        for mod in (0x2C, 0x60, 0x40, 0x0C):
            n.add(lapbether(addr, u_ctl(mod, 1)))
    for ft in (0x00, 0x04, 0x08):
        n.add(lapbether(0x01, bytes([0x01 | ft | (6 << 5)])))
        n.add(lapbether(0x01, bytes([0x01 | ft | 0x10 | (2 << 5)])))
    n.add(lapbether(0x01, bytes([(3 << 1) | (4 << 5)]), b'\x10\x01\x08' + b'lapb data'))
    n.add(lapbether(0x01, bytes([(7 << 1) | 0x10 | (7 << 5)]), b'\x10\x01\x20' + b'lapb data'))
    n.add(lapbether(0x55, u_ctl(0x2C, 1)))                      # invalid address
    # --- basic operation: X.75 over GSMTAP, with command/response by direction ---
    def gt(payload, up):
        n.add(udp_frame('10.0.0.1', '10.0.0.2', 4729, 4729, gsmtap(7, payload, up)))
    for up, a in ((True, 0x03), (True, 0x01), (False, 0x01), (False, 0x03)):
        for k, mod in enumerate(MODIFIERS):
            gt(bytes([a]) + u_ctl(mod, k & 1), up)
        for ft in (0x00, 0x04, 0x08, 0x0C):
            gt(bytes([a, 0x01 | ft | (1 << 5)]), up)
            gt(bytes([a, 0x01 | ft | 0x10 | (7 << 5)]), up)
        gt(bytes([a, (2 << 1) | (3 << 5)]) + b'x75 data', up)
        gt(bytes([a, (5 << 1) | 0x10 | (6 << 5)]) + b'x75 data', up)
    # --- Frame Relay DLCI 0 (LAPF): the control field is dissected with the Info text appended;
    # the C/R bit of the address gives command or response ---
    def fr(cr, ctl, payload=b''):
        n.add(bytes([cr << 1, 0x01]) + ctl + payload, iface=1)
    for cr in (0, 1):
        for mod in (0x6C, 0x60, 0x40, 0x0C, 0x84):
            fr(cr, u_ctl(mod, 1))
        for ft in (0x00, 0x04, 0x08, 0x0C):
            fr(cr, s_ext(ft, 9, cr))
        fr(cr, i_ext(4, 5, 1), b'\x08\x00')
        fr(cr, i_ext(6, 7, 0), b'\x08\x00')
    c = n.write(os.path.join(outdir, 'xdlc-coverage.pcapng'))
    print('xdlc-coverage.pcapng', c)

    m = PcapNG([1, 107])
    # control octet missing in LLC, I frame control cut to one octet in extended mode
    m.add(llc(True, b''))
    m.add(llc(True, b'\x00'))
    m.add(llc(False, b'\x01'))
    m.add(llc(True, b'\x04'))
    m.add(lapbether(0x01, b''))
    m.add(b'\x00\x01', iface=1)
    m.add(b'\x00\x01\x01', iface=1)
    c = m.write(os.path.join(outdir, 'xdlc-coverage-malformed.pcapng'))
    print('xdlc-coverage-malformed.pcapng', c)

if __name__ == '__main__':
    build(outdir())
