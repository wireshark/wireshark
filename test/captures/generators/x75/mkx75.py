#!/usr/bin/env python3
# Generates test/captures/x75_coverage.pcapng.gz
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


# ---- X.75 (async data over ISDN) in GSMTAP E1/T1 (UDP 4729) and Exported PDU ----
GSMTAP_E1T1_X75 = 7
ADDRS = (0x03, 0x01, 0x0F, 0x07)     # STE A, B, C, D addresses

def x75_frames():
    """(label, bytes) of X.75 frames for one address octet; no address here."""
    fr = []
    # unnumbered: SABM, UA, DISC (RD), DM, UI, FRMR, XID, TEST, SNRM, an unknown modifier; P/F on and off
    for ctl in (0x2F, 0x3F, 0x63, 0x73, 0x43, 0x53, 0x1F, 0x03, 0x87, 0xAF, 0xE3, 0x83, 0xEF, 0x07):
        fr.append(bytes([ctl]))
    # supervisory RR, RNR, REJ, SREJ with N(R) and P/F
    for ft in (0x01, 0x05, 0x09, 0x0D):
        fr.append(bytes([ft | (3 << 5)]))
        fr.append(bytes([ft | 0x10 | (5 << 5)]))
    return fr

def build(outdir):
    n = PcapNG([1, 252])
    def gt(payload, up):
        n.add(udp_frame('10.0.0.1', '10.0.0.2', 4729, 4729, gsmtap(GSMTAP_E1T1_X75, payload, up)))
    for up in (True, False):
        for a in ADDRS:
            for ctl in x75_frames():
                gt(bytes([a]) + ctl, up)
            # information frames: short text, text with CR LF, and one over 128 octets (the
            # Info column shows the first 128)
            gt(bytes([a, 0x00]) + b'ATDT5551234\r\n', up)
            gt(bytes([a, 0x12 | 0x00]) + b'CONNECT 9600', up)
            gt(bytes([a, 0x03]) + b'unnumbered information', up)
            gt(bytes([a, 0x10 | 0x02 | 0xA0]) + b'x' * 20, up)
    gt(bytes([0x03, 0x00]) + bytes(range(32, 127)) * 2, True)    # 190 octets
    gt(bytes([0x03, 0x00]), True)                                  # I frame without data
    # invalid address octets
    for a in (0x00, 0x02, 0x55, 0xFF):
        gt(bytes([a, 0x2F]), False)
    # Exported PDU: no direction, so the command/response decision is "command"
    for a in ADDRS:
        for ctl in (b'\x2F', b'\x63', b'\x01', b'\x21', b'\x00' + b'EXPORTED'):
            n.add(exported_pdu('x75', bytes([a]) + ctl), iface=1)
    n.add(exported_pdu('x75', bytes([0x55, 0x2F])), iface=1)
    c = n.write(os.path.join(outdir, 'x75-coverage.pcapng'))
    print('x75-coverage.pcapng', c)

    m = PcapNG([1, 252])
    # truncated frames: an address octet only, and a control octet missing
    m.add(exported_pdu('x75', bytes([0x03])), iface=1)
    m.add(exported_pdu('x75', bytes([0x03, 0x00])), iface=1)
    m.add(udp_frame('10.0.0.1', '10.0.0.2', 4729, 4729, gsmtap(GSMTAP_E1T1_X75, bytes([0x03]), True)))
    m.add(udp_frame('10.0.0.1', '10.0.0.2', 4729, 4729, gsmtap(GSMTAP_E1T1_X75, b'', True)))
    c = m.write(os.path.join(outdir, 'x75-coverage-malformed.pcapng'))
    print('x75-coverage-malformed.pcapng', c)

if __name__ == '__main__':
    build(outdir())
