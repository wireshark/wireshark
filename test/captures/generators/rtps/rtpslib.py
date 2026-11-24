# Helper module for the rtps capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Helpers for mkrtps.py (synthetic RTPS captures; no real traffic).
import struct
import os
import subprocess
import tempfile
import zlib


def align(b, n=4):
    return b + b'\0' * ((-len(b)) % n)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


ETH = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'


def ip_hdr(proto, plen, src, dst, ident=1):
    ip_s = bytes(int(x) for x in src.split('.'))
    ip_d = bytes(int(x) for x in dst.split('.'))
    tot = 20 + plen
    assert tot <= 65535
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot, ident, 0, 64, proto, 0, ip_s, ip_d)
    return ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]


def udp_frame(payload, sport=7410, dport=7411, src='192.0.2.1', dst='192.0.2.2'):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return ETH + ip_hdr(17, len(udp), src, dst) + udp


def tcp_frame(payload, sport=7412, dport=7413, seq=1000, src='192.0.2.1', dst='192.0.2.2'):
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 0x50, 0x18, 8192, 0, 0) + payload
    return ETH + ip_hdr(6, len(tcp), src, dst) + tcp


def pcap_write(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def _blk(btype, body):
    body = align(body)
    return struct.pack('<II', btype, len(body) + 12) + body + struct.pack('<I', len(body) + 12)


def pcapng_write(path, frames):
    """frames: list of (link, data); link 1 = Ethernet, 252 = Exported PDU."""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    out += _blk(1, struct.pack('<HHI', 1, 0, 262144))
    out += _blk(1, struct.pack('<HHI', 252, 0, 262144))
    for i, (link, d) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += _blk(6, struct.pack('<IIIII', 0 if link == 1 else 1, ts >> 32, ts & 0xffffffff, len(d), len(d)) + d)
    with open(path, 'wb') as f:
        f.write(out)


def exppdu(name, payload):
    n = name.encode()
    pad = (-len(n)) % 4
    tlv = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0)
    return (252, tlv + payload)


BAD = '_ws.malformed || _ws.expert.severity >= 0x00800000'
BADW = '_ws.malformed || _ws.expert.severity >= 0x00600000'     # also warnings


class Tshark:
    """Runs tshark to tell which candidate frames decode cleanly."""
    def __init__(self, tshark, cfg, prefs=()):
        self.tshark = tshark
        self.cfg = cfg
        self.prefs = prefs
        self.tmp = tempfile.mkdtemp(prefix='mkrtps', dir=os.environ.get('MKTMP'))
        self.crashed = []

    def _one(self, frames, extra, flt, fields):
        if frames and isinstance(frames[0], tuple):
            p = os.path.join(self.tmp, 'c.pcapng')
            pcapng_write(p, frames)
        else:
            p = os.path.join(self.tmp, 'c.pcap')
            pcap_write(p, frames)
        env = dict(os.environ, WIRESHARK_CONFIG_DIR=self.cfg)
        cmd = ['prlimit', '--as=%d' % (2 << 30), self.tshark, '-r', p] + list(self.prefs) + list(extra) + \
            ['-Y', flt or BAD, '-T', 'fields'] + sum((['-e', f] for f in fields.split(',')), [])
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=300)
        except subprocess.TimeoutExpired:
            return 124, ''
        return r.returncode, r.stdout

    def run(self, frames, extra=(), flt=None, fields='frame.number', _off=0):
        """Runs tshark over frames in chunks; a chunk that crashes, runs out of
        memory or times out is split until the single frames are found: those are
        reported as bad (and kept in self.crashed)."""
        out = []
        n = len(frames)
        step = 400
        for s in range(0, n, step):
            chunk = frames[s:s + step]
            rc, so = self._one(chunk, extra, flt, fields)
            if rc != 0:
                if len(chunk) == 1:
                    self.crashed.append(chunk[0])
                    if flt is None or flt == BADW:
                        out.append(str(_off + s + 1) if fields == 'frame.number' else '%d' % (_off + s + 1))
                    continue
                half = len(chunk) // 2
                sub = self.run(chunk[:half], extra, flt, fields, _off + s) + self.run(chunk[half:], extra, flt, fields, _off + s + half)
                out.extend(sub)
                continue
            if fields == 'frame.number':
                out.extend(str(int(x) + _off + s) for x in so.split())
            else:
                for line in so.splitlines():
                    c = line.split('\t')
                    c[0] = str(int(c[0]) + _off + s)
                    out.append('\t'.join(c))
        return out

    def table(self, frames, field):
        """(frame number, comma separated values of field) for every frame."""
        rows = self.run(frames, flt='frame', fields='frame.number,' + field)
        out = []
        for r in rows:
            c = r.split('\t')
            out.append((int(c[0]), c[1] if len(c) > 1 else ''))
        return out

    def bad(self, frames, extra=(), strict=False):
        return set(int(x) for x in self.run(frames, extra, flt=BADW if strict else None))

    def good(self, frames, extra=(), strict=False):
        b = self.bad(frames, extra, strict)
        return [i not in b for i in range(1, len(frames) + 1)]
