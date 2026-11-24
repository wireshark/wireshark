# Helper module for the usbll capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Helpers shared by mkusbll.py: USB 2.0 link layer packets, CRCs, pcapng writer.
import struct

PID = dict(MDATA=0x0F, STALL=0x1E, SETUP=0x2D, ERR=0x3C, DATA1=0x4B, NAK=0x5A,
           IN=0x69, SPLIT=0x78, DATA2=0x87, NYET=0x96, SOF=0xA5, PING=0xB4,
           DATA0=0xC3, ACK=0xD2, OUT=0xE1, EXT=0xF0)

_BV = [0x1e, 0x15, 0x03, 0x06, 0x0c, 0x18, 0x19, 0x1b, 0x1f, 0x17, 0x07, 0x0e,
       0x1c, 0x11, 0x0b, 0x16, 0x05, 0x0a, 0x14]


def crc5(v, vl, init):
    rv = init
    for i in range(vl):
        if v & (1 << i):
            rv ^= _BV[19 - vl + i]
    return rv


def crc16(data):
    c = 0xFFFF
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return c ^ 0xFFFF


# idb numbers of the pcapng written by Cap
HS, FS, LS, UNK = 0, 1, 2, 3
LINKTYPES = {HS: 295, FS: 294, LS: 293, UNK: 288}


class Cap:
    def __init__(self):
        self.pk = []
        self.t = 1700000000 * 1000000
        self.idb = HS

    def add(self, data, idb=None):
        self.pk.append((self.idb if idb is None else idb, self.t, bytes(data)))
        self.t += 125

    @staticmethod
    def _blk(btype, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', btype, len(body) + 12) + body + struct.pack('<I', len(body) + 12)

    def write(self, fn):
        out = self._blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for i in range(4):
            out += self._blk(1, struct.pack('<HHI', LINKTYPES[i], 0, 65535))
        for idb, ts, d in self.pk:
            out += self._blk(6, struct.pack('<IIIII', idb, ts >> 32, ts & 0xFFFFFFFF, len(d), len(d)) + d)
        with open(fn, 'wb') as f:
            f.write(out)

    # ---- link layer packets ----
    def sof(self, n, bad=False, extra=b''):
        w = (n & 0x7FF) | ((crc5(n, 11, 2) ^ (1 if bad else 0)) << 11)
        self.add(bytes([PID['SOF']]) + struct.pack('<H', w) + extra)

    def tok(self, pid, addr, ep, bad=False, extra=b''):
        v = (addr & 0x7F) | ((ep & 0xF) << 7)
        w = v | ((crc5(v, 11, 2) ^ (1 if bad else 0)) << 11)
        self.add(bytes([PID[pid] if isinstance(pid, str) else pid]) + struct.pack('<H', w) + extra)

    def hs(self, pid, extra=b''):
        self.add(bytes([PID[pid] if isinstance(pid, str) else pid]) + extra)

    def data(self, pid, payload=b'', bad=False):
        c = crc16(payload) ^ (1 if bad else 0)
        self.add(bytes([PID[pid]]) + bytes(payload) + struct.pack('<H', c))

    def split(self, hub, port, sc, s, et, eu=0, bad=False):
        v = (hub & 0x7F) | (sc << 7) | ((port & 0x7F) << 8) | (s << 15) | (eu << 16) | (et << 17)
        c = crc5(v, 19, 0x1d) ^ (1 if bad else 0)
        v |= c << 19
        self.add(bytes([PID['SPLIT']]) + struct.pack('<I', v)[:3])

    def lpm(self, state=1, besl=4, wake=1, rsv=0, bad=False):
        v = state | (besl << 4) | (wake << 8) | (rsv << 9)
        w = v | ((crc5(v, 11, 2) ^ (1 if bad else 0)) << 11)
        self.add(bytes([0xC3]) + struct.pack('<H', w))
