# Helper module for the vnc capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Minimal packet builder shared by the generator: Ethernet/IPv4/TCP flows
# with synthetic addresses (192.0.2.0/24) and a classic pcap writer.
import struct


class Net:
    def __init__(self):
        self.pkts = []
        self.marks = []

    def mark(self, name):
        self.marks.append((len(self.pkts) + 1, name))

    def write(self, fn, linktype=1, snaplen=262144):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, linktype))
            for i, p in enumerate(self.pkts):
                f.write(struct.pack('<IIII', 1000 + i // 1000, (i % 1000) * 1000, len(p), len(p)))
                f.write(p)

    def report(self, name, out=None):
        ends = [m[0] for m in self.marks[1:]] + [len(self.pkts) + 1]
        for (s, label), e in zip(self.marks, ends):
            print('%s %d-%d %s' % (name, s, e - 1, label), file=out)


def mac(n):
    return bytes([2, 0, 0, 0, 0, n])


class Flow:
    """TCP flow; frm 0 = client, 1 = server."""

    def __init__(self, net, cip, cport, sip, sport, cmac=1, smac=2, mss=1400):
        self.net = net
        self.ep = [(mac(cmac), bytes(cip), cport), (mac(smac), bytes(sip), sport)]
        self.seq = [1000, 50000]
        self.ipid = 1
        self.mss = mss

    def raw(self, frm, payload, flags=0x18):
        a, b = self.ep[frm], self.ep[1 - frm]
        seq, ack = self.seq[frm], self.seq[1 - frm]
        tcp = struct.pack('>HHIIBBHHH', a[2], b[2], seq, ack, 0x50, flags, 65535, 0, 0)
        tot = 20 + len(tcp) + len(payload)
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, tot, self.ipid, 0, 64, 6, 0, a[1], b[1])
        self.ipid += 1
        self.net.pkts.append(b[0] + a[0] + b'\x08\x00' + ip + tcp + payload)
        self.seq[frm] = (seq + len(payload) + (1 if flags & 3 else 0)) & 0xffffffff

    def send(self, frm, payload):
        """One segment per mss octets."""
        for i in range(0, max(len(payload), 1), self.mss):
            self.raw(frm, payload[i:i + self.mss])

    def split(self, frm, payload, *cuts):
        """Send payload cut at the given offsets (one segment each)."""
        prev = 0
        for c in list(cuts) + [len(payload)]:
            if c > prev:
                self.send(frm, payload[prev:c])
            prev = max(prev, c)

    def trickle(self, frm, payload, n):
        """First n octets one per segment, the rest in one segment."""
        for i in range(min(n, len(payload))):
            self.raw(frm, payload[i:i + 1])
        if len(payload) > n:
            self.send(frm, payload[n:])

    def handshake(self):
        self.raw(0, b'', 0x02)
        self.raw(1, b'', 0x12)
        self.raw(0, b'', 0x10)

    def close(self):
        self.raw(0, b'', 0x11)
        self.raw(1, b'', 0x11)
        self.raw(0, b'', 0x10)
