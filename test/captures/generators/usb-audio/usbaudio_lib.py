# Helper module for the usb-audio capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Helpers for mkusb-audio.py: Linux usbmon (link type 220) records and pcap
# writer, plus the descriptors of USB Audio class 1.0 and 2.0 devices.
import struct

CTRL, ISO, BULK, INT = 0, 1, 2, 3   # not usbmon codes, see XFER
XFER = {'iso': 0, 'int': 1, 'ctrl': 2, 'bulk': 3}


def u16(v):
    return struct.pack('<H', v)


class Mon:
    def __init__(self):
        self.pk = []
        self.idb = []
        self.id = 0x1000
        self.t = 0
        self.marks = []

    def mark(self, name):
        self.marks.append((len(self.pk) + 1, name))

    def _rec(self, urb_id, ev, xfer, ep, dev, data=b'', setup=None, urb_len=None, status=0):
        self.t += 1
        flag_setup = 0 if setup is not None else ord('-')
        flag_data = 0 if data else ord('<' if ev == 'S' else '>')
        if urb_len is None:
            urb_len = len(data)
        s = setup if setup is not None else b'\0' * 8
        hdr = struct.pack('<QBBBBHBBqiiII8siiII', urb_id, ord(ev), XFER[xfer], ep, dev, 1,
                          flag_setup, flag_data, 1700000000, self.t * 1000, status, urb_len,
                          len(data), s, 0, 0, 0, 0)
        assert len(hdr) == 64
        self.pk.append(hdr + data)
        self.idb.append(0)

    def exppdu(self, name, payload):
        """Exported PDU (link type 252) frame that names a registered dissector"""
        v = name.encode()
        v += b'\0' * (-len(v) % 4)
        self.pk.append(struct.pack('>HH', 12, len(v)) + v + struct.pack('>HH', 0, 0) + payload)
        self.idb.append(1)

    def control(self, dev, setup, data=b'', status=0):
        """setup is 8 bytes; for IN requests data is the response, for OUT requests the data stage"""
        self.id += 1
        wlen = struct.unpack('<H', setup[6:8])[0]
        d_in = bool(setup[0] & 0x80)
        ep = 0x80 if d_in else 0x00
        self._rec(self.id, 'S', 'ctrl', ep, dev, b'' if d_in else data, setup, urb_len=wlen)
        self._rec(self.id, 'C', 'ctrl', ep, dev, data if d_in else b'', None,
                  urb_len=len(data), status=status)

    def bulk_in(self, dev, ep, data):
        self.id += 1
        self._rec(self.id, 'S', 'bulk', ep | 0x80, dev, b'', None, urb_len=4096)
        self._rec(self.id, 'C', 'bulk', ep | 0x80, dev, data)

    def bulk_out(self, dev, ep, data):
        self.id += 1
        self._rec(self.id, 'S', 'bulk', ep, dev, data)
        self._rec(self.id, 'C', 'bulk', ep, dev, b'', None, urb_len=len(data))

    @staticmethod
    def _blk(btype, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', btype, len(body) + 12) + body + struct.pack('<I', len(body) + 12)

    def write_pcapng(self, fn):
        out = self._blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += self._blk(1, struct.pack('<HHI', 220, 0, 262144))
        out += self._blk(1, struct.pack('<HHI', 252, 0, 262144))
        for i, (p, idb) in enumerate(zip(self.pk, self.idb)):
            ts = 1700000000 * 1000000 + i * 1000
            out += self._blk(6, struct.pack('<IIIII', idb, ts >> 32, ts & 0xFFFFFFFF, len(p), len(p)) + p)
        with open(fn, 'wb') as f:
            f.write(out)

    def write(self, fn):
        with open(fn, 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 220))
            for i, p in enumerate(self.pk):
                f.write(struct.pack('<IIII', 1700000000, i * 1000, len(p), len(p)))
                f.write(p)


# ---------------- standard descriptors ----------------
def cfg(body, nif):
    return bytes([9, 2]) + u16(9 + len(body)) + bytes([nif, 1, 0, 0x80, 50]) + body


def iface(num, alt, neps, sub, proto=0, cls=1):
    return bytes([9, 4, num, alt, neps, cls, sub, proto, 0])


def ep_audio(addr, attr, mps, interval=1, refresh=0, synch=0):
    """9 octet endpoint descriptor of the audio class"""
    return bytes([9, 5, addr, attr]) + u16(mps) + bytes([interval, refresh, synch])


def devdesc(vid, pid, cls=0):
    return struct.pack('<BBHBBBBHHHBBBB', 18, 1, 0x0200, cls, 0, 0, 64, vid, pid, 0x0100, 1, 2, 3, 1)


def cs_if(sub, body):
    return bytes([3 + len(body), 0x24, sub]) + bytes(body)


def cs_ep(sub, body):
    return bytes([3 + len(body), 0x25, sub]) + bytes(body)


def gdesc(typ, idx, wlen):
    return bytes([0x80, 6, idx, typ, 0, 0]) + u16(wlen)
