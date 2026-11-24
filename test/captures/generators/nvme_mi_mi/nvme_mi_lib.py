# Helper module for the nvme_mi_mi capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Helpers shared by the NVMe-MI generators (mknvme_mi*.py).

NVMe-MI messages travel in MCTP (message type 4).  Frames are built with
struct only: pcapng with two interfaces, 0 = Linux cooked capture
(DLT 113, ARPHRD_MCTP, protocol 0x00FA) and 1 = Linux I2C (DLT 209), the
SMBus binding that gives the dissector physical addresses.  The MIC of a
message is a CRC-32C (an integrity check, no keys).
"""
import struct

HOST, DEV = 8, 9          # MCTP endpoint IDs

LT_SLL, LT_I2C, LT_EXPPDU = 113, 209, 252


# ---------------------------------------------------------------- pcapng
def _blk(btype, body):
    pad = (-len(body)) % 4
    tl = 12 + len(body) + pad
    return struct.pack('<II', btype, tl) + body + b'\0' * pad + struct.pack('<I', tl)


class Cap:
    def __init__(self):
        self.frames = []        # (ifid, data, captured_length)
        self.marks = []

    def add(self, ifid, data, cap=None):
        self.frames.append((ifid, bytes(data), len(data) if cap is None else cap))
        return len(self.frames)

    def mark(self, name):
        self.marks.append((len(self.frames) + 1, name))

    def write(self, path):
        out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in (LT_SLL, LT_I2C, LT_EXPPDU):
            out += _blk(1, struct.pack('<HHI', lt, 0, 65535))
        for i, (ifid, d, cap) in enumerate(self.frames):
            ts = (1700000000 + i) * 1000000 + (i % 7) * 1500
            out += _blk(6, struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff,
                                       cap, len(d)) + d[:cap])
        with open(path, 'wb') as f:
            f.write(out)

    def report(self, name):
        for i, (n, s) in enumerate(self.marks):
            e = self.marks[i + 1][0] - 1 if i + 1 < len(self.marks) else len(self.frames)
            print('%s %d-%d: %s' % (name, n, e, s))


def exported_pdu(name, payload):
    """Exported PDU (interface 2) naming a registered dissector: the body
    dissectors are then called with no NVMe-MI context"""
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('!HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('!HH', 0, 0) + payload


# ---------------------------------------------------------------- CRC-32C
def _mk_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0x82F63B78 if c & 1 else 0)
        t.append(c)
    return t


_T = _mk_table()


def crc32c(data):
    c = 0xffffffff
    for b in data:
        c = _T[(c ^ b) & 0xff] ^ (c >> 8)
    return c ^ 0xffffffff


# ------------------------------------------------------------------ MCTP
NMIMT_CONTROL, NMIMT_MI, NMIMT_ADMIN, NMIMT_PCIE, NMIMT_AEM = 0, 1, 2, 4, 5


def mi_msg(nmimt, ror, csi, body, ic=False, meb=0, ciap=0, bad_mic=False, mic=True):
    """MCTP message payload: message type byte + the 3 header bytes + body
    [+ MIC].  With ic=True the MIC (CRC-32C over everything before it,
    little endian) is appended."""
    hdr = bytes([0x04 | (0x80 if ic else 0),
                 (csi & 1) | (nmimt << 3) | (ror << 7),
                 (meb & 1) | ((ciap & 1) << 1), 0])
    m = hdr + body
    if ic and mic:
        c = crc32c(m)
        if bad_mic:
            c ^= 0xffffffff
        m += struct.pack('<I', c)
    return m


def mctp(payload, src, dst, tag, to, som=1, eom=1, seq=0, ver=1):
    flags = (som << 7) | (eom << 6) | ((seq & 3) << 4) | (to << 3) | (tag & 7)
    return bytes([ver, dst, src, flags]) + payload


def sll(mctp_pkt, outgoing=True):
    return struct.pack('>HHH8sH', 4 if outgoing else 0, 290, 0, b'', 0x00fa) + mctp_pkt


def pec(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xff if crc & 0x80 else (crc << 1) & 0xff
    return crc


def i2c(mctp_pkt, dst=0x40, src=0x81, with_pec=True):
    """SMBus block write (command code 0x0f) in a Linux I2C pseudo frame"""
    body = mctp_pkt
    i2cb = bytes([dst, 0x0f, len(body) + 1, src]) + body
    if with_pec:
        i2cb += bytes([pec(i2cb)])
    return bytes([0]) + struct.pack('>I', 0) + i2cb


class Link:
    """Sends requests (host -> device, TO=1) and responses (device -> host,
    TO=0) over one of the two interfaces."""

    def __init__(self, cap, smbus=False, host=HOST, dev=DEV):
        self.cap, self.smbus, self.host, self.dev = cap, smbus, host, dev
        self.tag = 0

    def _emit(self, pkt, outgoing, req):
        if self.smbus:
            if req:
                self.cap.add(1, i2c(pkt, dst=0x40, src=0x81))
            else:
                self.cap.add(1, i2c(pkt, dst=0x80, src=0x41))
        else:
            self.cap.add(0, sll(pkt, outgoing))

    def req(self, msg, tag=None, src=None, dst=None, frag=None, cap=None):
        t = self.tag if tag is None else tag
        if self.smbus and len(msg) > 64:
            self.fragmented(msg, req=True, tag=t)      # SMBus: at most 64 octets per packet
            return t
        pkt = mctp(msg, self.host if src is None else src, self.dev if dst is None else dst,
                   t, 1)
        n = self._emit(pkt, True, True)
        return t

    def resp(self, msg, tag=None, src=None, dst=None):
        t = self.tag if tag is None else tag
        if self.smbus and len(msg) > 64:
            self.fragmented(msg, req=False, tag=t)
            return t
        pkt = mctp(msg, self.dev if src is None else src, self.host if dst is None else dst,
                   t, 0)
        self._emit(pkt, False, False)
        return t

    def nxt(self):
        self.tag = (self.tag + 1) & 7

    def fragmented(self, msg, req=True, tag=None, mtu=64):
        """a message in several MCTP packets (SOM, middle, EOM)"""
        t = self.tag if tag is None else tag
        parts = [msg[i:i + mtu] for i in range(0, len(msg), mtu)]
        for i, p in enumerate(parts):
            pkt = mctp(p, self.host if req else self.dev, self.dev if req else self.host, t,
                       1 if req else 0, som=1 if i == 0 else 0,
                       eom=1 if i == len(parts) - 1 else 0, seq=i)
            self._emit(pkt, req, req)


# ------------------------------------------------------- common messages
def fill(n, seed=1):
    return bytes(((seed * 37 + i * 7 + (i >> 3)) & 0xff) for i in range(n))


def mi_cmd(opcode, cdw0=0, cdw1=0, data=b''):
    """MI command request body: opcode, 3 reserved, NMD0, NMD1, data"""
    return bytes([opcode, 0, 0, 0]) + struct.pack('<II', cdw0, cdw1) + data


def resp_body(status, nmresp=0, data=b''):
    """MI/Admin response body: status + 3 bytes + data"""
    return bytes([status]) + struct.pack('<I', nmresp)[:3] + data


def admin_sqe(opcode, cdw10=0, cdw11=0, cdw12=0, cdw13=0, cdw14=0, cdw15=0, nsid=0,
              flags=0, ctrl=0, dofst=0, dlen=0, cdw2=0, cdw3=0, mptr=0, resv0=0, resv1=0):
    return (bytes([opcode, flags]) + struct.pack('<HIIIQIIII', ctrl, nsid, cdw2, cdw3, mptr,
                                                  dofst, dlen, resv0, resv1)
            + struct.pack('<IIIIII', cdw10, cdw11, cdw12, cdw13, cdw14, cdw15))


def admin_resp(status, dw0=0, dw1=0, dw3=0, data=b'', short=False, nmresp=0):
    if short:
        return resp_body(status, nmresp, data)
    return resp_body(status, nmresp) + struct.pack('<III', dw0, dw1, dw3) + data
