# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Helpers shared by the ZigBee TLV / Security / Direct coverage generators.

Everything is synthetic.  Frames are built with struct only; there is no
cryptography here: secured frames carry filler bytes in place of the
payload and the MIC.
"""
import struct

LT_IEEE802_15_4_NOFCS = 230
LT_BLUETOOTH_H4_PHDR = 201
LT_EXPORTED_PDU = 252


# ---------------------------------------------------------------- pcapng
class Pcapng:
    def __init__(self):
        self.ifaces = []     # linktypes
        self.recs = []       # (ifid, data, orig_len)

    def iface(self, linktype):
        if linktype not in self.ifaces:
            self.ifaces.append(linktype)
        return self.ifaces.index(linktype)

    def add(self, linktype, data, orig_len=None):
        self.recs.append((self.iface(linktype), data, orig_len))
        return len(self.recs)             # 1-based frame number

    def __len__(self):
        return len(self.recs)

    @staticmethod
    def _blk(btype, body):
        pad = (-len(body)) % 4
        total = 12 + len(body) + pad
        return struct.pack('<II', btype, total) + body + b'\0' * pad + struct.pack('<I', total)

    def write(self, path):
        out = self._blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        for lt in self.ifaces:
            out += self._blk(1, struct.pack('<HHI', lt, 0, 262144))
        for i, (ifid, data, olen) in enumerate(self.recs):
            ts = (1700000000 + i) * 1000000
            body = struct.pack('<IIIII', ifid, ts >> 32, ts & 0xffffffff,
                               len(data), olen if olen is not None else len(data))
            out += self._blk(6, body + data)
        with open(path, 'wb') as f:
            f.write(out)


# ------------------------------------------------------------- Bluetooth
def u128(s):
    """UUID string -> 16 bytes little endian (as on the wire)."""
    return bytes.fromhex(s.replace('-', ''))[::-1]


def zbd_char(n):
    return u128('7072377d-%04x-421c-b163-491c27333a61' % n)


CH_DUMP = u128('29144af4-00ff-4481-bfe9-6d0299b429e3')
CH_SEC_AESMMO = u128('29144af4-0001-4481-bfe9-6d0299b429e3')
CH_SEC_SHA256 = u128('29144af4-0002-4481-bfe9-6d0299b429e3')
CH_SEC_P256 = u128('29144af4-0003-4481-bfe9-6d0299b429e3')
CH_FORM, CH_JOIN, CH_PERMIT, CH_LEAVE, CH_STATUS, CH_MANAGE, CH_IDENTIFY, CH_FB = \
    [zbd_char(i) for i in range(1, 9)]
CH_TUNNEL = bytes([0x3f, 0x31, 0xd5, 0x8b, 0x37, 0xb2, 0x20, 0x81,
                   0xf4, 0x45, 0x01, 0x00, 0xfd, 0x78, 0xd1, 0x8b])

# handle assignment used by every ZBD capture of this series
HANDLES = [(0x0020, CH_DUMP), (0x0021, CH_SEC_AESMMO), (0x0022, CH_SEC_SHA256),
           (0x0023, CH_SEC_P256), (0x0030, CH_FORM), (0x0031, CH_JOIN),
           (0x0032, CH_PERMIT), (0x0033, CH_LEAVE), (0x0034, CH_STATUS),
           (0x0035, CH_MANAGE), (0x0036, CH_IDENTIFY), (0x0037, CH_FB),
           (0x0040, CH_TUNNEL)]
H = {u: h for h, u in HANDLES}
BDADDR = bytes([0x55, 0x44, 0x33, 0x22, 0x11, 0x02])    # LE order on the wire
CONN = 0x0040


def hci_conn_complete(handle=CONN, bdaddr=BDADDR):
    """HCI Connection Complete event, so ACL data has a connection session."""
    params = struct.pack('<BH', 0, handle) + bdaddr + bytes([1, 0])
    return struct.pack('>I', 1) + bytes([0x04, 0x03, len(params)]) + params


def h4_acl(att, direction=1, handle=CONN):
    l2cap = struct.pack('<HH', len(att), 0x0004) + att
    acl = struct.pack('<HH', handle | 0x2000, len(l2cap)) + l2cap
    return struct.pack('>I', direction) + b'\x02' + acl


def att_find_info(pairs, direction=1):
    body = b''.join(struct.pack('<H', h) + u for h, u in pairs)
    return h4_acl(b'\x05\x02' + body, direction)


def att_notify(handle, value, direction=1):
    return h4_acl(b'\x1b' + struct.pack('<H', handle) + value, direction)


def att_indicate(handle, value, direction=1):
    return h4_acl(b'\x1d' + struct.pack('<H', handle) + value, direction)


def att_write(handle, value, direction=0):
    return h4_acl(b'\x12' + struct.pack('<H', handle) + value, direction)


def att_write_cmd(handle, value, direction=0):
    return h4_acl(b'\x52' + struct.pack('<H', handle) + value, direction)


def att_read_rsp(value, direction=1):
    return h4_acl(b'\x0b' + value, direction)


# ------------------------------------------------------------------- TLV
def tlv(t, value):
    """Type, length-1, value (all ZigBee TLVs use length = len(value)-1)."""
    assert 1 <= len(value) <= 256
    return bytes([t, len(value) - 1]) + value


def ieee(n):
    return struct.pack('<Q', n)


EUI_A = 0x00124b0001020304
EUI_B = 0x00124b00aabbccdd
EUI_C = 0x0200000000000001


# ---------------------------------------------------------------- 802.15.4
def wpan_data(payload, seq=1, pan=0x1a62, dst=0x0000, src=0x0001):
    """Data frame, PAN ID compression, short dst and src (no FCS)."""
    return struct.pack('<HBHHH', 0x8841, seq & 0xff, pan, dst, src) + payload


def wpan_beacon(payload, seq=1, pan=0x1a62, src=0x0000, gts=b'\x00', pending=b'\x00'):
    """Beacon frame, short source address, superframe spec 0xcfff / 0xff4f."""
    hdr = struct.pack('<HBHH', 0x8000, seq & 0xff, pan, src)
    return hdr + struct.pack('<H', 0xcfff) + gts + pending + payload


# --------------------------------------------------------------------- NWK
F_SEC = 0x0200
F_SRCROUTE = 0x0400
F_EXTDST = 0x0800
F_EXTSRC = 0x1000
F_MCAST = 0x0100


def nwk(payload, cmd=False, ver=2, src=0x0001, dst=0x0000, radius=30, seq=1,
        ext_src=EUI_A, ext_dst=None, sec=None, mcast=None, route=None, interpan=False):
    """NWK frame.  `sec` is the pre-built security header + MIC filler
    that follows the NWK header (see sec_hdr); the payload then follows
    it.  Without `sec` the payload follows the header directly."""
    fcf = (1 if cmd else 0) | (ver << 2)
    if sec is not None:
        fcf |= F_SEC
    if ext_src is False:
        ext_src = None
    if ext_src is not None:
        fcf |= F_EXTSRC
    if ext_dst is not None:
        fcf |= F_EXTDST
    if mcast is not None:
        fcf |= F_MCAST
    if route is not None:
        fcf |= F_SRCROUTE
    b = struct.pack('<HHHBB', fcf, dst, src, radius, seq & 0xff)
    if ext_dst is not None:
        b += ieee(ext_dst)
    if ext_src is not None:
        b += ieee(ext_src)
    if mcast is not None:
        b += bytes([mcast])
    if route is not None:
        idx, relays = route
        b += bytes([len(relays), idx]) + b''.join(struct.pack('<H', r) for r in relays)
    if sec is not None:
        b += sec
    return b + payload


def sec_hdr(key_id=1, counter=1, src64=None, keyseq=0, level=5, verified=False):
    """ZigBee security auxiliary header (control, counter, [src64], [keyseq])."""
    ctl = (level & 7) | ((key_id & 3) << 3) | ((1 << 5) if src64 is not None else 0) \
        | ((1 << 6) if verified else 0)
    b = bytes([ctl]) + struct.pack('<I', counter)
    if src64 is not None:
        b += ieee(src64)
    if key_id == 1:
        b += bytes([keyseq])
    return b


FILL = b'\xa5'    # filler for encrypted payload and MIC: never a valid MIC


def filler(n, v=0xa5):
    return bytes([v]) * n


# --------------------------------------------------------------------- APS
def aps_data(payload, cluster, profile=0x0104, dst_ep=1, src_ep=1, counter=1,
             delivery=0, security=False, ack_req=False, ext=None, group=None):
    fcf = 0x00 | (delivery << 2) | (0x20 if security else 0) | (0x40 if ack_req else 0) \
        | (0x80 if ext is not None else 0)
    b = bytes([fcf])
    if delivery != 3:
        b += bytes([dst_ep])
    if delivery == 3:
        b += struct.pack('<H', group or 0)
    b += struct.pack('<HHB', cluster, profile, src_ep) + bytes([counter & 0xff])
    if ext is not None:
        b += ext
    return b + payload


def aps_cmd(cmd, payload=b'', counter=1, security=False):
    fcf = 0x01 | (0x20 if security else 0)
    return bytes([fcf, counter & 0xff, cmd]) + payload


def zdp(cluster, body, counter=1, seq=1, **kw):
    """ZDP over APS data: 1 byte ZDP sequence + body."""
    return aps_data(bytes([seq & 0xff]) + body, cluster, profile=0x0000,
                    dst_ep=0, src_ep=0, counter=counter, **kw)


def transport_key(key, keytype=1, seq=0, dst64=EUI_A, src64=EUI_B, counter=1):
    """APS Transport-Key command, plaintext (the key travels in the clear
    in this synthetic frame; it is a made-up constant)."""
    desc = key + bytes([seq]) + ieee(dst64) + ieee(src64)
    return aps_cmd(0x05, bytes([keytype]) + desc, counter)


def att_mtu(mtu, direction):
    """Exchange MTU request (sent) / response (received)."""
    return h4_acl(bytes([0x02 if direction == 0 else 0x03]) + struct.pack('<H', mtu), direction)
