#!/usr/bin/env python3
# Generates test/captures/netlink_mac80211_hwsim_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the mac80211_hwsim (Generic Netlink) coverage captures.

Usage: mkhwsim.py <outdir>
Writes netlink-mac80211-hwsim-coverage.pcap (LINKTYPE_NETLINK, 253) and
netlink-mac80211-hwsim-coverage-malformed.pcapng.
Everything is built with struct; nothing comes from a real network.
"""
import os
import struct
import sys

# ---- helpers (pcap/pcapng writers and netlink builders) ----------------
ARPHRD_NETLINK = 824
NETLINK_GENERIC = 16
GENL_ID_CTRL = 0x10
NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLM_F_DUMP = 0x300
NLA_F_NESTED = 0x8000
NLA_F_NET_BYTEORDER = 0x4000
FAMILY_ID = 0x21
FAMILY_NAME = b'MAC80211_HWSIM'


def pcap(fn, pkts, linktype=253):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(p), len(p)))
            f.write(p)


def pcapng(fn, pkts):
    """pkts: list of (linktype, bytes); one interface per link type."""
    def blk(t, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    ifs = {}
    for lt, _ in pkts:
        if lt not in ifs:
            ifs[lt] = len(ifs)
            out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (lt, p) in enumerate(pkts):
        ts = 1700000000 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifs[lt], ts >> 32, ts & 0xffffffff, len(p), len(p)) + p)
    with open(fn, 'wb') as f:
        f.write(out)


def sll(proto=NETLINK_GENERIC):
    return struct.pack('>HHH8sH', 4, ARPHRD_NETLINK, 0, b'\0' * 8, proto)


class Enc:
    def __init__(self, big=False):
        self.e = '>' if big else '<'

    def attr(self, t, payload=b'', flags=0):
        l = 4 + len(payload)
        return struct.pack(self.e + 'HH', l, t | flags) + payload + b'\0' * ((4 - l % 4) % 4)

    def u8(self, t, v, flags=0):
        return self.attr(t, struct.pack('B', v), flags)

    def u16(self, t, v, flags=0):
        return self.attr(t, struct.pack(self.e + 'H', v), flags)

    def u32(self, t, v, flags=0):
        return self.attr(t, struct.pack(self.e + 'I', v), flags)

    def u64(self, t, v, flags=0):
        return self.attr(t, struct.pack(self.e + 'Q', v), flags)

    def s(self, t, v, flags=0):
        return self.attr(t, v + b'\0', flags)

    def nlmsg(self, mtype, payload, flags=NLM_F_REQUEST, seq=1, pid=0):
        return struct.pack(self.e + 'IHHII', 16 + len(payload), mtype, flags, seq, pid) + payload

    def genl(self, cmd, attrs=b'', version=1):
        return struct.pack(self.e + 'BBH', cmd, version, 0) + attrs

    def frame(self, mtype, cmd, attrs=b'', **kw):
        return sll() + self.nlmsg(mtype, self.genl(cmd, attrs), **kw)


def newfamily(e, fid, name, **kw):
    """CTRL_CMD_NEWFAMILY (1) telling the dissector fid -> name."""
    return e.frame(GENL_ID_CTRL, 1, e.u16(1, fid) + e.s(2, name), **kw)
# ---- end helpers --------------------------------------------------------

LE = Enc()
BE = Enc(True)

(CMD_UNSPEC, CMD_REGISTER, CMD_FRAME, CMD_TX_INFO_FRAME, CMD_NEW_RADIO, CMD_DEL_RADIO,
 CMD_GET_RADIO, CMD_ADD_MAC_ADDR, CMD_DEL_MAC_ADDR, CMD_START_PMSR, CMD_ABORT_PMSR,
 CMD_REPORT_PMSR) = range(12)
(A_UNSPEC, A_RECEIVER, A_TRANSMITTER, A_FRAME, A_FLAGS, A_RX_RATE, A_SIGNAL, A_TX_INFO,
 A_COOKIE, A_CHANNELS, A_RADIO_ID, A_REG_HINT_ALPHA2, A_REG_CUSTOM_REG, A_REG_STRICT_REG,
 A_SUPPORT_P2P_DEVICE, A_USE_CHANCTX, A_DESTROY_RADIO_ON_CLOSE, A_RADIO_NAME, A_NO_VIF,
 A_FREQ, A_PAD, A_TX_INFO_FLAGS, A_PERM_ADDR, A_IFTYPE_SUPPORT, A_CIPHER_SUPPORT,
 A_MLO_SUPPORT, A_PMSR_SUPPORT, A_PMSR_REQUEST, A_PMSR_RESULT, A_MULTI_RADIO) = range(30)

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
# 802.11 beacon-like management frame header (24 bytes) + a few bytes
DOT11 = bytes.fromhex('80000000ffffffffffff020000000001020000000001' '1000') + b'\0' * 12


def t(cmd, attrs=b'', e=LE, **kw):
    return e.frame(FAMILY_ID, cmd, attrs, **kw)


def main_frames():
    f = []
    # 1: map the dynamic family id to the family name
    f.append(newfamily(LE, FAMILY_ID, FAMILY_NAME))
    # 2: command without a payload
    f.append(t(CMD_REGISTER))
    # 3: NEW_RADIO: strings, flags (zero length attributes), u32, bytes
    f.append(t(CMD_NEW_RADIO,
               LE.u32(A_CHANNELS, 2) + LE.s(A_RADIO_NAME, b'hwsim0') +
               LE.s(A_REG_HINT_ALPHA2, b'US') + LE.attr(A_SUPPORT_P2P_DEVICE) +
               LE.attr(A_USE_CHANCTX) + LE.attr(A_DESTROY_RADIO_ON_CLOSE) +
               LE.attr(A_NO_VIF) + LE.attr(A_REG_STRICT_REG) +
               LE.u32(A_REG_CUSTOM_REG, 7) +
               LE.u32(A_IFTYPE_SUPPORT, 0x1ae) + LE.u64(A_CIPHER_SUPPORT, 0x0fac040fac020fac) +
               LE.attr(A_MLO_SUPPORT) + LE.attr(A_MULTI_RADIO),
               flags=NLM_F_REQUEST | NLM_F_ACK))
    # 4: FRAME as sent by the kernel to the wmediumd-like userspace
    f.append(t(CMD_FRAME,
               LE.attr(A_RECEIVER, MAC_A) + LE.attr(A_TRANSMITTER, MAC_B) +
               LE.attr(A_FRAME, DOT11) + LE.u32(A_FLAGS, 2) + LE.u32(A_RX_RATE, 1) +
               LE.u32(A_SIGNAL, 0xffffffd8) + LE.u32(A_FREQ, 2412) +
               LE.u64(A_COOKIE, 0x1122334455667788) +
               LE.attr(A_TX_INFO, bytes(range(16))) + LE.u32(A_TX_INFO_FLAGS, 0),
               pid=1234))
    # 5: TX_INFO_FRAME, with a 16-bit value
    f.append(t(CMD_TX_INFO_FRAME,
               LE.attr(A_TRANSMITTER, MAC_B) + LE.u16(A_TX_INFO_FLAGS, 3) +
               LE.u32(A_FLAGS, 4) + LE.u32(A_SIGNAL, 0xffffffc4) +
               LE.attr(A_TX_INFO, bytes(range(8))) + LE.u64(A_COOKIE, 5), pid=1234))
    # 6: DEL_RADIO and 7: GET_RADIO by id and by name
    f.append(t(CMD_DEL_RADIO, LE.u32(A_RADIO_ID, 3)))
    f.append(t(CMD_GET_RADIO, LE.u32(A_RADIO_ID, 1), flags=NLM_F_REQUEST | NLM_F_DUMP))
    f.append(t(CMD_GET_RADIO, LE.s(A_RADIO_NAME, b'hwsim1')))
    # 9, 10: MAC address commands
    f.append(t(CMD_ADD_MAC_ADDR, LE.u32(A_RADIO_ID, 1) + LE.attr(A_PERM_ADDR, MAC_A)))
    f.append(t(CMD_DEL_MAC_ADDR, LE.u32(A_RADIO_ID, 1) + LE.attr(A_PERM_ADDR, MAC_A)))
    # 11-13: peer measurement; the nested attributes are not decoded
    nest = LE.u32(1, 9) + LE.attr(2, b'\x01\x02\x03')
    f.append(t(CMD_START_PMSR, LE.u32(A_RADIO_ID, 1) +
               LE.attr(A_PMSR_SUPPORT, LE.attr(1, nest), NLA_F_NESTED) +
               LE.attr(A_PMSR_REQUEST, LE.attr(1, nest), NLA_F_NESTED)))
    f.append(t(CMD_ABORT_PMSR, LE.u32(A_RADIO_ID, 1) + LE.attr(A_PMSR_REQUEST, nest, NLA_F_NESTED)))
    f.append(t(CMD_REPORT_PMSR, LE.u32(A_RADIO_ID, 1) + LE.attr(A_PMSR_RESULT, nest, NLA_F_NESTED)))
    # 14: unknown command and unknown attribute types, odd sizes, empty name
    f.append(t(40, LE.attr(77, b'x') + LE.attr(78, b'abc') + LE.attr(79, b'12345') +
               LE.attr(A_RADIO_NAME) + LE.s(A_RADIO_NAME, b'a-longer-radio-name-7')))
    # 15: radio name with the nested and network byte order flags
    f.append(t(CMD_NEW_RADIO, LE.s(A_RADIO_NAME, b'flagged', NLA_F_NESTED) +
               LE.attr(A_CHANNELS, struct.pack('>I', 4), NLA_F_NET_BYTEORDER) +
               LE.attr(A_SIGNAL, struct.pack('>H', 0x1234), NLA_F_NET_BYTEORDER)))
    # 16: message in big endian byte order (the dissector guesses it from the length)
    f.append(t(CMD_NEW_RADIO, BE.s(A_RADIO_NAME, b'hwsim-be') + BE.u32(A_CHANNELS, 3) +
               BE.u16(A_SIGNAL, 0x55), e=BE))
    # 17: two messages in one packet, the second one without a payload
    f.append(sll() + LE.nlmsg(FAMILY_ID, LE.genl(CMD_GET_RADIO, LE.u32(A_RADIO_ID, 7)), seq=7) +
             LE.nlmsg(FAMILY_ID, LE.genl(CMD_REGISTER), seq=8))
    # 18: a netlink control message (NLMSG_DONE, type 3) and an error (type 2)
    f.append(sll() + struct.pack('<IHHII', 20, 3, 2, 9, 0) + struct.pack('<i', 0))
    f.append(sll() + struct.pack('<IHHII', 36, 2, 0, 9, 0) + struct.pack('<i', -2) +
             struct.pack('<IHHII', 16, FAMILY_ID, 1, 9, 0))
    return f


def malformed():
    f = []
    f.append((253, newfamily(LE, FAMILY_ID, FAMILY_NAME)))
    # attribute with a length of 3 (smaller than the header) stops the list
    f.append((253, t(CMD_NEW_RADIO, LE.u32(A_CHANNELS, 1) + struct.pack('<HH', 3, A_FRAME) + b'\0\0\0\0')))
    # attribute longer than the message
    f.append((253, t(CMD_FRAME, LE.u32(A_FLAGS, 1) + struct.pack('<HH', 400, A_FRAME) + b'\x80\0\0\0')))
    # trailing bytes shorter than an attribute header
    f.append((253, t(CMD_FRAME, LE.u32(A_FLAGS, 1) + b'\0\0')))
    # a radio name that is not null terminated at the end of the message
    f.append((253, t(CMD_NEW_RADIO, struct.pack('<HH', 10, A_RADIO_NAME) + b'abcdef')))
    # message length field larger than the data
    p = LE.genl(CMD_FRAME, LE.u32(A_FLAGS, 1))
    f.append((253, sll() + struct.pack('<IHHII', 16 + len(p) + 40, FAMILY_ID, 1, 1, 0) + p))
    # message length below the header size
    f.append((253, sll() + struct.pack('<IHHII', 8, FAMILY_ID, 1, 1, 0) + p))
    # genl header cut short
    f.append((253, sll() + struct.pack('<IHHII', 18, FAMILY_ID, 1, 1, 0) + b'\x01\x01'))
    return f


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    pcap(os.path.join(out, 'netlink-mac80211-hwsim-coverage.pcap'), main_frames())
    pcapng(os.path.join(out, 'netlink-mac80211-hwsim-coverage-malformed.pcapng'), malformed())


if __name__ == '__main__':
    main()
