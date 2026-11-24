#!/usr/bin/env python3
# AIM coverage capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""AIM (OSCAR) dissector (packet-aim.c and the AIM family sub-dissectors in
the same file).

The packet layouts follow what packet-aim.c parses; places where that looks
wrong are marked "NOTE".

Usage: mkaim.py [<output directory>]

Writes:
  aim-coverage.pcap            FLAP channels 1-5 and an unknown one, every
                               SNAC family and subtype the dissector knows,
                               every TLV value dissector, desegmentation
  aim-coverage-malformed.pcap  paths that end in an exception

TCP port 5190 is claimed by the "aol" dissector, so dissect with
  -d tcp.port==5190,aim

Every packet is built here; nothing comes from a real network.
"""

import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct

from capgen import eth, ipv4, tcp, write_pcap  # noqa: E402

AIM_PORT = 5190
CLIENT_PORT = 40001
SYN_OPTIONS = bytes.fromhex('020405b404020101')  # MSS, SACK permitted


class Pcap:
    def __init__(self):
        self.frames = []

    def tcp(self, sport, dport, seq, ack, flags, payload=b'', src=(10, 0, 0, 1), dst=(10, 0, 0, 2)):
        seg = tcp(payload, sport, dport, seq=seq, ack=ack, flags=flags,
                  options=SYN_OPTIONS if flags & 0x02 else b'', src=bytes(src), dst=bytes(dst))
        ip = ipv4(seg, 6, src=bytes(src), dst=bytes(dst), ident=len(self.frames) & 0xffff,
                  flags_frag=0x4000)
        self.frames.append(eth(ip, 0x0800, dst='02:00:00:00:00:02', src='02:00:00:00:00:01'))

    def write(self, path):
        write_pcap(path, self.frames, ts=lambda i: (1700000000 + i // 100, (i % 100) * 10000))


class TcpStream:
    """A TCP connection with a handshake and correct sequence numbers."""
    def __init__(self, cap, cport=CLIENT_PORT, sport=AIM_PORT):
        self.cap, self.cport, self.sport = cap, cport, sport
        self.cseq, self.sseq = 1000, 5000
        cap.tcp(cport, sport, self.cseq, 0, 0x02)
        cap.tcp(sport, cport, self.sseq, self.cseq + 1, 0x12, src=(10, 0, 0, 2), dst=(10, 0, 0, 1))
        self.cseq += 1
        self.sseq += 1
        cap.tcp(cport, sport, self.cseq, self.sseq, 0x10)
        self.flapseq = 1

    def client(self, data):
        self.cap.tcp(self.cport, self.sport, self.cseq, self.sseq, 0x18, data)
        self.cseq += len(data)

    def server(self, data):
        self.cap.tcp(self.sport, self.cport, self.sseq, self.cseq, 0x18, data,
                     src=(10, 0, 0, 2), dst=(10, 0, 0, 1))
        self.sseq += len(data)


# ---------------------------------------------------------------------------
# OSCAR building blocks


def u8(v):
    return struct.pack('>B', v & 0xff)


def u16(v):
    return struct.pack('>H', v & 0xffff)


def u32(v):
    return struct.pack('>I', v & 0xffffffff)


def le16(v):
    return struct.pack('<H', v & 0xffff)


def le32(v):
    return struct.pack('<I', v & 0xffffffff)


_flapseq = [0]


def flap(channel, data=b''):
    _flapseq[0] += 1
    return struct.pack('>BBHH', 0x2a, channel, _flapseq[0], len(data)) + data


_reqid = [0]


def snac(family, subtype, payload=b'', flags=0):
    _reqid[0] += 1
    return flap(2, struct.pack('>HHHI', family, subtype, flags, _reqid[0]) + payload)


def tlv(t, v):
    return u16(t) + u16(len(v)) + v


def bname(name):
    """A buddy name with a one octet length."""
    return u8(len(name)) + name


def tlvlist(*tlvs):
    """A TLV block that starts with the TLV count."""
    return u16(len(tlvs)) + b''.join(tlvs)


def guid(d1, d2, d3, d4):
    return u32(d1) + u16(d2) + u16(d3) + bytes(d4)


CAP_D4 = [0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00]
CAP_SEND_FILE = guid(0x09461343, 0x4c7f, 0x11d1, CAP_D4)
CAP_ICQ_UTF8 = guid(0x0946134e, 0x4c7f, 0x11d1, CAP_D4)
CAP_CHAT = guid(0x748f2420, 0x6287, 0x11d1, CAP_D4)
CAP_RTF = guid(0x97b12751, 0x243c, 0x4334, [0xad, 0x22, 0xd6, 0xab, 0xf7, 0x3f, 0x14, 0x92])
CAP_UNKNOWN = guid(0x01020304, 0x0506, 0x0708, [9, 10, 11, 12, 13, 14, 15, 16])

PLUGIN_NONE = bytes(16)
PLUGIN_STATUS_MANAGER = guid(0xD140CF10, 0xE94F, 0x11D3, [0xBC, 0xD2, 0x00, 0x04, 0xAC, 0x96, 0xDD, 0x96])

# Direct connection info: 35 octets as dissect_aim_tlv_value_dcinfo() reads
# them (NOTE: it adds the 4 octet auth cookie but steps over 2 octets).
DCINFO = (bytes([192, 168, 1, 10]) + u32(4000) + u8(4) + u16(8) + b'\xc0\x0c' +
          u32(80) + u32(3) + u32(1100000000) + u32(1100000001) + u32(1100000002) + u16(0))

# Online buddy TLVs: every type in aim_onlinebuddy_tlvs, plus an unknown one
ONLINEBUDDY_ALL = [
    tlv(0x0001, u16(0x0050)),                                   # user class
    tlv(0x0003, u32(1100000000)),                               # online since
    tlv(0x0004, u16(120)),                                      # idle time
    tlv(0x0005, u32(1000000000)),                               # member since
    tlv(0x0006, u32(0x00000001)),                               # status
    tlv(0x000a, bytes([10, 1, 2, 3])),                          # IP address
    tlv(0x000c, DCINFO),                                        # DC info
    tlv(0x000d, CAP_SEND_FILE + CAP_RTF + CAP_UNKNOWN),         # capabilities
    tlv(0x000f, u32(3600)),                                     # session length
    tlv(0x0010, u32(7200)),                                     # ICQ session length
    tlv(0x0011, b'\x01\x02\x03\x04\x05'),                       # time update
    tlv(0x0014, u8(1)),                                         # instance number
    tlv(0x0019, u16(0x1343) + u16(0x0000) + u16(0x0001) + u16(0x0105)),  # short caps
    tlv(0x001d, b'\x00\x01\x01\x10' + bytes(16)),               # BART info
    tlv(0x001f, u32(0)),                                        # nick flags 2
    tlv(0x0023, u32(1100000003)),                               # buddy feed time
    tlv(0x0026, u32(1100000004)),                               # sig time
    tlv(0x0027, u32(1100000005)),                               # away time
    tlv(0x002a, b'AU'),                                         # country
    tlv(0x7777, b'unknown'),                                    # not in the table
]


def userinfo(name, tlvs):
    return bname(name) + u16(0) + tlvlist(*tlvs)


# Client TLVs: every type in aim_client_tlvs, plus an unknown one
CLIENT_ALL = [
    tlv(0x0001, b'alice'), tlv(0x0002, b'\x11\x22\x33'), tlv(0x0012, b'\x44\x55'),
    tlv(0x0003, b'AOL Instant Messenger, version 5.9'), tlv(0x0016, u16(0x0109)),
    tlv(0x0017, u16(5)), tlv(0x0018, u16(9)), tlv(0x0019, u16(0)), tlv(0x001a, u16(3702)),
    tlv(0x0025, bytes(range(16))), tlv(0x0014, u32(0xd2)), tlv(0x000f, b'en'),
    tlv(0x000e, b'us'), tlv(0x0005, b'bos.example.invalid:5190'), tlv(0x0006, b'\xc0\x0c\x1e'),
    tlv(0x0004, b'http://err.example.invalid/'), tlv(0x0008, u16(5)), tlv(0x0009, u16(1)),
    tlv(0x000a, b'login.example.invalid'), tlv(0x000b, b'http://www.example.invalid/'),
    tlv(0x000c, u16(0)), tlv(0x0011, b'alice@example.invalid'), tlv(0x0013, u16(3)),
    tlv(0x0040, u32(100)), tlv(0x0041, b'http://beta.example.invalid/'),
    tlv(0x0042, b'beta info'), tlv(0x0043, b'beta name'), tlv(0x0044, u32(99)),
    tlv(0x0045, b'http://release.example.invalid/'), tlv(0x0046, b'release info'),
    tlv(0x0047, b'release name'), tlv(0x0048, bytes(16)), tlv(0x0049, bytes(16)),
    tlv(0x004a, u8(1)), tlv(0x000d, u16(0x0013)),
    tlv(0x0054, b'http://pw.example.invalid/'), tlv(0x0066, b''), tlv(0x00c8, u16(1) + u16(2)),
    tlv(0x00c9, u32(0xffffffff)), tlv(0x00ca, u8(1)), tlv(0x00cb, u16(0x0010)),
    tlv(0x00cc, u32(0xffffffff)), tlv(0x00cd, b'shortcut'), tlv(0x00d4, u32(1100000000)),
    tlv(0x00d5, bytes(16)), tlv(0x0131, b'Bob'), tlv(0x0137, b'bob@example.invalid'),
    tlv(0x013a, b'+15550100'), tlv(0x013c, b'a comment'), tlv(0x013d, u16(1)),
    tlv(0x013e, b'ding.wav'), tlv(0x0145, u32(1100000000)),
    tlv(0x6666, b'unknown'),
]

LOCATE_ALL = [
    tlv(0x0001, b'text/aolrtf; charset="us-ascii"'), tlv(0x0002, b'<HTML>profile</HTML>'),
    tlv(0x0003, b'text/aolrtf; charset="us-ascii"'), tlv(0x0004, b'<HTML>away</HTML>'),
    tlv(0x0005, CAP_CHAT + CAP_ICQ_UTF8), tlv(0x000a, u32(1100000000)),
    tlv(0x000b, u32(1100000001)), tlv(0x000c, u8(1)), tlv(0x000d, b'text/plain'),
    tlv(0x000e, b'buddy data'), tlv(0x5555, b'unknown'),
]

RENDEZVOUS_ALL = [
    tlv(0x0001, u16(1)), tlv(0x0002, bytes([10, 0, 0, 1])), tlv(0x0003, bytes([10, 0, 0, 2])),
    tlv(0x0004, bytes([10, 0, 0, 3])), tlv(0x0005, u16(5190)),
    tlv(0x0006, b'http://dl.example.invalid/'), tlv(0x0008, b'http://vdl.example.invalid/'),
    tlv(0x000a, u16(1)), tlv(0x000b, u16(2)), tlv(0x000c, b'Join me'),
    tlv(0x000d, b'us-ascii'), tlv(0x000e, b'en'), tlv(0x000f, b''), tlv(0x0010, b''),
    tlv(0x0011, b''), tlv(0x0012, u16(2)), tlv(0x0013, u16(1)), tlv(0x0014, u16(1)),
    tlv(0x0015, b'text/plain'), tlv(0x0016, bytes([0xf5, 0xff, 0xff, 0xfe])),
    tlv(0x0017, u16(0xebb9)),
    tlv(0x0018, bname(b'10.0.0.1:5190') + bname(b'10.0.0.2:4443')),
    tlv(0x0019, b'session'), tlv(0x001a, b'rollover'), tlv(0x2711, b'\x1b\x00' + bytes(25)),
    tlv(0x277e, b'invitees'), tlv(0x4444, b'unknown'),
]


def messageblock(*msgs, features=b'\x01\x01\x02'):
    b = u8(5) + u8(1) + u16(len(features)) + features
    for m in msgs:
        b += u16(0x0101) + u16(len(m) + 4) + u16(0) + u16(0) + m
    return b


def rendezvous(msgtype, tlvs):
    return u16(msgtype) + b'\x01\x02\x03\x04\x05\x06\x07\x08' + CAP_SEND_FILE + b''.join(tlvs)


def icq_meta(req_type, rest=b''):
    body = le32(123456789) + le16(req_type) + le16(2) + rest
    return tlv(0x0001, le16(len(body)) + body)


def extended_data(plugin, tail):
    """Extended data as dissect_aim_tlv_value_extended_data() reads it."""
    first = u16(9) + plugin + le16(0) + u32(0) + u8(0) + le16(0xfffe)
    second = le16(0xfffd) + bytes(12)
    return le16(len(first)) + first + le16(len(second)) + second + tail


def rate_class(cid):
    return (u16(cid) + u32(80) + u32(2500) + u32(2000) + u32(1500) + u32(800) +
            u32(3000) + u32(6000) + u32(0) + u8(3))


def chat_payload(name, msg, gap):
    """Chat message: the name is read at offset 30, the message at gap+len(name)."""
    head = bytes(range(0x40, 0x40 + 30))
    body = bname(name)
    body += b'\x00' * (gap - 31)
    return head + body + msg


# ---------------------------------------------------------------------------

def generic(s):
    F = 0x0001
    s.server(snac(F, 0x0001, u16(0x0004) + tlv(0x0004, b'http://err.example.invalid/')))
    s.server(snac(F, 0x0001, u16(0x0099)))                              # unknown error code
    s.client(snac(F, 0x0002, b''.join(u16(f) + u16(v) + u16(0x0110) + u16(0x08e4)
                                      for f, v in ((1, 4), (0x13, 4), (0x99, 1)))))
    s.server(snac(F, 0x0003, u16(1) + u16(2) + u16(3) + u16(4) + u16(0x99)))
    s.client(snac(F, 0x0004, u16(0x000e)))
    s.client(snac(F, 0x0004, u16(0x0099)))                              # unknown family
    s.server(snac(F, 0x0005, tlv(0x000d, u16(0x0e)) + tlv(0x0005, b'chat.example.invalid:5190') +
                  tlv(0x0006, b'\x01\x02\x03\x04')))
    s.client(snac(F, 0x0006))
    s.server(snac(F, 0x0007, u16(2) + rate_class(1) + rate_class(2) +
                  u16(1) + u16(3) + u16(1) + u16(2) + u16(4) + u16(6) + u16(0x99) + u16(1) +
                  u16(2) + u16(0)))
    s.client(snac(F, 0x0008, u16(1) + u16(2)))
    s.server(snac(F, 0x000a, u16(2) + rate_class(1)))
    s.server(snac(F, 0x000b))
    s.client(snac(F, 0x000c, u16(1) + u16(4)))
    s.server(snac(F, 0x000d))
    s.client(snac(F, 0x000e))
    s.server(snac(F, 0x000f, userinfo(b'alice', ONLINEBUDDY_ALL)))
    # NOTE: dissect_aim_generic_evil() adds the new warning level but then
    # reads user info from offset 0, so the high octet of the warning level
    # is the buddy name length. Warning level 0x0000 lines this up as an
    # empty name, warning level 0x0000 and one TLV.
    s.server(snac(F, 0x0010, u16(0) + u8(0) + u16(1) + tlv(0x0001, u16(0x10))))
    s.client(snac(F, 0x0011, u16(300)))
    s.server(snac(F, 0x0012, u16(2) + u16(0x13) + u16(0x02) +
                  tlv(0x0005, b'bos2.example.invalid') + tlv(0x0006, b'\xaa\xbb')))
    s.server(snac(F, 0x0013, u16(4) + tlv(0x000b, b'Welcome to the synthetic AIM service')))
    s.client(snac(F, 0x0014, u32(3)))
    s.server(snac(F, 0x0015, b'http://example.invalid/'))
    s.client(snac(F, 0x0016))
    s.client(snac(F, 0x0017, u16(1) + u16(4) + u16(0x13) + u16(4)))
    s.server(snac(F, 0x0018, u16(1) + u16(4) + u16(0x13) + u16(4)))
    s.client(snac(F, 0x001e, tlv(0x0006, u32(0x00030000)) + tlv(0x001d, b'\x00\x02\x04\x00') +
                  tlv(0x000c, DCINFO)))
    s.server(snac(F, 0x001f, u32(0x1000) + u32(0x20)))
    s.client(snac(F, 0x0020, bytes(range(16))))
    s.server(snac(F, 0x0021, u16(2) + u8(0x41) + u8(4) + b'away'))
    s.server(snac(F, 0x0099, b'unknown subtype'))
    # SNAC with the "contains version" flag: family version TLV first
    s.client(snac(F, 0x0011, u16(6) + tlv(0x0001, u16(4)) + u16(60), flags=0x8000))
    s.client(snac(F, 0x0011, u16(60), flags=0x0001))


def location(s):
    F = 0x0002
    s.server(snac(F, 0x0001, u16(0x000e)))
    s.client(snac(F, 0x0002))
    s.server(snac(F, 0x0003, tlv(1, u16(1024)) + tlv(2, u16(16)) + tlv(3, u16(0))))
    s.client(snac(F, 0x0004, b''.join(LOCATE_ALL)))
    for infotype in (1, 3, 5, 9):
        s.client(snac(F, 0x0005, u16(infotype) + bname(b'bob')))
    s.server(snac(F, 0x0006, bname(b'bob') + u16(0) + tlvlist(*ONLINEBUDDY_ALL[:3]) +
                  b''.join(LOCATE_ALL[:6])))
    s.client(snac(F, 0x0007, u16(0)))
    s.server(snac(F, 0x0008, bname(b'bob') + bname(b'carol')))
    s.client(snac(F, 0x0015, u32(1) + bname(b'bob')))


def buddylist(s):
    F = 0x0003
    s.server(snac(F, 0x0001, u16(0x0015)))
    s.client(snac(F, 0x0002))
    s.server(snac(F, 0x0003, tlv(1, u16(220)) + tlv(2, u16(750)) + tlv(3, u16(32)) + tlv(4, u16(1))))
    s.client(snac(F, 0x0004, bname(b'bob') + bname(b'carol')))
    s.client(snac(F, 0x0005, bname(b'carol')))
    s.client(snac(F, 0x0006))
    s.server(snac(F, 0x0007, bname(b'dave')))
    s.server(snac(F, 0x000a, bname(b'eve')))
    s.server(snac(F, 0x000b, userinfo(b'bob', ONLINEBUDDY_ALL)))
    s.server(snac(F, 0x000c, userinfo(b'bob', [tlv(0x0001, u16(0x0010))])))


def messaging(s):
    F = 0x0004
    cookie = b'\x31\x32\x33\x34\x35\x36\x37\x38'
    params = u16(0) + u32(0x0b) + u16(8000) + u16(999) + u16(999) + u32(0)
    s.server(snac(F, 0x0001, u16(0x0004)))
    s.client(snac(F, 0x0002, params))
    s.client(snac(F, 0x0003))
    s.client(snac(F, 0x0004))
    s.server(snac(F, 0x0005, params))
    # Outgoing IM, every channel 1 TLV
    ch1 = (tlv(0x0002, messageblock(b'<HTML>Hello Bob</HTML>', b'second part')) +
           tlv(0x0003, b'') + tlv(0x0004, b'') + tlv(0x0006, b'') + tlv(0x0008, u32(0x1000)) +
           tlv(0x0009, b'') + tlv(0x000b, b'') + tlv(0x3333, b'unknown'))
    s.client(snac(F, 0x0006, cookie + u16(1) + bname(b'bob') + ch1))
    # A message block whose block length is too short (warning, not error)
    s.client(snac(F, 0x0006, cookie + u16(1) + bname(b'bob') +
                  tlv(0x0002, u8(5) + u8(1) + u16(0) + u16(0x0101) + u16(4) + u32(0))))
    # Outgoing rendezvous with every rendezvous TLV
    ch2 = tlv(0x0005, rendezvous(0, RENDEZVOUS_ALL)) + tlv(0x0003, b'')
    s.client(snac(F, 0x0006, cookie + u16(2) + bname(b'bob') + ch2))
    s.client(snac(F, 0x0006, cookie + u16(4) + bname(b'bob') + b'channel 4 data'))
    # Incoming
    s.server(snac(F, 0x0007, cookie + u16(1) + userinfo(b'bob', ONLINEBUDDY_ALL[:2]) +
                  tlv(0x0002, messageblock(b'Hi Alice'))))
    s.server(snac(F, 0x0007, cookie + u16(2) + userinfo(b'bob', ONLINEBUDDY_ALL[:1]) +
                  tlv(0x0005, rendezvous(2, [tlv(0x000a, u16(1))]))))
    s.server(snac(F, 0x0007, cookie + u16(3) + userinfo(b'bob', []) + b'channel 3 data'))
    s.client(snac(F, 0x0008, u16(1) + bname(b'bob')))
    s.server(snac(F, 0x0009, u16(100) + u16(200)))
    s.server(snac(F, 0x000a, u16(1) + bname(b'bob') + u16(0) + u16(1) + u16(2)))
    # Client errors: rendezvous NAK, extended data with and without a
    # plugin, another reason, and channel specific without data
    s.server(snac(F, 0x000b, cookie + u16(2) + bname(b'bob') + u16(3) + u16(2) + u16(1)))
    s.server(snac(F, 0x000b, cookie + u16(1) + bname(b'bob') + u16(3) +
                  extended_data(PLUGIN_NONE, u8(0xe8) + u8(0x03) + u16(0) + u16(1) +
                                u16(9) + b'I am away')))
    s.server(snac(F, 0x000b, cookie + u16(4) + bname(b'bob') + u16(3) +
                  extended_data(PLUGIN_STATUS_MANAGER, b'plugin data')))
    s.server(snac(F, 0x000b, cookie + u16(4) + bname(b'bob') + u16(3) +
                  extended_data(CAP_UNKNOWN, b'plugin data')))
    s.server(snac(F, 0x000b, cookie + u16(1) + bname(b'bob') + u16(1)))
    s.server(snac(F, 0x000b, cookie + u16(1) + bname(b'bob') + u16(3)))
    s.server(snac(F, 0x000c, cookie + u16(1) + bname(b'bob')))
    for t in (0, 1, 2):
        s.client(snac(F, 0x0014, cookie + u16(1) + bname(b'bob') + u16(t)))


def adverts(s):
    F = 0x0005
    s.server(snac(F, 0x0001, u16(0x0005)))
    s.client(snac(F, 0x0002))
    s.server(snac(F, 0x0003, b'GIF89a\x01\x00\x01\x00\x00\x00\x00;'))


def invitation(s):
    F = 0x0006
    s.server(snac(F, 0x0001, u16(0x0006)))
    s.client(snac(F, 0x0002, tlv(0x0011, b'\x00') + tlv(0x0015, b'come join')))
    s.server(snac(F, 0x0003))


def admin(s):
    F = 0x0007
    s.server(snac(F, 0x0001, u16(0x000d)))
    s.client(snac(F, 0x0002, u16(0x0011) + u16(0)))
    s.server(snac(F, 0x0003, u16(3) + tlvlist(tlv(0x0011, b'alice@example.invalid'),
                                              tlv(0x0013, u16(3)))))
    s.client(snac(F, 0x0004, tlv(0x0011, b'new@example.invalid')))
    s.server(snac(F, 0x0005, u16(3) + tlvlist(tlv(0x0008, u16(0)))))
    s.client(snac(F, 0x0006))
    for st in (0x00, 0x1e, 0x23, 0x55):
        s.server(snac(F, 0x0007, u16(st) + tlv(0x0004, b'http://x.invalid/')))


def popup(s):
    F = 0x0008
    s.server(snac(F, 0x0001, u16(0x0008)))
    for t, v in ((1, b'<b>popup</b>'), (2, b'http://popup.invalid/'), (3, u16(200)),
                 (4, u16(100)), (5, u16(30)), (6, b'unknown')):
        s.server(snac(F, 0x0002, tlv(t, v)))


def bos(s):
    F = 0x0009
    s.server(snac(F, 0x0001, u16(0x0010)))
    s.client(snac(F, 0x0002))
    s.server(snac(F, 0x0003, tlv(1, u16(220)) + tlv(2, u16(220)) + tlv(3, u16(0))))
    s.client(snac(F, 0x0004, u32(0x000fffff)))
    for st in (5, 6, 7, 8):
        s.client(snac(F, st, bname(b'bob') + bname(b'carol')))


def userlookup(s):
    F = 0x000a
    s.server(snac(F, 0x0001, u16(0x0014)))
    s.client(snac(F, 0x0002, b'bob@example.invalid'))
    s.server(snac(F, 0x0003, tlv(0x0001, b'bob') + tlv(0x0001, b'bobby')))


def simple_family(s, F, subtypes):
    s.server(snac(F, 0x0001, u16(0x0001)))
    for st in subtypes:
        s.client(snac(F, st, b'\x00\x01'))


def chat(s):
    F = 0x000e
    s.server(snac(F, 0x0001, u16(0x0011)))
    s.server(snac(F, 0x0002, b'room info'))
    s.server(snac(F, 0x0003, userinfo(b'bob', [tlv(1, u16(0x10))]) + userinfo(b'carol', [])))
    s.server(snac(F, 0x0004, userinfo(b'bob', [])))
    # Outgoing: message after the first <html> tag, up to </html>
    s.client(snac(F, 0x0005, chat_payload(b'alice', b'xx<html><b>Hello</b> \x01room</html>tail', 40)))
    s.client(snac(F, 0x0005, chat_payload(b'alice', b'<HtMl>Mixed case</hTmL>', 40)))
    s.client(snac(F, 0x0005, chat_payload(b'alice', b'no tags at all', 40)))
    # Tag characters out of order, before and inside the message
    jumble = b'>LlMmTtHh/<<HTML>>LlMmTtHh</ <HTML</HTML>'
    s.client(snac(F, 0x0005, chat_payload(b'alice', jumble, 40)))
    s.server(snac(F, 0x0006, chat_payload(b'bob', jumble.lower(), 36)))
    s.client(snac(F, 0x0005, chat_payload(b'alice', b'<h', 40)))       # too short to search
    s.client(snac(F, 0x0005, bytes(30) + bname(b'alice')))             # no message at all
    # Incoming
    s.server(snac(F, 0x0006, chat_payload(b'bob', b'<HTML>Hi everybody</HTML>', 36)))
    s.server(snac(F, 0x0006, chat_payload(b'bob', b'<html><body>hi</body></html>', 36)))
    s.client(snac(F, 0x0007, u16(0) + bname(b'bob')))
    s.server(snac(F, 0x0008, u16(100) + u16(200)))
    # Outgoing and incoming chat
    # messages longer than 999 octets, which printed an uninitialised buffer
    data = bytearray(b'A' * 1100)
    data[30] = 0
    s.client(snac(F, 0x0005, bytes(data)))
    s.server(snac(F, 0x0006, bytes(data)))


def directory(s):
    F = 0x000f
    s.server(snac(F, 0x0001, u16(0x0014)))
    s.client(snac(F, 0x0002, tlv(0x001c, b'us-ascii') + tlv(0x000a, b'1')))
    s.server(snac(F, 0x0003, tlv(0x0001, b'bob') + tlv(0x0011, b'bob@example.invalid')))
    s.client(snac(F, 0x0004))
    s.server(snac(F, 0x0005, b'\x00\x01'))


def sst(s):
    F = 0x0010
    md5 = bytes(range(16))
    s.server(snac(F, 0x0001, u16(0x0001)))
    s.client(snac(F, 0x0002, u16(1) + u16(4) + b'ICON'))
    s.client(snac(F, 0x0002, u16(1) + u16(0)))
    s.server(snac(F, 0x0003, b'\x00\x00\x01\x01' + u8(16) + md5))
    s.client(snac(F, 0x0004, bname(b'bob') + b'\x01\x00\x01\x01' + u8(16) + md5))
    s.server(snac(F, 0x0005, bname(b'bob') + b'\x00\x01\x01' + u8(16) + md5 + u16(4) + b'ICON'))
    s.server(snac(F, 0x0005, bname(b'bob') + b'\x00\x01\x01' + u8(16) + md5 + u16(0)))


def ssi_item(name, gid, bid, typ, tlvs):
    t = b''.join(tlvs)
    return u16(len(name)) + name + u16(gid) + u16(bid) + u16(typ) + u16(len(t)) + t


def ssi(s):
    F = 0x0013
    items = [
        ssi_item(b'', 0, 0, 1, [tlv(0x00c8, u16(1))]),                  # master group
        ssi_item(b'Buddies', 1, 0, 1, [tlv(0x00c8, u16(2) + u16(3))]),
        ssi_item(b'bob', 1, 2, 0, [tlv(0x0131, b'Bobby'), tlv(0x0066, b'')]),
        ssi_item(b'carol', 1, 3, 0, []),
        ssi_item(b'', 0, 4, 4, [tlv(0x00ca, u8(4)), tlv(0x00cb, u16(0xffff)),
                                tlv(0x00cc, u32(0xffffffff))]),
        ssi_item(b'1', 0, 5, 0x14, [tlv(0x00d5, bytes(18))]),
        ssi_item(b'dave', 0, 6, 2, []), ssi_item(b'eve', 0, 7, 3, []),
        ssi_item(b'', 0, 8, 5, [tlv(0x00c9, u32(0x00007fff))]),
        ssi_item(b'x', 0, 9, 0x99, []),
    ]
    s.server(snac(F, 0x0001, u16(0x000a)))
    s.client(snac(F, 0x0002))
    s.server(snac(F, 0x0003, tlv(0x0004, u16(400) * 8) + tlv(0x0002, u16(0))))
    s.client(snac(F, 0x0004))
    s.client(snac(F, 0x0005, u32(1100000000) + u16(10)))
    s.server(snac(F, 0x0006, u8(0) + u16(len(items)) + b''.join(items) + u32(1100000000)))
    s.client(snac(F, 0x0007))
    s.client(snac(F, 0x0008, items[3]))
    s.client(snac(F, 0x0009, items[1] + items[2]))
    s.client(snac(F, 0x000a, items[3]))
    for code in (0, 1, 2, 3, 5, 10, 11, 12, 13, 14, 16, 17, 20, 26, 99):
        s.server(snac(F, 0x000e, u16(code)))
    s.server(snac(F, 0x000f, u32(1100000000) + u16(0)))
    s.client(snac(F, 0x0011))
    s.client(snac(F, 0x0012))
    s.client(snac(F, 0x0014, bname(b'bob') + u16(6) + b'please' + u16(0)))
    s.server(snac(F, 0x0015, bname(b'bob') + u16(0) + u16(0)))
    s.client(snac(F, 0x0018, bname(b'bob') + u16(6) + b'add me' + u16(0)))
    s.server(snac(F, 0x0019, u8(0) + u16(0) + u16(0)))
    s.client(snac(F, 0x001a, bname(b'bob') + u8(1) + u16(2) + b'ok'))
    s.server(snac(F, 0x001b, u8(0) + u8(0) + u16(0)))
    s.server(snac(F, 0x001c, bname(b'bob')))


def icq(s):
    F = 0x0015
    s.server(snac(F, 0x0001, u16(0x0002)))
    s.client(snac(F, 0x0002, icq_meta(0x003c)))
    s.client(snac(F, 0x0002, icq_meta(0x003e)))
    s.server(snac(F, 0x0003, icq_meta(0x0041, b'offline message')))
    s.server(snac(F, 0x0003, icq_meta(0x0042, u8(0))))
    s.client(snac(F, 0x0002, icq_meta(0x07d0, le16(0x04b2) + le32(987654321))))
    s.server(snac(F, 0x0003, icq_meta(0x07da, le16(0x00c8) + u8(0x0a))))
    s.server(snac(F, 0x0003, icq_meta(0x07da, le16(0x7777))))         # unknown meta call
    s.client(snac(F, 0x0002, icq_meta(0x1234, b'?')))                  # unknown request type
    s.client(snac(F, 0x0006, b'\x00\x01'))
    s.server(snac(F, 0x0007, b'\x00\x01'))


def signon(s):
    F = 0x0017
    s.server(snac(F, 0x0001, u16(0x0001)))
    s.client(snac(F, 0x0002, b''.join(CLIENT_ALL)))
    s.server(snac(F, 0x0003, tlv(0x0001, b'alice') + tlv(0x0005, b'bos.example.invalid:5190') +
                  tlv(0x0006, bytes(range(32))) + tlv(0x0011, b'alice@example.invalid') +
                  tlv(0x0054, b'http://pw.example.invalid/')))
    s.client(snac(F, 0x0004, tlv(0x0001, b'\x00' * 8)))
    s.server(snac(F, 0x0005, tlv(0x0001, b'\x00' * 8)))
    s.client(snac(F, 0x0006, u16(1) + u8(0) + bname(b'alice')))
    s.server(snac(F, 0x0007, u16(10) + b'1234567890'))
    s.server(snac(F, 0x000a))
    s.client(snac(F, 0x000b, b'\x00\x06123456'))


def email(s):
    F = 0x0018
    s.client(snac(F, 0x0006, b'\x00\x01'))
    s.server(snac(F, 0x0007, b'\x00\x01'))
    s.client(snac(F, 0x0016, b'\x00\x01'))
    s.client(snac(F, 0x0099, b'\x00\x01'))                             # unknown subtype


def coverage_packets(cap):
    s = TcpStream(cap)
    # Channel 1: sign-on with the protocol version and client TLVs, and empty
    s.client(flap(1, u32(1) + b''.join(CLIENT_ALL[:5])))
    s.server(flap(1, u32(1)))
    s.client(flap(1))
    generic(s)
    location(s)
    buddylist(s)
    messaging(s)
    adverts(s)
    invitation(s)
    admin(s)
    popup(s)
    bos(s)
    userlookup(s)
    simple_family(s, 0x000b, (2, 3, 4))                                 # stats
    simple_family(s, 0x000c, (2, 3))                                    # translate
    simple_family(s, 0x000d, range(2, 10))                              # chat nav
    chat(s)
    directory(s)
    sst(s)
    ssi(s)
    icq(s)
    signon(s)
    email(s)
    s.client(snac(0x0099, 0x0001, b'unknown family'))
    s.client(snac(0xfffe, 0x0001, b'OFT'))
    # Channels 3, 4, 5 and an unknown channel, with and without data
    s.server(flap(3, b'flap error'))
    s.server(flap(3))
    s.client(flap(5, b'\x00'))
    s.client(flap(5))
    s.server(flap(9, b'channel 9'))
    s.server(flap(9))
    # Desegmentation: two FLAPs in one segment, one FLAP over three segments,
    # and the end of one FLAP with the start of the next
    s.client(flap(5) + snac(0x0001, 0x0011, u16(1)))
    m = snac(0x0003, 0x000b, userinfo(b'bob', ONLINEBUDDY_ALL))
    s.server(m[:3])
    s.server(m[3:100])
    s.server(m[100:])
    m1 = snac(0x0004, 0x0014, b'12345678' + u16(1) + bname(b'bob') + u16(2))
    m2 = flap(5)
    s.client(m1[:10])
    s.client(m1[10:] + m2[:2])
    s.client(m2[2:])
    s.client(flap(4, tlv(0x0001, b'alice') + tlv(0x0009, u16(1)) +
                  tlv(0x000b, b'http://www.example.invalid/')))
    s.server(flap(4))
    # A segment that does not start with a FLAP: left to TCP
    t = TcpStream(cap, cport=CLIENT_PORT + 1)
    t.client(b'Z*not a FLAP')
    tls_packets(cap)


# ---------------------------------------------------------------------------
# AIM over TLS. TLS 1.2 with TLS_RSA_WITH_NULL_SHA: Wireshark shows the
# application data of a NULL cipher session without keys (the MAC is not
# checked), so the "aim_tls" heuristic can be reached. TLS_PORT has no
# dissector; dissect with -d tcp.port==4443,tls --enable-heuristic aim_tls.

TLS_PORT = 4443


def tls_record(ctype, body):
    return u8(ctype) + u16(0x0303) + u16(len(body)) + body


def tls_handshake(htype, body):
    return u8(htype) + struct.pack('>I', len(body))[1:] + body


def tls_session(cap, cport, app_client, app_server):
    s = TcpStream(cap, cport=cport, sport=TLS_PORT)
    mac = bytes(20)                                    # not checked without keys
    hello = u16(0x0303) + bytes(range(32)) + u8(0) + u16(2) + u16(0x0002) + u8(1) + u8(0)
    s.client(tls_record(22, tls_handshake(1, hello)))
    shello = u16(0x0303) + bytes(range(32, 64)) + u8(0) + u16(0x0002) + u8(0)
    s.server(tls_record(22, tls_handshake(2, shello) + tls_handshake(14, b'')))
    s.client(tls_record(22, tls_handshake(16, u16(64) + bytes(64))) + tls_record(20, b'\x01') +
             tls_record(22, tls_handshake(20, bytes(12)) + mac))
    s.server(tls_record(20, b'\x01') + tls_record(22, tls_handshake(20, bytes(12)) + mac))
    for data in app_client:
        s.client(tls_record(23, data + mac))
    for data in app_server:
        s.server(tls_record(23, data + mac))


def tls_packets(cap):
    # Not AIM: the heuristic declines it
    tls_session(cap, CLIENT_PORT + 10, [b'hello, not a FLAP'], [])
    # AIM: the heuristic takes the session
    tls_session(cap, CLIENT_PORT + 11, [flap(1, u32(1) + tlv(0x0001, b'alice'))],
                [snac(0x0001, 0x0003, u16(1) + u16(2))])


# ---------------------------------------------------------------------------
# Paths that end in an exception

def malformed_packets(cap):
    s = TcpStream(cap, cport=CLIENT_PORT + 2)
    # A TLV that claims more data than there is
    s.client(snac(0x0017, 0x0002, u16(0x0001) + u16(0x00ff) + b'alice'))
    # dissect_aim_tlv_value_extended_data(): second length 0, so the unknown
    # data is added with length -2 (the lengths are not checked)
    s.server(snac(0x0004, 0x000b, b'12345678' + u16(1) + bname(b'bob') + u16(3) +
                  le16(27) + u16(9) + PLUGIN_NONE + bytes(9) + le16(0) + le16(0) +
                  u8(1) + u8(0) + u16(0) + u16(0) + u16(2) + b'hi'))
    # Chat outgoing message shorter than the fixed 30 octet header
    s.client(snac(0x000e, 0x0005, b'short'))
    # A FLAP-level close with a truncated TLV
    s.client(flap(4, b'\x00\x01\x00'))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    cap = Pcap()
    coverage_packets(cap)
    cap.write(os.path.join(out, 'aim-coverage.pcap'))
    bad = Pcap()
    malformed_packets(bad)
    bad.write(os.path.join(out, 'aim-coverage-malformed.pcap'))


if __name__ == '__main__':
    main()
