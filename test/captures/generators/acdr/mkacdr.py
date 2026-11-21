#!/usr/bin/env python3
# Generates test/captures/acdr_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the ACDR (AudioCodes Debug Recording) coverage captures.
Usage: mkacdr.py <outdir>
Writes acdr-coverage.pcapng (valid traffic, UDP port 925 and Exported PDU)
and acdr-coverage-malformed.pcapng (input that only raises exceptions).
Everything is built with struct; nothing comes from a real network."""
import struct
import sys

# ---------------------------------------------------------------- link layers
def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip_udp(payload, sport=5004, dport=6000, src=(10, 0, 0, 1), dst=(10, 0, 0, 2)):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes(src), bytes(dst))
    return ip[:10] + struct.pack('!H', csum(ip)) + ip[12:] + udp

def udp_frame(payload, sport=40000, dport=925):
    eth = bytes.fromhex('020000000002' '020000000001') + b'\x08\x00'
    src, dst = (192, 0, 2, 1), (192, 0, 2, 2)
    return eth + ip_udp(payload, sport, dport, src, dst)

def exported_pdu(name, payload):
    n = name.encode() + b'\0'
    n += b'\0' * (-len(n) % 4)
    return struct.pack('!HH', 12, len(n)) + n + struct.pack('!HH', 0, 0) + payload

# ------------------------------------------------------------- ACDR payloads
def rtp(pt=8, seq=1, ts=160, ssrc=0x11223344, pl=bytes(range(16)), b0=0x80):
    return struct.pack('!BBHII', b0, pt, seq, ts, ssrc) + pl

def stun():
    return struct.pack('!HHI', 1, 0, 0x2112a442) + bytes(range(12))

def rtcp_sr():
    return struct.pack('!BBHIQIII', 0x80, 200, 6, 0x11223344, 0xe1000000_00000000,
                       160, 5, 800)

SIP = (b'OPTIONS sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060\r\n'
       b'From: <sip:alice@example.com>;tag=1\r\nTo: <sip:bob@example.com>\r\n'
       b'Call-ID: a1@192.0.2.1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n')
MEGACO = b'MEGACO/1 [192.0.2.1]:2944 T=1{C=-{SC=ROOT{SV{MT=RS,RE=901}}}}'
MGCP = b'AUEP 1 ds/ds1-1/1@gw.example.com MGCP 1.0\r\n'
SYSLOG = b'<34>Oct 11 22:14:15 gw app: debug recording started'
JSON = b'{"session":"s1","text":"hello","score":1}'
XML = b'<?xml version="1.0"?><cdr id="1"><call>7</call></cdr>'
HTTP = b'GET /index.html HTTP/1.1\r\nHost: a.example.com\r\n\r\n'
LDAP = bytes.fromhex('300c02010160070201030400' '8000')
FTP = b'220 ready\r\n'
TELNET = b'login: '
ETH = bytes.fromhex('020000000002' '020000000001' '88b5') + bytes(range(20))
UDPTL = bytes.fromhex('000101000000')

# ----------------------------------------------------------- ACDR header
def session(ver, board=0x000a1b, reset=3, num=0x0100):
    if ver in (5, 6):
        return struct.pack('!I', num)
    if ver == 7:
        return struct.pack('!I', (board << 8) | reset) + struct.pack('!I', num)
    return struct.pack('!I', (board << 8) | reset) + struct.pack('!Q', num)[3:]

def zero_session(ver):
    return bytes(4 if ver in (5, 6) else 8 if ver == 7 else 9)

def acdr(ver, media, tp=0, extra=0, ext=b'', pl=b'', ts=1000000, seq=1,
         src=1, dst=2, sess=None, mii=b'', plen=None, major=0):
    """One ACDR packet. ver is the minor version; plen overrides the payload
    offset / header extension length byte."""
    b = bytes([(major << 4) | ver])
    if ver <= 3:
        b += struct.pack('!Q', ts)[2:]
    else:
        b += struct.pack('!I', ts)
    if ver >= 4:
        b += struct.pack('!H', seq)
    if ver >= 9:
        b += struct.pack('!II', src & 0xffffffff, dst & 0xffffffff)
    else:
        b += struct.pack('!HH', src & 0xffff, dst & 0xffff)
    if ver < 5:
        b += bytes([extra, tp, media, 15 if plen is None else plen])
        return b + pl
    b += bytes([extra, tp, media, len(ext) if plen is None else plen])
    b += session(ver) if sess is None else sess
    return b + ext + mii + pl

# frame collection -----------------------------------------------------------
main_frames = []
groups = []

def grp(name):
    groups.append((len(main_frames) + 1, name))

def add(pl, **k):
    # one UDP flow per frame: a T.38 payload makes the T.38 dissector take
    # over the conversation
    k.setdefault('sport', 40000 if len(main_frames) < 4 else 40000 + len(main_frames))
    main_frames.append(('acdr', udp_frame(pl, **k)))

mal_frames = []
def madd(pl):
    # a T.38 payload makes the T.38 dissector take over the conversation
    # of the UDP flow, so each such frame gets its own flow
    mal_frames.append(('acdr', udp_frame(pl, sport=40000 + len(mal_frames))))

def add_epdu(name, pl):
    main_frames.append(('epdu', exported_pdu(name, pl)))

MII_HDR = struct.pack('!HH', 0x0102, 0x0040)

def ext4(ip=(10, 0, 0, 1), sp=5004, dp=6000, tos=0xb8, flags=None):
    e = bytes(ip) + struct.pack('!HHB', sp, dp, tos)
    return e if flags is None else e + bytes([flags])

def ext6(sp=5004, dp=6000, tos=0xb8):
    return bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [1]) + struct.pack('!HHB', sp, dp, tos)

# ============================================================ the reproducer
grp('reproducer of the fix (frames 1-4)')
r_rtp = struct.pack('!BBHII', 0x80, 96, 1, 160, 0x11223344) + bytes(range(16))
def acdr_v5(media, rtp_):
    hdr = struct.pack('!BIHHHBBBB', 0x05, 1000, 1, 1, 2, 0, 0, media, 9)
    hdr += struct.pack('!I', 7)
    return hdr + bytes([10, 0, 0, 1]) + struct.pack('!HHB', 5004, 6000, 0) + rtp_
add(acdr_v5(1, r_rtp))
add(acdr_v5(51, struct.pack('!BBHII', 0x80, 96, 1, 160, 0x11223344) + bytes([0xf0, 0x3c]) + bytes(31)))
add(acdr_v5(1, r_rtp))
add(bytes([0x03]) + bytes.fromhex('000100000000') +
    struct.pack('!HHBBBB', 1, 2, 0, 0, 7, 0) + b'hello')

# ================================================= versions and fixed header
grp('versions 0-9: timestamps, sequence numbers, source/dest ID, session IDs')
add(acdr(0, 7, ts=0x000100000000 - 1, pl=b'v0'))
add(acdr(1, 7, ts=123456789012, pl=b'v1'))
add(acdr(2, 7, ts=0xffffffffffff, src=0xffff, dst=0xffff, pl=b'v2'))
add(acdr(3, 7, ts=0x000100000000, pl=b'v3'))
add(acdr(4, 7, ts=0xffffffff, seq=0xffff, pl=b'v4'))
add(acdr(5, 7, ts=1, seq=2, pl=b'v5'))
add(acdr(6, 7, ts=2, seq=3, src=0xffff, dst=7, pl=b'v6'))
add(acdr(7, 7, ts=3, seq=4, pl=b'v7 session'))
add(acdr(7, 7, sess=zero_session(7), pl=b'v7 no session'))
add(acdr(7, 7, sess=session(7, num=0), pl=b'v7 no session number'))
add(acdr(8, 7, ts=4, pl=b'v8 session'))
add(acdr(8, 7, sess=zero_session(8), pl=b'v8 no session'))
add(acdr(8, 7, sess=session(8, num=0), pl=b'v8 no session number'))
add(acdr(9, 7, src=0x12345678, dst=0xffffffff, pl=b'v9 32 bit IDs'))
add(acdr(9, 7, src=5, dst=6, sess=zero_session(9), pl=b'v9 no session'))
add(acdr(9, 7, ts=0xffffffff, sess=session(9, board=0xffffff, reset=255,
                                            num=0xffffffffff), pl=b'v9 max'))
add(acdr(5, 7, sess=zero_session(5), pl=b'v5 session 0'))
add(acdr(6, 7, sess=zero_session(6), pl=b'v6 session 0'))

grp('unsupported versions (expert info)')
add(bytes([0x0a]) + bytes(40))
add(bytes([0x10]) + bytes(40))
add(bytes([0x1f]) + bytes(40))

# ================================================================ extra data
grp('extra data byte')
add(acdr(3, 7, extra=0, pl=b'x'))
add(acdr(3, 7, extra=0xaa, pl=b'x'))        # old versions: plain data byte
add(acdr(4, 7, extra=0xaa, pl=b'x'))        # v4: bit mask
for bit in (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x7f):
    add(acdr(5, 7, extra=bit, pl=ip_udp(b'x') if bit & 8 else b'x'))
add(acdr(2, 7, extra=0x01, pl=b'x'))        # medium bit ignored before v3
add(acdr(3, 7, extra=0x01, mii=b'', pl=b'x'))
add(acdr(3, 7, extra=0x02, pl=b'x'))        # IPv6 flag, but nothing to show

# =========================================================== header extensions
grp('header extension: DSP incoming/outgoing trace points, signaling')
ana = struct.pack('!HBBHHII', 0x0102, 0x81, 0x07, 0x0010, 0, 0x01020304, 0)
assert len(ana) == 16, len(ana)
hpi = bytes([0xf5, 0x03, 0x01, 0x02])
for tp, pl in ((33, struct.pack('!HH', 0x0101, 12) + b'sig-in'),
               (34, struct.pack('!HI', 0x0102, 34567) + b'sig-out'),
               (33, struct.pack('!HH', 0x0101, 12)),
               (34, struct.pack('!HI', 0x0102, 34567))):
    add(acdr(5, 37, tp=tp, ext=bytes([2, 9]), pl=ana + hpi + pl))
add(acdr(7, 37, tp=33, ext=bytes([1, 4]), pl=ana + hpi + struct.pack('!HH', 5, 2) + b'ab'))
add(acdr(5, 32, tp=33, ext=bytes([0, 1]), pl=ana + hpi + b'dsp payload'))
add(acdr(5, 37, tp=34, ext=b'', pl=ana + hpi + struct.pack('!HI', 1, 1)))

grp('header extension: CAS, net bricks, events, DSP media types')
add(acdr(5, 24, tp=25, ext=struct.pack('!I', 77), pl=b'cas'))
add(acdr(5, 25, tp=26, ext=struct.pack('!I', 78), pl=b'net bricks'))
add(acdr(5, 4, tp=5, ext=bytes([7, 2]), pl=b'event data'))
for media in (0, 18, 19, 32, 35, 50):
    add(acdr(5, media, tp=2, ext=bytes([3, 5]), pl=ETH if media == 50 else b'dsp data'))

grp('header extension: RTP media types, Network -> DSP trace points')
for tp in (0, 4, 18, 20, 27, 35):
    add(acdr(5, 1, tp=tp, ext=ext4(), pl=rtp()))
add(acdr(5, 1, tp=0, ext=ext4(flags=0x10), pl=rtp()))   # C5 control flags: favorite
add(acdr(5, 1, tp=0, ext=ext4(flags=0), pl=rtp()))
add(acdr(5, 1, tp=0, extra=0x02, ext=ext6(), pl=rtp()))  # IPv6 on version 5
add(acdr(7, 1, tp=4, extra=0x02, ext=ext6(), pl=rtp()))
add(acdr(3, 1, tp=0, extra=0x02, pl=rtp()))              # version 3: no extension
add(acdr(5, 1, tp=0, ext=ext4() + bytes(7), pl=rtp()))   # extension longer than fields
grp('header extension: RTP media types, DSP -> Network trace points')
for tp in (1, 5, 17, 22, 21, 19, 23, 24, 28):
    add(acdr(5, 1, tp=tp, ext=ext4(), pl=rtp()))
add(acdr(6, 1, tp=1, extra=0x02, ext=ext6(), pl=rtp()))
add(acdr(9, 1, tp=5, extra=0x02, ext=ext6(), pl=rtp()))
grp('header extension: other trace points of RTP media types, System trace point')
for tp in (2, 3, 6, 8, 16):
    add(acdr(5, 1, tp=tp, ext=b'\x01\x02\x03\x04\x05', pl=rtp()))
for media, pl in ((6, JSON), (10, SIP), (11, MEGACO), (12, MGCP), (13, bytes(8)),
                  (14, ETH)):
    add(acdr(5, media, tp=6, ext=bytes([10, 0, 0, 1, 10, 0, 0, 2]) +
             struct.pack('!HHBB', 5060, 5061, 17, 1), pl=pl))
add(acdr(5, 10, tp=6, ext=bytes([10, 0, 0, 1, 10, 0, 0, 2]) +
         struct.pack('!HHBB', 5060, 5061, 6, 0), pl=SIP))
add(acdr(5, 10, tp=5, ext=b'\xde\xad\xbe\xef', pl=SIP))      # payload header

grp('header extension: TLS and T38')
for app in range(10):
    add(acdr(5, 33, tp=4, ext=struct.pack('!HH', 5061, 40000) + bytes([10, 0, 0, 1, 10, 0, 0, 2]) +
             bytes([app]), pl=b''.join([bytes(0)]) + {
        0: b'\x16\x03\x03\x00\x01\x00', 1: HTTP, 2: HTTP, 3: SIP, 4: LDAP, 5: XML,
        6: b'raw tcp data', 7: TELNET, 8: FTP, 9: bytes.fromhex('0000000100000001')}[app]))
for sp, dp, pl in ((443, 40000, HTTP), (40000, 636, LDAP), (40000, 5061, SIP),
                   (40000, 41000, b'unknown tls port')):
    add(acdr(5, 34, tp=4, ext=struct.pack('!HH', sp, dp) + bytes([10, 0, 0, 1, 10, 0, 0, 2]) +
             bytes([6]), pl=pl))
add(acdr(5, 33, tp=4, ext=struct.pack('!HH', 443, 40000) + bytes([10, 0, 0, 1, 10, 0, 0, 2]) +
         bytes([2]), pl=HTTP))
# T38: UDP header in the last 8 bytes of a 12 byte extension (header added)
t38_udp = struct.pack('!HHHH', 6000, 6002, 8 + len(UDPTL), 0)
add(acdr(5, 3, tp=0, extra=0x08, ext=bytes([10, 0, 0, 1]) + t38_udp,
         pl=UDPTL))
add(acdr(5, 3, tp=1, extra=0x08, ext=bytes([10, 0, 0, 1]) + t38_udp,
         pl=UDPTL))
add(acdr(5, 3, tp=0, extra=0x08, ext=ext4(), pl=t38_udp + UDPTL))   # not 12
# T38 payloads without header (T.38 dissector, pass dependent state)
madd(acdr(5, 3, tp=0, ext=bytes([10, 0, 0, 1]), pl=UDPTL))     # extension of 4
madd(acdr(5, 3, tp=1, ext=bytes([10, 0, 0, 1]), pl=UDPTL))
madd(acdr(5, 3, tp=0, ext=ext4(), pl=UDPTL))
madd(acdr(5, 3, tp=1, ext=ext4(), pl=UDPTL))
madd(acdr(5, 3, tp=4, pl=UDPTL))
madd(acdr(5, 3, tp=0, ext=ext4(flags=0), pl=UDPTL))
madd(acdr(5, 3, tp=0, ext=ext4() + bytes([0]), pl=UDPTL))     # extension of 10

grp('header extension: other media types, MII header')
for media in (31, 38, 49, 7, 61):
    add(acdr(5, media, tp=2, ext=b'\xaa\xbb\xcc', pl=b'ext payload'))
add(acdr(5, 35, tp=0, extra=0x01, ext=bytes([1, 2]), mii=MII_HDR, pl=b'mii data'))
add(acdr(5, 35, tp=2, extra=0x00, ext=bytes([1, 2]), pl=b'ac5x data'))
for media in (47, 48):
    add(acdr(6, media, tp=3, extra=0x01, mii=MII_HDR, pl=b'playback'))
for media in (1, 2, 27, 28, 36, 55, 57, 58, 59, 60):
    add(acdr(5, media, tp=0, extra=0x01, ext=ext4(),
             mii=MII_HDR, pl=rtp(pl=bytes(4)) if False else b'mii body'))

# =================================================================== payloads
grp('payloads: RTP media types without header added')
add(acdr(5, 1, tp=0, ext=ext4(), pl=rtp(pt=0)))
add(acdr(5, 1, tp=0, ext=ext4(), pl=rtp(pt=96)))
add(acdr(5, 1, tp=0, ext=ext4(), pl=stun()))
add(acdr(5, 1, tp=0, ext=ext4(), pl=bytes([0x00]) + bytes(19)))   # version 0, no cookie
add(acdr(5, 1, tp=0, ext=ext4(), pl=rtp(pt=8, b0=0x90, pl=bytes(30))))
add(acdr(5, 1, tp=0, ext=ext4(), pl=rtp(pt=8, b0=0x80)))
add(acdr(5, 15, tp=0, ext=ext4(), pl=rtp(pt=0, pl=bytes(160))))
add(acdr(5, 36, tp=0, ext=ext4(), pl=rtp()))
add(acdr(5, 27, tp=0, ext=ext4(), pl=rtp(pt=97)))
add(acdr(5, 55, tp=0, ext=ext4(), pl=rtp(pt=98, pl=UDPTL)))
for media in (57, 58, 59, 60):
    add(acdr(5, media, tp=0, ext=ext4(), pl=rtp(pt=100 + media - 57)))
amr = bytes([0xf0, 0x3c]) + bytes(31)
grp('payloads: codec media types (AMR, EVRC, RFC 2198, RFC 2833, FEC)')
add(acdr(5, 51, tp=0, ext=ext4(), pl=rtp(pt=96, pl=amr)))
add(acdr(5, 51, tp=0, ext=ext4(), pl=rtp(pt=0, pl=amr)))
add(acdr(5, 51, tp=1, ext=ext4(), pl=rtp(pt=97, pl=amr)))
add(acdr(5, 52, tp=0, ext=ext4(), pl=rtp(pt=98, pl=bytes([0x03]) + bytes(22))))
red = bytes([0x80 | 8, 0x00, 0xa0, 0x00]) + bytes([8]) + bytes(8) + bytes(8)
add(acdr(5, 53, tp=0, ext=ext4(), pl=rtp(pt=99, pl=red)))
add(acdr(5, 56, tp=0, ext=ext4(), pl=rtp(pt=100, pl=red)))
add(acdr(5, 54, tp=0, ext=ext4(), pl=rtp(pt=101, pl=bytes([5, 0x8a, 0x00, 0xa0]))))
add(acdr(5, 54, tp=0, ext=ext4(), pl=rtp(pt=101, pl=bytes([1, 0x0a, 0x00, 0xa0]))))
add(acdr(5, 53, tp=0, ext=ext4(), pl=rtp(pt=0, pl=red)))
add(acdr(5, 51, tp=0, ext=ext4(), pl=stun()))
add(acdr(5, 51, tp=0, pl=rtp(pt=96, pl=amr)))       # no extension: no payload type
add(acdr(5, 1, tp=0, ext=ext4(), pl=rtp(pt=96)))     # PT 96 again, plain RTP
add(acdr(5, 51, tp=0, ext=ext4(), pl=rtp(pt=96, pl=amr)))
add(acdr(5, 1, tp=0, ext=ext4(), pl=rtp(pt=96)))

grp('payloads: RTCP, video, fragments, V.150.1, data relay')
add(acdr(5, 2, tp=0, ext=ext4(), pl=rtcp_sr()))
add(acdr(5, 2, tp=0, ext=ext4(), pl=stun()))
add(acdr(5, 28, tp=0, ext=ext4(), pl=rtcp_sr()))
add(acdr(5, 28, tp=0, ext=ext4(), pl=stun()))
add(acdr(5, 27, tp=1, ext=ext4(), pl=rtp(pt=96, pl=bytes(40))))
add(acdr(5, 31, tp=0, pl=b'v150 data'))
add(acdr(5, 38, tp=0, pl=b'fragment'))
add(acdr(5, 49, tp=0, pl=b'relay data'))
for media in (62, 63, 64):
    add(acdr(5, media, tp=0, pl=b'SSH-2.0-OpenSSH_9.0\r\n'))

grp('payloads: DSP packets (no AC49x/48x/45x/5x dissector in this tree)')
for media in (0, 18, 19, 32):
    for tp in (2, 3):
        add(acdr(5, media, tp=tp, ext=bytes([1, 1]), pl=bytes(range(24))))
add(acdr(5, 35, tp=2, extra=0x01, ext=bytes([1, 1]), mii=MII_HDR, pl=bytes(range(24))))
add(acdr(5, 35, tp=3, pl=bytes(range(24))))
add(acdr(5, 35, tp=34, pl=bytes(range(24))))
for media in (47, 48):
    add(acdr(5, media, tp=2, pl=bytes(range(24))))
add(acdr(5, 50, tp=0, ext=bytes([0, 0]), pl=ETH))

grp('payloads: signaling')
for tp in (25, 26, 0):
    add(acdr(5, 37, tp=tp, ext=b'', pl=(struct.pack('!HH', 0x42, 8) if tp in (25, 33)
                                       else struct.pack('!HI', 0x43, 4294967295)) + b'sig'))
add(acdr(5, 37, tp=25, pl=struct.pack('!HH', 0x42, 0)))
add(acdr(5, 37, tp=26, pl=struct.pack('!HI', 0x43, 1000000)))
add(acdr(5, 37, tp=26, pl=struct.pack('!HI', 0x43, 4294967295)))

grp('payloads: SIP, MEGACO, MGCP, JSON, XML, syslog, events, control')
add(acdr(5, 10, tp=4, pl=SIP))
add(acdr(5, 11, tp=4, pl=MEGACO))
add(acdr(5, 12, tp=4, pl=MGCP))
add(acdr(5, 6, tp=4, pl=JSON))
for media in (42, 43, 44):
    add(acdr(5, media, tp=4, pl=XML))
add(acdr(5, 5, tp=4, pl=SYSLOG))
add(acdr(5, 14, tp=4, pl=ETH))
add(acdr(5, 14, tp=4, extra=0x08, pl=ETH))

grp('payloads: header added (IP packet follows)')
ipu = ip_udp(SIP, 5060, 5060)
for media in (10, 11, 12, 1, 2, 27, 28, 31, 5, 33, 7, 4, 13, 38):
    add(acdr(5, media, tp=4, extra=0x08, pl=ipu))
add(acdr(5, 6, tp=4, extra=0x08, pl=ip_udp(JSON, 5000, 8080)))      # VoiceAI
def udp_only(pl, sp=5000, dp=5001):
    return struct.pack('!HHHH', sp, dp, 8 + len(pl), 0) + pl
add(acdr(5, 61, tp=4, extra=0x08, pl=udp_only(bytes([0x16, 0xfe, 0xfd]) + bytes(20))))
add(acdr(5, 3, tp=4, extra=0x08, pl=udp_only(UDPTL, 6010, 6012)))
add(acdr(5, 61, tp=4, pl=bytes([0x16, 0xfe, 0xfd]) + bytes(20)))   # DTLS, no header
add(acdr(5, 1, tp=4, extra=0x48, pl=ipu))                            # LI, header added
add(acdr(5, 1, tp=4, extra=0x40, ext=ext4(), pl=rtp()))              # LI, no header
add(acdr(5, 1, tp=0, extra=0xaa, ext=ext6(), pl=rtp()))               # 0xAA: not header added
add(acdr(3, 1, tp=0, extra=0xaa, pl=rtp()))

grp('payloads: media types nothing handles (Unknown packet Type)')
for media in (8, 9, 16, 17, 20, 21, 22, 23, 24, 25, 30, 39, 40, 41, 45, 46, 65, 200):
    add(acdr(5, media, tp=4, pl=b'unhandled'))

grp('payloads: TPNCP and commands')
for media in (13, 26, 29):
    for tp in (4, 5):
        add(acdr(5, media, tp=tp, pl=bytes.fromhex('0000000100000002')))
add(acdr(1, 4, tp=5, pl=bytes.fromhex('0000000100000002')))
add(acdr(5, 4, tp=5, pl=bytes.fromhex('0000000100000002')))

grp('codec media types with an MII header (payload type read after the extension)')
r_ = rtp(pt=96, pl=amr)
add(acdr(5, 51, tp=0, extra=0x01, ext=ext4(), mii=r_[:4], pl=r_[4:]))
add(acdr(5, 51, tp=0, extra=0x01, ext=ext4(), mii=rtp(pt=0, pl=amr)[:4], pl=rtp(pt=0, pl=amr)[4:]))
r_ = rtp(pt=98, pl=bytes([0x03]) + bytes(22))
add(acdr(5, 52, tp=0, extra=0x01, ext=ext4(), mii=r_[:4], pl=r_[4:]))

grp('Exported PDU: acdr, acdr.rtp, acdr.mii, acdr.xml without ACDR data')
add_epdu('acdr', acdr(5, 1, tp=0, ext=ext4(), pl=rtp()))
add_epdu('acdr.rtp', rtp())
add_epdu('acdr.mii', bytes(range(16)))
add_epdu('acdr.xml', XML)
add_epdu('acdr.rtp', rtp(pt=96))

# ============================================================== malformed set

madd(acdr(5, 7, pl=b'')[:10])                              # shorter than the header
madd(acdr(3, 7, pl=b'')[:5])                               # timestamp cut off
madd(acdr(5, 1, tp=0, ext=ext4(), pl=b'')[:25])            # extension cut off
madd(acdr(5, 1, tp=0, ext=ext4()[:3], pl=rtp()))           # extension shorter than its fields
madd(acdr(5, 1, tp=1, ext=ext4()[:3], pl=rtp()))
madd(acdr(5, 1, tp=0, extra=0x02, ext=ext6()[:10], pl=rtp()))
madd(acdr(5, 33, tp=4, ext=b'\x01\x02\x03', pl=b'x'))      # TLS extension too short
madd(acdr(5, 3, tp=0, ext=bytes([10, 0]), pl=UDPTL))
madd(acdr(5, 6, tp=6, ext=bytes([10, 0, 0, 1]), pl=JSON))
madd(acdr(5, 4, tp=5, ext=bytes([7]), pl=b'event'))
madd(acdr(5, 0, tp=2, ext=bytes([7]), pl=b'dsp'))
madd(acdr(5, 24, tp=25, ext=bytes([7, 7]), pl=b'cas'))
madd(acdr(5, 37, tp=33, ext=bytes([1]), pl=b''))           # DSP incoming, no headers
madd(acdr(5, 37, tp=33, ext=bytes([1, 2]), pl=ana[:10]))
madd(acdr(5, 37, tp=33, ext=bytes([1, 2]), pl=ana + hpi[:2]))
madd(acdr(5, 37, tp=34, ext=bytes([1, 2]), pl=ana + hpi))  # nothing after the headers
madd(acdr(5, 37, tp=33, pl=struct.pack('!HH', 0x42, 8) + b'sig'))
madd(acdr(5, 37, tp=34, pl=struct.pack('!HI', 0x43, 8) + b'sig'))
madd(acdr(5, 37, tp=25, pl=b'\x00'))                       # opcode cut off
madd(acdr(5, 37, tp=26, pl=struct.pack('!HH', 1, 2)))      # timestamp cut off
madd(acdr(5, 37, tp=25, pl=struct.pack('!H', 1)))          # size cut off
madd(acdr(5, 1, tp=0, ext=ext4(), pl=b''))                 # empty RTP
madd(acdr(5, 1, tp=0, ext=ext4(), pl=b'\x80\x60'))         # short RTP
madd(acdr(5, 2, tp=0, ext=ext4(), pl=b''))                 # empty RTCP
madd(acdr(5, 2, tp=0, ext=ext4(), pl=bytes([0x00, 1, 2, 3, 0x21, 0x12])))   # short STUN check
madd(acdr(5, 1, tp=0, ext=ext4(), pl=bytes([0x00, 1, 2, 3, 0x21, 0x12])))
madd(acdr(5, 51, tp=0, ext=ext4(), pl=b''))                # payload type read beyond the end
madd(acdr(5, 51, tp=0, ext=ext4(), pl=b'\x80'))
madd(acdr(5, 51, tp=0, ext=ext4(), pl=rtp(pt=96, pl=b'')))
madd(acdr(5, 54, tp=0, ext=ext4(), pl=rtp(pt=101, pl=b'\x01')))
madd(acdr(5, 53, tp=0, ext=ext4(), pl=rtp(pt=99, pl=b'\xff')))
madd(acdr(5, 56, tp=0, ext=ext4(), pl=rtp(pt=100, pl=b'\x88\x00')))
madd(acdr(5, 7, extra=0x01, mii=MII_HDR[:2]))              # MII header cut off
madd(acdr(5, 1, extra=0x01, ext=ext4(), mii=MII_HDR[:3]))
madd(acdr(5, 10, tp=4, extra=0x08, pl=b'\x45\x00'))        # IP header cut off
madd(acdr(5, 61, tp=4, extra=0x08, pl=ip_udp(b'x')[:24]))
madd(acdr(7, 7, sess=b'\x00\x01\x02')[:20])                # session ID cut off
madd(acdr(9, 7)[:26])
madd(acdr(5, 33, tp=4, ext=struct.pack('!HH', 5061, 40000) + bytes([10, 0, 0, 1, 10, 0, 0, 2]), pl=SIP))
madd(acdr(5, 1, tp=4, plen=200, pl=b'x'))                  # extension length beyond the packet
madd(acdr(5, 51, tp=0, plen=3, pl=b'ab'))
madd(acdr(5, 1, tp=0, ext=ext4(), plen=3, pl=rtp()))       # extension length shorter than the fields

# ============================================================ pcapng writer
def pad4(b):
    return b + b'\0' * (-len(b) % 4)

def block(t, body):
    n = 12 + len(body)
    return struct.pack('<II', t, n) + body + struct.pack('<I', n)

def write_pcapng(path, frames):
    out = block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    out += block(1, struct.pack('<HHI', 1, 0, 65535))      # interface 0: Ethernet
    out += block(1, struct.pack('<HHI', 252, 0, 65535))    # interface 1: Exported PDU
    for i, (kind, data) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += block(6, struct.pack('<IIIII', 0 if kind == 'acdr' else 1, ts >> 32,
                                    ts & 0xffffffff, len(data), len(data)) + pad4(data))
    with open(path, 'wb') as f:
        f.write(out)

if __name__ == '__main__':
    d = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcapng(d + '/acdr-coverage.pcapng', main_frames)
    write_pcapng(d + '/acdr-coverage-malformed.pcapng', mal_frames)
    print('main frames', len(main_frames), 'malformed frames', len(mal_frames))
    for i, (n, name) in enumerate(groups):
        end = groups[i + 1][0] - 1 if i + 1 < len(groups) else len(main_frames)
        print('%d-%d %s' % (n, end, name))
