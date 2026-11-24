#!/usr/bin/python3
# Generates test/captures/messageanalyzer_coverage.cap
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Message Analyzer / ETW WFP / ETW NDIS coverage captures.
Usage: mkmessageanalyzer.py <outdir> [-v]
Writes messageanalyzer-coverage.cap (NetMon 2.3 file) and
messageanalyzer-coverage-malformed.cap.  Everything is synthetic."""
import struct
import sys
import os

P = struct.pack

def netmon_file(frames):
    """frames: list of (network type, data).  NetMon 2.3 file, UTC
    timestamps per frame (FILETIME), no comment/process tables."""
    out = bytearray(128)
    offs = []
    base_ft = 116444736000000000 + 1700000000 * 10000000  # 2023-11-14
    for i, (net, data) in enumerate(frames):
        offs.append(len(out))
        out += P('<QII', i * 1000, len(data), len(data))
        out += data
        out += P('<HIQB', net, 0, base_ft + i * 10000, 0)
    ft_off = len(out)
    for o in offs:
        out += P('<I', o)
    hdr = P('<BBH8H', 3, 2, 1, 2023, 11, 2, 14, 22, 13, 20, 0)
    hdr += P('<10I', ft_off, 4 * len(offs), 0, 0, 0, 0, 0, 0, 0, 0)
    out[0:4] = b'GMBU'
    out[4:4 + len(hdr)] = hdr
    return bytes(out)

def u16s(s, nul=True):
    return s.encode('utf-16-le') + (b'\0\0' if nul else b'')

def guid(d1, d2, d3, d4):
    return P('<IHH', d1, d2, d3) + bytes(d4)

WFP_GUID = guid(0xc22d1b14, 0xc242, 0x49de, [0x9f, 0x17, 0x1d, 0x76, 0xb8, 0xb9, 0xc4, 0x58])
NDIS_GUID = guid(0x2ed6006e, 0x4729, 0x4609, [0xb4, 0x23, 0x3e, 0xe7, 0xbc, 0xd6, 0x78, 0xef])
OTHER_GUID = guid(0x12345678, 0x1234, 0x1234, [1, 2, 3, 4, 5, 6, 7, 8])

def event(prov, eid, user, keyword=0, flags=0, version=0, opcode=0, ext=()):
    """ETW event as stored in a NetMon NETEVENT frame."""
    h = P('<HHHH', 0, 0, flags, 0)         # size, type, flags, property
    h += P('<II', 1234, 4321)              # thread, process
    h += P('<Q', 133000000000000000)       # timestamp
    h += prov
    h += P('<HBBBBHQ', eid, version, 0, 4, opcode, 0, keyword)
    if flags & 0x12:
        h += P('<II', 1, 2)
    else:
        h += P('<Q', 3)
    h += bytes(range(16))                  # activity id
    h += P('<BBH', 1, 0, 7)                # buffer context
    h += P('<HHB', len(ext), len(user), 0)
    for typ, data in ext:
        h += P('<HHHH', 0, typ, 1, len(data)) + data
    return h + user

# --- network payloads ------------------------------------------------
IP4A, IP4B = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
IP6A = bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [1])
IP6B = bytes([0x20, 1, 0xd, 0xb8] + [0] * 11 + [2])
CNT = [0]

def csum(b):
    if len(b) % 2:
        b += b'\0'
    t = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while t >> 16:
        t = (t & 0xffff) + (t >> 16)
    return (~t) & 0xffff

def pseudo(v6, proto, n):
    if v6:
        return IP6A + IP6B + P('>IxxxB', n, proto)
    return IP4A + IP4B + P('>BBH', 0, proto, n)

def udp(sp, dp, payload, v6=False):
    h = P('>HHHH', sp, dp, 8 + len(payload), 0)
    c = csum(pseudo(v6, 17, len(h) + len(payload)) + h + payload)
    return P('>HHHH', sp, dp, 8 + len(payload), c or 0xffff) + payload

def tcp(sp, dp, flags=0x02, payload=b'', v6=False):
    CNT[0] += 1
    h = P('>HHIIBBHHH', sp, dp, 1000 * CNT[0], 0, 0x50, flags, 8192, 0, 0)
    c = csum(pseudo(v6, 6, len(h) + len(payload)) + h + payload)
    return P('>HHIIBBHHH', sp, dp, 1000 * CNT[0], 0, 0x50, flags, 8192, c, 0) + payload

def icmp_echo(payload=b'abcdefgh'):
    m = P('>BBHHH', 8, 0, 0, 1, 1) + payload
    return P('>BBHHH', 8, 0, csum(m), 1, 1) + payload

def icmp6_echo(payload=b'ping'):
    m = P('>BBHHH', 128, 0, 0, 1, 1) + payload
    return P('>BBHHH', 128, 0, csum(pseudo(True, 58, len(m)) + m), 1, 1) + payload

def dns():
    CNT[0] += 1
    return (P('>HHHHHH', 0x1000 + CNT[0], 0x0100, 1, 0, 0, 0)
            + b'\x03www\x07example\x03com\0' + P('>HH', 1, 1))

def wfp4(proto, l4, ctx=None):
    b = IP4A + IP4B + P('<B', proto)
    if ctx is not None:
        b += P('<Q', ctx)
    return b + P('<H', len(l4)) + l4

def wfp6(proto, l4, ctx=None):
    b = IP6A + IP6B + P('<B', proto)
    if ctx is not None:
        b += P('<Q', ctx)
    return b + P('<H', len(l4)) + l4

def U4(sp=None):
    CNT[0] += 1
    return udp(40000 + CNT[0], 53, dns())

def U6():
    CNT[0] += 1
    return udp(40000 + CNT[0], 53, dns(), True)

def T4(): CNT[0] += 1; return tcp(41000 + CNT[0], 80)
def T6(): CNT[0] += 1; return tcp(41000 + CNT[0], 80, v6=True)

def auth(v6, path, sport=49152, dport=443, direction=1, proto=6):
    a, b = (IP6A, IP6B) if v6 else (IP4A, IP4B)
    return (a + b + P('<HHQBB', sport, dport, 0x0000000100000002, direction, proto)
            + P('<QQ', 0xfffffa8001234567, 4242) + P('<H', len(path) * 2) + u16s(path, False))

ETH = (bytes.fromhex('000000000002' '020000000001') + b'\x08\x00')
def ip4(proto, l4):
    h = P('>BBHHHBBH', 0x45, 0, 20 + len(l4), 1, 0, 64, proto, 0) + IP4A + IP4B
    return h[:10] + P('>H', csum(h)) + h[12:] + l4
def eth_frame(): return ETH + ip4(17, U4())
def raw_ip(): return ip4(17, U4())
WLAN_NULL = bytes.fromhex('4801' '0000' '020000000002' '020000000001' '020000000003' '1000')

# --- NDIS event payloads ---------------------------------------------
K_ETH, K_WWAN, K_80211, K_START, K_END = 0x1, 0x200, 0x10000, 0x40000000, 0x80000000
FLAG_64 = 0x40

def frag(pkt, size=None):
    return P('<III', 1, 2, len(pkt) if size is None else size) + pkt

def vmswitch(ndest, pkt, oob, oobsize=None):
    b = P('<III', 1, 2, 7) + u16s('port0') + u16s('nic0') + u16s('Synthetic')
    b += P('<I', ndest)
    for i in range(ndest):
        b += P('<I', 10 + i) + u16s('dport%d' % i) + u16s('dnic%d' % i) + u16s('Emulated')
    b += P('<I', len(pkt)) + pkt
    return b + P('<I', len(oob) if oobsize is None else oobsize) + oob

def wifimeta(rev, phy, chan, size=None):
    if rev == 1:
        body = (P('<IIIH', 0x11, phy, chan, 3) + b'\0\0' + P('<i', -55) + P('<B', 13))
    else:
        body = bytes(range(10))
    return P('<BBH', 1, rev, len(body) if size is None else size) + body

def build():
    main = []
    sect = []
    def add(net, data, label=None):
        main.append((net, data))
    # Raw WFP capture frames (NetMon network types 0xE083-0xE088)
    # v4, UDP / TCP / ICMP / unknown protocol (data dissector)
    add(0xE083, wfp4(17, U4()))
    add(0xE083, wfp4(6, T4()))
    add(0xE083, wfp4(1, icmp_echo()))
    add(0xE083, wfp4(253, b'unknown-proto'))
    add(0xE084, wfp6(17, U6()))
    add(0xE084, wfp6(6, T6()))
    add(0xE084, wfp6(58, icmp6_echo()))
    add(0xE084, wfp6(253, b'unknown-proto'))
    add(0xE085, wfp4(17, U4(), 0x1122334455667788))
    add(0xE085, wfp4(6, T4(), 0x1))
    add(0xE086, wfp6(17, U6(), 0x1122334455667788))
    add(0xE086, wfp6(253, b'x', 0xffffffffffffffff))
    add(0xE087, auth(False, 'C:\\Windows\\System32\\svchost.exe'))
    add(0xE087, auth(False, '', 1025, 80, 0, 17))
    add(0xE088, auth(True, 'C:\\Program Files\\Example\\app.exe', 50000, 8443, 1, 6))
    n_raw = len(main)
    # ETW WFP capture events (NETEVENT frames, 0xFFE0)
    def wfp(eid, user, **kw):
        add(0xFFE0, event(WFP_GUID, eid, user, **kw))
    wfp(10001, u16s('wfpcap.sys') + P('<HH', 1, 2))
    wfp(10002, u16s('wfpcap.sys') + P('<HH', 1, 2))
    wfp(10003, P('<I', 3))
    wfp(10004, P('<I', 32))
    wfp(10005, P('<QIQ', 77, 5, 1 << 40))
    wfp(10006, P('<QIQ', 77, 5, 1 << 40))
    wfp(20001, u16s('Load failed') + P('<I', 0xC0000001))
    wfp(20002, u16s('Unload failed') + P('<I', 0xC0000001))
    wfp(20003, P('<I', 1) + u16s('Register failed') + P('<I', 0xC0000002))
    wfp(20004, P('<I', 2) + u16s('Unregister failed') + P('<I', 0xC0000002))
    wfp(20005, P('<I', 99) + u16s('Classify failed') + P('<I', 0xC0000003))
    wfp(60011, wfp4(17, U4()))
    wfp(60012, wfp4(6, T4(), 5))
    wfp(60021, wfp6(17, U6()))
    wfp(60022, wfp6(6, T6(), 6))
    wfp(60031, auth(False, 'C:\\a.exe'))
    wfp(60041, auth(True, 'C:\\b.exe'))
    wfp(60050, b'discard-data')
    wfp(12345, b'unknown-event')
    n_wfp = len(main)
    # ETW NDIS events
    def ndis(eid, user, **kw):
        add(0xFFE0, event(NDIS_GUID, eid, user, **kw))
    # 1001: complete Ethernet / 802.11 / WWAN packets, a packet with no
    # media keyword, and a fragment (no start/end)
    full = K_START | K_END
    ndis(1001, frag(eth_frame()), keyword=full | K_ETH)
    ndis(1001, frag(WLAN_NULL), keyword=full | K_80211)
    ndis(1001, frag(raw_ip()), keyword=full | K_WWAN)
    ndis(1001, frag(b'nomedia-bytes'), keyword=full)
    ndis(1001, frag(b'fragment-bytes'), keyword=K_START | K_ETH)
    # 1002: WiFi metadata revision 1 on 802.11a, 802.11g, channel 0,
    # unknown revision, and generic metadata
    ndis(1002, P('<III', 1, 2, 24) + wifimeta(1, 4, 5180), keyword=K_80211)
    ndis(1002, P('<III', 1, 2, 24) + wifimeta(1, 6, 2437), keyword=K_80211)
    ndis(1002, P('<III', 1, 2, 24) + wifimeta(1, 7, 0), keyword=K_80211)
    ndis(1002, P('<III', 1, 2, 14) + wifimeta(2, 0, 0), keyword=K_80211)
    ndis(1002, P('<III', 1, 2, 6) + b'\1\2\3\4\5\6', keyword=K_ETH)
    # 1003: VM switch: complete packet (start), fragment with 32-bit and
    # 64-bit OOB data, OOB size that does not match, no destinations
    oob32 = bytes(range(48))
    oob64 = bytes(range(96))
    ndis(1003, vmswitch(2, eth_frame(), b'\1\2\3'), keyword=K_START | K_ETH)
    ndis(1003, vmswitch(3, b'fragment-bytes', oob32), keyword=K_ETH)
    ndis(1003, vmswitch(1, b'fragment-bytes', oob64), keyword=K_ETH, flags=FLAG_64)
    ndis(1003, vmswitch(0, b'fragment-bytes', b'oob-raw-data', 4), keyword=K_ETH)
    # 1011-1016, 2001-2003, 3001/3002, 5000-5003, 5100, 5101
    ndis(1011, P('<I', 4))
    ndis(1012, u16s('Friendly') + u16s('{unique}') + u16s('svc') + u16s('1.0'))
    ndis(1013, u16s('Friendly') + u16s('{unique}') + u16s('svc') + u16s('1.0'))
    ndis(1014, P('<IIII', 1, 2, 6, 0x1000))
    ndis(1015, P('<IIII', 1, 2, 6, 0x1000))
    ndis(1016, P('<BBI', 7, 3, 6) + bytes.fromhex('020000000001'))
    ndis(2003, P('<BBI', 10, 5, 8) + bytes(8))
    ndis(2001, P('<III', 0x10, 0x20, 0x30))
    ndis(2002, P('<III', 0x10, 0x20, 0x30))
    ndis(3001, P('<BBII', 1, 2, 3, 4))
    ndis(3002, P('<BBII', 2, 21, 3, 4))
    for eid in (5000, 5001, 5002, 5003):
        ndis(eid, b'')
    ndis(5100, P('<BIII', 1, 2, 3, 4) + u16s('param') + u16s('descr'))
    ndis(5101, P('<B', 1) + u16s('Source') + P('<IH', 9, 3) +
         b''.join(P('<I', i) + u16s('Layer%d' % i) for i in range(3)))
    ndis(5101, P('<B', 2) + u16s('Source2') + P('<IH', 9, 0))
    ndis(9999, b'unknown-ndis-event', keyword=0x0000200000000000)
    # event with extended data items and flags (private session / 32-bit hdr)
    add(0xFFE0, event(NDIS_GUID, 3001, P('<BBII', 1, 2, 3, 4), flags=0x03,
                      ext=[(1, b'\0' * 8), (2, b'abcd')]))
    add(0xFFE0, event(NDIS_GUID, 1011, P('<I', 1), flags=0x0010 | 0x0020))
    add(0xFFE0, event(NDIS_GUID, 1011, P('<I', 1), flags=0x0108))
    # an event from another provider (no dissector): raw user data
    add(0xFFE0, event(OTHER_GUID, 1, b'other-provider-data'))
    # reproducers of the fix: event 1003 with several destinations whose
    # strings are longer than the destination count, and event 5101 with
    # 5 layers whose names are longer than 5 octets; both used to
    # overwrite the loop bound with the string size
    ndis(1003, vmswitch(5, b'fragment-bytes', oob32), keyword=K_ETH)
    ndis(5101, P('<B', 3) + u16s('Src') + P('<IH', 9, 5) +
         b''.join(P('<I', i) + u16s('LongLayerName%d' % i) for i in range(5)))
    marks = (n_raw, n_wfp)

    mal = []
    def madd(net, data):
        mal.append((net, data))
    madd(0xE083, IP4A + IP4B)                       # truncated v4
    madd(0xE084, IP6A)                              # truncated v6
    madd(0xE087, IP4A + IP4B + b'\x01\x02')         # truncated auth
    madd(0xE087, auth(False, 'abc')[:-3])           # path past end
    # 1003 complete packets: the dissector does not advance past the
    # packet, so the OOB size is read from the packet start (see README)
    madd(0xFFE0, event(NDIS_GUID, 1003, vmswitch(1, WLAN_NULL, b'\1\2\3'), keyword=K_START | K_80211))
    madd(0xFFE0, event(NDIS_GUID, 1003, vmswitch(1, raw_ip(), b''), keyword=K_START | K_WWAN))
    madd(0xFFE0, event(NDIS_GUID, 1003, vmswitch(1, b'nomedia', b''), keyword=K_START))
    madd(0xFFE0, event(WFP_GUID, 10001, b'\x41\x00'))              # unterminated string
    madd(0xFFE0, event(WFP_GUID, 10005, b'\0' * 5))                # short
    madd(0xFFE0, event(NDIS_GUID, 1001, P('<III', 1, 2, 5000) + b'abc', keyword=K_START | K_END | K_ETH))
    madd(0xFFE0, event(NDIS_GUID, 1001, P('<III', 1, 2, 100) + b'abc', keyword=K_ETH))  # fragment past end
    madd(0xFFE0, event(NDIS_GUID, 1002, P('<III', 1, 2, 24) + wifimeta(1, 4, 5180)[:10], keyword=K_80211))
    madd(0xFFE0, event(NDIS_GUID, 1003, P('<III', 1, 2, 7) + u16s('p') + u16s('n') + u16s('t') + P('<I', 0xffffff)))
    madd(0xFFE0, event(NDIS_GUID, 5101, P('<B', 1) + u16s('S') + P('<IH', 9, 60000)))
    madd(0xFFE0, event(NDIS_GUID, 5100, P('<BIII', 1, 2, 3, 4) + b'\x41\x00'))
    madd(0xFFE0, event(NDIS_GUID, 1012, b'\x41\x00\x42\x00'))
    madd(0xFFE0, event(NDIS_GUID, 3001, b'\1\2\3'))
    return main, mal, marks

if __name__ == '__main__':
    out = sys.argv[1]
    main, mal, marks = build()
    open(os.path.join(out, 'messageanalyzer-coverage.cap'), 'wb').write(netmon_file(main))
    open(os.path.join(out, 'messageanalyzer-coverage-malformed.cap'), 'wb').write(netmon_file(mal))
    if '-v' in sys.argv:
        print('main frames %d: raw WFP 1-%d, WFP events %d-%d, NDIS events %d-%d; malformed %d'
              % (len(main), marks[0], marks[0] + 1, marks[1], marks[1] + 1, len(main), len(mal)))
