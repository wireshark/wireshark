#!/usr/bin/env python3
# Generates test/captures/rtp_midi_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the RTP-MIDI dissector
(packet-rtp-midi.c, RFC 6295: command section, recovery journal with system
and channel journals).

Everything is built with struct; nothing comes from a real network.  A SIP
INVITE / 200 OK with SDP announces "rtp-midi" streams (a=rtpmap:96
rtp-midi/44100), and the RTP packets that follow carry the payload.

Usage: mkrtp_midi.py <output directory>

Writes:
  rtp-midi-coverage.pcapng            main capture (Ethernet; one Exported PDU
                                      interface for the small-fix reproducers)
  rtp-midi-coverage-malformed.pcapng  journals whose lengths do not add up,
                                      truncated chapters, bad N chapter ranges
"""
# ---- common helpers (pcap/pcapng writers, Ethernet/IP/UDP/TCP, SIP/SDP, RTP) ----
import os
import struct
import sys

MAC_A = bytes.fromhex('020000000a01')
MAC_B = bytes.fromhex('020000000a02')
IP_A = bytes([10, 0, 0, 1])
IP_B = bytes([10, 0, 0, 2])
T0 = 1700000000


def ip_csum(h):
    s = sum(struct.unpack('>%dH' % (len(h) // 2), h))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, src, dst, payload, ident=1):
    h = struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0) + src + dst
    h = h[:10] + struct.pack('>H', ip_csum(h)) + h[12:]
    return h + payload


def udp_frame(sport, dport, payload, a_to_b=True, src=None, dst=None):
    if src is None:
        src, dst = (IP_A, IP_B) if a_to_b else (IP_B, IP_A)
    macs = (MAC_B + MAC_A) if a_to_b else (MAC_A + MAC_B)
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    return macs + b'\x08\x00' + ipv4(17, src, dst, u)


def tcp_frame(sport, dport, seq, ack, flags, payload=b'', a_to_b=True):
    src, dst = (IP_A, IP_B) if a_to_b else (IP_B, IP_A)
    macs = (MAC_B + MAC_A) if a_to_b else (MAC_A + MAC_B)
    t = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    return macs + b'\x08\x00' + ipv4(6, src, dst, t)


def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            t = i * 0.01
            if isinstance(fr, tuple):
                fr, t = fr
            f.write(struct.pack('<IIII', T0 + int(t), int((t % 1) * 1000000), len(fr), len(fr)))
            f.write(fr)


def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)


def pcapng(path, frames, linktypes=(1,)):
    """frames: list of (interface index, bytes)."""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifc, fr) in enumerate(frames):
        ts = T0 * 1000000 + i * 10000
        if isinstance(fr, tuple):
            fr, t = fr
            ts = T0 * 1000000 + int(t * 1000000)
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    with open(path, 'wb') as f:
        f.write(out)


def tlv(t, v):
    return struct.pack('>HH', t, len(v)) + v


def exp_pdu(dissector, payload, bluetooth=False):
    hdr = tlv(12, dissector.encode() + b'\0' * ((-len(dissector)) % 4))
    if bluetooth:
        hdr += tlv(20, IP_A) + tlv(21, IP_B)
        hdr += tlv(24, struct.pack('>I', 15))
        hdr += tlv(25, struct.pack('>I', 1)) + tlv(26, struct.pack('>I', 1))
    return hdr + struct.pack('>HH', 0, 0) + payload


def sdp(addr, media, session='s7', origin_id=1, session_attrs=()):
    """media: list of (kind, port, proto, fmts, [attribute lines])."""
    s = 'v=0\r\no=- %d 1 IN IP4 %s\r\ns=%s\r\nc=IN IP4 %s\r\nt=0 0\r\n' % (origin_id, addr, session, addr)
    for a in session_attrs:
        s += 'a=%s\r\n' % a
    for kind, port, proto, fmts, attrs in media:
        s += 'm=%s %d %s %s\r\n' % (kind, port, proto, ' '.join(str(x) for x in fmts))
        for a in attrs:
            s += 'a=%s\r\n' % a
    return s.encode()


def sip_invite(call_id, body, frm='alice', to='bob', cseq=1, host_a='10.0.0.1', host_b='10.0.0.2'):
    h = ('INVITE sip:%s@%s SIP/2.0\r\nVia: SIP/2.0/UDP %s:5060;branch=z9hG4bK%s\r\n'
         'From: <sip:%s@%s>;tag=a1\r\nTo: <sip:%s@%s>\r\nCall-ID: %s\r\nCSeq: %d INVITE\r\n'
         'Contact: <sip:%s@%s>\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n'
         % (to, host_b, host_a, call_id, frm, host_a, to, host_b, call_id, cseq, frm, host_a, len(body)))
    return h.encode() + body


def sip_ok(call_id, body, frm='alice', to='bob', cseq=1, host_a='10.0.0.1', host_b='10.0.0.2'):
    h = ('SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP %s:5060;branch=z9hG4bK%s\r\n'
         'From: <sip:%s@%s>;tag=a1\r\nTo: <sip:%s@%s>;tag=b1\r\nCall-ID: %s\r\nCSeq: %d INVITE\r\n'
         'Contact: <sip:%s@%s>\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n'
         % (host_a, call_id, frm, host_a, to, host_b, call_id, cseq, to, host_b, len(body)))
    return h.encode() + body


def rtp(pt, seq, ts, ssrc, payload=b'', marker=False, csrc=(), ext=None, pad=0, version=2):
    """ext: (profile, bytes) with len(bytes) a multiple of 4."""
    o1 = (version << 6) | (0x20 if pad else 0) | (0x10 if ext is not None else 0) | len(csrc)
    o2 = (0x80 if marker else 0) | pt
    b = struct.pack('>BBHII', o1, o2, seq & 0xffff, ts & 0xffffffff, ssrc)
    for c in csrc:
        b += struct.pack('>I', c)
    if ext is not None:
        b += struct.pack('>HH', ext[0], len(ext[1]) // 4) + ext[1]
    b += payload
    if pad:
        b += b'\0' * (pad - 1) + bytes([pad])
    return b



PA, PB = 21000, 31000
BIT = 0x80


# ---- command section ---------------------------------------------------------
def delta(v):
    """MIDI delta time: 1 to 4 octets of 7 bits."""
    out = [v & 0x7f]
    v >>= 7
    while v:
        out.append((v & 0x7f) | 0x80)
        v >>= 7
    return bytes(reversed(out))


def cmd_section(cmds, z=False, j=False, p=False, long=False):
    """cmds: list of (delta bytes or None, command bytes)."""
    body = b''
    for i, (d, c) in enumerate(cmds):
        if d is not None:
            body += d
        body += c
    n = len(body)
    if n > 15:
        long = True
    flags = (0x40 if j else 0) | (0x20 if z else 0) | (0x10 if p else 0)
    if long:
        return struct.pack('>H', 0x8000 | (flags << 8) | n) + body
    return bytes([flags | n]) + body


# ---- journal -----------------------------------------------------------------
def journal(sysj=None, chans=(), seq=0x1234, s=False, h=False, totchan=None):
    """Recovery journal header; sysj is the system journal bytes, chans a list of channel journals."""
    n = len(chans)
    if totchan is None:
        totchan = max(n - 1, 0)
    flags = (0x80 if s else 0) | (0x40 if sysj else 0) | (0x20 if chans else 0) | (0x10 if h else 0) | totchan
    return bytes([flags]) + struct.pack('>H', seq) + (sysj or b'') + b''.join(chans)


def sysjournal(d=b'', v=b'', q=b'', f=b'', x=b'', s=False):
    body = d + v + q + f + x
    flags = (0x8000 if s else 0) | (0x4000 if d else 0) | (0x2000 if v else 0) | (0x1000 if q else 0) | \
            (0x0800 if f else 0) | (0x0400 if x else 0)
    return struct.pack('>H', flags | (len(body) + 2)) + body


def chan_journal(chan, p=b'', c=b'', m=b'', w=b'', n=b'', e=b'', t=b'', a=b'', s=False, h=False):
    body = p + c + m + w + n + e + t + a
    flags = (0x80 if p else 0) | (0x40 if c else 0) | (0x20 if m else 0) | (0x10 if w else 0) | \
            (0x08 if n else 0) | (0x04 if e else 0) | (0x02 if t else 0) | (0x01 if a else 0)
    length = len(body) + 3
    v = (0x800000 if s else 0) | (chan << 19) | (0x040000 if h else 0) | (length << 8) | flags
    return struct.pack('>I', v)[1:] + body


# system chapters
def ch_d(b=None, g=None, h=None, j=None, k=None, y=None, z=None, s=False):
    body = b''
    flags = 0x80 if s else 0
    for bit, val in ((0x40, b), (0x20, g), (0x10, h), (0x08, j), (0x04, k), (0x02, y), (0x01, z)):
        if val is not None:
            flags |= bit
            body += val
    return bytes([flags]) + body


def d_f4(count=None, value=None, legal=None, dsz=0, data=b''):
    """Chapter D F4 / F5 field: 2 octet header (S C V L DSZ LEN)."""
    body = b''
    f = 0
    if count is not None:
        f |= 0x4000
        body += bytes([count])
    if value is not None:
        f |= 0x2000
        body += value
    if legal is not None:
        f |= 0x1000
        body += legal
    body += data
    return struct.pack('>H', f | (dsz << 10) | (len(body) + 2)) + body


def d_f9(count=None, legal=None, data=b'', s=False):
    body = b''
    f = 0x80 if s else 0
    if count is not None:
        f |= 0x40
        body += bytes([count])
    if legal is not None:
        f |= 0x20
        body += legal
    body += data
    return bytes([f | (len(body) + 1)]) + body


# channel chapters
def cj_p(program=1, bank_msb=2, bank_lsb=3, s=True, b=True, x=True):
    return bytes([(0x80 if s else 0) | program, (0x80 if b else 0) | bank_msb, (0x80 if x else 0) | bank_lsb])


def cj_c(items, s=True):
    """items: list of (number, a_flag, value or (t, alt))."""
    out = bytes([(0x80 if s else 0) | (len(items) - 1)])
    for num, a, val in items:
        out += bytes([0x80 | num, (0x80 if a else 0) | val])
    return out


def cj_m_item(lsb, msb, q=False, flags=0, extra=b'', s=True, nomsb=False):
    """flags J K L M N T V R as one octet; extra: the optional fields"""
    if nomsb:
        return bytes([(0x80 if s else 0) | lsb, flags]) + extra
    return bytes([(0x80 if s else 0) | lsb, (0x80 if q else 0) | msb, flags]) + extra


def cj_m(items, hdr_flags=0):
    body = b''.join(items)
    return struct.pack('>H', hdr_flags | (len(body) + 2)) + body


def cj_n(notes, offbits=b'', low=0, high=None):
    if high is None:
        high = max(len(offbits) - 1, 0)
    if not offbits:
        low, high = 15, 0
    hdr = (len(notes) << 8) | (low << 4) | high
    out = struct.pack('>H', hdr)
    for n, v, y in notes:
        out += bytes([0x80 | n, (0x80 if y else 0) | v])
    return out + offbits


def cj_e(items):
    """items: (note, v_flag, value)"""
    out = bytes([0x80 | (len(items) - 1)])
    for n, vf, v in items:
        out += bytes([0x80 | n, (0x80 if vf else 0) | v])
    return out


def cj_a(items):
    out = bytes([0x80 | (len(items) - 1)])
    for n, x, pr in items:
        out += bytes([0x80 | n, (0x80 if x else 0) | pr])
    return out


def midi(payload, seq, ts=0, ssrc=0x6d000001):
    return rtp(96, seq, ts, ssrc, payload)


def main(outdir):
    F = []

    def add(fr, ifc=0):
        F.append((ifc, fr))
    off = sdp('10.0.0.1', [('audio', PA, 'RTP/AVP', [96], ['rtpmap:96 rtp-midi/44100',
                                                           'fmtp:96 cm_unused=ABCFGHJKMNPQTUVWXYZ;cm_used=2NPTW'])])
    ans = sdp('10.0.0.2', [('audio', PB, 'RTP/AVP', [96], ['rtpmap:96 rtp-midi/44100'])])
    add(udp_frame(5060, 5060, sip_invite('midi1', off)))
    add(udp_frame(5060, 5060, sip_ok('midi1', ans), a_to_b=False))
    seq = [1]
    ts = [0]

    def pkt(payload, a2b=True):
        seq[0] += 1
        ts[0] += 441
        if a2b:
            add(udp_frame(PA, PB, midi(payload, seq[0], ts[0])))
        else:
            add(udp_frame(PB, PA, midi(payload, seq[0], ts[0], 0x6d000002), a_to_b=False))
    NOTE_ON = bytes([0x90, 0x3c, 0x64])
    NOTE_ON2 = bytes([0x91, 0x40, 0x50])
    PROG = bytes([0xc2, 0x05])
    BEND = bytes([0xe0, 0x00, 0x40])
    CC = bytes([0xb0, 0x07, 0x7f])
    PRESS = bytes([0xd0, 0x30])
    POLY = bytes([0xa0, 0x3c, 0x20])
    SYSEX = bytes([0xf0, 0x7e, 0x7f, 0x09, 0x01, 0xf7])
    CLOCK = bytes([0xf8])
    MTC = bytes([0xf1, 0x25])

    # ---- command section only ---------------------------------------------------
    pkt(b'\x00')                                                        # empty
    pkt(cmd_section([(None, NOTE_ON)]))
    pkt(cmd_section([(delta(5), NOTE_ON)], z=True))
    pkt(cmd_section([(None, NOTE_ON), (delta(0), PROG), (delta(130), BEND), (delta(300000), CC),
                     (delta(20000000), PRESS)]), a2b=False)             # delta times of 1-4 octets
    pkt(cmd_section([(None, NOTE_ON), (delta(10), bytes([0x3e, 0x64])), (delta(10), bytes([0x40, 0x00]))]))   # running status
    pkt(cmd_section([(None, SYSEX), (delta(3), CLOCK), (delta(3), MTC)]))
    pkt(cmd_section([(None, POLY), (delta(1), NOTE_ON2)], p=True))                # P flag
    pkt(cmd_section([(None, NOTE_ON)] + [(delta(1), NOTE_ON)] * 5, long=True))                            # B flag (long header)
    pkt(cmd_section([(None, NOTE_ON), (delta(7), b'')]))                          # a trailing delta time only
    pkt(cmd_section([(delta(1), b'')], z=True))                                   # only a delta time
    pkt(cmd_section([(None, NOTE_ON)] + [(delta(1), NOTE_ON)] * 89, long=True))                           # longer than 15
    pkt(cmd_section([(None, bytes([0xff, 0x2f, 0x00]))]))                         # a meta-like status

    # ---- journals only ---------------------------------------------------------------
    pkt(cmd_section([], j=True) + journal(seq=1))                                # header only, S flag clear
    pkt(cmd_section([], j=True) + journal(seq=2, s=True, h=True))

    # ---- system journal: every chapter ------------------------------------------------------
    d_all = ch_d(b=bytes([0x83]), g=bytes([0x02]), h=bytes([0x81]),
                 j=d_f4(count=1, value=bytes([0x85]), dsz=3),
                 k=d_f4(legal=b'\x01\x02', dsz=2),
                 y=d_f9(count=3, legal=b'\x07'),
                 z=d_f9(data=b'\x05'), s=True)
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(d=d_all, s=True)))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(d=ch_d(b=bytes([0x05])))))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(d=ch_d(g=bytes([0x84]), h=bytes([0x05])))))
    # f4 with a count only, a value only, data only, legal only
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(d=ch_d(j=d_f4(count=7)))))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(d=ch_d(k=d_f4(value=bytes([0x90]))))))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(d=ch_d(j=d_f4(data=b'\x11\x22\x33'))))) # data
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(d=ch_d(j=d_f4(legal=b'\x44\x55'), k=d_f4(count=1, legal=b'\x66')))))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(d=ch_d(y=d_f9(count=1), z=d_f9(legal=b'\x01\x02\x03', s=True)))))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(d=ch_d(y=d_f9(data=b'\x01\x02\x03'), z=d_f9(count=4, data=b'\x04'))))) # data
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(v=bytes([0x8a]))))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(q=bytes([0x17, 0xaa, 0xbb]))))        # clock
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(q=bytes([0x45]))))                       # top
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(q=bytes([0xa5, 0x01, 0x02, 0x03]))))     # timetools
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(q=bytes([0x97, 0x01, 0x02, 0x03, 0x04, 0x05]))))   # both
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(f=bytes([0x50, 0x01, 0x02, 0x03, 0x04]))))   # complete, quarter frames
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(f=bytes([0x40 | 0x20 | 0x08 | 5, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d]))))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(f=bytes([0x20, 0x01, 0x02, 0x03, 0x04]))))     # partial
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(f=bytes([0x83]))))                         # neither
    # chapter X: all fields, FIRST of 1-4 octets, data, List tool
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(x=bytes([0x10 | 0x03, 0x05]) + b'\x00' * 2)))   # FIRST
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(x=bytes([0xe0 | 0x0c | 0x01, 0x02, 0x03, 0x8a, 0x05, 0x90, 0x3c, 0x40, 0x80, 0x3c, 0x00]))))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(x=bytes([0x30, 0x81, 0x01]))))                # FIRST 2 octets
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(x=bytes([0x10, 0x81, 0x81, 0x01]))))          # 3 octets
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(x=bytes([0x10, 0x81, 0x81, 0x81, 0x01]))))    # 4 octets
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(x=bytes([0x08, 0x90, 0x3c, 0x40, 0x80, 0x01]))))   # DATA with trailing octets
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=sysjournal(x=bytes([0x00, 0x01, 0x02]))))                # nothing but invalid data
    # every system chapter together
    allsys = sysjournal(d=ch_d(b=bytes([0x01]), s=True), v=bytes([0x83]), q=bytes([0x45]),
                        f=bytes([0x50, 0x01, 0x02, 0x03, 0x04]), x=bytes([0x08, 0x90, 0x3c, 0x40, 0x80]), s=True)
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(sysj=allsys, s=True, h=True))

    # ---- channel journals -----------------------------------------------------------------------
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[chan_journal(0, p=cj_p())]))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[chan_journal(3, p=cj_p(5, 6, 7, False, False, False), s=True, h=True)]))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[
        chan_journal(1, c=cj_c([(7, False, 100), (10, True, 0x40 | 0x05), (64, True, 0x3f)]))]))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[chan_journal(2, w=b'\x81\x82')]))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[chan_journal(4, t=b'\x85')]))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[chan_journal(5, a=cj_a([(60, False, 30), (61, True, 40)]))]))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[chan_journal(6, e=cj_e([(60, True, 64), (61, False, 3), (62, True, 0)]))]))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[
        chan_journal(7, n=cj_n([(60, 100, True), (62, 90, False)], offbits=b'\x01\x02', low=1, high=2))]))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[chan_journal(8, n=cj_n([(60, 100, True)]))]))   # no offbits
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[chan_journal(9, n=cj_n([], offbits=b'\x7f', low=0, high=0))]))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[chan_journal(9, n=struct.pack('>H', 0x0000 | (15 << 4) | 1))]))   # low 15, high 1
    # chapter M: items with every optional field
    m1 = cj_m_item(0x10, 0x20, flags=0xfc, extra=bytes([0x41, 0x42]) + bytes([0x80, 0x01]) + bytes([0x40, 0x02]) + bytes([0x7f]))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[chan_journal(10, m=cj_m([m1]))]))
    m2 = cj_m_item(0x11, 0x21, q=True, flags=0x08, extra=bytes([0x7f]))
    m3 = cj_m_item(0x12, 0x22, flags=0x80, extra=bytes([0x05]))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[chan_journal(11, m=cj_m([m2, m3]), c=cj_c([(1, False, 2)]))]))
    # the no-PNUM-MSB form: Z flag with U or W
    m4 = cj_m_item(0x13, 0, flags=0x40, extra=bytes([0x09]), nomsb=True)
    MZ = line_z = (lambda: cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[chan_journal(12, m=cj_m([m4], hdr_flags=0x0400))]))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[chan_journal(12, m=cj_m([m4], hdr_flags=0x0400 | 0x1000))]))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[chan_journal(12, m=cj_m([m4], hdr_flags=0x0400 | 0x0800))]))
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[chan_journal(12, m=cj_m([m1], hdr_flags=0x8000 | 0x2000 | 0x1000 | 0x0200))]))
    # all chapters of one channel
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[
        chan_journal(13, p=cj_p(), c=cj_c([(7, False, 100)]), m=cj_m([m3]), w=b'\x01\x02',
                     n=cj_n([(60, 100, True)], offbits=b'\x01'), e=cj_e([(60, True, 64)]), t=b'\x05',
                     a=cj_a([(60, False, 30)]))]))
    # several channels, with a system journal
    pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(
        sysj=sysjournal(v=bytes([0x01])),
        chans=[chan_journal(0, p=cj_p()), chan_journal(1, t=b'\x05'), chan_journal(15, w=b'\x01\x02')]), a2b=False)
    # enhanced encoding (H flag), a long command section and every channel number
    for ch in range(16):
        pkt(cmd_section([(None, NOTE_ON)], j=True) + journal(chans=[chan_journal(ch, t=bytes([ch]))], seq=ch))

    # ---- Exported PDU: small-fix reproducers ---------------------------------------------------------
    hdr = b'\x40' + b'\x40' + struct.pack('>H', 1)
    p1 = hdr + struct.pack('>H', 0x0400 | 4) + b'\x10\x05' + b'\x00' * 8     # FIRST must be decoded
    p2 = hdr + struct.pack('>H', 0x4000 | 7) + b'\x08' + struct.pack('>H', 0x1004) + b'\xaa\xbb' + b'\x00' * 8
    # (the 8 zero octets after the journal are not part of it; see the README)
    add(exp_pdu('rtpmidi', hdr + sysjournal(x=bytes([0x10, 0x05]))), 1)
    add(exp_pdu('rtpmidi', hdr + sysjournal(d=ch_d(j=d_f4(legal=b'\xaa\xbb')))), 1)
    # more chapter fields (appended): F5 with data, X with FIRST of two octets, DATA that starts with
    # data octets (a status octet first is not consumed by the dissector, see the README)
    cs = cmd_section([(None, NOTE_ON)], j=True)
    pkt(cs + journal(sysj=sysjournal(d=ch_d(k=d_f4(data=b'\x11\x22')))))
    pkt(cs + journal(sysj=sysjournal(x=bytes([0x10, 0x81, 0x01]))))
    pkt(cs + journal(sysj=sysjournal(x=bytes([0x08, 0x3c, 0x40, 0x90, 0x3c]))))
    pkt(cs + journal(sysj=sysjournal(x=bytes([0x08, 0x3c, 0x40]))))
    pcapng(os.path.join(outdir, 'rtp-midi-coverage.pcapng'), F, linktypes=(1, 252))

    # ---- malformed ---------------------------------------------------------------------------------------
    F = F[:2]
    seq[0] = 500
    pkt(b'')                                                                      # no payload
    pkt(MZ())                                                                     # Z flag only, but a no-MSB item
    pkt(b'\x05\x90')                                                              # command longer than the packet
    pkt(b'\x80')                                                                  # long header cut short
    pkt(cmd_section([(None, NOTE_ON)], j=True))                                   # journal flag, no journal
    pkt(cmd_section([(None, NOTE_ON)], j=True) + b'\x40\x00')                     # journal cut short
    pkt(cmd_section([], j=True) + journal(sysj=struct.pack('>H', 0x4000 | 9) + ch_d(b=bytes([1]))))   # system journal length does not match
    pkt(cmd_section([], j=True) + journal(chans=[chan_journal(0, t=b'\x01')[:-1] + b'']))             # channel journal length does not match
    cj = bytearray(chan_journal(0, t=b'\x01'))
    cj[1] = (cj[1] & 0xfc) | 0x03
    cj[2] = (cj[2] & 0x00) | 0x02
    pkt(cmd_section([], j=True) + journal(chans=[bytes(cj) + b'\x00']))
    pkt(cmd_section([], j=True) + journal(chans=[chan_journal(1, n=struct.pack('>H', (3 << 4) | 1))]))    # N chapter: low > high
    pkt(cmd_section([], j=True) + journal(chans=[chan_journal(1, p=b'\x01')[:4]]))                      # chapter P cut short
    pkt(cmd_section([], j=True) + journal(chans=[chan_journal(1, c=bytes([0xff]))]))                   # chapter C: 128 items, none present
    pkt(cmd_section([], j=True) + journal(chans=[chan_journal(1, e=bytes([0xff]))]))
    pkt(cmd_section([], j=True) + journal(chans=[chan_journal(1, a=bytes([0xff]))]))
    pkt(cmd_section([], j=True) + journal(chans=[chan_journal(1, m=struct.pack('>H', 40) + bytes(20))]))   # chapter M longer than the packet
    pkt(cmd_section([], j=True) + journal(chans=[chan_journal(1, m=struct.pack('>H', 0x4000 | 6) + bytes([0x00, 0x00, 0x00, 0x00]))]))   # P flag: pending octet
    pkt(cmd_section([], j=True) + journal(chans=[chan_journal(1, n=struct.pack('>H', (127 << 8) | (15 << 4) | 0))]))
    pkt(cmd_section([], j=True) + journal(sysj=sysjournal(x=bytes([0x10, 0x81, 0x81, 0x81, 0x81, 0x01]))))   # FIRST 5 octets
    pkt(cmd_section([], j=True) + journal(sysj=sysjournal(x=bytes([0x18, 0x81, 0x81]))))
    pkt(cmd_section([], j=True) + journal(sysj=sysjournal(d=bytes([0x08]) + struct.pack('>H', 0x2000 | 4) + b'\x01\x02')))   # f4 value never terminated
    pkt(cmd_section([], j=True) + journal(sysj=sysjournal(d=ch_d(j=struct.pack('>H', 0x2000 | 3) + bytes([0x01])))))
    pkt(cmd_section([], j=True) + journal(sysj=sysjournal(q=bytes([0x17, 0xaa]))))
    pkt(cmd_section([], j=True) + journal(sysj=sysjournal(f=bytes([0x60, 0x01]))))
    pkt(cmd_section([], j=True) + journal(sysj=sysjournal(d=ch_d(y=bytes([0x7f]))))) # f9 length larger than packet
    pkt(cmd_section([(None, bytes([0xf0, 0x01, 0x02]))]))                           # SysEx without the end
    pkt(cmd_section([(None, NOTE_ON), (b'\x81\x81\x81\x81', PROG)]))                # delta time of 5 octets
    pcapng(os.path.join(outdir, 'rtp-midi-coverage-malformed.pcapng'), F, linktypes=(1, 252))


if __name__ == '__main__':
    main(sys.argv[1])
