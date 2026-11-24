#!/usr/bin/env python3
# Generates test/captures/c15ch_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the C15 Call History dissector
(packet-c15ch.c).

C15 call history messages are carried directly over Ethernet with
ethertype 0x4742 (c15.ch); the heartbeat has its own ethertype 0x0C15
(c15hbeat). Every packet is built from scratch with struct; no captured
traffic is used. Addresses are locally administered MACs.

Usage: mkc15ch.py <output directory>

Writes:
  c15ch-coverage.pcap            one well-formed packet for every message
                                 type and every INC_GWE, OUT_GWE and TONE
                                 subtype, CP_EVENT PM/trunk PM variants,
                                 NITN_XLATE equipment variants, ISUP, Q.931
                                 and SCCP payloads, the Q.931 length
                                 reproducer (frame ranges in the README)
  c15ch-coverage-malformed.pcap  truncated messages, short headers, digit
                                 counts past their fields
"""

import os
import struct
import sys

MAC_A = bytes.fromhex('020000000001')
MAC_B = bytes.fromhex('020000000002')
ETH_C15CH = 0x4742
ETH_C15HB = 0x0C15

_callref = [0x1000]


def eth(etype, payload, dst=MAC_A, src=MAC_B):
    return dst + src + struct.pack('>H', etype) + payload


def c15(mt, payload, size=None, callref=None):
    """C15 common header (36 octets) and payload."""
    if callref is None:
        _callref[0] += 1
        callref = _callref[0]
    if size is None:
        size = 36 + len(payload)
    hdr = struct.pack('>IIIIIIIII', 1, mt, size, callref,
                      0x11, 0x22, 0x33, 0x44, 1700000000 + callref)
    return eth(ETH_C15CH, hdr + payload)


def pad(b, n):
    assert len(b) <= n, (len(b), n)
    return b + bytes(n - len(b))


def s(text, n):
    """NUL-terminated ASCII string in an n octet field."""
    b = text.encode('ascii')
    assert len(b) < n
    return pad(b + b'\0', n)


def digits(d, n):
    """Telephony digits, one per octet, in an n octet field."""
    return pad(bytes(d), n)


def u8(*v):
    return bytes(v)


def u32(*v):
    return struct.pack('>%dI' % len(v), *v)


def ip_le(a, b, c, d):
    """SDP addresses are read little endian."""
    return bytes([d, c, b, a])


# Digit patterns: 0-9, and the letters A * # ? ? D (10-15)
DIG_ALL = list(range(10))
DIG_SPECIAL = [10, 11, 12, 13, 14, 15]

# Message types
CP_STATE_CH, CP_EVENT, ISUP, NITN_XLATE, SCCP, CP_ORIG, CONN, NTWK_CONN, \
    MK_BRK, PATH_FIND, PATH_IDLE, DEST_DIGITS, TWC_RSWCH, SRCE_DEST, ROUTE, \
    INC_GWE, OUT_GWE, OUT_GWE_BC, Q931, AMA, QOS, ECHO_CANCEL, TONE, \
    ENCAP_ISUP, TCAP, CLLI, INFO, GENERIC_1, GENERIC_2, GENERIC_3, \
    GENERIC_4, GENERIC_5, CORRELATE, SIP_REG_SUBS, SYS_ALARM, TTY = range(1, 37)


# Heartbeat ------------------------------------------------------------------

def hbeat(clli, primary, secondary, iface, total=62):
    p = bytes(range(10)) + s(clli, 25) + u8(primary, secondary) + s(iface, 25)
    return eth(ETH_C15HB, pad(p, total))


def hbeat_long_iface():
    """Interface string longer than its 25 octet field (it is truncated);
    the frame is long enough for its terminating NUL."""
    p = bytes(range(10)) + s('CLLI-B', 25) + u8(0, 1) + b'IFACE-NAME-LONGER-THAN-25-OCTETS\0'
    return eth(ETH_C15HB, p)


# Second level messages --------------------------------------------------------

def cp_state_ch(oldpm, newpm):
    return c15(CP_STATE_CH, u32(oldpm, newpm, 3, 4, 5, 0x00000101, 1, 10, 2, 20))


def cp_event(pm, subpm, trkpm, event=1, parm=7):
    return c15(CP_EVENT, u32(pm, subpm, trkpm, 0x55, event, parm, 123456))


def isup_hdr(msgtype):
    h = u8(0, msgtype) + u32(7) + u8(1, 2, 3, 4, 5, 6, 9) + u32(0x101, 0x202)
    h += bytes(range(1, 19)) + u8(0xa1, 0xa2) + bytes(range(0x31, 0x39))
    assert len(h) == 49
    return h


ISUP_REL = u8(0x02, 0x00, 0x0c, 0x02, 0x00, 0x02, 0x80, 0x90)   # CIC 2, REL, cause 16
ISUP_RLC = u8(0x01, 0x00, 0x10, 0x00)                            # CIC 1, RLC


def isup():
    return c15(ISUP, isup_hdr(0x0c) + pad(ISUP_REL, 271) + u32(424242))


def encap_isup():
    return c15(ENCAP_ISUP, u8(1) + u32(len(ISUP_RLC)) + pad(ISUP_RLC, 268))


def nitnxlate(equip, gwtype, key=0, tgnum=0, site='SITE', subsite='SUB',
              frame=1, shelf=2, lsg=3, unit=4, user_tid='', host='',
              line_id=''):
    p = u32(0x66, 0x77, 9) + s(site, 5) + s(subsite, 5) + s(equip, 5)
    p += u32(gwtype, frame, shelf, lsg, unit, key)
    p += s(user_tid, 65) + s(host, 65) + u32(tgnum) + s(line_id, 5)
    assert len(p) == 190
    return c15(NITN_XLATE, p)


def sccp():
    called = u8(0x43, 0x01, 0x00, 0xfa)
    calling = u8(0x43, 0x02, 0x00, 0xfa)
    data = b'C15-SCCP'
    p1 = 3
    p2 = 2 + 1 + len(called)
    p3 = 1 + 1 + len(called) + 1 + len(calling)
    udt = u8(0x09, 0x00, p1, p2, p3, len(called)) + called + \
        u8(len(calling)) + calling + u8(len(data)) + data
    h = u8(1, 0x09, 15) + u32(0xabcd) + u8(1, 2, 3, 4, 5, 6, 7) + u32(0x88, 0x99) + u8(3)
    h += u8(0xee, 0xee)   # two octets skipped before the SCCP message type
    assert len(h) == 25
    return c15(SCCP, h + pad(udt, 273) + u32(31337))


def cp_orig():
    p = u32(2, 0x10, 0x20)
    p += u8(10) + digits([5, 5, 5, 1, 2, 3, 4, 5, 6, 7], 10)
    p += u8(1, 2, 3, 0, 1)
    p += u8(15) + digits(DIG_ALL + DIG_SPECIAL[:5], 15)
    p += u8(0, 1, 1, 0, 1)
    p += u8(7) + digits([8, 0, 0, 1, 2, 3, 4], 15)
    p += u8(3, 2, 1, 0) + u32(99)
    assert len(p) == 73
    return c15(CP_ORIG, p)


def conn():
    p = u32(1, 2, 3) + u8(1) + u32(0x10, 0x11, 0x20, 0x21) + u32(5, 6, 7, 8, 9, 0x1234)
    assert len(p) == 53
    return c15(CONN, p)


def ntwk_conn():
    p = u8(1, 2, 1) + s('FRM', 5) + u8(4, 3, 2, 1) + u32(77, 0x31, 0x32)
    p += u8(1, 0) + s('TOS', 5) + u8(8, 7, 6, 5) + u32(88)
    assert len(p) == 39
    return c15(NTWK_CONN, p)


def mk_brk():
    return c15(MK_BRK, u8(1, 2, 3) + u32(0xdead, 0xbeef))


def path_find():
    p = u8(1) + u32(0x41, 0x42) + u8(1) + s('PFA', 5) + u8(3, 4) + u32(5, 6, 7)
    p += u32(0x43, 0x44) + u32(0x45, 0x46) + u8(0) + s('PFB', 5) + u8(8, 9) + u32(10, 11, 12)
    p += u32(0x47, 0x48)
    assert len(p) == 73
    return c15(PATH_FIND, p)


def path_idle():
    p = u8(1, 2, 3) + u32(0x51, 0x52) + s('PIA', 5) + u8(3, 4) + u32(5, 6, 7)
    p += u32(0x53, 0x54) + u32(0x55, 0x56) + s('PIB', 5) + u8(8, 9) + u32(10, 11, 12)
    p += u32(0x57, 0x58)
    assert len(p) == 73
    return c15(PATH_IDLE, p)


def dest_digits():
    d = [6, 1, 3, 5, 5, 5, 0, 1, 9, 9] + DIG_SPECIAL   # A * # ? ? D
    return c15(DEST_DIGITS, u32(len(d)) + digits(d, 32))


def twc_rswch():
    return c15(TWC_RSWCH, u32(1, 2, 3, 4, 5, 6, 7))


def srce_dest():
    return c15(SRCE_DEST, u8(1, 2, 1))


def route(long):
    p = u32(42, 1, 2, 3) + u8(1)
    if long:
        p += u32(9, 16)
    return c15(ROUTE, p)


INC_GWE_HDR_NI, INC_GWE_HDR_TN = 0x123, 0x456


def inc_gwe(task, fiat, dtype, body):
    return c15(INC_GWE, u32(INC_GWE_HDR_NI, INC_GWE_HDR_TN) + u8(task, fiat, dtype) + body)


def ptrk_setup_body():
    p = u32(0x5151)
    p += u8(10) + digits([2, 1, 2, 5, 5, 5, 0, 1, 0, 0], 32)
    p += ip_le(192, 0, 2, 10) + u32(16384) + u8(1)
    p += u8(10) + digits([3, 1, 2, 5, 5, 5, 0, 2, 0, 0], 32)
    p += u8(3, 1) + u32(5)
    p += u8(4) + digits([4, 4, 4, 4], 15) + u8(2, 1)
    p += u8(5) + digits([5, 5, 5, 5, 5], 15)
    p += u8(6) + digits([6, 6, 6, 6, 6, 6], 10) + u8(3, 1) + u8(1)
    p += u8(7) + digits([7, 7, 7, 7, 7, 7, 7], 32)
    p += u8(4) + digits([0, 2, 8, 8], 4)
    p += u8(1)
    assert len(p) == 172, len(p)
    return p


def inc_gwe_bodies():
    """(task, fiat, data type, body) for every INC_GWE data type."""
    return [
        (1, 1, 1, u32(1, 200, 3) + ip_le(192, 0, 2, 1) + u32(5000) + ip_le(198, 51, 100, 2) + u32(6000)),
        (1, 2, 2, u32(4) + u8(1, 2, 3) + ip_le(192, 0, 2, 3) + u32(7000, 0x0f)),
        (1, 3, 3, u32(510)),
        (4, 4, 4, u8(5, 1)),
        (4, 6, 5, u8(1)),
        (7, 0, 6, u32(1) + u8(10) + digits([9, 1, 9, 5, 5, 5, 1, 2, 1, 2], 32)),
        (8, 3, 7, u32(0x71, 0x72, 3, 4, 0x7f000001)),
        (5, 4, 8, u32(0x81) + u8(11) + digits([1, 6, 1, 3, 5, 5, 5, 0, 1, 2, 3], 32) +
         ip_le(192, 0, 2, 8) + u32(8000)),
        (5, 12, 9, ptrk_setup_body()),
        (5, 5, 10, u32(0xa1) + u8(2) + ip_le(192, 0, 2, 9) + u32(9000) + u8(180, 0)),
        (5, 6, 11, u32(0xb1) + u8(3) + ip_le(192, 0, 2, 11) + u32(11000) + u8(1)),
        (5, 7, 12, u32(0xc1) + u8(4, 16, 0)),
        (5, 8, 13, u32(0xd1) + u8(5) + ip_le(192, 0, 2, 13) + u32(13000) +
         ip_le(198, 51, 100, 13) + u32(13002) + u8(200)),
        (5, 9, 14, u32(0xe1, 6, 12)),
        (5, 10, 15, u32(0xf1, 7) + u8(7) + digits([5, 5, 5, 0, 1, 4, 4], 15)),
        (5, 11, 16, u32(0x101, 8) + u8(8) + digits([5, 5, 5, 0, 1, 6, 6, 6], 32) + u32(0x16, 0x17)),
        (5, 13, 17, u32(0x111, 0x112)),
        (5, 14, 18, u32(0x121, 0x122, 0x123, 0x124)),
        (5, 15, 19, u32(0x131) + u8(1) + u32(5) + u8(0x2c)),
        (5, 16, 20, u32(0x141, 9) + ip_le(192, 0, 2, 20) + u32(20000)),
        (8, 1, 21, u32(0x151) + u8(4) + digits([2, 0, 0, 1], 32)),
        (5, 1, 22, u32(0x161, 2, 200, 10) + ip_le(192, 0, 2, 22) + u32(22000) +
         ip_le(198, 51, 100, 22) + u32(22002)),
        (5, 2, 23, u32(0x171)),
        (5, 17, 24, u32(0x181) + u8(1)),
    ]


def inc_gwe_extra():
    """Task variants: INVALID task (no fiat table), MTCE, OM, MGCP, an
    unknown fiat, an unknown task and data type IN_DATA_NONE."""
    return [
        inc_gwe(0, 0, 23, u32(0x201)),
        inc_gwe(2, 4, 3, u32(17)),
        inc_gwe(3, 9, 3, u32(18)),
        inc_gwe(6, 2, 4, u8(7, 2)),
        inc_gwe(9, 1, 3, u32(19)),
        inc_gwe(1, 1, 0, b''),
    ]


def out_gwe(msgtype, dtype, body, protocol=1):
    return c15(OUT_GWE, u32(0x321, 0x654) + u8(msgtype, protocol) + u32(0x9999) + u8(dtype) + body)


def out_gwe_bodies():
    return [
        # the 4 octet override overlaps the first 3 octets of the digit map
        (1, u8(1) + s('[2-9]xxxxxx|1[2-9]xxxxxxxxx', 250) + u8(1, 2, 30, 1)),
        (2, u32(0x22)),
        (3, u32(0x33) + ip_le(192, 0, 2, 33) + u32(3300)),
        (4, u32(0x44) + u8(1, 2)),
        (5, u32(0x55) + ip_le(192, 0, 2, 55) + u32(5500) + u8(1)),
        (6, u32(0x66) + ip_le(192, 0, 2, 66) + u32(6600) +
         u8(10) + digits([2, 1, 2, 5, 5, 5, 0, 1, 6, 6], 15) + u8(3, 1) +
         u8(11) + digits([1, 2, 1, 2, 5, 5, 5, 0, 1, 6, 7], 15) +
         u8(10) + digits([4, 1, 5, 5, 5, 5, 0, 1, 6, 8], 10) + u8(3, 1, 0)),
        (7, u32(0x77, 180) + u8(0)),
        (8, u32(1, 200)),
        (9, u32(16) + u8(1)),
        (10, u32(0x1010, 0x1011)),
        (11, u32(0x1111, 0x1112)),
        (12, u32(0x1212) + u8(2) + u32(0x1213, 0x1214, 0x1215, 0x1216)),
        (13, u32(0x1313, 0x1314)),
        (14, u8(1) + s('C15 CALLER', 100)),
        (15, u32(0x1515, 0x1516, 0x1517)),
        (16, u8(1) + u32(3)),
        (17, u8(1, 2)),
        (18, s('sip:subscriber@example.invalid', 72)),
        (19, u32(0x1919, 0x191a)),
        (20, u32(0x7f000002)),
        (21, u32(0x2121)),
        (22, u8(1, 0, 1)),
        (23, u8(2) + u32(0x2323)),
        (24, u32(0x2424)),
    ]


def outgwebc():
    p = u32(0x81, 0x82, 3) + u8(1, 2) + ip_le(192, 0, 2, 18) + u32(18000) + u8(1) + u32(0x0f)
    assert len(p) == 27
    return c15(OUT_GWE_BC, p)


def q931_frame(direction, ni, tn, mlen, skip, msg, callref=None):
    return c15(Q931, u8(direction) + u32(ni, tn, mlen) + bytes(skip) + msg, callref=callref)


Q931_SETUP = u8(0x08, 0x01, 0x01, 0x05, 0x04, 0x03, 0x80, 0x90, 0xa2)
Q931_RELEASE = u8(0x08, 0x01, 0x81, 0x4d, 0x08, 0x02, 0x80, 0x90)


def q931_repro():
    """c15ch_q931_len_wrap.py: frame 1 a valid length, frames 2
    and 3 a Q.931 message length shorter than the skipped octets."""
    def pkt(direction, mlen):
        q = bytes([0x08, 0x01, 0x01, 0x05, 0x04, 0x03, 0x80, 0x90, 0xa2])
        body = bytes([direction]) + struct.pack('>II', 1, 2) + struct.pack('>I', mlen) + bytes(13) + q
        hdr = struct.pack('>IIIIIIIII', 1, 19, 36 + len(body), 0x1234, 1, 2, 3, 4, 5)
        return b'\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x47\x42' + hdr + body
    return [pkt(0, 22), pkt(0, 5), pkt(1, 3)]


def ama(call_type=1):
    d = [8, 0, 0, 5, 5, 5, 0, 1, 9, 9] + DIG_SPECIAL[:5]
    p = u8(6) + digits(DIG_ALL, 10) + u8(len(d), 1) + digits(d, 15)
    p += u8(13, 45, 30, 5, 24, 12, 25, 1) + u32(65000) + u8(call_type)
    assert len(p) == 41
    return c15(AMA, p)


def qos():
    p = u32(0x91, 0x92, 0x1001, 1, 25, 2, 0, 18)
    p += u8(192, 0, 2, 21) + u8(198, 51, 100, 21) + u8(203, 0, 113, 21)
    p += u32(1000, 5, 1, 12, 40, 38, 3600, 420)
    p += u8(1) + s('6135550199', 13) + u8(4, 5, 13, 45, 30, 5, 25, 12, 24, 3)
    assert len(p) == 100
    return c15(QOS, p)


def echo_cancel(old, new, tone, spare=True):
    """The message is 31 octets, but the Location string item is added
    with 17 octets from offset 15 (one past the slot field), so a 31 octet
    message throws; give it a spare octet unless spare is False."""
    p = u32(0xec1, 0xec2) + u8(old, new, 1 if tone else 0) + u32(tone or 0) + u32(1, 2, 3, 4)
    assert len(p) == 31
    if spare:
        p += u8(0)
    return c15(ECHO_CANCEL, p)


def tone(subtype, body):
    return c15(TONE, u8(subtype) + body)


def tone_bodies():
    return [
        (1, u8(3, 4)),
        (2, u8(5, 6)),
        (3, u32(0x301, 0x302, 0x303) + u8(11) + digits([6, 1, 3, 5, 5, 5, 0, 1, 7, 7, 15], 54)),
        (4, u8(1, 2, 3, 4, 5)),
        (5, u8(1, 2, 3)),
        (6, u8(9) + u32(0x601, 0x602)),
        (7, u8(7, 8)),
        (8, u8(1, 2) + u32(0x801, 0x802) + u8(1) + u32(0x803)),
    ]


def tcap():
    return c15(TCAP, u8(1, 2, 3, 4, 2, 0, 1, 5, 1, 0, 1, 0, 2, 3, 4, 5) + u32(0xcafe))


def clli(name):
    p = s(name, 25) + u8(1, 2) + s('ETH-IFACE-0' if name else '', 25) + u32(1700000000, 250000)
    return c15(CLLI, p)


def clli_long():
    """A CLLI string of 28 characters runs past its 25 octet field into the
    core octets (it is truncated, and not put in the Info column)."""
    p = b'CLLI-STRING-LONGER-THAN-25-X\0' + s('ETH-IFACE-1', 23) + u32(1700000001, 1)
    assert len(p) == 60
    return c15(CLLI, p)


def c15_info():
    return c15(INFO, u8(3) + s('CODE001', 9) + s('C15 informational message text', 256))


def generic_hdr():
    return u32(*range(1, 20))


def generic(mt, length=None):
    h = generic_hdr()
    if mt == GENERIC_1:
        p = h + s('GENERIC MESSAGE ONE', 1232)
    elif mt == GENERIC_2:
        p = h + bytes(i & 0xff for i in range(1232))
    elif mt == GENERIC_3:
        p = h + s('GENERIC MESSAGE THREE', 616) + bytes(i & 0xff for i in range(616))
    elif mt == GENERIC_4:
        p = h + s('GENERIC MESSAGE FOUR', 924) + bytes(i & 0xff for i in range(308))
    else:
        p = h + s('GENERIC MESSAGE FIVE', 308) + bytes(i & 0xff for i in range(924))
    assert len(p) == 1308
    return c15(mt, p)


def correlate():
    p = u32(0xc0ffee, 7, 2, 3, 4, 5, 6, 7, 8, 9, 10)
    p += s('optional string parameter eight', 129) + s('optional string parameter nine', 129)
    assert len(p) == 302
    return c15(CORRELATE, p)


def sip_report(kind):
    p = s(kind, 12) + u32(*range(100, 113))
    assert len(p) == 64
    return c15(SIP_REG_SUBS, p)


def sys_alarm():
    p = s('OMM001', 7) + s('MAJ', 5) + s('SET', 4) + s('STA', 5) + s('SYS', 5)
    assert len(p) == 26
    return c15(SYS_ALARM, p)


def tty():
    p = u32(1, 2, 3, 4) + s('TTY0001', 8) + s('LOCATION', 40) + s('TEXT ONE', 40) + \
        s('TEXT TWO', 40) + s('TEXT THREE', 40)
    assert len(p) == 184
    return c15(TTY, p)


def main_capture():
    pk = []
    # Heartbeat
    pk += [hbeat('CLLIABCDE01', 1, 0, 'eth0'), hbeat('', 0, 1, ''), hbeat_long_iface()]
    # 1 CP_STATE_CH
    pk += [cp_state_ch(1, 2)]
    # 2 CP_EVENT: ordinary PMs 0, 5, 77; DIG_CKT_TEST (40) with every trunk
    # PM 0-5 and one out of range; PM out of range
    pk += [cp_event(0, 1, 0), cp_event(5, 2, 0, event=3), cp_event(77, 0, 0)]
    pk += [cp_event(40, 1, t, event=2) for t in range(6)]
    pk += [cp_event(40, 1, 6), cp_event(78, 3, 0)]
    # 3 ISUP
    pk += [isup()]
    # 4 NITN_XLATE equipment variants
    pk += [
        nitnxlate('GWE', 3, user_tid='gw1.example.invalid', host='host.example.invalid', line_id='aaln'),
        nitnxlate('IDE', 5, host='ide.example.invalid', line_id='ln1'),
        nitnxlate('VLIN', 2, tgnum=12, host='call-id-1@example.invalid'),
        nitnxlate('PTRK', 14, tgnum=5, host='call-id-2@example.invalid'),
        nitnxlate('LCE', 15, key=7, host='call-id-3@example.invalid'),
        nitnxlate('RSE', 1),
        nitnxlate('RSC', 1, key=3),
        nitnxlate('HUBE', 1),
        nitnxlate('', 0, site='', subsite=''),
        nitnxlate('XYZ', 0, key=9),
        nitnxlate('XYZ', 0),
    ]
    # 5 SCCP
    pk += [sccp()]
    # 6-15
    pk += [cp_orig(), conn(), ntwk_conn(), mk_brk(), path_find(), path_idle(),
           dest_digits(), twc_rswch(), srce_dest(), route(False), route(True)]
    # 16 INC_GWE, every data type, then task variants
    pk += [inc_gwe(t, f, d, b) for t, f, d, b in inc_gwe_bodies()]
    pk += inc_gwe_extra()
    # 17 OUT_GWE, every data type, then data type 0 with an unknown subtype
    pk += [out_gwe(d, d, b) for d, b in out_gwe_bodies()]
    pk += [out_gwe(99, 0, b'')]
    # 18 OUT_GWE_BC
    pk += [outgwebc()]
    # 19 Q931: direction 0 and 1 handed to Q.931, invalid direction 2, and
    # the length reproducer
    pk += [q931_frame(0, 0x91, 0x92, 13 + len(Q931_SETUP), 13, Q931_SETUP),
           q931_frame(1, 0x93, 0x94, 10 + len(Q931_RELEASE), 10, Q931_RELEASE),
           q931_frame(2, 0x95, 0x96, 10 + len(Q931_RELEASE), 10, Q931_RELEASE)]
    pk += q931_repro()
    # 20-27
    pk += [ama(), qos()]
    pk += [echo_cancel(0, 1, 0x77), echo_cancel(1, 2, 0), echo_cancel(2, 3, 0x78), echo_cancel(3, 0, 0)]
    pk += [tone(t, b) for t, b in tone_bodies()]
    pk += [tone(99, b'')]
    pk += [encap_isup(), tcap(), clli('CLLI0001'), clli(''), clli_long(), c15_info()]
    # 28-36
    pk += [generic(mt) for mt in (GENERIC_1, GENERIC_2, GENERIC_3, GENERIC_4, GENERIC_5)]
    pk += [correlate(), sip_report('REGISTER'), sip_report('SUBSCRIBE'), sys_alarm(), tty()]
    # 28-36 with no payload
    pk += [c15(mt, b'') for mt in range(GENERIC_1, TTY + 1)]
    # Unknown message type
    pk += [c15(37, u32(0))]
    return pk


def malformed_capture():
    pk = []
    # Header size smaller than the header: rejected
    pk += [c15(CP_STATE_CH, u32(1, 2), size=20)]
    # Size larger than the frame
    pk += [c15(CONN, u32(1, 2, 3), size=36 + 53)]
    # Truncated header
    pk += [eth(ETH_C15CH, u32(1, 2, 36))]
    # CP_EVENT shorter than 28 octets: rejected by the subdissector
    pk += [c15(CP_EVENT, u32(1, 2, 3))]
    # Every second level type truncated to 4 octets
    for mt in range(1, 37):
        pk += [c15(mt, u32(0x01020304))]
    for d in range(1, 25):
        pk += [inc_gwe(5, 1, d, b'\x01')]
    for d in range(1, 25):
        pk += [out_gwe(d, d, b'\x01')]
    for t in range(1, 9):
        pk += [tone(t, b'')]
    # ECHO_CANCEL of exactly 31 octets: the Location item runs one past it
    pk += [echo_cancel(0, 0, 0x10, spare=False)]
    # Digit counts larger than their fields (the digits are not shown)
    p = bytearray(ama()[14 + 36:])
    p[11] = 16
    pk += [c15(AMA, bytes(p))]
    pk += [c15(DEST_DIGITS, u32(40) + digits([1] * 32, 32))]
    # Strings without a terminating NUL
    pk += [hbeat('', 0, 0, '')[:14 + 20] + b'NO-NUL-CLLI']
    pk += [c15(CLLI, b'X' * 60)]
    # Heartbeat cut short
    pk += [eth(ETH_C15HB, bytes(30))]
    return pk


def write_pcap(path, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'c15ch-coverage.pcap'), main_capture())
    write_pcap(os.path.join(out, 'c15ch-coverage-malformed.pcap'), malformed_capture())


if __name__ == '__main__':
    main()
