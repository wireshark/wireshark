#!/usr/bin/env python3
# Generates test/captures/wisun_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the Wi-SUN dissector
(packet-wisun.c).

Wi-SUN FAN rides on IEEE 802.15.4: Wi-SUN header IEs (element ID 0x2a, a
sub ID and its content), Wi-SUN payload IEs (group 4, nested IEs in the
short or long format), the Wi-SUN vendor MAC command (OUI 0C:5A:9E) and the
multiplexed IE with the Wi-SUN multiplex ID (security sub ID). The
EAPOL relay is UDP port 10253. Netricity segments are only reachable
through Exported PDU (dissector name wisun.netricity.sc). Every packet
is built here with struct; no captured traffic is used. Frames are
IEEE 802.15.4 without FCS (linktype 230); the secured frames carry
placeholder (opaque) MIC bytes, nothing is encrypted or checked.

Usage: mkwisun.py <output directory>

Writes:
  wisun-coverage.pcapng            every header IE, every payload IE with all
                                   channel plan/function/exclude forms, the
                                   MDR command, the security extension, EDFE
                                   exchanges, EAPOL relay, Netricity segments
                                   and their reassembly
  wisun-coverage-malformed.pcapng  unsupported IEs, invalid channel plans,
                                   reserved bits, truncated IEs
"""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from wlccp_common import udp_frame

P = struct.pack
DLT_ETH, DLT_230, DLT_EXPDU = 1, 230, 252


def pcapng(path, blocks):
    def blk(t, body):
        body += b'\0' * (-len(body) % 4)
        return P('<II', t, len(body) + 12) + body + P('<I', len(body) + 12)
    o = blk(0x0a0d0d0a, P('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    lts = []
    for lt, _ in blocks:
        if lt not in lts:
            lts.append(lt)
            o += blk(1, P('<HHI', lt, 0, 65535))
    ts = 1700000000 * 1000000
    for lt, d in blocks:
        ts += 1000
        o += blk(6, P('<IIIII', lts.index(lt), ts >> 32, ts & 0xffffffff, len(d), len(d)) + d)
    open(path, 'wb').write(o)


# ------------------------------------------------------------ 802.15.4
DATA, CMD = 1, 3
NONE = 0
SHORT, LONG = 2, 3
PAN = 0x1234
A64, B64, C64 = 0x0011223344556677, 0x8899aabbccddeeff, 0x0102030405060708
seqno = [0]


def mac15(ft=DATA, dm=SHORT, sm=SHORT, ies=b'', payload=b'', dst=1, src=2, ver=2, seq=None, sec=None,
          ie=None):
    """a 2015 frame with PAN ID compression for short/short (one PAN ID),
    destination PAN ID only for extended/extended"""
    if seq is None:
        seqno[0] = (seqno[0] + 1) & 0xff
        seq = seqno[0]
    panc = 1 if dm != NONE and sm != NONE and (dm == sm == SHORT or dm != sm) else 0
    if ie is None:
        ie = bool(ies)
    f = ft | (0x08 if sec else 0) | (0x40 if panc else 0) | (0x200 if ie else 0) | (dm << 10) | (ver << 12) | (sm << 14)
    b = P('<HBH', f, seq, PAN)
    b += P('<H', dst) if dm == SHORT else P('<Q', dst)
    b += P('<H', src) if sm == SHORT else P('<Q', src)
    if sec:
        b += sec
    return b + ies + payload


def hie(i, content=b''):
    return P('<H', (i << 7) | len(content)) + content


def pie(gid, content=b''):
    return P('<H', 0x8000 | (gid << 11) | len(content)) + content


HT1, HT2 = hie(0x7e), hie(0x7f)
PT = pie(0xf)
SEC5 = bytes([5]) + P('<I', 1)            # aux header: level 5, key id mode 0, counter 1
MIC = b'\xa5' * 4


def wh(subid, content=b''):
    """Wi-SUN header IE"""
    return hie(0x2a, bytes([subid]) + content)


def wp(*nested):
    """Wi-SUN payload IE holding nested IEs"""
    return pie(4, b''.join(nested))


def hframe(*hies, payload=b'\x10data', **kw):
    return mac15(ies=b''.join(hies) + HT2, payload=payload, **kw)


def pframe(*pies, **kw):
    return mac15(ies=HT1 + wp(*pies) + PT, **kw)


def lng(sub, content):
    return P('<H', 0x8000 | (sub << 11) | len(content)) + content


def sht(sub, content):
    return P('<H', (sub << 8) | len(content)) + content


# ----------------------------------------------------- header IE builders
def utt(t, ufsi=0x010203): return wh(1, bytes([t]) + P('<I', ufsi)[:3])
def bt(slot=7, bio=0x0a0b0c): return wh(2, P('<H', slot) + P('<I', bio)[:3])
def fc(tx, rx): return wh(3, bytes([tx, rx]))
def rsl(v): return wh(4, bytes([v]))
def vh(vid, data=b'vendor'):
    v = bytes([vid]) if vid < 0x80 else bytes([0x80 | (vid >> 7), vid & 0x7f])
    return wh(6, v + data)
def nft(t): return wh(7, bytes([t]))
def lqi(v): return wh(8, bytes([v]))
def ea(eui=0x1122334455667788): return wh(9, P('>Q', eui))
def lutt(t, usn=0x1234, uio=0x050607): return wh(0x0a, bytes([t]) + P('<H', usn) + P('<I', uio)[:3])
def lbt(slot=9, bio=0x010203): return wh(0x0b, P('<H', slot) + P('<I', bio)[:3])
def nr(role, lbats=False, drift=10, acc=50, imin=1000, imax=2000, reserved=0):
    b = role | (0x80 if lbats else 0) | reserved
    c = bytes([b, drift, acc])
    if role == 2:
        c += P('<I', imin)[:3] + P('<I', imax)[:3]
    return wh(0x0c, c)
def lus(): return wh(0x0d, P('<I', 5000)[:3] + b'\x04')
def flus(): return wh(0x0e, b'\x0a\x03')
def lbs(): return wh(0x0f, P('<I', 6000)[:3] + P('<H', 77) + b'\x05\x08')
def lnd(): return wh(0x10, b'\x20' + P('<I', 300)[:3] + b'\x04\x08' + P('<H', 3))
def lto(): return wh(0x11, P('<I', 11)[:3] + P('<I', 12)[:3])
def panid(): return wh(0x12, P('<H', 0xface))
def rt(): return wh(0x1d, P('<HH', 500, 600))
def lbc(): return wh(0xc0, P('<I', 7000)[:3] + b'\x09')


# ---------------------------------------------------- payload IE builders
def sched(plan, func, excl, mask=None):
    """schedule: channel control + plan fields + function fields + exclude fields"""
    c = bytes([plan | (func << 3) | (excl << 6)])
    if plan == 0:
        c += b'\x01\x02'                       # regulatory domain, operating class
    elif plan == 1:
        c += P('<I', (3 << 24) | 902200) + P('<H', 129)
    elif plan == 2:
        c += b'\x01\x20'                       # regulatory domain, channel plan ID
    if func == 0:
        c += P('<H', 5)
    elif func == 3:
        c += bytes([3, 4, 5, 6])
    if excl == 1:
        c += bytes([2]) + P('<HHHH', 10, 12, 20, 22)
    elif excl == 2:
        c += mask if mask is not None else b'\xff\x0f\x00\x01'
    return c


def us(plan=0, func=0, excl=0, mask=None):
    return lng(1, bytes([15, 10, 50]) + sched(plan, func, excl, mask))


def bs(plan=0, func=0, excl=0):
    return lng(2, P('<I', 1000000) + P('<H', 0x55) + bytes([15, 10, 50]) + sched(plan, func, excl))


def vp(vid, data=b'vendor payload'):
    v = bytes([vid]) if vid < 0x80 else bytes([0x80 | (vid >> 7), vid & 0x7f])
    return lng(3, v + data)


def lcp(plan=0, func=0, excl=0):
    return lng(4, b'\x05' + sched(plan, func, excl))


def pan_ie(size=100, cost=300, flags=0x0b): return sht(4, P('<HH', size, cost) + bytes([flags]))
def netname(n=b'WiSUN-Net'): return sht(5, n)
def panver(v=0x1234): return sht(6, P('<H', v))
def gtkhash(): return sht(7, bytes(range(32)))
def pom(modes, mdr=0):
    return sht(8, bytes([len(modes) | (0x10 if mdr else 0)]) + bytes(modes))
def lfnver(v=0x2345): return sht(0x40, P('<H', v))
def lgtkhash(ctl=0x07, n=None):
    n = bin(ctl & 7).count('1') if n is None else n
    return sht(0x41, bytes([ctl]) + bytes(range(8 * n)))
def lbats(): return sht(9, b'\x02' + P('<H', 300))
def jm(*metrics): return sht(0x0a, b'\x01' + b''.join(metrics))
def plf(v=75): return bytes([0x41, v])         # id 1, length 1 (len code 1)


# ------------------------------------------------------------ other pieces
def mpx(tid, mux, rest):
    return pie(3, bytes([tid << 3]) + P('<H', mux) + rest)


def cmd_frame(*payload):
    return mac15(ft=CMD, payload=b''.join(payload), ies=b'', ie=False)


OUI = bytes([0x9e, 0x5a, 0x0c])


def eapol_eap(code, ident=1):
    return bytes([2, 0]) + P('>H', 5) + bytes([code, ident]) + P('>H', 5) + b'\x01'


def eapol_key(info):
    body = bytes([2]) + P('>HH', info, 16) + P('>Q', 1) + bytes(32) + bytes(16) + bytes(8) + bytes(8) + bytes(16) + P('>H', 0)
    return bytes([2, 3]) + P('>H', len(body)) + body


def relay(eapol, kmp=1, sup=0x0102030405060708):
    return udp_frame(P('>Q', sup) + bytes([kmp]) + eapol, 10253, 10253)


def exp_pdu(payload, name='wisun.netricity.sc'):
    n = name.encode()
    pad = b'\0' * (-len(n) % 4)
    return P('>HH', 12, len(n) + len(pad)) + n + pad + P('>HH', 0, 0) + payload


def nmhr(seq, sec=False, first=True):
    f = 0x8841 | (0x08 if sec else 0)
    h = P('<HBHHH', f, seq, PAN, 1, 2)
    if sec and first:
        h += SEC5
    return h


def seg(last, count, length, seq, data, sec=False, tone=0, cca=0, contention=0):
    flags = (1 if last else 0) | (tone << 4) | (cca << 2) | (contention << 1) | 0x00
    return bytes([flags]) + P('>H', (count << 10) | length) + nmhr(seq, sec, count == 0) + data


def netricity_message(seq, chunks, order=None, sec=False):
    """segments of one message: the first holds the start of the MAC
    payload; returned in the given order"""
    segs = []
    for i, c in enumerate(chunks):
        segs.append(seg(i == len(chunks) - 1, i, len(c), seq, c, sec))
    order = range(len(segs)) if order is None else order
    return [segs[i] for i in order]


# ------------------------------------------------------------------ main
def main_frames():
    F = []
    f = lambda fr: F.append((DLT_230, fr))
    x = lambda p: F.append((DLT_EXPDU, exp_pdu(p)))
    # --- header IEs
    for t in (0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 15, 0x20):
        f(hframe(utt(t, 0x010000 + t)))
    for t in (9, 10, 11, 12, 13, 0x30):
        f(hframe(lutt(t, 0x1000 + t)))
    f(hframe(bt(), lbt()))
    f(hframe(rsl(0), rsl(0xff), rsl(0x7f), rsl(0xae)))
    f(hframe(vh(5), vh(0x85), vh(0x1234 & 0x3fff, b''), vh(0)))
    f(hframe(nft(0), nft(1), nft(0x10), nft(0xff)))
    f(hframe(lqi(0), lqi(1), lqi(128), lqi(254), lqi(255)))
    f(hframe(ea()))
    f(hframe(nr(0), nr(1, lbats=True), nr(2, imin=1000, imax=4000), nr(2, lbats=True, drift=255, acc=255),
              nr(3), nr(7, lbats=True)))
    f(hframe(lus(), flus(), lbs(), lnd(), lto(), panid(), rt(), lbc()))
    f(hframe(utt(4), bt(), rsl(0x60), ea(), lqi(100), nft(2), lutt(13), lbt(), nr(1), lus(), flus(), lbs(), lnd(),
             lto(), panid(), rt(), lbc(), vh(9)))
    f(mac15(ies=b''.join((utt(0), bt())) + HT1 + wp(pan_ie(), netname()) + PT))        # header and payload IEs
    # --- EDFE (extended addressing; the exchange state is tracked per address)
    ex = lambda src, dst, *h: f(hframe(*h, dm=LONG, sm=LONG, dst=dst, src=src))
    ex(A64, B64, utt(4), fc(3, 2))             # initial frame (UTT first: the Info stays EDFE)
    ex(B64, A64, fc(2, 1), utt(4))             # response (FC first, then UTT)
    ex(A64, B64, fc(1, 1))                     # second response in the same exchange
    ex(B64, A64, fc(1, 0))                     # another
    ex(A64, B64, utt(5), fc(0, 0))             # final frame
    ex(A64, B64, fc(2, 3), utt(4))             # new exchange after a final frame
    ex(A64, B64, fc(2, 3))                     # initial frame repeated before any response
    ex(B64, A64, fc(1, 1))                     # response
    ex(A64, B64, fc(0, 0))                     # final
    ex(C64, A64, fc(1, 1))                     # a frame to an address with an old exchange
    ex(C64, B64, fc(0, 0), utt(4))
    f(hframe(fc(1, 2), dm=LONG, sm=SHORT, dst=B64, src=3))        # extended destination, short source
    f(hframe(fc(1, 2)))                                           # short addresses
    f(hframe(fc(1, 2), dm=SHORT, sm=LONG, dst=7, src=A64))
    # --- payload IEs: unicast schedule, every channel plan x function x exclude form
    for plan in (0, 1, 2):
        for func in (0, 1, 2, 3):
            f(pframe(*[us(plan, func, e) for e in (0, 1, 2, 3)]))
    f(pframe(us(0, 0, 2, mask=bytes(i % 256 for i in range(300)))))                       # exclude mask over 255 octets
    f(pframe(us(1, 2, 2, mask=bytes([0xff] * 40)), us(0, 0, 2, mask=bytes(255))))
    f(pframe(*[bs(p, fn, e) for p, fn, e in ((0, 0, 0), (1, 1, 1), (2, 3, 2), (0, 2, 0))]))
    f(pframe(*[lcp(p, fn, e) for p, fn, e in ((0, 0, 0), (1, 3, 1), (2, 2, 2), (0, 1, 3))]))
    f(pframe(vp(0x12), vp(0x1234 & 0x3fff), vp(0x7f, b''), vp(0x80 | 0x05 << 7, b'x')))
    f(pframe(pan_ie(), pan_ie(0xffff, 0xffff, 0x00), pan_ie(1, 0, 0xf8), pan_ie(5, 6, 0x54),
             netname(), netname(b''), netname(b'A' * 32), panver(), gtkhash()))
    f(pframe(pom([0x01]), pom([0x02, 0x13, 0x24, 0x35, 0x46], mdr=1), pom([]), pom([0x00, 0x1f, 0x58])))
    f(pframe(lfnver(), lgtkhash(0x00), lgtkhash(0x01), lgtkhash(0x02), lgtkhash(0x04), lgtkhash(0x07),
             lgtkhash(0x0f), lgtkhash(0x15), lbats()))
    f(pframe(jm(plf(), plf(0)), jm(), jm(plf(10))))
    f(pframe(us(), bs(), pan_ie(), netname(), panver(), gtkhash(), lfnver(), lbats(), vp(3), lcp()))
    f(pframe(us(), PT[:0], pan_ie(), payload=b'\x10after'))                           # payload after the IEs
    # --- vendor MAC command (MDR) and other sub commands
    for typ in range(6):
        f(cmd_frame(b'\x24', OUI, b'\x03', bytes([(typ << 4) | (typ + 1)])))
    f(cmd_frame(b'\x24', OUI, b'\x03', bytes([0x0f])))
    f(cmd_frame(b'\x24', OUI, b'\x03', bytes([0x2f])))
    f(cmd_frame(b'\x24', OUI, b'\x09', b'unknown'))
    f(cmd_frame(b'\x24', bytes([1, 2, 3]), b'\x03', b'x'))                           # other OUI
    # --- security extension through the multiplexed IE
    for err in (1, 2, 3, 4, 6, 9):
        f(mac15(ies=HT1 + mpx(4, 2, b'\x02' + bytes([1, err]) + bytes(range(8))) + PT))
    f(mac15(ies=HT1 + mpx(4, 2, b'\x02' + bytes([1, 5])) + PT))
    f(mac15(ies=HT1 + mpx(4, 2, b'\x02' + bytes([0x44, 1]) + b'xyz') + PT))
    # --- EAPOL relay: EAP request/response, EAPOL-Key with and without the ACK bit
    for fr in (relay(eapol_eap(1)), relay(eapol_eap(2)), relay(eapol_key(0x008a), 6), relay(eapol_key(0x010a), 6),
               relay(eapol_key(0x138a), 7)):
        F.append((DLT_ETH, fr))
    # --- Netricity segmentation: Exported PDU, then reassembly
    body = b'\x10' + bytes(range(60))
    for s_ in netricity_message(1, [body[:20], body[20:40], body[40:]]):
        x(s_)
    for s_ in netricity_message(2, [body[:30], body[30:]], order=(1, 0)):             # last segment first
        x(s_)
    for s_ in netricity_message(3, [body[:16], body[16:32], body[32:48], body[48:]], order=(0, 2, 1, 3)):
        x(s_)
    x(seg(1, 0, len(body), 4, body, tone=1, cca=2, contention=1))                      # unsegmented, other flags
    x(seg(1, 0, len(body), 5, b'\x10' + bytes(2), cca=3))                              # short payload
    for s_ in netricity_message(6, [body[:25], body[25:]], sec=True):                  # security bit, aux header on the first only
        x(s_)
    x(seg(0, 0, 3, 8, b'\x10ab'))                                                      # a segment whose message never completes
    return F


def malformed_frames():
    F = []
    f = lambda fr: F.append((DLT_230, fr))
    f(hframe(wh(0x05, b'\x01\x02')))                                  # MHDS IE: unsupported sub ID
    f(hframe(wh(0x70, b'\x01\x02\x03')))                              # unknown sub ID
    f(hframe(nr(1, reserved=0x08), nr(2, reserved=0x70)))             # reserved bits not zero
    f(pframe(lng(1, bytes([15, 10, 50, 0x03]))))                      # invalid channel plan 3
    f(pframe(lng(1, bytes([15, 10, 50, 0x07]))))                      # invalid channel plan 7
    f(pframe(lng(1, bytes([15, 10, 50, 0x01]) + P('<I', 0x10000000 | 902200) + P('<H', 129) + P('<H', 5))))   # reserved bits of the explicit plan
    f(pframe(lng(7, b'\x01\x02\x03'), sht(0x33, b'\x01\x02'), sht(0x7f, b'')))   # unsupported payload sub IEs
    f(pframe(jm(bytes([0x02, 1]), bytes([0x83, 1, 2, 3, 4]))))        # unsupported metric IDs
    f(pframe(jm(bytes([0x03])), jm(bytes([0x42, 1, 2])), jm(bytes([0x82, 1, 2])), jm(bytes([0xc5, 1, 2, 3, 4]))))
    f(hframe(wh(0x01, b'\x00')))                                      # UTT-IE cut short
    f(hframe(wh(0x03, b'\x01')))                                      # FC-IE cut short
    f(hframe(wh(0x0c, b'\x02\x01\x01\x01')))                          # LFN node role without the intervals
    f(hframe(wh(0x06, b'\x85')))                                      # vendor ID continues past the IE
    f(hframe(wh(0x06, b'\x80\x05' + b'data')))                       # non-minimal vendor ID: the length is taken from its value (observation 2)
    f(pframe(lng(3, b'\x80\x05' + b'data')))                          # the same in a vendor payload IE
    f(pframe(lng(1, bytes([15, 10]))))                                # US-IE cut short
    f(pframe(sht(0x41, bytes([0x07]) + bytes(10))))                   # LGTK hash too short
    f(pframe(sht(7, bytes(10))))                                      # GTK hash too short
    f(pframe(sht(8, bytes([5, 1]))))                                  # PHY modes beyond the IE
    f(pframe(lng(1, bytes([15, 10, 50, 0x40, 1, 2]) + bytes([9]))))   # 9 exclude ranges, none present
    f(pframe(lng(1, bytes([15, 10, 50, 0x18, 1, 2, 200]))))           # 200 hopping channels
    f(mac15(ies=HT1 + mpx(4, 2, b'\x02' + bytes([3])) + PT))          # security function without data
    f(cmd_frame(b'\x24', OUI))                                        # vendor command without a sub command
    F.append((DLT_ETH, udp_frame(b'\x01' * 6, 10253, 10253)))         # EAPOL relay cut short
    F.append((DLT_EXPDU, exp_pdu(b'\x01\x00')))                       # Netricity segment cut short
    F.append((DLT_EXPDU, exp_pdu(seg(1, 63, 1023, 9, b'abc'))))       # length beyond the data
    F.append((DLT_EXPDU, exp_pdu(seg(0, 0, 1000, 10, b'abc'))))
    F.append((DLT_EXPDU, exp_pdu(bytes([1]) + P('>H', 5) + b'\x00\x00')))   # no valid MHR
    return F


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    pcapng(os.path.join(out, 'wisun-coverage.pcapng'), main_frames())
    pcapng(os.path.join(out, 'wisun-coverage-malformed.pcapng'), malformed_frames())


if __name__ == '__main__':
    main()
