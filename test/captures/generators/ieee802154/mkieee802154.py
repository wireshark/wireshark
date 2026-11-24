#!/usr/bin/env python3
# Generates test/captures/ieee802154_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the IEEE 802.15.4 coverage captures (synthetic).  Usage: mkieee802154.py <outdir>

ieee802154-coverage.pcapng            main capture: DLT 195 (with FCS), 230 (no FCS), 283 (TAP),
                                      215 (non-ASK PHY), Linux SLL and Ethernet (ethertype 0x809a)
ieee802154-coverage-malformed.pcapng  malformed frames (not added to the tree)
ieee802154-coverage-fcs32.pcapng      frames with a 32 bit FCS and the CC24xx trailer (preferences)

The security code (decryption, MIC checks) is left uncovered on purpose: secured frames
carry placeholder MIC bytes, the key tables are never filled.
"""
import sys
import os
import struct
import random
import zlib

out = sys.argv[1] if len(sys.argv) > 1 else '.'
rng = random.Random(0x802154)

DLT_195, DLT_230, DLT_283, DLT_215, DLT_SLL, DLT_ETH = 195, 230, 283, 215, 113, 1


# ------------------------------------------------------------------ pcapng
def pcapng(path, blocks):
    """blocks: list of (linktype, bytes)"""
    def blk(t, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    o = blk(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    lts = []
    for blk_ in blocks:
        lt = blk_[0]
        if lt not in lts:
            lts.append(lt)
            o += blk(1, struct.pack('<HHI', lt, 0, 65535))
    ts = 1700000000 * 1000000
    for blk_ in blocks:
        lt, d = blk_[0], blk_[1]
        ts += blk_[2] if len(blk_) > 2 else 1000
        o += blk(6, struct.pack('<IIIII', lts.index(lt), ts >> 32, ts & 0xffffffff, len(d), len(d)) + d)
    open(path, 'wb').write(o)


def crc16(d):
    c = 0
    for b in d:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0x8408 if c & 1 else c >> 1
    return c


def fcs16(d):
    return d + struct.pack('<H', crc16(d))


def fcs32(d):
    return d + struct.pack('<I', zlib.crc32(d) & 0xffffffff)


def cc24xx(d, ok=True, rssi=0xd0, lqi=0x2a):
    return d + bytes([rssi, (0x80 if ok else 0) | lqi])


# ---------------------------------------------------------------- MAC frames
BEACON, DATA, ACK, CMD, MP, FRAG, EXT = 0, 1, 2, 3, 5, 6, 7
NONE, RSV, SHORT, LONG = 0, 1, 2, 3
V03, V06, V15 = 0, 1, 2
PAN = 0x1234
DST16, SRC16 = 0x0001, 0x0002
DST64, SRC64 = 0x0011223344556677, 0x8899aabbccddeeff


def pan_rule(ver, ft, dm, sm, panc):
    """(dst_pan_present, src_pan_present) like ieee802154_dissect_header, or None if invalid"""
    if ft == MP:
        return None
    if ver in (V03, V06):
        if dm != NONE and sm != NONE:
            return (True, panc != 1)
        if panc == 1:
            return None
        if dm != NONE and sm == NONE:
            return (True, False)
        if dm == NONE and sm != NONE:
            return (False, True)
        return (False, False)
    if ver == V15:
        if ft in (BEACON, DATA, ACK, CMD):
            t = (dm, sm, panc)
            if dm == NONE and sm == NONE:
                return (False, False) if panc == 0 else (True, False)
            if dm != NONE and sm == NONE:
                return (True, False) if panc == 0 else (False, False)
            if dm == NONE and sm != NONE:
                return (False, True) if panc == 0 else (False, False)
            if dm == LONG and sm == LONG:
                return (True, False) if panc == 0 else (False, False)
            if dm == SHORT and sm == SHORT:
                return (True, True) if panc == 0 else (True, False)
            return (True, True) if panc == 0 else (True, False)   # mixed short/extended
        return (False, False)
    return None


def aux(level=5, kid=0, counter=1, keysrc=b'', keyidx=1, fcsup=False, asn=False, ver=V06):
    c = level | (kid << 3)
    if ver == V15:
        c |= (0x20 if fcsup else 0) | (0x40 if asn else 0)
    b = bytes([c])
    if not (fcsup and ver == V15):
        b += struct.pack('<I', counter)
    if kid != 0:
        b += keysrc
        b += bytes([keyidx])
    return b


def mic_len(level):
    return (0x2 << (level & 3)) & ~3


def mac(ft, ver=V06, dm=NONE, sm=NONE, seq=1, panc=0, sec=None, pend=0, ackreq=0, ie=False, seqsup=False,
        payload=b'', dpan=PAN, span=PAN, dst=None, src=None, ies=b'', force=False, fcf_extra=0, mic=True, mp=None, raw=False):
    """build a MAC frame (no FCS).  sec: dict for aux()."""
    if ft == MP:
        return mpframe(mp or {}, payload)
    if ft == DATA and payload and not raw:
        payload = b'\x10' + payload          # a dispatch that 6LoWPAN (NALP) and LwMesh leave alone
    rule = pan_rule(ver, ft, dm, sm, panc)
    if rule is None and not force:
        raise ValueError('invalid combination %r' % ((ver, ft, dm, sm, panc),))
    dp, sp = rule if rule else (False, False)
    f = ft | (0x08 if sec is not None else 0) | (0x10 if pend else 0) | (0x20 if ackreq else 0) | (0x40 if panc else 0) \
        | (0x100 if seqsup else 0) | (0x200 if ie else 0) | (dm << 10) | (ver << 12) | (sm << 14) | fcf_extra
    b = struct.pack('<H', f)
    if not seqsup:
        b += bytes([seq & 0xff])
    if dp:
        b += struct.pack('<H', dpan)
    if dm == SHORT:
        b += struct.pack('<H', DST16 if dst is None else dst)
    elif dm == LONG:
        b += struct.pack('<Q', DST64 if dst is None else dst)
    if sp:
        b += struct.pack('<H', span)
    if sm == SHORT:
        b += struct.pack('<H', SRC16 if src is None else src)
    elif sm == LONG:
        b += struct.pack('<Q', SRC64 if src is None else src)
    if sec is not None and (ver != V03):
        b += aux(ver=ver, **sec)
    b += ies
    b += payload
    if sec is not None and mic:
        lvl = sec.get('level', 5) if ver != V03 else 0
        b += b'\xa5' * mic_len(lvl)
    return b


def mpframe(mp, payload):
    """multipurpose frame: mp = dict(long, dm, sm, panid, sec, seqsup, pend, ver, ackreq, ie, seq, dpan, span, ies)"""
    lng = mp.get('long', 1)
    dm, sm = mp.get('dm', NONE), mp.get('sm', NONE)
    f = MP | (lng << 3) | (dm << 4) | (sm << 6)
    if lng:
        f |= (mp.get('panid', 1) << 8) | (mp.get('secen', 0) << 9) | (mp.get('seqsup', 0) << 10) | (mp.get('pend', 0) << 11) \
            | (mp.get('ver', 0) << 12) | (mp.get('ackreq', 0) << 14) | (mp.get('ie', 0) << 15)
        b = struct.pack('<H', f)
    else:
        b = bytes([f])
    if not mp.get('seqsup', 0) or not lng:
        b += bytes([mp.get('seq', 7)])
    if lng and mp.get('panid', 1):
        b += struct.pack('<H', mp.get('dpan', PAN))
    if dm == SHORT:
        b += struct.pack('<H', DST16)
    elif dm == LONG:
        b += struct.pack('<Q', DST64)
    if sm == SHORT:
        b += struct.pack('<H', SRC16)
    elif sm == LONG:
        b += struct.pack('<Q', SRC64)
    if lng and mp.get('secen'):
        b += mp['sec']
    b += mp.get('ies', b'')
    return b + payload


# --------------------------------------------------------------- IEs
def hie(i, content=b''):
    return struct.pack('<H', (i << 7) | len(content)) + content


def pie(gid, content=b''):
    return struct.pack('<H', 0x8000 | (gid << 11) | len(content)) + content


def psie_short(i, content=b''):
    return struct.pack('<H', (i << 8) | len(content)) + content


def psie_long(i, content=b''):
    return struct.pack('<H', 0x8000 | (i << 11) | len(content)) + content


HT1, HT2 = hie(0x7e), hie(0x7f)
PT = pie(0xf)

main = []        # (linktype, bytes)
bad = []
f32 = []


def add(lt, frame, fcs=True, lst=None):
    if lt == DLT_195 and fcs:
        frame = fcs16(frame)
    (main if lst is None else lst).append((lt, frame))


def addbad195(frame):
    bad.append((DLT_195, fcs16(frame)))


def add195(frame, **kw):
    add(DLT_195, frame, **kw)


def add230(frame):
    add(DLT_230, frame, fcs=False)


RNDB = lambda n: bytes(rng.randrange(256) for _ in range(n))

# ============================================================= 1. FCF matrix
marks = {}
marks['fcf'] = len(main) + 1
for ver in (V03, V06, V15):
    for ft in (BEACON, DATA, ACK, CMD):
        for dm in (NONE, SHORT, LONG):
            for sm in (NONE, SHORT, LONG):
                for panc in (0, 1):
                    if pan_rule(ver, ft, dm, sm, panc) is None:
                        continue
                    pl = b''
                    if ft == BEACON:
                        pl = struct.pack('<H', 0xcfff) + b'\x00' + b'\x00'
                        pl += b''
                    elif ft == DATA:
                        pl = b'data' + bytes([ft, dm, sm]) if dm != NONE else b''
                    elif ft == CMD:
                        pl = b'\x04' if sm != NONE else b'\x07'     # data request / beacon request
                    if ver == V15 and ft == BEACON:
                        pl = b''
                    kw = {}
                    if ft == CMD and ver == V15 and sm == NONE:
                        continue
                    if ft == CMD and sm == NONE:
                        if dm != SHORT:
                            continue
                        kw = dict(dst=0xffff, dpan=0xffff)
                    try:
                        fr = mac(ft, ver, dm, sm, seq=rng.randrange(256), panc=panc, payload=pl,
                                 ackreq=rng.choice([0, 1]), pend=rng.choice([0, 1]), **kw)
                    except ValueError:
                        continue
                    add195(fr) if (ver + ft + dm + sm) % 2 else add230(fr)
# sequence number suppression (2015), IE present with termination
for dm, sm in ((SHORT, SHORT), (LONG, LONG), (NONE, SHORT), (SHORT, NONE), (NONE, NONE)):
    add195(mac(DATA, V15, dm, sm, seqsup=True, panc=1 if dm == sm == SHORT else 0, payload=b'noseq'))
    add195(mac(ACK, V15, dm, sm, seqsup=True, panc=0, ie=True, ies=HT2))
# Frames in the other link layers
add(DLT_195, mac(DATA, V06, SHORT, SHORT, payload=b'\x00\x01\x02'))
# frame pending, ack request, all frame versions in one ack
for v in (V03, V06, V15):
    add195(mac(ACK, v, NONE, NONE, seq=9, ackreq=0, pend=1))
marks['fcf_end'] = len(main)

# ============================================================= 2. Beacons
marks['beacon'] = len(main) + 1
sf = lambda bo, so, fcs_, pan_coord, assoc, battery=0: struct.pack('<H', bo | (so << 4) | (fcs_ << 8) | (battery << 12) | (pan_coord << 14) | (assoc << 15))
for gts in (0, 1, 2, 7):
    for p16, p64 in ((0, 0), (1, 0), (0, 1), (2, 3), (7, 7)):
        pl = sf(15, 15, 15, 1, 1)
        spec = gts | (0x80 if gts % 2 else 0)
        pl += bytes([spec])
        if gts:
            pl += bytes([rng.randrange(128)])
            for i in range(gts):
                pl += struct.pack('<HB', 0x1000 + i, (i + 1) | ((gts - i) << 4))
        pl += bytes([p16 | (p64 << 4)])
        pl += b''.join(struct.pack('<H', 0x3000 + i) for i in range(p16))
        pl += b''.join(struct.pack('<Q', 0x0123456789abcd00 + i) for i in range(p64))
        add195(mac(BEACON, V06, NONE, SHORT, panc=0, payload=pl))
        add230(mac(BEACON, V03, NONE, LONG, panc=0, payload=pl))
# beacon superframe variants
for bo, so, f_, pc, a_, bat in ((0, 0, 0, 0, 0, 0), (6, 3, 12, 1, 1, 1), (15, 15, 15, 0, 1, 1), (1, 1, 1, 1, 0, 0)):
    add195(mac(BEACON, V06, NONE, SHORT, payload=sf(bo, so, f_, pc, a_, bat) + b'\x00\x00'))
for pl_ in (b'\x00', b'\x01\x02\x03', bytes(range(16)), b'beaconpayload'):
    addbad195(mac(BEACON, V06, NONE, SHORT, payload=sf(15, 15, 15, 1, 1) + b'\x00\x00' + pl_))
# enhanced beacons (2015): header IEs, payload IEs
marks['eb'] = len(main) + 1
add195(mac(BEACON, V15, NONE, SHORT, panc=0, ie=True, ies=hie(0x1e, struct.pack('<H', 0x0123)) + HT1 +
           pie(1, psie_short(0x1a, bytes([1, 2, 3, 4, 5, 6])) +
               psie_short(0x1b, bytes([1, 0, 0x65, 0, 1, 1, 0, 0, 0, 0, 0, 0x01]) ) +
               psie_short(0x1c, bytes([0])) + psie_long(0x9, bytes([1]))) + PT, payload=b''))
add195(mac(BEACON, V15, NONE, LONG, panc=0, ie=True, ies=HT1 + pie(1, psie_short(0x1e, bytes([0x01]))) + PT))
for fl in (0x00, 0x02, 0x04, 0x06, 0x08, 0x10, 0x18, 0x1e, 0x0f, 0x1f):
    nl = (fl >> 3) & 3
    body = bytes([fl]) + (b'\x40' if fl & 2 else b'') + (b'\x80' if fl & 4 else b'') + bytes(range(1, nl + 1))
    add195(mac(BEACON, V15, NONE, SHORT, panc=0, ie=True, ies=HT1 + pie(1, psie_short(0x1e, body)) + PT))
# TSCH slotframe & link, timeslot variants, hopping, unknown sub IEs
for nsf, nl in ((0, 0), (1, 0), (1, 1), (2, 3), (3, 2)):
    body = bytes([nsf])
    for s in range(nsf):
        body += struct.pack('<BHB', s + 1, 101 + s, nl)
        for l in range(nl):
            body += struct.pack('<HHB', l, l + 1, 0x1f if l % 2 else 0x03)
    add195(mac(BEACON, V15, NONE, SHORT, panc=0, ie=True, ies=HT1 + pie(1, psie_short(0x1b, body)) + PT))
for ts in (bytes([0]), bytes([1]) + bytes(range(20)) + struct.pack('<HH', 0x1000, 0x2000),
           bytes([1]) + bytes(range(20)) + bytes(6) + bytes([1, 2, 3, 4, 5, 6])[:6]):
    add195(mac(BEACON, V15, NONE, SHORT, panc=0, ie=True, ies=HT1 + pie(1, psie_short(0x1c, ts)) + PT))
add195(mac(BEACON, V15, NONE, SHORT, panc=0, ie=True, ies=HT1 + pie(1, psie_long(0x9, bytes([3]) + b'hopseq')) + PT))
add195(mac(BEACON, V15, NONE, SHORT, panc=0, ie=True, ies=HT1 + pie(1, psie_short(0x22, b'sunx') + psie_long(0xa, b'\x01\x02')) + PT))
add195(mac(BEACON, V15, NONE, SHORT, panc=0, ie=True, ies=HT1 + pie(1, psie_short(0x1a, bytes(6)) + psie_short(0x1c, b'\x00')) + PT))
marks['ies'] = len(main) + 1

# ============================================================= 3. Header IEs
def one_hie(content_ies, ft=DATA, ver=V15, pl=b'x', term=True):
    return mac(ft, ver, SHORT, SHORT, ie=True, ies=content_ies + (HT2 if term else b''), payload=pl)

add195(one_hie(hie(0x1e, struct.pack('<H', 0x0123))))
add195(one_hie(hie(0x1e, struct.pack('<H', 0x8123))))
add195(one_hie(hie(0x1e, struct.pack('<H', 0x7123))))          # reserved bits: expert info (warning)
add195(one_hie(hie(0x1a, struct.pack('<HH', 10, 20))))
add195(one_hie(hie(0x1a, struct.pack('<HHH', 10, 20, 30))))
add195(one_hie(hie(0x1d, struct.pack('<H', 5))))
add195(one_hie(hie(0x1d, struct.pack('<HH', 5, 6))))
add195(one_hie(hie(0x29, struct.pack('<I', 1700000000))))
add195(one_hie(hie(0x00, bytes.fromhex('9bb8ea') + b'thread')))      # Thread OUI
add195(one_hie(hie(0x00, bytes.fromhex('1b194a') + b'zigbee')))
add195(one_hie(hie(0x00, bytes.fromhex('112233') + b'other')))
add195(one_hie(hie(0x00, bytes.fromhex('9bb8ea')), ft=ACK, pl=b''))
add195(one_hie(hie(0x21, b'\x01\x02\x03')))                       # unsupported ID (warning)
addbad195(one_hie(hie(0x2a, b'')))
add195(one_hie(hie(0x1e, struct.pack('<H', 1) + b'ex')))        # extra content (warning)
add195(one_hie(hie(0x1a, struct.pack('<HHH', 10, 20, 30) + b'zz')))
add195(mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1 + PT, payload=b'x'))
add195(mac(DATA, V15, SHORT, SHORT, ie=True, ies=hie(0x1e, struct.pack('<H', 1)) + HT2, payload=b'x'))
addbad195(one_hie(struct.pack('<H', 0x8000 | (0x20 << 7) | 2) + b'ab'))        # payload IE type in the header (warning)
add195(one_hie(hie(0x1e, struct.pack('<H', 1)) + hie(0x1a, struct.pack('<HH', 1, 2)) + hie(0x1d, struct.pack('<H', 3)) + hie(0x29, struct.pack('<I', 5))))
add195(mac(ACK, V15, NONE, NONE, seqsup=False, ie=True, ies=hie(0x1e, struct.pack('<H', 0x0100)) + HT2))
add195(mac(ACK, V15, SHORT, SHORT, ie=True, ies=hie(0x1d, struct.pack('<HH', 7, 9)) + HT2, panc=1))
# MP with IEs / wake-up frames
# ============================================================= 4. Payload IEs
def pie_frame(p, ver=V15, ft=DATA, hdr=HT1, pl=b''):
    return mac(ft, ver, SHORT, SHORT, ie=True, ies=hdr + p, payload=pl)

add195(pie_frame(PT, pl=b'after'))
add195(pie_frame(pie(0, b'esdu') + PT))
add195(pie_frame(pie(0x8, b'unk') + PT))
add195(pie_frame(pie(2, bytes.fromhex('1b194a') + b'zb') + PT))
add195(pie_frame(pie(2, bytes.fromhex('112233') + b'other') + PT))
add195(pie_frame(pie(4, b'wisun') + PT))
addbad195(pie_frame(pie(1, psie_short(0x1a, bytes(6))) + b'', pl=b'abc'))
add195(pie_frame(pie(1, b'') + PT))
addbad195(pie_frame(pie(0xe, b'abc'), pl=b'abc'))
# MLME nested IEs in all forms
add195(pie_frame(pie(1, psie_short(0x1a, struct.pack('<Q', 1)[:5] + b'\x03') + psie_short(0x1b, b'\x00') +
                     psie_short(0x1c, b'\x00') + psie_short(0x1e, b'\x00') + psie_long(0x9, b'\x01')) + PT))
add195(pie_frame(pie(1, psie_short(0x7f, b'abcd') + psie_long(0xf, b'\x01\x02\x03')) + PT))      # unsupported nested IEs
add195(pie_frame(pie(1, psie_short(0x1d, bytes(2)) + psie_short(0x1f, bytes(4)) + psie_short(0x20, bytes(6))) + PT))
add195(pie_frame(pie(1, psie_long(0x9, b'\x01')) + PT))
addbad195(pie_frame(pie(1, psie_long(0x9, b'')) + PT))
add195(pie_frame(pie(1, psie_long(0x9, b'\x01a')) + PT))
# IETF 6top
def sixtop(typ, code, rest=b'', sfid=1, seq=2, ver=0):
    return pie(5, bytes([0xc9, ver | (typ << 4), code, sfid, seq]) + rest)

for typ, code, rest in (
        (0, 1, struct.pack('<HBB', 0, 3, 1) + b'\x00\x00\x01\x00' + b'\x01\x00\x02\x00'),    # request add
        (0, 2, struct.pack('<HBB', 0, 3, 0) + b''),    # delete
        (0, 3, struct.pack('<HBB', 0, 3, 1) + b'\x00\x00\x01\x00' + b'\x01\x00\x02\x00' + b'\x02\x00\x03\x00'),
        (0, 4, struct.pack('<HB', 0, 3)),               # count
        (0, 5, struct.pack('<HBBHH', 0, 3, 0, 0, 5)),   # list
        (0, 6, b'\x01\x02'), (0, 6, b'\x01'), (0, 6, b'\x01\x02\x03\x04'), (0, 4, b'\x00\x01'), (0, 5, b'\x00'), (0, 3, b'\x00\x00\x02\x01'), (0, 7, b'\x01\x02'), (0, 7, b''), (0, 9, b''),
        (1, 0, b'\x00\x01'), (1, 0, b'\x01\x00\x02\x00\x03\x00\x04\x00'), (1, 0, b'\x01\x02\x03'), (1, 0, b''),
        (2, 1, b'\x01\x00\x02\x00'), (1, 2, b''), (2, 3, b''), (1, 4, b''), (1, 9, b''), (2, 7, b'\x00'),
        (1, 8, b''), (2, 0x20, b''), (3, 0, b''), (0, 1, b'\x00'), (0, 3, b'\x00\x00\x02\x01' + b'\x01\x00\x02\x00')):
    add195(pie_frame(sixtop(typ, code, rest) + PT))
add195(pie_frame(pie(5, bytes([0xc9, 1, 0])) + PT))                        # too short
add195(pie_frame(pie(5, bytes([0xc9, 0x05, 1, 1, 1, 0, 0, 0, 0])) + PT))   # unsupported version
# MPX
def mpx(tt, tid=0, rest=b'', payload=b''):
    return pie(3, bytes([tt | (tid << 3)]) + rest + payload)

add195(pie_frame(mpx(0, 1, struct.pack('<H', 0x86dd), b'\x60\x00\x00\x00\x00\x00\x3b\x40' + bytes(32)) + PT))
add195(pie_frame(mpx(0, 1, struct.pack('<H', 0x809a), mac(DATA, V06, SHORT, SHORT, payload=b'in') + b'') + PT))
add195(pie_frame(mpx(0, 2, struct.pack('<H', 0x1234), b'unknown') + PT))
add195(pie_frame(mpx(0, 2, struct.pack('<H', 5), b'low') + PT))
add195(pie_frame(mpx(1, 1, b'', b'nomux') + PT))
add195(pie_frame(mpx(1, 1, b'', b'nomux') + PT))
add195(pie_frame(mpx(0, 3, struct.pack('<H', 1), b'\x01' + b'\x02\x01\x00\x00') + PT))        # KMP 802.1X (eapol)
add195(pie_frame(mpx(0, 3, struct.pack('<H', 1), b'\x06' + b'\x02\x01\x00\x00') + PT))             # 4WH
add195(pie_frame(mpx(0, 3, struct.pack('<H', 1), b'\x07' + b'\x02\x01\x00\x00') + PT))
for k in (2, 3, 4, 5, 8, 9, 0):
    add195(pie_frame(mpx(0, 3, struct.pack('<H', 1), bytes([k]) + b'kmpdata') + PT))
add195(pie_frame(mpx(0, 3, struct.pack('<H', 1), b'\xff' + bytes.fromhex('112233') + b'v') + PT))
add195(pie_frame(mpx(0, 4, struct.pack('<H', 2), b'\x01' + b'\x7a\x33\x3b') + PT))         # Wi-SUN 6LoWPAN
add195(pie_frame(mpx(0, 4, struct.pack('<H', 2), b'\x02' + b'wisunsec') + PT))
add195(pie_frame(mpx(0, 4, struct.pack('<H', 2), b'\x00' + b'mhds') + PT))
add195(pie_frame(mpx(0, 4, struct.pack('<H', 2), b'\x09' + b'x') + PT))
add195(pie_frame(mpx(2, 5, b'\x00' + struct.pack('<HH', 100, 0x86dd), b'frag0') + PT))
add195(pie_frame(mpx(2, 5, b'\x00' + struct.pack('<HH', 100, 1), b'frag0') + PT))
add195(pie_frame(mpx(2, 5, b'\x00' + struct.pack('<HH', 100, 2), b'frag0') + PT))
add195(pie_frame(mpx(2, 5, b'\x01', b'frag1') + PT))
add195(pie_frame(mpx(4, 5, b'\x02', b'frag2') + PT))
add195(pie_frame(mpx(6, 5, struct.pack('<H', 100)) + PT))
add195(pie_frame(mpx(6, 5, b'') + PT))
add195(pie_frame(mpx(3, 5, b'') + PT))                                                              # reserved transfer type
add195(pie_frame(mpx(7, 5, b'xx') + PT))
# nested frames through MPX, a few levels
inner = mac(DATA, V06, SHORT, SHORT, payload=b'hi')
for lvl in range(3):
    inner = mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1 + mpx(0, lvl, struct.pack('<H', 0x809a), fcs16(inner)) + PT)
add195(inner)
# frames with data after the payload IEs, header IE and payload IE together
add195(pie_frame(pie(1, psie_short(0x1a, bytes(6))) + PT, hdr=hie(0x1e, struct.pack('<H', 3)) + HT1, pl=b'payload'))
marks['cmd'] = len(main) + 1

# ============================================================= 5. Commands
def cmd(ver, cid, dm, sm, payload=b'', panc=0, **kw):
    return mac(CMD, ver, dm, sm, panc=panc, payload=bytes([cid]) + payload, **kw)

for ver in (V03, V06):
    add195(cmd(ver, 1, SHORT, LONG, b'\x8e'))                           # assoc request
    add195(cmd(ver, 1, LONG, LONG, b'\xc7'))
    add195(cmd(ver, 2, LONG, LONG, struct.pack('<HB', 0x1234, 0), panc=1))   # assoc response (maps the address)
    add195(cmd(ver, 2, LONG, LONG, struct.pack('<HB', 0xffff, 1), panc=1))
    add195(cmd(ver, 2, LONG, LONG, struct.pack('<HB', 0x0055, 2), panc=1))
    add195(cmd(ver, 3, LONG, LONG, b'\x01', panc=1))                    # disassoc
    add195(cmd(ver, 3, LONG, LONG, b'\x02', panc=1))
    add195(cmd(ver, 4, SHORT, LONG, b''))                              # data request
    add195(cmd(ver, 4, SHORT, SHORT, b'', panc=1))
    add195(cmd(ver, 4, LONG, LONG, b'', panc=1))
    add195(cmd(ver, 4, NONE, SHORT, b''))
    add195(cmd(ver, 2, LONG, LONG, struct.pack('<HB', 0x0056, 3) + b'xx', panc=1))   # reserved status, extra bytes
    add195(cmd(ver, 3, LONG, LONG, b'\x03xyz', panc=1))                  # reserved reason, extra bytes
    addbad195(cmd(ver, 3, LONG, LONG, b'', panc=1))
    add195(cmd(ver, 8, LONG, LONG, struct.pack('<HHBHB', 0x1234, 0x0000, 11, 0x0003, 2) + b'xx', panc=1, dpan=0xffff))
    add195(cmd(ver, 9, NONE, SHORT, b'\x21zz'))
    add195(cmd(ver, 5, LONG, LONG, b'', panc=1))                       # PAN ID conflict
    add195(cmd(ver, 6, SHORT, LONG, b'', dst=0xffff, dpan=0xffff, span=0xffff))      # orphan notification
    add195(cmd(ver, 7, SHORT, NONE, b'', dst=0xffff, dpan=0xffff))     # beacon request
    add195(cmd(ver, 8, LONG, LONG, struct.pack('<HHBH', 0x1234, 0x0000, 11, 0x0003), panc=1, dpan=0xffff))    # coordinator realignment
    add195(cmd(ver, 8, LONG, LONG, struct.pack('<HHBHB', 0x1234, 0x0000, 11, 0x0003, 2), panc=1, dpan=0xffff))
    add195(cmd(ver, 8, SHORT, LONG, struct.pack('<HHBHB', 0x1234, 0x0000, 11, 0x0003, 2), dst=0xffff, dpan=0xffff))
    add195(cmd(ver, 9, NONE, SHORT, b'\x21'))                           # GTS request
    add195(cmd(ver, 9, NONE, SHORT, b'\x12'))
    add195(cmd(ver, 9, NONE, SHORT, b'\x3f'))
    add195(cmd(ver, 0x0a, SHORT, SHORT, b'trle', panc=1))               # commands that are only named
    for cid in (0x0b, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x20, 0x21, 0x22, 0x23):
        add195(cmd(ver, cid, SHORT, SHORT, b'\x01\x02\x03', panc=1))
        add195(cmd(ver, cid, SHORT, SHORT, b'', panc=1))
    add195(cmd(ver, 0x24, SHORT, SHORT, bytes.fromhex('112233') + b'vendorcmd', panc=1))
    add195(cmd(ver, 0x24, SHORT, SHORT, bytes.fromhex('9bb8ea') + b'thread', panc=1))
    for cid in (0x00, 0x0c, 0x30, 0xff):
        add195(cmd(ver, cid, SHORT, SHORT, b'\x01\x02', panc=1))
        add195(cmd(ver, cid, SHORT, SHORT, b'', panc=1))
# address requirement violations (warnings "wrong addressing")
addbad195(cmd(V06, 1, SHORT, SHORT, b'\x00', panc=1))
addbad195(cmd(V06, 2, SHORT, SHORT, struct.pack('<HB', 1, 0), panc=1))
addbad195(cmd(V06, 3, SHORT, SHORT, b'\x01', panc=1))
addbad195(cmd(V06, 4, NONE, NONE, b''))
addbad195(cmd(V06, 5, SHORT, SHORT, b'', panc=1))
addbad195(cmd(V06, 6, LONG, SHORT, b'', panc=0))
addbad195(cmd(V06, 7, LONG, NONE, b'', panc=0))
addbad195(cmd(V06, 8, SHORT, SHORT, struct.pack('<HHBH', 1, 2, 3, 4), panc=1))
addbad195(cmd(V06, 9, LONG, LONG, b'\x01', panc=1))
# 2015 commands: beacon request with IEs, association with IEs
add195(cmd(V15, 7, SHORT, NONE, b'', panc=0, ie=True, ies=HT1 + pie(1, psie_short(0x1e, b'\x00')) + PT))
add195(cmd(V15, 7, SHORT, NONE, b'', panc=0))
add195(cmd(V15, 1, SHORT, LONG, b'\x8e', panc=0))
add195(cmd(V15, 2, LONG, LONG, struct.pack('<HB', 0x1234, 0), panc=1))
add195(cmd(V15, 4, SHORT, SHORT, b'', panc=1))
add195(cmd(V15, 0x24, SHORT, SHORT, bytes.fromhex('9bb8ea') + b'tv', panc=1, ie=True, ies=HT2))
marks['sec'] = len(main) + 1

# ============================================================= 6. Security headers (no keys: not decrypted)
for ver in (V06, V15):
    for level in range(8):
        for kid in range(4):
            src = {0: b'', 1: b'', 2: b'ksrc', 3: b'ksource8'}[kid]
            fr = mac(DATA, ver, SHORT, SHORT, panc=1, sec=dict(level=level, kid=kid, counter=0x01020304, keysrc=src, keyidx=3),
                     payload=b'secret' if level else b'plain')
            if (level + kid) % 3 == 0:
                add195(fr)
            elif (level + kid) % 3 == 1:
                add230(fr)
for level in (0, 1, 2, 3, 4, 5, 6, 7):
    add195(mac(DATA, V15, SHORT, SHORT, panc=1, sec=dict(level=level, kid=0, fcsup=True), payload=b'suppressed'))
    add195(mac(DATA, V15, SHORT, SHORT, panc=1, sec=dict(level=level, kid=1, fcsup=True, asn=True), payload=b'asn'))
add195(mac(CMD, V06, SHORT, LONG, sec=dict(level=5, kid=1), payload=b'\x04\xaa\xaa'))
add195(mac(BEACON, V06, NONE, SHORT, sec=dict(level=5), payload=sf(15, 15, 15, 1, 1) + b'\x00\x00\xaa'))
add195(mac(ACK, V15, SHORT, SHORT, panc=1, sec=dict(level=1, kid=0), ie=True, ies=HT2))
add195(mac(DATA, V15, SHORT, SHORT, panc=1, sec=dict(level=5, kid=0), ie=True, ies=hie(0x1e, struct.pack('<H', 1)) + HT1 + pie(1, psie_short(0x1a, bytes(6))) + PT, payload=b'x'))
add195(mac(DATA, V03, SHORT, SHORT, panc=1, sec=dict(level=5), payload=b'v2003 secured'))
# the frame of the review that was shorter than its MIC after decryption failed
add230(mac(DATA, V06, SHORT, SHORT, panc=1, sec=dict(level=7, kid=0, counter=1), payload=b'\xaa\xbb', mic=False))
add230(mac(DATA, V06, SHORT, SHORT, panc=1, sec=dict(level=7, kid=0, counter=1), payload=b'', mic=False))
add195(mac(DATA, V06, SHORT, SHORT, panc=1, sec=dict(level=7, kid=0, counter=1), payload=b'\xaa', mic=False))
marks['mp'] = len(main) + 1

# ============================================================= 7. Multipurpose frames
for lng in (0, 1):
    for dm, sm in ((NONE, NONE), (SHORT, SHORT), (LONG, LONG), (SHORT, LONG), (NONE, LONG)):
        for panid in (0, 1):
            mp = dict(long=lng, dm=dm, sm=sm, panid=panid, ver=0, seq=5)
            add195(mac(MP, mp=mp, payload=b'mpdata'))
    if lng:
        add195(mac(MP, mp=dict(long=1, dm=SHORT, sm=SHORT, panid=1, ver=0, seqsup=1, pend=1, ackreq=1), payload=b'x'))
        add195(mac(MP, mp=dict(long=1, dm=SHORT, sm=SHORT, panid=1, ver=0, ie=1, ies=HT1 + PT), payload=b'x'))
        add195(mac(MP, mp=dict(long=1, dm=LONG, sm=NONE, panid=0, ver=0, ie=1, ies=hie(0x1d, struct.pack('<H', 1)) + HT2), payload=b'wake'))
        add195(mac(MP, mp=dict(long=1, dm=SHORT, sm=SHORT, panid=1, ver=0, secen=1, sec=aux(level=5, kid=0, ver=V06) + b''), payload=b'secure' + b'\xa5' * 4))
# wake-up frame layout of 802.15.4e: short FCF, 8 bytes in total
add195(mac(MP, mp=dict(long=0, dm=SHORT, sm=LONG), payload=b''))
marks['tap'] = len(main) + 1

# ============================================================= 8. TAP (DLT 283) and non-ASK PHY (DLT 215)
def tlv(t, d):
    return struct.pack('<HH', t, len(d)) + d + b'\0' * (-len(d) % 4)


def tap(tlvs, mac_frame):
    t = b''.join(tlvs)
    return struct.pack('<BBH', 0, 0, 4 + len(t)) + t + mac_frame


def f32le(x):
    return struct.pack('<f', x)

base = mac(DATA, V06, SHORT, SHORT, panc=1, payload=b'tapdata')
add(DLT_283, tap([tlv(0, b'\x01')], fcs16(base)), fcs=False)
add(DLT_283, tap([tlv(0, b'\x00')], base), fcs=False)
add(DLT_283, tap([tlv(0, b'\x02')], fcs32(base)), fcs=False)
add(DLT_283, tap([tlv(0, b'\x01'), tlv(1, f32le(-71.5)), tlv(2, struct.pack('<I', 250000)), tlv(3, struct.pack('<HB', 11, 0)),
                  tlv(5, struct.pack('<Q', 1000000123)), tlv(6, struct.pack('<Q', 1000004123)), tlv(7, struct.pack('<Q', 12345)),
                  tlv(8, struct.pack('<Q', 999000000)), tlv(9, struct.pack('<I', 10000)), tlv(10, b'\xc8'),
                  tlv(11, f32le(2405000.0)), tlv(12, f32le(2405000.0) + f32le(5000.0) + struct.pack('<H', 16))], fcs16(base)), fcs=False)
for band, typ, mode in ((0, 0, 1), (1, 1, 3), (4, 2, 2), (5, 3, 1), (6, 4, 1), (7, 5, 2), (8, 6, 4), (9, 7, 1), (10, 8, 3), (11, 9, 2), (12, 10, 1), (3, 11, 1), (2, 99, 5)):
    add(DLT_283, tap([tlv(0, b'\x01'), tlv(4, bytes([band, typ, mode]))], fcs16(base)), fcs=False)
add(DLT_283, tap([tlv(0, b'\x01'), tlv(4, b'\x01\x02')], fcs16(base)), fcs=False)
for page in (0, 1, 2, 3, 4, 5, 6, 9, 31, 99):
    add(DLT_283, tap([tlv(0, b'\x01'), tlv(3, struct.pack('<HB', 5, page))], fcs16(base)), fcs=False)
# PHY headers
for phr_type in range(0, 22):
    add(DLT_283, tap([tlv(0, b'\x01'), tlv(13, struct.pack('<HH', phr_type, 16) + RNDB(2) + b'\0\0')], fcs16(base)), fcs=False)
for ph in (0x0000, 0x0100, 0x0080, 0x8000, 0x8000 | 0x0000, 0x8000 | 0x0200, 0x8000 | 0x0400, 0x8000 | 0x0600, 0x8000 | 0x1000 | 0x0600,
           0x8000 | 0x07ff, 0x1fe0 | 0x8000, 0x6000 | 0x8000, 0x07ff, 0xffff, 0x8123, 0x8a55):
    for typ in (6, 18):
        add(DLT_283, tap([tlv(0, b'\x01'), tlv(13, struct.pack('<HHH', typ, 16, ph) + b'\0\0')], fcs16(base)), fcs=False)
add(DLT_283, tap([tlv(0, b'\x01'), tlv(13, struct.pack('<HH', 1, 16) + b'\0\0\0')], fcs16(base)), fcs=False)
bad.append((DLT_283, tap([tlv(0, b'\x01'), tlv(99, b'\x01\x02\x03\x04\x05'), tlv(0x7fff, b'')], fcs16(base))))       # unknown TLVs
add(DLT_283, tap([tlv(0, b'\x01'), tlv(0, b'\x01')], fcs16(base)), fcs=False)
add(DLT_283, tap([tlv(5, struct.pack('<Q', 5000000)), tlv(8, struct.pack('<Q', 1000000)), tlv(9, struct.pack('<I', 5000))], b''), fcs=False)    # no FCS TLV
add(DLT_283, tap([tlv(0, b'\x01'), tlv(5, struct.pack('<Q', 5000000)), tlv(8, struct.pack('<Q', 1000000)), tlv(6, struct.pack('<Q', 5999999)),
                  tlv(9, struct.pack('<I', 3000))], fcs16(base)), fcs=False)
add(DLT_283, tap([tlv(0, b'\x01')], b''), fcs=False)                    # no payload (comment)
add(DLT_283, tap([], base), fcs=False)
# TAP header with TLV padding bytes non zero (warning)
t = struct.pack('<HH', 10, 1) + b'\xc8\xff\xff\xff'
bad.append((DLT_283, struct.pack('<BBH', 0, 0, 4 + len(t) + 8) + t + tlv(0, b'\x01') + fcs16(base)))
# TAP: frame with Wi-SUN-like header and MAC frame
add(DLT_283, tap([tlv(0, b'\x01'), tlv(3, struct.pack('<HB', 5, 9)), tlv(4, b'\x04\x02\x03')], fcs16(mac(CMD, V15, SHORT, SHORT, panc=1, payload=b'\x04'))), fcs=False)

# non-ASK PHY: preamble(4) sfd(1) phr(1) then MAC with FCS
for ln in (0x08, 0x0d, 0x10):
    m = mac(DATA, V06, SHORT, SHORT, panc=1, payload=bytes(range(ln))[:ln - 9] if ln > 9 else b'')
    m = fcs16(m)
    add(DLT_215, b'\0\0\0\0' + b'\xa7' + bytes([len(m)]) + m, fcs=False)
m = fcs16(mac(BEACON, V06, NONE, SHORT, payload=sf(15, 15, 15, 1, 1) + b'\x00\x00'))
add(DLT_215, b'\0\0\0\0\xa7' + bytes([len(m)]) + m, fcs=False)

# ============================================================= 9. Other encapsulations
def sll(inner):
    return struct.pack('>HHH', 0, 0x0324, 8) + b'\0' * 8 + struct.pack('>H', 0x00f6) + inner       # ltype IEEE802154

ff = fcs16(mac(DATA, V06, SHORT, SHORT, panc=1, payload=b'sll'))
add(DLT_SLL, sll(ff), fcs=False)
add(DLT_SLL, sll(ff), fcs=False)


def eth(inner):
    return bytes.fromhex('020000000002020000000001') + struct.pack('>H', 0x809a) + inner

add(DLT_ETH, eth(ff), fcs=False)
add(DLT_ETH, eth(fcs16(mac(CMD, V06, SHORT, LONG, payload=b'\x04'))), fcs=False)
# ZBOSS dump: 'ZBOSS' + direction/page, channel, trace number; CC24xx trailer
zb = lambda m_, d=0, pg=0, ch=11, tn=5, ok=True: b'ZBOSS' + bytes([d | (pg << 1), ch]) + struct.pack('<I', tn) + cc24xx(m_, ok)
add(DLT_195, zb(mac(DATA, V06, SHORT, SHORT, panc=1, payload=b'\x08\x00\x00\x00\x00\x00\x1e\x01' + b'\x00\x01\x01\x00\xef\xbe\x01\x05' + b'zbdata', raw=True)), fcs=False)
bad.append((DLT_195, zb(mac(DATA, V06, SHORT, SHORT, panc=1, payload=b''), d=1, pg=3)))
add(DLT_195, zb(mac(DATA, V06, SHORT, SHORT, panc=1, payload=b'\x08\x00\x00\x00\x00\x00\x1e\x01' + b'\x00\x01\x01\x00\xef\xbe\x01\x05' + b'zbdata', raw=True), d=1, pg=3), fcs=False)
add(DLT_195, zb(mac(DATA, V06, SHORT, SHORT, panc=1, payload=b'zz', raw=True), ok=False), fcs=False)
add(DLT_195, zb(mac(CMD, V06, SHORT, LONG, payload=b'\x04')), fcs=False)

# ACK frames and frames for the "ACK tracking" preference (matched by sequence number and address)
marks['ack'] = len(main) + 1
for i in range(4):
    add195(mac(DATA, V06, SHORT, SHORT, seq=100 + i, panc=1, ackreq=1, payload=b'req'))
    add195(mac(ACK, V06, NONE, NONE, seq=100 + i))
add195(mac(DATA, V06, SHORT, SHORT, seq=110, panc=1, ackreq=1, payload=b'noack'))
add195(mac(ACK, V06, NONE, NONE, seq=111))
def req_ack(seq, dm, sm, ack_dst=None, ack_src=None, second=False, late=False, ver=V15):
    add195(mac(DATA, ver, dm, sm, seq=seq, panc=1, ackreq=1, payload=b'reqx'))
    kw = {}
    if ack_dst is not None:
        kw['dst'] = ack_dst
    if ack_src is not None:
        kw['src'] = ack_src
    ackf = fcs16(mac(ACK, ver, sm, dm, seq=seq, panc=1, ie=True, ies=HT2, **kw))
    main.append((DLT_195, ackf, 5000000 if late else 1000))
    if second:
        add195(mac(ACK, ver, sm, dm, seq=seq, panc=1, ie=True, ies=HT2, **kw))

req_ack(120, SHORT, SHORT, ack_src=DST16, ack_dst=SRC16)                     # matched
req_ack(121, LONG, LONG, ack_src=DST64, ack_dst=SRC64)
req_ack(122, SHORT, LONG, ack_src=DST16, ack_dst=SRC64)
req_ack(123, LONG, SHORT, ack_src=DST64, ack_dst=SRC16)
req_ack(124, SHORT, SHORT, ack_src=DST16, ack_dst=SRC16, second=True)           # matched twice
req_ack(125, SHORT, SHORT, ack_src=0x9999, ack_dst=SRC16)                     # from the wrong address
req_ack(126, SHORT, SHORT, ack_src=DST16, ack_dst=0x9999)                     # to the wrong address
req_ack(127, LONG, LONG, ack_src=DST64, ack_dst=0x1)                          # extended addresses, wrong destination
req_ack(128, LONG, LONG, ack_src=0x1, ack_dst=SRC64)
req_ack(129, SHORT, SHORT, ack_src=DST16, ack_dst=SRC16, late=True)           # ACK after the timeout
add195(mac(DATA, V15, LONG, LONG, seq=131, panc=1, ackreq=1, payload=b'reqL'))
add195(mac(ACK, V15, NONE, NONE, seq=131, ie=True, ies=HT2))
add195(mac(DATA, V15, SHORT, SHORT, seq=130, panc=0, ackreq=1, payload=b'req15'))                          # request with both PANs, ACK with none
add195(fcs16(b'') and mac(ACK, V15, NONE, NONE, seq=130, ie=True, ies=HT2))
marks['end'] = len(main) + 1

# ZEP (UDP 17754): v1 with and without the CC24xx metadata, v2 data and ack
def udp_eth(payload, sport=1234, dport=17754):
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    sm_ = sum(struct.unpack('>10H', ip)); sm_ = (sm_ & 0xffff) + (sm_ >> 16); sm_ = (sm_ & 0xffff) + (sm_ >> 16)
    ip = ip[:10] + struct.pack('>H', ~sm_ & 0xffff) + ip[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + udp


zdata = mac(DATA, V06, SHORT, SHORT, panc=1, payload=b'zep')
zcc = cc24xx(zdata)
zfcs = fcs16(zdata)
add(DLT_ETH, udp_eth(b'EX\x01' + bytes([11]) + struct.pack('>H', 1) + bytes([0, 0xff]) + bytes(7) + bytes([len(zcc)]) + zcc), fcs=False)
add(DLT_ETH, udp_eth(b'EX\x01' + bytes([11]) + struct.pack('>H', 1) + bytes([1, 0xc8]) + bytes(7) + bytes([len(zfcs)]) + zfcs), fcs=False)
add(DLT_ETH, udp_eth(b'EX\x02\x01' + bytes([12]) + struct.pack('>H', 2) + bytes([0, 0x80]) + bytes(8) + struct.pack('>I', 1) + bytes(10) + bytes([len(zcc)]) + zcc), fcs=False)
add(DLT_ETH, udp_eth(b'EX\x02\x01' + bytes([12]) + struct.pack('>H', 2) + bytes([1, 0x80]) + bytes(8) + struct.pack('>I', 2) + bytes(10) + bytes([len(zfcs)]) + zfcs), fcs=False)
add(DLT_ETH, udp_eth(b'EX\x02\x02' + struct.pack('>I', 3)), fcs=False)
# 802.15.4e wake-up frame (compatibility preference): short FCF, 12 bytes
add(DLT_230, bytes([MP | (SHORT << 4), 7]) + struct.pack('<HH', PAN, DST16) + struct.pack('<H', (0x1d << 7) | 2) + struct.pack('<H', 5) + b'\0\0', fcs=False)

# ===================================================== a larger packet, FCS variants of the same frame
f_ok = mac(DATA, V06, SHORT, SHORT, panc=1, payload=b'checksum')
add(DLT_195, f_ok + struct.pack('<H', 0xdead), fcs=False)    # bad FCS (a warning): goes to the malformed capture instead
main.pop()
bad.append((DLT_195, f_ok + struct.pack('<H', 0xdead)))

# =============================================================== malformed
mk = lambda ft, **kw: mac(ft, force=True, **kw)
bad.append((DLT_195, fcs16(struct.pack('<HB', 0x0001 | (RSV << 10) | (V06 << 12), 1))))                  # reserved dst address mode
bad.append((DLT_195, fcs16(struct.pack('<HB', 0x0001 | (RSV << 14) | (V06 << 12) | (SHORT << 10), 1) + b'\0\0\0\0')))
bad.append((DLT_195, fcs16(struct.pack('<HB', 0x0001 | (V15 + 1 << 12), 1))))                             # reserved version
bad.append((DLT_195, fcs16(struct.pack('<HB', 0x0001 | (3 << 12), 1))))
bad.append((DLT_195, fcs16(struct.pack('<HB', 0x0005 | (3 << 12), 1))))
bad.append((DLT_195, fcs16(struct.pack('<HB', 0x0001 | 0x40, 1))))                                         # panc without addresses (2003)
bad.append((DLT_195, fcs16(struct.pack('<HB', 0x0001 | 0x40 | (V15 << 12) | (SHORT << 10) | (LONG << 14), 1) + b'\0' * 12)))
bad.append((DLT_195, fcs16(struct.pack('<HB', 0x0001 | 0x40 | (V15 << 12) | (LONG << 10) | (SHORT << 14), 1) + b'\0' * 12)))
bad.append((DLT_195, fcs16(struct.pack('<HB', 0x0001 | 0x40 | (V15 << 12) | (SHORT << 10) | (SHORT << 14), 1) + b'\0' * 12)))
for ft in (4, 6, 7):
    bad.append((DLT_195, fcs16(struct.pack('<HB', ft | (V06 << 12) | (SHORT << 10) | (SHORT << 14), 1) + b'\0' * 8 + b'x')))
    bad.append((DLT_195, fcs16(struct.pack('<HB', ft | (V15 << 12) | (SHORT << 10) | (SHORT << 14), 1) + b'\0' * 8 + b'x')))
bad.append((DLT_195, fcs16(struct.pack('<HB', 0x0001 | 0x100 | (V06 << 12) | (SHORT << 10) | (SHORT << 14), 1) + b'\0' * 8)))   # seqno suppression in 2006
bad.append((DLT_195, fcs16(struct.pack('<HB', MP | 0x8 | (1 << 12 << 0) , 1))))
# truncated frames
good = fcs16(mac(DATA, V06, SHORT, SHORT, panc=1, payload=b'trunc'))
for n in range(1, 10):
    bad.append((DLT_195, good[:n]))
for n in (1, 2, 3, 5, 8, 12):
    bad.append((DLT_230, mac(DATA, V06, LONG, LONG, panc=0, payload=b'trunc')[:n]))
bad.append((DLT_230, mac(DATA, V06, LONG, LONG, panc=1, sec=dict(level=5, kid=3, keysrc=b'12345678'), payload=b'')[:20]))
bad.append((DLT_230, mac(BEACON, V06, NONE, SHORT, payload=sf(15, 15, 15, 1, 1) + b'\x03')[:-1]))
bad.append((DLT_230, mac(BEACON, V06, NONE, SHORT, payload=sf(15, 15, 15, 1, 1) + b'\x83\x01\x00\x00\x00')))
bad.append((DLT_230, mac(BEACON, V06, NONE, SHORT, payload=sf(15, 15, 15, 1, 1) + b'\x00\x32\x01\x02')))
bad.append((DLT_230, cmd(V06, 2, LONG, LONG, b'\x00', panc=1)))
bad.append((DLT_230, cmd(V06, 8, LONG, LONG, b'\x00\x00', panc=1)))
bad.append((DLT_230, cmd(V06, 1, SHORT, LONG, b'')))
# IE with lengths that do not fit
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=struct.pack('<H', (0x1e << 7) | 40) + b'ab')))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=hie(0x1e, b'\x01'))))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=hie(0x1a, b'\x01\x02\x03'))))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=hie(0x29, b'\x01\x02'))))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=hie(0x00, b'\x01'))))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1 + struct.pack('<H', 0x8000 | (1 << 11) | 30) + b'abc')))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1 + pie(1, struct.pack('<H', (0x1b << 8) | 20) + b'abc'))))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1 + pie(1, struct.pack('<H', 0x8000 | (9 << 11) | 20) + b'abc'))))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1 + pie(1, psie_short(0x1b, b'\x03\x01\x00\x00\x05')))))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1 + pie(1, psie_short(0x1a, b'\x01\x02')))))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1 + pie(1, psie_short(0x1c, b'\x01\x02\x03')))))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1 + pie(1, psie_short(0x1e, b'\x1e')))))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1 + pie(3, b''))))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1 + pie(3, b'\x00\x01'))))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1 + pie(3, b'\x02\x00\x00'))))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1 + pie(3, b'\x00\x01\x00\x01'))))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1 + pie(3, b'\x08'))))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1 + pie(2, b'\x01'))))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1 + pie(5, b'\xc9\x00\x01\x01\x01\x00\x00\x03\x00'))))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1)))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=HT1 + struct.pack('<H', 0x8000 | (3 << 11) | 5) + b'\x01')))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=b'')))
bad.append((DLT_230, mac(DATA, V15, SHORT, SHORT, ie=True, ies=b'\x01')))
# TAP truncations
tp = tap([tlv(0, b'\x01'), tlv(5, struct.pack('<Q', 5)), tlv(4, b'\x01\x00\x01'), tlv(13, struct.pack('<HHH', 6, 16, 0x8000) + b'\0\0')], fcs16(base))
for n in (3, 4, 6, 8, 9, 12, 16, 20, 24, 30, 36, 40, 44, 48):
    bad.append((DLT_283, tp[:n]))
bad.append((DLT_283, struct.pack('<BBH', 1, 0, 4) + fcs16(base)))                    # version 1
bad.append((DLT_283, struct.pack('<BBH', 0, 0, 2) + fcs16(base)))                    # length below 4
bad.append((DLT_283, struct.pack('<BBH', 0, 0, 200) + fcs16(base)))                  # length past the capture
bad.append((DLT_283, tap([tlv(0, b'\x01')[:5]], b'')))
bad.append((DLT_283, tap([tlv(0, b'\x07')], fcs16(base))))                          # invalid FCS type
bad.append((DLT_283, struct.pack('<BBH', 0, 0, 4 + 8) + struct.pack('<HH', 0, 1) + b'\x01\0\0\0' + fcs16(base)))   # the TAP padding reproducer
for i in range(3):
    t_ = struct.pack('<HHB', 0, 1, 1)                                   # FCS type TLV with length 1 at the end of the TLV area
    bad.append((DLT_283, struct.pack('<BBH', 0, 0, 4 + len(t_)) + t_ + mac(DATA, V06, SHORT, SHORT, payload=b'hello', panc=1) + b'\x00\x00'))
bad.append((DLT_283, struct.pack('<BBH', 0, 0, 4 + 5) + struct.pack('<HHB', 0, 1, 1) + b'\0\0\0' + b''))
# non-ASK PHY too short
bad.append((DLT_215, b'\0\0\0\0\xa7\x7f' + b'abc'))
bad.append((DLT_215, b'\0\0\0\0\xa7'))
bad.append((DLT_215, b'\0\0'))
# the MPX nesting reproducer of the review (depth 60) and MIC shorter than the frame
depth = 60
inner = struct.pack('<HB', 0x0001 | (2 << 12), 0) + b'hi' + b'\x00\x00'
for k in range(depth):
    mpx_ = struct.pack('<BH', 0x00, 0x809A) + inner
    pie_ = struct.pack('<H', 0x8000 | (3 << 11) | len(mpx_)) + mpx_
    inner = struct.pack('<HB', 0x0001 | (1 << 9) | (2 << 12), k & 0xff) + struct.pack('<H', 0x7e << 7) + pie_ + b'\x00\x00'
bad.append((DLT_230, inner[:-2]))
# multipurpose frame problems
bad.append((DLT_195, fcs16(mpframe(dict(long=1, dm=SHORT, sm=SHORT, panid=1, ver=1), b'x'))))
bad.append((DLT_195, fcs16(b'\x05')))
bad.append((DLT_195, fcs16(b'\x0d\x01')))
bad.append((DLT_195, fcs16(b'\x0d\x01\x00\x01'))[:3])
# random mutations of valid frames (coverage of bounds checks in the IE and command parsers)
rm = random.Random(7)
for i in range(900):
    lt, fr = main[rm.randrange(len(main))][:2]
    if lt not in (DLT_195, DLT_230, DLT_283, DLT_215):
        continue
    b = bytearray(fr)
    for _ in range(rm.randrange(1, 4)):
        k = rm.randrange(len(b))
        mode = rm.randrange(3)
        if mode == 0:
            b[k] = rm.randrange(256)
        elif mode == 1:
            b[k] ^= 1 << rm.randrange(8)
        else:
            del b[k:k + rm.randrange(1, 6)]
            if not b:
                b = bytearray(b'\0')
    bad.append((lt, bytes(b)))

# ============================================== 32 bit FCS and CC24xx metadata (preferences)
for lt in (DLT_195,):
    f32.append((lt, fcs32(mac(DATA, V06, SHORT, SHORT, panc=1, payload=b'fcs32'))))
    f32.append((lt, fcs32(mac(DATA, V06, SHORT, SHORT, panc=1, payload=b'fcs32')[:-1] + b'\x00')[:-1] + b'\x00'))
    f32.append((lt, cc24xx(mac(DATA, V06, SHORT, SHORT, panc=1, payload=b'cc24xx'), ok=True)))
    f32.append((lt, cc24xx(mac(DATA, V06, SHORT, SHORT, panc=1, payload=b'cc24xx'), ok=False)))
    f32.append((lt, fcs16(mac(DATA, V06, SHORT, SHORT, panc=1, payload=b'cc24xx'))[:-2] + b'\x00\x00'))
    f32.append((lt, fcs32(mac(CMD, V06, SHORT, LONG, payload=b'\x04'))))
    f32.append((lt, fcs32(mac(BEACON, V06, NONE, SHORT, payload=sf(15, 15, 15, 1, 1) + b'\x00\x00'))))
    f32.append((lt, b'\x01'))
    f32.append((lt, b'\x01\x08\x01'))

os.makedirs(out, exist_ok=True)
pcapng(os.path.join(out, 'ieee802154-coverage.pcapng'), main)
pcapng(os.path.join(out, 'ieee802154-coverage-malformed.pcapng'), bad)
pcapng(os.path.join(out, 'ieee802154-coverage-fcs32.pcapng'), f32)
print(len(main), len(bad), len(f32), marks)
