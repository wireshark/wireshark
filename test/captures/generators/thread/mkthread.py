#!/usr/bin/env python3
# Generates test/captures/thread_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Thread coverage captures. Usage: mkthread.py <outdir>
All packets are built with struct; nothing comes from a real network.
The values are dummy values (including the ones in the key TLVs)."""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

# ---------------------------------------------------------------- pcapng
def blk(t, body):
    body += b'\0' * ((4 - len(body) % 4) % 4)
    return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)

def write_ng(fn, frames, linktypes):
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifc, fr) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        out += blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    with open(os.path.join(OUT, fn), 'wb') as f:
        f.write(out)

EXP, WPAN = 0, 1

def exppdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    hdr = struct.pack('!HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('!HH', 0, 0)
    return hdr + payload

def tlv(t, v):
    if len(v) >= 255:
        return struct.pack('!BBH', t, 255, len(v)) + v
    return struct.pack('!BB', t, len(v)) + v

def tlv16(t, v):      # 16-bit length form, whatever the length
    return struct.pack('!BBH', t, 255, len(v)) + v

def b(n, seed=0):
    return bytes((seed + i * 7) & 0xff for i in range(n))

main = []
MARKS = []
def add(name, payload):
    main.append((EXP, exppdu(name, payload)))

# ------------------------------------------------------------- CoAP (TMF)
MID = [100]
def coap(path, payload=b'', code=2, typ=0, mid=None, ct=True, token=b''):
    """A CoAP message with Uri-Path segments and optionally Content-Format 42."""
    MID[0] += 1
    mid = MID[0]
    msg = struct.pack('!BBH', 0x40 | (typ << 4) | len(token), code, mid) + token
    prev = 0
    for seg in path:
        s = seg.encode()
        msg += bytes([((11 - prev) << 4) | len(s)]) + s
        prev = 11
    if ct:
        msg += bytes([((12 - prev) << 4) | 1, 42])
    if payload:
        msg += b'\xff' + payload
    return msg

def tmf(path, payload, **kw):
    add('coap_for_tmf', coap(path, payload, **kw))

# ------------------------------------------------- Thread address / nm / bl
def std_tlvs(nm=False):
    t = [
        (0, bytes.fromhex('fd0000000000000000000000000000aa')),   # Target EID
        (1, bytes.fromhex('0011223344556677')),                    # Extended MAC address
        (2, b'\x04\x00'),                                          # RLOC16
        (3, b'\x11\x22\x33\x44\x55\x66\x77\x88'),                   # ML-EID IID
        (4, b'\x00'), (4, b'\x01'), (4, b'\x02'), (4, b'\x03'), (4, b'\x04'), (4, b'\x05'), (4, b'\x09'),
        (6, struct.pack('!I', 3600)),                              # Last transaction time
        (7, b'\x05' + b'\xb8\xc5' + b'\0' * 6),                    # Router mask
        (8, b'\x03\x04' + b'\0' * 6),                              # ND option
        (9, b'\x86\x00' + b'\0' * 6),                              # ND data
        (11, struct.pack('!I', 600)), (11, b'\x3c'), (11, b'\x00\x3c'),   # Timeout
        (12, b'OpenThread'), (12, b''),                            # Network name
        (14, bytes.fromhex('fd00000000000000000000000000ee01') + bytes.fromhex('fe80000000000000021122fffe334455')),
        (14, b''),
        (5, b'\x01\x02'), (13, b'\xff'), (99, b'unknown'),          # unknown types
    ]
    if nm:
        t.append((15, b'\x12\x34'))
    return t

NWD = None   # filled below (needs the NWD builders)

# ------------------------------------------------------- network data
def nwd_tlv(t, stable, v):
    return tlv((t << 1) | stable, v)

def has_route(stable=1, n=2):
    return nwd_tlv(0, stable, b''.join(struct.pack('!HB', 0x0400 + i, 0x40 | (i << 5)) for i in range(n)))

def border_router(stable=1, n=2):
    return nwd_tlv(2, stable, b''.join(struct.pack('!HBB', 0x0800 + i, 0x80 | 0x3f, 0xc0 if i else 0x40) for i in range(n)))

def prefix(domain, plen, pbytes, subs=b'', stable=1):
    return nwd_tlv(1, stable, bytes([domain, plen]) + pbytes + subs)

def lowpan_id(flags, ctx_len, stable=1):
    return nwd_tlv(3, stable, bytes([flags, ctx_len]))

def server(v, stable=1):
    return nwd_tlv(6, stable, v)

def service(flags_sid, ent, sdata, subs=b'', stable=1):
    v = bytes([flags_sid]) + (struct.pack('!I', ent) if ent is not None else b'') + bytes([len(sdata)]) + sdata + subs
    return nwd_tlv(5, stable, v)

def commissioning(mc):
    return nwd_tlv(4, 0, mc)

# ------------------------------------------------------------- MeshCoP
def mc_all_valid():
    """One list of (type, value) with every MeshCoP TLV type at a valid length."""
    return [
        (0, b'\x00\x00\x0f'),                                         # channel: page 0, channel 15
        (1, b'\xfa\xce'),                                             # PAN ID
        (2, bytes.fromhex('dead00beef00cafe')),                       # extended PAN ID
        (3, b'ThreadNet'),                                            # network name
        (4, b(16, 0x10)),                                             # PSKc (dummy)
        (5, b(16, 0x20)),                                             # network key (dummy)
        (6, struct.pack('!I', 7)),                                    # key sequence counter
        (7, bytes.fromhex('fd00000000000001')),                       # mesh-local prefix
        (8, b'\xff' * 16), (8, b'\x00'),                                # steering data
        (9, b'\x04\x00'),                                             # border agent locator
        (10, b'my-commissioner'),                                     # commissioner ID
        (11, b'\xab\xcd'),                                            # commissioner session ID
        (12, b'\x02\x58\xf0'),                                        # security policy, Thread 1.1
        (12, b'\x02\x58\xff\xf8'),                                    # Thread 1.2/1.3
        (13, bytes([0, 1, 2, 3, 12, 14])),                            # Get
        (14, b'\x00\x00\x00\x00\x03\xe8\x40\x01'),   # active timestamp
        (15, struct.pack('!H', 49191)),                               # commissioner UDP port
        (16, b'\x01'), (16, b'\xff'), (16, b'\x00'),                  # state
        (18, struct.pack('!H', 49192)),                               # joiner UDP port
        (19, bytes.fromhex('0123456789abcdef')),                      # joiner IID
        (20, b'\x08\x00'),                                            # joiner router locator
        (21, b(16, 0x30)),                                            # joiner KEK (dummy)
        (32, b'https://example.test/provision'),                      # provisioning URL
        (33, b'Example Vendor'), (34, b'Model 1'), (35, b'1.2.3'), (36, b'vendor data'),
        (37, bytes.fromhex('ffeedd') + bytes([0x12, 0x34, 0x5a])),   # vendor stack version
        (49, bytes.fromhex('fd000000000000000000000000000042')),      # IPv6 address
        (51, b'\x00\x00\x00\x00\x07\xd0\x20\x00'),                    # pending timestamp
        (52, struct.pack('!I', 30000)),                               # delay timer
        (53, bytes([0, 4]) + struct.pack('!I', 0x07fff800)),          # channel mask
        (54, b'\x0a'), (55, b'\x00\x64'), (56, b'\x01\x2c'),          # count, period, scan duration
        (59, b'DomainA'),                                             # domain name
        (61, b'\xaa' * 16), (62, b'\xbb' * 8),                         # AE and NMKP steering data
        (64, b(20, 0x40)),                                            # commissioner signature
        (65, b'\x1f\x9a'), (66, b'\x1f\x9b'),                         # AE and NMKP UDP ports
        (68, bytes.fromhex('fd000000000000000000000000000043')),      # registrar IPv6 address
        (69, b'registrar.example.test'),                               # registrar hostname
        (128, b'\x11\x00'), (128, b'\x10\x00'), (129, b'\x11\x30'), (129, b'\x10\x00'),   # discovery
        (200, b'unknown tlv'),
        # last: after a decoded energy list the offset is advanced twice (see README)
        (57, b'\x10\x20' * 16),                                       # energy list (twice 16 channels)
    ]

def mc_skipped_then_name():
    """TLVs that are skipped (the fixes added the missing offset advance),
    each followed by a network name that must still be decoded."""
    out = b''
    for t, v in [(60, b'\x00\x01\x02\x03\x04'), (63, b'\x01\x02\x03'), (67, b'tri.example.test'),
                 (70, b'\x07' * 9), (71, b'\x08' * 11)]:
        out += tlv(t, v) + tlv(3, b'after-%d' % t)
    return out

ENC_MC_SRC = 5683

def udp_hdr_less(sport, dport, payload):
    return struct.pack('!HH', sport, dport) + payload

# DTLS record carrying an opaque (encrypted looking) handshake record
def dtls_record(ctype, epoch, seq, body):
    return struct.pack('!BHHIHH'.replace('IHH', 'HI'), ctype, 0xfefd, epoch, 0, 0)[:0] + \
        bytes([ctype, 0xfe, 0xfd]) + struct.pack('!H', epoch) + seq.to_bytes(6, 'big') + struct.pack('!H', len(body)) + body

# =================================================================== frames
# ---- Thread address, Network Management, Backbone Link (direct)
MARKS.append((len(main) + 1, 'Thread address, Network Management, Backbone Link (direct)'))
for name, nm in (('thread_address', False), ('thread_nm', True), ('thread_bl', False)):
    tl = std_tlvs(nm)
    for t, v in tl:
        add(name, tlv(t, v))
    # all of them in one message, and a message with the network data TLV
    add(name, b''.join(tlv(t, v) for t, v in tl))
    nd = prefix(0, 64, bytes.fromhex('fd00000000000001'), has_route() + border_router() + lowpan_id(0x11, 64)) + has_route(0)
    add(name, tlv(10, nd) + tlv(2, b'\x04\x00') + tlv(10, b''))

# ---- Thread diagnostics: every TLV type, a 16-bit length, the type list
MARKS.append((len(main) + 1, 'Thread diagnostics: every TLV type, a 16-bit length, the type list'))
dg = b''
for t in list(range(0, 35)) + [200]:
    if t == 18:
        continue
    dg += tlv(t, b(((t * 5) % 23) + 1, t))
add('thread_diagnostic', dg)
add('thread_diagnostic', tlv(18, bytes([0, 1, 2, 5, 6, 17, 18, 34])) + tlv16(25, b'long vendor name ' * 3) + tlv(0, b''))
for t in (0, 1, 2, 4, 5, 9, 16, 29, 31, 34, 255):
    add('thread_diagnostic', tlv(t, b(10, t)))

# ---- MeshCoP, one TLV per frame and together
MARKS.append((len(main) + 1, 'MeshCoP, one TLV per frame and together'))
for t, v in mc_all_valid():
    add('thread_meshcop', tlv(t, v))
add('thread_meshcop', b''.join(tlv(t, v) for t, v in mc_all_valid()))
add('thread_meshcop', mc_skipped_then_name())
# the 16-bit length form
add('thread_meshcop', tlv16(3, b'EscapedLen') + tlv16(33, b'V' * 20))
# channel masks: several pages, then an energy list that fits and one that does not
add('thread_meshcop', tlv(53, bytes([0, 4]) + struct.pack('!I', 0x07fff800) + bytes([1, 2, 0xff, 0xff])) +
    tlv(57, bytes(range(64))))
add('thread_meshcop', tlv(53, bytes([0, 4]) + struct.pack('!I', 0x07fff800)) + tlv(57, bytes(range(33))))
add('thread_meshcop', tlv(57, bytes(range(16))))            # no channel mask: shown as a string
# Joiner DTLS encapsulation: an opaque record
add('thread_meshcop', tlv(17, dtls_record(23, 1, 5, b(24, 3))) + tlv(17, b''))
# UDP encapsulation: one level to a port nobody decodes, one to CoAP, and the
# reproducer of the recursion bug: 12 levels towards CoAP port 5683, which
# the Thread CoAP dissector (Decode As udp.port 5683) hands back to MeshCoP
add('thread_meshcop', tlv(48, struct.pack('!HH', 61631, 61632) + b'payload'))
add('thread_meshcop', tlv(48, struct.pack('!HH', 61631, 61632) + b''))
inner = coap(['c', 'ag'], tlv(1, b'\x12\x34'))
add('thread_meshcop', tlv(48, struct.pack('!HH', 5683, 5683) + inner))
for levels in (2, 12):
    cur = coap(['c', 'ag'], tlv(1, b'\x12\x34'))
    for _ in range(levels):
        cur = coap(['c', 'ag'], tlv(48, struct.pack('!HH', 5683, 5683) + cur))
    add('thread_meshcop', tlv(48, struct.pack('!HH', 5683, 5683) + cur)) if levels == 12 else \
        tmf(['c', 'ag'], tlv(48, struct.pack('!HH', 5683, 5683) + cur))

# ---- Network data
MARKS.append((len(main) + 1, 'Network data'))
srv_bbr = b'\x04\x00' + b'\x07' + b'\x00\x05' + struct.pack('!I', 3600)    # server 16, seqno, delay, timeout
nwd = []
nwd.append(has_route(1, 1) + has_route(0, 3))
nwd.append(prefix(0, 64, bytes.fromhex('fd00000000000001'), has_route() + border_router() + lowpan_id(0x11, 64)))
nwd.append(prefix(1, 0, b'', border_router(0, 1)))
nwd.append(prefix(0, 128, bytes.fromhex('fd000000000000010000000000000001'), lowpan_id(0x00, 128, 0)))
nwd.append(prefix(0, 7, b'\xfc'))
nwd.append(commissioning(tlv(11, b'\x12\x34') + tlv(8, b'\xff' * 4) + tlv(9, b'\x04\x00')) + commissioning(b''))
# Service TLVs: enterprise number present (T = 0), T = 1 with the BBR service
# data (decoded as a BBR server), SRP anycast, SRP unicast (short and long),
# an unknown one, each with a Server sub-TLV
nwd.append(service(0x01, 44970, b'\x01\x02', server(b'\x04\x00' + b'extra data')))
nwd.append(service(0x80 | 0x02, None, b'\x01', server(srv_bbr)))
nwd.append(service(0x80 | 0x03, None, b'\x5c\x09', server(b'\x08\x00' + b'\xaa\xbb')))
nwd.append(service(0x80 | 0x03, None, b'\x5d', server(b'\x08\x00' + bytes.fromhex('fd000000000000000000000000000077') + b'\x1f\x90' + b'xx')))
nwd.append(service(0x80 | 0x03, None, b'\x5d' + bytes.fromhex('fd000000000000000000000000000077') + b'\x1f\x90', server(b'\x08\x00' + b'\x01\x02')))
nwd.append(service(0x80 | 0x04, None, b'\x20', server(b'\x08\x00')))
nwd.append(service(0x80 | 0x04, None, b'\x20'))                     # no sub-TLV
nwd.append(server(srv_bbr))                                         # a top-level server TLV
nwd.append(tlv(0x7e, b'\x01\x02'))                                  # unknown TLV type 63
for p in nwd:
    add('thread_nwd', p)
add('thread_nwd', b''.join(nwd[:6]))
# Network data inside a Network Management message and an MLE-like Address Solicit
tmf(['a', 'as'], tlv(0, bytes.fromhex('fd0000000000000000000000000000bb')) + tlv(1, bytes.fromhex('0011223344556677')) + tlv(10, nwd[1]))

# ---- CoAP for TMF: every namespace, plus the ones that give no Thread dissector
MARKS.append((len(main) + 1, 'CoAP for TMF: every namespace, plus the ones that give no Thread dissector'))
tmf(['a', 'as'], tlv(0, bytes.fromhex('fd0000000000000000000000000000bb')) + tlv(1, bytes.fromhex('0011223344556677')))
tmf(['a', 'ar'], tlv(2, b'\x04\x00') + tlv(3, b'\x01' * 8) + tlv(4, b'\x00'), code=2, mid=2)
tmf(['a', 'aq'], tlv(0, bytes.fromhex('fd0000000000000000000000000000aa')), mid=3, token=b'\x51')
tmf(['n', 'dr'], tlv(0, bytes.fromhex('fd0000000000000000000000000000aa')) + tlv(3, b'\x01' * 8) + tlv(6, b'\0\0\x0e\x10'), mid=4)
tmf(['b', 'bq'], tlv(0, bytes.fromhex('fd0000000000000000000000000000aa')) + tlv(2, b'\x04\x00'), mid=5)
tmf(['d', 'dg'], tlv(0, bytes.fromhex('0011223344556677')) + tlv(1, b'\x04\x00'), mid=6)
tmf(['c', 'cg'], tlv(3, b'ThreadNet') + tlv(1, b'\x12\x34'), mid=7)
tmf(['c', 'ag'], tlv(13, bytes([0, 1, 2])) + tlv(11, b'\x00\x01'), mid=8)
tmf(['x', 'unknown'], b'\x01\x02\x03', mid=9)                       # no handler for the namespace "x"
tmf(['c'], b'\x01\x02\x03', mid=10)                                 # too few URI path segments
tmf(['c', 'cs'], b'', mid=11)                                       # no payload
tmf(['c', 'cs'], tlv(3, b'x'), mid=12, ct=False)                    # no content format: not Thread
# the Thread CoAP dissector by name, outside of a CoAP message (no CoAP info)
add('thread_coap', b'\x01\x02\x03\x04')
# the information element dissector by name has no data
add('thread_ie', b'\x00\x00\x00\x00')

# ---- IEEE 802.15.4 beacons (the "thread_wlan_beacon" heuristic)
MARKS.append((len(main) + 1, 'IEEE 802.15.4 beacons (the "thread_wlan_beacon" heuristic)'))
def beacon(src_short=0x0400, src_ext=None, payload=b'', fcf=None, seq=1):
    if src_ext is None:
        f = 0x8000 if fcf is None else fcf             # short source address, no destination
        hdr = struct.pack('<HBH', f, seq, 0xface) + struct.pack('<H', src_short)
        if fcf == 0:                                   # no addresses at all
            hdr = struct.pack('<HB', 0, seq)
    else:
        f = 0xc000 if fcf is None else fcf
        hdr = struct.pack('<HBH', f, seq, 0xface) + src_ext
    # superframe specification, GTS fields, pending addresses
    return hdr + struct.pack('<H', 0xcfff) + b'\x00' + b'\x00' + payload

def thread_bcn(flags=0x91, name=b'ThreadNet', xpan=None, tlvs=b''):
    p = bytes([0x03, flags]) + name.ljust(16, b'\0')
    if xpan is not None:
        p += xpan
        p += tlvs
    return p

XP = bytes.fromhex('dead00beef00cafe')
wp = lambda fr: main.append((WPAN, fr))
wp(beacon(payload=thread_bcn()))                                               # no extended PAN ID
wp(beacon(payload=thread_bcn(xpan=XP)))                                        # no TLV
wp(beacon(payload=thread_bcn(0x91 | 0x01 | 0x08, xpan=XP, tlvs=tlv(8, b'\xff' * 16))))
wp(beacon(src_ext=bytes.fromhex('0011223344556677'), payload=thread_bcn(0x11, xpan=XP, tlvs=tlv(8, b'\x00\x01'))))
wp(beacon(payload=thread_bcn(0x00, xpan=XP, tlvs=tlv(9, b'\x01\x02\x03'))))    # unknown TLV type
wp(beacon(payload=thread_bcn(0x00, xpan=XP, tlvs=tlv(8, b''))))                # zero length TLV

write_ng('thread-coverage.pcapng', main, (252, 230))
n_main = len(main)

# =============================================================== malformed
mal = []
def madd(name, payload): mal.append((EXP, exppdu(name, payload)))
# wrong lengths for every type of every TLV dissector
for name, types in (('thread_address', range(0, 16)), ('thread_nm', range(0, 16)), ('thread_bl', range(0, 16))):
    for t in types:
        for v in (b'', b'\x01', b'\x01\x02\x03', b'\x01' * 17, b'\x01' * 33):
            madd(name, tlv(t, v) + tlv(t, b'\x02' * 16))
for t in list(range(0, 72)) + [128, 129]:
    for v in (b'', b'\x01', b'\x01\x02\x03', b'\x01' * 7, b'\x01' * 17, b'\x01' * 70):
        madd('thread_meshcop', tlv(t, v) + tlv(0, b'\x00\x01\x02'))
madd('thread_meshcop', tlv(53, bytes([0, 0])) + tlv(57, b'\x01\x02'))   # an entry with no channels
# a decoded energy list followed by another TLV: the offset is advanced twice
madd('thread_meshcop', tlv(53, bytes([0, 4]) + struct.pack('!I', 0x07fff800)) + tlv(57, bytes(range(32))) + tlv(3, b'ThreadNet') + tlv(1, b'\x12\x34'))
# channel mask not an integer number of entries, 300 entries
madd('thread_meshcop', tlv(53, bytes([0, 5, 1, 2])) + tlv(57, b'\x01' * 6))
madd('thread_meshcop', tlv16(53, b'\x00\x01\xff' * 300) + tlv(57, b'\0' * 300))
# UDP encapsulation shorter than the ports
for n in range(0, 4):
    madd('thread_meshcop', tlv(48, b'\x16\x33\x16\x33'[:n]))
# 40 levels of UDP encapsulation
cur = coap(['c', 'ag'], tlv(1, b'\x12\x34'))
for _ in range(40):
    cur = coap(['c', 'ag'], tlv(48, struct.pack('!HH', 5683, 5683) + cur))
madd('thread_meshcop', tlv(48, struct.pack('!HH', 5683, 5683) + cur))
# network data with odd lengths and sub-TLVs, and deep prefix nesting
for t in range(0, 8):
    for v in (b'', b'\x01', b'\x01\x02\x03\x04\x05', b'\x01' * 10):
        madd('thread_nwd', tlv(t << 1, v) + tlv(2, b'\0\0\0\0'))
madd('thread_nwd', tlv(2, b'\x00\x80\x00\x00\x01\x00\x00') + tlv(2, b'\x04'))     # prefix of 128 bits cut short
deep = b''
for _ in range(60):
    deep = nwd_tlv(1, 1, b'\x00\x08\xfd' + deep)
madd('thread_nwd', deep)
madd('thread_nwd', nwd_tlv(5, 1, b'\x01\x00\x00\x00\x01\xff\x01'))                # S data length past the end
# truncated TLVs: the length goes past the end
for name in ('thread_address', 'thread_nm', 'thread_bl', 'thread_diagnostic', 'thread_meshcop', 'thread_nwd'):
    madd(name, b'\x02\x10\x01\x02')
    madd(name, b'\x02')
madd('thread_diagnostic', b'\x19\xff\x10')                                       # 16-bit length cut off
madd('thread_diagnostic', b'\x19\xff\x10\x00' + b'x' * 5)
# beacons: cut off after the network name, after the TLV header
mw = lambda fr: mal.append((WPAN, fr))
# beacons the heuristic does not take (they become 802.15.4 TLVs): first octet not 3, no source address
mw(beacon(payload=b'\x07\x00' * 20))
mw(beacon(payload=b'\x03\x02ab', fcf=0x0000))
mw(beacon(payload=bytes([3, 0x91]) + b'abc'))
mw(beacon(payload=thread_bcn(xpan=XP[:5])))
mw(beacon(payload=thread_bcn(xpan=XP, tlvs=b'\x08\x20\x01\x02')))
mw(beacon(payload=thread_bcn(xpan=XP, tlvs=b'\x08')))
write_ng('thread-coverage-malformed.pcapng', mal, (252, 230))
print(n_main, len(mal))
for m in MARKS:
    print(m, file=sys.stderr)
