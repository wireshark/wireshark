# Helper module for the isis_lsp capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Helper library: builds IS-IS PDUs (802.3/LLC or ethertype 0x22F4) into pcap files.
import struct
import gzip

def tlv(t, v):
    assert len(v) <= 255, (t, len(v))
    return bytes([t, len(v)]) + bytes(v)

def sidlen(idlen):
    return 6 if idlen == 0 else (0 if idlen == 255 else idlen)

def common(hdrlen, ptype, idlen=0, irpd=0x83, ver=1, ver2=1, res=0, maxarea=0):
    return bytes([irpd, hdrlen, ver, idlen, ptype, ver2, res, maxarea])

def sid(n, l=6):
    if l == 0:
        return b''
    return bytes([0x02, 0, 0, 0, 0, n & 0xff])[-l:] if l <= 6 else bytes(l - 6) + bytes([0x02, 0, 0, 0, 0, n & 0xff])

def fletcher(pdu, pos):
    """Return pdu with the ISO 8473 checksum written at byte offset pos."""
    b = bytearray(pdu)
    b[pos] = b[pos + 1] = 0
    c0 = c1 = 0
    for x in b:
        c0 = (c0 + x) % 255
        c1 = (c1 + c0) % 255
    L = len(b)
    p = pos + 1
    x = ((L - p) * c0 - c1) % 255
    y = (c1 - (L - p + 1) * c0) % 255
    if x == 0: x = 255
    if y == 0: y = 255
    b[pos], b[pos + 1] = x, y
    return bytes(b)

def hello(kind, tlvs, idlen=0, src=None, hold=30, circ=None, prio=0x40, lan=None, local=1,
          pdulen=None, hdrlen=None, ptype=None, **hdr):
    """kind: 1 = L1 LAN, 2 = L2 LAN, 3 = point to point."""
    n = sidlen(idlen)
    src = sid(1, n) if src is None else src
    circ = (3 if kind == 3 else kind) if circ is None else circ
    body = b''.join(tlvs)
    if kind == 3:
        fixed = bytes([circ]) + src + struct.pack('>H', hold) + b'\0\0' + bytes([local])
    else:
        lan = (sid(2, n) + b'\x01') if lan is None else lan
        fixed = bytes([circ]) + src + struct.pack('>H', hold) + b'\0\0' + bytes([prio]) + lan
    hl = 8 + len(fixed) if hdrlen is None else hdrlen
    pl = hl + len(body) if pdulen is None else pdulen
    pt = {1: 15, 2: 16, 3: 17}[kind] if ptype is None else ptype
    f = bytearray(fixed)
    off = 1 + n
    f[off + 2:off + 4] = struct.pack('>H', pl)
    return common(hl, pt, idlen, **hdr) + bytes(f) + body

def lsp(level, tlvs, idlen=0, lspid=None, seq=1, life=1200, flags=0x03, cksum=0, pdulen=None,
        hdrlen=None, ptype=None, **hdr):
    n = sidlen(idlen)
    lspid = (sid(1, n) + b'\0\0') if lspid is None else lspid
    body = b''.join(tlvs)
    fixed_len = 2 + 2 + n + 2 + 4 + 2 + 1
    hl = 8 + fixed_len if hdrlen is None else hdrlen
    pl = hl + len(body) if pdulen is None else pdulen
    pt = (18 if level == 1 else 20) if ptype is None else ptype
    fixed = struct.pack('>HH', pl, life) + lspid + struct.pack('>IH', seq, cksum) + bytes([flags])
    return common(hl, pt, idlen, **hdr) + fixed + body

def csnp(level, tlvs, idlen=0, src=None, start=None, end=None, pdulen=None, hdrlen=None,
         ptype=None, **hdr):
    n = sidlen(idlen)
    src = (sid(1, n) + b'\0') if src is None else src
    start = (bytes(n + 2)) if start is None else start
    end = (b'\xff' * (n + 2)) if end is None else end
    body = b''.join(tlvs)
    fixed_len = 2 + n + 1 + 2 * (n + 2)
    hl = 8 + fixed_len if hdrlen is None else hdrlen
    pl = hl + len(body) if pdulen is None else pdulen
    pt = (24 if level == 1 else 25) if ptype is None else ptype
    return common(hl, pt, idlen, **hdr) + struct.pack('>H', pl) + src + start + end + body

def psnp(level, tlvs, idlen=0, src=None, pdulen=None, hdrlen=None, ptype=None, **hdr):
    n = sidlen(idlen)
    src = (sid(1, n) + b'\0') if src is None else src
    body = b''.join(tlvs)
    fixed_len = 2 + n + 1
    hl = 8 + fixed_len if hdrlen is None else hdrlen
    pl = hl + len(body) if pdulen is None else pdulen
    pt = (26 if level == 1 else 27) if ptype is None else ptype
    return common(hl, pt, idlen, **hdr) + struct.pack('>H', pl) + src + body

def lsp_entry(n, seq, life=1000, cks=0x1234, idx=1, frag=0):
    return struct.pack('>H', life) + sid(idx, n) + bytes([0, frag]) + struct.pack('>IH', seq, cks)

def eth(isis, dst='0180c2000014', mode='llc'):
    if mode == 'llc':
        payload = b'\xfe\xfe\x03' + isis
        return bytes.fromhex(dst) + bytes.fromhex('020000000001') + struct.pack('>H', len(payload)) + payload
    return bytes.fromhex(dst) + bytes.fromhex('020000000001') + b'\x22\xf4' + isis

def write_pcap(name, frames):
    """frames: list of bytes (isis PDU, LLC) or (bytes, mode)."""
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(frames):
            mode = 'llc'
            if isinstance(p, tuple):
                p, mode = p
            snap = None
            if mode.startswith('snap'):       # 'snap:N': capture only the last N bytes less
                snap = int(mode[5:])
                mode = 'llc'
            fr = eth(p, mode=mode)
            if len(fr) < 60 and mode != 'llc':
                fr += bytes(60 - len(fr))
            cap = fr if snap is None else fr[:len(fr) - snap]
            f.write(struct.pack('<IIII', 1700000000 + i // 10, (i % 10) * 1000, len(cap), len(fr)))
            f.write(cap)

def gz(name):
    with open(name, 'rb') as f, gzip.GzipFile(name + '.gz', 'wb', mtime=0) as g:
        g.write(f.read())

# ---- TLV value builders shared by the generators ----
import socket

def ip4(*a):
    return bytes(a)

def ip6(s):
    return socket.inet_pton(socket.AF_INET6, s)

def area(*areas):
    return b''.join(bytes([len(a)]) + a for a in areas)

def with_checksum(pdu, marker=b'\x0c\x02\xab\xcd'):
    """Insert a valid ISO checksum where the marker TLV (type 12, value 0xabcd) is."""
    i = pdu.index(marker)
    return fletcher(pdu, i + 2)

CKSUM = b'\x0c\x02\xab\xcd'

def auth_clear(pw=b'secret'):
    return tlv(10, b'\x01' + pw)

def auth_md5(d=bytes(range(16))):
    return tlv(10, b'\x36' + d)

def auth_crypto(keyid, d):
    return tlv(10, b'\x03' + struct.pack('>H', keyid) + d)

def lsp_with_checksum(pdu, n=6):
    """Set a valid LSP checksum (computed from the LSP ID to the end of the PDU)."""
    pl = struct.unpack('>H', pdu[8:10])[0]
    region = bytearray(pdu[12:pl])
    pos = n + 2 + 4
    region = bytearray(fletcher(bytes(region), pos))
    return pdu[:12] + bytes(region) + pdu[pl:]

def f32(x):
    return struct.pack('>f', x)
