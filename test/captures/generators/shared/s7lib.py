# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Helpers for building S7COMM PDUs (shared by the s7comm and s7comm_szl_ids generators)
import struct

def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(fr), len(fr)))
            f.write(fr)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(src, dst, proto, payload, ident=1):
    import socket
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def tcpseg(src, dst, sp, dp, seq, ack, flags, payload=b'', ident=1, win=65535):
    import socket
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
    if flags == 0x02:
        ack = 0
    h = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, win, 0, 0)
    h = h[:20] + opts
    ps = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 6, len(h) + len(payload))
    c = csum(ps + h + payload)
    h = h[:16] + struct.pack('>H', c) + h[18:]
    return (bytes.fromhex('020000000002') + bytes.fromhex('020000000001') + b'\x08\x00'
            + ip4(src, dst, 6, h + payload, ident))

class Flow:
    """One TCP connection; client = 192.0.2.1, server = 192.0.2.2 port 102."""
    def __init__(self, cport, frames, sport=102, cip='192.0.2.1', sip='192.0.2.2', cseq=1000, sseq=5000):
        self.c, self.s, self.cp, self.sp, self.f = cip, sip, cport, sport, frames
        self.cseq, self.sseq = cseq, sseq
        self.ident = 1
    def _send(self, from_client, flags, data=b''):
        self.ident += 1
        if from_client:
            fr = tcpseg(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, flags, data, self.ident)
            self.cseq += len(data) + (1 if flags & 3 else 0)
        else:
            fr = tcpseg(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, flags, data, self.ident)
            self.sseq += len(data) + (1 if flags & 3 else 0)
        self.f.append(fr)
    def open(self):
        self._send(True, 0x02); self._send(False, 0x12); self._send(True, 0x10)
    def c2s(self, data): self._send(True, 0x18, data)
    def s2c(self, data): self._send(False, 0x18, data)

# ---- TPKT / COTP -------------------------------------------------------
def tpkt(payload):
    return struct.pack('>BBH', 3, 0, 4 + len(payload)) + payload

def dt(s7, eot=True):
    return tpkt(bytes([2, 0xf0, 0x80 if eot else 0]) + s7)

def cotp_cr(src_ref, calling=b'\x01\x00', called=b'\x01\x02'):
    var = b'\xc0\x01\x0a' + b'\xc1' + bytes([len(calling)]) + calling + b'\xc2' + bytes([len(called)]) + called
    return tpkt(bytes([6 + len(var), 0xe0]) + struct.pack('>HHB', 0, src_ref, 0) + var)

def cotp_cc(dst_ref, src_ref, calling=b'\x01\x00', called=b'\x01\x02'):
    var = b'\xc0\x01\x0a' + b'\xc1' + bytes([len(calling)]) + calling + b'\xc2' + bytes([len(called)]) + called
    return tpkt(bytes([6 + len(var), 0xd0]) + struct.pack('>HHB', dst_ref, src_ref, 0) + var)

# ---- S7 PDUs -----------------------------------------------------------
def s7(rosctr, ref, param=b'', data=b'', err=(0, 0)):
    h = struct.pack('>BBHHHH', 0x32, rosctr, 0, ref, len(param), len(data))
    if rosctr in (2, 3):
        h += bytes(err)
    return h + param + data

def bcd(n): return ((n // 10) << 4) | (n % 10)

def ts8(y=24, mo=11, d=5, h=12, mi=30, s=45, ms=123, wd=3):
    """8 byte BCD time stamp (no reserved/year1 bytes)"""
    return bytes([bcd(y), bcd(mo), bcd(d), bcd(h), bcd(mi), bcd(s), bcd(ms // 10), ((ms % 10) << 4) | wd])

def ts10(y=24, mo=11, d=5, h=12, mi=30, s=45, ms=123, wd=3, res=0, y1=0x20):
    return bytes([res, y1]) + ts8(y, mo, d, h, mi, s, ms, wd)

# ---- items --------------------------------------------------------------
def item_any(tsize, length, db, area, addr):
    return bytes([0x12, 0x0a, 0x10, tsize]) + struct.pack('>HH', length, db) + bytes([area]) + addr.to_bytes(3, 'big')

def item_rec(mlen, index, rid, tsize=2):
    # S7ANY with the data record area 0x01
    return bytes([0x12, 0x0a, 0x10, tsize]) + struct.pack('>HHB', mlen, index, 0x01) + rid.to_bytes(3, 'big')

def item_dbread(areas):
    b = bytes([0x12, 2 + 5 * len(areas), 0xb0, len(areas)])
    for ln, db, st in areas:
        b += struct.pack('>BHH', ln, db, st)
    return b

def item_1200sym(area1, area2, crc, subs):
    b = bytes([0x12, 10 + 4 * len(subs), 0xb2, 0xff]) + struct.pack('>HHI', area1, area2, crc)
    for flags, val in subs:
        b += struct.pack('>I', (flags << 28) | val)
    return b

def item_nck(syn, area, unit, col, line, module, lcount):
    return bytes([0x12, 0x08, syn, (area << 5) | unit]) + struct.pack('>HHBB', col, line, module, lcount)

def item_drivees(u1, u2, u3, nr, idx):
    return bytes([0x12, 0x0a, 0xa2, u1]) + struct.pack('>HHHH', u2, u3, nr, idx)

def item_unknown(syn=0x99, body=b'\xaa\xbb\xcc'):
    return bytes([0x12, 1 + len(body), syn]) + body

def items_padded(items):
    out = b''
    for i, it in enumerate(items):
        out += it
        if len(it) % 2 and i < len(items) - 1:
            out += b'\0'
    return out

def dataitem(ret, tsize, payload, nbits=None, fill=False):
    """ret, tsize, length (bits when tsize is 3/4/5), data; fill adds the fill byte"""
    if nbits is None:
        nbits = len(payload) * (8 if tsize in (3, 4, 5) else 1)
    b = bytes([ret, tsize]) + struct.pack('>H', nbits) + payload
    return b + (b'\0' if fill else b'')

# ---- userdata -------------------------------------------------------------
def ud(typ, grp, sub, seq=0, payload=b'', ext=False, dur=0, last=0, err=0, ret=0xff, tsize=0x09,
       dlen=None, ref=1, rosctr=7, hdr=True, plen_extra=b''):
    """userdata PDU. typ 0 ind, 1 req, 2 res; hdr False omits the 4 byte return/size/length header."""
    tf = (typ << 6) | grp
    if ext:
        param = bytes([0, 1, 0x12, 8, 0x12, tf, sub, seq, dur, last]) + struct.pack('>H', err)
    else:
        param = bytes([0, 1, 0x12, 4, 0x11, tf, sub, seq])
    param += plen_extra
    if hdr:
        data = bytes([ret, tsize]) + struct.pack('>H', len(payload) if dlen is None else dlen) + payload
    else:
        data = payload
    return s7(rosctr, ref, param, data)

def tis(typ, sub, tp=b'', td=b'', tpn=None, tdn=None, **kw):
    pl = struct.pack('>HH', len(tp) if tpn is None else tpn, len(td) if tdn is None else tdn) + tp + td
    return ud(typ, 1, sub, payload=pl, **kw)
