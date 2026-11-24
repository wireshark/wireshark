# Generates test/captures/gdt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# shared helpers (copied into each generator)
import struct
import socket

def pcap(path, frames, linktype=1):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            orig = len(fr)
            if isinstance(fr, tuple):      # (captured bytes, original length)
                fr, orig = fr
            f.write(struct.pack('<IIII', 1700000000 + i // 1000, 1000 * (i % 1000), len(fr), orig))
            f.write(fr)

def _blk(t, body):
    pad = (-len(body)) % 4
    n = 12 + len(body) + pad
    return struct.pack('<II', t, n) + body + b'\0' * pad + struct.pack('<I', n)

def pcapng(path, idbs, frames):
    """idbs: list of linktypes; frames: list of (idb index, bytes)"""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in idbs:
        out += _blk(1, struct.pack('<HHI', lt, 0, 65535))
    for i, (ifc, fr) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += _blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(path, 'wb').write(out)

def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(src, dst, proto, payload, ident=1):
    h = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack('>H', csum(h)) + h[12:]
    return h + payload

def udp(sp, dp, payload):
    return struct.pack('>HHHH', sp, dp, 8 + len(payload), 0) + payload

def eth(dst, src, et, payload):
    return dst + src + struct.pack('>H', et) + payload

def tcpseg(src, dst, sp, dp, seq, ack, flags, payload=b'', ident=1, win=65535):
    """Ethernet/IPv4/TCP segment with correct checksums."""
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
    if flags == 0x02:
        ack = 0
    h = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opts) // 4) << 4, flags, win, 0, 0)
    h = h[:20] + opts
    ps = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('>BBH', 0, 6, len(h) + len(payload))
    c = csum(ps + h + payload)
    h = h[:16] + struct.pack('>H', c) + h[18:]
    return eth(bytes.fromhex('020000000002'), bytes.fromhex('020000000001'), 0x0800,
               ip4(src, dst, 6, h + payload, ident))

class Flow:
    """One TCP connection; client = 10.0.0.1, server = 10.0.0.2."""
    def __init__(self, cport, sport, frames, cip='10.0.0.1', sip='10.0.0.2', cseq=1000, sseq=5000):
        self.c, self.s, self.cp, self.sp, self.f = cip, sip, cport, sport, frames
        self.cseq, self.sseq = cseq, sseq
    def _send(self, from_client, flags, data=b''):
        if from_client:
            fr = tcpseg(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, flags, data)
            self.cseq += len(data) + (1 if flags & 3 else 0)
        else:
            fr = tcpseg(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, flags, data)
            self.sseq += len(data) + (1 if flags & 3 else 0)
        self.f.append(fr)
    def open(self):
        self._send(True, 0x02)
        self._send(False, 0x12)
        self._send(True, 0x10)
    def c2s(self, data): self._send(True, 0x18, data)
    def s2c(self, data): self._send(False, 0x18, data)
    def ack_c(self): self._send(True, 0x10)
    def ack_s(self): self._send(False, 0x10)
    def fin_s(self, data=b''): self._send(False, 0x19, data)
    def fin_c(self): self._send(True, 0x11)
    def close(self):
        self.fin_s(); self.fin_c(); self.ack_s()
import sys
import os

# ---- BER helpers (all tags in GDT are IMPLICIT)
def tlv(tag, val):
    l = len(val)
    if l < 128: ln = bytes([l])
    elif l < 256: ln = b'\x81' + bytes([l])
    else: ln = b'\x82' + struct.pack('>H', l)
    return bytes([tag]) + ln + val
def integer(n):
    b = n.to_bytes((n.bit_length() + 8) // 8, 'big', signed=True) if n >= 0 else n.to_bytes((( -n - 1).bit_length() + 8) // 8, 'big', signed=True)
    return tlv(0x02, b)
def octets(b): return tlv(0x04, b)
def seq(*items): return tlv(0x30, b''.join(items))
def ctx_prim(n, v): return tlv(0x80 | n, v)
def ctx_cons(n, *items): return tlv(0xa0 | n, b''.join(items))
def ctx_int(n, v): return ctx_prim(n, integer(v)[2:])

def endpoint(n, typ, ident=None):
    body = ctx_prim(1, typ)
    if ident is not None: body += ctx_prim(2, ident)
    return tlv(0xa0 | n, body)

def param(pid, values=None):
    items = integer(pid)
    if values is not None:
        items += seq(*[octets(v) for v in values])
    return seq(items)
def params(*ps): return seq(*ps)

def header(version=1, src=(b'stp', b'stp-1'), dst=(b'sgn', None), uuid=bytes(range(16)), seqn=5, flag=0,
           enc=None, hop=None, status=None):
    h = ctx_int(0, version) + endpoint(1, *src) + endpoint(2, *dst) + ctx_prim(3, uuid) + ctx_int(4, seqn) + ctx_int(5, flag)
    if enc is not None:
        h += ctx_cons(6, octets(enc[0]), *([enc[1]] if enc[1] is not None else []))
    if hop is not None:
        h += ctx_cons(7, ctx_int(1, hop[0]), ctx_int(2, hop[1]))
    if status is not None:
        h += ctx_int(8, status)
    return seq(h)

def msg(hdr, body=b''): return seq(hdr + body)

def action_body(n, action, ps=None):
    return ctx_cons(n, integer(action), *([ps] if ps is not None else []))

# ---- SCTP
def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return (~crc) & 0xffffffff

def sctp_packet(sport, dport, chunks):
    body = b''
    for payload, ppi, tsn, flags in chunks:
        ln = 16 + len(payload)
        body += struct.pack('>BBHIHHI', 0, flags, ln, tsn, 0, tsn & 0xffff, ppi) + payload + b'\0' * ((4 - ln % 4) % 4)
    hdr = struct.pack('>HHII', sport, dport, 0x11223344, 0)
    c = crc32c(hdr + body)
    hdr = hdr[:8] + struct.pack('<I', c)
    return hdr + body

def frame(sport, dport, chunks):
    return eth(bytes.fromhex('020000000002'), bytes.fromhex('020000000001'), 0x0800,
               ip4('10.0.0.1', '10.0.0.2', 132, sctp_packet(sport, dport, chunks)))

PPI = 49

def build(outdir):
    fr = []
    tsn = [100]
    def add(payload, ppi=PPI, sport=9000, dport=9001):
        tsn[0] += 1
        fr.append(frame(sport, dport, [(payload, ppi, tsn[0], 3)]))

    hdr = header()
    add(msg(hdr))                                                        # header only (the body is optional)
    # header variants
    add(msg(header(version=2, src=(b'a', None), dst=(b'b', b'id'), seqn=300, flag=1)))
    for flag in range(8):
        add(msg(header(flag=flag, seqn=flag)))
    for st in (0, 1, 2, 3, 4, 5, 6, 7, 255):
        add(msg(header(status=st, hop=(st & 3, 8))))
    add(msg(header(enc=(b'aes', params(param(6302, [b'\x01'])))), ctx_prim(1, b'\0' * 24)))   # encryption info with parameters
    add(msg(header(enc=(b'plain', None), hop=(1, 16), status=0), ctx_prim(1, b'x' * 200)))    # no parameters; 200 octet data (long form)
    add(msg(header(seqn=70000, version=70000)))                           # larger integers

    # bodies
    P = params(param(6000, [b'daemon']), param(6001, [b'id-1', b'id-2']), param(6004, [b'192.0.2.1']), param(500), param(6000 + 15, [b'', b'x']))
    add(msg(hdr, ctx_prim(1, b'encrypted payload')))                                           # encrypted-data
    add(msg(hdr, ctx_cons(2, integer(4), octets(b'\x45\x00' + bytes(20)), P)))                  # packet-fwd: payload type, payload, params
    add(msg(hdr, ctx_cons(2, integer(0))))                                                      # packet-fwd: payload type only
    add(msg(hdr, ctx_cons(2, integer(2000), octets(b'x'))))
    add(msg(hdr, action_body(3, 0, P)))                                                         # filter request
    add(msg(hdr, action_body(3, 1)))                                                            # filter result
    add(msg(hdr, ctx_cons(4, integer(11), octets(b'sms'), integer(0), P)))                      # data-retention: all fields
    add(msg(hdr, ctx_cons(4, integer(1))))                                                      # only the action (payload type and payload absent)
    add(msg(hdr, ctx_cons(4, octets(b'payload only'), integer(2))))                             # payload without type
    add(msg(hdr, ctx_cons(4, integer(8), integer(3), P)))
    for act in range(7):
        add(msg(hdr, ctx_cons(6, integer(act), octets(b'cfg'), params(param(7400, [b'name']), param(7401, [b'value'])))))   # conf
    add(msg(hdr, ctx_cons(6, integer(0))))
    add(msg(hdr, action_body(7, 0))); add(msg(hdr, action_body(7, 1, P)))                      # stats
    add(msg(hdr, action_body(8, 0, P))); add(msg(hdr, action_body(8, 1)))                      # auth
    add(msg(hdr, action_body(9, 0, P))); add(msg(hdr, action_body(9, 1)))                      # reg
    add(msg(hdr, ctx_cons(10, integer(3), octets(b'notify text'), P)))                         # ntfy
    add(msg(hdr, ctx_cons(10, integer(1))))
    for pt in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 1000):
        add(msg(hdr, ctx_cons(11, integer(pt), octets(b'data'), params(param(700, [b'\xc0\x00\x02\x01'])))))   # data
    add(msg(hdr, ctx_cons(11, integer(1))))
    for act in (0, 1, 2):
        add(msg(hdr, action_body(12, act, P)))                                                  # routing
    for sid in (42, 43, 44, 45, 46, 47):
        add(msg(hdr, ctx_cons(13, integer(sid), integer(sid & 3), P)))                          # service-msg
    add(msg(hdr, ctx_cons(13, integer(42), integer(0))))
    add(msg(hdr, ctx_cons(14, octets(b'machine'), integer(0), P)))                              # state-msg
    add(msg(hdr, ctx_cons(14, octets(b'machine'), integer(0))))

    # a spread of parameter types
    ids = [6000, 6010, 6020, 6100, 6116, 6200, 6203, 6300, 6302, 6400, 6403, 7400, 7418, 7500, 7501, 7600, 7605,
           600, 601, 700, 701, 800, 801, 900, 901, 1000, 1001, 500, 510, 530, 533, 3, 99999]
    add(msg(hdr, ctx_cons(2, integer(1), octets(b'ip'), params(*[param(i, [b'v%d' % i]) for i in ids]))))
    # two chunks in one SCTP packet; a message from another port pair
    tsn[0] += 2
    fr.append(frame(9000, 9001, [(msg(hdr), PPI, tsn[0] - 1, 3), (msg(hdr, ctx_prim(1, b'second')), PPI, tsn[0], 3)]))
    add(msg(hdr, ctx_prim(1, b'other ports')), sport=12345, dport=54321)
    # not GDT (another PPI)
    add(msg(hdr), ppi=0)
    # the pcapng with Exported PDU is not needed: GDT is reached through SCTP PPI 49
    pcap(os.path.join(outdir, 'gdt-coverage.pcap'), fr)

    m = []
    tsn[0] = 5000
    def bad(payload, sport=9000):
        tsn[0] += 1
        m.append(frame(sport, 9001, [(payload, PPI, tsn[0], 3)]))
    bad(b'')                                                              # empty
    bad(b'\x30')                                                          # truncated
    bad(seq(hdr[:20]))                                                    # truncated header
    bad(msg(hdr, ctx_cons(5, integer(0))))                                # unknown body choice [5]
    bad(msg(hdr, ctx_cons(15, integer(0))))                               # unknown body choice [15]
    bad(msg(hdr, tlv(0x04, b'wrong tag')))                                # not a context tag
    bad(seq(integer(1)))                                                  # header is not a sequence
    bad(msg(hdr, ctx_cons(2, octets(b'x'))))                              # payload type is not an integer
    bad(msg(hdr, ctx_cons(2, integer(1), octets(b'x'), seq(seq(octets(b'x'))))))   # parameter without an id
    bad(msg(hdr, ctx_cons(2, integer(1), octets(b'x'), seq(seq(integer(1), seq(integer(2)))))))   # value is not octet strings
    bad(msg(hdr, ctx_cons(14, integer(0), integer(0))))                  # state-msg: first field not an octet string
    bad(b'\x30\x84\xff\xff\xff\xff' + b'x' * 10)                          # length of 4 GiB
    bad(b'\x30\x80' + hdr + b'\x00\x00')                                  # indefinite length
    bad(msg(header(), ctx_cons(1, b'')))                                  # constructed octet string
    bad(msg(hdr[:-3] + b'\x00\x00\x00'))                                  # corrupt header end
    bad(tlv(0x30, hdr + hdr))                                            # two headers
    bad(msg(hdr, ctx_prim(1, b'x')) + b'trailing')                        # trailing data
    bad(seq(tlv(0x30, ctx_int(0, 1) + tlv(0xa1, ctx_prim(1, b'a')) )))      # header cut after the source
    bad(msg(hdr, ctx_cons(4, integer(1), integer(2), integer(3))))       # data retention: too many integers
    bad(msg(hdr, ctx_cons(6, integer(1), P_BAD := tlv(0x30, tlv(0x30, integer(1) + tlv(0x30, b'\x04\x80')))))) # nested garbage
    pcap(os.path.join(outdir, 'gdt-coverage-malformed.pcap'), m)

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
