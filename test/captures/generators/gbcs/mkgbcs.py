# Generates test/captures/gbcs_coverage.pcapng.gz
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

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload

def zigbee(payload, to_client, seqn):
    """IEEE 802.15.4 (no FCS) data frame carrying ZigBee NWK, APS and a ZCL Tunneling TransferData command (profile SE, cluster 0x0704)."""
    src, dst = (0x0000, 0x0001) if to_client else (0x0001, 0x0000)
    mac = struct.pack('<HBHHH', 0x8841, seqn, 0x1234, dst, src)
    nwk = struct.pack('<HHHBB', 0x0008, dst, src, 30, seqn)
    aps = struct.pack('<BBHHBB', 0x00, 1, 0x0704, 0x0109, 1, seqn)
    zcl = bytes([0x09 if to_client else 0x01, seqn, 0x01 if to_client else 0x02]) + struct.pack('<H', 5) + payload
    return mac + nwk + aps + zcl

def ber_len(n):
    if n < 128: return bytes([n])
    if n < 256: return b'\x81' + bytes([n])
    return b'\x82' + struct.pack('>H', n)

def elem(v): return bytes([len(v)]) + v
def txid(cra, counter): return elem(bytes([cra]) + struct.pack('>Q', counter))
def eui(v): return elem(struct.pack('>Q', v))
NONE = b'\x00'
def dt(year=2024, mon=5, day=17, h=13, m=45, s=30):
    return elem(struct.pack('>HBBBBBBBhB', year, mon, day, 5, h, m, s, 0, 0, 0))

def other_info(code, rp_id=None, rp_cnt=None, orig_cnt=None, cert=b''):
    v = struct.pack('>H', code)
    if rp_id is not None: v += struct.pack('>Q', rp_id)
    if rp_cnt is not None: v += struct.pack('>Q', rp_cnt)
    if orig_cnt is not None: v += struct.pack('>Q', orig_cnt)
    return ber_len(len(v) + len(cert)) + v + cert

def grouping(payload, cra=1, counter=0x0102030405060708, orig=0x1111111111111111, target=0x2222222222222222,
             when=NONE, code=0x0007, **oi):
    h = b'\xdf' + txid(cra, counter) + eui(orig) + eui(target) + when + other_info(code, **oi)
    return h + ber_len(len(payload)) + payload

def krp(v=b''): return elem(v)
MAC = b'\x00' * 12                     # placeholder (all zero), not a real MAC

def mac_header(orig=NONE, target=NONE, when=NONE, other=NONE, key=NONE, sc=0x30, ic=1):
    return b'\xdd' + NONE + orig + target + when + other + key + b'\x05' + bytes([sc]) + struct.pack('>I', ic)

def signed(payload, cra=1, k=b'', **kw):
    return grouping(payload, cra=cra, **kw) + krp(k)

def ciphered(payload, cra=1, k=b'', mh=None, **kw):
    return (mh or mac_header()) + grouping(payload, cra=cra, **kw) + krp(k) + MAC

def routing_header(cra=1, counter=0x0102030405060708, orig=0x1111111111111111, target=0x2222222222222222, code=0x0007, ic=1):
    return (b'\xdd' + txid(cra, counter) + eui(orig) + eui(target) + NONE + b'\x02' + struct.pack('>H', code)
            + NONE + b'\x05' + b'\x30' + struct.pack('>I', ic))

def gbt(last, block, ack, payload, streaming=False, window=0, **kw):
    ctrl = (0x80 if last else 0) | (0x40 if streaming else 0) | (window & 0x3f)
    return routing_header(**kw) + b'\xe0' + bytes([ctrl]) + struct.pack('>HH', block, ack) + ber_len(len(payload)) + payload

# ---- GBZ
def zcl_read(cluster_attr=(0x0000, 0x0001)):
    return b''.join(struct.pack('<H', a) for a in cluster_attr)

def comp(cluster, payload, frame_ctrl=0x00, trans=1, cmd=0x00, date=None, last=False, enc=None, length=None):
    """A GBZ use case component. enc = (header control, frame counter, ciphered length, security control, invocation
    counter, encrypted payload (placeholder bytes), MAC (placeholder))."""
    ctrl = (0x10 if date is not None else 0) | (0x02 if enc else 0) | (0x01 if last else 0)
    body = b''
    if date is not None: body += struct.pack('>I', date)
    if enc:
        body += bytes([enc[0], enc[1]])
    body += bytes([frame_ctrl, trans, cmd])
    if enc:
        body += struct.pack('>HBI', enc[2], enc[3], enc[4]) + enc[5] + enc[6]
    else:
        body += payload
    return bytes([ctrl]) + struct.pack('>HH', cluster, len(body) if length is None else length) + body

def gbz(components, cra=1):
    return struct.pack('>HB', 0x0109, len(components)) + b''.join(components)

def alert(code, ts=0x2f000000, extra=b''):
    return struct.pack('>HBHI', 0x0109, 0, code, ts) + extra

ENC_PAYLOAD = bytes(range(32))         # placeholder octets standing for the ciphertext
ENC = (0x00, 0x01, 32, 0x30, 7, ENC_PAYLOAD, MAC)

# BER (ASN.1) payload for the generic BER dissector
def tlv(tag, v): return bytes([tag]) + ber_len(len(v)) + v
BER_PAYLOAD = tlv(0x30, tlv(0x02, b'\x05') + tlv(0x04, b'abc') + tlv(0x30, tlv(0x06, b'\x2a\x03\x04') + tlv(0x01, b'\xff')))

def build(outdir):
    f = []
    def add(name, payload): f.append((0, exp_pdu(name, payload)))
    M = 'gbcs_message'
    # --- general signing: commands, responses and alerts with each kind of payload
    gz1 = gbz([comp(0x0702, zcl_read(), last=True)])
    add(M, signed(gz1, cra=1, code=0x0007))                                   # command, GBZ with a plain component
    add(M, signed(gz1, cra=2, code=0x001A))                                   # response
    gz2 = gbz([comp(0x0702, zcl_read((0, 1, 2)), date=0x2f000000, trans=2), comp(0x0702, zcl_read(), trans=3, last=True)])
    add(M, signed(gz2, cra=1, code=0x0019, when=dt()))                        # two components, one with a from date/time, date time in the header
    gz3 = gbz([comp(0x0702, b'', enc=ENC, trans=4, last=True)])
    add(M, signed(gz3, cra=1, code=0x0008, rp_id=0x3333333333333333))         # encrypted component (placeholders), remote party id
    gz4 = gbz([comp(0x0702, b'', enc=(0x00, 2, 32, 0x30, 8, ENC_PAYLOAD, MAC), date=0x2f000001, last=True)])
    add(M, signed(gz4, cra=1, code=0x000A, rp_id=5, rp_cnt=6))                # encrypted with a from date/time, remote party counter
    add(M, signed(gz1, cra=1, code=0x000B, rp_id=5, rp_cnt=6, orig_cnt=7))
    add(M, signed(gz1, cra=1, code=0x000C, rp_id=5, rp_cnt=6, orig_cnt=7, cert=b'\x30\x82\x01\x00cert'))   # certificate
    add(M, signed(gz1, cra=1, code=0x0099))                                  # unknown use case
    add(M, signed(gz1, cra=1, code=0x0013, k=b'\xaa' * 64))                   # KRP present
    add(M, signed(gz1, cra=0x07, code=0x0004))                                # unknown CRA
    many = gbz([comp(0x0702, zcl_read(), trans=i, last=(i == 33)) for i in range(34)])
    add(M, signed(many, cra=1, code=0x0007))                                  # more components than subtrees (31)
    # alerts
    add(M, signed(alert(0x8F1C, extra=struct.pack('>H', 0x8000) + bytes(range(32))), cra=3, code=0x0000))      # firmware verification failed
    add(M, signed(alert(0x8F72, extra=struct.pack('>H', 0x8001) + bytes(range(32, 64))), cra=3, code=0x0000))    # firmware verification successful
    add(M, signed(alert(0x8F66, extra=bytes([0x0E]) + struct.pack('>HQHBB', 0x0019, 9, 0x0702, 0x01, 0x0b)), cra=3, code=0))   # future dated command success
    add(M, signed(alert(0x8F67, extra=bytes([0x00]) + b'\0' * 4), cra=3, code=0))                              # future dated, no 0x0E start
    add(M, signed(alert(0x8F0A, extra=comp(0x0702, zcl_read(), last=True)), cra=3, code=0))                    # billing data log updated (component)
    add(M, signed(alert(0x81A0, extra=struct.pack('>H', 0x0004)), cra=3, code=0))                              # integrity issue warning
    add(M, signed(alert(0x8F35), cra=3, code=0))                                                                 # alert without extra data
    add(M, signed(alert(0x0001), cra=3, code=0))                                                                 # unknown alert
    # --- general ciphering with a MAC header and trailer (all placeholders)
    add(M, ciphered(gz1, cra=1, code=0x0007))
    add(M, ciphered(gz1, cra=2, code=0x0007, k=b'\xbb' * 64,
                    mh=mac_header(orig=eui(0x4444444444444444), target=eui(0x5555555555555555), when=dt(), other=elem(b'oi'), key=elem(b'ki'))))
    # --- DLMS and ASN.1 payloads
    for first in (0xD9, 0xDA, 0x0F):
        add(M, signed(bytes([first]) + b'\x00\x01\x02\x03dlms', cra=1, code=0x0013))
    add(M, signed(BER_PAYLOAD, cra=1, code=0x0012))                           # ASN.1 (BER)
    add(M, ciphered(BER_PAYLOAD, cra=2, code=0x0012))
    # --- a message that is neither (first octet unknown)
    add(M, b'\x55\x00\x01\x02')
    # --- general block transfer
    inner = signed(gz1, cra=1, code=0x0007)
    third = len(inner) // 3
    parts = [inner[:third], inner[third:2 * third], inner[2 * third:]]
    for i, p in enumerate(parts):
        add(M, gbt(i == 2, i + 1, 0, p, window=3 if i == 0 else 0))
        if i < 2:
            add(M, gbt(False, 0, i + 1, b''))                                  # block transfer acknowledge (no data)
    add(M, gbt(True, 1, 0, signed(gz1, cra=2, code=0x001A), cra=2, counter=0x0a0b0c0d0e0f1011))   # a single block
    add(M, gbt(False, 1, 0, inner[:20], streaming=True, counter=0x0a0b0c0d0e0f1022))               # streaming, never completed
    add(M, gbt(True, 1, 0, ciphered(BER_PAYLOAD, cra=2, code=0x0012), cra=2, counter=0x0a0b0c0d0e0f1033, orig=0x6666666666666666))
    # the reproducer of the second pass recursion: block 1 (last) holds a not-last block 1 of the same message
    rh = routing_header()
    p1 = gbt(False, 1, 0, b'\xaa' * 8)
    add(M, gbt(True, 1, 0, p1))
    # --- tunnel
    T = 'gbcs_tunnel'
    add(T, b'\x01')                                                         # GET
    add(T, b'\x02\x03' + signed(gz1, cra=2, code=0x001A))                   # GET-RESPONSE, 3 remaining
    add(T, b'\x02\x00' + gbt(True, 1, 0, signed(gz1, cra=2, code=0x001A), cra=2, counter=0x0a0b0c0d0e0f1044))   # response carrying a block
    add(T, b'\x03' + signed(gz1, cra=1, code=0x0007))                       # PUT
    add(T, signed(gz1, cra=1, code=0x0019))                                 # no tunnel header (0xDF)
    add(T, b'\x09\x01\x02')                                                  # no tunnel header, unknown command
    add(T, b'\x03')                                                          # PUT without data
    # --- the same through the ZigBee SE tunneling cluster (IEEE 802.15.4 frames, interface 1)
    z = []
    z.append(zigbee(b'\x01', False, 1))                                                 # GET
    z.append(zigbee(b'\x02\x01' + signed(gz1, cra=2, code=0x001A), True, 2))            # GET-RESPONSE
    z.append(zigbee(b'\x03' + signed(gz1, cra=1, code=0x0007), False, 3))               # PUT
    z.append(zigbee(signed(gz1, cra=1, code=0x0019), True, 4))                           # no tunnel header, 0xDF
    z.append(zigbee(gbt(True, 1, 0, signed(gz1, cra=2, code=0x001A), cra=2, counter=0x0a0b0c0d0e0f1055), True, 5))   # no tunnel header, 0xDD block
    z.append(zigbee(b'\x55\x01\x02\x03', True, 6))                                      # not GBCS: the heuristic does not accept it
    f.extend((1, x) for x in z)
    # --- the reproducers of "GBCS: Check GBZ component length against the header": components whose length is
    # too small for their own header (warning, the component is skipped)
    for ctrl, lens in ((0x00, (0, 1, 2)), (0x10, (0, 3, 6)), (0x02, (0, 5, 12, 23)), (0x12, (0, 10, 27))):
        for L in lens:
            add(M, grouping(struct.pack('>HB', 0x0109, 1) + bytes([ctrl]) + struct.pack('>HH', 0x0702, L) + bytes(range(L)), cra=1) + krp())
    pcapng(os.path.join(outdir, 'gbcs-coverage.pcapng'), [252, 230], f)

    # --- the reproducers of the component length fix and malformed input
    m = []
    def madd(name, payload): m.append((0, exp_pdu(name, payload)))
    def g_(c): return grouping(struct.pack('>HB', 0x0109, 1) + c, cra=1)
    for L in range(0, 26):
        madd(M, g_(bytes([0x03]) + struct.pack('>HH', 0x0702, L) + bytes(range(40))) + krp())     # encrypted, length too small
        madd(M, g_(bytes([0x11]) + struct.pack('>HH', 0x0702, L) + bytes(range(40))) + krp())          # from date/time, plain
        madd(M, g_(bytes([0x13]) + struct.pack('>HH', 0x0702, L) + bytes(range(40))) + krp())          # both
    madd(M, g_(bytes([0x00]) + struct.pack('>HH', 0x0702, 60) + bytes(10)) + krp())                    # length beyond the data
    madd(M, g_(bytes([0x00]) + struct.pack('>HH', 0x0702, 1) + bytes(1)) + krp())
    madd(M, grouping(struct.pack('>HBHI', 0x0109, 0, 0x8F1C, 0) + b'\0' * 5, cra=3))   # firmware alert cut short
    madd(M, grouping(struct.pack('>HBHI', 0x0109, 0, 0x8F0A, 0), cra=3))                                # billing alert without component
    madd(M, grouping(struct.pack('>HBH', 0x0109, 0, 0x8F1C), cra=3))
    madd(M, b'\xdf')                                                        # only the first octet
    madd(M, b'\xdf\x09\x01')                                                # transaction id cut short
    madd(M, b'\xdd')
    madd(M, b'\xdd\x00')
    madd(M, b'\xdd\x09\x01\x00\x00')
    madd(M, grouping(b'')[:-1])
    madd(M, grouping(b'\x01', code=0x0007)[:-3])
    madd(M, grouping(b'\x01' * 20)[:-5])                                    # payload longer than the message
    madd(M, grouping(b'\x01\x09\x01')[:-1])
    madd(M, grouping(BER_PAYLOAD) + b'\x00' * 3)                            # KRP and MAC missing... (signing): KRP length byte 0
    madd(M, gbt(True, 1, 0, b'x' * 30)[:-10])                               # block shorter than announced
    madd(M, gbt(True, 0, 0, b'x' * 5))                                      # block number 0 (block_number - 1 wraps)
    madd(M, gbt(False, 5, 0, b'x' * 5))
    madd(M, gbt(True, 3, 0, b'x' * 5))                                      # last block that is not block 1 (missing earlier blocks)
    madd(M, gbt(False, 1, 0, b'a' * 40, counter=0x0b0b0b0b0b0b0b0b)); madd(M, gbt(False, 1, 0, b'a' * 40, counter=0x0b0b0b0b0b0b0b0b))   # same block twice
    madd(M, gbt(False, 2, 0, b'b' * 8, counter=0x0b0b0b0b0b0b0b0b)); madd(M, gbt(True, 4, 0, b'c' * 8, counter=0x0b0b0b0b0b0b0b0b))      # gap in the sequence
    madd(M, grouping(b'\x30\x84\xff\xff\xff\xff', code=7))                  # BER with a length of 4 GiB
    madd(M, grouping(b'\x30\x03\x02\x01'))                                  # BER cut short
    madd(M, grouping(b'\xd9'))
    madd(M, grouping(b'\x01\x09'))                                          # starts like the SE profile
    madd(M, grouping(struct.pack('>H', 0x0109)))                            # GBZ without a component count
    madd(M, grouping(struct.pack('>HB', 0x0109, 1) + b'\x00\x07\x02'))     # component header cut short
    madd(M, b'\xdf' + txid(1, 1) + b'\xff')                                 # element length beyond the message
    madd(M, b'\xdf' + txid(1, 1) + eui(1) + eui(2) + b'\x0c' + b'\x07\xe8')  # date time cut short
    madd(M, b'\xdf' + txid(1, 1) + eui(1) + eui(2) + NONE + b'\x84\xff\xff\xff\xff')   # other information with a 4 GiB length
    madd(M, b'\xdf' + txid(1, 1) + eui(1) + eui(2) + NONE + b'\x01\x00')   # other information shorter than the message code (length 1)
    madd(M, b'\xdf' + txid(1, 1) + eui(1) + eui(2) + NONE + b'\x00')       # other information of length 0
    madd(T, b'')                                                            # empty tunnel packet
    pcapng(os.path.join(outdir, 'gbcs-coverage-malformed.pcapng'), [252], m)

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
