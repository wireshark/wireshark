# Helper module for the umts_fp capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
import struct
def exp_pdu(proto, payload):
    # EXP_PDU_TAG_DISSECTOR_NAME = 12, then the end-of-options tag
    name = proto.encode()
    name += b'\0' * (-len(name) % 4)
    return struct.pack('>HH', 12, len(name)) + name + struct.pack('>HH', 0, 0) + payload

def crc7(data):
    r = 0
    for b in data:
        for i in range(7, -1, -1):
            top = ((r >> 6) & 1) ^ ((b >> i) & 1)
            r = (r << 1) & 0x7f
            if top:
                r ^= 0x45
    return r

def crc16(data):
    r = 0
    for b in data:
        r ^= b << 8
        for _ in range(8):
            r = ((r << 1) ^ 0x8005) & 0xffff if r & 0x8000 else (r << 1) & 0xffff
    return r

def fp_frame(hdr, payload=b'', tail=b'', pcrc=True):
    """FP data frame: byte 0 = header CRC (7 bits) + frame type 0, then hdr
    (covered by the CRC), the transport block payload, an optional trailer
    and the payload CRC."""
    b0 = crc7(hdr) << 1
    f = bytes([b0]) + hdr + payload + tail
    if pcrc:
        f += struct.pack('>H', crc16(payload))
    return f

def fp_control(ftype, body=b''):
    """UMTS FP control frame: the header CRC covers the whole frame with
    the first octet reduced to the frame type bit"""
    rest = bytes([ftype]) + body
    return bytes([(crc7(bytes([1]) + rest) << 1) | 1]) + rest

# ---- hint header builders
UOFF = 0

def rb_entry(urnti, rlc=0, content=0, rbid=0, ctmux=0, ciph=0, deciph=0):
    urnti = urnti + UOFF if urnti else 0
    b4 = (rlc & 3) | ((content & 3) << 2) | ((rbid & 0xf) << 4)
    b5 = ((rbid >> 4) & 1) | (ctmux << 1) | (ciph << 2) | (deciph << 3)
    return struct.pack('<IBBH', urnti, b4, b5, 0)

def blk(count, size, extra=0):
    """4 octet transport format as used by PCH, RACH and FACH: block
    count (9 bits), block size (13 bits) and the PICH length (3 bits)"""
    v = (count & 0x1ff) | ((size & 0x1fff) << 9) | ((extra & 7) << 22)
    return struct.pack('<I', v)

def tf4(dch_id, n, size):
    """DCH transport format: DCH id (5 bits), N (9 bits), size (13+ bits)"""
    v = (dch_id - 1) & 0x1f
    v |= (n & 0x1ff) << 5
    v |= (size & 0x1fff) << 14
    return struct.pack('<I', v)

ATM, ETH = 0, 1
PCH, RACH, FACH, DCH, HSDSCH, EDCH = range(6)

def hint(frame_type, channel, body, pdu, cid=5, vpi=1, vci=33, hdrlen=None):
    """hint header + AAL2/ATM header or nothing + pdu"""
    hl = 4 + len(body) if hdrlen is None else hdrlen
    h = struct.pack('<HBB', hl, frame_type, channel) + body
    if frame_type == ATM:
        h += struct.pack('>II', cid, (vpi << 20) | (vci << 4))
    return h + pdu

def eth_frame(payload=b'\x01\x02\x03\x04'):
    udp = struct.pack('>HHHH', 3000, 3001, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2)))
    s = sum(struct.unpack('>10H', ip))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack('>H', (~s) & 0xffff) + ip[12:] + udp
    f = b'\x02\0\0\0\0\x02\x02\0\0\0\0\x01\x08\x00' + ip
    import zlib
    return f + struct.pack('<I', zlib.crc32(f))

def data(n, seed=0):
    return bytes((seed + 7 * i + 1) & 0xff for i in range(n))

P = lambda h: exp_pdu('fp_hint', h)
SEEDS = {"fach1": 2, "fach2": 2, "rach1": 63, "rach2": 63}
names = []
main, mal = [], []
BUILDERS = []
def add(lst, name, fn):
    """fn(seed) -> exported PDU record"""
    if lst is main:
        names.append(name)
        BUILDERS.append((name, fn))
    lst.append(P(fn(SEEDS.get(name, 0))))

def tbdata(n, seed):
    return data(n, seed)

# ---- PCH.  The first frame carries the paging indication bitmap, which
# the following frames with transport blocks refer to.
def pch_fp(pi, tfi, bitmap, tbs):
    return fp_frame(bytes([0x11, pi & 1, tfi]), bitmap + tbs)

add(main, 'pch_bm0', lambda sd: hint(ATM, PCH, blk(0, 0, 0), pch_fp(1, 0, b'\xa5' * 3, b'')))
add(mal, 'pch_tb0', lambda sd: hint(ATM, PCH, blk(1, 64, 0), pch_fp(0, 1, b'', tbdata(8, sd))))
add(main, 'pch_bm1', lambda sd: hint(ATM, PCH, blk(0, 0, 1), pch_fp(1, 0, b'\x5a' * 5, b'')))
add(mal, 'pch_tb1', lambda sd: hint(ATM, PCH, blk(1, 64, 1), pch_fp(1, 1, b'\x5a' * 5, tbdata(8, sd))))
add(main, 'pch_bm2', lambda sd: hint(ATM, PCH, blk(0, 0, 2), pch_fp(1, 0, b'\x3c' * 9, b'')))
add(main, 'pch_bm3', lambda sd: hint(ATM, PCH, blk(0, 0, 3), pch_fp(1, 0, b'\xc3' * 18, b'')))
add(main, 'pch_nopi', lambda sd: hint(ATM, PCH, blk(0, 0, 4), pch_fp(0, 0, b'', b'')))   # PICH value 4: unknown

# ---- RACH / FACH / DCH with radio bearers
def rach_fp(cfn, tb):
    return fp_frame(bytes([cfn, 0, 4]), tb + b'\x00')
def fach_fp(cfn, tb):
    return fp_frame(bytes([cfn, 0, 20]), tb)
def dch_fp(cfn, tfis, tbs):
    return fp_frame(bytes([cfn]) + bytes(tfis), tbs)

R = rb_entry
add(main, 'rach1', lambda sd: hint(ATM, RACH, blk(1, 64) + b'\x01' + R(0x1001, 2, 1, 3, 0, 0, 0),
                                   rach_fp(10, tbdata(8, sd))))
add(main, 'rach2', lambda sd: hint(ATM, RACH, blk(1, 64) + b'\x02' + R(0x1002, 3, 2, 4, 1, 1, 1)
                                   + R(0, 1, 3, 17, 0, 0, 1), rach_fp(11, tbdata(8, sd))))
add(main, 'fach1', lambda sd: hint(ATM, FACH, blk(1, 64) + b'\x01' + R(0x2001, 2, 1, 3, 0, 0, 0),
                                   fach_fp(12, tbdata(8, sd))))
add(main, 'fach2', lambda sd: hint(ATM, FACH, blk(1, 64) + b'\x03' + R(0x2002, 3, 2, 31, 1, 0, 1)
                                   + R(0x2003, 1, 3, 5, 0, 1, 1) + R(0x2004, 0, 0, 0, 1, 0, 0),
                                   fach_fp(13, tbdata(8, sd))))
add(main, 'dch1', lambda sd: hint(ATM, DCH, b'\x01' + tf4(1, 1, 64) + b'\x01' + R(0x3001, 2, 1, 3, 1, 0, 0),
                                  dch_fp(20, [0], tbdata(8, sd))))
add(main, 'dch2', lambda sd: hint(ATM, DCH, b'\x02' + tf4(1, 1, 40) + tf4(5, 1, 24) + b'\x01'
                                  + R(0x3002, 3, 1, 1, 0, 1, 1), dch_fp(21, [0, 0], tbdata(8, sd))))
add(main, 'dch3', lambda sd: hint(ATM, DCH, b'\x01' + tf4(2, 1, 64) + b'\x02' + R(0x3003, 3, 3, 2, 1, 0, 0)
                                  + R(0x3004, 0, 1, 6, 0, 0, 0), dch_fp(22, [0], tbdata(8, sd))))
# size 0x1fff means no transport block data: the size is not shown
add(main, 'dch_empty', lambda sd: hint(ATM, DCH, b'\x01' + tf4(2, 0, 0x1fff) + b'\x01' + R(0x3005, 3, 1, 3, 0, 0, 0),
                                       dch_fp(23, [0], b'')))
# three channels, one with two transport blocks
add(main, 'dch_multi', lambda sd: hint(ATM, DCH, b'\x03' + tf4(1, 2, 32) + tf4(3, 0, 0) + tf4(7, 1, 16) + b'\x01'
                                       + R(0x3006, 0, 1, 3, 1, 0, 0), dch_fp(24, [0, 0, 0], tbdata(10, sd))))
# a content value of 0 (unknown)
add(main, 'dch_unknown', lambda sd: hint(ATM, DCH, b'\x01' + tf4(3, 1, 64) + b'\x01' + R(0x3007, 0, 0, 0, 0, 0, 0),
                                         dch_fp(25, [0], tbdata(8, sd))))

# ---- HS-DSCH and E-DCH: the hint attaches the info, and control frames
# (valid header CRC) are decoded by FP
add(main, 'hs_ctl1', lambda sd: hint(ATM, HSDSCH, b'\x01\x00', fp_control(3, b'\x00')))
add(main, 'hs_ctl2', lambda sd: hint(ATM, HSDSCH, b'\x09\x01' + R(0x4001, 2, 1, 3, 0, 0, 0), fp_control(1, b'\x05')))
add(main, 'hs_ctl3', lambda sd: hint(ATM, HSDSCH, b'\x0b\x02' + R(0x4002, 3, 2, 4, 1, 0, 0) + R(0x4003, 3, 1, 1, 0, 1, 1),
                                     fp_control(6, b'\x01\x02\x03')))
add(main, 'ed_ctl1', lambda sd: hint(ATM, EDCH, b'\x01\x00\x00', fp_control(3, b'\x00')))
add(main, 'ed_ctl2', lambda sd: hint(ATM, EDCH, b'\x02\x02' + bytes([1, 3]) + struct.pack('<H', 336)
                                     + bytes([2, 4]) + struct.pack('<H', 144) + b'\x01' + R(0x5001, 2, 1, 3, 0, 0, 0),
                                     fp_control(1, b'\x05')))
add(main, 'ed_ctl3', lambda sd: hint(ATM, EDCH, b'\x03\x03' + bytes([1, 3]) + struct.pack('<H', 336) * 1
                                     + bytes([2, 4]) + struct.pack('<H', 144) + bytes([3, 5]) + struct.pack('<H', 0)
                                     + b'\x00', fp_control(6, b'\x01\x02\x03')))
# control frames on the other channel types
add(main, 'pch_ctl', lambda sd: hint(ATM, PCH, blk(0, 0, 0), fp_control(1, b'\x05')))
add(main, 'dch_ctl', lambda sd: hint(ATM, DCH, b'\x01' + tf4(1, 1, 64) + b'\x00', fp_control(1, b'\x05')))

# ---- unknown channel type, unknown frame type
add(main, 'chan_unknown', lambda sd: hint(ATM, 9, b'', fp_control(1, b'\x05')))
add(main, 'frame_unknown', lambda sd: hint(7, DCH, b'\x01' + tf4(1, 1, 8) + b'\x00', data(8, 0)))
# ---- Ethernet frame type: the Ethernet frame (with FCS) holds a UDP datagram
add(main, 'eth_dch', lambda sd: hint(ETH, DCH, b'\x01' + tf4(1, 1, 8) + b'\x00', eth_frame()))
add(main, 'eth_pch', lambda sd: hint(ETH, PCH, blk(0, 0), eth_frame(b'\x10\x20\x30')))

# ---- malformed / unsupported
# no radio bearer info: MAC and RLC miss their per-frame info
add(mal, 'rach_norb', lambda sd: hint(ATM, RACH, blk(1, 64) + b'\x00', rach_fp(10, tbdata(8, 0))))
add(mal, 'fach_norb', lambda sd: hint(ATM, FACH, blk(1, 64) + b'\x00', fach_fp(10, tbdata(8, 0))))
add(mal, 'dch_norb', lambda sd: hint(ATM, DCH, b'\x01' + tf4(1, 1, 64) + b'\x00', dch_fp(10, [0], tbdata(8, 0))))
add(mal, 'hs_norb', lambda sd: hint(ATM, HSDSCH, b'\x01\x00', data(8)))
add(mal, 'ed_norb', lambda sd: hint(ATM, EDCH, b'\x01\x00\x00', data(8)))
# more radio bearers than supported (64) -> warning, in all channel types
rbs = b''.join(R(0x6000 + i, 2, 1, i & 31, 0, 0, 0) for i in range(65))
add(mal, 'rach_many_rb', lambda sd: hint(ATM, RACH, blk(1, 64) + b'\x41' + rbs, rach_fp(10, tbdata(8, 0))))
add(mal, 'dch_many_rb', lambda sd: hint(ATM, DCH, b'\x01' + tf4(1, 1, 64) + b'\x41' + rbs, dch_fp(10, [0], tbdata(8, 0))))
# more FP channels than supported (65) -> warning
tfs = b''.join(tf4((i % 31) + 1, 0, 0) for i in range(65))
add(mal, 'dch_many_ch', lambda sd: hint(ATM, DCH, b'\x41' + tfs + b'\x00', dch_fp(10, [0] * 65, b'')))
# more E-DCH DDIs than supported (17)
ddis = b''.join(bytes([i, 3]) + struct.pack('<H', 336) for i in range(17))
add(mal, 'ed_many_ddi', lambda sd: hint(ATM, EDCH, b'\x01\x11' + ddis + b'\x00', fp_control(1, b'\x05')))
# truncated hints and headers
add(mal, 'short1', lambda sd: struct.pack('<H', 4))
add(mal, 'short2', lambda sd: struct.pack('<HBB', 4, 0, DCH))
add(mal, 'short_dch', lambda sd: struct.pack('<HBB', 8, 0, DCH) + b'\x03\x00\x00')
add(mal, 'short_ed', lambda sd: struct.pack('<HBB', 8, 0, EDCH) + b'\x03\x05\x01\x02')
add(mal, 'short_rb', lambda sd: struct.pack('<HBB', 12, 0, RACH) + blk(1, 64) + b'\x01' + b'\x01\x02')
add(mal, 'short_pch', lambda sd: struct.pack('<HBB', 6, 0, PCH) + b'\x01\x02')
# header length beyond the packet, and too short for the ATM header
add(mal, 'hdrlen_big', lambda sd: struct.pack('<HBB', 0xfff0, 0, 9) + b'\x00' * 8)
add(mal, 'no_atm', lambda sd: struct.pack('<HBB', 4, 0, 9) + b'\x00\x00')
add(mal, 'eth_short', lambda sd: struct.pack('<HBB', 4, 1, 9) + b'\x00\x00')
