#!/usr/bin/env python3
# Generates test/captures/uet_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate the UET coverage captures. Usage: mkuet.py <outdir>
#
# Ultra Ethernet Transport over UDP port 4793 (the default), over IPv6, and
# directly over IP protocol 253 with the entropy header (Decode As,
# -d ip.proto==253,uet). Every frame ends with a 4 byte CRC (the
# has_crc preference is on by default); the frames of the CRC section carry
# CRC32C values computed over the bytes the specification names (a plain
# error-detecting code, no keys), good and bad ones, for uet.validate_crc.
import os
import struct
import sys

# ---------------------------------------------------------------- CRC32C
def _table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        t.append(c)
    return t
T = _table()
def crc32c(data, crc=0xffffffff):
    for b in data:
        crc = T[(crc ^ b) & 0xff] ^ (crc >> 8)
    return crc

# ------------------------------------------------------------- frame tools
def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

ETH4 = bytes.fromhex('020000000002' '020000000001') + b'\x08\x00'
ETH6 = bytes.fromhex('020000000002' '020000000001') + b'\x86\xdd'
A4, B4 = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
A6 = bytes.fromhex('fd000000000000000000000000000001')
B6 = bytes.fromhex('fd000000000000000000000000000002')

def uet_crc(prefix, uet_wo_crc):
    """CRC over: source address onwards (here prefix) + zero checksum +
    the UET bytes; stored big endian."""
    return struct.pack('>I', (~crc32c(prefix + uet_wo_crc)) & 0xffffffff)

def udp4(uet, crc=None, sport=4793, dport=4793, ident=1):
    if crc is None:
        crc = b'\xde\xad\xbe\xef'
    elif crc == 'good':
        crc = uet_crc(A4 + B4 + struct.pack('>HHH', sport, dport, 8 + len(uet) + 4)
                      + b'\0\0', uet)
    elif crc == 'bad':
        crc = uet_crc(A4 + B4 + struct.pack('>HHH', sport, dport, 8 + len(uet) + 4)
                      + b'\0\0', uet)[::-1]
    u = struct.pack('>HHHH', sport, dport, 8 + len(uet) + 4, 0) + uet + crc
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), ident, 0, 64, 17, 0, A4, B4)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return ETH4 + ip + u

def udp6(uet, crc=None, sport=4793, dport=4793):
    if crc is None:
        crc = b'\xde\xad\xbe\xef'
    elif crc in ('good', 'bad'):
        want = crc
        crc = uet_crc(A6 + B6 + struct.pack('>HHH', sport, dport, 8 + len(uet) + 4)
                      + b'\0\0', uet)
        if want == 'bad':
            crc = crc[::-1]
    body = uet + crc
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(body), 0)
    pseudo = A6 + B6 + struct.pack('>IBBBB', 8 + len(body), 0, 0, 0, 17)
    ck = csum(pseudo + hdr + body) or 0xffff
    pl = struct.pack('>HHHH', sport, dport, 8 + len(body), ck) + body
    ip = struct.pack('>IHBB16s16s', 0x60000000, len(pl), 17, 64, A6, B6)
    return ETH6 + ip + pl

def ipproto(uet, crc=None, proto=253):
    """UET with entropy header directly over IPv4 (ip.proto 253); crc 'good'
    covers the addresses and the UET bytes without a UDP header."""
    if crc is None:
        crc = b'\xde\xad\xbe\xef'
    elif crc == 'good':
        crc = uet_crc(A4 + B4, uet)
    elif crc == 'bad':
        crc = uet_crc(A4 + B4, uet)[::-1]
    pl = uet + crc
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(pl), 1, 0, 64, proto, 0, A4, B4)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return ETH4 + ip + pl

def write(fn, frames, t0=1700000000):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, p in enumerate(frames):
            pk, orig = p if isinstance(p, tuple) else (p, len(p))
            f.write(struct.pack('<IIII', t0 + i // 100, (i % 100) * 10000, len(pk), orig))
            f.write(pk)

# --------------------------------------------------------------- PDS / SES
T_RESERVED, T_TSS, T_RUD, T_ROD, T_RUDI, T_RUDI_RESP, T_UUD, T_ACK, T_ACK_CC, \
    T_ACK_CCX, T_NACK, T_CTRL, T_NACK_CCX, T_RUD_CC, T_ROD_CC = range(15)
NH_NONE, NH_SMALL, NH_MED, NH_STD, NH_RSP, NH_RSP_DATA, NH_RSP_DATA_SMALL = range(7)
RETX, AR, SYN = 0x10, 0x08, 0x04

def pro(t, nh, flags=0):
    return struct.pack('>H', (t << 11) | (nh << 7) | flags)

def rud_req(t, nh, ses=b'', flags=0, clear=-3, psn=1000, spd=0x1111, dpd=0x2222,
            ccc=0x07, credit=0x010203, psn_off=5, payload=b''):
    h = pro(t, nh, flags) + struct.pack('>hI', clear, psn) + struct.pack('>H', spd)
    if flags & SYN:
        h += struct.pack('>H', 0x8000 | psn_off)
    else:
        h += struct.pack('>H', dpd)
    if t in (T_RUD_CC, T_ROD_CC):
        h += bytes([ccc]) + struct.pack('>I', credit)[1:]
    return h + ses + payload

def rudi(t, nh, ses=b'', pkt_id=77, payload=b''):
    return pro(t, nh) + struct.pack('>HI', 0, pkt_id) + ses + payload

def uud(nh, ses=b'', payload=b''):
    return pro(T_UUD, nh) + b'\0\0' + ses + payload

def ack(t, nh=NH_NONE, ses=b'', flags=0, ack_off=2, cack=500, spd=0x1111, dpd=0x2222,
        cc_type=0, mpr=8, sack_off=-1, bitmap=0x00000000000000ff, cc_state=None, ccx=None,
        payload=b''):
    h = pro(t, nh, flags) + struct.pack('>hIHH', ack_off, cack, spd, dpd)
    if t in (T_ACK_CC, T_ACK_CCX):
        h += bytes([cc_type << 4, mpr]) + struct.pack('>hQ', sack_off, bitmap)
        if t == T_ACK_CC:
            h += cc_state if cc_state is not None else bytes(8)
        else:
            h += ccx if ccx is not None else bytes(16)
    return h + ses + payload

def nack(t, code, nh=NH_NONE, ses=b'', flags=0, vendor=0, psn=900, spd=1, dpd=2, maxr=950,
         payload=b''):
    h = pro(t, nh, flags) + struct.pack('>BBIHHI', code, vendor, psn, spd, dpd, maxr)
    if t == T_NACK_CCX:
        h += bytes(range(16))
    return h + ses + payload

def ctl(ctype, flags=0, opaque=0x0102, psn=1234, spd=3, dpd=4, payload=0xdeadc0de):
    return pro(T_CTRL, ctype, flags) + struct.pack('>HIHHI', opaque, psn, spd, dpd, payload)

def tss(inner, sp=0, ttype=1, an=0x1234, sdi=0x0abc, ssi=0x0def, tsc=0x1122334455667788,
        reserved=0):
    w = (ttype << 27) | (sp << 26) | (reserved << 23) | (an << 12 & 0x7fffff) | 0
    w = (ttype << 27) | (sp << 26) | ((an & 0x3fff) << 12) | (sdi & 0xfff)
    h = struct.pack('>I', w)
    if sp:
        h += struct.pack('>I', ssi)
    h += struct.pack('>Q', tsc)
    return h + inner

def entropy(inner, ent=0xc0de, rsvd=0):
    return struct.pack('>HH', ent, rsvd) + inner

def opb(op, rsv=0):
    return bytes([(rsv << 6) | op])

def ses_small(op, flags=0x03, length=64, idxgen=1, job=0x000102, pid=0x0020, ri=0x0030,
              boff=0x1000, ext=b''):
    return opb(op) + bytes([flags]) + struct.pack('>H', length) + bytes([idxgen]) + \
        struct.pack('>I', job)[1:] + struct.pack('>HH', pid, ri) + struct.pack('>Q', boff) + ext

def ses_med(op, flags=0x03, length=1024, idxgen=2, job=0x000203, pid=0x0021, ri=0x0031,
            boff=0x2000, init=0xa1a2a3a4, mkey=0x1122334455667788, ext=b''):
    return opb(op) + bytes([flags]) + struct.pack('>H', length) + bytes([idxgen]) + \
        struct.pack('>I', job)[1:] + struct.pack('>HH', pid, ri) + struct.pack('>Q', boff) + \
        struct.pack('>IQ', init, mkey) + ext

def ses_std(op, flags=0x01, msgid=0x0042, idxgen=3, job=0x000304, pid=0x0022, ri=0x0032,
            boff=0x3000, init=0xb1b2b3b4, mkey=0x8877665544332211, hdata=0x0102030405060708,
            plen=100, moff=0, reqlen=4096, ext=b''):
    b = opb(op) + bytes([flags]) + struct.pack('>H', msgid) + bytes([idxgen]) + \
        struct.pack('>I', job)[1:] + struct.pack('>HH', pid, ri) + struct.pack('>Q', boff) + \
        struct.pack('>IQ', init, mkey)
    if flags & 0x01:       # SOM: header data
        b += struct.pack('>Q', hdata)
    else:
        b += struct.pack('>II', plen, moff)
    return b + struct.pack('>I', reqlen) + ext

def amo_ext(op, dtype=5, sem=1):
    return bytes([op, dtype, sem, 0])

def cswap_ext(op, dtype=7, sem=3):
    return bytes([op, dtype, sem, 0]) + bytes(range(16)) + bytes(range(100, 116))

def rendv_ext():
    return struct.pack('>IIQQ', 8192, 0x01020304, 0x1000, 0xfedcba9876543210)

def rsp(opcode, rc=1, msgid=0x0042, rig=1, job=0x000102, mod=0, lst=0):
    return bytes([(lst << 6) | opcode, (1 << 6) | rc]) + struct.pack('>H', msgid) + \
        bytes([rig]) + struct.pack('>I', job)[1:] + struct.pack('>I', mod)

def rsp_data(rc=1, msgid=0x0043, job=0x000102, rreq=0x0044, plen=64, mod=0, moff=128):
    return bytes([2, (1 << 6) | rc]) + struct.pack('>H', msgid) + bytes([0]) + \
        struct.pack('>I', job)[1:] + struct.pack('>HHII', rreq, plen, mod, moff)

def rsp_data_small(rc=1, plen=16, job=0x000102, opsn=555):
    return bytes([2, (1 << 6) | rc]) + struct.pack('>H', plen) + bytes([0]) + \
        struct.pack('>I', job)[1:] + struct.pack('>I', opsn)

def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    F = []
    P = lambda uet, **kw: F.append(udp4(uet, **kw))
    pay = b'payload-data-0123456789'

    # --- RUD/ROD requests, all four types, with every flag combination
    for t in (T_RUD, T_ROD, T_RUD_CC, T_ROD_CC):
        for fl in (0, RETX, AR, SYN, RETX | AR | SYN):
            P(rud_req(t, NH_NONE, flags=fl, clear=-3 if fl & 1 else 5, payload=pay))
    # --- SES requests: standard header with every opcode, with and without SOM / HD
    for op in range(16):
        ext = b''
        if op in (0x03, 0x04, 0x0D, 0x0E):
            ext = amo_ext(0x02 if op in (3, 0x0D) else 0x0A)
        if op in (0x06, 0x0A):
            ext = rendv_ext()
        P(rud_req(T_RUD, NH_STD, ses_std(op, flags=0x01 | (op & 0x3e), ext=ext), payload=pay))
    for op in (0x01, 0x05, 0x08, 0x0B, 0x0C):
        P(rud_req(T_ROD, NH_STD, ses_std(op, flags=0x02), payload=pay))          # no SOM: lengths
    # --- atomic and dual operand atomic extension headers
    for op in (0x03, 0x04, 0x0D, 0x0E):
        for aop in (0x02, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x0B):
            ext = cswap_ext(aop) if aop in (0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12) else amo_ext(aop)
            P(rud_req(T_RUD_CC, NH_STD, ses_std(op, ext=ext)))
            P(rud_req(T_ROD, NH_SMALL, ses_small(op, ext=ext)))
            P(rud_req(T_RUD, NH_MED, ses_med(op, ext=ext)))
    # --- small and medium requests (HD flag chooses header data or offset)
    for op in (0x01, 0x02, 0x05, 0x09):
        P(rud_req(T_RUD, NH_SMALL, ses_small(op, flags=0x01), payload=pay))
        P(rud_req(T_RUD, NH_SMALL, ses_small(op, flags=0x3f), payload=pay))
        P(rud_req(T_RUD, NH_MED, ses_med(op, flags=0x05), payload=pay))
        P(rud_req(T_RUD, NH_MED, ses_med(op, flags=0x03), payload=pay))
    # --- RUDI, UUD
    for t in (T_RUDI, T_RUDI_RESP):
        P(rudi(t, NH_NONE, payload=pay))
        P(rudi(t, NH_STD, ses_std(0x05), payload=pay))
        P(rudi(t, NH_RSP, rsp(1)))
    P(uud(NH_NONE, payload=pay))
    P(uud(NH_MED, ses_med(0x07), payload=pay))
    P(uud(NH_STD, ses_std(0x07, flags=0x03), payload=pay))
    # --- ACKs: plain, CC (NSCC, credit, other), CCX; ack flags; with responses
    for fl in (0, 0x20, 0x10, 0x08, 0x02, 0x04, 0x06, 0x3e):
        P(ack(T_ACK, flags=fl))
    for ct, cs in ((0, struct.pack('>HHBB', 0x1234, 0x5678, 0x9a, 0xbc)),
                   (1, bytes([1, 2, 3, 0, 0, 0, 0, 9])), (2, bytes(8)), (15, bytes(8))):
        P(ack(T_ACK_CC, cc_type=ct, cc_state=cs, sack_off=-5 if ct == 1 else 7))
    P(ack(T_ACK_CCX, cc_type=3, ccx=bytes(range(16))))
    for t in (T_ACK, T_ACK_CC, T_ACK_CCX):
        P(ack(t, NH_RSP, rsp(1)))
        P(ack(t, NH_RSP_DATA, rsp_data(), payload=pay))
        P(ack(t, NH_RSP_DATA_SMALL, rsp_data_small(), payload=pay))
    # --- responses with every opcode / return code
    for opc in (0, 1, 3):
        P(ack(T_ACK, NH_RSP, rsp(opc, rc=opc + 1)))
    for rc in (0, 0x01, 0x05, 0x1f, 0x24, 0x30):
        P(ack(T_ACK, NH_RSP, rsp(1, rc=rc)))
    # --- NACKs
    for code in (0x01, 0x04, 0x0B, 0x0D, 0x10, 0x1A, 0xFD, 0xFE, 0xFF, 0x00, 0x40):
        P(nack(T_NACK, code, flags=0x20 | (code & 3) << 3))
    P(nack(T_NACK_CCX, 0x03, flags=0x10))
    P(nack(T_NACK, 0x02, NH_RSP, rsp(1)))
    # --- control: every type and an undefined one
    for ct in range(10):
        P(ctl(ct, flags=ct & 0x1c))
    P(ctl(6, flags=0x7f))
    # --- reserved type: header only, and an undefined type (15..31)
    P(pro(T_RESERVED, 0) + b'\0' * 6)
    for t in (15, 16, 17, 31):
        P(pro(t, 0) + b'\0' * 12)
    # --- TSS (encryption header) in front of PDS: only the header layout is
    # decoded; the bytes that follow are the PDS in clear
    for sp in (0, 1):
        P(tss(rud_req(T_RUD, NH_STD, ses_std(0x01), payload=pay), sp=sp))
        P(tss(ack(T_ACK), sp=sp))
        P(tss(ctl(1), sp=sp, ttype=1))
    # --- IPv6
    F.append(udp6(rud_req(T_RUD, NH_STD, ses_std(0x01), payload=pay)))
    F.append(udp6(ack(T_ACK_CC), sport=40000, dport=4793))
    # --- another UDP port pair: only UDP port 4793 is the default; a source
    # port of 4793 is also enough
    F.append(udp4(nack(T_NACK, 0x04), sport=4793, dport=50000))
    # --- entropy header over IP protocol 253 (Decode As)
    ENT = len(F)
    for inner in (rud_req(T_RUD, NH_STD, ses_std(0x01), payload=pay),
                  ack(T_ACK_CC), nack(T_NACK, 3), ctl(7), rudi(T_RUDI, NH_NONE),
                  tss(ack(T_ACK), sp=0), tss(ack(T_ACK), sp=1)):
        F.append(ipproto(entropy(inner)))
    # --- CRC section: good and bad CRCs for validate_crc
    CRC0 = len(F)
    for inner in (rud_req(T_RUD, NH_NONE, payload=pay), ack(T_ACK), ctl(2)):
        F.append(udp4(inner, crc='good'))
        F.append(udp4(inner, crc='bad'))
        F.append(udp6(inner, crc='good'))
        F.append(ipproto(entropy(inner), crc='good'))
        F.append(ipproto(entropy(inner), crc='bad'))
    write(os.path.join(outdir, 'uet-coverage.pcap'), F)
    with open(os.path.join(outdir, 'layout.txt'), 'w') as f:
        f.write('entropy %d\ncrc %d\ntotal %d\n' % (ENT + 1, CRC0 + 1, len(F)))

    # ---- malformed capture
    M = []
    Q = lambda uet, **kw: M.append(udp4(uet, **kw))
    # PDS too short; RUD/ROD header shorter than 12; CC header shorter than 16
    Q(b'\x10\x00')
    Q(b'\x10\x00\x00')
    Q(rud_req(T_RUD, NH_NONE)[:6])
    Q(rud_req(T_RUD, NH_NONE)[:10])
    Q(rud_req(T_RUD_CC, NH_NONE)[:13])
    Q(rud_req(T_ROD_CC, NH_NONE, flags=SYN)[:14])
    # ACK ext header shorter than 20; ACK cut in the fixed part
    Q(ack(T_ACK_CC)[:12 + 5])
    Q(ack(T_ACK_CCX)[:12 + 15])
    Q(ack(T_ACK)[:8])
    Q(nack(T_NACK, 1)[:9])
    Q(ctl(1)[:10])
    # SES headers cut: small < 20, medium < 32, standard < 44, ext headers
    for n in (1, 3, 8, 19):
        Q(rud_req(T_RUD, NH_SMALL, ses_small(0x01))[:12 + n])
    for n in (1, 10, 31):
        Q(rud_req(T_RUD, NH_MED, ses_med(0x01))[:12 + n])
    for n in (1, 20, 43):
        Q(rud_req(T_RUD, NH_STD, ses_std(0x01))[:12 + n])
    Q(rud_req(T_RUD, NH_STD, ses_std(0x03, ext=cswap_ext(0x0D)))[:12 + 44 + 10])
    Q(rud_req(T_RUD, NH_STD, ses_std(0x03, ext=amo_ext(0x02)))[:12 + 44 + 2])
    Q(rud_req(T_RUD, NH_STD, ses_std(0x06, ext=rendv_ext()))[:12 + 44 + 10])
    Q(rud_req(T_RUD, NH_SMALL, ses_small(0x03, ext=cswap_ext(0x10)))[:12 + 20 + 7])
    Q(rud_req(T_RUD, NH_MED, ses_med(0x0D, ext=amo_ext(0x0B)))[:12 + 32 + 1])
    # responses: short, wrong opcode for the header type
    Q(ack(T_ACK, NH_RSP, rsp(1))[:12 + 5])
    Q(ack(T_ACK, NH_RSP, rsp(2)))                 # opcode "with data" in a plain response
    Q(ack(T_ACK, NH_RSP_DATA, rsp(1)))            # plain opcode in a data response
    Q(ack(T_ACK, NH_RSP_DATA_SMALL, rsp(0)))
    Q(ack(T_ACK, NH_RSP_DATA, rsp_data()[:7]))
    Q(ack(T_ACK, NH_RSP_DATA_SMALL, rsp_data_small()[:7]))
    # undefined next header values
    for nh in (7, 8, 15):
        Q(ack(T_ACK, nh, b'abcdef'))
    # TSS shorter than its header; with and without SP
    Q(tss(b'')[:6])
    Q(tss(b'', sp=1)[:10])
    Q(tss(ack(T_ACK), ttype=2))              # type 2 is not TSS: read as a PDS of that type
    Q(tss(b'')[:12] )
    Q(tss(rud_req(T_RUD, NH_NONE))[:12 + 4])
    # trailing data after a complete PDS, and frames that are only a CRC
    Q(rudi(T_RUDI, NH_NONE, payload=b'x' * 40))
    M.append(udp4(b'')); M.append(udp4(b'\x00'))
    # frames cut by the capture (captured shorter than reported)
    full = udp4(rud_req(T_RUD, NH_STD, ses_std(0x01), payload=pay))
    M.append((full[:-20], len(full)))
    M.append((full[:60], len(full)))
    # entropy header with too little data
    M.append(ipproto(b'\x12\x34'))
    M.append(ipproto(entropy(b'\x08')))
    # frames without a CRC: the remaining length is what the header sees
    M.append(udp4(rud_req(T_RUD, NH_STD, ses_std(0x03, ext=amo_ext(0x02)))[:12 + 44 + 2], crc=b''))
    M.append(udp4(rud_req(T_RUD_CC, NH_NONE)[:12], crc=b''))
    M.append(udp4(rud_req(T_ROD_CC, NH_NONE)[:14], crc=b''))
    # UDP length shorter than the IP payload: the CRC walk back from the UET
    # layer ends before the start of the frame (validate_crc)
    long_ = bytearray(udp4(rud_req(T_RUD, NH_NONE, payload=b'p' * 100), crc='good'))
    long_[38:40] = struct.pack('>H', struct.unpack('>H', bytes(long_[38:40]))[0] - 80)
    M.append(bytes(long_))
    # CRC validation with the IP total length short of the UET data
    bad_ip = bytearray(ipproto(entropy(ack(T_ACK)), crc='good'))
    bad_ip[16:18] = struct.pack('>H', 21)      # total length: header plus 1
    M.append(bytes(bad_ip))
    write(os.path.join(outdir, 'uet-coverage-malformed.pcap'), M)

main(sys.argv[1] if len(sys.argv) > 1 else '.')
