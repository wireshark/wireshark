#!/usr/bin/env python3
# Generates test/captures/dmp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Build synthetic captures for the DMP (STANAG 4406 Annex E, Direct
# Message Profile) dissector, packet-dmp.c.
#
# Usage: mkdmp.py <outdir>
# Writes dmp-coverage.pcap (clean) and dmp-coverage-malformed.pcap.
#
# Every packet is built with struct; nothing comes from a real network.
# DMP runs over UDP port 5031 (registered by default).

import os
import struct
import sys
import zlib

T0 = 1700000000
PORT = 5031


# ---------------------------------------------------------------- framing

def ipsum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


def ipv4(src, dst, proto, payload, ident=1):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0,
                     64, proto, 0, ip4(src), ip4(dst))
    return ip[:10] + struct.pack('!H', ipsum(ip)) + ip[12:] + payload


def udp(src, dst, payload, sport=PORT, dport=PORT):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = ipsum(ph + u) or 0xffff
    return u[:6] + struct.pack('!H', c) + u[8:]


def eth(payload):
    return bytes.fromhex('020000000002' '020000000001') + b'\x08\x00' + payload


def udp_frame(src, dst, payload, sport=PORT, dport=PORT):
    return eth(ipv4(src, dst, 17, udp(src, dst, payload, sport, dport)))


def icmp_unreach(src, dst, inner_ip):
    body = struct.pack('!BBHI', 3, 3, 0, 0) + inner_ip
    body = body[:2] + struct.pack('!H', ipsum(body)) + body[4:]
    return eth(ipv4(src, dst, 1, body))


def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, fr in frames:
            f.write(struct.pack('<IIII', ts, 0, len(fr), len(fr)))
            f.write(fr)


# ---------------------------------------------------------------- DMP helpers

STANAG, IPM, REPORT, NOTIF, ACK = range(5)


def crc_x25(data):
    """crc16_x25_ccitt_seed(..., 0xFFFF): unreflected, polynomial 0x1021."""
    crc = 0xffff
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xffff if crc & 0x8000 else (crc << 1) & 0xffff
    return crc


def with_cksum(pdu):
    return pdu + struct.pack('!H', crc_x25(pdu))


def b0(version=2, prot=0x1D):
    return bytes([(prot << 3) | (version - 1)])


def b1(mtype, addr_enc=0, cksum=0, hop=0):
    return bytes([(hop << 5) | (addr_enc << 4) | (cksum << 3) | mtype])


def ack_b1(ext=0, rec=0, addr_enc=0, cksum=0):
    return bytes([(ext << 7) | (rec << 5) | (addr_enc << 4) | (cksum << 3) | ACK])


def msgid(mid, ext=0, idtype=0, mts=b'', short=False, reserved=0):
    """Version 2 message identifier type byte(s) and message identifier."""
    if idtype in (1, 2):
        return bytes([(ext << 7) | (idtype << 5) | len(mts)]) + struct.pack('!H', mid)
    if short:
        return bytes([(ext << 7) | 0x10 | ((mid >> 8) & 0x0F), mid & 0xFF])
    return bytes([(ext << 7) | (idtype << 5) | reserved]) + struct.pack('!H', mid)


def pack7(s):
    """Pack 7-bit characters MSB first, as dissect_7bit_string() decodes."""
    bits = ''.join('{:07b}'.format(ord(c)) for c in s)
    bits += '0' * (-len(bits) % 8)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def subm_for(ts, back=10):
    """Encoded submission time `back` seconds before the frame time."""
    return (((ts - back) // 2) % 0x7FF8)


def subm(delta1, tdiff=None):
    if tdiff is None:
        return struct.pack('!H', delta1 & 0x7FFF)
    return struct.pack('!HB', 0x8000 | (delta1 & 0x7FFF), tdiff)


def flags(nrec, f=0):
    if nrec < 32 and nrec != 0:
        return bytes([(f << 5) | nrec])
    return bytes([f << 5]) + struct.pack('!H', nrec)


def dir_addr(a, res1=0, res2=0):
    """Direct (originator / extended-form) address, 1-3 octets."""
    if a < 128 and not res1:
        return bytes([a])
    if a < 8192:
        return bytes([0x80 | (a & 0x7F), (res1 << 6) | ((a >> 7) & 0x3F)])
    return bytes([0x80 | (a & 0x7F), 0x80 | (res1 << 6) | ((a >> 7) & 0x3F),
                  (res2 << 6) | ((a >> 13) & 0x3F)])


def dir_rec(rec, addr, rep=0, notif=0, action=1, res=0):
    """Direct recipient encoding (5.2.7)."""
    rep0 = rep if rec < 16 else 3
    not0 = notif if addr < 128 else 3
    out = [((rec & 0xF) << 4) | (rep0 << 2) | not0, (action << 7) | (addr & 0x7F)]
    if rec >= 16:
        rep1 = rep if rec < 1024 else 3
        out.append((rep1 << 6) | ((rec >> 4) & 0x3F))
        if rec >= 1024:
            out.append((rep << 6) | (res << 5) | ((rec >> 10) & 0x1F))
    if addr >= 128:
        not1 = notif if addr < 8192 else 3
        out.append((not1 << 6) | ((addr >> 7) & 0x3F))
        if addr >= 8192:
            out.append((notif << 6) | ((addr >> 13) & 0x3F))
    return bytes(out)


def ext_addr(atype, data, force_long=False):
    """Extended address (5.3.14)."""
    n = len(data)
    if atype < 4 and n < 32 and not force_long:
        return bytes([(atype << 5) | n]) + data
    return bytes([0x80 | (n & 0x1F), (atype << 5) | ((n >> 5) & 0x1F)]) + data


def ext_rec(form, rec, p1=b'', p2=b'', action=1, rep=0, notif=0):
    """Extended recipient encoding (5.2.8.2)."""
    out = bytes([(form << 5) | (action << 4) | (rep << 2) | notif])
    if rec < 128:
        out += bytes([rec])
    else:
        out += bytes([0x80 | (rec & 0x7F), rec >> 7])
    return out + p1 + p2


def ext_orig(form, a1=b'', a2=b'', res=0):
    return bytes([(form << 5) | res]) + a1 + a2


def sic_value(s, anyc):
    alpha = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    if anyc:
        alpha += "abcdefghijklmnopqrstuvwxyz'()+,-./:=? "
    base = len(alpha)
    v = 0
    for c in s:
        v = v * base + alpha.index(c)
    return v


ORNAME = bytes.fromhex('6014' '3012' '6104' '13024e4f' '6203' '130120' '8305') + b'ACME1'
PER_ADDR = bytes.fromhex('0102030405')
UNK_ADDR = bytes.fromhex('a1b2c3')


def body(text, eit=1, compr=0, res=0):
    return bytes([(eit << 5) | (compr << 3) | res]) + text


def stanag_content(st_type=0, prec=2, bf=0, sec=0x90, cats=b'\x00', exp=0x40, dtg=0x10,
                   sic=b'\xfe', res=0):
    return (bytes([(st_type << 6) | (res << 5) | (prec << 2) | bf, sec]) + cats +
            bytes([exp, dtg]) + sic)


def ipm_content(imp=1, bf=0, sec=0x90, cats=b'\x00', exp=0x40, res=0):
    return bytes([(res << 5) | (imp << 2) | bf, sec]) + cats + bytes([exp])


# Frame list of (src, dst, payload) for the main capture.
main = []
mal = []


def add(src, dst, pdu, lst=None, sport=PORT, dport=PORT):
    (main if lst is None else lst).append(('udp', src, dst, pdu, sport, dport))


def ts_of(lst):
    return T0 + len(lst) + 1


def simple_stanag(mid, nrec=1, orig=b'\x05', recips=None, content=None, text=b'Hello',
                  cksum=0, version=2, prot=0x1D, idfield=None, ts_lst=None, tdiff=None,
                  envflags=0, addr_enc=0, extensions=b'', hop=0, bodyb=None):
    ts = ts_of(main if ts_lst is None else ts_lst)
    pdu = b0(version, prot) + b1(STANAG, addr_enc, cksum, hop)
    if version >= 2:
        pdu += idfield if idfield is not None else msgid(mid, ext=1 if extensions else 0)
    else:
        pdu += struct.pack('!H', mid)
    pdu += subm(subm_for(ts), tdiff) + flags(nrec, envflags) + orig
    if recips is None:
        recips = dir_rec(0, 6)
    pdu += recips + extensions
    pdu += content if content is not None else stanag_content()
    pdu += bodyb if bodyb is not None else body(text)
    return with_cksum(pdu) if cksum else pdu


A, B, C, D, E, F = ('192.0.2.%d' % i for i in (10, 11, 12, 13, 14, 15))

# ------------------------------------------------------------------ 1-2
# Reproducer dmp_mtsid_2pass.py: a Report naming a subject MTS identifier
# that is only seen in the message that follows it.  On the first pass the
# lookup finds nothing; before the fix tshark -2 showed message id 1234.
R1, R2 = '192.0.2.1', '192.0.2.2'
mts = b'\x41\x42\x43\x44'
rep = bytes([0xE9, 0x02, 0x20 | len(mts)]) + b'\x00\x10'
rep += b'\x00\x00' + b'\x01' + b'\x00\x05' + b'\x00\x00' + mts + b'\x00\x00\x00\x07'
msg = bytes([0xE9, 0x00, 0x20 | len(mts)]) + struct.pack('!H', 1234) + mts
msg += b'\x00\x00' + b'\x01' + b'\x05' + b'\x00\x06' + b'\x00' + b'\x00\x00'
msg += b'\x00\x00' + b'\xFE' + b'\x00' + b'hello'
add(R2, R1, rep)
add(R1, R2, msg)

# ------------------------------------------------------------------ 3-
# SEQ/ACK analysis (messages with checksum, ACKs, reports, notifications)
add(A, B, simple_stanag(5000, cksum=1, text=b'First message'))            # 3
ack = lambda subj, reason=0, diag=0, cksum=1: b0() + ack_b1(cksum=cksum) + \
    bytes([reason, diag]) + struct.pack('!H', subj)
add(B, A, with_cksum(ack(5000)))                                           # 4 ACK
add(B, A, with_cksum(ack(5000)))                                           # 5 dup ACK
add(A, B, simple_stanag(5001, cksum=1, text=b'Second message'))           # 6
add(A, B, simple_stanag(5001, cksum=1, text=b'Second message'))           # 7 retrans 1
add(A, B, simple_stanag(5001, cksum=1, text=b'Second message'))           # 8 retrans 2
add(B, A, with_cksum(ack(5001)))                                           # 9 ACK of resent


def report_pdu(mid, subj, reports, cksum=1, version=2, nrec=1, recips=None,
               idfield=None, subjfield=None, sec=0x00, cats=b'\x00', addr_enc=0, lst=None,
               extensions=b''):
    ts = ts_of(main if lst is None else lst)
    pdu = b0(version) + b1(REPORT, addr_enc, cksum)
    if version >= 2:
        pdu += idfield if idfield is not None else msgid(mid, ext=1 if extensions else 0)
    else:
        pdu += struct.pack('!H', mid)
    pdu += subm(subm_for(ts)) + flags(nrec)
    pdu += recips if recips is not None else dir_rec(0, 5)
    pdu += extensions
    pdu += bytes([sec]) + cats
    pdu += subjfield if subjfield is not None else struct.pack('!H', subj)
    pdu += reports
    return with_cksum(pdu) if cksum else pdu


DR_SIMPLE = b'\x00' + b'\x20' + dir_rec(0, 7)   # DR, delivery time 1 min, reporting name


def notif_pdu(mid, subj, ntype, data, cksum=1, version=2, orig=b'\x06', nrec=1, recips=None,
              idfield=None, subjfield=None, sec=0x00, cats=b'\x00', lst=None, addr_enc=0):
    ts = ts_of(main if lst is None else lst)
    pdu = b0(version) + b1(NOTIF, addr_enc, cksum)
    if version >= 2:
        pdu += idfield if idfield is not None else msgid(mid)
    else:
        pdu += struct.pack('!H', mid)
    pdu += subm(subm_for(ts)) + flags(nrec) + orig
    pdu += recips if recips is not None else dir_rec(0, 5)
    pdu += bytes([sec | ntype]) + cats
    pdu += subjfield if subjfield is not None else struct.pack('!H', subj)
    pdu += data
    return with_cksum(pdu) if cksum else pdu


RN_SIMPLE = b'\x10' + b'Read\x00'

add(B, A, report_pdu(6000, 5000, DR_SIMPLE))                               # 10 report
add(A, B, with_cksum(ack(6000)))                                           # 11 ACK report
add(B, A, report_pdu(6001, 5001, DR_SIMPLE))                               # 12 report of resent
add(B, A, notif_pdu(6100, 5000, 0, RN_SIMPLE))                             # 13 RN
add(A, B, with_cksum(ack(6100)))                                           # 14 ACK notif
add(B, A, report_pdu(6000, 5000, DR_SIMPLE))                               # 15 report resent
add(B, A, notif_pdu(6100, 5000, 0, RN_SIMPLE))                             # 16 notif resent
add(B, A, report_pdu(6002, 7777, DR_SIMPLE))                               # 17 report, no msg
add(B, A, notif_pdu(6101, 7778, 0, RN_SIMPLE))                             # 18 notif, no msg
add(B, A, with_cksum(ack(9999)))                                           # 19 ACK, no msg
# 20 negative ACK with a recipient list (recipient present, checksum)
neg = b0() + ack_b1(rec=1, cksum=1) + bytes([1, 3]) + struct.pack('!H', 5001)
neg += dir_rec(0, 6) + dir_rec(1, 7)
add(B, A, with_cksum(neg))
# 21-22 IPM with checksum and its ACK
ipm = b0() + b1(IPM, 0, 1) + msgid(0x1234) + subm(subm_for(ts_of(main))) + flags(1) + b'\x08'
ipm += dir_rec(0, 9, action=0) + ipm_content() + body(b'IPM text')
add(C, D, with_cksum(ipm))
add(D, C, with_cksum(ack(0x1234)))
# 23 ACK without checksum
add(D, C, ack(0x1234, cksum=0))

# ------------------------------------------------------------------ ICMP
# 24: a DMP message inside an ICMP destination unreachable (in_error_pkt)
inner_pdu = simple_stanag(5002, cksum=1, text=b'Bounced')
inner = ipv4(A, B, 17, udp(A, B, inner_pdu))
main.append(('raw', icmp_unreach(B, A, inner)))

# ------------------------------------------------------------------ envelope
# Versions, protocol ids, identifiers, time differences
add(E, F, simple_stanag(0x2000, version=1))                                # v1 STANAG
add(E, F, simple_stanag(0x2001, prot=0x0D, idfield=msgid(0x2001)))         # national
add(E, F, simple_stanag(0x2002, prot=0x1F, idfield=msgid(0x2002)))         # wrong prot id
add(E, F, simple_stanag(0x123, idfield=msgid(0x123, short=True)))          # short id
add(E, F, simple_stanag(0x124, idfield=msgid(0x124)))                      # id < 4096
add(E, F, simple_stanag(0x2003, idfield=msgid(0x2003, reserved=0x05)))     # reserved bits
for td in (0x00, 0x10, 0x50, 0xA0, 0xE5, 0xFA):                            # time difference
    add(E, F, simple_stanag(0x2100 + td, tdiff=td, hop=3))
add(E, F, simple_stanag(0x2200, envflags=0x7))                             # all envelope flags
add(E, F, simple_stanag(0x2201, envflags=0x5))
# Submission time: reserved, and the two wrap branches of dmp_dec_subm_time()
ts = ts_of(main)
pdu = b0() + b1(STANAG) + msgid(0x2300) + struct.pack('!H', 0x7FF9) + flags(1) + b'\x05' + \
    dir_rec(0, 6) + stanag_content() + body(b'x')
add(E, F, pdu)
d2 = ((ts_of(main)) // 2) % 0x7FF8
# delta1 large, delta2 small: choose delta1 so that delta2 < delta1 - 0x1C2
pdu = b0() + b1(STANAG) + msgid(0x2301) + subm((d2 + 0x400) % 0x7FF8) + flags(1) + \
    b'\x05' + dir_rec(0, 6) + stanag_content() + body(b'x')
add(E, F, pdu)
d2 = ((ts_of(main)) // 2) % 0x7FF8
pdu = b0() + b1(STANAG) + msgid(0x2302) + subm((d2 - 0x7E40) % 0x7FF8) + flags(1) + \
    b'\x05' + dir_rec(0, 6) + stanag_content() + body(b'x')
add(E, F, pdu)

# Extended recipient count: 32 recipients, and a count below 32 (reserved)
add(E, F, simple_stanag(0x2400, nrec=32,
                        recips=b''.join(dir_rec(0, 10 + i) for i in range(32))))
add(E, F, b0() + b1(STANAG) + msgid(0x2401) + subm(subm_for(ts_of(main))) + b'\x00\x00\x02' +
    b'\x05' + dir_rec(0, 6) + dir_rec(0, 7) + stanag_content() + body(b'x'))
add(E, F, b0() + b1(STANAG) + msgid(0x2402) + subm(subm_for(ts_of(main))) + b'\x00\x80\x21' +
    b'\x05' + b''.join(dir_rec(0, 10 + i) for i in range(33)) + stanag_content() + body(b'x'))

# Direct recipient encodings: extended recipient numbers and addresses
recips = (dir_rec(0, 6, rep=1, notif=1) + dir_rec(20, 7, rep=2, notif=2, action=0) +
          dir_rec(1100, 200, rep=1, notif=1) + dir_rec(1, 9000, rep=2, notif=2) +
          dir_rec(2, 100, rep=0, notif=0, action=0))
add(E, F, simple_stanag(0x2500, nrec=5, recips=recips, orig=dir_addr(300)))
add(E, F, simple_stanag(0x2501, orig=dir_addr(20000)))
# IPM with To/Cc recipients and requests
ipm = b0() + b1(IPM) + msgid(0x2502) + subm(subm_for(ts_of(main))) + flags(2) + b'\x08'
ipm += dir_rec(0, 9, rep=1, notif=0, action=1) + dir_rec(0, 10, rep=0, notif=2, action=0)
ipm += ipm_content(imp=2) + body(b'IPM')
add(E, F, ipm)

# Extended address encoding: originator forms and recipient forms
def ext_msg(mid, orig, recips, nrec, mtype=STANAG, version=2, content=None, prot=0x1D):
    ts = ts_of(main)
    pdu = b0(version, prot) + b1(mtype, addr_enc=1)
    pdu += msgid(mid) if version >= 2 else struct.pack('!H', mid)
    pdu += subm(subm_for(ts)) + flags(nrec) + orig + recips
    if content is None:
        content = stanag_content() if mtype == STANAG else ipm_content()
    return pdu + content + body(b'Ext')


DA = dir_addr(33)
DA2 = dir_addr(1000)
EA_BER = ext_addr(0, ORNAME)
EA_PER = ext_addr(1, PER_ADDR)
EA_UNK = ext_addr(5, UNK_ADDR)
EA_LONG = ext_addr(1, bytes(range(40)))
rec_all = b''.join([
    ext_rec(0, 0, p1=DA, rep=1, notif=1),
    ext_rec(1, 1, p2=DA2, action=0, rep=2, notif=2),
    ext_rec(2, 1, p1=EA_BER),
    ext_rec(3, 200, p2=EA_PER, action=0),
    ext_rec(4, 1, p1=DA, p2=DA2),
    ext_rec(5, 1, p1=DA, p2=EA_UNK),
    ext_rec(6, 1, p1=EA_PER, p2=DA),
    ext_rec(7, 1, p1=EA_LONG, p2=EA_BER),
])
for form, orig in ((0, DA), (2, EA_BER), (4, DA + DA2), (5, DA + EA_PER),
                   (6, EA_UNK + DA), (7, EA_PER + EA_LONG), (1, b''), (3, b'')):
    add(E, F, ext_msg(0x2600 + form, ext_orig(form, orig), rec_all if form == 0 else
                      ext_rec(0, 0, p1=DA), 8 if form == 0 else 1))
add(E, F, ext_msg(0x2610, ext_orig(0, DA, res=3), ext_rec(0, 0, p1=DA), 1))      # reserved
add(E, F, ext_msg(0x2620, ext_orig(0, DA), ext_rec(0, 0, p1=DA), 1, version=1))  # v1 forms
add(E, F, ext_msg(0x2621, ext_orig(2, EA_BER), ext_rec(4, 0, p1=DA, p2=DA2), 1, version=1))
add(E, F, ext_msg(0x2622, ext_orig(4), ext_rec(0, 0, p1=DA), 1, version=1))
# v1 national with Thales-capable layout (decoded as DMP by default)
add(E, F, ext_msg(0x2623, ext_orig(0, DA), ext_rec(0, 0, p1=DA), 1, version=1, prot=0x0D))
# Notification with P2 address in the originator (intended recipient)
ts = ts_of(main)
pdu = b0() + b1(NOTIF, addr_enc=1) + msgid(0x2630) + subm(subm_for(ts)) + flags(1) + \
    ext_orig(4, DA + DA2) + ext_rec(0, 0, p1=DA) + b'\x00\x00' + b'\x26\x00' + b'\x10\x00'
add(E, F, pdu)

# ------------------------------------------------------------------ X.400 identifiers
# STANAG message with an MTS identifier and a notification request (IPM id)
X1, X2 = '192.0.2.20', '192.0.2.21'
mts1 = pack7('MTA1/0001')
ipmid = pack7('IPM-ID-1')
ts = ts_of(main)
pdu = b0() + b1(STANAG) + msgid(0x3000, idtype=1, mts=mts1) + mts1 + subm(subm_for(ts)) + \
    flags(1) + b'\x05' + dir_rec(0, 6, rep=1, notif=1) + bytes([len(ipmid)]) + ipmid + \
    stanag_content() + body(b'X400')
add(X1, X2, pdu)
# Report of it, naming the subject MTS identifier (found on the first pass)
add(X2, X1, report_pdu(0x3001, 0, DR_SIMPLE, cksum=0, idfield=msgid(0x3001, idtype=1, mts=mts1),
                       subjfield=mts1))
# Receipt notification naming the subject IPM identifier
ts = ts_of(main)
mts2 = pack7('MTA1/0002')
pdu = b0() + b1(NOTIF) + msgid(0x3002, idtype=1, mts=mts2) + mts2 + subm(subm_for(ts)) + \
    flags(1) + b'\x06' + dir_rec(0, 5) + b'\x00\x00' + bytes([len(ipmid)]) + ipmid + RN_SIMPLE
add(X2, X1, pdu)
# IPM with a national message identifier and an IPM id with a modifier
# Laid out as Thales XOmail identifiers ("MTA/<6 octets>" and
# "<prefix><number> <time>"), decoded as 7-bit strings by default
mts3 = pack7('X') + bytes.fromhex('000012340001')
ipmid2 = pack7('NATIPM')
ipm_thales = pack7('AB') + struct.pack('!HI', 2000, 1700000000)
ts = ts_of(main)
pdu = b0() + b1(IPM) + msgid(0x3003, idtype=2, mts=mts3) + mts3 + subm(subm_for(ts)) + \
    flags(1) + b'\x08' + dir_rec(0, 9, notif=2) + bytes([0x40 | len(ipm_thales)]) + ipm_thales + \
    ipm_content() + body(b'NAT')
add(X1, X2, pdu)
# National identifiers of other shapes: short MTS identifier, IPM
# identifiers with modifiers 2 (no prefix) and 3
mts6 = pack7('NAT77')
for mod, iid in ((2, struct.pack('!HI', 77, 1700000000)), (3, pack7('IPMID3'))):
    ts = ts_of(main)
    pdu = b0(2, 0x0D) + b1(IPM) + msgid(0x3010 + mod, idtype=2, mts=mts6) + mts6 + \
        subm(subm_for(ts)) + flags(1) + b'\x08' + dir_rec(0, 9, notif=2) + \
        bytes([(mod << 6) | len(iid)]) + iid + ipm_content() + body(b'NAT')
    add(X1, X2, pdu)
# MTS identifier with unused bits set in the last octet (warning)
mts4 = mts1[:-1] + bytes([mts1[-1] | 0x01])
ts = ts_of(main)
pdu = b0() + b1(STANAG) + msgid(0x3004, idtype=1, mts=mts4) + mts4 + subm(subm_for(ts)) + \
    flags(1) + b'\x05' + dir_rec(0, 6) + stanag_content() + body(b'bits')
add(X1, X2, pdu)
# Non-receipt notification for a subject IPM id never seen
ts = ts_of(main)
pdu = b0() + b1(NOTIF) + msgid(0x3005, idtype=1, mts=mts2) + mts2 + subm(subm_for(ts)) + \
    flags(1) + b'\x06' + dir_rec(0, 5) + b'\x01\x00' + bytes([len(ipmid2)]) + ipmid2 + b'\x05\x02'
add(X2, X1, pdu)

# ------------------------------------------------------------------ extensions
ext2 = b'\x81\xaa\xbb' + b'\x02\x01\x02\x03'
add(E, F, simple_stanag(0x3100, extensions=ext2))
add(E, F, report_pdu(0x3101, 0x2000, DR_SIMPLE, cksum=0, extensions=b'\x00\x99'))
# ACK with extensions: extensions follow the envelope, before the ACK body
ackx = b0() + ack_b1(ext=1, rec=1) + b'\x01\x55\x66' + b'\x00\x00' + struct.pack('!H', 0x2000) + \
    dir_rec(0, 6)
add(F, E, ackx)
# ACK, version 1, extended address recipient list with checksum
ackv1 = b0(1) + ack_b1(rec=1, addr_enc=1, cksum=1) + b'\x00\x00' + struct.pack('!H', 0x2000) + \
    ext_rec(0, 0, p1=DA) + ext_rec(2, 0, p1=EA_PER)
add(F, E, with_cksum(ackv1))

# ------------------------------------------------------------------ content
# STANAG message types and precedences
for st, prec, res in ((0, 0, 0), (1, 1, 0), (2, 5, 0), (3, 6, 0), (0, 7, 1), (1, 3, 0), (2, 4, 0)):
    add(E, F, simple_stanag(0x4000 + st * 8 + prec, content=stanag_content(st, prec, res=res)))
# IPM importance and reserved bits
for imp, res in ((0, 0), (2, 0), (1, 5), (3, 0)):
    ts = ts_of(main)
    pdu = b0() + b1(IPM) + msgid(0x4100 + imp * 8 + res) + subm(subm_for(ts)) + flags(1) + \
        b'\x08' + dir_rec(0, 9) + ipm_content(imp=imp, res=res) + body(b'imp')
    add(E, F, pdu)

# Security classification, policy, categories
def sec(cls, pol, hf=0):
    return (cls << 5) | (pol << 2) | hf


for cls, pol, hf, cats in (
        (0, 0, 0, b'\xff'),            # policy 0: category bits
        (1, 1, 1, b'\x00'),
        (2, 2, 2, b'\x81'),
        (3, 3, 3, b'\x00'),
        (4, 4, 0, b'\xf0'),            # NATO, categories cl,cs,ex,ne
        (5, 4, 0, b'\x9c'),            # NATO with reserved 0x08/0x04
        (6, 4, 0, b'\x51' + b'\x48'),  # permissive: rel-to Germany (0x08<<2|..)
        (7, 4, 0, b'\x01' + b'\xfd' + b'\x14' + b'\x1a' + b'\xa4'),  # country code, restrictive
        (1, 4, 0, b'\x01' + b'\x00'),  # permissive nation 0 (reserved)
        (2, 4, 0, b'\x23'),            # both extension bits (reserved)
        (3, 5, 0, b'\x20'),            # national
        (4, 6, 0, b'\x08\x00'),        # extended national (nation 8)
        (5, 7, 0, b'\x10\x55'),        # extended mission
        (6, 7, 0, b'\xff\x00'),        # mission id reserved
):
    add(E, F, simple_stanag(0x4200 + cls * 16 + pol, content=stanag_content(sec=sec(cls, pol, hf),
                                                                            cats=cats)))
# Version 1 security category reserved bits
add(E, F, simple_stanag(0x4300, version=1, content=stanag_content(sec=sec(2, 4), cats=b'\x83')))

# Expiry time, DTG
for exp in (0x00, 0x10, 0x50, 0xA0, 0xD0, 0xF0, 0xFF):
    add(E, F, simple_stanag(0x4400 + exp, content=stanag_content(exp=exp)))
for dtg in (0x00, 0x01, 0x81, 0x20, 0xA0, 0x50, 0x70, 0xF0, 0x7F):
    add(E, F, simple_stanag(0x4500 + dtg, content=stanag_content(dtg=dtg)))

# SIC encodings
def sic2(s):
    return struct.pack('!H', sic_value(s, False))


def sic3any(s):
    v = sic_value(s, True)
    assert v < 0x10000
    return bytes([0xB7]) + struct.pack('!H', v)


def sic_multi(sics, anyc):
    key = 0xC0 | (0x08 if anyc else 0) | (len(sics) - 1)
    out = bytes([key])
    for s in sics:
        v = sic_value(s, anyc)
        out += (bytes([0]) + struct.pack('!H', v)) if anyc else struct.pack('!H', v)
    return out


def sic_var_item(s, anyc):
    n = len(s)
    v = sic_value(s, anyc)
    if n == 3:
        return (bytes([0]) + struct.pack('!H', v)) if anyc else struct.pack('!H', v)
    if anyc:
        if n == 4:
            return struct.pack('!I', 0xA0000000 | v)
        if n == 5:
            assert v < 0x80000000
            return struct.pack('!I', v)
        if n == 6:
            return bytes([0xC0 | (v >> 32)]) + struct.pack('!I', v & 0xFFFFFFFF)
        if n == 7:
            return struct.pack('!H', 0xB000 | (v >> 32)) + struct.pack('!I', v & 0xFFFFFFFF)
        if n == 8:
            hi = (v >> 32) & 0x0FFF
            return bytes([0x90, hi >> 8, hi & 0xFF]) + struct.pack('!I', v & 0xFFFFFFFF)
    else:
        if n == 4:
            return struct.pack('!I', (0xC00000 | v) << 8)[:3]
        if n == 5:
            return struct.pack('!I', 0xA0000000 | v)
        if n == 6:
            return struct.pack('!I', v)
        if n == 7:
            return bytes([0xE0 | (v >> 32)]) + struct.pack('!I', v & 0xFFFFFFFF)
        if n == 8:
            return struct.pack('!H', 0xB000 | (v >> 32)) + struct.pack('!I', v & 0xFFFFFFFF)
    raise ValueError(s)


def sic_var(sics, anyc):
    key = 0xD0 | (0x08 if anyc else 0) | (len(sics) - 1)
    bitmap = 0
    for i, s in enumerate(sics):
        if len(s) > 3:
            bitmap |= 1 << (7 - i)
    return bytes([key, bitmap]) + b''.join(sic_var_item(s, anyc) for s in sics)


for sic in (sic2('ABC'), struct.pack('!H', 0xB6FF), sic3any('0a?'),
            bytes([0xBD, 0xFF, 0xFF]), b'\xbe', b'\xfe', b'\xff', b'\xe5',
            sic_multi(['AAA', 'B12', 'ZZZ'], False), sic_multi(['1bc', 'A?='], True),
            sic_var(['AB1', 'ABCD', 'ABCDE', 'ABCDEF', 'ABCDEFG', 'ABCDEFGH'], False),
            sic_var(['1b1', 'abcd', 'abcde', 'abcdef', 'abcdefg', '0Aabcdef', '1/y'], True)):
    add(E, F, simple_stanag(0x4600 + len(main), content=stanag_content(sic=sic)))

# Body formats and compression
add(E, F, simple_stanag(0x4700, content=stanag_content(bf=1),
                        bodyb=b'Subject line\x00' + body(b'With subject')))
add(E, F, simple_stanag(0x4701, content=stanag_content(bf=2), bodyb=b'\x01\x02\x03\x04'))
add(E, F, simple_stanag(0x4702, bodyb=body(zlib.compress(b'Compressed text ' * 4), compr=1)))
add(E, F, simple_stanag(0x4703, bodyb=body(b'not zlib data', compr=1)))
add(E, F, simple_stanag(0x4704, bodyb=body(b'?', compr=2)))
add(E, F, simple_stanag(0x4705, bodyb=body(b'\x01\x02bilateral', eit=3)))
add(E, F, simple_stanag(0x4706, bodyb=body(b'res', res=5)))
add(E, F, simple_stanag(0x4707, bodyb=body(b'')))
add(E, F, simple_stanag(0x4708, content=stanag_content(bf=3), bodyb=b'\x05'))
add(E, F, simple_stanag(0x4709, bodyb=body(zlib.compress(b'bilateral zlib'), compr=1, eit=3)))
add(E, F, simple_stanag(0x470A, content=stanag_content(bf=1), cksum=1,
                        bodyb=b'Subj\x00' + body(b'cksum body')))

# Reports: DR/NDR, info, delivery times, multiple reports, extended addresses
reports = (b'\x40' + b'\x00' + dir_rec(0, 7) + b'Delivered\x00' +          # DR with info
           b'\x80' + b'\x05' + dir_rec(0, 8) +                              # NDR P1 reason
           b'\xbe' + b'\x80\x10' + dir_rec(1, 9) + b'Info\x00' +            # NDR reason 0x3e
           b'\x81' + b'\x7d' + dir_rec(1, 10) +                             # NDR diag 0x7d
           b'\x1f' + b'\xff' + dir_rec(1, 11))                              # DR reserved bits
add(E, F, report_pdu(0x5000, 0x2000, reports, cksum=0, nrec=1))
for dt in (0x50, 0xA0, 0xD0, 0xF0):
    add(E, F, report_pdu(0x5001 + dt, 0x2000, bytes([0x00, dt]) + dir_rec(0, 7), cksum=0))
reports = (b'\x20' + b'\x30' + ext_rec(0, 0, p1=DA) +                       # DR ext addr enc
           b'\xc0' + b'\x81' + ext_rec(2, 0, p1=EA_PER) + b'\x00' +         # NDR ext, empty info
           b'\x40' + b'\x40' + dir_rec(0, 7) + b'L' * 130 + b'\x00')        # info > 128
add(E, F, report_pdu(0x5100, 0x2000, reports, cksum=0, sec=0x02))           # reserved 0x02
add(E, F, report_pdu(0x5101, 0x2000, DR_SIMPLE, cksum=0, version=1))
add(E, F, report_pdu(0x5102, 0x2000, DR_SIMPLE, cksum=0, sec=sec(1, 4), cats=b'\x80'))

# Notifications: RN/NRN/ON, receipt times, ON types, ACP127
for ntype, data in (
        (0, b'\x00' + b'\x00'),                                  # RN, no time, no info
        (0, b'\xff' + b'Info\x00'),                              # RN, reserved time
        (0, b'\x20' + b'M' * 130 + b'\x00'),                     # RN, long info
        (1, b'\x05\x01'),                                        # NRN P22 reasons
        (1, b'\x20\xfe'),                                        # NRN reserved/own
        (1, b'\x10\x10'),
        (2, b'\x30' + b'\x00' + b'On info\x00' + b'ACP127 RCPT\x00'),
        (2, b'\x30' + b'\x02' + b'\x00' + b'R' * 70 + b'\x00'),  # ACP127 > 64
        (2, b'\x30' + b'\x01' + b'\x00' + b'\x00'),              # empty ACP127
        (2, b'\x30' + b'\x05' + b'Other\x00'),                   # ON type >= 3
        (3, b''),                                                # reserved type
):
    add(E, F, notif_pdu(0x5200 + len(main), 0x2000, ntype, data, cksum=0))
add(E, F, notif_pdu(0x5300, 0x2000, 1, b'\x00\x00', cksum=0, version=1))

# Checksum: message whose last octets before the checksum are not decoded
# (reserved notification type), so the checksum is not where the
# dissection ended.  Before the fix it was read from the wrong offset.
add(E, F, notif_pdu(0x5400, 0x2001, 3, b'\x10\x20', cksum=1))
# Bad checksum
bad = simple_stanag(0x5401, cksum=1, text=b'bad checksum')
add(E, F, bad[:-2] + bytes([bad[-2] ^ 0xff, bad[-1]]))

# Two messages with the same id in opposite directions, ACKed
add(C, A, simple_stanag(0x5500, cksum=1))
add(A, C, simple_stanag(0x5500, cksum=1))
add(A, C, with_cksum(ack(0x5500)))


# More SIC characters (any-character SICs of 4 and 6 characters) and
# invalid SICs in a list of 3-character SICs and in a 3-to-8 list
add(E, F, simple_stanag(0x5600, content=stanag_content(sic=sic_var(["'()+,-", '.: ?'], True))))
add(E, F, simple_stanag(0x5601, content=stanag_content(
    sic=bytes([0xC1]) + struct.pack('!HH', sic_value('AAA', False), 0xFFFF))))
add(E, F, simple_stanag(0x5602, content=stanag_content(
    sic=bytes([0xD1, 0x40]) + struct.pack('!H', 0xFFFF) + struct.pack('!I', 0x8FFFFFFF))))
# Permissive category for a nation that is not in the list
add(E, F, simple_stanag(0x5603, content=stanag_content(sec=sec(2, 4), cats=b'\x01\xd8')))
# Reserved bits in an extended direct originator address
add(E, F, simple_stanag(0x5604, orig=dir_addr(20000, res1=1, res2=2)))
# Recipient number above 127 with a direct address (extended encoding)
add(E, F, ext_msg(0x5605, ext_orig(0, DA), ext_rec(0, 300, p1=DA), 1))
# Reserved bit in the second extended recipient number
add(E, F, simple_stanag(0x5606, recips=dir_rec(1100, 6, res=1)))
# X.400 identifiers of length 0, and an IPM identifier with unused bits
ts = ts_of(main)
pdu = b0() + b1(STANAG) + msgid(0x5607, idtype=1, mts=b'') + subm(subm_for(ts)) + \
    flags(1) + b'\x05' + dir_rec(0, 6, notif=1) + b'\x00' + stanag_content() + body(b'empty ids')
add(X1, X2, pdu)
ipm5 = ipmid2[:-1] + bytes([ipmid2[-1] | 0x01])
ts = ts_of(main)
pdu = b0() + b1(STANAG) + msgid(0x5608, idtype=1, mts=mts1) + mts1 + subm(subm_for(ts)) + \
    flags(1) + b'\x05' + dir_rec(0, 6, notif=1) + bytes([len(ipm5)]) + ipm5 + \
    stanag_content() + body(b'bits')
add(X1, X2, pdu)
# Unknown content types 5-7 (only the envelope is decoded)
for t in (5, 7):
    add(E, F, b0() + b1(t) + b'\x00\x00')

# Submission time just after the start of a period, received just before
# its end (first branch of dmp_dec_subm_time()); this frame has a later
# time stamp, so it is the last one.
TS_WRAP = 2 * ((T0 // 2 // 0x7FF8 + 1) * 0x7FF8 + 0x7EF4)
pdu = b0() + b1(STANAG) + msgid(0x5609) + subm(0x10) + flags(1) + b'\x05' + \
    dir_rec(0, 6) + stanag_content() + body(b'wrap')
add(E, F, pdu)
ts_override = {len(main) - 1: TS_WRAP}


# ------------------------------------------------------------------ malformed
def addm(pdu):
    add(E, F, pdu, lst=mal)


addm(b0(3) + b'\x00\x00')                                        # unsupported version
addm(b0(8) + b'\x00')
# 255 security categories (each extended)
addm(simple_stanag(0x6000, ts_lst=mal, content=stanag_content(sec=sec(1, 4), cats=b'\x01' * 300)))
# checksum flag, body too short
addm(b0() + b1(STANAG, 0, 1) + msgid(0x6001) + subm(0) + flags(1) + b'\x05' + dir_rec(0, 6) +
     stanag_content() + b'\x20')
# recipient number above 32767
addm(simple_stanag(0x6002, nrec=2, ts_lst=mal,
                   recips=dir_rec(30000, 6) + dir_rec(5000, 7)))
addm(ext_msg(0x600B, ext_orig(0, DA), ext_rec(0, 32767, p1=DA) + ext_rec(0, 5, p1=DA), 2))
# truncated envelope / content / addresses
full = simple_stanag(0x6003, ts_lst=mal, nrec=2, recips=dir_rec(20, 9000) + dir_rec(1, 7))
for cut in (1, 2, 4, 7, 9, 12, 16, 20):
    addm(full[:cut])
addm(b0() + b1(REPORT) + msgid(0x6004) + subm(0) + flags(1) + dir_rec(0, 5) + b'\x00\x00' +
     b'\x00\x10' + b'\x40\x10' + dir_rec(0, 7) + b'unterminated')
addm(b0() + b1(REPORT, 0, 1) + msgid(0x6005) + subm(0) + flags(1) + dir_rec(0, 5) + b'\x00\x00' +
     b'\x00\x10' + b'\x00')
addm(b0() + b1(NOTIF) + msgid(0x6006) + subm(0) + flags(1) + b'\x05' + dir_rec(0, 5) +
     b'\x02\x00' + b'\x00\x10' + b'\x30\x01' + b'no nul')
addm(ext_msg(0x6007, ext_orig(2, ext_addr(0, b'\x60\x05\x30\x03\x61\x01\x13')),
             ext_rec(0, 0, p1=DA), 1))
addm(b0() + ack_b1(rec=1, cksum=1) + b'\x00\x00\x12\x34' + b'\x30')
addm(simple_stanag(0x6008, ts_lst=mal, content=stanag_content(sic=b'\xd7\xff\xff')))
addm(simple_stanag(0x6009, ts_lst=mal, extensions=b'\xff\x01'))
addm(b0() + b1(STANAG) + msgid(0x600A, idtype=1, mts=b'\x00' * 31) + b'\x00' * 5)


def frames(lst):
    out = []
    for i, f in enumerate(lst):
        ts = T0 + i + 1
        if lst is main and i in ts_override:
            ts = ts_override[i]
        if f[0] == 'raw':
            out.append((ts, f[1]))
        else:
            _, src, dst, pdu, sp, dp = f
            out.append((ts, udp_frame(src, dst, pdu, sp, dp)))
    return out


if __name__ == '__main__':
    outdir = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(outdir, 'dmp-coverage.pcap'), frames(main))
    write_pcap(os.path.join(outdir, 'dmp-coverage-malformed.pcap'), frames(mal))
    print('main %d frames, malformed %d frames' % (len(main), len(mal)))
