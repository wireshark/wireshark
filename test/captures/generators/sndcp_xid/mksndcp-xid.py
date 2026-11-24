#!/usr/bin/env python3
# Generates test/captures/sndcp_xid_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-sndcp-xid.c (SNDCP XID parameters in LLC
# XID/SABM/UA frames of GPRS). Usage: mksndcp-xid.py <outdir>
# The frames are GSMTAP (UDP 4729, type 8 = Gb LLC) frames; the reproducer of
# the offset wrap loop is an Exported PDU frame ("sndcpxid").
import os
import struct
import sys
from pcaplib import (Pcapng, eth, ip4, udp, gsmtap, llc_gprs_u, llc_gprs_ui,
                     exported_pdu, GSMTAP_GB_LLC)

DLT_EN10MB, DLT_EXPORTED_PDU = 1, 252
U_SABM, U_UA, U_XID, U_DM = 0x07, 0x06, 0x0B, 0x01

# --- LLC XID parameters ---------------------------------------------------------
def llc_xid_param(typ, content):
    n = len(content)
    if n <= 3 and typ != 0xB:
        return bytes([(typ << 2) | n]) + content
    if n <= 3:
        return bytes([(typ << 2) | n]) + content
    return bytes([0x80 | (typ << 2) | (n >> 6), (n & 0x3f) << 2]) + content

def l3(content):
    return llc_xid_param(0xB, content)

# --- SNDCP XID parameters ----------------------------------------------------------
def version(v=0, extra=b''):
    return bytes([0, 1 + len(extra), v]) + extra

def comp_param(ptype, entities):
    body = b''.join(entities)
    return bytes([ptype, len(body)]) + body

def dcomp(*e): return comp_param(1, e)
def pcomp(*e): return comp_param(2, e)

def nsapi(*numbers):
    v = 0
    for n in numbers:
        v |= 1 << n             # NSAPI 15 -> 0x8000 ... NSAPI 5 -> 0x0020
    return struct.pack('!H', v)

def entity_p(ent, algo, nibbles, elements):
    body = bytes(nibbles) + elements
    return bytes([0x80 | ent, algo, len(body)]) + body

def entity_np(ent, elements):
    return bytes([ent, len(elements)]) + elements

PCOMP_1144 = lambda ent: entity_p(ent, 0, [0x12], nsapi(5, 6) + b'\x0f')
PCOMP_2507 = lambda ent: entity_p(ent, 1, [0x12, 0x34, 0x50], nsapi(7) + b'\x01\x00' + b'\x05' + b'\x80' + b'\x20' + b'\x02\x00')
ROHC_PROFILES = b''.join(struct.pack('!H', p) for p in range(1, 17))
PCOMP_ROHC = lambda ent: entity_p(ent, 2, [0x01], nsapi(5, 15) + b'\x00\xff' + b'\x00\x90' + ROHC_PROFILES)
DCOMP_V42 = lambda ent: entity_p(ent, 0, [0x01], nsapi(5) + b'\x03' + b'\x04\x00' + b'\x20')
DCOMP_V44 = lambda ent: entity_p(ent, 1, [0x12], nsapi(5, 6, 7) + b'\xc0' + b'\x02' + b'\x04\x00' + b'\x04\x01' + b'\x20\x00' + b'\x20\x01')

# Entities keep their algorithm for the whole capture (the dissector remembers
# the algorithm per entity in a table that is never reset)
PC1, PC2, PC3, PC4 = 1, 2, 3, 4
DC1, DC2 = 1, 2

def main(out):
    p = Pcapng()
    e = p.iface(DLT_EN10MB)
    x = p.iface(DLT_EXPORTED_PDU)
    n = [0]
    def send(llc, sport=1234):
        n[0] += 1
        g = gsmtap(GSMTAP_GB_LLC, llc)
        p.add(eth(ip4(17, udp(g, sport, 4729), ident=n[0]), 0x0800), e)
    def xid(*params, cmd=U_XID, sapi=3, **kw):
        send(llc_gprs_u(sapi, cmd, b''.join(params), **kw))

    # 1-2: XID command and response with the version only
    xid(l3(version(0)))
    xid(l3(version(1)), cr=1)
    # 3: LLC parameter (type 1, one octet) before the L3 parameters
    xid(llc_xid_param(1, b'\x05'), l3(version(0) + dcomp(DCOMP_V42(DC1)) + pcomp(PCOMP_1144(PC1))), sapi=5)
    # 4-5: protocol compression: RFC 2507 and ROHC with all 16 profiles
    xid(l3(version(0) + pcomp(PCOMP_2507(PC2))), sapi=5)
    xid(l3(version(0) + pcomp(PCOMP_ROHC(PC3))), sapi=9, cr=1)
    # 6: data compression: V.44
    xid(l3(version(0) + dcomp(DCOMP_V44(DC2))), sapi=11)
    # 7: everything in one parameter, in a SABM and then a UA
    full = version(2) + dcomp(DCOMP_V42(DC1), DCOMP_V44(DC2)) + pcomp(PCOMP_1144(PC1), PCOMP_2507(PC2), PCOMP_ROHC(PC3))
    xid(l3(full), cmd=U_SABM)
    xid(l3(full), cmd=U_UA, cr=1)
    # 9-11: entities without the P bit (decoded with the algorithm that the
    # entity used before), also an entity that was never defined
    xid(l3(pcomp(entity_np(PC2, nsapi(7) + b'\x01\x00\x05\x80\x20\x02\x00'))))
    xid(l3(dcomp(entity_np(DC2, nsapi(5) + b'\xc0\x02\x04\x00\x04\x01\x20\x00\x20\x01'),
                 entity_np(DC1, nsapi(5, 6) + b'\x03\x04\x00\x20'))))
    xid(l3(pcomp(entity_np(9, nsapi(5) + b'\x0f'), entity_np(PC3, nsapi(5) + b'\x00\xff\x00\x90\x00\x01'))))
    # 12-13: entities with fewer elements than the algorithm has (the list
    # ends with the length) and a version parameter with extra octets
    xid(l3(version(0, b'\xaa\xbb') + dcomp(entity_p(DC1, 0, [0x01], nsapi(5)))))
    xid(l3(pcomp(entity_p(PC4, 1, [0x12, 0x34, 0x50], nsapi(5) + b'\x01\x00'))))
    # 14: algorithm identifiers that are not defined (both kinds), ignored
    xid(l3(dcomp(entity_p(7, 5, [0x01], b'\x00\x00\x00')) + version(0)))
    xid(l3(pcomp(entity_p(7, 9, [0x01], b'\x00\x00\x00')) + version(0)))
    # 16-17: compression parameters shorter than three octets (ignored) and an
    # unknown parameter type (ends the parameter list)
    xid(l3(bytes([1, 2, 0x81, 0x00]) + version(0)))
    xid(l3(version(0) + bytes([7, 3, 1, 2, 3]) + version(0)))
    # 18: L3 parameters longer than 63 octets (the XL bit, length in two octets)
    xid(l3(version(0) + pcomp(PCOMP_ROHC(PC3), PCOMP_ROHC(PC3))))
    # 19: a UI frame on the same SAPI for contrast (SNDCP, not XID)
    send(llc_gprs_ui(3, 5, b'\x00\x00'))
    # 20: the reproducer of "SNDCP-XID: Fix offset wrap infinite loop and two
    # small bugs": an Exported PDU "sndcpxid" of 131071 octets. A compression
    # parameter that is too short, then version parameters.
    payload = bytearray(131071)
    payload[0:4] = b'\x01\x02\x00\x00'
    p.add(exported_pdu('sndcpxid', payload), x)
    p.write(os.path.join(out, 'sndcp-xid-coverage.pcapng'))

    m = Pcapng()
    e = m.iface(DLT_EN10MB)
    def msend(llc):
        n[0] += 1
        m.add(eth(ip4(17, udp(gsmtap(GSMTAP_GB_LLC, llc), 1234, 4729), ident=n[0]), 0x0800), e)
    def mxid(content, cmd=U_XID):
        msend(llc_gprs_u(3, cmd, l3(content)))
    # parameters cut off
    mxid(bytes([0, 1]))                                     # version without a value
    mxid(bytes([1, 20, 0x81, 0x00, 0x08, 0x00]))             # compression longer than the data
    mxid(version(0) + bytes([2, 10]) + b'\x81\x01\x05\x00')
    mxid(bytes([1, 4, 0x81, 0x00, 0x03, 0x01]))              # V.42bis entity with a short element list
    mxid(bytes([2, 5, 0x82, 0x02, 0xff, 0x01, 0x00]))         # ROHC entity longer than the parameter
    mxid(bytes([1, 4, 0x01, 0x00, 0x08, 0x00]))              # P bit clear, undefined entity
    mxid(bytes([2, 3, 0x80 | 31, 0x01, 0x08]))
    msend(llc_gprs_u(3, U_XID, bytes([0xAC, 0x40]) + b'\x00' * 3))   # L3 parameter, XL with length 16 but 3 octets
    m.write(os.path.join(out, 'sndcp-xid-coverage-malformed.pcapng'))

main(sys.argv[1] if len(sys.argv) > 1 else '.')
