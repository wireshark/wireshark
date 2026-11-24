#!/usr/bin/env python3
# Generates test/captures/opa_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic Omni-Path 9B coverage capture generator (packet-opa.c, "opa"): ERF records of
# type 29 (OMNI-PATH) in a pcapng file with link type ERF (197), plus an Ethernet
# interface is not needed.  Synthetic values only (LIDs, QPs, GIDs, payload from a seeded PRNG).
# Usage: mkopa.py <outdir> [probe]
#   probe: write the fitting capture (all sizes of the ladder for every candidate) that
#   fit_opa.py uses to compute the SIZES table.
import struct
import random
import sys
import zlib
import os
import json

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
MODE = sys.argv[2] if len(sys.argv) > 2 else 'main'

LADDER = [0, 8, 16, 24, 32, 40, 48, 64, 80, 96, 128, 160, 192, 256]
SELECT = {   # keys of the frames kept (greedy.py); empty: all of SIZES
    'OP00l', 'OP03l', 'OP06l', 'OP0bl', 'OP0cl', 'OP0dl', 'OP11l', 'OP12l', 'OP13l', 'OP15l',
    'OP16l', 'OP40l', 'OP43l', 'OP46l', 'OP4bl', 'OP4cl', 'OP4dl', 'OP4el', 'OP52l', 'OP53l',
    'OP55l', 'OP65l', 'OPc0l', 'OPc1l', 'OPc2l', 'OPc3l', 'OPc4l', 'OPc5l', 'OPc6l', 'OPc7l',
    'OPc8l', 'OPc9l', 'OPcal', 'OPcbl', 'OPccl', 'OPcdl', 'OPcel', 'OPcfl', 'OPd0l', 'OPd2l',
    'OPd3l', 'OPd4l', 'OPd8l', 'OPe0l', 'OPe1l', 'OPe2l', 'OPe3l', 'OPe4l', 'OPe5l', 'OPe6l',
    'OPe7l'
}
SIZES = {
    'OP00g': 16, 'OP00l': 16, 'OP01g': 16, 'OP01l': 16, 'OP02g': 16, 'OP02l': 16, 'OP03g': 16,
    'OP03l': 16, 'OP04g': 16, 'OP04l': 16, 'OP05g': 16, 'OP05l': 16, 'OP06g': 16, 'OP06l': 16,
    'OP07g': 16, 'OP07l': 16, 'OP08g': 16, 'OP08l': 16, 'OP09g': 16, 'OP09l': 16, 'OP0ag': 16,
    'OP0al': 16, 'OP0bg': 16, 'OP0bl': 16, 'OP0cg': 16, 'OP0cl': 16, 'OP0dg': 16, 'OP0dl': 16,
    'OP0eg': 16, 'OP0el': 16, 'OP0fg': 16, 'OP0fl': 16, 'OP10g': 16, 'OP10l': 16, 'OP11g': 16,
    'OP11l': 16, 'OP12g': 16, 'OP12l': 16, 'OP13g': 24, 'OP13l': 24, 'OP14g': 24, 'OP14l': 24,
    'OP15g': 16, 'OP15l': 16, 'OP16g': 16, 'OP16l': 16, 'OP17g': 16, 'OP17l': 16, 'OP18g': 16,
    'OP18l': 16, 'OP19g': 16, 'OP19l': 16, 'OP1ag': 16, 'OP1al': 16, 'OP1bg': 16, 'OP1bl': 16,
    'OP1cg': 16, 'OP1cl': 16, 'OP1dg': 16, 'OP1dl': 16, 'OP1eg': 16, 'OP1el': 16, 'OP1fg': 16,
    'OP1fl': 16, 'OP20g': 16, 'OP20l': 16, 'OP21g': 16, 'OP21l': 16, 'OP22g': 16, 'OP22l': 16,
    'OP23g': 16, 'OP23l': 16, 'OP24g': 16, 'OP24l': 16, 'OP25g': 16, 'OP25l': 16, 'OP26g': 16,
    'OP26l': 16, 'OP27g': 16, 'OP27l': 16, 'OP28g': 16, 'OP28l': 16, 'OP29g': 16, 'OP29l': 16,
    'OP2ag': 16, 'OP2al': 16, 'OP2bg': 16, 'OP2bl': 16, 'OP2cg': 16, 'OP2cl': 16, 'OP2dg': 16,
    'OP2dl': 16, 'OP2eg': 16, 'OP2el': 16, 'OP2fg': 16, 'OP2fl': 16, 'OP30g': 16, 'OP30l': 16,
    'OP31g': 16, 'OP31l': 16, 'OP32g': 16, 'OP32l': 16, 'OP33g': 16, 'OP33l': 16, 'OP34g': 16,
    'OP34l': 16, 'OP35g': 16, 'OP35l': 16, 'OP36g': 16, 'OP36l': 16, 'OP37g': 16, 'OP37l': 16,
    'OP38g': 16, 'OP38l': 16, 'OP39g': 16, 'OP39l': 16, 'OP3ag': 16, 'OP3al': 16, 'OP3bg': 16,
    'OP3bl': 16, 'OP3cg': 16, 'OP3cl': 16, 'OP3dg': 16, 'OP3dl': 16, 'OP3eg': 16, 'OP3el': 16,
    'OP3fg': 16, 'OP3fl': 16, 'OP40g': 16, 'OP40l': 16, 'OP41g': 16, 'OP41l': 16, 'OP42g': 40,
    'OP42l': 16, 'OP43g': 16, 'OP43l': 16, 'OP44g': 16, 'OP44l': 16, 'OP45g': 16, 'OP45l': 16,
    'OP46g': 24, 'OP46l': 24, 'OP47g': 16, 'OP47l': 16, 'OP48g': 16, 'OP48l': 16, 'OP49g': 16,
    'OP49l': 16, 'OP4ag': 24, 'OP4al': 24, 'OP4bg': 32, 'OP4bl': 32, 'OP4cg': 24, 'OP4cl': 24,
    'OP4dg': 16, 'OP4dl': 16, 'OP4eg': 16, 'OP4el': 16, 'OP4fg': 16, 'OP4fl': 16, 'OP50g': 16,
    'OP50l': 16, 'OP51g': 16, 'OP51l': 16, 'OP52g': 16, 'OP52l': 16, 'OP53g': 40, 'OP53l': 40,
    'OP54g': 40, 'OP54l': 40, 'OP55g': 16, 'OP55l': 16, 'OP56g': 16, 'OP56l': 16, 'OP57g': 16,
    'OP57l': 16, 'OP58g': 16, 'OP58l': 16, 'OP59g': 16, 'OP59l': 16, 'OP5ag': 16, 'OP5al': 16,
    'OP5bg': 16, 'OP5bl': 16, 'OP5cg': 16, 'OP5cl': 16, 'OP5dg': 16, 'OP5dl': 16, 'OP5eg': 16,
    'OP5el': 16, 'OP5fg': 16, 'OP5fl': 16, 'OP60g': 16, 'OP60l': 16, 'OP61g': 16, 'OP61l': 16,
    'OP62g': 16, 'OP62l': 16, 'OP63g': 16, 'OP63l': 16, 'OP64g': 16, 'OP64l': 32, 'OP65g': 16,
    'OP65l': 16, 'OP66g': 16, 'OP66l': 16, 'OP67g': 16, 'OP67l': 16, 'OP68g': 16, 'OP68l': 16,
    'OP69g': 16, 'OP69l': 16, 'OP6ag': 16, 'OP6al': 16, 'OP6bg': 16, 'OP6bl': 16, 'OP6cg': 16,
    'OP6cl': 16, 'OP6dg': 16, 'OP6dl': 16, 'OP6eg': 16, 'OP6el': 16, 'OP6fg': 16, 'OP6fl': 16,
    'OP70g': 16, 'OP70l': 16, 'OP71g': 16, 'OP71l': 16, 'OP72g': 16, 'OP72l': 16, 'OP73g': 16,
    'OP73l': 16, 'OP74g': 16, 'OP74l': 16, 'OP75g': 16, 'OP75l': 16, 'OP76g': 16, 'OP76l': 16,
    'OP77g': 16, 'OP77l': 16, 'OP78g': 16, 'OP78l': 16, 'OP79g': 16, 'OP79l': 16, 'OP7ag': 16,
    'OP7al': 16, 'OP7bg': 16, 'OP7bl': 16, 'OP7cg': 16, 'OP7cl': 16, 'OP7dg': 16, 'OP7dl': 16,
    'OP7eg': 16, 'OP7el': 16, 'OP7fg': 16, 'OP7fl': 16, 'OP80g': 16, 'OP80l': 16, 'OP81g': 16,
    'OP81l': 16, 'OP82g': 16, 'OP82l': 16, 'OP83g': 16, 'OP83l': 16, 'OP84g': 16, 'OP84l': 16,
    'OP85g': 16, 'OP85l': 16, 'OP86g': 16, 'OP86l': 16, 'OP87g': 16, 'OP87l': 16, 'OP88g': 16,
    'OP88l': 16, 'OP89g': 16, 'OP89l': 16, 'OP8ag': 16, 'OP8al': 16, 'OP8bg': 16, 'OP8bl': 16,
    'OP8cg': 16, 'OP8cl': 16, 'OP8dg': 16, 'OP8dl': 16, 'OP8eg': 16, 'OP8el': 16, 'OP8fg': 16,
    'OP8fl': 16, 'OP90g': 16, 'OP90l': 16, 'OP91g': 16, 'OP91l': 16, 'OP92g': 16, 'OP92l': 16,
    'OP93g': 16, 'OP93l': 16, 'OP94g': 16, 'OP94l': 16, 'OP95g': 16, 'OP95l': 16, 'OP96g': 16,
    'OP96l': 16, 'OP97g': 16, 'OP97l': 16, 'OP98g': 16, 'OP98l': 16, 'OP99g': 16, 'OP99l': 16,
    'OP9ag': 16, 'OP9al': 16, 'OP9bg': 16, 'OP9bl': 16, 'OP9cg': 16, 'OP9cl': 16, 'OP9dg': 16,
    'OP9dl': 16, 'OP9eg': 16, 'OP9el': 16, 'OP9fg': 16, 'OP9fl': 16, 'OPa0g': 16, 'OPa0l': 16,
    'OPa1g': 16, 'OPa1l': 16, 'OPa2g': 16, 'OPa2l': 16, 'OPa3g': 16, 'OPa3l': 16, 'OPa4g': 16,
    'OPa4l': 16, 'OPa5g': 16, 'OPa5l': 16, 'OPa6g': 16, 'OPa6l': 16, 'OPa7g': 16, 'OPa7l': 16,
    'OPa8g': 16, 'OPa8l': 16, 'OPa9g': 16, 'OPa9l': 16, 'OPaag': 16, 'OPaal': 16, 'OPabg': 16,
    'OPabl': 16, 'OPacg': 16, 'OPacl': 16, 'OPadg': 16, 'OPadl': 16, 'OPaeg': 16, 'OPael': 16,
    'OPafg': 16, 'OPafl': 16, 'OPb0g': 16, 'OPb0l': 16, 'OPb1g': 16, 'OPb1l': 16, 'OPb2g': 16,
    'OPb2l': 16, 'OPb3g': 16, 'OPb3l': 16, 'OPb4g': 16, 'OPb4l': 16, 'OPb5g': 16, 'OPb5l': 16,
    'OPb6g': 16, 'OPb6l': 16, 'OPb7g': 16, 'OPb7l': 16, 'OPb8g': 16, 'OPb8l': 16, 'OPb9g': 16,
    'OPb9l': 16, 'OPbag': 16, 'OPbal': 16, 'OPbbg': 16, 'OPbbl': 16, 'OPbcg': 16, 'OPbcl': 16,
    'OPbdg': 16, 'OPbdl': 16, 'OPbeg': 16, 'OPbel': 16, 'OPbfg': 16, 'OPbfl': 16, 'OPc0g': 16,
    'OPc0l': 16, 'OPc1g': 32, 'OPc1l': 32, 'OPc2g': 40, 'OPc2l': 40, 'OPc3g': 32, 'OPc3l': 32,
    'OPc4g': 32, 'OPc4l': 32, 'OPc5g': 32, 'OPc5l': 32, 'OPc6g': 32, 'OPc6l': 32, 'OPc7g': 32,
    'OPc7l': 32, 'OPc8g': 32, 'OPc8l': 32, 'OPc9g': 32, 'OPc9l': 32, 'OPcag': 32, 'OPcal': 32,
    'OPcbg': 32, 'OPcbl': 32, 'OPccg': 32, 'OPccl': 32, 'OPcdg': 32, 'OPcdl': 32, 'OPceg': 32,
    'OPcel': 32, 'OPcfg': 32, 'OPcfl': 32, 'OPd0g': 32, 'OPd0l': 32, 'OPd1g': 32, 'OPd1l': 32,
    'OPd2g': 32, 'OPd2l': 32, 'OPd3g': 16, 'OPd3l': 16, 'OPd4g': 32, 'OPd4l': 32, 'OPd5g': 32,
    'OPd5l': 32, 'OPd6g': 32, 'OPd6l': 32, 'OPd7g': 32, 'OPd7l': 32, 'OPd8g': 32, 'OPd8l': 32,
    'OPd9g': 32, 'OPd9l': 32, 'OPdag': 32, 'OPdal': 32, 'OPdbg': 16, 'OPdbl': 16, 'OPdcg': 16,
    'OPdcl': 16, 'OPddg': 16, 'OPddl': 16, 'OPdeg': 16, 'OPdel': 16, 'OPdfg': 16, 'OPdfl': 16,
    'OPe0g': 32, 'OPe0l': 32, 'OPe1g': 32, 'OPe1l': 32, 'OPe2g': 32, 'OPe2l': 32, 'OPe3g': 32,
    'OPe3l': 32, 'OPe4g': 32, 'OPe4l': 32, 'OPe5g': 32, 'OPe5l': 32, 'OPe6g': 32, 'OPe6l': 32,
    'OPe7g': 32, 'OPe7l': 32, 'OPe8g': 16, 'OPe8l': 16, 'OPe9g': 16, 'OPe9l': 16, 'OPeag': 16,
    'OPeal': 16, 'OPebg': 16, 'OPebl': 16, 'OPecg': 16, 'OPecl': 16, 'OPedg': 16, 'OPedl': 16,
    'OPeeg': 16, 'OPeel': 16, 'OPefg': 16, 'OPefl': 16, 'OPf0g': 16, 'OPf0l': 16, 'OPf1g': 16,
    'OPf1l': 16, 'OPf2g': 16, 'OPf2l': 16, 'OPf3g': 16, 'OPf3l': 16, 'OPf4g': 16, 'OPf4l': 16,
    'OPf5g': 16, 'OPf5l': 16, 'OPf6g': 16, 'OPf6l': 16, 'OPf7g': 16, 'OPf7l': 16, 'OPf8g': 16,
    'OPf8l': 16, 'OPf9g': 16, 'OPf9l': 16, 'OPfag': 16, 'OPfal': 16, 'OPfbg': 16, 'OPfbl': 16,
    'OPfcg': 16, 'OPfcl': 16, 'OPfdg': 16, 'OPfdl': 16, 'OPfeg': 16, 'OPfel': 16, 'OPffg': 16,
    'OPffl': 16
}

def fill(key, n):
    r = random.Random(zlib.crc32(key.encode()))
    out = bytearray()
    for _ in range(n):
        x = r.random()
        out.append(0 if x < 0.5 else (r.randrange(1, 4) if x < 0.75 else r.randrange(256)))
    return bytes(out)

def l2_9b(lnh, plen, dlid=0x0011, slid=0x0022, sl=1, sc=0, lver=0, res=0):
    return struct.pack('>BBHHH', (sc << 4) | lver, (sl << 4) | (res << 2) | lnh, dlid, (plen // 4) & 0xFFF, slid)

def grh(nxt, plen, tclass=0x12, flow=0x5A5A5, sgid=1, dgid=2):
    return struct.pack('>IHBB', (6 << 28) | (tclass << 20) | flow, plen, nxt, 64) + \
        bytes([0xFE, 0x80] + [0] * 13 + [sgid]) + bytes([0xFE, 0x80] + [0] * 13 + [dgid])

def bth(key, opcode, dqp, psn=1, a=0):
    r = random.Random(zlib.crc32(key.encode()))
    b1 = r.getrandbits(8)                  # SE, MigReq, PadCnt, TVer
    pkey = 0xFFFF if r.random() < 0.5 else r.getrandbits(16)
    b4 = r.getrandbits(8) & 0xC0           # FCN, BCN
    return struct.pack('>BBHB', opcode, b1, pkey, b4) + struct.pack('>I', dqp)[1:] + \
        struct.pack('>I', (a << 31) | psn)

def erf(pkt):
    rlen = 16 + len(pkt)
    return struct.pack('<Q', 0) + struct.pack('>BBHHH', 29, 0, rlen, 0, len(pkt)) + pkt

def blk(t, b):
    b += b'\0' * ((4 - len(b) % 4) % 4)
    return struct.pack('<II', t, len(b) + 12) + b + struct.pack('<I', len(b) + 12)

class Cap:
    def __init__(self):
        self.recs = []
    def add(self, pkt):
        self.recs.append(pkt)
    def write(self, path):
        with open(path, 'wb') as f:
            f.write(blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
            f.write(blk(1, struct.pack('<HHI', 197, 0, 0)))
            for k, d in enumerate(self.recs):
                d = erf(d)
                ts = 1600000000 * 10**6 + k * 1000
                f.write(blk(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xFFFFFFFF, len(d), len(d)) + d))
        return len(self.recs)

class Item:
    def __init__(self, key, build):
        self.key, self.build = key, build

def ud_data_packet(data, dqp=7, sqp=8):
    body = bth('ud', 0x64, dqp) + struct.pack('>IB', 0x80010000, 0) + struct.pack('>I', sqp)[1:] + data + b'\0\0\0\0'
    return l2_9b(2, len(body) + 8) + body

def items_main():
    items = []
    # every BTH opcode, local (LNH 2) and global (LNH 3 with GRH next header 0x1B); the
    # headers that follow depend on the opcode (RDETH, DETH, RETH, AETH, ..., KDETH + PSM)
    for opcode in range(256):
        for kind in ('l', 'g'):
            key = 'OP%02x%s' % (opcode, kind)
            def b(sz, opcode=opcode, kind=kind, key=key):
                payload = fill(key, sz)
                if 0xC0 <= opcode <= 0xDA and sz >= 28 + 8:
                    # PSM header: length of the short message payload (offset 20 of the PSM header)
                    p = bytearray(payload); p[8 + 20:8 + 24] = struct.pack('<I', 8); payload = bytes(p)
                body = bth(key, opcode, 0x000123 if opcode != 0x64 else 5) + payload + b'\0\0\0\0'
                if kind == 'l':
                    return l2_9b(2, len(body) + 8) + body
                body = grh(0x1B, len(body)) + body
                return l2_9b(3, len(body) + 8) + body
            items.append(Item(key, b))
    return items


def icmp6_echo(src, dst, payload=b'\x01\x02\x03\x04\x05\x06\x07\x08'):
    msg = struct.pack('>BBHHH', 128, 0, 0, 0x1234, 1) + payload
    pseudo = src + dst + struct.pack('>IBBBB', len(msg), 0, 0, 0, 58)
    s = sum(struct.unpack('>%dH' % ((len(pseudo) + len(msg)) // 2), pseudo + msg))
    while s >> 16: s = (s >> 16) + (s & 0xFFFF)
    msg = msg[:2] + struct.pack('>H', (~s) & 0xFFFF) + msg[4:]
    return struct.pack('>IHBB', 0x60000000, len(msg), 58, 64) + src + dst + msg

def ib_mad(cls, method, attr, tid, amod=0):
    # InfiniBand MAD (base version 1, 256 bytes): the IB dissector takes the frame over
    return (struct.pack('>BBBBHHQHHI', 1, cls, 1, method, 0, 0, tid, attr, 0, amod) + bytes(232))[:256]

def extras(g):
    n0 = len(g.recs)
    A = bytes([0xFE, 0x80] + [0] * 13 + [1])
    B = bytes([0xFE, 0x80] + [0] * 13 + [2])
    # IPv6 over OPA (LNH 1): an ICMPv6 echo request; the 4 bytes after the packet are not part of it
    ip6 = icmp6_echo(A, B)
    g.add(l2_9b(1, len(ip6) + 4 + 8) + ip6 + b'\0\0\0\0')
    # raw (LNH 0) packets
    g.add(l2_9b(0, 24) + fill('raw', 12) + b'\0\0\0\0')
    g.add(l2_9b(0, 12, sl=3, sc=2, lver=1, res=1, dlid=0xFFFF) + b'\0\0\0\0')
    # GRH whose next header is not BTH (0x1B): only the GRH is decoded
    for nxt in (0x11, 0x3B):
        body = fill('grh%d' % nxt, 24)
        g.add(l2_9b(3, 40 + len(body) + 8) + grh(nxt, len(body)) + body)
    # InfiniBand MAD in an OPA frame (UD Send Only, base version 1 at the MAD): the infiniband
    # dissector takes it over, locally and with a GRH
    udh = bth('ib', 0x64, 0) + struct.pack('>IB', 0x80010000, 0) + struct.pack('>I', 2)[1:]
    m = ib_mad(0x01, 0x01, 0x0011, 0x77) + b'\0\0\0\0'
    g.add(l2_9b(2, 8 + len(udh) + len(m)) + udh + m)
    m = ib_mad(0x04, 0x01, 0x0010, 0x78, 0) + b'\0\0\0\0'
    body = bth('ib2', 0x64, 1) + struct.pack('>IB', 0x80010000, 0) + struct.pack('>I', 2)[1:] + m
    # the IB check reads the "next header" of a GRH at byte 6 of the 9B header (the Source
    # LID), not at byte 6 of the GRH, so only a Source LID of 0x1Bxx gets here (see README)
    g.add(l2_9b(3, 8 + 40 + len(body), slid=0x1B22) + grh(0x1B, len(body)) + body)
    # management datagrams through OPA (QP 0 and 1): SM, SA, PM (see opa-mad-coverage for the MAD content)
    def mad(cls, method, attr, tid, data=b''):
        return struct.pack('>BBBBHHQHHI', 0x80, cls, 0x80, method, 0, 0, tid, attr, 0, 0) + data
    for dqp, sqp, payload in (
            (0, 2, mad(0x01, 0x01, 0x01, 1) + struct.pack('>Q', 0)),
            (1, 5, mad(0x03, 0x12, 0x11, 2) + struct.pack('>BBBBII', 1, 0, 0, 0, 0, 0) + struct.pack('>QHHQ', 0, 0, 0, 0)),
            (1, 6, mad(0x04, 0x01, 0x40, 3) + struct.pack('>BxxxI', 1, 1)),
            (7, 1, mad(0x01, 0x01, 0x11, 4) + struct.pack('>Q', 0))):
        body = bth('mad%d' % tid_(payload), 0x64, dqp, 9) + struct.pack('>IB', 0x80010000, 0) + struct.pack('>I', sqp)[1:] + payload + b'\0\0\0\0'
        g.add(l2_9b(2, len(body) + 8) + body)
    # Ethernet over OPA: UD packets to QPs other than 0/1 start with an Ethertype and a zero reserved field
    ip4 = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + 8, 1, 0, 64, 17, 0, bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])) + \
        struct.pack('>HHHH', 9, 9, 8, 0)
    g.add(ud_data_packet(b'\x08\x00\x00\x00' + ip4))
    g.add(ud_data_packet(b'\x08\x06\x00\x00' + bytes(28)))
    g.add(ud_data_packet(b'\x08\x00\x00\x01' + ip4))      # reserved field not zero: left undecoded
    g.add(ud_data_packet(b'\xFE\xFE\x00\x00' + fill('noeth', 16)))   # no dissector for the Ethertype
    # RD Acknowledge (fix of "OPA: Fix several small dissection errors"): RDETH, then AETH
    for kind in ('l', 'g'):
        body = bth('rdack', 0x51, 0x000123, 5) + struct.pack('>BBBB', 0, 0x12, 0x34, 0x56) + \
            struct.pack('>BBBB', 0x1F, 0xAB, 0xCD, 0xEF) + b'\0\0\0\0'
        if kind == 'l':
            g.add(l2_9b(2, len(body) + 8) + body)
        else:
            body = grh(0x1B, len(body)) + body
            g.add(l2_9b(3, len(body) + 8) + body)
    return len(g.recs) - n0

def tid_(b):
    return zlib.crc32(b)

def build_main(outdir):
    g = Cap()
    for it in items_main():
        if it.key in SIZES and (not SELECT or os.environ.get('ALL') or it.key in SELECT):
            g.add(it.build(SIZES[it.key]))
    extras(g)
    n = g.write(os.path.join(outdir, 'opa-coverage.pcapng'))
    print(n, 'frames')

def build_malformed(outdir):
    # truncated packets (every candidate cut after its BTH or in the middle of its headers),
    # a PSM Short message whose payload length exceeds the packet, a 9B header cut short
    g = Cap()
    for it in items_main():
        if it.key in SIZES and (not SELECT or it.key in SELECT):
            full = it.build(SIZES[it.key])
            g.add(full[:8 + 12 + 3])
            g.add(full[:len(full) - 4 - SIZES[it.key] // 2 - 2])
    p = fill('psm', 64)
    p = p[:8 + 20] + struct.pack('<I', 0x7FFFFFF0) + p[8 + 24:]
    body = bth('psm', 0xC2, 0x123) + p + b'\0\0\0\0'
    g.add(l2_9b(2, len(body) + 8) + body)
    g.add(l2_9b(2, 8)[:5])
    g.add(l2_9b(3, 8)[:8] + grh(0x1B, 4)[:20])
    n = g.write(os.path.join(outdir, 'opa-coverage-malformed.pcapng'))
    print(n, 'frames (malformed)')

def build_probe(outdir):
    g = Cap()
    index = []
    for it in items_main():
        for sz in LADDER:
            g.add(it.build(sz))
            index.append((it.key, sz))
    g.write(os.path.join(outdir, 'probe.pcapng'))
    json.dump(index, open(os.path.join(outdir, 'probe.json'), 'w'))
    print(len(index), 'probe frames')

if __name__ == '__main__':
    (build_probe if MODE == 'probe' else build_main)(OUT)
    if MODE != 'probe' and not os.environ.get('ALL'):
        build_malformed(OUT)
