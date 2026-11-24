#!/usr/bin/env python3
# Generates the epl captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures and device profiles that exercise the
Ethernet POWERLINK dissector (packet-epl.c) and its device profile
parser (packet-epl-profile-parser.c).

POWERLINK runs directly over Ethernet with ethertype 0x88AB (and over
UDP port 3819), registered by default. A managing node (MN, node 240)
polls controlled nodes (CN 1-9); every frame starts with the message
type, destination and source node. The SDO (service data object)
protocol in ASnd frames has a sequence layer and a command layer
(read/write by index, read/write multiple parameters, segmented
transfers). SDO writes to the PDO mapping objects 0x1600/0x1A00 set up
how PReq/PRes payloads are split. Every packet is built from scratch
with struct; no captured traffic is used (MAC addresses 02:00:00:00:00:nn
for node nn, IPv4 192.168.100.0/24 as POWERLINK prescribes).

Usage: mkepl.py <output directory> [-v]

Writes:
  epl-coverage.pcap            every message type, every ASnd/AInv
                               service, NMT commands, SDO sequence
                               layer states and duplicates, every SDO
                               command, segmented transfers, PDO
                               mappings set by SDO and used for PReq and
                               PRes, more than 4096 mappings, POWERLINK
                               over UDP
  epl-coverage-malformed.pcap  frames cut short, sizes past the end
  epl_coverage.eds             EDS profile (no [FileInfo] Description),
                               used with the node ID table for CN 2
  epl_coverage.xdd             XDD profile (no communication profile
                               name, an empty attribute, PDO mappings in
                               default/actual values), used with the
                               device type table for CN 4
  epl-runcov-*.eds/.xdd        more profiles for runcov.sh only (not
                               committed): a Description, a garbage
                               file, an XDD with a profile name, broken
                               XML
"""

import os
import struct
import sys

ETHERTYPE = 0x88AB
MN = 240
MC_SOC = bytes.fromhex('01111e000001')
MC_PRES = bytes.fromhex('01111e000002')
MC_SOA = bytes.fromhex('01111e000003')
MC_ASND = bytes.fromhex('01111e000004')
MC_AMNI = bytes.fromhex('01111e000005')

SOC, PREQ, PRES, SOA, ASND, AMNI, AINV = 1, 3, 4, 5, 6, 7, 0x0d

FRAMES = []
NAMES = {}


def mac(node):
    return bytes((2, 0, 0, 0, 0, node))


def add(frame, name=None):
    FRAMES.append(frame)
    if name:
        NAMES[name] = len(FRAMES)
    return len(FRAMES)


def eth(src, dst_mac, payload):
    return dst_mac + mac(src) + struct.pack('>H', ETHERTYPE) + payload


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def udp_epl(src, dst, payload):
    sip, dip = bytes((192, 168, 100, src)), bytes((192, 168, 100, dst))
    udp = struct.pack('>HHHH', 3819, 3819, 8 + len(payload), 0) + payload
    ph = struct.pack('>4s4sBBH', sip, dip, 0, 17, len(udp))
    udp = udp[:6] + struct.pack('>H', csum(ph + udp)) + udp[8:]
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0, sip, dip)
    ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
    return mac(dst) + mac(src) + b'\x08\x00' + ip + udp


def epl(mtyp, dest, src, body):
    return bytes((mtyp, dest, src)) + body


def soc(flags=0, secs=1700000000, nsecs=0, rel=0):
    return eth(MN, MC_SOC, epl(SOC, 255, MN, b'\0' + bytes((flags,)) + b'\0' +
                              struct.pack('<IIQ', secs, nsecs, rel)))


def preq(cn, payload, flags=0x01, flags2=0, pdov=0x20, size=None):
    return eth(MN, mac(cn), epl(PREQ, cn, MN, struct.pack('<BBBBBH', 0, flags, flags2, pdov, 0,
                                                          len(payload) if size is None else size) + payload))


def pres(src, payload, state=0xFD, flags=0x01, flags2=0, pdov=0x20, size=None):
    return eth(src, MC_PRES, epl(PRES, 255, src, struct.pack('<BBBBBH', state, flags, flags2, pdov, 0,
                                                             len(payload) if size is None else size) + payload))


def soa(svid, target, state=0xFD, flags=0, eplv=0x20, rr=0, src=MN, sync=None):
    b = struct.pack('<BBBBBBB', state, flags, 0, svid, target, eplv, rr)
    if sync is not None:
        b += sync
    return eth(src, MC_SOA, epl(SOA, 255, src, b))


def asnd(src, dest, svid, data, dst_mac=None):
    return eth(src, dst_mac or (mac(dest) if dest not in (255,) else MC_ASND),
               epl(ASND, dest, src, bytes((svid,)) + data))


def ainv(dest, svid, data=b'', state=0xFD, flags=0x06):
    return eth(MN, mac(dest), epl(AINV, dest, MN, struct.pack('<BBBB', state, 0, flags, svid) + data))


def ident(device_type, vendor, product, state=0x5D, en=0x18, flags2=0x0a, hostname=b'cn'):
    b = struct.pack('<BBBBBB', en, flags2, state, 0, 0x20, 0)
    b += struct.pack('<IHHHI', 0x0004021f, 1500, 36, 24, 25000)
    b += struct.pack('<HHH', 0, device_type, 0x0001)
    b += struct.pack('<IIII', vendor, product, 0x00010002, 0x12345678)
    b += struct.pack('<Q', 0x1122334455667788)
    b += struct.pack('<IIII', 20231114, 3600, 20231114, 7200)
    # IPv4 address, subnet mask and gateway as little endian U32
    b += bytes((1, 100, 168, 192)) + bytes((0, 255, 255, 255)) + bytes((254, 100, 168, 192))
    b += hostname.ljust(32, b'\0') + bytes(range(48))
    return b


def status(entries=(), state=0xFD):
    b = struct.pack('<BBBBBB', 0x18, 0x0a, state, 0, 0, 0)
    b += struct.pack('<BB', 0x85, 0) + bytes(range(1, 7))
    for typ, code, secs, add_info in entries:
        b += struct.pack('<HHIIQ', typ, code, secs, 0, add_info)
    return b


def sync_resp():
    return b'\0\0' + bytes((0x03, 0, 0, 0x80)) + struct.pack('<IIIII', 100, 1, 200, 300, 400)


class Seq:
    """SDO sequence numbers of one direction of a transfer."""

    def __init__(self):
        self.n = 20

    def next(self):
        self.n = (self.n + 1) % 64
        return self.n


SEQS = {}


def sdo(src, dest, cmd=b'', rcon=2, scon=2, rseq=None, sseq=None, dst_mac=None):
    """ASnd SDO with a sequence layer; the sequence numbers count up per
    (src, dest) unless given."""
    key = (src, dest)
    if key not in SEQS:
        SEQS[key] = (Seq(), Seq())
    r, s = SEQS[key]
    rs = r.next() if rseq is None else rseq
    ss = s.next() if sseq is None else sseq
    seq = struct.pack('<BBH', (rs << 2) | rcon, (ss << 2) | scon, 0)
    return asnd(src, dest, 5, seq + cmd, dst_mac=dst_mac)


def cmd(cid, data, tid=1, response=False, abort=False, seg=0, segsize=None):
    flags = (0x80 if response else 0) | (0x40 if abort else 0) | (seg << 4)
    return struct.pack('<BBBBHH', 0, tid, flags, cid, len(data) if segsize is None else segsize, 0) + data


def wbi(idx, sub, data):
    """Write by index (expedited) request payload."""
    return struct.pack('<HBB', idx, sub, 0) + data


def mapping(idx, sub, bit_offset, bits):
    return struct.pack('<HBBHBB', idx, sub, 0, bit_offset, bits, 0)


def multi_entries(entries, base=16):
    """Write Multiple Parameter by Index request entries (or Read Multiple
    response entries): each with the offset of the next entry (counted
    from octet 8, 0 for the last), index, subindex, flags/padding, data
    padded to 4 octets. entries: (idx, sub, data[, flagbits])"""
    out = b''
    for k, e in enumerate(entries):
        idx, sub, data = e[0], e[1], e[2]
        flagbits = e[3] if len(e) > 3 else 0
        pad = (-len(data)) % 4
        datalength = 8 + len(data) + pad
        nxt = 0 if k == len(entries) - 1 else (base + len(out) - 8) + datalength
        out += struct.pack('<IHBB', nxt, idx, sub, flagbits | pad) + data + b'\0' * pad
    return out


def main_frames():
    # ---- 1-15: a POWERLINK cycle and the SoA/ASnd services ----
    add(soc(0x00), 'soc')
    add(soc(0xc8, 1700000001, 500000000, 123456789), 'soc_flags')
    add(preq(1, b'\x11\x22\x33\x44', flags=0x25, flags2=0xc0, pdov=0x21), 'preq_nomap')
    add(pres(1, b'\xa1\xa2\xa3\xa4\xa5\xa6', state=0x6D, flags=0x31, flags2=0xff), 'pres_nomap')
    add(pres(MN, b'\x01\x02', state=0x6D), 'pres_mn')
    add(preq(2, b''), 'preq_empty')
    add(soa(0, 0), 'soa_noservice')
    add(soa(1, 1, flags=0x0e, state=0x1D), 'soa_ident')
    add(soa(2, 1, flags=0x04), 'soa_status')
    add(soa(3, 2, flags=0x02, rr=0x0f), 'soa_nmtreq')
    add(soa(4, 1), 'soa_reserved')
    add(soa(6, 3, sync=bytes((0x3f, 0, 0, 0xc0)) + struct.pack('<IIIII', 1, 2, 3, 4, 5) + mac(3)), 'soa_sync')
    add(soa(0xa5, 1), 'soa_manuf')
    add(soa(255, 2), 'soa_unspec')
    add(soa(0, 0, src=5, state=0x1D), 'soa_from_cn')
    # ---- IdentResponses (CN 1: 401/DEADBEEF/8BADF00D, CN 2: 401/0/0,
    #      CN 3 unknown device type, CN 4 for the XDD, the MN) ----
    add(asnd(1, 255, 1, ident(401, 0xDEADBEEF, 0x8BADF00D, hostname=b'cn1')), 'ires_cn1')
    add(asnd(2, 255, 1, ident(401, 0, 0, hostname=b'cn2')), 'ires_cn2')
    add(asnd(3, 255, 1, ident(0x1234, 0x11, 0x22, hostname=b'cn3')), 'ires_cn3')
    add(asnd(4, 255, 1, ident(401, 0xDEADBEEF, 0x8BADF00D, hostname=b'cn4')), 'ires_cn4')
    add(asnd(MN, 255, 1, ident(0, 0, 0, state=0xFD, hostname=b'mn')), 'ires_mn')
    # CN 1 again with another device type (a new conversation)
    add(asnd(1, 255, 1, ident(402, 0xDEADBEEF, 0x8BADF00D, hostname=b'cn1')), 'ires_cn1_again')
    add(asnd(1, 255, 1, ident(401, 0xDEADBEEF, 0x8BADF00D, hostname=b'cn1')), 'ires_cn1_back')
    # StatusResponses with no and two error entries, from the MN
    add(asnd(1, 255, 2, status()), 'sres_0')
    add(asnd(2, 255, 2, status([(0x1001, 0x8165, 1700000000, 1), (0xc002, 0x8235, 1700000001, 2)])), 'sres_2')
    add(asnd(MN, 255, 2, status(state=0x6D)), 'sres_mn')
    # NMT requests (ASnd and an invalid service)
    add(asnd(1, MN, 3, struct.pack('<BB', 0x21, 3) + b'\x01\x02'), 'nmtreq')
    add(asnd(1, MN, 3, struct.pack('<BB', 0x77, 3) + b'\x00'), 'nmtreq_unknown')
    # NMT commands
    add(asnd(MN, 255, 4, struct.pack('<BB', 0x21, 0) + b'\x00' * 4), 'nmt_start')
    add(asnd(MN, 1, 4, struct.pack('<BB', 0x62, 0) + b'new-hostname'.ljust(32, b'\0')), 'nmt_hostname')
    add(asnd(MN, 255, 4, struct.pack('<BB', 0x63, 0) + b'\x05'), 'nmt_flusharp')
    add(asnd(MN, 255, 4, struct.pack('<BB', 0xB0, 0) + bytes(range(6))), 'nmt_time')
    add(asnd(MN, 255, 4, struct.pack('<B', 0x2D) + bytes((0x1f,)) + mac(7) + struct.pack('<QIII', 0x0f, 7, 8, 2500000)), 'nmt_dna')
    add(asnd(MN, 1, 4, struct.pack('<BBH', 0x28, 0, 0x8165)), 'nmt_reset_err')
    add(asnd(MN, 1, 4, struct.pack('<BBH', 0x28, 0, 0)), 'nmt_reset_noerr')
    add(asnd(MN, 1, 4, struct.pack('<BB', 0x80, 0) + b'\xff' * 8), 'nmt_publish')
    add(asnd(MN, 1, 4, struct.pack('<BB', 0x07, 0) + b'\x00'), 'nmt_unknown')
    # SyncResponse, manufacturer specific and reserved services
    add(asnd(3, MN, 6, sync_resp()), 'syncresp')
    add(asnd(1, MN, 0xA0, b'\x01\x02\x03\x04'), 'asnd_manuf')
    add(asnd(1, MN, 0x07, b'\x05\x06'), 'asnd_reserved')
    add(asnd(1, MN, 0xFF, b'\x07\x08'), 'asnd_ff')
    # AInv with every service it dissects
    add(ainv(1, 1, ident(401, 0xDEADBEEF, 0x8BADF00D, hostname=b'cn1')), 'ainv_ident')
    add(ainv(2, 2, status()), 'ainv_status')
    add(ainv(3, 3, struct.pack('<BBB', 0x22, 3, 0)), 'ainv_nmtreq')
    add(ainv(3, 4, struct.pack('<BBB', 0x22, 0, 0)), 'ainv_nmtcmd')
    add(ainv(3, 255, struct.pack('<BB', 3, 0x20)), 'ainv_unspec')
    add(ainv(1, 5, struct.pack('<BBH', (1 << 2) | 1, (1 << 2) | 1, 0)), 'ainv_sdo')
    add(ainv(1, 6, b'\x00'), 'ainv_other')
    add(ainv(1, 0x80, b''), 'ainv_unknown_svid')
    # AMNI, an unknown message type and a frame too short for EPL
    add(eth(MN, MC_AMNI, epl(AMNI, 255, MN, b'\x00' * 6)), 'amni')
    add(eth(MN, MC_AMNI, epl(0x02, 255, MN, b'\x00' * 4)), 'unknown_mtyp')
    add(eth(MN, MC_AMNI, b'\x01\xff'), 'too_short')

    # ---- SDO sequence layer ----
    add(sdo(MN, 1, rcon=0, scon=0, rseq=0, sseq=0), 'seq_noconn')
    add(sdo(MN, 1, rcon=1, scon=1, rseq=0, sseq=0), 'seq_init')
    add(sdo(1, MN, rcon=1, scon=2, rseq=0, sseq=0), 'seq_init_resp')
    add(sdo(MN, 1, rcon=2, scon=1, rseq=0, sseq=0), 'seq_valid_init')
    add(sdo(MN, 1, rcon=2, scon=2, rseq=1, sseq=1), 'seq_valid_empty')
    add(sdo(MN, 1, rcon=2, scon=3, rseq=1, sseq=2), 'seq_ackreq')
    add(sdo(1, MN, rcon=3, scon=2, rseq=2, sseq=1), 'seq_retrans')
    add(sdo(1, MN, rcon=3, scon=3, rseq=2, sseq=2), 'seq_errerr')
    # a duplicate of seq_valid_empty (same sequence numbers within 100 frames)
    add(sdo(MN, 1, rcon=2, scon=2, rseq=1, sseq=1), 'seq_dup')
    # the last receive sequence number: the transfer's table is reset
    add(sdo(MN, 1, rcon=2, scon=2, rseq=0x3f, sseq=3), 'seq_3f')
    # same numbers as before the reset: not a duplicate
    add(sdo(MN, 1, rcon=2, scon=2, rseq=1, sseq=1), 'seq_after_reset')
    # SDO with a command layer of command ID 0 (nothing to show)
    add(sdo(MN, 1, cmd(0, b''), rseq=4, sseq=4), 'cmd_empty')

    # ---- SDO commands to CN 1 (requests MN->CN 1, responses CN 1->MN) ----
    # Write by index (expedited) to every kind of index
    wr = [
        ('w_1006', 0x1006, 0, struct.pack('<I', 5000)),      # no subindex
        ('w_1400', 0x1401, 1, b'\x01'),                       # PDO_RxCommParam_01h_REC
        ('w_1010', 0x1010, 5, struct.pack('<I', 0x65766173)),  # store param, manufacturer
        ('w_1011', 0x1011, 4, struct.pack('<I', 0x64616f6c)),  # restore param, manufacturer
        ('w_1003', 0x1003, 0, b'\x00'),                       # NumberOfEntries
        ('w_1f81', 0x1F81, 3, struct.pack('<I', 7)),          # named subindex list
        ('w_1018', 0x1018, 1, struct.pack('<I', 0xDEADBEEF)),  # Identity object
        ('w_2000', 0x2000, 7, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09'),  # user defined, > 8 octets
        ('w_1f8b', 0x1F8B, 2, b'\x10\x00'),                  # sub_val index
    ]
    for name, idx, sub, data in wr:
        add(sdo(MN, 1, cmd(1, wbi(idx, sub, data), segsize=4 + len(data))), name)
    add(sdo(1, MN, cmd(1, b'', response=True)), 'w_resp')
    # PDO mappings for CN 1: RPDO 0x1600/1-2 (PReq), TPDO 0x1A00/1 (PRes)
    add(sdo(MN, 1, cmd(1, wbi(0x1600, 1, mapping(0x2000, 1, 0, 16)), segsize=12)), 'map_rpdo1')
    add(sdo(MN, 1, cmd(1, wbi(0x1600, 2, mapping(0x2001, 0, 16, 8)), segsize=12)), 'map_rpdo2')
    add(sdo(MN, 1, cmd(1, wbi(0x1A00, 1, mapping(0x2002, 3, 0, 32)), segsize=12)), 'map_tpdo1')
    # an expedited write whose segment size is smaller than the data
    add(sdo(MN, 1, cmd(1, wbi(0x2003, 0, b'\x01\x02\x03\x04'), segsize=6)), 'w_short_segsize')
    # PReq and PRes split by the mappings; a PReq too short for the second mapping
    add(preq(1, b'\x34\x12\x56\x78\x9a'), 'preq_map')
    add(pres(1, b'\x00\x78\x56\x34\x12\xee'), 'pres_map')
    add(preq(1, b'\x34\x12'), 'preq_map_short')
    # the RPDO 0x1600/1 mapping is replaced (the old one ends here)
    add(sdo(MN, 1, cmd(1, wbi(0x1600, 1, mapping(0x2004, 0, 0, 16)), segsize=12)), 'map_rpdo1_new')
    add(preq(1, b'\x7f\x00\x56\xab'), 'preq_map_new')
    # Read by index request and response (the response is typed by the
    # cached request)
    add(sdo(MN, 1, cmd(2, struct.pack('<HBB', 0x1006, 0, 0)), sseq=10), 'r_req')
    add(sdo(1, MN, cmd(2, struct.pack('<I', 5000), response=True), sseq=10), 'r_resp')
    add(sdo(MN, 1, cmd(2, struct.pack('<HBB', 0x2000, 9, 0)), sseq=11), 'r_req2')
    add(sdo(1, MN, cmd(2, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a', response=True, segsize=8), sseq=11), 'r_resp2')
    # Write Multiple Parameter by Index request: mappings, every kind of
    # index, more than 8 entries, padding, the last entry with offset 0
    entries = [
        (0x1600, 3, mapping(0x2005, 0, 24, 8)),
        (0x1A00, 2, mapping(0x2006, 0, 32, 16)),
        (0x1006, 0, struct.pack('<I', 2500)),
        (0x1010, 6, struct.pack('<I', 1)),
        (0x1011, 7, struct.pack('<I', 1)),
        (0x1003, 0, b'\x02'),
        (0x1F81, 4, struct.pack('<I', 3)),
        (0x1401, 2, b'\x05\x06\x07'),
        (0x2000, 2, b'\xaa\xbb'),
        (0x1602, 1, mapping(0x2007, 0, 32, 8)),
        (0x1018, 2, struct.pack('<I', 0x1234)),
    ]
    body = multi_entries(entries)
    add(sdo(MN, 1, cmd(0x31, body)), 'wm_req')
    # Write Multiple response: entries with and without abort, more than 8
    resp = b''
    for k, (idx, sub) in enumerate([(0x1600, 3), (0x1006, 0), (0x1A00, 2), (0x2000, 2), (0x1401, 2),
                                    (0x1010, 6), (0x1003, 0), (0x1F81, 4), (0x1602, 1)]):
        if k in (2, 5):
            resp += struct.pack('<HBBI', idx, sub, 0x80, 0x06090011)
        else:
            resp += struct.pack('<HBBI', idx, sub, 0, 0)
    add(sdo(1, MN, cmd(0x31, resp, response=True)), 'wm_resp')
    # Read Multiple Parameter by Index request (4 octet entries, more than 8)
    rq = b''.join(struct.pack('<HBB', idx, sub, 0) for idx, sub in
                  [(0x1006, 0), (0x1600, 1), (0x1401, 1), (0x2000, 1), (0x1018, 1),
                   (0x1A00, 1), (0x1003, 0), (0x1F81, 1), (0x1010, 4)])
    add(sdo(MN, 1, cmd(0x32, rq)), 'rm_req')
    # Read Multiple response: data, an abort, a mapping (with a reserved
    # octet after the subindex), store/restore params, more than 8 entries
    rentries = [
        (0x1006, 0, struct.pack('<I', 2500)),
        (0x1600, 1, struct.pack('<HBBHBB', 0x2004, 0x05, 0xaa, 0, 8, 0)),
        (0x1401, 1, b'\x01'),
        (0x2000, 1, struct.pack('<I', 0x06020000), 0x80),
        (0x1018, 1, struct.pack('<I', 0xDEADBEEF)),
        (0x1010, 4, struct.pack('<I', 1)),
        (0x1011, 5, struct.pack('<I', 1)),
        (0x1A00, 1, mapping(0x2002, 3, 8, 32)),
        (0x1003, 0, b'\x01'),
        (0x1F81, 1, struct.pack('<I', 3)),
    ]
    add(sdo(1, MN, cmd(0x32, multi_entries(rentries), response=True)), 'rm_resp')
    # Abort of a write and of a Write Multiple response with two codes
    add(sdo(MN, 1, cmd(1, struct.pack('<I', 0x05040000), abort=True)), 'abort')
    add(sdo(1, MN, cmd(0x31, struct.pack('<HBBI', 0x2000, 1, 0x80, 0x06020000) +
                       struct.pack('<HBBI', 0x2000, 2, 0x80, 0x06090011), response=True, abort=True)), 'abort_wm')
    # Unknown command (Write by Name)
    add(sdo(MN, 1, cmd(5, b'name\0')), 'cmd_unknown')
    # Write Multiple with Initiate segmentation (shows the data size)
    add(sdo(MN, 1, cmd(0x31, struct.pack('<I', 100) + multi_entries([(0x1006, 0, struct.pack('<I', 1))], base=20),
                       seg=1)), 'wm_initiate')

    # ---- a write segment and a read segment before any Initiate ----
    add(sdo(MN, 6, cmd(1, b'early write segment', seg=2), rseq=5, sseq=5), 'early_wseg')
    add(sdo(6, MN, cmd(2, b'early read segment', response=True, seg=2), rseq=5, sseq=5), 'early_rseg')

    # ---- segmented download (write) to CN 2 ----
    part1 = struct.pack('<HBB', 0x2010, 0, 0) + b'A' * 20
    add(sdo(MN, 2, cmd(1, struct.pack('<I', 64) + part1, seg=1, segsize=len(part1) + 4), rseq=2, sseq=2), 'wseg_init')
    add(sdo(MN, 2, cmd(1, b'B' * 24, seg=2), rseq=2, sseq=3), 'wseg_mid')
    add(sdo(MN, 2, cmd(1, b'C' * 16, seg=3), rseq=2, sseq=4), 'wseg_end')
    add(sdo(2, MN, cmd(1, b'', response=True), rseq=4, sseq=2), 'wseg_resp')
    # a second download whose segments use send sequence numbers 63 and 1
    add(sdo(MN, 2, cmd(1, struct.pack('<I', 40) + struct.pack('<HBB', 0x2011, 0, 0) + b'D' * 12,
                       seg=1, segsize=20), rseq=3, sseq=62, scon=2), 'wseg2_init')
    add(sdo(MN, 2, cmd(1, b'E' * 12, seg=2), rseq=3, sseq=63), 'wseg2_mid')
    add(sdo(MN, 2, cmd(1, b'F' * 8, seg=3), rseq=3, sseq=1), 'wseg2_end')
    # ---- segmented upload (read) from CN 3 ----
    add(sdo(MN, 3, cmd(2, struct.pack('<HBB', 0x2020, 0, 0)), rseq=1, sseq=20), 'rseg_req')
    add(sdo(3, MN, cmd(2, struct.pack('<I', 60) + b'a' * 20, response=True, seg=1, segsize=24), rseq=50, sseq=50), 'rseg_init')
    add(sdo(3, MN, cmd(2, b'b' * 20, response=True, seg=2), rseq=51, sseq=51), 'rseg_mid')
    add(sdo(3, MN, cmd(2, b'c' * 20, response=True, seg=3), rseq=52, sseq=52), 'rseg_end')
    # a segment response with segment size 0 (not reassembled)
    add(sdo(3, MN, cmd(2, b'', response=True, seg=2, segsize=0), rseq=53, sseq=53), 'rseg_zero')

    # ---- SDO and typed values for CN 2 (typed with the EDS profile) ----
    typed = [
        (0x2100, 0, b'\x01'),                          # Boolean
        (0x2101, 0, b'\xfe'),                          # Integer8
        (0x2102, 0, struct.pack('<h', -2)),            # Integer16
        (0x2103, 0, struct.pack('<i', -3)),            # Integer32
        (0x2104, 0, b'\x05'),                          # Unsigned8
        (0x2105, 0, struct.pack('<H', 6)),             # Unsigned16
        (0x2106, 0, struct.pack('<I', 7)),             # Unsigned32
        (0x2107, 0, struct.pack('<f', 2.5)),           # Real32
        (0x2108, 0, b'hello'),                         # Visible_String
        (0x2109, 0, b'\x0a\x0b\x0c'),                  # Octet_String
        (0x210A, 0, 'hi'.encode('utf-16-le')),         # Unicode_String
        (0x210B, 0, b'\x01\x02\x03'),                  # Integer24
        (0x210C, 0, struct.pack('<d', 1.5)),           # Real64
        (0x210D, 0, b'\x01\x02\x03\x04\x05'),          # Integer40
        (0x210E, 0, b'\x01\x02\x03\x04\x05\x06'),      # Integer48
        (0x210F, 0, b'\x01\x02\x03\x04\x05\x06\x07'),  # Integer56
        (0x2110, 0, struct.pack('<q', -9)),            # Integer64
        (0x2111, 0, b'\x01\x02\x03'),                  # Unsigned24
        (0x2112, 0, b'\x01\x02\x03\x04\x05'),          # Unsigned40
        (0x2113, 0, b'\x01\x02\x03\x04\x05\x06'),      # Unsigned48
        (0x2114, 0, b'\x01\x02\x03\x04\x05\x06\x07'),  # Unsigned56
        (0x2115, 0, struct.pack('<Q', 15)),            # Unsigned64
        (0x2116, 0, mac(9)),                           # MAC_ADDRESS
        (0x2117, 0, bytes((192, 168, 100, 9))),        # IP_ADDRESS
        (0x2118, 0, struct.pack('>II', 1700000000, 5)),  # NETTIME
        (0x2119, 0, b'\x01\x02\x03\x04'),              # Time_of_Day (untyped)
        (0x2120, 1, struct.pack('<I', 0x11)),          # array subindex 1
        (0x2120, 2, struct.pack('<I', 0x22)),          # array subindex 2 (merged range)
        (0x2120, 5, b'\x05'),                          # array subindex 5
        (0x2121, 0, struct.pack('<I', 0x21)),          # record (ObjectType 9h)
        (0x2106, 0, struct.pack('<H', 6)),             # Unsigned32 written with 2 octets
    ]
    for k, (idx, sub, data) in enumerate(typed):
        add(sdo(MN, 2, cmd(1, wbi(idx, sub, data), segsize=4 + len(data))), 'typed_%04x_%d_%d' % (idx, sub, k))
    add(sdo(MN, 2, cmd(0x31, multi_entries([(0x2104, 0, b'\x05'), (0x2108, 0, b'multi'),
                                            (0x2120, 1, struct.pack('<I', 1))]))), 'typed_wm')
    add(sdo(MN, 2, cmd(0x32, struct.pack('<HBB', 0x2105, 0, 0) + struct.pack('<HBB', 0x2120, 2, 0))), 'typed_rm_req')
    add(sdo(2, MN, cmd(0x32, multi_entries([(0x2105, 0, struct.pack('<H', 6)),
                                            (0x2120, 2, struct.pack('<I', 2))]), response=True)), 'typed_rm_resp')
    add(sdo(MN, 2, cmd(2, struct.pack('<HBB', 0x210C, 0, 0)), sseq=40), 'typed_r_req')
    add(sdo(2, MN, cmd(2, struct.pack('<d', -0.25), response=True), sseq=40), 'typed_r_resp')
    add(sdo(MN, 2, cmd(2, struct.pack('<HBB', 0x2120, 1, 0)), sseq=41), 'typed_r_req_sub')
    add(sdo(2, MN, cmd(2, struct.pack('<I', 0x11), response=True), sseq=41), 'typed_r_resp_sub')
    # PDO mapping of CN 2 to EDS objects, and a PReq using it
    add(sdo(MN, 2, cmd(1, wbi(0x1600, 1, mapping(0x2105, 0, 0, 16)), segsize=12)), 'map_cn2_1')
    add(sdo(MN, 2, cmd(1, wbi(0x1600, 2, mapping(0x2120, 1, 16, 32)), segsize=12)), 'map_cn2_2')
    add(sdo(MN, 2, cmd(1, wbi(0x1600, 3, mapping(0x2199, 0, 48, 8)), segsize=12)), 'map_cn2_3')
    add(preq(2, struct.pack('<HIB', 6, 0x11, 0x99)), 'preq_cn2')
    # ---- CN 4: mappings from the XDD (device type table) ----
    add(preq(4, struct.pack('<HB', 300, 7)), 'preq_cn4')
    add(pres(4, struct.pack('<I', 0x01020304)), 'pres_cn4')
    add(sdo(MN, 4, cmd(1, wbi(0x2100, 1, struct.pack('<H', 300)), segsize=6)), 'xdd_w_speed')
    add(sdo(MN, 4, cmd(1, wbi(0x2100, 2, b'\x02'), segsize=5)), 'xdd_w_sub2')
    add(sdo(MN, 4, cmd(1, wbi(0x2101, 0, b'\x07'), segsize=5)), 'xdd_w_noname')
    add(sdo(MN, 4, cmd(1, wbi(0x2102, 0, b'label'), segsize=9)), 'xdd_w_label')
    add(sdo(MN, 4, cmd(1, wbi(0x1000, 0, struct.pack('<I', 401)), segsize=8)), 'xdd_w_1000')
    # ---- CN 3: profile by MAC address (EDS) ----
    add(sdo(MN, 3, cmd(1, wbi(0x2106, 0, struct.pack('<I', 3)), segsize=8)), 'mac_w')
    add(sdo(3, MN, cmd(1, b'', response=True)), 'mac_w_resp')

    # ---- POWERLINK over UDP ----
    add(udp_epl(MN, 1, epl(SOA, 255, MN, struct.pack('<BBBBBBB', 0xFD, 0, 0, 1, 1, 0x20, 0))), 'udp_soa')
    add(udp_epl(MN, 1, epl(ASND, 1, MN, b'\x05' + struct.pack('<BBH', (7 << 2) | 2, (7 << 2) | 2, 0) +
                           cmd(2, struct.pack('<HBB', 0x1006, 0, 0)))), 'udp_sdo')
    add(udp_epl(1, MN, epl(ASND, MN, 1, b'\x01' + ident(401, 1, 2, hostname=b'udp'))), 'udp_ires')

    # ---- duplicates far apart: the same numbers more than 100 frames later ----
    add(sdo(MN, 1, rcon=2, scon=2, rseq=1, sseq=1), 'seq_far')

    # ---- fix reproducer: more than 4096 object mappings (CN 9) ----
    for f in range(5):
        es = []
        for i in range(900):
            n = f * 900 + i
            es.append((0x1600, 1 + (n % 254), mapping(0x3000 + n, 0, (n * 8) % 0x10000, 8)))
        add(sdo(MN, 9, cmd(0x31, multi_entries(es))), 'many_%d' % f)
    add(preq(9, bytes(range(16))), 'preq_many')
    add(soc(0x00), 'soc_end')
    return FRAMES


def malformed_frames():
    F = []
    F.append(eth(MN, MC_SOC, epl(SOC, 255, MN, b'\0\0')))                   # SoC cut short
    F.append(preq(1, b'\x01\x02', size=40))                                 # PDO size past the end
    F.append(pres(1, b'\x01', size=10))
    F.append(eth(MN, MC_SOA, epl(SOA, 255, MN, b'\xfd\x00\x00\x06\x01\x20\x00\x00')))  # SyncRequest cut short
    F.append(eth(1, MC_ASND, epl(ASND, 255, 1, b'\x01' + ident(401, 0, 0)[:40])))     # IdentResponse cut
    F.append(eth(1, MC_ASND, epl(ASND, 255, 1, b'\x02' + status()[:8])))              # StatusResponse cut
    F.append(eth(MN, MC_ASND, epl(ASND, 255, MN, b'\x04\x2d\x00\x01\x02')))           # DNA cut short
    F.append(eth(MN, MC_ASND, epl(ASND, 255, MN, b'\x04\x62\x00abc')))                # hostname cut short
    F.append(eth(3, mac(MN), epl(ASND, MN, 3, b'\x06\x00')))                          # SyncResponse cut
    F.append(eth(MN, mac(1), epl(ASND, 1, MN, b'\x05\x0a\x0a')))                      # SDO sequence cut
    # SDO segment size larger than the frame (error expert info)
    F.append(eth(MN, mac(1), epl(ASND, 1, MN, b'\x05' + struct.pack('<BBH', (9 << 2) | 2, (9 << 2) | 2, 0) +
                                 cmd(1, wbi(0x1006, 0, b'\x01\x02'), segsize=200))))
    # Write Multiple with an entry offset past the end and one shorter than its header
    F.append(eth(MN, mac(1), epl(ASND, 1, MN, b'\x05' + struct.pack('<BBH', (10 << 2) | 2, (10 << 2) | 2, 0) +
                                 cmd(0x31, struct.pack('<IHBB', 400, 0x1006, 0, 0) + b'\x01\x02\x03\x04'))))
    F.append(eth(MN, mac(1), epl(ASND, 1, MN, b'\x05' + struct.pack('<BBH', (11 << 2) | 2, (11 << 2) | 2, 0) +
                                 cmd(0x31, struct.pack('<IHBB', 12, 0x1006, 0, 3) + b'\x01\x02\x03\x04'))))
    F.append(eth(1, mac(MN), epl(ASND, MN, 1, b'\x05' + struct.pack('<BBH', (12 << 2) | 2, (12 << 2) | 2, 0) +
                                 cmd(0x32, struct.pack('<IHBB', 400, 0x1006, 0, 0) + b'\x01\x02\x03\x04', response=True))))
    F.append(eth(1, mac(MN), epl(ASND, MN, 1, b'\x05' + struct.pack('<BBH', (13 << 2) | 2, (13 << 2) | 2, 0) +
                                 cmd(0x32, struct.pack('<IHBB', 10, 0x1006, 0, 3) + b'\x01\x02\x03\x04', response=True))))
    # Write Multiple response entry cut short, Read Multiple request cut short
    F.append(eth(1, mac(MN), epl(ASND, MN, 1, b'\x05' + struct.pack('<BBH', (14 << 2) | 2, (14 << 2) | 2, 0) +
                                 cmd(0x31, b'\x06\x10\x00\x80\x01', response=True))))
    F.append(eth(MN, mac(1), epl(ASND, 1, MN, b'\x05' + struct.pack('<BBH', (15 << 2) | 2, (15 << 2) | 2, 0) +
                                 cmd(0x32, b'\x06\x10'))))
    # Write by index with a mapping cut short, abort code cut short
    F.append(eth(MN, mac(1), epl(ASND, 1, MN, b'\x05' + struct.pack('<BBH', (16 << 2) | 2, (16 << 2) | 2, 0) +
                                 cmd(1, wbi(0x1600, 1, b'\x00\x20'), segsize=12))))
    F.append(eth(MN, mac(1), epl(ASND, 1, MN, b'\x05' + struct.pack('<BBH', (17 << 2) | 2, (17 << 2) | 2, 0) +
                                 cmd(1, b'\x01', abort=True))))
    F.append(eth(MN, mac(1), epl(AINV, 1, MN, b'\xfd\x00')))                           # AInv cut short
    return F


EDS = """# EDS for the EPL coverage capture (synthetic). No [FileInfo] Description.
[FileInfo]
FileName=epl_coverage.eds
CreatedBy=mkepl.py

[DeviceInfo]
VendorName=Example

[Comments]
Lines=0

[1000]
ParameterName=NMT_DeviceType_U32
ObjectType=0x7
DataType=0x0007

[2100]
ParameterName=Bool
ObjectType=0x7
DataType=0x0001
[2101]
ParameterName=Int8
ObjectType=0x7
DataType=0x0002
[2102]
ParameterName=Int16
ObjectType=0x7
DataType=0x0003
[2103]
ParameterName=Int32
ObjectType=0x7
DataType=0x0004
[2104]
ParameterName=Uint8
ObjectType=0x7
DataType=0x0005
[2105]
ParameterName=Uint16 # with a comment
ObjectType=0x7
DataType=0x0006
[2106]
ParameterName=Uint32
ObjectType=7
DataType=7
[2107]
ParameterName=Real32
ObjectType=0x7
DataType=0x0008
[2108]
ParameterName=VisibleString
ObjectType=0x7
DataType=0x0009
[2109]
ParameterName=OctetString
ObjectType=0x7
DataType=0x000A
[210A]
ParameterName=UnicodeString
ObjectType=0x7
DataType=0x000B
[210B]
ParameterName=Int24
ObjectType=0x7
DataType=0x0010
[210C]
ParameterName=Real64
ObjectType=0x7
DataType=0x0011
[210D]
ParameterName=Int40
ObjectType=0x7
DataType=0x0012
[210E]
ParameterName=Int48
ObjectType=0x7
DataType=0x0013
[210F]
ParameterName=Int56
ObjectType=0x7
DataType=0x0014
[2110]
ParameterName=Int64
ObjectType=0x7
DataType=0x0015
[2111]
ParameterName=Uint24
ObjectType=0x7
DataType=0x0016
[2112]
ParameterName=Uint40
ObjectType=0x7
DataType=0x0018
[2113]
ParameterName=Uint48
ObjectType=0x7
DataType=0x0019
[2114]
ParameterName=Uint56
ObjectType=0x7
DataType=0x001A
[2115]
ParameterName=Uint64
ObjectType=0x7
DataType=0x001B
[2116]
ParameterName=MacAddress
ObjectType=0x7
DataType=0x0401
[2117]
ParameterName=IpAddress
ObjectType=0x7
DataType=0x0402
[2118]
ParameterName=NetTime
ObjectType=0x7
DataType=0x0403
[2119]
ParameterName=TimeOfDay
ObjectType=0x7
DataType=0x000C
[2120sub1]
ParameterName=Element
ObjectType=0x7
DataType=0x0007
[2120]
ParameterName=Array
ObjectType=0x8
[2120sub0]
ParameterName=NumberOfEntries
ObjectType=0x7
DataType=0x0005
[2120sub2]
ParameterName=Element
ObjectType=0x7
DataType=0x0007
[2120sub5]
ParameterName=Fifth
ObjectType=0x7
DataType=0x0005
[2120sub1FF]
ParameterName=TooLarge
ObjectType=0x7
[2120subzz]
ParameterName=NotHex
ObjectType=0x7
[2121]
ParameterName=Record
ObjectType=9h
DataType=0007h
[2122]
ParameterName=NoObjectType
DataType=0x0007
[2123x]
ParameterName=NotAnIndex
ObjectType=0x7
"""

XDD = """<?xml version="1.0" encoding="UTF-8"?>
<!-- XDD for the EPL coverage capture (synthetic). The ProfileName XPath
     matches nothing: there is no Powerlink_Communication_Profile. -->
<ISO15745ProfileContainer xmlns="http://www.ethernet-powerlink.org" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <ISO15745Profile>
  <ProfileHeader>
   <ProfileIdentification>Powerlink_Device_Profile</ProfileIdentification>
   <ProfileName>Example device</ProfileName>
  </ProfileHeader>
  <ProfileBody xsi:type="ProfileBody_CommunicationNetwork_Powerlink">
   <ApplicationLayers>
    <DataTypeList>
     <defType dataType="0005"><Unsigned8/></defType>
     <defType dataType="0006"><Unsigned16/></defType>
     <defType dataType="0007"><Unsigned32/></defType>
     <defType dataType="0009"><Visible_String/></defType>
     <defType dataType="001B"><Unsigned64/></defType>
     <defType dataType="00FF"><NoSuchType/></defType>
     <defType dataType="zz"><Unsigned8/></defType>
     <defType dataType="" name="empty"><Unsigned8/></defType>
    </DataTypeList>
    <ObjectList>
     <Object index="1000" name="NMT_DeviceType_U32" objectType="7" dataType="0007" defaultValue="0x191"/>
     <Object index="1600" name="PDO_RxMappParam_00h_AU64" objectType="8" dataType="001B">
      <SubObject subIndex="00" name="NumberOfEntries" objectType="7" dataType="0005" defaultValue="2"/>
      <SubObject subIndex="01" name="ObjectMapping" objectType="7" dataType="001B" defaultValue="0x0010000000012100"/>
      <SubObject subIndex="02" name="ObjectMapping" objectType="7" dataType="001B" defaultValue="0x0" actualValue="0x0008001000002101"/>
      <SubObject subIndex="03" name="ObjectMapping" objectType="7" dataType="001B"/>
     </Object>
     <Object index="1A00" name="PDO_TxMappParam_00h_AU64" objectType="8" dataType="001B">
      <SubObject subIndex="00" name="NumberOfEntries" objectType="7" dataType="0005" defaultValue="1"/>
      <SubObject subIndex="01" name="ObjectMapping" objectType="7" dataType="001B" actualValue="0x0020000000002106"/>
     </Object>
     <Object index="2100" name="Record" objectType="9">
      <SubObject subIndex="00" name="NumberOfEntries" objectType="7" dataType="0005"/>
      <!-- a comment between subobjects -->
      <SubObject subIndex="01" name="Speed" objectType="7" dataType="0006"/>
      <SubObject subIndex="02" objectType="7"/>
     </Object>
     <Object index="2101" name="" objectType="7" dataType="0005"/>
     <Object index="2102" name="Label" objectType="7" dataType="0009"/>
     <Object index="2103" name="UnknownType" objectType="7" dataType="1234"/>
     <Object index="2106" name="Value32" objectType="7" dataType="0007"/>
     <Object index="zz" name="BadIndex" objectType="7"/>
     <Object name="NoIndex" objectType="7"/>
     <Object index="2104" name="BadSub" objectType="8">
      <SubObject subIndex="zz" name="Bad" objectType="7"/>
      <SubObject subIndex="01" name="Good" objectType="7" dataType="0005"/>
     </Object>
    </ObjectList>
   </ApplicationLayers>
  </ProfileBody>
 </ISO15745Profile>
</ISO15745ProfileContainer>
"""

# Profiles for runcov.sh only
EDS_DESC = """[FileInfo]
Description=Coverage EDS # a comment

[2106]
ParameterName=Value32
ObjectType=0x7
DataType=0x0007
[2108]
ParameterName=Text
ObjectType=0x7
DataType=0x0009
"""

XDD_NAMED = XDD.replace('Powerlink_Device_Profile', 'Powerlink_Communication_Profile')
XDD_TWO_NAMES = XDD_NAMED.replace('<ProfileName>Example device</ProfileName>',
                                  '<ProfileName>One</ProfileName><ProfileName>Two</ProfileName>')
XDD_EMPTY_NAME = XDD_NAMED.replace('<ProfileName>Example device</ProfileName>', '<ProfileName/>')


def main():
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'

    def pcap(name, frames):
        with open(os.path.join(out, name), 'wb') as f:
            f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
            for i, fr in enumerate(frames):
                f.write(struct.pack('<IIII', 1700000000 + i // 100, (i % 100) * 10000, len(fr), len(fr)))
                f.write(fr)

    pcap('epl-coverage.pcap', main_frames())
    pcap('epl-coverage-malformed.pcap', malformed_frames())
    files = {
        'epl_coverage.eds': EDS,
        'epl_coverage.xdd': XDD,
        'epl-runcov-desc.eds': EDS_DESC,
        'epl-runcov-garbage.eds': 'this is not a key file\n[unterminated\n',
        'epl-runcov-named.xdd': XDD_NAMED,
        'epl-runcov-twonames.xdd': XDD_TWO_NAMES,
        'epl-runcov-emptyname.xdd': XDD_EMPTY_NAME,
        'epl-runcov-broken.xdd': '<?xml version="1.0"?><ISO15745ProfileContainer><unclosed>',
        'epl-runcov-noext.txt': 'not a profile\n',
    }
    for name, text in files.items():
        with open(os.path.join(out, name), 'w') as f:
            f.write(text)
    if '-v' in sys.argv:
        for k, v in NAMES.items():
            print(v, k)


if __name__ == '__main__':
    main()
