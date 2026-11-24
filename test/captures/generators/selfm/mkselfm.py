#!/usr/bin/env python3
# Generates test/captures/selfm_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic coverage captures for the SEL Protocol (selfm) dissector.

Usage: mkselfm.py <outdir>

Writes selfm-coverage.pcapng (main capture: Exported PDU frames that name
the "selfm" dissector, plus a few TCP frames that need Decode As
tcp.port==2023), and selfm-coverage-malformed.pcapng.  Everything is built
with struct; nothing comes from a real network.
"""
import struct
import sys
import os

# ---------------------------------------------------------------- helpers

def crc16(d):
    c = 0xFFFF
    for b in d:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return c


def iac(b):
    """Telnet doubling of 0xFF, as a real SEL Telnet session sends it."""
    return b.replace(b'\xff', b'\xff\xff')


def chk(b):
    return bytes([(~sum(b)) & 0xFF])


def sel(cmd, rest, pad=False):
    """Non Fast Message PDU: cmd(2) len(1) rest... checksum.  len is the
    total PDU length."""
    body = rest + (b'\0' if pad else b'')
    total = 2 + 1 + len(body) + 1
    pdu = struct.pack('>HB', cmd, total) + body
    return pdu + chk(pdu)


def fm(func, seq, body, status=0, resp=0, crc=None, total=None):
    """Fast Message (0xA546) with a valid CRC16 unless crc is given."""
    t = 12 + len(body) + 2 if total is None else total
    pdu = struct.pack('>HB', 0xA546, t) + bytes([0x11, 0x22, 0x33, 0x44, 0x55, status, func, seq, resp]) + body
    return pdu + struct.pack('>H', crc16(pdu) if crc is None else crc)


def exp_pdu(payload, ports=None, name='selfm'):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    h = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
    if ports:
        (sip, dip, sp, dp) = ports
        h += struct.pack('>HH4s', 20, 4, bytes(sip)) + struct.pack('>HH4s', 21, 4, bytes(dip))
        h += struct.pack('>HHI', 24, 4, 2)    # TCP
        h += struct.pack('>HHI', 25, 4, sp) + struct.pack('>HHI', 26, 4, dp)
    h += struct.pack('>HH', 0, 0)
    return h + payload


def ip_tcp(src, dst, sp, dp, seq, ack, flags, payload=b''):
    opt = b'\x02\x04\x05\xb4' if flags & 2 else b''
    if flags == 2:
        ack = 0
    tcp = struct.pack('>HHIIBBHHH', sp, dp, seq, ack, (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt + payload
    ph = bytes(src) + bytes(dst) + struct.pack('>BBH', 0, 6, len(tcp))
    s = ph + tcp
    if len(s) % 2:
        s += b'\0'
    t = sum(struct.unpack('>%dH' % (len(s) // 2), s))
    while t >> 16:
        t = (t & 0xFFFF) + (t >> 16)
    tcp = tcp[:16] + struct.pack('>H', (~t) & 0xFFFF) + tcp[18:]
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, bytes(src), bytes(dst))
    s = struct.unpack('>10H', ip)
    t = sum(s)
    while t >> 16:
        t = (t & 0xFFFF) + (t >> 16)
    ip = ip[:10] + struct.pack('>H', (~t) & 0xFFFF) + ip[12:]
    eth = bytes([2, 0, 0, 0, 0, 2]) + bytes([2, 0, 0, 0, 0, 1]) + b'\x08\x00'
    return eth + ip + tcp


class Cap:
    """pcapng writer with two interfaces: 0 = Exported PDU, 1 = Ethernet."""

    def __init__(self):
        self.pkts = []

    def exp(self, payload, ports=None):
        self.pkts.append((0, exp_pdu(payload, ports)))

    def eth(self, frame):
        self.pkts.append((1, frame))

    def write(self, fname):
        def blk(t, body):
            body += b'\0' * ((4 - len(body) % 4) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        out += blk(1, struct.pack('<HHI', 252, 0, 65535))
        out += blk(1, struct.pack('<HHI', 1, 0, 65535))
        for i, (ifc, d) in enumerate(self.pkts):
            ts = 1700000000 * 1000000 + i * 1000
            out += blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xFFFFFFFF, len(d), len(d)) + d)
        with open(fname, 'wb') as f:
            f.write(out)


# ------------------------------------------------------------ PDU builders

def aiinfo(name, typ, sftype, sfofs):
    return name.ljust(6).encode() + bytes([typ, sftype]) + struct.pack('>H', sfofs)


def calc_block(b0, ctype):
    return bytes([b0, ctype]) + struct.pack('>HHH', 10, 20, 30) + bytes([0, 1, 2, 3, 4, 5])


def fm_config(cmd, num_flags, sf_loc, num_sf, ais, samples, num_dig, ncalc, ofs_ai, ofs_ts, ofs_dig,
              sfs=(), pad=False):
    """ais: list of (name, type, sf_type, sf_offset); the cfg sf floats are
    appended after the calc blocks when sf_loc == 1 (their offsets are
    patched into the ai entries when sf_offset is None)."""
    head_len = 16
    sf_base = head_len + 10 * len(ais) + 14 * ncalc
    ai = b''
    for i, (n, t, st, so) in enumerate(ais):
        if so is None:
            so = sf_base + 4 * i
        ai += aiinfo(n, t, st, so)
    rest = bytes([num_flags, sf_loc, num_sf, len(ais), samples, num_dig, ncalc])
    rest += struct.pack('>HHH', ofs_ai, ofs_ts, ofs_dig) + ai
    rest += b''.join(calc_block(0x15 + k, k % 7) for k in range(ncalc))
    if sf_loc == 1:
        rest += b''.join(struct.pack('>f', f) for f in sfs)
    return sel(cmd, rest, pad)


def fm_data(cmd, flag, body, pad=False):
    rest = (bytes([flag]) if flag is not None else b'') + body
    return sel(cmd, rest, pad)


def ts8(mon, day, yr, hr, mi, sec, ms):
    return bytes([mon, day, yr, hr, mi, sec]) + struct.pack('>H', ms)


def tag(name, qty, typ):
    return name.ljust(10).encode() + struct.pack('>HH', qty, typ)


def datafmt(base, items, seq=0xC0, numitem=None):
    return fm(0xB1, seq, struct.pack('>IH', base, len(items) if numitem is None else numitem) +
              b''.join(tag(*i) for i in items))


def readresp(base, payload, seq=0xC0):
    return fm(0x90, seq, struct.pack('>IH', base, len(payload) // 2) + payload)


def devdesc(regions, num_regions=None, seq=0xC0, trailer=b'', fid=b'SEL-351-R1-V0-Z001001-D20100101', rid=b'FEEDER 1'):
    body = fid.ljust(50, b' ') + rid.ljust(40, b' ')
    body += struct.pack('>HH', len(regions) if num_regions is None else num_regions, 2)
    for (n, b, w, f) in regions:
        body += n.ljust(10).encode() + struct.pack('>IHH', b, w, f)
    return fm(0xB0, seq, body + trailer)


def unsresp(n, status, idx=None, doy=100, year=2026, tod=3600000, ofs=None):
    body = b'\0\0\0\0' + struct.pack('>HHI', doy, year, tod)
    for i in range(n):
        ix = i if idx is None else idx[i]
        o = (i * 1500) if ofs is None else ofs[i]
        body += bytes([ix]) + struct.pack('>I', o)[1:]
    body += b'\xff\xff\xff\xfe' + struct.pack('>I', status)
    return fm(0x18, 0xC0, body)


# ---------------------------------------------------------------- main cap

GEN = []      # (kind, payload, ports)
P0 = None
S1 = ((10, 0, 0, 1), (10, 0, 0, 2), 49152, 23)
S2 = ((10, 0, 0, 1), (10, 0, 0, 3), 49153, 23)
S3 = ((10, 0, 0, 1), (10, 0, 0, 4), 49154, 23)
S4 = ((10, 0, 0, 1), (10, 0, 0, 5), 49155, 23)
S5 = ((10, 0, 0, 1), (10, 0, 0, 6), 49156, 23)
S6 = ((10, 0, 0, 1), (10, 0, 0, 7), 49157, 23)
S7 = ((10, 0, 0, 1), (10, 0, 0, 8), 49158, 23)


def main_frames():
    F = []   # (payload, ports)

    def add(p, ports=None, telnet=True):
        # A session with ports is a Telnet session: double the 0xFF bytes
        F.append((iac(p) if ports and telnet else p, ports))

    # ---- no ports (no Telnet clean): requests and scans, relay definition
    add(b'\xa5\xc0')                                   # Relay Definition request
    add(b'\xa5\xd1')                                   # FM data request
    add(b'\xa5\xb9')                                   # Clear Status Bits (unknown to the switch)
    add(b'\xa5\xed')                                   # Fast Operate Reset
    add(b'\xa5\xcd')                                   # Fast Operate Reset Definition
    add(b'\xa5\x99')                                   # unknown message type
    add(sel(0xA599, b'\x01\x02'))                       # unknown message type with a payload
    add(sel(0xA5B9, b'\x00'))                           # Clear Status Bits with a payload (not decoded)
    # relay definition: 2 FM commands, 1 status bit flag, 2 protocols; without and with a pad byte
    rd = bytes([2, 2, 1]) + struct.pack('>HHHH', 0xA5C1, 0xA5D1, 0xA5C2, 0xA5D2) + \
        struct.pack('>H', 0x0001) + bytes([0xA5, 0xB9, 0, 0, 0, 0]) + struct.pack('>HH', 0x0000, 0x0100)
    add(sel(0xA5C0, rd))
    add(sel(0xA5C0, rd, pad=True))
    # relay definition with nothing but the header counts at zero
    add(sel(0xA5C0, bytes([0, 0, 0])))
    # fast operate configuration: 2 breakers, 3 remote bits, pulse supported / not
    add(sel(0xA5CE, bytes([2]) + struct.pack('>H', 3) + bytes([1, 0]) + bytes([0x31, 0x32, 0x33, 0x34]) +
            bytes([0x20, 0x00, 0x40, 0x21, 0x01, 0x41, 0x22, 0x02, 0x42])))
    add(sel(0xA5CE, bytes([1]) + struct.pack('>H', 2) + bytes([0, 0]) + bytes([0x31, 0x32]) +
            bytes([0x20, 0x00, 0x21, 0x01]), pad=True))
    # alternate fast operate configuration
    add(sel(0xA5CF, bytes([2, 1, 4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9])))
    # fast operate commands: remote bit and breaker bit (known and unknown codes)
    add(sel(0xA5E0, bytes([0x20, 0x20])))
    add(sel(0xA5E0, bytes([0xF0, 0x0F])))
    add(sel(0xA5E3, bytes([0x31, 0x31])))
    add(sel(0xA5E3, bytes([0x7F, 0x7F])))
    # alternate fast operate: open, close, set, clear, pulse (len 7 + checksum)
    for c in (0xA5E5, 0xA5E6, 0xA5E7, 0xA5E8, 0xA5E9):
        add(sel(c, struct.pack('>HH', 0x0100 + (c & 0xF), 0xFEFF - (c & 0xF))))

    # FM data without a configuration (no ports; a conversation without a config)
    add(sel(0xA5D1, bytes([0]) + b'\x00' * 10))
    add(sel(0xA5D2, bytes([0]) + b'\x00' * 6))
    add(sel(0xA5D3, bytes([0]) + b'\x00' * 3))

    # two PDUs in one frame, then a PDU followed by ASCII, then PDU + 2 byte scan
    a = sel(0xA5E0, bytes([0x20, 0xDF]))
    b = fm(0x10, 0xC0, struct.pack('>IH', 0x1000, 4))
    add(a + b)
    add(a + b'\r\n=>')
    add(b + a)                                          # Fast Message PDU followed by a fast operate PDU

    # ---- Fast Message function codes (no ports): session without region names
    add(fm(0x01, 0xC0, bytes([0x18, 1, 2, 3])))                       # enable unsolicited
    add(fm(0x81, 0x00, b''))                                          # ack, response code 0
    add(fm(0x81, 0x01, b''))
    add(fm(0x02, 0xC0, bytes([0x18, 1])))                             # disable unsolicited
    add(fm(0x82, 0x00, b''))
    add(fm(0x05, 0xC0, b''))                                          # ping
    add(fm(0x85, 0xC0, b''))                                          # ping ack
    add(fm(0x10, 0xC0, struct.pack('>IH', 0x1000, 4)))                # read request
    add(fm(0x12, 0xC0, struct.pack('>HHH', 0x1111, 0x2222, 0x3333)))  # generic unsolicited data
    add(fm(0x12, 0xC0, b''))
    add(fm(0x16, 0xC0, b'\0\0\0\1'))                                  # SOE state request
    # SOE state response: 2 blocks, 20 bits (2 regs) and 16 bits (1 reg)
    blk = lambda bits, regs: b'\0\0\0\2' + bytes([bits, 0]) + struct.pack('>HHI', 120, 2026, 7200000) + \
        b''.join(struct.pack('>H', 0x8001 + i) for i in range(regs))
    add(fm(0x96, 0xC0, struct.pack('>H', 2) + blk(20, 2) + blk(16, 1)))
    add(fm(0x96, 0xC0, struct.pack('>H', 0)))
    add(fm(0x98, 0x00, b''))                                  # unsolicited response ack
    add(fm(0x20, 0xC0, struct.pack('>HHH', 0x0010, 0x0020, 3) + struct.pack('>HHH', 1, 2, 3)))  # unsolicited write
    add(fm(0x20, 0xC0, struct.pack('>HHH', 0x0010, 0x0020, 0)))
    add(fm(0x21, 0xC0, b''))                               # write request (not decoded)
    add(fm(0x30, 0xC0, b''))                                          # device description request
    add(fm(0x31, 0xC0, struct.pack('>I', 0x1000)))                    # data format request
    add(fm(0x32, 0xC0, b''))                                  # unsolicited data format response
    add(fm(0x33, 0xC0, struct.pack('>I', 0x1000)))                    # bit label request
    add(fm(0x40, 0xC0, b''))                                          # management request
    add(fm(0x00, 0xC0, b''))                                          # configuration block request
    add(fm(0x7E, 0xC0, b''))                                    # unknown function code
    # configuration block response, 3 RX and 2 TX function codes
    cb = bytes([1, 2, 3, 8, 4]) + b'\0' * 6 + bytes([3, 0x10, 0, 0x30, 0, 0x01, 0]) + bytes([2, 0x90, 0, 0xB0, 0])
    add(fm(0x80, 0xC0, cb))
    cb = bytes([0, 0, 0, 0, 0]) + b'\0' * 6 + bytes([0]) + bytes([0])
    add(fm(0x80, 0xC0, cb))
    # bit label response: 8 labels
    labels = b''.join(n.encode() + b'\0' for n in ('BIT0', 'BIT1', 'A', 'BIT3', 'LONGNAME', 'B5', 'B6', 'B7'))
    add(fm(0xB3, 0xC0, labels))
    # unsolicited SER with no elements, one element, five elements, none asserted
    add(unsresp(0, 0))
    add(unsresp(1, 1, idx=[3]))
    add(unsresp(5, 0b10110, idx=[0, 1, 2, 254, 255], ofs=[0, 100, 200, 300, 400000]))

    # ---- session 1 (Telnet, ports): device description, data formats, reads
    regions = [('METER', 0x1000, 20, 0), ('DEMAND', 0x2000, 30, 0), ('TARGET', 0x3000, 8, 1),
               ('HISTORY', 0x4000, 50, 0), ('STATUS', 0x5000, 4, 0), ('CONFIG', 0x6000, 40, 2),
               ('OTHER', 0x7000, 10, 0)]
    add(fm(0x30, 0xC0, b''), S1)
    add(devdesc(regions, num_regions=9, seq=0xC0), S1)
    add(devdesc([('MORE1', 0x8000, 3, 0), ('MORE2', 0x9000, 5, 0)], num_regions=9, seq=0xC1), S1)
    # 4xx style: 8 zero bytes of reserved control region space
    add(devdesc(regions[:2], trailer=b'\0' * 8), S1)
    add(fm(0x31, 0xC0, struct.pack('>I', 0x1000)), S1)
    items = [('TEXT8', 8, 0x11), ('TEXT16', 4, 0x12), ('DW8BL', 2, 0x21), ('DW8', 1, 0x22),
             ('INT16', 3, 0x31), ('UINT16', 2, 0x32), ('INT32', 2, 0x33), ('UINT32', 2, 0x34),
             ('FLOAT', 2, 0x41), ('UNKNOWN', 1, 0x99), ('DW16BL', 1, 0x23), ('DW16', 1, 0x24)]
    add(datafmt(0x1000, items), S1)
    add(fm(0x10, 0xC0, struct.pack('>IH', 0x1000, 30)), S1)
    pl = b'ABCDEFGH' + b'ab' b'cd' b'ef' b'gh'                     # CHAR8 8, CHAR16 4 (8 bytes)
    pl += bytes([0xA5, 0x5A]) + bytes([0x0F])                       # DW8BL 2, DW8 1
    pl += struct.pack('>hhh', -1, 0, 32767)                         # INT16 x3
    pl += struct.pack('>HH', 1, 65535)                              # UINT16 x2
    pl += struct.pack('>ii', -100000, 100000)                       # INT32 x2
    pl += struct.pack('>II', 1, 4000000000)                         # UINT32 x2
    pl += struct.pack('>ff', 1.5, -2.25)                            # FLOAT x2
    pl += b'\0' * 5                                                 # spare bytes: UNKNOWN and DW16 items consume none
    add(readresp(0x1000, pl), S1)
    # data region B: 18 items in two Data Format Response frames (16 + 2)
    items = [('ITEM%02d' % i, 1, 0x32) for i in range(18)]
    add(fm(0x31, 0xC0, struct.pack('>I', 0x2000)), S1)
    add(datafmt(0x2000, items[:16], seq=0xC0, numitem=18), S1)
    add(datafmt(0x2000, items[16:], seq=0xC1, numitem=18), S1)
    # read response split over three frames: FIR, middle, FIN
    pl = b''.join(struct.pack('>H', 0x100 + i) for i in range(18))
    add(fm(0x10, 0xC0, struct.pack('>IH', 0x2000, 18)), S1)
    add(readresp(0x2000, pl[:14], seq=0x80), S1)
    add(readresp(0x2000, pl[14:28], seq=0x01), S1)
    add(readresp(0x2000, pl[28:], seq=0x42), S1)
    # a read response with no format definition (region 0x5000) and unmatched base
    add(readresp(0x5000, b'\1\2\3\4'), S1)
    # bit labels, SER
    add(fm(0x33, 0xC0, struct.pack('>I', 0x5000)), S1)
    add(fm(0xB3, 0xC0, labels), S1)
    add(unsresp(3, 0b101, idx=[0, 1, 255]), S1)
    # the CVE-class and first pass reproducers on the branch (valid, fixed)
    add(unsresp(40, 0x00000002), S1)

    # ---- session 2: Fast Meter (A5C1) with scale factors in the data message
    ais = [('IA', 0, 1, 4), ('IB', 0, 0xFF, 0), ('VA', 1, 0, 0), ('VB', 2, 0, 0), ('VC', 0, 1, 4)]
    # offsets: flag at 3, sf float at 4..7, AI from 8: IA(2) IB(2) VA(4) VB(8) VC(2) = 18 -> ts at 26, dig at 34
    cfg = fm_config(0xA5C1, 1, 0, 1, ais, 1, 2, 1, 8, 26, 34)
    add(cfg, S2)
    data = struct.pack('>f', 0.5) + struct.pack('>h', 100) + struct.pack('>h', -200) + struct.pack('>f', 120.5) + \
        struct.pack('>d', 3.25) + struct.pack('>h', 7) + ts8(11, 26, 25, 12, 30, 45, 1123) + bytes([0xA5, 0x0F])
    add(fm_data(0xA5D1, 0x00, data), S2)
    # demand (A5C2): scale factors in the configuration message, 2 samples, no time stamp
    ais = [('IA', 0, 1, None), ('IB', 0, 1, None)]
    cfg = fm_config(0xA5C2, 1, 1, 2, ais, 2, 1, 0, 4, 12, 20, sfs=(0.1, 2.0))
    add(cfg, S2)
    add(fm_data(0xA5D2, 0, struct.pack('>hhhh', 10, 20, 30, 40) + ts8(2, 29, 24, 0, 0, 0, 0) + bytes([0x81])), S2)
    # peak demand (A5C3): four samples of floats, time stamp, 1 digital row, pad byte, no flag byte
    ais = [('IA', 1, 0xFF, 0), ('IB', 1, 0xFF, 0)]
    cfg = fm_config(0xA5C3, 0, 0, 0, ais, 4, 1, 0, 3, 3 + 4 * 2 * 4, 3 + 4 * 2 * 4 + 8, pad=True)
    add(cfg, S2)
    add(fm_data(0xA5D3, None, b''.join(struct.pack('>f', 1.0 + i) for i in range(8)) +
                ts8(1, 2, 3, 4, 5, 6, 789) + bytes([0xFF]), pad=True), S2)

    # ---- session 3: three samples (no sample label), type 3 channel, no digital
    ais = [('IA', 0, 0xFF, 0), ('IB', 3, 0xFF, 0)]
    cfg = fm_config(0xA5C1, 1, 0, 0, ais, 3, 0, 0, 4, 0xFFFF, 0xFFFF)
    add(cfg, S3)
    add(fm_data(0xA5D1, 0, struct.pack('>hhh', 1, 2, 3)), S3)
    # session 4: single sample, flags 2 (no flag byte decoding), only IA
    ais = [('IA', 0, 0xFF, 0)]
    cfg = fm_config(0xA5C1, 2, 0, 0, ais, 1, 0, 0, 4, 6, 0xFFFF)
    add(cfg, S4)
    add(fm_data(0xA5D1, 0, struct.pack('>h', 5) + ts8(6, 15, 22, 1, 2, 3, 4)), S4)
    # session 4 also: configuration with no analog inputs
    cfg = fm_config(0xA5C2, 1, 0, 0, [], 1, 1, 0, 4, 0xFFFF, 4)
    add(cfg, S4)
    add(fm_data(0xA5D2, 0, bytes([0x55])), S4)

    # ---- session 5: reproducers of the branch fixes
    add(datafmt(0x1000, [('ITEMNAME00', 2, 0x31)]), S5)
    add(readresp(0x1000, b'\0\1\0\2\0\3\0\4'), S5)
    # negative 16 bit analog (hf_selfm_fmdata_ai_value16 is now signed)
    ais = [('IA', 0, 0xFF, 0), ('VB', 1, 0xFF, 0)]
    add(fm_config(0xA5C1, 1, 0, 0, ais, 1, 0, 0, 4, 10, 0xFFFF), S5)
    add(fm_data(0xA5D1, 0, struct.pack('>h', -5) + struct.pack('>f', 1.5) + ts8(11, 11, 26, 12, 30, 45, 123)), S5)
    # a SER list conversation: Power Up (254) and Settings Changed (255), unnamed index
    add(unsresp(4, 0b1001, idx=[0, 1, 254, 255]), S5)

    # ---- TCP frames (need Decode As tcp.port==2023,selfm): see tcp_frames()
    return F


def tcp_frames():
    """Ethernet frames of one Telnet-style SEL session on port 2023."""
    src, dst = (10, 1, 0, 1), (10, 1, 0, 2)
    sp, dp = 49200, 2023
    out = []
    seq_c, seq_s = 1000, 5000

    def c(payload, flags=0x18):
        nonlocal seq_c
        out.append(ip_tcp(src, dst, sp, dp, seq_c, seq_s, flags, payload))
        seq_c += max(len(payload), 1 if flags & 3 else 0)

    def s(payload, flags=0x18):
        nonlocal seq_s
        out.append(ip_tcp(dst, src, dp, sp, seq_s, seq_c, flags, payload))
        seq_s += max(len(payload), 1 if flags & 3 else 0)

    c(b'', 0x02)
    s(b'', 0x12)
    c(b'', 0x10)
    # text that is not SEL binary
    s(b'=>\r\n')
    # a 2 byte scan message, a one byte segment
    c(b'\xa5\xc0')
    c(b'\xa5')
    c(b'\xc1')                      # (second byte alone is not an A5 start)
    # relay definition split over two segments (length < PDU length)
    rd = iac(sel(0xA5C0, bytes([1, 1, 1]) + struct.pack('>HH', 0xA5C1, 0xA5D1) + struct.pack('>H', 1) +
                 bytes([0xA5, 0xB9, 0, 0, 0, 0]) + struct.pack('>H', 0x0100)))
    s(rd[:9])
    s(rd[9:])
    # Read request, then a Read Response in 3 fragments (one segment each)
    items = [('NAMEA', 2, 0x32), ('NAMEB', 1, 0x41)]
    c(fm(0x10, 0xC0, struct.pack('>IH', 0x3000, 6)))
    s(iac(datafmt(0x3000, items)))
    pl = struct.pack('>HHf', 0x1234, 0xFFFF, 3.5)
    s(iac(readresp(0x3000, pl[:4], seq=0x80)))
    s(iac(readresp(0x3000, pl[4:6], seq=0x01)))
    s(iac(readresp(0x3000, pl[6:], seq=0x42)))
    # the same response again in a new segment sequence, one PDU split with IAC pairs so the
    # raw length reaches the PDU length but the cleaned length does not
    big = iac(fm(0x90, 0xC0, struct.pack('>IH', 0x3000, 4) + b'\xff\xff\xff\xff' + b'\xff\xff\xff\xff'))
    # the cleaned PDU length is 28; the first 28 raw bytes hold five doubled pairs, so cleaned < 28
    s(big[:28])
    s(big[28:])
    # two PDUs in one segment
    a = iac(sel(0xA5E0, bytes([0x20, 0xDF])))
    b = iac(fm(0x10, 0xC0, struct.pack('>IH', 0x3000, 6)))
    s(a + b)
    # PDU followed by the start of a second PDU: needs more segments
    s(a + b[:5])
    s(b[5:])
    # PDU followed by ASCII
    s(a + b'\r\n=>')
    c(b'', 0x11)
    s(b'', 0x11)
    c(b'', 0x10)
    return out


def malformed_frames():
    F = []

    def add(p, ports=None):
        F.append((iac(p) if ports else p, ports))

    # first pass reads past the end: configuration too short for its channel list
    add(sel(0xA5C1, bytes([1, 0, 0, 3, 1, 0, 0]) + struct.pack('>HHH', 4, 10, 20) + aiinfo('IA', 0, 0, 0)))
    add(sel(0xA5C2, bytes([1, 0, 0, 1, 1, 0, 1]) + struct.pack('>HHH', 4, 10, 20) + aiinfo('IA', 0, 0, 0)))
    add(b'\xa5\xc1\x05\x00\x00')                     # config message cut at the header
    # CRC wrong, and a Fast Message cut after the function code
    add(fm(0x10, 0xC0, struct.pack('>IH', 0x1000, 4), crc=0xBEEF))
    add(fm(0x90, 0xC0, struct.pack('>IH', 0x1000, 4) + b'\1\2\3\4', crc=0x1234))
    pdu = b'\xa5\x46\x0a' + bytes([1, 2, 3, 4, 5, 0, 0x10])
    add(pdu)
    # relay definition: counts larger than the data
    add(sel(0xA5C0, bytes([200, 100, 50])))
    add(sel(0xA5CE, bytes([200]) + struct.pack('>H', 500) + bytes([1, 0])))
    add(sel(0xA5E0, bytes([0x20])))                  # fast operate without validation byte
    add(sel(0xA5CF, bytes([2, 1])))
    add(sel(0xA5E5, bytes([1])))
    # data format response with more items than present
    add(fm(0xB1, 0xC0, struct.pack('>IH', 0x1000, 3) + tag('ONLY', 1, 0x32)[:12]))
    # device description response cut inside the region list
    add(fm(0xB0, 0xC0, b'F' * 50 + b'R' * 40 + struct.pack('>HH', 3, 1) + b'REG'.ljust(10, b'\0') + struct.pack('>IHH', 1, 2, 3)[:5]))
    # read response: the endless-loop case, quantity 0xFFFF (ends in an exception)
    add(datafmt(0x1000, [('ITEMNAME00', 0xFFFF, 0x31)]), P0)
    add(readresp(0x1000, b'\0\1\0\2\0\3\0\4'), P0)
    # a read response whose data is shorter than the items in the format (exception)
    ports = ((10, 9, 9, 1), (10, 9, 9, 2), 50000, 23)
    add(datafmt(0x1100, [('SHORT', 8, 0x31), ('S32', 4, 0x33)]), ports)
    add(readresp(0x1100, b'\0\1\0\2'), ports)
    # unsolicited SER with no end-of-record marker, and one with a length too large
    body = b'\0\0\0\0' + struct.pack('>HHI', 1, 2026, 1000) + b'\0\0\0\0' * 2 + b'\xaa\xaa\xaa\xaa'
    add(fm(0x18, 0xC0, body))
    add(fm(0x18, 0xC0, body, total=200))
    # SOE state response with a block count larger than the data
    add(fm(0x96, 0xC0, struct.pack('>H', 9) + b'\0\0\0\2' + bytes([16, 0]) + struct.pack('>HHI', 1, 2026, 1)))
    # fast meter data whose analog offset lies outside the message, with a config
    ports2 = ((10, 9, 9, 3), (10, 9, 9, 4), 50001, 23)
    ais = [('IA', 0, 0xFF, 0)]
    add(fm_config(0xA5C1, 1, 0, 0, ais, 1, 0, 0, 200, 210, 0xFFFF), ports2)
    add(fm_data(0xA5D1, 0, struct.pack('>h', 5)), ports2)
    # a bare 2 byte Fast Meter configuration request: the first pass reads the configuration fields
    add(b'\xa5\xc1')
    add(b'\xa5\xc2')
    # Fast Meter data whose configuration says "no time stamp" (offset 0xFFFF) with one sample:
    # the sample subtree length is computed from that offset (it decodes, but claims bytes that are not there)
    ports3 = ((10, 9, 9, 5), (10, 9, 9, 6), 50002, 23)
    add(fm_config(0xA5C1, 1, 0, 0, [('IA', 0, 0xFF, 0)], 1, 0, 0, 4, 0xFFFF, 0xFFFF), ports3)
    add(fm_data(0xA5D1, 0, struct.pack('>h', 5)), ports3)
    # PDU length byte below the header length (tree length underflow)
    add(b'\xa5\xe0\x01\x20\x00')
    add(b'\xa5\xd1\x00\x00\x00')
    add(b'\xa5\xc0\x01\x00')
    return F


def build(outdir):
    cap = Cap()
    for p, ports in main_frames():
        cap.exp(p, ports)
    for fr in tcp_frames():
        cap.eth(fr)
    cap.write(os.path.join(outdir, 'selfm-coverage.pcapng'))
    mal = Cap()
    for p, ports in malformed_frames():
        mal.exp(p, ports)
    mal.write(os.path.join(outdir, 'selfm-coverage-malformed.pcapng'))


if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
