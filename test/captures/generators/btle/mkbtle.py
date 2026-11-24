#!/usr/bin/env python3
# Generates test/captures/btle_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generate synthetic captures for packet-btle.c coverage.
# Usage: mkbtle.py <outdir>
# Writes btle-coverage.pcapng (main) and btle-coverage-malformed.pcapng.
# Every packet is built here with struct; nothing is captured from a real
# network. Three interfaces: Bluetooth LE LL without a pseudo header
# (link type 251), LE LL with the btle_rf pseudo header (256) and the
# Nordic BLE sniffer (272, gives an event counter).
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

LT_LE_LL = 251
LT_LE_LL_PHDR = 256
LT_NORDIC = 272

AA_ADV = 0x8e89bed6


# ---------------------------------------------------------------- pcapng
class Pcapng:
    def __init__(self):
        self.blocks = []
        self.ifaces = {}
        self.ts = 1700000000 * 1000000
        self.count = 0
        self._block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
        # Fixed interface order so interface ids do not depend on use
        for lt in (LT_LE_LL, LT_LE_LL_PHDR, LT_NORDIC):
            self.iface(lt)

    def _block(self, btype, body):
        body += b'\0' * ((-len(body)) % 4)
        total = len(body) + 12
        self.blocks.append(struct.pack('<II', btype, total) + body + struct.pack('<I', total))

    def iface(self, linktype):
        if linktype not in self.ifaces:
            self.ifaces[linktype] = len(self.ifaces)
            self._block(1, struct.pack('<HHI', linktype, 0, 262144))
        return self.ifaces[linktype]

    def add(self, linktype, data, caplen=None):
        i = self.iface(linktype)
        self.ts += 1250
        self.count += 1
        cap = data if caplen is None else data[:caplen]
        self._block(6, struct.pack('<IIIII', i, self.ts >> 32, self.ts & 0xffffffff,
                                   len(cap), len(data)) + cap)
        return self.count

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(b''.join(self.blocks))


# ---------------------------------------------------------------- CRC
# Same nibble table as btle_crc() in packet-btle.c
FLIPS = [
    0x0000, 0x32d8, 0x196c, 0x2bb4, 0x0cb6, 0x3e6e, 0x15da, 0x2702,
    0x065b, 0x3483, 0x1f37, 0x2def, 0x0aed, 0x3835, 0x1381, 0x2159,
    0x065b, 0x3483, 0x1f37, 0x2def, 0x0aed, 0x3835, 0x1381, 0x2159,
    0x0000, 0x32d8, 0x196c, 0x2bb4, 0x0cb6, 0x3e6e, 0x15da, 0x2702,
    0x0cb6, 0x3e6e, 0x15da, 0x2702, 0x0000, 0x32d8, 0x196c, 0x2bb4,
    0x0aed, 0x3835, 0x1381, 0x2159, 0x065b, 0x3483, 0x1f37, 0x2def,
    0x0aed, 0x3835, 0x1381, 0x2159, 0x065b, 0x3483, 0x1f37, 0x2def,
    0x0cb6, 0x3e6e, 0x15da, 0x2702, 0x0000, 0x32d8, 0x196c, 0x2bb4,
    0x196c, 0x2bb4, 0x0000, 0x32d8, 0x15da, 0x2702, 0x0cb6, 0x3e6e,
    0x1f37, 0x2def, 0x065b, 0x3483, 0x1381, 0x2159, 0x0aed, 0x3835,
    0x1f37, 0x2def, 0x065b, 0x3483, 0x1381, 0x2159, 0x0aed, 0x3835,
    0x196c, 0x2bb4, 0x0000, 0x32d8, 0x15da, 0x2702, 0x0cb6, 0x3e6e,
    0x15da, 0x2702, 0x0cb6, 0x3e6e, 0x196c, 0x2bb4, 0x0000, 0x32d8,
    0x1381, 0x2159, 0x0aed, 0x3835, 0x1f37, 0x2def, 0x065b, 0x3483,
    0x1381, 0x2159, 0x0aed, 0x3835, 0x1f37, 0x2def, 0x065b, 0x3483,
    0x15da, 0x2702, 0x0cb6, 0x3e6e, 0x196c, 0x2bb4, 0x0000, 0x32d8,
    0x32d8, 0x0000, 0x2bb4, 0x196c, 0x3e6e, 0x0cb6, 0x2702, 0x15da,
    0x3483, 0x065b, 0x2def, 0x1f37, 0x3835, 0x0aed, 0x2159, 0x1381,
    0x3483, 0x065b, 0x2def, 0x1f37, 0x3835, 0x0aed, 0x2159, 0x1381,
    0x32d8, 0x0000, 0x2bb4, 0x196c, 0x3e6e, 0x0cb6, 0x2702, 0x15da,
    0x3e6e, 0x0cb6, 0x2702, 0x15da, 0x32d8, 0x0000, 0x2bb4, 0x196c,
    0x3835, 0x0aed, 0x2159, 0x1381, 0x3483, 0x065b, 0x2def, 0x1f37,
    0x3835, 0x0aed, 0x2159, 0x1381, 0x3483, 0x065b, 0x2def, 0x1f37,
    0x3e6e, 0x0cb6, 0x2702, 0x15da, 0x32d8, 0x0000, 0x2bb4, 0x196c,
    0x2bb4, 0x196c, 0x32d8, 0x0000, 0x2702, 0x15da, 0x3e6e, 0x0cb6,
    0x2def, 0x1f37, 0x3483, 0x065b, 0x2159, 0x1381, 0x3835, 0x0aed,
    0x2def, 0x1f37, 0x3483, 0x065b, 0x2159, 0x1381, 0x3835, 0x0aed,
    0x2bb4, 0x196c, 0x32d8, 0x0000, 0x2702, 0x15da, 0x3e6e, 0x0cb6,
    0x2702, 0x15da, 0x3e6e, 0x0cb6, 0x2bb4, 0x196c, 0x32d8, 0x0000,
    0x2159, 0x1381, 0x3835, 0x0aed, 0x2def, 0x1f37, 0x3483, 0x065b,
    0x2159, 0x1381, 0x3835, 0x0aed, 0x2def, 0x1f37, 0x3483, 0x065b,
    0x2702, 0x15da, 0x3e6e, 0x0cb6, 0x2bb4, 0x196c, 0x32d8, 0x0000,
]


def ble_crc(data, init):
    state = init
    for b in data:
        for nib in (b & 0xf, (b >> 4) & 0xf):
            state = ((state << 4) ^ FLIPS[((state >> 16) & 0xf0) | nib]) & 0xffffff
    return state


def rev8(b):
    return int('{:08b}'.format(b)[::-1], 2)


def crc_bytes(pdu, init):
    c = ble_crc(pdu, init)
    v = 0
    for sh in (0, 8, 16):
        v |= rev8((c >> sh) & 0xff) << sh
    return v.to_bytes(3, 'big')


def ll(aa, pdu, init=0x555555, ci=None, badcrc=False):
    '''Access address, optional coding indicator, PDU, CRC.'''
    crc = crc_bytes(pdu, init)
    if badcrc:
        crc = bytes([crc[0] ^ 0x5a]) + crc[1:]
    return struct.pack('<I', aa) + (bytes([ci]) if ci is not None else b'') + pdu + crc


# ---------------------------------------------------------------- headers
def rf(chan, pdu_type=0, aux=0, crc_checked=True, crc_valid=True, phy=0,
       sig=None, noise=None, aa_off=None, ref_aa=None, extra=0):
    flags = (pdu_type << 7) | (aux << 12 if pdu_type == 1 else 0) | (phy << 14) | extra
    if crc_checked:
        flags |= 0x0400
        if crc_valid:
            flags |= 0x0800
    if sig is not None:
        flags |= 0x0002
    if noise is not None:
        flags |= 0x0004
    if aa_off is not None:
        flags |= 0x0020
    if ref_aa is not None:
        flags |= 0x0010
    return struct.pack('<BbbBIH', chan, sig or 0, noise or 0, aa_off or 0, ref_aa or 0, flags)


nordic_counter = [0]
nordic_time = [1000]


def nordic(payload, adv, chan, event_counter, central=False, crc_ok=True,
           mic=None, phy=0, aux=0):
    '''Nordic BLE sniffer header, protocol version 3.'''
    if adv:
        flags = (1 if crc_ok else 0) | (aux << 1) | (phy << 4)
    else:
        flags = (1 if crc_ok else 0) | (2 if central else 0) | (phy << 4)
        if mic is not None:
            flags |= 4 | (8 if mic else 0)
    nordic_counter[0] += 1
    nordic_time[0] += 1250
    event = struct.pack('<BBBBHI', 10, flags, chan, 50, event_counter, nordic_time[0])
    hdr = struct.pack('<BHBHB', 0, len(event) + len(payload), 3, nordic_counter[0], 2 if adv else 6)
    return hdr + event + payload


# ---------------------------------------------------------------- PDUs
def addr(n):
    '''Six octet device address, little endian on air.'''
    return bytes([n, 0x00, 0x00, 0xdb, 0x0b, 0xc0])


def ad(t, data):
    return bytes([len(data) + 1, t]) + data


AD_FLAGS = ad(0x01, b'\x06')
AD_NAME = ad(0x09, b'LE-cov')


def adv_pdu(pdu_type, payload, txadd=0, rxadd=0, chsel=0):
    hdr = pdu_type | (chsel << 5) | (txadd << 6) | (rxadd << 7)
    return bytes([hdr, len(payload)]) + payload


def chmap(top=0):
    return b'\xff\xff\xff\xff' + bytes([0x1f | (top << 5)])


def connect_payload(inita, adva, aa, crc_init, interval=24, hop=5, sca=3):
    lld = struct.pack('<I', aa) + crc_init.to_bytes(3, 'little') + b'\x02'
    lld += struct.pack('<HHHH', 3, interval, 0, 200) + chmap() + bytes([hop | (sca << 5)])
    return inita + adva + lld


def sync_info(aa, crc_init, offset=0x0123, units=1, adjust=1, interval=80, sca=5, evc=7):
    off = offset | (units << 13) | (adjust << 14)
    return struct.pack('<HH', off, interval) + chmap(sca) + struct.pack('<I', aa) + \
        crc_init.to_bytes(3, 'little') + struct.pack('<H', evc)


def biginfo(seed, encrypted=False):
    d = struct.pack('<I', 0x123 | 0x4000 | (8 << 15) | (2 << 27))
    d += struct.pack('<I', 2 | (1 << 5) | (100 << 8) | (1 << 28))
    d += (0x400 | (1 << 20)).to_bytes(3, 'little') + b'\x40\x00' + struct.pack('<I', seed)
    d += struct.pack('<I', 10000 | (40 << 20)) + struct.pack('<H', 0x1234) + chmap() + \
        b'\x00\x00\x00\x00\x80'
    if encrypted:
        d += b'\x11' * 8 + b'\x22' * 16
    return ad(0x2c, d)


def ext_adv(pdu_type, flags, fields, data, adv_mode=0, acad=b'', ext_len=None, txadd=0, rxadd=0):
    body = (bytes([flags]) if flags is not None else b'') + fields + acad
    if ext_len is None:
        ext_len = len(body)
    ext = bytes([(ext_len & 0x3f) | (adv_mode << 6)]) + body
    return adv_pdu(pdu_type, ext + data, txadd=txadd, rxadd=rxadd)


def adi(did, sid):
    return struct.pack('<H', did | (sid << 12))


def auxptr(chan=5, ca=1, units=0, off=100, phy=1):
    return bytes([chan | (ca << 6) | (units << 7)]) + struct.pack('<H', off | (phy << 13))


def data_pdu(llid, payload, sn=0, nesn=0, md=0, cte=None, length=None):
    hdr = llid | (nesn << 2) | (sn << 3) | (md << 4) | (0x20 if cte is not None else 0)
    ln = len(payload) if length is None else length
    return bytes([hdr, ln]) + (bytes([cte]) if cte is not None else b'') + payload


def ctrl(opcode, payload=b''):
    return bytes([opcode]) + payload


def l2cap(cid, payload, length=None):
    return struct.pack('<HH', len(payload) if length is None else length, cid) + payload


C, P = 1, 2   # directions


class Conn:
    '''Tracks the SN/NESN state the dissector expects.'''

    def __init__(self, aa, crc_init):
        self.aa = aa
        self.crc_init = crc_init
        self.first = True
        self.prev = {0: 0, C: 0, P: 1}

    def seq(self, d, retransmit=False, nack=False):
        if self.first:
            self.first = False
            return 0, 0
        o = P if d == C else C
        if d == 0:
            o = 0
        sn = self.prev[d] if retransmit else 1 - self.prev[d]
        nesn = self.prev[o] if nack else 1 - self.prev[o]
        self.prev[d] = sn
        return sn, nesn

    def pdu(self, d, llid, payload, retransmit=False, nack=False, **kw):
        sn, nesn = self.seq(d, retransmit, nack)
        return data_pdu(llid, payload, sn, nesn, **kw)


# Opcodes
OP = dict(CONNECTION_UPDATE_IND=0x00, CHANNEL_MAP_IND=0x01, TERMINATE_IND=0x02,
          ENC_REQ=0x03, ENC_RSP=0x04, START_ENC_REQ=0x05, START_ENC_RSP=0x06,
          UNKNOWN_RSP=0x07, FEATURE_REQ=0x08, FEATURE_RSP=0x09, PAUSE_ENC_REQ=0x0a,
          PAUSE_ENC_RSP=0x0b, VERSION_IND=0x0c, REJECT_IND=0x0d,
          PERIPHERAL_FEATURE_REQ=0x0e, CONNECTION_PARAM_REQ=0x0f,
          CONNECTION_PARAM_RSP=0x10, REJECT_EXT_IND=0x11, PING_REQ=0x12, PING_RSP=0x13,
          LENGTH_REQ=0x14, LENGTH_RSP=0x15, PHY_REQ=0x16, PHY_RSP=0x17,
          PHY_UPDATE_IND=0x18, MIN_USED_CHANNELS_IND=0x19, CTE_REQ=0x1a, CTE_RSP=0x1b,
          PERIODIC_SYNC_IND=0x1c, CLOCK_ACCURACY_REQ=0x1d, CLOCK_ACCURACY_RSP=0x1e,
          CIS_REQ=0x1f, CIS_RSP=0x20, CIS_IND=0x21, CIS_TERMINATE_IND=0x22,
          POWER_CONTROL_REQ=0x23, POWER_CONTROL_RSP=0x24, POWER_CHANGE_IND=0x25,
          SUBRATE_REQ=0x26, SUBRATE_IND=0x27, CHANNEL_REPORTING_IND=0x28,
          CHANNEL_STATUS_IND=0x29, PERIODIC_SYNC_WR_IND=0x2a, FEATURE_EXT_REQ=0x2b,
          FEATURE_EXT_RSP=0x2c, CS_SEC_RSP=0x2d, CS_CAPABILITIES_REQ=0x2e,
          CS_CAPABILITIES_RSP=0x2f, CS_CONFIG_REQ=0x30, CS_CONFIG_RSP=0x31, CS_REQ=0x32,
          CS_RSP=0x33, CS_IND=0x34, CS_TERMINATE_REQ=0x35, CS_FAE_REQ=0x36,
          CS_FAE_RSP=0x37, CS_CHANNEL_MAP_IND=0x38, CS_SEC_REQ=0x39,
          CS_TERMINATE_RSP=0x3a, FRAME_SPACE_REQ=0x3b, FRAME_SPACE_RSP=0x3c)

FEATURES = bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x00])
CONN_UPDATE = struct.pack('<BHHHHH', 2, 4, 40, 0, 300, 0)   # instant patched
CONN_PARAM = struct.pack('<HHHHBHHHHHHH', 6, 40, 0, 300, 2, 10, 0, 1, 2, 3, 4, 0xffff)
LENGTH = struct.pack('<HHHH', 251, 2120, 251, 2120)
SYNC_IND = struct.pack('<H', 1) + sync_info(0x5a5a1234, 0x112233)[:] + \
    struct.pack('<HH', 20, 30) + b'\x05' + b'\x02' + addr(0x30) + struct.pack('<H', 25)
SYNC_IND_NOOFF = struct.pack('<H', 2) + sync_info(0x5a5a1235, 0x112233, offset=0, units=0, adjust=0) + \
    struct.pack('<HH', 20, 30) + b'\x00' + b'\x01' + addr(0x31) + struct.pack('<H', 25)
SYNC_WR_IND = SYNC_IND + struct.pack('<I', 0x6b6b5678) + bytes([4, 10, 2, 3])
CIS_REQ = bytes([1, 2, 0x02, 0x02]) + struct.pack('<HH', 0x8000 | 100, 100) + \
    (10000).to_bytes(3, 'little') + (10000).to_bytes(3, 'little') + struct.pack('<HH', 100, 100) + \
    b'\x03' + (2500).to_bytes(3, 'little') + b'\x11\x02\x02' + struct.pack('<H', 8) + \
    (500).to_bytes(3, 'little') + (900).to_bytes(3, 'little') + struct.pack('<H', 40)
CIS_RSP = (500).to_bytes(3, 'little') + (900).to_bytes(3, 'little') + struct.pack('<H', 40)
CS_CAPS = bytes([1, 0x07, 1, 2, 3]) + struct.pack('<HH', 3, 3) + bytes([0x06, 0x24, 0x7f, 4]) + \
    struct.pack('<H', 10) + b'\x0f' + struct.pack('<HHHH', 0x3ff, 0x3ff, 0x3ff, 0x3) + b'\x1e'
CS_CONFIG_REQ = bytes([0x41]) + b'\xfc' + b'\xff' * 8 + b'\x7f' + bytes([1, 1, 1, 2, 3, 4, 3, 2, 0x31, 0x21, 2, 10, 20, 30, 40, 0])
CS_REQ = bytes([1]) + struct.pack('<H', 50) + (1000).to_bytes(3, 'little') + (2000).to_bytes(3, 'little') + \
    struct.pack('<HH', 100, 4) + b'\x01' + struct.pack('<H', 6) + (3000).to_bytes(3, 'little') + \
    struct.pack('<HH', 10, 5) + bytes([1, 2, 1, 0x80, 0x34])
CS_RSP = bytes([1]) + struct.pack('<H', 50) + (1000).to_bytes(3, 'little') + (2000).to_bytes(3, 'little') + \
    struct.pack('<H', 4) + b'\x01' + struct.pack('<H', 6) + (3000).to_bytes(3, 'little') + bytes([1, 2, 0x80, 0])
CS_IND = bytes([1]) + struct.pack('<H', 50) + (1500).to_bytes(3, 'little') + struct.pack('<H', 4) + b'\x01' + \
    struct.pack('<H', 6) + (3000).to_bytes(3, 'little') + bytes([1, 2, 0x80, 0])
CS_TERM = bytes([1]) + struct.pack('<H', 3) + b'\x13'
CS_SEC = b'\x01' * 8 + b'\x02' * 4 + b'\x03' * 8
CS_CHMAP = b'\xfc' + b'\xff' * 8 + b'\x7f' + struct.pack('<H', 60)


def conn_update(instant):
    return CONN_UPDATE[:-2] + struct.pack('<H', instant)


def chmap_ind(instant):
    return chmap() + struct.pack('<H', instant)


def phy_update(c2p, p2c, instant):
    return bytes([c2p, p2c]) + struct.pack('<H', instant)


# ================================================================ main
def build_main():
    pc = Pcapng()
    LE = lambda b: pc.add(LT_LE_LL, b)
    RF = lambda h, b: pc.add(LT_LE_LL_PHDR, h + b)
    NO = lambda b: pc.add(LT_NORDIC, b)
    marks = {}

    # ---------------- 1. Legacy advertising, no pseudo header (251)
    adva = addr(0x01)
    marks['legacy'] = pc.count + 1
    LE(ll(AA_ADV, adv_pdu(0x00, adva + AD_FLAGS + b'\x00' + AD_NAME, txadd=1, chsel=1)))
    LE(ll(AA_ADV, adv_pdu(0x00, adva)))                                         # no AD
    LE(ll(AA_ADV, adv_pdu(0x01, adva + addr(0x02), txadd=1, rxadd=1)))          # ADV_DIRECT_IND
    LE(ll(AA_ADV, adv_pdu(0x02, adva + AD_NAME)))                                # ADV_NONCONN_IND
    LE(ll(AA_ADV, adv_pdu(0x03, addr(0x03) + adva, txadd=1)))                    # SCAN_REQ
    LE(ll(AA_ADV, adv_pdu(0x04, adva + AD_NAME + ad(0xff, b'\x59\x00\x01\x02'))))  # SCAN_RSP
    LE(ll(AA_ADV, adv_pdu(0x04, adva)))                                          # SCAN_RSP, no data
    LE(ll(AA_ADV, adv_pdu(0x06, adva + AD_FLAGS)))                               # ADV_SCAN_IND
    # AD after a zero length octet: the AD dissector stops at the zero,
    # the BIGInfo scan in dissect_ad_eir() skips it and stops at the
    # structure that is longer than the rest of the PDU
    LE(ll(AA_ADV, adv_pdu(0x02, adva + AD_FLAGS + b'\x00' + b'\x20\x09AB')))
    LE(ll(AA_ADV, adv_pdu(0x0a, b'\x01\x02\x03\x04')))                           # reserved PDU type
    # From btle_crc_len255.py: valid CRC on 100, 253, 254 and
    # 255 octet payloads
    marks['crc255'] = pc.count + 1
    for n in (100, 253, 254, 255):
        LE(ll(AA_ADV, adv_pdu(0x02, addr(0x01) + b'\x00' * (n - 6))))
    LE(ll(AA_ADV, adv_pdu(0x02, adva + AD_NAME), badcrc=True))                 # Incorrect CRC

    # ---------------- 2. Extended advertising without context (251)
    # All extended header fields; Sync Info announces periodic AA PA1,
    # ACAD carries a BIGInfo with seed SEED1.
    PA1, PA1_CRC = 0x4d6a1234, 0x0c0ffe
    SEED1 = 0x0041a5a5
    marks['ext251'] = pc.count + 1
    fields = adva + addr(0x02) + b'\x48' + adi(5, 3) + auxptr() + sync_info(PA1, PA1_CRC) + b'\xf6'
    LE(ll(AA_ADV, ext_adv(0x07, 0x7f, fields, AD_NAME, adv_mode=1, acad=biginfo(SEED1), txadd=1, rxadd=1)))
    # Reproducer from btle_uninit_src_bd_addr.py: no AdvA,
    # BIGInfo in the ACAD, then a BIS PDU on its seed access address
    SEED0 = 0x00411234
    marks['uninit'] = pc.count + 1
    bi0 = bytes([34, 0x2c]) + b'\x11' * 13 + struct.pack('<I', SEED0) + b'\x22' * 16
    LE(ll(AA_ADV, ext_adv(0x07, 0x00, b'', b'', acad=bi0)))
    LE(ll(SEED0, data_pdu(0, b'\xaa\xbb')))
    # Reproducer from btle_acad_len_wrap.py: extended header
    # length 1 with AdvA announced (no ACAD now)
    marks['acadwrap'] = pc.count + 1
    LE(ll(AA_ADV, ext_adv(0x07, 0x01, b'', addr(0x01) + ad(0x09, b'ABCD') + b'\x00' * 240, ext_len=1)))
    LE(ll(AA_ADV, ext_adv(0x07, None, b'', b'', ext_len=0, adv_mode=2)))          # no flags
    LE(ll(AA_ADV, ext_adv(0x07, 0x00, b'', AD_NAME)))                             # flags only, data
    LE(ll(AA_ADV, ext_adv(0x08, 0x03, adva + addr(0x02), b'', txadd=1)))          # AUX_CONNECT_RSP
    LE(ll(AA_ADV, ext_adv(0x09, 0x09, adva + adi(6, 3), AD_FLAGS)))               # ADV_DECISION_IND
    # Periodic advertising on PA1 (guessed from the Sync Info), with a
    # BIGInfo for SEED2 in its ACAD
    SEED2 = 0x0040c3c3
    marks['periodic251'] = pc.count + 1
    LE(ll(PA1, ext_adv(0x07, 0x40, b'\x00', AD_NAME, acad=biginfo(SEED2, encrypted=True)), init=PA1_CRC))
    LE(ll(PA1, ext_adv(0x07, 0x00, b'', ad(0x16, b'\x51\x18\x00')), init=PA1_CRC))
    # Broadcast isochronous PDUs, guessed from the seed access address
    marks['bis251'] = pc.count + 1
    for aa_ in (SEED1, SEED1 | 0x80000000):
        LE(ll(aa_, data_pdu(0, b'\x01\x02\x03')))
    LE(ll(SEED1, data_pdu(1 | 0x0c | 0x10, b'\x04\x05')))
    LE(ll(SEED1, data_pdu(2, b'\x06\x07\x08\x09')))
    LE(ll(SEED1, data_pdu(3, ctrl(0x00, chmap_ind(100)))))      # BIG_CHANNEL_MAP_IND
    LE(ll(SEED1, data_pdu(3, ctrl(0x01, b'\x13' + struct.pack('<H', 120)))))  # BIG_TERMINATE_IND
    LE(ll(SEED1, data_pdu(3, ctrl(0x05, b'\xde\xad'))))         # unknown BIG control opcode
    LE(ll(SEED1, data_pdu(3, ctrl(0x05))))                      # unknown, no data
    LE(ll(SEED2, data_pdu(0, b'\x10\x11')))

    # ---------------- 3. Connection without direction (251)
    CA, CA_CRC = 0x50654321, 0x00a1b2
    cc = Conn(CA, CA_CRC)
    marks['conn251'] = pc.count + 1
    LE(ll(AA_ADV, adv_pdu(0x05, connect_payload(addr(0x10), addr(0x11), CA, CA_CRC), txadd=1)))

    def LEc(llid, payload, **kw):
        return LE(ll(CA, cc.pdu(0, llid, payload, **kw), init=CA_CRC))
    LEc(1, b'')                                                       # Empty PDU
    LEc(2, l2cap(5, bytes([0x12, 1]) + struct.pack('<HHHHH', 8, 6, 40, 0, 300)))  # complete L2CAP
    att = bytes([0x1b]) + struct.pack('<H', 0x0003) + bytes(range(20))
    LEc(2, l2cap(4, att)[:10])                                        # start, 10 of 27
    LEc(1, l2cap(4, att)[10:20])                                      # continuation
    LEc(1, l2cap(4, att)[20:])                                        # last -> reassembled
    LEc(3, ctrl(OP['VERSION_IND'], bytes([0x0d]) + struct.pack('<HH', 0x0059, 0x1234)))
    LEc(3, ctrl(OP['FEATURE_REQ'], FEATURES))
    LEc(3, ctrl(OP['ENC_REQ'], b'\x01' * 8 + b'\x02\x03' + b'\x04' * 8 + b'\x05' * 4))
    LEc(3, ctrl(OP['CONNECTION_UPDATE_IND'], conn_update(50)))
    LEc(3, ctrl(OP['CHANNEL_MAP_IND'], chmap_ind(60)))
    LEc(3, ctrl(OP['CIS_REQ'], CIS_REQ))
    LEc(3, ctrl(OP['PHY_UPDATE_IND'], phy_update(2, 2, 70)))
    LEc(3, ctrl(OP['CIS_IND'], struct.pack('<I', 0x7e7e7e01) + (500).to_bytes(3, 'little') +
                (1000).to_bytes(3, 'little') + (900).to_bytes(3, 'little') + struct.pack('<H', 40)))
    LE(ll(CA, cc.pdu(0, 1, b''), init=CA_CRC, badcrc=True))          # Incorrect CRC
    LEc(0, b'\x01\x02')                                               # reserved LLID
    LE(ll(0x71727374, data_pdu(1, b'\x00\x01\x02')))                  # unknown AA: fragment, no connection
    LE(ll(0x71727374, data_pdu(2, l2cap(4, b'\x0a\x03\x00', length=30))))   # start without connection

    # ---------------- 4. btle_rf (256): advertising channels, ChSel, aux
    marks['rfadv'] = pc.count + 1
    ADVA2 = addr(0x20)
    RF(rf(0, sig=-50, noise=-90, aa_off=0, ref_aa=AA_ADV), ll(AA_ADV, adv_pdu(0x00, ADVA2 + AD_FLAGS, chsel=1)))
    RF(rf(12, aa_off=2, ref_aa=AA_ADV), ll(AA_ADV, adv_pdu(0x00, ADVA2 + AD_NAME)))   # bit errors
    RF(rf(39, phy=2), ll(AA_ADV, adv_pdu(0x02, ADVA2 + AD_NAME), ci=1))              # coded PHY
    RF(rf(0, crc_checked=True, crc_valid=False), ll(AA_ADV, adv_pdu(0x02, ADVA2)))   # CRC invalid at capture
    RF(rf(39, crc_checked=False), ll(AA_ADV, adv_pdu(0x02, ADVA2 + AD_NAME)))        # CRC calculated
    # Extended advertising on the primary channel, then the auxiliary chain
    # (reproducer btle_ea_had_multipass.py first, then a
    # three fragment chain)
    marks['had'] = pc.count + 1
    RF(rf(0, 1, 0), ll(AA_ADV, ext_adv(0x07, 0x18, adi(5, 1) + auxptr(chan=0), b'')))
    ADI1 = adi(5, 1)
    RF(rf(1, 1, 0), ll(AA_ADV, ext_adv(0x07, 0x19, addr(0x01) + ADI1 + b'\x05\x10\x00',
                                        ad(0x01, b'\x06') + ad(0x09, b'ABCD'))))
    RF(rf(1, 1, 1), ll(AA_ADV, ext_adv(0x07, 0x08, ADI1, ad(0x09, b'WXYZ'))))
    ADI2 = adi(9, 2)
    RF(rf(5, 1, 0), ll(AA_ADV, ext_adv(0x07, 0x19, ADVA2 + ADI2 + auxptr(), AD_FLAGS + AD_NAME[:5])))
    # (the middle fragment carries AdvA: without it, the address copied
    # from the AUX_ADV_IND is the source only in the first pass; that
    # variant is in the malformed capture)
    RF(rf(5, 1, 1), ll(AA_ADV, ext_adv(0x07, 0x19, ADVA2 + ADI2 + auxptr(), AD_NAME[5:] + ad(0x0a, b'\x04'))))
    RF(rf(5, 1, 1), ll(AA_ADV, ext_adv(0x07, 0x08, ADI2, ad(0xff, b'\x59\x00' + b'\x77' * 10))))
    RF(rf(5, 1, 1), ll(AA_ADV, ext_adv(0x07, 0x08, adi(11, 4), AD_NAME)))          # final, no start
    RF(rf(5, 1, 1), ll(AA_ADV, ext_adv(0x07, 0x10, auxptr(), AD_NAME)))            # chain, no ADI
    RF(rf(5, 1, 0), ll(AA_ADV, ext_adv(0x07, 0x11, ADVA2 + auxptr(), AD_NAME)))    # AuxPtr, no ADI
    RF(rf(5, 1, 0), ll(AA_ADV, ext_adv(0x07, 0x09, ADVA2 + adi(12, 1), AD_NAME)))  # no AuxPtr
    RF(rf(5, 1, 3), ll(AA_ADV, ext_adv(0x07, 0x01, ADVA2, AD_NAME)))               # AUX_SCAN_RSP
    ADI3 = adi(13, 5)
    RF(rf(5, 1, 3), ll(AA_ADV, ext_adv(0x07, 0x19, ADVA2 + ADI3 + auxptr(), AD_NAME)))   # AUX_SCAN_RSP, chain
    RF(rf(5, 1, 1), ll(AA_ADV, ext_adv(0x07, 0x08, ADI3, AD_FLAGS)))
    RF(rf(5, 1, 0), ll(AA_ADV, ext_adv(0x09, 0x18, adi(14, 6) + auxptr(), AD_NAME)))     # ADV_DECISION_IND
    RF(rf(5, 1, 2), ll(AA_ADV, ext_adv(0x08, 0x01, ADVA2, b'')))                         # AUX_CONNECT_RSP
    RF(rf(5), ll(AA_ADV, adv_pdu(0x03, addr(0x21) + ADVA2, txadd=1)))                    # AUX_SCAN_REQ
    # Periodic advertising announced by an AUX_ADV_IND, then AUX_SYNC_IND
    # with a fragmented Host Advertising Data and a BIGInfo
    PA2, PA2_CRC = 0x4e5f6071, 0x00beef
    SEED3 = 0x0001d00d
    marks['periodic256'] = pc.count + 1
    RF(rf(5, 1, 0), ll(AA_ADV, ext_adv(0x07, 0x29, ADVA2 + adi(20, 7) + sync_info(PA2, PA2_CRC, offset=0, units=0, adjust=0), AD_NAME)))
    ADI4 = adi(21, 7)
    RF(rf(7, 1, 2), ll(PA2, ext_adv(0x07, 0x18, ADI4 + auxptr(), AD_NAME, acad=biginfo(SEED3)), init=PA2_CRC))
    RF(rf(7, 1, 1), ll(PA2, ext_adv(0x07, 0x08, ADI4, AD_FLAGS), init=PA2_CRC))
    RF(rf(7), ll(PA2, ext_adv(0x07, 0x00, b'', AD_NAME), init=PA2_CRC))                 # guessed periodic
    marks['bis256'] = pc.count + 1
    RF(rf(9, 6), ll(SEED3, data_pdu(0, b'\x01\x02')))
    RF(rf(9, 6), ll(SEED3, data_pdu(3, ctrl(0x01, b'\x16' + struct.pack('<H', 9)))))
    RF(rf(9, 6), ll(0x12344321, data_pdu(2, b'\x01')))                                   # BIS, unknown BIG
    # AUX_CONNECT_REQ on a secondary channel creates a connection
    CD, CD_CRC = 0x6a7b8c9d, 0x00d00d
    marks['auxconn'] = pc.count + 1
    RF(rf(5), ll(AA_ADV, adv_pdu(0x05, connect_payload(addr(0x22), ADVA2, CD, CD_CRC), txadd=1, rxadd=1)))
    cd = Conn(CD, CD_CRC)
    RF(rf(10, 2), ll(CD, cd.pdu(C, 1, b''), init=CD_CRC))
    RF(rf(10, 3), ll(CD, cd.pdu(P, 1, b''), init=CD_CRC))
    RF(rf(10, 0, crc_checked=False), ll(CD, cd.pdu(0, 1, b''), init=CD_CRC))           # direction unspecified

    # ---------------- 5. btle_rf connection with every control procedure
    CB, CB_CRC = 0x55aa55aa, 0x00c0de
    cb = Conn(CB, CB_CRC)
    marks['connA'] = pc.count + 1
    RF(rf(0), ll(AA_ADV, adv_pdu(0x05, connect_payload(addr(0x40), addr(0x41), CB, CB_CRC), txadd=1, chsel=1)))
    procs = {}

    def A(d, llid, payload, **kw):
        h = rf(20, 2 if d == C else 3, extra=kw.pop('extra', 0))
        return RF(h, ll(CB, cb.pdu(d, llid, payload, **kw), init=CB_CRC))

    def Ac(d, name, payload=b'', **kw):
        n = A(d, 3, ctrl(OP[name], payload), **kw)
        procs.setdefault(name, n)
        return n
    A(C, 1, b'')
    A(P, 1, b'')
    Ac(C, 'VERSION_IND', bytes([0x0e]) + struct.pack('<HH', 0x0059, 1))
    Ac(P, 'VERSION_IND', bytes([0x0c]) + struct.pack('<HH', 0x0002, 2))
    Ac(C, 'FEATURE_REQ', FEATURES)
    Ac(P, 'FEATURE_RSP', FEATURES)
    Ac(P, 'PERIPHERAL_FEATURE_REQ', FEATURES)
    Ac(C, 'FEATURE_RSP', FEATURES)
    Ac(C, 'LENGTH_REQ', LENGTH)
    Ac(P, 'LENGTH_RSP', LENGTH)
    Ac(P, 'LENGTH_REQ', LENGTH)
    Ac(C, 'LENGTH_RSP', LENGTH)
    Ac(C, 'PING_REQ', b'\x00')            # extra octet: unknown data
    Ac(P, 'PING_RSP')
    Ac(P, 'PING_REQ')
    marks['unknown_rsp'] = Ac(C, 'UNKNOWN_RSP', bytes([OP['PING_REQ']]))
    marks['enc'] = Ac(C, 'ENC_REQ', b'\x01' * 8 + b'\x02\x03' + b'\x04' * 8 + b'\x05' * 4)
    Ac(P, 'ENC_RSP', b'\x06' * 8 + b'\x07' * 4)
    Ac(P, 'START_ENC_REQ')
    Ac(C, 'START_ENC_RSP')
    Ac(P, 'START_ENC_RSP')
    Ac(C, 'PAUSE_ENC_REQ', b'\x00')       # extra octet: unknown data
    Ac(P, 'PAUSE_ENC_RSP')
    Ac(C, 'PAUSE_ENC_RSP')
    Ac(C, 'ENC_REQ', b'\x01' * 22)
    Ac(P, 'REJECT_IND', b'\x06')
    Ac(C, 'ENC_REQ', b'\x01' * 22)
    Ac(P, 'ENC_RSP', b'\x06' * 12)
    Ac(P, 'REJECT_IND', b'\x06')
    Ac(C, 'ENC_REQ', b'\x01' * 22)
    Ac(P, 'REJECT_EXT_IND', bytes([OP['ENC_REQ'], 0x06]))
    Ac(C, 'ENC_REQ', b'\x01' * 22)
    Ac(P, 'ENC_RSP', b'\x06' * 12)
    Ac(P, 'REJECT_EXT_IND', bytes([OP['ENC_REQ'], 0x06]))
    marks['connparam'] = Ac(C, 'CONNECTION_PARAM_REQ', CONN_PARAM)
    Ac(P, 'CONNECTION_PARAM_RSP', CONN_PARAM)
    Ac(C, 'CONNECTION_UPDATE_IND', conn_update(100))
    Ac(P, 'CONNECTION_PARAM_REQ', CONN_PARAM)
    Ac(C, 'CONNECTION_UPDATE_IND', conn_update(110))
    Ac(C, 'CONNECTION_PARAM_REQ', CONN_PARAM)
    Ac(P, 'REJECT_EXT_IND', bytes([OP['CONNECTION_PARAM_REQ'], 0x3b]))
    Ac(P, 'CONNECTION_PARAM_REQ', CONN_PARAM)
    Ac(C, 'REJECT_EXT_IND', bytes([OP['CONNECTION_PARAM_REQ'], 0x3b]))
    Ac(C, 'CONNECTION_UPDATE_IND', conn_update(120))
    Ac(C, 'CHANNEL_MAP_IND', chmap_ind(130))
    Ac(C, 'PHY_REQ', b'\x07\x07')
    Ac(P, 'PHY_RSP', b'\x03\x03')
    Ac(C, 'PHY_UPDATE_IND', phy_update(2, 2, 140))
    Ac(P, 'PHY_REQ', b'\x02\x02')
    Ac(C, 'PHY_UPDATE_IND', phy_update(0, 2, 0))          # C->P unchanged, no instant
    Ac(C, 'PHY_REQ', b'\x04\x04')
    Ac(P, 'REJECT_EXT_IND', bytes([OP['PHY_REQ'], 0x1a]))
    Ac(P, 'MIN_USED_CHANNELS_IND', b'\x03\x02')
    Ac(C, 'UNKNOWN_RSP', bytes([OP['MIN_USED_CHANNELS_IND']]))
    Ac(C, 'CTE_REQ', b'\x45')
    Ac(P, 'CTE_RSP')
    Ac(P, 'CTE_REQ', b'\x85')
    Ac(C, 'REJECT_EXT_IND', bytes([OP['CTE_REQ'], 0x1a]))
    Ac(C, 'PERIODIC_SYNC_IND', SYNC_IND)
    Ac(P, 'PERIODIC_SYNC_IND', SYNC_IND_NOOFF)
    Ac(C, 'CLOCK_ACCURACY_REQ', b'\x01')
    Ac(P, 'CLOCK_ACCURACY_RSP', b'\x00')
    CIS1 = 0x3c3c5a01
    marks['cis'] = Ac(C, 'CIS_REQ', CIS_REQ)
    Ac(P, 'CIS_RSP', CIS_RSP)
    Ac(C, 'CIS_IND', struct.pack('<I', CIS1) + (500).to_bytes(3, 'little') +
       (1000).to_bytes(3, 'little') + (900).to_bytes(3, 'little') + struct.pack('<H', 40))
    Ac(C, 'CIS_REQ', CIS_REQ)
    Ac(P, 'REJECT_EXT_IND', bytes([OP['CIS_REQ'], 0x0d]))
    Ac(C, 'CIS_REQ', CIS_REQ)
    Ac(P, 'CIS_RSP', CIS_RSP)
    Ac(C, 'REJECT_EXT_IND', bytes([OP['CIS_RSP'], 0x0d]))
    Ac(C, 'CIS_TERMINATE_IND', b'\x01\x02\x13')
    Ac(C, 'POWER_CONTROL_REQ', b'\x01\x02\x08')
    Ac(P, 'POWER_CONTROL_RSP', b'\x03\x02\x08\x04')
    Ac(P, 'POWER_CONTROL_REQ', b'\x02\xfe\x7e')
    Ac(C, 'REJECT_EXT_IND', bytes([OP['POWER_CONTROL_REQ'], 0x1a]))
    Ac(P, 'POWER_CHANGE_IND', b'\x01\x02\x7f\x7e')
    Ac(P, 'SUBRATE_REQ', struct.pack('<HHHHH', 1, 4, 2, 1, 300))
    Ac(C, 'SUBRATE_IND', struct.pack('<HHHHH', 2, 100, 1, 1, 300))
    Ac(C, 'SUBRATE_IND', struct.pack('<HHHHH', 1, 110, 0, 0, 300))
    Ac(P, 'SUBRATE_REQ', struct.pack('<HHHHH', 1, 4, 2, 1, 300))
    Ac(C, 'REJECT_EXT_IND', bytes([OP['SUBRATE_REQ'], 0x1a]))
    Ac(C, 'CHANNEL_REPORTING_IND', b'\x01\x05\x0a')
    Ac(P, 'CHANNEL_STATUS_IND', b'\x55' * 9 + b'\x05')
    Ac(C, 'PERIODIC_SYNC_WR_IND', SYNC_WR_IND)
    Ac(C, 'FEATURE_EXT_REQ')
    Ac(P, 'FEATURE_EXT_RSP')
    Ac(C, 'CS_SEC_REQ', CS_SEC)
    Ac(P, 'CS_SEC_RSP', CS_SEC)
    Ac(C, 'CS_CAPABILITIES_REQ', CS_CAPS)
    Ac(P, 'CS_CAPABILITIES_RSP', CS_CAPS)
    Ac(C, 'CS_CONFIG_REQ', CS_CONFIG_REQ)
    Ac(P, 'CS_CONFIG_RSP', b'\x01')
    Ac(C, 'CS_REQ', CS_REQ)
    Ac(P, 'CS_RSP', CS_RSP)
    Ac(C, 'CS_IND', CS_IND)
    Ac(C, 'CS_TERMINATE_REQ', CS_TERM)
    Ac(P, 'CS_TERMINATE_RSP', CS_TERM)
    Ac(C, 'CS_FAE_REQ')
    Ac(P, 'CS_FAE_RSP')
    Ac(C, 'CS_CHANNEL_MAP_IND', CS_CHMAP)
    Ac(C, 'FRAME_SPACE_REQ')
    Ac(P, 'FRAME_SPACE_RSP')
    # Procedures running in both directions at once that the dissector
    # accepts: a non-instant procedure while the peer's is open, and a
    # peer's instant procedure rejected by the central (Core 5.2, Vol 6,
    # Part B, 5.3)
    marks['concurrent'] = Ac(C, 'PING_REQ')
    Ac(P, 'LENGTH_REQ', LENGTH)
    Ac(C, 'LENGTH_RSP', LENGTH)
    Ac(P, 'PING_RSP')
    Ac(C, 'CONNECTION_PARAM_REQ', CONN_PARAM)
    Ac(P, 'PING_REQ')
    Ac(C, 'PING_RSP')
    Ac(P, 'PHY_REQ', b'\x02\x02')
    Ac(C, 'REJECT_EXT_IND', bytes([OP['PHY_REQ'], 0x23]))
    Ac(P, 'CONNECTION_PARAM_RSP', CONN_PARAM)
    Ac(C, 'CONNECTION_UPDATE_IND', conn_update(150))
    Ac(C, 'PHY_REQ', b'\x01\x01')
    Ac(P, 'PHY_RSP', b'\x01\x01')
    Ac(C, 'PHY_UPDATE_IND', phy_update(1, 0, 0))          # P->C unchanged, no instant
    A(C, 3, ctrl(0x3d, b'\x01\x02'))                     # unknown opcode
    # L2CAP: complete, fragmented with a NACK and a retransmission, CTE
    marks['l2cap'] = pc.count + 1
    smp = bytes([0x01, 0x03, 0x00, 0x01, 0x10, 0x07, 0x07])
    A(C, 2, l2cap(6, smp))                               # SMP Pairing Request
    sig = bytes([0x12, 2]) + struct.pack('<HHHHH', 8, 6, 40, 0, 300)
    A(P, 2, l2cap(5, sig)[:6])                           # start
    A(C, 1, b'', nack=True)                              # NACK
    A(P, 2, l2cap(5, sig)[:6], retransmit=True)          # retransmitted start
    A(C, 1, b'')
    A(P, 1, l2cap(5, sig)[6:12])                         # continuation
    A(C, 1, b'', md=1)
    A(P, 1, l2cap(5, sig)[12:], cte=0x14)                # last, with CTEInfo
    A(C, 1, b'')
    A(P, 1, b'\x01\x02\x03')                             # missing start
    A(C, 2, l2cap(4, b'\x0a\x03\x00', length=4)[:6])     # start, 2 remaining
    A(C, 1, b'\x01\x02\x03\x04\x05')                     # longer than remaining: missing start
    A(C, 3, ctrl(OP['PING_REQ']))                        # PING_REQ ...
    A(P, 1, b'', nack=True)                              # ... not acknowledged
    A(C, 3, ctrl(OP['PING_REQ']), retransmit=True)       # retransmitted control PDU
    A(P, 3, ctrl(OP['PING_RSP']))
    # Connected isochronous PDUs on the CIS created by LL_CIS_IND
    marks['cisdata'] = pc.count + 1
    RF(rf(22, 4), ll(CIS1, data_pdu(0, b'\x01\x02\x03', sn=0, nesn=0)))
    RF(rf(22, 5), ll(CIS1, data_pdu(1 | 0x10 | 0x20, b'\x04\x05', sn=1, nesn=1)))
    RF(rf(22, 4), ll(CIS1, data_pdu(2, b'\x06')))
    RF(rf(22, 5), ll(CIS1, data_pdu(3, b'\x07\x08')))
    RF(rf(22, 4), ll(0x3c3c5a02, data_pdu(0, b'\x09')))                   # CIS without LL_CIS_IND
    A(C, 3, ctrl(OP['TERMINATE_IND'], b'\x13'))

    # ---------------- 6. Nordic BLE: event counter, instants
    CN, CN_CRC = 0x4a4b4c4d, 0x00abcd
    cn = Conn(CN, CN_CRC)
    marks['nordic'] = pc.count + 1
    NO(nordic(ll(AA_ADV, adv_pdu(0x00, addr(0x50) + AD_NAME, chsel=1)), True, 37, 0))
    NO(nordic(ll(AA_ADV, ext_adv(0x07, 0x19, addr(0x50) + adi(30, 1) + auxptr(), AD_NAME)), True, 3, 0, aux=0, phy=1))
    NO(nordic(ll(AA_ADV, ext_adv(0x07, 0x08, adi(30, 1), AD_FLAGS)), True, 3, 0, aux=1, phy=1))
    NO(nordic(ll(AA_ADV, adv_pdu(0x05, connect_payload(addr(0x51), addr(0x50), CN, CN_CRC), chsel=1)), True, 38, 0))
    ev = [0]

    def N(d, llid, payload, step=True, **kw):
        if step:
            ev[0] += 1
        return NO(nordic(ll(CN, cn.pdu(d, llid, payload, **kw), init=CN_CRC), False, 8, ev[0],
                         central=(d == C)))

    def Nev(d, payload=b''):   # empty PDU, new event
        return N(d, 1, payload)
    N(C, 1, b'')
    N(P, 1, b'', step=False)
    marks['nordic_update'] = N(C, 3, ctrl(OP['CONNECTION_UPDATE_IND'], conn_update(ev[0] + 3)))
    N(P, 1, b'', step=False)
    Nev(C); N(P, 1, b'', step=False)
    Nev(C)                                             # event == instant: complete, parameters applied
    N(P, 3, ctrl(OP['PING_REQ']), step=False)
    N(C, 3, ctrl(OP['PING_RSP']), step=False)
    N(C, 3, ctrl(OP['CHANNEL_MAP_IND'], chmap_ind(ev[0] + 2)))
    Nev(C); Nev(C)
    N(C, 3, ctrl(OP['PHY_REQ'], b'\x03\x03'))
    N(P, 3, ctrl(OP['PHY_RSP'], b'\x03\x03'), step=False)
    N(C, 3, ctrl(OP['PHY_UPDATE_IND'], phy_update(2, 2, ev[0] + 3)))
    Nev(C); Nev(C); Nev(C)
    N(C, 3, ctrl(OP['CONNECTION_PARAM_REQ'], CONN_PARAM))
    N(P, 3, ctrl(OP['CONNECTION_PARAM_RSP'], CONN_PARAM), step=False)
    N(C, 3, ctrl(OP['CONNECTION_UPDATE_IND'], conn_update(ev[0] + 2)))
    Nev(C); Nev(C)
    N(P, 3, ctrl(OP['PHY_REQ'], b'\x01\x01'))
    N(C, 3, ctrl(OP['PHY_UPDATE_IND'], phy_update(1, 1, ev[0] + 2)), step=False)
    Nev(C); Nev(C)
    N(P, 3, ctrl(OP['CONNECTION_PARAM_REQ'], CONN_PARAM))
    N(C, 3, ctrl(OP['CONNECTION_UPDATE_IND'], conn_update(ev[0] + 2)), step=False)
    Nev(C); Nev(C)
    N(P, 3, ctrl(OP['MIN_USED_CHANNELS_IND'], b'\x01\x02'))
    N(C, 3, ctrl(OP['CHANNEL_MAP_IND'], chmap_ind(ev[0] + 2)), step=False)
    Nev(C); Nev(C)
    NO(nordic(ll(CN, cn.pdu(C, 2, l2cap(4, b'\x0a\x03\x00')), init=CN_CRC), False, 8, ev[0] + 1, central=True, mic=True))
    NO(nordic(ll(CN, cn.pdu(P, 2, l2cap(4, b'\x0b\x01\x02')), init=CN_CRC), False, 8, ev[0] + 1, mic=True))
    return pc, marks


# Payload of every control opcode, for the out-of-sequence runs
CTRL_PAYLOAD = {
    'CONNECTION_UPDATE_IND': conn_update(10), 'CHANNEL_MAP_IND': chmap_ind(10),
    'TERMINATE_IND': b'\x13', 'ENC_REQ': b'\x01' * 22, 'ENC_RSP': b'\x02' * 12,
    'UNKNOWN_RSP': b'\x55', 'FEATURE_REQ': FEATURES, 'FEATURE_RSP': FEATURES,
    'VERSION_IND': b'\x0e\x59\x00\x01\x00', 'REJECT_IND': b'\x06',
    'PERIPHERAL_FEATURE_REQ': FEATURES, 'CONNECTION_PARAM_REQ': CONN_PARAM,
    'CONNECTION_PARAM_RSP': CONN_PARAM, 'REJECT_EXT_IND': b'\x0f\x1a',
    'LENGTH_REQ': LENGTH, 'LENGTH_RSP': LENGTH, 'PHY_REQ': b'\x01\x01', 'PHY_RSP': b'\x01\x01',
    'PHY_UPDATE_IND': phy_update(1, 1, 10), 'MIN_USED_CHANNELS_IND': b'\x01\x02',
    'CTE_REQ': b'\x45', 'PERIODIC_SYNC_IND': SYNC_IND, 'CLOCK_ACCURACY_REQ': b'\x01',
    'CLOCK_ACCURACY_RSP': b'\x01', 'CIS_REQ': CIS_REQ, 'CIS_RSP': CIS_RSP,
    'CIS_IND': b'\x01\x5a\x3c\x3c' + b'\x00' * 11, 'CIS_TERMINATE_IND': b'\x01\x02\x13',
    'POWER_CONTROL_REQ': b'\x01\x02\x08', 'POWER_CONTROL_RSP': b'\x03\x02\x08\x04',
    'POWER_CHANGE_IND': b'\x01\x02\x7f\x7e', 'SUBRATE_REQ': struct.pack('<HHHHH', 1, 4, 2, 1, 300),
    'SUBRATE_IND': struct.pack('<HHHHH', 2, 100, 1, 1, 300), 'CHANNEL_REPORTING_IND': b'\x01\x05\x0a',
    'CHANNEL_STATUS_IND': b'\x55' * 10, 'PERIODIC_SYNC_WR_IND': SYNC_WR_IND,
    'CS_SEC_REQ': CS_SEC, 'CS_SEC_RSP': CS_SEC, 'CS_CAPABILITIES_REQ': CS_CAPS,
    'CS_CAPABILITIES_RSP': CS_CAPS, 'CS_CONFIG_REQ': CS_CONFIG_REQ, 'CS_CONFIG_RSP': b'\x01',
    'CS_REQ': CS_REQ, 'CS_RSP': CS_RSP, 'CS_IND': CS_IND, 'CS_TERMINATE_REQ': CS_TERM,
    'CS_TERMINATE_RSP': CS_TERM, 'CS_CHANNEL_MAP_IND': CS_CHMAP,
}


MAL = {}


def build_malformed():
    import random
    pc = Pcapng()
    LE = lambda b: pc.add(LT_LE_LL, b)
    RF = lambda h, b: pc.add(LT_LE_LL_PHDR, h + b)
    NO = lambda b: pc.add(LT_NORDIC, b)

    def new_conn(aa, crc):
        RF(rf(0), ll(AA_ADV, adv_pdu(0x05, connect_payload(addr(0x60), addr(0x61), aa, crc), chsel=1)))
        c = Conn(aa, crc)

        def send(d, name, payload=None, raw=None, **kw):
            body = raw if raw is not None else ctrl(OP[name], CTRL_PAYLOAD.get(name, b'') if payload is None else payload)
            return RF(rf(30, {C: 2, P: 3, 0: 0}[d]), ll(aa, c.pdu(d, 3, body, **kw), init=crc))
        return send

    MAL['out_of_sequence'] = pc.count + 1
    # Every control PDU out of sequence: responses without a request,
    # requests and indications from the wrong role, then the same with
    # every procedure left open (overlapping procedures).
    for order in ((C, P), (P, C), (0,)):
        send = new_conn(0x33000000 + order[0], 0x123456)
        for d in order:
            for name in OP:
                if not name.endswith('_REQ') and not name.endswith('_IND'):
                    send(d, name)
        for d in order:
            for name in OP:
                send(d, name)
    MAL['overlap_collision_conflict'] = pc.count + 1
    # The second pass finds no procedure for an overlapping start
    send = new_conn(0x34000001, 0x123456)
    send(C, 'FEATURE_REQ')
    send(C, 'VERSION_IND')
    # Incompatible collision: the peripheral starts an instant procedure
    # after answering the central's (frames[1] set)
    send = new_conn(0x34000002, 0x123456)
    send(C, 'CONNECTION_PARAM_REQ')
    send(P, 'CONNECTION_PARAM_RSP')
    send(P, 'PHY_REQ')
    # Wrong conflict resolution: the central continues its PHY update
    # while the peripheral's connection parameter request is open
    send = new_conn(0x34000003, 0x123456)
    send(P, 'CONNECTION_PARAM_REQ')
    send(C, 'PHY_REQ')
    send(P, 'PHY_RSP')
    send(C, 'PHY_UPDATE_IND')
    # Encryption start PDUs in the wrong place of the procedure
    send = new_conn(0x34000004, 0x123456)
    send(C, 'ENC_REQ')
    send(P, 'ENC_RSP')
    send(C, 'START_ENC_RSP')
    send(P, 'START_ENC_RSP')
    send(C, 'PAUSE_ENC_REQ')
    send(C, 'PAUSE_ENC_RSP')
    # LL_UNKNOWN_RSP with nothing to answer, unknown direction
    send = new_conn(0x34000005, 0x123456)
    send(C, 'UNKNOWN_RSP')
    send(0, 'UNKNOWN_RSP')
    send(P, 'SUBRATE_REQ')
    send(0, 'SUBRATE_IND')
    send(0, 'SUBRATE_IND')

    MAL['phy_update_uninit'] = pc.count + 1
    # Nordic: LL_PHY_UPDATE_IND without PHY changes passes an
    # uninitialised instant to the procedure tracking
    CN, CN_CRC = 0x4a4b4c4e, 0x00abcd
    NO(nordic(ll(AA_ADV, adv_pdu(0x05, connect_payload(addr(0x51), addr(0x50), CN, CN_CRC))), True, 37, 0))
    cn = Conn(CN, CN_CRC)
    NO(nordic(ll(CN, cn.pdu(C, 3, ctrl(OP['PHY_REQ'], b'\x01\x01')), init=CN_CRC), False, 8, 1, central=True))
    NO(nordic(ll(CN, cn.pdu(P, 3, ctrl(OP['PHY_RSP'], b'\x01\x01')), init=CN_CRC), False, 8, 1))
    NO(nordic(ll(CN, cn.pdu(C, 3, ctrl(OP['PHY_UPDATE_IND'], phy_update(0, 0, 0))), init=CN_CRC), False, 8, 2, central=True))
    NO(nordic(ll(CN, cn.pdu(C, 3, ctrl(OP['PING_REQ'])), init=CN_CRC), False, 8, 3, central=True))
    NO(nordic(ll(CN, cn.pdu(P, 3, ctrl(OP['PING_RSP'])), init=CN_CRC), False, 8, 3))

    MAL['aa_illegal_coded_short'] = pc.count + 1
    # AccessAddress illegal (offenses without a reference address)
    RF(rf(0, aa_off=3), ll(AA_ADV, adv_pdu(0x02, addr(0x01) + AD_NAME)))
    # Coded PHY, CRC not checked at capture: the CRC is calculated from
    # the coding indicator on
    RF(rf(39, phy=2, crc_checked=False), ll(AA_ADV, adv_pdu(0x02, addr(0x01) + AD_NAME), ci=0))
    # AD structure longer than the PDU
    LE(ll(AA_ADV, adv_pdu(0x02, addr(0x01) + b'\x20\x09AB')))
    # Short Sync Info (tvb_get_uint32 at offset + 9 on the first pass only)
    LE(ll(AA_ADV, ext_adv(0x07, 0x20, b'\x00' * 6, b'')))
    # Truncated PDUs
    for n in (5, 6, 8, 12, 20, 30):
        LE(ll(AA_ADV, adv_pdu(0x05, connect_payload(addr(0x10), addr(0x11), 0x50650000, 1)))[:n])
    LE(ll(AA_ADV, ext_adv(0x07, 0x7f, b'\x00' * 10, b''))[:16])
    LE(ll(0x50654321, data_pdu(3, ctrl(OP['CIS_REQ'], CIS_REQ[:10]))))
    # From btle_ea_had_truncated.py: snapshot length cuts the
    # Host Advertising Data
    p1 = rf(1, 1, 0) + ll(AA_ADV, ext_adv(0x07, 0x19, addr(0x01) + adi(5, 9) + b'\x05\x10\x00', AD_FLAGS + ad(0x09, b'ABCD')))
    for extra in range(4):
        pc.add(LT_LE_LL_PHDR, p1, caplen=10 + 4 + 2 + 1 + 1 + 11 + extra)
    RF(rf(1, 1, 1), ll(AA_ADV, ext_adv(0x07, 0x08, adi(5, 9), AD_NAME)))

    MAL['had_middle_no_adva'] = pc.count + 1
    # Middle AUX_CHAIN_IND without AdvA: its source is the AdvA of the
    # AUX_ADV_IND in the first pass only
    ADI = adi(15, 3)
    RF(rf(5, 1, 0), ll(AA_ADV, ext_adv(0x07, 0x19, addr(0x20) + ADI + auxptr(), AD_FLAGS)))
    RF(rf(5, 1, 1), ll(AA_ADV, ext_adv(0x07, 0x18, ADI + auxptr(), AD_NAME[:4])))
    RF(rf(5, 1, 1), ll(AA_ADV, ext_adv(0x07, 0x08, ADI, AD_NAME[4:])))

    MAL['random'] = pc.count + 1
    # Random PDUs, in the style of btle_fuzz_ctrl.py
    rnd = random.Random(1)
    CF, CF_CRC = 0x35000001, 0x654321
    RF(rf(0), ll(AA_ADV, adv_pdu(0x05, connect_payload(addr(0x70), addr(0x71), CF, CF_CRC))))
    for i in range(600):
        r = rnd.random()
        if r < 0.6:
            llid = rnd.choice([0, 1, 2, 3, 3, 3])
            hdr = llid | rnd.choice([0, 4, 8, 12, 0x10, 0x20])
            if llid == 3:
                body = bytes([rnd.randrange(0, 0x40)]) + bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 40)))
            else:
                body = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 30)))
            ln = len(body) if rnd.random() < 0.9 else rnd.randrange(256)
            pkt = struct.pack('<I', CF) + bytes([hdr, ln]) + body + b'\x00\x00\x00'
            RF(rf(5, rnd.choice([0, 2, 3, 4, 5, 6]), crc_checked=rnd.random() < 0.5), pkt)
        else:
            body = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 80)))
            pkt = struct.pack('<I', rnd.choice([AA_ADV, CF, 0x00411234])) + \
                bytes([rnd.choice([0, 1, 2, 3, 4, 5, 6, 7, 7, 7, 8, 9]) | (rnd.randrange(4) << 6), len(body)]) + body + b'\x00\x00\x00'
            RF(rf(rnd.choice([0, 1, 12, 39]), rnd.choice([0, 1, 6]), rnd.randrange(4), phy=rnd.choice([0, 0, 1, 2])), pkt)
    return pc


def build_repro():
    '''LL_PHY_UPDATE_IND with no PHY change on a Nordic BLE capture (event
    counter valid): the uninitialised item_value is stored as the instant.'''
    CN, CN_CRC = 0x4a4b4c4e, 0x00abcd
    cn = Conn(CN, CN_CRC)
    pkts = [nordic(ll(AA_ADV, adv_pdu(0x05, connect_payload(addr(0x51), addr(0x50), CN, CN_CRC))), True, 37, 0),
            nordic(ll(CN, cn.pdu(C, 3, ctrl(OP['PHY_REQ'], b'\x01\x01')), init=CN_CRC), False, 8, 1, central=True),
            nordic(ll(CN, cn.pdu(P, 3, ctrl(OP['PHY_RSP'], b'\x01\x01')), init=CN_CRC), False, 8, 1),
            nordic(ll(CN, cn.pdu(C, 3, ctrl(OP['PHY_UPDATE_IND'], phy_update(0, 0, 0))), init=CN_CRC), False, 8, 2, central=True),
            nordic(ll(CN, cn.pdu(C, 1, b''), init=CN_CRC), False, 8, 3, central=True)]
    with open(OUT + '/btle_phy_update_uninit.pcap', 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, LT_NORDIC))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)


def build_pcap():
    '''Nordic BLE in a pcap file: no interface id, so the default one.'''
    with open(OUT + '/btle-coverage-nordic.pcap', 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, LT_NORDIC))
        for i, p in enumerate([nordic(ll(AA_ADV, adv_pdu(0x00, addr(0x50) + AD_NAME)), True, 37, 0)]):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)

if __name__ == '__main__':
    pc, marks = build_main()
    pc.write(OUT + '/btle-coverage.pcapng')
    for k, v in marks.items():
        print(k, v)
    build_malformed().write(OUT + '/btle-coverage-malformed.pcapng')
    build_pcap()
    build_repro()
    for k, v in MAL.items():
        print('malformed', k, v)
