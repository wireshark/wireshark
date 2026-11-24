#!/usr/bin/env python3
# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Helpers shared by the UBX, Galileo I/NAV and GPS L1 LNAV generators.

Everything is built with struct; nothing comes from a real network.
Frames are written as a classic pcap with link type 252
(WTAP_ENCAP_WIRESHARK_UPPER_PDU, "Exported PDU"), which names the UBX
dissector ("ubx") or one of the GNSS sub-dissectors ("ubx_gal_inav",
"ubx_gps_l1") explicitly: UBX has no port, heuristic or Decode As entry.
"""
import os
import sys
import random
import struct

UBX_GNSS = {'gps': 0, 'sbas': 1, 'galileo': 2, 'beidou': 3, 'imes': 4,
            'qzss': 5, 'glonass': 6}


def write_pcap(path, frames, linktype=252):
    """frames: list of bytes (or (bytes, caplen) tuples)."""
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)) + fr)


def exp_pdu(name, payload):
    n = name.encode() + b'\0'
    n += b'\0' * ((4 - len(n) % 4) % 4)
    return struct.pack('>HH', 12, len(n)) + n + struct.pack('>HH', 0, 0) + payload


def ubx_frame(cid, payload, bad_chk=False, length=None):
    """cid is the 16 bit class/id (class in the high octet)."""
    ln = len(payload) if length is None else length
    body = struct.pack('>H', cid) + struct.pack('<H', ln) + payload
    a = b = 0
    for x in body:
        a = (a + x) & 0xff
        b = (b + a) & 0xff
    if bad_chk:
        a ^= 0x55
    return b'\xb5\x62' + body + bytes([a, b])


def setf(buf, off, n, mask, val):
    """Set the masked bits of the big endian n octet field at off, the way
    the dissector reads it with ENC_BIG_ENDIAN."""
    cur = int.from_bytes(buf[off:off + n], 'big')
    shift = (mask & -mask).bit_length() - 1
    cur = (cur & ~mask) | ((val << shift) & mask)
    buf[off:off + n] = cur.to_bytes(n, 'big')


def sfrbx(gnss, svid, words_le, version=2, sigid=0, freqid=0, chn=0,
          numwords=None, resv=0):
    """UBX-RXM-SFRBX payload; words_le is the data (multiple of 4 octets)."""
    nw = len(words_le) // 4 if numwords is None else numwords
    if version == 1:
        hdr = struct.pack('<BBBBBBBB', gnss, svid, resv, freqid, nw, resv, version, resv)
    else:
        hdr = struct.pack('<BBBBBBBB', gnss, svid, sigid, freqid, nw, chn, version, resv)
    return hdr + words_le


# ---- Galileo E1-B I/NAV page (32 octets: even page, odd page) ----

def gal_page(rnd, inav_type=1, even_alert=False, odd_alert=False, hkroot=0,
             mack=0, sar_start=0, sar_long=0, sar_data=0, zero=False):
    p = bytearray(32) if zero else bytearray(rnd.getrandbits(8) for _ in range(32))
    # even page
    setf(p, 0, 1, 0x80, 0)
    setf(p, 0, 1, 0x40, 1 if even_alert else 0)
    setf(p, 0, 1, 0x3f, inav_type)
    # odd page
    setf(p, 16, 1, 0x80, 1)
    setf(p, 16, 1, 0x40, 1 if odd_alert else 0)
    setf(p, 18, 4, 0x3fc00000, hkroot)
    setf(p, 18, 8, 0x003fffffffc00000, mack)
    setf(p, 23, 4, 0x20000000, sar_start)
    setf(p, 23, 4, 0x10000000, sar_long)
    setf(p, 23, 4, 0x0fffff00, sar_data)
    return bytes(p)


def gal_words_le(page):
    page = page + b'\0' * (-len(page) % 4)
    return b''.join(struct.pack('<I', struct.unpack('>I', page[i:i + 4])[0])
                    for i in range(0, len(page), 4))


def gal_sfrbx(page, svid, version=2):
    return sfrbx(2, svid, gal_words_le(page), version=version, sigid=1)


# ---- GPS L1 LNAV subframe (10 words of 30 bits, little endian 32 bit) ----

def gps_words(rnd, subframe, tow=1234, preamble=0x8b, alert=0, spoof=0,
              integrity=0):
    w = [rnd.getrandbits(30) for _ in range(10)]
    w[0] = (preamble << 22) | (rnd.getrandbits(14) << 8) | (integrity << 7) | (rnd.getrandbits(1) << 6) | rnd.getrandbits(6)
    w[1] = (tow << 13) | (alert << 12) | (spoof << 11) | (subframe << 8) | (rnd.getrandbits(2) << 6) | rnd.getrandbits(6)
    return b''.join(struct.pack('<I', x & 0x3fffffff) for x in w)


def gps_sfrbx(words, svid, version=2):
    return sfrbx(0, svid, words, version=version, sigid=0)


def outdir():
    return os.path.abspath(os.path.dirname(sys.argv[0]))
