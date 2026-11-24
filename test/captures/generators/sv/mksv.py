#!/usr/bin/env python3
# Generates test/captures/sv_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SV (IEC 61850-9-2 Sampled Values) coverage captures.
Usage: mksv.py <outdir>.  All packets are synthetic."""
import struct
import sys
import os
from berlib import gz, MAC_A, tlv, write_pcap

SVMAC = bytes.fromhex('010ccd040001')

def asdu(svid=b'MU01', datset=None, smpcnt=1, confrev=1, refrtm=None, smpsynch=None,
         smprate=None, seqdata=None, smpmod=None, gmid=None):
    b = tlv(0x80, svid)
    if datset is not None: b += tlv(0x81, datset)
    b += tlv(0x82, struct.pack('>H', smpcnt))
    b += tlv(0x83, struct.pack('>I', confrev))
    if refrtm is not None: b += tlv(0x84, refrtm)
    if smpsynch is not None: b += tlv(0x85, bytes([smpsynch]))
    if smprate is not None: b += tlv(0x86, struct.pack('>H', smprate))
    b += tlv(0x87, seqdata if seqdata is not None else b'')
    if smpmod is not None: b += tlv(0x88, struct.pack('>H', smpmod))
    if gmid is not None: b += tlv(0x89, gmid)
    return tlv(0x30, b)

def savpdu(asdus, noasdu=None):
    n = len(asdus) if noasdu is None else noasdu
    return tlv(0x60, tlv(0x80, struct.pack('>H', n)) + tlv(0xa2, b''.join(asdus)))

def sv(pdu, appid=0x4000, res1=0, res2=0, length=None):
    if length is None: length = 8 + len(pdu)
    return struct.pack('>HHHH', appid, length, res1, res2) + pdu

def frame(svb, vlan=None, etype=0x88ba):
    if vlan is not None:
        return SVMAC + MAC_A + struct.pack('>HHH', 0x8100, vlan, etype) + svb
    return SVMAC + MAC_A + struct.pack('>H', etype) + svb

def meas(vals):
    """vals: list of (value, quality)"""
    return b''.join(struct.pack('>iI', v, q) for v, q in vals)

def utc(sec=1700000000, frac=0x800000, extra=0x0a):
    return struct.pack(">I", sec) + bytes([(frac >> 16) & 0xff, (frac >> 8) & 0xff, frac & 0xff, extra])

# 8 channels as in IEC 61850-9-2LE: 4 currents, 4 voltages
def ch8(base, q=0):
    return meas([(base + i * 100, q) for i in range(8)])

def main(out):
    gm = bytes.fromhex('00 0c 29 ff fe 12 34 56'.replace(' ', ''))
    main_frames = []
    # 1: all optional fields, one ASDU, gmid with EUI-64 FFFE marker
    main_frames.append(frame(sv(savpdu([asdu(b'MU01', b'MU01/LLN0$dsSV', 100, 7, utc(), 2, 4000, ch8(1000), 0, gm)]))))
    # 2: simulated bit, three smpSynch/smpMod values, four ASDUs in one pdu
    main_frames.append(frame(sv(savpdu([
        asdu(b'MU01', None, 101, 7, None, 0, None, ch8(2000), 1),
        asdu(b'MU01', None, 102, 7, None, 1, None, ch8(3000), 2),
        asdu(b'MU01', None, 103, 7, None, 2, None, ch8(4000), 0),
        asdu(b'MU01', None, 104, 7, None, 3, None, ch8(5000), 3)]), res1=0x8000, appid=0x4001)))
    # 3: VLAN tagged, quality bits: every bit set and some values of validity/source
    qs = [0x00000000, 0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000008, 0x00000010,
          0x00000020, 0x00000040, 0x00000080, 0x00000100, 0x00000200, 0x00000400, 0x00000800,
          0x00001000, 0x00002000]
    main_frames.append(frame(sv(savpdu([asdu(b'MU02', b'ds', 5, 1, utc(1700000001, 0x100000, 0), 1, 80,
                                       meas([(-i * 1000, q) for i, q in enumerate(qs[:8])]), 1)]),
                                appid=0x4002), vlan=0x8000 | 4))
    main_frames.append(frame(sv(savpdu([asdu(b'MU02', None, 6, 1, None, None, None,
                                       meas([(i * 1000, q) for i, q in enumerate(qs[8:])]))]),
                                appid=0x4002), vlan=0x8000 | 4))
    # 5: more than eight measurement pairs in seqData (extra ones are not stored in the tap data)
    main_frames.append(frame(sv(savpdu([asdu(b'MU03', None, 7, 2, None, None, None, ch8(7) + ch8(70) + ch8(700))]), appid=0x4003)))
    # 6: seqData whose length is not a multiple of 8, empty seqData
    main_frames.append(frame(sv(savpdu([asdu(b'MU04', None, 8, 2, None, None, None, ch8(9)[:20]),
                                        asdu(b'MU04', None, 9, 2, None, None, None, b'')]), appid=0x4004)))
    # 7: two savPdus in one frame, the second with gmid without the FFFE marker
    main_frames.append(frame(sv(savpdu([asdu(b'MU05', None, 1, 3, None, None, None, ch8(1))]) +
                                savpdu([asdu(b'MU06', None, 2, 3, None, 1, None, ch8(2), None,
                                             bytes.fromhex('0011223344556677'))]), appid=0x4005)))
    # 8: noASDU 0, no ASDU at all
    main_frames.append(frame(sv(savpdu([], 0), appid=0x4006)))
    # 9: frame padded to the Ethernet minimum (trailer after the SV length)
    main_frames.append(frame(sv(savpdu([asdu(b'MU07', None, 3, 3, None, None, None, b'')]), appid=0x4007) + b'\0' * 12))
    # 10: unusual APPID, large smpCnt and confRev
    main_frames.append(frame(sv(savpdu([asdu(b'MU08', b'Dataset$X', 65535, 0xffffffff, utc(0, 0, 0), 2, 65535,
                                           ch8(-1), 2, gm)]), appid=0xffff)))
    write_pcap(os.path.join(out, 'sv-coverage.pcap'), main_frames)

    mal = []
    # 1: gmIdentity of 3 bytes (reproducer of the FT_BYTES assert fixed on the branch)
    mal.append(frame(sv(savpdu([asdu(b'sv1', None, 1, 1, None, 1, None, b'\0' * 8, None, b'\x01\x02\x03')]))))
    # 2: refrTm of 4 bytes (malformed UtcTime)
    mal.append(frame(sv(savpdu([asdu(b'sv1', None, 1, 1, b'\0\0\0\1', None, None, b'\0' * 8)]))))
    # 3: gmIdentity of 9 bytes after a short refrTm
    mal.append(frame(sv(savpdu([asdu(b'sv1', None, 1, 1, b'\0' * 9, None, None, b'\0' * 8, None, b'\0' * 9)]))))
    # 4: payload that is not BER (zero-byte pdu: first byte is an end-of-contents tag)
    mal.append(frame(sv(b'\x00\x00\x00\x00')))
    # 5: header only
    mal.append(frame(struct.pack('>HHHH', 0x4000, 8, 0, 0)))
    # 6: truncated header
    mal.append(frame(struct.pack('>HH', 0x4000, 8)))
    # 7: SV length longer than the frame, truncated pdu
    mal.append(frame(sv(savpdu([asdu(b'sv1', None, 1, 1, None, None, None, ch8(1))])[:40], length=200)))
    # 8: seqASDU holds a primitive element
    mal.append(frame(sv(tlv(0x60, tlv(0x80, b'\x00\x01') + tlv(0xa2, tlv(0x04, b'abc'))))))
    # 9: sampled value choice with the wrong tag
    mal.append(frame(sv(tlv(0x61, tlv(0x80, b'\x00\x01')))))
    write_pcap(os.path.join(out, 'sv-coverage-malformed.pcap'), mal)

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    main(out)
    gz(os.path.join(out, 'sv-coverage.pcap'), os.path.join(out, 'sv_coverage.pcap.gz'))
