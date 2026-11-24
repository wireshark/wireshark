#!/usr/bin/env python3
# Generates test/captures/drdynvc_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic RDP dynamic virtual channel (MS-RDPEDYC) captures for
# packet-rdp_drdynvc.c.  Usage: mkdrdynvc.py <outdir> [-v]
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from rdplib import Cap, Session
from dvclib import (
    caps_req, caps_resp, close, create_req, create_resp, data, data_first, softsync_req,
    softsync_resp, zmulti, zseg_literals, zseg_raw, zseg_with_match, zsingle,
)

VERBOSE = '-v' in sys.argv
OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
MARKS = []
CAPS = 'Microsoft::Windows::RDS::'


def mark(cap, title):
    MARKS.append((len(cap.frames) + 1, title))


def finish(cap, name):
    cap.write(os.path.join(OUT, name))
    if VERBOSE:
        print(name, len(cap.frames), 'frames')
        for i, (n, t) in enumerate(MARKS):
            end = MARKS[i + 1][0] - 1 if i + 1 < len(MARKS) else len(cap.frames)
            print('  %d-%d: %s' % (n, end, t))


# payloads understood by the channel dissectors
CLIP_READY = struct.pack('<HHI', 1, 0, 0)                                # cliprdr monitor ready
CLIP_LIST = struct.pack('<HHI', 2, 0, 36) + struct.pack('<I', 1) + b'CF_TEXT'.ljust(32, b'\0')
RAIL_HS = struct.pack('<HHI', 5, 8, 19041)                               # rail handshake
SND_TRAIN = struct.pack('<BBHHH', 6, 0, 4, 0x1234, 0)                    # rdpsnd training
DR_ANN = struct.pack('<HHHHI', 0x4472, 0x496e, 1, 12, 7)                 # rdpdr server announce
EGFX_START = zsingle(zseg_raw(struct.pack('<HHIII', 0x000b, 0, 16, 1000, 1)))   # EGFX start frame in a ZGFX segment
ECAM_SEL = struct.pack('<BBB', 1, 0x03, 1) + b'\0\0\0\0'                 # ecam select version request (stream-like body)
EAR_NONE = struct.pack('<IIIIQ', 0x4eacc3c8, 0, 1, 0, 0x1234)       # RDPEAR header without payload


def build_main():
    cap = Cap()
    s = Session(cap, 50000, ['drdynvc'], msgchan=True)
    S = lambda p, **k: s.chan('drdynvc', p, False, **k)      # server -> client
    C = lambda p, **k: s.chan('drdynvc', p, True, **k)       # client -> server

    mark(cap, 'capabilities (versions 1, 2, 3) and channel creation for every known channel type, 1/2/4 octet channel ids')
    S(caps_req(3))
    C(caps_resp(3))
    S(caps_req(1))
    S(caps_req(2, (1, 2, 3, 4)))
    chans = [(1, CAPS + 'Graphics', 0, 0), (2, 'rail', 0, 1), (3, 'cliprdr', 0, 2), (4, 'rdpdr', 0, 3),
             (5, 'AUDIO_PLAYBACK_DVC', 0, 0), (6, CAPS + 'AuthRedirection', 0, 0),
             (7, 'RDCamera_Device_Enumerator', 0, 0), (300, 'RDCamera_Device_Webcam1', 1, 0),
             (70000, CAPS + 'Telemetry', 2, 0), (9, 'no-such-channel', 0, 0), (10, CAPS + 'RAIL', 0, 0),
             (11, 'AUDIO_PLAYBACK_LOSSY_DVC', 0, 0), (12, 'AUDIO_INPUT', 0, 0), (13, CAPS + 'DisplayControl', 0, 0),
             (14, CAPS + 'Input', 0, 0), (15, CAPS + 'Geometry::v08.01', 0, 0),
             (16, CAPS + 'Video::Control::v08.01', 0, 0), (17, CAPS + 'Video::Data::v08.01', 0, 0)]
    for cid, name, cb, pri in chans:
        S(create_req(cid, name, cb, pri))
        C(create_resp(cid, 0, cb))
    C(create_resp(99, 0))                                   # response for a channel never created
    C(create_resp(9, -1))                                   # a failed channel creation (status HRESULT)

    mark(cap, 'single data PDUs for every channel type, both directions, and data for an unknown channel id')
    S(data(1, EGFX_START))
    S(data(2, RAIL_HS))
    S(data(3, CLIP_READY))
    C(data(3, CLIP_READY))
    S(data(4, DR_ANN))
    S(data(5, SND_TRAIN))
    S(data(7, ECAM_SEL))
    S(data(300, ECAM_SEL, cb=1))
    S(data(70000, b'telemetry data', cb=2))
    S(data(9, b'raw data of an unknown channel type'))
    S(data(99, b'data for a channel that was never created'))

    mark(cap, 'reassembly: data first + data PDUs (length fields of 1, 2 and 4 octets), both directions')
    lst = CLIP_LIST
    S(data_first(3, len(lst), lst[:16]))
    S(data(3, lst[16:30]))
    S(data(3, lst[30:]))
    C(data_first(3, len(lst), lst[:20], lb=1))
    C(data(3, lst[20:]))
    S(data_first(3, len(lst), lst[:10], lb=2))
    S(data(3, lst[10:]))
    S(data_first(9, 20, b'x' * 20))                          # single-packet DATA_FIRST on an unknown channel type
    S(data_first(3, len(CLIP_READY), CLIP_READY))             # single-packet DATA_FIRST for cliprdr
    S(data_first(1, len(EGFX_START), EGFX_START))
    S(data_first(2, len(RAIL_HS), RAIL_HS))
    S(data_first(5, len(SND_TRAIN), SND_TRAIN))
    S(data_first(4, len(DR_ANN), DR_ANN))
    S(data_first(7, len(ECAM_SEL), ECAM_SEL))
    S(data_first(99, 5, b'abcde'))                           # DATA_FIRST for a channel that was never created
    S(data_first(3, 100, b'a' * 8))                            # a reassembly that is restarted ...
    S(data_first(3, len(lst), lst[:16]))                       # ... by the next DATA_FIRST
    S(data(3, lst[16:]))
    S(data_first(3, 100, b'a' * 8))                            # an unfinished reassembly ...
    S(data_first(3, len(CLIP_READY), CLIP_READY))              # ... dropped by a single-packet DATA_FIRST
    S(bytes([0xb0, 0x05]))                                           # unknown PDU type
    S(bytes([0x00, 0x05]))
    mark(cap, 'reassembly of every channel type (end of the reassembly dispatches to the channel dissector)')
    for cid, p in ((1, EGFX_START), (2, RAIL_HS), (4, DR_ANN), (5, SND_TRAIN), (7, ECAM_SEL), (3, CLIP_READY),
                   (9, b'0123456789abcdef')):
        S(data_first(cid, len(p), p[:5]))
        S(data(cid, p[5:]))

    mark(cap, 'compressed PDUs: ZGFX single segments (raw, literals, back reference, unencoded run), multipart, bad descriptor')
    for p in (CLIP_READY, CLIP_LIST):
        S(data(3, zsingle(zseg_raw(p)), compressed=True))
        S(data(3, zsingle(zseg_literals(p)), compressed=True))
        S(data(3, zsingle(zseg_literals(p, table=False)), compressed=True))
    seg, expect = zseg_with_match(b'0123456789abcdef' * 3 + b'tail')
    S(data(9, zsingle(seg), compressed=True))                          # back reference + unencoded run (unknown channel type: shown as data)
    S(data(3, zmulti([zseg_raw(CLIP_READY[:4]), zseg_raw(CLIP_READY[4:])], len(CLIP_READY)), compressed=True))
    S(data(9, b'\x00' + CLIP_READY, compressed=True))                # not a ZGFX descriptor: raw data kept
    S(data(9, zsingle(bytes([0x24, 0xff])), compressed=True))        # corrupt segment: raw data kept
    S(data_first(9, 1, zsingle(zseg_literals(CLIP_READY)), compressed=True))   # compressed DATA_FIRST, single packet
    S(data_first(9, 1, b'\x00' + CLIP_READY, compressed=True))
    C(data_first(9, 1, zsingle(zseg_raw(CLIP_READY)), compressed=True))
    S(data(1, zsingle(zseg_literals(EGFX_START)), compressed=True))            # DVC compression around the EGFX ZGFX segment

    mark(cap, 'close requests and soft-sync')
    S(close(5))
    S(close(99))
    S(close(70000, cb=2))
    S(softsync_req([(1, [1, 3, 7]), (3, [4, 5, 424242])]))
    C(softsync_resp([1, 3]))
    S(softsync_req([], flags=0))
    S(softsync_req([(1, [])]))
    C(softsync_resp([]))

    # --- UDP side
    mark(cap, 'UDP transport: RDPMT tunnel linked to the TCP connection by a multitransport request, DVC PDUs over UDP')
    cookie = bytes(range(16))
    s.msg(struct.pack('<HH', 0x0002, 0) + struct.pack('<IHH', 0x55667788, 2, 0) + cookie)
    cap.exp('rdpmt', struct.pack('<BHB', 0, 24, 4) + struct.pack('<II', 0x55667788, 0) + cookie, True, sport=50050, pt=3)
    cap.exp('rdp_drdynvc', create_req(31, 'cliprdr'), False, sport=50050, pt=3)
    cap.exp('rdp_drdynvc', data(31, CLIP_READY), False, sport=50050, pt=3)
    cap.exp('rdp_drdynvc', data_first(31, len(CLIP_LIST), CLIP_LIST[:16]), False, sport=50050, pt=3)
    cap.exp('rdp_drdynvc', data(31, CLIP_LIST[16:]), False, sport=50050, pt=3)
    cap.exp('rdp_drdynvc', softsync_req([(3, [31])]), False, sport=50050, pt=3)
    cap.exp('rdp_drdynvc', close(31), False, sport=50050, pt=3)

    # --- reproducers of the fixes
    mark(cap, 'reproducers: reassembly with a middle fragment and an oversized fragment, announced length 4 GiB (Exported PDUs, no RDP session)')
    X = lambda p, c2s=False: cap.exp('rdp_drdynvc', p, c2s, sport=52000)
    X(create_req(5, 'foo'))
    X(data_first(5, 30, b'A' * 10))
    X(data(5, b'B' * 10))                    # middle fragment: used an uninitialized PDU info
    X(data(5, b'C' * 15))                    # more than pending: used an uninitialized PDU info on the second pass
    X(data(5, b'D' * 10))
    for i in range(4):
        X(data_first(5, 0xFFFFFFFF, b'A' * 16, lb=2))            # announced 4 GiB: allocated up front
    finish(cap, 'drdynvc-coverage.pcapng')


def build_malformed():
    cap = Cap()
    MARKS.clear()
    mark(cap, 'the UDP reproducer: DVC create request before the RDPMT tunnel request (no TCP link yet: differs between passes)')
    s = Session(cap, 50000, ['drdynvc'], msgchan=True)
    cookie = bytes(range(16))
    s.msg(struct.pack('<HH', 0x0002, 0) + struct.pack('<IHH', 0x11223344, 2, 0) + cookie)
    cap.exp('rdp_drdynvc', create_req(7, 'foo'), False, sport=50051, pt=3)
    cap.exp('rdpmt', struct.pack('<BHB', 0, 24, 4) + struct.pack('<II', 0x11223344, 0) + cookie, False, sport=50051, pt=3)
    cap.exp('rdp_drdynvc', create_req(7, 'foo'), False, sport=50051, pt=3)
    mark(cap, 'RDPEAR data (needs Kerberos keys: left uncovered, the payload is not GSS-API): single, first and reassembled')
    s.chan('drdynvc', create_req(6, CAPS + 'AuthRedirection'), False)
    s.chan('drdynvc', data(6, EAR_NONE), False)
    s.chan('drdynvc', data_first(6, len(EAR_NONE), EAR_NONE), False)
    s.chan('drdynvc', data_first(6, len(EAR_NONE), EAR_NONE[:10]), False)
    s.chan('drdynvc', data(6, EAR_NONE[10:]), False)
    mark(cap, 'truncated PDUs and fields that run past the end of the PDU')
    s.chan('drdynvc', bytes([0x10]), False)
    s.chan('drdynvc', bytes([0x11, 1]), False)
    s.chan('drdynvc', bytes([0x12, 1, 2]), False)
    s.chan('drdynvc', bytes([0x50]), False)
    s.chan('drdynvc', bytes([0x50, 0, 3, 0]), False)
    s.chan('drdynvc', bytes([0x80, 0, 4, 0, 0, 0]), False)
    s.chan('drdynvc', softsync_req([(1, [1, 2, 3])])[:20], False)
    s.chan('drdynvc', softsync_resp([1, 2])[:8], False)
    s.chan('drdynvc', create_req(3, 'x') + b'', False)
    s.chan('drdynvc', bytes([0x23, 3, 0, 0, 0]), False)           # data first with channel id length 3 (invalid)
    s.chan('drdynvc', bytes([0x60 | 0x0c, 3, 1]), False)
    mark(cap, 'compressed data with a descriptor that promises more than is there')
    s.chan('drdynvc', create_req(3, 'cliprdr'), False)
    s.chan('drdynvc', data(3, bytes([0xe1, 5, 0, 0xff, 0xff, 0, 0]), compressed=True), False)
    s.chan('drdynvc', data(3, bytes([0xe1, 0, 0, 0, 0, 0, 0]), compressed=True), False)
    s.chan('drdynvc', data(3, bytes([0xe1, 2, 0, 10, 0, 0, 0, 3, 0, 0, 0, 4, 1, 2]), compressed=True), False)
    s.chan('drdynvc', data(3, bytes([0xe0]), compressed=True), False)
    mark(cap, 'compressed multi-fragment reassembly (the compressed length is subtracted from the announced length: malformed in the channel dissector)')
    s.chan('drdynvc', data_first(3, 200, zsingle(zseg_raw(CLIP_LIST[:10])), compressed=True), False)
    s.chan('drdynvc', data(3, zsingle(zseg_raw(CLIP_LIST[10:])), compressed=True), False)
    s.chan('drdynvc', data(3, zsingle(zseg_raw(CLIP_READY)), compressed=True), False)
    finish(cap, 'drdynvc-coverage-malformed.pcapng')


if __name__ == '__main__':
    build_main()
    build_malformed()
