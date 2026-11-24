#!/usr/bin/env python3
# Generates test/captures/scte35_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the SCTE-35 coverage captures: mkscte35.py <outdir> [-v].  All data is synthetic.

SCTE-35 splice_info_sections (table ID 0xFC) are carried in MPEG-2 transport
stream packets over UDP (the mp2t UDP heuristic).  The same dissector file also
holds the splice_insert, splice_schedule, time_signal and private_command
command dissectors, which are reached through the splice command type."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from mpeglib import TS, section, udp_frame, write_pcap, LINKTYPE_ETHERNET

PTS = lambda v: struct.pack('>Q', v)[3:]          # 5 octets

def pts_field(v, marker=0x7e):
    """splice_time(): time_specified_flag=1, 6 reserved bits, 33 bit pts_time."""
    return PTS((1 << 39) | (marker << 32) | v)

def splice_info(cmd_type, cmd, descs=b'', pts_adj=0, enc_alg=0, enc=False, tier=0xfff,
                cw=0, version=0, cmd_len=None, desc_len=None, ecrc=None, crc=True, badlen=None, noecrc=False):
    cl = len(cmd) if cmd_len is None else cmd_len
    dl = len(descs) if desc_len is None else desc_len
    first = struct.pack('>B', version) + PTS(((1 if enc else 0) << 39) | (enc_alg << 33) | pts_adj)
    body = (first + bytes([cw]) + struct.pack('>HB', (tier << 4) | (cl >> 8), cl & 0xff)
            + bytes([cmd_type]) + cmd + struct.pack('>H', dl) + descs)
    if enc and not noecrc:
        body += struct.pack('>I', 0x12345678 if ecrc is None else ecrc)
    return section(0xFC, body, ssi=False, crc=True, length=badlen)

def desc(tag, ident, payload, length=None):
    return bytes([tag, 4 + len(payload) if length is None else length]) + struct.pack('>I', ident) + payload

CUEI = 0x43554549

def avail(provider=0x1234):
    return desc(0, CUEI, struct.pack('>I', provider))

def dtmf(chars=b'*123#', preroll=40):
    return desc(1, CUEI, bytes([preroll, (len(chars) << 5) | 0x1f]) + chars)

def seg(event=0x100, cancel=False, psf=True, comps=(), duration=None, dnr=True, flags=0x0f,
        upid_type=0x0f, upid=b'', type_id=0x34, num=1, exp=2, restr=3):
    p = struct.pack('>I', event) + bytes([(0x80 if cancel else 0) | 0x7f])
    if not cancel:
        b = (0x80 if psf else 0) | (0x40 if duration is not None else 0) | (0x20 if dnr else 0)
        if dnr:
            b |= 0x00 | (flags & 0x1c) | (restr & 3)
        else:
            b |= 0x1f
        p += bytes([b])
        if not psf:
            p += bytes([len(comps)])
            for tag, off in comps:
                p += bytes([tag]) + PTS((0x7f << 33) | off)
        if duration is not None:
            p += PTS(duration)
        p += bytes([upid_type, len(upid)]) + upid + bytes([type_id, num, exp])
    return desc(2, CUEI, p)

def insert(event=0x1001, cancel=False, oon=True, psf=True, df=True, sif=False, pts=0x1000, tsf=True,
           comps=(), dur=(1, 27000000), uid=0x55, avail_num=1, avails=4):
    p = struct.pack('>I', event) + bytes([(0x80 if cancel else 0) | 0x7f])
    if cancel:
        return p
    p += bytes([(0x80 if oon else 0) | (0x40 if psf else 0) | (0x20 if df else 0) | (0x10 if sif else 0) | 0x0f])
    if psf and not sif:
        p += pts_field(pts) if tsf else bytes([0x7f])
    if not psf:
        p += bytes([len(comps)])
        for tag, t in comps:
            p += bytes([tag])
            if not sif:
                p += pts_field(t) if t is not None else bytes([0x7f])
    if df:
        p += PTS(((dur[0]) << 39) | (0x3f << 33) | dur[1])
    return p + struct.pack('>HBB', uid, avail_num, avails)

def schedule(splices):
    p = bytes([len(splices)])
    for e in splices:
        ev = struct.pack('>I', e['event']) + bytes([(0x80 if e.get('cancel') else 0) | 0x7f])
        if not e.get('cancel'):
            psf = e.get('psf', True); df = e.get('df', False)
            ev += bytes([(0x80 if e.get('oon', True) else 0) | (0x40 if psf else 0) | (0x20 if df else 0) | 0x1f])
            if psf:
                ev += struct.pack('>I', e.get('utc', 0x65000000))
            else:
                comps = e.get('comps', ())
                ev += bytes([len(comps)])
                for tag, utc in comps:
                    ev += bytes([tag]) + struct.pack('>I', utc)
            if df:
                ev += PTS(((1 if e.get('auto', True) else 0) << 39) | (0x3f << 33) | e.get('dur', 900000))
            ev += struct.pack('>HBB', e.get('uid', 7), 1, 3)
        else:
            ev += b''
            ev = ev[:5]
            ev += struct.pack('>HBB', 0, 0, 0)[:0]
            ev += b''
            ev += struct.pack('>HBB', e.get('uid', 7), 1, 3)
        p += ev
    return p

def main(out, verbose=False):
    ts = TS()
    frames = []
    marks = []
    def add(sects, pid=0x40, mark=None):
        if mark:
            marks.append((len(frames) + 1, mark))
        pk = ts.sections(pid, list(sects) if isinstance(sects, (list, tuple)) else [sects])
        frames.append(udp_frame(b''.join(pk), dport=5004))

    add(splice_info(0x00, b''), mark='splice_null, with a PTS adjustment and a tier, protocol version 0')
    add(splice_info(0x00, b'', pts_adj=0x1ffffffff, tier=0x123, cw=0x55, version=1))
    add(splice_info(0x07, b''), mark='bandwidth_reservation, reserved command types (no command dissector)')
    add(splice_info(0x01, b'\x01\x02'))
    add(splice_info(0x08, b''))
    add(splice_info(0x06, pts_field(0x1234567)), mark='time_signal: with and without a time')
    add(splice_info(0x06, bytes([0x7e])))
    add(splice_info(0xff, struct.pack('>I', CUEI) + b'private data'), mark='private_command with an identifier and private bytes')
    add(splice_info(0xff, struct.pack('>I', 0xdeadbeef) + b'\x01'))
    add(splice_info(0x05, insert(), cw=1), mark='splice_insert: program splice with a time and a duration, immediate, without a time, component splices with and without times, cancellation')
    add(splice_info(0x05, insert(event=0x1002, oon=False, tsf=False, df=False)))
    add(splice_info(0x05, insert(event=0x1003, sif=True, df=True)))
    add(splice_info(0x05, insert(event=0x1004, psf=False, comps=[(1, 0x111), (2, 0x222), (3, None)], df=False)))
    add(splice_info(0x05, insert(event=0x1005, psf=False, sif=True, comps=[(5, 0), (6, 0)], dur=(0, 5))))
    add(splice_info(0x05, insert(event=0x1006, psf=False, comps=[], df=True)))
    add(splice_info(0x05, insert(event=0x1007, cancel=True)))
    add(splice_info(0x04, schedule([dict(event=1), dict(event=2, psf=False, comps=[(1, 100), (2, 200)], df=True),
                                    dict(event=3, cancel=True), dict(event=4, df=True, auto=False, oon=False)])),
        mark='splice_schedule: program and component splices, with and without durations, a cancellation; zero splices')
    add(splice_info(0x04, schedule([])))
    add(splice_info(0x04, schedule([dict(event=5, psf=False, comps=[], df=False)])))
    add(splice_info(0x06, pts_field(77), descs=avail() + dtmf() + seg(), pts_adj=90000),
        mark='Descriptors: avail, DTMF, segmentation (program, cancel, components with a duration, every UPID length and type, delivery restrictions)')
    add(splice_info(0x06, pts_field(78), descs=dtmf(b'', 0) + dtmf(b'0123456', 255)))
    add(splice_info(0x06, pts_field(79), descs=seg(event=1, cancel=True) + seg(event=2, psf=False, comps=[(1, 90000), (2, 180000)], duration=2700000,
                                                                              upid_type=0x08, upid=b'ABCD1234', type_id=0x30)))
    add(splice_info(0x06, pts_field(80), descs=seg(event=3, dnr=False, upid_type=0x0a, upid=b'10.5240/ABCD-EFGH-1234-5678-9012-Z', type_id=0x10, num=0, exp=0)
                    + seg(event=4, psf=False, comps=[], dnr=True, flags=0x1c, restr=0, duration=1, type_id=0x22)))
    add(splice_info(0x06, pts_field(81), descs=seg(event=5, upid_type=0x03, upid=b'ABCD0001000H', restr=1, type_id=0x01)
                    + seg(event=6, upid_type=0x0c, upid=b'managed', restr=2, type_id=0x41)))
    add(splice_info(0x06, pts_field(82), descs=desc(3, CUEI, b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c')
                    + desc(4, CUEI, b'\x01\x02\x03') + desc(0x80, 0x12345678, b'\x01')),
        mark='Reserved descriptor tags (skipped by their length); an encrypted section (only the flags and the encrypted CRC are shown)')
    add(splice_info(0x06, pts_field(1), enc=True, enc_alg=1, descs=avail()))
    add(splice_info(0x05, b'\xaa' * 30, enc=True, enc_alg=0x21))
    add(splice_info(0x06, pts_field(3)) + splice_info(0x00, b''), mark='Two sections in one transport stream packet; a section split over several transport stream packets (large descriptor loop)')
    big = b''.join(desc(0, CUEI, struct.pack('>I', i)) for i in range(60)) + seg(event=9, upid=b'x' * 100)
    add(splice_info(0x06, pts_field(4), descs=big))
    main_n = len(frames)
    main_marks = list(marks)

    # malformed: sections the dissector declines (length checks) or cuts short
    mfr = []
    def madd(s, pid=0x41):
        pk = ts.sections(pid, [s])
        mfr.append(udp_frame(b''.join(pk), dport=5004))
    madd(section(0xFC, bytes(8), ssi=False))                              # shorter than the minimum
    madd(splice_info(0x05, b'\x00\x00\x00\x01\x80', cmd_len=200))          # command length beyond the data
    madd(splice_info(0x06, pts_field(1), desc_len=500))                    # descriptor loop beyond the data
    madd(splice_info(0x06, pts_field(1), enc=True, desc_len=0)[:-3])       # encrypted CRC cut off
    madd(splice_info(0x05, b'\x00\x00\x00\x01'))                           # splice_insert too short
    madd(splice_info(0x05, b'\x00\x00\x00\x01\x00\x80'))                   # new event without the rest
    madd(splice_info(0x05, b'\x00\x00\x00\x01\x00\xe0\x00\x00'))           # program splice, duration missing
    madd(splice_info(0x05, b'\x00\x00\x00\x01\x00\xc0\x80\x00\x00'))       # program splice, time cut short
    madd(splice_info(0x05, b'\x00\x00\x00\x01\x00\x80\x05\x01\x02'))       # components beyond the data
    madd(splice_info(0x05, b'\x00\x00\x00\x01\x00\x80\x01\x01\x00'))       # component cut short
    madd(splice_info(0x05, b'\x00\x00\x00\x01\x00\x80\x01\x01\x80\x00'))   # component time cut short
    madd(splice_info(0x05, b'\x00\x00\x00\x01\x00\xa0\x00'))               # duration flag, no room
    madd(splice_info(0x06, b''))                                           # time_signal empty
    madd(splice_info(0x06, b'\xfe\x00'))                                   # time_signal time cut short
    madd(splice_info(0xff, b'\x00\x01'))                                   # private command too short
    madd(splice_info(0x04, b''))
    madd(splice_info(0x04, b'\x03\x00\x00\x00\x01\x80'))                   # splice count beyond the data
    madd(splice_info(0x04, b'\x01\x00\x00\x00\x01\x00'))                   # new splice cut short
    madd(splice_info(0x04, b'\x01\x00\x00\x00\x01\x00\xc0\x00\x00'))       # program utc cut short
    madd(splice_info(0x04, b'\x01\x00\x00\x00\x01\x00\x20\x05\x01\x02\x03\x04'))  # component table beyond the data
    madd(splice_info(0x04, b'\x01\x00\x00\x00\x01\x00\xe0\x00\x00\x00\x01\x02\x03'))  # duration cut short
    madd(splice_info(0x06, pts_field(1), descs=b'\x00\x08\x43\x55\x45\x49'))   # descriptor length beyond the loop
    madd(splice_info(0x06, pts_field(1), descs=desc(0, CUEI, b'\x01\x02', 6)))  # avail descriptor too short
    madd(splice_info(0x06, pts_field(1), descs=desc(1, CUEI, b'\x00', 5)))     # dtmf descriptor too short
    madd(splice_info(0x06, pts_field(1), descs=desc(1, CUEI, bytes([0, 0xe0, 0x31]), 7)))  # dtmf count beyond
    madd(splice_info(0x06, pts_field(1), descs=desc(2, CUEI, b'\x00\x00\x00\x01\x7f\x80\x03\x01', 8)))  # segmentation cut short
    madd(splice_info(0x06, pts_field(1), descs=desc(2, CUEI, b'\x00\x00\x00\x01\x7f\x00\x03\x01\x01\x02\x03\x04\x05\x06\x07', 15)))
    madd(splice_info(0x06, pts_field(1), descs=b'\x00'))                       # descriptor loop of one octet
    madd(splice_info(0x06, pts_field(1), descs=b'\x00\x00', desc_len=2))       # descriptor with length 0

    madd(splice_info(0x00, b'', enc=True, noecrc=True))                   # encrypted flag, no encrypted CRC: shorter than required
    madd(splice_info(0x05, b'\x00\x00\x00\x01\x00\x40' + bytes(4)))          # program splice, time flag missing
    madd(splice_info(0x05, b'\x00\x00\x00\x01\x00\x40\x80' + bytes(4)))     # program splice time cut short (11 octets)
    madd(splice_info(0x05, b'\x00\x00\x00\x01\x00\x00\x05' + bytes(4)))     # five components, no room
    madd(splice_info(0x05, b'\x00\x00\x00\x01\x00\x00\x02' + b'\x01\x80' + bytes(4) + b'\x02\x80'))  # second component cut short
    madd(splice_info(0x05, b'\x00\x00\x00\x01\x00\x70' + bytes(4)))          # duration flag, no room (immediate splice)
    madd(splice_info(0x04, b'\x01\x00\x00\x00\x01\x00\x60\x00\x00\x00\x01\x00' + bytes(3)))  # schedule duration, no room

    write_pcap(os.path.join(out, 'scte35-coverage.pcap'), frames, LINKTYPE_ETHERNET)
    write_pcap(os.path.join(out, 'scte35-coverage-malformed.pcap'), mfr, LINKTYPE_ETHERNET)
    if verbose:
        for n, tx in main_marks:
            print(n, tx)
        print(main_n, 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
