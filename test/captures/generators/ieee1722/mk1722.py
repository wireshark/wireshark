#!/usr/bin/env python3
# Generates test/captures/ieee1722_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic IEEE 1722 (AVTP) captures. Usage: mk1722.py <outdir> [-v]
# Writes ieee1722-coverage.pcap (Ethernet, ethertype 0x22f0, and UDP port
# 17220) and ieee1722-coverage-malformed.pcap. Everything is built with
# struct; addresses are made up (locally administered MACs, 192.0.2.0/24).
import struct
import sys
import os

def pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

SRC = bytes.fromhex('020000000002')
DST = bytes.fromhex('91e0f000fe01')
def eth(avtp, dst=DST):
    return dst + SRC + struct.pack('!H', 0x22F0) + avtp

def ipsum(h):
    s = sum(struct.unpack('!10H', h))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def udp(avtp, sport=40000, dport=17220, seq=None, dst='192.0.2.9', src='192.0.2.8'):
    payload = (struct.pack('!I', seq) if seq is not None else b'') + avtp
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0,
                     bytes(map(int, src.split('.'))), bytes(map(int, dst.split('.'))))
    ip = ip[:10] + struct.pack('!H', ipsum(ip)) + ip[12:]
    return bytes.fromhex('01005e000109') + SRC + b'\x08\x00' + ip + u

SID = bytes.fromhex('0200000000020001')

def b1(sv=1, ver=0, low=0):
    return (sv << 7) | (ver << 4) | low

# ---------------------------------------------------------------- 61883
def f61883(tag=1, channel=31, tcode=0xa, sy=0, payload=b'', datalen=None, seq=7, tv=1, mr=0, gv=0):
    h = bytes([0x00, b1(1, 0, (mr << 3) | (gv << 1) | tv), seq, 0]) + SID
    h += struct.pack('!II', 0x11223344, 0)
    h += struct.pack('!H', len(payload) if datalen is None else datalen)
    h += bytes([(tag << 6) | channel, (tcode << 4) | sy])
    return h + payload

def cip(qi1=0, sid=63, dbs=2, fn=0, qpc=0, sph=0, dbc=0, qi2=2, fmt=0x10, fdf=b'\x00\x00\x00'):
    return bytes([(qi1 << 6) | sid, dbs, (fn << 6) | (qpc << 3) | (sph << 2), dbc,
                  (qi2 << 6) | fmt]) + fdf

# ---------------------------------------------------------------- AAF
def faaf(fmt=4, rate=5, chans=2, bitdepth=16, data=b'', datalen=None, mr=0, tv=1,
         sparse=0, evt=0, seq=3):
    h = bytes([0x02, b1(1, 0, (mr << 3) | tv), seq, 0]) + SID + struct.pack('!I', 5000)
    h += bytes([fmt]) + struct.pack('!H', (rate << 12) | chans) + bytes([bitdepth])
    h += struct.pack('!H', len(data) if datalen is None else datalen)
    h += bytes([(sparse << 4) | evt, 0])
    return h + data

# ---------------------------------------------------------------- CVF
def fcvf(fmt=2, sub=0, data=b'', datalen=None, ptv=0, m=0, evt=0, seq=1):
    h = bytes([0x03, b1(1, 0, 1), seq, 0]) + SID + struct.pack('!I', 9000)
    h += bytes([fmt, sub, 0, 0])
    h += struct.pack('!H', len(data) if datalen is None else datalen)
    h += bytes([(ptv << 5) | (m << 4) | evt, 0])
    return h + data

# ---------------------------------------------------------------- CRF
def fcrf(ts=(), datalen=None, pull=0, base=48000, fs=0, tu=0, mr=0, typ=1, interval=160, seq=2, extra=b''):
    data = b''.join(struct.pack('!Q', t) for t in ts) + extra
    h = bytes([0x04, b1(1, 0, (mr << 3) | (fs << 1) | tu), seq, typ]) + SID
    h += struct.pack('!I', (pull << 29) | base)
    h += struct.pack('!HH', len(data) if datalen is None else datalen, interval)
    return h + data

# ---------------------------------------------------------------- ACF
def acf(typ, payload, length_q=None):
    n = 2 + len(payload)
    assert n % 4 == 0, n
    q = n // 4 if length_q is None else length_q
    return struct.pack('!H', (typ << 9) | q) + payload

def padto4(total_noacf, payload):
    '''returns (payload+pad bytes, pad length) so ACF header+total is a multiple of 4'''
    pad = (-(2 + total_noacf + len(payload))) % 4
    return payload + bytes(pad), pad

def can_acf(msgid=0x123, data=b'\x01\x02\x03\x04', eff=0, rtr=0, fd=0, brs=0, esi=0, mtv=1,
            bus=2, brief=False, v2=False, ts=0x0102030405060708, force_pad=None, typ=None,
            rsv2=0, padfield=None):
    if force_pad is None:
        body, pad = padto4(4 + (0 if brief else 8) + 2, data)
        # header is 14 (or 6) bytes including the flags, bus id, ts, id
    else:
        body, pad = data + bytes(force_pad), force_pad
    hdr_len = 6 if brief else 14
    # total with ACF header must be a multiple of 4: fix pad here
    if force_pad is None:
        pad = (-(2 + hdr_len + len(data))) % 4
        body = data + bytes(pad)
    if padfield is not None:
        pad = padfield
    flags_v1 = (pad << 6) | (mtv << 5) | (rtr << 4) | (eff << 3) | (brs << 2) | (fd << 1) | esi
    if not v2:
        h = bytes([flags_v1, bus & 0x1f])
        if not brief:
            h += struct.pack('!Q', ts)
        h += struct.pack('!I', (rsv2 << 29) | msgid)
        t = (0x02 if brief else 0x01) if typ is None else typ
    else:
        fl = (pad << 6) | (mtv << 5) | (rtr << 4) | (eff << 3) | ((bus >> 8) & 7)
        h = bytes([fl, bus & 0xff])
        if not brief:
            h += struct.pack('!Q', ts)
        h += struct.pack('!I', (brs << 31) | (fd << 30) | (esi << 29) | msgid)
        t = (0x22 if brief else 0x21) if typ is None else typ
    return acf(t, h + body)

def lin_acf(linid=0x12, data=b'\x01\x02\x03', bus=1, mtv=1, ts=0x1112131415161718, pad=None):
    if pad is None:
        pad = (-(2 + 10 + len(data))) % 4
    h = bytes([(pad << 6) | (mtv << 5) | bus, linid]) + struct.pack('!Q', ts)
    return acf(0x03, h + data + bytes(pad))

# ---------------------------------------------------------------- NTSCF / TSCF
def ntscf(acfs, ver=0, datalen=None, seq=0x1234, seqlsb=None, r=0, extra=b'', header_only=False):
    data = b''.join(acfs) + extra
    dl = len(data) if datalen is None else datalen
    if ver == 0:
        h = bytes([0x82, b1(1, 0, (r << 3) | ((dl >> 8) & 7)), dl & 0xff,
                   (seq & 0xff) if seqlsb is None else seqlsb]) + SID
    else:
        h = bytes([0x82, b1(1, ver, 0), 0, 0]) + struct.pack('!I', seq) + \
            bytes.fromhex('0200000000000001') + bytes([0x00, (r << 3) | ((dl >> 8) & 7), dl & 0xff,
            (seq & 0xff) if seqlsb is None else seqlsb]) + SID
        # bytes 16..17: rfield2 (12 bits) and R + length high bits
    return h + data

def tscf(acfs, ver=0, datalen=None, seq=0x1234, seqlsb=None, mr=0, tv=1, tu=0, extra=b'', ts=0x55667788):
    data = b''.join(acfs) + extra
    dl = len(data) if datalen is None else datalen
    h = bytes([0x05, b1(1, ver, (mr << 3) | tv),
               (seq & 0xff) if seqlsb is None else seqlsb, tu]) + SID
    if ver == 0:
        h += struct.pack('!I', ts)
    else:
        h += struct.pack('!I', seq) + struct.pack('!Q', ts) + bytes.fromhex('0200000000000001')
    h += struct.pack('!I', 0) + struct.pack('!H', dl) + b'\0\0'
    return h + data

def build(outdir, verbose=False):
    fr = []; notes = []
    def add(label, f):
        fr.append(f); notes.append(label)

    # ------------------------------------------------ 61883
    # The CIP branch of the dissector is unreachable (see README), so the
    # frames cover the tag field values and the tcode check only.
    add('61883 tag 0 (no CIP) tcode a', eth(f61883(tag=0, payload=bytes(16))))
    add('61883 tag 1 (CIP), audio payload', eth(f61883(tag=1, payload=cip() + bytes(16))))
    add('61883 tag 2', eth(f61883(tag=2, payload=bytes(16))))
    add('61883 tag 3, channel 5, tcode 0', eth(f61883(tag=3, channel=5, tcode=0, payload=bytes(16))))
    add('61883 mr gv tv flags', eth(f61883(tag=0, mr=1, gv=1, tv=0, payload=bytes(8))))
    add('61883 over UDP', udp(f61883(tag=1, payload=cip() + bytes(16)), seq=1))
    # ------------------------------------------------ AAF
    add('AAF int16 2ch', eth(faaf(fmt=4, chans=2, bitdepth=16, data=bytes(range(16)))))
    add('AAF int24 2ch', eth(faaf(fmt=3, chans=2, bitdepth=24, data=bytes(12))))
    add('AAF int32 2ch', eth(faaf(fmt=2, chans=2, bitdepth=32, data=bytes(16))))
    add('AAF float32 1ch', eth(faaf(fmt=1, chans=1, bitdepth=32, data=bytes(8), sparse=1, evt=3)))
    add('AAF user format (sample width 0)', eth(faaf(fmt=0, chans=2, bitdepth=16, data=bytes(8), mr=1, tv=0)))
    add('AAF bit depth 0', eth(faaf(fmt=4, chans=2, bitdepth=0, data=bytes(8))))
    add('AAF bit depth > sample width', eth(faaf(fmt=4, chans=2, bitdepth=24, data=bytes(8))))
    add('AAF channels 0', eth(faaf(fmt=4, chans=0, data=b'')))
    add('AAF AES3 (not supported)', eth(faaf(fmt=5, data=bytes(8))))
    add('AAF reserved format', eth(faaf(fmt=9, data=bytes(8))))
    add('AAF 8 channels 48k', eth(faaf(fmt=2, rate=5, chans=8, bitdepth=32, data=bytes(64))))
    add('AAF over UDP', udp(faaf(fmt=4, chans=2, bitdepth=16, data=bytes(8)), seq=2))
    # ------------------------------------------------ CVF
    jpeg = bytes([0, 0, 0, 0, 1, 80, 20, 15]) + bytes([0xff, 0xd8]) + bytes(20)
    add('CVF MJPEG', eth(fcvf(2, 0, jpeg, m=1, evt=2)))
    h264 = struct.pack('!I', 0x1234) + bytes([0x61, 0x88, 0x84]) + bytes(12)
    add('CVF H.264', eth(fcvf(2, 1, h264, ptv=1, m=1)))
    add('CVF H.264 NAL FU-A', eth(fcvf(2, 1, struct.pack('!I', 77) + bytes([0x7c, 0x85, 0x88, 0x84, 0x21, 0xa0, 0xff, 0x12, 0x34, 0x56, 0x78, 0x9a]))))
    add('CVF JPEG2000 (not supported)', eth(fcvf(2, 2, bytes(16))))
    add('CVF reserved subtype', eth(fcvf(2, 7, bytes(16))))
    add('CVF reserved format', eth(fcvf(0, 0, bytes(16))))
    add('CVF data length too large', eth(fcvf(2, 0, jpeg, datalen=500)))
    add('CVF MJPEG over UDP', udp(fcvf(2, 0, jpeg), seq=3))
    # ------------------------------------------------ CRF
    add('CRF 3 timestamps', eth(fcrf(ts=(1000, 2000, 3000), pull=1, base=48000, fs=1, tu=1, mr=1)))
    add('CRF no timestamps', eth(fcrf(ts=())))
    add('CRF length not multiple of 8', eth(fcrf(ts=(5,), extra=b'\x01\x02\x03')))
    add('CRF pull 4', eth(fcrf(ts=(1, 2), pull=4, base=0x1fffffff)))
    # ------------------------------------------------ unknown subtype
    add('unknown subtype 0x20', eth(bytes([0x20, 0x80]) + bytes(20)))
    add('unknown subtype over UDP', udp(bytes([0x20, 0x80]) + bytes(20), seq=4))
    # ------------------------------------------------ ACF CAN / LIN in NTSCF (v0)
    cans = [
        ('CAN std 4 bytes', can_acf(0x123, b'\x01\x02\x03\x04')),
        ('CAN ext id', can_acf(0x1abcdef0, b'\x11\x22\x33\x44\x55\x66\x77\x88', eff=1)),
        ('CAN rtr', can_acf(0x7ff, b'', rtr=1)),
        ('CAN mtv 0', can_acf(0x100, b'\xaa', mtv=0)),
        ('CAN FD 12 bytes', can_acf(0x18, bytes(12), fd=1, brs=1, esi=1)),
        ('CAN FD 64 bytes', can_acf(0x19, bytes(range(64)), fd=1, brs=1)),
        ('CAN FD invalid length 9', can_acf(0x1a, bytes(9), fd=1)),
        ('CAN invalid length 9', can_acf(0x1b, bytes(9))),
        ('CAN invalid std id > 0x7ff', can_acf(0x1000, b'\x01\x02\x03\x04', rsv2=5)),
        ('CAN 1 byte pad 3', can_acf(0x55, b'\x99')),
        ('CAN pad field larger than payload', can_acf(0x56, b'', padfield=3)),
        ('CAN brief', can_acf(0x321, b'\x01\x02', brief=True)),
        ('CAN brief ext fd', can_acf(0x1fffffff, bytes(24), brief=True, eff=1, fd=1)),
        ('CAN v2', can_acf(0x222, b'\x01\x02\x03\x04', v2=True, bus=0x155)),
        ('CAN v2 fd brs esi', can_acf(0x223, bytes(16), v2=True, fd=1, brs=1, esi=1, eff=1)),
        ('CAN v2 brief', can_acf(0x224, b'\x01\x02\x03\x04', v2=True, brief=True, bus=3)),
        ('CAN v2 brief fd', can_acf(0x225, bytes(20), v2=True, brief=True, fd=1, brs=1)),
        ('CAN 0x7df request', can_acf(0x7df, b'\x02\x01\x00\x00\x00\x00\x00\x00')),
        ('CAN J1939-like ext', can_acf(0x18fef100, bytes(8), eff=1)),
    ]
    for label, a in cans:
        add('NTSCF v0: ' + label, eth(ntscf([a])))
    lins = [
        ('LIN 3 bytes', lin_acf(0x12, b'\x01\x02\x03')),
        ('LIN 8 bytes', lin_acf(0x3c, bytes(range(8)), mtv=0)),
        ('LIN 0 bytes', lin_acf(0x01, b'')),
        ('LIN 9 bytes (invalid)', lin_acf(0x02, bytes(9))),
        ('LIN payload below pad', lin_acf(0x02, b'\x01', pad=3)),
    ]
    for label, a in lins:
        add('NTSCF v0: ' + label, eth(ntscf([a])))
    # several ACF messages in one NTSCF and TSCF
    multi = [can_acf(0x100, b'\x01\x02\x03\x04'), lin_acf(0x10, b'\x05\x06'),
             can_acf(0x101, b'\x07', brief=True), acf(0x7a, bytes(6))]
    add('NTSCF v0: four ACFs (CAN, LIN, CAN brief, user)', eth(ntscf(multi, r=1)))
    add('TSCF v0: four ACFs', eth(tscf(multi, mr=1, tu=1)))
    add('NTSCF v0 over UDP', udp(ntscf(multi[:2]), seq=5))
    add('NTSCF v0 over UDP, duplicate seq', udp(ntscf(multi[:2]), seq=5))
    add('NTSCF v0 over UDP, out of order seq', udp(ntscf(multi[:2]), seq=20))
    add('TSCF v0 over UDP other flow', udp(tscf(multi[:2]), seq=1, sport=40001))
    # unknown ACF types are shown as data
    for t in (0x00, 0x04, 0x05, 0x06, 0x0a, 0x0b, 0x7a, 0x30):
        add('NTSCF v0: ACF type 0x%02x' % t, eth(ntscf([acf(t, bytes(6))])))
    # ACF with msg_length 0 (< header) and cropped
    add('NTSCF v0: ACF msg_length 0', eth(ntscf([struct.pack('!H', (0x7a << 9) | 0) + bytes(6)])))
    add('NTSCF v0: ACF cropped', eth(ntscf([struct.pack('!H', (0x01 << 9) | 20) + bytes(14)])))
    add('NTSCF v0: ACF header only 1 byte', eth(ntscf([b'\x02'])))
    add('NTSCF v0: CAN header cropped', eth(ntscf([acf(0x01, bytes(10))])))
    add('NTSCF v0: CAN brief header cropped', eth(ntscf([acf(0x02, bytes(2))])))
    add('NTSCF v0: LIN header cropped', eth(ntscf([acf(0x03, bytes(6))])))
    # NTSCF/TSCF v1, versions above 1, cropped header
    add('NTSCF v1', eth(ntscf(multi[:2], ver=1)))
    add('NTSCF v1 seq lsb mismatch', eth(ntscf(multi[:1], ver=1, seq=0x100, seqlsb=7)))
    add('NTSCF version 3 (invalid)', eth(ntscf(multi[:1], ver=3)))
    add('NTSCF data length too large', eth(ntscf(multi[:1], datalen=300)))
    add('NTSCF no space for header v0', eth(bytes([0x82, 0x80, 0, 0, 1, 2, 3, 4])))
    add('NTSCF no space for header v1', eth(bytes([0x82, 0x90]) + bytes(20)))
    add('TSCF v1', eth(tscf(multi[:2], ver=1, mr=1)))
    add('TSCF v1 seq lsb mismatch', eth(tscf(multi[:1], ver=1, seq=0x100, seqlsb=7)))
    add('TSCF version 2 (invalid)', eth(tscf(multi[:1], ver=2)))
    add('TSCF no space for header v0', eth(bytes([0x05, 0x80]) + bytes(14)))
    add('TSCF no space for header v1', eth(bytes([0x05, 0x90]) + bytes(30)))
    add('TSCF data length too large', eth(tscf(multi[:1], datalen=500)))
    add('TSCF no data', eth(tscf([], mr=0)))
    add('NTSCF no data', eth(ntscf([])))
    # Reproducer from the review (finding 3, not fixed on the branch): the
    # data length is 4 more than the payload. The data length check is made
    # at the data_length field instead of after rsv4, so the clamp misses by
    # 4; the frame still decodes without a malformed packet.
    acf1 = acf(0x7f, b'\x00\x00')
    add('TSCF v0 data length 4 more than payload (reproducer)',
        eth(bytes([0x05, 0x81, 0, 0]) + SID + bytes(4) + bytes(4) +
            struct.pack('!H', len(acf1) + 4) + b'\0\0' + acf1))
    # every field of ACF CAN again over UDP v1
    add('NTSCF v1 over UDP CAN v2 brief', udp(ntscf([dict(cans)['CAN v2 brief']], ver=1), seq=30))
    pcap(os.path.join(outdir, 'ieee1722-coverage.pcap'), fr)

    # --------------------------------------------------- malformed
    mal = []
    mal.append(eth(f61883(tag=0, payload=b'')[:20]))                 # truncated 61883
    mal.append(eth(faaf(fmt=4, chans=2, bitdepth=16, data=bytes(4), datalen=200)))  # AAF datalen too large
    mal.append(eth(faaf()[:18]))                                      # truncated AAF
    mal.append(eth(fcvf(2, 0, bytes(10))[:20]))                       # truncated CVF
    mal.append(eth(fcrf(ts=(1,), datalen=64)))                        # CRF datalen beyond packet
    mal.append(eth(fcrf()[:15]))                                      # truncated CRF
    mal.append(eth(bytes([0x82])))                                    # only subtype
    mal.append(eth(ntscf([can_acf(0x100, b'\x01')])[:11]))            # truncated NTSCF
    mal.append(eth(tscf([can_acf(0x100, b'\x01')])[:23]))             # truncated TSCF
    mal.append(udp(b'\x00', seq=1))                                   # UDP, subtype only
    mal.append(udp(b'', seq=None))                                    # UDP, no data
    mal.append(eth(bytes([0x05, 0x81, 0, 0]) + SID + bytes(4) + bytes(4) + struct.pack('!H', 40) + b'\0\0' + can_acf(0x100, b'\x01\x02\x03\x04')))  # TSCF datalen +
    mal.append(eth(ntscf([can_acf(0x100, b'\x01\x02\x03\x04')])[:-3]))    # cropped ACF payload at the end
    mal.append(eth(ntscf([can_acf(0x100, b'\x01\x02\x03\x04', v2=True)])[:-6]))
    # NTSCF and TSCF named by an Exported PDU (link type 252), i.e. without
    # the common AVTP dissector that stores the header version: the version
    # defaults to 0. Coverage only, in its own file (one link type per file).
    def epdu(name, pdu):
        n = name.encode()
        tlv = struct.pack('!HH', 12, (len(n) + 3) // 4 * 4) + n.ljust((len(n) + 3) // 4 * 4, b'\0')
        return tlv + struct.pack('!HH', 0, 0) + pdu
    pcap(os.path.join(outdir, 'ieee1722-coverage-epdu.pcap'), [
        epdu('ntscf', ntscf([can_acf(0x100, b'\x01\x02\x03\x04')])),
        epdu('tscf', tscf([can_acf(0x100, b'\x01\x02\x03\x04')]))], linktype=252)
    pcap(os.path.join(outdir, 'ieee1722-coverage-malformed.pcap'), mal)
    if verbose:
        for i, n in enumerate(notes, 1):
            print(i, n)
        print('main frames:', len(fr), 'malformed frames:', len(mal))

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    build(out, '-v' in sys.argv)
