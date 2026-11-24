#!/usr/bin/env python3
# Generates test/captures/xra_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures for the XRA dissector (packet-xra.c).

XRA is the Excentis DOCSIS 3.1 sniffer header (pcap link-layer type 273,
LINKTYPE_DOCSIS31_XRA31): version, direction/packet type, a 16 bit TLV
length and TLVs, followed by a DOCSIS MAC frame (handed to the DOCSIS
dissector), a PLC message block list, NCP message blocks, an OFDMA
segment or an initial ranging request, depending on the packet type.
Every packet is built from scratch with struct; DOCSIS MAC frames are
minimal packet PDUs and REQ frames.

Usage: mkxra.py <outdir>
Writes xra-coverage.pcap and xra-coverage-malformed.pcap (link type 273).
"""
import os
import struct
import sys

LINKTYPE = 273

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, LINKTYPE))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 1000 * i, len(fr), len(fr)))
            f.write(fr)

def crc16_x25(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xFFFF

def ip_csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def udp_eth(payload, sport=4000, dport=5000):
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    ip = ip[:10] + struct.pack('>H', ip_csum(ip)) + ip[12:]
    return bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + u

def docsis_pdu(payload=b'docsis payload 0123456789'):
    """DOCSIS packet PDU (FC_TYPE 0), LEN counts the Ethernet frame."""
    eth = udp_eth(payload)
    h = bytes([0x00, 0x00]) + struct.pack('>H', len(eth))
    return h + struct.pack('<H', crc16_x25(h)) + eth

def docsis_req(sid=0x1234, minislots=5):
    h = bytes([0xC4, minislots]) + struct.pack('>H', sid)
    return h + struct.pack('<H', crc16_x25(h))

def tlv(t, v):
    assert len(v) <= 255
    return bytes([t, len(v)]) + v

def n(width, v):
    return v.to_bytes(width, 'big')

def xra(ptype, tlvs=b'', body=b'', ver=1, tlvlen=None):
    return struct.pack('>BBH', ver, ptype, len(tlvs) if tlvlen is None else tlvlen) + tlvs + body

# TLV types
DSCH, DSFREQ, MOD, ANNEX, PROF, CWINFO, NCPTR, NCPSYM, MER, USCH, SID, IUC, BURSTID, BURSTINFO, MSINFO, \
    CCC, GRANT, SEGHDR, NFRAMES, TADJ, POWER, SUBSLOT, CW = range(1, 24)

def cw_info(**kw):
    return b''.join(tlv(t, v) for t, v in kw.items())

main = []
mal = []

# 1: SC-QAM downstream MAC frames (type 1): TLVs and a packet PDU; both modulations and annexes
for chan, freq, mod, annex, mer in ((1, 231000000, 0, 0, 144), (33, 855000000, 1, 1, 160), (255, 0, 1, 0, 0)):
    main.append(xra(1, tlv(DSCH, n(1, chan)) + tlv(DSFREQ, n(4, freq)) + tlv(MOD, n(1, mod)) +
                    tlv(ANNEX, n(1, annex)) + tlv(MER, n(1, mer)), docsis_pdu()))
# a frame with the TLVs only (nothing follows the TLV region)
main.append(xra(1, tlv(DSCH, n(1, 2)) + tlv(DSFREQ, n(4, 100000000))))
main.append(xra(1))
# 2: OFDM DOCSIS (8): every profile, codeword info with all sub-TLVs
for prof in range(16):
    main.append(xra(8, tlv(DSCH, n(1, 159)) + tlv(PROF, n(1, prof)), docsis_pdu()))
cw = (tlv(2, n(2, 1360)) + tlv(1, n(1, 1)) + tlv(3, n(1, 1)) + tlv(4, n(1, 3)) + tlv(5, n(2, 5940)) +
      tlv(6, n(1, 1)) + tlv(7, n(2, 12)) + tlv(8, n(1, 17)) + tlv(9, n(1, 1)) + tlv(10, n(1, 2)) + tlv(99, b'\xaa\xbb'))
main.append(xra(8, tlv(DSCH, n(1, 159)) + tlv(CWINFO, cw) + tlv(CWINFO, b'') + tlv(CWINFO, tlv(2, n(2, 7))), docsis_pdu()))
# unknown TLV types, an empty TLV, extension TLVs 254 and 255
main.append(xra(8, tlv(24, b'\x01\x02') + tlv(200, b'') + tlv(254, b'cfg') + tlv(255, b'ext\x00') + tlv(DSCH, n(1, 3)), docsis_pdu()))
# 3: OFDM NCP (9): message blocks and CRC; truncation flag and symbol ID
def ncp_mb(profile, z, c, nn, l, t, u, r, start):
    b0 = (profile << 4) | (z << 3) | (c << 2) | (nn << 1) | l
    b12 = (t << 15) | (u << 14) | (r << 13) | (start & 0x1fff)
    return bytes([b0]) + struct.pack('>H', b12)
crc3 = b'\x12\x34\x56'
main.append(xra(9, tlv(NCPTR, n(1, 0)) + tlv(NCPSYM, n(1, 7)), ncp_mb(1, 0, 0, 0, 0, 1, 0, 0, 100) + ncp_mb(2, 1, 1, 1, 1, 0, 1, 1, 0x1fff) + crc3))
main.append(xra(9, tlv(NCPTR, n(1, 1)) + tlv(NCPSYM, n(4, 123456)), ncp_mb(15, 1, 0, 1, 1, 1, 1, 1, 8191) + crc3))
main.append(xra(9, tlv(NCPSYM, n(2, 9)), crc3))
main.append(xra(9, tlv(NCPSYM, n(1, 8)), ncp_mb(0, 0, 0, 0, 0, 0, 0, 0, 0) * 5 + crc3))
# 4: PLC (10): timestamp MB (always first), energy management, trigger, future use, message channel
ts_ts = (1 << 41) | (0x12345678 << 9) | (3 << 4) | 5
TS = bytes([0x10]) + struct.pack('>Q', ts_ts) + b'\xaa\xbb\xcc'                 # type 1, reserved 0, 12 octets
TS2 = bytes([0x1f]) + struct.pack('>Q', 0xffffffffffffffff) + b'\x00\x00\x00'
TS3 = bytes([0x10]) + struct.pack('>Q', 0) + b'\x00\x00\x00'
def em(nn): return bytes([0x20 | nn]) + bytes(3 + 6 * nn)
TR = bytes([0x40]) + bytes(8)
def fut(typ, nib2, b2): return bytes([(typ << 4) | nib2, b2]) + bytes(5 + 256 * (nib2 & 1) + b2 - 2)
def mc(pspf, psp, data): return bytes([0x30 | pspf]) + (struct.pack('>H', psp) if pspf else b'') + data
d1 = docsis_pdu(b'x' * 10)
d2 = docsis_pdu(b'y' * 30)
mc_data = d1 + b'\xff\xff\xff' + d2 + docsis_req() + b'\xff' * 20
main.append(xra(10, tlv(DSCH, n(1, 159)), TS + mc(1, 0, mc_data)))
main.append(xra(10, tlv(DSCH, n(1, 159)), TS + mc(1, 4, b'\xff' * 4 + mc_data)))
main.append(xra(10, tlv(DSCH, n(1, 159)), TS + mc(0, 0, bytes(30))))
main.append(xra(10, tlv(DSCH, n(1, 159)), TS + em(0) + em(1) + em(2) + TR + mc(1, 0, d1 + b'\xff' * 10)))
main.append(xra(10, tlv(DSCH, n(1, 159)), TS2 + fut(5, 0, 10) + fut(6, 1, 3) + fut(15, 1, 0xff) + TR + mc(1, 0, b'\xff' * 10)))
main.append(xra(10, tlv(DSCH, n(1, 159)), TS3 + TR))
main.append(xra(10, tlv(DSCH, n(1, 159)), TS))
# a DOCSIS frame whose length runs past the message channel block
big = docsis_pdu(b'z' * 100)
main.append(xra(10, tlv(DSCH, n(1, 159)), TS + mc(1, 0, big[:60] + b'\xff' * 30)))
# 5: OFDM PLC MMM (11), a DOCSIS frame
main.append(xra(11, tlv(DSCH, n(1, 159)), docsis_pdu()))
# 6: TDMA (65) and OFDMA data bursts (72) with and without a segment header
def segment(pfi, ptr, seq, cluster, req, data, good=True):
    """PFI/pointer field, sequence number/SID cluster, request, HCS (CRC-16, LE), data"""
    b = struct.pack('>HHH', (pfi << 15) | ptr, ((seq << 3) | (cluster & 7)) & 0xffff, req)
    h = crc16_x25(b) if good else 0x1234
    return b + struct.pack('<H', h) + data
minislot = tlv(1, n(4, 1000)) + tlv(2, n(1, 3)) + tlv(3, n(1, 9)) + tlv(77, b'\x01')
burst = tlv(1, n(8, 0x1122334455667788)) + tlv(USCH, n(1, 2)) + tlv(SID, n(2, 7)) + tlv(IUC, n(1, 11)) + tlv(55, b'\xaa\xbb')
burst_tlvs = (tlv(USCH, n(1, 3)) + tlv(SID, n(2, 4000)) + tlv(IUC, n(1, 9)) + tlv(BURSTID, n(8, 0xdeadbeef00000001)) +
              tlv(BURSTINFO, burst) + tlv(MSINFO, minislot) + tlv(CCC, n(1, 1)) + tlv(GRANT, n(3, 0x1234)) + tlv(GRANT, n(4, 0xff001234)))
for ptype in (65, 72):
    main.append(xra(ptype, burst_tlvs + tlv(SEGHDR, n(1, 1)), segment(1, 100, 33, 3, 0x0102, b'segment data' * 3)))
    main.append(xra(ptype, burst_tlvs + tlv(SEGHDR, n(1, 0)), segment(0, 0x3fff, 0x1fff, 7, 0xffff, b'x' * 4)))
    main.append(xra(ptype, burst_tlvs + tlv(SEGHDR, n(1, 0)), b'not a segment'))
    main.append(xra(ptype, tlv(USCH, n(1, 1)) + tlv(SEGHDR, n(1, 1)), segment(0, 1, 2, 3, 4, b'')))
    main.append(xra(ptype, tlv(USCH, n(1, 1)), b''))
# 7: OFDMA REQ (75), US DOCSIS MAC frame (80), fine ranging (74)
main.append(xra(75, tlv(USCH, n(1, 1)) + tlv(SID, n(2, 7)), docsis_req()))
main.append(xra(80, tlv(USCH, n(1, 1)) + tlv(SID, n(2, 7)) + tlv(IUC, n(1, 6)), docsis_pdu()))
main.append(xra(74, tlv(USCH, n(1, 1)) + tlv(SUBSLOT, n(4, 5)) + tlv(NFRAMES, n(2, 4)) + tlv(TADJ, n(4, 0xfffffff0)) + tlv(POWER, n(2, 0xff9c)), docsis_pdu()))
# 8: initial ranging (73): TLVs and the 10 octet request, every control word
for cwv in range(16):
    main.append(xra(73, tlv(USCH, n(1, 1)) + tlv(SUBSLOT, n(1, cwv)) + tlv(NFRAMES, n(2, cwv)) + tlv(TADJ, n(2, cwv * 100)) +
                    tlv(POWER, n(2, 100 + cwv * 13)) + tlv(CW, n(1, cwv)),
                    bytes.fromhex('0200000000aa') + n(1, 3) + b'\x01\x02\x03'))
main.append(xra(73, tlv(POWER, n(2, 0x8000)) + tlv(TADJ, n(1, 0xf0)), bytes.fromhex('02000000bbbb') + n(1, 4) + b'\xaa\xbb\xcc'))
# 9: probing sequence (76), unknown packet types and directions
main.append(xra(76, tlv(USCH, n(1, 1)), b'probing sequence data'))
main.append(xra(99, tlv(DSCH, n(1, 1)), b'unknown type'))
main.append(xra(0x81, b'', b'direction 2'))
main.append(xra(0xff, b'', b'direction 3'))
main.append(xra(0, b'', b''))
# version other than 1
main.append(xra(1, tlv(DSCH, n(1, 1)), docsis_pdu(), ver=2))
# MER and power levels (decimals): MER 0, 1, 255; power negative, zero
for m in (1, 255):
    main.append(xra(1, tlv(MER, n(1, m)), docsis_pdu()))
for p in (0, 0x7fff, 0xffff):
    main.append(xra(74, tlv(POWER, n(2, p)), docsis_pdu()))
# The reproducer of "XRA: Use an unsigned xra_length": a TLV length of 65535 (the
# header is then 65539 octets and wrapped to 3 in a 16 bit variable)
huge = b''.join(tlv(200 + i % 50, bytes(253)) for i in range(257))
assert len(huge) == 65535
main.append(xra(1, huge, docsis_pdu()))
main.append(xra(65, huge, b''))
# a TLV length of 65532 (header 65536, the 16 bit sum wraps to 0)
huge2 = b''.join(tlv(200, bytes(253)) for i in range(256)) + tlv(201, bytes(250))
assert len(huge2) == 65532
main.append(xra(1, huge2, docsis_pdu()))

# Malformed
mal.append(b'\x01')                                   # shorter than the header
mal.append(b'\x01\x01\x00')
mal.append(xra(1, b'', b'', tlvlen=10))               # TLV length past the end
mal.append(xra(1, tlv(DSCH, n(1, 1)), docsis_pdu(), tlvlen=0xffff))
mal.append(xra(1, b'\x01'))                           # TLV with a type and no length
mal.append(xra(1, b'\x01\x05\x00'))                   # TLV length past the TLV region
mal.append(xra(1, tlv(DSFREQ, n(5, 1))))              # integer field longer than 4 octets
mal.append(xra(1, tlv(DSFREQ, b'')))                  # zero length
mal.append(xra(1, tlv(DSCH, b'')))
mal.append(xra(1, tlv(MER, b'')))
mal.append(xra(74, tlv(POWER, b'\x01')))
mal.append(xra(74, tlv(POWER, b'')))
mal.append(xra(8, tlv(CWINFO, b'\x02')))              # codeword sub-TLV cut
mal.append(xra(8, tlv(CWINFO, b'\x02\x05\x00')))
mal.append(xra(8, tlv(CWINFO, tlv(2, n(3, 1)))))
mal.append(xra(65, tlv(MSINFO, b'\x01')))
mal.append(xra(65, tlv(MSINFO, tlv(1, n(5, 1)))))
mal.append(xra(65, tlv(BURSTINFO, b'\x01\x08\x00')))
mal.append(xra(65, tlv(BURSTINFO, tlv(1, n(9, 1)))))
mal.append(xra(65, tlv(BURSTID, n(9, 1))))
mal.append(xra(1, tlv(DSCH, n(1, 1)) + tlv(200, b'\x00')[:2]))   # unknown TLV length 1, data missing
mal.append(xra(10, b'', bytes([0x10]) + bytes(5)))                    # timestamp block cut
mal.append(xra(10, b'', bytes(1)))                                    # block header only
mal.append(xra(10, b'', TS + bytes([0x20])))                          # EM block, one octet
mal.append(xra(10, b'', TS + em(3)[:10]))                             # EM block cut
mal.append(xra(10, b'', TS + TR[:5]))
mal.append(xra(10, b'', TS + mc(1, 0, b'')[:2]))                       # message channel cut in the pointer
mal.append(xra(10, b'', TS + mc(1, 0xffff, bytes(20))))                # pointer past the end
mal.append(xra(10, b'', TS + mc(1, 0, bytes([0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))))
mal.append(xra(10, b'', TS + fut(5, 1, 0xff)[:30]))
mal.append(xra(10, b'', TS + b'\x50'))                                  # future block, one octet
mal.append(xra(9, b'', b'\x01\x02'))                                    # NCP shorter than the CRC
mal.append(xra(9, b'', b'\x01\x02\x03\x04'))
mal.append(xra(9, b'', b'\x01\x02\x03\x04\x05\x06'))
mal.append(xra(73, b'', b'\x01\x02\x03'))                               # initial ranging cut
mal.append(xra(73, b'', bytes(9)))
mal.append(xra(72, tlv(SEGHDR, n(1, 1)), b'\x80\x00\x00'))             # segment cut
mal.append(xra(72, tlv(SEGHDR, n(1, 1)), segment(1, 100, 33, 3, 0x0102, b'')[:7]))
mal.append(xra(72, tlv(SEGHDR, n(1, 1)), segment(1, 100, 33, 3, 0x0102, b'bad hcs', good=False)))   # bad HCS
mal.append(xra(72, tlv(SEGHDR, n(1, 1)), b''))
mal.append(xra(1, b'', b'\x00\x00'))                                    # DOCSIS frame cut
mal.append(xra(1, b'', docsis_pdu()[:10]))
mal.append(xra(1, b'', bytes([0x00, 0x00, 0x00, 0x20, 0x12, 0x34]) + b'short'))
# a TLV length larger than the frame
mal.append(xra(1, b'', b'', tlvlen=0xfffc))

out = sys.argv[1]
write_pcap(os.path.join(out, 'xra-coverage.pcap'), main)
write_pcap(os.path.join(out, 'xra-coverage-malformed.pcap'), mal)
print(len(main), len(mal))
