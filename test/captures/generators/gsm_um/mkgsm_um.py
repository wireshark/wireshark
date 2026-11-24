#!/usr/bin/env python3
# Generates test/captures/gsm_um_coverage.xml.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the GSM Um coverage captures. Usage: mkgsm_um.py <outdir>

GSM Um (WTAP_ENCAP_GSM_UM) is the link layer of the Gammu "DCT3 trace" XML
file format (wiretap/dct3trace.c). Writes gsm_um-coverage.xml (valid
records), gsm_um-coverage-malformed.xml (records that throw exceptions in
the payload dissectors) and gsm_um-coverage-exported-pdu.pcap (two Exported
PDU frames naming gsm_um). Everything is synthetic.
"""
import struct
import sys

CH = {'sdcch': 128, 'sacch': 112, 'facch': 176, 'ccch': 96, 'bcch': 80, 'unknown': 7}

def rec(direction, ch, data=None, arfcn=None, seq=None, bsic=None, error=None,
        shift=None, l2=None):
    """One <l1> record. For downlink the physical channel (ARFCN) etc.
    follow the direction attribute, as the file reader only parses them
    for downlink records."""
    a = ['direction="%s"' % direction, 'logicalchannel="%d"' % CH[ch]]
    if arfcn is not None: a.append('physicalchannel="%d"' % arfcn)
    if seq is not None: a.append('sequence="%d"' % seq)
    if bsic is not None: a.append('bsic="%d"' % bsic)
    if error is not None: a.append('error="%d"' % error)
    if shift is not None: a.append('timeshift="%d"' % shift)
    if data is not None: a.append('data="%s"' % data.hex())
    if l2 is not None:
        return '<l1 %s><l2 data="%s"/></l1>\n' % (' '.join(a), l2.hex())
    return '<l1 %s></l1>\n' % ' '.join(a)

def doc(records):
    return '<?xml version="1.0" encoding="UTF-8"?>\n<dump>\n' + ''.join(records) + '</dump>\n'

def pad(b, n=23, fill=0x2b):
    return b + bytes([fill]) * (n - len(b))

def ccch(pdu, pseudo=None):
    """CCCH/BCCH downlink block: L2 pseudo length octet, the message, filler."""
    n = len(pdu) if pseudo is None else pseudo
    return pad(bytes([(n << 2) | 1]) + pdu)

SI3 = bytes.fromhex('061b' '0001' '00f11000' '01' '450000' '00' '0000' '4d0000' '2b2b2b2b')

def exp_pdu(proto, payload):
    """An Exported PDU frame (link type 252) naming a dissector."""
    name = proto.encode()
    pad_ = (-len(name)) % 4
    return (struct.pack('>HH', 12, len(name) + pad_) + name + b'\0' * pad_ +
            struct.pack('>HH', 0, 0) + payload)

def write_pcap(path, frames, linktype):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)

def main(out):
    ok, bad = [], []
    # BCCH: system information type 3 (downlink), band by ARFCN
    arfcns = [(1, 'P-GSM 900'), (124, 'P-GSM 900'), (0, 'E-GSM 900'), (975, 'E-GSM 900'),
              (1023, 'E-GSM 900'), (955, 'R-GSM 900'), (974, 'R-GSM 900'),
              (512, 'DCS 1800'), (885, 'DCS 1800'), (810, 'DCS 1800'), (259, 'GSM 450'),
              (293, 'GSM 450'), (306, 'GSM 480'), (340, 'GSM 480'), (128, 'GSM 850'),
              (251, 'GSM 850'), (200, 'GSM 850'), (900, 'Unknown'), (500, 'Unknown'),
              (1100, 'Unknown')]
    for i, (a, band) in enumerate(arfcns):
        ok.append(rec('down', 'bcch', ccch(SI3[:22], 22), arfcn=a, seq=1000 + i, bsic=(i * 7) & 0x3f,
                      error=i & 1, shift=i * 3))
    # CCCH, PCH and AGCH downlink: paging request type 1, immediate
    # assignment reject and paging request type 2 (an empty block with
    # pseudo length 0 is not dissected)
    PAG1 = bytes.fromhex('0621' '00' '05f411223344')
    ok.append(rec('down', 'ccch', ccch(PAG1), arfcn=20, seq=5, bsic=3, error=0, shift=0))
    ok.append(rec('down', 'ccch', pad(bytes([0x01])), arfcn=20, seq=6, bsic=3, error=0, shift=0))
    IAR = bytes.fromhex('063a' '00' + ('000000' '10') * 4)
    ok.append(rec('down', 'ccch', ccch(IAR), arfcn=30, seq=7, bsic=4, error=0, shift=1))
    ok.append(rec('down', 'ccch', ccch(bytes.fromhex('0622' '00' '11223344' '55667788')), arfcn=30, seq=8, bsic=4, error=0, shift=1))
    # uplink CCCH, PCH and AGCH is a RACH (data): channel request
    ok.append(rec('up', 'ccch', bytes([0x4d])))
    ok.append(rec('up', 'ccch', bytes([0x03, 0x78])))
    ok.append(rec('up', 'ccch', bytes([0x03, 0x78])))
    # uplink broadcast channel is just data too
    ok.append(rec('up', 'bcch', bytes([0x00, 0x01, 0x02])))
    # SDCCH, SACCH and FACCH: LAPDm frames (SABM, UA, UI with RR messages)
    REL = bytes.fromhex('0d' '060d00')      # length 3; RR Channel Release
    ok.append(rec('down', 'sdcch', bytes.fromhex('01' '3f' '01'), arfcn=40, seq=10, bsic=5, error=0, shift=0))
    ok.append(rec('up', 'sdcch', bytes.fromhex('01' '73' '01')))
    ok.append(rec('down', 'sdcch', bytes.fromhex('01' '03') + REL, arfcn=40, seq=11, bsic=5, error=0, shift=0))
    ok.append(rec('up', 'sdcch', bytes.fromhex('01' '03' '0d' '061261')))
    ok.append(rec('down', 'facch', bytes.fromhex('01' '03') + REL, arfcn=40, seq=12, bsic=5, error=0, shift=0))
    ok.append(rec('up', 'facch', bytes.fromhex('01' '03' '0d' '061261')))
    ok.append(rec('down', 'sacch', bytes.fromhex('01' '03') + REL, arfcn=40, seq=13, bsic=5, error=0, shift=0))
    ok.append(rec('up', 'sacch', bytes.fromhex('01' '03' '0d' '061261')))
    # data from <l2>: a header is added; B format (SDCCH/SACCH/FACCH, an RR
    # supervisory frame) and Bbis (other channels, a length octet)
    ok.append(rec('up', 'sdcch', l2=b''))
    ok.append(rec('up', 'sacch', l2=b''))
    ok.append(rec('up', 'facch', l2=b''))
    ok.append(rec('up', 'ccch', l2=bytes.fromhex('0603')))
    ok.append(rec('down', 'ccch', l2=PAG1, arfcn=41, seq=14, bsic=6, error=0, shift=0))
    # an unknown logical channel is shown as data
    ok.append(rec('down', 'unknown', bytes.fromhex('0123456789'), arfcn=1, seq=1, bsic=1, error=1, shift=1))
    ok.append(rec('up', 'unknown', bytes.fromhex('0123456789')))
    # a record without any direction is uplink; extreme attribute values
    ok.append('<l1 logicalchannel="96" data="0a"></l1>\n')
    ok.append(rec('down', 'bcch', ccch(SI3[:22], 22), arfcn=1023, seq=2147483647, bsic=63, error=255, shift=65535))
    # Not in the main capture: a pseudo length beyond the block
    bad.append(rec('down', 'ccch', pad(bytes([0xfc]) + b'\x06\x21'), arfcn=1, seq=1, bsic=1, error=0, shift=0))
    bad.append(rec('down', 'ccch', bytes([0x7d, 0x06]), arfcn=1, seq=1, bsic=1, error=0, shift=0))
    # LAPDm with a truncated frame
    bad.append(rec('down', 'sdcch', bytes([0x01]), arfcn=1, seq=1, bsic=1, error=0, shift=0))
    bad.append(rec('up', 'facch', bytes([0x01, 0x03, 0x3f]), ))
    bad.append(rec('up', 'sdcch', bytes([0x01, 0x03, 0x03, 0x05, 0x06])))
    open(out + '/gsm_um-coverage.xml', 'w').write(doc(ok))
    open(out + '/gsm_um-coverage-malformed.xml', 'w').write(doc(bad))
    # Exported PDU naming gsm_um: the record has no GSM Um pseudo header, so
    # the dissector reads the channel and direction from unrelated data
    # (pcap, link type Exported PDU)
    write_pcap(out + '/gsm_um-coverage-exported-pdu.pcap',
               [exp_pdu('gsm_um', bytes([0x31, 0x06, 0x3f]) + b'\x2b' * 20),
                exp_pdu('gsm_um', b'\x01\x03\x01' + b'\x2b' * 20)], 252)
    print(len(ok), len(bad))

main(sys.argv[1] if len(sys.argv) > 1 else '.')
