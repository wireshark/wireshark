#!/usr/bin/env python3
# Generates test/captures/lixer_more_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generator for the extra LI_XER (TS 33.128 identity association) coverage
# capture. usage: mklixer.py <outdir>
# Writes lixer_more_coverage.pcapng (and lixer-coverage-malformed.pcapng, for
# the coverage number only). Every packet is built here with struct; the
# capture has two interfaces: Ethernet (the IEF to ICF TCP stream on port
# 40001, which only Decode As gives to LI_XER) and Exported PDU (the
# registered dissector "lixer"). No TLS, no keys, no ciphertext.
import struct
import sys
import os

def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    lb = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([tag, 0x80 | len(lb)]) + lb + body

def indef(tag, body):
    return bytes([tag, 0x80]) + body + b'\0\0'

GT = b'20261108120000Z'
OID = tlv(0x81, b'\x04\x14\x12\x00\x01')

def ncgi(nci=b'\x04\x12\x34\x56\x78\x90', plmn=b'\x00\xf1\x10'):
    return tlv(0xa5, tlv(0x81, plmn) + tlv(0x82, nci))

def assoc(pei, nci=b'\x04\x12\x34\x56\x78\x90', gpsi=b''):
    rec = (tlv(0xa1, tlv(0x81, b'001010123456789')) +
           tlv(0x82, b'\x00\xf1\x10\x01\x00\x41\x12\x34\x56\x78') +
           tlv(0x83, GT) + tlv(0x84, b'\x00\xf1\x10\x00\x00\x01') +
           ncgi(nci) + tlv(0x86, GT) + pei + gpsi)
    return rec

def msg(rec, wrap=tlv):
    return wrap(0x30, OID + tlv(0xa2, tlv(0xa1, rec)))

IMEISV = tlv(0xa8, tlv(0x82, b'3512345678901234'))
EUI64 = tlv(0xa8, tlv(0x84, b'\x02\x00\x00\xff\xfe\x00\x00\x01'))

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

CLI, SRV = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])

def tcp_pkt(src, dst, sport, dport, seq, ack, flags, payload=b''):
    opts = b'\x02\x04\x05\xb4\x04\x02\x01\x01\x01\x03\x03\x07' if flags & 0x02 else b''
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
    ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
    c = csum(ph + tcp + payload)
    tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 0, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    c_mac, s_mac = b'\x02\0\0\0\0\x01', b'\x02\0\0\0\0\x02'
    eth = (s_mac + c_mac if src == SRV else c_mac + s_mac) + b'\x08\x00'
    return eth + ip + tcp + payload

def exported_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload

class Cap:
    def __init__(self):
        self.frames = []   # (linktype index, bytes)
        self.port = 50000

    def exported(self, name, payload):
        self.frames.append((1, exported_pdu(name, payload)))

    def stream(self, segments):
        """A TCP connection to port 40001 sending the segments from the IEF"""
        self.port += 1
        sp = self.port
        c, s = 1000, 5000
        self.frames.append((0, tcp_pkt(CLI, SRV, sp, 40001, c, 0, 0x02)))
        self.frames.append((0, tcp_pkt(SRV, CLI, 40001, sp, s, c + 1, 0x12)))
        c += 1; s += 1
        for seg in segments:
            self.frames.append((0, tcp_pkt(CLI, SRV, sp, 40001, c, s, 0x18, seg)))
            c += len(seg)

    def write(self, fn):
        def blk(t, body):
            body += b'\0' * (-len(body) % 4)
            return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
        with open(fn, 'wb') as f:
            f.write(blk(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1)))
            f.write(blk(1, struct.pack('<HHI', 1, 0, 65535)))
            f.write(blk(1, struct.pack('<HHI', 252, 0, 65535)))
            for i, (ifc, p) in enumerate(self.frames):
                ts = (1794139200 + i) * 1000000
                f.write(blk(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(p), len(p)) + p))
        return len(self.frames)

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    m = Cap()
    imeisv = msg(assoc(IMEISV))
    eui64 = msg(assoc(EUI64, gpsi=tlv(0xaa, tlv(0x82, b'user@' + b'x' * 60 + b'.example.com'))))
    # 1-2: Exported PDU naming "lixer" (reached without Decode As): IMEISV, EUI-64
    m.exported('lixer', imeisv)
    m.exported('lixer', eui64)
    # 3-8: TCP stream: the IMEISV one as one segment, the EUI-64 one split inside its
    # length octets (the length cannot be read yet), then the same split in the value
    long_form = eui64
    assert long_form[1] in (0x81, 0x82)
    m.stream([imeisv, long_form[:2], long_form[2:]])
    # an IEFMessage with the indefinite length form, complete in one segment, with an
    # IMEISV; in a second stream followed by a definite length one in its own segment
    ind = msg(assoc(IMEISV, gpsi=tlv(0xaa, tlv(0x81, b'46701234567'))), wrap=indef)
    m.stream([ind])
    m.stream([ind, eui64])
    # Reproducer of "BER: Check the field before adding an empty bit string": an NCI
    # that is an empty BIT STRING (82 01 00); a clean frame before it
    m.exported('lixer', msg(assoc(IMEISV, nci=b'\x04\x12\x34\x56\x78\x90')))
    m.exported('lixer', msg(assoc(IMEISV, nci=b'\x00')))
    # Reproducer of "LI_XER: Do not walk an indefinite-length message for its length": an
    # indefinite IEFMessage that never ends, then small TLVs in many segments
    segs = [b'\x30\x80' + b'\x04\x00' * 2] + [b'\x04\x00' * 2 for _ in range(7)]
    m.stream(segs)
    n = m.write(os.path.join(out, 'lixer_more_coverage.pcapng'))
    print('lixer_more_coverage.pcapng', n, 'frames')

    # malformed capture (coverage number only)
    x = Cap()
    x.stream([imeisv[:1]])                      # one octet: below the minimum PDU size
    x.stream([imeisv[:2] + imeisv[2:20]])       # truncated
    x.stream([b'\x30\x84\xff\xff\xff\xff' + imeisv[6:]])   # a length that is too large
    x.stream([b'\x30\x80'])                     # indefinite length without any content
    x.stream([b'\x30'])
    x.exported('lixer', b'\x30\x80\x00\x00')
    x.exported('lixer', msg(assoc(EUI64, nci=b'\x04\x12\x34\x56\x78\x90\xaa')))
    x.exported('lixer', msg(assoc(IMEISV, nci=b'\x07\x12\x34\x56\x78\x90')))
    # IMEISV / EUI64 / MAC / IMEI of the wrong size
    x.exported('lixer', msg(assoc(tlv(0xa8, tlv(0x82, b'35123')))))
    x.exported('lixer', msg(assoc(tlv(0xa8, tlv(0x84, b'\x01\x02')))))
    n = x.write(os.path.join(out, 'lixer-coverage-malformed.pcapng'))
    print('lixer-coverage-malformed.pcapng', n, 'frames')

main()
