#!/usr/bin/env python3
# Generates test/captures/rfc7468_coverage.pcap.gz, rfc7468_coverage.pem.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the synthetic RFC 7468 (PEM) coverage files for file-rfc7468.c.

usage: mkrfc7468.py <outdir> [-v]
rfc7468-coverage.pem (main), more files (CRLF, explanatory text, blank
lines, labels with a registered dissector), the HTTP capture
rfc7468-coverage-http.pcap (media type application/pem-certificate-chain)
and rfc7468-coverage-malformed.pcap.  The base64 data is a few made-up
BER structures, not a real key or certificate.
"""
import base64
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'
VERBOSE = '-v' in sys.argv


def w(name, data):
    with open(os.path.join(OUT, name), 'wb') as f:
        f.write(data)
    if VERBOSE:
        print(name, len(data))


def tlv(tag, body):
    assert len(body) < 128
    return bytes([tag, len(body)]) + body


# BER: SEQUENCE { INTEGER 1, OCTET STRING "test", UTF8String "synthetic" }
BER = tlv(0x30, tlv(2, b'\x01') + tlv(4, b'test') + tlv(0x0c, b'synthetic'))
# CMS ContentInfo: SEQUENCE { OID 1.2.840.113549.1.7.1 (data), [0] { OCTET STRING } }
CMS = tlv(0x30, tlv(6, bytes.fromhex('2a864886f70d010701')) + tlv(0xa0, tlv(4, b'hello')))


def pem(label, der, width=64, eol=b'\n', post_label=None):
    b64 = base64.b64encode(der)
    lines = [b64[i:i + width] for i in range(0, len(b64), width)]
    return (b'-----BEGIN ' + label.encode() + b'-----' + eol + eol.join(lines) + eol
            + b'-----END ' + (post_label or label).encode() + b'-----' + eol)


main = pem('TEST DATA', BER * 3, 16)
w('rfc7468-coverage.pem', main)
w('rfc7468-coverage-crlf.pem', pem('TEST DATA', BER, 8, b'\r\n'))
# explanatory text before the boundary, blank lines (space, tab) before the data
w('rfc7468-coverage-text.pem',
  b'Subject: synthetic\nIssuer: nobody\n\n' + b'-----BEGIN DATA-----\n \n\t\n' + base64.b64encode(BER) + b'\n-----END DATA-----\ntrailing text\n')
# labels with a registered dissector
w('rfc7468-coverage-cms.pem', pem('CMS', CMS))
w('rfc7468-coverage-nodata.pem', b'-----BEGIN EMPTY-----\n-----END EMPTY-----\n')
# a single base64 line, a label with spaces and punctuation
w('rfc7468-coverage-label.pem', pem('X-ODD LABEL (1)', BER, 76))
# reproducer of the fix: many short base64 lines (the old code grew the
# buffer once per line; the original has 100000 lines)
# (a BER OCTET STRING of 8996 octets, base64 in 3000 lines of 4 characters)
LINES = base64.b64encode(b'\x04\x82' + struct.pack('>H', 8996) + b'\0' * 8996)
assert len(LINES) == 12000
w('rfc7468-coverage-lines.pem', b'-----BEGIN DATA-----\n' + b'\n'.join(
    LINES[i:i + 4] for i in range(0, len(LINES), 4)) + b'\n-----END DATA-----\n')
# lines of 1, 2 and 3 base64 characters: the decoder state spans lines
w('rfc7468-coverage-split.pem', b'-----BEGIN SPLIT-----\n' + b'\n'.join(
    base64.b64encode(BER)[i:i + 3] for i in range(0, len(base64.b64encode(BER)), 3)) + b'\n-----END SPLIT-----\n')

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def http_pcap(fname, responses):
    """responses: list of (content type or None, body, extra header)"""
    out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
    ts = 0
    for k, (ctype, body) in enumerate(responses):
        hdr = 'HTTP/1.1 200 OK\r\n'
        if ctype:
            hdr += 'Content-Type: %s\r\n' % ctype
        hdr += 'Content-Length: %d\r\n\r\n' % len(body)
        data = hdr.encode() + body
        seq = 1000
        sport = 40000 + k
        for i in range(0, len(data), 1400):
            segd = data[i:i + 1400]
            src, dst = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
            tcp = struct.pack('!HHIIBBHHH', 80, sport, seq, 1, 0x50, 0x18, 65535, 0, 0)
            ph = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(segd))
            tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp + segd)) + tcp[18:]
            ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(segd), 1, 0, 64, 6, 0, src, dst)
            ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
            pkt = b'\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00' + ip + tcp + segd
            out.append(struct.pack('<IIII', 1, ts, len(pkt), len(pkt)) + pkt)
            ts += 1
            seq += len(segd)
    open(os.path.join(OUT, fname), 'wb').write(b''.join(out))
    if VERBOSE:
        print(fname, len(responses), 'responses')
http_pcap('rfc7468-coverage-http.pcap', [
    ('application/pem-certificate-chain', main),
    ('application/pem-certificate-chain', pem('CMS', CMS)),
    ('application/pem-certificate-chain', b'Some text\n' + pem('TEST DATA', BER, 16)),
    ('application/pem-certificate-chain', b'-----BEGIN EMPTY-----\n-----END EMPTY-----\n'),
    ('application/pem-certificate-chain', open(os.path.join(OUT, 'rfc7468-coverage-lines.pem'), 'rb').read()),
    (None, pem('TEST DATA', BER, 16)),      # no media type: not claimed over HTTP
    # explanatory text, blank lines (space, tab) before the data and text after the file
    ('application/pem-certificate-chain', open(os.path.join(OUT, 'rfc7468-coverage-text.pem'), 'rb').read()),
])

bad = []
# no END line: the data is never decoded
bad.append(('noend', b'-----BEGIN DATA-----\n' + base64.b64encode(BER) + b'\n'))
# BEGIN line without a line end, text without any boundary, text only
bad.append(('noeol', b'-----BEGIN DATA-----'))
bad.append(('noeol2', b'-----BEGIN DATA-----\nQUJD'))
bad.append(('noeol3', b'-----BEGIN DATA-----\nQUJD\nQUJD'))     # last data line without a line end
bad.append(('label-space', b'-----BEGIN  DATA-----\nQUJD\n-----END DATA-----\n'))   # label starts with a space
bad.append(('label-dash', b'-----BEGIN -DATA-----\nQUJD\n-----END DATA-----\n'))
bad.append(('noboundary', b'line one\nline two\nline three\n'))
bad.append(('noboundary-eol', b'line one\nline two\nno end'))
# boundary-looking lines that are not: no suffix, too short, non-printable label
bad.append(('badeb', b'-----BEGIN DATA----\nQUJD\n-----END DATA-----\n'))
bad.append(('badlabel', b'-----BEGIN DA\x01TA-----\nQUJD\n-----END DATA-----\n'))
bad.append(('short', b'-----BEGIN -----\nQUJD\n-----END -----\n'))
bad.append(('noprefix', b'BEGIN DATA-----\nQUJD\n-----END DATA-----\n'))
# blank lines up to the end of the file
bad.append(('blanks', b'-----BEGIN DATA-----\n \n \n'))
# invalid base64 characters, base64 that is not BER, an END label that differs
bad.append(('badb64', b'-----BEGIN DATA-----\n!!!!****\n-----END DATA-----\n'))
bad.append(('notber', pem('DATA', b'this is plain text, not BER')))
bad.append(('endlabel', pem('DATA', BER, post_label='OTHER')))
# CMS label with data that is not a ContentInfo
bad.append(('cms-junk', pem('CMS', b'\x01\x02\x03\x04')))
# the quadratic reproducer, larger
bad.append(('lines', b'-----BEGIN CERTIFICATE-----\n' + b'AAAA\n' * 30000 + b'-----END CERTIFICATE-----\n'))
for n_, d in bad:
    if n_ != 'lines':
        w('rfc7468-bad-%s.pem' % n_, d)
http_pcap('rfc7468-coverage-malformed.pcap', [
    ('application/pem-certificate-chain', d) for n_, d in bad])
