#!/usr/bin/env python3
# Generates the mime_encap captures in test/captures
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MIME_FILE (WTAP_ENCAP_MIME) coverage files. Usage: mkmime_encap.py <outdir>
MIME_FILE is not a packet protocol: the "capture file" is the file itself, a
GIF, PNG, ... that wiretap's MIME file reader recognizes by its magic number.
Everything is synthetic (a 1x1 GIF and similar tiny files)."""
import struct
import sys
import os
import zlib

def gif():
    # GIF89a, 1x1, global colour table of 2 entries, one image, trailer
    hdr = b'GIF89a' + struct.pack('<HHBBB', 1, 1, 0x80, 0, 0) + bytes([0, 0, 0, 255, 255, 255])
    img = b'\x2c' + struct.pack('<HHHHB', 0, 0, 1, 1, 0) + b'\x02\x02\x44\x01\x00'
    return hdr + img + b'\x3b'

def png():
    def chunk(t, d):
        c = struct.pack('>I', len(d)) + t + d
        return c + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 0, 0, 0, 0)) +
            chunk(b'IDAT', zlib.compress(b'\x00\x00')) + chunk(b'IEND', b''))

def xml():
    return b'<?xml version="1.0" encoding="UTF-8"?>\n<root xmlns="urn:example:mime"><item id="1">text</item></root>\n'

FILES = {
    'mime-coverage.gif': gif,          # the main file: claimed by the GIF heuristic
    'mime-coverage.png': png,
    'mime-coverage.xml': xml,
    # magic numbers the MIME file reader accepts but that no heuristic dissector claims
    'mime-unhandled.elf': lambda: b'\x7fELF' + bytes(12),
    'mime-unhandled.ogg': lambda: b'OggS' + bytes(4),
    'mime-unhandled.zip': lambda: b'PK\x03\x04' + bytes(8),
    'mime-unhandled.tiff': lambda: b'II*\x00' + bytes(4),
}

if __name__ == '__main__':
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    for n, f in FILES.items():
        open(os.path.join(out, n), 'wb').write(f())
