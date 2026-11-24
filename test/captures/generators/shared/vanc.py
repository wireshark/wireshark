# Shared helper module for the capture generators in test/captures/generators
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""ST 291 ANC packet helpers: 10 bit words with parity, checksum, packing."""


def par(b):
    """10 bit word for an 8 bit value: b8 = even parity, b9 = not b8."""
    b8 = bin(b & 0xff).count('1') & 1
    return (b & 0xff) | (b8 << 8) | ((b8 ^ 1) << 9)


def anc_words(did, sdid, udw, bad_did=False, bad_sdid=False, bad_dc=False,
              bad_cs=False, raw_udw=None):
    """Words DID, SDID/DBN, DC, UDW..., CS. udw: list of 8 bit values
    (or raw 10 bit words with raw_udw)."""
    w = [par(did), par(sdid), par(len(udw) if raw_udw is None else len(raw_udw))]
    if bad_did:
        w[0] ^= 0x200
    if bad_sdid:
        w[1] ^= 0x200
    if bad_dc:
        w[2] ^= 0x100
    w += list(raw_udw) if raw_udw is not None else [par(u) for u in udw]
    cs = sum(x & 0x1ff for x in w) & 0x1ff
    if not cs & 0x100:
        cs |= 0x200
    if bad_cs:
        cs ^= 1
    return w + [cs]


def bits(words):
    """Concatenate 10 bit words into a bit string."""
    return ''.join(format(x, '010b') for x in words)


def tobytes(bitstr, pad='0'):
    bitstr += pad * ((-len(bitstr)) % 8)
    return bytes(int(bitstr[i:i + 8], 2) for i in range(0, len(bitstr), 8))


# ready-made user data words
def timecode(h=12, m=34, s=56, f=7, drop=False):
    """ST 12-2 ancillary time code: 16 UDWs, the BCD digits in b7..b4 of
    UDW 1, 3, 5, 7, 9, 11, 13, 15 (the other UDWs hold binary groups)."""
    return [(f % 10) << 4, 0, ((f // 10) << 4) | (0x40 if drop else 0), 0,
            (s % 10) << 4, 0, (s // 10) << 4, 0,
            (m % 10) << 4, 0, (m // 10) << 4, 0,
            (h % 10) << 4, 0, (h // 10) << 4, 0]


def afd(code=8, ar=1):
    return [(code << 3) | (ar << 2), 0, 0, 0, 0, 0, 0, 0]


def cdp(seq=0x1234, rate=7, timecode_present=True, nflags_extra=0):
    """A valid ST 334-2 CDP: header, time code section, CC data section
    with the count the frame rate code requires, footer with checksum."""
    counts = {1: 25, 2: 25, 3: 24, 4: 20, 5: 20, 6: 12, 7: 10, 8: 10}
    n = counts[rate]
    flags = 0x40 | 0x01 | (0x80 if timecode_present else 0) | 0x02
    body = b''
    if timecode_present:
        body += bytes([0x71, 0xc0 | 0x12, 0x34, 0x56 | 0x80, 0x07])
    body += bytes([0x72, 0xe0 | n]) + b''.join(bytes([0xfc, 0x80 + i, 0x80]) for i in range(n))
    length = 7 + len(body) + 4
    hdr = bytes([0x96, 0x69, length, (rate << 4) | 0x0f, flags]) + seq.to_bytes(2, 'big')
    ft = bytes([0x74]) + seq.to_bytes(2, 'big')
    s = hdr + body + ft
    return list(s + bytes([(-sum(s)) & 0xff]))
