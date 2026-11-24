# Helper module for the gquic capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Python port of is_gquic_unencrypt() for versions >= 34 (generator helper, not a test)
import struct
L4 = {0: 1, 1: 2, 2: 4, 3: 6}
OOO = [0, 2, 3, 4, 5, 6, 7, 8]
def walk(b, offset, len_pkn, enc='>'):
    n = len(b)
    rem = lambda o: n - o
    if rem(offset) <= 13: return False
    offset += 12
    while rem(offset) > 0:
        if rem(offset) <= 1: return False
        ft = b[offset]
        if ft & 0xE0 == 0:
            offset += 1
            if ft == 0: return False
            elif ft == 1: offset += 16
            elif ft == 2:
                offset += 4
                if rem(offset) <= 2: return False
                lr = struct.unpack(enc + 'H', b[offset:offset+2])[0]; offset += 2
                if rem(offset) == lr: return True
            elif ft == 3:
                offset += 8
                if rem(offset) <= 2: return False
                lr = struct.unpack(enc + 'H', b[offset:offset+2])[0]; offset += 2 + lr
            elif ft == 4: offset += 12
            elif ft == 5: offset += 4
            elif ft == 6: offset += len_pkn
        else:
            if ft & 0x80:
                ld = 2 if ft & 0x20 else 0
                lo = OOO[(ft & 0x1c) >> 2]; ls = (ft & 3) + 1
                offset += 1 + ls + lo + ld
                if rem(offset) <= 4: return False
                tag = b[offset:offset+4]
                if tag in (b'CHLO', b'SHLO', b'REJ\0'): return True
            elif ft & 0x40:
                ll = L4[(ft & 0x0c) >> 2]; mm = L4[ft & 3]
                offset += 1 + ll + 2
                nb = 0
                if ft & 0x20:
                    if rem(offset) <= 1: return False
                    nb = b[offset]; offset += 1
                offset += mm
                if nb: offset += nb * (1 + mm)
                if rem(offset) <= 1: return False
                nt = b[offset]; offset += 1
                if nt > 0: offset += 1 + 4 + (nt - 1) * 3
            else:
                offset += 1
    return False
