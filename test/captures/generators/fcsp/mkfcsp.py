# Generates test/captures/fcsp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ---- common helpers (synthetic data only) ----
import struct
import sys
import os
import zlib

def pcap(fname, frames, linktype=1):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            wl = len(fr)
            if isinstance(fr, tuple):
                fr, wl = fr
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(fr), wl))
            f.write(fr)

def eth(payload, ethertype, src=1, dst=2):
    return (bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) +
            struct.pack('>H', ethertype) + payload)

def fchdr(r_ctl, d_id, s_id, ftype, f_ctl, oxid, rxid=0xffff, seq_id=0, seqcnt=0, param=0, df_ctl=0, cs_ctl=0):
    return (bytes([r_ctl]) + d_id + bytes([cs_ctl]) + s_id + bytes([ftype]) +
            struct.pack('>I', f_ctl)[1:] + bytes([seq_id, df_ctl]) +
            struct.pack('>HHHI', seqcnt, oxid, rxid, param))

def fcoe(fc, sof=0x2E, eof=0x42, crc=None, ver=0):
    hdr = bytes([ver << 4]) + bytes(12) + bytes([sof])
    if crc is None:
        crc = zlib.crc32(fc) & 0xffffffff
    return eth(hdr + fc + struct.pack('<I', crc) + bytes([eof, 0, 0, 0]), 0x8906)

A = bytes([0x01, 0x02, 0x03])
B = bytes([0x01, 0x04, 0x05])
FIRST = 0x200000
LAST = 0x100000
SEQLAST = 0x080000
RESP = 0x800000
# ---- end common helpers ----
#!/usr/bin/env python3
# Generator for the FC-SP coverage captures.  Usage: mkfcsp.py <outdir>
# Writes fcsp-coverage.pcap (clean) and fcsp-coverage-malformed.pcap.
# FC-SP is reached through an ELS AUTH_ELS request (FC type 0x01, opcode 0x90)
# and through an SW_ILS AUTH_ILS request (FC type 0x22, opcode 0x40), both
# carried over FCoE.

ox = [0x2000]
TID = [1]

def msg(first, code, body=b'', flags=0, ver=1, length=None):
    tid = TID[0]
    TID[0] += 1
    return bytes([first, flags, code, ver]) + struct.pack('>II', 12 + len(body) if length is None else length, tid) + body

def wwn_name(w=b'\x10\x00\x00\x00\xc9\x12\x34\x56', typ=1):
    return struct.pack('>HH', typ, len(w)) + w

def hashlist(*h):
    return struct.pack('>HH', 1, len(h)) + b''.join(struct.pack('>I', x) for x in h)

def dhgids(*g):
    return struct.pack('>HH', 2, len(g)) + b''.join(struct.pack('>I', x) for x in g)

def proto(ptype, params=b''):
    return struct.pack('>II', 4 + len(params), ptype) + params

def negotiate(first, protos, name=None, nprotos=None):
    return msg(first, 0x0B, (name or wwn_name()) + struct.pack('>I', len(protos) if nprotos is None else nprotos) + b''.join(protos))

def els(payload, resp=False):
    if resp:
        # the response to the request just sent (same exchange)
        return fcoe(fchdr(0x23, A, B, 0x01, RESP | LAST | SEQLAST, ox[0], 0x3000) + payload)
    ox[0] += 1
    return fcoe(fchdr(0x22, B, A, 0x01, FIRST | SEQLAST | 0x010000, ox[0]) + payload)

def ils(payload):
    ox[0] += 1
    return fcoe(fchdr(0x02, B, A, 0x22, FIRST | SEQLAST | 0x010000, ox[0]) + payload)

def build():
    f = []
    # AUTH_Negotiate: DH-CHAP with hash and group lists, FCAP, an unknown protocol
    f.append(els(negotiate(0x90, [proto(1, hashlist(5, 6) + dhgids(0, 1, 2, 3, 4)), proto(2), proto(9, b'abcd')])))
    # DH-CHAP with an unknown parameter tag of length 0 (stops the list) and a non-zero length
    f.append(els(negotiate(0x90, [proto(1, hashlist(5) + struct.pack('>HH', 7, 0))])))
    f.append(els(negotiate(0x90, [proto(1, struct.pack('>HH', 7, 1) + bytes(4) + dhgids(1))])))
    # a name that is not a WWN
    f.append(els(negotiate(0x90, [proto(1, hashlist(6))], name=wwn_name(b'initiator1', 2))))
    # no protocols
    f.append(els(negotiate(0x90, [])))
    # SW_ILS AUTH_ILS carrying the same messages
    f.append(ils(negotiate(0x40, [proto(1, hashlist(5, 6) + dhgids(1, 2)), proto(2)])))
    # AUTH_Reject with each code and detail
    for code, det in ((1, 1), (1, 5), (2, 6), (2, 8), (9, 0x42)):
        f.append(els(msg(0x90, 0x0A, bytes([code, det, 0, 0]))))
    f.append(ils(msg(0x40, 0x0A, bytes([1, 3, 0, 0]))))
    # AUTH_Done
    f.append(els(msg(0x90, 0x0C, bytes(8))))
    # DH-CHAP_Challenge: WWN and other name type; with and without a DH value
    def challenge(name, chal, dhv, h=5, g=1):
        return (name + struct.pack('>II', h, g) + struct.pack('>I', len(chal)) + chal +
                struct.pack('>I', len(dhv)) + dhv)
    f.append(els(msg(0x90, 0x10, challenge(wwn_name(), bytes(range(16)), bytes(range(32))))))
    f.append(els(msg(0x90, 0x10, challenge(wwn_name(b'responder', 2), bytes(16), b'', 6, 0))))
    # DH-CHAP_Reply
    def reply(rsp, dhv, chal):
        return (struct.pack('>I', len(rsp)) + rsp + struct.pack('>I', len(dhv)) + dhv +
                struct.pack('>I', len(chal)) + chal)
    f.append(els(msg(0x90, 0x11, reply(bytes(range(16)), bytes(range(32)), bytes(range(16, 32))))))
    f.append(els(msg(0x90, 0x11, reply(bytes(16), b'', b''))))
    # DH-CHAP_Success
    f.append(els(msg(0x90, 0x12, struct.pack('>I', 16) + bytes(range(16)))))
    f.append(els(msg(0x90, 0x12, struct.pack('>I', 0))))
    # FCAP / FCPAP messages are not decoded
    for code in (0x13, 0x14, 0x15, 0x16, 0x17, 0x18):
        f.append(els(msg(0x90, code, bytes(range(12)))))
    # unknown message code
    f.append(els(msg(0x90, 0x99, bytes(4))))
    # an AUTH_ELS response is dissected by the ELS dissector only
    f.append(els(bytes([0x02, 0, 0, 0]) + bytes(8), resp=True))
    # flags, version and length fields
    f.append(els(msg(0x90, 0x0C, bytes(8), flags=0x80, ver=2, length=0xFFFF)))
    # a parameter length of exactly the rest of the packet is accepted
    f.append(els(msg(0x90, 0x0B, wwn_name() + struct.pack('>I', 1) + struct.pack('>I', 8) + struct.pack('>II', 2, 0))))
    return f

def main(out):
    pcap(os.path.join(out, 'fcsp-coverage.pcap'), build())

    bad = []
    # Reproducers of "FCSP: Fix negotiate loop and subtree placement": the
    # parameter length wraps the offset back (0xFFFFFFFC) or is simply too long
    for plen in (0xFFFFFFFC, 0xFFFFFFFF, 0x7FFFFFFF, 200):
        bad.append(els(msg(0x90, 0x0B, wwn_name() + struct.pack('>I', 0xFFFFFFFF) + struct.pack('>I', plen))))
        bad.append(ils(msg(0x40, 0x0B, wwn_name() + struct.pack('>I', 2) + struct.pack('>I', plen))))
    # a bad length with some data after it (the expert info is added without an exception)
    bad.append(els(msg(0x90, 0x0B, wwn_name() + struct.pack('>I', 2) + struct.pack('>I', 200) + bytes(12))))
    # second protocol with a bad length after a good one
    bad.append(els(negotiate(0x90, [proto(1, hashlist(5))], nprotos=3) + struct.pack('>I', 100)))
    # truncated messages
    for code, n in ((0x0A, 13), (0x0B, 20), (0x0B, 30), (0x10, 20), (0x10, 40), (0x11, 14), (0x12, 14), (0x13, 12)):
        m = msg(0x90, code, bytes(60))
        bad.append(els(m[:n]))
    # DH-CHAP challenge with lengths beyond the packet
    bad.append(els(msg(0x90, 0x10, wwn_name() + struct.pack('>IIII', 5, 1, 0x1000, 0))))
    bad.append(els(msg(0x90, 0x11, struct.pack('>I', 0xFFFFFFF0) + bytes(8))))
    # AUTH message shorter than the header (FC-SP reads the message code)
    bad.append(els(bytes([0x90, 0])))
    pcap(os.path.join(out, 'fcsp-coverage-malformed.pcap'), bad)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
