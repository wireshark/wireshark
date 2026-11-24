#!/usr/bin/env python3
# Generates test/captures/mux27010_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the MUX27010 coverage captures. Usage: mkmux27010.py <outdir>
mux27010-coverage.pcap            main capture, LINKTYPE_MUX27010 (236)
mux27010-coverage-malformed.pcap  bad FCS, illogical extended header, short and odd frames
Everything is synthetic."""
import struct
import sys
import os

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'

def make_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xE0 if c & 1 else c >> 1
        t.append(c)
    return t
TABLE = make_table()

def fcs(data):
    f = 0xFF
    for b in data:
        f = TABLE[f ^ b]
    return 0xFF - f

def addr(dlci, cr=1, ea=1):
    return bytes([dlci << 2 | cr << 1 | ea])

def length(n, ea=True):
    if ea:
        return bytes([n << 1 | 1])
    return struct.pack('<H', n << 1)           # two octets, EA = 0 in the first

SABM, UA, DM, DISC, UIH = 0x2F, 0x63, 0x0F, 0x43, 0xEF

def ext_entry(seqid, num, start, end, more):
    return struct.pack('>HHBBB', seqid, num, start, end, more)

def frame(direction, dlci, control, info=b'', pf=1, cr=1, ext=b'', ea_len=True, bad_fcs=False,
          nolen=False, cc_len_override=None):
    ctrl = control | (0x10 if pf else 0)
    body = addr(dlci, cr) + bytes([ctrl])
    if not nolen:
        body += length(len(info), ea_len)
    f = fcs(body) ^ (0x55 if bad_fcs else 0)
    return bytes([len(ext)]) + ext + bytes([direction, 0xF9]) + body + info + bytes([f])

def cc(cmd, values=b'', cr=1, type_ext=False, len_ext=False):
    """Control channel message: type octet(s), length octet(s), values."""
    t = bytes([cmd | cr << 1 | (0 if type_ext else 1)])
    if type_ext:
        t += b'\x01'
    ln = bytes([len(values) << 1 | 1])
    if len_ext:
        ln = bytes([(len(values) << 1) & 0xfe]) + b'\x01'
    return t + ln + values

def ctl(direction, info, **kw):
    return frame(direction, 0, UIH, info, **kw)

def ppp_lcp_echo(ident=1, magic=0x01020304):
    return bytes.fromhex('c021') + bytes([9, ident]) + struct.pack('>HI', 8, magic)

def write(name, pkts):
    with open(os.path.join(OUT, name), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 236))
        for i, p in enumerate(pkts):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)))
            f.write(p)

CMD_CLD, CMD_TEST, CMD_PSC, CMD_NSC, CMD_MSC, CMD_PN = 0xC0, 0x20, 0x40, 0x10, 0xE0, 0x80

def main():
    p = []
    A = p.append
    # ---- setup of the channels: SABM / UA / DM / DISC on DLCI 0 and 1, both directions
    A(frame(0, 0, SABM))
    A(frame(1, 0, UA))
    A(frame(0, 1, SABM))
    A(frame(1, 1, UA))
    A(frame(1, 2, DM))
    A(frame(0, 1, DISC))
    A(frame(1, 1, UA))
    A(frame(0, 1, SABM, pf=0))
    # ---- control channel
    A(ctl(0, cc(CMD_TEST, b'\x08' + b'TESTDATA')))                       # test command, TE version IEI
    A(ctl(1, cc(CMD_TEST, b'\x04' + b'MS', cr=0)))                       # response, MS IEI
    A(ctl(0, cc(CMD_TEST, b'\x01' + b'plain')))                          # version without IEI coding
    A(ctl(0, cc(CMD_PSC, b'\x01')))                                      # power saving control command
    A(ctl(1, cc(CMD_PSC, b'\x00', cr=0)))                                # response: failure
    A(ctl(1, cc(CMD_PSC, b'\x01', cr=0)))                                # response: success
    A(ctl(1, cc(CMD_PSC, b'\x02', cr=0)))                                # response, other value
    A(ctl(1, cc(CMD_NSC, b'\x23', cr=0)))                                # non-supported command response
    A(ctl(0, cc(CMD_MSC, bytes([1 << 2 | 3, 0x8d]))))                    # modem status: DLCI 1, FC/RTC/RTR/DCD
    A(ctl(0, cc(CMD_MSC, bytes([2 << 2 | 3, 0x52, 0x01]))))              # with the break octet
    A(ctl(0, cc(CMD_PN, bytes([1, 0xf0 | 0, 7, 10, 0x00, 0x7f, 3, 2]))))  # parameter negotiation
    A(ctl(1, cc(CMD_PN, bytes([1, 0x00, 7, 10, 0x40, 0x00, 3, 2]), cr=0)))
    A(ctl(0, cc(CMD_CLD, b'')))                                          # multiplexer close-down
    A(ctl(0, cc(0x30, b'\x00')))                                         # unknown command
    # ---- data channel, plain information (AT commands) with all frame types
    A(frame(0, 1, UIH, b'AT+CGMI\r\n'))
    A(frame(1, 1, UIH, b'\r\nACME Modem\r\n\r\nOK\r\n'))
    A(frame(0, 2, UIH, b'ATD*99#\r', pf=0))
    A(frame(1, 2, UIH, b'x' * 130, ea_len=False))                         # length > 127: two octet length
    A(frame(0, 3, 0x02 | 0x20, b'I-frame data'))                          # UIH_E: N(S)=1 N(R)=1
    A(frame(0, 3, 0x0C | 0xC0, b'more data'))
    A(frame(1, 3, 0x01 | 0x40, nolen=True, info=b''))                      # RR
    A(frame(1, 3, 0x05 | 0xA0, nolen=True, info=b''))                      # RNR
    A(frame(1, 3, 0x09 | 0x60, nolen=True, info=b''))                      # REJ
    A(frame(0, 3, 0x03, b'unknown frame type'))                           # unknown control
    A(frame(2, 1, UIH, b'direction 2'))                                   # invalid direction
    A(frame(3, 1, UIH, b'direction 3', cr=0))
    A(frame(0, 63, UIH, b''))                                             # no information, highest DLCI
    # ---- extended header (PPP over a data channel): three messages, one split in two, two entries in one frame
    msg = b'\x00' + ppp_lcp_echo(1)
    A(frame(1, 4, UIH, msg, ext=ext_entry(1, 0, 5, 5 + len(msg) - 1, 0)))   # a complete message
    m2 = b'\x00' + ppp_lcp_echo(2, 0x0a0b0c0d)
    A(frame(1, 4, UIH, m2[:6], ext=ext_entry(2, 0, 5, 10, 1)))              # first fragment
    A(frame(1, 4, UIH, m2[6:], ext=ext_entry(2, 1, 5, 5 + len(m2) - 6 - 1, 0)))   # last fragment
    m3 = b'\x00' + ppp_lcp_echo(3, 7)
    m4 = b'\x00' + ppp_lcp_echo(4, 8)
    A(frame(0, 4, UIH, m3 + m4, ext=ext_entry(3, 0, 5, 5 + len(m3) - 1, 0) +
            ext_entry(4, 0, 5 + len(m3), 5 + len(m3) + len(m4) - 1, 0)))     # two entries
    m5 = b'\x00' + ppp_lcp_echo(5, 9)
    m6 = b'\x00' + ppp_lcp_echo(6, 10)
    m7 = b'\x00' + ppp_lcp_echo(7, 11)
    A(frame(0, 4, UIH, m5 + m6 + m7, ext=ext_entry(5, 0, 5, 5 + len(m5) - 1, 0) +
            ext_entry(6, 0, 5 + len(m5), 5 + len(m5) + len(m6) - 1, 1) +      # "not last" flag set
            ext_entry(7, 0, 5 + len(m5) + len(m6), 5 + len(m5) + len(m6) + len(m7) - 1, 1)))   # three entries, the last never completes
    write('mux27010-coverage.pcap', p)

    # ---- malformed / odd
    q = []
    B = q.append
    B(frame(0, 1, UIH, b'AT\r\n', bad_fcs=True))                          # wrong FCS
    B(frame(0, 0, SABM, bad_fcs=True))
    B(frame(1, 4, UIH, b'\x00' + ppp_lcp_echo(8), ext=ext_entry(9, 0, 10, 5, 0)))      # end before start
    B(frame(1, 4, UIH, b'\x00' + ppp_lcp_echo(8), ext=ext_entry(9, 0, 5, 5, 0)))       # end == start
    # control channel claims fewer values than the frame carries: the FCS length wraps
    B(ctl(0, cc(CMD_PSC, b'\x01') + b'\x00' * 20))
    B(ctl(0, cc(CMD_MSC, b'\x0d') ))                                       # MSC shorter than it needs
    B(ctl(0, cc(CMD_PN, b'\x01\x02'), ))                                   # PN shorter than it needs
    B(ctl(0, cc(CMD_TEST, b'')))                                           # test command without a version
    B(ctl(0, cc(CMD_TEST, b'\x08' + b'EXTENDED TYPE', type_ext=True)))   # type with EA = 0: counted as one octet
    B(ctl(0, cc(CMD_TEST, b'\x08' + b'EXT LEN', len_ext=True)))          # length with EA = 0: same
    B(ctl(0, b'\x23'))                                                     # type without length
    B(ctl(0, b'\x22\x00\x00'))                                             # type with EA = 0 and no end
    B(ctl(0, b'\x03\x02\x02\x04\x06', ))
    B(frame(0, 1, UIH, b'abc', ea_len=False)[:-3])                         # two octet length, frame cut short
    B(frame(0, 1, UIH, b'abc')[:5])                                        # cut after the control octet
    B(frame(0, 1, UIH, b'abc')[:3])
    B(frame(0, 1, UIH, b'abc')[:1])
    B(b'\x07' + b'\x00' * 3)                                               # extended header size beyond the frame
    B(b'\x15' + b'\x00' * 30)                                              # three entries
    B(frame(0, 1, UIH, b'abc', ext=ext_entry(1, 0, 200, 220, 0)))          # offsets beyond the frame
    B(frame(0, 1, UIH, b'abc', ext=b'\x00' * 7))                           # empty entry
    B(frame(0, 1, UIH, b'abc', ext=b'\x00' * 28))                          # four entries: only three are shown
    write('mux27010-coverage-malformed.pcap', q)

main()
