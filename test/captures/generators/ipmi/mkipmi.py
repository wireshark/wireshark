#!/usr/bin/env python3
# Generates test/captures/ipmi_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic captures for packet-ipmi.c (IPMI core: IPMB/KCS/TMode headers,
# request/response matching, nesting, Type/Length strings, timestamps).
# usage: mkipmi.py <outdir> [-v]   (prints the frame ranges with -v)
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))















import struct
from ipmilib import Cap, gz, ipmb, req, rsp, trace_block

NF_CHASSIS, NF_BRIDGE, NF_SE, NF_APP, NF_UPDATE, NF_STORAGE, NF_TRANSPORT = 0, 2, 4, 6, 8, 10, 12
NF_GROUP, NF_OEM = 0x2c, 0x2e

ranges = []
def mark(cap, name, start):
    ranges.append((start, len(cap.frames), name))

def pair(cap, netfn, cmd, rq, rs, seq, how='udp', cc=0, dt=0.001, **kw):
    """Request and response of one command over the given carrier."""
    q = req(netfn, cmd, rq, seq)
    r = rsp(netfn, cmd, rs, seq, cc)
    send(cap, q, how, dt, **kw)
    send(cap, r, how, dt, **kw)

def send(cap, msg, how='udp', dt=0.001, **kw):
    if how == 'udp':
        return cap.udp(msg, dt=dt, **kw)
    if how == 'exp':
        return cap.exp(msg, dt=dt, **kw)
    if how == 'trace':
        return cap.trace(msg, dt=dt, **kw)
    raise ValueError(how)

def typelen_data(t, s):
    return bytes([(t << 6) | len(s)]) + s

def pack6(s):
    v = 0
    for i, c in enumerate(s):
        v |= (ord(c) - 0x20) << (6 * i)
    return v.to_bytes((len(s) * 6 + 7) // 8, 'little')

def build(cap):
    # --- 1. IPMI over RMCP / RMCP+ (UDP 623): the default path
    s = len(cap.frames)
    devid = bytes([0x20, 0x81, 0x05, 0x02, 0x02, 0xbf, 0x57, 0x01, 0x00, 0x34, 0x12, 1, 2, 3, 4])
    pair(cap, NF_APP, 0x01, b'', devid, 1)
    pair(cap, NF_APP, 0x01, b'', devid[:11], 2)                 # without the auxiliary revision
    pair(cap, NF_APP, 0x08, b'', bytes(range(16)), 3)           # GUID
    pair(cap, NF_STORAGE, 0x48, b'', struct.pack('<I', 0x5f000000), 4)   # absolute time
    # same pairs with an IPMI v1.5 session wrapper (no authentication)
    pair(cap, NF_APP, 0x01, b'', devid, 5, v15=True)
    mark(cap, 'RMCP/RMCP+ carrying IPMB', s + 1)

    # --- 2. Exported PDU carrying IPMB, KCS, TMode, I2C
    s = len(cap.frames)
    pair(cap, NF_APP, 0x01, b'', devid, 6, how='exp')
    cap.exp(req(NF_APP, 0x08, b'', 7), name='ipmb')
    cap.exp(rsp(NF_APP, 0x08, bytes(16), 7), name='ipmb')
    cap.exp(req(NF_APP, 0x01, b'', 8), name='ipmi.i2c')
    cap.exp(rsp(NF_APP, 0x01, devid, 8), name='ipmi.i2c')
    # KCS: NetFn/LUN, cmd, [cc,] data
    cap.exp(bytes([NF_APP << 2, 0x01]), name='kcs')
    cap.exp(bytes([(NF_APP | 1) << 2, 0x01, 0]) + devid, name='kcs')
    # TMode: NetFn/LUN, seq/bridge, cmd, [cc,] data
    cap.exp(bytes([NF_APP << 2, 9 << 2 | 1, 0x01]), name='tmode')
    cap.exp(bytes([(NF_APP | 1) << 2, 9 << 2 | 1, 0x01, 0]) + devid, name='tmode')
    mark(cap, 'Exported PDU: ipmi, ipmb, ipmi.i2c, kcs, tmode', s + 1)

    # --- 3. HPM.2 trace (link layer type 260): IPMB, KCS, TMode on channels 0, 1, 15
    s = len(cap.frames)
    for chn in (0, 1, 15):
        send(cap, req(NF_APP, 0x01, b'', 10 + chn), 'trace', chn=chn, flags=0x00)
        send(cap, rsp(NF_APP, 0x01, devid, 10 + chn), 'trace', chn=chn, flags=0x80)
    send(cap, req(NF_APP, 0x01, b'', 30), 'trace', flags=0x40)             # IPMB-B
    send(cap, rsp(NF_APP, 0x01, devid, 30), 'trace', flags=0xc0)
    send(cap, bytes([NF_APP << 2, 0x01]), 'trace', proto=5, flags=0x00)
    send(cap, bytes([(NF_APP | 1) << 2, 0x01, 0]) + devid, 'trace', proto=5, flags=0x80)
    send(cap, bytes([NF_APP << 2, 20 << 2 | 2, 0x01]), 'trace', proto=9, flags=0x00)
    send(cap, bytes([(NF_APP | 1) << 2, 20 << 2 | 2, 0x01, 0]) + devid, 'trace', proto=9, flags=0x80)
    mark(cap, 'HPM.2 trace blocks: IPMB (channels 0, 1, 15, IPMB-B), KCS, TMode', s + 1)

    # --- 4. Request/response matching
    s = len(cap.frames)
    q = req(NF_STORAGE, 0x48, b'', 40)
    send(cap, q)                                       # answered 6 s later: too late to match
    send(cap, rsp(NF_STORAGE, 0x48, struct.pack('<I', 1), 40), dt=6.0)
    send(cap, rsp(NF_STORAGE, 0x48, struct.pack('<I', 2), 41))          # no request at all
    send(cap, req(NF_STORAGE, 0x48, b'', 42))
    send(cap, req(NF_STORAGE, 0x48, b'', 43))
    send(cap, rsp(NF_STORAGE, 0x48, struct.pack('<I', 3), 43))          # answers the second
    send(cap, rsp(NF_STORAGE, 0x48, struct.pack('<I', 4), 42))          # then the first
    # LUNs and other addresses
    send(cap, ipmb(0x20, NF_APP, 0x83, 44, 0x01, b'', lun=2, rq_lun=1))
    send(cap, ipmb(0x83, NF_APP | 1, 0x20, 44, 0x01, bytes([0]) + devid, lun=1, rq_lun=2))
    # incorrect header and data checksums
    send(cap, ipmb(0x20, NF_APP, 0x81, 45, 0x01, b'', bad_cks1=True))
    send(cap, ipmb(0x81, NF_APP | 1, 0x20, 45, 0x01, bytes([0]) + devid, bad_cks2=True))
    mark(cap, 'Matching: late, unmatched, out of order, LUNs, bad checksums', s + 1)

    # --- 5. Completion codes, unknown NetFns, commands and signatures
    s = len(cap.frames)
    for i, cc in enumerate((0x00, 0x05, 0x85, 0xc0, 0xc1, 0xd6, 0xe0, 0xff)):
        pair(cap, NF_STORAGE, 0x48, b'', b'', 50 + i, cc=cc)
    # command specific completion code from the Send Message table
    send(cap, rsp(NF_APP, 0x34, b'', 60, cc=0x82))
    pair(cap, NF_APP, 0x7f, b'\x01\x02', b'\x03', 61)                   # unknown command
    pair(cap, 0x30, 0x01, b'\x01', b'\x02', 62)                         # OEM NetFn
    pair(cap, 0x0e, 0x01, b'\x01', b'\x02', 63)                         # reserved NetFn
    pair(cap, NF_GROUP, 0x01, b'\x77\x01', b'\x77\x02', 64)             # unknown group sig
    pair(cap, NF_OEM, 0x01, b'\x01\x02\x03\x04', b'\x01\x02\x03\x05', 65)   # OEM sig, unknown
    pair(cap, NF_OEM, 0x00, bytes([0x0a, 0x40, 0x00]), bytes([0x0a, 0x40, 0x00]), 66)  # PPS sig
    pair(cap, NF_OEM, 0x00, bytes([0x00, 0x40, 0x0a]), bytes([0x00, 0x40, 0x0a]), 67)  # PPS reversed
    pair(cap, NF_UPDATE, 0x00, b'\x01', b'\x02', 68)
    pair(cap, NF_BRIDGE, 0x00, b'\x01', b'\x02', 69)
    # messages shorter than the header: left as data
    send(cap, ipmb(0x81, NF_APP | 1, 0x20, 70, 0x01, b''))              # response without completion code
    send(cap, req(NF_APP, 0x01, b'', 71)[:6])
    send(cap, ipmb(0x20, NF_GROUP, 0x81, 72, 0x01, b''))
    mark(cap, 'Completion codes, unknown NetFns/commands/signatures, short messages', s + 1)

    # --- 6. Type/Length strings (PICMG Set/Get Shelf Address Info), timestamps
    s = len(cap.frames)
    seq = 80
    tl = [
        typelen_data(0, bytes([0x12, 0xab, 0xcd, 0x01, 0x23, 0xef])),        # binary
        typelen_data(1, bytes([0x12, 0x34, 0x5a, 0xbc])),                   # BCD+
        typelen_data(2, pack6('ABCDEFGHIJKL')),                              # 6-bit, whole triplets
        typelen_data(2, pack6('ABCDE')),                                     # 6-bit, 1 left (S1)
        typelen_data(2, pack6('ABCDEF')),                                    # 2 left
        bytes([0x80 | 2, 0x41, 0x42]),                                       # 6-bit, 2 bytes: 2 left
        bytes([0x80 | 5]) + bytes(range(0x30, 0x35)),                        # 5 bytes
        typelen_data(3, b'Shelf 1'),                                         # 8-bit ASCII
        typelen_data(3, b'a\x01b\xe9c'),                                     # non-printable characters
        bytes([0xc0]),                                                       # empty string
        typelen_data(3, b'A'),                                               # odd length
        typelen_data(3, b'B' * 62),
    ]
    for t in tl:
        send(cap, req(NF_GROUP, 0x03, b'\x00' + t + b'B', seq))             # a trailing byte follows
        seq += 1
    send(cap, rsp(NF_GROUP, 0x02, b'\x00' + tl[6], seq)); seq += 1
    for ts in (0xffffffff, 0x1000, 0x20000000, 0x20000001, 0x5f000000):
        send(cap, req(NF_STORAGE, 0x49, struct.pack('<I', ts), seq)); seq += 1
    mark(cap, 'Type/Length strings and timestamps', s + 1)

    # --- 7. Bridged messages: Send Message / Get Message
    s = len(cap.frames)
    inner_rq = req(NF_APP, 0x01, b'', 9)
    inner_rs = rsp(NF_APP, 0x01, devid, 9)
    def sendmsg(chan, msg, track=0, seq=100, resp=False, cc=0):
        if resp:
            return rsp(NF_APP, 0x34, msg, seq, cc)
        return req(NF_APP, 0x34, bytes([(track << 6) | chan]) + msg, seq)
    def getmsg(chan, msg, seq=100, cc=0):
        return rsp(NF_APP, 0x33, bytes([chan]) + msg, seq, cc)
    seq = 100
    # Send Message request: channel 0 (IPMB, target address only), channel 1 with and
    # without a session handle, tracked and raw modes, channel 15, broadcast
    for chan, msg in ((0, inner_rq), (1, bytes([0x07]) + inner_rq), (1, inner_rq),
                      (15, inner_rq), (2, inner_rs), (0, b'\x00' + inner_rq)):
        send(cap, sendmsg(chan, msg, seq=seq)); send(cap, sendmsg(chan, b'', seq=seq, resp=True)); seq += 1
    send(cap, sendmsg(0, inner_rq, track=1, seq=seq)); seq += 1
    send(cap, sendmsg(0, inner_rq, track=2, seq=seq)); seq += 1
    # Send Message response carrying a message; a failed one without
    send(cap, sendmsg(0, inner_rq, seq=seq))
    send(cap, sendmsg(0, inner_rs, seq=seq, resp=True)); seq += 1
    send(cap, sendmsg(0, inner_rq, seq=seq))
    send(cap, sendmsg(0, b'', seq=seq, resp=True, cc=0x83)); seq += 1
    # Get Message responses: the message has no target address (channel 0, and others
    # with a session handle, with a target address or neither), channel 15 has both
    nt = inner_rq[1:]            # the same message without the target address
    for chan, msg in ((0, nt), (1, bytes([0x05]) + inner_rq), (1, inner_rq), (1, nt), (15, bytes([0x05]) + inner_rq),
                      (2, nt)):
        send(cap, req(NF_APP, 0x33, b'', seq)); send(cap, getmsg(chan, msg, seq)); seq += 1
    send(cap, req(NF_APP, 0x33, b'', seq)); send(cap, getmsg(0, b'', seq, cc=0x80)); seq += 1
    # a nested request answered by a nested response, in Get Message and Send Message
    send(cap, req(NF_APP, 0x33, b'', seq))
    send(cap, getmsg(0, ipmb(0x20, NF_APP, 0x81, 5, 0x01, b'')[1:], seq)); seq += 1
    send(cap, getmsg(0, ipmb(0x20, NF_APP | 1, 0x81, 5, 0x01, b'\x00' + devid)[1:], seq)); seq += 1
    # nesting: Send Message in Send Message ... (levels 1 to 6)
    m = inner_rq
    for n in range(6):
        m = req(NF_APP, 0x34, bytes([0]) + m, 9)
        send(cap, m)
    m = inner_rs
    for n in range(4):
        m = rsp(NF_APP, 0x34, m, 9)
        send(cap, m)
    # top level channels other than 0 (HPM.2 trace channel number)
    for chn in (1, 2, 15):
        send(cap, bytes([0]) + req(NF_APP, 0x01, b'', 7), 'trace', chn=chn)    # broadcast
        send(cap, req(NF_APP, 0x01, b'', 7), 'trace', chn=chn)
    mark(cap, 'Send Message / Get Message, nested messages, other channels', s + 1)

    # nested Get Auxiliary Log Status below the level where data is cached
    m = req(NF_STORAGE, 0x5a, b'\x00', 9)
    for n in range(4):
        m = req(NF_APP, 0x34, bytes([0]) + m, 9)
    send(cap, m)
    m = rsp(NF_STORAGE, 0x5a, struct.pack('<I', 5) + struct.pack('<I', 6), 9)
    for n in range(4):
        m = rsp(NF_APP, 0x34, m, 9)
    send(cap, m)
    mark(cap, 'Get Auxiliary Log Status nested 4 levels deep', len(cap.frames) - 1)

    # --- 9. Commands of other files that use helpers of packet-ipmi.c: the
    # saved request data, the current header and completion code, and the
    # time and port formats of the numeric fields
    s = len(cap.frames)
    seq = 20
    pair(cap, NF_APP, 0x24, bytes([0x44, 0x13, 5, 0x3e, 0x10, 0x27]), b'', seq); seq += 1   # Set Watchdog Timer
    pair(cap, NF_STORAGE, 0x5a, b'\x00', struct.pack('<I', 0x5f000000) + struct.pack('<I', 12), seq); seq += 1
    pair(cap, NF_STORAGE, 0x5a, b'\x01', struct.pack('<I', 0x1000) + b'\x57\x01\x00' + b'\x11' * 7, seq); seq += 1
    pair(cap, NF_STORAGE, 0x5a, b'\x07', b'\x01\x02\x03\x04\x05\x06', seq); seq += 1    # unknown log type
    pair(cap, NF_GROUP, 0x17, b'\x00\x00\x01', b'\x00\x00\x00\x00', seq); seq += 1         # Bused Resource Control
    pair(cap, NF_GROUP, 0x1c, b'\x00\x01\x01\x04', b'\x00', seq); seq += 1             # Set Fan Policy
    send(cap, rsp(NF_GROUP, 0x34, b'\x00\x30\x00\x42', seq)); seq += 1            # Get Upgrade Status
    for cc in (0x00, 0x80, 0x81, 0xc0):
        send(cap, rsp(NF_GROUP, 0x37, b'\x00\x0f\x55', seq, cc=cc)); seq += 1      # Query Rollback Status
    pair(cap, NF_TRANSPORT, 0x01, bytes([1, 8, 0x6f, 0x02]), b'', seq); seq += 1     # LAN: RMCP port
    pair(cap, NF_TRANSPORT, 0x01, bytes([1, 11, 5]), b'', seq); seq += 1            # LAN: ARP interval
    pair(cap, NF_TRANSPORT, 0x01, bytes([1, 18, 1, 0x80, 5, 7]), b'', seq); seq += 1   # LAN: destination type
    pair(cap, NF_TRANSPORT, 0x10, bytes([1, 9, 0x05, 0x13]), b'', seq); seq += 1     # Serial: modem ring time
    pair(cap, NF_TRANSPORT, 0x10, bytes([1, 28, 1, 2]) + b'ABC' + bytes(range(4)) + bytes([0x12, 0x34, 0x56, 0x78, 0x9a]), b'', seq); seq += 1
    pair(cap, NF_TRANSPORT, 0x10, bytes([1, 31, 0x6f, 0x02]), b'', seq); seq += 1   # Serial: PPP RMCP port
    mark(cap, 'Commands of other files: watchdog, auxiliary log, PICMG, LAN/serial configuration', s + 1)

    # --- 8. Many unmatched requests: the request list is bounded (1024)
    s = len(cap.frames)
    N = 1030
    def key(i):
        return 0x81 + 2 * (i // 64), i & 0x3f           # unique (source address, sequence)
    for i in range(N):
        sa, sq = key(i)
        cap.exp(ipmb(0x20, NF_APP, sa, sq, 0x01, b''), dt=0.0001)
    # responses to requests 0 and 5 (dropped from the list), 6 (the oldest kept) and the last
    for i in (0, 5, 6, N - 1):
        sa, sq = key(i)
        cap.exp(ipmb(sa, NF_APP | 1, 0x20, sq, 0x01, bytes([0]) + devid), dt=0.0001)
    mark(cap, 'Request list bound: %d requests, then responses to requests 0, 5, 6 and %d' % (N, N - 1), s + 1)

def build_malformed(cap):
    # IPMB over I2C (link-layer type 209); needs Decode As i2c.message -> ipmi.i2c
    cap.i2c(req(NF_APP, 0x01, b'', 1), flags=0)
    cap.i2c(rsp(NF_APP, 0x01, bytes(15), 1), flags=1)      # master-receive: not IPMB
    cap.i2c(b'\x00' * 8, flags=0x0005, event=True)
    s = len(cap.frames)
    inner = req(NF_APP, 0x01, b'', 9)
    m = inner
    for n in range(40):                 # deeper than the limit of 32
        m = req(NF_APP, 0x34, bytes([0]) + m, 9)
    cap.udp(m)
    cap.exp(m)
    # truncated messages
    cap.exp(req(NF_STORAGE, 0x49, b'\x01', 1))
    cap.exp(rsp(NF_STORAGE, 0x48, b'\x01', 1))
    cap.exp(req(NF_GROUP, 0x03, b'\x00\xc5AB', 2))
    cap.exp(req(NF_APP, 0x34, b'', 2))
    cap.exp(rsp(NF_APP, 0x33, b'', 3))
    cap.exp(b'\x20')
    cap.exp(b'')
    cap.trace(b'\x20\x18\xc8', proto=1)
    cap.trace(b'\x18', proto=5)
    cap.trace(b'\x18\x01', proto=5)
    cap.trace(b'\x18\x01', proto=9)
    cap.trace(b'', proto=1)
    cap.trace(b'\x00' * 7, proto=1, dlen=40)
    cap.trace(b'\x01', proto=1, dlen=40)
    cap.add('trace', trace_block(0, 0, 1, 0, b'')[:10])
    cap.exp(ipmb(0x20, NF_GROUP, 0x81, 1, 0x03, b'\x00\x80'))        # empty-ish typelen
    cap.exp(ipmb(0x20, NF_GROUP, 0x81, 1, 0x03, b'\x00\xff'))        # length without data
    # the same with one octet missing at the end of each Type/Length kind
    for t in (0, 1, 2, 3):
        cap.exp(ipmb(0x20, NF_GROUP, 0x81, 1, 0x03, b'\x00' + bytes([(t << 6) | 8]) + b'abc'))

def main():
    out = sys.argv[1]
    cap = Cap()
    build(cap)
    cap.write_pcapng(os.path.join(out, 'ipmi-coverage.pcapng'))
    gz(os.path.join(out, 'ipmi-coverage.pcapng'))
    os.replace(os.path.join(out, 'ipmi-coverage.pcapng.gz'), os.path.join(out, 'ipmi_coverage.pcapng.gz'))
    bad = Cap()
    build_malformed(bad)
    bad.write_pcapng(os.path.join(out, 'ipmi-coverage-malformed.pcapng'))
    if '-v' in sys.argv:
        for a, b, n in ranges:
            print('%5d-%-5d %s' % (a, b, n))
        print('main %d frames, malformed %d frames' % (len(cap.frames), len(bad.frames)))

main()
