#!/usr/bin/env python3
# Generates test/captures/tpm20_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Builds tpm20-coverage.pcap and tpm20-coverage-malformed.pcap
import struct
import sys
import os
from pcaplib import Flow, write

RH_NULL, RH_OWNER, RH_ENDORSEMENT, RH_PLATFORM, RS_PW = 0x40000007, 0x40000001, 0x4000000b, 0x4000000c, 0x40000009

def cmd(cc, handles=(), params=b'', auth=None, tag=None):
    """TPM command: tag, size, command code, handles, [auth area], parameters.
    auth: list of (session handle, nonce, attributes, hmac); None = no sessions (tag 0x8001)."""
    body = b''.join(struct.pack('>I', h) for h in handles)
    t = 0x8001
    if auth is not None:
        t = 0x8002
        area = b''.join(struct.pack('>IH', h, len(n)) + n + bytes([a]) + struct.pack('>H', len(m)) + m for h, n, a, m in auth)
        body += struct.pack('>I', len(area)) + area
    if tag is not None:
        t = tag
    body += params
    return struct.pack('>HII', t, 10 + len(body), cc) + body

def pw(n=1):
    return [(RS_PW, b'', 1, b'')] * n

def rsp(rc=0, handles=(), params=None, auth=(), tag=None, raw=b''):
    """TPM response; params None = tag 0x8001, else 0x8002 with a parameter size and the auth area."""
    body = b''.join(struct.pack('>I', h) for h in handles)
    t = 0x8001
    if params is not None:
        t = 0x8002
        body += struct.pack('>I', len(params)) + params
    for n, a, m in auth:
        body += struct.pack('>H', len(n)) + n + bytes([a]) + struct.pack('>H', len(m)) + m
    if tag is not None:
        t = tag
    body += raw
    return struct.pack('>HII', t, 10 + len(body), rc) + body

def sized(b):
    return struct.pack('>H', len(b)) + b

def main(out):
    fr = []
    f = Flow(50000, 2322)             # TPM command channel
    p = Flow(50001, 2321)             # platform channel
    req = lambda d: fr.append(f.seg(d))
    rspf = lambda d: fr.append(f.seg(d, client=False))
    preq = lambda d: fr.append(p.seg(d))
    prsp = lambda d: fr.append(p.seg(d, client=False))
    # platform commands and responses (4 octets); the first response after a command is a code
    for c in (0x01, 0x0b, 0x08, 0x09, 0x0a, 0x14, 0x02, 0x7f):    # power on, NV on, send command, cancel on/off, session end, power off, unknown
        preq(struct.pack('>I', c))
        prsp(struct.pack('>I', 0))
    # a simulator exchange: send command, TPM command, response size (4 octets), TPM response, platform response
    preq(struct.pack('>I', 0x08))
    req(cmd(0x144, params=struct.pack('>H', 0)))                                  # Startup(CLEAR)
    prsp(struct.pack('>I', 10))                                                   # response size
    rspf(rsp())                                                                   # Startup response
    prsp(struct.pack('>I', 0))                                                    # response code
    req(cmd(0x144, params=struct.pack('>H', 1)))                                  # Startup(STATE)
    rspf(rsp(rc=0x100))                                                           # TPM_RC_INITIALIZE: error responses stop early
    req(cmd(0x144, params=struct.pack('>H', 0x8001)))
    rspf(rsp(rc=0x99999))                                                         # unknown response code
    # StartAuthSession: no sessions, with and without a symmetric algorithm
    nonce = bytes(range(16))
    req(cmd(0x176, [RH_NULL, RH_NULL], sized(nonce) + sized(b'') + b'\x00' + struct.pack('>HH', 0x0010, 0x000b)))
    rspf(rsp(handles=[0x03000000], raw=sized(bytes(range(16, 32)))))
    req(cmd(0x176, [RH_NULL, RH_NULL], sized(nonce) + sized(bytes(64)) + b'\x01' + struct.pack('>HHHH', 0x0006, 128, 0x0043, 0x000b)))
    rspf(rsp(handles=[0x03000001], raw=sized(bytes(range(32)))))
    # with an authorization area, response with parameter size and auth area
    req(cmd(0x176, [RH_NULL, RH_OWNER], sized(nonce) + sized(b'') + b'\x02' + struct.pack('>HH', 0x0010, 0x000c), auth=pw()))
    rspf(rsp(handles=[0x03000002], params=sized(bytes(range(16))), auth=[(b'', 1, b'')]))
    # CreatePrimary (0x12e): sensitive, public, data; response: public, creation data, digest, name
    req(cmd(0x12e, [RH_OWNER], sized(bytes(8)) + sized(bytes(20)) + sized(b'outside info'), auth=pw()))
    rspf(rsp(params=sized(bytes(40)) + sized(bytes(30)) + sized(bytes(32)) + sized(bytes(34)), auth=[(b'', 1, b'')]))
    req(cmd(0x12e, [RH_OWNER], sized(b'') + sized(b'') + sized(b''), auth=pw(2)))      # two sessions
    rspf(rsp(params=sized(b'') + sized(b'') + sized(b'') + sized(b''), auth=[(b'\x01\x02', 0x81, b'\x03'), (b'', 0, b'')]))
    # CreateLoaded (0x191)
    req(cmd(0x191, [RH_PLATFORM], sized(bytes(4)) + sized(bytes(12)), auth=pw()))
    rspf(rsp(handles=[0x80000001], params=sized(bytes(48)) + sized(bytes(60)) + sized(bytes(34)), auth=[(b'', 1, b'')]))
    # a session with every attribute bit, a nonce and an hmac; three sessions (the maximum)
    sess = [(0x02000000, bytes(range(16)), 0xff, bytes(range(32))), (RS_PW, b'', 0x00, b''), (0x02000001, bytes(4), 0x5a, bytes(20))]
    req(cmd(0x153, [0x80000000], bytes(30), auth=sess))                           # Create
    rspf(rsp(params=bytes(50), auth=[(bytes(16), 0xff, bytes(32)), (b'', 0, b''), (bytes(4), 0x5a, bytes(20))]))
    # commands of the handle table with 0, 1, 2 and 3 handles, with and without sessions
    for cc, hs in ((0x17b, ()), (0x17a, ()), (0x17e, ()), (0x143, ()), (0x121, (RH_OWNER,)), (0x126, (RH_PLATFORM,)),
                   (0x12a, (RH_OWNER,)), (0x11f, (RH_PLATFORM, 0x81000000)), (0x120, (RH_OWNER, 0x81000001)), (0x137, (0x81000002, 0x01000001)),
                   (0x149, (0x01000001, 0x01000002, 0x03000000)), (0x14d, (RH_ENDORSEMENT, 0x80000000, 0x03000001)),
                   (0x184, (0x80000000, 0x01000003, 0x01000004)), (0x162, (0x80000002,)), (0x165, (0x80000003,)),
                   (0x182, (16,)), (0x13c, (17,)), (0x157, (0x80000000,)), (0x161, ()), (0x167, ()), (0x186, ()), (0x15b, (0x80000000,)),
                   (0x198, (0x40000110,)), (0x7fff, (1, 2))):
        a = pw() if hs and cc != 0x7fff else None
        req(cmd(cc, hs, bytes(range(10)), auth=a))
        rspf(rsp(handles=[0x80000010] if cc in (0x157, 0x161, 0x167, 0x186, 0x15b) else [], params=bytes(12) if a else None,
                 auth=[(b'', 1, b'')] if a else [], raw=b'' if a else bytes(6)))
    # Load / ContextLoad responses with a handle and with tag 0x8001 and no parameters; GetRandom with data
    req(cmd(0x17b, (), struct.pack('>H', 16)))
    rspf(rsp(raw=sized(bytes(range(16)))))
    # response codes of every kind of handle value list and an error
    req(cmd(0x153, [0x80000000], bytes(8)))
    rspf(rsp(rc=0x921))
    # a command and response in one direction only (the response comes from a different, lower port)
    write(os.path.join(out, 'tpm20-coverage.pcap'), fr)
    print('main frames', len(fr))

    m = []
    g = Flow(50010, 2322)
    mq = lambda d: m.append(g.seg(d))
    mr = lambda d: m.append(g.seg(d, client=False))
    mr(rsp(params=sized(b'x')))                                                   # a response before any command: no command seen
    mq(cmd(0x153, [0x80000000], bytes(8), tag=0x1234))                            # invalid tag
    mr(rsp(tag=0x7777, handles=[], raw=b'12'))                                    # response with an invalid tag
    mq(cmd(0x153, [0x80000000], bytes(8), auth=[(RS_PW, b'', 1, b'')] * 4))       # four sessions: too many
    mr(rsp(params=b'', auth=[(b'', 1, b'')] * 4))
    # auth area of fewer than 9 octets
    mq(struct.pack('>HII', 0x8002, 10 + 4 + 4 + 4, 0x153) + struct.pack('>I', 0x80000000) + struct.pack('>I', 4) + bytes(4))
    mq(struct.pack('>HII', 0x8002, 10 + 4, 0x153) + struct.pack('>I', 0x80000000))                     # no auth area at all
    mq(struct.pack('>HII', 0x8002, 10 + 8, 0x153) + struct.pack('>I', 0x80000000) + struct.pack('>I', 0))   # auth area size 0
    mq(cmd(0x176, [RH_NULL, RH_NULL], sized(nonce) + sized(bytes(500))))           # sizes beyond the segment
    mq(cmd(0x12e, [RH_OWNER], struct.pack('>H', 0xffff)))
    mq(cmd(0x144, params=b''))                                                     # Startup without the type
    mq(cmd(0x153, [0x80000000], bytes(4), auth=[(RS_PW, bytes(300), 1, b'')])[:-100])   # truncated nonce
    mq(struct.pack('>HII', 0x8002, 10 + 4 + 4 + 9, 0x153) + struct.pack('>I', 0x80000000) + struct.pack('>I', 0xfffffff0) + struct.pack('>IHBH', RS_PW, 0, 1, 0))  # auth area size larger than the data
    mq(struct.pack('>I', 8) + b'\x00\x00')                                         # 6 octets: platform command with extra
    mr(b'\x00\x00\x00')                                                            # 3 octets
    mq(cmd(0x153, [0x80000000], bytes(8))[:9])                                     # 9 octets
    write(os.path.join(out, 'tpm20-coverage-malformed.pcap'), m)

main(sys.argv[1] if len(sys.argv) > 1 else '.')
