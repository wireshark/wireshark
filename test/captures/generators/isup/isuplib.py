# Helper module for the isup capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Helpers shared by mkisup.py and the candidate search (cand.py).
import struct
import random

def pcap_write(path, linktype, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, d in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 10, (i % 10) * 1000, len(d), len(d)))
            f.write(d)

def mtp3(isup, si=5, opc=100, dpc=200, sls=0):
    label = dpc | (opc << 14) | (sls << 28)
    return bytes([si]) + struct.pack('<I', label) + isup

def udp_sip(body, ctype, callid='1', sport=5060, dport=5060):
    sip = ('INVITE sip:a@example.com SIP/2.0\r\n'
           'Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK%s\r\n'
           'From: <sip:b@example.com>;tag=1\r\nTo: <sip:a@example.com>\r\n'
           'Call-ID: %s@10.0.0.1\r\nCSeq: 1 INVITE\r\n'
           'Content-Type: %s\r\nContent-Length: %d\r\n\r\n' % (callid, callid, ctype, len(body))).encode() + body
    udp = struct.pack('>HHHH', sport, dport, 8 + len(sip), 0) + sip
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    s = 0
    for i in range(0, 20, 2):
        s += (ip[i] << 8) | ip[i + 1]
    s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack('>H', ~s & 0xffff) + ip[12:]
    return bytes([0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 8, 0]) + ip + udp

# message layout: msg type -> (fixed octets, number of mandatory variable params, has optional part)
MSGS = {
    1: (5, 1, 1), 2: (0, 1, 1), 3: (2, 0, 1), 4: (2, 0, 1), 5: (1, 0, 0),
    6: (2, 0, 1), 7: (2, 0, 1), 8: (0, 0, 1), 9: (0, 0, 1), 12: (0, 1, 1),
    13: (1, 0, 1), 14: (1, 0, 1), 16: (0, 0, 1), 17: (0, 0, 0), 18: (0, 0, 0),
    19: (0, 0, 0), 20: (0, 0, 0), 21: (0, 0, 0), 22: (0, 0, 0), 23: (0, 1, 0),
    24: (1, 1, 0), 25: (1, 1, 0), 26: (1, 1, 0), 27: (1, 1, 0), 31: (1, 0, 1),
    32: (1, 0, 1), 33: (1, 1, 1), 36: (0, 0, 0), 41: (0, 1, 0), 42: (0, 1, 0),
    43: (0, 2, 0), 44: (1, 0, 1), 45: (0, 1, 1), 46: (0, 0, 0), 47: (0, 1, 1),
    48: (0, 0, 0), 50: (0, 0, 1), 51: (0, 0, 1), 52: (0, 0, 1), 53: (0, 0, 1),
    54: (0, 0, 1), 55: (0, 0, 1), 56: (0, 0, 1), 64: (0, 0, 1), 65: (0, 0, 1),
    66: (0, 0, 1),
}

def build_msg(mt, fixed=b'', var=(), opt=None, msgs=MSGS):
    """Message octets after the CIC: type, fixed part, pointers, variable parts,
    optional part.  opt: None (no optional part for this message), b'' (pointer 0)
    or the encoded optional parameters (the end-of-parameters octet is added)."""
    nvar = len(var)
    haveopt = opt is not None
    npt = nvar + (1 if haveopt else 0)
    ptrs = bytearray()
    body = bytearray()
    for j, v in enumerate(var):
        # pointer from its own octet to the length octet
        ptrs.append(npt - j + len(body))
        body += bytes([len(v)]) + v
    if haveopt:
        if opt == b'':
            ptrs.append(0)
        else:
            ptrs.append(npt - nvar + len(body))
            body += opt + b'\x00'
    return bytes([mt]) + fixed + bytes(ptrs) + bytes(body)

def oparam(t, body):
    return bytes([t, len(body)]) + body

def cic(c):
    return struct.pack('<H', c)

def pcapng_write(path, frames):
    """frames: list of (interface, bytes); interface 0 = MTP3 (141), 1 = Ethernet."""
    def block(t, body):
        body += b'\0' * (-len(body) % 4)
        n = len(body) + 12
        return struct.pack('<II', t, n) + body + struct.pack('<I', n)
    out = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in (141, 1):
        out += block(1, struct.pack('<HHI', lt, 0, 65535))
    for i, (ifc, d) in enumerate(frames):
        ts = 1700000000 * 1000000 + i * 1000
        body = struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(d), len(d)) + d
        out += block(6, body)
    open(path, 'wb').write(out)
