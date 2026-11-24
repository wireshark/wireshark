#!/usr/bin/env python3
# Generates test/captures/nbt_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Synthetic capture generator. Python struct only; all addresses are made up.
import struct
import sys
import os
import gzip

def _csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ipv4(src, dst, proto, payload, ident=1):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0,
                     bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', _csum(ip)) + ip[12:]
    return ip + payload

def eth(payload, src=2, dst=1, etype=0x0800):
    return bytes([2, 0, 0, 0, 0, dst]) + bytes([2, 0, 0, 0, 0, src]) + struct.pack('!H', etype) + payload

def udp(src, dst, sport, dport, payload, srcmac=2, dstmac=1):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return eth(ipv4(src, dst, 17, u), srcmac, dstmac)

def tcp(src, dst, sport, dport, seq, ack, payload, flags=0x18, srcmac=2, dstmac=1):
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''   # MSS on SYN and SYN-ACK
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts + payload
    return eth(ipv4(src, dst, 6, t), srcmac, dstmac)

A = [10, 0, 0, 1]
B = [10, 0, 0, 2]

class Stream:
    '''One TCP connection: A (client, MAC 2) to B (server, MAC 1).'''
    def __init__(self, frames, cport, sport, handshake=True):
        self.f = frames
        self.cp, self.sp = cport, sport
        self.cs, self.ss = 1000, 5000
        if handshake:
            frames.append(tcp(A, B, cport, sport, self.cs, 0, b'', 0x02))
            frames.append(tcp(B, A, sport, cport, self.ss, self.cs + 1, b'', 0x12, 1, 2))
            self.cs += 1; self.ss += 1
            frames.append(tcp(A, B, cport, sport, self.cs, self.ss, b'', 0x10))
    def c(self, data):
        self.f.append(tcp(A, B, self.cp, self.sp, self.cs, self.ss, data, 0x18))
        self.cs += len(data)
    def s(self, data):
        self.f.append(tcp(B, A, self.sp, self.cp, self.ss, self.cs, data, 0x18, 1, 2))
        self.ss += len(data)

def write_pcap(name, frames, linktype=1):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, fr in enumerate(frames):
            t = 1700000000 + i // 1000
            f.write(struct.pack('<IIII', t, (i % 1000) * 1000, len(fr), len(fr)))
            f.write(fr)

def gz(name):
    with open(name, 'rb') as f, gzip.GzipFile(name + '.gz', 'wb', mtime=0) as g:
        g.write(f.read())

# ---- NetBIOS over TCP/UDP: NBNS (UDP 137), NBDS (UDP 138), NBSS (TCP 139, 445) ----
def smb_negprot():
    d = b'\x02NT LM 0.12\x00'
    return struct.pack('<4sBIBHH8sHHHHH', b'\xffSMB', 0x72, 0, 0x18, 0xc853, 0, b'\0' * 8, 0,
                       0xffff, 0x1234, 0, 1) + b'\x00' + struct.pack('<H', len(d)) + d

def nbenc(name, t=0x20, scope=''):
    '''Level 1 encoded NetBIOS name as a DNS name (a 16 byte name, 32 characters).'''
    raw = name.encode().ljust(15, b' ')[:15] + bytes([t])
    return dnsname(b''.join(bytes([0x41 + (c >> 4), 0x41 + (c & 15)]) for c in raw), scope)

def dnsname(enc, scope=''):
    out = bytes([len(enc)]) + enc
    for label in scope.split('.') if scope else []:
        out += bytes([len(label)]) + label.encode()
    return out + b'\0'

PTR = b'\xc0\x0c'            # compression pointer to the first name
T_A, T_NB, T_NBSTAT = 1, 0x20, 0x21

def hdr(tid, opcode, resp, q, an, ns, ar, nb=0, aa=0, tc=0, rd=1, ra=0, bcast=0, rcode=0):
    flags = (resp << 15) | (opcode << 11) | (aa << 10) | (tc << 9) | (rd << 8) | (ra << 7) | (bcast << 4) | rcode
    return struct.pack('!HHHHHH', tid, flags, q, an, ns, ar)

def question(name, qtype=T_NB):
    return name + struct.pack('!HH', qtype, 1)

def rr(name, rtype, rdata, ttl=300000, cls=1):
    return name + struct.pack('!HHIH', rtype, cls, ttl, len(rdata)) + rdata

def nbrdata(flags, *ips):
    return b''.join(struct.pack('!H', flags) + bytes(ip) for ip in ips)

def nbstat(names, stats=True):
    d = bytes([len(names)])
    for n, t, fl in names:
        d += n.encode().ljust(15, b' ')[:15] + bytes([t]) + struct.pack('!H', fl)
    if stats:
        d += bytes([2, 0, 0x11, 0x22, 0x33, 0x44])          # unit id
        d += bytes([0x01, 0x00])                             # jumpers, test result
        d += struct.pack('!HHHHHH', 0x0300, 60, 1, 2, 3, 4)  # version, period, CRCs, alignment, collisions, aborts
        d += struct.pack('!II', 1000, 2000)                  # good sends, good receives
        d += struct.pack('!HHHHHHH', 5, 6, 7, 8, 9, 10, 1500)
    return d

frames = []
def u137(payload, src=A, dst=B, sp=137, dp=137, sm=2, dm=1):
    frames.append(udp(src, dst, sp, dp, payload, sm, dm))
def u138(payload):
    frames.append(udp(A, B, 138, 138, payload))

N1 = nbenc('FILESERVER', 0x20)
N2 = nbenc('WORKGROUP', 0x00)
N3 = nbenc('USERPC', 0x03, 'corp.example')
# --- name query, broadcast, and the responses
u137(hdr(0x0001, 0, 0, 1, 0, 0, 0, bcast=1) + question(N1))
u137(hdr(0x0001, 0, 1, 0, 1, 0, 0, aa=1, ra=0) + rr(N1, T_NB, nbrdata(0x0000, [10, 0, 0, 5])), B, A, 137, 137, 1, 2)
u137(hdr(0x0002, 0, 0, 1, 0, 0, 0) + question(N2))
u137(hdr(0x0002, 0, 1, 0, 1, 0, 0, aa=1) + rr(N2, T_NB, nbrdata(0x8000, [10, 0, 0, 5], [10, 0, 0, 6], [10, 0, 0, 7])), B, A, 137, 137, 1, 2)
u137(hdr(0x0003, 0, 1, 1, 1, 0, 0, aa=1, ra=1) + question(N1) + rr(PTR, T_NB, nbrdata(0x6000, [10, 0, 0, 8])), B, A, 137, 137, 1, 2)
u137(hdr(0x0004, 0, 0, 1, 0, 0, 0) + question(N3))
# negative responses
for rc in (1, 2, 3, 4, 5, 6, 7, 9):
    u137(hdr(0x0010 + rc, 0, 1, 0, 0, 0, 0, aa=1, rcode=rc), B, A, 137, 137, 1, 2)
# --- registration, multi-homed registration, refresh, release
u137(hdr(0x0020, 5, 0, 1, 0, 0, 1, bcast=1) + question(N1) + rr(PTR, T_NB, nbrdata(0x0000, [10, 0, 0, 5])))
u137(hdr(0x0021, 5, 1, 0, 1, 0, 0, aa=1) + rr(N1, T_NB, nbrdata(0x0000, [10, 0, 0, 5])), B, A, 137, 137, 1, 2)
u137(hdr(0x0022, 5, 1, 0, 1, 0, 0, aa=1, rcode=6) + rr(N1, T_NB, nbrdata(0x2000, [10, 0, 0, 9])), B, A, 137, 137, 1, 2)
u137(hdr(0x0023, 15, 0, 1, 0, 0, 1) + question(N2) + rr(PTR, T_NB, nbrdata(0x8000, [10, 0, 0, 5])))
u137(hdr(0x0024, 8, 0, 1, 0, 0, 1) + question(N1) + rr(PTR, T_NB, nbrdata(0x4000, [10, 0, 0, 5])))
u137(hdr(0x0025, 9, 0, 1, 0, 0, 1) + question(N1) + rr(PTR, T_NB, nbrdata(0x0000, [10, 0, 0, 5])))
u137(hdr(0x0026, 6, 0, 1, 0, 0, 1, bcast=1) + question(N1) + rr(PTR, T_NB, nbrdata(0x0000, [10, 0, 0, 5])))
u137(hdr(0x0026, 6, 1, 0, 1, 0, 0, aa=1) + rr(N1, T_NB, nbrdata(0x0000, [10, 0, 0, 5])), B, A, 137, 137, 1, 2)
# --- wait for acknowledgement (the NB RR holds only the flags word)
u137(hdr(0x0027, 7, 1, 0, 1, 0, 0, aa=1, rd=1, ra=1) + rr(N1, T_NB, struct.pack('!H', 0x8590)), B, A, 137, 137, 1, 2)
# --- node status
u137(hdr(0x0030, 0, 0, 1, 0, 0, 0) + question(nbenc('*', 0), T_NBSTAT))
names = [('FILESERVER', 0x00, 0x0400), ('WORKGROUP', 0x00, 0x8400), ('FILESERVER', 0x20, 0x0400),
         ('WORKGROUP', 0x1e, 0xc400), ('MSBROWSE', 0x01, 0x8600), ('ADMIN', 0x03, 0x6000)]
u137(hdr(0x0030, 0, 1, 1, 1, 0, 0, aa=1) + question(nbenc('*', 0), T_NBSTAT)
     + rr(PTR, T_NBSTAT, nbstat(names), 0), B, A, 137, 137, 1, 2)
# a name that was compressed in the answer, and no names at all
u137(hdr(0x0031, 0, 1, 0, 1, 0, 0, aa=1) + rr(nbenc('*', 0), T_NBSTAT, nbstat([]), 0), B, A, 137, 137, 1, 2)
# reproducer of "NBT: Use the full name buffer size for NBSTAT names": the RR name is a 2-byte
# compression pointer, and the first NetBIOS name has 15 characters
u137(hdr(0x1234, 0, 1, 1, 1, 0, 0, aa=1) + question(nbenc('*', 0), T_NBSTAT)
     + rr(PTR, T_NBSTAT, nbstat([('ABCDEFGHIJKLMNO', 0x00, 0x0400)], True), 0), B, A, 137, 137, 1, 2)
# --- other record types, authority and additional records
u137(hdr(0x0040, 0, 1, 1, 1, 1, 1, aa=1) + question(N1, T_A) + rr(PTR, T_A, bytes([10, 0, 0, 5]))
     + rr(N2, T_A, bytes([10, 0, 0, 6]), 100, 3) + rr(N3, 0x0b, b'\x01\x02\x03'), B, A, 137, 137, 1, 2)
u137(hdr(0x0041, 0, 1, 1, 0, 1, 1, aa=1) + question(N1) + rr(N1, T_NB, nbrdata(0x0000, [10, 0, 0, 5]))
     + rr(N2, T_NB, nbrdata(0x8000, [10, 0, 0, 6])), B, A, 137, 137, 1, 2)
# --- opcodes without a name (unknown opcode), names that are not valid NetBIOS names
u137(hdr(0x0050, 3, 0, 1, 0, 0, 0) + question(N1))
u137(hdr(0x0051, 0, 0, 1, 0, 0, 0) + question(dnsname(b'AB1D' + b'AA' * 14)))      # '1' is not in A-Z
u137(hdr(0x0052, 0, 0, 1, 0, 0, 0) + question(dnsname(b'ABC')))                    # odd number of characters
u137(hdr(0x0053, 0, 0, 1, 0, 0, 0) + question(dnsname(b'ABCD')))                   # too short
u137(hdr(0x0054, 0, 0, 1, 0, 0, 0) + question(dnsname(b'AB' * 17)))                # too long
u137(hdr(0x0055, 0, 0, 1, 0, 0, 0) + question(dnsname(b'AB' * 8 + b'Ab' + b'AA' * 7)))   # second char lower case
u137(hdr(0x0056, 0, 0, 1, 0, 0, 0) + question(dnsname(b'AB' * 8 + b'AB' + b'AA' * 7 + b'A')[:-1] + b'\x03foo\0'))
u137(hdr(0x0057, 0, 0, 1, 0, 0, 0) + question(dnsname(b'AB' * 16, 'a.b')))        # a scope without a type byte
u137(hdr(0x0058, 0, 0, 0, 0, 0, 0))                                                # empty

# --- NBDS datagram service on UDP 138
smb = smb_negprot()
def nbds(typ, flags, did, ip, port, rest):
    return struct.pack('!BBH4sH', typ, flags, did, bytes(ip), port) + rest
def dg(typ, flags, did, payload, src='WS1', dst='SERVER1', st=0, dt=0x20, ln=None, off=0):
    ln = len(payload) + 68 if ln is None else ln
    return nbds(typ, flags, did, [10, 0, 0, 1], 138, struct.pack('!HH', ln, off)
                + nbenc(src, st) + nbenc(dst, dt) + payload)
u138(dg(0x10, 0x02, 0x1001, smb))                       # direct unique, first fragment, B node
u138(dg(0x11, 0x06, 0x1002, b'raw datagram payload', 'WS1', 'WORKGROUP', 0, 0x00))
u138(dg(0x12, 0x0a, 0x1003, b'\x01\x02\x03\x04', 'WS2', '*', 3, 0))        # broadcast, M node
u138(dg(0x10, 0x0e, 0x1004, b'', 'WS3', 'ANOTHER', 0, 0x03))               # NBDD node, no payload
u138(dg(0x10, 0x00, 0x1005, b'continuation fragment', 'WS1', 'SERVER1', 0, 0x20, 21, 0x0100))   # not first
u138(nbds(0x13, 0x02, 0x1006, [10, 0, 0, 1], 138, bytes([0x82])))      # datagram error
u138(nbds(0x13, 0x02, 0x1007, [10, 0, 0, 1], 138, bytes([0x83])))
u138(nbds(0x13, 0x02, 0x1008, [10, 0, 0, 1], 138, bytes([0x84])))
for t in (0x14, 0x15, 0x16):
    u138(nbds(t, 0x02, 0x1010 + t, [10, 0, 0, 1], 138, nbenc('QUERIED', 0x20)))
u138(nbds(0x99, 0x02, 0x1020, [10, 0, 0, 1], 138, b'unknown message type'))
u138(nbds(0x10, 0x02, 0x1021, [10, 0, 0, 1], 138, struct.pack('!HH', 5, 0) + nbenc('SCOPED', 0x00, 'corp.example') + nbenc('DEST', 0x1d) + smb))

# --- NBSS session service on TCP 139
def nbss(typ, payload, flags=0, length=None):
    n = len(payload) if length is None else length
    return struct.pack('!BBH', typ, flags | (n >> 16), n & 0xffff) + payload

st = Stream(frames, 40139, 139)
st.c(nbss(0x81, nbenc('FILESERVER', 0x20) + nbenc('USERPC', 0x00)))                # session request
st.s(nbss(0x82, b''))                                                              # positive response
st.c(nbss(0x00, smb))                                                              # session messages
st.s(nbss(0x00, smb))
st.c(nbss(0x85, b'')); st.s(nbss(0x85, b''))                                       # keep-alive
st.c(nbss(0x00, b'hello, not SMB'))
st.c(nbss(0x00, smb) + nbss(0x00, b'second message in one segment'))
m = nbss(0x00, smb + b'\x00' * 50)                                                 # one message in two segments
st.c(m[:14]); st.c(m[14:])
m = nbss(0x00, b'header split in tiny segments')                                   # header split three ways
st.c(m[:1]); st.c(m[1:3]); st.c(m[3:8]); st.c(m[8:])
m = nbss(0x00, smb) + nbss(0x00, smb)[:2]                                          # a header cut after two bytes
st.c(m); st.c(nbss(0x00, smb)[2:])
st.s(nbss(0x83, bytes([0x80]))); st.s(nbss(0x83, bytes([0x81]))); st.s(nbss(0x83, bytes([0x82])))
st.s(nbss(0x83, bytes([0x83]))); st.s(nbss(0x83, bytes([0x8f]))); st.s(nbss(0x83, bytes([0x99])))
st.s(nbss(0x84, bytes([10, 0, 0, 77]) + struct.pack('!H', 139)))                   # retarget
# message longer than 64 KiB: the E flag adds 65536 to the length
big = nbss(0x00, b'B' * (65536 + 100))
st.c(big[:4 + 30000]); st.c(big[4 + 30000:4 + 60000]); st.c(big[4 + 60000:])
# things that are not valid NBSS headers: taken as continuation data
st.c(b'\x41\x00\x00\x05abcde')                                                     # unknown type
st.c(nbss(0x00, b'x' * 8, flags=0x04, length=8))                                   # reserved flag
st.c(nbss(0x00, b'', length=0))                                                    # empty message
st.c(nbss(0x81, b'x', length=1))                                                   # request too short
st.c(nbss(0x81, b'x' * 300, length=300))                                           # request too long
st.c(nbss(0x82, b'xx', length=2)); st.c(nbss(0x83, b'xx', length=2))
st.c(nbss(0x84, b'xxxxx', length=5)); st.c(nbss(0x85, b'x', length=1))
st.c(b'\x41\x00')                                                                  # 1 to 3 bytes with a bad type
st.c(nbss(0x00, smb + bytes(8)))                                                   # still in sync
st.c(b'\x00\x00')                                                                  # a header that never completes

# --- NBSS on TCP 445: direct hosting, 24 bit lengths, SMB signature
st = Stream(frames, 40445, 445)
st.c(nbss(0x00, smb))
st.s(nbss(0x85, b''))
st.c(nbss(0x00, smb) + nbss(0x00, smb))
m = bytes([0]) + struct.pack('!I', 0x20010)[1:] + smb + bytes(0x20010 - len(smb))      # 128 KiB message
for i in range(0, len(m), 40000):
    st.c(m[i:i + 40000])
st.c(nbss(0x00, smb))

main = frames
frames = []
# --- malformed: truncated NBNS records (every cut of a node status answer, and of an NB answer)
full = nbstat(names[:2])
def rrcut(name, rtype, rdata, n):
    # the record claims n bytes of data; the rest of the data follows it in the packet,
    # so the claimed length is what is "incomplete"
    return name + struct.pack('!HHIH', rtype, 1, 0, n) + rdata
for n in range(0, len(full) + 1):
    u137(hdr(0x2000 + n, 0, 1, 0, 1, 0, 0, aa=1) + rrcut(nbenc('*', 0), T_NBSTAT, full, n), B, A, 137, 137, 1, 2)
nbd = nbrdata(0, [10, 0, 0, 1], [10, 0, 0, 2])
for n in range(0, 12):
    u137(hdr(0x3000 + n, 0, 1, 0, 1, 0, 0, aa=1) + rrcut(N1, T_NB, nbd, n), B, A, 137, 137, 1, 2)
    u137(hdr(0x3100 + n, 7, 1, 0, 1, 0, 0, aa=1) + rrcut(N1, T_NB, b'\x85\x90\x00\x00', n), B, A, 137, 137, 1, 2)
# claimed data length shorter than the data, and data that is really cut
for n in (3, 20):
    u137(hdr(0x3150 + n, 0, 1, 0, 1, 0, 0, aa=1) + rr(nbenc('*', 0), T_NBSTAT, full[:n], 0), B, A, 137, 137, 1, 2)
# count of names larger than the data
u137(hdr(0x3200, 0, 1, 0, 1, 0, 0, aa=1) + rr(nbenc('*', 0), T_NBSTAT, bytes([200]) + bytes(40), 0), B, A, 137, 137, 1, 2)
# truncated headers and records
u137(hdr(0x3300, 0, 1, 1, 1, 0, 0)[:8])
u137(hdr(0x3301, 0, 0, 1, 0, 0, 0) + N1[:10])
u137(hdr(0x3302, 0, 1, 0, 1, 0, 0) + rr(N1, T_NB, b'')[:-6])
# datagrams: cut names, cut headers
u138(dg(0x10, 0x02, 0x4001, smb)[:30])
u138(dg(0x11, 0x02, 0x4002, b'')[:14])
u138(nbds(0x13, 0x02, 0x4003, [10, 0, 0, 1], 138, b''))
u138(nbds(0x14, 0x02, 0x4004, [10, 0, 0, 1], 138, nbenc('Q')[:20]))
u138(b'\x10\x02\x00')
# session service: a request with cut names, a message whose SMB payload is cut, retarget too short
st = Stream(frames, 40140, 139)
st.c(nbss(0x81, nbenc('A', 0x20)[:20], length=20))
st.c(nbss(0x83, b'', length=1)[:4])
st.c(nbss(0x84, bytes([10, 0, 0, 1]), length=6))
st.c(nbss(0x00, smb[:20]))
st.c(nbss(0x00, smb[:36]))
st.c(nbss(0x00, smb, length=len(smb) + 40))             # promises more bytes than are sent
st = Stream(frames, 40446, 445)
st.c(nbss(0x00, smb[:20]))

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    write_pcap(os.path.join(out, 'nbt-coverage.pcap'), main)
    gz(os.path.join(out, 'nbt-coverage.pcap'))
    os.rename(os.path.join(out, 'nbt-coverage.pcap.gz'), os.path.join(out, 'nbt_coverage.pcap.gz'))
    write_pcap(os.path.join(out, 'nbt-coverage-malformed.pcap'), frames)
