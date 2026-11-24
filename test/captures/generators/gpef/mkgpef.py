#!/usr/bin/env python3
# Generates test/captures/gpef_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the GPEF dissector
(packet-gpef.c, MS-GPEF EFS policy blob).  Everything is built with
struct; nothing comes from a real network.  Usage: mkgpef.py <out dir>

GPEF has no port of its own: the LSA DCE/RPC calls
QueryDomainInformationPolicy (response) and SetDomainInformationPolicy
(request) at information level 2 hand the EFS blob to the "efsblob"
dissector.  The calls go over DCE/RPC on TCP port 49155 (found by the
DCE/RPC heuristic), with a bind to the LSA interface first.

Writes:
  gpef-coverage.pcap            blobs with 0, 1, 2 and 3 keys: SID and
                                X.509 certificate per key, in query
                                responses and set requests
  gpef-coverage-malformed.pcap  the reproducers of the fix (SID and
                                certificate offsets outside the key) and
                                other bad keys and blobs
"""
import os
import sys
import struct

UUID_LSA = '12345778-1234-abcd-ef00-0123456789ab'
UUID_NDR = '8a885d04-1ceb-11c9-9fe8-08002b104860'
UUID_NDR64 = '71710533-beba-4937-8319-b5dbef9ccc36'

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('>%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i // 10, 100000 * (i % 10), len(fr), len(fr)))
            f.write(fr)


class TCP:
    """One TCP connection with a handshake; seq/ack kept per side."""
    MSS = 1460

    def __init__(self, frames, cport, sport=49155,
                 cip=(192, 0, 2, 50), sip=(192, 0, 2, 60)):
        self.frames = frames
        self.c = (bytes(cip), cport)
        self.s = (bytes(sip), sport)
        self.cseq, self.sseq = 0x10000000 + cport * 7, 0x20000000 + cport * 11
        self.seg(True, b'', 0x02)
        self.cseq += 1
        self.seg(False, b'', 0x12)
        self.sseq += 1
        self.seg(True, b'', 0x10)

    def seg(self, from_client, payload, flags=0x18):
        src, dst = (self.c, self.s) if from_client else (self.s, self.c)
        seq = self.cseq if from_client else self.sseq
        ack = 0 if flags == 0x02 else (self.sseq if from_client else self.cseq)
        opts = struct.pack('>BBH', 2, 4, self.MSS) if flags & 0x02 else b''
        tcp = struct.pack('>HHIIBBHHH', src[1], dst[1], seq, ack, (5 + len(opts) // 4) << 4,
                          flags, 65535, 0, 0) + opts
        ph = src[0] + dst[0] + struct.pack('>BBH', 0, 6, len(tcp) + len(payload))
        tcp = tcp[:16] + struct.pack('>H', csum(ph + tcp + payload)) + tcp[18:]
        ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 0, 0x4000, 64, 6, 0,
                         src[0], dst[0])
        ip = ip[:10] + struct.pack('>H', csum(ip)) + ip[12:]
        mc, ms = bytes.fromhex('020000000050'), bytes.fromhex('020000000060')
        eth = (ms + mc) if from_client else (mc + ms)
        self.frames.append(eth + b'\x08\x00' + ip + tcp + payload)
        if from_client:
            self.cseq += len(payload)
        else:
            self.sseq += len(payload)

    def send(self, from_client, data):
        for i in range(0, len(data), self.MSS):
            self.seg(from_client, data[i:i + self.MSS])

    def fin(self):
        self.seg(True, b'', 0x11)
        self.cseq += 1
        self.seg(False, b'', 0x11)
        self.sseq += 1
        self.seg(True, b'', 0x10)


class RPC:
    def __init__(self, tcp, le=True, ndr64=False):
        self.tcp, self.le, self.ndr64 = tcp, le, ndr64
        self.e = '<' if le else '>'
        self.call_id = 0

    def uuid_bytes(self, u):
        h = u.replace('-', '')
        a, b, c = int(h[0:8], 16), int(h[8:12], 16), int(h[12:16], 16)
        return struct.pack(self.e + 'IHH', a, b, c) + bytes.fromhex(h[16:])

    def pdu(self, ptype, body, call_id, flags=0x03):
        drep = bytes([0x10 if self.le else 0x00, 0, 0, 0])
        hdr = struct.pack(self.e + 'BBBB', 5, 0, ptype, flags) + drep
        hdr += struct.pack(self.e + 'HHI', 16 + len(body), 0, call_id)
        return hdr + body

    def call(self, opnum, req, resp):
        self.call_id += 1
        self.tcp.send(True, self.pdu(0, struct.pack(self.e + 'IHH', len(req), 0, opnum) + req, self.call_id))
        if resp is not None:
            self.tcp.send(False, self.pdu(2, struct.pack(self.e + 'IHBB', len(resp), 0, 0, 0) + resp, self.call_id))

    def bind(self):
        self.call_id += 1
        ts = (UUID_NDR64, 1) if self.ndr64 else (UUID_NDR, 2)
        body = struct.pack(self.e + 'HHI', 4280, 4280, 0) + struct.pack(self.e + 'B3x', 1)
        body += struct.pack(self.e + 'HBx', 0, 1) + self.uuid_bytes(UUID_LSA)
        body += struct.pack(self.e + 'I', 0)
        body += self.uuid_bytes(ts[0]) + struct.pack(self.e + 'I', ts[1])
        self.tcp.send(True, self.pdu(11, body, self.call_id))
        sec = b'49155\0'
        body = struct.pack(self.e + 'HHI', 4280, 4280, 0x12345) + struct.pack(self.e + 'H', len(sec)) + sec
        body += b'\0' * ((-(16 + len(body))) % 4)
        body += struct.pack(self.e + 'B3x', 1) + struct.pack(self.e + 'HH', 0, 0)
        body += self.uuid_bytes(ts[0]) + struct.pack(self.e + 'I', ts[1])
        self.tcp.send(False, self.pdu(12, body, self.call_id))

# ---- a minimal DER X.509 certificate for the EFS keys (synthetic)
def der(tag, body):
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = bytes([0x81, n])
    else:
        ln = bytes([0x82, n >> 8, n & 0xff])
    return bytes([tag]) + ln + body


def oid(s):
    p = [int(x) for x in s.split('.')]
    out = bytes([40 * p[0] + p[1]])
    for x in p[2:]:
        enc = [x & 0x7f]
        x >>= 7
        while x:
            enc.insert(0, 0x80 | (x & 0x7f))
            x >>= 7
        out += bytes(enc)
    return der(0x06, out)


def name(cn):
    return der(0x30, der(0x31, der(0x30, oid('2.5.4.3') + der(0x0c, cn.encode()))))


def certificate(cn, serial):
    alg = der(0x30, oid('1.2.840.113549.1.1.11') + der(0x05, b''))
    rsakey = der(0x30, der(0x02, b'\x00' + bytes((0xc1 + i) & 0xff for i in range(64))) + der(0x02, b'\x01\x00\x01'))
    spki = der(0x30, der(0x30, oid('1.2.840.113549.1.1.1') + der(0x05, b'')) + der(0x03, b'\x00' + rsakey))
    tbs = der(0x30, der(0xa0, der(0x02, b'\x02')) + der(0x02, bytes([serial])) + alg + name('EFS Recovery CA') +
              der(0x30, der(0x17, b'230101000000Z') + der(0x17, b'330101000000Z')) + name(cn) + spki)
    return der(0x30, tbs + alg + der(0x03, b'\x00' + bytes(64)))


def efskey(sid, cert):
    """MS-GPEF EfsKey: length1, length2, sid offset, reserved, cert length,
    cert offset, reserved 0x20, SID, certificate (offsets from length2)."""
    sidb = sid_bytes(sid)
    sid_off = 24
    cert_off = sid_off + len(sidb)
    rest = struct.pack('<IIIIII', 0x14, sid_off, 0, len(cert), cert_off, 0x20) + sidb + cert
    return struct.pack('<I', 4 + len(rest)) + rest


def efsblob(keys):
    return struct.pack('<II', 0x00010001, len(keys)) + b''.join(keys)


def sid_parse(s):
    p = s.split('-')
    return int(p[1]), int(p[2]), [int(x) for x in p[3:]]


def sid_count(s):
    return len(sid_parse(s)[2])


def sid_bytes(s):
    rev, auth, subs = sid_parse(s)
    return struct.pack('<BB', rev, len(subs)) + auth.to_bytes(6, 'big') + \
        b''.join(struct.pack('<I', x) for x in subs)


DOM = 'S-1-5-21-1004336348-1177238915-682003330'


HANDLE = bytes(4) + bytes(range(0x50, 0x5c)) + bytes([0x10]) * 4


def pad4(b):
    return b + b'\0' * (-len(b) % 4)


def query_req(level=2):
    return HANDLE + struct.pack('<H', level)


def query_resp(blob, level=2, status=0):
    """[out,unique] lsa_DomainInformationPolicy *info: referent, level,
    blob_size, referent, conformant size, blob; then the status."""
    return pad4(struct.pack('<IIIII', 0x00020000, level, len(blob), 0x00020004, len(blob)) + blob) + \
        struct.pack('<I', status)


def set_req(blob, level=2):
    return HANDLE + struct.pack('<H2xIIIII', level, 0x00020000, level, len(blob), 0x00020004, len(blob)) + blob


def set_resp(status=0):
    return struct.pack('<I', status)


def rawkey(length1, sid_off, cert_len, cert_off, sid, cert, length2=0x14, rest_pad=b''):
    """An EfsKey with every field given (no consistency checks)."""
    rest = struct.pack('<IIIIII', length2, sid_off, 0, cert_len, cert_off, 0x20) + sid + cert + rest_pad
    return struct.pack('<I', length1) + rest


def build(path_main, path_bad):
    f = []
    tcp = TCP(f, 50000)
    rpc = RPC(tcp)
    rpc.bind()
    adm = efskey(DOM + '-500', certificate('Administrator', 1))
    rec = efskey(DOM + '-1104', certificate('EFS Recovery', 2))
    sysk = efskey('S-1-5-18', certificate('SYSTEM', 3))
    # Query responses with 2, 0, 1 and 3 keys
    rpc.call(53, query_req(), query_resp(efsblob([adm, rec])))
    rpc.call(53, query_req(), query_resp(efsblob([])))
    rpc.call(53, query_req(), query_resp(efsblob([sysk])))
    rpc.call(53, query_req(), query_resp(efsblob([adm, rec, sysk])))
    # Set requests
    rpc.call(54, set_req(efsblob([rec, adm])), set_resp())
    rpc.call(54, set_req(efsblob([])), set_resp())
    tcp.fin()
    pcap(path_main, f)

    g = []
    tcp = TCP(g, 50001)
    rpc = RPC(tcp)
    rpc.bind()
    sid = sid_bytes('S-1-5-18')
    cert = certificate('Administrator', 1)
    # reproducers of the fix (gpef_offsets.py): SID offset 0x18 with an empty
    # certificate, SID offset that wraps to before the key, SID offset of the next key
    for so in (0x18, 0xFFFFFFF8, 0x18 + 40):
        k1 = struct.pack('<I', 4 + 24 + len(sid)) + struct.pack('<IIIIII', 0x20, so, 0, 0, 0x18, 0x20) + sid
        k2 = struct.pack('<I', 4 + 24 + len(sid)) + struct.pack('<IIIIII', 0x20, 0x18, 0, 0, 0x18, 0x20) + sid
        rpc.call(53, query_req(), query_resp(struct.pack('<II', 0x00010001, 2) + k1 + k2))
    # certificate offset past the key, and a length that wraps
    k = rawkey(4 + 24 + len(sid) + len(cert), 24, len(cert), 0x1000, sid, cert)
    rpc.call(53, query_req(), query_resp(efsblob([k])))
    k = rawkey(4 + 24 + len(sid) + len(cert), 24, 0xFFFFFFF0, 24 + len(sid), sid, cert)
    rpc.call(53, query_req(), query_resp(efsblob([k])))
    # SID offset at the end of the key
    k = rawkey(4 + 24 + len(sid) + len(cert), 24 + len(sid) + len(cert), len(cert), 24 + len(sid), sid, cert)
    rpc.call(53, query_req(), query_resp(efsblob([k])))
    # key shorter than its header, and a key longer than the blob
    rpc.call(53, query_req(), query_resp(struct.pack('<II', 0x00010001, 1) + struct.pack('<I', 8) + bytes(12)))
    rpc.call(53, query_req(), query_resp(struct.pack('<II', 0x00010001, 1) + struct.pack('<I', 5000) + bytes(40)))
    # key count beyond the keys in the blob (the second key is missing)
    rpc.call(53, query_req(), query_resp(struct.pack('<II', 0x00010001, 3) + efskey(DOM + '-500', cert)))
    # key count 0xffffffff, and a key of length 0
    rpc.call(53, query_req(), query_resp(struct.pack('<II', 0x00010001, 0xffffffff) + struct.pack('<I', 0) + bytes(20)))
    # a certificate that is not DER, and a key too short for its SID
    k = rawkey(4 + 24 + len(sid) + 4, 24, 4, 24 + len(sid), sid, b'\x30\x03\x02\x01')
    rpc.call(53, query_req(), query_resp(efsblob([k])))
    k = rawkey(4 + 24 + 6, 24, 0, 24, sid[:6], b'')
    rpc.call(53, query_req(), query_resp(efsblob([k])))
    # a blob of one octet and an empty blob
    rpc.call(53, query_req(), query_resp(b'\x01'))
    rpc.call(53, query_req(), query_resp(b''))
    tcp.fin()
    pcap(path_bad, g)


if __name__ == '__main__':
    out = sys.argv[1]
    build(os.path.join(out, 'gpef-coverage.pcap'), os.path.join(out, 'gpef-coverage-malformed.pcap'))
