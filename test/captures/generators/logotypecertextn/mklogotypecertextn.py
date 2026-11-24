#!/usr/bin/env python3
# Generates test/captures/logotypecertextn_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Write the synthetic LogotypeCertExtn coverage captures.

Usage: mklogotypecertextn.py <outdir>

The RFC 3709 logotype certificate extension is carried in X.509
certificates sent in TLS 1.2 Certificate handshake messages (TCP port
443). Each TLS connection (ClientHello; ServerHello, Certificate,
ServerHelloDone) carries one made-up certificate whose extensions hold
one variant of the extension. The certificates are built by hand with
DER helpers; the names, keys and signatures are placeholder bytes and
nothing is signed. Nothing comes from a real network.
"""
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else '.'


# ---------------------------------------------------------------- DER
def tlv(tag, body):
    n = len(body)
    if n < 128:
        ln = bytes([n])
    elif n < 256:
        ln = b'\x81' + bytes([n])
    else:
        ln = b'\x82' + struct.pack('>H', n)
    return bytes([tag]) + ln + body


def seq(*a):
    return tlv(0x30, b''.join(a))


def integer(v):
    n = max(1, (v.bit_length() + 8) // 8)
    return tlv(0x02, v.to_bytes(n, 'big'))


def oid(s):
    p = [int(x) for x in s.split('.')]
    b = bytes([p[0] * 40 + p[1]])
    for x in p[2:]:
        t = [x & 0x7f]
        x >>= 7
        while x:
            t.append(0x80 | (x & 0x7f))
            x >>= 7
        b += bytes(reversed(t))
    return tlv(0x06, b)


def ia5(s, tag=0x16):
    return tlv(tag, s.encode())


def octets(b):
    return tlv(0x04, b)


# ------------------------------------------------- logotype extension
SHA256 = '2.16.840.1.101.3.4.2.1'
SHA1 = '1.3.14.3.2.26'


def hashes(*algs):
    out = []
    for i, a in enumerate(algs):
        n = 32 if a == SHA256 else 20
        alg = seq(oid(a), b'\x05\x00') if i % 2 == 0 else seq(oid(a))
        out.append(seq(alg, octets(bytes([0x10 + i] * n))))
    return seq(*out)


def uris(*u):
    return seq(*[ia5(x) for x in u])


def details(mt, h, u):
    return seq(ia5(mt), hashes(*h), uris(*u))


def image(mt='image/png', info=None, h=(SHA256,), u=('https://logo.example.net/a.png',)):
    return seq(details(mt, h, u), *([info] if info is not None else []))


def image_info(typ=None, size=1234, x=64, y=48, res=None, lang=None):
    p = []
    if typ is not None:
        p.append(tlv(0x80, bytes([typ])))
    p += [integer(size), integer(x), integer(y)]
    if res is not None:
        p.append(tlv(0x80 | res[0], res[1].to_bytes(2, 'big')))
    if lang:
        p.append(tlv(0x84, lang.encode()))
    return seq(*p)


def audio(mt='audio/mpeg', info=None, h=(SHA1,), u=('https://logo.example.net/a.mp3',)):
    return seq(details(mt, h, u), *([info] if info is not None else []))


def audio_info(rate=None, lang=None):
    p = [integer(4096), integer(2500), integer(2)]
    if rate:
        p.append(tlv(0x83, rate.to_bytes(3, 'big')))
    if lang:
        p.append(tlv(0x84, lang.encode()))
    return seq(*p)


def direct(images=(), audios=()):
    body = b''
    if images:
        body += seq(*images)
    if audios:
        body += tlv(0xa1, b''.join(audios))
    return tlv(0xa0, body)


def indirect(h=(SHA256, SHA1), u=('https://ltd.example.net/x.ltd', 'http://ltd2.example.net/x.ltd')):
    return tlv(0xa1, hashes(*h) + uris(*u))


def other(typ, info):
    return seq(oid(typ), info)


def logotype(community=None, issuer=None, subject=None, others=None):
    b = b''
    if community is not None:
        b += tlv(0xa0, seq(*community))
    if issuer is not None:
        b += tlv(0xa1, issuer)
    if subject is not None:
        b += tlv(0xa2, subject)
    if others is not None:
        b += tlv(0xa3, seq(*others))
    return tlv(0x30, b)


I_PNG = image('image/png', image_info(), (SHA256,), ('https://logo.example.net/a.png',))
VARIANTS = []


def variant(oidstr, ext, crit=False):
    VARIANTS.append((oidstr, ext, crit))


PE = '1.3.6.1.5.5.7.1.12'
# 1 subject logo, direct, one image without image info
variant(PE, logotype(subject=direct([image('image/gif')])))
# 2 issuer logo, direct, image info: default type, resolution numBits
variant(PE, logotype(issuer=direct([image('image/jpeg', image_info(None, 70000, 640, 480, (1, 24)))])), True)
# 3 subject logo, grayScale, tableSize, language, two images (two hashes, two URIs)
variant(PE, logotype(subject=direct([
    image('image/png', image_info(0, 500, 16, 16, (2, 256), 'en'), (SHA256, SHA1),
          ('https://logo.example.net/g.png', 'ftp://logo.example.net/g.png')),
    image('image/svg+xml', image_info(1, 900, 32, 32, None, 'sv'))])))
# 4 community logos (two entries: direct with image and audio; indirect)
variant(PE, logotype(community=[
    direct([image('image/png', image_info(1, 10, 8, 8)), image()], [audio('audio/mpeg', audio_info(44100, 'fi'))]),
    indirect()]))
# 5 audio only, with and without audio info
variant(PE, logotype(subject=direct([], [audio(), audio('audio/wav', audio_info(8000), (SHA256, SHA1), ('https://a.example/w.wav',))])))
# 6 indirect issuer and subject logos
variant(PE, logotype(issuer=indirect(), subject=indirect((SHA256,), ('https://ltd.example.net/s.ltd',))))
# 7 other logos: loyalty and background OIDs and an unknown one
variant(PE, logotype(others=[
    other('1.3.6.1.5.5.7.20.1', direct([I_PNG])),
    other('1.3.6.1.5.5.7.20.2', indirect()),
    other('1.3.6.1.5.5.7.20.99', direct([image('image/png')]))]))
# 8 everything at once
variant(PE, logotype(community=[direct([I_PNG])], issuer=direct([I_PNG]), subject=indirect(),
                     others=[other('1.3.6.1.5.5.7.20.1', direct([], [audio()]))]))
# 9 empty extension
variant(PE, logotype())
# 10, 11 the extension under the loyalty and background extension OIDs
variant('1.3.6.1.5.5.7.20.1', logotype(subject=direct([I_PNG])))
variant('1.3.6.1.5.5.7.20.2', logotype(subject=indirect()))
# 12 an extension with a long URI (300 bytes)
variant(PE, logotype(subject=direct([image('image/png', image_info(), (SHA256,), ('https://x.example/' + 'a' * 280,))])))

# the same malformed in the second capture
BAD = []
good = logotype(subject=direct([I_PNG]))
BAD.append(good[:len(good) // 2])                         # truncated, length too large
BAD.append(tlv(0x30, tlv(0xa2, tlv(0xa5, b'\x00\x01'))))  # unknown choice alternative
BAD.append(tlv(0x30, tlv(0xa2, tlv(0xa0, tlv(0x30, tlv(0x30, tlv(0x30, ia5('x'))))))))  # details without hashes
BAD.append(tlv(0x30, tlv(0xa0, tlv(0x04, b'abc'))))       # wrong tag inside communityLogos
BAD.append(tlv(0x30, tlv(0xa3, seq(seq(integer(5), direct()))))) # logotypeType not an OID
BAD.append(tlv(0x30, tlv(0xa1, tlv(0xa1, tlv(0x30, seq(tlv(0x02, b'\x01'), octets(b'x')) + uris('u'))))))  # hash alg not a SEQUENCE
BAD.append(b'\x30\x84\xff\xff\xff\xff\x00')               # huge length
BAD.append(tlv(0x31, b''))                                # SET instead of SEQUENCE
BAD.append(tlv(0x30, tlv(0xa2, tlv(0xa0, tlv(0x30, tlv(0x30, seq(ia5('m'), hashes(SHA256), tlv(0x30, tlv(0x02, b'\x01')))))))))  # URI list holds an INTEGER


# ---------------------------------------------------------- certificate
def name(cn):
    return seq(tlv(0x31, seq(oid('2.5.4.3'), ia5(cn, 0x0c))))


def cert(n, ext, extoid=PE, crit=False):
    sigalg = seq(oid('1.2.840.113549.1.1.11'), b'\x05\x00')
    extn = seq(oid(extoid), *([b'\x01\x01\xff'] if crit else []), octets(ext))
    bc = seq(oid('2.5.29.19'), octets(seq()))
    tbs = seq(tlv(0xa0, integer(2)), integer(1000 + n), sigalg, name('Test CA %d' % n),
              seq(ia5('230101000000Z', 0x17), ia5('330101000000Z', 0x17)), name('subject %d' % n),
              seq(seq(oid('1.2.840.113549.1.1.1'), b'\x05\x00'),
                  tlv(0x03, b'\x00' + seq(integer(0xc0ffee000000000000000001 + n), integer(65537)))),
              tlv(0xa3, seq(bc, extn)))
    return seq(tbs, sigalg, tlv(0x03, b'\x00' + bytes([n]) * 32))


# ------------------------------------------------------------ transport
def ipv4(src, dst, proto, payload):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0,
                      bytes(src), bytes(dst))
    s = sum((hdr[i] << 8) | hdr[i + 1] for i in range(0, 20, 2))
    s = (s & 0xffff) + (s >> 16)
    s = (s & 0xffff) + (s >> 16)
    return hdr[:10] + struct.pack('>H', ~s & 0xffff) + hdr[12:] + payload


class Flow:
    def __init__(self, n):
        self.sport = 40000 + n
        self.seq = {False: 1000, True: 5000}

    def frame(self, payload, rev):
        a, b = bytes.fromhex('020000000001'), bytes.fromhex('020000000002')
        e = (b + a if rev else a + b) + b'\x08\x00'
        sp, dp = (443, self.sport) if rev else (self.sport, 443)
        s = self.seq[rev]
        self.seq[rev] += len(payload)
        ack = self.seq[not rev]
        tcp = struct.pack('>HHIIBBHHH', sp, dp, s, ack, 0x50, 0x18, 65535, 0, 0) + payload
        src, dst = ([192, 0, 2, 2], [192, 0, 2, 1]) if rev else ([192, 0, 2, 1], [192, 0, 2, 2])
        return e + ipv4(src, dst, 6, tcp)


def record(typ, body):
    return struct.pack('>BHH', typ, 0x0303, len(body)) + body


def handshake(typ, body):
    return bytes([typ]) + len(body).to_bytes(3, 'big') + body


def client_hello(n):
    body = struct.pack('>H', 0x0303) + bytes([n]) * 32 + b'\x00' + struct.pack('>HH', 2, 0xc02f) \
        + b'\x01\x00'
    body += struct.pack('>H', 0)
    return record(22, handshake(1, body))


def server_flight(n, der):
    sh = struct.pack('>H', 0x0303) + bytes([0x80 + n]) * 32 + b'\x00' + struct.pack('>HB', 0xc02f, 0) \
        + struct.pack('>H', 0)
    certs = len(der).to_bytes(3, 'big') + der
    cm = len(certs).to_bytes(3, 'big') + certs
    return record(22, handshake(2, sh)) + record(22, handshake(11, cm)) + record(22, handshake(14, b''))


def write_pcap(name, frames):
    with open(name, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def build(items):
    frames = []
    for n, (extoid, ext, crit) in enumerate(items, 1):
        fl = Flow(n)
        frames.append(fl.frame(client_hello(n), False))
        frames.append(fl.frame(server_flight(n, cert(n, ext, extoid, crit)), True))
    return frames


def main():
    frames = build(VARIANTS)
    write_pcap(os.path.join(OUT, 'logotypecertextn-coverage.pcap'), frames)
    mal = build([(PE, b, False) for b in BAD])
    write_pcap(os.path.join(OUT, 'logotypecertextn-coverage-malformed.pcap'), mal)
    print(len(frames), len(mal))


if __name__ == '__main__':
    main()
