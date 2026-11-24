#!/usr/bin/env python3
# Generates test/captures/zrtp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the ZRTP coverage captures: mkzrtp.py <outdir>.
ZRTP packets are RTP version 0 packets with the magic cookie "ZRTP". As in
a real call, a SIP INVITE with SDP announces the RTP ports; RTP then
hands the ZRTP packets on that port pair to the ZRTP dissector. Only the
packet structure is built: hashes, MACs and DH values are filler bytes
(the CRC-32C at the end of each message is the only real checksum)."""
import struct
import sys
import os

A, B = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
MA, MB = b'\x02\x00\x00\x00\x00\x01', b'\x02\x00\x00\x00\x00\x02'
PA, PB = 16384, 16386            # RTP ports of A and B
SSRC_A, SSRC_B = 0x11223344, 0x55667788

def crc32c(data):
    crc = 0xffffffff
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
    return ~crc & 0xffffffff

def ipck(ip):
    ck = sum(struct.unpack('>10H', ip)); ck = (ck & 0xffff) + (ck >> 16); ck = (ck & 0xffff) + (ck >> 16)
    return ip[:10] + struct.pack('>H', ~ck & 0xffff) + ip[12:]

ident = [0]
def udp(fromA, sport, dport, payload):
    ident[0] += 1
    s, d, ms, md = (A, B, MA, MB) if fromA else (B, A, MB, MA)
    u = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
    ip = ipck(struct.pack('>BBHHHBBH4s4s', 0x45, 0, 28 + len(payload), ident[0], 0, 64, 17, 0, s, d))
    return md + ms + b'\x08\x00' + ip + u + payload

seqs = {True: 100, False: 7000}
def zrtp(fromA, mtype, data, bad_crc=False, cut=None, seq=None, ssrc=None, ports=(PA, PB)):
    """One ZRTP packet: RTP-like header, preamble, length, type, data, CRC."""
    mtype = mtype.encode().ljust(8)[:8]
    msg = struct.pack('>HH', 0x505a, (12 + len(data) + 4) // 4) + mtype + data
    s = seqs[fromA] if seq is None else seq
    seqs[fromA] += 1
    hdr = struct.pack('>BBH', 0x10, 0, s) + b'ZRTP' + struct.pack('>I', ssrc or (SSRC_A if fromA else SSRC_B))
    body = hdr + msg
    crc = crc32c(body) ^ (0x1 if bad_crc else 0)
    pkt = body + struct.pack('<I', crc)   # the dissector expects the CRC-32C byte-swapped
    if cut is not None:
        pkt = pkt[:cut]
    pa, pb = ports
    return udp(fromA, pa if fromA else pb, pb if fromA else pa, pkt)

def fill(n, v):
    return bytes([(v + i) & 0xff for i in range(n)])

def hello(version=b'1.10', client=b'Test Client A    ', flags=0x60, hashes=(b'S256',), ciphers=(b'AES1',),
          auths=(b'HS32',), keys=(b'DH3k',), sass=(b'B32 ',), counts=None):
    hc, cc, ac, kc, sc = counts or (len(hashes), len(ciphers), len(auths), len(keys), len(sass))
    d = version + client[:16].ljust(16) + fill(32, 0x10) + fill(12, 0x40)
    d += bytes([flags, hc, (cc << 4) | ac, (kc << 4) | sc])
    for l in (hashes, ciphers, auths, keys, sass):
        d += b''.join(l)
    return d + fill(8, 0xa0)

def commit(hsh=b'S256', cipher=b'AES1', at=b'HS32', key=b'DH3k', sas=b'B32 '):
    d = fill(32, 0x20) + fill(12, 0x50) + hsh + cipher + at + key + sas
    if key == b'Mult':
        d += fill(16, 0x60)
    elif key == b'Prsh':
        d += fill(16, 0x60) + fill(8, 0x70)
    else:
        d += fill(32, 0x80)
    return d + fill(8, 0xb0)

def dhpart(pvlen):
    return fill(32, 0x30) + fill(8, 0x01) + fill(8, 0x02) + fill(8, 0x03) + fill(8, 0x04) + fill(pvlen, 0x90) + fill(8, 0xc0)

def confirm():
    return fill(8, 0xd0) + fill(16, 0xe0) + fill(40, 0xf0)     # HMAC, CFB IV, encrypted data

def sip(fromA, text):
    return udp(fromA, 5060, 5060, text.encode().replace(b'\n', b'\r\n'))

def sdp_msg(first):
    ip, port = ('192.0.2.1', PA) if first else ('192.0.2.2', PB)
    body = ('v=0\no=- 1 1 IN IP4 %s\ns=-\nc=IN IP4 %s\nt=0 0\nm=audio %d RTP/AVP 0 101\n'
            'a=rtpmap:0 PCMU/8000\na=rtpmap:101 telephone-event/8000\na=zrtp-hash:1.10 %s\n') % (ip, ip, port, '0' * 64)
    if first:
        start = 'INVITE sip:bob@192.0.2.2 SIP/2.0'
        hdr = ('Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\nFrom: <sip:alice@192.0.2.1>;tag=a\nTo: <sip:bob@192.0.2.2>\n'
               'Call-ID: zrtp-cov-1@192.0.2.1\nCSeq: 1 INVITE\nContact: <sip:alice@192.0.2.1>\n')
    else:
        start = 'SIP/2.0 200 OK'
        hdr = ('Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\nFrom: <sip:alice@192.0.2.1>;tag=a\nTo: <sip:bob@192.0.2.2>;tag=b\n'
               'Call-ID: zrtp-cov-1@192.0.2.1\nCSeq: 1 INVITE\nContact: <sip:bob@192.0.2.2>\n')
    return sip(first, start + '\n' + hdr + 'Content-Type: application/sdp\nContent-Length: %d\n\n' % len(body) + body)

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000, len(fr), len(fr)))
            f.write(fr)

ERRORS = [0x10, 0x20, 0x30, 0x40, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x61, 0x62, 0x63, 0x70, 0x80, 0x90, 0x91, 0xa0, 0xb0, 0x100, 0x777]

def srtp(fromA, seq, payload):
    # RTP version 2 packet on the media ports (SRTP after the Conf2ACK); filler payload
    h = struct.pack('>BBHII', 0x80, 0, seq, 160 * seq, SSRC_A if fromA else SSRC_B)
    return udp(fromA, PA if fromA else PB, PB if fromA else PA, h + payload)

def main(out):
    f = []
    f.append(sdp_msg(True)); f.append(sdp_msg(False))                      # 1-2 SIP/SDP
    ALL_H = (b'S256', b'S384', b'N256', b'N384')
    ALL_C = (b'AES1', b'AES2', b'AES3', b'2FS1', b'2FS2', b'2FS3', b'CAM1', b'CAM2', b'CAM3')
    ALL_A = (b'HS32', b'HS80', b'SK32', b'SK64')
    ALL_K = (b'DH2k', b'DH3k', b'DH4k', b'Prsh', b'EC25', b'EC38', b'EC52', b'Mult')
    ALL_S = (b'B32 ', b'B256')
    f.append(zrtp(True, 'Hello', hello(flags=0x70, hashes=ALL_H, ciphers=ALL_C, auths=ALL_A, keys=ALL_K, sass=ALL_S)))   # 3
    f.append(zrtp(False, 'HelloACK', b''))                                   # 4
    f.append(zrtp(False, 'Hello', hello(client=b'Test Client B', flags=0x40)))  # 5
    f.append(zrtp(True, 'HelloACK', b''))                                    # 6
    f.append(zrtp(True, 'Commit', commit()))                                 # 7 DH commit
    f.append(zrtp(False, 'DHPart1', dhpart(384)))                            # 8
    f.append(zrtp(True, 'DHPart2', dhpart(384)))                             # 9
    f.append(zrtp(False, 'Confirm1', confirm()))                             # 10
    f.append(zrtp(True, 'Confirm2', confirm()))                              # 11
    f.append(zrtp(False, 'Conf2ACK', b''))                                   # 12 starts the SRTP streams
    f.append(srtp(True, 1, fill(40, 0x11)))                                  # 13 media after the Conf2ACK
    f.append(srtp(False, 1, fill(40, 0x22)))                                 # 14
    # Hello variants
    f.append(zrtp(True, 'Hello', hello(version=b'0.95', counts=(0, 0, 0, 0, 0), hashes=(), ciphers=(), auths=(), keys=(), sass=())))  # 15 no algorithms
    f.append(zrtp(False, 'Hello', hello(version=b'0.85', flags=0x10, hashes=(b'XXXX',), ciphers=(b'YYYY',), auths=(b'ZZZZ',), keys=(b'WWWW',), sass=(b'VVVV',))))  # 16 unknown algorithm names
    f.append(zrtp(True, 'Hello', hello(version=b'9.99')))                    # 17 unsupported version
    f.append(zrtp(False, 'Hello', hello(version=b'0.50')))                   # 18 unsupported 0.x version
    f.append(zrtp(True, 'Hello', hello(version=b'1.00', flags=0x00, hashes=(b'S256',) * 7 + (b'S384',) * 8, ciphers=(b'AES1',) * 15,
                                          auths=(b'HS80',) * 15, keys=(b'EC25',) * 15, sass=(b'B256',) * 15)))   # 19 maximum counts
    f.append(zrtp(False, 'Hello', hello(version=b'0.90', hashes=(b'S256',), ciphers=(b'AES3', b'CAM1'), auths=(b'SK32',), keys=(b'DH2k', b'EC52'), sass=(b'B32 ',))))  # 20
    # Commit variants
    f.append(zrtp(True, 'Commit', commit(key=b'Mult')))                      # 21 multistream
    f.append(zrtp(False, 'Commit', commit(key=b'Prsh', hsh=b'N256', cipher=b'2FS2', at=b'SK64', sas=b'B256')))   # 22 preshared
    f.append(zrtp(True, 'Commit', commit(hsh=b'N384', cipher=b'CAM3', at=b'HS80', key=b'EC38')))   # 23
    f.append(zrtp(False, 'Commit', commit(hsh=b'????', cipher=b'????', at=b'????', key=b'????', sas=b'????')))   # 24 unknown values
    f.append(zrtp(True, 'DHPart1', dhpart(256)))                             # 25 DH2k sized
    f.append(zrtp(False, 'DHPart2', dhpart(64)))                             # 26
    f.append(zrtp(True, 'Confirm1', confirm()))                              # 27
    f.append(zrtp(False, 'Confirm2', confirm() + fill(16, 0x01)))            # 28
    # other message types
    f.append(zrtp(True, 'Ping', b'1.10' + fill(8, 0x30)))                    # 29
    f.append(zrtp(False, 'PingACK', b'1.10' + fill(8, 0x31) + fill(8, 0x32) + struct.pack('>I', SSRC_A)))   # 30
    f.append(zrtp(True, 'GoClear', fill(8, 0x40)))                           # 31
    f.append(zrtp(False, 'ClearACK', b''))                                   # 32
    f.append(zrtp(True, 'SASrelay', confirm()))                              # 33
    f.append(zrtp(False, 'RelayACK', b''))                                   # 34
    for e in ERRORS:                                                         # 35-55 every error code, one unknown
        f.append(zrtp(e & 1 == 0, 'Error', struct.pack('>I', e)))
    f.append(zrtp(False, 'ErrorACK', b''))                                   # 56
    f.append(zrtp(True, 'Zzzz', fill(8, 0x50)))                              # 57 unknown message type
    f.append(zrtp(False, 'Conf2ACK', b''))                                   # 58 a repeated Conf2ACK (retransmission)
    write_pcap(os.path.join(out, 'zrtp-coverage.pcap'), f)

    seqs[True], seqs[False] = 500, 9000
    b = [sdp_msg(True), sdp_msg(False)]
    b.append(zrtp(True, 'Hello', hello(), bad_crc=True))                     # bad CRC, error expert info
    b.append(zrtp(False, 'Ping', b'1.10' + fill(8, 0x30), bad_crc=True))
    b.append(zrtp(True, 'Hello', hello(), cut=60))                           # truncated in the algorithm lists
    b.append(zrtp(True, 'Hello', hello(), cut=24))                           # only the message header
    b.append(zrtp(True, 'Commit', commit(), cut=70))
    b.append(zrtp(False, 'DHPart1', dhpart(0), cut=70))                      # shorter than the fixed part
    b.append(zrtp(True, 'DHPart2', fill(40, 0), cut=90))                     # negative pv length
    b.append(zrtp(False, 'Confirm1', confirm(), cut=40))
    b.append(zrtp(True, 'Confirm2', fill(10, 0)))
    b.append(zrtp(False, 'Ping', b'1.1', cut=30))
    b.append(zrtp(True, 'PingACK', b'1.10' + fill(8, 0x31), cut=44))
    b.append(zrtp(False, 'GoClear', b'', cut=26))
    b.append(zrtp(True, 'Error', b'', cut=26))
    b.append(zrtp(False, 'Hello', b''))                                      # no data at all
    b.append(zrtp(True, 'HelloACK', b'', cut=14))                            # shorter than the message header
    b.append(zrtp(False, 'SASrelay', fill(30, 0), cut=60))
    b.append(zrtp(True, 'Commit', commit(key=b'Mult'), cut=100))
    b.append(zrtp(False, 'Commit', commit(key=b'Prsh'), cut=110))
    # a second session on ports no SDP announced: reached by the RTP heuristic
    # (--enable-heuristic rtp_udp) or Decode As udp.port==20000/20002,zrtp
    q = (20000, 20002)
    b.append(zrtp(True, 'Hello', hello(), ports=q))
    b.append(zrtp(False, 'HelloACK', b'', ports=q))
    b.append(zrtp(False, 'Conf2ACK', b'', ports=q))
    b.append(zrtp(True, 'Ping', b'1.10' + fill(8, 0x30), ports=q))
    write_pcap(os.path.join(out, 'zrtp-coverage-malformed.pcap'), b)

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
