#!/usr/bin/env python3
# Generates test/captures/ismacryp_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Generates the ISMACryp coverage captures. Usage: mkismacryp.py <outdir>
# Everything is synthetic: the "encrypted" payloads and the IVs/key
# indicators are made-up placeholder bytes, no key or cipher is involved.
# ISMACryp is reached through SDP (a SIP INVITE announcing the dynamic RTP
# payload types) and RTP.
import struct
import sys
import os


def write_pcap(fn, linktype, frames):
    with open(fn, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(fr), len(fr)))
            f.write(fr)


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ipv4(proto, payload, src='192.0.2.1', dst='192.0.2.2'):
    s = bytes(int(x) for x in src.split('.'))
    d = bytes(int(x) for x in dst.split('.'))
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, s, d)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload


def eth(etype, payload, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01'):
    return dst + src + struct.pack('!H', etype) + payload


def tcp(sport, dport, payload, seq=1, ack=1, flags=0x18):
    return struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


def eth_ip_tcp(sport, dport, payload, seq=1, ack=1, flags=0x18):
    return eth(0x0800, ipv4(6, tcp(sport, dport, payload, seq, ack, flags)))


def eth_ip_udp(sport, dport, payload):
    return eth(0x0800, ipv4(17, udp(sport, dport, payload)))


class Bits:
    def __init__(self):
        self.v, self.n = 0, 0

    def add(self, value, nbits):
        self.v = (self.v << nbits) | (value & ((1 << nbits) - 1))
        self.n += nbits

    def bytes_(self):
        pad = (8 - self.n % 8) % 8
        return (self.v << pad).to_bytes((self.n + pad) // 8, 'big')


class Prof:
    """The settings the dissector uses: its preferences (user mode) or the
    values implied by the RFC 3640 mode, and the version."""
    def __init__(self, version=11, selective=True, slice_ind=False, pad_ind=False,
                 iv=4, div=0, ki=0, ki_per_au=False, size=0, index=0, idelta=0,
                 cts=0, dts=22, rap=True, state=0, prefs=None):
        self.__dict__.update(locals())
        del self.__dict__['self']
        self.prefs = prefs or {}

    def header_byte(self):
        return (self.version == 11 and self.selective) or (
            self.version == 20 and (self.selective or self.slice_ind or self.pad_ind))


def au_header(p, b, first, enc=1, iv=b'\x80\x00\x00\x01', ki=b'', size=0,
              index=0, cts=None, dts=None, rap=1, state=0, slice_start=0,
              slice_end=0, padcnt=0):
    """Append one AU header. cts/dts: None (flag 0) or a delta value."""
    if p.header_byte():
        if p.version == 11:
            b.add(enc, 1)
            b.add(0, 7)
        else:
            b.add(enc, 1)
            b.add(slice_start, 1)
            b.add(slice_end, 1)
            b.add(padcnt, 3)
            b.add(0, 2)
    if first:
        for c in iv[:p.iv]:
            b.add(c, 8)
        for c in ki[:p.ki].ljust(p.ki, b'\x00'):
            b.add(c, 8)
    else:
        for c in iv[:p.div].ljust(p.div, b'\x01'):
            b.add(c, 8)
        if p.ki_per_au:
            for c in ki[:p.ki].ljust(p.ki, b'\x00'):
                b.add(c, 8)
    b.add(size, p.size)
    b.add(index, p.index if first else p.idelta)
    if p.cts:
        b.add(0 if cts is None else 1, 1)
        if cts is not None:
            b.add(cts, p.cts)
    if p.dts:
        b.add(0 if dts is None else 1, 1)
        if dts is not None:
            b.add(dts, p.dts)
    if p.rap:
        b.add(rap, 1)
    b.add(state, p.state)


def payload(p, aus, data=b'\xde\xad\xbe\xef' * 8):
    """AU headers section + the "encrypted" message."""
    b = Bits()
    for i, kw in enumerate(aus):
        au_header(p, b, i == 0, **kw)
    n = b.n
    return struct.pack('!H', n) + b.bytes_() + data


def rtp(pt, seq, ts, pl, ssrc=0x11223344, marker=0):
    return struct.pack('!BBHII', 0x80, (marker << 7) | pt, seq, ts, ssrc) + pl


SDP_PT = {96: 'enc-mpeg4-generic', 97: 'enc-isoff-generic', 98: 'ISMACRYP'}


def sdp_invite(ports, pts):
    body = ('v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n')
    for port, pt in zip(ports, pts):
        body += ('m=video %d RTP/AVP %d\r\na=rtpmap:%d %s/90000\r\n'
                 % (port, pt, pt, SDP_PT[pt]))
    msg = ('INVITE sip:media@192.0.2.2 SIP/2.0\r\n'
           'Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n'
           'From: <sip:a@192.0.2.1>;tag=1\r\nTo: <sip:media@192.0.2.2>\r\n'
           'Call-ID: ismacryp-coverage@192.0.2.1\r\nCSeq: 1 INVITE\r\n'
           'Contact: <sip:a@192.0.2.1>\r\nContent-Type: application/sdp\r\n'
           'Content-Length: %d\r\n\r\n%s' % (len(body), body))
    return eth_ip_udp(5060, 5060, msg.encode())


def stream(port, pt, pkts, sport=40000):
    """pkts: list of RTP payloads"""
    out = []
    for i, pl in enumerate(pkts):
        out.append(eth_ip_udp(sport, port, rtp(pt, 100 + i, 1000 + 3000 * i, pl)))
    return out


# the defaults of the dissector (RFC 3640 avc-video mode, version 1.1)
AVC = Prof(11, True, iv=4, dts=22, rap=True)
# version 2.0 with the preference defaults (all lengths zero)
V20D = Prof(20, True, iv=4, dts=0, rap=False)


def main(outdir):
    f = [sdp_invite([5004, 5006, 5008], [96, 97, 98])]
    # reproducer of the DTS flag fix: AU 1 with IV and DTS flag 0, AU 2 with
    # DTS flag 0 (the flag was read relative to the packet start before)
    f += stream(5004, 96, [
        payload(AVC, [dict(dts=None), dict(dts=None)]),
        # DTS flag 1 in the second AU (22 bit delta), third AU without
        payload(AVC, [dict(dts=0x2aaaaa, enc=0), dict(dts=0x155555, rap=0),
                      dict(dts=None, rap=1)]),
        # one AU, not encrypted, RAP 0, DTS set
        payload(AVC, [dict(enc=0, dts=0x3fffff, rap=0)]),
        # several AUs, flags alternate
        payload(AVC, [dict(dts=1)] + [dict(dts=(i if i % 2 else None)) for i in range(5)]),
    ])
    # version 2.0 (enc-isoff-generic): header byte and IV only
    f += stream(5006, 97, [
        payload(V20D, [dict(slice_start=1, slice_end=1, padcnt=5)]),
        payload(V20D, [dict(), dict(enc=0)]),
    ], 40001)
    # generic ISMACRYP payload type: version from the preference (1.1)
    f += stream(5008, 98, [
        payload(AVC, [dict(dts=None)]),
        payload(AVC, [dict(dts=7), dict(dts=None)]),
    ], 40002)
    write_pcap(os.path.join(outdir, 'ismacryp-coverage.pcap'), 1, f)
    write_prefs(outdir)
    write_malformed(outdir)


# Profiles for the preferences. Each gives the -o options the capture needs
# (all options start with ismacryp.) and the header layout they imply.
PROFILES = {
    # RFC 3640 modes (version 1.1)
    'aac': (Prof(11, True, iv=4, size=13, index=3, idelta=3, cts=0, dts=0,
                 rap=False),
            {'rfc3640_mode': 'aac-hbr'}),
    'mpeg4': (Prof(11, True, iv=4, dts=22, rap=True),
              {'rfc3640_mode': 'mpeg4-video'}),
    # user mode, version 1.1, key indicator in every AU, delta IV, CTS, DTS,
    # RAP and stream state, no header byte
    'user11': (Prof(11, False, iv=2, div=1, ki=2, ki_per_au=True, size=5, index=3,
                    idelta=2, cts=6, dts=7, rap=True, state=3),
               {'user_mode': 'TRUE', 'selective_encryption': 'FALSE', 'iv_length': 2,
                'delta_iv_length': 1, 'key_indicator_length': 2,
                'key_indicator_per_au_flag': 'TRUE', 'au_size_length': 5,
                'au_index_length': 3, 'au_index_delta_length': 2,
                'cts_delta_length': 6, 'dts_delta_length': 7,
                'random_access_indication': 'TRUE', 'stream_state_indication': 3}),
    # the same with a key indicator in the first AU only and a header byte
    'user11b': (Prof(11, True, iv=1, div=0, ki=3, ki_per_au=False, size=7, index=4,
                     idelta=4, cts=3, dts=0, rap=False, state=0),
                {'user_mode': 'TRUE', 'iv_length': 1, 'key_indicator_length': 3,
                 'au_size_length': 7, 'au_index_length': 4,
                 'au_index_delta_length': 4, 'cts_delta_length': 3,
                 'dts_delta_length': 0}),
    # version 2.0 with slice and padding indication
    'v20': (Prof(20, False, slice_ind=True, pad_ind=True, iv=4, div=2, ki=1,
                 ki_per_au=True, size=8, index=0, idelta=0, cts=0, dts=0,
                 rap=False),
            {'slice_indication': 'TRUE', 'padding_indication': 'TRUE',
             'selective_encryption': 'FALSE', 'delta_iv_length': 2,
             'key_indicator_length': 1, 'key_indicator_per_au_flag': 'TRUE',
             'au_size_length': 8, 'user_mode': 'TRUE'}),
    # version 2.0 with padding indication only (selective encryption off)
    'v20pad': (Prof(20, False, pad_ind=True, iv=0, dts=0, rap=False),
               {'padding_indication': 'TRUE', 'selective_encryption': 'FALSE',
                'iv_length': 0}),
    # version 2.0 with nothing selected: no header byte, no fields
    'v20none': (Prof(20, False, iv=0, dts=0, rap=False),
                {'selective_encryption': 'FALSE', 'iv_length': 0}),
}


def write_prefs(outdir):
    for name, (p, prefs) in PROFILES.items():
        ver_pt = 96 if p.version == 11 else 97
        f = [sdp_invite([5004], [ver_pt])]
        aus1 = [dict(iv=b'\xaa\xbb\xcc\xdd', ki=b'\x01\x02\x03', size=5, index=2, cts=5, dts=9,
                     rap=1, state=5, slice_start=1, slice_end=0, padcnt=3),
                dict(iv=b'\x77\x88', ki=b'\x04\x05\x06', size=3, index=1, cts=None, dts=None,
                     rap=0, state=2, slice_start=0, slice_end=1, padcnt=1, enc=0)]
        # CTS and DTS flags set in the second AU, too
        aus2 = [dict(size=2, index=1, cts=1, dts=3), dict(size=1, index=0, cts=2, dts=4)]
        # padding: the AU headers do not end on a byte boundary in most
        # profiles
        f += stream(5004, ver_pt, [payload(p, aus1), payload(p, aus2),
                                   payload(p, [dict(size=4, cts=None, dts=None)])])
        if name == 'v20none':
            # AU headers length of 8 bits but the layout has no field: the
            # zero bit AU header (reported in the tree)
            f += stream(5004, ver_pt, [struct.pack('!H', 8) + b'\x00' * 12], 40005)
        write_pcap(os.path.join(outdir, 'ismacryp-coverage-%s.pcap' % name), 1, f)
    # override of the RTP payload type version (needs -o override_rtp_pt)
    p = PROFILES['v20pad'][0]
    f = [sdp_invite([5004, 5006], [96, 97])]
    f += stream(5004, 96, [payload(p, [dict(padcnt=2)])])
    f += stream(5006, 97, [payload(p, [dict(padcnt=2)])], 40001)
    write_pcap(os.path.join(outdir, 'ismacryp-coverage-override.pcap'), 1, f)


def write_malformed(outdir):
    f = [sdp_invite([5004, 5006], [96, 97])]
    pl = []
    # total AU headers length that does not match the layout ("Error -
    # expected total AU headers size" text), larger and smaller
    b = payload(AVC, [dict(dts=None)])
    pl.append(struct.pack('!H', 100) + b[2:])
    pl.append(struct.pack('!H', 5) + b[2:])
    # AU headers length 0
    pl.append(struct.pack('!H', 0) + b[2:])
    # header section cut short
    pl.append(struct.pack('!H', 52) + b'\x80\x80')
    # only the length field
    pl.append(b'\x00\x34')
    # one octet
    pl.append(b'\x00')
    # message length 0 after headers
    full = payload(AVC, [dict(dts=None)], data=b'')
    pl.append(full)
    f += stream(5004, 96, pl)
    f += stream(5006, 97, [struct.pack('!H', 0xffff) + b'\x00' * 20])
    write_pcap(os.path.join(outdir, 'ismacryp-coverage-malformed.pcap'), 1, f)


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
