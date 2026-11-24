# Generates test/captures/vp8_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ---- common helpers (copied into each generator) ----
import struct
import os
import sys
import gzip

def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def pcap_write(fname, pkts, linktype=1, t0=1700000000):
    with open(fname, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype))
        for i, p in enumerate(pkts):
            olen = None
            if isinstance(p, tuple):
                if len(p) == 3:
                    p, ts, olen = p
                else:
                    p, ts = p
            else:
                ts = t0 + i
            f.write(struct.pack('<IIII', ts, 0, len(p), olen or len(p)))
            f.write(p)

def eth(payload, dst=b'\x02\0\0\0\0\x02', src=b'\x02\0\0\0\0\x01', et=0x0800):
    f = dst + src + struct.pack('!H', et) + payload
    return f + b'\0' * max(0, 60 - len(f))

def ip4(proto, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2), ttl=64, ident=1, flags_frag=0, tos=0):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, tos, 20 + len(payload), ident, flags_frag, ttl, proto, 0,
                    bytes(src), bytes(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload

def ip6(nh, payload, src=bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\1', dst=bytes([0x20, 1, 0xd, 0xb8]) + bytes(11) + b'\2', hlim=64):
    return struct.pack('!IHBB', 0x60000000, len(payload), nh, hlim) + src + dst + payload

def udp(sport, dport, payload, src=(192, 0, 2, 1), dst=(192, 0, 2, 2)):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 17, len(u))
    c = csum(ph + u) or 0xffff
    return u[:6] + struct.pack('!H', c) + u[8:]

def tcp(sport, dport, seq, ack, flags, payload=b'', src=(192, 0, 2, 1), dst=(192, 0, 2, 2), win=65535):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, win, 0, 0) + payload
    ph = bytes(src) + bytes(dst) + struct.pack('!BBH', 0, 6, len(t))
    return t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]

def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    tags = struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad
    tags += struct.pack('>HH', 0, 0)
    return tags + payload

def rtp(pt, seq, ts, ssrc, payload, marker=0):
    return struct.pack('!BBHII', 0x80, (marker << 7) | pt, seq, ts, ssrc) + payload

def gz(path, gzpath):
    with open(path, 'rb') as f:
        d = f.read()
    with open(gzpath, 'wb') as g:
        g.write(gzip.compress(d, 9, mtime=0))

# ---- SIP/SDP setup so that RTP payload types map to a codec ----
def sip_invite(rtpmaps, port, mline='video', pts=None, cseq=1, call='w4call1'):
    pts = pts or [pt for pt, _ in rtpmaps]
    sdp = ('v=0\r\no=alice 2890844526 2890844526 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\n'
           'm=%s %d RTP/AVP %s\r\n' % (mline, port, ' '.join(str(p) for p in pts)))
    for pt, name in rtpmaps:
        sdp += 'a=rtpmap:%d %s\r\n' % (pt, name)
    body = sdp.encode()
    hdr = ('INVITE sip:bob@192.0.2.2 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK%s\r\n'
           'Max-Forwards: 70\r\nTo: Bob <sip:bob@192.0.2.2>\r\nFrom: Alice <sip:alice@192.0.2.1>;tag=1928\r\n'
           'Call-ID: %s@192.0.2.1\r\nCSeq: %d INVITE\r\nContact: <sip:alice@192.0.2.1>\r\n'
           'Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n') % (call, call, cseq, len(body))
    return eth(ip4(17, udp(5060, 5060, hdr.encode() + body)))

def rtp_frame(port, payload, pt, seq, ts, ssrc=0x11223344, marker=0, sport=5002):
    r = rtp(pt, seq, ts, ssrc, payload, marker)
    return eth(ip4(17, udp(sport, port, r, src=(192, 0, 2, 2), dst=(192, 0, 2, 1)), src=(192, 0, 2, 2), dst=(192, 0, 2, 1), ident=seq))

# ---- VP8 RTP payload (RFC 7741), reached through SIP/SDP "VP8/90000" ----
PT = 96
PORT = 4002

def vp8_desc(x=0, r=0, n=0, s=1, pid=0, i=0, l=0, t=0, k=0, rsv=0, picid=None, tl0=None, tk=None):
    b = [(x << 7) | (r << 6) | (n << 5) | (s << 4) | (pid & 0xf)]
    if x:
        b.append((i << 7) | (l << 6) | (t << 5) | (k << 4) | (rsv & 0xf))
        if i:
            if picid is not None and picid > 0x7f:
                b += [0x80 | (picid >> 8), picid & 0xff]
            else:
                b.append((picid or 0) & 0x7f)
        if l:
            b.append(tl0 or 0)
        if t or k:
            b.append(tk or 0)
    return bytes(b)

def vp8_hdr(p=0, ver=0, show=1, psize=0):
    # frame type bit P: 0 = key frame, 1 = interframe; first partition size = s0 + 8*s1 + 2048*s2
    s0, s1, s2 = psize & 7, (psize >> 3) & 0xff, (psize >> 11) & 0xff
    return bytes([(s0 << 5) | (show << 4) | (ver << 1) | p, s1, s2])

def key_hdr(w=640, h=480, hs=0, vs=0, code=b'\x9d\x01\x2a'):
    return code + struct.pack('<HH', w | (hs << 14), h | (vs << 14))

def build(outdir):
    main = [sip_invite([(PT, 'VP8/90000')], PORT)]
    seq = [100]
    def add(payload, marker=0):
        seq[0] += 1
        main.append(rtp_frame(PORT, payload, PT, seq[0], 90000 + seq[0] * 3000, marker=marker))
    body = bytes(range(256)) * 2
    # key frame, whole first partition in the packet ("plus other partitions")
    add(vp8_desc() + vp8_hdr(0, 0, 1, 40) + key_hdr() + body[:100])
    # key frame, first partition split over several packets, then continuations
    add(vp8_desc(n=1) + vp8_hdr(0, 1, 1, 3000) + key_hdr(1280, 720) + body[:60])
    add(vp8_desc(s=0, pid=0) + body[:80])
    add(vp8_desc(s=0, pid=1) + body[:50], marker=1)
    # interframes
    add(vp8_desc() + vp8_hdr(1, 2, 1, 10) + body[:30])
    add(vp8_desc() + vp8_hdr(1, 3, 0, 5000) + body[:300])
    add(vp8_desc() + vp8_hdr(1, 3, 1, 100000 & 0x7ffff) + body[:64])
    # S = 1 but a partition other than 0: no payload header
    add(vp8_desc(s=1, pid=3) + body[:40])
    # reserved R bit and the reserved versions
    add(vp8_desc(r=1) + vp8_hdr(1, 4, 1, 9) + body[:20])
    add(vp8_desc() + vp8_hdr(1, 7, 1, 9) + body[:20])
    # extension byte: picture ID 7 bit
    add(vp8_desc(x=1, i=1, picid=0x55) + vp8_hdr(0, 0, 1, 20) + key_hdr(352, 288) + body[:40])
    # picture ID 15 bit, TL0PICIDX, TID/Y/KEYIDX
    add(vp8_desc(x=1, i=1, l=1, t=1, k=1, rsv=5, picid=0x1234, tl0=0x77, tk=0xE0 | 0x1f) +
        vp8_hdr(1, 0, 1, 12) + body[:40])
    # L only, T only, K only, and no flags set in the extension byte
    add(vp8_desc(x=1, l=1, tl0=9, s=0, pid=2) + body[:30])
    add(vp8_desc(x=1, t=1, tk=0x65, s=0, pid=2) + body[:30])
    add(vp8_desc(x=1, k=1, tk=0x0a, s=0, pid=2) + body[:30])
    add(vp8_desc(x=1, s=0, pid=0) + body[:30])
    # key frames with scaling bits and large sizes
    add(vp8_desc() + vp8_hdr(0, 0, 1, 64) + key_hdr(1920, 1080, 1, 2) + body[:128])
    add(vp8_desc() + vp8_hdr(0, 0, 1, 64) + key_hdr(16383, 16383, 3, 3) + body[:100])
    # payload exactly the size of the first partition
    add(vp8_desc() + vp8_hdr(1, 0, 1, 30) + body[:30])
    # payload one byte short of the first partition
    add(vp8_desc() + vp8_hdr(1, 0, 1, 31) + body[:30], marker=1)
    pcap_write(os.path.join(outdir, 'vp8-coverage.pcap'), main)

    mal = [sip_invite([(PT, 'VP8/90000')], PORT, call='w4call2')]
    seq[0] = 300
    # key frame with a wrong start code (error expert info)
    add(vp8_desc() + vp8_hdr(0, 0, 1, 20) + key_hdr(code=b'\x00\x00\x00') + body[:40])
    mal2 = main[:0]
    mal.extend(main[:0])
    # frames added by add() went into main; move them
    mal.append(main.pop())
    # packets cut short at each header field (exceptions)
    for payload in (b'', b'\x90', b'\x90\x00', b'\x90\x00\x00', b'\xd0\x80', b'\x90' + vp8_hdr(0, 0, 1, 5) + b'\x9d\x01',
                    b'\x90' + vp8_hdr(0, 0, 1, 5) + b'\x9d\x01\x2a\x80\x02'):
        seq[0] += 1
        mal.append(rtp_frame(PORT, payload, PT, seq[0], 5000))
    # extended descriptor with every flag, cut short
    for payload in (b'\x80', b'\x80\xf0', b'\x80\xf0\x80', b'\x80\xf0\x00', b'\x80\xf0\x00\x01', b'\x80\xf0\x00\x01\x02'):
        seq[0] += 1
        mal.append(rtp_frame(PORT, payload, PT, seq[0], 5001))
    pcap_write(os.path.join(outdir, 'vp8-coverage-malformed.pcap'), mal)
    gz(os.path.join(outdir, 'vp8-coverage.pcap'), os.path.join(outdir, 'vp8_coverage.pcap.gz'))

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
