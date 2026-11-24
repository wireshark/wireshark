# Generates test/captures/vp9_coverage.pcap.gz
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

# ---- VP9 RTP payload descriptor, reached through SIP/SDP "VP9/90000" ----
PT = 98
PORT = 4004

def vp9_desc(i=0, p=0, l=0, f=0, b=1, e=1, v=0, z=0, pid=None, ext=False, layer=None, tl0=None,
             pdiffs=(), ss=None):
    out = [(i << 7) | (p << 6) | (l << 5) | (f << 4) | (b << 3) | (e << 2) | (v << 1) | z]
    if i:
        pid = 0x2a if pid is None else pid
        if ext:
            out += [0x80 | (pid >> 8), pid & 0xff]
        else:
            out.append(pid & 0x7f)
    if l:
        out.append(layer if layer is not None else 0x00)
        if not f:
            out.append(tl0 if tl0 is not None else 0)
    if p and f:
        # P_DIFF with the N bit set on all but the last
        for k, d in enumerate(pdiffs):
            out.append((d << 1) | (1 if k < len(pdiffs) - 1 else 0))
    d = bytes(out)
    if v:
        d += ss
    return d

def ss_struct(ns=0, y=0, g=0, sizes=(), ng=None):
    # N_S (3 bits), Y, G; widths and heights per spatial layer, N_G
    b = (ns << 5) | (y << 4) | (g << 3)
    s = bytes([b])
    if y:
        for (w, h) in sizes:
            s += struct.pack('!HH', w, h)
    if g:
        s += bytes([ng or 0])
    return s

def build(outdir):
    main = [sip_invite([(PT, 'VP9/90000')], PORT, call='w4call9')]
    seq = [200]
    def add(payload, marker=0):
        seq[0] += 1
        main.append(rtp_frame(PORT, payload, PT, seq[0], 90000 + seq[0] * 3000, marker=marker, ssrc=0x55667788))
    body = bytes(range(200))
    # non-flexible mode (F=0): picture group index, 7 and 15 bit
    add(vp9_desc(i=1, f=0, pid=0x15) + body[:40])
    add(vp9_desc(i=1, f=0, pid=0x1234, ext=True, b=0, e=0) + body[:40])
    # flexible mode (F=1): picture ID, 7 and 15 bit
    add(vp9_desc(i=1, f=1, pid=0x66) + body[:40])
    add(vp9_desc(i=1, f=1, pid=0x7fff, ext=True, z=1) + body[:40])
    # layer indices: with TL0PICIDX (F=0) and without (F=1)
    add(vp9_desc(i=1, l=1, f=0, layer=0b01101011, tl0=0x33, pid=3) + body[:30])
    add(vp9_desc(i=1, l=1, f=1, layer=0b10010110, pid=4) + body[:30])
    # P and F: one, two and three reference indices (the chain stops after three)
    add(vp9_desc(i=1, p=1, f=1, pid=5, pdiffs=(1,)) + body[:30])
    add(vp9_desc(i=1, p=1, f=1, pid=6, pdiffs=(2, 3)) + body[:30])
    add(vp9_desc(i=1, p=1, f=1, pid=7, pdiffs=(4, 5, 6)) + body[:30])
    add(vp9_desc(i=1, p=1, l=1, f=1, pid=8, layer=0x21, pdiffs=(7,)) + body[:30])
    # scalability structure: one spatial layer without sizes, three with sizes and N_G
    add(vp9_desc(i=1, f=1, v=1, pid=9, ss=ss_struct(0, 0, 0)) + body[:30])
    add(vp9_desc(i=1, f=0, v=1, pid=10, ss=ss_struct(2, 1, 1, [(320, 180), (640, 360), (1280, 720)], 2)) + body[:30])
    add(vp9_desc(i=1, f=1, v=1, pid=11, ss=ss_struct(1, 1, 0, [(1920, 1080), (3840, 2160)])) + body[:30])
    add(vp9_desc(i=1, f=1, v=1, pid=12, ss=ss_struct(0, 0, 1, ng=5)) + body[:30])
    add(vp9_desc(i=1, f=0, v=1, pid=13, ss=ss_struct(7, 1, 1, [(w, w) for w in range(100, 900, 100)], 255)) + body[:30])
    # no picture ID (I=0): the byte after the descriptor is payload, not a picture ID
    # (the reproducer of "VP9: Decode the picture ID only when the I bit is set")
    add(vp9_desc(i=0, f=0, b=1, e=1) + b'\x12\x34' + body[:30])
    add(vp9_desc(i=0, f=1, b=0, e=1) + b'\x56\x78' + body[:30])
    add(vp9_desc(i=0, f=0, l=1, layer=0x41, tl0=0x07) + b'\x01' + body[:30])
    add(vp9_desc(i=0, f=1, l=1, layer=0x80) + b'\x02' + body[:30])
    # a descriptor alone and a minimal frame
    add(bytes([0x00]) + body[:1])
    add(bytes([0xff]) + b'\xff\xff' + b'\xff' * 3 + body[:20], marker=1)
    pcap_write(os.path.join(outdir, 'vp9-coverage.pcap'), main)

    mal = [sip_invite([(PT, 'VP9/90000')], PORT, call='w4call9b')]
    seq[0] = 400
    # descriptors cut off at each optional part
    for payload in (b'', b'\x80', b'\x80\x80', b'\xa0\x2a', b'\xa0\xaa\x00', b'\x60', b'\x70\x2a',
                    b'\x72', b'\x72\x2a', b'\x72\x2a\x00', b'\x7a\x2a\x00', b'\x7a\xaa\x00', b'\x32\x2a\x08\x00',
                    b'\x12\x2a\xe0', b'\x12\x2a\xe0\x00\x01', b'\x02\x40', b'\x02\x40\x00'):
        seq[0] += 1
        mal.append(rtp_frame(PORT, payload, PT, seq[0], 7000, ssrc=0x99aabbcc))
    pcap_write(os.path.join(outdir, 'vp9-coverage-malformed.pcap'), mal)
    gz(os.path.join(outdir, 'vp9-coverage.pcap'), os.path.join(outdir, 'vp9_coverage.pcap.gz'))

if __name__ == '__main__':
    build(sys.argv[1] if len(sys.argv) > 1 else '.')
