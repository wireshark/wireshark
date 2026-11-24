# Generates test/captures/ippusb_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ---- common helpers (synthetic traffic only) ----
import struct
import sys
import os

ETH_C = bytes.fromhex('020000000001')
ETH_S = bytes.fromhex('020000000002')


def csum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


def ipv4_hdr(src, dst, proto, payload_len, ident=1):
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + payload_len, ident, 0x4000,
                    64, proto, 0, ip4(src), ip4(dst))
    return h[:10] + struct.pack('!H', csum(h)) + h[12:]


def eth(src_is_client):
    return (ETH_S + ETH_C if src_is_client else ETH_C + ETH_S) + b'\x08\x00'


def tcp_seg(src, dst, sport, dport, seq, ack, payload, flags=0x18, c2s=True):
    opts = b'\x02\x04\x05\xb4' if flags & 0x02 else b''
    hdr = struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                      (5 + len(opts) // 4) << 4, flags, 65535, 0, 0) + opts
    pseudo = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(hdr) + len(payload))
    c = csum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack('!H', c) + hdr[18:]
    seg = hdr + payload
    return eth(c2s) + ipv4_hdr(src, dst, 6, len(seg)) + seg


def udp_dgram(src, dst, sport, dport, payload, c2s=True):
    hdr = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
    seg = hdr + payload
    return eth(c2s) + ipv4_hdr(src, dst, 17, len(seg)) + seg


class Tcp:
    """One TCP connection; frames collects (data) in order."""
    def __init__(self, frames, c, s, cport, sport, isn_c=1000, isn_s=5000, handshake=True):
        self.f, self.c, self.s, self.cp, self.sp = frames, c, s, cport, sport
        self.sc, self.ss = isn_c, isn_s
        if handshake:
            self.f.append(tcp_seg(c, s, cport, sport, self.sc, 0, b'', 0x02))
            self.f.append(tcp_seg(s, c, sport, cport, self.ss, self.sc + 1, b'', 0x12, c2s=False))
            self.sc += 1
            self.ss += 1
            self.f.append(tcp_seg(c, s, cport, sport, self.sc, self.ss, b'', 0x10))

    def send(self, payload, c2s=True):
        if c2s:
            self.f.append(tcp_seg(self.c, self.s, self.cp, self.sp, self.sc, self.ss, payload))
            self.sc += len(payload)
        else:
            self.f.append(tcp_seg(self.s, self.c, self.sp, self.cp, self.ss, self.sc, payload, c2s=False))
            self.ss += len(payload)

    def fin(self):
        self.f.append(tcp_seg(self.c, self.s, self.cp, self.sp, self.sc, self.ss, b'', 0x11))
        self.sc += 1
        self.f.append(tcp_seg(self.s, self.c, self.sp, self.cp, self.ss, self.sc, b'', 0x11, c2s=False))
        self.ss += 1


def write_pcap(path, frames, linktype=1, snaplen=262144):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, linktype))
        for i, fr in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, i * 1000 % 1000000, len(fr), len(fr)))
            f.write(fr)


def _blk(btype, body):
    pad = (-len(body)) % 4
    tot = 12 + len(body) + pad
    return struct.pack('<II', btype, tot) + body + b'\0' * pad + struct.pack('<I', tot)


def write_pcapng(path, linktypes, frames):
    """frames: list of (interface_index, bytes)"""
    out = _blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    for lt in linktypes:
        out += _blk(1, struct.pack('<HHI', lt, 0, 262144))
    for i, (ifidx, data) in enumerate(frames):
        ts = (1700000000 + i) * 1000000 + i * 1000
        out += _blk(6, struct.pack('<IIIII', ifidx, ts >> 32, ts & 0xffffffff,
                                   len(data), len(data)) + data)
    with open(path, 'wb') as f:
        f.write(out)
# ---- end common helpers ----
#!/usr/bin/env python3
"""Generate the IPPUSB coverage captures: mkippusb.py <outdir>
Writes ippusb-coverage.pcap (usbmon, link type 220) and
ippusb-coverage-malformed.pcap. All traffic is synthetic."""

CLS_IPPUSB = (7, 1, 4)
CLS_OLDHP = (0xff, 9, 1)
_t = [0]


def usbmon(urb_id, typ, xfer, ep, dev, flag_setup, flag_data, length, data=b'',
           setup=b'\0' * 8, status=0, bus=1):
    _t[0] += 1
    hdr = struct.pack('<QBBBBHbbqiiII8siiII', urb_id, ord(typ), xfer, ep, dev, bus,
                      flag_setup, flag_data, 1700000000 + _t[0], 0, status, length, len(data),
                      setup, 0, 0, 0, 0)
    return hdr + data


def ctl_in(frames, urb, dev, setup, data):
    frames.append(usbmon(urb, 'S', 2, 0x80, dev, 0, ord('<'), len(data), setup=setup, status=-115))
    frames.append(usbmon(urb, 'C', 2, 0x80, dev, ord('-'), 0, len(data), data, setup=setup))


def enumerate_dev(frames, dev, cls, urb=0x100):
    devdesc = struct.pack('<BBHBBBBHHHBBBB', 18, 1, 0x0200, 0, 0, 0, 64,
                          0x1234, 0x5678, 0x0100, 1, 2, 3, 1)
    ctl_in(frames, urb, dev, bytes([0x80, 0x06, 0x00, 0x01, 0, 0, 18, 0]), devdesc)
    cfg = struct.pack('<BBHBBBBB', 9, 2, 9 + 9 + 7 + 7, 1, 1, 0, 0x80, 50)
    cfg += struct.pack('<BBBBBBBBB', 9, 4, 0, 0, 2, cls[0], cls[1], cls[2], 0)
    cfg += struct.pack('<BBBBHB', 7, 5, 0x81, 2, 512, 0)
    cfg += struct.pack('<BBBBHB', 7, 5, 0x01, 2, 512, 0)
    ctl_in(frames, urb + 1, dev, bytes([0x80, 0x06, 0x00, 0x02, 0, 0, len(cfg), 0]), cfg)


class Dev:
    def __init__(self, frames, dev):
        self.f, self.dev, self.urb = frames, dev, 0x1000 * dev

    def out(self, data):
        """bulk OUT transfer (host to printer): data in the submit"""
        self.urb += 1
        self.f.append(usbmon(self.urb, 'S', 3, 0x01, self.dev, ord('-'), 0, len(data), data, status=-115))
        self.f.append(usbmon(self.urb, 'C', 3, 0x01, self.dev, ord('-'), ord('>'), len(data)))

    def inn(self, data):
        """bulk IN transfer (printer to host): data in the completion"""
        self.urb += 1
        self.f.append(usbmon(self.urb, 'S', 3, 0x81, self.dev, ord('-'), ord('<'), 512, status=-115))
        self.f.append(usbmon(self.urb, 'C', 3, 0x81, self.dev, ord('-'), 0, len(data), data))


def a(tag, name, val=b''):
    if isinstance(name, str):
        name = name.encode()
    if isinstance(val, str):
        val = val.encode()
    return bytes([tag]) + struct.pack('!H', len(name)) + name + struct.pack('!H', len(val)) + val


def i4(n):
    return struct.pack('!i', n)


def ipp(op, reqid, *attrs, end=True):
    return struct.pack('!BBHI', 2, 0, op, reqid) + b''.join(attrs) + (b'\x03' if end else b'')


def ops(uri='ipp://localhost/ipp/print'):
    return (b'\x01' + a(0x47, 'attributes-charset', 'utf-8') + a(0x48, 'attributes-natural-language', 'en')
            + a(0x45, 'printer-uri', uri))


def req_hdr(n, path='/ipp/print', ctype='application/ipp', chunked=False):
    h = 'POST %s HTTP/1.1\r\nHost: localhost:60000\r\nUser-Agent: synthetic\r\n' % path
    if ctype:
        h += 'Content-Type: %s\r\n' % ctype
    h += 'Transfer-Encoding: chunked\r\n' if chunked else 'Content-Length: %d\r\n' % n
    return (h + '\r\n').encode()


def rsp_hdr(n, chunked=False, ctype='application/ipp'):
    h = 'HTTP/1.1 200 OK\r\nServer: synthetic\r\nContent-Type: %s\r\n' % ctype
    h += 'Transfer-Encoding: chunked\r\n' if chunked else 'Content-Length: %d\r\n' % n
    return (h + '\r\n').encode()


def chunk(b):
    return b'%x\r\n' % len(b) + b + b'\r\n'


END = b'0\r\n\r\n'


def build(frames, mal=False):
    enumerate_dev(frames, 2, CLS_IPPUSB)
    d = Dev(frames, 2)
    # 1. Complete requests and responses in one transfer each (the header
    # and the IPP message, ending with the end-of-attributes tag)
    body = ipp(0x000b, 1, ops())
    d.out(req_hdr(len(body)) + body)
    body = ipp(0x0000, 1, b'\x01' + a(0x47, 'attributes-charset', 'utf-8')
               + a(0x48, 'attributes-natural-language', 'en') + a(0x41, 'status-message', 'successful-ok'),
               b'\x04' + a(0x42, 'printer-name', 'ippusb') + a(0x23, 'printer-state', i4(3)))
    d.inn(rsp_hdr(len(body)) + body)
    # a request for "POST / HTTP"
    body = ipp(0x0009, 2, ops())
    d.out(b'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/ipp\r\nContent-Length: %d\r\n\r\n' % len(body) + body)
    d.inn(rsp_hdr(len(ipp(0x0000, 2, ops()))) + ipp(0x0000, 2, ops()))
    # 2. Chunked response: header, chunks, final chunk (reassembled)
    big = ipp(0x0000, 3, ops(), b'\x04' + b''.join(a(0x44, 'kw-%d' % k, 'value-%d' % k) for k in range(40)))
    d.out(req_hdr(0, chunked=True))
    d.out(chunk(ipp(0x000b, 3, ops())))
    d.out(END)
    d.inn(rsp_hdr(0, chunked=True))
    d.inn(chunk(big[:200]))
    d.inn(chunk(big[200:400]))
    d.inn(chunk(big[400:]))
    d.inn(END)
    # 3. A stray transfer after a finished message (no header, nothing to
    # attach it to: the previous PDU must not take it)
    d.inn(b'stray data without a header')
    # 4. A header split over transfers. The Content-Type line that starts
    # a continuation decides whether the PDU is IPP: text/plain is not
    # (the PDU is then shown in the first pass only, so these two are in
    # the malformed capture), "x" is too short for application/ipp,
    # application/ipp is.
    for ct, content in ((('text/plain', b'plain text'), ('x', b'x')) if mal else ())\
            + (('application/ipp', ipp(0x000b, 4, ops())),):
        d.out(b'POST /ipp/print HTTP/1.1\r\nHost: localhost\r\n')
        d.out(b'Content-Type: ' + ct.encode() + b'\r\nTransfer-Encoding: chunked\r\n\r\n')
        d.out(chunk(content))
        d.out(END)
    # 5. A chunk split over transfers, the first one with the length of
    # the final chunk (5 octets) without being it
    msg = chunk(ipp(0x0000, 5, ops()))
    d.inn(rsp_hdr(0, chunked=True))
    d.inn(msg[:5])
    d.inn(msg[5:])
    d.inn(END)
    # 6. A stray transfer after a complete single-transfer message
    body = ipp(0x000b, 6, ops())
    d.out(req_hdr(len(body)) + body)
    d.inn(b'late stray data')
    if mal:
        # The reproducers of "IPPUSB: Initialize the PDU state and pass no
        # data to HTTP": the first transfer starts an HTTP request that never
        # continues (the nxtpdu of its PDU must be zero in the second pass,
        # where it is added to its own fragment table entry twice), a
        # complete message follows, then a stray transfer once more. In
        # the second pass the incomplete PDUs show "Fragment overlap".
        d.out(b'POST /ipp/print HTTP/1.1\r\nHost: 192.0.2.9\r\n')
        body = ipp(0x000b, 6, ops())
        d.out(b'POST /ipp/print HTTP/1.1\r\nContent-Type: application/ipp\r\nContent-Length: %d\r\n\r\n' % len(body) + body)
        d.inn(b'late stray data')
        # a new header while the previous message is still incomplete
        d.out(req_hdr(0, chunked=True))
        d.out(req_hdr(0, chunked=True))
        d.out(chunk(ipp(0x000b, 7, ops())))
        d.out(END)
    # 7. Old HP printers: interface class 0xff/9/1 on another device
    enumerate_dev(frames, 3, CLS_OLDHP, urb=0x300)
    e = Dev(frames, 3)
    body = ipp(0x000b, 8, ops())
    e.out(req_hdr(len(body)) + body)
    e.inn(rsp_hdr(0, chunked=True))
    e.inn(chunk(ipp(0x0000, 8, ops())))
    e.inn(END)
    if mal:
        # transfers shorter than the checks expect
        e.out(b'x')
        e.out(b'\x03')
        e.out(END[:4])
        e.out(b'POST /ipp')
        e.inn(b'HTTP/')
        e.inn(b'HTTP/1.1 200 OK\r\n')
        # a final chunk whose message was never started
        e.out(END)
        # chunked message cut by a new finished one
        e.out(req_hdr(0, chunked=True))
        e.out(chunk(ipp(0x000b, 9, ops())))
        body = ipp(0x000b, 10, ops())
        e.out(req_hdr(len(body)) + body)
        e.out(END)
        # a 5 octet continuation that is not a chunk end
        e.inn(rsp_hdr(0, chunked=True))
        e.inn(b'abcde')
        e.inn(END)
        # bytes after IPP that are not a valid message (HTTP gets a non-IPP body)
        e.out(req_hdr(0, chunked=True))
        e.out(chunk(b'\x02\x00\x00'))
        e.out(END)


frames = []
build(frames)
write_pcap(os.path.join(sys.argv[1], 'ippusb-coverage.pcap'), frames, linktype=220)
mal = []
build(mal, mal=True)
write_pcap(os.path.join(sys.argv[1], 'ippusb-coverage-malformed.pcap'), mal, linktype=220)
