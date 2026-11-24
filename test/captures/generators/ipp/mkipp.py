# Generates test/captures/ipp_coverage.pcapng.gz
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
"""Generate the IPP coverage captures: mkipp.py <outdir>
Writes ipp-coverage.pcap (valid traffic) and ipp-coverage-malformed.pcap.
All traffic is synthetic."""

C, S = '192.0.2.10', '192.0.2.20'


def a(tag, name, val=b''):
    if isinstance(name, str):
        name = name.encode()
    if isinstance(val, str):
        val = val.encode()
    return bytes([tag]) + struct.pack('!H', len(name)) + name + struct.pack('!H', len(val)) + val


def i4(n):
    return struct.pack('!i', n)


def ipp(op, reqid, *attrs, ver=(2, 0), end=True, tail=b''):
    return (bytes(ver) + struct.pack('!HI', op, reqid) + b''.join(attrs)
            + (b'\x03' if end else b'') + tail)


def http_req(body, path='/ipp/print', ctype='application/ipp', extra=''):
    h = 'POST %s HTTP/1.1\r\nHost: 192.0.2.20:631\r\n' % path
    if ctype:
        h += 'Content-Type: %s\r\n' % ctype
    h += extra + 'Content-Length: %d\r\n\r\n' % len(body)
    return h.encode() + body


def http_rsp(body, ctype='application/ipp', extra=''):
    h = 'HTTP/1.1 200 OK\r\nServer: synthetic\r\n'
    if ctype:
        h += 'Content-Type: %s\r\n' % ctype
    h += extra + 'Content-Length: %d\r\n\r\n' % len(body)
    return h.encode() + body


def chunked(body, n=40):
    out = b''
    for i in range(0, len(body), n):
        c = body[i:i + n]
        out += b'%x\r\n' % len(c) + c + b'\r\n'
    return out + b'0\r\n\r\n'


def std_ops(uri='ipp://192.0.2.20/ipp/print'):
    return (a(0x01, ''),
            a(0x47, 'attributes-charset', 'utf-8'),
            a(0x48, 'attributes-natural-language', 'en'),
            a(0x45, 'printer-uri', uri))


def op_attrs(uri='ipp://192.0.2.20/ipp/print'):
    return (b'\x01' + a(0x47, 'attributes-charset', 'utf-8')[0:0]
            + a(0x47, 'attributes-charset', 'utf-8')
            + a(0x48, 'attributes-natural-language', 'en')
            + a(0x45, 'printer-uri', uri))


def tag_hdr(t):
    return bytes([t])


def member(name, *vals):
    return a(0x4a, '', name) + b''.join(vals)


def col(name, *items):
    return a(0x34, name) + b''.join(items) + a(0x37, '')


frames = []
mal = []


def session(frs, cport, sport=631, c=C, s=S, **kw):
    return Tcp(frs, c, s, cport, sport, **kw)


# ---------------------------------------------------------------- flow 1
# Get-Printer-Attributes, response with the common value types
t = session(frames, 40001)
req = ipp(0x000b, 1, op_attrs(),
          a(0x44, 'requested-attributes', 'printer-name'),
          a(0x44, '', 'printer-state'), a(0x44, '', 'media-col-database'),
          a(0x49, 'document-format', 'application/pdf'),
          a(0x42, 'requesting-user-name', 'alice'),
          a(0x41, 'message', 'hello'),
          a(0x46, 'uri-scheme', 'ipp'),
          a(0x40, 'unknown-char', 'x'),
          a(0x4b, 'unknown-char2', 'y'))
t.send(http_req(req))

pa = b'\x04'
pa += a(0x23, 'printer-state', i4(3))
pa += a(0x44, 'printer-state-reasons', 'none')
pa += a(0x22, 'printer-is-accepting-jobs', b'\x01')
pa += a(0x22, 'printer-is-shared', b'\x00')
pa += a(0x22, 'bad-boolean', b'\x00\x01')
pa += a(0x21, 'queued-job-count', i4(7))
pa += a(0x21, 'copies-default', i4(1)) + a(0x21, '', i4(2)) + a(0x21, '', i4(3))
pa += a(0x21, 'int-range-len8', i4(1) + i4(99))
pa += a(0x21, 'int-len3', b'\x00\x00\x05')
pa += a(0x21, 'int-len3-multi', b'\x00\x00\x05') + a(0x21, '', i4(8)) + a(0x21, '', i4(1) + i4(2))
pa += a(0x21, 'int-then-range', i4(5)) + a(0x33, '', i4(1) + i4(2))
pa += a(0x23, 'job-state', i4(9))
pa += a(0x23, 'document-state', i4(5))
pa += (a(0x23, 'operations-supported', i4(2)) + a(0x23, '', i4(0x000b)) + a(0x23, '', i4(0x4001))
       + a(0x23, '', i4(0x7777)))
pa += a(0x23, 'finishings-default', i4(3)) + a(0x23, '', i4(20)) + a(0x23, '', i4(999))
pa += a(0x23, 'orientation-requested-default', i4(4))
pa += a(0x23, 'media-feed-orientation', i4(5))
pa += a(0x23, 'print-quality-default', i4(4))
pa += a(0x23, 'transmission-status', i4(7))
pa += a(0x23, 'printer-state-unknownvalue', i4(77))
pa += a(0x23, 'printer-state-bad', i4(77)[:3])
pa += a(0x23, 'some-other-enum', i4(17)) + a(0x23, '', i4(18))
pa += a(0x23, 'some-bad-enum', i4(17)[:2]) + a(0x23, '', i4(18))
pa += a(0x24, 'integer-type-unknown-tag', b'\x00\x00')
pa += a(0x20, 'integer-type-0x20', b'\x01')
pa += a(0x31, 'printer-current-time', struct.pack('!HBBBBBBcBB', 2026, 11, 6, 12, 40, 15, 3, b'+', 10, 0))
pa += a(0x31, 'bad-sign-time', struct.pack('!HBBBBBBcBB', 2026, 1, 2, 3, 4, 5, 6, b'x', 0, 30))
pa += a(0x31, 'short-time', b'\x07\xea\x0b')
pa += (a(0x32, 'printer-resolution-supported', i4(600) + i4(600) + b'\x03')
       + a(0x32, '', i4(200) + i4(100) + b'\x04') + a(0x32, '', i4(1) + i4(2) + b'\x09'))
pa += a(0x32, 'bad-resolution', b'\x01\x02')
pa += a(0x33, 'copies-supported', i4(1) + i4(999))
pa += a(0x33, 'range-multi', i4(1) + i4(5)) + a(0x33, '', i4(7)) + a(0x33, '', b'abc') + a(0x21, '', i4(3))
pa += a(0x33, 'range-len4', i4(12))
pa += a(0x33, 'range-weird', b'\x01\x02\x03')
pa += a(0x30, 'octet-one', b'raw bytes')
pa += a(0x30, 'octet-multi', b'one') + a(0x30, '', b'two') + a(0x30, '', b'')
pa += a(0x41, 'printer-info', 'A synthetic printer')
pa += a(0x42, 'printer-name', 'synth') + a(0x42, '', 'synth2')
pa += a(0x45, 'printer-uri-supported', 'ipp://192.0.2.20/ipp/print') + a(0x45, '', 'ipps://192.0.2.20/ipp/print')
# out-of-band
pa += a(0x10, 'oob-unsupported') + a(0x12, 'oob-unknown') + a(0x13, 'oob-novalue')
pa += a(0x15, 'oob-notsettable') + a(0x16, 'oob-delete') + a(0x17, 'oob-admin')
pa += a(0x13, '') + a(0x10, '', b'')
pa += a(0x11, 'oob-reserved')
# delimiter-less / unknown value tags
pa += a(0x50, 'unknown-tag-named', b'\x01\x02\x03') + a(0x50, '', b'\x04')
pa += a(0x38, 'octet-type-unknown', b'abc') + a(0x38, '', b'd')
pa += a(0xe0, 'extension-tag', b'ext')
# collections: named, nested, 1setOf, with every member syntax
pa += col('media-col-ready',
          member('media-size', col('', member('x-dimension', a(0x21, '', i4(21000))),
                                    member('y-dimension', a(0x21, '', i4(29700))))),
          member('media-type', a(0x44, '', 'stationery')),
          member('media-source', a(0x44, '', 'tray-1')))
pa += col('media-col-database', member('a', a(0x21, '', i4(1)))) + \
    col('', member('b', a(0x21, '', i4(2)))) + col('', member('c', a(0x21, '', i4(3))))
pa += col('empty-collection')
# member names longer than the 176 byte buffer of a collection value, and
# a nested collection that does not fit
pa += col('long-collection',
          member('m' * 100, a(0x21, '', i4(1))),
          member('n' * 100, a(0x21, '', i4(1))),
          member('o' * 30, a(0x21, '', i4(1))))
pa += col('long-nested',
          member('outer', col('', member('p' * 90, a(0x21, '', i4(1))),
                              member('q' * 70, a(0x21, '', i4(1))))),
          member('r' * 120, a(0x21, '', i4(1))))
pa += col('huge-collection', *[member('member-%03d-' % k + 'z' * 40, a(0x21, '', i4(k)))
                              for k in range(30)])
pa += col('nested-overflow', member('a' * 100, col('', member('b' * 80, a(0x21, '', i4(1))))))
pa += col('exact-174', member('x' * 174, a(0x21, '', i4(1))))
pa += col('exact-collection', *[member('e' * 20, a(0x21, '', i4(k))) for k in range(8)])
pa += a(0x4a, 'member-outside-collection', 'xyz')
pa += a(0x4a, 'member-empty-value', '')
# a plain textWithoutLanguage/keyword with a very long value
pa += a(0x44, 'long-keyword', 'k' * 300)
# trailing attribute group delimiters
pa += b'\x02' + a(0x21, 'job-id', i4(5)) + a(0x23, 'job-state', i4(3)) + a(0x44, 'job-state-reasons', 'none')
pa += b'\x05' + a(0x10, 'unsupported-one')
pa += b'\x06' + a(0x21, 'notify-subscription-id', i4(1))
pa += b'\x07' + a(0x21, 'notify-sequence-number', i4(1))
pa += b'\x08' + a(0x21, 'resource-id', i4(1))
pa += b'\x09' + a(0x23, 'document-state', i4(9))
pa += b'\x0b' + a(0x21, 'unknown-delimiter', i4(1))
rsp_ops = (b'\x01' + a(0x47, 'attributes-charset', 'utf-8')
           + a(0x48, 'attributes-natural-language', 'en')
           + a(0x41, 'status-message', 'successful-ok'))
t.send(http_rsp(ipp(0, 1, rsp_ops, pa)), c2s=False)
None

# ---------------------------------------------------------------- flow 2
# print job with a document after the attributes, response codes of all classes
t = session(frames, 40002, isn_c=70000, isn_s=90000)
doc = b'%PDF-1.4\n% synthetic document\n' + bytes(range(32, 120))
req = ipp(0x0002, 2, op_attrs(), a(0x42, 'job-name', 'test.pdf'),
          a(0x49, 'document-format', 'application/pdf'),
          b'\x02' + a(0x21, 'copies', i4(2)) + a(0x23, 'orientation-requested', i4(3))
          + a(0x23, 'print-quality', i4(5)) + a(0x23, 'finishings', i4(4)),
          tail=doc)
t.send(http_req(req))
t.send(http_rsp(ipp(0x0000, 2, rsp_ops, b'\x02' + a(0x21, 'job-id', i4(42))
                    + a(0x45, 'job-uri', 'ipp://192.0.2.20/jobs/42'))), c2s=False)
# a request for each operation and a response for each status class, in one
# connection; request ids 10..
reqid = 10
for op in (0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000a, 0x000c, 0x000d,
           0x0010, 0x0016, 0x0038, 0x4001, 0x4002, 0x400c, 0x7fff):
    t.send(http_req(ipp(op, reqid, op_attrs(), b'')))
    status = (0x0000, 0x0001, 0x0100, 0x0200, 0x0300, 0x0400, 0x0404, 0x0500, 0x0501, 0x0407)[reqid % 10]
    t.send(http_rsp(ipp(status, reqid, rsp_ops)), c2s=False)
    reqid += 1
# a response without a request in the capture
t.send(http_rsp(ipp(0x0000, 999, rsp_ops)), c2s=False)
# a request whose response never comes
t.send(http_req(ipp(0x0009, 1000, op_attrs())))
# version 1.1 and 2.1, 0.0
t.send(http_req(ipp(0x000b, 1001, op_attrs(), ver=(1, 1))))
t.send(http_rsp(ipp(0x0000, 1001, rsp_ops, ver=(1, 1))), c2s=False)
t.send(http_req(ipp(0x000b, 1002, op_attrs(), ver=(2, 1))))
t.send(http_req(ipp(0x000b, 1003, op_attrs(), ver=(0, 0))))
# no end-of-attributes tag
t.send(http_req(ipp(0x000b, 1004, op_attrs(), end=False)))
# header only, no attributes at all
t.send(http_req(ipp(0x000b, 1005, end=False)))
t.send(http_req(ipp(0x000b, 1006)))
t.fin()

# ---------------------------------------------------------------- flow 3
# Port 631 without a Content-Type: the HTTP dissector falls back to the port
# registration (and IPP has no media container information)
t = session(frames, 40003, isn_c=300, isn_s=400)
t.send(http_req(ipp(0x000b, 20, op_attrs()), ctype=None))
t.send(http_rsp(ipp(0x0000, 20, rsp_ops, b'\x04' + a(0x42, 'printer-name', 'noctype')), ctype=None), c2s=False)
# chunked response without Content-Type, as some printers send it
body = ipp(0x0000, 21, rsp_ops, b'\x04' + a(0x42, 'printer-name', 'chunked') + a(0x23, 'printer-state', i4(4)))
t.send(http_req(ipp(0x000b, 21, op_attrs()), ctype=None))
t.send(('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n').encode() + chunked(body), c2s=False)
# the same with Content-Type, on a nonstandard port
t.fin()

t = session(frames, 40004, sport=8631, isn_c=1, isn_s=2)
t.send(http_req(ipp(0x000b, 30, op_attrs()), path='/'))
t.send(http_rsp(ipp(0x0000, 30, rsp_ops, b'\x04' + a(0x42, 'printer-name', 'port8631'))), c2s=False)
# a long response split over TCP segments (HTTP reassembly feeds IPP)
body = ipp(0x0000, 31, rsp_ops, b'\x04' + b''.join(a(0x44, 'keyword-%d' % k, 'value-%d' % k)
                                                  for k in range(100)))
t.send(http_req(ipp(0x000b, 31, op_attrs())))
msg = http_rsp(body)
t.send(msg[:300], c2s=False)
t.send(msg[300:900], c2s=False)
t.send(msg[900:], c2s=False)
t.fin()

# an HTTP NOTIFY request with an IPP body (media container "HTTP notification")
t = session(frames, 40005, isn_c=77, isn_s=88)
body = ipp(0x001c, 40, op_attrs())
t.send(('NOTIFY /ipp/print HTTP/1.1\r\nHost: 192.0.2.20\r\nContent-Type: application/ipp\r\n'
        'Content-Length: %d\r\n\r\n' % len(body)).encode() + body)
t.send(http_rsp(ipp(0x0000, 40, rsp_ops)), c2s=False)
t.fin()


# IPP handed over by name in Exported PDU frames (no media container info)
def exp_tlv(tag, val):
    return struct.pack('!HH', tag, len(val)) + val


def exported(payload, sport, dport):
    return (exp_tlv(12, b'ipp') + exp_tlv(20, ip4(C)) + exp_tlv(21, ip4(S))
            + exp_tlv(24, struct.pack('!I', 2)) + exp_tlv(25, struct.pack('!I', sport))
            + exp_tlv(26, struct.pack('!I', dport)) + struct.pack('!HH', 0, 0) + payload)


allf = [(0, f) for f in frames]
allf.append((1, exported(ipp(0x000b, 50, op_attrs()), 40010, 631)))
allf.append((1, exported(ipp(0x0000, 50, rsp_ops, b'\x04' + a(0x42, 'printer-name', 'exported')), 631, 40010)))
write_pcapng(os.path.join(sys.argv[1], 'ipp-coverage.pcapng'), [1, 252], allf)

# ---------------------------------------------------------------- malformed
mal = []
t = session(mal, 41001, isn_c=10, isn_s=20)
# textWithLanguage / nameWithLanguage (valid per RFC 8010) and broken ones
twl = struct.pack('!H', 2) + b'en' + struct.pack('!H', 5) + b'hello'
tbad = struct.pack('!H', 2) + b'en' + struct.pack('!H', 500) + b'hello'
tbad2 = struct.pack('!H', 500) + b'en' + struct.pack('!H', 5) + b'hello'
tshort = b'\x00\x01a'
for k, attrs in enumerate((
        a(0x35, 'printer-info', twl),
        a(0x36, 'printer-name', twl) + a(0x36, '', twl),
        a(0x35, 'bad-string-len', tbad),
        a(0x36, 'bad-lang-len', tbad2),
        a(0x35, 'short-twl', tshort),
        a(0x36, 'short-nwl', b'')
        )):
    t.send(http_req(ipp(0x000b, 100 + k, op_attrs())))
    t.send(http_rsp(ipp(0, 100 + k, b'\x04' + attrs, tail=b'\x00' * 40)), c2s=False)
    t.send(http_rsp(ipp(0, 200 + k, b'\x04' + attrs)), c2s=False)


def bad(body):
    t.send(http_req(body))


# a request id used twice (the transaction is found by id only, so the
# second pass pairs the first response with the second request), an empty
# value of an unknown octetString type (the label shows a NULL string)
t.send(http_req(ipp(0x0009, 10, op_attrs())))
t.send(http_rsp(ipp(0x0000, 10, rsp_ops)), c2s=False)
t.send(http_req(ipp(0x0009, 10, op_attrs())))
t.send(http_rsp(ipp(0x0000, 10, rsp_ops, b'\x04' + a(0x3f, 'empty-unknown-octet-type', b''))), c2s=False)


# truncated attribute: name length runs past the end
bad(ipp(0x000b, 300, b'\x01', b'\x47\x00\xff' + b'attr', end=False))
# value length runs past the end
bad(ipp(0x000b, 301, b'\x01', b'\x47\x00\x01a\x01\x00' + b'short', end=False))
# only the tag
bad(ipp(0x000b, 302, b'\x01', b'\x21', end=False))
# tag and one octet of the name length
bad(ipp(0x000b, 303, b'\x01', b'\x21\x00', end=False))
# header shorter than the fixed part
bad(b'\x02\x00\x00\x0b\x00')
bad(b'\x02\x00')
# values that run past the end for each type
for tag, val in ((0x21, b'\x00\x00\x00\x05'), (0x22, b'\x01'), (0x23, b'\x00\x00\x00\x05'),
                 (0x31, b'\x00' * 11), (0x32, b'\x00' * 9), (0x33, b'\x00' * 8),
                 (0x30, b'abcdef'), (0x44, b'keyword'), (0x10, b'')):
    full = a(tag, 'trunc-attr', val)
    for cut in (1, 3):
        bad(ipp(0x000b, 310, b'\x01', full[:-cut], end=False))
# multi-valued attributes cut off in the next value
for tag, val in ((0x21, i4(1)), (0x23, i4(1)), (0x30, b'x'), (0x32, b'\x00' * 9), (0x33, i4(1) + i4(2)),
                 (0x44, b'k')):
    bad(ipp(0x000b, 311, b'\x01', a(tag, 'multi', val), bytes([tag]) + b'\x00\x00\x00\x04' + b'\x00', end=False))
    bad(ipp(0x000b, 311, b'\x01', a(tag, 'multi', val), bytes([tag]) + b'\x00\x00', end=False))
    bad(ipp(0x000b, 311, b'\x01', a(tag, 'multi', val), bytes([tag]), end=False))
    bad(ipp(0x000b, 311, b'\x01', a(tag, 'multi', val), bytes([tag]) + b'\x00\x05abc', end=False))
# collections that are never closed or cut off
bad(ipp(0x000b, 320, b'\x01', a(0x34, 'open-collection'), a(0x4a, '', 'member'), end=False))
bad(ipp(0x000b, 321, b'\x01', a(0x34, 'open-collection'), a(0x4a, '', 'member'), a(0x21, '', i4(1))))
bad(ipp(0x000b, 322, b'\x01', a(0x34, 'cut-collection'), b'\x4a\x00\x00\x00\x20abc', end=False))
bad(ipp(0x000b, 323, b'\x01', a(0x34, 'cut-collection'), b'\x4a\x00\x10abc', end=False))
bad(ipp(0x000b, 324, b'\x01', a(0x34, 'cut-collection'), b'\x4a\x00', end=False))
bad(ipp(0x000b, 325, b'\x01', a(0x34, 'cut-collection'), b'\x4a', end=False))
bad(ipp(0x000b, 326, b'\x01', a(0x34, 'cut-collection'), b'', end=False))
# an unnamed collection start and a lone endCollection
bad(ipp(0x000b, 327, b'\x01', a(0x34, ''), a(0x4a, '', 'x'), a(0x37, '')))
bad(ipp(0x000b, 328, b'\x01', a(0x37, 'lonely-end')))
bad(ipp(0x000b, 329, b'\x01', a(0x37, ''), a(0x37, '')))
# nesting deeper than the dissection depth limit
deep = b''.join(a(0x34, '') + a(0x4a, '', 'm') for _ in range(600))
bad(ipp(0x000b, 330, b'\x01', a(0x34, 'deep'), deep, end=False))
deep = b''.join(a(0x4a, '', 'm') + a(0x34, '') for _ in range(600))
bad(ipp(0x000b, 331, b'\x01', a(0x34, 'deep'), deep, a(0x37, '') * 600))
# the language length of a textWithLanguage value is read from the tag
# byte (see README): with 13.5 KB behind the value the strings are found
zeros = a(0x30, 'padding', b'\0' * 14000)
bad(ipp(0x000b, 340, b'\x01', a(0x35, 'twl-big', twl), zeros))
bad(ipp(0x000b, 341, b'\x01', a(0x44, 'kw', 'v'), a(0x35, '', twl), zeros))
bad(ipp(0x000b, 342, b'\x01', a(0x44, 'kw', 'v'), a(0x36, '', twl), zeros))
bad(ipp(0x000b, 343, b'\x01', a(0x35, 'twl-trunc', twl), b'\x35\x00\x10\x00', end=False))
t.fin()
write_pcap(os.path.join(sys.argv[1], 'ipp-coverage-malformed.pcap'), mal)
