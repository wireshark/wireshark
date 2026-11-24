#!/usr/bin/env python3
# Generates test/captures/edhoc_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the EDHOC dissector
(packet-edhoc.c, Ephemeral Diffie-Hellman Over COSE, RFC 9528).

EDHOC has no port of its own: it is a media type handler for
"application/edhoc+cbor-seq" and "application/cid-edhoc+cbor-seq",
reached by default through CoAP (Content-Format 64 and 65, UDP 5683),
HTTP (Content-Type) and MQTT v5 (the Content Type property), and by
name as "edhoc" (Exported PDU). Sessions are tracked per transport
conversation: a message 1 starts a session, the next messages are taken
as message 2, 3 and 4, an error (exactly two CBOR items) ends it, and a
message 1 after message 3, 4 or an error starts a new one.

Frames 1-37 are built here with struct and carry no usable ciphertext:
messages 2-4 are random-looking bytes and are reported as not decrypted
(a warning). Frames 38-52 come from edhoc_decrypt.py (written by the
main session, copied here unchanged): EDHOC sessions whose messages 2-4
decrypt with made-up secrets passed in the EDHOC secrets table (the
keystream and AEAD of those frames use the Python 'cryptography'
library, run with /usr/bin/python3). No captured traffic is used;
addresses are from 192.0.2.0/24.

Usage: mkedhoc.py <output directory> [-v]   (-v prints frame ranges)
       edhoc_decrypt.py -k                  prints the -o uat:... options

Writes:
  edhoc-coverage.pcapng            see the README (pcapng: Ethernet and
                                   Exported PDU interfaces)
  edhoc-coverage-malformed.pcapng  message 1 with G_X or C_I of the wrong
                                   type (the asserts of the fix), a frame
                                   that is not a message 1 before a valid
                                   session (session numbers in two
                                   passes), a one-element suite array, a
                                   G_X of the wrong length, message 2 for
                                   an unknown suite, messages 2-4 that are
                                   not byte strings, an EAD label that is
                                   not an integer, truncated CBOR
"""

import os
import struct
import sys

sys.dont_write_bytecode = True
import edhoc_decrypt
from edhoc_decrypt import cint, cbstr, ctstr, carr, cmap, head  # noqa: E402,F401

# ---------------------------------------------------------------- frames


def csum(b):
    if len(b) % 2:
        b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4(a):
    return bytes(int(x) for x in a.split('.'))


IDENT = [0x4000]


def ipv4(src, dst, proto, l4):
    IDENT[0] += 1
    h = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), IDENT[0], 0x4000, 64, proto, 0,
                    ip4(src), ip4(dst))
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return bytes([2, 0]) + ip4(dst) + bytes([2, 0]) + ip4(src) + b'\x08\x00' + h + l4


def udp_frame(src, sport, dst, dport, payload):
    u = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 17, len(u))
    u = u[:6] + struct.pack('!H', csum(ph + u) or 0xffff) + u[8:]
    return ipv4(src, dst, 17, u)


def tcp_seg(src, sport, dst, dport, seq, ack, payload):
    t = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, 0x18, 65535, 0, 0) + payload
    ph = ip4(src) + ip4(dst) + struct.pack('!BBH', 0, 6, len(t))
    t = t[:16] + struct.pack('!H', csum(ph + t)) + t[18:]
    return ipv4(src, dst, 6, t)


class Tcp:
    """A TCP connection captured after its handshake."""

    def __init__(self, cli, cport, srv, sport):
        self.cli, self.cport, self.srv, self.sport = cli, cport, srv, sport
        self.seq = {0: 1, 1: 1}

    def seg(self, data, from_server=False):
        d = 1 if from_server else 0
        a, ap, b, bp = (self.srv, self.sport, self.cli, self.cport) if d else \
                       (self.cli, self.cport, self.srv, self.sport)
        fr = tcp_seg(a, ap, b, bp, self.seq[d], self.seq[1 - d], data)
        self.seq[d] += len(data)
        return fr


def exp_pdu(name, payload):
    n = name.encode()
    pad = (4 - len(n) % 4) % 4
    return struct.pack('>HH', 12, len(n) + pad) + n + b'\0' * pad + struct.pack('>HH', 0, 0) + payload


def pcapng(path, frames):
    """frames: list of (interface, bytes); interface 0 Ethernet, 1 Exported PDU."""
    def block(btype, body):
        body += b'\0' * ((4 - len(body) % 4) % 4)
        return struct.pack('<II', btype, 12 + len(body)) + body + struct.pack('<I', 12 + len(body))
    with open(path, 'wb') as f:
        f.write(block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        f.write(block(1, struct.pack('<HHI', 1, 0, 262144)))
        f.write(block(1, struct.pack('<HHI', 252, 0, 262144)))
        for i, (ifc, data) in enumerate(frames):
            ts = (1700000000 + i) * 1000000
            f.write(block(6, struct.pack('<IIIII', ifc, ts >> 32, ts & 0xffffffff, len(data),
                                         len(data)) + data))

# ---------------------------------------------------------------- CoAP, HTTP, MQTT


def coap(mid, payload, cf, response=False, token=b''):
    code = 0x44 if response else 0x02         # 2.04 Changed / POST
    typ = 0x60 if response else 0x40          # ACK / CON
    hdr = bytes([typ | len(token), code]) + struct.pack('!H', mid) + token
    if response:
        opts = bytes([0xc1, cf])              # Content-Format (12)
    else:
        opts = bytes([0xb4]) + b'edhc' + bytes([0x11, cf])   # Uri-Path, Content-Format
    return hdr + opts + b'\xff' + payload


class CoapPeer:
    def __init__(self, cli, cport, srv):
        self.cli, self.cport, self.srv, self.mid = cli, cport, srv, 0x200

    def req(self, payload, cf=64):
        self.mid += 1
        return (0, udp_frame(self.cli, self.cport, self.srv, 5683, coap(self.mid, payload, cf)))

    def rsp(self, payload, cf=64):
        return (0, udp_frame(self.srv, 5683, self.cli, self.cport, coap(self.mid, payload, cf, True)))


def http_req(body, ctype=b'application/edhoc+cbor-seq'):
    return (b'POST /.well-known/edhoc HTTP/1.1\r\nHost: 192.0.2.61\r\nContent-Type: ' + ctype +
            b'\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)


def http_rsp(body, ctype=b'application/edhoc+cbor-seq'):
    return (b'HTTP/1.1 200 OK\r\nContent-Type: ' + ctype + b'\r\nContent-Length: ' +
            str(len(body)).encode() + b'\r\n\r\n' + body)


def mqtt_str(s):
    return struct.pack('>H', len(s)) + s


def mqtt_fixed(t, body):
    assert len(body) < 128
    return bytes([t, len(body)]) + body


def mqtt_publish(topic, payload, ctype=b'application/edhoc+cbor-seq'):
    props = b'\x03' + mqtt_str(ctype)
    return mqtt_fixed(0x30, mqtt_str(topic) + bytes([len(props)]) + props + payload)

# ---------------------------------------------------------------- EDHOC values


def blob(tag, n):
    """Made-up octets (not secrets, not ciphertext of anything)."""
    return bytes((tag * 37 + i * 13) & 0xff for i in range(n))


def msg1(method, suites, gx, c_i, ead=b''):
    if isinstance(suites, int):
        s = cint(suites)
    else:
        s = carr(len(suites)) + b''.join(cint(x) for x in suites)
    return cint(method) + s + cbstr(gx) + c_i + ead


INT64_MIN_LABEL = b'\x3b' + struct.pack('>Q', (1 << 63) - 1)   # -2**63
TRUE = b'\xf5'

RANGES = []


def mark(f, label):
    RANGES.append((len(f) + 1, label))


def main_frames():
    f = []
    # ---- CoAP session A: method 3, suites [6, 2], messages 1-4 (no
    # secrets), a fifth message, a second session ended by an error, a
    # third session
    mark(f, 'CoAP 192.0.2.40: sessions 0-3 (messages 1-4, extra messages, errors, new message 1)')
    a = CoapPeer('192.0.2.40', 40040, '192.0.2.41')
    ead = (cint(0) + cbstr(b'\x00\x00\x00') +              # padding
           cint(-5) + cbstr(b'\x01') +                      # critical, unknown
           INT64_MIN_LABEL + cbstr(b'\x02') +               # label -2**63 (fixed)
           cint(7) + cint(8) +                              # labels without values
           cint(99) + cbstr(cmap(1) + cint(1) + cint(2)))   # CBOR inside a bstr
    f.append(a.req(msg1(3, [6, 2], blob(1, 32), cint(-24), ead)))
    f.append(a.rsp(cbstr(blob(2, 32) + blob(3, 20))))                       # message 2
    f.append(a.req(cbstr(blob(4, 24))))                                     # message 3
    f.append(a.rsp(cbstr(blob(5, 8))))                                      # message 4
    f.append(a.req(cbstr(blob(6, 4))))                                      # after message 4
    # after message 4, CBOR sequences that are neither an error nor a
    # message 1 (suites a tstr; G_X an int; C_I a tstr; a suites array
    # whose item has a reserved head, so neither check can skip it)
    f.append(a.req(cint(3) + ctstr('x') + cint(0)))
    f.append(a.req(cint(3) + cint(2) + cint(5) + cint(0)))
    f.append(a.req(cint(3) + cint(2) + cbstr(b'\x01') + ctstr('c')))
    f.append(a.req(cint(3) + carr(2) + b'\x1c' + cint(0)))
    f.append(a.req(msg1(3, 2, blob(7, 32), cbstr(b'\x05\x06'))))             # session 1
    f.append(a.rsp(cint(1) + ctstr('Unspecified')))                         # error code 1
    f.append(a.req(msg1(3, [2, 3, 2], blob(8, 32), cint(9))))                # session 2
    f.append(a.rsp(cint(2) + carr(2) + cint(3) + cint(2)))                  # error: suites
    f.append(a.req(msg1(2, -24, blob(9, 32), cint(10))))                     # session 3, private suite
    # ---- CoAP session with CID prefixes (Content-Format 65)
    mark(f, 'CoAP 192.0.2.42: application/cid-edhoc+cbor-seq (true prefix, C_R prefixes)')
    c = CoapPeer('192.0.2.42', 40042, '192.0.2.43')
    f.append(c.req(TRUE + msg1(3, 0, blob(10, 32), cint(-20)), cf=65))       # true + message 1
    f.append(c.rsp(cbstr(blob(11, 32) + blob(12, 16))))                    # message 2
    f.append(c.req(cint(-7) + cbstr(blob(13, 24)), cf=65))                   # C_R int + message 3
    f.append(c.rsp(cbstr(blob(14, 8))))                                     # message 4
    f.append(c.req(TRUE + msg1(3, 1, blob(15, 32), cbstr(b'\x07')), cf=65))  # new session
    f.append(c.rsp(cbstr(blob(16, 32) + blob(17, 16))))
    f.append(c.req(cbstr(b'\x08') + cbstr(blob(18, 4)), cf=65))              # C_R bstr + short message 3
    # true prefix in the middle of a session: a new session
    f.append(c.req(TRUE + msg1(3, 2, blob(19, 32), cint(1)), cf=65))
    # ---- CoAP: C_I given as "true" (a correlator), X25519 suite 4
    mark(f, 'CoAP 192.0.2.44: C_I as a CBOR true, suites 4 and 24')
    t = CoapPeer('192.0.2.44', 40044, '192.0.2.45')
    f.append(t.req(msg1(0, 4, blob(20, 32), TRUE)))
    t = CoapPeer('192.0.2.44', 40045, '192.0.2.45')
    # suite 24 uses P-384 (48 octet keys)
    f.append(t.req(msg1(1, [6, 24], blob(21, 48), cint(2))))
    f.append(t.rsp(cbstr(blob(22, 48) + blob(23, 12))))
    # ---- CoAP: suite 25 (SHAKE256, X448), messages 1-4
    mark(f, 'CoAP 192.0.2.46: suite 25 (SHAKE256: no KDF), messages 1-4')
    e = CoapPeer('192.0.2.46', 40046, '192.0.2.47')
    f.append(e.req(msg1(3, [2, 25], blob(24, 57), cint(3))))
    f.append(e.rsp(cbstr(blob(25, 57) + blob(26, 16))))
    f.append(e.req(cbstr(blob(27, 24))))
    f.append(e.rsp(cbstr(blob(28, 16))))
    # ---- HTTP: session B, SIGN-SIGN, suite 0, messages 1-4
    mark(f, 'HTTP 192.0.2.60 -> .61:80: messages 1-4 (SIGN-SIGN, suite 0)')
    h = Tcp('192.0.2.60', 40060, '192.0.2.61', 80)
    f.append((0, h.seg(http_req(msg1(0, 0, blob(30, 32), cbstr(b'\x01\x02'))))))
    f.append((0, h.seg(http_rsp(cbstr(blob(31, 32) + blob(32, 40))), True)))
    f.append((0, h.seg(http_req(cbstr(blob(33, 40))))))
    f.append((0, h.seg(http_rsp(cbstr(blob(34, 8))), True)))
    # ---- MQTT v5: message 1 and 2 in PUBLISH packets (Content Type)
    mark(f, 'MQTT v5 192.0.2.62 -> .63:1883: CONNECT, PUBLISH with messages 1 and 2 (fixed)')
    m = Tcp('192.0.2.62', 40062, '192.0.2.63', 1883)
    connect = mqtt_fixed(0x10, mqtt_str(b'MQTT') + bytes([5, 0x02]) + struct.pack('>H', 60) +
                         b'\x00' + mqtt_str(b'edhoc'))
    f.append((0, m.seg(connect)))
    f.append((0, m.seg(mqtt_publish(b'edhoc/1', msg1(3, 2, blob(40, 32), cint(-24))))))
    f.append((0, m.seg(mqtt_publish(b'edhoc/1', cbstr(blob(41, 32) + blob(42, 10))))))
    # ---- Exported PDU naming "edhoc" (no state given: left to data)
    mark(f, 'Exported PDU "edhoc" (fixed: no state, left to the data dissector)')
    f.append((1, exp_pdu('edhoc', msg1(3, 2, blob(50, 32), cint(-24)))))
    return f


def malformed_frames():
    f = []
    a = CoapPeer('192.0.2.70', 40070, '192.0.2.71')
    # 1-2: the reproducers of edhoc_msg1_null_tvb.py: G_X not a bstr,
    # C_I an array (tvb_reported_length(NULL) asserted)
    f.append(a.req(bytes([0x03, 0x02, 0x00, 0x37])))
    a = CoapPeer('192.0.2.72', 40072, '192.0.2.73')
    f.append(a.req(bytes([0x03, 0x02, 0x58, 0x20]) + b'\x11' * 32 + bytes([0x80])))
    # 3-5: a frame that is not a message 1 (method is a tstr), then a
    # session: its index must be 0 in one and two passes
    a = CoapPeer('192.0.2.74', 40074, '192.0.2.75')
    f.append(a.req(ctstr('hello')))
    f.append(a.req(msg1(3, 2, blob(60, 32), cint(1))))
    f.append(a.rsp(cbstr(blob(61, 40))))
    # 6: suite array of one element
    a = CoapPeer('192.0.2.76', 40076, '192.0.2.77')
    f.append(a.req(msg1(3, [2], blob(62, 32), cint(1))))
    # 7-8: G_X of 16 octets for P-256; message 2 for an unknown suite 99
    a = CoapPeer('192.0.2.78', 40078, '192.0.2.79')
    f.append(a.req(msg1(3, 2, blob(63, 16), cint(1))))
    a = CoapPeer('192.0.2.80', 40080, '192.0.2.81')
    f.append(a.req(msg1(3, 99, blob(64, 32), cint(1))))
    f.append(a.rsp(cbstr(blob(65, 40))))
    # 10-12: messages 2, 3 and 4 that are not byte strings
    a = CoapPeer('192.0.2.82', 40082, '192.0.2.83')
    f.append(a.req(msg1(3, 2, blob(66, 32), cint(1))))
    f.append(a.rsp(cint(5) + cint(6) + cint(7)))
    a = CoapPeer('192.0.2.84', 40084, '192.0.2.85')
    f.append(a.req(msg1(3, 2, blob(67, 32), cint(1))))
    f.append(a.rsp(cbstr(blob(68, 40))))
    f.append(a.req(ctstr('m3') + cint(0)))
    a = CoapPeer('192.0.2.86', 40086, '192.0.2.87')
    f.append(a.req(msg1(3, 2, blob(69, 32), cint(1))))
    f.append(a.rsp(cbstr(blob(70, 40))))
    f.append(a.req(cbstr(blob(71, 24))))
    f.append(a.rsp(ctstr('m4') + cint(0)))
    # EAD label that is not an integer; method not an integer; truncated
    a = CoapPeer('192.0.2.88', 40088, '192.0.2.89')
    f.append(a.req(msg1(3, 2, blob(72, 32), cint(1), ctstr('x') + cbstr(b'\x00'))))
    a = CoapPeer('192.0.2.90', 40090, '192.0.2.91')
    f.append(a.req(msg1(3, 2, blob(73, 32), cint(1))[:20]))
    # MQTT v5 reproducer (edhoc_mqtt_null_data.py) as written: G_X of one
    # octet (pubkey length error)
    m = Tcp('192.0.2.92', 40092, '192.0.2.93', 1883)
    connect = mqtt_fixed(0x10, mqtt_str(b'MQTT') + bytes([5, 0x02]) + struct.pack('>H', 60) +
                         b'\x00' + mqtt_str(b''))
    f.append((0, m.seg(connect)))
    f.append((0, m.seg(mqtt_publish(b't', bytes([0x03, 0x02, 0x58, 0x01, 0x00, 0x37])))))
    return f


def main():
    out = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else '.'
    frames = main_frames()
    mark(frames, 'edhoc_decrypt.py: CoAP sessions 192.0.2.20-29 that decrypt with the secrets')
    frames += [(0, fr) for fr in edhoc_decrypt.frames()]
    pcapng(os.path.join(out, 'edhoc-coverage.pcapng'), frames)
    pcapng(os.path.join(out, 'edhoc-coverage-malformed.pcapng'), malformed_frames())
    if '-v' in sys.argv:
        for i, (start, label) in enumerate(RANGES):
            end = RANGES[i + 1][0] - 1 if i + 1 < len(RANGES) else len(frames)
            print('%d-%d: %s' % (start, end, label))


if __name__ == '__main__':
    main()
