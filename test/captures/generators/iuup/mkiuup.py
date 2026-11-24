#!/usr/bin/env python3
# Generates test/captures/iuup_coverage.pcapng.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate synthetic captures that exercise the IuUP dissector
(packet-iuup.c).  Every packet is built with struct; no captured traffic
is used.

IuUP is reached by default through RTP: an SDP "a=rtpmap:96
VND.3GPP.IUFP/16000" in a SIP INVITE/200 OK makes the RTP stream on the
negotiated ports carry IuUP.  The Exported PDU entry points "iuup" and
"find_iuup" are used for the data that a real capture would not carry
over RTP, and for the reproducers of the fixes.

Usage: mkiuup.py <output directory>

Writes:
  iuup-coverage.pcapng            SIP/SDP + RTP carrying IuUP (every PDU
                                  type, procedures, data with and without
                                  CRC), Exported PDUs
  iuup-coverage-malformed.pcapng  bad CRCs, error responses, malformed
                                  procedures, too many RFCIs, bad PDU
                                  types
  iuup-coverage-twobyte.pcapng    two byte pseudoheader frames (needs
                                  -o iuup.two_byte_pseudoheader:TRUE)
"""
import os
import struct
import sys

T6 = [0, 11, 12, 7, 24, 19, 20, 15, 48, 59, 60, 55, 40, 35, 36, 31]  # placeholder, replaced below


def _crc8_bc(i):
    r = i
    for _ in range(8):
        r = (((r << 1) ^ 0xbc) if r & 0x80 else (r << 1)) & 0xff
    return r


T6 = [_crc8_bc(i) >> 2 for i in range(256)]


def crc6(data, crc=0):
    for b in data:
        crc = T6[((crc << 2) ^ b) & 0xff] & 0x3f
    return crc & 0x3f


def _t10():
    out = []
    for i in range(256):
        r = i << 2
        for _ in range(8):
            r <<= 1
            if r & 0x400:
                r ^= 0x633
        out.append(r & 0x3ff)
    return out


T10 = _t10()


def crc10(data, crc=0):
    for b in data:
        crc = ((crc << 8) & 0x3ff) ^ T10[(crc >> 2) & 0xff] ^ b
    return crc


def payload_crc_ok(hdr2, c6, body):
    """Return the 2 octets (header CRC6 in the top bits of the first, CRC10
    below) so that the dissector's check over bytes 2.. gives 0."""
    for c in range(1024):
        b2 = (c6 << 2) | (c >> 8)
        b3 = c & 0xff
        x = ((b2 << 8) | b3) & 0x3ff
        r = crc10(body)
        r = crc10(bytes([x >> 2, (x << 6) & 0xff]), r)
        if r == 0:
            return bytes([b2, b3])
    raise SystemExit("no crc")


# ---------------------------------------------------------------- IuUP PDUs

def ctl(ack, proc, fn, body, mode=1, bad_hdr=False, bad_pay=False, crc=True):
    """Control PDU: byte 0 = 0xe0 | ack<<2 | fn, byte 1 = mode<<4 | proc;
    bytes 2-3 header CRC6 + payload CRC10 (when the procedure has one)."""
    b0 = 0xe0 | (ack << 2) | (fn & 3)
    b1 = (mode << 4) | proc
    c6 = crc6(bytes([b0, b1]))
    if bad_hdr:
        c6 ^= 0x15
    if crc:
        crcb = payload_crc_ok(bytes([b0, b1]), c6, body)
        if bad_pay:
            crcb = bytes([crcb[0] ^ 1, crcb[1]])
    else:
        crcb = bytes([c6 << 2, 0])
    return bytes([b0, b1]) + crcb + body


def init_body(nsub, rfcis, ti=False, chain=0, ipti=None, modes=0x0003, dpt=0x00):
    """rfcis: list of (id, [lens]) or (id, [lens], True) for the two octet
    length form; the last one gets the LRI bit."""
    b = bytes([(ti << 4) | (nsub << 1) | chain])
    for k, r in enumerate(rfcis):
        rid, lens = r[0], r[1]
        two = len(r) > 2 and r[2]
        o = (rid & 0x3f) | (0x40 if two else 0) | (0x80 if k == len(rfcis) - 1 else 0)
        b += bytes([o])
        for l in lens:
            b += struct.pack(">H", l) if two else bytes([l])
    if ti:
        n = len(rfcis)
        ip = ipti or [k & 0xf for k in range(n)]
        for k in range(0, n, 2):
            hi = ip[k] & 0xf
            lo = ip[k + 1] & 0xf if k + 1 < n else 0
            b += bytes([(hi << 4) | lo])
    b += struct.pack(">H", modes) + bytes([dpt << 4])
    return b


def data_pdu(fn, fqc, rfci, payload, with_crc, bad_hdr=False, bad_pay=False):
    b0 = ((0 if with_crc else 1) << 4) | (fn & 0xf)
    b1 = (fqc << 6) | (rfci & 0x3f)
    c6 = crc6(bytes([b0, b1]))
    if bad_hdr:
        c6 ^= 0x0a
    if with_crc:
        crcb = payload_crc_ok(bytes([b0, b1]), c6, payload)
        if bad_pay:
            crcb = bytes([crcb[0], crcb[1] ^ 0x40])
        return bytes([b0, b1]) + crcb + payload
    return bytes([b0, b1, c6 << 2]) + payload


def ratectl_body(inds):
    n = len(inds)
    b = bytes([n & 0x3f])
    for k in range(0, n, 8):
        v = 0
        for j, bit in enumerate(inds[k:k + 8]):
            v |= (bit & 1) << (7 - j)
        b += bytes([v])
    return b


# ---------------------------------------------------------------- file writers

def pcapng(path, interfaces, frames):
    """interfaces: list of link types; frames: (interface, bytes)."""
    def blk(typ, body):
        pad = (-len(body)) % 4
        n = 12 + len(body) + pad
        return struct.pack("<II", typ, n) + body + b"\0" * pad + struct.pack("<I", n)
    out = blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    for lt in interfaces:
        out += blk(1, struct.pack("<HHI", lt, 0, 65535))
    for i, (ifc, data) in enumerate(frames):
        ts = (1700000000 + i) * 1000000
        out += blk(6, struct.pack("<IIIII", ifc, ts >> 32, ts & 0xffffffff, len(data), len(data)) + data)
    open(path, "wb").write(out)


def exported_pdu(name, payload):
    n = name.encode()
    pad = (-len(n)) % 4
    return struct.pack(">HH", 12, len(n) + pad) + n + b"\0" * pad + struct.pack(">HH", 0, 0) + payload


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def eth_udp(src, dst, sport, dport, payload):
    ips = bytes(map(int, src.split(".")))
    ipd = bytes(map(int, dst.split(".")))
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp) + len(payload), 1, 0, 64, 17, 0, ips, ipd)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    mac = {"10.0.0.1": "020000000001", "10.0.0.2": "020000000002"}
    return bytes.fromhex(mac[dst] + mac[src] + "0800") + ip + udp + payload


def rtp(seq, ts, payload, pt=96, ssrc=0x1234, marker=0):
    return struct.pack("!BBHII", 0x80, (marker << 7) | pt, seq, ts, ssrc) + payload


A, B = "10.0.0.1", "10.0.0.2"
PA, PB = 20000, 20002


def sdp(addr, port):
    return ("v=0\r\no=- 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n"
            "m=audio %d RTP/AVP 96\r\na=rtpmap:96 VND.3GPP.IUFP/16000\r\n" % (addr, addr, port))


def sip_invite():
    body = sdp(A, PA)
    return ("INVITE sip:rnc@10.0.0.2 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n"
            "From: <sip:a@10.0.0.1>;tag=1\r\nTo: <sip:rnc@10.0.0.2>\r\nCall-ID: iuup1@10.0.0.1\r\n"
            "CSeq: 1 INVITE\r\nContact: <sip:a@10.0.0.1>\r\nContent-Type: application/sdp\r\n"
            "Content-Length: %d\r\n\r\n%s" % (len(body), body)).encode()


def sip_ok():
    body = sdp(B, PB)
    return ("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n"
            "From: <sip:a@10.0.0.1>;tag=1\r\nTo: <sip:rnc@10.0.0.2>;tag=2\r\nCall-ID: iuup1@10.0.0.1\r\n"
            "CSeq: 1 INVITE\r\nContact: <sip:rnc@10.0.0.2>\r\nContent-Type: application/sdp\r\n"
            "Content-Length: %d\r\n\r\n%s" % (len(body), body)).encode()


class Stream:
    """RTP streams between A and B carrying IuUP (stream 1) and, with other
    ports, stream 2."""
    def __init__(self):
        self.seq = 100
        self.frames = []

    def a2b(self, pdu):
        self.seq += 1
        self.frames.append((0, eth_udp(A, B, PA, PB, rtp(self.seq, self.seq * 160, pdu))))

    def b2a(self, pdu):
        self.seq += 1
        self.frames.append((0, eth_udp(B, A, PB, PA, rtp(self.seq, self.seq * 160, pdu))))


def amr_payload(nbytes, fill=0x5a):
    return bytes(((fill + k) & 0xff) for k in range(nbytes))


def heur_ok(b0, b1):
    """True when both the header CRC check of add_hdr_crc() and the check
    of the heuristic (CRC6 started with the received CRC over the first two
    octets gives 0) hold."""
    d = bytes([b0, b1])
    return crc6(d, crc6(d)) == 0


def ctl_heur(ack, proc, fn, body, crc=False):
    """A control PDU whose mode version is chosen so that the heuristic
    accepts it (find_iuup)."""
    for f2 in [fn] + [x for x in range(4) if x != fn]:
        for mode in range(16):
            if heur_ok(0xe0 | (ack << 2) | f2, (mode << 4) | proc):
                return ctl(ack, proc, f2, body, mode=mode, crc=crc)
    raise SystemExit("no heuristic header")


def data_heur(fn, with_crc, payload):
    for fqc in range(4):
        for rfci in range(64):
            b0 = ((0 if with_crc else 1) << 4) | fn
            if heur_ok(b0, (fqc << 6) | rfci):
                return data_pdu(fn, fqc, rfci, payload, with_crc), fqc, rfci
    raise SystemExit("no heuristic data header")


def main_frames():
    s = Stream()
    s.frames.append((0, eth_udp(A, B, 5060, 5060, sip_invite())))
    s.frames.append((0, eth_udp(B, A, 5060, 5060, sip_ok())))
    rfcis = [(1, [81, 103, 60]), (2, [39, 0, 0]), (3, [0, 0, 0]), (4, [0x0102, 0x0004, 0x0000], True)]
    # Initialization: 3 subflows, 4 RFCIs (the last with two octet lengths),
    # IPTIs, chain indicator set
    s.a2b(ctl(0, 0, 0, init_body(3, rfcis, ti=True, chain=1)))
    s.b2a(ctl(1, 0, 0, b"", crc=False))                                      # Init ACK
    # Re-initialisations: other mode versions, no IPTIs, odd and even RFCI counts with IPTIs
    s.a2b(ctl(0, 0, 1, init_body(1, [(0, [8]), (1, [16])], ti=False, chain=0, modes=0xffff, dpt=1)))
    s.a2b(ctl(0, 0, 2, init_body(3, rfcis[:3], ti=True)))
    s.a2b(ctl(0, 0, 3, init_body(3, rfcis[:2], ti=True)))
    s.a2b(ctl(0, 0, 0, init_body(3, rfcis, ti=False)))
    # Rate control (12 RFCIs, so two octets of indications) and its ACK
    s.a2b(ctl(0, 1, 0, ratectl_body([0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1])))
    s.b2a(ctl(1, 1, 0, ratectl_body([0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1]), crc=False))
    s.a2b(ctl(0, 1, 1, ratectl_body([1, 0, 1])))
    # Time alignment: delay, advance, boundary values, spare bytes, and its ACK
    for ta, fn in ((10, 0), (80, 1), (1, 2), (129, 3), (208, 0)):
        s.a2b(ctl(0, 2, fn, bytes([ta, 0]), crc=False))
    s.a2b(ctl(0, 2, 1, bytes([40]) + b"\xaa\xbb", crc=False))
    s.b2a(ctl(1, 2, 0, bytes([10, 0]), crc=False))
    # Data frames: RFCI 1 = 244 bits over 3 subflows (AMR 12.2 like), with and
    # without payload CRC
    p1 = amr_payload(31)
    s.a2b(data_pdu(0, 0, 1, p1, True))
    s.b2a(data_pdu(1, 0, 1, p1, False))
    s.a2b(data_pdu(2, 0, 2, amr_payload(5), True))                 # RFCI 2: 39 bits
    s.a2b(data_pdu(3, 0, 2, amr_payload(10), False))                # two Payload Frames
    s.a2b(data_pdu(4, 0, 3, b"", True))                             # no data, with CRC
    s.a2b(data_pdu(5, 0, 3, b"", False))                            # no data, without CRC
    s.a2b(data_pdu(6, 0, 1, amr_payload(31) + amr_payload(31, 0x10), False))
    s.a2b(data_pdu(7, 0, 17, amr_payload(8), False))                # RFCI not in the circuit
    s.a2b(data_pdu(8, 0, 1, amr_payload(31), False))
    s.a2b(data_pdu(9, 0, 4, amr_payload(33), True))                 # two octet length RFCI
    s.a2b(data_pdu(10, 0, 3, amr_payload(4), False))                # RFCI with no subflow bits
    return s.frames


def epdu(name, payload):
    return (1, exported_pdu(name, payload))


def main_epdus():
    f = []
    rf = [(0, [13, 26]), (1, [7, 0]), (2, [0, 0])]
    f.append(epdu("iuup", ctl(0, 0, 0, init_body(2, rf, ti=True, chain=0))))
    f.append(epdu("iuup", ctl(1, 0, 0, b"", crc=False)))
    f.append(epdu("iuup", data_pdu(0, 0, 0, amr_payload(5), True)))
    f.append(epdu("iuup", data_pdu(1, 0, 1, amr_payload(1), False)))
    f.append(epdu("iuup", data_pdu(1, 0, 2, amr_payload(2), False)))
    f.append(epdu("iuup", ctl(0, 1, 0, ratectl_body([1, 0, 1]))))
    f.append(epdu("iuup", ctl(0, 2, 0, bytes([20, 0]), crc=False)))
    # find_iuup: the dissector searches the data for a plausible IuUP header
    f.append(epdu("find_iuup", b"\x01\x02" + ctl_heur(0, 2, 0, bytes([20, 0]))))        # control at offset 2
    f.append(epdu("find_iuup", b"\xff" + ctl_heur(0, 1, 0, ratectl_body([1, 1]), crc=True)))
    f.append(epdu("find_iuup", b"\xa5\x5a\x77" + ctl_heur(0, 0, 0, init_body(1, [(0, [8])]), crc=True)))
    d, _, _ = data_heur(3, True, amr_payload(7))
    f.append(epdu("find_iuup", b"\x7f" + d))                                              # data with CRC
    d, _, _ = data_heur(4, False, amr_payload(5))
    f.append(epdu("find_iuup", d))                                                         # type 1 (data without CRC)
    for b0 in range(0x20, 0xe0, 0x10):                                                   # other PDU types: rejected
        for b1 in range(256):
            if heur_ok(b0, b1):
                f.append(epdu("find_iuup", bytes([b0, b1, crc6(bytes([b0, b1])) << 2, 0, 0, 0, 0])))
                break
        break
    f.append(epdu("find_iuup", b"\x00\x01\x02\x03\x04\x05\x06\x07"))                      # no IuUP
    f.append(epdu("find_iuup", b"\x00\x01"))                                              # too short
    f.append(epdu("find_iuup", b"\x00\x01\x02"))                                          # too short for the CRC
    # Reproducers of the fixes
    f.append(epdu("find_iuup", bytes([0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])))   # crc6 over-read
    f.append(epdu("iuup", ctl(0, 0, 0, bytes([0x00, 0x80, 0x00, 0x00, 0x00]))))            # RFCI 0 without subflows
    f.append(epdu("iuup", data_pdu(0, 0, 0, b"\x55" * 8, False)))                          # payload loop
    f.append(epdu("iuup", data_pdu(1, 0, 0, b"\x55" * 8, True)))
    return f


def malformed_frames():
    # A second SIP dialog with the same ports
    s = Stream()
    s.frames.append((0, eth_udp(A, B, 5060, 5060, sip_invite())))
    s.frames.append((0, eth_udp(B, A, 5060, 5060, sip_ok())))
    s.a2b(data_pdu(0, 0, 1, amr_payload(8), False))                                # no Init yet
    s.a2b(ctl(0, 0, 0, init_body(2, [(1, [16, 17])]), bad_hdr=True))              # bad header CRC
    s.a2b(ctl(0, 0, 0, init_body(2, [(1, [16, 17])]), bad_pay=True))              # bad payload CRC
    s.a2b(data_pdu(0, 1, 1, amr_payload(5), True, bad_hdr=True, bad_pay=True))    # FQC "bad"
    s.a2b(data_pdu(1, 2, 1, amr_payload(5), False))                               # FQC "bad due to radio"
    s.a2b(ctl(3, 0, 0, b"\x00\x00", crc=False))                                   # reserved Ack/Nack
    s.a2b(ctl(2, 0, 0, bytes([0x2a << 2, 0]), crc=False))                         # NACK
    s.a2b(ctl(2, 1, 0, bytes([0x00, 0]), crc=False))
    for ta in (0, 81, 128, 209, 255):
        s.a2b(ctl(0, 2, 0, bytes([ta, 0]), crc=False))                            # time alignment out of range
    s.a2b(ctl(0, 9, 0, b"\x00\x00", crc=False))                                   # unknown procedure
    s.a2b(ctl(1, 9, 0, b"\x00\x00", crc=False))                                   # ACK of an unknown procedure
    s.a2b(ctl(1, 0, 0, b"", crc=False))
    for cause in (0, 3, 20, 42, 63):
        s.a2b(ctl(0, 3, 0, bytes([0x40 | cause, 0]), crc=False))                  # Error Event
    s.a2b(ctl(1, 3, 1, bytes([0x80 | 1, 0]), crc=False))                          # ACK of an Error Event
    for t in (2, 3, 7, 13):
        s.a2b(bytes([t << 4, 0, 0, 0]))                                           # unknown PDU types
    f = list(s.frames)
    # Exported PDUs: more than 64 RFCIs (the fixed assertion), exactly 64
    f.append(epdu("iuup", ctl(0, 0, 0, bytes([0x00]) + bytes([0x00]) * 70 + b"\0\0\0")))
    f.append(epdu("iuup", ctl(0, 0, 0, bytes([0x00]) + bytes([0x00]) * 63 + bytes([0x80]) + b"\0\0\0")))
    # Frames cut short (exceptions)
    f.append(epdu("iuup", ctl(0, 0, 0, bytes([0x00, 0x00]))))                      # Init without the mode versions
    f.append(epdu("iuup", ctl(0, 1, 0, bytes([40]))))                             # Rate control with no indications
    f.append(epdu("iuup", ctl(0, 2, 0, bytes([20]), crc=False)))                  # Time alignment, no spare bytes
    f.append(epdu("iuup", b"\xe0\x00"))
    f.append(epdu("iuup", b"\x00"))
    return f


def twobyte_frames():
    """Two byte pseudoheader (direction bit and circuit id) in front of the
    PDU; Exported PDUs naming "iuup"."""
    def ph(direction, circuit, pdu):
        return epdu("iuup", struct.pack(">H", (direction << 15) | circuit) + pdu)
    rf = [(0, [13, 26]), (1, [7, 0])]
    f = []
    f.append(ph(0, 5, ctl(0, 0, 0, init_body(2, rf))))
    f.append(ph(1, 5, ctl(1, 0, 0, b"", crc=False)))
    f.append(ph(0, 5, data_pdu(0, 0, 0, amr_payload(5), True)))
    f.append(ph(1, 5, data_pdu(1, 0, 1, amr_payload(1), False)))
    f.append(ph(0, 6, data_pdu(1, 0, 1, amr_payload(2), False)))          # circuit 6: no Init
    f.append(ph(0, 5, ctl(0, 0, 1, init_body(1, [(0, [7]), (3, [15])]))))  # re-init of circuit 5
    f.append(ph(0, 5, data_pdu(2, 0, 3, amr_payload(2), False)))
    f.append(ph(0, 5, data_pdu(3, 0, 1, amr_payload(4), False)))          # RFCI 1 is now unknown
    f.append(ph(0, 7, ctl(0, 2, 0, bytes([20, 0]), crc=False)))
    return f


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    pcapng(os.path.join(out, "iuup-coverage.pcapng"), [1, 252], main_frames() + main_epdus())
    pcapng(os.path.join(out, "iuup-coverage-malformed.pcapng"), [1, 252], malformed_frames())
    pcapng(os.path.join(out, "iuup-coverage-twobyte.pcapng"), [1, 252], twobyte_frames())


if __name__ == "__main__":
    main()
