#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate test/captures/moqt-draft22.pcapng.gz: an MOQT draft-22 session over
QUIC (ALPN "moqt-22") between an in-process aioquic client and server.  The
TLS secrets are embedded in a Decryption Secrets Block so that the capture
decrypts without a keylog file.

Requires: pip install aioquic
Usage: generate-moqt-draft22-capture.py OUTPUT.pcapng.gz
"""

import datetime
import gzip
import io
import struct
import sys

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import HandshakeCompleted
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ALPN = "moqt-22"
CLIENT = ("192.0.2.1", 50000)
SERVER = ("192.0.2.2", 4443)


# --- MOQT encoding -------------------------------------------------------

def vi(value):
    """MOQT varint: leading 1 bits of the first byte give the length."""
    for length in range(1, 9):
        if value < 1 << (7 * length):
            prefix = (0xFF00 >> (length - 1)) & 0xFF
            raw = value.to_bytes(length, "big")
            return bytes([raw[0] | prefix]) + raw[1:]
    return b"\xff" + value.to_bytes(8, "big")


def lp(data):
    return vi(len(data)) + data


def ns(*fields):
    return vi(len(fields)) + b"".join(lp(f.encode()) for f in fields)


def name(text):
    return lp(text.encode())


def params(*items):
    """items: (type, encoded value), in ascending type order."""
    out, prev = vi(len(items)), 0
    for ptype, value in items:
        out += vi(ptype - prev) + value
        prev = ptype
    return out


def kvps(*items):
    """Key-Value-Pairs: odd types are length prefixed, even types are integers."""
    out, prev = b"", 0
    for key, value in items:
        out += vi(key - prev) + (lp(value) if key & 1 else vi(value))
        prev = key
    return out


def msg(mtype, body):
    return vi(mtype) + struct.pack("!H", len(body)) + body


def location(group, obj):
    return vi(group) + vi(obj)


def ranges(*pairs):
    """Range Filter ranges, delta encoded; a pair (start, None) is open-ended."""
    out, prev_end = b"", 0
    for start, end in pairs:
        out += vi(start - prev_end)
        if end is not None:
            out += vi(end - start)
            prev_end = end
    return out


def token_use_value(token_type, value):
    return vi(0x3) + vi(token_type) + value


# Message types and parameters, draft-ietf-moq-transport-22.
SETUP, GOAWAY, SUBSCRIBE, SUBSCRIBE_OK, REQUEST_ERROR = 0x2F00, 0x10, 0x03, 0x04, 0x05
PUBLISH_NAMESPACE, REQUEST_OK, NAMESPACE, PUBLISH_DONE = 0x06, 0x07, 0x08, 0x0B
TRACK_STATUS, NAMESPACE_DONE, PUBLISH_SKIPPED, FETCH, FETCH_OK = 0x0D, 0x0E, 0x0F, 0x16, 0x18
PUBLISH, PUBLISH_STATE_NOTIFY, REQUEST_UPDATE = 0x1D, 0x22, 0x02
SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS = 0x50, 0x51

P_AUTH, P_EXPIRES, P_LARGEST, P_FILL_TIMEOUT, P_FORWARD = 0x03, 0x08, 0x09, 0x0A, 0x10
P_SUB_PRIO, P_LOC_FILTER, P_GROUP_ORDER, P_FILL_PARAMS = 0x20, 0x21, 0x22, 0x23
P_SUBGROUP_FILTER, P_OBJ_PROP_FILTER, P_TRACK_PROP_FILTER, P_INCLUDE_PROPS = 0x25, 0x28, 0x29, 0x35


def u8(v):
    return bytes([v])


def loc_filter(ftype, *fields):
    return vi(ftype) + b"".join(vi(f) for f in fields)


# --- QUIC session plumbing -------------------------------------------------

class Session:
    def __init__(self):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "moq.example")])
        now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("moq.example")]), False)
                .sign(key, hashes.SHA256()))
        self.keylog = io.StringIO()
        ccfg = QuicConfiguration(is_client=True, alpn_protocols=[ALPN], max_datagram_frame_size=65536,
                                 server_name="moq.example", secrets_log_file=self.keylog)
        ccfg.verify_mode = 0
        scfg = QuicConfiguration(is_client=False, alpn_protocols=[ALPN], max_datagram_frame_size=65536)
        scfg.certificate, scfg.private_key = cert, key
        self.now = 1790000000.0
        self.client = QuicConnection(configuration=ccfg)
        self.server = QuicConnection(configuration=scfg, original_destination_connection_id=self.client.original_destination_connection_id)
        self.packets = []
        self.client.connect(SERVER, now=self.now)
        self.flush()
        assert any(isinstance(e, HandshakeCompleted) for e in self.drain(self.client))

    def drain(self, conn):
        events = []
        while (e := conn.next_event()) is not None:
            events.append(e)
        return events

    def flush(self):
        """Exchange datagrams until both sides go quiet."""
        while True:
            moved = False
            for src, dst, src_addr, dst_addr in ((self.client, self.server, CLIENT, SERVER),
                                                 (self.server, self.client, SERVER, CLIENT)):
                for data, _ in src.datagrams_to_send(now=self.now):
                    self.now += 0.001
                    self.packets.append((self.now, src_addr, dst_addr, data))
                    dst.receive_datagram(data, src_addr, now=self.now)
                    moved = True
            if not moved:
                break
            self.drain(self.server)

    def send(self, conn, stream_id, data, end=False, split=None):
        """Send stream data; split=n sends the first n bytes in a separate packet."""
        if split:
            conn.send_stream_data(stream_id, data[:split])
            self.flush()
            data = data[split:]
        conn.send_stream_data(stream_id, data, end)
        self.flush()


def write_pcapng(path, packets, keylog):
    def block(block_type, body):
        body += b"\0" * (-len(body) % 4)
        length = len(body) + 12
        return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)

    def ip_checksum(header):
        total = sum(struct.unpack("!10H", header))
        total = (total & 0xFFFF) + (total >> 16)
        return ~((total & 0xFFFF) + (total >> 16)) & 0xFFFF

    def frame(src, dst, payload):
        udp = struct.pack("!HHHH", src[1], dst[1], 8 + len(payload), 0) + payload
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17, 0,
                         bytes(map(int, src[0].split("."))), bytes(map(int, dst[0].split("."))))
        ip = ip[:10] + struct.pack("!H", ip_checksum(ip)) + ip[12:]
        macs = {CLIENT: b"\x02\0\0\0\0\x01", SERVER: b"\x02\0\0\0\0\x02"}
        return macs[dst] + macs[src] + b"\x08\x00" + ip + udp

    secrets = keylog.encode()
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += block(0x00000001, struct.pack("<HHI", 1, 0, 0))
    out += block(0x0000000A, struct.pack("<II", 0x544C534B, len(secrets)) + secrets)
    for ts, src, dst, payload in packets:
        data = frame(src, dst, payload)
        usec = int(ts * 1e6)
        out += block(0x00000006, struct.pack("<IIIII", 0, usec >> 32, usec & 0xFFFFFFFF, len(data), len(data)) + data)
    with gzip.GzipFile(path, "wb", mtime=0) as f:
        f.write(out)


# --- The MOQT session ------------------------------------------------------

def main():
    s = Session()
    c, sv = s.client, s.server
    track_ns = ("live", "demo")

    # Control streams.
    c_ctl, s_ctl = c.get_next_available_stream_id(is_unidirectional=True), sv.get_next_available_stream_id(is_unidirectional=True)
    s.send(c, c_ctl, msg(SETUP, kvps((0x01, b"/moq"), (0x05, b"moq.example"), (0x07, b"wireshark-test/1.0"), (0x08, 4))))
    s.send(sv, s_ctl, msg(SETUP, kvps((0x04, 4096), (0x06, 8), (0x07, b"wireshark-test-relay/1.0"))))

    # SUBSCRIBE with the new filter parameters, split over two STREAM frames.
    sub = c.get_next_available_stream_id()
    subscribe = msg(SUBSCRIBE, vi(0) + ns(*track_ns) + name("video") + params(
        (P_AUTH, lp(token_use_value(0x1, b"secret"))),
        (P_SUB_PRIO, u8(128)),
        (P_LOC_FILTER, loc_filter(0x4, 10, 0, 5, 3)),
        (P_GROUP_ORDER, u8(1)),
        (P_FILL_PARAMS, lp(params((P_FILL_TIMEOUT, vi(500)), (P_LOC_FILTER, loc_filter(0x1, 2))))),
        (P_SUBGROUP_FILTER, lp(u8(0) + ranges((0, 1)))),
        (P_OBJ_PROP_FILTER, lp(u8(1) + vi(0x0C) + ranges((3, 5), (10, None))))))
    s.send(c, sub, subscribe, split=len(subscribe) // 2)
    s.send(sv, sub, msg(SUBSCRIBE_OK, vi(1) + params((P_EXPIRES, vi(30000)), (P_LARGEST, location(11, 7)))
                        + kvps((0x0B, kvps((0x08, 90000))), (0x0E, 64))))
    s.send(sv, sub, msg(PUBLISH_STATE_NOTIFY, params((P_LARGEST, location(12, 0)), (P_FORWARD, u8(0)))))
    s.send(c, sub, msg(REQUEST_UPDATE, vi(2) + params((P_FORWARD, u8(1)))))
    s.send(sv, sub, msg(REQUEST_OK, params()))

    # Subgroup stream; the second Object is split over two STREAM frames.
    sg = sv.get_next_available_stream_id(is_unidirectional=True)
    header = vi(0x55) + vi(1) + vi(12) + vi(0) + u8(0x80)
    obj0 = vi(0) + vi(0) + lp(b"frame")
    obj2 = vi(1) + lp(kvps((0x0C, 30))) + lp(b"another frame")
    obj3 = vi(0) + vi(0) + vi(0) + vi(0x3)
    s.send(sv, sg, header + obj0 + obj2[:3])
    s.send(sv, sg, obj2[3:] + obj3, end=True)

    # Objects in datagrams, and padding.
    sv.send_datagram_frame(vi(0x00) + vi(1) + vi(20) + vi(4) + u8(0x10) + bytes(range(16)))
    s.flush()
    sv.send_datagram_frame(vi(0x2C) + vi(1) + vi(20) + vi(0x4))
    s.flush()
    c.send_datagram_frame(vi(0x132B3E29) + bytes(8))
    s.flush()
    pad = sv.get_next_available_stream_id(is_unidirectional=True)
    s.send(sv, pad, vi(0x132B3E28) + bytes(32), end=True)

    # FETCH: the range is now a LOCATION_FILTER parameter.
    fetch = c.get_next_available_stream_id()
    s.send(c, fetch, msg(FETCH, vi(4) + ns(*track_ns) + name("video") + params(
        (P_LOC_FILTER, loc_filter(0x4, 0, 0, 2, 5)), (P_GROUP_ORDER, u8(1)), (P_INCLUDE_PROPS, u8(0)))))
    s.send(sv, fetch, msg(FETCH_OK, u8(0) + location(2, 5) + params()), end=True)
    fs = sv.get_next_available_stream_id(is_unidirectional=True)
    s.send(sv, fs, vi(0x05) + vi(4)
           + vi(0x0F) + vi(0) + vi(0) + vi(0) + lp(b"obj0")
           + vi(0x34) + vi(2) + u8(3) + lp(kvps((0x10, 1234))) + lp(b"obj2")
           + vi(0x20C) + vi(1) + vi(3), end=True)

    # Namespace discovery.
    pn = c.get_next_available_stream_id()
    s.send(c, pn, msg(PUBLISH_NAMESPACE, vi(6) + ns("live") + params()))
    s.send(sv, pn, msg(REQUEST_OK, params()))
    sn = c.get_next_available_stream_id()
    s.send(c, sn, msg(SUBSCRIBE_NAMESPACE, vi(8) + ns("live") + params()))
    s.send(sv, sn, msg(REQUEST_OK, params()) + msg(NAMESPACE, ns("demo")))
    s.send(sv, sn, msg(NAMESPACE_DONE, ns("demo")))
    st = c.get_next_available_stream_id()
    s.send(c, st, msg(SUBSCRIBE_TRACKS, vi(10) + ns("live") + params(
        (P_GROUP_ORDER, u8(2)), (P_TRACK_PROP_FILTER, lp(u8(0) + vi(0x0E) + ranges((0, 100)))))))
    s.send(sv, st, msg(REQUEST_OK, params()) + msg(PUBLISH_SKIPPED, ns("demo") + name("audio")))

    # TRACK_STATUS answered with a redirect, while a PUBLISH ends.
    ts = c.get_next_available_stream_id()
    s.send(c, ts, msg(TRACK_STATUS, vi(12) + ns(*track_ns) + name("video") + params((P_INCLUDE_PROPS, u8(1)))))
    pub = sv.get_next_available_stream_id()
    s.send(sv, pub, msg(PUBLISH, vi(1) + ns(*track_ns) + name("chat") + vi(2) + params((P_FORWARD, u8(1)))
                        + kvps((0x30, 1))))
    s.send(c, pub, msg(REQUEST_OK, params()))
    sv.send_stream_data(ts, msg(REQUEST_ERROR, vi(0x34) + vi(0) + lp(b"moved") + lp(b"moqt://relay.example/moq")
                                + ns(*track_ns) + name("video")), True)
    sv.send_stream_data(pub, msg(PUBLISH_DONE, vi(0x2) + vi(0) + lp(b"")), True)
    s.flush()

    s.send(sv, s_ctl, msg(GOAWAY, lp(b"moqt://other.example/moq") + vi(5000)))
    c.close(error_code=0)
    s.flush()

    write_pcapng(sys.argv[1], s.packets, s.keylog.getvalue())
    print(f"{len(s.packets)} packets")


if __name__ == "__main__":
    main()
