#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Generate a moq-lite-06 session over QUIC between an in-process aioquic client
and server. It exercises the draft-06 messages: the Role, Cost and Hop setup
parameters, ANNOUNCE_START, ANNOUNCE_UPDATE and ANNOUNCE_END, the Max Age and
Frame Start/End fields, and the exclusive SUBSCRIBE_END. The TLS secrets are
embedded in a Decryption Secrets Block so that the capture decrypts without a
keylog file.

Requires: pip install aioquic
Usage: generate-moq-lite-06-capture.py OUTPUT.pcapng.gz
"""

import argparse
import datetime
import gzip
import io
import struct

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import HandshakeCompleted
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ALPN = "moq-lite-06"
CLIENT = ("192.0.2.1", 50000)
SERVER = ("192.0.2.2", 4443)


# --- moq-lite encoding ---------------------------------------------------

def vi(value):
    """QUIC variable-length integer."""
    for length, prefix in ((1, 0x00), (2, 0x40), (4, 0x80), (8, 0xC0)):
        if value < 1 << (8 * length - 2):
            raw = bytearray(value.to_bytes(length, "big"))
            raw[0] |= prefix
            return bytes(raw)
    raise ValueError(value)


def s(text):
    data = text.encode()
    return vi(len(data)) + data


def u8(value):
    return bytes([value])


def msg(body):
    """A message: Length, then the body."""
    return vi(len(body)) + body


def typed(mtype, body):
    """A typed response message: Type, Length, then the body."""
    return vi(mtype) + msg(body)


def zigzag(value):
    return (value << 1) ^ (value >> 63) if value >= 0 else ((-value) << 1) - 1


def frame(delta, payload):
    return vi(zigzag(delta)) + vi(len(payload)) + payload


def setup(*params):
    out = vi(len(params))
    for pid, value in params:
        out += vi(pid) + vi(len(value)) + value
    return msg(out)


def hops(*ids):
    return vi(len(ids)) + b"".join(vi(i) for i in ids)


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


# --- The moq-lite session --------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    args = parser.parse_args()
    ses = Session()
    c, sv = ses.client, ses.server

    # Setup streams: Path may carry a query, Role/Cost/Hop are new in draft 06.
    c_setup = c.get_next_available_stream_id(is_unidirectional=True)
    ses.send(c, c_setup, vi(0x1) + setup((0x2, b"?room=demo"), (0x3, vi(2)), (0x4, vi(5)),
                                         (0x5, vi(7))))
    s_setup = sv.get_next_available_stream_id(is_unidirectional=True)
    ses.send(sv, s_setup, vi(0x1) + setup((0x2, b""), (0x3, vi(1)), (0x5, vi(9))))

    # Announce stream: ANNOUNCE_REQUEST has no Exclude Hop; typed responses.
    ann = c.get_next_available_stream_id()
    ses.send(c, ann, vi(0x1) + msg(s("live/")))
    ses.send(sv, ann, msg(vi(9) + vi(2)) +
             typed(0x0, s("demo") + hops(3, 4) + vi(10) + vi(20)) +
             typed(0x0, s("other") + hops() + vi(1) + vi(2)))
    ses.send(sv, ann, typed(0x2, vi(0) + hops(3, 3) + vi(11) + vi(21)) + typed(0x1, vi(1)))

    # Track stream: TRACK_INFO without Ordered, with Max Age.
    trk = c.get_next_available_stream_id()
    ses.send(c, trk, vi(0x6) + msg(s("live/demo") + s("video")))
    ses.send(sv, trk, msg(u8(1) + vi(5000) + vi(90000)))

    # Subscribe stream with the draft-06 delivery fields.
    sub = c.get_next_available_stream_id()
    ses.send(c, sub, vi(0x2) + msg(vi(0) + s("live/demo") + s("video") + u8(128) + vi(1000) +
                                   vi(0) + vi(6) + vi(0) + vi(0)))
    # A Frame End without a Group End is a protocol violation.
    ses.send(c, sub, msg(u8(64) + vi(2000) + vi(3) + vi(0) + vi(1) + vi(4)))
    ses.send(sv, sub, typed(0x0, vi(3)))

    # Group stream: GROUP gains Frame Start.
    grp = sv.get_next_available_stream_id(is_unidirectional=True)
    ses.send(sv, grp, vi(0x0) + msg(vi(0) + vi(3) + vi(2)) + frame(3000, b"frame-2") +
             frame(3000, b"frame-3"), end=True)
    ses.send(sv, sub, typed(0x1, vi(6)), end=True)

    # Fetch stream: FETCH gains Frame Start and Frame End.
    fet = c.get_next_available_stream_id()
    ses.send(c, fet, vi(0x3) + msg(s("live/demo") + s("video") + u8(10) + vi(3) + vi(1) + vi(3)),
             end=True)
    ses.send(sv, fet, frame(0, b"fetched-1") + frame(3000, b"fetched-2"), end=True)

    # Goaway stream.
    bye = sv.get_next_available_stream_id()
    ses.send(sv, bye, vi(0x5) + msg(s("moql://relay.example/other")), end=True)
    c.close(error_code=0)
    ses.flush()

    write_pcapng(args.output, ses.packets, ses.keylog.getvalue())
    print(f"{len(ses.packets)} packets")


if __name__ == "__main__":
    main()
