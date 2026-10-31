#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate decryptable moq-lite + hang test captures with aioquic.

Usage: gen_hang_pcap.py OUTDIR

Writes OUTDIR/moq-hang.pcap and OUTDIR/moq-hang.keys, one QUIC session per
scenario, each on its own client port with broadcast room/dNN-lVV.hang.
Scenarios cover hang catalog layouts 00..03 over moq-lite-04 and moq-lite-05.
"""
import datetime
import json
import os
import struct
import sys
import zlib

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CLIENT = ("10.0.0.1", 50000)
SERVER = ("10.0.0.2", 4443)


def varint(v):
    if v < 0x40:
        return bytes([v])
    if v < 0x4000:
        return struct.pack(">H", 0x4000 | v)
    if v < 0x40000000:
        return struct.pack(">I", 0x80000000 | v)
    return struct.pack(">Q", 0xC000000000000000 | v)


def string(s):
    b = s.encode()
    return varint(len(b)) + b


def zigzag(v):
    return (v << 1) ^ (v >> 63)


# ---- pcap writing ---------------------------------------------------------

def ip_checksum(hdr):
    s = sum(struct.unpack("!10H", hdr))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


class Pcap:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.t = 1700000000.0

    def udp(self, src, dst, payload):
        udp = struct.pack("!HHHH", src[1], dst[1], 8 + len(payload), 0) + payload
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17, 0,
                         bytes(map(int, src[0].split("."))), bytes(map(int, dst[0].split("."))))
        ip = ip[:10] + struct.pack("!H", ip_checksum(ip)) + ip[12:]
        eth = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
        frame = eth + ip + udp
        self.t += 0.001
        sec = int(self.t)
        usec = int((self.t - sec) * 1e6)
        self.f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)

    def close(self):
        self.f.close()


# ---- QUIC plumbing ---------------------------------------------------------

def make_cert(tmpdir):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return cert, key


CLOCK = [0.0]


def pump(pcap, client, server, now):
    moved = True
    while moved:
        moved = False
        CLOCK[0] += 0.05
        now = CLOCK[0]
        for conn in (client, server):
            t = conn.get_timer()
            if t is not None and t <= now:
                conn.handle_timer(now=now)
        for conn, src, dst, peer in ((client, CLIENT, SERVER, server),
                                     (server, SERVER, CLIENT, client)):
            for data, _addr in conn.datagrams_to_send(now=now):
                pcap.udp(src, dst, data)
                peer.receive_datagram(data, src, now=now)
                moved = True


def deflate_group(frames):
    """One raw DEFLATE stream per group, sync flushed per frame, trailer stripped."""
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    out = []
    for f in frames:
        data = c.compress(f) + c.flush(zlib.Z_SYNC_FLUSH)
        assert data.endswith(b"\x00\x00\xff\xff")
        out.append(data[:-4])
    return out


# ---- scenarios -------------------------------------------------------------

def catalog(layout):
    if layout == 0:
        return {
            "video": [{"track": {"name": "video", "priority": 2},
                       "config": {"codec": "avc1.64001f", "codedWidth": 1280, "codedHeight": 720}}],
            "audio": [{"track": {"name": "audio", "priority": 1},
                       "config": {"codec": "opus", "sampleRate": 48000, "numberOfChannels": 2}}],
        }
    if layout == 1:
        return {
            "video": {"renditions": {"video": {"codec": "avc1.64001f", "codedWidth": 1280}},
                      "priority": 2},
            "audio": {"renditions": {"audio": {"codec": "opus", "sampleRate": 48000}},
                      "priority": 1},
        }
    cat = {
        "video": {"renditions": {
            "video": {"codec": "avc1.64001f", "container": {"kind": "legacy"}, "codedWidth": 1280},
            "video.cmaf": {"codec": "avc1.64001f", "container": {"kind": "cmaf", "init": ""}},
        }},
        "audio": {"renditions": {
            "audio": {"codec": "opus", "container": {"kind": "legacy"}, "sampleRate": 48000},
        }},
    }
    if layout == 3:
        cat["text"] = {"renditions": {"captions.en": {"format": "vtt", "role": "caption",
                                                      "lang": "en", "container": {"kind": "legacy"}}}}
        cat["json"] = {"tracks": {"chat.json": {"mode": "snapshot", "compression": "deflate"}}}
        cat["clock"] = {"wall": 213000000000000}
        cat["archive"] = {"track": "timeline.z", "timescale": 1000}
    return cat


def run(name, alpn, layout, outdir, pcap, keylog, port):
    global CLIENT
    CLIENT = ("10.0.0.1", port)
    v5 = alpn == "moq-lite-05"
    cert, key = make_cert(outdir)
    ccfg = QuicConfiguration(is_client=True, alpn_protocols=[alpn], secrets_log_file=keylog,
                             server_name="localhost", max_datagram_frame_size=1500)
    import ssl
    ccfg.verify_mode = ssl.CERT_NONE
    scfg = QuicConfiguration(is_client=False, alpn_protocols=[alpn], max_datagram_frame_size=1500)
    scfg.certificate = cert
    scfg.private_key = key

    now = 0.0
    client = QuicConnection(configuration=ccfg)
    server = QuicConnection(configuration=scfg, original_destination_connection_id=client.original_destination_connection_id)
    client.connect(SERVER, now=now)
    pump(pcap, client, server, now)

    path = "room/%s.hang" % name
    tracks = ["catalog.json", "video", "audio"]
    if layout >= 2:
        tracks.append("video.cmaf")
    if layout == 3:
        tracks += ["captions.en", "chat.json", "timeline.z", "catalog.json.z"]

    # Subscriber: one Subscribe stream per track.
    for sub_id, track in enumerate(tracks):
        sid = client.get_next_available_stream_id(is_unidirectional=False)
        body = varint(sub_id) + string(path) + string(track) + b"\x00"
        if alpn != "moq-lite-02":
            body += b"\x00" + varint(0) + varint(0) + varint(0)
        client.send_stream_data(sid, varint(2) + varint(len(body)) + body)
        pump(pcap, client, server, now)

    def frame(ts_delta, payload):
        hdr = varint(zigzag(ts_delta)) if v5 else b""
        return hdr + varint(len(payload)) + payload

    def group(sub_id, seq, frames, fin=True):
        sid = server.get_next_available_stream_id(is_unidirectional=True)
        data = varint(0) + varint(1 + len(varint(sub_id)) + len(varint(seq)) - 1)
        hdr = varint(sub_id) + varint(seq)
        data = varint(0) + varint(len(hdr)) + hdr + b"".join(frames)
        server.send_stream_data(sid, data, end_stream=fin)
        pump(pcap, client, server, now)

    def legacy(ts_us, payload):
        return varint(ts_us) + payload

    cat = json.dumps(catalog(layout)).encode()
    ids = {t: i for i, t in enumerate(tracks)}
    group(ids["catalog.json"], 0, [frame(0, cat)])

    # Video: keyframe + delta + empty end-of-frame marker.
    idr = b"\x00\x00\x00\x01\x65" + b"\x88" * 40
    p = b"\x00\x00\x00\x01\x41" + b"\x9a" * 20
    group(ids["video"], 0, [frame(0, legacy(0, idr)), frame(33, legacy(33333, p)),
                            frame(33, legacy(66666, b""))])
    # Audio: two Opus packets (TOC 0xfc: CELT FB 20 ms, code 0).
    group(ids["audio"], 0, [frame(0, legacy(0, b"\xfc" + b"\x11" * 30)),
                            frame(20, legacy(20000, b"\xfc" + b"\x22" * 30))])
    if layout >= 2:
        moof = struct.pack(">I", 16) + b"moof" + struct.pack(">I", 8) + b"mfhd"
        mdat = struct.pack(">I", 12) + b"mdat" + b"\x01\x02\x03\x04"
        group(ids["video.cmaf"], 0, [frame(0, moof + mdat)])
    if layout == 3:
        cue = b"WEBVTT\n\n00:00.000 --> 00:01.000\nHello hang\n"
        group(ids["captions.en"], 0, [frame(0, legacy(0, cue))])
        chat = deflate_group([b'{"messages":["hi"]}', b'{"messages":["hi","there"]}'])
        group(ids["chat.json"], 0, [frame(0, chat[0]), frame(0, chat[1])])
        tl = deflate_group([json.dumps({"offset": 0, "records": [
            {"segment": 0, "pts": 0, "duration": 2000,
             "tracks": {"video": [{"start": 0, "end": 0}]}}]}).encode(),
            json.dumps({"push": {"segment": 1, "pts": 2000, "duration": 2000}}).encode(),
            json.dumps({"pop": 1}).encode()])
        group(ids["timeline.z"], 0, [frame(0, f) for f in tl])
        catz = deflate_group([cat])
        group(ids["catalog.json.z"], 0, [frame(0, catz[0])])

    client.close()
    pump(pcap, client, server, now)


if __name__ == "__main__":
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    pcap = Pcap(os.path.join(out, "moq-hang.pcap"))
    keylog = open(os.path.join(out, "moq-hang.keys"), "w")
    port = 50000
    for layout in range(4):
        for alpn in ("moq-lite-04", "moq-lite-05"):
            run("d%02d-l%s" % (layout, alpn[-2:]), alpn, layout, out, pcap, keylog, port)
            port += 1
    pcap.close()
    keylog.close()
    print("ok")
