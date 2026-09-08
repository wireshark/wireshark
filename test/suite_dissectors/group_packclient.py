# Wireshark tests for the PackClient launcher transport dissector
# Copyright 2026, Ivan Immanuel Shaji
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""PackClient launcher transport tests."""

import hashlib
import ipaddress
import struct
import subprocess

import pytest


CLIENT_IP = "192.0.2.10"
SERVER_IP = "198.51.100.20"
CLIENT_PORT = 49152
SERVER_PORT = 59999
FRAME_PREFIX = 0x5A400000
TYPE_PLAINTEXT = 0x15
TYPE_ENCRYPTED = 0x16
MAX_OBJECT_SIZE = 0x08000000
VECTOR = b"passive-synthetic-vector"
DIGEST = hashlib.sha256(VECTOR).digest()
CIPHERTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")


def _frame_bytes(message_type, payload):
    body_length = 4 + len(payload)
    assert body_length <= 0x003FFFFF
    return struct.pack("<II", FRAME_PREFIX | body_length, message_type) + payload


def _hello():
    return struct.pack("<4sHHIIQII", b"PLH1", 1, 0x20, 0, 1,
                       0x0102030405060708, 4242, 0)


def _challenge():
    return struct.pack("<4sHH16s", b"PLC1", 1, 0xBEEF, bytes(range(16)))


def _authentication():
    return struct.pack("<4sHH32s", b"PLA1", 1, 0, bytes(range(32)))


def _plk1_header(version=1, total_size=24, original_size=24, lz4_flag=0):
    return struct.pack("<4sHBBQQ32s", b"PLK1", version, lz4_flag, 0,
                       total_size, original_size, DIGEST)


def _envelope(version=1, ciphertext=CIPHERTEXT, declared_length=None):
    if declared_length is None:
        declared_length = len(ciphertext)
    return (bytes([version]) + bytes(range(16))
            + struct.pack(">I", declared_length) + ciphertext + bytes(32))


def _changed(payload, offset, fmt, value):
    output = bytearray(payload)
    struct.pack_into(fmt, output, offset, value)
    return bytes(output)


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ethernet_ipv4_tcp(payload, sequence, identification, *,
                       server_port=SERVER_PORT, from_server=False,
                       acknowledgment=0, flags=0x18):
    source, destination = (ipaddress.ip_address(ip).packed
                           for ip in (CLIENT_IP, SERVER_IP))
    source_port, destination_port = CLIENT_PORT, server_port
    if from_server:
        source, destination = destination, source
        source_port, destination_port = destination_port, source_port
    total_length = 40 + len(payload)
    assert total_length <= 65535
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length,
                       identification, 0x4000, 64, 6, 0, source, destination)
    ipv4 = ipv4[:10] + struct.pack("!H", _checksum(ipv4)) + ipv4[12:]
    tcp = struct.pack("!HHIIBBHHH", source_port, destination_port, sequence,
                      acknowledgment, 5 << 4, flags, 8192, 0, 0)
    pseudo = source + destination + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", _checksum(pseudo + tcp + payload)) + tcp[18:]
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    return ethernet + ipv4 + tcp + payload


def _pcap(packets, captured_lengths=None):
    output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, packet in enumerate(packets):
        captured = len(packet) if captured_lengths is None else captured_lengths[index]
        assert 0 <= captured <= len(packet)
        output.extend(struct.pack("<IIII", 1_700_000_000, index,
                                  captured, len(packet)))
        output.extend(packet[:captured])
    return bytes(output)


def _capture(tmp_path, payloads, *, server_port=SERVER_PORT, captured_lengths=None):
    packets = []
    sequence = 1000
    for index, payload in enumerate(payloads):
        packets.append(_ethernet_ipv4_tcp(payload, sequence, index + 1,
                                         server_port=server_port))
        sequence += len(payload)
    path = tmp_path / "packclient.pcap"
    path.write_bytes(_pcap(packets, captured_lengths))
    return str(path)


@pytest.fixture(params=[False, True], ids=["one-pass", "two-pass"])
def two_pass(request):
    return request.param


def _fields(cmd_tshark, capture, test_env, fields, *, two_pass=False,
            decode_as=True, server_port=SERVER_PORT, display_filter="packclient",
            heuristic_first=True, desegment=True):
    args = [cmd_tshark, "-n", "-r", capture,
            "-o", f"tcp.desegment_tcp_streams:{str(desegment).upper()}",
            "-o", "ip.check_checksum:TRUE", "-o", "tcp.check_checksum:TRUE"]
    if two_pass:
        args.append("-2")
    if heuristic_first:
        args += ["-o", "tcp.try_heuristic_first:TRUE"]
    if decode_as:
        args += ["-d", f"tcp.port=={server_port},packclient"]
    if display_filter is not None:
        args += ["-Y", display_filter]
    args += ["-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
             "-E", "aggregator=,"]
    for field in fields:
        args += ["-e", field]
    stdout = subprocess.check_output(args, encoding="utf-8", env=test_env, timeout=30)
    return [line.split("\t") for line in stdout.splitlines()]


BAD_OBJECTS = [
    pytest.param(_changed(_hello(), 4, "<H", 2), "PLH1 fixed field", id="hello-version"),
    pytest.param(_changed(_hello(), 6, "<H", 0), "PLH1 fixed field", id="hello-field06"),
    pytest.param(_changed(_hello(), 8, "<I", 1), "PLH1 fixed field", id="hello-field08"),
    pytest.param(_changed(_hello(), 12, "<I", 0), "PLH1 fixed field", id="hello-field0c"),
    pytest.param(_changed(_hello(), 28, "<I", 1), "PLH1 fixed field", id="hello-reserved"),
    pytest.param(_changed(_challenge(), 4, "<H", 2), "PLC1 version", id="challenge-version"),
    pytest.param(_changed(_authentication(), 4, "<H", 2), "PLA1 fixed field", id="auth-version"),
    pytest.param(_changed(_authentication(), 6, "<H", 1), "PLA1 fixed field", id="auth-reserved"),
    pytest.param(_hello()[:-1], "invalid payload length", id="short-object"),
    pytest.param(_hello() + b"\x00", "invalid payload length", id="long-object"),
    pytest.param(_plk1_header(version=0), "wire version", id="plk-version0"),
    pytest.param(_plk1_header(version=3), "wire version", id="plk-version3"),
    pytest.param(_plk1_header(total_size=0), "total size", id="plk-total0"),
    pytest.param(_plk1_header(total_size=MAX_OBJECT_SIZE + 1), "total size", id="plk-total-over"),
    pytest.param(_plk1_header(total_size=2**64 - 1), "total size", id="plk-total-u64"),
    pytest.param(_plk1_header(version=2, original_size=0), "original size", id="plk-orig0"),
    pytest.param(_plk1_header(version=2, original_size=MAX_OBJECT_SIZE + 1),
                 "original size", id="plk-orig-over"),
    pytest.param(_plk1_header(version=2, original_size=2**64 - 1),
                 "original size", id="plk-orig-u64"),
]

BAD_ENVELOPES = [
    pytest.param(bytes(52), "shorter than", id="short"),
    pytest.param(_envelope(version=2), "version must be 1", id="version"),
    pytest.param(_envelope(ciphertext=b""), "ciphertext is empty", id="empty"),
    pytest.param(_envelope(ciphertext=bytes(15)), "not AES block-aligned", id="alignment"),
    pytest.param(_envelope(declared_length=32), "does not match", id="length"),
    pytest.param(_envelope(declared_length=0xFFFFFFFF), "does not match", id="length-u32"),
]

NEGATIVE_CANDIDATES = [
    pytest.param(_frame_bytes(0xFF, _hello()), id="unsupported-type"),
    pytest.param(_frame_bytes(TYPE_PLAINTEXT, b"NOPE" + bytes(28)), id="magic-collision"),
    pytest.param(_frame_bytes(TYPE_PLAINTEXT, _changed(_hello(), 4, "<H", 2)),
                 id="invalid-hello"),
    pytest.param(_frame_bytes(TYPE_PLAINTEXT, _plk1_header(total_size=0)), id="invalid-plk"),
    pytest.param(_frame_bytes(TYPE_ENCRYPTED, _envelope(version=2)), id="envelope-version"),
    pytest.param(_frame_bytes(TYPE_ENCRYPTED, _envelope(ciphertext=b"")), id="envelope-empty"),
    pytest.param(_frame_bytes(TYPE_ENCRYPTED, _envelope(ciphertext=bytes(15))),
                 id="envelope-alignment"),
    pytest.param(_frame_bytes(TYPE_ENCRYPTED, _envelope(declared_length=0xFFFFFFFF)),
                 id="envelope-length"),
]


class TestPackClient:
    def test_capture_generator(self):
        payload = _frame_bytes(TYPE_PLAINTEXT, _hello())
        packet = _ethernet_ipv4_tcp(payload, 1000, 1)
        capture = _pcap([packet])
        assert capture == _pcap([packet])
        assert struct.unpack_from("<IHHIIII", capture) == (0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        assert struct.unpack_from("<IIII", capture, 24) == (1_700_000_000, 0, len(packet), len(packet))
        assert capture[40:] == packet
        assert _checksum(packet[14:34]) == 0
        pseudo = packet[26:34] + struct.pack("!BBH", 0, 6, len(packet) - 34)
        assert _checksum(pseudo + packet[34:]) == 0

    def test_combined_objects_fields_and_summary(self, cmd_tshark, tmp_path, test_env, two_pass):
        objects = [_hello(), _challenge(), _authentication(), _plk1_header()]
        combined = b"".join(_frame_bytes(TYPE_PLAINTEXT, obj) for obj in objects)
        combined += _frame_bytes(TYPE_ENCRYPTED, _envelope())
        capture = _capture(tmp_path, [combined])
        rows = _fields(cmd_tshark, capture, test_env, (
            "packclient.object.magic", "packclient.message_type", "packclient.body_length",
            "packclient.plh1.tick_count", "packclient.plh1.process_id", "packclient.plc1.field_06",
            "packclient.plc1.challenge", "packclient.pla1.authenticator", "_ws.col.Info",
        ), two_pass=two_pass)
        assert len(rows) == 1
        assert rows[0][:8] == [
            "PLH1,PLC1,PLA1,PLK1", ",".join(["0x00000015"] * 4 + ["0x00000016"]),
            "36,28,44,60,73", str(0x0102030405060708), "4242", "0xbeef",
            bytes(range(16)).hex(), bytes(range(32)).hex(),
        ]
        assert rows[0][8] == (
            "Plaintext PLH1, Plaintext PLC1, Plaintext PLA1, Plaintext PLK1, "
            "Encrypted envelope (authentication not verified) type 0x16 metadata"
        )

    @pytest.mark.parametrize("message_type,payload,magic", [
        (TYPE_PLAINTEXT, _hello(), "PLH1"), (TYPE_PLAINTEXT, _challenge(), "PLC1"),
        (TYPE_PLAINTEXT, _authentication(), "PLA1"), (TYPE_PLAINTEXT, _plk1_header(), "PLK1"),
        (TYPE_ENCRYPTED, _envelope(), ""),
    ])
    def test_complete_heuristic(self, cmd_tshark, tmp_path, test_env, two_pass,
                                message_type, payload, magic):
        capture = _capture(tmp_path, [_frame_bytes(message_type, payload)])
        rows = _fields(cmd_tshark, capture, test_env,
                       ("_ws.col.Protocol", "packclient.object.magic"),
                       two_pass=two_pass, decode_as=False, heuristic_first=False)
        assert rows == [["PACKCLIENT", magic]]

    @pytest.mark.parametrize("version,total,original,flag", [
        (1, 1, 0, 0), (1, MAX_OBJECT_SIZE, 2**64 - 1, 255),
        (2, 1, 1, 0), (2, MAX_OBJECT_SIZE, MAX_OBJECT_SIZE, 1), (2, 24, 48, 255),
    ])
    def test_plk1_boundaries(self, cmd_tshark, tmp_path, test_env, two_pass,
                            version, total, original, flag):
        capture = _capture(tmp_path, [_frame_bytes(
            TYPE_PLAINTEXT, _plk1_header(version, total, original, flag))])
        rows = _fields(cmd_tshark, capture, test_env, (
            "packclient.object.magic", "packclient.plk1.wire_version", "packclient.plk1.lz4_flag",
            "packclient.plk1.total_size", "packclient.plk1.original_size",
            "packclient.plk1.expected_sha256",
        ), two_pass=two_pass, decode_as=False)
        assert rows == [["PLK1", str(version), f"0x{flag:02x}", str(total), str(original), DIGEST.hex()]]

    def test_envelope_metadata_only(self, cmd_tshark, tmp_path, test_env, two_pass):
        capture = _capture(tmp_path, [_frame_bytes(TYPE_ENCRYPTED, _envelope())])
        rows = _fields(cmd_tshark, capture, test_env, (
            "packclient.envelope.version", "packclient.envelope.iv",
            "packclient.envelope.ciphertext_length", "packclient.envelope.hmac",
            "packclient.object.magic", "_ws.col.Info",
        ), two_pass=two_pass)
        assert len(rows) == 1
        assert rows[0][:5] == ["1", bytes(range(16)).hex(), "16", "00" * 32, ""]
        assert "authentication not verified" in rows[0][5]

    @pytest.mark.parametrize("split", [1, 2, 4, 5, 8, 12, 14, 24, 39])
    def test_initial_split_requires_decode_as(self, cmd_tshark, tmp_path, test_env, two_pass, split):
        hello = _frame_bytes(TYPE_PLAINTEXT, _hello())
        capture = _capture(tmp_path, [hello[:split], hello[split:]])
        fields = ("packclient.object.magic",)
        assert _fields(cmd_tshark, capture, test_env, fields,
                       two_pass=two_pass, decode_as=False) == []
        assert _fields(cmd_tshark, capture, test_env, fields,
                       two_pass=two_pass) == [["PLH1"]]

    @pytest.mark.parametrize("split", [1, 2, 4, 8, 14, 47])
    def test_identified_stream_reassembles_later_pdu(self, cmd_tshark, tmp_path, test_env,
                                                    two_pass, split):
        hello = _frame_bytes(TYPE_PLAINTEXT, _hello())
        auth = _frame_bytes(TYPE_PLAINTEXT, _authentication())
        capture = _capture(tmp_path, [hello, auth[:split], auth[split:]])
        rows = _fields(cmd_tshark, capture, test_env, ("packclient.object.magic",),
                       two_pass=two_pass, decode_as=False)
        assert rows == [["PLH1"], ["PLA1"]]

    @pytest.mark.parametrize("candidate", NEGATIVE_CANDIDATES)
    @pytest.mark.parametrize("split", [None, 4, 5, 8, 14, 29])
    def test_invalid_candidate_does_not_claim_conversation(self, cmd_tshark, tmp_path,
                                                          test_env, two_pass, candidate, split):
        payloads = [candidate] if split is None else [candidate[:split], candidate[split:]]
        # Not independently identifiable; this catches accidental conversation assignment.
        payloads.append(_frame_bytes(TYPE_PLAINTEXT, b""))
        capture = _capture(tmp_path, payloads)
        assert _fields(cmd_tshark, capture, test_env, ("frame.number",),
                       two_pass=two_pass, decode_as=False) == []

    @pytest.mark.parametrize("payload,reason", BAD_OBJECTS)
    def test_malformed_objects(self, cmd_tshark, tmp_path, test_env, two_pass, payload, reason):
        capture = _capture(tmp_path, [_frame_bytes(TYPE_PLAINTEXT, payload)])
        rows = _fields(cmd_tshark, capture, test_env,
                       ("packclient.object.magic", "_ws.expert.message"), two_pass=two_pass)
        assert len(rows) == 1 and rows[0][0] == ""
        assert reason in rows[0][1]
        assert _fields(cmd_tshark, capture, test_env, ("frame.number",),
                       two_pass=two_pass, decode_as=False) == []

    @pytest.mark.parametrize("payload,reason", BAD_ENVELOPES)
    def test_malformed_envelopes(self, cmd_tshark, tmp_path, test_env, two_pass, payload, reason):
        capture = _capture(tmp_path, [_frame_bytes(TYPE_ENCRYPTED, payload)])
        rows = _fields(cmd_tshark, capture, test_env,
                       ("packclient.envelope.hmac", "_ws.expert.message", "_ws.col.Info"),
                       two_pass=two_pass)
        assert len(rows) == 1 and rows[0][0] == ""
        assert reason in rows[0][1]
        assert "type 0x16 metadata" not in rows[0][2]
        assert _fields(cmd_tshark, capture, test_env, ("frame.number",),
                       two_pass=two_pass, decode_as=False) == []

    @pytest.mark.parametrize("body_length", [0, 1, 2, 3])
    def test_short_framing(self, cmd_tshark, tmp_path, test_env, two_pass, body_length):
        frame = struct.pack("<I", FRAME_PREFIX | body_length) + bytes(body_length)
        capture = _capture(tmp_path, [frame])
        rows = _fields(cmd_tshark, capture, test_env,
                       ("packclient.message_type", "_ws.expert.message"), two_pass=two_pass)
        assert len(rows) == 1 and rows[0][0] == ""
        assert "Malformed PackClient framing" in rows[0][1]
        assert _fields(cmd_tshark, capture, test_env, ("frame.number",),
                       two_pass=two_pass, decode_as=False) == []

    def test_invalid_prefix(self, cmd_tshark, tmp_path, test_env, two_pass):
        capture = _capture(tmp_path, [b"\xff" * 4])
        rows = _fields(cmd_tshark, capture, test_env,
                       ("_ws.expert.message",), two_pass=two_pass)
        assert len(rows) == 1 and "Malformed PackClient framing" in rows[0][0]

    @pytest.mark.parametrize("cut", [0, 1, 2, 4, 8, 14, 29, 39])
    @pytest.mark.parametrize("message_type,payload", [
        (TYPE_PLAINTEXT, _hello()), (TYPE_ENCRYPTED, _envelope()),
    ])
    def test_snaplen_truncation(self, cmd_tshark, tmp_path, test_env, two_pass,
                                cut, message_type, payload):
        frame = _frame_bytes(message_type, payload)
        capture = _capture(tmp_path, [frame], captured_lengths=[54 + cut])
        rows = _fields(cmd_tshark, capture, test_env,
                       ("packclient.object.magic", "packclient.envelope.hmac"),
                       two_pass=two_pass, display_filter=None)
        assert rows == [["", ""]]

    @pytest.mark.parametrize("server_port,payload", [
        (443, bytes.fromhex("15030300020100")),
        (80, b"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n"),
    ])
    def test_unrelated_traffic(self, cmd_tshark, tmp_path, test_env, two_pass, server_port, payload):
        capture = _capture(tmp_path, [payload], server_port=server_port)
        assert _fields(cmd_tshark, capture, test_env, ("frame.number",),
                       two_pass=two_pass, decode_as=False) == []

    def test_bidirectional_exchange(self, cmd_tshark, tmp_path, test_env, two_pass):
        packets = []
        sequences = {False: 1000, True: 9000}
        # Complete TCP handshake.
        for from_server, seq, ack, flags in [
            (False, 999, 0, 0x02), (True, 8999, 1000, 0x12), (False, 1000, 9000, 0x10),
        ]:
            packets.append(_ethernet_ipv4_tcp(b"", seq, len(packets) + 1,
                           from_server=from_server, acknowledgment=ack, flags=flags))
        challenge = _frame_bytes(TYPE_PLAINTEXT, _challenge())
        exchange = [
            (False, _frame_bytes(TYPE_PLAINTEXT, _hello())),
            (True, challenge[:4]), (True, challenge[4:]),
            (False, _frame_bytes(TYPE_PLAINTEXT, _authentication())),
            (True, _frame_bytes(TYPE_PLAINTEXT, _plk1_header())),
            (True, _frame_bytes(TYPE_ENCRYPTED, _envelope())),
        ]
        for from_server, payload in exchange:
            packets.append(_ethernet_ipv4_tcp(payload, sequences[from_server], len(packets) + 1,
                           from_server=from_server, acknowledgment=sequences[not from_server]))
            sequences[from_server] += len(payload)
        path = tmp_path / "exchange.pcap"
        path.write_bytes(_pcap(packets))
        rows = _fields(cmd_tshark, str(path), test_env,
                       ("ip.src", "packclient.object.magic", "packclient.envelope.version"),
                       two_pass=two_pass, decode_as=False,
                       display_filter="packclient.object.magic || packclient.envelope.version")
        assert rows == [[CLIENT_IP, "PLH1", ""], [SERVER_IP, "PLC1", ""],
                        [CLIENT_IP, "PLA1", ""], [SERVER_IP, "PLK1", ""], [SERVER_IP, "", "1"]]
