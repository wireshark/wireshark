# Wireshark tests for PackClient Core transport dissection
# Copyright 2026, Ivan Immanuel Shaji
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""PackClient Core transport tests."""

import ipaddress
import struct
import subprocess

import pytest


CLIENT_IP = "192.0.2.10"
SERVER_IP = "198.51.100.20"
CLIENT_PORT = 49152
SERVER_PORT = 59999
FRAME_PREFIX = 0x5A400000
TYPE_CORE_STRUCTURED = 0x03
TYPE_CORE_PV10 = 0x12
TYPE_PLAINTEXT = 0x15
TYPE_ENCRYPTED = 0x16
CIPHERTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")


def _frame_bytes(message_type, payload):
    body_length = 4 + len(payload)
    assert body_length <= 0x003FFFFF
    return struct.pack("<II", FRAME_PREFIX | body_length, message_type) + payload


def _hello():
    return struct.pack("<4sHHIIQII", b"PLH1", 1, 0x20, 0, 1,
                       0x0102030405060708, 4242, 0)


def _core_envelope(version=1, ciphertext=CIPHERTEXT, declared_length=None):
    if declared_length is None:
        declared_length = len(ciphertext)
    return (bytes([version]) + bytes(range(16))
            + struct.pack("<I", declared_length) + ciphertext + bytes(32))


def _pv10(jpeg=None, declared_length=None, magic=b"PV10"):
    if jpeg is None:
        jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + bytes(16) + b"\xff\xd9"
    if declared_length is None:
        declared_length = len(jpeg)
    return magic + struct.pack("<I", declared_length) + jpeg


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ethernet_ipv4_tcp(payload, sequence, identification):
    source, destination = (ipaddress.ip_address(ip).packed
                           for ip in (CLIENT_IP, SERVER_IP))
    total_length = 40 + len(payload)
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_length,
                       identification, 0x4000, 64, 6, 0, source, destination)
    ipv4 = ipv4[:10] + struct.pack("!H", _checksum(ipv4)) + ipv4[12:]
    tcp = struct.pack("!HHIIBBHHH", CLIENT_PORT, SERVER_PORT, sequence,
                      0, 5 << 4, 0x18, 8192, 0, 0)
    pseudo = source + destination + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", _checksum(pseudo + tcp + payload)) + tcp[18:]
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    return ethernet + ipv4 + tcp + payload


def _pcap(packets):
    output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for frame_number, packet in enumerate(packets):
        output.extend(struct.pack("<IIII", 1_700_000_000, frame_number,
                                  len(packet), len(packet)))
        output.extend(packet)
    return bytes(output)


def _capture(tmp_path, payloads):
    packets = []
    sequence = 1000
    for packet_number, payload in enumerate(payloads):
        packets.append(_ethernet_ipv4_tcp(payload, sequence, packet_number + 1))
        sequence += len(payload)
    path = tmp_path / "packclient-core.pcap"
    path.write_bytes(_pcap(packets))
    return str(path)


@pytest.fixture(params=[False, True], ids=["one-pass", "two-pass"])
def two_pass(request):
    return request.param


def _fields(cmd_tshark, capture, test_env, fields, *, two_pass=False,
            decode_as=True, display_filter="packclient", heuristic_first=True):
    args = [cmd_tshark, "-n", "-r", capture,
            "-o", "tcp.desegment_tcp_streams:TRUE",
            "-o", "ip.check_checksum:TRUE", "-o", "tcp.check_checksum:TRUE"]
    if two_pass:
        args.append("-2")
    if heuristic_first:
        args += ["-o", "tcp.try_heuristic_first:TRUE"]
    if decode_as:
        args += ["-d", f"tcp.port=={SERVER_PORT},packclient"]
    if display_filter is not None:
        args += ["-Y", display_filter]
    args += ["-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
             "-E", "aggregator=,"]
    for field in fields:
        args += ["-e", field]
    stdout = subprocess.check_output(args, encoding="utf-8", env=test_env, timeout=30)
    return [line.split("\t") for line in stdout.splitlines()]


class TestPackClientCore:
    def test_core_envelope_uses_little_endian_length(self, cmd_tshark, tmp_path,
                                                    test_env, two_pass):
        capture = _capture(tmp_path, [_frame_bytes(TYPE_ENCRYPTED, _core_envelope())])
        rows = _fields(cmd_tshark, capture, test_env, (
            "packclient.phase", "packclient.envelope.ciphertext_length",
            "packclient.envelope.format", "packclient.envelope.hmac",
        ), two_pass=two_pass)
        assert rows == [["Core", "16", "Core (little-endian length)", "00" * 32]]

    def test_core_command_and_pv10_fields(self, cmd_tshark, tmp_path, test_env, two_pass):
        command = b"INP|HELLO|uuid=synthetic|S1|iid="
        combined = _frame_bytes(TYPE_CORE_STRUCTURED, command)
        combined += _frame_bytes(TYPE_CORE_PV10, _pv10())
        capture = _capture(tmp_path, [combined])
        rows = _fields(cmd_tshark, capture, test_env, (
            "packclient.phase", "packclient.message_type", "packclient.core.command",
            "packclient.pv10.magic", "packclient.pv10.jpeg_length",
        ), two_pass=two_pass)
        assert len(rows) == 1
        assert rows[0][0].split(",") == ["Core", "Core"]
        assert rows[0][1].split(",") == ["0x00000003", "0x00000012"]
        assert rows[0][2] == command.decode()
        assert rows[0][3] == "PV10"
        assert rows[0][4] == str(len(_pv10()) - 8)

    def test_launcher_heuristic_carries_into_core(self, cmd_tshark, tmp_path,
                                                  test_env, two_pass):
        command = b"SYS|R|EXT|STARTUP|OK|tags="
        combined = _frame_bytes(TYPE_PLAINTEXT, _hello())
        combined += _frame_bytes(TYPE_CORE_STRUCTURED, command)
        combined += _frame_bytes(TYPE_CORE_PV10, _pv10())
        capture = _capture(tmp_path, [combined])
        rows = _fields(cmd_tshark, capture, test_env, (
            "packclient.object.magic", "packclient.core.command", "packclient.pv10.magic",
        ), two_pass=two_pass, decode_as=False)
        assert rows == [["PLH1", command.decode(), "PV10"]]

    def test_standalone_core_does_not_expand_heuristic(self, cmd_tshark, tmp_path,
                                                       test_env, two_pass):
        frame = _frame_bytes(TYPE_CORE_STRUCTURED, b"INP|HELLO|uuid=synthetic|S1|iid=")
        capture = _capture(tmp_path, [frame])
        assert _fields(cmd_tshark, capture, test_env, ("frame.number",),
                       two_pass=two_pass, decode_as=False) == []

    @pytest.mark.parametrize("payload,reason", [
        pytest.param(b"PV10", "shorter than 8 bytes", id="short"),
        pytest.param(_pv10(magic=b"NOPE"), "does not begin with PV10", id="magic"),
        pytest.param(_pv10(declared_length=1), "length does not match", id="length"),
        pytest.param(_pv10(jpeg=b"NO" + bytes(4) + b"\xff\xd9"),
                     "does not begin with a JPEG SOI", id="soi"),
        pytest.param(_pv10(jpeg=b"\xff\xd8" + bytes(6)),
                     "does not end with a JPEG EOI", id="eoi"),
    ])
    def test_malformed_pv10(self, cmd_tshark, tmp_path, test_env, two_pass,
                            payload, reason):
        capture = _capture(tmp_path, [_frame_bytes(TYPE_CORE_PV10, payload)])
        rows = _fields(cmd_tshark, capture, test_env,
                       ("packclient.pv10.jpeg", "_ws.expert.message"),
                       two_pass=two_pass)
        assert len(rows) == 1 and rows[0][0] == ""
        assert reason in rows[0][1]
