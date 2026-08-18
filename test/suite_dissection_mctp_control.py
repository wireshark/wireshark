#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
"""MCTP Control Protocol dissector tests.

Exercises the command-specific payload decode in
epan/dissectors/packet-mctp-control.c against a synthetic capture generated
by tools/gen-mctp-control-test-capture.py:

  mctp-control.pcapng  (27 frames)
    Request/response pairs for Set Endpoint ID (Set, Force, and a
    rejected-assignment response), Get Endpoint ID, Get Endpoint UUID,
    Get MCTP Version Support (four entries covering every DSP0236 12.7.2
    version-encoding rule), Get Message Type Support, Allocate Endpoint IDs
    (Allocate and Get-allocation-information operations), and the
    payload-less Endpoint Discovery / Discovery Notify commands.
    Adversarial fixtures: an error-completion-code response carrying stale
    payload bytes (must fall to mctpc.data, not be decoded as fields, per
    DSP0236 12.3), a truncated Set Endpoint ID response and a Get MCTP
    Version Support response whose entry count exceeds the data present
    (both must flag _ws.malformed without breaking later frames), a
    response with trailing bytes after a fully decoded payload (fields AND
    mctpc.data), and a version entry with a spec-illegal 0xFF major BCD
    byte (must raise the invalid_bcd expert warning).
"""

import subprocess
import xml.etree.ElementTree as ET

import pytest

CAPTURE = 'mctp-control.pcapng'


@pytest.fixture
def pdml_shownames(cmd_tshark, capture_file, test_env):
    """Return [showname, ...] for every occurrence of one field in a frame.

    -Tfields prints raw values only; the version-string rendering and the
    value_string labels under test are only visible in the PDML showname.
    """
    def run(frame, name):
        stdout = subprocess.check_output(
            [cmd_tshark, '-r', capture_file(CAPTURE),
             '-Y', f'frame.number == {frame}', '-Tpdml'],
            encoding='utf-8', env=test_env)
        return [f.get('showname') for f in ET.fromstring(stdout).iter('field')
                if f.get('name') == name]
    return run


class TestMctpControlPayloads:
    """Per-command payload field decode (DSP0236 1.3.3 clause 12)."""

    def test_set_endpoint_id(self, assert_frames_match):
        assert_frames_match(CAPTURE, [
            # Frame 1: Set op request for EID 0x42 (Table 14)
            (1, 'mctpc.set_eid.op == 0 && mctpc.set_eid.eid == 0x42' +
                ' && mctpc.rq == 1'),
            # Frame 2: accepted, endpoint requires EID pool allocation
            (2, 'mctpc.set_eid.status == 0 && mctpc.set_eid.alloc_status == 1' +
                ' && mctpc.set_eid.eid_setting == 0x42' +
                ' && mctpc.set_eid.pool_size == 4 && mctpc.rq == 0'),
            # Frame 3: Force EID op
            (3, 'mctpc.set_eid.op == 1 && mctpc.set_eid.eid == 0x43'),
            # Frame 4: accepted, no pool
            (4, 'mctpc.set_eid.status == 0 && mctpc.set_eid.alloc_status == 0' +
                ' && mctpc.set_eid.eid_setting == 0x43' +
                ' && mctpc.set_eid.pool_size == 0'),
            # Frame 6: assignment REJECTED ([5:4]=01b), already-received
            # allocation ([1:0]=10b); reserved sub-bits [7:6]/[3:2] itemized
            (6, 'mctpc.set_eid.status == 1 && mctpc.set_eid.alloc_status == 2' +
                ' && mctpc.set_eid.rsvd_hi == 0 && mctpc.set_eid.rsvd_lo == 0' +
                ' && mctpc.set_eid.eid_setting == 0x42' +
                ' && mctpc.set_eid.pool_size == 2'),
        ])

    def test_set_eid_rejected_label(self, pdml_shownames):
        labels = pdml_shownames(6, 'mctpc.set_eid.status')
        assert len(labels) == 1 and 'rejected' in labels[0]

    def test_get_endpoint_id(self, assert_frames_match):
        assert_frames_match(CAPTURE, [
            # Frame 7: empty request — no payload fields, no leftover data
            (7, 'mctpc.command == 2 && mctpc.rq == 1' +
                ' && !mctpc.get_eid.eid && !mctpc.data'),
            # Frame 8: EID 0x42, bus owner/bridge, static EID matches.
            # DSP0236 byte 3 is [7:6] reserved, [5:4] Endpoint Type,
            # [3:2] reserved, [1:0] Endpoint ID Type -- all four are rendered,
            # so the byte is fully accounted for and matches how Set Endpoint
            # ID reports its own two reserved runs.
            (8, 'mctpc.get_eid.eid == 0x42' +
                ' && mctpc.get_eid.rsvd_hi == 0' +
                ' && mctpc.get_eid.endpoint_type == 1' +
                ' && mctpc.get_eid.rsvd_lo == 0' +
                ' && mctpc.get_eid.eid_type == 2' +
                ' && mctpc.get_eid.medium_info == 0'),
        ])

    def test_get_endpoint_uuid(self, assert_frames_match):
        assert_frames_match(CAPTURE, [
            # Frame 9: empty request
            (9, 'mctpc.command == 3 && !mctpc.uuid && !mctpc.data'),
            # Frame 10: RFC4122 MSB-first UUID (Tables 16/17)
            (10, 'mctpc.uuid == 12345678-9abc-def0-1122-334455667788'),
        ])

    def test_get_version_support(self, assert_frames_match):
        assert_frames_match(CAPTURE, [
            # Frame 11: request for message type 0xFF (base spec)
            (11, 'mctpc.get_ver.msg_type == 0xff'),
            # Frame 12: 4 entries, raw values intact
            (12, 'mctpc.get_ver.count == 4'
                 ' && mctpc.get_ver.entry == 0xf1f0ff00' +
                 ' && mctpc.get_ver.entry == 0xf1f3f300' +
                 ' && mctpc.get_ver.entry == 0xf3f71061' +
                 ' && mctpc.get_ver.entry == 0x1011f700'),
        ])

    def test_version_bcd_rendering(self, pdml_shownames):
        """Every version-encoding rule of DSP0236 12.7.2: 0xFF update byte
        skipped, single- and two-digit BCD fields, trailing alpha byte."""
        entries = pdml_shownames(12, 'mctpc.get_ver.entry')
        assert entries == [
            'Version number entry: 1.0 (0xf1f0ff00)',
            'Version number entry: 1.3.3 (0xf1f3f300)',
            'Version number entry: 3.7.10a (0xf3f71061)',
            'Version number entry: 10.11.7 (0x1011f700)',
        ]

    def test_get_message_type_support(self, assert_frames_match):
        assert_frames_match(CAPTURE, [
            (13, 'mctpc.command == 5 && !mctpc.get_msg_types.count' +
                 ' && !mctpc.data'),
            (14, 'mctpc.get_msg_types.count == 4' +
                 ' && mctpc.get_msg_types.type == 0x00' +
                 ' && mctpc.get_msg_types.type == 0x04' +
                 ' && mctpc.get_msg_types.type == 0x05' +
                 ' && mctpc.get_msg_types.type == 0x7e'),
        ])

    def test_message_type_labels(self, pdml_shownames):
        """DSP0239 Table 1 names, in list order."""
        types = pdml_shownames(14, 'mctpc.get_msg_types.type')
        assert types == [
            'Message type: MCTP control protocol (0x00)',
            'Message type: NVMe-MI over MCTP (0x04)',
            'Message type: SPDM (0x05)',
            'Message type: Vendor Defined - PCI (0x7e)',
        ]

    def test_allocate_endpoint_ids(self, assert_frames_match):
        assert_frames_match(CAPTURE, [
            # Frames 15/16: Allocate EIDs op, 4 EIDs from 0x50, accepted
            (15, 'mctpc.alloc_eids.op == 0 && mctpc.alloc_eids.count == 4' +
                 ' && mctpc.alloc_eids.start == 0x50'),
            (16, 'mctpc.alloc_eids.status == 0' +
                 ' && mctpc.alloc_eids.pool_size == 4' +
                 ' && mctpc.alloc_eids.first == 0x50'),
            # Frames 17/18: Get allocation information op
            (17, 'mctpc.alloc_eids.op == 2'),
            (18, 'mctpc.alloc_eids.status == 0' +
                 ' && mctpc.alloc_eids.pool_size == 4' +
                 ' && mctpc.alloc_eids.first == 0x50'),
        ])

    def test_payloadless_commands(self, assert_frames_match):
        """Endpoint Discovery / Discovery Notify carry no payload either
        direction (Tables 29/30) — completion code only on responses."""
        assert_frames_match(CAPTURE, [
            (19, 'mctpc.command == 12 && mctpc.rq == 1 && !mctpc.data'),
            (20, 'mctpc.command == 12 && mctpc.cc == 0 && !mctpc.data'),
            (21, 'mctpc.command == 13 && mctpc.rq == 1 && !mctpc.data'),
            (22, 'mctpc.command == 13 && mctpc.cc == 0 && !mctpc.data'),
        ])


class TestMctpControlAdversarial:
    """Error-path and malformed-frame behavior."""

    def test_error_cc_suppresses_payload_decode(self, assert_frames_match):
        """Per DSP0236 12.3 a non-success completion code carries no
        parametric data; stale bytes must fall to mctpc.data, never be
        decoded as command fields."""
        assert_frames_match(CAPTURE, [
            (23, 'mctpc.cc == 0x05 && mctpc.data == 42:12:00' +
                 ' && !mctpc.get_eid.eid'),
        ])

    def test_malformed_frames_flagged(self, tshark_fields):
        """The truncated Set Endpoint ID response (24) and the
        over-claiming Get MCTP Version Support response (25) must raise a
        bounds exception — and nothing else in the capture may."""
        stdout = tshark_fields(CAPTURE, '_ws.malformed')
        assert sorted(int(x) for x in stdout.split()) == [24, 25]

    def test_truncated_response_keeps_decoded_prefix(self, assert_frames_match):
        """Frame 24 still decodes the header, CC, and the one payload byte
        present before the exception."""
        assert_frames_match(CAPTURE, [
            (24, 'mctpc.command == 1 && mctpc.cc == 0' +
                 ' && mctpc.set_eid.status == 1'),
        ])

    def test_overclaimed_count_stops_at_data_end(self, assert_frames_match):
        """Frame 25 claims 10 version entries with only one present: the
        single complete entry decodes, then the loop must terminate."""
        assert_frames_match(CAPTURE, [
            (25, 'mctpc.get_ver.count == 10' +
                 ' && mctpc.get_ver.entry == 0xf1f0ff00'),
        ])

    def test_trailing_bytes_after_payload(self, assert_frames_match):
        """Frame 26: fully decoded Get Endpoint ID payload plus 2 leftover
        bytes — both the fields and mctpc.data must be present.  Also
        proves frames after the malformed fixtures still dissect."""
        assert_frames_match(CAPTURE, [
            (26, 'mctpc.get_eid.eid == 0x42 && mctpc.data == de:ad'),
        ])

    def test_invalid_bcd_expert(self, tshark_fields):
        """Frame 27 carries a version entry with an illegal 0xFF major BCD
        byte (DSP0236 12.7.2 defines 0xFF only for the update byte): the
        invalid_bcd expert warning must fire there, and only there — the
        legal 0xFF update bytes in frames 12/25 must not trigger it."""
        stdout = tshark_fields(CAPTURE, 'mctpc.get_ver.entry.invalid_bcd')
        assert stdout.split() == ['27']
