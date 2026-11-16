#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
"""MCTP Control Protocol (packet-mctp-control.c) tests, DSP0236 1.3.3 clauses
11-12 and DSP0239.

Capture: mctp-control.pcapng (tools/gen-mctp-control-test-capture.py; the
generator holds the frame maps).  F1-F53 are the base map; the three later
pcapng sections (PAYLOADS, CONFORMANCE, LENGTHS, PAIRING below) number their frames
from 1 in their maps, and the classes that read them use those numbers.  Each class
reads its fields from one cached decode (dissect_pdml / fields_table).

assert_frames_match ORs its cases, so each frame appears once per call with
its conditions AND'd together.
"""

import re
import subprocess
from collections import Counter
from typing import ClassVar

import pytest
from dissection_helpers import column, frame_in, frames_in, pdml_section, section

CAPTURE = 'mctp-control.pcapng'
CAPTURES = (CAPTURE,)
# The sections after F1-F53, as (first, last) frame numbers.
PAYLOADS = (54, 96)
CONFORMANCE = (97, 104)
LENGTHS = (105, 310)
PAIRING = (311, 346)
SMBUS_PAIRING = (347, 359)
EID_RANGES = (360, 377)
SIZE = (378, 378)
GET_VERSION = (379, 389)
RESPONSE_VALUES = (390, 407)

# A response with no matching request earlier in the capture gets a note
# (DSP0236 Table 10).  Most generated responses stand alone, so the tests
# that census other experts set it aside, and the pairing tests pin it.
UNMATCHED = 'mctpc.response.unmatched'
UNMATCHED_TEXT = 'No request with this source, tag, Instance ID and command was seen'
OTHER_EXPERTS = f'count(_ws.expert) > count({UNMATCHED})'


def other_experts(node):
    """The PDML expert items under node, less the unmatched-response note."""
    return [e for e in node.findall(".//field[@name='_ws.expert']")
            if e.find(f"./field[@name='{UNMATCHED}']") is None]


def other_messages(node):
    return [e.find("./field[@name='_ws.expert.message']") for e in other_experts(node)]


def other_expert_text(value):
    """A -T fields expert column, less the unmatched-response note."""
    parts = re.split(r',(?=Expert Info \()|,(?=Malformed Packet)', value) if value else []
    return ','.join(p for p in parts if UNMATCHED_TEXT not in p)


@pytest.mark.parametrize('capture', CAPTURES)
def test_no_dissector_exceptions(tshark_fields, capture):
    """Short payloads raise the normal tvb exceptions (asserted per
    section); nothing trips a dissector bug."""
    assert tshark_fields(capture, '_ws.dissector_bug').strip() == ''


@pytest.mark.parametrize('capture', CAPTURES)
def test_second_pass_matches_first(assert_pass_parity, capture):
    assert_pass_parity(capture)


def test_registration(cmd_tshark, test_env):
    """The dissector is registered under its name."""
    output = subprocess.check_output([cmd_tshark, '-G', 'dissectors'],
                                     encoding='utf-8', env=test_env)
    assert any('mctp-control' in line and 'MCTP Control Protocol' in line
               for line in output.splitlines())


class TestMctpControlCommands:
    """Request/response pairs for the DSP0236 clause 12 commands."""

    FIELDS = ('mctpc', 'mctpc.get_msg_types.type', 'mctp.rsvd', '_ws.expert',
              '_ws.expert.message', '_ws.col.info', 'mctpc.get_ver.entry.invalid_bcd')

    def test_command_payloads(self, assert_frames_match):
        """DSP0236 Tables 14-30: each command's fields, its reserved runs
        (5.3) beside the enums they share a byte with, and nothing left over
        as mctpc.data on a fully decoded payload."""
        assert_frames_match(CAPTURE, [
            (1, 'mctpc.set_eid.op == 0 && mctpc.set_eid.eid == 0x42 && mctpc.rq == 1'),
            (2, ('mctpc.set_eid.status == 0 && mctpc.set_eid.alloc_status == 1'
                 ' && mctpc.set_eid.eid_setting == 0x42 && mctpc.set_eid.pool_size == 4'
                 ' && mctpc.rq == 0')),
            (3, 'mctpc.set_eid.op == 1 && mctpc.set_eid.eid == 0x43'),
            (4, ('mctpc.set_eid.status == 0 && mctpc.set_eid.alloc_status == 0'
                 ' && mctpc.set_eid.eid_setting == 0x43 && mctpc.set_eid.pool_size == 0')),
            (6, ('mctpc.set_eid.status == 1 && mctpc.set_eid.alloc_status == 2'
                 ' && mctpc.set_eid.rsvd_hi == 0 && mctpc.set_eid.rsvd_lo == 0'
                 ' && mctpc.set_eid.eid_setting == 0x42 && mctpc.set_eid.pool_size == 2')),
            (7, 'mctpc.command == 2 && mctpc.rq == 1 && !mctpc.get_eid.eid && !mctpc.data'),
            # Table 15 byte 4 is shown, but Table 4's SMBus bits need an SMBus
            # ingress, which this SLL capture is not.
            (8, ('mctpc.get_eid.eid == 0x42 && mctpc.get_eid.rsvd_hi == 0'
                 ' && mctpc.get_eid.endpoint_type == 1 && mctpc.get_eid.rsvd_lo == 0'
                 ' && mctpc.get_eid.eid_type == 2 && mctpc.get_eid.medium_info == 0'
                 ' && !mctpc.get_eid.medium_info.fairness'
                 ' && !mctpc.get_eid.medium_info.rsvd')),
            (9, 'mctpc.command == 3 && !mctpc.uuid && !mctpc.data'),
            (10, 'mctpc.uuid == 12345678-9abc-def0-1122-334455667788'),
            (11, 'mctpc.get_ver.msg_type == 0xff'),
            (12, ('mctpc.get_ver.count == 4 && mctpc.get_ver.entry == 0xf1f0ff00'
                  ' && mctpc.get_ver.entry == 0xf1f3f300'
                  ' && mctpc.get_ver.entry == 0xf3f71061'
                  ' && mctpc.get_ver.entry == 0x1011f700')),
            (13, 'mctpc.command == 5 && !mctpc.get_msg_types.count && !mctpc.data'),
            (14, ('mctpc.get_msg_types.count == 3 && !mctpc.excess && !_ws.malformed'
                  ' && mctpc.get_msg_types.type == 0x04 && mctpc.get_msg_types.type == 0x05'
                  ' && mctpc.get_msg_types.type == 0x7e')),
            (15, ('mctpc.alloc_eids.op == 0 && mctpc.alloc_eids.count == 4'
                  ' && mctpc.alloc_eids.start == 0x50')),
            (16, ('mctpc.alloc_eids.status == 0 && mctpc.alloc_eids.pool_size == 4'
                  ' && mctpc.alloc_eids.first == 0x50')),
            (17, 'mctpc.alloc_eids.op == 2'),
            (18, ('mctpc.alloc_eids.status == 0 && mctpc.alloc_eids.pool_size == 4'
                  ' && mctpc.alloc_eids.first == 0x50')),
            (19, 'mctpc.command == 12 && mctpc.rq == 1 && !mctpc.data'),
            (20, 'mctpc.command == 12 && mctpc.cc == 0 && !mctpc.data'),
            (21, 'mctpc.command == 13 && mctpc.rq == 1 && !mctpc.data'),
            (22, 'mctpc.command == 13 && mctpc.cc == 0 && !mctpc.data'),
            # Table 27: two entries of different shape, each address bounded
            # by its own size byte.
            (28, ('mctpc.get_routing.next_handle == 0x01 && mctpc.get_routing.count == 2'
                  ' && mctpc.get_routing.range_size == 1 && mctpc.get_routing.start_eid == 0x10'
                  ' && mctpc.get_routing.entry_type == 0 && mctpc.get_routing.static == 0'
                  ' && mctpc.get_routing.port == 2 && mctpc.get_routing.binding_id == 0x01'
                  ' && mctpc.get_routing.media_type == 0x01 && mctpc.get_routing.addr_size == 1'
                  ' && mctpc.get_routing.addr == 51:'
                  ' && mctpc.get_routing.range_size == 8 && mctpc.get_routing.start_eid == 0x20'
                  ' && mctpc.get_routing.entry_type == 1 && mctpc.get_routing.static == 1'
                  ' && mctpc.get_routing.port == 3 && mctpc.get_routing.binding_id == 0x02'
                  ' && mctpc.get_routing.media_type == 0x08 && mctpc.get_routing.addr_size == 2'
                  ' && mctpc.get_routing.addr == 00:1b && !mctpc.data')),
            # [7:2] reserved runs above 2-bit enums, with the enums intact.
            (32, ('mctpc.set_eid.rsvd == 0x21 && mctpc.set_eid.op == 0'
                  ' && mctpc.set_eid.eid == 0x42')),
            (33, ('mctpc.alloc_eids.rsvd == 0x32 && mctpc.alloc_eids.op == 0'
                  ' && mctpc.alloc_eids.count == 4 && mctpc.alloc_eids.start == 0x50')),
            (34, ('mctpc.alloc_eids.rsvd == 0x1f && mctpc.alloc_eids.status == 1'
                  ' && mctpc.alloc_eids.pool_size == 4 && mctpc.alloc_eids.first == 0x50')),
            # Table 39: the binding/media prefix of a transport-specific command.
            (35, ('mctpc.command == 241 && mctpc.rq == 1 && mctpc.transport.binding == 1'
                  ' && mctpc.transport.media == 1 && mctpc.data == aa')),
            (44, 'mctpc.get_eid.endpoint_type == 2 && mctpc.get_eid.eid_type == 1'),
            (45, 'mctpc.get_eid.endpoint_type == 3 && mctpc.get_eid.eid_type == 2'),
            (48, ('mctpc.get_routing.next_handle == 0xff && mctpc.get_routing.count == 1'
                  ' && mctpc.get_routing.media_type == 0x07')),
            # 12.7.2's four version bytes, each filterable on its own.
            (27, ('mctpc.get_ver.entry == 0xfff1f000 && mctpc.get_ver.entry.major == 0xff'
                  ' && mctpc.get_ver.entry.minor == 0xf1 && mctpc.get_ver.entry.update == 0xf0'
                  ' && mctpc.get_ver.entry.alpha == 0x00')),
            (51, ('mctpc.get_eid.endpoint_type == 0 && mctpc.get_eid.eid_type == 0'
                  ' && mctpc.get_eid.eid == 0x42')),
            (52, 'mctpc.rq == 1 && mctpc.get_ver.msg_type == 0'),
            (53, ('mctpc.rq == 0 && mctpc.get_ver.count == 1'
                  ' && mctpc.get_ver.entry == 0xf1f3f300 && !_ws.malformed')),
        ])

    def test_adversarial_responses(self, assert_frames_match, tshark_fields):
        """Error completions, truncated, over-counted and padded payloads (DSP0236 12.3)."""
        assert_frames_match(CAPTURE, [
            (23, ('mctpc.cc == 0x05 && mctpc.excess == 42:12:00 && mctpc.length.invalid'
                  ' && !mctpc.data && !mctpc.get_eid.eid')),
            (24, 'mctpc.command == 1 && mctpc.cc == 0 && mctpc.set_eid.status == 1'),
            (25, 'mctpc.get_ver.count == 10 && mctpc.get_ver.entry == 0xf1f0ff00'),
            (26, ('mctpc.get_eid.eid == 0x42 && mctpc.excess == de:ad'
                  ' && mctpc.length.invalid && !mctpc.data')),
            (29, ('mctpc.get_routing.count == 2 && mctpc.get_routing.addr == 51:'
                  ' && !mctpc.data')),
            (30, ('mctpc.get_routing.addr_size == 255 && !mctpc.get_routing.addr'
                  ' && !mctpc.data')),
            (31, ('mctpc.get_routing.count == 1 && mctpc.get_routing.range_size == 1'
                  ' && !mctpc.get_routing.binding_id && !mctpc.data')),
        ])
        assert sorted(int(n) for n in tshark_fields(
            CAPTURE, 'frame.number <= 53 && _ws.malformed').split()) == [
            23, 24, 25, 26, 29, 30, 31]

    def test_flag_conformance(self, assert_frames_match):
        """IC and (TO, Rq, D) triples against DSP0236 11.4.2 and Table 11."""
        assert_frames_match(CAPTURE, [
            (36, 'mctp.msg.ic == 1 && mctpc.command == 2 && mctpc.rq == 1'),
            (37, ('mctpc.command == 1 && mctpc.rq == 1 && mctpc.d == 0 && mctp.tag.to == 0'
                  ' && !mctpc.set_eid.eid && !mctpc.set_eid.op && mctpc.data == 00:42')),
            (38, ('mctpc.command == 2 && mctpc.rq == 0 && mctpc.d == 1 && mctp.tag.to == 1'
                  ' && !mctpc.cc && !mctpc.get_eid.eid && mctpc.data == 00:42:12:00')),
            (39, ('mctpc.d == 1 && mctpc.rq == 1 && mctp.tag.to == 1'
                  ' && mctpc.set_eid.eid == 0x44')),
            (40, 'mctp.rsvd == 0x0f && mctp.version == 1 && mctpc.command == 2'),
        ])

    def test_expert_census(self, fields_table):
        """F36 sets IC on a control message (11.4.2) and F49's alpha byte
        is neither 00h nor a letter (12.7.2); the standalone responses get
        only the unmatched-response note."""
        t = {n: row for n, row in fields_table(CAPTURE, self.FIELDS + (UNMATCHED,)).items()
             if n <= 53}
        assert list(column(t, 'mctpc')) == list(range(1, 54))
        assert list(column(t, 'mctpc.get_ver.entry.invalid_bcd')) == [27]
        # F37 and F38 use reserved Table 11 classes, which are discarded.
        assert [n for n in range(36, 54) if other_expert_text(t[n]['_ws.expert'])] == [
            36, 37, 38, 49]
        assert [n for n in range(36, 54) if t[n][UNMATCHED] is not None and
                UNMATCHED_TEXT in t[n]['_ws.expert']] == [41, 42, 43, 44, 45, 48, 49, 50, 51]
        # The reserved nibble is unconditional: every other frame shows 0h.
        assert [n for n, row in t.items() if row['mctp.rsvd'] == '0x00'] == [
            n for n in range(1, 54) if n != 40]
        assert t[14]['mctpc.get_msg_types.type'] == '0x04,0x05,0x7e'

    def test_info_column(self, fields_table):
        """12.3's completion code is in Info, and Table 11's class depends
        on the destination EID: F39 is a Datagram, not a Request."""
        t = fields_table(CAPTURE, self.FIELDS)
        assert {n: t[n]['_ws.col.info'] for n in (1, 2, 19, 20, 23, 39)} == {
            1: 'MCTP Set Endpoint ID Request',
            2: 'MCTP Set Endpoint ID Response, Success (0x00)',
            19: 'MCTP Endpoint Discovery Request',
            20: 'MCTP Endpoint Discovery Response, Success (0x00)',
            23: 'MCTP Get Endpoint ID Response, Error: unsupported command (0x05)',
            39: 'MCTP Set Endpoint ID Datagram',
        }

    def test_labels(self, dissect_pdml):
        """Names reached only through the showname (BASE_HEX values never
        resolve through -Tfields)."""
        pdml = dissect_pdml(CAPTURE)
        expected = {
            (1, 'mctpc.command'): ['Command: Set Endpoint ID (0x01)'],
            (7, 'mctpc.command'): ['Command: Get Endpoint ID (0x02)'],
            (13, 'mctpc.command'): ['Command: Get Message Type Support (0x05)'],
            (28, 'mctpc.command'): ['Command: Get Routing Table Entries (0x0a)'],
            (35, 'mctpc.command'): ['Command: Transport Specific (0xf1)'],
            (14, 'mctpc.get_msg_types.type'): [
                'Message type: NVMe-MI over MCTP (0x04)', 'Message type: SPDM (0x05)',
                'Message type: Vendor Defined - PCI (0x7e)'],
            (28, 'mctpc.get_routing.entry_type'): [
                '00.. .... = Entry type: Single endpoint, not an MCTP bridge (0x0)',
                ('01.. .... = Entry type: EID range for a bridge, starting EID'
                ' is the bridge itself (0x1)')],
            (28, 'mctpc.get_routing.static'): [
                '..0. .... = Entry configuration: Dynamically created',
                '..1. .... = Entry configuration: Statically configured'],
            (28, 'mctpc.get_routing.binding_id'): [
                'Physical transport binding ID: MCTP over SMBus (DSP0237) (0x01)',
                'Physical transport binding ID: MCTP over PCIe VDM (DSP0238) (0x02)'],
            (28, 'mctpc.get_routing.media_type'): [
                'Physical media type ID: SMBus 2.0 100 kHz compatible (0x01)',
                'Physical media type ID: PCIe revision 1.1 compatible (0x08)'],
            (48, 'mctpc.get_routing.media_type'): ['Physical media type ID: Reserved (0x07)'],
            # Table 13: 06h-7Fh Reserved, 80h command specific.
            (20, 'mctpc.cc'): ['Completion code: Success (0x00)'],
            (23, 'mctpc.cc'): ['Completion code: Error: unsupported command (0x05)'],
            (41, 'mctpc.cc'): ['Completion code: Reserved (0x06)'],
            (42, 'mctpc.cc'): ['Completion code: Reserved (0x7f)'],
            (43, 'mctpc.cc'): ['Completion code: Command Specific (0x80)'],
            (44, 'mctpc.get_eid.endpoint_type'): ['..10 .... = Endpoint type: Reserved (0x2)'],
            (45, 'mctpc.get_eid.endpoint_type'): ['..11 .... = Endpoint type: Reserved (0x3)'],
            (46, 'mctpc.get_ver.msg_type'): [
                'Message type number: Vendor Defined - PCI (0x7e)'],
            (47, 'mctpc.get_ver.msg_type'): [
                'Message type number: Vendor Defined - IANA (0x7f)'],
            (39, 'mctpc.rq'): ['1... .... = Rq: Request'],
        }
        for (frame, name), labels in expected.items():
            assert pdml.shownames(frame, name) == labels, (frame, name)
        assert len(pdml.shownames(6, 'mctpc.set_eid.status')) == 1
        assert 'rejected' in pdml.shownames(6, 'mctpc.set_eid.status')[0]

    def test_version_rendering(self, dissect_pdml):
        """12.7.2: Fh single-digit markers, an absent (FFh) update byte,
        alpha bytes in [a-zA-Z] only, and no number composed from an invalid
        FFh major byte."""
        pdml = dissect_pdml(CAPTURE)
        assert pdml.shownames(12, 'mctpc.get_ver.entry') == [
            'Version number entry: 1.0 (0xf1f0ff00)',
            'Version number entry: 1.3.3 (0xf1f3f300)',
            'Version number entry: 3.7.10a (0xf3f71061)',
            'Version number entry: 10.11.7 (0x1011f700)']
        assert pdml.shownames(12, 'mctpc.get_ver.entry.major')[1] == 'Major version: 1'
        assert pdml.shownames(12, 'mctpc.get_ver.entry.minor')[1] == 'Minor version: 3'
        assert pdml.shownames(12, 'mctpc.get_ver.entry.update')[:2] == [
            'Update version: Not present (0xff)', 'Update version: 3']
        assert pdml.shownames(12, 'mctpc.get_ver.entry.alpha')[1:3] == [
            'Alpha: Not used (0x00)', 'Alpha: a (0x61)']
        assert pdml.shownames(27, 'mctpc.get_ver.entry') == [
            'Version number entry: [invalid 0xff].1.0 (0xfff1f000)']
        assert pdml.shownames(49, 'mctpc.get_ver.entry') == [
            'Version number entry: 1.3.3 (0xf1f3f330)']
        assert pdml.shownames(49, 'mctpc.get_ver.entry.alpha') == ['Alpha: [invalid 0x30]']
        assert pdml.shownames(50, 'mctpc.get_ver.entry') == [
            'Version number entry: 1.3.3Z (0xf1f3f35a)']

    def test_extents(self, dissect_pdml):
        """The control header item covers bytes 2-3 only (11.4), with its
        children inside it and the completion code just after; a truncated
        routing entry (F30) spans its Table 27 header."""
        pdml = dissect_pdml(CAPTURE)
        for frame in (7, 12, 28):
            mctpc, = pdml.packets[frame].findall(".//proto[@name='mctpc']")
            header, = [f for f in pdml.packets[frame].iter()
                       if f.get('show') == 'MCTP Control Protocol header']
            pos, size = int(header.get('pos')), int(header.get('size'))
            assert (pos, size) == (int(mctpc.get('pos')) + 1, 2), frame
            assert size < int(mctpc.get('size')), frame
            if frame == 12:
                for name in ('mctpc.rq', 'mctpc.d', 'mctpc.rsvd', 'mctpc.instance',
                             'mctpc.command'):
                    found = pdml.extents(12, name)
                    assert found, name
                    assert all(pos <= p and p + s <= pos + size for p, s in found), name
                assert pdml.extents(12, 'mctpc.cc') == [(pos + size, 1)]
        entry, = pdml.extents(30, 'mctpc.get_routing.entry')
        assert entry[1] == 6   # Table 27's 6-byte header; the address is cut short


class TestMctpControlReservedRuns:
    """All seven DSP0236 reserved runs in the LENGTHS section's F191-F206
    (even frames nonzero, odd frames zero); nonzero bits are shown and
    suppress nothing."""

    FILE = CAPTURE
    # (frame, field, offset, value); the masks are checked in test_registration.
    RUNS = (
        (192, 'mctpc.rsvd', 21, 1),
        (194, 'mctpc.set_eid.rsvd', 23, 63),
        (196, 'mctpc.set_eid.rsvd_hi', 24, 3),
        (198, 'mctpc.set_eid.rsvd_lo', 24, 3),
        (200, 'mctpc.get_eid.rsvd_hi', 25, 3),
        (202, 'mctpc.get_eid.rsvd_lo', 25, 3),
        (204, 'mctpc.alloc_eids.rsvd', 23, 63),
        (206, 'mctpc.alloc_eids.rsvd', 24, 63),
    )

    def test_no_experts(self, tshark_fields):
        assert not tshark_fields(self.FILE, f'{frames_in(LENGTHS, 191)} && {OTHER_EXPERTS}')

    def test_values_and_anchors(self, dissect_pdml):
        packets = pdml_section(dissect_pdml(self.FILE, two_pass=True,
                                            dfilter=frames_in(LENGTHS, 191)), LENGTHS).packets
        assert list(packets) == list(range(191, 207))
        runs = {run[0]: run[1:] for run in self.RUNS}
        for frame, packet in packets.items():
            field, pos, value = runs[frame if frame % 2 == 0 else frame + 1]
            node = packet.find(f".//field[@name='{field}']")
            assert node is not None and (node.get('pos'), node.get('size')) == (str(pos), '1')
            assert int(node.get('show'), 0) == (value if frame % 2 == 0 else 0)
        # Nonzero reserved bits do not suppress payloads.
        for packet in packets.values():
            assert packet.find(".//field[@name='mctpc.command']") is not None


class TestMctpControlFixedLengths:
    """Fixed-length requests and responses: exact, short, with excess and capture-short."""

    FILE = CAPTURE
    REQUESTS = (
        (1, 5), (2, 3), (3, 3), (4, 4), (5, 3), (6, 4), (7, 4),
        (8, 6), (10, 4), (11, 3), (12, 3), (13, 3), (14, 3),
        (15, 5), (16, 20), (17, 3), (18, 10), (19, 10), (20, 3),
    )
    SUCCESSES = (
        (1, 7), (2, 7), (3, 20), (8, 7), (9, 4), (11, 4), (12, 4),
        (13, 4), (14, 20), (17, 31), (18, 12), (19, 4), (0xf0, 4), (0xff, 4),
    )
    LENGTH_FRAMES = [
        frame for base in range(15, 147, 4) for frame in (base + 1, base + 2)
    ] + [148, 149]
    CAPTURE_FRAMES = list(range(18, 147, 4)) + [
        150, 157, 160, 164, 167, 170, 171, 173,
    ]
    # Reported-short closed layouts and count lists raise ReportedBoundsError.
    MALFORMED_FRAMES: ClassVar = [16, 28, 36, 40, 44, 48, 68, 72, 80, 84, 92, 96, 100, 104,
                        124, 128, 132, 156, 159, 163, 166, 172, 175]
    # Count-delimited responses with bytes past their counted data
    # (MCTPC-3), and a Query Hop response with 3 TU bytes (MCTPC-5).
    TRAILING_FRAMES: ClassVar = [158, 165, 174]
    CENSUS = (
        ('mctpc.length.invalid', sorted(LENGTH_FRAMES + TRAILING_FRAMES + [182])),
        # Set/Force EID with the illegal EIDs 00h/FFh (Table 14) or the
        # reserved EIDs 01h/07h (Table 2).
        ('mctpc.invalid_value', [3, 4, 6, 7, 188, 189]),
        # Routing-table entries giving SMBus media (01h) a 2-byte address,
        # where DSP0237 Table 3 defines 1 byte.
        ('mctpc.phys_addr.size_mismatch', [169, 174]),
    )

    @staticmethod
    def _nodes(packet, field):
        return packet.findall(f".//field[@name='{field}']")

    def test_exact_census_lengths_anchors_and_prefixes(self, dissect_pdml):
        packets = pdml_section(dissect_pdml(self.FILE), LENGTHS).packets
        # F191-F206 are the reserved runs (TestMctpControlReservedRuns).
        assert list(packets) == list(range(1, 207))
        packets = {n: p for n, p in packets.items() if n <= 190}
        all_bad = sorted({frame for _, frames in self.CENSUS for frame in frames}
                         | set(self.MALFORMED_FRAMES))
        assert [f for f, p in packets.items() if other_experts(p)] == all_bad
        for field, expected in self.CENSUS:
            assert [f for f, p in packets.items() if self._nodes(p, field)] == expected
        assert [f for f, p in packets.items() if p.findall(".//proto[@name='_ws.short']")] == \
            self.CAPTURE_FRAMES
        for frame, packet in packets.items():
            malformed = frame in self.MALFORMED_FRAMES
            assert bool(self._nodes(packet, '_ws.malformed.expert')) == malformed, frame
            assert len(other_messages(packet)) == sum(
                frame in frames for _, frames in self.CENSUS) + malformed, frame

        for start, layouts, rq in ((15, self.REQUESTS, True), (91, self.SUCCESSES, False)):
            for i, (cmd, length) in enumerate(layouts):
                base = start + 4 * i
                for delta, size in ((0, length), (1, length - 1),
                                    (2, length + 2), (3, length - 1)):
                    packet = packets[base + delta]
                    root = packet.find(".//proto[@name='mctpc']")
                    assert (int(root.get('pos')), int(root.get('size'))) == (20, size)
                    command = self._nodes(packet, 'mctpc.command')
                    if size >= 3:
                        assert len(command) == 1 and int(command[0].get('show'), 0) == cmd
                        assert (command[0].get('pos'), command[0].get('size')) == ('22', '1')
                    else:
                        assert command == []
                    if delta in (1, 2):
                        if size < 3:
                            message = ('MCTP Control header requires 3 bytes, '
                                       f'but only {size} bytes are reported')
                        else:
                            name = command[0].get('showname')[len('Command: '):].rsplit(' (', 1)[0]
                            if not rq and size < 4:
                                message = (f'{name} response requires a completion code '
                                           f'(minimum 4 bytes), but {size} bytes are reported')
                            else:
                                direction = 'request' if rq else 'response'
                                message = (f'{name} {direction} requires exactly {length} bytes, '
                                           f'but {size} bytes are reported')
                        assert other_messages(packet)[0].get('show') == message
                    if delta == 2:
                        residue = self._nodes(packet, 'mctpc.excess')
                        assert len(residue) == 1 and residue[0].get('value') == 'dead'
                        assert (int(residue[0].get('pos')),
                                int(residue[0].get('size'))) == (20 + length, 2)
                        assert len(self._nodes(residue[0], 'mctpc.length.invalid')) == 1
                        for raw in self._nodes(packet, 'mctpc.data'):
                            assert int(raw.get('pos')) + int(raw.get('size')) <= 20 + length
                    else:
                        assert not self._nodes(packet, 'mctpc.excess')
                    if delta == 1 and size >= 3:
                        assert len(self._nodes(command[0], 'mctpc.length.invalid')) == 1
                    if delta == 3:
                        # PDML writes _ws.malformed as a <proto>, not a <field>.
                        assert packet.find(".//proto[@name='_ws.malformed']") is None
                        assert packet.findall(".//proto[@name='_ws.short']")
                    if delta == 0 and not rq:
                        assert self._nodes(packet, 'mctpc.cc')[0].get('show') == '0x00'

        # Complete prefix fields survive a short closed body and count list.
        assert self._nodes(packets[92], 'mctpc.set_eid.eid_setting')
        assert self._nodes(packets[156], 'mctpc.get_ver.entry')[0].get('value') == 'f1f3f300'
        assert not self._nodes(packets[156], 'mctpc.data')
        assert self._nodes(packets[163], 'mctpc.get_msg_types.type')[0].get('show') == '0x04'
        for frame in (156, 163):
            count_name = 'mctpc.get_ver.count' if frame == 156 else 'mctpc.get_msg_types.count'
            count = self._nodes(packets[frame], count_name)[0]
            assert (count.get('pos'), count.get('size')) == ('24', '1')
        for frame in self.TRAILING_FRAMES:
            assert not self._nodes(packets[frame], 'mctpc.data')
            residue = self._nodes(packets[frame], 'mctpc.excess')
            assert len(residue) == 1 and residue[0].get('value') == 'dead'
            assert self._nodes(residue[0], 'mctpc.length.invalid')
        for frame in (170, 171):
            assert not self._nodes(packets[frame], 'mctpc.data')
        assert self._nodes(packets[173], 'mctpc.get_routing.next_handle')
        for frame in list(range(176, 191)) + list(range(1, 15)):
            if frame not in (3, 4, 6, 7, 182, 188, 189):
                assert not other_experts(packets[frame]), frame
        # Reserved EID values, not reserved bit fields.
        for frame, eid in ((188, 0x01), (189, 0x07)):
            assert [m.get('show') for m in other_messages(packets[frame])] == [
                (f'Endpoint ID 0x{eid:02x} is reserved, not available for '
                'assignment, for Set EID (DSP0236 special endpoint IDs)')]
            assert self._nodes(packets[frame], 'mctpc.set_eid.rsvd')[0].get('show') == '0x00'
            assert not self._nodes(packets[frame], 'mctpc.reserved_class')

        # The Table 1 reserved nibble is its own byte; the Table 14 EID is its exact
        # one-byte field.
        nibble = self._nodes(packets[2], 'mctp.rsvd')[0]
        assert (nibble.get('pos'), nibble.get('size')) == ('16', '1')
        assert self._nodes(packets[1], 'mctpc.command')[0].get('show') == \
            self._nodes(packets[2], 'mctpc.command')[0].get('show')
        for frame in (3, 4, 6, 7):
            eid = self._nodes(packets[frame], 'mctpc.set_eid.eid')[0]
            assert (eid.get('pos'), eid.get('size')) == ('24', '1')

    def test_completion_context_and_selected_pass(self, dissect_pdml, tshark_fields):
        names = {
            151: 'Message type number not supported',
            152: 'Command Specific',
            153: 'Insufficient routing-table space',
            154: 'Command Specific',
        }
        selected = pdml_section(dissect_pdml(self.FILE, dfilter=frames_in(LENGTHS, 147, 154)),
                                LENGTHS).packets
        for frame, name in names.items():
            cc = '0x80' if frame % 2 else '0x81'
            assert self._nodes(selected[frame], 'mctpc.cc')[0].get('showname') == \
                f'Completion code: {name} ({cc})'
        info = tshark_fields(self.FILE, f'frame.number == {frame_in(LENGTHS, 148)}',
                             fields=('_ws.col.info',)).strip()
        assert info == 'MCTP Get Endpoint ID Response, missing completion code'
        rows = tshark_fields(self.FILE, frames_in(LENGTHS, 151, 154),
                             fields=('_ws.col.info',)).splitlines()
        assert rows == [
            'MCTP Get MCTP Version Support Response, Message type number not supported (0x80)',
            'MCTP Get MCTP Version Support Response, Command Specific (0x81)',
            'MCTP Routing Information Update Response, Insufficient routing-table space (0x80)',
            'MCTP Routing Information Update Response, Command Specific (0x81)',
        ]

    def test_null_tree_expert_parity(self, dissect_pdml, expert_tap_counts):
        """The expert tap requests no tree; diagnosis must not depend on items."""
        p = dissect_pdml(self.FILE)
        assert expert_tap_counts(self.FILE) == Counter(
            m for n in p.packets for m in p.experts(n))

    def test_mctp_control_anchors(self, dissect_pdml):
        """mctp-control.pcapng's length experts hang off the item they describe."""
        expected = {
            23: ('mctpc.excess', 24, 3, 'mctpc.length.invalid'),
            24: ('mctpc.command', 22, 1, 'mctpc.length.invalid'),
            26: ('mctpc.excess', 27, 2, 'mctpc.length.invalid'),
        }
        packets = dissect_pdml(CAPTURE, two_pass=True).packets
        for frame, (field, pos, size, expert) in expected.items():
            packet = packets[frame]
            anchor = self._nodes(packet, field)[0]
            assert (int(anchor.get('pos')), int(anchor.get('size'))) == (pos, size)
            assert len(self._nodes(anchor, expert)) == 1
            # F24's reported-short body also raises the malformed exception.
            assert len(other_messages(packet)) == 1 + (frame == 24)


class TestMctpControlCommandPayloads:
    """The PAYLOADS section: the DSP0236 Tables 20-39 command layouts
    (payloads_section holds the frame map).  Table 25's binding-sized
    addresses are not iterated."""

    FILE = CAPTURE

    def test_layouts_and_bounds(self, dissect_pdml):
        packets = pdml_section(dissect_pdml(self.FILE), PAYLOADS).packets
        assert list(packets) == list(range(1, 44))

        def nodes(frame, field):
            return packets[frame].findall(f".//field[@name='{field}']")

        # Offsets are relative to the MCTP control message, which starts at 20.
        # Integers assert the decoded (mask-applied) value, strings raw bytes.
        def field(frame, name, value, offset, size):
            found = nodes(frame, name)
            assert len(found) == 1, (frame, name, found)
            node = found[0]
            if isinstance(value, bool):
                actual = node.get('show') == 'True'
            else:
                actual = int(node.get('show'), 0) if isinstance(value, int) else node.get('value')
            assert actual == value, (frame, name, actual)
            assert (int(node.get('pos')), int(node.get('size'))) == (20 + offset, size)

        expected = {
            1: [('mctpc.transport.binding', 1, 3, 1),
                ('mctpc.transport.media', 4, 4, 1), ('mctpc.data', 'aa55', 5, 2)],
            3: [('mctpc.transport.binding', 255, 3, 1),
                ('mctpc.transport.media', 0, 4, 1),
                ('mctpc.transport.iana', 0x01020304, 5, 4),
                ('mctpc.data', 'dead', 9, 2)],
            6: [('mctpc.network_uuid', '123456789abc4ef08122334455667788', 4, 16)],
            7: [('mctpc.resolve_eid.target', 0x42, 3, 1)],
            8: [('mctpc.resolve_eid.bridge', 0x50, 4, 1),
                ('mctpc.resolve_eid.addr', '1234a6', 5, 3)],
            9: [('mctpc.vendor.selector', 0, 3, 1)],
            10: [('mctpc.vendor.next_selector', 255, 4, 1),
                 ('mctpc.vendor.format', 0, 5, 1),
                 ('mctpc.vendor.pci', 0x1234, 6, 2),
                 ('mctpc.vendor.command_set', 0xa1b2, 8, 2),
                 ('mctpc.excess', 'dead', 10, 2)],
            11: [('mctpc.vendor.selector', 1, 3, 1)],
            12: [('mctpc.vendor.next_selector', 255, 4, 1),
                 ('mctpc.vendor.format', 1, 5, 1),
                 ('mctpc.vendor.iana', 0x01020304, 6, 4),
                 ('mctpc.vendor.command_set', 0xa5b6, 10, 2)],
            13: [('mctpc.routing_update.count', 2, 3, 1),
                 ('mctpc.routing_update.entry.rsvd', 0, 4, 1),
                 ('mctpc.routing_update.entry.type', 3, 4, 1),
                 ('mctpc.routing_update.entry.range_size', 4, 5, 1),
                 ('mctpc.routing_update.entry.eid', 0x51, 6, 1),
                 ('mctpc.routing_update.data', 'aa55000162cc', 7, 6)],
            15: [('mctpc.query_hop.target', 0x42, 3, 1),
                 ('mctpc.query_hop.msg_type', 4, 4, 1)],
            16: [('mctpc.query_hop.bridge', 0x50, 4, 1),
                 ('mctpc.query_hop.response_type', 255, 5, 1),
                 ('mctpc.query_hop.in_tu', 0x1122, 6, 2),
                 ('mctpc.query_hop.out_tu', 0x3344, 8, 2)],
            17: [('mctpc.resolve_uuid.uuid', '123456789abc4ef08122334455667788', 3, 16),
                 ('mctpc.resolve_uuid.handle', 0, 19, 1)],
            18: [('mctpc.resolve_uuid.next_handle', 255, 4, 1),
                 ('mctpc.resolve_uuid.count', 2, 5, 1),
                 ('mctpc.excess', 'dead', 17, 2)],
            20: [('mctpc.interfaces.count', 2, 4, 1)],
            22: [('mctpc.rate.rx_buffer', 0x01020304, 4, 4),
                 ('mctpc.rate.rx_rate', 0x11223344, 8, 4),
                 ('mctpc.rate.max_tx_rate', 0x21324354, 12, 4),
                 ('mctpc.rate.min_tx_rate', 0x31425364, 16, 4),
                 ('mctpc.rate.max_burst', 0x010203, 20, 3),
                 ('mctpc.rate.burst', 0x040506, 23, 3),
                 ('mctpc.rate.tx_rate', 0x41526374, 26, 4),
                 ('mctpc.rate.rsvd', 0, 30, 1),
                 ('mctpc.rate.non_requested', False, 30, 1),
                 ('mctpc.rate.supported', True, 30, 1)],
            23: [('mctpc.rate.requested_burst', 0x010203, 3, 3),
                 ('mctpc.rate.requested_rate', 0x12345678, 6, 4)],
            24: [('mctpc.rate.granted_burst', 0x23456789, 4, 4),
                 ('mctpc.rate.tx_rate', 0x3456789a, 8, 4)],
            25: [('mctpc.rate.burst', 0x020304, 3, 3),
                 ('mctpc.rate.tx_rate', 0x456789ab, 6, 4)],
            27: [('mctpc.transport.binding', 1, 3, 1)],
            29: [('mctpc.vendor.format', 2, 5, 1), ('mctpc.data', 'deadbeef', 6, 4)],
            31: [('mctpc.vendor.pci', 0x1234, 6, 2)],
            33: [('mctpc.routing_update.count', 2, 3, 1)],
            34: [('mctpc.query_hop.bridge', 0x50, 4, 1)],
            36: [('mctpc.resolve_uuid.count', 2, 5, 1)],
            37: [('mctpc.resolve_uuid.addr_size', 255, 9, 1)],
            38: [('mctpc.interfaces.count', 0, 4, 1)],
            40: [('mctpc.resolve_uuid.addr_size', 2, 9, 1)],
            41: [('mctpc.cc', 128, 3, 1), ('mctpc.excess', 'ff001234a1b2', 4, 6)],
            42: [('mctpc.resolve_uuid.count', 0, 5, 1), ('mctpc.excess', 'dead', 6, 2)],
        }
        for frame, fields in expected.items():
            for name, value, offset, size in fields:
                field(frame, name, value, offset, size)
        # Table 36 reports the burst size presently used, not a grant.
        assert [n.get('showname') for n in nodes(24, 'mctpc.rate.granted_burst')] == \
            ['Present transmit burst size (packets): 591751049']
        assert [n.get('showname') for n in nodes(23, 'mctpc.rate.requested_burst')] == \
            ['Requested transmit maximal burst size (packets): 66051']

        assert nodes(6, 'mctpc.network_uuid')[0].get('show') == \
            '12345678-9abc-4ef0-8122-334455667788'
        assert nodes(17, 'mctpc.resolve_uuid.uuid')[0].get('show') == \
            '12345678-9abc-4ef0-8122-334455667788'
        assert 'All supported message types' in nodes(16, 'mctpc.query_hop.response_type')[0].get('showname')
        hop_fields = [n for n in packets[16].iter('field')
                      if n.get('name', '').startswith('mctpc.query_hop.')]
        # Table 32 numbers the TU fields 4:5 and 5:6 but sizes each 2 bytes;
        # they are read as 4:5 and 6:7, the only non-overlapping layout.
        assert len(hop_fields) == 4 and not nodes(16, 'mctpc.query_hop.tu_data')
        assert not nodes(13, 'mctpc.get_routing.entry')

        # Off an SMBus ingress DSP0237 6.8's one-byte address is unavailable,
        # so exactly one Table 25 record is locatable and the rest of the
        # payload stays an undelimited tail.
        update_entries = nodes(13, 'mctpc.routing_update.entry')
        assert [(int(n.get('pos')), int(n.get('size'))) for n in update_entries] \
            == [(24, 3)]
        assert not nodes(13, 'mctpc.routing_update.entry.slave_addr')

        # Unlike Table 25, Table 34 explicitly delimits every record.
        entries = nodes(18, 'mctpc.resolve_uuid.entry')
        assert [(int(n.get('pos')), int(n.get('size'))) for n in entries] == [(26, 5), (31, 6)]
        for entry, eid, binding, media, address in (
                (entries[0], 0x42, 1, 4, '50'),
                (entries[1], 0x43, 2, 0x0b, '1234')):
            start = int(entry.get('pos'))
            for suffix, value, offset in (('eid', eid, 0), ('binding', binding, 1),
                                         ('media', media, 2), ('addr_size', len(address) // 2, 3)):
                node = entry.find(f"./field[@name='mctpc.resolve_uuid.{suffix}']")
                assert int(node.get('show'), 0) == value
                assert (int(node.get('pos')), int(node.get('size'))) == (start + offset, 1)
            node = entry.find("./field[@name='mctpc.resolve_uuid.addr']")
            assert node.get('value') == address
            assert (int(node.get('pos')), int(node.get('size'))) == (start + 4, len(address) // 2)

        for name, values, positions in (
                ('mctpc.interfaces.media', [4, 0x0b], [25, 27]),
                ('mctpc.interfaces.eid', [0x42, 0x43], [26, 28])):
            assert [int(n.get('show'), 0) for n in nodes(20, name)] == values
            assert [(int(n.get('pos')), int(n.get('size'))) for n in nodes(20, name)] == \
                [(pos, 1) for pos in positions]

        # Payloads cut short raise the normal tvb exceptions: reported-short
        # ones are malformed, F40's uncaptured tail is "packet size limited".
        census = {
            '_ws.malformed.expert': [27, 28, 30, 31, 32, 33, 34, 35, 36, 37, 39],
            # F10, F18 and F42 carry bytes past their counted data.
            'mctpc.length.invalid': [10, 18, 41, 42],
            'mctpc.invalid_value': [38],
        }
        bad = sorted(f for frames in census.values() for f in frames)
        assert [f for f in packets if other_experts(packets[f])] == bad
        for expert, frames in census.items():
            assert [f for f in packets if nodes(f, expert)] == frames
        assert [f for f, p in packets.items()
                if p.findall(".//proto[@name='_ws.short']")] == [40]
        for frame, packet in packets.items():
            assert len(other_messages(packet)) == (frame in bad)
            root = packet.find(".//proto[@name='mctpc']")
            start, end = int(root.get('pos')), int(root.get('pos')) + int(root.get('size'))
            for node in root.iter('field'):
                if node.get('name', '').startswith('mctpc.') and \
                        node.get('name') not in (*census, UNMATCHED):
                    pos, size = int(node.get('pos')), int(node.get('size'))
                    assert start <= pos <= pos + size <= end, (frame, node.attrib)
            if frame not in census['_ws.malformed.expert']:
                for expert in nodes(frame, '_ws.expert'):
                    assert start <= int(expert.get('pos')) <= end
        # DSP0236 Table 21 defines formats 0x00 and 0x01 only; 0x02 is a
        # reserved value (5.3).
        assert nodes(29, 'mctpc.vendor.format')[0].get('showname') == \
            'Vendor ID format: Reserved (0x02)'
        assert nodes(10, 'mctpc.vendor.format')[0].get('showname') == \
            'Vendor ID format: PCI Vendor ID (0x00)'
        assert nodes(12, 'mctpc.vendor.format')[0].get('showname') == \
            'Vendor ID format: IANA Enterprise Number (0x01)'

        for frame in (29, 30, 31, 41):
            assert not nodes(frame, 'mctpc.vendor.command_set')
        assert not nodes(29, 'mctpc.vendor.pci') and not nodes(29, 'mctpc.vendor.iana')
        assert not nodes(28, 'mctpc.transport.iana')
        assert not nodes(27, 'mctpc.transport.media')
        assert not nodes(34, 'mctpc.query_hop.response_type')
        assert len(nodes(35, 'mctpc.resolve_uuid.entry')) == 1
        assert not nodes(35, 'mctpc.resolve_uuid.addr_size')
        assert len(nodes(36, 'mctpc.resolve_uuid.entry')) == 1
        for frame in (37, 40):
            assert not nodes(frame, 'mctpc.resolve_uuid.addr')
        assert not nodes(38, 'mctpc.interfaces.media')
        assert len(nodes(39, 'mctpc.interfaces.media')) == 2
        assert len(nodes(39, 'mctpc.interfaces.eid')) == 1
        assert not nodes(41, 'mctpc.vendor.next_selector')
        assert not nodes(42, 'mctpc.resolve_uuid.entry')
        for frame in range(1, 27):
            assert bool(nodes(frame, 'mctpc.cc')) == (frame % 2 == 0)
            assert bool(nodes(frame, 'mctpc.excess')) == (frame in (10, 18))
        for frame in (2, 4, 5, 14, 19, 21, 26):
            assert not nodes(frame, 'mctpc.data')

    def test_reserved_vendor_format_stops_the_decode(self, tshark_fields):
        """DSP0236 Table 21 defines Vendor ID Formats 00h and 01h only; F29's
        02h hides where the command-set field is, so the rest is data.  F30/F31
        are defined-format responses cut short, so the decode throws."""
        stdout = tshark_fields(self.FILE, f'{frames_in(PAYLOADS)} && mctpc.vendor.format', fields=(
            'frame.number', 'mctpc.vendor.format', '_ws.expert'), separator='|')
        rows = [row.rsplit('|', 1) for row in stdout.splitlines()]
        assert [f'{head}|{other_expert_text(tail)}' for head, tail in rows] == [
            (f'{frame_in(PAYLOADS, 10)}|0x00|Expert Info (Error/Malformed):'
             ' Get Vendor Defined Message Support response has 2 bytes beyond'
             ' the data its count or format gives'),
            f'{frame_in(PAYLOADS, 12)}|0x01|',
            f'{frame_in(PAYLOADS, 29)}|0x02|',
            (f'{frame_in(PAYLOADS, 30)}|0x00|Expert Info (Error/Malformed):'
             ' Malformed Packet (Exception occurred)'),
            (f'{frame_in(PAYLOADS, 31)}|0x00|Expert Info (Error/Malformed):'
             ' Malformed Packet (Exception occurred)'),
        ]


class TestMctpControlBindingFields:
    """The fields DSP0236 leaves to the binding: DSP0237 6.8 Table 3 and 6.9
    Table 4 decodes on mctp-smbus.pcapng F28-F33, the generic items on the
    SLL frames of mctp-control.pcapng."""

    FILE = 'mctp-smbus.pcapng'
    FIELDS = ('frame.protocols', 'mctpc.routing_update.count',
              'mctpc.routing_update.entry.type', 'mctpc.routing_update.entry.range_size',
              'mctpc.routing_update.entry.eid', 'mctpc.routing_update.entry.slave_addr',
              'mctpc.routing_update.entry.addr_rsvd', 'mctpc.routing_update.data',
              'mctpc.data', '_ws.expert', '_ws.expert.message')

    def test_binding_fields(self, assert_frames_match):
        assert_frames_match(self.FILE, [
            (28, ('mctpc.get_eid.medium_info == 0x01 && mctpc.get_eid.medium_info.fairness == 1'
                  ' && mctpc.get_eid.medium_info.rsvd == 0')),
            (29, ('mctpc.get_eid.medium_info.rsvd == 0x01'
                  ' && mctpc.get_eid.medium_info.fairness == 1')),
            (30, ('mctpc.resolve_eid.slave_addr == 0x31 && mctpc.resolve_eid.addr_rsvd == 0'
                  ' && !mctpc.resolve_eid.addr && !mctpc.data')),
            (31, 'mctpc.resolve_eid.slave_addr == 0x31 && mctpc.resolve_eid.addr_rsvd == 1'),
        ])

    def test_routing_update_records(self, fields_table):
        """Every Table 25 record walks, in order; a short list throws after the complete records."""
        t = {n: row for n, row in fields_table(self.FILE, self.FIELDS).items() if 28 <= n <= 33}
        assert {n: row['frame.protocols'] for n, row in t.items()} == {
            n: 'i2c:mctp.smbus:mctp:mctpc' for n in range(28, 34)}
        assert [t[32][f] for f in self.FIELDS[1:9]] == [
            '2', '0x03,0x00', '4,2', '0x51,0x30', '0x31,0x20', '0x00,0x00', '', '']
        assert (t[33]['mctpc.routing_update.count'], t[33]['mctpc.routing_update.entry.eid'],
                other_expert_text(t[33]['_ws.expert.message'])) == (
            '3', '0x51,0x30', 'Malformed Packet (Exception occurred)')
        assert [n for n, row in t.items() if other_expert_text(row['_ws.expert'])] == [33]

    def test_no_dsp0237_fields_on_an_sll_ingress(self, assert_frames_match):
        assert_frames_match(CAPTURE, [
            (frame_in(PAYLOADS, 8), ('mctpc.resolve_eid.addr == 12:34:a6'
                                     ' && !mctpc.resolve_eid.slave_addr && !mctpc.resolve_eid.addr_rsvd')),
            (frame_in(PAYLOADS, 13), ('mctpc.routing_update.count == 2'
                                      ' && mctpc.routing_update.entry.eid == 0x51'
                                      ' && mctpc.routing_update.data == aa:55:00:01:62:cc'
                                      ' && !mctpc.routing_update.entry.slave_addr'
                                      ' && !mctpc.routing_update.entry.addr_rsvd')),
            # 0x62, not 62: a bare 62 parses as the decimal byte 0x3e.
            (frame_in(PAYLOADS, 43), ('mctpc.resolve_eid.bridge == 0x50 && mctpc.resolve_eid.addr == 0x62'
                                      ' && !mctpc.resolve_eid.slave_addr'
                                      ' && !mctpc.resolve_eid.addr_rsvd')),
        ])


class TestMctpControlConformance:
    """DSP0236 Table 11's destination column and 12.7.2's BCD rules."""

    FILE = CAPTURE
    FIELDS = ('_ws.col.info', 'mctpc.cc', 'mctpc.get_ver.entry.invalid_bcd',
              '_ws.expert', '_ws.expert.message')

    def test_message_classes(self, fields_table, assert_frames_match):
        t = section(fields_table(self.FILE, self.FIELDS), CONFORMANCE)
        assert [t[n]['_ws.col.info'] for n in range(1, 8)] == [
            'MCTP Get Endpoint ID Request',
            'MCTP Get Endpoint ID Response, Success (0x00)',
            'MCTP Get Endpoint ID Response, Error: unsupported command (0x05)',
            'MCTP Discovery Notify Datagram',
            'MCTP Prepare for Endpoint Discovery Broadcast Request',
            'MCTP Endpoint Discovery Broadcast Datagram',
            'MCTP Get Endpoint ID discarded, reserved destination/TO/Rq/D combination']
        assert (t[2]['mctpc.cc'], t[3]['mctpc.cc']) == ('0x00', '0x05')
        # F3 is a second response to F1's request, so it has no request.
        # F7's reserved class is flagged (DSP0236 11.7, Table 11).
        assert [n for n, row in t.items() if other_expert_text(row['_ws.expert'])] == [7, 8]
        assert 'Reserved destination/TO/Rq/D combination' in t[7]['_ws.expert.message']
        assert [n for n, row in t.items() if UNMATCHED_TEXT in row['_ws.expert']] == [3, 8]
        assert list(column(t, 'mctpc.get_ver.entry.invalid_bcd')) == [8]
        assert t[8]['_ws.expert.message'].count('Invalid BCD version encoding') == 3
        assert_frames_match(self.FILE, [(frame_in(CONFORMANCE, n), expr) for n, expr in (
            (2, 'mctp.dst == 0x0a && mctpc.rq == 0 && mctpc.d == 0 && mctp.tag.to == 0'),
            (5, 'mctp.dst == 0xff && mctpc.command == 0x0b'),
            (6, 'mctp.dst == 0xff && mctpc.command == 0x0c'),
            # 11.7: a discarded message is not decoded below its header.
            (7, ('mctp.dst == 0xff && mctpc.rq == 0 && mctpc.d == 0 && mctp.tag.to == 0'
                 ' && !mctpc.cc && !mctpc.get_eid.eid && mctpc.data == 00:30:12:00')),
            (8, ('mctpc.get_ver.entry == 0xf1faf300 && mctpc.get_ver.entry.minor == 0xfa'
                 ' && mctpc.get_ver.entry.update == 0x1a && mctpc.get_ver.entry.major == 0xff'
                 ' && mctpc.get_ver.entry.alpha == 0x61')),
        )])

    def test_bcd_rendering(self, dissect_pdml):
        pdml = dissect_pdml(self.FILE)
        f8 = frame_in(CONFORMANCE, 8)
        assert pdml.shownames(f8, 'mctpc.get_ver.entry') == [
            'Version number entry: 1.3.3 (0xf1f3f300)',
            'Version number entry: 1.0a (0xf1f0ff61)',
            'Version number entry: 1.[invalid 0xfa].3 (0xf1faf300)',
            'Version number entry: 1.3.[invalid 0x1a] (0xf1f31a00)',
            'Version number entry: [invalid 0xff].1.0 (0xfff1f000)']
        assert pdml.shownames(f8, 'mctpc.get_ver.entry.major') == [
            'Major version: 1', 'Major version: 1', 'Major version: 1',
            'Major version: 1', 'Major version: [invalid 0xff]']
        assert pdml.shownames(f8, 'mctpc.get_ver.entry.minor') == [
            'Minor version: 3', 'Minor version: 0', 'Minor version: [invalid 0xfa]',
            'Minor version: 3', 'Minor version: 1']
        assert pdml.shownames(f8, 'mctpc.get_ver.entry.update') == [
            'Update version: 3', 'Update version: Not present (0xff)', 'Update version: 3',
            'Update version: [invalid 0x1a]', 'Update version: 0']
        assert pdml.shownames(f8, 'mctpc.get_ver.entry.alpha') == [
            'Alpha: Not used (0x00)', 'Alpha: a (0x61)', 'Alpha: Not used (0x00)',
            'Alpha: Not used (0x00)', 'Alpha: Not used (0x00)']


class TestMctpControlPairing:
    """The PAIRING section: DSP0236 Table 10 request/response pairing (the
    generator's _packets_pairing holds the map) and the binding-defined
    physical address layouts."""

    FILE = CAPTURE
    LINKS = ('mctpc.response_in', 'mctpc.response_to')
    FIELDS = LINKS + ('mctpc.response_time', UNMATCHED, '_ws.expert')

    def table(self, fields_table, two_pass=True):
        return section(fields_table(self.FILE, self.FIELDS, two_pass=two_pass),
                       PAIRING, self.LINKS)

    def test_links(self, fields_table):
        """Interleaved, reverse-order and concurrent exchanges pair by
        (requester, responder, tag, IID, command); a broadcast or null-EID
        request pairs with whoever answers, and its first answer is the
        request's response_in.  F16 (other command), F18 (nothing asked),
        F19 (already answered) and F26 (answering a datagram) stay unpaired."""
        t = self.table(fields_table)
        assert {n: r['mctpc.response_to'] for n, r in t.items() if r['mctpc.response_to']} == {
            3: '2', 4: '1', 6: '5', 9: '8', 10: '7', 12: '11', 14: '13', 17: '15',
            21: '20', 22: '20', 24: '23', 28: '27', 30: '29', 32: '31', 34: '33',
            36: '35'}
        assert {n: r['mctpc.response_in'] for n, r in t.items() if r['mctpc.response_in']} == {
            1: '4', 2: '3', 5: '6', 7: '10', 8: '9', 11: '12', 13: '14', 15: '17',
            20: '21', 23: '24', 27: '28', 29: '30', 31: '32', 33: '34', 35: '36'}
        assert [n for n, r in t.items() if r[UNMATCHED] is not None and
                UNMATCHED_TEXT in r['_ws.expert']] == [16, 18, 19, 26]
        # 1 ms frame spacing; the response time is response - request.
        assert t[4]['mctpc.response_time'] == '0.003000000'
        assert t[22]['mctpc.response_time'] == '0.002000000'
        assert all(r['mctpc.response_time'] for n, r in t.items() if r['mctpc.response_to'])

    def test_first_pass_links_backward_only(self, fields_table):
        """Pairing is decided in the first pass: response_to and the notes
        are the same without -2, which only adds the forward response_in."""
        one, two = self.table(fields_table, False), self.table(fields_table)
        for field in ('mctpc.response_to', 'mctpc.response_time', '_ws.expert'):
            assert column(one, field) == column(two, field), field
        assert not column(one, 'mctpc.response_in')

    def test_expert_census(self, tshark_fields):
        """Only the planted conditions raise experts in this section."""
        stdout = tshark_fields(self.FILE, f'{frames_in(PAIRING)} && {OTHER_EXPERTS}',
                               fields=('frame.number', '_ws.expert.message'), separator='|')
        rows = {int(n) - PAIRING[0] + 1: other_expert_text(m)
                for n, m in (line.split('|', 1) for line in stdout.splitlines())}
        assert rows == {
            28: ("MCTP control message payload of 72 bytes exceeds the 64-byte baseline "
                 "transmission unit (DSP0236 11.6),"
                 "Physical address size 1 differs from the 2 bytes that media type "
                 "0x0b's transport binding defines"),
            30: ("Physical address size 2 differs from the 3 bytes that media type "
                 "0x41's transport binding defines"),
            34: ','.join([('Invalid version alpha byte: it must be 00h or an ASCII letter '
                          '(DSP0236 section 12.7.2)')] * 2),
            35: ('Integrity Check bit set on an MCTP control message; DSP0236 '
                 'section 11.4.2 requires 0b'),
        }

    def test_physical_addresses(self, dissect_pdml):
        """DSP0237 Tables 2/3 (SMBus/I2C 01h-05h, [7:1] and a reserved bit),
        DSP0238 Tables 3-5 (PCIe bus, device/function or ARI function;
        Flit Mode adds the segment) and DSP0233 Table 5 (I3C 30h, [7:1]).
        Media with no binding (06h) and wrong sizes stay raw."""
        packets = pdml_section(dissect_pdml(self.FILE), PAIRING).packets

        def decoded(frame, raw):
            out = []
            for node in packets[frame].findall(f".//field[@name='{raw}']"):
                out.append((node.get('value'), {
                    c.get('name').rsplit('.', 1)[1]: int(c.get('show'), 0)
                    for c in node.findall("./field")
                    if c.get('name', '').startswith('mctpc.phys_addr.')}))
            return out

        assert decoded(28, 'mctpc.get_routing.addr') == [
            ('52', {'smbus': 0x29, 'rsvd': 0}),
            ('53', {'smbus': 0x29, 'rsvd': 1}),
            ('1b0a', {'bus': 0x1b, 'device': 1, 'function': 2, 'ari_function': 0x0a}),
            ('ffff', {'bus': 0xff, 'device': 0x1f, 'function': 7, 'ari_function': 0xff}),
            ('01021a', {'segment': 1, 'bus': 2, 'device': 3, 'function': 2,
                        'ari_function': 0x1a}),
            ('10', {'i3c': 0x08, 'rsvd': 0}),
            ('50', {}),
            ('1b', {}),
        ]
        assert decoded(30, 'mctpc.resolve_uuid.addr') == [
            ('11', {'i3c': 0x08, 'rsvd': 1}),
            ('0102', {}),
        ]
        # The size expert hangs off the raw address it describes.
        addrs = packets[28].findall(".//field[@name='mctpc.get_routing.addr']")
        assert [bool(a.findall(".//field[@name='mctpc.phys_addr.size_mismatch']"))
                for a in addrs] == [False] * 7 + [True]

    def test_query_hop_transmission_units(self, dissect_pdml):
        """Table 32: each TU is 64 + 16 x value bytes."""
        packets = pdml_section(dissect_pdml(self.FILE), PAIRING).packets
        assert [n.get('showname') for n in packets[32].iter('field')
                if n.get('name') in ('mctpc.query_hop.in_tu', 'mctpc.query_hop.out_tu')] == [
            'Maximum incoming transmission unit: 64 bytes (0x0000)',
            'Maximum outgoing transmission unit: 1048624 bytes (0xffff)']

    def test_version_alpha(self, dissect_pdml):
        """12.7.2: the alpha byte is 00h or an ASCII letter; '0' and 7Fh
        are not."""
        packets = pdml_section(dissect_pdml(self.FILE), PAIRING).packets
        entries = packets[34].findall(".//field[@name='mctpc.get_ver.entry']")
        assert [bool(e.findall(".//field[@name='mctpc.get_ver.entry.invalid_alpha']"))
                for e in entries] == [False, False, False, True, True]


class TestMctpControlSmbusPairing:
    """The SMBUS_PAIRING section (the generator's _packets_smbus_pairing):
    null-EID requests pair by SMBus address, a broadcast takes one response
    per responder, and the Tables 24/25/32 values that are not allowed."""

    FILE = CAPTURE
    LINKS = ('mctpc.response_in', 'mctpc.response_to')
    FIELDS = LINKS + (UNMATCHED, '_ws.expert', 'mctpc.invalid_value')

    def table(self, fields_table, two_pass=True):
        return section(fields_table(self.FILE, self.FIELDS, two_pass=two_pass),
                       SMBUS_PAIRING, self.LINKS)

    def test_links(self, fields_table):
        """F1/F2 share requester, tag, IID and command and differ only in
        the slave address; F5 and F9 repeat an answer already given."""
        t = self.table(fields_table)
        assert sorted(t) == list(range(1, 14))
        assert {n: r['mctpc.response_to'] for n, r in t.items() if r['mctpc.response_to']} == {
            3: '2', 4: '1', 7: '6', 8: '6'}
        assert {n: r['mctpc.response_in'] for n, r in t.items() if r['mctpc.response_in']} == {
            1: '4', 2: '3', 6: '7'}
        assert [n for n, r in t.items() if r[UNMATCHED] is not None and
                UNMATCHED_TEXT in r['_ws.expert']] == [5, 9]

    def test_first_pass_matches(self, fields_table):
        one, two = self.table(fields_table, False), self.table(fields_table)
        for field in ('mctpc.response_to', '_ws.expert'):
            assert column(one, field) == column(two, field), field

    def test_invalid_values(self, tshark_fields):
        stdout = tshark_fields(self.FILE, f'{frames_in(SMBUS_PAIRING)} && {OTHER_EXPERTS}',
                               fields=('frame.number', '_ws.expert.message'), separator='|')
        rows = {int(n) - SMBUS_PAIRING[0] + 1: other_expert_text(m)
                for n, m in (line.split('|', 1) for line in stdout.splitlines())}
        assert rows == {
            10: 'Target Endpoint ID 0x00 is reserved (DSP0236 Query Hop message)',
            11: 'Target Endpoint ID 0xff is reserved (DSP0236 Query Hop message)',
            12: 'Count of update entries is 1-based; 0 is invalid'
                ' (DSP0236 Routing Information Update message)',
            13: 'Undefined entry type 4 (DSP0236 Routing Information Update entry'
                ' format defines 0-3)',
        }


class TestMctpControlEidRanges:
    """The EID_RANGES section (the generator's _packets_eid_ranges): DSP0236
    Table 2's reserved EIDs 01h-07h in Set/Force EID (Table 14) and
    Allocate Endpoint IDs (Table 23)."""

    FILE = CAPTURE
    FIELDS = ('mctpc.invalid_value', '_ws.expert.message')
    MESSAGES: ClassVar = {
        1: 'Endpoint ID 0x05 is reserved, not available for assignment, for'
           ' Set EID (DSP0236 special endpoint IDs)',
        2: 'Endpoint ID 0x01 is reserved, not available for assignment, for'
           ' Force EID (DSP0236 special endpoint IDs)',
        6: 'Starting Endpoint ID 0x03: the pool 0x03-0x06 includes null or'
           ' reserved EIDs 00h-07h, not available for allocation (DSP0236 special endpoint IDs)',
        7: 'Starting Endpoint ID 0xfe with 2 EIDs runs past FEh, the last'
           ' assignable EID (DSP0236 special endpoint IDs)',
        15: 'First Endpoint ID 0x05 is reserved, not available for allocation'
            ' (DSP0236 special endpoint IDs)',
        16: 'First Endpoint ID 0xff is the broadcast EID, not available for'
            ' allocation (DSP0236 special endpoint IDs)',
        18: 'EID setting 0x05 is reserved, not available for assignment'
            ' (DSP0236 special endpoint IDs)',
    }

    def table(self, fields_table, two_pass=False):
        return section(fields_table(self.FILE, self.FIELDS, two_pass=two_pass),
                       EID_RANGES)

    def test_reserved_eids(self, fields_table):
        t = self.table(fields_table)
        assert [n for n, r in t.items() if r['mctpc.invalid_value']] == sorted(self.MESSAGES)
        for n, row in t.items():
            assert other_expert_text(row['_ws.expert.message']) == \
                self.MESSAGES.get(n, ''), n

    def test_second_pass_matches(self, fields_table):
        assert self.table(fields_table, two_pass=True) == self.table(fields_table)


class TestMctpControlSize:
    """The SIZE section (the generator's _packets_size): a 65-byte control
    payload, one byte over DSP0236 11.6's 64-byte baseline."""

    FILE = CAPTURE
    FIELDS = ('mctpc.oversized', 'mctp.control.fragmented', '_ws.expert.message')

    def test_oversized(self, fields_table):
        for two_pass in (False, True):
            t = section(fields_table(self.FILE, self.FIELDS, two_pass=two_pass), SIZE)
            assert t[1]['mctpc.oversized'] != ''
            assert t[1]['mctp.control.fragmented'] == ''
            assert other_expert_text(t[1]['_ws.expert.message']) == (
                'MCTP control message payload of 65 bytes exceeds the 64-byte'
                ' baseline transmission unit (DSP0236 11.6)')


class TestMctpControlGetVersion:
    """The GET_VERSION section (the generator's _packets_get_version): a
    zero Version Number Entry count is invalid unless the matched request
    selected vendor-defined type 7Eh/7Fh (DSP0236 Table 18)."""

    FILE = CAPTURE
    LINKS = ('mctpc.response_to',)
    FIELDS = LINKS + ('mctpc.get_ver.count', 'mctpc.invalid_value', '_ws.expert.message')

    def table(self, fields_table, two_pass):
        return section(fields_table(self.FILE, self.FIELDS, two_pass=two_pass),
                       GET_VERSION, self.LINKS)

    def test_zero_count(self, fields_table):
        for two_pass in (False, True):
            t = self.table(fields_table, two_pass)
            assert column(t, 'mctpc.response_to') == {2: '1', 4: '3', 6: '5', 8: '7', 10: '9'}
            assert column(t, 'mctpc.get_ver.count') == {
                2: '0', 4: '1', 6: '0', 8: '0', 11: '0'}
            assert [n for n, r in t.items() if r['mctpc.invalid_value']] == [2]
            assert {n: other_expert_text(r['_ws.expert.message'])
                    for n, r in t.items() if other_expert_text(r['_ws.expert.message'])} == {
                2: 'Version Number Entry count is 1-based; 0 is invalid'
                   ' (DSP0236 Get MCTP Version Support message)'}
            assert UNMATCHED_TEXT in t[11]['_ws.expert.message']


class TestMctpControlResponseValues:
    """The RESPONSE_VALUES section (the generator's _packets_response_values):
    control in the Table 19 additional-type list, and reserved or broadcast
    EIDs reported by Get EID (Table 15) and Set EID (Table 14)."""

    FILE = CAPTURE
    # _ws.expert, not .message: other_expert_text needs the prefixes to drop
    # the unmatched-response note from these standalone responses.
    FIELDS = ('mctpc.get_msg_types.type', 'mctpc.invalid_value', '_ws.expert')
    MESSAGES: ClassVar = {
        1: 'MCTP control is implied and excluded from the additional message'
           ' types (DSP0236 Get Message Type Support message)',
        4: 'Endpoint ID 0x01 is reserved, not available for assignment (DSP0236 special endpoint IDs)',
        5: 'Endpoint ID 0x07 is reserved, not available for assignment (DSP0236 special endpoint IDs)',
        8: 'Endpoint ID 0xff is the broadcast EID, not available for assignment'
           ' (DSP0236 special endpoint IDs)',
        10: 'EID setting 0x01 is reserved, not available for assignment (DSP0236 special endpoint IDs)',
        11: 'EID setting 0x07 is reserved, not available for assignment (DSP0236 special endpoint IDs)',
        14: 'EID setting 0xff is the broadcast EID, not available for assignment'
            ' (DSP0236 special endpoint IDs)',
    }

    def test_invalid_values(self, fields_table):
        for two_pass in (False, True):
            t = section(fields_table(self.FILE, self.FIELDS, two_pass=two_pass),
                        RESPONSE_VALUES)
            assert [n for n, r in t.items() if r['mctpc.invalid_value']] == sorted(self.MESSAGES)
            for n, row in t.items():
                assert other_expert_text(row['_ws.expert']) == (
                    f'Expert Info (Warning/Protocol): {self.MESSAGES[n]}'
                    if n in self.MESSAGES else ''), n
            assert column(t, 'mctpc.get_msg_types.type') == {1: '0x00,0x04', 2: '0x04'}

    def test_expert_on_the_offending_item(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), RESPONSE_VALUES)
        for n, name in ((1, 'mctpc.get_msg_types.type'), (4, 'mctpc.get_eid.eid'),
                        (14, 'mctpc.set_eid.eid_setting')):
            items = [f for f in pdml.packets[n].findall(f".//field[@name='{name}']")
                     if f.find(".//field[@name='mctpc.invalid_value']") is not None]
            assert len(items) == 1, n
        assert pdml.packets[1].findall(
            ".//field[@name='mctpc.get_msg_types.type']")[0].get('show') == '0x00'
