#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
"""TCG Storage (packet-tcg-storage.c) tests, reached through NVMe-MI Security
Send/Receive.  All captures come from tools/gen-nvme-mi-test-capture.py; each
class describes its own.
"""

import subprocess
from collections import Counter
from functools import partial
from pathlib import Path
from typing import ClassVar

import dissection_helpers as helpers
import pytest
from dissection_helpers import FRAME_LINKS, column, frame_in

CAPTURES = (
    'nvme-mi-security.pcapng', 'nvme-mi-tcg.pcapng',
    'nvme-mi-tcg-field-checks.pcapng',
)


section = partial(helpers.section, links=FRAME_LINKS)
pdml_section = partial(helpers.pdml_section, links=FRAME_LINKS)
at = partial(helpers.at, links=FRAME_LINKS)
in_section = partial(helpers.in_section, links=FRAME_LINKS)


#: A deferral that a complete synchronous ComPacket cannot satisfy is
#: rejected and a regular session is aborted (Core 3.3.10.3(a)).
ATOM_REJECTED = ('tcg-storage.tok.spans_compacket && !tcg-storage.tok.fragment'
                 ' && !tcg-storage.tok.uid')
ATOM_ABORTED = ('tcg-storage.data && !tcg-storage.subpacket && !tcg-storage.tok.uid'
                ' && !_ws.expert && _ws.col.info contains'
                ' "session aborted after an atom spanning a synchronous ComPacket"')

PI_CHECKSUM, PI_SEQUENCE, PI_UNDECODED, PI_MALFORMED, PI_PROTOCOL = (
    0x01000000, 0x02000000, 0x05000000, 0x07000000, 0x09000000)
PI_NOTE, PI_WARN = 0x00400000, 0x00600000

#: (group, severity) of every TCG Storage expert in CAPTURES.
EXPERT_CLASS = {
    'tcg-storage.compacket.comid_mismatch': (PI_PROTOCOL, PI_WARN),
    'tcg-storage.comid_mgmt.comid_mismatch': (PI_PROTOCOL, PI_WARN),
    'tcg-storage.subpacket.credit.invalid_length': (PI_MALFORMED, PI_WARN),
    'tcg-storage.subpacket.kind.reserved': (PI_PROTOCOL, PI_WARN),
    'tcg-storage.tper_reset.if_recv': (PI_PROTOCOL, PI_NOTE),
    'tcg-storage.l0.feat.invalid_length': (PI_MALFORMED, PI_WARN),
    'tcg-storage.l0.feat.length_not_aligned': (PI_MALFORMED, PI_WARN),
    'tcg-storage.length_overrun': (PI_MALFORMED, PI_WARN),
    'tcg-storage.packet.seq_gap': (PI_SEQUENCE, PI_WARN),
    'tcg-storage.tok.delimiter': (PI_MALFORMED, PI_WARN),
    'tcg-storage.tok.reserved_token': (PI_PROTOCOL, PI_WARN),
    'tcg-storage.tok.spans_compacket': (PI_PROTOCOL, PI_WARN),
    'tcg-storage.tok.status_type': (PI_MALFORMED, PI_WARN),
    'tcg-storage.tok.zero_length': (PI_MALFORMED, PI_WARN),
    'tcg-storage.transfer_short': (PI_UNDECODED, PI_NOTE),
    'tcg-storage.truncated': (PI_MALFORMED, PI_WARN),
    'tcg-storage.txn.status_type': (PI_MALFORMED, PI_WARN),
    'nvme.security.secp_send_undefined': (PI_PROTOCOL, PI_WARN),
    'nvme.security.secp_nvme_undefined': (PI_PROTOCOL, PI_WARN),
}


def expert_name(expert):
    """The expert field of a PDML _ws.expert node."""
    name, = (n.get('name') for n in expert if not n.get('name').startswith('_ws.expert.'))
    return name


def expert_anchors(packet):
    """Counter of (expert field, parent field) over a PDML packet's experts."""
    parents = {child: parent for parent in packet.iter() for child in parent}
    return Counter((expert_name(e), parents[e].get('name'))
                   for e in packet.iter('field') if e.get('name') == '_ws.expert')


def tcg_anchors(packets):
    """{frame: expert_anchors} of the TCG Storage experts in PDML packets."""
    anchors = {}
    for frame, packet in packets.items():
        found = Counter({key: count for key, count in expert_anchors(packet).items()
                         if key[0].startswith('tcg-storage.')})
        if found:
            anchors[frame] = found
    return anchors


def expert_census(packets):
    """{expert field: {frame: count}} over PDML packets."""
    census = {}
    for frame, packet in packets.items():
        for (name, _), count in expert_anchors(packet).items():
            census.setdefault(name, Counter())[frame] += count
    return census


def pcapng_sections(data):
    """A merged capture's sections as (bytes, frame count) pairs."""
    import struct
    sections = []
    offset = 0
    while offset < len(data):
        kind, length = struct.unpack_from('<II', data, offset)
        assert length >= 12
        assert struct.unpack_from('<I', data, offset + length - 4)[0] == length
        if kind == 0x0A0D0D0A:
            sections.append([offset, 0])
        sections[-1][1] += kind == 6
        offset += length
    assert offset == len(data)
    ends = [start for start, _ in sections[1:]] + [len(data)]
    return [(data[start:end], frames) for (start, frames), end in zip(sections, ends)]


@pytest.fixture(scope='module')
def generator():
    """The globals of tools/gen-nvme-mi-test-capture.py."""
    import runpy
    return runpy.run_path(str(Path(__file__).resolve().parents[1]
                              / 'tools' / 'gen-nvme-mi-test-capture.py'))


def test_tcg_capture_is_generated(generator, capture_file):
    """nvme-mi-tcg.pcapng is the generator's sections, in order."""
    sections = pcapng_sections(Path(capture_file('nvme-mi-tcg.pcapng')).read_bytes())
    assert [data for data, _ in sections] == [
        generator['section_bytes'](builder) for builder in generator['tcg_sections']()]


def section_bytes(generator, packets, base):
    """The pcapng section the generator writes for packets from time base."""
    rows = [p if isinstance(p, tuple) else (p,) for p in packets]
    interfaces = any(isinstance(row[0], int) for row in rows)
    data = generator['shb']() + generator['idb']()
    if interfaces:
        data += generator['idb'](link_type=1)
    for i, row in enumerate(rows):
        interface, packet, *original = row if interfaces else (0, *row)
        data += generator['epb'](packet, (base + i) * 1_000_000,
                                 origlen=original[0] if original else None,
                                 interface_id=interface)
    return data


def generated_section(generator, builder, index, file, **options):
    """(span, cases, packets) of section index, checked against the generator."""
    vectors, base = builder
    packets, cases = generator[vectors](**options)
    sections = pcapng_sections(Path(file).read_bytes())
    assert len(sections) > index
    assert sections[index] == (section_bytes(generator, packets, base), len(packets))
    first = sum(frames for _, frames in sections[:index]) + 1
    return (first, first + len(packets) - 1), cases, packets


def uids(value):
    """The integer UIDs in a -Tfields tcg-storage.tok.uid value."""
    return [int(u, 0) for u in value.split(',') if u]


@pytest.mark.parametrize('capture', CAPTURES)
def test_no_dissector_exceptions(tshark_fields, capture):
    assert tshark_fields(capture, '_ws.malformed.expert || _ws.dissector_bug').strip() == ''


@pytest.mark.parametrize('capture', CAPTURES)
def test_second_pass_matches_first(assert_pass_parity, capture):
    assert_pass_parity(capture)


@pytest.mark.parametrize('capture', CAPTURES)
def test_null_tree_experts(dissect_pdml, expert_tap_counts, capture):
    """The tree-less expert tap reports the same experts as a tree dissection."""
    pdml = dissect_pdml(capture)
    assert expert_tap_counts(capture) == Counter(
        message for frame in pdml.packets for message in pdml.experts(frame))


def test_expert_groups_and_severities(dissect_pdml):
    """Every TCG Storage expert has the group and severity in EXPERT_CLASS."""
    seen = set()
    for capture in CAPTURES:
        for packet in dissect_pdml(capture).packets.values():
            for expert in packet.iter('field'):
                if expert.get('name') != '_ws.expert':
                    continue
                name = expert_name(expert)
                if name.startswith('tcg-storage.') or name in EXPERT_CLASS:
                    group = int(expert.find("field[@name='_ws.expert.group']").get('show'))
                    severity = int(expert.find("field[@name='_ws.expert.severity']").get('show'))
                    assert (group, severity) == EXPERT_CLASS[name], name
                    seen.add(name)
    assert seen == EXPERT_CLASS.keys()


#: {expert field: {frame: count}} of the Level 0 and ComID validation section.
LEVEL0_CENSUS = {
    'tcg-storage.l0.feat.invalid_length': {
        frame: 1 for frame in (8, 10, 12, 18, 20, 22, 26, 28, 30, 32, 121, 123, 125,
                                167, 169, 171, 173)},
    'tcg-storage.length_overrun': {42: 1, 44: 1, 90: 1},
    'tcg-storage.truncated': {75: 1},
    'tcg-storage.transfer_short': {111: 1, 119: 3},
    'tcg-storage.l0.feat.length_not_aligned': {121: 1, 123: 1, 125: 1, 127: 1},
    'tcg-storage.subpacket.credit.invalid_length': {92: 1, 96: 1, 104: 1},
    'tcg-storage.subpacket.kind.reserved': {98: 1},
    'tcg-storage.comid_mgmt.comid_mismatch': {frame: 1 for frame in (151, 152, 155, 156, 159)},
}


class TestTcgStorageLevel0AndComIdValidation:
    """Level 0 Discovery, ComID management and subpacket validation (Core 3.3.6, 3.3.4.3)."""

    FILE = 'nvme-mi-tcg.pcapng'
    SECTION = 1

    def test_fixture_hash_and_frame_map(self, capture_file, generator):
        span, cases, _packets = generated_section(
            generator, ('tcg_m5_validation_vectors', 1718000000), 0,
            capture_file(self.FILE))
        assert span == self.SPAN
        assert len(cases) == 92
        assert [frame for frames in cases.values() for frame in frames] == list(range(1, 184))
        assert cases['get-al2'] == (108, 109)
        assert cases['state-pad-recovery'] == (101, 102)
        assert cases['state-credit-recovery'] == (105, 106)
        assert {name: frames for name, frames in cases.items() if name.startswith('verify-')} == {
            'verify-partial-body': (59, 60),
            'verify-dates': (61, 62),
            'verify-no-rtc': (128, 129),
            'verify-zero-allocation': (130, 131),
            'verify-zero-expiry': (132, 133),
            'verify-zero-reset': (134, 135),
            'verify-invalid-dates': (136, 137),
            'verify-inactive-dates': (138, 139),
            'verify-issued-dates': (140, 141),
            'verify-invalid-no-rtc': (142, 143),
            'verify-inactive-no-rtc': (144, 145),
            'verify-no-rtc-selected': (146, 147),
            'verify-no-rtc-transfer-short': (148, 149),
        }
        assert {name: frames for name, frames in cases.items()
                if name.startswith(('mismatch-', 'match-')) or name == 'no-response-zero'} == {
            'mismatch-recv': (150, 151),
            'mismatch-send': (152, 153),
            'mismatch-recv-code-0': (154, 155),
            'mismatch-send-zero': (156, 157),
            'mismatch-recv-zero': (158, 159),
            'no-response-zero': (160, 161),
            'match-recv-ext': (162, 163),
            'match-send-ext': (164, 165),
        }
        assert {name: frames for name, frames in cases.items()
                if name.startswith(('geometry-', 'opal-', 'fixed-'))} == {
            'geometry-v1-length-24': (166, 167),
            'geometry-v1-length-32': (168, 169),
            'opal-v2-length-12': (170, 171),
            'opal-v2-length-20': (172, 173),
            'fixed-lengths-valid': (174, 175),
            'geometry-v2-future': (176, 177),
            'opal-v3-future': (178, 179),
            'geometry-transfer-short': (180, 181),
            'opal-transfer-short': (182, 183),
        }

    def test_exact_experts_and_anchors(self, dissect_pdml):
        packets = pdml_section(dissect_pdml(self.FILE), self.SPAN).packets
        assert len(packets) == 183
        assert expert_census(packets) == LEVEL0_CENSUS
        anchors = Counter()
        for packet in packets.values():
            anchors.update(expert_anchors(packet))
        assert anchors == {
            ('tcg-storage.l0.feat.invalid_length', 'tcg-storage.l0.feat.length'): 17,
            ('tcg-storage.length_overrun', 'tcg-storage.l0.length'): 1,
            ('tcg-storage.length_overrun', 'tcg-storage.data'): 1,
            ('tcg-storage.length_overrun', 'tcg-storage.subpacket.length'): 1,
            ('tcg-storage.truncated', 'tcg-storage.data'): 1,
            ('tcg-storage.transfer_short', 'tcg-storage.data'): 1,
            ('tcg-storage.transfer_short', 'tcg-storage.compacket'): 1,
            ('tcg-storage.transfer_short', 'tcg-storage.packet'): 1,
            ('tcg-storage.transfer_short', 'tcg-storage.subpacket'): 1,
            ('tcg-storage.l0.feat.length_not_aligned', 'tcg-storage.l0.feat.length'): 4,
            ('tcg-storage.subpacket.credit.invalid_length', 'tcg-storage.subpacket.length'): 3,
            ('tcg-storage.subpacket.kind.reserved', 'tcg-storage.subpacket.kind'): 1,
            ('tcg-storage.comid_mgmt.comid_mismatch', 'tcg-storage.comid_mgmt.comid'): 5,
        }
        # F26 is Locking Version 2 (Pyrite SSC 2.01 Table 5), a known version
        # whose Length 16 is not 0x0C; the expert text covers it.
        assert [node.get('show') for node in packets[26].findall(
            ".//field[@name='_ws.expert.message']")] == [
            'TPer v1, Locking v1-v3 and SIIS v1 feature data must be exactly 12 bytes']
        for frame in (16, 36, 38, 40):
            marker, = packets[frame].findall(
                ".//field[@name='tcg-storage.l0.unsupported_version']")
            assert marker.get('show') == 'True', frame
            versions = [
                node for node in packets[frame].iter('field')
                if node.get('name') in ('tcg-storage.l0.major_version',
                                        'tcg-storage.l0.minor_version',
                                        'tcg-storage.l0.feat.version')
            ]
            assert any('version not recognized' in node.get('showname', '').lower()
                       for node in versions), frame
            assert not any('tcg-storage.l0.unsupported_version' in message
                           for message in packets[frame].findall(
                               ".//field[@name='_ws.expert.message']")), frame
        assert expert_anchors(packets[42]) == {
            ('tcg-storage.length_overrun', 'tcg-storage.l0.length'): 1}
        assert expert_anchors(packets[90]) == {
            ('tcg-storage.length_overrun', 'tcg-storage.subpacket.length'): 1}

    def test_exact_malformed_census(self, tshark_fields):
        tshark_fields = in_section(tshark_fields, self.SPAN)
        # Fixed v1 descriptor Length contradictions are structural errors,
        # unlike selected/transfer-short prefixes and future feature versions.
        expected = {8, 10, 12, 18, 20, 22, 26, 28, 30, 32, 42, 44, 75, 90, 92, 96, 104,
                    121, 123, 125, 127, 167, 169, 171, 173}
        assert set(map(int, tshark_fields(self.FILE, '_ws.malformed').split())) == expected
        assert not tshark_fields(self.FILE, '_ws.malformed.expert').strip()

    def test_positive_twins_and_raw_boundaries(self, assert_frames_match, tshark_fields):
        tshark_fields = in_section(tshark_fields, self.SPAN)
        assert_frames_match(self.FILE, at(self.SPAN, [
            (2, 'count(tcg-storage.l0.feat.code) == 3 && !_ws.expert'),
            (38, '!tcg-storage.l0.feat && len(tcg-storage.data) == 88 && !_ws.malformed'),
            (40, 'count(tcg-storage.l0.feat.code) == 3 && !_ws.malformed'),
            *[(frame, '!tcg-storage.l0.major_version && !tcg-storage.l0.feat')
              for frame in (42, 44)],
            (46, '!tcg-storage.l0.feat && !_ws.expert'),
            (48, 'tcg-storage.l0.feat.length == 12 && !tcg-storage.l0.feat.tper.flags && !_ws.expert'),
            (50, 'tcg-storage.l0.feat.data == a5:a5:a5:a5 && !_ws.expert'),
            (52, 'len(tcg-storage.padding) == 4 && !_ws.expert'),
            (54, '!tcg-storage.comid_mgmt.data && len(tcg-storage.padding) == 4 && !_ws.expert'),
            (56, 'tcg-storage.comid_mgmt.data == a1:a2:a3:a4 && len(tcg-storage.padding) == 4'),
            (58, '!tcg-storage.comid_mgmt.data && !tcg-storage.padding'),
            (60, ('tcg-storage.comid_mgmt.data == 00:00:00:03'
                 ' && !tcg-storage.comid_mgmt.comid_state && !_ws.expert')),
            (64, 'tcg-storage.comid_mgmt.data == a1:a2:a3:a4 && len(tcg-storage.padding) == 4 && !_ws.expert'),
            (66, 'len(tcg-storage.comid_mgmt.data) == 4 && !tcg-storage.padding && !_ws.expert'),
            *[(frame, 'len(tcg-storage.padding) == 4 && !tcg-storage.comid_mgmt.data && !_ws.expert')
              for frame in (67, 69)],
            *[(frame, ('tcg-storage.comid_mgmt.request_data == 00:00:00:00'
                      ' && !tcg-storage.comid_mgmt.data && !tcg-storage.padding && !_ws.expert'))
              for frame in (71, 73)],
            (82, 'tcg-storage.comid_mgmt.available_data_length == 0 && !_ws.expert'),
            *[(frame, 'tcg-storage.get_comid.ext_comid == 0x10000001 && !_ws.expert')
              for frame in (84, 113)],
            (86, 'tcg-storage.subpacket.pad == 00:00:00 && !_ws.expert'),
            (90, 'tcg-storage.length_overrun && !tcg-storage.subpacket.pad && len(tcg-storage.padding) == 3'),
            (94, 'tcg-storage.subpacket.credit == 0 && !_ws.expert'),
            *[(frame, '!tcg-storage.subpacket.credit') for frame in (92, 96, 104)],
            (98, ('tcg-storage.data == a5:a5:a5:a5:a5:a5:a5:a5'
                  ' && tcg-storage.subpacket.kind.reserved && !_ws.malformed')),
            *[(frame, 'count(tcg-storage.tok.uid) == 2 && tcg-storage.tok.status == 0 && !_ws.expert')
              for frame in (102, 106)],
            *[(frame, ('tcg-storage.data == 10:00 && !tcg-storage.get_comid.ext_comid'
                      ' && !tcg-storage.comid_mgmt.request_code && !_ws.malformed'))
              for frame in (109, 111, 115)],
            (117, 'tcg-storage.comid_mgmt.available_data_length == 0 && !_ws.expert'),
            (119, 'len(tcg-storage.subpacket.pad) == 2 && !_ws.malformed'),
            *[(frame, ('len(tcg-storage.comid_mgmt.data) == 16'
                      ' && !tcg-storage.comid_mgmt.comid_state'
                      ' && !tcg-storage.comid_mgmt.date.year'
                      ' && !tcg-storage.comid_mgmt.time_allocated'
                      ' && !tcg-storage.comid_mgmt.time_expiry'
                      ' && !tcg-storage.comid_mgmt.time_since_reset && !_ws.expert'))
              for frame in (147, 149)],
        ]))
        # Later TPer versions keep the backward-compatible flags byte (Core
        # 2.01 3.3.6.3.1.2); SIIS later versions stay raw, and so does a
        # Locking Version 2 body whose Length is not 0x0C.
        for frame, data in ((16, 'a5' * 15), (26, 'a5' * 16), (36, 'a5' * 16)):
            assert tshark_fields(self.FILE, f'frame.number == {frame}',
                                  fields=('tcg-storage.l0.feat.data',)).strip() == data
        response = tshark_fields(self.FILE, 'frame.number == 54', fields=('_ws.col.info',))
        request = tshark_fields(self.FILE, 'frame.number == 73', fields=('_ws.col.info',))
        assert 'No Response Available' in response
        assert 'Unknown request code' in request and 'No Response Available' not in request

    def test_extents_and_fraction_schema(self, field_registry, dissect_pdml):
        packets = pdml_section(dissect_pdml(self.FILE), self.SPAN).packets
        for frame, field, positions in (
                (2, 'tcg-storage.l0.feat.reserved_tail', [(53, 11), (69, 11), (86, 10)]),
                (4, 'tcg-storage.l0.feat.code', [(48, 2), (64, 2)]),
                (38, 'tcg-storage.data', [(8, 88)]),
                (42, 'tcg-storage.data', [(4, 44)]),
                (52, 'tcg-storage.level0_discovery', [(0, 96)]),
                (52, 'tcg-storage.padding', [(96, 4)]),
                (56, 'tcg-storage.comid_mgmt.data', [(12, 4)]),
                (56, 'tcg-storage.padding', [(16, 4)]),
                (62, 'tcg-storage.comid_mgmt.date.fraction', [(23, 2), (33, 2), (43, 2)]),
                (64, 'tcg-storage.comid_mgmt.data', [(12, 4)]),
                (64, 'tcg-storage.padding', [(16, 4)]),
                (71, 'tcg-storage.comid_mgmt.request_data', [(8, 4)]),
                (73, 'tcg-storage.comid_mgmt.request_data', [(8, 4)]),
                (88, 'tcg-storage.subpacket.pad', [(57, 3)]),
                (90, 'tcg-storage.subpacket.length', [(52, 4)]),
                (90, 'tcg-storage.padding', [(57, 3)]),
                (96, 'tcg-storage.data', [(56, 8)]),
                (109, 'tcg-storage.data', [(0, 2)]),
                (119, 'tcg-storage.subpacket.pad', [(57, 2)]),
                (121, 'tcg-storage.l0.feat.data', [(52, 1)]),
                (147, 'tcg-storage.comid_mgmt.data', [(12, 16)]),
                (149, 'tcg-storage.comid_mgmt.data', [(12, 16)])):
            packet = packets[frame]
            base = int(packet.find(".//proto[@name='tcg-storage']").get('pos'))
            nodes = packet.findall(f".//field[@name='{field}']")
            assert [(int(n.get('pos')) - base, int(n.get('size'))) for n in nodes] == positions
        fractions = packets[62].findall(".//field[@name='tcg-storage.comid_mgmt.date.fraction']")
        assert len(fractions) == 3
        assert all(n.get('show') == '500' and '500ms' in n.get('showname') for n in fractions)
        row = field_registry['tcg-storage.comid_mgmt.date.fraction']
        assert row[3:7] == ['FT_UINT16', 'tcg-storage', 'BASE_DEC', '0x0']
        assert row[7] == 'milliseconds, 0–999'

    @pytest.mark.parametrize('two_pass', (False, True))
    def test_comid_mgmt_comid_matches_spsp(self, assert_frames_match, tshark_fields, two_pass):
        """The payload ComID is the SPSP ComID in both directions (Core 3.3.4.7.1-2)."""
        one = 'tcg-storage.comid_mgmt.comid_mismatch && count(_ws.expert) == 1'
        receive = f'{one} && _ws.expert.message contains "Security Receive"'
        send = f'{one} && _ws.expert.message contains "Security Send"'
        assert_frames_match(self.FILE, at(self.SPAN, [
            (151, f'{receive} && tcg-storage.comid_mgmt.data == a1:a2:a3:a4'),
            (152, f'{send} && len(tcg-storage.padding) == 4'),
            (155, f'{receive} && tcg-storage.comid_mgmt.comid == 0x1001'),
            (156, (f'{send} && tcg-storage.comid_mgmt.request_data == 00:00:00:00'
                   ' && !tcg-storage.comid_mgmt.data && !tcg-storage.padding')),
            (159, f'{receive} && tcg-storage.comid_mgmt.request_code == 3'),
            (161, ('!_ws.expert && tcg-storage.comid_mgmt.comid == 0'
                   ' && tcg-storage.comid_mgmt.request_code == 0')),
            (163, ('!_ws.expert && tcg-storage.comid_mgmt.comid_ext == 0xbeef'
                   ' && tcg-storage.comid_mgmt.data == a1:a2:a3:a4')),
            (164, ('!_ws.expert && tcg-storage.comid_mgmt.comid_ext == 0xbeef'
                   ' && len(tcg-storage.padding) == 4')),
            (84, 'tcg-storage.get_comid.ext_comid == 0x10000001 && !_ws.expert'),
        ]), two_pass=two_pass)
        flagged = in_section(tshark_fields, self.SPAN)(
            self.FILE, 'tcg-storage.comid_mgmt.comid_mismatch', two_pass=two_pass)
        assert list(map(int, flagged.split())) == [151, 152, 155, 156, 159]

    @pytest.mark.parametrize('two_pass', (False, True))
    def test_fixed_version_lengths(self, assert_frames_match, tshark_fields, two_pass):
        """Geometry v1 and Opal SSC V2 v2 Lengths are exact (Opal SSC 2.30 Tables 5/6)."""
        geometry = ('tcg-storage.l0.feat.code == 0x0003 && !tcg-storage.l0.feat.geometry.flags'
                    ' && !tcg-storage.l0.feat.geometry.lbs')
        # Only the following Ruby descriptor decodes the Opal layout.
        opal = ('tcg-storage.l0.feat.code == 0x0203 && count(tcg-storage.l0.feat.opal2.base_comid) == 1'
                ' && tcg-storage.l0.feat.opal2.base_comid == 0x2000')
        bad = ('tcg-storage.l0.feat.invalid_length && count(_ws.expert) == 1'
               ' && count(tcg-storage.l0.feat.data) == 1')
        clean = '!tcg-storage.l0.feat.invalid_length && !_ws.malformed'
        assert_frames_match(self.FILE, at(self.SPAN, [
            *[(frame, (f'{bad} && {geometry} && len(tcg-storage.l0.feat.data) == {length}'
                       ' && tcg-storage.l0.feat.opal2.base_comid == 0x1000'
                       ' && tcg-storage.l0.feat.opal2.num_comids == 1'))
              for frame, length in ((167, 24), (169, 32))],
            *[(frame, (f'{bad} && {opal} && len(tcg-storage.l0.feat.data) == {length}'
                       ' && tcg-storage.l0.feat.code == 0x0304'))
              for frame, length in ((171, 12), (173, 20))],
            (175, (f'{clean} && !_ws.expert && tcg-storage.l0.feat.geometry.lbs == 512'
                   ' && tcg-storage.l0.feat.opal2.num_comids == 1'
                   ' && !tcg-storage.l0.unsupported_version')),
            # No specification defines Geometry Version 2 or Opal SSC V2
            # Version 3: marked, with the known fields still decoded.
            (177, (f'{clean} && tcg-storage.l0.feat.geometry.lbs == 512'
                   ' && tcg-storage.l0.unsupported_version')),
            (179, (f'{clean} && tcg-storage.l0.feat.opal2.num_comids == 1'
                   ' && tcg-storage.l0.unsupported_version')),
            (181, f'{clean} && tcg-storage.l0.feat.length == 28 && !tcg-storage.l0.feat.geometry.lbs'),
            (183, f'{clean} && tcg-storage.l0.feat.length == 16 && !tcg-storage.l0.feat.opal2.num_comids'),
        ]), two_pass=two_pass)
        messages = in_section(tshark_fields, self.SPAN)(
            self.FILE, 'tcg-storage.l0.feat.invalid_length && frame.number >= 166',
            fields=('_ws.expert.message',), two_pass=two_pass).splitlines()
        assert messages == [
            *[('Geometry Reporting Version 1 feature data must be exactly 28 bytes'
               " (Opal SSC 'Level 0 Discovery - Geometry Reporting Feature"
               f" Descriptor'); Length is {length}") for length in (24, 32)],
            *[('Opal SSC V2 Version 2 feature data must be exactly 16 bytes'
               " (Opal SSC 'Level 0 Discovery - Opal SSC V2 Feature Descriptor');"
               f' Length is {length}') for length in (12, 20)],
        ]

    def test_comid_date_tuple_state(self, dissect_pdml):
        """Date tuples never imply RTC support or valid dates (Core Tables 33/34)."""
        import struct
        date = bytes.fromhex('07ea09050c223801f400')
        expiry = bytes.fromhex('07ea09050c233801f400')
        zero = bytes(10)
        stamp = ': 2026-09-05 12:34:56.500'
        later = ': 2026-09-05 12:35:56.500'
        no_rtc = ': Unavailable (no real-time clock)'
        zero_date = ': Unavailable (zero date value)'
        invalid = ': Inapplicable (Extended ComID is Invalid)'
        inactive = ': Inapplicable (Extended ComID is Inactive)'
        cases = {
            62: (3, (date, expiry, date), (stamp, later, stamp)),
            129: (3, (zero, zero, zero), (no_rtc, no_rtc, no_rtc)),
            131: (3, (zero, expiry, date), (zero_date, later, stamp)),
            133: (3, (date, zero, date), (stamp, zero_date, stamp)),
            135: (3, (date, expiry, zero), (stamp, later, zero_date)),
            137: (0, (date, expiry, date), (invalid, invalid, stamp)),
            139: (1, (date, expiry, date), (inactive, inactive, stamp)),
            141: (2, (date, expiry, date), (stamp, later, stamp)),
            143: (0, (zero, zero, zero),
                  (invalid + '; no real-time clock', invalid + '; no real-time clock', no_rtc)),
            145: (1, (zero, zero, zero),
                  (inactive + '; no real-time clock', inactive + '; no real-time clock', no_rtc)),
        }
        date_fields = ('time_allocated', 'time_expiry', 'time_since_reset')
        components = (('year', 0, 2), ('month', 2, 1), ('day', 3, 1), ('hour', 4, 1),
                      ('minute', 5, 1), ('second', 6, 1), ('fraction', 7, 2), ('reserved', 9, 1))
        packets = pdml_section(dissect_pdml(self.FILE), self.SPAN).packets
        for frame, (state, raw_dates, annotations) in cases.items():
            packet = packets[frame]
            proto = packet.find(".//proto[@name='tcg-storage']")
            base = int(proto.get('pos'))
            assert packet.find(".//field[@name='_ws.expert']") is None, frame
            state_node = proto.find(".//field[@name='tcg-storage.comid_mgmt.comid_state']")
            assert int(state_node.get('show'), 0) == state
            assert (int(state_node.get('pos')) - base, int(state_node.get('size'))) == (12, 4)
            padding = proto.find(".//field[@name='tcg-storage.padding']")
            assert (int(padding.get('pos')) - base, int(padding.get('size'))) == (46, 2)
            for index, (field, raw, annotation) in enumerate(zip(date_fields, raw_dates, annotations)):
                nodes = proto.findall(f".//field[@name='tcg-storage.comid_mgmt.{field}']")
                assert len(nodes) == 1, (frame, field)
                node = nodes[0]
                assert node.get('value') == raw.hex(), (frame, field)
                assert node.get('showname').endswith(annotation), (frame, field, node.attrib)
                assert '0000-00-00' not in node.get('showname')
                offset = 16 + index * 10
                assert (int(node.get('pos')) - base, int(node.get('size'))) == (offset, 10)
                assert len(node.findall('field')) == len(components)
                for (name, relative, size), value in zip(components, struct.unpack('>HBBBBBHB', raw)):
                    child = node.find(f"./field[@name='tcg-storage.comid_mgmt.date.{name}']")
                    assert child is not None, (frame, field, name)
                    assert int(child.get('show'), 0) == value, (frame, field, name)
                    assert (int(child.get('pos')) - base, int(child.get('size'))) == \
                        (offset + relative, size)


class TestTcgStorageSessionState:
    """Session state: status lists, sequence numbers, modes and stack resets (Core 3.2, 3.3.10)."""

    # Section frames: F1-F26 subsystems and end of session, F27-F108 status
    # grammar, F109-F134 sequence numbering, F135-F170 communication modes,
    # F171-F250 stack reset generations, F251-F274 invalid Security Receive
    # requests and recovery.

    FILE = 'nvme-mi-tcg.pcapng'
    SECTION = 3
    SECURE = frozenset({10, 24, 25, 108, 184, 208, 212, 216, 234, 236, 246, 274})
    PLAIN = 'count(tcg-storage.tok.uid) == 2 && !tcg-storage.packet.secure_data && !_ws.expert'

    def test_subsystem_and_control_session(self, assert_frames_match, tshark_fields):
        tshark_fields = in_section(tshark_fields, self.SPAN)
        assert list(map(int, tshark_fields(self.FILE, 'nvme-mi').split())) == list(range(1, 275))
        assert_frames_match(self.FILE, at(self.SPAN, [
            (10, 'nvme-mi.admin.cqe_dw0 && tcg-storage.packet.secure_data && !tcg-storage.tok.uid'),
            (12, self.PLAIN),  # same IDs, distinct transport endpoint
            (13, 'tcg-storage.tok.control == 0xfa && !_ws.expert'),
            (15, 'tcg-storage.tok.uid == 0xff02 && tcg-storage.tok.host_status == 0'),
            (24, 'tcg-storage.packet.secure_data && !tcg-storage.tok.uid'),
            (25, 'tcg-storage.packet.secure_data && !tcg-storage.tok.uid'),
        ]))
        assert set(map(int, tshark_fields(self.FILE, 'tcg-storage.packet.secure_data').split())) == self.SECURE

    def test_complete_unsigned_status_lists(self, assert_frames_match, tshark_fields):
        tshark_fields = in_section(tshark_fields, self.SPAN)
        malformed = {34, 46, 58, 70, 82, 94}
        assert set(map(int, tshark_fields(self.FILE, 'tcg-storage.tok.status_type').split())) == malformed
        assert_frames_match(self.FILE, at(self.SPAN, [
            *[(frame, 'tcg-storage.tok.status == 0 && tcg-storage.tok.status_type')
              for frame in (34, 46, 58, 70, 82)],
            (94, '!tcg-storage.tok.status && tcg-storage.tok.status_type'),
            *[(frame, self.PLAIN) for frame in (36, 37, 48, 49, 60, 61, 72, 73, 84, 85, 96, 97)],
            (106, 'tcg-storage.tok.status == 0 && !_ws.expert'),
            (108, 'tcg-storage.packet.secure_data'),
        ]))

    def test_negotiated_sequence_numbering(self, assert_frames_match, tshark_fields):
        tshark_fields = in_section(tshark_fields, self.SPAN)
        assert_frames_match(self.FILE, at(self.SPAN, [
            (114, 'tcg-storage.tok.fragment && !tcg-storage.tok.uid'),
            *[(frame, 'tcg-storage.data && !tcg-storage.subpacket && !tcg-storage.tok.uid')
              for frame in (116, 120)],
            *[(frame, self.PLAIN) for frame in (118, 121, 124, 132, 134)],
        ]))
        assert set(map(int, tshark_fields(
            self.FILE, '_ws.col.info contains "previously acted-on sequence"').split())) == {116, 120}

    def test_synchronous_compacket_boundary(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            (164, 'tcg-storage.tok.fragment && !tcg-storage.tok.uid && !_ws.expert'),
            *[(frame, ATOM_REJECTED) for frame in (140, 152)],
            *[(frame, ATOM_ABORTED) for frame in (142, 154)],
            *[(frame, self.PLAIN) for frame in (144, 146, 156, 158, 166, 168, 170)],
        ]))

    def test_reset_generation_and_isolation(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            (186, 'tcg-storage.tok.fragment && !_ws.expert'),
            (206, 'tcg-storage.comid_mgmt.stack_reset_result == 1'),
            (210, 'tcg-storage.comid_mgmt.available_data_length == 0'),
            (214, 'tcg-storage.comid_mgmt.stack_reset_result == 0'),
            *[(frame, 'tcg-storage.packet.secure_data && !tcg-storage.tok.uid')
              for frame in (184, 208, 212, 216, 234, 236)],
            # A trusted Success resets the ComID even without a captured
            # request; later packets are decoded from the reset state.
            (218, 'tcg-storage.comid_mgmt.stack_reset_result == 0 && !_ws.expert'),
            (220, 'tcg-storage.tok.uid && !_ws.expert'),
        ]))

    def test_receive_request_contract(self, assert_frames_match, tshark_fields):
        tshark_fields = in_section(tshark_fields, self.SPAN)
        assert_frames_match(self.FILE, at(self.SPAN, [
            # DLEN 0 with AL != 0 selects no data (NVMe-MI 2.2 Figure 139);
            # DOFST at or past an SECP 00h-03h AL is outside the completion
            # data (SIIS 1.20 Table 24).
            (251, 'nvme-mi.admin.dlen == 0 && nvme-mi.admin.invalid_dlen'),
            (253, 'nvme-mi.admin.invalid_dofst'),
            (255, 'nvme-mi.admin.invalid_dlen'),
            (257, ('nvme-mi.admin.doff == 0x68 && nvme-mi.admin.invalid_dofst'
                  ' && count(_ws.expert) == 1')),
            (265, ('nvme-mi.admin.dlen == 101 && nvme.cmd.security_recv.dword11.al == 104'
                  ' && nvme-mi.admin.invalid_dlen')),
            (266, 'tcg-storage.tok.uid == 0xff05 && tcg-storage.tok.status == 0 && !_ws.expert'),
            (268, self.PLAIN),
            (269, self.PLAIN),
            (274, 'tcg-storage.packet.secure_data && !tcg-storage.tok.uid'),
        ]))


class TestTcgStorageSequenceAndComIdTracking:
    """Sequence gaps, status invalidation and ComID tracking (Core 3.2.3, 3.3.4)."""

    # Section frames: F1-F38 sequence gaps and retransmission; F39-F62 counter
    # exhaustion; F63-F122 Packet-wide status invalidation; F123-F152
    # underfilled selected responses; F153-F200 packets missing from the
    # capture; F201-F278 token stream resets at a ComPacket boundary;
    # F279-F304 control-session numbering; F305-F366 GET_COMID reissue;
    # F367-F420 mismatched ComIDs; F421-F468 status lists that abort a session.

    FILE = 'nvme-mi-tcg.pcapng'
    SECTION = 4
    SECURE = frozenset({82, 83, 90, 91, 112, 113, 120, 121, 138, 139, 144, 145,
                        194, 196, 198, 200, 246, 304, 396, 402})
    PLAIN = 'count(tcg-storage.tok.uid) == 2 && !tcg-storage.packet.secure_data && !_ws.expert'
    RAW = 'tcg-storage.data && !tcg-storage.subpacket && !tcg-storage.tok.uid && !_ws.expert'
    # The one sequence-gap Warning, by group and severity: a filter naming
    # tcg-storage.packet.seq_gap would not compile on a build without it.
    GAP = (' && count(_ws.expert) == 1 && _ws.expert.group == 0x02000000'
           ' && _ws.expert.severity == 0x00600000')
    # The one ComID-mismatch Warning, likewise (PI_PROTOCOL, PI_WARN).
    MISMATCH = (' && count(_ws.expert) == 1 && _ws.expert.group == 0x09000000'
                ' && _ws.expert.severity == 0x00600000')

    def test_frame_and_integrity_census(self, tshark_fields):
        tshark_fields = in_section(tshark_fields, self.SPAN)
        assert list(map(int, tshark_fields(self.FILE, 'nvme-mi').split())) == list(range(1, 469))
        assert list(map(int, tshark_fields(self.FILE, 'nvme-mi.mic.status == 1').split())) == \
            list(range(1, 469))
        assert set(map(int, tshark_fields(self.FILE, 'tcg-storage.packet.secure_data').split())) == \
            self.SECURE

    def test_sequence_gaps_reanchor(self, assert_frames_match, tshark_fields):
        """N+2 is acted on, not held, and cannot consume N's open atom (Core 3.2.3.3.1.2)."""
        tshark_fields = in_section(tshark_fields, self.SPAN)
        assert_frames_match(self.FILE, at(self.SPAN, [
            *[(frame, 'tcg-storage.tok.fragment && !tcg-storage.tok.uid && !_ws.expert')
              for frame in (6, 32, 36)],
            (8, 'tcg-storage.packet.seq == 3 && tcg-storage.tok.status == 0'
                ' && !tcg-storage.tok.uid && !tcg-storage.tok.fragment' + self.GAP),
            *[(frame, self.PLAIN) for frame in (9, 12, 14, 16, 26, 34, 38)],
            *[(frame, self.RAW) for frame in (18, 20, 22, 24)],
        ]))
        assert set(map(int, tshark_fields(
            self.FILE, '_ws.col.info contains "sequence gap"').split())) == {8, 60, 170, 178, 196}
        assert set(map(int, tshark_fields(
            self.FILE, '_ws.col.info contains "previously acted-on sequence"').split())) == \
            {18, 20, 22, 24, 44, 46, 62, 176, 200, 351, 365}

    def test_counter_wrap_is_not_modular_ordering(self, assert_frames_match):
        """Core 3.2.3.3.1.2: uint32 Max -> 0 aborts, not a successor."""
        assert_frames_match(self.FILE, at(self.SPAN, [
            (40, 'tcg-storage.packet.seq == 0xfffffffe && tcg-storage.tok.fragment && !_ws.expert'),
            (42, 'tcg-storage.packet.seq == 0xffffffff && tcg-storage.tok.fragment && !_ws.expert'),
            *[(frame, self.RAW) for frame in (44, 46)],
            (48, self.RAW + ' && _ws.col.info contains "sequence number wrapped; session aborted"'),
            *[(frame, self.RAW + ' && _ws.col.info contains "session aborted after sequence wrap"')
              for frame in (50, 51)],
            (54, self.PLAIN),
            (55, 'tcg-storage.tok.uid == 0xff02 && tcg-storage.tok.host_status == 0 && !_ws.expert'),
            (58, 'tcg-storage.tok.uid == 0xff03 && tcg-storage.tok.status == 0 && !_ws.expert'),
            (60, 'tcg-storage.packet.seq == 3 && count(tcg-storage.tok.uid) == 2'
                 ' && !tcg-storage.packet.secure_data' + self.GAP),
            (62, self.RAW + ' && tcg-storage.packet.seq == 1'),
        ]))

    def test_capture_loss_does_not_stall_session(self, assert_frames_match, tshark_fields):
        """Packets missing from the capture do not stall a numbered session."""
        tshark_fields = in_section(tshark_fields, self.SPAN)
        assert_frames_match(self.FILE, at(self.SPAN, [
            *[(frame, ('tcg-storage.tok.uid == 0xff02 && tcg-storage.tok.host_status == 0'
                      ' && !_ws.expert')) for frame in (157, 161)],
            *[(frame, ('tcg-storage.tok.uid == 0xff03 && tcg-storage.tok.status == 0'
                      ' && !_ws.expert')) for frame in (160, 164)],
            (166, self.PLAIN),
            (168, 'tcg-storage.tok.fragment && !tcg-storage.tok.uid && !_ws.expert'),
            # Seq 2's open UID does not swallow Seq 4's call.
            (170, 'tcg-storage.packet.seq == 4 && count(tcg-storage.tok.uid) == 2'
                  ' && !tcg-storage.tok.fragment && !tcg-storage.packet.secure_data' + self.GAP),
            *[(frame, self.PLAIN) for frame in (172, 174, 180)],
            (176, self.RAW + ' && tcg-storage.packet.seq == 5'
                  ' && _ws.col.info contains "previously acted-on sequence"'),
            (178, 'tcg-storage.packet.seq == 2 && count(tcg-storage.tok.uid) == 2'
                  ' && !tcg-storage.packet.secure_data' + self.GAP),
            # The secure session re-anchors through the secure_data commit.
            (194, 'tcg-storage.packet.secure_data && !_ws.expert'),
            (196, 'tcg-storage.packet.seq == 3 && tcg-storage.packet.secure_data' + self.GAP),
            # Not still held: HEAD gives F198 the same tree, but a gap label.
            (198, ('tcg-storage.packet.seq == 4 && tcg-storage.packet.secure_data && !_ws.expert'
                  ' && !(_ws.col.info contains "sequence gap")')),
            (200, ('tcg-storage.packet.secure_data && !_ws.expert'
                  ' && _ws.col.info contains "previously acted-on sequence"')),
        ]))
        # By name, after the rows above (see GAP).
        assert tshark_fields(self.FILE, 'tcg-storage.packet.seq_gap').split() == \
            ['8', '60', '170', '178', '196']
        assert tshark_fields(self.FILE, 'frame.number == 170',
                             fields=('_ws.expert.message',)).strip() == \
            'SeqNumber 4, expected 3; tracking resumes from this Packet (Core 3.2.3.3.1.2)'

    def test_spec_settled_synchronous_boundary(self, assert_frames_match):
        """A method spans ComPackets only until the mode is settled (Core 3.3.10.3)."""
        assert_frames_match(self.FILE, at(self.SPAN, [
            *[(frame, 'tcg-storage.tok.fragment && !tcg-storage.tok.uid && !_ws.expert')
              for frame in (202, 218, 230, 252, 256, 276)],
            # Settled synchronous: the atom cannot complete in its ComPacket.
            (210, ATOM_REJECTED),
            # No evidence: carried, also to another controller (SIIS 6.7.1.1).
            (203, 'nvme-mi.admin.ctrl-id == 2'),
            (204, self.PLAIN),
            (212, ATOM_ABORTED),  # not 4096 bytes owed to F210
            (220, self.PLAIN),  # Asynchronous on both sides before the reset
            (222, 'tcg-storage.comid_mgmt.stack_reset_result == 0 && !_ws.expert'),
            (228, 'tcg-storage.l0.feat.tper.async == 1'),
            (232, self.PLAIN),  # Async Supported = 1 settles nothing
            (234, 'tcg-storage.l0.feat.tper.async == 0'),
            (237, ('tcg-storage.tok.uid == 0xff02 && tcg-storage.tok.host_status == 0'
                  ' && !_ws.expert')),
            (240, 'tcg-storage.tok.uid == 0xff03 && tcg-storage.tok.status == 0 && !_ws.expert'),
            # StartSession was observed, so the trusted session is tracked.
            (246, 'tcg-storage.packet.secure_data && !tcg-storage.tok.uid && !_ws.expert'),
            # An observed Asynchronous = TRUE beats endpoint b's Level 0.
            (250, 'tcg-storage.tok.status == 0 && !_ws.expert'),
            (254, self.PLAIN),
            # With no evidence on endpoint c, other streams do not consume the
            # carried fragment; any that did would change the first UID.
            *[(frame, 'tcg-storage.tok.uint == 1 && !tcg-storage.tok.uid && !_ws.expert')
              for frame in (258, 260, 262, 264, 265)],
            (268, self.PLAIN + ' && tcg-storage.tok.uid == 0x00000000000000ff'),
            (270, '!tcg-storage.tok.status && !_ws.expert'),
            (272, 'tcg-storage.tok.status == 0x13 && !_ws.expert'),
            # Endpoint b's later Level 0 clears its sync-only state.
            (274, 'tcg-storage.l0.feat.tper.async == 1'),
            (278, self.PLAIN),
        ]))

    def test_properties_reanchors_control_session(self, assert_frames_match):
        """Properties start control-session numbering without a gap (Core 3.3.7.1.2)."""
        method = 'tcg-storage.tok.uid == {} && tcg-storage.tok.{}status == 0 && !_ws.expert'
        assert_frames_match(self.FILE, at(self.SPAN, [
            *[(frame, method.format('0xff01', 'host_') + ' && tcg-storage.packet.seq == 0')
              for frame in (279, 291)],
            *[(frame, method.format('0xff01', '') + ' && tcg-storage.packet.seq == 0')
              for frame in (282, 294)],
            *[(frame, method.format('0xff02', 'host_')) for frame in (283, 287, 295)],
            (286, method.format('0xff03', '') + ' && tcg-storage.packet.seq == 2'),
            (290, method.format('0xff03', '') + ' && tcg-storage.packet.seq == 3'),
            (298, method.format('0xff03', '') + ' && tcg-storage.packet.seq == 0'),
            (299, method.format('0xff04', 'host_')),
            (302, method.format('0xff05', '')),
            (304, 'tcg-storage.packet.secure_data && !tcg-storage.tok.uid && !_ws.expert'),
        ]))

    def test_get_comid_starts_new_generation(self, assert_frames_match):
        """A reissued Extended ComID starts from initial assumptions (Core 5.2.2.4)."""
        method = 'tcg-storage.tok.uid == {} && tcg-storage.tok.{}status == 0 && !_ws.expert'
        assert_frames_match(self.FILE, at(self.SPAN, [
            *[(frame, f'tcg-storage.get_comid.ext_comid == {value} && !_ws.expert')
              for frame, value in ((306, '0x10000034'), (320, '0x10000034'),
                                   (336, '0x10000035'), (346, '0'),
                                   (348, '0x1000ffff'), (350, '0x10000036'),
                                   (354, '0x1000ffff'), (364, '0x1000ffff'))],
            *[(frame, method.format('0xff02', 'host_') + f' && tcg-storage.packet.seq == {seq}')
              for frame, seq in ((311, 1), (321, 0), (341, 1), (359, 1))],
            *[(frame, method.format('0xff03', '') + f' && tcg-storage.packet.seq == {seq}')
              for frame, seq in ((314, 1), (324, 0), (344, 1), (362, 1))],
            (315, method.format('0xff04', 'host_')),
            (318, method.format('0xff05', '')),
            # The earlier issue's trusted session no longer routes as secure.
            *[(frame, self.PLAIN) for frame in (326, 328, 330)],
            (332, ATOM_REJECTED),
            (334, ATOM_ABORTED),
            *[(frame, self.RAW + ' && tcg-storage.packet.seq == 0'
                      ' && _ws.col.info contains "previously acted-on sequence"')
              for frame in (351, 365)],
        ]))

    def test_mismatched_comid_is_not_tracked(self, assert_frames_match, tshark_fields):
        """A ComPacket naming another ComID advances no state (SIIS Tables 23/24)."""
        method = 'tcg-storage.tok.uid == {} && tcg-storage.tok.{}status == 0'
        clean = ' && !_ws.expert'
        secure = 'tcg-storage.packet.secure_data && !tcg-storage.tok.uid && !_ws.expert'
        shown = 'count(tcg-storage.tok.uid) == 2 && !tcg-storage.packet.secure_data'
        assert_frames_match(self.FILE, at(self.SPAN, [
            (367, method.format('0xff02', 'host_') + self.MISMATCH),
            (380, method.format('0xff03', '') + self.MISMATCH),
            *[(frame, method.format('0xff02', 'host_') + clean) for frame in (377, 387)],
            *[(frame, method.format('0xff03', '') + clean) for frame in (370, 390)],
            *[(frame, method.format('0xff04', 'host_') + clean) for frame in (371, 381, 391)],
            *[(frame, method.format('0xff05', '') + clean) for frame in (374, 384, 394)],
            *[(frame, self.PLAIN) for frame in (376, 386)],
            *[(frame, secure) for frame in (396, 402)],
            (398, shown + ' && tcg-storage.compacket.comid == 0x1000' + self.MISMATCH),
            (400, shown + ' && tcg-storage.compacket.comid == 0x1001' + self.MISMATCH),
            *[(frame, method.format('0xff01', 'host_') + ' && tcg-storage.packet.seq == 0' + clean)
              for frame in (403, 411)],
            (406, method.format('0xff01', '') + self.MISMATCH),
            (414, method.format('0xff01', '') + clean),
            *[(frame, self.PLAIN + ' && tcg-storage.packet.seq == 0') for frame in (408, 410)],
            (416, shown + ' && tcg-storage.packet.seq == 1' + self.MISMATCH),
            (418, self.PLAIN + ' && tcg-storage.packet.seq == 1'),
            # The inactive-ComID label needs the addressed ComID (3.3.3.3).
            (420, 'tcg-storage.compacket.comid_ext == 0xffff && tcg-storage.compacket.length == 0'
                  ' && _ws.col.info contains "(no pending response data)"' + self.MISMATCH),
        ]))
        # By name, after the rows above (see GAP): only these frames, in
        # either TCG capture.
        assert tshark_fields(self.FILE, 'tcg-storage.compacket.comid_mismatch').split() == \
            [str(frame_in(self.SPAN, n)) for n in (367, 380, 398, 400, 406, 416, 420)]
        assert tshark_fields('nvme-mi-security.pcapng',
                             'tcg-storage.compacket.comid_mismatch').strip() == ''

    def test_status_invalidation_spans_subpackets_not_packets(self, assert_frames_match,
                                                             tshark_fields):
        """A displayed StartTrustedSession after the violation is not observed."""
        tshark_fields = in_section(tshark_fields, self.SPAN)
        assert_frames_match(self.FILE, at(self.SPAN, [
            *[(frame, ('tcg-storage.tok.status_type && count(tcg-storage.tok.uid) == 4'
                      ' && tcg-storage.tok.uid == 0xff04 && tcg-storage.tok.host_status == 0'))
              for frame in (71, 101)],
            *[(frame, 'tcg-storage.tok.uid == 0xff05 && tcg-storage.tok.status == 0 && !_ws.expert')
              for frame in (74, 80, 88, 104, 110, 118)],
            *[(frame, self.PLAIN) for frame in (76, 77, 106, 107)],
            # Completed methods before the violation survive.
            *[(frame, 'tcg-storage.packet.secure_data && !tcg-storage.tok.uid && !_ws.expert')
              for frame in (82, 83, 112, 113, 90, 91, 120, 121)],
            # Two Packets in one ComPacket: the second can observe methods.
            *[(frame, ('tcg-storage.tok.status_type && count(tcg-storage.packet.seq) == 2'
                      ' && tcg-storage.tok.uid == 0xff04 && tcg-storage.tok.host_status == 0'))
              for frame in (85, 115)],
        ]))
        assert set(map(int, tshark_fields(
            self.FILE, 'tcg-storage.tok.status_type').split())) == \
            {71, 85, 101, 115, 426, 430, 432, 437, 442, 446, 466}

    def test_status_list_violation_aborts_regular_session(
            self, assert_frames_match, tshark_fields):
        """A malformed status list aborts a regular session (Core 3.2.2.4.2)."""
        tshark_fields = in_section(tshark_fields, self.SPAN)
        aborted = '_ws.col.info contains "session aborted after a malformed status list"'
        broken = ('tcg-storage.tok.status_type && tcg-storage.tok.delimiter'
                  ' && count(_ws.expert) == 2 && count(tcg-storage.data) == 1')
        assert_frames_match(self.FILE, at(self.SPAN, [
            # Mismatched End Name (regular F426, control F466) and End of
            # Data (F432) inside the list: only the delimiter stays raw.
            *[(frame, broken + ' && tcg-storage.data == f3: && count(tcg-storage.tok.uid) == 2'
                               ' && count(tcg-storage.tok.status) == 2 && !' + aborted)
              for frame in (426, 466)],
            (432, broken + ' && tcg-storage.data == f9: && count(tcg-storage.tok.uid) == 2'
                           ' && count(tcg-storage.tok.status) == 2 && !' + aborted),
            # Host-sent violation (either direction).
            (437, broken + ' && tcg-storage.data == f3: && tcg-storage.tok.host_status == 0'
                           ' && !tcg-storage.tok.uid && !' + aborted),
            # Two Packets in one ComPacket: the second is already aborted.
            (430, 'count(tcg-storage.packet) == 2 && count(tcg-storage.subpacket) == 1'
                  ' && count(tcg-storage.data) == 2 && tcg-storage.data == f3:'
                  ' && tcg-storage.tok.status == 0 && !tcg-storage.tok.uid'
                  ' && tcg-storage.tok.status_type && tcg-storage.tok.delimiter'
                  ' && count(_ws.expert) == 2 && ' + aborted),
            # One standalone vector per signal site: a non-uinteger element,
            # a short list and a zero-length integer atom.
            (442, 'count(tcg-storage.data) == 1 && tcg-storage.data == 41:'
                  ' && tcg-storage.tok.status == 0 && tcg-storage.tok.status_type'
                  ' && count(_ws.expert) == 1 && !' + aborted),
            (446, '!tcg-storage.data && tcg-storage.tok.status == 0'
                  ' && tcg-storage.tok.status_type && count(_ws.expert) == 1 && !' + aborted),
            (450, 'count(tcg-storage.data) == 1 && tcg-storage.data == 80:'
                  ' && tcg-storage.tok.status == 0 && tcg-storage.tok.zero_length'
                  ' && count(_ws.expert) == 1 && !' + aborted),
            *[(frame, self.RAW + ' && ' + aborted)
              for frame in (428, 434, 435, 440, 444, 448, 452)],
            # StartSession + SyncSession restart the session.
            (453, ('tcg-storage.tok.uid == 0xff02 && tcg-storage.tok.host_status == 0'
                  ' && !_ws.expert')),
            (456, ('tcg-storage.tok.uid == 0xff03 && tcg-storage.tok.status == 0'
                  ' && !_ws.expert')),
            *[(frame, self.PLAIN + ' && tcg-storage.tok.status == 0 && !tcg-storage.data')
              for frame in (458, 464, 468)],
            # A status list split across two ComPackets is not a violation.
            (460, '!tcg-storage.tok.status && !tcg-storage.data && !_ws.expert'),
            (462, 'tcg-storage.tok.status == 0x13 && !tcg-storage.data && !_ws.expert'),
        ]))
        assert set(map(int, tshark_fields(self.FILE, aborted).split())) == \
            {428, 430, 434, 435, 440, 444, 448, 452}

    def test_underfilled_selected_responses_cannot_mutate_state(
            self, assert_frames_match, tshark_fields):
        """Underfilled selected responses cannot mutate state (NVMe-MI 2.1 Fig 136)."""
        tshark_fields = in_section(tshark_fields, self.SPAN)
        good_response = ('nvme-mi.mic.status == 1 && nvme-mi.admin.status == 0'
                         ' && nvme.cqe.status.sc == 0 && nvme.cqe.status.sct == 0')
        assert_frames_match(self.FILE, at(self.SPAN, [
            *[(frame, ('nvme-mi.admin.dlen == 104 && nvme.cmd.security_recv.dword11.al == 104'
                      ' && !_ws.expert')) for frame in (129, 135)],
            # F130/F142: one Note and nothing else.
            (130, good_response + ' && len(nvme-mi.admin.data) == 100'
                  ' && tcg-storage.compacket.length == 80 && tcg-storage.tok.uid == 0xff05'
                  ' && tcg-storage.tok.status == 0 && !tcg-storage.padding'
                  ' && count(_ws.expert) == 1 && _ws.expert.severity == 0x00400000'),
            *[(frame, self.PLAIN) for frame in (132, 133)],
            # The underfilled F142 cannot mutate TCG state.
            *[(frame, 'tcg-storage.tok.uid && !_ws.expert')
              for frame in (150, 151)],
            (136, good_response + ' && len(nvme-mi.admin.data) == 104'
                  ' && tcg-storage.compacket.length == 80 && tcg-storage.tok.uid == 0xff05'
                  ' && tcg-storage.tok.status == 0 && len(tcg-storage.padding) == 4 && !_ws.expert'),
            *[(frame, 'tcg-storage.packet.secure_data && !tcg-storage.tok.uid && !_ws.expert')
              for frame in (138, 139, 144, 145)],
            *[(frame, ('nvme-mi.admin.dlen == 20 && nvme.cmd.security_recv.dword11.al == 20'
                      ' && !_ws.expert')) for frame in (141, 147)],
            (142, good_response + ' && len(nvme-mi.admin.data) == 16'
                  ' && tcg-storage.comid_mgmt.stack_reset_result == 0'
                  ' && !tcg-storage.padding'
                  ' && count(_ws.expert) == 1 && _ws.expert.severity == 0x00400000'),
            (148, good_response + ' && len(nvme-mi.admin.data) == 20'
                  ' && len(tcg-storage.padding) == 4 && !_ws.expert'),
        ]))
        # ...and the Note by name, after the value rows above: an unknown
        # field name would make the whole combined filter fail to compile.
        assert tshark_fields(self.FILE, 'nvme-mi.admin.short_response').split() == ['130', '142']


class TestTcgStorageEnclosingCompleteness:
    """Allocation Length never overrides a complete ComPacket or Packet boundary."""

    FILE = 'nvme-mi-tcg.pcapng'
    SECTION = 6

    def test_generated_section_and_integrity(self, generator, capture_file, tshark_fields):
        span, cases, packets = generated_section(
            generator, ('tcg_enclosing_completeness_vectors', 1719000000), 5,
            capture_file(self.FILE))
        assert span == self.SPAN
        assert cases == {
            'leftover': (1, 2), 'payload': (3, 4),
            'leftover-short': (5, 6), 'payload-short': (7, 8),
            'native-admin-queue': (9,), 'padding': (10, 11),
            'padding-short': (12, 13), 'packet-complete': (14, 15),
            'valid': (16, 17), 'snaplen-padding': (18, 19),
            'snaplen-header': (20, 21),
        }
        assert len(packets) == self.SPAN[1] - self.SPAN[0] + 1 == 21
        fields = in_section(tshark_fields, self.SPAN)
        assert list(map(int, fields(self.FILE, 'nvme-mi.mic.status == 1').split())) == \
            list(range(1, 9))

    def test_exact_experts_and_anchors(self, dissect_pdml):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        overrun, truncated, short = ('tcg-storage.' + name for name in
                                     ('length_overrun', 'truncated', 'transfer_short'))
        packet_length = 'tcg-storage.packet.length'
        subpacket_length = 'tcg-storage.subpacket.length'
        raw = 'tcg-storage.data'
        incomplete = Counter((short, 'tcg-storage.' + name) for name in
                             ('compacket', 'packet', 'subpacket'))
        expected = {
            2: Counter({(overrun, packet_length): 1, (truncated, raw): 1}),
            4: Counter({(overrun, packet_length): 1, (overrun, subpacket_length): 1}),
            6: Counter((short, 'tcg-storage.' + name) for name in
                       ('compacket', 'packet', 'data')),
            8: incomplete,
            11: Counter({(overrun, packet_length): 1, (overrun, subpacket_length): 1}),
            13: incomplete,
            15: Counter({(short, 'tcg-storage.compacket'): 1, (truncated, raw): 1}),
        }
        assert len(pdml.packets) == 21
        assert tcg_anchors(pdml.packets) == expected

    def test_boundaries_and_snaplen(self, dissect_pdml, tshark_fields):
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        for frame, field, positions in (
                (2, 'tcg-storage.data', [(56, 8)]),
                (4, 'tcg-storage.tok.control', [(i, 1) for i in range(56, 64)]),
                (11, 'tcg-storage.tok.control', [(56, 1)]),
                (17, 'tcg-storage.subpacket.pad', [(57, 3)])):
            base = int(pdml[frame].find(".//proto[@name='tcg-storage']").get('pos'))
            assert [(int(n.get('pos')) - base, int(n.get('size')))
                    for n in pdml.fields(frame, field)] == positions, (frame, field)
        assert not pdml.fields(11, 'tcg-storage.subpacket.pad')
        fields = in_section(tshark_fields, self.SPAN)
        assert list(map(int, fields(self.FILE, '_ws.malformed').split())) == \
            [2, 4, 11, 15]
        assert list(map(int, fields(self.FILE, '_ws.short').split())) == [19, 21]
        assert not fields(self.FILE, '_ws.dissector_bug').strip()
        for frame in (19, 21):
            assert int(pdml.field(frame, 'frame.cap_len')['show']) < \
                int(pdml.field(frame, 'frame.len')['show'])
            assert not pdml.fields(frame, '_ws.malformed.expert')
        assert int(pdml.field(19, 'frame.len')['show']) - \
            int(pdml.field(19, 'frame.cap_len')['show']) == 3
        assert int(pdml.field(21, 'frame.len')['show']) - \
            int(pdml.field(21, 'frame.cap_len')['show']) == 28


class TestTcgStorageContinuationDomains:
    """Malformed Packets neither consume nor append a saved token fragment."""

    FILE = 'nvme-mi-tcg.pcapng'

    @pytest.fixture(scope='class')
    @classmethod
    def continuation(cls, capture_file, generator):
        span, cases, packets = generated_section(
            generator, ('tcg_continuation_domains_vectors', 1720000000), 6,
            capture_file(cls.FILE))
        assert cases == {name: (2 * i + 1, 2 * i + 2) for i, name in enumerate((
            'malformed-a', 'malformed-b', 'short-a', 'short-b', 'healthy', 'snaplen',
            'padded-a', 'generous-padded-a', 'ordinary', 'witness-a', 'witness-b',
        ))}
        assert len(packets) == 22
        return span, cases

    @pytest.mark.parametrize('name', [
        'malformed-a', 'malformed-b', 'short-a', 'short-b', 'healthy', 'snaplen',
        'padded-a', 'generous-padded-a', 'ordinary', 'witness-a', 'witness-b',
    ])
    def test_exact_continuations_and_experts(self, continuation, dissect_pdml, name):
        span, cases = continuation
        pdml = pdml_section(dissect_pdml(self.FILE), span)
        assert len(pdml.packets) == 22
        short, truncated, overrun = ('tcg-storage.' + n for n in
                                     ('transfer_short', 'truncated', 'length_overrun'))
        raw = 'tcg-storage.data'
        fragment = 'tcg-storage.tok.fragment'
        byte_atom = 'tcg-storage.tok.bytes'
        for request, frame in (cases[name],):
            assert pdml[request].find(".//proto[@name='tcg-storage']") is None
            packet = pdml[frame]
            assert packet.find(".//proto[@name='_ws.dissector_bug']") is None
            experts = Counter({key: count for key, count in expert_anchors(packet).items()
                               if key[0] in (short, truncated, overrun)})
            expected = Counter()
            if name.startswith('short-'):
                expected = Counter((short, 'tcg-storage.' + n) for n in
                                   ('compacket', 'packet', 'subpacket', 'data'))
            elif name not in ('healthy', 'snaplen'):
                expected = Counter({(overrun, 'tcg-storage.subpacket.length'): 1,
                                    (truncated, raw): 1})
            assert experts == expected, (name, experts)
            subpackets = pdml.fields(frame, 'tcg-storage.subpacket')
            if name == 'snaplen':
                assert packet.find(".//proto[@name='_ws.short']") is not None
                assert not pdml.fields(frame, '_ws.malformed.expert')
                assert pdml.field(frame, 'nvme-mi.mic.status')['show'] == '3'
                assert int(pdml.field(frame, 'frame.len')['show']) - \
                    int(pdml.field(frame, 'frame.cap_len')['show']) == 36
                assert len(subpackets) == 2
                assert not pdml.fields(frame, byte_atom)
                assert not pdml.fields(frame, raw)
                assert subpackets[1].find(".//field[@name='" + fragment + "']") is None
                continue
            assert pdml.field(frame, 'nvme-mi.mic.status')['show'] == '1'
            if name == 'ordinary':
                assert not pdml.fields(frame, fragment)
                assert pdml.field(frame, raw)['value'] == 'e000'
                continue
            seed = subpackets[0].find(".//field[@name='" + fragment + "']")
            assert seed.get('value') == 'd0'
            base = int(packet.find(".//proto[@name='tcg-storage']").get('pos'))
            assert (int(seed.get('pos')) - base, int(seed.get('size'))) == (56, 1)
            second = subpackets[1]
            assert second.find(".//field[@name='" + fragment + "']") is None
            is_b = name.endswith('-b')
            if is_b:
                node = second.find(".//field[@name='" + raw + "']")
                assert node.get('value') == '40' + 'ff' * 31
                assert int(node.get('size')) == 32
                assert int(node.get('pos')) - base == (96 if name.startswith('witness') else 72)
                assert second.find(".//field[@name='tcg-storage.token_stream']") is None
            else:
                node = second.find(".//field[@name='" + byte_atom + "']")
                assert (node.get('value'), node.get('pos'), node.get('size')) == ('aabb', '2', '2')
                if name == 'healthy':
                    integer = second.find(".//field[@name='tcg-storage.tok.uint']")
                    assert (integer.get('show'), integer.get('pos'), integer.get('size')) == \
                        ('1', '31', '5')
                    assert second.find(".//field[@name='" + raw + "']") is None
                else:
                    tail = second.find(".//field[@name='" + raw + "']")
                    assert (tail.get('value'), tail.get('pos'), tail.get('size')) == ('e000', '31', '2')
            if name.startswith('witness'):
                assert len(subpackets) == 3
                last = subpackets[2]
                stream = last.find(".//field[@name='tcg-storage.token_stream']")
                assert stream.get('size') == '4'
                node = last.find(".//field[@name='" + byte_atom + "']")
                assert (node.get('value'), node.get('pos'), node.get('size')) == ('aabb', '2', '2')
                assert last.find(".//field[@name='" + fragment + "']") is None


class TestTcgStorageSynchronousAtom:
    """An atom spanning a complete synchronous ComPacket is rejected (Core 3.3.10.3)."""

    FILE = 'nvme-mi-tcg.pcapng'
    SEND = frozenset({'control', 'control-subpacket', 'regular-host', 'regular-ff02',
                      'regular-restarted-host'})
    WARN = (('150994944', '6291456'),)  # PI_PROTOCOL, PI_WARN
    ABORTED = 'session aborted after an atom spanning a synchronous ComPacket'
    SPANS = ('Atom cannot complete within this ComPacket while synchronous'
             ' (Core 3.3.10.3(a)); rest of the Packet not decoded')
    REJECTED = ('control', 'control-subpacket', 'regular', 'split-header',
                'reassembled', 'reassembled-medium', 'padding')
    COLUMNS = ('frame.number', '_ws.expert.group', '_ws.expert.severity',
               'tcg-storage.data', 'tcg-storage.tok.fragment', 'tcg-storage.tok.bytes',
               'tcg-storage.tok.uid', 'tcg-storage.packet.secure_data', '_ws.col.info')

    @pytest.fixture(scope='class')
    @classmethod
    def synchronous(cls, capture_file, generator):
        span, cases, packets = generated_section(
            generator, ('tcg_synchronous_atom_vectors', 1721000000), 7,
            capture_file(cls.FILE))
        assert len(packets) == 102
        return span, cases, generator

    def frame(self, cases, name):
        """The section frame that carries the case's TCG payload."""
        return cases[name][0 if name in self.SEND else 1]

    def expected(self, generator):
        """{case: (experts, data, fragment, bytes, uids, secure, aborted)}; None is unchecked."""
        g = generator
        call = (b'\xf8' + g['tcg_bytes_atom'](g['TCG_SMUID'])
                + g['tcg_bytes_atom'](g['TCG_SYNTHETIC_METHOD'])
                + b'\xf0' + g['tcg_bytes_atom'](g['TCG_ADMIN_SP']) + b'\xf1'
                + g['TCG_EOD_STATUS_SUCCESS'])
        start = (b'\xf8' + g['tcg_bytes_atom'](g['TCG_SMUID'])
                 + g['tcg_bytes_atom']((0xff02).to_bytes(8, 'big')) + b'\xf0'
                 + g['tcg_tiny_uint'](0x32) + g['tcg_bytes_atom'](g['TCG_ADMIN_SP'])
                 + b'\x01\xf1' + g['TCG_EOD_STATUS_SUCCESS'])
        atom = bytes(i % 251 for i in range(1990))
        CALL, START = [0xff, 0xeeeeee], [0xff, 0xff02]
        plain = ((), [], [], None, CALL, False, False)
        aborted = ((), [g['tcg_subpacket'](call).hex()], [], [], [], False, True)
        rows = {
            'control': (self.WARN, ['e2ffffff'], [], None, START, False, False),
            'control-subpacket': (self.WARN, ['e2ffffff', start.hex()], [], None, START,
                                  False, False),
            'control-31-payload': ((), [], [], [], [], True, False),
            'control-32-payload': plain,
            'control-33-payload': ((), [], [], [], [], True, False),
            'regular': (self.WARN, ['e2ffffff', call.hex()], [], None, CALL, False, False),
            'regular-next': aborted,
            'regular-host': aborted,
            'regular-other': plain,
            'regular-restarted': plain,
            'regular-restarted-host': plain,
            'split': ((), [], ['d002'], ['aabb'], [], False, False),
            'split-header': (self.WARN, ['ffffff'], ['e2'], None, CALL, False, False),
            'reassembled': (self.WARN, ['e2ffffff'], ['d0'], ['aabb'], [], False, False),
            'reassembled-next': aborted,
            'reassembled-medium': (self.WARN, ['d008'], ['d0'], ['aabb'], [], False, False),
            'padding': (self.WARN, ['d010'], [], [], [], False, False),
            'padding-next': aborted,
            'terminal': ((), [], ['d0'], [], [], False, False),
            'terminal-next': plain,
            'atom-1992': ((), [], [], [atom.hex()], [], False, False),
            'atom-1992-split': ((), [], [(b'\xd7\xc6' + atom)[:996].hex()], [atom.hex()], [],
                                False, False),
            'atom-1992-next': plain,
        }
        for prefix in ('async', 'none'):
            rows.update({
                prefix + '-first': ((), [], ['d002'], [], [], False, False),
                prefix + '-last': ((), [], [], ['aabb'], [], False, False),
                prefix + '-huge': ((), [], ['e2ffffff'], [], [], False, False),
                # Accepted residual gap: the corrupt declaration swallows it.
                prefix + '-huge-next': ((), [], [call.hex()], [], [], False, False),
            })
        for name in ('short-transfer', 'snaplen', 'lying'):
            rows[name] = (None, None, None, [], [], False, False)
            rows[name + '-next'] = plain
        return rows

    def rows(self, tshark_fields, span):
        out = in_section(tshark_fields, span)(self.FILE, 'tcg-storage.compacket',
                                              fields=self.COLUMNS, separator='|')
        rows = {}
        for line in out.splitlines():
            n, group, severity, data, fragment, byte_atoms, uid, secure, info = line.split('|')
            rows[int(n)] = (tuple(zip(group.split(','), severity.split(','))) if group else (),
                            data.split(',') if data else [],
                            fragment.split(',') if fragment else [],
                            byte_atoms.split(',') if byte_atoms else [],
                            uids(uid), secure != '', self.ABORTED in info)
        return rows

    def test_exact_rejection_and_containment(self, synchronous, tshark_fields):
        span, cases, generator = synchronous
        rows = self.rows(tshark_fields, span)
        expected = self.expected(generator)
        for name, row in expected.items():
            actual = rows[self.frame(cases, name)]
            for index, (want, got) in enumerate(zip(row, actual)):
                if want is not None:
                    assert got == want, (name, index, got)
        warned = {n for n, row in rows.items() if self.WARN[0] in row[0]}
        assert warned == {self.frame(cases, name) for name in self.REJECTED}
        assert all(rows[n][0] == self.WARN for n in warned)
        assert {n for n, row in rows.items() if row[6]} == \
            {self.frame(cases, name) for name in
             ('regular-next', 'regular-host', 'reassembled-next', 'padding-next')}
        assert {n for n, row in rows.items() if row[5]} == \
            {self.frame(cases, name) for name in ('control-31-payload', 'control-33-payload')}

    def test_unproven_endpoints_keep_their_experts(self, synchronous, assert_frames_match):
        span, cases, _ = synchronous
        no_spans = '!tcg-storage.tok.spans_compacket && tcg-storage.tok.fragment == e2:ff:ff:ff'
        assert_frames_match(self.FILE, at(span, [
            (self.frame(cases, 'short-transfer'),
             no_spans + ' && tcg-storage.transfer_short && nvme-mi.mic.status == 1'),
            (self.frame(cases, 'snaplen'), no_spans + ' && nvme-mi.mic.status == 3'
             ' && frame.len - frame.cap_len == 64'),
            (self.frame(cases, 'lying'),
             ('!tcg-storage.tok.spans_compacket && !tcg-storage.tok.fragment'
             ' && tcg-storage.length_overrun && tcg-storage.truncated'
             ' && tcg-storage.data == e2:ff:ff:ff:00:00:00')),
        ]))

    def test_coordinate_discriminator(self, synchronous, dissect_pdml):
        """D0 08 is measured from the transfer tail, not the reassembled child's end."""
        span, cases, _ = synchronous
        pdml = pdml_section(dissect_pdml(self.FILE), span)
        n = self.frame(cases, 'reassembled-medium')
        subpackets = pdml.fields(n, 'tcg-storage.subpacket')
        assert len(subpackets) == 2
        child = subpackets[1].find(".//field[@name='tcg-storage.token_stream']")
        assert child.get('size') == '6'  # d0 02 aa bb d0 08, reassembled
        node = child.find(".//field[@name='tcg-storage.data']")
        assert (node.get('value'), node.get('pos'), node.get('size')) == ('d008', '4', '2')
        assert subpackets[1].find(".//field[@name='tcg-storage.tok.fragment']") is None


class TestTcgStoragePropertiesExtensions:
    """Unknown Properties values follow Core 3.2.2.3.2.1."""

    FILE = 'nvme-mi-tcg.pcapng'
    SECTION = 5
    PLAIN = 'count(tcg-storage.tok.uid) == 2 && !tcg-storage.packet.secure_data && !_ws.expert'
    DUPLICATE = ('tcg-storage.data && !tcg-storage.subpacket && !tcg-storage.tok.uid'
                 ' && _ws.col.info contains "previously acted-on" && !_ws.expert')

    @pytest.fixture(scope='class')
    @classmethod
    def extensions(cls, generator):
        return generator['tcg_conformance_vectors'](properties_extensions=True)[1]

    def test_generated_section_and_integrity(self, generator, capture_file, tshark_fields):
        span, cases, packets = generated_section(
            generator, ('tcg_conformance_vectors', 1718000000), 4,
            capture_file(self.FILE), properties_extensions=True)
        assert span == self.SPAN
        assert len(packets) == self.SPAN[1] - self.SPAN[0] + 1
        assert sorted(n for pair in cases.values() for n in pair) == \
            list(range(1, len(packets) + 1))
        fields = in_section(tshark_fields, self.SPAN)
        assert list(map(int, fields(self.FILE, 'nvme-mi.mic.status == 1').split())) == \
            list(range(1, len(packets) + 1))

    def test_unknown_values_observe_both_properties(self, extensions, tshark_fields):
        """Unknown Properties values still observe both tracked properties."""
        cases = extensions
        fields = in_section(tshark_fields, self.SPAN)
        rows = {}
        for name, pair in cases.items():
            if not name.startswith('extension-'):
                continue
            frame = pair[1]
            if name.endswith('-duplicate'):
                rows[frame] = self.DUPLICATE
            elif name.endswith('-first') and '-sync-' not in name and '-async-' not in name:
                rows[frame] = self.PLAIN
            elif name.endswith('-sync-last'):
                rows[frame] = '!tcg-storage.tok.uid && !tcg-storage.tok.fragment'
            elif name == 'extension-async-last':
                rows[frame] = self.PLAIN
        for expr in set(rows.values()):
            selected = sorted(n for n, value in rows.items() if value == expr)
            out = fields(self.FILE, f'frame.number in {{{",".join(map(str, selected))}}}'
                         f' && ({expr})')
            assert list(map(int, out.split())) == selected
        responses = [pair[1] for name, pair in cases.items()
                     if name.startswith('extension-') and name.endswith('-response')]
        assert list(map(int, fields(self.FILE,
            f'frame.number in {{{",".join(map(str, responses))}}} && !_ws.expert').split())) == responses

    def test_invalid_known_values_never_partially_observe(self, extensions, tshark_fields):
        cases = extensions
        fields = in_section(tshark_fields, self.SPAN)
        checks = {}
        for name, pair in cases.items():
            if not name.startswith(('invalid-', 'malformed-extension-')):
                continue
            if name.endswith(('-first', '-repeat')) and '-sync-' not in name:
                checks[pair[1]] = self.PLAIN
            elif name.endswith('-sync-last'):
                checks[pair[1]] = '!tcg-storage.tok.uid && !tcg-storage.tok.fragment'
            elif name.endswith('-recovered-duplicate'):
                checks[pair[1]] = self.DUPLICATE
        for expr in set(checks.values()):
            selected = sorted(n for n, value in checks.items() if value == expr)
            out = fields(self.FILE, f'frame.number in {{{",".join(map(str, selected))}}}'
                         f' && ({expr})')
            assert list(map(int, out.split())) == selected
        for name in ('wide-option-plain', 'wide-start-option-plain'):
            frame = cases[name][1]
            assert fields(self.FILE, f'frame.number == {frame} && ({self.PLAIN})').strip() == str(frame)


class TestTcgStorageLevel0Prefix:
    """Level 0 Discovery truncated by Allocation Length (Core 3.3.6.2, NVMe-MI 2.1 Fig 136)."""

    FILE = 'nvme-mi-tcg.pcapng'
    INDEX = 8
    SHORT, ROOT = 'tcg-storage.transfer_short', 'tcg-storage.level0_discovery'
    # The raw MI data is hidden, so the note is on the visible "Data" subtree.
    MI_SHORT = ('nvme-mi.admin.short_response', '')
    COLUMNS = ('frame.number', 'frame.protocols', '_ws.expert.message',
               'tcg-storage.l0.feat.code', 'tcg-storage.l0.feat.tper.flags',
               'tcg-storage.l0.feat.locking.flags', 'tcg-storage.data',
               'tcg-storage.padding')

    @pytest.fixture(scope='class')
    @classmethod
    def prefix(cls, capture_file, generator):
        span, cases, _ = generated_section(
            generator, ('tcg_level0_prefix_vectors', 1722000000), cls.INDEX,
            capture_file(cls.FILE))
        return span, cases

    @staticmethod
    def payloads(cases, name):
        """The section frames carrying the case's Security Receive data."""
        return cases[name][1:]

    def test_case_map(self, prefix, tshark_fields):
        span, cases = prefix
        mi = ('selected-header', 'selected-body', 'allocation-body', 'short-header',
              'short-body', 'short-selected-body', 'complete-parent-overrun',
              'complete-parent-header-tail', 'bad-length-prefix', 'surplus',
              'selected-snaplen', 'later-window', 'complete-selected', 'selected-padding',
              'padding-short-80', 'padding-short-68', 'padding-selected-64',
              'padding-partial-80', 'padding-complete-80', 'padding-snaplen-80',
              'padding-overrun-80')
        expected = {name: (2 * i + 1, 2 * i + 2) for i, name in enumerate(mi)}
        expected['native-admin-queue'] = (43,)
        frame = 44
        for name, windows in (('native-nonfinal-body', 2), ('native-nonfinal-header', 2),
                              ('native-final-short-body', 1), ('native-padding-short', 1),
                              ('native-padding-nonfinal', 2), ('native-nonfinal-overrun', 2),
                              ('native-nonfinal-snaplen', 2), ('native-nonfinal-bad-span', 1),
                              ('native-leak-order', 2)):
            expected[name] = tuple(range(frame, frame + 1 + windows))
            frame += 1 + windows
        assert cases == expected
        fields = in_section(tshark_fields, span)
        mic_ok = fields(self.FILE, 'nvme-mi.mic.status == 1').split()
        assert list(map(int, mic_ok)) == [n for n in range(1, 43) if n not in (22, 40)]
        # TCP window declarations: (DATAO, DATAL, LAST_PDU|SUCCESS flags).
        out = fields(self.FILE, 'nvme-tcp.data.offset',
                     fields=('frame.number', 'nvme-tcp.data.offset',
                             'nvme-tcp.data.length', 'nvme-tcp.flags'), separator='|')
        assert {int(n): (int(o), int(d), f) for n, o, d, f in
                (line.split('|') for line in out.splitlines())} == {
            45: (0, 68, '0x00'), 46: (68, 12, '0x0c'), 48: (0, 16, '0x00'),
            49: (16, 64, '0x0c'), 51: (0, 68, '0x0c'), 53: (0, 64, '0x0c'),
            55: (0, 64, '0x00'), 56: (64, 16, '0x0c'), 58: (0, 68, '0x00'),
            59: (68, 12, '0x0c'), 61: (0, 68, '0x00'), 62: (68, 12, '0x0c'),
            64: (0, 80, '0x00'), 66: (0, 68, '0x00'), 67: (0, 68, '0x0c')}

    def expected_experts(self, cases):
        """{section frame: Counter((expert field, parent field))}; others have none."""
        short, root = self.SHORT, self.ROOT
        feat, raw = 'tcg-storage.l0.feat', 'tcg-storage.data'
        overrun = 'tcg-storage.length_overrun'
        clipped = Counter({(short, root): 1, (short, feat): 1})
        by_case = {
            'short-header': [Counter({self.MI_SHORT: 1, (short, raw): 1})],
            'short-body': [clipped + Counter([self.MI_SHORT])],
            'short-selected-body': [clipped + Counter([self.MI_SHORT])],
            'complete-parent-overrun': [Counter({(overrun, 'tcg-storage.l0.feat.length'): 1})],
            'complete-parent-header-tail': [Counter({('tcg-storage.truncated', raw): 1})],
            'bad-length-prefix': [Counter({(overrun, raw): 1})],
            'surplus': [Counter({('nvme-mi.admin.invalid_dlen',
                                  'nvme-mi.admin.data_excess'): 1})],
            'selected-snaplen': [Counter()],
            'later-window': [Counter()],
            'padding-short-80': [Counter({self.MI_SHORT: 1, (short, root): 1})],
            'padding-short-68': [Counter({self.MI_SHORT: 1, (short, root): 1})],
            'padding-partial-80': [Counter({self.MI_SHORT: 1, (short, root): 1})],
            'padding-snaplen-80': [Counter()],
            'padding-overrun-80': [Counter({self.MI_SHORT: 1, (short, root): 1,
                                            (overrun, 'tcg-storage.l0.feat.length'): 1})],
            'native-nonfinal-body': [Counter(), Counter()],
            'native-nonfinal-header': [Counter(), Counter()],
            'native-final-short-body': [clipped],
            'native-padding-short': [Counter({(short, root): 1})],
            'native-padding-nonfinal': [Counter(), Counter()],
            'native-nonfinal-overrun': [
                Counter({(overrun, 'tcg-storage.l0.feat.length'): 1}), Counter()],
            # The sliced PDU's span is unresolved, so it is no known-span
            # prefix; the existing initial-window short note stays.
            'native-nonfinal-snaplen': [Counter({(short, root): 1}), Counter()],
            'native-nonfinal-bad-span': [
                clipped + Counter([('nvme.data.len_exceeds_frame', 'nvme')])],
            'native-leak-order': [Counter(), clipped],
        }
        expected = {}
        for name, counters in by_case.items():
            frames = self.payloads(cases, name)
            assert len(frames) == len(counters), name
            expected.update((n, c) for n, c in zip(frames, counters) if c)
        return expected

    def test_exact_experts_and_anchors(self, prefix, dissect_pdml):
        span, cases = prefix
        pdml = pdml_section(dissect_pdml(self.FILE), span)
        assert len(pdml.packets) == 67
        expected = self.expected_experts(cases)
        for frame, packet in pdml.packets.items():
            assert expert_anchors(packet) == expected.get(frame, Counter()), frame
        for name in ('selected-snaplen', 'padding-snaplen-80'):
            frame = self.payloads(cases, name)[0]
            assert pdml.fields(frame, 'nvme-mi.mic_unverified'), name

    def test_level0_layout(self, prefix, dissect_pdml):
        """Offsets and sizes of the Level 0 root, features, raw data and padding."""
        span, cases = prefix
        pdml = pdml_section(dissect_pdml(self.FILE), span)
        names = ('level0_discovery', 'l0.feat', 'data', 'padding')
        header = [('data', 0, 16)]
        tper = [('level0_discovery', 0, 64), ('l0.feat', 48, 16)]
        clipped = [('level0_discovery', 0, 68), ('l0.feat', 48, 16), ('l0.feat', 64, 4)]
        full = [('level0_discovery', 0, 80), ('l0.feat', 48, 16), ('l0.feat', 64, 16)]
        layouts = {
            'selected-header': header, 'selected-body': clipped,
            'allocation-body': clipped, 'short-header': header, 'short-body': clipped,
            'short-selected-body': clipped, 'complete-parent-overrun': clipped,
            'complete-parent-header-tail': [('level0_discovery', 0, 66), ('l0.feat', 48, 16),
                                            ('data', 64, 2), ('padding', 66, 2)],
            'bad-length-prefix': header, 'surplus': clipped,
            'selected-snaplen': [('level0_discovery', 0, 60), ('l0.feat', 48, 12)],
            'complete-selected': full, 'selected-padding': full + [('padding', 80, 16)],
            'padding-short-80': tper, 'padding-short-68': tper, 'padding-selected-64': tper,
            'padding-partial-80': tper + [('padding', 64, 4)],
            'padding-complete-80': tper + [('padding', 64, 16)],
            # The capture ends at the owed padding: nothing after it is shown.
            'padding-snaplen-80': [('level0_discovery', 0, 64)],
            'padding-overrun-80': clipped,
            'native-nonfinal-body': clipped, 'native-nonfinal-header': header,
            'native-final-short-body': clipped, 'native-padding-short': tper,
            'native-padding-nonfinal': tper, 'native-nonfinal-overrun': clipped,
            'native-nonfinal-snaplen': [('level0_discovery', 0, 60), ('l0.feat', 48, 12)],
            'native-nonfinal-bad-span': clipped, 'native-leak-order': clipped,
        }
        tcg_frames = set()
        for name, layout in layouts.items():
            for i, frame in enumerate(self.payloads(cases, name)):
                if name.startswith('native-') and i > 0 and name != 'native-leak-order':
                    continue
                tcg_frames.add(frame)
                proto = pdml[frame].find(".//proto[@name='tcg-storage']")
                base = int(proto.get('pos'))
                got = [(n.get('name')[len('tcg-storage.'):], int(n.get('pos')) - base,
                        int(n.get('size'))) for n in proto.iter('field')
                       if n.get('name') in tuple('tcg-storage.' + x for x in names)]
                assert got == layout, (name, frame, got)
                tper_flags = [n.get('show') for n in
                              pdml.fields(frame, 'tcg-storage.l0.feat.tper.flags')]
                locking = [n.get('show') for n in
                           pdml.fields(frame, 'tcg-storage.l0.feat.locking.flags')]
                has_tper = any(item[:2] == ('l0.feat', 48) for item in layout)
                assert tper_flags == (['0x41'] if has_tper else []), name
                assert locking == (['0x03'] if ('l0.feat', 64, 16) in layout else []), name
        # Later TCP windows and the MI later window stay out of TCG Storage.
        assert {n for n, packet in pdml.packets.items()
                if packet.find(".//proto[@name='tcg-storage']") is not None} == tcg_frames

    def test_capture_loss_is_not_a_short_transfer(self, prefix, tshark_fields):
        span, cases = prefix
        fields = in_section(tshark_fields, span)
        out = fields(self.FILE, '_ws.short', fields=('frame.number', 'frame.len',
                                                     'frame.cap_len', 'nvme-mi.mic.status'),
                     separator='|')
        assert out.splitlines() == ['22|112|100|3', '40|124|104|3', '61|146|138|']
        assert [self.payloads(cases, name)[0] for name in
                ('selected-snaplen', 'padding-snaplen-80', 'native-nonfinal-snaplen')] == \
            [22, 40, 61]
        assert not fields(self.FILE, '_ws.malformed.expert || _ws.dissector_bug').strip()

    def test_leak_order(self, prefix, tshark_fields):
        """A non-final and a final window of one command do not leak into each other."""
        span, cases = prefix
        fields = in_section(tshark_fields, span)
        first = fields(self.FILE, fields=self.COLUMNS, separator='|')
        nonfinal, final = self.payloads(cases, 'native-leak-order')
        rows = {int(line.split('|')[0]): line for line in first.splitlines()}
        for frame in (nonfinal, final):
            assert rows[frame].split('|')[3:6] == ['0x0001,0x0002', '0x41', '']
        assert 'transfer stopped short' not in rows[nonfinal]
        assert rows[final].split('|')[2].count('transfer stopped short') == 2


class TestTcgStorageSecurity:
    """Security Send/Receive routed to SECP 00h or TCG Storage; nvme-mi-security.pcapng."""

    # F1/F2   SECP 00h SPSP 0000h: supported protocols 00h, 01h, 02h
    # F3/F4   Level 0 Discovery: TPer, Locking, Opal SSC V2, Data Removal
    # F5/F6   StartSession ComPacket (Send)
    # F7/F8   SyncSession ComPacket (Receive)
    # F9-F12  PROTOCOL STACK RESET request and ComID-management response
    # F13/F14 TPer Reset (SPSP 0004h): payload ignored, not ComID management
    # F15/F16 GET_COMID: the payload is only the 4-byte Extended ComID
    # F17/F18 Level 0 Discovery with a Ruby SSC (Opal 2.x layout)
    # F19/F20 F8's SyncSession with Empty atoms interleaved
    # F21/F22 Level 0 Discovery with SIIS and Namespace Geometry Reporting
    # F23/F24 SECP 00h with an SP Specific value defined by SPC-5

    FILE = 'nvme-mi-security.pcapng'
    SECTION = 1
    TCG_FRAMES = (4, 5, 8, 9, 12, 13, 16, 18, 20, 22)
    TCG_EXPERTS = ('tcg-storage.truncated', 'tcg-storage.length_overrun',
                   'tcg-storage.transfer_short', 'tcg-storage.tok.reserved_token',
                   'tcg-storage.tok.status_type',
                   'tcg-storage.l0.feat.length_not_aligned')
    FIELDS = ('nvme-mi', 'tcg-storage', 'frame.protocols', '_ws.col.protocol',
              '_ws.col.info', '_ws.malformed', '_ws.expert.message',
              'nvme.security.info',
              'nvme.cmd.security.data', 'tcg-storage.l0.feat.ssc_minor',
              'tcg-storage.l0.feat.ssc.reserved', 'tcg-storage.tok.status',
              'tcg-storage.tok.host_status', 'tcg-storage.l0.length',
              'tcg-storage.compacket.comid', 'tcg-storage.comid_mgmt.comid',
              'tcg-storage.comid_mgmt.request_code') + TCG_EXPERTS

    def test_decode(self, assert_frames_match):
        assert_frames_match(self.FILE, at(self.SPAN, [
            (2, ('nvme.security.info.list_len == 3 && nvme.security.info.protocol == 0x00'
                 ' && nvme.security.info.protocol == 0x01'
                 ' && nvme.security.info.protocol == 0x02')),
            # Core Table 39: bytes 4:7 are a major (0) and a minor (1) version.
            (4, ('tcg-storage.l0.length == 132 && tcg-storage.l0.major_version == 0'
                 ' && tcg-storage.l0.minor_version == 1'
                 ' && tcg-storage.l0.feat.code == 0x0001 && tcg-storage.l0.feat.code == 0x0002'
                 ' && tcg-storage.l0.feat.code == 0x0203 && tcg-storage.l0.feat.code == 0x0404'
                 ' && tcg-storage.l0.feat.opal2.base_comid == 0x1000'
                 ' && tcg-storage.l0.feat.opal2.num_comids == 1'
                 ' && tcg-storage.l0.feat.opal2.num_admins == 4'
                 ' && tcg-storage.l0.feat.opal2.num_users == 8'
                 ' && tcg-storage.l0.feat.ssc_minor == 2'
                 ' && tcg-storage.l0.feat.data_removal.mechanism.crypto_erase == 1'
                 ' && tcg-storage.l0.feat.data_removal.mechanism.vendor == 1'
                 ' && tcg-storage.l0.feat.data_removal.time_crypto_erase == 30'
                 ' && tcg-storage.l0.feat.data_removal.time_vendor == 600'
                 ' && tcg-storage.l0.feat.data_removal.interrupted == 1'
                 ' && tcg-storage.l0.feat.data_removal.processing == 0'
                 ' && tcg-storage.l0.feat.tper.sync == 1'
                 ' && tcg-storage.l0.feat.tper.comid_mgmt == 1'
                 ' && tcg-storage.l0.feat.tper.streaming == 0'
                 ' && tcg-storage.l0.feat.locking.supported == 1'
                 ' && tcg-storage.l0.feat.locking.enabled == 1'
                 ' && tcg-storage.l0.feat.locking.locked == 0')),
            (5, ('tcg-storage.compacket.comid == 0x1000 && tcg-storage.compacket.length == 76'
                 ' && tcg-storage.packet.seq == 1 && tcg-storage.packet.length == 52'
                 ' && tcg-storage.subpacket.kind == 0x0000'
                 ' && tcg-storage.subpacket.length == 38'
                 ' && tcg-storage.tok.uid == 0x00000000000000FF'
                 ' && tcg-storage.tok.uid == 0x000000000000FF02'
                 ' && tcg-storage.tok.bytes == 00:00:02:05:00:00:00:01'
                 ' && !(tcg-storage.tok.uid == 0x0000020500000001)')),
            (8, ('tcg-storage.compacket.comid == 0x1000'
                 ' && tcg-storage.tok.uid == 0x000000000000FF03 && tcg-storage.tok.status == 0')),
            (9, ('tcg-storage.comid_mgmt.comid == 0x1000 && tcg-storage.comid_mgmt.comid_ext == 0'
                 ' && tcg-storage.comid_mgmt.request_code == 2')),
            (12, ('tcg-storage.comid_mgmt.comid == 0x1000 && tcg-storage.comid_mgmt.comid_ext == 0'
                  ' && tcg-storage.comid_mgmt.request_code == 2'
                  ' && tcg-storage.comid_mgmt.available_data_length == 4')),
            # Core 3.3.4.3.1: GET_COMID's payload is the Extended ComID only.
            (16, 'tcg-storage.get_comid.ext_comid == 0x10000001'),
            # Ruby SSC Table 7 is the Opal 2.x layout.
            (18, ('tcg-storage.l0.feat.code == 0x0304'
                  ' && tcg-storage.l0.feat.opal2.base_comid == 0x2000'
                  ' && tcg-storage.l0.feat.opal2.range_crossing == 1'
                  ' && tcg-storage.l0.feat.opal2.num_admins == 4'
                  ' && tcg-storage.l0.feat.opal2.num_users == 9')),
            # Core 3.2.2.3.1.5: Empty atoms are ignored wherever they appear.
            (20, ('tcg-storage.tok.uid == 0x00000000000000FF'
                  ' && tcg-storage.tok.uid == 0x000000000000FF03 && tcg-storage.tok.status == 0')),
            # SIIS 1.20 3.6 Table 2.
            (22, ('tcg-storage.l0.feat.code == 0x0005'
                  ' && tcg-storage.l0.feat.siis.revision == 0x20'
                  ' && tcg-storage.l0.feat.siis.id_usage_scope == 2'
                  ' && tcg-storage.l0.feat.siis.key_change_zone == 1')),
        ]))

    def test_dispatch_and_columns(self, fields_table):
        t = section(fields_table(self.FILE, self.FIELDS), self.SPAN)

        def frames(predicate):
            return [n for n, row in t.items() if predicate(row)]

        assert list(column(t, 'nvme-mi')) == list(range(1, 25))
        # TCG decodes only the data-bearing frames; Send responses carry none.
        assert list(column(t, 'tcg-storage')) == list(self.TCG_FRAMES)
        assert frames(lambda r: 'tcg-storage' in r['frame.protocols']) == list(self.TCG_FRAMES)
        assert frames(lambda r: r['_ws.col.protocol'] == 'TCG') == list(self.TCG_FRAMES)
        assert frames(lambda r: any(r[f] for f in (
            'tcg-storage', 'tcg-storage.l0.length', 'tcg-storage.compacket.comid',
            'tcg-storage.comid_mgmt.comid'))) == list(self.TCG_FRAMES)
        assert list(column(t, 'nvme.security.info')) == [2, 24]
        # SECP 00h SPSP 0002h (SPC-5): the length header, descriptors raw.
        assert not t[24]['nvme.cmd.security.data'] and not t[24]['_ws.expert.message']
        # Opal SSC V2 alone has the SSC Minor Version nibble.
        assert column(t, 'tcg-storage.l0.feat.ssc_minor') == {4: '0x02'}
        assert 18 not in column(t, 'tcg-storage.l0.feat.ssc.reserved')
        assert frames(lambda r: r['tcg-storage.tok.status'] and
                      int(r['tcg-storage.tok.status'], 0) == 0) == [8, 20]
        assert frames(lambda r: r['tcg-storage.tok.host_status'] and
                      int(r['tcg-storage.tok.host_status'], 0) == 0) == [5]
        # A TPer Reset and GET_COMID are not ComID management requests.
        assert list(column(t, 'tcg-storage.comid_mgmt.comid')) == [9, 12]
        assert 16 not in column(t, 'tcg-storage.comid_mgmt.request_code')
        assert column(t, '_ws.malformed') == {}
        for name in self.TCG_EXPERTS:
            assert column(t, name) == {}, name
        info = {n: t[n]['_ws.col.info'] for n in (4, 5, 8, 9, 13, 16, 20)}
        for frame, present, absent in (
                (4, ('Level 0 Discovery', 'Opal 2.x'), ()),
                (5, ('StartSession()', 'Session Manager (SMUID)'), ()),
                (8, ('SyncSession()', 'Status: SUCCESS'), ()),
                (9, ('ComID Management', 'PROTOCOL STACK RESET'), ()),
                (13, ('TPer Reset',), ('ComID Management',)),
                (16, ('GET_COMID',), ('ComID Management',)),
                (20, ('Session Manager (SMUID)', 'SyncSession()', 'Status: SUCCESS'), ())):
            assert all(p in info[frame] for p in present), (frame, info[frame])
            assert not any(a in info[frame] for a in absent), (frame, info[frame])

    def test_ns_geometry_reporting_decoded_as_geometry(self, cmd_tshark, capture_file,
                                                       test_env, assert_frames_match):
        """Feature 0405h has the Geometry Reporting layout (CNL 1.00 Table 10,
        Configurable Locking 1.30 Table 11)."""
        out = subprocess.check_output(
            [cmd_tshark, '-r', capture_file(self.FILE), '-Y', 'frame.number == 22', '-V'],
            encoding='utf-8', env=test_env)
        assert 'Namespace Geometry Reporting Feature' in out
        assert 'SIIS Feature' in out
        geometry = 'tcg-storage.l0.feat.geometry.'
        assert_frames_match(self.FILE, at(self.SPAN, [
            (22, (f'tcg-storage.l0.feat.code == 0x0405 && tcg-storage.l0.feat.length == 28'
                  f' && {geometry}align == 1 && {geometry}lbs == 4096'
                  f' && {geometry}granularity == 8 && {geometry}lowest_lba == 0'
                  ' && !tcg-storage.l0.feat.data && !_ws.expert')),
        ]))


class TestNvmeSecuritySelector:
    """SIIS 1.20 Tables 23/24: SECP 00h is not defined for IF-SEND and SECP 06h
    is not defined for NVMe; nvme-mi-security.pcapng F71-F98."""

    FILE = 'nvme-mi-security.pcapng'
    SECTION = 7

    @pytest.mark.parametrize('two_pass', (False, True))
    def test_selector_experts(self, assert_frames_match, tshark_fields, two_pass):
        send = 'nvme.security.secp_send_undefined'
        nvme = 'nvme.security.secp_nvme_undefined'
        raw = 'nvme.cmd.security.data == ' + ':'.join(['a5'] * 16)
        on_secp = ' && count(_ws.expert) == 1 && !tcg-storage && !nvme.security.info'
        assert_frames_match(self.FILE, at(self.SPAN, [
            (1, f'{send} && nvme.cmd.security.dword10.secp == 0 && {raw}{on_secp}'),
            (3, f'{send} && !nvme.cmd.security.data{on_secp}'),
            (6, 'nvme.security.info.protocol == 0x02 && !_ws.expert'),
            (8, 'nvme.security.info.cert_len == 4 && !_ws.expert'),
            (10, 'nvme.security.info.compliance_len == 12 && !_ws.expert'),
            (11, f'{nvme} && nvme.cmd.security.dword10.secp == 6 && {raw}{on_secp}'),
            *[(frame, f'{nvme} && nvme.cmd.security.dword10.secp == 6{on_secp}')
              for frame in (13, 15, 17)],
            (16, f'{raw} && !_ws.expert && !tcg-storage'),
            (19, f'{raw} && !_ws.expert && !tcg-storage'),
            *[(frame, f'{raw} && !_ws.expert && !tcg-storage') for frame in (22, 24)],
            (26, 'tcg-storage.l0.feat.code == 0x0203 && !_ws.expert'),
            (27, 'tcg-storage.comid_mgmt.request_code == 2 && !_ws.expert'),
        ]), two_pass=two_pass)
        rows = in_section(tshark_fields, self.SPAN)(
            self.FILE, f'{send} || {nvme}', two_pass=two_pass)
        assert list(map(int, rows.split())) == [1, 3, 11, 13, 15, 17]

    def test_expert_on_selector(self, dissect_pdml):
        packets = pdml_section(dissect_pdml(self.FILE), self.SPAN).packets
        for frame, name in ((1, 'send'), (3, 'send'), (11, 'nvme'), (13, 'nvme'),
                            (15, 'nvme'), (17, 'nvme')):
            assert expert_anchors(packets[frame]) == {
                (f'nvme.security.secp_{name}_undefined',
                 'nvme.cmd.security.dword10.secp'): 1}, frame


class TestTcgStorageShortTransfer:
    """Security Receive transfers shorter than the Allocation Length."""

    # F1/F2  ComPacket, AL 88, 64 bytes delivered
    # F3/F4  AL 40 fully delivered, ComPacket declaring 68: a real overrun
    # F5/F6  Level 0 Discovery: DLEN 64 of AL 136, a fulfilled MI selection
    #        and so a legal prefix, not a short transfer
    # F7/F8  the ComPacket cut at 30 bytes, inside the Packet header
    # F9/F10 the Discovery selected at DLEN 50 of 136 bytes, inside a feature
    #        header: attributed as a selected prefix, though DLEN 50 is not
    #        dword aligned and so is not normative MI traffic

    FILE = 'nvme-mi-security.pcapng'
    SECTION = 2

    def test_expert_anchors(self, dissect_pdml):
        """A fulfilled MI selection is a legal prefix, not a short transfer (Core 3.3.6.2)."""
        short, overrun, truncated = ('tcg-storage.' + name for name in
                                     ('transfer_short', 'length_overrun', 'truncated'))
        pdml = pdml_section(dissect_pdml(self.FILE), self.SPAN)
        assert tcg_anchors(pdml.packets) == {
            2: Counter((short, 'tcg-storage.' + name)
                       for name in ('compacket', 'packet', 'subpacket', 'data')),
            4: Counter({(overrun, 'tcg-storage.compacket.length'): 1,
                        (truncated, 'tcg-storage.data'): 1}),
            8: Counter({(short, 'tcg-storage.compacket'): 1, (short, 'tcg-storage.data'): 1}),
        }

    def test_declared_lengths_and_malformed_census(self, tshark_fields, assert_frames_match):
        """A short read is ordinary traffic: only F4 is malformed."""
        here = f'frame.number >= {self.SPAN[0]} && frame.number <= {self.SPAN[1]}'
        assert tshark_fields(self.FILE, here + ' && nvme-mi').split() == [
            str(frame_in(self.SPAN, n)) for n in range(1, 11)]
        assert tshark_fields(self.FILE, here + ' && _ws.malformed').split() == [
            str(frame_in(self.SPAN, 4))]
        assert_frames_match(self.FILE, at(self.SPAN, [
            (1, 'nvme.cmd.security_recv.dword11.al == 88'),
            (2, 'tcg-storage.compacket.length == 68 && tcg-storage.packet.length == 44'),
            (8, 'tcg-storage.compacket.length == 68 && tcg-storage.data'),
        ]))


class TestTcgStorageMalformed:
    """Token-stream and Level 0 Discovery error paths (Core 3.3.6.3.1.3, 3.3.7.1.1)."""

    FILE = 'nvme-mi-security.pcapng'
    SECTION = 6
    FIELDS = ('tcg-storage.tok.uid', 'tcg-storage.tok.status', '_ws.expert',
              '_ws.expert.message', '_ws.col.info', 'tcg-storage.l0.feat.length_not_aligned',
              'tcg-storage.l0.feat.invalid_length')

    def test_status_and_tsn(self, fields_table):
        t = section(fields_table(self.FILE, self.FIELDS), self.SPAN)
        statuses = column(t, 'tcg-storage.tok.status')
        assert [n for n, v in statuses.items() if int(v, 0) == 0x1234] == [8]
        assert not [n for n, v in statuses.items() if int(v, 0) == 5]
        assert not t[8]['_ws.expert']
        assert 'Status: Unknown' in t[8]['_ws.col.info']
        # F12 is a SyncSession whose SPSessionID is 0010h. Core 2.01 3.3.7.1.1
        # forbids the TSM to assign a TSN from 0 to 4095 to a regular session,
        # but the dissector does not diagnose it, so nothing is asserted about
        # its experts: only that the status closes with 0.
        assert [(n, row['tcg-storage.tok.status'])
                for n, row in t.items()
                if 0xff03 in uids(row['tcg-storage.tok.uid'])] == [
            (8, '0x0000000000001234'), (12, '0x0000000000000000')]
        assert t[8]['_ws.expert.message'] == ''
        assert list(column(t, 'tcg-storage.l0.feat.length_not_aligned')) == [10]
        assert list(column(t, 'tcg-storage.l0.feat.invalid_length')) == [10]

    def test_misaligned_length_is_not_realigned(self, assert_frames_match):
        """A misaligned feature Length is named, not repaired."""
        assert_frames_match(self.FILE, at(self.SPAN, [
            (10, ('tcg-storage.l0.feat.code == 0x0310'
                  ' && !(tcg-storage.l0.feat.code == 0x0003)')),
        ]))


class TestTcgIntegrityNote:
    """Security state is tracked only with verified MICs (NVMe-MI 2.1 3.2.1.1)."""

    FILE = 'nvme-mi-tcg.pcapng'
    MARKER = 'nvme-mi.admin.security_state_integrity'
    BAD_MIC = 'Message Integrity Check does not match the computed CRC-32C'
    # {case: indices into the case's frames}; absent cases carry no note.
    DEFAULT: ClassVar = {
        'send-bad': (0,), 'recv-bad': (1,), 'recv-bad-request': (1,),
        'recv-nomic-request': (1,), 'send-snap': (0,), 'recv-snap': (1,),
        'tper-reset-send': (0, 1), 'stack-reset-send': (0,), 'level0-recv': (1,),
        'tper-bad-request': (0, 1), 'tper-bad-response': (1,),
        'tper-nomic-response': (1,), 'tper-snap-response': (1,),
        'recv-replay': (1,), 'tper-replay': (0, 1),
    }
    # With checking disabled no MIC is verified good: every eligible frame.
    UNCHECKED: ClassVar = {
        **DEFAULT, 'send-good': (0,), 'recv-good': (1,), 'send-response-data': (0,),
        'tper-good': (0, 1), 'tper-bad-response': (0, 1), 'tper-nomic-response': (0, 1),
        'tper-snap-response': (0, 1), 'tper-sliced-cqe': (0,), 'tper-short-cqe': (0,),
        'tper-cqe-error': (0,), 'tper-mi-error': (0,), 'tper-response-data': (0,),
        'stack-reset-completion': (0,), 'compacket-completion': (0,),
    }
    PREFS: ClassVar = {
        'default': ({}, DEFAULT),
        'unchecked': ({'nvme-mi.check_mic': 'FALSE'}, UNCHECKED),
    }

    @pytest.fixture(scope='class')
    @classmethod
    def notes(cls, capture_file, generator):
        span, cases, packets = generated_section(
            generator, ('tcg_integrity_note_vectors', 1723000000), 9,
            capture_file(cls.FILE))
        assert len(packets) == 88
        return span, cases

    @staticmethod
    def expected(cases, notes):
        return {cases[name][i] for name, frames in notes.items() for i in frames}

    @pytest.mark.parametrize('prefs', sorted(PREFS))
    @pytest.mark.parametrize('two_pass', [False, True])
    def test_note_frames(self, notes, fields_table, prefs, two_pass):
        """The hidden marker keeps its filter while MIC status explains the result."""
        span, cases = notes
        values, expected = self.PREFS[prefs]
        t = section(fields_table(self.FILE, ('_ws.expert.message', self.MARKER),
                                 prefs=values,
                                 two_pass=two_pass), span)
        assert len(t) == span[1] - span[0] + 1
        assert list(column(t, self.MARKER)) == sorted(self.expected(cases, expected))
        assert all('security state advancement' not in row['_ws.expert.message'].lower()
                   for row in t.values())
        if prefs == 'default':
            bad = {n for n, row in t.items() if self.BAD_MIC in row['_ws.expert.message']}
            assert {cases['send-bad'][0], cases['recv-bad'][1], cases['level0-recv'][1],
                    cases['tper-bad-request'][0], cases['tper-bad-response'][1],
                    cases['recv-orphan'][0], cases['tper-orphan'][0]} <= bad

    def test_note_anchor(self, notes, dissect_pdml):
        """The state marker is hidden and does not create an expert highlight."""
        span, cases = notes
        pdml = pdml_section(dissect_pdml(self.FILE), span)
        for frame in sorted(self.expected(cases, self.DEFAULT)):
            marker, = pdml.fields(frame, self.MARKER)
            assert marker.get('hide') == 'yes', frame
            assert not any('security state advancement' in message.lower()
                           for message in pdml.experts(frame)), frame

    NEGATIVE = ('send-sliced', 'recv-sliced', 'recv-orphan', 'recv-mi-error',
                'recv-cqe-error', 'send-invalid-window', 'recv-invalid-window',
                'recv-later-window', 'recv-short', 'recv-surplus', 'send-response-data',
                'level0-send', 'secp3-send', 'secp0-recv', 'tper-sliced-cqe',
                'tper-short-cqe', 'tper-cqe-error', 'tper-mi-error', 'tper-orphan',
                'tper-incomplete-request', 'tper-invalid-request', 'tper-response-data',
                'stack-reset-completion', 'compacket-completion')

    def test_negatives_lack_verified_integrity(self, notes, fields_table):
        """Every negative case also fails another gate besides the MIC."""
        span, cases = notes
        t = section(fields_table(self.FILE, ('nvme-mi.mic.status',
                                             'nvme-mi.mic_unverified',
                                             '_ws.expert.message')), span)
        for name in self.NEGATIVE:
            assert name not in self.DEFAULT
            assert any(t[n]['nvme-mi.mic_unverified'] == 'True' or
                       'Message Integrity Check does not match' in
                       t[n]['_ws.expert.message'] for n in cases[name]), name

    def test_invalid_window_request(self, notes, fields_table):
        """DLEN past the SECP 01h AL is flagged (SIIS 1.20 Table 24)."""
        span, cases = notes
        t = section(fields_table(self.FILE, ('nvme-mi.admin.invalid_dlen',)), span)
        assert t[cases['recv-invalid-window'][0]]['nvme-mi.admin.invalid_dlen']

    def test_replay_never_noted(self, notes, fields_table):
        """A Replay is linked to the original but never noted."""
        span, cases = notes
        t = section(fields_table(self.FILE, ('nvme-mi.replay_of', self.MARKER)),
                    span)
        for name in ('recv-replay', 'tper-replay'):
            original, replayed = cases[name][1], cases[name][4]
            assert t[replayed]['nvme-mi.replay_of'] == str(original)
            assert t[original][self.MARKER] == 'True'
            assert not t[replayed][self.MARKER]

    def test_orphans_are_orphans(self, notes, fields_table):
        span, cases = notes
        t = section(fields_table(self.FILE, ('_ws.expert.message', 'nvme-mi.response_to')),
                    span)
        for name in ('recv-orphan', 'tper-orphan'):
            (frame,) = cases[name]
            assert 'Admin response without a usable matching request' in \
                t[frame]['_ws.expert.message']
            assert not t[frame]['nvme-mi.response_to']


class TestTcgResetLifecycle:
    """Stack Reset and TPer Reset state changes (Core 3.3.4.3.3, Opal SSC 2.30 3.2.3)."""

    FILE = 'nvme-mi-tcg.pcapng'
    FIELDS = ('tcg-storage.comid_mgmt.stack_reset_result',
              'nvme-mi.admin.tper_reset_applied',
              'tcg-storage.packet.secure_data', 'tcg-storage.tok.uid',
              'tcg-storage.tok.fragment', 'tcg-storage.tok.spans_compacket',
              'tcg-storage.packet.seq', 'nvme-mi.replay_of', '_ws.expert.message',
              'nvme-mi.admin.security_state_integrity',
              '_ws.col.info', 'nvme.cqe.status.sc', 'nvme.cqe.status.sct',
              'nvme.cqe.status.m', 'nvme.cqe.status.dnr')
    MARKER = TestTcgIntegrityNote.MARKER

    @pytest.fixture(scope='class')
    @classmethod
    def lifecycle(cls, capture_file, generator):
        span, cases, packets = generated_section(
            generator, ('tcg_reset_lifecycle_vectors', 1724000000), 10,
            capture_file(cls.FILE))
        assert len(packets) == 527
        return span, cases

    def table(self, fields_table, lifecycle, prefs=None):
        span, cases = lifecycle
        t = section(fields_table(self.FILE, self.FIELDS, prefs=prefs), span)
        assert len(t) == span[1] - span[0] + 1
        return t, cases

    @staticmethod
    def tcg(cases, name):
        """The frame carrying a case's TCG payload: a Send's request or a Receive's response."""
        frames = cases[name]
        return frames[0] if name.endswith(('-reset', '-supersede', '-tper', '-host-old', '-props')) or '-ff02' in name or '-ff04' in name else frames[1]

    def secure(self, row):
        return bool(row['tcg-storage.packet.secure_data'])

    def test_stack_reset_success_resets_after_traffic(self, lifecycle, fields_table):
        """A trusted Success resets the ComID even after intervening traffic."""
        t, cases = self.table(fields_table, lifecycle)
        tcg = lambda name: t[self.tcg(cases, name)]
        assert self.secure(tcg('late-secure'))
        assert all(tcg(name)['tcg-storage.tok.uid'] for name in (
            'late-props', 'late-props-response', 'late-ff02', 'late-ff03', 'late-ff04',
            'late-ff05'))
        assert tcg('late-success')['tcg-storage.comid_mgmt.stack_reset_result'] == '0x00000000'
        assert not tcg('late-success')['_ws.expert.message']
        assert tcg('late-raw')['tcg-storage.tok.uid']

    def test_stack_reset_quiet_success_once(self, lifecycle, fields_table):
        """A successful response resets state and restores synchronous defaults."""
        t, cases = self.table(fields_table, lifecycle)
        tcg = lambda name: self.tcg(cases, name)
        assert self.secure(t[tcg('quiet-secure')])
        assert t[tcg('quiet-success')]['tcg-storage.comid_mgmt.stack_reset_result'] == \
            '0x00000000'
        old = t[tcg('quiet-old')]
        assert not self.secure(old) and old['tcg-storage.tok.uid']
        # Synchronous defaults again (Core 5.2.2.2): a split atom is rejected.
        assert t[tcg('quiet-first')]['tcg-storage.tok.spans_compacket']
        assert not t[tcg('quiet-first')]['tcg-storage.tok.fragment']
        assert 'session aborted after an atom' in t[tcg('quiet-next')]['_ws.col.info']
        assert self.secure(t[tcg('quiet-new-secure')])
        assert t[tcg('quiet-repeat')]['tcg-storage.comid_mgmt.stack_reset_result'] == \
            '0x00000000'
        assert not self.secure(t[tcg('quiet-new-again')])
        for twin in ('empty', 'duplicate'):
            assert t[tcg(twin + '-success')]['tcg-storage.comid_mgmt.stack_reset_result'] == \
                '0x00000000'

    def test_stack_reset_supersession_and_failure(self, lifecycle, fields_table):
        """Only a successful Stack Reset response resets the tracked state."""
        t, cases = self.table(fields_table, lifecycle)
        tcg = lambda name: self.tcg(cases, name)
        for name in ('verify', 'unknown'):
            assert t[tcg(name + '-success')]['tcg-storage.comid_mgmt.stack_reset_result'] == \
                '0x00000000'
        for name in ('fail-failure', 'fail-pending', 'fail-none'):
            expected = '0x00000001' if name == 'fail-failure' else ''
            assert t[tcg(name)]['tcg-storage.comid_mgmt.stack_reset_result'] == expected, name
        assert self.secure(t[tcg('fail-secure')])
        assert t[tcg('fail-success')]['tcg-storage.comid_mgmt.stack_reset_result'] == \
            '0x00000000'
        assert t[tcg('fail-success-again')]['tcg-storage.comid_mgmt.stack_reset_result'] == \
            '0x00000000'
        assert self.secure(t[tcg('fail-new-secure')])

    def test_stack_reset_success_replaces_reissued_generation(self, lifecycle,
                                                              fields_table):
        """A successful Stack Reset response resets the current generation."""
        t, cases = self.table(fields_table, lifecycle)
        tcg = lambda name: self.tcg(cases, name)
        for name in ('reissue', 'retire'):
            assert t[tcg(name + '-success')]['tcg-storage.comid_mgmt.stack_reset_result'] == \
                '0x00000000'
            assert not self.secure(t[tcg(name + '-new-secure')]), name
        assert t[cases['retire-tper'][1]]['nvme-mi.admin.tper_reset_applied'] == 'True'
        old = t[tcg('reissue-old')]
        assert not self.secure(old)

    def test_stack_reset_overrides_observed_async(self, lifecycle, fields_table):
        """A successful STACK_RESET restores synchronous mode (Core 3.3.4.7.5)."""
        t, cases = self.table(fields_table, lifecycle)
        tcg = lambda name: self.tcg(cases, name)
        assert cases['status-bits-tper-after'][1] == len(t)
        assert t[tcg('sync-async-first')]['tcg-storage.tok.fragment']
        assert not t[tcg('sync-async-first')]['_ws.expert.message']
        assert t[tcg('sync-success')]['tcg-storage.comid_mgmt.stack_reset_result'] == \
            '0x00000000'
        first = t[tcg('sync-first')]
        assert first['tcg-storage.tok.spans_compacket'] and not first['tcg-storage.tok.fragment']
        assert 'while synchronous' in first['_ws.expert.message']

    def test_tper_reset_completion_retires_only_its_scope(self, lifecycle, fields_table):
        """A TPer Reset completion retires only its own scope's ComIDs."""
        t, cases = self.table(fields_table, lifecycle)
        tcg = lambda name: self.tcg(cases, name)
        request, completion = cases['a-tper']
        assert not t[request]['nvme-mi.admin.tper_reset_applied']
        assert t[completion]['nvme-mi.admin.tper_reset_applied'] == 'True'
        for name in ('a9-secure', 'a10-secure', 'b9-secure', 'b10-secure',
                     'a10-new-secure'):
            assert self.secure(t[tcg(name)]), name
        assert t[tcg('a9-first')]['tcg-storage.tok.fragment']
        for name in ('a9-old', 'a9-host-old', 'a10-old'):
            row = t[tcg(name)]
            assert row['tcg-storage.tok.uid'] and not self.secure(row), name
        nxt = t[tcg('a9-next')]
        assert 'Session Manager' not in nxt['_ws.col.info'] and \
            not nxt['tcg-storage.tok.fragment']
        assert t[tcg('a9-reset-first')]['tcg-storage.tok.spans_compacket']
        assert t[tcg('b9-first')]['tcg-storage.tok.fragment']
        assert t[tcg('a10-first')]['tcg-storage.tok.spans_compacket']
        assert 'session aborted after an atom' in t[tcg('a10-next')]['_ws.col.info']
        section_frames = range(1, len(t) + 1)
        assert {n for n in section_frames
                if t[n]['nvme-mi.admin.tper_reset_applied'] == 'True'} == \
            {cases[name][1] for name in
             ('retire-tper', 'a-tper', 'replay-tper', 'status-bits-tper')}

    def test_admin_success_with_m_dnr_updates_tcg_state(self, lifecycle,
                                                        fields_table):
        """M and DNR do not override the SCT and SC success status."""
        t, cases = self.table(fields_table, lifecycle)
        properties = cases['status-bits-properties-props-response'][1]
        gap = cases['status-bits-gap'][1]
        tper = cases['status-bits-tper'][1]
        after = cases['status-bits-tper-after'][1]
        for frame in (properties, tper):
            assert t[frame]['nvme.cqe.status.sc'] == '0x0000'
            assert t[frame]['nvme.cqe.status.sct'] == '0x0000'
            assert t[frame]['nvme.cqe.status.m'] == 'True'
            assert t[frame]['nvme.cqe.status.dnr'] == 'True'
            assert not t[frame]['_ws.expert.message']
        assert t[gap]['tcg-storage.packet.seq'] == '3'
        assert 'sequence gap' in t[gap]['_ws.col.info']
        assert t[tper]['nvme-mi.admin.tper_reset_applied'] == 'True'
        assert not self.secure(t[after])

    FAILED = ('mi-error', 'cqe-error', 'missing', 'short-cqe', 'zero', 'invalid', 'data')
    UNVERIFIED = ('bad-response', 'bad-request', 'snap')

    def test_tper_reset_failed_or_missing_completion_keeps_state(self, lifecycle,
                                                                 fields_table):
        """A failed, missing or short TPer Reset completion keeps state."""
        t, cases = self.table(fields_table, lifecycle)
        for name in self.FAILED:
            assert all(not t[n]['nvme-mi.admin.tper_reset_applied']
                       for n in cases[name + '-tper']), name
            assert self.secure(t[self.tcg(cases, name + '-secure')]), name
        assert len(cases['missing-tper']) == 1

    def test_tper_reset_integrity_and_replay(self, lifecycle, fields_table):
        """Unverified completions and Replays never reset a TPer."""
        t, cases = self.table(fields_table, lifecycle)
        for name in self.UNVERIFIED:
            completion = cases[name + '-tper'][1]
            assert t[completion]['nvme-mi.admin.tper_reset_applied'] == 'False', name
            assert self.secure(t[self.tcg(cases, name + '-secure')]), name
        marked = {n for n, row in t.items()
                  if row[self.MARKER] == 'True'}
        assert marked == {cases['bad-response-tper'][1], cases['bad-request-tper'][0],
                          cases['bad-request-tper'][1], cases['snap-tper'][1]}
        (orphan,) = cases['orphan-tper']
        assert 'Admin response without a usable matching request' in \
            t[orphan]['_ws.expert.message']
        assert not t[orphan]['nvme-mi.admin.tper_reset_applied']
        assert self.secure(t[self.tcg(cases, 'orphan-secure')])
        _request, completion = cases['replay-tper']
        assert t[completion]['nvme-mi.admin.tper_reset_applied'] == 'True'
        replayed = cases['replay-replayed']
        assert any(t[n]['nvme-mi.replay_of'] for n in replayed)
        assert all(not t[n]['nvme-mi.admin.tper_reset_applied'] for n in replayed)
        assert self.secure(t[self.tcg(cases, 'replay-new-secure')])

    def test_tper_reset_unchecked_mic_never_applies(self, lifecycle, fields_table):
        """With MIC checking disabled, no TPer Reset completion applies."""
        t, cases = self.table(fields_table, lifecycle, prefs={'nvme-mi.check_mic': 'FALSE'})
        assert not any(row['nvme-mi.admin.tper_reset_applied'] == 'True'
                       for row in t.values())
        for name in ('retire-tper', 'a-tper', 'replay-tper'):
            assert t[cases[name][1]]['nvme-mi.admin.tper_reset_applied'] == 'False', name
            assert t[cases[name][1]][self.MARKER] == 'True', name

    def test_stack_reset_success_results(self, lifecycle, fields_table):
        """Every Stack Reset response of the lifecycle that succeeds, including
        the reissued and the forensic-unmatched ones, reports result 0."""
        t, cases = self.table(fields_table, lifecycle)
        successes = [self.tcg(cases, name) for name in (
            'late-success', 'quiet-success', 'empty-success', 'duplicate-success',
            'verify-success', 'unknown-success', 'fail-success', 'reissue-success',
            'forensic-unmatched')]
        for frame in successes:
            assert t[frame]['tcg-storage.comid_mgmt.stack_reset_result'] == '0x00000000'


class TestTcgRequestIntegrityNote:
    """Filterable Security Send integrity status on the tcg_integrity_note_vectors."""

    FILE = 'nvme-mi-tcg.pcapng'
    NOTE = 'nvme-mi.admin.security_state_integrity'
    POSITIVE = ('send-good', 'send-response-data', 'compacket-completion')

    @pytest.fixture(scope='class')
    @classmethod
    def notes(cls, capture_file, generator):
        span, cases, _ = generated_section(
            generator, ('tcg_integrity_note_vectors', 1723000000), 9,
            capture_file(cls.FILE))
        return span, cases, generator

    def noted(self, pdml, frame):
        return bool(pdml.fields(frame, self.NOTE))

    def test_spsp_0001_send(self, notes, dissect_pdml, tmp_path_factory):
        """A SECP 01h/SPSP 0001h Send renders its Data without a state marker."""
        _, _, g = notes
        compacket = g['tcg_compacket'](g['tcg_packet'](
            g['tcg_subpacket'](g['TCG_EOD_STATUS_SUCCESS']), 0x100, 0x1), 0x1000)
        data = g['shb']() + g['idb']()
        frames = []
        for eid, spsp, payload in ((0xE0, 0x1000, compacket), (0xE1, 0x0001, bytes(4))):
            frames += [g['mi_admin_frame'](True, g['mi_security_request'](True, 1, spsp,
                                                                        payload), eid, 0),
                       g['mi_admin_frame'](False, g['admin_resp_with_data'](b''), eid, 0)]
        for i, (packet, original) in enumerate(frames):
            data += g['epb'](packet, 1725000000 * 1_000_000 + i * 1_000_000, origlen=original)
        path = tmp_path_factory.mktemp('tx4') / 'spsp-0001.pcapng'
        path.write_bytes(data)
        pdml = dissect_pdml(str(path))
        assert any(f.get('show') == 'Data' for f in pdml[3].iter('field'))
        assert not self.noted(pdml, 3)


class TestTcgStorageLevel0Opal230:
    """Opal SSC 2.30 Level 0 descriptors (Opal 2.30 Tables 3-12, Core 2.01
    Tables 40 and 43)."""

    FILE = 'nvme-mi-tcg.pcapng'
    INDEX = 11
    L0 = 'tcg-storage.l0.feat.'
    DRM = L0 + 'data_removal.'

    @pytest.fixture(scope='class')
    @classmethod
    def frames(cls, capture_file, generator):
        span, cases, _ = generated_section(
            generator, ('tcg_level0_opal230_vectors', 1725000000), cls.INDEX,
            capture_file(cls.FILE))
        return {name: span[0] - 1 + response for name, (_, response) in cases.items()}

    def test_descriptor_fields(self, frames, assert_frames_match):
        lk, op = self.L0 + 'locking.', self.L0 + 'opal2.'
        new_version = 'tcg-storage.l0.unsupported_version && len(tcg-storage.l0.feat.data) == '
        assert_frames_match(self.FILE, [
            (frames['locking-v3'],
             (f'{lk}hw_reset == 1 && {lk}mbr_shadowing_not_supported == 1 && {lk}locked == 1'
             f' && !{lk}reserved && !tcg-storage.l0.unsupported_version && !_ws.expert')),
            (frames['locking-v1-reserved'],
             (f'{lk}reserved == 3 && !{lk}hw_reset && !{lk}mbr_shadowing_not_supported'
             f' && {lk}supported == 1 && !_ws.expert')),
            # Pyrite SSC 2.01 / Ruby SSC 1.00 Table 5: bit 7 is Reserved in Version 2.
            (frames['locking-v2'],
             (f'{lk}reserved_v2 == 1 && {lk}mbr_shadowing_not_supported == 1 && !{lk}hw_reset'
             f' && !tcg-storage.l0.unsupported_version && !tcg-storage.l0.feat.data'
             f' && !_ws.expert')),
            (frames['locking-v4-extended'], f'{lk}hw_reset == 1 && {new_version}15'),
            (frames['tper-v2'],
             f'{self.L0}tper.async == 1 && {self.L0}tper.streaming == 1 && {new_version}11'),
            (frames['opal2-minor3-msid'],
             (f'{self.L0}ssc_minor == 3 && {op}initial_cpin_sid == 0'
             f' && {op}revert_cpin_sid == 0 && !_ws.expert')),
            (frames['opal2-minor3-vu'],
             f'{op}initial_cpin_sid == 0xff && {op}revert_cpin_sid == 0xff'),
            (frames['opal2-minor4-reserved'],
             f'{self.L0}ssc_minor == 4 && {op}initial_cpin_sid == 0x7f'),
            (frames['drm-times'],
             (f'{self.DRM}format.crypto_erase == 1 && {self.DRM}time_crypto_erase == 5'
             f' && {self.DRM}time_block_erase == 65535 && len({self.DRM}reserved2) == 16'
             f' && !tcg-storage.l0.feat.data && !_ws.expert')),
            (frames['feature-0000'],
             (f'{self.L0}code == 0x0000 && {self.L0}code == 0x0001'
             f' && {self.L0}tper.flags == 0x41 && !_ws.expert')),
            (frames['drm-v2-len16'],
             (f'{self.L0}length == 16 && {self.DRM}time_vendor == 30'
             f' && !{self.DRM}reserved2 && !tcg-storage.l0.feat.data'
             f' && tcg-storage.l0.feat.invalid_length')),
            (frames['drm-v2-len36'],
             (f'{self.L0}length == 36 && len({self.DRM}reserved2) == 16'
             f' && len(tcg-storage.l0.feat.data) == 4'
             f' && tcg-storage.l0.feat.invalid_length')),
            # No specification defines Version 3; Version 2 withdrew fields of
            # Version 1, so the body stays raw.
            (frames['drm-v3-len16'],
             (f'{self.L0}version == 3 && tcg-storage.l0.unsupported_version'
             f' && len(tcg-storage.l0.feat.data) == 16 && !{self.DRM}mechanism'
             f' && !{self.DRM}time_vendor && !_ws.expert')),
            (frames['drm-v2-window'],
             (f'{self.L0}length == 32 && len(tcg-storage.l0.feat.data) == 16'
             f' && !{self.DRM}time_crypto_erase && !_ws.expert')),
            (frames['drm-v2-len16-window'],
             (f'{self.L0}length == 16 && len(tcg-storage.l0.feat.data) == 8'
             f' && !{self.DRM}time_crypto_erase && tcg-storage.l0.feat.invalid_length')),
        ])

    def test_display_text(self, frames, dissect_pdml):
        pdml = dissect_pdml(self.FILE)

        def shows(name, field):
            return pdml.shownames(frames[name], field)

        assert shows('opal2-minor3-msid', self.L0 + 'ssc_minor') == [
            '.... 0011 = SSC Minor Version Number: Opal SSC 2.30 (0x3)']
        assert shows('opal2-minor4-reserved', self.L0 + 'ssc_minor') == [
            '.... 0100 = SSC Minor Version Number: Reserved (0x4)']
        assert shows('opal2-minor3-vu', self.L0 + 'opal2.initial_cpin_sid') == [
            ('Initial C_PIN_SID PIN Indicator: Vendor Unique (may differ from C_PIN_MSID PIN)'
            ' (0xff)')]
        assert shows('drm-times', self.DRM + 'time_overwrite') == [
            'Data Removal Time (Overwrite Data Erase): 0 (Not reported)']
        assert shows('drm-times', self.DRM + 'time_block_erase') == [
            'Data Removal Time (Block Erase): 65535 (>= 131068 seconds)']
        assert shows('drm-times', self.DRM + 'time_crypto_erase') == [
            'Data Removal Time (Cryptographic Erase): 5 (10 minutes)']
        assert shows('drm-times', self.DRM + 'time_vendor') == [
            'Data Removal Time (Vendor Specific Erase): 30 (60 seconds)']
        assert pdml.shownames(frames['feature-0000'], 'tcg-storage.l0.feat') == [
            'Reserved', 'TPer Feature']
        assert shows('feature-0000', self.L0 + 'code') == [
            'Feature Code: Reserved (0x0000)', 'Feature Code: TPer Feature (0x0001)']
        # Feature and field names as Opal SSC 2.30 3.1.1.5/3.1.1.6 and Table 6 give them.
        assert shows('opal2-minor3-msid', self.L0 + 'code') == [
            'Feature Code: Opal SSC V2 Feature (0x0203)']
        assert shows('opal2-minor3-msid', self.L0 + 'opal2.num_admins') == [
            'Number of Locking SP Admin Authorities Supported: 4']
        assert shows('opal2-minor3-msid', self.L0 + 'opal2.num_users') == [
            'Number of Locking SP User Authorities Supported: 4']
        assert shows('drm-times', self.L0 + 'code') == [
            'Feature Code: Supported Data Removal Mechanism Feature (0x0404)']

    def test_drm_v2_length(self, frames, dissect_pdml):
        """Opal 2.30 Table 9 Length 0x20, anchored on Length, in both passes."""
        flagged = ('drm-v2-len16', 'drm-v2-len36', 'drm-v2-len16-window')
        for two_pass in (False, True):
            pdml = dissect_pdml(self.FILE, two_pass=two_pass)
            for name in flagged:
                packet = pdml[frames[name]]
                assert tcg_anchors({0: packet}) == {0: Counter({
                    ('tcg-storage.l0.feat.invalid_length',
                     'tcg-storage.l0.feat.length'): 1})}, name
                assert any('Supported Data Removal Mechanism Feature Descriptor' in m
                           for m in pdml.experts(frames[name])), name
            for name in ('drm-times', 'drm-v3-len16', 'drm-v2-window'):
                assert not pdml.experts(frames[name]), name


class TestTcgMethodSemantics:
    """Method parameter names from the Core 2.01 and Opal SSC 2.30 signatures,
    UIDs resolved only in uidref parameters (Core Appendix 1, Opal 4.2/4.3),
    printable byte-sequence Names, and the Start/End Transaction status
    (Core 3.2.2.3.3.4/5, Tables 15/16)."""

    FILE = 'nvme-mi-tcg.pcapng'
    INDEX = 12

    @pytest.fixture(scope='class')
    @classmethod
    def frames(cls, capture_file, generator):
        span, cases, _ = generated_section(
            generator, ('tcg_method_semantics_vectors', 1726000000), cls.INDEX,
            capture_file(cls.FILE))
        return {name: (span[0] - 1 + request, span[0] - 1 + response)
                for name, (request, response) in cases.items()}

    def test_parameter_names(self, frames, tshark_fields):
        def params(name, field='tcg-storage.param'):
            return tshark_fields(self.FILE, f'frame.number == {frames[name][0]}',
                                 (field,)).strip().split(',')

        assert params('start-session') == [
            'HostSessionID', 'SPID', 'Write', 'HostExchangeAuthority',
            'HostSigningAuthority', 'SessionTimeout']
        # An option whose name is not a uinteger leaves later ones intact.
        assert params('bad-option-name') == [
            'HostSessionID', 'SPID', 'Write',
            'Optional parameter (name is not a uinteger)', 'TransTimeout']
        assert params('locking-next') == ['Where', 'Count']
        assert params('get-cellblock') == [
            'startRow', 'startColumn', 'endColumn',
            'Cellblock component (unrecognized name)', 'Cellblock']
        assert params('authenticate') == ['Authority', 'Proof']
        assert params('set-values') == ['Values']
        assert params('unknown-method') == [
            'Required parameter 0', 'Required parameter 1', 'Optional parameter 2']
        assert params('revert-sp') == ['KeepGlobalRangeKey']
        # Feature Set parameters stay numbered.
        assert params('activate-sum') == ['Optional parameter 0x60000']
        assert params('delete-row') == ['Rows entry', 'Rows entry', 'Rows']
        assert params('add-ace') == ['InvokingID', 'MethodID', 'ACE']
        assert params('genkey-range') == ['PinLength']
        assert params('descriptor-get') == ['Cellblock']

    def test_uid_resolution(self, frames, dissect_pdml, assert_frames_match):
        pdml = dissect_pdml(self.FILE)

        def uids(name):
            return pdml.shownames(frames[name][0], 'tcg-storage.param.uid')

        assert uids('start-session') == [
            'Parameter UID: Admin SP (0x0000020500000001)',
            'Parameter UID: SID (0x0000000900000006)',
            'Parameter UID: Admin1 (0x0000000900010001)']
        assert uids('locking-next') == ['Parameter UID: Locking_Range1 (0x0000080200030001)']
        assert uids('get-cellblock') == ['Parameter UID: C_PIN_User2 (0x0000000b00030002)']
        # Admin SP Admin1 takes precedence over the Admin template Issuers row.
        assert uids('authenticate') == ['Parameter UID: Admin1 (Admin SP) (0x0000000900000201)']
        assert uids('delete-row') == [
            'Parameter UID: User3 (0x0000000900030003)',
            'Parameter UID: Authority row 0x00abcdef (0x0000000900abcdef)']
        assert uids('add-ace') == [
            'Parameter UID: Locking_Range2 (0x0000080200030002)',
            'Parameter UID: Set (0x0000000600000017)',
            'Parameter UID: ACE_Locking_Range2_Set_RdLocked (0x000000080003e002)']
        assert pdml.shownames(frames['start-session'][0], 'tcg-storage.tok.bytes')[2] == \
            'Bytes: 0000020500000001 [SPID: Admin SP]'
        assert_frames_match(self.FILE, [
            # Bytes that look like a UID are not resolved outside a uidref.
            (frames['authenticate'][0], 'count(tcg-storage.param.uid) == 1'),
            (frames['set-values'][0], '!tcg-storage.param.uid && !_ws.expert'),
            (frames['unknown-method'][0],
             '!tcg-storage.param.uid && _ws.col.info contains "This SP.0x00000006000000aa()"'),
            (frames['revert-sp'][0], '!tcg-storage.param.uid && !_ws.expert'),
            (frames['activate-sum'][0],
             '!tcg-storage.param.uid && _ws.col.info contains "Locking SP.Activate()"'),
            (frames['locking-next'][0], '_ws.col.info contains "Locking.Next()"'),
            (frames['get-cellblock'][0], '_ws.col.info contains "C_PIN.Get()"'),
            (frames['genkey-range'][0], '_ws.col.info contains "K_AES_256_Range3_Key.GenKey()"'),
            (frames['descriptor-get'][0],
             '_ws.col.info contains "Locking table descriptor.Get()"'),
            (frames['txn-host'][0], '_ws.col.info contains "Locking_GlobalRange.Get()"'),
            # The invoking and method UID fields keep their count of two.
            (frames['add-ace'][0], 'count(tcg-storage.tok.uid) == 2 && !_ws.expert'),
        ])

    def test_transactions(self, frames, assert_frames_match):
        assert_frames_match(self.FILE, [
            (frames['txn-host'][0],
             ('tcg-storage.txn.start_status == 0 && tcg-storage.txn.end_status == 0'
             ' && !(_ws.col.info contains "aborted") && !_ws.expert')),
            (frames['txn-tper-abort'][1],
             ('tcg-storage.txn.start_status == 0 && tcg-storage.txn.end_status == 1'
             ' && _ws.col.info contains ", Transaction aborted" && !_ws.expert')),
            # Any nonzero SP End Transaction status means the SP aborted.
            (frames['txn-bad-status'][1],
             ('tcg-storage.txn.status_type && !tcg-storage.txn.start_status'
             ' && tcg-storage.txn.end_status == 127'
             ' && _ws.col.info contains ", Transaction aborted"')),
        ])

    def test_display_text(self, frames, dissect_pdml):
        pdml = dissect_pdml(self.FILE)
        assert pdml.shownames(frames['txn-tper-abort'][1], 'tcg-storage.txn.end_status') == [
            'End Transaction Status: Abort (1)']
        assert pdml.shownames(frames['txn-bad-status'][1], 'tcg-storage.txn.end_status') == [
            'End Transaction Status: Reserved (127)']
        assert pdml.shownames(frames['authenticate'][0], 'tcg-storage.tok.bytes')[2:] == [
            'Bytes: 0000000900000201 [Authority: Admin1 (Admin SP)]',
            'Bytes: 0000020500000001 [Proof]']


class TestTcgMethodPairing:
    """Regular-session responses paired with their calls (Core 3.2.4.2) and
    results named from the method result signatures (Core 5.3.3, 5.4.3.1)."""

    FILE = 'nvme-mi-tcg.pcapng'
    INDEX = 13

    @pytest.fixture(scope='class')
    @classmethod
    def frames(cls, capture_file, generator):
        span, cases, _ = generated_section(
            generator, ('tcg_method_pairing_vectors', 1727000000), cls.INDEX,
            capture_file(cls.FILE))
        return {name: [span[0] - 1 + frame for frame in scenario]
                for name, scenario in cases.items()}

    def test_pairing(self, frames, assert_frames_match):
        get, multiple = frames['get'], frames['multiple']
        msid, rand, rand_resp, msid_resp = frames['interleaved']
        control = frames['control-session']
        assert_frames_match(self.FILE, [
            (get[1], (f'tcg-storage.request_in == {get[0]}'
             ' && tcg-storage.response_to == "Locking_GlobalRange.Get"'
             ' && _ws.col.info contains ", Response to Locking_GlobalRange.Get(), Status: SUCCESS"')),
            (get[0], f'tcg-storage.response_in == {get[1]}'),
            # Three calls in one Send, answered in order by one Receive.
            (multiple[1], (f'count(tcg-storage.request_in) == 3'
             f' && all tcg-storage.request_in == {multiple[0]}'
             ' && tcg-storage.response_to == "Locking.Next"'
             ' && tcg-storage.response_to == "This SP.Authenticate"'
             ' && tcg-storage.response_to == "AccessControl.GetACL"')),
            (multiple[0], 'count(tcg-storage.response_in) == 3'),
            # Each session keeps its own queue.
            (rand_resp, (f'tcg-storage.request_in == {rand}'
             ' && tcg-storage.response_to == "This SP.Random"')),
            (msid_resp, (f'tcg-storage.request_in == {msid}'
             ' && tcg-storage.response_to == "C_PIN_MSID.Get"')),
            (frames['unpaired'][0],
             '!tcg-storage.response_to && !tcg-storage.param && tcg-storage.tok.status == 0'),
            (frames['unknown-method'][1],
             'tcg-storage.response_to == "This SP.0x00000006000000aa"'),
            (frames['empty-result'][1],
             'tcg-storage.response_to == "C_PIN_SID.Set" && !tcg-storage.param'),
            # Session Manager calls carry their own method header.
            (control[0], '!tcg-storage.response_in'),
            (control[1], '!tcg-storage.request_in && !tcg-storage.response_to'),
            (control[2], '!tcg-storage.response_to'),
        ], two_pass=True)

    def test_one_pass(self, frames, assert_frames_match):
        """The pairing is known on the first pass; only the forward link
        from the call needs the second."""
        get = frames['get']
        assert_frames_match(self.FILE, [
            (get[1], (f'tcg-storage.request_in == {get[0]}'
             ' && _ws.col.info contains "Response to Locking_GlobalRange.Get()"')),
            (get[0], '!tcg-storage.response_in && tcg-storage.tok.uid'),
        ])

    def test_result_names(self, frames, tshark_fields, dissect_pdml):
        def params(frame, field='tcg-storage.param'):
            return tshark_fields(self.FILE, f'frame.number == {frame}',
                                 (field,)).strip().split(',')

        assert params(frames['get'][1]) == ['Result']
        assert params(frames['multiple'][1], 'tcg-storage.response_to') == [
            'Locking.Next', 'This SP.Authenticate', 'AccessControl.GetACL']
        assert params(frames['multiple'][1]) == [
            'Result entry', 'Result entry', 'Result', 'Result',
            'Result entry', 'Result entry', 'Result']
        assert params(frames['unknown-method'][1]) == ['Result value 0', 'Result value 1']
        assert params(frames['free-space'][1]) == ['FreeSpace', 'TableRows']
        assert params(frames['interleaved'][2]) == ['Result']
        pdml = dissect_pdml(self.FILE)
        assert pdml.shownames(frames['multiple'][1], 'tcg-storage.param.uid') == [
            'Parameter UID: Locking_GlobalRange (0x0000080200000001)',
            'Parameter UID: Locking_Range1 (0x0000080200030001)',
            ('Parameter UID: ACE_Locking_Range1_Get_RangeStartToActiveKey'
            ' (0x000000080003d001)'),
            'Parameter UID: ACE_Anybody (0x0000000800000001)']


class TestTcgTrustedSessionFailure:
    """A failed StartTrustedSession leaves nothing for a later
    SyncTrustedSession to answer: the TPer's failure reply (Core 5.3.4.1.5)
    and a failed Security Send both end the pending request.  3.3.10.2.1 item
    3 describes the state after an IF-SEND that completed without error; that
    the TPer did not act on a failed one is inferred from it."""

    FILE = 'nvme-mi-tcg.pcapng'
    INDEX = 14
    SECURE = 'tcg-storage.packet.secure_data && !tcg-storage.tok.uid'
    PLAIN = '!tcg-storage.packet.secure_data && tcg-storage.tok.uid'

    @pytest.fixture(scope='class')
    @classmethod
    def frames(cls, capture_file, generator):
        span, cases, _ = generated_section(
            generator, ('tcg_trusted_failure_vectors', 1728000000), cls.INDEX,
            capture_file(cls.FILE))
        return {name: [span[0] - 1 + frame for frame in scenario]
                for name, scenario in cases.items()}

    def test_failure_voids_the_pending_start(self, frames, assert_frames_match):
        for two_pass in (False, True):
            assert_frames_match(self.FILE, [
                (frames['ok-payload'][1], self.SECURE),
                (frames['reply-fail-failed'][1],
                 'tcg-storage.tok.uid == 0xff05 && _ws.col.info contains "NOT_AUTHORIZED"'),
                (frames['reply-fail-payload'][1], self.PLAIN),
                (frames['send-fail-payload'][1], self.PLAIN),
            ], two_pass=two_pass)


class TestTcgTrustedSessionRace:
    """Two StartTrustedSession Security Sends for one session, one per
    NVMe-MI Command Slot, both outstanding when the first completes with an
    error: the failure must not end the second request, so its successful
    SyncTrustedSession makes the session secure."""

    FILE = 'nvme-mi-tcg.pcapng'
    INDEX = 17

    def test_failure_keeps_a_later_start(self, capture_file, generator,
                                         assert_frames_match):
        span, cases, _ = generated_section(
            generator, ('tcg_trusted_race_vectors', 1733000000), self.INDEX,
            capture_file(self.FILE))
        frames = {name: [span[0] - 1 + frame for frame in pair]
                  for name, pair in cases.items()}
        # The failed Send completes after the second one was sent.
        assert frames['first-ff04'][0] < frames['second-ff04'][0] < frames['first-ff04'][1]
        for two_pass in (False, True):
            assert_frames_match(self.FILE, [
                (frames['ff05'][1], 'tcg-storage.tok.uid == 0xff05 && !_ws.expert'),
                (frames['payload'][1],
                 'tcg-storage.packet.secure_data && !tcg-storage.tok.uid'),
            ], two_pass=two_pass)


class TestTcgStorageLevel0Versions:
    """Level 0 descriptor versions defined outside Opal SSC 2.30: Locking
    Version 2 (Pyrite SSC 2.01 Table 5, Ruby SSC 1.00 Table 5), Supported Data
    Removal Mechanism Version 1 (Pyrite SSC 2.01 Tables 7/8, Key Per I/O SSC
    1.00 Tables 6/7), Opal SSC V2 Version 1 (Opal SSC 2.00/2.01 Table 7), the
    Namespace Geometry Reporting Length (CNL 1.00 Table 10), Block SID
    Authentication Version 2 (Block SID 1.01 Table 2), the Feature Set Minor
    Version Number (ADT 1.01 Table 3, Configurable Locking 1.30 Table 7), and
    feature codes that are only named."""

    FILE = 'nvme-mi-tcg.pcapng'
    INDEX = 15
    L0 = 'tcg-storage.l0.feat.'

    @pytest.fixture(scope='class')
    @classmethod
    def frames(cls, capture_file, generator):
        span, cases, _ = generated_section(
            generator, ('tcg_level0_versions_vectors', 1729000000), cls.INDEX,
            capture_file(cls.FILE))
        return {name: span[0] - 1 + response for name, (_, response) in cases.items()}

    def test_descriptor_fields(self, frames, assert_frames_match):
        lk, drm = self.L0 + 'locking.', self.L0 + 'data_removal.'
        op, bsid = self.L0 + 'opal2.', self.L0 + 'block_sid.'
        for two_pass in (False, True):
            assert_frames_match(self.FILE, [
                (frames['locking-v2'],
                 (f'{lk}mbr_shadowing_not_supported == 1 && {lk}locked == 1'
                  f' && {lk}enabled == 1 && {lk}supported == 1 && {lk}reserved_v2 == 0'
                  f' && !{lk}hw_reset && !{lk}reserved && len({self.L0}reserved_tail) == 11'
                  ' && !tcg-storage.l0.feat.data && !tcg-storage.l0.unsupported_version'
                  ' && !_ws.expert')),
                (frames['drm-v1'],
                 (f'{drm}processing == 1 && {drm}interrupted == 1'
                  f' && {drm}mechanism.overwrite == 1 && {drm}mechanism.block_erase == 1'
                  f' && {drm}mechanism.unmap == 1 && {drm}mechanism.reset_write_pointers == 1'
                  f' && {drm}mechanism.crypto_erase == 0 && {drm}mechanism.vendor == 0'
                  f' && {drm}format.unmap == 1 && {drm}format.reset_write_pointers == 0'
                  f' && {drm}time_overwrite == 10 && {drm}time_block_erase == 20'
                  f' && {drm}time_crypto_erase == 0 && {drm}time_unmap == 30'
                  f' && {drm}time_reset_write_pointers == 40 && {drm}time_vendor == 0'
                  f' && len({drm}reserved2) == 16 && !{drm}reserved1'
                  ' && !tcg-storage.l0.feat.data && !tcg-storage.l0.unsupported_version'
                  ' && !_ws.expert')),
                (frames['drm-v1-len16'],
                 (f'{self.L0}length == 16 && {drm}time_unmap == 30 && !{drm}reserved2'
                  ' && tcg-storage.l0.feat.invalid_length && count(_ws.expert) == 1')),
                (frames['drm-v0'],
                 (f'tcg-storage.l0.unsupported_version && len({self.L0}data) == 32'
                  f' && !{drm}mechanism && !{drm}flags && !_ws.expert')),
                (frames['opal2-v1'],
                 (f'{op}base_comid == 0x1000 && {op}num_comids == 1 && {op}num_admins == 4'
                  f' && {op}num_users == 8 && {op}initial_cpin_sid == 0'
                  f' && {op}revert_cpin_sid == 0 && {self.L0}reserved == 1'
                  f' && !{self.L0}ssc_minor && !tcg-storage.l0.unsupported_version'
                  ' && !_ws.expert')),
                (frames['opal2-v1-len12'],
                 (f'{self.L0}length == 12 && !{op}base_comid && len({self.L0}data) == 12'
                  ' && tcg-storage.l0.feat.invalid_length && count(_ws.expert) == 1')),
                (frames['ns-geometry-len12'],
                 (f'{self.L0}code == 0x0405 && !{self.L0}geometry.flags'
                  f' && len({self.L0}data) == 12'
                  ' && tcg-storage.l0.feat.invalid_length && count(_ws.expert) == 1')),
                (frames['block-sid-v2'],
                 (f'{bsid}flags == 0x0f && {bsid}freeze_lock_supported == 1'
                  f' && {bsid}freeze_lock_state == 1 && {bsid}sid_value_state == 1'
                  f' && {bsid}sid_blocked_state == 1 && {bsid}hw_reset == 1 && !_ws.expert')),
                (frames['block-sid-v1'],
                 (f'{bsid}flags == 0x0f && !{bsid}freeze_lock_supported'
                  f' && !{bsid}freeze_lock_state && {bsid}sid_value_state == 1'
                  f' && {bsid}sid_blocked_state == 1 && {bsid}hw_reset == 1 && !_ws.expert')),
                (frames['datastore-v2-minor1'],
                 (f'{self.L0}datastore.minor == 1 && !{self.L0}reserved'
                  f' && {self.L0}datastore.max_tables == 9 && !_ws.expert')),
                (frames['datastore-v1-minor1'],
                 (f'{self.L0}reserved == 1 && !{self.L0}datastore.minor'
                  f' && {self.L0}datastore.max_tables == 9 && !_ws.expert')),
                (frames['cnl-v2-minor1'],
                 (f'{self.L0}cnl.minor == 1 && !{self.L0}reserved'
                  f' && {self.L0}cnl.max_ranges_per_ns == 8 && !_ws.expert')),
                (frames['cnl-v1-minor1'],
                 (f'{self.L0}reserved == 1 && !{self.L0}cnl.minor'
                  f' && {self.L0}cnl.max_ranges_per_ns == 8 && !_ws.expert')),
                # Undefined versions are marked; the known fields stay decoded.
                (frames['ruby-v2'],
                 (f'tcg-storage.l0.unsupported_version && {op}num_users == 8'
                  ' && !_ws.expert')),
                (frames['block-sid-v3'],
                 (f'tcg-storage.l0.unsupported_version && {bsid}freeze_lock_state == 1'
                  ' && !_ws.expert')),
                (frames['ns-geometry-v2'],
                 (f'tcg-storage.l0.unsupported_version && {self.L0}geometry.lbs == 512'
                  ' && !_ws.expert')),
                # Defined versions are not.
                *[(frames[name], '!tcg-storage.l0.unsupported_version')
                  for name in ('opal2-v1', 'block-sid-v2', 'block-sid-v1',
                               'datastore-v2-minor1', 'cnl-v2-minor1')],
            ], two_pass=two_pass)

    def test_display_text(self, frames, dissect_pdml):
        pdml = dissect_pdml(self.FILE)
        drm = self.L0 + 'data_removal.'
        # Named-only codes keep a raw body, like an unknown code, and neither
        # is an error.
        assert pdml.shownames(frames['named-only'], 'tcg-storage.l0.feat') == [
            'Key Per I/O SSC v1.00 Feature', 'Locking LBA Ranges Control Feature',
            'Shadow MBR for Multiple Namespaces Feature', 'C_PIN Enhancements Feature',
            'Namespace Key Per I/O Capabilities Feature', 'Logical Port Locking Feature',
            'MEK Multiparty Authorization Feature', 'Epoch Key Purge Feature',
            'Unknown Feature']
        assert pdml.shownames(frames['named-only'], self.L0 + 'code')[:2] == [
            'Feature Code: Key Per I/O SSC v1.00 Feature (0x0305)',
            'Feature Code: Locking LBA Ranges Control Feature (0x0401)']
        assert pdml.shownames(frames['named-only'], self.L0 + 'data') == [
            'Feature Data: a5a5a5a5'] * 9
        assert pdml.experts(frames['named-only']) == []
        # Additional DataStore Tables 1.01 4.2.1 and Table 3; Configurable
        # Locking 1.30 Table 7.
        assert pdml.shownames(frames['datastore-v2-minor1'], self.L0 + 'code') == [
            'Feature Code: Additional DataStore Tables Feature (0x0202)']
        assert pdml.shownames(frames['datastore-v2-minor1'], self.L0 + 'datastore.minor') == [
            ('.... 0001 = Feature Set Minor Version Number:'
             ' Additional DataStore Tables Feature Set v1.01 (0x1)')]
        assert pdml.shownames(frames['cnl-v2-minor1'], self.L0 + 'cnl.minor') == [
            ('.... 0001 = Feature Set Minor Version Number:'
             ' Configurable Locking for NVMe Namespaces and SCSI LUNs v1.01 (0x1)')]
        assert pdml.shownames(frames['drm-v1'], drm + 'time_unmap') == [
            'Data Removal Time (Unmap): 30 (60 minutes)']
        assert pdml.shownames(frames['drm-v1'], drm + 'time_reset_write_pointers') == [
            'Data Removal Time (Reset Write Pointers): 40 (80 seconds)']
        assert pdml.experts(frames['drm-v1-len16']) == [
            'Data Removal Mechanism Version 1 feature data must be exactly 32 bytes'
            " (Pyrite SSC 2.01 / Key Per I/O SSC 'Level 0 Discovery - Supported Data"
            " Removal Mechanism Feature Descriptor'); Length is 16"]
        assert pdml.experts(frames['opal2-v1-len12']) == [
            'Opal SSC V2 Version 1 feature data must be exactly 16 bytes'
            " (Opal SSC 'Level 0 Discovery - Opal SSC V2 Feature Descriptor'); Length is 12"]
        assert pdml.experts(frames['ns-geometry-len12']) == [
            'Namespace Geometry Reporting Version 1 feature data must be exactly 28 bytes'
            " (Configurable Locking 'Namespace Geometry Reporting Feature Descriptor');"
            ' Length is 12']


class TestTcgStorageLevel0Coverage:
    """One descriptor per feature listed here, laid out from its defining
    table: Enterprise SSC 1.01 Table 07, Opal SSC 1.00 Table 6, Single User
    Mode 1.00 Table 7, ADT 1.01 Table 2, Opalite 1.00 / Pyrite 1.00 / Pyrite
    2.01 Table 6, Block SID 1.00 Table 1 / 1.01 Table 2 and Configurable
    Locking 1.30 Table 6; then a Supported Data Removal Mechanism Version 1
    declaring Length 0 (Pyrite SSC 2.01 Table 7: 0x20)."""

    FILE = 'nvme-mi-tcg.pcapng'
    INDEX = 16
    L0 = 'tcg-storage.l0.feat.'

    @pytest.fixture(scope='class')
    @classmethod
    def frames(cls, capture_file, generator):
        span, cases, _ = generated_section(
            generator, ('tcg_level0_coverage_vectors', 1732000000), cls.INDEX,
            capture_file(cls.FILE))
        return {name: span[0] - 1 + response for name, (_, response) in cases.items()}

    def test_decoded_fields(self, frames, assert_frames_match):
        f = self.L0
        clean = ' && !tcg-storage.l0.feat.data && !tcg-storage.l0.unsupported_version && !_ws.expert'
        lite = (f'{f}ssc.base_comid == 0x0800 && {f}ssc.num_comids == 1'
                f' && len({f}ssc.reserved) == 5 && {f}ssc.initial_cpin_sid == 0'
                f' && {f}ssc.revert_cpin_sid == 0 && !{f}opal2.num_admins')
        for two_pass in (False, True):
            assert_frames_match(self.FILE, [
                (frames['enterprise'],
                 (f'{f}code == 0x0100 && {f}enterprise.base_comid == 0x07fe'
                  f' && {f}enterprise.num_comids == 2 && {f}enterprise.range_crossing == 1'
                  f' && len({f}data) == 11 && !tcg-storage.l0.unsupported_version'
                  ' && !_ws.expert')),
                (frames['opal1'],
                 (f'{f}code == 0x0200 && {f}opal1.base_comid == 0x1000'
                  f' && {f}opal1.num_comids == 1 && {f}opal1.range_crossing == 1'
                  f' && len({f}data) == 11 && !_ws.expert')),
                (frames['sum'],
                 (f'{f}code == 0x0201 && {f}sum.num_objects == 9 && {f}sum.any == 1'
                  f' && {f}sum.all == 0 && {f}sum.policy == 1 && len({f}data) == 7'
                  ' && !_ws.expert')),
                (frames['datastore'],
                 (f'{f}code == 0x0202 && {f}datastore.minor == 1'
                  f' && {f}datastore.reserved == 0 && {f}datastore.max_tables == 9'
                  f' && {f}datastore.max_size == 10485760 && {f}datastore.alignment == 512'
                  + clean)),
                *[(frames[name], f'{f}code == {code} && {lite}' + clean)
                  for name, code in (('opalite', '0x0301'), ('pyrite1', '0x0302'),
                                     ('pyrite2', '0x0303'))],
                (frames['block-sid-v1'],
                 (f'{f}block_sid.sid_value_state == 1 && {f}block_sid.sid_blocked_state == 1'
                  f' && {f}block_sid.hw_reset == 1 && !{f}block_sid.freeze_lock_state'
                  f' && len({f}data) == 10 && !_ws.expert')),
                (frames['block-sid-v2'],
                 (f'{f}block_sid.sid_value_state == 1 && {f}block_sid.sid_blocked_state == 1'
                  f' && {f}block_sid.freeze_lock_supported == 1'
                  f' && {f}block_sid.freeze_lock_state == 1 && {f}block_sid.hw_reset == 0'
                  ' && !tcg-storage.l0.unsupported_version && !_ws.expert')),
                (frames['cnl'],
                 (f'{f}code == 0x0403 && {f}cnl.minor == 3 && {f}cnl.range_c == 1'
                  f' && {f}cnl.range_p == 1 && {f}cnl.sum_c == 1 && len({f}cnl.reserved) == 3'
                  f' && {f}cnl.max_key_count == 64 && {f}cnl.unused_key_count == 60'
                  f' && {f}cnl.max_ranges_per_ns == 8' + clean)),
                # One fault, one expert: the Length, not also a truncated body.
                (frames['drm-v1-len0'],
                 (f'{f}code == 0x0404 && {f}length == 0 && {f}invalid_length'
                  ' && count(_ws.expert) == 1 && !tcg-storage.truncated'
                  f' && !{f}data && !{f}data_removal.flags')),
            ], two_pass=two_pass)


class TestTcgFieldChecks:
    """TPer Reset with TL 0 (Opal SSC 2.30 3.2.3 Table 13; SIIS 1.20 Table
    25), reserved Subpacket Kinds and Credit Control Length (Core 2.01 Tables
    19 and 21), and IF-RECV on the TPER_RESET ComID; nvme-mi-tcg-field-checks.pcapng."""

    FILE = 'nvme-mi-tcg-field-checks.pcapng'
    TL0 = ('TPer Reset Transfer Length shall be non-zero (Opal SSC section 3.2.3'
           " 'TPER_RESET Command'); SIIS NVMe TPer Interface Status Codes: Invalid Field in Command")
    NO_RECV = ('No IF-RECV is defined for the TPER_RESET ComID 0x0004 (Opal SSC'
               ' 3.2.3); decoded as a ComID management response')

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_tper_reset_zero_tl(self, dissect_pdml, tshark_fields, two_pass):
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        info = tshark_fields(self.FILE, 'frame.number <= 6', ('_ws.col.info',),
                             two_pass=two_pass).splitlines()
        assert p.frames_with('nvme.security.tper_reset_zero_tl') == [1]
        assert p.experts(1) == [self.TL0]
        assert p.label(1, 'nvme.cmd.security_send.dword11.tl') == '0 (TPer Reset)'
        assert p[1].find(".//proto[@name='tcg-storage']") is None
        assert info[0].endswith('(Security Send) (TPer Reset)')
        # TL 4 reaches TCG once; SECP 01h is not a TPer Reset.
        assert p.experts(3) == []
        assert info[2].endswith('TCG Security Send (TPer Reset)')
        assert info[2].count('TPer Reset') == 1
        assert p.experts(5) == []
        assert 'TPer Reset' not in info[4]
        for frame in (2, 4, 6):
            assert p.experts(frame) == [], frame

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_subpacket_checks(self, dissect_pdml, two_pass):
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        credit = 'tcg-storage.subpacket.credit.invalid_length'
        kind = 'tcg-storage.subpacket.kind.reserved'
        assert p.frames_with(credit) == [7]
        assert p.experts(7) == [
            ('Credit Control Subpacket Length must be 4;'
            ' session state not tracked')]
        length = p.fields(7, 'tcg-storage.subpacket.length')[0]
        assert length.find(f".//field[@name='{credit}']") is not None
        assert p.experts(9) == []
        assert p.values(9, 'tcg-storage.subpacket.credit') == [0x100]
        assert p.frames_with(kind) == [11]
        assert p.experts(11) == [
            ('Reserved Subpacket Kind; only 0x0000 (Data) and 0x8001 (Credit'
            " Control) are defined (TCG Core 'Subpacket Types')")]
        assert p.label(11, 'tcg-storage.subpacket.kind') == 'Reserved (0x1234)'
        assert p.shownames(11, 'tcg-storage.subpacket')[0].endswith(
            '(Reserved, 2 bytes)')

    @pytest.mark.parametrize('two_pass', [False, True])
    def test_tper_reset_comid_recv(self, dissect_pdml, two_pass):
        p = dissect_pdml(self.FILE, two_pass=two_pass)
        mismatch = 'tcg-storage.comid_mgmt.comid_mismatch'
        assert p.frames_with('tcg-storage.tper_reset.if_recv') == [14, 16, 18]
        # The best-effort ComID management decode stays.
        assert p.values(14, 'tcg-storage.comid_mgmt.request_code') == [0]
        assert p.values(16, 'tcg-storage.comid_mgmt.stack_reset_result') == [0]
        # An all-zero Extended ComID with No Response Available is what Core
        # 3.3.4.7.5 mandates; ComID 0004h matches SPSP.
        assert p.experts(14) == [self.NO_RECV]
        assert p.experts(18) == [self.NO_RECV]
        assert p.frames_with(mismatch) == [16]
        assert p.experts(16) == [
            self.NO_RECV,
            'ComID 0x1000 differs from the Security Receive ComID (SPSP) 0x0004']
        assert p.experts(20) == []
        for frame in (13, 15, 17, 19):
            assert p.experts(frame) == [], frame
