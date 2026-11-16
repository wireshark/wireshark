#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
"""MCTP transport (packet-mctp.c) tests: message assembly (DSP0236 8.6-8.9),
packet size rules (8.4.2, 11.6) and header-only continuation packets.

Captures: mctp-transport.pcapng, mctp-ingress-scope.pcapng and
mctp-version-state.pcapng
(tools/gen-mctp-test-capture.py).  mctp-transport.pcapng is eight pcapng
sections whose generator maps number their frames from 1; the classes that
read a section use those numbers, and frame_in() converts them for tshark.

assert_frames_match ORs its cases, so each frame appears once per call with
its conditions AND'd together.
"""

import runpy
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import ClassVar

import pytest
from dissection_helpers import at, column, frame_in, frames_in, section

CAPTURE = 'mctp-transport.pcapng'
CAPTURES = (CAPTURE, 'mctp-ingress-scope.pcapng')
# The sections of mctp-transport.pcapng, as (first, last) frame numbers.
REASSEMBLY = (1, 33)
SIZE = (34, 81)
EMPTY = (82, 87)
LIMITS = (88, 95)
MALFORMED = (96, 103)
SLL2 = (104, 107)
ASSEMBLY_LIMIT = (108, 137)
VDM = (138, 145)


@pytest.mark.parametrize('capture', CAPTURES)
def test_no_dissector_exceptions(tshark_fields, capture):
    assert tshark_fields(capture, '_ws.malformed.expert || _ws.dissector_bug').strip() == ''


@pytest.mark.parametrize('capture', CAPTURES)
def test_second_pass_matches_first(assert_pass_parity, capture):
    assert_pass_parity(capture)


class TestMctpReassembly:
    """Message assembly against DSP0236 8.6-8.9, with Null EID termini told apart by address."""

    EXPERTS = ('mctp.assembly.orphan', 'mctp.assembly.restarted', 'mctp.assembly.seq_gap',
               'mctp.tu.mismatch')
    FIELDS = EXPERTS + ('_ws.expert', 'frame.protocols', 'mctp.msg.type',
                        'mctp.reassembled.length', 'data.data', 'data.len', '_ws.col.info')

    def test_ordinary_message_reassembles(self, tshark_fields, assert_frames_match):
        assert tshark_fields(CAPTURE, f'{frames_in(REASSEMBLY)} && mctp').split() == [
            str(n) for n in range(1, 34)]
        assert_frames_match(CAPTURE, [
            (1, 'mctp.flags.som == 1 && mctp.flags.eom == 0'),
            (2, ('mctp.reassembled.length == 7'
                 ' && mctp.reassembled.data == 04:11:22:33:44:55:66'
                 ' && mctp.msg.type == 0x04 && nvme-mi')),
        ])

    def test_orphan_packets_are_dropped(self, assert_frames_match):
        """8.7: a continuation packet with no assembly in progress is dropped
        and starts nothing; its header is still shown, with the reason."""
        assert_frames_match(CAPTURE, [
            (3, ('mctp.flags.som == 0 && mctp.flags.eom == 1'
                 ' && mctp.assembly.orphan && mctp.tag == 0x0a && mctp.src == 65'
                 ' && !mctp.msg.type && !mctp.reassembled.length'
                 ' && !nvme-mi && !nvme-mi.admin.prohibited_opcode')),
            (4, ('mctp.flags.som == 0 && mctp.flags.eom == 0'
                 ' && mctp.assembly.orphan && mctp.tag == 0x0b && mctp.src == 66'
                 ' && !mctp.msg.type && !nvme-mi')),
            (11, '!mctp.reassembled.length && !mctp.msg.type && !nvme-mi'),
        ])

    def test_new_start_terminates_the_assembly(self, assert_frames_match):
        """8.9: a start packet on a terminus with an assembly in progress drops
        that assembly and begins a new one, even as a single-packet message."""
        assert_frames_match(CAPTURE, [
            (5, 'mctp.flags.som == 1 && !mctp.assembly.restarted'),
            (6, 'mctp.flags.som == 1 && mctp.assembly.restarted'),
            (7, ('mctp.reassembled.length == 5 && mctp.reassembled.data == 04:22:22:33:33'
                 ' && !nvme-mi.admin.prohibited_opcode')),
            (8, 'mctp.flags.som == 1 && !mctp.assembly.restarted'),
            (9, ('mctp.flags.som == 1 && mctp.flags.eom == 1 && mctp.assembly.restarted'
                 ' && mctpc.command == 0x02 && mctpc.rq == 1')),
            (10, '!mctp.reassembled.length && !mctp.msg.type && !nvme-mi'),
        ])

    def test_sequence_numbers(self, assert_frames_match):
        """8.9: a non-start packet whose sequence number is not a modulo-4
        increment drops the assembly; the 3 -> 0 wrap is in sequence."""
        assert_frames_match(CAPTURE, [
            (12, 'mctp.flags.som == 1 && mctp.seq == 0 && !mctp.assembly.seq_gap'),
            (13, ('mctp.seq == 3 && mctp.assembly.seq_gap'
                  ' && !mctp.reassembled.length && !mctp.msg.type'
                  ' && !nvme-mi && !nvme-mi.admin.prohibited_opcode')),
            (15, ('mctp.flags.som == 0 && mctp.flags.eom == 0'
                  ' && mctp.assembly.seq_gap')),
            (16, ('mctp.assembly.orphan && !mctp.assembly.seq_gap'
                  ' && !mctp.reassembled.length && !mctp.msg.type')),
            (17, 'mctp.seq == 3 && !mctp.assembly.seq_gap'),
            (18, 'mctp.seq == 0 && !mctp.assembly.seq_gap'),
            (19, ('mctp.seq == 1 && !mctp.assembly.seq_gap'
                  ' && mctp.reassembled.length == 7'
                  ' && mctp.reassembled.data == 0a:77:77:88:88:99:99'
                  ' && mctp.msg.type == 0x0a')),
            (20, 'mctp.seq == 2 && !mctp.assembly.seq_gap'),
            (21, ('mctp.seq == 2 && mctp.assembly.seq_gap'
                  ' && !mctp.reassembled.length && !mctp.msg.type && !nvme-mi')),
        ])

    def test_null_eid_termini(self, assert_frames_match):
        """Endpoints without an EID are told apart by physical address (8.3 Table 2)."""
        assert_frames_match(CAPTURE, [
            (22, 'mctp.flags.som == 1 && !mctp.assembly.restarted'),
            (23, 'mctp.flags.som == 1 && !mctp.assembly.restarted'),
            (24, ('mctp.smbus.src_addr == 0x40 && mctp.src == 0 && mctp.dst == 0'
                  ' && mctp.tag == 0x0d && mctp.reassembled.length == 5'
                  ' && mctp.reassembled.data == 0a:aa:aa:a1:a1')),
            (25, ('mctp.smbus.src_addr == 0x41 && mctp.src == 0 && mctp.dst == 0'
                  ' && mctp.tag == 0x0d && mctp.reassembled.length == 5'
                  ' && mctp.reassembled.data == 0a:bb:bb:b1:b1'
                  ' && mctp.flags.eom == 1 && !mctp.assembly.orphan')),
            (28, ('mctp.smbus.dst_addr == 0x40 && mctp.src == 8 && mctp.dst == 0'
                  ' && mctp.tag == 0x0c && mctp.reassembled.data == 0a:c0:c0:c1:c1')),
            (29, ('mctp.smbus.dst_addr == 0x41 && mctp.src == 8 && mctp.dst == 0'
                  ' && mctp.tag == 0x0c && mctp.reassembled.data == 0a:d0:d0:d1:d1')),
            (30, '!mctp.smbus && mctp.src == 0 && !mctp.assembly.restarted'),
            (31, '!mctp.smbus && mctp.src == 72 && !mctp.assembly.restarted'),
            (32, ('mctp.src == 0 && mctp.reassembled.length == 5'
                  ' && mctp.reassembled.data == 0a:e0:e0:e1:e1')),
            (33, ('mctp.src == 72 && mctp.reassembled.length == 5'
                  ' && mctp.reassembled.data == 0a:f0:f0:f1:f1')),
        ])

    def test_expert_census(self, fields_table):
        """Exact frame sets, so an expert that over-fires is caught.  F2 and
        F7 reach NVMe-MI, which may flag them; no other frame has an expert."""
        t = section(fields_table(CAPTURE, self.FIELDS), REASSEMBLY)
        expected = {
            'mctp.assembly.orphan': [3, 4, 10, 11, 16],
            'mctp.assembly.restarted': [6, 9],
            'mctp.assembly.seq_gap': [13, 15, 21],
            'mctp.tu.mismatch': [1, 4, 5, 6, 8, 12, 14, 15, 17, 18, 20, 22, 23,
                                 26, 27, 30, 31],
        }
        for field, frames in expected.items():
            assert list(column(t, field)) == frames, field
        assert {n for n, row in t.items()
                if row['_ws.expert'] and not any(row[f] for f in self.EXPERTS)} <= {2, 7}

    def test_payload_dispatch(self, fields_table):
        """Bytes after the type byte of a complete message nobody claims (0Ah)
        go to the data dissector; a claimed message (F2) is not rendered
        twice; a dropped packet's bytes are shown as data and nothing more."""
        t = section(fields_table(CAPTURE, self.FIELDS), REASSEMBLY)
        assert (t[19]['mctp.msg.type'], t[19]['data.data'], t[19]['data.len']) == (
            '0x0a', '777788889999', '6')
        complete = [n for n, row in t.items()
                    if row['mctp.reassembled.length'] and row['mctp.msg.type'] == '0x0a']
        assert complete
        assert [n for n, row in t.items()
                if row['data.data'] and row['mctp.msg.type'] == '0x0a'] == complete
        assert ',' not in t[2]['data.data']
        dropped = {n: row['data.data'] for n, row in t.items()
                   if row['mctp.assembly.orphan'] or row['mctp.assembly.seq_gap']}
        assert dropped == {3: '041111042222', 4: '04aabb', 10: '8888', 11: 'ccdd',
                           13: '2222', 15: '5555', 16: '6666', 21: 'bbbb'}
        for n in dropped:
            assert t[n]['frame.protocols'] == 'sll:mctp:data', n
            assert not t[n]['mctp.msg.type'] and not t[n]['mctp.reassembled.length'], n

    def test_info_column(self, fields_table):
        """A non-final packet's Info names the wire Pkt Seq #, not a fragment
        index (a start packet's sequence number can be any value)."""
        t = section(fields_table(CAPTURE, self.FIELDS), REASSEMBLY)
        assert [t[n]['_ws.col.info'] for n in (17, 18, 20, 22)] == [
            'MCTP message fragment, seq 3', 'MCTP message fragment, seq 0',
            'MCTP message fragment, seq 2', '[0x40->0x20] MCTP message fragment, seq 0']

    def test_message_type_label(self, cmd_tshark, capture_file, test_env):
        """The type subtree header and the field below it agree (DSP0239
        Table 1 reserves 0Ah); the assigned NVMe-MI name is unchanged."""
        out = subprocess.check_output(
            [cmd_tshark, '-r', capture_file(CAPTURE), '-V'],
            encoding='utf-8', env=test_env)
        assert 'Type: Reserved (0x0a)' in out
        assert 'Message type: Reserved (0x0a)' in out
        assert 'Type: unknown (0xa)' not in out
        assert 'Type: NVMe-MI (0x04)' in out


SIZE_EXPERT_FRAMES = {
    'mctp.tu.mismatch': {7, 8, 11, 24, 27, 35},
    'mctp.assembly.orphan': {31, 33, 48},
    'mctp.assembly.restarted': {43},
    # A control message must not carry IC (DSP0236 11.1).
    'mctpc.ic_set': {6},
    # A control message fits in one 64-byte packet (DSP0236 11.6).
    'mctp.control.fragmented': {3, 5, 21, 23, 34, 38, 42, 47},
    'mctpc.oversized': {2, 4, 6, 22, 25, 35, 40, 46},
}
# F27 breaks both the minimum and the same-size rule.
SIZE_EXPERT_TWICE = {(27, 'mctp.tu.mismatch')}
SIZE_CONTROL_FRAMES = {1, 2, 4, 6, 20, 22, 25, 35, 40, 46}


def size_frame_set(frames):
    """A display filter selecting SIZE frames (by their section numbers)."""
    return 'frame.number in {' + ','.join(str(frame_in(SIZE, f)) for f in sorted(frames)) + '}'


def size_frames(stdout):
    """SIZE section numbers of the frame numbers tshark printed."""
    return {int(n) - SIZE[0] + 1 for n in stdout.split()}


class TestMctpSizeRules:
    """Packet and message sizes against DSP0236 8.4.2."""

    def test_exact_expert_census_and_multiplicity(self, tshark_fields):
        """One diagnostic per violated rule, including overlaps."""
        names = tuple(SIZE_EXPERT_FRAMES)
        rows = tshark_fields(
            CAPTURE, frames_in(SIZE), fields=('frame.number', *names), separator='|').splitlines()
        assert len(rows) == 48
        for frame, row in enumerate(rows, 1):
            assert row.split('|') == [str(frame_in(SIZE, frame))] + [
                ('1,1' if (frame, name) in SIZE_EXPERT_TWICE else '1')
                if frame in SIZE_EXPERT_FRAMES[name] else '' for name in names]
        assert size_frames(tshark_fields(
            CAPTURE, f'{frames_in(SIZE)} && _ws.expert')) == \
            set().union(*SIZE_EXPERT_FRAMES.values())
        assert not tshark_fields(CAPTURE, f'{frames_in(SIZE)} && _ws.malformed')

    def test_control_messages_of_every_size_decode(
            self, assert_frames_match, tshark_fields):
        assert_frames_match(CAPTURE, at(SIZE, [
            (1, 'frame.len == 84 && mctpc && !_ws.expert'),
            (2, 'frame.len == 90 && mctpc && mctpc.oversized && !mctp.control.fragmented'),
            (3, 'mctp.msg.type == 0 && !mctpc && mctp.control.fragmented && !mctpc.oversized'),
            (4, ('mctp.reassembled.length == 70 && mctpc && mctpc.oversized'
                ' && !mctp.control.fragmented')),
            (5, 'mctp.msg.ic == 1 && !mctpc && mctp.control.fragmented'),
            (6, 'mctp.msg.ic == 1 && mctpc'),
            (20, 'mctpc.command == 2 && !_ws.expert'),
            (21, 'mctp.control.fragmented && !mctpc'),
            (22, 'mctpc && mctpc.oversized && !mctp.control.fragmented'),
            (24, 'mctp.tu.mismatch && !mctp.msg.type'),
            (35, 'mctp.reassembled.length == 134'),
        ]))
        assert size_frames(tshark_fields(CAPTURE, f'{frames_in(SIZE)} && mctpc')) == \
            SIZE_CONTROL_FRAMES

    def test_size_warnings_do_not_suppress_or_change_reassembly(
            self, tshark_fields):
        def opaque(size):
            return bytes([0x0a]) + bytes(range(1, size))

        def control(size, ic=False):
            return bytes([0x80 if ic else 0, 0x80, 0xff]) + bytes(size - 3)

        expected = {
            4: control(70), 6: control(70, ic=True), 9: opaque(10),
            12: opaque(148), 15: opaque(132), 18: opaque(164),
            22: control(84), 25: control(138), 28: opaque(72),
            35: control(134), 37: b'\x0a' + bytes(79) + b'\x80' + bytes(69),
            40: control(70), 41: opaque(80) + bytes(70), 45: opaque(164),
        }
        rows = tshark_fields(
            CAPTURE, f'{frames_in(SIZE)} && mctp.reassembled.length',
            fields=('frame.number', 'mctp.reassembled.length',
                    'mctp.reassembled.data'), separator='|').splitlines()
        assert rows == [
            f'{frame_in(SIZE, frame)}|{len(payload)}|{payload.hex(" ")}'
            for frame, payload in expected.items()]
        # The raw fallback gets every byte after the message type.
        assert tshark_fields(
            CAPTURE, f'frame.number == {frame_in(SIZE, 9)}',
            fields=('data.data', 'data.len'), separator='|').strip() == \
            '010203040506070809|9'

    def test_conformant_non_control_and_smaller_final_units_are_clean(
            self, tshark_fields):
        frames = {10, 12, 13, 14, 15, 16, 17, 18, 19, 26, 28,
                  29, 30, 36, 37, 39, 41, 44, 45}
        assert not tshark_fields(CAPTURE, f'({size_frame_set(frames)}) && _ws.expert')
        # In particular, continuation bytes 00h/80h are not type/IC bytes.
        assert tshark_fields(
            CAPTURE, f'frame.number == {frame_in(SIZE, 37)}',
            fields=('mctp.msg.type', 'mctp.msg.ic'), separator='|').strip() == \
            '0x0a|False'

    def test_uncaptured_fragments_drop_the_assembly(
            self, assert_frames_match):
        """A fragment cut by the capture drops the assembly; reported sizes still decide 8.4.2."""
        assert_frames_match(CAPTURE, at(SIZE, [
            (30, 'frame.cap_len < frame.len && !mctp.tu.mismatch && _ws.short'),
            (31, 'mctp.assembly.orphan && !mctp.reassembled.length && !mctp.msg.type'),
            (32, '!mctp.msg.type && _ws.short'),
            (33, ('mctp.assembly.orphan && !mctp.tu.mismatch && !mctp.msg.type'
                  ' && !mctpc')),
            (46, 'frame.cap_len == 84 && frame.len == 90 && mctpc'),
            (47, 'mctp.msg.type == 0 && !mctp.tu.mismatch && _ws.short'),
            (48, 'mctp.assembly.orphan && !mctp.tu.mismatch && !mctpc && !mctp.reassembled.length'),
        ]))

    def test_ingress_scope_and_restart_do_not_leak_start_metadata(
            self, assert_frames_match):
        def fragments(*frames):
            return ' && '.join(f'mctp.fragment == {frame_in(SIZE, n)}' for n in frames)

        assert_frames_match(CAPTURE, at(SIZE, [
            (38, 'frame.interface_id == 0 && mctp.msg.type == 0'),
            (39, ('frame.interface_id == 1 && mctp.msg.type == 0x0a'
                 ' && !_ws.expert')),
            (40, f'mctpc && mctp.reassembled.length == 70 && {fragments(38, 40)}'),
            (41, ('mctp.msg.type == 0x0a && mctp.reassembled.length == 150'
                 f' && {fragments(39, 41)} && !_ws.expert')),
            (43, 'mctp.assembly.restarted && mctp.msg.type == 0x0a'),
            (44, '!mctp.tu.mismatch'),
            (45, ('mctp.reassembled.length == 164 && mctp.fragment.count == 3'
                 f' && {fragments(43, 44, 45)} && !_ws.expert')),
        ]))

    def test_expert_rendering_and_precise_byte_anchors(
            self, cmd_tshark, capture_file, test_env):
        args = [cmd_tshark, '-n', '-r', capture_file(CAPTURE), '-Y', frames_in(SIZE)]
        verbose = subprocess.check_output(
            [*args, '-V'], text=True, env=test_env)
        assert 'Middle packet payload is 80 bytes, differing from the ' \
               "start packet's 64 bytes (DSP0236 8.4.2)" in verbose
        assert 'Final packet payload is 70 bytes, exceeding the ' \
               "start packet's 64 bytes (DSP0236 8.4.2)" in verbose
        root = ET.fromstring(subprocess.check_output(
            [*args, '-Tpdml'], text=True, env=test_env))
        packets = section({int(p.find('.//field[@name="frame.number"]').get('show')): p
                           for p in root}, SIZE)
        # Expert fields are generated. Their containing items, two levels up,
        # select the captured packet-payload bytes.
        for frame, count, offset, length in [
                (8, 1, 20, 4), (11, 1, 20, 80), (27, 2, 20, 4),
                (35, 1, 20, 70)]:
            packet = packets[frame]
            parents = {child: parent for parent in packet.iter()
                       for child in parent}
            experts = packet.findall('.//field[@name="mctp.tu.mismatch"]')
            assert len(experts) == count
            for expert in experts:
                anchor = parents[parents[expert]]
                assert (int(anchor.get('pos')), int(anchor.get('size'))) == \
                    (offset, length)
        for frame in (1, 3, 4, 5, 6, 47):
            fields = packets[frame].findall('.//field[@name="mctp.msg.type"]')
            assert len(fields) == 1
            assert (int(fields[0].get('pos')), int(fields[0].get('size'))) == \
                (0 if frame in (4, 6) else 20, 1)

    def test_arbitrary_selected_frame_redissection(self, sharkd_revisits):
        """Out-of-order selections after the first pass, then repeats."""
        selected = [48, 24, 8, 40, 11, 41, 5, 6, 43, 44, 47, 32, 33,
                    31, 2, 3, 4, 27, 30, 25, 45]
        order = selected + selected[::-1]
        trees = sharkd_revisits(CAPTURE, [frame_in(SIZE, n) for n in order],
                                keys=('fn', 'f', 'l'))
        prior = {}
        for frame, nodes in zip(order, trees):
            names = [n[0] for n in nodes]
            for name, frames in SIZE_EXPERT_FRAMES.items():
                assert names.count(name) == (
                    (frame in frames) + ((frame, name) in SIZE_EXPERT_TWICE)), (frame, name)
            assert ('mctpc' in names) == (frame in SIZE_CONTROL_FRAMES)
            snapshot = sorted(n for n in nodes if n[0].startswith(('mctp', 'data')))
            if frame in prior:
                assert snapshot == prior[frame]
            prior[frame] = snapshot


class TestMctpHeaderOnlyContinuation:
    """DSP0236 Table 1 carries the message type byte in a message's first
    packet only, so a continuation packet may be the transport header alone;
    a start packet still needs the type byte.  The EMPTY section's F1-F6."""

    def test_header_only_packets(self, fields_table, assert_frames_match):
        t = section(fields_table(CAPTURE, ('mctp.too_short', '_ws.col.info')), EMPTY)
        assert list(column(t, 'mctp.too_short')) == [3]
        assert t[3]['_ws.col.info'] == 'Bogus length 4, minimum 5'
        assert_frames_match(CAPTURE, at(EMPTY, [
            (2, ('mctp && !mctp.too_short && mctp.reassembled.length == 64'
                 ' && mctp.msg.type == 0x0a')),
            (4, 'mctp.assembly.orphan && !mctp.too_short'),
            (6, 'nvme-mi.mi.opcode == 6 && mctp.reassembled.length == 64'),
        ]))


class TestMctpTransportLimits:
    """A sliced fragment drops its assembly; messages at DSP0235 7.6's 4,224-byte limit."""

    FILE = CAPTURE
    FIELDS = ('mctp', 'nvme-mi', 'frame.len', 'frame.cap_len',
              'mctp.assembly.orphan', 'mctp.reassembled.length')

    def test_capture_incomplete_assemblies(self, fields_table, assert_frames_match):
        t = section(fields_table(self.FILE, self.FIELDS), LIMITS)
        assert list(column(t, 'mctp.assembly.orphan')) == [4]
        assert list(column(t, 'mctp.reassembled.length')) == [2]
        assert [n for n, row in t.items()
                if row['mctp'] and int(row['frame.cap_len']) < int(row['frame.len'])] == [3, 8]
        assert not t[4]['nvme-mi'] and not t[8]['nvme-mi']
        assert (t[5]['frame.len'], t[6]['frame.len']) == ('4244', '4245')
        assert_frames_match(self.FILE, at(LIMITS, [
            (2, 'mctp.reassembled.length == 20 && nvme-mi.mi.opcode == 0x01'),
            (3, '_ws.short && !mctp.reassembled.in'),
            (4, 'mctp.assembly.orphan && !mctp.reassembled.length'),
            (5, 'nvme-mi.mi.opcode == 0x01 && mctp.tag.value == 5'),
            (6, 'nvme-mi.mi.opcode == 0x01 && mctp.tag.value == 6'),
            (8, '_ws.short && !mctp.reassembled.length && !nvme-mi'),
        ]))


class TestMctpIngressScope:
    """The assembly key carries the ingress scope (DSP0236 3)."""

    FILE = 'mctp-ingress-scope.pcapng'
    FIELDS = ('frame.interface_id', 'i2c.bus', 'mctp', 'mctp.reassembled.length')

    def test_scope_separates_assemblies(self, fields_table, assert_frames_match):
        t = fields_table(self.FILE, self.FIELDS)
        assert [row['frame.interface_id'] for row in t.values()] == [
            '0', '1', '1', '0', '2', '3', '2', '3', '0', '0', '1', '0']
        assert list(column(t, 'i2c.bus').values()) == ['0', '4', '4', '0', '0', '0', '4', '0']
        assert {n: row['frame.interface_id'] for n, row in t.items()
                if row['mctp'] and int(row['frame.interface_id']) >= 2} == {
            5: '2', 6: '3', 7: '2', 8: '3'}
        assert {n: (row['mctp.reassembled.length'], row['frame.interface_id'])
                for n, row in t.items() if row['mctp.reassembled.length']} == {
            7: ('20', '2'), 8: ('20', '3')}
        assert_frames_match(self.FILE, [
            (7, 'mctp.fragment == 5 && mctp.fragment == 7 && mctp.fragment.count == 2'),
            (8, 'mctp.fragment == 6 && mctp.fragment == 8 && mctp.fragment.count == 2'),
        ])


class TestMctpSll2Parity:
    """SLL v1 and SLL v2 twins decode the same above the link layer."""

    FILE = CAPTURE
    #: Compared between twins: everything but sll.* (the difference under
    #: test) and frame.*; pos is dropped because a v2 header is 4 bytes longer.
    PREFIXES = ('mctp.', 'nvme-mi.', 'data.', '_ws.expert')

    @staticmethod
    def layer_fields(pdml, frame, prefixes):
        return [tuple(f.get(k, '') for k in ('name', 'showname', 'size', 'value', 'show',
                                             'unmaskedvalue'))
                for f in pdml[frame].iter('field') if (f.get('name') or '').startswith(prefixes)]

    def test_upper_layers_match_their_twins(self, dissect_pdml, fields_table):
        t = section(fields_table(self.FILE, ('nvme-mi', 'frame.interface_id', 'sll.pkttype',
                                             'nvme-mi.req_superseded', 'nvme-mi.response_to')),
                    SLL2)
        assert list(column(t, 'nvme-mi')) == [1, 2, 3, 4]
        assert [row['frame.interface_id'] for row in t.values()] == ['0', '1', '0', '1']
        assert [row['sll.pkttype'] for row in t.values()] == ['0', '0', '4', '4']
        assert column(t, 'nvme-mi.req_superseded') == column(t, 'nvme-mi.response_to') == {}
        pdml = dissect_pdml(self.FILE)
        for a, b, minimum in ((1, 2, 20), (3, 4, 10)):
            v1 = self.layer_fields(pdml, frame_in(SLL2, a), self.PREFIXES)
            v2 = self.layer_fields(pdml, frame_in(SLL2, b), self.PREFIXES)
            assert len(v1) > minimum, f'only {len(v1)} fields collected'
            assert v1 == v2, ([x for x in v1 if x not in v2], [x for x in v2 if x not in v1])
        assert any(f[0] == 'nvme-mi.reserved_type' for f in self.layer_fields(
            pdml, frame_in(SLL2, 3), self.PREFIXES))



class TestMctpHeaderMalformed:
    """Dropped packets (DSP0236 8.7) render their header, one reason and their bytes."""

    FILE = CAPTURE
    FIELDS = ('mctp.version.unsupported', 'mctp.too_short', '_ws.expert', '_ws.short',
              'data', 'data.data', 'mctp.msg.type', 'mctp.msg.ic', 'mctp.rsvd',
              'mctp.version', 'frame.protocols',
              'frame.cap_len', 'frame.len', '_ws.col.info')

    def test_dropped_packets_render_their_header(self, assert_frames_match):
        assert_frames_match(self.FILE, at(MALFORMED, [
            (1, ('mctp && mctp.version == 2 && mctp.version != 1'
                 ' && mctp.dst == 0x30 && mctp.src == 0x0a && mctp.flags.som == 1'
                 ' && mctp.flags.eom == 1 && mctp.tag.to == 1 && mctp.tag.value == 0')),
            (2, ('mctp && mctp.version == 1 && mctp.rsvd == 0 && mctp.dst == 0x30'
                 ' && mctp.src == 0x0a && mctp.tag.to == 1')),
            (6, 'mctp && mctp.version == 1'),
            (7, ('mctp.too_short && !mctp.version && !mctp.rsvd && !mctp.dst && !mctp.src'
                 ' && !mctp.flags')),
            (8, ('mctp && _ws.short && !mctp.too_short && !mctp.version.unsupported'
                 ' && !_ws.malformed && !_ws.expert && !data && !mctp.version'
                 ' && !mctp.rsvd && !mctp.dst && !mctp.src && !mctp.flags && !mctp.seq'
                 ' && !mctp.tag')),
        ]))

    def test_reasons_and_payloads(self, fields_table):
        t = section(fields_table(self.FILE, self.FIELDS), MALFORMED)
        assert list(column(t, 'mctp.version.unsupported')) == [1]
        assert list(column(t, 'mctp.too_short')) == [2, 7]
        assert list(column(t, '_ws.expert')) == [1, 2, 7]
        assert list(column(t, '_ws.short')) == [8]
        # A bad header version says nothing about byte 4, so it is all data.
        assert (t[1]['data.data'], t[1]['mctp.msg.type']) == ('0ab1b2b3', '')
        # Only a start packet needs the type byte, so with no flags byte the
        # provable minimum is the header.
        assert t[7]['_ws.col.info'] == 'Bogus length 0, minimum 4'
        assert (t[3]['mctp.msg.type'], t[3]['frame.protocols']) == ('0x0a', 'sll:mctp')
        # DSP0236 5.3: the reserved nibble is shown and ignored.
        assert (t[4]['mctp.rsvd'], t[4]['mctp.version']) == ('0x0f', '1')
        assert [(t[n]['frame.cap_len'], t[n]['frame.len'], t[n]['mctp.too_short'],
                 t[n]['_ws.col.info']) for n in (7, 8)] == [
            ('16', '16', '1', 'Bogus length 0, minimum 4'),
            ('16', '24', '', '[Packet size limited during capture]')]
        assert t[8]['frame.protocols'] == 'sll:mctp'
        # An unclaimed complete message (type 0Ah) hands its payload to data,
        # IC set or not; an empty payload adds no layer.
        assert (t[6]['mctp.msg.type'], t[6]['data.data'], t[6]['frame.protocols']) == (
            '0x0a', 'b1b2b3', 'sll:mctp:data')
        assert (t[5]['mctp.msg.ic'], t[5]['mctp.msg.type'], t[5]['data.data']) == (
            'True', '0x0a', 'b1b2b3')
        assert list(column(t, 'data')) == [1, 4, 5, 6]


class TestMctpAssemblyPacketLimit:
    """The ASSEMBLY_LIMIT section (assembly_limit_section): the packet that
    would take an assembly past mctp.max_assembly_packets ends it."""

    FILE = CAPTURE
    CAP: ClassVar = {'mctp.max_assembly_packets': 8}
    FIELDS = ('mctp.assembly.packet_limit', 'mctp.assembly.orphan', '_ws.expert',
              '_ws.expert.message', 'mctp.reassembled.length', 'mctp.fragment.count',
              'data.len', 'frame.protocols', '_ws.col.info')

    def test_cap_ends_the_assembly_at_the_packet_past_it(self, fields_table):
        t = section(fields_table(self.FILE, self.FIELDS, prefs=self.CAP), ASSEMBLY_LIMIT)
        assert list(column(t, 'mctp.assembly.packet_limit')) == [17, 30]
        assert list(column(t, 'mctp.assembly.orphan')) == [18, 19]
        assert list(column(t, '_ws.expert')) == [17, 18, 19, 30]
        assert column(t, 'mctp.reassembled.length') == {8: '512', 21: '128'}
        assert column(t, 'mctp.fragment.count') == {8: '8', 21: '2'}
        for n in (17, 30):
            assert (t[n]['frame.protocols'], t[n]['data.len']) == ('sll:mctp:data', '64'), n
            assert t[n]['_ws.col.info'].endswith(' dropped, assembly packet limit reached'), n
            assert 'past 8 packets' in t[n]['_ws.expert.message'], n

    def test_second_pass_replays_the_cap(self, fields_table):
        one = section(fields_table(self.FILE, self.FIELDS, prefs=self.CAP), ASSEMBLY_LIMIT)
        assert one == section(fields_table(self.FILE, self.FIELDS, prefs=self.CAP,
                                           two_pass=True), ASSEMBLY_LIMIT)

    def test_default_does_not_cap_these_messages(self, fields_table):
        t = section(fields_table(self.FILE, self.FIELDS), ASSEMBLY_LIMIT)
        assert column(t, 'mctp.reassembled.length') == {
            8: '512', 19: '704', 21: '128', 30: '576'}
        assert not column(t, '_ws.expert')

    def test_zero_is_a_cap_of_one_not_unbounded(self, fields_table):
        # An unbounded assembly makes each packet walk an ever-longer
        # fragment list, so 0 counts as 1: the second packet of each message
        # hits the limit and the rest of that message are dropped as orphans.
        for cap in (0, 1):
            t = section(fields_table(self.FILE, self.FIELDS,
                                     prefs={'mctp.max_assembly_packets': cap}),
                        ASSEMBLY_LIMIT)
            assert list(column(t, 'mctp.assembly.packet_limit')) == [2, 10, 21, 23], cap
            assert not column(t, 'mctp.reassembled.length'), cap
            assert 'past 1 packets' in t[2]['_ws.expert.message'], cap


class TestMctpVendorDefined:
    """DSP0236 13.1 Table 40 (Vendor Defined - PCI, 7Eh) and 13.2 Table 41
    (Vendor Defined - IANA, 7Fh): the vendor ID, MSB first, then a body the
    vendor defines (vdm_section holds the map)."""

    FIELDS = ('mctp.vdm', 'mctp.vdm.pci_vid', 'mctp.vdm.iana', 'data.data',
              'mctp.vdm.too_short', '_ws.expert', '_ws.col.protocol', '_ws.col.info')

    def test_vendor_ids_and_bodies(self, fields_table):
        t = section(fields_table(CAPTURE, self.FIELDS), VDM)
        assert {n: (r['mctp.vdm.pci_vid'], r['mctp.vdm.iana'], r['data.data'])
                for n, r in t.items()} == {
            1: ('0x8086', '', '010203'),
            2: ('', '343', 'aabb'),
            3: ('0x1ab4', '', ''),
            4: ('', '', '80'),
            5: ('', '', '000001'),
            6: ('', '', ''),
            # IC set: the MIC is the vendor's, so it stays in the body.
            7: ('0x8086', '', '01deadbeef'),
            8: ('', '0', ''),
        }
        assert all(r['_ws.col.protocol'] == 'MCTP VDM' for r in t.values())
        assert [t[n]['_ws.col.info'] for n in (1, 2, 4)] == [
            'Vendor Defined - PCI, Vendor ID 0x8086',
            'Vendor Defined - IANA, Enterprise 343',
            'Vendor Defined - PCI']

    def test_short_vendor_id(self, fields_table):
        """Only a message too short for its vendor ID is flagged."""
        t = section(fields_table(CAPTURE, self.FIELDS), VDM)
        assert list(column(t, '_ws.expert')) == [4, 5, 6]
        assert list(column(t, 'mctp.vdm.too_short')) == [4, 5, 6]

    def test_layout(self, dissect_pdml):
        """The ID follows the type byte at offset 20 (SLL 16 + MCTP 4)."""
        pdml = dissect_pdml(CAPTURE)
        for n, name, size in ((1, 'mctp.vdm.pci_vid', 2), (2, 'mctp.vdm.iana', 4)):
            node = pdml.packets[frame_in(VDM, n)].find(f".//field[@name='{name}']")
            assert (int(node.get('pos')), int(node.get('size'))) == (21, size)
        assert pdml.shownames(frame_in(VDM, 2), 'mctp.vdm.iana') == [
            'IANA Enterprise ID: Intel Corporation (343)']

    def test_vendor_tables(self, cmd_tshark, test_env):
        """Vendor dissectors register on the vendor ID, as on mctp.type."""
        tables = subprocess.check_output([cmd_tshark, '-G', 'dissector-tables'],
                                         encoding='utf-8', env=test_env)
        names = {line.split('\t')[0] for line in tables.splitlines()}
        assert {'mctp.vdm.pci', 'mctp.vdm.iana'} <= names


class TestCrossLayerCaptures:
    """An unsupported version starts or ends no assembly."""

    VERSION = 'mctp-version-state.pcapng'

    def test_fixture_bytes(self, capture_file):
        generator = runpy.run_path(str(Path(__file__).resolve().parents[1]
                                       / 'tools/gen-mctp-test-capture.py'))
        fixtures = generator['cross_layer_fixtures']()
        assert set(fixtures) == {self.VERSION}
        for filename, expected in fixtures.items():
            assert Path(capture_file(filename)).read_bytes() == expected, filename

    def test_version_dropped_before_assembly(self, assert_frames_match, tshark_fields):
        for two_pass in (False, True):
            assert_frames_match(self.VERSION, [
                (2, 'mctp.version.unsupported && !mctp.assembly.restarted'),
                (3, ('mctp.reassembled.length == 72 && mctp.fragment == 1'
                     ' && mctp.fragment == 3 && mctp.fragment.count == 2')),
                (5, 'mctp.version.unsupported'),
                (6, 'mctp.assembly.orphan && !mctp.reassembled.length'),
            ], two_pass=two_pass)
