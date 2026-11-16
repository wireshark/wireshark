#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Self-tests of the dissection suite helpers: a wrong expectation must fail.'''

import subprocess

import dissection_helpers as helpers
import pytest

CAPTURE = 'dhcp.pcap'   # Four DHCP frames.
SPAN = (101, 110)


class TestAssertFramesMatch:
    def test_every_case_of_a_frame_must_hold(self, assert_frames_match):
        with pytest.raises(AssertionError):
            assert_frames_match(CAPTURE, [(1, 'dhcp'), (1, '!dhcp')])

    def test_missing_frame_fails(self, assert_frames_match):
        with pytest.raises(AssertionError):
            assert_frames_match(CAPTURE, [(1, 'dhcp'), (5, 'frame')])

    def test_rejected_filter_fails(self, assert_frames_match):
        with pytest.raises(subprocess.CalledProcessError):
            assert_frames_match(CAPTURE, [(1, 'dhcp.no_such_field')])


class TestSectionNumbers:
    def test_link_comparisons_are_converted(self):
        dfilter = ('frame.number >= 5 && frame.number<7 && nvme-mi.response_to != 3'
                   ' && mctp.fragment in {2..4, 9} && frame.number == 0x0a')
        assert helpers.to_capture(SPAN, dfilter, helpers.FRAME_LINKS) == (
            'frame.number >= 105 && frame.number<107 && nvme-mi.response_to != 103'
            ' && mctp.fragment in {102..104, 109} && frame.number == 110')

    def test_every_comparison_token_is_converted(self):
        # epan/dfilter/scanner.l: all_eq and any_ne too, and 0X hex.
        dfilter = ('frame.number all_eq 3 && frame.number any_ne 4'
                   ' && frame.number === 5 && frame.number !== 0X06')
        assert helpers.to_capture(SPAN, dfilter, helpers.FRAME_LINKS) == (
            'frame.number all_eq 103 && frame.number any_ne 104'
            ' && frame.number === 105 && frame.number !== 106')

    def test_other_fields_are_left_alone(self):
        dfilter = 'mctp.fragment.count == 2 && count(mctp.fragment) == 2 && frame.len == 5'
        assert helpers.to_capture(SPAN, dfilter, helpers.FRAME_LINKS) == dfilter

    @pytest.mark.parametrize('frame', (0, 11))
    def test_frame_outside_the_section_fails(self, frame):
        with pytest.raises(AssertionError):
            helpers.at(SPAN, [(frame, 'frame')])


class TestPdml:
    def test_unregistered_name_fails(self, dissect_pdml):
        p = dissect_pdml(CAPTURE)
        for lookup in (p.fields, p.field, p.shows, p.values, p.shownames):
            with pytest.raises(KeyError):
                lookup(1, 'dhcp.no_such_field')
        with pytest.raises(KeyError):
            p.frames_with('dhcp.no_such_field')

    def test_unregistered_name_fails_without_packets(self, dissect_pdml):
        p = dissect_pdml(CAPTURE, dfilter='frame.number == 0')
        assert p.packets == {}
        assert p.frames_with('dhcp.type') == []
        with pytest.raises(KeyError):
            p.frames_with('dhcp.no_such_field')

    def test_registered_but_absent_field_is_empty(self, dissect_pdml):
        p = dissect_pdml(CAPTURE)
        assert p.fields(1, 'tcp.port') == []
        assert p.field(1, 'tcp.port') is None
        assert p.frames_with('tcp.port') == []
        assert p.values(1, 'dhcp.type') == [1]
