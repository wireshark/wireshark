#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

'''SMPTE ST 2038 tests'''

import subprocess


def _tshark_fields(cmd_tshark, capture, display_filter, fields, env):
    return subprocess.check_output((
        cmd_tshark,
        '-r', capture,
        '-Y', display_filter,
        '-T', 'fields',
        '-E', 'occurrence=a',
        '-E', 'aggregator=|',
        *(arg for field in fields for arg in ('-e', field)),
    ), encoding='utf-8', env=env)


class TestSt2038:

    def test_st2038_registration_and_decode(self, cmd_tshark, capture_file,
                                            test_env):
        capture = capture_file('st2038.pcap.gz')

        # The PMT registration descriptor is what selects the ST 2038
        # dissector for private-data PES packets. Verify that signaling before
        # checking the fields produced by the automatic handoff.
        stdout = _tshark_fields(
            cmd_tshark, capture,
            'mpeg_descr.registration.format_identifier == 0x56414e43',
            (
                'frame.number', 'mpeg_pmt.stream.type',
                'mpeg_pmt.stream.elementary_pid',
                'mpeg_descr.registration.format_identifier',
            ),
            test_env,
        )
        assert stdout == '2\t0x06\t0x0101\t0x56414e43\n'

        fields = (
            'frame.number', 'st2038.anc_count', 'st2038.reserved',
            'st2038.c_not_y', 'st2038.line_number',
            'st2038.horizontal_offset', 'st291.did', 'st291.sdid',
            'st291.dbn', 'st2038.data_count', 'st2038.udw',
            'st2038.udw_array', 'st2038.checksum',
            'st2038.checksum_calculated', 'st2038.alignment_bits',
            'st2038.stuffing_bytes',
        )
        stdout = _tshark_fields(
            cmd_tshark, capture, 'st2038', fields, test_env)

        # Cover multiple ANC records, Type 1 and Type 2 headers, both C/Y
        # channel values, packed UDW data, alignment bits, and trailing
        # stuffing. The second PES packet is malformed but remains decodable.
        assert stdout == (
            '3\t2\t0x00|0x00\tFalse|True\t9|9\t0|345\t0x50|0x80\t0x01\t0x34\t'
            '0x0101|0x0200\t16ad\t16ad|<MISSING>\t0x01fd|0x02b4\t'
            '0x01fd|0x02b4\t0x0000000000000003\tffff\n'
            '4\t2\t0x01|0x00\tFalse|True\t9|10\t0|20\t0x50|0x80\t0x01\t0x34\t'
            '0x0101|0x0200\t16ad\t16ad|<MISSING>\t0x01fc|0x02b4\t'
            '0x01fd|0x02b4\t0x00000000000000ff|0x0000000000000000\t\n'
        )

    def test_st2038_malformed(self, cmd_tshark, capture_file, test_env):
        fields = (
            'frame.number', 'st2038.reserved.nonzero',
            'st2038.st291_parity_bad', 'st2038.checksum.bad',
            'st2038.alignment.bad', 'st2038.inter_record_stuffing',
            'st2038.multiple_lines', 'st2038.truncated',
            '_ws.expert.message',
        )
        stdout = _tshark_fields(
            cmd_tshark, capture_file('st2038.pcap.gz'),
            'st2038', fields, test_env)

        # The first PES packet is conforming. The second covers each
        # recoverable expert diagnostic while proving both records are still
        # decoded (the ANC count is checked above).
        assert stdout == (
            '3\t\t\t\t\t\t\t\t\n'
            '4\t1\t1\t1\t1\t1\t1\t\t'
            'Reserved six-bit field is 0x1, expected 0|'
            'Invalid ST 291 DID parity/inverse bits (raw word 0x050); decoding bits 7..0|'
            'ST 291 checksum does not match|'
            'Non-standard inter-record stuffing bits accepted for interoperability|'
            'ST 2038 requires one raster line per PES packet; first ANC packet used line 9|'
            'ST 2038 alignment bits must be one\n'
        )
