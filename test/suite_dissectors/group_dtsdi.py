#
# Wireshark tests
#
# Copyright (c) 2026, Devin Heitmueller <dheitmueller@ltnglobal.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

'''DekTec DTSDI tests'''

import subprocess


CAPTURE = 'dtsdi-vanc-op47.dtsdi.gz'
ST352_CAPTURE = 'dtsdi-v2-16bit-st352.dtsdi.gz'


class TestDtsdi:

    def test_dtsdi_ancillary_data(self, cmd_tshark, capture_file, test_env):
        '''Checks DTSDI metadata, ANC discovery, and OP-47 handoff.'''
        stdout = subprocess.check_output((
            cmd_tshark,
            '-r', capture_file(CAPTURE),
            '-T', 'fields',
            '-E', 'occurrence=a',
            '-E', 'aggregator=|',
            '-e', 'frame.number',
            '-e', 'dektec_sdi.format_version',
            '-e', 'dektec_sdi.data_type',
            '-e', 'dektec_sdi.storage',
            '-e', 'dektec_sdi.active_video_present',
            '-e', 'dektec_sdi.vanc.packet_count',
            '-e', 'dektec_sdi.hanc.packet_count',
            '-e', 'dektec_sdi.hanc.audio_packet_count',
            '-e', 'st291.did',
            '-e', 'st291.sdid',
            '-e', 'op47.sdp.identifier',
            '-e', '_ws.expert.message',
        ), encoding='utf-8', env=test_env)

        assert stdout == (
            '1\t2\t0x10\t10\tTrue\t1\t2\t7688\t'
            '0x41|0x43|0x41\t0x01|0x02|0x01\t0x5115\t\n'
        )

    def test_dtsdi_hanc_audio_default(self, cmd_tshark, capture_file,
                                      test_env):
        '''Checks that HANC audio is summarized but not expanded by default.'''
        stdout = subprocess.check_output((
            cmd_tshark,
            '-r', capture_file(CAPTURE),
            '-T', 'fields',
            '-e', '_ws.col.info',
            '-e', 'dektec_sdi.hanc.audio_span',
            '-e', 'dektec_sdi.anc.packet',
        ), encoding='utf-8', env=test_env)

        assert stdout == (
            '1080i50, VANC: 1 packet, HANC: 2 non-audio packets, '
            'Audio: present (7688 packets)\t1\t1,1,1\n'
        )

    def test_dtsdi_16bit_st352(self, cmd_tshark, capture_file, test_env):
        '''Checks 16-bit storage, inferred metadata, and HANC ST 352.'''
        stdout = subprocess.check_output((
            cmd_tshark,
            '-r', capture_file(ST352_CAPTURE),
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'dektec_sdi.format_version',
            '-e', 'dektec_sdi.data_type',
            '-e', 'dektec_sdi.storage',
            '-e', 'dektec_sdi.active_video_present',
            '-e', 'dektec_sdi.vanc.packet_count',
            '-e', 'dektec_sdi.hanc.packet_count',
            '-e', 'dektec_sdi.hanc.audio_packet_count',
            '-e', 'dektec_sdi.anc.line',
            '-e', 'dektec_sdi.anc.stream',
            '-e', 'st291.did',
            '-e', 'st291.sdid',
            '-e', '_ws.expert.message',
            '-e', '_ws.col.info',
        ), encoding='utf-8', env=test_env)

        assert stdout == (
            '1\t2\t0x09\t16\tTrue\t0\t1\t3208\t10\tY\t0x41\t0x01\t\t'
            '720p59.94, VANC: 0 packets, HANC: 1 non-audio packet, '
            'Audio: present (3208 packets)\n'
        )
