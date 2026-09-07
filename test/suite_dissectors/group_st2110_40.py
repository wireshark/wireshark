#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

'''SMPTE ST 2110-40 tests'''

import subprocess

class TestSt2110_40:

    def test_st2110_40_decode_as(self, cmd_tshark, capture_file, test_env):
        stdout = subprocess.check_output((
            cmd_tshark,
            '-r', capture_file('st2110-40.pcap.gz'),

            # The capture contains RTP on UDP port 5000,
            # but has no signaling identifying it as RTP.
            '-d', 'udp.port==5000,rtp',
            '-d', 'udp.port==5010,rtp',
            '-d', 'udp.port==1234,rtp',
            '-d', 'udp.port==20000,rtp',

            # RTP payload type 100 is dynamic.  The capture has no SDP
            # identifying PT 100 as ST 2110-40, so explicitly decode it.
            '-d', 'rtp.pt==100,st2110_40',

            '-Y', 'st2110_40',

            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'rtp.p_type',
            '-e', 'st291.did',
            '-e', 'st291.sdid',
            '-e', 'st12_2.timecode',
        ),
        encoding='utf-8',
        env=test_env)

        assert stdout == (
            '1\t100\t\t\t\n'
            '2\t100\t0x60\t0x60\t16:16:10;12\n'
            '3\t100\t0x41\t0x05\t\n'
            '4\t100\t0x61\t0x01\t\n'
            '5\t100\t0x60,0x61,0x60\t0x60,0x01,0x60\t01:04:33;23,01:04:33;23\n'
            '6\t100\t0x61\t0x01\t\n'
            '7\t100\t0x60,0x53,0x60,0x43\t0x60,0x02,0x60,0x02\t00:00:50:19,00:00:50:19\n'
        )
