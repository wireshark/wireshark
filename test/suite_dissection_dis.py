#
# Wireshark tests - DIS dissection tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''DIS (Distributed Interactive Simulation) dissection tests'''

import subprocess

DIS_DECODE_AS_ARGS = ('-d', 'udp.port==6993,dis')


class TestDissectDis:
    '''Tests for DIS dissection and stream analysis tap.'''

    def test_dis_protocol_present(self, cmd_tshark, capture_file, test_env):
        '''Verify the sample capture is dissected as DIS.'''
        stdout = subprocess.check_output((cmd_tshark,) + DIS_DECODE_AS_ARGS + (
                '-r', capture_file('dis_voice_sample.pcap'),
                '-Tfields',
                '-eframe.protocols',
            ), encoding='utf-8', env=test_env)
        lines = [line for line in stdout.strip().split('\n') if line]
        assert lines
        assert any(':dis' in line or line.endswith('dis') for line in lines)

    def test_dis_streams_stat_output(self, cmd_tshark, capture_file, test_env):
        '''Verify the DIS streams tap reports the expected stream summary.'''
        stdout = subprocess.check_output((cmd_tshark,) + DIS_DECODE_AS_ARGS + (
                '-r', capture_file('dis_voice_sample.pcap'),
                '-q',
                '-z', 'dis,streams',
            ), encoding='utf-8', env=test_env)
        assert 'DIS Streams' in stdout
        assert '172.17.34.253' in stdout
        assert '255.255.255.255' in stdout
        assert '0x0002' in stdout

    def test_dis_packet_count(self, cmd_tshark, capture_file, test_env):
        '''Verify packet parsing does not crash on the DIS capture.'''
        proc = subprocess.run((cmd_tshark,) + DIS_DECODE_AS_ARGS + (
                '-r', capture_file('dis_voice_sample.pcap'),
                '-q',
            ), capture_output=True, text=True, env=test_env, check=False)
        assert proc.returncode == 0, f"tshark failed: {proc.stderr}"
