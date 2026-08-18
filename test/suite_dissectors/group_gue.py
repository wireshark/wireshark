#
# Wireshark tests
#
# Copyright 2026 by Takeru Hayasaka <hayatake396@gmail.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Generic UDP Encapsulation (GUE) tests'''

import subprocess


class TestGue:

    def test_gue_header_fields(self, cmd_tshark, capture_file, test_env):
        '''Checks the GUE header fields of data, extension, control and
        variant 1 packets.'''

        stdout = subprocess.check_output((cmd_tshark,
                                '-r', capture_file('gue.pcapng.gz'),
                                '-Y', 'gue',
                                '-T', 'fields',
                                '-e', 'frame.number',
                                '-e', 'gue.version',
                                '-e', 'gue.c',
                                '-e', 'gue.hlen',
                                '-e', 'gue.proto',
                                '-e', 'gue.ctype',
                                '-e', 'gue.flags',
                                '-e', 'gue.ext_data',
                                ),
                                encoding='utf-8', env=test_env)

        assert stdout == (
            '1\t0\tFalse\t0\t4\t\t0x0000\t\n'
            '2\t0\tFalse\t1\t4\t\t0x8000\tdeadbeef\n'
            '3\t0\tTrue\t0\t\t0\t0x0000\t\n'
            '4\t1\t\t\t\t\t\t\n'
            '5\t0\tFalse\t0\t41\t\t0x0000\t\n'
        )

    def test_gue_encapsulated_icmp(self, cmd_tshark, capture_file, test_env):
        '''Checks that the payload of GUE data messages is handed off to
        the dissector for the carried IP protocol.'''

        stdout = subprocess.check_output((cmd_tshark,
                                '-r', capture_file('gue.pcapng.gz'),
                                '-Y', 'gue && icmp',
                                '-T', 'fields',
                                '-e', 'frame.number',
                                '-e', 'gue.proto',
                                '-e', 'icmp.type',
                                ),
                                encoding='utf-8', env=test_env)

        assert stdout == (
            '1\t4\t8\n'
            '2\t4\t0\n'
            '4\t\t8\n'
        )

    def test_gue_variant1_direct_ip(self, cmd_tshark, capture_file, test_env):
        '''Checks that a variant 1 packet is dissected as a directly
        encapsulated IPv4 packet.'''

        stdout = subprocess.check_output((cmd_tshark,
                                '-r', capture_file('gue.pcapng.gz'),
                                '-Y', 'gue.version == 1',
                                '-T', 'fields',
                                '-e', 'frame.number',
                                '-e', 'ip.src',
                                ),
                                encoding='utf-8', env=test_env)

        assert stdout == '4\t10.0.0.1,192.0.2.1\n'

    def test_gue_control_message(self, cmd_tshark, capture_file, test_env):
        '''Checks the Info column of a GUE control message.'''

        stdout = subprocess.check_output((cmd_tshark,
                                '-r', capture_file('gue.pcapng.gz'),
                                '-Y', 'gue.c == 1',
                                '-T', 'fields',
                                '-e', 'frame.number',
                                '-e', '_ws.col.info',
                                ),
                                encoding='utf-8', env=test_env)

        assert stdout == '3\tControl message (type 0)\n'
