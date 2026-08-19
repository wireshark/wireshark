#
# Wireshark tests
#
# Copyright 2026 by Takeru Hayasaka <hayatake396@gmail.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Generic UDP Encapsulation (GUE) tests'''

import subprocess
import xml.etree.ElementTree as ET


class TestGue:

    def test_gue_header_fields(self, cmd_tshark, capture_file, test_env):
        '''Checks the GUE header fields of data, extension, control and
        variant 1 packets.'''

        stdout = subprocess.check_output((cmd_tshark,
                                '-r', capture_file('gue.pcapng.gz'),
                                '-Y', 'gue',
                                '-T', 'fields',
                                '-e', 'frame.number',
                                '-e', 'gue.variant',
                                '-e', 'gue.c',
                                '-e', 'gue.hlen',
                                '-e', 'gue.proto',
                                '-e', 'gue.ctype',
                                '-e', 'gue.flags',
                                '-e', 'gue.ext_data',
                                '-e', 'gue.exid',
                                ),
                                encoding='utf-8', env=test_env)

        assert stdout == (
            '1\t0\tFalse\t0\t4\t\t0x0000\t\t\n'
            '2\t0\tFalse\t1\t4\t\t0x8000\tdeadbeef\t\n'
            '3\t0\tTrue\t0\t\t0\t0x0000\t\t\n'
            '4\t1\t\t\t\t\t\t\t\n'
            '5\t0\tFalse\t0\t41\t\t0x0000\t\t\n'
            '6\t0\tTrue\t0\t\t255\t0x0000\t\t0x12345678\n'
            '7\t0\tTrue\t0\t\t255\t0x0000\t\t0x12345678\n'
            '8\t0\tTrue\t0\t\t255\t0x0000\t\t\n'
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
                                '-Y', 'gue.variant == 1',
                                '-T', 'fields',
                                '-e', 'frame.number',
                                '-e', 'ip.src',
                                ),
                                encoding='utf-8', env=test_env)

        assert stdout == '4\t10.0.0.1,192.0.2.1\n'

    def test_gue_variant1_item_length(self, cmd_tshark, capture_file, test_env):
        '''Checks that the GUE protocol item for a variant 1 packet covers
        the one byte it shares with the encapsulated IP header's version
        field, instead of being reported as zero-length while its
        gue.variant child field claims that byte for itself.'''

        stdout = subprocess.check_output((cmd_tshark,
                                '-r', capture_file('gue.pcapng.gz'),
                                '-T', 'pdml',
                                '-J', 'gue',
                                '-Y', 'gue.variant == 1',
                                ),
                                encoding='utf-8', env=test_env)

        tree = ET.fromstring(stdout)
        gue_proto = tree.find(".//proto[@name='gue']")
        variant_field = gue_proto.find("field[@name='gue.variant']")

        proto_pos = int(gue_proto.get('pos'))
        proto_size = int(gue_proto.get('size'))
        field_pos = int(variant_field.get('pos'))
        field_size = int(variant_field.get('size'))

        assert proto_size == 1
        assert field_pos >= proto_pos
        assert field_pos + field_size <= proto_pos + proto_size

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

        assert stdout == (
            '3\tControl message (type 0)\n'
            '6\tControl message (type 255)\n'
            '7\tControl message (type 255)\n'
            '8\tControl message (type 255)\n'
        )

    def test_gue_exid(self, cmd_tshark, capture_file, test_env):
        '''Checks the ExID of experimental (type 255) control messages.
        draft-ietf-intarea-gue-09 section 3.2.2 places the ExID in the
        control message payload rather than the GUE header, so it is
        not counted by Hlen, and a message may consist of nothing but
        the ExID.'''

        stdout = subprocess.check_output((cmd_tshark,
                                '-r', capture_file('gue.pcapng.gz'),
                                '-Y', 'gue.ctype == 255',
                                '-T', 'fields',
                                '-e', 'frame.number',
                                '-e', 'gue.exid',
                                '-e', 'data.data',
                                ),
                                encoding='utf-8', env=test_env)

        assert stdout == (
            '6\t0x12345678\taabb\n'
            '7\t0x12345678\t\n'
            '8\t\taabb\n'
        )

        stdout = subprocess.check_output((cmd_tshark,
                                '-r', capture_file('gue.pcapng.gz'),
                                '-Y', 'gue.exid.missing',
                                '-T', 'fields',
                                '-e', 'frame.number',
                                '-e', '_ws.expert.message',
                                ),
                                encoding='utf-8', env=test_env)

        assert stdout == (
            '8\tExperimental control message payload is too short to hold an ExID\n'
        )
