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


class TestGueLinuxPrivateFlags:
    '''The base draft assigns no standard or private flag bits, but the
    Linux kernel does (include/net/gue.h) and uses them whenever a fou/gue
    tunnel is configured with encap-remcsum, so real GUE traffic is not
    fully decoded without them.'''

    def test_gue_linux_remcsum_header_fields(self, cmd_tshark, capture_file, test_env):
        '''Checks the private flags and REMCSUM fields against traffic
        generated by the Linux kernel: an IPIP tunnel between two network
        namespaces, set up with "ip fou add port 6080 gue" and
        encap-remcsum.  Odd frames carry REMCSUM; even frames are the kernel's own ICMP
        replies, which are not CHECKSUM_PARTIAL and so carry no
        extension.'''

        stdout = subprocess.check_output((cmd_tshark,
                                '-r', capture_file('gue-remcsum.pcapng.gz'),
                                '-Y', 'gue',
                                '-T', 'fields',
                                '-e', 'frame.number',
                                '-e', 'gue.hlen',
                                '-e', 'gue.proto',
                                '-e', 'gue.flags',
                                '-e', 'gue.priv_flags',
                                '-e', 'gue.remcsum.start',
                                '-e', 'gue.remcsum.offset',
                                '-e', 'gue.surplus',
                                ),
                                encoding='utf-8', env=test_env)

        assert stdout == (
            '1\t2\t4\t0x0001\t0x80000000\t20\t26\t\n'
            '2\t0\t4\t0x0000\t\t\t\t\n'
            '3\t2\t4\t0x0001\t0x80000000\t20\t26\t\n'
            '4\t0\t4\t0x0000\t\t\t\t\n'
            '5\t2\t4\t0x0001\t0x80000000\t20\t26\t\n'
            '6\t0\t4\t0x0000\t\t\t\t\n'
        )

    def test_gue_linux_remcsum_inner_ip(self, cmd_tshark, capture_file, test_env):
        '''Checks that REMCSUM-carrying frames still peel down to the
        tunnelled inner IPv4 packet (proto IPIP=4), i.e. that decoding the
        private flags extension does not disturb the handoff to the
        payload dissector.'''

        stdout = subprocess.check_output((cmd_tshark,
                                '-r', capture_file('gue-remcsum.pcapng.gz'),
                                '-Y', 'gue.priv_flags.remcsum == 1',
                                '-T', 'fields',
                                '-e', 'frame.number',
                                '-e', 'ip.src',
                                '-e', 'ip.dst',
                                ),
                                encoding='utf-8', env=test_env)

        assert stdout == (
            '1\t198.51.100.1,10.0.0.1\t198.51.100.2,10.0.0.2\n'
            '3\t198.51.100.1,10.0.0.1\t198.51.100.2,10.0.0.2\n'
            '5\t198.51.100.1,10.0.0.1\t198.51.100.2,10.0.0.2\n'
        )

    def test_gue_linux_remcsum_icmp_replies(self, cmd_tshark, capture_file, test_env):
        '''Checks that the extension-less reply frames still decapsulate to
        the inner ICMP port-unreachable message.'''

        stdout = subprocess.check_output((cmd_tshark,
                                '-r', capture_file('gue-remcsum.pcapng.gz'),
                                '-Y', 'gue && icmp',
                                '-T', 'fields',
                                '-e', 'frame.number',
                                '-e', 'gue.proto',
                                '-e', 'icmp.type',
                                ),
                                encoding='utf-8', env=test_env)

        assert stdout == (
            '2\t4\t3\n'
            '4\t4\t3\n'
            '6\t4\t3\n'
        )

    def test_gue_other_flag_leaves_extension_undecoded(self, cmd_tshark,
                                                        cmd_text2pcap,
                                                        result_file, test_env):
        '''A flag other than PRIV makes the offset of every extension
        field after it indeterminate (section 3.3.1), so the whole Hlen
        area is left undecoded even though the private flags bit is set
        as well and the bytes look like a valid REMCSUM extension.  Frame
        1 sets the group identifier flag of
        draft-ietf-intarea-gue-extensions, which is not decoded; frame 2
        sets a flag no draft assigns.'''

        # variant=0, C=0, Hlen=2; proto=0xfd (unassigned); flags 0x8001
        # (group identifier plus PRIV) and 0x0003 (unassigned bit 14 plus
        # PRIV); 8 bytes of extension that deliberately look like a valid
        # private flags word (REMCSUM) followed by start/offset fields;
        # 5 bytes of payload.
        msgs = [
            bytes([0x02, 0xfd, 0x80, 0x01]),
            bytes([0x02, 0xfd, 0x00, 0x03]),
        ]
        extension_and_payload = bytes([
            0x80, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x1a,
            0x48, 0x45, 0x4c, 0x4c, 0x4f,
        ])

        pcap_path = result_file('pcap')
        txt_path = result_file('txt')
        with open(txt_path, 'w') as f:
            for header in msgs:
                msg = header + extension_and_payload
                for i in range(0, len(msg), 16):
                    chunk = msg[i:i + 16]
                    f.write('{:06x}  {}\n'.format(i, ' '.join(f'{b:02x}' for b in chunk)))
        subprocess.check_call(
            (cmd_text2pcap, '-u', '6080,6080', txt_path, pcap_path),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        stdout = subprocess.check_output((cmd_tshark,
                                '-r', pcap_path,
                                '-Y', '_ws.expert',
                                '-T', 'fields',
                                '-e', 'frame.number',
                                '-e', '_ws.expert.message',
                                ),
                                encoding='utf-8', env=test_env)
        assert stdout == (
            '1\tGUE extension flag not decoded; extension fields left undecoded\n'
            '2\tUnassigned GUE flag set; extension fields left undecoded\n'
        )

        # The empty columns are the private-flags and REMCSUM fields the
        # extension bytes were built to resemble.
        stdout = subprocess.check_output((cmd_tshark,
                                '-r', pcap_path,
                                '-T', 'fields',
                                '-e', 'gue.ext_data',
                                '-e', 'gue.priv_flags',
                                '-e', 'gue.remcsum.start',
                                '-e', 'gue.remcsum.offset',
                                '-e', 'gue.surplus',
                                ),
                                encoding='utf-8', env=test_env)
        assert stdout == (
            '800000000014001a\t\t\t\t\n'
            '800000000014001a\t\t\t\t\n'
        )
