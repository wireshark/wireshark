#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Linux cooked capture (SLL) dissector tests (packet-sll.c).'''

import struct
import subprocess

import pytest

DLT_LINUX_SLL2 = 276


def sll2_pcap(path, packet_type):
    '''One SLL2 frame whose Link-layer address length byte is not zero.'''
    # Protocol type, reserved, interface index, ARPHRD_ETHER, packet type,
    # address length, 8 address bytes, then 4 bytes of payload.
    header = struct.pack('>HHIHBB', 0x1234, 0, 1, 1, packet_type, 6) + bytes(8)
    frame = header + b'\xde\xad\xbe\xef'
    with open(path, 'wb') as pcap:
        pcap.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, DLT_LINUX_SLL2))
        pcap.write(struct.pack('<IIII', 0, 0, len(frame), len(frame)) + frame)


class TestSll2PacketType:
    # The SLL2 packet type is one byte at offset 10; the next byte is the
    # address length.  Reading both as a 16-bit packet type made every frame
    # with a non-zero address length look like an unknown packet type.
    @pytest.mark.parametrize('packet_type, info', (
        (0, 'Unicast to us'), (1, 'Broadcast'), (2, 'Multicast'),
        (3, 'Unicast to another host'), (4, 'Sent by us')))
    def test_packet_type(self, packet_type, info, cmd_tshark, test_env, tmp_path):
        pcap = tmp_path / 'sll2.pcap'
        sll2_pcap(pcap, packet_type)
        out = subprocess.check_output(
            [cmd_tshark, '-r', str(pcap), '-Tfields', '-e', 'sll.pkttype', '-e', 'sll.halen',
             '-e', '_ws.col.info'], encoding='utf-8', env=test_env)
        assert out.rstrip('\n').split('\t') == [str(packet_type), '6', info]
