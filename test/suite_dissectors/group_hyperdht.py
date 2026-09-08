#
# Wireshark tests
#
# Copyright 2026 by Vijaygopal Balasa <balasavijaygopal@gmail.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''HyperDHT tests'''

import subprocess


class TestHyperdht:
    def test_hyperdht_command_sequence(self, cmd_tshark, capture_file, test_env):
        '''Every command of both namespaces decodes, in capture order.

        Replies carry no command on the wire, so the name shown against one
        comes from the request its transaction id was matched to.
        '''
        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Tfields', '-e_ws.col.info',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            'Req PING', 'Reply PING',
            'Req PING_NAT', 'Reply PING_NAT',
            'Req FIND_NODE', 'Reply FIND_NODE',
            'Req DOWN_HINT', 'Reply DOWN_HINT',
            'Req DELAYED_PING', 'Reply DELAYED_PING',
            'Req PEER_HANDSHAKE Mode=FROM_CLIENT',
            'Reply PEER_HANDSHAKE Mode=REPLY',
            'Req PEER_HOLEPUNCH Mode=FROM_RELAY',
            'Req PEER_HOLEPUNCH Mode=FROM_SERVER',
            'Req FIND_PEER', 'Reply FIND_PEER',
            'Req LOOKUP', 'Reply LOOKUP',
            'Req ANNOUNCE', 'Reply ANNOUNCE',
            'Req UNANNOUNCE', 'Reply UNANNOUNCE',
            'Req MUTABLE_PUT', 'Reply MUTABLE_PUT',
            'Req MUTABLE_GET', 'Reply MUTABLE_GET',
            'Req IMMUTABLE_PUT', 'Reply IMMUTABLE_PUT',
            'Req IMMUTABLE_GET', 'Reply IMMUTABLE_GET',
            'Req UNKNOWN (9)', 'Reply UNKNOWN (9) Error=UNKNOWN_COMMAND',
            'Req UNKNOWN (42)', 'Reply UNKNOWN (42) Error=UNKNOWN_COMMAND',
            'Req PING', 'Reply PING Error=UNKNOWN (99)',
            'Req PING', 'Reply PING',
            'Reply (Request not seen) Error=INVALID_TOKEN',
            'Req PLUGIN', 'Reply PLUGIN', 'Req PLUGIN',
            'Req PEER_HOLEPUNCH Mode=FROM_CLIENT',
            'Reply PEER_HOLEPUNCH Mode=REPLY',
            'Req PEER_HANDSHAKE Mode=FROM_RELAY',
            'Req PEER_HANDSHAKE Mode=FROM_SERVER',
            'Req PEER_HANDSHAKE Mode=FROM_SECOND_RELAY',
            'Req PEER_HOLEPUNCH Mode=FROM_RELAY',
            'Req PEER_HANDSHAKE Mode=FROM_SERVER',
            'Req PEER_HANDSHAKE[Packet size limited during capture]',
            'Reply PEER_HANDSHAKE Mode=REPLY',
            'Req LOOKUP',
            'Req PEER_HANDSHAKE Mode=FROM_SERVER',
            'Reply LOOKUP',
            'Req PEER_HOLEPUNCH Mode=FROM_RELAY',
            'Req LOOKUP',
            'Reply LOOKUP',
            'Req FIND_NODE', 'Reply FIND_NODE',
        ]

    def test_hyperdht_command_namespaces(self, cmd_tshark, capture_file, test_env):
        '''Internal commands and HyperDHT commands are separate number spaces.

        Both use small integers, so PING (internal 0) and PEER_HANDSHAKE
        (external 0) are only told apart by the internal flag. Both fields
        share the one filter name hyperdht.command, and a name resolves
        against its own namespace, so filtering by "PING" does not pick up
        PEER_HANDSHAKE frames.
        '''
        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Y', 'hyperdht.flag.internal == 1 && hyperdht.command',
                '-Tfields', '-ehyperdht.command',
            ), encoding='utf-8', env=test_env)
        assert stdout.split() == ['0', '1', '2', '3', '4', '9', '0', '0', '2']

        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Y', 'hyperdht.flag.internal == 0 && hyperdht.command',
                '-Tfields', '-ehyperdht.command',
            ), encoding='utf-8', env=test_env)
        assert stdout.split() == ['0', '1', '1', '2', '3', '4', '5', '6',
                                  '7', '8', '9', '42', '10', '10', '1',
                                  '0', '0', '0', '1', '0', '0', '3', '0',
                                  '1', '3']

        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Y', 'hyperdht.command == "PING"',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert stdout.split() == ['1', '35', '37']

        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Y', 'hyperdht.response == 1 && hyperdht.command',
                '-Tfields', '-eframe.number',
            ), encoding='utf-8', env=test_env)
        assert stdout == ''

    def test_hyperdht_ping_nat(self, cmd_tshark, capture_file, test_env):
        '''The PING_NAT reply arrives on a different five-tuple and still links.

        The request names the port the reply is to be sent to, so the reply
        comes back from a socket the request never spoke to.
        '''
        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Y', 'frame.number == 3 || frame.number == 4',
                '-Tfields', '-eframe.number', '-ehyperdht.transaction_id',
                '-ehyperdht.ping_nat.port', '-ehyperdht.response_in',
                '-ehyperdht.request_in', '-eudp.srcport', '-eudp.dstport',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '3\t2\t49802\t4\t\t49761\t49737',
            '4\t2\t\t\t3\t49737\t49802',
        ]

        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Y', 'frame.number == 4',
                '-Tfields', '-ehyperdht.response_time',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '0.001000000'

    def test_hyperdht_errors(self, cmd_tshark, capture_file, test_env):
        '''Error codes decode to the names dht-rpc gives them.'''
        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Y', 'hyperdht.error',
                '-Tfields', '-eframe.number', '-ehyperdht.error',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == ['32\t1', '34\t1', '36\t99', '39\t2']

        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Y', 'frame.number in {32, 39}',
                '-V',
            ), encoding='utf-8', env=test_env)
        assert 'Error: UNKNOWN_COMMAND (1)' in stdout
        assert 'Error: INVALID_TOKEN (2)' in stdout

    def test_hyperdht_plugin(self, cmd_tshark, capture_file, test_env):
        '''A plugin request names the plugin; its value is optional.

        Frame 42 is the same plugin with the value flag clear, which is what
        separates an absent value from an empty one.
        '''
        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Y', 'frame.number in {40, 41, 42}',
                '-Tfields', '-eframe.number', '-ehyperdht.plugin.name',
                '-ehyperdht.plugin.version', '-ehyperdht.plugin.command',
                '-ehyperdht.plugin.flag.value', '-ehyperdht.plugin.value',
                '-ehyperdht.plugin.response.value', '-ehyperdht.request_in',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '40\tblind-relay\t1\t2\tTrue\tc0ffee01\t\t',
            '41\t\t\t\t\t\ta0a1a2\t40',
            '42\tblind-relay\t1\t7\tFalse\t\t\t',
        ]

    def test_hyperdht_holepunch_reply(self, cmd_tshark, capture_file, test_env):
        '''A holepunch reply links to its request; the punch id lives there.

        The reply carries id 0 because the server already zeroes the id on
        the FROM_SERVER leg the reply is built from.
        '''
        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Y', 'frame.number == 43 || frame.number == 44',
                '-Tfields', '-eframe.number', '-ehyperdht.transaction_id',
                '-ehyperdht.peer_holepunch.mode',
                '-ehyperdht.peer_holepunch.id',
                '-ehyperdht.response_in', '-ehyperdht.request_in',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '43\t23\t0\t4321\t44\t',
            '44\t23\t4\t0\t\t43',
        ]

    def test_hyperdht_relay_round(self, cmd_tshark, capture_file, test_env):
        '''Relayed handshake and holepunch legs pair up without a response.

        A relayed leg is answered by another request under the same
        transaction id, not by a dht-rpc response: the FROM_RELAY forward
        links to the FROM_SERVER request that answers it. The
        FROM_SECOND_RELAY leg, a forward the server declined (frame 48) and
        an answer whose forward went over a second relay (frame 49) are all
        legitimate and stay unlinked.
        '''
        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Y', 'frame.number in {13, 14, 45, 46, 47, 48, 49}',
                '-Tfields', '-eframe.number', '-ehyperdht.transaction_id',
                '-ehyperdht.peer_holepunch.id',
                '-ehyperdht.response_in', '-ehyperdht.request_in',
                '-ehyperdht.response_time',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '13\t7\t1234\t14\t\t',
            '14\t7\t0\t\t13\t0.001000000',
            '45\t24\t\t46\t\t',
            '46\t24\t\t\t45\t0.001000000',
            '47\t25\t\t\t\t',
            '48\t26\t5678\t\t\t',
            '49\t27\t\t\t\t',
        ]

    def test_hyperdht_truncated_request(self, cmd_tshark, capture_file, test_env):
        '''A snaplen-truncated request still anchors its reply.

        Frame 50 is cut mid-value, so its mode is unreadable in the capture,
        but the peer saw the whole packet: the request must be tracked and
        the fully captured reply must keep its link.
        '''
        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Y', 'frame.number == 51',
                '-Tfields', '-ehyperdht.request_in', '-ehyperdht.response_time',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == ['50\t0.001000000']

    def test_hyperdht_tid_collision(self, cmd_tshark, capture_file, test_env):
        '''A relayed answer must not close an ordinary request's slot.

        Frame 53 is a FROM_SERVER leg reusing the transaction id the LOOKUP
        of frame 52 still has in flight on the same conversation. The LOOKUP
        keeps its real reply and the stray answer stays unlinked.
        '''
        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Y', 'frame.number in {52, 53, 54}',
                '-Tfields', '-eframe.number', '-ehyperdht.response_in',
                '-ehyperdht.request_in', '-ehyperdht.response_time',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '52\t54\t\t',
            '53\t\t\t',
            '54\t\t52\t0.002000000',
        ]

    def test_hyperdht_stale_forward_slot(self, cmd_tshark, capture_file, test_env):
        '''A declined forward's slot must not adopt a later ordinary request.

        Frame 55 is a FROM_RELAY forward the server declined, so its slot is
        never resolved. Frame 56 reuses the transaction id five seconds later
        as an ordinary LOOKUP: it must start a fresh transaction, so its
        reply's response time is the real millisecond, not the five seconds
        since the forward.
        '''
        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Y', 'frame.number in {55, 56, 57}',
                '-Tfields', '-eframe.number', '-ehyperdht.response_in',
                '-ehyperdht.request_in', '-ehyperdht.response_time',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '55\t\t\t',
            '56\t57\t\t',
            '57\t\t56\t0.001000000',
        ]

    def test_hyperdht_bad_length(self, cmd_tshark, capture_file, test_env):
        '''A count that outruns the packet is clamped, flagged, and decoded.

        Frame 59 declares nine closer nodes with two on the wire: both real
        records still render, the reply still links to its request, and the
        length expert item fires instead of a malformed-packet abort.
        '''
        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Y', 'hyperdht.bad_length',
                '-Tfields', '-eframe.number', '-ehyperdht.closer_nodes.node.ipv4',
                '-ehyperdht.closer_nodes.node.port', '-ehyperdht.request_in',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == ['59\t10.0.0.2,10.0.0.3\t49737,40001\t58']

    def test_hyperdht_expert_items(self, cmd_tshark, capture_file, test_env):
        '''Every expert item the capture is built to raise, and no others.'''
        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Y', '_ws.expert',
                '-Tfields', '-eframe.number', '-e_ws.expert.message',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '31\tUnrecognized command',
            '33\tUnrecognized command',
            '36\tUnrecognized error code',
            '37\tTrailing data after end of message',
            '39\tNo request captured for this response',
            '42\tNo response captured for this request',
            '59\tLength or element count exceeds the remaining packet data',
        ]

        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht.pcap.gz'),
                '-Y', 'hyperdht.trailing_bytes',
                '-Tfields', '-eframe.number', '-ehyperdht.trailing',
            ), encoding='utf-8', env=test_env)
        assert stdout.strip() == '37\tdeadbeef'

    def test_hyperdht_transaction_id_reuse(self, cmd_tshark, capture_file, test_env):
        '''Transaction ids are reused and requests are retransmitted.

        Frames 1 and 3 share a transaction id, so each reply has to match the
        request still outstanding rather than the first one ever seen. Frames
        5 and 6 are the same request sent twice; the single reply is timed
        from the first transmission.
        '''
        stdout = subprocess.check_output((cmd_tshark, '-2',
                '-r', capture_file('hyperdht_tidreuse.pcap.gz'),
                '-Tfields', '-eframe.number', '-ehyperdht.transaction_id',
                '-ehyperdht.request_in', '-ehyperdht.response_in',
                '-ehyperdht.response_time',
            ), encoding='utf-8', env=test_env)
        assert stdout.splitlines() == [
            '1\t7\t\t2\t',
            '2\t7\t1\t\t0.001000000',
            '3\t7\t\t4\t',
            '4\t7\t3\t\t0.001000000',
            '5\t9\t\t7\t',
            '6\t9\t\t7\t',
            '7\t9\t5\t\t0.002000000',
        ]
