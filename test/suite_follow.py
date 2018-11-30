#
# -*- coding: utf-8 -*-
# Wireshark tests
#
# Copyright (c) 2018 Peter Wu <peter@lekensteyn.nl>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Follow Stream tests'''

import subprocesstest
import fixtures


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_follow_tcp(subprocesstest.SubprocessTestCase):
    def test_follow_tcp_bad_conditions(self, cmd_tshark, capture_file):
        '''Checks whether Follow TCP correctly handles lots of edge cases.'''
        # Edge cases include:
        # 1. two sequential segments
        # 2. out-of-order (swapped two sequential segments)
        # 3. Bad overlap (second overlap with different data should be ignored)
        # 4. Ignore bad retransmitted data, but extend with remaining data.
        # 5. Check handling of overlapping data while fragments are incomplete
        #    (out-of-order - cannot add fragments to stream)
        # 6. lost but acked segments
        # 7. lost 3/5 fragments, but acked
        # Not checked: lost and not acked (currently truncated, is that OK?)
        proc = self.assertRun((cmd_tshark,
                                '-r', capture_file('tcp-badsegments.pcap'),
                                '-qz', 'follow,tcp,hex,0',
                                ))

        self.assertIn("""\
===================================================================
Follow: tcp,hex
Filter: tcp.stream eq 0
Node 0: 10.0.0.1:32323
Node 1: 10.0.0.2:80
00000000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  GET / HT TP/1.1..
00000010  48 6f 73 74 3a 6c 6f 63  61 6c 68 6f 73 74 0d 0a  Host:loc alhost..
00000020  58 2d 53 77 61 70 70 65  64 3a 20 31 73 74 0d 0a  X-Swappe d: 1st..
00000030  58 2d 53 77 61 70 70 65  64 3a 20 32 6e 64 0d 0a  X-Swappe d: 2nd..
00000040  58 2d 4f 76 65 72 6c 61  70 2d 50 61 63 6b 65 74  X-Overla p-Packet
00000050  3a 20 65 78 74 72 61 20  64 61 74 61 2d 2d 0d 0a  : extra  data--..
00000060  58 2d 4f 6f 4f 2d 4f 76  65 72 6c 61 70 3a 20 74  X-OoO-Ov erlap: t
00000070  68 69 73 20 69 73 20 64  65 6c 61 79 65 64 0d 0a  his is d elayed..
00000080  58 2d 4f 6f 4f 2d 4f 76  65 72 6c 61 70 32 3a 20  X-OoO-Ov erlap2:
00000090  73 65 63 6f 6e 64 20 64  65 6c 61 79 65 64 0d 0a  second d elayed..
000000A0  58 2d 4f 6f 4f 2d 4f 76  65 72 6c 61 70 33 3a 65  X-OoO-Ov erlap3:e
000000B0  78 74 65 6e 64 20 66 72  61 67 6d 65 6e 74 0d 0a  xtend fr agment..
000000C0  5b 33 32 20 62 79 74 65  73 20 6d 69 73 73 69 6e  [32 byte s missin
000000D0  67 20 69 6e 20 63 61 70  74 75 72 65 20 66 69 6c  g in cap ture fil
000000E0  65 5d 00                                          e].
000000E3  58 2d 4d 69 73 73 69 6e  67 2d 42 75 74 2d 41 63  X-Missin g-But-Ac
000000F3  6b 65 64 2d 50 72 65 76  69 6f 75 73 3a 31 0d 0a  ked-Prev ious:1..
00000103  5b 31 36 20 62 79 74 65  73 20 6d 69 73 73 69 6e  [16 byte s missin
00000113  67 20 69 6e 20 63 61 70  74 75 72 65 20 66 69 6c  g in cap ture fil
00000123  65 5d 00                                          e].
00000126  3a                                                :
00000127  5b 31 33 20 62 79 74 65  73 20 6d 69 73 73 69 6e  [13 byte s missin
00000137  67 20 69 6e 20 63 61 70  74 75 72 65 20 66 69 6c  g in cap ture fil
00000147  65 5d 00                                          e].
0000014A  0d                                                .
0000014B  5b 31 20 62 79 74 65 73  20 6d 69 73 73 69 6e 67  [1 bytes  missing
0000015B  20 69 6e 20 63 61 70 74  75 72 65 20 66 69 6c 65   in capt ure file
0000016B  5d 00                                             ].
0000016D  58 2d 4d 69 73 73 69 6e  67 2d 33 2d 4f 75 74 2d  X-Missin g-3-Out-
0000017D  4f 66 2d 35 2d 42 75 74  2d 41 43 4b 3a 59 0d 0a  Of-5-But -ACK:Y..
0000018D  0d 0a                                             ..
===================================================================
""".replace("\r\n", "\n"),
            proc.stdout_str.replace("\r\n", "\n"))
