#
# Wireshark tests
#
# Copyright 2020-2021 by Thomas Dreibholz <dreibh [AT] simula.no>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Follow DCCP Stream tests'''

import subprocesstest
import fixtures


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_follow_dccp(subprocesstest.SubprocessTestCase):
    def test_follow_dccp_bad_conditions(self, cmd_tshark, capture_file):
        '''Checks whether Follow DCCP correctly handles some tests.'''

        # Test 1:
        # 1. Identification of DCCP Flow #9
        # 2. Selection and decoding of DCCP Flow #9
        proc = self.assertRun((cmd_tshark,
                                '-r', capture_file('netperfmeter-dccp.pcapng.gz'),
                                '-qz', 'follow,dccp,hex,9',
                                ))

        self.assertIn("""\
===================================================================
Follow: dccp,hex
Filter: dccp.stream eq 9
Node 0: 127.0.0.1:43933
Node 1: 127.0.0.1:9000
00000000  04 00 00 1a 00 00 00 09  4b cd f3 aa 30 3c 67 74  ........ K...0<gt
00000010  f2 41 ee 5f c8 10 1f 41  00 00                    .A._...A ..
0000001A  05 03 27 10 00 00 00 09  f2 41 ee 5f c8 10 1f 41  ..'..... .A._...A
0000002A  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ........ ........
0000003A  00 00 00 00 00 00 00 00  00 05 ba 0a bf 18 68 19  ........ ......h.
0000004A  1e 1f 20 21 22 23 24 25  26 27 28 29 2a 2b 2c 2d  .. !"#$% &'()*+,-
0000005A  2e 2f 30 31 32 33 34 35  36 37 38 39 3a 3b 3c 3d  ./012345 6789:;<=
0000006A  3e 3f 40 41 42 43 44 45  46 47 48 49 4a 4b 4c 4d  >?@ABCDE FGHIJKLM
0000007A  4e 4f 50 51 52 53 54 55  56 57 58 59 5a 5b 5c 5d  NOPQRSTU VWXYZ[\]
0000008A  5e 5f 60 61 62 63 64 65  66 67 68 69 6a 6b 6c 6d  ^_`abcde fghijklm
0000009A  6e 6f 70 71 72 73 74 75  76 77 78 79 7a 7b 7c 7d  nopqrstu vwxyz{|}
000000AA  7e 7f 1e 1f 20 21 22 23  24 25 26 27 28 29 2a 2b  ~... !"# $%&'()*+
000000BA  2c 2d 2e 2f 30 31 32 33  34 35 36 37 38 39 3a 3b  ,-./0123 456789:;
000000CA  3c 3d 3e 3f 40 41 42 43  44 45 46 47 48 49 4a 4b  <=>?@ABC DEFGHIJK
000000DA  4c 4d 4e 4f 50 51 52 53  54 55 56 57 58 59 5a 5b  LMNOPQRS TUVWXYZ[
000000EA  5c 5d 5e 5f 60 61 62 63  64 65 66 67 68 69 6a 6b  \]^_`abc defghijk
000000FA  6c 6d 6e 6f 70 71 72 73  74 75 76 77 78 79 7a 7b  lmnopqrs tuvwxyz{
0000010A  7c 7d 7e 7f 1e 1f 20 21  22 23 24 25 26 27 28 29  |}~... ! "#$%&'()
0000011A  2a 2b 2c 2d 2e 2f 30 31  32 33 34 35 36 37 38 39  *+,-./01 23456789
""".replace("\r\n", "\n"),
            proc.stdout_str)

        # Test 2:
        # Trying identification of not-existing DCCP Flow #10
        proc = self.assertRun((cmd_tshark,
                                '-r', capture_file('netperfmeter-dccp.pcapng.gz'),
                                '-qz', 'follow,dccp,hex,10',
                                ))

        self.assertIn("""\
===================================================================
Follow: dccp,hex
Filter: dccp.stream eq 10
Node 0: :0
Node 1: :0
===================================================================
""".replace("\r\n", "\n"),
            proc.stdout_str)
