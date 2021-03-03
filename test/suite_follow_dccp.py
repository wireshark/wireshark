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
    def test_follow_dccp_existing_flow(self, cmd_tshark, capture_file):
        '''Checks whether Follow DCCP correctly handles an existing flow.'''

        # Test 1:
        # 1. Identification of DCCP Flow #9
        # 2. Selection and decoding of DCCP Flow #9
        proc = self.assertRun((cmd_tshark,
                                '-r', capture_file('netperfmeter.pcapng.gz'),
                                '-qz', 'follow,dccp,hex,9',
                                ))

        result = ''.join([x.strip()+"\n" for x in proc.stdout_str.splitlines()])
        self.assertIn("""\
===================================================================
Follow: dccp,hex
Filter: dccp.stream eq 9
Node 0: 192.168.0.20:42807
Node 1: 192.168.0.27:9000
00000000  04 00 00 1a 00 00 00 0d  4b cd f3 aa 30 3c 67 74  ........ K...0<gt
00000010  12 12 01 be 09 2f f4 24  00 00                    ...../.$ ..
0000001A  05 03 01 00 00 00 00 0d  12 12 01 be 09 2f f4 24  ........ ...../.$
0000002A  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ........ ........
0000003A  00 00 00 00 00 00 00 00  00 05 bc a2 0c c3 83 68  ........ .......h
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
	00000000  05 03 01 00 00 00 00 0d  12 12 01 be 09 2f f4 24  ........ ...../.$
	00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ........ ........
	00000020  00 00 00 00 00 00 00 00  00 05 bc a2 0c c5 76 71  ........ ......vq
	00000030  7f 7e 7d 7c 7b 7a 79 78  77 76 75 74 73 72 71 70  .~}|{zyx wvutsrqp
	00000040  6f 6e 6d 6c 6b 6a 69 68  67 66 65 64 63 62 61 60  onmlkjih gfedcba`
	00000050  5f 5e 5d 5c 5b 5a 59 58  57 56 55 54 53 52 51 50  _^]\[ZYX WVUTSRQP
	00000060  4f 4e 4d 4c 4b 4a 49 48  47 46 45 44 43 42 41 40  ONMLKJIH GFEDCBA@
	00000070  3f 3e 3d 3c 3b 3a 39 38  37 36 35 34 33 32 31 30  ?>=<;:98 76543210
	00000080  2f 2e 2d 2c 2b 2a 29 28  27 26 25 24 23 22 21 20  /.-,+*)( '&%$#"!
	00000090  1f 1e 7f 7e 7d 7c 7b 7a  79 78 77 76 75 74 73 72  ...~}|{z yxwvutsr
	000000A0  71 70 6f 6e 6d 6c 6b 6a  69 68 67 66 65 64 63 62  qponmlkj ihgfedcb
	000000B0  61 60 5f 5e 5d 5c 5b 5a  59 58 57 56 55 54 53 52  a`_^]\[Z YXWVUTSR
	000000C0  51 50 4f 4e 4d 4c 4b 4a  49 48 47 46 45 44 43 42  QPONMLKJ IHGFEDCB
	000000D0  41 40 3f 3e 3d 3c 3b 3a  39 38 37 36 35 34 33 32  A@?>=<;: 98765432
	000000E0  31 30 2f 2e 2d 2c 2b 2a  29 28 27 26 25 24 23 22  10/.-,+* )('&%$#"
	000000F0  21 20 1f 1e 7f 7e 7d 7c  7b 7a 79 78 77 76 75 74  ! ...~}| {zyxwvut
""".replace("\r\n", "\n").replace("\t", ""),
            result)


    def test_follow_dccp_non_existing_flow(self, cmd_tshark, capture_file):
        '''Checks whether Follow DCCP correctly handles a non-existing existing flow.'''

        # Test 2:
        # Trying identification of not-existing DCCP Flow #10
        proc = self.assertRun((cmd_tshark,
                                '-r', capture_file('netperfmeter.pcapng.gz'),
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
