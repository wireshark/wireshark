#!/usr/bin/env python3
#
# Wireshark tests
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Make the synthetic AX.25 captures of the sequence and reject mode tests.

Each capture below is text2pcap input, written by hand: raw AX.25 frames
(link-layer type 3, no FCS), each preceded by its time in seconds and a
comment with its frame number. The times are chosen to cross T1 (3 s by
default) and T3 (300 s by default, the ax25.t3 preference) where a test
needs it.

Run from the top of the source tree, with text2pcap in PATH or given:

    python3 test/util_ax25_captures.py [path/to/text2pcap]

which writes test/captures/<name>.pcap.gz for every capture here.
'''

import gzip
import os
import subprocess
import sys
import tempfile

CAPTURES = {
'ax25_srej': '''\
# Link 1 (W1AA/W1AB): SABM link without XID, so v2.0 defaults:
# implicit reject. An SREJ is flagged (WARN).
# 1: SABM
0.000000
0000 ae 62 82 84 40 40 e0 ae 62 82 82 40 40 61 3f

# 2: UA
1.000000
0000 ae 62 82 82 40 40 60 ae 62 82 84 40 40 e1 73

# 3: I N(S)=0
2.000000
0000 ae 62 82 84 40 40 e0 ae 62 82 82 40 40 61 00 f0
0010 6f 6e 65

# 4: I N(S)=1
3.000000
0000 ae 62 82 84 40 40 e0 ae 62 82 82 40 40 61 02 f0
0010 74 77 6f

# 5: SREJ N(R)=0: implicit reject in effect (WARN)
4.000000
0000 ae 62 82 82 40 40 60 ae 62 82 84 40 40 e1 0d

# Link 2 (W2AA/W2AB): SABME link without XID, so v2.2 defaults:
# selective reject. Several single SREJs are legal.
# 6: SABME
100.000000
0000 ae 64 82 84 40 40 e0 ae 64 82 82 40 40 61 7f

# 7: UA
101.000000
0000 ae 64 82 82 40 40 60 ae 64 82 84 40 40 e1 73

# 8: I N(S)=0
102.000000
0000 ae 64 82 84 40 40 e0 ae 64 82 82 40 40 61 00 00
0010 f0 64 61 74 61 20 30

# 9: I N(S)=1
103.000000
0000 ae 64 82 84 40 40 e0 ae 64 82 82 40 40 61 02 00
0010 f0 64 61 74 61 20 31

# 10: I N(S)=2
104.000000
0000 ae 64 82 84 40 40 e0 ae 64 82 82 40 40 61 04 00
0010 f0 64 61 74 61 20 32

# 11: I N(S)=3
105.000000
0000 ae 64 82 84 40 40 e0 ae 64 82 82 40 40 61 06 00
0010 f0 64 61 74 61 20 33

# 12: SREJ N(R)=1
106.000000
0000 ae 64 82 82 40 40 60 ae 64 82 84 40 40 e1 0d 02

# 13: SREJ N(R)=3 (a second one: legal)
106.100000
0000 ae 64 82 82 40 40 60 ae 64 82 84 40 40 e1 0d 06

# Link 3 (W3AA/W3AB): XID as Direwolf sends it: the command offers
# REJ, SREJ and SREJ multiframe, the response selects SREJ multiframe
# alone (bit 21). Multi-SREJ is in effect; using it is fine.
# 14: XID command: REJ, SREJ, SREJ multiframe, modulo 128
200.000000
0000 ae 66 82 84 40 40 e0 ae 66 82 82 40 40 61 bf 82
0010 80 00 05 03 03 86 a8 22

# 15: XID response: SREJ multiframe, modulo 128
201.000000
0000 ae 66 82 82 40 40 60 ae 66 82 84 40 40 e1 bf 82
0010 80 00 05 03 03 80 a8 22

# 16: SABME
202.000000
0000 ae 66 82 84 40 40 e0 ae 66 82 82 40 40 61 7f

# 17: UA
203.000000
0000 ae 66 82 82 40 40 60 ae 66 82 84 40 40 e1 73

# 18: I N(S)=0
204.000000
0000 ae 66 82 84 40 40 e0 ae 66 82 82 40 40 61 00 00
0010 f0 64 61 74 61 20 30

# 19: I N(S)=1
205.000000
0000 ae 66 82 84 40 40 e0 ae 66 82 82 40 40 61 02 00
0010 f0 64 61 74 61 20 31

# 20: I N(S)=2
206.000000
0000 ae 66 82 84 40 40 e0 ae 66 82 82 40 40 61 04 00
0010 f0 64 61 74 61 20 32

# 21: I N(S)=3
207.000000
0000 ae 66 82 84 40 40 e0 ae 66 82 82 40 40 61 06 00
0010 f0 64 61 74 61 20 33

# 22: I N(S)=4
208.000000
0000 ae 66 82 84 40 40 e0 ae 66 82 82 40 40 61 08 00
0010 f0 64 61 74 61 20 34

# 23: I N(S)=5
209.000000
0000 ae 66 82 84 40 40 e0 ae 66 82 82 40 40 61 0a 00
0010 f0 64 61 74 61 20 35

# 24: multi-SREJ N(R)=1, and 3
210.000000
0000 ae 66 82 82 40 40 60 ae 66 82 84 40 40 e1 0d 02
0010 06

# 25: multi-SREJ N(R)=1, and the span 3-5
211.000000
0000 ae 66 82 82 40 40 60 ae 66 82 84 40 40 e1 0d 02
0010 07 0b

# Link 4 (W4AA/W4AB): SABME link without XID. Multi-SREJ was never
# selected: a multi-SREJ is flagged (WARN).
# 26: SABME
300.000000
0000 ae 68 82 84 40 40 e0 ae 68 82 82 40 40 61 7f

# 27: UA
301.000000
0000 ae 68 82 82 40 40 60 ae 68 82 84 40 40 e1 73

# 28: I N(S)=0
302.000000
0000 ae 68 82 84 40 40 e0 ae 68 82 82 40 40 61 00 00
0010 f0 64 61 74 61 20 30

# 29: I N(S)=1
303.000000
0000 ae 68 82 84 40 40 e0 ae 68 82 82 40 40 61 02 00
0010 f0 64 61 74 61 20 31

# 30: I N(S)=2
304.000000
0000 ae 68 82 84 40 40 e0 ae 68 82 82 40 40 61 04 00
0010 f0 64 61 74 61 20 32

# 31: I N(S)=3
305.000000
0000 ae 68 82 84 40 40 e0 ae 68 82 82 40 40 61 06 00
0010 f0 64 61 74 61 20 33

# 32: multi-SREJ N(R)=1, and 2 (WARN)
306.000000
0000 ae 68 82 82 40 40 60 ae 68 82 84 40 40 e1 0d 02
0010 04

# Link 5 (W5AA/W5AB): capture starts mid-session. A two-octet SREJ
# is a modulo 8 multi-SREJ as much as a modulo 128 SREJ, so it
# doesn't set the modulo; the RR after it does (bits 4-7 set).
# 33: SREJ N(R)=0 with one more octet: modulo stays assumed
400.000000
0000 ae 6a 82 82 40 40 60 ae 6a 82 84 40 40 e1 0d a0

# 34: RR N(R)=3: modulo 8 inferred
401.000000
0000 ae 6a 82 82 40 40 60 ae 6a 82 84 40 40 e1 61

# 35: multi-SREJ N(R)=3, and 6, in modulo 8 (WARN); reject mode unknown
402.000000
0000 ae 6a 82 82 40 40 60 ae 6a 82 84 40 40 e1 6d c0

# Link 6 (W6AA/W6AB): the XID response has PI 3 with PL=0, the
# default: selective reject without multi-SREJ.
# 36: XID command: REJ, SREJ, SREJ multiframe, modulo 128
500.000000
0000 ae 6c 82 84 40 40 e0 ae 6c 82 82 40 40 61 bf 82
0010 80 00 05 03 03 86 a8 22

# 37: XID response: PI 3, PL=0
501.000000
0000 ae 6c 82 82 40 40 60 ae 6c 82 84 40 40 e1 bf 82
0010 80 00 02 03 00

# 38: SABME
502.000000
0000 ae 6c 82 84 40 40 e0 ae 6c 82 82 40 40 61 7f

# 39: UA
503.000000
0000 ae 6c 82 82 40 40 60 ae 6c 82 84 40 40 e1 73

# 40: I N(S)=0
504.000000
0000 ae 6c 82 84 40 40 e0 ae 6c 82 82 40 40 61 00 00
0010 f0 64 61 74 61 20 30

# 41: I N(S)=1
505.000000
0000 ae 6c 82 84 40 40 e0 ae 6c 82 82 40 40 61 02 00
0010 f0 64 61 74 61 20 31

# 42: I N(S)=2
506.000000
0000 ae 6c 82 84 40 40 e0 ae 6c 82 82 40 40 61 04 00
0010 f0 64 61 74 61 20 32

# 43: SREJ N(R)=1: fine
507.000000
0000 ae 6c 82 82 40 40 60 ae 6c 82 84 40 40 e1 0d 02

# Link 7 (W7AA/W7AB): FRMR answering XID, so v2.0 defaults: implicit
# reject, also on the SABM link that follows.
# 44: XID command
600.000000
0000 ae 6e 82 84 40 40 e0 ae 6e 82 82 40 40 61 bf 82
0010 80 00 05 03 03 86 a4 02

# 45: FRMR answering it
601.000000
0000 ae 6e 82 82 40 40 60 ae 6e 82 84 40 40 e1 97 bf
0010 00 01

# 46: SABM (new stream)
602.000000
0000 ae 6e 82 84 40 40 e0 ae 6e 82 82 40 40 61 3f

# 47: UA
603.000000
0000 ae 6e 82 82 40 40 60 ae 6e 82 84 40 40 e1 73

# 48: I N(S)=0
604.000000
0000 ae 6e 82 84 40 40 e0 ae 6e 82 82 40 40 61 00 f0
0010 6f 6e 65

# 49: SREJ N(R)=0: implicit reject (WARN)
605.000000
0000 ae 6e 82 82 40 40 60 ae 6e 82 84 40 40 e1 0d

''',
'ax25_srej_errors': '''\
# Link 1 (W8AA/W8AB): XID negotiates implicit reject; an SREJ is an
# error.
# 1: XID command: REJ, SREJ, modulo 128
0.000000
0000 ae 70 82 84 40 40 e0 ae 70 82 82 40 40 61 bf 82
0010 80 00 05 03 03 86 a8 02

# 2: XID response: REJ, modulo 128
1.000000
0000 ae 70 82 82 40 40 60 ae 70 82 84 40 40 e1 bf 82
0010 80 00 05 03 03 82 a8 02

# 3: SABME
2.000000
0000 ae 70 82 84 40 40 e0 ae 70 82 82 40 40 61 7f

# 4: UA
3.000000
0000 ae 70 82 82 40 40 60 ae 70 82 84 40 40 e1 73

# 5: I N(S)=0
4.000000
0000 ae 70 82 84 40 40 e0 ae 70 82 82 40 40 61 00 00
0010 f0 64 61 74 61 20 30

# 6: I N(S)=1
5.000000
0000 ae 70 82 84 40 40 e0 ae 70 82 82 40 40 61 02 00
0010 f0 64 61 74 61 20 31

# 7: SREJ N(R)=0 (ERROR)
6.000000
0000 ae 70 82 82 40 40 60 ae 70 82 84 40 40 e1 0d 00

# Link 2 (W9AA/W9AB): XID selects SREJ without SREJ multiframe; a
# multi-SREJ is an error.
# 8: XID command: REJ, SREJ, SREJ multiframe, modulo 128
100.000000
0000 ae 72 82 84 40 40 e0 ae 72 82 82 40 40 61 bf 82
0010 80 00 05 03 03 86 a8 22

# 9: XID response: SREJ, modulo 128
101.000000
0000 ae 72 82 82 40 40 60 ae 72 82 84 40 40 e1 bf 82
0010 80 00 05 03 03 84 a8 02

# 10: SABME
102.000000
0000 ae 72 82 84 40 40 e0 ae 72 82 82 40 40 61 7f

# 11: UA
103.000000
0000 ae 72 82 82 40 40 60 ae 72 82 84 40 40 e1 73

# 12: I N(S)=0
104.000000
0000 ae 72 82 84 40 40 e0 ae 72 82 82 40 40 61 00 00
0010 f0 64 61 74 61 20 30

# 13: I N(S)=1
105.000000
0000 ae 72 82 84 40 40 e0 ae 72 82 82 40 40 61 02 00
0010 f0 64 61 74 61 20 31

# 14: I N(S)=2
106.000000
0000 ae 72 82 84 40 40 e0 ae 72 82 82 40 40 61 04 00
0010 f0 64 61 74 61 20 32

# 15: multi-SREJ N(R)=0, and 2 (ERROR)
107.000000
0000 ae 72 82 82 40 40 60 ae 72 82 84 40 40 e1 0d 00
0010 04

''',
'ax25_seq_mod8': '''\
# Link 1 (K1AA/K1AB), modulo 8: a digipeated copy, a REJ and its
# go-back-N, the 7 -> 0 wrap, retransmissions by T1 and unexplained,
# one with another I field.
# 1: SABM
0.000000
0000 96 62 82 84 40 40 e0 96 62 82 82 40 40 61 3f

# 2: UA: V(S) = V(A) = 0 on both sides
1.000000
0000 96 62 82 82 40 40 60 96 62 82 84 40 40 e1 73

# 3: I N(S)=0
2.000000
0000 96 62 82 84 40 40 e0 96 62 82 82 40 40 61 00 f0
0010 64 61 74 61 20 30

# 4: I N(S)=1
2.500000
0000 96 62 82 84 40 40 e0 96 62 82 82 40 40 61 02 f0
0010 64 61 74 61 20 31

# 5: RR N(R)=2
3.000000
0000 96 62 82 82 40 40 60 96 62 82 84 40 40 e1 41

# 6: I N(S)=2 via DIGI1
4.000000
0000 96 62 82 84 40 40 e0 96 62 82 82 40 40 60 88 92
0010 8e 92 62 40 61 04 f0 64 61 74 61 20 32

# 7: the same, repeated by DIGI1: a digipeated copy, not a retransmission
4.200000
0000 96 62 82 84 40 40 e0 96 62 82 82 40 40 60 88 92
0010 8e 92 62 40 e1 04 f0 64 61 74 61 20 32

# 8: I N(S)=3
5.000000
0000 96 62 82 84 40 40 e0 96 62 82 82 40 40 61 06 f0
0010 64 61 74 61 20 33

# 9: I N(S)=4
5.500000
0000 96 62 82 84 40 40 e0 96 62 82 82 40 40 61 08 f0
0010 64 61 74 61 20 34

# 10: REJ N(R)=3
6.000000
0000 96 62 82 82 40 40 60 96 62 82 84 40 40 e1 69

# 11: I N(S)=3: retransmission, REJ
6.500000
0000 96 62 82 84 40 40 e0 96 62 82 82 40 40 61 06 f0
0010 64 61 74 61 20 33

# 12: I N(S)=4: retransmission, REJ
7.000000
0000 96 62 82 84 40 40 e0 96 62 82 82 40 40 61 08 f0
0010 64 61 74 61 20 34

# 13: I N(S)=5: new
7.500000
0000 96 62 82 84 40 40 e0 96 62 82 82 40 40 61 0a f0
0010 64 61 74 61 20 35

# 14: I N(S)=6
8.000000
0000 96 62 82 84 40 40 e0 96 62 82 82 40 40 61 0c f0
0010 64 61 74 61 20 36

# 15: I N(S)=7
8.500000
0000 96 62 82 84 40 40 e0 96 62 82 82 40 40 61 0e f0
0010 64 61 74 61 20 37

# 16: RR N(R)=0
9.000000
0000 96 62 82 82 40 40 60 96 62 82 84 40 40 e1 01

# 17: I N(S)=0: new, after the wrap
9.500000
0000 96 62 82 84 40 40 e0 96 62 82 82 40 40 61 00 f0
0010 64 61 74 61 20 38

# 18: RR N(R)=1
10.000000
0000 96 62 82 82 40 40 60 96 62 82 84 40 40 e1 21

# 19: I N(S)=1
14.000000
0000 96 62 82 84 40 40 e0 96 62 82 82 40 40 61 02 f0
0010 64 61 74 61 20 39

# 20: I N(S)=1: retransmission after 6 s, T1
20.000000
0000 96 62 82 84 40 40 e0 96 62 82 82 40 40 61 02 f0
0010 64 61 74 61 20 39

# 21: I N(S)=2
21.000000
0000 96 62 82 84 40 40 e0 96 62 82 82 40 40 61 04 f0
0010 64 61 74 61 20 31 30

# 22: I N(S)=2: retransmission after 1 s, unexplained, with another I field
22.000000
0000 96 62 82 84 40 40 e0 96 62 82 82 40 40 61 04 f0
0010 64 61 74 61 20 31 30 20 61 67 61 69 6e

# 23: RR N(R)=3
23.000000
0000 96 62 82 82 40 40 60 96 62 82 84 40 40 e1 61

# Link 2 (K2AA/K2AB), modulo 8 with selective reject (XID): SREJ, a
# T1 enquiry and the retransmission after its answer, a frame not
# captured and the one that is then out of order, duplicate
# acknowledgements, a T3 poll.
# 24: XID command: REJ, SREJ, modulo 8
100.000000
0000 96 64 82 84 40 40 e0 96 64 82 82 40 40 61 bf 82
0010 80 00 05 03 03 86 a4 02

# 25: XID response: SREJ, modulo 8
101.000000
0000 96 64 82 82 40 40 60 96 64 82 84 40 40 e1 bf 82
0010 80 00 05 03 03 84 a4 02

# 26: SABM
102.000000
0000 96 64 82 84 40 40 e0 96 64 82 82 40 40 61 3f

# 27: UA
103.000000
0000 96 64 82 82 40 40 60 96 64 82 84 40 40 e1 73

# 28: I N(S)=0
104.000000
0000 96 64 82 84 40 40 e0 96 64 82 82 40 40 61 00 f0
0010 64 61 74 61 20 30

# 29: I N(S)=1
105.000000
0000 96 64 82 84 40 40 e0 96 64 82 82 40 40 61 02 f0
0010 64 61 74 61 20 31

# 30: I N(S)=2
106.000000
0000 96 64 82 84 40 40 e0 96 64 82 82 40 40 61 04 f0
0010 64 61 74 61 20 32

# 31: I N(S)=3
107.000000
0000 96 64 82 84 40 40 e0 96 64 82 82 40 40 61 06 f0
0010 64 61 74 61 20 33

# 32: SREJ N(R)=1, F=0
108.000000
0000 96 64 82 82 40 40 60 96 64 82 84 40 40 e1 2d

# 33: I N(S)=1: retransmission, SREJ
108.500000
0000 96 64 82 84 40 40 e0 96 64 82 82 40 40 61 02 f0
0010 64 61 74 61 20 31

# 34: RR N(R)=4
109.000000
0000 96 64 82 82 40 40 60 96 64 82 84 40 40 e1 81

# 35: I N(S)=4
110.000000
0000 96 64 82 84 40 40 e0 96 64 82 82 40 40 61 08 f0
0010 64 61 74 61 20 34

# 36: I N(S)=5
111.000000
0000 96 64 82 84 40 40 e0 96 64 82 82 40 40 61 0a f0
0010 64 61 74 61 20 35

# 37: RR command P=1, N(R)=0 as before: keep-alive, T1 enquiry (4 and 5 outstanding)
114.500000
0000 96 64 82 84 40 40 e0 96 64 82 82 40 40 61 11

# 38: RR F=1 N(R)=5: keep-alive ACK, V(S) := 5
115.000000
0000 96 64 82 82 40 40 60 96 64 82 84 40 40 e1 b1

# 39: I N(S)=5: retransmission, poll answered
115.500000
0000 96 64 82 84 40 40 e0 96 64 82 82 40 40 61 0a f0
0010 64 61 74 61 20 35

# 40: RR N(R)=6
116.000000
0000 96 64 82 82 40 40 60 96 64 82 84 40 40 e1 c1

# 41: I N(S)=7: N(S)=6 not captured
117.000000
0000 96 64 82 84 40 40 e0 96 64 82 82 40 40 61 0e f0
0010 64 61 74 61 20 37

# 42: I N(S)=6: out of order
117.500000
0000 96 64 82 84 40 40 e0 96 64 82 82 40 40 61 0c f0
0010 64 61 74 61 20 36

# 43: RR N(R)=0
118.000000
0000 96 64 82 82 40 40 60 96 64 82 84 40 40 e1 01

# 44: RR N(R)=0 again: duplicate ACK #1
119.000000
0000 96 64 82 82 40 40 60 96 64 82 84 40 40 e1 01

# 45: RR N(R)=0 again: duplicate ACK #2
120.000000
0000 96 64 82 82 40 40 60 96 64 82 84 40 40 e1 01

# 46: RR command P=1, N(R)=0 after 310 s: keep-alive, T3 poll
430.000000
0000 96 64 82 84 40 40 e0 96 64 82 82 40 40 61 11

# 47: RR F=1: keep-alive ACK
431.000000
0000 96 64 82 82 40 40 60 96 64 82 84 40 40 e1 11

# Link 3 (K3AA/K3AB): busy conditions. A poll answered with RNR then
# RR, an unsolicited RR, anomalous resumes (N(R) higher, then lower),
# and an RNR ended by a SABM.
# 48: SABM
1000.000000
0000 96 66 82 84 40 40 e0 96 66 82 82 40 40 61 3f

# 49: UA
1001.000000
0000 96 66 82 82 40 40 60 96 66 82 84 40 40 e1 73

# 50: I N(S)=0
1002.000000
0000 96 66 82 84 40 40 e0 96 66 82 82 40 40 61 00 f0
0010 64 61 74 61 20 30

# 51: I N(S)=1
1003.000000
0000 96 66 82 84 40 40 e0 96 66 82 82 40 40 61 02 f0
0010 64 61 74 61 20 31

# 52: RNR N(R)=2: busy
1004.000000
0000 96 66 82 82 40 40 60 96 66 82 84 40 40 e1 45

# 53: RNR N(R)=2 again: busy repeated
1005.000000
0000 96 66 82 82 40 40 60 96 66 82 84 40 40 e1 45

# 54: RR command P=1: polls the busy side
1009.000000
0000 96 66 82 84 40 40 e0 96 66 82 82 40 40 61 11

# 55: RNR F=1: still busy
1009.500000
0000 96 66 82 82 40 40 60 96 66 82 84 40 40 e1 55

# 56: RR command P=1: polls again
1013.000000
0000 96 66 82 84 40 40 e0 96 66 82 82 40 40 61 11

# 57: RR F=1 N(R)=2: resume, poll response
1013.500000
0000 96 66 82 82 40 40 60 96 66 82 84 40 40 e1 51

# 58: I N(S)=2
1014.000000
0000 96 66 82 84 40 40 e0 96 66 82 82 40 40 61 04 f0
0010 64 61 74 61 20 32

# 59: RNR N(R)=3: busy
1015.000000
0000 96 66 82 82 40 40 60 96 66 82 84 40 40 e1 65

# 60: RR command P=1 N(R)=3: resume, unsolicited (as in the SDL)
1017.000000
0000 96 66 82 82 40 40 e0 96 66 82 84 40 40 61 71

# 61: RR F=1
1017.500000
0000 96 66 82 84 40 40 60 96 66 82 82 40 40 e1 11

# 62: I N(S)=3
1018.000000
0000 96 66 82 84 40 40 e0 96 66 82 82 40 40 61 06 f0
0010 64 61 74 61 20 33

# 63: RNR N(R)=3: busy, 3 not taken
1019.000000
0000 96 66 82 82 40 40 60 96 66 82 84 40 40 e1 65

# 64: RR N(R)=4: resume with a higher N(R)
1021.000000
0000 96 66 82 82 40 40 60 96 66 82 84 40 40 e1 81

# 65: I N(S)=4
1022.000000
0000 96 66 82 84 40 40 e0 96 66 82 82 40 40 61 08 f0
0010 64 61 74 61 20 34

# 66: RR N(R)=5
1023.000000
0000 96 66 82 82 40 40 60 96 66 82 84 40 40 e1 a1

# 67: RNR N(R)=5: busy
1024.000000
0000 96 66 82 82 40 40 60 96 66 82 84 40 40 e1 a5

# 68: REJ N(R)=4: resume with a lower N(R)
1025.000000
0000 96 66 82 82 40 40 60 96 66 82 84 40 40 e1 89

# 69: RNR N(R)=5: busy
1026.000000
0000 96 66 82 82 40 40 60 96 66 82 84 40 40 e1 a5

# 70: SABM: link reset, the busy condition ends (new stream)
1027.000000
0000 96 66 82 84 40 40 e0 96 66 82 82 40 40 61 3f

# 71: UA
1028.000000
0000 96 66 82 82 40 40 60 96 66 82 84 40 40 e1 73

# 72: RR N(R)=0: not a resume
1029.000000
0000 96 66 82 82 40 40 60 96 66 82 84 40 40 e1 01

# Link 4 (K4AA/K4AB): the busy side repeats RNR every 100 s, but
# the other side only polls after 341 s, more than T3 + N2 x T1.
# 73: SABM
2000.000000
0000 96 68 82 84 40 40 e0 96 68 82 82 40 40 61 3f

# 74: UA
2001.000000
0000 96 68 82 82 40 40 60 96 68 82 84 40 40 e1 73

# 75: I N(S)=0
2002.000000
0000 96 68 82 84 40 40 e0 96 68 82 82 40 40 61 00 f0
0010 64 61 74 61 20 30

# 76: RNR N(R)=1: busy
2003.000000
0000 96 68 82 82 40 40 60 96 68 82 84 40 40 e1 25

# 77: RNR N(R)=1: busy repeated
2103.000000
0000 96 68 82 82 40 40 60 96 68 82 84 40 40 e1 25

# 78: RNR N(R)=1: busy repeated
2203.000000
0000 96 68 82 82 40 40 60 96 68 82 84 40 40 e1 25

# 79: RNR N(R)=1: busy repeated
2303.000000
0000 96 68 82 82 40 40 60 96 68 82 84 40 40 e1 25

# 80: RR command P=1: the first poll, 341 s after the RNR (more than 330 s)
2344.000000
0000 96 68 82 84 40 40 e0 96 68 82 82 40 40 61 11

# 81: RR F=1 N(R)=1: resume, poll response
2345.000000
0000 96 68 82 82 40 40 60 96 68 82 84 40 40 e1 31

# Link 5 (K5AA/K5AB), modulo 8, k=7: the last N(S) was 7, so
# V(S)=0. With V(A)=3, an I frame with N(S)=6 is a retransmission.
# 82: SABM
5000.000000
0000 96 6a 82 84 40 40 e0 96 6a 82 82 40 40 61 3f

# 83: UA
5001.000000
0000 96 6a 82 82 40 40 60 96 6a 82 84 40 40 e1 73

# 84: I N(S)=0
5002.000000
0000 96 6a 82 84 40 40 e0 96 6a 82 82 40 40 61 00 f0
0010 64 61 74 61 20 30

# 85: I N(S)=1
5003.000000
0000 96 6a 82 84 40 40 e0 96 6a 82 82 40 40 61 02 f0
0010 64 61 74 61 20 31

# 86: I N(S)=2
5004.000000
0000 96 6a 82 84 40 40 e0 96 6a 82 82 40 40 61 04 f0
0010 64 61 74 61 20 32

# 87: I N(S)=3
5005.000000
0000 96 6a 82 84 40 40 e0 96 6a 82 82 40 40 61 06 f0
0010 64 61 74 61 20 33

# 88: I N(S)=4
5006.000000
0000 96 6a 82 84 40 40 e0 96 6a 82 82 40 40 61 08 f0
0010 64 61 74 61 20 34

# 89: I N(S)=5
5007.000000
0000 96 6a 82 84 40 40 e0 96 6a 82 82 40 40 61 0a f0
0010 64 61 74 61 20 35

# 90: I N(S)=6
5008.000000
0000 96 6a 82 84 40 40 e0 96 6a 82 82 40 40 61 0c f0
0010 64 61 74 61 20 36

# 91: RR N(R)=1
5009.000000
0000 96 6a 82 82 40 40 60 96 6a 82 84 40 40 e1 21

# 92: I N(S)=7: V(S)=0
5010.000000
0000 96 6a 82 84 40 40 e0 96 6a 82 82 40 40 61 0e f0
0010 64 61 74 61 20 37

# 93: RR N(R)=3: V(A)=3
5011.000000
0000 96 6a 82 82 40 40 60 96 6a 82 84 40 40 e1 61

# 94: I N(S)=6: a retransmission
5012.000000
0000 96 6a 82 84 40 40 e0 96 6a 82 82 40 40 61 0c f0
0010 64 61 74 61 20 36

# Link 6 (K6AA/K6AB), modulo 8, k=7: the last N(S) was 7, so
# V(S)=0. With V(A)=7, an I frame with N(S)=6 is a spurious retransmission.
# 95: SABM
6000.000000
0000 96 6c 82 84 40 40 e0 96 6c 82 82 40 40 61 3f

# 96: UA
6001.000000
0000 96 6c 82 82 40 40 60 96 6c 82 84 40 40 e1 73

# 97: I N(S)=0
6002.000000
0000 96 6c 82 84 40 40 e0 96 6c 82 82 40 40 61 00 f0
0010 64 61 74 61 20 30

# 98: I N(S)=1
6003.000000
0000 96 6c 82 84 40 40 e0 96 6c 82 82 40 40 61 02 f0
0010 64 61 74 61 20 31

# 99: I N(S)=2
6004.000000
0000 96 6c 82 84 40 40 e0 96 6c 82 82 40 40 61 04 f0
0010 64 61 74 61 20 32

# 100: I N(S)=3
6005.000000
0000 96 6c 82 84 40 40 e0 96 6c 82 82 40 40 61 06 f0
0010 64 61 74 61 20 33

# 101: I N(S)=4
6006.000000
0000 96 6c 82 84 40 40 e0 96 6c 82 82 40 40 61 08 f0
0010 64 61 74 61 20 34

# 102: I N(S)=5
6007.000000
0000 96 6c 82 84 40 40 e0 96 6c 82 82 40 40 61 0a f0
0010 64 61 74 61 20 35

# 103: I N(S)=6
6008.000000
0000 96 6c 82 84 40 40 e0 96 6c 82 82 40 40 61 0c f0
0010 64 61 74 61 20 36

# 104: RR N(R)=1
6009.000000
0000 96 6c 82 82 40 40 60 96 6c 82 84 40 40 e1 21

# 105: I N(S)=7: V(S)=0
6010.000000
0000 96 6c 82 84 40 40 e0 96 6c 82 82 40 40 61 0e f0
0010 64 61 74 61 20 37

# 106: RR N(R)=7: V(A)=7
6011.000000
0000 96 6c 82 82 40 40 60 96 6c 82 84 40 40 e1 e1

# 107: I N(S)=6: a spurious retransmission
6012.000000
0000 96 6c 82 84 40 40 e0 96 6c 82 82 40 40 61 0c f0
0010 64 61 74 61 20 36

# Link 7 (K7AA/K7AB), modulo 8, k=7: the last N(S) was 7, so
# V(S)=0. With V(A)=0, an I frame with N(S)=6 is a new frame after 6 not captured.
# 108: SABM
7000.000000
0000 96 6e 82 84 40 40 e0 96 6e 82 82 40 40 61 3f

# 109: UA
7001.000000
0000 96 6e 82 82 40 40 60 96 6e 82 84 40 40 e1 73

# 110: I N(S)=0
7002.000000
0000 96 6e 82 84 40 40 e0 96 6e 82 82 40 40 61 00 f0
0010 64 61 74 61 20 30

# 111: I N(S)=1
7003.000000
0000 96 6e 82 84 40 40 e0 96 6e 82 82 40 40 61 02 f0
0010 64 61 74 61 20 31

# 112: I N(S)=2
7004.000000
0000 96 6e 82 84 40 40 e0 96 6e 82 82 40 40 61 04 f0
0010 64 61 74 61 20 32

# 113: I N(S)=3
7005.000000
0000 96 6e 82 84 40 40 e0 96 6e 82 82 40 40 61 06 f0
0010 64 61 74 61 20 33

# 114: I N(S)=4
7006.000000
0000 96 6e 82 84 40 40 e0 96 6e 82 82 40 40 61 08 f0
0010 64 61 74 61 20 34

# 115: I N(S)=5
7007.000000
0000 96 6e 82 84 40 40 e0 96 6e 82 82 40 40 61 0a f0
0010 64 61 74 61 20 35

# 116: I N(S)=6
7008.000000
0000 96 6e 82 84 40 40 e0 96 6e 82 82 40 40 61 0c f0
0010 64 61 74 61 20 36

# 117: RR N(R)=1
7009.000000
0000 96 6e 82 82 40 40 60 96 6e 82 84 40 40 e1 21

# 118: I N(S)=7: V(S)=0
7010.000000
0000 96 6e 82 84 40 40 e0 96 6e 82 82 40 40 61 0e f0
0010 64 61 74 61 20 37

# 119: RR N(R)=0: V(A)=0
7011.000000
0000 96 6e 82 82 40 40 60 96 6e 82 84 40 40 e1 01

# 120: I N(S)=6: a new frame after 6 not captured
7012.000000
0000 96 6e 82 84 40 40 e0 96 6e 82 82 40 40 61 0c f0
0010 64 61 74 61 20 36

''',
'ax25_seq_mod128': '''\
# Link 1 (M1AA/M1AB), modulo 128, k=127 (notified by XID): the
# capture starts mid-session. The last N(S) was 127, so V(S)=0.
# With V(A)=124, an I frame with N(S)=126 is a retransmission.
# 1: XID command: SREJ, modulo 128, k 127
0.000000
0000 9a 62 82 84 40 40 e0 9a 62 82 82 40 40 61 bf 82
0010 80 00 08 03 03 84 a8 02 08 01 7f

# 2: XID response: SREJ, modulo 128, k 127
1.000000
0000 9a 62 82 82 40 40 60 9a 62 82 84 40 40 e1 bf 82
0010 80 00 08 03 03 84 a8 02 08 01 7f

# 3: RR N(R)=121: two octets, modulo 128 inferred
2.000000
0000 9a 62 82 82 40 40 60 9a 62 82 84 40 40 e1 01 f2

# 4: I N(S)=121
3.000000
0000 9a 62 82 84 40 40 e0 9a 62 82 82 40 40 61 f2 00
0010 f0 64 61 74 61 20 31 32 31

# 5: I N(S)=122
4.000000
0000 9a 62 82 84 40 40 e0 9a 62 82 82 40 40 61 f4 00
0010 f0 64 61 74 61 20 31 32 32

# 6: I N(S)=123
5.000000
0000 9a 62 82 84 40 40 e0 9a 62 82 82 40 40 61 f6 00
0010 f0 64 61 74 61 20 31 32 33

# 7: I N(S)=124
6.000000
0000 9a 62 82 84 40 40 e0 9a 62 82 82 40 40 61 f8 00
0010 f0 64 61 74 61 20 31 32 34

# 8: I N(S)=125
7.000000
0000 9a 62 82 84 40 40 e0 9a 62 82 82 40 40 61 fa 00
0010 f0 64 61 74 61 20 31 32 35

# 9: I N(S)=126
8.000000
0000 9a 62 82 84 40 40 e0 9a 62 82 82 40 40 61 fc 00
0010 f0 64 61 74 61 20 31 32 36

# 10: I N(S)=127
9.000000
0000 9a 62 82 84 40 40 e0 9a 62 82 82 40 40 61 fe 00
0010 f0 64 61 74 61 20 31 32 37

# 11: RR N(R)=124: V(A)=124
10.000000
0000 9a 62 82 82 40 40 60 9a 62 82 84 40 40 e1 01 f8

# 12: I N(S)=126: a retransmission
11.000000
0000 9a 62 82 84 40 40 e0 9a 62 82 82 40 40 61 fc 00
0010 f0 64 61 74 61 20 31 32 36

# 13: I N(S)=0: new, after the wrap
12.000000
0000 9a 62 82 84 40 40 e0 9a 62 82 82 40 40 61 00 00
0010 f0 64 61 74 61 20 31 32 38

# Link 2 (M2AA/M2AB), modulo 128, k=127 (notified by XID): the
# capture starts mid-session. The last N(S) was 127, so V(S)=0.
# With V(A)=127, an I frame with N(S)=126 is a spurious retransmission.
# 14: XID command: SREJ, modulo 128, k 127
1000.000000
0000 9a 64 82 84 40 40 e0 9a 64 82 82 40 40 61 bf 82
0010 80 00 08 03 03 84 a8 02 08 01 7f

# 15: XID response: SREJ, modulo 128, k 127
1001.000000
0000 9a 64 82 82 40 40 60 9a 64 82 84 40 40 e1 bf 82
0010 80 00 08 03 03 84 a8 02 08 01 7f

# 16: RR N(R)=121: two octets, modulo 128 inferred
1002.000000
0000 9a 64 82 82 40 40 60 9a 64 82 84 40 40 e1 01 f2

# 17: I N(S)=121
1003.000000
0000 9a 64 82 84 40 40 e0 9a 64 82 82 40 40 61 f2 00
0010 f0 64 61 74 61 20 31 32 31

# 18: I N(S)=122
1004.000000
0000 9a 64 82 84 40 40 e0 9a 64 82 82 40 40 61 f4 00
0010 f0 64 61 74 61 20 31 32 32

# 19: I N(S)=123
1005.000000
0000 9a 64 82 84 40 40 e0 9a 64 82 82 40 40 61 f6 00
0010 f0 64 61 74 61 20 31 32 33

# 20: I N(S)=124
1006.000000
0000 9a 64 82 84 40 40 e0 9a 64 82 82 40 40 61 f8 00
0010 f0 64 61 74 61 20 31 32 34

# 21: I N(S)=125
1007.000000
0000 9a 64 82 84 40 40 e0 9a 64 82 82 40 40 61 fa 00
0010 f0 64 61 74 61 20 31 32 35

# 22: I N(S)=126
1008.000000
0000 9a 64 82 84 40 40 e0 9a 64 82 82 40 40 61 fc 00
0010 f0 64 61 74 61 20 31 32 36

# 23: I N(S)=127
1009.000000
0000 9a 64 82 84 40 40 e0 9a 64 82 82 40 40 61 fe 00
0010 f0 64 61 74 61 20 31 32 37

# 24: RR N(R)=127: V(A)=127
1010.000000
0000 9a 64 82 82 40 40 60 9a 64 82 84 40 40 e1 01 fe

# 25: I N(S)=126: a spurious retransmission
1011.000000
0000 9a 64 82 84 40 40 e0 9a 64 82 82 40 40 61 fc 00
0010 f0 64 61 74 61 20 31 32 36

# Link 3 (M3AA/M3AB), modulo 128, k=127 (notified by XID): the
# capture starts mid-session. The last N(S) was 127, so V(S)=0.
# With V(A)=0, an I frame with N(S)=126 is a new frame after 0-125 not captured.
# 26: XID command: SREJ, modulo 128, k 127
2000.000000
0000 9a 66 82 84 40 40 e0 9a 66 82 82 40 40 61 bf 82
0010 80 00 08 03 03 84 a8 02 08 01 7f

# 27: XID response: SREJ, modulo 128, k 127
2001.000000
0000 9a 66 82 82 40 40 60 9a 66 82 84 40 40 e1 bf 82
0010 80 00 08 03 03 84 a8 02 08 01 7f

# 28: RR N(R)=121: two octets, modulo 128 inferred
2002.000000
0000 9a 66 82 82 40 40 60 9a 66 82 84 40 40 e1 01 f2

# 29: I N(S)=121
2003.000000
0000 9a 66 82 84 40 40 e0 9a 66 82 82 40 40 61 f2 00
0010 f0 64 61 74 61 20 31 32 31

# 30: I N(S)=122
2004.000000
0000 9a 66 82 84 40 40 e0 9a 66 82 82 40 40 61 f4 00
0010 f0 64 61 74 61 20 31 32 32

# 31: I N(S)=123
2005.000000
0000 9a 66 82 84 40 40 e0 9a 66 82 82 40 40 61 f6 00
0010 f0 64 61 74 61 20 31 32 33

# 32: I N(S)=124
2006.000000
0000 9a 66 82 84 40 40 e0 9a 66 82 82 40 40 61 f8 00
0010 f0 64 61 74 61 20 31 32 34

# 33: I N(S)=125
2007.000000
0000 9a 66 82 84 40 40 e0 9a 66 82 82 40 40 61 fa 00
0010 f0 64 61 74 61 20 31 32 35

# 34: I N(S)=126
2008.000000
0000 9a 66 82 84 40 40 e0 9a 66 82 82 40 40 61 fc 00
0010 f0 64 61 74 61 20 31 32 36

# 35: I N(S)=127
2009.000000
0000 9a 66 82 84 40 40 e0 9a 66 82 82 40 40 61 fe 00
0010 f0 64 61 74 61 20 31 32 37

# 36: RR N(R)=0: V(A)=0
2010.000000
0000 9a 66 82 82 40 40 60 9a 66 82 84 40 40 e1 01 00

# 37: I N(S)=126: a new frame after 0-125 not captured
2011.000000
0000 9a 66 82 84 40 40 e0 9a 66 82 82 40 40 61 fc 00
0010 f0 64 61 74 61 20 31 32 36

''',
'ax25_seq_one_sided': '''\
# Link 1: only O1AA is heard, modulo 8, k=7. Without V(A), N(S)=6
# after V(S)=0 is a retransmission if the I field is the same, else
# a new frame after 0-5 not captured: both guesses. Nothing that
# needs the other side (spurious retransmission, prompts, keep-alive
# ACK, busy side not polled) is flagged.
# 1: RR N(R)=3: modulo 8 inferred (bits 4-7)
0.000000
0000 9e 62 82 84 40 40 60 9e 62 82 82 40 40 e1 61

# 2: I N(S)=0
1.000000
0000 9e 62 82 84 40 40 e0 9e 62 82 82 40 40 61 60 f0
0010 64 61 74 61 20 30

# 3: I N(S)=1
2.000000
0000 9e 62 82 84 40 40 e0 9e 62 82 82 40 40 61 62 f0
0010 64 61 74 61 20 31

# 4: I N(S)=2
3.000000
0000 9e 62 82 84 40 40 e0 9e 62 82 82 40 40 61 64 f0
0010 64 61 74 61 20 32

# 5: I N(S)=3
4.000000
0000 9e 62 82 84 40 40 e0 9e 62 82 82 40 40 61 66 f0
0010 64 61 74 61 20 33

# 6: I N(S)=4
5.000000
0000 9e 62 82 84 40 40 e0 9e 62 82 82 40 40 61 68 f0
0010 64 61 74 61 20 34

# 7: I N(S)=5
6.000000
0000 9e 62 82 84 40 40 e0 9e 62 82 82 40 40 61 6a f0
0010 64 61 74 61 20 35

# 8: I N(S)=6
7.000000
0000 9e 62 82 84 40 40 e0 9e 62 82 82 40 40 61 6c f0
0010 64 61 74 61 20 36

# 9: I N(S)=7
8.000000
0000 9e 62 82 84 40 40 e0 9e 62 82 82 40 40 61 6e f0
0010 64 61 74 61 20 37

# 10: I N(S)=6, same I field: retransmission (guess)
9.000000
0000 9e 62 82 84 40 40 e0 9e 62 82 82 40 40 61 6c f0
0010 64 61 74 61 20 36

# 11: I N(S)=6, another I field: new (guess)
10.000000
0000 9e 62 82 84 40 40 e0 9e 62 82 82 40 40 61 6c f0
0010 64 61 74 61 20 31 34

# 12: RR command P=1 N(R)=3: keep-alive, T1 enquiry (guess: frames may be outstanding)
20.000000
0000 9e 62 82 84 40 40 e0 9e 62 82 82 40 40 61 71

# 13: RNR N(R)=3: busy
21.000000
0000 9e 62 82 84 40 40 60 9e 62 82 82 40 40 e1 65

# 14: RNR N(R)=3: busy repeated (never polled, but the poller is not heard)
121.000000
0000 9e 62 82 84 40 40 60 9e 62 82 82 40 40 e1 65

# 15: RNR N(R)=3: busy repeated (never polled, but the poller is not heard)
221.000000
0000 9e 62 82 84 40 40 60 9e 62 82 82 40 40 e1 65

# 16: RNR N(R)=3: busy repeated (never polled, but the poller is not heard)
341.000000
0000 9e 62 82 84 40 40 60 9e 62 82 82 40 40 e1 65

# 17: RR N(R)=3: resume, unsolicited
342.000000
0000 9e 62 82 84 40 40 60 9e 62 82 82 40 40 e1 61

# 18: RR N(R)=3
343.000000
0000 9e 62 82 84 40 40 60 9e 62 82 82 40 40 e1 61

# 19: RR N(R)=3 again: duplicate ACK
344.000000
0000 9e 62 82 84 40 40 60 9e 62 82 82 40 40 e1 61

# Link 2: only O2AA is heard, modulo 128. With the default k of 32,
# N(S)=126 after V(S)=0 can only be an old frame; with k=127
# (-o ax25.k:127) it is the same guess as on link 1.
# 20: RR N(R)=0: two octets, modulo 128 inferred
1000.000000
0000 9e 64 82 84 40 40 60 9e 64 82 82 40 40 e1 01 00

# 21: I N(S)=121
1001.000000
0000 9e 64 82 84 40 40 e0 9e 64 82 82 40 40 61 f2 00
0010 f0 64 61 74 61 20 31 32 31

# 22: I N(S)=122
1002.000000
0000 9e 64 82 84 40 40 e0 9e 64 82 82 40 40 61 f4 00
0010 f0 64 61 74 61 20 31 32 32

# 23: I N(S)=123
1003.000000
0000 9e 64 82 84 40 40 e0 9e 64 82 82 40 40 61 f6 00
0010 f0 64 61 74 61 20 31 32 33

# 24: I N(S)=124
1004.000000
0000 9e 64 82 84 40 40 e0 9e 64 82 82 40 40 61 f8 00
0010 f0 64 61 74 61 20 31 32 34

# 25: I N(S)=125
1005.000000
0000 9e 64 82 84 40 40 e0 9e 64 82 82 40 40 61 fa 00
0010 f0 64 61 74 61 20 31 32 35

# 26: I N(S)=126
1006.000000
0000 9e 64 82 84 40 40 e0 9e 64 82 82 40 40 61 fc 00
0010 f0 64 61 74 61 20 31 32 36

# 27: I N(S)=127
1007.000000
0000 9e 64 82 84 40 40 e0 9e 64 82 82 40 40 61 fe 00
0010 f0 64 61 74 61 20 31 32 37

# 28: I N(S)=126, same I field
1008.000000
0000 9e 64 82 84 40 40 e0 9e 64 82 82 40 40 61 fc 00
0010 f0 64 61 74 61 20 31 32 36

# 29: I N(S)=126, another I field
1009.000000
0000 9e 64 82 84 40 40 e0 9e 64 82 82 40 40 61 fc 00
0010 f0 64 61 74 61 20 32 35 34

''',
'ax25_repeat': '''\
# Link 1 (R1AA/R1AB): frames repeated as is, as a KISS modem with
# local echo shows them, or as T1 retries: each is a retransmission
# of the first one and changes nothing. A UA repeated after DISC/UA
# does not start a new stream.
# 1: SABM
0.000000
0000 a4 62 82 84 40 40 e0 a4 62 82 82 40 40 61 3f

# 2: the same SABM: repeat of 1
0.001000
0000 a4 62 82 84 40 40 e0 a4 62 82 82 40 40 61 3f

# 3: UA
1.000000
0000 a4 62 82 82 40 40 60 a4 62 82 84 40 40 e1 73

# 4: I N(S)=0
2.000000
0000 a4 62 82 84 40 40 e0 a4 62 82 82 40 40 61 00 f0
0010 64 61 74 61 20 30

# 5: RR N(R)=1
3.000000
0000 a4 62 82 82 40 40 60 a4 62 82 84 40 40 e1 21

# 6: RR command P=1: keep-alive, T3 poll
4.000000
0000 a4 62 82 84 40 40 e0 a4 62 82 82 40 40 61 11

# 7: the same poll: repeat of 6
4.001000
0000 a4 62 82 84 40 40 e0 a4 62 82 82 40 40 61 11

# 8: RR F=1: keep-alive ACK of 6
5.000000
0000 a4 62 82 82 40 40 60 a4 62 82 84 40 40 e1 31

# 9: RR N(R)=1
6.000000
0000 a4 62 82 82 40 40 60 a4 62 82 84 40 40 e1 21

# 10: the same RR, P/F=0: a duplicate ACK, not a repeat
7.000000
0000 a4 62 82 82 40 40 60 a4 62 82 84 40 40 e1 21

# 11: DISC
8.000000
0000 a4 62 82 82 40 40 e0 a4 62 82 84 40 40 61 53

# 12: UA: disconnected
9.000000
0000 a4 62 82 84 40 40 60 a4 62 82 82 40 40 e1 73

# 13: the same UA: repeat of 12, still disconnected, same stream
9.001000
0000 a4 62 82 84 40 40 60 a4 62 82 82 40 40 e1 73

# 14: SABM: a new stream
20.000000
0000 a4 62 82 84 40 40 e0 a4 62 82 82 40 40 61 3f

# 15: UA
21.000000
0000 a4 62 82 82 40 40 60 a4 62 82 84 40 40 e1 73

# 16: DISC
30.000000
0000 a4 62 82 84 40 40 e0 a4 62 82 82 40 40 61 53

# 17: the same DISC 3.5 s later: T1 retry of 16
33.500000
0000 a4 62 82 84 40 40 e0 a4 62 82 82 40 40 61 53

# 18: UA
34.000000
0000 a4 62 82 82 40 40 60 a4 62 82 84 40 40 e1 73

# Link 2: only R2AA is heard. Its T3 polls repeat each other, but
# come T3 apart: keep-alives, not repeats. Its UA can answer a SABM
# that was not heard, so it is not taken for a repeat of the first.
# 19: RR N(R)=0: modulo 8 inferred
100.000000
0000 a4 64 82 84 40 40 60 a4 64 82 82 40 40 e1 01

# 20: RR command P=1: keep-alive
101.000000
0000 a4 64 82 84 40 40 e0 a4 64 82 82 40 40 61 11

# 21: the same poll 301 s later: keep-alive again
402.000000
0000 a4 64 82 84 40 40 e0 a4 64 82 82 40 40 61 11

# 22: UA
500.000000
0000 a4 64 82 84 40 40 60 a4 64 82 82 40 40 e1 73

# 23: the same UA: the other side is not heard, not a repeat
500.001000
0000 a4 64 82 84 40 40 60 a4 64 82 82 40 40 e1 73

''',
}


def main():
    text2pcap = sys.argv[1] if len(sys.argv) > 1 else 'text2pcap'
    captures = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'captures')
    with tempfile.TemporaryDirectory() as tmp:
        for name, text in CAPTURES.items():
            src = os.path.join(tmp, name + '.txt')
            pcap = os.path.join(tmp, name + '.pcap')
            with open(src, 'w') as f:
                f.write(text)
            subprocess.run((text2pcap, '-q', '-F', 'pcap', '-l', '3', '-t', '%s.%f', src, pcap),
                           check=True)
            with open(pcap, 'rb') as f, gzip.GzipFile(os.path.join(captures, name + '.pcap.gz'),
                                                      'wb', mtime=0) as out:
                out.write(f.read())


if __name__ == '__main__':
    main()
