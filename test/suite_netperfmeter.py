#
# Wireshark tests
#
# Copyright 2021 by Thomas Dreibholz <dreibh [AT] simula.no>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''NetPerfMeter tests'''

import subprocesstest
import fixtures


@fixtures.mark_usefixtures('test_env')
@fixtures.uses_fixtures
class case_netperfmeter(subprocesstest.SubprocessTestCase):

    def test_netperfmeter_test_control(self, cmd_tshark, capture_file):
        '''Checks whether the NetPerfMeter dissector correctly handles NetPerfMeter Control via SCTP.'''

        # Test: Identify and decode NetPerfMeter Control via SCTP
        proc = self.assertRun((cmd_tshark,
                                '-r', capture_file('netperfmeter.pcap.gz'),
                                '-Y', 'sctp && npmp && ((npmp.message_type != 5) && (npmp.message_type != 4))'
                                ))

        result = ''.join([x.strip()+"\n" for x in proc.stdout_str.splitlines()])
        # print(proc.stdout_str)
        self.assertIn("""\
8 0.047986661    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 258 NetPerfMeter Add Flow
10 0.048177359    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 86 NetPerfMeter Acknowledge
14 0.250594074    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 86 NetPerfMeter Acknowledge
15 0.265810836    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 274 SACK NetPerfMeter Add Flow
16 0.266440967    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 102 SACK NetPerfMeter Acknowledge
19 0.470002309    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 86 NetPerfMeter Acknowledge
24 0.489028109    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 274 SACK NetPerfMeter Add Flow
25 0.489660783    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 102 SACK NetPerfMeter Acknowledge
29 0.690068166    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 86 NetPerfMeter Acknowledge
33 0.699478059    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 274 SACK NetPerfMeter Add Flow
34 0.700126978    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 102 SACK NetPerfMeter Acknowledge
37 0.902209296    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 86 NetPerfMeter Acknowledge
53 1.150824987    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 78 NetPerfMeter Start Measurement
60 1.158613559    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 102 SACK NetPerfMeter Acknowledge
7477 11.234965462    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 78 NetPerfMeter Stop Measurement
7478 11.251742556    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 102 SACK NetPerfMeter Acknowledge
7480 11.454363938    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 26538 NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results
7481 11.475644976    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 98 SACK NetPerfMeter Remove Flow
7482 11.476276100    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 102 SACK NetPerfMeter Acknowledge
7484 11.678405933    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 61270 NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results
7485 11.732979950    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 98 SACK NetPerfMeter Remove Flow
7486 11.733621587    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 102 SACK NetPerfMeter Acknowledge
7488 11.934431870    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 61258 NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results
7489 11.954124867    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 98 SACK NetPerfMeter Remove Flow
7490 11.954904670    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 102 SACK NetPerfMeter Acknowledge
7492 12.158217467    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 61418 NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results
7493 12.176065138    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 98 SACK NetPerfMeter Remove Flow
7494 12.176848625    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 102 SACK NetPerfMeter Acknowledge
7497 12.378201722    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 61322 NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results NetPerfMeter Results
""".replace("\r\n", "\n"),
            result)

    def test_netperfmeter_test_udp(self, cmd_tshark, capture_file):
        '''Checks whether the NetPerfMeter dissector correctly handles NetPerfMeter Data via UDP.'''

        # Test: Identify and decode NetPerfMeter Data via UDP
        proc = self.assertRun((cmd_tshark,
                                '-r', capture_file('netperfmeter.pcap.gz'),
                                '-Y', 'frame.number >= 1 && frame.number <= 128 && udp && npmp'
                                ))

        result = ''.join([x.strip()+"\n" for x in proc.stdout_str.splitlines()])
        # print(proc.stdout_str)
        self.assertIn("""\
17 0.267395029    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 68 NetPerfMeter Identify Flow
42 1.063498967    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10042 NetPerfMeter Data
46 1.103276672    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10042 NetPerfMeter Data
50 1.146994673    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10042 NetPerfMeter Data
56 1.155831942    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10042 NetPerfMeter Data
63 1.169450861    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10042 NetPerfMeter Data
67 1.172176716    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10042 NetPerfMeter Data
72 1.182528637    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10042 NetPerfMeter Data
""".replace("\r\n", "\n"),
            result)

    def test_netperfmeter_test_dccp(self, cmd_tshark, capture_file):
        '''Checks whether the NetPerfMeter dissector correctly handles NetPerfMeter Data via DCCP.'''

        # Test: Identify and decode NetPerfMeter Data via DCCP
        proc = self.assertRun((cmd_tshark,
                                '-r', capture_file('netperfmeter.pcap.gz'),
                                '-Y', 'frame.number >= 1 && frame.number <= 128 && dccp && npmp'
                                ))

        result = ''.join([x.strip()+"\n" for x in proc.stdout_str.splitlines()])
        # print(proc.stdout_str)
        self.assertIn("""\
35 0.700539147    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 104 NetPerfMeter Identify Flow
51 1.147581794    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10078 NetPerfMeter Data
59 1.158157910    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10062 NetPerfMeter Data
65 1.170887361    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10062 NetPerfMeter Data
69 1.172886004    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10062 NetPerfMeter Data
74 1.184662323    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10078 NetPerfMeter Data
77 1.188786697    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10070 NetPerfMeter Data
87 1.197675906    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10070 NetPerfMeter Data
""".replace("\r\n", "\n"),
            result)

    def test_netperfmeter_test_tcp(self, cmd_tshark, capture_file):
        '''Checks whether the NetPerfMeter dissector correctly handles NetPerfMeter Data via TCP.'''

        # Test: Identify and decode NetPerfMeter Data via TCP
        proc = self.assertRun((cmd_tshark,
                                '-r', capture_file('netperfmeter.pcap.gz'),
                                '-Y', 'frame.number >= 1 && frame.number <= 128 && tcp && npmp'
                                ))

        result = ''.join([x.strip()+"\n" for x in proc.stdout_str.splitlines()])
        self.assertIn("""\
38 1.016973544    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10066 NetPerfMeter Data
40 1.063038724    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10066 NetPerfMeter Data
44 1.102926584    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10066 NetPerfMeter Data
48 1.146650977    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10066 NetPerfMeter Data
54 1.154725099    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10066 NetPerfMeter Data
61 1.167350917    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10066 NetPerfMeter Data
70 1.180928603    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10066 NetPerfMeter Data
79 1.189654354    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10066 NetPerfMeter Data
""".replace("\r\n", "\n"),
            result)

    def test_netperfmeter_test_sctp(self, cmd_tshark, capture_file):
        '''Checks whether the NetPerfMeter dissector correctly handles NetPerfMeter Data via SCTP.'''

        # Test: Identify and decode NetPerfMeter Data via SCTP
        proc = self.assertRun((cmd_tshark,
                                '-r', capture_file('netperfmeter.pcap.gz'),
                                '-Y', 'frame.number >= 1 && frame.number <= 128 && sctp && npmp && ((npmp.message_type == 5) || (npmp.message_type == 4))'
                                ))

        result = ''.join([x.strip()+"\n" for x in proc.stdout_str.splitlines()])
        # print(proc.stdout_str)
        self.assertIn("""\
26 0.492426657    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 90 NetPerfMeter Identify Flow
43 1.102424794    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10062 NetPerfMeter Data
57 1.157083210    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10078 SACK NetPerfMeter Data
58 1.157123642    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10078 SACK NetPerfMeter Data
64 1.169707829    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10078 SACK NetPerfMeter Data
68 1.172645421    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10078 SACK NetPerfMeter Data
73 1.183433213    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10078 SACK NetPerfMeter Data
76 1.188438431    127.0.0.1 → 127.0.0.1    NetPerfMeterProtocol 10078 SACK NetPerfMeter Data
""".replace("\r\n", "\n"),
            result)
