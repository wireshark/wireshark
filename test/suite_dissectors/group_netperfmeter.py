#
# Wireshark tests
#
# Copyright 2021 by Thomas Dreibholz <dreibh [AT] simula.no>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''NetPerfMeter tests'''

import subprocess


class TestNetperfmeter:

    def test_netperfmeter_test_control(self, cmd_tshark, capture_file, test_env):
        '''Checks whether the NetPerfMeter dissector correctly handles NetPerfMeter Control via SCTP.'''

        # Test: Identify and decode NetPerfMeter Control via SCTP
        stdout = subprocess.check_output((cmd_tshark,
                                '-r', capture_file('netperfmeter.pcapng.gz'),
                                '-Y', 'sctp && netperfmeter && ((netperfmeter.message_type != 5) && (netperfmeter.message_type != 4))'
                                ),
                                encoding='utf-8', env=test_env)

        result = ''.join([x.strip()+"\n" for x in stdout.splitlines()])

        assert """\
8 0.019316433  192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 260 NetPerfMeter Add Flow
10 0.038537718 0.019221285 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
14 0.326752277 0.288214559 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
18 0.333703948 0.006951671 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=1, Arwnd=106496) NetPerfMeter Add Flow
19 0.340092259 0.006388311 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=1, Arwnd=106496) NetPerfMeter Acknowledge
23 0.547510935 0.207418676 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
24 0.548336846 0.000825911 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=3, Arwnd=106496) NetPerfMeter Add Flow
25 0.556582544 0.008245698 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=2, Arwnd=106496) NetPerfMeter Acknowledge
28 0.768799828 0.212217284 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
29 0.769562835 0.000763007 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=5, Arwnd=106496) NetPerfMeter Add Flow
30 0.777872331 0.008309496 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=3, Arwnd=106496) NetPerfMeter Acknowledge
33 0.986925179 0.209052848 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
37 0.992962317 0.006037138 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=7, Arwnd=106496) NetPerfMeter Add Flow
38 1.000163511 0.007201194 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=4, Arwnd=106496) NetPerfMeter Acknowledge
41 1.245101828 0.244938317 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
45 1.248598897 0.003497069 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=9, Arwnd=106496) NetPerfMeter Add Flow
46 1.257101874 0.008502977 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=5, Arwnd=106496) NetPerfMeter Acknowledge
49 1.502117462 0.245015588 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
53 1.509411259 0.007293797 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=11, Arwnd=106496) NetPerfMeter Add Flow
54 1.518356124 0.008944865 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=6, Arwnd=106496) NetPerfMeter Acknowledge
57 1.762124577 0.243768453 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
61 1.768546288 0.006421711 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=13, Arwnd=106496) NetPerfMeter Add Flow
62 1.776275446 0.007729158 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=7, Arwnd=106496) NetPerfMeter Acknowledge
65 1.996204594 0.219929148 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
69 2.003084950 0.006880356 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=15, Arwnd=106496) NetPerfMeter Add Flow
70 2.012723649 0.009638699 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=8, Arwnd=106496) NetPerfMeter Acknowledge
73 2.253277911 0.240554262 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
77 2.259089003 0.005811092 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=17, Arwnd=106496) NetPerfMeter Add Flow
78 2.267758027 0.008669024 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=9, Arwnd=106496) NetPerfMeter Acknowledge
81 2.513148441 0.245390414 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
85 2.519444777 0.006296336 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=19, Arwnd=106496) NetPerfMeter Add Flow
86 2.526479512 0.007034735 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=10, Arwnd=106496) NetPerfMeter Acknowledge
89 2.772395957 0.245916445 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
93 2.781575331 0.009179374 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=21, Arwnd=106496) NetPerfMeter Add Flow
94 2.789065601 0.007490270 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=11, Arwnd=106496) NetPerfMeter Acknowledge
97 2.998736571 0.209670970 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
101 3.005046187 0.006309616 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=23, Arwnd=106496) NetPerfMeter Add Flow
102 3.011025634 0.005979447 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=12, Arwnd=106496) NetPerfMeter Acknowledge
105 3.255120658 0.244095024 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
109 3.262979723 0.007859065 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=25, Arwnd=106496) NetPerfMeter Add Flow
110 3.270638348 0.007658625 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=13, Arwnd=106496) NetPerfMeter Acknowledge
113 3.518145868 0.247507520 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
118 3.536880998 0.018735130 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=27, Arwnd=106496) NetPerfMeter Add Flow
119 3.541489068 0.004608070 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=14, Arwnd=106496) NetPerfMeter Acknowledge
123 3.776536632 0.235047564 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
124 3.777268092 0.000731460 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=29, Arwnd=106496) NetPerfMeter Add Flow
125 3.784200653 0.006932561 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=15, Arwnd=106496) NetPerfMeter Acknowledge
128 3.995220129 0.211019476 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
129 3.995907203 0.000687074 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=31, Arwnd=106496) NetPerfMeter Add Flow
131 4.006264635 0.010357432 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=16, Arwnd=106496) NetPerfMeter Acknowledge
135 4.215292054 0.209027419 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
136 4.216018889 0.000726835 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=33, Arwnd=106496) NetPerfMeter Add Flow
137 4.222906817 0.006887928 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=17, Arwnd=106496) NetPerfMeter Acknowledge
141 4.430858169 0.207951352 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
142 4.431619137 0.000760968 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=35, Arwnd=106496) NetPerfMeter Add Flow
143 4.439186831 0.007567694 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=18, Arwnd=106496) NetPerfMeter Acknowledge
147 4.647960736 0.208773905 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
148 4.648753903 0.000793167 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=37, Arwnd=106496) NetPerfMeter Add Flow
149 4.654062259 0.005308356 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=19, Arwnd=106496) NetPerfMeter Acknowledge
153 4.861696359 0.207634100 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
158 4.881874024 0.020177665 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 276 SACK (Ack=39, Arwnd=106496) NetPerfMeter Add Flow
159 4.886932549 0.005058525 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=20, Arwnd=106496) NetPerfMeter Acknowledge
163 5.095411239 0.208478690 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
184 5.101147570 0.005736331 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 96 SACK (Ack=41, Arwnd=106496) NetPerfMeter Start Measurement
227 5.315482367 0.214334797 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
2084 15.615367349 10.299884982 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 80 NetPerfMeter Stop Measurement
2086 16.091680420 0.476313071 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 88 NetPerfMeter Acknowledge
2087 16.092542043 0.000861623 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2088 16.092542469 0.000000426 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2089 16.092542579 0.000000110 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2090 16.092542691 0.000000112 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2093 16.098744445 0.006201754 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2095 16.099492702 0.000748257 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2096 16.099493075 0.000000373 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2097 16.099493204 0.000000129 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2098 16.099493337 0.000000133 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2101 16.108240278 0.008746941 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2102 16.109665125 0.001424847 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2103 16.109665219 0.000000094 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2104 16.109665258 0.000000039 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2105 16.109665298 0.000000040 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2106 16.109665335 0.000000037 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2107 16.109665374 0.000000039 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2108 16.109665413 0.000000039 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2109 16.109665451 0.000000038 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2114 16.115534573 0.005869122 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2116 16.117085522 0.001550949 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2117 16.117085740 0.000000218 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2118 16.117085774 0.000000034 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2119 16.117085808 0.000000034 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2120 16.117085841 0.000000033 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2121 16.117085874 0.000000033 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2122 16.117085906 0.000000032 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2123 16.117085940 0.000000034 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2125 16.117208639 0.000122699 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2129 16.117847682 0.000639043 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2131 16.120936939 0.003089257 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2132 16.121564917 0.000627978 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2134 16.124001266 0.002436349 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2135 16.126359615 0.002358349 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2136 16.126359784 0.000000169 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2137 16.126359829 0.000000045 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2138 16.126359875 0.000000046 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2139 16.126359923 0.000000048 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2140 16.126359972 0.000000049 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2141 16.126360016 0.000000044 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2142 16.126360065 0.000000049 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2144 16.126516782 0.000156717 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2145 16.126516838 0.000000056 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2150 16.126568776 0.000051938 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2151 16.126568857 0.000000081 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2152 16.126568903 0.000000046 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2153 16.126568947 0.000000044 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1088 NetPerfMeter Results
2154 16.126568990 0.000000043 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2155 16.126569037 0.000000047 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2156 16.126569084 0.000000047 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2162 16.128296076 0.001726992 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2163 16.128991998 0.000695922 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2164 16.128992266 0.000000268 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2166 16.132186659 0.003194393 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2168 16.133696852 0.001510193 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2169 16.133697204 0.000000352 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2170 16.133697304 0.000000100 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2171 16.133697400 0.000000096 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2172 16.133697505 0.000000105 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2175 16.136109923 0.002412418 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2177 16.138000289 0.001890366 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2178 16.138000795 0.000000506 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2179 16.138000952 0.000000157 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2180 16.138001087 0.000000135 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2181 16.138001222 0.000000135 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2182 16.138001355 0.000000133 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2183 16.138001497 0.000000142 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2184 16.138001654 0.000000157 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2189 16.138407582 0.000405928 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2190 16.138407852 0.000000270 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2191 16.138407948 0.000000096 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1360 NetPerfMeter Results
2193 16.138949169 0.000541221 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=113, Arwnd=106496) NetPerfMeter Remove Flow
2194 16.147965640 0.009016471 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=23, Arwnd=106496) NetPerfMeter Acknowledge
2195 16.149160472 0.001194832 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2197 16.149694877 0.000534405 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2199 16.359112863 0.209417986 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 400 NetPerfMeter Results
2200 16.360439472 0.001326609 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=117, Arwnd=106496) NetPerfMeter Remove Flow
2201 16.367838301 0.007398829 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=24, Arwnd=106496) NetPerfMeter Acknowledge
2202 16.369999711 0.002161410 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2204 16.370249698 0.000249987 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 252 NetPerfMeter Results
2205 16.371333521 0.001083823 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=120, Arwnd=106496) NetPerfMeter Remove Flow
2206 16.377931209 0.006597688 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=25, Arwnd=106496) NetPerfMeter Acknowledge
2207 16.379416052 0.001484843 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2209 16.379921676 0.000505624 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2211 16.586758032 0.206836356 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 460 NetPerfMeter Results
2212 16.588004878 0.001246846 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=124, Arwnd=106496) NetPerfMeter Remove Flow
2213 16.596287178 0.008282300 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=26, Arwnd=106496) NetPerfMeter Acknowledge
2214 16.600862615 0.004575437 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2216 16.601572074 0.000709459 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 256 NetPerfMeter Results
2217 16.602770488 0.001198414 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=127, Arwnd=106496) NetPerfMeter Remove Flow
2218 16.608528578 0.005758090 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=27, Arwnd=106496) NetPerfMeter Acknowledge
2219 16.610851595 0.002323017 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2221 16.611228721 0.000377126 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2224 16.820428495 0.209199774 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 368 NetPerfMeter Results
2226 16.821725312 0.001296817 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=131, Arwnd=106496) NetPerfMeter Remove Flow
2227 16.829665670 0.007940358 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=28, Arwnd=106496) NetPerfMeter Acknowledge
2228 16.831477557 0.001811887 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2230 16.831711400 0.000233843 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 276 NetPerfMeter Results
2233 16.832859448 0.001148048 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=134, Arwnd=106496) NetPerfMeter Remove Flow
2235 16.838963861 0.006104413 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=29, Arwnd=106496) NetPerfMeter Acknowledge
2236 16.839917250 0.000953389 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2238 16.841055807 0.001138557 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 236 NetPerfMeter Results
2241 16.842312060 0.001256253 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=137, Arwnd=106496) NetPerfMeter Remove Flow
2243 16.847748197 0.005436137 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=30, Arwnd=106496) NetPerfMeter Acknowledge
2244 16.848933463 0.001185266 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2246 16.849525492 0.000592029 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 236 NetPerfMeter Results
2249 16.850661714 0.001136222 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=140, Arwnd=106496) NetPerfMeter Remove Flow
2251 16.857615760 0.006954046 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=31, Arwnd=106496) NetPerfMeter Acknowledge
2252 16.859140443 0.001524683 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2254 16.859653107 0.000512664 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 976 NetPerfMeter Results
2257 16.860923512 0.001270405 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=143, Arwnd=106496) NetPerfMeter Remove Flow
2259 16.866293943 0.005370431 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=32, Arwnd=106496) NetPerfMeter Acknowledge
2260 16.867822941 0.001528998 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2262 16.868668201 0.000845260 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2265 17.079265007 0.210596806 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 368 NetPerfMeter Results
2267 17.080555093 0.001290086 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=147, Arwnd=106496) NetPerfMeter Remove Flow
2268 17.089928582 0.009373489 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=33, Arwnd=106496) NetPerfMeter Acknowledge
2269 17.091479195 0.001550613 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2271 17.092073003 0.000593808 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 272 NetPerfMeter Results
2274 17.093044526 0.000971523 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=150, Arwnd=106496) NetPerfMeter Remove Flow
2276 17.099098185 0.006053659 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=34, Arwnd=106496) NetPerfMeter Acknowledge
2277 17.100201203 0.001103018 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2279 17.100852674 0.000651471 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 244 NetPerfMeter Results
2282 17.101916382 0.001063708 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=153, Arwnd=106496) NetPerfMeter Remove Flow
2284 17.109026614 0.007110232 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=35, Arwnd=106496) NetPerfMeter Acknowledge
2285 17.112907819 0.003881205 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2287 17.115302865 0.002395046 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 244 NetPerfMeter Results
2290 17.116443045 0.001140180 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=156, Arwnd=106496) NetPerfMeter Remove Flow
2292 17.122058351 0.005615306 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=36, Arwnd=106496) NetPerfMeter Acknowledge
2293 17.125840461 0.003782110 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2295 17.126459769 0.000619308 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 976 NetPerfMeter Results
2297 17.126760188 0.000300419 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=159, Arwnd=106496) NetPerfMeter Remove Flow
2300 17.132579296 0.005819108 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=37, Arwnd=106496) NetPerfMeter Acknowledge
2301 17.133301477 0.000722181 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2302 17.133302153 0.000000676 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 284 NetPerfMeter Results
2304 17.133706810 0.000404657 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=162, Arwnd=106496) NetPerfMeter Remove Flow
2305 17.138731552 0.005024742 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=38, Arwnd=106496) NetPerfMeter Acknowledge
2306 17.139818471 0.001086919 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2308 17.140335127 0.000516656 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 288 NetPerfMeter Results
2309 17.140830809 0.000495682 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=165, Arwnd=106496) NetPerfMeter Remove Flow
2310 17.145622016 0.004791207 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=39, Arwnd=106496) NetPerfMeter Acknowledge
2311 17.147059541 0.001437525 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2313 17.148571671 0.001512130 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2314 17.149475099 0.000903428 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2316 17.150223037 0.000747938 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2318 17.359940788 0.209717751 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 740 NetPerfMeter Results
2319 17.361102522 0.001161734 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=171, Arwnd=106496) NetPerfMeter Remove Flow
2320 17.368203507 0.007100985 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=40, Arwnd=106496) NetPerfMeter Acknowledge
2321 17.370823736 0.002620229 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2323 17.371236232 0.000412496 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 280 NetPerfMeter Results
2324 17.372205596 0.000969364 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=174, Arwnd=106496) NetPerfMeter Remove Flow
2325 17.378113171 0.005907575 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=41, Arwnd=106496) NetPerfMeter Acknowledge
2326 17.379408121 0.001294950 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2328 17.379940226 0.000532105 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 284 NetPerfMeter Results
2329 17.380772832 0.000832606 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=177, Arwnd=106496) NetPerfMeter Remove Flow
2330 17.389000119 0.008227287 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=42, Arwnd=106496) NetPerfMeter Acknowledge
2331 17.389893116 0.000892997 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2332 17.389893325 0.000000209 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 380 NetPerfMeter Results
2334 17.390667295 0.000773970 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 100 SACK (Ack=180, Arwnd=106496) NetPerfMeter Remove Flow
2335 17.395701306 0.005034011 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 104 SACK (Ack=43, Arwnd=106496) NetPerfMeter Acknowledge
2336 17.397791412 0.002090106 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1468 NetPerfMeter Results
2338 17.398332887 0.000541475 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 284 NetPerfMeter Results
""".replace("\r\n", "\n") in result

    def test_netperfmeter_test_udp(self, cmd_tshark, capture_file, test_env):
        '''Checks whether the NetPerfMeter dissector correctly handles NetPerfMeter Data via UDP.'''

        # Test: Identify and decode NetPerfMeter Data via UDP
        stdout = subprocess.check_output((cmd_tshark,
                                '-r', capture_file('netperfmeter.pcapng.gz'),
                                '-Y', 'frame.number >= 1 && frame.number <= 512 && udp && netperfmeter'
                                ),
                                encoding='utf-8', env=test_env)

        result = ''.join([x.strip()+"\n" for x in stdout.splitlines()])

        assert """\
26 0.556893098  192.168.0.20 → 192.168.0.27 UDP, NetPerfMeter 70 NetPerfMeter Identify Flow
31 0.778199411 0.221306313 192.168.0.20 → 192.168.0.27 UDP, NetPerfMeter 70 NetPerfMeter Identify Flow
166 5.097058561 4.318859150 192.168.0.20 → 192.168.0.27 UDP, NetPerfMeter 1068 NetPerfMeter Data
167 5.097156368 0.000097807 192.168.0.20 → 192.168.0.27 UDP, NetPerfMeter 556 NetPerfMeter Data
203 5.188581678 0.091425310 192.168.0.27 → 192.168.0.20 UDP, NetPerfMeter 1068 NetPerfMeter Data
204 5.198869201 0.010287523 192.168.0.27 → 192.168.0.20 UDP, NetPerfMeter 556 NetPerfMeter Data
229 5.347412858 0.148543657 192.168.0.20 → 192.168.0.27 UDP, NetPerfMeter 1068 NetPerfMeter Data
248 5.521667162 0.174254304 192.168.0.27 → 192.168.0.20 UDP, NetPerfMeter 1068 NetPerfMeter Data
249 5.529727434 0.008060272 192.168.0.27 → 192.168.0.20 UDP, NetPerfMeter 556 NetPerfMeter Data
251 5.597939044 0.068211610 192.168.0.20 → 192.168.0.27 UDP, NetPerfMeter 1068 NetPerfMeter Data
252 5.597979296 0.000040252 192.168.0.20 → 192.168.0.27 UDP, NetPerfMeter 556 NetPerfMeter Data
315 5.848599107 0.250619811 192.168.0.20 → 192.168.0.27 UDP, NetPerfMeter 1068 NetPerfMeter Data
326 5.869626418 0.021027311 192.168.0.27 → 192.168.0.20 UDP, NetPerfMeter 1068 NetPerfMeter Data
327 5.870477253 0.000850835 192.168.0.27 → 192.168.0.20 UDP, NetPerfMeter 556 NetPerfMeter Data
336 6.099006262 0.228529009 192.168.0.20 → 192.168.0.27 UDP, NetPerfMeter 1068 NetPerfMeter Data
337 6.099035694 0.000029432 192.168.0.20 → 192.168.0.27 UDP, NetPerfMeter 556 NetPerfMeter Data
374 6.239221234 0.140185540 192.168.0.27 → 192.168.0.20 UDP, NetPerfMeter 1068 NetPerfMeter Data
375 6.240243736 0.001022502 192.168.0.27 → 192.168.0.20 UDP, NetPerfMeter 556 NetPerfMeter Data
406 6.349592731 0.109348995 192.168.0.20 → 192.168.0.27 UDP, NetPerfMeter 1068 NetPerfMeter Data
429 6.538916191 0.189323460 192.168.0.27 → 192.168.0.20 UDP, NetPerfMeter 1068 NetPerfMeter Data
430 6.540208385 0.001292194 192.168.0.27 → 192.168.0.20 UDP, NetPerfMeter 556 NetPerfMeter Data
438 6.600112279 0.059903894 192.168.0.20 → 192.168.0.27 UDP, NetPerfMeter 556 NetPerfMeter Data
439 6.600127896 0.000015617 192.168.0.20 → 192.168.0.27 UDP, NetPerfMeter 1068 NetPerfMeter Data
499 6.850796522 0.250668626 192.168.0.20 → 192.168.0.27 UDP, NetPerfMeter 1068 NetPerfMeter Data
509 6.874579699 0.023783177 192.168.0.27 → 192.168.0.20 UDP, NetPerfMeter 1068 NetPerfMeter Data
510 6.875289205 0.000709506 192.168.0.27 → 192.168.0.20 UDP, NetPerfMeter 556 NetPerfMeter Data
""".replace("\r\n", "\n") in result

    def test_netperfmeter_test_dccp(self, cmd_tshark, capture_file, test_env):
        '''Checks whether the NetPerfMeter dissector correctly handles NetPerfMeter Data via DCCP.'''

        # Test: Identify and decode NetPerfMeter Data via DCCP
        stdout = subprocess.check_output((cmd_tshark,
                                '-r', capture_file('netperfmeter.pcapng.gz'),
                                '-Y', 'frame.number >= 1 && frame.number <= 256 && dccp && netperfmeter'
                                ),
                                encoding='utf-8', env=test_env)

        result = ''.join([x.strip()+"\n" for x in stdout.splitlines()])

        assert """\
39 1.000448305  192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 106 NetPerfMeter Identify Flow
47 1.257376250 0.256927945 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 106 NetPerfMeter Identify Flow
55 1.518626642 0.261250392 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 106 NetPerfMeter Identify Flow
63 1.776552210 0.257925568 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 106 NetPerfMeter Identify Flow
71 2.013038051 0.236485841 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 106 NetPerfMeter Identify Flow
79 2.268029558 0.254991507 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 106 NetPerfMeter Identify Flow
87 2.526765502 0.258735944 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 106 NetPerfMeter Identify Flow
95 2.789401573 0.262636071 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 106 NetPerfMeter Identify Flow
103 3.011188128 0.221786555 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 106 NetPerfMeter Identify Flow
111 3.270945041 0.259756913 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 106 NetPerfMeter Identify Flow
168 5.097388740 1.826443699 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 1112 NetPerfMeter Data
169 5.097563303 0.000174563 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 1112 NetPerfMeter Data
170 5.097680252 0.000116949 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 600 NetPerfMeter Data
171 5.097804675 0.000124423 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 600 NetPerfMeter Data
172 5.097860862 0.000056187 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 336 NetPerfMeter Data
173 5.097960425 0.000099563 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 1104 NetPerfMeter Data
174 5.098168605 0.000208180 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 1104 NetPerfMeter Data
175 5.098268064 0.000099459 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 592 NetPerfMeter Data
176 5.098379939 0.000111875 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 592 NetPerfMeter Data
177 5.098474409 0.000094470 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 336 NetPerfMeter Data
205 5.203489906 0.105015497 192.168.0.27 → 192.168.0.20 DCCP, NetPerfMeter 1088 NetPerfMeter Data
206 5.208120579 0.004630673 192.168.0.27 → 192.168.0.20 DCCP, NetPerfMeter 1088 NetPerfMeter Data
207 5.211621270 0.003500691 192.168.0.27 → 192.168.0.20 DCCP, NetPerfMeter 576 NetPerfMeter Data
208 5.216629302 0.005008032 192.168.0.27 → 192.168.0.20 DCCP, NetPerfMeter 576 NetPerfMeter Data
209 5.218637208 0.002007906 192.168.0.27 → 192.168.0.20 DCCP, NetPerfMeter 320 NetPerfMeter Data
210 5.220923234 0.002286026 192.168.0.27 → 192.168.0.20 DCCP, NetPerfMeter 1088 NetPerfMeter Data
211 5.224470647 0.003547413 192.168.0.27 → 192.168.0.20 DCCP, NetPerfMeter 1088 NetPerfMeter Data
212 5.228633904 0.004163257 192.168.0.27 → 192.168.0.20 DCCP, NetPerfMeter 576 NetPerfMeter Data
213 5.235096316 0.006462412 192.168.0.27 → 192.168.0.20 DCCP, NetPerfMeter 576 NetPerfMeter Data
214 5.235387030 0.000290714 192.168.0.27 → 192.168.0.20 DCCP, NetPerfMeter 320 NetPerfMeter Data
230 5.347723929 0.112336899 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 1088 NetPerfMeter Data
231 5.348299245 0.000575316 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 1088 NetPerfMeter Data
236 5.432621676 0.084322431 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 320 NetPerfMeter Data
237 5.433090508 0.000468832 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 320 NetPerfMeter Data
238 5.458215001 0.025124493 192.168.0.27 → 192.168.0.20 DCCP, NetPerfMeter 1104 NetPerfMeter Data
240 5.472252869 0.014037868 192.168.0.27 → 192.168.0.20 DCCP, NetPerfMeter 1104 NetPerfMeter Data
250 5.597889485 0.125636616 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 1096 NetPerfMeter Data
255 5.598126766 0.000237281 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 1088 NetPerfMeter Data
256 5.598378615 0.000251849 192.168.0.20 → 192.168.0.27 DCCP, NetPerfMeter 576 NetPerfMeter Data
""".replace("\r\n", "\n") in result

    def test_netperfmeter_test_tcp(self, cmd_tshark, capture_file, test_env):
        '''Checks whether the NetPerfMeter dissector correctly handles NetPerfMeter Data via TCP.'''

        # Test: Identify and decode NetPerfMeter Data via TCP
        stdout = subprocess.check_output((cmd_tshark,
                                '-r', capture_file('netperfmeter.pcapng.gz'),
                                '-Y', 'frame.number >= 1 && frame.number <= 512 && tcp && netperfmeter'
                                ),
                                encoding='utf-8', env=test_env)

        result = ''.join([x.strip()+"\n" for x in stdout.splitlines()])

        assert """\
12 0.038833197  192.168.0.20 → 192.168.0.27 TCP, NetPerfMeter 94 NetPerfMeter Identify Flow
20 0.340423798 0.301590601 192.168.0.20 → 192.168.0.27 TCP, NetPerfMeter 94 NetPerfMeter Identify Flow
164 5.096822593 4.756398795 192.168.0.20 → 192.168.0.27 TCP, NetPerfMeter 1092 NetPerfMeter Data
165 5.096933125 0.000110532 192.168.0.20 → 192.168.0.27 TCP, NetPerfMeter 580 NetPerfMeter Data
199 5.180197902 0.083264777 192.168.0.27 → 192.168.0.20 TCP, NetPerfMeter 1092 NetPerfMeter Data
201 5.183618768 0.003420866 192.168.0.27 → 192.168.0.20 TCP, NetPerfMeter 580 NetPerfMeter Data
228 5.347212980 0.163594212 192.168.0.20 → 192.168.0.27 TCP, NetPerfMeter 1092 NetPerfMeter Data
243 5.510843364 0.163630384 192.168.0.27 → 192.168.0.20 TCP, NetPerfMeter 1092 NetPerfMeter Data
246 5.518285725 0.007442361 192.168.0.27 → 192.168.0.20 TCP, NetPerfMeter 580 NetPerfMeter Data
253 5.598004664 0.079718939 192.168.0.20 → 192.168.0.27 TCP, NetPerfMeter 580 NetPerfMeter Data
254 5.598037007 0.000032343 192.168.0.20 → 192.168.0.27 TCP, NetPerfMeter 1092 NetPerfMeter Data
313 5.843608886 0.245571879 192.168.0.27 → 192.168.0.20 TCP, NetPerfMeter 1092 NetPerfMeter Data
316 5.848649435 0.005040549 192.168.0.20 → 192.168.0.27 TCP, NetPerfMeter 1092 NetPerfMeter Data
320 5.852294838 0.003645403 192.168.0.27 → 192.168.0.20 TCP, NetPerfMeter 580 NetPerfMeter Data
335 6.098962324 0.246667486 192.168.0.20 → 192.168.0.27 TCP, NetPerfMeter 580 NetPerfMeter Data
342 6.099194942 0.000232618 192.168.0.20 → 192.168.0.27 TCP, NetPerfMeter 1092 NetPerfMeter Data
370 6.178557080 0.079362138 192.168.0.27 → 192.168.0.20 TCP, NetPerfMeter 1092 NetPerfMeter Data
372 6.186668259 0.008111179 192.168.0.27 → 192.168.0.20 TCP, NetPerfMeter 580 NetPerfMeter Data
408 6.349677977 0.163009718 192.168.0.20 → 192.168.0.27 TCP, NetPerfMeter 1092 NetPerfMeter Data
425 6.512522597 0.162844620 192.168.0.27 → 192.168.0.20 TCP, NetPerfMeter 1092 NetPerfMeter Data
427 6.521373219 0.008850622 192.168.0.27 → 192.168.0.20 TCP, NetPerfMeter 580 NetPerfMeter Data
436 6.600056667 0.078683448 192.168.0.20 → 192.168.0.27 TCP, NetPerfMeter 580 NetPerfMeter Data
441 6.600170332 0.000113665 192.168.0.20 → 192.168.0.27 TCP, NetPerfMeter 1092 NetPerfMeter Data
497 6.846781911 0.246611579 192.168.0.27 → 192.168.0.20 TCP, NetPerfMeter 1092 NetPerfMeter Data
502 6.850917051 0.004135140 192.168.0.20 → 192.168.0.27 TCP, NetPerfMeter 1092 NetPerfMeter Data
507 6.857231771 0.006314720 192.168.0.27 → 192.168.0.20 TCP, NetPerfMeter 580 NetPerfMeter Data
""".replace("\r\n", "\n") in result

    def test_netperfmeter_test_sctp(self, cmd_tshark, capture_file, test_env):
        '''Checks whether the NetPerfMeter dissector correctly handles NetPerfMeter Data via SCTP.'''

        # Test: Identify and decode NetPerfMeter Data via SCTP
        stdout = subprocess.check_output((cmd_tshark,
                                '-r', capture_file('netperfmeter.pcapng.gz'),
                                '-Y', 'frame.number >= 1 && frame.number <= 256 && sctp && netperfmeter && ((netperfmeter.message_type == 5) || (netperfmeter.message_type == 4))'
                                ),
                                encoding='utf-8', env=test_env)

        result = ''.join([x.strip()+"\n" for x in stdout.splitlines()])

        assert """\
120 3.541753666  192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 92 NetPerfMeter Identify Flow
126 3.784578040 0.242824374 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 92 NetPerfMeter Identify Flow
132 4.006622016 0.222043976 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 92 NetPerfMeter Identify Flow
138 4.223204664 0.216582648 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 92 NetPerfMeter Identify Flow
144 4.439513544 0.216308880 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 92 NetPerfMeter Identify Flow
150 4.654398275 0.214884731 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 92 NetPerfMeter Identify Flow
160 4.887196553 0.232798278 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 92 NetPerfMeter Identify Flow
178 5.098706269 0.211509716 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 1088 NetPerfMeter Data
180 5.098939899 0.000233630 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 660 NetPerfMeter Data
181 5.099244178 0.000304279 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter, NetPerfMeter 1232 NetPerfMeter Data NetPerfMeter Data
182 5.099428646 0.000184468 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 1088 NetPerfMeter Data
183 5.099642887 0.000214241 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 1088 NetPerfMeter Data
215 5.242589734 0.142946847 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1104 SACK (Ack=11, Arwnd=106496) NetPerfMeter Data
216 5.242748399 0.000158665 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter, NetPerfMeter 1248 SACK (Ack=0, Arwnd=211968) NetPerfMeter Data NetPerfMeter Data
218 5.247412901 0.004664502 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 680 NetPerfMeter Data
220 5.252114400 0.004701499 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 208 SACK (Ack=13, Arwnd=105344) NetPerfMeter Data
221 5.266387026 0.014272626 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1088 NetPerfMeter Data
223 5.266637245 0.000250219 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1088 NetPerfMeter Data
224 5.273527654 0.006890409 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1104 SACK (Ack=1, Arwnd=106496) NetPerfMeter Data
232 5.349726358 0.076198704 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 208 SACK (Ack=5, Arwnd=212992) NetPerfMeter Data
235 5.355361743 0.005635385 192.168.0.27 → 192.168.0.20 SCTP, NetPerfMeter 1104 SACK (Ack=14, Arwnd=106368) NetPerfMeter Data
242 5.475302128 0.119940385 192.168.0.20 → 192.168.0.27 SCTP, NetPerfMeter 208 SACK (Ack=6, Arwnd=212992) NetPerfMeter Data
""".replace("\r\n", "\n") in result
