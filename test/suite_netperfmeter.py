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
                                '-r', capture_file('netperfmeter.pcapng.gz'),
                                '-Y', 'sctp && netperfmeter && ((netperfmeter.message_type != 5) && (netperfmeter.message_type != 4))'
                                ))

        result = ''.join([x.strip()+"\n" for x in proc.stdout_str.splitlines()])
        # print(proc.stdout_str)
        self.assertIn("""\
8 0.019316433 192.168.0.20 → 192.168.0.27 NetPerfMeter 260 NetPerfMeter Add Flow
10 0.038537718 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
14 0.326752277 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
18 0.333703948 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
19 0.340092259 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
23 0.547510935 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
24 0.548336846 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
25 0.556582544 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
28 0.768799828 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
29 0.769562835 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
30 0.777872331 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
33 0.986925179 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
37 0.992962317 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
38 1.000163511 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
41 1.245101828 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
45 1.248598897 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
46 1.257101874 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
49 1.502117462 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
53 1.509411259 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
54 1.518356124 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
57 1.762124577 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
61 1.768546288 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
62 1.776275446 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
65 1.996204594 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
69 2.003084950 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
70 2.012723649 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
73 2.253277911 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
77 2.259089003 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
78 2.267758027 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
81 2.513148441 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
85 2.519444777 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
86 2.526479512 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
89 2.772395957 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
93 2.781575331 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
94 2.789065601 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
97 2.998736571 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
101 3.005046187 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
102 3.011025634 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
105 3.255120658 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
109 3.262979723 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
110 3.270638348 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
113 3.518145868 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
118 3.536880998 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
119 3.541489068 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
123 3.776536632 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
124 3.777268092 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
125 3.784200653 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
128 3.995220129 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
129 3.995907203 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
131 4.006264635 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
135 4.215292054 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
136 4.216018889 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
137 4.222906817 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
141 4.430858169 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
142 4.431619137 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
143 4.439186831 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
147 4.647960736 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
148 4.648753903 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
149 4.654062259 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
153 4.861696359 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
158 4.881874024 192.168.0.20 → 192.168.0.27 NetPerfMeter 276 SACK NetPerfMeter Add Flow
159 4.886932549 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
163 5.095411239 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
184 5.101147570 192.168.0.20 → 192.168.0.27 NetPerfMeter 96 SACK NetPerfMeter Start Measurement
227 5.315482367 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
2084 15.615367349 192.168.0.20 → 192.168.0.27 NetPerfMeter 80 NetPerfMeter Stop Measurement
2086 16.091680420 192.168.0.27 → 192.168.0.20 NetPerfMeter 88 NetPerfMeter Acknowledge
2087 16.092542043 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2088 16.092542469 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2089 16.092542579 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2090 16.092542691 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2093 16.098744445 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2095 16.099492702 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2096 16.099493075 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2097 16.099493204 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2098 16.099493337 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2101 16.108240278 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2102 16.109665125 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2103 16.109665219 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2104 16.109665258 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2105 16.109665298 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2106 16.109665335 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2107 16.109665374 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2108 16.109665413 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2109 16.109665451 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2114 16.115534573 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2116 16.117085522 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2117 16.117085740 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2118 16.117085774 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2119 16.117085808 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2120 16.117085841 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2121 16.117085874 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2122 16.117085906 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2123 16.117085940 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2125 16.117208639 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2129 16.117847682 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2131 16.120936939 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2132 16.121564917 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2134 16.124001266 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2135 16.126359615 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2136 16.126359784 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2137 16.126359829 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2138 16.126359875 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2139 16.126359923 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2140 16.126359972 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2141 16.126360016 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2142 16.126360065 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2144 16.126516782 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2145 16.126516838 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2150 16.126568776 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2151 16.126568857 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2152 16.126568903 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2153 16.126568947 192.168.0.27 → 192.168.0.20 NetPerfMeter 1088 NetPerfMeter Results
2154 16.126568990 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2155 16.126569037 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2156 16.126569084 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2162 16.128296076 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2163 16.128991998 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2164 16.128992266 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2166 16.132186659 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2168 16.133696852 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2169 16.133697204 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2170 16.133697304 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2171 16.133697400 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2172 16.133697505 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2175 16.136109923 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2177 16.138000289 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2178 16.138000795 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2179 16.138000952 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2180 16.138001087 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2181 16.138001222 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2182 16.138001355 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2183 16.138001497 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2184 16.138001654 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2189 16.138407582 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2190 16.138407852 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2191 16.138407948 192.168.0.27 → 192.168.0.20 NetPerfMeter 1360 NetPerfMeter Results
2193 16.138949169 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2194 16.147965640 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2195 16.149160472 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2197 16.149694877 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2199 16.359112863 192.168.0.27 → 192.168.0.20 NetPerfMeter 400 NetPerfMeter Results
2200 16.360439472 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2201 16.367838301 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2202 16.369999711 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2204 16.370249698 192.168.0.27 → 192.168.0.20 NetPerfMeter 252 NetPerfMeter Results
2205 16.371333521 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2206 16.377931209 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2207 16.379416052 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2209 16.379921676 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2211 16.586758032 192.168.0.27 → 192.168.0.20 NetPerfMeter 460 NetPerfMeter Results
2212 16.588004878 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2213 16.596287178 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2214 16.600862615 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2216 16.601572074 192.168.0.27 → 192.168.0.20 NetPerfMeter 256 NetPerfMeter Results
2217 16.602770488 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2218 16.608528578 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2219 16.610851595 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2221 16.611228721 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2224 16.820428495 192.168.0.27 → 192.168.0.20 NetPerfMeter 368 NetPerfMeter Results
2226 16.821725312 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2227 16.829665670 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2228 16.831477557 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2230 16.831711400 192.168.0.27 → 192.168.0.20 NetPerfMeter 276 NetPerfMeter Results
2233 16.832859448 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2235 16.838963861 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2236 16.839917250 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2238 16.841055807 192.168.0.27 → 192.168.0.20 NetPerfMeter 236 NetPerfMeter Results
2241 16.842312060 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2243 16.847748197 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2244 16.848933463 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2246 16.849525492 192.168.0.27 → 192.168.0.20 NetPerfMeter 236 NetPerfMeter Results
2249 16.850661714 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2251 16.857615760 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2252 16.859140443 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2254 16.859653107 192.168.0.27 → 192.168.0.20 NetPerfMeter 976 NetPerfMeter Results
2257 16.860923512 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2259 16.866293943 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2260 16.867822941 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2262 16.868668201 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2265 17.079265007 192.168.0.27 → 192.168.0.20 NetPerfMeter 368 NetPerfMeter Results
2267 17.080555093 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2268 17.089928582 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2269 17.091479195 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2271 17.092073003 192.168.0.27 → 192.168.0.20 NetPerfMeter 272 NetPerfMeter Results
2274 17.093044526 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2276 17.099098185 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2277 17.100201203 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2279 17.100852674 192.168.0.27 → 192.168.0.20 NetPerfMeter 244 NetPerfMeter Results
2282 17.101916382 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2284 17.109026614 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2285 17.112907819 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2287 17.115302865 192.168.0.27 → 192.168.0.20 NetPerfMeter 244 NetPerfMeter Results
2290 17.116443045 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2292 17.122058351 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2293 17.125840461 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2295 17.126459769 192.168.0.27 → 192.168.0.20 NetPerfMeter 976 NetPerfMeter Results
2297 17.126760188 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2300 17.132579296 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2301 17.133301477 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2302 17.133302153 192.168.0.27 → 192.168.0.20 NetPerfMeter 284 NetPerfMeter Results
2304 17.133706810 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2305 17.138731552 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2306 17.139818471 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2308 17.140335127 192.168.0.27 → 192.168.0.20 NetPerfMeter 288 NetPerfMeter Results
2309 17.140830809 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2310 17.145622016 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2311 17.147059541 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2313 17.148571671 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2314 17.149475099 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2316 17.150223037 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2318 17.359940788 192.168.0.27 → 192.168.0.20 NetPerfMeter 740 NetPerfMeter Results
2319 17.361102522 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2320 17.368203507 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2321 17.370823736 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2323 17.371236232 192.168.0.27 → 192.168.0.20 NetPerfMeter 280 NetPerfMeter Results
2324 17.372205596 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2325 17.378113171 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2326 17.379408121 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2328 17.379940226 192.168.0.27 → 192.168.0.20 NetPerfMeter 284 NetPerfMeter Results
2329 17.380772832 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2330 17.389000119 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2331 17.389893116 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2332 17.389893325 192.168.0.27 → 192.168.0.20 NetPerfMeter 380 NetPerfMeter Results
2334 17.390667295 192.168.0.20 → 192.168.0.27 NetPerfMeter 100 SACK NetPerfMeter Remove Flow
2335 17.395701306 192.168.0.27 → 192.168.0.20 NetPerfMeter 104 SACK NetPerfMeter Acknowledge
2336 17.397791412 192.168.0.27 → 192.168.0.20 NetPerfMeter 1468 NetPerfMeter Results
2338 17.398332887 192.168.0.27 → 192.168.0.20 NetPerfMeter 284 NetPerfMeter Results
""".replace("\r\n", "\n"),
            result)

    def test_netperfmeter_test_udp(self, cmd_tshark, capture_file):
        '''Checks whether the NetPerfMeter dissector correctly handles NetPerfMeter Data via UDP.'''

        # Test: Identify and decode NetPerfMeter Data via UDP
        proc = self.assertRun((cmd_tshark,
                                '-r', capture_file('netperfmeter.pcapng.gz'),
                                '-Y', 'frame.number >= 1 && frame.number <= 512 && udp && netperfmeter'
                                ))

        result = ''.join([x.strip()+"\n" for x in proc.stdout_str.splitlines()])
        # print(proc.stdout_str)
        self.assertIn("""\
26 0.556893098 192.168.0.20 → 192.168.0.27 NetPerfMeter 70 NetPerfMeter Identify Flow
31 0.778199411 192.168.0.20 → 192.168.0.27 NetPerfMeter 70 NetPerfMeter Identify Flow
166 5.097058561 192.168.0.20 → 192.168.0.27 NetPerfMeter 1068 NetPerfMeter Data
167 5.097156368 192.168.0.20 → 192.168.0.27 NetPerfMeter 556 NetPerfMeter Data
203 5.188581678 192.168.0.27 → 192.168.0.20 NetPerfMeter 1068 NetPerfMeter Data
204 5.198869201 192.168.0.27 → 192.168.0.20 NetPerfMeter 556 NetPerfMeter Data
229 5.347412858 192.168.0.20 → 192.168.0.27 NetPerfMeter 1068 NetPerfMeter Data
248 5.521667162 192.168.0.27 → 192.168.0.20 NetPerfMeter 1068 NetPerfMeter Data
249 5.529727434 192.168.0.27 → 192.168.0.20 NetPerfMeter 556 NetPerfMeter Data
251 5.597939044 192.168.0.20 → 192.168.0.27 NetPerfMeter 1068 NetPerfMeter Data
252 5.597979296 192.168.0.20 → 192.168.0.27 NetPerfMeter 556 NetPerfMeter Data
315 5.848599107 192.168.0.20 → 192.168.0.27 NetPerfMeter 1068 NetPerfMeter Data
326 5.869626418 192.168.0.27 → 192.168.0.20 NetPerfMeter 1068 NetPerfMeter Data
327 5.870477253 192.168.0.27 → 192.168.0.20 NetPerfMeter 556 NetPerfMeter Data
336 6.099006262 192.168.0.20 → 192.168.0.27 NetPerfMeter 1068 NetPerfMeter Data
337 6.099035694 192.168.0.20 → 192.168.0.27 NetPerfMeter 556 NetPerfMeter Data
374 6.239221234 192.168.0.27 → 192.168.0.20 NetPerfMeter 1068 NetPerfMeter Data
375 6.240243736 192.168.0.27 → 192.168.0.20 NetPerfMeter 556 NetPerfMeter Data
406 6.349592731 192.168.0.20 → 192.168.0.27 NetPerfMeter 1068 NetPerfMeter Data
429 6.538916191 192.168.0.27 → 192.168.0.20 NetPerfMeter 1068 NetPerfMeter Data
430 6.540208385 192.168.0.27 → 192.168.0.20 NetPerfMeter 556 NetPerfMeter Data
438 6.600112279 192.168.0.20 → 192.168.0.27 NetPerfMeter 556 NetPerfMeter Data
439 6.600127896 192.168.0.20 → 192.168.0.27 NetPerfMeter 1068 NetPerfMeter Data
499 6.850796522 192.168.0.20 → 192.168.0.27 NetPerfMeter 1068 NetPerfMeter Data
509 6.874579699 192.168.0.27 → 192.168.0.20 NetPerfMeter 1068 NetPerfMeter Data
510 6.875289205 192.168.0.27 → 192.168.0.20 NetPerfMeter 556 NetPerfMeter Data
""".replace("\r\n", "\n"),
            result)

    def test_netperfmeter_test_dccp(self, cmd_tshark, capture_file):
        '''Checks whether the NetPerfMeter dissector correctly handles NetPerfMeter Data via DCCP.'''

        # Test: Identify and decode NetPerfMeter Data via DCCP
        proc = self.assertRun((cmd_tshark,
                                '-r', capture_file('netperfmeter.pcapng.gz'),
                                '-Y', 'frame.number >= 1 && frame.number <= 256 && dccp && netperfmeter'
                                ))

        result = ''.join([x.strip()+"\n" for x in proc.stdout_str.splitlines()])
        # print(proc.stdout_str)
        self.assertIn("""\
39 1.000448305 192.168.0.20 → 192.168.0.27 NetPerfMeter 106 NetPerfMeter Identify Flow
47 1.257376250 192.168.0.20 → 192.168.0.27 NetPerfMeter 106 NetPerfMeter Identify Flow
55 1.518626642 192.168.0.20 → 192.168.0.27 NetPerfMeter 106 NetPerfMeter Identify Flow
63 1.776552210 192.168.0.20 → 192.168.0.27 NetPerfMeter 106 NetPerfMeter Identify Flow
71 2.013038051 192.168.0.20 → 192.168.0.27 NetPerfMeter 106 NetPerfMeter Identify Flow
79 2.268029558 192.168.0.20 → 192.168.0.27 NetPerfMeter 106 NetPerfMeter Identify Flow
87 2.526765502 192.168.0.20 → 192.168.0.27 NetPerfMeter 106 NetPerfMeter Identify Flow
95 2.789401573 192.168.0.20 → 192.168.0.27 NetPerfMeter 106 NetPerfMeter Identify Flow
103 3.011188128 192.168.0.20 → 192.168.0.27 NetPerfMeter 106 NetPerfMeter Identify Flow
111 3.270945041 192.168.0.20 → 192.168.0.27 NetPerfMeter 106 NetPerfMeter Identify Flow
168 5.097388740 192.168.0.20 → 192.168.0.27 NetPerfMeter 1112 NetPerfMeter Data
169 5.097563303 192.168.0.20 → 192.168.0.27 NetPerfMeter 1112 NetPerfMeter Data
170 5.097680252 192.168.0.20 → 192.168.0.27 NetPerfMeter 600 NetPerfMeter Data
171 5.097804675 192.168.0.20 → 192.168.0.27 NetPerfMeter 600 NetPerfMeter Data
172 5.097860862 192.168.0.20 → 192.168.0.27 NetPerfMeter 336 NetPerfMeter Data
173 5.097960425 192.168.0.20 → 192.168.0.27 NetPerfMeter 1104 NetPerfMeter Data
174 5.098168605 192.168.0.20 → 192.168.0.27 NetPerfMeter 1104 NetPerfMeter Data
175 5.098268064 192.168.0.20 → 192.168.0.27 NetPerfMeter 592 NetPerfMeter Data
176 5.098379939 192.168.0.20 → 192.168.0.27 NetPerfMeter 592 NetPerfMeter Data
177 5.098474409 192.168.0.20 → 192.168.0.27 NetPerfMeter 336 NetPerfMeter Data
205 5.203489906 192.168.0.27 → 192.168.0.20 NetPerfMeter 1088 NetPerfMeter Data
206 5.208120579 192.168.0.27 → 192.168.0.20 NetPerfMeter 1088 NetPerfMeter Data
207 5.211621270 192.168.0.27 → 192.168.0.20 NetPerfMeter 576 NetPerfMeter Data
208 5.216629302 192.168.0.27 → 192.168.0.20 NetPerfMeter 576 NetPerfMeter Data
209 5.218637208 192.168.0.27 → 192.168.0.20 NetPerfMeter 320 NetPerfMeter Data
210 5.220923234 192.168.0.27 → 192.168.0.20 NetPerfMeter 1088 NetPerfMeter Data
211 5.224470647 192.168.0.27 → 192.168.0.20 NetPerfMeter 1088 NetPerfMeter Data
212 5.228633904 192.168.0.27 → 192.168.0.20 NetPerfMeter 576 NetPerfMeter Data
213 5.235096316 192.168.0.27 → 192.168.0.20 NetPerfMeter 576 NetPerfMeter Data
214 5.235387030 192.168.0.27 → 192.168.0.20 NetPerfMeter 320 NetPerfMeter Data
230 5.347723929 192.168.0.20 → 192.168.0.27 NetPerfMeter 1088 NetPerfMeter Data
231 5.348299245 192.168.0.20 → 192.168.0.27 NetPerfMeter 1088 NetPerfMeter Data
236 5.432621676 192.168.0.20 → 192.168.0.27 NetPerfMeter 320 NetPerfMeter Data
237 5.433090508 192.168.0.20 → 192.168.0.27 NetPerfMeter 320 NetPerfMeter Data
238 5.458215001 192.168.0.27 → 192.168.0.20 NetPerfMeter 1104 NetPerfMeter Data
240 5.472252869 192.168.0.27 → 192.168.0.20 NetPerfMeter 1104 NetPerfMeter Data
250 5.597889485 192.168.0.20 → 192.168.0.27 NetPerfMeter 1096 NetPerfMeter Data
255 5.598126766 192.168.0.20 → 192.168.0.27 NetPerfMeter 1088 NetPerfMeter Data
256 5.598378615 192.168.0.20 → 192.168.0.27 NetPerfMeter 576 NetPerfMeter Data
""".replace("\r\n", "\n"),
            result)

    def test_netperfmeter_test_tcp(self, cmd_tshark, capture_file):
        '''Checks whether the NetPerfMeter dissector correctly handles NetPerfMeter Data via TCP.'''

        # Test: Identify and decode NetPerfMeter Data via TCP
        proc = self.assertRun((cmd_tshark,
                                '-r', capture_file('netperfmeter.pcapng.gz'),
                                '-Y', 'frame.number >= 1 && frame.number <= 512 && tcp && netperfmeter'
                                ))

        result = ''.join([x.strip()+"\n" for x in proc.stdout_str.splitlines()])
        self.assertIn("""\
12 0.038833197 192.168.0.20 → 192.168.0.27 NetPerfMeter 94 NetPerfMeter Identify Flow
20 0.340423798 192.168.0.20 → 192.168.0.27 NetPerfMeter 94 NetPerfMeter Identify Flow
164 5.096822593 192.168.0.20 → 192.168.0.27 NetPerfMeter 1092 NetPerfMeter Data
165 5.096933125 192.168.0.20 → 192.168.0.27 NetPerfMeter 580 NetPerfMeter Data
199 5.180197902 192.168.0.27 → 192.168.0.20 NetPerfMeter 1092 NetPerfMeter Data
201 5.183618768 192.168.0.27 → 192.168.0.20 NetPerfMeter 580 NetPerfMeter Data
228 5.347212980 192.168.0.20 → 192.168.0.27 NetPerfMeter 1092 NetPerfMeter Data
243 5.510843364 192.168.0.27 → 192.168.0.20 NetPerfMeter 1092 NetPerfMeter Data
246 5.518285725 192.168.0.27 → 192.168.0.20 NetPerfMeter 580 NetPerfMeter Data
253 5.598004664 192.168.0.20 → 192.168.0.27 NetPerfMeter 580 NetPerfMeter Data
254 5.598037007 192.168.0.20 → 192.168.0.27 NetPerfMeter 1092 NetPerfMeter Data
313 5.843608886 192.168.0.27 → 192.168.0.20 NetPerfMeter 1092 NetPerfMeter Data
316 5.848649435 192.168.0.20 → 192.168.0.27 NetPerfMeter 1092 NetPerfMeter Data
320 5.852294838 192.168.0.27 → 192.168.0.20 NetPerfMeter 580 NetPerfMeter Data
335 6.098962324 192.168.0.20 → 192.168.0.27 NetPerfMeter 580 NetPerfMeter Data
342 6.099194942 192.168.0.20 → 192.168.0.27 NetPerfMeter 1092 NetPerfMeter Data
370 6.178557080 192.168.0.27 → 192.168.0.20 NetPerfMeter 1092 NetPerfMeter Data
372 6.186668259 192.168.0.27 → 192.168.0.20 NetPerfMeter 580 NetPerfMeter Data
408 6.349677977 192.168.0.20 → 192.168.0.27 NetPerfMeter 1092 NetPerfMeter Data
425 6.512522597 192.168.0.27 → 192.168.0.20 NetPerfMeter 1092 NetPerfMeter Data
427 6.521373219 192.168.0.27 → 192.168.0.20 NetPerfMeter 580 NetPerfMeter Data
436 6.600056667 192.168.0.20 → 192.168.0.27 NetPerfMeter 580 NetPerfMeter Data
441 6.600170332 192.168.0.20 → 192.168.0.27 NetPerfMeter 1092 NetPerfMeter Data
497 6.846781911 192.168.0.27 → 192.168.0.20 NetPerfMeter 1092 NetPerfMeter Data
502 6.850917051 192.168.0.20 → 192.168.0.27 NetPerfMeter 1092 NetPerfMeter Data
507 6.857231771 192.168.0.27 → 192.168.0.20 NetPerfMeter 580 NetPerfMeter Data
""".replace("\r\n", "\n"),
            result)

    def test_netperfmeter_test_sctp(self, cmd_tshark, capture_file):
        '''Checks whether the NetPerfMeter dissector correctly handles NetPerfMeter Data via SCTP.'''

        # Test: Identify and decode NetPerfMeter Data via SCTP
        proc = self.assertRun((cmd_tshark,
                                '-r', capture_file('netperfmeter.pcapng.gz'),
                                '-Y', 'frame.number >= 1 && frame.number <= 256 && sctp && netperfmeter && ((netperfmeter.message_type == 5) || (netperfmeter.message_type == 4))'
                                ))

        result = ''.join([x.strip()+"\n" for x in proc.stdout_str.splitlines()])
        # print(proc.stdout_str)
        self.assertIn("""\
120 3.541753666 192.168.0.20 → 192.168.0.27 NetPerfMeter 92 NetPerfMeter Identify Flow
126 3.784578040 192.168.0.20 → 192.168.0.27 NetPerfMeter 92 NetPerfMeter Identify Flow
132 4.006622016 192.168.0.20 → 192.168.0.27 NetPerfMeter 92 NetPerfMeter Identify Flow
138 4.223204664 192.168.0.20 → 192.168.0.27 NetPerfMeter 92 NetPerfMeter Identify Flow
144 4.439513544 192.168.0.20 → 192.168.0.27 NetPerfMeter 92 NetPerfMeter Identify Flow
150 4.654398275 192.168.0.20 → 192.168.0.27 NetPerfMeter 92 NetPerfMeter Identify Flow
160 4.887196553 192.168.0.20 → 192.168.0.27 NetPerfMeter 92 NetPerfMeter Identify Flow
178 5.098706269 192.168.0.20 → 192.168.0.27 NetPerfMeter 1088 NetPerfMeter Data
180 5.098939899 192.168.0.20 → 192.168.0.27 NetPerfMeter 660 NetPerfMeter Data
181 5.099244178 192.168.0.20 → 192.168.0.27 NetPerfMeter 1232 NetPerfMeter Data NetPerfMeter Data
182 5.099428646 192.168.0.20 → 192.168.0.27 NetPerfMeter 1088 NetPerfMeter Data
183 5.099642887 192.168.0.20 → 192.168.0.27 NetPerfMeter 1088 NetPerfMeter Data
215 5.242589734 192.168.0.27 → 192.168.0.20 NetPerfMeter 1104 SACK NetPerfMeter Data
216 5.242748399 192.168.0.20 → 192.168.0.27 NetPerfMeter 1248 SACK NetPerfMeter Data NetPerfMeter Data
218 5.247412901 192.168.0.27 → 192.168.0.20 NetPerfMeter 680 NetPerfMeter Data
220 5.252114400 192.168.0.27 → 192.168.0.20 NetPerfMeter 208 SACK NetPerfMeter Data
221 5.266387026 192.168.0.27 → 192.168.0.20 NetPerfMeter 1088 NetPerfMeter Data
223 5.266637245 192.168.0.27 → 192.168.0.20 NetPerfMeter 1088 NetPerfMeter Data
224 5.273527654 192.168.0.27 → 192.168.0.20 NetPerfMeter 1104 SACK NetPerfMeter Data
232 5.349726358 192.168.0.20 → 192.168.0.27 NetPerfMeter 208 SACK NetPerfMeter Data
235 5.355361743 192.168.0.27 → 192.168.0.20 NetPerfMeter 1104 SACK NetPerfMeter Data
242 5.475302128 192.168.0.20 → 192.168.0.27 NetPerfMeter 208 SACK NetPerfMeter Data
""".replace("\r\n", "\n"),
            result)
