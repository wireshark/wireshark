#!/usr/bin/env python3
# Generates test/captures/zbee-zcl-ha_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Coverage capture generator for packet-zbee-zcl-ha.c (ZigBee ZCL ha clusters)
# Synthetic ZigBee frames, generated with struct only: 802.15.4 (linktype
# 230, no FCS) -> ZigBee NWK -> APS (HA profile) -> ZCL, reached through
# the default zbee_nwk heuristic.  Addresses are made up.
#   usage: mkzbee-zcl-ha.py <outdir>
# writes zbee-zcl-ha-coverage.pcap, zbee-zcl-ha-coverage-malformed.pcap and
# zbee-zcl-ha_coverage.pcap.gz
import struct
import sys
import os
import gzip

# cluster id -> (name, attributes, cluster-specific commands)
#   attribute entries: (attr id, data type, data length, fill) ; the data
#   is zeros, a 1..n ramp or 0xff bytes (strings carry the length byte)
#   command entries:   (command id, FCF direction bit, fill, payload length)
CLUSTERS = {2816: ('appliance_identification',
        [(0, 226, 7, 'ramp'), (0, 62, 7, 'ramp'), (0, 226, 7, 'zero'), (0, 226, 7, 'ff'),
         (0, 226, 7, 'sgn'), (0, 226, 7, 'max'), (0, 62, 7, 'zero'), (0, 62, 7, 'ff'),
         (0, 62, 7, 'sgn'), (0, 62, 7, 'max'), (16, 32, 1, 'ramp'), (16, 33, 2, 'ramp'),
         (16, 32, 1, 'zero'), (16, 32, 1, 'ff'), (16, 32, 1, 'sgn'), (16, 32, 1, 'max'),
         (16, 33, 2, 'zero'), (16, 33, 2, 'ff'), (16, 33, 2, 'sgn'), (16, 33, 2, 'max'),
         (17, 33, 2, 'ramp'), (17, 25, 2, 'ramp'), (17, 33, 2, 'zero'), (17, 33, 2, 'ff'),
         (17, 33, 2, 'sgn'), (17, 33, 2, 'max'), (17, 25, 2, 'zero'), (17, 25, 2, 'ff'),
         (17, 25, 2, 'sgn'), (17, 25, 2, 'max'), (18, 32, 1, 'ramp'), (18, 33, 2, 'ramp'),
         (18, 32, 1, 'zero'), (18, 32, 1, 'ff'), (18, 32, 1, 'sgn'), (18, 32, 1, 'max'),
         (18, 33, 2, 'zero'), (18, 33, 2, 'ff'), (18, 33, 2, 'sgn'), (18, 33, 2, 'max'),
         (19, 33, 2, 'ramp'), (19, 25, 2, 'ramp'), (19, 33, 2, 'zero'), (19, 33, 2, 'ff'),
         (19, 33, 2, 'sgn'), (19, 33, 2, 'max'), (19, 25, 2, 'zero'), (19, 25, 2, 'ff'),
         (19, 25, 2, 'sgn'), (19, 25, 2, 'max'), (20, 32, 1, 'ramp'), (20, 33, 2, 'ramp'),
         (20, 32, 1, 'zero'), (20, 32, 1, 'ff'), (20, 32, 1, 'sgn'), (20, 32, 1, 'max'),
         (20, 33, 2, 'zero'), (20, 33, 2, 'ff'), (20, 33, 2, 'sgn'), (20, 33, 2, 'max'),
         (21, 32, 1, 'ramp'), (21, 33, 2, 'ramp'), (21, 32, 1, 'zero'), (21, 32, 1, 'ff'),
         (21, 32, 1, 'sgn'), (21, 32, 1, 'max'), (21, 33, 2, 'zero'), (21, 33, 2, 'ff'),
         (21, 33, 2, 'sgn'), (21, 33, 2, 'max'), (22, 32, 1, 'ramp'), (22, 33, 2, 'ramp'),
         (22, 32, 1, 'zero'), (22, 32, 1, 'ff'), (22, 32, 1, 'sgn'), (22, 32, 1, 'max'),
         (22, 33, 2, 'zero'), (22, 33, 2, 'ff'), (22, 33, 2, 'sgn'), (22, 33, 2, 'max'),
         (23, 32, 1, 'ramp'), (23, 33, 2, 'ramp'), (23, 32, 1, 'zero'), (23, 32, 1, 'ff'),
         (23, 32, 1, 'sgn'), (23, 32, 1, 'max'), (23, 33, 2, 'zero'), (23, 33, 2, 'ff'),
         (23, 33, 2, 'sgn'), (23, 33, 2, 'max'), (24, 34, 3, 'ramp'), (24, 226, 3, 'ramp'),
         (24, 34, 3, 'zero'), (24, 34, 3, 'ff'), (24, 34, 3, 'sgn'), (24, 34, 3, 'max'),
         (24, 226, 3, 'zero'), (24, 226, 3, 'ff'), (24, 226, 3, 'sgn'), (24, 226, 3, 'max'),
         (25, 33, 2, 'ramp'), (25, 25, 2, 'ramp'), (25, 33, 2, 'zero'), (25, 33, 2, 'ff'),
         (25, 33, 2, 'sgn'), (25, 33, 2, 'max'), (25, 25, 2, 'zero'), (25, 25, 2, 'ff'),
         (25, 25, 2, 'sgn'), (25, 25, 2, 'max'), (26, 32, 1, 'ramp'), (26, 48, 1, 'ramp'),
         (26, 32, 1, 'zero'), (26, 32, 1, 'ff'), (26, 32, 1, 'sgn'), (26, 32, 1, 'max'),
         (26, 48, 1, 'zero'), (26, 48, 1, 'ff'), (26, 48, 1, 'sgn'), (26, 48, 1, 'max')],
        []),
 2817: ('meter_identification',
        [(0, 32, 1, 'ramp'), (0, 33, 2, 'ramp'), (0, 32, 1, 'zero'), (0, 32, 1, 'ff'),
         (0, 32, 1, 'sgn'), (0, 32, 1, 'max'), (0, 33, 2, 'zero'), (0, 33, 2, 'ff'),
         (0, 33, 2, 'sgn'), (0, 33, 2, 'max'), (1, 33, 2, 'ramp'), (1, 25, 2, 'ramp'),
         (1, 33, 2, 'zero'), (1, 33, 2, 'ff'), (1, 33, 2, 'sgn'), (1, 33, 2, 'max'),
         (1, 25, 2, 'zero'), (1, 25, 2, 'ff'), (1, 25, 2, 'sgn'), (1, 25, 2, 'max'),
         (4, 33, 2, 'ramp'), (4, 25, 2, 'ramp'), (4, 33, 2, 'zero'), (4, 33, 2, 'ff'),
         (4, 33, 2, 'sgn'), (4, 33, 2, 'max'), (4, 25, 2, 'zero'), (4, 25, 2, 'ff'),
         (4, 25, 2, 'sgn'), (4, 25, 2, 'max'), (5, 32, 1, 'ramp'), (5, 33, 2, 'ramp'),
         (5, 32, 1, 'zero'), (5, 32, 1, 'ff'), (5, 32, 1, 'sgn'), (5, 32, 1, 'max'),
         (5, 33, 2, 'zero'), (5, 33, 2, 'ff'), (5, 33, 2, 'sgn'), (5, 33, 2, 'max'),
         (6, 32, 1, 'ramp'), (6, 33, 2, 'ramp'), (6, 32, 1, 'zero'), (6, 32, 1, 'ff'),
         (6, 32, 1, 'sgn'), (6, 32, 1, 'max'), (6, 33, 2, 'zero'), (6, 33, 2, 'ff'),
         (6, 33, 2, 'sgn'), (6, 33, 2, 'max'), (7, 32, 1, 'ramp'), (7, 33, 2, 'ramp'),
         (7, 32, 1, 'zero'), (7, 32, 1, 'ff'), (7, 32, 1, 'sgn'), (7, 32, 1, 'max'),
         (7, 33, 2, 'zero'), (7, 33, 2, 'ff'), (7, 33, 2, 'sgn'), (7, 33, 2, 'max'),
         (8, 32, 1, 'ramp'), (8, 33, 2, 'ramp'), (8, 32, 1, 'zero'), (8, 32, 1, 'ff'),
         (8, 32, 1, 'sgn'), (8, 32, 1, 'max'), (8, 33, 2, 'zero'), (8, 33, 2, 'ff'),
         (8, 33, 2, 'sgn'), (8, 33, 2, 'max'), (10, 32, 1, 'ramp'), (10, 33, 2, 'ramp'),
         (10, 32, 1, 'zero'), (10, 32, 1, 'ff'), (10, 32, 1, 'sgn'), (10, 32, 1, 'max'),
         (10, 33, 2, 'zero'), (10, 33, 2, 'ff'), (10, 33, 2, 'sgn'), (10, 33, 2, 'max'),
         (11, 32, 1, 'ramp'), (11, 33, 2, 'ramp'), (11, 32, 1, 'zero'), (11, 32, 1, 'ff'),
         (11, 32, 1, 'sgn'), (11, 32, 1, 'max'), (11, 33, 2, 'zero'), (11, 33, 2, 'ff'),
         (11, 33, 2, 'sgn'), (11, 33, 2, 'max'), (12, 32, 1, 'ramp'), (12, 33, 2, 'ramp'),
         (12, 32, 1, 'zero'), (12, 32, 1, 'ff'), (12, 32, 1, 'sgn'), (12, 32, 1, 'max'),
         (12, 33, 2, 'zero'), (12, 33, 2, 'ff'), (12, 33, 2, 'sgn'), (12, 33, 2, 'max'),
         (13, 32, 1, 'ramp'), (13, 33, 2, 'ramp'), (13, 32, 1, 'zero'), (13, 32, 1, 'ff'),
         (13, 32, 1, 'sgn'), (13, 32, 1, 'max'), (13, 33, 2, 'zero'), (13, 33, 2, 'ff'),
         (13, 33, 2, 'sgn'), (13, 33, 2, 'max'), (14, 32, 1, 'ramp'), (14, 33, 2, 'ramp'),
         (14, 32, 1, 'zero'), (14, 32, 1, 'ff'), (14, 32, 1, 'sgn'), (14, 32, 1, 'max'),
         (14, 33, 2, 'zero'), (14, 33, 2, 'ff'), (14, 33, 2, 'sgn'), (14, 33, 2, 'max')],
        []),
 2818: ('appliance_events_and_alert', [],
        [(0, 0, 'ramp', 0), (0, 0, 'ramp', 40), (0, 0, 'zero', 0), (0, 0, 'zero', 40),
         (0, 1, 'ramp', 0), (0, 1, 'ramp', 40), (0, 1, 'zero', 0), (0, 1, 'zero', 40),
         (1, 0, 'ramp', 0), (1, 0, 'ramp', 40), (1, 0, 'zero', 0), (1, 0, 'zero', 40),
         (1, 1, 'ramp', 0), (1, 1, 'ramp', 40), (1, 1, 'zero', 0), (1, 1, 'zero', 40),
         (2, 0, 'ramp', 0), (2, 0, 'ramp', 40), (2, 0, 'zero', 0), (2, 0, 'zero', 40),
         (2, 1, 'ramp', 0), (2, 1, 'ramp', 40), (2, 1, 'zero', 0), (2, 1, 'zero', 40),
         (3, 0, 'ramp', 0), (3, 0, 'ramp', 40), (3, 0, 'zero', 0), (3, 0, 'zero', 40),
         (3, 1, 'ramp', 0), (3, 1, 'ramp', 40), (3, 1, 'zero', 0), (3, 1, 'zero', 40)]),
 2819: ('appliance_statistics',
        [(0, 32, 1, 'ramp'), (0, 33, 2, 'ramp'), (0, 32, 1, 'zero'), (0, 32, 1, 'ff'),
         (0, 32, 1, 'sgn'), (0, 32, 1, 'max'), (0, 33, 2, 'zero'), (0, 33, 2, 'ff'),
         (0, 33, 2, 'sgn'), (0, 33, 2, 'max'), (1, 32, 1, 'ramp'), (1, 33, 2, 'ramp'),
         (1, 32, 1, 'zero'), (1, 32, 1, 'ff'), (1, 32, 1, 'sgn'), (1, 32, 1, 'max'),
         (1, 33, 2, 'zero'), (1, 33, 2, 'ff'), (1, 33, 2, 'sgn'), (1, 33, 2, 'max')],
        [(0, 0, 'ramp', 0), (0, 0, 'ramp', 40), (0, 0, 'zero', 0), (0, 0, 'zero', 40),
         (0, 1, 'ramp', 0), (0, 1, 'zero', 0), (0, 1, 'zero', 40), (1, 0, 'ramp', 0),
         (1, 0, 'ramp', 40), (1, 0, 'zero', 0), (1, 0, 'zero', 40), (1, 1, 'ramp', 0),
         (1, 1, 'zero', 0), (1, 1, 'zero', 40), (2, 0, 'ramp', 0), (2, 0, 'ramp', 40),
         (2, 0, 'zero', 0), (2, 0, 'zero', 40), (2, 1, 'ramp', 0), (2, 1, 'ramp', 39),
         (2, 1, 'zero', 0), (2, 1, 'zero', 39), (3, 0, 'ramp', 0), (3, 0, 'ramp', 40),
         (3, 0, 'zero', 0), (3, 0, 'zero', 40), (3, 1, 'ramp', 0), (3, 1, 'ramp', 39),
         (3, 1, 'zero', 0), (3, 1, 'zero', 39)]),
 2821: ('diagnostics',
        [(0, 32, 1, 'ramp'), (0, 33, 2, 'ramp'), (0, 32, 1, 'zero'), (0, 32, 1, 'ff'),
         (0, 32, 1, 'sgn'), (0, 32, 1, 'max'), (0, 33, 2, 'zero'), (0, 33, 2, 'ff'),
         (0, 33, 2, 'sgn'), (0, 33, 2, 'max'), (1, 32, 1, 'ramp'), (1, 33, 2, 'ramp'),
         (1, 32, 1, 'zero'), (1, 32, 1, 'ff'), (1, 32, 1, 'sgn'), (1, 32, 1, 'max'),
         (1, 33, 2, 'zero'), (1, 33, 2, 'ff'), (1, 33, 2, 'sgn'), (1, 33, 2, 'max'),
         (256, 32, 1, 'ramp'), (256, 33, 2, 'ramp'), (256, 32, 1, 'zero'), (256, 32, 1, 'ff'),
         (256, 32, 1, 'sgn'), (256, 32, 1, 'max'), (256, 33, 2, 'zero'), (256, 33, 2, 'ff'),
         (256, 33, 2, 'sgn'), (256, 33, 2, 'max'), (257, 32, 1, 'ramp'), (257, 33, 2, 'ramp'),
         (257, 32, 1, 'zero'), (257, 32, 1, 'ff'), (257, 32, 1, 'sgn'), (257, 32, 1, 'max'),
         (257, 33, 2, 'zero'), (257, 33, 2, 'ff'), (257, 33, 2, 'sgn'), (257, 33, 2, 'max'),
         (258, 32, 1, 'ramp'), (258, 33, 2, 'ramp'), (258, 32, 1, 'zero'), (258, 32, 1, 'ff'),
         (258, 32, 1, 'sgn'), (258, 32, 1, 'max'), (258, 33, 2, 'zero'), (258, 33, 2, 'ff'),
         (258, 33, 2, 'sgn'), (258, 33, 2, 'max'), (259, 32, 1, 'ramp'), (259, 33, 2, 'ramp'),
         (259, 32, 1, 'zero'), (259, 32, 1, 'ff'), (259, 32, 1, 'sgn'), (259, 32, 1, 'max'),
         (259, 33, 2, 'zero'), (259, 33, 2, 'ff'), (259, 33, 2, 'sgn'), (259, 33, 2, 'max'),
         (260, 32, 1, 'ramp'), (260, 33, 2, 'ramp'), (260, 32, 1, 'zero'), (260, 32, 1, 'ff'),
         (260, 32, 1, 'sgn'), (260, 32, 1, 'max'), (260, 33, 2, 'zero'), (260, 33, 2, 'ff'),
         (260, 33, 2, 'sgn'), (260, 33, 2, 'max'), (261, 32, 1, 'ramp'), (261, 33, 2, 'ramp'),
         (261, 32, 1, 'zero'), (261, 32, 1, 'ff'), (261, 32, 1, 'sgn'), (261, 32, 1, 'max'),
         (261, 33, 2, 'zero'), (261, 33, 2, 'ff'), (261, 33, 2, 'sgn'), (261, 33, 2, 'max'),
         (262, 32, 1, 'ramp'), (262, 33, 2, 'ramp'), (262, 32, 1, 'zero'), (262, 32, 1, 'ff'),
         (262, 32, 1, 'sgn'), (262, 32, 1, 'max'), (262, 33, 2, 'zero'), (262, 33, 2, 'ff'),
         (262, 33, 2, 'sgn'), (262, 33, 2, 'max'), (263, 32, 1, 'ramp'), (263, 33, 2, 'ramp'),
         (263, 32, 1, 'zero'), (263, 32, 1, 'ff'), (263, 32, 1, 'sgn'), (263, 32, 1, 'max'),
         (263, 33, 2, 'zero'), (263, 33, 2, 'ff'), (263, 33, 2, 'sgn'), (263, 33, 2, 'max'),
         (264, 32, 1, 'ramp'), (264, 33, 2, 'ramp'), (264, 32, 1, 'zero'), (264, 32, 1, 'ff'),
         (264, 32, 1, 'sgn'), (264, 32, 1, 'max'), (264, 33, 2, 'zero'), (264, 33, 2, 'ff'),
         (264, 33, 2, 'sgn'), (264, 33, 2, 'max'), (265, 32, 1, 'ramp'), (265, 33, 2, 'ramp'),
         (265, 32, 1, 'zero'), (265, 32, 1, 'ff'), (265, 32, 1, 'sgn'), (265, 32, 1, 'max'),
         (265, 33, 2, 'zero'), (265, 33, 2, 'ff'), (265, 33, 2, 'sgn'), (265, 33, 2, 'max'),
         (266, 32, 1, 'ramp'), (266, 33, 2, 'ramp'), (266, 32, 1, 'zero'), (266, 32, 1, 'ff'),
         (266, 32, 1, 'sgn'), (266, 32, 1, 'max'), (266, 33, 2, 'zero'), (266, 33, 2, 'ff'),
         (266, 33, 2, 'sgn'), (266, 33, 2, 'max'), (267, 32, 1, 'ramp'), (267, 33, 2, 'ramp'),
         (267, 32, 1, 'zero'), (267, 32, 1, 'ff'), (267, 32, 1, 'sgn'), (267, 32, 1, 'max'),
         (267, 33, 2, 'zero'), (267, 33, 2, 'ff'), (267, 33, 2, 'sgn'), (267, 33, 2, 'max'),
         (268, 32, 1, 'ramp'), (268, 33, 2, 'ramp'), (268, 32, 1, 'zero'), (268, 32, 1, 'ff'),
         (268, 32, 1, 'sgn'), (268, 32, 1, 'max'), (268, 33, 2, 'zero'), (268, 33, 2, 'ff'),
         (268, 33, 2, 'sgn'), (268, 33, 2, 'max'), (269, 32, 1, 'ramp'), (269, 33, 2, 'ramp'),
         (269, 32, 1, 'zero'), (269, 32, 1, 'ff'), (269, 32, 1, 'sgn'), (269, 32, 1, 'max'),
         (269, 33, 2, 'zero'), (269, 33, 2, 'ff'), (269, 33, 2, 'sgn'), (269, 33, 2, 'max'),
         (270, 32, 1, 'ramp'), (270, 33, 2, 'ramp'), (270, 32, 1, 'zero'), (270, 32, 1, 'ff'),
         (270, 32, 1, 'sgn'), (270, 32, 1, 'max'), (270, 33, 2, 'zero'), (270, 33, 2, 'ff'),
         (270, 33, 2, 'sgn'), (270, 33, 2, 'max'), (271, 32, 1, 'ramp'), (271, 33, 2, 'ramp'),
         (271, 32, 1, 'zero'), (271, 32, 1, 'ff'), (271, 32, 1, 'sgn'), (271, 32, 1, 'max'),
         (271, 33, 2, 'zero'), (271, 33, 2, 'ff'), (271, 33, 2, 'sgn'), (271, 33, 2, 'max'),
         (272, 32, 1, 'ramp'), (272, 33, 2, 'ramp'), (272, 32, 1, 'zero'), (272, 32, 1, 'ff'),
         (272, 32, 1, 'sgn'), (272, 32, 1, 'max'), (272, 33, 2, 'zero'), (272, 33, 2, 'ff'),
         (272, 33, 2, 'sgn'), (272, 33, 2, 'max'), (273, 32, 1, 'ramp'), (273, 33, 2, 'ramp'),
         (273, 32, 1, 'zero'), (273, 32, 1, 'ff'), (273, 32, 1, 'sgn'), (273, 32, 1, 'max'),
         (273, 33, 2, 'zero'), (273, 33, 2, 'ff'), (273, 33, 2, 'sgn'), (273, 33, 2, 'max'),
         (274, 32, 1, 'ramp'), (274, 33, 2, 'ramp'), (274, 32, 1, 'zero'), (274, 32, 1, 'ff'),
         (274, 32, 1, 'sgn'), (274, 32, 1, 'max'), (274, 33, 2, 'zero'), (274, 33, 2, 'ff'),
         (274, 33, 2, 'sgn'), (274, 33, 2, 'max'), (275, 32, 1, 'ramp'), (275, 33, 2, 'ramp'),
         (275, 32, 1, 'zero'), (275, 32, 1, 'ff'), (275, 32, 1, 'sgn'), (275, 32, 1, 'max'),
         (275, 33, 2, 'zero'), (275, 33, 2, 'ff'), (275, 33, 2, 'sgn'), (275, 33, 2, 'max'),
         (276, 32, 1, 'ramp'), (276, 33, 2, 'ramp'), (276, 32, 1, 'zero'), (276, 32, 1, 'ff'),
         (276, 32, 1, 'sgn'), (276, 32, 1, 'max'), (276, 33, 2, 'zero'), (276, 33, 2, 'ff'),
         (276, 33, 2, 'sgn'), (276, 33, 2, 'max'), (277, 32, 1, 'ramp'), (277, 33, 2, 'ramp'),
         (277, 32, 1, 'zero'), (277, 32, 1, 'ff'), (277, 32, 1, 'sgn'), (277, 32, 1, 'max'),
         (277, 33, 2, 'zero'), (277, 33, 2, 'ff'), (277, 33, 2, 'sgn'), (277, 33, 2, 'max'),
         (278, 32, 1, 'ramp'), (278, 33, 2, 'ramp'), (278, 32, 1, 'zero'), (278, 32, 1, 'ff'),
         (278, 32, 1, 'sgn'), (278, 32, 1, 'max'), (278, 33, 2, 'zero'), (278, 33, 2, 'ff'),
         (278, 33, 2, 'sgn'), (278, 33, 2, 'max'), (279, 32, 1, 'ramp'), (279, 33, 2, 'ramp'),
         (279, 32, 1, 'zero'), (279, 32, 1, 'ff'), (279, 32, 1, 'sgn'), (279, 32, 1, 'max'),
         (279, 33, 2, 'zero'), (279, 33, 2, 'ff'), (279, 33, 2, 'sgn'), (279, 33, 2, 'max'),
         (280, 32, 1, 'ramp'), (280, 33, 2, 'ramp'), (280, 32, 1, 'zero'), (280, 32, 1, 'ff'),
         (280, 32, 1, 'sgn'), (280, 32, 1, 'max'), (280, 33, 2, 'zero'), (280, 33, 2, 'ff'),
         (280, 33, 2, 'sgn'), (280, 33, 2, 'max'), (281, 32, 1, 'ramp'), (281, 33, 2, 'ramp'),
         (281, 32, 1, 'zero'), (281, 32, 1, 'ff'), (281, 32, 1, 'sgn'), (281, 32, 1, 'max'),
         (281, 33, 2, 'zero'), (281, 33, 2, 'ff'), (281, 33, 2, 'sgn'), (281, 33, 2, 'max'),
         (282, 32, 1, 'ramp'), (282, 33, 2, 'ramp'), (282, 32, 1, 'zero'), (282, 32, 1, 'ff'),
         (282, 32, 1, 'sgn'), (282, 32, 1, 'max'), (282, 33, 2, 'zero'), (282, 33, 2, 'ff'),
         (282, 33, 2, 'sgn'), (282, 33, 2, 'max'), (283, 32, 1, 'ramp'), (283, 33, 2, 'ramp'),
         (283, 32, 1, 'zero'), (283, 32, 1, 'ff'), (283, 32, 1, 'sgn'), (283, 32, 1, 'max'),
         (283, 33, 2, 'zero'), (283, 33, 2, 'ff'), (283, 33, 2, 'sgn'), (283, 33, 2, 'max'),
         (284, 32, 1, 'ramp'), (284, 33, 2, 'ramp'), (284, 32, 1, 'zero'), (284, 32, 1, 'ff'),
         (284, 32, 1, 'sgn'), (284, 32, 1, 'max'), (284, 33, 2, 'zero'), (284, 33, 2, 'ff'),
         (284, 33, 2, 'sgn'), (284, 33, 2, 'max'), (285, 32, 1, 'ramp'), (285, 33, 2, 'ramp'),
         (285, 32, 1, 'zero'), (285, 32, 1, 'ff'), (285, 32, 1, 'sgn'), (285, 32, 1, 'max'),
         (285, 33, 2, 'zero'), (285, 33, 2, 'ff'), (285, 33, 2, 'sgn'), (285, 33, 2, 'max')],
        [])}

# hand-made frames: (cluster id, ZCL frame as hex, comment)
EXTRA = []

# frames that are cut short on purpose (malformed capture only)
CUTS = []

def data(t, n, fill):
    if fill == 'ramp':
        d = bytes(range(1, n + 1))
    elif fill == 'zero':
        d = bytes(n)
    elif fill == 'sgn':
        d = bytes(n - 1) + b'\x80'
    elif fill == 'max':
        d = b'\xff' * (n - 1) + b'\x7f'
    else:
        d = b'\xff' * n
    if t in (0x41, 0x42):
        d = bytes([n - 1]) + d[1:]
    return d

def zcl_frame(seq, cluster, zcl, profile=0x0104):
    mac = struct.pack('<HBHHH', 0x8841, seq & 0xff, 0x1234, 0x0000, 0x0001)
    nwk = struct.pack('<HHHBB', 0x0008, 0x0000, 0x0001, 0x1e, seq & 0xff)
    aps = struct.pack('<BBHHBB', 0x00, 0x01, cluster, profile, 0x01, seq & 0xff)
    return mac + nwk + aps + zcl

def write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 230))
        for i, p in enumerate(frames):
            f.write(struct.pack('<IIII', 1700000000 + i, 0, len(p), len(p)) + p)

def build():
    fr = []
    cuts = []
    def add(cid, zcl):
        fr.append(zcl_frame(len(fr) + 1, cid, bytes(zcl)))
        return len(fr) - 1
    for cid in sorted(CLUSTERS):
        name, attrs, cmds = CLUSTERS[cid]
        # cluster-specific commands
        for cmd, d, fill, n in cmds:
            pl = bytes(n) if fill == 'zero' else bytes(range(1, n + 1))
            add(cid, bytes([0x01 | (d << 3), 1, cmd]) + pl)
        # one attribute per Report Attributes frame, server side
        recs = []
        for a, t, n, fill in attrs:
            rec = struct.pack('<HB', a, t) + data(t, n, fill)
            recs.append((a, t, rec))
            add(cid, bytes([0x08, 1, 0x0a]) + rec)
        # attributes the cluster does not know (generic data decoding)
        for t, d in ((0x20, b'\x05'), (0x42, b'\x02ab'), (0x21, b'\x01\x02'), (0x10, b'\x01')):
            add(cid, bytes([0x08, 1, 0x0a]) + struct.pack('<HB', 0x7ffe, t) + d)
        # unknown cluster-specific commands, both directions
        for d in (0x01, 0x09):
            add(cid, bytes([d, 1, 0x7f, 1, 2, 3]))
        ramps = [(a, t, struct.pack('<HB', a, t) + data(t, n, 'ramp')) for a, t, n, fill in attrs if fill == 'ramp']
        for i in range(0, len(ramps), 6):
            chunk = ramps[i:i + 6]
            # Report Attributes from the client side (client attributes)
            add(cid, bytes([0x00, 2, 0x0a]) + b''.join(r for _, _, r in chunk))
            # Read Attributes Response, server side and client side
            add(cid, bytes([0x08, 3, 0x01]) + b''.join(struct.pack('<HB', a, 0) + r[2:] for a, _, r in chunk))
            add(cid, bytes([0x00, 3, 0x01]) + b''.join(struct.pack('<HB', a, 0) + r[2:] for a, _, r in chunk))
            # Write Attributes, Undivided, No Response (both directions)
            add(cid, bytes([0x00, 4, 0x02]) + b''.join(r for _, _, r in chunk))
            add(cid, bytes([0x08, 4, 0x02]) + b''.join(r for _, _, r in chunk))
            add(cid, bytes([0x00, 5, 0x03]) + b''.join(r for _, _, r in chunk))
            add(cid, bytes([0x00, 6, 0x05]) + b''.join(r for _, _, r in chunk))
            # Read Attributes, Write Attributes Response (failure records)
            ids = b''.join(struct.pack('<H', a) for a, _, _ in chunk)
            add(cid, bytes([0x00, 7, 0x00]) + ids)
            add(cid, bytes([0x08, 7, 0x00]) + ids)
            add(cid, bytes([0x08, 8, 0x04]) + b''.join(bytes([0x86]) + struct.pack('<H', a) for a, _, _ in chunk))
            add(cid, bytes([0x00, 8, 0x04]) + b''.join(bytes([0x86]) + struct.pack('<H', a) for a, _, _ in chunk))
            # Discover Attributes Response
            for dd in (0x00, 0x08):
                add(cid, bytes([dd, 9, 0x0d, 1]) + b''.join(struct.pack('<HB', a, t) for a, t, _ in chunk))
            # Configure Reporting: reported, with change for analog types
            cfg = b''
            for (a, t, r), (_, _, n, _f) in zip(chunk, [x for x in attrs if x[3] == 'ramp'][i:i + 6]):
                cfg += bytes([0]) + struct.pack('<HBHH', a, t, 1, 60) + data(t, n, 'ramp') if (t & 0xf0) == 0x20 or (t & 0xf8) == 0x38 or (t & 0xf8) == 0xe0 else bytes([0]) + struct.pack('<HBHH', a, t, 1, 60)
            add(cid, bytes([0x00, 10, 0x06]) + cfg)
            add(cid, bytes([0x08, 10, 0x06]) + cfg)
            # Configure Reporting: received (timeout), response, read config
            add(cid, bytes([0x00, 11, 0x06]) + b''.join(bytes([1]) + struct.pack('<HH', a, 300) for a, _, _ in chunk))
            add(cid, bytes([0x08, 11, 0x06]) + b''.join(bytes([1]) + struct.pack('<HH', a, 300) for a, _, _ in chunk))
            add(cid, bytes([0x08, 12, 0x07]) + b''.join(bytes([0x8c, k & 1]) + struct.pack('<H', a) for k, (a, _, _) in enumerate(chunk)))
            add(cid, bytes([0x00, 12, 0x07]) + b''.join(bytes([0x8c, k & 1]) + struct.pack('<H', a) for k, (a, _, _) in enumerate(chunk)))
            add(cid, bytes([0x00, 13, 0x08]) + b''.join(bytes([k & 1]) + struct.pack('<H', a) for k, (a, _, _) in enumerate(chunk)))
            add(cid, bytes([0x08, 13, 0x08]) + b''.join(bytes([k & 1]) + struct.pack('<H', a) for k, (a, _, _) in enumerate(chunk)))
        if ramps:
            a, t, r = ramps[0]
            add(cid, bytes([0x08, 14, 0x09, 0, 0]) + struct.pack('<HBHH', a, t, 1, 60) + data(t, len(r) - 3, 'ramp'))
            add(cid, bytes([0x00, 14, 0x09, 0, 1]) + struct.pack('<HH', a, 300))
            add(cid, bytes([0x00, 14, 0x09, 0, 1]) + struct.pack('<HH', a, 300))
    for cid, hx, comment in EXTRA:
        add(cid, bytes.fromhex(hx))
    for k in CUTS:
        cuts.append(k)
    return fr

def main():
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    fr = build()
    write_pcap(os.path.join(out, 'zbee-zcl-ha-coverage.pcap'), fr)
    # malformed capture: every 7th frame cut by one byte, and every 11th by 3
    bad = [f[:-1] for f in fr[::7]] + [f[:-3] for f in fr[3::11]]
    write_pcap(os.path.join(out, 'zbee-zcl-ha-coverage-malformed.pcap'), bad)
    with open(os.path.join(out, 'zbee-zcl-ha-coverage.pcap'), 'rb') as f:
        raw = f.read()
    with gzip.GzipFile(os.path.join(out, 'zbee-zcl-ha_coverage.pcap.gz'), 'wb', mtime=0) as g:
        g.write(raw)
    print(len(fr), len(bad))

if __name__ == '__main__':
    main()
