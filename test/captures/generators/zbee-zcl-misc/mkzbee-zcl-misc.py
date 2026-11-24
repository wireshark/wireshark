#!/usr/bin/env python3
# Generates test/captures/zbee-zcl-misc_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Coverage capture generator for packet-zbee-zcl-misc.c (ZigBee ZCL misc clusters)
# Synthetic ZigBee frames, generated with struct only: 802.15.4 (linktype
# 230, no FCS) -> ZigBee NWK -> APS (HA profile) -> ZCL, reached through
# the default zbee_nwk heuristic.  Addresses are made up.
#   usage: mkzbee-zcl-misc.py <outdir>
# writes zbee-zcl-misc-coverage.pcap, zbee-zcl-misc-coverage-malformed.pcap and
# zbee-zcl-misc_coverage.pcap.gz
import struct
import sys
import os
import gzip

# cluster id -> (name, attributes, cluster-specific commands)
#   attribute entries: (attr id, data type, data length, fill) ; the data
#   is zeros, a 1..n ramp or 0xff bytes (strings carry the length byte)
#   command entries:   (command id, FCF direction bit, fill, payload length)
CLUSTERS = {513: ('thermostat',
       [(0, 32, 1, 'ramp'), (0, 33, 2, 'ramp'), (0, 32, 1, 'zero'), (0, 32, 1, 'ff'),
        (0, 32, 1, 'sgn'), (0, 32, 1, 'max'), (0, 33, 2, 'zero'), (0, 33, 2, 'ff'),
        (0, 33, 2, 'sgn'), (0, 33, 2, 'max'), (1, 32, 1, 'ramp'), (1, 33, 2, 'ramp'),
        (1, 32, 1, 'zero'), (1, 32, 1, 'ff'), (1, 32, 1, 'sgn'), (1, 32, 1, 'max'),
        (1, 33, 2, 'zero'), (1, 33, 2, 'ff'), (1, 33, 2, 'sgn'), (1, 33, 2, 'max'),
        (2, 32, 1, 'ramp'), (2, 33, 2, 'ramp'), (2, 32, 1, 'zero'), (2, 32, 1, 'ff'),
        (2, 32, 1, 'sgn'), (2, 32, 1, 'max'), (2, 33, 2, 'zero'), (2, 33, 2, 'ff'),
        (2, 33, 2, 'sgn'), (2, 33, 2, 'max'), (3, 32, 1, 'ramp'), (3, 33, 2, 'ramp'),
        (3, 32, 1, 'zero'), (3, 32, 1, 'ff'), (3, 32, 1, 'sgn'), (3, 32, 1, 'max'),
        (3, 33, 2, 'zero'), (3, 33, 2, 'ff'), (3, 33, 2, 'sgn'), (3, 33, 2, 'max'),
        (4, 32, 1, 'ramp'), (4, 33, 2, 'ramp'), (4, 32, 1, 'zero'), (4, 32, 1, 'ff'),
        (4, 32, 1, 'sgn'), (4, 32, 1, 'max'), (4, 33, 2, 'zero'), (4, 33, 2, 'ff'),
        (4, 33, 2, 'sgn'), (4, 33, 2, 'max'), (5, 32, 1, 'ramp'), (5, 33, 2, 'ramp'),
        (5, 32, 1, 'zero'), (5, 32, 1, 'ff'), (5, 32, 1, 'sgn'), (5, 32, 1, 'max'),
        (5, 33, 2, 'zero'), (5, 33, 2, 'ff'), (5, 33, 2, 'sgn'), (5, 33, 2, 'max'),
        (6, 32, 1, 'ramp'), (6, 33, 2, 'ramp'), (6, 32, 1, 'zero'), (6, 32, 1, 'ff'),
        (6, 32, 1, 'sgn'), (6, 32, 1, 'max'), (6, 33, 2, 'zero'), (6, 33, 2, 'ff'),
        (6, 33, 2, 'sgn'), (6, 33, 2, 'max'), (7, 32, 1, 'ramp'), (7, 33, 2, 'ramp'),
        (7, 32, 1, 'zero'), (7, 32, 1, 'ff'), (7, 32, 1, 'sgn'), (7, 32, 1, 'max'),
        (7, 33, 2, 'zero'), (7, 33, 2, 'ff'), (7, 33, 2, 'sgn'), (7, 33, 2, 'max'),
        (8, 32, 1, 'ramp'), (8, 33, 2, 'ramp'), (8, 32, 1, 'zero'), (8, 32, 1, 'ff'),
        (8, 32, 1, 'sgn'), (8, 32, 1, 'max'), (8, 33, 2, 'zero'), (8, 33, 2, 'ff'),
        (8, 33, 2, 'sgn'), (8, 33, 2, 'max'), (9, 32, 1, 'ramp'), (9, 33, 2, 'ramp'),
        (9, 32, 1, 'zero'), (9, 32, 1, 'ff'), (9, 32, 1, 'sgn'), (9, 32, 1, 'max'),
        (9, 33, 2, 'zero'), (9, 33, 2, 'ff'), (9, 33, 2, 'sgn'), (9, 33, 2, 'max'),
        (16, 32, 1, 'ramp'), (16, 33, 2, 'ramp'), (16, 32, 1, 'zero'), (16, 32, 1, 'ff'),
        (16, 32, 1, 'sgn'), (16, 32, 1, 'max'), (16, 33, 2, 'zero'), (16, 33, 2, 'ff'),
        (16, 33, 2, 'sgn'), (16, 33, 2, 'max'), (17, 32, 1, 'ramp'), (17, 33, 2, 'ramp'),
        (17, 32, 1, 'zero'), (17, 32, 1, 'ff'), (17, 32, 1, 'sgn'), (17, 32, 1, 'max'),
        (17, 33, 2, 'zero'), (17, 33, 2, 'ff'), (17, 33, 2, 'sgn'), (17, 33, 2, 'max'),
        (18, 32, 1, 'ramp'), (18, 33, 2, 'ramp'), (18, 32, 1, 'zero'), (18, 32, 1, 'ff'),
        (18, 32, 1, 'sgn'), (18, 32, 1, 'max'), (18, 33, 2, 'zero'), (18, 33, 2, 'ff'),
        (18, 33, 2, 'sgn'), (18, 33, 2, 'max'), (19, 32, 1, 'ramp'), (19, 33, 2, 'ramp'),
        (19, 32, 1, 'zero'), (19, 32, 1, 'ff'), (19, 32, 1, 'sgn'), (19, 32, 1, 'max'),
        (19, 33, 2, 'zero'), (19, 33, 2, 'ff'), (19, 33, 2, 'sgn'), (19, 33, 2, 'max'),
        (20, 32, 1, 'ramp'), (20, 33, 2, 'ramp'), (20, 32, 1, 'zero'), (20, 32, 1, 'ff'),
        (20, 32, 1, 'sgn'), (20, 32, 1, 'max'), (20, 33, 2, 'zero'), (20, 33, 2, 'ff'),
        (20, 33, 2, 'sgn'), (20, 33, 2, 'max'), (21, 32, 1, 'ramp'), (21, 33, 2, 'ramp'),
        (21, 32, 1, 'zero'), (21, 32, 1, 'ff'), (21, 32, 1, 'sgn'), (21, 32, 1, 'max'),
        (21, 33, 2, 'zero'), (21, 33, 2, 'ff'), (21, 33, 2, 'sgn'), (21, 33, 2, 'max'),
        (22, 32, 1, 'ramp'), (22, 33, 2, 'ramp'), (22, 32, 1, 'zero'), (22, 32, 1, 'ff'),
        (22, 32, 1, 'sgn'), (22, 32, 1, 'max'), (22, 33, 2, 'zero'), (22, 33, 2, 'ff'),
        (22, 33, 2, 'sgn'), (22, 33, 2, 'max'), (23, 32, 1, 'ramp'), (23, 33, 2, 'ramp'),
        (23, 32, 1, 'zero'), (23, 32, 1, 'ff'), (23, 32, 1, 'sgn'), (23, 32, 1, 'max'),
        (23, 33, 2, 'zero'), (23, 33, 2, 'ff'), (23, 33, 2, 'sgn'), (23, 33, 2, 'max'),
        (24, 32, 1, 'ramp'), (24, 33, 2, 'ramp'), (24, 32, 1, 'zero'), (24, 32, 1, 'ff'),
        (24, 32, 1, 'sgn'), (24, 32, 1, 'max'), (24, 33, 2, 'zero'), (24, 33, 2, 'ff'),
        (24, 33, 2, 'sgn'), (24, 33, 2, 'max'), (25, 32, 1, 'ramp'), (25, 33, 2, 'ramp'),
        (25, 32, 1, 'zero'), (25, 32, 1, 'ff'), (25, 32, 1, 'sgn'), (25, 32, 1, 'max'),
        (25, 33, 2, 'zero'), (25, 33, 2, 'ff'), (25, 33, 2, 'sgn'), (25, 33, 2, 'max'),
        (26, 32, 1, 'ramp'), (26, 33, 2, 'ramp'), (26, 32, 1, 'zero'), (26, 32, 1, 'ff'),
        (26, 32, 1, 'sgn'), (26, 32, 1, 'max'), (26, 33, 2, 'zero'), (26, 33, 2, 'ff'),
        (26, 33, 2, 'sgn'), (26, 33, 2, 'max'), (27, 32, 1, 'ramp'), (27, 33, 2, 'ramp'),
        (27, 32, 1, 'zero'), (27, 32, 1, 'ff'), (27, 32, 1, 'sgn'), (27, 32, 1, 'max'),
        (27, 33, 2, 'zero'), (27, 33, 2, 'ff'), (27, 33, 2, 'sgn'), (27, 33, 2, 'max'),
        (28, 32, 1, 'ramp'), (28, 33, 2, 'ramp'), (28, 32, 1, 'zero'), (28, 32, 1, 'ff'),
        (28, 32, 1, 'sgn'), (28, 32, 1, 'max'), (28, 33, 2, 'zero'), (28, 33, 2, 'ff'),
        (28, 33, 2, 'sgn'), (28, 33, 2, 'max'), (29, 32, 1, 'ramp'), (29, 33, 2, 'ramp'),
        (29, 32, 1, 'zero'), (29, 32, 1, 'ff'), (29, 32, 1, 'sgn'), (29, 32, 1, 'max'),
        (29, 33, 2, 'zero'), (29, 33, 2, 'ff'), (29, 33, 2, 'sgn'), (29, 33, 2, 'max'),
        (30, 32, 1, 'ramp'), (30, 33, 2, 'ramp'), (30, 32, 1, 'zero'), (30, 32, 1, 'ff'),
        (30, 32, 1, 'sgn'), (30, 32, 1, 'max'), (30, 33, 2, 'zero'), (30, 33, 2, 'ff'),
        (30, 33, 2, 'sgn'), (30, 33, 2, 'max'), (32, 32, 1, 'ramp'), (32, 33, 2, 'ramp'),
        (32, 32, 1, 'zero'), (32, 32, 1, 'ff'), (32, 32, 1, 'sgn'), (32, 32, 1, 'max'),
        (32, 33, 2, 'zero'), (32, 33, 2, 'ff'), (32, 33, 2, 'sgn'), (32, 33, 2, 'max'),
        (33, 32, 1, 'ramp'), (33, 33, 2, 'ramp'), (33, 32, 1, 'zero'), (33, 32, 1, 'ff'),
        (33, 32, 1, 'sgn'), (33, 32, 1, 'max'), (33, 33, 2, 'zero'), (33, 33, 2, 'ff'),
        (33, 33, 2, 'sgn'), (33, 33, 2, 'max'), (34, 32, 1, 'ramp'), (34, 33, 2, 'ramp'),
        (34, 32, 1, 'zero'), (34, 32, 1, 'ff'), (34, 32, 1, 'sgn'), (34, 32, 1, 'max'),
        (34, 33, 2, 'zero'), (34, 33, 2, 'ff'), (34, 33, 2, 'sgn'), (34, 33, 2, 'max'),
        (35, 32, 1, 'ramp'), (35, 33, 2, 'ramp'), (35, 32, 1, 'zero'), (35, 32, 1, 'ff'),
        (35, 32, 1, 'sgn'), (35, 32, 1, 'max'), (35, 33, 2, 'zero'), (35, 33, 2, 'ff'),
        (35, 33, 2, 'sgn'), (35, 33, 2, 'max'), (36, 32, 1, 'ramp'), (36, 33, 2, 'ramp'),
        (36, 32, 1, 'zero'), (36, 32, 1, 'ff'), (36, 32, 1, 'sgn'), (36, 32, 1, 'max'),
        (36, 33, 2, 'zero'), (36, 33, 2, 'ff'), (36, 33, 2, 'sgn'), (36, 33, 2, 'max'),
        (37, 32, 1, 'ramp'), (37, 33, 2, 'ramp'), (37, 32, 1, 'zero'), (37, 32, 1, 'ff'),
        (37, 32, 1, 'sgn'), (37, 32, 1, 'max'), (37, 33, 2, 'zero'), (37, 33, 2, 'ff'),
        (37, 33, 2, 'sgn'), (37, 33, 2, 'max'), (41, 32, 1, 'ramp'), (41, 33, 2, 'ramp'),
        (41, 32, 1, 'zero'), (41, 32, 1, 'ff'), (41, 32, 1, 'sgn'), (41, 32, 1, 'max'),
        (41, 33, 2, 'zero'), (41, 33, 2, 'ff'), (41, 33, 2, 'sgn'), (41, 33, 2, 'max'),
        (48, 32, 1, 'ramp'), (48, 33, 2, 'ramp'), (48, 32, 1, 'zero'), (48, 32, 1, 'ff'),
        (48, 32, 1, 'sgn'), (48, 32, 1, 'max'), (48, 33, 2, 'zero'), (48, 33, 2, 'ff'),
        (48, 33, 2, 'sgn'), (48, 33, 2, 'max'), (49, 32, 1, 'ramp'), (49, 33, 2, 'ramp'),
        (49, 32, 1, 'zero'), (49, 32, 1, 'ff'), (49, 32, 1, 'sgn'), (49, 32, 1, 'max'),
        (49, 33, 2, 'zero'), (49, 33, 2, 'ff'), (49, 33, 2, 'sgn'), (49, 33, 2, 'max'),
        (50, 32, 1, 'ramp'), (50, 33, 2, 'ramp'), (50, 32, 1, 'zero'), (50, 32, 1, 'ff'),
        (50, 32, 1, 'sgn'), (50, 32, 1, 'max'), (50, 33, 2, 'zero'), (50, 33, 2, 'ff'),
        (50, 33, 2, 'sgn'), (50, 33, 2, 'max'), (52, 32, 1, 'ramp'), (52, 33, 2, 'ramp'),
        (52, 32, 1, 'zero'), (52, 32, 1, 'ff'), (52, 32, 1, 'sgn'), (52, 32, 1, 'max'),
        (52, 33, 2, 'zero'), (52, 33, 2, 'ff'), (52, 33, 2, 'sgn'), (52, 33, 2, 'max'),
        (53, 32, 1, 'ramp'), (53, 33, 2, 'ramp'), (53, 32, 1, 'zero'), (53, 32, 1, 'ff'),
        (53, 32, 1, 'sgn'), (53, 32, 1, 'max'), (53, 33, 2, 'zero'), (53, 33, 2, 'ff'),
        (53, 33, 2, 'sgn'), (53, 33, 2, 'max'), (54, 32, 1, 'ramp'), (54, 33, 2, 'ramp'),
        (54, 32, 1, 'zero'), (54, 32, 1, 'ff'), (54, 32, 1, 'sgn'), (54, 32, 1, 'max'),
        (54, 33, 2, 'zero'), (54, 33, 2, 'ff'), (54, 33, 2, 'sgn'), (54, 33, 2, 'max'),
        (55, 32, 1, 'ramp'), (55, 33, 2, 'ramp'), (55, 32, 1, 'zero'), (55, 32, 1, 'ff'),
        (55, 32, 1, 'sgn'), (55, 32, 1, 'max'), (55, 33, 2, 'zero'), (55, 33, 2, 'ff'),
        (55, 33, 2, 'sgn'), (55, 33, 2, 'max'), (56, 32, 1, 'ramp'), (56, 33, 2, 'ramp'),
        (56, 32, 1, 'zero'), (56, 32, 1, 'ff'), (56, 32, 1, 'sgn'), (56, 32, 1, 'max'),
        (56, 33, 2, 'zero'), (56, 33, 2, 'ff'), (56, 33, 2, 'sgn'), (56, 33, 2, 'max'),
        (57, 32, 1, 'ramp'), (57, 33, 2, 'ramp'), (57, 32, 1, 'zero'), (57, 32, 1, 'ff'),
        (57, 32, 1, 'sgn'), (57, 32, 1, 'max'), (57, 33, 2, 'zero'), (57, 33, 2, 'ff'),
        (57, 33, 2, 'sgn'), (57, 33, 2, 'max'), (58, 32, 1, 'ramp'), (58, 33, 2, 'ramp'),
        (58, 32, 1, 'zero'), (58, 32, 1, 'ff'), (58, 32, 1, 'sgn'), (58, 32, 1, 'max'),
        (58, 33, 2, 'zero'), (58, 33, 2, 'ff'), (58, 33, 2, 'sgn'), (58, 33, 2, 'max'),
        (64, 32, 1, 'ramp'), (64, 33, 2, 'ramp'), (64, 32, 1, 'zero'), (64, 32, 1, 'ff'),
        (64, 32, 1, 'sgn'), (64, 32, 1, 'max'), (64, 33, 2, 'zero'), (64, 33, 2, 'ff'),
        (64, 33, 2, 'sgn'), (64, 33, 2, 'max'), (65, 32, 1, 'ramp'), (65, 33, 2, 'ramp'),
        (65, 32, 1, 'zero'), (65, 32, 1, 'ff'), (65, 32, 1, 'sgn'), (65, 32, 1, 'max'),
        (65, 33, 2, 'zero'), (65, 33, 2, 'ff'), (65, 33, 2, 'sgn'), (65, 33, 2, 'max'),
        (66, 32, 1, 'ramp'), (66, 33, 2, 'ramp'), (66, 32, 1, 'zero'), (66, 32, 1, 'ff'),
        (66, 32, 1, 'sgn'), (66, 32, 1, 'max'), (66, 33, 2, 'zero'), (66, 33, 2, 'ff'),
        (66, 33, 2, 'sgn'), (66, 33, 2, 'max'), (67, 32, 1, 'ramp'), (67, 33, 2, 'ramp'),
        (67, 32, 1, 'zero'), (67, 32, 1, 'ff'), (67, 32, 1, 'sgn'), (67, 32, 1, 'max'),
        (67, 33, 2, 'zero'), (67, 33, 2, 'ff'), (67, 33, 2, 'sgn'), (67, 33, 2, 'max'),
        (68, 32, 1, 'ramp'), (68, 33, 2, 'ramp'), (68, 32, 1, 'zero'), (68, 32, 1, 'ff'),
        (68, 32, 1, 'sgn'), (68, 32, 1, 'max'), (68, 33, 2, 'zero'), (68, 33, 2, 'ff'),
        (68, 33, 2, 'sgn'), (68, 33, 2, 'max'), (69, 32, 1, 'ramp'), (69, 33, 2, 'ramp'),
        (69, 32, 1, 'zero'), (69, 32, 1, 'ff'), (69, 32, 1, 'sgn'), (69, 32, 1, 'max'),
        (69, 33, 2, 'zero'), (69, 33, 2, 'ff'), (69, 33, 2, 'sgn'), (69, 33, 2, 'max'),
        (70, 32, 1, 'ramp'), (70, 33, 2, 'ramp'), (70, 32, 1, 'zero'), (70, 32, 1, 'ff'),
        (70, 32, 1, 'sgn'), (70, 32, 1, 'max'), (70, 33, 2, 'zero'), (70, 33, 2, 'ff'),
        (70, 33, 2, 'sgn'), (70, 33, 2, 'max'), (71, 32, 1, 'ramp'), (71, 33, 2, 'ramp'),
        (71, 32, 1, 'zero'), (71, 32, 1, 'ff'), (71, 32, 1, 'sgn'), (71, 32, 1, 'max'),
        (71, 33, 2, 'zero'), (71, 33, 2, 'ff'), (71, 33, 2, 'sgn'), (71, 33, 2, 'max')],
       [(0, 0, 'ramp', 2), (0, 0, 'ramp', 40), (0, 0, 'zero', 2), (0, 0, 'zero', 40),
        (0, 1, 'ramp', 9), (0, 1, 'ramp', 40), (0, 1, 'zero', 3), (0, 1, 'zero', 40),
        (1, 0, 'ramp', 9), (1, 0, 'ramp', 40), (1, 0, 'zero', 3), (1, 0, 'zero', 40),
        (1, 1, 'ramp', 0), (1, 1, 'ramp', 40), (1, 1, 'zero', 0), (1, 1, 'zero', 40),
        (2, 0, 'ramp', 2), (2, 0, 'ramp', 40), (2, 0, 'zero', 2), (2, 0, 'zero', 40),
        (2, 1, 'ramp', 0), (2, 1, 'ramp', 40), (2, 1, 'zero', 0), (2, 1, 'zero', 40),
        (3, 0, 'ramp', 0), (3, 0, 'ramp', 40), (3, 0, 'zero', 0), (3, 0, 'zero', 40),
        (3, 1, 'ramp', 0), (3, 1, 'ramp', 40), (3, 1, 'zero', 0), (3, 1, 'zero', 40),
        (4, 0, 'ramp', 0), (4, 0, 'ramp', 40), (4, 0, 'zero', 0), (4, 0, 'zero', 40),
        (4, 1, 'ramp', 0), (4, 1, 'ramp', 40), (4, 1, 'zero', 0), (4, 1, 'zero', 40)]),
 1280: ('ias_zone',
        [(0, 32, 1, 'ramp'), (0, 48, 1, 'ramp'), (0, 32, 1, 'zero'), (0, 32, 1, 'ff'),
         (0, 32, 1, 'sgn'), (0, 32, 1, 'max'), (0, 48, 1, 'zero'), (0, 48, 1, 'ff'),
         (0, 48, 1, 'sgn'), (0, 48, 1, 'max'), (1, 33, 2, 'ramp'), (1, 25, 2, 'ramp'),
         (1, 33, 2, 'zero'), (1, 33, 2, 'ff'), (1, 33, 2, 'sgn'), (1, 33, 2, 'max'),
         (1, 25, 2, 'zero'), (1, 25, 2, 'ff'), (1, 25, 2, 'sgn'), (1, 25, 2, 'max'),
         (2, 33, 2, 'ramp'), (2, 25, 2, 'ramp'), (2, 33, 2, 'zero'), (2, 33, 2, 'ff'),
         (2, 33, 2, 'sgn'), (2, 33, 2, 'max'), (2, 25, 2, 'zero'), (2, 25, 2, 'ff'),
         (2, 25, 2, 'sgn'), (2, 25, 2, 'max'), (16, 32, 1, 'ramp'), (16, 33, 2, 'ramp'),
         (16, 32, 1, 'zero'), (16, 32, 1, 'ff'), (16, 32, 1, 'sgn'), (16, 32, 1, 'max'),
         (16, 33, 2, 'zero'), (16, 33, 2, 'ff'), (16, 33, 2, 'sgn'), (16, 33, 2, 'max')],
        [(0, 0, 'ramp', 2), (0, 0, 'ramp', 40), (0, 0, 'zero', 2), (0, 0, 'zero', 40),
         (0, 1, 'ramp', 6), (0, 1, 'ramp', 40), (0, 1, 'zero', 6), (0, 1, 'zero', 40),
         (1, 0, 'ramp', 0), (1, 0, 'ramp', 40), (1, 0, 'zero', 0), (1, 0, 'zero', 40),
         (1, 1, 'ramp', 4), (1, 1, 'ramp', 40), (1, 1, 'zero', 4), (1, 1, 'zero', 40),
         (2, 0, 'ramp', 0), (2, 0, 'ramp', 40), (2, 0, 'zero', 0), (2, 0, 'zero', 40),
         (2, 1, 'ramp', 0), (2, 1, 'ramp', 40), (2, 1, 'zero', 0), (2, 1, 'zero', 40),
         (3, 0, 'ramp', 0), (3, 0, 'ramp', 40), (3, 0, 'zero', 0), (3, 0, 'zero', 40),
         (3, 1, 'ramp', 0), (3, 1, 'ramp', 40), (3, 1, 'zero', 0), (3, 1, 'zero', 40)])}

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
    write_pcap(os.path.join(out, 'zbee-zcl-misc-coverage.pcap'), fr)
    # malformed capture: every 7th frame cut by one byte, and every 11th by 3
    bad = [f[:-1] for f in fr[::7]] + [f[:-3] for f in fr[3::11]]
    write_pcap(os.path.join(out, 'zbee-zcl-misc-coverage-malformed.pcap'), bad)
    with open(os.path.join(out, 'zbee-zcl-misc-coverage.pcap'), 'rb') as f:
        raw = f.read()
    with gzip.GzipFile(os.path.join(out, 'zbee-zcl-misc_coverage.pcap.gz'), 'wb', mtime=0) as g:
        g.write(raw)
    print(len(fr), len(bad))

if __name__ == '__main__':
    main()
