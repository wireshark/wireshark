#!/usr/bin/env python3
#
# By Zoran Bošnjak <zoran.bosnjak@via.si>
#
# Helper script to generate asterix samples, for test purposes.
# Based on 'libasterix' python library
#   - https://pypi.org/project/libasterix/
#   - https://github.com/zoranbosnjak/asterix-libs/tree/main/libs/python#readme
#
# usage: capture data with 'tcpdump'
# tcpdump -i lo -s 0 port 8600 -w samples.pcap
#
# Generate samples, use 'ast-tool-py' for sending to UDP
# python this-script.py | ast-tool-py -s to-udp --unicast "*" 127.0.0.1 8600
#
# Decode samples with 'ast-tool-py'
# ast-tool-py replay --format pcap samples.pcap | ast-tool-py decode
#
# Compare decoded result with wireshark/tshark output
# tshark -r samples.pcap -V
# wireshark samples.pcap
# SPDX-License-Identifier: GPL-2.0-or-later

from typing import *
from binascii import hexlify, unhexlify
from dataclasses import dataclass

from asterix.base import *
import asterix.generated as gen

# Select particular asterix categories and editions
Cat001 = gen.Cat_001_1_4
Cat004 = gen.Cat_004_1_13
Cat008 = gen.Cat_008_1_3
Cat062 = gen.Cat_062_1_21

# prepare records

record001_simple = Cat001.cv_uap.spec('plot').create({
    '010': (('SAC', 1), ('SIC', 2)),
    '020': ((('TYP',0),0,0,0,0,0,None),),
})

record001_plot = Cat001.cv_uap.spec('plot').create({
    '010': (('SAC', 1), ('SIC', 2)),
    '020': ((('TYP',0),0,0,0,0,0,None),),
    '040': (('RHO', (123.0, 'NM')), ('THETA', (45.0, "°"))),
})

record001_track = Cat001.cv_uap.spec('track').create({
    '010': (('SAC', 1), ('SIC', 2)),
    '020': ((('TYP',1),0,0,0,0,0,None),),
    '040': (('RHO', (123.0, 'NM')), ('THETA', (45.0, "°"))),
})

# dependent variation
record004 = Cat004.cv_record.create({
    '000': 5, # Area Proximity Warning (APW)
    '120': {
        'CC': (
            ('TID', 1),
            ('CPC', 0), # structure is 'raw', set to 0
            ('CS', 0)
            )
        }
    })

record008 = Cat008.cv_record.create({
    # integer content (signed, unsigned)
    '036': [
        (('X', 1), ('Y', 2), ('LENGTH', 3)),
        (('X', 127), ('Y', 127), ('LENGTH', 3)),
        (('X', -1), ('Y', -2), ('LENGTH', 130)),
        (('X', -128), ('Y', -127), ('LENGTH', 255)),
    ]
})

record062 = Cat062.cv_record.create({
    '010': (('SAC', 1), ('SIC', 2)),

    # table content
    '135': (('QNH', 1), ('CTB', 0)),

    # string content (ascii, icao, octal)
    '390': {'CS': "FLT1"},
    '245': (0, 0, ('CHR', "ID1")),
    '060': (0, 0, 0, 0, ('MODE3A', "1234")),

    # quantity content (signed, unsigned)
    '100': (('X', (123.4, 'm')), ('Y', (-123.4, 'm'))),
    '380': {
        'MHG': (270.0, "°"),

        # dependent content
        'IAS': ( # type: ignore
            ('IM', 0),  # set IM to 0
            ('IAS', 1)  # set IAS to raw value 1 (no unit conversion)
        ),
    },

    # abuse spare item
    '120': (2, ('MODE2', 1)),
})

# prepare datablocks
datablocks = [
    Cat001.create([record001_simple, record001_simple]),
    Cat001.create([record001_plot, record001_track]),
    Cat004.create([record004]),
    Cat008.create([record008]),
    Cat062.create([record062]),
]

# encode as bytes
s = b''.join([db.unparse().to_bytes() for db in datablocks])
print(hexlify(s).decode('utf-8'))

