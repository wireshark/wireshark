#!/usr/bin/env python3
# Generates test/captures/moq_file_coverage.dat, moq_file_coverage.moq
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the MoQ Object File coverage files: mkmoq_file.py <outdir> [-v]

moq_file_coverage.moq  JSON metadata file read by wiretap/moq.c (opened by
                       heuristic; each item becomes an Exported PDU
                       "moq_file" record); the object bytes come from
                       moq_file_coverage.dat in the same directory.
moq-file-coverage-malformed.pcapng
                       Exported PDU "moq_file" records the reader never
                       produces (bad length, bad JSON, wrong types) for
                       the dissector's defensive paths.
Everything is synthetic.
"""
import json
import os
import struct
import sys

def main(outdir, verbose=False):
    os.makedirs(outdir, exist_ok=True)
    data = bytes((i * 7 + 3) & 0xff for i in range(256))
    open(os.path.join(outdir, 'moq_file_coverage.dat'), 'wb').write(data)
    DF = 'moq_file_coverage.dat'
    T0 = 1729457464000
    items = [
        # 1: every field
        dict(trackNamespace=['ZXhhbXBsZQ', 'dmlkZW8'], trackName='dGVzdC10cmFjaw', objectID=7, groupID=3, subgroupID=1,
             forwardingPref='Subgroup', objectStatus=0, publisherPriority=10, receiveTime=T0, dataFile=DF,
             dataOffset=0, dataLength=8),
        # 2: the legacy key names (namesSpace, subGroup), a namespace of three entries
        dict(namesSpace=['YQ', 'Yg', 'Yw'], trackName='bGVnYWN5', objectID=1, groupID=2, subGroup=5, forwardingPref='Datagram',
             receiveTime=T0 + 1, dataFile=DF, dataOffset=8, dataLength=16),
        # 3: track, group and object but no subgroup
        dict(trackName='dHJhY2s', objectID=9, groupID=4, receiveTime=T0 + 2, dataFile=DF, dataOffset=24, dataLength=4),
        # 4: track and object only
        dict(trackName='dHJhY2syCg', objectID=11, receiveTime=T0 + 3, dataFile=DF, dataOffset=28, dataLength=5),
        # 5: no track name
        dict(objectID=1, groupID=1, receiveTime=T0 + 4, dataFile=DF, dataOffset=33, dataLength=6),
        # 6: track name without an object ID
        dict(trackName='bm8tb2JqZWN0', groupID=1, receiveTime=T0 + 5, dataFile=DF, dataOffset=39, dataLength=3),
        # 7: no object bytes (dataLength 0): no data item, no Info text
        dict(trackName='ZW1wdHk', objectID=2, groupID=2, subgroupID=0, receiveTime=T0 + 6, dataFile=DF, dataOffset=0, dataLength=0),
        # 8: a negative receive time, objectStatus and priority, status values
        dict(trackName='bmVn', objectID=0, groupID=0, subgroupID=0, objectStatus=3, publisherPriority=255,
             receiveTime=-1500, dataFile=DF, dataOffset=42, dataLength=2),
        # 9: the reproducer of the fix: "a\\u0041" is the text aA and must not be decoded a second time
        dict(trackName='a\\u0041', objectID=3, groupID=1, subgroupID=1, receiveTime=T0 + 7, dataFile=DF, dataOffset=44, dataLength=4),
        # 10: a name with a JSON escape that is decoded once, and an escaped value elsewhere
        dict(trackName='café \"q\"', objectID=4, groupID=1, subgroupID=2, forwardingPref='Sub\\group', receiveTime=T0 + 8,
             dataFile=DF, dataOffset=48, dataLength=7),
        # 11: a namespace that is not an array (ignored), a large object, large IDs
        dict(trackNamespace='notanarray', trackName='YmlnZ2Vy', objectID=2 ** 40, groupID=2 ** 41, subgroupID=2 ** 42,
             receiveTime=T0 + 9, dataFile=DF, dataOffset=0, dataLength=256),
        # 12: a data offset in the middle of the file with other fields and an empty namespace array
        dict(trackNamespace=[], trackName='bWlk', objectID=5, groupID=5, subgroupID=5, receiveTime=T0 + 10,
             dataFile=DF, dataOffset=100, dataLength=100),
        # 13: strings where numbers belong and numbers where strings belong
        dict(trackName=12, objectID='x', groupID=1.5, subgroupID=True, forwardingPref=7, receiveTime=T0 + 11,
             dataFile=DF, dataOffset=10, dataLength=3),
        # items the reader skips (not frames): no dataFile, bad offsets, directory traversal, subdirectory
        dict(trackName='c2tpcA', objectID=1, dataOffset=0, dataLength=1),
        dict(trackName='c2tpcA', dataFile='../x.dat', dataOffset=0, dataLength=1),
        dict(trackName='c2tpcA', dataFile='sub/x.dat', dataOffset=0, dataLength=1),
        dict(trackName='c2tpcA', dataFile=DF, dataOffset=-1, dataLength=1),
    ]
    txt = json.dumps(items, indent=2)
    open(os.path.join(outdir, 'moq_file_coverage.moq'), 'w').write(txt + '\n')

    # ------------------------------------------------ Exported PDU records
    def epdu(payload):
        n = b'moq_file'
        return struct.pack('!HH', 12, len(n)) + n + struct.pack('!HH', 0, 0) + payload
    def rec(meta, obj=b'', length=None):
        return struct.pack('!I', len(meta) if length is None else length) + meta + obj
    recs = [
        b'', b'\x00\x00', b'\x00\x00\x00',                                   # shorter than the length field
        rec(b'{}', b'ab'),
        rec(b'{"objectID":1}', b'ab'),
        rec(b'{"trackName":"dA","groupID":1}', b'ab'),
        rec(b'{"trackName":"dA","objectID":1,"subgroupID":4}', b'ab'),       # no group: "Track %s O="
        rec(b'', b'xyz'),                                                      # empty metadata
        rec(b'[1,2,3]', b'xyz'),                                               # not an object
        rec(b'not json', b'xyz'),
        rec(b'{"trackName":', b'xyz'),                                         # truncated JSON
        rec(b'{"trackName":"a\\\\u0041","objectID":1,"groupID":2}', b'xyz'),    # the reproducer of the fix in a record
        rec(b'{"trackNamespace":[1,"a",[2]],"trackName":"x"}', b'x'),
        rec(b'{"namesSpace":"str","trackName":"x"}', b'x'),
        rec(b'{"objectID":1}', length=100),                                     # metadata length beyond the record
        rec(b'{"objectID":1}', b'', length=0xffffffff),
        rec(b'{"objectID":1}'),                                                 # no object bytes
        rec(b'{"objectID":99999999999999999999999,"groupID":-1}', b'q'),         # numbers out of range
        rec(b'{"objectID":1,"objectID":2}', b'q'),                              # duplicate key
        rec(b'{"a":{"b":{"c":[{"trackName":"deep","objectID":3}]}},"trackName":"top","objectID":8}', b'q'),
        rec(b'{"trackName":"\\ud83d\\ude00","objectID":1}', b'q'),              # a surrogate pair
        rec(b'{"trackName":"\\ud83d","objectID":1}', b'q'),                     # a lone surrogate
        rec(b'{"trackName":"x\\u0000y","objectID":1}', b'q'),                   # an escaped NUL
        rec(b'{"trackName":"' + b'x' * 300 + b'","objectID":1}', b'q'),
        rec(b'{"trackName":"x","objectID":1}\0trailing', b'q'),
    ]
    def blk(t, body):
        body += b'\0' * (-len(body) % 4)
        return struct.pack('<II', t, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)) + blk(1, struct.pack('<HHI', 252, 0, 0))
    for i, r in enumerate(recs):
        fr = epdu(r); ts = (1700000000 + i) * 1000000
        out += blk(6, struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff, len(fr), len(fr)) + fr)
    open(os.path.join(outdir, 'moq-file-coverage-malformed.pcapng'), 'wb').write(out)
    if verbose:
        print(len(items), 'items in the .moq file (13 records, 4 skipped by the reader);', len(recs), 'records in the pcapng')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
