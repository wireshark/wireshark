#!/usr/bin/env python3
# Generates test/captures/scylla_coverage.pcap.gz
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
"""Build the Scylla RPC coverage captures: mkscylla.py <outdir> [-v].  All data is synthetic.

The dissector has no default port (7000 is the expected one), so the
captures are dissected with  -d tcp.port==7000,scylla ."""
import os
import sys

sys.path.insert(1, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'shared'))













import struct
from c17lib import Cap, Tcp

MAGIC = b'SSTARRPC'
CLIENT_ID, MUTATION, MUTATION_DONE, READ_DATA, READ_MUTATION_DATA, READ_DIGEST = 0, 1, 2, 3, 4, 5
GOSSIP_DIGEST_SYN, GOSSIP_ECHO, GOSSIP_SHUTDOWN, DEFINITIONS_UPDATE, TRUNCATE = 6, 9, 10, 11, 12
GET_SCHEMA_VERSION, MUTATION_FAILED, PAXOS_PREPARE, PAXOS_LEARN, HINT_MUTATION = 21, 24, 39, 41, 42
RAFT_APPEND_ENTRIES, TASKS_GET_CHILDREN = 47, 74

def feat(num, data=b'', length=None):
    return struct.pack('<II', num, len(data) if length is None else length) + data

def nego(*features, size=None):
    body = b''.join(features)
    return MAGIC + struct.pack('<I', len(body) if size is None else size) + body

def req(verb, msg_id, payload=b'', timeout=30000):
    return struct.pack('<QQQI', timeout, verb, msg_id, len(payload)) + payload

def resp(msg_id, payload=b'\xaa' * 8):
    return struct.pack('<QI', msg_id, len(payload)) + payload

def mutation(pkeys, tail=b'row data'):
    pk = struct.pack('<I', len(pkeys)) + b''.join(struct.pack('<I', len(k)) + k for k in pkeys)
    body = (struct.pack('<II', 0, 0) + bytes(range(16)) + bytes(range(16, 32))
            + struct.pack('<I', len(pk)) + pk + tail)
    return struct.pack('<II', len(body), len(body)) + body[8:]

def read_data(tail=b'query'):
    return struct.pack('<I', 5000) + bytes(range(100, 116)) + bytes(range(200, 216)) + tail

def main(out, verbose=False):
    c = Cap(1)
    c.mark('Protocol negotiation with every feature: compression, timeout propagation, connection ID, stream parent, isolation cookie, handler duration, an unknown feature, a connection ID of another length, an empty feature')
    t = Tcp(c, 40000, 7000)
    t.c2s(nego(feat(0, b'lz4'), feat(1), feat(2, struct.pack('<Q', 0x1122334455667788)),
               feat(3, struct.pack('<Q', 0xaabbccdd)), feat(4, b'default-cookie'), feat(5, b'\x01'),
               feat(77, b'\x01\x02\x03'), feat(2, b'\x01\x02\x03\x04'), feat(1, b'')))
    t.s2c(nego(feat(0), feat(2, struct.pack('<Q', 7))))
    t.s2c(nego())
    c.mark('Requests without a response expected: gossip, mutation (with partition keys), mutation done and failed, hint mutation, Paxos learn, definitions update')
    t.c2s(req(CLIENT_ID, 1, b'\x05\x00\x00\x00node1'))
    t.c2s(req(MUTATION, 2, mutation([b'key1', b'key22', b'k'])))
    t.c2s(req(MUTATION, 3, mutation([])))
    t.c2s(req(MUTATION_DONE, 4, b'\x00' * 4))
    t.c2s(req(MUTATION_FAILED, 5, b'\x00' * 8))
    t.c2s(req(HINT_MUTATION, 6, b'hint'))
    t.c2s(req(PAXOS_LEARN, 7, b'learn'))
    t.c2s(req(DEFINITIONS_UPDATE, 8, b''))
    t.c2s(req(GOSSIP_DIGEST_SYN, 9, b'syn' * 5))
    t.c2s(req(GOSSIP_SHUTDOWN, 10, b'\x01'))
    c.mark('Requests with responses: read data, read digest, gossip echo, schema version, truncate, Paxos prepare, Raft, a task request; responses in a different order')
    t.c2s(req(READ_DATA, 11, read_data()))
    t.c2s(req(READ_DIGEST, 12, b'digest request'))
    t.c2s(req(GOSSIP_ECHO, 13, b'\x00\x00\x00\x00'))
    t.c2s(req(GET_SCHEMA_VERSION, 14))
    t.c2s(req(TRUNCATE, 15, b'ks.table'))
    t.c2s(req(PAXOS_PREPARE, 16, b'p'))
    t.c2s(req(RAFT_APPEND_ENTRIES, 17, b'raft'))
    t.c2s(req(TASKS_GET_CHILDREN, 18, b''))
    t.s2c(resp(13))
    t.s2c(resp(11, b'\xbb' * 40))
    t.s2c(resp(12, b'\x01\x00\x00\x00digest'))
    t.s2c(resp(14, b'\x02\x00\x00\x00'))
    t.s2c(resp(15, b'\xcc' * 4))
    t.s2c(resp(16, b'\xdd' * 12))
    t.s2c(resp(17, b'\xee' * 3))
    t.s2c(resp(18, b'\x01\x01'))
    t.s2c(resp(1, b'\x77' * 4))
    c.mark('A response to a request with no response expected, and a response with an unknown message ID')
    t.s2c(resp(2, b'\xaa' * 8))
    t.s2c(resp(999, b'\xaa' * 8))
    c.mark('Read data with an empty tail; two requests in one segment; a request split over three segments (reassembly)')
    t.c2s(req(READ_DATA, 20, read_data(b'')))
    t.c2s(req(GOSSIP_ECHO, 21, b'1234') + req(READ_DIGEST, 22, b'abcd'))
    big = req(READ_DIGEST, 23, bytes(range(256)) * 2)
    t.c2s(big[:40]); t.c2s(big[40:300]); t.c2s(big[300:])
    t.s2c(resp(20, b'\x11' * 16) + resp(21, b'\x22' * 16))
    t.s2c(resp(22, b'\x33' * 16))
    r = resp(23, b'\x44' * 200)
    t.s2c(r[:5]); t.s2c(r[5:])
    c.mark('An RPC streaming message (the first word is the length, as a segment of its own)')
    t3 = Tcp(c, 40002, 7000)
    st = struct.pack('<QI', 36, 24) + b'\x55' * 24 + b'tail'
    t3.c2s(st)

    m = Cap(1)
    m.mark('A request that never gets a response (second pass: the response frame is read from uninitialised memory, see the README), a response before its request (matched to the later request on the second pass)')
    t4 = Tcp(m, 40050, 7000)
    t4.c2s(req(TRUNCATE, 30, b'no.reply'))
    t4.s2c(resp(40, b'\x44' * 8))
    t4.c2s(req(GOSSIP_ECHO, 40, b'late'))
    m.mark('Reproducer of the endless loop fix: a connection ID feature length of 0xfffffff8, and other feature lengths beyond the negotiation data (error expert info)')
    tm = Tcp(m, 40100, 7000)
    tm.c2s(nego(feat(2, b'', 0xfffffff8), b'\0' * 8, size=16))
    tm.c2s(nego(feat(3, b'', 0xfffffff8), b'\0' * 8, size=16))
    tm.c2s(nego(feat(0, b'ab', 100)))
    tm.c2s(nego(feat(4, b'x', 2), feat(5, b'', 0xffffffff)))
    m.mark('Mutations with truncated partition keys, a length that is too large (exceptions), a request cut short')
    tm.c2s(req(MUTATION, 1, mutation([b'abc'])[:50]))
    pk = struct.pack('<II', 0, 0) + bytes(32) + struct.pack('<I', 12) + struct.pack('<I', 3) + struct.pack('<I', 0x7fffffff) + b'xx'
    tm.c2s(req(MUTATION, 2, pk))
    tm.c2s(req(READ_DATA, 3, b'\0' * 10))
    tm.c2s(resp(5, b'\xaa' * 8)[:10])

    c.write(os.path.join(out, 'scylla-coverage.pcap'))
    m.write(os.path.join(out, 'scylla-coverage-malformed.pcap'))
    if verbose:
        for n, tx in c.marks:
            print(n, tx)
        print(len(c.frames), 'frames')

if __name__ == '__main__':
    main(sys.argv[1], '-v' in sys.argv)
