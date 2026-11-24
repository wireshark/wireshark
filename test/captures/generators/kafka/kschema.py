# Helper module for the kafka capture generator
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# Kafka message schemas as the dissector (packet-kafka.c) expects them.
# Field tuple: (kind, vmin, vmax[, sub])
#   kinds: i8 i16 i32 i64 u16 f64 bool uuid ts  s (string) ns (nullable string)
#          b (bytes) rec (record set) arr (array of sub fields, tagged struct)
#          arrp (array of primitive kind in sub) narr (nullable array of structs)
#          tag (tagged fields, struct end marker, always last)
INF = 99

def f(kind, a=0, b=INF, sub=None):
    return (kind, a, b, sub)

def s(a=0, b=INF): return f('s', a, b)
def ns(a=0, b=INF): return f('ns', a, b)
def i8(a=0, b=INF): return f('i8', a, b)
def i16(a=0, b=INF): return f('i16', a, b)
def i32(a=0, b=INF): return f('i32', a, b)
def i64(a=0, b=INF): return f('i64', a, b)
def ts(a=0, b=INF): return f('ts', a, b)
def u16(a=0, b=INF): return f('u16', a, b)
def f64(a=0, b=INF): return f('f64', a, b)
def bl(a=0, b=INF): return f('bool', a, b)
def uuid(a=0, b=INF): return f('uuid', a, b)
def by(a=0, b=INF): return f('b', a, b)
def rec(a=0, b=INF): return f('rec', a, b)
def arr(sub, a=0, b=INF, tag=True): return f('arr' if tag else 'arrn', a, b, sub)
def narr(sub, a=0, b=INF): return f('narr', a, b, sub)
def arrp(kind, a=0, b=INF): return f('arrp', a, b, kind)
def narrp(kind, a=0, b=INF): return f('narrp', a, b, kind)
def tag(a=0, b=INF): return f('tag', a, b)
def arr0(sub, a=0, b=INF): return f('arr0', a, b, sub)
def carr(sub, a=0, b=INF): return f('carr', a, b, sub)
def rs(a=0, b=INF): return f('rs', a, b)
def rawtag(name, a=0, b=INF): return f('rawtag', a, b, name)

SCHEMAS = {}   # key -> (req, resp)

# --- Produce 0
SCHEMAS[0] = (
 [ns(3), i16(), i32(),
  arr([s(0,12), uuid(13), arr([i32(), rec(), tag(9)]), tag(9)], tag=False), tag(9)],
 [arr([s(0,12), uuid(13), arr([i32(), i16(), i64(), ts(2), i64(5), narr([i32(), ns(), tag(9)], 8), ns(8), tag(9)]), tag(9)], tag=False),
  i32(1), tag(9)])
# --- Fetch 1
SCHEMAS[1] = (
 [i32(0,14), i32(), i32(), i32(3), i8(4), i32(7), i32(7),
  arr([s(0,12), uuid(13), arr([i32(), i32(9), i64(), i32(12), i64(5), i32(), rawtag('fetchpart', 12)]), tag(12)], tag=False),
  arr([s(0,12), uuid(13), arrp('i32'), tag(12)], 7, INF, False),
  s(11), tag(12)],
 [i32(1), i16(7), i32(7),
  arr([s(0,12), uuid(13), arr([i32(), i16(), i64(), i64(4), i64(5),
        narr([i64(), i64(), tag(12)], 4), i32(11), rec(), tag(12)]), tag(12)], tag=False),
  tag(12)])
# --- Offsets 2
SCHEMAS[2] = (
 [i32(), i8(2), arr([s(), arr([i32(), i32(4), i64(), i32(0,0), tag(6)]), tag(6)], tag=False), tag(6)],
 [i32(2), arr([s(), arr([i32(), i16(), arrp('i64', 0, 0), i64(1), i64(1), i32(4), tag(6)]), tag(6)], tag=False), tag(6)])
# --- Metadata 3
SCHEMAS[3] = (
 [narr([uuid(10), ns(), tag(9)], 0, 99), bl(4), bl(8, 10), bl(8), tag(9)],
 [i32(3), arr([i32(), s(), i32(), ns(1), tag(9)], tag=False), ns(2), i32(1),
  arr([i16(), ns(), uuid(10), bl(1), arr([i16(), i32(), i32(), i32(7), arrp('i32'), arrp('i32'), arrp('i32', 5), tag(9)]), i32(8), tag(9)], tag=False),
  i32(8, 10), i16(13), tag(9)])
# --- LeaderAndIsr 4
_lisr_part_v01 = [s(0,1), i32(), i32(), i32(), i32(), arrp('i32'), i32(), arrp('i32'), arrp('i32', 3), arrp('i32', 3), bl(1), i8(6), tag(4)]
SCHEMAS[4] = (
 [i32(), bl(7), i32(), i64(2), i8(5),
  arr(_lisr_part_v01, 0, 1, tag=False),
  arr([s(), uuid(5), arr([i32(), i32(), i32(), i32(), arrp('i32'), i32(), arrp('i32'), arrp('i32', 3), arrp('i32', 3), bl(1), i8(6), tag(4)]), tag(4)], 2, INF, False),
  arr([i32(), s(), i32(), tag(4)], tag=False), tag(4)],
 [i16(), arr([s(0,4), i32(), i16(), tag(4)], 0, 4, False),
  arr([uuid(5), arr([i32(), i16(), tag(4)]), tag(4)], 5, INF, False), tag(4)])
# --- StopReplica 5
SCHEMAS[5] = (
 [i32(), bl(4), i32(), i64(1), bl(0,2),
  arr([s(), i32()], 0, 0, False),
  arr([s(), arrp('i32'), tag(2)], 1, 2, False),
  arr([s(), arr([i32(), i32(), bl()], tag=False), tag(2)], 3, INF, False), tag(3), tag(2)],
 [i16(), arr([s(), i32(), i16(), tag(2)], tag=False), tag(2)])
# --- UpdateMetadata 6
_um_part = [i32(), i32(), i32(), i32(), arrp('i32'), i32(), arrp('i32'), arrp('i32')]
SCHEMAS[6] = (
 [i32(), bl(8), i32(), i64(5),
  arr([s()] + _um_part + [tag(6)], 0, 4, False),
  arr([s(), uuid(7), arr(_um_part + [tag(6)]), tag(6)], 5, INF, False),
  arr([i32(), s(0, 0), i32(0, 0),
       arr([i32(), s(), ns(3), i16(), tag(6)], 1, INF, False), ns(2), tag(6)], tag=False), tag(6)],
 [i16(), tag(6)])
# --- ControlledShutdown 7
SCHEMAS[7] = (
 [i32(), i64(2), tag(3)],
 [i16(), arr([s(), i32(), tag(3)], tag=False), tag(3)])
# --- OffsetCommit 8
SCHEMAS[8] = (
 [s(), i32(1), s(1), ns(7), i64(2, 4),
  arr([s(), arr([i32(), i64(), i32(6), ts(1, 1), ns(), tag(8)]), tag(8)], tag=False), tag(8)],
 [i32(3), arr([s(), arr([i32(), i16(), tag(8)]), tag(8)], tag=False), tag(8)])
# --- OffsetFetch 9
_of_topics_old = arr([s(), arrp('i32'), tag(6)], tag=False)
SCHEMAS[9] = (
 [s(0, 7), f('narr', 0, 7, [s(), arrp('i32'), tag(6)]),
  arr([s(), ns(9), i32(9), narr([s(), arrp('i32'), tag(6)]), tag(6)], 8, INF, False),
  bl(7), tag(6)],
 [i32(3), arr([s(), arr([i32(), i64(), i32(5), ns(), i16(), tag(6)]), tag(6)], 0, 7, False),
  i16(2, 7),
  arr([s(), arr([s(), arr([i32(), i64(), i32(5), ns(), i16(), tag(6)]), tag(6)]), i16(), tag(6)], 8, INF, False),
  tag(6)])
# --- FindCoordinator 10
SCHEMAS[10] = (
 [s(0, 0), s(0, 3), i8(1), arrp('s', 4), tag(3)],
 [i32(1), i16(0, 3), ns(1, 3), i32(0, 3), s(0, 3), i32(0, 3),
  arr([s(), i32(), s(), i32(), i16(), ns(), tag(3)], 4, INF, False), tag(3)])
# --- JoinGroup 11
SCHEMAS[11] = (
 [s(), i32(), i32(1), s(), ns(5), s(),
  arr([s(), by(), tag(6)], tag=False), ns(8), tag(6)],
 [i32(2), i16(), i32(), ns(7), ns(), s(), bl(9), s(),
  arr([s(), ns(5), by(), tag(6)], tag=False), tag(6)])
# --- Heartbeat 12
SCHEMAS[12] = ([s(), i32(), s(), ns(3), tag(4)], [i32(1), i16(), tag(4)])
# --- LeaveGroup 13
SCHEMAS[13] = (
 [s(), s(0, 2), arr([s(), ns(), ns(5), tag(4)], 3, INF, False), tag(4)],
 [i32(1), i16(), arr([s(), ns(), i16(), tag(4)], 3, INF, False), tag(4)])
# --- SyncGroup 14
SCHEMAS[14] = (
 [s(), i32(), s(), ns(3), ns(5), ns(5), arr([s(), by(), tag(4)], tag=False), tag(4)],
 [i32(1), i16(), ns(5), ns(5), by(), tag(4)])
# --- DescribeGroups 15
SCHEMAS[15] = (
 [arrp('s'), bl(3), tag(5)],
 [i32(1), arr([i16(), s(), s(), s(), s(),
               arr([s(), ns(4), s(), s(), by(), by(), tag(5)]), i32(3), tag(5)], tag=False), tag(5)])
# --- ListGroups 16
SCHEMAS[16] = ([tag(3)], [i32(1), i16(), arr([s(), s(), tag(3)], tag=False), tag(3)])
# --- SaslHandshake 17
SCHEMAS[17] = ([s()], [i16(), arrp('s')])
# --- ApiVersions 18  (response built specially)
SCHEMAS[18] = (
 [s(3), s(3), s(5), i32(5), tag(3)],
 [i16(), arr([i16(), i16(), i16(), tag(3)], tag=False), i32(1), tag(3)])
# --- CreateTopics 19
SCHEMAS[19] = (
 [arr([s(), i32(), i16(), arr0([i32(), arrp('i32'), tag(5)]), arr([s(), s(), tag(5)]), tag(5)], tag=False),
  i32(), bl(1), tag(5)],
 [i32(2), arr([s(), uuid(7), i16(), ns(1), i32(5), i16(5), narr([s(), ns(), i8(), i8(), i8(), tag(5)], 5), tag(5)], tag=False), tag(5)])
# --- DeleteTopics 20
SCHEMAS[20] = (
 [arr([ns(), uuid()], 6, INF, False), tag(6), arrp('s', 0, 5), i32(), tag(4)],
 [i32(1), arr([ns(), uuid(6), i16(), ns(5), tag(4)], tag=False), tag(4)])
# --- DeleteRecords 21
SCHEMAS[21] = (
 [arr([s(), arr([i32(), i64()], tag=False)], tag=False), i32()],
 [i32(), arr([s(), arr([i32(), i64(), i16()], tag=False)], tag=False)])
# --- InitProducerId 22
SCHEMAS[22] = (
 [ns(), i32(), i64(3), i16(3), tag(2)],
 [i32(), i16(), i64(), i16(), tag(2)])
# --- OffsetForLeaderEpoch 23
SCHEMAS[23] = (
 [i32(3), arr([s(), arr([i32(), i32(2), i32()], tag=False)], tag=False)],
 [i32(2), arr([s(), arr([i16(), i32(), i32(1), i64()], tag=False)], tag=False)])
# --- AddPartitionsToTxn 24
SCHEMAS[24] = (
 [s(), i64(), i16(), arr([s(), arrp('i32')], tag=False)],
 [i32(), arr([s(), arr([i32(), i16()], tag=False)], tag=False)])
SCHEMAS[25] = ([s(), i64(), i16(), s()], [i32(), i16()])
SCHEMAS[26] = ([s(), i64(), i16(), bl()], [i32(), i16()])
# --- WriteTxnMarkers 27
SCHEMAS[27] = (
 [arr([i64(), i16(), bl(), arr([s(), arrp('i32')], tag=False), i32()], tag=False)],
 [i32(), arr([i64(), arr([s(), arr([i32(), i16()], tag=False)], tag=False)], tag=False)])
# --- TxnOffsetCommit 28
SCHEMAS[28] = (
 [s(), s(), i64(), i16(), i32(3), s(3), ns(3),
  arr([s(), arr([i32(), i64(), i32(2), ns(), tag(3)]), tag(3)], tag=False), tag(3)],
 [i32(), arr([s(), arr([i32(), i16(), tag(3)]), tag(3)], tag=False), tag(3)])
# --- ACLs 29-31
_acl_f = [i8(), s(), i8(1), s(), s(), i8(), i8(), tag(2)]
SCHEMAS[29] = (
 [i8(), ns(), i8(1), ns(), ns(), i8(), i8(), tag(2)],
 [i32(), i16(), ns(), arr([i8(), s(), i8(1), arr([s(), s(), i8(), i8(), tag(2)]), tag(2)], tag=False), tag(2)])
SCHEMAS[30] = (
 [arr(_acl_f, tag=False), tag(2)],
 [i32(), arr([i16(), ns(), tag(2)], tag=False), tag(2)])
SCHEMAS[31] = (
 [arr([i8(), ns(), i8(1), ns(), ns(), i8(), i8(), tag(2)], tag=False), tag(2)],
 [i32(), carr([i16(), ns(), arr([i16(), ns(), i8(), s(), i8(1), s(), s(), i8(), i8(), tag(2)]), tag(2)]), tag(2)])
# --- DescribeConfigs 32
SCHEMAS[32] = (
 [arr([i8(), s(), narrp('s'), tag(4)], tag=False), bl(1), bl(3), tag(4)],
 [i32(), arr([i16(), ns(), i8(), s(),
              arr([s(), ns(), bl(), bl(0, 0), i8(1), bl(),
                   arr([rs(), rs(), i8(), tag(4)], 1), i8(3), ns(3), tag(4)]), tag(4)], tag=False), tag(4)])
# --- AlterConfigs 33
SCHEMAS[33] = (
 [arr([i8(), s(), arr([s(), ns()], tag=False)], tag=False), bl()],
 [i32(), arr([i16(), ns(), i8(), s()], tag=False)])
# --- AlterReplicaLogDirs 34
SCHEMAS[34] = (
 [arr([s(), arr([s(), arrp('i32')], tag=False)], tag=False)],
 [i32(), arr([s(), arr([i32(), i16()], tag=False)], tag=False)])
# --- DescribeLogDirs 35
SCHEMAS[35] = (
 [narr([s(), arrp('i32')])],
 [i32(), arr([i16(), s(), arr([s(), arr([i32(), i64(), i64(), bl()], tag=False)], tag=False)], tag=False)])
# --- SaslAuthenticate 36
SCHEMAS[36] = ([by(), tag(2)], [i16(), ns(), by(), i64(1), tag(2)])
# --- CreatePartitions 37
SCHEMAS[37] = (
 [arr([s(), i32(), narrp('i32'), tag(2)], tag=False), i32(), bl(), tag(2)],
 [i32(), arr([s(), i16(), ns(), tag(2)], tag=False), tag(2)])
# --- delegation tokens 38-41
SCHEMAS[38] = ([arr([s(), s(), tag(2)], tag=False), i64(), tag(2)],
               [i16(), s(), s(), ts(), ts(), ts(), s(), by(), i32(), tag(2)])
SCHEMAS[39] = ([by(), i64(), tag(2)], [i16(), ts(), i32(), tag(2)])
SCHEMAS[40] = ([by(), i64(), tag(2)], [i16(), ts(), i32(), tag(2)])
SCHEMAS[41] = ([narr([s(), s(), tag(2)]), tag(2)],
               [i16(), arr([s(), s(), ts(), ts(), ts(), s(), by(), arr([s(), s(), tag(2)]), tag(2)], tag=False), i32(), tag(2)])
# --- DeleteGroups 42
SCHEMAS[42] = ([arrp('s'), tag(2)], [i32(), arr([s(), i16(), tag(2)], tag=False), tag(2)])
# --- ElectLeaders 43
SCHEMAS[43] = (
 [i8(1), arr([arrp('i32'), tag(2)]), i32(), tag(2)],
 [i32(), i16(1), arr([s(), arr([i32(), i16(), ns(), tag(2)]), tag(2)], tag=False), tag(2)])
# --- IncrementalAlterConfigs 44
SCHEMAS[44] = (
 [arr([i8(), s(), arr([s(), i8(), ns(), tag(1)]), tag(1)], tag=False), bl(), tag(1)],
 [i32(), arr([i16(), ns(), i8(), s(), tag(1)], tag=False), tag(1)])
# --- AlterPartitionReassignments 45
SCHEMAS[45] = (
 [i32(), arr([s(), arr([i32(), narrp('i32'), tag(0)]), tag(0)], tag=False), tag(0)],
 [i32(), i16(), ns(), arr([s(), arr([i32(), i16(), ns(), tag(0)]), tag(0)], tag=False), tag(0)])
# --- ListPartitionReassignments 46
SCHEMAS[46] = (
 [i32(), narr([s(), arrp('i32'), tag(0)]), tag(0)],
 [i32(), i16(), ns(), arr([s(), arr([i32(), i16(), ns(), arrp('i32'), arrp('i32'), arrp('i32'), tag(0)]), tag(0)], tag=False), tag(0)])
# --- OffsetDelete 47
SCHEMAS[47] = (
 [s(), arr([s(), arrp('i32')], tag=False)],
 [i16(), i32(), arr([s(), arr([i32(), i16()], tag=False)], tag=False)])
# --- Client quotas 48/49
_ent = [s(), ns(), tag(1)]
SCHEMAS[48] = (
 [arr([s(), i8(), ns(), tag(1)], tag=False), bl(), tag(1)],
 [i32(), i16(), ns(), narr([arr(_ent, tag=False), arr([s(), f64(), tag(1)], tag=False), tag(1)]), tag(1)])
SCHEMAS[49] = (
 [arr([arr(_ent, tag=False), arr([s(), f64(), bl(), tag(1)], tag=False), tag(1)], tag=False), bl(), tag(1)],
 [i32(), arr([i16(), ns(), arr(_ent, tag=False), tag(1)], tag=False), tag(1)])
# --- BeginQuorumEpoch 53
SCHEMAS[53] = (
 [ns(), i32(1), arr([s(), arr([i32(), uuid(1), i32(), i32(), tag(1)]), tag(1)], tag=False),
  arr([f('cs'), f('cs'), u16(), tag(1)], 1, INF, False), tag(1)],
 [i16(), arr([s(), arr([i32(), i16(), i32(), i32(), tag(1)]), tag(1)], tag=False),
  f('quorumtag', 1)])
# --- AlterPartition 56
SCHEMAS[56] = (
 [i32(), i64(),
  arr([uuid(2), f('cs', 0, 1), arr([i32(), i32(), arrp('i32', 0, 2), arr([i32(), i64(), tag(0)], 3, INF, False), i8(1), i32(), tag(0)]), tag(0)], tag=False), tag(0)],
 [i32(), i16(),
  arr([uuid(2), f('cs', 0, 1), arr([i32(), i16(), i32(), i32(), arrp('i32'), i8(1), i32(), tag(0)]), tag(0)], tag=False), tag(0)])
# --- DescribeCluster 60
SCHEMAS[60] = (
 [bl(), i8(1), tag(0)],
 [i32(), i16(), ns(), i8(1), s(), i32(), arr([i32(), s(), i32(), ns(), tag(0)], tag=False), i32(), tag(0)])
# --- BrokerHeartbeat 63
SCHEMAS[63] = (
 [i32(), i64(), i64(), bl(), bl(), f('bhtag', 0)],
 [i32(), i16(), bl(), bl(), bl(), tag(0)])
# --- AllocateProducerIds 67
SCHEMAS[67] = ([i32(), i64(), tag(0)], [i32(), i16(), i64(), i32(), tag(0)])
# --- ConsumerGroupHeartbeat 68
SCHEMAS[68] = (
 [s(), s(), i32(), ns(), ns(), i32(), narrp('s'), ns(1), ns(), narr([uuid(), arrp('i32'), tag(0)]), tag(0)],
 [i32(), i16(), ns(), ns(), i32(), i32(), f('cgassign'), tag(0)])
