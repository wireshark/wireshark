/*
 * packet-hazelcast.c
 * dissector for hazelcast wire protocol
 * Paul Erkkila <paul.erkkila@level3.com>
 *
 * Website: http://www.hazelcast.com/
 *
 * reversed from this code:
 * http://code.google.com/p/hazelcast/source/browse/branches/1.9.4/hazelcast/src/main/java/com/hazelcast/nio/Packet.java
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <packet-tcp.h>

void proto_register_hazelcast(void);
void proto_reg_handoff_hazelcast(void);

static int proto_hazelcast = -1;
static int hazelcast_tap = -1;

static int hf_hazelcast_headerLength = -1;
static int hf_hazelcast_headerKeyLength = -1;
static int hf_hazelcast_headerValueLength = -1;
static int hf_hazelcast_headerVersion = -1;

static int hf_hazelcast_operation = -1;
static int hf_hazelcast_blockID = -1;
static int hf_hazelcast_threadID = -1;
static int hf_hazelcast_timeout = -1;
static int hf_hazelcast_ttl = -1;
static int hf_hazelcast_txnID = -1;
static int hf_hazelcast_longValue = -1;
static int hf_hazelcast_version = -1;
static int hf_hazelcast_lockCount = -1;
static int hf_hazelcast_lockAddrIP = -1;
static int hf_hazelcast_lockAddrPort = -1;
static int hf_hazelcast_callID = -1;
static int hf_hazelcast_responseType = -1;
static int hf_hazelcast_nameLength = -1;
static int hf_hazelcast_name = -1;
static int hf_hazelcast_indexCount = -1;
static int hf_hazelcast_keyPartitionHash = -1;
static int hf_hazelcast_valuePartitionHash = -1;
static int hf_hazelcast_keys = -1;
static int hf_hazelcast_values = -1;

/* flags */
static int hf_hazelcast_flags = -1;

#define HAZELCAST_LOCKCOUNT_FLAG        (1 << 0)
#define HAZELCAST_TIMEOUT_FLAG          (1 << 1)
#define HAZELCAST_TTL_FLAG              (1 << 2)
#define HAZELCAST_TXN_FLAG              (1 << 3)
#define HAZELCAST_LONGVALUE_FLAG        (1 << 4)
#define HAZELCAST_VERSION_FLAG          (1 << 5)
#define HAZELCAST_CLIENT_FLAG           (1 << 6)
#define HAZELCAST_LOCKADDRNULL_FLAG     (1 << 7)

static int hf_hazelcast_flags_lockCount = -1;
static int hf_hazelcast_flags_timeout = -1;
static int hf_hazelcast_flags_ttl = -1;
static int hf_hazelcast_flags_txn = -1;
static int hf_hazelcast_flags_longValue = -1;
static int hf_hazelcast_flags_version = -1;
static int hf_hazelcast_flags_client = -1;
static int hf_hazelcast_flags_lockAddrNull = -1;


static gint ett_hazelcast = -1;
static gint ett_hazelcast_flags = -1;

/* prefs */
static gboolean hazelcast_desegment = TRUE;
static guint gPORT_PREF = 5701;

static const value_string operationTypes[] = {
    {0,   "NONE"},
    {1,   "RESPONSE"},
    {2,   "LOG"},
    {3,   "HEARTBEAT"},
    {4,   "JOIN_CHECK"},
    {5,   "REMOTELY_PROCESS"},
    {6,   "REMOTELY_PROCESS_AND_RESPOND"},
    {7,   "REMOTELY_CALLABLE_BOOLEAN"},
    {8,   "REMOTELY_CALLABLE_OBJECT"},
    {9,   "EVENT"},
    {10,  "EXECUTE"},
    {11,  "CANCEL_EXECUTION"},
    {12,  "ADD_LISTENER"},
    {13,  "ADD_LISTENER_NO_RESPONSE"},
    {14,  "REMOVE_LISTENER"},
    {15,  "BLOCKING_ADD_KEY"},
    {16,  "BLOCKING_REMOVE_KEY"},
    {17,  "BLOCKING_OFFER_KEY"},
    {18,  "BLOCKING_GENERATE_KEY"},
    {19,  "BLOCKING_ITERATE"},
    {20,  "BLOCKING_SIZE"},
    {21,  "BLOCKING_TAKE_KEY"},
    {22,  "BLOCKING_CANCEL_TAKE_KEY"},
    {23,  "BLOCKING_SET"},
    {24,  "BLOCKING_PEEK_KEY"},
    {25,  "BLOCKING_GET_KEY_BY_INDEX"},
    {26,  "BLOCKING_GET_INDEX_BY_KEY"},
    {27,  "BLOCKING_QUEUE_POLL"},
    {28,  "BLOCKING_QUEUE_OFFER"},
    {29,  "BLOCKING_QUEUE_SIZE"},
    {30,  "BLOCKING_QUEUE_PEEK"},
    {31,  "BLOCKING_QUEUE_REMOVE"},
    {32,  "TOPIC_PUBLISH"},
    {33,  "ATOMIC_NUMBER_ADD_AND_GET"},
    {34,  "ATOMIC_NUMBER_GET_AND_ADD"},
    {35,  "ATOMIC_NUMBER_GET_AND_SET"},
    {36,  "ATOMIC_NUMBER_COMPARE_AND_SET"},
    {37,  "CONCURRENT_MAP_PUT"},
    {38,  "CONCURRENT_MAP_PUT_ALL"},
    {39,  "CONCURRENT_MAP_PUT_TRANSIENT"},
    {40,  "CONCURRENT_MAP_SET"},
    {41,  "CONCURRENT_MAP_MERGE"},
    {42,  "CONCURRENT_MAP_ASYNC_MERGE"},
    {43,  "CONCURRENT_MAP_WAN_MERGE"},
    {44,  "CONCURRENT_MAP_TRY_PUT"},
    {45,  "CONCURRENT_MAP_PUT_AND_UNLOCK"},
    {46,  "CONCURRENT_MAP_GET"},
    {47,  "CONCURRENT_MAP_GET_ALL"},
    {48,  "CONCURRENT_MAP_REMOVE"},
    {49,  "CONCURRENT_MAP_TRY_REMOVE"},
    {50,  "CONCURRENT_MAP_REMOVE_ITEM"},
    {51,  "CONCURRENT_MAP_GET_MAP_ENTRY"},
    {52,  "CONCURRENT_MAP_GET_DATA_RECORD_ENTRY"},
    {53,  "CONCURRENT_MAP_BLOCK_INFO"},
    {54,  "CONCURRENT_MAP_BLOCK_MIGRATION_CHECK"},
    {55,  "CONCURRENT_MAP_SIZE"},
    {56,  "CONCURRENT_MAP_CONTAINS_KEY"},
    {57,  "CONCURRENT_MAP_CONTAINS_ENTRY"},
    {58,  "CONCURRENT_MAP_ITERATE_ENTRIES"},
    {59,  "CONCURRENT_MAP_ITERATE_KEYS"},
    {60,  "CONCURRENT_MAP_ITERATE_KEYS_ALL"},
    {61,  "CONCURRENT_MAP_ITERATE_VALUES"},
    {62,  "CONCURRENT_MAP_LOCK"},
    {63,  "CONCURRENT_MAP_LOCK_MAP"},
    {64,  "CONCURRENT_MAP_UNLOCK"},
    {65,  "CONCURRENT_MAP_FORCE_UNLOCK"},
    {66,  "CONCURRENT_MAP_UNLOCK_MAP"},
    {67,  "CONCURRENT_MAP_BLOCKS"},
    {68,  "CONCURRENT_MAP_CONTAINS_VALUE"},
    {69,  "CONCURRENT_MAP_PUT_IF_ABSENT"},
    {70,  "CONCURRENT_MAP_REMOVE_IF_SAME"},
    {71,  "CONCURRENT_MAP_REPLACE_IF_NOT_NULL"},
    {72,  "CONCURRENT_MAP_REPLACE_IF_SAME"},
    {73,  "CONCURRENT_MAP_TRY_LOCK_AND_GET"},
    {74,  "CONCURRENT_MAP_ADD_TO_LIST"},
    {75,  "CONCURRENT_MAP_ADD_TO_SET"},
    {76,  "CONCURRENT_MAP_MIGRATE_RECORD"},
    {77,  "CONCURRENT_MAP_PUT_MULTI"},
    {78,  "CONCURRENT_MAP_REMOVE_MULTI"},
    {79,  "CONCURRENT_MAP_VALUE_COUNT"},
    {80,  "CONCURRENT_MAP_BACKUP_PUT"},
    {81,  "CONCURRENT_MAP_BACKUP_REMOVE"},
    {82,  "CONCURRENT_MAP_BACKUP_REMOVE_MULTI"},
    {83,  "CONCURRENT_MAP_BACKUP_LOCK"},
    {84,  "CONCURRENT_MAP_BACKUP_ADD"},
    {85,  "CONCURRENT_MAP_INVALIDATE"},
    {86,  "CONCURRENT_MAP_EVICT"},
    {87,  "CONCURRENT_MAP_FLUSH"},
    {88,  "TRANSACTION_BEGIN"},
    {89,  "TRANSACTION_COMMIT"},
    {90,  "TRANSACTION_ROLLBACK"},
    {91,  "DESTROY"},
    {92,  "GET_ID"},
    {93,  "NEW_ID"},
    {94,  "ADD_INDEX"},
    {95,  "GET_INSTANCES"},
    {96,  "GET_MEMBERS"},
    {97,  "GET_CLUSTER_TIME"},
    {98,  "CLIENT_AUTHENTICATE"},
    {99,  "CLIENT_ADD_INSTANCE_LISTENER"},
    {100, "CLIENT_GET_PARTITIONS"},
    {101, "BLOCKING_QUEUE_REMAINING_CAPACITY"},
    {102, "BLOCKING_QUEUE_ENTRIES"},
    {103, "COUNT_DOWN_LATCH_AWAIT"},
    {104, "COUNT_DOWN_LATCH_COUNT_DOWN"},
    {105, "COUNT_DOWN_LATCH_DESTROY"},
    {106, "COUNT_DOWN_LATCH_GET_COUNT"},
    {107, "COUNT_DOWN_LATCH_GET_OWNER"},
    {108, "COUNT_DOWN_LATCH_SET_COUNT"},
    {109, "SEMAPHORE_ATTACH_DETACH_PERMITS"},
    {110, "SEMAPHORE_CANCEL_ACQUIRE"},
    {111, "SEMAPHORE_DESTROY"},
    {112, "SEMAPHORE_DRAIN_PERMITS"},
    {113, "SEMAPHORE_GET_ATTACHED_PERMITS"},
    {114, "SEMAPHORE_GET_AVAILABLE_PERMITS"},
    {115, "SEMAPHORE_REDUCE_PERMITS"},
    {116, "SEMAPHORE_RELEASE"},
    {117, "SEMAPHORE_TRY_ACQUIRE"},
    {118, "LOCK_LOCK"},
    {119, "LOCK_UNLOCK"},
    {120, "LOCK_FORCE_UNLOCK"},
    {0  , NULL}
};
static value_string_ext operationTypes_ext = VALUE_STRING_EXT_INIT(operationTypes);

static const value_string responseTypes[] = {
    {2,   "RESPONSE_NONE"},
    {3,   "RESPONSE_SUCCESS"},
    {4,   "RESPONSE_FAILURE"},
    {5,   "RESPONSE_REDO"},
    {0, NULL}
};
static value_string_ext responseTypes_ext = VALUE_STRING_EXT_INIT(responseTypes);




/* Get the length of a single HAZELCAST message */
static guint get_hazelcast_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset) {

    guint messageLength;
    guint headerKeyLength;
    guint headerValueLength;

    messageLength = tvb_get_ntohl(tvb, offset);

    headerKeyLength = tvb_get_ntohl(tvb, offset+4);

    headerValueLength = tvb_get_ntohl(tvb, offset+8);

    /*
     *    * That length doesn't include the length of the header itself add that in.
     */
    return messageLength + headerKeyLength + headerValueLength + 13;

}

static int dissect_hazelcast_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void* data _U_) {

    guint8  version;

    guint8  flags;
    guint8  operation;

    guint8  lockCountFlag;
    guint8  timeoutFlag;
    guint8  ttlFlag;
    guint8  txnFlag;
    guint8  longValueFlag;
    guint8  versionFlag;
    guint8  lockAddrNullFlag;

    guint32 nameLength;
    guint32 keyLength;
    guint32 valueLength;
    gint    offset = 0;

    proto_tree *hcast_tree = NULL;
    proto_tree *flag_tree = NULL;

    proto_item *tf = NULL;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HAZELCAST");
    col_set_str(pinfo->cinfo, COL_INFO, "Hazelcast distributed object goodness");

    if (tree) {

        proto_item *ti = NULL;
        ti = proto_tree_add_item(tree, proto_hazelcast, tvb, 0, -1, ENC_NA);

        hcast_tree = proto_item_add_subtree(ti, ett_hazelcast);
    }
    if (tvb_length_remaining(tvb, 0) < 13) {
        col_set_str(pinfo->cinfo, COL_INFO, "Hazelcast too short");
        return 0;
    }

    version = tvb_get_guint8(tvb, 12);
    if ( version != 6 ) {
        col_set_str(pinfo->cinfo, COL_INFO, "Hazelcast unsupported version");
        return 12;
    }

    proto_tree_add_item(hcast_tree, hf_hazelcast_headerLength, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(hcast_tree, hf_hazelcast_headerKeyLength, tvb, offset, 4, ENC_BIG_ENDIAN);
    keyLength = tvb_get_ntohl(tvb, offset);
    offset += 4;
    proto_tree_add_item(hcast_tree, hf_hazelcast_headerValueLength, tvb, offset, 4, ENC_BIG_ENDIAN);
    valueLength = tvb_get_ntohl(tvb, offset);
    offset += 4;
    proto_tree_add_item(hcast_tree, hf_hazelcast_headerVersion, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;


    proto_tree_add_item(hcast_tree, hf_hazelcast_operation, tvb, offset, 1, ENC_BIG_ENDIAN);
    operation = tvb_get_guint8(tvb, offset);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(operation, operationTypes, "Unknown (0x%02x)"));
    offset += 1;

    proto_tree_add_item(hcast_tree, hf_hazelcast_blockID, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(hcast_tree, hf_hazelcast_threadID, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    flags = tvb_get_guint8(tvb, offset);

    tf = proto_tree_add_item(hcast_tree, hf_hazelcast_flags, tvb, offset, 1, ENC_BIG_ENDIAN);

    flag_tree = proto_item_add_subtree(tf, ett_hazelcast_flags);

    proto_tree_add_item(flag_tree, hf_hazelcast_flags_lockCount, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_hazelcast_flags_timeout, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_hazelcast_flags_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_hazelcast_flags_txn, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_hazelcast_flags_longValue, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_hazelcast_flags_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_hazelcast_flags_client, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_hazelcast_flags_lockAddrNull, tvb, offset, 1, ENC_BIG_ENDIAN);


    lockCountFlag    = flags & HAZELCAST_LOCKCOUNT_FLAG;
    timeoutFlag      = flags & HAZELCAST_TIMEOUT_FLAG;
    ttlFlag          = flags & HAZELCAST_TTL_FLAG;
    txnFlag          = flags & HAZELCAST_TXN_FLAG;
    longValueFlag    = flags & HAZELCAST_LONGVALUE_FLAG;
    versionFlag      = flags & HAZELCAST_VERSION_FLAG;
    lockAddrNullFlag = flags & HAZELCAST_LOCKADDRNULL_FLAG;

    offset += 1;


    if ( lockCountFlag ) {
        proto_tree_add_item(hcast_tree, hf_hazelcast_lockCount, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if ( timeoutFlag ) {
        proto_tree_add_item(hcast_tree, hf_hazelcast_timeout, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if ( ttlFlag ) {
        proto_tree_add_item(hcast_tree, hf_hazelcast_ttl, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if ( txnFlag ) {
        proto_tree_add_item(hcast_tree, hf_hazelcast_txnID, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if ( longValueFlag ) {
        proto_tree_add_item(hcast_tree, hf_hazelcast_longValue, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if ( versionFlag ) {
        proto_tree_add_item(hcast_tree, hf_hazelcast_version, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if ( lockAddrNullFlag == 0 ) {
        proto_tree_add_item(hcast_tree, hf_hazelcast_lockAddrIP, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(hcast_tree, hf_hazelcast_lockAddrPort, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    proto_tree_add_item(hcast_tree, hf_hazelcast_callID, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    proto_tree_add_item(hcast_tree, hf_hazelcast_responseType, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(hcast_tree, hf_hazelcast_nameLength, tvb, offset, 4, ENC_BIG_ENDIAN);
    nameLength = tvb_get_ntohl(tvb, offset);
    offset += 4;

    if ( nameLength > 0 ) {
        proto_tree_add_item(hcast_tree, hf_hazelcast_name, tvb, offset, nameLength, ENC_ASCII|ENC_NA);
        offset += nameLength;
    }

    proto_tree_add_item(hcast_tree, hf_hazelcast_indexCount, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(hcast_tree, hf_hazelcast_keyPartitionHash, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(hcast_tree, hf_hazelcast_valuePartitionHash, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if ( keyLength > 0 ) {
        proto_tree_add_item(hcast_tree, hf_hazelcast_keys, tvb, offset, keyLength, ENC_NA);
        offset += keyLength;
    }

    if ( valueLength > 0 ) {
        proto_tree_add_item(hcast_tree, hf_hazelcast_values, tvb, offset, valueLength, ENC_NA);
        /*offset += valueLength;*/
    }

    return tvb_length(tvb);
}

/*
 * Code to actually dissect the packets
 *
 * this really just works in TCP reassembly and calls the real dissector
 *
 */
static int dissect_hazelcast(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data) {

    tcp_dissect_pdus(tvb, pinfo, tree, hazelcast_desegment, 13, get_hazelcast_message_len, dissect_hazelcast_message, data);
    return tvb_length(tvb);
}

void proto_register_hazelcast(void) {

    static hf_register_info hf[] = {

        { &hf_hazelcast_headerLength,
          { "Hazelcast hdr length", "hazelcast.hdr.length", FT_UINT32, BASE_DEC, NULL, 0x0, "header length", HFILL }
        },
        { &hf_hazelcast_headerKeyLength,
          { "Hazelcast hdr key length", "hazelcast.hdr.keylength", FT_UINT32, BASE_DEC, NULL, 0x0, "header key length", HFILL }
        },
        { &hf_hazelcast_headerValueLength,
          { "Hazelcast hdr value length", "hazelcast.hdr.valuelength", FT_UINT32, BASE_DEC, NULL, 0x0, "header value length", HFILL }
        },
        { &hf_hazelcast_headerVersion,
          { "Hazelcast hdr version", "hazelcast.hdr.version", FT_UINT8, BASE_DEC, NULL, 0x0, "header version", HFILL }
        },
        { &hf_hazelcast_operation,
          { "Hazelcast operation", "hazelcast.operation", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &operationTypes_ext, 0x0, "operation", HFILL }
        },
        { &hf_hazelcast_blockID,
          { "Hazelcast blockID", "hazelcast.blockID", FT_UINT32, BASE_HEX, NULL, 0x0, "blockID", HFILL }
        },
        { &hf_hazelcast_threadID,
          { "Hazelcast threadID", "hazelcast.threadID", FT_UINT32, BASE_DEC, NULL, 0x0, "threadID", HFILL }
        },
        { &hf_hazelcast_flags,
          { "hazelcast flags", "hazelcast.flags", FT_UINT32, BASE_HEX, NULL, 0x0, "flags", HFILL }
        },
        { &hf_hazelcast_flags_lockCount,
          { "hazelcast lockCount flag", "hazelcast.flags.lockCount", FT_BOOLEAN, 8, NULL, HAZELCAST_LOCKCOUNT_FLAG, NULL, HFILL }
        },
        { &hf_hazelcast_flags_timeout,
          { "hazelcast timeout flag", "hazelcast.flags.timeout", FT_BOOLEAN, 8, NULL, HAZELCAST_TIMEOUT_FLAG, NULL, HFILL }
        },
        { &hf_hazelcast_flags_ttl,
          { "hazelcast ttl flag", "hazelcast.flags.ttl", FT_BOOLEAN, 8, NULL, HAZELCAST_TTL_FLAG, NULL, HFILL }
        },
        { &hf_hazelcast_flags_txn,
          { "hazelcast txn flag", "hazelcast.flags.txn", FT_BOOLEAN, 8, NULL, HAZELCAST_TXN_FLAG, NULL, HFILL }
        },
        { &hf_hazelcast_flags_longValue,
          { "hazelcast longValue flag", "hazelcast.flags.longValue", FT_BOOLEAN, 8, NULL, HAZELCAST_LONGVALUE_FLAG, NULL, HFILL }
        },
        { &hf_hazelcast_flags_version,
          { "hazelcast version flag", "hazelcast.flags.version", FT_BOOLEAN, 8, NULL, HAZELCAST_VERSION_FLAG, NULL, HFILL }
        },
        { &hf_hazelcast_flags_client,
          { "hazelcast client flag", "hazelcast.flags.client", FT_BOOLEAN, 8, NULL, HAZELCAST_CLIENT_FLAG, NULL, HFILL }
        },
        { &hf_hazelcast_flags_lockAddrNull,
          { "hazelcast lockAddrNull flag", "hazelcast.flags.lockAddrNull", FT_BOOLEAN, 8, NULL, HAZELCAST_LOCKADDRNULL_FLAG, NULL, HFILL }
        },
        { &hf_hazelcast_timeout,
          { "hazelcast timeout", "hazelcast.timeout", FT_UINT64, BASE_DEC, NULL, 0x0, "timeout", HFILL }
        },
        { &hf_hazelcast_ttl,
          { "hazelcast ttl", "hazelcast.ttl", FT_UINT64, BASE_DEC, NULL, 0x0, "ttl", HFILL }
        },
        { &hf_hazelcast_longValue,
          { "hazelcast longValue", "hazelcast.longValue", FT_UINT64, BASE_DEC, NULL, 0x0, "longValue", HFILL }
        },
        { &hf_hazelcast_txnID,
          { "hazelcast txnID", "hazelcast.txnID", FT_UINT64, BASE_DEC, NULL, 0x0, "txnID", HFILL }
        },
        { &hf_hazelcast_version,
          { "hazelcast version", "hazelcast.version", FT_UINT64, BASE_DEC, NULL, 0x0, "version", HFILL }
        },
        { &hf_hazelcast_lockCount,
          { "hazelcast lockCount", "hazelcast.lockCount", FT_UINT32, BASE_DEC, NULL, 0x0, "lockCount", HFILL }
        },
        { &hf_hazelcast_lockAddrIP,
          { "hazelcast lock address IP", "hazelcast.lockaddr.ip", FT_IPv4, BASE_NONE, NULL, 0x0, "lockAddrIP", HFILL }
        },
        { &hf_hazelcast_lockAddrPort,
          { "hazelcast lock address Port", "hazelcast.lockaddr.port", FT_UINT32, BASE_DEC, NULL, 0x0, "lockAddrPort", HFILL }
        },
        { &hf_hazelcast_callID,
          { "hazelcast callID", "hazelcast.callID", FT_INT64, BASE_DEC, NULL, 0x0, "callID", HFILL }
        },
        { &hf_hazelcast_responseType,
          { "hazelcast response type", "hazelcast.responseType", FT_UINT8, BASE_DEC|BASE_EXT_STRING, &responseTypes_ext, 0x0, "responseType", HFILL }
        },
        { &hf_hazelcast_nameLength,
          { "hazelcast name length", "hazelcast.nameLength", FT_UINT32, BASE_DEC, NULL, 0x0, "nameLength", HFILL }
        },
        { &hf_hazelcast_name,
          { "hazelcast name", "hazelcast.name", FT_STRING, BASE_NONE, NULL, 0x0, "name", HFILL }
        },
        { &hf_hazelcast_indexCount,
          { "hazelcast indexCount", "hazelcast.indexCount", FT_UINT8, BASE_DEC, NULL, 0x0, "indexCount", HFILL }
        },
        { &hf_hazelcast_keyPartitionHash,
          { "hazelcast keyPartitionHash", "hazelcast.keyPartitionHash", FT_UINT32, BASE_HEX, NULL, 0x0, "keyPartitionHash", HFILL }
        },
        { &hf_hazelcast_valuePartitionHash,
          { "hazelcast valuePartitionHash", "hazelcast.valuePartitionHash", FT_UINT32, BASE_HEX, NULL, 0x0, "valuePartitionHash", HFILL }
        },
        { &hf_hazelcast_keys,
          { "hazelcast keys", "hazelcast.keys", FT_BYTES, BASE_NONE, NULL, 0x0, "keys", HFILL }
        },
        { &hf_hazelcast_values,
          { "hazelcast values", "hazelcast.values", FT_BYTES, BASE_NONE, NULL, 0x0, "values", HFILL }
        }

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_hazelcast,
        &ett_hazelcast_flags
    };

    module_t *hazelcast_module;


    proto_hazelcast = proto_register_protocol (
        "Hazelcast Wire Protocol", /* name */
        "HAZELCAST",      /* short name */
        "hzlcst"       /* abbrev     */
        );

    proto_register_field_array(proto_hazelcast, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    hazelcast_module = prefs_register_protocol(proto_hazelcast, NULL);

    prefs_register_bool_preference(hazelcast_module, "desegment",
                                   "Reassemble hazelcast messages spanning multiple TCP segments",
                                   "Whether the hazel dissector should reassemble messages spanning multiple TCP segments."
                                   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &hazelcast_desegment);

    prefs_register_uint_preference(hazelcast_module, "tcp.port",
                                   "Hazelcast TCP Port",
                                   " Hazelcast TCP port if other than the default",
                                   10,
                                   &gPORT_PREF);

    hazelcast_tap = register_tap("hzlcst");

}


void
proto_reg_handoff_hazelcast(void) {
    static gboolean initialized = FALSE;
    static dissector_handle_t hazelcast_handle;
    static int currentPort;

    if (!initialized) {
        hazelcast_handle = new_create_dissector_handle(dissect_hazelcast, proto_hazelcast);
        initialized = TRUE;
    } else {
        dissector_delete_uint("tcp.port", currentPort, hazelcast_handle);
    }

    currentPort = gPORT_PREF;
    dissector_add_uint("tcp.port", currentPort, hazelcast_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

