/* packet-scylla.c
 * Routines for Scylla RPC dissection
 * Copyright 2020 ScyllaDB, Piotr Sarna <sarna@scylladb.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * ScyllaDB RPC protocol is used for inter-node communication
 * in the ScyllaDB database - reading/sending data, exchanging
 * cluster information through gossip, updating schemas, etc.
 *
 * Protocol references:
 * https://github.com/scylladb/seastar/blob/master/doc/rpc.md
 * https://github.com/scylladb/scylla/blob/master/message/messaging_service.hh
 *
 */

#include <config.h>

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-tcp.h"

void proto_reg_handoff_scylla(void);
void proto_register_scylla(void);

static dissector_handle_t scylla_handle;

#define SCYLLA_PORT 0 /* Not IANA registered, 7000 is the expected value */

#define SCYLLA_HEADER_SIZE 28
#define SCYLLA_HEADER_VERB_OFFSET 8
#define SCYLLA_HEADER_MSG_ID_OFFSET 16
#define SCYLLA_HEADER_LEN_OFFSET 24

#define SCYLLA_RESPONSE_SIZE 12
#define SCYLLA_RESPONSE_MSG_ID_OFFSET 0
#define SCYLLA_RESPONSE_LEN_OFFSET 8

#define SCYLLA_NEGOTIATION_SIZE 12
#define SCYLLA_NEGOTIATION_LEN_OFFSET 8

static int proto_scylla;

static int hf_scylla_request;
static int hf_scylla_request_response_frame;
static int hf_scylla_timeout;
static int hf_scylla_verb;
static int hf_scylla_msg_id;
static int hf_scylla_len;
static int hf_scylla_response;
static int hf_scylla_response_size;
static int hf_scylla_response_request_frame;
static int hf_scylla_negotiation_magic;
static int hf_scylla_negotiation_size;
static int hf_scylla_payload; // TODO: dissect everything, so that generic "payload" is not needed

// Mutation
static int hf_scylla_mut_size1;
static int hf_scylla_mut_size2;
static int hf_scylla_mut_table_id;
static int hf_scylla_mut_schema_id;
static int hf_scylla_mut_len_pkeys;
static int hf_scylla_mut_num_pkeys;
static int hf_scylla_mut_len_pkey;
static int hf_scylla_mut_pkey;

// Read data
static int hf_scylla_read_data_timeout;
static int hf_scylla_read_data_table_id;
static int hf_scylla_read_data_schema_version;

static int ett_scylla;
static int ett_scylla_header;
static int ett_scylla_response;
static int ett_scylla_negotiation;
static int ett_scylla_mut;
static int ett_scylla_mut_pkey;
static int ett_scylla_read_data;

static bool scylla_desegment = true;

static expert_field ei_scylla_response_missing;

enum scylla_packets {
    CLIENT_ID = 0,
    MUTATION = 1,
    MUTATION_DONE = 2,
    READ_DATA = 3,
    READ_MUTATION_DATA = 4,
    READ_DIGEST = 5,
    // Used by gossip
    GOSSIP_DIGEST_SYN = 6,
    GOSSIP_DIGEST_ACK = 7,
    GOSSIP_DIGEST_ACK2 = 8,
    GOSSIP_ECHO = 9,
    GOSSIP_SHUTDOWN = 10,
    // end of gossip verb
    DEFINITIONS_UPDATE = 11,
    TRUNCATE = 12,
    REPLICATION_FINISHED = 13,
    MIGRATION_REQUEST = 14,
    // Used by streaming
    PREPARE_MESSAGE = 15,
    PREPARE_DONE_MESSAGE = 16,
    STREAM_MUTATION = 17,
    STREAM_MUTATION_DONE = 18,
    COMPLETE_MESSAGE = 19,
    // end of streaming verbs
    REPAIR_CHECKSUM_RANGE = 20,
    GET_SCHEMA_VERSION = 21,
    SCHEMA_CHECK = 22,
    COUNTER_MUTATION = 23,
    MUTATION_FAILED = 24,
    STREAM_MUTATION_FRAGMENTS = 25,
    REPAIR_ROW_LEVEL_START = 26,
    REPAIR_ROW_LEVEL_STOP = 27,
    REPAIR_GET_FULL_ROW_HASHES = 28,
    REPAIR_GET_COMBINED_ROW_HASH = 29,
    REPAIR_GET_SYNC_BOUNDARY = 30,
    REPAIR_GET_ROW_DIFF = 31,
    REPAIR_PUT_ROW_DIFF = 32,
    REPAIR_GET_ESTIMATED_PARTITIONS = 33,
    REPAIR_SET_ESTIMATED_PARTITIONS = 34,
    REPAIR_GET_DIFF_ALGORITHMS = 35,
    REPAIR_GET_ROW_DIFF_WITH_RPC_STREAM = 36,
    REPAIR_PUT_ROW_DIFF_WITH_RPC_STREAM = 37,
    REPAIR_GET_FULL_ROW_HASHES_WITH_RPC_STREAM = 38,
    PAXOS_PREPARE = 39,
    PAXOS_ACCEPT = 40,
    PAXOS_LEARN = 41,
    HINT_MUTATION = 42,
    PAXOS_PRUNE = 43,
    LAST = 44,
};

static const val64_string packettypenames[] = {
    {CLIENT_ID,                                  "CLIENT_ID"},
    {MUTATION,                                   "MUTATION"},
    {MUTATION_DONE,                              "MUTATION_DONE"},
    {READ_DATA,                                  "READ_DATA"},
    {READ_MUTATION_DATA,                         "READ_MUTATION_DATA"},
    {READ_DIGEST,                                "READ_DIGEST"},
    {GOSSIP_DIGEST_SYN,                          "GOSSIP_DIGEST_SYN"},
    {GOSSIP_DIGEST_ACK,                          "GOSSIP_DIGEST_ACK"},
    {GOSSIP_DIGEST_ACK2,                         "GOSSIP_DIGEST_ACK2"},
    {GOSSIP_ECHO,                                "GOSSIP_ECHO"},
    {GOSSIP_SHUTDOWN,                            "GOSSIP_SHUTDOWN"},
    {DEFINITIONS_UPDATE,                         "DEFINITIONS_UPDATE"},
    {TRUNCATE,                                   "TRUNCATE"},
    {REPLICATION_FINISHED,                       "REPLICATION_FINISHED"},
    {MIGRATION_REQUEST,                          "MIGRATION_REQUEST"},
    {PREPARE_MESSAGE,                            "PREPARE_MESSAGE"},
    {PREPARE_DONE_MESSAGE,                       "PREPARE_DONE_MESSAGE"},
    {STREAM_MUTATION,                            "STREAM_MUTATION"},
    {STREAM_MUTATION_DONE,                       "STREAM_MUTATION_DONE"},
    {COMPLETE_MESSAGE,                           "COMPLETE_MESSAGE"},
    {REPAIR_CHECKSUM_RANGE,                      "REPAIR_CHECKSUM_RANGE"},
    {GET_SCHEMA_VERSION,                         "GET_SCHEMA_VERSION"},
    {SCHEMA_CHECK,                               "SCHEMA_CHECK"},
    {COUNTER_MUTATION,                           "COUNTER_MUTATION"},
    {MUTATION_FAILED,                            "MUTATION_FAILED"},
    {STREAM_MUTATION_FRAGMENTS,                  "STREAM_MUTATION_FRAGMENTS"},
    {REPAIR_ROW_LEVEL_START,                     "REPAIR_ROW_LEVEL_START"},
    {REPAIR_ROW_LEVEL_STOP,                      "REPAIR_ROW_LEVEL_STOP"},
    {REPAIR_GET_FULL_ROW_HASHES,                 "REPAIR_GET_FULL_ROW_HASHES"},
    {REPAIR_GET_COMBINED_ROW_HASH,               "REPAIR_GET_COMBINED_ROW_HASH"},
    {REPAIR_GET_SYNC_BOUNDARY,                   "REPAIR_GET_SYNC_BOUNDARY"},
    {REPAIR_GET_ROW_DIFF,                        "REPAIR_GET_ROW_DIFF"},
    {REPAIR_PUT_ROW_DIFF,                        "REPAIR_PUT_ROW_DIFF"},
    {REPAIR_GET_ESTIMATED_PARTITIONS,            "REPAIR_GET_ESTIMATED_PARTITIONS"},
    {REPAIR_SET_ESTIMATED_PARTITIONS,            "REPAIR_SET_ESTIMATED_PARTITIONS"},
    {REPAIR_GET_DIFF_ALGORITHMS,                 "REPAIR_GET_DIFF_ALGORITHMS"},
    {REPAIR_GET_ROW_DIFF_WITH_RPC_STREAM,        "REPAIR_GET_ROW_DIFF_WITH_RPC_STREAM"},
    {REPAIR_PUT_ROW_DIFF_WITH_RPC_STREAM,        "REPAIR_PUT_ROW_DIFF_WITH_RPC_STREAM"},
    {REPAIR_GET_FULL_ROW_HASHES_WITH_RPC_STREAM, "REPAIR_GET_FULL_ROW_HASHES_WITH_RPC_STREAM"},
    {PAXOS_PREPARE,                              "PAXOS_PREPARE"},
    {PAXOS_ACCEPT,                               "PAXOS_ACCEPT"},
    {PAXOS_LEARN,                                "PAXOS_LEARN"},
    {HINT_MUTATION,                              "HINT_MUTATION"},
    {PAXOS_PRUNE,                                "PAXOS_PRUNE"},
    {0, NULL}
};

static bool
looks_like_rpc_negotiation(tvbuff_t *tvb, const int offset) {
    return tvb_memeql(tvb, offset, (const uint8_t *)"SSTARRPC", 8) == 0;
}

static bool
looks_like_response(uint64_t verb_type, uint32_t len) {
    return verb_type >= LAST || len > 64*1024*1024;
}

typedef struct {
    uint64_t verb_type;
    uint32_t request_frame_num;
    uint32_t response_frame_num;
} request_response_t;

static unsigned
get_scylla_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    uint64_t verb_type = LAST;
    uint32_t plen = 0;
    if (looks_like_rpc_negotiation(tvb, offset)) {
        return tvb_get_letohl(tvb, offset + SCYLLA_NEGOTIATION_LEN_OFFSET) + SCYLLA_NEGOTIATION_SIZE;
    }
    if (tvb_reported_length(tvb) >= SCYLLA_HEADER_SIZE) {
        plen = tvb_get_letohl(tvb, offset + SCYLLA_HEADER_LEN_OFFSET);
        verb_type = tvb_get_letoh64(tvb, offset + SCYLLA_HEADER_VERB_OFFSET);
    }

    if (looks_like_response(verb_type, plen)) {
        return tvb_get_letohl(tvb, offset + SCYLLA_RESPONSE_LEN_OFFSET) + SCYLLA_RESPONSE_SIZE;
    }
    return plen + SCYLLA_HEADER_SIZE;
}

static int
dissect_scylla_negotiation_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *scylla_tree)
{
    int offset = 0;
    uint32_t len = tvb_get_letohl(tvb, offset + SCYLLA_NEGOTIATION_LEN_OFFSET) + SCYLLA_NEGOTIATION_SIZE;

    proto_tree *scylla_negotiation_tree = proto_tree_add_subtree(scylla_tree, tvb, offset,
            len, ett_scylla_negotiation, NULL, "Protocol negotiation");
    proto_tree_add_item(scylla_negotiation_tree, hf_scylla_negotiation_magic, tvb, offset, 8, ENC_ASCII);
    int negotiation_offset = 8;
    proto_tree_add_item(scylla_negotiation_tree, hf_scylla_negotiation_size, tvb, offset + negotiation_offset, 4, ENC_LITTLE_ENDIAN);
    negotiation_offset += 4;
    proto_tree_add_item(scylla_negotiation_tree, hf_scylla_payload, tvb, offset + negotiation_offset, len - negotiation_offset, ENC_NA);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Scylla");
    col_set_str(pinfo->cinfo, COL_INFO, "Protocol negotiation");
    return tvb_reported_length(tvb);
}

static int
dissect_scylla_response_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *scylla_tree, request_response_t *req_resp)
{
    int offset = 0;
    uint32_t len = tvb_get_letohl(tvb, offset + SCYLLA_RESPONSE_LEN_OFFSET) + SCYLLA_RESPONSE_SIZE;

    /* Add response subtree */
    proto_item *response_ti = proto_tree_add_string_format(scylla_tree, hf_scylla_response,
                                                           tvb, offset, len, "", "Response");
    proto_tree *scylla_response_tree = proto_item_add_subtree(response_ti, ett_scylla_response);

    int resp_offset = 0;

    uint64_t msg_id;
    proto_tree_add_item_ret_uint64(scylla_response_tree, hf_scylla_msg_id, tvb, offset + resp_offset, 8, ENC_LITTLE_ENDIAN, &msg_id);
    resp_offset += 8;
    proto_tree_add_item(scylla_response_tree, hf_scylla_response_size, tvb, offset + resp_offset, 4, ENC_LITTLE_ENDIAN);
    resp_offset += 4;
    proto_tree_add_item(scylla_response_tree, hf_scylla_payload, tvb, offset + resp_offset, len - resp_offset, ENC_NA);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Scylla");
    if (req_resp) {
        /* Fill in the response frame */
        req_resp->response_frame_num = pinfo->num;

        proto_item *verb_item = proto_tree_add_uint64(scylla_response_tree, hf_scylla_verb, tvb, offset + len, 8, req_resp->verb_type);
        proto_item_set_generated(verb_item);
        proto_item *req = proto_tree_add_uint(scylla_tree, hf_scylla_response_request_frame, tvb, 0, 0, req_resp->request_frame_num);
        proto_item_set_generated(req);

        proto_item_append_text(response_ti, " (msg_id=%" PRIu64 ", %s)",
                               msg_id, val64_to_str(req_resp->verb_type, packettypenames, "Unknown (0x%02x)"));

        col_clear(pinfo->cinfo, COL_INFO);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Response for %s",
            val64_to_str(req_resp->verb_type, packettypenames, "Unknown (0x%02x)"));
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "Response for unknown packet");
    }
    return tvb_reported_length(tvb);
}

static int
dissect_scylla_msg_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *scylla_tree, proto_item *ti, uint64_t verb_type, uint32_t len, request_response_t *req_resp)
{
    int offset = 0;

    /* Add request subtree */
    proto_item *request_ti = proto_tree_add_string_format(scylla_tree, hf_scylla_request,
                                                          tvb, offset, SCYLLA_HEADER_SIZE,
                                                          "", "Header for %s",
                                                          val64_to_str(verb_type, packettypenames, "Unknown (0x%02x)"));
    proto_tree *scylla_header_tree = proto_item_add_subtree(request_ti, ett_scylla_response);

    proto_tree_add_item(scylla_header_tree, hf_scylla_timeout, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    proto_item_append_text(ti, ", Type %s", val64_to_str(verb_type, packettypenames, "Unknown (0x%02x)"));
    proto_tree_add_item(scylla_header_tree, hf_scylla_verb, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;
    uint64_t msg_id;
    proto_tree_add_item_ret_uint64(scylla_header_tree, hf_scylla_msg_id, tvb, offset, 8, ENC_LITTLE_ENDIAN, &msg_id);
    offset += 8;
    proto_tree_add_item(scylla_header_tree, hf_scylla_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_item_append_text(request_ti, " (msg_id=%" PRIu64 ")", msg_id);

    switch (verb_type) {
    case MUTATION: {
        proto_tree* scylla_mut_tree = proto_tree_add_subtree(scylla_tree, tvb, offset,
                len, ett_scylla_mut, NULL, "Mutation");
        int mut_offset = 0;
        uint32_t len_keys;
        uint32_t num_keys;
        proto_tree_add_item(scylla_mut_tree, hf_scylla_mut_size1, tvb, offset + mut_offset, 4, ENC_LITTLE_ENDIAN);
        mut_offset += 4;
        proto_tree_add_item(scylla_mut_tree, hf_scylla_mut_size2, tvb, offset + mut_offset, 4, ENC_LITTLE_ENDIAN);
        mut_offset += 4;
        proto_tree_add_item(scylla_mut_tree, hf_scylla_mut_table_id, tvb, offset + mut_offset, 16, ENC_NA);
        mut_offset += 16;
        proto_tree_add_item(scylla_mut_tree, hf_scylla_mut_schema_id, tvb, offset + mut_offset, 16, ENC_NA);
        mut_offset += 16;
        proto_tree_add_item_ret_uint(scylla_mut_tree, hf_scylla_mut_len_pkeys, tvb, offset + mut_offset, 4, ENC_LITTLE_ENDIAN, &len_keys);
        mut_offset += 4;
        proto_tree* scylla_mut_pkey_tree = proto_tree_add_subtree(scylla_mut_tree, tvb, offset + mut_offset,
                len - mut_offset, ett_scylla_mut_pkey, NULL, "Partition key");
        proto_tree_add_item_ret_uint(scylla_mut_pkey_tree, hf_scylla_mut_num_pkeys, tvb, offset + mut_offset, 4, ENC_LITTLE_ENDIAN, &num_keys);
        mut_offset += 4;
        unsigned i;
        for (i = 0; i < num_keys; ++i) {
            uint32_t len_pkey = tvb_get_letohl(tvb, offset + mut_offset);
            proto_tree_add_item(scylla_mut_pkey_tree, hf_scylla_mut_len_pkey, tvb, offset + mut_offset, 4, ENC_LITTLE_ENDIAN);
            mut_offset += 4;
            proto_tree_add_item(scylla_mut_pkey_tree, hf_scylla_mut_pkey, tvb, offset + mut_offset, len_pkey, ENC_NA);
            mut_offset += len_pkey;
        }
        // TODO: dissect further
        proto_tree_add_item(scylla_mut_tree, hf_scylla_payload, tvb, offset + mut_offset, len - mut_offset, ENC_NA);
        }
        break;
    case READ_DATA: {
        proto_tree* scylla_read_tree = proto_tree_add_subtree(scylla_tree, tvb, offset,
                len, ett_scylla_read_data, NULL, "Read data");
        int rd_offset = 0;

        proto_tree_add_item(scylla_read_tree, hf_scylla_read_data_timeout, tvb, offset + rd_offset, 4, ENC_LITTLE_ENDIAN);
        rd_offset += 4;
        proto_tree_add_item(scylla_read_tree, hf_scylla_read_data_table_id, tvb, offset + rd_offset, 16, ENC_NA);
        rd_offset += 16;
        proto_tree_add_item(scylla_read_tree, hf_scylla_read_data_schema_version, tvb, offset + rd_offset, 16, ENC_NA);
        rd_offset += 16;
        //TODO: dissect further
        proto_tree_add_item(scylla_read_tree, hf_scylla_payload, tvb, offset + rd_offset, len - rd_offset, ENC_NA);
        }
        break;
    default:
        // Generic payload. TODO: dissect
        proto_tree_add_item(scylla_tree, hf_scylla_payload, tvb, offset, len, ENC_NA);
        break;
    }

    /* req_resp will only be set if fd was already visited (PINFO_FD_VISITED(pinfo)) */
    if (req_resp) {
        if (req_resp->response_frame_num > 0) {
            proto_item *rep = proto_tree_add_uint(scylla_tree, hf_scylla_request_response_frame, tvb, 0, 0, req_resp->response_frame_num);
            proto_item_set_generated(rep);
        } else {
            expert_add_info(pinfo, request_ti, &ei_scylla_response_missing);
        }
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Scylla");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Request %s",
             val64_to_str(verb_type, packettypenames, "Unknown (0x%02x)"));
    return tvb_reported_length(tvb);
}

static bool
response_expected(uint64_t verb_type)
{
    switch (verb_type) {
    case GOSSIP_DIGEST_SYN:
    case GOSSIP_DIGEST_ACK:
    case GOSSIP_DIGEST_ACK2:
    case GOSSIP_SHUTDOWN:
    case DEFINITIONS_UPDATE:
    case MUTATION:
    case MUTATION_DONE:
    case MUTATION_FAILED:
    case HINT_MUTATION:
    case PAXOS_LEARN:
    case PAXOS_PRUNE:
        return false;
    default:
        return true;
    }
}


static int
dissect_scylla_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;
    conversation_t *conversation;
    wmem_map_t *conv_map;

    proto_item *ti = proto_tree_add_item(tree, proto_scylla, tvb, 0, -1, ENC_NA);
    proto_tree *scylla_tree = proto_item_add_subtree(ti, ett_scylla);

    uint64_t verb_type = LAST;
    uint32_t len = 0;

    if (looks_like_rpc_negotiation(tvb, offset)) {
        return dissect_scylla_negotiation_pdu(tvb, pinfo, scylla_tree);
    }

    if (tvb_reported_length(tvb) >= SCYLLA_HEADER_SIZE) {
        verb_type = tvb_get_letoh64(tvb, offset + SCYLLA_HEADER_VERB_OFFSET);
        len = tvb_get_letohl(tvb, offset + SCYLLA_HEADER_LEN_OFFSET);
    }

    conversation = find_or_create_conversation(pinfo);
    conv_map  = (wmem_map_t *)conversation_get_proto_data(conversation, proto_scylla);
    if (conv_map == NULL) {
        conv_map = wmem_map_new(wmem_file_scope(), wmem_int64_hash, g_int64_equal);
        conversation_add_proto_data(conversation, proto_scylla, conv_map);
    }

    if (looks_like_response(verb_type, len)) {
        void *req_resp;
        uint64_t msg_id;
        msg_id = tvb_get_letoh64(tvb, offset + SCYLLA_RESPONSE_MSG_ID_OFFSET);
        req_resp = wmem_map_lookup(conv_map, &msg_id);
        return dissect_scylla_response_pdu(tvb, pinfo, scylla_tree, (request_response_t *)req_resp);
    }

    uint64_t msg_id = tvb_get_letoh64(tvb, offset + SCYLLA_HEADER_MSG_ID_OFFSET);
    void *req_resp = NULL;

    if (response_expected(verb_type)) {
        if (!PINFO_FD_VISITED(pinfo)) {
            uint64_t *key = wmem_new(wmem_file_scope(), uint64_t);
            request_response_t *val = wmem_new(wmem_file_scope(), request_response_t);
            *key = msg_id;
            val->verb_type = verb_type;
            val->request_frame_num = pinfo->num;
            wmem_map_insert(conv_map, key, val);
        } else {
            req_resp = wmem_map_lookup(conv_map, &msg_id);
        }
    }

    return dissect_scylla_msg_pdu(tvb, pinfo, scylla_tree, ti, verb_type, len, (request_response_t *)req_resp);
}

static int
dissect_scylla(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, scylla_desegment, SCYLLA_NEGOTIATION_SIZE,
        get_scylla_pdu_len, dissect_scylla_pdu, data);
    return tvb_reported_length(tvb);
}

void
proto_register_scylla(void)
{
    static hf_register_info hf[] = {
        // RPC header
        { &hf_scylla_request, { "request", "scylla.request", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_request_response_frame, { "Response frame", "scylla.request.response", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0, NULL, HFILL } },
        { &hf_scylla_timeout, { "RPC timeout", "scylla.timeout", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_verb, { "verb", "scylla.verb", FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(packettypenames), 0x0, NULL, HFILL } },
        { &hf_scylla_msg_id, { "msg id", "scylla.msg_id", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_len, { "packet length", "scylla.len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_payload, { "payload", "scylla.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_response, { "response", "scylla.response", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_response_size, { "response size", "scylla.response.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_response_request_frame, { "Request frame", "scylla.response.request", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0, NULL, HFILL } },
        { &hf_scylla_negotiation_magic, { "negotiation magic sequence", "scylla.negotiation.magic", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_negotiation_size, { "negotiation size", "scylla.negotiation.size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        // mutation verb
        { &hf_scylla_mut_size1, { "mutation size 1", "scylla.mut.size1", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_mut_size2, { "mutation size 2", "scylla.mut.size2", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_mut_table_id, { "mutation table id", "scylla.mut.table_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_mut_schema_id, { "mutation schema id", "scylla.mut.schema_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_mut_len_pkeys, { "size of partition keys payload", "scylla.mut.len_pkeys", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_mut_num_pkeys, { "number of partition keys", "scylla.mut.num_pkeys", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_mut_len_pkey, { "length of a partition key", "scylla.mut.len_pkey", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_mut_pkey, { "partition key", "scylla.mut.pkey", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        // read_data verb
        { &hf_scylla_read_data_timeout, { "timeout", "scylla.read_data.timeout", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_read_data_table_id, { "table ID", "scylla.read_data.table_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_scylla_read_data_schema_version, { "Schema version", "scylla.read_data.schema_version", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

    };

    static ei_register_info ei[] = {
        { &ei_scylla_response_missing,
          { "scylla.ei_scylla_response_missing",
                  PI_COMMENTS_GROUP, PI_NOTE, "Response has not arrived yet", EXPFILL }},
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_scylla,
        &ett_scylla_header,
        &ett_scylla_response,
        &ett_scylla_negotiation,
        &ett_scylla_mut,
        &ett_scylla_mut_pkey,
        &ett_scylla_read_data,
    };

    expert_module_t* expert_scylla;

    proto_scylla = proto_register_protocol("Scylla RPC protocol", "Scylla", "scylla");
    module_t* scylla_module = prefs_register_protocol(proto_scylla, NULL);
    prefs_register_bool_preference(scylla_module, "desegment",
        "Desegment all Scylla messages spanning multiple TCP segments",
        "Whether Scylla dissector should desegment all messages spanning multiple TCP segments",
        &scylla_desegment);

    proto_register_field_array(proto_scylla, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_scylla = expert_register_protocol(proto_scylla);
    expert_register_field_array(expert_scylla, ei, array_length(ei));

    scylla_handle = register_dissector("scylla", dissect_scylla, proto_scylla);
}

void
proto_reg_handoff_scylla(void)
{
    dissector_add_uint_with_preference("tcp.port", SCYLLA_PORT, scylla_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
