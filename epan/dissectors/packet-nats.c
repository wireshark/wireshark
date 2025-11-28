/* packet-nats.c
 * Routines for NATS Client Protocol dissection
 * https://docs.nats.io/reference/reference-protocols/nats-protocol
 *
 * Copyright 2025, Max Dmitrichenko <dmitrmax@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/dissectors/packet-nats.h>
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/proto_data.h>
#include <epan/strutil.h>

#include <wsutil/strtoi.h>
#include <wsutil/utf8_entities.h>

static const uint32_t NATS_PORT = 4222;
static const int EOL_LEN = 2; // CRLF length

static int proto_nats;
static dissector_handle_t handle_nats;
static dissector_table_t subject_table;

static int hf_nats_op;
static int hf_nats_subject;
static int hf_nats_reply_to;
static int hf_nats_subscription_id;
static int hf_nats_queue_group;
static int hf_nats_max_msgs;
static int hf_nats_total_bytes;
static int hf_nats_header_bytes;
static int hf_nats_body_bytes;
static int hf_nats_headers;
static int hf_nats_headers_version;
static int hf_nats_headers_header;
static int hf_nats_features;
static int hf_nats_req_latency;
static int hf_nats_rsp_latency;
static int hf_nats_req_frame_ref;
static int hf_nats_rsp_frame_ref;

static int ett_nats;
static int ett_nats_headers;

/** Request/Response matching data. */
typedef struct _nats_request_info
{
    const char* req_subject;
    uint32_t req_frame_num;
    uint32_t rsp_frame_num;
    nstime_t req_abs_ts;
    nstime_t rsp_abs_ts;
} nats_request_info_t;

/** Per-TVB data of a NATS. */
typedef struct _nats_tvb_info
{
    wmem_map_t* req_table;
    wmem_map_t* rsp_table;
} nats_tvb_info_t;

/** Conversation data of a NATS connection. */
typedef struct _nats_conv_t
{
    /* Used for req/res matching */
    wmem_map_t* matches_table;
} nats_conv_t;

/** Parsing helper */
typedef struct _nats_request_token
{
    int offset;
    int length;
    const char* value;
} nats_request_token_t;

/** Context for the dissector search in the table */
typedef struct _nats_dissector_search_context
{
    const char* subject;
    dissector_handle_t dissector;
} nats_dissector_search_context_t;

static nats_tvb_info_t* get_tvb_info(packet_info* pinfo)
{
    nats_tvb_info_t* tvb_info =
        p_get_proto_data(wmem_file_scope(), pinfo, proto_nats, 0);
    return tvb_info;
}

static nats_tvb_info_t* get_or_create_tvb_info(packet_info* pinfo)
{
    nats_tvb_info_t* tvb_info =
        p_get_proto_data(wmem_file_scope(), pinfo, proto_nats, 0);

    if (!PINFO_FD_VISITED(pinfo) && tvb_info == NULL)
    {
        tvb_info = wmem_alloc(wmem_file_scope(), sizeof(nats_tvb_info_t));
        tvb_info->req_table =
            wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);

        tvb_info->rsp_table =
            wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);

        p_set_proto_data(wmem_file_scope(), pinfo, proto_nats, 0, tvb_info);
    }

    return tvb_info;
}

static nats_conv_t* get_nats_conversation_data(packet_info* pinfo,
                                               conversation_t** conversation)
{
    nats_conv_t* conv_data;

    *conversation = find_or_create_conversation(pinfo);

    /* Retrieve information from conversation
     * or add it if it isn't there yet
     */
    conv_data =
        (nats_conv_t *) conversation_get_proto_data(*conversation, proto_nats);
    if (!conv_data)
    {
        /* Setup the conversation structure itself */
        conv_data = wmem_new0(wmem_file_scope(), nats_conv_t);
        conv_data->matches_table =
            wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);

        conversation_add_proto_data(*conversation, proto_nats, conv_data);
        conversation_set_dissector_from_frame_number(*conversation, pinfo->num,
                                                     handle_nats);
    }

    return conv_data;
}

static proto_tree* nats_get_or_create_proto_tree(tvbuff_t* tvb, int offset, int length, proto_tree* parent)
{
    proto_item* ti = proto_tree_add_protocol_format(parent, proto_nats, tvb, offset, length, "NATS PDU (%d bytes)",
                                                    length);
    proto_tree* result = proto_item_add_subtree(ti, ett_nats);

    return result;
}


static size_t nats_parse_tokens(tvbuff_t* tvb, int offset, int last_offset, packet_info* pinfo,
                                nats_request_token_t* tokens, size_t max_tokens)
{
    int current_offset = offset;

    for (size_t i = 0; i < max_tokens; i++)
    {
        int token_length = tvb_get_token_len(
            tvb, current_offset, last_offset - current_offset, NULL, false);
        if (!token_length)
            return i;

        tokens[i].offset = current_offset;
        tokens[i].length = token_length;

        tokens[i].value = (char*)tvb_get_string_enc(
            pinfo->pool, tvb, current_offset, token_length, ENC_UTF_8);

        current_offset += token_length;

        current_offset =
            tvb_skip_wsp(tvb, current_offset, last_offset - current_offset);
    }

    return max_tokens;
}

static void dissect_nats_headers(tvbuff_t* tvb, int offset, int end_offset,
                                 packet_info* pinfo,
                                 proto_tree* tree, nats_data_t* nats_data)
{
    int len = end_offset - offset;
    int next_offset = 0;
    tvb_find_line_end(tvb, offset, len, &next_offset, false);

    proto_item* ti;
    proto_tree* header_tree;

    ti = proto_tree_add_item(tree, hf_nats_headers, tvb, offset,
                             end_offset - offset, ENC_NA);
    header_tree = proto_item_add_subtree(ti, ett_nats_headers);

    proto_tree_add_item(header_tree, hf_nats_headers_version, tvb, offset,
                        next_offset - offset - EOL_LEN, ENC_ASCII);

    len -= next_offset - offset;
    offset = next_offset;

    nats_data->headers_map = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);

    while (tvb_find_line_end(tvb, offset, len, &next_offset, false) > 0)
    {
        int colon_offset = tvb_find_uint8(tvb, offset, next_offset - offset, ':');
        if (colon_offset != -1)
        {
            const uint8_t* header_name = tvb_get_string_enc(pinfo->pool, tvb, offset, colon_offset - offset, ENC_UTF_8);
            int value_offset = tvb_skip_wsp(tvb, colon_offset + 1, next_offset - colon_offset - EOL_LEN - 1);
            const uint8_t* header_value = tvb_get_string_enc(pinfo->pool, tvb, value_offset,
                                                             next_offset - value_offset - EOL_LEN, ENC_UTF_8);

            wmem_list_t* list = wmem_map_lookup(nats_data->headers_map, header_name);
            if (!list)
            {
                list = wmem_list_new(pinfo->pool);
                wmem_list_append(list, (void *) header_value);
                wmem_map_insert(nats_data->headers_map, header_name, list);
            }
            else
            {
                wmem_list_append(list, (void *) header_value);
            }
        }

        proto_tree_add_item(header_tree, hf_nats_headers_header, tvb, offset,
                            next_offset - offset - EOL_LEN, ENC_UTF_8);

        len -= next_offset - offset;
        offset = next_offset;
    }
}

static void nats_dissector_search(const char* table_name _U_, ftenum_t selector_type _U_,
                                  void* key, void* value, void* user_data)
{
    nats_dissector_search_context_t* context = user_data;
    const char* subject_regexp = key;
    dtbl_entry_t* dtbl_entry = (dtbl_entry_t *) value;
    dissector_handle_t dissector_handle = dtbl_entry_get_handle(dtbl_entry);

    // TODO: Add search for the most specified regexp
    //       But for now support only upper level dissectors
    //       which subscribe to all subjects using the ">" wildcard
    if (context->dissector == NULL && strncmp(subject_regexp, ">", 2) == 0)
    {
        context->dissector = dissector_handle;
    }
}

static int dissect_nats_with_payload(tvbuff_t* tvb, int offset, int next_offset,
                                     nats_request_token_t token_op, nats_request_token_t token_subject,
                                     nats_request_token_t token_total_bytes,
                                     const nats_request_token_t* token_sid,
                                     const nats_request_token_t* token_reply_to,
                                     const nats_request_token_t* token_header_bytes,
                                     packet_info* pinfo, proto_tree* tree)
{
    proto_tree* nats_pdu_tree = NULL;
    nats_tvb_info_t* tvb_info = NULL;
    nats_data_t* nats_data = wmem_alloc0(pinfo->pool, sizeof(nats_data_t));

    uint32_t header_bytes = 0;
    uint32_t total_bytes = 0;
    uint32_t body_bytes = 0;

    uint32_t available = tvb_reported_length_remaining(tvb, next_offset);

    if (token_header_bytes &&
        !ws_strtou32(token_header_bytes->value, NULL, &header_bytes))
    {
        return 0;
    }

    if (!ws_strtou32(token_total_bytes.value, NULL, &total_bytes))
    {
        return 0;
    }

    if (total_bytes < header_bytes)
        return 0;

    body_bytes = total_bytes - header_bytes;

    if (available < total_bytes + EOL_LEN)
    {
        pinfo->desegment_offset = offset;
        pinfo->desegment_len = total_bytes + EOL_LEN - available;

        return tvb_reported_length_remaining(tvb, offset);
    }

    nats_pdu_tree = nats_get_or_create_proto_tree(tvb, offset, next_offset + total_bytes + EOL_LEN - offset, tree);

    proto_tree_add_string(nats_pdu_tree, hf_nats_op, tvb, token_op.offset,
                          token_op.length, token_op.value);

    proto_tree_add_string(nats_pdu_tree, hf_nats_subject, tvb, token_subject.offset,
                          token_subject.length, token_subject.value);

    if (token_sid)
    {
        proto_tree_add_string(nats_pdu_tree, hf_nats_subscription_id, tvb,
                              token_sid->offset, token_sid->length,
                              token_sid->value);
    }

    if (token_reply_to)
    {
        proto_tree_add_string(nats_pdu_tree, hf_nats_reply_to, tvb,
                              token_reply_to->offset, token_reply_to->length,
                              token_reply_to->value);
    }

    if (token_header_bytes)
    {
        proto_tree_add_uint64(nats_pdu_tree, hf_nats_header_bytes, tvb,
                              token_header_bytes->offset,
                              token_header_bytes->length, header_bytes);
    }
    proto_tree_add_uint64(nats_pdu_tree, hf_nats_total_bytes, tvb,
                          token_total_bytes.offset, token_total_bytes.length,
                          total_bytes);
    PROTO_ITEM_SET_GENERATED(proto_tree_add_uint64(nats_pdu_tree, hf_nats_body_bytes,
        tvb, 0, 0, body_bytes));

    if (header_bytes)
    {
        dissect_nats_headers(tvb, next_offset, next_offset + header_bytes, pinfo,
                             nats_pdu_tree, nats_data);
    }

    if (!PINFO_FD_VISITED(pinfo))
    {
        conversation_t* conversation = NULL;
        nats_conv_t* conv_data = get_nats_conversation_data(pinfo, &conversation);
        nats_request_info_t* req_info =
            wmem_map_lookup(conv_data->matches_table, token_subject.value);

        // If request found, move it from conversation table into tvb info
        if (req_info)
        {
            tvb_info = get_or_create_tvb_info(pinfo);

            req_info->rsp_frame_num = pinfo->fd->num;
            req_info->rsp_abs_ts = pinfo->abs_ts;

            wmem_map_insert(tvb_info->rsp_table, wmem_strdup(wmem_file_scope(), token_subject.value), req_info);
            wmem_map_remove(conv_data->matches_table, token_subject.value);
        }

        // If PDU has reply_to token than it is request. Save it for later search
        if (token_reply_to)
        {
            tvb_info = get_or_create_tvb_info(pinfo);

            const uint8_t* key = tvb_get_string_enc(
                wmem_file_scope(), tvb, token_reply_to->offset,
                token_reply_to->length, ENC_UTF_8);

            nats_request_info_t* new_req_info =
                wmem_alloc0(wmem_file_scope(), sizeof(nats_request_info_t));

            new_req_info->req_subject = wmem_strdup(wmem_file_scope(), token_subject.value);
            new_req_info->req_frame_num = pinfo->fd->num;
            new_req_info->req_abs_ts = pinfo->abs_ts;

            wmem_map_insert(tvb_info->req_table, key, new_req_info);
            wmem_map_insert(conv_data->matches_table, key, new_req_info);
        }
    }

    // Call subdissector or add body field if no subdissector found
    if (body_bytes)
    {
        const char* subject = token_subject.value;

        nats_data->subject = subject;
        nats_data->reply_to = token_reply_to ? token_reply_to->value : NULL;

        tvb_info = get_tvb_info(pinfo);

        if (tvb_info)
        {
            nats_request_info_t* req_info =
                wmem_map_lookup(tvb_info->rsp_table, token_subject.value);
            if (req_info && req_info->req_subject)
            {
                subject = req_info->req_subject;
                nats_data->in_reply_to = req_info->req_subject;
            }
        }

        nats_dissector_search_context_t context = {subject, NULL};

        dissector_table_foreach("nats.subject", nats_dissector_search, &context);

        tvbuff_t* next_tvb = tvb_new_subset_length(tvb, next_offset + header_bytes, body_bytes);

        if (context.dissector)
        {
            call_dissector_with_data(context.dissector, next_tvb, pinfo, nats_pdu_tree, nats_data);
        }
        else
        {
            call_data_dissector(next_tvb, pinfo, nats_pdu_tree);
        }
    }

    // Add generated fields for analytics
    tvb_info = get_tvb_info(pinfo);

    if (tvb_info)
    {
        nats_request_info_t* req_info =
            wmem_map_lookup(tvb_info->rsp_table, token_subject.value);
        if (req_info)
        {
            nstime_t delta;
            nstime_delta(&delta, &pinfo->abs_ts, &req_info->req_abs_ts);

            proto_item* ti =
                proto_tree_add_time(nats_pdu_tree, hf_nats_rsp_latency, tvb, 0, 0, &delta);
            PROTO_ITEM_SET_GENERATED(ti);

            proto_item* req_item =
                proto_tree_add_uint(nats_pdu_tree, hf_nats_req_frame_ref, tvb, 0, 0,
                                    req_info->req_frame_num);
            PROTO_ITEM_SET_GENERATED(req_item);
        }

        if (token_reply_to)
        {
            nats_request_info_t* rsp_info =
                wmem_map_lookup(tvb_info->req_table, token_reply_to->value);

            if (rsp_info && rsp_info->rsp_frame_num)
            {
                nstime_t delta;
                nstime_delta(&delta, &rsp_info->rsp_abs_ts, &rsp_info->req_abs_ts);

                proto_item* ti = proto_tree_add_time(nats_pdu_tree, hf_nats_req_latency, tvb,
                                                     0, 0, &delta);
                PROTO_ITEM_SET_GENERATED(ti);

                proto_item* rsp_item =
                    proto_tree_add_uint(nats_pdu_tree, hf_nats_rsp_frame_ref, tvb, 0, 0,
                                        rsp_info->rsp_frame_num);
                PROTO_ITEM_SET_GENERATED(rsp_item);
            }
        }
    }

    return next_offset + total_bytes + EOL_LEN - offset;
}

static int dissect_nats_pub(tvbuff_t* tvb, int offset, int next_offset,
                            packet_info* pinfo, proto_tree* tree)
{
    static const size_t TOKEN_OP = 0;
    static const size_t TOKEN_SUBJECT = 1;

    nats_request_token_t tokens[4] = {0};

    size_t token_reply_to = 0;
    size_t token_total_bytes = 0;

    bool has_reply_to = false;

    size_t num_tokens =
        nats_parse_tokens(tvb, offset, next_offset, pinfo, tokens, array_length(tokens));

    if (num_tokens < 3)
        return 0;

    if (num_tokens == 4)
    {
        has_reply_to = true;
        token_reply_to = 2;
        token_total_bytes = 3;
    }
    else
    {
        token_total_bytes = 2;
    }

    return dissect_nats_with_payload(
        tvb, offset, next_offset, tokens[TOKEN_OP], tokens[TOKEN_SUBJECT],
        tokens[token_total_bytes], NULL,
        has_reply_to ? &tokens[token_reply_to] : NULL, NULL, pinfo, tree);
}

static int dissect_nats_hpub(tvbuff_t* tvb, int offset, int next_offset,
                             packet_info* pinfo, proto_tree* tree)
{
    static const size_t TOKEN_OP = 0;
    static const size_t TOKEN_SUBJECT = 1;

    nats_request_token_t tokens[5] = {0};

    size_t token_reply_to = 0;
    size_t token_header_bytes = 0;
    size_t token_total_bytes = 0;

    bool has_reply_to = false;

    size_t num_tokens =
        nats_parse_tokens(tvb, offset, next_offset, pinfo, tokens, array_length(tokens));

    if (num_tokens < 4)
        return 0;

    if (num_tokens == 5)
    {
        has_reply_to = true;
        token_reply_to = 2;
        token_header_bytes = 3;
        token_total_bytes = 4;
    }
    else
    {
        token_header_bytes = 2;
        token_total_bytes = 3;
    }

    return dissect_nats_with_payload(
        tvb, offset, next_offset, tokens[TOKEN_OP], tokens[TOKEN_SUBJECT],
        tokens[token_total_bytes], NULL,
        has_reply_to ? &tokens[token_reply_to] : NULL,
        &tokens[token_header_bytes], pinfo, tree);
}

static int dissect_nats_msg(tvbuff_t* tvb, int offset, int next_offset,
                            packet_info* pinfo, proto_tree* tree)
{
    static const size_t TOKEN_OP = 0;
    static const size_t TOKEN_SUBJECT = 1;
    static const size_t TOKEN_SID = 2;

    nats_request_token_t tokens[5] = {0};

    size_t token_reply_to = 0;
    size_t token_total_bytes = 0;

    bool has_reply_to = false;

    size_t num_tokens =
        nats_parse_tokens(tvb, offset, next_offset, pinfo, tokens, array_length(tokens));

    if (num_tokens < 4)
        return 0;

    if (num_tokens == 5)
    {
        has_reply_to = true;
        token_reply_to = 3;
        token_total_bytes = 4;
    }
    else
    {
        token_total_bytes = 3;
    }

    return dissect_nats_with_payload(
        tvb, offset, next_offset, tokens[TOKEN_OP], tokens[TOKEN_SUBJECT],
        tokens[token_total_bytes], &tokens[TOKEN_SID],
        has_reply_to ? &tokens[token_reply_to] : NULL, NULL, pinfo, tree);
}

static int dissect_nats_hmsg(tvbuff_t* tvb, int offset, int next_offset,
                             packet_info* pinfo, proto_tree* tree)
{
    static const size_t TOKEN_OP = 0;
    static const size_t TOKEN_SUBJECT = 1;
    static const size_t TOKEN_SID = 2;

    nats_request_token_t tokens[6] = {0};

    size_t token_reply_to = 0;
    size_t token_header_bytes = 0;
    size_t token_total_bytes = 0;

    bool has_reply_to = false;

    size_t num_tokens =
        nats_parse_tokens(tvb, offset, next_offset, pinfo, tokens, array_length(tokens));

    if (num_tokens < 5)
        return 0;

    if (num_tokens == 6)
    {
        has_reply_to = true;
        token_reply_to = 3;
        token_header_bytes = 4;
        token_total_bytes = 5;
    }
    else
    {
        token_header_bytes = 3;
        token_total_bytes = 4;
    }

    return dissect_nats_with_payload(
        tvb, offset, next_offset, tokens[TOKEN_OP], tokens[TOKEN_SUBJECT],
        tokens[token_total_bytes], &tokens[TOKEN_SID],
        has_reply_to ? &tokens[token_reply_to] : NULL,
        &tokens[token_header_bytes], pinfo, tree);
}

static int dissect_nats_sub(tvbuff_t* tvb, int offset, int next_offset,
                            packet_info* pinfo,
                            proto_tree* tree)
{
    static const size_t TOKEN_OP = 0;
    static const size_t TOKEN_SUBJECT = 1;

    proto_tree* pdu_tree = NULL;

    nats_request_token_t tokens[4] = {0};

    size_t token_queue_group = 0;
    size_t token_sid = 0;

    bool has_queue_group = false;

    size_t num_tokens =
        nats_parse_tokens(tvb, offset, next_offset, pinfo, tokens, array_length(tokens));

    if (num_tokens < 3)
        return 0;

    if (num_tokens == 4)
    {
        has_queue_group = true;

        token_queue_group = 2;
        token_sid = 3;
    }
    else
    {
        token_sid = 2;
    }

    pdu_tree = nats_get_or_create_proto_tree(tvb, offset, next_offset - offset, tree);

    proto_tree_add_string(pdu_tree, hf_nats_op, tvb, tokens[TOKEN_OP].offset,
                          tokens[TOKEN_OP].length, tokens[TOKEN_OP].value);

    proto_tree_add_string(
        pdu_tree, hf_nats_subject, tvb, tokens[TOKEN_SUBJECT].offset,
        tokens[TOKEN_SUBJECT].length, tokens[TOKEN_SUBJECT].value);

    if (has_queue_group)
    {
        proto_tree_add_string(
            pdu_tree, hf_nats_queue_group, tvb, tokens[token_queue_group].offset,
            tokens[token_queue_group].length, tokens[token_queue_group].value);
    }

    proto_tree_add_string(pdu_tree, hf_nats_subscription_id, tvb,
                          tokens[token_sid].offset, tokens[token_sid].length,
                          tokens[token_sid].value);

    return next_offset - offset;
}

static int dissect_nats_unsub(tvbuff_t* tvb, int offset, int next_offset,
                              packet_info* pinfo,
                              proto_tree* tree)
{
    static const size_t TOKEN_OP = 0;
    static const size_t TOKEN_SID = 1;
    static const size_t TOKEN_MAX_MSGS = 2;

    proto_tree* pdu_tree = NULL;

    nats_request_token_t tokens[3] = {0};

    bool has_max_msgs = false;

    size_t num_tokens =
        nats_parse_tokens(tvb, offset, next_offset, pinfo, tokens, array_length(tokens));

    if (num_tokens < 2)
        return 0;

    if (num_tokens == 3)
    {
        has_max_msgs = true;
    }

    pdu_tree = nats_get_or_create_proto_tree(tvb, offset, next_offset - offset, tree);

    proto_tree_add_string(pdu_tree, hf_nats_op, tvb, tokens[TOKEN_OP].offset,
                          tokens[TOKEN_OP].length, tokens[TOKEN_OP].value);

    proto_tree_add_string(pdu_tree, hf_nats_subscription_id, tvb,
                          tokens[TOKEN_SID].offset, tokens[TOKEN_SID].length,
                          tokens[TOKEN_SID].value);

    if (has_max_msgs)
    {
        proto_tree_add_string(
            pdu_tree, hf_nats_max_msgs, tvb, tokens[TOKEN_MAX_MSGS].offset,
            tokens[TOKEN_MAX_MSGS].length, tokens[TOKEN_MAX_MSGS].value);
    }

    return next_offset - offset;
}

static int dissect_nats_ping_pong(tvbuff_t* tvb, int offset, int next_offset,
                                  packet_info* pinfo,
                                  proto_tree* tree)
{
    static const size_t TOKEN_OP = 0;

    proto_tree* pdu_tree = NULL;

    nats_request_token_t tokens[1] = {0};

    size_t num_tokens =
        nats_parse_tokens(tvb, offset, next_offset, pinfo, tokens, array_length(tokens));

    if (num_tokens < 1)
        return 0;

    pdu_tree = nats_get_or_create_proto_tree(tvb, offset, next_offset - offset, tree);

    proto_tree_add_string(pdu_tree, hf_nats_op, tvb, tokens[TOKEN_OP].offset,
                          tokens[TOKEN_OP].length, tokens[TOKEN_OP].value);

    return next_offset - offset;
}

static int dissect_nats_info_connect(tvbuff_t* tvb, int offset, int next_offset,
                                     proto_tree* tree)
{
    proto_tree* pdu_tree = NULL;

    int op_offset = offset;
    int op_length =
        tvb_get_token_len(tvb, offset, next_offset - offset, NULL, false);

    int features_offset = tvb_skip_wsp(tvb, op_offset + op_length,
                                       next_offset - op_offset - op_length);

    int features_length = next_offset - features_offset - EOL_LEN;

    pdu_tree = nats_get_or_create_proto_tree(tvb, offset, next_offset - offset, tree);
    proto_tree_add_item(pdu_tree, hf_nats_op, tvb, op_offset, op_length,
                        ENC_ASCII);

    proto_tree_add_item(pdu_tree, hf_nats_features, tvb, features_offset,
                        features_length, ENC_NA);

    return next_offset - offset;
}

static int dissect_nats(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree,
                        void* data _U_)
{
    int offset = 0;

    int line_offset = 0;
    int next_offset = 0;

    while (tvb_find_line_end(tvb, line_offset, -1, &next_offset, true) != -1)
    {
        int result = 0;

        int token_len =
            tvb_get_token_len(tvb, line_offset, next_offset, NULL, true);

        switch (token_len)
        {
        case 3:
            if (tvb_strncaseeql(tvb, line_offset, "MSG", 3) == 0)
            {
                result = dissect_nats_msg(tvb, line_offset, next_offset, pinfo, tree);
            }
            else if (tvb_strncaseeql(tvb, line_offset, "PUB", 3) == 0)
            {
                result = dissect_nats_pub(tvb, line_offset, next_offset, pinfo, tree);
            }
            else if (tvb_strncaseeql(tvb, line_offset, "SUB", 3) == 0)
            {
                result = dissect_nats_sub(tvb, line_offset, next_offset, pinfo, tree);
            }
            break;
        case 4:
            if (tvb_strncaseeql(tvb, line_offset, "HMSG", 4) == 0)
            {
                result = dissect_nats_hmsg(tvb, line_offset, next_offset, pinfo, tree);
            }
            else if (tvb_strncaseeql(tvb, line_offset, "HPUB", 4) == 0)
            {
                result = dissect_nats_hpub(tvb, line_offset, next_offset, pinfo, tree);
            }
            else if (tvb_strncaseeql(tvb, line_offset, "PING", 4) == 0)
            {
                result = dissect_nats_ping_pong(tvb, line_offset, next_offset, pinfo, tree);
            }
            else if (tvb_strncaseeql(tvb, line_offset, "PONG", 4) == 0)
            {
                result = dissect_nats_ping_pong(tvb, line_offset, next_offset, pinfo, tree);
            }
            else if (tvb_strncaseeql(tvb, line_offset, "INFO", 4) == 0)
            {
                result = dissect_nats_info_connect(tvb, line_offset, next_offset, tree);
            }
            break;
        case 5:
            if (tvb_strncaseeql(tvb, line_offset, "UNSUB", 5) == 0)
            {
                result = dissect_nats_unsub(tvb, line_offset, next_offset, pinfo, tree);
            }
            break;
        case 7:
            if (tvb_strncaseeql(tvb, line_offset, "CONNECT", 7) == 0)
            {
                result = dissect_nats_info_connect(tvb, line_offset, next_offset, tree);
            }
            break;
        default:
            break;
        }

        if (result == 0)
        {
            line_offset = next_offset;
        }
        else
        {
            line_offset += result;
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "NATS");
            col_set_str(pinfo->cinfo, COL_INFO, "NATS Data" UTF8_HORIZONTAL_ELLIPSIS);
        }

        offset = line_offset;
        // In case next call of tvb_find_line_end will not find next CRLF
        next_offset = line_offset;
    }

    if (tvb_reported_length_remaining(tvb, offset) != 0)
    {
        pinfo->desegment_offset = offset;
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
    }

    return tvb_reported_length(tvb);
}

void proto_register_nats(void)
{
    static hf_register_info hf[] = {
        {
            &hf_nats_op,
            {
                "Operation", "nats.op", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
                HFILL
            }
        },
        {
            &hf_nats_subject,
            {
                "Subject", "nats.subject", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_reply_to,
            {
                "Reply To Subject", "nats.reply_to", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_subscription_id,
            {
                "Subscription ID", "nats.subscription.id", FT_STRING, BASE_NONE, NULL,
                0x0, "ID of the subscription chosen by the client during the subscribe op", HFILL
            }
        },
        {
            &hf_nats_queue_group,
            {
                "Queue Group", "nats.subscription.group", FT_STRING, BASE_NONE, NULL,
                0x0, "NATS Queue Group for load distribution to multiple subscribers", HFILL
            }
        },
        {
            &hf_nats_max_msgs,
            {
                "Max Messages", "nats.subscription.max_msgs", FT_STRING, BASE_NONE,
                NULL, 0x0, "NATS message count after which subscription is automatically unsubscribed", HFILL
            }
        },
        {
            &hf_nats_total_bytes,
            {
                "Total Bytes", "nats.total_length", FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
                "Total Length in bytes of headers and body", HFILL
            }
        },
        {
            &hf_nats_header_bytes,
            {
                "Headers Bytes", "nats.headers.length", FT_UINT64, BASE_DEC_HEX, NULL,
                0x0, NULL, HFILL
            }
        },
        {
            &hf_nats_body_bytes,
            {
                "Body Length", "nats.body.length", FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_headers,
            {
                "Headers", "nats.headers", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_headers_version,
            {
                "Headers Version", "nats.headers.version", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_headers_header,
            {
                "Header", "nats.headers.header", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_features,
            {
                "Features", "nats.features", FT_NONE, BASE_NONE, NULL, 0x0,
                "NATS Connection Handshake Features", HFILL
            }
        },
        {
            &hf_nats_req_latency,
            {
                "Request Latency", "nats.request.latency", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
                "Calculated time between the frame with request and the frame with response if both are seen", HFILL
            }
        },
        {
            &hf_nats_rsp_latency,
            {
                "Response Latency", "nats.response.latency", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
                "Calculated time between the frame with request and the frame with response if both are present in the capture", HFILL
            }
        },
        {
            &hf_nats_req_frame_ref,
            {
                "Request Frame", "nats.request.in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "The number of the frame containing the request for the current response if it is present in the capture", HFILL
            }
        },
        {
            &hf_nats_rsp_frame_ref,
            {
                "Response Frame", "nats.response.in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "The number of the frame containing the response to the current request if it is present in the capture", HFILL
            }
        },

    };

    static int* ett[] = {
        &ett_nats,
        &ett_nats_headers,
    };

    proto_nats = proto_register_protocol("NATS", "NATS", "nats");
    handle_nats = create_dissector_handle(dissect_nats, proto_nats);

    proto_register_field_array(proto_nats, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    subject_table = register_dissector_table(
        "nats.subject", // table name
        "NATS Subject", // UI name
        proto_nats, // protocol id
        FT_STRING, // field type
        BASE_NONE);

    register_dissector("NATS", dissect_nats, proto_nats);
}

void proto_reg_handoff_nats(void)
{
    dissector_add_uint_with_preference("tcp.port", NATS_PORT, handle_nats);
}
