/* packet-nats.c
 * Routines for NATS Client Protocol dissection
 * https://docs.nats.io/reference/reference-protocols/nats-protocol
 *
 * Copyright 2025, Max Dmitrichenko <dmitrmax@gmail.com>
 * Copyright 2025, Florian Matouschek <florian@matoutech.dev>
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

static dissector_handle_t json_handle;

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
static int hf_nats_header_version;
static int hf_nats_header_version_major;
static int hf_nats_header_version_minor;
static int hf_nats_header;
static int hf_nats_header_name;
static int hf_nats_header_value;
static int hf_nats_features;
static int hf_nats_err_msg;
static int hf_nats_req_latency;
static int hf_nats_rsp_latency;
static int hf_nats_req_frame_ref;
static int hf_nats_rsp_frame_ref;

static int hf_nats_info;
static int hf_nats_connect;
static int hf_nats_pub;
static int hf_nats_hpub;
static int hf_nats_sub;
static int hf_nats_unsub;
static int hf_nats_msg;
static int hf_nats_hmsg;
static int hf_nats_ping;
static int hf_nats_pong;
static int hf_nats_ok;
static int hf_nats_err;

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

static void dissect_nats_header_version(tvbuff_t* tvb, int offset, int end_offset,
                                        packet_info* pinfo, proto_tree* header_tree)
{
    proto_item *header_version = proto_tree_add_item(header_tree, hf_nats_header_version, tvb,
                                                     offset, end_offset - offset, ENC_ASCII);
    proto_tree *header_version_tree = proto_item_add_subtree(header_version, ett_nats_headers);

    /* The header version has the format NATS/X.x where
     *     X: major version
     *     x: minor version
     *
     * We are searching for the slash and dot character to find those values.
     *
     * https://github.com/nats-io/nats-architecture-and-design/blob/main/adr/ADR-4.md#version-header
     */

    unsigned slash_offset, dot_offset;

    if (!tvb_find_uint8_length(tvb, offset, end_offset - offset, '/', &slash_offset))
        return;

    if (!tvb_find_uint8_length(tvb, slash_offset, end_offset - slash_offset, '.', &dot_offset))
        return;

    const unsigned major_offset = slash_offset + 1;
    const int minor_offset = dot_offset + 1;

    const unsigned major_length = dot_offset - slash_offset - 1;
    const unsigned minor_length = end_offset - dot_offset - 1;

    char *major_string = (char*)tvb_get_string_enc(pinfo->pool, tvb, major_offset, major_length, ENC_ASCII);
    char *minor_string = (char*)tvb_get_string_enc(pinfo->pool, tvb, minor_offset, minor_length, ENC_ASCII);

    uint8_t major_number = 0;
    uint8_t minor_number = 0;

    if (!ws_strtou8(major_string, NULL, &major_number))
        return;

    if (!ws_strtou8(minor_string, NULL, &minor_number))
        return;

    proto_tree_add_uint(header_version_tree, hf_nats_header_version_major, tvb,
                        major_offset, major_length, major_number);
    proto_tree_add_uint(header_version_tree, hf_nats_header_version_minor, tvb,
                        minor_offset, minor_length, minor_number);
}

static void dissect_nats_headers(tvbuff_t* tvb, unsigned offset, unsigned end_offset,
                                 packet_info* pinfo,
                                 proto_tree* tree, nats_data_t* nats_data)
{
    unsigned len = end_offset - offset;
    unsigned next_offset = 0;
    tvb_find_line_end_length(tvb, offset, len, NULL, &next_offset);

    proto_item* ti;
    proto_tree* header_tree;

    ti = proto_tree_add_item(tree, hf_nats_headers, tvb, offset,
                             end_offset - offset, ENC_NA);
    header_tree = proto_item_add_subtree(ti, ett_nats_headers);

    dissect_nats_header_version(tvb, offset, next_offset - EOL_LEN, pinfo, header_tree);

    len -= next_offset - offset;
    offset = next_offset;

    nats_data->headers_map = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);

    while (tvb_find_line_end_length(tvb, offset, len, NULL, &next_offset))
    {
        unsigned colon_offset;
        if (tvb_find_uint8_length(tvb, offset, next_offset - offset, ':', &colon_offset))
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

            proto_item *header_item = proto_tree_add_item(header_tree, hf_nats_header, tvb,
                                                          offset, next_offset - offset - EOL_LEN, ENC_UTF_8);
            proto_tree *header_item_tree = proto_item_add_subtree(header_item, ett_nats_headers);

            proto_tree_add_item(header_item_tree, hf_nats_header_name, tvb,
                                offset, colon_offset - offset, ENC_ASCII);
            proto_tree_add_item(header_item_tree, hf_nats_header_value, tvb,
                                value_offset, next_offset - value_offset - EOL_LEN, ENC_ASCII);
        }

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
                                     packet_info* pinfo, proto_tree* tree, int operation_hf)
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

    proto_item *operation_item = proto_tree_add_item(tree, operation_hf, tvb, offset,
                                                     next_offset + total_bytes + EOL_LEN - offset, ENC_NA);
    nats_pdu_tree = proto_item_add_subtree(operation_item, ett_nats);

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

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "PUB");

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
        has_reply_to ? &tokens[token_reply_to] : NULL, NULL, pinfo, tree, hf_nats_pub);
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

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "HPUB");

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
        &tokens[token_header_bytes], pinfo, tree, hf_nats_hpub);
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

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "MSG");

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
        has_reply_to ? &tokens[token_reply_to] : NULL, NULL, pinfo, tree, hf_nats_msg);
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

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "HMSG");

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
        &tokens[token_header_bytes], pinfo, tree, hf_nats_hmsg);
}

static int dissect_nats_sub(tvbuff_t* tvb, int offset, int next_offset,
                            packet_info* pinfo, proto_tree* tree)
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

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "SUB");

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

    proto_item *sub_item = proto_tree_add_item(tree, hf_nats_sub, tvb,
                                               offset, next_offset - offset, ENC_NA);
    pdu_tree = proto_item_add_subtree(sub_item, ett_nats);

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
                              packet_info* pinfo, proto_tree* tree)
{
    static const size_t TOKEN_OP = 0;
    static const size_t TOKEN_SID = 1;
    static const size_t TOKEN_MAX_MSGS = 2;

    proto_tree* pdu_tree = NULL;

    nats_request_token_t tokens[3] = {0};

    bool has_max_msgs = false;
    uint64_t max_msgs = 0;

    size_t num_tokens =
        nats_parse_tokens(tvb, offset, next_offset, pinfo, tokens, array_length(tokens));

    if (num_tokens < 2)
        return 0;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "UNSUB");

    if (num_tokens == 3)
    {
        has_max_msgs = true;
    }

    proto_item *unsub_item = proto_tree_add_item(tree, hf_nats_unsub, tvb,
                                                 offset, next_offset - offset, ENC_NA);
    pdu_tree = proto_item_add_subtree(unsub_item, ett_nats);

    proto_tree_add_string(pdu_tree, hf_nats_op, tvb, tokens[TOKEN_OP].offset,
                          tokens[TOKEN_OP].length, tokens[TOKEN_OP].value);

    proto_tree_add_string(pdu_tree, hf_nats_subscription_id, tvb,
                          tokens[TOKEN_SID].offset, tokens[TOKEN_SID].length,
                          tokens[TOKEN_SID].value);

    if (has_max_msgs)
    {
        if (!ws_strtou64(tokens[TOKEN_MAX_MSGS].value, NULL, &max_msgs))
            return 0;

        proto_tree_add_uint64(pdu_tree, hf_nats_max_msgs, tvb, tokens[TOKEN_MAX_MSGS].offset,
                              tokens[TOKEN_MAX_MSGS].length, max_msgs);
    }

    return next_offset - offset;
}

static int dissect_nats_ping(tvbuff_t* tvb, int offset, int next_offset,
                             packet_info* pinfo, proto_tree* tree)
{
    static const size_t TOKEN_OP = 0;

    proto_tree* pdu_tree = NULL;

    nats_request_token_t tokens[1] = {0};

    size_t num_tokens =
        nats_parse_tokens(tvb, offset, next_offset, pinfo, tokens, array_length(tokens));

    if (num_tokens < 1)
        return 0;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "PING");

    proto_item *ping_item = proto_tree_add_item(tree, hf_nats_ping, tvb,
                                                offset, next_offset - offset, ENC_NA);
    pdu_tree = proto_item_add_subtree(ping_item, ett_nats);

    proto_tree_add_string(pdu_tree, hf_nats_op, tvb, tokens[TOKEN_OP].offset,
                          tokens[TOKEN_OP].length, tokens[TOKEN_OP].value);

    return next_offset - offset;
}

static int dissect_nats_pong(tvbuff_t* tvb, int offset, int next_offset,
                             packet_info* pinfo, proto_tree* tree)
{
    static const size_t TOKEN_OP = 0;

    proto_tree* pdu_tree = NULL;

    nats_request_token_t tokens[1] = {0};

    size_t num_tokens =
        nats_parse_tokens(tvb, offset, next_offset, pinfo, tokens, array_length(tokens));

    if (num_tokens < 1)
        return 0;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "PONG");

    proto_item *pong_item = proto_tree_add_item(tree, hf_nats_pong, tvb,
                                                offset, next_offset - offset, ENC_NA);
    pdu_tree = proto_item_add_subtree(pong_item, ett_nats);

    proto_tree_add_string(pdu_tree, hf_nats_op, tvb, tokens[TOKEN_OP].offset,
                          tokens[TOKEN_OP].length, tokens[TOKEN_OP].value);

    return next_offset - offset;
}

static int dissect_nats_info(tvbuff_t* tvb, int offset, int next_offset,
                             packet_info* pinfo, proto_tree* tree)
{
    proto_tree* pdu_tree = NULL;

    int op_offset = offset;
    int op_length =
        tvb_get_token_len(tvb, offset, next_offset - offset, NULL, false);

    int features_offset = tvb_skip_wsp(tvb, op_offset + op_length,
                                       next_offset - op_offset - op_length);

    int features_length = next_offset - features_offset - EOL_LEN;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "INFO");

    proto_item *info_item = proto_tree_add_item(tree, hf_nats_info, tvb,
                                                offset, next_offset - offset, ENC_NA);
    pdu_tree = proto_item_add_subtree(info_item, ett_nats);

    proto_tree_add_item(pdu_tree, hf_nats_op, tvb, op_offset, op_length,
                        ENC_ASCII);

    proto_item *features_item = proto_tree_add_item(pdu_tree, hf_nats_features, tvb,
                        features_offset, features_length, ENC_NA);
    proto_tree *features_tree = proto_item_add_subtree(features_item, ett_nats);

    tvbuff_t *json_tvb = tvb_new_subset_length(tvb, features_offset, features_length);

    call_dissector(json_handle, json_tvb, pinfo, features_tree);

    return next_offset - offset;
}

static int dissect_nats_connect(tvbuff_t* tvb, int offset, int next_offset,
                                packet_info* pinfo, proto_tree* tree)
{
    proto_tree* pdu_tree = NULL;

    int op_offset = offset;
    int op_length =
        tvb_get_token_len(tvb, offset, next_offset - offset, NULL, false);

    int features_offset = tvb_skip_wsp(tvb, op_offset + op_length,
                                       next_offset - op_offset - op_length);

    int features_length = next_offset - features_offset - EOL_LEN;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "CONNECT");

    proto_item *connect_item = proto_tree_add_item(tree, hf_nats_connect, tvb,
                                                   offset, next_offset - offset, ENC_NA);
    pdu_tree = proto_item_add_subtree(connect_item, ett_nats);

    proto_tree_add_item(pdu_tree, hf_nats_op, tvb, op_offset, op_length,
                        ENC_ASCII);

    proto_item *features_item = proto_tree_add_item(pdu_tree, hf_nats_features, tvb,
                        features_offset, features_length, ENC_NA);
    proto_tree *features_tree = proto_item_add_subtree(features_item, ett_nats);

    tvbuff_t *json_tvb = tvb_new_subset_length(tvb, features_offset, features_length);

    call_dissector(json_handle, json_tvb, pinfo, features_tree);

    return next_offset - offset;
}

static int dissect_nats_ok(tvbuff_t* tvb, int offset, int next_offset,
                           packet_info* pinfo, proto_tree* tree)
{
    static const size_t TOKEN_OP = 0;

    proto_tree* pdu_tree = NULL;

    nats_request_token_t tokens[1] = {0};

    size_t num_tokens =
        nats_parse_tokens(tvb, offset, next_offset, pinfo, tokens, array_length(tokens));

    if (num_tokens < 1)
        return 0;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "+OK");

    proto_item *ok_item = proto_tree_add_item(tree, hf_nats_ok, tvb,
                                              offset, next_offset - offset, ENC_NA);
    pdu_tree = proto_item_add_subtree(ok_item, ett_nats);

    proto_tree_add_string(pdu_tree, hf_nats_op, tvb, tokens[TOKEN_OP].offset,
                          tokens[TOKEN_OP].length, tokens[TOKEN_OP].value);

    return next_offset - offset;
}

static int dissect_nats_err(tvbuff_t* tvb, int offset, int next_offset,
                            packet_info* pinfo, proto_tree* tree)
{
    proto_tree* pdu_tree = NULL;

    int op_offset = offset;
    int op_length =
        tvb_get_token_len(tvb, offset, next_offset - offset, NULL, false);

    int message_offset = tvb_skip_wsp(tvb, op_offset + op_length,
                                       next_offset - op_offset - op_length);

    int message_length = next_offset - message_offset - EOL_LEN;

    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "-ERR");

    proto_item *err_item = proto_tree_add_item(tree, hf_nats_err, tvb,
                                               offset, next_offset - offset, ENC_NA);
    pdu_tree = proto_item_add_subtree(err_item, ett_nats);

    proto_tree_add_item(pdu_tree, hf_nats_op, tvb, op_offset, op_length, ENC_ASCII);

    proto_tree_add_item(pdu_tree, hf_nats_err_msg, tvb,
                        message_offset, message_length, ENC_UTF_8);

    return next_offset - offset;
}

static int dissect_nats(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree,
                        void* data _U_)
{
    unsigned offset = 0;

    unsigned line_offset = 0;
    unsigned next_offset = 0;

    proto_item *nats_tree_item = proto_tree_add_item(tree, proto_nats, tvb,
                                                     0, -1, ENC_UTF_8);
    proto_tree *nats_tree = proto_item_add_subtree(nats_tree_item, ett_nats);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NATS");
    col_clear(pinfo->cinfo, COL_INFO);

    while (tvb_find_line_end_remaining(tvb, line_offset, NULL, &next_offset))
    {
        int result = 0;

        int token_len =
            tvb_get_token_len(tvb, line_offset, next_offset, NULL, true);

        switch (token_len)
        {
        case 3:
            if (tvb_strncaseeql(tvb, line_offset, "MSG", 3) == 0)
            {
                result = dissect_nats_msg(tvb, line_offset, next_offset, pinfo, nats_tree);
            }
            else if (tvb_strncaseeql(tvb, line_offset, "PUB", 3) == 0)
            {
                result = dissect_nats_pub(tvb, line_offset, next_offset, pinfo, nats_tree);
            }
            else if (tvb_strncaseeql(tvb, line_offset, "SUB", 3) == 0)
            {
                result = dissect_nats_sub(tvb, line_offset, next_offset, pinfo, nats_tree);
            }
            else if (tvb_strncaseeql(tvb, line_offset, "+OK", 3) == 0)
            {
                result = dissect_nats_ok(tvb, line_offset, next_offset, pinfo, nats_tree);
            }
            break;
        case 4:
            if (tvb_strncaseeql(tvb, line_offset, "HMSG", 4) == 0)
            {
                result = dissect_nats_hmsg(tvb, line_offset, next_offset, pinfo, nats_tree);
            }
            else if (tvb_strncaseeql(tvb, line_offset, "HPUB", 4) == 0)
            {
                result = dissect_nats_hpub(tvb, line_offset, next_offset, pinfo, nats_tree);
            }
            else if (tvb_strncaseeql(tvb, line_offset, "PING", 4) == 0)
            {
                result = dissect_nats_ping(tvb, line_offset, next_offset, pinfo, nats_tree);
            }
            else if (tvb_strncaseeql(tvb, line_offset, "PONG", 4) == 0)
            {
                result = dissect_nats_pong(tvb, line_offset, next_offset, pinfo, nats_tree);
            }
            else if (tvb_strncaseeql(tvb, line_offset, "INFO", 4) == 0)
            {
                result = dissect_nats_info(tvb, line_offset, next_offset, pinfo, nats_tree);
            }
            else if (tvb_strncaseeql(tvb, line_offset, "-ERR", 4) == 0)
            {
                result = dissect_nats_err(tvb, line_offset, next_offset, pinfo, nats_tree);
            }
            break;
        case 5:
            if (tvb_strncaseeql(tvb, line_offset, "UNSUB", 5) == 0)
            {
                result = dissect_nats_unsub(tvb, line_offset, next_offset, pinfo, nats_tree);
            }
            break;
        case 7:
            if (tvb_strncaseeql(tvb, line_offset, "CONNECT", 7) == 0)
            {
                result = dissect_nats_connect(tvb, line_offset, next_offset, pinfo, nats_tree);
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
        }

        offset = line_offset;
        // In case next call of tvb_find_line_end_length will not find next CRLF
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
                "Max Messages", "nats.subscription.max_msgs", FT_UINT64, BASE_DEC,
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
            &hf_nats_header_version,
            {
                "Version", "nats.header.version", FT_STRING, BASE_NONE, NULL, 0x0,
                "Header Version", HFILL
            }
        },
        {
            &hf_nats_header_version_major,
            {
                "Major Version", "nats.header.version.major", FT_UINT8, BASE_DEC, NULL, 0x0,
                "Header Major Version", HFILL
            }
        },
        {
            &hf_nats_header_version_minor,
            {
                "Minor Version", "nats.header.version.minor", FT_UINT8, BASE_DEC, NULL, 0x0,
                "Header Minor Version", HFILL
            }
        },
        {
            &hf_nats_header,
            {
                "Header", "nats.header", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_header_name,
            {
                "Name", "nats.header.name", FT_STRING, BASE_NONE, NULL, 0x0,
                "Header Name", HFILL
            }
        },
        {
            &hf_nats_header_value,
            {
                "Value", "nats.header.value", FT_STRING, BASE_NONE, NULL, 0x0,
                "Header Value", HFILL
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
            &hf_nats_err_msg,
            {
                "Error Message", "nats.err_msg", FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL
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
        {
            &hf_nats_info,
            {
                "INFO", "nats.info", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_connect,
            {
                "CONNECT", "nats.connect", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_pub,
            {
                "PUB", "nats.pub", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_hpub,
            {
                "HPUB", "nats.hpub", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_sub,
            {
                "SUB", "nats.sub", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_unsub,
            {
                "UNSUB", "nats.unsub", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_msg,
            {
                "MSG", "nats.msg", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_hmsg,
            {
                "HMSG", "nats.hmsg", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_ping,
            {
                "PING", "nats.ping", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_pong,
            {
                "PONG", "nats.pong", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_ok,
            {
                "+OK", "nats.ok", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_nats_err,
            {
                "-ERR", "nats.err", FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },

    };

    static int* ett[] = {
        &ett_nats,
        &ett_nats_headers,
    };

    proto_nats = proto_register_protocol("NATS", "NATS", "nats");
    handle_nats = create_dissector_handle(dissect_nats, proto_nats);

    json_handle = find_dissector("json");

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
