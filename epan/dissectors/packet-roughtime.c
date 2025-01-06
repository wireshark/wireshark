/* packet-roughtime.c
 * Dissector for Roughtime Time Synchronization
 *
 * Copyright (c) 2024 by Martin Mayer <martin.mayer@m2-it-solutions.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Based on:
 *
 * - Google Roughtime Protocol
 *   https://roughtime.googlesource.com/roughtime/+/HEAD/PROTOCOL.md
 *
 * - IETF Roughtime I-D
 *   https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/
 *
 *   Most recent version at time of writing
 *   https://www.ietf.org/archive/id/draft-ietf-ntp-roughtime-12.html
 */

/*
 * To Do:
 *
 * - Default port assignments
 *   Change temporary ports to IANA assigned ports after RFC publication
 *
 * - Stream support
 *   Add TCP support when implementations adopted it or when there are example captures from other sources
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/conversation.h>

/* Tag Registry (RFC -unpublished-) */
#define TAG_TYPE_SIG    0x00474953  // SIG\x00
#define TAG_TYPE_VER    0x00524556  // VER\x00
#define TAG_TYPE_SRV    0x00565253  // SRV\x00
#define TAG_TYPE_NONC   0x434E4F4E  // NONC
#define TAG_TYPE_DELE   0x454C4544  // DELE
#define TAG_TYPE_PATH   0x48544150  // PATH
#define TAG_TYPE_RADI   0x49444152  // RADI
#define TAG_TYPE_PUBK   0x4B425550  // PUBK
#define TAG_TYPE_MIDP   0x5044494D  // MIDP
#define TAG_TYPE_SREP   0x50455253  // SREP
#define TAG_TYPE_VERS   0x53524556  // VERS
#define TAG_TYPE_MINT   0x544E494D  // MINT
#define TAG_TYPE_ROOT   0x544F4F52  // ROOT
#define TAG_TYPE_CERT   0x54524543  // CERT
#define TAG_TYPE_MAXT   0x5458414D  // MAXT
#define TAG_TYPE_INDX   0x58444E49  // INDX
#define TAG_TYPE_ZZZZ   0x5A5A5A5A  // ZZZZ

/* Additional tags (Google) */
#define TAG_TYPE_PAD    0xFF444150  // PAD\xFF

/* Roughtime IETF Header Magic Word */
#define HDR_IETF        0x4D49544847554F52 // ROUGHTIM

#define PROTO_TEXT_GOOGLE   "Google"
#define PROTO_TEXT_IETF     "IETF"

void proto_register_roughtime(void);
void proto_reg_handoff_roughtime(void);

static dissector_handle_t roughtime_handle;

static int proto_roughtime;

/* Fields */
static int hf_roughtime_proto;
static int hf_roughtime_hdr;
static int hf_roughtime_msg_len;
static int hf_roughtime_srep;
static int hf_roughtime_cert;
static int hf_roughtime_dele;
static int hf_roughtime_num_tags;
static int hf_roughtime_offset;
static int hf_roughtime_tag;
static int hf_roughtime_nonce;
static int hf_roughtime_ver;
static int hf_roughtime_sig;
static int hf_roughtime_srv;
static int hf_roughtime_pad;
static int hf_roughtime_index;
static int hf_roughtime_path;
static int hf_roughtime_radius;
static int hf_roughtime_midp;
static int hf_roughtime_mint;
static int hf_roughtime_maxt;
static int hf_roughtime_root;
static int hf_roughtime_pubk;
static int hf_roughtime_value;
static int hf_roughtime_time;
static int hf_roughtime_time_low;
static int hf_roughtime_time_up;
static int hf_roughtime_response_in;
static int hf_roughtime_response_to;

/* Map struct */
typedef struct _roughtime_map_t {
    uint32_t value_offset;
    uint32_t type;
    uint32_t length;
} roughtime_map_t;

/* Type enum */
typedef enum _roughtime_proto_type_e {
    PROTO_TYPE_UNDEFINED,
    PROTO_TYPE_GOOGLE,
    PROTO_TYPE_IETF
} roughtime_proto_type_e;

/* Expert fields */
static expert_field ei_roughtime_illegal_length;
static expert_field ei_roughtime_response_too_large;
static expert_field ei_roughtime_path_too_large;

/* Trees */
static int ett_roughtime;
static int ett_roughtime_srep;
static int ett_roughtime_cert;
static int ett_roughtime_dele;

/* Request/response tracking */
typedef struct _roughtime_req_resp_t {
    uint32_t req_frame;
    uint32_t resp_frame;
    uint32_t req_length;
    uint32_t resp_length;
} roughtime_req_resp_t;

static const range_string roughtime_version_rvals[] = {
    { 0x00000000, 0x00000000, "Reserved" },
    { 0x00000001, 0x00000001, "Roughtime Version 1" },
    /* DRAFTS: Subject to removal? */
    { 0x80000008, 0x80000008, "draft-ietf-ntp-roughtime-8" },
    { 0x80000009, 0x80000009, "draft-ietf-ntp-roughtime-9" },
    { 0x8000000A, 0x8000000A, "draft-ietf-ntp-roughtime-10" },
    { 0x8000000B, 0x8000000B, "draft-ietf-ntp-roughtime-11" },
    { 0x8000000C, 0x8000000C, "draft-ietf-ntp-roughtime-12" },
    /* END DRAFTS */
    { 0x8000000D, 0xFFFFFFFF, "Reserved (Private or Experimental use)" },
    {          0,          0, NULL }
};

static proto_item* add_generated_time_item(tvbuff_t *tvb, proto_tree *tree, int hf, nstime_t *ts) {
    proto_item *pi = proto_tree_add_time(tree, hf, tvb, 0, 0, ts);
    proto_item_set_generated(pi);
    return pi;
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_roughtime_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, roughtime_proto_type_e proto_type) {

    uint32_t num_tags, tag, tag_offset = 0, type, radius_i = 0;
    nstime_t time_midp, time_radius, time_lower, time_upper;
    proto_item *pi;
    proto_tree *msg_tree;
    wmem_array_t *map_arr = wmem_array_new(pinfo->pool, sizeof(roughtime_map_t));
    roughtime_map_t *map, map_init = {.type = 0, .length = 0};
    conversation_t *conv;
    roughtime_req_resp_t *conv_data;

    /* This function will get called recursively, guard it */
    increment_dissection_depth(pinfo);

    /* Presence of fields of interest for req/resp tracking */
    bool fa_srep = false, fa_nonc = false;

    int offset = 0;
    nstime_set_unset(&time_midp);
    nstime_set_unset(&time_radius);

    proto_tree_add_item_ret_uint(tree, hf_roughtime_num_tags, tvb, 0, 4, ENC_LITTLE_ENDIAN, &num_tags);
    offset += 4;

    conv = find_or_create_conversation(pinfo);
    conv_data = (roughtime_req_resp_t *)conversation_get_proto_data(conv, proto_roughtime);

    /*
     * Value Offset Block
     *
     * Listed after Num. Tags in 4-octet chunks
     */
    tag = 0;
    while(tag < num_tags) {
        if(tag == 0) {
            pi = proto_tree_add_uint(tree, hf_roughtime_offset, tvb, offset, 0, 0);
            proto_item_set_generated(pi);
        } else {
            proto_tree_add_item_ret_uint(tree, hf_roughtime_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &tag_offset);
            offset += 4;
        }
        map_init.value_offset = tag_offset;
        wmem_array_append_one(map_arr, map_init);

        // Calculate the value lengths of the preceding entry
        if(tag > 0) {
            map = (roughtime_map_t*)wmem_array_index(map_arr, tag-1);
            map->length = tag_offset - map->value_offset;
        }
        // Calculate the value lengths of the last entry
        if(tag + 1 == num_tags) {
            map = (roughtime_map_t*)wmem_array_index(map_arr, tag);
            map->length = tag_offset - map->value_offset;
            map->length = tvb_reported_length_remaining(tvb, offset + map->value_offset + 4*num_tags);
        }

        tag++;
    }

    /*
     * Tag Block
     *
     * Listed after Value Offset Block in 4-octet chunks
     */
    tag = 0;
    while(tag < num_tags) {

        map = (roughtime_map_t*)wmem_array_index(map_arr, tag);

        type = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
        const uint8_t *type_str;

        // If we reached the PAD-tag which is terminated by 0xFF, read only 3 octets and extend the item length.
        // All other 3-char tags are null-terminated.
        if(type == TAG_TYPE_PAD) {
            pi = proto_tree_add_item_ret_string(tree, hf_roughtime_tag, tvb, offset, 3, ENC_ASCII, pinfo->pool, &type_str);
            proto_item_set_len(pi, 4);
        } else {
            proto_tree_add_item_ret_string(tree, hf_roughtime_tag, tvb, offset, 4, ENC_ASCII, pinfo->pool, &type_str);
        }

        col_append_sep_str(pinfo->cinfo, COL_INFO, " ", type_str);

        map->type = type;
        offset += 4;
        tag++;
    }

    /*
     * Value Block
     *
     * Listed after Tag Block, each with variable length
     */
    tag = 0;
    while(tag < num_tags) {

        map = (roughtime_map_t*)wmem_array_index(map_arr, tag);

        switch (map->type)
        {
            case TAG_TYPE_SREP:
                fa_srep = true;
                pi = proto_tree_add_item(tree, hf_roughtime_srep, tvb, offset, map->length, ENC_NA);
                msg_tree = proto_item_add_subtree(pi, ett_roughtime_srep);
                dissect_roughtime_msg(tvb_new_subset_length(tvb, offset, map->length), pinfo, msg_tree, proto_type);
                break;

            case TAG_TYPE_NONC:
                fa_nonc = true;
                proto_tree_add_item(tree, hf_roughtime_nonce, tvb, offset, map->length, ENC_NA);
                break;

            case TAG_TYPE_VER:
            case TAG_TYPE_VERS:
                if(map->length == 0) {
                    // Add empty item for informational purpose
                    proto_tree_add_item(tree, hf_roughtime_ver, tvb, offset, 0, ENC_NA);
                }
                else if(map->length % 4 == 0) {
                    for(uint32_t i = 0; i < map->length; i += 4) {
                        proto_tree_add_item(tree, hf_roughtime_ver, tvb, offset + i, 4, ENC_LITTLE_ENDIAN);
                    }
                }
                else {
                    expert_add_info(pinfo, tree, &ei_roughtime_illegal_length);
                }
                break;

            case TAG_TYPE_ZZZZ:
            case TAG_TYPE_PAD:
                proto_tree_add_item(tree, hf_roughtime_pad, tvb, offset, map->length, ENC_NA);
                break;

            case TAG_TYPE_SIG:
                proto_tree_add_item(tree, hf_roughtime_sig, tvb, offset, map->length, ENC_NA);
                if(map->length != 64) {
                    expert_add_info(pinfo, tree, &ei_roughtime_illegal_length);
                }
                break;

            case TAG_TYPE_SRV:
                proto_tree_add_item(tree, hf_roughtime_srv, tvb, offset, map->length, ENC_NA);
                break;

            case TAG_TYPE_CERT:
                pi = proto_tree_add_item(tree, hf_roughtime_cert, tvb, offset, map->length, ENC_NA);
                msg_tree = proto_item_add_subtree(pi, ett_roughtime_cert);
                dissect_roughtime_msg(tvb_new_subset_length(tvb, offset, map->length), pinfo, msg_tree, proto_type);
                break;

            case TAG_TYPE_INDX:
                proto_tree_add_item(tree, hf_roughtime_index, tvb, offset, map->length, ENC_NA);
                if(map->length != 4) {
                    expert_add_info(pinfo, tree, &ei_roughtime_illegal_length);
                }
                break;

            case TAG_TYPE_PATH:
                if(map->length == 0) {
                    // Add empty item for informational purpose
                    proto_tree_add_item(tree, hf_roughtime_path, tvb, offset, 0, ENC_NA);
                }
                else if(proto_type == PROTO_TYPE_GOOGLE && map->length % 64 == 0) {
                    for(uint32_t i = 0; i < map->length; i += 64) {
                        proto_tree_add_item(tree, hf_roughtime_path, tvb, offset + i, 64, ENC_NA);
                    }
                }
                else if(proto_type == PROTO_TYPE_IETF && map->length % 32 == 0) {
                    for(uint32_t i = 0; i < map->length; i += 32) {
                        proto_tree_add_item(tree, hf_roughtime_path, tvb, offset + i, 32, ENC_NA);
                    }
                    if(map->length > 32*32) {
                        expert_add_info(pinfo, tree, &ei_roughtime_path_too_large);
                    }
                }
                else {
                    proto_tree_add_item(tree, hf_roughtime_path, tvb, offset, map->length, ENC_NA);
                    expert_add_info(pinfo, tree, &ei_roughtime_illegal_length);
                }
                break;

            case TAG_TYPE_RADI:
                if(map->length != 4) {
                    expert_add_info(pinfo, tree, &ei_roughtime_illegal_length);
                    break;
                }

                if(proto_type == PROTO_TYPE_GOOGLE) {
                    pi = proto_tree_add_item_ret_uint(tree, hf_roughtime_radius, tvb, offset, 4, ENC_LITTLE_ENDIAN, &radius_i);
                    proto_item_append_text(pi, "µs");

                    nstime_set_zero(&time_radius);
                    time_radius.nsecs = radius_i*1000;
                }
                else if(proto_type == PROTO_TYPE_IETF) {
                    pi = proto_tree_add_item_ret_uint(tree, hf_roughtime_radius, tvb, offset, 4, ENC_LITTLE_ENDIAN, &radius_i);
                    proto_item_append_text(pi, "s");

                    nstime_set_zero(&time_radius);
                    time_radius.secs = radius_i;
                }
                break;

            case TAG_TYPE_MIDP:
                if(map->length != 8) {
                    expert_add_info(pinfo, tree, &ei_roughtime_illegal_length);
                    break;
                }

                if(proto_type == PROTO_TYPE_GOOGLE) {
                    proto_tree_add_time_item(tree, hf_roughtime_midp, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_USECS, &time_midp, NULL, NULL);
                    pi = proto_tree_add_item(tree, hf_roughtime_time, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_USECS);
                    proto_item_set_hidden(pi); // available for filtering

                }
                else if(proto_type == PROTO_TYPE_IETF) {
                    proto_tree_add_time_item(tree, hf_roughtime_midp, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_SECS, &time_midp, NULL, NULL);
                    pi = proto_tree_add_item(tree, hf_roughtime_time, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_SECS);
                    proto_item_set_hidden(pi); // available for filtering
                }
                break;

            case TAG_TYPE_ROOT:
                proto_tree_add_item(tree, hf_roughtime_root, tvb, offset, map->length, ENC_NA);
                break;

            case TAG_TYPE_PUBK:
                proto_tree_add_item(tree, hf_roughtime_pubk, tvb, offset, map->length, ENC_NA);
                break;

            case TAG_TYPE_MINT:
                if(map->length != 8) {
                    expert_add_info(pinfo, tree, &ei_roughtime_illegal_length);
                    break;
                }

                if(proto_type == PROTO_TYPE_GOOGLE) {
                    proto_tree_add_item(tree, hf_roughtime_mint, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_USECS);
                }
                else if(proto_type == PROTO_TYPE_IETF) {
                    proto_tree_add_item(tree, hf_roughtime_mint, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_SECS);
                }
                break;

            case TAG_TYPE_MAXT:
                if(map->length != 8) {
                    expert_add_info(pinfo, tree, &ei_roughtime_illegal_length);
                    break;
                }

                if(proto_type == PROTO_TYPE_GOOGLE) {
                    proto_tree_add_item(tree, hf_roughtime_maxt, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_USECS);
                }
                else if(proto_type == PROTO_TYPE_IETF) {
                    proto_tree_add_item(tree, hf_roughtime_maxt, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_SECS);
                }
                break;

            case TAG_TYPE_DELE:
                pi = proto_tree_add_item(tree, hf_roughtime_dele, tvb, offset, map->length, ENC_NA);
                msg_tree = proto_item_add_subtree(pi, ett_roughtime_dele);
                dissect_roughtime_msg(tvb_new_subset_length(tvb, offset, map->length), pinfo, msg_tree, proto_type);
                break;

            default:
                proto_tree_add_item(tree, hf_roughtime_value, tvb, offset, map->length, ENC_NA);
                break;
        }

        offset += map->length;
        tag++;
    }

    /*
     * Time calculation based on accuracy (Radius)
     */
    if(!nstime_is_unset(&time_radius) && !nstime_is_unset(&time_midp)) {

        nstime_delta(&time_lower, &time_midp, &time_radius);
        nstime_sum(&time_upper, &time_midp, &time_radius);

        add_generated_time_item(tvb, tree, hf_roughtime_time_low, &time_lower);
        add_generated_time_item(tvb, tree, hf_roughtime_time_up, &time_upper);
    }

    /*
     * Conversation data
     *
     * Checks must only suceed on top-level message (non-recursive)
     */
    if(conv_data && pinfo->dissection_depth == 1) {

        if(fa_srep && conv_data->resp_frame == 0) {
            conv_data->resp_frame = pinfo->num;
            conv_data->resp_length = tvb_reported_length(tvb);
        }
        else if (fa_nonc && conv_data->req_frame == 0) {
            conv_data->req_frame = pinfo->num;
            conv_data->req_length = tvb_reported_length(tvb);
        }
    }

    decrement_dissection_depth(pinfo);

    return offset;
}

static int
dissect_roughtime(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset;
    uint32_t msg_len;
    proto_item *ti, *pi, *ci;
    proto_tree *roughtime_tree;
    conversation_t *conv;
    roughtime_req_resp_t *conv_data;
    roughtime_proto_type_e proto_type = PROTO_TYPE_UNDEFINED;

    offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Roughtime");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_roughtime, tvb, 0, 0, ENC_NA);
    roughtime_tree = proto_item_add_subtree(ti, ett_roughtime);

    /* Conversation init */
    conv = find_or_create_conversation(pinfo);
    conv_data = (roughtime_req_resp_t *)conversation_get_proto_data(conv, proto_roughtime);
    if (!conv_data) {
        conv_data = wmem_new(wmem_file_scope(), roughtime_req_resp_t);
        conv_data->req_frame = 0;
        conv_data->resp_frame = 0;
        conv_data->req_length = 0;
        conv_data->resp_length = 0;
        conversation_add_proto_data(conv, proto_roughtime, conv_data);
    }

    /*
     * The protocol type
     * If we have no IETF header, assume Google's protocol version
     */
    if(tvb_get_uint64(tvb, 0, ENC_LITTLE_ENDIAN) == HDR_IETF) {
        proto_type = PROTO_TYPE_IETF;
        pi = proto_tree_add_string(roughtime_tree, hf_roughtime_proto, tvb, 0, 0, PROTO_TEXT_IETF);
        proto_item_set_generated(pi);
        proto_item_append_text(ti, ", Proto: %s", PROTO_TEXT_IETF);
        col_append_fstr(pinfo->cinfo, COL_INFO, "Proto: %s", PROTO_TEXT_IETF);
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Tags:");

        proto_tree_add_item(roughtime_tree, hf_roughtime_hdr, tvb, 0, 8, ENC_ASCII);
        offset += 8;

        proto_tree_add_item_ret_uint(roughtime_tree, hf_roughtime_msg_len, tvb, offset, 4, ENC_LITTLE_ENDIAN, &msg_len);
        offset += 4;

        offset += dissect_roughtime_msg(
            tvb_new_subset_length(tvb, offset, msg_len),
            pinfo, roughtime_tree, proto_type);

    } else {
        proto_type = PROTO_TYPE_GOOGLE;
        pi = proto_tree_add_string(roughtime_tree, hf_roughtime_proto, tvb, 0, 0, PROTO_TEXT_GOOGLE);
        proto_item_set_generated(pi);
        proto_item_append_text(ti, ", Proto: %s", PROTO_TEXT_GOOGLE);
        col_append_fstr(pinfo->cinfo, COL_INFO, "Proto: %s", PROTO_TEXT_GOOGLE);
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Tags:");

        offset += dissect_roughtime_msg(
            tvb_new_subset_remaining(tvb, offset),
            pinfo, roughtime_tree, proto_type);
    }

    /*
     * Request/Response Tracking
     *
     * Request and response is determined by the tags available in a Roughtime message.
     * -> Handled in dissect_roughtime_msg()
     *
     *   Request:  Never has SREP
     *   Response: Has SREP
     *
     */
    if(conv_data) {
        if(conv_data->req_frame > 0 && conv_data->resp_frame > 0 && conv_data->req_frame == pinfo->num) {
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "%s, ", "Request");
            ci = proto_tree_add_uint(roughtime_tree, hf_roughtime_response_in, tvb, 0, 0, conv_data->resp_frame);
            proto_item_set_generated(ci);
        }
        else if (conv_data->req_frame > 0 && conv_data->resp_frame > 0 && conv_data->resp_frame == pinfo->num) {
            col_prepend_fstr(pinfo->cinfo, COL_INFO, "%s, ", "Response");
            ci = proto_tree_add_uint(roughtime_tree, hf_roughtime_response_to, tvb, 0, 0, conv_data->req_frame);
            proto_item_set_generated(ci);

            // The response must be smaller than the request to avoid amplification
            if( conv_data->req_length > 0 && conv_data->resp_length > 0 &&
                conv_data->resp_length > conv_data->req_length )
            {
                expert_add_info(pinfo, roughtime_tree, &ei_roughtime_response_too_large);
            }
        }
    }

    proto_item_set_end(ti, tvb, offset);
    return offset;
}

void
proto_register_roughtime(void)
{
    static hf_register_info hf[] = {
        { &hf_roughtime_proto,
            { "Protocol", "roughtime.proto",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_hdr,
            { "Header", "roughtime.hdr",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_msg_len,
            { "Message Length", "roughtime.msg_len",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_srep,
            { "Signed Response", "roughtime.srep",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_cert,
            { "Certificate", "roughtime.cert",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_dele,
            { "Delegation", "roughtime.dele",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_num_tags,
            { "Number of Tags", "roughtime.numtags",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_offset,
            { "Value Offset", "roughtime.offset",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_tag,
            { "Tag", "roughtime.tag",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_nonce,
            { "Nonce", "roughtime.nonce",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_ver,
            { "Version", "roughtime.ver",
            FT_UINT32, BASE_HEX | BASE_RANGE_STRING,
            RVALS(roughtime_version_rvals), 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_sig,
            { "Signature", "roughtime.sig",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_srv,
            { "Server Key", "roughtime.srv",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_index,
            { "Index", "roughtime.index",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_path,
            { "Path", "roughtime.path",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_radius,
            { "Radius", "roughtime.radius",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_midp,
            { "Midpoint", "roughtime.midp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_mint,
            { "Min. Time", "roughtime.mint",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_maxt,
            { "Max. Time", "roughtime.maxt",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_root,
            { "Root", "roughtime.root",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_pubk,
            { "Public Key", "roughtime.pubk",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_value,
            { "Value", "roughtime.value",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_pad,
            { "Padding", "roughtime.pad",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_time,
            { "Time", "roughtime.time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
            NULL, 0x0,
            "Midpoint of guaranteed time", HFILL }
        },
        { &hf_roughtime_time_low,
            { "Time (lower)", "roughtime.time.low",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
            NULL, 0x0,
            "Calculated lower bound of guaranteed time", HFILL }
        },
        { &hf_roughtime_time_up,
            { "Time (upper)", "roughtime.time.up",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
            NULL, 0x0,
            "Calculated upper bound of guaranteed time", HFILL }
        },
        { &hf_roughtime_response_in,
            { "Response In", "roughtime.response_in",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            NULL, HFILL }
        },
        { &hf_roughtime_response_to,
            { "Response To", "roughtime.response_to",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_roughtime_illegal_length,
            { "roughtime.length.illegal", PI_MALFORMED, PI_ERROR,
                "Illegal field length", EXPFILL }
        },
        { &ei_roughtime_response_too_large,
            { "roughtime.response.too_large", PI_MALFORMED, PI_ERROR,
                "Response is larger than request", EXPFILL }
        },
        { &ei_roughtime_path_too_large,
            { "roughtime.path.too_large", PI_MALFORMED, PI_ERROR,
                "Merkle tree height exceeded", EXPFILL }
        },
    };

    static int *ett[] = {
        &ett_roughtime,
        &ett_roughtime_srep,
        &ett_roughtime_cert,
        &ett_roughtime_dele,
    };

    expert_module_t* expert_roughtime;

    proto_roughtime = proto_register_protocol("Roughtime", "Roughtime", "roughtime");

    proto_register_field_array(proto_roughtime, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_roughtime = expert_register_protocol(proto_roughtime);
    expert_register_field_array(expert_roughtime, ei, array_length(ei));

    roughtime_handle = register_dissector("roughtime", dissect_roughtime, proto_roughtime);
}

void
proto_reg_handoff_roughtime(void)
{
    dissector_add_uint_range_with_preference("udp.port", "2002-2003", roughtime_handle);
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
