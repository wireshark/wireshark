/* packet-hpfeeds.c
 * Routines for Honeypot Protocol Feeds packet disassembly
 * Copyright 2013, Sebastiano DI PAOLA - <sebastiano.dipaola@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/*
 * Additional information regarding hpfeeds protocol can be found here
 * https://redmine.honeynet.org/projects/hpfeeds/wiki
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/tap.h>
#include <epan/stats_tree.h>
#include <epan/wmem_scopes.h>

#include "packet-tcp.h"

struct HpfeedsTap {
    guint payload_size;
    guint8* channel;
    guint8 opcode;
};

static int hpfeeds_tap = -1;

static const gchar* st_str_channels_payload = "Payload size per channel";
static const gchar* st_str_opcodes = "Opcodes";

static int st_node_channels_payload = -1;
static int st_node_opcodes = -1;

static wmem_list_t* channels_list;

struct channel_node {
    guint8* channel;
    guint st_node_channel_payload;
};

void proto_register_hpfeeds(void);
void proto_reg_handoff_hpfeeds(void);

static heur_dissector_list_t heur_subdissector_list;

/* Preferences */
static gboolean hpfeeds_desegment = TRUE;
static gboolean try_heuristic = TRUE;

static int proto_hpfeeds = -1;

static int hf_hpfeeds_opcode = -1;
static int hf_hpfeeds_msg_length = -1;
static int hf_hpfeeds_nonce = -1;
static int hf_hpfeeds_secret = -1;
static int hf_hpfeeds_payload = -1;
static int hf_hpfeeds_server_len = -1;
static int hf_hpfeeds_server = -1;
static int hf_hpfeeds_ident_len = -1;
static int hf_hpfeeds_ident = -1;
static int hf_hpfeeds_channel = -1;
static int hf_hpfeeds_chan_len = -1;
static int hf_hpfeeds_errmsg = -1;

static gint ett_hpfeeds = -1;

static expert_field ei_hpfeeds_opcode_unknown = EI_INIT;

/* OPCODE */
#define OP_ERROR       0         /* error message*/
#define OP_INFO        1         /* server name, nonce */
#define OP_AUTH        2         /* client id, sha1(nonce+authkey) */
#define OP_PUBLISH     3         /* client id, channelname, payload */
#define OP_SUBSCRIBE   4         /* client id, channelname*/

/* OFFSET FOR HEADER */
#define HPFEEDS_HDR_LEN  5

static const value_string opcode_vals[] = {
    { OP_ERROR,      "Error" },
    { OP_INFO,       "Info" },
    { OP_AUTH,       "Auth" },
    { OP_PUBLISH,    "Publish" },
    { OP_SUBSCRIBE,  "Subscribe" },
    { 0,              NULL },
};

static void
dissect_hpfeeds_error_pdu(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    proto_tree_add_item(tree, hf_hpfeeds_errmsg, tvb, offset, -1, ENC_ASCII);
}

static void
dissect_hpfeeds_info_pdu(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint8 len = 0;
    proto_tree *data_subtree;
    guint8 *strptr = NULL;

    len = tvb_get_guint8(tvb, offset);
    /* don't move the offset yet as we need to get data after this operation */
    strptr = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1, len, ENC_ASCII);
    data_subtree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_hpfeeds, NULL, "Broker: %s", strptr);

    proto_tree_add_item(data_subtree, hf_hpfeeds_server_len, tvb, offset, 1,
        ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(data_subtree, hf_hpfeeds_server, tvb, offset, len,
        ENC_ASCII);
    offset += len;

    proto_tree_add_item(data_subtree, hf_hpfeeds_nonce, tvb, offset, -1,
        ENC_NA);
}

static void
dissect_hpfeeds_auth_pdu(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint8 len = 0;

    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_hpfeeds_ident_len, tvb,
                    offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_hpfeeds_ident, tvb,
                    offset, len, ENC_ASCII);
    offset += len;

    proto_tree_add_item(tree, hf_hpfeeds_secret, tvb,
                    offset, -1, ENC_NA);
}

static guint8*
hpfeeds_get_channel_name(tvbuff_t* tvb, guint offset)
{
    guint8 len = tvb_get_guint8(tvb, offset);
    offset += len + 1;
    len = tvb_get_guint8(tvb, offset);
    offset += 1;
    return tvb_get_string_enc(wmem_file_scope(), tvb, offset, len, ENC_ASCII);
}

static guint
hpfeeds_get_payload_size(tvbuff_t* tvb, guint offset)
{
    guint message_len = tvb_get_ntohl(tvb, offset);
    guint ident_len = tvb_get_guint8(tvb, offset + 5);
    guint channel_len = tvb_get_guint8(tvb, offset + 6 + ident_len);
    return (message_len - 2 - ident_len - 1 - channel_len);
}

static void
dissect_hpfeeds_publish_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    guint offset)
{
    guint8 len = 0;
    heur_dtbl_entry_t *hdtbl_entry;
    tvbuff_t *next_tvb;
    const guint8 *channelname = NULL;
    const char* save_match_string = NULL;

    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_hpfeeds_ident_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_hpfeeds_ident, tvb, offset, len, ENC_ASCII);
    offset += len;
    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_hpfeeds_chan_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* get the channel name as ephemeral string to pass it to the heuristic decoders */
    proto_tree_add_item_ret_string(tree, hf_hpfeeds_channel, tvb, offset, len, ENC_ASCII|ENC_NA,
        wmem_packet_scope(), &channelname);
    offset += len;

    /* try the heuristic dissectors */
    if (try_heuristic) {
        /* save the current match_string before calling the subdissectors */
        if (pinfo->match_string)
            save_match_string = pinfo->match_string;
        pinfo->match_string = (const char*)channelname;

        next_tvb = tvb_new_subset_remaining(tvb, offset);

        if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, &hdtbl_entry, NULL)) {
            return;
        }

        pinfo->match_string = save_match_string;
    }

    /* heuristic failed. Print remaining bytes as flat payload */
    proto_tree_add_item(tree, hf_hpfeeds_payload, tvb, offset, -1, ENC_NA);
}

static void hpfeeds_stats_tree_init(stats_tree* st)
{
    st_node_channels_payload = stats_tree_create_node(st, st_str_channels_payload, 0, STAT_DT_INT, TRUE);
    st_node_opcodes = stats_tree_create_pivot(st, st_str_opcodes, 0);

    channels_list = wmem_list_new(wmem_epan_scope());
}

static tap_packet_status hpfeeds_stats_tree_packet(stats_tree* st _U_, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
{
    const struct HpfeedsTap *pi = (const struct HpfeedsTap *)p;
    wmem_list_frame_t* head = wmem_list_head(channels_list);
    wmem_list_frame_t* cur = head;
    struct channel_node* ch_node;

    if (pi->opcode == OP_PUBLISH) {
        /* search an existing channel node and create it if it does not */
        while(cur != NULL) {
            ch_node = (struct channel_node*)wmem_list_frame_data(cur);
            if (strncmp((gchar*)ch_node->channel, (gchar*)pi->channel, strlen((gchar*)pi->channel)) == 0) {
                break;
            }
            cur = wmem_list_frame_next(cur);
        }

        if (cur == NULL) {
            ch_node = wmem_new0(wmem_file_scope(), struct channel_node);
            ch_node->channel = (guchar*)wmem_strdup(wmem_file_scope(), (gchar*)pi->channel);
            ch_node->st_node_channel_payload = stats_tree_create_node(st, (gchar*)ch_node->channel,
                st_node_channels_payload, STAT_DT_INT, FALSE);
            wmem_list_append(channels_list, ch_node);
        }

        avg_stat_node_add_value_int(st, st_str_channels_payload, 0, FALSE, pi->payload_size);
        avg_stat_node_add_value_int(st, (gchar*)ch_node->channel, 0, FALSE, pi->payload_size);
    }

    stats_tree_tick_pivot(st, st_node_opcodes,
            val_to_str(pi->opcode, opcode_vals, "Unknown opcode (%d)"));
    return TAP_PACKET_REDRAW;
}

static void
dissect_hpfeeds_subscribe_pdu(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint8 len = 0;
    /* get length of ident field */
    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_hpfeeds_ident_len, tvb, offset, 1,
        ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_hpfeeds_ident, tvb, offset, len,
        ENC_ASCII);
    /* move forward inside data */
    offset += len;
    proto_tree_add_item(tree, hf_hpfeeds_channel, tvb, offset, -1,
        ENC_ASCII);
}

/*
 * Get the length of the HPFEED message, including header
 * This is a trivial function, but it's mandatory as it is used as a callback
 * by the routine to re-assemble the protocol spread on multiple TCP packets
 */
static guint
get_hpfeeds_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return tvb_get_ntohl(tvb, offset + 0);
}

static int
dissect_hpfeeds_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    struct HpfeedsTap *hpfeeds_stats;

    /* We have already parsed msg length we need to skip to opcode offset */
    guint offset = 0;

    guint8 opcode;
    proto_item *ti;
    proto_tree *hpfeeds_tree, *data_subtree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HPFEEDS");

    ti = proto_tree_add_item(tree, proto_hpfeeds, tvb, 0, -1, ENC_NA);
    hpfeeds_tree = proto_item_add_subtree(ti, ett_hpfeeds);
    proto_tree_add_item(hpfeeds_tree, hf_hpfeeds_msg_length, tvb, offset,
        4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Get opcode and write it */
    opcode = tvb_get_guint8(tvb, offset);

    /* Clear out stuff in the info column */
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type %s",
        val_to_str(opcode, opcode_vals, "Unknown (0x%02x)"));

    ti = proto_tree_add_item(hpfeeds_tree, hf_hpfeeds_opcode, tvb, offset,
            1, ENC_BIG_ENDIAN);
    data_subtree = proto_item_add_subtree(ti, ett_hpfeeds);
    offset += 1;

    if (opcode >= array_length(opcode_vals) - 1) {
        expert_add_info_format(pinfo, ti, &ei_hpfeeds_opcode_unknown,
                "Unknown value %02x for opcode field", opcode);
    }

    if (tree) { /* we are being asked for details */
        switch (opcode) {
            case OP_ERROR:
                dissect_hpfeeds_error_pdu(tvb, data_subtree, offset);
            break;
            case OP_INFO:
                dissect_hpfeeds_info_pdu(tvb, data_subtree, offset);
            break;
            case OP_AUTH:
                dissect_hpfeeds_auth_pdu(tvb, data_subtree, offset);
            break;
            case OP_PUBLISH:
                dissect_hpfeeds_publish_pdu(tvb, pinfo, data_subtree, offset);
            break;
            case OP_SUBSCRIBE:
                dissect_hpfeeds_subscribe_pdu(tvb, data_subtree, offset);
            break;
            /* No need for a default, we check that outside the if(tree)
             * block earlier */
        }
    }

    /* In publish, generate stats every packet, even not in tree */
    hpfeeds_stats = wmem_new0(wmem_file_scope(), struct HpfeedsTap);
    if (opcode == OP_PUBLISH) {
        hpfeeds_stats->channel = hpfeeds_get_channel_name(tvb, offset);
        hpfeeds_stats->payload_size = hpfeeds_get_payload_size(tvb, 0);
    }

    hpfeeds_stats->opcode = opcode;
    tap_queue_packet(hpfeeds_tap, pinfo, hpfeeds_stats);
    return tvb_captured_length(tvb);
}

static int
dissect_hpfeeds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, hpfeeds_desegment, HPFEEDS_HDR_LEN,
        get_hpfeeds_pdu_len, dissect_hpfeeds_pdu, data);
    return tvb_captured_length(tvb);
}

void
proto_register_hpfeeds(void)
{
    static hf_register_info hf[] = {

        { &hf_hpfeeds_opcode,
            { "Opcode", "hpfeeds.opcode",
            FT_UINT8, BASE_DEC_HEX,
            VALS(opcode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_hpfeeds_msg_length,
            { "Message Length", "hpfeeds.msglen",
            FT_UINT32, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hpfeeds_nonce,
            { "Nonce", "hpfeeds.nonce",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hpfeeds_secret,
            { "Secret", "hpfeeds.secret",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hpfeeds_payload,
            { "Payload", "hpfeeds.payload",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hpfeeds_server,
            { "Server", "hpfeeds.server",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hpfeeds_ident,
            { "Ident", "hpfeeds.ident",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hpfeeds_channel,
            { "Channel", "hpfeeds.channel",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hpfeeds_chan_len,
            { "Channel length", "hpfeeds.channel_len",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hpfeeds_ident_len,
            { "Ident length", "hpfeeds.ident_len",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hpfeeds_errmsg,
            { "Error message", "hpfeeds.errmsg",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hpfeeds_server_len,
            { "Server length", "hpfeeds.server_len",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
    };


    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_hpfeeds
    };

    static ei_register_info ei[] = {
        { &ei_hpfeeds_opcode_unknown, { "hpfeeds.opcode.unknown", PI_PROTOCOL, PI_WARN, "Unknown value for opcode field", EXPFILL }},
    };

    module_t *hpfeeds_module;
    expert_module_t* expert_hpfeeds;

    proto_hpfeeds = proto_register_protocol (
        "HPFEEDS HoneyPot Feeds Protocol", /* name */
        "HPFEEDS",      /* short name */
        "hpfeeds"       /* abbrev     */
        );

    heur_subdissector_list = register_heur_dissector_list("hpfeeds", proto_hpfeeds);

    proto_register_field_array(proto_hpfeeds, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_hpfeeds = expert_register_protocol(proto_hpfeeds);
    expert_register_field_array(expert_hpfeeds, ei, array_length(ei));

    hpfeeds_module = prefs_register_protocol(proto_hpfeeds, NULL);
    prefs_register_bool_preference(hpfeeds_module, "desegment_hpfeeds_messages",
        "Reassemble HPFEEDS messages spanning multiple TCP segments",
        "Whether the HPFEEDS dissector should reassemble messages spanning "
        "multiple TCP segments. "
        "To use this option, you must also enable \"Allow subdissectors to "
        "reassemble TCP streams\" in the TCP protocol settings.",
        &hpfeeds_desegment);

    prefs_register_bool_preference(hpfeeds_module, "try_heuristic",
        "Try heuristic sub-dissectors",
        "Try to decode the payload using an heuristic sub-dissector",
        &try_heuristic);

    hpfeeds_tap = register_tap("hpfeeds");
}

void
proto_reg_handoff_hpfeeds(void)
{
    dissector_handle_t hpfeeds_handle;

    hpfeeds_handle = create_dissector_handle(dissect_hpfeeds, proto_hpfeeds);
    stats_tree_register("hpfeeds", "hpfeeds", "HPFEEDS", 0, hpfeeds_stats_tree_packet, hpfeeds_stats_tree_init, NULL);

    dissector_add_for_decode_as_with_preference("tcp.port", hpfeeds_handle);
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
