/* packet-ilnp.c
 * Routines for ILNP dissection
 * Copyright 2025, Shubh Sinhal <shubh.sinhal@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * ILNP is an extension on IPv6 which changes the addressing semantics to
 * treat the Identifier (Node Identifier - 64 bits) and the Locator (Network
 * address - 64 bits) to improve mobility and multi-homing support
 *
 * RFC 6740 - ILNP Architectural Description
 * RFC 6741 - ILNP Engineering Considerations
 *
 * More information about ILNP can be found at "https://ilnp.cs.st-andrews.ac.uk/"
 *
 * This dissector was developed using the IPv6 dissector as a reference base
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/address_types.h>
#include <epan/to_str.h>
#include <epan/proto.h>
#include <epan/tap.h>
#include <epan/conversation_table.h>
#include <epan/conversation_filter.h>
#include <epan/stats_tree.h>

void proto_register_ilnp(void);

/* Conversation data */
struct ilnp_analysis {
    uint32_t initial_frame; // Initial frame starting this conversation
    uint32_t stream;        // Stream ID
};

typedef struct _ilnp_tap_info_t {
    address ilnp_src_l64;     /* source l64*/
    address ilnp_src_nid;     /* source nid */
    address ilnp_dst_l64;     /* destination l64*/
    address ilnp_dst_nid;     /* destination nid */
    address ilnp_src_ilv;     /* source ilv */
    address ilnp_dst_ilv;     /* destination ilv */
    uint32_t ilnp_stream;     /* track conversations */
} ilnp_tap_info_t;

static int proto_ilnp;

/* Header fields */
static int hf_ilnp_nonce;
static int hf_ilnp_src_l64;
static int hf_ilnp_dst_l64;
static int hf_ilnp_src_nid;
static int hf_ilnp_dst_nid;
static int hf_ilnp_src_ilv;
static int hf_ilnp_dst_ilv;
static int hf_ilnp_l64;
static int hf_ilnp_nid;
static int hf_ilnp_ilv;
static int hf_ilnp_stream;

static int ett_ilnp;

static dissector_handle_t ilnp_handle;

// Global ILNP Stream counter
static uint32_t ilnp_stream_count;

/* ILNP tap handle */
static int ilnp_tap;


/***********************************************************************************************************************************
 *
 * CONVERSATIONS
 *
 ***********************************************************************************************************************************/

static const char* ilnp_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
    if ((filter == CONV_FT_SRC_ADDRESS) && (conv->src_address.type == AT_ILNP_NID))
        return "ilnp.src_nid";

    if ((filter == CONV_FT_DST_ADDRESS) && (conv->dst_address.type == AT_ILNP_NID))
        return "ilnp.dst_nid";

    if ((filter == CONV_FT_ANY_ADDRESS) && (conv->src_address.type == AT_ILNP_NID))
        return "ilnp.nid";

    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t ilnp_ct_dissector_info = {&ilnp_conv_get_filter_type};

// Callback to add an ilnp conversation to the Statistics->Conversations->ILNP table
static tap_packet_status
ilnp_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pct;
    hash->flags = flags;

    const ilnp_tap_info_t *ilnp_tap_info = (const ilnp_tap_info_t *)vip;

    add_conversation_table_data_with_conv_id(hash, &ilnp_tap_info->ilnp_src_nid, &ilnp_tap_info->ilnp_dst_nid, 0, 0,
            (conv_id_t)ilnp_tap_info->ilnp_stream, 1, pinfo->fd->pkt_len,
            &pinfo->rel_ts, &pinfo->abs_ts, &ilnp_ct_dissector_info, CONVERSATION_ILNP);

    return TAP_PACKET_REDRAW;
}

static const char* ilnp_endpoint_get_filter_type(endpoint_item_t* endpoint, conv_filter_type_e filter)
{
    if ((filter == CONV_FT_ANY_ADDRESS) && (endpoint->myaddress.type == AT_ILNP_NID))
        return "ilnp.nid";

    return CONV_FILTER_INVALID;
}

static et_dissector_info_t ilnp_endpoint_dissector_info = {&ilnp_endpoint_get_filter_type};

// Callback to add an ilnp nids to the Statistics->Endpoints->ILNP table
static tap_packet_status
ilnp_endpoint_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pit;
    hash->flags = flags;

    const ilnp_tap_info_t *ilnp_tap_info = (const ilnp_tap_info_t *)vip;

    add_endpoint_table_data(hash, &ilnp_tap_info->ilnp_src_nid, 0, true, 1,
                pinfo->fd->pkt_len, &ilnp_endpoint_dissector_info, ENDPOINT_ILNP);
    add_endpoint_table_data(hash, &ilnp_tap_info->ilnp_dst_nid, 0, false, 1,
                pinfo->fd->pkt_len, &ilnp_endpoint_dissector_info, ENDPOINT_ILNP);

    return TAP_PACKET_REDRAW;
}

static bool
ilnp_filter_valid(packet_info *pinfo, void *user_data _U_)
{
    return proto_is_frame_protocol(pinfo->layers, "ilnp");
}

static char*
ilnp_build_filter(packet_info *pinfo, void *user_data _U_)
{
    address src_nid, dst_nid;

    alloc_address_wmem(pinfo->pool, &src_nid, AT_ILNP_NID, 8, pinfo->net_src.data);
    alloc_address_wmem(pinfo->pool, &dst_nid, AT_ILNP_NID, 8, pinfo->net_dst.data);

    return ws_strdup_printf("ilnp.nid eq %s and ilnp.nid eq %s",
                address_to_str(pinfo->pool, &src_nid),
                address_to_str(pinfo->pool, &dst_nid));
}


static struct ilnp_analysis*
init_ilnp_conversation_data(packet_info *pinfo) {
    struct ilnp_analysis *ilnpd;

    /* Initialize the ip protocol data structure to add to the ilnp conversation */
    ilnpd=wmem_new0(wmem_file_scope(), struct ilnp_analysis);

    ilnpd->initial_frame = pinfo->num;
    ilnpd->stream = ilnp_stream_count++;

    return ilnpd;
}

static struct ilnp_analysis*
get_ilnp_conversation_data(conversation_t *conv, packet_info *pinfo) {
    struct ilnp_analysis *ilnpd;

    /* Get the data for this conversation */
    ilnpd = (struct ilnp_analysis *) conversation_get_proto_data(conv, proto_ilnp);
    if (!ilnpd) { // if it doesn't exist, initialise new one
        ilnpd = init_ilnp_conversation_data(pinfo);
        conversation_add_proto_data(conv, proto_ilnp, ilnpd);
    }

    return ilnpd;
}



/***********************************************************************************************************************************
 *
 * STATISTICS
 *
 ***********************************************************************************************************************************/

static int st_node_ilnp_nids = -1;
static int st_node_ilnp_src_nid = -1;
static int st_node_ilnp_dst_nid = -1;
static const char* st_str_ilnp_nid = "ILNP Statistics" STATS_TREE_MENU_SEPARATOR "All Node Identifiers";
static const char* st_str_ilnp_srcdst_nid = "ILNP Statistics" STATS_TREE_MENU_SEPARATOR "Source and Destination Node Identifier Addresses";
static const char* st_str_ilnp_src_nid = "Source ILNP Node Identifiers";
static const char* st_str_ilnp_dst_nid = "Destination ILNP Node Identifiers";

static int st_node_ilnp_l64s = -1;
static int st_node_ilnp_src_l64 = -1;
static int st_node_ilnp_dst_l64 = -1;
static const char* st_str_ilnp_l64 = "ILNP Statistics" STATS_TREE_MENU_SEPARATOR "All Locators";
static const char* st_str_ilnp_srcdst_l64 = "ILNP Statistics" STATS_TREE_MENU_SEPARATOR "Source and Destination Locator Addresses";
static const char* st_str_ilnp_src_l64 = "Source ILNP Locators";
static const char* st_str_ilnp_dst_l64 = "Destination ILNP Locators";

static int st_node_ilnp_ilvs = -1;
static int st_node_ilnp_src_ilv = -1;
static int st_node_ilnp_dst_ilv = -1;
static const char* st_str_ilnp_ilv = "ILNP Statistics" STATS_TREE_MENU_SEPARATOR "All Identifier-Locator Vectors";
static const char* st_str_ilnp_srcdst_ilv = "ILNP Statistics" STATS_TREE_MENU_SEPARATOR "Source and Destination Identifier-Locator Vector Addresses";
static const char* st_str_ilnp_src_ilv = "Source ILNP Identifier-Locator Vectors";
static const char* st_str_ilnp_dst_ilv = "Destination ILNP Identifier-Locator Vectors";

static int st_node_ilnp_ptype = -1;
static const char* st_str_ilnp_ptype = "ILNP Statistics" STATS_TREE_MENU_SEPARATOR "IP Protocol Types";


static void ilnp_nids_stats_tree_init(stats_tree* st) {
    st_node_ilnp_nids = stats_tree_create_node(st, st_str_ilnp_nid, 0, STAT_DT_INT, true);
}

static void ilnp_l64s_stats_tree_init(stats_tree* st) {
    st_node_ilnp_l64s = stats_tree_create_node(st, st_str_ilnp_l64, 0, STAT_DT_INT, true);
}

static void ilnp_ilvs_stats_tree_init(stats_tree* st) {
    st_node_ilnp_ilvs = stats_tree_create_node(st, st_str_ilnp_ilv, 0, STAT_DT_INT, true);
}

static tap_packet_status ilnp_nids_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p _U_, tap_flags_t flags _U_)
{
    const ilnp_tap_info_t* ilnpt = (const ilnp_tap_info_t*)p;
    tick_stat_node(st, st_str_ilnp_nid, 0, false);
    tick_stat_node(st, address_to_str(pinfo->pool, &ilnpt->ilnp_src_nid), st_node_ilnp_nids, false);
    tick_stat_node(st, address_to_str(pinfo->pool, &ilnpt->ilnp_dst_nid), st_node_ilnp_nids, false);
    return TAP_PACKET_REDRAW;
}

static tap_packet_status ilnp_l64s_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p _U_, tap_flags_t flags _U_)
{
    const ilnp_tap_info_t* ilnpt = (const ilnp_tap_info_t*)p;
    tick_stat_node(st, st_str_ilnp_l64, 0, false);
    tick_stat_node(st, address_to_str(pinfo->pool, &ilnpt->ilnp_src_l64), st_node_ilnp_l64s, false);
    tick_stat_node(st, address_to_str(pinfo->pool, &ilnpt->ilnp_dst_l64), st_node_ilnp_l64s, false);
    return TAP_PACKET_REDRAW;
}

static tap_packet_status ilnp_ilvs_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p _U_, tap_flags_t flags _U_)
{
    const ilnp_tap_info_t* ilnpt = (const ilnp_tap_info_t*)p;
    tick_stat_node(st, st_str_ilnp_ilv, 0, false);
    tick_stat_node(st, address_to_str(pinfo->pool, &ilnpt->ilnp_src_ilv), st_node_ilnp_ilvs, false);
    tick_stat_node(st, address_to_str(pinfo->pool, &ilnpt->ilnp_dst_ilv), st_node_ilnp_ilvs, false);
    return TAP_PACKET_REDRAW;
}

//Same as ip_srcdst_stats_tree_init
static void ilnp_srcdst_stats_tree_init(stats_tree* st,
    const char* st_str_src, int* st_node_src_ptr,
    const char* st_str_dst, int* st_node_dst_ptr)
{
    /* create one tree branch for source */
    *st_node_src_ptr = stats_tree_create_node(st, st_str_src, 0, STAT_DT_INT, true);
    /* set flag so this branch will always be sorted to top of tree */
    stat_node_set_flags(st, st_str_src, 0, false, ST_FLG_SORT_TOP);
    /* create another top level node for destination branch */
    *st_node_dst_ptr = stats_tree_create_node(st, st_str_dst, 0, STAT_DT_INT, true);
    /* set flag so this branch will not be expanded by default */
    stat_node_set_flags(st, st_str_dst, 0, false, ST_FLG_DEF_NOEXPAND);
}

static void
ilnp_srcdst_nid_stats_tree_init(stats_tree* st)
{
    ilnp_srcdst_stats_tree_init(st, st_str_ilnp_src_nid, &st_node_ilnp_src_nid, st_str_ilnp_dst_nid, &st_node_ilnp_dst_nid);
}
static void ilnp_srcdst_l64_stats_tree_init(stats_tree* st)
{
    ilnp_srcdst_stats_tree_init(st, st_str_ilnp_src_l64, &st_node_ilnp_src_l64, st_str_ilnp_dst_l64, &st_node_ilnp_dst_l64);
}

static void ilnp_srcdst_ilv_stats_tree_init(stats_tree* st)
{
    ilnp_srcdst_stats_tree_init(st, st_str_ilnp_src_ilv, &st_node_ilnp_src_ilv, st_str_ilnp_dst_ilv, &st_node_ilnp_dst_ilv);
}

static tap_packet_status ilnp_srcdst_stats_tree_packet(stats_tree* st,
    packet_info* pinfo,
    const address* src_addr,
    const address* dst_addr,
    int st_node_src,
    const char* st_str_src,
    int st_node_dst,
    const char* st_str_dst)
{
    /* update source branch */
    tick_stat_node(st, st_str_src, 0, false);
    tick_stat_node(st, address_to_str(pinfo->pool, src_addr), st_node_src, false);
    /* update destination branch */
    tick_stat_node(st, st_str_dst, 0, false);
    tick_stat_node(st, address_to_str(pinfo->pool, dst_addr), st_node_dst, false);
    return TAP_PACKET_REDRAW;
}

static tap_packet_status ilnp_srcdst_nid_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p _U_, tap_flags_t flags _U_)
{
    const ilnp_tap_info_t* ilnpt = (const ilnp_tap_info_t*)p;
    return ilnp_srcdst_stats_tree_packet(st, pinfo, &ilnpt->ilnp_src_nid, &ilnpt->ilnp_dst_nid, st_node_ilnp_src_nid, st_str_ilnp_src_nid, st_node_ilnp_dst_nid, st_str_ilnp_dst_nid);
}

static tap_packet_status ilnp_srcdst_l64_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p _U_, tap_flags_t flags _U_)
{
    const ilnp_tap_info_t* ilnpt = (const ilnp_tap_info_t*)p;
    return ilnp_srcdst_stats_tree_packet(st, pinfo, &ilnpt->ilnp_src_l64, &ilnpt->ilnp_dst_l64, st_node_ilnp_src_l64, st_str_ilnp_src_l64, st_node_ilnp_dst_l64, st_str_ilnp_dst_l64);
}

static tap_packet_status ilnp_srcdst_ilv_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p _U_, tap_flags_t flags _U_)
{
    const ilnp_tap_info_t* ilnpt = (const ilnp_tap_info_t*)p;
    return ilnp_srcdst_stats_tree_packet(st, pinfo, &ilnpt->ilnp_src_ilv, &ilnpt->ilnp_dst_ilv, st_node_ilnp_src_ilv, st_str_ilnp_src_ilv, st_node_ilnp_dst_ilv, st_str_ilnp_dst_ilv);
}

static void ilnp_ptype_stats_tree_init(stats_tree* st)
{
    st_node_ilnp_ptype = stats_tree_create_pivot(st, st_str_ilnp_ptype, 0);
}

static tap_packet_status ilnp_ptype_stats_tree_packet(stats_tree* st, packet_info* pinfo, epan_dissect_t* edt _U_, const void* p _U_, tap_flags_t flags _U_)
{
    stats_tree_tick_pivot(st, st_node_ilnp_ptype, port_type_to_str(pinfo->ptype));
    return TAP_PACKET_REDRAW;
}

/***********************************************************************************************************************************
 *
 * DISSECTION
 *
 ***********************************************************************************************************************************/

static int
dissect_ilnp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    proto_tree *ilnp_tree;
    proto_item *ilnp_item, *ti;
    uint8_t *str_ilnp_src_nid, *str_ilnp_src_l64,
            *str_ilnp_dst_nid, *str_ilnp_dst_l64,
            *str_ilnp_src_ilv, *str_ilnp_dst_ilv;
    conversation_t* conv;
    struct ilnp_analysis* ilnpd;
    ilnp_tap_info_t* ilnph;

    //ILNP works on top of IPv6 only (as it "repurposes" the address data)
    if ((pinfo->net_src.type != AT_IPv6) || (pinfo->net_dst.type != AT_IPv6))
        return 0;

    ilnph = wmem_new0(pinfo->pool, ilnp_tap_info_t);

    // Define ilnp tree and add it as a subtree to the main proto tree
    ilnp_item = proto_tree_add_item(tree, proto_ilnp, tvb, 0, -1, ENC_NA);
    ilnp_tree = proto_item_add_subtree(ilnp_item, ett_ilnp);

    // Add ILNP Nonce to subtree
    proto_tree_add_item(ilnp_tree, hf_ilnp_nonce, tvb, 0, -1, ENC_NA);

    //Set the NID as source and destination addresses of the packet
    alloc_address_wmem(pinfo->pool, &pinfo->src, AT_ILNP_NID, 8, ((uint8_t*)pinfo->net_src.data)+8);
    alloc_address_wmem(pinfo->pool, &pinfo->dst, AT_ILNP_NID, 8, ((uint8_t*)pinfo->net_dst.data)+8);

    //Get address data from the current network layer and put into tap data
    alloc_address_wmem(pinfo->pool, &ilnph->ilnp_src_l64, AT_ILNP_L64, 8, pinfo->net_src.data);
    alloc_address_wmem(pinfo->pool, &ilnph->ilnp_src_nid, AT_ILNP_NID, 8, ((uint8_t*)pinfo->net_src.data)+8);
    alloc_address_wmem(pinfo->pool, &ilnph->ilnp_dst_l64, AT_ILNP_L64, 8, pinfo->net_dst.data);
    alloc_address_wmem(pinfo->pool, &ilnph->ilnp_dst_nid, AT_ILNP_NID, 8, ((uint8_t*)pinfo->net_dst.data)+8);
    alloc_address_wmem(pinfo->pool, &ilnph->ilnp_src_ilv, AT_ILNP_ILV, 16, pinfo->net_src.data);
    alloc_address_wmem(pinfo->pool, &ilnph->ilnp_dst_ilv, AT_ILNP_ILV, 16, pinfo->net_dst.data);

    //Add tap data to the dissection tree

    // convert all addresses to strings for display
    str_ilnp_src_nid = address_to_str(pinfo->pool, &ilnph->ilnp_src_nid);
    str_ilnp_src_l64 = address_to_str(pinfo->pool, &ilnph->ilnp_src_l64);
    str_ilnp_dst_nid = address_to_str(pinfo->pool, &ilnph->ilnp_dst_nid);
    str_ilnp_dst_l64 = address_to_str(pinfo->pool, &ilnph->ilnp_dst_l64);
    str_ilnp_src_ilv = address_to_str(pinfo->pool, &ilnph->ilnp_src_ilv);
    str_ilnp_dst_ilv = address_to_str(pinfo->pool, &ilnph->ilnp_dst_ilv);

    // Add address fields to ILNP subtree.  Some fields without specifying src or dst for added filter options
    proto_tree_add_string(ilnp_tree, hf_ilnp_src_l64, tvb, 0, 0, str_ilnp_src_l64);
    ti = proto_tree_add_string(ilnp_tree, hf_ilnp_l64, tvb, 0, 0, str_ilnp_src_l64);
    proto_item_set_hidden(ti);
    proto_tree_add_string(ilnp_tree, hf_ilnp_src_nid, tvb, 0, 0, str_ilnp_src_nid);
    ti = proto_tree_add_string(ilnp_tree, hf_ilnp_nid, tvb, 0, 0, str_ilnp_src_nid);
    proto_item_set_hidden(ti);
    ti = proto_tree_add_string(ilnp_tree, hf_ilnp_src_ilv, tvb, 0, 0, str_ilnp_src_ilv);
    proto_item_set_hidden(ti);
    ti = proto_tree_add_string(ilnp_tree, hf_ilnp_ilv, tvb, 0, 0, str_ilnp_src_ilv);
    proto_item_set_hidden(ti);
    proto_tree_add_string(ilnp_tree, hf_ilnp_dst_l64, tvb, 0, 0, str_ilnp_dst_l64);
    ti = proto_tree_add_string(ilnp_tree, hf_ilnp_l64, tvb, 0, 0, str_ilnp_dst_l64);
    proto_item_set_hidden(ti);
    proto_tree_add_string(ilnp_tree, hf_ilnp_dst_nid, tvb, 0, 0, str_ilnp_dst_nid);
    ti = proto_tree_add_string(ilnp_tree, hf_ilnp_nid, tvb, 0, 0, str_ilnp_dst_nid);
    proto_item_set_hidden(ti);
    ti = proto_tree_add_string(ilnp_tree, hf_ilnp_dst_ilv, tvb, 0, 0, str_ilnp_dst_ilv);
    proto_item_set_hidden(ti);
    ti = proto_tree_add_string(ilnp_tree, hf_ilnp_ilv, tvb, 0, 0, str_ilnp_dst_ilv);
    proto_item_set_hidden(ti);

    // Add test to the main ILNP dropdown in the packet details pane.
    proto_item_append_text(ilnp_item, ", Src: %s, Dst: %s", str_ilnp_src_ilv, str_ilnp_dst_ilv);

    // does not use nonce or l64
    conv = find_conversation_strat(pinfo, CONVERSATION_ILNP, NO_PORT_X, false);
    if (!conv) { // if no conversation exists
        conv = conversation_new_strat(pinfo, CONVERSATION_ILNP, NO_PORTS);
    }
    else {    // otherwise add to existing conversation
        if (!(pinfo->fd->visited)) {
            if (pinfo->num > conv->last_frame) {
                conv->last_frame = pinfo->num;
            }
        }
    }

    // Get stream id for display
    ilnpd = get_ilnp_conversation_data(conv, pinfo);
    if (ilnpd) {
        // set stream id in tap info struct
        ilnph->ilnp_stream = ilnpd->stream;
        // add to protocol tree
        ti = proto_tree_add_uint(ilnp_tree, hf_ilnp_stream, tvb, 0, 0, ilnpd->stream);
        proto_item_set_generated(ti);
    }

    // queue packet to trigger linked tap listeners
    tap_queue_packet(ilnp_tap, pinfo, ilnph);

    return tvb_captured_length(tvb);
}

// Initialise the ILNP dissector with a stream count starting at 0
static void ilnp_init(void) {
    ilnp_stream_count = 0;
}

void proto_register_ilnp(void) {

    static hf_register_info hf[] = {
        { &hf_ilnp_nonce,
            { "ILNP Nonce Value", "ilnp.nonce", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ilnp_src_l64,
            { "Source L64", "ilnp.src_l64", FT_STRING, BASE_NONE, NULL, 0x0,
                "ILNP Source Locator", HFILL}
        },
        { &hf_ilnp_src_nid,
            { "Source NID", "ilnp.src_nid", FT_STRING, BASE_NONE, NULL, 0x0,
                "ILNP Source Node Identifier", HFILL}
        },
        { &hf_ilnp_dst_l64,
            { "Destination L64", "ilnp.dst_l64", FT_STRING, BASE_NONE, NULL, 0x0,
                "ILNP Destination Locator", HFILL}
        },
        { &hf_ilnp_dst_nid,
            { "Destination NID", "ilnp.dst_nid", FT_STRING, BASE_NONE, NULL, 0x0,
                "ILNP Destination Node Identifier", HFILL}
        },
        { &hf_ilnp_src_ilv,
            { "Source ILV", "ilnp.src_ilv", FT_STRING, BASE_NONE, NULL, 0x0,
                "ILNP Source Identifier-Locator Vector", HFILL}
        },
        { &hf_ilnp_dst_ilv,
            { "Destination ILV", "ilnp.dst_ilv", FT_STRING, BASE_NONE, NULL, 0x0,
                "ILNP Destination Identifier-Locator Vector", HFILL}
        },
        { &hf_ilnp_ilv,
            { "Source or Destination ILV", "ilnp.ilv", FT_STRING, BASE_NONE, NULL, 0x0,
                "ILNP Source or Destination Identifier-Locator Vector", HFILL}
        },
        { &hf_ilnp_nid,
            { "Source or Destination NID", "ilnp.nid", FT_STRING, BASE_NONE, NULL, 0x0,
                "ILNP Source or Destination Node Identifier", HFILL}
        },
        { &hf_ilnp_l64,
            { "Source or Destination L64", "ilnp.l64", FT_STRING, BASE_NONE, NULL, 0x0,
                "ILNP Source or Destination Locator", HFILL}
        },
        { &hf_ilnp_stream,
            { "Stream index", "ilnp.stream",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
    };

    static int* ett[] = {
        &ett_ilnp,
    };

    proto_ilnp = proto_register_protocol("Identifier-Locator Network Protocol", "ILNP", "ilnp");
    proto_register_field_array(proto_ilnp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_init_routine(ilnp_init);

    ilnp_handle = register_dissector("ilnp", dissect_ilnp, proto_ilnp);

    ilnp_tap = register_tap("ilnp");

    register_conversation_table(proto_ilnp, true, ilnp_conversation_packet, ilnp_endpoint_packet);
    register_conversation_filter("ilnp", "ILNP", ilnp_filter_valid, ilnp_build_filter, NULL);

    /* XXX - This isn't really a plugin, but the non-plugin version requires GUI changes */
    stats_tree_register_plugin("ilnp", "ilnp_nids", st_str_ilnp_nid, 0, ilnp_nids_stats_tree_packet, ilnp_nids_stats_tree_init, NULL);
    stats_tree_register_plugin("ilnp", "ilnp_l64s", st_str_ilnp_l64, 0, ilnp_l64s_stats_tree_packet, ilnp_l64s_stats_tree_init, NULL);
    stats_tree_register_plugin("ilnp", "ilnp_ilvs", st_str_ilnp_ilv, 0, ilnp_ilvs_stats_tree_packet, ilnp_ilvs_stats_tree_init, NULL);
    stats_tree_register_plugin("ilnp", "ilnp_ptype", st_str_ilnp_ptype, 0, ilnp_ptype_stats_tree_packet, ilnp_ptype_stats_tree_init, NULL);
    stats_tree_register_plugin("ilnp", "ilnp_srcdst_nid", st_str_ilnp_srcdst_nid, 0, ilnp_srcdst_nid_stats_tree_packet, ilnp_srcdst_nid_stats_tree_init, NULL);
    stats_tree_register_plugin("ilnp", "ilnp_srcdst_l64", st_str_ilnp_srcdst_l64, 0, ilnp_srcdst_l64_stats_tree_packet, ilnp_srcdst_l64_stats_tree_init, NULL);
    stats_tree_register_plugin("ilnp", "ilnp_srcdst_ilv", st_str_ilnp_srcdst_ilv, 0, ilnp_srcdst_ilv_stats_tree_packet, ilnp_srcdst_ilv_stats_tree_init, NULL);
}
