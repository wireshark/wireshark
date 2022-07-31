/* packet-udp.c
 * Routines for UDP/UDP-Lite packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Richard Sharpe, 13-Feb-1999, added dispatch table support and
 *                              support for tftp.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"
#include "packet-udp.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/in_cksum.h>
#include <epan/prefs.h>
#include <epan/follow.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/proto_data.h>

#include <wsutil/utf8_entities.h>
#include <wsutil/pint.h>
#include <wsutil/str_util.h>

#include <epan/conversation.h>
#include <epan/conversation_table.h>
#include <epan/conversation_filter.h>
#include <epan/exported_pdu.h>
#include <epan/decode_as.h>

void proto_register_udp(void);
void proto_reg_handoff_udp(void);

static dissector_handle_t udp_handle;
static dissector_handle_t udplite_handle;

static int udp_tap = -1;
static int udp_follow_tap = -1;
static int exported_pdu_tap = -1;

static int proto_udp = -1;
static int proto_udplite = -1;

static int hf_udp_checksum = -1;
static int hf_udp_checksum_calculated = -1;
static int hf_udp_checksum_status = -1;
static int hf_udp_dstport = -1;
static int hf_udp_length = -1;
static int hf_udp_payload = -1;
static int hf_udp_pdu_size = -1;
static int hf_udp_port = -1;
static int hf_udp_proc_dst_cmd = -1;
static int hf_udp_proc_dst_pid = -1;
static int hf_udp_proc_dst_uid = -1;
static int hf_udp_proc_dst_uname = -1;
static int hf_udp_proc_src_cmd = -1;
static int hf_udp_proc_src_pid = -1;
static int hf_udp_proc_src_uid = -1;
static int hf_udp_proc_src_uname = -1;
static int hf_udp_srcport = -1;
static int hf_udp_stream = -1;
static int hf_udp_ts_delta = -1;
static int hf_udp_ts_relative = -1;
static int hf_udplite_checksum_coverage = -1;

static gint ett_udp = -1;
static gint ett_udp_checksum = -1;
static gint ett_udp_process_info = -1;
static gint ett_udp_timestamps = -1;

static expert_field ei_udp_possible_traceroute = EI_INIT;
static expert_field ei_udp_length_bad = EI_INIT;
static expert_field ei_udplite_checksum_coverage_bad = EI_INIT;
static expert_field ei_udp_checksum_zero = EI_INIT;
static expert_field ei_udp_checksum_bad = EI_INIT;
static expert_field ei_udp_length_bad_zero = EI_INIT;

/* Preferences */

/* Place UDP summary in proto tree */
static gboolean udp_summary_in_tree = TRUE;

/* Check UDP checksums */
static gboolean udp_check_checksum = FALSE;

/* Ignore zero-value UDP checksums over IPv6 */
static gboolean udp_ignore_ipv6_zero_checksum = FALSE;

/* Collect IPFIX process flow information */
static gboolean udp_process_info = FALSE;

/* Ignore an invalid checksum coverage field for UDP-Lite */
static gboolean udplite_ignore_checksum_coverage = TRUE;

/* Check UDP-Lite checksums */
static gboolean udplite_check_checksum = FALSE;

static dissector_table_t udp_dissector_table;
static heur_dissector_list_t heur_subdissector_list;
static guint32 udp_stream_count;

/* Determine if there is a sub-dissector and call it.  This has been */
/* separated into a stand alone routine so other protocol dissectors */
/* can call to it, ie. socks */

static gboolean try_heuristic_first = FALSE;

static gboolean udp_calculate_ts = TRUE;
static gboolean udplite_calculate_ts = TRUE;

/* Per-packet-info for UDP */
typedef struct {
    heur_dtbl_entry_t *heur_dtbl_entry;
    nstime_t ts_delta;
    gboolean ts_delta_valid;
} udp_p_info_t;

static void
udp_src_prompt(packet_info *pinfo, gchar *result)
{
    guint32 port = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo,
                                        hf_udp_srcport, pinfo->curr_layer_num));

    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "source (%u%s)", port, UTF8_RIGHTWARDS_ARROW);
}

static gpointer
udp_src_value(packet_info *pinfo)
{
    return p_get_proto_data(pinfo->pool, pinfo, hf_udp_srcport, pinfo->curr_layer_num);
}

static void
udp_dst_prompt(packet_info *pinfo, gchar *result)
{
    guint32 port = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo,
                                        hf_udp_dstport, pinfo->curr_layer_num));

    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "destination (%s%u)", UTF8_RIGHTWARDS_ARROW, port);
}

static gpointer
udp_dst_value(packet_info *pinfo)
{
    return p_get_proto_data(pinfo->pool, pinfo, hf_udp_dstport, pinfo->curr_layer_num);
}

static void
udp_both_prompt(packet_info *pinfo, gchar *result)
{
    guint32 srcport = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo,
                                        hf_udp_srcport, pinfo->curr_layer_num));
    guint32 dstport = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo,
                                        hf_udp_dstport, pinfo->curr_layer_num));
    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Both (%u%s%u)", srcport, UTF8_LEFT_RIGHT_ARROW, dstport);
}

/* Conversation and process code originally copied from packet-tcp.c */
static struct udp_analysis *
init_udp_conversation_data(packet_info *pinfo)
{
    struct udp_analysis *udpd;

    /* Initialize the udp protocol data structure to add to the udp conversation */
    udpd = wmem_new0(wmem_file_scope(), struct udp_analysis);
    /*
    udpd->flow1.username = NULL;
    udpd->flow1.command = NULL;
    udpd->flow2.username = NULL;
    udpd->flow2.command = NULL;
    */

    udpd->stream = udp_stream_count++;
    udpd->ts_first = pinfo->abs_ts;
    udpd->ts_prev = pinfo->abs_ts;

    return udpd;
}

struct udp_analysis *
get_udp_conversation_data(conversation_t *conv, packet_info *pinfo)
{
    int direction;
    struct udp_analysis *udpd = NULL;

    /* Did the caller supply the conversation pointer? */
    if (conv == NULL)
        conv = find_or_create_conversation(pinfo);

    /* Get the data for this conversation */
    udpd = conversation_get_proto_data(conv, proto_udp);

    /* If the conversation was just created or it matched a
     * conversation with template options, udpd will not
     * have been initialized. So, initialize
     * a new udpd structure for the conversation.
     */
    if (!udpd) {
        udpd = init_udp_conversation_data(pinfo);
        conversation_add_proto_data(conv, proto_udp, udpd);
    }

    if (!udpd) {
        return NULL;
    }

    /* check direction and get ua lists */
    direction = cmp_address(&pinfo->src, &pinfo->dst);
    /* if the addresses are equal, match the ports instead */
    if (direction == 0) {
        direction = (pinfo->srcport > pinfo->destport) ? 1 : -1;
    }
    if (direction >= 0) {
        udpd->fwd = &(udpd->flow1);
        udpd->rev = &(udpd->flow2);
    }
    else {
        udpd->fwd = &(udpd->flow2);
        udpd->rev = &(udpd->flow1);
    }

    return udpd;
}

static const char* udp_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
    if (filter == CONV_FT_SRC_PORT)
        return "udp.srcport";

    if (filter == CONV_FT_DST_PORT)
        return "udp.dstport";

    if (filter == CONV_FT_ANY_PORT)
        return "udp.port";

    if(!conv) {
        return CONV_FILTER_INVALID;
    }

    if (filter == CONV_FT_SRC_ADDRESS) {
        if (conv->src_address.type == AT_IPv4)
            return "ip.src";
        if (conv->src_address.type == AT_IPv6)
            return "ipv6.src";
    }

    if (filter == CONV_FT_DST_ADDRESS) {
        if (conv->dst_address.type == AT_IPv4)
            return "ip.dst";
        if (conv->dst_address.type == AT_IPv6)
            return "ipv6.dst";
    }

    if (filter == CONV_FT_ANY_ADDRESS) {
        if (conv->src_address.type == AT_IPv4)
            return "ip.addr";
        if (conv->src_address.type == AT_IPv6)
            return "ipv6.addr";
    }

    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t udp_ct_dissector_info = {&udp_conv_get_filter_type};

static tap_packet_status
udpip_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pct;
    hash->flags = flags;

    const e_udphdr *udphdr=(const e_udphdr *)vip;

    add_conversation_table_data_with_conv_id(hash,
                &udphdr->ip_src, &udphdr->ip_dst, udphdr->uh_sport, udphdr->uh_dport,
                (conv_id_t) udphdr->uh_stream, 1, pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts,
                &udp_ct_dissector_info, ENDPOINT_UDP);

    return TAP_PACKET_REDRAW;
}

static const char* udp_host_get_filter_type(hostlist_talker_t* host, conv_filter_type_e filter)
{

    if (filter == CONV_FT_SRC_PORT)
        return "udp.srcport";

    if (filter == CONV_FT_DST_PORT)
        return "udp.dstport";

    if (filter == CONV_FT_ANY_PORT)
        return "udp.port";

    if(!host) {
        return CONV_FILTER_INVALID;
    }


    if (filter == CONV_FT_SRC_ADDRESS) {
        if (host->myaddress.type == AT_IPv4)
            return "ip.src";
        if (host->myaddress.type == AT_IPv6)
            return "ipv6.src";
    }

    if (filter == CONV_FT_DST_ADDRESS) {
        if (host->myaddress.type == AT_IPv4)
            return "ip.dst";
        if (host->myaddress.type == AT_IPv6)
            return "ipv6.dst";
    }

    if (filter == CONV_FT_ANY_ADDRESS) {
        if (host->myaddress.type == AT_IPv4)
            return "ip.addr";
        if (host->myaddress.type == AT_IPv6)
            return "ipv6.addr";
    }

    return CONV_FILTER_INVALID;
}

static hostlist_dissector_info_t udp_host_dissector_info = {&udp_host_get_filter_type};

static tap_packet_status
udpip_hostlist_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pit;
    hash->flags = flags;

    const e_udphdr *udphdr=(const e_udphdr *)vip;

    /* Take two "add" passes per packet, adding for each direction, ensures that all
    packets are counted properly (even if address is sending to itself)
    XXX - this could probably be done more efficiently inside hostlist_table */
    add_hostlist_table_data(hash, &udphdr->ip_src, udphdr->uh_sport, TRUE, 1, pinfo->fd->pkt_len, &udp_host_dissector_info, ENDPOINT_UDP);
    add_hostlist_table_data(hash, &udphdr->ip_dst, udphdr->uh_dport, FALSE, 1, pinfo->fd->pkt_len, &udp_host_dissector_info, ENDPOINT_UDP);

    return TAP_PACKET_REDRAW;
}

static gboolean
udp_filter_valid(packet_info *pinfo)
{
    return proto_is_frame_protocol(pinfo->layers, "udp");
}

static gchar*
udp_build_filter(packet_info *pinfo)
{
    if( pinfo->net_src.type == AT_IPv4 && pinfo->net_dst.type == AT_IPv4 ) {
        /* UDP over IPv4 */
        return ws_strdup_printf("(ip.addr eq %s and ip.addr eq %s) and (udp.port eq %d and udp.port eq %d)",
                    address_to_str(pinfo->pool, &pinfo->net_src),
                    address_to_str(pinfo->pool, &pinfo->net_dst),
                    pinfo->srcport, pinfo->destport );
    }

    if( pinfo->net_src.type == AT_IPv6 && pinfo->net_dst.type == AT_IPv6 ) {
        /* UDP over IPv6 */
        return ws_strdup_printf("(ipv6.addr eq %s and ipv6.addr eq %s) and (udp.port eq %d and udp.port eq %d)",
                    address_to_str(pinfo->pool, &pinfo->net_src),
                    address_to_str(pinfo->pool, &pinfo->net_dst),
                    pinfo->srcport, pinfo->destport );
    }

    return NULL;
}

static gchar *udp_follow_conv_filter(epan_dissect_t *edt _U_, packet_info *pinfo, guint *stream, guint *sub_stream _U_)
{
    conversation_t *conv;
    struct udp_analysis *udpd;

    /* XXX: Since UDP doesn't use the endpoint API, we can only look
     * up using the current pinfo addresses and ports. We don't want
     * to create a new conversation or new UDP stream.
     * Eventually the endpoint API should support storing multiple
     * endpoints and UDP should be changed to use the endpoint API.
     */
    if (((pinfo->net_src.type == AT_IPv4 && pinfo->net_dst.type == AT_IPv4) ||
        (pinfo->net_src.type == AT_IPv6 && pinfo->net_dst.type == AT_IPv6))
        && (pinfo->ptype == PT_UDP) &&
        (conv=find_conversation(pinfo->num, &pinfo->net_src, &pinfo->net_dst, ENDPOINT_UDP, pinfo->srcport, pinfo->destport, 0)) != NULL)
    {
        /* UDP over IPv4/6 */
        udpd=get_udp_conversation_data(conv, pinfo);
        if (udpd == NULL)
            return NULL;

        *stream = udpd->stream;
        return ws_strdup_printf("udp.stream eq %u", udpd->stream);
    }

    return NULL;
}

static gchar *udp_follow_index_filter(guint stream, guint sub_stream _U_)
{
    return ws_strdup_printf("udp.stream eq %u", stream);
}

static gchar *udp_follow_address_filter(address *src_addr, address *dst_addr, int src_port, int dst_port)
{
    const gchar  *ip_version = src_addr->type == AT_IPv6 ? "v6" : "";
    gchar         src_addr_str[WS_INET6_ADDRSTRLEN];
    gchar         dst_addr_str[WS_INET6_ADDRSTRLEN];

    address_to_str_buf(src_addr, src_addr_str, sizeof(src_addr_str));
    address_to_str_buf(dst_addr, dst_addr_str, sizeof(dst_addr_str));

    return ws_strdup_printf("((ip%s.src eq %s and udp.srcport eq %d) and "
                     "(ip%s.dst eq %s and udp.dstport eq %d))"
                     " or "
                     "((ip%s.src eq %s and udp.srcport eq %d) and "
                     "(ip%s.dst eq %s and udp.dstport eq %d))",
                     ip_version, src_addr_str, src_port,
                     ip_version, dst_addr_str, dst_port,
                     ip_version, dst_addr_str, dst_port,
                     ip_version, src_addr_str, src_port);
}


/* Attach process info to a flow */
/* XXX - We depend on the UDP dissector finding the conversation first */
void
add_udp_process_info(guint32 frame_num, address *local_addr, address *remote_addr,
                        guint16 local_port, guint16 remote_port, guint32 uid, guint32 pid,
                        gchar *username, gchar *command)
{
    conversation_t *conv;
    struct udp_analysis *udpd;
    udp_flow_t *flow = NULL;

    if (!udp_process_info) {
        return;
    }

    conv = find_conversation(frame_num, local_addr, remote_addr, ENDPOINT_UDP, local_port, remote_port, 0);
    if (!conv) {
        return;
    }

    udpd = (struct udp_analysis *)conversation_get_proto_data(conv, proto_udp);
    if (!udpd) {
        return;
    }

    if ((cmp_address(local_addr, conversation_key_addr1(conv->key_ptr)) == 0) && (local_port == conversation_key_port1(conv->key_ptr))) {
        flow = &udpd->flow1;
    }
    else if ((cmp_address(remote_addr, conversation_key_addr1(conv->key_ptr)) == 0) && (remote_port == conversation_key_port1(conv->key_ptr))) {
        flow = &udpd->flow2;
    }
    if (!flow || flow->command) {
        return;
    }

    flow->process_uid = uid;
    flow->process_pid = pid;
    flow->username = wmem_strdup(wmem_file_scope(), username);
    flow->command = wmem_strdup(wmem_file_scope(), command);
}


/* Return the current stream count */
guint32 get_udp_stream_count(void)
{
    return udp_stream_count;
}

static void
handle_export_pdu_dissection_table(packet_info *pinfo, tvbuff_t *tvb, guint32 port)
{
    if (have_tap_listener(exported_pdu_tap)) {
        exp_pdu_data_item_t exp_pdu_data_table_value = {exp_pdu_data_dissector_table_num_value_size, exp_pdu_data_dissector_table_num_value_populate_data, NULL};

        const exp_pdu_data_item_t *udp_exp_pdu_items[] = {
            &exp_pdu_data_src_ip,
            &exp_pdu_data_dst_ip,
            &exp_pdu_data_port_type,
            &exp_pdu_data_src_port,
            &exp_pdu_data_dst_port,
            &exp_pdu_data_orig_frame_num,
            &exp_pdu_data_table_value,
            NULL
        };

        exp_pdu_data_t *exp_pdu_data;

        exp_pdu_data_table_value.data = GUINT_TO_POINTER(port);

        exp_pdu_data = export_pdu_create_tags(pinfo, "udp.port", EXP_PDU_TAG_DISSECTOR_TABLE_NAME, udp_exp_pdu_items);
        exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
        exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
        exp_pdu_data->pdu_tvb = tvb;

        tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
    }
}

static void
handle_export_pdu_heuristic(packet_info *pinfo, tvbuff_t *tvb, heur_dtbl_entry_t *hdtbl_entry)
{
    exp_pdu_data_t *exp_pdu_data = NULL;

    if (have_tap_listener(exported_pdu_tap)) {
        if ((!hdtbl_entry->enabled) ||
                (hdtbl_entry->protocol != NULL && !proto_is_protocol_enabled(hdtbl_entry->protocol))) {
            exp_pdu_data = export_pdu_create_common_tags(pinfo, "data", EXP_PDU_TAG_PROTO_NAME);
        }
        else if (hdtbl_entry->protocol != NULL) {
            exp_pdu_data = export_pdu_create_common_tags(pinfo, hdtbl_entry->short_name, EXP_PDU_TAG_HEUR_PROTO_NAME);
        }

        if (exp_pdu_data != NULL) {
            exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
            exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
            exp_pdu_data->pdu_tvb = tvb;

            tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
        }
    }
}

static void
handle_export_pdu_conversation(packet_info *pinfo, tvbuff_t *tvb, int uh_dport, int uh_sport)
{
    if (have_tap_listener(exported_pdu_tap)) {
        conversation_t *conversation = find_conversation(pinfo->num, &pinfo->dst, &pinfo->src, ENDPOINT_UDP, uh_dport, uh_sport, 0);
        if (conversation != NULL) {
            dissector_handle_t handle = (dissector_handle_t)wmem_tree_lookup32_le(conversation->dissector_tree, pinfo->num);
            if (handle != NULL) {
                exp_pdu_data_t *exp_pdu_data = export_pdu_create_common_tags(pinfo, dissector_handle_get_dissector_name(handle), EXP_PDU_TAG_PROTO_NAME);
                exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
                exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
                exp_pdu_data->pdu_tvb = tvb;

                tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
            }
        }
    }
}

void
decode_udp_ports(tvbuff_t *tvb, int offset, packet_info *pinfo,
             proto_tree *udp_tree, int uh_sport, int uh_dport, int uh_ulen)
{
    tvbuff_t *next_tvb;
    int low_port, high_port;
    gboolean try_low_port, try_high_port;
    gint len, reported_len;
    udp_p_info_t *udp_p_info;
    /* Save curr_layer_num as it might be changed by subdissector */
    guint8 curr_layer_num = pinfo->curr_layer_num;
    heur_dtbl_entry_t *hdtbl_entry;
    exp_pdu_data_t *exp_pdu_data;
    proto_tree* tree = proto_tree_get_root(udp_tree);

    /* populate per packet data variable */
    udp_p_info = (udp_p_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_udp, pinfo->curr_layer_num);

    len = tvb_captured_length_remaining(tvb, offset);
    reported_len = tvb_reported_length_remaining(tvb, offset);
    if (uh_ulen != -1) {
        /* This is the length from the UDP header; the payload should be cut
             off at that length.  (If our caller passed a value here, they
             are assumed to have checked that it's >= 8, and hence >= offset.)

             XXX - what if it's *greater* than the reported length? */
        if ((uh_ulen - offset) < reported_len)
            reported_len = uh_ulen - offset;
        if (len > reported_len)
            len = reported_len;
    }

    proto_tree_add_bytes_format(udp_tree, hf_udp_payload, tvb, offset,
            -1, NULL, "UDP payload (%u byte%s)", len,
            plurality(len, "", "s"));

    next_tvb = tvb_new_subset_length_caplen(tvb, offset, len, reported_len);

    /* If the user has a "Follow UDP Stream" window loading, pass a pointer
     * to the payload tvb through the tap system. */
    if (have_tap_listener(udp_follow_tap))
        tap_queue_packet(udp_follow_tap, pinfo, next_tvb);

    if (PINFO_FD_VISITED(pinfo)) {
        if (udp_p_info && udp_p_info->heur_dtbl_entry != NULL) {
            call_heur_dissector_direct(udp_p_info->heur_dtbl_entry, next_tvb, pinfo, tree, NULL);
            handle_export_pdu_heuristic(pinfo, next_tvb, udp_p_info->heur_dtbl_entry);
            return;
        }
    }

    /* determine if this packet is part of a conversation and call dissector */
    /* for the conversation if available */
    if (try_conversation_dissector(&pinfo->dst, &pinfo->src, ENDPOINT_UDP,
             uh_dport, uh_sport, next_tvb, pinfo, tree, NULL, NO_ADDR_B|NO_PORT_B)) {
        handle_export_pdu_conversation(pinfo, next_tvb, uh_dport, uh_sport);
        return;
    }

    /* XXX - we ignore port numbers of 0, as some dissectors use a port
         number of 0 to disable the port, and as RFC 768 says that the source
         port in UDP datagrams is optional and is 0 if not used. */

    if (uh_sport > uh_dport) {
        low_port  = uh_dport;
        high_port = uh_sport;
    }
    else {
        low_port  = uh_sport;
        high_port = uh_dport;
    }

    try_low_port = FALSE;
    if (low_port != 0) {
        if (dissector_is_uint_changed(udp_dissector_table, low_port)) {
            if (dissector_try_uint(udp_dissector_table, low_port, next_tvb, pinfo, tree)) {
                handle_export_pdu_dissection_table(pinfo, next_tvb, low_port);
                return;
            }
        }
        else {
            /* The default; try it later */
            try_low_port = TRUE;
        }
    }

    try_high_port = FALSE;
    if (high_port != 0) {
        if (dissector_is_uint_changed(udp_dissector_table, high_port)) {
            if (dissector_try_uint(udp_dissector_table, high_port, next_tvb, pinfo, tree)) {
                handle_export_pdu_dissection_table(pinfo, next_tvb, high_port);
                return;
            }
        }
        else {
            /* The default; try it later */
            try_high_port = TRUE;
        }
    }

    if (try_heuristic_first) {
        /* Do lookup with the heuristic subdissector table */
        if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, &hdtbl_entry, NULL)) {
            if (!udp_p_info) {
                udp_p_info = wmem_new0(wmem_file_scope(), udp_p_info_t);
                p_add_proto_data(wmem_file_scope(), pinfo, proto_udp, curr_layer_num, udp_p_info);
            }

            udp_p_info->heur_dtbl_entry = hdtbl_entry;

            handle_export_pdu_heuristic(pinfo, next_tvb, udp_p_info->heur_dtbl_entry);
            return;
        }
    }

    /* Do lookups with the subdissector table.
         We try the port number with the lower value first, followed by the
         port number with the higher value.  This means that, for packets
         where a dissector is registered for *both* port numbers:

                1) we pick the same dissector for traffic going in both directions;

                2) we prefer the port number that's more likely to be the right
                     one (as that prefers well-known ports to reserved ports);

         although there is, of course, no guarantee that any such strategy
         will always pick the right port number.
     */

    if ((try_low_port) && dissector_try_uint(udp_dissector_table, low_port, next_tvb, pinfo, tree)) {
        handle_export_pdu_dissection_table(pinfo, next_tvb, low_port);
        return;
    }
    if ((try_high_port) && dissector_try_uint(udp_dissector_table, high_port, next_tvb, pinfo, tree)) {
        handle_export_pdu_dissection_table(pinfo, next_tvb, high_port);
        return;
    }

    if (!try_heuristic_first) {
        /* Do lookup with the heuristic subdissector table */
        if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, &hdtbl_entry, NULL)) {
            if (!udp_p_info) {
                udp_p_info = wmem_new0(wmem_file_scope(), udp_p_info_t);
                p_add_proto_data(wmem_file_scope(), pinfo, proto_udp, curr_layer_num, udp_p_info);
            }

            udp_p_info->heur_dtbl_entry = hdtbl_entry;

            handle_export_pdu_heuristic(pinfo, next_tvb, udp_p_info->heur_dtbl_entry);
            return;
        }
    }

    call_data_dissector(next_tvb, pinfo, tree);

    if (have_tap_listener(exported_pdu_tap)) {
        exp_pdu_data = export_pdu_create_common_tags(pinfo, "data", EXP_PDU_TAG_PROTO_NAME);
        exp_pdu_data->tvb_captured_length = tvb_captured_length(next_tvb);
        exp_pdu_data->tvb_reported_length = tvb_reported_length(next_tvb);
        exp_pdu_data->pdu_tvb = next_tvb;

        tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
    }
}

int
udp_dissect_pdus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
         guint fixed_len,  gboolean (*heuristic_check)(packet_info *, tvbuff_t *, int, void*),
         guint (*get_pdu_len)(packet_info *, tvbuff_t *, int, void*),
         dissector_t dissect_pdu, void* dissector_data)
{
    volatile int offset = 0;
    int offset_before;
    guint captured_length_remaining;
    volatile guint plen;
    guint length;
    tvbuff_t *next_tvb;
    proto_item *item=NULL;
    const char *saved_proto;
    guint8 curr_layer_num;
    wmem_list_frame_t *frame;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        /*
        * We use "tvb_ensure_captured_length_remaining()" to make
        * sure there actually *is* data remaining.  The protocol
        * we're handling could conceivably consists of a sequence of
        * fixed-length PDUs, and therefore the "get_pdu_len" routine
        * might not actually fetch anything from the tvbuff, and thus
        * might not cause an exception to be thrown if we've run past
        * the end of the tvbuff.
        *
        * This means we're guaranteed that "captured_length_remaining" is positive.
        */
        captured_length_remaining = tvb_ensure_captured_length_remaining(tvb, offset);

        /*
        * If there is a heuristic function, check it
        */
        if ((heuristic_check != NULL) &&
                ((*heuristic_check)(pinfo, tvb, offset, dissector_data) == FALSE)) {
            return offset;
         }

        /*
        * Get the length of the PDU.
        */
        plen = (*get_pdu_len)(pinfo, tvb, offset, dissector_data);
        if (plen == 0) {
            /*
             * Either protocol has variable length (which isn't supposed by UDP)
             * or packet doesn't belong to protocol
             */
            return offset;
         }

        if (plen < fixed_len) {
            /*
            * Either:
            *
            *  1) the length value extracted from the fixed-length portion
            *     doesn't include the fixed-length portion's length, and
            *     was so large that, when the fixed-length portion's
            *     length was added to it, the total length overflowed;
            *
            *  2) the length value extracted from the fixed-length portion
            *     includes the fixed-length portion's length, and the value
            *     was less than the fixed-length portion's length, i.e. it
            *     was bogus.
            *
            * Report this as a bounds error.
            */
            show_reported_bounds_error(tvb, pinfo, tree);
            return offset;
        }

        curr_layer_num = pinfo->curr_layer_num-1;
        frame = wmem_list_frame_prev(wmem_list_tail(pinfo->layers));
        while (frame && (proto_udp != (gint) GPOINTER_TO_UINT(wmem_list_frame_data(frame)))) {
            frame = wmem_list_frame_prev(frame);
            curr_layer_num--;
        }

         /*
            * Display the PDU length as a field
            */
        item = proto_tree_add_uint((proto_tree *)p_get_proto_data(pinfo->pool, pinfo, proto_udp, curr_layer_num),
                                    hf_udp_pdu_size, tvb, offset, plen, plen);
        proto_item_set_generated(item);

        /*
        * Construct a tvbuff containing the amount of the payload we have
        * available.  Make its reported length the amount of data in the PDU.
        */
        length = captured_length_remaining;
        if (length > plen)
            length = plen;
        next_tvb = tvb_new_subset_length_caplen(tvb, offset, length, plen);

        /*
        * Dissect the PDU.
        *
        * If it gets an error that means there's no point in
        * dissecting any more PDUs, rethrow the exception in
        * question.
        *
        * If it gets any other error, report it and continue, as that
        * means that PDU got an error, but that doesn't mean we should
        * stop dissecting PDUs within this frame or chunk of reassembled
        * data.
        */
        saved_proto = pinfo->current_proto;
        TRY {
            (*dissect_pdu)(next_tvb, pinfo, tree, dissector_data);
        }
        CATCH_NONFATAL_ERRORS {
            /*  Restore the private_data structure in case one of the
             *  called dissectors modified it (and, due to the exception,
             *  was unable to restore it).
             */
            show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);

            /*
             * Restore the saved protocol as well; we do this after
             * show_exception(), so that the "Malformed packet" indication
             * shows the protocol for which dissection failed.
             */
            pinfo->current_proto = saved_proto;
        }
        ENDTRY;

        /*
         * Step to the next PDU.
         * Make sure we don't overflow.
         */
        offset_before = offset;
        offset += plen;
        if (offset <= offset_before)
            break;
    }

    return offset;
}

static gboolean
capture_udp(const guchar *pd _U_, int offset _U_, int len _U_, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
    guint16 src_port, dst_port, low_port, high_port;

    if (!BYTES_ARE_IN_FRAME(offset, len, 4))
        return FALSE;

    capture_dissector_increment_count(cpinfo, proto_udp);

    src_port = pntoh16(&pd[offset]);
    dst_port = pntoh16(&pd[offset+2]);

    if (src_port > dst_port) {
        low_port = dst_port;
        high_port = src_port;
    }
    else {
        low_port = src_port;
        high_port = dst_port;
    }

    if (low_port != 0 && try_capture_dissector("udp.port", low_port, pd, offset+20, len, cpinfo, pseudo_header))
        return TRUE;

    if (high_port != 0 && try_capture_dissector("udp.port", high_port, pd, offset+20, len, cpinfo, pseudo_header))
        return TRUE;

    /* We've at least identified one type of packet, so this shouldn't be "other" */
    return TRUE;
}

/* Calculate the timestamps relative to this conversation */
static void
udp_compute_timestamps(packet_info *pinfo, struct udp_analysis *udp_data, int proto)
{
    if (!udp_data)
        return;

    /* get per packet date for UDP/UDP-Lite based on protocol id */
    udp_p_info_t *udp_per_packet_data = (udp_p_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto, pinfo->curr_layer_num);

    if(!udp_per_packet_data) {
        udp_per_packet_data = wmem_new0(wmem_file_scope(), udp_p_info_t);
        p_add_proto_data(wmem_file_scope(), pinfo, proto, pinfo->curr_layer_num, udp_per_packet_data);
    }

    nstime_delta(&udp_per_packet_data->ts_delta, &pinfo->abs_ts, &udp_data->ts_prev);
    udp_per_packet_data->ts_delta_valid = TRUE;

    udp_data->ts_prev = pinfo->abs_ts;
}

/* Add a subtree with the timestamps relative to this conversation */
static void
udp_print_timestamps(packet_info *pinfo, tvbuff_t *tvb, proto_tree *parent_tree, struct udp_analysis *udp_data, int proto)
{
    proto_item  *item;
    proto_tree  *tree;
    nstime_t    ts;

    if (!udp_data)
        return;

    /* get per packet date for UDP/UDP-Lite based on protocol id */
    udp_p_info_t *udp_per_packet_data = (udp_p_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto, pinfo->curr_layer_num);

    tree = proto_tree_add_subtree(parent_tree, tvb, 0, 0, ett_udp_timestamps, &item, "Timestamps");
    proto_item_set_generated(item);

    nstime_delta(&ts, &pinfo->abs_ts, &udp_data->ts_first);
    item = proto_tree_add_time(tree, hf_udp_ts_relative, tvb, 0, 0, &ts);
    proto_item_set_generated(item);

    if (udp_per_packet_data && udp_per_packet_data->ts_delta_valid) {
        item = proto_tree_add_time(tree, hf_udp_ts_delta, tvb, 0, 0,
                    &udp_per_packet_data->ts_delta);
        proto_item_set_generated(item);
    }
}

static void
udp_handle_timestamps(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree, struct udp_analysis *udp_data, guint32 ip_proto)
{
    int proto_id = (ip_proto == IP_PROTO_UDP ? proto_udp : proto_udplite);

    /*
     * Calculate the timestamps relative to this conversation (but only on the
     * first run when frames are accessed sequentially)
     */
    if (!PINFO_FD_VISITED(pinfo))
        udp_compute_timestamps(pinfo, udp_data, proto_id);

    /* handle conversation timestamps */
    udp_print_timestamps(pinfo, tvb, tree, udp_data, proto_id);
}

static void
dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 ip_proto)
{
    proto_tree *udp_tree = NULL;
    proto_item *ti, *item, *hidden_item, *calc_item;
    proto_item *src_port_item, *dst_port_item, *len_cov_item;
    guint       len;
    guint       reported_len;
    vec_t       cksum_vec[4];
    guint32     phdr[2];
    guint16     computed_cksum;
    int         offset = 0;
    e_udphdr   *udph;
    proto_tree *checksum_tree;
    conversation_t *conv = NULL;
    struct udp_analysis *udpd = NULL;
    proto_tree *process_tree;
    gboolean    udp_jumbogram = FALSE;

    udph = wmem_new0(pinfo->pool, e_udphdr);
    udph->uh_sport = tvb_get_ntohs(tvb, offset);
    udph->uh_dport = tvb_get_ntohs(tvb, offset + 2);
    copy_address_shallow(&udph->ip_src, &pinfo->src);
    copy_address_shallow(&udph->ip_dst, &pinfo->dst);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, (ip_proto == IP_PROTO_UDP) ? "UDP" : "UDP-Lite");
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_ports(pinfo->cinfo, COL_INFO, PT_UDP, udph->uh_sport, udph->uh_dport);

    reported_len = tvb_reported_length(tvb);
    len = tvb_captured_length(tvb);

    ti = proto_tree_add_item(tree, (ip_proto == IP_PROTO_UDP) ? proto_udp : proto_udplite, tvb, offset, 8, ENC_NA);
    if (udp_summary_in_tree) {
        proto_item_append_text(ti, ", Src Port: %s, Dst Port: %s",
                     port_with_resolution_to_str(pinfo->pool, PT_UDP, udph->uh_sport),
                     port_with_resolution_to_str(pinfo->pool, PT_UDP, udph->uh_dport));
    }
    udp_tree = proto_item_add_subtree(ti, ett_udp);
    p_add_proto_data(pinfo->pool, pinfo, proto_udp, pinfo->curr_layer_num, udp_tree);

    src_port_item = proto_tree_add_item(udp_tree, hf_udp_srcport, tvb, offset, 2, ENC_BIG_ENDIAN);
    dst_port_item = proto_tree_add_item(udp_tree, hf_udp_dstport, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    p_add_proto_data(pinfo->pool, pinfo, hf_udp_srcport, pinfo->curr_layer_num, GUINT_TO_POINTER(udph->uh_sport));
    p_add_proto_data(pinfo->pool, pinfo, hf_udp_dstport, pinfo->curr_layer_num, GUINT_TO_POINTER(udph->uh_dport));

    hidden_item = proto_tree_add_item(udp_tree, hf_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);
    hidden_item = proto_tree_add_item(udp_tree, hf_udp_port, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);

    /* The beginning port number, 32768 + 666 (33434), is from LBL's traceroute.c source code and this code
     * further assumes that 3 attempts are made per hop */
    if ((udph->uh_sport > (32768 + 666)) && (udph->uh_sport <= (32768 + 666 + 30))) {
        expert_add_info_format(pinfo, src_port_item, &ei_udp_possible_traceroute, "Possible traceroute: hop #%u, attempt #%u",
                     ((udph->uh_sport - 32768 - 666 - 1) / 3) + 1,
                     ((udph->uh_sport - 32768 - 666 - 1) % 3) + 1);
    }
    if ((udph->uh_dport > (32768 + 666)) && (udph->uh_dport <= (32768 + 666 + 30))) {
        expert_add_info_format(pinfo, dst_port_item, &ei_udp_possible_traceroute, "Possible traceroute: hop #%u, attempt #%u",
                         ((udph->uh_dport - 32768 - 666 - 1) / 3) + 1,
                         ((udph->uh_dport - 32768 - 666 - 1) % 3) + 1);
    }

    udph->uh_ulen = udph->uh_sum_cov = tvb_get_ntohs(tvb, offset + 4);
    if (ip_proto == IP_PROTO_UDP) {
        len_cov_item = proto_tree_add_item(udp_tree, hf_udp_length, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
        if (udph->uh_ulen == 0 && pinfo->src.type == AT_IPv6) {
            /* RFC 2675 (section 4) - UDP Jumbograms */
            udph->uh_ulen = udph->uh_sum_cov = reported_len;
            udp_jumbogram = TRUE;
        }
        if (udph->uh_ulen < 8) {
            /* Bogus length - it includes the header, so it must be >= 8. */
            proto_item_append_text(len_cov_item, " (bogus, must be >= 8)");
            expert_add_info_format(pinfo, len_cov_item, &ei_udp_length_bad, "Bad length value %u < 8", udph->uh_ulen);
            col_append_fstr(pinfo->cinfo, COL_INFO, " [BAD UDP LENGTH %u < 8]", udph->uh_ulen);
            return;
        }
        if ((udph->uh_ulen > reported_len) && (!pinfo->fragmented) && (!pinfo->flags.in_error_pkt)) {
            /* Bogus length - it goes past the end of the IP payload */
            proto_item_append_text(len_cov_item, " (bogus, payload length %u)", reported_len);
            expert_add_info_format(pinfo, len_cov_item, &ei_udp_length_bad, "Bad length value %u > IP payload length", udph->uh_ulen);
            col_append_fstr(pinfo->cinfo, COL_INFO, " [BAD UDP LENGTH %u > IP PAYLOAD LENGTH]", udph->uh_ulen);
            /*return;*/
        }
        if (udp_jumbogram && (udph->uh_ulen < 65536)) {
            expert_add_info(pinfo, len_cov_item, &ei_udp_length_bad_zero);
        }
    }
    else {
        len_cov_item = proto_tree_add_item(udp_tree, hf_udplite_checksum_coverage, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
        udph->uh_ulen = reported_len;
        if (udph->uh_sum_cov == 0) {
            udph->uh_sum_cov = reported_len;
        }
        item = proto_tree_add_uint(udp_tree, hf_udp_length, tvb, offset + 4, 0, udph->uh_ulen);
        proto_item_set_generated(item);
        if ((udph->uh_sum_cov < 8) || (udph->uh_sum_cov > udph->uh_ulen)) {
            /* Bogus coverage - it includes the header, so it must be >= 8, and no larger then the IP payload size. */
            proto_item_append_text(len_cov_item, " (bogus, must be >= 8 and <= %u)", udph->uh_ulen);
            expert_add_info_format(pinfo, len_cov_item, &ei_udplite_checksum_coverage_bad, "Bad checksum coverage length value %u < 8 or > %u",
                         udph->uh_sum_cov, udph->uh_ulen);
            col_append_fstr(pinfo->cinfo, COL_INFO, " [BAD LIGHTWEIGHT UDP CHECKSUM COVERAGE LENGTH %u < 8 or > %u]",
                        udph->uh_sum_cov, udph->uh_ulen);
            if (!udplite_ignore_checksum_coverage) {
                return;
            }
        }
    }

    col_append_str_uint(pinfo->cinfo, COL_INFO, "Len", udph->uh_ulen - 8, " "); /* Payload length */
    if (udp_jumbogram)
        col_append_str(pinfo->cinfo, COL_INFO, " [Jumbogram]");

    udph->uh_sum = tvb_get_ntohs(tvb, offset + 6);
    if (udph->uh_sum == 0) {
        /* No checksum supplied in the packet. */

        gboolean ignore_zero_checksum = (ip_proto == IP_PROTO_UDP) &&
            ((pinfo->src.type == AT_IPv4) || ((pinfo->src.type == AT_IPv6) && udp_ignore_ipv6_zero_checksum));
        proto_checksum_enum_e checksum_status;

        item = proto_tree_add_item(udp_tree, hf_udp_checksum, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
        if (ignore_zero_checksum || pinfo->flags.in_error_pkt) {
            proto_item_append_text(item, " [zero-value ignored]");
            checksum_status = PROTO_CHECKSUM_E_NOT_PRESENT;
        }
        else {
            proto_item_append_text(item, " [zero-value illegal]");
            checksum_status = PROTO_CHECKSUM_E_ILLEGAL;
            expert_add_info(pinfo, item, &ei_udp_checksum_zero);
            col_append_str(pinfo->cinfo, COL_INFO, " [ILLEGAL CHECKSUM (0)]");
        }
        checksum_tree = proto_item_add_subtree(item, ett_udp_checksum);
        item = proto_tree_add_uint(checksum_tree, hf_udp_checksum_status, tvb, offset + 6, 2, checksum_status);
        proto_item_set_generated(item);
    }
    else if (!pinfo->fragmented && (len >= reported_len) &&
                         (len >= udph->uh_sum_cov) && (reported_len >= udph->uh_sum_cov) &&
                         (udph->uh_sum_cov >= 8)) {
        /* The packet isn't part of a fragmented datagram and isn't
             truncated, so we can checksum it.
             XXX - make a bigger scatter-gather list once we do fragment
             reassembly? */

        if (((ip_proto == IP_PROTO_UDP) && udp_check_checksum) ||
                ((ip_proto == IP_PROTO_UDPLITE) && udplite_check_checksum)) {
            /* Set up the fields of the pseudo-header. */
            SET_CKSUM_VEC_PTR(cksum_vec[0], (const guint8 *)pinfo->src.data, pinfo->src.len);
            SET_CKSUM_VEC_PTR(cksum_vec[1], (const guint8 *)pinfo->dst.data, pinfo->dst.len);
            switch (pinfo->src.type) {

            case AT_IPv4:
                if (ip_proto == IP_PROTO_UDP)
                    phdr[0] = g_htonl((ip_proto<<16) | udph->uh_ulen);
                else
                    phdr[0] = g_htonl((ip_proto<<16) | reported_len);
                SET_CKSUM_VEC_PTR(cksum_vec[2], (const guint8 *)&phdr, 4);
                break;

            case AT_IPv6:
                if (ip_proto == IP_PROTO_UDP)
                    phdr[0] = g_htonl(udph->uh_ulen);
                else
                    phdr[0] = g_htonl(reported_len);
                phdr[1] = g_htonl(ip_proto);
                SET_CKSUM_VEC_PTR(cksum_vec[2], (const guint8 *)&phdr, 8);
                break;

            default:
                /* UDP runs only atop IPv4 and IPv6.... */
                DISSECTOR_ASSERT_NOT_REACHED();
                break;
            }
            SET_CKSUM_VEC_TVB(cksum_vec[3], tvb, offset, udph->uh_sum_cov);
            computed_cksum = in_cksum(&cksum_vec[0], 4);

            item = proto_tree_add_checksum(udp_tree, tvb, offset + 6, hf_udp_checksum, hf_udp_checksum_status, &ei_udp_checksum_bad,
                                                                            pinfo, computed_cksum, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_IN_CKSUM);
            checksum_tree = proto_item_add_subtree(item, ett_udp_checksum);

            /*
             * in_cksum() should never return 0xFFFF here, because, to quote
             * RFC 1624 section 3 "Discussion":
             *
             *     In one's complement, there are two representations of
             *     zero: the all zero and the all one bit values, often
             *     referred to as +0 and -0.  One's complement addition
             *     of non-zero inputs can produce -0 as a result, but
             *     never +0.  Since there is guaranteed to be at least
             *     one non-zero field in the IP header, and the checksum
             *     field in the protocol header is the complement of the
             *     sum, the checksum field can never contain ~(+0), which
             *     is -0 (0xFFFF).  It can, however, contain ~(-0), which
             *     is +0 (0x0000).
             *
             * RFC 1624 is discussing the checksum of the *IPv4* header,
             * where the "version" field is 4, ensuring that, in a valid
             * IPv4 header, there is at least one non-zero field, but it
             * also applies to a UDP datagram, because the length includes
             * the length of the UDP header, so at least one field in a UDP
             * datagram is non-zero.
             *
             * in_cksum() returns the negation of the one's-complement
             * sum of all the data handed to it, and that data won't be
             * all zero, so the sum won't be 0 (+0), and thus the negation
             * won't be -0, i.e. won't be 0xFFFF.
             */
            if (computed_cksum != 0) {
                 proto_item_append_text(item, " (maybe caused by \"UDP checksum offload\"?)");
                 col_append_str(pinfo->cinfo, COL_INFO, " [UDP CHECKSUM INCORRECT]");
                 calc_item = proto_tree_add_uint(checksum_tree, hf_udp_checksum_calculated,
                         tvb, offset + 6, 2, in_cksum_shouldbe(udph->uh_sum, computed_cksum));
            }
            else {
                 calc_item = proto_tree_add_uint(checksum_tree, hf_udp_checksum_calculated,
                         tvb, offset + 6, 2, udph->uh_sum);
            }
            proto_item_set_generated(calc_item);

        }
        else {
            proto_tree_add_checksum(udp_tree, tvb, offset + 6, hf_udp_checksum, hf_udp_checksum_status, &ei_udp_checksum_bad, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
        }
    }
    else {
        proto_tree_add_checksum(udp_tree, tvb, offset + 6, hf_udp_checksum, hf_udp_checksum_status, &ei_udp_checksum_bad, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
    }

    /* Skip over header */
    offset += 8;

    pinfo->ptype = PT_UDP;
    pinfo->srcport = udph->uh_sport;
    pinfo->destport = udph->uh_dport;

    /* find(or create if needed) the conversation for this udp session */
    conv = find_or_create_conversation(pinfo);
    udpd = get_udp_conversation_data(conv, pinfo);
    if (udpd) {
        item = proto_tree_add_uint(udp_tree, hf_udp_stream, tvb, offset, 0, udpd->stream);
        proto_item_set_generated(item);

        /* Copy the stream index into the header as well to make it available
        * to tap listeners.
        */
        udph->uh_stream = udpd->stream;
    }

    tap_queue_packet(udp_tap, pinfo, udph);

    if (udpd && ((udpd->fwd && udpd->fwd->command) || (udpd->rev && udpd->rev->command))) {
        process_tree = proto_tree_add_subtree(udp_tree, tvb, offset, 0, ett_udp_process_info, &ti, "Process Information");
        proto_item_set_generated(ti);
        if (udpd->fwd && udpd->fwd->command) {
            proto_tree_add_uint(process_tree, hf_udp_proc_dst_uid, tvb, 0, 0, udpd->fwd->process_uid);
            proto_tree_add_uint(process_tree, hf_udp_proc_dst_pid, tvb, 0, 0, udpd->fwd->process_pid);
            proto_tree_add_string(process_tree, hf_udp_proc_dst_uname, tvb, 0, 0, udpd->fwd->username);
            proto_tree_add_string(process_tree, hf_udp_proc_dst_cmd, tvb, 0, 0, udpd->fwd->command);
        }
        if (udpd->rev->command) {
            proto_tree_add_uint(process_tree, hf_udp_proc_src_uid, tvb, 0, 0, udpd->rev->process_uid);
            proto_tree_add_uint(process_tree, hf_udp_proc_src_pid, tvb, 0, 0, udpd->rev->process_pid);
            proto_tree_add_string(process_tree, hf_udp_proc_src_uname, tvb, 0, 0, udpd->rev->username);
            proto_tree_add_string(process_tree, hf_udp_proc_src_cmd, tvb, 0, 0, udpd->rev->command);
        }
    }

    if (udph->uh_ulen == 8) {
        /* Empty UDP payload, nothing left to do. */
        return;
    }

    /* Do we need to calculate timestamps relative to the udp-stream? */
    /* Different boolean preferences have to be checked. */
    /* If the protocol is UDP then the UDP preference */
    if (!pinfo->flags.in_error_pkt &&
            ((ip_proto == IP_PROTO_UDP && udp_calculate_ts)
             /* Otherwise the UDP-Lite preference */
             || (ip_proto == IP_PROTO_UDPLITE && udplite_calculate_ts))) {
        udp_handle_timestamps(pinfo, tvb, udp_tree, udpd, ip_proto);
    }

    /*
     * Call sub-dissectors.
     *
     * XXX - should we do this if this is included in an error packet?
     * It might be nice to see the details of the packet that caused the
     * ICMP error, but it might not be nice to have the dissector update
     * state based on it.
     * Also, we probably don't want to run UDP taps on those packets.
     *
     * We definitely don't want to do it for an error packet if there's
     * nothing left in the packet.
     */
    if (!pinfo->flags.in_error_pkt || (tvb_captured_length_remaining(tvb, offset) > 0))
        decode_udp_ports(tvb, offset, pinfo, udp_tree, udph->uh_sport, udph->uh_dport, udph->uh_ulen);
}

static int
dissect_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect(tvb, pinfo, tree, IP_PROTO_UDP);
    return tvb_captured_length(tvb);
}

static int
dissect_udplite(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect(tvb, pinfo, tree, IP_PROTO_UDPLITE);
    return tvb_captured_length(tvb);
}

static void
udp_init(void)
{
    udp_stream_count = 0;
}

void
proto_register_udp(void)
{
    static hf_register_info hf_udp[] = {
        { &hf_udp_srcport,
            { "Source Port", "udp.srcport",
              FT_UINT16, BASE_PT_UDP, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_udp_dstport,
            { "Destination Port", "udp.dstport",
              FT_UINT16, BASE_PT_UDP, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_udp_port,
            { "Source or Destination Port", "udp.port",
              FT_UINT16, BASE_PT_UDP, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_udp_stream,
            { "Stream index", "udp.stream",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_udp_length,
            { "Length", "udp.length",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              "Length in octets including this header and the data", HFILL }
        },
        { &hf_udp_checksum,
            { "Checksum", "udp.checksum",
              FT_UINT16, BASE_HEX, NULL, 0x0,
              "Details at: https://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html", HFILL }
        },
        { &hf_udp_checksum_calculated,
            { "Calculated Checksum", "udp.checksum_calculated",
              FT_UINT16, BASE_HEX, NULL, 0x0,
              "The expected UDP checksum field as calculated from the UDP packet", HFILL }
        },
        { &hf_udp_checksum_status,
            { "Checksum Status", "udp.checksum.status",
              FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_udp_proc_src_uid,
            { "Source process user ID", "udp.proc.srcuid",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_udp_proc_src_pid,
            { "Source process ID", "udp.proc.srcpid",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_udp_proc_src_uname,
            { "Source process user name", "udp.proc.srcuname",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_udp_proc_src_cmd,
            { "Source process name", "udp.proc.srccmd",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "Source process command name", HFILL }
        },
        { &hf_udp_proc_dst_uid,
            { "Destination process user ID", "udp.proc.dstuid",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_udp_proc_dst_pid,
            { "Destination process ID", "udp.proc.dstpid",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_udp_proc_dst_uname,
            { "Destination process user name", "udp.proc.dstuname",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_udp_proc_dst_cmd,
            { "Destination process name", "udp.proc.dstcmd",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "Destination process command name", HFILL }
        },
        { &hf_udp_pdu_size,
            { "PDU Size", "udp.pdu.size",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              "The size of this PDU", HFILL }
        },
        { &hf_udp_ts_relative,
            { "Time since first frame", "udp.time_relative",
              FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
              "Time relative to first frame in this UDP stream", HFILL }
        },
        { &hf_udp_ts_delta,
            { "Time since previous frame", "udp.time_delta",
              FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
              "Time delta from previous frame in this UDP stream", HFILL }
        },
        { &hf_udp_payload,
            { "Payload", "udp.payload",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
    };

    static hf_register_info hf_udplite[] = {
        { &hf_udplite_checksum_coverage,
            { "Checksum coverage", "udp.checksum_coverage",
              FT_UINT16, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_udp,
        &ett_udp_checksum,
        &ett_udp_process_info,
        &ett_udp_timestamps
    };

    static ei_register_info ei[] = {
        { &ei_udp_possible_traceroute, { "udp.possible_traceroute", PI_SEQUENCE, PI_CHAT, "Possible traceroute", EXPFILL }},
        { &ei_udp_length_bad, { "udp.length.bad", PI_MALFORMED, PI_ERROR, "Bad length value", EXPFILL }},
        { &ei_udplite_checksum_coverage_bad, { "udplite.checksum_coverage.bad", PI_MALFORMED, PI_ERROR, "Bad checksum coverage length value", EXPFILL }},
        { &ei_udp_checksum_zero, { "udp.checksum.zero", PI_CHECKSUM, PI_ERROR, "Illegal checksum value (0)", EXPFILL }},
        { &ei_udp_checksum_bad, { "udp.checksum.bad", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
        { &ei_udp_length_bad_zero, { "udp.length.bad_zero", PI_PROTOCOL, PI_WARN, "Length is zero but payload < 65536", EXPFILL }},
    };

    static build_valid_func udp_da_src_values[1] = {udp_src_value};
    static build_valid_func udp_da_dst_values[1] = {udp_dst_value};
    static build_valid_func udp_da_both_values[2] = {udp_src_value, udp_dst_value};
    static decode_as_value_t udp_da_values[3] = {{udp_src_prompt, 1, udp_da_src_values}, {udp_dst_prompt, 1, udp_da_dst_values}, {udp_both_prompt, 2, udp_da_both_values}};
    static decode_as_t udp_da = {"udp", "udp.port", 3, 2, udp_da_values, "UDP", "port(s) as",
                     decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    module_t *udp_module;
    module_t *udplite_module;
    expert_module_t* expert_udp;

    proto_udp = proto_register_protocol("User Datagram Protocol", "UDP", "udp");
    proto_register_field_array(proto_udp, hf_udp, array_length(hf_udp));
    udp_handle = register_dissector("udp", dissect_udp, proto_udp);
    expert_udp = expert_register_protocol(proto_udp);

    proto_udplite = proto_register_protocol("Lightweight User Datagram Protocol", "UDP-Lite", "udplite");
    proto_register_field_array(proto_udplite, hf_udplite, array_length(hf_udplite));
    udplite_handle = create_dissector_handle(dissect_udplite, proto_udplite);

    proto_register_subtree_array(ett, array_length(ett));
    expert_register_field_array(expert_udp, ei, array_length(ei));

    /* subdissector code */
    udp_dissector_table = register_dissector_table("udp.port", "UDP port", proto_udp, FT_UINT16, BASE_DEC);
    heur_subdissector_list = register_heur_dissector_list("udp", proto_udp);

    register_capture_dissector_table("udp.port", "UDP");

    /* Register configuration preferences */
    udp_module = prefs_register_protocol(proto_udp, NULL);
    prefs_register_bool_preference(udp_module, "summary_in_tree",
                         "Show UDP summary in protocol tree",
                         "Whether the UDP summary line should be shown in the protocol tree",
                         &udp_summary_in_tree);
    prefs_register_bool_preference(udp_module, "try_heuristic_first",
                         "Try heuristic sub-dissectors first",
                         "Try to decode a packet using an heuristic sub-dissector"
                         " before using a sub-dissector registered to a specific port",
                         &try_heuristic_first);
    prefs_register_bool_preference(udp_module, "check_checksum",
                         "Validate the UDP checksum if possible",
                         "Whether to validate the UDP checksum",
                         &udp_check_checksum);
    prefs_register_bool_preference(udp_module, "ignore_ipv6_zero_checksum",
                         "Ignore zero-value UDP checksums over IPv6",
                         "Whether to ignore zero-value UDP checksums over IPv6",
                         &udp_ignore_ipv6_zero_checksum);
    prefs_register_bool_preference(udp_module, "process_info",
                         "Collect process flow information",
                         "Collect process flow information from IPFIX",
                         &udp_process_info);
    prefs_register_bool_preference(udp_module, "calculate_timestamps",
                         "Calculate conversation timestamps",
                         "Calculate timestamps relative to the first frame and the previous frame in the udp conversation",
                         &udp_calculate_ts);

    udplite_module = prefs_register_protocol(proto_udplite, NULL);
    prefs_register_bool_preference(udplite_module, "ignore_checksum_coverage",
                         "Ignore UDP-Lite checksum coverage",
                         "Ignore an invalid checksum coverage field and continue dissection",
                         &udplite_ignore_checksum_coverage);
    prefs_register_bool_preference(udplite_module, "check_checksum",
                         "Validate the UDP-Lite checksum if possible",
                         "Whether to validate the UDP-Lite checksum",
                         &udplite_check_checksum);
    prefs_register_bool_preference(udplite_module, "calculate_timestamps",
                         "Calculate conversation timestamps",
                         "Calculate timestamps relative to the first frame and the previous frame in the udp-lite conversation",
                         &udplite_calculate_ts);

    register_decode_as(&udp_da);
    register_conversation_table(proto_udp, FALSE, udpip_conversation_packet, udpip_hostlist_packet);
    register_conversation_filter("udp", "UDP", udp_filter_valid, udp_build_filter);
    register_follow_stream(proto_udp, "udp_follow", udp_follow_conv_filter, udp_follow_index_filter, udp_follow_address_filter,
                        udp_port_to_display, follow_tvb_tap_listener);

    register_init_routine(udp_init);
}

void
proto_reg_handoff_udp(void)
{
    capture_dissector_handle_t udp_cap_handle;

    dissector_add_uint("ip.proto", IP_PROTO_UDP, udp_handle);
    dissector_add_uint("ip.proto", IP_PROTO_UDPLITE, udplite_handle);

    udp_cap_handle = create_capture_dissector_handle(capture_udp, proto_udp);
    capture_dissector_add_uint("ip.proto", IP_PROTO_UDP, udp_cap_handle);
    udp_cap_handle = create_capture_dissector_handle(capture_udp, proto_udplite);
    capture_dissector_add_uint("ip.proto", IP_PROTO_UDPLITE, udp_cap_handle);

    udp_tap = register_tap("udp");
    udp_follow_tap = register_tap("udp_follow");
    exported_pdu_tap = find_tap_id(EXPORT_PDU_TAP_NAME_LAYER_4);
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
