/* packet-ipv6.c
 * Routines for IPv6 packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SHIM6 support added by Matthijs Mekking <matthijs@NLnetLabs.nl>
 *
 * MobileIPv6 support added by Tomislav Borosa <tomislav.borosa@siemens.hr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <math.h>
#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/expert.h>
#include <epan/ip_opts.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/conversation_table.h>
#include <epan/dissector_filters.h>
#include <epan/reassemble.h>
#include <epan/ipproto.h>
#include <epan/etypes.h>
#include <epan/ppptypes.h>
#include <epan/aftypes.h>
#include <epan/nlpid.h>
#include <epan/arcnet_pids.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>
#include <epan/to_str.h>

#include <wiretap/erf.h>
#include <wsutil/str_util.h>
#include "packet-ipv6.h"
#include "packet-ip.h"
#include "packet-juniper.h"
#include "packet-sflow.h"
#include "packet-vxlan.h"

#ifdef HAVE_GEOIP_V6
#include <GeoIP.h>
#include <epan/geoip_db.h>
#endif /* HAVE_GEOIP_V6 */

void proto_register_ipv6(void);
void proto_reg_handoff_ipv6(void);

/* Option types and related macros */
#define IP6OPT_PAD1                     0x00    /* 00 0 00000 =   0 */
#define IP6OPT_PADN                     0x01    /* 00 0 00001 =   1 */
#define IP6OPT_TEL                      0x04    /* 00 0 00100 =   4 */
#define IP6OPT_RTALERT                  0x05    /* 00 0 00101 =   5 */
#define IP6OPT_CALIPSO                  0x07    /* 00 0 00111 =   7 */
#define IP6OPT_SMF_DPD                  0x08    /* 00 0 01000 =   8 */
#define IP6OPT_EXP_1E                   0x1E    /* 00 0 11110 =  30 */
#define IP6OPT_QUICKSTART               0x26    /* 00 1 00110 =  38 */
#define IP6OPT_EXP_3E                   0x3E    /* 00 1 11110 =  62 */
#define IP6OPT_EXP_5E                   0x5E    /* 01 0 11110 =  94 */
#define IP6OPT_RPL                      0x63    /* 01 1 00011 =  99 */
#define IP6OPT_MPL                      0x6D    /* 01 1 01101 = 109 */
#define IP6OPT_EXP_7E                   0x7E    /* 01 1 11110 = 126 */
#define IP6OPT_ENDI                     0x8A    /* 10 0 01010 = 138 */ /* DEPRECATED */
#define IP6OPT_ILNP_NONCE               0x8B    /* 10 0 01011 = 139 */
#define IP6OPT_LIO                      0x8C    /* 10 0 01100 = 140 */
#define IP6OPT_EXP_9E                   0x9E    /* 10 0 11110 = 158 */
#define IP6OPT_EXP_BE                   0xBE    /* 10 1 11110 = 190 */
#define IP6OPT_JUMBO                    0xC2    /* 11 0 00010 = 194 */
#define IP6OPT_HOME_ADDRESS             0xC9    /* 11 0 01001 = 201 */
#define IP6OPT_EXP_DE                   0xDE    /* 11 0 11110 = 222 */
#define IP6OPT_IP_DFF                   0xEE    /* 11 1 01110 = 238 */
#define IP6OPT_EXP_FE                   0xFE    /* 11 1 11110 = 254 */

#define IP6OPT_RTALERT_MLD              0       /* Datagram contains MLD msg */
#define IP6OPT_RTALERT_RSVP             1       /* Datagram contains RSVP msg */
#define IP6OPT_RTALERT_ACTNET           2       /* Datagram contains ACTNET msg */

/* RPL Routing header */
#define IP6RRPL_BITMASK_CMPRI     0xF0000000
#define IP6RRPL_BITMASK_CMPRE     0x0F000000
#define IP6RRPL_BITMASK_PAD       0x00F00000
#define IP6RRPL_BITMASK_RESERVED  0x000FFFFF

/* Protocol specific data indices */
#define IPV6_PROTO_NXT_HDR          0
#define IPV6_PROTO_VALUE            1
#define IPV6_PROTO_PINFO            2

static int ipv6_tap = -1;

static int proto_ipv6                           = -1;
static int proto_ipv6_hopopts                   = -1;
static int proto_ipv6_routing                   = -1;
static int proto_ipv6_fraghdr                   = -1;
static int proto_ipv6_dstopts                   = -1;

static int hf_ipv6_version                      = -1;
static int hf_ip_version                        = -1;
static int hf_ipv6_tclass                       = -1;
static int hf_ipv6_tclass_dscp                  = -1;
static int hf_ipv6_tclass_ecn                   = -1;
static int hf_ipv6_flow                         = -1;
static int hf_ipv6_plen                         = -1;
static int hf_ipv6_nxt                          = -1;
static int hf_ipv6_hlim                         = -1;
static int hf_ipv6_src                          = -1;
static int hf_ipv6_src_host                     = -1;
static int hf_ipv6_src_sa_mac                   = -1;
static int hf_ipv6_src_isatap_ipv4              = -1;
static int hf_ipv6_src_6to4_gateway_ipv4        = -1;
static int hf_ipv6_src_6to4_sla_id              = -1;
static int hf_ipv6_src_teredo_server_ipv4       = -1;
static int hf_ipv6_src_teredo_port              = -1;
static int hf_ipv6_src_teredo_client_ipv4       = -1;
static int hf_ipv6_dst                          = -1;
static int hf_ipv6_dst_host                     = -1;
static int hf_ipv6_dst_sa_mac                   = -1;
static int hf_ipv6_dst_isatap_ipv4              = -1;
static int hf_ipv6_dst_6to4_gateway_ipv4        = -1;
static int hf_ipv6_dst_6to4_sla_id              = -1;
static int hf_ipv6_dst_teredo_server_ipv4       = -1;
static int hf_ipv6_dst_teredo_port              = -1;
static int hf_ipv6_dst_teredo_client_ipv4       = -1;
static int hf_ipv6_addr                         = -1;
static int hf_ipv6_host                         = -1;
static int hf_ipv6_sa_mac                       = -1;
static int hf_ipv6_isatap_ipv4                  = -1;
static int hf_ipv6_6to4_gateway_ipv4            = -1;
static int hf_ipv6_6to4_sla_id                  = -1;
static int hf_ipv6_teredo_server_ipv4           = -1;
static int hf_ipv6_teredo_port                  = -1;
static int hf_ipv6_teredo_client_ipv4           = -1;
static int hf_ipv6_opt                          = -1;
static int hf_ipv6_opt_type                     = -1;
static int hf_ipv6_opt_type_action              = -1;
static int hf_ipv6_opt_type_change              = -1;
static int hf_ipv6_opt_type_rest                = -1;
static int hf_ipv6_opt_length                   = -1;
static int hf_ipv6_opt_pad1                     = -1;
static int hf_ipv6_opt_padn                     = -1;
static int hf_ipv6_opt_tel                      = -1;
static int hf_ipv6_opt_rtalert                  = -1;
static int hf_ipv6_opt_jumbo                    = -1;
static int hf_ipv6_opt_calipso_doi              = -1;
static int hf_ipv6_opt_calipso_cmpt_length      = -1;
static int hf_ipv6_opt_calipso_sens_level       = -1;
static int hf_ipv6_opt_calipso_checksum         = -1;
static int hf_ipv6_opt_calipso_cmpt_bitmap      = -1;
static int hf_ipv6_opt_qs_func                  = -1;
static int hf_ipv6_opt_qs_rate                  = -1;
static int hf_ipv6_opt_qs_ttl                   = -1;
static int hf_ipv6_opt_qs_ttl_diff              = -1;
static int hf_ipv6_opt_qs_unused                = -1;
static int hf_ipv6_opt_qs_nonce                 = -1;
static int hf_ipv6_opt_qs_reserved              = -1;
static int hf_ipv6_opt_mipv6_home_address       = -1;
static int hf_ipv6_opt_rpl_flag                 = -1;
static int hf_ipv6_opt_rpl_flag_o               = -1;
static int hf_ipv6_opt_rpl_flag_r               = -1;
static int hf_ipv6_opt_rpl_flag_f               = -1;
static int hf_ipv6_opt_rpl_flag_rsv             = -1;
static int hf_ipv6_opt_rpl_instance_id          = -1;
static int hf_ipv6_opt_rpl_senderrank           = -1;
static int hf_ipv6_opt_ilnp_nonce               = -1;
static int hf_ipv6_opt_lio_len                  = -1;
static int hf_ipv6_opt_lio_id                   = -1;
static int hf_ipv6_opt_mpl_flag                 = -1;
static int hf_ipv6_opt_mpl_flag_s               = -1;
static int hf_ipv6_opt_mpl_flag_m               = -1;
static int hf_ipv6_opt_mpl_flag_v               = -1;
static int hf_ipv6_opt_mpl_flag_rsv             = -1;
static int hf_ipv6_opt_mpl_sequence             = -1;
static int hf_ipv6_opt_mpl_seed_id              = -1;
static int hf_ipv6_opt_dff_flags                = -1;
static int hf_ipv6_opt_dff_flag_ver             = -1;
static int hf_ipv6_opt_dff_flag_dup             = -1;
static int hf_ipv6_opt_dff_flag_ret             = -1;
static int hf_ipv6_opt_dff_flag_rsv             = -1;
static int hf_ipv6_opt_dff_seqnum               = -1;
static int hf_ipv6_opt_experimental             = -1;
static int hf_ipv6_opt_unknown_data             = -1;
static int hf_ipv6_opt_unknown                  = -1;
static int hf_ipv6_dstopts_nxt                  = -1;
static int hf_ipv6_dstopts_len                  = -1;
static int hf_ipv6_dstopts_len_oct              = -1;
static int hf_ipv6_hopopts_nxt                  = -1;
static int hf_ipv6_hopopts_len                  = -1;
static int hf_ipv6_hopopts_len_oct              = -1;
static int hf_ipv6_routing_nxt                  = -1;
static int hf_ipv6_routing_len                  = -1;
static int hf_ipv6_routing_len_oct              = -1;
static int hf_ipv6_routing_type                 = -1;
static int hf_ipv6_routing_segleft              = -1;
static int hf_ipv6_fraghdr_nxt                  = -1;
static int hf_ipv6_fraghdr_reserved_octet       = -1;
static int hf_ipv6_fraghdr_offset               = -1;
static int hf_ipv6_fraghdr_reserved_bits        = -1;
static int hf_ipv6_fraghdr_more                 = -1;
static int hf_ipv6_fraghdr_ident                = -1;
static int hf_ipv6_fragment                     = -1;
static int hf_ipv6_fragment_overlap             = -1;
static int hf_ipv6_fragment_overlap_conflict    = -1;
static int hf_ipv6_fragment_multiple_tails      = -1;
static int hf_ipv6_fragment_too_long_fragment   = -1;
static int hf_ipv6_fragment_error               = -1;
static int hf_ipv6_fragment_count               = -1;
static int hf_ipv6_fragments                    = -1;
static int hf_ipv6_reassembled_in               = -1;
static int hf_ipv6_reassembled_length           = -1;
static int hf_ipv6_reassembled_data             = -1;

static int hf_ipv6_routing_src_reserved         = -1;
static int hf_ipv6_routing_src_addr             = -1;

static int hf_ipv6_routing_mipv6_reserved       = -1;
static int hf_ipv6_routing_mipv6_home_address   = -1;

static int hf_ipv6_routing_rpl_cmprI            = -1;
static int hf_ipv6_routing_rpl_cmprE            = -1;
static int hf_ipv6_routing_rpl_pad              = -1;
static int hf_ipv6_routing_rpl_reserved         = -1;
static int hf_ipv6_routing_rpl_addr_count       = -1;
static int hf_ipv6_routing_rpl_addr             = -1;
static int hf_ipv6_routing_rpl_fulladdr         = -1;

static int hf_ipv6_routing_srh_first_seg        = -1;
static int hf_ipv6_routing_srh_flags            = -1;
static int hf_ipv6_routing_srh_flag_c           = -1;
static int hf_ipv6_routing_srh_flag_p           = -1;
static int hf_ipv6_routing_srh_flag_o           = -1;
static int hf_ipv6_routing_srh_flag_a           = -1;
static int hf_ipv6_routing_srh_flag_h           = -1;
static int hf_ipv6_routing_srh_flag_unused      = -1;
static int hf_ipv6_routing_srh_reserved         = -1;
static int hf_ipv6_routing_srh_addr             = -1;

#ifdef HAVE_GEOIP_V6
static int hf_geoip_country             = -1;
static int hf_geoip_city                = -1;
static int hf_geoip_org                 = -1;
static int hf_geoip_isp                 = -1;
static int hf_geoip_asnum               = -1;
static int hf_geoip_lat                 = -1;
static int hf_geoip_lon                 = -1;
static int hf_geoip_src_country         = -1;
static int hf_geoip_src_city            = -1;
static int hf_geoip_src_org             = -1;
static int hf_geoip_src_isp             = -1;
static int hf_geoip_src_asnum           = -1;
static int hf_geoip_src_lat             = -1;
static int hf_geoip_src_lon             = -1;
static int hf_geoip_dst_country         = -1;
static int hf_geoip_dst_city            = -1;
static int hf_geoip_dst_org             = -1;
static int hf_geoip_dst_isp             = -1;
static int hf_geoip_dst_asnum           = -1;
static int hf_geoip_dst_lat             = -1;
static int hf_geoip_dst_lon             = -1;
#endif /* HAVE_GEOIP_V6 */

static gint ett_ipv6_proto              = -1;
static gint ett_ipv6_traffic_class      = -1;
static gint ett_ipv6_opt                = -1;
static gint ett_ipv6_opt_type           = -1;
static gint ett_ipv6_opt_rpl            = -1;
static gint ett_ipv6_opt_mpl            = -1;
static gint ett_ipv6_opt_dff_flags      = -1;
static gint ett_ipv6_hopopts_proto      = -1;
static gint ett_ipv6_fraghdr_proto      = -1;
static gint ett_ipv6_routing_proto      = -1;
static gint ett_ipv6_routing_srh_flags  = -1;
static gint ett_ipv6_routing_srh_vect   = -1;
static gint ett_ipv6_fragments          = -1;
static gint ett_ipv6_fragment           = -1;
static gint ett_ipv6_dstopts_proto      = -1;

#ifdef HAVE_GEOIP_V6
static gint ett_geoip_info              = -1;
#endif /* HAVE_GEOIP_V6 */

static expert_field ei_ipv6_routing_invalid_length = EI_INIT;
static expert_field ei_ipv6_routing_invalid_segleft = EI_INIT;
static expert_field ei_ipv6_routing_not_implemented = EI_INIT;
static expert_field ei_ipv6_dst_addr_not_multicast = EI_INIT;
static expert_field ei_ipv6_src_route_list_mult_inst_same_addr = EI_INIT;
static expert_field ei_ipv6_src_route_list_src_addr = EI_INIT;
static expert_field ei_ipv6_src_route_list_dst_addr = EI_INIT;
static expert_field ei_ipv6_src_route_list_multicast_addr = EI_INIT;
static expert_field ei_ipv6_routing_rpl_cmpri_cmpre_pad = EI_INIT;
static expert_field ei_ipv6_routing_rpl_addr_count_ge0 = EI_INIT;
static expert_field ei_ipv6_routing_rpl_reserved = EI_INIT;
static expert_field ei_ipv6_opt_jumbo_missing = EI_INIT;
static expert_field ei_ipv6_opt_jumbo_prohibited = EI_INIT;
static expert_field ei_ipv6_opt_jumbo_truncated = EI_INIT;
static expert_field ei_ipv6_opt_jumbo_fragment = EI_INIT;
static expert_field ei_ipv6_opt_jumbo_not_hopbyhop = EI_INIT;
static expert_field ei_ipv6_opt_invalid_len = EI_INIT;
static expert_field ei_ipv6_opt_unknown_data = EI_INIT;
static expert_field ei_ipv6_hopopts_not_first = EI_INIT;
static expert_field ei_ipv6_plen_exceeds_framing = EI_INIT;
static expert_field ei_ipv6_bogus_ipv6_version = EI_INIT;
static expert_field ei_ipv6_invalid_header = EI_INIT;

#define IPv6_HDR_VERS(ipv6)     (((*(guint8 *)(ipv6)) >> 4) & 0x0f)
#define IPv6_HDR_TCLS(ipv6)     _ipv6_hdr_tcls(ipv6)

#define TVB_IPv6_HDR_VERS(tvb, offset)  tvb_get_bits8(tvb, (offset) * 8, 4)
#define TVB_IPv6_HDR_TCLS(tvb, offset)  tvb_get_bits8(tvb, (offset) * 8 + 4, 8)

extern const struct e_in6_addr *tvb_get_ptr_ipv6(tvbuff_t tvb, int offset);
#define tvb_get_ptr_ipv6(tvb, offset) \
    ((const struct e_in6_addr *)tvb_get_ptr(tvb, offset, IPv6_ADDR_SIZE))

static inline guint8 _ipv6_hdr_tcls(const struct ws_ip6_hdr *hdr)
{
    guint8 hi, low;
    const guint8 *p = (const guint8 *)hdr;

    hi = p[0] << 4;
    low = p[1] >> 4;
    return (hi & 0xf0) | (low & 0x0f);
}

ipv6_pinfo_t *p_get_ipv6_pinfo(packet_info *pinfo)
{
    return (ipv6_pinfo_t *)p_get_proto_data(pinfo->pool, pinfo, proto_ipv6, IPV6_PROTO_PINFO);
}

static void ipv6_prompt(packet_info *pinfo, gchar* result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "IP protocol %u as",
        GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_ipv6, (pinfo->curr_layer_num<<8) | IPV6_PROTO_VALUE)));
}

static gpointer ipv6_value(packet_info *pinfo)
{
    return p_get_proto_data(pinfo->pool, pinfo, proto_ipv6, (pinfo->curr_layer_num<<8) | IPV6_PROTO_VALUE);
}

static void ipv6_next_header_prompt(packet_info *pinfo, gchar* result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "IP Next Header %u as",
        GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_ipv6, (pinfo->curr_layer_num<<8) | IPV6_PROTO_NXT_HDR)));
}

static gpointer ipv6_next_header_value(packet_info *pinfo)
{
    return p_get_proto_data(pinfo->pool, pinfo, proto_ipv6, (pinfo->curr_layer_num<<8) | IPV6_PROTO_NXT_HDR);
}

static const char* ipv6_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
    if ((filter == CONV_FT_SRC_ADDRESS) && (conv->src_address.type == AT_IPv6))
        return "ipv6.src";

    if ((filter == CONV_FT_DST_ADDRESS) && (conv->dst_address.type == AT_IPv6))
        return "ipv6.dst";

    if ((filter == CONV_FT_ANY_ADDRESS) && (conv->src_address.type == AT_IPv6))
        return "ipv6.addr";

    return CONV_FILTER_INVALID;
}

static ct_dissector_info_t ipv6_ct_dissector_info = {&ipv6_conv_get_filter_type};

static int
ipv6_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
    conv_hash_t *hash = (conv_hash_t*) pct;
    const struct ws_ip6_hdr *ip6h = (const struct ws_ip6_hdr *)vip;
    address src;
    address dst;

    /* Addresses aren't implemented as 'address' type in struct ws_ip6_hdr */
    src.type = dst.type = AT_IPv6;
    src.len  = dst.len = sizeof(struct e_in6_addr);
    src.data = &ip6h->ip6_src;
    dst.data = &ip6h->ip6_dst;

    add_conversation_table_data(hash, &src, &dst, 0, 0, 1, pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts, &ipv6_ct_dissector_info, PT_NONE);

    return 1;
}

static const char* ipv6_host_get_filter_type(hostlist_talker_t* host, conv_filter_type_e filter)
{
    if ((filter == CONV_FT_ANY_ADDRESS) && (host->myaddress.type == AT_IPv6))
        return "ipv6.addr";

    return CONV_FILTER_INVALID;
}

static hostlist_dissector_info_t ipv6_host_dissector_info = {&ipv6_host_get_filter_type};

static int
ipv6_hostlist_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
    conv_hash_t *hash = (conv_hash_t*) pit;
    const struct ws_ip6_hdr *ip6h = (const struct ws_ip6_hdr *)vip;
    address src;
    address dst;

    /* Addresses aren't implemented as 'address' type in struct ws_ip6_hdr */
    set_address(&src, AT_IPv6, sizeof(struct e_in6_addr), &ip6h->ip6_src);
    set_address(&dst, AT_IPv6, sizeof(struct e_in6_addr), &ip6h->ip6_dst);

    add_hostlist_table_data(hash, &src, 0, TRUE, 1, pinfo->fd->pkt_len, &ipv6_host_dissector_info, PT_NONE);
    add_hostlist_table_data(hash, &dst, 0, FALSE, 1, pinfo->fd->pkt_len, &ipv6_host_dissector_info, PT_NONE);

    return 1;
}

static gboolean
ipv6_filter_valid(packet_info *pinfo)
{
    return proto_is_frame_protocol(pinfo->layers, "ipv6");
}

static gchar*
ipv6_build_filter(packet_info *pinfo)
{
    return g_strdup_printf("ipv6.addr eq %s and ipv6.addr eq %s",
                address_to_str(pinfo->pool, &pinfo->net_src),
                address_to_str(pinfo->pool, &pinfo->net_dst));
}

static gint
ipv6_previous_layer_id(packet_info *pinfo)
{
    wmem_list_frame_t *layer;

    layer = wmem_list_tail(pinfo->layers);
    DISSECTOR_ASSERT(layer);
    layer = wmem_list_frame_prev(layer);
    if (layer != NULL) {
        return GPOINTER_TO_INT(wmem_list_frame_data(layer));
    }
    return -1;
}

static const fragment_items ipv6_frag_items = {
    &ett_ipv6_fragment,
    &ett_ipv6_fragments,
    &hf_ipv6_fragments,
    &hf_ipv6_fragment,
    &hf_ipv6_fragment_overlap,
    &hf_ipv6_fragment_overlap_conflict,
    &hf_ipv6_fragment_multiple_tails,
    &hf_ipv6_fragment_too_long_fragment,
    &hf_ipv6_fragment_error,
    &hf_ipv6_fragment_count,
    &hf_ipv6_reassembled_in,
    &hf_ipv6_reassembled_length,
    &hf_ipv6_reassembled_data,
    "IPv6 fragments"
};

static dissector_table_t ip_dissector_table;
static dissector_table_t ipv6_next_header_dissector_table;

/* Reassemble fragmented datagrams */
static gboolean ipv6_reassemble = TRUE;

/* Place IPv6 summary in proto tree */
static gboolean ipv6_summary_in_tree = TRUE;

#ifdef HAVE_GEOIP_V6
/* Look up addresses in GeoIP */
static gboolean ipv6_use_geoip = TRUE;
#endif /* HAVE_GEOIP_V6 */

/* Perform strict RFC adherence checking */
static gboolean g_ipv6_rpl_srh_strict_rfc_checking = FALSE;

/* Use heuristics to determine subdissector */
static gboolean try_heuristic_first = FALSE;

/* Display IPv6 extension headers under the root tree */
static gboolean ipv6_exthdr_under_root = FALSE;

/* Hide extension header generated field for length */
static gboolean ipv6_exthdr_hide_len_oct_field = FALSE;

/*
 * defragmentation of IPv6
 */
static reassembly_table ipv6_reassembly_table;

/* http://www.iana.org/assignments/ipv6-parameters (last updated 2015-07-07) */
static const value_string ipv6_opt_type_vals[] = {
    { IP6OPT_PAD1,          "Pad1"                          },
    { IP6OPT_PADN,          "PadN"                          },
    { IP6OPT_TEL,           "Tunnel Encapsulation Limit"    },
    { IP6OPT_RTALERT,       "Router Alert"                  },
    { IP6OPT_CALIPSO,       "CALIPSO"                       },
    { IP6OPT_SMF_DPD,       "SMF_DPD"                       },
    { IP6OPT_EXP_1E,        "Experimental (0x1E)"           },
    { IP6OPT_QUICKSTART,    "Quick-Start"                   },
    { IP6OPT_EXP_3E,        "Experimental (0x3E)"           },
    { IP6OPT_EXP_5E,        "Experimental (0x5E)"           },
    { IP6OPT_RPL,           "RPL Option"                    },
    { IP6OPT_MPL,           "MPL Option"                    },
    { IP6OPT_EXP_7E,        "Experimental (0x7E)"           },
    { IP6OPT_ENDI,          "Endpoint Identification (DEPRECATED)" },
    { IP6OPT_ILNP_NONCE,    "ILNP Nonce"                    },
    { IP6OPT_LIO,           "Line-Identification Option"    },
    { IP6OPT_EXP_9E,        "Experimental (0x9E)"           },
    { IP6OPT_EXP_BE,        "Experimental (0xBE)"           },
    { IP6OPT_JUMBO,         "Jumbo Payload"                 },
    { IP6OPT_HOME_ADDRESS,  "Home Address"                  },
    { IP6OPT_EXP_DE,        "Experimental (0xDE)"           },
    { IP6OPT_IP_DFF,        "IP_DFF"                        },
    { IP6OPT_EXP_FE,        "Experimental (0xFE)"           },
    { 0, NULL }
};
value_string_ext ipv6_opt_type_vals_ext = VALUE_STRING_EXT_INIT(ipv6_opt_type_vals);

enum {
    IPv6_OPT_ACTION_SKIP = 0,
    IPv6_OPT_ACTION_DISC,
    IPv6_OPT_ACTION_ICMP,
    IPv6_OPT_ACTION_MCST,
};

static const value_string ipv6_opt_type_action_vals[] = {
    { IPv6_OPT_ACTION_SKIP, "Skip and continue" },
    { IPv6_OPT_ACTION_DISC, "Discard" },
    { IPv6_OPT_ACTION_ICMP, "Discard and send ICMP Parameter Problem" },
    { IPv6_OPT_ACTION_MCST, "Discard and send ICMP if not multicast" },
    { 0, NULL }
};

gboolean
capture_ipv6(const guchar *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
    guint8 nxt;
    int    advance;

    if (!BYTES_ARE_IN_FRAME(offset, len, 4+4+16+16))
        return FALSE;

    capture_dissector_increment_count(cpinfo, proto_ipv6);

    nxt = pd[offset+6];           /* get the "next header" value */
    offset += 4+4+16+16;          /* skip past the IPv6 header */

again:
    switch (nxt) {
    case IP_PROTO_HOPOPTS:
    case IP_PROTO_ROUTING:
    case IP_PROTO_DSTOPTS:
        if (!BYTES_ARE_IN_FRAME(offset, len, 2))
            return FALSE;

        nxt = pd[offset];
        advance = (pd[offset+1] + 1) << 3;
        if (!BYTES_ARE_IN_FRAME(offset, len, advance))
            return FALSE;

        offset += advance;
        goto again;
    case IP_PROTO_FRAGMENT:
        if (!BYTES_ARE_IN_FRAME(offset, len, 2))
            return FALSE;

        nxt = pd[offset];
        advance = 8;
        if (!BYTES_ARE_IN_FRAME(offset, len, advance))
            return FALSE;

        offset += advance;
        goto again;
    case IP_PROTO_AH:
        if (!BYTES_ARE_IN_FRAME(offset, len, 2))
            return FALSE;

        nxt = pd[offset];
        advance = 8 + ((pd[offset+1] - 1) << 2);
        if (!BYTES_ARE_IN_FRAME(offset, len, advance))
            return FALSE;

        offset += advance;
        goto again;
    case IP_PROTO_SHIM6:
        if (!BYTES_ARE_IN_FRAME(offset, len, 2))
            return FALSE;

        nxt = pd[offset];
        advance = (pd[offset+1] + 1) << 3;
        if (!BYTES_ARE_IN_FRAME(offset, len, advance))
            return FALSE;

        offset += advance;
        goto again;
    }

    return try_capture_dissector("ipv6.nxt", nxt, pd, offset, len, cpinfo, pseudo_header);
}

#ifdef HAVE_GEOIP_V6
static void
add_geoip_info_entry(proto_tree *geoip_info_tree, proto_item *geoip_info_item, tvbuff_t *tvb, gint offset, const struct e_in6_addr *ip, int isdst)
{
    guint       num_dbs  = geoip_db_num_dbs();
    guint       item_cnt = 0;
    guint       dbnum;

    for (dbnum = 0; dbnum < num_dbs; dbnum++) {
        char *geoip_str = geoip_db_lookup_ipv6(dbnum, *ip, NULL);
        int db_type = geoip_db_type(dbnum);

        int geoip_hf, geoip_local_hf;

        switch (db_type) {
        case GEOIP_COUNTRY_EDITION_V6:
            geoip_hf = hf_geoip_country;
            geoip_local_hf = (isdst) ? hf_geoip_dst_country : hf_geoip_src_country;
            break;
#if NUM_DB_TYPES > 31
        case GEOIP_CITY_EDITION_REV0_V6:
        case GEOIP_CITY_EDITION_REV1_V6:
            geoip_hf = hf_geoip_city;
            geoip_local_hf = (isdst) ? hf_geoip_dst_city : hf_geoip_src_city;
            break;
        case GEOIP_ORG_EDITION_V6:
            geoip_hf = hf_geoip_org;
            geoip_local_hf = (isdst) ? hf_geoip_dst_org : hf_geoip_src_org;
            break;
        case GEOIP_ISP_EDITION_V6:
            geoip_hf = hf_geoip_isp;
            geoip_local_hf = (isdst) ? hf_geoip_dst_isp : hf_geoip_src_isp;
            break;
        case GEOIP_ASNUM_EDITION_V6:
            geoip_hf = hf_geoip_asnum;
            geoip_local_hf = (isdst) ? hf_geoip_dst_asnum : hf_geoip_src_asnum;
            break;
#endif /* DB_NUM_TYPES */
        case WS_LAT_FAKE_EDITION:
            geoip_hf = hf_geoip_lat;
            geoip_local_hf = (isdst) ? hf_geoip_dst_lat : hf_geoip_src_lat;
            break;
        case WS_LON_FAKE_EDITION:
            geoip_hf = hf_geoip_lon;
            geoip_local_hf = (isdst) ? hf_geoip_dst_lon : hf_geoip_src_lon;
            break;
        default:
            continue;
        }

        if (geoip_str) {
            proto_item *item;
            if (db_type == WS_LAT_FAKE_EDITION || db_type == WS_LON_FAKE_EDITION) {
                /* Convert latitude, longitude to double. Fix bug #5077 */
                item = proto_tree_add_double_format_value(geoip_info_tree, geoip_local_hf, tvb,
                                                          offset, 16, g_ascii_strtod(geoip_str, NULL), "%s", geoip_str);
                PROTO_ITEM_SET_GENERATED(item);
                item  = proto_tree_add_double_format_value(geoip_info_tree, geoip_hf, tvb,
                                                           offset, 16, g_ascii_strtod(geoip_str, NULL), "%s", geoip_str);
                PROTO_ITEM_SET_GENERATED(item);
                PROTO_ITEM_SET_HIDDEN(item);
            } else {
                item = proto_tree_add_string(geoip_info_tree, geoip_local_hf, tvb,
                                             offset, 16, geoip_str);
                PROTO_ITEM_SET_GENERATED(item);
                item  = proto_tree_add_string(geoip_info_tree, geoip_hf, tvb,
                                              offset, 16, geoip_str);
                PROTO_ITEM_SET_GENERATED(item);
                PROTO_ITEM_SET_HIDDEN(item);
            }

            item_cnt++;
            proto_item_append_text(geoip_info_item, "%s%s", plurality(item_cnt, "", ", "), geoip_str);
            wmem_free(NULL, geoip_str);
        }
    }

    if (item_cnt == 0)
        proto_item_append_text(geoip_info_item, "Unknown");
}

static void
add_geoip_info(proto_tree *tree, tvbuff_t *tvb, gint offset, const struct e_in6_addr *src, const struct e_in6_addr *dst)
{
    guint       num_dbs;
    proto_item *geoip_info_item;
    proto_tree *geoip_info_tree;

    num_dbs = geoip_db_num_dbs();
    if (num_dbs < 1)
        return;

    geoip_info_tree = proto_tree_add_subtree(tree, tvb, offset + IP6H_SRC, 16, ett_geoip_info, &geoip_info_item, "Source GeoIP: ");
    PROTO_ITEM_SET_GENERATED(geoip_info_item);
    add_geoip_info_entry(geoip_info_tree, geoip_info_item, tvb, offset + IP6H_SRC, src, 0);

    geoip_info_tree = proto_tree_add_subtree(tree, tvb, offset + IP6H_DST, 16, ett_geoip_info, &geoip_info_item, "Destination GeoIP: ");
    PROTO_ITEM_SET_GENERATED(geoip_info_item);
    add_geoip_info_entry(geoip_info_tree, geoip_info_item, tvb, offset + IP6H_DST, dst, 1);
}
#endif /* HAVE_GEOIP_V6 */

static void
ipv6_reassemble_init(void)
{
    reassembly_table_init(&ipv6_reassembly_table,
                          &addresses_reassembly_table_functions);
}

/* Returns 'show_data' */
static gboolean
ipv6_reassemble_do(tvbuff_t **tvb_ptr, gint *offset_ptr, packet_info *pinfo, proto_tree *ipv6_tree, guint32 plen)
{
    ipv6_pinfo_t    *ipv6_pinfo = p_get_ipv6_pinfo(pinfo);
    fragment_head   *ipfd_head;
    tvbuff_t        *next_tvb;
    gboolean         update_col_info = TRUE;

    pinfo->fragmented = TRUE;
    if (!ipv6_reassemble) {
        /* not reassembling */
        if (ipv6_pinfo->frag_off != 0) {
             /* not in the first fragment */
            return TRUE;
        }
        return FALSE;
    }

    /* reassembling */
    if (tvb_bytes_exist(*tvb_ptr, *offset_ptr, plen)) {
        ipfd_head = fragment_add_check(&ipv6_reassembly_table,
                                       *tvb_ptr, *offset_ptr, pinfo, ipv6_pinfo->frag_ident, NULL,
                                       ipv6_pinfo->frag_off, plen, ipv6_pinfo->frag_flg);
        next_tvb = process_reassembled_data(*tvb_ptr, *offset_ptr, pinfo, "Reassembled IPv6",
                                            ipfd_head, &ipv6_frag_items, &update_col_info, ipv6_tree);
        if (next_tvb) {
            /* Process post-fragment headers after reassembly */
            *offset_ptr = 0;
            *tvb_ptr = next_tvb;
            pinfo->fragmented = FALSE;
            return FALSE;
        }
    }
    return TRUE;
}

static void
ipv6_reassemble_cleanup(void)
{
    reassembly_table_destroy(&ipv6_reassembly_table);
}

enum {
    IPv6_RT_HEADER_SOURCE_ROUTING=0,
    IPv6_RT_HEADER_NIMROD,
    IPv6_RT_HEADER_MobileIP,
    IPv6_RT_HEADER_RPL,
    IPv6_RT_HEADER_SEGMENT_ROUTING
};

/* Routing Header Types */
static const value_string routing_header_type[] = {
    { IPv6_RT_HEADER_SOURCE_ROUTING, "IPv6 Source Routing" },
    { IPv6_RT_HEADER_NIMROD, "Nimrod" },
    { IPv6_RT_HEADER_MobileIP, "Mobile IP" },
    { IPv6_RT_HEADER_RPL, "RPL" },
    { IPv6_RT_HEADER_SEGMENT_ROUTING, "Segment Routing"},
    { 0, NULL }
};

struct rthdr_proto_item {
    proto_item *len;
    proto_item *type;
    proto_item *segs;
};

static proto_item *
_proto_tree_add_ipv6_vector_address(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start,
                            gint length, const struct e_in6_addr *value_ptr, int idx)
{
    address addr;
    gchar *str;

    set_address(&addr, AT_IPv6, IPv6_ADDR_SIZE, value_ptr);
    str = address_with_resolution_to_str(wmem_packet_scope(), &addr);
    return proto_tree_add_ipv6_format(tree, hfindex, tvb, start, length,
                        value_ptr, "Address[%d]: %s", idx, str);
}

/* IPv6 Source Routing Header (Type 0) */
static void
dissect_routing6_rt0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *rthdr_tree,
                        struct rthdr_proto_item *rthdr_ti, struct ip6_rthdr rt)
{
    proto_item *ti;
    gint idx;
    gint rt0_addr_count;
    const struct e_in6_addr *addr = NULL;

    proto_tree_add_item(rthdr_tree, hf_ipv6_routing_src_reserved, tvb, offset, 4, ENC_NA);
    offset += 4;

    if (rt.ip6r_len % 2 != 0) {
        expert_add_info_format(pinfo, rthdr_ti->len, &ei_ipv6_routing_invalid_length,
                "IPv6 Routing Header extension header length must not be odd");
    }
    rt0_addr_count = rt.ip6r_len / 2;
    if (rt.ip6r_segleft > rt0_addr_count) {
        expert_add_info_format(pinfo, rthdr_ti->segs, &ei_ipv6_routing_invalid_segleft,
                "IPv6 Type 0 Routing Header segments left field must not exceed address count (%u)", rt0_addr_count);
    }

    for (idx = 1; idx <= rt0_addr_count; idx++) {
        addr = tvb_get_ptr_ipv6(tvb, offset);
        ti = _proto_tree_add_ipv6_vector_address(rthdr_tree, hf_ipv6_routing_src_addr, tvb,
                            offset, IPv6_ADDR_SIZE, addr, idx);
        offset += IPv6_ADDR_SIZE;
        if (in6_is_addr_multicast(addr)) {
            expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_multicast_addr);
        }
    }

    if (addr != NULL && rt.ip6r_segleft > 0) {
        alloc_address_wmem(pinfo->pool, &pinfo->dst, AT_IPv6, IPv6_ADDR_SIZE, addr);
    }
}

/* Mobile IPv6 Routing Header (Type 2) */
static void
dissect_routing6_mipv6(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *rthdr_tree,
                        struct rthdr_proto_item *rthdr_ti, struct ip6_rthdr rt)
{
    proto_item *ti;
    const struct e_in6_addr *addr;

    proto_tree_add_item(rthdr_tree, hf_ipv6_routing_mipv6_reserved, tvb, offset, 4, ENC_NA);
    offset += 4;

    if (rt.ip6r_len != 2) {
        expert_add_info_format(pinfo, rthdr_ti->len, &ei_ipv6_routing_invalid_length,
                "IPv6 Type 2 Routing Header extension header length must equal 2");
    }
    if (rt.ip6r_segleft != 1) {
        expert_add_info_format(pinfo, rthdr_ti->segs, &ei_ipv6_routing_invalid_segleft,
                "IPv6 Type 2 Routing Header segments left field must equal 1");
    }

    addr = tvb_get_ptr_ipv6(tvb, offset);
    ti = _proto_tree_add_ipv6_vector_address(rthdr_tree, hf_ipv6_routing_mipv6_home_address, tvb,
                        offset, IPv6_ADDR_SIZE, addr, 1);
    if (in6_is_addr_multicast(addr)) {
        expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_multicast_addr);
    }

    if (rt.ip6r_segleft > 0) {
        alloc_address_wmem(pinfo->pool, &pinfo->dst, AT_IPv6, IPv6_ADDR_SIZE, addr);
    }
}

/* RPL Source Routing Header (Type 3) */
static void
dissect_routing6_rpl(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *rthdr_tree,
                        struct rthdr_proto_item *rthdr_ti, struct ip6_rthdr rt)
{
    proto_item *pi = proto_tree_get_parent(rthdr_tree);
    proto_item *ti;
    guint8 cmprI, cmprE, cmprX, pad;
    guint32 reserved;
    gint idx;
    gint rpl_addr_count;
    struct e_in6_addr rpl_fulladdr;
    const struct e_in6_addr *ip6_dst_addr, *ip6_src_addr;
    wmem_array_t *rpl_addr_vector = NULL;
    guint i;

    /* IPv6 destination address used for elided bytes */
    ip6_dst_addr = (const struct e_in6_addr *)pinfo->dst.data;
    /* IPv6 source address used for strict checking */
    ip6_src_addr = (const struct e_in6_addr *)pinfo->src.data;

    /* from RFC6554: Multicast addresses MUST NOT appear in the IPv6 Destination Address field */
    if (in6_is_addr_multicast(ip6_dst_addr)) {
        expert_add_info(pinfo, pi, &ei_ipv6_dst_addr_not_multicast);
    }

    proto_tree_add_item(rthdr_tree, hf_ipv6_routing_rpl_cmprI, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(rthdr_tree, hf_ipv6_routing_rpl_cmprE, tvb, offset, 4, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(rthdr_tree, hf_ipv6_routing_rpl_pad, tvb, offset, 4, ENC_BIG_ENDIAN);

    cmprI = tvb_get_guint8(tvb, offset) & 0xF0;
    cmprE = tvb_get_guint8(tvb, offset) & 0x0F;
    pad   = tvb_get_guint8(tvb, offset + 1) & 0xF0;

    /* Shift bytes over */
    cmprI >>= 4;
    pad >>= 4;

    /* from RFC6554: when CmprI and CmprE are both 0, Pad MUST carry a value of 0 */
    if (cmprI == 0 && cmprE == 0 && pad != 0) {
        expert_add_info_format(pinfo, ti, &ei_ipv6_routing_rpl_cmpri_cmpre_pad, "When cmprI equals 0 and cmprE equals 0, pad MUST equal 0 but instead was %d", pad);
    }

    ti = proto_tree_add_item(rthdr_tree, hf_ipv6_routing_rpl_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    reserved = tvb_get_bits32(tvb, ((offset + 1) * 8) + 4, 20, ENC_BIG_ENDIAN);

    if (reserved != 0) {
        expert_add_info_format(pinfo, ti, &ei_ipv6_routing_rpl_reserved, "Reserved field must equal 0 but instead was %d", reserved);
    }

    /* From RFC6554:
     *   n = (((Hdr Ext Len * 8) - Pad - (16 - CmprE)) / (16 - CmprI)) + 1
     */
    rpl_addr_count = 0;
    if (rt.ip6r_len > 0) {
        rpl_addr_count = (((rt.ip6r_len * 8) - pad - (16 - cmprE)) / (16 - cmprI)) + 1;
    }
    ti = proto_tree_add_int(rthdr_tree, hf_ipv6_routing_rpl_addr_count, tvb, offset, 2, rpl_addr_count);
    PROTO_ITEM_SET_GENERATED(ti);
    if (rpl_addr_count < 0) {
        /* This error should always be reported */
        expert_add_info_format(pinfo, ti, &ei_ipv6_routing_rpl_addr_count_ge0, "Calculated total address count must be greater than or equal to 0, instead was %d", rpl_addr_count);
    }
    else if (rt.ip6r_segleft > (guint)rpl_addr_count) {
        expert_add_info_format(pinfo, rthdr_ti->segs, &ei_ipv6_routing_invalid_segleft,
            "IPv6 RPL Routing Header segments left field must not exceed address count (%d)", rpl_addr_count);
    }

    if (rpl_addr_count > 0) {
        offset += 4;

        if (g_ipv6_rpl_srh_strict_rfc_checking)
            rpl_addr_vector = wmem_array_sized_new(wmem_packet_scope(), IPv6_ADDR_SIZE, rpl_addr_count);

        /* We use cmprI for internal (e.g.: not last) address for how many bytes to elide, so actual bytes present = 16-CmprI */
        for (idx = 1; idx <= rpl_addr_count; idx++) {
            if (idx == rpl_addr_count)
                cmprX = 16 - cmprE;
            else
                cmprX = 16 - cmprI;
            proto_tree_add_item(rthdr_tree, hf_ipv6_routing_rpl_addr, tvb, offset, cmprX, ENC_NA);
            /* Display Full Address */
            memcpy(&rpl_fulladdr, ip6_dst_addr, IPv6_ADDR_SIZE);
            tvb_memcpy(tvb, &rpl_fulladdr.bytes[16-cmprX], offset, cmprX);
            ti = _proto_tree_add_ipv6_vector_address(rthdr_tree, hf_ipv6_routing_rpl_fulladdr, tvb,
                                offset, cmprX, &rpl_fulladdr, idx);
            PROTO_ITEM_SET_GENERATED(ti);
            offset += cmprX;

            /* IPv6 Source and Destination addresses of the encapsulating datagram (MUST) not appear in the SRH*/
            if (memcmp(&rpl_fulladdr, ip6_src_addr, IPv6_ADDR_SIZE) == 0) {
                expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_src_addr);
            }
            if (memcmp(&rpl_fulladdr, ip6_dst_addr, IPv6_ADDR_SIZE) == 0) {
                expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_dst_addr);
            }

            /* Multicast addresses MUST NOT appear in the in SRH */
            if (in6_is_addr_multicast(&rpl_fulladdr)) {
                expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_multicast_addr);
            }

            if (g_ipv6_rpl_srh_strict_rfc_checking) {
                /* from RFC6554: */
                /* The SRH MUST NOT specify a path that visits a node more than once. */
                /* To do this, we will just check the current 'addr' against the previous addresses */
                for (i = 0; i < wmem_array_get_count(rpl_addr_vector); i++) {
                    /* Compare the addresses */
                    if (memcmp(&rpl_fulladdr, wmem_array_index(rpl_addr_vector, i), IPv6_ADDR_SIZE) == 0) {
                        /* Found a previous that is the same */
                        expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_mult_inst_same_addr);
                        break;
                    }
                }
                wmem_array_append(rpl_addr_vector, &rpl_fulladdr, 1);
            }

            if (rt.ip6r_segleft > 0) {
                alloc_address_wmem(pinfo->pool, &pinfo->dst, AT_IPv6, IPv6_ADDR_SIZE, &rpl_fulladdr);
            }
        }
    }
}

/* Segment Routing Header (Type 4) */
/* draft-ietf-6man-segment-routing-header-01 */
static void
dissect_routing6_srh(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *rthdr_tree,
                        struct rthdr_proto_item *rthdr_ti, struct ip6_rthdr rt)
{
    proto_item *ti;
    gint offlim, offstart;
    gint idx;
    gint srh_first_seg, srh_addr_count;
    const struct e_in6_addr *addr;
    proto_tree *rthdr_srh_addr_tree;
    static const int *srh_flags[] = {
        &hf_ipv6_routing_srh_flag_c,
        &hf_ipv6_routing_srh_flag_p,
        &hf_ipv6_routing_srh_flag_o,
        &hf_ipv6_routing_srh_flag_a,
        &hf_ipv6_routing_srh_flag_h,
        &hf_ipv6_routing_srh_flag_unused,
        NULL
    };

    srh_first_seg = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(rthdr_tree, hf_ipv6_routing_srh_first_seg, tvb, offset, 1, ENC_NA);
    offset += 1;
    srh_addr_count = srh_first_seg + 1;

    /* TODO: dissect TLVs */
    ti = proto_tree_add_bitmask(rthdr_tree, tvb, offset, hf_ipv6_routing_srh_flags,
                            ett_ipv6_routing_srh_flags, srh_flags, ENC_BIG_ENDIAN);
    expert_add_info_format(pinfo, ti, &ei_ipv6_routing_not_implemented,
                "Dissection for SRH TLVs not yet implemented");
    offset += 2;

    proto_tree_add_item(rthdr_tree, hf_ipv6_routing_srh_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (rt.ip6r_segleft > srh_first_seg) {
        expert_add_info_format(pinfo, rthdr_ti->segs, &ei_ipv6_routing_invalid_segleft,
                               "IPv6 Type 4 Routing Header segments left field must not exceed first segment (%u)", srh_first_seg);
    }

    offstart = offset;
    offlim = offset + srh_addr_count * IPv6_ADDR_SIZE;

    /* Destination address is the first vector address */
    addr = tvb_get_ptr_ipv6(tvb, offset);
    if (in6_is_addr_multicast(addr)) {
        expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_multicast_addr);
    }
    ti = _proto_tree_add_ipv6_vector_address(rthdr_tree, hf_ipv6_routing_srh_addr, tvb,
                            offset, IPv6_ADDR_SIZE, addr, 0);
    if (rt.ip6r_segleft == 1) {
        proto_item_append_text(ti, " [next segment]");
    }

    if (rt.ip6r_segleft > 0) {
        alloc_address_wmem(pinfo->pool, &pinfo->dst, AT_IPv6, IPv6_ADDR_SIZE, addr);
    }

    offset += IPv6_ADDR_SIZE;
    for (idx = 1; offset < offlim; offset += IPv6_ADDR_SIZE, idx++) {
        addr = tvb_get_ptr_ipv6(tvb, offset);
        if (in6_is_addr_multicast(addr)) {
            expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_multicast_addr);
        }
        ti = _proto_tree_add_ipv6_vector_address(rthdr_tree, hf_ipv6_routing_srh_addr, tvb,
                            offset, IPv6_ADDR_SIZE, addr, idx);
        if (idx == rt.ip6r_segleft - 1) {
            proto_item_append_text(ti, " [next segment]");
        }
    }

    rthdr_srh_addr_tree = proto_tree_add_subtree_format(rthdr_tree, tvb, offstart, srh_addr_count * IPv6_ADDR_SIZE,
                            ett_ipv6_routing_srh_vect, &ti, "Segments in Traversal Order");
    PROTO_ITEM_SET_GENERATED(ti);
    offset -= IPv6_ADDR_SIZE;
    for (idx = srh_first_seg; offset >= offstart; offset -= IPv6_ADDR_SIZE, idx--) {
        addr = tvb_get_ptr_ipv6(tvb, offset);
        ti = _proto_tree_add_ipv6_vector_address(rthdr_srh_addr_tree, hf_ipv6_routing_srh_addr, tvb,
                            offset, IPv6_ADDR_SIZE, addr, idx);
        if (idx == rt.ip6r_segleft - 1) {
            proto_item_append_text(ti, " [next segment]");
        }
    }
}

static int
dissect_routing6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
    struct ip6_rthdr   rt;
    guint              len;
    proto_tree        *rthdr_tree;
    proto_item        *pi, *ti;
    struct rthdr_proto_item rthdr_ti;
    int                offset = 0;

    col_append_sep_str(pinfo->cinfo, COL_INFO, " , ", "IPv6 routing");

    tvb_memcpy(tvb, (guint8 *)&rt, offset, sizeof(rt));
    len = (rt.ip6r_len + 1) << 3;

    /* !!! specify length */
    pi = proto_tree_add_item(tree, proto_ipv6_routing, tvb, offset, len, ENC_NA);
    proto_item_append_text(pi, " (%s)", val_to_str(rt.ip6r_type, routing_header_type, "Unknown type %u"));

    rthdr_tree = proto_item_add_subtree(pi, ett_ipv6_routing_proto);

    proto_tree_add_item(rthdr_tree, hf_ipv6_routing_nxt, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    rthdr_ti.len = proto_tree_add_item(rthdr_tree, hf_ipv6_routing_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_uint(rthdr_tree, hf_ipv6_routing_len_oct, tvb, offset, 1, len);
    proto_item_append_text(ti, " bytes");
    PROTO_ITEM_SET_GENERATED(ti);
    if (ipv6_exthdr_hide_len_oct_field) {
        PROTO_ITEM_SET_HIDDEN(ti);
        proto_item_append_text(rthdr_ti.len, " (%d bytes)", len);
    }
    offset += 1;

    rthdr_ti.type = proto_tree_add_item(rthdr_tree, hf_ipv6_routing_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    rthdr_ti.segs = proto_tree_add_item(rthdr_tree, hf_ipv6_routing_segleft, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    switch (rt.ip6r_type) {
    case IPv6_RT_HEADER_SOURCE_ROUTING:
        dissect_routing6_rt0(tvb, offset, pinfo, rthdr_tree, &rthdr_ti, rt);
        break;
    case IPv6_RT_HEADER_MobileIP:
        dissect_routing6_mipv6(tvb, offset, pinfo, rthdr_tree, &rthdr_ti, rt);
        break;
    case IPv6_RT_HEADER_RPL:
        dissect_routing6_rpl(tvb, offset, pinfo, rthdr_tree, &rthdr_ti, rt);
        break;
    case IPv6_RT_HEADER_SEGMENT_ROUTING:
        dissect_routing6_srh(tvb, offset, pinfo, rthdr_tree, &rthdr_ti, rt);
        break;
    default:
        break;
    }

    return len;
}

static int
dissect_fraghdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    proto_item      *pi, *ti;
    proto_tree      *frag_tree;
    guint8           nxt;
    guint16          offlg;
    gint             offset = 0;
    ipv6_pinfo_t    *ipv6_pinfo;

    ipv6_pinfo = p_get_ipv6_pinfo(pinfo);

    nxt = tvb_get_guint8(tvb, offset);
    offlg = tvb_get_ntohs(tvb, offset + 2);
    ipv6_pinfo->frag_off = offlg & IP6F_OFF_MASK; /* offset in bytes */
    ipv6_pinfo->frag_flg = offlg & IP6F_MORE_FRAG;
    ipv6_pinfo->frag_ident = tvb_get_ntohl(tvb, offset + 4);
    col_add_fstr(pinfo->cinfo, COL_INFO, "IPv6 fragment (off=%u more=%s ident=0x%08x nxt=%u)",
                        ipv6_pinfo->frag_off, ipv6_pinfo->frag_flg ? "y" : "n", ipv6_pinfo->frag_ident, nxt);

    /* IPv6 Fragmentation Header has fixed length of 8 bytes */
    pi = proto_tree_add_item(tree, proto_ipv6_fraghdr, tvb, offset, 8, ENC_NA);
    if (ipv6_pinfo->jumbo_plen != 0) {
        expert_add_info(pinfo, pi, &ei_ipv6_opt_jumbo_fragment);
    }

    frag_tree = proto_item_add_subtree(pi, ett_ipv6_fraghdr_proto);

    if (frag_tree) {
        proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_nxt, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_reserved_octet, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        ti = proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, " (%d bytes)", ipv6_pinfo->frag_off);

        proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_reserved_bits, tvb, offset, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_more, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_ident, tvb, offset, 4, ENC_BIG_ENDIAN);
        /*offset += 4;*/
    }

    return 8;
}

static const value_string rtalertvals[] = {
    { IP6OPT_RTALERT_MLD, "MLD" },
    { IP6OPT_RTALERT_RSVP, "RSVP" },
    { IP6OPT_RTALERT_ACTNET, "Active Network" },
    { 0, NULL }
};

struct opt_proto_item {
    proto_item *type, *len;
};

/*
 * Jumbo Payload Option
 *
                                   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                   |  Option Type  |  Opt Data Len |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Jumbo Payload Length                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static gint
dissect_opt_jumbo(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *opt_tree,
                    struct opt_proto_item *opt_ti, guint8 opt_len, gboolean hopopts, guint16 ip6_plen)
{
    proto_item *pi = proto_tree_get_parent(opt_tree);
    proto_item *ti;
    guint32 jumbo_plen = 0;

    if (opt_len != 4) {
        expert_add_info_format(pinfo, opt_ti->len, &ei_ipv6_opt_invalid_len,
                "Jumbo Payload: Invalid length (%u bytes)", opt_len);
    }
    ti = proto_tree_add_item_ret_uint(opt_tree, hf_ipv6_opt_jumbo, tvb, offset, 4, ENC_BIG_ENDIAN, &jumbo_plen);
    offset += 4;

    if (!hopopts) {
        expert_add_info(pinfo, pi, &ei_ipv6_opt_jumbo_not_hopbyhop);
    }
    if (ip6_plen != 0) {
        expert_add_info(pinfo, pi, &ei_ipv6_opt_jumbo_prohibited);
    }
    if (jumbo_plen < 65536) {
        expert_add_info(pinfo, ti, &ei_ipv6_opt_jumbo_truncated);
    }

    return offset;
}

/*
 * RPL Option
 *
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                     |  Option Type  |  Opt Data Len |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |O|R|F|0|0|0|0|0| RPLInstanceID |          SenderRank           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                         (sub-TLVs)                            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static gint
dissect_opt_rpl(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *opt_tree,
                    struct opt_proto_item *opt_ti, guint8 opt_len)
{
    static const int *rpl_flags[] = {
        &hf_ipv6_opt_rpl_flag_o,
        &hf_ipv6_opt_rpl_flag_r,
        &hf_ipv6_opt_rpl_flag_f,
        &hf_ipv6_opt_rpl_flag_rsv,
        NULL
    };

    if (opt_len < 4) {
        expert_add_info_format(pinfo, opt_ti->len, &ei_ipv6_opt_invalid_len,
                "RPL Option: Invalid length (%u bytes)", opt_len);
    }
    proto_tree_add_bitmask(opt_tree, tvb, offset, hf_ipv6_opt_rpl_flag, ett_ipv6_opt_rpl, rpl_flags, ENC_NA);
    offset += 1;
    proto_tree_add_item(opt_tree, hf_ipv6_opt_rpl_instance_id, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(opt_tree, hf_ipv6_opt_rpl_senderrank, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* TODO: Add dissection of sub-TLVs */

    return offset;
}

/*
 * Tunnel Encapsulation Limit Option
 *
      Option Type     Opt Data Len   Opt Data Len
    0 1 2 3 4 5 6 7
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 0 0 0 0 1 0 0|       1       | Tun Encap Lim |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static gint
dissect_opt_tel(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *opt_tree,
                    struct opt_proto_item *opt_ti, guint8 opt_len)
{
    if (opt_len != 1) {
        expert_add_info_format(pinfo, opt_ti->len, &ei_ipv6_opt_invalid_len,
                "Tunnel Encapsulation Limit: Invalid length (%u bytes)", opt_len);
    }
    proto_tree_add_item(opt_tree, hf_ipv6_opt_tel, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

/*
 * IPv6 Router Alert Option
 *
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 0 0|0 0 1 0 1|0 0 0 0 0 0 1 0|        Value (2 octets)       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                      length = 2
*/
static gint
dissect_opt_rtalert(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *opt_tree,
                        struct opt_proto_item *opt_ti, guint8 opt_len)
{
    if (opt_len != 2) {
        expert_add_info_format(pinfo, opt_ti->len, &ei_ipv6_opt_invalid_len,
                "Router alert: Invalid Length (%u bytes)", opt_len);
    }
    proto_tree_add_item(opt_tree, hf_ipv6_opt_rtalert, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

/*
 * Quick-Start Option for IPv6
 *
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Option      |  Length=6     | Func. | Rate  |   Not Used    |
   |               |               | 1000  | Report|               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        QS Nonce                           | R |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static gint
dissect_opt_quickstart(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *opt_tree,
                        struct opt_proto_item *opt_ti, guint8 opt_len, guint8 hlim)
{
    proto_item *pi = proto_tree_get_parent(opt_tree);
    proto_item *ti;
    guint8 command, function, rate;
    guint8 ttl_diff = 0;
    guint32 qs_ttl = 0;

    if (opt_len != 6) {
        expert_add_info_format(pinfo, opt_ti->len, &ei_ipv6_opt_invalid_len,
                "Quick-Start: Invalid Length (%u bytes)", opt_len);
    }

    command = tvb_get_guint8(tvb, offset);
    function = command >> 4;
    rate = command & QS_RATE_MASK;

    proto_tree_add_item(opt_tree, hf_ipv6_opt_qs_func, tvb, offset, 1, ENC_BIG_ENDIAN);

    switch (function) {
    case QS_RATE_REQUEST:
        proto_tree_add_item(opt_tree, hf_ipv6_opt_qs_rate, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item_ret_uint(opt_tree, hf_ipv6_opt_qs_ttl, tvb, offset, 1, ENC_BIG_ENDIAN, &qs_ttl);
        ttl_diff = (hlim - qs_ttl) % 256;
        ti = proto_tree_add_uint(opt_tree, hf_ipv6_opt_qs_ttl_diff, tvb, offset, 1, ttl_diff);
        PROTO_ITEM_SET_GENERATED(ti);
        proto_item_append_text(pi, ", %s, QS TTL %u, QS TTL diff %u",
                               val_to_str_ext(rate, &qs_rate_vals_ext, "Unknown (%u)"),
                               qs_ttl, ttl_diff);
        offset += 1;
        proto_tree_add_item(opt_tree, hf_ipv6_opt_qs_nonce, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(opt_tree, hf_ipv6_opt_qs_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    case QS_RATE_REPORT:
        proto_tree_add_item(opt_tree, hf_ipv6_opt_qs_rate, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(pi, ", %s", val_to_str_ext(rate, &qs_rate_vals_ext, "Unknown (%u)"));
        offset += 1;
        proto_tree_add_item(opt_tree, hf_ipv6_opt_qs_unused, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(opt_tree, hf_ipv6_opt_qs_nonce, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(opt_tree, hf_ipv6_opt_qs_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    default:
        break;
    }

    return offset;
}

/*
   ------------------------------------------------------------
   | Next Header | Hdr Ext Len   | Option Type | Option Length|
   +-------------+---------------+-------------+--------------+
   |             CALIPSO Domain of Interpretation             |
   +-------------+---------------+-------------+--------------+
   | Cmpt Length |  Sens Level   |     Checksum (CRC-16)      |
   +-------------+---------------+-------------+--------------+
   |      Compartment Bitmap (Optional; variable length)      |
   +-------------+---------------+-------------+--------------+
*/
static gint
dissect_opt_calipso(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *opt_tree,
                    struct opt_proto_item *opt_ti, guint8 opt_len)
{
    guint32 cmpt_length = 0;

    if (opt_len < 8) {
        expert_add_info_format(pinfo, opt_ti->len, &ei_ipv6_opt_invalid_len,
                "CALIPSO: Invalid Length (%u bytes)", opt_len);
    }

    proto_tree_add_item(opt_tree, hf_ipv6_opt_calipso_doi, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item_ret_uint(opt_tree, hf_ipv6_opt_calipso_cmpt_length, tvb,
                        offset, 1, ENC_BIG_ENDIAN, &cmpt_length);
    offset += 1;

    proto_tree_add_item(opt_tree, hf_ipv6_opt_calipso_sens_level, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_checksum(opt_tree, tvb, offset, hf_ipv6_opt_calipso_checksum, -1,
                                NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
    offset += 2;

    proto_tree_add_item(opt_tree, hf_ipv6_opt_calipso_cmpt_bitmap, tvb,
                        offset, cmpt_length*4, ENC_NA);
    offset += cmpt_length*4;

    return offset;
}

/*
 * Home Address Option
 *
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                      |  Option Type  | Option Length |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                                                               +
      |                                                               |
      +                          Home Address                         +
      |                                                               |
      +                                                               +
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static gint
dissect_opt_home_address(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *opt_tree,
                            struct opt_proto_item *opt_ti, guint8 opt_len)
{
    if (opt_len != 16) {
        expert_add_info_format(pinfo, opt_ti->len, &ei_ipv6_opt_invalid_len,
                "Home Address: Invalid length (%u bytes)", opt_len);
    }
    proto_tree_add_item(opt_tree, hf_ipv6_opt_mipv6_home_address, tvb, offset, 16, ENC_NA);
    alloc_address_tvb(pinfo->pool, &pinfo->src, AT_IPv6, 16, tvb, offset);
    offset += 16;

    return offset;
}

/*
 * ILNP Nonce Option
 *

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Next Header   | Hdr Ext Len   |  Option Type  | Option Length |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /                         Nonce Value                           /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static gint
dissect_opt_ilnp_nonce(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *opt_tree,
                            struct opt_proto_item *opt_ti _U_, guint8 opt_len)
{
    proto_tree_add_item(opt_tree, hf_ipv6_opt_ilnp_nonce, tvb, offset, opt_len, ENC_NA);
    offset += opt_len;

    return offset;
}

/*
 * Line-Identification Option
 *
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                   |  Option Type  | Option Length |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | LineIDLen     |     Line ID...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static gint
dissect_opt_lio(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *opt_tree,
                            struct opt_proto_item *opt_ti _U_, guint8 opt_len)
{
    guint32 lid_len = 0;

    proto_tree_add_item_ret_uint(opt_tree, hf_ipv6_opt_lio_len, tvb, offset, 1, ENC_BIG_ENDIAN, &lid_len);
    offset += 1;

    if (lid_len + 1 > opt_len) {
        /* XXX Add expert info */
        lid_len = opt_len - 1;
    }
    proto_tree_add_item(opt_tree, hf_ipv6_opt_lio_id, tvb, offset, lid_len, ENC_BIG_ENDIAN|ENC_ASCII);
    offset += lid_len;

    return offset;
}

/*
 * MPL Option
 *
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                     |  Option Type  |  Opt Data Len |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     | S |M|V|  rsv  |   sequence    |      seed-id (optional)       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static gint
dissect_opt_mpl(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *opt_tree,
                    struct opt_proto_item *opt_ti _U_, guint8 opt_len _U_)
{
    static const int *mpl_flags[] = {
        &hf_ipv6_opt_mpl_flag_s,
        &hf_ipv6_opt_mpl_flag_m,
        &hf_ipv6_opt_mpl_flag_v,
        &hf_ipv6_opt_mpl_flag_rsv,
        NULL
    };
    static const guint8 seed_id_len_arr[4] = {0, 2, 8, 16};
    guint8 seed_id_len;

    proto_tree_add_bitmask(opt_tree, tvb, offset, hf_ipv6_opt_mpl_flag, ett_ipv6_opt_mpl, mpl_flags, ENC_NA);
    seed_id_len = seed_id_len_arr[tvb_get_guint8(tvb, offset) >> 6];
    offset +=1;

    proto_tree_add_item(opt_tree, hf_ipv6_opt_mpl_sequence, tvb, offset, 1, ENC_NA);
    offset +=1;
    if (seed_id_len > 0) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_mpl_seed_id, tvb, offset, seed_id_len, ENC_NA);
        offset += seed_id_len;
    }

    return offset;
}

/*
 * IPv6 DFF Header
 *
                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Next Header  |  Hdr Ext Len  |  OptTypeDFF   | OptDataLenDFF |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |VER|D|R|0|0|0|0|        Sequence Number        |      Pad1     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static gint
dissect_opt_dff(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *opt_tree,
                            struct opt_proto_item *opt_ti, guint8 opt_len)
{
    static const int *dff_flags[] = {
        &hf_ipv6_opt_dff_flag_ver,
        &hf_ipv6_opt_dff_flag_dup,
        &hf_ipv6_opt_dff_flag_ret,
        &hf_ipv6_opt_dff_flag_rsv,
        NULL
    };

    /* Option length is 3 octets */
    /* http://www.rfc-editor.org/errata_search.php?eid=3937 */
    if (opt_len != 3) {
        expert_add_info_format(pinfo, opt_ti->len, &ei_ipv6_opt_invalid_len,
                "IPv6 DFF: Invalid length (%u bytes)", opt_len);
    }
    proto_tree_add_bitmask(opt_tree, tvb, offset, hf_ipv6_opt_dff_flags,
                            ett_ipv6_opt_dff_flags, dff_flags, ENC_NA);
    offset += 1;
    proto_tree_add_item(opt_tree, hf_ipv6_opt_dff_seqnum, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static gint
dissect_opt_unknown(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *opt_tree,
                            struct opt_proto_item *opt_ti _U_, guint8 opt_len)
{
    proto_item *ti;

    ti = proto_tree_add_item(opt_tree, hf_ipv6_opt_unknown, tvb,
                        offset, opt_len, ENC_NA);
    expert_add_info(pinfo, ti, &ei_ipv6_opt_unknown_data);

    return offset + opt_len;
}

static int
dissect_opts(tvbuff_t *tvb, int offset, proto_tree *tree, packet_info *pinfo, ws_ip *iph, const int exthdr_proto)
{
    gint            len, offset_end;
    proto_tree     *exthdr_tree, *opt_tree, *opt_type_tree;
    proto_item     *pi, *ti, *ti_len;
    int             hf_exthdr_item_nxt, hf_exthdr_item_len, hf_exthdr_item_len_oct;
    int             ett_exthdr_proto;
    guint8          opt_type, opt_len, opt_start;
    gboolean        hopopts;
    struct opt_proto_item opt_ti;
    ipv6_pinfo_t   *ipv6_pinfo = p_get_ipv6_pinfo(pinfo);

    hopopts = (exthdr_proto == proto_ipv6_hopopts);

    len = (tvb_get_guint8(tvb, offset + 1) + 1) << 3;
    offset_end = offset + len;

    /* !!! specify length */
    ti = proto_tree_add_item(tree, exthdr_proto, tvb, offset, len, ENC_NA);

    if (hopopts && ipv6_previous_layer_id(pinfo) != proto_ipv6) {
        /* IPv6 Hop-by-Hop must appear immediately after IPv6 header (RFC 2460) */
        expert_add_info(pinfo, ti, &ei_ipv6_hopopts_not_first);
    }

    if (exthdr_proto == proto_ipv6_hopopts) {
        hf_exthdr_item_nxt = hf_ipv6_hopopts_nxt;
        hf_exthdr_item_len = hf_ipv6_hopopts_len;
        hf_exthdr_item_len_oct = hf_ipv6_hopopts_len_oct;
        ett_exthdr_proto = ett_ipv6_hopopts_proto;
    } else if (exthdr_proto == proto_ipv6_dstopts) {
        hf_exthdr_item_nxt = hf_ipv6_dstopts_nxt;
        hf_exthdr_item_len = hf_ipv6_dstopts_len;
        hf_exthdr_item_len_oct = hf_ipv6_dstopts_len_oct;
        ett_exthdr_proto = ett_ipv6_dstopts_proto;
    } else {
        DISSECTOR_ASSERT_NOT_REACHED();
    }

    exthdr_tree = proto_item_add_subtree(ti, ett_exthdr_proto);

    proto_tree_add_item(exthdr_tree, hf_exthdr_item_nxt, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    ti_len = proto_tree_add_item(exthdr_tree, hf_exthdr_item_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_uint(exthdr_tree, hf_exthdr_item_len_oct, tvb, offset, 1, len);
    proto_item_append_text(ti, " bytes");
    PROTO_ITEM_SET_GENERATED(ti);
    if (ipv6_exthdr_hide_len_oct_field) {
        PROTO_ITEM_SET_HIDDEN(ti);
        proto_item_append_text(ti_len, " (%d bytes)", len);
    }
    offset += 1;

    while (offset < offset_end) {
        /* there are more options */

        opt_type = tvb_get_guint8(tvb, offset);
        opt_len = tvb_get_guint8(tvb, offset + 1);

        pi = proto_tree_add_none_format(exthdr_tree, hf_ipv6_opt, tvb, offset, 2 + opt_len,
                    "%s", val_to_str_ext(opt_type, &ipv6_opt_type_vals_ext, "Unknown IPv6 Option (%u)"));
        opt_tree = proto_item_add_subtree(pi, ett_ipv6_opt);

        opt_ti.type = proto_tree_add_item(opt_tree, hf_ipv6_opt_type, tvb, offset, 1, ENC_BIG_ENDIAN);

        if (opt_type == IP6OPT_PAD1) {
            /* The Pad1 option is a special case, and contains no data. */
            proto_tree_add_item(opt_tree, hf_ipv6_opt_pad1, tvb, offset, 1, ENC_NA);
            offset += 1;
            continue;
        }

        opt_type_tree = proto_item_add_subtree(opt_ti.type, ett_ipv6_opt_type);
        proto_tree_add_item(opt_type_tree, hf_ipv6_opt_type_action, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(opt_type_tree, hf_ipv6_opt_type_change, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(opt_type_tree, hf_ipv6_opt_type_rest,   tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        opt_ti.len = proto_tree_add_item(opt_tree, hf_ipv6_opt_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        if (opt_type == IP6OPT_PADN) {
            /* RFC 2460 states :
             * "The PadN option is used to insert two or more octets of
             * padding into the Options area of a header.  For N octets of
             * padding, the Opt Data Len field contains the value N-2, and
             * the Option Data consists of N-2 zero-valued octets."
             */
            proto_tree_add_item(opt_tree, hf_ipv6_opt_padn, tvb, offset, opt_len, ENC_NA);
            offset += opt_len;
            continue;
        }

        opt_start = offset;
        switch (opt_type) {
        case IP6OPT_JUMBO:
            offset = dissect_opt_jumbo(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len, hopopts, ipv6_pinfo->ip6_plen);
            break;
        case IP6OPT_RPL:
            offset = dissect_opt_rpl(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
            break;
        case IP6OPT_TEL:
            offset = dissect_opt_tel(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
            break;
        case IP6OPT_RTALERT:
            offset = dissect_opt_rtalert(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
            break;
        case IP6OPT_QUICKSTART:
            offset = dissect_opt_quickstart(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len, iph->ip_ttl);
            break;
        case IP6OPT_CALIPSO:
            offset = dissect_opt_calipso(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
            break;
        case IP6OPT_SMF_DPD:
            /* TODO: Dissect SMF_DPD */
            offset = dissect_opt_unknown(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
            break;
        case IP6OPT_HOME_ADDRESS:
            offset = dissect_opt_home_address(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
            break;
        case IP6OPT_ILNP_NONCE:
            offset = dissect_opt_ilnp_nonce(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
            break;
        case IP6OPT_LIO:
            offset = dissect_opt_lio(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
            break;
        case IP6OPT_MPL:
            offset = dissect_opt_mpl(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
            break;
        case IP6OPT_IP_DFF:
            offset = dissect_opt_dff(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
            break;
        case IP6OPT_EXP_1E:
        case IP6OPT_EXP_3E:
        case IP6OPT_EXP_5E:
        case IP6OPT_EXP_7E:
        case IP6OPT_EXP_9E:
        case IP6OPT_EXP_BE:
        case IP6OPT_EXP_DE:
        case IP6OPT_EXP_FE:
            proto_tree_add_item(opt_tree, hf_ipv6_opt_experimental, tvb,
                                offset, opt_len, ENC_NA);
            offset += opt_len;
            break;
        default:
            offset = dissect_opt_unknown(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
            break;
        }
        if (offset < opt_start + opt_len) {
            ti = proto_tree_add_item(opt_tree, hf_ipv6_opt_unknown_data, tvb,
                                offset, opt_start + opt_len - offset, ENC_NA);
            expert_add_info(pinfo, ti, &ei_ipv6_opt_unknown_data);
            offset = opt_start + opt_len;
        }
    }

    return len;
}

static int
dissect_hopopts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, " , ", "IPv6 hop-by-hop options");

    return dissect_opts(tvb, 0, tree, pinfo, (ws_ip *)data, proto_ipv6_hopopts);
}

static int
dissect_dstopts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, " , ", "IPv6 destination options");

    return dissect_opts(tvb, 0, tree, pinfo, (ws_ip *)data, proto_ipv6_dstopts);
}

static gboolean
ipv6_check_jumbo_plen(tvbuff_t *tvb, gint offset, packet_info *pinfo)
{
    gint         offset_end, opt_type, opt_len;
    guint32      jumbo_plen;
    ipv6_pinfo_t *ipv6_pinfo;

    offset_end = offset + ((tvb_get_guint8(tvb, offset + 1) +1) * 8);
    offset +=2;

    while (offset < offset_end && tvb_bytes_exist(tvb, offset, 6)) {
        opt_type = tvb_get_guint8(tvb, offset);
        offset += 1;
        if (opt_type == IP6OPT_PAD1) {
            continue;
        }
        opt_len = tvb_get_guint8(tvb, offset);
        offset += 1;
        if (opt_type == IP6OPT_JUMBO && opt_len == 4) {
            jumbo_plen = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
            if (jumbo_plen > G_MAXUINT16) {
                ipv6_pinfo = p_get_ipv6_pinfo(pinfo);
                ipv6_pinfo->jumbo_plen = jumbo_plen;
                return TRUE;
            }
            return FALSE;
        }
        offset += opt_len;
    }
    return FALSE;
}

static int
dissect_ipv6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree    *ipv6_tree, *ipv6_exthdr_tree, *pt;
    proto_item    *ipv6_item, *ti, *pi;
    proto_item    *ti_ipv6_plen = NULL, *ti_ipv6_version;
    guint8         tfc;
    guint8         nxt_saved;
    int            advance;
    int            offset;
    guint          reported_plen;
    tvbuff_t      *next_tvb, *options_tvb;
    gboolean       save_fragmented;
    gboolean       show_data = FALSE, loop = TRUE;
    guint8        *mac_addr;
    const char    *name;
    dissector_handle_t nxt_handle;
    address        addr;
    ipv6_pinfo_t  *ipv6_pinfo;
    int version;

    /* Provide as much IP header information as possible as some dissectors
       in the ip.proto dissector table may need it */
    ws_ip iph;

    struct ws_ip6_hdr *ipv6;

    offset = 0;

    ipv6_pinfo = wmem_new0(wmem_packet_scope(), ipv6_pinfo_t);
    p_add_proto_data(pinfo->pool, pinfo, proto_ipv6, IPV6_PROTO_PINFO, ipv6_pinfo);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPv6");
    col_clear(pinfo->cinfo, COL_INFO);

    ipv6_item = proto_tree_add_item(tree, proto_ipv6, tvb, offset,
                    ipv6_exthdr_under_root ? IPv6_HDR_SIZE : -1, ENC_NA);
    ipv6_tree = proto_item_add_subtree(ipv6_item, ett_ipv6_proto);

    /* Validate IP version (6) */
    version = TVB_IPv6_HDR_VERS(tvb, offset + IP6H_CTL_VFC);
    ti_ipv6_version = proto_tree_add_item(ipv6_tree, hf_ipv6_version, tvb,
                                 offset + IP6H_CTL_VFC, 1, ENC_BIG_ENDIAN);
    pi = proto_tree_add_item(ipv6_tree, hf_ip_version, tvb,
                                 offset + IP6H_CTL_VFC, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(pi, " [This field makes the filter match on \"ip.version == 6\" possible]");
    PROTO_ITEM_SET_HIDDEN(pi);
    if (version != 6) {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                 "Bogus IPv6 version (%u, must be 6)", version);
        expert_add_info_format(pinfo, ti_ipv6_version, &ei_ipv6_bogus_ipv6_version, "Bogus IPv6 version");
        return offset + IP6H_CTL_VFC;
    }

    /* Validate header size (40 bytes) */
    if (tvb_reported_length(tvb) < IPv6_HDR_SIZE) {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                        "Invalid IPv6 header (%u bytes, need exactly 40)",
                        tvb_reported_length(tvb));
        expert_add_info_format(pinfo, ipv6_item, &ei_ipv6_invalid_header,
                        "IPv6 header must be exactly 40 bytes");
    }

    /* !!! warning: (4-bit) version, (6-bit) DSCP, (2-bit) ECN and (20-bit) Flow */
    ti = proto_tree_add_item(ipv6_tree, hf_ipv6_tclass, tvb,
                        offset + IP6H_CTL_FLOW, 4, ENC_BIG_ENDIAN);

    tfc = TVB_IPv6_HDR_TCLS(tvb, offset + IP6H_CTL_FLOW);
    proto_item_append_text(ti, " (DSCP: %s, ECN: %s)",
                        val_to_str_ext_const(IPDSFIELD_DSCP(tfc), &dscp_short_vals_ext, "Unknown"),
                        val_to_str_ext_const(IPDSFIELD_ECN(tfc), &ecn_short_vals_ext, "Unknown"));

    pt = proto_item_add_subtree(ti, ett_ipv6_traffic_class);
    proto_tree_add_item(pt, hf_ipv6_tclass_dscp, tvb,
                        offset + IP6H_CTL_FLOW, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_ipv6_tclass_ecn, tvb,
                        offset + IP6H_CTL_FLOW, 4, ENC_BIG_ENDIAN);

    /* Set DSCP column */
    col_add_str(pinfo->cinfo, COL_DSCP_VALUE,
                val_to_str_ext(IPDSFIELD_DSCP(tfc), &dscp_short_vals_ext, "%u"));

    proto_tree_add_item(ipv6_tree, hf_ipv6_flow, tvb,
                        offset + IP6H_CTL_FLOW, 4, ENC_BIG_ENDIAN);

    ti_ipv6_plen = proto_tree_add_item(ipv6_tree, hf_ipv6_plen, tvb,
                        offset + IP6H_CTL_PLEN, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(ipv6_tree, hf_ipv6_nxt, tvb, offset + IP6H_CTL_NXT, 1, ENC_NA);

    proto_tree_add_item(ipv6_tree, hf_ipv6_hlim, tvb,
                        offset + IP6H_CTL_HLIM, 1, ENC_BIG_ENDIAN);

    if (tree) {
        /* Add the different items for the source address */
        proto_tree_add_item(ipv6_tree, hf_ipv6_src, tvb,
                            offset + IP6H_SRC, IPv6_ADDR_SIZE, ENC_NA);
        ti = proto_tree_add_item(ipv6_tree, hf_ipv6_addr, tvb,
                            offset + IP6H_SRC, IPv6_ADDR_SIZE, ENC_NA);
        PROTO_ITEM_SET_HIDDEN(ti);

        set_address_tvb(&addr, AT_IPv6, IPv6_ADDR_SIZE, tvb, offset + IP6H_SRC);

        if (ipv6_summary_in_tree) {
            proto_item_append_text(ipv6_item, ", Src: %s", address_with_resolution_to_str(wmem_packet_scope(), &addr));
        }

        name = address_to_display(wmem_packet_scope(), &addr);
        ti = proto_tree_add_string(ipv6_tree, hf_ipv6_src_host, tvb,
                                   offset + IP6H_SRC, IPv6_ADDR_SIZE, name);
        PROTO_ITEM_SET_GENERATED(ti);
        PROTO_ITEM_SET_HIDDEN(ti);
        ti = proto_tree_add_string(ipv6_tree, hf_ipv6_host, tvb,
                                   offset + IP6H_SRC, IPv6_ADDR_SIZE, name);
        PROTO_ITEM_SET_GENERATED(ti);
        PROTO_ITEM_SET_HIDDEN(ti);

        /* Extract embedded (IPv6 and MAC) address information */
        if (tvb_get_ntohs(tvb, offset + IP6H_SRC) == 0x2002) { /* RFC 3056 section 2 */
            ti = proto_tree_add_item(ipv6_tree, hf_ipv6_src_6to4_gateway_ipv4, tvb,
                                     offset + IP6H_SRC + 2, 4, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_item(ipv6_tree, hf_ipv6_src_6to4_sla_id, tvb,
                                     offset + IP6H_SRC + 6, 2, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_item(ipv6_tree, hf_ipv6_6to4_gateway_ipv4, tvb,
                                     offset + IP6H_SRC + 2, 4, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(ti);
            PROTO_ITEM_SET_HIDDEN(ti);
            ti = proto_tree_add_item(ipv6_tree, hf_ipv6_6to4_sla_id, tvb,
                                     offset + IP6H_SRC + 6, 2, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(ti);
            PROTO_ITEM_SET_HIDDEN(ti);
        } else if (tvb_get_ntohl(tvb, offset + IP6H_SRC) == 0x20010000) { /* RFC 4380 section 4 */
            guint16 mapped_port = tvb_get_ntohs(tvb, offset + IP6H_SRC + 10) ^ 0xffff;
            guint32 client_v4 = tvb_get_ipv4(tvb, offset + IP6H_SRC + 12) ^ 0xffffffff;

            ti = proto_tree_add_item(ipv6_tree, hf_ipv6_src_teredo_server_ipv4, tvb,
                                     offset + IP6H_SRC + 4, 4, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_uint(ipv6_tree, hf_ipv6_src_teredo_port, tvb,
                                     offset + IP6H_SRC + 10, 2, mapped_port);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_ipv4(ipv6_tree, hf_ipv6_src_teredo_client_ipv4, tvb,
                                     offset + IP6H_SRC + 12, 4, client_v4);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_item(ipv6_tree, hf_ipv6_teredo_server_ipv4, tvb,
                                     offset + IP6H_SRC + 4, 4, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(ti);
            PROTO_ITEM_SET_HIDDEN(ti);
            ti = proto_tree_add_uint(ipv6_tree, hf_ipv6_teredo_port, tvb,
                                     offset + IP6H_SRC + 10, 2, mapped_port);
            PROTO_ITEM_SET_GENERATED(ti);
            PROTO_ITEM_SET_HIDDEN(ti);
            ti = proto_tree_add_ipv4(ipv6_tree, hf_ipv6_teredo_client_ipv4, tvb,
                                     offset + IP6H_SRC + 12, 4, client_v4);
            PROTO_ITEM_SET_GENERATED(ti);
            PROTO_ITEM_SET_HIDDEN(ti);
        }

        if (tvb_get_guint8(tvb, offset + IP6H_SRC + 8) & 0x02 && tvb_get_ntohs(tvb, offset + IP6H_SRC + 11) == 0xfffe) {  /* RFC 4291 appendix A */
            mac_addr = (guint8 *)wmem_alloc(wmem_packet_scope(), 6);
            tvb_memcpy(tvb, mac_addr, offset + IP6H_SRC + 8, 3);
            tvb_memcpy(tvb, mac_addr+3, offset+ IP6H_SRC + 13, 3);
            mac_addr[0] &= ~0x02;
            ti = proto_tree_add_ether(ipv6_tree, hf_ipv6_src_sa_mac, tvb,
                                      offset + IP6H_SRC + 8, 6, mac_addr);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_ether(ipv6_tree, hf_ipv6_sa_mac, tvb,
                                      offset + IP6H_SRC + 8, 6, mac_addr);
            PROTO_ITEM_SET_GENERATED(ti);
            PROTO_ITEM_SET_HIDDEN(ti);
        } else if ((tvb_get_ntohl(tvb, offset + IP6H_SRC + 8) & 0xfcffffff) == 0x00005efe) { /* RFC 5214 section 6.1 */
            ti = proto_tree_add_item(ipv6_tree, hf_ipv6_src_isatap_ipv4, tvb,
                                     offset + IP6H_SRC + 12, 4, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_item(ipv6_tree, hf_ipv6_isatap_ipv4, tvb,
                                     offset + IP6H_SRC + 12, 4, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(ti);
            PROTO_ITEM_SET_HIDDEN(ti);
        }

        /* Add different items for the destination address */
        proto_tree_add_item(ipv6_tree, hf_ipv6_dst, tvb,
                            offset + IP6H_DST, IPv6_ADDR_SIZE, ENC_NA);
        ti = proto_tree_add_item(ipv6_tree, hf_ipv6_addr, tvb,
                            offset + IP6H_DST, IPv6_ADDR_SIZE, ENC_NA);
        PROTO_ITEM_SET_HIDDEN(ti);

        set_address_tvb(&addr, AT_IPv6, IPv6_ADDR_SIZE, tvb, offset + IP6H_DST);

        if (ipv6_summary_in_tree) {
            proto_item_append_text(ipv6_item, ", Dst: %s", address_with_resolution_to_str(wmem_packet_scope(), &addr));
        }

        name = address_to_display(wmem_packet_scope(), &addr);
        ti = proto_tree_add_string(ipv6_tree, hf_ipv6_dst_host, tvb,
                                   offset + IP6H_DST, IPv6_ADDR_SIZE, name);
        PROTO_ITEM_SET_GENERATED(ti);
        PROTO_ITEM_SET_HIDDEN(ti);
        ti = proto_tree_add_string(ipv6_tree, hf_ipv6_host, tvb,
                                   offset + IP6H_DST, IPv6_ADDR_SIZE, name);
        PROTO_ITEM_SET_GENERATED(ti);
        PROTO_ITEM_SET_HIDDEN(ti);

        /* Extract embedded (IPv6 and MAC) address information */
        if (tvb_get_ntohs(tvb, offset + IP6H_DST) == 0x2002) { /* RFC 3056 section 2 */
            ti = proto_tree_add_item(ipv6_tree, hf_ipv6_dst_6to4_gateway_ipv4, tvb,
                                     offset + IP6H_DST + 2, 4, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_item(ipv6_tree, hf_ipv6_dst_6to4_sla_id, tvb,
                                     offset + IP6H_DST + 6, 2, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_item(ipv6_tree, hf_ipv6_6to4_gateway_ipv4, tvb,
                                     offset + IP6H_DST + 2, 4, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(ti);
            PROTO_ITEM_SET_HIDDEN(ti);
            ti = proto_tree_add_item(ipv6_tree, hf_ipv6_6to4_sla_id, tvb,
                                     offset + IP6H_DST + 6, 2, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(ti);
            PROTO_ITEM_SET_HIDDEN(ti);
        } else if (tvb_get_ntohl(tvb, offset + IP6H_DST) == 0x20010000) { /* RFC 4380 section 4 */
            guint16 mapped_port = tvb_get_ntohs(tvb, offset + IP6H_DST + 10) ^ 0xffff;
            guint32 client_v4 = tvb_get_ipv4(tvb, offset + IP6H_DST + 12) ^ 0xffffffff;

            ti = proto_tree_add_item(ipv6_tree, hf_ipv6_dst_teredo_server_ipv4, tvb,
                                     offset + IP6H_DST + 4, 4, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_uint(ipv6_tree, hf_ipv6_dst_teredo_port, tvb,
                                     offset + IP6H_DST + 10, 2, mapped_port);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_ipv4(ipv6_tree, hf_ipv6_dst_teredo_client_ipv4, tvb,
                                     offset + IP6H_DST + 12, 4, client_v4);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_item(ipv6_tree, hf_ipv6_teredo_server_ipv4, tvb,
                                     offset + IP6H_DST + 4, 4, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(ti);
            PROTO_ITEM_SET_HIDDEN(ti);
            ti = proto_tree_add_uint(ipv6_tree, hf_ipv6_teredo_port, tvb,
                                     offset + IP6H_DST + 10, 2, mapped_port);
            PROTO_ITEM_SET_GENERATED(ti);
            PROTO_ITEM_SET_HIDDEN(ti);
            ti = proto_tree_add_ipv4(ipv6_tree, hf_ipv6_teredo_client_ipv4, tvb,
                                     offset + IP6H_DST + 12, 4, client_v4);
            PROTO_ITEM_SET_GENERATED(ti);
            PROTO_ITEM_SET_HIDDEN(ti);
        }

        if (tvb_get_guint8(tvb, offset + IP6H_DST + 8) & 0x02 && tvb_get_ntohs(tvb, offset + IP6H_DST + 11) == 0xfffe) { /* RFC 4291 appendix A */
            mac_addr = (guint8 *)wmem_alloc(wmem_packet_scope(), 6);
            tvb_memcpy(tvb, mac_addr, offset + IP6H_DST + 8, 3);
            tvb_memcpy(tvb, mac_addr+3, offset+ IP6H_DST + 13, 3);
            mac_addr[0] &= ~0x02;
            ti = proto_tree_add_ether(ipv6_tree, hf_ipv6_dst_sa_mac, tvb,
                                      offset + IP6H_DST + 8, 6, mac_addr);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_ether(ipv6_tree, hf_ipv6_sa_mac, tvb,
                                      offset + IP6H_DST + 8, 6, mac_addr);
            PROTO_ITEM_SET_GENERATED(ti);
            PROTO_ITEM_SET_HIDDEN(ti);
        } else if ((tvb_get_ntohl(tvb, offset + IP6H_DST + 8) & 0xfcffffff) == 0x00005efe) { /* RFC 5214 section 6.1 */
            ti = proto_tree_add_item(ipv6_tree, hf_ipv6_dst_isatap_ipv4, tvb,
                                     offset + IP6H_DST + 12, 4, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_item(ipv6_tree, hf_ipv6_isatap_ipv4, tvb,
                                     offset + IP6H_DST + 12, 4, ENC_BIG_ENDIAN);
            PROTO_ITEM_SET_GENERATED(ti);
            PROTO_ITEM_SET_HIDDEN(ti);
        }
    }

    alloc_address_tvb(pinfo->pool, &pinfo->net_src, AT_IPv6, IPv6_ADDR_SIZE, tvb, offset + IP6H_SRC);
    copy_address_shallow(&pinfo->src, &pinfo->net_src);
    alloc_address_tvb(pinfo->pool, &pinfo->net_dst, AT_IPv6, IPv6_ADDR_SIZE, tvb, offset + IP6H_DST);
    copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

    /* We have an IPv6 header with valid length */
    ipv6 = (struct ws_ip6_hdr *)tvb_memdup(wmem_packet_scope(), tvb, offset, IPv6_HDR_SIZE);

#ifdef HAVE_GEOIP_V6
    if (tree && ipv6_use_geoip) {
        add_geoip_info(ipv6_tree, tvb, offset, &ipv6->ip6_src, &ipv6->ip6_dst);
    }
#endif

    /* Fill in IP fields for potential subdissectors */
    memset(&iph, 0, sizeof(iph));
    iph.ip_v_hl = IPv6_HDR_VERS(ipv6);
    iph.ip_tos  = IPv6_HDR_TCLS(ipv6);
    iph.ip_len  = g_ntohs(ipv6->ip6_plen);
    iph.ip_nxt  = ipv6->ip6_nxt;
    iph.ip_ttl  = ipv6->ip6_hlim;
    copy_address_shallow(&iph.ip_src, &pinfo->src);
    copy_address_shallow(&iph.ip_dst, &pinfo->dst);

    ipv6_pinfo->jumbo_plen = 0;
    ipv6_pinfo->ip6_plen = g_ntohs(ipv6->ip6_plen);

    if (ipv6_exthdr_under_root) {
        ipv6_exthdr_tree = tree;
    } else {
        ipv6_exthdr_tree = ipv6_tree;
    }

    /* Save next header value for Decode As dialog */
    p_add_proto_data(pinfo->pool, pinfo, proto_ipv6,
            (pinfo->curr_layer_num<<8) | IPV6_PROTO_NXT_HDR, GUINT_TO_POINTER((guint)iph.ip_nxt));
    offset += IPv6_HDR_SIZE;

    /* Check for Jumbo option */
    if (iph.ip_len == 0 && iph.ip_nxt == IP_PROTO_HOPOPTS) {
        if (ipv6_check_jumbo_plen(tvb, offset, pinfo)) {
            proto_item_append_text(ti_ipv6_plen, " (Jumbogram)");
            iph.ip_len = ipv6_pinfo->jumbo_plen;
        } else {
            /* IPv6 length zero is invalid if there is a hop-by-hop header without jumbo option */
            col_add_fstr(pinfo->cinfo, COL_INFO, "Invalid IPv6 payload length");
            expert_add_info(pinfo, ti_ipv6_plen, &ei_ipv6_opt_jumbo_missing);
        }
    }

    reported_plen = tvb_reported_length(tvb) - IPv6_HDR_SIZE;
    if (!pinfo->flags.in_error_pkt && iph.ip_len > reported_plen) {
        expert_add_info_format(pinfo, ti_ipv6_plen, &ei_ipv6_plen_exceeds_framing,
                    "IPv6 payload length exceeds framing length (%d bytes)", reported_plen);
    }

    /* Adjust the length of this tvbuff to include only the IPv6 datagram. */
    set_actual_length(tvb, iph.ip_len + IPv6_HDR_SIZE);
    save_fragmented = pinfo->fragmented;

    while (loop && !show_data) {
        advance = 0;
        options_tvb = tvb_new_subset_remaining(tvb, offset);
        nxt_handle = dissector_get_uint_handle(ipv6_next_header_dissector_table, iph.ip_nxt);
        if (nxt_handle != NULL) {
            advance = call_dissector_with_data(nxt_handle, options_tvb, pinfo, ipv6_exthdr_tree, &iph);
        }

        if (advance > 0) {
            nxt_saved = iph.ip_nxt;
            iph.ip_nxt = tvb_get_guint8(tvb, offset);
            offset += advance;
            iph.ip_len -= advance;
            if (nxt_saved == IP_PROTO_FRAGMENT) {
                if ((ipv6_pinfo->frag_off != 0) || ipv6_pinfo->frag_flg) {
                    show_data = ipv6_reassemble_do(&tvb, &offset, pinfo, ipv6_tree, iph.ip_len);
                }
            }
        } else if (iph.ip_nxt == IP_PROTO_NONE) {
            col_set_str(pinfo->cinfo, COL_INFO, "IPv6 no next header");
            show_data = TRUE;
        } else {
            loop = FALSE;
        }
    }

    if (!ipv6_exthdr_under_root) {
        proto_item_set_len (ipv6_item, offset);
    }

    /* collect packet info */
    p_add_proto_data(pinfo->pool, pinfo, proto_ipv6, (pinfo->curr_layer_num<<8) | IPV6_PROTO_VALUE, GUINT_TO_POINTER((guint)iph.ip_nxt));
    tap_queue_packet(ipv6_tap, pinfo, ipv6);

    /* Get a tvbuff for the payload. */
    next_tvb = tvb_new_subset_remaining(tvb, offset);

    if (show_data) {
        /* COL_INFO already set */
        call_data_dissector(next_tvb, pinfo, tree);
    }
    else {
        /* First fragment and not reassembling, not fragmented, or already reassembled. */
        /* Dissect what we have here. */
        if (!ip_try_dissect(try_heuristic_first, next_tvb, pinfo, tree, &iph)) {
            /* Unknown protocol. */
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s (%u)", ipprotostr(iph.ip_nxt), iph.ip_nxt);
            call_data_dissector(next_tvb, pinfo, tree);
        }
    }
    pinfo->fragmented = save_fragmented;
    return tvb_captured_length(tvb);
}

void
proto_register_ipv6(void)
{
    static hf_register_info hf_ipv6[] = {
        { &hf_ipv6_version,
            { "Version", "ipv6.version",
                FT_UINT8, BASE_DEC, NULL, 0xF0,
                NULL, HFILL }
        },
        { &hf_ip_version,
            { "Version", "ip.version",
                FT_UINT8, BASE_DEC, NULL, 0xF0,
                NULL, HFILL }
        },
        { &hf_ipv6_tclass,
            { "Traffic class", "ipv6.tclass",
                FT_UINT32, BASE_HEX, NULL, 0x0FF00000,
                NULL, HFILL }
        },
        { &hf_ipv6_tclass_dscp,
            { "Differentiated Services Codepoint", "ipv6.tclass.dscp",
                FT_UINT32, BASE_DEC | BASE_EXT_STRING, &dscp_vals_ext, 0x0FC00000,
                NULL, HFILL }
        },
        { &hf_ipv6_tclass_ecn,
            { "Explicit Congestion Notification", "ipv6.tclass.ecn",
                FT_UINT32, BASE_DEC | BASE_EXT_STRING, &ecn_vals_ext, 0x00300000,
                NULL, HFILL }
        },
        { &hf_ipv6_flow,
            { "Flow label", "ipv6.flow",
                FT_UINT32, BASE_HEX, NULL, 0x000FFFFF,
                NULL, HFILL }
        },
        { &hf_ipv6_plen,
            { "Payload length", "ipv6.plen",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_nxt,
            { "Next header", "ipv6.nxt",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_hlim,
            { "Hop limit", "ipv6.hlim",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_src,
            { "Source", "ipv6.src",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Source IPv6 Address", HFILL }
        },
        { &hf_ipv6_src_host,
            { "Source Host", "ipv6.src_host",
                FT_STRING, BASE_NONE, NULL, 0x0,
                "Source IPv6 Host", HFILL }
        },
        { &hf_ipv6_src_sa_mac,
            { "Source SA MAC", "ipv6.src_sa_mac",
                FT_ETHER, BASE_NONE, NULL, 0x0,
                "Source IPv6 Stateless Autoconfiguration MAC Address", HFILL }
        },
        { &hf_ipv6_src_isatap_ipv4,
            { "Source ISATAP IPv4", "ipv6.src_isatap_ipv4",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                "Source IPv6 ISATAP Encapsulated IPv4 Address", HFILL }
        },
        { &hf_ipv6_src_6to4_gateway_ipv4,
            { "Source 6to4 Gateway IPv4", "ipv6.src_6to4_gw_ipv4",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                "Source IPv6 6to4 Gateway IPv4 Address", HFILL }
        },
        { &hf_ipv6_src_6to4_sla_id,
            { "Source 6to4 SLA ID", "ipv6.src_6to4_sla_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Source IPv6 6to4 SLA ID", HFILL }
        },
        { &hf_ipv6_src_teredo_server_ipv4,
            { "Source Teredo Server IPv4", "ipv6.src_ts_ipv4",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                "Source IPv6 Teredo Server Encapsulated IPv4 Address", HFILL }
        },
        { &hf_ipv6_src_teredo_port,
            { "Source Teredo Port", "ipv6.src_tc_port",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Source IPv6 Teredo Client Mapped Port", HFILL }
        },
        { &hf_ipv6_src_teredo_client_ipv4,
            { "Source Teredo Client IPv4", "ipv6.src_tc_ipv4",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                "Source IPv6 Teredo Client Encapsulated IPv4 Address", HFILL }
        },
        { &hf_ipv6_dst,
            { "Destination", "ipv6.dst",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Destination IPv6 Address", HFILL }
        },
        { &hf_ipv6_dst_host,
            { "Destination Host", "ipv6.dst_host",
                FT_STRING, BASE_NONE, NULL, 0x0,
                "Destination IPv6 Host", HFILL }
        },
        { &hf_ipv6_dst_sa_mac,
            { "Destination SA MAC", "ipv6.dst_sa_mac",
                FT_ETHER, BASE_NONE, NULL, 0x0,
                "Destination IPv6 Stateless Autoconfiguration MAC Address", HFILL }
        },
        { &hf_ipv6_dst_isatap_ipv4,
            { "Destination ISATAP IPv4", "ipv6.dst_isatap_ipv4",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                "Destination IPv6 ISATAP Encapsulated IPv4 Address", HFILL }
        },
        { &hf_ipv6_dst_6to4_gateway_ipv4,
            { "Destination 6to4 Gateway IPv4", "ipv6.dst_6to4_gw_ipv4",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                "Destination IPv6 6to4 Gateway IPv4 Address", HFILL }
        },
        { &hf_ipv6_dst_6to4_sla_id,
            { "Destination 6to4 SLA ID", "ipv6.dst_6to4_sla_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Destination IPv6 6to4 SLA ID", HFILL }
        },
        { &hf_ipv6_dst_teredo_server_ipv4,
            { "Destination Teredo Server IPv4", "ipv6.dst_ts_ipv4",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                "Destination IPv6 Teredo Server Encapsulated IPv4 Address", HFILL }
        },
        { &hf_ipv6_dst_teredo_port,
            { "Destination Teredo Port", "ipv6.dst_tc_port",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Destination IPv6 Teredo Client Mapped Port", HFILL }
        },
        { &hf_ipv6_dst_teredo_client_ipv4,
            { "Destination Teredo Client IPv4", "ipv6.dst_tc_ipv4",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                "Destination IPv6 Teredo Client Encapsulated IPv4 Address", HFILL }
        },
        { &hf_ipv6_addr,
            { "Source or Destination Address", "ipv6.addr",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_host,
            { "Source or Destination Host", "ipv6.host",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_sa_mac,
            { "SA MAC", "ipv6.sa_mac",
                FT_ETHER, BASE_NONE, NULL, 0x0,
                "IPv6 Stateless Autoconfiguration MAC Address", HFILL }
        },
        { &hf_ipv6_isatap_ipv4,
            { "ISATAP IPv4", "ipv6.isatap_ipv4",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                "IPv6 ISATAP Encapsulated IPv4 Address", HFILL }
        },
        { &hf_ipv6_6to4_gateway_ipv4,
            { "6to4 Gateway IPv4", "ipv6.6to4_gw_ipv4",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                "IPv6 6to4 Gateway IPv4 Address", HFILL }
        },
        { &hf_ipv6_6to4_sla_id,
            { "6to4 SLA ID", "ipv6.6to4_sla_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "IPv6 6to4 SLA ID", HFILL }
        },
        { &hf_ipv6_teredo_server_ipv4,
            { "Teredo Server IPv4", "ipv6.ts_ipv4",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                "IPv6 Teredo Server Encapsulated IPv4 Address", HFILL }
        },
        { &hf_ipv6_teredo_port,
            { "Teredo Port", "ipv6.tc_port",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "IPv6 Teredo Client Mapped Port", HFILL }
        },
        { &hf_ipv6_teredo_client_ipv4,
            { "Teredo Client IPv4", "ipv6.tc_ipv4",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                "IPv6 Teredo Client Encapsulated IPv4 Address", HFILL }
        },

#ifdef HAVE_GEOIP_V6
        { &hf_geoip_country,
            { "Source or Destination GeoIP Country", "ipv6.geoip.country",
                FT_STRING, STR_UNICODE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_city,
            { "Source or Destination GeoIP City", "ipv6.geoip.city",
                FT_STRING, STR_UNICODE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_org,
            { "Source or Destination GeoIP Organization", "ipv6.geoip.org",
                FT_STRING, STR_UNICODE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_isp,
            { "Source or Destination GeoIP ISP", "ipv6.geoip.isp",
                FT_STRING, STR_UNICODE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_asnum,
            { "Source or Destination GeoIP AS Number", "ipv6.geoip.asnum",
                FT_STRING, STR_UNICODE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_lat,
            { "Source or Destination GeoIP Latitude", "ipv6.geoip.lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_lon,
            { "Source or Destination GeoIP Longitude", "ipv6.geoip.lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_src_country,
            { "Source GeoIP Country", "ipv6.geoip.src_country",
                FT_STRING, STR_UNICODE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_src_city,
            { "Source GeoIP City", "ipv6.geoip.src_city",
                FT_STRING, STR_UNICODE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_src_org,
            { "Source GeoIP Organization", "ipv6.geoip.src_org",
                FT_STRING, STR_UNICODE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_src_isp,
            { "Source GeoIP ISP", "ipv6.geoip.src_isp",
                FT_STRING, STR_UNICODE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_src_asnum,
            { "Source GeoIP AS Number", "ipv6.geoip.src_asnum",
                FT_STRING, STR_UNICODE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_src_lat,
            { "Source GeoIP Latitude", "ipv6.geoip.src_lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_src_lon,
            { "Source GeoIP Longitude", "ipv6.geoip.src_lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_dst_country,
            { "Destination GeoIP Country", "ipv6.geoip.dst_country",
                FT_STRING, STR_UNICODE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_dst_city,
            { "Destination GeoIP City", "ipv6.geoip.dst_city",
                FT_STRING, STR_UNICODE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_dst_org,
            { "Destination GeoIP Organization", "ipv6.geoip.dst_org",
                FT_STRING, STR_UNICODE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_dst_isp,
            { "Destination GeoIP ISP", "ipv6.geoip.dst_isp",
                FT_STRING, STR_UNICODE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_dst_asnum,
            { "Destination GeoIP AS Number", "ipv6.geoip.dst_asnum",
                FT_STRING, STR_UNICODE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_dst_lat,
            { "Destination GeoIP Latitude", "ipv6.geoip.dst_lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_dst_lon,
            { "Destination GeoIP Longitude", "ipv6.geoip.dst_lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
#endif /* HAVE_GEOIP_V6 */

        { &hf_ipv6_opt,
            { "IPv6 Option", "ipv6.opt",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Option", HFILL }
        },
        { &hf_ipv6_opt_type,
            { "Type", "ipv6.opt.type",
                FT_UINT8, BASE_HEX | BASE_EXT_STRING, &ipv6_opt_type_vals_ext, 0x0,
                "Option type", HFILL }
        },
        { &hf_ipv6_opt_type_action,
            { "Action", "ipv6.opt.type.action",
                FT_UINT8, BASE_DEC, VALS(ipv6_opt_type_action_vals), 0xC0,
                "Action for unrecognized option type", HFILL }
        },
        { &hf_ipv6_opt_type_change,
            { "May change", "ipv6.opt.type.change",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
                "Whether the option data may change en-route", HFILL }
        },
        { &hf_ipv6_opt_type_rest,
            { "Low-order bits", "ipv6.opt.type.rest",
                FT_UINT8, BASE_HEX, NULL, 0x1F,
                "Remaining low-order bits", HFILL }
        },
        { &hf_ipv6_opt_length,
            { "Length", "ipv6.opt.length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Option length in octets", HFILL }
        },
        { &hf_ipv6_opt_pad1,
            { "Pad1", "ipv6.opt.pad1",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Pad1 Option", HFILL }
        },
        { &hf_ipv6_opt_padn,
            { "PadN", "ipv6.opt.padn",
                FT_BYTES, BASE_NONE|BASE_ALLOW_ZERO, NULL, 0x0,
                "PadN Option", HFILL }
        },
        { &hf_ipv6_opt_rtalert,
            { "Router Alert", "ipv6.opt.router_alert",
                FT_UINT16, BASE_DEC, VALS(rtalertvals), 0x0,
                "Router Alert Option", HFILL }
        },
        { &hf_ipv6_opt_tel,
            { "Tunnel Encapsulation Limit", "ipv6.opt.tel",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "How many further levels of encapsulation are permitted", HFILL }
        },
        { &hf_ipv6_opt_jumbo,
            { "Payload Length", "ipv6.opt.jumbo",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "IPv6 (Jumbo) Payload Length", HFILL }
        },
        { &hf_ipv6_opt_calipso_doi,
            { "CALIPSO Domain of Interpretation", "ipv6.opt.calipso.doi",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_calipso_cmpt_length,
            { "Compartment Length", "ipv6.opt.calipso.cmpt.length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_calipso_sens_level,
            { "Sensitivity Level", "ipv6.opt.calipso.sens_level",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_calipso_checksum,
            { "Checksum", "ipv6.opt.calipso.checksum",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_calipso_cmpt_bitmap,
            { "Compartment Bitmap", "ipv6.opt.calipso.cmpt_bitmap",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_qs_func,
            { "Function", "ipv6.opt.qs_func",
                FT_UINT8, BASE_DEC, VALS(qs_func_vals), QS_FUNC_MASK,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_qs_rate,
            { "Rate", "ipv6.opt.qs_rate",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &qs_rate_vals_ext, QS_RATE_MASK,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_qs_ttl,
            { "QS TTL", "ipv6.opt.qs_ttl",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_qs_ttl_diff,
            { "TTL Diff", "ipv6.opt.qs_ttl_diff",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_qs_unused,
            { "Not Used", "ipv6.opt.qs_unused",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_qs_nonce,
            { "QS Nonce", "ipv6.opt.qs_nonce",
                FT_UINT32, BASE_HEX, NULL, 0xFFFFFFFC,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_qs_reserved,
            { "Reserved", "ipv6.opt.qs_reserved",
                FT_UINT32, BASE_HEX, NULL, 0x0003,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_mipv6_home_address,
            { "MIPv6 Home Address", "ipv6.opt.mipv6.home_address",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_rpl_flag,
            { "Flag", "ipv6.opt.rpl.flag",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_rpl_flag_o,
            { "Down", "ipv6.opt.rpl.flag.o",
                FT_BOOLEAN, 8, NULL, 0x80,
                "The packet is expected to progress Up or Down", HFILL }
        },
        { &hf_ipv6_opt_rpl_flag_r,
            { "Rank Error", "ipv6.opt.rpl.flag.r",
                FT_BOOLEAN, 8, NULL, 0x40,
                "Whether a rank error was detected", HFILL }
        },
        { &hf_ipv6_opt_rpl_flag_f,
            { "Forwarding Error", "ipv6.opt.rpl.flag.f",
                FT_BOOLEAN, 8, NULL, 0x20,
                "Set if the node cannot forward the packet further towards the destination", HFILL }
        },
        { &hf_ipv6_opt_rpl_flag_rsv,
            { "Reserved", "ipv6.opt.rpl.flag.rsv",
                FT_UINT8, BASE_HEX, NULL, 0x1F,
                "Reserved (must be zero)", HFILL }
        },
        { &hf_ipv6_opt_rpl_instance_id,
            { "RPLInstanceID", "ipv6.opt.rpl.instance_id",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "The DODAG instance along which the packet is sent", HFILL }
        },
        { &hf_ipv6_opt_rpl_senderrank,
            { "Sender Rank", "ipv6.opt.rpl.sender_rank",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                "Set to zero by the source and to DAGRank(rank) by a router that forwards inside the RPL network", HFILL }
        },
        { &hf_ipv6_opt_ilnp_nonce,
            { "ILNP Nonce", "ipv6.opt.ilnp_nonce",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_lio_len,
            { "LineIDLen", "ipv6.opt.lio.length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_lio_id,
            { "Line ID", "ipv6.opt.lio.line_id",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_mpl_flag,
            { "Flag", "ipv6.opt.mpl.flag",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_mpl_flag_s,
            { "Seed ID Length", "ipv6.opt.mpl.flag.s",
                FT_UINT8, BASE_DEC, NULL, 0xC0,
                "Identifies the length of Seed ID", HFILL }
        },
        { &hf_ipv6_opt_mpl_flag_m,
            { "Largest Sequence", "ipv6.opt.mpl.flag.m",
                FT_BOOLEAN, 8, NULL, 0x20,
                "Indicates Sequence is known to be the largest sequence number", HFILL }
        },
        { &hf_ipv6_opt_mpl_flag_v,
            { "Version", "ipv6.opt.mpl.flag.v",
                FT_BOOLEAN, 8, NULL, 0x10,
                "0 indicates this option conforms to RFC<TBC>", HFILL }
        },
        { &hf_ipv6_opt_mpl_flag_rsv,
            { "Reserved", "ipv6.opt.mpl.flag.rsv",
                FT_UINT8, BASE_HEX, NULL, 0x0F,
                "Reserved (must be zero)", HFILL }
        },
        { &hf_ipv6_opt_mpl_sequence,
            { "Sequence", "ipv6.opt.mpl.sequence",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "Identifies relative ordering of MPL Data Messages from the MPL Seed identified by Seed ID", HFILL }
        },
        { &hf_ipv6_opt_mpl_seed_id,
            { "Seed ID", "ipv6.opt.mpl.seed_id",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "Uniquely identifies the MPL Seed that initiated dissemination of the MPL Data Message", HFILL }
        },
        { &hf_ipv6_opt_dff_flags,
            { "Flags", "ipv6.opt.dff.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_dff_flag_ver,
            { "Version (VER)", "ipv6.opt.dff.flag.ver",
                FT_UINT8, BASE_DEC, NULL, 0xC0,
                "The version of DFF that is used", HFILL }
        },
        { &hf_ipv6_opt_dff_flag_dup,
            { "Duplicate (DUP)", "ipv6.opt.dff.flag.dup",
                FT_BOOLEAN, 8, NULL, 0x20,
                "Indicates the packet is being retransmitted", HFILL }
        },
        { &hf_ipv6_opt_dff_flag_ret,
            { "Return (RET)", "ipv6.opt.dff.flag.ret",
                FT_BOOLEAN, 8, NULL, 0x10,
                "Must be set to 1 prior to sending the packet back to the Previous Hop", HFILL }
        },
        { &hf_ipv6_opt_dff_flag_rsv,
            { "Reserved", "ipv6.opt.dff.flag.rsv",
                FT_UINT8, BASE_HEX, NULL, 0x0F,
                "Reserved (must be zero)", HFILL }
        },
        { &hf_ipv6_opt_dff_seqnum,
            { "Sequence Number", "ipv6.opt.dff.sequence_number",
                FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_experimental,
            { "Experimental Option", "ipv6.opt.experimental",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_unknown_data,
            { "Unknown Data", "ipv6.opt_unknown_data",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "Not interpreted data", HFILL }
        },
        { &hf_ipv6_opt_unknown,
            { "Unknown Option Payload", "ipv6.opt.unknown",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_fragment,
            { "IPv6 Fragment", "ipv6.fragment",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_fragment_overlap,
            { "Fragment overlap", "ipv6.fragment.overlap",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment overlaps with other fragments", HFILL }
        },
        { &hf_ipv6_fragment_overlap_conflict,
            { "Conflicting data in fragment overlap", "ipv6.fragment.overlap.conflict",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Overlapping fragments contained conflicting data", HFILL }
        },
        { &hf_ipv6_fragment_multiple_tails,
            { "Multiple tail fragments found", "ipv6.fragment.multipletails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Several tails were found when defragmenting the packet", HFILL }
        },
        { &hf_ipv6_fragment_too_long_fragment,
            { "Fragment too long", "ipv6.fragment.toolongfragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment contained data past end of packet", HFILL }
        },
        { &hf_ipv6_fragment_error,
            { "Defragmentation error", "ipv6.fragment.error",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "Defragmentation error due to illegal fragments", HFILL }
        },
        { &hf_ipv6_fragment_count,
            { "Fragment count", "ipv6.fragment.count",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_fragments,
            { "IPv6 Fragments", "ipv6.fragments",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_reassembled_in,
            { "Reassembled IPv6 in frame", "ipv6.reassembled.in",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "This IPv6 packet is reassembled in this frame", HFILL }
        },
        { &hf_ipv6_reassembled_length,
            { "Reassembled IPv6 length", "ipv6.reassembled.length",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "The total length of the reassembled payload", HFILL }
        },
        { &hf_ipv6_reassembled_data,
            { "Reassembled IPv6 data", "ipv6.reassembled.data",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "The reassembled payload", HFILL }
        }
    };

    static hf_register_info hf_ipv6_hopopts[] = {
        { &hf_ipv6_hopopts_nxt,
            { "Next Header", "ipv6.hopopts.nxt",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_hopopts_len,
            { "Length", "ipv6.hopopts.len",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Extension header length in 8-octet words (minus 1)", HFILL }
        },
        { &hf_ipv6_hopopts_len_oct,
            { "Length", "ipv6.hopopts.len_oct",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Extension header length in octets", HFILL }
        }
    };

    static hf_register_info hf_ipv6_dstopts[] = {
        { &hf_ipv6_dstopts_nxt,
            { "Next Header", "ipv6.dstopts.nxt",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_dstopts_len,
            { "Length", "ipv6.dstopts.len",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Extension header length in 8-octet words (minus 1)", HFILL }
        },
        { &hf_ipv6_dstopts_len_oct,
            { "Length", "ipv6.dstopts.len_oct",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Extension header length in octets", HFILL }
        }
    };

    static hf_register_info hf_ipv6_routing[] = {

        /* IPv6 Routing Header */
        { &hf_ipv6_routing_nxt,
            { "Next Header", "ipv6.routing.nxt",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_routing_len,
            { "Length", "ipv6.routing.len",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Extension header length in 8-octet words (minus 1)", HFILL }
        },
        { &hf_ipv6_routing_len_oct,
            { "Length", "ipv6.routing.len_oct",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Extension header length in octets", HFILL }
        },
        { &hf_ipv6_routing_type,
            { "Type", "ipv6.routing.type",
                FT_UINT8, BASE_DEC, VALS(routing_header_type), 0x0,
                "Routing Header Type", HFILL }
        },
        { &hf_ipv6_routing_segleft,
            { "Segments Left", "ipv6.routing.segleft",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Routing Header Segments Left", HFILL }
        },

        /* Source Routing Header */
        { &hf_ipv6_routing_src_reserved,
            { "Reserved", "ipv6.routing.src.reserved",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "Must be zero", HFILL }
        },
        { &hf_ipv6_routing_src_addr,
            { "Address", "ipv6.routing.src.addr",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Source Routing Header Address", HFILL }},

        /* Mobile IPv6 */
        { &hf_ipv6_routing_mipv6_reserved,
            { "Reserved", "ipv6.routing.mipv6.reserved",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "Must be zero", HFILL }
        },
        { &hf_ipv6_routing_mipv6_home_address,
            { "Home Address", "ipv6.routing.mipv6.home_address",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },

        /* RPL Routing Header */
        { &hf_ipv6_routing_rpl_cmprI,
            { "Compressed Internal Octets (CmprI)", "ipv6.routing.rpl.cmprI",
                FT_UINT32, BASE_DEC, NULL, IP6RRPL_BITMASK_CMPRI,
                "Elided octets from all but last segment", HFILL }
        },
        { &hf_ipv6_routing_rpl_cmprE,
            { "Compressed Final Octets (CmprE)", "ipv6.routing.rpl.cmprE",
                FT_UINT32, BASE_DEC, NULL, IP6RRPL_BITMASK_CMPRE,
                "Elided octets from last segment address", HFILL }
        },
        { &hf_ipv6_routing_rpl_pad,
            { "Padding Bytes", "ipv6.routing.rpl.pad",
                FT_UINT32, BASE_DEC, NULL, IP6RRPL_BITMASK_PAD,
                NULL, HFILL }
        },
        { &hf_ipv6_routing_rpl_reserved,
            { "Reserved", "ipv6.routing.rpl.reserved",
                FT_UINT32, BASE_DEC, NULL, IP6RRPL_BITMASK_RESERVED,
                "Must be zero", HFILL }
        },
        { &hf_ipv6_routing_rpl_addr_count,
            { "Total Address Count", "ipv6.routing.rpl.addr_count",
                FT_INT32, BASE_DEC, NULL, 0,
                NULL, HFILL }
        },
        { &hf_ipv6_routing_rpl_addr,
            { "Address", "ipv6.routing.rpl.address",
                FT_BYTES, BASE_NONE, NULL, 0,
                NULL, HFILL }
        },
        { &hf_ipv6_routing_rpl_fulladdr,
            { "Full Address", "ipv6.routing.rpl.full_address",
                FT_IPv6, BASE_NONE, NULL, 0,
                "Uncompressed IPv6 Address", HFILL }
        },

        /* Segment Routing Header */
        { &hf_ipv6_routing_srh_first_seg,
            { "First segment", "ipv6.routing.srh.first_segment",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Index of the first segment", HFILL }
        },
        { &hf_ipv6_routing_srh_flags,
            { "Flags", "ipv6.routing.srh.flags",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_routing_srh_flag_c,
            { "Cleanup", "ipv6.routing.srh.flag_c",
                FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x8000,
                NULL, HFILL }
        },
        { &hf_ipv6_routing_srh_flag_p,
            { "Protected", "ipv6.routing.srh.flag_p",
                FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x4000,
                NULL, HFILL }
        },
        { &hf_ipv6_routing_srh_flag_o,
            { "OAM", "ipv6.routing.srh.flag_o",
                FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x2000,
                NULL, HFILL }
        },
        { &hf_ipv6_routing_srh_flag_a,
            { "Alert", "ipv6.routing.srh.flag_a",
                FT_BOOLEAN, 16, TFS(&tfs_present_not_present), 0x1000,
                NULL, HFILL }
        },
        { &hf_ipv6_routing_srh_flag_h,
            { "HMAC", "ipv6.routing.srh.flag_h",
                FT_BOOLEAN, 16, TFS(&tfs_present_not_present), 0x0800,
                NULL, HFILL }
        },
        { &hf_ipv6_routing_srh_flag_unused,
            { "Unused", "ipv6.routing.srh.flag_unused",
                FT_UINT16, BASE_HEX, NULL, 0x07FF,
                NULL, HFILL }
        },
        { &hf_ipv6_routing_srh_reserved,
            { "Reserved", "ipv6.routing.srh.reserved",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "Must be zero", HFILL }
        },
        { &hf_ipv6_routing_srh_addr,
            { "Address", "ipv6.routing.srh.addr",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Segment address", HFILL }
        }
    };

    static hf_register_info hf_ipv6_fraghdr[] = {
        { &hf_ipv6_fraghdr_nxt,
            { "Next header", "ipv6.fraghdr.nxt",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_fraghdr_reserved_octet,
            { "Reserved octet", "ipv6.fraghdr.reserved_octet",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "Should always be 0", HFILL }
        },
        { &hf_ipv6_fraghdr_offset,
            { "Offset", "ipv6.fraghdr.offset",
                FT_UINT16, BASE_DEC, NULL, IP6F_OFF_MASK,
                "Fragment Offset", HFILL }
        },
        { &hf_ipv6_fraghdr_reserved_bits,
            { "Reserved bits", "ipv6.fraghdr.reserved_bits",
                FT_UINT16, BASE_DEC, NULL, IP6F_RESERVED_MASK,
                NULL, HFILL }
        },
        { &hf_ipv6_fraghdr_more,
            { "More Fragments", "ipv6.fraghdr.more",
                FT_BOOLEAN, 16, TFS(&tfs_yes_no), IP6F_MORE_FRAG,
                NULL, HFILL }
        },
        { &hf_ipv6_fraghdr_ident,
            { "Identification", "ipv6.fraghdr.ident",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                "Fragment Identification", HFILL }
        }
    };

    static gint *ett_ipv6[] = {
        &ett_ipv6_proto,
        &ett_ipv6_traffic_class,
#ifdef HAVE_GEOIP_V6
        &ett_geoip_info,
#endif /* HAVE_GEOIP_V6 */
        &ett_ipv6_opt,
        &ett_ipv6_opt_type,
        &ett_ipv6_opt_rpl,
        &ett_ipv6_opt_mpl,
        &ett_ipv6_opt_dff_flags,
        &ett_ipv6_fragment,
        &ett_ipv6_fragments
    };

    static gint *ett_ipv6_hopopts[] = {
        &ett_ipv6_hopopts_proto
    };

    static gint *ett_ipv6_routing[] = {
        &ett_ipv6_routing_proto,
        &ett_ipv6_routing_srh_flags,
        &ett_ipv6_routing_srh_vect
    };

    static gint *ett_ipv6_fraghdr[] = {
        &ett_ipv6_fraghdr_proto
    };

    static gint *ett_ipv6_dstopts[] = {
        &ett_ipv6_dstopts_proto
    };

    static ei_register_info ei_ipv6[] = {
        { &ei_ipv6_opt_jumbo_missing,
            { "ipv6.opt.jumbo.missing", PI_PROTOCOL, PI_ERROR,
                "IPv6 payload length equals 0 and Hop-By-Hop present and Jumbo Payload option missing", EXPFILL }
        },
        { &ei_ipv6_opt_jumbo_prohibited,
            { "ipv6.opt.jumbo.prohibited", PI_PROTOCOL, PI_ERROR,
                "When IPv6 payload length does not equal 0 a Jumbo Payload option must not be present", EXPFILL }
        },
        { &ei_ipv6_opt_jumbo_truncated,
            { "ipv6.opt.jumbo.truncated", PI_PROTOCOL, PI_ERROR,
                "Jumbo Payload option present and jumbo length < 65536", EXPFILL }
        },
        { &ei_ipv6_opt_jumbo_fragment,
            { "ipv6.opt.jumbo.fragment", PI_PROTOCOL, PI_ERROR,
                "Jumbo Payload option cannot be used with a fragment header", EXPFILL }
        },
        { &ei_ipv6_opt_jumbo_not_hopbyhop,
            { "ipv6.opt.jumbo.not_hopbyhop", PI_PROTOCOL, PI_ERROR,
                "Jumbo Payload option must be a hop-by-hop option", EXPFILL }
        },
        { &ei_ipv6_opt_invalid_len,
            { "ipv6.opt.invalid_len", PI_MALFORMED, PI_ERROR,
                "Invalid IPv6 option length", EXPFILL }
        },
        { &ei_ipv6_opt_unknown_data,
            { "ipv6.opt.unknown_data.expert", PI_UNDECODED, PI_NOTE,
                "Unknown Data (not interpreted)", EXPFILL }
        },
        { &ei_ipv6_plen_exceeds_framing,
            { "ipv6.plen_exceeds_framing", PI_PROTOCOL, PI_WARN,
                "IPv6 payload length does not match expected framing length", EXPFILL }
        },
        { &ei_ipv6_bogus_ipv6_version,
            { "ipv6.bogus_ipv6_version", PI_PROTOCOL, PI_ERROR,
                "Bogus IP version", EXPFILL }
            },
        { &ei_ipv6_invalid_header,
            { "ipv6.invalid_header", PI_MALFORMED, PI_ERROR,
                "Invalid IPv6 header", EXPFILL }
        }
    };

    static ei_register_info ei_ipv6_hopopts[] = {
        { &ei_ipv6_hopopts_not_first,
            { "ipv6.hopopts.not_first", PI_PROTOCOL, PI_ERROR,
                "IPv6 Hop-by-Hop extension header must appear immediately after IPv6 header", EXPFILL }
        }
    };

    static ei_register_info ei_ipv6_routing[] = {
        { &ei_ipv6_dst_addr_not_multicast,
            { "ipv6.dst_addr.not_multicast", PI_PROTOCOL, PI_WARN,
                "Destination address must not be a multicast address", EXPFILL }
        },
        { &ei_ipv6_src_route_list_mult_inst_same_addr,
            { "ipv6.src_route_list.mult_inst_same_addr", PI_PROTOCOL, PI_ERROR,
                "Multiple instances of the same address must not appear in the source route list", EXPFILL }
        },
        { &ei_ipv6_src_route_list_src_addr,
            { "ipv6.src_route_list.src_addr", PI_PROTOCOL, PI_ERROR,
                "Source address must not appear in the source route list", EXPFILL }
        },
        { &ei_ipv6_src_route_list_dst_addr,
            { "ipv6.src_route_list.dst_addr", PI_PROTOCOL, PI_ERROR,
                "Destination address must not appear in the source route list", EXPFILL }
        },
        { &ei_ipv6_src_route_list_multicast_addr,
            { "ipv6.src_route_list.multicast_addr", PI_PROTOCOL, PI_ERROR,
                "Multicast addresses must not appear in the source route list", EXPFILL }
        },
        { &ei_ipv6_routing_rpl_cmpri_cmpre_pad,
            { "ipv6.routing.rpl.cmprI_cmprE_pad", PI_PROTOCOL, PI_WARN,
                "When cmprI equals 0 and cmprE equals 0, pad MUST equal 0 but instead was X", EXPFILL }
        },
        { &ei_ipv6_routing_rpl_addr_count_ge0,
            { "ipv6.routing.rpl.addr_count_ge0", PI_MALFORMED, PI_ERROR,
                "Calculated total address count must be greater than or equal to 0, instead was X", EXPFILL }
        },
        { &ei_ipv6_routing_rpl_reserved,
            { "ipv6.routing.rpl.reserved_not0", PI_PROTOCOL, PI_WARN,
                "Reserved field must equal 0 but instead was X", EXPFILL }
        },
        { &ei_ipv6_routing_invalid_length,
            { "ipv6.routing.invalid_length", PI_MALFORMED, PI_ERROR,
                "Invalid IPv6 Routing header length", EXPFILL }
            },
        { &ei_ipv6_routing_invalid_segleft,
            { "ipv6.routing.invalid_segleft", PI_PROTOCOL, PI_ERROR,
                "IPv6 Routing Header segments left field must not exceed address count", EXPFILL }
        },
        { &ei_ipv6_routing_not_implemented,
            { "ipv6.routing.not_implemented", PI_UNDECODED, PI_NOTE,
                "Undecoded IPv6 routing header field", EXPFILL }
        }
    };

    /* Decode As handling */
    static build_valid_func ipv6_da_build_value[1] = {ipv6_value};
    static decode_as_value_t ipv6_da_values = {ipv6_prompt, 1, ipv6_da_build_value};
    static decode_as_t ipv6_da = {"ipv6", "Network", "ip.proto", 1, 0, &ipv6_da_values, NULL, NULL,
                                  decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    static build_valid_func ipv6_next_header_da_build_value[1] = {ipv6_next_header_value};
    static decode_as_value_t ipv6_next_header_da_values = {ipv6_next_header_prompt, 1, ipv6_next_header_da_build_value};
    static decode_as_t ipv6_next_header_da = {"ipv6", "IPv6 Next Header", "ipv6.nxt", 1, 0, &ipv6_next_header_da_values, NULL, NULL,
                                  decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    module_t *ipv6_module;
    expert_module_t* expert_ipv6;
    expert_module_t* expert_ipv6_hopopts;
    expert_module_t* expert_ipv6_routing;

    proto_ipv6 = proto_register_protocol("Internet Protocol Version 6", "IPv6", "ipv6");
    proto_register_field_array(proto_ipv6, hf_ipv6, array_length(hf_ipv6));
    proto_register_subtree_array(ett_ipv6, array_length(ett_ipv6));
    expert_ipv6 = expert_register_protocol(proto_ipv6);
    expert_register_field_array(expert_ipv6, ei_ipv6, array_length(ei_ipv6));

    proto_ipv6_hopopts = proto_register_protocol("IPv6 Hop-by-Hop Option", "IPv6 Hop-by-Hop", "ipv6.hopopts");
    proto_register_field_array(proto_ipv6_hopopts, hf_ipv6_hopopts, array_length(hf_ipv6_hopopts));
    proto_register_subtree_array(ett_ipv6_hopopts, array_length(ett_ipv6_hopopts));
    expert_ipv6_hopopts = expert_register_protocol(proto_ipv6_hopopts);
    expert_register_field_array(expert_ipv6_hopopts, ei_ipv6_hopopts, array_length(ei_ipv6_hopopts));

    proto_ipv6_routing = proto_register_protocol("Routing Header for IPv6", "IPv6 Routing", "ipv6.routing");
    proto_register_field_array(proto_ipv6_routing, hf_ipv6_routing, array_length(hf_ipv6_routing));
    proto_register_subtree_array(ett_ipv6_routing, array_length(ett_ipv6_routing));
    expert_ipv6_routing = expert_register_protocol(proto_ipv6_routing);
    expert_register_field_array(expert_ipv6_routing, ei_ipv6_routing, array_length(ei_ipv6_routing));

    proto_ipv6_fraghdr = proto_register_protocol("Fragment Header for IPv6", "IPv6 Fragment", "ipv6.fraghdr");
    proto_register_field_array(proto_ipv6_fraghdr, hf_ipv6_fraghdr, array_length(hf_ipv6_fraghdr));
    proto_register_subtree_array(ett_ipv6_fraghdr, array_length(ett_ipv6_fraghdr));

    proto_ipv6_dstopts = proto_register_protocol("Destination Options for IPv6", "IPv6 Destination", "ipv6.dstopts");
    proto_register_field_array(proto_ipv6_dstopts, hf_ipv6_dstopts, array_length(hf_ipv6_dstopts));
    proto_register_subtree_array(ett_ipv6_dstopts, array_length(ett_ipv6_dstopts));

    ipv6_next_header_dissector_table = register_dissector_table("ipv6.nxt", "IPv6 Next Header", proto_ipv6, FT_UINT32, BASE_DEC);
    register_capture_dissector_table("ipv6.nxt", "IPv6 Next Header");

    /* Register configuration options */
    ipv6_module = prefs_register_protocol(proto_ipv6, NULL);
    prefs_register_bool_preference(ipv6_module, "defragment",
                                   "Reassemble fragmented IPv6 datagrams",
                                   "Whether fragmented IPv6 datagrams should be reassembled",
                                   &ipv6_reassemble);
    prefs_register_bool_preference(ipv6_module, "summary_in_tree",
                                   "Show IPv6 summary in protocol tree",
                                   "Whether the IPv6 summary line should be shown in the protocol tree",
                                   &ipv6_summary_in_tree);
#ifdef HAVE_GEOIP_V6
    prefs_register_bool_preference(ipv6_module, "use_geoip" ,
                                   "Enable GeoIP lookups",
                                   "Whether to look up IPv6 addresses in each GeoIP database we have loaded",
                                   &ipv6_use_geoip);
#endif /* HAVE_GEOIP_V6 */

    /* RPL Strict Header Checking */
    prefs_register_bool_preference(ipv6_module, "perform_strict_rpl_srh_rfc_checking",
                                   "Perform strict checking for adherence to the RFC for RPL Source Routing Headers (RFC 6554)",
                                   "Whether to check that all RPL Source Routed packets do not visit a node more than once",
                                   &g_ipv6_rpl_srh_strict_rfc_checking);

    prefs_register_bool_preference(ipv6_module, "try_heuristic_first",
                                   "Try heuristic sub-dissectors first",
                                   "Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to a specific port",
                                   &try_heuristic_first);

    prefs_register_bool_preference(ipv6_module, "exthdr_under_root_protocol_tree",
                                   "Display IPv6 extension headers under the root protocol tree",
                                   "Whether to display IPv6 extension headers as a separate protocol or a sub-protocol of the IPv6 packet",
                                   &ipv6_exthdr_under_root);

    prefs_register_bool_preference(ipv6_module, "exthdr_hide_len_oct_field",
                                   "Use a single field for IPv6 extension header length",
                                   "If enabled the Length field in octets will be hidden",
                                   &ipv6_exthdr_hide_len_oct_field);

    register_dissector("ipv6", dissect_ipv6, proto_ipv6);
    register_init_routine(ipv6_reassemble_init);
    register_cleanup_routine(ipv6_reassemble_cleanup);
    ipv6_tap = register_tap("ipv6");

    register_decode_as(&ipv6_da);
    register_decode_as(&ipv6_next_header_da);

    register_conversation_table(proto_ipv6, TRUE, ipv6_conversation_packet, ipv6_hostlist_packet);
    register_conversation_filter("ipv6", "IPv6", ipv6_filter_valid, ipv6_build_filter);
}

void
proto_reg_handoff_ipv6(void)
{
    dissector_handle_t ipv6_handle;
    dissector_handle_t ipv6_hopopts_handle;
    dissector_handle_t ipv6_routing_handle;
    dissector_handle_t ipv6_fraghdr_handle;
    dissector_handle_t ipv6_dstopts_handle;

    ipv6_handle = find_dissector("ipv6");
    dissector_add_uint("ethertype", ETHERTYPE_IPv6, ipv6_handle);
    dissector_add_uint("erf.types.type", ERF_TYPE_IPV6, ipv6_handle);
    dissector_add_uint("ppp.protocol", PPP_IPV6, ipv6_handle);
    dissector_add_uint("ppp.protocol", ETHERTYPE_IPv6, ipv6_handle);
    dissector_add_uint("gre.proto", ETHERTYPE_IPv6, ipv6_handle);
    dissector_add_uint("ip.proto", IP_PROTO_IPV6, ipv6_handle);
    dissector_add_uint("null.type", BSD_AF_INET6_BSD, ipv6_handle);
    dissector_add_uint("null.type", BSD_AF_INET6_FREEBSD, ipv6_handle);
    dissector_add_uint("null.type", BSD_AF_INET6_DARWIN, ipv6_handle);
    dissector_add_uint("chdlc.protocol", ETHERTYPE_IPv6, ipv6_handle);
    dissector_add_uint("fr.nlpid", NLPID_IP6, ipv6_handle);
    dissector_add_uint("osinl.excl", NLPID_IP6, ipv6_handle);
    dissector_add_uint("x.25.spi", NLPID_IP6, ipv6_handle);
    dissector_add_uint("arcnet.protocol_id", ARCNET_PROTO_IPv6, ipv6_handle);
    dissector_add_uint("juniper.proto", JUNIPER_PROTO_IP6, ipv6_handle);
    dissector_add_uint("juniper.proto", JUNIPER_PROTO_MPLS_IP6, ipv6_handle);
    dissector_add_uint("pwach.channel_type", 0x57, ipv6_handle); /* IPv6, RFC4385 clause 6. */
    dissector_add_uint("sflow_245.header_protocol", SFLOW_245_HEADER_IPv6, ipv6_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_RAW_IP6, ipv6_handle);
    dissector_add_uint("enc", BSD_AF_INET6_BSD, ipv6_handle);
    dissector_add_uint("vxlan.next_proto", VXLAN_IPV6, ipv6_handle);

    dissector_add_for_decode_as("udp.port", ipv6_handle);

    ipv6_hopopts_handle = create_dissector_handle(dissect_hopopts, proto_ipv6_hopopts);
    dissector_add_uint("ipv6.nxt", IP_PROTO_HOPOPTS, ipv6_hopopts_handle);

    ipv6_routing_handle = create_dissector_handle(dissect_routing6, proto_ipv6_routing);
    dissector_add_uint("ipv6.nxt", IP_PROTO_ROUTING, ipv6_routing_handle);

    ipv6_fraghdr_handle = create_dissector_handle(dissect_fraghdr, proto_ipv6_fraghdr);
    dissector_add_uint("ipv6.nxt", IP_PROTO_FRAGMENT, ipv6_fraghdr_handle);

    ipv6_dstopts_handle = create_dissector_handle(dissect_dstopts, proto_ipv6_dstopts);
    dissector_add_uint("ipv6.nxt", IP_PROTO_DSTOPTS, ipv6_dstopts_handle);

    ip_dissector_table = find_dissector_table("ip.proto");
    register_capture_dissector("ethertype", ETHERTYPE_IPv6, capture_ipv6, proto_ipv6);
    register_capture_dissector("enc", BSD_AF_INET6_BSD, capture_ipv6, proto_ipv6);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
