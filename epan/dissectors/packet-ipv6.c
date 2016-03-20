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
#include <epan/in_cksum.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>

#include <wiretap/erf.h>
#include <wsutil/str_util.h>
#include "packet-ipv6.h"
#include "packet-ip.h"
#include "packet-juniper.h"
#include "packet-sflow.h"

#ifdef HAVE_GEOIP_V6
#include <GeoIP.h>
#include <epan/geoip_db.h>
#endif /* HAVE_GEOIP_V6 */

void proto_register_ipv6(void);
void proto_reg_handoff_ipv6(void);

#define IPv6_HDR_SIZE   40
#define IPv6_ADDR_SIZE  16

#define IPv6_HDR_TCLS(ipv6)     ((guint8)(g_ntohl((ipv6)->ip6_flow) >> 20))

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
#define IP6OPT_ENDI                     0x8A    /* 10 0 01010 = 138 */
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

/* SHIM6 control message types */
#define SHIM6_TYPE_I1           0x01    /* 0 000 0001 */
#define SHIM6_TYPE_R1           0x02    /* 0 000 0010 */
#define SHIM6_TYPE_I2           0x03    /* 0 000 0011 */
#define SHIM6_TYPE_R2           0x04    /* 0 000 0100 */
#define SHIM6_TYPE_R1BIS        0x05    /* 0 000 0101 */
#define SHIM6_TYPE_I2BIS        0x06    /* 0 000 0110 */
#define SHIM6_TYPE_UPD_REQ      0x40    /* 0 100 0000 = 64 */
#define SHIM6_TYPE_UPD_ACK      0x41    /* 0 100 0001 = 65 */
#define SHIM6_TYPE_KEEPALIVE    0x42    /* 0 100 0010 = 66 */
#define SHIM6_TYPE_PROBE        0x43    /* 0 100 0011 = 67 */

/* SHIM6 Options */
#define SHIM6_OPT_RESPVAL       0x01    /* 0 000 0001 */
#define SHIM6_OPT_LOCLIST       0x02    /* 0 000 0010 */
#define SHIM6_OPT_LOCPREF       0x03    /* 0 000 0011 */
#define SHIM6_OPT_CGAPDM        0x04    /* 0 000 0100 */
#define SHIM6_OPT_CGASIG        0x05    /* 0 000 0101 */
#define SHIM6_OPT_ULIDPAIR      0x06    /* 0 000 0110 */
#define SHIM6_OPT_FII           0x07    /* 0 000 0111 */

/* SHIM6 Bitmasks */
#define SHIM6_BITMASK_P         0x80    /* 1 000 0000 */
#define SHIM6_BITMASK_TYPE      0x7F    /* 0 111 1111 */
#define SHIM6_BITMASK_PROTOCOL  0x01    /* 0 000 0001 */
#define SHIM6_BITMASK_SPECIFIC  0xFE    /* 1 111 1110 */
#define SHIM6_BITMASK_R         0x80    /* 1 000 0000 */
#define SHIM6_BITMASK_CT        0x7F    /* 0 111 1111 */
#define SHIM6_BITMASK_OPT_TYPE  0xFFFE  /* 1 111 1111    1 111 1110 */
#define SHIM6_BITMASK_CRITICAL  0x01    /* 0 000 0001 */
#define SHIM6_BITMASK_PRECVD    0xF0    /* 1 111 0000 */
#define SHIM6_BITMASK_PSENT     0x0F    /* 0 000 1111 */
#define SHIM6_BITMASK_STA       0xC0    /* 1 100 0000 */

/* SHIM6 Verification Methods */
#define SHIM6_VERIF_HBA         0x01    /* 0 000 0001 */
#define SHIM6_VERIF_CGA         0x02    /* 0 000 0010 */

/* SHIM6 Flags */
#define SHIM6_FLAG_BROKEN       0x01    /* 0 000 0001 */
#define SHIM6_FLAG_TEMPORARY    0x02    /* 0 000 0010 */

/* SHIM6 REAP States */
#define SHIM6_REAP_OPERATIONAL  0x00    /* 0 000 0000 */
#define SHIM6_REAP_EXPLORING    0x01    /* 0 000 0001 */
#define SHIM6_REAP_INBOUNDOK    0x02    /* 0 000 0010 */

/* Protocol specific data indices */
#define IPV6_PROTO_NXT_HDR          0
#define IPV6_PROTO_VALUE            1
#define IPV6_PROTO_META             2

/* Metadata collected on IPv6 header and extensions */
typedef struct {
    gint exthdr_count;
    gboolean jumbogram;
    guint32 jumbo_length;
} ipv6_meta_t;

static int ipv6_tap = -1;

static int proto_ipv6                           = -1;
static int proto_ipv6_hopopts                   = -1;
static int proto_ipv6_routing                   = -1;
static int proto_ipv6_fraghdr                   = -1;
static int proto_ipv6_shim6                     = -1;
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
static int hf_ipv6_opt_mpl_flag                 = -1;
static int hf_ipv6_opt_mpl_flag_s               = -1;
static int hf_ipv6_opt_mpl_flag_m               = -1;
static int hf_ipv6_opt_mpl_flag_v               = -1;
static int hf_ipv6_opt_mpl_flag_rsv             = -1;
static int hf_ipv6_opt_mpl_sequence             = -1;
static int hf_ipv6_opt_mpl_seed_id              = -1;
static int hf_ipv6_opt_experimental             = -1;
static int hf_ipv6_opt_unknown_data             = -1;
static int hf_ipv6_opt_unknown                  = -1;
static int hf_ipv6_dstopts_nxt                  = -1;
static int hf_ipv6_dstopts_length               = -1;
static int hf_ipv6_hopopts_nxt                  = -1;
static int hf_ipv6_hopopts_length               = -1;
static int hf_ipv6_unknown_hdr                  = -1;
static int hf_ipv6_unknown_hdr_nxt              = -1;
static int hf_ipv6_unknown_hdr_length           = -1;
static int hf_ipv6_routing_nxt                  = -1;
static int hf_ipv6_routing_length               = -1;
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
static int hf_ipv6_padding                      = -1;

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

static int hf_ipv6_shim6_nxt            = -1;
static int hf_ipv6_shim6_len            = -1;
static int hf_ipv6_shim6_p              = -1;
/* context tag is 49 bits, cannot be used for filter yet */
static int hf_ipv6_shim6_ct             = -1;
static int hf_ipv6_shim6_type           = -1;
static int hf_ipv6_shim6_proto          = -1;
static int hf_ipv6_shim6_checksum       = -1;
static int hf_ipv6_shim6_checksum_bad   = -1;
static int hf_ipv6_shim6_checksum_good  = -1;
static int hf_ipv6_shim6_inonce         = -1; /* also for request nonce */
static int hf_ipv6_shim6_rnonce         = -1;
static int hf_ipv6_shim6_reserved       = -1;
static int hf_ipv6_shim6_reserved2      = -1;
static int hf_ipv6_shim6_precvd         = -1;
static int hf_ipv6_shim6_psent          = -1;
static int hf_ipv6_shim6_psrc           = -1;
static int hf_ipv6_shim6_pdst           = -1;
static int hf_ipv6_shim6_pnonce         = -1;
static int hf_ipv6_shim6_pdata          = -1;
static int hf_ipv6_shim6_sulid          = -1;
static int hf_ipv6_shim6_rulid          = -1;
static int hf_ipv6_shim6_reap           = -1;
static int hf_ipv6_shim6_opt_type       = -1;
static int hf_ipv6_shim6_opt_len        = -1;
static int hf_ipv6_shim6_opt_total_len  = -1;
static int hf_ipv6_shim6_opt_loc_verif_methods = -1;
static int hf_ipv6_shim6_opt_critical   = -1;
static int hf_ipv6_shim6_opt_loclist    = -1;
static int hf_ipv6_shim6_locator        = -1;
static int hf_ipv6_shim6_loc_flag       = -1;
static int hf_ipv6_shim6_loc_prio       = -1;
static int hf_ipv6_shim6_loc_weight     = -1;
static int hf_ipv6_shim6_opt_locnum     = -1;
static int hf_ipv6_shim6_opt_elemlen    = -1;
static int hf_ipv6_shim6_opt_fii        = -1;
static int hf_ipv6_shim6_validator      = -1;
static int hf_ipv6_shim6_cga_parameter_data_structure = -1;
static int hf_ipv6_shim6_cga_signature  = -1;

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

static gint ett_ipv6                    = -1;
static gint ett_ipv6_opt                = -1;
static gint ett_ipv6_opt_rpl            = -1;
static gint ett_ipv6_opt_mpl            = -1;
static gint ett_ipv6_fraghdr            = -1;
static gint ett_ipv6_routing            = -1;
static gint ett_ipv6_shim6              = -1;
static gint ett_ipv6_shim6_option       = -1;
static gint ett_ipv6_shim6_locators     = -1;
static gint ett_ipv6_shim6_verif_methods = -1;
static gint ett_ipv6_shim6_loc_pref     = -1;
static gint ett_ipv6_shim6_probes_sent  = -1;
static gint ett_ipv6_shim6_probe_sent   = -1;
static gint ett_ipv6_shim6_probes_rcvd  = -1;
static gint ett_ipv6_shim6_probe_rcvd   = -1;
static gint ett_ipv6_shim6_cksum        = -1;
static gint ett_ipv6_fragments          = -1;
static gint ett_ipv6_fragment           = -1;
static gint ett_ipv6_traffic_class      = -1;

#ifdef HAVE_GEOIP_V6
static gint ett_geoip_info              = -1;
#endif /* HAVE_GEOIP_V6 */

static expert_field ei_ipv6_routing_invalid_length = EI_INIT;
static expert_field ei_ipv6_routing_invalid_segleft = EI_INIT;
static expert_field ei_ipv6_dst_addr_not_multicast = EI_INIT;
static expert_field ei_ipv6_src_route_list_mult_inst_same_addr = EI_INIT;
static expert_field ei_ipv6_src_route_list_src_addr = EI_INIT;
static expert_field ei_ipv6_src_route_list_dst_addr = EI_INIT;
static expert_field ei_ipv6_src_route_list_multicast_addr = EI_INIT;
static expert_field ei_ipv6_routing_rpl_cmpri_cmpre_pad = EI_INIT;
static expert_field ei_ipv6_routing_rpl_addr_count_ge0 = EI_INIT;
static expert_field ei_ipv6_routing_rpl_reserved = EI_INIT;
static expert_field ei_ipv6_opt_tel_invalid_len = EI_INIT;
static expert_field ei_ipv6_opt_jumbo_invalid_len = EI_INIT;
static expert_field ei_ipv6_opt_jumbo_missing = EI_INIT;
static expert_field ei_ipv6_opt_jumbo_prohibited = EI_INIT;
static expert_field ei_ipv6_opt_jumbo_truncated = EI_INIT;
static expert_field ei_ipv6_opt_jumbo_fragment = EI_INIT;
static expert_field ei_ipv6_opt_jumbo_not_hopbyhop = EI_INIT;
static expert_field ei_ipv6_opt_rtalert_invalid_len = EI_INIT;
static expert_field ei_ipv6_opt_unknown_data = EI_INIT;
static expert_field ei_ipv6_mipv6_home_address_invalid_len = EI_INIT;
static expert_field ei_ipv6_shim6_opt_elemlen_invalid = EI_INIT;
static expert_field ei_ipv6_shim6_checksum_bad = EI_INIT;
static expert_field ei_ipv6_hopopts_not_first = EI_INIT;
static expert_field ei_ipv6_bogus_ipv6_length = EI_INIT;
static expert_field ei_ipv6_bogus_payload_length = EI_INIT;
static expert_field ei_ipv6_bogus_ipv6_version = EI_INIT;
static expert_field ei_ipv6_invalid_header = EI_INIT;

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
    const struct ip6_hdr *ip6h = (const struct ip6_hdr *)vip;
    address src;
    address dst;

    /* Addresses aren't implemented as 'address' type in struct ip6_hdr */
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
    const struct ip6_hdr *ip6h = (const struct ip6_hdr *)vip;
    address src;
    address dst;

    /* Addresses aren't implemented as 'address' type in struct ip6_hdr */
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

/*
 * defragmentation of IPv6
 */
static reassembly_table ipv6_reassembly_table;

/* http://www.iana.org/assignments/ipv6-parameters (last updated 2015-07-07) */
static const value_string ipv6_opt_vals[] = {
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
    { IP6OPT_ENDI,          "Endpoint Identification"       },
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
value_string_ext ipv6_opt_vals_ext = VALUE_STRING_EXT_INIT(ipv6_opt_vals);

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

/**
 * Unicast Scope
 * Note that we must check topmost 10 bits only, not 16 bits (see RFC2373).
 */
#if 0 /* XXX Currently unused */
static inline gboolean in6_is_addr_link_local(struct e_in6_addr *a) {
    if ((a->bytes[0] == 0xfe) && ((a->bytes[1] & 0xc0) == 0x80)) {
        return TRUE;
    }
    return FALSE;
}

static inline gboolean in6_is_addr_sitelocal(struct e_in6_addr *a) {
    if ((a->bytes[0] == 0xfe) && ((a->bytes[1] & 0xc0) == 0xc0)) {
        return TRUE;
    }
    return FALSE;
}
#endif

/**
 * Multicast
 */
static inline gboolean in6_is_addr_multicast(struct e_in6_addr *a) {
    if (a->bytes[0] == 0xff) {
        return TRUE;
    }
    return FALSE;
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

static void
ipv6_reassemble_cleanup(void)
{
    reassembly_table_destroy(&ipv6_reassembly_table);
}

enum {
    IPv6_RT_HEADER_SOURCE_ROUTING=0,
    IPv6_RT_HEADER_NIMROD,
    IPv6_RT_HEADER_MobileIP,
    IPv6_RT_HEADER_RPL
};

/* Routing Header Types */
static const value_string routing_header_type[] = {
    { IPv6_RT_HEADER_SOURCE_ROUTING, "IPv6 Source Routing" },
    { IPv6_RT_HEADER_NIMROD, "Nimrod" },
    { IPv6_RT_HEADER_MobileIP, "Mobile IP" },
    { IPv6_RT_HEADER_RPL, "RPL" },
    { 0, NULL }
};

static int
dissect_routing6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
    struct ip6_rthdr   rt;
    guint              len;
    proto_tree        *rthdr_tree;
    proto_item        *pi, *ti, *ti_len, *ti_seg;
    int                offset = 0;
    struct e_in6_addr *addr, *dst_addr = NULL;
    ipv6_meta_t       *ipv6_info;

    ipv6_info = (ipv6_meta_t *)p_get_proto_data(pinfo->pool, pinfo, proto_ipv6, IPV6_PROTO_META);
    /* addr contains the final destination address after dissection of a routing type is finished */
    addr = wmem_new0(pinfo->pool, struct e_in6_addr);

    col_append_sep_str(pinfo->cinfo, COL_INFO, " , ", "IPv6 routing");

    tvb_memcpy(tvb, (guint8 *)&rt, offset, sizeof(rt));
    len = (rt.ip6r_len + 1) << 3;

    /* !!! specify length */
    pi = proto_tree_add_item(tree, proto_ipv6_routing, tvb, offset, len, ENC_NA);
    proto_item_append_text(pi, " (%s)", val_to_str(rt.ip6r_type, routing_header_type, "Unknown type %u"));

    rthdr_tree = proto_item_add_subtree(pi, ett_ipv6_routing);

    proto_tree_add_item(rthdr_tree, hf_ipv6_routing_nxt, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    ti_len = proto_tree_add_item(rthdr_tree, hf_ipv6_routing_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(ti_len, " (%d bytes)", len);
    offset += 1;

    proto_tree_add_item(rthdr_tree, hf_ipv6_routing_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    ti_seg = proto_tree_add_item(rthdr_tree, hf_ipv6_routing_segleft, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* IPv6 Source Routing Header (Type 0) */
    if (rt.ip6r_type == IPv6_RT_HEADER_SOURCE_ROUTING) {
        int offlim;
        guint rt0_addr_count;

        proto_tree_add_item(rthdr_tree, hf_ipv6_routing_src_reserved, tvb, offset, 4, ENC_NA);
        offset += 4;

        if (rt.ip6r_len % 2 != 0) {
            expert_add_info_format(pinfo, ti_len, &ei_ipv6_routing_invalid_length,
                "IPv6 Routing Header extension header length must not be odd");
        } else {
            rt0_addr_count = rt.ip6r_len / 2;
            if (rt.ip6r_segleft > rt0_addr_count) {
                expert_add_info_format(pinfo, ti_seg, &ei_ipv6_routing_invalid_segleft,
                    "IPv6 Type 0 Routing Header segments left field must not exceed address count (%u)", rt0_addr_count);
            }
            offlim = offset + rt0_addr_count * IPv6_ADDR_SIZE;
            for (; offset < offlim; offset += IPv6_ADDR_SIZE) {
                ti = proto_tree_add_item(rthdr_tree, hf_ipv6_routing_src_addr, tvb,
                                    offset, IPv6_ADDR_SIZE, ENC_NA);
                tvb_get_ipv6(tvb, offset, addr);
                if (in6_is_addr_multicast(addr)) {
                    expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_multicast_addr);
                }
            }
            dst_addr = addr;
        }
    }

    /* Mobile IPv6 Routing Header (Type 2) */
    else if (rt.ip6r_type == IPv6_RT_HEADER_MobileIP) {
        proto_tree_add_item(rthdr_tree, hf_ipv6_routing_mipv6_reserved, tvb, offset, 4, ENC_NA);
        offset += 4;

        if (rt.ip6r_len != 2) {
            expert_add_info_format(pinfo, ti_len, &ei_ipv6_routing_invalid_length,
                "IPv6 Type 2 Routing Header extension header length must equal 2");
        } else {
            if (rt.ip6r_segleft != 1) {
                expert_add_info_format(pinfo, ti_seg, &ei_ipv6_routing_invalid_segleft,
                    "IPv6 Type 2 Routing Header segments left field must equal 1");
            }
            ti = proto_tree_add_item(rthdr_tree, hf_ipv6_routing_mipv6_home_address, tvb,
                                    offset, IPv6_ADDR_SIZE, ENC_NA);
            tvb_get_ipv6(tvb, offset, addr);
            if (in6_is_addr_multicast(addr)) {
                expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_multicast_addr);
            }
            dst_addr = addr;
        }
    }

    /* RPL Source Routing Header (Type 3) */
    else if (rt.ip6r_type == IPv6_RT_HEADER_RPL) {
        guint8 cmprI;
        guint8 cmprE;
        guint8 pad;
        guint32 reserved;
        gint rpl_addr_count;

        /* IPv6 destination address used for elided bytes */
        struct e_in6_addr dstAddr;
        /* IPv6 source address used for strict checking */
        struct e_in6_addr srcAddr;

        memcpy((guint8 *)&dstAddr, pinfo->dst.data, pinfo->dst.len);
        memcpy((guint8 *)&srcAddr, pinfo->src.data, pinfo->src.len);

        /* from RFC6554: Multicast addresses MUST NOT appear in the IPv6 Destination Address field */
        if(g_ipv6_rpl_srh_strict_rfc_checking && in6_is_addr_multicast(&dstAddr)){
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
        if(g_ipv6_rpl_srh_strict_rfc_checking && (cmprI == 0 && cmprE == 0 && pad != 0)){
            expert_add_info_format(pinfo, ti, &ei_ipv6_routing_rpl_cmpri_cmpre_pad, "When cmprI equals 0 and cmprE equals 0, pad MUST equal 0 but instead was %d", pad);
        }

        ti = proto_tree_add_item(rthdr_tree, hf_ipv6_routing_rpl_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
        reserved = tvb_get_bits32(tvb, ((offset + 1) * 8) + 4, 20, ENC_BIG_ENDIAN);

        if(g_ipv6_rpl_srh_strict_rfc_checking && reserved != 0){
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
            expert_add_info_format(pinfo, ti_seg, &ei_ipv6_routing_invalid_segleft,
                "IPv6 RPL Routing Header segments left field must not exceed address count (%d)", rpl_addr_count);
        }

        if (rpl_addr_count > 0) {
            offset += 4;

            /* We use cmprI for internal (e.g.: not last) address for how many bytes to elide, so actual bytes present = 16-CmprI */
            while(rpl_addr_count > 1) {
                proto_tree_add_item(rthdr_tree, hf_ipv6_routing_rpl_addr, tvb, offset, (16-cmprI), ENC_NA);
                /* Display Full Address */
                memcpy((guint8 *)addr, (guint8 *)&dstAddr, sizeof(dstAddr));
                tvb_memcpy(tvb, (guint8 *)addr + cmprI, offset, (16-cmprI));
                ti = proto_tree_add_ipv6(rthdr_tree, hf_ipv6_routing_rpl_fulladdr, tvb, offset, (16-cmprI), addr);
                PROTO_ITEM_SET_GENERATED(ti);
                offset += (16-cmprI);
                rpl_addr_count--;

                if(g_ipv6_rpl_srh_strict_rfc_checking){
                    /* from RFC6554: */
                    /* The SRH MUST NOT specify a path that visits a node more than once. */
                    /* To do this, we will just check the current 'addr' against the next addresses */
                    gint tempSegments;
                    gint tempOffset;
                    tempSegments = rpl_addr_count; /* Has already been decremented above */
                    tempOffset = offset; /* Has already been moved */
                    while(tempSegments > 1) {
                        struct e_in6_addr tempAddr;
                        memcpy((guint8 *)&tempAddr, (guint8 *)&dstAddr, sizeof(dstAddr));
                        tvb_memcpy(tvb, (guint8 *)&tempAddr + cmprI, tempOffset, (16-cmprI));
                        /* Compare the addresses */
                        if (memcmp(addr->bytes, tempAddr.bytes, 16) == 0) {
                            /* Found a later address that is the same */
                            expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_mult_inst_same_addr);
                            break;
                        }
                        tempOffset += (16-cmprI);
                        tempSegments--;
                    }
                    if (tempSegments == 1) {
                        struct e_in6_addr tempAddr;

                        memcpy((guint8 *)&tempAddr, (guint8 *)&dstAddr, sizeof(dstAddr));
                        tvb_memcpy(tvb, (guint8 *)&tempAddr + cmprE, tempOffset, (16-cmprE));
                        /* Compare the addresses */
                        if (memcmp(addr->bytes, tempAddr.bytes, 16) == 0) {
                            /* Found a later address that is the same */
                            expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_mult_inst_same_addr);
                        }
                    }
                    /* IPv6 Source and Destination addresses of the encapsulating datagram (MUST) not appear in the SRH*/
                    if (memcmp(addr->bytes, srcAddr.bytes, 16) == 0) {
                        expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_src_addr);
                    }

                    if (memcmp(addr->bytes, dstAddr.bytes, 16) == 0) {
                        expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_dst_addr);
                    }

                    /* Multicast addresses MUST NOT appear in the in SRH */
                    if(in6_is_addr_multicast(addr)){
                        expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_multicast_addr);
                    }
                }
            }

            /* We use cmprE for last address for how many bytes to elide, so actual bytes present = 16-CmprE */
            if (rpl_addr_count == 1) {
                proto_tree_add_item(rthdr_tree, hf_ipv6_routing_rpl_addr, tvb, offset, (16-cmprE), ENC_NA);
                /* Display Full Address */
                memcpy((guint8 *)addr, (guint8 *)&dstAddr, sizeof(dstAddr));
                tvb_memcpy(tvb, (guint8 *)addr + cmprE, offset, (16-cmprE));
                ti = proto_tree_add_ipv6(rthdr_tree, hf_ipv6_routing_rpl_fulladdr, tvb, offset, (16-cmprE), addr);
                PROTO_ITEM_SET_GENERATED(ti);
                /* offset += (16-cmprE); */

                if(g_ipv6_rpl_srh_strict_rfc_checking){
                    /* IPv6 Source and Destination addresses of the encapsulating datagram (MUST) not appear in the SRH*/
                    if (memcmp(addr->bytes, srcAddr.bytes, 16) == 0) {
                        expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_src_addr);
                    }

                    if (memcmp(addr->bytes, dstAddr.bytes, 16) == 0) {
                        expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_dst_addr);
                    }

                    /* Multicast addresses MUST NOT appear in the in SRH */
                    if(in6_is_addr_multicast(addr)){
                        expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_multicast_addr);
                    }
                }
                dst_addr = addr;
            }
        }
    }

    if (dst_addr != NULL && rt.ip6r_segleft > 0) {
        set_address(&pinfo->dst, AT_IPv6, IPv6_ADDR_SIZE, dst_addr);
    }

    ipv6_info->exthdr_count++;
    return len;
}

static int
dissect_frag6(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
                guint16 *frag_off, gboolean *frag_flg, guint32 *frag_ident) {
    proto_item      *pi, *ti;
    proto_tree      *frag_tree;
    guint8           nxt;
    guint16          offlg;
    ipv6_meta_t     *ipv6_info;

    ipv6_info = (ipv6_meta_t *)p_get_proto_data(pinfo->pool, pinfo, proto_ipv6, IPV6_PROTO_META);

    nxt = tvb_get_guint8(tvb, offset);
    offlg = tvb_get_ntohs(tvb, offset + 2);
    *frag_off = offlg & IP6F_OFF_MASK; /* offset in bytes */
    *frag_flg = offlg & IP6F_MORE_FRAG;
    *frag_ident = tvb_get_ntohl(tvb, offset + 4);
    col_add_fstr(pinfo->cinfo, COL_INFO, "IPv6 fragment (off=%u more=%s ident=0x%08x nxt=%u)",
                        *frag_off, *frag_flg ? "y" : "n", *frag_ident, nxt);

    /* IPv6 Fragmentation Header has fixed length of 8 bytes */
    pi = proto_tree_add_item(tree, proto_ipv6_fraghdr, tvb, offset, 8, ENC_NA);
    if (ipv6_info->jumbo_length) {
        expert_add_info(pinfo, pi, &ei_ipv6_opt_jumbo_fragment);
    }

    frag_tree = proto_item_add_subtree(pi, ett_ipv6_fraghdr);

    if (frag_tree) {
        proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_nxt, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_reserved_octet, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        ti = proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, " (%d bytes)", *frag_off);

        proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_reserved_bits, tvb, offset, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_more, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_ident, tvb, offset, 4, ENC_BIG_ENDIAN);
        /*offset += 4;*/
    }

    ipv6_info->exthdr_count++;
    return 8;
}

static const value_string rtalertvals[] = {
    { IP6OPT_RTALERT_MLD, "MLD" },
    { IP6OPT_RTALERT_RSVP, "RSVP" },
    { IP6OPT_RTALERT_ACTNET, "Active Network" },
    { 0, NULL }
};

static int
dissect_unknown_exthdr(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    int         len;
    proto_tree *unkhdr_tree;
    proto_item *ti, *ti_len;

    len = (tvb_get_guint8(tvb, offset + 1) + 1) << 3;

    if (tree) {
        /* !!! specify length */
        ti = proto_tree_add_item(tree, hf_ipv6_unknown_hdr, tvb, offset, len, ENC_NA);

        unkhdr_tree = proto_item_add_subtree(ti, ett_ipv6);

        proto_tree_add_item(unkhdr_tree, hf_ipv6_unknown_hdr_nxt, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        ti_len = proto_tree_add_item(unkhdr_tree, hf_ipv6_unknown_hdr_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_len, " (%d byte%s)", len, plurality(len, "", "s"));
        /* offset += 1; */
    }
    return len;
}

static int
dissect_opts(tvbuff_t *tvb, int offset, proto_tree *tree, packet_info *pinfo, const int exthdr_proto, ws_ip *iph)
{
    int         len;
    int         offset_end, offset_opt_end;
    proto_tree *exthdr_tree, *opt_tree;
    proto_item *ti, *ti_len, *ti_opt, *ti_opt_len;
    int         hf_exthdr_item_nxt, hf_exthdr_item_length;
    guint8      opt_len, opt_type;
    ipv6_meta_t *ipv6_info;
    guint32     plen_jumbo;
    gboolean    hopopts = FALSE;

    ipv6_info = (ipv6_meta_t *)p_get_proto_data(pinfo->pool, pinfo, proto_ipv6, IPV6_PROTO_META);
    hopopts = (exthdr_proto == proto_ipv6_hopopts);

    len = (tvb_get_guint8(tvb, offset + 1) + 1) << 3;
    offset_end = offset + len;

    /* !!! specify length */
    ti = proto_tree_add_item(tree, exthdr_proto, tvb, offset, len, ENC_NA);

    if (hopopts && ipv6_info->exthdr_count > 0) {
        /* IPv6 Hop-by-Hop must appear immediately after IPv6 header (RFC 2460) */
        expert_add_info(pinfo, ti, &ei_ipv6_hopopts_not_first);
    }

    exthdr_tree = proto_item_add_subtree(ti, ett_ipv6);

    if (exthdr_proto == proto_ipv6_hopopts) {
        hf_exthdr_item_nxt = hf_ipv6_hopopts_nxt;
        hf_exthdr_item_length = hf_ipv6_hopopts_length;
    } else if (exthdr_proto == proto_ipv6_dstopts) {
        hf_exthdr_item_nxt = hf_ipv6_dstopts_nxt;
        hf_exthdr_item_length = hf_ipv6_dstopts_length;
    } else {
        DISSECTOR_ASSERT_NOT_REACHED();
    }

    proto_tree_add_item(exthdr_tree, hf_exthdr_item_nxt, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    ti_len = proto_tree_add_item(exthdr_tree, hf_exthdr_item_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(ti_len, " (%d byte%s)", len, plurality(len, "", "s"));
    offset += 1;

    while (offset_end > offset) {
        /* there are more options */

        /* IPv6 Option */
        ti_opt = proto_tree_add_item(exthdr_tree, hf_ipv6_opt, tvb, offset, 1, ENC_NA);
        opt_tree = proto_item_add_subtree(ti_opt, ett_ipv6_opt);

        /* Option type */
        proto_tree_add_item(opt_tree, hf_ipv6_opt_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        opt_type = tvb_get_guint8(tvb, offset);

        /* Add option name to option root label */
        proto_item_append_text(ti_opt, " (%s", val_to_str_ext(opt_type, &ipv6_opt_vals_ext, "Unknown %u"));

        /* The Pad1 option is a special case, and contains no data. */
        if (opt_type == IP6OPT_PAD1) {
            proto_tree_add_item(opt_tree, hf_ipv6_opt_pad1, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_item_append_text(ti_opt, ")");
            continue;
        }
        offset += 1;

        /* Option length */
        ti_opt_len = proto_tree_add_item(opt_tree, hf_ipv6_opt_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        opt_len = tvb_get_guint8(tvb, offset);
        proto_item_set_len(ti_opt, opt_len + 2);
        offset += 1;
        offset_opt_end = offset + opt_len;

        switch (opt_type) {
        case IP6OPT_PADN:
            /* RFC 2460 states :
             * "The PadN option is used to insert two or more octets of
             * padding into the Options area of a header.  For N octets of
             * padding, the Opt Data Len field contains the value N-2, and
             * the Option Data consists of N-2 zero-valued octets."
             */
            proto_tree_add_item(opt_tree, hf_ipv6_opt_padn, tvb,
                                offset, opt_len, ENC_NA);
            offset += opt_len;
            break;
        case IP6OPT_TEL:
            if (opt_len != 1) {
                expert_add_info_format(pinfo, ti_opt_len, &ei_ipv6_opt_tel_invalid_len,
                                       "Tunnel Encapsulation Limit: Invalid length (%u bytes)", opt_len);
            }
            proto_tree_add_item(opt_tree, hf_ipv6_opt_tel, tvb,
                                offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case IP6OPT_JUMBO:
            if (opt_len != 4) {
                expert_add_info_format(pinfo, ti_opt_len, &ei_ipv6_opt_jumbo_invalid_len,
                                       "Jumbo payload: Invalid length (%u bytes)", opt_len);
            }
            ti = proto_tree_add_item(opt_tree, hf_ipv6_opt_jumbo, tvb,
                                offset, 4, ENC_BIG_ENDIAN);
            if (!hopopts) {
                expert_add_info(pinfo, ti_opt, &ei_ipv6_opt_jumbo_not_hopbyhop);
            } else if (ipv6_info->exthdr_count == 0) {
                if (!ipv6_info->jumbogram) {
                    if (iph->ip_len) {
                        expert_add_info(pinfo, ti_opt, &ei_ipv6_opt_jumbo_prohibited);
                        proto_item_append_text(ti, " [Ignored]");
                    } else {
                        ipv6_info->jumbogram = TRUE;
                        plen_jumbo = tvb_get_ntohl(tvb, offset);
                        if (plen_jumbo < 65536) {
                            expert_add_info(pinfo, ti, &ei_ipv6_opt_jumbo_truncated);
                        } else {
                            ipv6_info->jumbo_length = plen_jumbo;
                        }
                    }
                } else {
                    /* XXX - Repeated jumbo TLV */
                    ;
                }
            }
            offset += 4;
            break;
        case IP6OPT_RTALERT:
        {
            if (opt_len != 2) {
                expert_add_info_format(pinfo, ti_opt_len, &ei_ipv6_opt_rtalert_invalid_len,
                                       "Router alert: Invalid Length (%u bytes)",
                                       opt_len + 2);
            }
            proto_tree_add_item(opt_tree, hf_ipv6_opt_rtalert, tvb,
                                offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        }
        case IP6OPT_HOME_ADDRESS:
        {
            if (opt_len != 16) {
                expert_add_info_format(pinfo, ti_opt_len, &ei_ipv6_mipv6_home_address_invalid_len,
                                       "Home Address: Invalid length (%u bytes)", opt_len);
            }
            proto_tree_add_item(opt_tree, hf_ipv6_opt_mipv6_home_address, tvb,
                                offset, 16, ENC_NA);
            set_address_tvb(&pinfo->src, AT_IPv6, 16, tvb, offset);
            offset += 16;
            break;
        }
        case IP6OPT_CALIPSO:
        {
            guint8 cmpt_length;
            proto_tree_add_item(opt_tree, hf_ipv6_opt_calipso_doi, tvb,
                                offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            proto_tree_add_item(opt_tree, hf_ipv6_opt_calipso_cmpt_length, tvb,
                                offset, 1, ENC_BIG_ENDIAN);
            cmpt_length = tvb_get_guint8(tvb, offset);
            offset += 1;
            proto_tree_add_item(opt_tree, hf_ipv6_opt_calipso_sens_level, tvb,
                                offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            /* Need to add Check Checksum..*/
            proto_tree_add_item(opt_tree, hf_ipv6_opt_calipso_checksum, tvb,
                                offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(opt_tree, hf_ipv6_opt_calipso_cmpt_bitmap, tvb,
                                offset, cmpt_length*4, ENC_NA);
            offset += cmpt_length*4;
            break;
        }
        case IP6OPT_QUICKSTART:
        {

            guint8 command = tvb_get_guint8(tvb, offset);
            guint8 function = command >> 4;
            guint8 rate = command & QS_RATE_MASK;
            guint8 ttl_diff;

            proto_tree_add_item(opt_tree, hf_ipv6_opt_qs_func, tvb, offset, 1, ENC_BIG_ENDIAN);

            if (function == QS_RATE_REQUEST) {
                proto_tree_add_item(opt_tree, hf_ipv6_opt_qs_rate, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(opt_tree, hf_ipv6_opt_qs_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
                ttl_diff = (iph->ip_ttl - tvb_get_guint8(tvb, offset) % 256);
                ti = proto_tree_add_uint(opt_tree, hf_ipv6_opt_qs_ttl_diff,
                                                      tvb, offset, 1, ttl_diff);
                PROTO_ITEM_SET_GENERATED(ti);
                proto_item_append_text(ti_opt, ", %s, QS TTL %u, QS TTL diff %u",
                                       val_to_str_ext(rate, &qs_rate_vals_ext, "Unknown (%u)"),
                                       tvb_get_guint8(tvb, offset), ttl_diff);
                offset += 1;
                proto_tree_add_item(opt_tree, hf_ipv6_opt_qs_nonce, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(opt_tree, hf_ipv6_opt_qs_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            } else if (function == QS_RATE_REPORT) {
                proto_tree_add_item(opt_tree, hf_ipv6_opt_qs_rate, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_item_append_text(ti_opt, ", %s",
                                       val_to_str_ext(rate, &qs_rate_vals_ext, "Unknown (%u)"));
                proto_tree_add_item(opt_tree, hf_ipv6_opt_qs_unused, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(opt_tree, hf_ipv6_opt_qs_nonce, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(opt_tree, hf_ipv6_opt_qs_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }

        }
        break;
        case IP6OPT_RPL:
        {
            static const int * rpl_flags[] = {
                &hf_ipv6_opt_rpl_flag_o,
                &hf_ipv6_opt_rpl_flag_r,
                &hf_ipv6_opt_rpl_flag_f,
                &hf_ipv6_opt_rpl_flag_rsv,
                NULL
            };

            proto_tree_add_bitmask(opt_tree, tvb, offset, hf_ipv6_opt_rpl_flag, ett_ipv6_opt_rpl, rpl_flags, ENC_NA);
            offset +=1;

            proto_tree_add_item(opt_tree, hf_ipv6_opt_rpl_instance_id, tvb, offset, 1, ENC_NA);
            offset +=1;

            proto_tree_add_item(opt_tree, hf_ipv6_opt_rpl_senderrank, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset +=2;

            /* TODO: Add dissector of sub TLV */
        }
        break;
        case IP6OPT_MPL:
        {
            static const int * mpl_flags[] = {
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
                offset +=seed_id_len;
            }
        }
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
            proto_tree_add_item(opt_tree, hf_ipv6_opt_unknown, tvb,
                                offset, opt_len, ENC_NA);
            offset += opt_len;
            break;
        }
        if(offset < offset_opt_end){
            ti = proto_tree_add_item(opt_tree, hf_ipv6_opt_unknown_data, tvb, offset, offset_opt_end - offset, ENC_NA);
            expert_add_info(pinfo, ti, &ei_ipv6_opt_unknown_data);
            offset = offset_opt_end;
        }
        /* Close the ) to option root label */
        proto_item_append_text(ti_opt, ")");
    }

    ipv6_info->exthdr_count++;
    return len;
}

static int
dissect_hopopts(tvbuff_t *tvb, packet_info * pinfo, proto_tree *tree, void *data)
{
    ws_ip* iph = (ws_ip*)data;

    col_append_sep_str(pinfo->cinfo, COL_INFO, " , ", "IPv6 hop-by-hop options");

    return dissect_opts(tvb, 0, tree, pinfo, proto_ipv6_hopopts, iph);
}

static int
dissect_dstopts(tvbuff_t *tvb, packet_info * pinfo, proto_tree *tree, void *data)
{
    ws_ip* iph = (ws_ip*)data;

    col_append_sep_str(pinfo->cinfo, COL_INFO, " , ", "IPv6 destination options");

    return dissect_opts(tvb, 0, tree, pinfo, proto_ipv6_dstopts, iph);
}

/* START SHIM6 PART */

static guint16
shim6_checksum(tvbuff_t *tvb, int offset, int len)
{
    vec_t cksum_vec[1];

    SET_CKSUM_VEC_TVB(cksum_vec[0], tvb, offset, len);
    return in_cksum(&cksum_vec[0], 1);
}

static const value_string shimoptvals[] = {
    { SHIM6_OPT_RESPVAL,  "Responder Validator Option" },
    { SHIM6_OPT_LOCLIST,  "Locator List Option" },
    { SHIM6_OPT_LOCPREF,  "Locator Preferences Option" },
    { SHIM6_OPT_CGAPDM,   "CGA Parameter Data Structure Option" },
    { SHIM6_OPT_CGASIG,   "CGA Signature Option" },
    { SHIM6_OPT_ULIDPAIR, "ULID Pair Option" },
    { SHIM6_OPT_FII,      "Forked Instance Identifier Option" },
    { 0, NULL }
};

static const value_string shimverifmethods[] = {
    { SHIM6_VERIF_HBA, "HBA" },
    { SHIM6_VERIF_CGA, "CGA" },
    { 0, NULL }
};

static const value_string shimflags[] _U_ = {
    { SHIM6_FLAG_BROKEN,    "BROKEN" },
    { SHIM6_FLAG_TEMPORARY, "TEMPORARY" },
    { 0, NULL }
};

static const value_string shimreapstates[] = {
    { SHIM6_REAP_OPERATIONAL, "Operational" },
    { SHIM6_REAP_EXPLORING,   "Exploring" },
    { SHIM6_REAP_INBOUNDOK,   "InboundOK" },
    { 0, NULL }
};

static const value_string shim6_protocol[] = {
    { 0, "SHIM6" },
    { 1, "HIP" },
    { 0, NULL }
};


static void
dissect_shim6_opt_loclist(proto_tree * opt_tree, tvbuff_t * tvb, gint *offset)
{
    proto_tree *subtree;
    guint       count;
    guint       optlen;
    int         p = *offset;

    proto_tree_add_item(opt_tree, hf_ipv6_shim6_opt_loclist, tvb, p, 4, ENC_BIG_ENDIAN);
    p += 4;

    optlen = tvb_get_guint8(tvb, p);
    proto_tree_add_item(opt_tree, hf_ipv6_shim6_opt_locnum, tvb, p, 1, ENC_BIG_ENDIAN);
    p++;

    /* Verification Methods */
    subtree = proto_tree_add_subtree(opt_tree, tvb, p, optlen,
                             ett_ipv6_shim6_verif_methods, NULL, "Locator Verification Methods");

    for (count=0; count < optlen; count++)
        proto_tree_add_item(subtree, hf_ipv6_shim6_opt_loc_verif_methods, tvb,
                            p+count, 1, ENC_BIG_ENDIAN);
    p += optlen;

    /* Padding, included in length field */
    if ((7 - optlen % 8) > 0) {
        proto_tree_add_item(opt_tree, hf_ipv6_padding, tvb, p, (7 - optlen % 8), ENC_NA);
        p += (7 - optlen % 8);
    }

    /* Locators */
    subtree = proto_tree_add_subtree(opt_tree, tvb, p, 16 * optlen, ett_ipv6_shim6_locators, NULL, "Locators");

    for (count=0; count < optlen; count++) {
        proto_tree_add_item(subtree, hf_ipv6_shim6_locator, tvb, p, 16, ENC_NA);
        p += 16;
    }
    *offset = p;
}

static void
dissect_shim6_opt_loc_pref(proto_tree * opt_tree, tvbuff_t * tvb, gint *offset, gint len, packet_info *pinfo)
{
    proto_tree *subtree;

    gint        p;
    gint        optlen;
    gint        count;

    p = *offset;

    proto_tree_add_item(opt_tree, hf_ipv6_shim6_opt_loclist, tvb, p, 4, ENC_BIG_ENDIAN);
    p += 4;

    optlen = tvb_get_guint8(tvb, p);
    proto_tree_add_item(opt_tree, hf_ipv6_shim6_opt_elemlen, tvb, p, 1, ENC_BIG_ENDIAN);

    if (optlen < 1 || optlen > 3) {
        proto_tree_add_expert_format(opt_tree, pinfo, &ei_ipv6_shim6_opt_elemlen_invalid, tvb, p, 1,
                                     "Invalid element length: %u", optlen);
        return;
    }

    p++;

    /* Locator Preferences */
    count = 1;
    while (p < len) {
        subtree = proto_tree_add_subtree_format(opt_tree, tvb, p, optlen, ett_ipv6_shim6_loc_pref, NULL,
                                                "Locator Preferences %u", count);

        /* Flags */
        if (optlen >= 1)
            proto_tree_add_item(subtree, hf_ipv6_shim6_loc_flag, tvb, p, 1, ENC_BIG_ENDIAN);
        /* Priority */
        if (optlen >= 2)
            proto_tree_add_item(subtree, hf_ipv6_shim6_loc_prio, tvb, p+1, 1, ENC_BIG_ENDIAN);
        /* Weight */
        if (optlen >= 3)
            proto_tree_add_item(subtree, hf_ipv6_shim6_loc_weight, tvb, p+2, 1, ENC_BIG_ENDIAN);
        /*
         * Shim6 Draft 08 doesn't specify the format when the Element length is
         * more than three, except that any such formats MUST be defined so that
         * the first three octets are the same as in the above case, that is, a
         * of a 1 octet flags field followed by a 1 octet priority field, and a
         * 1 octet weight field.
         */
        p += optlen;
        count++;
    }
    *offset = p;
}


static int
dissect_shimopts(tvbuff_t *tvb, int offset, proto_tree *tree, packet_info *pinfo)
{
    int          len, total_len;
    gint         p;
    gint         padding;
    proto_tree  *opt_tree;
    proto_item  *ti;


    p = offset;

    p += 4;

    len = tvb_get_ntohs(tvb, offset+2);
    padding = 7 - ((len + 3) % 8);
    total_len = 4 + len + padding;

    if (tree)
    {
        /* Option Type */
        opt_tree = proto_tree_add_subtree(tree, tvb, offset, total_len, ett_ipv6_shim6_option, NULL,
                            val_to_str_const( (tvb_get_ntohs(tvb, offset) & SHIM6_BITMASK_OPT_TYPE) >> 1, shimoptvals, "Unknown Option Type"));

        proto_tree_add_item(opt_tree, hf_ipv6_shim6_opt_type, tvb, offset, 2, ENC_BIG_ENDIAN);

        /* Critical */
        proto_tree_add_item(opt_tree, hf_ipv6_shim6_opt_critical, tvb, offset+1, 1, ENC_BIG_ENDIAN);

        /* Content Length */
        proto_tree_add_item(opt_tree, hf_ipv6_shim6_opt_len, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        ti = proto_tree_add_uint(opt_tree, hf_ipv6_shim6_opt_total_len, tvb, offset+2, 2, total_len);
        PROTO_ITEM_SET_GENERATED(ti);

        /* Option Type Specific */
        switch (tvb_get_ntohs(tvb, offset) >> 1)
        {
        case SHIM6_OPT_RESPVAL:
            proto_tree_add_item(opt_tree, hf_ipv6_shim6_validator, tvb, p, len, ENC_NA);
            p += len;
            if (total_len-(len+4) > 0)
                proto_tree_add_item(opt_tree, hf_ipv6_padding, tvb, p, total_len-(len+4), ENC_NA);
            break;
        case SHIM6_OPT_LOCLIST:
            dissect_shim6_opt_loclist(opt_tree, tvb, &p);
            break;
        case SHIM6_OPT_LOCPREF:
            dissect_shim6_opt_loc_pref(opt_tree, tvb, &p, offset+len+4, pinfo);
            if (total_len-(len+4) > 0)
                proto_tree_add_item(opt_tree, hf_ipv6_padding, tvb, p, total_len-(len+4), ENC_NA);
            break;
        case SHIM6_OPT_CGAPDM:
            proto_tree_add_item(opt_tree, hf_ipv6_shim6_cga_parameter_data_structure, tvb, p, len, ENC_NA);
            p += len;
            if (total_len-(len+4) > 0)
                proto_tree_add_item(opt_tree, hf_ipv6_padding, tvb, p, total_len-(len+4), ENC_NA);
            break;
        case SHIM6_OPT_CGASIG:
            proto_tree_add_item(opt_tree, hf_ipv6_shim6_cga_signature, tvb, p, len, ENC_NA);
            p += len;
            if (total_len-(len+4) > 0)
                proto_tree_add_item(opt_tree, hf_ipv6_padding, tvb, p, total_len-(len+4), ENC_NA);
            break;
        case SHIM6_OPT_ULIDPAIR:
            proto_tree_add_item(opt_tree, hf_ipv6_shim6_reserved, tvb, p, 4, ENC_NA);
            p += 4;
            proto_tree_add_item(opt_tree, hf_ipv6_shim6_sulid, tvb, p, 16, ENC_NA);
            p += 16;
            proto_tree_add_item(opt_tree, hf_ipv6_shim6_rulid, tvb, p, 16, ENC_NA);
            p += 16;
            break;
        case SHIM6_OPT_FII:
            proto_tree_add_item(opt_tree, hf_ipv6_shim6_opt_fii, tvb, p, 4, ENC_BIG_ENDIAN);
            p += 4;
            break;
        default:
            break;
        }
    }
    return total_len;
}

static void
dissect_shim6_ct(proto_tree * shim_tree, gint hf_item, tvbuff_t * tvb, gint offset, const guchar * label)
{
    guint8  tmp[6];
    guchar *ct_str;

    tmp[0] = tvb_get_guint8(tvb, offset++);
    tmp[1] = tvb_get_guint8(tvb, offset++);
    tmp[2] = tvb_get_guint8(tvb, offset++);
    tmp[3] = tvb_get_guint8(tvb, offset++);
    tmp[4] = tvb_get_guint8(tvb, offset++);
    tmp[5] = tvb_get_guint8(tvb, offset++);

    ct_str = wmem_strdup_printf(wmem_packet_scope(),
                                "%s: %02X %02X %02X %02X %02X %02X", label,
                                tmp[0] & SHIM6_BITMASK_CT, tmp[1], tmp[2],
                                tmp[3], tmp[4], tmp[5]
        );
    proto_tree_add_none_format(shim_tree, hf_item, tvb, offset - 6, 6, "%s", ct_str);
}

static void
dissect_shim6_probes(proto_tree * shim_tree, tvbuff_t * tvb, gint offset,
                     const guchar * label, guint nbr_probe,
                     gboolean probes_rcvd)
{
    proto_tree *probes_tree;
    proto_tree *probe_tree;
    gint        ett_probes;
    gint        ett_probe;
    guint       count;

    if (probes_rcvd) {
        ett_probes = ett_ipv6_shim6_probes_rcvd;
        ett_probe = ett_ipv6_shim6_probe_rcvd;
    } else {
        ett_probes = ett_ipv6_shim6_probes_sent;
        ett_probe = ett_ipv6_shim6_probe_sent;
    }
    probes_tree = proto_tree_add_subtree(shim_tree, tvb, offset, 40 * nbr_probe, ett_probes, NULL, label);

    for (count=0; count < nbr_probe; count++) {
        probe_tree = proto_tree_add_subtree_format(probes_tree, tvb, offset, 40,
                                            ett_probe, NULL, "Probe %u", count+1);

        proto_tree_add_item(probe_tree, hf_ipv6_shim6_psrc, tvb, offset, 16, ENC_NA);
        offset += 16;
        proto_tree_add_item(probe_tree, hf_ipv6_shim6_pdst, tvb, offset, 16, ENC_NA);
        offset += 16;

        proto_tree_add_item(probe_tree, hf_ipv6_shim6_pnonce, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(probe_tree, hf_ipv6_shim6_pdata, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
}

/* Dissect SHIM6 data: control messages */
static int
dissect_shimctrl(tvbuff_t *tvb, gint offset, guint type, proto_tree *shim_tree)
{
    gint         p;
    guint8       tmp;
    const gchar *sta;
    guint        probes_sent;
    guint        probes_rcvd;

    p = offset;

    switch (type)
    {
    case SHIM6_TYPE_I1:
        dissect_shim6_ct(shim_tree, hf_ipv6_shim6_ct, tvb, p, "Initiator Context Tag");
        p += 6;
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_inonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        break;
    case SHIM6_TYPE_R1:
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_reserved2, tvb, p, 2, ENC_NA);
        p += 2;
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_inonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_rnonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        break;
    case SHIM6_TYPE_I2:
        dissect_shim6_ct(shim_tree, hf_ipv6_shim6_ct, tvb, p, "Initiator Context Tag");
        p += 6;
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_inonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_rnonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_reserved2, tvb, p, 4, ENC_NA);
        p += 4;
        break;
    case SHIM6_TYPE_R2:
        dissect_shim6_ct(shim_tree, hf_ipv6_shim6_ct, tvb, p, "Responder Context Tag");
        p += 6;
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_inonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        break;
    case SHIM6_TYPE_R1BIS:
        dissect_shim6_ct(shim_tree, hf_ipv6_shim6_ct, tvb, p, "Packet Context Tag");
        p += 6;
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_rnonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        break;
    case SHIM6_TYPE_I2BIS:
        dissect_shim6_ct(shim_tree, hf_ipv6_shim6_ct, tvb, p, "Initiator Context Tag");
        p += 6;
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_inonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_rnonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_reserved2, tvb, p, 6, ENC_NA);
        p += 6;
        dissect_shim6_ct(shim_tree, hf_ipv6_shim6_ct, tvb, p, "Initiator Context Tag");
        p += 6;
        break;
    case SHIM6_TYPE_UPD_REQ:
    case SHIM6_TYPE_UPD_ACK:
        dissect_shim6_ct(shim_tree, hf_ipv6_shim6_ct, tvb, p, "Receiver Context Tag");
        p += 6;
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_rnonce, tvb, p, 4, ENC_BIG_ENDIAN);
        p += 4;
        break;
    case SHIM6_TYPE_KEEPALIVE:
        dissect_shim6_ct(shim_tree, hf_ipv6_shim6_ct, tvb, p, "Receiver Context Tag");
        p += 6;
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_reserved2, tvb, p, 4, ENC_NA);
        p += 4;
        break;
    case SHIM6_TYPE_PROBE:
        dissect_shim6_ct(shim_tree, hf_ipv6_shim6_ct, tvb, p, "Receiver Context Tag");
        p += 6;

        tmp = tvb_get_guint8(tvb, p);
        probes_sent = tmp & SHIM6_BITMASK_PSENT;
        probes_rcvd = (tmp & SHIM6_BITMASK_PRECVD) >> 4;
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_psent, tvb,
                            p, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_precvd, tvb,
                            p, 1, ENC_BIG_ENDIAN);
        p++;

        sta = val_to_str_const((tvb_get_guint8(tvb, p) & SHIM6_BITMASK_STA) >> 6,
                               shimreapstates, "Unknown REAP State");
        proto_tree_add_uint_format_value(shim_tree, hf_ipv6_shim6_reap, tvb,
                                         p, 1, (tvb_get_guint8(tvb, p) & SHIM6_BITMASK_STA) >> 6,
                                         "%s", sta);

        proto_tree_add_item(shim_tree, hf_ipv6_shim6_reserved2, tvb, p, 3, ENC_NA);
        p += 3;

        /* Probes Sent */
        if (probes_sent) {
            dissect_shim6_probes(shim_tree, tvb, p, "Probes Sent",
                                 probes_sent, FALSE);
            p += 40 * probes_sent;
        }

        /* Probes Received */
        if (probes_rcvd) {
            dissect_shim6_probes(shim_tree, tvb, p, "Probes Received",
                                 probes_rcvd, TRUE);
            p += 40 * probes_rcvd;
        }
        break;
    default:
        break;
    }
    return p-offset;
}

/* Dissect SHIM6 data: payload, common part, options */
static const value_string shimctrlvals[] = {
    { SHIM6_TYPE_I1,        "I1" },
    { SHIM6_TYPE_R1,        "R1" },
    { SHIM6_TYPE_I2,        "I2" },
    { SHIM6_TYPE_R2,        "R2" },
    { SHIM6_TYPE_R1BIS,     "R1bis" },
    { SHIM6_TYPE_I2BIS,     "I2bis" },
    { SHIM6_TYPE_UPD_REQ,   "Update Request" },
    { SHIM6_TYPE_UPD_ACK,   "Update Acknowledgment" },
    { SHIM6_TYPE_KEEPALIVE, "Keepalive" },
    { SHIM6_TYPE_PROBE,     "Probe" },
    { 0, NULL }
};

static void
add_shim6_checksum_additional_info(tvbuff_t * tvb, packet_info * pinfo,
                proto_item * it_cksum, int offset, gboolean is_cksum_correct)
{
    proto_tree *checksum_tree;
    proto_item *item;

    checksum_tree = proto_item_add_subtree(it_cksum, ett_ipv6_shim6_cksum);
    item = proto_tree_add_boolean(checksum_tree, hf_ipv6_shim6_checksum_good, tvb,
                                  offset, 2, is_cksum_correct);
    PROTO_ITEM_SET_GENERATED(item);
    item = proto_tree_add_boolean(checksum_tree, hf_ipv6_shim6_checksum_bad, tvb,
                                  offset, 2, !is_cksum_correct);
    PROTO_ITEM_SET_GENERATED(item);
    if (!is_cksum_correct) {
        expert_add_info(pinfo, item, &ei_ipv6_shim6_checksum_bad);
        col_append_str(pinfo->cinfo, COL_INFO, " [Shim6 CHECKSUM INCORRECT]");
    }
}

static int
dissect_shim6(tvbuff_t *tvb, packet_info * pinfo, proto_tree *tree, void* data _U_)
{
    struct ip6_shim  shim;
    int              offset = 0, len;
    gint             p;
    proto_tree      *shim_tree;
    proto_item      *ti;
    guint8           tmp[5];
    ipv6_meta_t     *ipv6_info;

    ipv6_info = (ipv6_meta_t *)p_get_proto_data(pinfo->pool, pinfo, proto_ipv6, IPV6_PROTO_META);

    tvb_memcpy(tvb, (guint8 *)&shim, offset, sizeof(shim));
    len = (shim.ip6s_len + 1) << 3;

    if (shim.ip6s_p & SHIM6_BITMASK_P) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, " , ", "Shim6 (Payload)");
    }
    else {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, " , ", "Shim6 (%s)",
                        val_to_str_const(shim.ip6s_p & SHIM6_BITMASK_TYPE, shimctrlvals, "Unknown"));
    }

    ti = proto_tree_add_item(tree, proto_ipv6_shim6, tvb, offset, len, ENC_NA);
    shim_tree = proto_item_add_subtree(ti, ett_ipv6_shim6);

    /* Next Header */
    proto_tree_add_uint_format_value(shim_tree, hf_ipv6_shim6_nxt, tvb,
                                     offset + (int)offsetof(struct ip6_shim, ip6s_nxt), 1, shim.ip6s_nxt,
                                     "%s (%u)", ipprotostr(shim.ip6s_nxt), shim.ip6s_nxt);

    /* Header Extension Length */
    proto_tree_add_uint_format_value(shim_tree, hf_ipv6_shim6_len, tvb,
                                     offset + (int)offsetof(struct ip6_shim, ip6s_len), 1, shim.ip6s_len,
                                     "%u (%d bytes)", shim.ip6s_len, len);

    /* P Field */
    proto_tree_add_item(shim_tree, hf_ipv6_shim6_p, tvb,
                        offset + (int)offsetof(struct ip6_shim, ip6s_p), 1, ENC_BIG_ENDIAN);

    /* skip the first 2 bytes (nxt hdr, hdr ext len, p+7bits) */
    p = offset + 3;

    if (shim.ip6s_p & SHIM6_BITMASK_P) {
        tmp[0] = tvb_get_guint8(tvb, p++);
        tmp[1] = tvb_get_guint8(tvb, p++);
        tmp[2] = tvb_get_guint8(tvb, p++);
        tmp[3] = tvb_get_guint8(tvb, p++);
        tmp[4] = tvb_get_guint8(tvb, p++);

        /* Payload Extension Header */
        proto_tree_add_none_format(shim_tree, hf_ipv6_shim6_ct, tvb,
                                   offset + (int)offsetof(struct ip6_shim, ip6s_p), 6,
                                   "Receiver Context Tag: %02x %02x %02x %02x %02x %02x",
                                   shim.ip6s_p & SHIM6_BITMASK_CT, tmp[0], tmp[1], tmp[2], tmp[3], tmp[4]);
    } else {
        /* Control Message */
        guint16 csum;
        int advance;

        /* Message Type */
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_type, tvb,
                            offset + (int)offsetof(struct ip6_shim, ip6s_p), 1,
                            ENC_BIG_ENDIAN
            );

        /* Protocol bit (Must be zero for SHIM6) */
        proto_tree_add_item(shim_tree, hf_ipv6_shim6_proto, tvb, p, 1, ENC_BIG_ENDIAN);
        p++;

        /* Checksum */
        csum = shim6_checksum(tvb, offset, len);

        if (csum == 0) {
            ti = proto_tree_add_uint_format_value(shim_tree, hf_ipv6_shim6_checksum, tvb, p, 2,
                                                  tvb_get_ntohs(tvb, p), "0x%04x [correct]", tvb_get_ntohs(tvb, p));
            add_shim6_checksum_additional_info(tvb, pinfo, ti, p, TRUE);
        } else {
            ti = proto_tree_add_uint_format_value(shim_tree, hf_ipv6_shim6_checksum, tvb, p, 2,
                                                  tvb_get_ntohs(tvb, p), "0x%04x [incorrect: should be 0x%04x]",
                                                  tvb_get_ntohs(tvb, p), in_cksum_shouldbe(tvb_get_ntohs(tvb, p), csum));
            add_shim6_checksum_additional_info(tvb, pinfo, ti, p, FALSE);
        }
        p += 2;

        /* Type specific data */
        advance = dissect_shimctrl(tvb, p, shim.ip6s_p & SHIM6_BITMASK_TYPE, shim_tree);
        p += advance;

        /* Options */
        while (p < offset+len) {
            p += dissect_shimopts(tvb, p, shim_tree, pinfo);
        }
    }

    ipv6_info->exthdr_count++;
    return len;
}

/* END SHIM6 PART */

static int
dissect_ipv6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree    *ipv6_tree, *ipv6_exthdr_tree, *pt;
    proto_item    *ipv6_item, *ti, *pi;
    proto_item    *ti_ipv6_plen = NULL, *ti_ipv6_version;
    guint8         nxt, tfc;
    int            advance;
    guint32        plen;
    guint16        frag_off;
    gboolean       frag_flg;
    guint32        frag_ident;
    int            offset;
    fragment_head *ipfd_head;
    tvbuff_t      *next_tvb, *options_tvb;
    gboolean       update_col_info = TRUE;
    gboolean       save_fragmented;
    gboolean       show_data = FALSE;
    guint8        *mac_addr;
    const char    *name;
    dissector_handle_t nxt_handle;
    address        addr;
    ipv6_meta_t   *ipv6_info;
    int version;

    /* Provide as much IPv4 header information as possible as some dissectors
       in the ip.proto dissector table may need it */
    ws_ip iph;

    struct ip6_hdr *ipv6;

    offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPv6");
    col_clear(pinfo->cinfo, COL_INFO);
    ipv6_item = proto_tree_add_item(tree, proto_ipv6, tvb, offset,
                    ipv6_exthdr_under_root ? IPv6_HDR_SIZE : -1, ENC_NA);

    if (tvb_reported_length(tvb) < IPv6_HDR_SIZE) {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                 "Invalid IPv6 header (%u bytes, need exactly 40)",
                 tvb_reported_length(tvb));
        expert_add_info(pinfo, ipv6_item, &ei_ipv6_invalid_header);
        return tvb_captured_length(tvb);
    }

    ipv6_tree = proto_item_add_subtree(ipv6_item, ett_ipv6);

    memset(&iph, 0, sizeof(iph));
    ipv6 = (struct ip6_hdr*)tvb_memdup(wmem_packet_scope(), tvb, offset, sizeof(struct ip6_hdr));

    version = hi_nibble(ipv6->ip6_vfc);
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

    tfc = IPv6_HDR_TCLS(ipv6);
    col_add_fstr(pinfo->cinfo, COL_DSCP_VALUE, "%u", IPDSFIELD_DSCP(tfc));

    /* Get extension header and payload length */
    plen = g_ntohs(ipv6->ip6_plen);

    set_address_tvb(&pinfo->net_src, AT_IPv6, 16, tvb, offset + IP6H_SRC);
    copy_address_shallow(&pinfo->src, &pinfo->net_src);
    set_address_tvb(&pinfo->net_dst, AT_IPv6, 16, tvb, offset + IP6H_DST);
    copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

    ipv6_info = wmem_new0(wmem_packet_scope(), ipv6_meta_t);
    p_add_proto_data(pinfo->pool, pinfo, proto_ipv6, IPV6_PROTO_META, ipv6_info);

    if (tree) {
        /* !!! warning: (4-bit) version, (6-bit) DSCP, (2-bit) ECN and (20-bit) Flow */


        ti = proto_tree_add_item(ipv6_tree, hf_ipv6_tclass, tvb,
                            offset + IP6H_CTL_FLOW, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, " (DSCP: %s, ECN: %s)",
                            val_to_str_ext_const(IPDSFIELD_DSCP(tfc), &dscp_short_vals_ext, "Unknown"),
                            val_to_str_ext_const(IPDSFIELD_ECN(tfc), &ecn_short_vals_ext, "Unknown"));
        pt = proto_item_add_subtree(ti, ett_ipv6_traffic_class);
        proto_tree_add_item(pt, hf_ipv6_tclass_dscp, tvb,
                            offset + IP6H_CTL_FLOW, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(pt, hf_ipv6_tclass_ecn, tvb,
                            offset + IP6H_CTL_FLOW, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(ipv6_tree, hf_ipv6_flow, tvb,
                            offset + IP6H_CTL_FLOW, 4, ENC_BIG_ENDIAN);

        ti_ipv6_plen = proto_tree_add_item(ipv6_tree, hf_ipv6_plen, tvb,
                            offset + IP6H_CTL_PLEN, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ipv6_tree, hf_ipv6_nxt, tvb, offset + IP6H_CTL_NXT, 1, ENC_NA);

        proto_tree_add_item(ipv6_tree, hf_ipv6_hlim, tvb,
                            offset + IP6H_CTL_HLIM, 1, ENC_BIG_ENDIAN);

        /* Add the different items for the source address */
        proto_tree_add_item(ipv6_tree, hf_ipv6_src, tvb,
                            offset + IP6H_SRC, 16, ENC_NA);
        ti = proto_tree_add_ipv6(ipv6_tree, hf_ipv6_addr, tvb,
                                 offset + IP6H_SRC,
                                 16, &ipv6->ip6_src);
        PROTO_ITEM_SET_HIDDEN(ti);
        name = address_to_display(wmem_packet_scope(), &pinfo->src);
        if (ipv6_summary_in_tree) {
            set_address(&addr, AT_IPv6, 16, ipv6->ip6_src.bytes);
            proto_item_append_text(ipv6_item, ", Src: %s", address_with_resolution_to_str(wmem_packet_scope(), &addr));
        }
        ti = proto_tree_add_string(ipv6_tree, hf_ipv6_src_host, tvb,
                                   offset + IP6H_SRC,
                                   16, name);
        PROTO_ITEM_SET_GENERATED(ti);
        PROTO_ITEM_SET_HIDDEN(ti);
        ti = proto_tree_add_string(ipv6_tree, hf_ipv6_host, tvb,
                                   offset + IP6H_SRC,
                                   16, name);
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
                            offset + IP6H_DST, 16, ENC_NA);
        ti = proto_tree_add_ipv6(ipv6_tree, hf_ipv6_addr, tvb,
                                 offset + IP6H_DST,
                                 16, &ipv6->ip6_dst);
        PROTO_ITEM_SET_HIDDEN(ti);
        name = address_to_display(wmem_packet_scope(), &pinfo->dst);
        if (ipv6_summary_in_tree) {
            set_address(&addr, AT_IPv6, 16, ipv6->ip6_dst.bytes);
            proto_item_append_text(ipv6_item, ", Dst: %s", address_with_resolution_to_str(wmem_packet_scope(), &addr));
        }
        ti = proto_tree_add_string(ipv6_tree, hf_ipv6_dst_host, tvb,
                                   offset + IP6H_DST,
                                   16, name);
        PROTO_ITEM_SET_GENERATED(ti);
        PROTO_ITEM_SET_HIDDEN(ti);
        ti = proto_tree_add_string(ipv6_tree, hf_ipv6_host, tvb,
                                   offset + IP6H_DST,
                                   16, name);
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

#ifdef HAVE_GEOIP_V6
    if (tree && ipv6_use_geoip) {
        add_geoip_info(ipv6_tree, tvb, offset, &ipv6->ip6_src, &ipv6->ip6_dst);
    }
#endif
    /* Fill in IPv4 fields for potential subdissectors */
    iph.ip_v_hl = (tvb_get_guint8(tvb, offset + IP6H_CTL_VFC) >> 4) & 0x0F;
    iph.ip_tos = (guint8)((tvb_get_ntohl(tvb, offset + IP6H_CTL_FLOW) >> 20) & 0xFF);
    iph.ip_len = tvb_get_ntohs(tvb, offset + IP6H_CTL_PLEN);
    /* Yes, there is not TTL in IPv6 Header... but it is the same of Hop Limit...*/
    iph.ip_ttl = tvb_get_guint8(tvb, offset + IP6H_CTL_HLIM);

    if (ipv6_exthdr_under_root) {
        ipv6_exthdr_tree = tree;
    } else {
        ipv6_exthdr_tree = ipv6_tree;
    }

    /* start of the new header (could be a extension header) */
    nxt = tvb_get_guint8(tvb, offset + 6);
    /* Save next header value for Decode As dialog */
    p_add_proto_data(pinfo->pool, pinfo, proto_ipv6, (pinfo->curr_layer_num<<8) | IPV6_PROTO_NXT_HDR, GUINT_TO_POINTER((guint)nxt));
    offset += (int)sizeof(struct ip6_hdr);
    advance = 0;

    if (nxt == IP_PROTO_HOPOPTS) {
        options_tvb = tvb_new_subset_remaining(tvb, offset);
        advance = dissect_hopopts(options_tvb, pinfo, ipv6_exthdr_tree, &iph);
        if (advance > 0) {
            nxt = tvb_get_guint8(tvb, offset);
            offset += advance;
            if (ipv6_info->jumbogram) {
                if (ti_ipv6_plen) {
                    proto_item_append_text(ti_ipv6_plen, " (Jumbogram)");
                }
                plen = ipv6_info->jumbo_length;
                if (plen == 0) {
                    col_add_fstr(pinfo->cinfo, COL_INFO, "Bogus IPv6 jumbo length");
                    return tvb_captured_length(tvb);
                }
            } else if (plen == 0) {
                /* IPv6 length zero is invalid if there is a hop-by-hop header without jumbo option */
                col_add_fstr(pinfo->cinfo, COL_INFO, "Invalid IPv6 payload length");
                if (ti_ipv6_plen) {
                    expert_add_info(pinfo, ti_ipv6_plen, &ei_ipv6_opt_jumbo_missing);
                }
                return tvb_captured_length(tvb);
            } else if (plen < (guint32)advance) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "Bogus IPv6 payload length");
                if (ti_ipv6_plen) {
                    proto_item_append_text(ti_ipv6_plen, " (Bogus, less than hop-by-hop extension header length)");
                    expert_add_info(pinfo, ti_ipv6_plen, &ei_ipv6_bogus_ipv6_length);
                }
                return tvb_captured_length(tvb);
            }
        }
    }
    if (plen == (guint32)advance && nxt != IP_PROTO_NONE) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Bogus IPv6 payload length");
        if (ti_ipv6_plen) {
            proto_item_append_text(ti_ipv6_plen, " (Bogus, next header is %s)", ipprotostr(nxt));
            expert_add_info(pinfo, ti_ipv6_plen, &ei_ipv6_bogus_ipv6_length);
        }
        return tvb_captured_length(tvb);
    }
    if (plen > (tvb_reported_length(tvb) - 40)) {
        expert_add_info_format(pinfo, ti_ipv6_plen, &ei_ipv6_bogus_payload_length,
                    "IPv6 payload length exceeds framing length (%d bytes)",
                    tvb_reported_length(tvb) - 40);
    }
    /* Adjust the length of this tvbuff to include only the IPv6 datagram. */
    set_actual_length(tvb, plen + (guint)sizeof (struct ip6_hdr));
    plen -= advance;
    save_fragmented = pinfo->fragmented;

again:

    /* Get a tvbuff for the options. */
    options_tvb = tvb_new_subset_remaining(tvb, offset);
    nxt_handle = dissector_get_uint_handle(ipv6_next_header_dissector_table, nxt);

    if ((nxt_handle) &&
        ((advance = call_dissector_with_data(nxt_handle, options_tvb, pinfo, ipv6_exthdr_tree, &iph)) > 0)) {
        nxt = tvb_get_guint8(tvb, offset);
        offset += advance;
        plen -= advance;
        goto again;
    } else {
        switch (nxt) {
        case IP_PROTO_FRAGMENT:
            advance = dissect_frag6(tvb, offset, pinfo, ipv6_exthdr_tree,
                                    &frag_off, &frag_flg, &frag_ident);
            nxt = tvb_get_guint8(tvb, offset);
            offset += advance;
            plen -= advance;
            if ((frag_off == 0) && !frag_flg) {
                goto again;
            }
            pinfo->fragmented = TRUE;
            if (ipv6_reassemble) {
                /* reassembling */
                if (tvb_bytes_exist(tvb, offset, plen)) {
                    ipfd_head = fragment_add_check(&ipv6_reassembly_table,
                                                   tvb, offset, pinfo, frag_ident, NULL,
                                                   frag_off, plen, frag_flg);
                    next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled IPv6",
                                                        ipfd_head, &ipv6_frag_items, &update_col_info, ipv6_tree);
                    if (next_tvb) {  /* Process post-fragment headers after reassembly... */
                        offset = 0;
                        tvb = next_tvb;
                        pinfo->fragmented = FALSE;
                        goto again;
                    }
                }
            }
            else {
                /* not reassembling */
                if (frag_off == 0) /* ... or in the first fragment */
                    goto again;
            }
            show_data = TRUE;
            break;
        case IP_PROTO_NONE:
            col_set_str(pinfo->cinfo, COL_INFO, "IPv6 no next header");
            show_data = TRUE;
            break;

        default:
            if ((ipv6extprotostr(nxt) != NULL) &&
                        !dissector_get_uint_handle(ip_dissector_table, nxt)) {
                advance = dissect_unknown_exthdr(tvb, offset, ipv6_exthdr_tree);
                nxt = tvb_get_guint8(tvb, offset);
                offset += advance;
                plen -= advance;
                ipv6_info->exthdr_count++;
                goto again;
            }
        }
    }

    if (!ipv6_exthdr_under_root) {
        proto_item_set_len (ipv6_item, offset);
    }
    iph.ip_p = nxt;

    /* collect packet info */
    p_add_proto_data(pinfo->pool, pinfo, proto_ipv6, (pinfo->curr_layer_num<<8) | IPV6_PROTO_VALUE, GUINT_TO_POINTER((guint)nxt));
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
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s (%u)", ipprotostr(nxt), nxt);
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

        { &hf_ipv6_unknown_hdr,
            { "Unknown Extension Header", "ipv6.unknown_hdr",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_unknown_hdr_nxt,
            { "Next Header", "ipv6.unknown_hdr.nxt",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_unknown_hdr_length,
            { "Length", "ipv6.unknown_hdr.length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Extension Header Length", HFILL }
        },
        { &hf_ipv6_opt,
            { "IPv6 Option", "ipv6.opt",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Option", HFILL }
        },
        { &hf_ipv6_opt_type,
            { "Type", "ipv6.opt.type",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipv6_opt_vals_ext, 0x0,
                "Option type", HFILL }
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
        },
        { &hf_ipv6_padding,
            { "Padding", "ipv6.padding",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        }
    };

    static hf_register_info hf_ipv6_hopopts[] = {
        { &hf_ipv6_hopopts_nxt,
            { "Next Header", "ipv6.hopopts.nxt",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_hopopts_length,
            { "Length", "ipv6.hopopts.length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Extension Header Length", HFILL }
        }
    };

    static hf_register_info hf_ipv6_routing[] = {

        /* IPv6 Routing Header */
        { &hf_ipv6_routing_nxt,
            { "Next Header", "ipv6.routing.nxt",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_routing_length,
            { "Length", "ipv6.routing.length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Extension Header Length", HFILL }
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

    static hf_register_info hf_ipv6_shim6[] = {
        { &hf_ipv6_shim6_nxt,
            { "Next Header", "ipv6.shim6.nxt",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_shim6_len,
            { "Length", "ipv6.shim6.length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Extension Header Length", HFILL }
        },
        { &hf_ipv6_shim6_p,
            { "P Bit", "ipv6.shim6.p",
                FT_BOOLEAN, 8, NULL, SHIM6_BITMASK_P,
                NULL, HFILL }
        },
        { &hf_ipv6_shim6_ct,
            { "Context Tag", "ipv6.shim6.ct",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_shim6_type,
            { "Message Type", "ipv6.shim6.type",
                FT_UINT8, BASE_DEC, VALS(shimctrlvals), SHIM6_BITMASK_TYPE,
                NULL, HFILL }
        },
        { &hf_ipv6_shim6_proto,
            { "Protocol", "ipv6.shim6.proto",
                FT_UINT8, BASE_DEC, VALS(shim6_protocol), SHIM6_BITMASK_PROTOCOL,
                NULL, HFILL }
        },
        { &hf_ipv6_shim6_checksum,
            { "Checksum", "ipv6.shim6.checksum",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                "Shim6 Checksum", HFILL }
        },
        { &hf_ipv6_shim6_checksum_bad,
            { "Bad Checksum", "ipv6.shim6.checksum_bad",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Shim6 Bad Checksum", HFILL }
        },
        { &hf_ipv6_shim6_checksum_good,
            { "Good Checksum", "ipv6.shim6.checksum_good",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_shim6_inonce,
            { "Initiator Nonce", "ipv6.shim6.inonce",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_shim6_rnonce,
            { "Responder Nonce", "ipv6.shim6.rnonce",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_shim6_reserved,
            { "Reserved", "ipv6.shim6.reserved",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_shim6_reserved2,
            { "Reserved2", "ipv6.shim6.reserved2",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_shim6_precvd,
            { "Probes Received", "ipv6.shim6.precvd",
                FT_UINT8, BASE_DEC, NULL, SHIM6_BITMASK_PRECVD,
                NULL, HFILL }
        },
        { &hf_ipv6_shim6_psent,
            { "Probes Sent", "ipv6.shim6.psent",
                FT_UINT8, BASE_DEC, NULL, SHIM6_BITMASK_PSENT,
                NULL, HFILL }
        },
        { &hf_ipv6_shim6_psrc,
            { "Source Address", "ipv6.shim6.psrc",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Shim6 Probe Source Address", HFILL }
        },
        { &hf_ipv6_shim6_pdst,
            { "Destination Address", "ipv6.shim6.pdst",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Shim6 Probe Destination Address", HFILL }
        },
        { &hf_ipv6_shim6_pnonce,
            { "Nonce", "ipv6.shim6.pnonce",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
                "Shim6 Probe Nonce", HFILL }
        },
        { &hf_ipv6_shim6_pdata,
            { "Data", "ipv6.shim6.pdata",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                "Shim6 Probe Data", HFILL }
        },
        { &hf_ipv6_shim6_sulid,
            { "Sender ULID", "ipv6.shim6.sulid",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Shim6 Sender ULID", HFILL }
        },
        { &hf_ipv6_shim6_rulid,
            { "Receiver ULID", "ipv6.shim6.rulid",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Shim6 Receiver ULID", HFILL }
        },
        { &hf_ipv6_shim6_reap,
            { "REAP State", "ipv6.shim6.reap",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_shim6_opt_type,
            { "Option Type", "ipv6.shim6.opt.type",
                FT_UINT16, BASE_DEC, VALS(shimoptvals), SHIM6_BITMASK_OPT_TYPE,
                "Shim6 Option Type", HFILL }
        },
        { &hf_ipv6_shim6_opt_critical,
            { "Option Critical Bit", "ipv6.shim6.opt.critical",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), SHIM6_BITMASK_CRITICAL,
                "TRUE: option is critical, FALSE: option is not critical", HFILL }
        },
        { &hf_ipv6_shim6_opt_len,
            { "Content Length", "ipv6.shim6.opt.len",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Content Length Option", HFILL }
        },
        { &hf_ipv6_shim6_opt_total_len,
            { "Total Length", "ipv6.shim6.opt.total_len",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Total Option Length", HFILL }
        },
        { &hf_ipv6_shim6_opt_loc_verif_methods,
            { "Verification Method", "ipv6.shim6.opt.verif_method",
                FT_UINT8, BASE_DEC, VALS(shimverifmethods), 0x0,
                "Locator Verification Method", HFILL }
        },
        { &hf_ipv6_shim6_opt_loclist,
            { "Locator List Generation", "ipv6.shim6.opt.loclist",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_shim6_locator,
            { "Locator", "ipv6.shim6.locator",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Shim6 Locator", HFILL }
        },
        { &hf_ipv6_shim6_opt_locnum,
            { "Num Locators", "ipv6.shim6.opt.locnum",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Number of locators in Locator List", HFILL }
        },
        { &hf_ipv6_shim6_opt_elemlen,
            { "Element Length", "ipv6.shim6.opt.elemlen",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Length of Elements in Locator Preferences Option", HFILL }
        },
        { &hf_ipv6_shim6_loc_flag,
            { "Flags", "ipv6.shim6.loc.flags",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Locator Preferences Flags", HFILL }
        },
        { &hf_ipv6_shim6_loc_prio,
            { "Priority", "ipv6.shim6.loc.prio",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Locator Preferences Priority", HFILL }
        },
        { &hf_ipv6_shim6_loc_weight,
            { "Weight", "ipv6.shim6.loc.weight",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Locator Preferences Weight", HFILL }
        },
        { &hf_ipv6_shim6_opt_fii,
            { "Forked Instance Identifier", "ipv6.shim6.opt.fii",
                FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_shim6_validator,
            { "Validator", "ipv6.shim6.validator",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_shim6_cga_parameter_data_structure,
            { "CGA Parameter Data Structure", "ipv6.shim6.cga_parameter_data_structure",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_shim6_cga_signature,
            { "CGA Signature", "ipv6.shim6.cga_signature",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        }
    };

    static hf_register_info hf_ipv6_dstopts[] = {
        { &hf_ipv6_dstopts_nxt,
            { "Next Header", "ipv6.dstopts.nxt",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_dstopts_length,
            { "Length", "ipv6.dstopts.length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Extension Header Length", HFILL }
        }
    };

    static gint *ett[] = {
        &ett_ipv6,
        &ett_ipv6_opt,
        &ett_ipv6_opt_rpl,
        &ett_ipv6_opt_mpl,
        &ett_ipv6_fraghdr,
        &ett_ipv6_routing,
        &ett_ipv6_shim6,
        &ett_ipv6_shim6_option,
        &ett_ipv6_shim6_locators,
        &ett_ipv6_shim6_verif_methods,
        &ett_ipv6_shim6_loc_pref,
        &ett_ipv6_shim6_probes_sent,
        &ett_ipv6_shim6_probes_rcvd,
        &ett_ipv6_shim6_probe_sent,
        &ett_ipv6_shim6_probe_rcvd,
        &ett_ipv6_shim6_cksum,
        &ett_ipv6_fragment,
        &ett_ipv6_fragments,
        &ett_ipv6_traffic_class,
#ifdef HAVE_GEOIP_V6
        &ett_geoip_info
#endif /* HAVE_GEOIP_V6 */
    };

    static ei_register_info ei[] = {
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
        { &ei_ipv6_opt_tel_invalid_len,
            { "ipv6.opt.tel.invalid_len", PI_MALFORMED, PI_ERROR,
                "Tunnel Encapsulation Limit: Invalid length", EXPFILL }
        },
        { &ei_ipv6_opt_jumbo_invalid_len,
            { "ipv6.opt.jumbo.invalid_len", PI_MALFORMED, PI_ERROR,
                "Jumbo Payload: Invalid length", EXPFILL }
        },
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
        { &ei_ipv6_opt_rtalert_invalid_len,
            { "ipv6.opt.router_alert.invalid_len", PI_MALFORMED, PI_ERROR,
                "Router alert: Invalid Length", EXPFILL }
        },
        { &ei_ipv6_opt_unknown_data,
            { "ipv6.opt.unknown_data.expert", PI_UNDECODED, PI_NOTE,
                "Unknown Data (not interpreted)", EXPFILL }
        },
        { &ei_ipv6_mipv6_home_address_invalid_len,
            { "ipv6.mipv6_home_address.invalid_len", PI_MALFORMED, PI_ERROR,
                "Home Address: Invalid length", EXPFILL }
        },
        { &ei_ipv6_shim6_opt_elemlen_invalid,
            { "ipv6.shim6.opt.elemlen.invalid", PI_MALFORMED, PI_ERROR,
                "Invalid element length", EXPFILL }
        },
        { &ei_ipv6_shim6_checksum_bad,
            { "ipv6.shim6.checksum_bad.expert", PI_CHECKSUM, PI_ERROR,
                "Bad checksum", EXPFILL }
        },
        { &ei_ipv6_hopopts_not_first,
            { "ipv6.hopopts.not_first", PI_PROTOCOL, PI_ERROR,
                "IPv6 Hop-by-Hop extension header must appear immediately after IPv6 header", EXPFILL }
        },
        { &ei_ipv6_bogus_ipv6_length,
            { "ipv6.bogus_ipv6_length", PI_PROTOCOL, PI_ERROR,
                "Bogus IPv6 length", EXPFILL }
        },
        { &ei_ipv6_bogus_payload_length,
            { "ipv6.bogus_payload_length", PI_PROTOCOL, PI_WARN,
                "IPv6 payload length does not match expected framing length", EXPFILL }
        },
        { &ei_ipv6_bogus_ipv6_version,
            { "ipv6.bogus_ipv6_version", PI_PROTOCOL, PI_ERROR,
                "Bogus IP version", EXPFILL }
            },
        { &ei_ipv6_invalid_header,
            { "ipv6.invalid_header", PI_MALFORMED, PI_ERROR,
                "IPv6 header must be exactly 40 bytes", EXPFILL }
        },
        { &ei_ipv6_routing_invalid_length,
            { "ipv6.routing.invalid_length", PI_MALFORMED, PI_ERROR,
                "Invalid IPv6 Routing header length", EXPFILL }
            },
        { &ei_ipv6_routing_invalid_segleft,
            { "ipv6.routing.invalid_segleft", PI_PROTOCOL, PI_ERROR,
                "IPv6 Routing Header segments left field must not exceed address count", EXPFILL }
        },
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

    proto_ipv6 = proto_register_protocol("Internet Protocol Version 6", "IPv6", "ipv6");
    proto_register_field_array(proto_ipv6, hf_ipv6, array_length(hf_ipv6));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ipv6 = expert_register_protocol(proto_ipv6);
    expert_register_field_array(expert_ipv6, ei, array_length(ei));

    proto_ipv6_hopopts = proto_register_protocol("IPv6 Hop-by-Hop Option", "IPv6 Hop-by-Hop", "ipv6.hopopts");
    proto_ipv6_routing = proto_register_protocol("Routing Header for IPv6", "IPv6 Routing", "ipv6.routing");
    proto_ipv6_fraghdr = proto_register_protocol("Fragment Header for IPv6", "IPv6 Fragment", "ipv6.fraghdr");
    proto_ipv6_shim6 = proto_register_protocol("Shim6 Protocol", "Shim6", "ipv6.shim6");
    proto_ipv6_dstopts = proto_register_protocol("Destination Options for IPv6", "IPv6 Destination", "ipv6.dstopts");

    proto_register_field_array(proto_ipv6_hopopts, hf_ipv6_hopopts, array_length(hf_ipv6_hopopts));
    proto_register_field_array(proto_ipv6_routing, hf_ipv6_routing, array_length(hf_ipv6_routing));
    proto_register_field_array(proto_ipv6_fraghdr, hf_ipv6_fraghdr, array_length(hf_ipv6_fraghdr));
    proto_register_field_array(proto_ipv6_shim6, hf_ipv6_shim6, array_length(hf_ipv6_shim6));
    proto_register_field_array(proto_ipv6_dstopts, hf_ipv6_dstopts, array_length(hf_ipv6_dstopts));

    ipv6_next_header_dissector_table = register_dissector_table("ipv6.nxt", "IPv6 Next Header", proto_ipv6, FT_UINT32, BASE_DEC, DISSECTOR_TABLE_NOT_ALLOW_DUPLICATE);
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
                                   "Whether to check that all RPL Source Routing Headers adhere to RFC 6554",
                                   &g_ipv6_rpl_srh_strict_rfc_checking);

    prefs_register_bool_preference(ipv6_module, "try_heuristic_first",
                                   "Try heuristic sub-dissectors first",
                                   "Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to a specific port",
                                   &try_heuristic_first);

    prefs_register_bool_preference(ipv6_module, "exthdr_under_root_protocol_tree",
                                   "Display IPv6 extension headers under the root protocol tree",
                                   "Whether to display IPv6 extension headers as a separate protocol or a sub-protocol of the IPv6 packet",
                                   &ipv6_exthdr_under_root);

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
    dissector_handle_t ipv6_hopopts_handle, ipv6_routing_handle,
                       ipv6_shim6_handle, ipv6_dstopts_handle;

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

    dissector_add_for_decode_as("udp.port", ipv6_handle);

    ipv6_hopopts_handle = create_dissector_handle(dissect_hopopts, proto_ipv6_hopopts );
    dissector_add_uint("ipv6.nxt", IP_PROTO_HOPOPTS, ipv6_hopopts_handle);
    ipv6_routing_handle = create_dissector_handle(dissect_routing6, proto_ipv6_routing );
    dissector_add_uint("ipv6.nxt", IP_PROTO_ROUTING, ipv6_routing_handle);
    ipv6_shim6_handle = create_dissector_handle(dissect_shim6, proto_ipv6_shim6 );
    dissector_add_uint("ipv6.nxt", IP_PROTO_SHIM6, ipv6_shim6_handle);
    ipv6_dstopts_handle = create_dissector_handle(dissect_dstopts, proto_ipv6_dstopts );
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
