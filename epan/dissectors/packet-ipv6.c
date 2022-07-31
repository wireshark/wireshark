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
 * Added support for new IPv6 Hop by Hop PMTU Option  <bob.hinden@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <math.h>
#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/expert.h>
#include <epan/ip_opts.h>
#include <epan/addr_resolv.h>
#include <epan/maxmind_db.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/conversation_table.h>
#include <epan/conversation_filter.h>
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
#include <epan/exported_pdu.h>

#include <wiretap/erf_record.h>
#include <wsutil/str_util.h>
#include "packet-ip.h"
#include "packet-juniper.h"
#include "packet-sflow.h"
#include "packet-vxlan.h"
#include "packet-mpls.h"
#include "packet-nsh.h"

void proto_register_ipv6(void);
void proto_reg_handoff_ipv6(void);

/* Offsets of fields within an IPv6 header. */
#define IP6H_CTL_VFC    0
#define IP6H_CTL_FLOW   0
#define IP6H_CTL_PLEN   4
#define IP6H_CTL_NXT    6
#define IP6H_CTL_HLIM   7
#define IP6H_SRC        8
#define IP6H_DST        24

/* Option types and related macros */
#define IP6OPT_PAD1                     0x00    /* 00 0 00000 =   0 */
#define IP6OPT_PADN                     0x01    /* 00 0 00001 =   1 */
#define IP6OPT_TEL                      0x04    /* 00 0 00100 =   4 */
#define IP6OPT_RTALERT                  0x05    /* 00 0 00101 =   5 */
#define IP6OPT_CALIPSO                  0x07    /* 00 0 00111 =   7 */
#define IP6OPT_SMF_DPD                  0x08    /* 00 0 01000 =   8 */
#define IP6OPT_PDM                      0x0F    /* 00 0 01111 =  15 */
#define IP6OPT_EXP_1E                   0x1E    /* 00 0 11110 =  30 */
#define IP6OPT_QUICKSTART               0x26    /* 00 1 00110 =  38 */
#define IP6OPT_PMTU                     0x30    /* 00 1 10000 =  48 */
#define IP6OPT_IOAM                     0x31    /* 00 1 10001 =  49 */
#define IP6OPT_EXP_3E                   0x3E    /* 00 1 11110 =  62 */
#define IP6OPT_TPF                      0x41    /* 01 0 00001 =  65 */
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

/* IOAM Option-Types */
#define IP6IOAM_PRE_TRACE               0       /* Pre-allocated Trace */
#define IP6IOAM_INC_TRACE               1       /* Incremental Trace */
#define IP6IOAM_POT                     2       /* Proof of Transit */
#define IP6IOAM_E2E                     3       /* Edge to Edge */

/* IOAM Trace Types */
#define IP6IOAM_TRACE_MASK_BIT0         (1 << 23) /* Hop_lim + Node ID */
#define IP6IOAM_TRACE_MASK_BIT1         (1 << 22) /* Ingress and Egress IDs */
#define IP6IOAM_TRACE_MASK_BIT2         (1 << 21) /* Timestamp seconds */
#define IP6IOAM_TRACE_MASK_BIT3         (1 << 20) /* Timestamp fraction */
#define IP6IOAM_TRACE_MASK_BIT4         (1 << 19) /* Transit delay */
#define IP6IOAM_TRACE_MASK_BIT5         (1 << 18) /* IOAM-Namespace data */
#define IP6IOAM_TRACE_MASK_BIT6         (1 << 17) /* Queue depth */
#define IP6IOAM_TRACE_MASK_BIT7         (1 << 16) /* Checksum complement */
#define IP6IOAM_TRACE_MASK_BIT8         (1 << 15) /* (wide) Hop_lim + Node ID */
#define IP6IOAM_TRACE_MASK_BIT9         (1 << 14) /* (wide) Ingress and Egress IDs */
#define IP6IOAM_TRACE_MASK_BIT10        (1 << 13) /* (wide) IOAM-Namespace data */
#define IP6IOAM_TRACE_MASK_BIT11        (1 << 12) /* Buffer occupancy */
#define IP6IOAM_TRACE_MASK_BIT12        (1 << 11) /* Undefined */
#define IP6IOAM_TRACE_MASK_BIT13        (1 << 10) /* Undefined */
#define IP6IOAM_TRACE_MASK_BIT14        (1 <<  9) /* Undefined */
#define IP6IOAM_TRACE_MASK_BIT15        (1 <<  8) /* Undefined */
#define IP6IOAM_TRACE_MASK_BIT16        (1 <<  7) /* Undefined */
#define IP6IOAM_TRACE_MASK_BIT17        (1 <<  6) /* Undefined */
#define IP6IOAM_TRACE_MASK_BIT18        (1 <<  5) /* Undefined */
#define IP6IOAM_TRACE_MASK_BIT19        (1 <<  4) /* Undefined */
#define IP6IOAM_TRACE_MASK_BIT20        (1 <<  3) /* Undefined */
#define IP6IOAM_TRACE_MASK_BIT21        (1 <<  2) /* Undefined */
#define IP6IOAM_TRACE_MASK_BIT22        (1 <<  1) /* Opaque state snapshot */

/* Protocol specific data indices */
#define IPV6_PROTO_VALUE            1
#define IPV6_PROTO_PINFO            2

static int ipv6_tap  = -1;

static int exported_pdu_tap = -1;

static int proto_ipv6                           = -1;
static int proto_ipv6_hopopts                   = -1;
static int proto_ipv6_routing                   = -1;
static int proto_ipv6_fraghdr                   = -1;
static int proto_ipv6_dstopts                   = -1;

static int proto_ipv6_routing_rt0               = -1;
static int proto_ipv6_routing_mipv6             = -1;
static int proto_ipv6_routing_rpl               = -1;
static int proto_ipv6_routing_srh               = -1;
static int proto_ipv6_routing_crh               = -1;

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
static int hf_ipv6_src_slaac_mac                = -1;
static int hf_ipv6_src_isatap_ipv4              = -1;
static int hf_ipv6_src_6to4_gateway_ipv4        = -1;
static int hf_ipv6_src_6to4_sla_id              = -1;
static int hf_ipv6_src_teredo_server_ipv4       = -1;
static int hf_ipv6_src_teredo_port              = -1;
static int hf_ipv6_src_teredo_client_ipv4       = -1;
static int hf_ipv6_src_embed_ipv4               = -1;
static int hf_ipv6_dst                          = -1;
static int hf_ipv6_dst_host                     = -1;
static int hf_ipv6_dst_slaac_mac                = -1;
static int hf_ipv6_dst_isatap_ipv4              = -1;
static int hf_ipv6_dst_6to4_gateway_ipv4        = -1;
static int hf_ipv6_dst_6to4_sla_id              = -1;
static int hf_ipv6_dst_teredo_server_ipv4       = -1;
static int hf_ipv6_dst_teredo_port              = -1;
static int hf_ipv6_dst_teredo_client_ipv4       = -1;
static int hf_ipv6_dst_embed_ipv4               = -1;
static int hf_ipv6_addr                         = -1;
static int hf_ipv6_host                         = -1;
static int hf_ipv6_slaac_mac                    = -1;
static int hf_ipv6_isatap_ipv4                  = -1;
static int hf_ipv6_6to4_gateway_ipv4            = -1;
static int hf_ipv6_6to4_sla_id                  = -1;
static int hf_ipv6_teredo_server_ipv4           = -1;
static int hf_ipv6_teredo_port                  = -1;
static int hf_ipv6_teredo_client_ipv4           = -1;
static int hf_ipv6_embed_ipv4_prefix            = -1;
static int hf_ipv6_embed_ipv4                   = -1;
static int hf_ipv6_embed_ipv4_u                 = -1;
static int hf_ipv6_embed_ipv4_suffix            = -1;
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
static int hf_ipv6_opt_pmtu_min                 = -1;
static int hf_ipv6_opt_pmtu_rtn                 = -1;
static int hf_ipv6_opt_pmtu_rtn_flag            = -1;
static int hf_ipv6_opt_jumbo                    = -1;
static int hf_ipv6_opt_calipso_doi              = -1;
static int hf_ipv6_opt_calipso_cmpt_length      = -1;
static int hf_ipv6_opt_calipso_sens_level       = -1;
static int hf_ipv6_opt_calipso_checksum         = -1;
static int hf_ipv6_opt_calipso_cmpt_bitmap      = -1;
static int hf_ipv6_opt_smf_dpd_hash_bit         = -1;
static int hf_ipv6_opt_smf_dpd_tid_type         = -1;
static int hf_ipv6_opt_smf_dpd_tid_len          = -1;
static int hf_ipv6_opt_smf_dpd_tagger_id        = -1;
static int hf_ipv6_opt_smf_dpd_ident            = -1;
static int hf_ipv6_opt_smf_dpd_hav              = -1;
static int hf_ipv6_opt_pdm_scale_dtlr           = -1;
static int hf_ipv6_opt_pdm_scale_dtls           = -1;
static int hf_ipv6_opt_pdm_psn_this_pkt         = -1;
static int hf_ipv6_opt_pdm_psn_last_recv        = -1;
static int hf_ipv6_opt_pdm_delta_last_recv      = -1;
static int hf_ipv6_opt_pdm_delta_last_sent      = -1;
static int hf_ipv6_opt_qs_func                  = -1;
static int hf_ipv6_opt_qs_rate                  = -1;
static int hf_ipv6_opt_qs_ttl                   = -1;
static int hf_ipv6_opt_qs_ttl_diff              = -1;
static int hf_ipv6_opt_qs_unused                = -1;
static int hf_ipv6_opt_qs_nonce                 = -1;
static int hf_ipv6_opt_qs_reserved              = -1;
static int hf_ipv6_opt_ioam_rsv                 = -1;
static int hf_ipv6_opt_ioam_opt_type            = -1;
static int hf_ipv6_opt_ioam_trace_ns            = -1;
static int hf_ipv6_opt_ioam_trace_nodelen       = -1;
static int hf_ipv6_opt_ioam_trace_flags         = -1;
static int hf_ipv6_opt_ioam_trace_flag_o        = -1;
static int hf_ipv6_opt_ioam_trace_flag_l        = -1;
static int hf_ipv6_opt_ioam_trace_flag_a        = -1;
static int hf_ipv6_opt_ioam_trace_flag_rsv      = -1;
static int hf_ipv6_opt_ioam_trace_remlen        = -1;
static int hf_ipv6_opt_ioam_trace_type          = -1;
static int hf_ipv6_opt_ioam_trace_type_bit0     = -1;
static int hf_ipv6_opt_ioam_trace_type_bit1     = -1;
static int hf_ipv6_opt_ioam_trace_type_bit2     = -1;
static int hf_ipv6_opt_ioam_trace_type_bit3     = -1;
static int hf_ipv6_opt_ioam_trace_type_bit4     = -1;
static int hf_ipv6_opt_ioam_trace_type_bit5     = -1;
static int hf_ipv6_opt_ioam_trace_type_bit6     = -1;
static int hf_ipv6_opt_ioam_trace_type_bit7     = -1;
static int hf_ipv6_opt_ioam_trace_type_bit8     = -1;
static int hf_ipv6_opt_ioam_trace_type_bit9     = -1;
static int hf_ipv6_opt_ioam_trace_type_bit10    = -1;
static int hf_ipv6_opt_ioam_trace_type_bit11    = -1;
static int hf_ipv6_opt_ioam_trace_type_undef    = -1;
static int hf_ipv6_opt_ioam_trace_type_bit22    = -1;
static int hf_ipv6_opt_ioam_trace_type_rsv      = -1;
static int hf_ipv6_opt_ioam_trace_rsv           = -1;
static int hf_ipv6_opt_ioam_trace_free_space    = -1;
static int hf_ipv6_opt_ioam_trace_node_hlim     = -1;
static int hf_ipv6_opt_ioam_trace_node_id       = -1;
static int hf_ipv6_opt_ioam_trace_node_iif      = -1;
static int hf_ipv6_opt_ioam_trace_node_eif      = -1;
static int hf_ipv6_opt_ioam_trace_node_tss      = -1;
static int hf_ipv6_opt_ioam_trace_node_tsf      = -1;
static int hf_ipv6_opt_ioam_trace_node_trdelay  = -1;
static int hf_ipv6_opt_ioam_trace_node_nsdata   = -1;
static int hf_ipv6_opt_ioam_trace_node_qdepth   = -1;
static int hf_ipv6_opt_ioam_trace_node_csum     = -1;
static int hf_ipv6_opt_ioam_trace_node_id_wide  = -1;
static int hf_ipv6_opt_ioam_trace_node_iif_wide = -1;
static int hf_ipv6_opt_ioam_trace_node_eif_wide = -1;
static int hf_ipv6_opt_ioam_trace_node_nsdata_wide = -1;
static int hf_ipv6_opt_ioam_trace_node_bufoccup = -1;
static int hf_ipv6_opt_ioam_trace_node_undefined = -1;
static int hf_ipv6_opt_ioam_trace_node_oss_len  = -1;
static int hf_ipv6_opt_ioam_trace_node_oss_scid = -1;
static int hf_ipv6_opt_ioam_trace_node_oss_data = -1;
static int hf_ipv6_opt_tpf_information          = -1;
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
static int hf_ipv6_routing_unknown_data         = -1;
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

static int hf_ipv6_routing_srh_last_entry       = -1;
static int hf_ipv6_routing_srh_flags            = -1;
static int hf_ipv6_routing_srh_tag              = -1;
static int hf_ipv6_routing_srh_addr             = -1;

static int hf_ipv6_routing_crh16_current_sid      = -1;
static int hf_ipv6_routing_crh32_current_sid      = -1;
static int hf_ipv6_routing_crh16_segment_id     = -1;
static int hf_ipv6_routing_crh32_segment_id     = -1;

static int hf_geoip_country             = -1;
static int hf_geoip_country_iso         = -1;
static int hf_geoip_city                = -1;
static int hf_geoip_as_number           = -1;
static int hf_geoip_as_org              = -1;
static int hf_geoip_latitude            = -1;
static int hf_geoip_longitude           = -1;
static int hf_geoip_src_summary         = -1;
static int hf_geoip_src_country         = -1;
static int hf_geoip_src_country_iso     = -1;
static int hf_geoip_src_city            = -1;
static int hf_geoip_src_as_number       = -1;
static int hf_geoip_src_as_org          = -1;
static int hf_geoip_src_latitude        = -1;
static int hf_geoip_src_longitude       = -1;
static int hf_geoip_dst_summary         = -1;
static int hf_geoip_dst_country         = -1;
static int hf_geoip_dst_country_iso     = -1;
static int hf_geoip_dst_city            = -1;
static int hf_geoip_dst_as_number       = -1;
static int hf_geoip_dst_as_org          = -1;
static int hf_geoip_dst_latitude        = -1;
static int hf_geoip_dst_longitude       = -1;

static gint ett_ipv6_proto              = -1;
static gint ett_ipv6_traffic_class      = -1;
static gint ett_ipv6_opt                = -1;
static gint ett_ipv6_opt_type           = -1;
static gint ett_ipv6_opt_rpl            = -1;
static gint ett_ipv6_opt_mpl            = -1;
static gint ett_ipv6_opt_dff_flags      = -1;
static gint ett_ipv6_opt_ioam_trace_flags = -1;
static gint ett_ipv6_opt_ioam_trace_types = -1;
static gint ett_ipv6_hopopts_proto      = -1;
static gint ett_ipv6_fraghdr_proto      = -1;
static gint ett_ipv6_routing_proto      = -1;
static gint ett_ipv6_routing_srh_vect   = -1;
static gint ett_ipv6_fragments          = -1;
static gint ett_ipv6_fragment           = -1;
static gint ett_ipv6_dstopts_proto      = -1;

static gint ett_geoip_info              = -1;

static expert_field ei_ipv6_routing_invalid_length = EI_INIT;
static expert_field ei_ipv6_routing_invalid_segleft = EI_INIT;
static expert_field ei_ipv6_routing_undecoded = EI_INIT;
static expert_field ei_ipv6_dst_addr_not_multicast = EI_INIT;
static expert_field ei_ipv6_src_route_list_mult_inst_same_addr = EI_INIT;
static expert_field ei_ipv6_src_route_list_src_addr = EI_INIT;
static expert_field ei_ipv6_src_route_list_dst_addr = EI_INIT;
static expert_field ei_ipv6_src_route_list_multicast_addr = EI_INIT;
static expert_field ei_ipv6_routing_rpl_cmpri_cmpre_pad = EI_INIT;
static expert_field ei_ipv6_routing_rpl_addr_count_ge0 = EI_INIT;
static expert_field ei_ipv6_routing_rpl_reserved = EI_INIT;
static expert_field ei_ipv6_routing_deprecated = EI_INIT;
static expert_field ei_ipv6_opt_jumbo_missing = EI_INIT;
static expert_field ei_ipv6_opt_jumbo_prohibited = EI_INIT;
static expert_field ei_ipv6_opt_jumbo_truncated = EI_INIT;
static expert_field ei_ipv6_opt_jumbo_fragment = EI_INIT;
static expert_field ei_ipv6_opt_invalid_len = EI_INIT;
static expert_field ei_ipv6_opt_unknown_data = EI_INIT;
static expert_field ei_ipv6_opt_deprecated = EI_INIT;
static expert_field ei_ipv6_opt_mpl_ipv6_src_seed_id = EI_INIT;
static expert_field ei_ipv6_hopopts_not_first = EI_INIT;
static expert_field ei_ipv6_plen_exceeds_framing = EI_INIT;
static expert_field ei_ipv6_plen_zero = EI_INIT;
static expert_field ei_ipv6_bogus_ipv6_version = EI_INIT;
static expert_field ei_ipv6_invalid_header = EI_INIT;
static expert_field ei_ipv6_opt_header_mismatch = EI_INIT;
static expert_field ei_ipv6_opt_ioam_invalid_nodelen = EI_INIT;
static expert_field ei_ipv6_opt_ioam_invalid_remlen = EI_INIT;
static expert_field ei_ipv6_opt_ioam_invalid_trace_type = EI_INIT;
static expert_field ei_ipv6_embed_ipv4_u_value = EI_INIT;

static dissector_handle_t ipv6_handle;

#define set_address_ipv6(dst, src_ip6) \
    set_address((dst), AT_IPv6, IPv6_ADDR_SIZE, (src_ip6))

#define set_address_ipv6_tvb(dst, tvb, offset) \
    set_address_tvb((dst), AT_IPv6, IPv6_ADDR_SIZE, (tvb), (offset))

#define alloc_address_wmem_ipv6(scope, dst, src_ip6) \
    alloc_address_wmem((scope), (dst), AT_IPv6, IPv6_ADDR_SIZE, (src_ip6))

#define alloc_address_tvb_ipv6(scope, dst, tvb, offset) \
    alloc_address_tvb((scope), (dst), AT_IPv6, IPv6_ADDR_SIZE, (tvb), (offset))

extern const ws_in6_addr *tvb_get_ptr_ipv6(tvbuff_t tvb, int offset);
#define tvb_get_ptr_ipv6(tvb, offset) \
    ((const ws_in6_addr *)tvb_get_ptr(tvb, offset, IPv6_ADDR_SIZE))

ipv6_pinfo_t *p_get_ipv6_pinfo(packet_info *pinfo)
{
    return (ipv6_pinfo_t *)p_get_proto_data(pinfo->pool, pinfo, proto_ipv6, IPV6_PROTO_PINFO);
}

/* Return tree pointer (for tree root preference) */
proto_tree *p_ipv6_pinfo_select_root(packet_info *pinfo, proto_tree *tree)
{
    ipv6_pinfo_t *p;

    if ((p = p_get_ipv6_pinfo(pinfo)) != NULL && p->ipv6_tree != NULL)
        return p->ipv6_tree;
    return tree;
}

ipv6_pinfo_t *p_ipv6_pinfo_add_len(packet_info *pinfo, int exthdr_len)
{
    ipv6_pinfo_t *p;

    if ((p = p_get_ipv6_pinfo(pinfo)) == NULL)
        return NULL;

    p->frag_plen -= exthdr_len;
    p->ipv6_item_len += exthdr_len;
    return p;
}

static void p_add_ipv6_nxt(packet_info *pinfo, guint8 nxt)
{
    guint8 *ptr;

    ptr = (guint8 *)wmem_memdup(pinfo->pool, &nxt, sizeof(guint8));
    p_add_proto_data(pinfo->pool, pinfo, proto_ipv6,
                        (pinfo->curr_layer_num<<8) | IPV6_PROTO_VALUE, ptr);
}

static guint8 *p_get_ipv6_nxt(packet_info *pinfo)
{
    return (guint8 *)p_get_proto_data(pinfo->pool, pinfo, proto_ipv6,
                        (pinfo->curr_layer_num<<8) | IPV6_PROTO_VALUE);
}

static gpointer ipv6_value(packet_info *pinfo)
{
    guint8 *nxt = p_get_ipv6_nxt(pinfo);

    if (nxt == NULL) {
        return GUINT_TO_POINTER(255); /* Reserved IP Protocol */
    }
    return GUINT_TO_POINTER((guint)*nxt);
}

static void ipv6_prompt(packet_info *pinfo, gchar *result)
{
    gpointer value = ipv6_value(pinfo);

    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "IP protocol %u as", GPOINTER_TO_UINT(value));
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

static tap_packet_status
ipv6_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pct;
    hash->flags = flags;

    const ipv6_tap_info_t *ip6 = (const ipv6_tap_info_t *)vip;

    add_conversation_table_data(hash, &ip6->ip6_src, &ip6->ip6_dst, 0, 0, 1,
            pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts,
            &ipv6_ct_dissector_info, ENDPOINT_NONE);

    return TAP_PACKET_REDRAW;
}

static const char* ipv6_host_get_filter_type(hostlist_talker_t* host, conv_filter_type_e filter)
{
    if ((filter == CONV_FT_ANY_ADDRESS) && (host->myaddress.type == AT_IPv6))
        return "ipv6.addr";

    return CONV_FILTER_INVALID;
}

static hostlist_dissector_info_t ipv6_host_dissector_info = {&ipv6_host_get_filter_type};

static tap_packet_status
ipv6_hostlist_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
    conv_hash_t *hash = (conv_hash_t*) pit;
    hash->flags = flags;

    const ipv6_tap_info_t *ip6 = (const ipv6_tap_info_t *)vip;

    add_hostlist_table_data(hash, &ip6->ip6_src, 0, TRUE, 1,
                pinfo->fd->pkt_len, &ipv6_host_dissector_info, ENDPOINT_NONE);
    add_hostlist_table_data(hash, &ip6->ip6_dst, 0, FALSE, 1,
                pinfo->fd->pkt_len, &ipv6_host_dissector_info, ENDPOINT_NONE);

    return TAP_PACKET_REDRAW;
}

static gboolean
ipv6_filter_valid(packet_info *pinfo)
{
    return proto_is_frame_protocol(pinfo->layers, "ipv6");
}

static gchar*
ipv6_build_filter(packet_info *pinfo)
{
    return ws_strdup_printf("ipv6.addr eq %s and ipv6.addr eq %s",
                address_to_str(pinfo->pool, &pinfo->net_src),
                address_to_str(pinfo->pool, &pinfo->net_dst));
}


/* UAT for providing a list of NAT64 prefixes */

struct nat64_prefix_data {
    char *ipaddr;
    uint8_t prefix_len;
    uint32_t prefix_wildcard_len;
};


static uat_t *nat64_prefix_uat = NULL;
static struct nat64_prefix_data *nat64_prefix_uats = NULL;
static guint number_of_nat64_prefix = 0;


UAT_CSTRING_CB_DEF(nat64_prefix_uats, ipaddr, struct nat64_prefix_data)

static gboolean
nat64_prefix_uat_fld_ip_chk_cb(void *r _U_, const char *ipaddr, guint len _U_, const void *u1 _U_, const void *u2 _U_, char **err)
{
    /* Check for a valid IPv6 address */
    ws_in6_addr addr;

    if (ws_inet_pton6(ipaddr, &addr)) {
        *err = NULL;
        return TRUE;
    }

    *err = ws_strdup_printf("No valid IPv6 address given.");
    return FALSE;
}

static const value_string nat64_prefix_length_vals[] =
{
    { 32, "32" },
    { 40, "40" },
    { 48, "48" },
    { 56, "56" },
    { 64, "64" },
    { 96, "96" },
    {  0, NULL }
};

UAT_VS_DEF(nat64_prefix_uats, prefix_len, struct nat64_prefix_data, uint8_t, 96, "96")

static const value_string nat64_prefix_wildcard_length_vals[] =
{
    {  0, "0" },
    {  8, "8" },
    { 16, "16" },
    { 32, "32" },
    { 64, "64" },
    {  0, NULL }
};

UAT_VS_DEF(nat64_prefix_uats, prefix_wildcard_len, struct nat64_prefix_data, uint8_t, 0, "0")


static void
nat64_prefix_free_cb(void *data)
{
    struct nat64_prefix_data *h = (struct nat64_prefix_data *)data;

    g_free(h->ipaddr);
}

static void *
nat64_prefix_copy_cb(void *dst_, const void *src_, size_t len _U_)
{
    const struct nat64_prefix_data *src = (const struct nat64_prefix_data *)src_;
    struct nat64_prefix_data *dst = (struct nat64_prefix_data *)dst_;

    dst->ipaddr = g_strdup(src->ipaddr);
    dst->prefix_len = src->prefix_len;
    dst->prefix_wildcard_len = src->prefix_wildcard_len;

    return dst;
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
static dissector_table_t ipv6_routing_dissector_table;

/* Reassemble fragmented datagrams */
static gboolean ipv6_reassemble = TRUE;

/* Place IPv6 summary in proto tree */
static gboolean ipv6_summary_in_tree = TRUE;

/* Look up addresses via mmdbresolve */
static gboolean ipv6_use_geoip = TRUE;

/* Perform strict RFC adherence checking */
static gboolean g_ipv6_rpl_srh_strict_rfc_checking = FALSE;

/* Use heuristics to determine subdissector */
static gboolean try_heuristic_first = FALSE;

/* Display IPv6 extension headers under the root tree */
static gboolean ipv6_exthdr_under_root = FALSE;

/* Hide extension header generated field for length */
static gboolean ipv6_exthdr_hide_len_oct_field = FALSE;

/* Assume TSO and correct zero-length IP packets */
static gboolean ipv6_tso_supported = FALSE;

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
    { IP6OPT_PDM,           "Performance and Diagnostic Metrics" },
    { IP6OPT_EXP_1E,        "Experimental (0x1E)"           },
    { IP6OPT_QUICKSTART,    "Quick-Start"                   },
    { IP6OPT_PMTU,          "Path MTU Option"               },
    { IP6OPT_IOAM,          "IOAM Option"                   },
    { IP6OPT_EXP_3E,        "Experimental (0x3E)"           },
    { IP6OPT_TPF,           "Tunnel Payload Forwarding (TPF) Information" },
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
static value_string_ext ipv6_opt_type_vals_ext = VALUE_STRING_EXT_INIT(ipv6_opt_type_vals);

static const value_string ipv6_opt_rtalert_vals[] = {
    { IP6OPT_RTALERT_MLD,       "MLD"            },
    { IP6OPT_RTALERT_RSVP,      "RSVP"           },
    { IP6OPT_RTALERT_ACTNET,    "Active Network" },
    { 0, NULL }
};

enum {
    IP6OPT_SMF_DPD_NULL = 0,
    IP6OPT_SMF_DPD_DFLT,
    IP6OPT_SMF_DPD_IPv4,
    IP6OPT_SMF_DPD_IPv6
};

static const value_string ipv6_opt_smf_dpd_tidty_vals[] = {
    { IP6OPT_SMF_DPD_NULL, "NULL"       },
    { IP6OPT_SMF_DPD_DFLT, "DEFAULT"    },
    { IP6OPT_SMF_DPD_IPv4, "IPv4"       },
    { IP6OPT_SMF_DPD_IPv6, "IPv6"       },
    { 0, NULL }
};

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

enum {
    IPv6_OPT_HDR_HBH = 0,
    IPv6_OPT_HDR_DST,
    IPv6_OPT_HDR_ANY
};

static const gint _ipv6_opt_type_hdr[][2] = {
    { IP6OPT_TEL,           IPv6_OPT_HDR_DST },
    { IP6OPT_RTALERT,       IPv6_OPT_HDR_HBH },
    { IP6OPT_PMTU,          IPv6_OPT_HDR_HBH },
    { IP6OPT_CALIPSO,       IPv6_OPT_HDR_HBH },
    { IP6OPT_SMF_DPD,       IPv6_OPT_HDR_HBH },
    { IP6OPT_PDM,           IPv6_OPT_HDR_DST },
    { IP6OPT_QUICKSTART,    IPv6_OPT_HDR_HBH },
    { IP6OPT_IOAM,          IPv6_OPT_HDR_HBH },
    { IP6OPT_TPF,           IPv6_OPT_HDR_DST },
    { IP6OPT_RPL,           IPv6_OPT_HDR_HBH },
    { IP6OPT_MPL,           IPv6_OPT_HDR_HBH },
    { IP6OPT_ILNP_NONCE,    IPv6_OPT_HDR_DST },
    { IP6OPT_LIO,           IPv6_OPT_HDR_DST },
    { IP6OPT_JUMBO,         IPv6_OPT_HDR_HBH },
    { IP6OPT_HOME_ADDRESS,  IPv6_OPT_HDR_DST },
    { IP6OPT_IP_DFF,        IPv6_OPT_HDR_HBH },
    { 0, IPv6_OPT_HDR_ANY }
};

static inline gint
ipv6_opt_type_hdr(gint type)
{
    const gint (*p)[2] = _ipv6_opt_type_hdr;

    for (; (*p)[1] != IPv6_OPT_HDR_ANY; p++) {
        if ((*p)[0] == type) {
            return (*p)[1];
        }
    }
    return IPv6_OPT_HDR_ANY;
}

enum {
    IPv6_RT_HEADER_SOURCE_ROUTING  = 0,     /* DEPRECATED */
    IPv6_RT_HEADER_NIMROD          = 1,     /* DEPRECATED */
    IPv6_RT_HEADER_MOBILE_IP       = 2,
    IPv6_RT_HEADER_RPL             = 3,
    IPv6_RT_HEADER_SEGMENT_ROUTING = 4,
    IPv6_RT_HEADER_COMPACT_16      = 5,
    IPv6_RT_HEADER_COMPACT_32      = 6,
    IPv6_RT_HEADER_EXP1            = 253,
    IPv6_RT_HEADER_EXP2            = 254
};

/* Routing Header Types */
static const value_string routing_header_type[] = {
    { IPv6_RT_HEADER_SOURCE_ROUTING,    "Source Route"     },
    { IPv6_RT_HEADER_NIMROD,            "Nimrod"           },
    { IPv6_RT_HEADER_MOBILE_IP,         "Type 2 Routing"   },
    { IPv6_RT_HEADER_RPL,               "RPL Source Route" },
    { IPv6_RT_HEADER_SEGMENT_ROUTING,   "Segment Routing"  },
    { IPv6_RT_HEADER_COMPACT_16,        "Compact Routing Header 16"  },
    { IPv6_RT_HEADER_COMPACT_32,        "Compact Routing Header 32"  },
    { IPv6_RT_HEADER_EXP1,              "Experiment 1"     },
    { IPv6_RT_HEADER_EXP2,              "Experiment 2"     },
    { 0, NULL }
};

static const value_string mpl_seed_id_len_vals[] = {
    { 0, "0" },
    { 1, "16-bit unsigned integer" },
    { 2, "64-bit unsigned integer" },
    { 3, "128-bit unsigned integer" },
    { 0, NULL }
};

static gboolean
capture_ipv6(const guchar *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
    guint8 nxt;

    if (!BYTES_ARE_IN_FRAME(offset, len, IPv6_HDR_SIZE))
        return FALSE;

    capture_dissector_increment_count(cpinfo, proto_ipv6);

    nxt = pd[offset+6];           /* get the "next header" value */
    offset += IPv6_HDR_SIZE;      /* skip past the IPv6 header */

    return try_capture_dissector("ip.proto", nxt, pd, offset, len, cpinfo, pseudo_header);
}

static gboolean
capture_ipv6_exthdr(const guchar *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
    guint8 nxt;
    int    advance;

    if (!BYTES_ARE_IN_FRAME(offset, len, 2))
        return FALSE;
    nxt = pd[offset];
    switch (nxt) {
        case IP_PROTO_FRAGMENT:
            advance = IPv6_FRAGMENT_HDR_SIZE;
            break;
        default:
            advance = (pd[offset+1] + 1) << 3;
            break;
    }
    if (!BYTES_ARE_IN_FRAME(offset, len, advance))
        return FALSE;
    offset += advance;

    return try_capture_dissector("ip.proto", nxt, pd, offset, len, cpinfo, pseudo_header);
}

static void
add_geoip_info_entry(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset, const ws_in6_addr *ip6, int isdst)
{
    const mmdb_lookup_t *lookup = maxmind_db_lookup_ipv6(ip6);
    if (!lookup->found) return;

    wmem_strbuf_t *summary = wmem_strbuf_new(pinfo->pool, "");
    if (lookup->city) {
        wmem_strbuf_append(summary, lookup->city);
    }
    if (lookup->country_iso) {
        if (wmem_strbuf_get_len(summary) > 0) wmem_strbuf_append(summary, ", ");
        wmem_strbuf_append(summary, lookup->country_iso);
    } else if (lookup->country) {
        if (wmem_strbuf_get_len(summary) > 0) wmem_strbuf_append(summary, ", ");
        wmem_strbuf_append(summary, lookup->country);
    }
    if (lookup->as_number > 0) {
        if (wmem_strbuf_get_len(summary) > 0) wmem_strbuf_append(summary, ", ");
        wmem_strbuf_append_printf(summary, "ASN %u", lookup->as_number);
    }
    if (lookup->as_org) {
        if (wmem_strbuf_get_len(summary) > 0) wmem_strbuf_append(summary, ", ");
        wmem_strbuf_append(summary, lookup->as_org);
    }

    int addr_offset = offset + isdst ? IP6H_DST : IP6H_SRC;
    int dir_hf = isdst ? hf_geoip_dst_summary : hf_geoip_src_summary;
    proto_item *geoip_info_item = proto_tree_add_string(tree, dir_hf, tvb, addr_offset, 16, wmem_strbuf_finalize(summary));
    proto_item_set_generated(geoip_info_item);
    proto_tree *geoip_info_tree = proto_item_add_subtree(geoip_info_item, ett_geoip_info);

    proto_item *item;

    if (lookup->city) {
        dir_hf = isdst ? hf_geoip_dst_city : hf_geoip_src_city;
        item = proto_tree_add_string(geoip_info_tree, dir_hf, tvb, addr_offset, 16, lookup->city);
        proto_item_set_generated(item);
        item = proto_tree_add_string(geoip_info_tree, hf_geoip_city, tvb, addr_offset, 16, lookup->city);
        proto_item_set_generated(item);
    }

    if (lookup->country) {
        dir_hf = isdst ? hf_geoip_dst_country : hf_geoip_src_country;
        item = proto_tree_add_string(geoip_info_tree, dir_hf, tvb, addr_offset, 16, lookup->country);
        proto_item_set_generated(item);
        item = proto_tree_add_string(geoip_info_tree, hf_geoip_country, tvb, addr_offset, 16, lookup->country);
        proto_item_set_generated(item);
    }

    if (lookup->country_iso) {
        dir_hf = isdst ? hf_geoip_dst_country_iso : hf_geoip_src_country_iso;
        item = proto_tree_add_string(geoip_info_tree, dir_hf, tvb, addr_offset, 16, lookup->country_iso);
        proto_item_set_generated(item);
        item = proto_tree_add_string(geoip_info_tree, hf_geoip_country_iso, tvb, addr_offset, 16, lookup->country_iso);
        proto_item_set_generated(item);
    }

    if (lookup->as_number > 0) {
        dir_hf = isdst ? hf_geoip_dst_as_number : hf_geoip_src_as_number;
        item = proto_tree_add_uint(geoip_info_tree, dir_hf, tvb, addr_offset, 16, lookup->as_number);
        proto_item_set_generated(item);
        item = proto_tree_add_uint(geoip_info_tree, hf_geoip_as_number, tvb, addr_offset, 16, lookup->as_number);
        proto_item_set_generated(item);
    }

    if (lookup->as_org) {
        dir_hf = isdst ? hf_geoip_dst_as_org : hf_geoip_src_as_org;
        item = proto_tree_add_string(geoip_info_tree, dir_hf, tvb, addr_offset, 16, lookup->as_org);
        proto_item_set_generated(item);
        item = proto_tree_add_string(geoip_info_tree, hf_geoip_as_org, tvb, addr_offset, 16, lookup->as_org);
        proto_item_set_generated(item);
    }

    if (lookup->latitude >= -90.0 && lookup->latitude <= 90.0) {
        dir_hf = isdst ? hf_geoip_dst_latitude : hf_geoip_src_latitude;
        item = proto_tree_add_double(geoip_info_tree, dir_hf, tvb, addr_offset, 16, lookup->latitude);
        proto_item_set_generated(item);
        item = proto_tree_add_double(geoip_info_tree, hf_geoip_latitude, tvb, addr_offset, 16, lookup->latitude);
        proto_item_set_generated(item);
    }

    if (lookup->longitude >= -180.0 && lookup->longitude <= 180.0) {
        dir_hf = isdst ? hf_geoip_dst_longitude : hf_geoip_src_longitude;
        item = proto_tree_add_double(geoip_info_tree, dir_hf, tvb, addr_offset, 16, lookup->longitude);
        proto_item_set_generated(item);
        item = proto_tree_add_double(geoip_info_tree, hf_geoip_longitude, tvb, addr_offset, 16, lookup->longitude);
        proto_item_set_generated(item);
    }
}

static void
add_geoip_info(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, gint offset, const ws_in6_addr *src, const ws_in6_addr *dst)
{
    add_geoip_info_entry(tree, pinfo, tvb, offset, src, FALSE);
    add_geoip_info_entry(tree, pinfo, tvb, offset, dst, TRUE);
}

/* Returns TRUE if reassembled */
static gboolean
ipv6_reassemble_do(tvbuff_t **tvb_ptr, gint *offset_ptr, packet_info *pinfo, proto_tree *ipv6_tree,
                    guint32 plen, guint16 frag_off, gboolean frag_flg, guint32 frag_ident,
                    gboolean *show_data_ptr)
{
    fragment_head   *ipfd_head;
    tvbuff_t        *next_tvb;
    gboolean         update_col_info = TRUE;

    pinfo->fragmented = TRUE;
    *show_data_ptr = TRUE;
    if (!ipv6_reassemble) {
        /* not reassembling */
        if (frag_off == 0) {
             /* first fragment */
            *show_data_ptr = FALSE;
        }
        return FALSE;
    }

    /* reassembling */
    if (tvb_bytes_exist(*tvb_ptr, *offset_ptr, plen)) {
        ipfd_head = fragment_add_check(&ipv6_reassembly_table,
                                       *tvb_ptr, *offset_ptr, pinfo, frag_ident, NULL,
                                       frag_off, plen, frag_flg);
        next_tvb = process_reassembled_data(*tvb_ptr, *offset_ptr, pinfo, "Reassembled IPv6",
                                            ipfd_head, &ipv6_frag_items, &update_col_info, ipv6_tree);
        if (next_tvb) {
            /* Process post-fragment headers after reassembly */
            *offset_ptr = 0;
            *tvb_ptr = next_tvb;
            pinfo->fragmented = FALSE;
            *show_data_ptr = FALSE;
            return TRUE;
        }
    }
    return FALSE;
}

static proto_item *
_proto_tree_add_ipv6_vector_address(proto_tree *tree, packet_info *pinfo, int hfindex, tvbuff_t *tvb, gint start,
                            gint length, const ws_in6_addr *value_ptr, int idx)
{
    address addr;
    gchar *str;

    set_address_ipv6(&addr, value_ptr);
    str = address_with_resolution_to_str(pinfo->pool, &addr);
    return proto_tree_add_ipv6_format(tree, hfindex, tvb, start, length,
                        value_ptr, "Address[%d]: %s", idx, str);
}

/* IPv6 Source Routing Header (Type 0) */
static int
dissect_routing6_rt0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct ws_rthdr *rt = (struct ws_rthdr *)data;
    proto_item *ti;
    int offset = 0;
    gint idx;
    gint rt0_addr_count;
    const ws_in6_addr *addr = NULL;

    proto_tree_add_item(tree, hf_ipv6_routing_src_reserved, tvb, offset, 4, ENC_NA);
    offset += 4;

    if (rt->hdr.ip6r_len % 2 != 0) {
        expert_add_info_format(pinfo, rt->ti_len, &ei_ipv6_routing_invalid_length,
                "IPv6 Routing Header extension header length must not be odd");
    }
    rt0_addr_count = rt->hdr.ip6r_len / 2;
    if (rt->hdr.ip6r_segleft > rt0_addr_count) {
        expert_add_info_format(pinfo, rt->ti_segleft, &ei_ipv6_routing_invalid_segleft,
                "IPv6 Type 0 Routing Header segments left field must not exceed address count (%u)", rt0_addr_count);
    }

    for (idx = 1; idx <= rt0_addr_count; idx++) {
        addr = tvb_get_ptr_ipv6(tvb, offset);
        ti = _proto_tree_add_ipv6_vector_address(tree, pinfo, hf_ipv6_routing_src_addr, tvb,
                            offset, IPv6_ADDR_SIZE, addr, idx);
        offset += IPv6_ADDR_SIZE;
        if (in6_addr_is_multicast(addr)) {
            expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_multicast_addr);
        }
    }

    if (addr != NULL && pinfo->dst.type == AT_IPv6 && rt->hdr.ip6r_segleft > 0) {
        alloc_address_wmem_ipv6(pinfo->pool, &pinfo->dst, addr);
    }

    expert_add_info(pinfo, rt->ti_type, &ei_ipv6_routing_deprecated);
    return tvb_captured_length(tvb);
}

/* Mobile IPv6 Routing Header (Type 2) */
static int
dissect_routing6_mipv6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct ws_rthdr *rt = (struct ws_rthdr *)data;
    proto_item *ti;
    int offset = 0;
    const ws_in6_addr *addr;

    proto_tree_add_item(tree, hf_ipv6_routing_mipv6_reserved, tvb, offset, 4, ENC_NA);
    offset += 4;

    if (rt->hdr.ip6r_len != 2) {
        expert_add_info_format(pinfo, rt->ti_len, &ei_ipv6_routing_invalid_length,
                "IPv6 Type 2 Routing Header extension header length must equal 2");
    }
    if (rt->hdr.ip6r_segleft != 1) {
        expert_add_info_format(pinfo, rt->ti_segleft, &ei_ipv6_routing_invalid_segleft,
                "IPv6 Type 2 Routing Header segments left field must equal 1");
    }

    addr = tvb_get_ptr_ipv6(tvb, offset);
    ti = _proto_tree_add_ipv6_vector_address(tree, pinfo, hf_ipv6_routing_mipv6_home_address, tvb,
                        offset, IPv6_ADDR_SIZE, addr, 1);
    if (in6_addr_is_multicast(addr)) {
        expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_multicast_addr);
    }

    if (pinfo->dst.type == AT_IPv6 && rt->hdr.ip6r_segleft > 0) {
        alloc_address_wmem_ipv6(pinfo->pool, &pinfo->dst, addr);
    }

    return tvb_captured_length(tvb);
}

/* RPL Source Routing Header (Type 3) */
static int
dissect_routing6_rpl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct ws_rthdr *rt = (struct ws_rthdr *)data;
    proto_item *ti;
    int offset = 0;
    guint8 cmprI, cmprE, cmprX, pad;
    guint32 reserved;
    gint idx;
    gint rpl_addr_count;
    ws_in6_addr rpl_fulladdr;
    const ws_in6_addr *ip6_dst_addr, *ip6_src_addr;
    wmem_array_t *rpl_addr_vector = NULL;
    guint i;

    /* Must be IPv6 addresses */
    if ((pinfo->dst.type != AT_IPv6) || (pinfo->src.type != AT_IPv6))
        return 0;

    /* IPv6 destination address used for elided bytes */
    ip6_dst_addr = (const ws_in6_addr *)pinfo->dst.data;
    /* IPv6 source address used for strict checking */
    ip6_src_addr = (const ws_in6_addr *)pinfo->src.data;

    /* from RFC6554: Multicast addresses MUST NOT appear in the IPv6 Destination Address field */
    if (in6_addr_is_multicast(ip6_dst_addr)) {
        expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_ipv6_dst_addr_not_multicast);
    }

    proto_tree_add_item(tree, hf_ipv6_routing_rpl_cmprI, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ipv6_routing_rpl_cmprE, tvb, offset, 4, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(tree, hf_ipv6_routing_rpl_pad, tvb, offset, 4, ENC_BIG_ENDIAN);

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

    ti = proto_tree_add_item(tree, hf_ipv6_routing_rpl_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    reserved = tvb_get_bits32(tvb, ((offset + 1) * 8) + 4, 20, ENC_BIG_ENDIAN);

    if (reserved != 0) {
        expert_add_info_format(pinfo, ti, &ei_ipv6_routing_rpl_reserved, "Reserved field must equal 0 but instead was %d", reserved);
    }

    /* From RFC6554:
     *   n = (((Hdr Ext Len * 8) - Pad - (16 - CmprE)) / (16 - CmprI)) + 1
     */
    rpl_addr_count = 0;
    if (rt->hdr.ip6r_len > 0) {
        rpl_addr_count = (((rt->hdr.ip6r_len * 8) - pad - (16 - cmprE)) / (16 - cmprI)) + 1;
    }
    ti = proto_tree_add_int(tree, hf_ipv6_routing_rpl_addr_count, tvb, offset, 2, rpl_addr_count);
    proto_item_set_generated(ti);
    if (rpl_addr_count < 0) {
        /* This error should always be reported */
        expert_add_info_format(pinfo, ti, &ei_ipv6_routing_rpl_addr_count_ge0, "Calculated total address count must be greater than or equal to 0, instead was %d", rpl_addr_count);
    }
    else if (rt->hdr.ip6r_segleft > (guint)rpl_addr_count) {
        expert_add_info_format(pinfo, rt->ti_segleft, &ei_ipv6_routing_invalid_segleft,
            "IPv6 RPL Routing Header segments left field must not exceed address count (%d)", rpl_addr_count);
    }

    if (rpl_addr_count > 0) {
        offset += 4;

        if (g_ipv6_rpl_srh_strict_rfc_checking)
            rpl_addr_vector = wmem_array_sized_new(pinfo->pool, IPv6_ADDR_SIZE, rpl_addr_count);

        /* We use cmprI for internal (e.g.: not last) address for how many bytes to elide, so actual bytes present = 16-CmprI */
        for (idx = 1; idx <= rpl_addr_count; idx++) {
            if (idx == rpl_addr_count)
                cmprX = 16 - cmprE;
            else
                cmprX = 16 - cmprI;
            proto_tree_add_item(tree, hf_ipv6_routing_rpl_addr, tvb, offset, cmprX, ENC_NA);
            /* Display Full Address */
            memcpy(&rpl_fulladdr, ip6_dst_addr, IPv6_ADDR_SIZE);
            tvb_memcpy(tvb, &rpl_fulladdr.bytes[16-cmprX], offset, cmprX);
            ti = _proto_tree_add_ipv6_vector_address(tree, pinfo, hf_ipv6_routing_rpl_fulladdr, tvb,
                                offset, cmprX, &rpl_fulladdr, idx);
            proto_item_set_generated(ti);
            offset += cmprX;

            /* IPv6 Source and Destination addresses of the encapsulating datagram (MUST) not appear in the SRH*/
            if (memcmp(&rpl_fulladdr, ip6_src_addr, IPv6_ADDR_SIZE) == 0) {
                expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_src_addr);
            }
            if (memcmp(&rpl_fulladdr, ip6_dst_addr, IPv6_ADDR_SIZE) == 0) {
                expert_add_info(pinfo, ti, &ei_ipv6_src_route_list_dst_addr);
            }

            /* Multicast addresses MUST NOT appear in the in SRH */
            if (in6_addr_is_multicast(&rpl_fulladdr)) {
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

            if (pinfo->dst.type == AT_IPv6 && rt->hdr.ip6r_segleft > 0) {
                alloc_address_wmem_ipv6(pinfo->pool, &pinfo->dst, &rpl_fulladdr);
            }
        }
    }

    return tvb_captured_length(tvb);
}

/* Segment Routing Header (Type 4) */
static int
dissect_routing6_srh(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct ws_rthdr *rt = (struct ws_rthdr *)data;
    int offset = 0;
    gint addr_offset;
    guint32 last_entry, addr_count;

    proto_tree_add_item_ret_uint(tree, hf_ipv6_routing_srh_last_entry,
                                    tvb, offset, 1, ENC_BIG_ENDIAN,
                                    &last_entry);
    addr_count = last_entry + 1;
    offset += 1;

    proto_tree_add_item(tree, hf_ipv6_routing_srh_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_ipv6_routing_srh_tag, tvb, offset, 2, ENC_NA);
    offset += 2;

    if (rt->hdr.ip6r_segleft > addr_count) {
        expert_add_info_format(pinfo, rt->ti_segleft, &ei_ipv6_routing_invalid_segleft,
                               "IPv6 Type 4 Routing Header segments left field must not exceed address count (%u)", addr_count);
    }

    if (pinfo->dst.type == AT_IPv6 && rt->hdr.ip6r_segleft > 0) {
        alloc_address_wmem_ipv6(pinfo->pool, &pinfo->dst, tvb_get_ptr_ipv6(tvb, offset));
    }

    for (unsigned i = 0; i < addr_count; i++) {
        addr_offset = offset + i * IPv6_ADDR_SIZE;
        _proto_tree_add_ipv6_vector_address(tree, pinfo, hf_ipv6_routing_srh_addr, tvb,
                addr_offset, IPv6_ADDR_SIZE, tvb_get_ptr_ipv6(tvb, addr_offset), i);
    }

    /* TODO: dissect TLVs */

    return tvb_captured_length(tvb);
}

/* Compact Routing Header 16 (Type 5) and  Compact Routing Header 32 (Type 6).
    https://tools.ietf.org/html/draft-bonica-6man-comp-rtg-hdr-23. */
static int dissect_routing6_crh(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    int offset, minimum_crh_length;
    gint sid;

    unsigned sid_count;
    unsigned octets_per_sid;
    unsigned sids_beyond_first_word;
    unsigned sids_per_word;
    struct ws_rthdr* rt = (struct ws_rthdr*)data;
    gboolean is_crh16 = rt->hdr.ip6r_type == IPv6_RT_HEADER_COMPACT_16;
    guint8 segments_left = rt->hdr.ip6r_segleft;

    /* Compute the minimum CRH length measured in 8-octet units, not including
    the first 8 octets */
    minimum_crh_length = -1;
    switch (rt->hdr.ip6r_type) {
    case IPv6_RT_HEADER_COMPACT_16:
        octets_per_sid = 2;
        sids_per_word = 4;
        sid_count = rt->hdr.ip6r_len * 4 + 2;
        if (segments_left <= 2)
            minimum_crh_length = 0;
        sids_beyond_first_word = segments_left - 2;
        break;
    case IPv6_RT_HEADER_COMPACT_32:
        octets_per_sid = 4;
        sids_per_word = 2;
        sid_count = rt->hdr.ip6r_len * 2 + 1;
        if (segments_left <= 1)
            minimum_crh_length = 0;
        sids_beyond_first_word = segments_left - 1;
        break;
    default:
        DISSECTOR_ASSERT_NOT_REACHED();
    }
    if (minimum_crh_length) {
        minimum_crh_length = sids_beyond_first_word / sids_per_word;
        if (sids_beyond_first_word % sids_per_word)
            minimum_crh_length++;
    }
    if (minimum_crh_length > rt->hdr.ip6r_len) {
        expert_add_info_format(pinfo, rt->ti_len, &ei_ipv6_routing_invalid_length,
            "IPv6 Compact Routing Header minimum length must not exceed header length (%u)",
            rt->hdr.ip6r_len);
    }

    offset = 0;
    if (is_crh16) {
        proto_item* current_sid_item = proto_tree_add_item(tree, hf_ipv6_routing_crh16_current_sid,
            tvb, offset + (octets_per_sid * segments_left), octets_per_sid, ENC_BIG_ENDIAN);
        proto_item_set_generated(current_sid_item);
    } else {
        proto_item* current_sid_item = proto_tree_add_item(tree, hf_ipv6_routing_crh32_current_sid,
            tvb, offset + (octets_per_sid * segments_left), octets_per_sid, ENC_BIG_ENDIAN);
        proto_item_set_generated(current_sid_item);
    }
    sid = is_crh16 ? tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN)
                   : tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree* segment_ids
        = proto_tree_add_subtree(tree, tvb, 0, -1, 0, NULL, "Segment Identifiers");
    for (unsigned i = 0; i < sid_count && sid; i++) {
        if (is_crh16) {
            proto_tree_add_uint_format(segment_ids, hf_ipv6_routing_crh16_segment_id, tvb, offset,
                octets_per_sid, sid, "SID[%d] = %d", i, sid);
        } else {
            proto_tree_add_uint_format(segment_ids, hf_ipv6_routing_crh32_segment_id, tvb, offset,
                octets_per_sid, sid, "SID[%d] = %d", i, sid);
        }
        offset += octets_per_sid;
        sid = is_crh16 ? tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN)
                       : tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    }

    return tvb_captured_length(tvb);
}

/*
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    .                                                               .
    .                       type-specific data                      .
    .                                                               .
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static int
dissect_routing6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    struct ws_rthdr    rt;
    guint              nxt, hdr_len, total_len;
    proto_tree        *rt_tree, *root_tree;
    proto_item        *pi, *ti, *ti_hdr_len, *ti_type, *ti_segs;
    int                offset = 0;
    tvbuff_t          *next_tvb;
    int                type, type_len;
    dissector_handle_t type_dissector;

    col_append_sep_str(pinfo->cinfo, COL_INFO, " , ", "IPv6 routing");

    root_tree = p_ipv6_pinfo_select_root(pinfo, tree);

    pi = proto_tree_add_item(root_tree, proto_ipv6_routing, tvb, offset, -1, ENC_NA);
    rt_tree = proto_item_add_subtree(pi, ett_ipv6_routing_proto);

    proto_tree_add_item(rt_tree, hf_ipv6_routing_nxt, tvb, offset, 1, ENC_BIG_ENDIAN);
    nxt = tvb_get_guint8(tvb, offset);
    offset += 1;

    ti_hdr_len = proto_tree_add_item(rt_tree, hf_ipv6_routing_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    hdr_len = tvb_get_guint8(tvb, offset);
    /*
          Hdr Ext Len         8-bit unsigned integer.  Length of the Routing
                              header in 8-octet units, not including the
                              first 8 octets.
    */
    total_len = (hdr_len + 1) * 8;
    type_len = total_len - 4;

    proto_item_set_len(pi, total_len);
    ti = proto_tree_add_uint(rt_tree, hf_ipv6_routing_len_oct, tvb, offset, 1, total_len);
    proto_item_set_generated(ti);
    if (ipv6_exthdr_hide_len_oct_field) {
        proto_item_set_hidden(ti);
        proto_item_append_text(ti_hdr_len, " (%d bytes)", total_len);
    }
    p_ipv6_pinfo_add_len(pinfo, total_len);
    offset += 1;

    ti_type = proto_tree_add_item(rt_tree, hf_ipv6_routing_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    type = tvb_get_guint8(tvb, offset);
    proto_item_append_text(pi, " (%s)", val_to_str(type, routing_header_type, "Unknown type %u"));
    offset += 1;

    ti_segs = proto_tree_add_item(rt_tree, hf_ipv6_routing_segleft, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    type_dissector = dissector_get_uint_handle(ipv6_routing_dissector_table, type);
    if (type_dissector != NULL) {
        tvb_memcpy(tvb, &(rt.hdr), 0, 4);
        rt.ti_len = ti_hdr_len;
        rt.ti_type = ti_type;
        rt.ti_segleft = ti_segs;
        call_dissector_with_data(type_dissector, tvb_new_subset_length(tvb, offset, type_len), pinfo, rt_tree, &rt);
    }
    else {
        /* Unknown Routing Header Type */
        ti = proto_tree_add_item(rt_tree, hf_ipv6_routing_unknown_data, tvb, offset, type_len, ENC_NA);
        expert_add_info(pinfo, ti, &ei_ipv6_routing_undecoded);
    }

    p_add_ipv6_nxt(pinfo, nxt);

    next_tvb = tvb_new_subset_remaining(tvb, total_len);
    ipv6_dissect_next(nxt, next_tvb, pinfo, tree, (ws_ip6 *)data);
    return tvb_captured_length(tvb);
}

static int
dissect_fraghdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    proto_item      *pi, *ti;
    proto_tree      *frag_tree, *root_tree;
    guint8           nxt;
    guint16          offlg;
    guint16          frag_off;
    gboolean         frag_flg;
    guint32          frag_ident;
    gint             offset = 0;
    ipv6_pinfo_t    *ipv6_pinfo;
    gboolean         show_data = FALSE;
    gboolean         reassembled;
    tvbuff_t        *next_tvb;

    nxt = tvb_get_guint8(tvb, offset);
    offlg = tvb_get_ntohs(tvb, offset + 2);
    frag_off = offlg & IP6F_OFF_MASK; /* offset in bytes */
    frag_flg = offlg & IP6F_MORE_FRAG;
    frag_ident = tvb_get_ntohl(tvb, offset + 4);
    col_add_fstr(pinfo->cinfo, COL_INFO, "IPv6 fragment (off=%u more=%s ident=0x%08x nxt=%u)",
                        frag_off, frag_flg ? "y" : "n", frag_ident, nxt);

    root_tree = p_ipv6_pinfo_select_root(pinfo, tree);
    ipv6_pinfo = p_ipv6_pinfo_add_len(pinfo, IPv6_FRAGMENT_HDR_SIZE);

    /* IPv6 Fragmentation Header has fixed length of 8 bytes */
    pi = proto_tree_add_item(root_tree, proto_ipv6_fraghdr, tvb, offset, IPv6_FRAGMENT_HDR_SIZE, ENC_NA);
    if (ipv6_pinfo != NULL && ipv6_pinfo->jumbo_plen != 0) {
        expert_add_info(pinfo, pi, &ei_ipv6_opt_jumbo_fragment);
    }

    frag_tree = proto_item_add_subtree(pi, ett_ipv6_fraghdr_proto);

    proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_nxt, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_reserved_octet, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    ti = proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_item_append_text(ti, " (%d bytes)", frag_off);

    proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_reserved_bits, tvb, offset, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_more, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(frag_tree, hf_ipv6_fraghdr_ident, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (ipv6_pinfo != NULL && ipv6_pinfo->frag_plen > 0) {
        if ((frag_off != 0) || frag_flg) {
            reassembled = ipv6_reassemble_do(&tvb, &offset, pinfo, root_tree, ipv6_pinfo->frag_plen,
                                             frag_off, frag_flg, frag_ident, &show_data);
            if (show_data) {
                next_tvb = tvb_new_subset_remaining(tvb, offset);
                call_data_dissector(next_tvb, pinfo, tree);
                return tvb_captured_length(tvb);
            }
            if (reassembled) {
                ipv6_pinfo->frag_plen = 0;
                next_tvb = tvb_new_subset_remaining(tvb, offset);
                ipv6_dissect_next(nxt, next_tvb, pinfo, tree, (ws_ip6 *)data);
                return tvb_captured_length(tvb);
            }
        }
    }

    p_add_ipv6_nxt(pinfo, nxt);

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    ipv6_dissect_next(nxt, next_tvb, pinfo, tree, (ws_ip6 *)data);
    return tvb_captured_length(tvb);
}

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
                    struct opt_proto_item *opt_ti, guint8 opt_len)
{
    proto_item *pi = proto_tree_get_parent(opt_tree);
    proto_item *ti;
    guint32 jumbo_plen = 0;
    ipv6_pinfo_t *ipv6_pinfo = p_get_ipv6_pinfo(pinfo);

    if (opt_len != 4) {
        expert_add_info_format(pinfo, opt_ti->len, &ei_ipv6_opt_invalid_len,
                "Jumbo Payload: Invalid length (%u bytes)", opt_len);
    }
    ti = proto_tree_add_item_ret_uint(opt_tree, hf_ipv6_opt_jumbo, tvb, offset, 4, ENC_BIG_ENDIAN, &jumbo_plen);
    offset += 4;

    if (ipv6_pinfo != NULL && ipv6_pinfo->ip6_plen != 0) {
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
    static int * const rpl_flags[] = {
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
 * IPv6 Minimum Path MTU Hop by Hop Option
 *

    Option    Option    Option
     Type    Data Len   Data
   +--------+--------+--------+--------+---------+-------+-+
   |BBCTTTTT|00000100|     Min-PMTU    |     Rtn-PMTU    |R|
   +--------+--------+--------+--------+---------+-------+-+

     Option Type:

     BB     00   Skip over this option and continue processing.

     C       1   Option data can change en route to the packet's final
                 destination.

     TTTTT 10000 Option Type assigned from IANA [IANA-HBH].

     Length:  4  The size of the each value field in Option Data
                 field supports Path MTU values from 0 to 65,535 octets.

     Min-PMTU: n 16-bits.  The minimum PMTU in octets, reflecting the
                 smallest link MTU that the packet experienced across
                 the path.  This is called the Reported PMTU.  A value
                 less than the IPv6 minimum link MTU [RFC8200]
                 should be ignored.

     Rtn-PMTU: n 15-bits.  The returned mimimum PMTU, carrying the 15
                 most significant bits of the latest received Min-PMTU
                 field.  The value zero means that no Reported MTU is
                 being returned.

     R        n  1-bit.  R-Flag.   Set by the source to signal that
                 the destination should include the received
                 Reported PMTU in Rtn-PMTU field.

   [IANA-HBH]
              "Destination Options and Hop-by-Hop Options",
              <https://www.iana.org/assignments/ipv6-parameters/
              ipv6-parameters.xhtml#ipv6-parameters-2>
*/
static gint
dissect_opt_pmtu(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *opt_tree,
                        struct opt_proto_item *opt_ti, guint8 opt_len)
{
    guint16 val;

    if (opt_len != 4) {
        expert_add_info_format(pinfo, opt_ti->len, &ei_ipv6_opt_invalid_len,
                "PMTU Option: Invalid Length (%u bytes)", opt_len);
    }

    proto_tree_add_item(opt_tree, hf_ipv6_opt_pmtu_min, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    val = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(opt_tree, hf_ipv6_opt_pmtu_rtn, tvb, offset, 2, val & 0xFFFE);
    offset += 1;
    proto_tree_add_boolean(opt_tree, hf_ipv6_opt_pmtu_rtn_flag, tvb, offset, 1, val & 0x0001);
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
                        struct opt_proto_item *opt_ti, guint8 opt_len, ws_ip6 *iph)
{
    proto_item *pi = proto_tree_get_parent(opt_tree);
    proto_item *ti;
    guint8 command, function, rate;
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
        proto_item_append_text(pi, ", %s, QS TTL %u",
                               val_to_str_ext(rate, &qs_rate_vals_ext, "Unknown (%u)"),
                               qs_ttl);
        if (iph != NULL) {
            guint8 ttl_diff;

            ttl_diff = (iph->ip6_hop - qs_ttl) % 256;
            ti = proto_tree_add_uint(opt_tree, hf_ipv6_opt_qs_ttl_diff, tvb, offset, 1, ttl_diff);
            proto_item_set_generated(ti);
            proto_item_append_text(pi, ", QS TTL diff %u", ttl_diff);
        }
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

static const value_string ipv6_ioam_opt_types[] = {
    { IP6IOAM_PRE_TRACE,  "Pre-allocated Trace" },
    { IP6IOAM_INC_TRACE,  "Incremental Trace"   },
    { IP6IOAM_POT,        "Proof of Transit"    },
    { IP6IOAM_E2E,        "Edge to Edge"        },
    { 0, NULL}
};

static gint
dissect_opt_ioam_trace_node(tvbuff_t *tvb, gint offset,
                            proto_tree *opt_tree, guint32 trace_type)
{
    proto_tree* sub_tree;

    if (trace_type & IP6IOAM_TRACE_MASK_BIT0) {
        sub_tree = proto_tree_add_subtree(opt_tree, tvb, offset, 4, 0, NULL,
                                          "Hop_Lim and Node ID (short)");
        proto_tree_add_item(sub_tree, hf_ipv6_opt_ioam_trace_node_hlim,
                            tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sub_tree, hf_ipv6_opt_ioam_trace_node_id,
                            tvb, offset + 1, 3, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT1) {
        sub_tree = proto_tree_add_subtree(opt_tree, tvb, offset, 4, 0, NULL,
                                          "Ingress and Egress IDs (short)");
        proto_tree_add_item(sub_tree, hf_ipv6_opt_ioam_trace_node_iif,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_ipv6_opt_ioam_trace_node_eif,
                            tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT2) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_tss,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT3) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_tsf,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT4) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_trdelay,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT5) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_nsdata,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT6) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_qdepth,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT7) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_csum,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT8) {
        sub_tree = proto_tree_add_subtree(opt_tree, tvb, offset, 8, 0, NULL,
                                          "Hop_Lim and Node ID (wide)");
        proto_tree_add_item(sub_tree, hf_ipv6_opt_ioam_trace_node_hlim,
                            tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sub_tree, hf_ipv6_opt_ioam_trace_node_id_wide,
                            tvb, offset + 1, 7, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT9) {
        sub_tree = proto_tree_add_subtree(opt_tree, tvb, offset, 8, 0, NULL,
                                          "Ingress and Egress IDs (wide)");
        proto_tree_add_item(sub_tree, hf_ipv6_opt_ioam_trace_node_iif_wide,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_ipv6_opt_ioam_trace_node_eif_wide,
                            tvb, offset + 4, 4, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT10) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_nsdata_wide,
                            tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT11) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_bufoccup,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT12) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_undefined,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT13) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_undefined,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT14) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_undefined,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT15) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_undefined,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT16) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_undefined,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT17) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_undefined,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT18) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_undefined,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT19) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_undefined,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT20) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_undefined,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    if (trace_type & IP6IOAM_TRACE_MASK_BIT21) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_node_undefined,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    return offset;
}

/*
 * IOAM Trace Option Header
 *
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |         Namespace-ID          | NodeLen | Flags | RemainingLen|
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                IOAM-Trace-Type                |   Reserved    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<-+
     |                                                               |  |
     |                        node data list [0]                     |  |
     |                                                               |  |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  D
     |                                                               |  a
     |                        node data list [1]                     |  t
     |                                                               |  a
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ~                             ........                          ~  S
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  p
     |                                                               |  a
     |                        node data list [n-1]                   |  c
     |                                                               |  e
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
     |                                                               |  |
     |                        node data list [n]                     |  |
     |                                                               |  |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+<-+
*/
static gint
dissect_opt_ioam_trace(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *opt_tree, struct opt_proto_item *opt_ti, guint8 opt_len)
{
    proto_item *ti;
    guint32 trace_type, oss_scid;
    guint16 len;
    guint8 remlen, nodelen, oss_len, i = 0;
    gint new_offset;

    static int * const ioam_trace_flags[] = {
        &hf_ipv6_opt_ioam_trace_flag_o,
        &hf_ipv6_opt_ioam_trace_flag_l,
        &hf_ipv6_opt_ioam_trace_flag_a,
        &hf_ipv6_opt_ioam_trace_flag_rsv,
        NULL
    };

    static int * const ioam_trace_types[] = {
        &hf_ipv6_opt_ioam_trace_type_bit0,
        &hf_ipv6_opt_ioam_trace_type_bit1,
        &hf_ipv6_opt_ioam_trace_type_bit2,
        &hf_ipv6_opt_ioam_trace_type_bit3,
        &hf_ipv6_opt_ioam_trace_type_bit4,
        &hf_ipv6_opt_ioam_trace_type_bit5,
        &hf_ipv6_opt_ioam_trace_type_bit6,
        &hf_ipv6_opt_ioam_trace_type_bit7,
        &hf_ipv6_opt_ioam_trace_type_bit8,
        &hf_ipv6_opt_ioam_trace_type_bit9,
        &hf_ipv6_opt_ioam_trace_type_bit10,
        &hf_ipv6_opt_ioam_trace_type_bit11,
        &hf_ipv6_opt_ioam_trace_type_undef,
        &hf_ipv6_opt_ioam_trace_type_bit22,
        &hf_ipv6_opt_ioam_trace_type_rsv,
        NULL
    };

    if (opt_len < 10) {
        expert_add_info_format(pinfo, opt_ti->len, &ei_ipv6_opt_invalid_len,
                               "IOAM Option: Invalid length (%u bytes)", opt_len);
    }

    proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_ns, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    nodelen = tvb_get_bits8(tvb, offset * 8, 5);
    ti = proto_tree_add_bits_item(opt_tree, hf_ipv6_opt_ioam_trace_nodelen, tvb,
                                  offset * 8, 5, ENC_BIG_ENDIAN);
    if (!nodelen)
        expert_add_info(pinfo, ti, &ei_ipv6_opt_ioam_invalid_nodelen);

    proto_tree_add_bitmask(opt_tree, tvb, offset, hf_ipv6_opt_ioam_trace_flags,
                           ett_ipv6_opt_ioam_trace_flags, ioam_trace_flags, ENC_NA);

    remlen = tvb_get_bits8(tvb, offset * 8 + 9, 7);
    ti = proto_tree_add_bits_item(opt_tree, hf_ipv6_opt_ioam_trace_remlen, tvb,
                                  offset * 8 + 9, 7, ENC_BIG_ENDIAN);
    if (remlen * 4 > opt_len - 10) {
        expert_add_info_format(pinfo, ti, &ei_ipv6_opt_ioam_invalid_remlen,
                               "IOAM RemLen: Invalid length (%u bytes)", remlen * 4);
    }

    offset += 2;

    trace_type = tvb_get_bits32(tvb, offset * 8, 24, ENC_BIG_ENDIAN);
    ti = proto_tree_add_bitmask(opt_tree, tvb, offset, hf_ipv6_opt_ioam_trace_type,
                                ett_ipv6_opt_ioam_trace_types, ioam_trace_types, ENC_BIG_ENDIAN);
    proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_trace_rsv, tvb, offset + 3, 1, ENC_NA);
    offset += 4;

    /* node data list parsing starts here */
    if (!nodelen || remlen * 4 > opt_len - 10)
        return offset;

    proto_tree* trace_tree
        = proto_tree_add_subtree(opt_tree, tvb, offset, opt_len - 10, 0, NULL, "Trace Data");

    if (remlen) {
        proto_tree_add_item(trace_tree, hf_ipv6_opt_ioam_trace_free_space, tvb,
                            offset, remlen * 4, ENC_NA);
        offset += remlen * 4;
    }

    len = opt_len - 10 - remlen * 4;
    while (len && len >= nodelen * 4) {
        proto_tree* node_tree
            = proto_tree_add_subtree_format(trace_tree, tvb, offset,
                                            nodelen * 4, 0, NULL, "Node %u", ++i);

        new_offset = dissect_opt_ioam_trace_node(tvb, offset, node_tree, trace_type);
        if (new_offset - offset != nodelen * 4) {
            expert_add_info(pinfo, ti, &ei_ipv6_opt_ioam_invalid_trace_type);
            return offset;
        }

        offset = new_offset;
        len -= nodelen * 4;

        /* Opaque State Snapshot */
        if (trace_type & IP6IOAM_TRACE_MASK_BIT22) {
            if (len < 4) {
                expert_add_info_format(pinfo, opt_ti->len, &ei_ipv6_opt_invalid_len,
                                       "IOAM Option: Invalid length (%u bytes)", opt_len);
                return offset;
            }

            oss_len = tvb_get_guint8(tvb, offset);

            proto_tree* oss_tree
                = proto_tree_add_subtree(node_tree, tvb, offset, (oss_len + 1) * 4,
                                         0, NULL, "Opaque State Snapshot");
            proto_tree_add_item(oss_tree, hf_ipv6_opt_ioam_trace_node_oss_len,
                                tvb, offset, 1, ENC_NA);
            proto_tree_add_item_ret_uint(oss_tree, hf_ipv6_opt_ioam_trace_node_oss_scid,
                                         tvb, offset + 1, 3, ENC_BIG_ENDIAN, &oss_scid);
            offset += 4;

            len -= 4;
            if (len < oss_len * 4) {
                expert_add_info_format(pinfo, opt_ti->len, &ei_ipv6_opt_invalid_len,
                                       "IOAM Option: Invalid length (%u bytes)", opt_len);
                return offset;
            }

            if (oss_len > 0) {
                proto_tree_add_item(oss_tree, hf_ipv6_opt_ioam_trace_node_oss_data,
                                    tvb, offset, oss_len * 4, ENC_NA);

                len -= oss_len * 4;
                offset += oss_len * 4;
            }
        }
    }

    if (len) {
        expert_add_info_format(pinfo, opt_ti->len, &ei_ipv6_opt_invalid_len,
                               "IOAM Option: Invalid length (%u bytes)", opt_len);
    }

    return offset;
}

/*
 * IOAM Option Header
 *
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Option Type  |  Opt Data Len |   Reserved    |   IOAM Type   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static gint
dissect_opt_ioam(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                 proto_tree *opt_tree, struct opt_proto_item *opt_ti, guint8 opt_len)
{
    guint32 opt_type;

    if (opt_len < 2) {
        expert_add_info_format(pinfo, opt_ti->len, &ei_ipv6_opt_invalid_len,
                               "IOAM Option: Invalid length (%u bytes)", opt_len);
    }

    proto_tree_add_item(opt_tree, hf_ipv6_opt_ioam_rsv, tvb, offset, 1, ENC_NA);
    proto_tree_add_item_ret_uint(opt_tree, hf_ipv6_opt_ioam_opt_type, tvb,
                                 offset + 1, 1, ENC_NA, &opt_type);
    offset += 2;

    proto_tree* opt_type_tree
        = proto_tree_add_subtree(opt_tree, tvb, offset, opt_len - 2, 0, NULL,
                                 val_to_str_const(opt_type, ipv6_ioam_opt_types,
                                                  "Unknown Option-Type"));

    switch (opt_type) {
    case IP6IOAM_PRE_TRACE:
    case IP6IOAM_INC_TRACE:
        offset = dissect_opt_ioam_trace(tvb, offset, pinfo, opt_type_tree, opt_ti, opt_len);
        break;
    case IP6IOAM_POT:
        break;
    case IP6IOAM_E2E:
        break;
    }

    return offset;
}

/*
 * Tunnel Payload Forwarding Option for IPv6
 *
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                     |  Option Type  | Option Length |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                        TPF Information                        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static gint
dissect_opt_tpf(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *opt_tree,
                        struct opt_proto_item *opt_ti, guint8 opt_len)
{
    if (opt_len != 4) {
        expert_add_info_format(pinfo, opt_ti->len, &ei_ipv6_opt_invalid_len,
                "TPF: Invalid Length (%u bytes)", opt_len);
    }
    proto_tree_add_item(opt_tree, hf_ipv6_opt_tpf_information, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

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
 * IPv6 SMF_DPD Option Header
 *
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     ...              |0|0|0|  01000  | Opt. Data Len |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |0|TidTy| TidLen|             TaggerId (optional) ...           |
      +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                               |            Identifier  ...
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

           Figure 3: IPv6 SMF_DPD Option Header in I-DPD mode

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                     ...              |0|0|0| OptType | Opt. Data Len |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |1|    Hash Assist Value (HAV) ...
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

           Figure 4: IPv6 SMF_DPD Option Header in H-DPD Mode
*/
static gint
dissect_opt_smf_dpd(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *opt_tree,
                    struct opt_proto_item *opt_ti _U_, guint8 opt_len)
{
    guint8 hash_tid;
    guint8 tid_len;
    gint ident_len;

    proto_tree_add_item(opt_tree, hf_ipv6_opt_smf_dpd_hash_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
    hash_tid = tvb_get_guint8(tvb, offset);

    if (hash_tid & 0x80) {
        /* H-DPD Mode */
        proto_tree_add_item(opt_tree, hf_ipv6_opt_smf_dpd_hav, tvb, offset, opt_len, ENC_NA);
        return offset + opt_len;
    }

    /* I-DPD Mode */
    proto_tree_add_item(opt_tree, hf_ipv6_opt_smf_dpd_tid_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(opt_tree, hf_ipv6_opt_smf_dpd_tid_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    ident_len = opt_len - 1;
    if (hash_tid & 0x70) {
        tid_len = (hash_tid & 0x0f) + 1;
        proto_tree_add_item(opt_tree, hf_ipv6_opt_smf_dpd_tagger_id, tvb, offset, tid_len, ENC_NA);
        offset += tid_len;
        ident_len -= tid_len;
    }
    if (ident_len > 0) {
        proto_tree_add_item(opt_tree, hf_ipv6_opt_smf_dpd_ident, tvb, offset, ident_len, ENC_NA);
        offset += ident_len;
    }

    return offset;
}

/*
 * Performance and Diagnostic Metrics Destination Option (ietf-ippm-6man-pdm-option-13)
 *
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Option Type  | Option Length |    ScaleDTLR  |     ScaleDTLS |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   PSN This Packet             |  PSN Last Received            |
      |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |   Delta Time Last Received    |  Delta Time Last Sent         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
static gint
dissect_opt_pdm(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *opt_tree,
                    struct opt_proto_item *opt_ti _U_, guint8 opt_len)
{
    if (opt_len != 10) {
        expert_add_info_format(pinfo, opt_ti->len, &ei_ipv6_opt_invalid_len,
                "PDM: Invalid length (%u bytes)", opt_len);
    }
    proto_tree_add_item(opt_tree, hf_ipv6_opt_pdm_scale_dtlr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(opt_tree, hf_ipv6_opt_pdm_scale_dtls, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(opt_tree, hf_ipv6_opt_pdm_psn_this_pkt, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(opt_tree, hf_ipv6_opt_pdm_psn_last_recv, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(opt_tree, hf_ipv6_opt_pdm_delta_last_recv, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(opt_tree, hf_ipv6_opt_pdm_delta_last_sent, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

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
    proto_tree_add_item(opt_tree, hf_ipv6_opt_mipv6_home_address, tvb, offset, IPv6_ADDR_SIZE, ENC_NA);
    alloc_address_tvb_ipv6(pinfo->pool, &pinfo->src, tvb, offset);
    offset += IPv6_ADDR_SIZE;

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
    static int * const mpl_flags[] = {
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
    else {
        expert_add_info(pinfo, opt_ti->type, &ei_ipv6_opt_mpl_ipv6_src_seed_id);
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
    static int * const dff_flags[] = {
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
dissect_opts(tvbuff_t *tvb, int offset, proto_tree *tree, packet_info *pinfo, ws_ip6 *iph, const int exthdr_proto)
{
    gint            len, offset_end;
    guint8          nxt;
    proto_tree     *exthdr_tree, *opt_tree, *opt_type_tree, *root_tree;
    proto_item     *pi, *ti, *ti_len;
    int             hf_exthdr_item_nxt, hf_exthdr_item_len, hf_exthdr_item_len_oct;
    int             ett_exthdr_proto;
    guint8          opt_type, opt_len, opt_start;
    gint            opt_hdr_type;
    const gchar    *opt_name;
    gboolean        hopopts;
    struct opt_proto_item opt_ti;
    tvbuff_t       *next_tvb;

    hopopts = (exthdr_proto == proto_ipv6_hopopts);

    nxt = tvb_get_guint8(tvb, offset);
    len = (tvb_get_guint8(tvb, offset + 1) + 1) << 3;
    offset_end = offset + len;

    root_tree = p_ipv6_pinfo_select_root(pinfo, tree);
    p_ipv6_pinfo_add_len(pinfo, len);

    /* !!! specify length */
    ti = proto_tree_add_item(root_tree, exthdr_proto, tvb, offset, len, ENC_NA);

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
    proto_item_set_generated(ti);
    if (ipv6_exthdr_hide_len_oct_field) {
        proto_item_set_hidden(ti);
        proto_item_append_text(ti_len, " (%d bytes)", len);
    }
    offset += 1;

    while (offset < offset_end) {
        /* there are more options */

        opt_type = tvb_get_guint8(tvb, offset);
        opt_len = tvb_get_guint8(tvb, offset + 1);
        opt_name = val_to_str_ext(opt_type, &ipv6_opt_type_vals_ext, "Unknown IPv6 Option (%u)");

        pi = proto_tree_add_none_format(exthdr_tree, hf_ipv6_opt, tvb, offset, 2 + opt_len,
                    "%s", opt_name);
        opt_tree = proto_item_add_subtree(pi, ett_ipv6_opt);

        opt_ti.type = proto_tree_add_item(opt_tree, hf_ipv6_opt_type, tvb, offset, 1, ENC_BIG_ENDIAN);

        if (opt_type == IP6OPT_PAD1) {
            /* The Pad1 option is a special case, and contains no data. */
            proto_tree_add_item(opt_tree, hf_ipv6_opt_pad1, tvb, offset, 1, ENC_NA);
            offset += 1;
            continue;
        }

        if ((opt_hdr_type = ipv6_opt_type_hdr(opt_type)) != IPv6_OPT_HDR_ANY) {
            if (hopopts && (opt_hdr_type == IPv6_OPT_HDR_DST)) {
                expert_add_info_format(pinfo, opt_ti.type, &ei_ipv6_opt_header_mismatch,
                        "%s must use a destination options header", opt_name);
            }
            else if (!hopopts && (opt_hdr_type == IPv6_OPT_HDR_HBH)) {
                expert_add_info_format(pinfo, opt_ti.type, &ei_ipv6_opt_header_mismatch,
                        "%s must use a hop-by-hop options header", opt_name);
            }
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
            offset = dissect_opt_jumbo(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
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
        case IP6OPT_PMTU:
            offset = dissect_opt_pmtu(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
            break;
        case IP6OPT_QUICKSTART:
            offset = dissect_opt_quickstart(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len, iph);
            break;
        case IP6OPT_IOAM:
            offset = dissect_opt_ioam(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
            break;
        case IP6OPT_TPF:
            offset = dissect_opt_tpf(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
            break;
        case IP6OPT_CALIPSO:
            offset = dissect_opt_calipso(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
            break;
        case IP6OPT_SMF_DPD:
            offset = dissect_opt_smf_dpd(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
            break;
        case IP6OPT_PDM:
            offset = dissect_opt_pdm(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
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
        case IP6OPT_ENDI:
            offset = dissect_opt_unknown(tvb, offset, pinfo, opt_tree, &opt_ti, opt_len);
            expert_add_info(pinfo, opt_ti.type, &ei_ipv6_opt_deprecated);
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

    p_add_ipv6_nxt(pinfo, nxt);

    next_tvb = tvb_new_subset_remaining(tvb, len);
    ipv6_dissect_next(nxt, next_tvb, pinfo, tree, iph);
    return tvb_captured_length(tvb);
}

static int
dissect_hopopts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, " , ", "IPv6 hop-by-hop options");

    return dissect_opts(tvb, 0, tree, pinfo, (ws_ip6 *)data, proto_ipv6_hopopts);
}

static int
dissect_dstopts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, " , ", "IPv6 destination options");

    return dissect_opts(tvb, 0, tree, pinfo, (ws_ip6 *)data, proto_ipv6_dstopts);
}

/* return value is > G_MAXUINT16, else zero */
/* tvb + offset contains the Hbh header */
static guint32
ipv6_get_jumbo_plen(tvbuff_t *tvb, gint offset)
{
    gint         offset_end, hdr_len;
    gint         opt_type, opt_len;
    guint32      jumbo_plen;

    if (!tvb_bytes_exist(tvb, offset, 2)) {
        return 0;
    }
    hdr_len = (tvb_get_guint8(tvb, offset + 1) + 1) * 8;
    offset_end = offset + hdr_len;
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
                return jumbo_plen;
            }
            return 0;
        }
        offset += opt_len;
    }
    return 0;
}

static void
add_ipv6_address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset,
                        gint hf_addr, gint hf_host)
{
    address addr;
    const char *name;
    proto_item *ti;

    proto_tree_add_item(tree, hf_addr, tvb, offset, IPv6_ADDR_SIZE, ENC_NA);
    ti = proto_tree_add_item(tree, hf_ipv6_addr, tvb, offset, IPv6_ADDR_SIZE, ENC_NA);
    proto_item_set_hidden(ti);

    set_address_ipv6_tvb(&addr, tvb, offset);
    name = address_to_display(pinfo->pool, &addr);

    ti = proto_tree_add_string(tree, hf_host, tvb, offset, IPv6_ADDR_SIZE, name);
    proto_item_set_generated(ti);
    proto_item_set_hidden(ti);
    ti = proto_tree_add_string(tree, hf_ipv6_host, tvb, offset, IPv6_ADDR_SIZE, name);
    proto_item_set_generated(ti);
    proto_item_set_hidden(ti);
}

#define ADDRESS_SET_GENERATED_HIDDEN(ti) \
    G_STMT_START {                              \
        proto_item_set_generated(ti);           \
        if (i > 0) proto_item_set_hidden(ti);   \
    } G_STMT_END

/* RFC 3056 section 2 */
static void
add_ipv6_address_6to4(proto_tree *tree, tvbuff_t *tvb, int offset,
                        gint hf_gateway, gint hf_sla_id)
{
    if (tvb_get_ntohs(tvb, offset) != 0x2002)
        return;

    struct { gint gateway, sla_id; } hf[2] = {
        { hf_gateway, hf_sla_id},
        { hf_ipv6_6to4_gateway_ipv4, hf_ipv6_6to4_sla_id}
    };
    proto_item *ti;
    for (int i = 0; i < 2; i++) {
        ti = proto_tree_add_item(tree, hf[i].gateway, tvb, offset + 2, 4, ENC_BIG_ENDIAN);
        ADDRESS_SET_GENERATED_HIDDEN(ti);
        ti = proto_tree_add_item(tree, hf[i].sla_id, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
        ADDRESS_SET_GENERATED_HIDDEN(ti);
    }
}

/* RFC 4380 section 4 */
static void
add_ipv6_address_teredo(proto_tree *tree, tvbuff_t *tvb, int offset,
                        gint hf_server, gint hf_port, gint hf_client)
{
    if (tvb_get_ntohl(tvb, offset) != 0x20010000)
        return;

    guint16 mapped_port = tvb_get_ntohs(tvb, offset + 10) ^ 0xffff;
    guint32 client_v4 = tvb_get_ipv4(tvb, offset + 12) ^ 0xffffffff;

    struct { gint server, port, client; } hf[2] = {
        { hf_server, hf_port, hf_client },
        { hf_ipv6_teredo_server_ipv4, hf_ipv6_teredo_port, hf_ipv6_teredo_client_ipv4 }
    };
    proto_item *ti;
    for (int i = 0; i < 2; i++) {
        ti = proto_tree_add_item(tree, hf[i].server, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
        ADDRESS_SET_GENERATED_HIDDEN(ti);
        ti = proto_tree_add_uint(tree, hf[i].port, tvb, offset + 10, 2, mapped_port);
        ADDRESS_SET_GENERATED_HIDDEN(ti);
        ti = proto_tree_add_ipv4(tree, hf[i].client, tvb, offset + 12, 4, client_v4);
        ADDRESS_SET_GENERATED_HIDDEN(ti);
    }
}

/* RFC 4291 appendix A */
static void
add_ipv6_address_slaac(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_slaac)
{
    if (!(tvb_get_guint8(tvb, offset + 8) & 0x02) ||
                            !(tvb_get_ntohs(tvb, offset + 11) == 0xfffe)) {
        return;
    }

    guint8 *mac_addr = (guint8 *)wmem_alloc(pinfo->pool, 6);
    tvb_memcpy(tvb, mac_addr, offset + 8, 3);
    tvb_memcpy(tvb, mac_addr+3, offset + 13, 3);
    mac_addr[0] &= ~0x02;

    struct { gint mac; } hf[2] = {
        { hf_slaac },
        { hf_ipv6_slaac_mac }
    };
    proto_item *ti;
    for (int i = 0; i < 2; i++) {
        ti = proto_tree_add_ether(tree, hf[i].mac, tvb, offset + 8, 8, mac_addr);
        ADDRESS_SET_GENERATED_HIDDEN(ti);
    }
}

/* RFC 5214 section 6.1 */
static void
add_ipv6_address_isatap(proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_isatap)
{
    if ((tvb_get_ntohl(tvb, offset + 8) & 0xfcffffff) != 0x00005efe)
        return;

    struct { gint ipv4; } hf[2] = {
        { hf_isatap },
        { hf_ipv6_isatap_ipv4 }
    };
    proto_item *ti;
    for (int i = 0; i < 2; i++) {
        ti = proto_tree_add_item(tree, hf[i].ipv4, tvb, offset + 12, 4, ENC_BIG_ENDIAN);
        ADDRESS_SET_GENERATED_HIDDEN(ti);
    }
}

/* RFC 6052 */
static void
add_ipv6_address_embed_ipv4(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_embed)
{
    /* Section 2.1: Well-Known Prefix for IPv4-Embedded IPv6 Address: 64:FF9B::/96 */
    static const guint8 well_known_prefix[] = {
        0x00, 0x64, 0xFF, 0x9B,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    ws_in6_addr ipv6_addr;
    ws_in4_addr ipv4_addr;
    gint ipv4_prefix;
    gint ipv4_offset;
    gboolean ipv6_embed_ipv4 = false;

    if (tvb_memeql(tvb, offset, well_known_prefix, sizeof well_known_prefix) == 0) {
        ipv4_addr = tvb_get_bits32(tvb, 96, 32, ENC_BIG_ENDIAN);
        ipv4_prefix = 96;
        ipv4_offset = 96;
        ipv6_embed_ipv4 = true;
    } else {
        for (size_t j = 0; j < number_of_nat64_prefix; j++) {
            if (nat64_prefix_uats[j].prefix_len <= nat64_prefix_uats[j].prefix_wildcard_len) {
                continue;
            }

            if (ws_inet_pton6(nat64_prefix_uats[j].ipaddr, &ipv6_addr)) {
                if (tvb_memeql(tvb, offset, (const guint8 *)&ipv6_addr,
                    (nat64_prefix_uats[j].prefix_len - nat64_prefix_uats[j].prefix_wildcard_len) / 8) == 0) {
                    switch (nat64_prefix_uats[j].prefix_len)
                    {
                        case 32:
                            ipv4_addr = tvb_get_bits32(tvb, (offset * 8) + 32, 32, ENC_BIG_ENDIAN);
                            break;
                        case 40:
                            ipv4_addr = tvb_get_bits32(tvb, (offset * 8) + 40, 24, ENC_BIG_ENDIAN) << 8;
                            ipv4_addr |= tvb_get_bits32(tvb, (offset * 8) + 72, 8, ENC_BIG_ENDIAN);
                            break;
                        case 48:
                            ipv4_addr = tvb_get_bits32(tvb, (offset * 8) + 48, 16, ENC_BIG_ENDIAN) << 16;
                            ipv4_addr |= tvb_get_bits32(tvb, (offset * 8) + 72, 16, ENC_BIG_ENDIAN);
                            break;
                        case 56:
                            ipv4_addr = tvb_get_bits32(tvb, (offset * 8) + 56, 8, ENC_BIG_ENDIAN) << 24;
                            ipv4_addr |= tvb_get_bits32(tvb, (offset * 8) + 72, 24, ENC_BIG_ENDIAN);
                            break;
                        case 64:
                            ipv4_addr = tvb_get_bits32(tvb, (offset * 8) + 72, 32, ENC_BIG_ENDIAN);
                            break;
                        case 96:
                            ipv4_addr = tvb_get_bits32(tvb, (offset * 8) + 96, 32, ENC_BIG_ENDIAN);
                            break;
                        default:
                            DISSECTOR_ASSERT_NOT_REACHED();
                    }

                    ipv4_prefix = nat64_prefix_uats[j].prefix_len;
                    if (ipv4_prefix != 64) {
                        ipv4_offset = ipv4_prefix;
                    } else {
                        ipv4_offset = 72;
                    }
                    ipv6_embed_ipv4 = true;
                    break;
                }
            }
        }
    }

    if (ipv6_embed_ipv4) {
        proto_item *ti;

        // The prefix
        ti = proto_tree_add_item(tree, hf_ipv6_embed_ipv4_prefix, tvb, offset, ipv4_prefix / 8, ENC_NA);
        PROTO_ITEM_SET_GENERATED(ti);

        // Majority of IPv4 address is after u-field
        if (ipv4_prefix >= 56) {
            if (ipv4_prefix < 96) {
                ti = proto_tree_add_item(tree, hf_ipv6_embed_ipv4_u, tvb, offset + 8, 1, ENC_NA);
                PROTO_ITEM_SET_GENERATED(ti);
            }
            if (tvb_get_guint8(tvb, offset + 8)) {
                expert_add_info(pinfo, ti, &ei_ipv6_embed_ipv4_u_value);
            }
        }

        // IPv4 embedded address
        ipv4_addr = g_ntohl(ipv4_addr);
        ti = proto_tree_add_ipv4(tree, hf_embed, tvb,
                                 offset + (ipv4_offset / 8),
                                 (ipv4_offset > 32 && ipv4_offset < 64) ? 5 : 4, ipv4_addr);
        PROTO_ITEM_SET_GENERATED(ti);

        ti = proto_tree_add_ipv4(tree, hf_ipv6_embed_ipv4, tvb,
                                 offset + (ipv4_offset / 8),
                                 (ipv4_offset > 32 && ipv4_offset < 64) ? 5 : 4, ipv4_addr);
        PROTO_ITEM_SET_GENERATED(ti);

        // Majority of IPv4 address is before u-field
        if (ipv4_prefix < 56) {
            ti = proto_tree_add_item(tree, hf_ipv6_embed_ipv4_u, tvb, offset + 8, 1, ENC_NA);
            PROTO_ITEM_SET_GENERATED(ti);
            if (tvb_get_guint8(tvb, offset + 8)) {
                expert_add_info(pinfo, ti, &ei_ipv6_embed_ipv4_u_value);
            }
        }

        // Suffix, if present
        if (ipv4_prefix < 96) {
            ti = proto_tree_add_item(tree, hf_ipv6_embed_ipv4_suffix, tvb,
                                     offset + ((72 + ipv4_prefix - 32) / 8),
                                     (56 - (ipv4_prefix - 32)) / 8,
                                     ENC_NA);
            PROTO_ITEM_SET_GENERATED(ti);
        }
    }
}

static void
export_pdu(tvbuff_t *tvb, packet_info *pinfo)
{
  if (have_tap_listener(exported_pdu_tap)) {
    exp_pdu_data_t *exp_pdu_data = wmem_new0(pinfo->pool, exp_pdu_data_t);

    exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
    exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
    exp_pdu_data->pdu_tvb = tvb;
    tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
  }
}

static int
dissect_ipv6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree    *ipv6_tree, *pt;
    proto_item    *ipv6_item, *ti, *pi;
    proto_item    *ti_ipv6_plen = NULL, *ti_ipv6_version;
    guint8         ip6_tcls, ip6_nxt, ip6_hlim;
    guint32        ip6_flow;
    const ws_in6_addr *ip6_src, *ip6_dst;
    guint32        ip6_plen = 0, jumbo_plen = 0;
    guint32        plen;
    int            offset;
    guint          reported_plen;
    tvbuff_t      *next_tvb;
    gboolean       save_fragmented;
    int            version;
    ws_ip6        *iph;

    offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPv6");
    col_clear(pinfo->cinfo, COL_INFO);

    ipv6_item = proto_tree_add_item(tree, proto_ipv6, tvb, offset, IPv6_HDR_SIZE, ENC_NA);
    ipv6_tree = proto_item_add_subtree(ipv6_item, ett_ipv6_proto);

    /* Validate IP version (6) */
    version = tvb_get_bits8(tvb, (offset + IP6H_CTL_VFC) * 8, 4);
    ti_ipv6_version = proto_tree_add_bits_item(ipv6_tree, hf_ipv6_version, tvb,
                                 (offset + IP6H_CTL_VFC) * 8, 4, ENC_BIG_ENDIAN);
    pi = proto_tree_add_item(ipv6_tree, hf_ip_version, tvb,
                                 offset + IP6H_CTL_VFC, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(pi, " [This field makes the filter match on \"ip.version == 6\" possible]");
    proto_item_set_hidden(pi);
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
                        offset + IP6H_CTL_VFC, 4, ENC_BIG_ENDIAN);
    ip6_tcls = tvb_get_bits8(tvb, (offset + IP6H_CTL_VFC) * 8 + 4, 8);
    proto_item_append_text(ti, " (DSCP: %s, ECN: %s)",
                        val_to_str_ext_const(IPDSFIELD_DSCP(ip6_tcls), &dscp_short_vals_ext, "Unknown"),
                        val_to_str_ext_const(IPDSFIELD_ECN(ip6_tcls), &ecn_short_vals_ext, "Unknown"));

    pt = proto_item_add_subtree(ti, ett_ipv6_traffic_class);
    proto_tree_add_item(pt, hf_ipv6_tclass_dscp, tvb,
                        offset + IP6H_CTL_VFC, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pt, hf_ipv6_tclass_ecn, tvb,
                        offset + IP6H_CTL_VFC, 4, ENC_BIG_ENDIAN);

    /* Set DSCP column */
    col_add_str(pinfo->cinfo, COL_DSCP_VALUE,
                val_to_str_ext(IPDSFIELD_DSCP(ip6_tcls), &dscp_short_vals_ext, "%u"));

    proto_tree_add_item_ret_uint(ipv6_tree, hf_ipv6_flow, tvb,
                        offset + IP6H_CTL_FLOW + 1, 3, ENC_BIG_ENDIAN, &ip6_flow);

    ip6_plen = tvb_get_guint16(tvb, offset + IP6H_CTL_PLEN, ENC_BIG_ENDIAN);

    ip6_nxt = tvb_get_guint8(tvb, offset + IP6H_CTL_NXT);

    if (ipv6_tso_supported && ip6_plen == 0 &&
                    ip6_nxt != IP_PROTO_HOPOPTS && ip6_nxt != IP_PROTO_NONE) {
        ip6_plen = tvb_reported_length(tvb) - IPv6_HDR_SIZE;
        pi = proto_tree_add_uint_format_value(ipv6_tree, hf_ipv6_plen, tvb,
                                offset + IP6H_CTL_PLEN, 2, ip6_plen,
                                "%u bytes (reported as 0, presumed to be because "
                                "of \"TCP segmentation offload\" (TSO))",
                                ip6_plen);
        proto_item_set_generated(pi);
    } else {
        ti_ipv6_plen = proto_tree_add_item(ipv6_tree, hf_ipv6_plen, tvb,
                                offset + IP6H_CTL_PLEN, 2, ENC_BIG_ENDIAN);
        if (ip6_plen == 0 && ip6_nxt != IP_PROTO_HOPOPTS && ip6_nxt != IP_PROTO_NONE) {
            expert_add_info(pinfo, ti_ipv6_plen, &ei_ipv6_plen_zero);
        }
    }

    proto_tree_add_item(ipv6_tree, hf_ipv6_nxt, tvb, offset + IP6H_CTL_NXT, 1, ENC_NA);

    proto_tree_add_item(ipv6_tree, hf_ipv6_hlim, tvb,
                        offset + IP6H_CTL_HLIM, 1, ENC_BIG_ENDIAN);
    ip6_hlim = tvb_get_guint8(tvb, offset + IP6H_CTL_HLIM);

    /* Source address */
    add_ipv6_address(pinfo, ipv6_tree, tvb, offset + IP6H_SRC, hf_ipv6_src, hf_ipv6_src_host);
    ip6_src = tvb_get_ptr_ipv6(tvb, offset + IP6H_SRC);
    alloc_address_wmem_ipv6(pinfo->pool, &pinfo->net_src, ip6_src);
    copy_address_shallow(&pinfo->src, &pinfo->net_src);

    /* Destination address */
    add_ipv6_address(pinfo, ipv6_tree, tvb, offset + IP6H_DST, hf_ipv6_dst, hf_ipv6_dst_host);
    ip6_dst = tvb_get_ptr_ipv6(tvb, offset + IP6H_DST);
    alloc_address_wmem_ipv6(pinfo->pool, &pinfo->net_dst, ip6_dst);
    copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

    if (tree) {
        if (ipv6_summary_in_tree) {
            proto_item_append_text(ipv6_item, ", Src: %s, Dst: %s",
                    address_with_resolution_to_str(pinfo->pool, &pinfo->src),
                    address_with_resolution_to_str(pinfo->pool, &pinfo->dst));
        }

        /* Add the different items for the address */
        add_ipv6_address_6to4(ipv6_tree, tvb, offset + IP6H_SRC,
                hf_ipv6_src_6to4_gateway_ipv4, hf_ipv6_src_6to4_sla_id);
        add_ipv6_address_6to4(ipv6_tree, tvb, offset + IP6H_DST,
                hf_ipv6_dst_6to4_gateway_ipv4, hf_ipv6_dst_6to4_sla_id);

        add_ipv6_address_teredo(ipv6_tree, tvb, offset + IP6H_SRC,
                hf_ipv6_src_teredo_server_ipv4, hf_ipv6_src_teredo_port, hf_ipv6_src_teredo_client_ipv4);
        add_ipv6_address_teredo(ipv6_tree, tvb, offset + IP6H_DST,
                hf_ipv6_dst_teredo_server_ipv4, hf_ipv6_dst_teredo_port, hf_ipv6_dst_teredo_client_ipv4);

        add_ipv6_address_slaac(pinfo, ipv6_tree, tvb, offset + IP6H_SRC, hf_ipv6_src_slaac_mac);
        add_ipv6_address_slaac(pinfo, ipv6_tree, tvb, offset + IP6H_DST, hf_ipv6_dst_slaac_mac);

        add_ipv6_address_isatap(ipv6_tree, tvb, offset + IP6H_SRC, hf_ipv6_src_isatap_ipv4);
        add_ipv6_address_isatap(ipv6_tree, tvb, offset + IP6H_DST, hf_ipv6_dst_isatap_ipv4);

        add_ipv6_address_embed_ipv4(pinfo, ipv6_tree, tvb, offset + IP6H_SRC, hf_ipv6_src_embed_ipv4);
        add_ipv6_address_embed_ipv4(pinfo, ipv6_tree, tvb, offset + IP6H_DST, hf_ipv6_dst_embed_ipv4);

        if (ipv6_use_geoip) {
            add_geoip_info(ipv6_tree, pinfo, tvb, offset, ip6_src, ip6_dst);
        }
    }

    /* Increment offset to point to next header (may be an extension header) */
    offset += IPv6_HDR_SIZE;

    /* Check for Jumbo option */
    plen = ip6_plen;
    if (plen == 0 && ip6_nxt == IP_PROTO_HOPOPTS) {
        jumbo_plen = ipv6_get_jumbo_plen(tvb, offset);
        if (jumbo_plen != 0) {
            proto_item_append_text(ti_ipv6_plen, " (Jumbogram)");
            plen = jumbo_plen;
        } else {
            /* IPv6 length zero is invalid if there is a hop-by-hop header without jumbo option */
            col_add_fstr(pinfo->cinfo, COL_INFO, "Invalid IPv6 payload length");
            expert_add_info(pinfo, ti_ipv6_plen, &ei_ipv6_opt_jumbo_missing);
        }
    }

    reported_plen = tvb_reported_length(tvb) - IPv6_HDR_SIZE;
    if (!pinfo->flags.in_error_pkt && plen > reported_plen) {
        expert_add_info_format(pinfo, ti_ipv6_plen, &ei_ipv6_plen_exceeds_framing,
                    "IPv6 payload length exceeds framing length (%d bytes)", reported_plen);
    }

    /* Fill in IP header fields for subdissectors */
    iph = wmem_new0(pinfo->pool, ws_ip6);
    iph->ip6_ver = 6;
    iph->ip6_tc = ip6_tcls;
    iph->ip6_flw = ip6_flow;
    iph->ip6_len = plen;
    iph->ip6_nxt = ip6_nxt;
    iph->ip6_hop = ip6_hlim;
    alloc_address_wmem_ipv6(pinfo->pool, &iph->ip6_src, ip6_src);
    alloc_address_wmem_ipv6(pinfo->pool, &iph->ip6_dst, ip6_dst);

    /* Shared state between IPv6 header and extensions. */
    ipv6_pinfo_t  *ipv6_pinfo = wmem_new0(pinfo->pool, ipv6_pinfo_t);
    ipv6_pinfo->ip6_plen = ip6_plen;
    ipv6_pinfo->jumbo_plen = jumbo_plen;
    ipv6_pinfo->frag_plen = ip6_plen; /* updated by extension header dissectors, if any */
    if (!ipv6_exthdr_under_root) {
        ipv6_pinfo->ipv6_tree = ipv6_tree;
        ipv6_pinfo->ipv6_item_len = IPv6_HDR_SIZE;
    }
    p_add_proto_data(pinfo->pool, pinfo, proto_ipv6, IPV6_PROTO_PINFO, ipv6_pinfo);

    /* Adjust the length of this tvbuff to include only the IPv6 datagram. */
    set_actual_length(tvb, IPv6_HDR_SIZE + plen);
    /* Only export after adjusting the length */
    export_pdu(tvb, pinfo);
    save_fragmented = pinfo->fragmented;

    p_add_ipv6_nxt(pinfo, ip6_nxt);

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    ipv6_dissect_next(ip6_nxt, next_tvb, pinfo, tree, iph);

    pinfo->fragmented = save_fragmented;
    return tvb_captured_length(tvb);
}

void
ipv6_dissect_next(guint nxt, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, ws_ip6 *iph)
{
    dissector_handle_t nxt_handle;
    ipv6_pinfo_t *ipv6_pinfo = p_get_ipv6_pinfo(pinfo);

    /* https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#extension-header */

    switch (nxt) {
        case IP_PROTO_HOPOPTS:
        case IP_PROTO_ROUTING:
        case IP_PROTO_FRAGMENT:
        //case IP_PROTO_ESP:    Even though ESP is technically an extension header,
        //                      we treat it as a payload container.
        case IP_PROTO_AH:
        case IP_PROTO_DSTOPTS:
        case IP_PROTO_MIPV6:
        //case IP_PROTO_HIP:    Even though HIP is technically an extension header, the only defined
        //                      next header is IP_NONE. Also the HIP dissector is not ready for this.
        case IP_PROTO_SHIM6:
            nxt_handle = dissector_get_uint_handle(ip_dissector_table, nxt);
            break;
        default:
            nxt_handle = NULL;
            break;
    }
    if (nxt_handle != NULL) {
        call_dissector_with_data(nxt_handle, tvb, pinfo, tree, iph);
        return;
    }

    /*
     * Done with extension header chain
     */

    if (ipv6_pinfo != NULL && ipv6_pinfo->ipv6_tree != NULL) {
        /* Set IPv6 Header length */
        proto_item_set_len(proto_tree_get_parent(ipv6_pinfo->ipv6_tree), ipv6_pinfo->ipv6_item_len);
        ipv6_pinfo->ipv6_tree = NULL;
    }

    if (iph != NULL && iph->ip6_ver == 6) {
        iph->ip6_nxt = nxt; /* upper-layer protocol more useful */
        tap_queue_packet(ipv6_tap, pinfo, iph);
    }

    if (nxt == IP_PROTO_NONE) {
        col_set_str(pinfo->cinfo, COL_INFO, "IPv6 no next header");
        call_data_dissector(tvb, pinfo, tree);
        return;
    }

    if (ip_try_dissect(try_heuristic_first, nxt, tvb, pinfo, tree, iph)) {
        return;
    }

    /* Unknown protocol. */
    col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown IP Protocol: %s (%u)", ipprotostr(nxt), nxt);
    call_data_dissector(tvb, pinfo, tree);
}

void
proto_register_ipv6(void)
{
    static hf_register_info hf_ipv6[] = {
        { &hf_ipv6_version,
            { "Version", "ipv6.version",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
        },
        { &hf_ip_version,
            { "Version", "ip.version",
                FT_UINT8, BASE_DEC, NULL, 0xF0,
                NULL, HFILL }
        },
        { &hf_ipv6_tclass,
            { "Traffic Class", "ipv6.tclass",
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
            { "Flow Label", "ipv6.flow",
                FT_UINT24, BASE_HEX, NULL, 0x0FFFFF,
                NULL, HFILL }
        },
        { &hf_ipv6_plen,
            { "Payload Length", "ipv6.plen",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_nxt,
            { "Next Header", "ipv6.nxt",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_hlim,
            { "Hop Limit", "ipv6.hlim",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_src,
            { "Source Address", "ipv6.src",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Source IPv6 Address", HFILL }
        },
        { &hf_ipv6_src_host,
            { "Source Host", "ipv6.src_host",
                FT_STRING, BASE_NONE, NULL, 0x0,
                "Source IPv6 Host", HFILL }
        },
        { &hf_ipv6_src_slaac_mac,
            { "Source SLAAC MAC", "ipv6.src_slaac_mac",
                FT_ETHER, BASE_NONE, NULL, 0x0,
                "Source IPv6 Stateless Address Autoconfiguration (SLAAC) 48-bit MAC Identifier", HFILL }
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
        { &hf_ipv6_src_embed_ipv4,
            { "Source Embedded IPv4", "ipv6.src_embed_ipv4",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                "Source IPv4-Embedded IPv6 Address", HFILL }
        },
        { &hf_ipv6_dst,
            { "Destination Address", "ipv6.dst",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Destination IPv6 Address", HFILL }
        },
        { &hf_ipv6_dst_host,
            { "Destination Host", "ipv6.dst_host",
                FT_STRING, BASE_NONE, NULL, 0x0,
                "Destination IPv6 Host", HFILL }
        },
        { &hf_ipv6_dst_slaac_mac,
            { "Destination SLAAC MAC", "ipv6.dst_slaac_mac",
                FT_ETHER, BASE_NONE, NULL, 0x0,
                "Destination IPv6 Stateless Address Autoconfiguration (SLAAC) 48-bit MAC Identifier", HFILL }
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
        { &hf_ipv6_dst_embed_ipv4,
            { "Destination Embedded IPv4", "ipv6.dst_embed_ipv4",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                "Destination IPv4-Embedded IPv6 Address", HFILL }
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
        { &hf_ipv6_slaac_mac,
            { "SLAAC MAC", "ipv6.slaac_mac",
                FT_ETHER, BASE_NONE, NULL, 0x0,
                "IPv6 Stateless Address Autoconfiguration (SLAAC) 48-bit MAC Identifier", HFILL }
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
        { &hf_ipv6_embed_ipv4_prefix,
            { "Embedded IPv4 Prefix", "ipv6.embed_ipv4_prefix",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "IPv4-Embedded IPv6 Address Prefix", HFILL }
        },
        { &hf_ipv6_embed_ipv4,
            { "Embedded IPv4", "ipv6.embed_ipv4",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                "IPv4-Embedded IPv6 Address", HFILL }
        },
        { &hf_ipv6_embed_ipv4_u,
            { "Embedded IPv4 u field", "ipv6.embed_ipv4_u",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "IPv4-Embedded IPv6 Address u field", HFILL }
        },
        { &hf_ipv6_embed_ipv4_suffix,
            { "Embedded IPv4 Suffix", "ipv6.embed_ipv4_suffix",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "IPv4-Embedded IPv6 Address Suffix", HFILL }
        },

        { &hf_geoip_country,
            { "Source or Destination GeoIP Country", "ipv6.geoip.country",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_country_iso,
            { "Source or Destination GeoIP ISO Two Letter Country Code", "ipv6.geoip.country_iso",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_city,
            { "Source or Destination GeoIP City", "ipv6.geoip.city",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_as_number,
            { "Source or Destination GeoIP AS Number", "ipv6.geoip.asnum",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_as_org,
            { "Source or Destination GeoIP AS Organization", "ipv6.geoip.org",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_latitude,
            { "Source or Destination GeoIP Latitude", "ipv6.geoip.lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_longitude,
            { "Source or Destination GeoIP Longitude", "ipv6.geoip.lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_src_summary,
            { "Source GeoIP", "ipv6.geoip.src_summary",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_src_country,
            { "Source GeoIP Country", "ipv6.geoip.src_country",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_src_country_iso,
            { "Source GeoIP ISO Two Letter Country Code", "ipv6.geoip.src_country_iso",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_src_city,
            { "Source GeoIP City", "ipv6.geoip.src_city",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_src_as_number,
            { "Source GeoIP AS Number", "ipv6.geoip.src_asnum",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_src_as_org,
            { "Source GeoIP AS Organization", "ipv6.geoip.src_org",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_src_latitude,
            { "Source GeoIP Latitude", "ipv6.geoip.src_lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_src_longitude,
            { "Source GeoIP Longitude", "ipv6.geoip.src_lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_dst_summary,
            { "Destination GeoIP", "ipv6.geoip.dst_summary",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_dst_country,
            { "Destination GeoIP Country", "ipv6.geoip.dst_country",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_dst_country_iso,
            { "Destination GeoIP ISO Two Letter Country Code", "ipv6.geoip.dst_country_iso",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_dst_city,
            { "Destination GeoIP City", "ipv6.geoip.dst_city",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_dst_as_number,
            { "Destination GeoIP AS Number", "ipv6.geoip.dst_asnum",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_dst_as_org,
            { "Destination GeoIP AS Organization", "ipv6.geoip.dst_org",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_dst_latitude,
            { "Destination GeoIP Latitude", "ipv6.geoip.dst_lat",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_geoip_dst_longitude,
            { "Destination GeoIP Longitude", "ipv6.geoip.dst_lon",
                FT_DOUBLE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },

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
            { "May Change", "ipv6.opt.type.change",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
                "Whether the option data may change en-route", HFILL }
        },
        { &hf_ipv6_opt_type_rest,
            { "Low-Order Bits", "ipv6.opt.type.rest",
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
        { &hf_ipv6_opt_pmtu_min,
            { "Minimum Reported PMTU", "ipv6.opt.pmtu.min",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "The minimum reported PMTU in octets", HFILL }
        },
        { &hf_ipv6_opt_pmtu_rtn,
            { "Return Minimum PMTU", "ipv6.opt.pmtu.rtn",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "The Return Min-PMTU in octets", HFILL }
        },
        { &hf_ipv6_opt_pmtu_rtn_flag,
            { "Return Flag", "ipv6.opt.pmtu.r_flag",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Destination should include the received reported PMTU", HFILL }
        },
        { &hf_ipv6_opt_rtalert,
            { "Router Alert", "ipv6.opt.router_alert",
                FT_UINT16, BASE_DEC, VALS(ipv6_opt_rtalert_vals), 0x0,
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
                FT_UINT32, BASE_DEC, NULL, 0x0,
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
        { &hf_ipv6_opt_smf_dpd_hash_bit,
            { "H-bit", "ipv6.opt.smf_dpd.hash_bit",
                FT_BOOLEAN, 8, NULL, 0x80,
                "Hash indicator", HFILL }
        },
        { &hf_ipv6_opt_smf_dpd_tid_type,
            { "TaggerID Type", "ipv6.opt.smf_dpd.tid_type",
                FT_UINT8, BASE_DEC, VALS(ipv6_opt_smf_dpd_tidty_vals), 0x70,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_smf_dpd_tid_len,
            { "TaggerID Length", "ipv6.opt.smf_dpd.tid_len",
                FT_UINT8, BASE_DEC, NULL, 0x0F,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_smf_dpd_tagger_id,
            { "TaggerID", "ipv6.opt.smf_dpd.tagger_id",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_smf_dpd_ident,
            { "Identifier", "ipv6.opt.smf_dpd.ident",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_smf_dpd_hav,
            { "Hash Assist Value", "ipv6.opt.smf_dpd.hav",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_pdm_scale_dtlr,
            { "Scale DTLR", "ipv6.opt.pdm.scale_dtlr",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Scale for Delta Time Last Received", HFILL }
        },
        { &hf_ipv6_opt_pdm_scale_dtls,
            { "Scale DTLS", "ipv6.opt.pdm.scale_dtls",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Scale for Delta Time Last Sent", HFILL }
        },
        { &hf_ipv6_opt_pdm_psn_this_pkt,
            { "PSN This Packet", "ipv6.opt.pdm.psn_this_pkt",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Packet Sequence Number This Packet", HFILL }
        },
        { &hf_ipv6_opt_pdm_psn_last_recv,
            { "PSN Last Received", "ipv6.opt.pdm.psn_last_recv",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Packet Sequence Number Last Received", HFILL }
        },
        { &hf_ipv6_opt_pdm_delta_last_recv,
            { "Delta Time Last Received", "ipv6.opt.pdm.delta_last_recv",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_pdm_delta_last_sent,
            { "Delta Time Last Sent", "ipv6.opt.pdm.delta_last_sent",
                FT_UINT16, BASE_DEC, NULL, 0x0,
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
        { &hf_ipv6_opt_ioam_rsv,
            { "Reserved", "ipv6.opt.ioam.rsv",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Reserved (must be zero)", HFILL }
        },
        { &hf_ipv6_opt_ioam_opt_type,
            { "Option-Type", "ipv6.opt.ioam.opt_type",
                FT_UINT8, BASE_DEC, VALS(ipv6_ioam_opt_types), 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_ns,
            { "Namespace ID", "ipv6.opt.ioam.trace.ns",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_nodelen,
            { "Node Length", "ipv6.opt.ioam.trace.nodelen",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_flags,
            { "Flags", "ipv6.opt.ioam.trace.flags",
                FT_UINT16, BASE_HEX, NULL, 0x780,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_flag_o,
            { "Overflow", "ipv6.opt.ioam.trace.flag.o",
                FT_BOOLEAN, 16, NULL, 0x400,
                "Not enough free space", HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_flag_l,
            { "Loopback", "ipv6.opt.ioam.trace.flag.l",
                FT_BOOLEAN, 16, NULL, 0x200,
                "Send a copy of the packet back towards the source", HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_flag_a,
            { "Active", "ipv6.opt.ioam.trace.flag.a",
                FT_BOOLEAN, 16, NULL, 0x100,
                "Active measurement packet", HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_flag_rsv,
            { "Reserved", "ipv6.opt.ioam.trace.flag.rsv",
                FT_BOOLEAN, 16, NULL, 0x80,
                "Reserved (must be zero)", HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_remlen,
            { "Remaining Length", "ipv6.opt.ioam.trace.remlen",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_type,
            { "Trace Type", "ipv6.opt.ioam.trace.type",
                FT_UINT24, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_type_bit0,
            { "Hop_Lim and Node ID (short)", "ipv6.opt.ioam.trace.type.bit0",
                FT_BOOLEAN, 24, NULL, 0x800000,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_type_bit1,
            { "Ingress and Egress IDs (short)", "ipv6.opt.ioam.trace.type.bit1",
                FT_BOOLEAN, 24, NULL, 0x400000,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_type_bit2,
            { "Timestamp seconds", "ipv6.opt.ioam.trace.type.bit2",
                FT_BOOLEAN, 24, NULL, 0x200000,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_type_bit3,
            { "Timestamp fraction", "ipv6.opt.ioam.trace.type.bit3",
                FT_BOOLEAN, 24, NULL, 0x100000,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_type_bit4,
            { "Transit delay", "ipv6.opt.ioam.trace.type.bit4",
                FT_BOOLEAN, 24, NULL, 0x80000,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_type_bit5,
            { "IOAM-Namespace specific data (short)", "ipv6.opt.ioam.trace.type.bit5",
                FT_BOOLEAN, 24, NULL, 0x40000,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_type_bit6,
            { "Queue depth", "ipv6.opt.ioam.trace.type.bit6",
                FT_BOOLEAN, 24, NULL, 0x20000,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_type_bit7,
            { "Checksum complement", "ipv6.opt.ioam.trace.type.bit7",
                FT_BOOLEAN, 24, NULL, 0x10000,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_type_bit8,
            { "Hop_Lim and Node ID (wide)", "ipv6.opt.ioam.trace.type.bit8",
                FT_BOOLEAN, 24, NULL, 0x8000,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_type_bit9,
            { "Ingress and Egress IDs (wide)", "ipv6.opt.ioam.trace.type.bit9",
                FT_BOOLEAN, 24, NULL, 0x4000,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_type_bit10,
            { "IOAM-Namespace specific data (wide)", "ipv6.opt.ioam.trace.type.bit10",
                FT_BOOLEAN, 24, NULL, 0x2000,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_type_bit11,
            { "Buffer occupancy", "ipv6.opt.ioam.trace.type.bit11",
                FT_BOOLEAN, 24, NULL, 0x1000,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_type_undef,
            { "Undefined", "ipv6.opt.ioam.trace.type.undef",
                FT_BOOLEAN, 24, NULL, 0xffc,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_type_bit22,
            { "Opaque State Snapshot", "ipv6.opt.ioam.trace.type.bit22",
                FT_BOOLEAN, 24, NULL, 0x2,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_type_rsv,
            { "Reserved", "ipv6.opt.ioam.trace.type.rsv",
                FT_BOOLEAN, 24, NULL, 0x1,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_rsv,
            { "Reserved", "ipv6.opt.ioam.trace.rsv",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Reserved (must be zero)", HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_free_space,
            { "Free space", "ipv6.opt.ioam.trace.free_space",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_hlim,
            { "Hop Limit", "ipv6.opt.ioam.trace.node.hlim",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_id,
            { "ID", "ipv6.opt.ioam.trace.node.id",
                FT_UINT24, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_iif,
            { "Ingress ID", "ipv6.opt.ioam.trace.node.iif",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_eif,
            { "Egress ID", "ipv6.opt.ioam.trace.node.eif",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_tss,
            { "Timestamp Seconds", "ipv6.opt.ioam.trace.node.tss",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_tsf,
            { "Timestamp Fraction", "ipv6.opt.ioam.trace.node.tsf",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_trdelay,
            { "Transit Delay", "ipv6.opt.ioam.trace.node.trdelay",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_nsdata,
            { "Namespace Data (short)", "ipv6.opt.ioam.trace.node.nsdata",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_qdepth,
            { "Queue Depth", "ipv6.opt.ioam.trace.node.qdepth",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_csum,
            { "Checksum Complement", "ipv6.opt.ioam.trace.node.csum",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_id_wide,
            { "ID", "ipv6.opt.ioam.trace.node.id_wide",
                FT_UINT56, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_iif_wide,
            { "Ingress ID", "ipv6.opt.ioam.trace.node.iif_wide",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_eif_wide,
            { "Egress ID", "ipv6.opt.ioam.trace.node.eif_wide",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_nsdata_wide,
            { "Namespace Data (wide)", "ipv6.opt.ioam.trace.node.nsdata_wide",
                FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_bufoccup,
            { "Buffer Occupancy", "ipv6.opt.ioam.trace.node.bufoccup",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_undefined,
            { "Undefined bit", "ipv6.opt.ioam.trace.node.undefined",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_oss_len,
            { "Length", "ipv6.opt.ioam.trace.node.oss.len",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_oss_scid,
            { "Schema ID", "ipv6.opt.ioam.trace.node.oss.scid",
                FT_UINT24, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_ioam_trace_node_oss_data,
            { "Data", "ipv6.opt.ioam.trace.node.oss.data",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_ipv6_opt_tpf_information,
            { "TPF Information", "ipv6.opt.tpf_information",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                "Tunnel Payload Forwarding Information", HFILL }
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
                FT_UINT8, BASE_DEC, VALS(mpl_seed_id_len_vals), 0xC0,
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
                FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
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
                FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
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
                FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
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
        { &hf_ipv6_routing_unknown_data,
            { "Type-Specific Data", "ipv6.routing.unknown_data",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "Unknown routing header type-specific data", HFILL }
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
        { &hf_ipv6_routing_srh_last_entry,
            { "Last Entry", "ipv6.routing.srh.last_entry",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Index (zero based) of the last element of the Segment List", HFILL }
        },
        { &hf_ipv6_routing_srh_flags,
            { "Flags", "ipv6.routing.srh.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "Unused, 8 bits of flags", HFILL }
        },
        { &hf_ipv6_routing_srh_tag,
            { "Tag", "ipv6.routing.srh.tag",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "Tag a packet as part of a class or group of packets", HFILL }
        },
        { &hf_ipv6_routing_srh_addr,
            { "Address", "ipv6.routing.srh.addr",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Segment address", HFILL }
        },

        /* Compact Routing Header */
        { &hf_ipv6_routing_crh16_current_sid,
            { "Current SID", "ipv6.routing.crh16.current_sid",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Value of the current Segment ID", HFILL }
        },
        { &hf_ipv6_routing_crh32_current_sid,
            { "Current SID", "ipv6.routing.crh32.current_sid",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "Value of the current Segment ID", HFILL }
        },
        { &hf_ipv6_routing_crh16_segment_id,
            { "Segment ID", "ipv6.routing.crh16.sid",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Segment address", HFILL }
        },
        { &hf_ipv6_routing_crh32_segment_id,
            { "Segment ID", "ipv6.routing.crh32.sid",
                FT_UINT32, BASE_DEC, NULL, 0x0,
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
        &ett_geoip_info,
        &ett_ipv6_opt,
        &ett_ipv6_opt_type,
        &ett_ipv6_opt_rpl,
        &ett_ipv6_opt_mpl,
        &ett_ipv6_opt_dff_flags,
        &ett_ipv6_opt_ioam_trace_flags,
        &ett_ipv6_opt_ioam_trace_types,
        &ett_ipv6_fragment,
        &ett_ipv6_fragments
    };

    static gint *ett_ipv6_hopopts[] = {
        &ett_ipv6_hopopts_proto
    };

    static gint *ett_ipv6_routing[] = {
        &ett_ipv6_routing_proto,
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
            { "ipv6.opt.jumbo.missing", PI_MALFORMED, PI_ERROR,
                "IPv6 payload length equals 0 and Hop-By-Hop present and Jumbo Payload option missing", EXPFILL }
        },
        { &ei_ipv6_opt_jumbo_prohibited,
            { "ipv6.opt.jumbo.prohibited", PI_PROTOCOL, PI_WARN,
                "When IPv6 payload length does not equal 0 a Jumbo Payload option must not be present", EXPFILL }
        },
        { &ei_ipv6_opt_jumbo_truncated,
            { "ipv6.opt.jumbo.truncated", PI_PROTOCOL, PI_WARN,
                "Jumbo Payload option present and jumbo length < 65536", EXPFILL }
        },
        { &ei_ipv6_opt_jumbo_fragment,
            { "ipv6.opt.jumbo.fragment", PI_PROTOCOL, PI_WARN,
                "Jumbo Payload option cannot be used with a fragment header", EXPFILL }
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
        { &ei_ipv6_plen_zero,
            { "ipv6.plen_zero", PI_PROTOCOL, PI_CHAT,
                "IPv6 payload length equals 0 (maybe because of \"TCP segmentation offload\" (TSO))", EXPFILL }
        },
        { &ei_ipv6_bogus_ipv6_version,
            { "ipv6.bogus_ipv6_version", PI_MALFORMED, PI_ERROR,
                "Bogus IP version", EXPFILL }
            },
        { &ei_ipv6_invalid_header,
            { "ipv6.invalid_header", PI_MALFORMED, PI_ERROR,
                "Invalid IPv6 header", EXPFILL }
        },
        { &ei_ipv6_opt_header_mismatch,
            { "ipv6.opt.header_mismatch", PI_PROTOCOL, PI_WARN,
                "Wrong options extension header for type", EXPFILL }
        },
        { &ei_ipv6_opt_deprecated,
            { "ipv6.opt.deprecated", PI_DEPRECATED, PI_NOTE,
                "Option type is deprecated", EXPFILL }
        },
        { &ei_ipv6_opt_mpl_ipv6_src_seed_id,
            { "ipv6.opt.mpl.ipv6_src_seed_id", PI_PROTOCOL, PI_COMMENT,
                "Seed ID is the IPv6 Source Address", EXPFILL }
        },
        { &ei_ipv6_opt_ioam_invalid_nodelen,
            { "ipv6.opt.ioam.trace.invalid_nodelen", PI_PROTOCOL, PI_ERROR,
                "Invalid \"NodeLen\" value: cannot be 0", EXPFILL }
        },
        { &ei_ipv6_opt_ioam_invalid_remlen,
            { "ipv6.opt.ioam.trace.invalid_remlen", PI_PROTOCOL, PI_ERROR,
                "Invalid \"RemLen\" value", EXPFILL }
        },
        { &ei_ipv6_opt_ioam_invalid_trace_type,
            { "ipv6.opt.ioam.trace.invalid_type", PI_PROTOCOL, PI_ERROR,
                "Mismatch between Trace Type and NodeLen", EXPFILL }
        },
        { &ei_ipv6_embed_ipv4_u_value,
            { "ipv6.embed_ipv4.u.nonzero", PI_PROTOCOL, PI_WARN,
                "IPv4-Embedded IPv6 address bit 64 to 71 must be zero", EXPFILL }
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
            { "ipv6.src_route_list.mult_inst_same_addr", PI_PROTOCOL, PI_WARN,
                "Multiple instances of the same address must not appear in the source route list", EXPFILL }
        },
        { &ei_ipv6_src_route_list_src_addr,
            { "ipv6.src_route_list.src_addr", PI_PROTOCOL, PI_WARN,
                "Source address must not appear in the source route list", EXPFILL }
        },
        { &ei_ipv6_src_route_list_dst_addr,
            { "ipv6.src_route_list.dst_addr", PI_PROTOCOL, PI_WARN,
                "Destination address must not appear in the source route list", EXPFILL }
        },
        { &ei_ipv6_src_route_list_multicast_addr,
            { "ipv6.src_route_list.multicast_addr", PI_PROTOCOL, PI_WARN,
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
            { "ipv6.routing.rpl.reserved_not0", PI_PROTOCOL, PI_NOTE,
                "Reserved field must equal 0 but instead was X", EXPFILL }
        },
        { &ei_ipv6_routing_invalid_length,
            { "ipv6.routing.invalid_length", PI_MALFORMED, PI_ERROR,
                "Invalid IPv6 Routing header length", EXPFILL }
            },
        { &ei_ipv6_routing_invalid_segleft,
            { "ipv6.routing.invalid_segleft", PI_PROTOCOL, PI_WARN,
                "IPv6 Routing Header segments left field must not exceed address count", EXPFILL }
        },
        { &ei_ipv6_routing_undecoded,
            { "ipv6.routing.undecoded", PI_UNDECODED, PI_NOTE,
                "Undecoded IPv6 routing header field", EXPFILL }
        },
        { &ei_ipv6_routing_deprecated,
            { "ipv6.routing.deprecated", PI_DEPRECATED, PI_NOTE,
                "Routing header type is deprecated", EXPFILL }
        }
    };

    /* Decode As handling */
    static build_valid_func ipv6_da_build_value[1] = {ipv6_value};
    static decode_as_value_t ipv6_da_values = {ipv6_prompt, 1, ipv6_da_build_value};

    static decode_as_t ipv6_da = {"ipv6", "ip.proto", 1, 0, &ipv6_da_values, NULL, NULL,
                                  decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    static decode_as_t ipv6_hopopts_da = {"ipv6.hopopts", "ip.proto", 1, 0, &ipv6_da_values, NULL, NULL,
                                  decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    static decode_as_t ipv6_routing_da = {"ipv6.routing", "ip.proto", 1, 0, &ipv6_da_values, NULL, NULL,
                                  decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    static decode_as_t ipv6_fraghdr_da = {"ipv6.fraghdr", "ip.proto", 1, 0, &ipv6_da_values, NULL, NULL,
                                  decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    static decode_as_t ipv6_dstopts_da = {"ipv6.dstopts", "ip.proto", 1, 0, &ipv6_da_values, NULL, NULL,
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

    ipv6_routing_dissector_table = register_dissector_table("ipv6.routing.type", "IPv6 Routing Type",
                                                proto_ipv6_routing, FT_UINT8, BASE_DEC);

    proto_ipv6_routing_rt0 = proto_register_protocol_in_name_only("IPv6 Routing Type - Source Route", "Source Route", "ipv6.routing.type.rt0", proto_ipv6, FT_BYTES);
    proto_ipv6_routing_mipv6 = proto_register_protocol_in_name_only("IPv6 Routing Type - Type 2", "Type 2", "ipv6.routing.type.mipv6", proto_ipv6, FT_BYTES);
    proto_ipv6_routing_rpl = proto_register_protocol_in_name_only("IPv6 Routing Type - RPL Source Route", "RPL Source Route", "ipv6.routing.type.mipv6", proto_ipv6, FT_BYTES);
    proto_ipv6_routing_srh = proto_register_protocol_in_name_only("IPv6 Routing Types - Segment Routing", "Segment Routing", "ipv6.routing.type.srh", proto_ipv6, FT_BYTES);
    proto_ipv6_routing_crh = proto_register_protocol_in_name_only("IPv6 Routing Types - Compact Routing", "Compact Routing", "ipv6.routing.type.crh", proto_ipv6, FT_BYTES);

    proto_ipv6_fraghdr = proto_register_protocol("Fragment Header for IPv6", "IPv6 Fragment", "ipv6.fraghdr");
    proto_register_field_array(proto_ipv6_fraghdr, hf_ipv6_fraghdr, array_length(hf_ipv6_fraghdr));
    proto_register_subtree_array(ett_ipv6_fraghdr, array_length(ett_ipv6_fraghdr));

    proto_ipv6_dstopts = proto_register_protocol("Destination Options for IPv6", "IPv6 Destination", "ipv6.dstopts");
    proto_register_field_array(proto_ipv6_dstopts, hf_ipv6_dstopts, array_length(hf_ipv6_dstopts));
    proto_register_subtree_array(ett_ipv6_dstopts, array_length(ett_ipv6_dstopts));

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
    prefs_register_bool_preference(ipv6_module, "use_geoip" ,
                                   "Enable IPv6 geolocation",
                                   "Whether to look up IPv6 addresses in each MaxMind database we have loaded",
                                   &ipv6_use_geoip);

    /* RPL Strict Header Checking */
    prefs_register_bool_preference(ipv6_module, "perform_strict_rpl_srh_rfc_checking",
                                   "Perform strict checking for RPL Source Routing Headers (RFC 6554)",
                                   "Check that all RPL Source Routed packets conform to RFC 6554 and do not visit a node more than once",
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

    prefs_register_bool_preference(ipv6_module, "tso_support",
                                    "Support packet-capture from IPv6 TSO-enabled hardware",
                                    "Whether to correct for TSO-enabled (TCP segmentation offload) hardware "
                                    "captures, such as spoofing the IPv6 packet length", &ipv6_tso_supported);

    static uat_field_t nat64_uats_flds[] = {
        UAT_FLD_CSTRING_OTHER(nat64_prefix_uats, ipaddr, "NAT64 Prefix", nat64_prefix_uat_fld_ip_chk_cb, "IPv6 prefix address"),
        UAT_FLD_VS(nat64_prefix_uats, prefix_len, "Prefix length", nat64_prefix_length_vals, "IPv6 prefix address length"),
        UAT_FLD_VS(nat64_prefix_uats, prefix_wildcard_len, "Prefix wildcard length", nat64_prefix_wildcard_length_vals, "IPv6 prefix address wildcard length"),
        UAT_END_FIELDS
    };

    nat64_prefix_uat = uat_new("NAT64 Network-Specific Prefixes",
        sizeof(struct nat64_prefix_data),
        "NAT64_NSP_list",               /* filename */
        TRUE,                           /* from_profile */
        &nat64_prefix_uats,             /* data_ptr */
        &number_of_nat64_prefix,        /* numitems_ptr */
        UAT_AFFECTS_DISSECTION,
        NULL,
        nat64_prefix_copy_cb,
        NULL,
        nat64_prefix_free_cb,
        NULL,
        NULL,
        nat64_uats_flds);

    prefs_register_uat_preference(ipv6_module, "nat64_prefixes",
        "NAT64 Prefixes",
        "A list of IPv6 prefixes used for NAT64s",
        nat64_prefix_uat);

    ipv6_handle = register_dissector("ipv6", dissect_ipv6, proto_ipv6);
    reassembly_table_register(&ipv6_reassembly_table,
                          &addresses_reassembly_table_functions);
    ipv6_tap = register_tap("ipv6");

    register_decode_as(&ipv6_da);
    register_decode_as(&ipv6_hopopts_da);
    register_decode_as(&ipv6_routing_da);
    register_decode_as(&ipv6_fraghdr_da);
    register_decode_as(&ipv6_dstopts_da);

    register_conversation_table(proto_ipv6, TRUE, ipv6_conversation_packet, ipv6_hostlist_packet);
    register_conversation_filter("ipv6", "IPv6", ipv6_filter_valid, ipv6_build_filter);

    register_capture_dissector("ipv6", capture_ipv6, proto_ipv6);
}

void
proto_reg_handoff_ipv6(void)
{
    dissector_handle_t ipv6_hopopts_handle;
    dissector_handle_t ipv6_routing_handle;
    dissector_handle_t ipv6_fraghdr_handle;
    dissector_handle_t ipv6_dstopts_handle;
    capture_dissector_handle_t ipv6_cap_handle;
    capture_dissector_handle_t ipv6_ext_cap_handle;
    dissector_handle_t h;

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
    dissector_add_uint("pwach.channel_type", PW_ACH_TYPE_IPV6, ipv6_handle);
    dissector_add_uint("mcc.proto", PW_ACH_TYPE_IPV6, ipv6_handle);
    dissector_add_uint("sflow_245.header_protocol", SFLOW_245_HEADER_IPv6, ipv6_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_RAW_IP6, ipv6_handle);
    dissector_add_uint("enc", BSD_AF_INET6_BSD, ipv6_handle);
    dissector_add_uint("vxlan.next_proto", VXLAN_IPV6, ipv6_handle);
    dissector_add_uint("nsh.next_proto", NSH_IPV6, ipv6_handle);

    dissector_add_for_decode_as_with_preference("udp.port", ipv6_handle);

    ipv6_hopopts_handle = create_dissector_handle(dissect_hopopts, proto_ipv6_hopopts);
    dissector_add_uint("ip.proto", IP_PROTO_HOPOPTS, ipv6_hopopts_handle);

    ipv6_routing_handle = create_dissector_handle(dissect_routing6, proto_ipv6_routing);
    dissector_add_uint("ip.proto", IP_PROTO_ROUTING, ipv6_routing_handle);

    ipv6_fraghdr_handle = create_dissector_handle(dissect_fraghdr, proto_ipv6_fraghdr);
    dissector_add_uint("ip.proto", IP_PROTO_FRAGMENT, ipv6_fraghdr_handle);

    ipv6_dstopts_handle = create_dissector_handle(dissect_dstopts, proto_ipv6_dstopts);
    dissector_add_uint("ip.proto", IP_PROTO_DSTOPTS, ipv6_dstopts_handle);

    ip_dissector_table = find_dissector_table("ip.proto");

    ipv6_cap_handle = find_capture_dissector("ipv6");
    capture_dissector_add_uint("ethertype", ETHERTYPE_IPv6, ipv6_cap_handle);
    capture_dissector_add_uint("enc", BSD_AF_INET6_BSD, ipv6_cap_handle);
    capture_dissector_add_uint("null.bsd", BSD_AF_INET6_BSD, ipv6_cap_handle);
    capture_dissector_add_uint("null.bsd", BSD_AF_INET6_FREEBSD, ipv6_cap_handle);
    capture_dissector_add_uint("null.bsd", BSD_AF_INET6_DARWIN, ipv6_cap_handle);
    capture_dissector_add_uint("fr.nlpid", NLPID_IP6, ipv6_cap_handle);

    ipv6_ext_cap_handle = create_capture_dissector_handle(capture_ipv6_exthdr, proto_ipv6_hopopts);
    capture_dissector_add_uint("ip.proto", IP_PROTO_HOPOPTS, ipv6_ext_cap_handle);
    ipv6_ext_cap_handle = create_capture_dissector_handle(capture_ipv6_exthdr, proto_ipv6_routing);
    capture_dissector_add_uint("ip.proto", IP_PROTO_ROUTING, ipv6_ext_cap_handle);
    ipv6_ext_cap_handle = create_capture_dissector_handle(capture_ipv6_exthdr, proto_ipv6_fraghdr);
    capture_dissector_add_uint("ip.proto", IP_PROTO_FRAGMENT, ipv6_ext_cap_handle);
    ipv6_ext_cap_handle = create_capture_dissector_handle(capture_ipv6_exthdr, proto_ipv6_dstopts);
    capture_dissector_add_uint("ip.proto", IP_PROTO_DSTOPTS, ipv6_ext_cap_handle);

    h = create_dissector_handle(dissect_routing6_rt0, proto_ipv6_routing_rt0);
    dissector_add_uint("ipv6.routing.type", IPv6_RT_HEADER_SOURCE_ROUTING, h);
    h = create_dissector_handle(dissect_routing6_mipv6, proto_ipv6_routing_mipv6);
    dissector_add_uint("ipv6.routing.type", IPv6_RT_HEADER_MOBILE_IP, h);
    h = create_dissector_handle(dissect_routing6_rpl, proto_ipv6_routing_rpl);
    dissector_add_uint("ipv6.routing.type", IPv6_RT_HEADER_RPL, h);
    h = create_dissector_handle(dissect_routing6_srh, proto_ipv6_routing_srh);
    dissector_add_uint("ipv6.routing.type", IPv6_RT_HEADER_SEGMENT_ROUTING, h);
    h = create_dissector_handle(dissect_routing6_crh, proto_ipv6_routing_crh);
    dissector_add_uint("ipv6.routing.type", IPv6_RT_HEADER_COMPACT_16, h);
    dissector_add_uint("ipv6.routing.type", IPv6_RT_HEADER_COMPACT_32, h);

    exported_pdu_tap = find_tap_id("IP");
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
