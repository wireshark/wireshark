/* packet-icmpv6.c
 * Routines for ICMPv6 packet disassembly
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * MobileIPv6 support added by Tomislav Borosa <tomislav.borosa@siemens.hr>
 * Copyright 2006, Nicolas DICHTEL - 6WIND - <nicolas.dichtel@6wind.com>
 *
 * HMIPv6 support added by Martti Kuparinen <martti.kuparinen@iki.fi>
 *
 * FMIPv6 support added by Martin Andre <andre@clarinet.u-strasbg.fr>
 *
 * RPL support added by Colin O'Flynn & Owen Kirby.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/in_cksum.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/asn1.h>
#include <epan/strutil.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-ipv6.h"
#include "packet-dns.h"
#include "packet-x509af.h"
#include "packet-x509if.h"


#ifndef offsetof
#define offsetof(type, member)  ((size_t)(&((type *)0)->member))
#endif

/*
 * The information used comes from:
 * RFC 2461: Neighbor Discovery for IP Version 6 (IPv6)
 * RFC 2894: Router Renumbering for IPv6
 * RFC 4068: Fast Handovers for Mobile IPv6
 * RFC 4620: IPv6 Node Information Queries
 * RFC 4861: Neighbor Discovery for IP version 6 (IPv6)
 * draft-ietf-mobileip-hmipv6-05.txt
 * draft-ieft-roll-rpl-12.txt
 */


static int proto_icmpv6 = -1;
static int hf_icmpv6_type = -1;
static int hf_icmpv6_code = -1;
static int hf_icmpv6_checksum = -1;
static int hf_icmpv6_checksum_bad = -1;
static int hf_icmpv6_reserved = -1;
static int hf_icmpv6_nor = -1;
static int hf_icmpv6_haad_ha_addrs = -1;
static int hf_icmpv6_ra_cur_hop_limit = -1;
static int hf_icmpv6_ra_router_lifetime = -1;
static int hf_icmpv6_ra_reachable_time = -1;
static int hf_icmpv6_ra_retrans_timer = -1;

/* RPL: draft-ietf-roll-rpl-12.txt: Routing over Low-Power and Lossy Networks. */
static int hf_icmpv6_dis_reserved = -1;
static int hf_icmpv6_dio_grounded = -1;
static int hf_icmpv6_dio_preference = -1;
static int hf_icmpv6_dio_rank = -1;
static int hf_icmpv6_dio_instance = -1;
static int hf_icmpv6_dio_version = -1;
static int hf_icmpv6_dio_zero = -1;
static int hf_icmpv6_dio_trigger_seqnum = -1;
static int hf_icmpv6_dio_dagid = -1;
static int hf_icmpv6_dio_mop = -1;
static int hf_icmpv6_dao_instance = -1;
static int hf_icmpv6_dao_seqnum = -1;
static int hf_icmpv6_dao_reserved = -1;
static int hf_icmpv6_dao_flag_k = -1;
static int hf_icmpv6_dao_flag_d = -1;
static int hf_icmpv6_dao_flag_rsv = -1;
static int hf_icmpv6_dao_dodagid = -1;
static int hf_icmpv6_daoack_instance = -1;
static int hf_icmpv6_daoack_seqnum = -1;
static int hf_icmpv6_daoack_status = -1;
static int hf_icmpv6_daoack_flag_d = -1;
static int hf_icmpv6_daoack_flag_rsv = -1;
static int hf_icmpv6_daoack_dodagid = -1;
static int hf_icmpv6_rpl_opt = -1;
static int hf_icmpv6_rpl_opt_type = -1;
static int hf_icmpv6_rpl_opt_length = -1;
static int hf_icmpv6_rpl_opt_reserved = -1;
static int hf_icmpv6_rpl_opt_padn = -1;
static int hf_icmpv6_rpl_opt_route_prefix_length = -1;
static int hf_icmpv6_rpl_opt_route_flag = -1;
static int hf_icmpv6_rpl_opt_route_pref = -1;
static int hf_icmpv6_rpl_opt_route_reserved = -1;
static int hf_icmpv6_rpl_opt_route_lifetime = -1;
static int hf_icmpv6_rpl_opt_route_prefix = -1;
static int hf_icmpv6_rpl_opt_config_flag = -1;
static int hf_icmpv6_rpl_opt_config_reserved = -1;
static int hf_icmpv6_rpl_opt_config_auth = -1;
static int hf_icmpv6_rpl_opt_config_pcs = -1;
static int hf_icmpv6_rpl_opt_config_doublings = -1;
static int hf_icmpv6_rpl_opt_config_min_interval = -1;
static int hf_icmpv6_rpl_opt_config_redundancy = -1;
static int hf_icmpv6_rpl_opt_config_rank_incr = -1;
static int hf_icmpv6_rpl_opt_config_hop_rank_inc = -1;
static int hf_icmpv6_rpl_opt_config_ocp = -1;
static int hf_icmpv6_rpl_opt_config_rsv = -1;
static int hf_icmpv6_rpl_opt_config_def_lifetime = -1;
static int hf_icmpv6_rpl_opt_config_lifetime_unit = -1;
static int hf_icmpv6_rpl_opt_target_flag = -1;
static int hf_icmpv6_rpl_opt_target_prefix_length = -1;
static int hf_icmpv6_rpl_opt_target_prefix = -1;
static int hf_icmpv6_rpl_opt_transit_flag = -1;
static int hf_icmpv6_rpl_opt_transit_flag_e = -1;
static int hf_icmpv6_rpl_opt_transit_flag_rsv = -1;
static int hf_icmpv6_rpl_opt_transit_pathseq = -1;
static int hf_icmpv6_rpl_opt_transit_pathctl = -1;
static int hf_icmpv6_rpl_opt_transit_pathlifetime = -1;
static int hf_icmpv6_rpl_opt_transit_parent = -1;
static int hf_icmpv6_rpl_opt_solicited_instance = -1;
static int hf_icmpv6_rpl_opt_solicited_flag = -1;
static int hf_icmpv6_rpl_opt_solicited_flag_v = -1;
static int hf_icmpv6_rpl_opt_solicited_flag_i = -1;
static int hf_icmpv6_rpl_opt_solicited_flag_d = -1;
static int hf_icmpv6_rpl_opt_solicited_flag_rsv = -1;
static int hf_icmpv6_rpl_opt_solicited_dodagid = -1;
static int hf_icmpv6_rpl_opt_solicited_version = -1;
static int hf_icmpv6_rpl_opt_prefix = -1;
static int hf_icmpv6_rpl_opt_prefix_flag = -1;
static int hf_icmpv6_rpl_opt_prefix_flag_l = -1;
static int hf_icmpv6_rpl_opt_prefix_flag_a = -1;
static int hf_icmpv6_rpl_opt_prefix_flag_r = -1;
static int hf_icmpv6_rpl_opt_prefix_flag_rsv = -1;
static int hf_icmpv6_rpl_opt_prefix_vlifetime = -1;
static int hf_icmpv6_rpl_opt_prefix_plifetime = -1;
static int hf_icmpv6_rpl_opt_prefix_length = -1;
static int hf_icmpv6_rpl_opt_targetdesc = -1;

static int hf_icmpv6_opt = -1;
static int hf_icmpv6_opt_type = -1;
static int hf_icmpv6_opt_length = -1;
static int hf_icmpv6_opt_linkaddr_mac = -1;
static int hf_icmpv6_opt_src_linkaddr_mac = -1;
static int hf_icmpv6_opt_target_linkaddr_mac = -1;
static int hf_icmpv6_opt_linkaddr = -1;
static int hf_icmpv6_opt_src_linkaddr = -1;
static int hf_icmpv6_opt_target_linkaddr = -1;
static int hf_icmpv6_opt_prefix_len = -1;
static int hf_icmpv6_opt_prefix_flag = -1;
static int hf_icmpv6_opt_prefix_flag_l = -1;
static int hf_icmpv6_opt_prefix_flag_a = -1;
static int hf_icmpv6_opt_prefix_flag_reserved = -1;
static int hf_icmpv6_opt_prefix_valid_lifetime = -1;
static int hf_icmpv6_opt_prefix_preferred_lifetime = -1;
static int hf_icmpv6_opt_prefix = -1;
static int hf_icmpv6_opt_naack_option_code = -1;
static int hf_icmpv6_opt_naack_status = -1;
static int hf_icmpv6_opt_naack_supplied_ncoa = -1;
static int hf_icmpv6_opt_cga_pad_len = -1;
static int hf_icmpv6_opt_cga = -1;
static int hf_icmpv6_opt_cga_modifier = -1;
static int hf_icmpv6_opt_cga_subnet_prefix = -1;
static int hf_icmpv6_opt_cga_count = -1;
static int hf_icmpv6_opt_cga_ext_type = -1;
static int hf_icmpv6_opt_cga_ext_length = -1;
static int hf_icmpv6_opt_cga_ext_data = -1;
static int hf_icmpv6_opt_rsa_key_hash = -1;
static int hf_icmpv6_opt_digital_signature_padding = -1;
static int hf_icmpv6_opt_timestamp = -1;
static int hf_icmpv6_opt_nonce = -1;
static int hf_icmpv6_opt_certificate_padding = -1;
static int hf_icmpv6_opt_ipa_option_code = -1;
static int hf_icmpv6_opt_ipa_prefix_len = -1;
static int hf_icmpv6_opt_ipa_ipv6_address = -1;
static int hf_icmpv6_opt_nrpi_option_code = -1;
static int hf_icmpv6_opt_nrpi_prefix_len = -1;
static int hf_icmpv6_opt_nrpi_prefix = -1;
static int hf_icmpv6_opt_lla_option_code = -1;
static int hf_icmpv6_opt_lla_bytes = -1;
static int hf_icmpv6_opt_map_dist = -1;
static int hf_icmpv6_opt_map_pref = -1;
static int hf_icmpv6_opt_map_flag = -1;
static int hf_icmpv6_opt_map_flag_r = -1;
static int hf_icmpv6_opt_map_flag_reserved = -1;
static int hf_icmpv6_opt_map_valid_lifetime = -1;
static int hf_icmpv6_opt_map_global_address = -1;
static int hf_icmpv6_opt_route_info_flag = -1;
static int hf_icmpv6_opt_route_info_flag_route_preference = -1;
static int hf_icmpv6_opt_route_info_flag_reserved = -1;
static int hf_icmpv6_opt_route_lifetime = -1;
static int hf_icmpv6_opt_name_type = -1;
static int hf_icmpv6_opt_name_x501 = -1;
static int hf_icmpv6_opt_name_fqdn = -1;
static int hf_icmpv6_opt_cert_type = -1;
static int hf_icmpv6_identifier = -1;
static int hf_icmpv6_all_comp = -1;
static int hf_icmpv6_comp = -1;
static int hf_icmpv6_x509if_Name = -1;
static int hf_icmpv6_x509af_Certificate = -1;
static int hf_icmpv6_opt_redirected_packet = -1;
static int hf_icmpv6_opt_mtu = -1;
static int hf_icmpv6_opt_nbma_shortcut_limit = -1;
static int hf_icmpv6_opt_advertisement_interval = -1;
static int hf_icmpv6_opt_home_agent_preference = -1;
static int hf_icmpv6_opt_home_agent_lifetime = -1;
static int hf_icmpv6_opt_ipv6_address = -1;
static int hf_icmpv6_opt_reserved = -1;
static int hf_icmpv6_opt_padding = -1;
static int hf_icmpv6_opt_rdnss_lifetime = -1;
static int hf_icmpv6_opt_rdnss = -1;
static int hf_icmpv6_opt_efo = -1;
static int hf_icmpv6_opt_efo_m = -1;
static int hf_icmpv6_opt_efo_o = -1;
static int hf_icmpv6_opt_efo_h = -1;
static int hf_icmpv6_opt_efo_prf = -1;
static int hf_icmpv6_opt_efo_p = -1;
static int hf_icmpv6_opt_efo_rsv = -1;
static int hf_icmpv6_opt_hkr_pad_length = -1;
static int hf_icmpv6_opt_hkr_at = -1;
static int hf_icmpv6_opt_hkr_reserved = -1;
static int hf_icmpv6_opt_hkr_encryption_public_key = -1;
static int hf_icmpv6_opt_hkr_padding = -1;
static int hf_icmpv6_opt_hkr_lifetime = -1;
static int hf_icmpv6_opt_hkr_encrypted_handover_key = -1;
static int hf_icmpv6_opt_hai_option_code = -1;
static int hf_icmpv6_opt_hai_length = -1;
static int hf_icmpv6_opt_hai_value = -1;
static int hf_icmpv6_opt_mn_option_code = -1;
static int hf_icmpv6_opt_mn_length = -1;
static int hf_icmpv6_opt_mn_value = -1;
static int hf_icmpv6_opt_dnssl_lifetime = -1;
static int hf_icmpv6_opt_dnssl = -1;

static int hf_icmpv6_opt_aro_status = -1;
static int hf_icmpv6_opt_aro_registration_lifetime = -1;
static int hf_icmpv6_opt_aro_eui64 = -1;
static int hf_icmpv6_opt_6co_context_length = -1;
static int hf_icmpv6_opt_6co_flag = -1;
static int hf_icmpv6_opt_6co_flag_c = -1;
static int hf_icmpv6_opt_6co_flag_cid = -1;
static int hf_icmpv6_opt_6co_flag_reserved = -1;
static int hf_icmpv6_opt_6co_valid_lifetime = -1;
static int hf_icmpv6_opt_6co_context_prefix  = -1;
static int hf_icmpv6_opt_abro_version = -1;
static int hf_icmpv6_opt_abro_6lbr_address = -1;

static int hf_icmpv6_ni_qtype = -1;
static int hf_icmpv6_ni_flag = -1;
static int hf_icmpv6_ni_flag_g = -1;
static int hf_icmpv6_ni_flag_s = -1;
static int hf_icmpv6_ni_flag_l = -1;
static int hf_icmpv6_ni_flag_c = -1;
static int hf_icmpv6_ni_flag_a = -1;
static int hf_icmpv6_ni_flag_t = -1;
static int hf_icmpv6_ni_flag_rsv = -1;
static int hf_icmpv6_ni_nonce = -1;
static int hf_icmpv6_ni_query_subject_ipv6 = -1;
static int hf_icmpv6_ni_query_subject_fqdn = -1;
static int hf_icmpv6_ni_query_subject_ipv4 = -1;
static int hf_icmpv6_ni_reply_node_ttl = -1;
static int hf_icmpv6_ni_reply_node_name = -1;
static int hf_icmpv6_ni_reply_node_address = -1;
static int hf_icmpv6_ni_reply_ipv4_address = -1;

static int hf_icmpv6_rr_sequencenumber = -1;
static int hf_icmpv6_rr_segmentnumber = -1;
static int hf_icmpv6_rr_flag = -1;
static int hf_icmpv6_rr_flag_t = -1;
static int hf_icmpv6_rr_flag_r = -1;
static int hf_icmpv6_rr_flag_a = -1;
static int hf_icmpv6_rr_flag_s = -1;
static int hf_icmpv6_rr_flag_p = -1;
static int hf_icmpv6_rr_flag_rsv = -1;
static int hf_icmpv6_rr_maxdelay = -1;
static int hf_icmpv6_rr_pco_mp_part = -1;
static int hf_icmpv6_rr_pco_mp_opcode = -1;
static int hf_icmpv6_rr_pco_mp_oplength = -1;
static int hf_icmpv6_rr_pco_mp_ordinal = -1;
static int hf_icmpv6_rr_pco_mp_matchlen = -1;
static int hf_icmpv6_rr_pco_mp_minlen = -1;
static int hf_icmpv6_rr_pco_mp_maxlen = -1;
static int hf_icmpv6_rr_pco_mp_matchprefix = -1;
static int hf_icmpv6_rr_pco_up_part = -1;
static int hf_icmpv6_rr_pco_up_uselen = -1;
static int hf_icmpv6_rr_pco_up_keeplen = -1;
static int hf_icmpv6_rr_pco_up_flagmask = -1;
static int hf_icmpv6_rr_pco_up_flagmask_l = -1;
static int hf_icmpv6_rr_pco_up_flagmask_a = -1;
static int hf_icmpv6_rr_pco_up_flagmask_reserved = -1;
static int hf_icmpv6_rr_pco_up_raflags = -1;
static int hf_icmpv6_rr_pco_up_raflags_l = -1;
static int hf_icmpv6_rr_pco_up_raflags_a = -1;
static int hf_icmpv6_rr_pco_up_raflags_reserved = -1;
static int hf_icmpv6_rr_pco_up_validlifetime = -1;
static int hf_icmpv6_rr_pco_up_preferredlifetime = -1;
static int hf_icmpv6_rr_pco_up_flag = -1;
static int hf_icmpv6_rr_pco_up_flag_v = -1;
static int hf_icmpv6_rr_pco_up_flag_p = -1;
static int hf_icmpv6_rr_pco_up_flag_reserved = -1;
static int hf_icmpv6_rr_pco_up_useprefix = -1;
static int hf_icmpv6_rr_rm = -1;
static int hf_icmpv6_rr_rm_flag = -1;
static int hf_icmpv6_rr_rm_flag_b = -1;
static int hf_icmpv6_rr_rm_flag_f = -1;
static int hf_icmpv6_rr_rm_flag_reserved = -1;
static int hf_icmpv6_rr_rm_ordinal = -1;
static int hf_icmpv6_rr_rm_matchedlen = -1;
static int hf_icmpv6_rr_rm_interfaceindex = -1;
static int hf_icmpv6_rr_rm_matchedprefix = -1;

static gint ett_icmpv6 = -1;
static gint ett_icmpv6opt = -1;
static gint ett_icmpv6flag = -1;
static gint ett_multicastRR = -1;
static gint ett_icmpv6opt_name = -1;
static gint ett_cga_param_name = -1;
static gint ett_dao_rr_stack = -1;

static dissector_handle_t ipv6_handle;
static dissector_handle_t data_handle;

static const value_string icmpv6_type_str[] = {
    { ICMP6_DST_UNREACH,           "Unreachable" },
    { ICMP6_PACKET_TOO_BIG,        "Too big" },
    { ICMP6_TIME_EXCEEDED,         "Time exceeded" },
    { ICMP6_PARAM_PROB,            "Parameter problem" },
    { 100,                         "Private experimentation" },
    { 101,                         "Private experimentation" },
    { 127,                         "Reserved for expansion of ICMPv6 error messages" },
    { ICMP6_ECHO_REQUEST,          "Echo (ping) request" },
    { ICMP6_ECHO_REPLY,            "Echo (ping) reply" },
    { ICMP6_MEMBERSHIP_QUERY,      "Multicast listener query" },
    { ICMP6_MEMBERSHIP_REPORT,     "Multicast listener report" },
    { ICMP6_MEMBERSHIP_REDUCTION,  "Multicast listener done" },
    { ND_ROUTER_SOLICIT,           "Router solicitation" },
    { ND_ROUTER_ADVERT,            "Router advertisement" },
    { ND_NEIGHBOR_SOLICIT,         "Neighbor solicitation" },
    { ND_NEIGHBOR_ADVERT,          "Neighbor advertisement" },
    { ND_REDIRECT,                 "Redirect" },
    { ICMP6_ROUTER_RENUMBERING,    "Router renumbering" },
    { ICMP6_NI_QUERY,              "Node information query" },
    { ICMP6_NI_REPLY,              "Node information reply" },
    { ICMP6_IND_SOLICIT,           "Inverse neighbor discovery solicitation" },
    { ICMP6_IND_ADVERT,            "Inverse neighbor discovery advertisement" },
    { ICMP6_MLDV2_REPORT,          "Multicast Listener Report Message v2" },
    { ICMP6_MIP6_DHAAD_REQUEST,    "Dynamic Home Agent Address Discovery Request" },
    { ICMP6_MIP6_DHAAD_REPLY,      "Dynamic Home Agent Address Discovery Reply" },
    { ICMP6_MIP6_MPS,              "Mobile Prefix Solicitation" },
    { ICMP6_MIP6_MPA,              "Mobile Prefix Advertisement" },
    { ICMP6_CERT_PATH_SOL,         "Certification Path Solicitation" },
    { ICMP6_CERT_PATH_AD,          "Certification Path Advertisement" },
    { ICMP6_EXPERIMENTAL_MOBILITY, "Experimental Mobility" },
    { ICMP6_MCAST_ROUTER_ADVERT,   "Multicast Router Advertisement" },
    { ICMP6_MCAST_ROUTER_SOLICIT,  "Multicast Router Solicitation" },
    { ICMP6_MCAST_ROUTER_TERM,     "Multicast Router Termination" },
    { ICMP6_FMIPV6_MESSAGES,       "FMIPv6 Messages" },
    { ICMP6_RPL_CONTROL,           "RPL Control Message" },
    { 200,                         "Private experimentation" },
    { 201,                         "Private experimentation" },
    { 255,                         "Reserved for expansion of ICMPv6 informational messages" },
    { 0, NULL }
};

static const value_string icmpv6_unreach_code_str[] = {
    { ICMP6_DST_UNREACH_NOROUTE,     "Route unreachable" },
    { ICMP6_DST_UNREACH_ADMIN,       "Administratively prohibited" },
    { ICMP6_DST_UNREACH_BEYONDSCOPE, "Beyond scope of source address" },
    { ICMP6_DST_UNREACH_ADDR,        "Address unreachable" },
    { ICMP6_DST_UNREACH_NOPORT,      "Port unreachable" },
    { ICMP6_DST_UNREACH_INGR_EGR,    "Source address failed ingress/egress policy" },
    { ICMP6_DST_UNREACH_REJECT,      "Reject route to destination" },
    { 0, NULL }
};

static const value_string icmpv6_timeex_code_str[] = {
    { ICMP6_TIME_EXCEED_TRANSIT,    "In-transit" },
    { ICMP6_TIME_EXCEED_REASSEMBLY, "Reassembly" },
    { 0, NULL }
};

static const value_string icmpv6_paramprob_code_str[] = {
    { ICMP6_PARAMPROB_HEADER,     "Header" },
    { ICMP6_PARAMPROB_NEXTHEADER, "Next header" },
    { ICMP6_PARAMPROB_OPTION,     "Option" },
    { 0, NULL }
};

static const value_string icmpv6_router_renum_code_str[] = {
    { ICMP6_ROUTER_RENUMBERING_COMMAND,      "Command" },
    { ICMP6_ROUTER_RENUMBERING_RESULT,       "Result" },
    { ICMP6_ROUTER_RENUMBERING_SEQNUM_RESET, "Sequence number reset" },
    { 0, NULL }
};

/*
    RFC4620 - IPv6 Node Information Queries
*/

#define NI_QTYPE_NOOP		0 /* NOOP  */
#define NI_QTYPE_SUPTYPES	1 /* Supported Qtypes (Obso) */
#define NI_QTYPE_NODENAME	2 /* Node Name */
#define NI_QTYPE_NODEADDR	3 /* Node Addresses */
#define NI_QTYPE_IPV4ADDR	4 /* IPv4 Addresses */

static const value_string ni_qtype_val[] = {
    { NI_QTYPE_NOOP,            "NOOP" },
    { NI_QTYPE_SUPTYPES,        "Supported query types (Obsolete)" },
    { NI_QTYPE_NODENAME,        "Node Name" },
    { NI_QTYPE_NODEADDR,        "Node addresses" },
    { NI_QTYPE_IPV4ADDR,        "IPv4 node addresses" },
    { 0,                        NULL }
};
#define NI_FLAG_G	0x0020
#define NI_FLAG_S	0x0010
#define NI_FLAG_L	0x0008
#define NI_FLAG_C	0x0004
#define NI_FLAG_A	0x0002
#define NI_FLAG_T	0x0001
#define NI_FLAG_RSV     0xFFC0

static const true_false_string tfs_ni_flag_a = {
    "All unicast address",
    "Unicast addresses on the queried interface"
};

/*
    RFC2894 - Router Renumbering for IPv6
*/

#define RR_FLAG_T	0x80
#define RR_FLAG_R	0x40
#define RR_FLAG_A	0x20
#define RR_FLAG_S	0x10
#define RR_FLAG_P	0x08
#define RR_FLAG_RSV     0x07

static const value_string rr_pco_mp_opcode_val[] = {
    { 1,    "Add" },
    { 2,    "Change" },
    { 3,    "Set Global" },
    { 0,    NULL }
};

static const value_string names_router_pref[] = {
    { ND_RA_FLAG_RTPREF_HIGH,   "High" },
    { ND_RA_FLAG_RTPREF_MEDIUM, "Medium" },
    { ND_RA_FLAG_RTPREF_LOW,    "Low" },
    { ND_RA_FLAG_RTPREF_RSV,    "Reserved" },
    { 0, NULL}
};

static const value_string names_fmip6_prrtadv_code[] = {
    { FMIP6_PRRTADV_MNTUP,      "MN should use AP-ID, AR-info tuple" },
    { FMIP6_PRRTADV_NI_HOVER,   "Network Initiated Handover trigger" },
    { FMIP6_PRRTADV_NORTINFO,   "No new router information" },
    { FMIP6_PRRTADV_LIMRTINFO,  "Limited new router information" },
    { FMIP6_PRRTADV_UNSOL,      "Unsolicited" },
    { 0,                        NULL }
};

static const value_string names_fmip6_hi_code[] = {
    { FMIP6_HI_PCOA,    "FBU sent from previous link" },
    { FMIP6_HI_NOTPCOA, "FBU sent from new link" },
    { 0,                NULL }
};

static const value_string names_fmip6_hack_code[] = {
    { FMIP6_HACK_VALID,         "Handover Accepted, NCoA valid" },
    { FMIP6_HACK_INVALID,       "Handover Accepted, NCoA not valid" },
    { FMIP6_HACK_INUSE,         "Handover Accepted, NCoA in use" },
    { FMIP6_HACK_ASSIGNED,      "Handover Accepted, NCoA assigned" },
    { FMIP6_HACK_NOTASSIGNED,   "Handover Accepted, NCoA not assigned" },
    { FMIP6_HACK_NOTACCEPTED,   "Handover Not Accepted, reason unspecified" },
    { FMIP6_HACK_PROHIBITED,    "Administratively prohibited" },
    { FMIP6_HACK_INSUFFICIENT,  "Insufficient resources" },
    { 0,                        NULL }
};

static const value_string nd_opt_ipa_option_code_val[] = {
    { 1, "Old Care-of Address" },
    { 2, "New Care-of Address" },
    { 3, "NAR's IP address" },
    { 4, "NAR's Prefix (sent in PrRtAdv)" },
    { 0, NULL }
};

static const value_string nd_opt_lla_option_code_val[] = {
    { 0, "Wildcard" },
    { 1, "Link-layer Address of the New Access Point" },
    { 2, "Link-layer Address of the MN" },
    { 3, "Link-layer Address of the NAR" },
    { 4, "Link-layer Address of the source" },
    { 5, "The AP belongs to the current interface of the router" },
    { 6, "No prefix information available" },
    { 7, "No fast handovers support available" },
    { 0, NULL }
};

static const value_string nd_opt_hai_option_code_val[] = {
    { 1, "Access Network Identifier (AN ID)" },
    { 2, "Sector ID" },
    { 0, NULL }
};

static const value_string nd_opt_mn_option_code_val[] = {
    { 1, "NAI" },
    { 2, "IMSI" },
    { 0, NULL }
};
static const value_string nd_opt_naack_status_val[] = {
    { 1,    "New CoA is invalid, perform address configuration" },
    { 2,    "New CoA is invalid, use the supplied CoA" },
    { 3,    "NCoA is invalid, use NAR's IP address as NCoA in FBU" },
    { 4,    "PCoA supplied, do not send FBU" },
    { 128,  "LLA is unrecognized" },
    { 0,    NULL }
};



static const value_string names_6lowpannd_aro_status_str[] = {
    { 0, "Success" },
    { 1, "Duplicate Exists" },
    { 2, "Neighbor Cache Full" },
    { 0, NULL }
};

/* RPL: draft-ietf-roll-rpl-12.txt: Routing over Low-Power and Lossy Networks. */
/* Pending IANA Assignment */
/* RPL ICMPv6 Codes */
#define ICMP6_RPL_DIS       0   /* DODAG Information Solicitation */
#define ICMP6_RPL_DIO       1   /* DODAG Information Object */
#define ICMP6_RPL_DAO       2   /* Destination Advertisement Object */
#define ICMP6_RPL_DAOACK    3   /* Destination Advertisement Object Ack */

/* RPL DIO Flags */
#define RPL_DIO_FLAG_GROUNDED           0x80
#define RPL_DIO_FLAG_ZERO               0x40
#define RPL_DIO_FLAG_MOP                0x38
#define RPL_DIO_FLAG_PREFERENCE         0x07

/* RPL DAO Flags */
#define RPL_DAO_FLAG_K                  0x80
#define RPL_DAO_FLAG_D                  0x40
#define RPL_DAO_FLAG_RESERVED           0x3F

/* RPL DAO ACK Flags */
#define RPL_DAOACK_FLAG_D               0x80
#define RPL_DAOACK_FLAG_RESERVED        0x7F

/* RPL Option Bitfields */
#define RPL_OPT_PREFIX_FLAG_L           0x80
#define RPL_OPT_PREFIX_FLAG_A           0x40
#define RPL_OPT_PREFIX_FLAG_R           0x20
#define RPL_OPT_PREFIX_FLAG_RSV         0x1F
#define RPL_OPT_ROUTE_PREFERENCE        0x18
#define RPL_OPT_ROUTE_RESERVED          0xE7
#define RPL_OPT_CONFIG_FLAG_AUTH        0x08
#define RPL_OPT_CONFIG_FLAG_PCS         0x07
#define RPL_OPT_CONFIG_FLAG_RESERVED    0xF0
#define RPL_OPT_TRANSIT_FLAG_E          0x80
#define RPL_OPT_TRANSIT_FLAG_RSV        0x7F
#define RPL_OPT_SOLICITED_FLAG_V        0x80
#define RPL_OPT_SOLICITED_FLAG_I        0x40
#define RPL_OPT_SOLICITED_FLAG_D        0x20
#define RPL_OPT_SOLICITED_FLAG_RSV      0x1F

static const value_string names_rpl_code[] = {
    { ICMP6_RPL_DIS,    "DODAG Information Solicitation" },
    { ICMP6_RPL_DIO,    "DODAG Information Object" },
    { ICMP6_RPL_DAO,    "Destination Advertisement Object" },
    { ICMP6_RPL_DAOACK, "Destination Advertisement Object Acknowledgement" },
    { 0, NULL }
};

/* RPL Option Types */
/* Pending IANA Assignment */
#define RPL_OPT_PAD1        0   /* 1-byte padding */
#define RPL_OPT_PADN        1   /* n-byte padding */
#define RPL_OPT_METRIC      2   /* DAG metric container */
#define RPL_OPT_ROUTING     3   /* Routing Information */
#define RPL_OPT_CONFIG      4   /* DAG configuration */
#define RPL_OPT_TARGET      5   /* RPL Target */
#define RPL_OPT_TRANSIT     6   /* Transit */
#define RPL_OPT_SOLICITED   7   /* Solicited Information */
#define RPL_OPT_PREFIX      8   /* Destination prefix */
#define RPL_OPT_TARGETDESC  9   /* RPL Target Descriptor */

static const value_string rpl_option_vals[] = {
    { RPL_OPT_PAD1,     "1-byte padding" },
    { RPL_OPT_PADN,     "n-byte padding" },
    { RPL_OPT_METRIC,   "Metric container" },
    { RPL_OPT_ROUTING,  "Routing"},
    { RPL_OPT_CONFIG,   "DODAG configuration" },
    { RPL_OPT_TARGET,   "RPL Target" },
    { RPL_OPT_TRANSIT,  "Transit Information" },
    { RPL_OPT_SOLICITED,"Solicited Information"},
    { RPL_OPT_PREFIX,   "Prefix Information"},
    { RPL_OPT_TARGETDESC, "RPL Target Descriptor"},
    { 0, NULL }
};

/* http://www.iana.org/assignments/icmpv6-parameters */

#define ND_OPT_SOURCE_LINKADDR		1
#define ND_OPT_TARGET_LINKADDR		2
#define ND_OPT_PREFIX_INFORMATION	3
#define ND_OPT_REDIRECTED_HEADER	4
#define ND_OPT_MTU			5
#define ND_OPT_NBMA                     6
#define ND_OPT_ADVINTERVAL		7
#define ND_OPT_HOMEAGENT_INFO		8
#define ND_OPT_SOURCE_ADDRLIST		9
#define ND_OPT_TARGET_ADDRLIST		10
#define ND_OPT_CGA			11
#define ND_OPT_RSA			12
#define ND_OPT_TIMESTAMP		13
#define ND_OPT_NONCE			14
#define ND_OPT_TRUST_ANCHOR		15
#define ND_OPT_CERTIFICATE		16
#define ND_OPT_IP_ADDRESS_PREFIX        17
#define ND_OPT_NEW_ROUTER_PREFIX_INFO   18
#define ND_OPT_LINK_LAYER_ADDRESS       19
#define ND_OPT_NEIGHBOR_ADV_ACK         20
#define ND_OPT_MAP			23 
#define ND_OPT_ROUTE_INFO		24 
#define ND_OPT_RECURSIVE_DNS_SERVER	25
#define ND_OPT_FLAGS_EXTENSION          26
#define ND_OPT_HANDOVER_KEY_REQUEST     27
#define ND_OPT_HANDOVER_KEY_REPLY       28
#define ND_OPT_HANDOVER_ASSIST_INFO     29
#define ND_OPT_MOBILE_NODE_ID           30
#define ND_OPT_DNS_SEARCH_LIST          31
/* draft-6lowpan-nd types, pending IANA assignment */
#define ND_OPT_ADDR_RESOLUTION 		131 /* Conflit with RFC6106.. */
#define ND_OPT_6LOWPAN_CONTEXT 		32
#define ND_OPT_AUTH_BORDER_ROUTER  	33

static const value_string option_vals[] = {
/*  1 */   { ND_OPT_SOURCE_LINKADDR,           "Source link-layer address" },
/*  2 */   { ND_OPT_TARGET_LINKADDR,           "Target link-layer address" },
/*  3 */   { ND_OPT_PREFIX_INFORMATION,        "Prefix information" },
/*  4 */   { ND_OPT_REDIRECTED_HEADER,         "Redirected header" },
/*  5 */   { ND_OPT_MTU,                       "MTU" },
/*  6 */   { ND_OPT_NBMA,                      "NBMA Shortcut Limit Option" },             /* [RFC2491] */
/*  7 */   { ND_OPT_ADVINTERVAL,               "Advertisement Interval" },                 /* [RFC3775] */
/*  8 */   { ND_OPT_HOMEAGENT_INFO,            "Home Agent Information" },                 /* [RFC3775] */
/*  9 */   { ND_OPT_SOURCE_ADDRLIST,           "Source Address List" },                    /* [RFC3122] */
/* 10 */   { ND_OPT_TARGET_ADDRLIST,           "Target Address List" },                    /* [RFC3122] */
/* 11 */   { ND_OPT_CGA,                       "CGA" },                                    /* [RFC3971] */
/* 12 */   { ND_OPT_RSA,                       "RSA Signature" },                          /* [RFC3971] */
/* 13 */   { ND_OPT_TIMESTAMP,                 "Timestamp" },                              /* [RFC3971] */
/* 14 */   { ND_OPT_NONCE,                     "Nonce" },                                  /* [RFC3971] */
/* 15 */   { ND_OPT_TRUST_ANCHOR,              "Trust Anchor" },                           /* [RFC3971] */
/* 16 */   { ND_OPT_CERTIFICATE,               "Certificate" },                            /* [RFC3971] */
/* 17 */   { ND_OPT_IP_ADDRESS_PREFIX,         "IP Address/Prefix Option" },               /* [RFC5568] */
/* 18 */   { ND_OPT_NEW_ROUTER_PREFIX_INFO,    "New Router Prefix Information" },          /* [RFC4068] OBSO */
/* 19 */   { ND_OPT_LINK_LAYER_ADDRESS,        "Link-layer Address" },                     /* [RFC5568] */
/* 20 */   { ND_OPT_NEIGHBOR_ADV_ACK,          "Neighbor Advertisement Acknowledgment" },  /* [RFC5568] */
/* 21-22   Unassigned */
/* 23 */   { ND_OPT_MAP,                       "MAP" },                                    /* [RFC4140] */
/* 24 */   { ND_OPT_ROUTE_INFO,                "Route Information" },                      /* [RFC4191] */
/* 25 */   { ND_OPT_RECURSIVE_DNS_SERVER,      "Recursive DNS Server" },                   /* [RFC6106] */
/* 26 */   { ND_OPT_FLAGS_EXTENSION,           "RA Flags Extension" },                     /* [RFC5175] */
/* 27 */   { ND_OPT_HANDOVER_KEY_REQUEST,      "Handover Key Request" },                   /* [RFC5269] */
/* 28 */   { ND_OPT_HANDOVER_KEY_REPLY,        "Handover Key Reply" },                     /* [RFC5269] */
/* 29 */   { ND_OPT_HANDOVER_ASSIST_INFO,      "Handover Assist Information" },            /* [RFC5271] */
/* 30 */   { ND_OPT_MOBILE_NODE_ID,            "Mobile Node Identifier Option" },          /* [RFC5271] */
/* 31 */   { ND_OPT_DNS_SEARCH_LIST,           "DNS Search List Option" },                 /* [RFC6106] */
/* 31 */   { ND_OPT_ADDR_RESOLUTION,           "Address Resolution Option" },              /* 6LoWPAN-ND */
/* 32 */   { ND_OPT_6LOWPAN_CONTEXT,           "6LoWPAN Context Option" },                 /* 6LoWPAN-ND */
/* 33 */   { ND_OPT_AUTH_BORDER_ROUTER,        "Authorative Border Router" },              /* 6LoWPAN-ND */
/* 34-137  Unassigned */
   { 138,                              "CARD Request" },                           /* [RFC4065] */
   { 139,                              "CARD Reply" },                             /* [RFC4065] */
/* 140-252 Unassigned */
   { 253,                              "RFC3692-style Experiment 1" },             /* [RFC4727] */
   { 254,                              "RFC3692-style Experiment 2" },             /* [RFC4727] */
   { 0,                                NULL }
};

static const value_string icmpv6_option_name_type_vals[] = {
    { 1,    "DER Encoded X.501 Name" },
    { 2,    "FQDN" },
    { 3,    "SHA-1 Subject Key Identifier (SKI)" },
    { 4,    "SHA-224 Subject Key Identifier (SKI)" },
    { 5,    "SHA-256 Subject Key Identifier (SKI)" },
    { 6,    "SHA-384 Subject Key Identifier (SKI)" },
    { 7,    "SHA-512 Subject Key Identifier (SKI)" },
    { 253,  "Reserved for Experimental Use" },
    { 254,  "Reserved for Experimental Use" },
    { 255,  "Reserved" },
    { 0,    NULL }
};

static const value_string icmpv6_option_cert_type_vals[] = {
    { 1,    "X.509v3 Certificate" },
    { 0,    NULL }
};

#define FLAGS_EO_M      0x8000
#define FLAGS_EO_O      0x4000
#define FLAGS_EO_H      0x2000
#define FLAGS_EO_PRF    0x1800
#define FLAGS_EO_P      0x0400
#define FLAGS_EO_RSV    0x02FF

static void
dissect_contained_icmpv6(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    gboolean save_in_error_pkt;
    tvbuff_t *next_tvb;

    /* Save the current value of the "we're inside an error packet"
       flag, and set that flag; subdissectors may treat packets
       that are the payload of error packets differently from
       "real" packets. */
    save_in_error_pkt = pinfo->in_error_pkt;
    pinfo->in_error_pkt = TRUE;

    next_tvb = tvb_new_subset_remaining(tvb, offset);

    /* tiny sanity check */
    if ((tvb_get_guint8(tvb, offset) & 0xf0) == 0x60) {
        /* The contained packet is an IPv6 datagram; dissect it. */
        call_dissector(ipv6_handle, next_tvb, pinfo, tree);
    } else
        call_dissector(data_handle,next_tvb, pinfo, tree);

    /* Restore the "we're inside an error packet" flag. */
    pinfo->in_error_pkt = save_in_error_pkt;
}

static void
dissect_icmpv6ndopt(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *icmp6opt_tree, *flag_tree;
    proto_item *ti, *ti_opt, *ti_opt_len;
    guint8 opt_type;
    int opt_len;
    int opt_offset;

    while ((int)tvb_reported_length(tvb) > offset) {
	/* there are more options */

	/* ICMPv6 Option */
	opt_len = tvb_get_guint8(tvb, offset + 1) * 8; 
	ti = proto_tree_add_item(tree, hf_icmpv6_opt, tvb, offset, opt_len, FALSE);
	icmp6opt_tree = proto_item_add_subtree(ti, ett_icmpv6opt);
        opt_offset = offset;

	/* Option type */
	proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_type, tvb, opt_offset, 1, FALSE);
        opt_type = tvb_get_guint8(tvb, opt_offset);
        opt_offset += 1;

	/* Add option name to option root label */
	proto_item_append_text(ti, " (%s", val_to_str(opt_type, option_vals, "Unknown %d"));

	/* Option length */
	ti_opt_len = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_length, tvb,opt_offset, 1, FALSE);
        opt_offset += 1;

        /* Add length value in bytes */
	proto_item_append_text(ti_opt_len, " (%i bytes)", opt_len);

        if(opt_len == 0){
            expert_add_info_format(pinfo, ti_opt_len, PI_MALFORMED, PI_ERROR, "Invalid option length (Zero)");
            return;
        }

	/* decode... */
	switch (opt_type) {
	case ND_OPT_SOURCE_LINKADDR: /* Source Link-layer Address (1) */
        {
            const guint8	*link_addr;
            /* if the opt len is 8, the Link Addr is MAC Address */ 
            if(opt_len == 8){
            	proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_linkaddr_mac, tvb, opt_offset, 6, FALSE);
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_src_linkaddr_mac, tvb, opt_offset, 6, FALSE);
                PROTO_ITEM_SET_HIDDEN(ti_opt);

                link_addr = tvb_get_ptr(tvb, opt_offset, 6);
	        col_append_fstr(pinfo->cinfo, COL_INFO, " from %s", ether_to_str(link_addr));
                proto_item_append_text(ti, " : %s",  ether_to_str(link_addr));

            }else{
            	proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_linkaddr, tvb, opt_offset, opt_len-2, FALSE);
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_src_linkaddr, tvb, opt_offset, opt_len-2, FALSE);
                PROTO_ITEM_SET_HIDDEN(ti_opt);
            }
            break;
        }
	case ND_OPT_TARGET_LINKADDR: /* Target Link-layer Address (2) */
	{
            const guint8	*link_addr;
            /* if the opt len is 8, the Link Addr is MAC Address */ 
            if(opt_len == 8){
            	proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_linkaddr_mac, tvb, opt_offset, 6, FALSE);
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_target_linkaddr_mac, tvb, opt_offset, 6, FALSE);
                PROTO_ITEM_SET_HIDDEN(ti_opt);

                link_addr = tvb_get_ptr(tvb, opt_offset, 6);
	        col_append_fstr(pinfo->cinfo, COL_INFO, " is at %s", ether_to_str(link_addr));
                proto_item_append_text(ti, " : %s",  ether_to_str(link_addr));

            }else{
            	proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_linkaddr, tvb, opt_offset, opt_len-2, FALSE);
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_target_linkaddr, tvb, opt_offset, opt_len-2, FALSE);
                PROTO_ITEM_SET_HIDDEN(ti_opt);
            }

	    break;
	}
	case ND_OPT_PREFIX_INFORMATION: /* Prefix Information (3) */
	{
            guint8 prefix_len;
            struct e_in6_addr prefix;
            /* RFC 4861 */

            /* Prefix Length */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_prefix_len, tvb, opt_offset, 1, FALSE);
            prefix_len = tvb_get_guint8(tvb, opt_offset);
            opt_offset += 1;

            /* Flags */
            ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_prefix_flag, tvb, opt_offset, 1, FALSE);
            flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6flag);

            proto_tree_add_item(flag_tree, hf_icmpv6_opt_prefix_flag_l, tvb, opt_offset, 1, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_opt_prefix_flag_a, tvb, opt_offset, 1, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_opt_prefix_flag_reserved, tvb, opt_offset, 1, FALSE);
            opt_offset += 1;
            
             /* Prefix Valid Lifetime */
            ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_prefix_valid_lifetime, tvb, opt_offset, 4, FALSE);
           
             switch(tvb_get_ntohl(tvb, opt_offset)){
                case 0xffffffff:
                	proto_item_append_text(ti_opt, " (Infinity)");
                break;
                default:
                break;
            }
            opt_offset += 4;

            /* Prefix Preferred Lifetime */
            ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_prefix_preferred_lifetime, tvb, opt_offset, 4, FALSE);
           
             switch(tvb_get_ntohl(tvb, opt_offset)){ 
                case 0xffffffff:
                	proto_item_append_text(ti_opt, " (Infinity)");
                break;
                default:
                break;
            }
            opt_offset += 4;

            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 4, FALSE);
            opt_offset += 4;
            
            /* Prefix */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_prefix, tvb, opt_offset, 16, FALSE);
            tvb_get_ipv6(tvb, opt_offset, &prefix);
            proto_item_append_text(ti, " : %s/%d", ip6_to_str(&prefix), prefix_len);
            opt_offset += 16;         

	    break;
	}
	case ND_OPT_REDIRECTED_HEADER: /* Redirected Header (4) */

            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 6, FALSE);
            opt_offset += 6;

            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_redirected_packet, tvb, opt_offset, -1, FALSE);

			dissect_contained_icmpv6(tvb, opt_offset, pinfo, icmp6opt_tree);
	    break;
	case ND_OPT_MTU: /* MTU (5) */

            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 2, FALSE);
            opt_offset += 2;

            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_mtu, tvb, opt_offset, 4, FALSE);
            proto_item_append_text(ti, " : %d", tvb_get_ntohl(tvb, opt_offset));
	    break;
	case ND_OPT_NBMA: /* NBMA Shortcut Limit Option (6) */

            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_nbma_shortcut_limit, tvb, opt_offset, 1, FALSE);
            proto_item_append_text(ti, " : %d", tvb_get_guint8(tvb, opt_offset));

            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 1, FALSE);
            opt_offset += 1;

            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 4, FALSE);
            opt_offset += 4;

	    break;
	case ND_OPT_ADVINTERVAL: /* Advertisement Interval Option (7) */

            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 2, FALSE);
            opt_offset += 2;

            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_advertisement_interval, tvb, opt_offset, 4, FALSE);
            proto_item_append_text(ti, " : %d", tvb_get_ntohl(tvb, opt_offset));

	    break;
	case ND_OPT_HOMEAGENT_INFO: /* Home Agent Information Option (8) */
	{

            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 2, FALSE);
            opt_offset += 2;

            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_home_agent_preference, tvb, opt_offset, 2, FALSE);
            opt_offset += 2;

            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_home_agent_lifetime, tvb, opt_offset, 2, FALSE);
            opt_offset += 2;
	    break;
	}
        case  ND_OPT_SOURCE_ADDRLIST: /* Source Address List (9) */
        case  ND_OPT_TARGET_ADDRLIST: /* Target Address List (10)*/
        {
            struct e_in6_addr ipv6_address;
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 6, FALSE);
            opt_offset += 6;

            while(opt_offset < (offset + opt_len) ) {
		proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_ipv6_address, tvb, opt_offset, 16, FALSE);
                tvb_get_ipv6(tvb, opt_offset, &ipv6_address);
                proto_item_append_text(ti, " %s", ip6_to_str(&ipv6_address));
		opt_offset += 16;
	    }
            break;
        }
	case ND_OPT_CGA: /* CGA option (11) */ 
        {
            proto_tree *cga_tree;
            proto_item *cga_item;
	    guint16 ext_data_len;
            guint8 padd_length;
            int par_len;
            asn1_ctx_t asn1_ctx;
	    /* RFC 3971 5.1.  CGA Option */

	    /* Pad Length */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_cga_pad_len, tvb, opt_offset, 1, FALSE);
	    padd_length = tvb_get_guint8(tvb, opt_offset);
	    opt_offset += 1;

	    /* Reserved 8 bits */

            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1;

	    /* CGA Parameters A variable-length field containing the CGA Parameters data
	     * structure described in Section 4 of
	     * "Cryptographically Generated Addresses (CGA)", RFC3972.
	     */
	    par_len = opt_len -4 -padd_length;
	    cga_item = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_cga, tvb, opt_offset, par_len, FALSE);
	    par_len += opt_offset; 

	    cga_tree = proto_item_add_subtree(cga_item, ett_cga_param_name);
	    proto_tree_add_item(cga_tree, hf_icmpv6_opt_cga_modifier, tvb, opt_offset, 16, FALSE);
	    opt_offset += 16;

	    proto_tree_add_item(cga_tree, hf_icmpv6_opt_cga_subnet_prefix, tvb, opt_offset, 8, FALSE);
	    opt_offset += 8;

	    proto_tree_add_item(cga_tree ,hf_icmpv6_opt_cga_count, tvb, opt_offset, 1, FALSE);
	    opt_offset++;

	    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
	    opt_offset = dissect_x509af_SubjectPublicKeyInfo(FALSE, tvb, opt_offset, &asn1_ctx, cga_tree, -1);

	    /* Process RFC 4581*/
	    while (opt_offset < par_len) {
		proto_tree_add_item(cga_tree, hf_icmpv6_opt_cga_ext_type, tvb, opt_offset, 2, FALSE);
		opt_offset += 2;

		ext_data_len = tvb_get_ntohs(tvb, opt_offset);
		proto_tree_add_item(cga_tree, hf_icmpv6_opt_cga_ext_length, tvb, opt_offset, 2, FALSE);
		opt_offset += 2;

                proto_tree_add_item(cga_tree, hf_icmpv6_opt_cga_ext_data, tvb, opt_offset, ext_data_len, FALSE);
		opt_offset += ext_data_len;
	    }

	    /* Padding */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_padding, tvb, opt_offset, padd_length, FALSE);
	    break;
	}
	case ND_OPT_RSA: /* RSA Signature option (12) */
        {
            int par_len;
	    /*5.2.  RSA Signature Option */
	    /* Reserved, A 16-bit field reserved for future use. */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 2, FALSE);
	    opt_offset = opt_offset + 2;

	    /* Key Hash
	     * A 128-bit field containing the most significant (leftmost) 128
	     * bits of a SHA-1 [14] hash of the public key used for constructing
	     * the signature.
	     */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_rsa_key_hash, tvb, opt_offset, 16, FALSE);
	    opt_offset = opt_offset + 16;

	    /* Digital Signature */
	    par_len = opt_len - 20;
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_digital_signature_padding , tvb, opt_offset, par_len, FALSE);

	    /* Padding */
	    /* TODO: Calculate padding length and exlude from the signature */
	    break;
        }
	case ND_OPT_TIMESTAMP: /* Timestamp option (13) */
	    /* Reserved A 48-bit field reserved for future use. */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 6, FALSE);
	    opt_offset += 6;

	    /* Timestamp
	     * A 64-bit unsigned integer field containing a timestamp.  The value
	     * indicates the number of seconds since January 1, 1970, 00:00 UTC,
	     * by using a fixed point format.  In this format, the integer number
	     * of seconds is contained in the first 48 bits of the field, and the
	     * remaining 16 bits indicate the number of 1/64K fractions of a
	     * second.
	     */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_timestamp, tvb, opt_offset + 2, 4, FALSE);
	    break;
	case ND_OPT_NONCE: /* Nonce option (14) */
	    /* 5.3.2.  Nonce Option */

            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_nonce, tvb, opt_offset, opt_len - 2, FALSE);
	    /* Nonce */
	    break;
	case ND_OPT_TRUST_ANCHOR: /* Trust Anchor option (15) */
        {
            proto_tree *name_tree;
            proto_item *name_item;
            guint8 name_type;
            guint8 padd_length;
            int par_len;
            asn1_ctx_t asn1_ctx;

	    /* Name Type */
	    name_type = tvb_get_guint8(tvb, opt_offset);
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_name_type, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1;

	    /* Pad Length */
	    padd_length = tvb_get_guint8(tvb, opt_offset);
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_cga_pad_len, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1;

	    par_len = opt_len - 4 - padd_length;

	    switch (name_type){
	    case 1:
		/* DER Encoded X.501 Name */
		name_item = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_name_x501, tvb, opt_offset, par_len, FALSE);
		name_tree = proto_item_add_subtree(name_item, ett_icmpv6opt_name);
		asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
		dissect_x509if_Name(FALSE, tvb, opt_offset, &asn1_ctx, name_tree, hf_icmpv6_x509if_Name);
		break;
	    case 2:
		/* FQDN */
		proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_name_fqdn, tvb, opt_offset, par_len, FALSE);
		break;
	    default:
		break;
	    }
	    opt_offset = opt_offset + par_len;

	    /* Padding */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_padding, tvb, opt_offset, padd_length, FALSE);

	    break;
        }
	case ND_OPT_CERTIFICATE: /* Certificate option (16) */
        {
            guint8 cert_type;
            guint8 padd_length;
            asn1_ctx_t asn1_ctx;

	    /* Cert Type */
	    cert_type = tvb_get_guint8(tvb, opt_offset);
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_cert_type, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1;

	    /* Reserved */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1;

	    /* Certificate */

	    if(cert_type == 1){
		asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
		opt_offset = dissect_x509af_Certificate(FALSE, tvb, opt_offset, &asn1_ctx, icmp6opt_tree, hf_icmpv6_x509af_Certificate);
		padd_length = opt_len - (opt_offset - offset);
		/* Padding */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_padding, tvb, opt_offset, padd_length, FALSE);
	    }else{
		padd_length = opt_len - 4;
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_certificate_padding, tvb, opt_offset, padd_length, FALSE);
	    }
	    break;
        }
	case ND_OPT_IP_ADDRESS_PREFIX: /* IP Address/Prefix Option (17) */
        {
            guint8 prefix_len;
            struct e_in6_addr ipv6_address;

            /* Option-code */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_ipa_option_code, tvb, opt_offset, 1, FALSE);
            opt_offset += 1;
            
            /* Prefix Len */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_ipa_prefix_len, tvb, opt_offset, 1, FALSE);
            prefix_len = tvb_get_guint8(tvb, opt_offset);
            opt_offset += 1;

            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 4, FALSE);
            opt_offset += 4;

            /* IPv6 Address */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_ipa_ipv6_address, tvb, opt_offset, 16, FALSE);
            tvb_get_ipv6(tvb, opt_offset, &ipv6_address);
            opt_offset += 16;

            proto_item_append_text(ti, " %s/%d", ip6_to_str(&ipv6_address), prefix_len);

	    break;
	}
	case ND_OPT_NEW_ROUTER_PREFIX_INFO: /* New Router Prefix Information Option (18) OBSO... */
	{

            guint8 prefix_len;
            struct e_in6_addr prefix;

            /* Option-code */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_nrpi_option_code, tvb, opt_offset, 1, FALSE);
            opt_offset += 1;
            
            /* Prefix Len */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_nrpi_prefix_len, tvb, opt_offset, 1, FALSE);
            prefix_len = tvb_get_guint8(tvb, opt_offset);
            opt_offset += 1;

            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 4, FALSE);
            opt_offset += 4;

            /* Prefix */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_nrpi_prefix, tvb, opt_offset, 16, FALSE);
            tvb_get_ipv6(tvb, opt_offset, &prefix);
            opt_offset += 16;

            proto_item_append_text(ti, " %s/%d", ip6_to_str(&prefix), prefix_len);
	    break;
	}
	case ND_OPT_LINK_LAYER_ADDRESS: /* Link-layer Address Option (19) */
	{
            /* Option-Code */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_lla_option_code, tvb, opt_offset, 1, FALSE);
            opt_offset += 1;

            /* Link Layer Address */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_lla_bytes, tvb, opt_offset, opt_len-3, FALSE);
	    break;
	}

	case ND_OPT_NEIGHBOR_ADV_ACK: /* Neighbor Advertisement Acknowledgment Option (20) */
	{
            guint8 status;
            
            /* Option-Code */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_naack_option_code, tvb, opt_offset, 1, FALSE);
            opt_offset += 1;

            /* Status */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_naack_status, tvb, opt_offset, 1, FALSE);
            status = tvb_get_guint8(tvb, opt_offset);
            opt_offset += 1;

            if(status == 2){
                  proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_naack_supplied_ncoa, tvb, opt_offset, 16, FALSE);
            }else{
                  proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, opt_len - 4, FALSE);
            }
	    break;
	}
	case ND_OPT_MAP: /* MAP Option (23) */
	{

            /* Dist */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_map_dist, tvb, opt_offset, 1, FALSE);

            /* Pref */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_map_pref, tvb, opt_offset, 1, FALSE);
            opt_offset += 1;
            
            /* Flags */
	    ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_map_flag, tvb, opt_offset, 1, FALSE);
	    flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6flag);

            proto_tree_add_item(flag_tree, hf_icmpv6_opt_map_flag_r, tvb, opt_offset, 1, FALSE);
	    proto_tree_add_item(flag_tree, hf_icmpv6_opt_map_flag_reserved, tvb, opt_offset, 1, FALSE);
            opt_offset += 1;

            /* Valid Lifetime */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_map_valid_lifetime, tvb, opt_offset, 4, FALSE);
            opt_offset += 4;

            /* Global Address */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_map_global_address, tvb, opt_offset, 16, FALSE);
            opt_offset += 16;
	    break;
	}
	case ND_OPT_ROUTE_INFO: /* Route Information Option (24) */
	{
            /* RFC 4191 */
            guint8 prefix_len;
            guint8 route_preference;
            struct e_in6_addr prefix;
            
            /* Prefix Len */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_prefix_len, tvb, opt_offset, 1, FALSE);
            prefix_len = tvb_get_guint8(tvb, opt_offset);
            opt_offset += 1;

            /* Flags */
            ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_route_info_flag, tvb, opt_offset, 1, FALSE);
            flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6flag);

            proto_tree_add_item(flag_tree, hf_icmpv6_opt_route_info_flag_route_preference, tvb, opt_offset, 1, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_opt_route_info_flag_reserved, tvb, opt_offset, 1, FALSE);

            route_preference = tvb_get_guint8(tvb, opt_offset);
            route_preference = (route_preference & ND_RA_FLAG_RTPREF_MASK) >> 3;
            proto_item_append_text(ti, " : %s", val_to_str(route_preference, names_router_pref, "Unknown %d") );
            opt_offset += 1;

            /* Route Lifetime */
            ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_route_lifetime, tvb, opt_offset, 4, FALSE);
           
             switch(tvb_get_ntohl(tvb, opt_offset)){ 
                case 0xffffffff:
                	proto_item_append_text(ti_opt, " (Infinity)");
                break;
                default:
                break;
            }
            opt_offset += 4;

            /* Prefix */
            switch(opt_len){
                case 8: /* Default Option Length without prefix */
                    proto_item_append_text(ti, " ::/%d", prefix_len);
                break;
                case 16: 
                    memset(&prefix, 0, sizeof(prefix));
                    tvb_memcpy(tvb, (guint8 *)&prefix.bytes, opt_offset, 8);
                    proto_tree_add_ipv6(icmp6opt_tree, hf_icmpv6_opt_prefix, tvb, opt_offset, 8, prefix.bytes);
                    proto_item_append_text(ti, " %s/%d", ip6_to_str(&prefix), prefix_len);
                break;
                case 24: 
                    tvb_get_ipv6(tvb, opt_offset, &prefix);
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_prefix, tvb, opt_offset, 16, FALSE);
                    proto_item_append_text(ti, " %s/%d", ip6_to_str(&prefix), prefix_len);
                break;
                default:
		    expert_add_info_format(pinfo, ti_opt_len, PI_MALFORMED, PI_ERROR, "Invalid Option Length");
                break;     
            }
	    break;

	}

	case ND_OPT_RECURSIVE_DNS_SERVER: /* Recursive DNS Server Option (25) */
        {
            struct e_in6_addr rdnss;
            /* Reserved */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 2, FALSE);
            opt_offset += 2;

            /* RDNSS Lifetime */
            ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_rdnss_lifetime, tvb, opt_offset, 4, FALSE);
	    /* A value of all one bits (0xffffffff) represents infinity.  A value of
	     * zero means that the RDNSS address MUST no longer be used.
	     */
            switch(tvb_get_ntohl(tvb, opt_offset)){ 
                case 0:
                	proto_item_append_text(ti_opt, " (RDNSS address MUST no longer be used)");
                break;
                case 0xffffffff:
                	proto_item_append_text(ti_opt, " (Infinity)");
                break;
                default:
                break;
            }
            opt_offset += 4;
            
            while(opt_offset < (offset + opt_len) ) {
		proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_rdnss, tvb, opt_offset, 16, FALSE);
                tvb_get_ipv6(tvb, opt_offset, &rdnss);
                proto_item_append_text(ti, " %s", ip6_to_str(&rdnss));
                opt_offset += 16;

	    }
	    break;
        }
	case ND_OPT_FLAGS_EXTENSION: /* RA Flags Extension Option (26) */
	{
            ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_efo, tvb, opt_offset, 6, FALSE);
            flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6flag);

            proto_tree_add_item(flag_tree, hf_icmpv6_opt_efo_m, tvb, opt_offset, 2, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_opt_efo_o, tvb, opt_offset, 2, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_opt_efo_h, tvb, opt_offset, 2, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_opt_efo_prf, tvb, opt_offset, 2, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_opt_efo_p, tvb, opt_offset, 2, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_opt_efo_rsv, tvb, opt_offset, 2, FALSE);
            opt_offset += 2;

            proto_tree_add_item(flag_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 4, FALSE);
            break;
        }
        case ND_OPT_HANDOVER_KEY_REQUEST: /* Handover Key Request Option (27) */
        {
            int par_len;
            guint padd_length;

	    /* Pad Length */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_pad_length, tvb, opt_offset, 1, FALSE);
	    padd_length = tvb_get_guint8(tvb, opt_offset);
	    opt_offset += 1; 

	    /* AT */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_at, tvb, opt_offset, 1, FALSE);

	    /* Reserved */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_reserved, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1; 

	    /* Handover Key Encryption Public Key */
	    par_len = opt_len-4-padd_length;
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_encryption_public_key, tvb, opt_offset, par_len, FALSE);
	    opt_offset += par_len; 

	    /* Padding */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_padding, tvb, opt_offset, padd_length, FALSE);
	    opt_offset += 1; 
            break;
        }
        case ND_OPT_HANDOVER_KEY_REPLY: /* Handover Key Reply Option (28) */
        {
            int par_len;
            guint padd_length;

	    /* Pad Length */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_pad_length, tvb, opt_offset, 1, FALSE);
	    padd_length = tvb_get_guint8(tvb, opt_offset);
	    opt_offset += 1; 

	    /* AT */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_at, tvb, opt_offset, 1, FALSE);

	    /* Reserved */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_reserved, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1; 

	    /* Lifetime */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_lifetime, tvb, opt_offset, 2, FALSE);
	    opt_offset += 2; 

	    /* Encrypted Handover Key */
	    par_len = opt_len-6-padd_length;
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_encrypted_handover_key, tvb, opt_offset, par_len, FALSE);
	    opt_offset += par_len; 

	    /* Padding */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_padding, tvb, opt_offset, padd_length, FALSE);
	    opt_offset += 1; 
            break;
        }
	case ND_OPT_HANDOVER_ASSIST_INFO: /* Handover Assist Information Option (29) */
	{
            guint8 hai_len;
            int padd_length;
            /* Option-Code */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hai_option_code, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1; 

            /* HAI Length */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hai_length, tvb, opt_offset, 1, FALSE);
	    hai_len = tvb_get_guint8(tvb, opt_offset);
	    opt_offset += 1; 

            /* HAI Value */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hai_value, tvb, opt_offset, hai_len, FALSE);
	    opt_offset += hai_len; 

            /* Padding... */
            padd_length = opt_len - opt_offset;
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_padding, tvb, opt_offset, padd_length, FALSE);

            break;
        }
	case ND_OPT_MOBILE_NODE_ID: /* Mobile Node Identifier Option (30) */
	{
            guint8 mn_len;
            int padd_length;
            /* Option-Code */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_mn_option_code, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1; 

            /* MN Length */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_mn_length, tvb, opt_offset, 1, FALSE);
	    mn_len = tvb_get_guint8(tvb, opt_offset);
	    opt_offset += 1; 

            /* MN Value */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_mn_value, tvb, opt_offset, mn_len, FALSE);
	    opt_offset += mn_len; 

            /* Padding... */
            padd_length = opt_len - opt_offset;
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_padding, tvb, opt_offset, padd_length, FALSE);
            break;
        }
	case ND_OPT_DNS_SEARCH_LIST: /* DNS Search List Option (31) */
	{
            int dnssl_len;
            const guchar *dnssl_name;

            /* Reserved */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 2, FALSE);
            opt_offset += 2;

            /* DNSSL Lifetime */
            ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_dnssl_lifetime, tvb, opt_offset, 4, FALSE);
            switch(tvb_get_ntohl(tvb, opt_offset)){ 
                case 0xffffffff:
                	proto_item_append_text(ti_opt, " (Infinity)");
                break;
                default:
                break;
            }
            opt_offset += 4;
            while(opt_offset < (offset + opt_len) ) {
                
                if(tvb_get_guint8(tvb, opt_offset) == 0){ /* if Zero there is padding, skip the loop */
                break;
                }
                dnssl_len = get_dns_name(tvb, opt_offset, 0, opt_offset, &dnssl_name);
		proto_tree_add_string(icmp6opt_tree, hf_icmpv6_opt_dnssl, tvb, opt_offset, dnssl_len, dnssl_name);
                proto_item_append_text(ti, " %s", dnssl_name);
		opt_offset += dnssl_len;

	    }
	    break;
        }
	case ND_OPT_6LOWPAN_CONTEXT: /* 6LoWPAN Context (32) */
	{
	    /* 6lowpan-ND */
            guint8 context_len;
            struct e_in6_addr context_prefix;

	    /* Context Length */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_6co_context_length, tvb, opt_offset, 1, FALSE);
            context_len = tvb_get_guint8(tvb, opt_offset);
	    opt_offset += 1; 

	    /*  Flags & CID */
	    ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_6co_flag, tvb, opt_offset, 1, FALSE);
	    flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6flag);
            proto_tree_add_item(flag_tree, hf_icmpv6_opt_6co_flag_c, tvb, opt_offset, 1, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_opt_6co_flag_cid, tvb, opt_offset, 1, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_opt_6co_flag_reserved, tvb, opt_offset, 1, FALSE);
            opt_offset += 1;

            /* Reserved */ 
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 2, FALSE);
            opt_offset += 2;

	    /* Lifetime */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_6co_valid_lifetime, tvb, opt_offset, 2, FALSE);
            opt_offset += 2;

	    /* Context */
            switch(opt_len){
                case 8: /* Default Option Length without context prefix */
                    proto_item_append_text(ti, " ::/%d", context_len);
                break;
                case 16: 
                    memset(&context_prefix, 0, sizeof(context_prefix));
                    tvb_memcpy(tvb, (guint8 *)&context_prefix.bytes, opt_offset, 8);
                    proto_tree_add_ipv6(icmp6opt_tree, hf_icmpv6_opt_6co_context_prefix, tvb, opt_offset, 8, context_prefix.bytes);
                    proto_item_append_text(ti, " %s/%d", ip6_to_str(&context_prefix), context_len);
                break;
                case 24: 
                    tvb_get_ipv6(tvb, opt_offset, &context_prefix);
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_6co_context_prefix, tvb, opt_offset, 16, FALSE);
                    proto_item_append_text(ti, " %s/%d", ip6_to_str(&context_prefix), context_len);
                break;
                default:
		    expert_add_info_format(pinfo, ti_opt_len, PI_MALFORMED, PI_ERROR, "Invalid Option Length");
                break;     
            }
	}
	break;
	case ND_OPT_ADDR_RESOLUTION: /* Address Registration (TBD2 Pending IANA...) */
	{
	    /* 6lowpan-ND */
            guint8 status;
            gchar *eui64;

	    /* Status */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_aro_status, tvb, opt_offset, 1, FALSE);
            status = tvb_get_guint8(tvb, opt_offset);
            opt_offset += 1;

	    /* Reserved */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 3, FALSE);
            opt_offset += 3;

	    /* Lifetime */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_aro_registration_lifetime, tvb, opt_offset, 2, FALSE);
            opt_offset += 2;

	    /* EUI-64 */ 
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_aro_eui64, tvb, opt_offset, 8, FALSE);
            eui64 = tvb_bytes_to_str_punct(tvb, opt_offset, 8, ':');
            proto_item_append_text(ti, " : Register %s %s", eui64, val_to_str(status, names_6lowpannd_aro_status_str, "Unknown %d"));
            opt_offset += 8;

	}
	break;
	case ND_OPT_AUTH_BORDER_ROUTER: /* Authoritative Border Router (33) */
	{
	    guint16 version;
            struct e_in6_addr addr_6lbr;

            /* Version */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_abro_version, tvb, opt_offset, 2, FALSE);
            version = tvb_get_ntohs(tvb, opt_offset);
	    opt_offset += 2; 

            /* Reserved */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 4, FALSE);
	    opt_offset += 4; 

            /* 6LBR Address */ 
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_abro_6lbr_address, tvb, opt_offset, 16, FALSE);
            tvb_get_ipv6(tvb, opt_offset, &addr_6lbr);
            proto_item_append_text(ti, " : Version %d, 6LBR : %s", version, ip6_to_str(&addr_6lbr));
            opt_offset += 16;

	}
	    break;

            default : 
	        expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_NOTE, "Dissector for ICMPv6 Option (%d) code not implemented, Contact Wireshark developers if you want this supported", opt_type);
            break;

	} /* switch (opt_type) */

        offset += opt_len;

	/* Close the ) to option root label */
	proto_item_append_text(ti, ")");
    }
}


/* RPL: draft-ietf-roll-rpl-12.txt: Routing over Low-Power and Lossy Networks. */
static void
dissect_icmpv6_rpl_opt(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *icmp6opt_tree, *flag_tree;
    proto_item *ti, *ti_opt, *ti_opt_len;
    guint8 opt_type;
    int opt_len;
    int opt_offset;

    while ((int)tvb_reported_length(tvb) > offset) {
	/* there are more options */

	/* ICMPv6 RPL Option */
	ti = proto_tree_add_item(tree, hf_icmpv6_rpl_opt, tvb, offset, 1, FALSE);
	icmp6opt_tree = proto_item_add_subtree(ti, ett_icmpv6opt);
        opt_offset = offset;

	/* Option type */
	proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_type, tvb, opt_offset, 1, FALSE);
        opt_type = tvb_get_guint8(tvb, opt_offset);
        opt_offset += 1;

	/* Add option name to option root label */
	proto_item_append_text(ti, " (%s", val_to_str(opt_type, rpl_option_vals, "Unknown %d"));

	/* The Pad1 option is a special case, and contains no data. */
	if (opt_type == RPL_OPT_PAD1) {
	    offset += 1;
	    continue;
	}

	/* Option length */
	ti_opt_len = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_length, tvb, opt_offset, 1, FALSE);
	opt_len = tvb_get_guint8(tvb, opt_offset);
	proto_item_set_len(ti, opt_len + 2);
        opt_offset += 1;

	/* decode... */
	switch (opt_type) {
	case RPL_OPT_PADN:
	    /* n-byte padding */
            ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_padn, tvb, opt_offset, opt_len, FALSE);
	    proto_item_append_text(ti_opt, " (Length : %i bytes)", opt_len);
	    break;

	case RPL_OPT_METRIC:
	    /* DAG metric container */
	    /* See draft-ietf-roll-routing-metrics for formatting. */
	    break;
	case RPL_OPT_ROUTING: {
            guint8 prefix_len;
            struct e_in6_addr prefix;

	    /* Prefix length */
	    prefix_len = tvb_get_guint8(tvb, opt_offset);
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_route_prefix_length, tvb, opt_offset, 1, FALSE);
            opt_offset +=1;

            /* Flags */
            ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_route_flag, tvb, opt_offset, 1, FALSE);
            flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6flag);

            proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_route_pref, tvb, opt_offset, 1, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_route_reserved, tvb, opt_offset, 1, FALSE);		
            opt_offset +=1;

            /* Prefix lifetime. */
            ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_route_lifetime, tvb, opt_offset, 4, FALSE);
           
            switch(tvb_get_ntohl(tvb, opt_offset)){ 
            case 0xffffffff:
              	proto_item_append_text(ti_opt, " (Infinity)");
            break;
            default:
            break;
            }
            opt_offset += 4;

            switch(opt_len){
                case 6: /* Default Option Length without prefix */
                    proto_item_append_text(ti, " ::/%d", prefix_len);
                break;
                case 14: 
                    memset(&prefix, 0, sizeof(prefix));
                    tvb_memcpy(tvb, (guint8 *)&prefix.bytes, opt_offset, 8);
                    proto_tree_add_ipv6(icmp6opt_tree, hf_icmpv6_rpl_opt_route_prefix, tvb, opt_offset, 8, prefix.bytes);
                    proto_item_append_text(ti, " %s/%d", ip6_to_str(&prefix), prefix_len);
                break;
                case 22: 
                    tvb_get_ipv6(tvb, opt_offset, &prefix);
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_route_prefix, tvb, opt_offset, 16, FALSE);
                    proto_item_append_text(ti, " %s/%d", ip6_to_str(&prefix), prefix_len);
                break;
                default:
		    expert_add_info_format(pinfo, ti_opt_len, PI_MALFORMED, PI_ERROR, "Invalid Option Length");
                break;     
            }
	    break;
            }
	    case RPL_OPT_CONFIG: {

	    /* Flags */
            ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_flag, tvb, opt_offset, 1, FALSE);
            flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6flag);

	    proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_config_reserved, tvb, opt_offset, 1, FALSE);
	    proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_config_auth, tvb, opt_offset, 1, FALSE);
	    proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_config_pcs, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1;

	    /* DIOIntervalDoublings */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_doublings, tvb, opt_offset, 1, FALSE);
            opt_offset += 1;

            /* DIOIntervalMin */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_min_interval, tvb, opt_offset, 1, FALSE);
            opt_offset += 1;

            /* DIORedundancyConstant */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_redundancy, tvb, opt_offset, 1, FALSE);
            opt_offset += 1;

            /* MaxRankIncrease */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_rank_incr, tvb, opt_offset, 2, FALSE);
            opt_offset += 2;

            /* MinHopRankInc */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_hop_rank_inc, tvb, opt_offset, 2, FALSE);
            opt_offset += 2;
            
            /* OCP */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_ocp, tvb, opt_offset, 2, FALSE);
            opt_offset += 2;

            /* Reserved */ 
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_rsv, tvb, opt_offset, 1, FALSE);
            opt_offset += 1;

            /* Default Lifetime */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_def_lifetime, tvb, opt_offset, 1, FALSE);
            opt_offset += 1;

            /* Lifetime Unit */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_lifetime_unit, tvb, opt_offset, 2, FALSE);
            opt_offset += 2;
            break;
	    }
	    case RPL_OPT_TARGET: {
	    guint8              prefix_len;
	    struct e_in6_addr   target_prefix;

	    /* Flag */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_target_flag, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1;

	    /* Prefix length */
	    prefix_len = tvb_get_guint8(tvb, opt_offset);
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_target_prefix_length, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1;

	    /* Target Prefix */

            switch(opt_len){
                case 2: /* Default Option Length without prefix */
                    proto_item_append_text(ti, " ::/%d", prefix_len);
                break;
                case 10: 
                    memset(&target_prefix, 0, sizeof(target_prefix));
                    tvb_memcpy(tvb, (guint8 *)&target_prefix.bytes, opt_offset, 8);
                    proto_tree_add_ipv6(icmp6opt_tree, hf_icmpv6_rpl_opt_target_prefix, tvb, opt_offset, 8, target_prefix.bytes);
                    proto_item_append_text(ti, " %s/%d", ip6_to_str(&target_prefix), prefix_len);
                break;
                case 18: 
                    tvb_get_ipv6(tvb, opt_offset, &target_prefix);
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_target_prefix, tvb, opt_offset, 16, FALSE);
                    proto_item_append_text(ti, " %s/%d", ip6_to_str(&target_prefix), prefix_len);
                break;
                default:
		    expert_add_info_format(pinfo, ti_opt_len, PI_MALFORMED, PI_ERROR, "Invalid Option Length");
                break;     
            }
	    break;
	    }
	    case RPL_OPT_TRANSIT: {

	    /* Flags */
	    ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_transit_flag, tvb, opt_offset, 1, FALSE);
            flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6flag);

	    proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_transit_flag_e, tvb, opt_offset, 1, FALSE);
	    proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_transit_flag_rsv, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1;

	    /* Path Control */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_transit_pathctl, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1;

	    /* Path Sequence */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_transit_pathseq, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1;

	    /* Path Lifetime */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_transit_pathlifetime, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1;

	    /* Option contains parent */
	    if(opt_len > 4)
	    {
	       proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_transit_parent, tvb, opt_offset, 16, FALSE);
	       opt_offset += 16;
	    }

	    break;
	    }
	    case RPL_OPT_SOLICITED: {

            /*Instance ID */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_solicited_instance, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1;

	    /* Flags */
            ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_solicited_flag, tvb, opt_offset, 1, FALSE);
            flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6flag);

	    proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_solicited_flag_v, tvb, opt_offset, 1, FALSE);
	    proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_solicited_flag_i, tvb, opt_offset, 1, FALSE);
	    proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_solicited_flag_d, tvb, opt_offset, 1, FALSE);
	    proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_solicited_flag_rsv, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1;

	    /* DODAG ID */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_solicited_dodagid, tvb, opt_offset, 16, FALSE);
	    opt_offset += 16;

	    /* Version Number */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_solicited_version, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1;

	    break;
	    }
	    case RPL_OPT_PREFIX: {
	    /* Destination prefix option. */
	    guint8              prefix_len;
	    struct e_in6_addr   prefix;

	    /* Prefix length */
	    prefix_len = tvb_get_guint8(tvb, opt_offset);
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_prefix_length, tvb, opt_offset, 1, FALSE);
	    opt_offset +=1;
	
	    /* Flags */
	    ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_prefix_flag, tvb, opt_offset, 1, FALSE);
            flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6flag);

	    proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_prefix_flag_l, tvb, opt_offset, 1, FALSE);
	    proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_prefix_flag_a, tvb, opt_offset, 1, FALSE);
	    proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_prefix_flag_r, tvb, opt_offset, 1, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_prefix_flag_rsv, tvb, opt_offset, 1, FALSE);
	    opt_offset += 1;

	    /* Valid lifetime. */
            ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_prefix_vlifetime, tvb, opt_offset, 4, FALSE);
            switch(tvb_get_ntohl(tvb, opt_offset)){ 
                case 0xffffffff:
                	proto_item_append_text(ti_opt, " (Infinity)");
                break;
                default:
                break;
            }
	    opt_offset += 4;

	    /* Preferrred Lifetime */
            ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_prefix_plifetime, tvb, opt_offset, 4, FALSE);
            switch(tvb_get_ntohl(tvb, opt_offset)){ 
                case 0xffffffff:
                	proto_item_append_text(ti_opt, " (Infinity)");
                break;
                default:
                break;
            }
	    opt_offset += 4;

	    /* 4 reserved bytes. */
            proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_reserved, tvb, opt_offset, 4, FALSE);
	    opt_offset += 4;

	    /* Prefix */
            tvb_get_ipv6(tvb, opt_offset, &prefix);
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_prefix, tvb, opt_offset, 16, FALSE);
            proto_item_append_text(ti, " %s/%d", ip6_to_str(&prefix), prefix_len);
	    opt_offset += 16;

	    break;
	    }

	    case RPL_OPT_TARGETDESC: {

	    /* Descriptor */
	    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_targetdesc, tvb, opt_offset, 4, FALSE);
	    opt_offset += 4;
	    break;
	    }
            default : 
	        expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_NOTE, "Dissector for ICMPv6 RPL Option (%d) code not implemented, Contact Wireshark developers if you want this supported", opt_type);
            break;
	} /* switch (opt_type) */

        offset += opt_len + 2;

	/* Close the ) to option root label */
	proto_item_append_text(ti, ")");
    }
}

/*
 * RFC 4620 - IPv6 Node Information Queries
 */

static void
dissect_nodeinfo(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, guint8 icmp6_type, guint8 icmp6_code)
{
    proto_tree *flag_tree;
    proto_item *ti;
    guint16 qtype;
    int ni_offset = offset + 4;

    /* Qtype */
    proto_tree_add_item(tree, hf_icmpv6_ni_qtype, tvb, ni_offset, 2, FALSE);
    qtype = tvb_get_ntohs(tvb, ni_offset);
    ni_offset += 2;

    /* Flags */
    ti = proto_tree_add_item(tree, hf_icmpv6_ni_flag, tvb, ni_offset, 2, FALSE);
    flag_tree = proto_item_add_subtree(ti, ett_icmpv6flag);
    proto_tree_add_item(flag_tree, hf_icmpv6_ni_flag_g, tvb, ni_offset, 2, FALSE);
    proto_tree_add_item(flag_tree, hf_icmpv6_ni_flag_s, tvb, ni_offset, 2, FALSE);
    proto_tree_add_item(flag_tree, hf_icmpv6_ni_flag_l, tvb, ni_offset, 2, FALSE);
    proto_tree_add_item(flag_tree, hf_icmpv6_ni_flag_c, tvb, ni_offset, 2, FALSE);
    proto_tree_add_item(flag_tree, hf_icmpv6_ni_flag_a, tvb, ni_offset, 2, FALSE);
    proto_tree_add_item(flag_tree, hf_icmpv6_ni_flag_t, tvb, ni_offset, 2, FALSE);
    proto_tree_add_item(flag_tree, hf_icmpv6_ni_flag_rsv, tvb, ni_offset, 2, FALSE);
    ni_offset += 2;
         
    /* Nonce */
    proto_tree_add_item(tree, hf_icmpv6_ni_nonce, tvb, ni_offset, 8, FALSE);
    ni_offset += 8;
    
    /* Data ? */
    if(tvb_reported_length_remaining(tvb, ni_offset) == 0){
        return;
    }

    if(icmp6_type == ICMP6_NI_QUERY){
        switch(icmp6_code){
        case ICMP6_NI_SUBJ_IPV6: {
            proto_tree_add_item(tree, hf_icmpv6_ni_query_subject_ipv6, tvb, ni_offset, 16, FALSE);
            ni_offset += 16;
        break;
        }
        case ICMP6_NI_SUBJ_FQDN: {
            int fqdn_len;
            const guchar *fqdn_name;
            fqdn_len = get_dns_name(tvb, ni_offset, 0, ni_offset, &fqdn_name);
            proto_tree_add_string(tree, hf_icmpv6_ni_query_subject_fqdn, tvb, ni_offset, fqdn_len, fqdn_name);
            ni_offset += fqdn_len;
        break;
        }
        case ICMP6_NI_SUBJ_IPV4: {
            proto_tree_add_item(tree, hf_icmpv6_ni_query_subject_ipv4, tvb, ni_offset, 4, FALSE);
            ni_offset += 4;
        break;
        }
        }
    } else { /* It is ICMP6_NI_REPLY */
        switch(qtype){
        case NI_QTYPE_NOOP:
        break;
        case NI_QTYPE_NODENAME: {
            int node_len;
            const guchar *node_name;
            /* TTL */
            proto_tree_add_item(tree, hf_icmpv6_ni_reply_node_ttl, tvb, ni_offset, 4, FALSE);
            ni_offset += 4;
            /* Data ? */
            if(tvb_reported_length_remaining(tvb, ni_offset) == 0){
                return;
            }
            while(ni_offset < (int)tvb_reported_length(tvb) ) {
                
                if(tvb_get_guint8(tvb, ni_offset) == 0){ /* if Zero there is padding, skip the loop */
                    break;
                }
                /* Node Name */
                node_len = get_dns_name(tvb, ni_offset, 0, ni_offset, &node_name);
                proto_tree_add_string(tree, hf_icmpv6_ni_reply_node_name, tvb, ni_offset, node_len, node_name);
                ni_offset += node_len;
            }
        break;
        }
        case NI_QTYPE_NODEADDR: {
            while(ni_offset < (int)tvb_reported_length(tvb) ) {  
                /* TTL */
                proto_tree_add_item(tree, hf_icmpv6_ni_reply_node_ttl, tvb, ni_offset, 4, FALSE);
                ni_offset += 4;
                /* Node Addresses */
                proto_tree_add_item(tree, hf_icmpv6_ni_reply_node_address, tvb, ni_offset, 16, FALSE);
                ni_offset += 16;
            }
        break;
        }   
        case NI_QTYPE_IPV4ADDR: {
            while(ni_offset < (int)tvb_reported_length(tvb) ) {  
                /* TTL */ 
                proto_tree_add_item(tree, hf_icmpv6_ni_reply_node_ttl, tvb, ni_offset, 4, FALSE);
                ni_offset += 4;
                /* IPv4 Address */
                proto_tree_add_item(tree, hf_icmpv6_ni_reply_ipv4_address, tvb, ni_offset, 4, FALSE);
                ni_offset += 4;
            }
        break;
        }          
        }
    }
}
/*
 * RFC 2894 - Router Renumbering for IPv6
*/
static void
dissect_rrenum(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, guint8 icmp6_type _U_, guint8 icmp6_code)
{
    proto_tree *flag_tree, *mp_tree, *up_tree, *rm_tree;
    proto_item *ti, *ti_mp, *ti_up, *ti_rm;
    int rr_offset = offset + 4;

    /* Sequence Number */
    proto_tree_add_item(tree, hf_icmpv6_rr_sequencenumber, tvb, rr_offset, 4, FALSE);
    rr_offset += 4;

    /* Segment Number */
    proto_tree_add_item(tree, hf_icmpv6_rr_segmentnumber, tvb, rr_offset, 1, FALSE);
    rr_offset += 1;

    /* Flags */
    ti = proto_tree_add_item(tree, hf_icmpv6_rr_flag, tvb, rr_offset, 1, FALSE);
    flag_tree = proto_item_add_subtree(ti, ett_icmpv6flag);
    proto_tree_add_item(flag_tree, hf_icmpv6_rr_flag_t, tvb, rr_offset, 1, FALSE);
    proto_tree_add_item(flag_tree, hf_icmpv6_rr_flag_r, tvb, rr_offset, 1, FALSE);
    proto_tree_add_item(flag_tree, hf_icmpv6_rr_flag_a, tvb, rr_offset, 1, FALSE);
    proto_tree_add_item(flag_tree, hf_icmpv6_rr_flag_s, tvb, rr_offset, 1, FALSE);
    proto_tree_add_item(flag_tree, hf_icmpv6_rr_flag_p, tvb, rr_offset, 1, FALSE);
    proto_tree_add_item(flag_tree, hf_icmpv6_rr_flag_rsv, tvb, rr_offset, 1, FALSE);
    rr_offset += 1;

    /* Max Delay */
    proto_tree_add_item(tree, hf_icmpv6_rr_maxdelay, tvb, rr_offset, 2, FALSE);
    rr_offset += 2;

    /* Reserved */
    proto_tree_add_item(tree, hf_icmpv6_reserved, tvb, rr_offset, 4, FALSE);
    rr_offset += 4;

    /* Data ? */
    if(tvb_reported_length_remaining(tvb, rr_offset) == 0){
        return;
    }

    if(icmp6_code == ICMP6_ROUTER_RENUMBERING_COMMAND){
        /* Match-Prefix Part */
        guint8 opcode, oplength, matchlen, minlen, maxlen;
        struct e_in6_addr matchprefix;

        ti_mp = proto_tree_add_item(tree, hf_icmpv6_rr_pco_mp_part, tvb, rr_offset, 24, FALSE);
        mp_tree = proto_item_add_subtree(ti_mp, ett_icmpv6opt);

        /* OpCode */
        proto_tree_add_item(mp_tree, hf_icmpv6_rr_pco_mp_opcode, tvb, rr_offset, 1, FALSE);
        opcode = tvb_get_guint8(tvb, rr_offset);
        rr_offset += 1;

        /* OpLength */
        proto_tree_add_item(mp_tree, hf_icmpv6_rr_pco_mp_oplength, tvb, rr_offset, 1, FALSE);
        oplength = tvb_get_guint8(tvb, rr_offset);
        rr_offset += 1;  

        /* Ordinal */
        proto_tree_add_item(mp_tree, hf_icmpv6_rr_pco_mp_ordinal, tvb, rr_offset, 1, FALSE);
        rr_offset += 1;     

        /* MatchLen  */
        proto_tree_add_item(mp_tree, hf_icmpv6_rr_pco_mp_matchlen, tvb, rr_offset, 1, FALSE);
        matchlen = tvb_get_guint8(tvb, rr_offset);
        rr_offset += 1;     

        /* MinLen  */
        proto_tree_add_item(mp_tree, hf_icmpv6_rr_pco_mp_minlen, tvb, rr_offset, 1, FALSE);
        minlen = tvb_get_guint8(tvb, rr_offset);
        rr_offset += 1;  

        /* MaxLen  */
        proto_tree_add_item(mp_tree, hf_icmpv6_rr_pco_mp_maxlen, tvb, rr_offset, 1, FALSE);
        maxlen = tvb_get_guint8(tvb, rr_offset);
        rr_offset += 1;  

        /* Reserved  */
        proto_tree_add_item(mp_tree, hf_icmpv6_reserved, tvb, rr_offset, 2, FALSE);
        rr_offset += 2;  

        /* Match Prefix  */
        proto_tree_add_item(mp_tree, hf_icmpv6_rr_pco_mp_matchprefix, tvb, rr_offset, 16, FALSE);
        tvb_get_ipv6(tvb, rr_offset, &matchprefix);
        rr_offset += 16; 

        /* Add Info (Prefix, Length...) to Match Prefix Part label */
        proto_item_append_text(ti_mp, ": %s %s/%u (%u-%u)", val_to_str(opcode, rr_pco_mp_opcode_val, "Unknown %d"), ip6_to_str(&matchprefix), matchlen, minlen, maxlen);

        while ((int)tvb_reported_length(tvb) > rr_offset) {   
            /* Use-Prefix Part */
            guint8 uselen, keeplen;
            struct e_in6_addr useprefix;

            ti_up = proto_tree_add_item(tree, hf_icmpv6_rr_pco_up_part, tvb, rr_offset, 32, FALSE);
            up_tree = proto_item_add_subtree(ti_up, ett_icmpv6opt);

            /* UseLen */
            proto_tree_add_item(up_tree, hf_icmpv6_rr_pco_up_uselen, tvb, rr_offset, 1, FALSE);
            uselen = tvb_get_guint8(tvb, rr_offset);
            rr_offset += 1;

            /* KeepLen */
            proto_tree_add_item(up_tree, hf_icmpv6_rr_pco_up_keeplen, tvb, rr_offset, 1, FALSE);
            keeplen = tvb_get_guint8(tvb, rr_offset);
            rr_offset += 1;        

            /* FlagMask */
            ti = proto_tree_add_item(up_tree, hf_icmpv6_rr_pco_up_flagmask, tvb, rr_offset, 1, FALSE);
            flag_tree = proto_item_add_subtree(ti, ett_icmpv6flag);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_flagmask_l, tvb, rr_offset, 1, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_flagmask_a, tvb, rr_offset, 1, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_flagmask_reserved, tvb, rr_offset, 1, FALSE);
            rr_offset += 1;    

            /* RaFlags */
            ti = proto_tree_add_item(up_tree, hf_icmpv6_rr_pco_up_raflags, tvb, rr_offset, 1, FALSE);
            flag_tree = proto_item_add_subtree(ti, ett_icmpv6flag);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_raflags_l, tvb, rr_offset, 1, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_raflags_a, tvb, rr_offset, 1, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_raflags_reserved, tvb, rr_offset, 1, FALSE);
            rr_offset += 1; 

            /* Valid Lifetime */
            ti = proto_tree_add_item(up_tree, hf_icmpv6_rr_pco_up_validlifetime, tvb, rr_offset, 4, FALSE);
            switch(tvb_get_ntohl(tvb, rr_offset)){
                case 0xffffffff:
                	proto_item_append_text(ti, " (Infinity)");
                break;
                default:
                break;
            }
            rr_offset += 4;

            /* Preferred Lifetime */
            ti = proto_tree_add_item(up_tree, hf_icmpv6_rr_pco_up_preferredlifetime, tvb, rr_offset, 4, FALSE);
            switch(tvb_get_ntohl(tvb, rr_offset)){
                case 0xffffffff:
                	proto_item_append_text(ti, " (Infinity)");
                break;
                default:
                break;
            }
            rr_offset += 4;   

            /* Flags */
            ti = proto_tree_add_item(up_tree, hf_icmpv6_rr_pco_up_flag, tvb, rr_offset, 4, FALSE);
            flag_tree = proto_item_add_subtree(ti, ett_icmpv6flag);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_flag_v, tvb, rr_offset, 4, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_flag_p, tvb, rr_offset, 4, FALSE);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_flag_reserved, tvb, rr_offset, 4, FALSE);
            rr_offset += 4;       

            /* UsePrefix */
            proto_tree_add_item(up_tree, hf_icmpv6_rr_pco_up_useprefix, tvb, rr_offset, 16, FALSE);
            tvb_get_ipv6(tvb, rr_offset, &useprefix);
            rr_offset += 16;      

            /* Add Info (Prefix, Length...) to Use Prefix Part label */
            proto_item_append_text(ti_up, ": %s/%u (keep %u)", ip6_to_str(&useprefix), uselen, keeplen);
        }
        
    }else if(icmp6_code == ICMP6_ROUTER_RENUMBERING_RESULT){
        while ((int)tvb_reported_length(tvb) > rr_offset) {   
        guint8 matchlen;
        guint32 interfaceindex;
        struct e_in6_addr matchedprefix;     
        /* Result Message */

        ti_rm = proto_tree_add_item(tree, hf_icmpv6_rr_rm, tvb, rr_offset, 24, FALSE);
        rm_tree = proto_item_add_subtree(ti_rm, ett_icmpv6opt);

        /* Flags */
        ti = proto_tree_add_item(mp_tree, hf_icmpv6_rr_rm_flag, tvb, rr_offset, 2, FALSE);
        flag_tree = proto_item_add_subtree(ti, ett_icmpv6flag);
        proto_tree_add_item(flag_tree, hf_icmpv6_rr_rm_flag_b, tvb, rr_offset, 2, FALSE);
        proto_tree_add_item(flag_tree, hf_icmpv6_rr_rm_flag_f, tvb, rr_offset, 2, FALSE);
        proto_tree_add_item(flag_tree, hf_icmpv6_rr_rm_flag_reserved, tvb, rr_offset, 2, FALSE);
        rr_offset +=2;

        /* Ordinal */ 
        proto_tree_add_item(rm_tree, hf_icmpv6_rr_rm_ordinal, tvb, rr_offset, 1, FALSE);
        rr_offset +=1;

        /* MatchLen */ 
        proto_tree_add_item(rm_tree, hf_icmpv6_rr_rm_matchedlen, tvb, rr_offset, 1, FALSE);
        matchlen = tvb_get_guint8(tvb, rr_offset);
        rr_offset +=1;

        /* InterfaceIndex */ 
        proto_tree_add_item(rm_tree, hf_icmpv6_rr_rm_interfaceindex, tvb, rr_offset, 4, FALSE);
        interfaceindex = tvb_get_ntohl(tvb, rr_offset);
        rr_offset +=4;

        /* MatchedPrefix */ 
        proto_tree_add_item(rm_tree, hf_icmpv6_rr_rm_matchedprefix, tvb, rr_offset, 16, FALSE);
        tvb_get_ipv6(tvb, rr_offset, &matchedprefix);
        rr_offset +=16;

        /* Add Info (Prefix, Length...) to Use Resultat Message label */
        proto_item_append_text(ti_rm, ": %s/%u (interface %u)", ip6_to_str(&matchedprefix), matchlen, interfaceindex);
        }
    }

}

/*
 * See I-D draft-vida-mld-v2-08
 */
static const value_string mldrv2ModesNames[] = {
    { 1, "Include" },
    { 2, "Exclude" },
    { 3, "Changed to include" },
    { 4, "Changed to exclude" },
    { 5, "Allow new sources" },
    { 6, "Block old sources" },
    { 0, NULL }
};

static void
dissect_mldrv2( tvbuff_t *tvb, guint32 offset, guint16 count, proto_tree *tree )
{
    proto_tree *sub_tree;
    proto_item *tf;

    guint8 recordType, auxDataLen;
    guint32 sourceNb, recordSize, localOffset;
    struct e_in6_addr addr;

    for( ; count; count--, offset += recordSize ) {
        localOffset = offset;
        recordType = tvb_get_guint8( tvb, localOffset );
        localOffset += 1;
        auxDataLen = tvb_get_guint8( tvb, localOffset );
        localOffset += 1;
        sourceNb = tvb_get_ntohs( tvb, localOffset );
        localOffset += 2;
        recordSize = 4 + 16 + (16 * sourceNb) + (auxDataLen * 4);

        tvb_get_ipv6(tvb, localOffset, &addr);
        tf = proto_tree_add_text( tree, tvb, offset, recordSize,
                                  "%s: %s (%s)", val_to_str(recordType, mldrv2ModesNames,"Unknown mode"),
                                  get_hostname6(&addr), ip6_to_str(&addr)
            );
        sub_tree = proto_item_add_subtree(tf, ett_multicastRR);

        proto_tree_add_text( sub_tree, tvb, offset,   1, "Mode: %s (%u)",
                             val_to_str(recordType, mldrv2ModesNames,"Unknown mode"), recordType );
        proto_tree_add_text( sub_tree, tvb, offset+1, 1, "Aux data len: %u", auxDataLen * 4);
        proto_tree_add_text( sub_tree, tvb, offset+2, 2, "Number of Sources: %u", sourceNb);
        proto_tree_add_text( sub_tree, tvb, localOffset, 16, "Multicast Address: %s", ip6_to_str(&addr) );
        localOffset += 16;

        for( ; sourceNb; sourceNb--, localOffset += 16 ) {
            tvb_get_ipv6(tvb, localOffset, &addr);
            proto_tree_add_text( sub_tree, tvb, localOffset, 16,
                                 "Source Address: %s (%s)", get_hostname6(&addr), ip6_to_str(&addr)
                );
        }
    }
}

static void
dissect_mldqv2(tvbuff_t *tvb, guint32 offset, guint16 count, proto_tree *tree)
{
    struct e_in6_addr addr;

    for ( ; count; count--, offset += 16) {
        tvb_get_ipv6(tvb, offset, &addr);
        proto_tree_add_text(tree, tvb, offset, 16,
                            "Source Address: %s (%s)", get_hostname6(&addr), ip6_to_str(&addr));
    }
}

static void
dissect_icmpv6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *icmp6_tree, *field_tree;
    proto_item *ti, *hidden_item, *tf = NULL;
    struct icmp6_hdr icmp6_hdr, *dp;
    const char *codename, *typename;
    const char *colcodename, *coltypename;
    int len;
    guint length, reported_length;
    vec_t cksum_vec[4];
    guint32 phdr[2];
    guint16 cksum, computed_cksum;
    int offset;
    tvbuff_t *next_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ICMPv6");
    col_clear(pinfo->cinfo, COL_INFO);

    offset = 0;
    tvb_memcpy(tvb, (guint8 *)&icmp6_hdr, offset, sizeof icmp6_hdr);
    dp = &icmp6_hdr;
    typename = coltypename = val_to_str (dp->icmp6_type, icmpv6_type_str, "Unknown");
    codename = colcodename = NULL;

    len = sizeof(*dp);
    switch (dp->icmp6_type) {
    case ICMP6_DST_UNREACH:
        codename = colcodename = val_to_str (dp->icmp6_code, icmpv6_unreach_code_str, "Unknown");
        break;
    case ICMP6_TIME_EXCEEDED:
        codename = colcodename = val_to_str (dp->icmp6_code, icmpv6_timeex_code_str, "Unknown");
        break;
    case ICMP6_PARAM_PROB:
        codename = colcodename = val_to_str (dp->icmp6_code, icmpv6_paramprob_code_str, "Unknown");
        break;
    case ND_ROUTER_SOLICIT:
        len = sizeof(struct nd_router_solicit);
        break;
    case ND_ROUTER_ADVERT:
        len = sizeof(struct nd_router_advert);
        break;
    case ND_NEIGHBOR_SOLICIT:
        len = sizeof(struct nd_neighbor_solicit);
        break;
    case ND_NEIGHBOR_ADVERT:
        len = sizeof(struct nd_neighbor_advert);
        break;
    case ND_REDIRECT:
        len = sizeof(struct nd_redirect);
        break;
    case ICMP6_ROUTER_RENUMBERING:
        codename = colcodename = val_to_str (dp->icmp6_code, icmpv6_router_renum_code_str, "Unknown");
        len = 16;
        break;
    case ICMP6_NI_QUERY:
    case ICMP6_NI_REPLY:
    {
        struct icmp6_nodeinfo icmp6_nodeinfo, *ni;

        ni = &icmp6_nodeinfo;
        tvb_memcpy(tvb, (guint8 *)ni, offset, sizeof *ni);

        if (ni->ni_type == ICMP6_NI_QUERY) {
            switch (ni->ni_code) {
            case ICMP6_NI_SUBJ_IPV6:
                codename = "Query subject = IPv6 addresses";
                break;
            case ICMP6_NI_SUBJ_FQDN:
                if (tvb_bytes_exist(tvb, offset, sizeof(*ni)))
                    codename = "Query subject = DNS name";
                else
                    codename = "Query subject = empty";
                break;
            case ICMP6_NI_SUBJ_IPV4:
                codename = "Query subject = IPv4 addresses";
                break;
            default:
                codename = "Unknown";
                break;
            }
        } else {
            switch (ni->ni_code) {
            case ICMP6_NI_SUCCESS:
                codename = "Successful";
                break;
            case ICMP6_NI_REFUSED:
                codename = "Refused";
                break;
            case ICMP6_NI_UNKNOWN:
                codename = "Unknown query type";
                break;
            default:
                codename = "Unknown";
                break;
            }
        }
        colcodename = val_to_str(pntohs(&ni->ni_qtype), ni_qtype_val, "Unknown");
        len = sizeof(struct icmp6_nodeinfo);
        break;
    }
    case ICMP6_ECHO_REQUEST:
    case ICMP6_ECHO_REPLY:
    case ICMP6_MEMBERSHIP_REPORT:
    case ICMP6_MIP6_DHAAD_REQUEST:
    case ICMP6_MIP6_DHAAD_REPLY:
    case ICMP6_MIP6_MPS:
    case ICMP6_MIP6_MPA:
    case ICMP6_CERT_PATH_SOL:
    case ICMP6_CERT_PATH_AD:
    case ICMP6_MLDV2_REPORT:
        codename = "Should always be zero";
        break;
    case ICMP6_EXPERIMENTAL_MOBILITY:
        switch (dp->icmp6_data8[0]) {
        case FMIP6_SUBTYPE_RTSOLPR:
            typename = coltypename = "RtSolPr (ICMPv6 Experimental Mobility)";
            codename = "Should always be zero";
            break;
        case FMIP6_SUBTYPE_PRRTADV:
            typename = coltypename = "PrRtAdv (ICMPv6 Experimental Mobility)";
            codename = val_to_str(dp->icmp6_code, names_fmip6_prrtadv_code, "Unknown");
            break;
        case FMIP6_SUBTYPE_HI:
            typename = coltypename = "HI (ICMPv6 Experimental Mobility)";
            codename = val_to_str(dp->icmp6_code, names_fmip6_hi_code, "Unknown");
            break;
        case FMIP6_SUBTYPE_HACK:
            typename = coltypename = "HAck (ICMPv6 Experimental Mobility)";
            codename = val_to_str(dp->icmp6_code, names_fmip6_hack_code, "Unknown");
            break;
        default:
            codename = colcodename = "Unknown";
            break;
        } /* switch (dp->icmp6_data8[0]) */
        break;
    case ICMP6_RPL_CONTROL:
        codename = colcodename = val_to_str (dp->icmp6_code, names_rpl_code, "Unknown");
        break;
    default:
        codename = colcodename = "Unknown";
        break;
    } /* switch (dp->icmp6_type) */

    if (check_col(pinfo->cinfo, COL_INFO)) {
        char typebuf[256], codebuf[256];


        if (pinfo->destport == 0x0dd8 && dp->icmp6_type == ICMP6_ECHO_REQUEST) {
            /* RFC 4380
             * 5.2.9. Direct IPv6 Connectivity Test
             */
            col_set_str(pinfo->cinfo, COL_PROTOCOL, "Teredo");
            col_set_str(pinfo->cinfo, COL_INFO, "Direct IPv6 Connectivity Test");
        } else {
            if (coltypename && strcmp(coltypename, "Unknown") == 0) {
                g_snprintf(typebuf, sizeof(typebuf), "Unknown (0x%02x)",
                           dp->icmp6_type);
                coltypename = typebuf;
            }
            if (colcodename && strcmp(colcodename, "Unknown") == 0) {
                g_snprintf(codebuf, sizeof(codebuf), "Unknown (0x%02x)",
                           dp->icmp6_code);
                colcodename = codebuf;
            }
            if (colcodename) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s (%s)", coltypename, colcodename);
            } else {
                col_add_str(pinfo->cinfo, COL_INFO, coltypename);
            }
        }
    }

    if (tree) {
        /* !!! specify length */
        ti = proto_tree_add_item(tree, proto_icmpv6, tvb, offset, -1, FALSE);
        icmp6_tree = proto_item_add_subtree(ti, ett_icmpv6);

        proto_tree_add_uint_format(icmp6_tree, hf_icmpv6_type, tvb,
                                   offset + offsetof(struct icmp6_hdr, icmp6_type), 1,
                                   dp->icmp6_type,
                                   "Type: %u (%s)", dp->icmp6_type, typename);
        if (codename) {
            proto_tree_add_uint_format(icmp6_tree, hf_icmpv6_code, tvb,
                                       offset + offsetof(struct icmp6_hdr, icmp6_code), 1,
                                       dp->icmp6_code,
                                       "Code: %u (%s)", dp->icmp6_code, codename);
        } else {
            proto_tree_add_uint_format(icmp6_tree, hf_icmpv6_code, tvb,
                                       offset + offsetof(struct icmp6_hdr, icmp6_code), 1,
                                       dp->icmp6_code,
                                       "Code: %u", dp->icmp6_code);
        }
        cksum = (guint16)g_htons(dp->icmp6_cksum);
        length = tvb_length(tvb);
        reported_length = tvb_reported_length(tvb);
        if (!pinfo->fragmented && length >= reported_length) {
            /* The packet isn't part of a fragmented datagram and isn't
               truncated, so we can checksum it. */

            /* Set up the fields of the pseudo-header. */
            cksum_vec[0].ptr = pinfo->src.data;
            cksum_vec[0].len = pinfo->src.len;
            cksum_vec[1].ptr = pinfo->dst.data;
            cksum_vec[1].len = pinfo->dst.len;
            cksum_vec[2].ptr = (const guint8 *)&phdr;
            phdr[0] = g_htonl(tvb_reported_length(tvb));
            phdr[1] = g_htonl(IP_PROTO_ICMPV6);
            cksum_vec[2].len = 8;
            cksum_vec[3].len = tvb_reported_length(tvb);
            cksum_vec[3].ptr = tvb_get_ptr(tvb, offset, cksum_vec[3].len);
            computed_cksum = in_cksum(cksum_vec, 4);
            if (computed_cksum == 0) {
                proto_tree_add_uint_format(icmp6_tree, hf_icmpv6_checksum,
                                           tvb,
                                           offset + offsetof(struct icmp6_hdr, icmp6_cksum), 2,
                                           cksum,
                                           "Checksum: 0x%04x [correct]", cksum);
            } else {
                hidden_item = proto_tree_add_boolean(icmp6_tree, hf_icmpv6_checksum_bad,
                                                     tvb,
                                                     offset + offsetof(struct icmp6_hdr, icmp6_cksum), 2,
                                                     TRUE);
                PROTO_ITEM_SET_HIDDEN(hidden_item);
                proto_tree_add_uint_format(icmp6_tree, hf_icmpv6_checksum,
                                           tvb,
                                           offset + offsetof(struct icmp6_hdr, icmp6_cksum), 2,
                                           cksum,
                                           "Checksum: 0x%04x [incorrect, should be 0x%04x]",
                                           cksum, in_cksum_shouldbe(cksum, computed_cksum));
            }
        } else {
            proto_tree_add_uint(icmp6_tree, hf_icmpv6_checksum, tvb,
                                offset + offsetof(struct icmp6_hdr, icmp6_cksum), 2,
                                cksum);
        }

#define ICMP6_DATA_OFFSET 4
#define ICMP6_SEQ_OFFSET 6
        /* decode... */
        switch (dp->icmp6_type) {
        case ICMP6_DST_UNREACH:
        case ICMP6_TIME_EXCEEDED:
            dissect_contained_icmpv6(tvb, offset + sizeof(*dp), pinfo,
                                     icmp6_tree);
            break;
        case ICMP6_PACKET_TOO_BIG:
            proto_tree_add_text(icmp6_tree, tvb,
                                offset + ICMP6_DATA_OFFSET, 4,
                                "MTU: %u", pntohl(&dp->icmp6_mtu));
            dissect_contained_icmpv6(tvb, offset + sizeof(*dp), pinfo,
                                     icmp6_tree);
            break;
        case ICMP6_PARAM_PROB:
            proto_tree_add_text(icmp6_tree, tvb,
                                offset + ICMP6_DATA_OFFSET, 4,
                                "Problem pointer: 0x%04x", pntohl(&dp->icmp6_pptr));
            dissect_contained_icmpv6(tvb, offset + sizeof(*dp), pinfo,
                                     icmp6_tree);
            break;
        case ICMP6_ECHO_REQUEST:
        case ICMP6_ECHO_REPLY:
            proto_tree_add_text(icmp6_tree, tvb,
                                offset + ICMP6_DATA_OFFSET, 2,
                                "ID: 0x%04x", (guint16)g_ntohs(dp->icmp6_id));
            proto_tree_add_text(icmp6_tree, tvb,
                                offset + ICMP6_SEQ_OFFSET, 2,
                                "Sequence: %u", (guint16)g_ntohs(dp->icmp6_seq));
            col_append_fstr(pinfo->cinfo, COL_INFO,
                            " id=0x%04x, seq=%u",
                            g_ntohs(dp->icmp6_id), g_ntohs(dp->icmp6_seq));

            if (pinfo->destport == 0x0dd8 && dp->icmp6_type == ICMP6_ECHO_REQUEST) {
                /* RFC 4380
                 * 5.2.9. Direct IPv6 Connectivity Test
                 */
                proto_tree_add_text(icmp6_tree, tvb, offset + ICMP6_SEQ_OFFSET + 2, 4,
                                    "Nonce: 0x%08x", tvb_get_ntohl(tvb, offset + ICMP6_SEQ_OFFSET + 2));
            } else {
                next_tvb = tvb_new_subset(tvb, offset + sizeof(*dp), -1, -1);
                call_dissector(data_handle,next_tvb, pinfo, icmp6_tree);
            }
            break;
        case ICMP6_MEMBERSHIP_QUERY:
        case ICMP6_MEMBERSHIP_REPORT:
        case ICMP6_MEMBERSHIP_REDUCTION:
#define MLDV2_MINLEN 28
#define MLDV1_MINLEN 24
            if (dp->icmp6_type == ICMP6_MEMBERSHIP_QUERY) {
                if (length >= MLDV2_MINLEN) {
                    guint32 mrc;
                    guint16 qqi;
                    guint8 flag;
                    guint16 nsrcs;

                    mrc = g_ntohs(dp->icmp6_maxdelay);
                    flag = tvb_get_guint8(tvb, offset + sizeof(*dp) + 16);
                    qqi = tvb_get_guint8(tvb, offset + sizeof(*dp) + 16 + 1);
                    nsrcs = tvb_get_ntohs(tvb, offset + sizeof(*dp) + 16 + 2);

                    if (mrc >= 32768)
                        mrc = ((mrc & 0x0fff) | 0x1000) <<
                            (((mrc & 0x7000) >> 12) + 3);
                    proto_tree_add_text(icmp6_tree, tvb,
                                        offset + ICMP6_DATA_OFFSET, 2,
                                        "Maximum response delay[ms]: %u", mrc);

                    proto_tree_add_text(icmp6_tree, tvb, offset + sizeof(*dp),
                                        16, "Multicast Address: %s",
                                        ip6_to_str((const struct e_in6_addr *)(tvb_get_ptr(tvb,
                                                                                           offset + sizeof *dp, sizeof (struct e_in6_addr)))));

                    proto_tree_add_text(icmp6_tree, tvb,
                                        offset + sizeof(*dp) + 16, 1, "S Flag: %s",
                                        flag & 0x08 ? "ON" : "OFF");
                    proto_tree_add_text(icmp6_tree, tvb,
                                        offset + sizeof(*dp) + 16, 1, "Robustness: %d",
                                        flag & 0x07);
                    if (qqi >= 128)
                        qqi = ((qqi & 0x0f) | 0x10) << (((qqi & 0x70) >> 4) + 3);
                    proto_tree_add_text(icmp6_tree, tvb,
                                        offset + sizeof(*dp) + 17, 1, "QQI: %d", qqi);

                    dissect_mldqv2(tvb, offset + sizeof(*dp) + 20, nsrcs,
                                   icmp6_tree);
                    break;
                } else if (length > MLDV1_MINLEN) {
                    next_tvb = tvb_new_subset(tvb, offset + sizeof(*dp), -1, -1);
                    call_dissector(data_handle,next_tvb, pinfo, tree);
                    break;
                }
                /* MLDv1 Query -> FALLTHOUGH */
            } /* if (dp->icmp6_type == ICMP6_MEMBERSHIP_QUERY) */
#undef MLDV2_MINLEN
#undef MLDV1_MINLEN
            proto_tree_add_text(icmp6_tree, tvb,
                                offset + ICMP6_DATA_OFFSET, 2,
                                "Maximum response delay: %u",
                                (guint16)g_ntohs(dp->icmp6_maxdelay));
            proto_tree_add_text(icmp6_tree, tvb, offset + sizeof(*dp), 16,
                                "Multicast Address: %s",
                                ip6_to_str((const struct e_in6_addr *)(tvb_get_ptr(tvb, offset + sizeof *dp, sizeof (struct e_in6_addr)))));
            break;
        case ND_ROUTER_SOLICIT:
            dissect_icmpv6ndopt(tvb, offset + sizeof(*dp), pinfo, icmp6_tree);
            break;
        case ICMP6_MLDV2_REPORT:
        {
            guint16 nbRecords;

            nbRecords = tvb_get_ntohs( tvb, offset+4+2 );
            proto_tree_add_text( icmp6_tree, tvb, offset+4, 2, "Reserved: %d (Should always be zero)",
                                 tvb_get_ntohs (tvb, offset+4) );
            proto_tree_add_item( icmp6_tree, hf_icmpv6_nor, tvb, offset+4+2, 2, FALSE );
            dissect_mldrv2( tvb, offset+4+2+2, nbRecords, icmp6_tree );
            break;
        }
#define ND_RA_CURHOPLIMIT_OFFSET 4
#define ND_RA_FLAGS_RESERVED_OFFSET 5
#define ND_RA_ROUTER_LIFETIME_OFFSET 6
        case ND_ROUTER_ADVERT:
        {
            struct nd_router_advert nd_router_advert, *ra;
            int flagoff;
            guint32 ra_flags;

            ra = &nd_router_advert;
            tvb_memcpy(tvb, (guint8 *)ra, offset, sizeof *ra);

            /* Current hop limit */
            proto_tree_add_uint(icmp6_tree, hf_icmpv6_ra_cur_hop_limit, tvb,
                                offset + ND_RA_CURHOPLIMIT_OFFSET,
                                1, ra->nd_ra_curhoplimit);

            /* Flags */
            flagoff = offset + ND_RA_FLAGS_RESERVED_OFFSET;
            ra_flags = tvb_get_guint8(tvb, flagoff);
            tf = proto_tree_add_text(icmp6_tree, tvb, flagoff, 1, "Flags: 0x%02x", ra_flags);
            field_tree = proto_item_add_subtree(tf, ett_icmpv6flag);

            proto_tree_add_text(field_tree, tvb, flagoff, 1, "%s",
                                decode_boolean_bitfield(ra_flags,
                                                        ND_RA_FLAG_MANAGED, 8, "Managed", "Not managed"));
            proto_tree_add_text(field_tree, tvb, flagoff, 1, "%s",
                                decode_boolean_bitfield(ra_flags,
                                                        ND_RA_FLAG_OTHER, 8, "Other", "Not other"));
            proto_tree_add_text(field_tree, tvb, flagoff, 1, "%s",
                                decode_boolean_bitfield(ra_flags,
                                                        ND_RA_FLAG_HOME_AGENT, 8,
                                                        "Home Agent", "Not Home Agent"));
            proto_tree_add_text(field_tree, tvb, flagoff, 1, "%s",
                                decode_enumerated_bitfield(ra_flags, ND_RA_FLAG_RTPREF_MASK, 8,
                                                           names_router_pref, "Router preference: %s"));
            proto_tree_add_text(field_tree, tvb, flagoff, 1, "%s",
                                decode_boolean_bitfield(ra_flags,
                                                        ND_RA_FLAG_ND_PROXY, 8,
                                                        "Proxied", "Not Proxied"));

            /* Router lifetime */
            proto_tree_add_uint(icmp6_tree, hf_icmpv6_ra_router_lifetime, tvb,
                                offset + ND_RA_ROUTER_LIFETIME_OFFSET,
                                2, (guint16)g_ntohs(ra->nd_ra_router_lifetime));

            /* Reachable time */
            proto_tree_add_uint(icmp6_tree, hf_icmpv6_ra_reachable_time, tvb,
                                offset + offsetof(struct nd_router_advert, nd_ra_reachable), 4,
                                pntohl(&ra->nd_ra_reachable));

            /* Retrans timer */
            proto_tree_add_uint(icmp6_tree, hf_icmpv6_ra_retrans_timer, tvb,
                                offset + offsetof(struct nd_router_advert, nd_ra_retransmit), 4,
                                pntohl(&ra->nd_ra_retransmit));

            dissect_icmpv6ndopt(tvb, offset + sizeof(struct nd_router_advert), pinfo, icmp6_tree);
            break;
        }
        case ND_NEIGHBOR_SOLICIT:
        {
            struct nd_neighbor_solicit nd_neighbor_solicit, *ns;

            ns = &nd_neighbor_solicit;
            tvb_memcpy(tvb, (guint8 *)ns, offset, sizeof *ns);
            proto_tree_add_text(icmp6_tree, tvb, offset+4, 4, "Reserved: %d (Should always be zero)",
                                tvb_get_ntohl (tvb, offset+4));
            proto_tree_add_text(icmp6_tree, tvb,
                                offset + offsetof(struct nd_neighbor_solicit, nd_ns_target), 16,
                                "Target: %s (%s)",
                                get_hostname6(&ns->nd_ns_target),
                                ip6_to_str(&ns->nd_ns_target));
            col_append_fstr(pinfo->cinfo, COL_INFO,
                            " for %s", ip6_to_str(&ns->nd_ns_target));

            dissect_icmpv6ndopt(tvb, offset + sizeof(*ns), pinfo, icmp6_tree);
            break;
        }
#define ND_NA_FLAGS_RESERVED_OFFSET 4
        case ND_NEIGHBOR_ADVERT:
        {
            int flagoff, targetoff;
            guint32 na_flags;
            struct e_in6_addr na_target;
            emem_strbuf_t *flags_strbuf = ep_strbuf_new_label("");

            flagoff = offset + ND_NA_FLAGS_RESERVED_OFFSET;
            na_flags = tvb_get_ntohl(tvb, flagoff);

            tf = proto_tree_add_text(icmp6_tree, tvb, flagoff, 4, "Flags: 0x%08x", na_flags);
            field_tree = proto_item_add_subtree(tf, ett_icmpv6flag);
            proto_tree_add_text(field_tree, tvb, flagoff, 4, "%s",
                                decode_boolean_bitfield(na_flags,
                                                        ND_NA_FLAG_ROUTER, 32, "Router", "Not router"));
            proto_tree_add_text(field_tree, tvb, flagoff, 4, "%s",
                                decode_boolean_bitfield(na_flags,
                                                        ND_NA_FLAG_SOLICITED, 32, "Solicited", "Not adverted"));
            proto_tree_add_text(field_tree, tvb, flagoff, 4, "%s",
                                decode_boolean_bitfield(na_flags,
                                                        ND_NA_FLAG_OVERRIDE, 32, "Override", "Not override"));

            targetoff = offset + offsetof(struct nd_neighbor_advert, nd_na_target);
            tvb_memcpy(tvb, (guint8 *)&na_target, targetoff, sizeof na_target);
            proto_tree_add_text(icmp6_tree, tvb, targetoff, 16,
                                "Target: %s (%s)",
                                get_hostname6(&na_target),
                                ip6_to_str(&na_target));
            if (na_flags & ND_NA_FLAG_ROUTER) {
                ep_strbuf_append(flags_strbuf, "rtr, ");
            }
            if (na_flags & ND_NA_FLAG_SOLICITED) {
                ep_strbuf_append(flags_strbuf, "sol, ");
            }
            if (na_flags & ND_NA_FLAG_OVERRIDE) {
                ep_strbuf_append(flags_strbuf, "ovr, ");
            }
            if (flags_strbuf->len > 2) {
                ep_strbuf_truncate(flags_strbuf, flags_strbuf->len - 2);
            } else {
                ep_strbuf_printf(flags_strbuf, "none");
            }
            col_append_fstr(pinfo->cinfo, COL_INFO,
                            " %s (%s)", ip6_to_str(&na_target), flags_strbuf->str);

            dissect_icmpv6ndopt(tvb, offset + sizeof(struct nd_neighbor_advert), pinfo, icmp6_tree);
            break;
        }
        case ND_REDIRECT:
        {
            struct nd_redirect nd_redirect, *rd;

            rd = &nd_redirect;
            tvb_memcpy(tvb, (guint8 *)rd, offset, sizeof *rd);
            proto_tree_add_text(icmp6_tree, tvb, offset+4, 4, "Reserved: %d (Should always be zero)",
                                tvb_get_ntohs (tvb, offset+4));
            proto_tree_add_text(icmp6_tree, tvb,
                                offset + offsetof(struct nd_redirect, nd_rd_target), 16,
                                "Target: %s (%s)",
                                get_hostname6(&rd->nd_rd_target),
                                ip6_to_str(&rd->nd_rd_target));

            proto_tree_add_text(icmp6_tree, tvb,
                                offset + offsetof(struct nd_redirect, nd_rd_dst), 16,
                                "Destination: %s (%s)",
                                get_hostname6(&rd->nd_rd_dst),
                                ip6_to_str(&rd->nd_rd_dst));

            dissect_icmpv6ndopt(tvb, offset + sizeof(*rd), pinfo, icmp6_tree);
            break;
        }
        case ICMP6_ROUTER_RENUMBERING:
            dissect_rrenum(tvb, offset, pinfo, icmp6_tree, dp->icmp6_type, dp->icmp6_code);
            break;
        case ICMP6_NI_QUERY:
        case ICMP6_NI_REPLY:
        {
            dissect_nodeinfo(tvb, offset, pinfo, icmp6_tree, dp->icmp6_type, dp->icmp6_code);
            break;
        }
        case ICMP6_MIP6_DHAAD_REQUEST:
            proto_tree_add_text(icmp6_tree, tvb,
                                offset + 4, 2, "Identifier: %d (0x%02x)",
                                tvb_get_ntohs(tvb, offset + 4),
                                tvb_get_ntohs(tvb, offset + 4));
            proto_tree_add_text(icmp6_tree, tvb,
                                offset + 6, 2, "Reserved: %d",
                                tvb_get_ntohs(tvb, offset + 6));
            break;
        case ICMP6_MIP6_DHAAD_REPLY:
            proto_tree_add_text(icmp6_tree, tvb,
                                offset + 4, 2, "Identifier: %d (0x%02x)",
                                tvb_get_ntohs(tvb, offset + 4),
                                tvb_get_ntohs(tvb, offset + 4));
            proto_tree_add_text(icmp6_tree, tvb,
                                offset + 6, 2, "Reserved: %d",
                                tvb_get_ntohs(tvb, offset + 6));
            /* Show all Home Agent Addresses */
            {
                int i, suboffset;
                int ha_num = (length - 8)/16;

                for (i = 0; i < ha_num; i++) {
                    suboffset = 16 * i;
                    proto_tree_add_ipv6(icmp6_tree, hf_icmpv6_haad_ha_addrs,
                                        tvb, offset + 8 + suboffset, 16,
                                        tvb_get_ptr(tvb, offset + 8 + suboffset, 16));
                }
            }
            break;
        case ICMP6_MIP6_MPS:
            proto_tree_add_text(icmp6_tree, tvb,
                                offset + 4, 2, "Identifier: %d (0x%02x)",
                                tvb_get_ntohs(tvb, offset + 4),
                                tvb_get_ntohs(tvb, offset + 4));
            proto_tree_add_text(icmp6_tree, tvb,
                                offset + 6, 2, "Reserved: %d",
                                tvb_get_ntohs(tvb, offset + 6));
            break;
        case ICMP6_MIP6_MPA:
            proto_tree_add_text(icmp6_tree, tvb,
                                offset + 4, 2, "Identifier: %d (0x%02x)",
                                tvb_get_ntohs(tvb, offset + 4),
                                tvb_get_ntohs(tvb, offset + 4));
            proto_tree_add_text(icmp6_tree, tvb,
                                offset + 6, 1, "%s",
                                decode_boolean_bitfield(tvb_get_guint8(tvb, offset + 6),
                                                        0x80, 8,
                                                        "Managed Address Configuration",
                                                        "No Managed Address Configuration"));
            proto_tree_add_text(icmp6_tree, tvb,
                                offset + 6, 1, "%s",
                                decode_boolean_bitfield(tvb_get_guint8(tvb, offset + 6),
                                                        0x40, 8,
                                                        "Other Stateful Configuration",
                                                        "No Other Stateful Configuration"));
            proto_tree_add_text(icmp6_tree, tvb,
                                offset + 7, 1, "Reserved: %d",
                                tvb_get_guint8(tvb, offset + 7));
            /* Show all options */
            dissect_icmpv6ndopt(tvb, offset + 8, pinfo, icmp6_tree);
            break;
        case ICMP6_EXPERIMENTAL_MOBILITY:
            switch (dp->icmp6_data8[0]) {
            case FMIP6_SUBTYPE_RTSOLPR:
            {
                struct fmip6_rtsolpr *rtsolpr;
                rtsolpr = (struct fmip6_rtsolpr*) dp;
                proto_tree_add_text(icmp6_tree, tvb,
                                    offset + 4, 1,
                                    "Subtype: Router Solicitation for Proxy Advertisement");
                proto_tree_add_text(icmp6_tree, tvb,
                                    offset + 6, 2,
                                    "Identifier: %d", pntohs(&rtsolpr->fmip6_rtsolpr_id));
                dissect_icmpv6ndopt(tvb, offset + sizeof(*dp), pinfo, icmp6_tree);
                break;
            }
            case FMIP6_SUBTYPE_PRRTADV:
            {
                struct fmip6_prrtadv *prrtadv;
                prrtadv = (struct fmip6_prrtadv*) dp;
                proto_tree_add_text(icmp6_tree, tvb,
                                    offset + 4, 1,
                                    "Subtype: Proxy Router Advertisement");
                proto_tree_add_text(icmp6_tree, tvb,
                                    offset + 6, 2,
                                    "Identifier: %d", pntohs(&prrtadv->fmip6_prrtadv_id));
                dissect_icmpv6ndopt(tvb, offset + sizeof(*dp), pinfo, icmp6_tree);
                break;
            }
            case FMIP6_SUBTYPE_HI:
            {
                struct fmip6_hi *hi;
                int flagoff;
                guint8 hi_flags;
                hi = (struct fmip6_hi*) dp;
                proto_tree_add_text(icmp6_tree, tvb,
                                    offset + 4, 1,
                                    "Subtype: Handover Initiate");

                flagoff = offset + 5;
                hi_flags = tvb_get_guint8(tvb, flagoff);
                tf = proto_tree_add_text(icmp6_tree, tvb, flagoff, 1, "Flags: 0x%02x", hi_flags);
                field_tree = proto_item_add_subtree(tf, ett_icmpv6flag);
                proto_tree_add_text(field_tree, tvb, flagoff, 1, "%s",
                                    decode_boolean_bitfield(hi_flags,
                                                            FMIP_HI_FLAG_ASSIGNED, 8, "Assigned", "Not assigned"));
                proto_tree_add_text(field_tree, tvb, flagoff, 1, "%s",
                                    decode_boolean_bitfield(hi_flags,
                                                            FMIP_HI_FLAG_BUFFER, 8, "Buffered", "Not buffered"));
                proto_tree_add_text(icmp6_tree, tvb,
                                    offset + 6, 2,
                                    "Identifier: %d", pntohs(&hi->fmip6_hi_id));
                dissect_icmpv6ndopt(tvb, offset + sizeof(*dp), pinfo, icmp6_tree);
                break;
            }
            case FMIP6_SUBTYPE_HACK:
            {
                struct fmip6_hack *hack;
                hack = (struct fmip6_hack*) dp;
                proto_tree_add_text(icmp6_tree, tvb,
                                    offset + 4, 1,
                                    "Subtype: Handover Acknowledge");
                proto_tree_add_text(icmp6_tree, tvb,
                                    offset + 6, 2,
                                    "Identifier: %d", pntohs(&hack->fmip6_hack_id));
                dissect_icmpv6ndopt(tvb, offset + sizeof(*dp), pinfo, icmp6_tree);
                break;
            }
            } /* switch (dp->icmp6_data8[0]) */
            break;
        case ICMP6_CERT_PATH_SOL:
            /*RFC 3971 6.4.1.  Certification Path Solicitation Message Format */
            offset += 4;
            proto_tree_add_text(icmp6_tree, tvb, offset, -1,
                                "Certification Path Solicitation Message");
            /* Identifier A 16-bit unsigned integer field */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_identifier, tvb, offset,
                                2, FALSE);
            offset += 2;
            /* Component A 16-bit unsigned integer field,
             * 65,535 if the sender seeks to retrieve all certificates.
             * Otherwise, set to the identifier that the receiver wants.
             */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_comp, tvb, offset, 2,
                                FALSE);
            offset += 2;
            dissect_icmpv6ndopt(tvb, offset, pinfo, icmp6_tree);
            break;
        case ICMP6_CERT_PATH_AD:
            /*RFC 3971 6.4.2.  Certification Path Advertisement Message Format */
            offset = offset +4;
            proto_tree_add_text(icmp6_tree, tvb, offset, -1,"Certification Path Advertisement Message");

            /* Identifier A 16-bit unsigned integer field */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_identifier, tvb, offset, 2, FALSE);
            offset = offset + 2;
            /* All Components  A 16-bit unsigned integer field*/
            proto_tree_add_item(icmp6_tree, hf_icmpv6_all_comp, tvb, offset, 2, FALSE);
            offset = offset + 2;

            /* Component A 16-bit unsigned integer field, used to inform the receiver
             * which certificate is being sent.
             */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_comp, tvb, offset, 2, FALSE);
            offset = offset + 2;

            /* Reserved */
            proto_tree_add_text(icmp6_tree, tvb, offset, 2,"Reserved");
            offset = offset + 2;

            dissect_icmpv6ndopt(tvb, offset, pinfo, icmp6_tree);
            break;
        case ICMP6_RPL_CONTROL:
            /* RPL: draft-ietf-roll-rpl-12.txt: Routing over Low-Power and Lossy Networks. */
            offset += 4; /* Skip the type, code and checksum. */
            if (dp->icmp6_code == ICMP6_RPL_DIS) {

                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_dis_reserved, tvb, offset, 2, FALSE);
                offset += 2;

            }
            else if (dp->icmp6_code == ICMP6_RPL_DIO) {
                /* DODAG Information Object */
                guint8  flags;

                /* RPLInstanceID */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_dio_instance, tvb, offset, 1, FALSE);
                offset += 1;

                /* RPLInstanceID */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_dio_version, tvb, offset, 1, FALSE);
                offset += 1;

                /* Rank */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_dio_rank, tvb, offset, 2, FALSE);
                offset += 2;

                /* flags */
                flags = tvb_get_guint8(tvb, offset);
                proto_tree_add_boolean(icmp6_tree, hf_icmpv6_dio_grounded, tvb, offset, 1, flags & RPL_DIO_FLAG_GROUNDED);
                proto_tree_add_boolean(icmp6_tree, hf_icmpv6_dio_zero, tvb, offset, 1, flags & RPL_DIO_FLAG_ZERO);
                proto_tree_add_uint(icmp6_tree, hf_icmpv6_dio_mop, tvb, offset, 1, flags & RPL_DIO_FLAG_MOP);
                proto_tree_add_uint(icmp6_tree, hf_icmpv6_dio_preference, tvb, offset, 1, flags & RPL_DIO_FLAG_PREFERENCE);
                offset += 1;

                /* Destination Advertisement Trigger Sequence Number (DTSN) */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_dio_trigger_seqnum, tvb, offset, 1, FALSE);
                offset += 1;
                offset += 2;

                /* DODAGID */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_dio_dagid, tvb, offset, 16, FALSE);
                offset += 16;
            }
            else if (dp->icmp6_code == ICMP6_RPL_DAO) {
                /* Destination Advertisement Object */
                struct e_in6_addr   addr6;
                guint8 flags;

                /* DAO Instance */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_dao_instance, tvb, offset, 1, FALSE);
                offset += 1;

                /* flags */
                flags = tvb_get_guint8(tvb, offset);
                proto_tree_add_boolean(icmp6_tree, hf_icmpv6_dao_flag_k, tvb, offset, 1, flags & RPL_DAO_FLAG_K);
                proto_tree_add_boolean(icmp6_tree, hf_icmpv6_dao_flag_d, tvb, offset, 1, flags & RPL_DAO_FLAG_D);
                proto_tree_add_uint(icmp6_tree, hf_icmpv6_dao_flag_rsv, tvb, offset, 1, flags & RPL_DAO_FLAG_RESERVED);
                offset += 1;

                /* DAO Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_dao_reserved, tvb, offset, 1, FALSE);
                offset += 1;

                /* DAO Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_dao_seqnum, tvb, offset, 1, FALSE);
                offset += 1;

                if(flags & RPL_DAO_FLAG_D)
                {
                    tvb_memcpy(tvb, addr6.bytes, offset, 16);
                    proto_tree_add_ipv6(icmp6_tree, hf_icmpv6_dao_dodagid, tvb, offset, 16, addr6.bytes);
                    offset += 16;
                }
            }
            else if (dp->icmp6_code == ICMP6_RPL_DAOACK) {
                /* Destination Advertisement Object */
                struct e_in6_addr   addr6;
                guint8 flags;

                /* DAO Instance */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_daoack_instance, tvb, offset, 1, FALSE);
                offset += 1;

                /* flags */
                flags = tvb_get_guint8(tvb, offset);
                proto_tree_add_boolean(icmp6_tree, hf_icmpv6_daoack_flag_d, tvb, offset, 1, flags & RPL_DAOACK_FLAG_D);
                proto_tree_add_uint(icmp6_tree, hf_icmpv6_daoack_flag_rsv, tvb, offset, 1, flags & RPL_DAOACK_FLAG_RESERVED);
                offset += 1;

                /* DAO Sequence */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_daoack_seqnum, tvb, offset, 1, FALSE);
                offset += 1;

                /* DAO Status */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_daoack_status, tvb, offset, 1, FALSE);
                offset += 1;

                if(flags & RPL_DAOACK_FLAG_D)
                {
                    tvb_memcpy(tvb, addr6.bytes, offset, 16);
                    proto_tree_add_ipv6(icmp6_tree, hf_icmpv6_daoack_dodagid, tvb, offset, 16, addr6.bytes);
                    offset += 16;
                }
                return;
            }
            /* Options */
            dissect_icmpv6_rpl_opt(tvb, offset, pinfo, icmp6_tree);
            break;
        default:
            next_tvb = tvb_new_subset(tvb, offset + sizeof(*dp), -1, -1);
            call_dissector(data_handle,next_tvb, pinfo, tree);
            break;
        } /* switch (dp->icmp6_type) */
    } /* if (tree) */
}

void
proto_register_icmpv6(void)
{
    static hf_register_info hf[] = {
        { &hf_icmpv6_type,
          { "Type",           "icmpv6.type",    FT_UINT8,  BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_code,
          { "Code",           "icmpv6.code",    FT_UINT8,  BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_checksum,
          { "Checksum",       "icmpv6.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_checksum_bad,
          { "Bad Checksum",   "icmpv6.checksum_bad", FT_BOOLEAN, BASE_NONE,  NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_reserved,
          { "Reserved",           "icmpv6.reserved",    FT_BYTES,  BASE_NONE, NULL, 0x0,
            "Must be Zero", HFILL }},
        { &hf_icmpv6_nor,
          { "Number of records", "icmpv6.nor", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_haad_ha_addrs,
          { "Home Agent Addresses", "icmpv6.haad.ha_addrs", FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_ra_cur_hop_limit,
          { "Cur hop limit",           "icmpv6.ra.cur_hop_limit", FT_UINT8,  BASE_DEC, NULL, 0x0,
            "Current hop limit", HFILL }},
        { &hf_icmpv6_ra_router_lifetime,
          { "Router lifetime",         "icmpv6.ra.router_lifetime", FT_UINT16,  BASE_DEC, NULL, 0x0,
            "Router lifetime (s)", HFILL }},
        { &hf_icmpv6_ra_reachable_time,
          { "Reachable time",          "icmpv6.ra.reachable_time", FT_UINT32,  BASE_DEC, NULL, 0x0,
            "Reachable time (ms)", HFILL }},
        { &hf_icmpv6_ra_retrans_timer,
          { "Retrans timer",           "icmpv6.ra.retrans_timer", FT_UINT32,  BASE_DEC, NULL, 0x0,
            "Retrans timer (ms)", HFILL }},
        { &hf_icmpv6_opt,
          { "ICMPv6 Option",           "icmpv6.opt", FT_NONE,  BASE_NONE, NULL, 0x0,
            "Option", HFILL }},
        { &hf_icmpv6_opt_type,
          { "Type",           "icmpv6.opt.type", FT_UINT8,  BASE_DEC, VALS(option_vals), 0x0,
            "Options type", HFILL }},
        { &hf_icmpv6_opt_length,
          { "Length",         "icmpv6.opt.length", FT_UINT8,  BASE_DEC, NULL, 0x0,
            "The length (in units of 8 bytes) of the option (including the Type and Length fields)", HFILL }},
        { &hf_icmpv6_opt_reserved,
          { "Reserved", "icmpv6.opt.reserved", FT_NONE, BASE_NONE, NULL, 0x0,
            "Reserved (Must be 0)", HFILL }},
        { &hf_icmpv6_opt_padding,
          { "Padding", "icmpv6.opt.padding", FT_NONE, BASE_NONE, NULL, 0x0,
            "Padding (Must be 0)", HFILL }},
        { &hf_icmpv6_opt_linkaddr,
          { "Link-layer address",         "icmpv6.opt.linkaddr", FT_BYTES,  BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
       { &hf_icmpv6_opt_src_linkaddr,
          { "Source Link-layer address",         "icmpv6.opt.src_linkaddr", FT_BYTES,  BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
       { &hf_icmpv6_opt_target_linkaddr,
          { "Target Link-layer address",         "icmpv6.opt.target_linkaddr", FT_BYTES,  BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_linkaddr_mac,
          { "Link-layer address",         "icmpv6.opt.linkaddr", FT_ETHER,  BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
       { &hf_icmpv6_opt_src_linkaddr_mac,
          { "Source Link-layer address",         "icmpv6.opt.src_linkaddr", FT_ETHER,  BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
       { &hf_icmpv6_opt_target_linkaddr_mac,
          { "Target Link-layer address",         "icmpv6.opt.target_linkaddr", FT_ETHER,  BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
	{ &hf_icmpv6_opt_prefix_len,
          { "Prefix Length", "icmpv6.opt.prefix.length", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The number of leading bits in the Prefix that are valid", HFILL }},
	{ &hf_icmpv6_opt_prefix_flag,
          { "Flag", "icmpv6.opt.prefix.flag", FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }},
	{ &hf_icmpv6_opt_prefix_flag_l,
          { "On-link flag(L)", "icmpv6.opt.prefix.flag.l", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
            "When set, indicates that this prefix can be used for on-link determination", HFILL }},
	{ &hf_icmpv6_opt_prefix_flag_a,
          { "Autonomous address-configuration flag(A)", "icmpv6.opt_prefix.flag.a", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
            "When set indicates that this prefix can be used for stateless address configuration", HFILL }},
	{ &hf_icmpv6_opt_prefix_flag_reserved,
          { "Reserved", "icmpv6.opt.prefix.flag.reserved", FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }},
	{ &hf_icmpv6_opt_prefix_valid_lifetime,
          { "Valid Lifetime", "icmpv6.opt.prefix.valid_lifetime", FT_UINT32, BASE_DEC, NULL, 0x00,
            "The length of time in seconds that the prefix is valid for the purpose of on-link determination", HFILL }},
	{ &hf_icmpv6_opt_prefix_preferred_lifetime,
          { "Preferred Lifetime", "icmpv6.opt.prefix.preferred_lifetime", FT_UINT32, BASE_DEC, NULL, 0x00,
            "The length of time in seconds that addresses generated from the prefix via stateless address autoconfiguration remain preferred", HFILL }},
	{ &hf_icmpv6_opt_prefix,
          { "Prefix", "icmpv6.opt.prefix", FT_IPv6, BASE_NONE, NULL, 0x00,
            "An IP address or a prefix of an IP address", HFILL }},
        { &hf_icmpv6_opt_cga_pad_len,
          { "Pad Length",     "icmpv6.opt.cga.pad_length", FT_UINT8,  BASE_DEC, NULL, 0x0,
            "Pad Length (in bytes)", HFILL }},
        { &hf_icmpv6_opt_cga,
          { "CGA",            "icmpv6.opt.cga", FT_BYTES,  BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_cga_modifier,
          { "Modifier",       "icmpv6.opt.cga.modifier", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_cga_subnet_prefix,
          { "Subnet Prefix",  "icmpv6.opt.cga.subnet_prefix", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_cga_count,
          { "Count",          "icmpv6.opt.cga.count", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_cga_ext_type,
          { "Ext Type",       "icmpv6.opt.cga.ext_type", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_cga_ext_length,
          { "Ext Length",     "icmpv6.opt.cga.ext_length", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_cga_ext_data,
          { "Ext Data",     "icmpv6.opt.cga.ext_length", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_rsa_key_hash,
          { "Key Hash",       "icmpv6.opt.rsa.key_hash", FT_BYTES,  BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_digital_signature_padding,
          { "Digital Signature and Padding",       "icmpv6.opt.digital_signature_padding", FT_NONE,  BASE_NONE, NULL, 0x0,
            "TO DO FIX ME !!", HFILL }},
        { &hf_icmpv6_opt_timestamp,
          { "Timestamp",       "icmpv6.opt.timestamp", FT_ABSOLUTE_TIME,  ABSOLUTE_TIME_LOCAL, NULL, 0x0,
            "The value indicates the number of seconds since January 1, 1970, 00:00 UTC", HFILL }},
        { &hf_icmpv6_opt_nonce,
          { "Nonce",       "icmpv6.opt.nonce", FT_BYTES,  BASE_NONE, NULL, 0x0,
            "A field containing a random number selected by the sender of the solicitation message", HFILL }},
        { &hf_icmpv6_opt_certificate_padding,
          { "Certificat and Padding",       "icmpv6.opt.certificate_padding", FT_NONE,  BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
	{ &hf_icmpv6_opt_ipa_option_code,
          { "Option-code", "icmpv6.opt.ipa.option_code", FT_UINT8, BASE_DEC, VALS(nd_opt_ipa_option_code_val), 0x00,
            NULL, HFILL }},
	{ &hf_icmpv6_opt_ipa_prefix_len,
          { "Prefix Length", "icmpv6.opt.ipa.prefix_len", FT_UINT8, BASE_DEC, NULL, 0x00,
            "That indicates the length of the IPv6 Address Prefix", HFILL }},
	{ &hf_icmpv6_opt_ipa_ipv6_address,
          { "IPv6 Address", "icmpv6.opt.ipa.ipv6_address", FT_IPv6, BASE_NONE, NULL, 0x00,
            "The IP address/prefix defined by the Option-Code field", HFILL }},
	{ &hf_icmpv6_opt_nrpi_option_code,
          { "Option-code", "icmpv6.opt.nrpi.option_code", FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},
	{ &hf_icmpv6_opt_nrpi_prefix_len,
          { "Prefix Length", "icmpv6.opt.nrpi.prefix_len", FT_UINT8, BASE_DEC, NULL, 0x00,
            "The number of leading bits in the Prefix that are valid", HFILL }},
	{ &hf_icmpv6_opt_nrpi_prefix,
          { "Prefix", "icmpv6.opt.nrpi.prefix", FT_IPv6, BASE_NONE, NULL, 0x00,
            "An IP address or a prefix of an IP address", HFILL }},
	{ &hf_icmpv6_opt_lla_option_code,
          { "Option-code", "icmpv6.opt.lla.option_code", FT_UINT8, BASE_DEC, VALS(nd_opt_lla_option_code_val), 0x00,
            NULL, HFILL }},
	{ &hf_icmpv6_opt_lla_bytes,
          { "Link-Layer Address", "icmpv6.opt.lla.bytes", FT_BYTES, BASE_NONE, NULL, 0x00,
            "(in Bytes Format)", HFILL }},
	{ &hf_icmpv6_opt_naack_option_code,
          { "Option-Code", "icmpv6.opt.naack.option_code", FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }},
	{ &hf_icmpv6_opt_naack_status,
          { "Status", "icmpv6.opt.naack.status", FT_UINT8, BASE_DEC, VALS(nd_opt_naack_status_val), 0x00,
            "Indicating the disposition of the Unsolicited Neighbor Advertisement message", HFILL }},
	{ &hf_icmpv6_opt_naack_supplied_ncoa,
          { "Supplied NCoA", "icmpv6.opt.naack.supplied_ncoa", FT_IPv6, BASE_NONE, NULL, 0x00,
            NULL, HFILL }}, 

        { &hf_icmpv6_opt_map_dist,
          { "Distance",       "icmpv6.opt.map.distance", FT_UINT8,  BASE_DEC, NULL, 0xF0,
            "Identifying the distance between MAP and the receiver of the advertisement (in the number of hops)", HFILL }},
        { &hf_icmpv6_opt_map_pref,
          { "Preference",       "icmpv6.opt.map.preference", FT_UINT8,  BASE_DEC, NULL, 0x0F,
            "Used as an indicator of operator preference (Highest is better)", HFILL }},
        { &hf_icmpv6_opt_map_flag,
          { "Flag",       "icmpv6.opt.map.flag", FT_UINT8,  BASE_HEX, NULL, 0x00,
            NULL, HFILL }},
        { &hf_icmpv6_opt_map_flag_r,
          { "RCoA Flag",       "icmpv6.opt.map.flag.r", FT_BOOLEAN,  8, NULL, 0x80,
            "It indicates that the mobile node is allocated the RCoA by the MAP", HFILL }},
        { &hf_icmpv6_opt_map_flag_reserved,
          { "Reserved",       "icmpv6.opt.map.flag.reserved", FT_UINT8,  BASE_DEC, NULL, 0x7F,
            "Must be 0", HFILL }},
        { &hf_icmpv6_opt_map_valid_lifetime,
          { "Valid Lifetime",       "icmpv6.opt.map.valid_lifetime", FT_UINT32,  BASE_DEC, NULL, 0x0,
            "This value indicates the validity of the MAP's address and the RCoA.", HFILL }},
        { &hf_icmpv6_opt_map_global_address,
          { "Global Address",       "icmpv6.opt.map.global_address", FT_IPv6,  BASE_NONE, NULL, 0x0,
            "TOne of the MAP's global addresses", HFILL }},
	{ &hf_icmpv6_opt_route_info_flag,
          { "Flag", "icmpv6.opt.route_info.flag", FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }},
	{ &hf_icmpv6_opt_route_info_flag_route_preference,
          { "Route Preference", "icmpv6.opt.route_info.flag.route_preference", FT_UINT8, BASE_DEC, VALS(names_router_pref), ND_RA_FLAG_RTPREF_MASK,
            "The Route Preference indicates whether to prefer the router associated with this prefix over others", HFILL }},
	{ &hf_icmpv6_opt_route_info_flag_reserved,
          { "Reserved", "icmpv6.opt.route_info.flag.reserved", FT_UINT8, BASE_DEC, NULL, ND_RA_FLAG_RESERV_MASK,
            "Must be 0", HFILL }},
	{ &hf_icmpv6_opt_route_lifetime,
          { "Route Lifetime", "icmpv6.opt.route_lifetime", FT_UINT32, BASE_DEC, NULL, 0x00,
            "The length of time in seconds that the prefix is valid for the purpose of route determination", HFILL }},
	
        { &hf_icmpv6_opt_name_type,
          { "Name Type",      "icmpv6.opt.name_type", FT_UINT8,  BASE_DEC, VALS(icmpv6_option_name_type_vals), 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_name_x501,
          { "DER Encoded X.501 Name", "icmpv6.opt.name_x501", FT_BYTES,  BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_name_fqdn,
          { "FQDN",           "icmpv6.opt.name_type.fqdn", FT_STRING,  BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_cert_type,
          { "Cert Type",       "icmpv6.opt.name_type", FT_UINT8,  BASE_DEC, VALS(icmpv6_option_cert_type_vals), 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_identifier,
          { "Identifier",      "icmpv6.identifier", FT_UINT16,  BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_all_comp,
          { "All Components",  "icmpv6.all_comp", FT_UINT16,  BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_comp,
          { "Component",       "icmpv6.comp", FT_UINT16,  BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_x509if_Name,
          { "Name",            "icmpv6.x509_Name", FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_x509af_Certificate,
          { "Certificate",     "icmpv6.x509_Certificate", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_redirected_packet,
          { "Redirected Packet", "icmpv6.opt.redirected_packet", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_mtu,
          { "MTU", "icmpv6.opt.mtu", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The recommended MTU for the link", HFILL }},
        { &hf_icmpv6_opt_nbma_shortcut_limit,
          { "Shortcut Limit", "icmpv6.opt.nbma.shortcut_limit", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Hop limit for shortcut attempt", HFILL }},
        { &hf_icmpv6_opt_advertisement_interval,
          { "Advertisement Interval", "icmpv6.opt.advertisement_interval", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The maximum time (in milliseconds) between successive unsolicited Router Advertisement messages sent by this router on this network interface", HFILL }},
        { &hf_icmpv6_opt_home_agent_preference,
          { "Home Agent Preference", "icmpv6.opt.home_agent_preference", FT_UINT16, BASE_DEC, NULL, 0x0,
            "The preference for the home agent sending this Router Advertisement", HFILL }},
        { &hf_icmpv6_opt_home_agent_lifetime,
          { "Home Agent Preference", "icmpv6.opt.home_agent_lifetime", FT_UINT16, BASE_DEC, NULL, 0x0,
            "The lifetime associated with the home agent in units of seconds.", HFILL }},
        { &hf_icmpv6_opt_ipv6_address,
          { "IPv6 Address", "icmpv6.opt.ipv6_address", FT_IPv6, BASE_NONE, NULL, 0x0,
            "IPv6 addresses of the interface", HFILL }},
        { &hf_icmpv6_opt_rdnss_lifetime,
          { "Lifetime", "icmpv6.opt.rdnss.lifetime", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_rdnss,
          { "Recursive DNS Servers", "icmpv6.opt.rdnss", FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_efo,
          { "Flags Expansion Option", "icmpv6.opt.efo", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_efo_m,
          { "Managed address configuration", "icmpv6.opt.efo.m", FT_BOOLEAN, 16, TFS(&tfs_set_notset), FLAGS_EO_M,
            "When set, it indicates that addresses are available via DHCPv6", HFILL }},
        { &hf_icmpv6_opt_efo_o,
          { "Other configuration", "icmpv6.opt.efo.o", FT_BOOLEAN, 16, TFS(&tfs_set_notset), FLAGS_EO_O,
            "When set, it indicates that other configuration information is available via DHCPv6", HFILL }},
        { &hf_icmpv6_opt_efo_h,
          { "Home Agent", "icmpv6.opt.efo.h", FT_BOOLEAN, 16, TFS(&tfs_set_notset), FLAGS_EO_H,
            "When set, it indicate that the router sending this Router Advertisement is also functioning as a Mobile IPv6 home agent on this link", HFILL }},
        { &hf_icmpv6_opt_efo_prf,
          { "Prf (Default Router Preference)", "icmpv6.opt.efo.prf", FT_UINT16, BASE_DEC, VALS(names_router_pref), FLAGS_EO_PRF,
            "Indicates whether to prefer this router over other default routers", HFILL }},
        { &hf_icmpv6_opt_efo_p,
          { "Proxy", "icmpv6.opt.efo.p", FT_BOOLEAN, 16, TFS(&tfs_set_notset), FLAGS_EO_P,
           NULL, HFILL }},
        { &hf_icmpv6_opt_efo_rsv,
          { "Reserved (Must be Zero)", "icmpv6.opt.efo.rsv", FT_UINT16, BASE_DEC, NULL, FLAGS_EO_RSV,
            NULL, HFILL }},
        { &hf_icmpv6_opt_hkr_pad_length,
          { "Pad Length", "icmpv6.opt.hkr.pad_length", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The number of padding octets beyond the end of the Handover Key", HFILL }},
        { &hf_icmpv6_opt_hkr_at,
          { "AT", "icmpv6.opt.hkr.at", FT_UINT8, BASE_DEC, NULL, 0xF0,
            "The algorithm type field describing the algorithm used by FMIPv6 to calculate the authenticator", HFILL }},
        { &hf_icmpv6_opt_hkr_reserved,
          { "Reserved", "icmpv6.opt.hkr.reserved", FT_UINT8, BASE_DEC, NULL, 0x0F,
            "Reserved (Must be Zero)", HFILL }},
        { &hf_icmpv6_opt_hkr_encryption_public_key,
          { "Handover Key Encryption Public Key", "icmpv6.opt.hkr.encryption_public_key", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_hkr_padding,
          { "Padding", "icmpv6.opt.hkr.padding", FT_BYTES, BASE_NONE, NULL, 0x0,
            "A variable-length field making the option length a multiple of 8", HFILL }},
        { &hf_icmpv6_opt_hkr_lifetime,
          { "Padding", "icmpv6.opt.hkr.lifetime", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Lifetime of the handover key (in seconds)", HFILL }},
        { &hf_icmpv6_opt_hkr_encrypted_handover_key,
          { "Encrypted Handover Key", "icmpv6.opt.hkr.encrypted_handover_key", FT_BYTES, BASE_NONE, NULL, 0x0,
            "The shared handover key, encrypted with the MN's handover key encryption public key", HFILL }},
        { &hf_icmpv6_opt_hai_option_code,
          { "Option-Code", "icmpv6.opt.hai.option_code", FT_UINT8, BASE_DEC, VALS(nd_opt_hai_option_code_val), 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_hai_length,
          { "HAI-Length", "icmpv6.opt.hai.length", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The size of the HAI-Value field in octets", HFILL }},
        { &hf_icmpv6_opt_hai_value,
          { "HAI-Value", "icmpv6.opt.hai.value", FT_BYTES, BASE_NONE, NULL, 0x0,
            "The value specified by the Option-Code", HFILL }},
        { &hf_icmpv6_opt_mn_option_code,
          { "Option-Code", "icmpv6.opt.mn.option_code", FT_UINT8, BASE_DEC, VALS(nd_opt_mn_option_code_val), 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_mn_length,
          { "MN-Length", "icmpv6.opt.mn.length", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The size of the MN-Value field in octets", HFILL }},
        { &hf_icmpv6_opt_mn_value,
          { "MN-Value", "icmpv6.opt.mn.value", FT_BYTES, BASE_NONE, NULL, 0x0,
            "The value specified by the Option-Code", HFILL }},
        { &hf_icmpv6_opt_dnssl_lifetime,
          { "Lifetime", "icmpv6.opt.dnssl.lifetime", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_dnssl,
          { "Domain Names", "icmpv6.opt.dnssl", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_aro_status,
          { "Status", "icmpv6.opt.aro.status", FT_UINT8, BASE_DEC, VALS(names_6lowpannd_aro_status_str), 0x00,
            "The amount of time (in a unit of 10 seconds) that the router should retain the Neighbor Cache entry", HFILL }},
        { &hf_icmpv6_opt_aro_registration_lifetime,
          { "Registration  Lifetime", "icmpv6.opt.aro.registration_lifetime", FT_UINT16, BASE_DEC, NULL, 0x00,
            "The amount of time (in a unit of 10 seconds) that the router should retain the Neighbor Cache entry", HFILL }},
        { &hf_icmpv6_opt_aro_eui64, /*  TODO: add a FT_EUI64 Type ? */
          { "EUI-64", "icmpv6.opt.aro.eui64", FT_BYTES, BASE_NONE, NULL, 0x00,
            "This field is used to uniquely identify the interface of the registered address", HFILL }},
        { &hf_icmpv6_opt_6co_context_length,
          { "Context Length", "icmpv6.opt.6co.context_length", FT_UINT8, BASE_DEC, NULL, 0x00,
            "The number of leading bits in the Context Prefix field that are valid", HFILL }},
        { &hf_icmpv6_opt_6co_flag,
          { "Flag", "icmpv6.opt.6co.flag", FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }},
        { &hf_icmpv6_opt_6co_flag_c,
          { "Compression Flag", "icmpv6.opt.6co.flag.c", FT_BOOLEAN, 8, TFS(&tfs_set_notset), ND_OPT_6CO_FLAG_C,
            "This flag indicates if the context is valid for use in compression", HFILL }},
        { &hf_icmpv6_opt_6co_flag_cid,
          { "CID", "icmpv6.opt.6co.flag.cid", FT_UINT8, BASE_DEC, NULL, ND_OPT_6CO_FLAG_CID,
            "Context Identifier for this prefix information", HFILL }},
        { &hf_icmpv6_opt_6co_flag_reserved,
          { "Reserved", "icmpv6.opt.6co.flag.reserved", FT_UINT8, BASE_DEC, NULL, ND_OPT_6CO_FLAG_RESERVED,
            "Must be zero", HFILL }},
        { &hf_icmpv6_opt_6co_valid_lifetime,
          { "Lifetime", "icmpv6.opt.6co.valid_lifetime", FT_UINT16, BASE_DEC, NULL, 0x00,
            "The length of time in a unit of 10 seconds that the context is valid for the purpose of header compression or decompression", HFILL }},
        { &hf_icmpv6_opt_6co_context_prefix,
          { "Context Prefix", "icmpv6.opt.6co.context_prefix", FT_IPv6, BASE_NONE, NULL, 0x00,
            "The IPv6 prefix or address corresponding to the Context ID (CID) field", HFILL }},
        { &hf_icmpv6_opt_abro_version,
          { "Version", "icmpv6.opt.abro.version", FT_UINT16, BASE_DEC, NULL, 0x00,
            "The version number corresponding to this set of information contained in the RA message", HFILL }},
        { &hf_icmpv6_opt_abro_6lbr_address,
          { "6LBR Address", "icmpv6.opt.abro.6lbr_address", FT_IPv6, BASE_NONE, NULL, 0x00,
            "IPv6 address of the 6LBR that is the origin of the included version number", HFILL }},
        /* RPL: draft-ietf-roll-rpl-12.txt: Routing over Low-Power and Lossy Networks. */
        { &hf_icmpv6_dis_reserved,
           { "Grounded",          "icmpv6.rpl.dis.reserved", FT_UINT16, BASE_DEC, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_dio_grounded,
           { "Grounded",          "icmpv6.rpl.dio.grounded", FT_BOOLEAN, 8, NULL, RPL_DIO_FLAG_GROUNDED,
             NULL, HFILL }},
        { &hf_icmpv6_dio_zero,
           { "Zero",              "icmpv6.rpl.dio.zero", FT_BOOLEAN, 8, NULL, RPL_DIO_FLAG_ZERO,
             NULL, HFILL }},
        { &hf_icmpv6_dio_mop,
           { "MOP",               "icmpv6.rpl.dio.mop", FT_UINT8, BASE_HEX, NULL, RPL_DIO_FLAG_MOP,
             NULL, HFILL }},
        { &hf_icmpv6_dio_preference,
           { "DAG Preference",    "icmpv6.rpl.dio.preference", FT_UINT8, BASE_DEC, NULL, RPL_DIO_FLAG_PREFERENCE,
             NULL, HFILL }},
        { &hf_icmpv6_dio_rank,
           { "Rank",              "icmpv6.rpl.dio.rank", FT_UINT16, BASE_DEC, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_dio_instance,
           { "RPLInstanceID",     "icmpv6.rpl.dio.instance", FT_UINT8, BASE_DEC, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_dio_version,
           { "version",           "icmpv6.rpl.dio.version", FT_UINT8, BASE_DEC, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_dio_trigger_seqnum,
           { "DTSN",              "icmpv6.rpl.dio.dtsn", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Destination advertisement trigger sequence number", HFILL }},
        { &hf_icmpv6_dao_instance,
           { "DAO Instance",      "icmpv6.rpl.dao.instance", FT_UINT8, BASE_DEC, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_dio_dagid,
           { "DODAGID",           "icmpv6.rpl.dio.dagid", FT_IPv6, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_dao_seqnum,
           { "DAO Sequence",      "icmpv6.rpl.dao.sequence", FT_UINT8, BASE_DEC, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_dao_reserved,
           { "Reserved",          "icmpv6.rpl.dao.reserved", FT_UINT8, BASE_DEC, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_dao_flag_k,
           { "DAO-ACK Request",   "icmpv6.rpl.dao.flag_k", FT_BOOLEAN, 8, NULL, RPL_DAO_FLAG_K,
             NULL, HFILL }},
        { &hf_icmpv6_dao_flag_d,
           { "DODAGID Present",   "icmpv6.rpl.dao.flag_d", FT_BOOLEAN, 8, NULL, RPL_DAO_FLAG_D,
             NULL, HFILL }},
        { &hf_icmpv6_dao_flag_rsv,
           { "Reserved",          "icmpv6.rpl.dao.flag_rsv", FT_UINT8, BASE_DEC, NULL, RPL_DAO_FLAG_RESERVED,
             NULL, HFILL }},
        { &hf_icmpv6_dao_dodagid,
           { "DODAGID",           "icmpv6.rpl.dao.dodagid", FT_IPv6, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_daoack_instance,
           { "Instance",          "icmpv6.rpl.daoack.instance", FT_UINT8, BASE_DEC, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_daoack_seqnum,
           { "DAO-ACK Sequence",  "icmpv6.rpl.daoack.sequence", FT_UINT8, BASE_DEC, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_daoack_status,
           { "Status",            "icmpv6.rpl.daoack.status", FT_UINT8, BASE_DEC, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_daoack_flag_d,
           { "DODAGID Present",   "icmpv6.rpl.daoack.flag_d", FT_BOOLEAN, 8, NULL, RPL_DAOACK_FLAG_D,
             NULL, HFILL }},
        { &hf_icmpv6_daoack_flag_rsv,
           { "Reserved",          "icmpv6.rpl.daoack.flag_rsv", FT_UINT8, BASE_DEC, NULL, RPL_DAOACK_FLAG_RESERVED,
             NULL, HFILL }},
        { &hf_icmpv6_daoack_dodagid,
           { "DODAGID",           "icmpv6.rpl.daoack.dodagid", FT_IPv6, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rpl_opt,
          { "ICMPv6 RPL Option",           "icmpv6.opt", FT_NONE,  BASE_NONE, NULL, 0x0,
            "Option", HFILL }},
        { &hf_icmpv6_rpl_opt_type,
          { "Type",           "icmpv6.rpl.opt.type", FT_UINT8,  BASE_DEC, VALS(rpl_option_vals), 0x0,
            "Options type", HFILL }},
        { &hf_icmpv6_rpl_opt_length,
          { "Length",         "icmpv6.rpl.opt.length", FT_UINT8,  BASE_DEC, NULL, 0x0,
            "The length of the option in octets excluding the Type and Length fields", HFILL }},
        { &hf_icmpv6_rpl_opt_reserved,
          { "Reserved", "icmpv6.rpl.opt.reserved", FT_NONE, BASE_NONE, NULL, 0x0,
            "Reserved (Must be 0)", HFILL }},
        { &hf_icmpv6_rpl_opt_padn,
          { "Paddn", "icmpv6.rpl.opt.padn", FT_NONE, BASE_NONE, NULL, 0x0,
            "Padding (Must be 0)", HFILL }},
        { &hf_icmpv6_rpl_opt_route_prefix_length,
           { "Prefix Length",      "icmpv6.rpl.opt.route.prefix_length", FT_UINT8, BASE_DEC, NULL, 0x0,
             "The number of leading bits in the Prefix that are valid", HFILL }},
        { &hf_icmpv6_rpl_opt_route_flag,
           { "Flag","icmpv6.rpl.opt.route.flag", FT_NONE, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rpl_opt_route_pref,
           { "Preference","icmpv6.rpl.opt.route.pref", FT_UINT8, BASE_DEC, VALS(names_router_pref), RPL_OPT_ROUTE_PREFERENCE,
             "The Route Preference indicates whether to prefer the router associated with this prefix over others, when multiple identical prefixes (for different routers) have been received", HFILL }},
        { &hf_icmpv6_rpl_opt_route_reserved,
           { "Reserved","icmpv6.rpl.opt.route.reserved", FT_UINT8, BASE_DEC, NULL, RPL_OPT_ROUTE_RESERVED,
             "Reserved (Must be Zero)", HFILL }},
        { &hf_icmpv6_rpl_opt_route_lifetime,
           { "Route Lifetime",    "icmpv6.rpl.opt.route.lifetime", FT_UINT32, BASE_DEC, NULL, 0x0,
             "The length of time in seconds (relative to the time the packet is sent) that the prefix is valid for route determination", HFILL }},
        { &hf_icmpv6_rpl_opt_route_prefix,
           { "Prefix",             "icmpv6.rpl.opt.route.prefix", FT_IPv6, BASE_NONE, NULL, 0x0,
             "Variable-length field containing an IP address or a prefix of an IPv6 address", HFILL }},
        { &hf_icmpv6_rpl_opt_config_flag,
           { "Flag","icmpv6.rpl.opt.config.flag", FT_NONE, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rpl_opt_config_reserved,
           { "Reserved","icmpv6.rpl.opt.config.reserved", FT_UINT8, BASE_DEC, NULL, RPL_OPT_CONFIG_FLAG_RESERVED,
             "Must be Zero", HFILL }},
        { &hf_icmpv6_rpl_opt_config_auth,
           { "Authentication Enabled","icmpv6.rpl.opt.config.auth", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RPL_OPT_CONFIG_FLAG_AUTH,
             "One bit flag describing the security mode of the network", HFILL }},
        { &hf_icmpv6_rpl_opt_config_pcs,
           { "Path Control Size",  "icmpv6.rpl.opt.config.pcs", FT_UINT8, BASE_DEC, NULL, RPL_OPT_CONFIG_FLAG_PCS,
             "Used to configure the number of bits that may be allocated to the Path Control field", HFILL }},
        { &hf_icmpv6_rpl_opt_config_doublings,
           { "DIOIntervalDoublings","icmpv6.rpl.opt.config.interval_double", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Used to configure Imax of the DIO trickle timer", HFILL }},
        { &hf_icmpv6_rpl_opt_config_min_interval,
           { "DIOIntervalMin",     "icmpv6.rpl.opt.config.interval_min", FT_UINT16, BASE_DEC, NULL, 0x0,
             "Used to configure Imin of the DIO trickle timer", HFILL }},
        { &hf_icmpv6_rpl_opt_config_redundancy,
           { "DIORedundancyConstant", "icmpv6.rpl.opt.config.redundancy", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Used to configure k of the DIO trickle timer", HFILL }},
        { &hf_icmpv6_rpl_opt_config_rank_incr,
           { "MaxRankInc",         "icmpv6.rpl.opt.config.max_rank_inc", FT_UINT16, BASE_DEC, NULL, 0x0,
             "Used to configure DAGMaxRankIncrease", HFILL }},
        { &hf_icmpv6_rpl_opt_config_hop_rank_inc,
           { "MinHopRankInc",      "icmpv6.rpl.opt.config.min_hop_rank_inc", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Used to configure MinHopRankIncrease", HFILL }},
        { &hf_icmpv6_rpl_opt_config_ocp,
           { "OCP (Objective Code Point)","icmpv6.rpl.opt.config.ocp", FT_UINT16, BASE_DEC, NULL, 0x0,
              "The OCP field identifies the OF and is managed by the IANA", HFILL }},
        { &hf_icmpv6_rpl_opt_config_rsv,
           { "Reserved",           "icmpv6.rpl.opt.config.rsv", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }},
        { &hf_icmpv6_rpl_opt_config_def_lifetime,
           { "Default Lifetime",   "icmpv6.rpl.opt.config.def_lifetime", FT_UINT8, BASE_DEC, NULL, 0x0,
              "This is the lifetime that is used as default for all RPL routes", HFILL }},
        { &hf_icmpv6_rpl_opt_config_lifetime_unit,
           { "Lifetime Unit",      "icmpv6.rpl.opt.config.lifetime_unit", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Provides the unit in seconds that is used to express route lifetimes in RPL", HFILL }},
        { &hf_icmpv6_rpl_opt_target_flag,
           { "Reserved",           "icmpv6.rpl.opt.target.flag", FT_NONE, BASE_NONE, NULL, 0x0,
              "Unused field reserved for flags", HFILL }},
        { &hf_icmpv6_rpl_opt_target_prefix_length,
           { "Target Length",      "icmpv6.rpl.opt.target.prefix_length", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Number of valid leading bits in the IPv6 Prefix", HFILL }},

        { &hf_icmpv6_rpl_opt_target_prefix,
           { "Target",             "icmpv6.rpl.opt.target.prefix", FT_IPv6, BASE_NONE, NULL, 0x0,
              "Identifying an IPv6 destination address, prefix, or multicast group", HFILL }},

        { &hf_icmpv6_rpl_opt_transit_flag,
           { "Flags",              "icmpv6.rpl.opt.transit.flag", FT_NONE, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
         { &hf_icmpv6_rpl_opt_transit_flag_e,
           { "External",           "icmpv6.rpl.opt.transit.flag.e", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RPL_OPT_TRANSIT_FLAG_E,
             "Indicate that the parent router redistributes external targets into the RPL network", HFILL }},
         { &hf_icmpv6_rpl_opt_transit_flag_rsv,
           { "Reserved",           "icmpv6.rpl.opt.transit.flag.rsv", FT_UINT8, BASE_DEC, NULL, RPL_OPT_TRANSIT_FLAG_RSV,
             "Must be Zero", HFILL }},
        { &hf_icmpv6_rpl_opt_transit_pathctl,
           { "Path Control",       "icmpv6.rpl.opt.transit.pathctl", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Limits the number of DAO-Parents to which a DAO message advertising connectivity", HFILL }},
        { &hf_icmpv6_rpl_opt_transit_pathseq,
           { "Path Sequence",      "icmpv6.rpl.opt.transit.pathseq", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Increments the Path Sequence each time it issues a RPL Target option with updated information", HFILL }},
        { &hf_icmpv6_rpl_opt_transit_pathlifetime,
           { "Path Lifetime",      "icmpv6.rpl.opt.transit.pathlifetime", FT_UINT8, BASE_DEC, NULL, 0x0,
              "The length of time in Lifetime Units that the prefix is valid for route determination", HFILL }},
        { &hf_icmpv6_rpl_opt_transit_parent,
           { "Parent Address",     "icmpv6.rpl.opt.transit.parent", FT_IPv6, BASE_NONE, NULL, 0x0,
              "IPv6 Address of the DODAG Parent of the node originally issuing the Transit Information Option", HFILL }},
        { &hf_icmpv6_rpl_opt_solicited_instance,
           { "Instance",           "icmpv6.rpl.opt.solicited.instance", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Containing the RPLInstanceID that is being solicited when valid", HFILL }},
        { &hf_icmpv6_rpl_opt_solicited_flag,
           { "Flag",  "icmpv6.rpl.opt.solicited.flag", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }},
        { &hf_icmpv6_rpl_opt_solicited_flag_v,
           { "Version predicate",  "icmpv6.rpl.opt.solicited.flag.v", FT_BOOLEAN, 8, TFS(&tfs_true_false), RPL_OPT_SOLICITED_FLAG_V,
              "The Version predicate is true if the receiver's DODAGVersionNumber matches the requested Version Number", HFILL }},
        { &hf_icmpv6_rpl_opt_solicited_flag_i,
           { "InstanceID predicate","icmpv6.rpl.opt.solicited.flag.i", FT_BOOLEAN, 8, TFS(&tfs_true_false), RPL_OPT_SOLICITED_FLAG_I,
              "The InstanceID predicate is true when the RPL node's current RPLInstanceID matches the requested RPLInstanceID", HFILL }},
        { &hf_icmpv6_rpl_opt_solicited_flag_d,
           { "DODAGID predicate",  "icmpv6.rpl.opt.solicited.flag.d", FT_BOOLEAN, 8, TFS(&tfs_true_false), RPL_OPT_SOLICITED_FLAG_D,
              "The DODAGID predicate is true if the RPL node's parent set has the same DODAGID as the DODAGID field", HFILL }},
         { &hf_icmpv6_rpl_opt_solicited_flag_rsv,
           { "Reserved",           "icmpv6.rpl.opt.solicited.flag.rsv", FT_UINT8, BASE_DEC, NULL, RPL_OPT_SOLICITED_FLAG_RSV,
             "Must be Zero", HFILL }},
        { &hf_icmpv6_rpl_opt_solicited_dodagid,
           { "DODAGID",            "icmpv6.rpl.opt.solicited.dodagid", FT_IPv6, BASE_NONE, NULL, 0x0,
              "the DODAGID that is being solicited when valid", HFILL }},
        { &hf_icmpv6_rpl_opt_solicited_version,
           { "Version",            "icmpv6.rpl.opt.solicited.version", FT_UINT8, BASE_DEC, NULL, 0x0,
              "the value of  DODAGVersionNumber that is being solicited when valid", HFILL }},

        { &hf_icmpv6_rpl_opt_prefix_length,
           { "Prefix Length",      "icmpv6.rpl.opt.prefix.length", FT_UINT8, BASE_DEC, NULL, 0x0,
             "The number of leading bits in the Prefix that are valid", HFILL }},
        { &hf_icmpv6_rpl_opt_prefix_flag,
           { "Flag",            "icmpv6.rpl.opt.prefix.flag", FT_NONE, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rpl_opt_prefix_flag_l,
           { "On Link",            "icmpv6.rpl.opt.prefix.flag.l", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RPL_OPT_PREFIX_FLAG_L,
             "When set, indicates that this prefix can be used for on-link determination", HFILL }},
        { &hf_icmpv6_rpl_opt_prefix_flag_a,
           { "Auto Address Config","icmpv6.rpl.opt.config.flag.a", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RPL_OPT_PREFIX_FLAG_A,
             "When set indicates that this prefix can be used for stateless address configuration", HFILL }},
        { &hf_icmpv6_rpl_opt_prefix_flag_r,
           { "Router Address",     "icmpv6.rpl.opt.config.flag.r", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RPL_OPT_PREFIX_FLAG_R,
             "When set, indicates that the Prefix field contains a complete IPv6 address assigned to the sending router that can be used as parent in a target option", HFILL }},
        { &hf_icmpv6_rpl_opt_prefix_flag_rsv,
           { "Reserved",     "icmpv6.rpl.opt.config.flag.rsv", FT_UINT8, BASE_DEC, NULL, RPL_OPT_PREFIX_FLAG_RSV,
             "Must Be Zero", HFILL }},
        { &hf_icmpv6_rpl_opt_prefix_vlifetime,
           { "Valid Lifetime",    "icmpv6.rpl.opt.prefix.valid_lifetime", FT_UINT32, BASE_DEC, NULL, 0x0,
             "The length of time in seconds that the prefix is valid for the purpose of on-link determination", HFILL }},
        { &hf_icmpv6_rpl_opt_prefix_plifetime,
           { "Preferred Lifetime", "icmpv6.rpl.opt.prefix.preferred_lifetime", FT_UINT32, BASE_DEC, NULL, 0x0,
             "The length of time in seconds that addresses generated from the prefix via stateless address autoconfiguration remain preferred", HFILL }},
        { &hf_icmpv6_rpl_opt_prefix,
           { "Destination Prefix", "icmpv6.rpl.opt.prefix", FT_IPv6, BASE_NONE, NULL, 0x0,
             "An IPv6 address or a prefix of an IPv6 address", HFILL }},
        { &hf_icmpv6_rpl_opt_targetdesc,
           { "Descriptor",         "icmpv6.rpl.opt.targetdesc.descriptor", FT_UINT32, BASE_HEX, NULL, 0x0,
             "Opaque Data", HFILL }},
        /* RFC 4620 IPv6 Node Information Queries */
        { &hf_icmpv6_ni_qtype,
           { "Qtype",         "icmpv6.ni.qtype", FT_UINT16, BASE_DEC, VALS(ni_qtype_val), 0x0,
             "Designates the type of information", HFILL }},
        { &hf_icmpv6_ni_flag,
           { "Flags",         "icmpv6.ni.flag", FT_UINT16, BASE_HEX, NULL, 0x0,
             "Qtype-specific flags that may be defined for certain Query types and their Replies", HFILL }},
        { &hf_icmpv6_ni_flag_g,
           { "Global-scope addresses",         "icmpv6.ni.flag.g", FT_BOOLEAN, 16, TFS(&tfs_set_notset), NI_FLAG_G,
             "Global-scope addresses are requested", HFILL }},
        { &hf_icmpv6_ni_flag_s,
           { "Site-local addresses",         "icmpv6.ni.flag.s", FT_BOOLEAN, 16, TFS(&tfs_set_notset), NI_FLAG_S,
             "Site-local addresses are requested", HFILL }},
        { &hf_icmpv6_ni_flag_l,
           { "Link-local addresses",         "icmpv6.ni.flag.l", FT_BOOLEAN, 16, TFS(&tfs_set_notset), NI_FLAG_L,
             "Link-local addresses are requested", HFILL }},
        { &hf_icmpv6_ni_flag_c,
           { "Compression",         "icmpv6.ni.flag.c", FT_BOOLEAN, 16, TFS(&tfs_set_notset), NI_FLAG_C,
             "IPv4-compatible (now deprecated) and IPv4-mapped addresses are requested", HFILL }},
        { &hf_icmpv6_ni_flag_a,
           { "Unicast Addresses",         "icmpv6.ni.flag.a", FT_BOOLEAN, 16, TFS(&tfs_ni_flag_a), NI_FLAG_A,
             "Responder's unicast addresses", HFILL }},
        { &hf_icmpv6_ni_flag_t,
           { "Truncated",         "icmpv6.ni.flag.t", FT_BOOLEAN, 16, TFS(&tfs_set_notset), NI_FLAG_T,
             "Defined in a Reply only, indicates that the set of addresses is incomplete for space reasons", HFILL }},
        { &hf_icmpv6_ni_flag_rsv,
           { "Reserved",         "icmpv6.ni.flag.rsv", FT_UINT16, BASE_HEX, NULL, NI_FLAG_RSV,
             "Must be Zero", HFILL }},
        { &hf_icmpv6_ni_nonce,
           { "Nonce",         "icmpv6.ni.nonce", FT_UINT64, BASE_HEX, NULL, 0x0,
             "An opaque 64-bit field", HFILL }},
        { &hf_icmpv6_ni_query_subject_ipv6,
           { "IPv6 subject address",         "icmpv6.ni.query.subject_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_ni_query_subject_fqdn,
           { "FQDN subject",         "icmpv6.ni.query.subject_fqdn", FT_STRING, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_ni_query_subject_ipv4,
           { "IPv4 subject address",         "icmpv6.ni.query.subject_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_ni_reply_node_ttl,
           { "TTL",         "icmpv6.ni.query.subject_ipv4", FT_UINT32, BASE_DEC, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_ni_reply_node_name,
           { "Name Node",         "icmpv6.ni.query.node_name", FT_STRING, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_ni_reply_node_address,
           { "IPv6 Node address",         "icmpv6.ni.query.node_address", FT_IPv6, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_ni_reply_ipv4_address,
           { "IPv4 Node address",         "icmpv6.ni.query.ipv4_address", FT_IPv4, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},

        /* RFC 2894: Router Renumbering for IPv6 */
        { &hf_icmpv6_rr_sequencenumber,
           { "Sequence Number",         "icmpv6.rr.sequence_number", FT_UINT32, BASE_DEC, NULL, 0x0,
             "The sequence number MUST be non-decreasing between Sequence Number Resets", HFILL }},
        { &hf_icmpv6_rr_segmentnumber,
           { "Segment Number",         "icmpv6.rr.segment_number", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Enumerates different valid RR messages having the same Sequence Number", HFILL }},
        { &hf_icmpv6_rr_flag,
           { "Flags",         "icmpv6.rr.flag", FT_UINT8, BASE_HEX, NULL, 0x0,
             "Five are defined and three bits are reserved", HFILL }},
        { &hf_icmpv6_rr_flag_t,
           { "Test Command",         "icmpv6.rr.flag.t", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RR_FLAG_T,
             "Indicates a Test message: processing is to be simulated and no configuration changes are to be made", HFILL }},
        { &hf_icmpv6_rr_flag_r,
           { "Result requested",         "icmpv6.rr.flag.r", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RR_FLAG_R,
             "Indicates that the router send a Result message upon completion of processing the Command message", HFILL }},
        { &hf_icmpv6_rr_flag_a,
           { "All Interfaces",         "icmpv6.rr.flag.a", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RR_FLAG_A,
             "Indicates that the Command be applied to all interfaces regardless of administrative shutdown status", HFILL }},
        { &hf_icmpv6_rr_flag_s,
           { "Site-specific",         "icmpv6.rr.flag.s", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RR_FLAG_S,
             "Indicates that the Command be applied only to interfaces which belong to the same site as the interface to which the Command is addressed", HFILL }},
        { &hf_icmpv6_rr_flag_p,
           { "Processed previously",         "icmpv6.rr.flag.p", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RR_FLAG_P,
             "Indicates that the Command message was previously processed (and is not a Test) and the responding router is not processing it again", HFILL }},
        { &hf_icmpv6_rr_flag_rsv,
           { "Reserved",         "icmpv6.rr.flag.rsv", FT_UINT8, BASE_DEC, NULL, RR_FLAG_RSV,
             "Must be Zero", HFILL }},
        { &hf_icmpv6_rr_maxdelay,
           { "Max Delay",         "icmpv6.rr.maxdelay", FT_UINT16, BASE_DEC, NULL, 0x0,
             "Specifying the maximum time (in milliseconds) by which a router MUST delay sending any reply to this Command", HFILL }},

        { &hf_icmpv6_rr_pco_mp_part,
           { "Match-Prefix Part",         "icmpv6.rr.pco.mp", FT_NONE, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rr_pco_mp_opcode,
           { "OpCode",         "icmpv6.rr.pco.mp.opcode", FT_UINT8, BASE_DEC, VALS(rr_pco_mp_opcode_val), 0x0,
             "Specifying the operation to be performed when the associated MatchPrefix matches an interface's prefix or address", HFILL }},
        { &hf_icmpv6_rr_pco_mp_oplength,
           { "OpLength",         "icmpv6.rr.pco.mp.oplength", FT_UINT8, BASE_DEC, NULL, 0x0,
             "The total length of this Prefix Control Operation (in units of 8 octets)", HFILL }},
        { &hf_icmpv6_rr_pco_mp_ordinal,
           { "Ordinal",         "icmpv6.rr.pco.mp.ordinal", FT_UINT8, BASE_HEX, NULL, 0x0,
             "The value is otherwise unconstrained", HFILL }},
        { &hf_icmpv6_rr_pco_mp_matchlen,
           { "MatchLen",         "icmpv6.rr.pco.mp.matchlen", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Between 0 and 128 inclusive specifying the number of initial bits of MatchPrefix which are significant in matching", HFILL }},
        { &hf_icmpv6_rr_pco_mp_minlen,
           { "MinLen",         "icmpv6.rr.pco.mp.minlen", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Specifying the minimum length which any configured prefix must have in order to be eligible for testing against the MatchPrefix", HFILL }},
        { &hf_icmpv6_rr_pco_mp_maxlen,
           { "MaxLen",         "icmpv6.rr.pco.mp.maxlen", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Specifying the maximum length which any configured prefix must have in order to be eligible for testing against the MatchPrefix", HFILL }},
        { &hf_icmpv6_rr_pco_mp_matchprefix,
           { "MatchPrefix",         "icmpv6.rr.pco.mp.matchprefix", FT_IPv6, BASE_NONE, NULL, 0x0,
             "The 128-bit prefix to be compared with each interface's prefix or address", HFILL }},
        { &hf_icmpv6_rr_pco_up_part,
           { "Use-Prefix Part",         "icmpv6.rr.pco.up", FT_NONE, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rr_pco_up_uselen,
           { "UseLen",         "icmpv6.rr.pco.up.uselen", FT_UINT8, BASE_DEC, NULL, 0x0,
             "specifying the number of initial bits of UsePrefix to use in creating a new prefix for an interface", HFILL }},
        { &hf_icmpv6_rr_pco_up_keeplen,
           { "KeepLen",         "icmpv6.rr.pco.up.keeplen", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Specifying the number of bits of the prefix or address which matched the associated Match-Prefix which should be retained in the new prefix", HFILL }},
        { &hf_icmpv6_rr_pco_up_flagmask,
           { "FlagMask",         "icmpv6.rr.pco.up.flagmask", FT_UINT8, BASE_HEX, NULL, 0x0,
             "A 1 bit in any position means that the corresponding flag bit in a Router Advertisement (RA) Prefix Information Option for the New Prefix should be set from the RAFlags field in this Use-Prefix Part", HFILL }},

	{ &hf_icmpv6_rr_pco_up_flagmask_l,
          { "On-link flag(L)", "icmpv6.rr.pco.up.flagmask.l", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
            "When set, indicates the On-link (L) flag bit in a Router Advertisement (RA) Prefix Information Option for the New Prefix should be set from the RAFlags field in this Use-Prefix Part", HFILL }},
	{ &hf_icmpv6_rr_pco_up_flagmask_a,
          { "Autonomous address-configuration flag(A)", "icmpv6.rr.pco.up.flagmask.a", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
            "When set, indicates the Autonomous address-configuration (A) flag bit in a Router Advertisement (RA) Prefix Information Option for the New Prefix should be set from the RAFlags field in this Use-Prefix Part", HFILL }},
	{ &hf_icmpv6_rr_pco_up_flagmask_reserved,
          { "Reserved", "icmpv6.rr.pco.up.flagmask.reserved", FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }},
        { &hf_icmpv6_rr_pco_up_raflags,
           { "RAFlags",         "icmpv6.rr.pco.up.raflags", FT_UINT8, BASE_HEX, NULL, 0x0,
             "Under control of the FlagMask field, may be used to initialize the flags in Router Advertisement Prefix Information Options  which advertise the New Prefix", HFILL }},
	{ &hf_icmpv6_rr_pco_up_raflags_l,
          { "On-link flag(L)", "icmpv6.rr.pco.up.flagmask.l", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
            "When set, indicates that this prefix can be used for on-link determination", HFILL }},
	{ &hf_icmpv6_rr_pco_up_raflags_a,
          { "Autonomous address-configuration flag(A)", "icmpv6.rr.pco.up.flagmask.a", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
            "When set indicates that this prefix can be used for stateless address configuration", HFILL }},
	{ &hf_icmpv6_rr_pco_up_raflags_reserved,
          { "Reserved", "icmpv6.rr.pco.up.flagmask.reserved", FT_UINT8, BASE_DEC, NULL, 0x3f,
            NULL, HFILL }},
        { &hf_icmpv6_rr_pco_up_validlifetime,
           { "Valid Lifetime",         "icmpv6.rr.pco.up.validlifetime", FT_UINT32, BASE_DEC, NULL, 0x0,
             "The number of seconds for which the New Prefix will be valid", HFILL }},
        { &hf_icmpv6_rr_pco_up_preferredlifetime,
           { "Preferred Lifetime",         "icmpv6.rr.pco.up.preferredlifetime", FT_UINT32, BASE_DEC, NULL, 0x0,
             "The number of seconds for which the New Prefix will be preferred", HFILL }},
        { &hf_icmpv6_rr_pco_up_flag,
           { "Flags",         "icmpv6.rr.pco.up.flag", FT_UINT32, BASE_HEX, NULL, 0x0,
             NULL, HFILL }},
	{ &hf_icmpv6_rr_pco_up_flag_v,
          { "Decrement valid lifetime", "icmpv6.rr.pco.up.flag.v", FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x80000000,
            "When set, indicating that the valid lifetime of the New Prefix MUST be effectively decremented in real time", HFILL }},
	{ &hf_icmpv6_rr_pco_up_flag_p,
          { "Decrement preferred lifetime", "icmpv6.rr.pco.up.flag.p", FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x40000000,
            "When set, indicating that the preferred lifetime of the New Prefix MUST be effectively decremented in real time", HFILL }},
	{ &hf_icmpv6_rr_pco_up_flag_reserved,
          { "Reserved", "icmpv6.rr.pco.up.flag.reserved", FT_UINT32, BASE_DEC, NULL, 0x3FFFFFFF,
            NULL, HFILL }},
        { &hf_icmpv6_rr_pco_up_useprefix,
           { "UsePrefix",         "icmpv6.rr.pco.up.useprefix", FT_IPv6, BASE_NONE, NULL, 0x0,
             "The 128-bit Use-prefix which either becomes or is used in forming (if KeepLen is nonzero) the New Prefix", HFILL }},
        { &hf_icmpv6_rr_rm,
           { "Result Message",         "icmpv6.rr.rm", FT_NONE, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rr_rm_flag,
           { "Flags",         "icmpv6.rr.rm.flag", FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }},
	{ &hf_icmpv6_rr_rm_flag_b,
          { "Bounds", "icmpv6.rr.rm.flag.b", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0002,
            "When set, indicates that one or more fields in the associated PCO were out of bounds", HFILL }},
	{ &hf_icmpv6_rr_rm_flag_f,
          { "Forbidden", "icmpv6.rr.rm.flag.f", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0001,
            "When set, indicates that one or more Use-Prefix parts from the associated PCO were not honored by the router because of attempted formation of a forbidden prefix format, such as a multicast or loopback address", HFILL }},
	{ &hf_icmpv6_rr_rm_flag_reserved,
          { "Reserved", "icmpv6.rr.rm.flag.reserved", FT_UINT16, BASE_DEC, NULL, 0xFFFD,
            "Must be Zero", HFILL }},
        { &hf_icmpv6_rr_rm_ordinal,
           { "Ordinal",         "icmpv6.rr.rm.ordinal", FT_UINT8, BASE_HEX, NULL, 0x0,
             "The value is otherwise unconstrained", HFILL }},
        { &hf_icmpv6_rr_rm_matchedlen,
           { "MatchedLen",         "icmpv6.rr.rm.matchedlen", FT_UINT8, BASE_DEC, NULL, 0x0,
             "The length of the Matched Prefix", HFILL }},
        { &hf_icmpv6_rr_rm_interfaceindex,
           { "InterfaceIndex",         "icmpv6.rr.rm.interfaceindex", FT_UINT32, BASE_DEC, NULL, 0x0,
             "The router's numeric designation of the interface on which the MatchedPrefix was configured", HFILL }},
        { &hf_icmpv6_rr_rm_matchedprefix,
           { "MatchedPrefix",         "icmpv6.rr.rm.matchedprefix", FT_IPv6, BASE_NONE, NULL, 0x0,
             "The 128 Bits MatchedPrefix", HFILL }},
    };

    static gint *ett[] = {
        &ett_icmpv6,
        &ett_icmpv6opt,
        &ett_icmpv6flag,
        &ett_multicastRR,
        &ett_icmpv6opt_name,
        &ett_cga_param_name,
        &ett_dao_rr_stack
    };

    proto_icmpv6 = proto_register_protocol("Internet Control Message Protocol v6",
                                           "ICMPv6", "icmpv6");
    proto_register_field_array(proto_icmpv6, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("icmpv6", dissect_icmpv6, proto_icmpv6);
}

void
proto_reg_handoff_icmpv6(void)
{
    dissector_handle_t icmpv6_handle;

    icmpv6_handle = create_dissector_handle(dissect_icmpv6, proto_icmpv6);
    dissector_add_uint("ip.proto", IP_PROTO_ICMPV6, icmpv6_handle);

    /*
     * Get a handle for the IPv6 dissector.
     */
    ipv6_handle = find_dissector("ipv6");
    data_handle = find_dissector("data");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab
 * :indentSize=4:tabSize=8:noTabs=true:
 */
