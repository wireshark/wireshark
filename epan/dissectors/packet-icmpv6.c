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
 * Enhance ICMPv6 dissector by Alexis La Goutte
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
#include <epan/conversation.h>
#include <epan/emem.h>
#include <epan/tap.h>

#include "packet-ber.h"
#include "packet-dns.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-icmp.h"    /* same transaction_t used both both v4 and v6 */

/*
 * The information used comes from:
 * RFC 1885/2463/4443: Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification
 * RFC 2461/4861: Neighbor Discovery for IP Version 6 (IPv6)
 * RFC 2491: IPv6 over Non-Broadcast Multiple Access (NBMA) networks
 * RFC 2710: Multicast Listener Discovery for IPv6
 * RFC 2894: Router Renumbering for IPv6
 * RFC 3122: Extensions to IPv6 Neighbor Discovery for Inverse Discovery Specification
 * RFC 3775/6275: Mobility Support in IPv6
 * RFC 3810: Multicast Listener Discovery Version 2 (MLDv2) for IPv6
 * RFC 3971: SEcure Neighbor Discovery (SEND)
 * RFC 4065: Instructions for Seamoby and Experimental Mobility Protocol IANA Allocations
 * RFC 4068/5268/5568: Fast Handovers for Mobile IPv6 (Mobile IPv6 Fast Handovers)
 * RFC 4140/5380: Hierarchical Mobile IPv6 Mobility Management (HMIPv6)
 * RFC 4191: Default Router Preferences and More-Specific Routes
 * RFC 4286: Multicast Router Discovery
 * RFC 4620: IPv6 Node Information Queries
 * RFC 5006/6106: IPv6 Router Advertisement Options for DNS Configuration
 * RFC 5075/5175: IPv6 Router Advertisement Flags Option
 * RFC 5269: Distributing a Symmetric Fast Mobile IPv6 (FMIPv6) Handover Key Using SEcure Neighbor Discovery (SEND)
 * RFC 5271: Mobile IPv6 Fast Handovers for 3G CDMA Networks
 * RFC 6275: Mobility Support in IPv6
 * draft-ieft-roll-rpl-19.txt: RPL: IPv6 Routing Protocol for Low power and Lossy Networks
 * draft-ietf-csi-proxy-send-05: Secure Proxy ND Support for SEND
 * draft-ietf-6lowpan-nd-18: Neighbor Discovery Optimization for Low Power and Lossy Networks (6LoWPAN)
 * http://www.iana.org/assignments/icmpv6-parameters (last updated 2011-04-08)
 */

static int proto_icmpv6 = -1;
static int hf_icmpv6_type = -1;
static int hf_icmpv6_code = -1;
static int hf_icmpv6_checksum = -1;
static int hf_icmpv6_checksum_bad = -1;
static int hf_icmpv6_reserved = -1;
static int hf_icmpv6_data = -1;
static int hf_icmpv6_unknown_data = -1;
static int hf_icmpv6_mtu = -1;
static int hf_icmpv6_pointer = -1;
static int hf_icmpv6_echo_identifier = -1;
static int hf_icmpv6_echo_sequence_number = -1;
static int hf_icmpv6_nonce = -1;

/* RFC 2461/4861 : Neighbor Discovery for IP version 6 (IPv6) */
static int hf_icmpv6_nd_ra_cur_hop_limit = -1;
static int hf_icmpv6_nd_ra_flag = -1;
static int hf_icmpv6_nd_ra_flag_m = -1;
static int hf_icmpv6_nd_ra_flag_o = -1;
static int hf_icmpv6_nd_ra_flag_h = -1;
static int hf_icmpv6_nd_ra_flag_prf = -1;
static int hf_icmpv6_nd_ra_flag_p = -1;
static int hf_icmpv6_nd_ra_flag_rsv = -1;
static int hf_icmpv6_nd_ra_router_lifetime = -1;
static int hf_icmpv6_nd_ra_reachable_time = -1;
static int hf_icmpv6_nd_ra_retrans_timer = -1;
static int hf_icmpv6_nd_ns_target_address = -1;
static int hf_icmpv6_nd_na_flag = -1;
static int hf_icmpv6_nd_na_flag_r = -1;
static int hf_icmpv6_nd_na_flag_s = -1;
static int hf_icmpv6_nd_na_flag_o = -1;
static int hf_icmpv6_nd_na_flag_rsv = -1;
static int hf_icmpv6_nd_na_target_address = -1;
static int hf_icmpv6_nd_rd_target_address = -1;
static int hf_icmpv6_nd_rd_destination_address = -1;

/* ND Options */
static int hf_icmpv6_opt = -1;
static int hf_icmpv6_opt_type = -1;
static int hf_icmpv6_opt_length = -1;
static int hf_icmpv6_opt_linkaddr_mac = -1;
static int hf_icmpv6_opt_src_linkaddr_mac = -1;
static int hf_icmpv6_opt_target_linkaddr_mac = -1;
static int hf_icmpv6_opt_linkaddr = -1;
static int hf_icmpv6_opt_src_linkaddr = -1;
static int hf_icmpv6_opt_target_linkaddr = -1;
static int hf_icmpv6_opt_linkaddr_eui64 = -1;
static int hf_icmpv6_opt_src_linkaddr_eui64 = -1;
static int hf_icmpv6_opt_target_linkaddr_eui64 = -1;
static int hf_icmpv6_opt_prefix_len = -1;
static int hf_icmpv6_opt_prefix_flag = -1;
static int hf_icmpv6_opt_prefix_flag_l = -1;
static int hf_icmpv6_opt_prefix_flag_a = -1;
static int hf_icmpv6_opt_prefix_flag_r = -1;
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
static int hf_icmpv6_opt_ps_key_hash = -1;
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


/* RFC 2710: Multicast Listener Discovery for IPv6 */
static int hf_icmpv6_mld_mrd = -1;
static int hf_icmpv6_mld_multicast_address = -1;

/* RFC 2894: Router Renumbering for IPv6 */
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

/* RFC 3810: Multicast Listener Discovery Version 2 (MLDv2) for IPv6 */
static int hf_icmpv6_mld_mrc = -1;
static int hf_icmpv6_mld_flag = -1;
static int hf_icmpv6_mld_flag_s = -1;
static int hf_icmpv6_mld_flag_qrv = -1;
static int hf_icmpv6_mld_flag_rsv = -1;
static int hf_icmpv6_mld_qqi = -1;
static int hf_icmpv6_mld_nb_sources = -1;
static int hf_icmpv6_mld_source_address = -1;
static int hf_icmpv6_mldr_nb_mcast_records = -1;
static int hf_icmpv6_mldr_mar = -1;
static int hf_icmpv6_mldr_mar_record_type = -1;
static int hf_icmpv6_mldr_mar_aux_data_len = -1;
static int hf_icmpv6_mldr_mar_nb_sources = -1;
static int hf_icmpv6_mldr_mar_multicast_address = -1;
static int hf_icmpv6_mldr_mar_source_address = -1;
static int hf_icmpv6_mldr_mar_auxiliary_data = -1;

/* RFC3775/6275: Mobility Support in IPv6 */
static int hf_icmpv6_mip6_identifier = -1;
static int hf_icmpv6_mip6_home_agent_address = -1;
static int hf_icmpv6_mip6_flag = -1;
static int hf_icmpv6_mip6_flag_m = -1;
static int hf_icmpv6_mip6_flag_o = -1;
static int hf_icmpv6_mip6_flag_rsv = -1;

/* RFC3971: SEcure Neighbor Discovery (SEND) */
static int hf_icmpv6_send_identifier = -1;
static int hf_icmpv6_send_all_components = -1;
static int hf_icmpv6_send_component = -1;

/* RFC 4068/5268/5568: Fast Handovers for Mobile IPv6 ( Mobile IPv6 Fast Handovers ) */
static int hf_icmpv6_fmip6_subtype = -1;
static int hf_icmpv6_fmip6_hi_flag = -1;
static int hf_icmpv6_fmip6_hi_flag_s = -1;
static int hf_icmpv6_fmip6_hi_flag_u = -1;
static int hf_icmpv6_fmip6_hi_flag_reserved = -1;
static int hf_icmpv6_fmip6_identifier = -1;

/* RFC 4286: Multicast Router Discovery */
static int hf_icmpv6_mcast_ra_query_interval = -1;
static int hf_icmpv6_mcast_ra_robustness_variable = -1;

/* RFC 4620: IPv6 Node Information Queries */
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

/* RPL: draft-ietf-roll-rpl-19.txt: Routing over Low-Power and Lossy Networks. */
static int hf_icmpv6_rpl_dis_flag = -1;
static int hf_icmpv6_rpl_dio_instance = -1;
static int hf_icmpv6_rpl_dio_version = -1;
static int hf_icmpv6_rpl_dio_rank = -1;
static int hf_icmpv6_rpl_dio_flag = -1;
static int hf_icmpv6_rpl_dio_flag_g = -1;
static int hf_icmpv6_rpl_dio_flag_0 = -1;
static int hf_icmpv6_rpl_dio_flag_mop = -1;
static int hf_icmpv6_rpl_dio_flag_prf = -1;
static int hf_icmpv6_rpl_dio_dtsn = -1;
static int hf_icmpv6_rpl_dio_dagid = -1;
static int hf_icmpv6_rpl_dao_instance = -1;
static int hf_icmpv6_rpl_dao_flag = -1;
static int hf_icmpv6_rpl_dao_flag_k = -1;
static int hf_icmpv6_rpl_dao_flag_d = -1;
static int hf_icmpv6_rpl_dao_flag_rsv = -1;
static int hf_icmpv6_rpl_dao_sequence = -1;
static int hf_icmpv6_rpl_dao_dodagid = -1;
static int hf_icmpv6_rpl_daoack_instance = -1;
static int hf_icmpv6_rpl_daoack_flag = -1;
static int hf_icmpv6_rpl_daoack_flag_d = -1;
static int hf_icmpv6_rpl_daoack_flag_rsv = -1;
static int hf_icmpv6_rpl_daoack_sequence = -1;
static int hf_icmpv6_rpl_daoack_status = -1;
static int hf_icmpv6_rpl_daoack_dodagid = -1;
static int hf_icmpv6_rpl_cc_instance = -1;
static int hf_icmpv6_rpl_cc_flag = -1;
static int hf_icmpv6_rpl_cc_flag_r = -1;
static int hf_icmpv6_rpl_cc_flag_rsv = -1;
static int hf_icmpv6_rpl_cc_nonce = -1;
static int hf_icmpv6_rpl_cc_dodagid = -1;
static int hf_icmpv6_rpl_cc_destination_counter = -1;
static int hf_icmpv6_rpl_secure_flag = -1;
static int hf_icmpv6_rpl_secure_flag_t = -1;
static int hf_icmpv6_rpl_secure_flag_rsv = -1;
static int hf_icmpv6_rpl_secure_algorithm = -1;
static int hf_icmpv6_rpl_secure_algorithm_encryption = -1;
static int hf_icmpv6_rpl_secure_algorithm_signature = -1;
static int hf_icmpv6_rpl_secure_kim = -1;
static int hf_icmpv6_rpl_secure_lvl = -1;
static int hf_icmpv6_rpl_secure_rsv = -1;
static int hf_icmpv6_rpl_secure_counter = -1;
static int hf_icmpv6_rpl_secure_key_source = -1;
static int hf_icmpv6_rpl_secure_key_index = -1;
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

static int hf_icmpv6_da_status = -1;
static int hf_icmpv6_da_rsv = -1;
static int hf_icmpv6_da_lifetime = -1;
static int hf_icmpv6_da_eui64 = -1;
static int hf_icmpv6_da_raddr = -1;

static int icmpv6_tap = -1;

/* Conversation related data */
static int hf_icmpv6_resp_in = -1;
static int hf_icmpv6_resp_to = -1;
static int hf_icmpv6_resptime = -1;

typedef struct _icmpv6_conv_info_t {
    emem_tree_t *pdus;
} icmpv6_conv_info_t;

static icmp_transaction_t *transaction_start(packet_info *pinfo, proto_tree *tree, guint32 *key);
static icmp_transaction_t *transaction_end(packet_info *pinfo, proto_tree *tree, guint32 *key);

static gint ett_icmpv6 = -1;
static gint ett_icmpv6_opt = -1;
static gint ett_icmpv6_mar = -1;
static gint ett_icmpv6_flag_prefix = -1;
static gint ett_icmpv6_flag_map = -1;
static gint ett_icmpv6_flag_route_info = -1;
static gint ett_icmpv6_flag_6lowpan = -1;
static gint ett_icmpv6_flag_efo = -1;
static gint ett_icmpv6_rpl_opt = -1;
static gint ett_icmpv6_rpl_flag_routing = -1;
static gint ett_icmpv6_rpl_flag_config = -1;
static gint ett_icmpv6_rpl_flag_transit = -1;
static gint ett_icmpv6_rpl_flag_solicited = -1;
static gint ett_icmpv6_rpl_flag_prefix = -1;
static gint ett_icmpv6_flag_ni = -1;
static gint ett_icmpv6_flag_rr = -1;
static gint ett_icmpv6_rr_mp = -1;
static gint ett_icmpv6_rr_up = -1;
static gint ett_icmpv6_rr_up_flag_mask = -1;
static gint ett_icmpv6_rr_up_flag_ra = -1;
static gint ett_icmpv6_rr_up_flag = -1;
static gint ett_icmpv6_rr_rm = -1;
static gint ett_icmpv6_rr_rm_flag = -1;
static gint ett_icmpv6_flag_mld = -1;
static gint ett_icmpv6_flag_ra = -1;
static gint ett_icmpv6_flag_na = -1;
static gint ett_icmpv6_flag_mip6 = -1;
static gint ett_icmpv6_flag_fmip6 = -1;
static gint ett_icmpv6_flag_secure = -1;
static gint ett_icmpv6_flag_rpl_dio = -1;
static gint ett_icmpv6_flag_rpl_dao = -1;
static gint ett_icmpv6_flag_rpl_daoack = -1;
static gint ett_icmpv6_flag_rpl_cc = -1;
static gint ett_icmpv6_opt_name = -1;
static gint ett_icmpv6_cga_param_name = -1;

static dissector_handle_t ipv6_handle;
static dissector_handle_t data_handle;

#define ICMP6_DST_UNREACH                 1
#define ICMP6_PACKET_TOO_BIG              2
#define ICMP6_TIME_EXCEEDED               3
#define ICMP6_PARAM_PROB                  4
#define ICMP6_ECHO_REQUEST              128
#define ICMP6_ECHO_REPLY                129
#define ICMP6_MEMBERSHIP_QUERY          130
#define ICMP6_MEMBERSHIP_REPORT         131
#define ICMP6_MEMBERSHIP_REDUCTION      132
#define ICMP6_ND_ROUTER_SOLICIT         133
#define ICMP6_ND_ROUTER_ADVERT          134
#define ICMP6_ND_NEIGHBOR_SOLICIT       135
#define ICMP6_ND_NEIGHBOR_ADVERT        136
#define ICMP6_ND_REDIRECT               137
#define ICMP6_ROUTER_RENUMBERING        138
#define ICMP6_NI_QUERY                  139
#define ICMP6_NI_REPLY                  140
#define ICMP6_IND_SOLICIT               141
#define ICMP6_IND_ADVERT                142
#define ICMP6_MLDV2_REPORT              143
#define ICMP6_MIP6_DHAAD_REQUEST        144
#define ICMP6_MIP6_DHAAD_REPLY          145
#define ICMP6_MIP6_MPS                  146
#define ICMP6_MIP6_MPA                  147
#define ICMP6_CERT_PATH_SOL             148
#define ICMP6_CERT_PATH_AD              149
#define ICMP6_EXPERIMENTAL_MOBILITY     150
#define ICMP6_MCAST_ROUTER_ADVERT       151
#define ICMP6_MCAST_ROUTER_SOLICIT      152
#define ICMP6_MCAST_ROUTER_TERM         153
#define ICMP6_FMIPV6_MESSAGES           154
#define ICMP6_RPL_CONTROL               155
#define ICMP6_6LOWPANND_DAR             156 /* Pending IANA assignment */
#define ICMP6_6LOWPANND_DAC             157 /* Pending IANA assignment */


static const value_string icmpv6_type_val[] = {
    { ICMP6_DST_UNREACH,           "Destination Unreachable" },                         /* [RFC4443] */
    { ICMP6_PACKET_TOO_BIG,        "Packet Too Big" },                                  /* [RFC4443] */
    { ICMP6_TIME_EXCEEDED,         "Time Exceeded" },                                   /* [RFC4443] */
    { ICMP6_PARAM_PROB,            "Parameter Problem" },                               /* [RFC4443] */
    { 100,                         "Private experimentation" },                         /* [RFC4443] */
    { 101,                         "Private experimentation" },                         /* [RFC4443] */
    { 127,                         "Reserved for expansion of ICMPv6 error messages" }, /* [RFC4443] */
    { ICMP6_ECHO_REQUEST,          "Echo (ping) request" },                             /* [RFC4443] */
    { ICMP6_ECHO_REPLY,            "Echo (ping) reply" },                               /* [RFC4443] */
    { ICMP6_MEMBERSHIP_QUERY,      "Multicast Listener Query" },                        /* [RFC2710] */
    { ICMP6_MEMBERSHIP_REPORT,     "Multicast Listener Report" },                       /* [RFC2710] */
    { ICMP6_MEMBERSHIP_REDUCTION,  "Multicast Listener Done" },                         /* [RFC2710] */
    { ICMP6_ND_ROUTER_SOLICIT,     "Router Solicitation" },                             /* [RFC4861] */
    { ICMP6_ND_ROUTER_ADVERT,      "Router Advertisement" },                            /* [RFC4861] */
    { ICMP6_ND_NEIGHBOR_SOLICIT,   "Neighbor Solicitation" },                           /* [RFC4861] */
    { ICMP6_ND_NEIGHBOR_ADVERT,    "Neighbor Advertisement" },                          /* [RFC4861] */
    { ICMP6_ND_REDIRECT,           "Redirect" },                                        /* [RFC4861] */
    { ICMP6_ROUTER_RENUMBERING,    "Router Renumbering" },                              /* [RFC2894] */
    { ICMP6_NI_QUERY,              "Node Information Query" },                          /* [RFC4620] */
    { ICMP6_NI_REPLY,              "Node Information Reply" },                          /* [RFC4620] */
    { ICMP6_IND_SOLICIT,           "Inverse Neighbor Discovery Solicitation" },         /* [RFC3122] */
    { ICMP6_IND_ADVERT,            "Inverse Neighbor Discovery Advertisement" },        /* [RFC3122] */
    { ICMP6_MLDV2_REPORT,          "Multicast Listener Report Message v2" },            /* [RFC3810] */
    { ICMP6_MIP6_DHAAD_REQUEST,    "Home Agent Address Discovery Request" },            /* [RFC6275] */
    { ICMP6_MIP6_DHAAD_REPLY,      "Home Agent Address Discovery Reply" },              /* [RFC6275] */
    { ICMP6_MIP6_MPS,              "Mobile Prefix Solicitation" },                      /* [RFC6275] */
    { ICMP6_MIP6_MPA,              "Mobile Prefix Advertisement" },                     /* [RFC6275] */
    { ICMP6_CERT_PATH_SOL,         "Certification Path Solicitation" },                 /* [RFC3971] */
    { ICMP6_CERT_PATH_AD,          "Certification Path Advertisement" },                /* [RFC3971] */
    { ICMP6_EXPERIMENTAL_MOBILITY, "Experimental Mobility" },                           /* [RFC4065] */
    { ICMP6_MCAST_ROUTER_ADVERT,   "Multicast Router Advertisement" },                  /* [RFC4286] */
    { ICMP6_MCAST_ROUTER_SOLICIT,  "Multicast Router Solicitation" },                   /* [RFC4286] */
    { ICMP6_MCAST_ROUTER_TERM,     "Multicast Router Termination" },                    /* [RFC4286] */
    { ICMP6_FMIPV6_MESSAGES,       "FMIPv6" },                                          /* [RFC5568] */
    { ICMP6_RPL_CONTROL,           "RPL Control" },                                     /* draft-ieft-roll-rpl-19.txt Pending IANA */
    { ICMP6_6LOWPANND_DAR,         "Duplicate Address Request"},                        /* draft-ietf-6lowpan-nd-18.txt Pending IANA */
    { ICMP6_6LOWPANND_DAC,         "Duplicate Address Confirmation"},                   /* draft-ietf-6lowpan-nd-18.txt Pending IANA */
    { 200,                         "Private experimentation" },                         /* [RFC4443] */
    { 201,                         "Private experimentation" },                         /* [RFC4443] */
    { 255,                         "Reserved for expansion of ICMPv6 informational messages" }, /* [RFC4443] */
    { 0, NULL }
};

#define ICMP6_DST_UNREACH_NOROUTE               0       /* no route to destination */
#define ICMP6_DST_UNREACH_ADMIN                 1       /* administratively prohibited */
#define ICMP6_DST_UNREACH_NOTNEIGHBOR           2       /* not a neighbor(obsolete) */
#define ICMP6_DST_UNREACH_BEYONDSCOPE           2       /* beyond scope of source address */
#define ICMP6_DST_UNREACH_ADDR                  3       /* address unreachable */
#define ICMP6_DST_UNREACH_NOPORT                4       /* port unreachable */
#define ICMP6_DST_UNREACH_INGR_EGR              5       /* source address failed ingress/egress policy */
#define ICMP6_DST_UNREACH_REJECT                6       /* reject route to destination */
#define ICMP6_DST_UNREACH_ERROR                 7       /* error in Source Routing Header */

static const value_string icmpv6_unreach_code_val[] = {
    { ICMP6_DST_UNREACH_NOROUTE,     "no route to destination" },
    { ICMP6_DST_UNREACH_ADMIN,       "Administratively prohibited" },
    { ICMP6_DST_UNREACH_BEYONDSCOPE, "Beyond scope of source address" },
    { ICMP6_DST_UNREACH_ADDR,        "Address unreachable" },
    { ICMP6_DST_UNREACH_NOPORT,      "Port unreachable" },
    { ICMP6_DST_UNREACH_INGR_EGR,    "Source address failed ingress/egress policy" },
    { ICMP6_DST_UNREACH_REJECT,      "Reject route to destination" },
    { ICMP6_DST_UNREACH_ERROR,       "Error in Source Routing Header" }, /* [draft-ieft-roll-rpl-19.txt] */
    { 0, NULL }
};

#define ICMP6_TIME_EXCEED_TRANSIT       0       /* ttl==0 in transit */
#define ICMP6_TIME_EXCEED_REASSEMBLY    1       /* ttl==0 in reass */

static const value_string icmpv6_timeex_code_val[] = {
    { ICMP6_TIME_EXCEED_TRANSIT,    "hop limit exceeded in transit" },
    { ICMP6_TIME_EXCEED_REASSEMBLY, "fragment reassembly time exceeded" },
    { 0, NULL }
};

#define ICMP6_PARAMPROB_HEADER                  0       /* erroneous header field */
#define ICMP6_PARAMPROB_NEXTHEADER              1       /* unrecognized next header */
#define ICMP6_PARAMPROB_OPTION                  2       /* unrecognized option */

static const value_string icmpv6_paramprob_code_val[] = {
    { ICMP6_PARAMPROB_HEADER,     "erroneous header field encountered" },
    { ICMP6_PARAMPROB_NEXTHEADER, "unrecognized Next Header type encountered" },
    { ICMP6_PARAMPROB_OPTION,     "unrecognized IPv6 option encountered" },
    { 0, NULL }
};


/* RFC2894 - Router Renumbering for IPv6 */

#define ICMP6_ROUTER_RENUMBERING_COMMAND          0     /* rr command */
#define ICMP6_ROUTER_RENUMBERING_RESULT           1     /* rr result */
#define ICMP6_ROUTER_RENUMBERING_SEQNUM_RESET   255     /* rr seq num reset */

static const value_string icmpv6_rr_code_val[] = {
    { ICMP6_ROUTER_RENUMBERING_COMMAND,      "Command" },
    { ICMP6_ROUTER_RENUMBERING_RESULT,       "Result" },
    { ICMP6_ROUTER_RENUMBERING_SEQNUM_RESET, "Sequence number reset" },
    { 0, NULL }
};

#define RR_FLAG_T       0x80
#define RR_FLAG_R       0x40
#define RR_FLAG_A       0x20
#define RR_FLAG_S       0x10
#define RR_FLAG_P       0x08
#define RR_FLAG_RSV     0x07

static const value_string rr_pco_mp_opcode_val[] = {
    { 1,    "Add" },
    { 2,    "Change" },
    { 3,    "Set Global" },
    { 0,    NULL }
};


/* RFC3810 - Multicast Listener Discovery Version 2 (MLDv2) for IPv6 */

#define MLDV2_PACKET_MINLEN 28

#define MLD_FLAG_S      0x08
#define MLD_FLAG_QRV    0x07
#define MLD_FLAG_RSV    0xF0

static const value_string mldr_record_type_val[] = {
    { 1, "Include" },
    { 2, "Exclude" },
    { 3, "Changed to include" },
    { 4, "Changed to exclude" },
    { 5, "Allow new sources" },
    { 6, "Block old sources" },
    { 0, NULL }
};

/* RFC 4068/5268/5568: Fast Handovers for Mobile IPv6 ( Mobile IPv6 Fast Handovers ) */

#define FMIP6_SUBTYPE_RTSOLPR   2
#define FMIP6_SUBTYPE_PRRTADV   3
#define FMIP6_SUBTYPE_HI        4
#define FMIP6_SUBTYPE_HACK      5

static const value_string fmip6_subtype_val[] = {
    { FMIP6_SUBTYPE_RTSOLPR,    "Router Solicitation for Proxy Advertisement" },
    { FMIP6_SUBTYPE_PRRTADV,    "Proxy Router Advertisement" },
    { FMIP6_SUBTYPE_HI,         "Handover Initiate" },
    { FMIP6_SUBTYPE_HACK,       "Handover Acknowledge" },
    { 0,                        NULL }
};

static const value_string fmip6_prrtadv_code_val[] = {
    { 0,   "MN should use AP-ID, AR-info tuple" },
    { 1,   "Network Initiated Handover trigger" },
    { 2,   "No new router information" },
    { 3,   "Limited new router information" },
    { 4,   "Unsolicited" },
    { 0,    NULL }
};

static const value_string fmip6_hi_code_val[] = {
    { 0,    "FBU sent from previous link" },
    { 1,    "FBU sent from new link" },
    { 0,    NULL }
};

static const value_string fmip6_hack_code_val[] = {
    { 0,    "Handover Accepted, NCoA valid" },
    { 1,    "Handover Accepted, NCoA not valid" },
    { 2,    "Handover Accepted, NCoA in use" },
    { 3,    "Handover Accepted, NCoA assigned" },
    { 4,    "Handover Accepted, NCoA not assigned" },
    { 128,  "Handover Not Accepted, reason unspecified" },
    { 129,  "Administratively prohibited" },
    { 130,  "Insufficient resources" },
    { 0,    NULL }
};

#define FMIP6_HI_FLAG_S     0x80
#define FMIP6_HI_FLAG_U     0x40
#define FMIP6_HI_FLAG_RSV   0x3F

/* RFC 4620 - IPv6 Node Information Queries */

#define ICMP6_NI_SUBJ_IPV6      0   /* Query Subject is an IPv6 address */
#define ICMP6_NI_SUBJ_FQDN      1   /* Query Subject is a Domain name */
#define ICMP6_NI_SUBJ_IPV4      2   /* Query Subject is an IPv4 address */

#define ICMP6_NI_SUCCESS        0   /* node information successful reply */
#define ICMP6_NI_REFUSED        1   /* node information request is refused */
#define ICMP6_NI_UNKNOWN        2   /* unknown Qtype */

#define NI_QTYPE_NOOP           0   /* NOOP  */
#define NI_QTYPE_SUPTYPES       1   /* Supported Qtypes (Obso) */
#define NI_QTYPE_NODENAME       2   /* Node Name */
#define NI_QTYPE_NODEADDR       3   /* Node Addresses */
#define NI_QTYPE_IPV4ADDR       4   /* IPv4 Addresses */

static const value_string ni_query_code_val[] = {
    { ICMP6_NI_SUBJ_IPV6,   "Query subject = IPv6 addresses" },
    { ICMP6_NI_SUBJ_FQDN,   "Query subject = DNS name or empty" },
    { ICMP6_NI_SUBJ_IPV4,   "Query subject = IPv4 addresses" },
    { 0, NULL }
};

static const value_string ni_reply_code_val[] = {
    { ICMP6_NI_SUCCESS,   "Successful" },
    { ICMP6_NI_REFUSED,   "Refused" },
    { ICMP6_NI_UNKNOWN,   "Unknown query type" },
    { 0, NULL }
};
static const value_string ni_qtype_val[] = {
    { NI_QTYPE_NOOP,            "NOOP" },
    { NI_QTYPE_SUPTYPES,        "Supported query types (Obsolete)" },
    { NI_QTYPE_NODENAME,        "Node Name" },
    { NI_QTYPE_NODEADDR,        "Node addresses" },
    { NI_QTYPE_IPV4ADDR,        "IPv4 node addresses" },
    { 0,                        NULL }
};

#define NI_FLAG_G       0x0020
#define NI_FLAG_S       0x0010
#define NI_FLAG_L       0x0008
#define NI_FLAG_C       0x0004
#define NI_FLAG_A       0x0002
#define NI_FLAG_T       0x0001
#define NI_FLAG_RSV     0xFFC0

static const true_false_string tfs_ni_flag_a = {
    "All unicast address",
    "Unicast addresses on the queried interface"
};

#define ND_OPT_SOURCE_LINKADDR           1
#define ND_OPT_TARGET_LINKADDR           2
#define ND_OPT_PREFIX_INFORMATION        3
#define ND_OPT_REDIRECTED_HEADER         4
#define ND_OPT_MTU                       5
#define ND_OPT_NBMA                      6
#define ND_OPT_ADVINTERVAL               7
#define ND_OPT_HOMEAGENT_INFO            8
#define ND_OPT_SOURCE_ADDRLIST           9
#define ND_OPT_TARGET_ADDRLIST          10
#define ND_OPT_CGA                      11
#define ND_OPT_RSA                      12
#define ND_OPT_TIMESTAMP                13
#define ND_OPT_NONCE                    14
#define ND_OPT_TRUST_ANCHOR             15
#define ND_OPT_CERTIFICATE              16
#define ND_OPT_IP_ADDRESS_PREFIX        17
#define ND_OPT_NEW_ROUTER_PREFIX_INFO   18
#define ND_OPT_LINK_LAYER_ADDRESS       19
#define ND_OPT_NEIGHBOR_ADV_ACK         20
#define ND_OPT_MAP                      23
#define ND_OPT_ROUTE_INFO               24
#define ND_OPT_RECURSIVE_DNS_SERVER     25
#define ND_OPT_FLAGS_EXTENSION          26
#define ND_OPT_HANDOVER_KEY_REQUEST     27
#define ND_OPT_HANDOVER_KEY_REPLY       28
#define ND_OPT_HANDOVER_ASSIST_INFO     29
#define ND_OPT_MOBILE_NODE_ID           30
#define ND_OPT_DNS_SEARCH_LIST          31
#define ND_OPT_PROXY_SIGNATURE          32
/* draft-6lowpan-nd types, pending IANA assignment */
#define ND_OPT_ADDR_REGISTRATION        131 /* Conflit with RFC6106.. */
#define ND_OPT_6LOWPAN_CONTEXT          132 /* Conflit with draft-ietf-csi-proxy-send-05.txt.. */
#define ND_OPT_AUTH_BORDER_ROUTER       33

static const value_string option_vals[] = {
/*  1 */   { ND_OPT_SOURCE_LINKADDR,           "Source link-layer address" },
/*  2 */   { ND_OPT_TARGET_LINKADDR,           "Target link-layer address" },
/*  3 */   { ND_OPT_PREFIX_INFORMATION,        "Prefix information" },
/*  4 */   { ND_OPT_REDIRECTED_HEADER,         "Redirected header" },
/*  5 */   { ND_OPT_MTU,                       "MTU" },
/*  6 */   { ND_OPT_NBMA,                      "NBMA Shortcut Limit Option" },             /* [RFC2491] */
/*  7 */   { ND_OPT_ADVINTERVAL,               "Advertisement Interval" },                 /* [RFC6275] */
/*  8 */   { ND_OPT_HOMEAGENT_INFO,            "Home Agent Information" },                 /* [RFC6275] */
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
/* 32 */   { ND_OPT_PROXY_SIGNATURE,           "Proxy Signature (PS)" },                   /* [draft-ietf-csi-proxy-send-05.txt] */
/* 31 */   { ND_OPT_ADDR_REGISTRATION,         "Address Registration Option" },            /* [draft-ietf-6lowpan-nd-18.txt] */
/* 32 */   { ND_OPT_6LOWPAN_CONTEXT,           "6LoWPAN Context Option" },                 /* [draft-ietf-6lowpan-nd-18.txt] */
/* 33 */   { ND_OPT_AUTH_BORDER_ROUTER,        "Authorative Border Router" },              /* [draft-ietf-6lowpan-nd-18.txt] */
/* 34-137  Unassigned */
   { 138,                              "CARD Request" },                           /* [RFC4065] */
   { 139,                              "CARD Reply" },                             /* [RFC4065] */
/* 140-252 Unassigned */
   { 253,                              "RFC3692-style Experiment 1" },             /* [RFC4727] */
   { 254,                              "RFC3692-style Experiment 2" },             /* [RFC4727] */
   { 0,                                NULL }
};

#define ND_RA_FLAG_M    0x80
#define ND_RA_FLAG_O    0x40
#define ND_RA_FLAG_H    0x20
#define ND_RA_FLAG_PRF  0x18
#define ND_RA_FLAG_P    0x04
#define ND_RA_FLAG_RSV  0x02

#define ND_NA_FLAG_R    0x80000000
#define ND_NA_FLAG_S    0x40000000
#define ND_NA_FLAG_O    0x20000000
#define ND_NA_FLAG_RSV  0x1FFFFFFF

static const value_string nd_flag_router_pref[] = {
    { 1, "High" },
    { 0, "Medium" },
    { 3, "Low" },
    { 2, "Reserved" },
    { 0, NULL}
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

#define ND_OPT_6CO_FLAG_C        0x10
#define ND_OPT_6CO_FLAG_CID      0x0F
#define ND_OPT_6CO_FLAG_RESERVED 0xE0

static const value_string nd_opt_6lowpannd_status_val[] = {
    { 0, "Success" },
    { 1, "Duplicate Exists" },
    { 2, "Neighbor Cache Full" },
    { 0, NULL }
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

/* RFC 4191: Default Router Preferences and More-Specific Routes  */

#define ND_RA_FLAG_RTPREF_MASK  0x18 /* 00011000 */
#define ND_RA_FLAG_RESERV_MASK  0xE7 /* 11100111 */

/* RFC 5075/5175 : IPv6 Router Advertisement Flags Option */
#define FLAGS_EO_M      0x8000
#define FLAGS_EO_O      0x4000
#define FLAGS_EO_H      0x2000
#define FLAGS_EO_PRF    0x1800
#define FLAGS_EO_P      0x0400
#define FLAGS_EO_RSV    0x02FF



/* RPL: draft-ietf-roll-rpl-19.txt: Routing over Low-Power and Lossy Networks. */
/* Pending IANA Assignment */
/* RPL ICMPv6 Codes */
#define ICMP6_RPL_DIS       0x00   /* DODAG Information Solicitation */
#define ICMP6_RPL_DIO       0x01   /* DODAG Information Object */
#define ICMP6_RPL_DAO       0x02   /* Destination Advertisement Object */
#define ICMP6_RPL_DAOACK    0x03   /* Destination Advertisement Object Ack */
#define ICMP6_RPL_SDIS      0x80   /* Secure DODAG Information Solicitation */
#define ICMP6_RPL_SDIO      0x81   /* Secure DODAG Information Object */
#define ICMP6_RPL_SDAO      0x82   /* Secure Destination Advertisement Object */
#define ICMP6_RPL_SDAOACK   0x83   /* Secure Destination Advertisement Object Ack */
#define ICMP6_RPL_CC        0x8A   /* Consistency Check */


/* RPL DIO Flags */
#define RPL_DIO_FLAG_G           0x80
#define RPL_DIO_FLAG_0           0x40
#define RPL_DIO_FLAG_MOP         0x38
#define RPL_DIO_FLAG_PRF         0x07

/* RPL DAO Flags */
#define RPL_DAO_FLAG_K                  0x80
#define RPL_DAO_FLAG_D                  0x40
#define RPL_DAO_FLAG_RESERVED           0x3F

/* RPL DAO ACK Flags */
#define RPL_DAOACK_FLAG_D               0x80
#define RPL_DAOACK_FLAG_RESERVED        0x7F

/* RPL CC Flags */
#define RPL_CC_FLAG_R               0x80
#define RPL_CC_FLAG_RESERVED        0x7F

/* RPL Secure */
#define ICMP6_RPL_SECURE    0x80

#define RPL_SECURE_FLAG_T   0x80
#define RPL_SECURE_FLAG_RSV 0x7F

#define RPL_SECURE_LVL      0x07
#define RPL_SECURE_KIM      0xC0
#define RPL_SECURE_RSV      0x38

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

static const value_string rpl_dio_map_val[] = {
    { 0, "No downward routes maintained by RPL" },
    { 1, "Non storing mode" },
    { 2, "Storing without multicast support" },
    { 3, "Storing with multicast support" },
    { 0, NULL }
};
static const value_string rpl_code_val[] = {
    { ICMP6_RPL_DIS,    "DODAG Information Solicitation" },
    { ICMP6_RPL_DIO,    "DODAG Information Object" },
    { ICMP6_RPL_DAO,    "Destination Advertisement Object" },
    { ICMP6_RPL_DAOACK, "Destination Advertisement Object Acknowledgement" },
    { ICMP6_RPL_SDIS,   "Secure DODAG Information Solicitation" },
    { ICMP6_RPL_SDIO,   "Secure DODAG Information Object" },
    { ICMP6_RPL_SDAO,   "Secure Destination Advertisement Object" },
    { ICMP6_RPL_SDAOACK,"Secure Destination Advertisement Object Acknowledgement" },
    { ICMP6_RPL_CC,     "Consistency Check" },
    { 0, NULL }
};

static const value_string rpl_secure_algorithm_encryption_val[] = {
    { 0, "CCM with AES-128" },
    { 0, NULL }
};

static const value_string rpl_secure_algorithm_signature_val[] = {
    { 0, "RSA with SHA-256" },
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
    { RPL_OPT_PAD1,       "1-byte padding" },
    { RPL_OPT_PADN,       "n-byte padding" },
    { RPL_OPT_METRIC,     "Metric container" },
    { RPL_OPT_ROUTING,    "Routing"},
    { RPL_OPT_CONFIG,     "DODAG configuration" },
    { RPL_OPT_TARGET,     "RPL Target" },
    { RPL_OPT_TRANSIT,    "Transit Information" },
    { RPL_OPT_SOLICITED,  "Solicited Information"},
    { RPL_OPT_PREFIX,     "Prefix Information"},
    { RPL_OPT_TARGETDESC, "RPL Target Descriptor"},
    { 0, NULL }
};



static int
dissect_contained_icmpv6(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    gboolean save_in_error_pkt;
    tvbuff_t *next_tvb;

    /* Save the current value of the "we're inside an error packet"
       flag, and set that flag; subdissectors may treat packets
       that are the payload of error packets differently from
       "real" packets. */
    save_in_error_pkt = pinfo->flags.in_error_pkt;
    pinfo->flags.in_error_pkt = TRUE;

    next_tvb = tvb_new_subset_remaining(tvb, offset);

    /* tiny sanity check */
    if ((tvb_get_guint8(tvb, offset) & 0xf0) == 0x60) {
        /* The contained packet is an IPv6 datagram; dissect it. */
        offset += call_dissector(ipv6_handle, next_tvb, pinfo, tree);
    } else
        offset += call_dissector(data_handle, next_tvb, pinfo, tree);

    /* Restore the "we're inside an error packet" flag. */
    pinfo->flags.in_error_pkt = save_in_error_pkt;

    return offset;
}


/* ======================================================================= */
static conversation_t *_find_or_create_conversation(packet_info *pinfo)
{
    conversation_t *conv = NULL;

    /* Have we seen this conversation before? */
    conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
        pinfo->ptype, 0, 0, 0);
    if ( conv == NULL )
    {
        /* No, this is a new conversation. */
        conv = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
            pinfo->ptype, 0, 0, 0);
    }
    return (conv);
}

/* ======================================================================= */
static icmp_transaction_t *transaction_start(packet_info *pinfo, proto_tree *tree, guint32 *key)
{
    conversation_t *conversation;
    icmpv6_conv_info_t *icmpv6_info;
    icmp_transaction_t *icmpv6_trans;
    emem_tree_key_t icmpv6_key[2];
    proto_item *it;

    /* Handle the conversation tracking */
    conversation = _find_or_create_conversation(pinfo);
    icmpv6_info = conversation_get_proto_data(conversation, proto_icmpv6);
    if ( icmpv6_info == NULL )
    {
        icmpv6_info = se_alloc(sizeof(icmpv6_conv_info_t));
        icmpv6_info->pdus = se_tree_create_non_persistent(
            EMEM_TREE_TYPE_RED_BLACK, "icmpv6_pdus");
        conversation_add_proto_data(conversation, proto_icmpv6, icmpv6_info);
    }

    icmpv6_key[0].length = 2;
    icmpv6_key[0].key = key;
    icmpv6_key[1].length = 0;
    icmpv6_key[1].key = NULL;
    if ( !PINFO_FD_VISITED(pinfo) )
    {
        icmpv6_trans = se_alloc(sizeof(icmp_transaction_t));
        icmpv6_trans->rqst_frame = PINFO_FD_NUM(pinfo);
        icmpv6_trans->resp_frame = 0;
        icmpv6_trans->rqst_time = pinfo->fd->abs_ts;
        icmpv6_trans->resp_time = 0.0;
        se_tree_insert32_array(icmpv6_info->pdus, icmpv6_key, (void *)icmpv6_trans);
    }
    else /* Already visited this frame */
        icmpv6_trans = se_tree_lookup32_array(icmpv6_info->pdus, icmpv6_key);

    if ( icmpv6_trans == NULL )
        return (NULL);

    /* Print state tracking in the tree */
    if ( tree && icmpv6_trans->resp_frame &&
        (icmpv6_trans->rqst_frame == PINFO_FD_NUM(pinfo)) )
    {
        it = proto_tree_add_uint(tree, hf_icmpv6_resp_in, NULL, 0, 0,
            icmpv6_trans->resp_frame);
        PROTO_ITEM_SET_GENERATED(it);
    }

    return (icmpv6_trans);

} /* transaction_start() */

/* ======================================================================= */
static icmp_transaction_t *transaction_end(packet_info *pinfo, proto_tree *tree, guint32 *key)
{
    conversation_t *conversation;
    icmpv6_conv_info_t *icmpv6_info;
    icmp_transaction_t *icmpv6_trans;
    emem_tree_key_t icmpv6_key[2];
    proto_item *it;
    nstime_t ns;

    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
        pinfo->ptype, 0, 0, 0);
    if ( conversation == NULL )
        return (NULL);

    icmpv6_info = conversation_get_proto_data(conversation, proto_icmpv6);
    if ( icmpv6_info == NULL )
        return (NULL);

    icmpv6_key[0].length = 2;
    icmpv6_key[0].key = key;
    icmpv6_key[1].length = 0;
    icmpv6_key[1].key = NULL;
    icmpv6_trans = se_tree_lookup32_array(icmpv6_info->pdus, icmpv6_key);
    if ( icmpv6_trans == NULL )
        return (NULL);

    /* Print state tracking in the tree */
    if ( icmpv6_trans->rqst_frame &&
        (icmpv6_trans->rqst_frame < PINFO_FD_NUM(pinfo)) &&
        ((icmpv6_trans->resp_frame == 0) ||
        (icmpv6_trans->resp_frame == PINFO_FD_NUM(pinfo))) )
    {
        icmpv6_trans->resp_frame = PINFO_FD_NUM(pinfo);
        if ( tree )
        {
            it = proto_tree_add_uint(tree, hf_icmpv6_resp_to, NULL, 0, 0,
                icmpv6_trans->rqst_frame);
            PROTO_ITEM_SET_GENERATED(it);
        }

        nstime_delta(&ns, &pinfo->fd->abs_ts, &icmpv6_trans->rqst_time);
        icmpv6_trans->resp_time = nstime_to_msec(&ns);
        if ( tree )
        {
            it = proto_tree_add_double_format_value(tree, hf_icmpv6_resptime, NULL,
                0, 0, icmpv6_trans->resp_time, "%.3f ms", icmpv6_trans->resp_time);
            PROTO_ITEM_SET_GENERATED(it);
        }
    }

    return (icmpv6_trans);

} /* transaction_end() */

static int
dissect_icmpv6_nd_opt(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
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
        ti = proto_tree_add_item(tree, hf_icmpv6_opt, tvb, offset, opt_len, ENC_NA);
        icmp6opt_tree = proto_item_add_subtree(ti, ett_icmpv6_opt);
        opt_offset = offset;

        /* Option type */
        proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_type, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
        opt_type = tvb_get_guint8(tvb, opt_offset);
        opt_offset += 1;

        /* Add option name to option root label */
        proto_item_append_text(ti, " (%s", val_to_str(opt_type, option_vals, "Unknown %d"));

        /* Option length */
        ti_opt_len = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_length, tvb,opt_offset, 1, ENC_BIG_ENDIAN);
        opt_offset += 1;

        /* Add length value in bytes */
        proto_item_append_text(ti_opt_len, " (%i bytes)", opt_len);

        if(opt_len == 0){
            expert_add_info_format(pinfo, ti_opt_len, PI_MALFORMED, PI_ERROR, "Invalid option length (Zero)");
            return opt_offset;
        }

        /* decode... */
        switch (opt_type) {
            case ND_OPT_SOURCE_LINKADDR: /* Source Link-layer Address (1) */
            {
                const gchar *link_str;
                /* if the opt len is 8, the Link Addr is MAC Address */
                if(opt_len == 8){
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_linkaddr_mac, tvb, opt_offset, 6, ENC_NA);
                    ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_src_linkaddr_mac, tvb, opt_offset, 6, ENC_NA);
                    PROTO_ITEM_SET_HIDDEN(ti_opt);

                    link_str = tvb_ether_to_str(tvb, opt_offset);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " from %s", link_str);
                    proto_item_append_text(ti, " : %s", link_str);
                /* if the opt len is 16 and the 6 last bytes is 0n the Link Addr is EUI64 Address */
                }else if(opt_len == 16 && tvb_get_ntohl(tvb, opt_offset + 8) == 0 && tvb_get_ntohs(tvb, opt_offset + 12) == 0){
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_linkaddr_eui64, tvb, opt_offset, 8, ENC_BIG_ENDIAN);
                    ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_src_linkaddr_eui64, tvb, opt_offset, 8, ENC_BIG_ENDIAN);
                    PROTO_ITEM_SET_HIDDEN(ti_opt);

                    /* Padding: 6 bytes */
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_padding, tvb, opt_offset + 8, 6, ENC_NA);

                    link_str = tvb_eui64_to_str(tvb, opt_offset, ENC_BIG_ENDIAN);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " from %s", link_str);
                    proto_item_append_text(ti, " : %s", link_str);
                }else{
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_linkaddr, tvb, opt_offset, opt_len-2, ENC_NA);
                    ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_src_linkaddr, tvb, opt_offset, opt_len-2, ENC_NA);
                    PROTO_ITEM_SET_HIDDEN(ti_opt);
                }
                opt_offset += opt_len;

                break;
            }
            case ND_OPT_TARGET_LINKADDR: /* Target Link-layer Address (2) */
            {
                const gchar *link_str;
                /* if the opt len is 8, the Link Addr is MAC Address */
                if(opt_len == 8){
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_linkaddr_mac, tvb, opt_offset, 6, ENC_NA);
                    ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_target_linkaddr_mac, tvb, opt_offset, 6, ENC_NA);
                    PROTO_ITEM_SET_HIDDEN(ti_opt);

                    link_str = tvb_ether_to_str(tvb, opt_offset);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " is at %s", link_str);
                    proto_item_append_text(ti, " : %s", link_str);

                /* if the opt len is 16 and the 6 last bytes is 0n the Link Addr is EUI64 Address */
                }else if(opt_len == 16 && tvb_get_ntohl(tvb, opt_offset + 8) == 0 && tvb_get_ntohs(tvb, opt_offset + 12) == 0){
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_linkaddr_eui64, tvb, opt_offset, 8, ENC_BIG_ENDIAN);
                    ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_target_linkaddr_eui64, tvb, opt_offset, 8, ENC_BIG_ENDIAN);
                    PROTO_ITEM_SET_HIDDEN(ti_opt);

                    /* Padding: 6 bytes */
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_padding, tvb, opt_offset + 8, 6, ENC_NA);

                    link_str = tvb_eui64_to_str(tvb, opt_offset, ENC_BIG_ENDIAN);
                    col_append_fstr(pinfo->cinfo, COL_INFO, " from %s", link_str);
                    proto_item_append_text(ti, " : %s", link_str);
                }else{
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_linkaddr, tvb, opt_offset, opt_len-2, ENC_NA);
                    ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_target_linkaddr, tvb, opt_offset, opt_len-2, ENC_NA);
                    PROTO_ITEM_SET_HIDDEN(ti_opt);
                }
                opt_offset += opt_len;
                break;
            }
            case ND_OPT_PREFIX_INFORMATION: /* Prefix Information (3) */
            {
                guint8 prefix_len;
                /* RFC 4861 */

                /* Prefix Length */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_prefix_len, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                prefix_len = tvb_get_guint8(tvb, opt_offset);
                opt_offset += 1;

                /* Flags */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_prefix_flag, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6_flag_prefix);

                proto_tree_add_item(flag_tree, hf_icmpv6_opt_prefix_flag_l, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_opt_prefix_flag_a, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_opt_prefix_flag_r, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_opt_prefix_flag_reserved, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Prefix Valid Lifetime */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_prefix_valid_lifetime, tvb, opt_offset, 4, ENC_BIG_ENDIAN);

                switch(tvb_get_ntohl(tvb, opt_offset)){
                    case 0xffffffff:
                        proto_item_append_text(ti_opt, " (Infinity)");
                        break;
                    default:
                        break;
                }
                opt_offset += 4;

                /* Prefix Preferred Lifetime */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_prefix_preferred_lifetime, tvb, opt_offset, 4, ENC_BIG_ENDIAN);

                switch(tvb_get_ntohl(tvb, opt_offset)){
                    case 0xffffffff:
                        proto_item_append_text(ti_opt, " (Infinity)");
                        break;
                    default:
                        break;
                }
                opt_offset += 4;

                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 4, ENC_NA);
                opt_offset += 4;

                /* Prefix */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_prefix, tvb, opt_offset, 16, ENC_NA);
                proto_item_append_text(ti, " : %s/%d", tvb_ip6_to_str(tvb, opt_offset), prefix_len);
                opt_offset += 16;

                break;
            }
            case ND_OPT_REDIRECTED_HEADER: /* Redirected Header (4) */

                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 6, ENC_NA);
                opt_offset += 6;

                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_redirected_packet, tvb, opt_offset, -1, ENC_NA);

                offset = dissect_contained_icmpv6(tvb, opt_offset, pinfo, icmp6opt_tree);
                break;
            case ND_OPT_MTU: /* MTU (5) */

                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 2, ENC_NA);
                opt_offset += 2;

                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_mtu, tvb, opt_offset, 4, ENC_BIG_ENDIAN);
                proto_item_append_text(ti, " : %d", tvb_get_ntohl(tvb, opt_offset));
                opt_offset += 4;
                break;
            case ND_OPT_NBMA: /* NBMA Shortcut Limit Option (6) */

                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_nbma_shortcut_limit, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_item_append_text(ti, " : %d", tvb_get_guint8(tvb, opt_offset));

                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 1, ENC_NA);
                opt_offset += 1;

                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 4, ENC_NA);
                opt_offset += 4;

                break;
            case ND_OPT_ADVINTERVAL: /* Advertisement Interval Option (7) */

                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 2, ENC_NA);
                opt_offset += 2;

                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_advertisement_interval, tvb, opt_offset, 4, ENC_BIG_ENDIAN);
                proto_item_append_text(ti, " : %d", tvb_get_ntohl(tvb, opt_offset));
                opt_offset += 4;

                break;
            case ND_OPT_HOMEAGENT_INFO: /* Home Agent Information Option (8) */
            {

                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 2, ENC_NA);
                opt_offset += 2;

                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_home_agent_preference, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
                opt_offset += 2;

                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_home_agent_lifetime, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
                opt_offset += 2;
                break;
            }
            case  ND_OPT_SOURCE_ADDRLIST: /* Source Address List (9) */
            case  ND_OPT_TARGET_ADDRLIST: /* Target Address List (10)*/
            {
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 6, ENC_NA);
                opt_offset += 6;

                while(opt_offset < (offset + opt_len) ) {
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_ipv6_address, tvb, opt_offset, 16, ENC_NA);
                    proto_item_append_text(ti, " %s", tvb_ip6_to_str(tvb, opt_offset));
                    opt_offset += 16;
                }
                break;
            }
            case ND_OPT_CGA: /* CGA Option (11) */
            {
                proto_tree *cga_tree;
                proto_item *cga_item;
                guint16 ext_data_len;
                guint8 padd_length;
                int par_len;
                asn1_ctx_t asn1_ctx;

                /* Pad Length */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_cga_pad_len, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                padd_length = tvb_get_guint8(tvb, opt_offset);
                opt_offset += 1;

                /* Reserved 8 bits */

                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 1, ENC_NA);
                opt_offset += 1;

                /* CGA Parameters A variable-length field containing the CGA Parameters data
                 * structure described in Section 4 of
                 * "Cryptographically Generated Addresses (CGA)", RFC3972.
                 */
                par_len = opt_len -4 -padd_length;
                cga_item = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_cga, tvb, opt_offset, par_len, ENC_NA);
                par_len += opt_offset;

                cga_tree = proto_item_add_subtree(cga_item, ett_icmpv6_cga_param_name);
                proto_tree_add_item(cga_tree, hf_icmpv6_opt_cga_modifier, tvb, opt_offset, 16, ENC_NA);
                opt_offset += 16;

                proto_tree_add_item(cga_tree, hf_icmpv6_opt_cga_subnet_prefix, tvb, opt_offset, 8, ENC_NA);
                opt_offset += 8;

                proto_tree_add_item(cga_tree ,hf_icmpv6_opt_cga_count, tvb, opt_offset, 1, ENC_NA);
                opt_offset += 1;

                asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
                opt_offset = dissect_x509af_SubjectPublicKeyInfo(FALSE, tvb, opt_offset, &asn1_ctx, cga_tree, -1);

                /* Process RFC 4581*/
                while (opt_offset < par_len) {
                    proto_tree_add_item(cga_tree, hf_icmpv6_opt_cga_ext_type, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
                    opt_offset += 2;

                    ext_data_len = tvb_get_ntohs(tvb, opt_offset);
                    proto_tree_add_item(cga_tree, hf_icmpv6_opt_cga_ext_length, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
                    opt_offset += 2;

                    proto_tree_add_item(cga_tree, hf_icmpv6_opt_cga_ext_data, tvb, opt_offset, ext_data_len, ENC_NA);
                    opt_offset += ext_data_len;
                }

                /* Padding */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_padding, tvb, opt_offset, padd_length, ENC_NA);
                opt_offset += padd_length;
                break;
            }
            case ND_OPT_RSA: /* RSA Signature Option (12) */
            {
                int par_len;
                /*5.2.  RSA Signature Option */
                /* Reserved, A 16-bit field reserved for future use. */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 2, ENC_NA);
                opt_offset = opt_offset + 2;

                /* Key Hash
                 * A 128-bit field containing the most significant (leftmost) 128
                 * bits of a SHA-1 [14] hash of the public key used for constructing
                 * the signature.
                 */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_rsa_key_hash, tvb, opt_offset, 16, ENC_NA);
                opt_offset = opt_offset + 16;

                /* Digital Signature */
                par_len = opt_len - 20;
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_digital_signature_padding , tvb, opt_offset, par_len, ENC_NA);
                opt_offset += par_len;

                /* Padding */
                /* TODO: Calculate padding length and exlude from the signature */
                break;
            }
            case ND_OPT_TIMESTAMP: /* Timestamp Option (13) */
                /* Reserved A 48-bit field reserved for future use. */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 6, ENC_NA);
                opt_offset += 6;

                /* Timestamp
                 * A 64-bit unsigned integer field containing a timestamp.  The value
                 * indicates the number of seconds since January 1, 1970, 00:00 UTC,
                 * by using a fixed point format.  In this format, the integer number
                 * of seconds is contained in the first 48 bits of the field, and the
                 * remaining 16 bits indicate the number of 1/64K fractions of a
                 * second.
                 */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_timestamp, tvb, opt_offset + 2, 4, ENC_TIME_TIMESPEC|ENC_BIG_ENDIAN);
                opt_offset += 8;
                break;
            case ND_OPT_NONCE: /* Nonce option (14) */

                /* 5.3.2.  Nonce Option */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_nonce, tvb, opt_offset, opt_len - 2, ENC_NA);
                opt_offset += opt_len -2;
                break;
            case ND_OPT_TRUST_ANCHOR: /* Trust Anchor Option (15) */
            {
                proto_tree *name_tree;
                proto_item *name_item;
                guint8 name_type;
                guint8 padd_length;
                int par_len;
                asn1_ctx_t asn1_ctx;

                /* Name Type */
                name_type = tvb_get_guint8(tvb, opt_offset);
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_name_type, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Pad Length */
                padd_length = tvb_get_guint8(tvb, opt_offset);
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_cga_pad_len, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                par_len = opt_len - 4 - padd_length;

                switch (name_type){
                    case 1:
                        /* DER Encoded X.501 Name */
                        name_item = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_name_x501, tvb, opt_offset, par_len, ENC_NA);
                        name_tree = proto_item_add_subtree(name_item, ett_icmpv6_opt_name);
                        asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
                        dissect_x509if_Name(FALSE, tvb, opt_offset, &asn1_ctx, name_tree, hf_icmpv6_x509if_Name);
                        break;
                    case 2:
                        /* FQDN */
                        proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_name_fqdn, tvb, opt_offset, par_len, ENC_ASCII|ENC_NA);
                        break;
                    default:
                        break;
                }
                opt_offset += par_len;

                /* Padding */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_padding, tvb, opt_offset, padd_length, ENC_NA);
                opt_offset += padd_length;

                break;
            }
            case ND_OPT_CERTIFICATE: /* Certificate Option (16) */
            {
                guint8 cert_type;
                guint8 padd_length;
                asn1_ctx_t asn1_ctx;

                /* Cert Type */
                cert_type = tvb_get_guint8(tvb, opt_offset);
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_cert_type, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Reserved */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 1, ENC_NA);
                opt_offset += 1;

                /* Certificate */

                if(cert_type == 1){
                    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
                    opt_offset = dissect_x509af_Certificate(FALSE, tvb, opt_offset, &asn1_ctx, icmp6opt_tree, hf_icmpv6_x509af_Certificate);
                    padd_length = opt_len - (opt_offset - offset);
                    /* Padding */
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_padding, tvb, opt_offset, padd_length, ENC_NA);
                    opt_offset += padd_length;
                }else{
                    padd_length = opt_len - 4;
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_certificate_padding, tvb, opt_offset, padd_length, ENC_NA);
                    opt_offset += padd_length;
                }
                break;

            }
            case ND_OPT_IP_ADDRESS_PREFIX: /* IP Address/Prefix Option (17) */
            {
                guint8 prefix_len;

                /* Option-code */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_ipa_option_code, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Prefix Len */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_ipa_prefix_len, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                prefix_len = tvb_get_guint8(tvb, opt_offset);
                opt_offset += 1;

                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 4, ENC_NA);
                opt_offset += 4;

                /* IPv6 Address */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_ipa_ipv6_address, tvb, opt_offset, 16, ENC_NA);
                proto_item_append_text(ti, " %s/%d", tvb_ip6_to_str(tvb, opt_offset), prefix_len);
                opt_offset += 16;

                break;
            }
            case ND_OPT_NEW_ROUTER_PREFIX_INFO: /* New Router Prefix Information Option (18) OBSO... */
            {

                guint8 prefix_len;

                /* Option-code */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_nrpi_option_code, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Prefix Len */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_nrpi_prefix_len, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                prefix_len = tvb_get_guint8(tvb, opt_offset);
                opt_offset += 1;

                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 4, ENC_NA);
                opt_offset += 4;

                /* Prefix */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_nrpi_prefix, tvb, opt_offset, 16, ENC_NA);
                proto_item_append_text(ti, " %s/%d", tvb_ip6_to_str(tvb, opt_offset), prefix_len);
                opt_offset += 16;

                break;
            }
            case ND_OPT_LINK_LAYER_ADDRESS: /* Link-layer Address Option (19) */
            {
                /* Option-Code */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_lla_option_code, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Link Layer Address */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_lla_bytes, tvb, opt_offset, opt_len-3, ENC_NA);
                opt_offset += opt_len - 3;
                break;
            }

            case ND_OPT_NEIGHBOR_ADV_ACK: /* Neighbor Advertisement Acknowledgment Option (20) */
            {
                guint8 status;

                /* Option-Code */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_naack_option_code, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Status */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_naack_status, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                status = tvb_get_guint8(tvb, opt_offset);
                opt_offset += 1;

                if(status == 2){
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_naack_supplied_ncoa, tvb, opt_offset, 16, ENC_NA);
                    opt_offset += 16;
                }else{
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, opt_len - 4, ENC_NA);
                    opt_offset += opt_len - 4;
                }
                break;
            }
            case ND_OPT_MAP: /* MAP Option (23) */
            {

                /* Dist */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_map_dist, tvb, opt_offset, 1, ENC_BIG_ENDIAN);

                /* Pref */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_map_pref, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Flags */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_map_flag, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6_flag_map);

                proto_tree_add_item(flag_tree, hf_icmpv6_opt_map_flag_r, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_opt_map_flag_reserved, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Valid Lifetime */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_map_valid_lifetime, tvb, opt_offset, 4, ENC_BIG_ENDIAN);
                opt_offset += 4;

                /* Global Address */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_map_global_address, tvb, opt_offset, 16, ENC_NA);
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
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_prefix_len, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                prefix_len = tvb_get_guint8(tvb, opt_offset);
                opt_offset += 1;

                /* Flags */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_route_info_flag, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6_flag_route_info);

                proto_tree_add_item(flag_tree, hf_icmpv6_opt_route_info_flag_route_preference, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_opt_route_info_flag_reserved, tvb, opt_offset, 1, ENC_BIG_ENDIAN);

                route_preference = tvb_get_guint8(tvb, opt_offset);
                route_preference = (route_preference & ND_RA_FLAG_RTPREF_MASK) >> 3;
                proto_item_append_text(ti, " : %s", val_to_str(route_preference, nd_flag_router_pref, "Unknown %d") );
                opt_offset += 1;

                /* Route Lifetime */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_route_lifetime, tvb, opt_offset, 4, ENC_BIG_ENDIAN);

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
                        opt_offset += 8;
                        break;
                    case 24:
                        proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_prefix, tvb, opt_offset, 16, ENC_NA);
                        proto_item_append_text(ti, " %s/%d", tvb_ip6_to_str(tvb, opt_offset), prefix_len);
                        opt_offset += 16;
                        break;
                    default:
                        expert_add_info_format(pinfo, ti_opt_len, PI_MALFORMED, PI_ERROR, "Invalid Option Length");
                        break;
                }
                break;

            }

            case ND_OPT_RECURSIVE_DNS_SERVER: /* Recursive DNS Server Option (25) */
            {
                /* Reserved */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 2, ENC_NA);
                opt_offset += 2;

                /* RDNSS Lifetime */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_rdnss_lifetime, tvb, opt_offset, 4, ENC_BIG_ENDIAN);
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
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_rdnss, tvb, opt_offset, 16, ENC_NA);
                    proto_item_append_text(ti, " %s", tvb_ip6_to_str(tvb, opt_offset));
                    opt_offset += 16;

                }
                break;
            }
            case ND_OPT_FLAGS_EXTENSION: /* RA Flags Extension Option (26) */
            {
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_efo, tvb, opt_offset, 6, ENC_NA);
                flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6_flag_efo);

                proto_tree_add_item(flag_tree, hf_icmpv6_opt_efo_m, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_opt_efo_o, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_opt_efo_h, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_opt_efo_prf, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_opt_efo_p, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_opt_efo_rsv, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
                opt_offset += 2;

                proto_tree_add_item(flag_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 4, ENC_NA);
                opt_offset += 4;
                break;
            }
            case ND_OPT_HANDOVER_KEY_REQUEST: /* Handover Key Request Option (27) */
            {
                int par_len;
                guint padd_length;

                /* Pad Length */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_pad_length, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                padd_length = tvb_get_guint8(tvb, opt_offset);
                opt_offset += 1;

                /* AT */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_at, tvb, opt_offset, 1, ENC_BIG_ENDIAN);

                /* Reserved */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_reserved, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Handover Key Encryption Public Key */
                par_len = opt_len-4-padd_length;
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_encryption_public_key, tvb, opt_offset, par_len, ENC_NA);
                opt_offset += par_len;

                /* Padding */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_padding, tvb, opt_offset, padd_length, ENC_NA);
                opt_offset += 1;
                break;
            }
            case ND_OPT_HANDOVER_KEY_REPLY: /* Handover Key Reply Option (28) */
            {
                int par_len;
                guint padd_length;

                /* Pad Length */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_pad_length, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                padd_length = tvb_get_guint8(tvb, opt_offset);
                opt_offset += 1;

                /* AT */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_at, tvb, opt_offset, 1, ENC_BIG_ENDIAN);

                /* Reserved */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_reserved, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Lifetime */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_lifetime, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
                opt_offset += 2;

                /* Encrypted Handover Key */
                par_len = opt_len-6-padd_length;
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_encrypted_handover_key, tvb, opt_offset, par_len, ENC_NA);
                opt_offset += par_len;

                /* Padding */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hkr_padding, tvb, opt_offset, padd_length, ENC_NA);
                opt_offset += 1;
                break;
            }
            case ND_OPT_HANDOVER_ASSIST_INFO: /* Handover Assist Information Option (29) */
            {
                guint8 hai_len;
                int padd_length;
                /* Option-Code */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hai_option_code, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* HAI Length */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hai_length, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                hai_len = tvb_get_guint8(tvb, opt_offset);
                opt_offset += 1;

                /* HAI Value */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_hai_value, tvb, opt_offset, hai_len, ENC_NA);
                opt_offset += hai_len;

                /* Padding... */
                padd_length = opt_len - opt_offset;
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_padding, tvb, opt_offset, padd_length, ENC_NA);
                opt_offset += padd_length;

                break;
            }
            case ND_OPT_MOBILE_NODE_ID: /* Mobile Node Identifier Option (30) */
            {
                guint8 mn_len;
                int padd_length;
                /* Option-Code */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_mn_option_code, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* MN Length */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_mn_length, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                mn_len = tvb_get_guint8(tvb, opt_offset);
                opt_offset += 1;

                /* MN Value */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_mn_value, tvb, opt_offset, mn_len, ENC_NA);
                opt_offset += mn_len;

                /* Padding... */
                padd_length = opt_len - opt_offset;
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_padding, tvb, opt_offset, padd_length, ENC_NA);
                opt_offset += padd_length;

                break;
            }
            case ND_OPT_DNS_SEARCH_LIST: /* DNS Search List Option (31) */
            {
                int dnssl_len;
                const guchar *dnssl_name;

                /* Reserved */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 2, ENC_NA);
                opt_offset += 2;

                /* DNSSL Lifetime */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_dnssl_lifetime, tvb, opt_offset, 4, ENC_BIG_ENDIAN);
                switch(tvb_get_ntohl(tvb, opt_offset)){
                    case 0:
                        proto_item_append_text(ti_opt, " (DNSSL domain name MUST no longer be used)");
                        break;
                    case 0xffffffff:
                        proto_item_append_text(ti_opt, " (Infinity)");
                        break;
                    default:
                        break;
                }
                opt_offset += 4;
                while(opt_offset < (offset + opt_len) ) {

                    if(tvb_get_guint8(tvb, opt_offset) == 0){
                        /* Padding... */
                        int padd_length = (offset + opt_len) - opt_offset;
                        proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_padding, tvb, opt_offset, padd_length, FALSE);
                        opt_offset += padd_length;
                        break;
                    }
                    dnssl_len = get_dns_name(tvb, opt_offset, 0, opt_offset, &dnssl_name);
                    proto_tree_add_string(icmp6opt_tree, hf_icmpv6_opt_dnssl, tvb, opt_offset, dnssl_len, dnssl_name);
                    proto_item_append_text(ti, " %s", dnssl_name);
                    opt_offset += dnssl_len;

                }
                break;
            }
            case ND_OPT_PROXY_SIGNATURE: /* Proxy Signature Option (32) */
            {
                int par_len;

                /* Reserved */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 2, ENC_NA);
                opt_offset +=  2;

                /* Key Hash
                 * A 128-bit field containing the most significant (leftmost) 128
                 * bits of a SHA-1 [14] hash of the public key used for constructing
                 * the signature.
                 */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_ps_key_hash, tvb, opt_offset, 16, ENC_NA);
                opt_offset += 16;

                /* Digital Signature */
                par_len = opt_len - 20;
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_digital_signature_padding , tvb, opt_offset, par_len, ENC_NA);
                opt_offset += par_len;
                /* Padding */
                /* TODO: Calculate padding length and exlude from the signature */
                break;
            }
            case ND_OPT_ADDR_REGISTRATION: /* Address Registration (TBD1 Pending IANA...) */
            {
                /* 6lowpan-ND */
                guint8 status;

                /* Status */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_aro_status, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                status = tvb_get_guint8(tvb, opt_offset);
                opt_offset += 1;

                /* Reserved */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 3, ENC_NA);
                opt_offset += 3;

                /* Lifetime */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_aro_registration_lifetime, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
                opt_offset += 2;

                /* EUI-64 */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_aro_eui64, tvb, opt_offset, 8, ENC_BIG_ENDIAN);
                proto_item_append_text(ti, " : Register %s %s", tvb_eui64_to_str(tvb, opt_offset, FALSE), val_to_str(status, nd_opt_6lowpannd_status_val, "Unknown %d"));
                opt_offset += 8;

            }
            break;
            case ND_OPT_6LOWPAN_CONTEXT: /* 6LoWPAN Context (TBD2 Pending IANA...) */
            {
                /* 6lowpan-ND */
                guint8 context_len;
                struct e_in6_addr context_prefix;

                /* Context Length */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_6co_context_length, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                context_len = tvb_get_guint8(tvb, opt_offset);
                opt_offset += 1;

                /*  Flags & CID */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_6co_flag, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6_flag_6lowpan);
                proto_tree_add_item(flag_tree, hf_icmpv6_opt_6co_flag_c, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_opt_6co_flag_cid, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_opt_6co_flag_reserved, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Reserved */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 2, ENC_NA);
                opt_offset += 2;

                /* Lifetime */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_6co_valid_lifetime, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
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
                        opt_offset += 8;
                        break;
                    case 24:
                        proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_6co_context_prefix, tvb, opt_offset, 16, ENC_NA);
                        proto_item_append_text(ti, " %s/%d", tvb_ip6_to_str(tvb, opt_offset), context_len);
                        opt_offset += 16;
                        break;
                    default:
                        expert_add_info_format(pinfo, ti_opt_len, PI_MALFORMED, PI_ERROR, "Invalid Option Length");
                        break;
                }
            }
            break;
            case ND_OPT_AUTH_BORDER_ROUTER: /* Authoritative Border Router (33) */
            {
                guint16 version;

                /* Version */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_abro_version, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
                version = tvb_get_ntohs(tvb, opt_offset);
                opt_offset += 2;

                /* Reserved */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_reserved, tvb, opt_offset, 4, ENC_NA);
                opt_offset += 4;

                /* 6LBR Address */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_opt_abro_6lbr_address, tvb, opt_offset, 16, ENC_NA);
                proto_item_append_text(ti, " : Version %d, 6LBR : %s", version, tvb_ip6_to_str(tvb, opt_offset));
                opt_offset += 16;

            }
            break;

            default :
                expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_NOTE,
                                       "Dissector for ICMPv6 Option (%d)"
                                       " code not implemented, Contact Wireshark developers"
                                       " if you want this supported", opt_type);
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_data, tvb, opt_offset, opt_len, ENC_NA);
                opt_offset += opt_len;
                break;

        } /* switch (opt_type) */

        offset += opt_len;

        if(offset > opt_offset){
            ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_unknown_data, tvb, opt_offset, offset - opt_offset, ENC_NA);
            expert_add_info_format(pinfo, ti_opt, PI_MALFORMED, PI_ERROR, "Unknown Data (not interpreted)");
        }
        /* Close the ) to option root label */
        proto_item_append_text(ti, ")");
    }
    return offset;
}


/* RPL: draft-ietf-roll-rpl-19.txt: Routing over Low-Power and Lossy Networks. */
static int
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
        ti = proto_tree_add_item(tree, hf_icmpv6_rpl_opt, tvb, offset, 1, ENC_NA);
        icmp6opt_tree = proto_item_add_subtree(ti, ett_icmpv6_rpl_opt);
        opt_offset = offset;

        /* Option type */
        proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_type, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
        opt_type = tvb_get_guint8(tvb, opt_offset);
        opt_offset += 1;

        /* Add option name to option root label */
        proto_item_append_text(ti, " (%s", val_to_str(opt_type, rpl_option_vals, "Unknown %d"));

        /* The Pad1 option is a special case, and contains no data. */
        if (opt_type == RPL_OPT_PAD1) {
            offset += 1;
            proto_item_append_text(ti, ")");
            continue;
        }

        /* Option length */
        ti_opt_len = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_length, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
        opt_len = tvb_get_guint8(tvb, opt_offset);
        proto_item_set_len(ti, opt_len + 2);
        opt_offset += 1;

        /* decode... */
        switch (opt_type) {
            case RPL_OPT_PADN:
                /* n-byte padding */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_padn, tvb, opt_offset, opt_len, ENC_NA);
                proto_item_append_text(ti_opt, " (Length : %i bytes)", opt_len);
                opt_offset += opt_len;
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
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_route_prefix_length, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset +=1;

                /* Flags */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_route_flag, tvb, opt_offset, 1, ENC_NA);
                flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6_rpl_flag_routing);

                proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_route_pref, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_route_reserved, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset +=1;

                /* Prefix lifetime. */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_route_lifetime, tvb, opt_offset, 4, ENC_BIG_ENDIAN);

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
                        opt_offset += 8;
                        break;
                    case 22:
                        proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_route_prefix, tvb, opt_offset, 16, ENC_NA);
                        proto_item_append_text(ti, " %s/%d", tvb_ip6_to_str(tvb, opt_offset), prefix_len);
                        opt_offset += 16;
                        break;
                    default:
                        expert_add_info_format(pinfo, ti_opt_len, PI_MALFORMED, PI_ERROR, "Invalid Option Length");
                        break;
                }
                break;
            }
            case RPL_OPT_CONFIG: {

                /* Flags */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_flag, tvb, opt_offset, 1, ENC_NA);
                flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6_rpl_flag_config);

                proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_config_reserved, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_config_auth, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_config_pcs, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* DIOIntervalDoublings */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_doublings, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* DIOIntervalMin */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_min_interval, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* DIORedundancyConstant */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_redundancy, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* MaxRankIncrease */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_rank_incr, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
                opt_offset += 2;

                /* MinHopRankInc */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_hop_rank_inc, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
                opt_offset += 2;

                /* OCP */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_ocp, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
                opt_offset += 2;

                /* Reserved */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_rsv, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Default Lifetime */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_def_lifetime, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Lifetime Unit */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_config_lifetime_unit, tvb, opt_offset, 2, ENC_BIG_ENDIAN);
                opt_offset += 2;
                break;
            }
            case RPL_OPT_TARGET: {
                guint8              prefix_len;
                struct e_in6_addr   target_prefix;

                /* Flag */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_target_flag, tvb, opt_offset, 1, ENC_NA);
                opt_offset += 1;

                /* Prefix length */
                prefix_len = tvb_get_guint8(tvb, opt_offset);
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_target_prefix_length, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
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
                        opt_offset += 8;
                        break;
                    case 18:
                        proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_target_prefix, tvb, opt_offset, 16, ENC_NA);
                        proto_item_append_text(ti, " %s/%d", tvb_ip6_to_str(tvb, opt_offset), prefix_len);
                        opt_offset += 16;
                        break;
                    default:
                        expert_add_info_format(pinfo, ti_opt_len, PI_MALFORMED, PI_ERROR, "Invalid Option Length");
                        break;
                }
                break;
            }
            case RPL_OPT_TRANSIT: {
                /* Flags */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_transit_flag, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6_rpl_flag_transit);

                proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_transit_flag_e, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_transit_flag_rsv, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Path Control */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_transit_pathctl, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Path Sequence */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_transit_pathseq, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Path Lifetime */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_transit_pathlifetime, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Option contains parent */
                if(opt_len > 4)
                {
                    proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_transit_parent, tvb, opt_offset, 16, ENC_NA);
                    proto_item_append_text(ti, " %s", tvb_ip6_to_str(tvb, opt_offset));
                    opt_offset += 16;
                }

                break;
            }
            case RPL_OPT_SOLICITED: {

                /*Instance ID */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_solicited_instance, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Flags */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_solicited_flag, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6_rpl_flag_solicited);

                proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_solicited_flag_v, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_solicited_flag_i, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_solicited_flag_d, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_solicited_flag_rsv, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* DODAG ID */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_solicited_dodagid, tvb, opt_offset, 16, ENC_NA);
                opt_offset += 16;

                /* Version Number */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_solicited_version, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                break;
            }
            case RPL_OPT_PREFIX: {
                /* Destination prefix option. */
                guint8              prefix_len;

                /* Prefix length */
                prefix_len = tvb_get_guint8(tvb, opt_offset);
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_prefix_length, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset +=1;

                /* Flags */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_prefix_flag, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                flag_tree = proto_item_add_subtree(ti_opt, ett_icmpv6_rpl_flag_prefix);

                proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_prefix_flag_l, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_prefix_flag_a, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_prefix_flag_r, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_rpl_opt_prefix_flag_rsv, tvb, opt_offset, 1, ENC_BIG_ENDIAN);
                opt_offset += 1;

                /* Valid lifetime. */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_prefix_vlifetime, tvb, opt_offset, 4, ENC_BIG_ENDIAN);
                switch(tvb_get_ntohl(tvb, opt_offset)){
                    case 0xffffffff:
                        proto_item_append_text(ti_opt, " (Infinity)");
                        break;
                    default:
                        break;
                }
                opt_offset += 4;

                /* Preferrred Lifetime */
                ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_prefix_plifetime, tvb, opt_offset, 4, ENC_BIG_ENDIAN);
                switch(tvb_get_ntohl(tvb, opt_offset)){
                    case 0xffffffff:
                        proto_item_append_text(ti_opt, " (Infinity)");
                        break;
                    default:
                        break;
                }
                opt_offset += 4;

                /* 4 reserved bytes. */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_reserved, tvb, opt_offset, 4, ENC_NA);
                opt_offset += 4;

                /* Prefix */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_prefix, tvb, opt_offset, 16, ENC_NA);
                proto_item_append_text(ti, " %s/%d", tvb_ip6_to_str(tvb, opt_offset), prefix_len);
                opt_offset += 16;

                break;
            }

            case RPL_OPT_TARGETDESC: {

                /* Descriptor */
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_rpl_opt_targetdesc, tvb, opt_offset, 4, ENC_BIG_ENDIAN);
                opt_offset += 4;
                break;
            }
            default :
                expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_NOTE,
                                       "Dissector for ICMPv6 RPL Option"
                                       " (%d) code not implemented, Contact"
                                       " Wireshark developers if you want this supported", opt_type);
                proto_tree_add_item(icmp6opt_tree, hf_icmpv6_data, tvb, opt_offset, opt_len, ENC_NA);
                opt_offset += opt_len;
                break;
        } /* switch (opt_type) */

        offset += opt_len + 2;

        if(offset > opt_offset){
            ti_opt = proto_tree_add_item(icmp6opt_tree, hf_icmpv6_unknown_data, tvb, opt_offset, offset - opt_offset, ENC_NA);
            expert_add_info_format(pinfo, ti_opt, PI_MALFORMED, PI_ERROR, "Unknown Data (not interpreted)");
        }

        /* Close the ) to option root label */
        proto_item_append_text(ti, ")");
    } /* while */
    return offset;
}

static int
dissect_rpl_control(tvbuff_t *tvb, int rpl_offset, packet_info *pinfo _U_, proto_tree *icmp6_tree, guint8 icmp6_type _U_, guint8 icmp6_code)
{
    proto_tree *flag_tree;
    proto_item *ti;

    /* Secure RPL ? (ICMP Code start to 0x8x) */
    if(icmp6_code & ICMP6_RPL_SECURE)
    {
        guint8 kim, lvl;

        /* Flags */
        ti = proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_secure_flag, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
        flag_tree = proto_item_add_subtree(ti, ett_icmpv6_flag_secure);
        proto_tree_add_item(flag_tree, hf_icmpv6_rpl_secure_flag_t, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flag_tree, hf_icmpv6_rpl_secure_flag_rsv, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
        rpl_offset += 1;

        /* Algorithm */
        ti = proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_secure_algorithm, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
        flag_tree = proto_item_add_subtree(ti, ett_icmpv6_flag_secure);
        proto_tree_add_item(flag_tree, hf_icmpv6_rpl_secure_algorithm_encryption, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flag_tree, hf_icmpv6_rpl_secure_algorithm_signature, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
        rpl_offset += 1;

        /* KIM & LVL */
        ti = proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_secure_flag, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
        flag_tree = proto_item_add_subtree(ti, ett_icmpv6_flag_secure);
        proto_tree_add_item(flag_tree, hf_icmpv6_rpl_secure_kim, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flag_tree, hf_icmpv6_rpl_secure_lvl, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flag_tree, hf_icmpv6_rpl_secure_rsv, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
        kim = tvb_get_guint8(tvb, rpl_offset) & RPL_SECURE_KIM >> 6;
        lvl = tvb_get_guint8(tvb, rpl_offset) & RPL_SECURE_LVL;
        rpl_offset += 1;

        /* Flags */
        proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_secure_flag, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
        rpl_offset += 1;

        /* Counter */
        proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_secure_counter, tvb, rpl_offset, 4, ENC_BIG_ENDIAN);
        rpl_offset += 4;

        /*  Key Identifier */
        switch(kim){
            case 0:
            {
                proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_secure_key_index, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
                rpl_offset += 1;
                break;
            }
            case 1:
            {
                /* No Key Identifier */
                break;
            }
            case 2:
            {
                proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_secure_key_source, tvb, rpl_offset, 8, ENC_NA);
                rpl_offset += 8;
                proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_secure_key_index, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
                rpl_offset += 1;
                break;
            }
            case 3:
            {
                if(lvl == 1 || lvl == 3)
                {
                    proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_secure_key_source, tvb, rpl_offset, 8, ENC_NA);
                    rpl_offset += 8;
                    proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_secure_key_index, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
                    rpl_offset += 1;
                }
                break;
            }

        }

    }
    switch(icmp6_code){
        case ICMP6_RPL_DIS: /* DODAG Information Solicitation (0) */
        case ICMP6_RPL_SDIS: /* Secure DODAG Information Solicitation (128) */
        {
            /* Flags */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_dis_flag, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            rpl_offset += 1;

            /* Reserved */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, rpl_offset, 1, ENC_NA);
            rpl_offset += 1;

            /* RPL Options */
            rpl_offset = dissect_icmpv6_rpl_opt(tvb, rpl_offset, pinfo, icmp6_tree);
            break;
        }
        case ICMP6_RPL_DIO: /* DODAG Information Object (1) */
        case ICMP6_RPL_SDIO: /* Secure DODAG Information Object (129) */
        {
            /* RPLInstanceID */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_dio_instance, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            rpl_offset += 1;

            /* Version Number */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_dio_version, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            rpl_offset += 1;

            /* Rank */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_dio_rank, tvb, rpl_offset, 2, ENC_BIG_ENDIAN);
            rpl_offset += 2;

            /* Flags */
            ti = proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_dio_flag, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            flag_tree = proto_item_add_subtree(ti, ett_icmpv6_flag_rpl_dio);
            proto_tree_add_item(flag_tree, hf_icmpv6_rpl_dio_flag_g, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(flag_tree, hf_icmpv6_rpl_dio_flag_0, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(flag_tree, hf_icmpv6_rpl_dio_flag_mop, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(flag_tree, hf_icmpv6_rpl_dio_flag_prf, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            rpl_offset += 1;

            /* Destination Advertisement Trigger Sequence Number (DTSN) */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_dio_dtsn, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            rpl_offset += 1;

            /* Flags */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_dio_flag, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            rpl_offset += 1;

            /* Reserved */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, rpl_offset, 1, ENC_NA);
            rpl_offset += 1;

            /* DODAGID */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_dio_dagid, tvb, rpl_offset, 16, ENC_NA);
            rpl_offset += 16;

            /* RPL Options */
            rpl_offset = dissect_icmpv6_rpl_opt(tvb, rpl_offset, pinfo, icmp6_tree);
            break;
        }
        case ICMP6_RPL_DAO: /* Destination Advertisement Object (2) */
        case ICMP6_RPL_SDAO: /* Secure Destination Advertisement Object (130) */
        {
            guint8 flags;

            /* DAO Instance */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_dao_instance, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            rpl_offset += 1;

            /* Flags */
            ti = proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_dao_flag, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            flag_tree = proto_item_add_subtree(ti, ett_icmpv6_flag_rpl_dao);
            proto_tree_add_item(flag_tree, hf_icmpv6_rpl_dao_flag_k, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(flag_tree, hf_icmpv6_rpl_dao_flag_d, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(flag_tree, hf_icmpv6_rpl_dao_flag_rsv, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            flags = tvb_get_guint8(tvb, rpl_offset);
            rpl_offset += 1;

            /* Reserved */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, rpl_offset, 1, ENC_NA);
            rpl_offset += 1;

            /* Sequence */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_dao_sequence, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            rpl_offset += 1;

            /* DODAGID */
            if(flags & RPL_DAO_FLAG_D)
            {
                proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_dao_dodagid, tvb, rpl_offset, 16, ENC_NA);
                rpl_offset += 16;
            }
            /* Options */
            rpl_offset = dissect_icmpv6_rpl_opt(tvb, rpl_offset, pinfo, icmp6_tree);
            break;
        }
        case ICMP6_RPL_DAOACK: /* Destination Advertisement Object Acknowledgment (3) */
        case ICMP6_RPL_SDAOACK: /* Secure Destination Advertisement Object Acknowledgment (131) */
        {
            guint8 flags;

            /* DAO Instance */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_daoack_instance, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            rpl_offset += 1;

            /* Flags */
            ti = proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_daoack_flag, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            flag_tree = proto_item_add_subtree(ti, ett_icmpv6_flag_rpl_daoack);
            proto_tree_add_item(flag_tree, hf_icmpv6_rpl_daoack_flag_d, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(flag_tree, hf_icmpv6_rpl_daoack_flag_rsv, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            flags = tvb_get_guint8(tvb, rpl_offset);
            rpl_offset += 1;

            /* DAO Sequence */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_daoack_sequence, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            rpl_offset += 1;

            /* Status */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_daoack_status, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            rpl_offset += 1;

            /* DODAGID */
            if(flags & RPL_DAOACK_FLAG_D)
            {
                proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_daoack_dodagid, tvb, rpl_offset, 16, ENC_NA);
                rpl_offset += 16;
            }

            /* Options */
            rpl_offset = dissect_icmpv6_rpl_opt(tvb, rpl_offset, pinfo, icmp6_tree);
            break;
        }
       case ICMP6_RPL_CC:
       {
            /* CC Instance */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_cc_instance, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            rpl_offset += 1;

            /* Flags */
            ti = proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_cc_flag, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            flag_tree = proto_item_add_subtree(ti, ett_icmpv6_flag_rpl_cc);
            proto_tree_add_item(flag_tree, hf_icmpv6_rpl_cc_flag_r, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(flag_tree, hf_icmpv6_rpl_cc_flag_rsv, tvb, rpl_offset, 1, ENC_BIG_ENDIAN);
            rpl_offset += 1;

            /* CC Nonce */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_cc_nonce, tvb, rpl_offset, 2, ENC_BIG_ENDIAN);
            rpl_offset += 2;

            /* DODAGID */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_cc_dodagid, tvb, rpl_offset, 16, ENC_NA);
            rpl_offset += 16;

            /* Destination Counter */
            proto_tree_add_item(icmp6_tree, hf_icmpv6_rpl_cc_destination_counter, tvb, rpl_offset, 4, ENC_BIG_ENDIAN);
            rpl_offset += 4;

            /* Options */
            rpl_offset = dissect_icmpv6_rpl_opt(tvb, rpl_offset, pinfo, icmp6_tree);
            break;
       }

    }
    return rpl_offset;
}
/* RFC 4620 - IPv6 Node Information Queries */

static int
dissect_nodeinfo(tvbuff_t *tvb, int ni_offset, packet_info *pinfo _U_, proto_tree *tree, guint8 icmp6_type, guint8 icmp6_code)
{
    proto_tree *flag_tree;
    proto_item *ti;
    guint16 qtype;

    /* Qtype */
    proto_tree_add_item(tree, hf_icmpv6_ni_qtype, tvb, ni_offset, 2, ENC_BIG_ENDIAN);
    qtype = tvb_get_ntohs(tvb, ni_offset);
    ni_offset += 2;

    /* Flags */
    ti = proto_tree_add_item(tree, hf_icmpv6_ni_flag, tvb, ni_offset, 2, ENC_BIG_ENDIAN);
    flag_tree = proto_item_add_subtree(ti, ett_icmpv6_flag_ni);
    proto_tree_add_item(flag_tree, hf_icmpv6_ni_flag_g, tvb, ni_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_icmpv6_ni_flag_s, tvb, ni_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_icmpv6_ni_flag_l, tvb, ni_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_icmpv6_ni_flag_c, tvb, ni_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_icmpv6_ni_flag_a, tvb, ni_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_icmpv6_ni_flag_t, tvb, ni_offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_icmpv6_ni_flag_rsv, tvb, ni_offset, 2, ENC_BIG_ENDIAN);
    ni_offset += 2;

    /* Nonce */
    proto_tree_add_item(tree, hf_icmpv6_ni_nonce, tvb, ni_offset, 8, ENC_BIG_ENDIAN);
    ni_offset += 8;

    /* Data ? */
    if(tvb_reported_length_remaining(tvb, ni_offset) == 0){
        return ni_offset;
    }

    if(icmp6_type == ICMP6_NI_QUERY){
        switch(icmp6_code){
            case ICMP6_NI_SUBJ_IPV6: {
                proto_tree_add_item(tree, hf_icmpv6_ni_query_subject_ipv6, tvb, ni_offset, 16, ENC_NA);
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
                proto_tree_add_item(tree, hf_icmpv6_ni_query_subject_ipv4, tvb, ni_offset, 4, ENC_BIG_ENDIAN);
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
                proto_tree_add_item(tree, hf_icmpv6_ni_reply_node_ttl, tvb, ni_offset, 4, ENC_BIG_ENDIAN);
                ni_offset += 4;
                /* Data ? */
                if(tvb_reported_length_remaining(tvb, ni_offset) == 0){
                    return ni_offset;
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
                    proto_tree_add_item(tree, hf_icmpv6_ni_reply_node_ttl, tvb, ni_offset, 4, ENC_BIG_ENDIAN);
                    ni_offset += 4;
                    /* Node Addresses */
                    proto_tree_add_item(tree, hf_icmpv6_ni_reply_node_address, tvb, ni_offset, 16, ENC_NA);
                    ni_offset += 16;
                }
                break;
            }
            case NI_QTYPE_IPV4ADDR: {
                while(ni_offset < (int)tvb_reported_length(tvb) ) {
                    /* TTL */
                    proto_tree_add_item(tree, hf_icmpv6_ni_reply_node_ttl, tvb, ni_offset, 4, ENC_BIG_ENDIAN);
                    ni_offset += 4;
                    /* IPv4 Address */
                    proto_tree_add_item(tree, hf_icmpv6_ni_reply_ipv4_address, tvb, ni_offset, 4, ENC_BIG_ENDIAN);
                    ni_offset += 4;
                }
                break;
            }
        }
    }
    return ni_offset;
}
/* RFC 2894 - Router Renumbering for IPv6 */

static int
dissect_rrenum(tvbuff_t *tvb, int rr_offset, packet_info *pinfo _U_, proto_tree *tree, guint8 icmp6_type _U_, guint8 icmp6_code)
{
    proto_tree *flag_tree, *mp_tree, *up_tree, *rm_tree;
    proto_item *ti, *ti_mp, *ti_up, *ti_rm;

    /* Sequence Number */
    proto_tree_add_item(tree, hf_icmpv6_rr_sequencenumber, tvb, rr_offset, 4, ENC_BIG_ENDIAN);
    rr_offset += 4;

    /* Segment Number */
    proto_tree_add_item(tree, hf_icmpv6_rr_segmentnumber, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
    rr_offset += 1;

    /* Flags */
    ti = proto_tree_add_item(tree, hf_icmpv6_rr_flag, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
    flag_tree = proto_item_add_subtree(ti, ett_icmpv6_flag_rr);
    proto_tree_add_item(flag_tree, hf_icmpv6_rr_flag_t, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_icmpv6_rr_flag_r, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_icmpv6_rr_flag_a, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_icmpv6_rr_flag_s, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_icmpv6_rr_flag_p, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(flag_tree, hf_icmpv6_rr_flag_rsv, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
    rr_offset += 1;

    /* Max Delay */
    proto_tree_add_item(tree, hf_icmpv6_rr_maxdelay, tvb, rr_offset, 2, ENC_BIG_ENDIAN);
    rr_offset += 2;

    /* Reserved */
    proto_tree_add_item(tree, hf_icmpv6_reserved, tvb, rr_offset, 4, ENC_NA);
    rr_offset += 4;

    /* Data ? */
    if(tvb_reported_length_remaining(tvb, rr_offset) == 0){
        return rr_offset;
    }

    if(icmp6_code == ICMP6_ROUTER_RENUMBERING_COMMAND){
        /* Match-Prefix Part */
        guint8 opcode, matchlen, minlen, maxlen;

        ti_mp = proto_tree_add_item(tree, hf_icmpv6_rr_pco_mp_part, tvb, rr_offset, 24, ENC_NA);
        mp_tree = proto_item_add_subtree(ti_mp, ett_icmpv6_rr_mp);

        /* OpCode */
        proto_tree_add_item(mp_tree, hf_icmpv6_rr_pco_mp_opcode, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
        opcode = tvb_get_guint8(tvb, rr_offset);
        rr_offset += 1;

        /* OpLength */
        proto_tree_add_item(mp_tree, hf_icmpv6_rr_pco_mp_oplength, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
        rr_offset += 1;

        /* Ordinal */
        proto_tree_add_item(mp_tree, hf_icmpv6_rr_pco_mp_ordinal, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
        rr_offset += 1;

        /* MatchLen  */
        proto_tree_add_item(mp_tree, hf_icmpv6_rr_pco_mp_matchlen, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
        matchlen = tvb_get_guint8(tvb, rr_offset);
        if (matchlen > 128) {
            expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN,
                "MatchLen is greater than 128");
        }
        rr_offset += 1;

        /* MinLen  */
        proto_tree_add_item(mp_tree, hf_icmpv6_rr_pco_mp_minlen, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
        minlen = tvb_get_guint8(tvb, rr_offset);
        rr_offset += 1;

        /* MaxLen  */
        proto_tree_add_item(mp_tree, hf_icmpv6_rr_pco_mp_maxlen, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
        maxlen = tvb_get_guint8(tvb, rr_offset);
        rr_offset += 1;

        /* Reserved  */
        proto_tree_add_item(mp_tree, hf_icmpv6_reserved, tvb, rr_offset, 2, ENC_NA);
        rr_offset += 2;

        /* Match Prefix  */
        proto_tree_add_item(mp_tree, hf_icmpv6_rr_pco_mp_matchprefix, tvb, rr_offset, 16, ENC_NA);

        /* Add Info (Prefix, Length...) to Match Prefix Part label */
        proto_item_append_text(ti_mp, ": %s %s/%u (%u-%u)", val_to_str(opcode, rr_pco_mp_opcode_val, "Unknown %d"), tvb_ip6_to_str(tvb, rr_offset), matchlen, minlen, maxlen);
        rr_offset += 16;

        while ((int)tvb_reported_length(tvb) > rr_offset) {
            /* Use-Prefix Part */
            guint8 uselen, keeplen;

            ti_up = proto_tree_add_item(tree, hf_icmpv6_rr_pco_up_part, tvb, rr_offset, 32, ENC_NA);
            up_tree = proto_item_add_subtree(ti_up, ett_icmpv6_rr_up);

            /* UseLen */
            proto_tree_add_item(up_tree, hf_icmpv6_rr_pco_up_uselen, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
            uselen = tvb_get_guint8(tvb, rr_offset);
            rr_offset += 1;

            /* KeepLen */
            proto_tree_add_item(up_tree, hf_icmpv6_rr_pco_up_keeplen, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
            keeplen = tvb_get_guint8(tvb, rr_offset);
            rr_offset += 1;

            /* FlagMask */
            ti = proto_tree_add_item(up_tree, hf_icmpv6_rr_pco_up_flagmask, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
            flag_tree = proto_item_add_subtree(ti, ett_icmpv6_rr_up_flag_mask);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_flagmask_l, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_flagmask_a, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_flagmask_reserved, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
            rr_offset += 1;

            /* RaFlags */
            ti = proto_tree_add_item(up_tree, hf_icmpv6_rr_pco_up_raflags, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
            flag_tree = proto_item_add_subtree(ti, ett_icmpv6_rr_up_flag_ra);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_raflags_l, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_raflags_a, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_raflags_reserved, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
            rr_offset += 1;

            /* Valid Lifetime */
            ti = proto_tree_add_item(up_tree, hf_icmpv6_rr_pco_up_validlifetime, tvb, rr_offset, 4, ENC_BIG_ENDIAN);
            switch(tvb_get_ntohl(tvb, rr_offset)){
                case 0xffffffff:
                    proto_item_append_text(ti, " (Infinity)");
                break;
                default:
                break;
            }
            rr_offset += 4;

            /* Preferred Lifetime */
            ti = proto_tree_add_item(up_tree, hf_icmpv6_rr_pco_up_preferredlifetime, tvb, rr_offset, 4, ENC_BIG_ENDIAN);
            switch(tvb_get_ntohl(tvb, rr_offset)){
                case 0xffffffff:
                    proto_item_append_text(ti, " (Infinity)");
                break;
                default:
                break;
            }
            rr_offset += 4;

            /* Flags */
            ti = proto_tree_add_item(up_tree, hf_icmpv6_rr_pco_up_flag, tvb, rr_offset, 4, ENC_BIG_ENDIAN);
            flag_tree = proto_item_add_subtree(ti, ett_icmpv6_rr_up_flag);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_flag_v, tvb, rr_offset, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_flag_p, tvb, rr_offset, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(flag_tree, hf_icmpv6_rr_pco_up_flag_reserved, tvb, rr_offset, 4, ENC_BIG_ENDIAN);
            rr_offset += 4;

            /* UsePrefix */
            proto_tree_add_item(up_tree, hf_icmpv6_rr_pco_up_useprefix, tvb, rr_offset, 16, ENC_NA);
            rr_offset += 16;

            /* Add Info (Prefix, Length...) to Use Prefix Part label */
            proto_item_append_text(ti_up, ": %s/%u (keep %u)", tvb_ip6_to_str(tvb, rr_offset), uselen, keeplen);
        }

    }else if(icmp6_code == ICMP6_ROUTER_RENUMBERING_RESULT){
        while ((int)tvb_reported_length(tvb) > rr_offset) {
        guint8 matchlen;
        guint32 interfaceindex;
        /* Result Message */

        ti_rm = proto_tree_add_item(tree, hf_icmpv6_rr_rm, tvb, rr_offset, 24, ENC_NA);
        rm_tree = proto_item_add_subtree(ti_rm, ett_icmpv6_rr_rm);

        /* Flags */
        ti = proto_tree_add_item(rm_tree, hf_icmpv6_rr_rm_flag, tvb, rr_offset, 2, ENC_BIG_ENDIAN);
        flag_tree = proto_item_add_subtree(ti, ett_icmpv6_rr_rm_flag);
        proto_tree_add_item(flag_tree, hf_icmpv6_rr_rm_flag_reserved, tvb, rr_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(flag_tree, hf_icmpv6_rr_rm_flag_b, tvb, rr_offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(flag_tree, hf_icmpv6_rr_rm_flag_f, tvb, rr_offset, 2, ENC_BIG_ENDIAN);
        rr_offset +=2;

        /* Ordinal */
        proto_tree_add_item(rm_tree, hf_icmpv6_rr_rm_ordinal, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
        rr_offset +=1;

        /* MatchLen */
        ti = proto_tree_add_item(rm_tree, hf_icmpv6_rr_rm_matchedlen, tvb, rr_offset, 1, ENC_BIG_ENDIAN);
        matchlen = tvb_get_guint8(tvb, rr_offset);
        if (matchlen > 128) {
            expert_add_info_format(pinfo, ti, PI_PROTOCOL, PI_WARN,
                "MatchedLen is greater than 128");
        }
        rr_offset +=1;

        /* InterfaceIndex */
        proto_tree_add_item(rm_tree, hf_icmpv6_rr_rm_interfaceindex, tvb, rr_offset, 4, ENC_BIG_ENDIAN);
        interfaceindex = tvb_get_ntohl(tvb, rr_offset);
        rr_offset +=4;

        /* MatchedPrefix */
        proto_tree_add_item(rm_tree, hf_icmpv6_rr_rm_matchedprefix, tvb, rr_offset, 16, ENC_NA);

        /* Add Info (Prefix, Length...) to Use Resultant Message label */
        proto_item_append_text(ti_rm, ": %s/%u (interface %u)", tvb_ip6_to_str(tvb, rr_offset), matchlen, interfaceindex);
        rr_offset +=16;
        }
    }
    return rr_offset;
}


static int
dissect_mldrv2( tvbuff_t *tvb, guint32 offset, packet_info *pinfo _U_, proto_tree *tree )
{
    proto_tree *mar_tree;
    proto_item *ti_mar;
    int mldr_offset = offset;

    /* Reserved */
    proto_tree_add_item(tree, hf_icmpv6_reserved, tvb, mldr_offset, 2, ENC_NA );
    mldr_offset += 2;

    /* Nr of Mcast Address Records (M) */
    proto_tree_add_item(tree, hf_icmpv6_mldr_nb_mcast_records, tvb, mldr_offset, 2, ENC_BIG_ENDIAN );
    mldr_offset += 2;

    /* Multicast Address Record */
    while(mldr_offset < (int)tvb_reported_length(tvb) ) {
        guint8 aux_data_len, record_type;
        guint16 i, nb_sources;
        struct e_in6_addr multicast_address;

        ti_mar = proto_tree_add_item(tree, hf_icmpv6_mldr_mar, tvb, mldr_offset, -1, ENC_NA);
        mar_tree = proto_item_add_subtree(ti_mar, ett_icmpv6_mar);

        /* Record Type */
        proto_tree_add_item(mar_tree, hf_icmpv6_mldr_mar_record_type, tvb, mldr_offset, 1, ENC_BIG_ENDIAN);
        record_type = tvb_get_guint8(tvb, mldr_offset);
        mldr_offset += 1;

        /* Aux Data Len */
        proto_tree_add_item(mar_tree, hf_icmpv6_mldr_mar_aux_data_len, tvb, mldr_offset, 1, ENC_BIG_ENDIAN);
        aux_data_len = tvb_get_guint8(tvb, mldr_offset);
        mldr_offset += 1;

        /* Number of Sources (N) */
        proto_tree_add_item(mar_tree, hf_icmpv6_mldr_mar_nb_sources, tvb, mldr_offset, 2, ENC_BIG_ENDIAN);
        nb_sources = tvb_get_ntohs(tvb, mldr_offset);
        mldr_offset += 2;

        /* Multicast Address */
        proto_tree_add_item(mar_tree, hf_icmpv6_mldr_mar_multicast_address, tvb, mldr_offset, 16, ENC_NA);
        tvb_get_ipv6(tvb, mldr_offset, &multicast_address);
        mldr_offset += 16;

        /* Source Address */
        for (i=1; i <= nb_sources; i++){
            proto_tree_add_item(mar_tree, hf_icmpv6_mldr_mar_source_address, tvb, mldr_offset, 16, ENC_NA);
            mldr_offset += 16;
        }

        /* Auxiliary Data ? */
        if(aux_data_len)
        {
            proto_tree_add_item(mar_tree, hf_icmpv6_mldr_mar_auxiliary_data, tvb, mldr_offset, aux_data_len * 4, ENC_NA);
            mldr_offset += aux_data_len * 4;
        }

        /* Multicast Address Record Length */
        proto_item_set_len(ti_mar, 4 + 16 + (16 * nb_sources) + (aux_data_len * 4));
        proto_item_append_text(ti_mar, " %s: %s", val_to_str(record_type, mldr_record_type_val,"Unknown Record Type (%d)"), ip6_to_str(&multicast_address));

    }
    return mldr_offset;
}


static int
dissect_icmpv6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *icmp6_tree = NULL, *flag_tree = NULL;
    proto_item *ti = NULL, *hidden_item, *checksum_item = NULL, *code_item = NULL, *ti_flag = NULL;
    const char *code_name = NULL;
    guint length = 0, reported_length;
    vec_t cksum_vec[4];
    guint32 phdr[2];
    guint16 cksum, computed_cksum;
    int offset;
    tvbuff_t *next_tvb;
    guint8 icmp6_type, icmp6_code;
    icmp_transaction_t *trans = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ICMPv6");
    col_clear(pinfo->cinfo, COL_INFO);

    offset = 0;

    if (tree) {
        ti = proto_tree_add_item(tree, proto_icmpv6, tvb, offset, -1, ENC_NA);
        icmp6_tree = proto_item_add_subtree(ti, ett_icmpv6);

        /* Type */
        proto_tree_add_item(icmp6_tree, hf_icmpv6_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    icmp6_type = tvb_get_guint8(tvb, offset);
    offset += 1;

    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(icmp6_type, icmpv6_type_val, "Unknown (%d)"));

    if (tree)
        code_item = proto_tree_add_item(icmp6_tree, hf_icmpv6_code, tvb, offset, 1, ENC_BIG_ENDIAN);

    icmp6_code = tvb_get_guint8(tvb, offset);
    offset += 1;

    switch (icmp6_type) {
        case ICMP6_DST_UNREACH:
            code_name = val_to_str(icmp6_code, icmpv6_unreach_code_val, "Unknown");
            break;
        case ICMP6_TIME_EXCEEDED:
            code_name = val_to_str(icmp6_code, icmpv6_timeex_code_val, "Unknown (%d)");
            break;
        case ICMP6_PARAM_PROB:
            code_name = val_to_str(icmp6_code, icmpv6_paramprob_code_val, "Unknown (%d)");
            break;
        case ICMP6_ROUTER_RENUMBERING:
            code_name = val_to_str(icmp6_code, icmpv6_rr_code_val, "Unknown (%d)");
            break;
        case ICMP6_NI_QUERY:
            code_name = val_to_str(icmp6_code, ni_query_code_val, "Unknown (%d)");
            break;
        case ICMP6_NI_REPLY:
            code_name = val_to_str(icmp6_code, ni_reply_code_val, "Unknown (%d)");
            break;
        case ICMP6_RPL_CONTROL:
            code_name = val_to_str(icmp6_code, rpl_code_val, "Unknown (%d)");
            break;
    }

    if (code_name)
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", code_name);

    /* RFC 4380
     * 2.7.   Teredo UDP Port
     * 5.2.9. Direct IPv6 Connectivity Test  */
    if (pinfo->destport == 3544 && icmp6_type == ICMP6_ECHO_REQUEST) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Teredo");
        col_set_str(pinfo->cinfo, COL_INFO, "Direct IPv6 Connectivity Test");
    }

    if (tree) {
        if (code_name)
            proto_item_append_text(code_item, " (%s)", code_name);
        checksum_item = proto_tree_add_item(icmp6_tree, hf_icmpv6_checksum, tvb, offset, 2, ENC_BIG_ENDIAN);
    }

    cksum = tvb_get_ntohs(tvb, offset);

    if (1) { /* There's an expert info in here so always execute */
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
            phdr[0] = g_htonl(reported_length);
            phdr[1] = g_htonl(IP_PROTO_ICMPV6);
            cksum_vec[2].len = 8;
            cksum_vec[3].len = reported_length;
            cksum_vec[3].ptr = tvb_get_ptr(tvb, 0, cksum_vec[3].len);
            computed_cksum = in_cksum(cksum_vec, 4);

            if (computed_cksum == 0) {
                proto_item_append_text(checksum_item, " [correct]");
            } else {
                hidden_item = proto_tree_add_boolean(icmp6_tree, hf_icmpv6_checksum_bad, tvb, offset, 2, TRUE);

                PROTO_ITEM_SET_GENERATED(hidden_item);
                proto_item_append_text(checksum_item, " [incorrect, should be 0x%04x]", in_cksum_shouldbe(cksum, computed_cksum));
                expert_add_info_format(pinfo, checksum_item, PI_CHECKSUM, PI_WARN,
                                       "ICMPv6 Checksum Incorrect, should be 0x%04x", in_cksum_shouldbe(cksum, computed_cksum));
            }
        }
    }
    offset += 2;

    if (icmp6_type == ICMP6_ECHO_REQUEST || icmp6_type == ICMP6_ECHO_REPLY) {
        guint16 identifier, sequence;

        /* Identifier */
        if (tree)
            proto_tree_add_item(icmp6_tree, hf_icmpv6_echo_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
        identifier = tvb_get_ntohs(tvb, offset);
        offset += 2;

        /* Sequence Number */
        if (tree)
            proto_tree_add_item(icmp6_tree, hf_icmpv6_echo_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
        sequence = tvb_get_ntohs(tvb, offset);
        offset += 2;

        col_append_fstr(pinfo->cinfo, COL_INFO, " id=0x%04x, seq=%u", identifier, sequence);

        if (pinfo->destport == 3544 && icmp6_type == ICMP6_ECHO_REQUEST) {
            /* RFC 4380
             * 2.7.   Teredo UDP Port
             * 5.2.9. Direct IPv6 Connectivity Test
             *
             * TODO: Clarify the nonce:  The RFC states, "(It is recommended to
             * use a random number [the nonce] at least 64 bits long.)"
             *
             * Shouldn't the nonce be at least 8 then?  Why not just use (-1),
             * as it could really be any length, couldn't it?
             */
            if (tree)
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nonce, tvb, offset, 4, ENC_NA);
            offset += 4;
        } else {
            if (!pinfo->flags.in_error_pkt) {
                guint32 conv_key[2];

                conv_key[1] = (guint32)((identifier << 16) | sequence);

                if (icmp6_type == ICMP6_ECHO_REQUEST) {
                    conv_key[0] = (guint32)cksum;
                    if (pinfo->flags.in_gre_pkt)
                        conv_key[0] |= 0x00010000; /* set a bit for "in GRE" */
                    trans = transaction_start(pinfo, icmp6_tree, conv_key);
                } else { /* ICMP6_ECHO_REPLY */
                    guint16 tmp[2];

                    tmp[0] = ~cksum;
                    tmp[1] = ~0x0100; /* The difference between echo request & reply */
                    cksum_vec[0].len = sizeof(tmp);
                    cksum_vec[0].ptr = (guint8 *)tmp;
                    conv_key[0] = in_cksum(cksum_vec, 1);
                    if (pinfo->flags.in_gre_pkt)
                        conv_key[0] |= 0x00010000; /* set a bit for "in GRE" */
                    trans = transaction_end(pinfo, icmp6_tree, conv_key);
                }
            }
            next_tvb = tvb_new_subset(tvb, offset, -1, -1);
            offset += call_dissector(data_handle, next_tvb, pinfo, icmp6_tree);
        }
    }

    if (1) { /* There are expert infos buried in here so always execute */
        /* decode... */
        switch (icmp6_type) {
            case ICMP6_DST_UNREACH: /* Destination Unreachable (1) */
            case ICMP6_TIME_EXCEEDED: /* Time Exceeded (3) */
                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 4, ENC_NA);
                offset += 4;

                offset = dissect_contained_icmpv6(tvb, offset, pinfo, icmp6_tree);
                break;
            case ICMP6_PACKET_TOO_BIG: /* Packet Too Big (2) */
                /* MTU */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_mtu, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                offset = dissect_contained_icmpv6(tvb, offset, pinfo, icmp6_tree);
                break;
            case ICMP6_PARAM_PROB: /* Parameter Problem (4) */
                /* MTU */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_pointer, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                offset = dissect_contained_icmpv6(tvb, offset, pinfo, icmp6_tree);
                break;
            case ICMP6_ECHO_REQUEST:    /* Echo Request (128) */
            case ICMP6_ECHO_REPLY:      /* Echo Reply (129) */
                /* Already handled above */
                break;
            case ICMP6_MEMBERSHIP_QUERY: /* Multicast Listener Query (130) */
            case ICMP6_MEMBERSHIP_REPORT: /* Multicast Listener Report (131) */
            case ICMP6_MEMBERSHIP_REDUCTION: /* Multicast Listener Done (132) */
            {
                /* It is MLDv2 packet ? (the min length for a MLDv2 packet is 28) */
                if ((icmp6_type == ICMP6_MEMBERSHIP_QUERY) && (length >= MLDV2_PACKET_MINLEN)) {
                    guint32 mrc;
                    guint16 qqi, i, nb_sources;

                    /* Maximum Response Code */
                    mrc = tvb_get_ntohs(tvb, offset);
                    if (mrc >= 32768){
                        mrc = ((mrc & 0x0fff) | 0x1000) << (((mrc & 0x7000) >> 12) + 3);
                    }
                    proto_tree_add_uint(icmp6_tree, hf_icmpv6_mld_mrc, tvb, offset, 2, mrc);
                    offset += 2;

                    /* Reserved */
                    proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 2, ENC_NA);
                    offset += 2;

                    /* Multicast Address */
                    proto_tree_add_item(icmp6_tree, hf_icmpv6_mld_multicast_address, tvb, offset, 16, ENC_NA);
                    offset += 16;

                    /* Flag */
                    ti_flag = proto_tree_add_item(icmp6_tree, hf_icmpv6_mld_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
                    flag_tree = proto_item_add_subtree(ti_flag, ett_icmpv6_flag_mld);
                    proto_tree_add_item(flag_tree, hf_icmpv6_mld_flag_s, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(flag_tree, hf_icmpv6_mld_flag_qrv, tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(flag_tree, hf_icmpv6_mld_flag_rsv, tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset += 1;

                    /* QQI */
                    qqi = tvb_get_guint8(tvb, offset);
                    if (qqi >= 128){
                        qqi = ((qqi & 0x0f) | 0x10) << (((qqi & 0x70) >> 4) + 3);
                    }
                    proto_tree_add_uint(icmp6_tree, hf_icmpv6_mld_qqi, tvb, offset, 1, qqi);
                    offset += 1;

                    /* Number of Sources */
                    proto_tree_add_item(icmp6_tree, hf_icmpv6_mld_nb_sources, tvb, offset, 2, ENC_BIG_ENDIAN);
                    nb_sources = tvb_get_ntohs(tvb, offset);
                    offset += 2;

                    /* Source Address */
                    for (i=1; i <= nb_sources; i++){
                        proto_tree_add_item(icmp6_tree, hf_icmpv6_mld_source_address, tvb, offset, 16, ENC_NA);
                        offset += 16;
                    }

                }else{ /* It is a MLDv1 Packet */

                    proto_tree_add_item(icmp6_tree, hf_icmpv6_mld_mrd, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    /* Reserved */
                    proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 2, ENC_NA);
                    offset += 2;

                    /* Multicast Address */
                    proto_tree_add_item(icmp6_tree, hf_icmpv6_mld_multicast_address, tvb, offset, 16, ENC_NA);
                    offset += 16;
                }
                break;
            }
            case ICMP6_ND_ROUTER_SOLICIT: /* Router Solicitation (133) */
            {
                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 4, ENC_NA);
                offset += 4;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_ND_ROUTER_ADVERT: /* Router Advertisement (134) */
            {

                /* Current hop limit */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_ra_cur_hop_limit, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* Flags */
                ti_flag = proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_ra_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
                flag_tree = proto_item_add_subtree(ti_flag, ett_icmpv6_flag_ra);

                proto_tree_add_item(flag_tree, hf_icmpv6_nd_ra_flag_m, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_ra_flag_o, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_ra_flag_h, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_ra_flag_prf, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_ra_flag_p, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_ra_flag_rsv, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* Router lifetime */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_ra_router_lifetime, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Reachable time */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_ra_reachable_time, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                /* Retrans timer */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_ra_retrans_timer, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_ND_NEIGHBOR_SOLICIT: /* Neighbor Solicitation (135) */
            {
                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 4, ENC_NA);
                offset += 4;

                /* Target Address */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_ns_target_address, tvb, offset, 16, ENC_NA);
                col_append_fstr(pinfo->cinfo, COL_INFO, " for %s", tvb_ip6_to_str(tvb, offset));

                offset += 16;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_ND_NEIGHBOR_ADVERT: /* Neighbor Advertisement (136) */
            {
                guint32 na_flags;
                emem_strbuf_t *flags_strbuf = ep_strbuf_new_label("");

                /* Flags */
                ti_flag = proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_na_flag, tvb, offset, 4, ENC_BIG_ENDIAN);
                flag_tree = proto_item_add_subtree(ti_flag, ett_icmpv6_flag_na);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_na_flag_r, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_na_flag_s, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_na_flag_o, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_nd_na_flag_rsv, tvb, offset, 4, ENC_BIG_ENDIAN);
                na_flags = tvb_get_ntohl(tvb, offset);
                offset += 4;

                /* Target Address */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_na_target_address, tvb, offset, 16, ENC_NA);


                if (na_flags & ND_NA_FLAG_R) {
                    ep_strbuf_append(flags_strbuf, "rtr, ");
                }
                if (na_flags & ND_NA_FLAG_S) {
                    ep_strbuf_append(flags_strbuf, "sol, ");
                }
                if (na_flags & ND_NA_FLAG_O) {
                    ep_strbuf_append(flags_strbuf, "ovr, ");
                }
                if (flags_strbuf->len > 2) {
                    ep_strbuf_truncate(flags_strbuf, flags_strbuf->len - 2);
                } else {
                    ep_strbuf_printf(flags_strbuf, "none");
                }

                col_append_fstr(pinfo->cinfo, COL_INFO, " %s (%s)", tvb_ip6_to_str(tvb, offset), flags_strbuf->str);
                offset += 16;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_ND_REDIRECT: /* Redirect Message (137) */
            {
                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 4, ENC_NA);
                offset += 4;

                /* Target Address */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_rd_target_address, tvb, offset, 16, ENC_NA);
                offset += 16;

                /* Destination Address */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_nd_rd_destination_address, tvb, offset, 16, ENC_NA);
                offset += 16;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_ROUTER_RENUMBERING: /* Router Renumbering (138) */
            {
                offset = dissect_rrenum(tvb, offset, pinfo, icmp6_tree, icmp6_type, icmp6_code);
                break;
            }
            case ICMP6_NI_QUERY: /* ICMP Node Information Query (139) */
            case ICMP6_NI_REPLY: /* ICMP Node Information Response (140) */
            {
                offset = dissect_nodeinfo(tvb, offset, pinfo, icmp6_tree, icmp6_type, icmp6_code);
                break;
            }
            case ICMP6_IND_SOLICIT: /* Inverse Neighbor Discovery Solicitation Message (141) */
            case ICMP6_IND_ADVERT: /* Inverse Neighbor Discovery Advertisement Message (142) */
            {
                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 4, ENC_NA);
                offset += 4;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_MLDV2_REPORT: /* Version 2 Multicast Listener Report (143) */
            {
                offset = dissect_mldrv2( tvb, offset, pinfo, icmp6_tree );
                break;
            }
            case ICMP6_MIP6_DHAAD_REQUEST: /* Home Agent Address Discovery Request Message (144) */
            {
                /* Identifier */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_mip6_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 2, ENC_NA);
                offset += 2;

                break;
            }
            case ICMP6_MIP6_DHAAD_REPLY: /* Home Agent Address Discovery Reply Message (145) */
            {
                /* Identifier */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_mip6_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 2, ENC_NA);
                offset += 2;

                /* Show all Home Agent Addresses */
                while((int)length > offset)
                {
                    proto_tree_add_item(icmp6_tree, hf_icmpv6_mip6_home_agent_address, tvb, offset, 16, ENC_NA);
                    offset += 16;
                }
                break;
            }
            case ICMP6_MIP6_MPS: /* Mobile Prefix Solicitation (146) */
            {
                /* Identifier */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_mip6_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 2, ENC_NA);
                offset += 2;
                break;
            }
            case ICMP6_MIP6_MPA: /* Mobile Prefix Advertisement (147) */
            {
                /* Identifier */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_mip6_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Flag */
                ti_flag = proto_tree_add_item(icmp6_tree, hf_icmpv6_mip6_flag, tvb,offset, 6, ENC_NA);
                flag_tree = proto_item_add_subtree(ti_flag, ett_icmpv6_flag_mip6);
                proto_tree_add_item(flag_tree, hf_icmpv6_mip6_flag_m, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_mip6_flag_o, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(flag_tree, hf_icmpv6_mip6_flag_rsv, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_CERT_PATH_SOL: /* Certification Path Solicitation Message (148) */
            {

                /* Identifier */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_send_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Component  */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_send_component, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_CERT_PATH_AD: /* Certification Path Advertisement Message (149) */
            {

                /* Identifier */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_send_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* All Components */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_send_all_components, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Component  */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_send_component, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 2, ENC_NA);
                offset += 2;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_EXPERIMENTAL_MOBILITY: /* ICMP messages utilized by experimental mobility protocols (150) */
            case ICMP6_FMIPV6_MESSAGES:  /* FMIPv6 Messages (154)*/
            {
                guint8 subtype;

                /* Subtype */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_fmip6_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
                subtype = tvb_get_guint8(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", val_to_str(subtype, fmip6_subtype_val, "Unknown (%d)"));
                offset += 1;

                switch(subtype){
                    case FMIP6_SUBTYPE_RTSOLPR:
                    {
                        /* Reserved */
                        proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 1, ENC_NA);
                    }
                    break;
                    case FMIP6_SUBTYPE_PRRTADV:
                    {
                        proto_item_append_text(code_item, " (%s)", val_to_str(icmp6_code, fmip6_prrtadv_code_val, "Unknown %d") );
                        /* Reserved */
                        proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 1, ENC_NA);
                    }
                    break;
                    case FMIP6_SUBTYPE_HI:
                    {
                        proto_item_append_text(code_item, " (%s)", val_to_str(icmp6_code, fmip6_hi_code_val, "Unknown %d") );
                        /* Flags */
                        ti_flag = proto_tree_add_item(icmp6_tree, hf_icmpv6_fmip6_hi_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
                        flag_tree = proto_item_add_subtree(ti_flag, ett_icmpv6_flag_fmip6);

                        proto_tree_add_item(flag_tree, hf_icmpv6_fmip6_hi_flag_s, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(flag_tree, hf_icmpv6_fmip6_hi_flag_u, tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(flag_tree, hf_icmpv6_fmip6_hi_flag_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                    }
                    break;
                    case FMIP6_SUBTYPE_HACK:
                    {
                        proto_item_append_text(code_item, " (%s)", val_to_str(icmp6_code, fmip6_hack_code_val, "Unknown %d") );
                        /* Reserved */
                        proto_tree_add_item(icmp6_tree, hf_icmpv6_reserved, tvb, offset, 1, ENC_NA);
                    }
                    break;
                }
                offset +=1;

                /* Identifier */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_fmip6_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Show options */
                offset = dissect_icmpv6_nd_opt(tvb, offset, pinfo, icmp6_tree);
                break;
            }
            case ICMP6_MCAST_ROUTER_ADVERT: /* Multicast Router Advertisement (151) */
            {
                /* Query Interval */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_mcast_ra_query_interval, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* Robustness Variable */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_mcast_ra_robustness_variable, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            case ICMP6_MCAST_ROUTER_SOLICIT: /* Multicast Router Solicitation (152) */
            case ICMP6_MCAST_ROUTER_TERM: /* Multicast Router Termination (153) */
            {
                /* No Action... */
                break;
            }
            case ICMP6_RPL_CONTROL: /* RPL Control (155) */
            {
                /* RPL: draft-ietf-roll-rpl-19.txt: Routing over Low-Power and Lossy Networks. */
                offset = dissect_rpl_control(tvb, offset, pinfo, icmp6_tree, icmp6_type, icmp6_code);
                break;
            }

            case ICMP6_6LOWPANND_DAR:
            case ICMP6_6LOWPANND_DAC:
            {
                /* Status */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_da_status, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* Reserved */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_da_rsv, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                /* Lifetime */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_da_lifetime, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                /* EUI-64 */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_da_eui64, tvb, offset, 8, ENC_BIG_ENDIAN);
                offset += 8;

                /* Address */
                proto_tree_add_item(icmp6_tree, hf_icmpv6_da_raddr, tvb, offset, 16, ENC_NA);
                offset += 16;
                break;
            }
            default:
                expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_NOTE,
                                       "Dissector for ICMPv6 Type (%d)"
                                       " code not implemented, Contact Wireshark"
                                       " developers if you want this supported", icmp6_type);
                proto_tree_add_item(icmp6_tree, hf_icmpv6_data, tvb, offset, -1, ENC_NA);
                break;
        } /* switch (icmp6_type) */
    } /* if (1) */

    if (trans)
        tap_queue_packet(icmpv6_tap, pinfo, trans);

    return offset;
}

void
proto_register_icmpv6(void)
{
    static hf_register_info hf[] = {
        { &hf_icmpv6_type,
          { "Type", "icmpv6.type", FT_UINT8, BASE_DEC, VALS(icmpv6_type_val), 0x0,
            "Indicates the type of the message", HFILL }},
        { &hf_icmpv6_code,
          { "Code", "icmpv6.code", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Depends on the message type.  It is used to create an additional level of message granularity", HFILL }},
        { &hf_icmpv6_checksum,
          { "Checksum", "icmpv6.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
            "Used to detect data corruption in the ICMPv6 message and parts of the IPv6 header", HFILL }},
        { &hf_icmpv6_checksum_bad,
          { "Bad Checksum", "icmpv6.checksum_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_reserved,
          { "Reserved", "icmpv6.reserved", FT_BYTES, BASE_NONE, NULL, 0x0,
            "Must be Zero", HFILL }},
        { &hf_icmpv6_data,
          { "Data", "icmpv6.data", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_unknown_data,
          { "Unknown Data", "icmpv6.unknown_data", FT_BYTES, BASE_NONE, NULL, 0x0,
            "Not interpreted Data", HFILL }},
        { &hf_icmpv6_mtu,
          { "MTU", "icmpv6.mtu", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The Maximum Transmission Unit of the next-hop link", HFILL }},
        { &hf_icmpv6_pointer,
          { "Pointer", "icmpv6.pointer", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Identifies the octet offset within the invoking packet where the error was detected", HFILL }},
        { &hf_icmpv6_echo_identifier,
          { "Identifier", "icmpv6.echo.identifier", FT_UINT16, BASE_HEX, NULL, 0x0,
            "An identifier to aid in matching with Request and Reply", HFILL }},
        { &hf_icmpv6_echo_sequence_number,
          { "Sequence", "icmpv6.echo.sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0,
            "A sequence number to aid in matching Echo Replies to this Echo Request", HFILL }},
        { &hf_icmpv6_nonce,
          { "Nonce", "icmpv6.nonce", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        /* RFC 2461/4861 : Neighbor Discovery for IP version 6 (IPv6) */
        { &hf_icmpv6_nd_ra_cur_hop_limit,
          { "Cur hop limit", "icmpv6.nd.ra.cur_hop_limit", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The default value that should be placed in the Hop Count field of the IP header for outgoing IP packets", HFILL }},
        { &hf_icmpv6_nd_ra_flag,
          { "Flags", "icmpv6.nd.ra.flag", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_nd_ra_flag_m,
          { "Managed address configuration", "icmpv6.nd.ra.flag.m", FT_BOOLEAN, 8, TFS(&tfs_set_notset), ND_RA_FLAG_M,
            "When set, it indicates that addresses are available via DHCPv6", HFILL }},
        { &hf_icmpv6_nd_ra_flag_o,
          { "Other configuration", "icmpv6.nd.ra.flag.o", FT_BOOLEAN, 8, TFS(&tfs_set_notset), ND_RA_FLAG_O,
            "When set, it indicates that other configuration information is available via DHCPv6", HFILL }},
        { &hf_icmpv6_nd_ra_flag_h,
          { "Home Agent", "icmpv6.nd.ra.flag.h", FT_BOOLEAN, 8, TFS(&tfs_set_notset), ND_RA_FLAG_H,
            "When set, it indicate that the router sending this Router Advertisement is also functioning as a Mobile IPv6 home agent on this link", HFILL }},
        { &hf_icmpv6_nd_ra_flag_prf,
          { "Prf (Default Router Preference)", "icmpv6.nd.ra.flag.prf", FT_UINT8, BASE_DEC, VALS(nd_flag_router_pref), ND_RA_FLAG_PRF,
            "Indicates whether to prefer this router over other default routers", HFILL }},
        { &hf_icmpv6_nd_ra_flag_p,
          { "Proxy", "icmpv6.nd.ra.flag.p", FT_BOOLEAN, 8, TFS(&tfs_set_notset), ND_RA_FLAG_P,
           NULL, HFILL }},
        { &hf_icmpv6_nd_ra_flag_rsv,
          { "Reserved", "icmpv6.nd.ra.flag.rsv", FT_UINT8, BASE_DEC, NULL, ND_RA_FLAG_RSV,
            "Must be Zero", HFILL }},
        { &hf_icmpv6_nd_ra_router_lifetime,
          { "Router lifetime (s)", "icmpv6.nd.ra.router_lifetime", FT_UINT16, BASE_DEC, NULL, 0x0,
            "The lifetime associated with the default router", HFILL }},
        { &hf_icmpv6_nd_ra_reachable_time,
          { "Reachable time (ms)", "icmpv6.nd.ra.reachable_time", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The time that a node assumes a neighbor is reachable after having received a reachability confirmation", HFILL }},
        { &hf_icmpv6_nd_ra_retrans_timer,
          { "Retrans timer (ms)", "icmpv6.nd.ra.retrans_timer", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The time between retransmitted Neighbor Solicitation messages", HFILL }},
        { &hf_icmpv6_nd_ns_target_address,
          { "Target Address", "icmpv6.nd.ns.target_address", FT_IPv6, BASE_NONE, NULL, 0x0,
            "The IP address of the target of the solicitation", HFILL }},
        { &hf_icmpv6_nd_na_flag,
          { "Flags", "icmpv6.nd.na.flag", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_nd_na_flag_r,
          { "Router", "icmpv6.nd.na.flag.r", FT_BOOLEAN, 32, TFS(&tfs_set_notset), ND_NA_FLAG_R,
            "When set, it indicates that the sender is a router", HFILL }},
        { &hf_icmpv6_nd_na_flag_s,
          { "Solicited", "icmpv6.nd.na.flag.s", FT_BOOLEAN, 32, TFS(&tfs_set_notset), ND_NA_FLAG_S,
            "When set, it indicates that the advertisement was sent in response to a Neighbor Solicitation from the Destination address", HFILL }},
        { &hf_icmpv6_nd_na_flag_o,
          { "Override", "icmpv6.nd.na.flag.o", FT_BOOLEAN, 32, TFS(&tfs_set_notset), ND_NA_FLAG_O,
            "When set, it indicates that the advertisement should override an existing cache entry and update the cached link-layer address", HFILL }},
        { &hf_icmpv6_nd_na_flag_rsv,
          { "Reserved", "icmpv6.nd.na.flag.rsv", FT_UINT32, BASE_DEC, NULL, ND_NA_FLAG_RSV,
            "Must be Zero", HFILL }},
        { &hf_icmpv6_nd_na_target_address,
          { "Target Address", "icmpv6.nd.na.target_address", FT_IPv6, BASE_NONE, NULL, 0x0,
            "the Target Address field in the Neighbor Solicitation message that prompted this advertisement", HFILL }},
        { &hf_icmpv6_nd_rd_target_address,
          { "Target Address", "icmpv6.nd.rd.target_address", FT_IPv6, BASE_NONE, NULL, 0x0,
            "An IP address that is a better first hop to use for the ICMP Destination Address", HFILL }},
        { &hf_icmpv6_nd_rd_destination_address,
          { "Destination Address", "icmpv6.rd.na.destination_address", FT_IPv6, BASE_NONE, NULL, 0x0,
            "The IP address of the destination that is redirected to the target", HFILL }},
        { &hf_icmpv6_opt,
          { "ICMPv6 Option", "icmpv6.opt", FT_NONE, BASE_NONE, NULL, 0x0,
            "Option", HFILL }},
        { &hf_icmpv6_opt_type,
          { "Type", "icmpv6.opt.type", FT_UINT8, BASE_DEC, VALS(option_vals), 0x0,
            "Options type", HFILL }},
        { &hf_icmpv6_opt_length,
          { "Length", "icmpv6.opt.length", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The length (in units of 8 bytes) of the option (including the Type and Length fields)", HFILL }},
        { &hf_icmpv6_opt_reserved,
          { "Reserved", "icmpv6.opt.reserved", FT_NONE, BASE_NONE, NULL, 0x0,
            "Reserved (Must be 0)", HFILL }},
        { &hf_icmpv6_opt_padding,
          { "Padding", "icmpv6.opt.padding", FT_NONE, BASE_NONE, NULL, 0x0,
            "Padding (Must be 0)", HFILL }},
        { &hf_icmpv6_opt_linkaddr,
          { "Link-layer address", "icmpv6.opt.linkaddr", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
       { &hf_icmpv6_opt_src_linkaddr,
          { "Source Link-layer address", "icmpv6.opt.src_linkaddr", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
       { &hf_icmpv6_opt_target_linkaddr,
          { "Target Link-layer address", "icmpv6.opt.target_linkaddr", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_linkaddr_mac,
          { "Link-layer address", "icmpv6.opt.linkaddr", FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
       { &hf_icmpv6_opt_src_linkaddr_mac,
          { "Source Link-layer address", "icmpv6.opt.src_linkaddr", FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
       { &hf_icmpv6_opt_target_linkaddr_mac,
          { "Target Link-layer address", "icmpv6.opt.target_linkaddr", FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_linkaddr_eui64,
          { "Link-layer address", "icmpv6.opt.linkaddr", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
       { &hf_icmpv6_opt_src_linkaddr_eui64,
          { "Source Link-layer address", "icmpv6.opt.src_linkaddr", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
       { &hf_icmpv6_opt_target_linkaddr_eui64,
          { "Target Link-layer address", "icmpv6.opt.target_linkaddr", FT_EUI64, BASE_NONE, NULL, 0x0,
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
          { "Autonomous address-configuration flag(A)", "icmpv6.opt.prefix.flag.a", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
            "When set indicates that this prefix can be used for stateless address configuration", HFILL }},
        { &hf_icmpv6_opt_prefix_flag_r,
          { "Router address flag(R)", "icmpv6.opt.prefix.flag.r", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
            "When set indicates that the Prefix field contains a complete IP address assigned to the sending router", HFILL }},
        { &hf_icmpv6_opt_prefix_flag_reserved,
          { "Reserved", "icmpv6.opt.prefix.flag.reserved", FT_UINT8, BASE_DEC, NULL, 0x1f,
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
          { "Pad Length", "icmpv6.opt.cga.pad_length", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Pad Length (in bytes)", HFILL }},
        { &hf_icmpv6_opt_cga,
          { "CGA", "icmpv6.opt.cga", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_cga_modifier,
          { "Modifier", "icmpv6.opt.cga.modifier", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_cga_subnet_prefix,
          { "Subnet Prefix", "icmpv6.opt.cga.subnet_prefix", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_cga_count,
          { "Count", "icmpv6.opt.cga.count", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_cga_ext_type,
          { "Ext Type", "icmpv6.opt.cga.ext_type", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_cga_ext_length,
          { "Ext Length", "icmpv6.opt.cga.ext_length", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_cga_ext_data,
          { "Ext Data", "icmpv6.opt.cga.ext_length", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_rsa_key_hash,
          { "Key Hash", "icmpv6.opt.rsa.key_hash", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_digital_signature_padding,
          { "Digital Signature and Padding", "icmpv6.opt.digital_signature_padding", FT_NONE, BASE_NONE, NULL, 0x0,
            "TO DO FIX ME !!", HFILL }},
        { &hf_icmpv6_opt_ps_key_hash,
          { "Key Hash", "icmpv6.opt.ps.key_hash", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_timestamp,
          { "Timestamp", "icmpv6.opt.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
            "The value indicates the number of seconds since January 1, 1970, 00:00 UTC", HFILL }},
        { &hf_icmpv6_opt_nonce,
          { "Nonce", "icmpv6.opt.nonce", FT_BYTES, BASE_NONE, NULL, 0x0,
            "A field containing a random number selected by the sender of the solicitation message", HFILL }},
        { &hf_icmpv6_opt_certificate_padding,
          { "Certificat and Padding", "icmpv6.opt.certificate_padding", FT_NONE, BASE_NONE, NULL, 0x0,
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
          { "Distance", "icmpv6.opt.map.distance", FT_UINT8, BASE_DEC, NULL, 0xF0,
            "Identifying the distance between MAP and the receiver of the advertisement (in the number of hops)", HFILL }},
        { &hf_icmpv6_opt_map_pref,
          { "Preference", "icmpv6.opt.map.preference", FT_UINT8, BASE_DEC, NULL, 0x0F,
            "Used as an indicator of operator preference (Highest is better)", HFILL }},
        { &hf_icmpv6_opt_map_flag,
          { "Flag", "icmpv6.opt.map.flag", FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }},
        { &hf_icmpv6_opt_map_flag_r,
          { "RCoA Flag", "icmpv6.opt.map.flag.r", FT_BOOLEAN, 8, NULL, 0x80,
            "It indicates that the mobile node is allocated the RCoA by the MAP", HFILL }},
        { &hf_icmpv6_opt_map_flag_reserved,
          { "Reserved", "icmpv6.opt.map.flag.reserved", FT_UINT8, BASE_DEC, NULL, 0x7F,
            "Must be 0", HFILL }},
        { &hf_icmpv6_opt_map_valid_lifetime,
          { "Valid Lifetime", "icmpv6.opt.map.valid_lifetime", FT_UINT32, BASE_DEC, NULL, 0x0,
            "This value indicates the validity of the MAP's address and the RCoA.", HFILL }},
        { &hf_icmpv6_opt_map_global_address,
          { "Global Address", "icmpv6.opt.map.global_address", FT_IPv6, BASE_NONE, NULL, 0x0,
            "TOne of the MAP's global addresses", HFILL }},
        { &hf_icmpv6_opt_route_info_flag,
          { "Flag", "icmpv6.opt.route_info.flag", FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }},
        { &hf_icmpv6_opt_route_info_flag_route_preference,
          { "Route Preference", "icmpv6.opt.route_info.flag.route_preference", FT_UINT8, BASE_DEC, VALS(nd_flag_router_pref), ND_RA_FLAG_RTPREF_MASK,
            "The Route Preference indicates whether to prefer the router associated with this prefix over others", HFILL }},
        { &hf_icmpv6_opt_route_info_flag_reserved,
          { "Reserved", "icmpv6.opt.route_info.flag.reserved", FT_UINT8, BASE_DEC, NULL, ND_RA_FLAG_RESERV_MASK,
            "Must be 0", HFILL }},
        { &hf_icmpv6_opt_route_lifetime,
          { "Route Lifetime", "icmpv6.opt.route_lifetime", FT_UINT32, BASE_DEC, NULL, 0x00,
            "The length of time in seconds that the prefix is valid for the purpose of route determination", HFILL }},
        { &hf_icmpv6_opt_name_type,
          { "Name Type", "icmpv6.opt.name_type", FT_UINT8, BASE_DEC, VALS(icmpv6_option_name_type_vals), 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_name_x501,
          { "DER Encoded X.501 Name", "icmpv6.opt.name_x501", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_name_fqdn,
          { "FQDN", "icmpv6.opt.name_type.fqdn", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_opt_cert_type,
          { "Cert Type", "icmpv6.opt.name_type", FT_UINT8, BASE_DEC, VALS(icmpv6_option_cert_type_vals), 0x0,
            NULL, HFILL }},
        /* RFC3971:  SEcure Neighbor Discovery (SEND) */
        { &hf_icmpv6_send_identifier,
          { "Identifier", "icmpv6.send.identifier", FT_UINT16, BASE_DEC, NULL, 0x0,
            "An identifier to aid in matching with Request and Reply", HFILL }},
        { &hf_icmpv6_send_all_components,
          { "All Components", "icmpv6.send.all_components", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Inform the receiver of the number of certificates in the entire path", HFILL }},
        { &hf_icmpv6_send_component,
          { "Component", "icmpv6.send.component", FT_UINT16, BASE_DEC, NULL, 0x0,
            "If the field is set to 65,535 if the sender seeks to retrieve all certificates", HFILL }},

        { &hf_icmpv6_x509if_Name,
          { "Name", "icmpv6.x509_Name", FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_x509af_Certificate,
          { "Certificate", "icmpv6.x509_Certificate", FT_NONE, BASE_NONE, NULL, 0x0,
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
          { "Prf (Default Router Preference)", "icmpv6.opt.efo.prf", FT_UINT16, BASE_DEC, VALS(nd_flag_router_pref), FLAGS_EO_PRF,
            "Indicates whether to prefer this router over other default routers", HFILL }},
        { &hf_icmpv6_opt_efo_p,
          { "Proxy", "icmpv6.opt.efo.p", FT_BOOLEAN, 16, TFS(&tfs_set_notset), FLAGS_EO_P,
           NULL, HFILL }},
        { &hf_icmpv6_opt_efo_rsv,
          { "Reserved", "icmpv6.opt.efo.rsv", FT_UINT16, BASE_DEC, NULL, FLAGS_EO_RSV,
            "Must be Zero", HFILL }},
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
          { "Status", "icmpv6.opt.aro.status", FT_UINT8, BASE_DEC, VALS(nd_opt_6lowpannd_status_val), 0x00,
            "Indicates the status of a registration in the NA response", HFILL }},
        { &hf_icmpv6_opt_aro_registration_lifetime,
          { "Registration  Lifetime", "icmpv6.opt.aro.registration_lifetime", FT_UINT16, BASE_DEC, NULL, 0x00,
            "The amount of time (in a unit of 60 seconds) that the router should retain the Neighbor Cache entry", HFILL }},
        { &hf_icmpv6_opt_aro_eui64,
          { "EUI-64", "icmpv6.opt.aro.eui64", FT_EUI64, BASE_NONE, NULL, 0x00,
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
            "The length of time in a unit of 60 seconds that the context is valid for the purpose of header compression or decompression", HFILL }},
        { &hf_icmpv6_opt_6co_context_prefix,
          { "Context Prefix", "icmpv6.opt.6co.context_prefix", FT_IPv6, BASE_NONE, NULL, 0x00,
            "The IPv6 prefix or address corresponding to the Context ID (CID) field", HFILL }},
        { &hf_icmpv6_opt_abro_version,
          { "Version", "icmpv6.opt.abro.version", FT_UINT16, BASE_DEC, NULL, 0x00,
            "The version number corresponding to this set of information contained in the RA message", HFILL }},
        { &hf_icmpv6_opt_abro_6lbr_address,
          { "6LBR Address", "icmpv6.opt.abro.6lbr_address", FT_IPv6, BASE_NONE, NULL, 0x00,
            "IPv6 address of the 6LBR that is the origin of the included version number", HFILL }},

        /* RFC2710:  Multicast Listener Discovery for IPv6 */
        { &hf_icmpv6_mld_mrd,
          { "Maximum Response Delay [ms]", "icmpv6.mld.maximum_response_delay", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Specifies the maximum allowed delay before sending a responding Report, in units of milliseconds", HFILL }},
        { &hf_icmpv6_mld_multicast_address,
          { "Multicast Address", "icmpv6.mld.multicast_address", FT_IPv6, BASE_NONE, NULL, 0x0,
            "Specific IPv6 multicast address", HFILL }},
        /* RFC 2894: Router Renumbering for IPv6 */
        { &hf_icmpv6_rr_sequencenumber,
           { "Sequence Number", "icmpv6.rr.sequence_number", FT_UINT32, BASE_DEC, NULL, 0x0,
             "The sequence number MUST be non-decreasing between Sequence Number Resets", HFILL }},
        { &hf_icmpv6_rr_segmentnumber,
           { "Segment Number", "icmpv6.rr.segment_number", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Enumerates different valid RR messages having the same Sequence Number", HFILL }},
        { &hf_icmpv6_rr_flag,
           { "Flags", "icmpv6.rr.flag", FT_UINT8, BASE_HEX, NULL, 0x0,
             "Five are defined and three bits are reserved", HFILL }},
        { &hf_icmpv6_rr_flag_t,
           { "Test Command", "icmpv6.rr.flag.t", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RR_FLAG_T,
             "Indicates a Test message: processing is to be simulated and no configuration changes are to be made", HFILL }},
        { &hf_icmpv6_rr_flag_r,
           { "Result requested", "icmpv6.rr.flag.r", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RR_FLAG_R,
             "Indicates that the router send a Result message upon completion of processing the Command message", HFILL }},
        { &hf_icmpv6_rr_flag_a,
           { "All Interfaces", "icmpv6.rr.flag.a", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RR_FLAG_A,
             "Indicates that the Command be applied to all interfaces regardless of administrative shutdown status", HFILL }},
        { &hf_icmpv6_rr_flag_s,
           { "Site-specific", "icmpv6.rr.flag.s", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RR_FLAG_S,
             "Indicates that the Command be applied only to interfaces which belong to the same site as the interface to which the Command is addressed", HFILL }},
        { &hf_icmpv6_rr_flag_p,
           { "Processed previously", "icmpv6.rr.flag.p", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RR_FLAG_P,
             "Indicates that the Command message was previously processed (and is not a Test) and the responding router is not processing it again", HFILL }},
        { &hf_icmpv6_rr_flag_rsv,
           { "Reserved", "icmpv6.rr.flag.rsv", FT_UINT8, BASE_DEC, NULL, RR_FLAG_RSV,
             "Must be Zero", HFILL }},
        { &hf_icmpv6_rr_maxdelay,
           { "Max Delay", "icmpv6.rr.maxdelay", FT_UINT16, BASE_DEC, NULL, 0x0,
             "Specifying the maximum time (in milliseconds) by which a router MUST delay sending any reply to this Command", HFILL }},

        { &hf_icmpv6_rr_pco_mp_part,
           { "Match-Prefix Part", "icmpv6.rr.pco.mp", FT_NONE, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rr_pco_mp_opcode,
           { "OpCode", "icmpv6.rr.pco.mp.opcode", FT_UINT8, BASE_DEC, VALS(rr_pco_mp_opcode_val), 0x0,
             "Specifying the operation to be performed when the associated MatchPrefix matches an interface's prefix or address", HFILL }},
        { &hf_icmpv6_rr_pco_mp_oplength,
           { "OpLength", "icmpv6.rr.pco.mp.oplength", FT_UINT8, BASE_DEC, NULL, 0x0,
             "The total length of this Prefix Control Operation (in units of 8 octets)", HFILL }},
        { &hf_icmpv6_rr_pco_mp_ordinal,
           { "Ordinal", "icmpv6.rr.pco.mp.ordinal", FT_UINT8, BASE_HEX, NULL, 0x0,
             "The value is otherwise unconstrained", HFILL }},
        { &hf_icmpv6_rr_pco_mp_matchlen,
           { "MatchLen", "icmpv6.rr.pco.mp.matchlen", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Between 0 and 128 inclusive specifying the number of initial bits of MatchPrefix which are significant in matching", HFILL }},
        { &hf_icmpv6_rr_pco_mp_minlen,
           { "MinLen", "icmpv6.rr.pco.mp.minlen", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Specifying the minimum length which any configured prefix must have in order to be eligible for testing against the MatchPrefix", HFILL }},
        { &hf_icmpv6_rr_pco_mp_maxlen,
           { "MaxLen", "icmpv6.rr.pco.mp.maxlen", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Specifying the maximum length which any configured prefix must have in order to be eligible for testing against the MatchPrefix", HFILL }},
        { &hf_icmpv6_rr_pco_mp_matchprefix,
           { "MatchPrefix", "icmpv6.rr.pco.mp.matchprefix", FT_IPv6, BASE_NONE, NULL, 0x0,
             "The 128-bit prefix to be compared with each interface's prefix or address", HFILL }},
        { &hf_icmpv6_rr_pco_up_part,
           { "Use-Prefix Part", "icmpv6.rr.pco.up", FT_NONE, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rr_pco_up_uselen,
           { "UseLen", "icmpv6.rr.pco.up.uselen", FT_UINT8, BASE_DEC, NULL, 0x0,
             "specifying the number of initial bits of UsePrefix to use in creating a new prefix for an interface", HFILL }},
        { &hf_icmpv6_rr_pco_up_keeplen,
           { "KeepLen", "icmpv6.rr.pco.up.keeplen", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Specifying the number of bits of the prefix or address which matched the associated Match-Prefix which should be retained in the new prefix", HFILL }},
        { &hf_icmpv6_rr_pco_up_flagmask,
           { "FlagMask", "icmpv6.rr.pco.up.flagmask", FT_UINT8, BASE_HEX, NULL, 0x0,
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
           { "RAFlags", "icmpv6.rr.pco.up.raflags", FT_UINT8, BASE_HEX, NULL, 0x0,
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
           { "Valid Lifetime", "icmpv6.rr.pco.up.validlifetime", FT_UINT32, BASE_DEC, NULL, 0x0,
             "The number of seconds for which the New Prefix will be valid", HFILL }},
        { &hf_icmpv6_rr_pco_up_preferredlifetime,
           { "Preferred Lifetime", "icmpv6.rr.pco.up.preferredlifetime", FT_UINT32, BASE_DEC, NULL, 0x0,
             "The number of seconds for which the New Prefix will be preferred", HFILL }},
        { &hf_icmpv6_rr_pco_up_flag,
           { "Flags", "icmpv6.rr.pco.up.flag", FT_UINT32, BASE_HEX, NULL, 0x0,
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
           { "UsePrefix", "icmpv6.rr.pco.up.useprefix", FT_IPv6, BASE_NONE, NULL, 0x0,
             "The 128-bit Use-prefix which either becomes or is used in forming (if KeepLen is nonzero) the New Prefix", HFILL }},
        { &hf_icmpv6_rr_rm,
           { "Result Message", "icmpv6.rr.rm", FT_NONE, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rr_rm_flag,
           { "Flags", "icmpv6.rr.rm.flag", FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rr_rm_flag_b,
          { "Bounds", "icmpv6.rr.rm.flag.b", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0002,
            "When set, indicates that one or more fields in the associated PCO were out of bounds", HFILL }},
        { &hf_icmpv6_rr_rm_flag_f,
          { "Forbidden", "icmpv6.rr.rm.flag.f", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0001,
            "When set, indicates that one or more Use-Prefix parts from the associated PCO were not honored by the router because of attempted formation of a forbidden prefix format, such as a multicast or loopback address", HFILL }},
        { &hf_icmpv6_rr_rm_flag_reserved,
          { "Reserved", "icmpv6.rr.rm.flag.reserved", FT_UINT16, BASE_DEC, NULL, 0xFFFC,
            "Must be Zero", HFILL }},
        { &hf_icmpv6_rr_rm_ordinal,
           { "Ordinal", "icmpv6.rr.rm.ordinal", FT_UINT8, BASE_HEX, NULL, 0x0,
             "The value is otherwise unconstrained", HFILL }},
        { &hf_icmpv6_rr_rm_matchedlen,
           { "MatchedLen", "icmpv6.rr.rm.matchedlen", FT_UINT8, BASE_DEC, NULL, 0x0,
             "The length of the Matched Prefix", HFILL }},
        { &hf_icmpv6_rr_rm_interfaceindex,
           { "InterfaceIndex", "icmpv6.rr.rm.interfaceindex", FT_UINT32, BASE_DEC, NULL, 0x0,
             "The router's numeric designation of the interface on which the MatchedPrefix was configured", HFILL }},
        { &hf_icmpv6_rr_rm_matchedprefix,
           { "MatchedPrefix", "icmpv6.rr.rm.matchedprefix", FT_IPv6, BASE_NONE, NULL, 0x0,
             "The 128 Bits MatchedPrefix", HFILL }},

        /* RFC3775/6275: Mobility Support in IPv6 */
        { &hf_icmpv6_mip6_identifier,
          { "Identifier", "icmpv6.mip6.identifier", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            "An identifier to aid in matching with Request and Reply", HFILL }},
        { &hf_icmpv6_mip6_home_agent_address,
          { "Home Agent Address", "icmpv6.mip6.home_agent_address", FT_IPv6, BASE_NONE, NULL, 0x0,
            "A list of addresses of home agents on the home link for the mobile node", HFILL }},
        { &hf_icmpv6_mip6_flag,
          { "Flags", "icmpv6.mip6.flag", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_icmpv6_mip6_flag_m,
          { "Managed address configuration", "icmpv6.mip6.flag.m", FT_BOOLEAN, 16, TFS(&tfs_set_notset), FLAGS_EO_M,
            "When set, it indicates that addresses are available via DHCPv6", HFILL }},
        { &hf_icmpv6_mip6_flag_o,
          { "Other configuration", "icmpv6.mip6.flag.o", FT_BOOLEAN, 16, TFS(&tfs_set_notset), FLAGS_EO_O,
            "When set, it indicates that other configuration information is available via DHCPv6", HFILL }},
        { &hf_icmpv6_mip6_flag_rsv,
          { "Reserved", "icmpv6.mip6.flag.rsv", FT_UINT16, BASE_DEC, NULL, 0x2FFF,
            "Must be Zero", HFILL }},

        /* RFC3810: Multicast Listener Discovery Version 2 (MLDv2) for IPv6 */
        { &hf_icmpv6_mld_mrc,
          { "Maximum Response Code", "icmpv6.mld.maximum_response_code", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Specifies the maximum allowed delay before sending a responding Report", HFILL }},
       { &hf_icmpv6_mld_flag,
          { "Flags", "icmpv6.mld.flag", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
       { &hf_icmpv6_mld_flag_s,
          { "Suppress Router-Side Processing", "icmpv6.mld.flag.s", FT_BOOLEAN, 8, NULL, MLD_FLAG_S,
            "Indicates to any receiving multicast routers that they have to suppress the normal timer updates they perform upon hearing a Query", HFILL }},
       { &hf_icmpv6_mld_flag_qrv,
          { "QRV (Querier's Robustness Variable)", "icmpv6.mld.flag.qrv", FT_UINT8, BASE_DEC, NULL, MLD_FLAG_QRV,
            "Contains the RV (Robustness Variable) value used by the Querier", HFILL }},
       { &hf_icmpv6_mld_flag_rsv,
          { "Reserved", "icmpv6.mld.flag.reserved", FT_UINT8, BASE_DEC, NULL, MLD_FLAG_RSV,
            "Must Be Zero", HFILL }},
       { &hf_icmpv6_mld_qqi,
          { "QQIC (Querier's Query Interval Code)", "icmpv6.mld.qqi", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Specifies the QI (Query Interval) used by the Querier", HFILL }},
       { &hf_icmpv6_mld_nb_sources,
          { "Number of Sources", "icmpv6.mld.nb_sources", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Specifies how many source addresses are present in the Query", HFILL }},
       { &hf_icmpv6_mld_source_address,
          { "Source Address", "icmpv6.mld.source_address", FT_IPv6, BASE_NONE, NULL, 0x0,
            "The Source Address fields are a vector of unicast addresses", HFILL }},
        { &hf_icmpv6_mldr_nb_mcast_records,
          { "Number of Multicast Address Records", "icmpv6.mldr.nb_mcast_records", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Specifies how many Multicast Address Records are present in this Report", HFILL }},
        { &hf_icmpv6_mldr_mar,
          { "Multicast Address Record", "icmpv6.mldr.mar", FT_NONE, BASE_NONE, NULL, 0x0,
            "Each Multicast Address Record is a block of fields that contain information on the sender listening to a single multicast address on the interface from which the Report is sent", HFILL }},
        { &hf_icmpv6_mldr_mar_record_type,
          { "Record Type", "icmpv6.mldr.mar.record_type", FT_UINT8, BASE_DEC, VALS(mldr_record_type_val), 0x0,
            "It specifies the type of the Multicast Address Record", HFILL }},
        { &hf_icmpv6_mldr_mar_aux_data_len,
          { "Aux Data Len", "icmpv6.mldr.mar.aux_data_len", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The Aux Data Len field contains the length (in units of 32-bit words) of the Auxiliary Data Field in this Multicast Address Record", HFILL }},
        { &hf_icmpv6_mldr_mar_nb_sources,
          { "Number of Sources", "icmpv6.mldr.mar.nb_sources", FT_UINT16, BASE_DEC, NULL, 0x0,
            "The Number of Sources field specifies how many source addresses are present in this Multicast Address Record", HFILL }},
        { &hf_icmpv6_mldr_mar_multicast_address,
          { "Multicast Address", "icmpv6.mldr.mar.multicast_address", FT_IPv6, BASE_NONE, NULL, 0x0,
            "The Multicast Address field contains the multicast address to which this Multicast Address Record pertains", HFILL }},
        { &hf_icmpv6_mldr_mar_source_address,
          { "Source Address", "icmpv6.mldr.mar.source_address", FT_IPv6, BASE_NONE, NULL, 0x0,
            "The Source Address fields are a vector of unicast addresses", HFILL }},
        { &hf_icmpv6_mldr_mar_auxiliary_data,
          { "Auxiliary Data", "icmpv6.mldr.mar.auxiliary_data", FT_BYTES, BASE_NONE, NULL, 0x0,
            "Contains additional information that pertain to this Multicast Address Record", HFILL }},
        /* RFC 4068/5268/5568: Fast Handovers for Mobile IPv6 ( Mobile IPv6 Fast Handovers ) */
        { &hf_icmpv6_fmip6_subtype,
           { "Subtype", "icmpv6.fmip6.subtype", FT_UINT8, BASE_DEC, VALS(fmip6_subtype_val), 0x0,
             "Designates the Subtype of information", HFILL }},
        { &hf_icmpv6_fmip6_hi_flag,
          { "Flag", "icmpv6.fmip6.hi.flag", FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }},
        { &hf_icmpv6_fmip6_hi_flag_s,
          { "Assigned address configuration", "icmpv6.fmip6.hi.flag.s", FT_BOOLEAN, 8, TFS(&tfs_set_notset), FMIP6_HI_FLAG_S,
            "When set, this message requests a new CoA to be returned by the destination", HFILL }},
        { &hf_icmpv6_fmip6_hi_flag_u,
          { "Buffer", "icmpv6.fmip6.hi.flag.a", FT_BOOLEAN, 8, TFS(&tfs_set_notset), FMIP6_HI_FLAG_U,
            "When set, the destination SHOULD buffer any packets toward the node indicated in the options of this message", HFILL }},
        { &hf_icmpv6_fmip6_hi_flag_reserved,
          { "Reserved", "icmpv6.fmip6.hi.flag.reserved", FT_UINT8, BASE_DEC, NULL, FMIP6_HI_FLAG_RSV,
            NULL, HFILL }},
        { &hf_icmpv6_fmip6_identifier,
          { "Identifier", "icmpv6.fmip6.identifier", FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            "An identifier to aid in matching with Request and Reply", HFILL }},

        /* RFC 4286: Multicast Router Discovery */
        { &hf_icmpv6_mcast_ra_query_interval,
          { "Query Interval", "icmpv6.mcast_ra.query_interval", FT_UINT16, BASE_DEC, NULL, 0x0,
            "The Query Interval value (in seconds) in use by MLD on the interface.", HFILL }},
        { &hf_icmpv6_mcast_ra_robustness_variable,
          { "Robustness Variable", "icmpv6.mcast_ra.robustness_variable", FT_UINT16, BASE_DEC, NULL, 0x0,
            "The Robustness Variable in use by MLD on the advertising interface", HFILL }},

        /* RFC 4620: IPv6 Node Information Queries */
        { &hf_icmpv6_ni_qtype,
           { "Qtype", "icmpv6.ni.qtype", FT_UINT16, BASE_DEC, VALS(ni_qtype_val), 0x0,
             "Designates the type of information", HFILL }},
        { &hf_icmpv6_ni_flag,
           { "Flags", "icmpv6.ni.flag", FT_UINT16, BASE_HEX, NULL, 0x0,
             "Qtype-specific flags that may be defined for certain Query types and their Replies", HFILL }},
        { &hf_icmpv6_ni_flag_g,
           { "Global-scope addresses", "icmpv6.ni.flag.g", FT_BOOLEAN, 16, TFS(&tfs_set_notset), NI_FLAG_G,
             "Global-scope addresses are requested", HFILL }},
        { &hf_icmpv6_ni_flag_s,
           { "Site-local addresses", "icmpv6.ni.flag.s", FT_BOOLEAN, 16, TFS(&tfs_set_notset), NI_FLAG_S,
             "Site-local addresses are requested", HFILL }},
        { &hf_icmpv6_ni_flag_l,
           { "Link-local addresses", "icmpv6.ni.flag.l", FT_BOOLEAN, 16, TFS(&tfs_set_notset), NI_FLAG_L,
             "Link-local addresses are requested", HFILL }},
        { &hf_icmpv6_ni_flag_c,
           { "Compression", "icmpv6.ni.flag.c", FT_BOOLEAN, 16, TFS(&tfs_set_notset), NI_FLAG_C,
             "IPv4-compatible (now deprecated) and IPv4-mapped addresses are requested", HFILL }},
        { &hf_icmpv6_ni_flag_a,
           { "Unicast Addresses", "icmpv6.ni.flag.a", FT_BOOLEAN, 16, TFS(&tfs_ni_flag_a), NI_FLAG_A,
             "Responder's unicast addresses", HFILL }},
        { &hf_icmpv6_ni_flag_t,
           { "Truncated", "icmpv6.ni.flag.t", FT_BOOLEAN, 16, TFS(&tfs_set_notset), NI_FLAG_T,
             "Defined in a Reply only, indicates that the set of addresses is incomplete for space reasons", HFILL }},
        { &hf_icmpv6_ni_flag_rsv,
           { "Reserved", "icmpv6.ni.flag.rsv", FT_UINT16, BASE_HEX, NULL, NI_FLAG_RSV,
             "Must be Zero", HFILL }},
        { &hf_icmpv6_ni_nonce,
           { "Nonce", "icmpv6.ni.nonce", FT_UINT64, BASE_HEX, NULL, 0x0,
             "An opaque 64-bit field", HFILL }},
        { &hf_icmpv6_ni_query_subject_ipv6,
           { "IPv6 subject address", "icmpv6.ni.query.subject_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_ni_query_subject_fqdn,
           { "FQDN subject", "icmpv6.ni.query.subject_fqdn", FT_STRING, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_ni_query_subject_ipv4,
           { "IPv4 subject address", "icmpv6.ni.query.subject_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_ni_reply_node_ttl,
           { "TTL", "icmpv6.ni.query.subject_ipv4", FT_UINT32, BASE_DEC, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_ni_reply_node_name,
           { "Name Node", "icmpv6.ni.query.node_name", FT_STRING, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_ni_reply_node_address,
           { "IPv6 Node address", "icmpv6.ni.query.node_address", FT_IPv6, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_ni_reply_ipv4_address,
           { "IPv4 Node address", "icmpv6.ni.query.ipv4_address", FT_IPv4, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},

        /* RPL: draft-ietf-roll-rpl-19.txt: Routing over Low-Power and Lossy Networks. */
        { &hf_icmpv6_rpl_dis_flag,
           { "Flags", "icmpv6.rpl.dis.flags", FT_UINT8, BASE_DEC, NULL, 0x0,
             "8-bit unused field reserved for flags", HFILL }},
        { &hf_icmpv6_rpl_dio_instance,
           { "RPLInstanceID", "icmpv6.rpl.dio.instance", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Set by the DODAG root that indicates which RPL Instance the DODAG is part of", HFILL }},
        { &hf_icmpv6_rpl_dio_version,
           { "Version", "icmpv6.rpl.dio.version", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Set by the DODAG root to the DODAGVersionNumber", HFILL }},
        { &hf_icmpv6_rpl_dio_rank,
           { "Rank", "icmpv6.rpl.dio.rank", FT_UINT16, BASE_DEC, NULL, 0x0,
             "Indicating the DODAG rank of the node sending the DIO message", HFILL }},
        { &hf_icmpv6_rpl_dio_flag,
           { "Flags", "icmpv6.rpl.dio.flag", FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rpl_dio_flag_g,
           { "Grounded (G)", "icmpv6.rpl.dio.flag.g", FT_BOOLEAN, 8, NULL, RPL_DIO_FLAG_G,
             "Indicates whether the DODAG advertised can satisfy the application-defined goal", HFILL }},
        { &hf_icmpv6_rpl_dio_flag_0,
           { "Zero", "icmpv6.rpl.dio.flag.0", FT_BOOLEAN, 8, NULL, RPL_DIO_FLAG_0,
             NULL, HFILL }},
        { &hf_icmpv6_rpl_dio_flag_mop,
           { "Mode of Operation (MOP)", "icmpv6.rpl.dio.flag.mop", FT_UINT8, BASE_HEX, VALS(rpl_dio_map_val), RPL_DIO_FLAG_MOP,
             "Identifies the mode of operation of the RPL Instance as administratively provisioned at and distributed by the DODAG Root", HFILL }},
        { &hf_icmpv6_rpl_dio_flag_prf,
           { "DODAG Preference", "icmpv6.rpl.dio.flag.preference", FT_UINT8, BASE_DEC, NULL, RPL_DIO_FLAG_PRF,
             "Defines how preferable the root of this DODAG is compared to other DODAG roots within the instance", HFILL }},
        { &hf_icmpv6_rpl_dio_dtsn,
           { "Destination Advertisement Trigger Sequence Number (DTSN)", "icmpv6.rpl.dio.dtsn", FT_UINT8, BASE_DEC, NULL, 0x0,
             "The DTSN is used as part of the procedure to maintain downward routes.", HFILL }},
        { &hf_icmpv6_rpl_dio_dagid,
           { "DODAGID", "icmpv6.rpl.dio.dagid", FT_IPv6, BASE_NONE, NULL, 0x0,
             "IPv6 address set by a DODAG root which uniquely identifies a DODAG", HFILL }},
        { &hf_icmpv6_rpl_dao_instance,
           { "RPLInstanceID", "icmpv6.rpl.dao.instance", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Indicating the topology instance associated with the DODAG as learned from the DIO", HFILL }},
        { &hf_icmpv6_rpl_dao_flag,
           { "Flags", "icmpv6.rpl.dao.flag", FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rpl_dao_flag_k,
           { "DAO-ACK Request (K)", "icmpv6.rpl.dao.flag.k", FT_BOOLEAN, 8, NULL, RPL_DAO_FLAG_K,
             "Indicates that the recipient is expected to send a DAO-ACK back", HFILL }},
        { &hf_icmpv6_rpl_dao_flag_d,
           { "DODAGID Present (D)", "icmpv6.rpl.dao.flag.d", FT_BOOLEAN, 8, NULL, RPL_DAO_FLAG_D,
             "Indicates that the DODAGID field is present", HFILL }},
        { &hf_icmpv6_rpl_dao_flag_rsv,
           { "Reserved", "icmpv6.rpl.dao.flag.rsv", FT_UINT8, BASE_DEC, NULL, RPL_DAO_FLAG_RESERVED,
             "Must be zero", HFILL }},
        { &hf_icmpv6_rpl_dao_sequence,
           { "DAO Sequence", "icmpv6.rpl.dao.sequence", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Incremented at each unique DAO message from a node and echoed in the DAO-ACK message", HFILL }},
        { &hf_icmpv6_rpl_dao_dodagid,
           { "DODAGID", "icmpv6.rpl.dao.dodagid", FT_IPv6, BASE_NONE, NULL, 0x0,
             "IPv6 address set by a DODAG root which uniquely identifies a DODAG", HFILL }},
        { &hf_icmpv6_rpl_daoack_instance,
           { "RPLInstanceID", "icmpv6.rpl.daoack.instance", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Indicating the topology instance associated with the DODAG, as learned from the DIO", HFILL }},
        { &hf_icmpv6_rpl_daoack_flag,
           { "Flag", "icmpv6.rpl.daoack.flag", FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rpl_daoack_flag_d,
           { "DODAGID Present (D)", "icmpv6.rpl.daoack.flag.d", FT_BOOLEAN, 8, NULL, RPL_DAOACK_FLAG_D,
             "Indicates that the DODAGID field is present", HFILL }},
        { &hf_icmpv6_rpl_daoack_flag_rsv,
           { "Reserved", "icmpv6.rpl.daoack.flag.rsv", FT_UINT8, BASE_DEC, NULL, RPL_DAOACK_FLAG_RESERVED,
             "Must be zero", HFILL }},
        { &hf_icmpv6_rpl_daoack_sequence,
           { "DAO-ACK Sequence", "icmpv6.rpl.daoack.sequence", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Incremented at each DAO message from a node, and echoed in the DAO-ACK by the recipient", HFILL }},
        { &hf_icmpv6_rpl_daoack_status,
           { "Status", "icmpv6.rpl.daoack.status", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Indicates the completion", HFILL }},
        { &hf_icmpv6_rpl_daoack_dodagid,
           { "DODAGID", "icmpv6.rpl.daoack.dodagid", FT_IPv6, BASE_NONE, NULL, 0x0,
             "IPv6 address integer set by a DODAG root which uniquely identifies a DODAG", HFILL }},
        { &hf_icmpv6_rpl_cc_instance,
           { "RPLInstanceID", "icmpv6.rpl.cc.instance", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Indicating the topology instance associated with the DODAG, as learned from the DIO", HFILL }},
        { &hf_icmpv6_rpl_cc_flag,
           { "Flag", "icmpv6.rpl.cc.flag", FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rpl_cc_flag_r,
           { "Reponse (R)", "icmpv6.rpl.cc.flag.r", FT_BOOLEAN, 8, NULL, RPL_CC_FLAG_R,
             "Indicates whether the CC message is a response", HFILL }},
        { &hf_icmpv6_rpl_cc_flag_rsv,
           { "Reserved", "icmpv6.rpl.cc.flag.rsv", FT_UINT8, BASE_DEC, NULL, RPL_CC_FLAG_RESERVED,
             "Must be zero", HFILL }},
        { &hf_icmpv6_rpl_cc_nonce,
           { "CC Nonce", "icmpv6.rpl.cc.nonce", FT_UINT16, BASE_HEX, NULL, 0x0,
             "The corresponding CC response includes the same CC nonce value as the request, as learned from the DIO", HFILL }},
        { &hf_icmpv6_rpl_cc_dodagid,
           { "DODAGID", "icmpv6.rpl.cc.dodagid", FT_IPv6, BASE_NONE, NULL, 0x0,
             "IPv6 address integer set by a DODAG root which uniquely identifies a DODAG", HFILL }},
        { &hf_icmpv6_rpl_cc_destination_counter,
           { "Destination Counter", "icmpv6.rpl.cc.destination_counter", FT_UINT32, BASE_DEC, NULL, 0x0,
             "Indicating the sender's estimate of the destination's current security Counter value", HFILL }},
        { &hf_icmpv6_rpl_secure_flag,
           { "Flags", "icmpv6.rpl.secure.flag", FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rpl_secure_flag_t,
           { "Counter is Time (T)", "icmpv6.rpl.secure.flag.t", FT_BOOLEAN, 8, NULL, RPL_SECURE_FLAG_T,
             "If it is set then the Counter field is a timestamp", HFILL }},
        { &hf_icmpv6_rpl_secure_flag_rsv,
           { "Reserved", "icmpv6.rpl.secure.flag.rsv", FT_UINT8, BASE_DEC, NULL, RPL_SECURE_FLAG_RSV,
             "Must be zero", HFILL }},
        { &hf_icmpv6_rpl_secure_algorithm,
           { "Algorithm", "icmpv6.rpl.secure.algorithm", FT_UINT8, BASE_DEC, NULL, 0x0,
             "The Security Algorithm field specifies the encryption, MAC, and signature scheme the network uses", HFILL }},
        { &hf_icmpv6_rpl_secure_algorithm_encryption,
           { "Algorithm (Encryption)", "icmpv6.rpl.secure.algorithm.encryption", FT_UINT8, BASE_DEC, VALS(rpl_secure_algorithm_encryption_val), 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rpl_secure_algorithm_signature,
           { "Algorithm (Signature)", "icmpv6.rpl.secure.algorithm.signature", FT_UINT8, BASE_DEC, VALS(rpl_secure_algorithm_signature_val), 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rpl_secure_kim,
           { "Key Identifier Mode (KIM)", "icmpv6.rpl.secure.kim", FT_UINT8, BASE_DEC, NULL, RPL_SECURE_KIM,
             "That indicates whether the key used for packet protection is determined implicitly or explicitly and indicates the particular representation of the Key Identifier field", HFILL }},
        { &hf_icmpv6_rpl_secure_lvl,
           { "Security Level (LVL)", "icmpv6.rpl.secure.lvl", FT_UINT8, BASE_DEC, NULL, RPL_SECURE_LVL,
             "Indicates the provided packet protection", HFILL }},
        { &hf_icmpv6_rpl_secure_rsv,
           { "Reserved", "icmpv6.rpl.secure.rsv", FT_UINT8, BASE_DEC, NULL, RPL_SECURE_RSV,
             "Must be zero", HFILL }},
        { &hf_icmpv6_rpl_secure_counter,
           { "Counter", "icmpv6.rpl.secure.counter", FT_UINT32, BASE_DEC, NULL, 0x0,
             "Indicates the non-repeating 4-octet value used to construct the cryptographic mechanism that implements packet protection and allows for the provision of semantic security", HFILL }},
        { &hf_icmpv6_rpl_secure_key_source,
           { "Key Source", "icmpv6.rpl.secure.key.source", FT_BYTES, BASE_NONE, NULL, 0x0,
             "Indicates the logical identifier of the originator of a group key", HFILL }},
        { &hf_icmpv6_rpl_secure_key_index,
           { "Key Source", "icmpv6.rpl.secure.key.index", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Allows unique identification of different keys with the same originator", HFILL }},
        { &hf_icmpv6_rpl_opt,
          { "ICMPv6 RPL Option", "icmpv6.opt", FT_NONE, BASE_NONE, NULL, 0x0,
            "Option", HFILL }},
        { &hf_icmpv6_rpl_opt_type,
          { "Type", "icmpv6.rpl.opt.type", FT_UINT8, BASE_DEC, VALS(rpl_option_vals), 0x0,
            "Options type", HFILL }},
        { &hf_icmpv6_rpl_opt_length,
          { "Length", "icmpv6.rpl.opt.length", FT_UINT8, BASE_DEC, NULL, 0x0,
            "The length of the option in octets excluding the Type and Length fields", HFILL }},
        { &hf_icmpv6_rpl_opt_reserved,
          { "Reserved", "icmpv6.rpl.opt.reserved", FT_NONE, BASE_NONE, NULL, 0x0,
            "Reserved (Must be 0)", HFILL }},
        { &hf_icmpv6_rpl_opt_padn,
          { "Paddn", "icmpv6.rpl.opt.padn", FT_NONE, BASE_NONE, NULL, 0x0,
            "Padding (Must be 0)", HFILL }},
        { &hf_icmpv6_rpl_opt_route_prefix_length,
           { "Prefix Length", "icmpv6.rpl.opt.route.prefix_length", FT_UINT8, BASE_DEC, NULL, 0x0,
             "The number of leading bits in the Prefix that are valid", HFILL }},
        { &hf_icmpv6_rpl_opt_route_flag,
           { "Flag","icmpv6.rpl.opt.route.flag", FT_NONE, BASE_NONE, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rpl_opt_route_pref,
           { "Preference","icmpv6.rpl.opt.route.pref", FT_UINT8, BASE_DEC, VALS(nd_flag_router_pref), RPL_OPT_ROUTE_PREFERENCE,
             "The Route Preference indicates whether to prefer the router associated with this prefix over others, when multiple identical prefixes (for different routers) have been received", HFILL }},
        { &hf_icmpv6_rpl_opt_route_reserved,
           { "Reserved","icmpv6.rpl.opt.route.reserved", FT_UINT8, BASE_DEC, NULL, RPL_OPT_ROUTE_RESERVED,
             "Reserved (Must be Zero)", HFILL }},
        { &hf_icmpv6_rpl_opt_route_lifetime,
           { "Route Lifetime", "icmpv6.rpl.opt.route.lifetime", FT_UINT32, BASE_DEC, NULL, 0x0,
             "The length of time in seconds (relative to the time the packet is sent) that the prefix is valid for route determination", HFILL }},
        { &hf_icmpv6_rpl_opt_route_prefix,
           { "Prefix", "icmpv6.rpl.opt.route.prefix", FT_IPv6, BASE_NONE, NULL, 0x0,
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
           { "Path Control Size", "icmpv6.rpl.opt.config.pcs", FT_UINT8, BASE_DEC, NULL, RPL_OPT_CONFIG_FLAG_PCS,
             "Used to configure the number of bits that may be allocated to the Path Control field", HFILL }},
        { &hf_icmpv6_rpl_opt_config_doublings,
           { "DIOIntervalDoublings","icmpv6.rpl.opt.config.interval_double", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Used to configure Imax of the DIO trickle timer", HFILL }},
        { &hf_icmpv6_rpl_opt_config_min_interval,
           { "DIOIntervalMin", "icmpv6.rpl.opt.config.interval_min", FT_UINT16, BASE_DEC, NULL, 0x0,
             "Used to configure Imin of the DIO trickle timer", HFILL }},
        { &hf_icmpv6_rpl_opt_config_redundancy,
           { "DIORedundancyConstant", "icmpv6.rpl.opt.config.redundancy", FT_UINT8, BASE_DEC, NULL, 0x0,
             "Used to configure k of the DIO trickle timer", HFILL }},
        { &hf_icmpv6_rpl_opt_config_rank_incr,
           { "MaxRankInc", "icmpv6.rpl.opt.config.max_rank_inc", FT_UINT16, BASE_DEC, NULL, 0x0,
             "Used to configure DAGMaxRankIncrease", HFILL }},
        { &hf_icmpv6_rpl_opt_config_hop_rank_inc,
           { "MinHopRankInc", "icmpv6.rpl.opt.config.min_hop_rank_inc", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Used to configure MinHopRankIncrease", HFILL }},
        { &hf_icmpv6_rpl_opt_config_ocp,
           { "OCP (Objective Code Point)","icmpv6.rpl.opt.config.ocp", FT_UINT16, BASE_DEC, NULL, 0x0,
              "The OCP field identifies the OF and is managed by the IANA", HFILL }},
        { &hf_icmpv6_rpl_opt_config_rsv,
           { "Reserved", "icmpv6.rpl.opt.config.rsv", FT_UINT8, BASE_DEC, NULL, 0x0,
              NULL, HFILL }},
        { &hf_icmpv6_rpl_opt_config_def_lifetime,
           { "Default Lifetime", "icmpv6.rpl.opt.config.def_lifetime", FT_UINT8, BASE_DEC, NULL, 0x0,
              "This is the lifetime that is used as default for all RPL routes", HFILL }},
        { &hf_icmpv6_rpl_opt_config_lifetime_unit,
           { "Lifetime Unit", "icmpv6.rpl.opt.config.lifetime_unit", FT_UINT16, BASE_DEC, NULL, 0x0,
              "Provides the unit in seconds that is used to express route lifetimes in RPL", HFILL }},
        { &hf_icmpv6_rpl_opt_target_flag,
           { "Reserved", "icmpv6.rpl.opt.target.flag", FT_NONE, BASE_NONE, NULL, 0x0,
              "Unused field reserved for flags", HFILL }},
        { &hf_icmpv6_rpl_opt_target_prefix_length,
           { "Target Length", "icmpv6.rpl.opt.target.prefix_length", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Number of valid leading bits in the IPv6 Prefix", HFILL }},
        { &hf_icmpv6_rpl_opt_target_prefix,
           { "Target", "icmpv6.rpl.opt.target.prefix", FT_IPv6, BASE_NONE, NULL, 0x0,
              "Identifying an IPv6 destination address, prefix, or multicast group", HFILL }},
        { &hf_icmpv6_rpl_opt_transit_flag,
           { "Flags", "icmpv6.rpl.opt.transit.flag", FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }},
         { &hf_icmpv6_rpl_opt_transit_flag_e,
           { "External", "icmpv6.rpl.opt.transit.flag.e", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RPL_OPT_TRANSIT_FLAG_E,
             "Indicate that the parent router redistributes external targets into the RPL network", HFILL }},
         { &hf_icmpv6_rpl_opt_transit_flag_rsv,
           { "Reserved", "icmpv6.rpl.opt.transit.flag.rsv", FT_UINT8, BASE_DEC, NULL, RPL_OPT_TRANSIT_FLAG_RSV,
             "Must be Zero", HFILL }},
        { &hf_icmpv6_rpl_opt_transit_pathctl,
           { "Path Control", "icmpv6.rpl.opt.transit.pathctl", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Limits the number of DAO-Parents to which a DAO message advertising connectivity", HFILL }},
        { &hf_icmpv6_rpl_opt_transit_pathseq,
           { "Path Sequence", "icmpv6.rpl.opt.transit.pathseq", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Increments the Path Sequence each time it issues a RPL Target option with updated information", HFILL }},
        { &hf_icmpv6_rpl_opt_transit_pathlifetime,
           { "Path Lifetime", "icmpv6.rpl.opt.transit.pathlifetime", FT_UINT8, BASE_DEC, NULL, 0x0,
              "The length of time in Lifetime Units that the prefix is valid for route determination", HFILL }},
        { &hf_icmpv6_rpl_opt_transit_parent,
           { "Parent Address", "icmpv6.rpl.opt.transit.parent", FT_IPv6, BASE_NONE, NULL, 0x0,
              "IPv6 Address of the DODAG Parent of the node originally issuing the Transit Information Option", HFILL }},
        { &hf_icmpv6_rpl_opt_solicited_instance,
           { "Instance", "icmpv6.rpl.opt.solicited.instance", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Containing the RPLInstanceID that is being solicited when valid", HFILL }},
        { &hf_icmpv6_rpl_opt_solicited_flag,
           { "Flag", "icmpv6.rpl.opt.solicited.flag", FT_UINT8, BASE_HEX, NULL, 0x0,
              NULL, HFILL }},
        { &hf_icmpv6_rpl_opt_solicited_flag_v,
           { "Version predicate", "icmpv6.rpl.opt.solicited.flag.v", FT_BOOLEAN, 8, TFS(&tfs_true_false), RPL_OPT_SOLICITED_FLAG_V,
              "The Version predicate is true if the receiver's DODAGVersionNumber matches the requested Version Number", HFILL }},
        { &hf_icmpv6_rpl_opt_solicited_flag_i,
           { "InstanceID predicate","icmpv6.rpl.opt.solicited.flag.i", FT_BOOLEAN, 8, TFS(&tfs_true_false), RPL_OPT_SOLICITED_FLAG_I,
              "The InstanceID predicate is true when the RPL node's current RPLInstanceID matches the requested RPLInstanceID", HFILL }},
        { &hf_icmpv6_rpl_opt_solicited_flag_d,
           { "DODAGID predicate", "icmpv6.rpl.opt.solicited.flag.d", FT_BOOLEAN, 8, TFS(&tfs_true_false), RPL_OPT_SOLICITED_FLAG_D,
              "The DODAGID predicate is true if the RPL node's parent set has the same DODAGID as the DODAGID field", HFILL }},
         { &hf_icmpv6_rpl_opt_solicited_flag_rsv,
           { "Reserved", "icmpv6.rpl.opt.solicited.flag.rsv", FT_UINT8, BASE_DEC, NULL, RPL_OPT_SOLICITED_FLAG_RSV,
             "Must be Zero", HFILL }},
        { &hf_icmpv6_rpl_opt_solicited_dodagid,
           { "DODAGID", "icmpv6.rpl.opt.solicited.dodagid", FT_IPv6, BASE_NONE, NULL, 0x0,
              "the DODAGID that is being solicited when valid", HFILL }},
        { &hf_icmpv6_rpl_opt_solicited_version,
           { "Version", "icmpv6.rpl.opt.solicited.version", FT_UINT8, BASE_DEC, NULL, 0x0,
              "the value of  DODAGVersionNumber that is being solicited when valid", HFILL }},

        { &hf_icmpv6_rpl_opt_prefix_length,
           { "Prefix Length", "icmpv6.rpl.opt.prefix.length", FT_UINT8, BASE_DEC, NULL, 0x0,
             "The number of leading bits in the Prefix that are valid", HFILL }},
        { &hf_icmpv6_rpl_opt_prefix_flag,
           { "Flag", "icmpv6.rpl.opt.prefix.flag", FT_UINT8, BASE_HEX, NULL, 0x0,
             NULL, HFILL }},
        { &hf_icmpv6_rpl_opt_prefix_flag_l,
           { "On Link", "icmpv6.rpl.opt.prefix.flag.l", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RPL_OPT_PREFIX_FLAG_L,
             "When set, indicates that this prefix can be used for on-link determination", HFILL }},
        { &hf_icmpv6_rpl_opt_prefix_flag_a,
           { "Auto Address Config","icmpv6.rpl.opt.config.flag.a", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RPL_OPT_PREFIX_FLAG_A,
             "When set indicates that this prefix can be used for stateless address configuration", HFILL }},
        { &hf_icmpv6_rpl_opt_prefix_flag_r,
           { "Router Address", "icmpv6.rpl.opt.config.flag.r", FT_BOOLEAN, 8, TFS(&tfs_set_notset), RPL_OPT_PREFIX_FLAG_R,
             "When set, indicates that the Prefix field contains a complete IPv6 address assigned to the sending router that can be used as parent in a target option", HFILL }},
        { &hf_icmpv6_rpl_opt_prefix_flag_rsv,
           { "Reserved", "icmpv6.rpl.opt.config.flag.rsv", FT_UINT8, BASE_DEC, NULL, RPL_OPT_PREFIX_FLAG_RSV,
             "Must Be Zero", HFILL }},
        { &hf_icmpv6_rpl_opt_prefix_vlifetime,
           { "Valid Lifetime", "icmpv6.rpl.opt.prefix.valid_lifetime", FT_UINT32, BASE_DEC, NULL, 0x0,
             "The length of time in seconds that the prefix is valid for the purpose of on-link determination", HFILL }},
        { &hf_icmpv6_rpl_opt_prefix_plifetime,
           { "Preferred Lifetime", "icmpv6.rpl.opt.prefix.preferred_lifetime", FT_UINT32, BASE_DEC, NULL, 0x0,
             "The length of time in seconds that addresses generated from the prefix via stateless address autoconfiguration remain preferred", HFILL }},
        { &hf_icmpv6_rpl_opt_prefix,
           { "Destination Prefix", "icmpv6.rpl.opt.prefix", FT_IPv6, BASE_NONE, NULL, 0x0,
             "An IPv6 address or a prefix of an IPv6 address", HFILL }},
        { &hf_icmpv6_rpl_opt_targetdesc,
           { "Descriptor", "icmpv6.rpl.opt.targetdesc.descriptor", FT_UINT32, BASE_HEX, NULL, 0x0,
             "Opaque Data", HFILL }},

        /* 6lowpan-nd: Neighbour Discovery for 6LoWPAN Networks */
        { &hf_icmpv6_da_status,
          { "Status", "icmpv6.6lowpannd.da.status", FT_UINT8, BASE_DEC, VALS(nd_opt_6lowpannd_status_val), 0x0,
            "Indicates the status of a registration in the DAC", HFILL }},
        { &hf_icmpv6_da_rsv,
          { "Reserved", "icmpv6.6lowpannd.da.rsv", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Must be Zero", HFILL }},
        { &hf_icmpv6_da_lifetime,
          { "Lifetime", "icmpv6.6lowpannd.da.lifetime", FT_UINT16, BASE_DEC, NULL, 0x0,
            "The amount of time in a unit of 60 seconds that the router should retain the Neighbor Cache entry for the sender of the NS that includes this option", HFILL }},
        { &hf_icmpv6_da_eui64,
          { "EUI-64", "icmpv6.6lowpannd.da.eui64", FT_EUI64, BASE_NONE, NULL, 0x0,
            "This field is used to uniquely identify the interface of the registered address by including the EUI-64 identifier", HFILL }},
        { &hf_icmpv6_da_raddr,
          { "Registered Address", "icmpv6.6lowpannd.da.reg_addr", FT_IPv6, BASE_NONE, NULL, 0x0,
            "Carries the host address, which was contained in the IPv6 Source field in the NS that contained the ARO option sent by the host", HFILL }},

        /* Conversation-related [generated] header fields */
        { &hf_icmpv6_resp_in,
            { "Response In", "icmpv6.resp_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
              "The response to this request is in this frame", HFILL }},
        { &hf_icmpv6_resp_to,
            { "Response To", "icmpv6.resp_to", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
              "This is the response to the request in this frame", HFILL }},
        { &hf_icmpv6_resptime,
            { "Response Time", "icmpv6.resptime", FT_DOUBLE, BASE_NONE, NULL, 0x0,
              "The time between the request and the response, in ms.", HFILL }}
    };

    static gint *ett[] = {
        &ett_icmpv6,
        &ett_icmpv6_opt,
        &ett_icmpv6_mar,
        &ett_icmpv6_flag_prefix,
        &ett_icmpv6_flag_map,
        &ett_icmpv6_flag_route_info,
        &ett_icmpv6_flag_6lowpan,
        &ett_icmpv6_flag_efo,
        &ett_icmpv6_rpl_opt,
        &ett_icmpv6_rpl_flag_routing,
        &ett_icmpv6_rpl_flag_config,
        &ett_icmpv6_rpl_flag_transit,
        &ett_icmpv6_rpl_flag_solicited,
        &ett_icmpv6_rpl_flag_prefix,
        &ett_icmpv6_flag_ni,
        &ett_icmpv6_flag_rr,
        &ett_icmpv6_rr_mp,
        &ett_icmpv6_rr_up,
        &ett_icmpv6_rr_up_flag_mask,
        &ett_icmpv6_rr_up_flag_ra,
        &ett_icmpv6_rr_up_flag,
        &ett_icmpv6_rr_rm,
        &ett_icmpv6_rr_rm_flag,
        &ett_icmpv6_flag_mld,
        &ett_icmpv6_flag_ra,
        &ett_icmpv6_flag_na,
        &ett_icmpv6_flag_mip6,
        &ett_icmpv6_flag_fmip6,
        &ett_icmpv6_flag_secure,
        &ett_icmpv6_flag_rpl_dio,
        &ett_icmpv6_flag_rpl_dao,
        &ett_icmpv6_flag_rpl_daoack,
        &ett_icmpv6_flag_rpl_cc,
        &ett_icmpv6_opt_name,
        &ett_icmpv6_cga_param_name
    };

    proto_icmpv6 = proto_register_protocol("Internet Control Message Protocol v6",
                                           "ICMPv6", "icmpv6");
    proto_register_field_array(proto_icmpv6, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    new_register_dissector("icmpv6", dissect_icmpv6, proto_icmpv6);
    icmpv6_tap = register_tap("icmpv6");
}

void
proto_reg_handoff_icmpv6(void)
{
    dissector_handle_t icmpv6_handle;

    icmpv6_handle = new_create_dissector_handle(dissect_icmpv6, proto_icmpv6);
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
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
