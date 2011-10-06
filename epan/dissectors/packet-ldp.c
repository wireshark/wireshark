/* packet-ldp.c
 * Routines for LDP (RFC 3036) packet disassembly
 *
 * $Id$
 *
 * Copyright (c) November 2000 by Richard Sharpe <rsharpe@ns.aus.com>
 *
 * CRLDP (RFC3212) is now supported
 *   - (c) 2002 Michael Rozhavsky <mike[AT]tochna.technion.ac.il>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/afn.h>
#include <epan/emem.h>

#include "packet-frame.h"
#include "packet-diffserv-mpls-common.h"
#include "packet-ldp.h"

#define TCP_PORT_LDP 646
#define UDP_PORT_LDP 646

void proto_reg_handoff_ldp(void);

static int proto_ldp = -1;

/* Delete the following if you do not use it, or add to it if you need */
static int hf_ldp_req = -1;
static int hf_ldp_rsp = -1;
static int hf_ldp_version = -1;
static int hf_ldp_pdu_len = -1;
static int hf_ldp_lsr = -1;
static int hf_ldp_ls_id = -1;
static int hf_ldp_msg_ubit = -1;
static int hf_ldp_msg_type = -1;
static int hf_ldp_msg_len = -1;
static int hf_ldp_msg_id = -1;
static int hf_ldp_msg_vendor_id = -1;
static int hf_ldp_msg_experiment_id = -1;
static int hf_ldp_tlv_value = -1;
static int hf_ldp_tlv_type = -1;
static int hf_ldp_tlv_unknown = -1;
static int hf_ldp_tlv_len = -1;
static int hf_ldp_tlv_val_hold = -1;
static int hf_ldp_tlv_val_target = -1;
static int hf_ldp_tlv_val_request = -1;
static int hf_ldp_tlv_val_res = -1;
static int hf_ldp_tlv_ipv4_taddr = -1;
static int hf_ldp_tlv_config_seqno = -1;
static int hf_ldp_tlv_ipv6_taddr = -1;
static int hf_ldp_tlv_fec_wc = -1;
static int hf_ldp_tlv_fec_af = -1;
static int hf_ldp_tlv_fec_len = -1;
static int hf_ldp_tlv_fec_pfval = -1;
static int hf_ldp_tlv_fec_hoval = -1;
static int hf_ldp_tlv_addrl_addr_family = -1;
static int hf_ldp_tlv_addrl_addr = -1;
static int hf_ldp_tlv_hc_value = -1;
static int hf_ldp_tlv_pv_lsrid = -1;
static int hf_ldp_tlv_generic_label = -1;
static int hf_ldp_tlv_atm_label_vbits = -1;
static int hf_ldp_tlv_atm_label_vpi = -1;
static int hf_ldp_tlv_atm_label_vci = -1;
static int hf_ldp_tlv_fr_label_len = -1;
static int hf_ldp_tlv_fr_label_dlci = -1;
static int hf_ldp_tlv_ft_protect_sequence_num = -1;
static int hf_ldp_tlv_status_ebit = -1;
static int hf_ldp_tlv_status_fbit = -1;
static int hf_ldp_tlv_status_data = -1;
static int hf_ldp_tlv_status_msg_id = -1;
static int hf_ldp_tlv_status_msg_type = -1;
static int hf_ldp_tlv_extstatus_data = -1;
static int hf_ldp_tlv_returned_version = -1;
static int hf_ldp_tlv_returned_pdu_len = -1;
static int hf_ldp_tlv_returned_lsr = -1;
static int hf_ldp_tlv_returned_ls_id = -1;
static int hf_ldp_tlv_returned_msg_ubit = -1;
static int hf_ldp_tlv_returned_msg_type = -1;
static int hf_ldp_tlv_returned_msg_len = -1;
static int hf_ldp_tlv_returned_msg_id = -1;
static int hf_ldp_tlv_mac = -1;
static int hf_ldp_tlv_sess_ver = -1;
static int hf_ldp_tlv_sess_ka = -1;
static int hf_ldp_tlv_sess_advbit = -1;
static int hf_ldp_tlv_sess_ldetbit = -1;
static int hf_ldp_tlv_sess_pvlim = -1;
static int hf_ldp_tlv_sess_mxpdu = -1;
static int hf_ldp_tlv_sess_rxlsr = -1;
static int hf_ldp_tlv_sess_rxls = -1;
static int hf_ldp_tlv_sess_atm_merge = -1;
static int hf_ldp_tlv_sess_atm_lr = -1;
static int hf_ldp_tlv_sess_atm_dir = -1;
static int hf_ldp_tlv_sess_atm_minvpi = -1;
static int hf_ldp_tlv_sess_atm_maxvpi = -1;
static int hf_ldp_tlv_sess_atm_minvci = -1;
static int hf_ldp_tlv_sess_atm_maxvci = -1;
static int hf_ldp_tlv_sess_fr_merge = -1;
static int hf_ldp_tlv_sess_fr_lr = -1;
static int hf_ldp_tlv_sess_fr_dir = -1;
static int hf_ldp_tlv_sess_fr_len = -1;
static int hf_ldp_tlv_sess_fr_mindlci = -1;
static int hf_ldp_tlv_sess_fr_maxdlci = -1;
static int hf_ldp_tlv_ft_sess_flags = -1;
static int hf_ldp_tlv_ft_sess_flag_r = -1;
static int hf_ldp_tlv_ft_sess_flag_res = -1;
static int hf_ldp_tlv_ft_sess_flag_s = -1;
static int hf_ldp_tlv_ft_sess_flag_a = -1;
static int hf_ldp_tlv_ft_sess_flag_c = -1;
static int hf_ldp_tlv_ft_sess_flag_l = -1;
static int hf_ldp_tlv_ft_sess_res = -1;
static int hf_ldp_tlv_ft_sess_reconn_to = -1;
static int hf_ldp_tlv_ft_sess_recovery_time = -1;
static int hf_ldp_tlv_ft_ack_sequence_num = -1;
static int hf_ldp_tlv_lbl_req_msg_id = -1;
static int hf_ldp_tlv_vendor_id = -1;
static int hf_ldp_tlv_experiment_id = -1;
static int hf_ldp_tlv_fec_vc_controlword = -1;
static int hf_ldp_tlv_fec_vc_vctype = -1;
static int hf_ldp_tlv_fec_vc_infolength = -1;
static int hf_ldp_tlv_fec_vc_groupid = -1;
static int hf_ldp_tlv_fec_vc_vcid = -1;
static int hf_ldp_tlv_fec_vc_intparam_length = -1;
static int hf_ldp_tlv_fec_vc_intparam_mtu = -1;
static int hf_ldp_tlv_fec_vc_intparam_tdmbps = -1;
static int hf_ldp_tlv_fec_vc_intparam_id = -1;
static int hf_ldp_tlv_fec_vc_intparam_maxcatmcells = -1;
static int hf_ldp_tlv_fec_vc_intparam_desc = -1;
static int hf_ldp_tlv_fec_vc_intparam_cepbytes = -1;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_ais = -1;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_une = -1;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_rtp = -1;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_ebm = -1;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_mah = -1;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_res = -1;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_ceptype = -1;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_t3 = -1;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_e3 = -1;
static int hf_ldp_tlv_fec_vc_intparam_vlanid = -1;
static int hf_ldp_tlv_fec_vc_intparam_dlcilen = -1;
static int hf_ldp_tlv_fec_vc_intparam_fcslen = -1;
static int hf_ldp_tlv_fec_vc_intparam_tdmopt_r = -1;
static int hf_ldp_tlv_fec_vc_intparam_tdmopt_d = -1;
static int hf_ldp_tlv_fec_vc_intparam_tdmopt_f = -1;
static int hf_ldp_tlv_fec_vc_intparam_tdmopt_res1 = -1;
static int hf_ldp_tlv_fec_vc_intparam_tdmopt_pt = -1;
static int hf_ldp_tlv_fec_vc_intparam_tdmopt_res2 = -1;
static int hf_ldp_tlv_fec_vc_intparam_tdmopt_freq = -1;
static int hf_ldp_tlv_fec_vc_intparam_tdmopt_ssrc = -1;
static int hf_ldp_tlv_fec_vc_intparam_vccv_cctype_cw = -1;
static int hf_ldp_tlv_fec_vc_intparam_vccv_cctype_mplsra = -1;
static int hf_ldp_tlv_fec_vc_intparam_vccv_cctype_ttl1 = -1;
static int hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_icmpping = -1;
static int hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_lspping = -1;
static int hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd = -1;
static int hf_ldp_tlv_lspid_act_flg = -1;
static int hf_ldp_tlv_lspid_cr_lsp = -1;
static int hf_ldp_tlv_lspid_ldpid = -1;
static int hf_ldp_tlv_er_hop_loose = -1;
static int hf_ldp_tlv_er_hop_prelen = -1;
static int hf_ldp_tlv_er_hop_prefix4 = -1;
static int hf_ldp_tlv_er_hop_prefix6 = -1;
static int hf_ldp_tlv_er_hop_as = -1;
static int hf_ldp_tlv_er_hop_cr_lsp = -1;
static int hf_ldp_tlv_er_hop_ldpid = -1;
static int hf_ldp_tlv_flags_reserv = -1;
static int hf_ldp_tlv_flags_weight = -1;
static int hf_ldp_tlv_flags_ebs = -1;
static int hf_ldp_tlv_flags_cbs = -1;
static int hf_ldp_tlv_flags_cdr = -1;
static int hf_ldp_tlv_flags_pbs = -1;
static int hf_ldp_tlv_flags_pdr = -1;
static int hf_ldp_tlv_frequency = -1;
static int hf_ldp_tlv_pdr = -1;
static int hf_ldp_tlv_pbs = -1;
static int hf_ldp_tlv_cdr = -1;
static int hf_ldp_tlv_cbs = -1;
static int hf_ldp_tlv_ebs = -1;
static int hf_ldp_tlv_weight = -1;
static int hf_ldp_tlv_set_prio = -1;
static int hf_ldp_tlv_hold_prio = -1;
static int hf_ldp_tlv_route_pinning = -1;
static int hf_ldp_tlv_resource_class = -1;
static int hf_ldp_tlv_diffserv = -1;
static int hf_ldp_tlv_diffserv_type = -1;
static int hf_ldp_tlv_diffserv_mapnb = -1;
static int hf_ldp_tlv_diffserv_map = -1;
static int hf_ldp_tlv_diffserv_map_exp = -1;
static int hf_ldp_tlv_diffserv_phbid = -1;
static int hf_ldp_tlv_diffserv_phbid_dscp = -1;
static int hf_ldp_tlv_diffserv_phbid_code = -1;
static int hf_ldp_tlv_diffserv_phbid_bit14 = -1;
static int hf_ldp_tlv_diffserv_phbid_bit15 = -1;
static int hf_ldp_tlv_fec_gen_agi_type = -1;
static int hf_ldp_tlv_fec_gen_agi_length = -1;
static int hf_ldp_tlv_fec_gen_agi_value = -1;
static int hf_ldp_tlv_fec_gen_saii_type = -1;
static int hf_ldp_tlv_fec_gen_saii_length = -1;
static int hf_ldp_tlv_fec_gen_saii_value = -1;
static int hf_ldp_tlv_fec_gen_taii_type = -1;
static int hf_ldp_tlv_fec_gen_taii_length = -1;
static int hf_ldp_tlv_fec_gen_taii_value = -1;
static int hf_ldp_tlv_fec_gen_aai_globalid = -1;
static int hf_ldp_tlv_fec_gen_aai_prefix = -1;
static int hf_ldp_tlv_fec_gen_aai_ac_id = -1;
static int hf_ldp_tlv_pw_status_data = -1;
static int hf_ldp_tlv_pw_not_forwarding = -1;
static int hf_ldp_tlv_pw_lac_ingress_recv_fault = -1;
static int hf_ldp_tlv_pw_lac_egress_recv_fault = -1;
static int hf_ldp_tlv_pw_psn_pw_ingress_recv_fault = -1;
static int hf_ldp_tlv_pw_psn_pw_egress_recv_fault = -1;
static int hf_ldp_tlv_pw_grouping_value = -1;
static int hf_ldp_tlv_intparam_length = -1;
static int hf_ldp_tlv_intparam_mtu = -1;
static int hf_ldp_tlv_intparam_tdmbps = -1;
static int hf_ldp_tlv_intparam_id = -1;
static int hf_ldp_tlv_intparam_maxcatmcells = -1;
static int hf_ldp_tlv_intparam_desc = -1;
static int hf_ldp_tlv_intparam_cepbytes = -1;
static int hf_ldp_tlv_intparam_cepopt_ais = -1;
static int hf_ldp_tlv_intparam_cepopt_une = -1;
static int hf_ldp_tlv_intparam_cepopt_rtp = -1;
static int hf_ldp_tlv_intparam_cepopt_ebm = -1;
static int hf_ldp_tlv_intparam_cepopt_mah = -1;
static int hf_ldp_tlv_intparam_cepopt_res = -1;
static int hf_ldp_tlv_intparam_cepopt_ceptype = -1;
static int hf_ldp_tlv_intparam_cepopt_t3 = -1;
static int hf_ldp_tlv_intparam_cepopt_e3 = -1;
static int hf_ldp_tlv_intparam_vlanid = -1;
static int hf_ldp_tlv_intparam_dlcilen = -1;
static int hf_ldp_tlv_intparam_fcslen = -1;
static int hf_ldp_tlv_intparam_tdmopt_r = -1;
static int hf_ldp_tlv_intparam_tdmopt_d = -1;
static int hf_ldp_tlv_intparam_tdmopt_f = -1;
static int hf_ldp_tlv_intparam_tdmopt_res1 = -1;
static int hf_ldp_tlv_intparam_tdmopt_pt = -1;
static int hf_ldp_tlv_intparam_tdmopt_res2 = -1;
static int hf_ldp_tlv_intparam_tdmopt_freq = -1;
static int hf_ldp_tlv_intparam_tdmopt_ssrc = -1;
static int hf_ldp_tlv_intparam_vccv_cctype_cw = -1;
static int hf_ldp_tlv_intparam_vccv_cctype_mplsra = -1;
static int hf_ldp_tlv_intparam_vccv_cctype_ttl1 = -1;
static int hf_ldp_tlv_intparam_vccv_cvtype_icmpping = -1;
static int hf_ldp_tlv_intparam_vccv_cvtype_lspping = -1;
static int hf_ldp_tlv_intparam_vccv_cvtype_bfd = -1;


static int ett_ldp = -1;
static int ett_ldp_header = -1;
static int ett_ldp_ldpid = -1;
static int ett_ldp_message = -1;
static int ett_ldp_tlv = -1;
static int ett_ldp_tlv_val = -1;
static int ett_ldp_tlv_ft_flags = -1;
static int ett_ldp_fec = -1;
static int ett_ldp_fec_vc_interfaceparam = -1;
static int ett_ldp_fec_vc_interfaceparam_cepopt = -1;
static int ett_ldp_fec_vc_interfaceparam_vccvtype = -1;
static int ett_ldp_diffserv_map = -1;
static int ett_ldp_diffserv_map_phbid = -1;
static int ett_ldp_gen_agi = -1;
static int ett_ldp_gen_saii = -1;
static int ett_ldp_gen_taii = -1;
static int ett_ldp_gen_aai_type2 = -1;

/* desegmentation of LDP over TCP */
static gboolean ldp_desegment = TRUE;

static guint32 global_ldp_tcp_port = TCP_PORT_LDP;
static guint32 global_ldp_udp_port = UDP_PORT_LDP;

/*
 * The following define all the TLV types I know about
 * http://www.iana.org/assignments/ldp-namespaces
 */

#define TLV_FEC                       0x0100
#define TLV_ADDRESS_LIST              0x0101
#define TLV_HOP_COUNT                 0x0103
#define TLV_PATH_VECTOR               0x0104
#define TLV_GENERIC_LABEL             0x0200
#define TLV_ATM_LABEL                 0x0201
#define TLV_FRAME_LABEL               0x0202
#define TLV_FT_PROTECTION             0x0203
#define TLV_STATUS                    0x0300
#define TLV_EXTENDED_STATUS           0x0301
#define TLV_RETURNED_PDU              0x0302
#define TLV_RETURNED_MESSAGE          0x0303
#define TLV_COMMON_HELLO_PARMS        0x0400
#define TLV_IPV4_TRANSPORT_ADDRESS    0x0401
#define TLV_CONFIGURATION_SEQNO       0x0402
#define TLV_IPV6_TRANSPORT_ADDRESS    0x0403
#define TLV_MAC                       0x0404
#define TLV_COMMON_SESSION_PARMS      0x0500
#define TLV_ATM_SESSION_PARMS         0x0501
#define TLV_FRAME_RELAY_SESSION_PARMS 0x0502
#define TLV_FT_SESSION                0x0503
#define TLV_FT_ACK                    0x0504
#define TLV_FT_CORK                   0x0505
#define TLV_LABEL_REQUEST_MESSAGE_ID  0x0600    /* RFC5036 */
#define TLV_MTU                       0x0601    /* RFC3988 */
#define TLV_ER                        0x0800
#define TLV_ER_HOP_IPV4               0x0801
#define TLV_ER_HOP_IPV6               0x0802
#define TLV_ER_HOP_AS                 0x0803
#define TLV_ER_HOP_LSPID              0x0804
#define TLV_TRAFFIC_PARAM             0x0810
#define TLV_PREEMPTION                0x0820
#define TLV_LSPID                     0x0821
#define TLV_RESOURCE_CLASS            0x0822
#define TLV_ROUTE_PINNING             0x0823
/*
0x0824             Generalized Label Request TLV        [RFC3472]
0x0825             Generalized Label TLV                [RFC3472]
0x0826             Upstream Label TLV                   [RFC3472]
0x0827             Label Set TLV                        [RFC3472]
0x0828             Waveband Label TLV                   [RFC3472]
0x0829             ER-Hop TLV                           [RFC3472]
0x082a             Acceptable Label Set TLV             [RFC3472]
0x082b             Admin Status TLV                     [RFC3472]
0x082c             Interface ID TLV                     [RFC3472]
0x082d             IPV4 Interface ID TLV                [RFC3472]
0x082e             IPV6 Interface ID TLV                [RFC3472]
0x082f             IPv4 IF_ID Status TLV                [RFC3472]
0x0830             IPv6 IF_ID Status TLV                [RFC3472]
0x0831             Op-Sp Call ID TLV                    [RFC3475]
0x0832             GU Call ID TLV                       [RFC3475]
0x0833             Call Capability TLV                  [RFC3475]
0x0834             Crankback TLV                        [RFC3475]
0x0835             Protection TLV                       [RFC3472]
0x0836             LSP_TUNNEL_INTERFACE_ID TLV          [RFC3480]
0x0837             Unnumbered Interface ID TLV          [RFC3480]
0x0838             SONET/SDH Traffic Parameters TLV     [RFC4606]
*/
#define TLV_DIFFSERV                 0x0901
#define TLV_VENDOR_PRIVATE_START     0x3E00
#define TLV_VENDOR_PRIVATE_END       0x3EFF
#define TLV_EXPERIMENTAL_START       0x3F00
#define TLV_EXPERIMENTAL_END         0x3FFF
#define TLV_PW_STATUS                0x096A
#define TLV_PW_INTERFACE_PARAMETERS  0x096B
#define TLV_PW_GROUPING              0x096C

static const value_string tlv_type_names[] = {
    { TLV_FEC,                       "Forwarding Equivalence Classes TLV" },
    { TLV_ADDRESS_LIST,              "Address List TLV"},
    { TLV_HOP_COUNT,                 "Hop Count TLV"},
    { TLV_PATH_VECTOR,               "Path Vector TLV"},
    { TLV_GENERIC_LABEL,             "Generic Label TLV"},
    { TLV_ATM_LABEL,                 "ATM Label TLV"},
    { TLV_FRAME_LABEL,               "Frame Label TLV"},
    { TLV_FT_PROTECTION,             "FT Protection TLV"},
    { TLV_STATUS,                    "Status TLV"},
    { TLV_EXTENDED_STATUS,           "Extended Status TLV"},
    { TLV_RETURNED_PDU,              "Returned PDU TLV"},
    { TLV_RETURNED_MESSAGE,          "Returned Message TLV"},
    { TLV_COMMON_HELLO_PARMS,        "Common Hello Parameters TLV"},
    { TLV_IPV4_TRANSPORT_ADDRESS,    "IPv4 Transport Address TLV"},
    { TLV_CONFIGURATION_SEQNO,       "Configuration Sequence Number TLV"},
    { TLV_IPV6_TRANSPORT_ADDRESS,    "IPv6 Transport Address TLV"},
    { TLV_MAC,                       "MAC TLV"},
    { TLV_COMMON_SESSION_PARMS,      "Common Session Parameters TLV"},
    { TLV_ATM_SESSION_PARMS,         "ATM Session Parameters TLV"},
    { TLV_FRAME_RELAY_SESSION_PARMS, "Frame Relay Session Parameters TLV"},
    { TLV_FT_SESSION,                "FT Session TLV"},
    { TLV_FT_ACK,                    "FT ACK TLV"},
    { TLV_FT_CORK,                   "FT Cork TLV"},
    { TLV_LABEL_REQUEST_MESSAGE_ID,  "Label Request Message ID TLV"},
    { TLV_MTU,                       "MTU TLV"},
    { TLV_LSPID,                     "LSP ID TLV"},
    { TLV_ER,                        "Explicit route TLV"},
    { TLV_ER_HOP_IPV4,               "ER hop IPv4 prefix TLV"},
    { TLV_ER_HOP_IPV6,               "ER hop IPv6 prefix TLV"},
    { TLV_ER_HOP_AS,                 "ER hop Autonomous system number prefix TLV"},
    { TLV_TRAFFIC_PARAM,             "Traffic parameters TLV"},
    { TLV_PREEMPTION,                "Preemption TLV"},
    { TLV_ER_HOP_LSPID,              "ER hop LSPID prefix TLV"},
    { TLV_RESOURCE_CLASS,            "Resource Class (Color) TLV"},
    { TLV_ROUTE_PINNING,             "Route Pinning TLV"},
    { 0x0824,                        "Generalized Label Request TLV"},        /* RFC3472 */
    { 0x0825,                        "Generalized Label TLV"},                /* RFC3472 */
    { 0x0826,                        "Upstream Label TLV"},                   /* RFC3472 */
    { 0x0827,                        "Label Set TLV"},                        /* RFC3472 */
    { 0x0828,                        "Waveband Label TLV"},                   /* RFC3472 */
    { 0x0829,                        "ER-Hop TLV"},                           /* RFC3472 */
    { 0x082a,                        "Acceptable Label Set TLV"},             /* RFC3472 */
    { 0x082b,                        "Admin Status TLV"},                     /* RFC3472 */
    { 0x082c,                        "Interface ID TLV"},                     /* RFC3472 */
    { 0x082d,                        "IPV4 Interface ID TLV"},                /* RFC3472 */
    { 0x082e,                        "IPV6 Interface ID TLV"},                /* RFC3472 */
    { 0x082f,                        "IPv4 IF_ID Status TLV"},                /* RFC3472 */
    { 0x0830,                        "IPv6 IF_ID Status TLV"},                /* RFC3472 */
    { 0x0831,                        "Op-Sp Call ID TLV"},                    /* RFC3475 */
    { 0x0832,                        "GU Call ID TLV"},                       /* RFC3475 */
    { 0x0833,                        "Call Capability TLV"},                  /* RFC3475 */
    { 0x0834,                        "Crankback TLV"},                        /* RFC3475 */
    { 0x0835,                        "Protection TLV"},                       /* RFC3472 */
    { 0x0836,                        "LSP_TUNNEL_INTERFACE_ID TLV"},          /* RFC3480 */
    { 0x0837,                        "Unnumbered Interface ID TLV"},          /* RFC3480 */
    { 0x0838,                        "SONET/SDH Traffic Parameters TLV"},     /* RFC4606]*/
    { 0x0960,                        "IPv4 Source ID TLV"},                   /*[RFC3476]*/
    { 0x0961,                        "IPv6 Source ID TLV"},                   /*[RFC3476]*/
    { 0x0962,                        "NSAP Source ID TLV"},                   /*[RFC3476]*/
    { 0x0963,                        "IPv4 Destination ID TLV"},              /*[RFC3476]*/
    { 0x0964,                        "IPv6 Destination ID TLV"},              /*[RFC3476]*/
    { 0x0965,                        "NSAP Destination ID TLV"},              /*[RFC3476]*/
    { 0x0966,                        "Egress Label TLV"},                     /*[RFC3476]*/
    { 0x0967,                        "Local Connection ID TLV"},              /*[RFC3476]*/
    { 0x0968,                        "Diversity TLV"},                        /*[RFC3476]*/
    { 0x0969,                        "Contract ID TLV"},                      /*[RFC3476]*/
    { TLV_PW_STATUS,                 "PW Status TLV"},                        /*[RFC4447]*/
    { TLV_PW_INTERFACE_PARAMETERS,   "PW Interface Parameters TLV"},          /*[RFC4447]*/
    { TLV_PW_GROUPING,               "Group ID TLV"},                         /*[RFC4447]*/
    { 0x096E,                        "Bandwidth TLV"},                        /*[draft-ietf-pwe3-dynamic-ms-pw](TEMPORARY - Expires 2008-11-21)*/
    { 0x0970,                        "UNI Service Level TLV"},                /*[RFC3476]*/
    { TLV_DIFFSERV,                  "Diff-Serv TLV"},
    { TLV_VENDOR_PRIVATE_START,      "Vendor Private TLV"},
    { TLV_EXPERIMENTAL_START,        "Experimental TLV"},
    { 0, NULL}
};

/*
 * The following define all the message types I know about
 */

#define LDP_NOTIFICATION                0x0001
#define LDP_HELLO                       0x0100
#define LDP_INITIALIZATION              0x0200
#define LDP_KEEPALIVE                   0x0201
#define LDP_ADDRESS                     0x0300
#define LDP_ADDRESS_WITHDRAWAL          0x0301
#define LDP_LABEL_MAPPING               0x0400
#define LDP_LABEL_REQUEST               0x0401
#define LDP_LABEL_WITHDRAWAL            0x0402
#define LDP_LABEL_RELEASE               0x0403
#define LDP_LABEL_ABORT_REQUEST         0x0404
#define LDP_VENDOR_PRIVATE_START        0x3E00
#define LDP_VENDOR_PRIVATE_END          0x3EFF
#define LDP_EXPERIMENTAL_MESSAGE_START  0x3F00
#define LDP_EXPERIMENTAL_MESSAGE_END    0x3FFF

static const value_string ldp_message_types[] = {
    {LDP_NOTIFICATION,               "Notification Message"},
    {LDP_HELLO,                      "Hello Message"},
    {LDP_INITIALIZATION,             "Initialization Message"},
    {LDP_KEEPALIVE,                  "Keep Alive Message"},
    {LDP_ADDRESS,                    "Address Message"},
    {LDP_ADDRESS_WITHDRAWAL,         "Address Withdrawal Message"},
    {LDP_LABEL_MAPPING,              "Label Mapping Message"},
    {LDP_LABEL_REQUEST,              "Label Request Message"},
    {LDP_LABEL_WITHDRAWAL,           "Label Withdrawal Message"},
    {LDP_LABEL_RELEASE,              "Label Release Message"},
    {LDP_LABEL_ABORT_REQUEST,        "Label Abort Request Message"},
    {LDP_VENDOR_PRIVATE_START,       "Vendor-Private Message"},
    {LDP_EXPERIMENTAL_MESSAGE_START, "Experimental Message"},
    {0, NULL}
};

static const true_false_string ldp_message_ubit = {
    "Unknown bit set",
    "Unknown bit not set"
};

static const true_false_string hello_targeted_vals = {
    "Targeted Hello",
    "Link Hello"
};

static const value_string tlv_unknown_vals[] = {
    {0, "Known TLV, do not Forward"},
    {1, "Known TLV, do Forward"},
    {2, "Unknown TLV, do not Forward"},
    {3, "Unknown TLV, do Forward"},
    {0, NULL}
};

#define WILDCARD_FEC    1
#define PREFIX_FEC      2
#define HOST_FEC        3
#define CRLSP_FEC       4
#define VC_FEC          0x80    /* draft-martini-l2circuit-trans-mpls */
#define GEN_FEC         0x81

static const value_string fec_types[] = {
  {WILDCARD_FEC, "Wildcard FEC"},
  {PREFIX_FEC,   "Prefix FEC"},
  {HOST_FEC,     "Host Address FEC"},
  {CRLSP_FEC,    "CR LSP FEC"},
  {VC_FEC,       "Virtual Circuit FEC"},
  {GEN_FEC,      "Generalized PWid FEC"},
  {0, NULL}
};


const value_string fec_vc_types_vals[] = {
    {0x0001, "Frame Relay DLCI"},
    {0x0002, "ATM AAL5 SDU VCC transport"},
    {0x0003, "ATM transparent cell transport"},
    {0x0004, "Ethernet VLAN"},
    {0x0005, "Ethernet"},
    {0x0006, "HDLC"},
    {0x0007, "PPP"},
    {0x0008, "SONET/SDH Circuit Emulation Service"},
    {0x0009, "ATM n-to-one VCC cell transport"},
    {0x000A, "ATM n-to-one VPC cell transport"},
    {0x000B, "IP layer2 transport"},
    {0x000C, "ATM one-to-one VCC Cell Mode"},
    {0x000D, "ATM one-to-one VPC Cell Mode"},
    {0x000E, "ATM AAL5 PDU VCC transport"},
    {0x000F, "Frame-Relay Port mode"},
    {0x0010, "SONET/SDH Circuit Emulation over Packet"},
    {0x0011, "Structure-agnostic E1 over Packet"},
    {0x0012, "Structure-agnostic T1 (DS1) over Packet"},
    {0x0013, "Structure-agnostic E3 over Packet"},
    {0x0014, "Structure-agnostic T3 (DS3) over Packet"},
    {0x0015, "CESoPSN basic mode"},
    {0x0016, "TDMoIP basic mode"},
    {0x0017, "CESoPSN TDM with CAS"},
    {0x0018, "TDMoIP TDM with CAS"},
    {0, NULL}
};


static const value_string fec_vc_ceptype_vals[] = {
    {0, "SPE mode (STS-1/STS-Mc)"},
    {1, "VT mode (VT1.5/VT2/VT3/VT6)"},
    {2, "Fractional SPE (STS-1/VC-3/VC-4)"},
    {0, NULL}
};

static const true_false_string fec_vc_tdmopt_r = {
    "Expects to receive RTP Header",
    "Does not expect to receive RTP Header"
};

static const true_false_string fec_vc_tdmopt_d = {
    "Expects the peer to use Differential timestamping",
    "Does not expect the peer to use Differential timestamping"
};

static const true_false_string fec_vc_tdmopt_f = {
    "Expects TDMoIP encapsulation",
    "Expects CESoPSN encapsulation"
};


#define FEC_VC_INTERFACEPARAM_MTU          0x01
#define FEC_VC_INTERFACEPARAM_MAXCATMCELLS 0x02
#define FEC_VC_INTERFACEPARAM_DESCRIPTION  0x03
#define FEC_VC_INTERFACEPARAM_CEPBYTES     0x04
#define FEC_VC_INTERFACEPARAM_CEPOPTIONS   0x05
#define FEC_VC_INTERFACEPARAM_VLANID       0x06
#define FEC_VC_INTERFACEPARAM_TDMBPS       0x07
#define FEC_VC_INTERFACEPARAM_FRDLCILEN    0x08
#define FEC_VC_INTERFACEPARAM_FRAGIND      0x09
#define FEC_VC_INTERFACEPARAM_FCSRETENT    0x0A
#define FEC_VC_INTERFACEPARAM_TDMOPTION    0x0B
#define FEC_VC_INTERFACEPARAM_VCCV         0x0C



static const value_string fec_vc_interfaceparm[] = {
  {FEC_VC_INTERFACEPARAM_MTU,           "MTU"},
  {FEC_VC_INTERFACEPARAM_MAXCATMCELLS,  "Max Concatenated ATM cells"},
  {FEC_VC_INTERFACEPARAM_DESCRIPTION,   "Interface Description"},
  {FEC_VC_INTERFACEPARAM_CEPBYTES,      "CEP/TDM Payload Bytes"},
  {FEC_VC_INTERFACEPARAM_CEPOPTIONS,    "CEP options"},
  {FEC_VC_INTERFACEPARAM_VLANID,        "Requested VLAN ID"},
  {FEC_VC_INTERFACEPARAM_TDMBPS,        "CEP/TDM bit-rate"},
  {FEC_VC_INTERFACEPARAM_FRDLCILEN,     "Frame-Relay DLCI Length"},
  {FEC_VC_INTERFACEPARAM_FRAGIND,       "Fragmentation indicator"},
  {FEC_VC_INTERFACEPARAM_FCSRETENT,     "FCS retention indicator"},
  {FEC_VC_INTERFACEPARAM_TDMOPTION,     "TDM options"},
  {FEC_VC_INTERFACEPARAM_VCCV,          "VCCV"},
  {0, NULL},
};

static const true_false_string fec_vc_cbit = {
    "Control Word Present",
    "Control Word NOT Present"
};



static const value_string tlv_atm_merge_vals[] = {
    {0, "Merge not supported"},
    {1, "VP merge supported"},
    {2, "VC merge supported"},
    {3, "VP & VC merge supported"},
    {0, NULL}
};

static const value_string tlv_atm_vbits_vals[] = {
    {0, "VPI & VCI Significant"},
    {1, "Only VPI Significant"},
    {2, "Only VCI Significant"},
    {3, "VPI & VCI not Significant, nonsense"},
    {0, NULL}
};

static const value_string tlv_fr_merge_vals[] = {
    {0, "Merge not supported"},
    {1, "Merge supported"},
    {2, "Unspecified"},
    {3, "Unspecified"},
    {0, NULL}
};

static const value_string tlv_fr_len_vals[] = {
    {0, "10 bits"},
    {1, "Reserved"},
    {2, "23 bits"},
    {3, "Reserved"},
    {0, NULL}
};

static const value_string tlv_ft_flags[] = {
    { 0, "Invalid"},
    { 1, "Using LDP Graceful Restart"},
    { 2, "Check-Pointing of all labels"},
    { 3, "Invalid"},
    { 4, "Invalid"},
    { 5, "Invalid"},
    { 6, "Check-Pointing of all labels"},
    { 7, "Invalid"},
    { 8, "Full FT on selected labels"},
    { 9, "Invalid"},
    {10, "Full FT on selected labels"},
    {11, "Invalid"},
    {12, "Full FT on all labels"},
    {13, "Invalid"},
    {14, "Full FT on all labels"},
    {15, "Invalid"},
    {0, NULL}
};

static const true_false_string tlv_ft_r = {
    "LSR has preserved state and resources for all FT-Labels",
    "LSR has not preserved state and resources for all FT-Labels"
};

static const true_false_string tlv_ft_s = {
    "FT Protection TLV supported on other than KeepAlive",
    "FT Protection TLV not supported on other than KeepAlive"
};

static const true_false_string tlv_ft_a = {
    "Treat all labels as Sequence Numbered FT Labels",
    "May treat some labels as FT and others as non-FT"
};

static const true_false_string tlv_ft_c = {
    "Check-Pointing procedures in use",
    "Check-Pointing procedures not in use"
};

static const true_false_string tlv_ft_l = {
    "Re-learn the state from the network",
    "Do not re-learn the state from the network"
};

static const value_string ldp_act_flg_vals[] = {
    {0, "indicates initial LSP setup"},
    {1, "indicates modify LSP"},
    {0, NULL}
};

static const value_string route_pinning_vals[] = {
    {0, "route pinning is not requested"},
    {1, "route pinning is requested"},
    {0, NULL}
};

static const value_string diffserv_type_vals[] = {
    {0, "E-LSP"},
    {1, "L-LSP"},
    {0, NULL}
};

static const value_string ldp_loose_vals[] = {
    {0, "strict hop"},
    {1, "loose hop"},
    {0, NULL}
};

static const true_false_string tlv_negotiable = {
    "Negotiable",
    "Not negotiable"
};

static const value_string freq_values[] = {
    {0, "Unspecified"},
    {1, "Frequent"},
    {2, "VeryFrequent"},
    {0, NULL}
};

static const true_false_string tlv_atm_dirbit = {
    "Bidirectional capability",
    "Unidirectional capability"
};

static const true_false_string hello_requested_vals = {
    "Source requests periodic hellos",
    "Source does not request periodic hellos"
};

static const true_false_string tlv_sess_advbit_vals = {
    "Downstream On Demand proposed",
    "Downstream Unsolicited proposed"
};

static const true_false_string tlv_sess_ldetbit_vals = {
    "Loop Detection Enabled",
    "Loop Detection Disabled"
};

static const true_false_string tlv_status_ebit = {
    "Fatal Error Notification",
    "Advisory Notification"
};

static const true_false_string tlv_status_fbit = {
    "Notification should be Forwarded",
    "Notification should NOT be Forwarded"
};

static const value_string tlv_status_data[] = {
    { 0, "Success"},
    { 1, "Bad LDP Identifier"},
    { 2, "Bad Protocol Version"},
    { 3, "Bad PDU Length"},
    { 4, "Unknown Message Type"},
    { 5, "Bad Message Length"},
    { 6, "Unknown TLV"},
    { 7, "Bad TLV Length"},
    { 8, "Malformed TLV Value"},
    { 9, "Hold Timer Expired"},
    {10, "Shutdown"},
    {11, "Loop Detected"},
    {12, "Unknown FEC"},
    {13, "No Route"},
    {14, "No Label Resources"},
    {15, "Label Resources / Available"},
    {16, "Session Rejected / No Hello"},
    {17, "Session Rejected / Parameters Advertisement Mode"},
    {18, "Session Rejected / Parameters Max PDU Length"},
    {19, "Session Rejected / Parameters Label Range"},
    {20, "KeepAlive Timer Expired"},
    {21, "Label Request Aborted"},
    {22, "Missing Message Parameters"},
    {23, "Unsupported Address Family"},
    {24, "Session Rejected / Bad KeepAlive Time"},
    {25, "Internal Error"},
    {26, "No LDP Session"},
    {27, "Zero FT seqnum"},
    {28, "Unexpected TLV / Session Not FT"},
    {29, "Unexpected TLV / Label Not FT"},
    {30, "Missing FT Protection TLV"},
    {31, "FT ACK sequence error"},
    {32, "Temporary Shutdown"},
    {33, "FT Seq Numbers Exhausted"},
    {34, "FT Session parameters / changed"},
    {35, "Unexpected FT Cork TLV"},
    {0x01000001, "Unexpected Diff-Serv TLV"},
    {0x01000002, "Unsupported PHB"},
    {0x01000003, "Invalid EXP<->PHB Mapping"},
    {0x01000004, "Unsupported PSC"},
    {0x01000005, "Per-LSP context allocation failure"},
    {0x04000001, "Bad Explicit Routing TLV Error"},
    {0x04000002, "Bad Strict Node Error"},
    {0x04000003, "Bad Strict Node Error"},
    {0x04000004, "Bad Initial ER-Hop Error"},
    {0x04000005, "Resource Unavailable"},
    {0x04000006, "Traffic Parameters Unavailable"},
    {0x04000007, "LSP Preempted"},
    {0x04000008, "Modify Request Not Supported"},
    {0x20000001, "Illegal C-Bit"},
    {0x20000002, "Wrong C-Bit"},
    {0x00000028,  "PW status"},
    {0, NULL}
};

#define PW_NOT_FORWARDING               0x1
#define PW_LAC_INGRESS_RECV_FAULT       0x2
#define PW_LAC_EGRESS_TRANS_FAULT       0x4
#define PW_PSN_PW_INGRESS_RECV_FAULT    0x8
#define PW_PSN_PW_EGRESS_TRANS_FAULT    0x10

/* Define storage class for a string handler function
 * with a const guint8 * argument, and returning a const gchar *
 */
typedef const gchar *(string_handler_func)(const guint8 *);

/* Default handler for address to string conversion */
static const gchar *
default_str_handler(const guint8 * bytes _U_)
{
    return "<Support for this Address Family not implemented>";
}

static void
dissect_subtlv_interface_parameters(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem, int *interface_parameters_hf[]);

static void
dissect_genpwid_fec_aai_type2_parameter(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem);

/* Dissect FEC TLV */

static void
dissect_tlv_fec(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    static int *interface_params_header_fields[] = {
        &hf_ldp_tlv_fec_vc_intparam_length ,
        &hf_ldp_tlv_fec_vc_intparam_mtu ,
        &hf_ldp_tlv_fec_vc_intparam_tdmbps ,
        &hf_ldp_tlv_fec_vc_intparam_id ,
        &hf_ldp_tlv_fec_vc_intparam_maxcatmcells ,
        &hf_ldp_tlv_fec_vc_intparam_desc ,
        &hf_ldp_tlv_fec_vc_intparam_cepbytes ,
        &hf_ldp_tlv_fec_vc_intparam_cepopt_ais ,
        &hf_ldp_tlv_fec_vc_intparam_cepopt_une ,
        &hf_ldp_tlv_fec_vc_intparam_cepopt_rtp ,
        &hf_ldp_tlv_fec_vc_intparam_cepopt_ebm ,
        &hf_ldp_tlv_fec_vc_intparam_cepopt_mah ,
        &hf_ldp_tlv_fec_vc_intparam_cepopt_res ,
        &hf_ldp_tlv_fec_vc_intparam_cepopt_ceptype ,
        &hf_ldp_tlv_fec_vc_intparam_cepopt_t3 ,
        &hf_ldp_tlv_fec_vc_intparam_cepopt_e3 ,
        &hf_ldp_tlv_fec_vc_intparam_vlanid ,
        &hf_ldp_tlv_fec_vc_intparam_dlcilen ,
        &hf_ldp_tlv_fec_vc_intparam_fcslen ,
        &hf_ldp_tlv_fec_vc_intparam_tdmopt_r ,
        &hf_ldp_tlv_fec_vc_intparam_tdmopt_d ,
        &hf_ldp_tlv_fec_vc_intparam_tdmopt_f ,
        &hf_ldp_tlv_fec_vc_intparam_tdmopt_res1 ,
        &hf_ldp_tlv_fec_vc_intparam_tdmopt_pt ,
        &hf_ldp_tlv_fec_vc_intparam_tdmopt_res2 ,
        &hf_ldp_tlv_fec_vc_intparam_tdmopt_freq ,
        &hf_ldp_tlv_fec_vc_intparam_tdmopt_ssrc ,
        &hf_ldp_tlv_fec_vc_intparam_vccv_cctype_cw ,
        &hf_ldp_tlv_fec_vc_intparam_vccv_cctype_mplsra ,
        &hf_ldp_tlv_fec_vc_intparam_vccv_cctype_ttl1 ,
        &hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_icmpping ,
        &hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_lspping ,
        &hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd
    };

    proto_tree *ti, *val_tree, *fec_tree=NULL;
    proto_tree *agi_tree=NULL, *saii_tree=NULL, *taii_tree=NULL;
    guint16     family, ix=1, ax;
    guint8      addr_size=0, *addr, implemented, prefix_len_octets, prefix_len, host_len, vc_len;
    guint8      intparam_len, aai_type = 0;
    string_handler_func *str_handler = default_str_handler;
    const char *str;
    guint8 gen_fec_id_len = 0;

    ti=proto_tree_add_text(tree, tvb, offset, rem, "FEC Elements");
    val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);

    while (rem > 0){
        switch (tvb_get_guint8(tvb, offset)) {
        case WILDCARD_FEC:
        case CRLSP_FEC:
            ti = proto_tree_add_text(val_tree, tvb, offset, 1, "FEC Element %u", ix);
            fec_tree = proto_item_add_subtree(ti, ett_ldp_fec);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_wc,tvb, offset, 1, ENC_BIG_ENDIAN);
            rem -= 1;
            offset += 1;
            break;

        case PREFIX_FEC:
            if ( rem < 4 ){/*not enough*/
                proto_tree_add_text(val_tree, tvb, offset, rem, "Error in FEC Element %u", ix);
                return;
            }
            family=tvb_get_ntohs(tvb, offset+1);
            prefix_len=tvb_get_guint8(tvb, offset+3);
            prefix_len_octets=(prefix_len+7)/8;

            implemented=1;
            switch(family) {
            case AFNUM_INET: /*IPv4*/
                addr_size=4;
                str_handler=ip_to_str;
                break;
            case AFNUM_INET6: /*IPv6*/
                addr_size=16;
                str_handler = (string_handler_func *) ip6_to_str;
                break;
            default:
                implemented=0;
                break;
            }

            if ( !implemented ) {
                guint16 noctets;

                noctets= rem>4+prefix_len_octets?4+prefix_len_octets:rem;
                proto_tree_add_text(val_tree, tvb, offset, noctets,"Support for Address Family not implemented");
                offset+=noctets;
                rem-=noctets;
                break;
            }

            if ( rem < 4+MIN(addr_size, prefix_len_octets) ){
                proto_tree_add_text(val_tree, tvb, offset, rem, "Error in FEC Element %u", ix);
                return;
            }

            /*Add a subtree for this*/
            ti = proto_tree_add_text(val_tree, tvb, offset, 4+MIN(addr_size, prefix_len_octets), "FEC Element %u", ix);
            fec_tree = proto_item_add_subtree(ti, ett_ldp_fec);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_wc, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_af, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_len, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;


            if ( addr_size < prefix_len_octets) {
                offset+=addr_size;
                rem-=addr_size;
                proto_tree_add_text(fec_tree, tvb, offset-1, 1,
                                    "Invalid prefix %u length for family %s",
                                    prefix_len, val_to_str(family, afn_vals, "Unknown Family"));
                break;
            }

            addr=ep_alloc0(addr_size);

            for(ax=0; ax+1 <= prefix_len_octets; ax++)
                addr[ax]=tvb_get_guint8(tvb, offset+ax);
            if ( prefix_len % 8 )
                addr[ax-1] = addr[ax-1]&(0xFF<<(8-prefix_len%8));

            str = str_handler((const guint8 *)addr);
            proto_tree_add_string_format(fec_tree, hf_ldp_tlv_fec_pfval, tvb, offset, prefix_len_octets,
                                         str, "Prefix: %s", str);

            offset += prefix_len_octets;
            rem -= 4+prefix_len_octets;
            break;

        case HOST_FEC:
            if ( rem < 4 ){/*not enough*/
                proto_tree_add_text(val_tree, tvb, offset, rem, "Error in FEC Element %u", ix);
                return;
            }
            family=tvb_get_ntohs(tvb, offset+1);
            host_len=tvb_get_guint8(tvb, offset+3);

            implemented=1;
            switch(family) {
            case AFNUM_INET: /*IPv4*/
                addr_size=4;
                str_handler=ip_to_str;
                break;
            case AFNUM_INET6: /*IPv6*/
                addr_size=16;
                str_handler = (string_handler_func *) ip6_to_str;
                break;
            default:
                implemented=0;
                break;
            }

            if ( !implemented ) {
                guint16 noctets;

                noctets= rem>4+host_len?4+host_len:rem;
                proto_tree_add_text(val_tree, tvb, offset, noctets,"Support for Address Family not implemented");
                offset+=noctets;
                rem-=noctets;
                break;
            }

            if ( rem < 4+addr_size ){
                proto_tree_add_text(val_tree, tvb, offset, rem, "Error in FEC Element %u", ix);
                return;
            }

            /*Add a subtree for this*/
            ti = proto_tree_add_text(val_tree, tvb, offset, 4+addr_size, "FEC Element %u", ix);
            fec_tree = proto_item_add_subtree(ti, ett_ldp_fec);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_wc, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_af, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_len, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;


            if ( addr_size != host_len) {
                offset+=addr_size;
                rem-=addr_size;
                proto_tree_add_text(fec_tree, tvb, offset-1, 1,
                                    "Invalid address length %u length for family %s",
                                    host_len, val_to_str(family, afn_vals, "Unknown Family"));
                break;
            }

            addr=ep_alloc0(addr_size);

            for(ax=0; ax+1 <= host_len; ax++)
                addr[ax]=tvb_get_guint8(tvb, offset+ax);

            str = str_handler((const guint8 *)addr);
            proto_tree_add_string_format(fec_tree, hf_ldp_tlv_fec_hoval, tvb, offset, host_len,
                                         str, "Address: %s", str);

            offset += host_len;
            rem -= 4+host_len;
            break;

        case VC_FEC:
            if ( rem < 8 ){/*not enough bytes for a minimal VC_FEC*/
                proto_tree_add_text(val_tree, tvb, offset, rem, "Error in FEC Element %u", ix);
                return;
            }
            vc_len = tvb_get_guint8 (tvb, offset+3);


            ti = proto_tree_add_text(val_tree, tvb, offset, 8+vc_len, "FEC Element %u", ix);
            fec_tree = proto_item_add_subtree(ti, ett_ldp_fec);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_wc, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_vc_controlword, tvb, offset+1, 1, FALSE);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_vc_vctype, tvb, offset+1, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_vc_infolength, tvb, offset+3,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_vc_groupid,tvb, offset +4, 4, ENC_BIG_ENDIAN);
            rem -=8;
            offset +=8;

            if ( (vc_len > 3) && ( rem > 3 ) ) { /* there is enough room for vcid */
                proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_vc_vcid,tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_item_append_text (ti," VCID: %u",tvb_get_ntohl(tvb,offset));

            } else {
                proto_tree_add_text(val_tree,tvb,offset +4, 8 +vc_len, "VC FEC size format error");
                return;
            }
            rem -= 4;
            vc_len -= 4;
            offset += 4;

            while ( (vc_len > 1) && (rem > 1) ) {   /* enough to include id and length */
                intparam_len = tvb_get_guint8(tvb, offset+1);
                if (intparam_len < 2){ /* At least Type and Len, protect against len = 0 */
                    proto_tree_add_text(fec_tree, tvb, offset +1, 1, "Malformed interface parameter");
                    return;
                }

                if ( (vc_len -intparam_len) <0 && (rem -intparam_len) <0 ) { /* error condition */
                    proto_tree_add_text(fec_tree, tvb, offset +2, MIN(vc_len,rem), "Malformed data");
                    return;
                }
                dissect_subtlv_interface_parameters(tvb, offset, fec_tree, intparam_len, interface_params_header_fields);

                rem -= intparam_len;
                vc_len -= intparam_len;
                offset += intparam_len;
            }
            break;
        case GEN_FEC:
        {
            /* Ref: RFC 4447 */
            if ( rem < 4 ){/*not enough bytes for a minimal VC_FEC*/
                proto_tree_add_text(val_tree, tvb, offset, rem, "Error in FEC Element %u", ix);
                return;
            }
            vc_len = tvb_get_guint8 (tvb, offset+3);

            /* Add the FEC to the tree */
            ti = proto_tree_add_text(val_tree, tvb, offset, 8+vc_len, "FEC Element %u", ix);
            fec_tree = proto_item_add_subtree(ti, ett_ldp_fec);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_wc, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_vc_controlword, tvb, offset+1, 1, FALSE);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_vc_vctype, tvb, offset+1, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_vc_infolength, tvb, offset+3,1,ENC_BIG_ENDIAN);
            rem -= 4;
            offset += 4;

            if ( (vc_len > 1) && ( rem > 1 ) ) { /* there is enough room for AGI */
                gen_fec_id_len = tvb_get_guint8 (tvb, offset+1);
                /* Add AGI to the tree */
                ti = proto_tree_add_text(fec_tree, tvb, offset, 2 + gen_fec_id_len, "AGI");
                agi_tree = proto_item_add_subtree(ti, ett_ldp_gen_agi);
                proto_tree_add_item(agi_tree, hf_ldp_tlv_fec_gen_agi_type,tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(agi_tree, hf_ldp_tlv_fec_gen_agi_length,tvb, offset + 1, 1, ENC_BIG_ENDIAN);
                if ( gen_fec_id_len > 0)
                {
                    proto_tree_add_item(agi_tree, hf_ldp_tlv_fec_gen_agi_value, tvb, offset+2, gen_fec_id_len , ENC_NA );
                }
                rem -= 2 + gen_fec_id_len;
                vc_len -= 2 + gen_fec_id_len;
                offset += 2 + gen_fec_id_len;

            } else {
                proto_tree_add_text(fec_tree ,tvb,offset , 2 +vc_len, "Generalized FEC: AGI size format error");
                return;
            }

            if ( (vc_len > 1) && ( rem > 1 ) ) { /* there is enough room for SAII */
                gen_fec_id_len = tvb_get_guint8 (tvb, offset+1);
                /* Add SAII to the tree */
                aai_type = tvb_get_guint8(tvb, offset);
                if ( aai_type == 2 && gen_fec_id_len != 12)
                {
                    /* According to RFC 5003, for Type 2 AAI, the length should be 12 bytes */
                    proto_tree_add_text(fec_tree,tvb,offset , 2 + gen_fec_id_len, "Generalized FEC: SAII size format error");
                }
                else
                {
                    ti = proto_tree_add_text(fec_tree, tvb, offset, 2 + gen_fec_id_len, "SAII");
                    saii_tree = proto_item_add_subtree(ti, ett_ldp_gen_saii);
                    proto_tree_add_item(saii_tree, hf_ldp_tlv_fec_gen_saii_type,tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(saii_tree, hf_ldp_tlv_fec_gen_saii_length,tvb, offset + 1, 1, ENC_BIG_ENDIAN);
                    if ( gen_fec_id_len > 0)
                    {
                        /* Get the AAI Type. */
                        /* If it is  Type 2 (RFC 5003), then the length is 12 bytes, */
                        /* and the following fields exist. */
                        /*    0                   1                   2                   3    */
                        /*    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
                        /*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
                        /*   |  AII Type=02  |    Length     |        Global ID              | */
                        /*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
                        /*   |       Global ID (contd.)      |        Prefix                 | */
                        /*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
                        /*   |       Prefix (contd.)         |        AC ID                  | */
                        /*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
                        /*   |      AC ID                    | */
                        /*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

                        if ( aai_type == 2)
                        {
                            dissect_genpwid_fec_aai_type2_parameter(tvb, offset +2, saii_tree, gen_fec_id_len);
                        }
                        else
                        {
                            proto_tree_add_item(saii_tree,
                                                hf_ldp_tlv_fec_gen_saii_value,
                                                tvb,
                                                offset+2,
                                                gen_fec_id_len ,
                                                ENC_NA );
                        }
                    }
                }
                rem -= 2 + gen_fec_id_len;
                vc_len -= 2 + gen_fec_id_len;
                offset += 2 + gen_fec_id_len;

            } else {
                proto_tree_add_text(fec_tree,tvb,offset , 2 + vc_len, "Generalized FEC: SAII size format error");
                return;
            }

            if ( (vc_len > 1) && ( rem > 1 ) ) { /* there is enough room for TAII */
                gen_fec_id_len = tvb_get_guint8 (tvb, offset+1);
                /* Add TAII to the tree */
                aai_type = tvb_get_guint8(tvb, offset);
                if ( aai_type == 2 && gen_fec_id_len != 12)
                {
                    /* According to RFC 5003, for Type 2 AAI, the length should be 12 bytes */
                    proto_tree_add_text(fec_tree,tvb,offset , 2 + gen_fec_id_len, "Generalized FEC: TAII size format error");
                }
                else
                {
                    ti = proto_tree_add_text(fec_tree, tvb, offset, 2 + gen_fec_id_len, "TAII");
                    taii_tree = proto_item_add_subtree(ti, ett_ldp_gen_taii);
                    proto_tree_add_item(taii_tree, hf_ldp_tlv_fec_gen_taii_type,tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(taii_tree, hf_ldp_tlv_fec_gen_taii_length,tvb, offset + 1, 1, ENC_BIG_ENDIAN);
                    if ( gen_fec_id_len > 0)
                    {
                        /* Get the AAI Type. */
                        /* If it is  Type 2 (RFC 5003), then the length is 12 bytes, */
                        /* and the following fields exist. */
                        /*    0                   1                   2                   3    */
                        /*    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  */
                        /*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
                        /*   |  AII Type=02  |    Length     |        Global ID              | */
                        /*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
                        /*   |       Global ID (contd.)      |        Prefix                 | */
                        /*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
                        /*   |       Prefix (contd.)         |        AC ID                  | */
                        /*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
                        /*   |      AC ID                    | */
                        /*   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */

                        if ( aai_type == 2)
                        {
                            dissect_genpwid_fec_aai_type2_parameter(tvb, offset +2, taii_tree, gen_fec_id_len);
                        }
                        else
                        {
                            proto_tree_add_item(taii_tree, hf_ldp_tlv_fec_gen_taii_value, tvb, offset+2, gen_fec_id_len , ENC_NA);
                        }
                    }
                }
                rem -= 2 + gen_fec_id_len;
                vc_len -= 2 + gen_fec_id_len;
                offset += 2 + gen_fec_id_len;


            } else {
                proto_tree_add_text(fec_tree,tvb,offset , 2 +vc_len, "Generalized FEC: TAII size format error");
                return;
            }

            break;
        }
        default:  /* Unknown */
            /* XXX - do all FEC's have a length that's a multiple of 4? */
            /* Hmmm, don't think so. Will check. RJS. */
            /* If we don't know its structure, we have to exit */
            ti = proto_tree_add_text(val_tree, tvb, offset, 4, "FEC Element %u", ix);
            fec_tree = proto_item_add_subtree(ti, ett_ldp_fec);
            proto_tree_add_text(fec_tree, tvb, offset, rem, "Unknown FEC TLV type");
            return;
        }
        ix++;
    }
}

/* Dissect Address List TLV */

static void
dissect_tlv_address_list(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;
    guint16     family, ix;
    guint8      addr_size, *addr;
    string_handler_func *str_handler = default_str_handler;
    const char *str;

    if ( rem < 2 ) {
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing Address List TLV: length is %d, should be >= 2",
                            rem);
        return;
    }

    family=tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_ldp_tlv_addrl_addr_family, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    switch(family) {
    case AFNUM_INET: /*IPv4*/
        addr_size=4;
        str_handler=ip_to_str;
        break;
    case AFNUM_INET6: /*IPv6*/
        addr_size=16;
        str_handler = (string_handler_func *) ip6_to_str;
        break;
    default:
        proto_tree_add_text(tree, tvb, offset+2, rem-2,
                            "Support for Address Family not implemented");
        return;
    }

    offset+=2; rem-=2;
    ti=proto_tree_add_text(tree, tvb, offset, rem, "Addresses");
    val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);

    addr=ep_alloc(addr_size);

    for(ix=1; rem >= addr_size; ix++, offset += addr_size,
            rem -= addr_size) {
        if ( (tvb_memcpy(tvb, addr, offset, addr_size))
             == NULL)
            break;

        str = str_handler((const guint8 *)addr);
        proto_tree_add_string_format(val_tree,
                                     hf_ldp_tlv_addrl_addr, tvb, offset, addr_size, str,
                                     "Address %u: %s", ix, str);
    }
    if (rem)
        proto_tree_add_text(val_tree, tvb, offset, rem,
                            "Error processing TLV: Extra data at end of address list");
}

/* Dissect Path Vector TLV */

static void
dissect_tlv_path_vector(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;
    guint8      ix;
    guint32 addr;

    ti=proto_tree_add_text(tree, tvb, offset, rem, "LSR IDs");
    val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);

    for(ix=1; rem >= 4; ix++, offset += 4, rem -= 4) {
        addr = tvb_get_ipv4(tvb, offset);
        proto_tree_add_ipv4_format(val_tree,
                                   hf_ldp_tlv_pv_lsrid, tvb, offset, 4,
                                   addr, "LSR Id %u: %s", ix,
                                   ip_to_str((guint8 *)&addr));
    }
    if (rem)
        proto_tree_add_text(val_tree, tvb, offset, rem,
                            "Error processing TLV: Extra data at end of path vector");
}

/* Dissect ATM Label TLV */

static void
dissect_tlv_atm_label(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;
    guint16     id;

    if (rem != 4){
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing ATM Label TLV: length is %d, should be 4",
                            rem);
        return;
    }
    ti=proto_tree_add_text(tree, tvb, offset, rem, "ATM Label");
    val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);

    proto_tree_add_item(val_tree, hf_ldp_tlv_atm_label_vbits, tvb, offset, 1, ENC_BIG_ENDIAN);

    id=tvb_get_ntohs(tvb, offset)&0x0FFF;
    proto_tree_add_uint_format(val_tree, hf_ldp_tlv_atm_label_vpi, tvb, offset, 2, id, "VPI: %u", id);

    id=tvb_get_ntohs(tvb, offset+2);
    proto_tree_add_uint_format(val_tree, hf_ldp_tlv_atm_label_vci, tvb, offset+2, 2, id, "VCI: %u", id);
}

/* Dissect FRAME RELAY Label TLV */

static void
dissect_tlv_frame_label(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;
    guint8      len;
    guint32     id;

    if (rem != 4){
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing Frame Relay Label TLV: length is %d, should be 4",
                            rem);
        return;
    }
    ti=proto_tree_add_text(tree, tvb, offset, rem, "Frame Relay Label");
    val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);

    len=(guint8)(tvb_get_ntohs(tvb, offset)>>7) & 0x03;
    proto_tree_add_uint_format(val_tree, hf_ldp_tlv_fr_label_len, tvb, offset, 2, len,
                               "Number of DLCI bits: %s (%u)", val_to_str(len, tlv_fr_len_vals, "Unknown Length"), len);

    id=tvb_get_ntoh24(tvb, offset+1)&0x7FFFFF;
    proto_tree_add_uint_format(val_tree,
                               hf_ldp_tlv_fr_label_dlci, tvb, offset+1, 3, id, "DLCI: %u", id);
}

/* Dissect STATUS TLV */

static void
dissect_tlv_status(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;
    guint32     data;

    if (rem != 10){
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing Status TLV: length is %d, should be 10",
                            rem);
        return;
    }

    ti=proto_tree_add_text(tree, tvb, offset, rem, "Status");
    val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);

    proto_tree_add_item(val_tree, hf_ldp_tlv_status_ebit, tvb, offset, 1, FALSE);
    proto_tree_add_item(val_tree, hf_ldp_tlv_status_fbit, tvb, offset, 1, FALSE);

    data=tvb_get_ntohl(tvb, offset)&0x3FFFFFFF;
    proto_tree_add_uint_format(val_tree, hf_ldp_tlv_status_data, tvb, offset, 4,
                               data, "Status Data: %s (0x%X)", val_to_str(data, tlv_status_data, "Unknown Status Data"), data);

    proto_tree_add_item(val_tree, hf_ldp_tlv_status_msg_id, tvb, offset+4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(val_tree, hf_ldp_tlv_status_msg_type, tvb, offset+8, 2, ENC_BIG_ENDIAN);
}

/* Dissect Returned PDU TLV */

static void
dissect_tlv_returned_pdu(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;

    if (rem < 10){
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing Returned PDU TLV: length is %d, should be >= 10",
                            rem);
        return;
    }
    ti=proto_tree_add_text(tree, tvb, offset, rem, "Returned PDU");
    val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);

    proto_tree_add_item(val_tree, hf_ldp_tlv_returned_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(val_tree, hf_ldp_tlv_returned_pdu_len, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(val_tree, hf_ldp_tlv_returned_lsr, tvb, offset+4, 4, FALSE);
    proto_tree_add_item(val_tree, hf_ldp_tlv_returned_ls_id, tvb, offset+8, 2, ENC_BIG_ENDIAN);
    offset += 10;
    rem -= 10;

    if ( rem > 0 ) {
        /*XXX - dissect returned pdu data*/
        proto_tree_add_text(val_tree, tvb, offset, rem, "Returned PDU Data");
    }
}

/* Dissect Returned MESSAGE TLV */

static void
dissect_tlv_returned_message(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;
    guint16     type;

    if (rem < 4) {
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing Returned Message TLV: length is %d, should be >= 4",
                            rem);
        return;
    }
    ti=proto_tree_add_text(tree, tvb, offset, rem, "Returned Message");
    val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);

    proto_tree_add_item(val_tree, hf_ldp_tlv_returned_msg_ubit, tvb, offset, 1, FALSE);

    type=tvb_get_ntohs(tvb, offset)&0x7FFF;
    /*chk for vendor-private*/
    if (type>=LDP_VENDOR_PRIVATE_START && type<=LDP_VENDOR_PRIVATE_END){
        proto_tree_add_uint_format(val_tree, hf_ldp_tlv_returned_msg_type, tvb, offset, 2,
                                   type, "Message Type: Vendor Private (0x%X)", type);
        /*chk for experimental*/
    } else if (type>=LDP_EXPERIMENTAL_MESSAGE_START && type<=LDP_EXPERIMENTAL_MESSAGE_END){
        proto_tree_add_uint_format(val_tree, hf_ldp_tlv_returned_msg_type, tvb, offset, 2,
                                   type, "Message Type: Experimental (0x%X)", type);
    } else {
        proto_tree_add_uint_format(val_tree, hf_ldp_tlv_returned_msg_type, tvb, offset, 2,
                                   type, "Message Type: %s (0x%X)", val_to_str(type, ldp_message_types,"Unknown Message Type"), type);
    }

    proto_tree_add_item(val_tree, hf_ldp_tlv_returned_msg_len, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    offset += 4;
    rem    -= 4;

    if ( rem >= 4  ) { /*have msg_id*/
        proto_tree_add_item(val_tree, hf_ldp_tlv_returned_msg_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        rem -= 4;
    }

    if ( rem > 0 ) {
        /*XXX - dissect returned msg parameters*/
        proto_tree_add_text(val_tree, tvb, offset, rem, "Returned Message Parameters");
    }
}

/* Dissect the common hello params */

static void
#if 0
dissect_tlv_common_hello_parms(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
#else
dissect_tlv_common_hello_parms(tvbuff_t *tvb, guint offset, proto_tree *tree)
#endif
{
#if 0
    proto_tree *ti;
#endif
    proto_tree *val_tree;

#if 0
    ti = proto_tree_add_item(tree, hf_ldp_tlv_value, tvb, offset, rem, ENC_NA);
    val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);
#else
    val_tree=tree;
#endif
    proto_tree_add_item(val_tree, hf_ldp_tlv_val_hold, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(val_tree, hf_ldp_tlv_val_target, tvb, offset + 2, 2, FALSE);
    proto_tree_add_item(val_tree, hf_ldp_tlv_val_request, tvb, offset + 2, 2, FALSE);
    proto_tree_add_item(val_tree, hf_ldp_tlv_val_res, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
}

/* Dissect MAC TLV */

static void
dissect_tlv_mac(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree   *ti, *val_tree;
    guint8        ix;

    ti = proto_tree_add_text(tree, tvb, offset, rem, "MAC addresses");
    val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);

    for(ix=1; rem >= 6; ix++, offset += 6, rem -= 6) {
        proto_tree_add_item(val_tree, hf_ldp_tlv_mac, tvb, offset, 6, FALSE);
    }
    if (rem)
        proto_tree_add_text(val_tree, tvb, offset, rem,
                            "Error processing TLV: Extra data at end of path vector");
}



/* Dissect the common session params */

static void
dissect_tlv_common_session_parms(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;

    if ( rem != 14) { /*length of Comm Sess Parms tlv*/
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing Common Session Parameters TLV: length is %d, should be 14",
                            rem);
        return;
    }
    ti = proto_tree_add_text(tree, tvb, offset, rem, "Parameters");
    val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

    /*Protocol Version*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_ver, tvb,offset, 2, ENC_BIG_ENDIAN);

    /*KeepAlive Time*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_ka, tvb,offset + 2, 2, ENC_BIG_ENDIAN);

    /*A bit*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_advbit,tvb, offset + 4, 1, FALSE);

    /*D bit*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_ldetbit,tvb, offset + 4, 1, FALSE);

    /*Path Vector Limit*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_pvlim,tvb, offset + 5, 1, ENC_BIG_ENDIAN);

    /*Max PDU Length*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_mxpdu,tvb, offset + 6, 2, ENC_BIG_ENDIAN);

    /*Rx LSR*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_rxlsr,tvb, offset + 8, 4, FALSE);

    /*Rx LS*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_rxls,tvb, offset + 12, 2, ENC_BIG_ENDIAN);
}

/* Dissect the atm session params */

static void
dissect_tlv_atm_session_parms(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree, *lbl_tree;
    guint8      numlr, ix;
    guint16     id;

    if (rem < 4) {
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing ATM Parameters TLV: length is %d, should be >= 4",
                            rem);
        return;
    }

    ti = proto_tree_add_text(tree, tvb, offset, rem,"ATM Parameters");
    val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_atm_merge,tvb, offset, 1, ENC_BIG_ENDIAN);

    /*get the number of label ranges*/
    numlr=(tvb_get_guint8(tvb, offset)>>2) & 0x0F;
    proto_tree_add_uint_format(val_tree, hf_ldp_tlv_sess_atm_lr,
                               tvb, offset, 1, numlr, "Number of Label Range components: %u",
                               numlr);

    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_atm_dir,tvb, offset, 1, FALSE);

    /*move into range components*/
    offset += 4;
    rem    -= 4;
    ti = proto_tree_add_text(val_tree, tvb, offset, rem,"ATM Label Range Components");

    if (numlr) {
        val_tree=proto_item_add_subtree(ti,ett_ldp_tlv_val);
        if ( ! val_tree ) return;
    }
    /*now dissect ranges*/
    for(ix=1; numlr > 0 && rem >= 8; ix++, rem-=8, numlr--) {
        ti=proto_tree_add_text(val_tree, tvb, offset, 8,
                               "ATM Label Range Component %u", ix);
        lbl_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);

        id=tvb_get_ntohs(tvb, offset)&0x0FFF;
        proto_tree_add_uint_format(lbl_tree,
                                   hf_ldp_tlv_sess_atm_minvpi,
                                   tvb, offset, 2,
                                   id, "Minimum VPI: %u", id);
        id=tvb_get_ntohs(tvb, offset+4)&0x0FFF;
        proto_tree_add_uint_format(lbl_tree,
                                   hf_ldp_tlv_sess_atm_maxvpi,
                                   tvb, (offset+4), 2, id,
                                   "Maximum VPI: %u", id);

        id=tvb_get_ntohs(tvb, offset+2);
        proto_tree_add_uint_format(lbl_tree,
                                   hf_ldp_tlv_sess_atm_minvci,
                                   tvb, offset+2, 2,
                                   id, "Minimum VCI: %u", id);
        id=tvb_get_ntohs(tvb, offset+6);
        proto_tree_add_uint_format(lbl_tree,
                                   hf_ldp_tlv_sess_atm_maxvci,
                                   tvb, offset+6, 2,
                                   id, "Maximum VCI: %u", id);

        offset += 8;
    }
    if( rem || numlr)
        proto_tree_add_text(val_tree, tvb, offset, rem,
                            "Error processing TLV: Extra data at end of TLV");
}

/* Dissect the frame relay session params */

static void
dissect_tlv_frame_relay_session_parms(tvbuff_t *tvb, guint offset,proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree, *lbl_tree;
    guint8      numlr, ix, len;
    guint32     id;

    if(rem < 4) {
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing Frame Relay Parameters TLV: length is %d, should be >= 4",
                            rem);
        return;
    }

    ti = proto_tree_add_text(tree, tvb, offset, rem, "Frame Relay Parameters");
    val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_fr_merge,
                        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*get the number of label ranges*/
    numlr=(tvb_get_guint8(tvb, offset)>>2) & 0x0F;
    proto_tree_add_uint_format(val_tree, hf_ldp_tlv_sess_fr_lr,
                               tvb, offset, 1, numlr, "Number of Label Range components: %u",
                               numlr);

    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_fr_dir,
                        tvb, offset, 1, FALSE);

    /*move into range components*/
    offset += 4;
    rem    -= 4;
    ti = proto_tree_add_text(val_tree, tvb, offset, rem,
                             "Frame Relay Label Range Components");

    if(numlr) {
        val_tree=proto_item_add_subtree(ti,
                                        ett_ldp_tlv_val);
        if( ! val_tree ) return;
    }

    /*now dissect ranges*/
    for(ix=1; numlr > 0 && rem >= 8; ix++, rem-=8, numlr--) {
        ti=proto_tree_add_text(val_tree, tvb, offset, 8,
                               "Frame Relay Label Range Component %u", ix);
        lbl_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);

        len=(guint8)(tvb_get_ntohs(tvb, offset)>>7) & 0x03;
        proto_tree_add_uint_format(lbl_tree, hf_ldp_tlv_sess_fr_len, tvb, offset, 2, len,
                                   "Number of DLCI bits: %s (%u)", val_to_str(len, tlv_fr_len_vals, "Unknown Length"), len);

        id=tvb_get_ntoh24(tvb, offset+1)&0x7FFFFF;
        proto_tree_add_uint_format(lbl_tree,
                                   hf_ldp_tlv_sess_fr_mindlci, tvb, offset+1, 3, id, "Minimum DLCI %u", id);
        id=tvb_get_ntoh24(tvb, offset+5)&0x7FFFFF;
        proto_tree_add_uint_format(lbl_tree,
                                   hf_ldp_tlv_sess_fr_maxdlci, tvb, offset+5, 3, id, "Maximum DLCI %u", id);

        offset += 8;
    }

    if( rem || numlr)
        proto_tree_add_text(val_tree, tvb, offset, rem,
                            "Error processing TLV: Extra data at end of TLV");
}

/* Dissect the Fault Tolerant (FT) Session TLV */

static void
dissect_tlv_ft_session(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree, *flags_tree;
    guint16 flags;

    if(rem != 12){
        /* error, length must be 12 bytes */
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing FT Session TLV: length is %d, should be 12",
                            rem);
        return;
    }

    ti = proto_tree_add_text(tree, tvb, offset, rem, "FT Session Parameters");
    val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

    /* Flags */
    ti = proto_tree_add_item(val_tree, hf_ldp_tlv_ft_sess_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    flags_tree = proto_item_add_subtree(ti,  ett_ldp_tlv_ft_flags);

    flags = tvb_get_ntohs(tvb, offset);
    proto_item_append_text(ti, " (%s%s)", (flags & 0x8000) ? "R, " : "",
                           val_to_str(flags & 0xF, tlv_ft_flags, "Invalid"));
    proto_tree_add_item(flags_tree, hf_ldp_tlv_ft_sess_flag_r, tvb, offset, 2, FALSE);
    proto_tree_add_item(flags_tree, hf_ldp_tlv_ft_sess_flag_res, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_ldp_tlv_ft_sess_flag_s, tvb, offset, 2, FALSE);
    proto_tree_add_item(flags_tree, hf_ldp_tlv_ft_sess_flag_a, tvb, offset, 2, FALSE);
    proto_tree_add_item(flags_tree, hf_ldp_tlv_ft_sess_flag_c, tvb, offset, 2, FALSE);
    proto_tree_add_item(flags_tree, hf_ldp_tlv_ft_sess_flag_l, tvb, offset, 2, FALSE);

    /* Reserved */
    proto_tree_add_item(val_tree, hf_ldp_tlv_ft_sess_res, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    /* FT Reconnect TO */
    proto_tree_add_item(val_tree, hf_ldp_tlv_ft_sess_reconn_to, tvb, offset + 4,
                        4, ENC_BIG_ENDIAN);

    /* Recovery Time */
    proto_tree_add_item(val_tree, hf_ldp_tlv_ft_sess_recovery_time, tvb, offset + 8,
                        4, ENC_BIG_ENDIAN);
}

static void
dissect_tlv_lspid(tvbuff_t *tvb, guint offset,proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;

    if(rem != 8) {
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing LSP ID TLV: length is %d, should be 8",
                            rem);
        return;
    }

    ti = proto_tree_add_text(tree, tvb, offset, rem, "LSP ID");
    val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

    proto_tree_add_item(val_tree, hf_ldp_tlv_lspid_act_flg,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(val_tree, hf_ldp_tlv_lspid_cr_lsp,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(val_tree, hf_ldp_tlv_lspid_ldpid,
                        tvb, offset, 4, FALSE);
}

static void
dissect_tlv_er_hop_ipv4(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;

    if(rem != 8) {
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing ER HOP IPv4 TLV: length is %d, should be 8",
                            rem);
        return;
    }
    ti = proto_tree_add_text(tree, tvb, offset, rem, "ER HOP IPv4");
    val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

    if(val_tree != NULL) {
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_loose,
                            tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_prelen,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset ++;
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_prefix4,
                            tvb, offset, 4, FALSE);
    }
}

static void
dissect_tlv_er_hop_ipv6(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;

    if(rem != 20) {
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing ER HOP IPv6 TLV: length is %d, should be 20",
                            rem);
        return;
    }
    ti = proto_tree_add_text(tree, tvb, offset, rem, "ER HOP IPv6");
    val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

    if(val_tree != NULL) {
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_loose,
                            tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_prelen,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset ++;
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_prefix6,
                            tvb, offset, 16, FALSE);
    }
}

static void
dissect_tlv_er_hop_as(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;

    if(rem != 4) {
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing ER HOP AS TLV: length is %d, should be 4",
                            rem);
        return;
    }
    ti = proto_tree_add_text(tree, tvb, offset, rem, "ER HOP AS");
    val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

    if(val_tree != NULL) {
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_loose,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_as,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
    }
}

static void
dissect_tlv_er_hop_lspid(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;

    if(rem != 8) {
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing ER HOP LSPID TLV: length is %d, should be 8",
                            rem);
        return;
    }
    ti = proto_tree_add_text(tree, tvb, offset, rem, "ER HOP LSPID");
    val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

    if(val_tree != NULL) {
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_loose,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_cr_lsp,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_ldpid,
                            tvb, offset, 4, FALSE);
    }
}

static void
dissect_tlv_traffic(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;
    guint8  val_8;
    float   val_f;
    proto_item *pi;

    if(rem != 24) {
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing Traffic Parameters TLV: length is %d, should be 24",
                            rem);
        return;
    }
    ti = proto_tree_add_text(tree, tvb, offset, rem, "Traffic parameters");
    val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

    if(val_tree != NULL) {
        /* flags */
        proto_tree_add_item(val_tree, hf_ldp_tlv_flags_reserv, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(val_tree, hf_ldp_tlv_flags_weight, tvb, offset, 1, FALSE);
        proto_tree_add_item(val_tree, hf_ldp_tlv_flags_ebs, tvb, offset, 1, FALSE);
        proto_tree_add_item(val_tree, hf_ldp_tlv_flags_cbs, tvb, offset, 1, FALSE);
        proto_tree_add_item(val_tree, hf_ldp_tlv_flags_cdr, tvb, offset, 1, FALSE);
        proto_tree_add_item(val_tree, hf_ldp_tlv_flags_pbs, tvb, offset, 1, FALSE);
        proto_tree_add_item(val_tree, hf_ldp_tlv_flags_pdr, tvb, offset, 1, FALSE);

        offset ++;
        /* frequency */
        proto_tree_add_item(val_tree, hf_ldp_tlv_frequency, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset ++;

        /* reserver byte */
        offset ++;

        /* weight */
        pi = proto_tree_add_item(val_tree, hf_ldp_tlv_weight, tvb, offset, 1, ENC_BIG_ENDIAN);
        val_8 = tvb_get_guint8(tvb, offset);
        if (val_8 == 0)
            proto_item_set_text(pi, "Weight: Not applicable");
        offset ++;

        /* PDR */
        val_f = tvb_get_ntohieee_float (tvb, offset);
        proto_tree_add_double_format(val_tree, hf_ldp_tlv_pdr, tvb, offset,
                                     4, val_f, "PDR: %.10g Bps", val_f);
        offset += 4;
        /* PBS */
        val_f = tvb_get_ntohieee_float (tvb, offset);
        proto_tree_add_double_format(val_tree, hf_ldp_tlv_pbs, tvb, offset,
                                     4, val_f, "PBS: %.10g Bytes", val_f);
        offset += 4;

        /* CDR */
        val_f = tvb_get_ntohieee_float (tvb, offset);
        proto_tree_add_double_format(val_tree, hf_ldp_tlv_cdr, tvb, offset,
                                     4, val_f, "CDR: %.10g Bps", val_f);
        offset += 4;

        /* CBS */
        val_f = tvb_get_ntohieee_float (tvb, offset);
        proto_tree_add_double_format(val_tree, hf_ldp_tlv_cbs, tvb, offset,
                                     4, val_f, "CBS: %.10g Bytes", val_f);
        offset += 4;

        /* EBS */
        val_f = tvb_get_ntohieee_float (tvb, offset);
        proto_tree_add_double_format(val_tree, hf_ldp_tlv_ebs, tvb, offset,
                                     4, val_f, "EBS: %.10g Bytes", val_f);

    }
}

static void
dissect_tlv_route_pinning(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;

    if(rem != 4) {
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing Route Pinning TLV: length is %d, should be 4",
                            rem);
        return;
    }
    ti = proto_tree_add_text(tree, tvb, offset, rem, "Route Pinning");
    val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

    if(val_tree != NULL) {
        proto_tree_add_item(val_tree, hf_ldp_tlv_route_pinning,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
    }
}


static void
dissect_tlv_resource_class(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;

    if(rem != 4) {
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing Resource Class TLV: length is %d, should be 4",
                            rem);
        return;
    }
    ti = proto_tree_add_text(tree, tvb, offset, rem, "Resource Class");
    val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

    if(val_tree != NULL) {
        proto_tree_add_item(val_tree, hf_ldp_tlv_resource_class,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
    }
}


static void
dissect_tlv_preemption(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;

    if(rem != 4) {
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing Preemption TLV: length is %d, should be 4",
                            rem);
        return;
    }
    ti = proto_tree_add_text(tree, tvb, offset, rem, "Preemption");
    val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

    if(val_tree != NULL) {
        proto_tree_add_item(val_tree, hf_ldp_tlv_set_prio,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(val_tree, hf_ldp_tlv_hold_prio,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
    }
}


static void
dissect_tlv_diffserv(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    static int *hfindexes[] = {
        &hf_ldp_tlv_diffserv_map,
        &hf_ldp_tlv_diffserv_map_exp,
        &hf_ldp_tlv_diffserv_phbid,
        &hf_ldp_tlv_diffserv_phbid_dscp,
        &hf_ldp_tlv_diffserv_phbid_code,
        &hf_ldp_tlv_diffserv_phbid_bit14,
        &hf_ldp_tlv_diffserv_phbid_bit15
    };
    static gint *etts[] = {
        &ett_ldp_diffserv_map,
        &ett_ldp_diffserv_map_phbid
    };
    int type, mapnb, count;

    if (rem < 4) {
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing Diff-Serv TLV: length is %d, should be >= 4", rem);
        return;
    }
    proto_tree_add_uint(tree, hf_ldp_tlv_diffserv_type, tvb, offset, 1,
                        type = tvb_get_guint8(tvb, offset));
    type = (type >> 7) + 1;
    if (type == 1) {
        /* E-LSP */
        offset += 3;
        proto_tree_add_uint(tree, hf_ldp_tlv_diffserv_mapnb, tvb, offset,
                            1, mapnb = tvb_get_guint8(tvb, offset) & 15);
        offset += 1;
        for (count = 0; count < mapnb; count++) {
            dissect_diffserv_mpls_common(tvb, tree, type, offset, hfindexes, etts);
            offset += 4;
        }
    }
    else if (type == 2) {
        /* L-LSP */
        dissect_diffserv_mpls_common(tvb, tree, type, offset + 2, hfindexes, etts);
    }
}


static int
dissect_tlv(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem);

static void
dissect_tlv_er(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;
    int len;

    ti = proto_tree_add_text(tree, tvb, offset, rem, "Explicit route");
    val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

    if(val_tree != NULL) {
        while (rem > 0) {
            len = dissect_tlv (tvb, offset, val_tree, rem);
            offset += len;
            rem -= len;
        }
    }
}


static void
dissect_tlv_pw_status(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem);

static void
dissect_tlv_pw_grouping(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem);

/* Dissect a TLV and return the number of bytes consumed ... */

static int
dissect_tlv(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    guint16 type, typebak;
    int length;

    length=tvb_reported_length_remaining(tvb, offset);
    rem=MIN(rem, length);

    if( rem < 4 ) {/*chk for minimum header*/
        if (tree) {
            proto_tree_add_text(tree, tvb, offset, rem,
                                "Error processing TLV: length is %d, should be >= 4",
                                rem);
        }
        return rem;
    }
    type = tvb_get_ntohs(tvb, offset) & 0x3FFF;

    length = tvb_get_ntohs(tvb, offset + 2);
    rem -= 4; /*do not count header*/
    length = MIN(length, rem);  /* Don't go haywire if a problem ... */

    if (tree) {
        proto_tree *ti = NULL, *tlv_tree;
        /*chk for vendor-private*/
        if(type>=TLV_VENDOR_PRIVATE_START && type<=TLV_VENDOR_PRIVATE_END){
            typebak=type;               /*keep type*/
            type=TLV_VENDOR_PRIVATE_START;
            ti = proto_tree_add_text(tree, tvb, offset, length + 4, "Vendor Private TLV");
            /*chk for experimental*/
        } else if(type>=TLV_EXPERIMENTAL_START && type<=TLV_EXPERIMENTAL_END){
            typebak=type;               /*keep type*/
            type=TLV_EXPERIMENTAL_START;
            ti = proto_tree_add_text(tree, tvb, offset, length + 4, "Experimental TLV");
        } else {
            typebak=0;
            ti = proto_tree_add_text(tree, tvb, offset, length + 4, "%s",
                                     val_to_str(type, tlv_type_names, "Unknown TLV type (0x%04X)"));
        }

        tlv_tree = proto_item_add_subtree(ti, ett_ldp_tlv);

        proto_tree_add_item(tlv_tree, hf_ldp_tlv_unknown, tvb, offset, 1, ENC_BIG_ENDIAN);

        switch (type) {
        case TLV_VENDOR_PRIVATE_START:
            proto_tree_add_uint_format(tlv_tree, hf_ldp_tlv_type, tvb, offset, 2,
                                       typebak, "TLV Type: Vendor Private (0x%X)", typebak);
            break;
        case TLV_EXPERIMENTAL_START:
            proto_tree_add_uint_format(tlv_tree, hf_ldp_tlv_type, tvb, offset, 2,
                                       typebak, "TLV Type: Experimental (0x%X)", typebak);
            break;
        default:
            proto_tree_add_uint_format(tlv_tree, hf_ldp_tlv_type, tvb, offset, 2,
                                       type, "TLV Type: %s (0x%X)", val_to_str(type, tlv_type_names, "Unknown TLV type"), type );
        }

        proto_tree_add_item(tlv_tree, hf_ldp_tlv_len, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

        switch (type) {

        case TLV_FEC:
            dissect_tlv_fec(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_ADDRESS_LIST:
            dissect_tlv_address_list(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_HOP_COUNT:
            if( length != 1 ) /*error, only one byte*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4,length,
                                    "Error processing Hop Count TLV: length is %d, should be 1",
                                    length);
            else
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_hc_value, tvb,offset + 4, length, ENC_BIG_ENDIAN);
            break;

        case TLV_PATH_VECTOR:
            dissect_tlv_path_vector(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_GENERIC_LABEL:
            if( length != 4 ) /*error, need only label*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing Generic Label TLV: length is %d, should be 4",
                                    length);
            else {
                guint32 label=tvb_get_ntohl(tvb, offset+4) & 0x000FFFFF;

                proto_tree_add_uint_format(tlv_tree, hf_ldp_tlv_generic_label,
                                           tvb, offset+4, length, label, "Generic Label: %u", label);
            }
            break;

        case TLV_ATM_LABEL:
            dissect_tlv_atm_label(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_FRAME_LABEL:
            dissect_tlv_frame_label(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_FT_PROTECTION:
            if( length != 4 ) /* Length must be 4 bytes */
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing FT Protection TLV: length is %d, should be 4",
                                    length);
            else
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_ft_protect_sequence_num, tvb,
                                    offset + 4,length, ENC_BIG_ENDIAN);
            break;

        case TLV_STATUS:
            dissect_tlv_status(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_EXTENDED_STATUS:
            if( length != 4 ) /*error, need only status_code(guint32)*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing Extended Status TLV: length is %d, should be 4",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_extstatus_data, tvb, offset + 4, length, ENC_BIG_ENDIAN);
            }
            break;

        case TLV_RETURNED_PDU:
            dissect_tlv_returned_pdu(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_RETURNED_MESSAGE:
            dissect_tlv_returned_message(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_COMMON_HELLO_PARMS:
#if 0
            dissect_tlv_common_hello_parms(tvb, offset + 4, tlv_tree, length);
#else
            dissect_tlv_common_hello_parms(tvb, offset + 4, tlv_tree);
#endif
            break;

        case TLV_IPV4_TRANSPORT_ADDRESS:
            if( length != 4 ) /*error, need only ipv4*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing IPv4 Transport Address TLV: length is %d, should be 4",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_ipv4_taddr, tvb, offset + 4, 4, FALSE);
            }
            break;

        case TLV_CONFIGURATION_SEQNO:
            if( length != 4 ) /*error, need only seq_num(guint32)*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing Configuration Sequence Number TLV: length is %d, should be 4",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_config_seqno, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            }
            break;

        case TLV_IPV6_TRANSPORT_ADDRESS:
            if( length != 16 ) /*error, need only ipv6*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing IPv6 Transport Address TLV: length is %d, should be 16",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_ipv6_taddr, tvb, offset + 4, 16, FALSE);
            }
            break;

        case TLV_MAC: /* draft-lasserre-vkompella-ppvpn-vpls-02.txt */
            dissect_tlv_mac(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_COMMON_SESSION_PARMS:
            dissect_tlv_common_session_parms(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_ATM_SESSION_PARMS:
            dissect_tlv_atm_session_parms(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_FRAME_RELAY_SESSION_PARMS:
            dissect_tlv_frame_relay_session_parms(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_FT_SESSION:
            /* Used in RFC3478 LDP Graceful Restart */
            dissect_tlv_ft_session(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_FT_ACK:
            if( length != 4 ) /* Length must be 4 bytes */
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing FT ACK TLV: length is %d, should be 4",
                                    length);
            else
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_ft_ack_sequence_num, tvb,
                                    offset + 4,length, ENC_BIG_ENDIAN);
            break;

        case TLV_FT_CORK:
            if( length != 0 ) /* Length must be 0 bytes */
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing FT Cork TLV: length is %d, should be 0",
                                    length);
            break;

        case TLV_LABEL_REQUEST_MESSAGE_ID:
            if( length != 4 ) /*error, need only one msgid*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing Label Request Message ID TLV: length is %d, should be 4",
                                    length);
            else
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_lbl_req_msg_id, tvb,offset + 4,length, ENC_BIG_ENDIAN);
            break;

        case TLV_LSPID:
            dissect_tlv_lspid(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_ER:
            dissect_tlv_er(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_ER_HOP_IPV4:
            dissect_tlv_er_hop_ipv4(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_ER_HOP_IPV6:
            dissect_tlv_er_hop_ipv6(tvb, offset +4, tlv_tree, length);
            break;

        case TLV_ER_HOP_AS:
            dissect_tlv_er_hop_as(tvb, offset + 4, tlv_tree, length);
            break;

        case TLV_ER_HOP_LSPID:
            dissect_tlv_er_hop_lspid(tvb, offset +4, tlv_tree, length);
            break;

        case TLV_TRAFFIC_PARAM:
            dissect_tlv_traffic(tvb, offset +4, tlv_tree, length);
            break;

        case TLV_PREEMPTION:
            dissect_tlv_preemption(tvb, offset +4, tlv_tree, length);
            break;

        case TLV_RESOURCE_CLASS:
            dissect_tlv_resource_class(tvb, offset +4, tlv_tree, length);
            break;

        case TLV_ROUTE_PINNING:
            dissect_tlv_route_pinning(tvb, offset +4, tlv_tree, length);
            break;

        case TLV_DIFFSERV:
            dissect_tlv_diffserv(tvb, offset +4, tlv_tree, length);
            break;

        case TLV_VENDOR_PRIVATE_START:
            if( length < 4 ) /*error, at least Vendor ID*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing Vendor Private Start TLV: length is %d, should be >= 4",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_vendor_id, tvb,offset + 4, 4, ENC_BIG_ENDIAN);
                if( length > 4 )  /*have data*/
                    proto_tree_add_text(tlv_tree, tvb, offset + 8, length-4,"Data");
            }
            break;

        case TLV_EXPERIMENTAL_START:
            if( length < 4 ) /*error, at least Experiment ID*/
                proto_tree_add_text(tlv_tree, tvb, offset + 4, length,
                                    "Error processing Experimental Start TLV: length is %d, should be >= 4",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_experiment_id, tvb,offset + 4, 4, ENC_BIG_ENDIAN);
                if( length > 4 )  /*have data*/
                    proto_tree_add_text(tlv_tree, tvb, offset + 8, length-4,"Data");
            }
            break;

        case TLV_PW_STATUS:
        {
            /* Ref: RFC 4447  and 4446*/
            dissect_tlv_pw_status(tvb, offset +4, tlv_tree, length);
            break;
        }
        case TLV_PW_INTERFACE_PARAMETERS:
        {
            /* Ref: RFC 4447 */
            static int *interface_params_header_fields[] = {
                &hf_ldp_tlv_intparam_length ,
                &hf_ldp_tlv_intparam_mtu ,
                &hf_ldp_tlv_intparam_tdmbps ,
                &hf_ldp_tlv_intparam_id ,
                &hf_ldp_tlv_intparam_maxcatmcells ,
                &hf_ldp_tlv_intparam_desc ,
                &hf_ldp_tlv_intparam_cepbytes ,
                &hf_ldp_tlv_intparam_cepopt_ais ,
                &hf_ldp_tlv_intparam_cepopt_une ,
                &hf_ldp_tlv_intparam_cepopt_rtp ,
                &hf_ldp_tlv_intparam_cepopt_ebm ,
                &hf_ldp_tlv_intparam_cepopt_mah ,
                &hf_ldp_tlv_intparam_cepopt_res ,
                &hf_ldp_tlv_intparam_cepopt_ceptype ,
                &hf_ldp_tlv_intparam_cepopt_t3 ,
                &hf_ldp_tlv_intparam_cepopt_e3 ,
                &hf_ldp_tlv_intparam_vlanid ,
                &hf_ldp_tlv_intparam_dlcilen ,
                &hf_ldp_tlv_intparam_fcslen ,
                &hf_ldp_tlv_intparam_tdmopt_r ,
                &hf_ldp_tlv_intparam_tdmopt_d ,
                &hf_ldp_tlv_intparam_tdmopt_f ,
                &hf_ldp_tlv_intparam_tdmopt_res1 ,
                &hf_ldp_tlv_intparam_tdmopt_pt ,
                &hf_ldp_tlv_intparam_tdmopt_res2 ,
                &hf_ldp_tlv_intparam_tdmopt_freq ,
                &hf_ldp_tlv_intparam_tdmopt_ssrc ,
                &hf_ldp_tlv_intparam_vccv_cctype_cw ,
                &hf_ldp_tlv_intparam_vccv_cctype_mplsra ,
                &hf_ldp_tlv_intparam_vccv_cctype_ttl1 ,
                &hf_ldp_tlv_intparam_vccv_cvtype_icmpping ,
                &hf_ldp_tlv_intparam_vccv_cvtype_lspping ,
                &hf_ldp_tlv_intparam_vccv_cvtype_bfd
            };
            int vc_len = length;
            offset += 4;
            while ( (vc_len > 1) && (rem > 1) ) {       /* enough to include id and length */
                int intparam_len = tvb_get_guint8(tvb, offset+1);
                if (intparam_len < 2){ /* At least Type and Len, protect against len = 0 */
                    proto_tree_add_text(tlv_tree, tvb, offset +1, 1, "Malformed interface parameter");
                    break;
                }

                if ( (vc_len -intparam_len) <0 && (rem -intparam_len) <0 ) { /* error condition */
                    proto_tree_add_text(tlv_tree, tvb, offset +2, MIN(vc_len,rem), "Malformed data");
                    break;
                }
                dissect_subtlv_interface_parameters(tvb, offset, tlv_tree, intparam_len, interface_params_header_fields);

                rem -= intparam_len;
                vc_len -= intparam_len;
                offset += intparam_len;
            }
            break;
        }
        case TLV_PW_GROUPING:
        {
            /* Ref: RFC 4447 */
            dissect_tlv_pw_grouping(tvb, offset +4, tlv_tree, length);
            break;
        }
        default:
            proto_tree_add_item(tlv_tree, hf_ldp_tlv_value, tvb, offset + 4, length, ENC_NA);
            break;
        }
    }

    return length + 4;  /* Length of the value field + header */
}


/* Dissect a Message and return the number of bytes consumed ... */

static int
dissect_msg(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree)
{
    guint16     type, typebak;
    guint8      extra=0;
    int length, rem, ao=0, co;
    proto_tree *msg_tree = NULL;

    rem=tvb_reported_length_remaining(tvb, offset);

    if( rem < 8 ) {/*chk for minimum header = type + length + msg_id*/
        col_append_str(pinfo->cinfo, COL_INFO, "Bad Message");
        if (tree) {
            proto_tree_add_text(tree, tvb, offset, rem,
                                "Error processing Message: length is %d, should be >= 8",
                                rem);
        }
        return rem;
    }
    type = tvb_get_ntohs(tvb, offset) & 0x7FFF;

    /*chk for vendor-private*/
    if(type>=LDP_VENDOR_PRIVATE_START && type<=LDP_VENDOR_PRIVATE_END){
        typebak=type;           /*keep type*/
        type=LDP_VENDOR_PRIVATE_START;
        extra=4;
        /*chk for experimental*/
    } else if(type>=LDP_EXPERIMENTAL_MESSAGE_START && type<=LDP_EXPERIMENTAL_MESSAGE_END){
        typebak=type;           /*keep type*/
        type=LDP_EXPERIMENTAL_MESSAGE_START;
        extra=4;
    } else {
        typebak=0;
        extra=0;
    }

    if( (length = tvb_get_ntohs(tvb, offset + 2)) < (4+extra) ) {/*not enough data for type*/
        col_append_str(pinfo->cinfo, COL_INFO, "Bad Message Length ");
        if (tree) {
            proto_tree_add_text(tree, tvb, offset, rem,
                                "Error processing Message Length: length is %d, should be >= %u",
                                length, 4+extra);
        }
        return rem;
    }
    rem -= 4;
    length = MIN(length, rem);  /* Don't go haywire if a problem ... */

    if( check_col(pinfo->cinfo, COL_INFO) ){
        switch (type) {
        case LDP_VENDOR_PRIVATE_START:
            col_append_fstr(pinfo->cinfo, COL_INFO, "Vendor-Private Message (0x%04X) ", typebak);
            break;
        case LDP_EXPERIMENTAL_MESSAGE_START:
            col_append_fstr(pinfo->cinfo, COL_INFO, "Experimental Message (0x%04X) ", typebak);
            break;
        default:
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(type, ldp_message_types, "Unknown Message (0x%04X)"));
        }
    }

    if (tree) {
        proto_tree *ti = NULL;

        switch (type) {
        case LDP_VENDOR_PRIVATE_START:
            ti = proto_tree_add_text(tree, tvb, offset, length + 4, "Vendor-Private Message");
            break;
        case LDP_EXPERIMENTAL_MESSAGE_START:
            ti = proto_tree_add_text(tree, tvb, offset, length + 4, "Experimental Message");
            break;
        default:
            ti = proto_tree_add_text(tree, tvb, offset, length + 4, "%s",
                                     val_to_str(type, ldp_message_types, "Unknown Message type (0x%04X)"));
        }

        msg_tree = proto_item_add_subtree(ti, ett_ldp_message);

        proto_tree_add_item(msg_tree, hf_ldp_msg_ubit, tvb, offset, 1, FALSE);

        switch (type) {
        case LDP_VENDOR_PRIVATE_START:
            proto_tree_add_uint_format(msg_tree, hf_ldp_msg_type, tvb, offset, 2,
                                       typebak, "Message Type: Vendor Private (0x%X)", typebak);
            break;
        case LDP_EXPERIMENTAL_MESSAGE_START:
            proto_tree_add_uint_format(msg_tree, hf_ldp_msg_type, tvb, offset, 2,
                                       typebak, "Message Type: Experimental (0x%X)", typebak);
            break;
        default:
            proto_tree_add_uint_format(msg_tree, hf_ldp_msg_type, tvb, offset, 2,
                                       type, "Message Type: %s (0x%X)", val_to_str(type, ldp_message_types,"Unknown Message Type"), type);
        }

        proto_tree_add_item(msg_tree, hf_ldp_msg_len, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(msg_tree, hf_ldp_msg_id, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        if(extra){
            int hf_tmp;

            switch(type){
            case LDP_VENDOR_PRIVATE_START:
                hf_tmp=hf_ldp_msg_vendor_id;
                break;
            case LDP_EXPERIMENTAL_MESSAGE_START:
                hf_tmp=hf_ldp_msg_experiment_id;
                break;
            default:
                hf_tmp = 0;
            }
            proto_tree_add_item(msg_tree, hf_tmp, tvb, offset+8, extra, FALSE);
        }
    }

    offset += (8+extra);
    length -= (4+extra);

    if (tree) {
        while ( (length-ao) > 0 ) {
            co = dissect_tlv(tvb, offset, msg_tree, length-ao);
            offset += co;
            ao += co;
        }
    }

    return length+8+extra;
}

/* Dissect a PDU */
static void
dissect_ldp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0, co;
    int rem, length;
    proto_tree *ti=NULL, *pdu_tree = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LDP");

    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        ti=proto_tree_add_item(tree, proto_ldp, tvb, 0, -1, FALSE);
        pdu_tree = proto_item_add_subtree(ti, ett_ldp);

        proto_tree_add_item(pdu_tree, hf_ldp_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    }

    length = tvb_get_ntohs(tvb, offset+2);
    if (tree) {
        proto_tree_add_uint(pdu_tree, hf_ldp_pdu_len, tvb, offset+2, 2, length);
    }

    length += 4;        /* add the version and type sizes */
    rem = tvb_reported_length_remaining(tvb, offset);
    if (length < rem)
        tvb_set_reported_length(tvb, length);

    if (tree) {
        proto_tree_add_item(pdu_tree, hf_ldp_lsr, tvb, offset+4, 4, FALSE);
        proto_tree_add_item(pdu_tree, hf_ldp_ls_id, tvb, offset+8, 2, ENC_BIG_ENDIAN);
    }
    offset += 10;

    while ( tvb_reported_length_remaining(tvb, offset) > 0 ) {
        co = dissect_msg(tvb, offset, pinfo, pdu_tree);
        offset += co;
    }
}

static int
dissect_ldp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /*
     * Make sure the first PDU has a version number of 1;
     * if not, reject this, so we don't get confused by
     * packets that happen to be going to or from the
     * LDP port but that aren't LDP packets.
     */
    if (tvb_length(tvb) < 2) {
        /*
         * Not enough information to tell.
         */
        return 0;
    }
    if (tvb_get_ntohs(tvb, 0) != 1) {
        /*
         * Not version 1.
         */
        return 0;
    }

    dissect_ldp_pdu(tvb, pinfo, tree);

    /*
     * XXX - return minimum of this and the length of the PDU?
     */
    return tvb_length(tvb);
}

static void
dissect_tlv_pw_status(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;
    guint32     data;

    if(rem != 4){
        proto_tree_add_text(tree, tvb, offset, rem,
                            "Error processing PW Status TLV: length is %d, should be 4",
                            rem);
        return;
    }

    data=tvb_get_ntohl(tvb, offset);
    ti = proto_tree_add_uint_format(tree, hf_ldp_tlv_pw_status_data, tvb, offset , rem,
                                    data, "PW Status: 0x%08x ", data);

    val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);
    /* Display the bits 0-4 if they are set or not set */
    proto_tree_add_boolean(val_tree, hf_ldp_tlv_pw_not_forwarding, tvb, offset , 4, data);
    proto_tree_add_boolean(val_tree, hf_ldp_tlv_pw_lac_ingress_recv_fault, tvb, offset , 4, data);
    proto_tree_add_boolean(val_tree, hf_ldp_tlv_pw_lac_egress_recv_fault, tvb, offset , 4, data);
    proto_tree_add_boolean(val_tree, hf_ldp_tlv_pw_psn_pw_ingress_recv_fault, tvb, offset , 4, data);
    proto_tree_add_boolean(val_tree, hf_ldp_tlv_pw_psn_pw_egress_recv_fault, tvb, offset , 4, data);
}

static void
dissect_tlv_pw_grouping(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem _U_)
{
    proto_tree_add_item(tree,hf_ldp_tlv_pw_grouping_value,tvb,offset,4,ENC_BIG_ENDIAN);
}

static void
dissect_subtlv_interface_parameters(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem, int *interface_parameters_hf[])
{
#if 0
    static int interface_parameters_hf[] = {
         0 - hf_ldp_tlv_fec_vc_intparam_length ,
         1 - hf_ldp_tlv_fec_vc_intparam_mtu ,
         2 - hf_ldp_tlv_fec_vc_intparam_tdmbps ,
         3 - hf_ldp_tlv_fec_vc_intparam_id ,
         4 - hf_ldp_tlv_fec_vc_intparam_maxcatmcells ,
         5 - hf_ldp_tlv_fec_vc_intparam_desc ,
         6 - hf_ldp_tlv_fec_vc_intparam_cepbytes ,
         7 - hf_ldp_tlv_fec_vc_intparam_cepopt_ais ,
         8 - hf_ldp_tlv_fec_vc_intparam_cepopt_une ,
         9 - hf_ldp_tlv_fec_vc_intparam_cepopt_rtp ,
        10 - hf_ldp_tlv_fec_vc_intparam_cepopt_ebm ,
        11 - hf_ldp_tlv_fec_vc_intparam_cepopt_mah ,
        12 - hf_ldp_tlv_fec_vc_intparam_cepopt_res ,
        13 - hf_ldp_tlv_fec_vc_intparam_cepopt_ceptype ,
        14 - hf_ldp_tlv_fec_vc_intparam_cepopt_t3 ,
        15 - hf_ldp_tlv_fec_vc_intparam_cepopt_e3 ,
        16 - hf_ldp_tlv_fec_vc_intparam_vlanid ,
        17 - hf_ldp_tlv_fec_vc_intparam_dlcilen ,
        18 - hf_ldp_tlv_fec_vc_intparam_fcslen ,
        19 - hf_ldp_tlv_fec_vc_intparam_tdmopt_r ,
        20 - hf_ldp_tlv_fec_vc_intparam_tdmopt_d ,
        21 - hf_ldp_tlv_fec_vc_intparam_tdmopt_f ,
        22 - hf_ldp_tlv_fec_vc_intparam_tdmopt_res1 ,
        23 - hf_ldp_tlv_fec_vc_intparam_tdmopt_pt ,
        24 - hf_ldp_tlv_fec_vc_intparam_tdmopt_res2 ,
        25 - hf_ldp_tlv_fec_vc_intparam_tdmopt_freq ,
        26 - hf_ldp_tlv_fec_vc_intparam_tdmopt_ssrc ,
        27 - hf_ldp_tlv_fec_vc_intparam_vccv_cctype_cw ,
        28 - hf_ldp_tlv_fec_vc_intparam_vccv_cctype_mplsra ,
        29 - hf_ldp_tlv_fec_vc_intparam_vccv_cctype_ttl1 ,
        30 - hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_icmpping ,
        31 - hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_lspping ,
        32 - hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd
    };
#endif
    proto_tree *ti = proto_tree_add_text(tree, tvb, offset, rem, "Interface Parameter");
    proto_tree *cepopt_tree=NULL, *vccvtype_tree=NULL;
    proto_tree *vcintparam_tree = proto_item_add_subtree(ti, ett_ldp_fec_vc_interfaceparam);

    guint8  intparam_len = rem;
    proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[3],tvb,offset,1,FALSE);
    proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[0],tvb, offset+1, 1, FALSE);

    switch (tvb_get_guint8(tvb, offset)) {
    case FEC_VC_INTERFACEPARAM_MTU:
        proto_item_append_text(ti,": MTU %u", tvb_get_ntohs(tvb,offset+2));
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[1],tvb, offset+2, 2, FALSE);
        break;
    case FEC_VC_INTERFACEPARAM_TDMBPS:
        /* draft-ietf-pwe3-control-protocol-06.txt */
        proto_item_append_text(ti,": BPS %u", tvb_get_ntohl(tvb,offset+2));
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[2],tvb, offset+2, 4, FALSE);
        break;
    case FEC_VC_INTERFACEPARAM_MAXCATMCELLS:
        proto_item_append_text(ti,": Max ATM Concat Cells %u", tvb_get_ntohs(tvb,offset+2));
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[4],tvb, offset+2, 2, FALSE);
        break;
    case FEC_VC_INTERFACEPARAM_DESCRIPTION:
        proto_item_append_text(ti,": Description");
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[5],tvb, offset+2, (intparam_len -2), FALSE);
        break;
    case FEC_VC_INTERFACEPARAM_CEPBYTES:
        proto_item_append_text(ti,": CEP/TDM Payload Bytes %u", tvb_get_ntohs(tvb,offset+2));
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[6],tvb, offset+2, 2, FALSE);
        break;
    case FEC_VC_INTERFACEPARAM_CEPOPTIONS:
        /* draft-ietf-pwe3-sonet-05.txt */
        proto_item_append_text(ti,": CEP Options");
        ti = proto_tree_add_text(vcintparam_tree, tvb, offset + 2, 2, "CEP Options");
        cepopt_tree = proto_item_add_subtree(ti, ett_ldp_fec_vc_interfaceparam_cepopt);
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[7], tvb, offset + 2, 2, FALSE);
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[8], tvb, offset + 2, 2, FALSE);
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[9], tvb, offset + 2, 2, FALSE);
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[10], tvb, offset + 2, 2, FALSE);
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[11], tvb, offset + 2, 2, FALSE);
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[12], tvb, offset + 2, 2, FALSE);
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[13], tvb, offset + 2, 2, FALSE);
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[14], tvb, offset + 2, 2, FALSE);
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[15], tvb, offset + 2, 2, FALSE);
        break;
    case FEC_VC_INTERFACEPARAM_VLANID:
        proto_item_append_text(ti,": VLAN Id %u", tvb_get_ntohs(tvb,offset+2));
        proto_tree_add_item(vcintparam_tree, *interface_parameters_hf[16], tvb, offset+2, 2, FALSE);
        break;
    case FEC_VC_INTERFACEPARAM_FRDLCILEN:
        proto_item_append_text(ti,": DLCI Length %u", tvb_get_ntohs(tvb,offset+2));
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[17], tvb, offset+2, 2, FALSE);
        break;
    case FEC_VC_INTERFACEPARAM_FRAGIND:
        /* draft-ietf-pwe3-fragmentation-05.txt */
        proto_item_append_text(ti,": Fragmentation");
        break;
    case FEC_VC_INTERFACEPARAM_FCSRETENT:
        /* draft-ietf-pwe3-fcs-retention-02.txt */
        proto_item_append_text(ti,": FCS retention, FCS Length %u Bytes", tvb_get_ntohs(tvb,offset+2));
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[18], tvb, offset+2, 2, FALSE);
        break;
    case FEC_VC_INTERFACEPARAM_TDMOPTION:
        /* draft-vainshtein-pwe3-tdm-control-protocol-extensions */
        proto_item_append_text(ti,": TDM Options");
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[19], tvb, offset+2, 2, FALSE);
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[20], tvb, offset+2, 2, FALSE);
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[21], tvb, offset+2, 2, FALSE);
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[22], tvb, offset+2, 2, FALSE);
        if (intparam_len >= 8){
            proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[23], tvb, offset+4, 1, FALSE);
            proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[24], tvb, offset+5, 1, FALSE);
            proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[25], tvb, offset+6, 2, FALSE);
        }
        if (intparam_len >= 12){
            proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[26], tvb, offset+8, 4, FALSE);
        }
        break;
    case FEC_VC_INTERFACEPARAM_VCCV:
        /* draft-ietf-pwe3-vccv-03.txt */
        proto_item_append_text(ti,": VCCV");
        ti = proto_tree_add_text(vcintparam_tree, tvb, offset + 2, 1, "CC Type");
        vccvtype_tree = proto_item_add_subtree(ti, ett_ldp_fec_vc_interfaceparam_vccvtype);
        proto_tree_add_item(vccvtype_tree, *interface_parameters_hf[27], tvb, offset+2, 1, FALSE);
        proto_tree_add_item(vccvtype_tree, *interface_parameters_hf[28], tvb, offset+2, 1, FALSE);
        proto_tree_add_item(vccvtype_tree, *interface_parameters_hf[29], tvb, offset+2, 1, FALSE);
        ti = proto_tree_add_text(vcintparam_tree, tvb, offset + 3, 1, "CV Type");
        vccvtype_tree = proto_item_add_subtree(ti, ett_ldp_fec_vc_interfaceparam_vccvtype);
        proto_tree_add_item(vccvtype_tree, *interface_parameters_hf[30], tvb, offset+3, 1, FALSE);
        proto_tree_add_item(vccvtype_tree, *interface_parameters_hf[31], tvb, offset+3, 1, FALSE);
        proto_tree_add_item(vccvtype_tree, *interface_parameters_hf[32], tvb, offset+3, 1, FALSE);
        break;
    default: /* unknown */
        proto_item_append_text(ti," unknown");
        proto_tree_add_text(vcintparam_tree,tvb, offset+2, (intparam_len -2), "Unknown data");

        break;
    }
}

static void
dissect_genpwid_fec_aai_type2_parameter(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
    proto_tree *ti             = proto_tree_add_text(tree, tvb, offset, rem, "AAI");
    proto_tree *aai_param_tree = proto_item_add_subtree(ti, ett_ldp_gen_aai_type2);
    /* check if the remaining length is 12 bytes or not... */
    if ( rem != 12)
    {
        proto_tree_add_text(tree, tvb, offset, rem ,"Error processing AAI Parameter: length is %d, should be 12 bytes for Type 2.",
                            rem);

        return;

    }

    proto_tree_add_item(aai_param_tree,hf_ldp_tlv_fec_gen_aai_globalid,tvb,offset,4,ENC_BIG_ENDIAN);
    proto_tree_add_item(aai_param_tree,hf_ldp_tlv_fec_gen_aai_prefix,tvb, offset+4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(aai_param_tree,hf_ldp_tlv_fec_gen_aai_ac_id,tvb, offset+4, 4, ENC_BIG_ENDIAN);
}

static int
dissect_ldp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    volatile gboolean   first = TRUE;
    volatile int        offset = 0;
    int                 length_remaining;
    guint16             plen;
    int                 length;
    tvbuff_t *volatile  next_tvb;
    void               *pd_save;

    while (tvb_reported_length_remaining(tvb, offset) != 0) {
        length_remaining = tvb_length_remaining(tvb, offset);

        /*
         * Make sure the first PDU has a version number of 1;
         * if not, reject this, so we don't get confused by
         * packets that happen to be going to or from the
         * LDP port but that aren't LDP packets.
         *
         * XXX - this means we can't handle an LDP PDU of which
         * only one byte appears in a TCP segment.  If that's
         * a problem, we'll either have to completely punt on
         * rejecting non-LDP packets, or will have to assume
         * that if we have only one byte, it's an LDP packet.
         */
        if (first) {
            if (length_remaining < 2) {
                /*
                 * Not enough information to tell.
                 */
                return 0;
            }
            if (tvb_get_ntohs(tvb, offset) != 1) {
                /*
                 * Not version 1.
                 */
                return 0;
            }
            first = FALSE;
        }

        /*
         * Can we do reassembly?
         */
        if (ldp_desegment && pinfo->can_desegment) {
            /*
             * Yes - is the LDP header split across segment
             * boundaries?
             */
            if (length_remaining < 4) {
                /*
                 * Yes.  Tell the TCP dissector where the data for this message
                 * starts in the data it handed us and that we need "some more
                 * data."  Don't tell it exactly how many bytes we need because
                 * if/when we ask for even more (after the header) that will
                 * break reassembly.
                 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                return -((gint32) pinfo->desegment_len);
            }
        }

        /*
         * Get the length of the rest of the LDP packet.
         * XXX - check for a version of 1 first?
         */
        plen = tvb_get_ntohs(tvb, offset + 2);

        /*
         * Can we do reassembly?
         */
        if (ldp_desegment && pinfo->can_desegment) {
            /*
             * Yes - is the LDP packet split across segment
             * boundaries?
             */
            if (length_remaining < plen + 4) {
                /*
                 * Yes.  Tell the TCP dissector where the
                 * data for this message starts in the data
                 * it handed us, and how many more bytes we
                 * need, and return.
                 */
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = (plen + 4) - length_remaining;
                return -((gint32) pinfo->desegment_len);
            }
        }

        /*
         * Construct a tvbuff containing the amount of the payload
         * we have available.  Make its reported length the
         * amount of data in the DNS-over-TCP packet.
         *
         * XXX - if reassembly isn't enabled. the subdissector
         * will throw a BoundsError exception, rather than a
         * ReportedBoundsError exception.  We really want
         * a tvbuff where the length is "length", the reported
         * length is "plen + 4", and the "if the snapshot length
         * were infinite" length is the minimum of the
         * reported length of the tvbuff handed to us and "plen+4",
         * with a new type of exception thrown if the offset is
         * within the reported length but beyond that third length,
         * with that exception getting the "Unreassembled Packet"
         * error.
         */
        length = length_remaining;
        if (length > plen + 4)
            length = plen + 4;
        next_tvb = tvb_new_subset(tvb, offset, length, plen + 4);

        /*
         * Dissect the LDP packet.
         *
         * Catch the ReportedBoundsError exception; if this
         * particular message happens to get a ReportedBoundsError
         * exception, that doesn't mean that we should stop
         * dissecting LDP messages within this frame or chunk of
         * reassembled data.
         *
         * If it gets a BoundsError, we can stop, as there's nothing
         * more to see, so we just re-throw it.
         */
        pd_save = pinfo->private_data;
        TRY {
            dissect_ldp_pdu(next_tvb, pinfo, tree);
        }
        CATCH(BoundsError) {
            RETHROW;
        }
        CATCH(ReportedBoundsError) {
            /*  Restore the private_data structure in case one of the
             *  called dissectors modified it (and, due to the exception,
             *  was unable to restore it).
             */
            pinfo->private_data = pd_save;

            show_reported_bounds_error(tvb, pinfo, tree);
        }
        ENDTRY;

        /*
         * Skip the LDP header and the payload.
         */
        offset += plen + 4;
    }
    return tvb_length(tvb);
}

/* Register all the bits needed with the filtering engine */

void
proto_register_ldp(void)
{
    static hf_register_info hf[] = {
        { &hf_ldp_req,
          /* Change the following to the type you need */
          { "Request", "ldp.req", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_rsp,
          { "Response", "ldp.rsp", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_version,
          { "Version", "ldp.hdr.version", FT_UINT16, BASE_DEC,
            NULL, 0x0, "LDP Version Number", HFILL }},

        { &hf_ldp_pdu_len,
          { "PDU Length", "ldp.hdr.pdu_len", FT_UINT16, BASE_DEC,
            NULL, 0x0, "LDP PDU Length", HFILL }},

        { &hf_ldp_lsr,
          { "LSR ID", "ldp.hdr.ldpid.lsr", FT_IPv4, BASE_NONE,
            NULL, 0x0, "LDP Label Space Router ID", HFILL }},

        { &hf_ldp_ls_id,
          { "Label Space ID", "ldp.hdr.ldpid.lsid", FT_UINT16, BASE_DEC,
            NULL, 0, "LDP Label Space ID", HFILL }},

        { &hf_ldp_msg_ubit,
          { "U bit", "ldp.msg.ubit", FT_BOOLEAN, 8,
            TFS(&ldp_message_ubit), 0x80, "Unknown Message Bit", HFILL }},

        { &hf_ldp_msg_type,
          { "Message Type", "ldp.msg.type", FT_UINT16, BASE_HEX,
            VALS(ldp_message_types), 0x7FFF, "LDP message type", HFILL }},

        { &hf_ldp_msg_len,
          { "Message Length", "ldp.msg.len", FT_UINT16, BASE_DEC,
            NULL, 0x0, "LDP Message Length (excluding message type and len)", HFILL }},

        { &hf_ldp_msg_id,
          { "Message ID", "ldp.msg.id", FT_UINT32, BASE_HEX,
            NULL, 0x0, "LDP Message ID", HFILL }},

        { &hf_ldp_msg_vendor_id,
          { "Vendor ID", "ldp.msg.vendor.id", FT_UINT32, BASE_HEX,
            NULL, 0x0, "LDP Vendor-private Message ID", HFILL }},

        { &hf_ldp_msg_experiment_id,
          { "Experiment ID", "ldp.msg.experiment.id", FT_UINT32, BASE_HEX,
            NULL, 0x0, "LDP Experimental Message ID", HFILL }},

        { &hf_ldp_tlv_unknown,
          { "TLV Unknown bits", "ldp.msg.tlv.unknown", FT_UINT8, BASE_HEX,
            VALS(tlv_unknown_vals), 0xC0, "TLV Unknown bits Field", HFILL }},

        { &hf_ldp_tlv_type,
          { "TLV Type", "ldp.msg.tlv.type", FT_UINT16, BASE_HEX,
            VALS(tlv_type_names), 0x3FFF, "TLV Type Field", HFILL }},

        { &hf_ldp_tlv_len,
          { "TLV Length", "ldp.msg.tlv.len", FT_UINT16, BASE_DEC,
            NULL, 0x0, "TLV Length Field", HFILL }},

        { &hf_ldp_tlv_value,
          { "TLV Value", "ldp.msg.tlv.value", FT_BYTES, BASE_NONE,
            NULL, 0x0, "TLV Value Bytes", HFILL }},

        { &hf_ldp_tlv_val_hold,
          { "Hold Time", "ldp.msg.tlv.hello.hold", FT_UINT16, BASE_DEC,
            NULL, 0x0, "Hello Common Parameters Hold Time", HFILL }},

        { &hf_ldp_tlv_val_target,
          { "Targeted Hello", "ldp.msg.tlv.hello.targeted", FT_BOOLEAN, 16,
            TFS(&hello_targeted_vals), 0x8000, "Hello Common Parameters Targeted Bit", HFILL }},

        { &hf_ldp_tlv_val_request,
          { "Hello Requested", "ldp.msg.tlv.hello.requested", FT_BOOLEAN, 16,
            TFS(&hello_requested_vals), 0x4000, "Hello Common Parameters Hello Requested Bit", HFILL }},

        { &hf_ldp_tlv_val_res,
          { "Reserved", "ldp.msg.tlv.hello.res", FT_UINT16, BASE_HEX,
            NULL, 0x3FFF, "Hello Common Parameters Reserved Field", HFILL }},

        { &hf_ldp_tlv_ipv4_taddr,
          { "IPv4 Transport Address", "ldp.msg.tlv.ipv4.taddr", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_config_seqno,
          { "Configuration Sequence Number", "ldp.msg.tlv.hello.cnf_seqno", FT_UINT32, BASE_DEC,
            NULL, 0x0, "Hello Configuration Sequence Number", HFILL }},

        { &hf_ldp_tlv_ipv6_taddr,
          { "IPv6 Transport Address", "ldp.msg.tlv.ipv6.taddr", FT_IPv6, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_fec_wc,
          { "FEC Element Type", "ldp.msg.tlv.fec.type", FT_UINT8, BASE_DEC,
            VALS(fec_types), 0x0, "Forwarding Equivalence Class Element Types", HFILL }},

        { &hf_ldp_tlv_fec_af,
          { "FEC Element Address Type", "ldp.msg.tlv.fec.af", FT_UINT16, BASE_DEC,
            VALS(afn_vals), 0x0, "Forwarding Equivalence Class Element Address Family", HFILL }},

        { &hf_ldp_tlv_fec_len,
          { "FEC Element Length", "ldp.msg.tlv.fec.len", FT_UINT8, BASE_DEC,
            NULL, 0x0, "Forwarding Equivalence Class Element Length", HFILL }},

        { &hf_ldp_tlv_fec_pfval,
          { "FEC Element Prefix Value", "ldp.msg.tlv.fec.pfval", FT_STRING, BASE_NONE,
            NULL, 0x0, "Forwarding Equivalence Class Element Prefix", HFILL }},

        { &hf_ldp_tlv_fec_hoval,
          { "FEC Element Host Address Value", "ldp.msg.tlv.fec.hoval", FT_STRING, BASE_NONE,
            NULL, 0x0, "Forwarding Equivalence Class Element Address", HFILL }},

        { &hf_ldp_tlv_addrl_addr_family,
          { "Address Family", "ldp.msg.tlv.addrl.addr_family", FT_UINT16, BASE_DEC,
            VALS(afn_vals), 0x0, "Address Family List", HFILL }},

        { &hf_ldp_tlv_addrl_addr,
          { "Address", "ldp.msg.tlv.addrl.addr", FT_STRING, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_hc_value,
          { "Hop Count Value", "ldp.msg.tlv.hc.value", FT_UINT8, BASE_DEC,
            NULL, 0x0, "Hop Count", HFILL }},

        { &hf_ldp_tlv_pv_lsrid,
          { "LSR Id", "ldp.msg.tlv.pv.lsrid", FT_IPv4, BASE_NONE,
            NULL, 0x0, "Path Vector LSR Id", HFILL }},

        { &hf_ldp_tlv_sess_ver,
          { "Session Protocol Version", "ldp.msg.tlv.sess.ver", FT_UINT16, BASE_DEC,
            NULL, 0x0, "Common Session Parameters Protocol Version", HFILL }},

        { &hf_ldp_tlv_sess_ka,
          { "Session KeepAlive Time", "ldp.msg.tlv.sess.ka", FT_UINT16, BASE_DEC,
            NULL, 0x0, "Common Session Parameters KeepAlive Time", HFILL }},

        { &hf_ldp_tlv_sess_advbit,
          { "Session Label Advertisement Discipline", "ldp.msg.tlv.sess.advbit", FT_BOOLEAN, 8,
            TFS(&tlv_sess_advbit_vals), 0x80, "Common Session Parameters Label Advertisement Discipline", HFILL }},

        { &hf_ldp_tlv_sess_ldetbit,
          { "Session Loop Detection", "ldp.msg.tlv.sess.ldetbit", FT_BOOLEAN, 8,
            TFS(&tlv_sess_ldetbit_vals), 0x40, "Common Session Parameters Loop Detection", HFILL }},

        { &hf_ldp_tlv_sess_pvlim,
          { "Session Path Vector Limit", "ldp.msg.tlv.sess.pvlim", FT_UINT8, BASE_DEC,
            NULL, 0x0, "Common Session Parameters Path Vector Limit", HFILL }},

        { &hf_ldp_tlv_sess_mxpdu,
          { "Session Max PDU Length", "ldp.msg.tlv.sess.mxpdu", FT_UINT16, BASE_DEC,
            NULL, 0x0, "Common Session Parameters Max PDU Length", HFILL }},

        { &hf_ldp_tlv_sess_rxlsr,
          { "Session Receiver LSR Identifier", "ldp.msg.tlv.sess.rxlsr", FT_IPv4, BASE_NONE,
            NULL, 0x0, "Common Session Parameters LSR Identifier", HFILL }},

        { &hf_ldp_tlv_sess_rxls,
          { "Session Receiver Label Space Identifier", "ldp.msg.tlv.sess.rxls", FT_UINT16, BASE_DEC,
            NULL, 0x0, "Common Session Parameters Receiver Label Space Identifier", HFILL }},

        { &hf_ldp_tlv_sess_atm_merge,
          { "Session ATM Merge Parameter", "ldp.msg.tlv.sess.atm.merge", FT_UINT8, BASE_DEC,
            VALS(tlv_atm_merge_vals), 0xC0, "Merge ATM Session Parameters", HFILL }},

        { &hf_ldp_tlv_sess_atm_lr,
          { "Number of ATM Label Ranges", "ldp.msg.tlv.sess.atm.lr", FT_UINT8, BASE_DEC,
            NULL, 0x3C, "Number of Label Ranges", HFILL }},

        { &hf_ldp_tlv_sess_atm_dir,
          { "Directionality", "ldp.msg.tlv.sess.atm.dir", FT_BOOLEAN, 8,
            TFS(&tlv_atm_dirbit), 0x02, "Label Directionality", HFILL }},

        { &hf_ldp_tlv_sess_atm_minvpi,
          { "Minimum VPI", "ldp.msg.tlv.sess.atm.minvpi", FT_UINT16, BASE_DEC,
            NULL, 0x0FFF, NULL, HFILL }},

        { &hf_ldp_tlv_sess_atm_minvci,
          { "Minimum VCI", "ldp.msg.tlv.sess.atm.minvci", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_sess_atm_maxvpi,
          { "Maximum VPI", "ldp.msg.tlv.sess.atm.maxvpi", FT_UINT16, BASE_DEC,
            NULL, 0x0FFF, NULL, HFILL }},

        { &hf_ldp_tlv_sess_atm_maxvci,
          { "Maximum VCI", "ldp.msg.tlv.sess.atm.maxvci", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_sess_fr_merge,
          { "Session Frame Relay Merge Parameter", "ldp.msg.tlv.sess.fr.merge", FT_UINT8, BASE_DEC,
            VALS(tlv_fr_merge_vals), 0xC0, "Merge Frame Relay Session Parameters", HFILL }},

        { &hf_ldp_tlv_sess_fr_lr,
          { "Number of Frame Relay Label Ranges", "ldp.msg.tlv.sess.fr.lr", FT_UINT8, BASE_DEC,
            NULL, 0x3C, "Number of Label Ranges", HFILL }},

        { &hf_ldp_tlv_sess_fr_dir,
          { "Directionality", "ldp.msg.tlv.sess.fr.dir", FT_BOOLEAN, 8,
            TFS(&tlv_atm_dirbit), 0x02, "Label Directionality", HFILL }},

        { &hf_ldp_tlv_sess_fr_len,
          { "Number of DLCI bits", "ldp.msg.tlv.sess.fr.len", FT_UINT16, BASE_DEC,
            VALS(tlv_fr_len_vals), 0x0180, "DLCI Number of bits", HFILL }},

        { &hf_ldp_tlv_sess_fr_mindlci,
          { "Minimum DLCI", "ldp.msg.tlv.sess.fr.mindlci", FT_UINT24, BASE_DEC,
            NULL, 0x7FFFFF, NULL, HFILL }},

        { &hf_ldp_tlv_sess_fr_maxdlci,
          { "Maximum DLCI", "ldp.msg.tlv.sess.fr.maxdlci", FT_UINT24, BASE_DEC,
            NULL, 0x7FFFFF, NULL, HFILL }},

        { &hf_ldp_tlv_ft_sess_flags,
          { "Flags", "ldp.msg.tlv.ft_sess.flags", FT_UINT16, BASE_HEX,
            NULL, 0x0, "FT Session Flags", HFILL }},

        { &hf_ldp_tlv_ft_sess_flag_r,
          { "R bit", "ldp.msg.tlv.ft_sess.flag_r", FT_BOOLEAN, 16,
            TFS(&tlv_ft_r), 0x8000, "FT Reconnect Flag", HFILL }},

        { &hf_ldp_tlv_ft_sess_flag_res,
          { "Reserved", "ldp.msg.tlv.ft_sess.flag_res", FT_UINT16, BASE_HEX,
            NULL, 0x7FF0, "Reserved bits", HFILL }},

        { &hf_ldp_tlv_ft_sess_flag_s,
          { "S bit", "ldp.msg.tlv.ft_sess.flag_s", FT_BOOLEAN, 16,
            TFS(&tlv_ft_s), 0x8, "Save State Flag", HFILL }},

        { &hf_ldp_tlv_ft_sess_flag_a,
          { "A bit", "ldp.msg.tlv.ft_sess.flag_a", FT_BOOLEAN, 16,
            TFS(&tlv_ft_a), 0x4, "All-Label protection Required", HFILL }},

        { &hf_ldp_tlv_ft_sess_flag_c,
          { "C bit", "ldp.msg.tlv.ft_sess.flag_c", FT_BOOLEAN, 16,
            TFS(&tlv_ft_c), 0x2, "Check-Pointint Flag", HFILL }},

        { &hf_ldp_tlv_ft_sess_flag_l,
          { "L bit", "ldp.msg.tlv.ft_sess.flag_l", FT_BOOLEAN, 16,
            TFS(&tlv_ft_l), 0x1, "Learn From network Flag", HFILL }},

        { &hf_ldp_tlv_ft_sess_res,
          { "Reserved", "ldp.msg.tlv.ft_sess.res", FT_UINT16, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_ft_sess_reconn_to,
          { "Reconnect Timeout", "ldp.msg.tlv.ft_sess.reconn_to", FT_UINT32, BASE_DEC,
            NULL, 0x0, "FT Reconnect Timeout", HFILL }},

        { &hf_ldp_tlv_ft_sess_recovery_time,
          { "Recovery Time", "ldp.msg.tlv.ft_sess.recovery_time", FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_ft_ack_sequence_num,
          { "FT ACK Sequence Number", "ldp.msg.tlv.ft_ack.sequence_num", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_lbl_req_msg_id,
          { "Label Request Message ID", "ldp.tlv.lbl_req_msg_id", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Label Request Message to be aborted", HFILL }},

        { &hf_ldp_tlv_vendor_id,
          { "Vendor ID", "ldp.msg.tlv.vendor_id", FT_UINT32, BASE_HEX,
            NULL, 0, "IEEE 802 Assigned Vendor ID", HFILL }},

        { &hf_ldp_tlv_experiment_id,
          { "Experiment ID", "ldp.msg.tlv.experiment_id", FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }},

        { &hf_ldp_tlv_generic_label,
          { "Generic Label", "ldp.msg.tlv.generic.label", FT_UINT32, BASE_HEX,
            NULL, 0x000FFFFF, NULL, HFILL }},

        { &hf_ldp_tlv_atm_label_vbits,
          { "V-bits", "ldp.msg.tlv.atm.label.vbits", FT_UINT8, BASE_HEX,
            VALS(tlv_atm_vbits_vals), 0x30, "ATM Label V Bits", HFILL }},

        { &hf_ldp_tlv_atm_label_vpi,
          { "VPI", "ldp.msg.tlv.atm.label.vpi", FT_UINT16, BASE_DEC,
            NULL, 0x0FFF, "ATM Label VPI", HFILL }},

        { &hf_ldp_tlv_atm_label_vci,
          { "VCI", "ldp.msg.tlv.atm.label.vci", FT_UINT16, BASE_DEC,
            NULL, 0, "ATM Label VCI", HFILL }},

        { &hf_ldp_tlv_fr_label_len,
          { "Number of DLCI bits", "ldp.msg.tlv.fr.label.len", FT_UINT16, BASE_DEC,
            VALS(tlv_fr_len_vals), 0x0180, "DLCI Number of bits", HFILL }},

        { &hf_ldp_tlv_fr_label_dlci,
          { "DLCI", "ldp.msg.tlv.fr.label.dlci", FT_UINT24, BASE_DEC,
            NULL, 0x7FFFFF, "FRAME RELAY Label DLCI", HFILL }},

        { &hf_ldp_tlv_ft_protect_sequence_num,
          { "FT Sequence Number", "ldp.msg.tlv.ft_protect.sequence_num", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_status_ebit,
          { "E Bit", "ldp.msg.tlv.status.ebit", FT_BOOLEAN, 8,
            TFS(&tlv_status_ebit), 0x80, "Fatal Error Bit", HFILL }},

        { &hf_ldp_tlv_status_fbit,
          { "F Bit", "ldp.msg.tlv.status.fbit", FT_BOOLEAN, 8,
            TFS(&tlv_status_fbit), 0x40, "Forward Bit", HFILL }},

        { &hf_ldp_tlv_status_data,
          { "Status Data", "ldp.msg.tlv.status.data", FT_UINT32, BASE_HEX,
            VALS(tlv_status_data), 0x3FFFFFFF, NULL, HFILL }},

        { &hf_ldp_tlv_status_msg_id,
          { "Message ID", "ldp.msg.tlv.status.msg.id", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Identifies peer message to which Status TLV refers", HFILL }},

        { &hf_ldp_tlv_status_msg_type,
          { "Message Type", "ldp.msg.tlv.status.msg.type", FT_UINT16, BASE_HEX,
            VALS(ldp_message_types), 0x0, "Type of peer message to which Status TLV refers", HFILL }},

        { &hf_ldp_tlv_extstatus_data,
          { "Extended Status Data", "ldp.msg.tlv.extstatus.data", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_returned_version,
          { "Returned PDU Version", "ldp.msg.tlv.returned.version", FT_UINT16, BASE_DEC,
            NULL, 0x0, "LDP Version Number", HFILL }},

        { &hf_ldp_tlv_returned_pdu_len,
          { "Returned PDU Length", "ldp.msg.tlv.returned.pdu_len", FT_UINT16, BASE_DEC,
            NULL, 0x0, "LDP PDU Length", HFILL }},

        { &hf_ldp_tlv_returned_lsr,
          { "Returned PDU LSR ID", "ldp.msg.tlv.returned.ldpid.lsr", FT_IPv4, BASE_NONE,
            NULL, 0x0, "LDP Label Space Router ID", HFILL }},

        { &hf_ldp_tlv_returned_ls_id,
          { "Returned PDU Label Space ID", "ldp.msg.tlv.returned.ldpid.lsid", FT_UINT16, BASE_HEX,
            NULL, 0x0, "LDP Label Space ID", HFILL }},

        { &hf_ldp_tlv_returned_msg_ubit,
          { "Returned Message Unknown bit", "ldp.msg.tlv.returned.msg.ubit", FT_BOOLEAN, 8,
            TFS(&ldp_message_ubit), 0x80, "Message Unknown bit", HFILL }},

        { &hf_ldp_tlv_returned_msg_type,
          { "Returned Message Type", "ldp.msg.tlv.returned.msg.type", FT_UINT16, BASE_HEX,
            VALS(ldp_message_types), 0x7FFF, "LDP message type", HFILL }},

        { &hf_ldp_tlv_returned_msg_len,
          { "Returned Message Length", "ldp.msg.tlv.returned.msg.len", FT_UINT16, BASE_DEC,
            NULL, 0x0, "LDP Message Length (excluding message type and len)", HFILL }},

        { &hf_ldp_tlv_returned_msg_id,
          { "Returned Message ID", "ldp.msg.tlv.returned.msg.id", FT_UINT32, BASE_HEX,
            NULL, 0x0, "LDP Message ID", HFILL }},

        { &hf_ldp_tlv_mac,
          { "MAC address", "ldp.msg.tlv.mac", FT_ETHER, BASE_NONE,
            NULL, 0x0, NULL, HFILL}},

        { &hf_ldp_tlv_fec_vc_controlword,
          { "C-bit", "ldp.msg.tlv.fec.vc.controlword", FT_BOOLEAN, 8,
            TFS(&fec_vc_cbit), 0x80, "Control Word Present", HFILL }},

        { &hf_ldp_tlv_fec_vc_vctype,
          { "VC Type", "ldp.msg.tlv.fec.vc.vctype", FT_UINT16, BASE_HEX,
            VALS(fec_vc_types_vals), 0x7FFF, "Virtual Circuit Type", HFILL }},

        { &hf_ldp_tlv_fec_vc_infolength,
          { "VC Info Length", "ldp.msg.tlv.fec.vc.infolength", FT_UINT8, BASE_DEC,
            NULL, 0x0, "VC FEC Info Length", HFILL }},

        { &hf_ldp_tlv_fec_vc_groupid,
          { "Group ID", "ldp.msg.tlv.fec.vc.groupid", FT_UINT32, BASE_DEC,
            NULL, 0x0, "VC FEC Group ID", HFILL }},

        { &hf_ldp_tlv_fec_vc_vcid,
          { "VC ID", "ldp.msg.tlv.fec.vc.vcid", FT_UINT32, BASE_DEC,
            NULL, 0x0, "VC FEC VCID", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_length,
          { "Length", "ldp.msg.tlv.fec.vc.intparam.length", FT_UINT8, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Paramater Length", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_mtu,
          { "MTU", "ldp.msg.tlv.fec.vc.intparam.mtu", FT_UINT16, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Paramater MTU", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_tdmbps,
          { "BPS", "ldp.msg.tlv.fec.vc.intparam.tdmbps", FT_UINT32, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Parameter CEP/TDM bit-rate", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_id,
          { "ID", "ldp.msg.tlv.fec.vc.intparam.id", FT_UINT8, BASE_HEX,
            VALS(fec_vc_interfaceparm), 0x0, "VC FEC Interface Paramater ID", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_maxcatmcells,
          { "Number of Cells", "ldp.msg.tlv.fec.vc.intparam.maxatm", FT_UINT16, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Param Max ATM Concat Cells", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_desc,
          { "Description", "ldp.msg.tlv.fec.vc.intparam.desc", FT_STRING, BASE_NONE,
            NULL, 0, "VC FEC Interface Description", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_cepbytes,
          { "Payload Bytes", "ldp.msg.tlv.fec.vc.intparam.cepbytes", FT_UINT16, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Param CEP/TDM Payload Bytes", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_cepopt_ais,
          { "AIS", "ldp.msg.tlv.fec.vc.intparam.cepopt_ais", FT_BOOLEAN, 16,
            NULL, 0x8000, "VC FEC Interface Param CEP Option AIS", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_cepopt_une,
          { "UNE", "ldp.msg.tlv.fec.vc.intparam.cepopt_une", FT_BOOLEAN, 16,
            NULL, 0x4000, "VC FEC Interface Param CEP Option Unequipped", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_cepopt_rtp,
          { "RTP", "ldp.msg.tlv.fec.vc.intparam.cepopt_rtp", FT_BOOLEAN, 16,
            NULL, 0x2000, "VC FEC Interface Param CEP Option RTP Header", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_cepopt_ebm,
          { "EBM", "ldp.msg.tlv.fec.vc.intparam.cepopt_ebm", FT_BOOLEAN, 16,
            NULL, 0x1000, "VC FEC Interface Param CEP Option EBM Header", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_cepopt_mah,
          { "MAH", "ldp.msg.tlv.fec.vc.intparam.cepopt_mah", FT_BOOLEAN, 16,
            NULL, 0x0800, "VC FEC Interface Param CEP Option MPLS Adaptation header", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_cepopt_res,
          { "Reserved", "ldp.msg.tlv.fec.vc.intparam.cepopt_res", FT_UINT16, BASE_HEX,
            NULL , 0x07E0, "VC FEC Interface Param CEP Option Reserved", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_cepopt_ceptype,
          { "CEP Type", "ldp.msg.tlv.fec.vc.intparam.cepopt_ceptype", FT_UINT16, BASE_HEX,
            VALS(fec_vc_ceptype_vals), 0x001C, "VC FEC Interface Param CEP Option CEP Type", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_cepopt_t3,
          { "Async T3", "ldp.msg.tlv.fec.vc.intparam.cepopt_t3", FT_BOOLEAN, 16,
            NULL, 0x0002, "VC FEC Interface Param CEP Option Async T3", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_cepopt_e3,
          { "Async E3", "ldp.msg.tlv.fec.vc.intparam.cepopt_e3", FT_BOOLEAN, 16,
            NULL, 0x0001, "VC FEC Interface Param CEP Option Async E3", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_vlanid,
          { "VLAN Id", "ldp.msg.tlv.fec.vc.intparam.vlanid", FT_UINT16, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Param VLAN Id", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_dlcilen,
          { "DLCI Length", "ldp.msg.tlv.fec.vc.intparam.dlcilen", FT_UINT16, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Parameter Frame-Relay DLCI Length", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_fcslen,
          { "FCS Length", "ldp.msg.tlv.fec.vc.intparam.fcslen", FT_UINT16, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Paramater FCS Length", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_tdmopt_r,
          { "R Bit", "ldp.msg.tlv.fec.vc.intparam.tdmopt_r", FT_BOOLEAN, 16,
            TFS(&fec_vc_tdmopt_r), 0x8000, "VC FEC Interface Param TDM Options RTP Header", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_tdmopt_d,
          { "D Bit", "ldp.msg.tlv.fec.vc.intparam.tdmopt_d", FT_BOOLEAN, 16,
            TFS(&fec_vc_tdmopt_d), 0x4000, "VC FEC Interface Param TDM Options Dynamic Timestamp", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_tdmopt_f,
          { "F Bit", "ldp.msg.tlv.fec.vc.intparam.tdmopt_f", FT_BOOLEAN, 16,
            TFS(&fec_vc_tdmopt_f), 0x2000, "VC FEC Interface Param TDM Options Flavor bit", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_tdmopt_res1,
          { "RSVD-1", "ldp.msg.tlv.fec.vc.intparam.tdmopt_res1", FT_UINT16, BASE_HEX,
            NULL, 0x1FFF, "VC FEC Interface Param TDM Options Reserved", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_tdmopt_pt,
          { "PT", "ldp.msg.tlv.fec.vc.intparam.tdmopt_pt", FT_UINT8, BASE_DEC,
            NULL, 0x7F, "VC FEC Interface Param TDM Options Payload Type", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_tdmopt_res2,
          { "RSVD-2", "ldp.msg.tlv.fec.vc.intparam.tdmopt_res2", FT_UINT8, BASE_HEX,
            NULL, 0x00, "VC FEC Interface Param TDM Options Reserved", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_tdmopt_freq,
          { "FREQ", "ldp.msg.tlv.fec.vc.intparam.tdmopt_freq", FT_UINT16, BASE_DEC,
            NULL, 0x00, "VC FEC Interface Param TDM Options Frequency", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_tdmopt_ssrc,
          { "SSRC", "ldp.msg.tlv.fec.vc.intparam.tdmopt_ssrc", FT_UINT32, BASE_HEX,
            NULL, 0x00, "VC FEC Interface Param TDM Options SSRC", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_vccv_cctype_cw,
          { "PWE3 Control Word", "ldp.msg.tlv.fec.vc.intparam.vccv.cctype_cw", FT_BOOLEAN, 8,
            NULL, 0x01, "VC FEC Interface Param VCCV CC Type PWE3 CW", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_vccv_cctype_mplsra,
          { "MPLS Router Alert", "ldp.msg.tlv.fec.vc.intparam.vccv.cctype_mplsra", FT_BOOLEAN, 8,
            NULL, 0x02, "VC FEC Interface Param VCCV CC Type MPLS Router Alert", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_vccv_cctype_ttl1,
          { "MPLS Inner Label TTL = 1", "ldp.msg.tlv.fec.vc.intparam.vccv.cctype_ttl1", FT_BOOLEAN, 8,
            NULL, 0x04, "VC FEC Interface Param VCCV CC Type Inner Label TTL 1", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_icmpping,
          { "ICMP Ping", "ldp.msg.tlv.fec.vc.intparam.vccv.cvtype_icmpping", FT_BOOLEAN, 8,
            NULL, 0x01, "VC FEC Interface Param VCCV CV Type ICMP Ping", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_lspping,
          { "LSP Ping", "ldp.msg.tlv.fec.vc.intparam.vccv.cvtype_lspping", FT_BOOLEAN, 8,
            NULL, 0x02, "VC FEC Interface Param VCCV CV Type LSP Ping", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd,
          { "BFD", "ldp.msg.tlv.fec.vc.intparam.vccv.cvtype_bfd", FT_BOOLEAN, 8,
            NULL, 0x04, "VC FEC Interface Param VCCV CV Type BFD", HFILL }},

        { &hf_ldp_tlv_lspid_act_flg,
          { "Action Indicator Flag", "ldp.msg.tlv.lspid.actflg", FT_UINT16, BASE_HEX,
            VALS(ldp_act_flg_vals), 0x000F, NULL, HFILL}},

        { &hf_ldp_tlv_lspid_cr_lsp,
          { "Local CR-LSP ID", "ldp.msg.tlv.lspid.locallspid", FT_UINT16, BASE_HEX,
            NULL, 0x0, NULL, HFILL}},

        { &hf_ldp_tlv_lspid_ldpid,
          { "Ingress LSR Router ID", "ldp.msg.tlv.lspid.lsrid", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL}},

        { &hf_ldp_tlv_er_hop_loose,
          { "Loose route bit", "ldp.msg.tlv.er_hop.loose", FT_UINT24, BASE_HEX,
            VALS(ldp_loose_vals), 0x800000, NULL, HFILL}},

        { &hf_ldp_tlv_er_hop_prelen,
          { "Prefix length", "ldp.msg.tlv.er_hop.prefixlen", FT_UINT8, BASE_DEC,
            NULL, 0x0, "Prefix len", HFILL}},

        { &hf_ldp_tlv_er_hop_prefix4,
          { "IPv4 Address", "ldp.msg.tlv.er_hop.prefix4", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL}},

        { &hf_ldp_tlv_er_hop_prefix6,
          { "IPv6 Address", "ldp.msg.tlv.er_hop.prefix6", FT_IPv6, BASE_NONE,
            NULL, 0x0, NULL, HFILL}},

        { &hf_ldp_tlv_er_hop_as,
          { "AS Number", "ldp.msg.tlv.er_hop.as", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL}},

        { &hf_ldp_tlv_er_hop_cr_lsp,
          { "Local CR-LSP ID", "ldp.msg.tlv.er_hop.locallspid", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL}},

        { &hf_ldp_tlv_er_hop_ldpid,
          { "Local CR-LSP ID", "ldp.msg.tlv.er_hop.lsrid", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL}},

        { &hf_ldp_tlv_flags_reserv,
          { "Reserved", "ldp.msg.tlv.flags_reserv", FT_UINT8, BASE_HEX,
            NULL, 0xC0, NULL, HFILL}},

        { &hf_ldp_tlv_flags_pdr,
          { "PDR", "ldp.msg.tlv.flags_pdr", FT_BOOLEAN, 8,
            TFS(&tlv_negotiable), 0x1, "PDR negotiability flag", HFILL}},

        { &hf_ldp_tlv_flags_pbs,
          { "PBS", "ldp.msg.tlv.flags_pbs", FT_BOOLEAN, 8,
            TFS(&tlv_negotiable), 0x2, "PBS negotiability flag", HFILL}},

        { &hf_ldp_tlv_flags_cdr,
          { "CDR", "ldp.msg.tlv.flags_cdr", FT_BOOLEAN, 8,
            TFS(&tlv_negotiable), 0x4, "CDR negotiability flag", HFILL}},

        { &hf_ldp_tlv_flags_cbs,
          { "CBS", "ldp.msg.tlv.flags_cbs", FT_BOOLEAN, 8,
            TFS(&tlv_negotiable), 0x8, "CBS negotiability flag", HFILL}},

        { &hf_ldp_tlv_flags_ebs,
          { "EBS", "ldp.msg.tlv.flags_ebs", FT_BOOLEAN, 8,
            TFS(&tlv_negotiable), 0x10, "EBS negotiability flag", HFILL}},

        { &hf_ldp_tlv_flags_weight,
          { "Weight", "ldp.msg.tlv.flags_weight", FT_BOOLEAN, 8,
            TFS(&tlv_negotiable), 0x20, "Weight negotiability flag", HFILL}},

        { &hf_ldp_tlv_frequency,
          { "Frequency", "ldp.msg.tlv.frequency", FT_UINT8, BASE_DEC,
            VALS(freq_values), 0, NULL, HFILL}},

        { &hf_ldp_tlv_weight,
          { "Weight", "ldp.msg.tlv.weight", FT_UINT8, BASE_DEC,
            NULL, 0, "Weight of the CR-LSP", HFILL}},

        { &hf_ldp_tlv_pdr,
          { "PDR", "ldp.msg.tlv.pdr", FT_DOUBLE, BASE_NONE,
            NULL, 0, "Peak Data Rate", HFILL}},

        { &hf_ldp_tlv_pbs,
          { "PBS", "ldp.msg.tlv.pbs", FT_DOUBLE, BASE_NONE,
            NULL, 0, "Peak Burst Size", HFILL}},

        { &hf_ldp_tlv_cdr,
          { "CDR", "ldp.msg.tlv.cdr", FT_DOUBLE, BASE_NONE,
            NULL, 0, "Committed Data Rate", HFILL}},

        { &hf_ldp_tlv_cbs,
          { "CBS", "ldp.msg.tlv.cbs", FT_DOUBLE, BASE_NONE,
            NULL, 0, "Committed Burst Size", HFILL}},

        { &hf_ldp_tlv_ebs,
          { "EBS", "ldp.msg.tlv.ebs", FT_DOUBLE, BASE_NONE,
            NULL, 0, "Excess Burst Size", HFILL}},

        { &hf_ldp_tlv_set_prio,
          { "Set Prio", "ldp.msg.tlv.set_prio", FT_UINT8, BASE_DEC,
            NULL, 0, "LSP setup priority", HFILL}},

        { &hf_ldp_tlv_hold_prio,
          { "Hold Prio", "ldp.msg.tlv.hold_prio", FT_UINT8, BASE_DEC,
            NULL, 0, "LSP hold priority", HFILL}},

        { &hf_ldp_tlv_route_pinning,
          { "Route Pinning", "ldp.msg.tlv.route_pinning", FT_UINT32, BASE_DEC,
            VALS(route_pinning_vals), 0x80000000, NULL, HFILL}},

        { &hf_ldp_tlv_resource_class,
          { "Resource Class", "ldp.msg.tlv.resource_class", FT_UINT32, BASE_HEX,
            NULL, 0, "Resource Class (Color)", HFILL}},

        { &hf_ldp_tlv_diffserv,
          { "Diff-Serv TLV", "ldp.msg.tlv.diffserv", FT_NONE, BASE_NONE,
            NULL, 0, "Diffserv TLV", HFILL}},

        { &hf_ldp_tlv_diffserv_type,
          { "LSP Type", "ldp.msg.tlv.diffserv.type", FT_UINT8, BASE_DEC,
            VALS(diffserv_type_vals), 0x80, NULL, HFILL}},

        { &hf_ldp_tlv_diffserv_mapnb,
          { "MAPnb", "ldp.msg.tlv.diffserv.mapnb", FT_UINT8, BASE_DEC,
            NULL, 0, MAPNB_DESCRIPTION, HFILL}},

        { &hf_ldp_tlv_diffserv_map,
          { "MAP", "ldp.msg.tlv.diffserv.map", FT_NONE, BASE_NONE,
            NULL, 0, MAP_DESCRIPTION, HFILL}},

        { &hf_ldp_tlv_diffserv_map_exp,
          { "EXP", "ldp.msg.tlv.diffserv.map.exp", FT_UINT8, BASE_DEC,
            NULL, 0, EXP_DESCRIPTION, HFILL}},

        { &hf_ldp_tlv_diffserv_phbid,
          { PHBID_DESCRIPTION, "ldp.msg.tlv.diffserv.phbid", FT_NONE, BASE_NONE,
            NULL, 0, NULL, HFILL}},

        { &hf_ldp_tlv_diffserv_phbid_dscp,
          { PHBID_DSCP_DESCRIPTION, "ldp.msg.tlv.diffserv.phbid.dscp", FT_UINT16, BASE_DEC,
            NULL, PHBID_DSCP_MASK, NULL, HFILL}},

        { &hf_ldp_tlv_diffserv_phbid_code,
          { PHBID_CODE_DESCRIPTION, "ldp.msg.tlv.diffserv.phbid.code", FT_UINT16, BASE_DEC,
            NULL, PHBID_CODE_MASK, NULL, HFILL}},

        { &hf_ldp_tlv_diffserv_phbid_bit14,
          { PHBID_BIT14_DESCRIPTION, "ldp.msg.tlv.diffserv.phbid.bit14", FT_UINT16, BASE_DEC,
            VALS(phbid_bit14_vals), PHBID_BIT14_MASK, NULL, HFILL}},

        { &hf_ldp_tlv_diffserv_phbid_bit15,
          { PHBID_BIT15_DESCRIPTION, "ldp.msg.tlv.diffserv.phbid.bit15", FT_UINT16, BASE_DEC,
            VALS(phbid_bit15_vals), PHBID_BIT15_MASK, NULL, HFILL}},

        { &hf_ldp_tlv_fec_gen_agi_type,
          { "AGI Type", "ldp.msg.tlv.fec.gen.agi.type", FT_UINT8, BASE_DEC,
            NULL, 0x0, "Attachment Group Identifier Type", HFILL}},

        { &hf_ldp_tlv_fec_gen_agi_length,
          { "AGI Length", "ldp.msg.tlv.fec.gen.agi.length", FT_UINT8, BASE_DEC,
            NULL, 0x0, "Attachment Group Identifier Length", HFILL}},

        { &hf_ldp_tlv_fec_gen_agi_value,
          { "AGI Value", "ldp.msg.tlv.fec.gen.agi.value", FT_BYTES, BASE_NONE,
            NULL, 0x0, "Attachment Group Identifier Value", HFILL}},

        { &hf_ldp_tlv_fec_gen_saii_type,
          { "SAII Type", "ldp.msg.tlv.fec.gen.saii.type", FT_UINT8, BASE_DEC,
            NULL, 0x0, "Source Attachment Individual Identifier Type", HFILL}},

        { &hf_ldp_tlv_fec_gen_saii_length,
          { "SAII Length", "ldp.msg.tlv.fec.gen.saii.length", FT_UINT8, BASE_DEC,
            NULL, 0x0, "Source Attachment Individual Identifier Length", HFILL}},

        { &hf_ldp_tlv_fec_gen_saii_value,
          { "SAII Value", "ldp.msg.tlv.fec.gen.saii.value", FT_BYTES, BASE_NONE,
            NULL, 0x0, "Source Attachment Individual Identifier Value", HFILL}},

        { &hf_ldp_tlv_fec_gen_taii_type,
          { "TAII Type", "ldp.msg.tlv.fec.gen.taii.type", FT_UINT8, BASE_DEC,
            NULL, 0x0, "Target Attachment Individual Identifier Type", HFILL}},

        { &hf_ldp_tlv_fec_gen_taii_length,
          { "TAII length", "ldp.msg.tlv.fec.gen.taii.length", FT_UINT8, BASE_DEC,
            NULL, 0x0, "Target Attachment Individual Identifier Length", HFILL}},

        { &hf_ldp_tlv_fec_gen_taii_value,
          { "TAII Value", "ldp.msg.tlv.fec.gen.taii.value", FT_BYTES, BASE_NONE,
            NULL, 0x0, "Target Attachment Individual Identifier Value", HFILL}},

        { &hf_ldp_tlv_fec_gen_aai_globalid,
          { "Global Id", "ldp.msg.tlv.fec.gen.aii.globalid", FT_UINT32, BASE_DEC,
            NULL, 0x0, "Attachment Individual Identifier Global Id", HFILL}},

        { &hf_ldp_tlv_fec_gen_aai_prefix,
          { "Prefix", "ldp.msg.tlv.fec.gen.aii.prefix", FT_UINT32, BASE_DEC,
            NULL, 0x0, "Attachment Individual Identifier Prefix", HFILL}},

        { &hf_ldp_tlv_fec_gen_aai_ac_id,
          { "Prefix", "ldp.msg.tlv.fec.gen.aii.acid", FT_UINT32, BASE_DEC,
            NULL, 0x0, "Attachment Individual Identifier AC Id", HFILL}},

        { &hf_ldp_tlv_pw_status_data,
          { "Status Code", "ldp.msg.tlv.pwstatus.code", FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }},

        { &hf_ldp_tlv_pw_not_forwarding,
          { "Pseudowire Not Forwarding", "ldp.msg.tlv.pwstatus.code.pwnotforward", FT_BOOLEAN, 32,
            TFS(&tfs_set_notset), PW_NOT_FORWARDING, NULL, HFILL }},

        { &hf_ldp_tlv_pw_lac_ingress_recv_fault,
          { "Local Attachment Circuit (ingress) Receive Fault", "ldp.msg.tlv.pwstatus.code.pwlacingressrecvfault",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), PW_LAC_INGRESS_RECV_FAULT, NULL, HFILL }},

        { &hf_ldp_tlv_pw_lac_egress_recv_fault,
          { "Local Attachment Circuit (egress) Transmit Fault", "ldp.msg.tlv.pwstatus.code.pwlacegresstransfault",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), PW_LAC_EGRESS_TRANS_FAULT, NULL, HFILL }},

        { &hf_ldp_tlv_pw_psn_pw_ingress_recv_fault,
          { "Local PSN-facing PW (ingress) Receive Fault", "ldp.msg.tlv.pwstatus.code.pwpsnpwingressrecvfault",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), PW_PSN_PW_INGRESS_RECV_FAULT, NULL, HFILL }},

        { &hf_ldp_tlv_pw_psn_pw_egress_recv_fault,
          { "Local PSN-facing PW (egress) Transmit Fault", "ldp.msg.tlv.pwstatus.code.pwpsnpwegresstransfault",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), PW_PSN_PW_EGRESS_TRANS_FAULT, NULL, HFILL }},

        { &hf_ldp_tlv_pw_grouping_value,
          { "Value", "ldp.msg.tlv.pwgrouping.value",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "PW Grouping Value", HFILL }},

        { &hf_ldp_tlv_intparam_length,
          { "Length", "ldp.msg.tlv.intparam.length", FT_UINT8, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Paramater Length", HFILL }},

        { &hf_ldp_tlv_intparam_mtu,
          { "MTU", "ldp.msg.tlv.intparam.mtu", FT_UINT16, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Paramater MTU", HFILL }},

        { &hf_ldp_tlv_intparam_tdmbps,
          { "BPS", "ldp.msg.tlv.intparam.tdmbps", FT_UINT32, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Parameter CEP/TDM bit-rate", HFILL }},

        { &hf_ldp_tlv_intparam_id,
          { "ID", "ldp.msg.tlv.intparam.id", FT_UINT8, BASE_HEX,
            VALS(fec_vc_interfaceparm), 0x0, "VC FEC Interface Paramater ID", HFILL }},

        { &hf_ldp_tlv_intparam_maxcatmcells,
          { "Number of Cells", "ldp.msg.tlv.intparam.maxatm", FT_UINT16, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Param Max ATM Concat Cells", HFILL }},

        { &hf_ldp_tlv_intparam_desc,
          { "Description", "ldp.msg.tlv.intparam.desc", FT_STRING, BASE_NONE,
            NULL, 0, "VC FEC Interface Description", HFILL }},

        { &hf_ldp_tlv_intparam_cepbytes,
          { "Payload Bytes", "ldp.msg.tlv.intparam.cepbytes", FT_UINT16, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Param CEP/TDM Payload Bytes", HFILL }},

        { &hf_ldp_tlv_intparam_cepopt_ais,
          { "AIS", "ldp.msg.tlv.intparam.cepopt_ais", FT_BOOLEAN, 16,
            NULL, 0x8000, "VC FEC Interface Param CEP Option AIS", HFILL }},

        { &hf_ldp_tlv_intparam_cepopt_une,
          { "UNE", "ldp.msg.tlv.intparam.cepopt_une", FT_BOOLEAN, 16,
            NULL, 0x4000, "VC FEC Interface Param CEP Option Unequipped", HFILL }},

        { &hf_ldp_tlv_intparam_cepopt_rtp,
          { "RTP", "ldp.msg.tlv.intparam.cepopt_rtp", FT_BOOLEAN, 16,
            NULL, 0x2000, "VC FEC Interface Param CEP Option RTP Header", HFILL }},

        { &hf_ldp_tlv_intparam_cepopt_ebm,
          { "EBM", "ldp.msg.tlv.intparam.cepopt_ebm", FT_BOOLEAN, 16,
            NULL, 0x1000, "VC FEC Interface Param CEP Option EBM Header", HFILL }},

        { &hf_ldp_tlv_intparam_cepopt_mah,
          { "MAH", "ldp.msg.tlv.intparam.cepopt_mah", FT_BOOLEAN, 16,
            NULL, 0x0800, "VC FEC Interface Param CEP Option MPLS Adaptation header", HFILL }},

        { &hf_ldp_tlv_intparam_cepopt_res,
          { "Reserved", "ldp.msg.tlv.intparam.cepopt_res", FT_UINT16, BASE_HEX,
            NULL , 0x07E0, "VC FEC Interface Param CEP Option Reserved", HFILL }},

        { &hf_ldp_tlv_intparam_cepopt_ceptype,
          { "CEP Type", "ldp.msg.tlv.intparam.cepopt_ceptype", FT_UINT16, BASE_HEX,
            VALS(fec_vc_ceptype_vals), 0x001C, "VC FEC Interface Param CEP Option CEP Type", HFILL }},

        { &hf_ldp_tlv_intparam_cepopt_t3,
          { "Async T3", "ldp.msg.tlv.intparam.cepopt_t3", FT_BOOLEAN, 16,
            NULL, 0x0002, "VC FEC Interface Param CEP Option Async T3", HFILL }},

        { &hf_ldp_tlv_intparam_cepopt_e3,
          { "Async E3", "ldp.msg.tlv.intparam.cepopt_e3", FT_BOOLEAN, 16,
            NULL, 0x0001, "VC FEC Interface Param CEP Option Async E3", HFILL }},

        { &hf_ldp_tlv_intparam_vlanid,
          { "VLAN Id", "ldp.msg.tlv.intparam.vlanid", FT_UINT16, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Param VLAN Id", HFILL }},

        { &hf_ldp_tlv_intparam_dlcilen,
          { "DLCI Length", "ldp.msg.tlv.intparam.dlcilen", FT_UINT16, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Parameter Frame-Relay DLCI Length", HFILL }},

        { &hf_ldp_tlv_intparam_fcslen,
          { "FCS Length", "ldp.msg.tlv.intparam.fcslen", FT_UINT16, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Paramater FCS Length", HFILL }},

        { &hf_ldp_tlv_intparam_tdmopt_r,
          { "R Bit", "ldp.msg.tlv.intparam.tdmopt_r", FT_BOOLEAN, 16,
            TFS(&fec_vc_tdmopt_r), 0x8000, "VC FEC Interface Param TDM Options RTP Header", HFILL }},

        { &hf_ldp_tlv_intparam_tdmopt_d,
          { "D Bit", "ldp.msg.tlv.intparam.tdmopt_d", FT_BOOLEAN, 16,
            TFS(&fec_vc_tdmopt_d), 0x4000, "VC FEC Interface Param TDM Options Dynamic Timestamp", HFILL }},

        { &hf_ldp_tlv_intparam_tdmopt_f,
          { "F Bit", "ldp.msg.tlv.intparam.tdmopt_f", FT_BOOLEAN, 16,
            TFS(&fec_vc_tdmopt_f), 0x2000, "VC FEC Interface Param TDM Options Flavor bit", HFILL }},

        { &hf_ldp_tlv_intparam_tdmopt_res1,
          { "RSVD-1", "ldp.msg.tlv.intparam.tdmopt_res1", FT_UINT16, BASE_HEX,
            NULL, 0x1FFF, "VC FEC Interface Param TDM Options Reserved", HFILL }},

        { &hf_ldp_tlv_intparam_tdmopt_pt,
          { "PT", "ldp.msg.tlv.intparam.tdmopt_pt", FT_UINT8, BASE_DEC,
            NULL, 0x7F, "VC FEC Interface Param TDM Options Payload Type", HFILL }},

        { &hf_ldp_tlv_intparam_tdmopt_res2,
          { "RSVD-2", "ldp.msg.tlv.intparam.tdmopt_res2", FT_UINT8, BASE_HEX,
            NULL, 0x00, "VC FEC Interface Param TDM Options Reserved", HFILL }},

        { &hf_ldp_tlv_intparam_tdmopt_freq,
          { "FREQ", "ldp.msg.tlv.intparam.tdmopt_freq", FT_UINT16, BASE_DEC,
            NULL, 0x00, "VC FEC Interface Param TDM Options Frequency", HFILL }},

        { &hf_ldp_tlv_intparam_tdmopt_ssrc,
          { "SSRC", "ldp.msg.tlv.intparam.tdmopt_ssrc", FT_UINT32, BASE_HEX,
            NULL, 0x00, "VC FEC Interface Param TDM Options SSRC", HFILL }},

        { &hf_ldp_tlv_intparam_vccv_cctype_cw,
          { "PWE3 Control Word", "ldp.msg.tlv.intparam.vccv.cctype_cw", FT_BOOLEAN, 8,
            NULL, 0x01, "VC FEC Interface Param VCCV CC Type PWE3 CW", HFILL }},

        { &hf_ldp_tlv_intparam_vccv_cctype_mplsra,
          { "MPLS Router Alert", "ldp.msg.tlv.intparam.vccv.cctype_mplsra", FT_BOOLEAN, 8,
            NULL, 0x02, "VC FEC Interface Param VCCV CC Type MPLS Router Alert", HFILL }},

        { &hf_ldp_tlv_intparam_vccv_cctype_ttl1,
          { "MPLS Inner Label TTL = 1", "ldp.msg.tlv.intparam.vccv.cctype_ttl1", FT_BOOLEAN, 8,
            NULL, 0x04, "VC FEC Interface Param VCCV CC Type Inner Label TTL 1", HFILL }},

        { &hf_ldp_tlv_intparam_vccv_cvtype_icmpping,
          { "ICMP Ping", "ldp.msg.tlv.intparam.vccv.cvtype_icmpping", FT_BOOLEAN, 8,
            NULL, 0x01, "VC FEC Interface Param VCCV CV Type ICMP Ping", HFILL }},

        { &hf_ldp_tlv_intparam_vccv_cvtype_lspping,
          { "LSP Ping", "ldp.msg.tlv.intparam.vccv.cvtype_lspping", FT_BOOLEAN, 8,
            NULL, 0x02, "VC FEC Interface Param VCCV CV Type LSP Ping", HFILL }},

        { &hf_ldp_tlv_intparam_vccv_cvtype_bfd,
          { "BFD", "ldp.msg.tlv.intparam.vccv.cvtype_bfd", FT_BOOLEAN, 8,
            NULL, 0x04, "VC FEC Interface Param VCCV CV Type BFD", HFILL }}
    };

    static gint *ett[] = {
        &ett_ldp,
        &ett_ldp_header,
        &ett_ldp_ldpid,
        &ett_ldp_message,
        &ett_ldp_tlv,
        &ett_ldp_tlv_val,
        &ett_ldp_tlv_ft_flags,
        &ett_ldp_fec,
        &ett_ldp_fec_vc_interfaceparam,
        &ett_ldp_fec_vc_interfaceparam_cepopt,
        &ett_ldp_fec_vc_interfaceparam_vccvtype,
        &ett_ldp_diffserv_map,
        &ett_ldp_diffserv_map_phbid,
        &ett_ldp_gen_agi,
        &ett_ldp_gen_saii,
        &ett_ldp_gen_taii,
        &ett_ldp_gen_aai_type2
    };

    module_t *ldp_module;

    proto_ldp = proto_register_protocol("Label Distribution Protocol",
                                        "LDP", "ldp");

    proto_register_field_array(proto_ldp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register our configuration options for , particularly our port */

    ldp_module = prefs_register_protocol(proto_ldp, proto_reg_handoff_ldp);

    prefs_register_uint_preference(ldp_module, "tcp.port", "LDP TCP Port",
                                   "Set the TCP port for messages (if other"
                                   " than the default of 646)",
                                   10, &global_ldp_tcp_port);

    prefs_register_uint_preference(ldp_module, "udp.port", "LDP UDP Port",
                                   "Set the UDP port for messages (if other"
                                   " than the default of 646)",
                                   10, &global_ldp_udp_port);

    prefs_register_bool_preference(ldp_module, "desegment_ldp_messages",
                                   "Reassemble LDP messages spanning multiple TCP segments",
                                   "Whether the LDP dissector should reassemble messages spanning multiple TCP segments."
                                   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\""
                                   " in the TCP protocol settings.",
                                   &ldp_desegment);
}

/* The registration hand-off routine */
void
proto_reg_handoff_ldp(void)
{
    static gboolean ldp_prefs_initialized = FALSE;
    static dissector_handle_t ldp_tcp_handle, ldp_handle;
    static int tcp_port;
    static int udp_port;


    if (!ldp_prefs_initialized) {

        ldp_tcp_handle = new_create_dissector_handle(dissect_ldp_tcp, proto_ldp);
        ldp_handle = new_create_dissector_handle(dissect_ldp, proto_ldp);

        ldp_prefs_initialized = TRUE;

    }
    else {

        dissector_delete_uint("tcp.port", tcp_port, ldp_tcp_handle);
        dissector_delete_uint("udp.port", udp_port, ldp_handle);

    }

    /* Set our port number for future use */

    tcp_port = global_ldp_tcp_port;
    udp_port = global_ldp_udp_port;

    dissector_add_uint("tcp.port", global_ldp_tcp_port, ldp_tcp_handle);
    dissector_add_uint("udp.port", global_ldp_udp_port, ldp_handle);

}
