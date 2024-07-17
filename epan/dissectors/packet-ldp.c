/* packet-ldp.c
 * Routines for LDP (RFC 3036) packet disassembly
 *
 * Copyright (c) November 2000 by Richard Sharpe <rsharpe@ns.aus.com>
 *
 * CRLDP (RFC3212) is now supported
 *   - (c) 2002 Michael Rozhavsky <mike[AT]tochna.technion.ac.il>
 *
 * (c) Copyright 2011, Shobhank Sharma <ssharma5@ncsu.edu>
 *   -  update the VCCV bitmaps as per RFC 5885
 *
 * (c) Copyright 2012, Aditya Ambadkar and Diana Chris <arambadk,dvchris@ncsu.edu>
 *   -  support for the flowlabel sub-tlv as per RFC 6391
 *
 * (c) Copyright 2013, Gaurav Patwardhan <gspatwar@ncsu.edu>
 *   -  support for the GTSM flag as per RFC 6720
 *
 * (c) Copyright 2013, Rupesh Patro <rbpatro@ncsu.edu>
 *   -  Support for Upstream-Assigned Label TLVs and Sub-TLVs as per RFC 6389
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/afn.h>
#include <epan/expert.h>
#include <epan/show_exception.h>

#include "packet-diffserv-mpls-common.h"
#include "packet-ldp.h"

#define TCP_PORT_LDP 646
#define UDP_PORT_LDP 646


void proto_register_ldp(void);
void proto_reg_handoff_ldp(void);

static dissector_handle_t ldp_tcp_handle, ldp_handle;

static int proto_ldp;

/* Delete the following if you do not use it, or add to it if you need */
/* static int hf_ldp_req; */
/* static int hf_ldp_rsp; */
static int hf_ldp_version;
static int hf_ldp_pdu_len;
static int hf_ldp_lsr;
static int hf_ldp_ls_id;
static int hf_ldp_msg_ubit;
static int hf_ldp_msg_type;
static int hf_ldp_msg_len;
static int hf_ldp_msg_id;
static int hf_ldp_msg_vendor_id;
static int hf_ldp_msg_experiment_id;
static int hf_ldp_tlv_value;
static int hf_ldp_tlv_type;
static int hf_ldp_tlv_unknown;
static int hf_ldp_tlv_len;
static int hf_ldp_tlv_val_hold;
static int hf_ldp_tlv_val_target;
static int hf_ldp_tlv_val_request;
static int hf_ldp_tlv_val_res;
static int hf_ldp_tlv_val_gtsm_flag;
static int hf_ldp_tlv_ipv4_taddr;
static int hf_ldp_tlv_config_seqno;
static int hf_ldp_tlv_ipv6_taddr;
static int hf_ldp_tlv_fec_wc;
static int hf_ldp_tlv_fec_af;
static int hf_ldp_tlv_fec_len;
static int hf_ldp_tlv_fec_pfval;
static int hf_ldp_tlv_fec_hoval;
static int hf_ldp_tlv_addrl_addr_family;
static int hf_ldp_tlv_addrl_addr;
static int hf_ldp_tlv_hc_value;
static int hf_ldp_tlv_pv_lsrid;
static int hf_ldp_tlv_generic_label;
static int hf_ldp_tlv_atm_label_vbits;
static int hf_ldp_tlv_atm_label_vpi;
static int hf_ldp_tlv_atm_label_vci;
static int hf_ldp_tlv_fr_label_len;
static int hf_ldp_tlv_fr_label_dlci;
static int hf_ldp_tlv_ft_protect_sequence_num;
static int hf_ldp_tlv_status_ebit;
static int hf_ldp_tlv_status_fbit;
static int hf_ldp_tlv_status_data;
static int hf_ldp_tlv_status_msg_id;
static int hf_ldp_tlv_status_msg_type;
static int hf_ldp_tlv_extstatus_data;
static int hf_ldp_tlv_returned_version;
static int hf_ldp_tlv_returned_pdu_len;
static int hf_ldp_tlv_returned_lsr;
static int hf_ldp_tlv_returned_ls_id;
static int hf_ldp_tlv_returned_msg_ubit;
static int hf_ldp_tlv_returned_msg_type;
static int hf_ldp_tlv_returned_msg_len;
static int hf_ldp_tlv_returned_msg_id;
static int hf_ldp_tlv_mac;
static int hf_ldp_tlv_sess_ver;
static int hf_ldp_tlv_sess_ka;
static int hf_ldp_tlv_sess_advbit;
static int hf_ldp_tlv_sess_ldetbit;
static int hf_ldp_tlv_sess_pvlim;
static int hf_ldp_tlv_sess_mxpdu;
static int hf_ldp_tlv_sess_rxlsr;
static int hf_ldp_tlv_sess_rxls;
static int hf_ldp_tlv_sess_atm_merge;
static int hf_ldp_tlv_sess_atm_lr;
static int hf_ldp_tlv_sess_atm_dir;
static int hf_ldp_tlv_sess_atm_minvpi;
static int hf_ldp_tlv_sess_atm_maxvpi;
static int hf_ldp_tlv_sess_atm_minvci;
static int hf_ldp_tlv_sess_atm_maxvci;
static int hf_ldp_tlv_sess_fr_merge;
static int hf_ldp_tlv_sess_fr_lr;
static int hf_ldp_tlv_sess_fr_dir;
static int hf_ldp_tlv_sess_fr_len;
static int hf_ldp_tlv_sess_fr_mindlci;
static int hf_ldp_tlv_sess_fr_maxdlci;
static int hf_ldp_tlv_ft_sess_flags;
static int hf_ldp_tlv_ft_sess_flag_r;
static int hf_ldp_tlv_ft_sess_flag_res;
static int hf_ldp_tlv_ft_sess_flag_s;
static int hf_ldp_tlv_ft_sess_flag_a;
static int hf_ldp_tlv_ft_sess_flag_c;
static int hf_ldp_tlv_ft_sess_flag_l;
static int hf_ldp_tlv_ft_sess_res;
static int hf_ldp_tlv_ft_sess_reconn_to;
static int hf_ldp_tlv_ft_sess_recovery_time;
static int hf_ldp_tlv_ft_ack_sequence_num;
static int hf_ldp_tlv_lbl_req_msg_id;
static int hf_ldp_tlv_vendor_id;
static int hf_ldp_tlv_experiment_id;
static int hf_ldp_tlv_fec_vc_controlword;
static int hf_ldp_tlv_fec_vc_vctype;
static int hf_ldp_tlv_fec_vc_infolength;
static int hf_ldp_tlv_fec_vc_groupid;
static int hf_ldp_tlv_fec_vc_vcid;
static int hf_ldp_tlv_fec_vc_intparam_length;
static int hf_ldp_tlv_fec_vc_intparam_mtu;
static int hf_ldp_tlv_fec_vc_intparam_tdmbps;
static int hf_ldp_tlv_fec_vc_intparam_id;
static int hf_ldp_tlv_fec_vc_intparam_maxcatmcells;
static int hf_ldp_tlv_fec_vc_intparam_desc;
static int hf_ldp_tlv_fec_vc_intparam_cepbytes;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_ais;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_une;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_rtp;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_ebm;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_mah;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_res;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_ceptype;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_t3;
static int hf_ldp_tlv_fec_vc_intparam_cepopt_e3;
static int hf_ldp_tlv_fec_vc_intparam_vlanid;
static int hf_ldp_tlv_fec_vc_intparam_dlcilen;
static int hf_ldp_tlv_fec_vc_intparam_fcslen;
static int hf_ldp_tlv_fec_vc_intparam_tdmopt_r;
static int hf_ldp_tlv_fec_vc_intparam_tdmopt_d;
static int hf_ldp_tlv_fec_vc_intparam_tdmopt_f;
static int hf_ldp_tlv_fec_vc_intparam_tdmopt_res1;
static int hf_ldp_tlv_fec_vc_intparam_tdmopt_pt;
static int hf_ldp_tlv_fec_vc_intparam_tdmopt_res2;
static int hf_ldp_tlv_fec_vc_intparam_tdmopt_freq;
static int hf_ldp_tlv_fec_vc_intparam_tdmopt_ssrc;
static int hf_ldp_tlv_fec_vc_intparam_vccv_cctype_cw;
static int hf_ldp_tlv_fec_vc_intparam_vccv_cctype_mplsra;
static int hf_ldp_tlv_fec_vc_intparam_vccv_cctype_ttl1;
static int hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_icmpping;
static int hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_lspping;
static int hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd1;
static int hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd2;
static int hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd3;
static int hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd4;
static int hf_ldp_tlv_fec_vc_intparam_flowlabel_t;                    /* Flow label interface parameter RFC6391 */
static int hf_ldp_tlv_fec_vc_intparam_flowlabel_r;                    /* Flow label interface parameter RFC6391 */
static int hf_ldp_tlv_fec_vc_intparam_flowlabel_res;                  /* Flow label interface parameter RFC6391 */
static int hf_ldp_tlv_lspid_act_flg;
static int hf_ldp_tlv_lspid_cr_lsp;
static int hf_ldp_tlv_lspid_ldpid;
static int hf_ldp_tlv_er_hop_loose;
static int hf_ldp_tlv_er_hop_prelen;
static int hf_ldp_tlv_er_hop_prefix4;
static int hf_ldp_tlv_er_hop_prefix6;
static int hf_ldp_tlv_er_hop_as;
static int hf_ldp_tlv_er_hop_cr_lsp;
static int hf_ldp_tlv_er_hop_ldpid;
static int hf_ldp_tlv_flags_reserv;
static int hf_ldp_tlv_flags_weight;
static int hf_ldp_tlv_flags_ebs;
static int hf_ldp_tlv_flags_cbs;
static int hf_ldp_tlv_flags_cdr;
static int hf_ldp_tlv_flags_pbs;
static int hf_ldp_tlv_flags_pdr;
static int hf_ldp_tlv_frequency;
static int hf_ldp_tlv_pdr;
static int hf_ldp_tlv_pbs;
static int hf_ldp_tlv_cdr;
static int hf_ldp_tlv_cbs;
static int hf_ldp_tlv_ebs;
static int hf_ldp_tlv_weight;
static int hf_ldp_tlv_set_prio;
static int hf_ldp_tlv_hold_prio;
static int hf_ldp_tlv_route_pinning;
static int hf_ldp_tlv_resource_class;
/* static int hf_ldp_tlv_diffserv; */
static int hf_ldp_tlv_diffserv_type;
static int hf_ldp_tlv_diffserv_mapnb;
static int hf_ldp_tlv_diffserv_map;
static int hf_ldp_tlv_diffserv_map_exp;
static int hf_ldp_tlv_diffserv_phbid;
static int hf_ldp_tlv_diffserv_phbid_dscp;
static int hf_ldp_tlv_diffserv_phbid_code;
static int hf_ldp_tlv_diffserv_phbid_bit14;
static int hf_ldp_tlv_diffserv_phbid_bit15;
static int hf_ldp_tlv_fec_gen_agi_type;
static int hf_ldp_tlv_fec_gen_agi_length;
static int hf_ldp_tlv_fec_gen_agi_value;
static int hf_ldp_tlv_fec_gen_saii_type;
static int hf_ldp_tlv_fec_gen_saii_length;
static int hf_ldp_tlv_fec_gen_saii_value;
static int hf_ldp_tlv_fec_gen_taii_type;
static int hf_ldp_tlv_fec_gen_taii_length;
static int hf_ldp_tlv_fec_gen_taii_value;
static int hf_ldp_tlv_fec_gen_aai_globalid;
static int hf_ldp_tlv_fec_gen_aai_prefix;
static int hf_ldp_tlv_fec_gen_aai_ac_id;
static int hf_ldp_tlv_fec_pw_controlword;
static int hf_ldp_tlv_fec_pw_pwtype;
static int hf_ldp_tlv_fec_pw_infolength;
static int hf_ldp_tlv_fec_pw_groupid;
static int hf_ldp_tlv_fec_pw_pwid;
static int hf_ldp_tlv_pw_status_data;
static int hf_ldp_tlv_pw_not_forwarding;
static int hf_ldp_tlv_pw_lac_ingress_recv_fault;
static int hf_ldp_tlv_pw_lac_egress_recv_fault;
static int hf_ldp_tlv_pw_psn_pw_ingress_recv_fault;
static int hf_ldp_tlv_pw_psn_pw_egress_recv_fault;
static int hf_ldp_tlv_pw_grouping_value;
static int hf_ldp_tlv_intparam_length;
static int hf_ldp_tlv_intparam_mtu;
static int hf_ldp_tlv_intparam_tdmbps;
static int hf_ldp_tlv_intparam_id;
static int hf_ldp_tlv_intparam_maxcatmcells;
static int hf_ldp_tlv_intparam_desc;
static int hf_ldp_tlv_intparam_cepbytes;
static int hf_ldp_tlv_intparam_cepopt_ais;
static int hf_ldp_tlv_intparam_cepopt_une;
static int hf_ldp_tlv_intparam_cepopt_rtp;
static int hf_ldp_tlv_intparam_cepopt_ebm;
static int hf_ldp_tlv_intparam_cepopt_mah;
static int hf_ldp_tlv_intparam_cepopt_res;
static int hf_ldp_tlv_intparam_cepopt_ceptype;
static int hf_ldp_tlv_intparam_cepopt_t3;
static int hf_ldp_tlv_intparam_cepopt_e3;
static int hf_ldp_tlv_intparam_vlanid;
static int hf_ldp_tlv_intparam_dlcilen;
static int hf_ldp_tlv_intparam_fcslen;
static int hf_ldp_tlv_intparam_tdmopt_r;
static int hf_ldp_tlv_intparam_tdmopt_d;
static int hf_ldp_tlv_intparam_tdmopt_f;
static int hf_ldp_tlv_intparam_tdmopt_res1;
static int hf_ldp_tlv_intparam_tdmopt_pt;
static int hf_ldp_tlv_intparam_tdmopt_res2;
static int hf_ldp_tlv_intparam_tdmopt_freq;
static int hf_ldp_tlv_intparam_tdmopt_ssrc;
static int hf_ldp_tlv_intparam_vccv_cctype_cw;
static int hf_ldp_tlv_intparam_vccv_cctype_mplsra;
static int hf_ldp_tlv_intparam_vccv_cctype_ttl1;
static int hf_ldp_tlv_intparam_vccv_cvtype_icmpping;
static int hf_ldp_tlv_intparam_vccv_cvtype_lspping;
static int hf_ldp_tlv_intparam_vccv_cvtype_bfd;
static int hf_ldp_tlv_upstr_sbit;
static int hf_ldp_tlv_upstr_lbl_req_resvbit;
static int hf_ldp_tlv_upstr_ass_lbl;
static int hf_ldp_tlv_upstr_lbl_resvbit;
static int hf_ldp_tlv_ipv4_intID_hop_addr;
static int hf_ldp_tlv_logical_intID;
static int hf_ldp_tlv_ip_multicast_srcaddr;
static int hf_ldp_tlv_ip_multicast_mltcstaddr;
static int hf_ldp_tlv_ldp_p2mp_lsptype;
static int hf_ldp_tlv_ip_mpls_context_srcaddr;
static int hf_ldp_tlv_ldp_p2mp_addrfam;
static int hf_ldp_tlv_ldp_p2mp_addrlen;
static int hf_ldp_tlv_ldp_p2mp_rtnodeaddr;
static int hf_ldp_tlv_ldp_p2mp_oplength;
static int hf_ldp_tlv_ldp_p2mp_opvalue;
static int hf_ldp_tlv_rsvp_te_p2mp_id;
static int hf_ldp_tlv_must_be_zero;
static int hf_ldp_tlv_tunnel_id;
static int hf_ldp_tlv_ext_tunnel_id;
static int hf_ldp_tlv_inv_length;
static int hf_ldp_returned_pdu_data;
static int hf_ldp_returned_message_parameters;
static int hf_ldp_data;
static int hf_ldp_unknown_data;


static int ett_ldp;
static int ett_ldp_header;
static int ett_ldp_ldpid;
static int ett_ldp_message;
static int ett_ldp_tlv;
static int ett_ldp_tlv_val;
static int ett_ldp_tlv_ft_flags;
static int ett_ldp_fec;
static int ett_ldp_fec_vc_interfaceparam;
static int ett_ldp_fec_vc_interfaceparam_cepopt;
static int ett_ldp_fec_vc_interfaceparam_vccvtype;
static int ett_ldp_diffserv_map;
static int ett_ldp_diffserv_map_phbid;
static int ett_ldp_gen_agi;
static int ett_ldp_gen_saii;
static int ett_ldp_gen_taii;
static int ett_ldp_gen_aai_type2;
static int ett_ldp_sub_tlv;

static expert_field ei_ldp_dtsm_and_target;
static expert_field ei_ldp_gtsm_supported;
static expert_field ei_ldp_gtsm_not_supported_basic_discovery;
static expert_field ei_ldp_gtsm_not_supported;
static expert_field ei_ldp_inv_length;
static expert_field ei_ldp_tlv_fec_vc_infolength;
static expert_field ei_ldp_tlv_fec_type;
static expert_field ei_ldp_tlv_fec_len;
static expert_field ei_ldp_malformed_data;
static expert_field ei_ldp_address_family_not_implemented;
static expert_field ei_ldp_malformed_interface_parameter;
static expert_field ei_ldp_tlv_fec;

/* desegmentation of LDP over TCP */
static bool ldp_desegment = true;

/*
 * The following define all the TLV types I know about
 * http://www.iana.org/assignments/ldp-namespaces
 */
#define TLV_SEQUENCE_NUMBER                     0x0001  /* [RFC7769] */
#define TLV_FEC                                 0x0100  /* [RFC5036] */
#define TLV_ADDRESS_LIST                        0x0101  /* [RFC5036] */
#define TLV_HOP_COUNT                           0x0103  /* [RFC5036] */
#define TLV_PATH_VECTOR                         0x0104  /* [RFC5036] */
#define TLV_GENERIC_LABEL                       0x0200  /* [RFC5036] */
#define TLV_ATM_LABEL                           0x0201  /* [RFC5036] */
#define TLV_FRAME_RELAY_LABEL                   0x0202  /* [RFC5036] */
#define TLV_FT_PROTECTION                       0x0203  /* [RFC3479] */
#define TLV_LDP_UPSTREAM_ASSIGNED_LABEL         0x0204  /* [RFC6389] */
#define TLV_LDP_UPSTREAM_ASSIGNED_LABEL_REQUEST 0x0205  /* [RFC6389] */
#define TLV_ENTROPY_LABEL_CAPA                  0x0206  /* [RFC6790] */
#define TLV_STATUS                              0x0300  /* [RFC5036] */
#define TLV_EXTENDED_STATUS                     0x0301  /* [RFC5036] */
#define TLV_RETURNED_PDU                        0x0302  /* [RFC5036] */
#define TLV_RETURNED_MESSAGE                    0x0303  /* [RFC5036] */
#define TLV_RETURNED_TLVS                       0x0304  /* [RFC5561] */
#define TLV_COMMON_HELLO_PARAMS                 0x0400  /* [RFC5036] */
#define TLV_IPV4_TRANSPORT_ADDRESS              0x0401  /* [RFC5036] */
#define TLV_CONFIGURATION_SEQUENCE_NUMBER       0x0402  /* [RFC5036] */
#define TLV_IPV6_TRANSPORT_ADDRESS              0x0403  /* [RFC5036] */
#define TLV_MAC                                 0x0404  /* [RFC4762] */
#define TLV_CRYPTOGRAPHIC_AUTHENTICATION        0x0405  /* [RFC7349] */
#define TLV_MAC_FLUSH_PARAMS                    0x0406  /* [RFC7361] */
#define TLV_PBB_B_MAC_LIST_SUB                  0x0407  /* [RFC7361] */
#define TLV_PBB_I_SID_LIST_SUB                  0x0408  /* [RFC7361] */
#define TLV_COMMON_SESSION_PARAMS               0x0500  /* [RFC5036] */
#define TLV_ATM_SESSION_PARAMS                  0x0501  /* [RFC5036] */
#define TLV_FRAME_RELAY_SESSION_PARAMS          0x0502  /* [RFC5036] */
#define TLV_FT_SESSION                          0x0503  /* [RFC3479] */
#define TLV_FT_ACK                              0x0504  /* [RFC3479] */
#define TLV_FT_CORK                             0x0505  /* [RFC3479] */
#define TLV_DYNAMIC_CAPA_ANNOUNCEMENT           0x0506  /* [RFC5561] */
#define TLV_LDP_UPSTREAM_LABEL_ASSIGNMENT_CAPA  0x0507  /* [RFC6389] */
#define TLV_P2MP_CAPA_PARAM                     0x0508  /* [RFC6388] */
#define TLV_MP2MP_CAPA_PARAM                    0x0509  /* [RFC6388] */
#define TLV_MBB_CAPA_PARAM                      0x050A  /* [RFC6388] */
#define TLV_TYPED_WILDCARD_FEC_CAPA             0x050B  /* [RFC5918] */
#define TLV_MULTI_TOPOLOGY_CAPA                 0x050C  /* [RFC7307] */
#define TLV_STATE_ADVERTISEMENT_CONTROL_CAPA    0x050D  /* [RFC7473] */
#define TLV_MRT_CAPA                            0x050E  /* draft-iefp-mpls-ldp-mrt */
#define TLV_TARGETED_APPLICATION_CAPA           0x050F  /* [RFC8223] */
#define TLV_LABEL_REQUEST_MESSAGE_ID            0x0600  /* [RFC5036] */
#define TLV_MTU                                 0x0601  /* [RFC3988] */
#define TLV_UNRECOGNIZED_NOTIFICATION_CAPA      0x0603  /* [RFC5919] */
#define TLV_ICCP_CAPA                           0x0700  /* [RFC7275] */
#define TLV_DUAL_STACK_CAPA                     0x0701  /* [RFC7552] */
#define TLV_EXPLICIT_ROUTE                      0x0800  /* [RFC3212] */
#define TLV_IPV4_PREFIX_ER_HOP                  0x0801  /* [RFC3212] */
#define TLV_IPV6_PREFIX_ER_HOP                  0x0802  /* [RFC3212] */
#define TLV_AUTONOMOUS_SYSTEM_NUMBER_ER_HOP     0x0803  /* [RFC3212] */
#define TLV_LSP_ID_ER_HOP                       0x0804  /* [RFC3212] */
#define TLV_L2_PW_ADDRESS_OF_SWITCHING_POINT    0x0805  /* [RFC7392] */
#define TLV_TRAFFIC_PARAMS                      0x0810  /* [RFC3212] */
#define TLV_PREEMPTION                          0x0820  /* [RFC3212] */
#define TLV_LSPID                               0x0821  /* [RFC3212] */
#define TLV_RESOURCE_CLASS                      0x0822  /* [RFC3212] */
#define TLV_ROUTE_PINNING                       0x0823  /* [RFC3212] */
#define TLV_GENERALIZED_LABEL_REQUEST           0x0824  /* [RFC3472] */
#define TLV_GENERALIZED_LABEL                   0x0825  /* [RFC3472] */
#define TLV_UPSTREAM_LABEL                      0x0826  /* [RFC3472] */
#define TLV_LABEL_SET                           0x0827  /* [RFC3472] */
#define TLV_WAVEBAND_LABEL                      0x0828  /* [RFC3472] */
#define TLV_ER_HOP                              0x0829  /* [RFC3472] */
#define TLV_ACCEPTABLE_LABEL_SET                0x082A  /* [RFC3472] */
#define TLV_ADMIN_STATUS                        0x082B  /* [RFC3472] */
#define TLV_INTERFACE_ID                        0x082C  /* [RFC3472] */
#define TLV_IPV4_INTERFACE_ID                   0x082D  /* [RFC3472] */
#define TLV_IPV6_INTERFACE_ID                   0x082E  /* [RFC3472] */
#define TLV_IPV4_IF_ID_STATUS                   0x082F  /* [RFC3472] */
#define TLV_IPV6_IF_ID_STATUS                   0x0830  /* [RFC3472] */
#define TLV_OP_SP_CALL_ID                       0x0831  /* [RFC3475] */
#define TLV_GU_CALL_ID                          0x0832  /* [RFC3475] */
#define TLV_CALL_CAPA                           0x0833  /* [RFC3475] */
#define TLV_CRANKBACK                           0x0834  /* [RFC3475] */
#define TLV_PROTECTION                          0x0835  /* [RFC3472] */
#define TLV_LSP_TUNNEL_INTERFACE_ID             0x0836  /* [RFC3480] */
#define TLV_UNNUMBERED_INTERFACE_ID             0x0837  /* [RFC3480] */
#define TLV_SONET_SDH_TRAFFIC_PARAMS            0x0838  /* [RFC4606] */
#define TLV_DIFF_SERV                           0x0901  /* [RFC3270] */
#define TLV_HSMP_LSP_CAPA_PARAM                 0x0902  /* [RFC7140] */
#define TLV_IPV4_SOURCE_ID                      0x0960  /* [RFC3476] */
#define TLV_IPV6_SOURCE_ID                      0x0961  /* [RFC3476] */
#define TLV_NSAP_SOURCE_ID                      0x0962  /* [RFC3476] */
#define TLV_IPV4_DESTINATION_ID                 0x0963  /* [RFC3476] */
#define TLV_IPV6_DESTINATION_ID                 0x0964  /* [RFC3476] */
#define TLV_NSAP_DESTINATION_ID                 0x0965  /* [RFC3476] */
#define TLV_EGRESS_LABEL                        0x0966  /* [RFC3476] */
#define TLV_LOCAL_CONNECTION_ID                 0x0967  /* [RFC3476] */
#define TLV_DIVERSITY                           0x0968  /* [RFC3476] */
#define TLV_CONTRACT_ID                         0x0969  /* [RFC3476] */
#define TLV_PW_STATUS                           0x096A  /* [RFC8077] */
#define TLV_PW_INTERFACE_PARAMS                 0x096B  /* [RFC8077] */
#define TLV_PW_GROUP_ID                         0x096C  /* [RFC8077] */
#define TLV_PSEUDOWIRE_SWITCHING_POINT_PE       0x096D  /* [RFC6073] */
#define TLV_BANDWIDTH                           0x096E  /* [RFC7267] */
#define TLV_LDP_MP_STATUS_TLV_TYPE              0x096F  /* [RFC6388] */
#define TLV_UNI_SERVICE_LEVEL                   0x0970  /* [RFC3476] */
#define TLV_QUEUE_REQUEST                       0x0971  /* [RFC7032] */
#define TLV_MP_NODE_PROTECTION_CAPA             0x0972  /* [RFC7715] */
#define TLV_PSN_TUNNEL_BINDING                  0x0973  /* [RFC7965] */
#define TLV_EGRESS_PROTECTION_CAPA              0x0974  /* [RFC8104] */

/* Not in IANA list */
#define TLV_RSVP_TE_P2MP_LSP         0x001C
#define TLV_LDP_P2MP_LSP             0x001D
#define TLV_IP_MULTICAST_TUNNEL      0x001E
#define TLV_MPLS_CONTEXT_LBL         0x001F
#define TLV_VENDOR_PRIVATE_START     0x3E00
#define TLV_VENDOR_PRIVATE_END       0x3EFF
#define TLV_EXPERIMENTAL_START       0x3F00
#define TLV_EXPERIMENTAL_END         0x3FFF

static const value_string tlv_type_names[] = {
    { TLV_SEQUENCE_NUMBER,                     "Sequence Number TLV"                    },
    { TLV_FEC,                                 "FEC"                                    },
    { TLV_ADDRESS_LIST,                        "Address List"                           },
    { TLV_HOP_COUNT,                           "Hop Count"                              },
    { TLV_PATH_VECTOR,                         "Path Vector"                            },
    { TLV_GENERIC_LABEL,                       "Generic Label"                          },
    { TLV_ATM_LABEL,                           "ATM Label"                              },
    { TLV_FRAME_RELAY_LABEL,                   "Frame Relay Label"                      },
    { TLV_FT_PROTECTION,                       "FT Protection TLV"                      },
    { TLV_LDP_UPSTREAM_ASSIGNED_LABEL,         "LDP Upstream-Assigned Label TLV"        },
    { TLV_LDP_UPSTREAM_ASSIGNED_LABEL_REQUEST, "LDP Upstream-Assigned Label Request TLV" },
    { TLV_ENTROPY_LABEL_CAPA,                  "Entropy Label Capability TLV"           },
    { TLV_STATUS,                              "Status"                                 },
    { TLV_EXTENDED_STATUS,                     "Extended Status"                        },
    { TLV_RETURNED_PDU,                        "Returned PDU"                           },
    { TLV_RETURNED_MESSAGE,                    "Returned Message"                       },
    { TLV_RETURNED_TLVS,                       "Returned TLVs"                          },
    { TLV_COMMON_HELLO_PARAMS,                 "Common Hello Parameters"                },
    { TLV_IPV4_TRANSPORT_ADDRESS,              "IPv4 Transport Address"                 },
    { TLV_CONFIGURATION_SEQUENCE_NUMBER,       "Configuration Sequence Number"          },
    { TLV_IPV6_TRANSPORT_ADDRESS,              "IPv6 Transport Address"                 },
    { TLV_MAC,                                 "MAC TLV"                                },
    { TLV_CRYPTOGRAPHIC_AUTHENTICATION,        "Cryptographic Authentication TLV"       },
    { TLV_MAC_FLUSH_PARAMS,                    "MAC Flush Parameters TLV"               },
    { TLV_PBB_B_MAC_LIST_SUB,                  "PBB B-MAC List Sub-TLV"                 },
    { TLV_PBB_I_SID_LIST_SUB,                  "PBB I-SID List Sub-TLV"                 },
    { TLV_COMMON_SESSION_PARAMS,               "Common Session Parameters"              },
    { TLV_ATM_SESSION_PARAMS,                  "ATM Session Parameters"                 },
    { TLV_FRAME_RELAY_SESSION_PARAMS,          "Frame Relay Session Parameters"         },
    { TLV_FT_SESSION,                          "FT Session TLV"                         },
    { TLV_FT_ACK,                              "FT Ack TLV"                             },
    { TLV_FT_CORK,                             "FT Cork TLV"                            },
    { TLV_DYNAMIC_CAPA_ANNOUNCEMENT,           "Dynamic Capability Announcement"        },
    { TLV_LDP_UPSTREAM_LABEL_ASSIGNMENT_CAPA,  "LDP Upstream Label Assignment Capability TLV" },
    { TLV_P2MP_CAPA_PARAM,                     "P2MP Capability Parameter"              },
    { TLV_MP2MP_CAPA_PARAM,                    "MP2MP Capability Parameter"             },
    { TLV_MBB_CAPA_PARAM,                      "MBB Capability Parameter"               },
    { TLV_TYPED_WILDCARD_FEC_CAPA,             "Typed Wildcard FEC Capability"          },
    { TLV_MULTI_TOPOLOGY_CAPA,                 "Multi-Topology Capability"              },
    { TLV_STATE_ADVERTISEMENT_CONTROL_CAPA,    "State Advertisement Control Capability" },
    { TLV_TARGETED_APPLICATION_CAPA,           "Targeted Application Capability"        },
    { TLV_LABEL_REQUEST_MESSAGE_ID,            "Label Request Message ID"               },
    { TLV_MTU,                                 "MTU TLV"                                },
    { TLV_UNRECOGNIZED_NOTIFICATION_CAPA,      "Unrecognized Notification Capability"   },
    { TLV_ICCP_CAPA,                           "ICCP capability TLV"                    },
    { TLV_DUAL_STACK_CAPA,                     "Dual-Stack capability"                  },
    { TLV_EXPLICIT_ROUTE,                      "Explicit Route TLV"                     },
    { TLV_IPV4_PREFIX_ER_HOP,                  "Ipv4 Prefix ER-Hop TLV"                 },
    { TLV_IPV6_PREFIX_ER_HOP,                  "Ipv6 Prefix ER-Hop TLV"                 },
    { TLV_AUTONOMOUS_SYSTEM_NUMBER_ER_HOP,     "Autonomous System Number ER-Hop TLV"    },
    { TLV_LSP_ID_ER_HOP,                       "LSP-ID ER-HOP TLV"                      },
    { TLV_L2_PW_ADDRESS_OF_SWITCHING_POINT,    "L2 PW Address of Switching Point"       },
    { TLV_TRAFFIC_PARAMS,                      "Traffic Parameters TLV"                 },
    { TLV_PREEMPTION,                          "Preemption TLV"                         },
    { TLV_LSPID,                               "LSPID TLV"                              },
    { TLV_RESOURCE_CLASS,                      "Resource Class TLV"                     },
    { TLV_ROUTE_PINNING,                       "Route Pinning TLV"                      },
    { TLV_GENERALIZED_LABEL_REQUEST,           "Generalized Label Request TLV"          },
    { TLV_GENERALIZED_LABEL,                   "Generalized Label TLV"                  },
    { TLV_UPSTREAM_LABEL,                      "Upstream Label TLV"                     },
    { TLV_LABEL_SET,                           "Label Set TLV"                          },
    { TLV_WAVEBAND_LABEL,                      "Waveband Label TLV"                     },
    { TLV_ER_HOP,                              "ER-Hop TLV"                             },
    { TLV_ACCEPTABLE_LABEL_SET,                "Acceptable Label Set TLV"               },
    { TLV_ADMIN_STATUS,                        "Admin Status TLV"                       },
    { TLV_INTERFACE_ID,                        "Interface ID TLV"                       },
    { TLV_IPV4_INTERFACE_ID,                   "IPV4 Interface ID TLV"                  },
    { TLV_IPV6_INTERFACE_ID,                   "IPV6 Interface ID TLV"                  },
    { TLV_IPV4_IF_ID_STATUS,                   "IPv4 IF_ID Status TLV"                  },
    { TLV_IPV6_IF_ID_STATUS,                   "IPv6 IF_ID Status TLV"                  },
    { TLV_OP_SP_CALL_ID,                       "Op-Sp Call ID TLV"                      },
    { TLV_GU_CALL_ID,                          "GU Call ID TLV"                         },
    { TLV_CALL_CAPA,                           "Call Capability TLV"                    },
    { TLV_CRANKBACK,                           "Crankback TLV"                          },
    { TLV_PROTECTION,                          "Protection TLV"                         },
    { TLV_LSP_TUNNEL_INTERFACE_ID,             "LSP_TUNNEL_INTERFACE_ID TLV"            },
    { TLV_UNNUMBERED_INTERFACE_ID,             "Unnumbered Interface ID TLV"            },
    { TLV_SONET_SDH_TRAFFIC_PARAMS,            "SONET/SDH Traffic Parameters TLV"       },
    { TLV_DIFF_SERV,                           "Diff-Serv TLV"                          },
    { TLV_HSMP_LSP_CAPA_PARAM,                 "HSMP LSP Capability Parameter"          },
    { TLV_IPV4_SOURCE_ID,                      "IPv4 Source ID TLV"                     },
    { TLV_IPV6_SOURCE_ID,                      "IPv6 Source ID TLV"                     },
    { TLV_NSAP_SOURCE_ID,                      "NSAP Source ID TLV"                     },
    { TLV_IPV4_DESTINATION_ID,                 "IPv4 Destination ID TLV"                },
    { TLV_IPV6_DESTINATION_ID,                 "IPv6 Destination ID TLV"                },
    { TLV_NSAP_DESTINATION_ID,                 "NSAP Destination ID TLV"                },
    { TLV_EGRESS_LABEL,                        "Egress Label TLV"                       },
    { TLV_LOCAL_CONNECTION_ID,                 "Local Connection ID TLV"                },
    { TLV_DIVERSITY,                           "Diversity TLV"                          },
    { TLV_CONTRACT_ID,                         "Contract ID TLV"                        },
    { TLV_PW_STATUS,                           "PW Status TLV"                          },
    { TLV_PW_INTERFACE_PARAMS,                 "PW Interface Parameters TLV"            },
    { TLV_PW_GROUP_ID,                         "PW Group ID TLV"                        },
    { TLV_PSEUDOWIRE_SWITCHING_POINT_PE,       "Pseudowire Switching Point PE TLV"      },
    { TLV_BANDWIDTH,                           "Bandwidth TLV"                          },
    { TLV_LDP_MP_STATUS_TLV_TYPE,              "LDP MP Status TLV Type"                 },
    { TLV_UNI_SERVICE_LEVEL,                   "UNI Service Level TLV"                  },
    { TLV_QUEUE_REQUEST,                       "Queue Request TLV"                      },
    { TLV_MP_NODE_PROTECTION_CAPA,             "MP Node Protection Capability"          },
    { TLV_PSN_TUNNEL_BINDING,                  "PSN Tunnel Binding TLV"                 },
    { TLV_EGRESS_PROTECTION_CAPA,              "Egress Protection Capability"           },

    { TLV_RSVP_TE_P2MP_LSP,                    "RSVP-TE P2MP LSP TLV"                   },
    { TLV_LDP_P2MP_LSP,                        "LDP P2MP LSP TLV"                       },
    { TLV_IP_MULTICAST_TUNNEL,                 "IP Multicast Tunnel TLV"                },

    { 0, NULL}
};

/*
 * https://www.iana.org/assignments/ldp-namespaces
 */

#define LDP_NOTIFICATION                0x0001  /* [RFC5036] */
#define LDP_HELLO                       0x0100  /* [RFC5036] */
#define LDP_INITIALIZATION              0x0200  /* [RFC5036] */
#define LDP_KEEPALIVE                   0x0201  /* [RFC5036] */
#define LDP_CAPABILITY                  0x0202  /* [RFC5561] */
#define LDP_ADDRESS                     0x0300  /* [RFC5036] */
#define LDP_ADDRESS_WITHDRAWAL          0x0301  /* [RFC5036] */
#define LDP_LABEL_MAPPING               0x0400  /* [RFC5036] */
#define LDP_LABEL_REQUEST               0x0401  /* [RFC5036] */
#define LDP_LABEL_WITHDRAWAL            0x0402  /* [RFC5036] */
#define LDP_LABEL_RELEASE               0x0403  /* [RFC5036] */
#define LDP_LABEL_ABORT_REQUEST         0x0404  /* [RFC5036] */
#define LDP_CALL_SETUP                  0x0500  /* [RFC3475] */
#define LDP_CALL_RELEASE                0x0501  /* [RFC3475] */
#define LDP_RG_CONNECT_MESSAGE          0x0700  /* [RFC7275] */
#define LDP_RG_DISCONNECT_MESSAGE       0x0701  /* [RFC7275] */
#define LDP_RG_NOTIFICATION_MESSAGE     0x0702  /* [RFC7275] */
#define LDP_RG_APPLICATION_DATA_MESSAGE 0x0703  /* [RFC7275] */
#define LDP_VENDOR_PRIVATE_START        0x3E00
#define LDP_VENDOR_PRIVATE_END          0x3EFF
#define LDP_EXPERIMENTAL_MESSAGE_START  0x3F00
#define LDP_EXPERIMENTAL_MESSAGE_END    0x3FFF

static const value_string ldp_message_types[] = {
    {LDP_NOTIFICATION,                 "Notification Message"},
    {LDP_HELLO,                        "Hello Message"},
    {LDP_INITIALIZATION,               "Initialization Message"},
    {LDP_KEEPALIVE,                    "Keep Alive Message"},
    {LDP_CAPABILITY,                   "Capability Message"},
    {LDP_ADDRESS,                      "Address Message"},
    {LDP_ADDRESS_WITHDRAWAL,           "Address Withdrawal Message"},
    {LDP_LABEL_MAPPING,                "Label Mapping Message"},
    {LDP_LABEL_REQUEST,                "Label Request Message"},
    {LDP_LABEL_WITHDRAWAL,             "Label Withdrawal Message"},
    {LDP_LABEL_RELEASE,                "Label Release Message"},
    {LDP_LABEL_ABORT_REQUEST,          "Label Abort Request Message"},
    {LDP_CALL_SETUP,                   "Call Setup Message"},
    {LDP_CALL_RELEASE,                 "Call Release Message"},
    {LDP_RG_CONNECT_MESSAGE,           "RG Connect Message"},
    {LDP_RG_DISCONNECT_MESSAGE,        "RG Disconnect Message"},
    {LDP_RG_NOTIFICATION_MESSAGE,      "RG Notification Message"},
    {LDP_RG_APPLICATION_DATA_MESSAGE,  "RG Application Data Message"},
    {LDP_VENDOR_PRIVATE_START,         "Vendor-Private Message"},
    {LDP_EXPERIMENTAL_MESSAGE_START,   "Experimental Message"},
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

#define WILDCARD_FEC                  0x01    /* [RFC5036][RFC7358] */
#define PREFIX_FEC                    0x02    /* [RFC5036][RFC7358] */
#define HOST_FEC                      0x03    /* "Unassigned" according to IANA */
#define CRLSP_FEC                     0x04    /* [RFC3212][RFC7358] */
#define TYPED_WILDCARD_FEC            0x05    /* [RFC5918][RFC7358] */
#define P2MP_FEC                      0x06    /* [RFC6388][RFC7358] */
#define MP2MP_FEC_UP                  0x07    /* [RFC6388][RFC7358] */
#define MP2MP_FEC_DOWN                0x08    /* [RFC6388][RFC7358] */
#define HSMP_UPSTREAM                 0x09    /* [RFC7140][RFC7358] */
#define HSMP_DOWNSTREAM               0x0A    /* [RFC7140][RFC7358] */
#define PWID_FEC_ELEMENT              0x80    /* [RFC8077][RFC7358] */
#define GENERALIZED_PWID_FEC          0x81    /* [RFC8077][RFC7358] */
#define P2MP_PW_UPSTREAM_FEC          0x82    /* [draft-ietf-pwe3-p2mp-pw][RFC7358] */
#define PROTECTION_FEC                0x83    /* [RFC8104][RFC7358] */
#define P2MP_PW_DOWNSTREAM_FEC        0x84    /* [draft-ietf-pwe3-p2mp-pw][RFC7358] */

const value_string fec_types_vals[] = {
  {WILDCARD_FEC,                      "Wildcard FEC"},
  {PREFIX_FEC,                        "Prefix FEC"},
  {HOST_FEC,                          "Host Address FEC"},
  {CRLSP_FEC,                         "CR LSP FEC"},
  {TYPED_WILDCARD_FEC,                "Typed Wildcard FEC Element"},
  {P2MP_FEC,                          "P2MP"},
  {MP2MP_FEC_UP,                      "MP2MP-up"},
  {MP2MP_FEC_DOWN,                    "MP2MP-down"},
  {HSMP_UPSTREAM,                     "HSMP-upstream"},
  {HSMP_DOWNSTREAM,                   "HSMP-downstream"},
  {PWID_FEC_ELEMENT,                  "PWid FEC Element"},
  {GENERALIZED_PWID_FEC,              "Generalized PWid FEC Element"},
  {P2MP_PW_UPSTREAM_FEC,              "P2MP PW Upstream FEC Element"},
  {PROTECTION_FEC,                    "Protection FEC Element"},
  {P2MP_PW_DOWNSTREAM_FEC,            "P2MP_PW_DOWNSTREAM_FEC"},

  {0, NULL}
};


/*
 * MPLS Pseudowire Types
 *
 * RFC 4446
 *
 * http://www.iana.org/assignments/pwe3-parameters/pwe3-parameters.xhtml#pwe3-parameters-2
 */
const value_string fec_vc_types_vals[] = {
    {0x0001, "Frame Relay DLCI (Martini Mode)"},
    {0x0002, "ATM AAL5 SDU VCC transport"},
    {0x0003, "ATM transparent cell transport"},
    {0x0004, "Ethernet Tagged Mode"},
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
    {0x0016, "TDMoIP AAL1 Mode"},
    {0x0017, "CESoPSN TDM with CAS"},
    {0x0018, "TDMoIP AAL2 Mode"},
    {0x0019, "Frame Relay DLCI"},
    {0x001A, "ROHC Transport Header-compressed Packets"},
    {0x001B, "ECRTP Transport Header-compressed Packets"},
    {0x001C, "IPHC Transport Header-compressed Packets"},
    {0x001D, "cRTP Transport Header-compressed Packets"},
    {0x001E, "ATM VP Virtual Trunk"},
    {0x001F, "FC Port Mode"},

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
#define FEC_VC_INTERFACEPARAM_ROHCOMPLS    0x0D
#define FEC_VC_INTERFACEPARAM_TDMOIPAAL1C  0x0E
#define FEC_VC_INTERFACEPARAM_CEIOMPLS     0x0F
#define FEC_VC_INTERFACEPARAM_TDMOIPAAL1   0x10
#define FEC_VC_INTERFACEPARAM_TDMOIPAAL2   0x11
#define FEC_VC_INTERFACEPARAM_STACK        0x16
#define FEC_VC_INTERFACEPARAM_FLOWLABEL    0x17
#define FEC_VC_INTERFACEPARAM_PWGENFLAGS   0x18
#define FEC_VC_INTERFACEPARAM_VCCVEXTCV    0x19
#define FEC_VC_INTERFACEPARAM_ETREE        0x1A
#define FEC_VC_INTERFACEPARAM_ZTEPRIVATE   0xFD


static const value_string fec_vc_interfaceparm[] = {
  {FEC_VC_INTERFACEPARAM_MTU,           "Interface MTU"},
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
  {FEC_VC_INTERFACEPARAM_ROHCOMPLS,     "ROHC over MPLS configuration"},
  {FEC_VC_INTERFACEPARAM_TDMOIPAAL1C,   "TDMoIP AAL1 cells per packet"},
  {FEC_VC_INTERFACEPARAM_CEIOMPLS,      "CRTP/ECRTP/IPHC HC over MPLS configuration"},
  {FEC_VC_INTERFACEPARAM_TDMOIPAAL1,    "TDMoIP AAL1 mode"},
  {FEC_VC_INTERFACEPARAM_TDMOIPAAL2,    "TDMoIP AAL2 Options"},
  {FEC_VC_INTERFACEPARAM_STACK,         "Stack capability"},
  {FEC_VC_INTERFACEPARAM_FLOWLABEL,     "Flow Label"},
  {FEC_VC_INTERFACEPARAM_PWGENFLAGS,    "PW Generic Protocol Flags"},
  {FEC_VC_INTERFACEPARAM_VCCVEXTCV,     "VCCV Extended CV Parameter"},
  {FEC_VC_INTERFACEPARAM_ETREE,         "E-Tree"},
  {FEC_VC_INTERFACEPARAM_ZTEPRIVATE,    "Zte optional Supplier private interface parameters"},

  {0, NULL},
};

static const true_false_string fec_vc_cbit = {
    "Control Word Present",
    "Control Word NOT Present"
};

#if 0
static const true_false_string fec_vc_ = {
    "Control Word Present",
    "Control Word NOT Present"
};
#endif

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
    { 0x00000000, "Success"                                },
    { 0x00000001, "Bad LDP Identifier"                     },
    { 0x00000002, "Bad Protocol Version"                   },
    { 0x00000003, "Bad PDU Length"                         },
    { 0x00000004, "Unknown Message Type"                   },
    { 0x00000005, "Bad Message Length"                     },
    { 0x00000006, "Unknown TLV"                            },
    { 0x00000007, "Bad TLV Length"                         },
    { 0x00000008, "Malformed TLV Value"                    },
    { 0x00000009, "Hold Timer Expired"                     },
    { 0x0000000A, "Shutdown"                               },
    { 0x0000000B, "Loop Detected"                          },
    { 0x0000000C, "Unknown FEC"                            },
    { 0x0000000D, "No Route"                               },
    { 0x0000000E, "No Label Resources"                     },
    { 0x0000000F, "Label Resources/Available"              },
    { 0x00000010, "Session Rejected/No Hello"              },
    { 0x00000011, "Session Rejected/Parameters Advertisement Mode" },
    { 0x00000012, "Session Rejected/Parameters Max PDU Length" },
    { 0x00000013, "Session Rejected/Parameters Label Range" },
    { 0x00000014, "KeepAlive Timer Expired"                },
    { 0x00000015, "Label Request Aborted"                  },
    { 0x00000016, "Missing Message Parameters"             },
    { 0x00000017, "Unsupported Address Family"             },
    { 0x00000018, "Session Rejected/Bad KeepAlive Time"    },
    { 0x00000019, "Internal Error"                         },
    { 0x0000001A, "No LDP Session"                         },
    { 0x0000001B, "Zero FT seqnum"                         },
    { 0x0000001C, "Unexpected TLV / Session Not FT"        },
    { 0x0000001D, "Unexpected TLV / Label Not FT"          },
    { 0x0000001E, "Missing FT Protection TLV"              },
    { 0x0000001F, "FT ACK sequence error"                  },
    { 0x00000020, "Temporary Shutdown"                     },
    { 0x00000021, "FT Seq Numbers Exhausted"               },
    { 0x00000022, "FT Session parameters / changed"        },
    { 0x00000023, "Unexpected FT Cork TLV"                 },
    { 0x00000024, "Illegal C-Bit"                          },
    { 0x00000025, "Wrong C-Bit"                            },
    { 0x00000026, "Incompatible bit-rate"                  },
    { 0x00000027, "CEP-TDM mis-configuration"              },
    { 0x00000028, "PW Status"                              },
    { 0x0000002A, "Generic Misconfiguration Error"         },
    { 0x0000002B, "Label Withdraw PW Status Method Not Supported" },
    { 0x0000002C, "IP Address of CE"                       },
    { 0x0000002D, "Attachment Circuit bound to different remote Attachment Circuit" },
    { 0x0000002E, "Unsupported Capability"                 },
    { 0x0000002F, "End-of-LIB"                             },
    { 0x00000030, "Attachment Circuit bound to different PE" },
    { 0x00000031, "Invalid Topology ID"                    },
    { 0x00000032, "Transport Connection Mismatch"          },
    { 0x00000033, "Dual-Stack Noncompliance"               },
    { 0x00000034, "MRT Capability negotiated without MT Capability" },
    { 0x00000035, "VCCV Type Error"                        },
    { 0x00000037, "Bandwidth resources unavailable"        },
    { 0x00000038, "Resources Unavailable"                  },
    { 0x00000039, "AII Unreachable"                        },
    { 0x0000003A, "PW Loop Detected"                       },
    { 0x0000003B, "Reject - unable to use the suggested tunnel/LSPs" },
    { 0x0000003C, "The C-bit or S-bit unknown"             },
    { 0x00000040, "LDP MP status"                          },
    { 0x0000004A, "IP Address Type Mismatch"               },
    { 0x0000004B, "Wrong IP Address Type"                  },
    { 0x0000004C, "Session Rejected/Targeted Application Capability Mismatch" },
    { 0x00010001, "Unknown ICCP RG"                        },
    { 0x00010002, "ICCP Connection Count Exceeded"         },
    { 0x00010003, "ICCP Application Connection Count Exceeded" },
    { 0x00010004, "ICCP Application not in RG"             },
    { 0x00010005, "Incompatible ICCP Protocol Version"     },
    { 0x00010006, "ICCP Rejected Message"                  },
    { 0x00010007, "ICCP Administratively Disabled"         },
    { 0x00010010, "ICCP RG Removed"                        },
    { 0x00010011, "ICCP Application Removed from RG"       },
    { 0x01000001, "Unexpected Diff-Serv TLV"               },
    { 0x01000002, "Unsupported PHB"                        },
    { 0x01000003, "Invalid EXP<-->PHB mapping"             },
    { 0x01000004, "Unsupported PSC"                        },
    { 0x01000005, "Per-LSP context allocation failure"     },
    { 0x04000001, "Bad Explicit Routing TLV Error"         },
    { 0x04000002, "Bad Strict Node Error"                  },
    { 0x04000003, "Bad Loose Node Error"                   },
    { 0x04000004, "Bad Initial ER-Hop Error"               },
    { 0x04000005, "Resource Unavailable"                   },
    { 0x04000006, "Traffic Parameters Unavailable"         },
    { 0x04000007, "LSP Preempted"                          },
    { 0x04000008, "Modify Request Not Supported"           },
    { 0x04000009, "Invalid SNP ID"                         },
    { 0x0400000A, "Calling Party busy"                     },
    { 0x0400000B, "Unavailable SNP ID"                     },
    { 0x0400000C, "Invalid SNPP ID"                        },
    { 0x0400000D, "Unavailable SNPP ID"                    },
    { 0x0400000E, "Failed to create SNC"                   },
    { 0x0400000F, "Failed to establish LC"                 },
    { 0x04000010, "Invalid A End-User Name"                },
    { 0x04000011, "Invalid Z End-User Name"                },
    { 0x04000012, "Invalid CoS"                            },
    { 0x04000013, "Unavailable CoS"                        },
    { 0x04000014, "Invalid GoS"                            },
    { 0x04000015, "Unavailable GoS"                        },
    { 0x04000016, "Failed Security Check"                  },
    { 0x04000017, "TimeOut"                                },
    { 0x04000018, "Invalid Call Name"                      },
    { 0x04000019, "Failed to Release SNC"                  },
    { 0x0400001A, "Failed to Free LC"                      },
    { 0x20000000, "Unknown VPN ID"                         },
    { 0x20000001, "Illegal C-Bit"                          },
    { 0x20000002, "Wrong C-Bit"                            },
    { 0x20000003, "E-Tree VLAN mapping not supported"      },
    { 0x20000004, "Leaf-to-Leaf PW released"               },

    {0, NULL}
};

static const true_false_string tlv_upstr_sbit_vals = {
    "LSR is advertising the capability to distribute and receive upstream-assigned label bindings",
    "LSR is withdrawing the capability to distribute and receive upstream-assigned label bindings"
};

#define PW_NOT_FORWARDING               0x00000001
#define PW_LAC_INGRESS_RECV_FAULT       0x00000002
#define PW_LAC_EGRESS_TRANS_FAULT       0x00000004
#define PW_PSN_PW_INGRESS_RECV_FAULT    0x00000008
#define PW_PSN_PW_EGRESS_TRANS_FAULT    0x00000010

static void
dissect_subtlv_interface_parameters(tvbuff_t *tvb, unsigned offset, proto_tree *tree, int rem, int *interface_parameters_hf[]);

static void
dissect_genpwid_fec_aai_type2_parameter(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem);

/* Dissect FEC TLV */

static void
dissect_tlv_fec(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
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
        &hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd1,
        &hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd2,
        &hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd3,
        &hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd4,
        &hf_ldp_tlv_fec_vc_intparam_flowlabel_t,
        &hf_ldp_tlv_fec_vc_intparam_flowlabel_r,
        &hf_ldp_tlv_fec_vc_intparam_flowlabel_res,
    };

    proto_tree *ti, *ti2, *val_tree, *fec_tree=NULL;
    proto_tree *agi_tree=NULL, *saii_tree=NULL, *taii_tree=NULL;
    uint16_t    family, ix=1, ax;
    uint16_t    op_length = tvb_get_bits16(tvb, ((offset+8)*8), 16, ENC_BIG_ENDIAN);
    uint8_t     addr_size=0, *addr, implemented, prefix_len_octets, prefix_len, host_len, vc_len;
    uint8_t     intparam_len, aai_type = 0;
    uint32_t    pwid_len, agi_aii_len;
    const char *str;
    uint8_t gen_fec_id_len = 0;
    address_type addr_type;
    address      addr_str;

    val_tree=proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "FEC Elements");

    while (rem > 0){
        switch (tvb_get_uint8(tvb, offset)) {
        case WILDCARD_FEC:
        case CRLSP_FEC:
            fec_tree = proto_tree_add_subtree_format(val_tree, tvb, offset, 1,
                                        ett_ldp_fec, NULL, "FEC Element %u", ix);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_wc,tvb, offset, 1, ENC_BIG_ENDIAN);
            rem -= 1;
            offset += 1;
            break;

        case PREFIX_FEC:
            if ( rem < 4 ){/*not enough*/
                proto_tree_add_expert_format(val_tree, pinfo, &ei_ldp_tlv_fec, tvb, offset, rem, "Error in FEC Element %u", ix);
                return;
            }
            family=tvb_get_ntohs(tvb, offset+1);
            prefix_len=tvb_get_uint8(tvb, offset+3);
            prefix_len_octets=(prefix_len+7)/8;

            implemented=1;
            switch(family) {
            case AFNUM_INET: /*IPv4*/
                addr_size=4;
                addr_type = AT_IPv4;
                break;
            case AFNUM_INET6: /*IPv6*/
                addr_size=16;
                addr_type = AT_IPv6;
                break;
            default:
                implemented=0;
                break;
            }

            if ( !implemented ) {
                uint16_t noctets;

                noctets= rem>4+prefix_len_octets?4+prefix_len_octets:rem;
                proto_tree_add_expert(val_tree, pinfo, &ei_ldp_address_family_not_implemented, tvb, offset, noctets);
                offset+=noctets;
                rem-=noctets;
                break;
            }

            if ( rem < 4+MIN(addr_size, prefix_len_octets) ){
                proto_tree_add_expert_format(val_tree, pinfo, &ei_ldp_tlv_fec, tvb, offset, rem, "Error in FEC Element %u", ix);
                return;
            }

            /*Add a subtree for this*/
            fec_tree = proto_tree_add_subtree_format(val_tree, tvb, offset, 4+MIN(addr_size, prefix_len_octets),
                                            ett_ldp_fec, NULL, "FEC Element %u", ix);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_wc, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_af, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            ti = proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_len, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;


            if ( addr_size < prefix_len_octets) {
                offset+=addr_size;
                rem-=addr_size;
                expert_add_info_format(pinfo, ti, &ei_ldp_tlv_fec_len,
                                    "Invalid prefix %u length for family %s",
                                    prefix_len, val_to_str_const(family, afn_vals, "Unknown Family"));
                break;
            }

            addr=(uint8_t *)wmem_alloc0(pinfo->pool, addr_size);

            for(ax=0; ax+1 <= prefix_len_octets; ax++)
                addr[ax]=tvb_get_uint8(tvb, offset+ax);
            if ( prefix_len % 8 )
                addr[ax-1] = addr[ax-1]&(0xFF<<(8-prefix_len%8));

            set_address(&addr_str, addr_type, addr_size, addr);
            str = address_to_str(pinfo->pool, &addr_str);
            proto_tree_add_string_format(fec_tree, hf_ldp_tlv_fec_pfval, tvb, offset, prefix_len_octets,
                                         str, "Prefix: %s", str);

            offset += prefix_len_octets;
            rem -= 4+prefix_len_octets;
            break;

        case HOST_FEC:
            if ( rem < 4 ){/*not enough*/
                proto_tree_add_expert_format(val_tree, pinfo, &ei_ldp_tlv_fec, tvb, offset, rem, "Error in FEC Element %u", ix);
                return;
            }
            family=tvb_get_ntohs(tvb, offset+1);
            host_len=tvb_get_uint8(tvb, offset+3);

            implemented=1;
            switch(family) {
            case AFNUM_INET: /*IPv4*/
                addr_size=4;
                addr_type = AT_IPv4;
                break;
            case AFNUM_INET6: /*IPv6*/
                addr_size=16;
                addr_type = AT_IPv6;
                break;
            default:
                implemented=0;
                break;
            }

            if ( !implemented ) {
                uint16_t noctets;

                noctets= rem>4+host_len?4+host_len:rem;
                proto_tree_add_expert(val_tree, pinfo, &ei_ldp_address_family_not_implemented, tvb, offset, noctets);
                offset+=noctets;
                rem-=noctets;
                break;
            }

            if ( rem < 4+addr_size ){
                proto_tree_add_expert_format(val_tree, pinfo, &ei_ldp_tlv_fec, tvb, offset, rem, "Error in FEC Element %u", ix);
                return;
            }

            /*Add a subtree for this*/
            fec_tree = proto_tree_add_subtree_format(val_tree, tvb, offset, 4+addr_size, ett_ldp_fec, NULL, "FEC Element %u", ix);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_wc, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_af, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            ti = proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_len, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;


            if ( addr_size != host_len) {
                offset+=addr_size;
                rem-=addr_size;
                expert_add_info_format(pinfo, ti, &ei_ldp_tlv_fec_len,
                                    "Invalid address length %u length for family %s",
                                    host_len, val_to_str_const(family, afn_vals, "Unknown Family"));
                break;
            }

            addr=(uint8_t *)wmem_alloc0(pinfo->pool, addr_size);

            for(ax=0; ax+1 <= host_len; ax++)
                addr[ax]=tvb_get_uint8(tvb, offset+ax);

            set_address(&addr_str, addr_type, addr_size, addr);
            str = address_to_str(pinfo->pool, &addr_str);
            proto_tree_add_string_format(fec_tree, hf_ldp_tlv_fec_hoval, tvb, offset, host_len,
                                         str, "Address: %s", str);

            offset += host_len;
            rem -= 4+host_len;
            break;

        case TYPED_WILDCARD_FEC:
            if ( rem < 8 ){/*not enough bytes for a minimal TYPED_WILDCARD_FEC*/
                proto_tree_add_expert_format(val_tree, pinfo, &ei_ldp_tlv_fec, tvb, offset, rem, "Error in FEC Element %u", ix);
                return;
            }
            vc_len = tvb_get_uint8 (tvb, offset+3);


            fec_tree = proto_tree_add_subtree_format(val_tree, tvb, offset, 8+vc_len, ett_ldp_fec, &ti, "FEC Element %u", ix);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_wc, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_vc_controlword, tvb, offset+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_vc_vctype, tvb, offset+1, 2, ENC_BIG_ENDIAN);
            ti2 = proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_vc_infolength, tvb, offset+3,1,ENC_BIG_ENDIAN);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_vc_groupid,tvb, offset +4, 4, ENC_BIG_ENDIAN);
            rem -=8;
            offset +=8;

            if ( (vc_len > 3) && ( rem > 3 ) ) { /* there is enough room for vcid */
                proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_vc_vcid,tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_item_append_text (ti," VCID: %u",tvb_get_ntohl(tvb,offset));

            } else {
                expert_add_info(pinfo, ti2, &ei_ldp_tlv_fec_vc_infolength);
                return;
            }
            rem -= 4;
            vc_len -= 4;
            offset += 4;

            while ( (vc_len > 1) && (rem > 1) ) {   /* enough to include id and length */
                intparam_len = tvb_get_uint8(tvb, offset+1);
                if (intparam_len < 2){ /* At least Type and Len, protect against len = 0 */
                    proto_tree_add_expert(fec_tree, pinfo, &ei_ldp_malformed_interface_parameter, tvb, offset +1, 1);
                    return;
                }

                if ( (vc_len -intparam_len) <0 && (rem -intparam_len) <0 ) { /* error condition */
                    proto_tree_add_expert(fec_tree, pinfo, &ei_ldp_malformed_data, tvb, offset +2, MIN(vc_len,rem));
                    return;
                }
                dissect_subtlv_interface_parameters(tvb, offset, fec_tree, intparam_len, interface_params_header_fields);

                rem -= intparam_len;
                vc_len -= intparam_len;
                offset += intparam_len;
            }
            break;

        case P2MP_PW_UPSTREAM_FEC:
        {
            /* Ref: RFC 4447 */
            if ( rem < 4 ){/*not enough bytes for a minimal TYPED_WILDCARD_FEC*/
                proto_tree_add_expert_format(val_tree, pinfo, &ei_ldp_tlv_fec, tvb, offset, rem, "Error in FEC Element %u", ix);
                return;
            }
            vc_len = tvb_get_uint8 (tvb, offset+3);

            /* Add the FEC to the tree */
            fec_tree = proto_tree_add_subtree_format(val_tree, tvb, offset, 8+vc_len, ett_ldp_fec, NULL, "FEC Element %u", ix);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_wc, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_vc_controlword, tvb, offset+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_vc_vctype, tvb, offset+1, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_vc_infolength, tvb, offset+3,1,ENC_BIG_ENDIAN);
            rem -= 4;
            offset += 4;

            if ( (vc_len > 1) && ( rem > 1 ) ) { /* there is enough room for AGI */
                gen_fec_id_len = tvb_get_uint8 (tvb, offset+1);
                /* Add AGI to the tree */
                agi_tree = proto_tree_add_subtree_format(fec_tree, tvb, offset, 2 + gen_fec_id_len, ett_ldp_gen_agi, NULL, "AGI");
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
                proto_tree_add_expert_format(fec_tree, pinfo, &ei_ldp_tlv_fec_vc_infolength, tvb, offset, 2 +vc_len, "Generalized FEC: AGI size format error");
                return;
            }

            if ( (vc_len > 1) && ( rem > 1 ) ) { /* there is enough room for SAII */
                gen_fec_id_len = tvb_get_uint8 (tvb, offset+1);
                /* Add SAII to the tree */
                aai_type = tvb_get_uint8(tvb, offset);
                if ( aai_type == 2 && gen_fec_id_len != 12)
                {
                    /* According to RFC 5003, for Type 2 AAI, the length should be 12 bytes */
                    proto_tree_add_expert_format(fec_tree, pinfo, &ei_ldp_tlv_fec_vc_infolength, tvb, offset, 2 + gen_fec_id_len, "Generalized FEC: SAII size format error");
                }
                else
                {
                    saii_tree = proto_tree_add_subtree(fec_tree, tvb, offset, 2 + gen_fec_id_len, ett_ldp_gen_saii, NULL, "SAII");
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
                            dissect_genpwid_fec_aai_type2_parameter(tvb, pinfo, offset +2, saii_tree, gen_fec_id_len);
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
                proto_tree_add_expert_format(fec_tree, pinfo, &ei_ldp_tlv_fec_vc_infolength, tvb, offset, 2 + vc_len, "Generalized FEC: SAII size format error");
                return;
            }

            if ( (vc_len > 1) && ( rem > 1 ) ) { /* there is enough room for TAII */
                gen_fec_id_len = tvb_get_uint8 (tvb, offset+1);
                /* Add TAII to the tree */
                aai_type = tvb_get_uint8(tvb, offset);
                if ( aai_type == 2 && gen_fec_id_len != 12)
                {
                    /* According to RFC 5003, for Type 2 AAI, the length should be 12 bytes */
                    proto_tree_add_expert_format(fec_tree, pinfo, &ei_ldp_tlv_fec_vc_infolength, tvb, offset, 2 + gen_fec_id_len, "Generalized FEC: TAII size format error");
                }
                else
                {
                    taii_tree = proto_tree_add_subtree(fec_tree, tvb, offset, 2 + gen_fec_id_len, ett_ldp_gen_taii, NULL, "TAII");
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
                            dissect_genpwid_fec_aai_type2_parameter(tvb, pinfo, offset +2, taii_tree, gen_fec_id_len);
                        }
                        else
                        {
                            proto_tree_add_item(taii_tree, hf_ldp_tlv_fec_gen_taii_value, tvb, offset+2, gen_fec_id_len , ENC_NA);
                        }
                    }
                }
                rem -= 2 + gen_fec_id_len;
                /*vc_len -= 2 + gen_fec_id_len;*/
                offset += 2 + gen_fec_id_len;


            } else {
                proto_tree_add_expert_format(fec_tree, pinfo, &ei_ldp_tlv_fec_vc_infolength, tvb, offset, 2 +vc_len, "Generalized FEC: TAII size format error");
                return;
            }

            break;
        }
        case P2MP_FEC:
        case MP2MP_FEC_UP:
        case MP2MP_FEC_DOWN:
        case HSMP_UPSTREAM:
        case HSMP_DOWNSTREAM:
        {
            if (rem < 4 ){/*not enough*/
                proto_item* inv_length;
                inv_length = proto_tree_add_item(val_tree, hf_ldp_tlv_inv_length, tvb, offset, rem, ENC_BIG_ENDIAN);
                expert_add_info(pinfo, inv_length, &ei_ldp_inv_length);
                return;
            }

            fec_tree = proto_tree_add_subtree_format(val_tree, tvb, offset, 4+tvb_get_uint8 (tvb, offset+1),
                                                            ett_ldp_fec, NULL, "FEC Element %u", ix);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_wc, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_af, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_len, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(fec_tree, hf_ldp_tlv_ldp_p2mp_rtnodeaddr, tvb,offset, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_ldp_p2mp_oplength, tvb,offset + 4, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_ldp_p2mp_opvalue, tvb,offset + 6, op_length, ENC_NA);

            offset = offset + 6 + op_length;
            rem = rem - 10 - op_length;

            break;
        }

        case PWID_FEC_ELEMENT:
        {
            if (rem < 8 ){/*not enough*/
                proto_item* inv_length;
                inv_length = proto_tree_add_item(val_tree, hf_ldp_tlv_inv_length, tvb, offset, rem, ENC_BIG_ENDIAN);
                expert_add_info(pinfo, inv_length, &ei_ldp_inv_length);
                return;
            }

            fec_tree = proto_tree_add_subtree_format(val_tree, tvb, offset, 8+tvb_get_uint8 (tvb, offset+3),
                                                            ett_ldp_fec, NULL, "FEC Element %u", ix);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_wc, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_pw_controlword, tvb, offset+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_pw_pwtype, tvb, offset+1, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item_ret_uint(fec_tree, hf_ldp_tlv_fec_pw_infolength, tvb, offset+3,1,ENC_BIG_ENDIAN, &pwid_len);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_pw_groupid,tvb, offset +4, 4, ENC_BIG_ENDIAN);
            rem -=8;
            offset +=8;

            if ( (pwid_len > 3) && ( rem > 3 ) ) { /* there is enough room for pwid */
                proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_pw_pwid,tvb, offset, 4, ENC_BIG_ENDIAN);
                rem -=4;
                offset +=4;

            }

            while ( (pwid_len > 1) && (rem > 1) ) {   /* enough to include id and length */
                intparam_len = tvb_get_uint8(tvb, offset+1);
                if (intparam_len < 2){ /* At least Type and Len, protect against len = 0 */
                    proto_tree_add_expert(fec_tree, pinfo, &ei_ldp_malformed_interface_parameter, tvb, offset +1, 1);
                    return;
                }

                if ( ((uint32_t)intparam_len > pwid_len) && (rem -intparam_len) <0 ) { /* error condition */
                    proto_tree_add_expert(fec_tree, pinfo, &ei_ldp_malformed_data, tvb, offset +2, MIN(pwid_len,(uint32_t)rem));
                    return;
                }
                dissect_subtlv_interface_parameters(tvb, offset, fec_tree, intparam_len, interface_params_header_fields);

                rem -= intparam_len;
                pwid_len -= intparam_len;
                offset += intparam_len;
            }

            break;
        }

        case GENERALIZED_PWID_FEC:
        {
            if (rem < 4 ){/*not enough*/
                proto_item* inv_length;
                inv_length = proto_tree_add_item(val_tree, hf_ldp_tlv_inv_length, tvb, offset, rem, ENC_BIG_ENDIAN);
                expert_add_info(pinfo, inv_length, &ei_ldp_inv_length);
                return;
            }

            fec_tree = proto_tree_add_subtree_format(val_tree, tvb, offset, 4+tvb_get_uint8 (tvb, offset+3),
                                                            ett_ldp_fec, NULL, "FEC Element %u", ix);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_wc, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_pw_controlword, tvb, offset+1, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_pw_pwtype, tvb, offset+1, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item_ret_uint(fec_tree, hf_ldp_tlv_fec_pw_infolength, tvb, offset+3,1,ENC_BIG_ENDIAN, &pwid_len);
            rem -= 4;
            offset += 4;
            if ( (pwid_len > 5) && ( rem > 5 ) ) { /* there is enough room for AGI/AII data */
                proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_gen_agi_type,tvb, offset, 1, ENC_BIG_ENDIAN);
                rem -= 1;
                offset += 1;
                proto_tree_add_item_ret_uint(fec_tree, hf_ldp_tlv_fec_gen_agi_length, tvb, offset,1,ENC_BIG_ENDIAN, &agi_aii_len);
                rem -= 1;
                offset += 1;
                if ( agi_aii_len > 0)
                {
                    proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_gen_agi_value, tvb, offset, agi_aii_len , ENC_NA );
                    rem -= agi_aii_len;
                    offset += agi_aii_len;
                }
                proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_gen_saii_type,tvb, offset, 1, ENC_BIG_ENDIAN);
                rem -= 1;
                offset += 1;
                proto_tree_add_item_ret_uint(fec_tree, hf_ldp_tlv_fec_gen_saii_length, tvb, offset,1,ENC_BIG_ENDIAN, &agi_aii_len);
                rem -= 1;
                offset += 1;
                if ( agi_aii_len > 0)
                {
                    proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_gen_saii_value, tvb, offset, agi_aii_len , ENC_NA );
                    rem -= agi_aii_len;
                    offset += agi_aii_len;
                }
                proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_gen_taii_type,tvb, offset, 1, ENC_BIG_ENDIAN);
                rem -= 1;
                offset += 1;
                proto_tree_add_item_ret_uint(fec_tree, hf_ldp_tlv_fec_gen_taii_length, tvb, offset,1,ENC_BIG_ENDIAN, &agi_aii_len);
                rem -= 1;
                offset += 1;
                if ( agi_aii_len > 0)
                {
                    proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_gen_taii_value, tvb, offset, agi_aii_len , ENC_NA );
                    rem -= agi_aii_len;
                    offset += agi_aii_len;
                }
            }
            break;
        }

        default:  /* Unknown */
            /* XXX - do all FEC's have a length that's a multiple of 4? */
            /* Hmmm, don't think so. Will check. RJS. */
            /* If we don't know its structure, we have to exit */
            fec_tree = proto_tree_add_subtree_format(val_tree, tvb, offset, 4, ett_ldp_fec, NULL, "FEC Element %u", ix);
            proto_tree_add_expert(fec_tree, pinfo, &ei_ldp_tlv_fec_type, tvb, offset, rem);
            return;
        }
        ix++;
    }
}

/* Dissect Address List TLV */

static void
dissect_tlv_address_list(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;
    uint16_t    family, ix;
    uint8_t     addr_size, *addr;
    const char *str;
    address_type addr_type;
    address      addr_str;

    if ( rem < 2 ) {
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
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
        addr_type = AT_IPv4;
        break;
    case AFNUM_INET6: /*IPv6*/
        addr_size=16;
        addr_type = AT_IPv6;
        break;
    default:
        proto_tree_add_expert(tree, pinfo, &ei_ldp_address_family_not_implemented, tvb, offset+2, rem-2);
        return;
    }

    offset+=2; rem-=2;
    val_tree=proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "Addresses");

    addr=(uint8_t *)wmem_alloc(pinfo->pool, addr_size);

    for(ix=1; rem >= addr_size; ix++, offset += addr_size,
            rem -= addr_size) {
        if ( (tvb_memcpy(tvb, addr, offset, addr_size))
             == NULL)
            break;

        set_address(&addr_str, addr_type, addr_size, addr);
        str = address_to_str(pinfo->pool, &addr_str);
        proto_tree_add_string_format(val_tree,
                                     hf_ldp_tlv_addrl_addr, tvb, offset, addr_size, str,
                                     "Address %u: %s", ix, str);
    }
    if (rem)
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem, "Error processing TLV: Extra data at end of address list");
}

/* Dissect Path Vector TLV */

static void
dissect_tlv_path_vector(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;
    uint8_t     ix;
    uint32_t addr;

    val_tree=proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "LSR IDs");

    for(ix=1; rem >= 4; ix++, offset += 4, rem -= 4) {
        addr = tvb_get_ipv4(tvb, offset);
        proto_tree_add_ipv4_format(val_tree,
                                   hf_ldp_tlv_pv_lsrid, tvb, offset, 4,
                                   addr, "LSR Id %u: %s", ix,
                                   tvb_ip_to_str(pinfo->pool, tvb, offset));
    }
    if (rem)
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem, "Error processing TLV: Extra data at end of path vector");
}

/* Dissect ATM Label TLV */

static void
dissect_tlv_atm_label(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;

    if (rem != 4){
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem, "Error processing ATM Label TLV: length is %d, should be 4", rem);
        return;
    }
    val_tree=proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "ATM Label");

    proto_tree_add_item(val_tree, hf_ldp_tlv_atm_label_vbits, tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(val_tree, hf_ldp_tlv_atm_label_vpi, tvb, offset, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(val_tree, hf_ldp_tlv_atm_label_vci, tvb, offset+2, 2, ENC_BIG_ENDIAN);
}

/* Dissect FRAME RELAY Label TLV */

static void
dissect_tlv_frame_label(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;
    uint8_t     len;

    if (rem != 4){
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing Frame Relay Label TLV: length is %d, should be 4",
                            rem);
        return;
    }
    val_tree=proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "Frame Relay Label");

    len=(uint8_t)(tvb_get_ntohs(tvb, offset)>>7) & 0x03;
    proto_tree_add_uint_format_value(val_tree, hf_ldp_tlv_fr_label_len, tvb, offset, 2, len,
                               "%s (%u)", val_to_str_const(len, tlv_fr_len_vals, "Unknown Length"), len);

    proto_tree_add_item(val_tree,
                               hf_ldp_tlv_fr_label_dlci, tvb, offset+1, 3, ENC_BIG_ENDIAN);
}

/* Dissect STATUS TLV */

static void
dissect_tlv_status(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;
    uint32_t    data;

    if (rem != 10){
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing Status TLV: length is %d, should be 10",
                            rem);
        return;
    }

    val_tree=proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "Status");

    proto_tree_add_item(val_tree, hf_ldp_tlv_status_ebit, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(val_tree, hf_ldp_tlv_status_fbit, tvb, offset, 1, ENC_BIG_ENDIAN);

    data=tvb_get_ntohl(tvb, offset)&0x3FFFFFFF;
    proto_tree_add_uint_format_value(val_tree, hf_ldp_tlv_status_data, tvb, offset, 4,
                               data, "%s (0x%X)", val_to_str_const(data, tlv_status_data, "Unknown Status Data"), data);

    proto_tree_add_item(val_tree, hf_ldp_tlv_status_msg_id, tvb, offset+4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(val_tree, hf_ldp_tlv_status_msg_type, tvb, offset+8, 2, ENC_BIG_ENDIAN);
}

/* Dissect Returned PDU TLV */

static void
dissect_tlv_returned_pdu(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;

    if (rem < 10){
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing Returned PDU TLV: length is %d, should be >= 10",
                            rem);
        return;
    }
    val_tree=proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "Returned PDU");

    proto_tree_add_item(val_tree, hf_ldp_tlv_returned_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(val_tree, hf_ldp_tlv_returned_pdu_len, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(val_tree, hf_ldp_tlv_returned_lsr, tvb, offset+4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(val_tree, hf_ldp_tlv_returned_ls_id, tvb, offset+8, 2, ENC_BIG_ENDIAN);
    offset += 10;
    rem -= 10;

    if ( rem > 0 ) {
        /*XXX - dissect returned pdu data*/
        proto_tree_add_item(val_tree, hf_ldp_returned_pdu_data, tvb, offset, rem, ENC_NA);
    }
}

/* Dissect Returned MESSAGE TLV */

static void
dissect_tlv_returned_message(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;
    uint16_t    type;

    if (rem < 4) {
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing Returned Message TLV: length is %d, should be >= 4",
                            rem);
        return;
    }
    val_tree=proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "Returned Message");

    proto_tree_add_item(val_tree, hf_ldp_tlv_returned_msg_ubit, tvb, offset, 1, ENC_BIG_ENDIAN);

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
                                   type, "Message Type: %s (0x%X)", val_to_str_const(type, ldp_message_types,"Unknown Message Type"), type);
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
        proto_tree_add_item(val_tree, hf_ldp_returned_message_parameters, tvb, offset, rem, ENC_NA);
    }
}

/* Dissect the common hello params */

static void
#if 0
dissect_tlv_common_hello_parms(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
#else
dissect_tlv_common_hello_parms(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree)
#endif
{
#if 0
    proto_tree *ti;
#endif
    proto_tree *val_tree;
    proto_item *gtsm_flag_item;
    uint16_t gtsm_flag_buffer;
#if 0
    ti = proto_tree_add_item(tree, hf_ldp_tlv_value, tvb, offset, rem, ENC_NA);
    val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);
#else
    val_tree=tree;
#endif
    proto_tree_add_item(val_tree, hf_ldp_tlv_val_hold, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(val_tree, hf_ldp_tlv_val_target, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(val_tree, hf_ldp_tlv_val_request, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
    gtsm_flag_item = proto_tree_add_item(val_tree, hf_ldp_tlv_val_gtsm_flag, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    gtsm_flag_buffer = tvb_get_bits16(tvb, ((offset+2)*8), 16, ENC_BIG_ENDIAN);

    if ( gtsm_flag_buffer & 0x2000 ) {
        if ( gtsm_flag_buffer & 0x8000 ) {
            expert_add_info(pinfo, gtsm_flag_item, &ei_ldp_dtsm_and_target);
        } else {
            expert_add_info(pinfo, gtsm_flag_item, &ei_ldp_gtsm_supported);
        }
    } else {
        if ( gtsm_flag_buffer & 0x8000 ) {
                expert_add_info(pinfo, gtsm_flag_item, &ei_ldp_gtsm_not_supported_basic_discovery);
        } else {
                expert_add_info(pinfo, gtsm_flag_item, &ei_ldp_gtsm_not_supported);
        }
    }

    proto_tree_add_item(val_tree, hf_ldp_tlv_val_res, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
}

/* Dissect MAC TLV */

static void
dissect_tlv_mac(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree   *val_tree;

    val_tree=proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "MAC addresses");

    for(; rem >= 6; offset += 6, rem -= 6) {
        proto_tree_add_item(val_tree, hf_ldp_tlv_mac, tvb, offset, 6, ENC_NA);
    }
    if (rem)
        proto_tree_add_expert_format(val_tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem, "Error processing TLV: Extra data at end of path vector");
}



/* Dissect the common session params */

static void
dissect_tlv_common_session_parms(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;

    if ( rem != 14) { /*length of Comm Sess Parms tlv*/
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem, "Error processing Common Session Parameters TLV: length is %d, should be 14", rem);
        return;
    }
    val_tree=proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "Parameters");

    /*Protocol Version*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_ver, tvb,offset, 2, ENC_BIG_ENDIAN);

    /*KeepAlive Time*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_ka, tvb,offset + 2, 2, ENC_BIG_ENDIAN);

    /*A bit*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_advbit,tvb, offset + 4, 1, ENC_BIG_ENDIAN);

    /*D bit*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_ldetbit,tvb, offset + 4, 1, ENC_BIG_ENDIAN);

    /*Path Vector Limit*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_pvlim,tvb, offset + 5, 1, ENC_BIG_ENDIAN);

    /*Max PDU Length*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_mxpdu,tvb, offset + 6, 2, ENC_BIG_ENDIAN);

    /*Rx LSR*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_rxlsr,tvb, offset + 8, 4, ENC_BIG_ENDIAN);

    /*Rx LS*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_rxls,tvb, offset + 12, 2, ENC_BIG_ENDIAN);
}

/* Dissect the atm session params */

static void
dissect_tlv_atm_session_parms(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree, *lbl_tree;
    uint8_t     numlr, ix;

    if (rem < 4) {
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing ATM Parameters TLV: length is %d, should be >= 4",
                            rem);
        return;
    }

    val_tree=proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "ATM Parameters");

    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_atm_merge,tvb, offset, 1, ENC_BIG_ENDIAN);

    /*get the number of label ranges*/
    numlr=(tvb_get_uint8(tvb, offset)>>2) & 0x0F;
    proto_tree_add_uint_format(val_tree, hf_ldp_tlv_sess_atm_lr,
                               tvb, offset, 1, numlr, "Number of Label Range components: %u",
                               numlr);

    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_atm_dir,tvb, offset, 1, ENC_BIG_ENDIAN);

    /*move into range components*/
    offset += 4;
    rem    -= 4;
    val_tree=proto_tree_add_subtree(val_tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "ATM Label Range Components");

    /*now dissect ranges*/
    for(ix=1; numlr > 0 && rem >= 8; ix++, rem-=8, numlr--) {
        lbl_tree=proto_tree_add_subtree_format(val_tree, tvb, offset, 8,
                               ett_ldp_tlv_val, NULL, "ATM Label Range Component %u", ix);

        proto_tree_add_item(lbl_tree,
                                   hf_ldp_tlv_sess_atm_minvpi,
                                   tvb, offset, 2,
                                   ENC_BIG_ENDIAN);
        proto_tree_add_item(lbl_tree,
                                   hf_ldp_tlv_sess_atm_maxvpi,
                                   tvb, (offset+4), 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(lbl_tree,
                                   hf_ldp_tlv_sess_atm_minvci,
                                   tvb, offset+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(lbl_tree,
                                   hf_ldp_tlv_sess_atm_maxvci,
                                   tvb, offset+6, 2, ENC_BIG_ENDIAN);

        offset += 8;
    }
    if( rem || numlr)
        proto_tree_add_expert_format(val_tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing TLV: Extra data at end of TLV");
}

/* Dissect the frame relay session params */

static void
dissect_tlv_frame_relay_session_parms(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree, *lbl_tree;
    uint8_t     numlr, ix, len;

    if(rem < 4) {
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing Frame Relay Parameters TLV: length is %d, should be >= 4",
                            rem);
        return;
    }

    val_tree=proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "Frame Relay Parameters");

    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_fr_merge,
                        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*get the number of label ranges*/
    numlr=(tvb_get_uint8(tvb, offset)>>2) & 0x0F;
    proto_tree_add_uint_format(val_tree, hf_ldp_tlv_sess_fr_lr,
                               tvb, offset, 1, numlr, "Number of Label Range components: %u",
                               numlr);

    proto_tree_add_item(val_tree, hf_ldp_tlv_sess_fr_dir,
                        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*move into range components*/
    offset += 4;
    rem    -= 4;
    val_tree=proto_tree_add_subtree(val_tree, tvb, offset, rem, ett_ldp_tlv_val, NULL,
                             "Frame Relay Label Range Components");

    /*now dissect ranges*/
    for(ix=1; numlr > 0 && rem >= 8; ix++, rem-=8, numlr--) {
        lbl_tree=proto_tree_add_subtree_format(val_tree, tvb, offset, 8,
                               ett_ldp_tlv_val, NULL, "Frame Relay Label Range Component %u", ix);

        len=(uint8_t)(tvb_get_ntohs(tvb, offset)>>7) & 0x03;
        proto_tree_add_uint_format_value(lbl_tree, hf_ldp_tlv_sess_fr_len, tvb, offset, 2, len,
                                   "%s (%u)", val_to_str_const(len, tlv_fr_len_vals, "Unknown Length"), len);

        proto_tree_add_item(lbl_tree, hf_ldp_tlv_sess_fr_mindlci, tvb, offset+1, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(lbl_tree, hf_ldp_tlv_sess_fr_maxdlci, tvb, offset+5, 3, ENC_BIG_ENDIAN);

        offset += 8;
    }

    if( rem || numlr)
        proto_tree_add_expert_format(val_tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing TLV: Extra data at end of TLV");
}

/* Dissect the Fault Tolerant (FT) Session TLV */

static void
dissect_tlv_ft_session(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree, *flags_tree;
    uint16_t flags;

    if(rem != 12){
        /* error, length must be 12 bytes */
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing FT Session TLV: length is %d, should be 12",
                            rem);
        return;
    }

    val_tree=proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "FT Session Parameters");

    /* Flags */
    ti = proto_tree_add_item(val_tree, hf_ldp_tlv_ft_sess_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
    flags_tree = proto_item_add_subtree(ti,  ett_ldp_tlv_ft_flags);

    flags = tvb_get_ntohs(tvb, offset);
    proto_item_append_text(ti, " (%s%s)", (flags & 0x8000) ? "R, " : "",
                           val_to_str_const(flags & 0xF, tlv_ft_flags, "Invalid"));
    proto_tree_add_item(flags_tree, hf_ldp_tlv_ft_sess_flag_r, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_ldp_tlv_ft_sess_flag_res, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_ldp_tlv_ft_sess_flag_s, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_ldp_tlv_ft_sess_flag_a, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_ldp_tlv_ft_sess_flag_c, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_ldp_tlv_ft_sess_flag_l, tvb, offset, 2, ENC_BIG_ENDIAN);

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
dissect_tlv_lspid(tvbuff_t *tvb, packet_info *pinfo, unsigned offset,proto_tree *tree, int rem)
{
    proto_tree *val_tree;

    if(rem != 8) {
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing LSP ID TLV: length is %d, should be 8",
                            rem);
        return;
    }

    val_tree=proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "LSP ID");

    proto_tree_add_item(val_tree, hf_ldp_tlv_lspid_act_flg,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(val_tree, hf_ldp_tlv_lspid_cr_lsp,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(val_tree, hf_ldp_tlv_lspid_ldpid,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void
dissect_tlv_er_hop_ipv4(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;

    if(rem != 8) {
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing ER HOP IPv4 TLV: length is %d, should be 8",
                            rem);
        return;
    }
    val_tree=proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "ER HOP IPv4");

    if(val_tree != NULL) {
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_loose,
                            tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_prelen,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset ++;
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_prefix4,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
    }
}

static void
dissect_tlv_er_hop_ipv6(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;

    if(rem != 20) {
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing ER HOP IPv6 TLV: length is %d, should be 20",
                            rem);
        return;
    }
    val_tree = proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "ER HOP IPv6");

    if(val_tree != NULL) {
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_loose,
                            tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_prelen,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset ++;
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_prefix6,
                            tvb, offset, 16, ENC_NA);
    }
}

static void
dissect_tlv_er_hop_as(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;

    if(rem != 4) {
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing ER HOP AS TLV: length is %d, should be 4",
                            rem);
        return;
    }
    val_tree = proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "ER HOP AS");

    if(val_tree != NULL) {
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_loose,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_as,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
    }
}

static void
dissect_tlv_er_hop_lspid(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;

    if(rem != 8) {
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing ER HOP LSPID TLV: length is %d, should be 8",
                            rem);
        return;
    }
    val_tree = proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "ER HOP LSPID");

    if(val_tree != NULL) {
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_loose,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_cr_lsp,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(val_tree, hf_ldp_tlv_er_hop_ldpid,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
    }
}

static void
dissect_tlv_traffic(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;
    uint8_t val_8;
    float   val_f;
    proto_item *pi;

    if(rem != 24) {
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing Traffic Parameters TLV: length is %d, should be 24",
                            rem);
        return;
    }
    val_tree = proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "Traffic parameters");

    if(val_tree != NULL) {
        /* flags */
        proto_tree_add_item(val_tree, hf_ldp_tlv_flags_reserv, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(val_tree, hf_ldp_tlv_flags_weight, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(val_tree, hf_ldp_tlv_flags_ebs, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(val_tree, hf_ldp_tlv_flags_cbs, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(val_tree, hf_ldp_tlv_flags_cdr, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(val_tree, hf_ldp_tlv_flags_pbs, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(val_tree, hf_ldp_tlv_flags_pdr, tvb, offset, 1, ENC_BIG_ENDIAN);

        offset ++;
        /* frequency */
        proto_tree_add_item(val_tree, hf_ldp_tlv_frequency, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset ++;

        /* reserver byte */
        offset ++;

        /* weight */
        pi = proto_tree_add_item(val_tree, hf_ldp_tlv_weight, tvb, offset, 1, ENC_BIG_ENDIAN);
        val_8 = tvb_get_uint8(tvb, offset);
        if (val_8 == 0)
            proto_item_set_text(pi, "Weight: Not applicable");
        offset ++;

        /* PDR */
        val_f = tvb_get_ntohieee_float (tvb, offset);
        proto_tree_add_double_format_value(val_tree, hf_ldp_tlv_pdr, tvb, offset,
                                     4, val_f, "%.10g Bps", val_f);
        offset += 4;
        /* PBS */
        val_f = tvb_get_ntohieee_float (tvb, offset);
        proto_tree_add_double_format_value(val_tree, hf_ldp_tlv_pbs, tvb, offset,
                                     4, val_f, "%.10g Bytes", val_f);
        offset += 4;

        /* CDR */
        val_f = tvb_get_ntohieee_float (tvb, offset);
        proto_tree_add_double_format_value(val_tree, hf_ldp_tlv_cdr, tvb, offset,
                                     4, val_f, "%.10g Bps", val_f);
        offset += 4;

        /* CBS */
        val_f = tvb_get_ntohieee_float (tvb, offset);
        proto_tree_add_double_format_value(val_tree, hf_ldp_tlv_cbs, tvb, offset,
                                     4, val_f, "%.10g Bytes", val_f);
        offset += 4;

        /* EBS */
        val_f = tvb_get_ntohieee_float (tvb, offset);
        proto_tree_add_double_format_value(val_tree, hf_ldp_tlv_ebs, tvb, offset,
                                     4, val_f, "%.10g Bytes", val_f);

    }
}

static void
dissect_tlv_route_pinning(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;

    if(rem != 4) {
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing Route Pinning TLV: length is %d, should be 4",
                            rem);
        return;
    }
    val_tree = proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "Route Pinning");

    if(val_tree != NULL) {
        proto_tree_add_item(val_tree, hf_ldp_tlv_route_pinning,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
    }
}


static void
dissect_tlv_resource_class(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;

    if(rem != 4) {
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing Resource Class TLV: length is %d, should be 4",
                            rem);
        return;
    }
    val_tree = proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "Resource Class");

    if(val_tree != NULL) {
        proto_tree_add_item(val_tree, hf_ldp_tlv_resource_class,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
    }
}


static void
dissect_tlv_preemption(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;

    if(rem != 4) {
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing Preemption TLV: length is %d, should be 4",
                            rem);
        return;
    }
    val_tree = proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "Preemption");

    if(val_tree != NULL) {
        proto_tree_add_item(val_tree, hf_ldp_tlv_set_prio,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(val_tree, hf_ldp_tlv_hold_prio,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
    }
}


static void
dissect_tlv_diffserv(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
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
    static int *etts[] = {
        &ett_ldp_diffserv_map,
        &ett_ldp_diffserv_map_phbid
    };
    int type, mapnb, count;

    if (rem < 4) {
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing Diff-Serv TLV: length is %d, should be >= 4", rem);
        return;
    }
    proto_tree_add_uint(tree, hf_ldp_tlv_diffserv_type, tvb, offset, 1,
                        type = tvb_get_uint8(tvb, offset));
    type = (type >> 7) + 1;
    if (type == 1) {
        /* E-LSP */
        offset += 3;
        proto_tree_add_uint(tree, hf_ldp_tlv_diffserv_mapnb, tvb, offset,
                            1, mapnb = tvb_get_uint8(tvb, offset) & 15);
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
dissect_tlv(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem);

static void
// NOLINTNEXTLINE(misc-no-recursion)
dissect_tlv_er(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;
    int len;

    val_tree = proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "Explicit route");

    if(val_tree != NULL) {
        while (rem > 0) {
            len = dissect_tlv (tvb, pinfo, offset, val_tree, rem);
            offset += len;
            rem -= len;
        }
    }
}


static void
dissect_tlv_pw_status(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem);

static void
dissect_tlv_pw_grouping(tvbuff_t *tvb, unsigned offset, proto_tree *tree, int rem);

/* Dissect Upstream Label Assignment Capability TLV */
static void
dissect_tlv_upstrm_lbl_ass_cap(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;

    if ( rem != 1)
    {
        proto_item* inv_length;
        inv_length = proto_tree_add_item(tree, hf_ldp_tlv_inv_length, tvb, offset, rem, ENC_BIG_ENDIAN);
        expert_add_info(pinfo, inv_length, &ei_ldp_inv_length);
        return;
    }

    /*State bit*/
    val_tree = proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "State Bit");
    proto_tree_add_item(val_tree, hf_ldp_tlv_upstr_sbit, tvb,offset, 1, ENC_BIG_ENDIAN);
}
/*Dissect Upstream Assigned Label Request TLV*/
static void
dissect_tlv_upstrm_ass_lbl_req(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    if ( rem != 4)
    {
        proto_item* inv_length;
        inv_length = proto_tree_add_item(tree, hf_ldp_tlv_inv_length, tvb, offset, rem, ENC_BIG_ENDIAN);
        expert_add_info(pinfo, inv_length, &ei_ldp_inv_length);
        return;
    }

    /*Reserved Bits*/
    proto_tree_add_item(tree, hf_ldp_tlv_upstr_lbl_req_resvbit, tvb,offset, 4, ENC_BIG_ENDIAN);
}

/*Dissect Upstream Assigned Label TLV*/
static void
dissect_tlv_upstrm_ass_lbl(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;

    if ( rem != 8)
    {
        proto_item* inv_length;
        inv_length = proto_tree_add_item(tree, hf_ldp_tlv_inv_length, tvb, offset, rem, ENC_BIG_ENDIAN);
        expert_add_info(pinfo, inv_length, &ei_ldp_inv_length);
        return;
    }
    /*Value Field starts here*/
    val_tree = proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "Upstream-Assigned Label");

    /*Reserved bits*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_upstr_lbl_resvbit, tvb,offset, 4, ENC_BIG_ENDIAN);

    /*The Upstream Label*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_upstr_ass_lbl, tvb,offset + 4, 4, ENC_BIG_ENDIAN);
}
/*Dissect IPv4 Interface ID TLV*/
static void
// NOLINTNEXTLINE(misc-no-recursion)
dissect_tlv_ipv4_interface_id(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree, *sub_tree;

    val_tree = proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "IPv4 Interface ID");

    /*Dissect IPv4 Next/Previous Hop Address*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_ipv4_intID_hop_addr, tvb,offset, 4, ENC_BIG_ENDIAN);

    /*Dissect Logical Interface ID*/
    proto_tree_add_item(val_tree, hf_ldp_tlv_logical_intID, tvb,offset + 4, 4, ENC_BIG_ENDIAN);

    sub_tree = proto_tree_add_subtree(val_tree, tvb, offset + 8, rem, ett_ldp_sub_tlv, NULL, "Sub TLV");

    if(rem != 20 && rem != 24 && rem != 28 && rem != 29)
    {
        /*rem = 20 >> Length of IP Multicast Tunnel TLV
          rem = 29 >> Length of LDP P2MP LSV TLV
          rem = 24 >> Length of RSVP-TE P2MP LSP TLV
          rem = 28 >> Length of MPLS Context Label TLV*/

        proto_item* inv_length;
        inv_length = proto_tree_add_item(val_tree, hf_ldp_tlv_inv_length, tvb, offset, rem, ENC_BIG_ENDIAN);
        expert_add_info(pinfo, inv_length, &ei_ldp_inv_length);
    }
    else
    {
        rem = rem - 8;
        dissect_tlv(tvb, pinfo, offset + 8, sub_tree, rem);
    }
}
/*Dissect IP Multicast Tunnel TLV*/
static void
dissect_tlv_ip_multicast_tunnel(tvbuff_t *tvb, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;

    val_tree = proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "IP Multicast Label");

    proto_tree_add_item(val_tree, hf_ldp_tlv_ip_multicast_srcaddr, tvb,offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(val_tree, hf_ldp_tlv_ip_multicast_mltcstaddr, tvb,offset + 4, 4, ENC_BIG_ENDIAN);
}

static void
// NOLINTNEXTLINE(misc-no-recursion)
dissect_tlv_mpls_context_lbl(tvbuff_t *tvb,packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *val_tree;

    proto_tree_add_item(tree, hf_ldp_tlv_ip_mpls_context_srcaddr, tvb,offset, 4, ENC_BIG_ENDIAN);
    val_tree = proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_tlv_val, NULL, "MPLS Context Label");
    dissect_tlv(tvb, pinfo, offset + 4, val_tree, rem);
}

static void
dissect_tlv_ldp_p2mp_lsp(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
    uint16_t addr_length = tvb_get_bits16(tvb, ((offset+3)*8), 8, ENC_BIG_ENDIAN);
    uint16_t opcode_length = tvb_get_bits16(tvb, ((offset + 4 + addr_length)*8), 16, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_ldp_tlv_ldp_p2mp_lsptype, tvb,offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ldp_tlv_ldp_p2mp_addrfam, tvb,offset + 1, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ldp_tlv_ldp_p2mp_addrlen, tvb,offset + 3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ldp_tlv_ldp_p2mp_rtnodeaddr, tvb,offset + 4, addr_length, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ldp_tlv_ldp_p2mp_oplength, tvb,offset + 4 + addr_length, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ldp_tlv_ldp_p2mp_opvalue, tvb,offset + 4 + addr_length + 2, opcode_length, ENC_NA);
}

static void
dissect_tlv_rsvp_te_p2mp_lsp(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{

    proto_tree_add_item(tree, hf_ldp_tlv_rsvp_te_p2mp_id, tvb,offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ldp_tlv_must_be_zero, tvb,offset + 4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ldp_tlv_tunnel_id, tvb,offset + 6, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ldp_tlv_ext_tunnel_id, tvb,offset + 8, 4, ENC_BIG_ENDIAN);
}

/* Dissect a TLV and return the number of bytes consumed ... */

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_tlv(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    uint16_t type, typebak;
    int length;

    length=tvb_reported_length_remaining(tvb, offset);
    rem=MIN(rem, length);

    if( rem < 4 ) {/*chk for minimum header*/
        if (tree) {
            proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                                "Error processing TLV: length is %d, should be >= 4",
                                rem);
        }
        return rem;
    }
    type = tvb_get_ntohs(tvb, offset) & 0x3FFF;

    length = tvb_get_ntohs(tvb, offset + 2);
    rem -= 4; /*do not count header*/
    length = MIN(length, rem);  /* Don't go haywire if a problem ... */

    increment_dissection_depth(pinfo);

    if (tree) {
        proto_tree *tlv_tree;
        /*chk for vendor-private*/
        if(type>=TLV_VENDOR_PRIVATE_START && type<=TLV_VENDOR_PRIVATE_END){
            typebak=type;               /*keep type*/
            type=TLV_VENDOR_PRIVATE_START;
            tlv_tree = proto_tree_add_subtree(tree, tvb, offset, length + 4, ett_ldp_tlv, NULL, "Vendor Private TLV");
            /*chk for experimental*/
        } else if(type>=TLV_EXPERIMENTAL_START && type<=TLV_EXPERIMENTAL_END){
            typebak=type;               /*keep type*/
            type=TLV_EXPERIMENTAL_START;
            tlv_tree = proto_tree_add_subtree(tree, tvb, offset, length + 4, ett_ldp_tlv, NULL, "Experimental TLV");
        } else {
            typebak=0;
            tlv_tree = proto_tree_add_subtree(tree, tvb, offset, length + 4, ett_ldp_tlv, NULL,
                                     val_to_str(type, tlv_type_names, "Unknown TLV type (0x%04X)"));
        }

        proto_tree_add_item(tlv_tree, hf_ldp_tlv_unknown, tvb, offset, 1, ENC_BIG_ENDIAN);

        switch (type) {
        case TLV_VENDOR_PRIVATE_START:
            proto_tree_add_uint_format_value(tlv_tree, hf_ldp_tlv_type, tvb, offset, 2,
                                       typebak, "Vendor Private (0x%X)", typebak);
            break;
        case TLV_EXPERIMENTAL_START:
            proto_tree_add_uint_format_value(tlv_tree, hf_ldp_tlv_type, tvb, offset, 2,
                                       typebak, "Experimental (0x%X)", typebak);
            break;
        default:
            proto_tree_add_uint_format(tlv_tree, hf_ldp_tlv_type, tvb, offset, 2,
                                       type, "TLV Type: %s (0x%X)", val_to_str_const(type, tlv_type_names, "Unknown TLV type"), type );
        }

        proto_tree_add_item(tlv_tree, hf_ldp_tlv_len, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

        switch (type) {

        case TLV_FEC:
            dissect_tlv_fec(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_ADDRESS_LIST:
            dissect_tlv_address_list(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_HOP_COUNT:
            if( length != 1 ) /*error, only one byte*/
                proto_tree_add_expert_format(tlv_tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset + 4,length,
                                    "Error processing Hop Count TLV: length is %d, should be 1",
                                    length);
            else
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_hc_value, tvb,offset + 4, length, ENC_BIG_ENDIAN);
            break;

        case TLV_PATH_VECTOR:
            dissect_tlv_path_vector(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_GENERIC_LABEL:
            if( length != 4 ) /*error, need only label*/
                proto_tree_add_expert_format(tlv_tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset + 4, length,
                                    "Error processing Generic Label TLV: length is %d, should be 4",
                                    length);
            else {
                uint32_t label=tvb_get_ntohl(tvb, offset+4) & 0x000FFFFF;

                proto_tree_add_uint(tlv_tree, hf_ldp_tlv_generic_label,
                                           tvb, offset+4, length, label);
            }
            break;

        case TLV_ATM_LABEL:
            dissect_tlv_atm_label(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_FRAME_RELAY_LABEL:
            dissect_tlv_frame_label(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_FT_PROTECTION:
            if( length != 4 ) /* Length must be 4 bytes */
                proto_tree_add_expert_format(tlv_tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset + 4, length,
                                    "Error processing FT Protection TLV: length is %d, should be 4",
                                    length);
            else
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_ft_protect_sequence_num, tvb,
                                    offset + 4,length, ENC_BIG_ENDIAN);
            break;

        case TLV_ENTROPY_LABEL_CAPA:
            if( length != 0 ) /* Length must be 0 bytes */
                proto_tree_add_expert_format(tlv_tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset + 4, length,
                                    "Error processing Entropy Label Capability TLV: length is %d, should be 0",
                                    length);
            break;

        case TLV_STATUS:
            dissect_tlv_status(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_EXTENDED_STATUS:
            if( length != 4 ) /*error, need only status_code(uint32_t)*/
                proto_tree_add_expert_format(tlv_tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset + 4, length,
                                    "Error processing Extended Status TLV: length is %d, should be 4",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_extstatus_data, tvb, offset + 4, length, ENC_BIG_ENDIAN);
            }
            break;

        case TLV_RETURNED_PDU:
            dissect_tlv_returned_pdu(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_RETURNED_MESSAGE:
            dissect_tlv_returned_message(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_COMMON_HELLO_PARAMS:
#if 0
            dissect_tlv_common_hello_parms(tvb, pinfo, offset + 4, tlv_tree, length);
#else
            dissect_tlv_common_hello_parms(tvb, pinfo, offset + 4, tlv_tree);
#endif
            break;

        case TLV_IPV4_TRANSPORT_ADDRESS:
            if( length != 4 ) /*error, need only ipv4*/
                proto_tree_add_expert_format(tlv_tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset + 4, length,
                                    "Error processing IPv4 Transport Address TLV: length is %d, should be 4",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_ipv4_taddr, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            }
            break;

        case TLV_CONFIGURATION_SEQUENCE_NUMBER:
            if( length != 4 ) /*error, need only seq_num(uint32_t)*/
                proto_tree_add_expert_format(tlv_tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset + 4, length,
                                    "Error processing Configuration Sequence Number TLV: length is %d, should be 4",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_config_seqno, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
            }
            break;

        case TLV_IPV6_TRANSPORT_ADDRESS:
            if( length != 16 ) /*error, need only ipv6*/
                proto_tree_add_expert_format(tlv_tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset + 4, length,
                                    "Error processing IPv6 Transport Address TLV: length is %d, should be 16",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_ipv6_taddr, tvb, offset + 4, 16, ENC_NA);
            }
            break;

        case TLV_MAC: /* draft-lasserre-vkompella-ppvpn-vpls-02.txt */
            dissect_tlv_mac(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_COMMON_SESSION_PARAMS:
            dissect_tlv_common_session_parms(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_ATM_SESSION_PARAMS:
            dissect_tlv_atm_session_parms(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_FRAME_RELAY_SESSION_PARAMS:
            dissect_tlv_frame_relay_session_parms(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_FT_SESSION:
            /* Used in RFC3478 LDP Graceful Restart */
            dissect_tlv_ft_session(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_FT_ACK:
            if( length != 4 ) /* Length must be 4 bytes */
                proto_tree_add_expert_format(tlv_tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset + 4, length,
                                    "Error processing FT ACK TLV: length is %d, should be 4",
                                    length);
            else
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_ft_ack_sequence_num, tvb,
                                    offset + 4,length, ENC_BIG_ENDIAN);
            break;

        case TLV_FT_CORK:
            if( length != 0 ) /* Length must be 0 bytes */
                proto_tree_add_expert_format(tlv_tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset + 4, length,
                                    "Error processing FT Cork TLV: length is %d, should be 0",
                                    length);
            break;

        case TLV_LABEL_REQUEST_MESSAGE_ID:
            if( length != 4 ) /*error, need only one msgid*/
                proto_tree_add_expert_format(tlv_tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset + 4, length,
                                    "Error processing Label Request Message ID TLV: length is %d, should be 4",
                                    length);
            else
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_lbl_req_msg_id, tvb,offset + 4,length, ENC_BIG_ENDIAN);
            break;

        case TLV_LSPID:
            dissect_tlv_lspid(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_ER_HOP:
            dissect_tlv_er(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_IPV4_PREFIX_ER_HOP:
            dissect_tlv_er_hop_ipv4(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_IPV6_PREFIX_ER_HOP:
            dissect_tlv_er_hop_ipv6(tvb, pinfo, offset +4, tlv_tree, length);
            break;

        case TLV_AUTONOMOUS_SYSTEM_NUMBER_ER_HOP:
            dissect_tlv_er_hop_as(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_LSP_ID_ER_HOP:
            dissect_tlv_er_hop_lspid(tvb, pinfo, offset +4, tlv_tree, length);
            break;

        case TLV_TRAFFIC_PARAMS:
            dissect_tlv_traffic(tvb, pinfo, offset +4, tlv_tree, length);
            break;

        case TLV_PREEMPTION:
            dissect_tlv_preemption(tvb, pinfo, offset +4, tlv_tree, length);
            break;

        case TLV_RESOURCE_CLASS:
            dissect_tlv_resource_class(tvb, pinfo, offset +4, tlv_tree, length);
            break;

        case TLV_ROUTE_PINNING:
            dissect_tlv_route_pinning(tvb, pinfo, offset +4, tlv_tree, length);
            break;

        case TLV_DIFF_SERV:
            dissect_tlv_diffserv(tvb, pinfo, offset +4, tlv_tree, length);
            break;

        case TLV_HSMP_LSP_CAPA_PARAM:
            dissect_tlv_upstrm_lbl_ass_cap(tvb, pinfo, offset + 4, tlv_tree, length);
            break;

        case TLV_VENDOR_PRIVATE_START:
            if( length < 4 ) /*error, at least Vendor ID*/
                proto_tree_add_expert_format(tlv_tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset + 4, length,
                                    "Error processing Vendor Private Start TLV: length is %d, should be >= 4",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_vendor_id, tvb,offset + 4, 4, ENC_BIG_ENDIAN);
                if( length > 4 )  /*have data*/
                    proto_tree_add_item(tlv_tree, hf_ldp_data, tvb, offset + 8, length-4, ENC_NA);
            }
            break;

        case TLV_EXPERIMENTAL_START:
            if( length < 4 ) /*error, at least Experiment ID*/
                proto_tree_add_expert_format(tlv_tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset + 4, length,
                                    "Error processing Experimental Start TLV: length is %d, should be >= 4",
                                    length);
            else {
                proto_tree_add_item(tlv_tree, hf_ldp_tlv_experiment_id, tvb,offset + 4, 4, ENC_BIG_ENDIAN);
                if( length > 4 )  /*have data*/
                    proto_tree_add_item(tlv_tree, hf_ldp_data, tvb, offset + 8, length-4, ENC_NA);
            }
            break;

        case TLV_PW_STATUS:
        {
            /* Ref: RFC 4447  and 4446*/
            dissect_tlv_pw_status(tvb, pinfo, offset +4, tlv_tree, length);
            break;
        }
        case TLV_PW_INTERFACE_PARAMS:
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
                &hf_ldp_tlv_intparam_vccv_cvtype_bfd,
                &hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd2,
                &hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd3,
                &hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd4,
                &hf_ldp_tlv_fec_vc_intparam_flowlabel_t,
                &hf_ldp_tlv_fec_vc_intparam_flowlabel_r,
                &hf_ldp_tlv_fec_vc_intparam_flowlabel_res
            };
            int vc_len = length;
            offset += 4;
            while ( (vc_len > 1) && (rem > 1) ) {       /* enough to include id and length */
                int intparam_len = tvb_get_uint8(tvb, offset+1);
                if (intparam_len < 2){ /* At least Type and Len, protect against len = 0 */
                    proto_tree_add_expert(tlv_tree, pinfo, &ei_ldp_malformed_interface_parameter, tvb, offset +1, 1);
                    break;
                }

                if ( (vc_len -intparam_len) <0 && (rem -intparam_len) <0 ) { /* error condition */
                    proto_tree_add_expert(tlv_tree, pinfo, &ei_ldp_malformed_data, tvb, offset +2, MIN(vc_len,rem));
                    break;
                }
                dissect_subtlv_interface_parameters(tvb, offset, tlv_tree, intparam_len, interface_params_header_fields);

                rem -= intparam_len;
                vc_len -= intparam_len;
                offset += intparam_len;
            }
            break;
        }
        case TLV_PW_GROUP_ID:
        {
            /* Ref: RFC 4447 */
            dissect_tlv_pw_grouping(tvb, offset +4, tlv_tree, length);
            break;
        }
        case TLV_LDP_UPSTREAM_LABEL_ASSIGNMENT_CAPA:
            dissect_tlv_upstrm_lbl_ass_cap(tvb, pinfo, offset + 4, tlv_tree, length);
            break;
        case TLV_LDP_UPSTREAM_ASSIGNED_LABEL_REQUEST:
            dissect_tlv_upstrm_ass_lbl_req(tvb, pinfo, offset + 4, tlv_tree, length);
            break;
        case TLV_LDP_UPSTREAM_ASSIGNED_LABEL:
            dissect_tlv_upstrm_ass_lbl(tvb, pinfo, offset + 4, tlv_tree, length);
            break;
        case TLV_IPV4_INTERFACE_ID:
            dissect_tlv_ipv4_interface_id(tvb, pinfo, offset + 4, tlv_tree, length);
            /*dissect_tlv_ipv4_interface_id(tvb, offset + 4, tlv_tree, length);*/
            break;
        case TLV_IP_MULTICAST_TUNNEL:
            dissect_tlv_ip_multicast_tunnel(tvb, offset + 4, tlv_tree, rem);
            break;
        case TLV_MPLS_CONTEXT_LBL:
            dissect_tlv_mpls_context_lbl(tvb, pinfo, offset + 4, tlv_tree, rem);
            break;
        case TLV_LDP_P2MP_LSP:
            dissect_tlv_ldp_p2mp_lsp(tvb, offset + 4, tlv_tree);
            break;
        case TLV_RSVP_TE_P2MP_LSP:
            dissect_tlv_rsvp_te_p2mp_lsp(tvb, offset + 4, tlv_tree);
            break;
        default:
            proto_tree_add_item(tlv_tree, hf_ldp_tlv_value, tvb, offset + 4, length, ENC_NA);
            break;
        }
    }

    decrement_dissection_depth(pinfo);
    return length + 4;  /* Length of the value field + header */
}


/* Dissect a Message and return the number of bytes consumed ... */

static int
dissect_msg(tvbuff_t *tvb, unsigned offset, packet_info *pinfo, proto_tree *tree)
{
    uint16_t    type, typebak;
    uint8_t     extra=0;
    int length, rem, ao=0, co;
    proto_tree *msg_tree = NULL;

    rem=tvb_reported_length_remaining(tvb, offset);

    if( rem < 8 ) {/*chk for minimum header = type + length + msg_id*/
        col_append_str(pinfo->cinfo, COL_INFO, "Bad Message");
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_inv_length, tvb, offset, rem,
                                "Error processing Message: length is %d, should be >= 8",
                                rem);
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
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_inv_length, tvb, offset, rem,
                                "Error processing Message Length: length is %d, should be >= %u",
                                length, 4+extra);
        return rem;
    }
    rem -= 4;
    length = MIN(length, rem);  /* Don't go haywire if a problem ... */

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

    if (tree) {

        switch (type) {
        case LDP_VENDOR_PRIVATE_START:
            msg_tree = proto_tree_add_subtree(tree, tvb, offset, length + 4, ett_ldp_message, NULL, "Vendor-Private Message");
            break;
        case LDP_EXPERIMENTAL_MESSAGE_START:
            msg_tree = proto_tree_add_subtree(tree, tvb, offset, length + 4, ett_ldp_message, NULL, "Experimental Message");
            break;
        default:
            msg_tree = proto_tree_add_subtree(tree, tvb, offset, length + 4, ett_ldp_message, NULL,
                                     val_to_str(type, ldp_message_types, "Unknown Message type (0x%04X)"));
        }

        proto_tree_add_item(msg_tree, hf_ldp_msg_ubit, tvb, offset, 1, ENC_BIG_ENDIAN);

        switch (type) {
        case LDP_VENDOR_PRIVATE_START:
            proto_tree_add_uint_format_value(msg_tree, hf_ldp_msg_type, tvb, offset, 2,
                                       typebak, "Vendor Private (0x%X)", typebak);
            break;
        case LDP_EXPERIMENTAL_MESSAGE_START:
            proto_tree_add_uint_format_value(msg_tree, hf_ldp_msg_type, tvb, offset, 2,
                                       typebak, "Experimental (0x%X)", typebak);
            break;
        default:
            proto_tree_add_uint_format(msg_tree, hf_ldp_msg_type, tvb, offset, 2,
                                       type, "Message Type: %s (0x%X)", val_to_str_const(type, ldp_message_types,"Unknown Message Type"), type);
        }

        proto_tree_add_item(msg_tree, hf_ldp_msg_len, tvb, offset+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(msg_tree, hf_ldp_msg_id, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        if(extra){
            proto_tree_add_item(msg_tree, (type == LDP_VENDOR_PRIVATE_START) ?
                hf_ldp_msg_vendor_id : hf_ldp_msg_experiment_id, tvb, offset+8,
                extra, ENC_BIG_ENDIAN);
        }
    }

    offset += (8+extra);
    length -= (4+extra);

    if (tree) {
        while ( (length-ao) > 0 ) {
            co = dissect_tlv(tvb, pinfo, offset, msg_tree, length-ao);
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
        ti=proto_tree_add_item(tree, proto_ldp, tvb, 0, -1, ENC_NA);
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
        proto_tree_add_item(pdu_tree, hf_ldp_lsr, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(pdu_tree, hf_ldp_ls_id, tvb, offset+8, 2, ENC_BIG_ENDIAN);
    }
    offset += 10;

    while ( tvb_reported_length_remaining(tvb, offset) > 0 ) {
        co = dissect_msg(tvb, offset, pinfo, pdu_tree);
        offset += co;
    }
}

static int
dissect_ldp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /*
     * Make sure the first PDU has a version number of 1;
     * if not, reject this, so we don't get confused by
     * packets that happen to be going to or from the
     * LDP port but that aren't LDP packets.
     */
    if (tvb_captured_length(tvb) < 2) {
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
    return tvb_captured_length(tvb);
}

static void
dissect_tlv_pw_status(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *ti, *val_tree;

    if(rem != 4){
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_tlv_fec_len, tvb, offset, rem,
                            "Error processing PW Status TLV: length is %d, should be 4",
                            rem);
        return;
    }

    ti = proto_tree_add_item(tree, hf_ldp_tlv_pw_status_data, tvb, offset, rem, ENC_BIG_ENDIAN);

    val_tree=proto_item_add_subtree(ti, ett_ldp_tlv_val);
    /* Display the bits 0-4 if they are set or not set */
    proto_tree_add_item(val_tree, hf_ldp_tlv_pw_not_forwarding, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(val_tree, hf_ldp_tlv_pw_lac_ingress_recv_fault, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(val_tree, hf_ldp_tlv_pw_lac_egress_recv_fault, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(val_tree, hf_ldp_tlv_pw_psn_pw_ingress_recv_fault, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(val_tree, hf_ldp_tlv_pw_psn_pw_egress_recv_fault, tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void
dissect_tlv_pw_grouping(tvbuff_t *tvb, unsigned offset, proto_tree *tree, int rem _U_)
{
    proto_tree_add_item(tree,hf_ldp_tlv_pw_grouping_value,tvb,offset,4,ENC_BIG_ENDIAN);
}

static void
dissect_subtlv_interface_parameters(tvbuff_t *tvb, unsigned offset, proto_tree *tree, int rem, int *interface_parameters_hf[])
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
        32 - hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd1,
        33 - hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd2,
        34 - hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd3,
        35 - hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd4,
        36 - hf_ldp_tlv_fec_vc_intparam_flowlabel_t,
        37 - hf_ldp_tlv_fec_vc_intparam_flowlabel_r,
        38 - hf_ldp_tlv_fec_vc_intparam_flowlabel_res
    };
#endif
    proto_tree *ti;
    proto_tree *cepopt_tree=NULL, *vccvtype_tree=NULL;
    proto_tree *vcintparam_tree = proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_fec_vc_interfaceparam, &ti, "Interface Parameter");

    uint8_t intparam_len = rem;
    proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[3],tvb,offset,1,ENC_BIG_ENDIAN);
    proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[0],tvb, offset+1, 1, ENC_BIG_ENDIAN);

    switch (tvb_get_uint8(tvb, offset)) {
    case FEC_VC_INTERFACEPARAM_MTU:
        proto_item_append_text(ti,": MTU %u", tvb_get_ntohs(tvb,offset+2));
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[1],tvb, offset+2, 2, ENC_BIG_ENDIAN);
        break;
    case FEC_VC_INTERFACEPARAM_TDMBPS:
        /* draft-ietf-pwe3-control-protocol-06.txt */
        proto_item_append_text(ti,": BPS %u", tvb_get_ntohl(tvb,offset+2));
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[2],tvb, offset+2, 4, ENC_BIG_ENDIAN);
        break;
    case FEC_VC_INTERFACEPARAM_MAXCATMCELLS:
        proto_item_append_text(ti,": Max ATM Concat Cells %u", tvb_get_ntohs(tvb,offset+2));
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[4],tvb, offset+2, 2, ENC_BIG_ENDIAN);
        break;
    case FEC_VC_INTERFACEPARAM_DESCRIPTION:
        proto_item_append_text(ti,": Description");
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[5],tvb, offset+2, (intparam_len -2), ENC_ASCII|ENC_NA);
        break;
    case FEC_VC_INTERFACEPARAM_CEPBYTES:
        proto_item_append_text(ti,": CEP/TDM Payload Bytes %u", tvb_get_ntohs(tvb,offset+2));
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[6],tvb, offset+2, 2, ENC_BIG_ENDIAN);
        break;
    case FEC_VC_INTERFACEPARAM_CEPOPTIONS:
        /* draft-ietf-pwe3-sonet-05.txt */
        proto_item_append_text(ti,": CEP Options");
        cepopt_tree = proto_tree_add_subtree(vcintparam_tree, tvb, offset + 2, 2, ett_ldp_fec_vc_interfaceparam_cepopt, NULL, "CEP Options");
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[7], tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[8], tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[9], tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[10], tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[11], tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[12], tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[13], tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[14], tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(cepopt_tree, *interface_parameters_hf[15], tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        break;
    case FEC_VC_INTERFACEPARAM_VLANID:
        proto_item_append_text(ti,": VLAN Id %u", tvb_get_ntohs(tvb,offset+2));
        proto_tree_add_item(vcintparam_tree, *interface_parameters_hf[16], tvb, offset+2, 2, ENC_BIG_ENDIAN);
        break;
    case FEC_VC_INTERFACEPARAM_FRDLCILEN:
        proto_item_append_text(ti,": DLCI Length %u", tvb_get_ntohs(tvb,offset+2));
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[17], tvb, offset+2, 2, ENC_BIG_ENDIAN);
        break;
    case FEC_VC_INTERFACEPARAM_FRAGIND:
        /* draft-ietf-pwe3-fragmentation-05.txt */
        proto_item_append_text(ti,": Fragmentation");
        break;
    case FEC_VC_INTERFACEPARAM_FCSRETENT:
        /* draft-ietf-pwe3-fcs-retention-02.txt */
        proto_item_append_text(ti,": FCS retention, FCS Length %u Bytes", tvb_get_ntohs(tvb,offset+2));
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[18], tvb, offset+2, 2, ENC_BIG_ENDIAN);
        break;
    case FEC_VC_INTERFACEPARAM_TDMOPTION:
        /* draft-vainshtein-pwe3-tdm-control-protocol-extensions */
        proto_item_append_text(ti,": TDM Options");
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[19], tvb, offset+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[20], tvb, offset+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[21], tvb, offset+2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[22], tvb, offset+2, 2, ENC_BIG_ENDIAN);
        if (intparam_len >= 8){
            proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[23], tvb, offset+4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[24], tvb, offset+5, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[25], tvb, offset+6, 2, ENC_BIG_ENDIAN);
        }
        if (intparam_len >= 12){
            proto_tree_add_item(vcintparam_tree,*interface_parameters_hf[26], tvb, offset+8, 4, ENC_BIG_ENDIAN);
        }
        break;
    case FEC_VC_INTERFACEPARAM_VCCV:
        /* draft-ietf-pwe3-vccv-03.txt */
        proto_item_append_text(ti,": VCCV");
        vccvtype_tree = proto_tree_add_subtree(vcintparam_tree, tvb, offset + 2, 1, ett_ldp_fec_vc_interfaceparam_vccvtype, NULL, "CC Type");
        proto_tree_add_item(vccvtype_tree, *interface_parameters_hf[27], tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(vccvtype_tree, *interface_parameters_hf[28], tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(vccvtype_tree, *interface_parameters_hf[29], tvb, offset+2, 1, ENC_BIG_ENDIAN);
        vccvtype_tree = proto_tree_add_subtree(vcintparam_tree, tvb, offset + 3, 1, ett_ldp_fec_vc_interfaceparam_vccvtype, NULL, "CV Type");
        proto_tree_add_item(vccvtype_tree, *interface_parameters_hf[30], tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(vccvtype_tree, *interface_parameters_hf[31], tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(vccvtype_tree, *interface_parameters_hf[32], tvb, offset+3, 1, ENC_BIG_ENDIAN);
        break;
    case FEC_VC_INTERFACEPARAM_FLOWLABEL:
        proto_item_append_text(ti,": Flow Label for Pseudowire");
        proto_tree_add_item(vcintparam_tree, *interface_parameters_hf[36], tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(vcintparam_tree, *interface_parameters_hf[37], tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(vcintparam_tree, *interface_parameters_hf[38], tvb, offset+2, 2, ENC_BIG_ENDIAN);
        break;
    default: /* unknown */
        proto_item_append_text(ti," unknown");
        proto_tree_add_item(vcintparam_tree, hf_ldp_unknown_data, tvb, offset+2, (intparam_len -2), ENC_NA);

        break;
    }
}

static void
dissect_genpwid_fec_aai_type2_parameter(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree, int rem)
{
    proto_tree *aai_param_tree = proto_tree_add_subtree(tree, tvb, offset, rem, ett_ldp_gen_aai_type2, NULL, "AAI");
    /* check if the remaining length is 12 bytes or not... */
    if ( rem != 12)
    {
        proto_tree_add_expert_format(tree, pinfo, &ei_ldp_inv_length, tvb, offset, rem,
                            "Error processing AAI Parameter: length is %d, should be 12 bytes for Type 2.",
                            rem);
        return;

    }

    proto_tree_add_item(aai_param_tree,hf_ldp_tlv_fec_gen_aai_globalid,tvb,offset,4,ENC_BIG_ENDIAN);
    proto_tree_add_item(aai_param_tree,hf_ldp_tlv_fec_gen_aai_prefix,tvb, offset+4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(aai_param_tree,hf_ldp_tlv_fec_gen_aai_ac_id,tvb, offset+4, 4, ENC_BIG_ENDIAN);
}

static int
dissect_ldp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    volatile bool       first = true;
    volatile int        offset = 0;
    int                 length_remaining;
    uint16_t            plen;
    int                 length;
    tvbuff_t *volatile  next_tvb;
    while (tvb_reported_length_remaining(tvb, offset) != 0) {
        length_remaining = tvb_captured_length_remaining(tvb, offset);

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
            first = false;
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
                return -((int32_t) pinfo->desegment_len);
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
                return -((int32_t) pinfo->desegment_len);
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
        next_tvb = tvb_new_subset_length_caplen(tvb, offset, length, plen + 4);

        /*
         * Dissect the LDP packet.
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
        TRY {
            dissect_ldp_pdu(next_tvb, pinfo, tree);
        }
        CATCH_NONFATAL_ERRORS {
            show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
        }
        ENDTRY;

        /*
         * Skip the LDP header and the payload.
         */
        offset += plen + 4;
    }
    return tvb_captured_length(tvb);
}

/* Register all the bits needed with the filtering engine */

void
proto_register_ldp(void)
{
    static hf_register_info hf[] = {
#if 0
        { &hf_ldp_req,
          /* Change the following to the type you need */
          { "Request", "ldp.req", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
#endif

#if 0
        { &hf_ldp_rsp,
          { "Response", "ldp.rsp", FT_BOOLEAN, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
#endif

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

        { &hf_ldp_tlv_val_gtsm_flag,
          { "GTSM Flag", "ldp.msg.tlv.hello.gtsm", FT_BOOLEAN, 16,
            TFS(&tfs_set_notset), 0x2000, "Hello Common Parameters GTSM bit", HFILL }},

        { &hf_ldp_tlv_val_res,
          { "Reserved", "ldp.msg.tlv.hello.res", FT_UINT16, BASE_HEX,
            NULL, 0x1FFF, "Hello Common Parameters Reserved Field", HFILL }},

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
            VALS(fec_types_vals), 0x0, "Forwarding Equivalence Class Element Types", HFILL }},

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
            NULL, 0x0, NULL, HFILL }},

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
            NULL, 0x3C, NULL, HFILL }},

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
            NULL, 0x3C, NULL, HFILL }},

        { &hf_ldp_tlv_sess_fr_dir,
          { "Directionality", "ldp.msg.tlv.sess.fr.dir", FT_BOOLEAN, 8,
            TFS(&tlv_atm_dirbit), 0x02, "Label Directionality", HFILL }},

        { &hf_ldp_tlv_sess_fr_len,
          { "Number of DLCI bits", "ldp.msg.tlv.sess.fr.len", FT_UINT16, BASE_DEC,
            VALS(tlv_fr_len_vals), 0x0180, NULL, HFILL }},

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
            TFS(&tlv_ft_c), 0x2, "Check-Pointing Flag", HFILL }},

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
          { "Label Request Message ID", "ldp.msg.tlv.lbl_req_msg_id", FT_UINT32, BASE_HEX,
            NULL, 0x0, "Label Request Message to be aborted", HFILL }},

        { &hf_ldp_tlv_vendor_id,
          { "Vendor ID", "ldp.msg.tlv.vendor_id", FT_UINT32, BASE_HEX,
            NULL, 0, "IEEE 802 Assigned Vendor ID", HFILL }},

        { &hf_ldp_tlv_experiment_id,
          { "Experiment ID", "ldp.msg.tlv.experiment_id", FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL }},

        { &hf_ldp_tlv_generic_label,
          { "Generic Label", "ldp.msg.tlv.generic.label", FT_UINT32, BASE_DEC_HEX,
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
            VALS(tlv_fr_len_vals), 0x0180, NULL, HFILL }},

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
            TFS(&ldp_message_ubit), 0x80, NULL, HFILL }},

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
            NULL, 0x0, "VC FEC Interface Parameter Length", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_mtu,
          { "MTU", "ldp.msg.tlv.fec.vc.intparam.mtu", FT_UINT16, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Parameter MTU", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_tdmbps,
          { "BPS", "ldp.msg.tlv.fec.vc.intparam.tdmbps", FT_UINT32, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Parameter CEP/TDM bit-rate", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_id,
          { "ID", "ldp.msg.tlv.fec.vc.intparam.id", FT_UINT8, BASE_HEX,
            VALS(fec_vc_interfaceparm), 0x0, "VC FEC Interface Parameter ID", HFILL }},

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
            NULL, 0x0, "VC FEC Interface Parameter FCS Length", HFILL }},

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

        { &hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd1,
          { "BFD IP/UDP-encapsulated, for PW Fault Detection only", "ldp.msg.tlv.fec.vc.intparam.vccv.cvtype_bfd1", FT_BOOLEAN, 8,
            NULL, 0x04, "VC FEC Interface Param VCCV CV Type BFD IP/UDP-encapsulated, for PW Fault Detection only", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd2,
          { "BFD IP/UDP-encapsulated, for PW Fault Detection and AC/PW Fault Status Signaling", "ldp.msg.tlv.fec.vc.intparam.vccv.cvtype_bfd2", FT_BOOLEAN, 8,
            NULL, 0x08, "VC FEC Interface Param VCCV CV Type BFD IP/UDP-encapsulated, for PW Fault Detection and AC/PW Fault Status Signaling", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd3,
          { "BFD BFD PW-ACH-encapsulated, for PW Fault Detection only", "ldp.msg.tlv.fec.vc.intparam.vccv.cvtype_bfd3", FT_BOOLEAN, 8,
            NULL, 0x10, "VC FEC Interface Param VCCV CV Type BFD PW-ACH-encapsulated, for PW Fault Detection only", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_vccv_cvtype_bfd4,
          { "BFD BFD PW-ACH-encapsulated, for PW Fault Detection and AC/PW Fault Status Signaling", "ldp.msg.tlv.fec.vc.intparam.vccv.cvtype_bfd4", FT_BOOLEAN, 8,
            NULL, 0x20, "VC FEC Interface Param VCCV CV Type BFD PW-ACH-encapsulated, for PW Fault Detection and AC/PW Fault Status Signaling", HFILL }},

        { &hf_ldp_tlv_fec_vc_intparam_flowlabel_t,
          { "Flow Label Transmit bit", "ldp.msg.tlv.fec.vc.intparam.flowlabel.t", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL}},

        { &hf_ldp_tlv_fec_vc_intparam_flowlabel_r,
          { "Flow Label Receive bit", "ldp.msg.tlv.fec.vc.intparam.flowlabel.r", FT_UINT8, BASE_DEC, NULL, 0x40, NULL, HFILL}},

        { &hf_ldp_tlv_fec_vc_intparam_flowlabel_res,
          { "Flow Label Reserved", "ldp.msg.tlv.fec.vc.intparam.flowlabel.res", FT_UINT16, BASE_HEX, NULL, 0x3FFF, NULL, HFILL}},

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

#if 0
        { &hf_ldp_tlv_diffserv,
          { "Diff-Serv TLV", "ldp.msg.tlv.diffserv", FT_NONE, BASE_NONE,
            NULL, 0, "Diffserv TLV", HFILL}},
#endif

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

        { &hf_ldp_tlv_fec_pw_controlword,
          { "C-bit", "ldp.msg.tlv.fec.pw.controlword", FT_BOOLEAN, 8,
            TFS(&fec_vc_cbit), 0x80, "Control Word Present", HFILL }},

        { &hf_ldp_tlv_fec_pw_pwtype,
          { "PW Type", "ldp.msg.tlv.fec.pw.pwtype", FT_UINT16, BASE_HEX,
            VALS(fec_vc_types_vals), 0x7FFF, "Virtual Circuit Type", HFILL }},

        { &hf_ldp_tlv_fec_pw_infolength,
          { "PW Info Length", "ldp.msg.tlv.fec.pw.infolength", FT_UINT8, BASE_DEC,
            NULL, 0x0, "PW FEC Info Length", HFILL }},

        { &hf_ldp_tlv_fec_pw_groupid,
          { "Group ID", "ldp.msg.tlv.fec.pw.groupid", FT_UINT32, BASE_DEC,
            NULL, 0x0, "PW FEC Group ID", HFILL }},

        { &hf_ldp_tlv_fec_pw_pwid,
          { "PW ID", "ldp.msg.tlv.fec.pw.pwid", FT_UINT32, BASE_DEC,
            NULL, 0x0, "PW FEC PWID", HFILL }},

        { &hf_ldp_tlv_pw_status_data,
          { "PW Status", "ldp.msg.tlv.pwstatus.code", FT_UINT32, BASE_HEX,
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
            NULL, 0x0, "VC FEC Interface Parameter Length", HFILL }},

        { &hf_ldp_tlv_intparam_mtu,
          { "MTU", "ldp.msg.tlv.intparam.mtu", FT_UINT16, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Parameter MTU", HFILL }},

        { &hf_ldp_tlv_intparam_tdmbps,
          { "BPS", "ldp.msg.tlv.intparam.tdmbps", FT_UINT32, BASE_DEC,
            NULL, 0x0, "VC FEC Interface Parameter CEP/TDM bit-rate", HFILL }},

        { &hf_ldp_tlv_intparam_id,
          { "ID", "ldp.msg.tlv.intparam.id", FT_UINT8, BASE_HEX,
            VALS(fec_vc_interfaceparm), 0x0, "VC FEC Interface Parameter ID", HFILL }},

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
            NULL, 0x0, "VC FEC Interface Parameter FCS Length", HFILL }},

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
            NULL, 0x04, "VC FEC Interface Param VCCV CV Type BFD", HFILL }},

        { &hf_ldp_tlv_upstr_sbit,
          { "S-Bit", "ldp.msg.tlv.upstream.sbit", FT_BOOLEAN, 8,
            TFS(&tlv_upstr_sbit_vals), 0x80, "Upstream Label Assignment Capability State Bit", HFILL }},

        { &hf_ldp_tlv_upstr_lbl_req_resvbit,
          { "Reserved Bits", "ldp.msg.tlv.upstream_label_req.resvbit", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_upstr_ass_lbl,
          { "Upstream-Assigned Label", "ldp.msg.tlv.upstream.label", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_upstr_lbl_resvbit,
          { "Reserved Bits", "ldp.msg.tlv.upstream.resvbit", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_ipv4_intID_hop_addr,
          { "IPv4 Next/Previous Hop Address", "ldp.msg.tlv.ipv4_interface_ID.hop_addr", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_logical_intID,
          { "Logical Interface ID", "ldp.msg.tlv.interface_ID.logical_intID", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_ip_multicast_srcaddr,
          { "Source Address", "ldp.msg.tlv.ip_multicast.ipv4_srcaddr", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_ip_multicast_mltcstaddr,
          { "Multicast Group Address", "ldp.msg.tlv.ip_multicast.ipv4_maddr", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_ip_mpls_context_srcaddr,
          { "Source Address", "ldp.msg.tlv.ip_mpls_context.ipv4_srcaddr", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_ldp_p2mp_lsptype,
          { "P2MP Type", "ldp.msg.tlv.ldp_p2mp.type", FT_UINT8, BASE_HEX,
            NULL, 0x0, "TLV Type", HFILL }},

        { &hf_ldp_tlv_ldp_p2mp_addrfam,
          { "Address Family", "ldp.msg.tlv.ldp_p2mp.addr_family", FT_UINT16, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_ldp_p2mp_addrlen,
          { "Address Length", "ldp.msg.tlv.ldp_p2mp.addr_len", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_ldp_p2mp_rtnodeaddr,
          { "Root Node Address", "ldp.msg.tlv.ldp_p2mp.ipv4_rtnodeaddr", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_ldp_p2mp_oplength,
          { "Opaque Length", "ldp.msg.tlv.ldp_p2mp.oplength", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_ldp_p2mp_opvalue,
          { "Opaque Value", "ldp.msg.tlv.ldp_p2mp.opvalue", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_rsvp_te_p2mp_id,
          { "P2MP ID", "ldp.msg.tlv.rsvp_te_p2mp.id", FT_UINT32, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_must_be_zero,
          { "MUST be zero", "ldp.msg.tlv.rsvp_te_p2mp.zero", FT_UINT16, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_tunnel_id,
          { "Tunnel ID", "ldp.msg.tlv.rsvp_te_p2mp.tunnel_id", FT_UINT16, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_ext_tunnel_id,
          { "Extended Tunnel ID", "ldp.msg.tlv.rsvp_te_p2mp.ipv4_ext_tunnel_id", FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_tlv_inv_length,
          { "Invalid length", "ldp.msg.tlv.invalid.length", FT_UINT16, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_returned_pdu_data,
          { "Returned PDU Data", "ldp.returned_pdu_data", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_returned_message_parameters,
          { "Returned Message Parameters", "ldp.returned_message_parameters", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_data,
          { "Data", "ldp.data", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},

        { &hf_ldp_unknown_data,
          { "Unknown Data", "ldp.unknown_data", FT_BYTES, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
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
        &ett_ldp_gen_aai_type2,
        &ett_ldp_sub_tlv
    };

    static ei_register_info ei[] = {
        { &ei_ldp_dtsm_and_target, { "ldp.dtsm_and_target", PI_PROTOCOL, PI_WARN, "ERROR - Both GTSM and Target Flag are enabled.", EXPFILL }},
        { &ei_ldp_gtsm_supported, { "ldp.gtsm_supported", PI_PROTOCOL, PI_CHAT, "GTSM is supported by the source", EXPFILL }},
        { &ei_ldp_gtsm_not_supported_basic_discovery, { "ldp.gtsm_not_supported_basic_discovery", PI_PROTOCOL, PI_WARN, "GTSM is not supported by the source, since basic discovery is not enabled", EXPFILL }},
        { &ei_ldp_gtsm_not_supported, { "ldp.gtsm_not_supported", PI_PROTOCOL, PI_CHAT, "GTSM is not supported by the source", EXPFILL }},
        { &ei_ldp_inv_length, { "ldp.invalid_length", PI_MALFORMED, PI_ERROR, "Length of the packet is malformed", EXPFILL }},
        { &ei_ldp_address_family_not_implemented, { "ldp.address_family_not_implemented", PI_UNDECODED, PI_WARN, "Support for Address Family not implemented", EXPFILL }},
        { &ei_ldp_tlv_fec, { "ldp.msg.tlv.fec.error", PI_PROTOCOL, PI_ERROR, "Error in FEC Element %u", EXPFILL }},
        { &ei_ldp_tlv_fec_len, { "ldp.msg.tlv.fec.len.invalid", PI_PROTOCOL, PI_ERROR, "Invalid prefix %u length for family %s", EXPFILL }},
        { &ei_ldp_tlv_fec_vc_infolength, { "ldp.msg.tlv.fec.vc.infolength.invalid", PI_PROTOCOL, PI_ERROR, "VC FEC size format error", EXPFILL }},
        { &ei_ldp_malformed_interface_parameter, { "ldp.malformed_interface_parameter", PI_MALFORMED, PI_ERROR, "Malformed interface parameter", EXPFILL }},
        { &ei_ldp_malformed_data, { "ldp.malformed_data", PI_MALFORMED, PI_ERROR, "Malformed data", EXPFILL }},
        { &ei_ldp_tlv_fec_type, { "ldp.msg.tlv.fec.unknown", PI_PROTOCOL, PI_WARN, "Unknown FEC TLV type", EXPFILL }},

    };

    module_t *ldp_module;
    expert_module_t* expert_ldp;

    proto_ldp = proto_register_protocol("Label Distribution Protocol", "LDP", "ldp");

    proto_register_field_array(proto_ldp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ldp = expert_register_protocol(proto_ldp);
    expert_register_field_array(expert_ldp, ei, array_length(ei));

    ldp_handle = register_dissector("ldp", dissect_ldp, proto_ldp);
    ldp_tcp_handle = register_dissector("ldp.tcp", dissect_ldp_tcp, proto_ldp);

    /* Register our configuration options for , particularly our port */

    ldp_module = prefs_register_protocol(proto_ldp, NULL);

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
    dissector_add_uint_with_preference("tcp.port", TCP_PORT_LDP, ldp_tcp_handle);
    dissector_add_uint_with_preference("udp.port", UDP_PORT_LDP, ldp_handle);
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
