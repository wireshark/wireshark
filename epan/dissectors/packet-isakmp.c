/* packet-isakmp.c
 * Routines for the Internet Security Association and Key Management Protocol
 * (ISAKMP) (RFC 2408) and the Internet IP Security Domain of Interpretation
 * for ISAKMP (RFC 2407)
 * Brad Robel-Forrest <brad.robel-forrest@watchguard.com>
 *
 * Added routines for the Internet Key Exchange (IKEv2) Protocol
 * (draft-ietf-ipsec-ikev2-17.txt)
 * Shoichi Sakane <sakane@tanu.org>
 *
 * Added routines for RFC3947 Negotiation of NAT-Traversal in the IKE
 *   ronnie sahlberg
 *
 * 04/2009 Added routines for decryption of IKEv2 Encrypted Payload
 *   Naoyoshi Ueda <piyomaru3141@gmail.com>
 *
 * 08/2016 Added decryption using AES-GCM, AES-CCM and AES-CTR
 *         and verification using AES-GCM, AES-CCM
 *   Michal Skalski <mskalski13@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References:
 * IKEv2 https://tools.ietf.org/html/rfc4306
 * IKEv2bis https://tools.ietf.org/html/rfc5996
 *
 * http://www.iana.org/assignments/isakmp-registry (last updated 2011-11-07)
 * http://www.iana.org/assignments/ipsec-registry (last updated 2011-03-14)
 * http://www.iana.org/assignments/ikev2-parameters (last updated 2011-12-19)
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/asn1.h>
#include <epan/reassemble.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/conversation.h>
#include <wsutil/str_util.h>
#include "packet-x509if.h"
#include "packet-x509af.h"
#include "packet-gsm_a_common.h"
#include "packet-isakmp.h"
#include "packet-ber.h"

#include <wsutil/wsgcrypt.h>
#include <epan/proto_data.h>
#include <epan/strutil.h>
#include <epan/uat.h>

void proto_register_isakmp(void);
void proto_reg_handoff_isakmp(void);

typedef struct _attribute_common_fields {
  int all;
  int format;
  int type;
  int length;
  int value;
} attribute_common_fields;

static int proto_isakmp = -1;

static int hf_isakmp_nat_keepalive = -1;
static int hf_isakmp_nat_hash = -1;
static int hf_isakmp_nat_original_address_ipv6 = -1;
static int hf_isakmp_nat_original_address_ipv4 = -1;

static int hf_isakmp_ispi         = -1;
static int hf_isakmp_rspi         = -1;
static int hf_isakmp_typepayload     = -1;
static int hf_isakmp_nextpayload     = -1;
static int hf_isakmp_criticalpayload = -1;
static int hf_isakmp_reserved2       = -1;
static int hf_isakmp_reserved7       = -1;
static int hf_isakmp_reserved        = -1;
static int hf_isakmp_datapayload     = -1;
static int hf_isakmp_extradata       = -1;
static int hf_isakmp_version         = -1;
static int hf_isakmp_mjver           = -1;
static int hf_isakmp_mnver           = -1;
static int hf_isakmp_exchangetype_v1 = -1;
static int hf_isakmp_exchangetype_v2 = -1;
static int hf_isakmp_flags           = -1;
static int hf_isakmp_flag_e          = -1;
static int hf_isakmp_flag_c          = -1;
static int hf_isakmp_flag_a          = -1;
static int hf_isakmp_flag_i          = -1;
static int hf_isakmp_flag_v          = -1;
static int hf_isakmp_flag_r          = -1;
static int hf_isakmp_messageid       = -1;
static int hf_isakmp_length          = -1;
static int hf_isakmp_payloadlen      = -1;
static int hf_isakmp_sa_doi          = -1;
static int hf_isakmp_sa_situation    = -1;
static int hf_isakmp_sa_attribute_next_payload     = -1;
static int hf_isakmp_sa_situation_identity_only    = -1;
static int hf_isakmp_sa_situation_secrecy          = -1;
static int hf_isakmp_sa_situation_integrity        = -1;
static int hf_isakmp_prop_protoid_v1 = -1;
static int hf_isakmp_prop_protoid_v2 = -1;
static int hf_isakmp_prop_number     = -1;
static int hf_isakmp_prop_transforms = -1;
static int hf_isakmp_spisize         = -1;
static int hf_isakmp_spi             = -1;
static int hf_isakmp_trans_number    = -1;
static int hf_isakmp_trans_id        = -1;
static int hf_isakmp_id_type_v1      = -1;
static int hf_isakmp_id_type_v2      = -1;
static int hf_isakmp_id_protoid      = -1;
static int hf_isakmp_id_port         = -1;
static int hf_isakmp_id_data         = -1;
static int hf_isakmp_id_data_ipv4_addr = -1;
static int hf_isakmp_id_data_fqdn    = -1;
static int hf_isakmp_id_data_user_fqdn = -1;
static int hf_isakmp_id_data_ipv4_subnet = -1;
static int hf_isakmp_id_data_ipv4_range_start = -1;
static int hf_isakmp_id_data_ipv4_range_end = -1;
static int hf_isakmp_id_data_ipv6_addr = -1;
static int hf_isakmp_id_data_ipv6_subnet = -1;
static int hf_isakmp_id_data_ipv6_range_start = -1;
static int hf_isakmp_id_data_ipv6_range_end = -1;
static int hf_isakmp_id_data_key_id = -1;
static int hf_isakmp_id_data_cert = -1;
static int hf_isakmp_cert_encoding_v1 = -1;
static int hf_isakmp_cert_encoding_v2 = -1;
static int hf_isakmp_cert_data = -1;
static int hf_isakmp_cert_x509_hash = -1;
static int hf_isakmp_cert_x509_url = -1;
static int hf_isakmp_certreq_type_v1 = -1;
static int hf_isakmp_certreq_type_v2 = -1;
static int hf_isakmp_certreq_authority_v1  = -1;
static int hf_isakmp_certreq_authority_v2 = -1;
static int hf_isakmp_certreq_authority_sig = -1;
static int hf_isakmp_auth_meth = -1;
static int hf_isakmp_auth_data = -1;
static int hf_isakmp_auth_digital_sig_asn1_len = -1;
static int hf_isakmp_auth_digital_sig_asn1_data = -1;
static int hf_isakmp_auth_digital_sig_value = -1;
static int hf_isakmp_notify_doi = -1;
static int hf_isakmp_notify_protoid_v1 = -1;
static int hf_isakmp_notify_protoid_v2 = -1;
static int hf_isakmp_notify_msgtype_v1 = -1;
static int hf_isakmp_notify_msgtype_v2 = -1;
static int hf_isakmp_notify_data = -1;
static int hf_isakmp_notify_data_dpd_are_you_there = -1;
static int hf_isakmp_notify_data_dpd_are_you_there_ack = -1;
static int hf_isakmp_notify_data_unity_load_balance = -1;
static int hf_isakmp_notify_data_accepted_dh_group = -1;
static int hf_isakmp_notify_data_ipcomp_cpi = -1;
static int hf_isakmp_notify_data_ipcomp_transform_id = -1;
static int hf_isakmp_notify_data_auth_lifetime = -1;
static int hf_isakmp_notify_data_redirect_gw_ident_type = -1;
static int hf_isakmp_notify_data_redirect_gw_ident_len = -1;
static int hf_isakmp_notify_data_redirect_new_resp_gw_ident_ipv4 = -1;
static int hf_isakmp_notify_data_redirect_new_resp_gw_ident_ipv6 = -1;
static int hf_isakmp_notify_data_redirect_new_resp_gw_ident_fqdn = -1;
static int hf_isakmp_notify_data_redirect_new_resp_gw_ident = -1;
static int hf_isakmp_notify_data_redirect_nonce_data = -1;
static int hf_isakmp_notify_data_redirect_org_resp_gw_ident_ipv4 = -1;
static int hf_isakmp_notify_data_redirect_org_resp_gw_ident_ipv6 = -1;
static int hf_isakmp_notify_data_redirect_org_resp_gw_ident = -1;
static int hf_isakmp_notify_data_ticket_lifetime = -1;
static int hf_isakmp_notify_data_ticket_data = -1;

static attribute_common_fields hf_isakmp_notify_data_rohc_attr = { -1, -1, -1, -1, -1 };
static int hf_isakmp_notify_data_rohc_attr_max_cid = -1;
static int hf_isakmp_notify_data_rohc_attr_profile = -1;
static int hf_isakmp_notify_data_rohc_attr_integ = -1;
static int hf_isakmp_notify_data_rohc_attr_icv_len = -1;
static int hf_isakmp_notify_data_rohc_attr_mrru = -1;
static int hf_isakmp_notify_data_qcd_token_secret_data = -1;
static int hf_isakmp_notify_data_ha_nonce_data = -1;
static int hf_isakmp_notify_data_ha_expected_send_req_msg_id = -1;
static int hf_isakmp_notify_data_ha_expected_recv_req_msg_id = -1;
static int hf_isakmp_notify_data_ha_incoming_ipsec_sa_delta_value = -1;
static int hf_isakmp_notify_data_secure_password_methods = -1;
static int hf_isakmp_notify_data_signature_hash_algorithms = -1;
static int hf_isakmp_delete_doi = -1;
static int hf_isakmp_delete_protoid_v1 = -1;
static int hf_isakmp_delete_protoid_v2 = -1;
static int hf_isakmp_delete_spi = -1;
static int hf_isakmp_vid_bytes = -1;
static int hf_isakmp_vid_string = -1;
static int hf_isakmp_vid_cp_product = -1;
static int hf_isakmp_vid_cp_version = -1;
static int hf_isakmp_vid_cp_timestamp = -1;
static int hf_isakmp_vid_cp_reserved = -1;
static int hf_isakmp_vid_cp_features = -1;
static int hf_isakmp_vid_cisco_unity_major = -1;
static int hf_isakmp_vid_cisco_unity_minor = -1;
static int hf_isakmp_vid_ms_nt5_isakmpoakley = -1;
static int hf_isakmp_vid_aruba_via_auth_profile = -1;
static int hf_isakmp_vid_fortinet_fortigate_release = -1;
static int hf_isakmp_vid_fortinet_fortigate_build = -1;
static int hf_isakmp_ts_number_of_ts = -1;
static int hf_isakmp_ts_type = -1;
static int hf_isakmp_ts_protoid = -1;
static int hf_isakmp_ts_selector_length = -1;
static int hf_isakmp_ts_start_port = -1;
static int hf_isakmp_ts_end_port = -1;
static int hf_isakmp_ts_start_addr_ipv4 = -1;
static int hf_isakmp_ts_end_addr_ipv4 = -1;
static int hf_isakmp_ts_start_addr_ipv6 = -1;
static int hf_isakmp_ts_end_addr_ipv6 = -1;
static int hf_isakmp_ts_start_addr_fc = -1;
static int hf_isakmp_ts_end_addr_fc = -1;
static int hf_isakmp_ts_start_r_ctl = -1;
static int hf_isakmp_ts_end_r_ctl = -1;
static int hf_isakmp_ts_start_type = -1;
static int hf_isakmp_ts_end_type = -1;
static int hf_isakmp_ts_data = -1;
static int hf_isakmp_num_spis = -1;
static int hf_isakmp_hash = -1;
static int hf_isakmp_sig = -1;
static int hf_isakmp_nonce = -1;

static int hf_isakmp_notify_data_3gpp_backoff_timer_len = -1;

static int hf_isakmp_notify_data_3gpp_device_identity_len = -1;
static int hf_isakmp_notify_data_3gpp_device_identity_type = -1;
static int hf_isakmp_notify_data_3gpp_device_identity_imei = -1;
static int hf_isakmp_notify_data_3gpp_device_identity_imeisv = -1;

static int hf_isakmp_notify_data_3gpp_emergency_call_numbers_len = -1;
static int hf_isakmp_notify_data_3gpp_emergency_call_numbers_spare = -1;
static int hf_isakmp_notify_data_3gpp_emergency_call_numbers_element_len = -1;
static int hf_isakmp_notify_data_3gpp_emergency_call_numbers_flags = -1;

static int hf_isakmp_notify_data_3gpp_emergency_call_numbers_flag_b1_police = -1;
static int hf_isakmp_notify_data_3gpp_emergency_call_numbers_flag_b2_ambulance = -1;
static int hf_isakmp_notify_data_3gpp_emergency_call_numbers_flag_b3_fire_brigade = -1;
static int hf_isakmp_notify_data_3gpp_emergency_call_numbers_flag_b4_marine_guard = -1;
static int hf_isakmp_notify_data_3gpp_emergency_call_numbers_flag_b5_mountain_rescue = -1;

static int hf_iskamp_notify_data_3gpp_emergency_call_number = -1;

static attribute_common_fields hf_isakmp_tek_key_attr = { -1, -1, -1, -1, -1 };

static attribute_common_fields hf_isakmp_ipsec_attr = { -1, -1, -1, -1, -1 };
static int hf_isakmp_ipsec_attr_life_type = -1;
static int hf_isakmp_ipsec_attr_life_duration_uint32 = -1;
static int hf_isakmp_ipsec_attr_life_duration_uint64 = -1;
static int hf_isakmp_ipsec_attr_life_duration_bytes = -1;
static int hf_isakmp_ipsec_attr_group_description = -1;
static int hf_isakmp_ipsec_attr_encap_mode = -1;
static int hf_isakmp_ipsec_attr_auth_algorithm = -1;
static int hf_isakmp_ipsec_attr_key_length = -1;
static int hf_isakmp_ipsec_attr_key_rounds = -1;
static int hf_isakmp_ipsec_attr_cmpr_dict_size = -1;
static int hf_isakmp_ipsec_attr_cmpr_algorithm = -1;
static int hf_isakmp_ipsec_attr_ecn_tunnel = -1;
static int hf_isakmp_ipsec_attr_ext_seq_nbr = -1;
static int hf_isakmp_ipsec_attr_auth_key_length = -1;
static int hf_isakmp_ipsec_attr_sig_enco_algorithm = -1;
static int hf_isakmp_ipsec_attr_addr_preservation = -1;
static int hf_isakmp_ipsec_attr_sa_direction = -1;

static attribute_common_fields hf_isakmp_resp_lifetime_ipsec_attr = { -1, -1, -1, -1, -1 };
static int hf_isakmp_resp_lifetime_ipsec_attr_life_type = -1;
static int hf_isakmp_resp_lifetime_ipsec_attr_life_duration_uint32 = -1;
static int hf_isakmp_resp_lifetime_ipsec_attr_life_duration_uint64 = -1;
static int hf_isakmp_resp_lifetime_ipsec_attr_life_duration_bytes = -1;

static attribute_common_fields hf_isakmp_ike_attr = { -1, -1, -1, -1, -1 };
static int hf_isakmp_ike_attr_encryption_algorithm = -1;
static int hf_isakmp_ike_attr_hash_algorithm = -1;
static int hf_isakmp_ike_attr_authentication_method = -1;
static int hf_isakmp_ike_attr_group_description = -1;
static int hf_isakmp_ike_attr_group_type = -1;
static int hf_isakmp_ike_attr_group_prime = -1;
static int hf_isakmp_ike_attr_group_generator_one = -1;
static int hf_isakmp_ike_attr_group_generator_two = -1;
static int hf_isakmp_ike_attr_group_curve_a = -1;
static int hf_isakmp_ike_attr_group_curve_b = -1;
static int hf_isakmp_ike_attr_life_type = -1;
static int hf_isakmp_ike_attr_life_duration_uint32 = -1;
static int hf_isakmp_ike_attr_life_duration_uint64 = -1;
static int hf_isakmp_ike_attr_life_duration_bytes = -1;
static int hf_isakmp_ike_attr_prf = -1;
static int hf_isakmp_ike_attr_key_length = -1;
static int hf_isakmp_ike_attr_field_size = -1;
static int hf_isakmp_ike_attr_group_order = -1;
static int hf_isakmp_ike_attr_block_size = -1;
static int hf_isakmp_ike_attr_asymmetric_cryptographic_algorithm_type = -1;

static attribute_common_fields hf_isakmp_resp_lifetime_ike_attr = { -1, -1, -1, -1, -1 };
static int hf_isakmp_resp_lifetime_ike_attr_life_type = -1;
static int hf_isakmp_resp_lifetime_ike_attr_life_duration_uint32 = -1;
static int hf_isakmp_resp_lifetime_ike_attr_life_duration_uint64 = -1;
static int hf_isakmp_resp_lifetime_ike_attr_life_duration_bytes = -1;

static int hf_isakmp_trans_type = -1;
static int hf_isakmp_trans_encr = -1;
static int hf_isakmp_trans_prf = -1;
static int hf_isakmp_trans_integ = -1;
static int hf_isakmp_trans_dh = -1;
static int hf_isakmp_trans_esn = -1;
static int hf_isakmp_trans_id_v2 = -1;

static attribute_common_fields hf_isakmp_ike2_attr = { -1, -1, -1, -1, -1 };
static int hf_isakmp_ike2_attr_key_length = -1;

static int hf_isakmp_fragments = -1;
static int hf_isakmp_fragment = -1;
static int hf_isakmp_fragment_overlap = -1;
static int hf_isakmp_fragment_overlap_conflicts = -1;
static int hf_isakmp_fragment_multiple_tails = -1;
static int hf_isakmp_fragment_too_long_fragment = -1;
static int hf_isakmp_fragment_error = -1;
static int hf_isakmp_fragment_count = -1;
static int hf_isakmp_reassembled_in = -1;
static int hf_isakmp_reassembled_length = -1;

static int hf_isakmp_ike2_fragment_number = -1;
static int hf_isakmp_ike2_total_fragments = -1;

static int hf_isakmp_cisco_frag_packetid = -1;
static int hf_isakmp_cisco_frag_seq = -1;
static int hf_isakmp_cisco_frag_last = -1;

static int hf_isakmp_key_exch_dh_group = -1;
static int hf_isakmp_key_exch_data = -1;
static int hf_isakmp_eap_data = -1;

static int hf_isakmp_gspm_data = -1;

static int hf_isakmp_cfg_type_v1 = -1;
static int hf_isakmp_cfg_identifier = -1;
static int hf_isakmp_cfg_type_v2 = -1;

static attribute_common_fields hf_isakmp_cfg_attr = { -1, -1, -1, -1, -1 };
static int hf_isakmp_cfg_attr_type_v1 = -1;
static int hf_isakmp_cfg_attr_type_v2 = -1;

static int hf_isakmp_cfg_attr_internal_ip4_address = -1;
static int hf_isakmp_cfg_attr_internal_ip4_netmask = -1;
static int hf_isakmp_cfg_attr_internal_ip4_dns = -1;
static int hf_isakmp_cfg_attr_internal_ip4_nbns = -1;
static int hf_isakmp_cfg_attr_internal_address_expiry = -1;
static int hf_isakmp_cfg_attr_internal_ip4_dhcp = -1;
static int hf_isakmp_cfg_attr_application_version = -1;
static int hf_isakmp_cfg_attr_internal_ip6_address_ip = -1;
static int hf_isakmp_cfg_attr_internal_ip6_address_prefix = -1;
static int hf_isakmp_cfg_attr_internal_ip6_netmask = -1;
static int hf_isakmp_cfg_attr_internal_ip6_dns = -1;
static int hf_isakmp_cfg_attr_internal_ip6_nbns = -1;
static int hf_isakmp_cfg_attr_internal_ip6_dhcp = -1;
static int hf_isakmp_cfg_attr_internal_ip4_subnet_ip = -1;
static int hf_isakmp_cfg_attr_internal_ip4_subnet_netmask = -1;
static int hf_isakmp_cfg_attr_supported_attributes = -1;
static int hf_isakmp_cfg_attr_internal_ip6_subnet_ip = -1;
static int hf_isakmp_cfg_attr_internal_ip6_subnet_prefix = -1;
static int hf_isakmp_cfg_attr_internal_ip6_link_interface = -1;
static int hf_isakmp_cfg_attr_internal_ip6_link_id = -1;
static int hf_isakmp_cfg_attr_internal_ip6_prefix_ip = -1;
static int hf_isakmp_cfg_attr_internal_ip6_prefix_length = -1;
static int hf_isakmp_cfg_attr_p_cscf_ip4_address = -1;
static int hf_isakmp_cfg_attr_p_cscf_ip6_address = -1;
static int hf_isakmp_cfg_attr_xauth_type = -1;
static int hf_isakmp_cfg_attr_xauth_user_name = -1;
static int hf_isakmp_cfg_attr_xauth_user_password = -1;
static int hf_isakmp_cfg_attr_xauth_passcode = -1;
static int hf_isakmp_cfg_attr_xauth_message = -1;
static int hf_isakmp_cfg_attr_xauth_challenge = -1;
static int hf_isakmp_cfg_attr_xauth_domain = -1;
static int hf_isakmp_cfg_attr_xauth_status = -1;
static int hf_isakmp_cfg_attr_xauth_next_pin = -1;
static int hf_isakmp_cfg_attr_xauth_answer = -1;
static int hf_isakmp_cfg_attr_unity_banner = -1;
static int hf_isakmp_cfg_attr_unity_def_domain = -1;

static int hf_isakmp_sak_next_payload = -1;
static int hf_isakmp_sak_reserved = -1;
static int hf_isakmp_sak_payload_len = -1;
static int hf_isakmp_sak_protocol = -1;
static int hf_isakmp_sak_src_id_type = -1;
static int hf_isakmp_sak_src_id_port = -1;
static int hf_isakmp_sak_src_id_length = -1;
static int hf_isakmp_sak_src_id_data = -1;
static int hf_isakmp_sak_dst_id_type = -1;
static int hf_isakmp_sak_dst_id_port = -1;
static int hf_isakmp_sak_dst_id_length = -1;
static int hf_isakmp_sak_dst_id_data = -1;
static int hf_isakmp_sak_spi = -1;

static int hf_isakmp_sat_next_payload = -1;
static int hf_isakmp_sat_reserved = -1;
static int hf_isakmp_sat_payload_len = -1;
static int hf_isakmp_sat_protocol_id = -1;
static int hf_isakmp_sat_protocol = -1;
static int hf_isakmp_sat_src_id_type = -1;
static int hf_isakmp_sat_src_id_port = -1;
static int hf_isakmp_sat_src_id_length = -1;
static int hf_isakmp_sat_src_id_data = -1;
static int hf_isakmp_sat_dst_id_type = -1;
static int hf_isakmp_sat_dst_id_port = -1;
static int hf_isakmp_sat_dst_id_length = -1;
static int hf_isakmp_sat_dst_id_data = -1;
static int hf_isakmp_sat_transform_id = -1;
static int hf_isakmp_sat_spi = -1;
static int hf_isakmp_sat_payload = -1;

static int hf_isakmp_kd_num_key_pkt = -1;
static int hf_isakmp_kd_payload = -1;
static int hf_isakmp_kdp_type = -1;
static int hf_isakmp_kdp_length = -1;
static int hf_isakmp_kdp_spi_size = -1;
static int hf_isakmp_kdp_spi = -1;

static int hf_isakmp_seq_seq = -1;

static int hf_isakmp_enc_decrypted_data = -1;
static int hf_isakmp_enc_contained_data = -1;
static int hf_isakmp_enc_pad_length= -1;
static int hf_isakmp_enc_padding = -1;
static int hf_isakmp_enc_data = -1;
static int hf_isakmp_enc_iv = -1;
static int hf_isakmp_enc_icd = -1;

static gint ett_isakmp = -1;
static gint ett_isakmp_version = -1;
static gint ett_isakmp_flags = -1;
static gint ett_isakmp_payload = -1;
static gint ett_isakmp_payload_digital_signature = -1;
static gint ett_isakmp_payload_digital_signature_asn1_data = -1;
static gint ett_isakmp_fragment = -1;
static gint ett_isakmp_fragments = -1;
static gint ett_isakmp_sa = -1;
static gint ett_isakmp_attr = -1;
static gint ett_isakmp_id = -1;
static gint ett_isakmp_notify_data = -1;
static gint ett_isakmp_notify_data_3gpp_emergency_call_numbers_main = -1;
static gint ett_isakmp_notify_data_3gpp_emergency_call_numbers_element = -1;
static gint ett_isakmp_ts = -1;
static gint ett_isakmp_kd = -1;
/* For decrypted IKEv2 Encrypted payload*/
static gint ett_isakmp_decrypted_data = -1;
static gint ett_isakmp_decrypted_payloads = -1;

static expert_field ei_isakmp_enc_iv = EI_INIT;
static expert_field ei_isakmp_ikev2_integrity_checksum = EI_INIT;
static expert_field ei_isakmp_enc_data_length_mult_block_size = EI_INIT;
static expert_field ei_isakmp_enc_pad_length_big = EI_INIT;
static expert_field ei_isakmp_attribute_value_empty = EI_INIT;
static expert_field ei_isakmp_payload_bad_length = EI_INIT;
static expert_field ei_isakmp_bad_fragment_number = EI_INIT;
static expert_field ei_isakmp_notify_data_3gpp_unknown_device_identity = EI_INIT;

static dissector_handle_t eap_handle = NULL;
static dissector_handle_t isakmp_handle;


static reassembly_table isakmp_cisco_reassembly_table;
static reassembly_table isakmp_ike2_reassembly_table;

static const fragment_items isakmp_frag_items = {
  /* Fragment subtrees */
  &ett_isakmp_fragment,
  &ett_isakmp_fragments,
  /* Fragment fields */
  &hf_isakmp_fragments,
  &hf_isakmp_fragment,
  &hf_isakmp_fragment_overlap,
  &hf_isakmp_fragment_overlap_conflicts,
  &hf_isakmp_fragment_multiple_tails,
  &hf_isakmp_fragment_too_long_fragment,
  &hf_isakmp_fragment_error,
  &hf_isakmp_fragment_count,
  /* Reassembled in field */
  &hf_isakmp_reassembled_in,
  /* Reassembled length field */
  &hf_isakmp_reassembled_length,
  /* Reassembled data field */
  NULL,
  /* Tag */
  "Message fragments"
};
/* IKE port number assigned by IANA */
#define UDP_PORT_ISAKMP 500
#define TCP_PORT_ISAKMP 500

/*
 * Identifier Type
 *   RFC2407 for IKEv1
 *   RFC3554 for ID_LIST
 *   RFC4306 for IKEv2
 *   RFC4595 for ID_FC_NAME
 */
#define IKE_ID_IPV4_ADDR                1
#define IKE_ID_FQDN                     2
#define IKE_ID_USER_FQDN                3
#define IKE_ID_IPV4_ADDR_SUBNET         4
#define IKE_ID_IPV6_ADDR                5
#define IKE_ID_IPV6_ADDR_SUBNET         6
#define IKE_ID_IPV4_ADDR_RANGE          7
#define IKE_ID_IPV6_ADDR_RANGE          8
#define IKE_ID_DER_ASN1_DN              9
#define IKE_ID_DER_ASN1_GN              10
#define IKE_ID_KEY_ID                   11
#define IKE_ID_LIST                     12
#define IKE_ID_FC_NAME                  12
#define IKE_ID_RFC822_ADDR              3
/*
 * Traffic Selector Type
 *   Not in use for IKEv1
 */
#define IKEV2_TS_IPV4_ADDR_RANGE        7
#define IKEV2_TS_IPV6_ADDR_RANGE        8
#define IKEV2_TS_FC_ADDR_RANGE          9  /* RFC 4595 */
/*
 * Configuration Payload Attribute Types
 *   draft-ietf-ipsec-isakmp-mode-cfg-05.txt for IKEv1
 *   draft-ietf-ipsec-isakmp-xauth-06.txt and draft-beaulieu-ike-xauth-02.txt for XAUTH
 *   RFC4306 for IKEv2
 *   RFC5739 for INTERNAL_IP6_LINK and INTERNAL_IP6_PREFIX
 *   draft-gundavelli-ipsecme-3gpp-ims-options for P_CSCF_IP4_ADDRESS and P_CSCF_IP6_ADDRESS
 */
#define INTERNAL_IP4_ADDRESS            1
#define INTERNAL_IP4_NETMASK            2
#define INTERNAL_IP4_DNS                3
#define INTERNAL_IP4_NBNS               4
#define INTERNAL_ADDRESS_EXPIRY         5
#define INTERNAL_IP4_DHCP               6
#define APPLICATION_VERSION             7
#define INTERNAL_IP6_ADDRESS            8
#define INTERNAL_IP6_NETMASK            9
#define INTERNAL_IP6_DNS                10
#define INTERNAL_IP6_NBNS               11
#define INTERNAL_IP6_DHCP               12
#define INTERNAL_IP4_SUBNET             13
#define SUPPORTED_ATTRIBUTES            14
#define INTERNAL_IP6_SUBNET             15
#define MIP6_HOME_PREFIX                16
#define INTERNAL_IP6_LINK               17
#define INTERNAL_IP6_PREFIX             18
#define P_CSCF_IP4_ADDRESS              20
#define P_CSCF_IP6_ADDRESS              21
/* checkpoint configuration attributes */
#define CHKPT_DEF_DOMAIN                16387
#define CHKPT_MAC_ADDRESS               16388
#define CHKPT_MARCIPAN_REASON_CODE      16389
#define CHKPT_UNKNOWN1                  16400
#define CHKPT_UNKNOWN2                  16401
#define CHKPT_UNKNOWN3                  16402
/* XAUTH configuration attributes */
#define XAUTH_TYPE                      16520
#define XAUTH_USER_NAME                 16521
#define XAUTH_USER_PASSWORD             16522
#define XAUTH_PASSCODE                  16523
#define XAUTH_MESSAGE                   16524
#define XAUTH_CHALLENGE                 16525
#define XAUTH_DOMAIN                    16526
#define XAUTH_STATUS                    16527
#define XAUTH_NEXT_PIN                  16528
#define XAUTH_ANSWER                    16529
/* unity (CISCO) configuration attributes */
#define UNITY_BANNER                    28672
#define UNITY_SAVE_PASSWD               28673
#define UNITY_DEF_DOMAIN                28674
#define UNITY_SPLIT_DOMAIN              28675
#define UNITY_SPLIT_INCLUDE             28676
#define UNITY_NATT_PORT                 28677
#define UNITY_SPLIT_EXCLUDE             28678
#define UNITY_PFS                       28679
#define UNITY_FW_TYPE                   28680
#define UNITY_BACKUP_SERVERS            28681
#define UNITY_DDNS_HOSTNAME             28682

/* Payload Type
* RFC2408 / RFC3547 for IKEv1
* RFC4306 for IKEv2
*/
#define PLOAD_IKE_NONE                  0
#define PLOAD_IKE_SA                    1
#define PLOAD_IKE_P                     2
#define PLOAD_IKE_T                     3
#define PLOAD_IKE_KE                    4
#define PLOAD_IKE_ID                    5
#define PLOAD_IKE_CERT                  6
#define PLOAD_IKE_CR                    7
#define PLOAD_IKE_HASH                  8
#define PLOAD_IKE_SIG                   9
#define PLOAD_IKE_NONCE                 10
#define PLOAD_IKE_N                     11
#define PLOAD_IKE_D                     12
#define PLOAD_IKE_VID                   13
#define PLOAD_IKE_A                     14
#define PLOAD_IKE_SAK                   15
#define PLOAD_IKE_SAT                   16
#define PLOAD_IKE_KD                    17
#define PLOAD_IKE_SEQ                   18
#define PLOAD_IKE_POP                   19
#define PLOAD_IKE_NAT_D                 20
#define PLOAD_IKE_NAT_OA                21
#define PLOAD_IKE_GAP                   22
#define PLOAD_IKE2_SA                   33
#define PLOAD_IKE2_KE                   34
#define PLOAD_IKE2_IDI                  35
#define PLOAD_IKE2_IDR                  36
#define PLOAD_IKE2_CERT                 37
#define PLOAD_IKE2_CERTREQ              38
#define PLOAD_IKE2_AUTH                 39
#define PLOAD_IKE2_NONCE                40
#define PLOAD_IKE2_N                    41
#define PLOAD_IKE2_D                    42
#define PLOAD_IKE2_V                    43
#define PLOAD_IKE2_TSI                  44
#define PLOAD_IKE2_TSR                  45
#define PLOAD_IKE2_SK                   46
#define PLOAD_IKE2_CP                   47
#define PLOAD_IKE2_EAP                  48
#define PLOAD_IKE2_GSPM                 49
#define PLOAD_IKE2_IDG                  50
#define PLOAD_IKE2_GSA                  51
#define PLOAD_IKE2_KD                   52
#define PLOAD_IKE2_SKF                  53
#define PLOAD_IKE_NAT_D13               130
#define PLOAD_IKE_NAT_OA14              131
#define PLOAD_IKE_CISCO_FRAG            132
/*
* IPSEC Situation Definition (RFC2407)
*/
#define SIT_IDENTITY_ONLY       0x01
#define SIT_SECRECY             0x02
#define SIT_INTEGRITY           0x04


static const value_string exchange_v1_type[] = {
  { 0,  "NONE" },
  { 1,  "Base" },
  { 2,  "Identity Protection (Main Mode)" },
  { 3,  "Authentication Only" },
  { 4,  "Aggressive" },
  { 5,  "Informational" },
  { 6,  "Transaction (Config Mode)" },
  { 32, "Quick Mode" },
  { 33, "New Group Mode" },
  { 0,  NULL },
};

static const value_string exchange_v2_type[] = {
  { 34, "IKE_SA_INIT" },
  { 35, "IKE_AUTH" },
  { 36, "CREATE_CHILD_SA" },
  { 37, "INFORMATIONAL" },
  { 38, "IKE_SESSION_RESUME" }, /* RFC5723 */
  { 0,  NULL },
};

static const value_string frag_last_vals[] = {
  { 0,  "More fragments" },
  { 1,  "Last fragment" },
  { 0,  NULL },
};
/* Ex vs_proto */
static const value_string protoid_v1_type[] = {
  { 0,  "RESERVED" },
  { 1,  "ISAKMP" },
  { 2,  "IPSEC_AH" },
  { 3,  "IPSEC_ESP" },
  { 4,  "IPCOMP" },
  { 5,  "GIGABEAM_RADIO" }, /* RFC4705 */
  { 0,  NULL },
};

static const value_string protoid_v2_type[] = {
  { 0,  "RESERVED" },
  { 1,  "IKE" },
  { 2,  "AH" },
  { 3,  "ESP" },
  { 4,  "FC_ESP_HEADER" },
  { 5,  "FC_CT_AUTHENTICATION" },
  { 0,  NULL },
};

static const range_string payload_type[] = {
  { PLOAD_IKE_NONE,PLOAD_IKE_NONE,             "NONE / No Next Payload " },
  { PLOAD_IKE_SA,PLOAD_IKE_SA,                 "Security Association" },
  { PLOAD_IKE_P,PLOAD_IKE_P,                   "Proposal" },
  { PLOAD_IKE_T,PLOAD_IKE_T,                   "Transform" },
  { PLOAD_IKE_KE,PLOAD_IKE_KE,                 "Key Exchange" },
  { PLOAD_IKE_ID,PLOAD_IKE_ID,                 "Identification" },
  { PLOAD_IKE_CERT,PLOAD_IKE_CERT,             "Certificate" },
  { PLOAD_IKE_CR,PLOAD_IKE_CR,                 "Certificate Request" },
  { PLOAD_IKE_HASH,PLOAD_IKE_HASH,             "Hash" },
  { PLOAD_IKE_SIG,PLOAD_IKE_SIG,               "Signature" },
  { PLOAD_IKE_NONCE,PLOAD_IKE_NONCE,           "Nonce" },
  { PLOAD_IKE_N,PLOAD_IKE_N,                   "Notification" },
  { PLOAD_IKE_D,PLOAD_IKE_D,                   "Delete" },
  { PLOAD_IKE_VID,PLOAD_IKE_VID,               "Vendor ID" },
  { PLOAD_IKE_A,PLOAD_IKE_A,                   "Attributes" }, /* draft-ietf-ipsec-isakmp-mode-cfg-05.txt */
  { PLOAD_IKE_SAK,PLOAD_IKE_SAK,               "SA KEK Payload" }, /* Reassigned with RFC3547; formerly: draft-ietf-ipsec-nat-t-ike-04 to 08 */
  { PLOAD_IKE_SAT,PLOAD_IKE_SAT,               "SA TEK Payload"}, /* Reassigned with RFC3547; formerly: draft-ietf-ipsec-nat-t-ike-05 to 08*/
  { PLOAD_IKE_KD,PLOAD_IKE_KD,                 "Key Download" },
  { PLOAD_IKE_SEQ,PLOAD_IKE_SEQ,               "Sequence Number" },
  { PLOAD_IKE_POP,PLOAD_IKE_POP,               "Proof of Possession" }, /* According to RFC6407 deprecated */
  { PLOAD_IKE_NAT_D,PLOAD_IKE_NAT_D,           "NAT-D (RFC 3947)" },
  { PLOAD_IKE_NAT_OA,PLOAD_IKE_NAT_OA,         "NAT-OA (RFC 3947)"},
  { PLOAD_IKE_GAP,PLOAD_IKE_GAP,               "Group Associated Policy"},
  { PLOAD_IKE2_SA,PLOAD_IKE2_SA,               "Security Association"},
  { PLOAD_IKE2_KE,PLOAD_IKE2_KE,               "Key Exchange"},
  { PLOAD_IKE2_IDI,PLOAD_IKE2_IDI,             "Identification - Initiator"},
  { PLOAD_IKE2_IDR,PLOAD_IKE2_IDR,             "Identification - Responder"},
  { PLOAD_IKE2_CERT,PLOAD_IKE2_CERT,           "Certificate"},
  { PLOAD_IKE2_CERTREQ,PLOAD_IKE2_CERTREQ,     "Certificate Request"},
  { PLOAD_IKE2_AUTH,PLOAD_IKE2_AUTH,           "Authentication"},
  { PLOAD_IKE2_NONCE,PLOAD_IKE2_NONCE,         "Nonce"},
  { PLOAD_IKE2_N,PLOAD_IKE2_N,                 "Notify"},
  { PLOAD_IKE2_D,PLOAD_IKE2_D,                 "Delete"},
  { PLOAD_IKE2_V,PLOAD_IKE2_V,                 "Vendor ID"},
  { PLOAD_IKE2_TSI,PLOAD_IKE2_TSI,             "Traffic Selector - Initiator"},
  { PLOAD_IKE2_TSR,PLOAD_IKE2_TSR,             "Traffic Selector - Responder"},
  { PLOAD_IKE2_SK,PLOAD_IKE2_SK,               "Encrypted and Authenticated"},
  { PLOAD_IKE2_CP,PLOAD_IKE2_CP,               "Configuration"},
  { PLOAD_IKE2_EAP,PLOAD_IKE2_EAP,             "Extensible Authentication"},
  { PLOAD_IKE2_GSPM,PLOAD_IKE2_GSPM,           "Generic Secure Password Method"},
  { PLOAD_IKE2_IDG,PLOAD_IKE2_IDG,             "Group Identification"},
  { PLOAD_IKE2_GSA,PLOAD_IKE2_GSA,             "Group Security Association"},
  { PLOAD_IKE2_KD,PLOAD_IKE2_KD,               "Key Download"},
  { PLOAD_IKE2_SKF,PLOAD_IKE2_SKF,             "Encrypted and Authenticated Fragment"},
  { 54,127,                                    "Unassigned"     },
  { 128,129,                                   "Private Use"   },
  { PLOAD_IKE_NAT_D13,PLOAD_IKE_NAT_D13,       "NAT-D (draft-ietf-ipsec-nat-t-ike-01 to 03)"},
  { PLOAD_IKE_NAT_OA14,PLOAD_IKE_NAT_OA14,     "NAT-OA (draft-ietf-ipsec-nat-t-ike-01 to 03)"},
  { PLOAD_IKE_CISCO_FRAG,PLOAD_IKE_CISCO_FRAG, "Cisco-Fragmentation"},
  { 133,256,                                   "Private Use"   },
  { 0,0,        NULL },
  };

/*
 * ISAKMP Domain of Interpretation (DOI)
 *   RFC2408 for ISAKMP
 *   RFC2407 for IPSEC
 *   RFC3547 for GDOI
 */
static const value_string doi_type[] = {
  { 0,  "ISAKMP" },
  { 1,  "IPSEC" },
  { 2,  "GDOI" },
  { 0,  NULL },
};

/* Transform Type */

#define IPSEC_ATTR_LIFE_TYPE                   1
#define IPSEC_ATTR_LIFE_DURATION               2
#define IPSEC_ATTR_GROUP_DESC                  3
#define IPSEC_ATTR_ENCAP_MODE                  4
#define IPSEC_ATTR_AUTH_ALGORITHM              5
#define IPSEC_ATTR_KEY_LENGTH                  6
#define IPSEC_ATTR_KEY_ROUNDS                  7
#define IPSEC_ATTR_CMPR_DICT_SIZE              8
#define IPSEC_ATTR_CMPR_ALGORITHM              9
#define IPSEC_ATTR_ECN_TUNNEL                  10      /* [RFC3168] */
#define IPSEC_ATTR_EXT_SEQ_NBR                 11      /* [RFC4304] */
#define IPSEC_ATTR_AUTH_KEY_LENGTH             12      /* [RFC4359] */
#define IPSEC_ATTR_SIG_ENCO_ALGORITHM          13      /* [RFC4359] */
#define IPSEC_ATTR_ADDR_PRESERVATION           14      /* [RFC6407] */
#define IPSEC_ATTR_SA_DIRECTION                15      /* [RFC6407] */

static const range_string ipsec_attr_type[] = {
  { 1,1,         "SA-Life-Type" },
  { 2,2,         "SA-Life-Duration" },
  { 3,3,         "Group-Description" },
  { 4,4,         "Encapsulation-Mode" },
  { 5,5,         "Authentication-Algorithm" },
  { 6,6,         "Key-Length" },
  { 7,7,         "Key-Rounds" },
  { 8,8,         "Compress-Dictionary-Size" },
  { 9,9,         "Compress-Private-Algorithm" },
  { 10,10,       "ECN Tunnel" },
  { 11,11,       "Extended (64-bit) Sequence Number" },
  { 12,12,       "Authentication Key Length" },
  { 13,13,       "Signature Encoding Algorithm" },
  { 14,14,       "Address Preservation" },
  { 15,15,       "SA Direction" },
  { 16,32000,    "Unassigned (Future use)" },
  { 32001,32767, "Private use" },
  { 0,0,         NULL },
};

#define KEY_ATTR_TEK_RSERVED                   0
#define KEY_ATTR_TEK_ALGORITHM                 1
#define KEY_ATTR_TEK_INTEGRITY                 2
#define KEY_ATTR_TEK_SRC_AUTH                  3

static const range_string tek_key_attr_type[] = {
  { 1,1,         "TEK_ALGORITHM_KEY" },
  { 2,2,         "TEK_INTEGRITY_KEY" },
  { 3,3,         "TEK_SOURCE_AUTH_KEY" },
  { 4,137,       "Unassigned (Future use)" },
  { 128,255,     "Private use" },
  { 256,32767,   "Unassigned (Future use)" },
  { 0,0,         NULL },
};

/* Transform IKE Type */
#define IKE_ATTR_ENCRYPTION_ALGORITHM   1
#define IKE_ATTR_HASH_ALGORITHM                 2
#define IKE_ATTR_AUTHENTICATION_METHOD  3
#define IKE_ATTR_GROUP_DESCRIPTION              4
#define IKE_ATTR_GROUP_TYPE                             5
#define IKE_ATTR_GROUP_PRIME                    6
#define IKE_ATTR_GROUP_GENERATOR_ONE    7
#define IKE_ATTR_GROUP_GENERATOR_TWO    8
#define IKE_ATTR_GROUP_CURVE_A                  9
#define IKE_ATTR_GROUP_CURVE_B                  10
#define IKE_ATTR_LIFE_TYPE                              11
#define IKE_ATTR_LIFE_DURATION                  12
#define IKE_ATTR_PRF                                    13
#define IKE_ATTR_KEY_LENGTH                             14
#define IKE_ATTR_FIELD_SIZE                             15
#define IKE_ATTR_GROUP_ORDER                    16
#define IKE_ATTR_BLOCK_SIZE                     17
#define IKE_ATTR_ACAT                           20



static const range_string ike_attr_type[] = {
  { 1,1,         "Encryption-Algorithm" },
  { 2,2,         "Hash-Algorithm" },
  { 3,3,         "Authentication-Method" },
  { 4,4,         "Group-Description" },
  { 5,5,         "Group-Type" },
  { 6,6,         "Group-Prime" },
  { 7,7,         "Group-Generator-One" },
  { 8,8,         "Group-Generator-Two" },
  { 9,9,         "Group-Curve-A" },
  { 10,10,       "Group-Curve-B" },
  { 11,11,       "Life-Type" },
  { 12,12,       "Life-Duration" },
  { 13,13,       "PRF" },
  { 14,14,       "Key-Length" },
  { 15,15,       "Field-Size" },
  { 16,16,       "Group-Order" },
  { 17,17,       "Block-Size" },
  { 18,19,       "Unassigned (Future use)" },
  { 20,20,       "Asymmetric-Cryptographic-Algorithm-Type" },
  { 21,16383,    "Unassigned (Future use)" },
  { 16384,32767, "Private use" },
  { 0,0,         NULL },
};

#if 0
static const value_string vs_v2_sttr[] = {
  { 1,  "SA-Life-Type" },
  { 2,  "SA-Life-Duration" },
  { 3,  "Group-Description" },
  { 4,  "Encapsulation-Mode" },
  { 5,  "Authentication-Algorithm" },
  { 6,  "Key-Length" },
  { 7,  "Key-Rounds" },
  { 8,  "Compress-Dictionary-Size" },
  { 9,  "Compress-Private-Algorithm" },
  { 10, "ECN Tunnel" },
  { 0,  NULL },
};
#endif

static const value_string vs_v1_trans_isakmp[] = {
  { 0,  "RESERVED" },
  { 1,  "KEY_IKE" },
  { 0,  NULL },
};

static const value_string vs_v1_trans_ah[] = {
  { 0,  "RESERVED" },
  { 1,  "RESERVED" },
  { 2,  "MD5" },
  { 3,  "SHA" },
  { 4,  "DES" },
  { 5,  "SHA2-256" },
  { 6,  "SHA2-384" },
  { 7,  "SHA2-512" },
  { 0,  NULL },
};

static const value_string vs_v1_trans_esp[] = {
  { 0,  "RESERVED" },
  { 1,  "DES-IV64" },
  { 2,  "DES" },
  { 3,  "3DES" },
  { 4,  "RC5" },
  { 5,  "IDEA" },
  { 6,  "CAST" },
  { 7,  "BLOWFISH" },
  { 8,  "3IDEA" },
  { 9,  "DES-IV32" },
  { 10, "RC4" },
  { 11, "NULL" },
  { 12, "AES" },
  { 0,  NULL },
};

static const value_string transform_id_ipcomp[] = {
  { 0,  "RESERVED" },
  { 1,  "OUI" },
  { 2,  "DEFLATE" },
  { 3,  "LZS" },
  { 4,  "LZJH" },
  { 0,  NULL },
};
static const value_string redirect_gateway_identity_type[] = {
  { 1,  "IPv4 address" },
  { 2,  "IPv6 address" },
  { 3,  "FQDN" },
  { 0,  NULL },
};
static const value_string attr_life_type[] = {
  { 0,  "RESERVED" },
  { 1,  "Seconds" },
  { 2,  "Kilobytes" },
  { 0,  NULL },
};

static const value_string ipsec_attr_encap_mode[] = {
  { 0,  "RESERVED" },
  { 1,  "Tunnel" },
  { 2,  "Transport" },
  { 3,  "UDP-Encapsulated-Tunnel" }, /* RFC3947 */
  { 4,  "UDP-Encapsulated-Transport" }, /* RFC3947 */
  { 61440,      "Check Point IPSec UDP Encapsulation" },
  { 61443,      "UDP-Encapsulated-Tunnel (draft)" },
  { 61444,      "UDP-Encapsulated-Transport (draft)" },
  { 0,  NULL },
};

static const value_string ipsec_attr_auth_algo[] = {
  { 0,  "RESERVED" },
  { 1,  "HMAC-MD5" },
  { 2,  "HMAC-SHA" },
  { 3,  "DES-MAC" },
  { 4,  "KPDK" },
  { 5,  "HMAC-SHA2-256" },
  { 6,  "HMAC-SHA2-384" },
  { 7,  "HMAC-SHA2-512" },
  { 8,  "HMAC-RIPEMD" },                /* [RFC2857] */
  { 9,  "AES-XCBC-MAC" },               /* [RFC3566] */
  { 10, "SIG-RSA" },                    /* [RFC4359] */
  { 11, "AES-128-GMAC" },               /* [RFC4543][Errata1821] */
  { 12, "AES-192-GMAC" },               /* [RFC4543][Errata1821] */
  { 13, "AES-256-GMAC" },               /* [RFC4543][Errata1821] */

/*
        Values 11-61439 are reserved to IANA.  Values 61440-65535 are
        for private use.
*/
  { 0,  NULL },
};

#define ENC_DES_CBC             1
#define ENC_IDEA_CBC            2
#define ENC_BLOWFISH_CBC        3
#define ENC_RC5_R16_B64_CBC     4
#define ENC_3DES_CBC            5
#define ENC_CAST_CBC            6
#define ENC_AES_CBC             7
#define ENC_CAMELLIA_CBC        8
#define ENC_SM4_CBC_DEPRECATED  127
#define ENC_SM1_CBC             128
#define ENC_SM4_CBC             129

static const value_string ike_attr_enc_algo[] = {
  { 0,                          "RESERVED" },
  { ENC_DES_CBC,                "DES-CBC" },
  { ENC_IDEA_CBC,               "IDEA-CBC" },
  { ENC_BLOWFISH_CBC,           "BLOWFISH-CBC" },
  { ENC_RC5_R16_B64_CBC,        "RC5-R16-B64-CBC" },
  { ENC_3DES_CBC,               "3DES-CBC" },
  { ENC_CAST_CBC,               "CAST-CBC" },
  { ENC_AES_CBC,                "AES-CBC" },
  { ENC_CAMELLIA_CBC,           "CAMELLIA-CBC" },
  { ENC_SM4_CBC_DEPRECATED,     "SM4-CBC (DEPRECATED)" },
  { ENC_SM1_CBC,                "SM1-CBC" },
  { ENC_SM4_CBC,                "SM4-CBC" },
  { 0,  NULL },
};

#define HMAC_MD5        1
#define HMAC_SHA        2
#define HMAC_TIGER      3
#define HMAC_SHA2_256   4
#define HMAC_SHA2_384   5
#define HMAC_SHA2_512   6
#define HMAC_SM3        20

static const value_string ike_attr_hash_algo[] = {
  { 0,                  "RESERVED" },
  { HMAC_MD5,           "MD5" },
  { HMAC_SHA,           "SHA" },
  { HMAC_TIGER,         "TIGER" },
  { HMAC_SHA2_256,      "SHA2-256" },
  { HMAC_SHA2_384,      "SHA2-384" },
  { HMAC_SHA2_512,      "SHA2-512" },
  { HMAC_SM3,           "SM3" },
  { 0,  NULL },
};

#define ASYMMETRIC_RSA   1
#define ASYMMETRIC_SM2   2

static const value_string ike_attr_asym_algo[] = {
  { ASYMMETRIC_RSA,      "RSA" },
  { ASYMMETRIC_SM2,      "SM2" },
  { 0,  NULL },
};

static const value_string ipsec_attr_ecn_tunnel[] = {
  { 0, "RESERVED" },
  { 1, "Allowed" },
  { 2, "Forbidden" },
  { 0,  NULL },
};

static const value_string ipsec_attr_ext_seq_nbr[] = {
  { 0, "RESERVED" },
  { 1, "64-bit Sequence Number" },
  { 0,  NULL },
};

#if 0
static const value_string transform_attr_sig_enco_algo_type[] = {
  { 0, "RESERVED" },
  { 1, "RSASSA-PKCS1-v1_5" },
  { 2, "RSASSA-PSS" },
  { 0,  NULL },
};
#endif

static const value_string ipsec_attr_addr_preservation[] = {
  { 0, "Reserved" },
  { 1, "None" },
  { 2, "Source-Only" },
  { 3, "Destination-Only" },
  { 4, "Source-and-Destination" },
  { 0,  NULL },
};

static const value_string ipsec_attr_sa_direction[] = {
  { 0, "Reserved" },
  { 1, "Sender-Only" },
  { 2, "Receiver-Only" },
  { 3, "Symmetric" },
  { 0,  NULL },
};

static const value_string ike_attr_authmeth[] = {
  /* ipsec-registry.xhtml */
  { 0,     "RESERVED" },
  { 1,     "Pre-shared key" },
  { 2,     "DSS signatures" },
  { 3,     "RSA signatures" },
  { 4,     "Encryption with RSA" },
  { 5,     "Revised encryption with RSA" },
  { 6,     "Reserved (was Encryption with El-Gamal)" },
  { 7,     "Reserved (was Revised encryption with El-Gamal)" },
  { 8,     "Reserved (was ECDSA signatures)" },
  { 9,     "ECDSA with SHA-256 on the P-256 curve" },
  { 10,    "ECDSA with SHA-384 on the P-384 curve" },
  { 11,    "ECDSA with SHA-512 on the P-521 curve" },
  /* draft-ietf-ipsec-isakmp-hybrid-auth-05 */
  { 64221, "HybridInitRSA" },
  { 64222, "HybridRespRSA" },
  { 64223, "HybridInitDSS" },
  { 64224, "HybridRespDSS" },
  /* draft-beaulieu-ike-xauth-02 */
  { 65001, "XAUTHInitPreShared" },
  { 65002, "XAUTHRespPreShared" },
  { 65003, "XAUTHInitDSS" },
  { 65004, "XAUTHRespDSS" },
  { 65005, "XAUTHInitRSA" },
  { 65006, "XAUTHRespRSA" },
  { 65007, "XAUTHInitRSAEncryption" },
  { 65008, "XAUTHRespRSAEncryption" },
  { 65009, "XAUTHInitRSARevisedEncryption" },
  { 65010, "XAUTHRespRSARevisedEncryption" },
  { 0,  NULL },
};

static const value_string dh_group[] = {
  { 0,  "UNDEFINED - 0" },
  { 1,  "Default 768-bit MODP group" },
  { 2,  "Alternate 1024-bit MODP group" },
  { 3,  "EC2N group on GP[2^155] group" },
  { 4,  "EC2N group on GP[2^185] group" },
  { 5,  "1536 bit MODP group" },
  { 6,  "EC2N group over GF[2^163]" },
  { 7,  "EC2N group over GF[2^163]" },
  { 8,  "EC2N group over GF[2^283]" },
  { 9,  "EC2N group over GF[2^283]" },
  { 10, "EC2N group over GF[2^409]" },
  { 11, "EC2N group over GF[2^409]" },
  { 12, "EC2N group over GF[2^571]" },
  { 13, "EC2N group over GF[2^571]" },
  { 14, "2048 bit MODP group" },
  { 15, "3072 bit MODP group" },
  { 16, "4096 bit MODP group" },
  { 17, "6144 bit MODP group" },
  { 18, "8192 bit MODP group" },
  { 19, "256-bit random ECP group" },
  { 20, "384-bit random ECP group" },
  { 21, "521-bit random ECP group" },
  { 22, "1024-bit MODP Group with 160-bit Prime Order Subgroup" },
  { 23, "2048-bit MODP Group with 224-bit Prime Order Subgroup" },
  { 24, "2048-bit MODP Group with 256-bit Prime Order Subgroup" },
  { 25, "192-bit Random ECP Group" },
  { 26, "224-bit Random ECP Group" },
  { 27, "224-bit Brainpool ECP group" },
  { 28, "256-bit Brainpool ECP group" },
  { 29, "384-bit Brainpool ECP group" },
  { 30, "512-bit Brainpool ECP group" },
  { 0,  NULL }
};

static const value_string ike_attr_grp_type[] = {
  { 0,  "UNDEFINED - 0" },
  { 1,  "MODP" },
  { 2,  "ECP" },
  { 3,  "EC2N" },
  { 0,  NULL },
};

#define TF_IKE2_ENCR    1
#define TF_IKE2_PRF     2
#define TF_IKE2_INTEG   3
#define TF_IKE2_DH      4
#define TF_IKE2_ESN     5
static const range_string transform_ike2_type[] = {
  { 0,0,        "RESERVED" },
  { TF_IKE2_ENCR,TF_IKE2_ENCR,  "Encryption Algorithm (ENCR)" },
  { TF_IKE2_PRF,TF_IKE2_PRF,    "Pseudo-random Function (PRF)"},
  { TF_IKE2_INTEG,TF_IKE2_INTEG,"Integrity Algorithm (INTEG)"},
  { TF_IKE2_DH,TF_IKE2_DH,      "Diffie-Hellman Group (D-H)"},
  { TF_IKE2_ESN,TF_IKE2_ESN,    "Extended Sequence Numbers (ESN)"},
  { 6,240,      "Reserved to IANA"},
  { 241,255,    "Private Use"},
  { 0,0,                NULL },
};
/* For Transform Type 1 (Encryption Algorithm), defined Transform IDs */
static const value_string transform_ike2_encr_type[] = {
  { 0,  "RESERVED" },
  { 1,  "ENCR_DES_IV64" },
  { 2,  "ENCR_DES" },
  { 3,  "ENCR_3DES" },
  { 4,  "ENCR_RC5" },
  { 5,  "ENCR_IDEA" },
  { 6,  "ENCR_CAST" },
  { 7,  "ENCR_BLOWFISH" },
  { 8,  "ENCR_3IDEA" },
  { 9,  "ENCR_DES_IV32" },
  { 10, "RESERVED" },
  { 11, "ENCR_NULL" },
  { 12, "ENCR_AES_CBC" },
  { 13, "ENCR_AES_CTR" },                               /* [RFC3686] */
  { 14, "ENCR_AES-CCM_8" },                             /* [RFC4309] */
  { 15, "ENCR-AES-CCM_12" },                            /* [RFC4309] */
  { 16, "ENCR-AES-CCM_16" },                            /* [RFC4309] */
  { 17, "UNASSIGNED" },
  { 18, "AES-GCM with a 8 octet ICV" },                 /* [RFC4106] */
  { 19, "AES-GCM with a 12 octet ICV" },                /* [RFC4106] */
  { 20, "AES-GCM with a 16 octet ICV" },                /* [RFC4106] */
  { 21, "ENCR_NULL_AUTH_AES_GMAC" },                    /* [RFC4543] */
  { 22, "Reserved for IEEE P1619 XTS-AES" },            /* [Ball] */
  { 23, "ENCR_CAMELLIA_CBC" },                          /* [RFC5529] */
  { 24, "ENCR_CAMELLIA_CTR" },                          /* [RFC5529] */
  { 25, "ENCR_CAMELLIA_CCM with an 8-octet ICV" },      /* [RFC5529] */
  { 26, "ENCR_CAMELLIA_CCM with a 12-octet ICV" },      /* [RFC5529] */
  { 27, "ENCR_CAMELLIA_CCM with a 16-octet ICV" },      /* [RFC5529] */
  { 28, "ENCR_CHACHA20_POLY1305" },                     /* [RFC7634] */
/*
 *              29-1023    RESERVED TO IANA         [RFC4306]
 *              1024-65535    PRIVATE USE           [RFC4306]
 */
    { 0,        NULL },
  };

/* For Transform Type 2 (Pseudo-random Function), defined Transform IDs */
static const value_string transform_ike2_prf_type[] = {
  { 0,  "RESERVED" },
  { 1,  "PRF_HMAC_MD5" },
  { 2,  "PRF_HMAC_SHA1" },
  { 3,  "PRF_HMAC_TIGER" },
  { 4,  "PRF_AES128_CBC" },
  { 5,  "PRF_HMAC_SHA2_256" },          /* [RFC4868] */
  { 6,  "PRF_HMAC_SHA2_384" },          /* [RFC4868] */
  { 7,  "PRF_HMAC_SHA2_512" },          /* [RFC4868] */
  { 8,  "PRF_AES128_CMAC6" },           /* [RFC4615] */
/*
     9-1023    RESERVED TO IANA            [RFC4306]
     1024-65535    PRIVATE USE             [RFC4306]
*/
  { 0,  NULL },
};

/* For Transform Type 3 (Integrity Algorithm), defined Transform IDs */
static const value_string transform_ike2_integ_type[] = {
  { 0,  "NONE" },
  { 1,  "AUTH_HMAC_MD5_96" },
  { 2,  "AUTH_HMAC_SHA1_96" },
  { 3,  "AUTH_DES_MAC" },
  { 4,  "AUTH_KPDK_MD5" },
  { 5,  "AUTH_AES_XCBC_96" },
  { 6,  "AUTH_HMAC_MD5_128" },          /* [RFC4595] */
  { 7,  "AUTH_HMAC_SHA1_160" },         /* [RFC4595] */
  { 8,  "AUTH_AES_CMAC_96" },           /* [RFC4494] */
  { 9,  "AUTH_AES_128_GMAC" },          /* [RFC4543] */
  { 10, "AUTH_AES_192_GMAC" },          /* [RFC4543] */
  { 11, "AUTH_AES_256_GMAC" },          /* [RFC4543] */
  { 12, "AUTH_HMAC_SHA2_256_128" },     /* [RFC4868] */
  { 13, "AUTH_HMAC_SHA2_384_192" },     /* [RFC4868] */
  { 14, "AUTH_HMAC_SHA2_512_256" },     /* [RFC4868] */
/*
 15-1023    RESERVED TO IANA               [RFC4306]
 1024-65535    PRIVATE USE                 [RFC4306]
*/
  { 0,  NULL },
};
/* For Transform Type 5 (Extended Sequence Numbers), defined Transform */
static const value_string transform_ike2_esn_type[] = {
  { 0,  "No Extended Sequence Numbers" },
  { 1,  "Extended Sequence Numbers" },
  { 0,  NULL },
};
/* Transform IKE2 Type */
#define IKE2_ATTR_KEY_LENGTH            14

static const range_string transform_ike2_attr_type[] = {
  { 0,13,        "Reserved" },
  { 14,14,       "Key Length" },
  { 15,17,       "Reserved" },
  { 18,16383,    "Unassigned (Future use)" },
  { 16384,32767, "Private use" },
  { 0,0,         NULL },
};

static const range_string cert_v1_type[] = {
  { 0,0,        "NONE" },
  { 1,1,        "PKCS #7 wrapped X.509 certificate" },
  { 2,2,        "PGP Certificate" },
  { 3,3,        "DNS Signed Key" },
  { 4,4,        "X.509 Certificate - Signature" },
  { 5,5,        "X.509 Certificate - Key Exchange" },
  { 6,6,        "Kerberos Tokens" },
  { 7,7,        "Certificate Revocation List (CRL)" },
  { 8,8,        "Authority Revocation List (ARL)" },
  { 9,9,        "SPKI Certificate" },
  { 10,10,      "X.509 Certificate - Attribute" },
  { 11,255,     "RESERVED" },
  { 0,0,        NULL },
};

static const range_string cert_v2_type[] = {
  { 0,0,        "RESERVED" },
  { 1,1,        "PKCS #7 wrapped X.509 certificate" },
  { 2,2,        "PGP Certificate" },
  { 3,3,        "DNS Signed Key" },
  { 4,4,        "X.509 Certificate - Signature" },
  { 5,5,        "*undefined by any document*" },
  { 6,6,        "Kerberos Tokens" },
  { 7,7,        "Certificate Revocation List (CRL)" },
  { 8,8,        "Authority Revocation List (ARL)" },
  { 9,9,        "SPKI Certificate" },
  { 10,10,      "X.509 Certificate - Attribute" },
  { 11,11,      "Raw RSA Key" },
  { 12,12,      "Hash and URL of X.509 certificate" },
  { 13,13,      "Hash and URL of X.509 bundle" },
  { 14,14,      "OCSP Content" },                       /* [RFC4806] */
  { 15,200,     "RESERVED to IANA" },
  { 201,255,    "PRIVATE USE" },
  { 0,0,        NULL },
};

#define AUTH_METH_DIGITAL_SIGNATURE 14

static const range_string authmeth_v2_type[] = {
  { 0,0,        "RESERVED TO IANA" },
  { 1,1,        "RSA Digital Signature" },
  { 2,2,        "Shared Key Message Integrity Code" },
  { 3,3,        "DSS Digital Signature" },
  { 4,8,        "RESERVED TO IANA" },
  { 9,9,        "ECDSA with SHA-256 on the P-256 curve" }, /* RFC4754 */
  { 10,10,      "ECDSA with SHA-384 on the P-384 curve" }, /* RFC4754 */
  { 11,11,      "ECDSA with SHA-512 on the P-521 curve" }, /* RFC4754 */
  { 12,12,      "Generic Secure Password Authentication Method" }, /* RFC6467 */
  { 13,13,      "NULL Authentication" },                   /* RFC7619 */
  { 14,14,      "Digital Signature" },                     /* RFC7427 */
  { 15,200,     "RESERVED TO IANA" },
  { 201,255,    "PRIVATE USE" },
  { 0,0,        NULL },
};

static const range_string notifmsg_v1_type[] = {
  { 0,0,        "<UNKNOWN>" },
  { 1,1,        "INVALID-PAYLOAD-TYPE" },
  { 2,2,        "DOI-NOT-SUPPORTED" },
  { 3,3,        "SITUATION-NOT-SUPPORTED" },
  { 4,4,        "INVALID-COOKIE" },
  { 5,5,        "INVALID-MAJOR-VERSION" },
  { 6,6,        "INVALID-MINOR-VERSION" },
  { 7,7,        "INVALID-EXCHANGE-TYPE" },
  { 8,8,        "INVALID-FLAGS" },
  { 9,9,        "INVALID-MESSAGE-ID" },
  { 10,10,      "INVALID-PROTOCOL-ID" },
  { 11,11,      "INVALID-SPI" },
  { 12,12,      "INVALID-TRANSFORM-ID" },
  { 13,13,      "ATTRIBUTES-NOT-SUPPORTED" },
  { 14,14,      "NO-PROPOSAL-CHOSEN" },
  { 15,15,      "BAD-PROPOSAL-SYNTAX" },
  { 16,16,      "PAYLOAD-MALFORMED" },
  { 17,17,      "INVALID-KEY-INFORMATION" },
  { 18,18,      "INVALID-ID-INFORMATION" },
  { 19,19,      "INVALID-CERT-ENCODING" },
  { 20,20,      "INVALID-CERTIFICATE" },
  { 21,21,      "CERT-TYPE-UNSUPPORTED" },
  { 22,22,      "INVALID-CERT-AUTHORITY" },
  { 23,23,      "INVALID-HASH-INFORMATION" },
  { 24,24,      "AUTHENTICATION-FAILED" },
  { 25,25,      "INVALID-SIGNATURE" },
  { 26,26,      "ADDRESS-NOTIFICATION" },
  { 27,27,      "NOTIFY-SA-LIFETIME" },
  { 28,28,      "CERTIFICATE-UNAVAILABLE" },
  { 29,29,      "UNSUPPORTED-EXCHANGE-TYPE" },
  { 30,30,      "UNEQUAL-PAYLOAD-LENGTHS" },
  { 31,8191,    "RESERVED (Future Use)" },
  { 8192,16383, "Private Use" },
  { 16384,16384,"CONNECTED" },
  { 16385,24575,"RESERVED (Future Use)" },
  { 24576,24576,"RESPONDER-LIFETIME" },
  { 24577,24577,"REPLAY-STATUS" },
  { 24578,24578,"INITIAL-CONTACT" },
  { 24579,32767,"DOI-specific codes" },
  { 32768,36135,"Private Use" },
  { 36136,36136,"R-U-THERE"  },
  { 36137,36137,"R-U-THERE-ACK"  },
  { 36138,40500,"Private Use" },
  { 40501,40501,"UNITY-LOAD-BALANCE" },
  { 40502,40502,"UNITY-UNKNOWN" },
  { 40503,40503,"UNITY-GROUP-HASH" },
  { 40503,40959,"Private Use" },
  { 40960,65535,"RESERVED (Future Use)" },
  { 0,0,        NULL },
};

static const range_string notifmsg_v2_type[] = {
  { 0,0,        "RESERVED" },
  { 1,1,        "UNSUPPORTED_CRITICAL_PAYLOAD" },
  { 2,3,        "RESERVED" },
  { 4,4,        "INVALID_IKE_SPI" },
  { 5,5,        "INVALID_MAJOR_VERSION" },
  { 6,6,        "RESERVED" },
  { 7,7,        "INVALID_SYNTAX" },
  { 8,8,        "RESERVED" },
  { 9,9,        "INVALID_MESSAGE_ID" },
  { 10,10,      "RESERVED" },
  { 11,11,      "INVALID_SPI" },
  { 12,13,      "RESERVED" },
  { 14,14,      "NO_PROPOSAL_CHOSEN" },
  { 15,16,      "RESERVED" },
  { 17,17,      "INVALID_KE_PAYLOAD" },
  { 24,24,      "AUTHENTICATION_FAILED" },
  { 25,33,      "RESERVED" },
  { 34,34,      "SINGLE_PAIR_REQUIRED" },
  { 35,35,      "NO_ADDITIONAL_SAS" },
  { 36,36,      "INTERNAL_ADDRESS_FAILURE" },
  { 37,37,      "FAILED_CP_REQUIRED" },
  { 38,38,      "TS_UNACCEPTABLE" },
  { 39,39,      "INVALID_SELECTORS" },
  { 40,40,      "UNACCEPTABLE_ADDRESSES" },                     /* RFC4555 */
  { 41,41,      "UNEXPECTED_NAT_DETECTED" },                    /* RFC4555 */
  { 42,42,      "USE_ASSIGNED_HoA" },                           /* RFC5026 */
  { 43,43,      "TEMPORARY_FAILURE" },                          /* RFC5996 */
  { 44,44,      "CHILD_SA_NOT_FOUND" },                         /* RFC5996 */
  { 45,45,      "INVALID_GROUP_ID" },                           /* draft-yeung-g-ikev2 */
  { 46,46,      "CHILD_SA_NOT_FOUND" },                         /* draft-yeung-g-ikev2 */
  { 47,8191,    "RESERVED TO IANA - Error types" },
  { 8192,16383,         "Private Use - Errors" },
  { 16384,16384,        "INITIAL_CONTACT" },
  { 16385,16385,        "SET_WINDOW_SIZE" },
  { 16386,16386,        "ADDITIONAL_TS_POSSIBLE" },
  { 16387,16387,        "IPCOMP_SUPPORTED" },
  { 16388,16388,        "NAT_DETECTION_SOURCE_IP" },
  { 16389,16389,        "NAT_DETECTION_DESTINATION_IP" },
  { 16390,16390,        "COOKIE" },
  { 16391,16391,        "USE_TRANSPORT_MODE" },
  { 16392,16392,        "HTTP_CERT_LOOKUP_SUPPORTED" },
  { 16393,16393,        "REKEY_SA" },
  { 16394,16394,        "ESP_TFC_PADDING_NOT_SUPPORTED" },
  { 16395,16395,        "NON_FIRST_FRAGMENTS_ALSO" },
  { 16396,16396,        "MOBIKE_SUPPORTED" },                   /* RFC4555 */
  { 16397,16397,        "ADDITIONAL_IP4_ADDRESS" },             /* RFC4555 */
  { 16398,16398,        "ADDITIONAL_IP6_ADDRESS" },             /* RFC4555 */
  { 16399,16399,        "NO_ADDITIONAL_ADDRESSES" },            /* RFC4555 */
  { 16400,16400,        "UPDATE_SA_ADDRESSES" },                /* RFC4555 */
  { 16401,16401,        "COOKIE2" },                            /* RFC4555 */
  { 16402,16402,        "NO_NATS_ALLOWED" },                    /* RFC4555 */
  { 16403,16403,        "AUTH_LIFETIME" },                      /* RFC4478 */
  { 16404,16404,        "MULTIPLE_AUTH_SUPPORTED" },            /* RFC4739 */
  { 16405,16405,        "ANOTHER_AUTH_FOLLOWS" },               /* RFC4739 */
  { 16406,16406,        "REDIRECT_SUPPORTED" },                 /* RFC5685 */
  { 16407,16407,        "REDIRECT" },                           /* RFC5685 */
  { 16408,16408,        "REDIRECTED_FROM" },                    /* RFC5685 */
  { 16409,16409,        "TICKET_LT_OPAQUE" },                   /* RFC5723 */
  { 16410,16410,        "TICKET_REQUEST" },                     /* RFC5723 */
  { 16411,16411,        "TICKET_ACK" },                         /* RFC5723 */
  { 16412,16412,        "TICKET_NACK" },                        /* RFC5723 */
  { 16413,16413,        "TICKET_OPAQUE" },                      /* RFC5723 */
  { 16414,16414,        "LINK_ID" },                            /* RFC5739 */
  { 16415,16415,        "USE_WESP_MODE" },                      /* RFC5840 */
  { 16416,16416,        "ROHC_SUPPORTED" },                     /* RFC5857 */
  { 16417,16417,        "EAP_ONLY_AUTHENTICATION" },            /* RFC5998 */
  { 16418,16418,        "CHILDLESS_IKEV2_SUPPORTED" },          /* RFC6023 */
  { 16419,16419,        "QUICK_CRASH_DETECTION" },              /* RFC6290 */
  { 16420,16420,        "IKEV2_MESSAGE_ID_SYNC_SUPPORTED" },    /* RFC6311 */
  { 16421,16421,        "IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED" },/* RFC6311 */
  { 16422,16422,        "IKEV2_MESSAGE_ID_SYNC" },              /* RFC6311 */
  { 16423,16423,        "IPSEC_REPLAY_COUNTER_SYNC" },          /* RFC6311 */
  { 16424,16424,        "SECURE_PASSWORD_METHODS" },            /* RFC6467 */
  { 16425,16425,        "PSK_PERSIST" },                        /* RFC6631 */
  { 16426,16426,        "PSK_CONFIRM" },                        /* RFC6631 */
  { 16427,16427,        "ERX_SUPPORTED" },                      /* RFC6867 */
  { 16428,16428,        "IFOM_CAPABILITY" },                    /* [Frederic_Firmin][3GPP TS 24.303 v10.6.0 annex B.2] */
  { 16429,16429,        "SENDER_REQUEST_ID" },                  /* [draft-yeung-g-ikev2] */
  { 16430,16430,        "IKEV2_FRAGMENTATION_SUPPORTED" },      /* RFC7383 */
  { 16431,16431,        "SIGNATURE_HASH_ALGORITHMS" },          /* RFC7427 */
  { 16432,40959,        "RESERVED TO IANA - STATUS TYPES" },
  { 40960,65535,        "Private Use - STATUS TYPES" },
  { 0,0,        NULL },
};

/* 3GPP private error and status types in Notify messages
 * 3GPP TS 24.302 V16.0.0 (2019-03)
 * 3GPP TS 24.502 V15.3.0 (2019-03)
 * Note currently all private data types wil be decoded as 3GPP if that's not good enough a preference must be used
 */
static const range_string notifmsg_v2_3gpp_type[] = {
  /* PRIVATE ERROR TYPES */
  { 8192,8192,        "PDN_CONNECTION_REJECTION" },                 /* TS 24.302 */
  { 8193,8193,        "MAX_CONNECTION_REACHED" },                   /* TS 24.302 */
  { 8194,8240,        "Private Use - Errors" },
  { 8241,8241,        "SEMANTIC_ERROR_IN_THE_TFT_OPERATION" },      /* TS 24.302 */
  { 8242,8242,        "SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION" },   /* TS 24.302 */
  { 8243,8243,        "Private Use - Errors" },
  { 8244,8244,        "SEMANTIC_ERRORS_IN_PACKET_FILTERS" },        /* TS 24.302 */
  { 8245,8245,        "SYNTACTICAL_ERRORS_IN_PACKET_FILTERS" },     /* TS 24.302 */
  { 8246,8999,        "Private Use - Errors" },
  { 9000,9000,        "NON_3GPP_ACCESS_TO_EPC_NOT_ALLOWED" },       /* TS 24.302 */
  { 9001,9001,        "USER_UNKNOWN" },                             /* TS 24.302 */
  { 9002,9002,        "NO_APN_SUBSCRIPTION" },
  { 9003,9003,        "AUTHORIZATION_REJECTED" },                   /* TS 24.302 */
  { 9004,9005,        "Private Use - Errors" },
  { 9006,9006,        "ILLEGAL_ME" },                               /* TS 24.302 */
  { 9007,10499,       "Private Use - Errors" },
  { 10500,10500,      "NETWORK_FAILURE" },                          /* TS 24.302 */
  { 10501,11000,      "Private Use - Errors" },
  { 11001,11001,      "RAT_TYPE_NOT_ALLOWED" },                     /* TS 24.302 */
  { 11002,11004,      "Private Use - Errors" },
  { 11005,11005,      "IMEI_NOT_ACCEPTED" },                        /* TS 24.302 */
  { 11006,11010,      "Private Use - Errors" },
  { 11011,11011,      "PLMN_NOT_ALLOWED" },                         /* TS 24.302 */
  { 11012,11054,      "Private Use - Errors" },
  { 11055,11055,      "UNAUTHENTICATED_EMERGENCY_NOT_SUPPORTED" },  /* TS 24.302 */
  { 11056,15499,      "Private Use - Errors" },
  { 15500,15500,      "CONGESTION" },                               /* TS 24.502 */
  { 15501,16383,      "Private Use - Errors" },
  /* PRIVATE STATUS TYPES */
  { 40960,40960,      "Private Use - STATUS TYPES" },
  { 40961,40961,      "REACTIVATION_REQUESTED_CAUSE" },             /* TS 24.302 */
  { 40962,41040,      "Private Use - STATUS TYPES" },
  { 41041,41041,      "BACKOFF_TIMER" },                            /* TS 24.302 */
  { 41042,41049,      "Private Use - STATUS TYPES" },
  { 41050,41050,      "PDN_TYPE_IPv4_ONLY_ALLOWED" },               /* TS 24.302 */
  { 41051,41051,      "PDN_TYPE_IPv6_ONLY_ALLOWED" },               /* TS 24.302 */
  { 41052,41100,      "Private Use - STATUS TYPES" },
  { 41101,41101,      "DEVICE_IDENTITY" },                          /* TS 24.302 */
  { 41102,41111,      "Private Use - STATUS TYPES" },
  { 41112,41112,      "EMERGENCY_SUPPORT" },                        /* TS 24.302 */
  { 41113,41133,      "Private Use - STATUS TYPES" },
  { 41134,41134,      "EMERGENCY_CALL_NUMBERS" },                   /* TS 24.302 */
  { 41135,41287,      "Private Use - STATUS TYPES" },
  { 41288,41288,      "NBIFOM_GENERIC_CONTAINER" },                 /* TS 24.302 */
  { 41289,41303,      "Private Use - STATUS TYPES" },
  { 41304,41304,      "P-CSCF_RESELECTION_SUPPORT" },               /* TS 24.302 */
  { 41305,41500,      "Private Use - STATUS TYPES" },
  { 41501,41501,      "PTI" },                                      /* TS 24.302 */
  { 41502,42010,      "Private Use - STATUS TYPES" },
  { 42011,42011,      "P-IKEV2_MULTIPLE_BEARER_PDN_CONNECTIVITY" }, /* TS 24.302 */
  { 42012,42013,      "Private Use - STATUS TYPES" },
  { 42014,42014,      "P-EPS_QOS" },                                /* TS 24.302 */
  { 42015,42015,      "P-EXTENDED_EPS_QOS" },                       /* TS 24.302 */
  { 42016,42016,      "Private Use - STATUS TYPES" },
  { 42017,42017,      "P-TFT" },                                    /* TS 24.302 */
  { 42018,42019,      "Private Use - STATUS TYPES" },
  { 42020,42020,      "P-MODIFIED_BEARER" },                        /* TS 24.302 */
  { 42021,42093,      "Private Use - STATUS TYPES" },
  { 42094,42094,      "P-APN_AMBR" },                               /* TS 24.302 */
  { 42095,42095,      "P-EXTENDED_APN_AMBR" },                      /* TS 24.302 */
  { 42096,51014,      "Private Use - STATUS TYPES" },
  { 51015,51015,      "P-N1_MODE_CAPABILITY" },                     /* TS 24.302 */
  { 51016,51114,      "Private Use - STATUS TYPES" },
  { 51115,51115,      "P-N1_MODE_INFORMATION" },                    /* TS 24.302 */
  { 51116,55500,      "Private Use - STATUS TYPES" },
  { 55501,55501,      "5G_QOS_INFO" },                              /* TS 24.502 */
  { 55502,55502,      "NAS_IP4_ADDRESS" },                          /* TS 24.502 */
  { 55503,55503,      "NAS_IP6_ADDRESS" },                          /* TS 24.502 */
  { 55504,55504,      "UP_IP4_ADDRESS" },                           /* TS 24.502 */
  { 55505,55505,      "UP_IP6_ADDRESS" },                           /* TS 24.502 */
  { 55506,55506,      "NAS_TCP_PORT" },                             /* TS 24.502 */
  { 55507,55507,      "N3GPP_BACKOFF_TIMER" },                      /* TS 24.502 */
  { 55508,65535,      "Private Use - STATUS TYPES" },

  { 0,0,        NULL },
};

static const range_string vs_v1_cfgtype[] = {
  { 0,0,        "Reserved" },
  { 1,1,        "ISAKMP_CFG_REQUEST" },
  { 2,2,        "ISAKMP_CFG_REPLY" },
  { 3,3,        "ISAKMP_CFG_SET" },
  { 4,4,        "ISAKMP_CFG_ACK" },
  { 5,127,      "Future use"    },
  { 128,256,    "Private Use"   },
  { 0,0,        NULL },
  };


static const range_string vs_v2_cfgtype[] = {
  { 0,0,        "RESERVED" },
  { 1,1,        "CFG_REQUEST" },
  { 2,2,        "CFG_REPLY" },
  { 3,3,        "CFG_SET" },
  { 4,4,        "CFG_ACK" },
  { 5,127,      "Future use"    },
  { 128,256,    "Private Use"   },
  { 0,0,        NULL },
  };

static const range_string vs_v1_cfgattr[] = {
  { 0,0,         "RESERVED" },
  { 1,1,         "INTERNAL_IP4_ADDRESS" },
  { 2,2,         "INTERNAL_IP4_NETMASK" },
  { 3,3,         "INTERNAL_IP4_DNS" },
  { 4,4,         "INTERNAL_IP4_NBNS" },
  { 5,5,         "INTERNAL_ADDRESS_EXPIRY" },
  { 6,6,         "INTERNAL_IP4_DHCP" },
  { 7,7,         "APPLICATION_VERSION" },
  { 8,8,         "INTERNAL_IP6_ADDRESS" },
  { 9,9,         "INTERNAL_IP6_NETMASK" },
  { 10,10,       "INTERNAL_IP6_DNS" },
  { 11,11,       "INTERNAL_IP6_NBNS" },
  { 12,12,       "INTERNAL_IP6_DHCP" },
  { 13,13,       "INTERNAL_IP4_SUBNET" },
  { 14,14,       "SUPPORTED_ATTRIBUTES" },
  { 15,15,       "INTERNAL_IP6_SUBNET" },
  { 16,16383,    "FUTURE USE"},
  { 16384,16386, "PRIVATE USE"},
  { 16387,16387, "CHKPT_DEF_DOMAIN" },
  { 16388,16388, "CHKPT_MAC_ADDRESS" },
  { 16389,16389, "CHKPT_MARCIPAN_REASON_CODE" },
  { 16400,16400, "CHKPT_UNKNOWN1" },
  { 16401,16401, "CHKPT_UNKNOWN2" },
  { 16402,16402, "CHKPT_UNKNOWN3" },
  { 16403,16519, "PRIVATE USE"},
  { 16520,16520, "XAUTH_TYPE" },
  { 16521,16521, "XAUTH_USER_NAME" },
  { 16522,16522, "XAUTH_USER_PASSWORD" },
  { 16523,16523, "XAUTH_PASSCODE" },
  { 16524,16524, "XAUTH_MESSAGE" },
  { 16525,16525, "XAUTH_CHALLANGE" },
  { 16526,16526, "XAUTH_DOMAIN" },
  { 16527,16527, "XAUTH_STATUS" },
  { 16528,16528, "XAUTH_NEXT_PIN" },
  { 16529,16529, "XAUTH_ANSWER" },
  { 16530,28671, "PRIVATE USE"},
  { 28672,28672, "UNITY_BANNER" },
  { 28673,28673, "UNITY_SAVE_PASSWD" },
  { 28674,28674, "UNITY_DEF_DOMAIN" },
  { 28675,28675, "UNITY_SPLIT_DOMAIN" },
  { 28676,28676, "UNITY_SPLIT_INCLUDE" },
  { 28677,28677, "UNITY_NATT_PORT" },
  { 28678,28678, "UNITY_SPLIT_EXCLUDE" },
  { 28679,28679, "UNITY_PFS" },
  { 28680,28680, "UNITY_FW_TYPE" },
  { 28681,28681, "UNITY_BACKUP_SERVERS" },
  { 28682,28682, "UNITY_DDNS_HOSTNAME" },
  { 28683,32767, "PRIVATE USE"},
  { 0,0,         NULL },
  };

static const range_string vs_v2_cfgattr[] = {
  { 0,0,         "RESERVED" },
  { 1,1,         "INTERNAL_IP4_ADDRESS" },
  { 2,2,         "INTERNAL_IP4_NETMASK" },
  { 3,3,         "INTERNAL_IP4_DNS" },
  { 4,4,         "INTERNAL_IP4_NBNS" },
  { 5,5,         "INTERNAL_ADDRESS_EXPIRY" },   /* OBSO */
  { 6,6,         "INTERNAL_IP4_DHCP" },
  { 7,7,         "APPLICATION_VERSION" },
  { 8,8,         "INTERNAL_IP6_ADDRESS" },
  { 9,9,         "RESERVED" },
  { 10,10,       "INTERNAL_IP6_DNS" },
  { 11,11,       "INTERNAL_IP6_NBNS" },         /* OBSO */
  { 12,12,       "INTERNAL_IP6_DHCP" },
  { 13,13,       "INTERNAL_IP4_SUBNET" },
  { 14,14,       "SUPPORTED_ATTRIBUTES" },
  { 15,15,       "INTERNAL_IP6_SUBNET" },
  { 16,16,       "MIP6_HOME_PREFIX" },
  { 17,17,       "INTERNAL_IP6_LINK" },
  { 18,18,       "INTERNAL_IP6_PREFIX" },
  { 19,19,       "HOME_AGENT_ADDRESS" },        /* 3GPP TS 24.302 http://www.3gpp.org/ftp/Specs/html-info/24302.htm */
  { 20,20,       "P_CSCF_IP4_ADDRESS" },        /* 3GPP IMS Option for IKEv2 https://datatracker.ietf.org/doc/draft-gundavelli-ipsecme-3gpp-ims-options/ */
  { 21,21,       "P_CSCF_IP6_ADDRESS" },
  { 22,22,       "FTT_KAT" },
  { 23,16383,    "RESERVED TO IANA"},
  { 16384,32767, "PRIVATE USE"},
  { 0,0,          NULL },
  };

static const range_string cfgattr_xauth_type[] = {
  { 0,0,         "Generic" },
  { 1,1,         "RADIUS-CHAP" },
  { 2,2,         "OTP" },
  { 3,3,         "S/KEY" },
  { 4,32767,     "Future use" },
  { 32768,65535, "Private use" },
  { 0,0,          NULL },
  };


static const value_string cfgattr_xauth_status[] = {
  { 0,  "Fail" },
  { 1,  "Success" },
  { 0,  NULL },
};

static const value_string cp_product[] = {
  { 1,  "Firewall-1" },
  { 2,  "SecuRemote/SecureClient" },
  { 0,  NULL },
};

static const value_string cp_version[] = {
  { 2,"4.1" },
  { 3,"4.1 SP-1" },
  { 4002,"4.1 (SP-2 or above)" },
  { 5000,"NG" },
  { 5001,"NG Feature Pack 1" },
  { 5002,"NG Feature Pack 2" },
  { 5003,"NG Feature Pack 3" },
  { 5004,"NG with Application Intelligence" },
  { 5005,"NG with Application Intelligence R55" },
  { 5006,"NG with Application Intelligence R56" },
  { 0,  NULL },
};
static const range_string traffic_selector_type[] = {
  { 0,6,        "Reserved" },
  { 7,7,        "TS_IPV4_ADDR_RANGE" },
  { 8,8,        "TS_IPV6_ADDR_RANGE" },
  { 9,9,        "TS_FC_ADDR_RANGE" },
  { 10,240,     "Future use" },
  { 241,255,    "Private use" },
  { 0,0,          NULL },
  };
static const value_string ms_nt5_isakmpoakley_type[] = {
  { 2, "Windows 2000" },
  { 3, "Windows XP SP1" },
  { 4, "Windows 2003 and Windows XP SP2" },
  { 5, "Windows Vista" },
  { 0, NULL }
};
static const range_string vs_v1_id_type[] = {
  { 0,0,                                                "RESERVED" },
  { IKE_ID_IPV4_ADDR,IKE_ID_IPV4_ADDR,                  "IPV4_ADDR" },
  { IKE_ID_FQDN,IKE_ID_FQDN,                            "FQDN" },
  { IKE_ID_USER_FQDN,IKE_ID_USER_FQDN,                  "USER_FQDN" },
  { IKE_ID_IPV4_ADDR_SUBNET,IKE_ID_IPV4_ADDR_SUBNET,    "IPV4_ADDR_SUBNET" },
  { IKE_ID_IPV6_ADDR,IKE_ID_IPV6_ADDR,                  "IPV6_ADDR" },
  { IKE_ID_IPV6_ADDR_SUBNET,IKE_ID_IPV6_ADDR_SUBNET,    "IPV6_ADDR_SUBNET" },
  { IKE_ID_IPV4_ADDR_RANGE,IKE_ID_IPV4_ADDR_RANGE,      "IPV4_ADDR_RANGE" },
  { IKE_ID_IPV6_ADDR_RANGE,IKE_ID_IPV6_ADDR_RANGE,      "IPV6_ADDR_RANGE" },
  { IKE_ID_DER_ASN1_DN,IKE_ID_DER_ASN1_DN,              "DER_ASN1_DN" },
  { IKE_ID_DER_ASN1_GN,IKE_ID_DER_ASN1_GN,              "DER_ASN1_GN" },
  { IKE_ID_KEY_ID,IKE_ID_KEY_ID,                        "KEY_ID" },
  { IKE_ID_LIST,IKE_ID_LIST,                            "KEY_LIST" },
  { 13,248,                                             "Future use" },
  { 249,255,                                            "Private Use" },
  { 0,0,          NULL },
  };
static const range_string vs_v2_id_type[] = {
  { 0,0,                                                "RESERVED" },
  { IKE_ID_IPV4_ADDR,IKE_ID_IPV4_ADDR,                  "IPV4_ADDR" },
  { IKE_ID_FQDN,IKE_ID_FQDN,                            "FQDN" },
  { IKE_ID_RFC822_ADDR,IKE_ID_RFC822_ADDR,              "ID_RFC822_ADDR" },
  { 4,4,                                                "Unassigned" },
  { IKE_ID_IPV6_ADDR,IKE_ID_IPV6_ADDR,                  "IPV6_ADDR" },
  { 6,8,                                                "Unassigned" },
  { IKE_ID_DER_ASN1_DN,IKE_ID_DER_ASN1_DN,              "DER_ASN1_DN" },
  { IKE_ID_DER_ASN1_GN,IKE_ID_DER_ASN1_GN,              "DER_ASN1_GN" },
  { IKE_ID_KEY_ID,IKE_ID_KEY_ID,                        "KEY_ID" },
  { IKE_ID_FC_NAME,IKE_ID_FC_NAME,                      "KEY_LIST" },
  { 13,200,                                             "Future use" },
  { 201,255,                                            "Private Use" },
  { 0,0,          NULL },
  };
#define COOKIE_SIZE 8

typedef struct isakmp_hdr {
  guint8        next_payload;
  guint8        version;
  guint8        exch_type;
  guint8        flags;
#define E_FLAG          0x01
#define C_FLAG          0x02
#define A_FLAG          0x04
#define I_FLAG          0x08
#define V_FLAG          0x10
#define R_FLAG          0x20
  guint32       message_id;
  guint32       length;
} isakmp_hdr_t;

static const true_false_string attribute_format = {
  "Type/Value (TV)",
  "Type/Length/Value (TLV)"
};
static const true_false_string flag_e = {
  "Encrypted",
  "Not encrypted"
};
static const true_false_string flag_c = {
  "Commit",
  "No commit"
};
static const true_false_string flag_a = {
  "Authentication",
  "No authentication"
};
static const true_false_string flag_i = {
  "Initiator",
  "Responder"
};
static const true_false_string flag_v = {
  "A higher version enabled",
  "No higher version"
};


/* ROHC Attribute Type RFC5857 */

#define ROHC_MAX_CID            1
#define ROHC_PROFILE            2
#define ROHC_INTEG              3
#define ROHC_ICV_LEN            4
#define ROHC_MRRU               5

static const range_string rohc_attr_type[] = {
  { 1,1,         "Maximum Context Identifier (MAX_CID)" },
  { 2,2,         "ROHC Profile (ROHC_PROFILE)" },
  { 3,3,         "ROHC Integrity Algorithm (ROHC_INTEG)" },
  { 4,4,         "ROHC ICV Length in bytes (ROHC_ICV_LEN)" },
  { 5,5,         "Maximum Reconstructed Reception Unit (MRRU)" },
  { 6,16383,     "Unassigned (Future use)" },
  { 16384,32767, "Private use" },
  { 0,0,         NULL },
};

static const range_string signature_hash_algorithms[] = {
  { 0,0,        "Reserved" },
  { 1,1,        "SHA1" },
  { 2,2,        "SHA2-256" },
  { 3,3,        "SHA2-384" },
  { 4,4,        "SHA2-512" },
  { 5,5,        "Identity" },
  { 6,1023,     "Unassigned" },
  { 1024,65535, "Reserved for Private Use" },
  {0,0,         NULL },
};

static const range_string sat_protocol_ids[] = {
  { 0,0,      "Reserved" },
  { 1,1,      "GDOI_PROTO_IPSEC_ESP" },
  { 2,2,      "GDOI_PROTO_IPSEC_AH" },
  { 3,127,    "Unassigned" },
  { 128, 255, "Private Use" },
  { 0,0,      NULL },
};

static const range_string key_download_types[] = {
  { 0,0,      "Reserved" },
  { 1,1,      "TEK" },
  { 2,2,      "KEK" },
  { 3,3,      "LKH" },
  { 4,4,      "SID" },
  { 5,127,    "Unassigned" },
  { 128, 255, "Private Use" },
  { 0,0,      NULL },
};

static const value_string device_identity_types[] = {
  { 0x01,  "IMEI" },
  { 0x02,  "IMEISV" },
  { 0,     NULL },
};

#define ISAKMP_HDR_SIZE ((int)sizeof(struct isakmp_hdr) + (2 * COOKIE_SIZE))


#define MAX_KEY_SIZE       256
#define MAX_DIGEST_SIZE     64
#define MAX_OAKLEY_KEY_LEN  32

#define PINFO_CBC_IV 1

#define DECR_PARAMS_INIT    0
#define DECR_PARAMS_READY   1
#define DECR_PARAMS_FAIL    2

typedef struct _ikev1_uat_data_key {
  guchar *icookie;
  guint icookie_len;
  guchar *key;
  guint key_len;
} ikev1_uat_data_key_t;

typedef struct decrypt_data {
  gboolean       is_psk;
  address        initiator;
  guint          ike_encr_alg;
  guint          ike_encr_keylen;
  guint          ike_hash_alg;
  gint           cipher_algo;
  gsize          cipher_keylen;
  gsize          cipher_blklen;
  gint           digest_algo;
  guint          digest_len;
  guint          group;
  gchar         *gi;
  guint          gi_len;
  gchar         *gr;
  guint          gr_len;
  guchar         secret[MAX_KEY_SIZE];
  guint          secret_len;
  GHashTable    *iv_hash;
  guint          state;
} decrypt_data_t;

/* IKEv1: Lookup from  Initiator-SPI -> decrypt_data_t* */
static GHashTable *isakmp_hash = NULL;

static ikev1_uat_data_key_t* ikev1_uat_data = NULL;
static uat_t * ikev1_uat = NULL;
static guint num_ikev1_uat_data = 0;

/* Specifications of encryption algorithms for IKEv2 decryption */
typedef struct _ikev2_encr_alg_spec {
  guint number;
  /* Length of encryption key */
  guint key_len;
  /* Block size of the cipher */
  guint block_len;
  /* Length of initialization vector */
  guint iv_len;
  /* Encryption algorithm ID to be passed to gcry_cipher_open() */
  gint gcry_alg;
  /* Cipher mode to be passed to gcry_cipher_open() */
  gint gcry_mode;

  /* Salt length used in AEAD (GCM/CCM) mode. Salt value is last salt_len bytes of encr_key.
   * IV for decryption is the result of concatenating salt value and iv_len bytes of iv.
   * For non-AED ciphers salt_len 0 */
  guint salt_len;
  /* Authenticated Encryption TAG length (ICV) - length of data taken from end of encrypted output
   * used for integrity checksum, computed during decryption (for AEAD ciphers)*/
  guint icv_len;

} ikev2_encr_alg_spec_t;

#define IKEV2_ENCR_NULL        1
#define IKEV2_ENCR_3DES        2
#define IKEV2_ENCR_AES_CBC_128 3
#define IKEV2_ENCR_AES_CBC_192 4
#define IKEV2_ENCR_AES_CBC_256 5

#define IKEV2_ENCR_AES_CTR_128 6
#define IKEV2_ENCR_AES_CTR_192 7
#define IKEV2_ENCR_AES_CTR_256 8

/* AEAD algorithms. Require gcrypt_version >= 1.6.0 if integrity verification shall be performed */
#define IKEV2_ENCR_AES_GCM_128_16  101
#define IKEV2_ENCR_AES_GCM_192_16  102
#define IKEV2_ENCR_AES_GCM_256_16  103

#define IKEV2_ENCR_AES_GCM_128_8   104
#define IKEV2_ENCR_AES_GCM_192_8   105
#define IKEV2_ENCR_AES_GCM_256_8   106

#define IKEV2_ENCR_AES_GCM_128_12  107
#define IKEV2_ENCR_AES_GCM_192_12  108
#define IKEV2_ENCR_AES_GCM_256_12  109

#define IKEV2_ENCR_AES_CCM_128_16  111
#define IKEV2_ENCR_AES_CCM_192_16  112
#define IKEV2_ENCR_AES_CCM_256_16  113

#define IKEV2_ENCR_AES_CCM_128_8   114
#define IKEV2_ENCR_AES_CCM_192_8   115
#define IKEV2_ENCR_AES_CCM_256_8   116

#define IKEV2_ENCR_AES_CCM_128_12  117
#define IKEV2_ENCR_AES_CCM_192_12  118
#define IKEV2_ENCR_AES_CCM_256_12  119


static ikev2_encr_alg_spec_t ikev2_encr_algs[] = {
  {IKEV2_ENCR_NULL, 0, 1, 0, GCRY_CIPHER_NONE, GCRY_CIPHER_MODE_NONE, 0, 0},
  {IKEV2_ENCR_3DES, 24, 8, 8, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC, 0, 0},
  {IKEV2_ENCR_AES_CBC_128, 16, 16, 16, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0, 0},
  {IKEV2_ENCR_AES_CBC_192, 24, 16, 16, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CBC, 0, 0},
  {IKEV2_ENCR_AES_CBC_256, 32, 16, 16, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0, 0},

  {IKEV2_ENCR_AES_CTR_128, 20, 1, 8, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 4, 0},
  {IKEV2_ENCR_AES_CTR_192, 28, 1, 8, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CTR, 4, 0},
  {IKEV2_ENCR_AES_CTR_256, 36, 1, 8, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CTR, 4, 0},

  /* GCM algorithms: key length: aes-length + 4 bytes of IV (salt), iv - 8 bytes */
  {IKEV2_ENCR_AES_GCM_128_16, 20, 1, 8, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 4, 16},
  {IKEV2_ENCR_AES_GCM_192_16, 28, 1, 8, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_GCM, 4, 16},
  {IKEV2_ENCR_AES_GCM_256_16, 36, 1, 8, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 4, 16},

  {IKEV2_ENCR_AES_GCM_128_8, 20, 1, 8, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 4, 8},
  {IKEV2_ENCR_AES_GCM_192_8, 28, 1, 8, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_GCM, 4, 8},
  {IKEV2_ENCR_AES_GCM_256_8, 36, 1, 8, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 4, 8},

  {IKEV2_ENCR_AES_GCM_128_12, 20, 1, 8, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, 4, 12},
  {IKEV2_ENCR_AES_GCM_192_12, 28, 1, 8, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_GCM, 4, 12},
  {IKEV2_ENCR_AES_GCM_256_12, 36, 1, 8, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 4, 12},

  /* CCM algorithms: key length: aes-length + 3 bytes of salt, iv - 8 bytes */
  {IKEV2_ENCR_AES_CCM_128_16, 19, 1, 8, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM, 3, 16},
  {IKEV2_ENCR_AES_CCM_192_16, 27, 1, 8, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CCM, 3, 16},
  {IKEV2_ENCR_AES_CCM_256_16, 35, 1, 8, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CCM, 3, 16},

  {IKEV2_ENCR_AES_CCM_128_8, 19, 1, 8, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM, 3, 8},
  {IKEV2_ENCR_AES_CCM_192_8, 27, 1, 8, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CCM, 3, 8},
  {IKEV2_ENCR_AES_CCM_256_8, 35, 1, 8, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CCM, 3, 8},

  {IKEV2_ENCR_AES_CCM_128_12, 19, 1, 8, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM, 3, 12},
  {IKEV2_ENCR_AES_CCM_192_12, 27, 1, 8, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CCM, 3, 12},
  {IKEV2_ENCR_AES_CCM_256_12, 35, 1, 8, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CCM, 3, 12},

  {0, 0, 0, 0, 0, 0, 0, 0}
};

/*
 * Specifications of authentication algorithms for
 * decryption and/or ICD (Integrity Checksum Data) checking of IKEv2
 */
typedef struct _ikev2_auth_alg_spec {
  guint number;
  /* Output length of the hash algorithm */
  guint output_len;
  /* Length of the hash key */
  guint key_len;
  /* Actual ICD length after truncation */
  guint trunc_len;
  /* Hash algorithm ID to be passed to gcry_md_open() */
  gint gcry_alg;
  /* Flags to be passed to gcry_md_open() */
  guint gcry_flag;
} ikev2_auth_alg_spec_t;

#define IKEV2_AUTH_NONE         1
#define IKEV2_AUTH_HMAC_MD5_96  2
#define IKEV2_AUTH_HMAC_SHA1_96 3
#define IKEV2_AUTH_HMAC_SHA2_256_96 4
#define IKEV2_AUTH_HMAC_SHA2_256_128 5
#define IKEV2_AUTH_HMAC_SHA2_384_192 6
#define IKEV2_AUTH_HMAC_SHA2_512_256 7
#define IKEV2_AUTH_ANY_96BITS   8
#define IKEV2_AUTH_ANY_128BITS  9
#define IKEV2_AUTH_ANY_160BITS  10
#define IKEV2_AUTH_ANY_192BITS  11
#define IKEV2_AUTH_ANY_256BITS  12
#define IKEV2_AUTH_ANY_64BITS   13
#define IKEV2_AUTH_HMAC_MD5_128  14
#define IKEV2_AUTH_HMAC_SHA1_160 15

static ikev2_auth_alg_spec_t ikev2_auth_algs[] = {
/*{number, output_len, key_len, trunc_len, gcry_alg, gcry_flag}*/
  {IKEV2_AUTH_NONE, 0, 0, 0, GCRY_MD_NONE, 0},
  {IKEV2_AUTH_HMAC_MD5_96, 16, 16, 12, GCRY_MD_MD5, GCRY_MD_FLAG_HMAC},
  {IKEV2_AUTH_HMAC_SHA1_96, 20, 20, 12, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC},
  {IKEV2_AUTH_HMAC_MD5_128, 16, 16, 16, GCRY_MD_MD5, GCRY_MD_FLAG_HMAC},
  {IKEV2_AUTH_HMAC_SHA1_160, 20, 20, 20, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC},
  {IKEV2_AUTH_HMAC_SHA2_256_96, 32, 32, 12, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC},
  {IKEV2_AUTH_HMAC_SHA2_256_128, 32, 32, 16, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC},
  {IKEV2_AUTH_HMAC_SHA2_384_192, 48, 48, 24, GCRY_MD_SHA384, GCRY_MD_FLAG_HMAC},
  {IKEV2_AUTH_HMAC_SHA2_512_256, 64, 64, 32, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC},
  {IKEV2_AUTH_ANY_96BITS, 0, 0, 12, 0, 0},
  {IKEV2_AUTH_ANY_128BITS, 0, 0, 16, 0, 0},
  {IKEV2_AUTH_ANY_160BITS, 0, 0, 20, 0, 0},
  {IKEV2_AUTH_ANY_192BITS, 0, 0, 24, 0, 0},
  {IKEV2_AUTH_ANY_256BITS, 0, 0, 32, 0, 0},
  {IKEV2_AUTH_ANY_64BITS, 0, 0, 8, 0, 0},

  {0, 0, 0, 0, 0, 0}
};

typedef struct _ikev2_decrypt_data {
  guchar *encr_key;
  guchar *auth_key;
  ikev2_encr_alg_spec_t *encr_spec;
  ikev2_auth_alg_spec_t *auth_spec;
} ikev2_decrypt_data_t;

typedef struct _ikev2_uat_data_key {
  guchar *spii;
  guint spii_len;
  guchar *spir;
  guint spir_len;
} ikev2_uat_data_key_t;

typedef struct _ikev2_uat_data {
  ikev2_uat_data_key_t key;
  guint encr_alg;
  guint auth_alg;
  guchar *sk_ei;
  guint sk_ei_len;
  guchar *sk_er;
  guint sk_er_len;
  guchar *sk_ai;
  guint sk_ai_len;
  guchar *sk_ar;
  guint sk_ar_len;
  ikev2_encr_alg_spec_t *encr_spec;
  ikev2_auth_alg_spec_t *auth_spec;
} ikev2_uat_data_t;

static ikev2_uat_data_t* ikev2_uat_data = NULL;
static guint num_ikev2_uat_data = 0;
static uat_t* ikev2_uat;

/* IKEv2: (I-SPI, R-SPI) -> ikev2_uat_data_t* */
static GHashTable *ikev2_key_hash = NULL;

#define IKEV2_ENCR_3DES_STR "3DES [RFC2451]"
static const value_string vs_ikev2_encr_algs[] = {
  {IKEV2_ENCR_3DES,        IKEV2_ENCR_3DES_STR},
  {IKEV2_ENCR_AES_CBC_128, "AES-CBC-128 [RFC3602]"},
  {IKEV2_ENCR_AES_CBC_192, "AES-CBC-192 [RFC3602]"},
  {IKEV2_ENCR_AES_CBC_256, "AES-CBC-256 [RFC3602]"},
  {IKEV2_ENCR_NULL,        "NULL [RFC2410]"},

  {IKEV2_ENCR_AES_CTR_128, "AES-CTR-128 [RFC5930]"},
  {IKEV2_ENCR_AES_CTR_192, "AES-CTR-192 [RFC5930]"},
  {IKEV2_ENCR_AES_CTR_256, "AES-CTR-256 [RFC5930]"},

  {IKEV2_ENCR_AES_GCM_128_16, "AES-GCM-128 with 16 octet ICV [RFC5282]"},
  {IKEV2_ENCR_AES_GCM_192_16, "AES-GCM-192 with 16 octet ICV [RFC5282]"},
  {IKEV2_ENCR_AES_GCM_256_16, "AES-GCM-256 with 16 octet ICV [RFC5282]"},

  {IKEV2_ENCR_AES_GCM_128_8, "AES-GCM-128 with 8 octet ICV [RFC5282]"},
  {IKEV2_ENCR_AES_GCM_192_8, "AES-GCM-192 with 8 octet ICV [RFC5282]"},
  {IKEV2_ENCR_AES_GCM_256_8, "AES-GCM-256 with 8 octet ICV [RFC5282]"},

  {IKEV2_ENCR_AES_GCM_128_12, "AES-GCM-128 with 12 octet ICV [RFC5282]"},
  {IKEV2_ENCR_AES_GCM_192_12, "AES-GCM-192 with 12 octet ICV [RFC5282]"},
  {IKEV2_ENCR_AES_GCM_256_12, "AES-GCM-256 with 12 octet ICV [RFC5282]"},

  {IKEV2_ENCR_AES_CCM_128_16, "AES-CCM-128 with 16 octet ICV [RFC5282]"},
  {IKEV2_ENCR_AES_CCM_192_16, "AES-CCM-192 with 16 octet ICV [RFC5282]"},
  {IKEV2_ENCR_AES_CCM_256_16, "AES-CCM-256 with 16 octet ICV [RFC5282]"},

  {IKEV2_ENCR_AES_CCM_128_8, "AES-CCM-128 with 8 octet ICV [RFC5282]"},
  {IKEV2_ENCR_AES_CCM_192_8, "AES-CCM-192 with 8 octet ICV [RFC5282]"},
  {IKEV2_ENCR_AES_CCM_256_8, "AES-CCM-256 with 8 octet ICV [RFC5282]"},

  {IKEV2_ENCR_AES_CCM_128_12, "AES-CCM-128 with 12 octet ICV [RFC5282]"},
  {IKEV2_ENCR_AES_CCM_192_12, "AES-CCM-192 with 12 octet ICV [RFC5282]"},
  {IKEV2_ENCR_AES_CCM_256_12, "AES-CCM-256 with 12 octet ICV [RFC5282]"},

  {0, NULL}
};

#define IKEV2_AUTH_HMAC_SHA1_96_STR "HMAC_SHA1_96 [RFC2404]"
static const value_string vs_ikev2_auth_algs[] = {
  {IKEV2_AUTH_HMAC_MD5_96,  "HMAC_MD5_96 [RFC2403]"},
  {IKEV2_AUTH_HMAC_SHA1_96, IKEV2_AUTH_HMAC_SHA1_96_STR},
  {IKEV2_AUTH_HMAC_MD5_128,  "HMAC_MD5_128 [RFC4595]"},
  {IKEV2_AUTH_HMAC_SHA1_160, "HMAC_SHA1_160 [RFC4595]"},
  {IKEV2_AUTH_HMAC_SHA2_256_96, "HMAC_SHA2_256_96 [draft-ietf-ipsec-ciph-sha-256-00]"},
  {IKEV2_AUTH_HMAC_SHA2_256_128, "HMAC_SHA2_256_128 [RFC4868]"},
  {IKEV2_AUTH_HMAC_SHA2_384_192, "HMAC_SHA2_384_192 [RFC4868]"},
  {IKEV2_AUTH_HMAC_SHA2_512_256, "HMAC_SHA2_512_256 [RFC4868]"},
  {IKEV2_AUTH_NONE,         "NONE [RFC4306]"},
  {IKEV2_AUTH_ANY_64BITS,   "ANY 64-bits of Authentication [No Checking]"},
  {IKEV2_AUTH_ANY_96BITS,   "ANY 96-bits of Authentication [No Checking]"},
  {IKEV2_AUTH_ANY_128BITS,  "ANY 128-bits of Authentication [No Checking]"},
  {IKEV2_AUTH_ANY_160BITS,  "ANY 160-bits of Authentication [No Checking]"},
  {IKEV2_AUTH_ANY_192BITS,  "ANY 192-bits of Authentication [No Checking]"},
  {IKEV2_AUTH_ANY_256BITS,  "ANY 256-bits of Authentication [No Checking]"},
  {0, NULL}
};

static ikev2_encr_alg_spec_t* ikev2_decrypt_find_encr_spec(guint num) {
  ikev2_encr_alg_spec_t *e;

  for (e = ikev2_encr_algs; e->number != 0; e++) {
    if (e->number == num) {
      return e;
    }
  }
  return NULL;
}

static ikev2_auth_alg_spec_t* ikev2_decrypt_find_auth_spec(guint num) {
  ikev2_auth_alg_spec_t *a;

  for (a = ikev2_auth_algs; a->number != 0; a++) {
    if (a->number == num) {
      return a;
    }
  }
  return NULL;
}

static gint ikev1_find_gcry_cipher_algo(guint ike_cipher, guint ike_keylen) {
  switch(ike_cipher) {
    case ENC_3DES_CBC:
      return GCRY_CIPHER_3DES;

    case ENC_DES_CBC:
      return GCRY_CIPHER_DES;

    case ENC_AES_CBC:
      switch (ike_keylen) {
        case 128:
          return GCRY_CIPHER_AES128;
        case 192:
          return GCRY_CIPHER_AES192;
        case 256:
          return GCRY_CIPHER_AES256;
      }
      return GCRY_CIPHER_NONE;
  }
  return GCRY_CIPHER_NONE;
}

static gint ikev1_find_gcry_md_algo(guint ike_hash) {
  switch(ike_hash) {
    case HMAC_MD5:
      return GCRY_MD_MD5;
    case HMAC_SHA:
      return GCRY_MD_SHA1;
    case HMAC_SHA2_256:
      return GCRY_MD_SHA256;
    case HMAC_SHA2_384:
      return GCRY_MD_SHA384;
    case HMAC_SHA2_512:
      return GCRY_MD_SHA512;
  }
  return GCRY_MD_NONE;
}

static gpointer
generate_iv(const gpointer b1, gsize b1_len,
            const gpointer b2, gsize b2_len,
            gint md_algo, gsize iv_len) {

  gcry_md_hd_t md_ctx;
  gpointer iv;

  if (gcry_md_open(&md_ctx, md_algo, 0) != GPG_ERR_NO_ERROR)
    return NULL;

  gcry_md_write(md_ctx, b1, b1_len);
  gcry_md_write(md_ctx, b2, b2_len);

  iv = wmem_alloc(wmem_file_scope(), iv_len);
  memcpy(iv, gcry_md_read(md_ctx, md_algo), iv_len);
  gcry_md_close(md_ctx);

  return iv;
}

/* Get the IV previously stored for the current message ID,
 * or create a new IV if the message ID was not seen before.
 * The caller owns the result and does not need to copy it.
 * This function may return NULL.
 */
static gpointer
get_iv(guint32 message_id, decrypt_data_t *decr) {
  gpointer iv, iv1;
  gsize cipher_blklen;
  gpointer msgid_key;
  guint32 msgid_net;
  gboolean found;

  cipher_blklen = decr->cipher_blklen;

  /* Get the current IV for the given message ID,
   * and remove it from the hash table without destroying it. */
  msgid_key = GINT_TO_POINTER(message_id);
  found = g_hash_table_lookup_extended(decr->iv_hash, msgid_key, NULL, &iv);
  if (found) {
    g_hash_table_steal(decr->iv_hash, msgid_key);
    return iv;
  }

  /* No IV for this message ID was found; a new phase has started.
   * Generate the first IV for it from its message ID and the current
   * phase 1 IV. The phase 1 IV always exists in the hash table
   * and is not NULL.
   */
  iv1 = g_hash_table_lookup(decr->iv_hash, GINT_TO_POINTER(0));
  msgid_net = g_htonl(message_id);
  iv = generate_iv(iv1, cipher_blklen,
                   &msgid_net, sizeof(msgid_net),
                   decr->digest_algo, cipher_blklen);
  return iv;
}

/* Fill in the next IV from the final ciphertext block. */
static void
set_next_iv(const guint8 *buf, guint buf_len, guint32 message_id, decrypt_data_t *decr) {
  gpointer iv;
  gsize cipher_blklen;
  gpointer msgid_key;

  cipher_blklen = decr->cipher_blklen;

  if (buf_len < cipher_blklen) {
    iv = NULL;
  } else {
    iv = wmem_alloc(wmem_file_scope(), cipher_blklen);
    memcpy(iv, buf + buf_len - cipher_blklen, cipher_blklen);
  }

  msgid_key = GINT_TO_POINTER(message_id);
  g_hash_table_insert(decr->iv_hash, msgid_key, iv);
}

static void
update_ivs(packet_info *pinfo, const guint8 *buf, guint buf_len, guint32 message_id, decrypt_data_t *decr) {
  gpointer iv;

  /* Get the current IV and store it as per-packet data. */
  iv = get_iv(message_id, decr);
  p_add_proto_data(wmem_file_scope(), pinfo, proto_isakmp, PINFO_CBC_IV, iv);

  set_next_iv(buf, buf_len, message_id, decr);
}

static gboolean
prepare_decrypt_params(decrypt_data_t *decr) {
  decr->cipher_algo = ikev1_find_gcry_cipher_algo(decr->ike_encr_alg,
                                                  decr->ike_encr_keylen);
  decr->digest_algo = ikev1_find_gcry_md_algo(decr->ike_hash_alg);

  if (decr->cipher_algo == GCRY_CIPHER_NONE ||
      decr->digest_algo == GCRY_MD_NONE)
    return FALSE;

  decr->cipher_keylen = gcry_cipher_get_algo_keylen(decr->cipher_algo);
  decr->cipher_blklen = gcry_cipher_get_algo_blklen(decr->cipher_algo);
  decr->digest_len = gcry_md_get_algo_dlen(decr->digest_algo);

  if (decr->secret_len < decr->cipher_keylen ||
      decr->digest_len < decr->cipher_blklen)
    return FALSE;

  if (decr->gi_len == 0 || decr->gr_len == 0)
    return FALSE;

  return TRUE;
}

/* Generate phase 1 IV from DH values
 * and store it into the IV hash table. */
static gboolean
prepare_phase1_iv(decrypt_data_t *decr) {
  gpointer iv;

  iv = generate_iv(decr->gi, decr->gi_len,
                   decr->gr, decr->gr_len,
                   decr->digest_algo, decr->cipher_blklen);
  if (!iv)
    return FALSE;

  g_hash_table_insert(decr->iv_hash, GINT_TO_POINTER(0), iv);
  return TRUE;
}

static gboolean
prepare_decrypt(decrypt_data_t *decr) {
  gboolean result;

  if (!decr)
    return FALSE;

  if (decr->state == DECR_PARAMS_INIT) {
    /* Short-circuit evaluation is intended. */
    result = prepare_decrypt_params(decr) &&
             prepare_phase1_iv(decr);
    decr->state = result ? DECR_PARAMS_READY : DECR_PARAMS_FAIL;
  }

  return (decr->state == DECR_PARAMS_READY);
}

static decrypt_data_t *
create_decrypt_data(void) {
  decrypt_data_t *decr;

  decr = (decrypt_data_t *)g_slice_alloc(sizeof(decrypt_data_t));
  memset(decr, 0, sizeof(decrypt_data_t));
  decr->iv_hash = g_hash_table_new(NULL, NULL);
  clear_address(&decr->initiator);

  return decr;
}

static tvbuff_t *
decrypt_payload(tvbuff_t *tvb, packet_info *pinfo, const guint8 *buf, guint buf_len, decrypt_data_t *decr) {
  guint8 *decrypted_data;
  gcry_cipher_hd_t decr_ctx;
  tvbuff_t *encr_tvb;
  gpointer iv;
  gboolean error;

  if (buf_len < decr->cipher_blklen)
    return NULL;

  iv = p_get_proto_data(wmem_file_scope(), pinfo, proto_isakmp, PINFO_CBC_IV);
  if (!iv)
    return NULL;

  if (gcry_cipher_open(&decr_ctx, decr->cipher_algo, GCRY_CIPHER_MODE_CBC, 0) != GPG_ERR_NO_ERROR)
    return NULL;

  decrypted_data = (guint8 *)wmem_alloc(pinfo->pool, buf_len);

  /* Short-circuit evaluation is intended. */
  error = gcry_cipher_setiv(decr_ctx, iv, decr->cipher_blklen) ||
          gcry_cipher_setkey(decr_ctx, decr->secret, decr->secret_len) ||
          gcry_cipher_decrypt(decr_ctx, decrypted_data, buf_len, buf, buf_len);

  gcry_cipher_close(decr_ctx);
  if (error)
    return NULL;

  encr_tvb = tvb_new_child_real_data(tvb, decrypted_data, buf_len, buf_len);

  /* Add the decrypted data to the data source list. */
  add_new_data_source(pinfo, encr_tvb, "Decrypted IKE");

  return encr_tvb;
}

static proto_tree *dissect_payload_header(tvbuff_t *, packet_info *, int, int, int, guint8,
    guint8 *, guint16 *, proto_tree *);

static void dissect_sa(tvbuff_t *, int, int, proto_tree *, int, packet_info *, gboolean, void*);
static void dissect_proposal(tvbuff_t *, packet_info *, int, int, proto_tree *, int, void*);
static void dissect_transform(tvbuff_t *, packet_info *, int, int, proto_tree *, int, int, void*);
static void dissect_key_exch(tvbuff_t *, int, int, proto_tree *, int, packet_info *, void*);
static void dissect_id_type(tvbuff_t *, int, int, guint8, proto_tree *, proto_item *, packet_info *);
static void dissect_id(tvbuff_t *, int, int, proto_tree *, int, packet_info *);
static void dissect_cert(tvbuff_t *, int, int, proto_tree *, int, packet_info *);
static void dissect_certreq(tvbuff_t *, int, int, proto_tree *, int, packet_info *);
static void dissect_auth(tvbuff_t *, packet_info *, int, int, proto_tree *);
static void dissect_hash(tvbuff_t *, int, int, proto_tree *);
static void dissect_sig(tvbuff_t *, int, int, proto_tree *);
static void dissect_nonce(tvbuff_t *, int, int, proto_tree *);
static void dissect_notif(tvbuff_t *, packet_info *, int, int, proto_tree *, int);
static void dissect_delete(tvbuff_t *, int, int, proto_tree *, int);
static int dissect_vid(tvbuff_t *, int, int, proto_tree *);
static void dissect_config(tvbuff_t *, packet_info *, int, int, proto_tree *, int, gboolean);
static void dissect_sa_kek(tvbuff_t *, packet_info *, int, int, proto_tree *);
static void dissect_sa_tek(tvbuff_t *, packet_info *, int, int, proto_tree *);
static void dissect_key_download(tvbuff_t *, packet_info *, int, int, proto_tree *, int);
static void dissect_sequence(tvbuff_t *, packet_info *, int, int, proto_tree *);
static void dissect_nat_discovery(tvbuff_t *, int, int, proto_tree * );
static void dissect_nat_original_address(tvbuff_t *, int, int, proto_tree *, int );
static void dissect_ts_payload(tvbuff_t *, int, int, proto_tree *);
static tvbuff_t * dissect_enc(tvbuff_t *, int, int, proto_tree *, packet_info *, guint8, gboolean, void*, gboolean);
static void dissect_eap(tvbuff_t *, int, int, proto_tree *, packet_info *);
static void dissect_gspm(tvbuff_t *, int, int, proto_tree *);
static void dissect_cisco_fragmentation(tvbuff_t *, int, int, proto_tree *, packet_info *);

/* State of current fragmentation within a conversation */
typedef struct ikev2_fragmentation_state_t {
  guint32 message_id;
  guint8  next_payload;
} ikev2_fragmentation_state_t;

/* frame_number -> next_payload.  The key will be the frame that completes the original message */
static GHashTable *defrag_next_payload_hash = NULL;

static void dissect_ikev2_fragmentation(tvbuff_t *, int, proto_tree *, packet_info *, guint32 message_id, guint8 next_payload,
                                        gboolean is_request, void* decr_info);

static const guint8 VID_SSH_IPSEC_EXPRESS_1_1_0[] = { /* Ssh Communications Security IPSEC Express version 1.1.0 */
        0xfB, 0xF4, 0x76, 0x14, 0x98, 0x40, 0x31, 0xFA,
        0x8E, 0x3B, 0xB6, 0x19, 0x80, 0x89, 0xB2, 0x23
};

static const guint8 VID_SSH_IPSEC_EXPRESS_1_1_1[] = { /* Ssh Communications Security IPSEC Express version 1.1.1 */
        0x19, 0x52, 0xDC, 0x91, 0xAC, 0x20, 0xF6, 0x46,
        0xFB, 0x01, 0xCF, 0x42, 0xA3, 0x3A, 0xEE, 0x30
};

static const guint8 VID_SSH_IPSEC_EXPRESS_1_1_2[] = { /* Ssh Communications Security IPSEC Express version 1.1.2 */
        0xE8, 0xBF, 0xFA, 0x64, 0x3E, 0x5C, 0x8F, 0x2C,
        0xD1, 0x0F, 0xDA, 0x73, 0x70, 0xB6, 0xEB, 0xE5
};

static const guint8 VID_SSH_IPSEC_EXPRESS_1_2_1[] = { /* Ssh Communications Security IPSEC Express version 1.2.1 */
        0xC1, 0x11, 0x1B, 0x2D, 0xEE, 0x8C, 0xBC, 0x3D,
        0x62, 0x05, 0x73, 0xEC, 0x57, 0xAA, 0xB9, 0xCB
};

static const guint8 VID_SSH_IPSEC_EXPRESS_1_2_2[] = { /* Ssh Communications Security IPSEC Express version 1.2.2 */
        0x09, 0xEC, 0x27, 0xBF, 0xBC, 0x09, 0xC7, 0x58,
        0x23, 0xCF, 0xEC, 0xBF, 0xFE, 0x56, 0x5A, 0x2E
};

static const guint8 VID_SSH_IPSEC_EXPRESS_2_0_0[] = { /* SSH Communications Security IPSEC Express version 2.0.0 */
        0x7F, 0x21, 0xA5, 0x96, 0xE4, 0xE3, 0x18, 0xF0,
        0xB2, 0xF4, 0x94, 0x4C, 0x23, 0x84, 0xCB, 0x84
};

static const guint8 VID_SSH_IPSEC_EXPRESS_2_1_0[] = { /* SSH Communications Security IPSEC Express version 2.1.0 */
        0x28, 0x36, 0xD1, 0xFD, 0x28, 0x07, 0xBC, 0x9E,
        0x5A, 0xE3, 0x07, 0x86, 0x32, 0x04, 0x51, 0xEC
};

static const guint8 VID_SSH_IPSEC_EXPRESS_2_1_1[] = { /* SSH Communications Security IPSEC Express version 2.1.1 */
        0xA6, 0x8D, 0xE7, 0x56, 0xA9, 0xC5, 0x22, 0x9B,
        0xAE, 0x66, 0x49, 0x80, 0x40, 0x95, 0x1A, 0xD5
};

static const guint8 VID_SSH_IPSEC_EXPRESS_2_1_2[] = { /* SSH Communications Security IPSEC Express version 2.1.2 */
        0x3F, 0x23, 0x72, 0x86, 0x7E, 0x23, 0x7C, 0x1C,
        0xD8, 0x25, 0x0A, 0x75, 0x55, 0x9C, 0xAE, 0x20
};

static const guint8 VID_SSH_IPSEC_EXPRESS_3_0_0[] = { /* SSH Communications Security IPSEC Express version 3.0.0 */
        0x0E, 0x58, 0xD5, 0x77, 0x4D, 0xF6, 0x02, 0x00,
        0x7D, 0x0B, 0x02, 0x44, 0x36, 0x60, 0xF7, 0xEB
};

static const guint8 VID_SSH_IPSEC_EXPRESS_3_0_1[] = { /* SSH Communications Security IPSEC Express version 3.0.1 */
        0xF5, 0xCE, 0x31, 0xEB, 0xC2, 0x10, 0xF4, 0x43,
        0x50, 0xCF, 0x71, 0x26, 0x5B, 0x57, 0x38, 0x0F
};

static const guint8 VID_SSH_IPSEC_EXPRESS_4_0_0[] = { /* SSH Communications Security IPSEC Express version 4.0.0 */
        0xF6, 0x42, 0x60, 0xAF, 0x2E, 0x27, 0x42, 0xDA,
        0xDD, 0xD5, 0x69, 0x87, 0x06, 0x8A, 0x99, 0xA0
};

static const guint8 VID_SSH_IPSEC_EXPRESS_4_0_1[] = { /* SSH Communications Security IPSEC Express version 4.0.1 */
        0x7A, 0x54, 0xD3, 0xBD, 0xB3, 0xB1, 0xE6, 0xD9,
        0x23, 0x89, 0x20, 0x64, 0xBE, 0x2D, 0x98, 0x1C
};

static const guint8 VID_SSH_IPSEC_EXPRESS_4_1_0[] = { /* SSH Communications Security IPSEC Express version 4.1.0 */
        0x9A, 0xA1, 0xF3, 0xB4, 0x34, 0x72, 0xA4, 0x5D,
        0x5F, 0x50, 0x6A, 0xEB, 0x26, 0x0C, 0xF2, 0x14
};

static const guint8 VID_SSH_IPSEC_EXPRESS_4_1_1[] = { /* SSH Communications Security IPSEC Express version 4.1.1 */
        0x89, 0xF7, 0xB7, 0x60, 0xD8, 0x6B, 0x01, 0x2A,
        0xCF, 0x26, 0x33, 0x82, 0x39, 0x4D, 0x96, 0x2F
};

static const guint8 VID_SSH_IPSEC_EXPRESS_4_2_0[] = { /* SSH Communications Security IPSEC Express version 4.2.0 */
        0x68, 0x80, 0xC7, 0xD0, 0x26, 0x09, 0x91, 0x14,
        0xE4, 0x86, 0xC5, 0x54, 0x30, 0xE7, 0xAB, 0xEE
};

static const guint8 VID_SSH_IPSEC_EXPRESS_5_0[] = { /* SSH Communications Security IPSEC Express version 5.0 */
        0xB0, 0x37, 0xA2, 0x1A, 0xCE, 0xCC, 0xB5, 0x57,
        0x0F, 0x60, 0x25, 0x46, 0xF9, 0x7B, 0xDE, 0x8C
};

static const guint8 VID_SSH_IPSEC_EXPRESS_5_0_0[] = { /* SSH Communications Security IPSEC Express version 5.0.0 */
        0x2B, 0x2D, 0xAD, 0x97, 0xC4, 0xD1, 0x40, 0x93,
        0x00, 0x53, 0x28, 0x7F, 0x99, 0x68, 0x50, 0xB0
};

static const guint8 VID_SSH_IPSEC_EXPRESS_5_1_0[] = { /* SSH Communications Security IPSEC Express version 5.1.0 */
        0x45, 0xE1, 0x7F, 0x3A, 0xBE, 0x93, 0x94, 0x4C,
        0xB2, 0x02, 0x91, 0x0C, 0x59, 0xEF, 0x80, 0x6B
};

static const guint8 VID_SSH_IPSEC_EXPRESS_5_1_1[] = { /* SSH Communications Security IPSEC Express version 5.1.1 */
        0x59, 0x25, 0x85, 0x9F, 0x73, 0x77, 0xED, 0x78,
        0x16, 0xD2, 0xFB, 0x81, 0xC0, 0x1F, 0xA5, 0x51
};

static const guint8 VID_SSH_SENTINEL[] = { /* SSH Sentinel */
        0x05, 0x41, 0x82, 0xA0, 0x7C, 0x7A, 0xE2, 0x06,
        0xF9, 0xD2, 0xCF, 0x9D, 0x24, 0x32, 0xC4, 0x82
};

static const guint8 VID_SSH_SENTINEL_1_1[] = { /* SSH Sentinel 1.1 */
        0xB9, 0x16, 0x23, 0xE6, 0x93, 0xCA, 0x18, 0xA5,
        0x4C, 0x6A, 0x27, 0x78, 0x55, 0x23, 0x05, 0xE8
};

static const guint8 VID_SSH_SENTINEL_1_2[] = { /* SSH Sentinel 1.2 */
        0x54, 0x30, 0x88, 0x8D, 0xE0, 0x1A, 0x31, 0xA6,
        0xFA, 0x8F, 0x60, 0x22, 0x4E, 0x44, 0x99, 0x58
};

static const guint8 VID_SSH_SENTINEL_1_3[] = { /* SSH Sentinel 1.3 */
        0x7E, 0xE5, 0xCB, 0x85, 0xF7, 0x1C, 0xE2, 0x59,
        0xC9, 0x4A, 0x5C, 0x73, 0x1E, 0xE4, 0xE7, 0x52
};

static const guint8 VID_SSH_SENTINEL_1_4[] = { /* SSH Sentinel 1.4 */
        0x63, 0xD9, 0xA1, 0xA7, 0x00, 0x94, 0x91, 0xB5,
        0xA0, 0xA6, 0xFD, 0xEB, 0x2A, 0x82, 0x84, 0xF0
};

static const guint8 VID_SSH_SENTINEL_1_4_1[] = { /* SSH Sentinel 1.4.1 */
        0xEB, 0x4B, 0x0D, 0x96, 0x27, 0x6B, 0x4E, 0x22,
        0x0A, 0xD1, 0x62, 0x21, 0xA7, 0xB2, 0xA5, 0xE6
};

static const guint8 VID_SSH_QUICKSEC_0_9_0[] = { /* SSH Communications Security QuickSec 0.9.0 */
        0x37, 0xEB, 0xA0, 0xC4, 0x13, 0x61, 0x84, 0xE7,
        0xDA, 0xF8, 0x56, 0x2A, 0x77, 0x06, 0x0B, 0x4A
};

static const guint8 VID_SSH_QUICKSEC_1_1_0[] = { /* SSH Communications Security QuickSec 1.1.0 */
        0x5D, 0x72, 0x92, 0x5E, 0x55, 0x94, 0x8A, 0x96,
        0x61, 0xA7, 0xFC, 0x48, 0xFD, 0xEC, 0x7F, 0xF9
};

static const guint8 VID_SSH_QUICKSEC_1_1_1[] = { /* SSH Communications Security QuickSec 1.1.1 */
        0x77, 0x7F, 0xBF, 0x4C, 0x5A, 0xF6, 0xD1, 0xCD,
        0xD4, 0xB8, 0x95, 0xA0, 0x5B, 0xF8, 0x25, 0x94
};

static const guint8 VID_SSH_QUICKSEC_1_1_2[] = { /* SSH Communications Security QuickSec 1.1.2 */
        0x2C, 0xDF, 0x08, 0xE7, 0x12, 0xED, 0xE8, 0xA5,
        0x97, 0x87, 0x61, 0x26, 0x7C, 0xD1, 0x9B, 0x91
};

static const guint8 VID_SSH_QUICKSEC_1_1_3[] = { /* SSH Communications Security QuickSec 1.1.3 */
        0x59, 0xE4, 0x54, 0xA8, 0xC2, 0xCF, 0x02, 0xA3,
        0x49, 0x59, 0x12, 0x1F, 0x18, 0x90, 0xBC, 0x87
};

static const guint8 VID_draft_huttunen_ipsec_esp_in_udp_00[] = { /* draft-huttunen-ipsec-esp-in-udp-00.txt */
        0x6A, 0x74, 0x34, 0xC1, 0x9D, 0x7E, 0x36, 0x34,
        0x80, 0x90, 0xA0, 0x23, 0x34, 0xC9, 0xC8, 0x05
};

static const guint8 VID_draft_huttunen_ipsec_esp_in_udp_01[] = { /* draft-huttunen-ipsec-esp-in-udp-01.txt */
        0x50, 0x76, 0x0F, 0x62, 0x4C, 0x63, 0xE5, 0xC5,
        0x3E, 0xEA, 0x38, 0x6C, 0x68, 0x5C, 0xA0, 0x83
};

static const guint8 VID_draft_stenberg_ipsec_nat_traversal_01[] = { /* draft-stenberg-ipsec-nat-traversal-01 */
        0x27, 0xBA, 0xB5, 0xDC, 0x01, 0xEA, 0x07, 0x60,
        0xEA, 0x4E, 0x31, 0x90, 0xAC, 0x27, 0xC0, 0xD0
};

static const guint8 VID_draft_stenberg_ipsec_nat_traversal_02[]= { /* draft-stenberg-ipsec-nat-traversal-02 */
        0x61, 0x05, 0xC4, 0x22, 0xE7, 0x68, 0x47, 0xE4,
        0x3F, 0x96, 0x84, 0x80, 0x12, 0x92, 0xAE, 0xCD
};

static const guint8 VID_draft_ietf_ipsec_nat_t_ike[]= { /* draft-ietf-ipsec-nat-t-ike */
        0x4D, 0xF3, 0x79, 0x28, 0xE9, 0xFC, 0x4F, 0xD1,
        0xB3, 0x26, 0x21, 0x70, 0xD5, 0x15, 0xC6, 0x62
};

static const guint8 VID_draft_ietf_ipsec_nat_t_ike_00[]= { /* draft-ietf-ipsec-nat-t-ike-00 */
        0x44, 0x85, 0x15, 0x2D, 0x18, 0xB6, 0xBB, 0xCD,
        0x0B, 0xE8, 0xA8, 0x46, 0x95, 0x79, 0xDD, 0xCC
};

static const guint8 VID_draft_ietf_ipsec_nat_t_ike_01[]= { /* "draft-ietf-ipsec-nat-t-ike-01" */
        0x16, 0xF6, 0xCA, 0x16, 0xE4, 0xA4, 0x06, 0x6D,
        0x83, 0x82, 0x1A, 0x0F, 0x0A, 0xEA, 0xA8, 0x62
};

static const guint8 VID_draft_ietf_ipsec_nat_t_ike_02[]= { /* draft-ietf-ipsec-nat-t-ike-02 */
        0xCD, 0x60, 0x46, 0x43, 0x35, 0xDF, 0x21, 0xF8,
        0x7C, 0xFD, 0xB2, 0xFC, 0x68, 0xB6, 0xA4, 0x48
};

static const guint8 VID_draft_ietf_ipsec_nat_t_ike_02n[]= { /* draft-ietf-ipsec-nat-t-ike-02\n */
        0x90, 0xCB, 0x80, 0x91, 0x3E, 0xBB, 0x69, 0x6E,
        0x08, 0x63, 0x81, 0xB5, 0xEC, 0x42, 0x7B, 0x1F
};

static const guint8 VID_draft_ietf_ipsec_nat_t_ike_03[] = { /* draft-ietf-ipsec-nat-t-ike-03 */
        0x7D, 0x94, 0x19, 0xA6, 0x53, 0x10, 0xCA, 0x6F,
        0x2C, 0x17, 0x9D, 0x92, 0x15, 0x52, 0x9d, 0x56
};

static const guint8 VID_draft_ietf_ipsec_nat_t_ike_04[] = { /* draft-ietf-ipsec-nat-t-ike-04 */
        0x99, 0x09, 0xb6, 0x4e, 0xed, 0x93, 0x7c, 0x65,
        0x73, 0xde, 0x52, 0xac, 0xe9, 0x52, 0xfa, 0x6b
};
static const guint8 VID_draft_ietf_ipsec_nat_t_ike_05[] = { /* draft-ietf-ipsec-nat-t-ike-05 */
        0x80, 0xd0, 0xbb, 0x3d, 0xef, 0x54, 0x56, 0x5e,
        0xe8, 0x46, 0x45, 0xd4, 0xc8, 0x5c, 0xe3, 0xee
};
static const guint8 VID_draft_ietf_ipsec_nat_t_ike_06[] = { /* draft-ietf-ipsec-nat-t-ike-06 */
        0x4d, 0x1e, 0x0e, 0x13, 0x6d, 0xea, 0xfa, 0x34,
        0xc4, 0xf3, 0xea, 0x9f, 0x02, 0xec, 0x72, 0x85
};
static const guint8 VID_draft_ietf_ipsec_nat_t_ike_07[] = { /* draft-ietf-ipsec-nat-t-ike-07 */
        0x43, 0x9b, 0x59, 0xf8, 0xba, 0x67, 0x6c, 0x4c,
        0x77, 0x37, 0xae, 0x22, 0xea, 0xb8, 0xf5, 0x82
};
static const guint8 VID_draft_ietf_ipsec_nat_t_ike_08[] = { /* draft-ietf-ipsec-nat-t-ike-08 */
        0x8f, 0x8d, 0x83, 0x82, 0x6d, 0x24, 0x6b, 0x6f,
        0xc7, 0xa8, 0xa6, 0xa4, 0x28, 0xc1, 0x1d, 0xe8
};
static const guint8 VID_draft_ietf_ipsec_nat_t_ike_09[] = { /* draft-ietf-ipsec-nat-t-ike-09 */
        0x42, 0xea, 0x5b, 0x6f, 0x89, 0x8d, 0x97, 0x73,
        0xa5, 0x75, 0xdf, 0x26, 0xe7, 0xdd, 0x19, 0xe1
};
static const guint8 VID_testing_nat_t_rfc[] = { /* Testing NAT-T RFC */
        0xc4, 0x0f, 0xee, 0x00, 0xd5, 0xd3, 0x9d, 0xdb,
        0x1f, 0xc7, 0x62, 0xe0, 0x9b, 0x7c, 0xfe, 0xa7
};

static const guint8 VID_rfc3947_nat_t[] = { /* RFC 3947 Negotiation of NAT-Traversal in the IKE */
        0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45,
        0x5c, 0x57, 0x28, 0xf2, 0x0e, 0x95, 0x45, 0x2f
};
static const guint8 VID_draft_beaulieu_ike_xauth_02[]= { /* draft-beaulieu-ike-xauth-02.txt 02 or 06 ??*/
        0x09, 0x00, 0x26, 0x89, 0xDF, 0xD6, 0xB7, 0x12,
        0x80, 0xA2, 0x24, 0xDE, 0xC3, 0x3B, 0x81, 0xE5
};

static const guint8 VID_xauth[]= { /* XAUTH (truncated MD5 hash of "draft-ietf-ipsra-isakmp-xauth-06.txt") */
        0x09, 0x00, 0x26, 0x89, 0xDF, 0xD6, 0xB7, 0x12
};

static const guint8 VID_rfc3706_dpd[]= { /* RFC 3706 */
        0xAF, 0xCA, 0xD7, 0x13, 0x68, 0xA1, 0xF1, 0xC9,
        0x6B, 0x86, 0x96, 0xFC, 0x77, 0x57, 0x01, 0x00
};
static const guint8 VID_draft_ietf_ipsec_antireplay_00[]= { /* draft-ietf-ipsec-antireplay-00.txt */
        0x32, 0x5D, 0xF2, 0x9A, 0x23, 0x19, 0xF2, 0xDD
};

static const guint8 VID_draft_ietf_ipsec_heartbeats_00[]= { /* draft-ietf-ipsec-heartbeats-00.txt */
        0x8D, 0xB7, 0xA4, 0x18, 0x11, 0x22, 0x16, 0x60
};
static const guint8 VID_IKE_CHALLENGE_RESPONSE_1[]= { /* IKE Challenge/Response for Authenticated Cryptographic Keys */
        0xBA, 0x29, 0x04, 0x99, 0xC2, 0x4E, 0x84, 0xE5,
        0x3A, 0x1D, 0x83, 0xA0, 0x5E, 0x5F, 0x00, 0xC9
};

static const guint8 VID_IKE_CHALLENGE_RESPONSE_2[]= { /* IKE Challenge/Response for Authenticated Cryptographic Keys */
        0x0D, 0x33, 0x61, 0x1A, 0x5D, 0x52, 0x1B, 0x5E,
        0x3C, 0x9C, 0x03, 0xD2, 0xFC, 0x10, 0x7E, 0x12
};

static const guint8 VID_IKE_CHALLENGE_RESPONSE_REV_1[]= { /* IKE Challenge/Response for Authenticated Cryptographic Keys (Revised) */

        0xAD, 0x32, 0x51, 0x04, 0x2C, 0xDC, 0x46, 0x52,
        0xC9, 0xE0, 0x73, 0x4C, 0xE5, 0xDE, 0x4C, 0x7D
};

static const guint8 VID_IKE_CHALLENGE_RESPONSE_REV_2[]= { /* IKE Challenge/Response for Authenticated Cryptographic Keys (Revised) */
        0x01, 0x3F, 0x11, 0x82, 0x3F, 0x96, 0x6F, 0xA9,
        0x19, 0x00, 0xF0, 0x24, 0xBA, 0x66, 0xA8, 0x6B
};

static const guint8 VID_CISCO_FRAG2[]= { /* Cisco Fragmentation - md5("FRAGMENTATION") */
        0x40, 0x48, 0xB7, 0xD5, 0x6E, 0xBC, 0xE8, 0x85,
        0x25, 0xE7, 0xDE, 0x7F, 0x00, 0xD6, 0xC2, 0xD3
};

static const guint8 VID_MS_VID_INITIAL_CONTACT[]= { /* Microsoft Vid-Initial-Contact */
        0x26, 0x24, 0x4d, 0x38, 0xed, 0xdb, 0x61, 0xb3,
        0x17, 0x2a, 0x36, 0xe3, 0xd0, 0xcf, 0xb8, 0x19
};

static const guint8 VID_GSS_API_1[]= { /* A GSS-API Authentication Method for IKE */
        0xB4, 0x6D, 0x89, 0x14, 0xF3, 0xAA, 0xA3, 0xF2,
        0xFE, 0xDE, 0xB7, 0xC7, 0xDB, 0x29, 0x43, 0xCA
};

static const guint8 VID_GSS_API_2[]= { /* A GSS-API Authentication Method for IKE */
        0xAD, 0x2C, 0x0D, 0xD0, 0xB9, 0xC3, 0x20, 0x83,
        0xCC, 0xBA, 0x25, 0xB8, 0x86, 0x1E, 0xC4, 0x55
};

static const guint8 VID_GSSAPI[]= { /* GSSAPI */
        0x62, 0x1B, 0x04, 0xBB, 0x09, 0x88, 0x2A, 0xC1,
        0xE1, 0x59, 0x35, 0xFE, 0xFA, 0x24, 0xAE, 0xEE
};

static const guint8 VID_MS_NT5_ISAKMPOAKLEY[]= { /* MS NT5 ISAKMPOAKLEY */
        0x1E, 0x2B, 0x51, 0x69, 0x05, 0x99, 0x1C, 0x7D,
        0x7C, 0x96, 0xFC, 0xBF, 0xB5, 0x87, 0xE4, 0x61
};

static const guint8 VID_CISCO_UNITY[]= { /* CISCO-UNITY */
        0x12, 0xF5, 0xF2, 0x8C, 0x45, 0x71, 0x68, 0xA9,
        0x70, 0x2D, 0x9F, 0xE2, 0x74, 0xCC
};


static const guint8 VID_CISCO_CONCENTRATOR[]= { /* CISCO-CONCENTRATOR */
        0x1F, 0x07, 0xF7, 0x0E, 0xAA, 0x65, 0x14, 0xD3,
        0xB0, 0xFA, 0x96, 0x54, 0x2A, 0x50, 0x01, 0x00
};
static const guint8 VID_CISCO_FRAG[] = { /* Cisco Fragmentation */
        0x40, 0x48, 0xB7, 0xD5, 0x6E, 0xBC, 0xE8, 0x85,
        0x25, 0xE7, 0xDE, 0x7F, 0x00, 0xD6, 0xC2, 0xD3,
        0x80, 0x00, 0x00, 0x00
};

static const guint8 VID_CISCO_FLEXVPN_SUPPORTED[] = { /* FLEXVPN-SUPPORTED */
        0x46, 0x4c, 0x45, 0x58, 0x56, 0x50, 0x4e, 0x2d,
        0x53, 0x55, 0x50, 0x50, 0x4f, 0x52, 0x54, 0x45,
        0x44
};

static const guint8 VID_CISCO_DELETE_REASON[] = { /* CISCO-DELETE-REASON */
        0x43, 0x49, 0x53, 0x43, 0x4f, 0x2d, 0x44, 0x45,
        0x4c, 0x45, 0x54, 0x45, 0x2d, 0x52, 0x45, 0x41,
        0x53, 0x4f, 0x4e
};

static const guint8 VID_CISCO_DYNAMIC_ROUTE[] = { /* CISCO-DYNAMIC-ROUTE */
        0x43, 0x49, 0x53, 0x43, 0x4f, 0x2d, 0x44, 0x59,
        0x4e, 0x41, 0x4d, 0x49, 0x43, 0x2d, 0x52, 0x4f,
        0x55, 0x54, 0x45
};

static const guint8 VID_CISCO_VPN_REV_02[] = { /* CISCO-VPN-REV-02 */
        0x43, 0x49, 0x53, 0x43, 0x4f, 0x56, 0x50, 0x4e,
        0x2d, 0x52, 0x45, 0x56, 0x2d, 0x30, 0x32
};

/* CISCO(COPYRIGHT)&Copyright (c) 2009 Cisco Systems, Inc. */
static const guint8 VID_CISCO_COPYRIGHT[] = { /* Cisco Copyright */
        0x43, 0x49, 0x53, 0x43, 0x4f, 0x28, 0x43, 0x4f,
        0x50, 0x59, 0x52, 0x49, 0x47, 0x48, 0x54, 0x29,
        0x26, 0x43, 0x6f, 0x70, 0x79, 0x72, 0x69, 0x67,
        0x68, 0x74, 0x20, 0x28, 0x63, 0x29, 0x20, 0x32,
        0x30, 0x30, 0x39, 0x20, 0x43, 0x69, 0x73, 0x63,
        0x6f, 0x20, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d,
        0x73, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e
};

static const guint8 VID_CISCO_GRE_MODE[] = { /* CISCO-GRE-MODE */
        0x43, 0x49, 0x53, 0x43, 0x4f, 0x2d, 0x47, 0x52,
        0x45, 0x2d, 0x4d, 0x4f, 0x44, 0x45
};

static const guint8 VID_CP_01_R65[] = { /* CryptoPro/GOST 0.1 / Check Point R65 */
        0xF4, 0xED, 0x19, 0xE0, 0xC1, 0x14, 0xEB, 0x51,
        0x6F, 0xAA, 0xAC, 0x0E, 0xE3, 0x7D, 0xAF, 0x28,
        0x7, 0xB4, 0x38, 0x1F
};

static const guint8 VID_CP_10_R71[] = { /* CryptoPro/GOST 1.0 / Check Point R71 */
        0x03, 0x10, 0x17, 0xE0, 0x7F, 0x7A, 0x82, 0xE3,
        0xAA, 0x69, 0x50, 0xC9, 0x99, 0x99, 0x01, 0x00
};

static const guint8 VID_CP_11[] = { /* CryptoPro/GOST 1.1 */
        0x03, 0x10, 0x17, 0xE0, 0x7F, 0x7A, 0x82, 0xE3,
        0xAA, 0x69, 0x50, 0xC9, 0x99, 0x99, 0x01, 0x01
};

static const guint8 VID_CYBERGUARD[] = { /* CyberGuard */
        0x9A, 0xA1, 0xF3, 0xB4, 0x34, 0x72, 0xA4, 0x5D,
        0x5F, 0x50, 0x6A, 0xEB, 0x26, 0xC0, 0xF2, 0x14
};

static const guint8 VID_SHREWSOFT[] = { /* Shrew Soft */
        0xf1, 0x4b, 0x94, 0xb7, 0xbf, 0xf1, 0xfe, 0xf0,
        0x27, 0x73, 0xb8, 0xc4, 0x9f, 0xed, 0xed, 0x26
};
static const guint8 VID_STRONGSWAN[] = { /* strongSwan */
        0x88, 0x2f, 0xe5, 0x6d, 0x6f, 0xd2, 0x0d, 0xbc,
        0x22, 0x51, 0x61, 0x3b, 0x2e, 0xbe, 0x5b, 0xeb
};
static const guint8 VID_KAME_RACOON[] = { /* KAME/racoon */
        0x70, 0x03, 0xcb, 0xc1, 0x09, 0x7d, 0xbe, 0x9c,
        0x26, 0x00, 0xba, 0x69, 0x83, 0xbc, 0x8b, 0x35
};

static const guint8 VID_IPSEC_TOOLS[] = { /* IPsec-Tools */
        0x20, 0xa3, 0x62, 0x2c, 0x1c, 0xea, 0x7c, 0xe3,
        0x7b, 0xee, 0x3c, 0xa4, 0x84, 0x42, 0x52, 0x76
};

static const guint8 VID_NETSCREEN_1[] = { /* Netscreen-1 */
        0x29, 0x9e, 0xe8, 0x28, 0x9f, 0x40, 0xa8, 0x97,
        0x3b, 0xc7, 0x86, 0x87, 0xe2, 0xe7, 0x22, 0x6b,
        0x53, 0x2c, 0x3b, 0x76
};

static const guint8 VID_NETSCREEN_2[] = { /* Netscreen-2 */
        0x3a, 0x15, 0xe1, 0xf3, 0xcf, 0x2a, 0x63, 0x58,
        0x2e, 0x3a, 0xc8, 0x2d, 0x1c, 0x64, 0xcb, 0xe3,
        0xb6, 0xd7, 0x79, 0xe7
};

static const guint8 VID_NETSCREEN_3[] = { /* Netscreen-3 */
        0x47, 0xd2, 0xb1, 0x26, 0xbf, 0xcd, 0x83, 0x48,
        0x97, 0x60, 0xe2, 0xcf, 0x8c, 0x5d, 0x4d, 0x5a,
        0x03, 0x49, 0x7c, 0x15
};

static const guint8 VID_NETSCREEN_4[] = { /* Netscreen-4 */
        0x4a, 0x43, 0x40, 0xb5, 0x43, 0xe0, 0x2b, 0x84,
        0xc8, 0x8a, 0x8b, 0x96, 0xa8, 0xaf, 0x9e, 0xbe,
        0x77, 0xd9, 0xac, 0xcc
};

static const guint8 VID_NETSCREEN_5[] = { /* Netscreen-5 */
        0x64, 0x40, 0x5f, 0x46, 0xf0, 0x3b, 0x76, 0x60,
        0xa2, 0x3b, 0xe1, 0x16, 0xa1, 0x97, 0x50, 0x58,
        0xe6, 0x9e, 0x83, 0x87
};

static const guint8 VID_NETSCREEN_6[] = { /* Netscreen-6 */
        0x69, 0x93, 0x69, 0x22, 0x87, 0x41, 0xc6, 0xd4,
        0xca, 0x09, 0x4c, 0x93, 0xe2, 0x42, 0xc9, 0xde,
        0x19, 0xe7, 0xb7, 0xc6
};

static const guint8 VID_NETSCREEN_7[] = { /* Netscreen-7 */
        0x8c, 0x0d, 0xc6, 0xcf, 0x62, 0xa0, 0xef, 0x1b,
        0x5c, 0x6e, 0xab, 0xd1, 0xb6, 0x7b, 0xa6, 0x98,
        0x66, 0xad, 0xf1, 0x6a
};

static const guint8 VID_NETSCREEN_8[] = { /* Netscreen-8 */
        0x92, 0xd2, 0x7a, 0x9e, 0xcb, 0x31, 0xd9, 0x92,
        0x46, 0x98, 0x6d, 0x34, 0x53, 0xd0, 0xc3, 0xd5,
        0x7a, 0x22, 0x2a, 0x61
};

static const guint8 VID_NETSCREEN_9[] = { /* Netscreen-9 */
        0x9b, 0x09, 0x6d, 0x9a, 0xc3, 0x27, 0x5a, 0x7d,
        0x6f, 0xe8, 0xb9, 0x1c, 0x58, 0x31, 0x11, 0xb0,
        0x9e, 0xfe, 0xd1, 0xa0
};

static const guint8 VID_NETSCREEN_10[] = { /* Netscreen-10 */
        0xbf, 0x03, 0x74, 0x61, 0x08, 0xd7, 0x46, 0xc9,
        0x04, 0xf1, 0xf3, 0x54, 0x7d, 0xe2, 0x4f, 0x78,
        0x47, 0x9f, 0xed, 0x12
};

static const guint8 VID_NETSCREEN_11[] = { /* Netscreen-11 */
        0xc2, 0xe8, 0x05, 0x00, 0xf4, 0xcc, 0x5f, 0xbf,
        0x5d, 0xaa, 0xee, 0xd3, 0xbb, 0x59, 0xab, 0xae,
        0xee, 0x56, 0xc6, 0x52
};

static const guint8 VID_NETSCREEN_12[] = { /* Netscreen-12 */
        0xc8, 0x66, 0x0a, 0x62, 0xb0, 0x3b, 0x1b, 0x61,
        0x30, 0xbf, 0x78, 0x16, 0x08, 0xd3, 0x2a, 0x6a,
        0x8d, 0x0f, 0xb8, 0x9f
};

static const guint8 VID_NETSCREEN_13[] = { /* Netscreen-13 */
        0xf8, 0x85, 0xda, 0x40, 0xb1, 0xe7, 0xa9, 0xab,
        0xd1, 0x76, 0x55, 0xec, 0x5b, 0xbe, 0xc0, 0xf2,
        0x1f, 0x0e, 0xd5, 0x2e
};

static const guint8 VID_NETSCREEN_14[] = { /* Netscreen-14 */
        0x2a, 0x2b, 0xca, 0xc1, 0x9b, 0x8e, 0x91, 0xb4,
        0x26, 0x10, 0x78, 0x07, 0xe0, 0x2e, 0x72, 0x49,
        0x56, 0x9d, 0x6f, 0xd3
};
static const guint8 VID_NETSCREEN_15[] = { /* Netscreen-15 */
        0x16, 0x6f, 0x93, 0x2d, 0x55, 0xeb, 0x64, 0xd8,
        0xe4, 0xdf, 0x4f, 0xd3, 0x7e, 0x23, 0x13, 0xf0,
        0xd0, 0xfd, 0x84, 0x51
};

static const guint8 VID_NETSCREEN_16[] = { /* Netscreen-16 */
        0xa3, 0x5b, 0xfd, 0x05, 0xca, 0x1a, 0xc0, 0xb3,
        0xd2, 0xf2, 0x4e, 0x9e, 0x82, 0xbf, 0xcb, 0xff,
        0x9c, 0x9e, 0x52, 0xb5
};

static const guint8 VID_ZYWALL[] = { /* ZYWALL */
        0x62, 0x50, 0x27, 0x74, 0x9d, 0x5a, 0xb9, 0x7f,
        0x56, 0x16, 0xc1, 0x60, 0x27, 0x65, 0xcf, 0x48,
        0x0a, 0x3b, 0x7d, 0x0b
};

static const guint8 VID_SIDEWINDER[] = { /* SIDEWINDER */
        0x84, 0x04, 0xad, 0xf9, 0xcd, 0xa0, 0x57, 0x60,
        0xb2, 0xca, 0x29, 0x2e, 0x4b, 0xff, 0x53, 0x7b
};

static const guint8 VID_SONICWALL[] = { /* SonicWALL */
        0x40, 0x4B, 0xF4, 0x39, 0x52, 0x2C, 0xA3, 0xF6
};

static const guint8 VID_HEARTBEAT_NOTIFY[] = { /* Heartbeat Notify */
        0x48 ,0x65, 0x61, 0x72, 0x74, 0x42, 0x65, 0x61,
        0x74, 0x5f, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79
};

static const guint8 VID_DWR[] = { /* DWR: Delete with reason */
        0x2D, 0x79, 0x22, 0xC6, 0xB3, 0x01, 0xD9, 0xB0,
        0xE1, 0x34, 0x27, 0x39, 0xE9, 0xCF, 0xBB, 0xD5
};

static const guint8 VID_ARUBA_RAP[] = { /* Remote AP (Aruba Networks)  */
        0xca, 0x3e, 0x2b, 0x85, 0x4b, 0xa8, 0x03, 0x00,
        0x17, 0xdc, 0x10, 0x23, 0xa4, 0xfd, 0xe2, 0x04,
        0x1f, 0x9f, 0x74, 0x63
};

static const guint8 VID_ARUBA_CONTROLLER[] = { /* Controller (Aruba Networks)  */
        0x3c, 0x8e, 0x70, 0xbd, 0xf9, 0xc7, 0xd7, 0x4a,
        0xdd, 0x53, 0xe4, 0x10, 0x09, 0x15, 0xdc, 0x2e,
        0x4b, 0xb5, 0x12, 0x74
};

static const guint8 VID_ARUBA_VIA_CLIENT[] = { /* VIA Client (Aruba Networks)  */
        0x88, 0xf0, 0xe3, 0x14, 0x9b, 0x3f, 0xa4, 0x8b,
        0x05, 0xaa, 0x7f, 0x68, 0x5f, 0x0b, 0x76, 0x6b,
        0xe1, 0x86, 0xcc, 0xb8
};

static const guint8 VID_ARUBA_VIA_AUTH_PROFILE[] = { /* VIA Auth Profile (Aruba Networks)  */
        0x56, 0x49, 0x41, 0x20, 0x41, 0x75, 0x74, 0x68,
        0x20, 0x50, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65,
        0x20, 0x3a, 0x20
};

/*
 * MS-IKEE Internet Key Exchange Protocol Extensions (v20080212).pdf
 * Windows Vista and Windows Server 2008
*/
static const guint8 VID_MS_IKEE_20080212_CGA1[] = { /* IKE CGA Version 1 */
        0xe3, 0xa5, 0x96, 0x6a, 0x76, 0x37, 0x9f, 0xe7,
        0x07, 0x22, 0x82, 0x31, 0xe5, 0xce, 0x86, 0x52
};

static const guint8 VID_MS_IKEE_20080212_MS_NDC[] = { /* MS-Negotiation Discovery Capable */
        0xfb, 0x1d, 0xe3, 0xcd, 0xf3, 0x41, 0xb7, 0xea,
        0x16, 0xb7, 0xe5, 0xbe, 0x08, 0x55, 0xf1, 0x20
};

static const guint8 VID_FORTINET_FORTIGATE[] = { /* Fortigate (Fortinet) */
        0x82, 0x99, 0x03, 0x17, 0x57, 0xA3, 0x60, 0x82,
        0xC6, 0xA6, 0x21, 0xDE
};

static const guint8 VID_FORTINET_FORTICLIENT_CONNECT[] = { /* Forticlient Connect license (Fortinet) */
        0x4C, 0x53, 0x42, 0x7B, 0x6D, 0x46, 0x5D, 0x1B,
        0x33, 0x7B, 0xB7, 0x55, 0xA3, 0x7A, 0x7F, 0xEF
};

static const guint8 VID_FORTINET_ENDPOINT_CONTROL[] = { /* Endpoint Control (Fortinet) */
        0xB4, 0xF0, 0x1C, 0xA9, 0x51, 0xE9, 0xDA, 0x8D,
        0x0B, 0xAF, 0xBB, 0xD3, 0x4A, 0xD3, 0x04, 0x4E
};

static const bytes_string vendor_id[] = {
  { VID_SSH_IPSEC_EXPRESS_1_1_0, sizeof(VID_SSH_IPSEC_EXPRESS_1_1_0), "Ssh Communications Security IPSEC Express version 1.1.0" },
  { VID_SSH_IPSEC_EXPRESS_1_1_1, sizeof(VID_SSH_IPSEC_EXPRESS_1_1_1), "Ssh Communications Security IPSEC Express version 1.1.1" },
  { VID_SSH_IPSEC_EXPRESS_1_1_2, sizeof(VID_SSH_IPSEC_EXPRESS_1_1_2), "Ssh Communications Security IPSEC Express version 1.1.2" },
  { VID_SSH_IPSEC_EXPRESS_1_2_1, sizeof(VID_SSH_IPSEC_EXPRESS_1_2_1), "Ssh Communications Security IPSEC Express version 1.2.1" },
  { VID_SSH_IPSEC_EXPRESS_1_2_2, sizeof(VID_SSH_IPSEC_EXPRESS_1_2_2), "Ssh Communications Security IPSEC Express version 1.2.2" },
  { VID_SSH_IPSEC_EXPRESS_2_0_0, sizeof(VID_SSH_IPSEC_EXPRESS_2_0_0), "SSH Communications Security IPSEC Express version 2.0.0" },
  { VID_SSH_IPSEC_EXPRESS_2_1_0, sizeof(VID_SSH_IPSEC_EXPRESS_2_1_0), "SSH Communications Security IPSEC Express version 2.1.0" },
  { VID_SSH_IPSEC_EXPRESS_2_1_1, sizeof(VID_SSH_IPSEC_EXPRESS_2_1_1), "SSH Communications Security IPSEC Express version 2.1.1" },
  { VID_SSH_IPSEC_EXPRESS_2_1_2, sizeof(VID_SSH_IPSEC_EXPRESS_2_1_2), "SSH Communications Security IPSEC Express version 2.1.2" },
  { VID_SSH_IPSEC_EXPRESS_3_0_0, sizeof(VID_SSH_IPSEC_EXPRESS_3_0_0), "SSH Communications Security IPSEC Express version 3.0.0" },
  { VID_SSH_IPSEC_EXPRESS_3_0_1, sizeof(VID_SSH_IPSEC_EXPRESS_3_0_1), "SSH Communications Security IPSEC Express version 3.0.1" },
  { VID_SSH_IPSEC_EXPRESS_4_0_0, sizeof(VID_SSH_IPSEC_EXPRESS_4_0_0), "SSH Communications Security IPSEC Express version 4.0.0" },
  { VID_SSH_IPSEC_EXPRESS_4_0_1, sizeof(VID_SSH_IPSEC_EXPRESS_4_0_1), "SSH Communications Security IPSEC Express version 4.0.1" },
  { VID_SSH_IPSEC_EXPRESS_4_1_0, sizeof(VID_SSH_IPSEC_EXPRESS_4_1_0), "SSH Communications Security IPSEC Express version 4.1.0" },
  { VID_SSH_IPSEC_EXPRESS_4_1_1, sizeof(VID_SSH_IPSEC_EXPRESS_4_1_1), "SSH Communications Security IPSEC Express version 4.1.1" },
  { VID_SSH_IPSEC_EXPRESS_4_2_0, sizeof(VID_SSH_IPSEC_EXPRESS_4_2_0), "SSH Communications Security IPSEC Express version 4.2.0" },
  { VID_SSH_IPSEC_EXPRESS_5_0,   sizeof(VID_SSH_IPSEC_EXPRESS_5_0),   "SSH Communications Security IPSEC Express version 5.0"   },
  { VID_SSH_IPSEC_EXPRESS_5_0_0, sizeof(VID_SSH_IPSEC_EXPRESS_5_0_0), "SSH Communications Security IPSEC Express version 5.0.0" },
  { VID_SSH_IPSEC_EXPRESS_5_1_0, sizeof(VID_SSH_IPSEC_EXPRESS_5_1_0), "SSH Communications Security IPSEC Express version 5.1.0" },
  { VID_SSH_IPSEC_EXPRESS_5_1_1, sizeof(VID_SSH_IPSEC_EXPRESS_5_1_1), "SSH Communications Security IPSEC Express version 5.1.1" },
  { VID_SSH_SENTINEL, sizeof(VID_SSH_SENTINEL), "SSH Sentinel" },
  { VID_SSH_SENTINEL_1_1, sizeof(VID_SSH_SENTINEL_1_1), "SSH Sentinel 1.1" },
  { VID_SSH_SENTINEL_1_2, sizeof(VID_SSH_SENTINEL_1_2), "SSH Sentinel 1.2" },
  { VID_SSH_SENTINEL_1_3, sizeof(VID_SSH_SENTINEL_1_3), "SSH Sentinel 1.3" },
  { VID_SSH_SENTINEL_1_4, sizeof(VID_SSH_SENTINEL_1_4), "SSH Sentinel 1.4" },
  { VID_SSH_SENTINEL_1_4_1, sizeof(VID_SSH_SENTINEL_1_4_1), "SSH Sentinel 1.4.1" },
  { VID_SSH_QUICKSEC_0_9_0, sizeof(VID_SSH_QUICKSEC_0_9_0), "SSH Communications Security QuickSec 0.9.0" },
  { VID_SSH_QUICKSEC_1_1_0, sizeof(VID_SSH_QUICKSEC_1_1_0), "SSH Communications Security QuickSec 1.1.0" },
  { VID_SSH_QUICKSEC_1_1_1, sizeof(VID_SSH_QUICKSEC_1_1_1), "SSH Communications Security QuickSec 1.1.1" },
  { VID_SSH_QUICKSEC_1_1_2, sizeof(VID_SSH_QUICKSEC_1_1_2), "SSH Communications Security QuickSec 1.1.2" },
  { VID_SSH_QUICKSEC_1_1_3, sizeof(VID_SSH_QUICKSEC_1_1_3), "SSH Communications Security QuickSec 1.1.3" },
  { VID_draft_huttunen_ipsec_esp_in_udp_00, sizeof(VID_draft_huttunen_ipsec_esp_in_udp_00), "draft-huttunen-ipsec-esp-in-udp-00.txt" },
  { VID_draft_huttunen_ipsec_esp_in_udp_01, sizeof(VID_draft_huttunen_ipsec_esp_in_udp_01), "draft-huttunen-ipsec-esp-in-udp-01.txt (ESPThruNAT)" },
  { VID_draft_stenberg_ipsec_nat_traversal_01, sizeof(VID_draft_stenberg_ipsec_nat_traversal_01), "draft-stenberg-ipsec-nat-traversal-01" },
  { VID_draft_stenberg_ipsec_nat_traversal_02, sizeof(VID_draft_stenberg_ipsec_nat_traversal_02), "draft-stenberg-ipsec-nat-traversal-02" },
  { VID_draft_ietf_ipsec_nat_t_ike, sizeof(VID_draft_ietf_ipsec_nat_t_ike), "draft-ietf-ipsec-nat-t-ike" },
  { VID_draft_ietf_ipsec_nat_t_ike_00, sizeof(VID_draft_ietf_ipsec_nat_t_ike_00), "draft-ietf-ipsec-nat-t-ike-00" },
  { VID_draft_ietf_ipsec_nat_t_ike_01, sizeof(VID_draft_ietf_ipsec_nat_t_ike_01), "draft-ietf-ipsec-nat-t-ike-01" },
  { VID_draft_ietf_ipsec_nat_t_ike_02, sizeof(VID_draft_ietf_ipsec_nat_t_ike_02), "draft-ietf-ipsec-nat-t-ike-02" },
  { VID_draft_ietf_ipsec_nat_t_ike_02n, sizeof(VID_draft_ietf_ipsec_nat_t_ike_02n), "draft-ietf-ipsec-nat-t-ike-02\\n" },
  { VID_draft_ietf_ipsec_nat_t_ike_03, sizeof(VID_draft_ietf_ipsec_nat_t_ike_03), "draft-ietf-ipsec-nat-t-ike-03" },
  { VID_draft_ietf_ipsec_nat_t_ike_04, sizeof(VID_draft_ietf_ipsec_nat_t_ike_04), "draft-ietf-ipsec-nat-t-ike-04" },
  { VID_draft_ietf_ipsec_nat_t_ike_05, sizeof(VID_draft_ietf_ipsec_nat_t_ike_05), "draft-ietf-ipsec-nat-t-ike-05" },
  { VID_draft_ietf_ipsec_nat_t_ike_06, sizeof(VID_draft_ietf_ipsec_nat_t_ike_06), "draft-ietf-ipsec-nat-t-ike-06" },
  { VID_draft_ietf_ipsec_nat_t_ike_07, sizeof(VID_draft_ietf_ipsec_nat_t_ike_07), "draft-ietf-ipsec-nat-t-ike-07" },
  { VID_draft_ietf_ipsec_nat_t_ike_08, sizeof(VID_draft_ietf_ipsec_nat_t_ike_08), "draft-ietf-ipsec-nat-t-ike-08" },
  { VID_draft_ietf_ipsec_nat_t_ike_09, sizeof(VID_draft_ietf_ipsec_nat_t_ike_09), "draft-ietf-ipsec-nat-t-ike-09" },
  { VID_testing_nat_t_rfc, sizeof(VID_testing_nat_t_rfc), "Testing NAT-T RFC" },
  { VID_rfc3947_nat_t, sizeof(VID_rfc3947_nat_t), "RFC 3947 Negotiation of NAT-Traversal in the IKE" },
  { VID_draft_beaulieu_ike_xauth_02, sizeof(VID_draft_beaulieu_ike_xauth_02), "draft-beaulieu-ike-xauth-02.txt" },
  { VID_xauth, sizeof(VID_xauth), "XAUTH" },
  { VID_rfc3706_dpd, sizeof(VID_rfc3706_dpd), "RFC 3706 DPD (Dead Peer Detection)" },
  { VID_draft_ietf_ipsec_antireplay_00, sizeof(VID_draft_ietf_ipsec_antireplay_00), "draft-ietf-ipsec-antireplay-00.txt" },
  { VID_draft_ietf_ipsec_heartbeats_00, sizeof(VID_draft_ietf_ipsec_heartbeats_00), "draft-ietf-ipsec-heartbeats-00.txt" },
  { VID_IKE_CHALLENGE_RESPONSE_1, sizeof(VID_IKE_CHALLENGE_RESPONSE_1), "IKE Challenge/Response for Authenticated Cryptographic Keys" },
  { VID_IKE_CHALLENGE_RESPONSE_2, sizeof(VID_IKE_CHALLENGE_RESPONSE_2), "IKE Challenge/Response for Authenticated Cryptographic Keys" },
  { VID_IKE_CHALLENGE_RESPONSE_REV_1, sizeof(VID_IKE_CHALLENGE_RESPONSE_REV_1), "IKE Challenge/Response for Authenticated Cryptographic Keys (Revised)" },
  { VID_IKE_CHALLENGE_RESPONSE_REV_2, sizeof(VID_IKE_CHALLENGE_RESPONSE_REV_2), "IKE Challenge/Response for Authenticated Cryptographic Keys (Revised)" },
  { VID_CISCO_FRAG2, sizeof(VID_CISCO_FRAG2), "Cisco Fragmentation" },
  { VID_CISCO_FLEXVPN_SUPPORTED, sizeof(VID_CISCO_FLEXVPN_SUPPORTED), "Cisco FlexVPN Supported" },
  { VID_CISCO_DELETE_REASON, sizeof(VID_CISCO_DELETE_REASON), "Cisco Delete Reason Supported"},
  { VID_CISCO_DYNAMIC_ROUTE, sizeof(VID_CISCO_DYNAMIC_ROUTE), "Cisco Dynamic Route Supported"},
  { VID_CISCO_VPN_REV_02, sizeof(VID_CISCO_VPN_REV_02), "Cisco VPN Revision 2"},
  { VID_CISCO_COPYRIGHT, sizeof(VID_CISCO_COPYRIGHT), "Cisco Copyright"},
  { VID_CISCO_GRE_MODE, sizeof(VID_CISCO_GRE_MODE), "Cisco GRE Mode Supported"},
  { VID_MS_VID_INITIAL_CONTACT, sizeof(VID_MS_VID_INITIAL_CONTACT), "Microsoft Vid-Initial-Contact" },
  { VID_GSS_API_1, sizeof(VID_GSS_API_1), "A GSS-API Authentication Method for IKE" },
  { VID_GSS_API_2, sizeof(VID_GSS_API_2), "A GSS-API Authentication Method for IKE" },
  { VID_GSSAPI, sizeof(VID_GSSAPI), "GSSAPI" },
  { VID_MS_NT5_ISAKMPOAKLEY, sizeof(VID_MS_NT5_ISAKMPOAKLEY), "MS NT5 ISAKMPOAKLEY" },
  { VID_CISCO_UNITY, sizeof(VID_CISCO_UNITY), "CISCO-UNITY" },
  { VID_CISCO_CONCENTRATOR, sizeof(VID_CISCO_CONCENTRATOR), "CISCO-CONCENTRATOR" },
  { VID_CISCO_FRAG, sizeof(VID_CISCO_FRAG), "Cisco Fragmentation" },
  { VID_CP_01_R65, sizeof(VID_CP_01_R65), "CryptoPro/GOST 0.1 / Check Point R65" },
  { VID_CP_10_R71, sizeof(VID_CP_10_R71), "CryptoPro/GOST 1.0 / Check Point R71" },
  { VID_CP_11, sizeof(VID_CP_11), "CryptoPro/GOST 1.1" },
  { VID_CYBERGUARD, sizeof(VID_CYBERGUARD), "CyberGuard" },
  { VID_SHREWSOFT, sizeof(VID_SHREWSOFT), "Shrew Soft" },
  { VID_STRONGSWAN, sizeof(VID_STRONGSWAN), "strongSwan" },
  { VID_KAME_RACOON, sizeof(VID_KAME_RACOON), "KAME/racoon" },
  { VID_IPSEC_TOOLS, sizeof(VID_IPSEC_TOOLS), "IPSec-Tools" },
  { VID_NETSCREEN_1, sizeof(VID_NETSCREEN_1), "Netscreen-1" },
  { VID_NETSCREEN_2, sizeof(VID_NETSCREEN_2), "Netscreen-2" },
  { VID_NETSCREEN_3, sizeof(VID_NETSCREEN_3), "Netscreen-3" },
  { VID_NETSCREEN_4, sizeof(VID_NETSCREEN_4), "Netscreen-4" },
  { VID_NETSCREEN_5, sizeof(VID_NETSCREEN_5), "Netscreen-5" },
  { VID_NETSCREEN_6, sizeof(VID_NETSCREEN_6), "Netscreen-6" },
  { VID_NETSCREEN_7, sizeof(VID_NETSCREEN_7), "Netscreen-7" },
  { VID_NETSCREEN_8, sizeof(VID_NETSCREEN_8), "Netscreen-8" },
  { VID_NETSCREEN_9, sizeof(VID_NETSCREEN_9), "Netscreen-9" },
  { VID_NETSCREEN_10, sizeof(VID_NETSCREEN_10), "Netscreen-10" },
  { VID_NETSCREEN_11, sizeof(VID_NETSCREEN_11), "Netscreen-11" },
  { VID_NETSCREEN_12, sizeof(VID_NETSCREEN_12), "Netscreen-12" },
  { VID_NETSCREEN_13, sizeof(VID_NETSCREEN_13), "Netscreen-13" },
  { VID_NETSCREEN_14, sizeof(VID_NETSCREEN_14), "Netscreen-14" },
  { VID_NETSCREEN_15, sizeof(VID_NETSCREEN_15), "Netscreen-15" },
  { VID_NETSCREEN_16, sizeof(VID_NETSCREEN_16), "Netscreen-16" },
  { VID_ZYWALL, sizeof(VID_ZYWALL), "ZYWALL" },
  { VID_SIDEWINDER, sizeof(VID_SIDEWINDER), "SIDEWINDER" },
  { VID_SONICWALL, sizeof(VID_SONICWALL), "SonicWALL" },
  { VID_HEARTBEAT_NOTIFY, sizeof(VID_HEARTBEAT_NOTIFY), "Heartbeat Notify" },
  { VID_DWR, sizeof(VID_DWR), "DWR: Delete with reason" },
  { VID_ARUBA_RAP, sizeof(VID_ARUBA_RAP), "Remote AP (Aruba Networks)" },
  { VID_ARUBA_CONTROLLER, sizeof(VID_ARUBA_CONTROLLER), "Controller (Aruba Networks)" },
  { VID_ARUBA_VIA_CLIENT, sizeof(VID_ARUBA_VIA_CLIENT), "VIA Client (Aruba Networks)" },
  { VID_ARUBA_VIA_AUTH_PROFILE, sizeof(VID_ARUBA_VIA_AUTH_PROFILE), "VIA Auth Profile (Aruba Networks)" },
  { VID_MS_IKEE_20080212_CGA1, sizeof(VID_MS_IKEE_20080212_CGA1), "IKE CGA Version 1" },
  { VID_MS_IKEE_20080212_MS_NDC, sizeof(VID_MS_IKEE_20080212_MS_NDC), "MS-Negotiation Discovery Capable" },
  { VID_FORTINET_FORTIGATE, sizeof(VID_FORTINET_FORTIGATE), "Fortigate (Fortinet)" },
  { VID_FORTINET_FORTICLIENT_CONNECT, sizeof(VID_FORTINET_FORTICLIENT_CONNECT), "Forticlient connect license (Fortinet)" },
  { VID_FORTINET_ENDPOINT_CONTROL, sizeof(VID_FORTINET_ENDPOINT_CONTROL), "Endpoint Control (Fortinet)" },
  { 0, 0, NULL }
};



static void
dissect_payloads(tvbuff_t *tvb, proto_tree *tree,
                int isakmp_version, guint8 initial_payload, int offset, int length,
                packet_info *pinfo, guint32 message_id, gboolean is_request, void* decr_data)
{
  guint8         payload, next_payload;
  guint16        payload_length;
  proto_tree *   ntree;

  for (payload = initial_payload; length > 0; payload = next_payload) {
    if (payload == PLOAD_IKE_NONE) {
      /*
       * What?  There's more stuff in this chunk of data, but the
       * previous payload had a "next payload" type of None?
       */
      proto_tree_add_item(tree, hf_isakmp_extradata, tvb, offset, length, ENC_NA);
      break;
    }

    ntree = dissect_payload_header(tvb, pinfo, offset, length, isakmp_version, payload, &next_payload, &payload_length, tree);
    if (payload_length >= 4) {  /* XXX = > 4? */
      tvb_ensure_bytes_exist(tvb, offset + 4, payload_length - 4);
        switch(payload){
          case PLOAD_IKE_SA:
          case PLOAD_IKE2_SA:
            dissect_sa(tvb, offset + 4, payload_length - 4, ntree, isakmp_version, pinfo, is_request, decr_data);
            break;
          case PLOAD_IKE_P:
            dissect_proposal(tvb, pinfo, offset + 4, payload_length - 4, ntree, isakmp_version, decr_data );
            break;
          case PLOAD_IKE_KE:
          case PLOAD_IKE2_KE:
            dissect_key_exch(tvb, offset + 4, payload_length - 4, ntree, isakmp_version, pinfo, decr_data );
            break;
          case PLOAD_IKE_ID:
          case PLOAD_IKE2_IDI:
          case PLOAD_IKE2_IDR:
            dissect_id(tvb, offset + 4, payload_length - 4, ntree, isakmp_version, pinfo );
            break;
          case PLOAD_IKE_CERT:
          case PLOAD_IKE2_CERT:
            dissect_cert(tvb, offset + 4, payload_length - 4, ntree, isakmp_version, pinfo );
            break;
          case PLOAD_IKE_CR:
          case PLOAD_IKE2_CERTREQ:
            dissect_certreq(tvb, offset + 4, payload_length - 4, ntree, isakmp_version, pinfo );
            break;
          case PLOAD_IKE_HASH:
            dissect_hash(tvb, offset + 4, payload_length - 4, ntree);
            break;
          case PLOAD_IKE_SIG:
            dissect_sig(tvb, offset + 4, payload_length - 4, ntree);
            break;
          case PLOAD_IKE_NONCE:
          case PLOAD_IKE2_NONCE:
            dissect_nonce(tvb, offset + 4, payload_length - 4, ntree);
            break;
          case PLOAD_IKE_N:
          case PLOAD_IKE2_N:
            dissect_notif(tvb, pinfo, offset + 4, payload_length - 4, ntree, isakmp_version);
            break;
          case PLOAD_IKE_D:
          case PLOAD_IKE2_D:
            dissect_delete(tvb, offset + 4, payload_length - 4, ntree, isakmp_version);
            break;
          case PLOAD_IKE_VID:
          case PLOAD_IKE2_V:
            dissect_vid(tvb, offset + 4, payload_length - 4, ntree);
            break;
          case PLOAD_IKE_A:
          case PLOAD_IKE2_CP:
            dissect_config(tvb, pinfo, offset + 4, payload_length - 4, ntree, isakmp_version, is_request);
            break;
          case PLOAD_IKE_SAK:
            dissect_sa_kek(tvb, pinfo, offset + 4, payload_length - 4, ntree);
            break;
          case PLOAD_IKE_SAT:
            dissect_sa_tek(tvb, pinfo, offset + 4, payload_length - 4, ntree);
            break;
          case PLOAD_IKE_KD:
            dissect_key_download(tvb, pinfo, offset + 4, payload_length - 4, ntree, isakmp_version);
            break;
          case PLOAD_IKE_SEQ:
            dissect_sequence(tvb, pinfo, offset + 4, payload_length - 4, ntree);
            break;
          case PLOAD_IKE2_AUTH:
            dissect_auth(tvb, pinfo, offset + 4, payload_length - 4, ntree);
            break;
          case PLOAD_IKE2_TSI:
          case PLOAD_IKE2_TSR:
            dissect_ts_payload(tvb, offset + 4, payload_length - 4, ntree);
            break;
          case PLOAD_IKE2_SK:
            if(isakmp_version == 2)
              dissect_enc(tvb, offset + 4, payload_length - 4, ntree, pinfo, next_payload, is_request, decr_data, TRUE);
            break;
          case PLOAD_IKE2_EAP:
            dissect_eap(tvb, offset + 4, payload_length - 4, ntree, pinfo );
            break;
          case PLOAD_IKE2_GSPM:
            dissect_gspm(tvb, offset + 4, payload_length - 4, ntree);
            break;
          case PLOAD_IKE_NAT_D:
          case PLOAD_IKE_NAT_D13:
            dissect_nat_discovery(tvb, offset + 4, payload_length - 4, ntree );
            break;
          case PLOAD_IKE_NAT_OA:
          case PLOAD_IKE_NAT_OA14:
            dissect_nat_original_address(tvb, offset + 4, payload_length - 4, ntree, isakmp_version );
            break;
          case PLOAD_IKE_CISCO_FRAG:
            dissect_cisco_fragmentation(tvb, offset + 4, payload_length - 4, ntree, pinfo );
            break;
          case PLOAD_IKE2_SKF:
            if (isakmp_version == 2) {
              /* N.B. not passing in length as must be the last payload in the message */
              dissect_ikev2_fragmentation(tvb, offset + 4, ntree, pinfo, message_id, next_payload, is_request, decr_data );
            }
            break;
          default:
            proto_tree_add_item(ntree, hf_isakmp_datapayload, tvb, offset + 4, payload_length-4, ENC_NA);
            break;
        }
    }
    else if (payload_length > length) {
      proto_tree_add_expert_format(ntree, pinfo, &ei_isakmp_payload_bad_length, tvb, 0, 0,
                                   "Payload (bogus, length is %u, greater than remaining length %d",
                                   payload_length, length);
      return;
    }
    else {
      proto_tree_add_expert_format(ntree, pinfo, &ei_isakmp_payload_bad_length, tvb, 0, 0,
                                   "Payload (bogus, length is %u, must be at least 4)",
                                   payload_length);
      payload_length = 4;
    }

    offset += payload_length;
    length -= payload_length;
  }
}

void
isakmp_dissect_payloads(tvbuff_t *tvb, proto_tree *tree, int isakmp_version,
                        guint8 initial_payload, int offset, int length,
                        packet_info *pinfo)
{
  dissect_payloads(tvb, tree, isakmp_version, initial_payload, offset, length,
                   pinfo, 0, FALSE, NULL);
}

static int
dissect_isakmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int             offset      = 0, len;
  isakmp_hdr_t    hdr;
  proto_item     *ti, *vers_item, *ti_root;
  proto_tree     *isakmp_tree = NULL, *vers_tree;
  int             isakmp_version;
  void*           decr_data   = NULL;
  guint8          flags;
  guint8          i_cookie[COOKIE_SIZE], *ic_key;
  decrypt_data_t *decr        = NULL;
  tvbuff_t       *decr_tvb;
  proto_tree     *decr_tree;
  address         null_addr;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISAKMP");
  col_clear(pinfo->cinfo, COL_INFO);

  /* Some simple heuristics to catch non-isakmp packets */
  if (tvb_reported_length(tvb)== 1 && tvb_get_guint8(tvb, offset) !=0xff)
    return 0;
  else if (tvb_reported_length(tvb) < ISAKMP_HDR_SIZE)
    return 0;
  else if (tvb_get_ntohl(tvb, ISAKMP_HDR_SIZE-4) < ISAKMP_HDR_SIZE)
    return 0;

  ti_root = proto_tree_add_item(tree, proto_isakmp, tvb, offset, -1, ENC_NA);
  isakmp_tree = proto_item_add_subtree(ti_root, ett_isakmp);

  /* RFC3948 2.3 NAT Keepalive packet:
   * 1 byte payload with the value 0xff.
   */
  if ( (tvb_reported_length(tvb)== 1) && (tvb_get_guint8(tvb, offset) == 0xff) ){
    col_set_str(pinfo->cinfo, COL_INFO, "NAT Keepalive");
    proto_tree_add_item(isakmp_tree, hf_isakmp_nat_keepalive, tvb, offset, 1, ENC_NA);
    return 1;
  }

  hdr.length = tvb_get_ntohl(tvb, offset + ISAKMP_HDR_SIZE - 4);
  hdr.exch_type = tvb_get_guint8(tvb, COOKIE_SIZE + COOKIE_SIZE + 1 + 1);
  hdr.version = tvb_get_guint8(tvb, COOKIE_SIZE + COOKIE_SIZE + 1);
  isakmp_version = hi_nibble(hdr.version);      /* save the version */
  hdr.flags = tvb_get_guint8(tvb, COOKIE_SIZE + COOKIE_SIZE + 1 + 1 + 1);

  if (isakmp_version == 1) {
    clear_address(&null_addr);

    tvb_memcpy(tvb, i_cookie, offset, COOKIE_SIZE);
    decr = (decrypt_data_t*) g_hash_table_lookup(isakmp_hash, i_cookie);

    if (! decr) {
      ic_key = (guint8 *)g_slice_alloc(COOKIE_SIZE);
      memcpy(ic_key, i_cookie, COOKIE_SIZE);
      decr = create_decrypt_data();
      g_hash_table_insert(isakmp_hash, ic_key, decr);
    }

    if (addresses_equal(&decr->initiator, &null_addr)) {
      /* XXX - We assume that we're seeing the second packet in an exchange here.
       * Is there a way to verify this? */
      copy_address_wmem(wmem_file_scope(), &decr->initiator, &pinfo->src);
    }

    decr_data = decr;
  } else if (isakmp_version == 2) {
    ikev2_uat_data_key_t hash_key;
    ikev2_uat_data_t *ike_sa_data;
    ikev2_decrypt_data_t *ikev2_dec_data;
    guchar spii[COOKIE_SIZE], spir[COOKIE_SIZE];

    tvb_memcpy(tvb, spii, offset, COOKIE_SIZE);
    tvb_memcpy(tvb, spir, offset + COOKIE_SIZE, COOKIE_SIZE);
    hash_key.spii = spii;
    hash_key.spir = spir;
    hash_key.spii_len = COOKIE_SIZE;
    hash_key.spir_len = COOKIE_SIZE;

    ike_sa_data = (ikev2_uat_data_t *)g_hash_table_lookup(ikev2_key_hash, &hash_key);
    if (ike_sa_data) {
      guint8 initiator_flag;
      initiator_flag = hdr.flags & I_FLAG;
      ikev2_dec_data = wmem_new(pinfo->pool, ikev2_decrypt_data_t);
      ikev2_dec_data->encr_key = initiator_flag ? ike_sa_data->sk_ei : ike_sa_data->sk_er;
      ikev2_dec_data->auth_key = initiator_flag ? ike_sa_data->sk_ai : ike_sa_data->sk_ar;
      ikev2_dec_data->encr_spec = ike_sa_data->encr_spec;
      ikev2_dec_data->auth_spec = ike_sa_data->auth_spec;

      decr_data = ikev2_dec_data;
    }
  }

  {
    proto_tree_add_item(isakmp_tree, hf_isakmp_ispi, tvb, offset, COOKIE_SIZE, ENC_NA);
    offset += COOKIE_SIZE;

    proto_tree_add_item(isakmp_tree, hf_isakmp_rspi, tvb, offset, COOKIE_SIZE, ENC_NA);
    offset += COOKIE_SIZE;

    hdr.next_payload = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(isakmp_tree,  hf_isakmp_nextpayload, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;

    vers_item = proto_tree_add_uint_format_value(isakmp_tree, hf_isakmp_version, tvb, offset,
                                           1, hdr.version, "%u.%u",
                                           hi_nibble(hdr.version), lo_nibble(hdr.version));
    vers_tree = proto_item_add_subtree(vers_item, ett_isakmp_version);
    proto_tree_add_item(vers_tree, hf_isakmp_mjver, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(vers_tree, hf_isakmp_mnver, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if(isakmp_version == 1) {
        proto_tree_add_item(isakmp_tree,  hf_isakmp_exchangetype_v1, tvb, offset, 1, ENC_BIG_ENDIAN);
        col_add_str(pinfo->cinfo, COL_INFO,val_to_str(hdr.exch_type, exchange_v1_type, "Unknown %d"));
    } else if (isakmp_version == 2){
        proto_tree_add_item(isakmp_tree,  hf_isakmp_exchangetype_v2, tvb, offset, 1, ENC_BIG_ENDIAN);
        col_add_str(pinfo->cinfo, COL_INFO,val_to_str(hdr.exch_type, exchange_v2_type, "Unknown %d"));
    }
    offset += 1;

    {
      proto_item *      fti;
      proto_tree *      ftree;

      fti   = proto_tree_add_item(isakmp_tree, hf_isakmp_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
      ftree = proto_item_add_subtree(fti, ett_isakmp_flags);
      flags = tvb_get_guint8(tvb, offset);

      if (isakmp_version == 1) {
        proto_tree_add_item(ftree, hf_isakmp_flag_e, tvb, offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(ftree, hf_isakmp_flag_c, tvb, offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(ftree, hf_isakmp_flag_a, tvb, offset, 1, ENC_BIG_ENDIAN);

      } else if (isakmp_version == 2) {
        proto_tree_add_item(ftree, hf_isakmp_flag_i, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ftree, hf_isakmp_flag_v, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ftree, hf_isakmp_flag_r, tvb, offset, 1, ENC_BIG_ENDIAN);

        proto_item_append_text(fti, " (%s, %s, %s)",
                               tfs_get_string(flags & I_FLAG, &flag_i),
                               tfs_get_string(flags & V_FLAG, &flag_v),
                               tfs_get_string(flags & R_FLAG, &tfs_response_request));
      }
      offset += 1;
    }

    hdr.message_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(isakmp_tree, hf_isakmp_messageid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Add some summary to the Info column */
    if (isakmp_version == 2) {
      col_append_fstr(pinfo->cinfo, COL_INFO, " MID=%02u %s %s",
                      hdr.message_id,
                      tfs_get_string(flags & I_FLAG, &flag_i),
                      tfs_get_string(flags & R_FLAG, &tfs_response_request));
    }

    if (hdr.length < ISAKMP_HDR_SIZE) {
      proto_tree_add_uint_format_value(isakmp_tree, hf_isakmp_length, tvb, offset, 4,
                                 hdr.length, "(bogus, length is %u, should be at least %lu)",
                                 hdr.length, (unsigned long)ISAKMP_HDR_SIZE);
      return tvb_captured_length(tvb);
    }

    len = hdr.length - ISAKMP_HDR_SIZE;

    if (len < 0) {
      proto_tree_add_uint_format_value(isakmp_tree, hf_isakmp_length, tvb, offset, 4,
                                 hdr.length, "(bogus, length is %u, which is too large)",
                                 hdr.length);
      return tvb_captured_length(tvb);
    }
    tvb_ensure_bytes_exist(tvb, offset, len);
    proto_tree_add_item(isakmp_tree, hf_isakmp_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (isakmp_version == 1 && (hdr.flags & E_FLAG)) {
      /* Encrypted flag set (v1 only), so decrypt before dissecting payloads */
      if (len) {
        ti = proto_tree_add_item(isakmp_tree, hf_isakmp_enc_data, tvb, offset, len, ENC_NA);
        proto_item_append_text(ti, " (%d byte%s)", len, plurality(len, "", "s"));

        /* Collect initialization vectors during first pass. */
        if (!PINFO_FD_VISITED(pinfo))
          if (prepare_decrypt(decr))
            update_ivs(pinfo, tvb_get_ptr(tvb, offset, len), len, hdr.message_id, decr);
        decr_tvb = decrypt_payload(tvb, pinfo, tvb_get_ptr(tvb, offset, len), len, decr);
        if (decr_tvb) {
          decr_tree = proto_item_add_subtree(ti, ett_isakmp);
          dissect_payloads(decr_tvb, decr_tree, isakmp_version,
                           hdr.next_payload, 0, tvb_reported_length(decr_tvb), pinfo, hdr.message_id, !(flags & R_FLAG), decr_data);
        }
      }
    } else {
      dissect_payloads(tvb, isakmp_tree, isakmp_version, hdr.next_payload,
                       offset, len, pinfo, hdr.message_id, !(flags & R_FLAG), decr_data);
    }

    offset += len;
  }

  proto_item_set_end(ti_root, tvb, offset);

  return offset;
}


static proto_tree *
dissect_payload_header(tvbuff_t *tvb, packet_info *pinfo, int offset, int length,
    int isakmp_version, guint8 payload, guint8 *next_payload_p,
    guint16 *payload_length_p, proto_tree *tree)
{
  guint8                next_payload;
  guint16               payload_length;
  proto_item *          ti;
  proto_tree *          ntree;

  if (length < 4) {
    proto_tree_add_expert_format(tree, pinfo, &ei_isakmp_payload_bad_length, tvb, offset, length,
                        "Not enough room in payload for all transforms");
    *next_payload_p = 0;
    *payload_length_p = 0;
    return NULL;
  }
  next_payload = tvb_get_guint8(tvb, offset);
  payload_length = tvb_get_ntohs(tvb, offset + 2);

  ti = proto_tree_add_uint(tree, hf_isakmp_typepayload, tvb, offset, payload_length, payload);

  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);

  proto_tree_add_item(ntree, hf_isakmp_nextpayload, tvb, offset, 1, ENC_BIG_ENDIAN);

  /* The critical flag only applies to IKEv2 payloads but not proposals and transforms. */
  if (isakmp_version == 1 || payload == PLOAD_IKE_P || payload == PLOAD_IKE_T) {
    proto_tree_add_item(ntree, hf_isakmp_reserved, tvb, offset + 1, 1, ENC_NA);
  } else if (isakmp_version == 2) {
    proto_tree_add_item(ntree, hf_isakmp_criticalpayload, tvb, offset+1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ntree, hf_isakmp_reserved7, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
  }
  proto_tree_add_item(ntree, hf_isakmp_payloadlen, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

  *next_payload_p = next_payload;
  *payload_length_p = payload_length;
  return ntree;
}

static void
dissect_sa(tvbuff_t *tvb, int offset, int length, proto_tree *tree, int isakmp_version, packet_info *pinfo, gboolean is_request, void* decr_data)
{
  guint32       doi;
  guint16       saattr;
  proto_item    *sti;
  proto_tree    *stree;
  proto_tree    *currtree;

  /* make a copy of current tree working position which we will use while dissecting other payloads*/
  currtree = tree;
  if (isakmp_version == 1) {
    doi = tvb_get_ntohl(tvb, offset);

    proto_tree_add_item(tree, hf_isakmp_sa_doi, tvb, offset, 4, ENC_BIG_ENDIAN);

    offset += 4;
    length -= 4;

    switch(doi) {
      case 1: {
        /* IPSEC */
        if (length < 4) {
          proto_tree_add_bytes_format_value(tree, hf_isakmp_sa_situation, tvb, offset, length,
                                      NULL,
                                      "%s (length is %u, should be >= 4)",
                                      tvb_bytes_to_str(pinfo->pool, tvb, offset, length), length);
          return;
        }
        sti = proto_tree_add_item(tree, hf_isakmp_sa_situation, tvb, offset, 4, ENC_NA);
        stree = proto_item_add_subtree(sti, ett_isakmp_sa);

        proto_tree_add_item(stree, hf_isakmp_sa_situation_identity_only, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(stree, hf_isakmp_sa_situation_secrecy, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(stree, hf_isakmp_sa_situation_integrity, tvb, offset, 4, ENC_BIG_ENDIAN);

        offset += 4;
        length -= 4;

        dissect_payloads(tvb, tree, isakmp_version, PLOAD_IKE_P, offset,
                         length, pinfo, 0, is_request, decr_data);
        break;
      }
      case 2: {
        /* add GDOI specific changes here for RFC 6407*/
        if (length < 8) {     /* situation + next payload + reserved2*/
          proto_tree_add_bytes_format_value(tree, hf_isakmp_sa_situation, tvb, offset, length,
                                      NULL,
                                      "%s (length is %u, should be >= 8)",
                                      tvb_bytes_to_str(pinfo->pool, tvb, offset, length), length);
          return;
        }
        proto_tree_add_item(tree, hf_isakmp_sa_situation, tvb, offset, 4, ENC_NA);    /* must be always 0 as per RFC 6407 no further decoding required*/
        saattr = tvb_get_ntohs(tvb, offset+4);
        proto_tree_add_item(tree, hf_isakmp_sa_attribute_next_payload, tvb, offset+4, 2, ENC_NA);
        proto_tree_add_item(tree, hf_isakmp_reserved2 , tvb, offset+6, 2, ENC_NA);

        offset += 8;
        length -= 8;

        /* possible attribute values here 15(SAK),16(SAT),18(GAP)*/
        switch(saattr) {
        case PLOAD_IKE_SAK:
           dissect_sa_kek(tvb, pinfo, offset, length, currtree );
           break;
        case PLOAD_IKE_SAT:
           dissect_sa_tek(tvb, pinfo, offset, length, currtree);
           break;
        }
        break;
      }
      default:
        proto_tree_add_item(tree, hf_isakmp_sa_situation, tvb, offset, length, ENC_NA);
        break;
    }
  } else if (isakmp_version == 2) {
    dissect_payloads(tvb, tree, isakmp_version, PLOAD_IKE_P, offset,
                     length, pinfo, 0, is_request, decr_data);
  }
}

static void
dissect_proposal(tvbuff_t *tvb, packet_info *pinfo, int offset, int length, proto_tree *tree, int isakmp_version, void* decr_data)
{
  guint8                protocol_id;
  guint8                spi_size;
  guint8                num_transforms;
  guint8                next_payload;
  guint16               payload_length;
  proto_tree *          ntree;
  guint8                proposal_num;

  proposal_num = tvb_get_guint8(tvb, offset);

  proto_item_append_text(tree, " # %d", proposal_num);

  proto_tree_add_item(tree, hf_isakmp_prop_number, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  length -= 1;

  protocol_id = tvb_get_guint8(tvb, offset);

  if (isakmp_version == 1)
  {
     proto_tree_add_item(tree, hf_isakmp_prop_protoid_v1, tvb, offset, 1, ENC_BIG_ENDIAN);
  }else if (isakmp_version == 2)
  {
     proto_tree_add_item(tree, hf_isakmp_prop_protoid_v2, tvb, offset, 1, ENC_BIG_ENDIAN);
  }
  offset += 1;
  length -= 1;

  spi_size = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_isakmp_spisize, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  length -= 1;

  num_transforms = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_isakmp_prop_transforms, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  length -= 1;

  if (spi_size) {
    proto_tree_add_item(tree, hf_isakmp_spi, tvb, offset, spi_size, ENC_NA);

    offset += spi_size;
    length -= spi_size;
  }

  while (num_transforms > 0) {
    ntree = dissect_payload_header(tvb, pinfo, offset, length, isakmp_version,
                                   PLOAD_IKE_T, &next_payload, &payload_length, tree);
    if (length < payload_length) {
      proto_tree_add_expert_format(tree, pinfo, &ei_isakmp_payload_bad_length, tvb, offset + 4, length,
                           "Payload (bogus, length is %u, greater than remaining length %d", payload_length, length);
      break;
    } else if (payload_length < 4) {
      proto_tree_add_expert_format(tree, pinfo, &ei_isakmp_payload_bad_length, tvb, offset + 4, length,
                           "Payload (bogus, length is %u, must be at least 4)", payload_length);
      break;
    }
    dissect_transform(tvb, pinfo, offset + 4, payload_length - 4, ntree, isakmp_version, protocol_id, decr_data);

    offset += payload_length;
    length -= payload_length;
    num_transforms--;

  }
}

/** Dissect an attribute header, which is common to all attributes.
 *
 * @param [in]  tvb             The tv buffer of the current data.
 * @param [in]  tree            The tree to append the attribute subtree to.
 * @param [in]  offset          The start of the data in tvb.
 * @param [in]  hf_attr         A struct of indices pointing to attribute header field descriptions.
 * @param [in]  attr_typenames  The table for translation of the attribute type id to a name.
 * @param [out] headerlen       The length of the attribute header, excluding the value.
 * @param [out] value_len       The length of the attribute value.
 * @param [out] attr_type       The attribute type, as read from the attribute header.
 * @param [out] attr_item       The root item created for this attribute.
 * @param [out] subtree         The subtree created for this attribute.
 */
static void
dissect_attribute_header(tvbuff_t *tvb, proto_tree *tree, int offset,
                         attribute_common_fields hf_attr, const range_string *attr_typenames,
                         guint *headerlen, guint *value_len, guint *attr_type,
                         proto_item **attr_item, proto_tree **subtree)
{
  guint attr_type_format;
  gboolean has_len;
  const gchar *attr_typename;

  attr_type_format = tvb_get_ntohs(tvb, offset);
  has_len = !(attr_type_format & 0x8000);
  *attr_type = attr_type_format & 0x7fff;

  if (has_len) {
    /* Type/Length/Value format */
    *headerlen = 4;
    *value_len = tvb_get_ntohs(tvb, offset + 2);
  } else {
    /* Type/Value format */
    *headerlen = 2;
    *value_len = 2;
  }

  *attr_item = proto_tree_add_item(tree, hf_attr.all, tvb, offset, *headerlen + *value_len, ENC_NA);
  attr_typename = rval_to_str(*attr_type, attr_typenames, "Unknown Attribute Type (%02d)");
  proto_item_append_text(*attr_item, " (t=%d,l=%d): %s", *attr_type, *value_len, attr_typename);

  *subtree = proto_item_add_subtree(*attr_item, ett_isakmp_attr);
  proto_tree_add_item(*subtree, hf_attr.format, tvb, offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_uint(*subtree, hf_attr.type, tvb, offset, 2, *attr_type);

  if (has_len)
    proto_tree_add_item(*subtree, hf_attr.length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

  if (*value_len > 0)
    proto_tree_add_item(*subtree, hf_attr.value, tvb, offset + *headerlen, *value_len, ENC_NA);
}

/* Returns the number of bytes consumed by this attribute. */
static int
dissect_rohc_attribute(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  guint headerlen, value_len, attr_type;
  proto_item *attr_item;
  proto_tree *attr_tree;

  dissect_attribute_header(tvb, tree, offset,
                           hf_isakmp_notify_data_rohc_attr, rohc_attr_type,
                           &headerlen, &value_len, &attr_type,
                           &attr_item, &attr_tree);

  offset += headerlen;

  if (value_len == 0)
  {
    expert_add_info(pinfo, attr_item, &ei_isakmp_attribute_value_empty);
    return headerlen;
  }

  switch(attr_type) {
    case ROHC_MAX_CID:
      proto_tree_add_item(attr_tree, hf_isakmp_notify_data_rohc_attr_max_cid, tvb, offset, value_len, ENC_BIG_ENDIAN);
      break;
    case ROHC_PROFILE:
      proto_tree_add_item(attr_tree, hf_isakmp_notify_data_rohc_attr_profile, tvb, offset, value_len, ENC_BIG_ENDIAN);
      break;
    case ROHC_INTEG:
      proto_tree_add_item(attr_tree, hf_isakmp_notify_data_rohc_attr_integ, tvb, offset, value_len, ENC_BIG_ENDIAN);
      break;
    case ROHC_ICV_LEN:
      proto_tree_add_item(attr_tree, hf_isakmp_notify_data_rohc_attr_icv_len, tvb, offset, value_len, ENC_BIG_ENDIAN);
      break;
    case ROHC_MRRU:
      proto_tree_add_item(attr_tree, hf_isakmp_notify_data_rohc_attr_mrru, tvb, offset, value_len, ENC_BIG_ENDIAN);
      break;

    default:
      /* No Default Action */
      break;
  }

  return headerlen + value_len;
}

/* Dissect life duration, which is variable-length.  Note that this function
 * handles both/either the security association life duration as defined in
 * section 4.5 of RFC2407 (https://tools.ietf.org/html/rfc2407), as well as the
 * life duration according to the attribute classes table in Appendix A of
 * RFC2409: https://tools.ietf.org/html/rfc2409#page-33 */
static void
dissect_life_duration(tvbuff_t *tvb, proto_tree *tree, proto_item *ti, int hf_uint32, int hf_uint64, int hf_bytes, int offset, guint len)
{
  switch (len) {
    case 0:
      break;
    case 1: {
      guint8 val;
      val = tvb_get_guint8(tvb, offset);

      proto_tree_add_uint(tree, hf_uint32, tvb, offset, len, val);
      proto_item_append_text(ti, ": %u", val);
      break;
    }
    case 2: {
      guint16 val;
      val = tvb_get_ntohs(tvb, offset);

      proto_tree_add_uint(tree, hf_uint32, tvb, offset, len, val);
      proto_item_append_text(ti, ": %u", val);
      break;
    }
    case 3: {
      guint32 val;
      val = tvb_get_ntoh24(tvb, offset);

      proto_tree_add_uint(tree, hf_uint32, tvb, offset, len, val);
      proto_item_append_text(ti, ": %u", val);
      break;
    }
    case 4: {
      guint32 val;
      val = tvb_get_ntohl(tvb, offset);

      proto_tree_add_uint(tree, hf_uint32, tvb, offset, len, val);
      proto_item_append_text(ti, ": %u", val);
      break;
    }
    case 5: {
      guint64 val;
      val = tvb_get_ntoh40(tvb, offset);

      proto_tree_add_uint64_format_value(tree, hf_uint64, tvb, offset, len, val, "%" PRIu64, val);
      proto_item_append_text(ti, ": %" PRIu64, val);
      break;
    }
    case 6: {
        guint64 val;
        val = tvb_get_ntoh48(tvb, offset);

        proto_tree_add_uint64_format_value(tree, hf_uint64, tvb, offset, len, val, "%" PRIu64, val);
        proto_item_append_text(ti, ": %" PRIu64, val);
        break;
    }
    case 7: {
      guint64 val;
      val = tvb_get_ntoh56(tvb, offset);

      proto_tree_add_uint64_format_value(tree, hf_uint64, tvb, offset, len, val, "%" PRIu64, val);
      proto_item_append_text(ti, ": %" PRIu64, val);
      break;
    }
    case 8: {
      guint64 val;
      val = tvb_get_ntoh64(tvb, offset);

      proto_tree_add_uint64_format_value(tree, hf_uint64, tvb, offset, len, val, "%" PRIu64, val);
      proto_item_append_text(ti, ": %" PRIu64, val);
      break;
    }
    default:
      proto_tree_add_item(tree, hf_bytes, tvb, offset, len, ENC_NA);
      proto_item_append_text(ti, ": %" PRIx64 " ...", tvb_get_ntoh64(tvb, offset));
      break;
  }
}

/* Returns the number of bytes consumed by this attribute. */
static int
dissect_ipsec_attribute(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  guint headerlen, value_len, attr_type;
  proto_item *attr_item;
  proto_tree *attr_tree;

  dissect_attribute_header(tvb, tree, offset,
                           hf_isakmp_ipsec_attr, ipsec_attr_type,
                           &headerlen, &value_len, &attr_type,
                           &attr_item, &attr_tree);

  offset += headerlen;

  if (value_len == 0)
  {
    expert_add_info(pinfo, attr_item, &ei_isakmp_attribute_value_empty);
    return headerlen;
  }

  switch(attr_type) {
    case IPSEC_ATTR_LIFE_TYPE:
      proto_tree_add_item(attr_tree, hf_isakmp_ipsec_attr_life_type, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), attr_life_type, "Unknown %d"));
      break;
    case IPSEC_ATTR_LIFE_DURATION:
      dissect_life_duration(tvb, attr_tree, attr_item, hf_isakmp_ipsec_attr_life_duration_uint32, hf_isakmp_ipsec_attr_life_duration_uint64, hf_isakmp_ipsec_attr_life_duration_bytes, offset, value_len);
      break;
    case IPSEC_ATTR_GROUP_DESC:
      proto_tree_add_item(attr_tree, hf_isakmp_ipsec_attr_group_description, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), dh_group, "Unknown %d"));
      break;
    case IPSEC_ATTR_ENCAP_MODE:
      proto_tree_add_item(attr_tree, hf_isakmp_ipsec_attr_encap_mode, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), ipsec_attr_encap_mode, "Unknown %d"));
      break;
    case IPSEC_ATTR_AUTH_ALGORITHM:
      proto_tree_add_item(attr_tree, hf_isakmp_ipsec_attr_auth_algorithm, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), ipsec_attr_auth_algo, "Unknown %d"));
      break;
    case IPSEC_ATTR_KEY_LENGTH:
      proto_tree_add_item(attr_tree, hf_isakmp_ipsec_attr_key_length, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %d", tvb_get_ntohs(tvb, offset));
      break;
    case IPSEC_ATTR_KEY_ROUNDS:
      proto_tree_add_item(attr_tree, hf_isakmp_ipsec_attr_key_rounds, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %d", tvb_get_ntohs(tvb, offset));
      break;
    case IPSEC_ATTR_CMPR_DICT_SIZE:
      proto_tree_add_item(attr_tree, hf_isakmp_ipsec_attr_cmpr_dict_size, tvb, offset, value_len, ENC_BIG_ENDIAN);
      break;
    case IPSEC_ATTR_CMPR_ALGORITHM:
      proto_tree_add_item(attr_tree, hf_isakmp_ipsec_attr_cmpr_algorithm, tvb, offset, value_len, ENC_NA);
      break;
    case IPSEC_ATTR_ECN_TUNNEL:
      proto_tree_add_item(attr_tree, hf_isakmp_ipsec_attr_ecn_tunnel, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), ipsec_attr_ecn_tunnel, "Unknown %d"));
      break;
    case IPSEC_ATTR_EXT_SEQ_NBR:
      proto_tree_add_item(attr_tree, hf_isakmp_ipsec_attr_ext_seq_nbr, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), ipsec_attr_ext_seq_nbr, "Unknown %d"));
      break;
    case IPSEC_ATTR_AUTH_KEY_LENGTH:
      proto_tree_add_item(attr_tree, hf_isakmp_ipsec_attr_auth_key_length, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %d", tvb_get_ntohs(tvb, offset));
      break;
    case IPSEC_ATTR_SIG_ENCO_ALGORITHM:
      proto_tree_add_item(attr_tree, hf_isakmp_ipsec_attr_sig_enco_algorithm, tvb, offset, value_len, ENC_NA);
      break;

    case IPSEC_ATTR_ADDR_PRESERVATION:
      proto_tree_add_item(attr_tree, hf_isakmp_ipsec_attr_addr_preservation, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), ipsec_attr_addr_preservation, "Unknown %d"));
      break;

    case IPSEC_ATTR_SA_DIRECTION:
      proto_tree_add_item(attr_tree, hf_isakmp_ipsec_attr_sa_direction, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), ipsec_attr_sa_direction, "Unknown %d"));
    default:
      /* No Default Action */
      break;
  }

  return headerlen + value_len;
}

/* Returns the number of bytes consumed by this attribute. */
static int
dissect_resp_lifetime_ipsec_attribute(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  guint headerlen, value_len, attr_type;
  proto_item *attr_item;
  proto_tree *attr_tree;

  dissect_attribute_header(tvb, tree, offset,
                           hf_isakmp_resp_lifetime_ipsec_attr, ipsec_attr_type,
                           &headerlen, &value_len, &attr_type,
                           &attr_item, &attr_tree);

  offset += headerlen;

  if (value_len == 0)
  {
    expert_add_info(pinfo, attr_item, &ei_isakmp_attribute_value_empty);
    return headerlen;
  }

  switch(attr_type) {
    case IPSEC_ATTR_LIFE_TYPE:
      proto_tree_add_item(attr_tree, hf_isakmp_resp_lifetime_ipsec_attr_life_type, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), attr_life_type, "Unknown %d"));
      break;
    case IPSEC_ATTR_LIFE_DURATION:
      dissect_life_duration(tvb, attr_tree, attr_item, hf_isakmp_resp_lifetime_ipsec_attr_life_duration_uint32, hf_isakmp_resp_lifetime_ipsec_attr_life_duration_uint64, hf_isakmp_resp_lifetime_ipsec_attr_life_duration_bytes, offset, value_len);
      break;
    default:
      /* No Default Action */
      break;
  }

  return headerlen + value_len;
}

/* Returns the number of bytes consumed by this attribute. */
static int
dissect_ike_attribute(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, decrypt_data_t *decr)
{
  guint headerlen, value_len, attr_type;
  proto_item *attr_item;
  proto_tree *attr_tree;

  dissect_attribute_header(tvb, tree, offset,
                           hf_isakmp_ike_attr, ike_attr_type,
                           &headerlen, &value_len, &attr_type,
                           &attr_item, &attr_tree);

  offset += headerlen;

  if (value_len == 0)
  {
    expert_add_info(pinfo, attr_item, &ei_isakmp_attribute_value_empty);
    return headerlen;
  }

  switch(attr_type) {
    case IKE_ATTR_ENCRYPTION_ALGORITHM:
      proto_tree_add_item(attr_tree, hf_isakmp_ike_attr_encryption_algorithm, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), ike_attr_enc_algo, "Unknown %d"));
      if (decr) decr->ike_encr_alg = tvb_get_ntohs(tvb, offset);
      break;
    case IKE_ATTR_HASH_ALGORITHM:
      proto_tree_add_item(attr_tree, hf_isakmp_ike_attr_hash_algorithm, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), ike_attr_hash_algo, "Unknown %d"));
      if (decr) decr->ike_hash_alg = tvb_get_ntohs(tvb, offset);
      break;
    case IKE_ATTR_AUTHENTICATION_METHOD:
      proto_tree_add_item(attr_tree, hf_isakmp_ike_attr_authentication_method, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), ike_attr_authmeth, "Unknown %d"));
      if (decr) decr->is_psk = tvb_get_ntohs(tvb, offset) == 0x01 ? TRUE : FALSE;
      break;
    case IKE_ATTR_GROUP_DESCRIPTION:
      proto_tree_add_item(attr_tree, hf_isakmp_ike_attr_group_description, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), dh_group, "Unknown %d"));
      if (decr) decr->group = tvb_get_ntohs(tvb, offset);
      break;
    case IKE_ATTR_GROUP_TYPE:
      proto_tree_add_item(attr_tree, hf_isakmp_ike_attr_group_type, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), ike_attr_grp_type, "Unknown %d"));
      break;
    case IKE_ATTR_GROUP_PRIME:
      proto_tree_add_item(attr_tree, hf_isakmp_ike_attr_group_prime, tvb, offset, value_len, ENC_NA);
      break;
    case IKE_ATTR_GROUP_GENERATOR_ONE:
      proto_tree_add_item(attr_tree, hf_isakmp_ike_attr_group_generator_one, tvb, offset, value_len, ENC_NA);
      break;
    case IKE_ATTR_GROUP_GENERATOR_TWO:
      proto_tree_add_item(attr_tree, hf_isakmp_ike_attr_group_generator_two, tvb, offset, value_len, ENC_NA);
      break;
    case IKE_ATTR_GROUP_CURVE_A:
      proto_tree_add_item(attr_tree, hf_isakmp_ike_attr_group_curve_a, tvb, offset, value_len, ENC_NA);
      break;
    case IKE_ATTR_GROUP_CURVE_B:
      proto_tree_add_item(attr_tree, hf_isakmp_ike_attr_group_curve_b, tvb, offset, value_len, ENC_NA);
      break;
    case IKE_ATTR_LIFE_TYPE:
      proto_tree_add_item(attr_tree, hf_isakmp_ike_attr_life_type, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), attr_life_type, "Unknown %d"));
      break;
    case IKE_ATTR_LIFE_DURATION:
      dissect_life_duration(tvb, attr_tree, attr_item, hf_isakmp_ike_attr_life_duration_uint32, hf_isakmp_ike_attr_life_duration_uint64, hf_isakmp_ike_attr_life_duration_bytes, offset, value_len);
      break;
    case IKE_ATTR_PRF:
      proto_tree_add_item(attr_tree, hf_isakmp_ike_attr_prf, tvb, offset, value_len, ENC_NA);
      break;
    case IKE_ATTR_KEY_LENGTH:
      proto_tree_add_item(attr_tree, hf_isakmp_ike_attr_key_length, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %d", tvb_get_ntohs(tvb, offset));
      if (decr) decr->ike_encr_keylen = tvb_get_ntohs(tvb, offset);
      break;
    case IKE_ATTR_FIELD_SIZE:
      proto_tree_add_item(attr_tree, hf_isakmp_ike_attr_field_size, tvb, offset, value_len, ENC_NA);
      break;
    case IKE_ATTR_GROUP_ORDER:
      proto_tree_add_item(attr_tree, hf_isakmp_ike_attr_group_order, tvb, offset, value_len, ENC_NA);
      break;
    case IKE_ATTR_BLOCK_SIZE:
      proto_tree_add_item(attr_tree, hf_isakmp_ike_attr_block_size, tvb, offset, value_len, ENC_NA);
      break;
    case IKE_ATTR_ACAT:
      proto_tree_add_item(attr_tree, hf_isakmp_ike_attr_asymmetric_cryptographic_algorithm_type, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), ike_attr_asym_algo, "Unknown %d"));
      break;
    default:
      /* No Default Action */
      break;
  }

  return headerlen + value_len;
}

/* Returns the number of bytes consumed by this attribute. */
static int
dissect_resp_lifetime_ike_attribute(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  guint headerlen, value_len, attr_type;
  proto_item *attr_item;
  proto_tree *attr_tree;

  dissect_attribute_header(tvb, tree, offset,
                           hf_isakmp_resp_lifetime_ike_attr, ike_attr_type,
                           &headerlen, &value_len, &attr_type,
                           &attr_item, &attr_tree);

  offset += headerlen;

  if (value_len == 0)
  {
    expert_add_info(pinfo, attr_item, &ei_isakmp_attribute_value_empty);
    return headerlen;
  }

  switch(attr_type) {
    case IKE_ATTR_LIFE_TYPE:
      proto_tree_add_item(attr_tree, hf_isakmp_resp_lifetime_ike_attr_life_type, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), attr_life_type, "Unknown %d"));
      break;
    case IKE_ATTR_LIFE_DURATION:
      dissect_life_duration(tvb, attr_tree, attr_item, hf_isakmp_resp_lifetime_ike_attr_life_duration_uint32, hf_isakmp_resp_lifetime_ike_attr_life_duration_uint64, hf_isakmp_resp_lifetime_ike_attr_life_duration_bytes, offset, value_len);
      break;
    default:
      /* No Default Action */
      break;
  }

  return headerlen + value_len;
}

/* Returns the number of bytes consumed by this attribute. */
static int
dissect_ike2_transform_attribute(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  guint headerlen, value_len, attr_type;
  proto_item *attr_item;
  proto_tree *attr_tree;

  dissect_attribute_header(tvb, tree, offset,
                           hf_isakmp_ike2_attr, transform_ike2_attr_type,
                           &headerlen, &value_len, &attr_type,
                           &attr_item, &attr_tree);

  offset += headerlen;

  if (value_len == 0)
  {
    expert_add_info(pinfo, attr_item, &ei_isakmp_attribute_value_empty);
    return headerlen;
  }

  switch(attr_type) {
    case IKE2_ATTR_KEY_LENGTH:
      proto_tree_add_item(attr_tree, hf_isakmp_ike2_attr_key_length, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %d", tvb_get_ntohs(tvb, offset));
      break;
    default:
      /* No Default Action */
      break;
  }

  return headerlen + value_len;
}

static void
dissect_transform(tvbuff_t *tvb, packet_info *pinfo, int offset, int length, proto_tree *tree, int isakmp_version, int protocol_id, void* decr_data)
{
  if (isakmp_version == 1)
  {
    guint8              transform_id;
    guint8              transform_num;
    decrypt_data_t *decr = (decrypt_data_t *)decr_data;
    int offset_end = 0;
    offset_end = offset + length;

    transform_num = tvb_get_guint8(tvb, offset);
    proto_item_append_text(tree," # %d",transform_num);

    proto_tree_add_item(tree, hf_isakmp_trans_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    transform_id = tvb_get_guint8(tvb, offset);
    switch (protocol_id) {
    case 1:     /* ISAKMP */
      proto_tree_add_uint_format_value(tree, hf_isakmp_trans_id, tvb, offset, 1,
                                 transform_id, "%s (%u)",
                                 val_to_str_const(transform_id, vs_v1_trans_isakmp, "UNKNOWN-TRANS-TYPE"), transform_id);
      break;
    case 2:     /* AH */
      proto_tree_add_uint_format_value(tree, hf_isakmp_trans_id, tvb, offset, 1,
                                 transform_id, "%s (%u)",
                                 val_to_str_const(transform_id, vs_v1_trans_ah, "UNKNOWN-AH-TRANS-TYPE"), transform_id);
      break;
    case 3:     /* ESP */
      proto_tree_add_uint_format_value(tree, hf_isakmp_trans_id, tvb, offset, 1,
                                 transform_id, "%s (%u)",
                                 val_to_str_const(transform_id, vs_v1_trans_esp, "UNKNOWN-ESP-TRANS-TYPE"), transform_id);
      break;
    case 4:     /* IPCOMP */
      proto_tree_add_uint_format_value(tree, hf_isakmp_trans_id, tvb, offset, 1,
                                 transform_id, "%s (%u)",
                                 val_to_str_const(transform_id, transform_id_ipcomp, "UNKNOWN-IPCOMP-TRANS-TYPE"), transform_id);
      break;
    default:
      proto_tree_add_item(tree, hf_isakmp_trans_id, tvb, offset, 1, ENC_BIG_ENDIAN);
      break;
    }
    offset += 1;

    proto_tree_add_item(tree, hf_isakmp_reserved, tvb, offset, 2, ENC_NA);
    offset += 2;

    if (protocol_id == 1 && transform_id == 1) {
      if (decr) {
        /* Allow detection of missing IKE transform attributes:
         * Make sure their values are not carried over from another transform
         * dissected previously. */
        decr->ike_encr_alg = 0;
        decr->ike_encr_keylen = 0;
        decr->ike_hash_alg = 0;
      }
      while (offset < offset_end) {
        offset += dissect_ike_attribute(tvb, pinfo, tree, offset, decr);
      }
    }
    else {
       while (offset < offset_end) {
         offset += dissect_ipsec_attribute(tvb, pinfo, tree, offset);
       }
    }
  }
  else if(isakmp_version == 2)
  {
    guint8 transform_type;
    int offset_end = 0;
    offset_end = offset + length;

    transform_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_isakmp_trans_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_isakmp_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;

    switch(transform_type){
    case TF_IKE2_ENCR:
      proto_tree_add_item(tree, hf_isakmp_trans_encr, tvb, offset, 2, ENC_BIG_ENDIAN);
      break;
    case TF_IKE2_PRF:
      proto_tree_add_item(tree, hf_isakmp_trans_prf, tvb, offset, 2, ENC_BIG_ENDIAN);
      break;
    case TF_IKE2_INTEG:
      proto_tree_add_item(tree, hf_isakmp_trans_integ, tvb, offset, 2, ENC_BIG_ENDIAN);
      break;
    case TF_IKE2_DH:
      proto_tree_add_item(tree, hf_isakmp_trans_dh, tvb, offset, 2, ENC_BIG_ENDIAN);
      break;
    case TF_IKE2_ESN:
      proto_tree_add_item(tree, hf_isakmp_trans_esn, tvb, offset, 2, ENC_BIG_ENDIAN);
      break;
    default:
      proto_tree_add_item(tree, hf_isakmp_trans_id_v2, tvb, offset, 2, ENC_BIG_ENDIAN);
      break;
    }
    offset += 2;

    while (offset < offset_end) {
      offset += dissect_ike2_transform_attribute(tvb, pinfo, tree, offset);
    }
  }
}

static void
dissect_key_exch(tvbuff_t *tvb, int offset, int length, proto_tree *tree, int isakmp_version,
                 packet_info* pinfo, void* decr_data)
{
  if (isakmp_version == 2) {
    proto_tree_add_item(tree, hf_isakmp_key_exch_dh_group, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    length -= 2;

    proto_tree_add_item(tree, hf_isakmp_reserved, tvb, offset, 2, ENC_NA);
    offset += 2;
    length -= 2;
  }

  proto_tree_add_item(tree, hf_isakmp_key_exch_data, tvb, offset, length, ENC_NA);

  if (isakmp_version == 1 && decr_data) {
    decrypt_data_t *decr = (decrypt_data_t *)decr_data;

    if (decr->gi_len == 0 && addresses_equal(&decr->initiator, &pinfo->src)) {
      decr->gi = (gchar *)g_malloc(length);
      tvb_memcpy(tvb, decr->gi, offset, length);
      decr->gi_len = length;
    } else if (decr->gr_len == 0 && !addresses_equal(&decr->initiator, &pinfo->src)) {
      decr->gr = (gchar *)g_malloc(length);
      tvb_memcpy(tvb, decr->gr, offset, length);
      decr->gr_len = length;
    }
  }
}

static void
dissect_id_type(tvbuff_t *tvb, int offset, int length, guint8 id_type, proto_tree *idtree, proto_item *idit, packet_info *pinfo )
{
  const guint8          *str;
  asn1_ctx_t            asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  switch (id_type) {
    case IKE_ID_IPV4_ADDR:
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv4_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
      proto_item_append_text(idit, "%s", tvb_ip_to_str(pinfo->pool, tvb, offset));
      break;
    case IKE_ID_FQDN:
      proto_tree_add_item_ret_string(idtree, hf_isakmp_id_data_fqdn, tvb, offset, length, ENC_ASCII|ENC_NA, pinfo->pool, &str);
      proto_item_append_text(idit, "%s", str);
      break;
    case IKE_ID_USER_FQDN:
      proto_tree_add_item_ret_string(idtree, hf_isakmp_id_data_user_fqdn, tvb, offset, length, ENC_ASCII|ENC_NA, pinfo->pool, &str);
      proto_item_append_text(idit, "%s", str);
      break;
    case IKE_ID_IPV4_ADDR_SUBNET:
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv4_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv4_subnet, tvb, offset+4, 4, ENC_BIG_ENDIAN);
      proto_item_append_text(idit, "%s/%s", tvb_ip_to_str(pinfo->pool, tvb, offset), tvb_ip_to_str(pinfo->pool, tvb, offset+4));
      break;
    case IKE_ID_IPV4_ADDR_RANGE:
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv4_range_start, tvb, offset, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv4_range_end, tvb, offset+4, 4, ENC_BIG_ENDIAN);
      proto_item_append_text(idit, "%s/%s", tvb_ip_to_str(pinfo->pool, tvb, offset), tvb_ip_to_str(pinfo->pool, tvb, offset+4));
      break;
    case IKE_ID_IPV6_ADDR:
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv6_addr, tvb, offset, 16, ENC_NA);
      proto_item_append_text(idit, "%s", tvb_ip6_to_str(pinfo->pool, tvb, offset));
      break;
    case IKE_ID_IPV6_ADDR_SUBNET:
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv6_addr, tvb, offset, 16, ENC_NA);
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv6_subnet, tvb, offset+16, 16, ENC_NA);
      proto_item_append_text(idit, "%s/%s", tvb_ip6_to_str(pinfo->pool, tvb, offset), tvb_ip6_to_str(pinfo->pool, tvb, offset+16));
      break;
    case IKE_ID_IPV6_ADDR_RANGE:
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv6_range_start, tvb, offset, 16, ENC_NA);
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv6_range_end, tvb, offset+16, 16, ENC_NA);
      proto_item_append_text(idit, "%s/%s", tvb_ip6_to_str(pinfo->pool, tvb, offset), tvb_ip6_to_str(pinfo->pool, tvb, offset+16));
      break;
    case IKE_ID_KEY_ID:
      proto_tree_add_item(idtree, hf_isakmp_id_data_key_id, tvb, offset, length, ENC_NA);
      break;
    case IKE_ID_DER_ASN1_DN:
      dissect_x509if_Name(FALSE, tvb, offset, &asn1_ctx, idtree, hf_isakmp_id_data_cert);
      break;
    default:
      proto_item_append_text(idit, "%s", tvb_bytes_to_str(pinfo->pool, tvb,offset,length));
      break;
  }
}

static void
dissect_id(tvbuff_t *tvb, int offset, int length, proto_tree *tree, int isakmp_version, packet_info *pinfo )
{
  guint8                id_type;
  guint8                protocol_id;
  guint16               port;
  proto_item            *idit;
  proto_tree            *idtree;

  id_type = tvb_get_guint8(tvb, offset);
  if (isakmp_version == 1)
  {
     proto_tree_add_item(tree, hf_isakmp_id_type_v1, tvb, offset, 1, ENC_BIG_ENDIAN);
  }else if (isakmp_version == 2)
  {
     proto_tree_add_item(tree, hf_isakmp_id_type_v2, tvb, offset, 1, ENC_BIG_ENDIAN);
  }
  offset += 1;
  length -= 1;

  if (isakmp_version == 1) {
    protocol_id = tvb_get_guint8(tvb, offset);
    if (protocol_id == 0)
      proto_tree_add_uint_format_value(tree, hf_isakmp_id_protoid, tvb, offset, 1,
                                 protocol_id, "Unused");
    else
      proto_tree_add_item(tree, hf_isakmp_id_protoid, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    length -= 1;

    port = tvb_get_ntohs(tvb, offset);
    if (port == 0)
      proto_tree_add_uint_format_value(tree, hf_isakmp_id_port, tvb, offset, 2,
                                 port, "Unused");
    else
      proto_tree_add_item(tree, hf_isakmp_id_port, tvb, offset, 2, ENC_BIG_ENDIAN);

    offset += 2;
    length -= 2;

  } else if (isakmp_version == 2) {
    proto_tree_add_item(tree, hf_isakmp_reserved, tvb, offset, 3, ENC_NA);
    offset += 3;
    length -= 3;
  }

  /*
   * It shows strings of all types though some of types are not
   * supported in IKEv2 specification actually.
   */
  idit = proto_tree_add_item(tree, hf_isakmp_id_data, tvb, offset, length, ENC_NA);
  idtree = proto_item_add_subtree(idit, ett_isakmp_id);
  dissect_id_type(tvb, offset, length, id_type, idtree, idit, pinfo);
}

static void
dissect_cert(tvbuff_t *tvb, int offset, int length, proto_tree *tree, int isakmp_version, packet_info *pinfo )
{
  guint8                cert_type;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  cert_type = tvb_get_guint8(tvb, offset);

  if (isakmp_version == 1)
  {
     proto_tree_add_item(tree, hf_isakmp_cert_encoding_v1, tvb, offset, 1, ENC_BIG_ENDIAN);
  }else if (isakmp_version == 2)
  {
     proto_tree_add_item(tree, hf_isakmp_cert_encoding_v2, tvb, offset, 1, ENC_BIG_ENDIAN);
  }

  offset += 1;
  length -= 1;

  if (isakmp_version == 1)
  {
    dissect_x509af_Certificate(FALSE, tvb, offset, &asn1_ctx, tree, hf_isakmp_cert_data);
  }else if (isakmp_version == 2)
  {
    switch(cert_type){
      case 12:{
        proto_item *ti_url;

        proto_tree_add_item(tree, hf_isakmp_cert_x509_hash, tvb, offset, 20, ENC_NA);
        offset += 20;
        length -= 20;

        ti_url = proto_tree_add_item(tree, hf_isakmp_cert_x509_url, tvb, offset, length, ENC_ASCII);
        proto_item_set_url(ti_url);
        }
        break;
      default:
        dissect_x509af_Certificate(FALSE, tvb, offset, &asn1_ctx, tree, hf_isakmp_cert_data);
        break;
    }
  }

}

static void
dissect_certreq(tvbuff_t *tvb, int offset, int length, proto_tree *tree, int isakmp_version, packet_info *pinfo )
{
  guint8                cert_type;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  cert_type = tvb_get_guint8(tvb, offset);

  if (isakmp_version == 1)
  {
    proto_tree_add_item(tree, hf_isakmp_certreq_type_v1, tvb, offset, 1, ENC_BIG_ENDIAN);
  }else if (isakmp_version == 2)
  {
    proto_tree_add_item(tree, hf_isakmp_certreq_type_v2, tvb, offset, 1, ENC_BIG_ENDIAN);
  }

  offset += 1;
  length -= 1;

  if (isakmp_version == 1)
  {
    if (length == 0)
      return;

    switch(cert_type){
      case 4:
        dissect_x509if_Name(FALSE, tvb, offset, &asn1_ctx, tree, hf_isakmp_certreq_authority_sig);
        break;
      default:
        proto_tree_add_item(tree, hf_isakmp_certreq_authority_v1, tvb, offset, length, ENC_NA);
        break;
    }
  }else if (isakmp_version == 2)
  {
    /* this is a list of 20 byte SHA-1 hashes */
    while (length > 0) {
      proto_tree_add_item(tree, hf_isakmp_certreq_authority_v2, tvb, offset, 20, ENC_NA);
      offset+=20;
      length-=20;
    }
  }
}

static void
dissect_auth(tvbuff_t *tvb, packet_info *pinfo, int offset, int length, proto_tree *tree)
{
  guint32                       auth_meth;
  guint32                       asn1_len;
  proto_item *                  ti;
  proto_tree *                  subtree;
  proto_tree *                  asn1tree;

  proto_tree_add_item_ret_uint(tree, hf_isakmp_auth_meth, tvb, offset, 1, ENC_BIG_ENDIAN, &auth_meth);
  offset += 1;
  length -= 1;

  proto_tree_add_item(tree, hf_isakmp_reserved, tvb, offset, 3, ENC_NA);
  offset += 3;
  length -= 3;

  ti = proto_tree_add_item(tree, hf_isakmp_auth_data, tvb, offset, length, ENC_NA);

  if (auth_meth == AUTH_METH_DIGITAL_SIGNATURE) {
    subtree = proto_item_add_subtree(ti, ett_isakmp_payload_digital_signature);

    proto_tree_add_item_ret_uint(subtree, hf_isakmp_auth_digital_sig_asn1_len, tvb, offset, 1, ENC_BIG_ENDIAN, &asn1_len);
    offset += 1;
    length -= 1;

    /* cast ok, since length was parsed out of one unsigned byte into guint32 */
    if ( (asn1_len > 0) && ((int)asn1_len < length) ) {

      ti = proto_tree_add_item(subtree, hf_isakmp_auth_digital_sig_asn1_data, tvb, offset, asn1_len, ENC_NA);
      asn1tree = proto_item_add_subtree(ti, ett_isakmp_payload_digital_signature_asn1_data);
      dissect_unknown_ber(pinfo, tvb, offset, asn1tree);

      offset += asn1_len;
      length -= asn1_len;

      proto_tree_add_item(subtree, hf_isakmp_auth_digital_sig_value, tvb, offset, length, ENC_NA);
    }
  }
}

static void
dissect_hash(tvbuff_t *tvb, int offset, int length, proto_tree *ntree)
{
  proto_tree_add_item(ntree, hf_isakmp_hash, tvb, offset, length, ENC_NA);
}

static void
dissect_sig(tvbuff_t *tvb, int offset, int length, proto_tree *ntree)
{
  proto_tree_add_item(ntree, hf_isakmp_sig, tvb, offset, length, ENC_NA);
}

static void
dissect_nonce(tvbuff_t *tvb, int offset, int length, proto_tree *ntree)
{
  proto_tree_add_item(ntree, hf_isakmp_nonce, tvb, offset, length, ENC_NA);
}

static void
dissect_cisco_fragmentation(tvbuff_t *tvb, int offset, int length, proto_tree *tree, packet_info *pinfo)
{
  guint8 seq; /* Packet sequence number, starting from 1 */
  guint8 last;
  proto_tree *ptree;
  ptree = proto_tree_get_parent(tree);
  if (length < 4)
    return;

  proto_tree_add_item(tree, hf_isakmp_cisco_frag_packetid, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  seq = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_isakmp_cisco_frag_seq, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  last = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_isakmp_cisco_frag_last, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  /*length-=4;*/

  /* Start Reassembly stuff for Cisco IKE fragmentation */
  {
    gboolean save_fragmented;
    tvbuff_t *defrag_isakmp_tvb;
    fragment_head *frag_msg;

    save_fragmented = pinfo->fragmented;
    pinfo->fragmented = TRUE;
    frag_msg = fragment_add_seq_check(&isakmp_cisco_reassembly_table, tvb, offset,
                                      pinfo,
                                      12345,                    /*FIXME:  Fragmented packet id, guint16, somehow get CKY here */
                                      NULL,
                                      seq-1,                    /* fragment sequence number, starting from 0 */
                                      tvb_reported_length_remaining(tvb, offset), /* fragment length - to the end */
                                      !last);                   /* More fragments? */
    defrag_isakmp_tvb = process_reassembled_data(tvb, offset, pinfo,
                                                 "Reassembled ISAKMP", frag_msg,
                                                 &isakmp_frag_items,  /* groups and items, using same as Cisco */
                                                 NULL, ptree);

    if (last && defrag_isakmp_tvb) { /* take it all */
      dissect_isakmp(defrag_isakmp_tvb, pinfo, ptree, NULL);
    }
    col_append_fstr(pinfo->cinfo, COL_INFO,
                      " (%sMessage fragment %u%s)",
                      (last && frag_msg ? "Reassembled + " : ""),
                      seq, (last ? " - last" : ""));
    pinfo->fragmented = save_fragmented;
  }
  /* End Reassembly stuff for Cisco IKE fragmentation */

}

/* This is RFC7383 reassembly. */
static void
dissect_ikev2_fragmentation(tvbuff_t *tvb, int offset, proto_tree *tree,
                            packet_info *pinfo, guint message_id, guint8 next_payload, gboolean is_request, void* decr_info)
{
  guint16 fragment_number, total_fragments;
  gboolean message_next_payload_set = FALSE;
  guint8  message_next_payload = 0;
  gint iv_len, icd_len;
  gint iv_offset;
  gint icd_offset;
  ikev2_decrypt_data_t *key_info;

  /* Fragment Number */
  fragment_number = tvb_get_ntohs(tvb, offset);
  total_fragments = tvb_get_ntohs(tvb, offset+2);
  proto_tree_add_item(tree, hf_isakmp_ike2_fragment_number, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  if (fragment_number == 0) {
    proto_tree_add_expert_format(tree, pinfo, &ei_isakmp_bad_fragment_number, tvb, 0, 0,
                                 "Fragment number must not be zero");
  }
  else if (fragment_number > total_fragments) {
    proto_tree_add_expert_format(tree, pinfo, &ei_isakmp_bad_fragment_number, tvb, 0, 0,
                                 "Fragment number (%u) must not be greater than total fragments (%u)",
                                 fragment_number, total_fragments);
  }

  /* During the first pass, store in the conversation the next_payload */
  if (!pinfo->fd->visited && (fragment_number == 1)) {
    /* Create/update conversation with message_id -> next_payload */
    conversation_t* p_conv = find_or_create_conversation(pinfo);
    ikev2_fragmentation_state_t *p_state = wmem_new0(wmem_file_scope(), ikev2_fragmentation_state_t);
    p_state->message_id = message_id;
    p_state->next_payload = next_payload;

    /* Store the state with the conversation */
    conversation_add_proto_data(p_conv, proto_isakmp, (void*)p_state);
  }

  /* Total fragments */
  proto_tree_add_item(tree, hf_isakmp_ike2_total_fragments, tvb, offset, 2, ENC_BIG_ENDIAN);
  if (total_fragments == 0) {
    proto_tree_add_expert_format(tree, pinfo, &ei_isakmp_bad_fragment_number, tvb, 0, 0,
                                 "Total fragments must not be zero");
  }

  /* Show fragment summary in Info column */
  col_append_fstr(pinfo->cinfo, COL_INFO, " (fragment %u/%u)", fragment_number, total_fragments);

  offset += 2;

  /* If this is the last fragment, need to know what the payload type for the reassembled message is,
     which was included in the first fragment */
  if (fragment_number == total_fragments) {
    if (!pinfo->fd->visited) {
      /* On first pass, get it from the conversation info */
      conversation_t *p_conv = find_conversation_pinfo(pinfo, 0);
      if (p_conv != NULL) {
        ikev2_fragmentation_state_t *p_state = (ikev2_fragmentation_state_t*)conversation_get_proto_data(p_conv, proto_isakmp);
        if (p_state != NULL) {
          if (p_state->message_id == message_id) {
            message_next_payload = p_state->next_payload;
            message_next_payload_set = TRUE;

            /* Store in table for this frame for future passes */
            g_hash_table_insert(defrag_next_payload_hash, GUINT_TO_POINTER(pinfo->num), GUINT_TO_POINTER((guint)message_next_payload));
          }
        }
      }
    }
    else {
      /* On later passes, look up in hash table by frame number */
      message_next_payload = (guint8)GPOINTER_TO_UINT(g_hash_table_lookup(defrag_next_payload_hash, GUINT_TO_POINTER(pinfo->num)));
      if (message_next_payload != 0) {
        message_next_payload_set = TRUE;
      }
    }
  }

  /* Can only know lengths of following fields if we have the key information */
  if (decr_info) {
    key_info = (ikev2_decrypt_data_t*)(decr_info);
    iv_len = key_info->encr_spec->iv_len;
    icd_len = key_info->auth_spec->trunc_len;
  }
  else {
    /* Can't show any more info. */
    return;
  }

  /* Initialization Vector */
  iv_offset = offset;
  proto_tree_add_item(tree, hf_isakmp_enc_iv, tvb, offset, iv_len, ENC_NA);
  offset += iv_len;

  icd_offset = offset + tvb_reported_length_remaining(tvb, offset) - icd_len;

  /* Encryption data */
  proto_tree_add_item(tree, hf_isakmp_enc_data, tvb, offset, icd_offset-offset, ENC_NA);

  /* Can only check how much padding there is after decrypting... */

  /* Start Reassembly stuff for IKE2 fragmentation */
  {
    gboolean save_fragmented;
    tvbuff_t *defrag_decrypted_isakmp_tvb;
    tvbuff_t *isakmp_decrypted_fragment_tvb;
    fragment_head *frag_msg;
    guint8 padding_length;
    guint16 fragment_length;

    /* Decrypt but don't dissect this encrypted payload. */
    isakmp_decrypted_fragment_tvb = dissect_enc(tvb, iv_offset, tvb_reported_length_remaining(tvb, iv_offset), tree, pinfo,
                                                0,        /* Payload type won't be used in this call, and may not know yet */
                                                is_request,
                                                decr_info,
                                                FALSE     /* Don't dissect decrypted tvb as not a completed payload */
                                                );

    /* Save pinfo->fragmented, will later restore it */
    save_fragmented = pinfo->fragmented;
    pinfo->fragmented = TRUE;

    /* Remove padding length + any padding bytes from reassembled payload */
    padding_length = tvb_get_guint8(isakmp_decrypted_fragment_tvb, tvb_reported_length(isakmp_decrypted_fragment_tvb)-1);
    fragment_length = tvb_reported_length(isakmp_decrypted_fragment_tvb) - 1 - padding_length;

    /* Adding decrypted tvb into reassembly table here */
    frag_msg = fragment_add_seq_check(&isakmp_ike2_reassembly_table,
                                      isakmp_decrypted_fragment_tvb,
                                      0,    /* offset */
                                      pinfo,
                                      message_id,                                 /* message_id from top-level header */
                                      NULL,                                       /* data? */
                                      fragment_number-1,                          /* fragment sequence number, starting from 0 */
                                      fragment_length,                            /* fragment - (padding_length + padding) */
                                      fragment_number < total_fragments);         /* More fragments? */

    defrag_decrypted_isakmp_tvb = process_reassembled_data(tvb, offset, pinfo,
                                                           "Reassembled IKE2 ISAKMP",
                                                           frag_msg,
                                                           &isakmp_frag_items, /* Tree IDs & items - using same ones as Cisco. */
                                                           NULL, tree);

    if (defrag_decrypted_isakmp_tvb && key_info && message_next_payload_set) {
      /* Completely reassembled  - already decrypted - dissect reassembled payload if know next payload type */
      col_append_fstr(pinfo->cinfo, COL_INFO, " (reassembled)");
      dissect_payloads(defrag_decrypted_isakmp_tvb, tree,
                      2,           /* Could store with next_payload, but wouldn't be here otherwise.. */
                      message_next_payload,
                      0, tvb_reported_length(defrag_decrypted_isakmp_tvb),
                      pinfo, message_id, is_request, decr_info);
    }
    /* Restore this flag */
    pinfo->fragmented = save_fragmented;
  }
  /* End Reassembly stuff for IKE2 fragmentation */
}

static void
dissect_notif(tvbuff_t *tvb, packet_info *pinfo, int offset, int length, proto_tree *tree, int isakmp_version)
{
  guint32               doi = 0;
  guint8                protocol_id;
  guint8                spi_size;
  guint16               msgtype;
  proto_item            *data_item;
  proto_tree            *data_tree;
  int                   offset_end = 0;
  offset_end = offset + length;

  if (isakmp_version == 1) {
    doi = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_isakmp_notify_doi, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    length -= 4;
  }

  protocol_id = tvb_get_guint8(tvb, offset);
  if (isakmp_version == 1)
  {
     proto_tree_add_item(tree, hf_isakmp_notify_protoid_v1, tvb, offset, 1, ENC_BIG_ENDIAN);
  }else if (isakmp_version == 2)
  {
     proto_tree_add_item(tree, hf_isakmp_notify_protoid_v2, tvb, offset, 1, ENC_BIG_ENDIAN);
  }
  offset += 1;
  length -= 1;

  spi_size = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_isakmp_spisize, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  length -= 1;

  msgtype = tvb_get_ntohs(tvb, offset);

  if (isakmp_version == 1)
  {
    proto_tree_add_item(tree, hf_isakmp_notify_msgtype_v1, tvb, offset, 2, ENC_BIG_ENDIAN);
  }else if (isakmp_version == 2)
  {
    if ((msgtype < 8192) || (msgtype > 16383 && msgtype < 40959 )) {
      /* Standard error and status types */
      proto_tree_add_uint_format_value(tree, hf_isakmp_notify_msgtype_v2, tvb, offset, 2, msgtype, "%s (%u)",
          rval_to_str_const(msgtype, notifmsg_v2_type, "Unknown"), msgtype);
      proto_item_append_text(tree, " - %s",
          rval_to_str_const(msgtype,
              notifmsg_v2_type,
              "Unknown"));
    } else {
      /* Private error and status types */
      proto_tree_add_uint_format_value(tree, hf_isakmp_notify_msgtype_v2, tvb, offset, 2, msgtype, "%s (%u)",
          rval_to_str_const(msgtype, notifmsg_v2_3gpp_type, "Unknown"), msgtype);
      proto_item_append_text(tree, " - %s",
          rval_to_str_const(msgtype,
              notifmsg_v2_3gpp_type,
              "Unknown"));
    }
  }
  offset += 2;
  length -= 2;

  if (spi_size) {
    proto_tree_add_item(tree, hf_isakmp_spi, tvb, offset, spi_size, ENC_NA);
    offset += spi_size;
    length -= spi_size;
  }

  /* Notification Data */

  data_item = proto_tree_add_item(tree, hf_isakmp_notify_data, tvb, offset, length, ENC_NA);
  data_tree = proto_item_add_subtree(data_item, ett_isakmp_notify_data);

  if (isakmp_version == 1)
  {
    switch (msgtype) {
      case 24576: /* RESPONDER LIFETIME */
        if (protocol_id == 1) {
          /* Phase 1 */
          while (offset < offset_end) {
            offset += dissect_resp_lifetime_ike_attribute(tvb, pinfo, data_tree, offset);
          }
        } else if (protocol_id > 1 && doi == 1) {
          /* Phase 2, IPsec DOI */
          while (offset < offset_end) {
            offset += dissect_resp_lifetime_ipsec_attribute(tvb, pinfo, data_tree, offset);
          }
        }
        break;
      case 36136: /* DPD ARE YOU THERE */
        proto_tree_add_item(tree, hf_isakmp_notify_data_dpd_are_you_there, tvb, offset, length, ENC_BIG_ENDIAN);
        break;
      case 36137: /* DPD ARE YOU THERE ACK */
        proto_tree_add_item(tree, hf_isakmp_notify_data_dpd_are_you_there_ack, tvb, offset, length, ENC_BIG_ENDIAN);
        break;
      case 40501: /* UNITY Load Balance */
        proto_tree_add_item(tree, hf_isakmp_notify_data_unity_load_balance, tvb, offset, length, ENC_BIG_ENDIAN);
        break;
      default:
        /* No Default Action */
        break;
    }

  } else if (isakmp_version == 2)
  {
    switch(msgtype){
      case 17: /* INVALID_KE_PAYLOAD */
        proto_tree_add_item(tree, hf_isakmp_notify_data_accepted_dh_group, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
      case 16387: /* IPCOMP_SUPPORTED */
        proto_tree_add_item(tree, hf_isakmp_notify_data_ipcomp_cpi, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_isakmp_notify_data_ipcomp_transform_id, tvb, offset+2, 1, ENC_BIG_ENDIAN);
        break;
      case 16403: /* AUTH_LIFETIME" */
      {
        guint32 hours;
        guint32 minutes;
        guint32 seconds;
        guint32 durations_seconds;

        durations_seconds = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);

        hours = durations_seconds / 3600;
        minutes = (durations_seconds % 3600) / 60;
        seconds = (durations_seconds % 3600) % 60;

        proto_tree_add_uint_format_value(tree, hf_isakmp_notify_data_auth_lifetime, tvb, offset, length, durations_seconds,
                    "%u seconds (%u hour(s) %02u minute(s) %02u second(s))", durations_seconds, hours, minutes, seconds);
        break;
      }
      case 16407: /* REDIRECT */
        proto_tree_add_item(tree, hf_isakmp_notify_data_redirect_gw_ident_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_isakmp_notify_data_redirect_gw_ident_len, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        switch(tvb_get_guint8(tvb, offset)){ /* Ident Type ? */
          case 1:
            proto_tree_add_item(tree, hf_isakmp_notify_data_redirect_new_resp_gw_ident_ipv4, tvb, offset+2, 4, ENC_BIG_ENDIAN);
            break;
          case 2:
            proto_tree_add_item(tree, hf_isakmp_notify_data_redirect_new_resp_gw_ident_ipv6, tvb, offset+2, 16, ENC_NA);
            break;
          case 3:
            proto_tree_add_item(tree, hf_isakmp_notify_data_redirect_new_resp_gw_ident_fqdn, tvb, offset+2, tvb_get_guint8(tvb,offset+1), ENC_ASCII);
            break;
          default :
            proto_tree_add_item(tree, hf_isakmp_notify_data_redirect_new_resp_gw_ident, tvb, offset+2, tvb_get_guint8(tvb,offset+1), ENC_NA);
            break;
        }
        length -= tvb_get_guint8(tvb, offset+1) + 2;
        offset += tvb_get_guint8(tvb, offset+1) + 2;
        if(length)
        {
          proto_tree_add_item(tree, hf_isakmp_notify_data_redirect_nonce_data, tvb, offset, length, ENC_NA);
        }
        break;
      case 16408: /* REDIRECT_FROM */
        proto_tree_add_item(tree, hf_isakmp_notify_data_redirect_gw_ident_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_isakmp_notify_data_redirect_gw_ident_len, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        switch(tvb_get_guint8(tvb, offset)){ /* Ident Type ? */
          case 1:
            proto_tree_add_item(tree, hf_isakmp_notify_data_redirect_org_resp_gw_ident_ipv4, tvb, offset+2, 4, ENC_BIG_ENDIAN);
            break;
          case 2:
            proto_tree_add_item(tree, hf_isakmp_notify_data_redirect_org_resp_gw_ident_ipv6, tvb, offset+2, 16, ENC_NA);
            break;
          default :
            proto_tree_add_item(tree, hf_isakmp_notify_data_redirect_org_resp_gw_ident, tvb, offset+2, tvb_get_guint8(tvb,offset+1), ENC_NA);
            break;
        }
        break;
      case 16409: /* TICKET_LT_OPAQUE */
        proto_tree_add_item(tree, hf_isakmp_notify_data_ticket_lifetime, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        length -= 4;
        proto_tree_add_item(tree, hf_isakmp_notify_data_ticket_data, tvb, offset, length, ENC_NA);
        break;
      case 16413: /* TICKET_OPAQUE */
        proto_tree_add_item(tree, hf_isakmp_notify_data_ticket_data, tvb, offset, length, ENC_NA);
        break;
      case 16416: /* ROHC_SUPPORTED */
        while (offset < offset_end) {
          offset += dissect_rohc_attribute(tvb, pinfo, tree, offset);
        }
        break;
      case 16419: /* QUICK_CRASH_DETECTION */
        proto_tree_add_item(tree, hf_isakmp_notify_data_qcd_token_secret_data, tvb, offset, length, ENC_NA);
        break;
      case 16422: /* IKEV2_MESSAGE_ID_SYNC */
        proto_tree_add_item(tree, hf_isakmp_notify_data_ha_nonce_data, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_isakmp_notify_data_ha_expected_send_req_msg_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_isakmp_notify_data_ha_expected_recv_req_msg_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        break;
      case 16423: /* IPSEC_REPLAY_COUNTER_SYNC */
        proto_tree_add_item(tree, hf_isakmp_notify_data_ha_incoming_ipsec_sa_delta_value, tvb, offset, length, ENC_NA);
        break;
      case 16424: /* SECURE_PASSWORD_METHODS */
        proto_tree_add_item(tree, hf_isakmp_notify_data_secure_password_methods, tvb, offset, length, ENC_NA);
        break;
      case 16431: /*SIGNATURE_HASH_ALGORITHMS*/
        while(offset < offset_end) {
          proto_tree_add_item(tree, hf_isakmp_notify_data_signature_hash_algorithms, tvb, offset, 2, ENC_BIG_ENDIAN);
          offset += 2;
        }
        break;
      case 41041:
        /* private status 3GPP BACKOFF_TIMER*/
        proto_tree_add_item(tree, hf_isakmp_notify_data_3gpp_backoff_timer_len, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        de_gc_timer3(tvb, tree, pinfo, offset, 1, NULL, 0);
        break;
      case 41101: /* DEVICE_IDENTITY */
        if(length>=3) {
            guint64 octet;
            guint32 bit_offset;

            /* As specified in 3GPP TS 24.302  (Section 8.2.9.2) */
            /* Payload Octet 5,6 - Identity length */
            proto_tree_add_item(tree, hf_isakmp_notify_data_3gpp_device_identity_len, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            bit_offset = offset<<3;
            bit_offset += 6;

            /* Payload Octet 7 - Identity type */
            proto_tree_add_bits_ret_val(tree, hf_isakmp_notify_data_3gpp_device_identity_type, tvb, bit_offset, 2, &octet, ENC_LITTLE_ENDIAN);

            offset += 1;
            length -= 3;

            if(length==0) {
                break;
            }

            /* Payload Octet 8-n - Identity value */
            switch (octet) {
                case 1:
                    /* IMEI */
                    proto_tree_add_item(tree, hf_isakmp_notify_data_3gpp_device_identity_imei, tvb, offset, length, ENC_BCD_DIGITS_0_9);
                    break;
                case 2:
                    /* IMEISV */
                    proto_tree_add_item(tree, hf_isakmp_notify_data_3gpp_device_identity_imeisv, tvb, offset, length, ENC_BCD_DIGITS_0_9);
                    break;
                default:
                    proto_tree_add_expert(tree, pinfo, &ei_isakmp_notify_data_3gpp_unknown_device_identity, tvb, offset, length);
                    break;
            }
        }
        break;
      case 41134:
        /* private status 3GPP EMERGENCY_CALL_NUMBERS*/
        /* If Notify Data is not empty/missing */
        if(length>0)
        {
          /* As specified in 3GPP TS 23.302 (Section 8.1.2.3) and TS 24.008 (Section 10.5.3.13) */
          proto_tree *em_call_num_tree;

          /* Main Payload Subtree */
          em_call_num_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_isakmp_notify_data_3gpp_emergency_call_numbers_main, NULL, "Emergency Call Numbers");

          /* Payload Octet 5 - Length of IE Contents */
          proto_tree_add_item(em_call_num_tree, hf_isakmp_notify_data_3gpp_emergency_call_numbers_len, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;

          /* Subtree for actual values */
          proto_tree *current_emergency_call_number_tree;

          while(offset<offset_end){
            guint8 current_em_num_len = tvb_get_guint8(tvb,offset)+1; //Total length including octets 3 and 4 for proper highlighting

            /* Subtree for elements*/
            current_emergency_call_number_tree = proto_tree_add_subtree(em_call_num_tree, tvb, offset, current_em_num_len, ett_isakmp_notify_data_3gpp_emergency_call_numbers_element, NULL, "Emergency Number");

            /*IE Octet 3 Number of octets used to encode the Emergency Service Category Value and the Number digits. */
            proto_tree_add_item(current_emergency_call_number_tree, hf_isakmp_notify_data_3gpp_emergency_call_numbers_element_len,tvb,offset,1,ENC_BIG_ENDIAN);
            offset += 1;

            /*IE Octet 4 |Spare=0|Spare=0|Spare=0|Emergency Service Category Value|
             * Bits 1 to 5 are coded as bits 1 to 5 of octet 3 of the Service Category
             * information element as specified in subclause 10.5.4.33. (TS 24.008)
             */
            static int * const isakmp_notify_data_3gpp_emergency_call_numbers_flags[] = {
              &hf_isakmp_notify_data_3gpp_emergency_call_numbers_spare,
              &hf_isakmp_notify_data_3gpp_emergency_call_numbers_flag_b5_mountain_rescue,
              &hf_isakmp_notify_data_3gpp_emergency_call_numbers_flag_b4_marine_guard,
              &hf_isakmp_notify_data_3gpp_emergency_call_numbers_flag_b3_fire_brigade,
              &hf_isakmp_notify_data_3gpp_emergency_call_numbers_flag_b2_ambulance,
              &hf_isakmp_notify_data_3gpp_emergency_call_numbers_flag_b1_police,
              NULL
            };
            proto_tree_add_bitmask_with_flags(current_emergency_call_number_tree, tvb, offset, hf_isakmp_notify_data_3gpp_emergency_call_numbers_flags,
                ett_isakmp_notify_data_3gpp_emergency_call_numbers_element, isakmp_notify_data_3gpp_emergency_call_numbers_flags,ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT | BMT_NO_TFS);
            offset += 1;

            /*IE Octet 5 to j | Digit_N+1 | Digit_N | */
            current_em_num_len -= 2; //Not counting octets 3 and 4
            proto_tree_add_item(current_emergency_call_number_tree, hf_iskamp_notify_data_3gpp_emergency_call_number, tvb, offset, current_em_num_len, ENC_BCD_DIGITS_0_9);
            offset += current_em_num_len; //moving to the next number in the list
          }
        }
        break;
      default:
        /* No Default Action */
        break;
    }
  }
}

static void
dissect_delete(tvbuff_t *tvb, int offset, int length, proto_tree *tree, int isakmp_version)
{
  guint8                spi_size;

  if (isakmp_version == 1) {
    proto_tree_add_item(tree, hf_isakmp_delete_doi, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    length -= 4;
  }


  if (isakmp_version == 1)
  {
    proto_tree_add_item(tree, hf_isakmp_delete_protoid_v1, tvb, offset, 1, ENC_BIG_ENDIAN);
  }else if (isakmp_version == 2)
  {
    proto_tree_add_item(tree, hf_isakmp_delete_protoid_v2, tvb, offset, 1, ENC_BIG_ENDIAN);
  }

  offset += 1;
  length -= 1;

  spi_size = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_isakmp_spisize, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  length -= 1;

  proto_tree_add_item(tree, hf_isakmp_num_spis, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  length -= 2;

  if (spi_size > 0) {
    while (length > 0) {
      proto_tree_add_item(tree, hf_isakmp_delete_spi, tvb, offset, spi_size, ENC_NA);
      offset+=spi_size;
      length-=spi_size;
    }
  }
}


static int
dissect_vid(tvbuff_t *tvb, int offset, int length, proto_tree *tree)
{
  const guint8 * pVID;
  const char * vendorstring;

  pVID = tvb_get_ptr(tvb, offset, length);

  vendorstring = bytesprefix_to_str(pVID, (size_t)length, vendor_id, "Unknown Vendor ID");
  proto_tree_add_item(tree, hf_isakmp_vid_bytes, tvb, offset, length, ENC_NA);
  proto_tree_add_string(tree, hf_isakmp_vid_string, tvb, offset, length, vendorstring);
  proto_item_append_text(tree," : %s", vendorstring);

  /* very old CryptPro/GOST (Check Point R65) VID */
  if (length >= 24 && memcmp(pVID, VID_CP_01_R65, 20) == 0)
  {
    offset += 20;
    proto_tree_add_item(tree, hf_isakmp_vid_cp_product, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset +=4;
    proto_tree_add_item(tree, hf_isakmp_vid_cp_version, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset +=4;
    proto_tree_add_item(tree, hf_isakmp_vid_cp_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset +=4;
    proto_tree_add_item(tree, hf_isakmp_vid_cp_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset +=4;
    proto_tree_add_item(tree, hf_isakmp_vid_cp_features, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset +=4;
  }

  /* Cisco Unity VID */
  if (length >= 14 && memcmp(pVID, VID_CISCO_UNITY, 14) == 0)
  {
    offset += 14;
    proto_tree_add_item(tree, hf_isakmp_vid_cisco_unity_major, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(tree, " %u", tvb_get_guint8(tvb,offset));
    offset += 1;
    proto_tree_add_item(tree, hf_isakmp_vid_cisco_unity_minor, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(tree, ".%u", tvb_get_guint8(tvb,offset));
    offset += 1;
  }

  /* VID_MS_NT5_ISAKMPOAKLEY */
  if (length >= 16 && memcmp(pVID, VID_MS_NT5_ISAKMPOAKLEY, 16) == 0)
  {
    offset += 16;
    proto_tree_add_item(tree, hf_isakmp_vid_ms_nt5_isakmpoakley, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
  }

  /* VID_ARUBA_VIA_AUTH_PROFILE */
  if (length >= 19 && memcmp(pVID, VID_ARUBA_VIA_AUTH_PROFILE, 19) == 0)
  {
    offset += 19;
    proto_tree_add_item(tree, hf_isakmp_vid_aruba_via_auth_profile, tvb, offset, length-19, ENC_ASCII);
    offset += 4;
  }

  /* VID_FORTIGATE (Fortinet) */
  if (length >= 12 && memcmp(pVID, VID_FORTINET_FORTIGATE, 12) == 0)
  {
    offset += 12;
    proto_tree_add_item(tree, hf_isakmp_vid_fortinet_fortigate_release, tvb, offset, 2, ENC_ASCII|ENC_NA);
    offset += 2;
    proto_tree_add_item(tree, hf_isakmp_vid_fortinet_fortigate_build, tvb, offset, 2, ENC_ASCII|ENC_NA);
    offset += 2;
  }
  return offset;
}

/* Returns the number of bytes consumed by this attribute. */
static int
dissect_config_attribute(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int isakmp_version, gboolean is_request)
{
  const range_string *vs_cfgattr;
  guint headerlen, value_len, attr_type;
  proto_item *attr_item;
  proto_tree *attr_tree;
  guint i;
  const guint8* str;

  if (isakmp_version == 1) {
    vs_cfgattr = vs_v1_cfgattr;
    hf_isakmp_cfg_attr.type = hf_isakmp_cfg_attr_type_v1;
  } else if (isakmp_version == 2) {
    vs_cfgattr = vs_v2_cfgattr;
    hf_isakmp_cfg_attr.type = hf_isakmp_cfg_attr_type_v2;
  } else {
    /* Fail gracefully in case of an unsupported isakmp_version. */
    return 4;
  }

  dissect_attribute_header(tvb, tree, offset,
                           hf_isakmp_cfg_attr, vs_cfgattr,
                           &headerlen, &value_len, &attr_type,
                           &attr_item, &attr_tree);

  offset += headerlen;

  if (value_len == 0)
  {
    /* Don't complain about zero length if part of a config request - values will be assigned and included in the response message */
    if (!is_request) {
      expert_add_info(pinfo, attr_item, &ei_isakmp_attribute_value_empty);
    }
    return headerlen;
  }

  switch (attr_type) {
    case INTERNAL_IP4_ADDRESS: /* 1 */
      if (value_len % 4 == 0)
      {
        for (i = 0; i < value_len / 4; i++)
        {
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip4_address, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
        }
      }
      break;
    case INTERNAL_IP4_NETMASK: /* 2 */
      proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip4_netmask, tvb, offset, 4, ENC_BIG_ENDIAN);
      break;
    case INTERNAL_IP4_DNS: /* 3 */
      if (value_len % 4 == 0)
      {
        for (i = 0; i < value_len / 4; i++)
        {
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip4_dns, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
        }
      }
      break;
    case INTERNAL_IP4_NBNS: /* 4 */
      if (value_len % 4 == 0)
      {
        for (i = 0; i < value_len / 4; i++)
        {
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip4_nbns, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
        }
      }
      break;
    case INTERNAL_ADDRESS_EXPIRY: /* 5 */
      proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_address_expiry, tvb, offset, 4, ENC_BIG_ENDIAN);
      break;
    case INTERNAL_IP4_DHCP: /* 6 */
      if (value_len % 4 == 0)
      {
        for (i = 0; i < value_len / 4; i++)
        {
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip4_dhcp, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
        }
      }
      break;
    case APPLICATION_VERSION: /* 7 */
      proto_tree_add_item_ret_string(attr_tree, hf_isakmp_cfg_attr_application_version, tvb, offset, value_len, ENC_ASCII|ENC_NA, pinfo->pool, &str);
      proto_item_append_text(attr_item, ": %s", str);
      break;
    case INTERNAL_IP6_ADDRESS: /* 8 */
      if (value_len % 17 == 0)
      {
        for (i = 0; i < value_len / 17; i++)
        {
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip6_address_ip, tvb, offset, 16, ENC_NA);
          offset += 16;
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip6_address_prefix, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
        }
      }
      break;
    case INTERNAL_IP6_NETMASK: /* 9 Only in IKEv1 */
      proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip6_netmask, tvb, offset, 18, ENC_NA);
      break;
    case INTERNAL_IP6_DNS: /* 10 */
      if (value_len % 16 == 0)
      {
        for (i = 0; i < value_len / 16; i++)
        {
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip6_dns, tvb, offset, 16, ENC_NA);
          offset += 16;
        }
      }
      break;
    case INTERNAL_IP6_NBNS: /* 11 */
      if (value_len % 16 == 0)
      {
        for (i = 0; i < value_len / 16; i++)
        {
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip6_nbns, tvb, offset, 16, ENC_NA);
          offset += 16;
        }
      }
      break;
    case INTERNAL_IP6_DHCP: /* 12 */
      if (value_len % 16 == 0)
      {
        for (i = 0; i < value_len / 16; i++)
        {
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip6_dhcp, tvb, offset, 16, ENC_NA);
          offset += 16;
        }
      }
      break;
    case INTERNAL_IP4_SUBNET: /* 13 */
      if (value_len % 8 == 0)
      {
        for (i = 0; i < value_len / 8; i++)
        {
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip4_subnet_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip4_subnet_netmask, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
        }
      }
      break;
    case SUPPORTED_ATTRIBUTES: /* 14 */
      if (value_len % 2 == 0)
      {
        for (i = 0; i < value_len / 2; i++)
        {
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_supported_attributes, tvb, offset, 2, ENC_BIG_ENDIAN);
          offset += 2;
        }
      }
      break;
    case INTERNAL_IP6_SUBNET: /* 15 */
      if (value_len % 17 == 0)
      {
        for (i = 0; i < value_len / 17; i++)
        {
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip6_subnet_ip, tvb, offset, 16, ENC_NA);
          offset += 16;
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip6_subnet_prefix, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
        }
      }
      break;
    case INTERNAL_IP6_LINK: /* 17 */
      proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip6_link_interface, tvb, offset, 8, ENC_BIG_ENDIAN);
      offset += 8;
      proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip6_link_id, tvb, offset, value_len - 8, ENC_NA);
      break;
    case INTERNAL_IP6_PREFIX: /* 18 */
      if (value_len % 17 == 0)
      {
        for (i = 0; i < value_len / 17; i++)
        {
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip6_prefix_ip, tvb, offset, 16, ENC_NA);
          offset += 16;
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_internal_ip6_prefix_length, tvb, offset, 1, ENC_BIG_ENDIAN);
          offset += 1;
        }
      }
      break;
    case P_CSCF_IP4_ADDRESS: /* 20 */
      if (value_len % 4 == 0)
      {
        for (i = 0; i < value_len / 4; i++)
        {
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_p_cscf_ip4_address, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
        }
      }
      break;
    case P_CSCF_IP6_ADDRESS: /* 21 */
      if (value_len % 16 == 0)
      {
        for (i = 0; i < value_len / 16; i++)
        {
          proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_p_cscf_ip6_address, tvb, offset, 16, ENC_NA);
          offset += 16;
        }
      }
      break;
    case XAUTH_TYPE: /* 16520 */
      proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_xauth_type, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", rval_to_str(tvb_get_ntohs(tvb, offset), cfgattr_xauth_type, "Unknown %d"));
      break;
    case XAUTH_USER_NAME: /* 16521 */
      proto_tree_add_item_ret_string(attr_tree, hf_isakmp_cfg_attr_xauth_user_name, tvb, offset, value_len, ENC_ASCII|ENC_NA, pinfo->pool, &str);
      proto_item_append_text(attr_item, ": %s", str);
      break;
    case XAUTH_USER_PASSWORD: /* 16522 */
      proto_tree_add_item_ret_string(attr_tree, hf_isakmp_cfg_attr_xauth_user_password, tvb, offset, value_len, ENC_ASCII|ENC_NA, pinfo->pool, &str);
      proto_item_append_text(attr_item, ": %s", str);
      break;
    case XAUTH_PASSCODE: /* 16523 */
      proto_tree_add_item_ret_string(attr_tree, hf_isakmp_cfg_attr_xauth_passcode, tvb, offset, value_len, ENC_ASCII|ENC_NA, pinfo->pool, &str);
      proto_item_append_text(attr_item, ": %s", str);
      break;
    case XAUTH_MESSAGE: /* 16524 */
      proto_tree_add_item_ret_string(attr_tree, hf_isakmp_cfg_attr_xauth_message, tvb, offset, value_len, ENC_ASCII|ENC_NA, pinfo->pool, &str);
      proto_item_append_text(attr_item, ": %s", str);
      break;
    case XAUTH_CHALLENGE: /* 16525 */
      proto_tree_add_item_ret_string(attr_tree, hf_isakmp_cfg_attr_xauth_challenge, tvb, offset, value_len, ENC_ASCII|ENC_NA, pinfo->pool, &str);
      proto_item_append_text(attr_item, ": %s", str);
      break;
    case XAUTH_DOMAIN: /* 16526 */
      proto_tree_add_item_ret_string(attr_tree, hf_isakmp_cfg_attr_xauth_domain, tvb, offset, value_len, ENC_ASCII|ENC_NA, pinfo->pool, &str);
      proto_item_append_text(attr_item, ": %s", str);
      break;
    case XAUTH_STATUS: /* 16527 */
      proto_tree_add_item(attr_tree, hf_isakmp_cfg_attr_xauth_status, tvb, offset, value_len, ENC_BIG_ENDIAN);
      proto_item_append_text(attr_item, ": %s", val_to_str(tvb_get_ntohs(tvb, offset), cfgattr_xauth_status, "Unknown %d"));
      break;
    case XAUTH_NEXT_PIN: /* 16528 */
      proto_tree_add_item_ret_string(attr_tree, hf_isakmp_cfg_attr_xauth_next_pin, tvb, offset, value_len, ENC_ASCII|ENC_NA, pinfo->pool, &str);
      proto_item_append_text(attr_item, ": %s", str);
      break;
    case XAUTH_ANSWER: /* 16527 */
      proto_tree_add_item_ret_string(attr_tree, hf_isakmp_cfg_attr_xauth_answer, tvb, offset, value_len, ENC_ASCII|ENC_NA, pinfo->pool, &str);
      proto_item_append_text(attr_item, ": %s", str);
      break;

    case UNITY_BANNER: /* 28672 */
      proto_tree_add_item_ret_string(attr_tree, hf_isakmp_cfg_attr_unity_banner, tvb, offset, value_len, ENC_ASCII|ENC_NA, pinfo->pool, &str);
      proto_item_append_text(attr_item, ": %s", str);
      break;
    case UNITY_DEF_DOMAIN: /* 28674 */
      proto_tree_add_item_ret_string(attr_tree, hf_isakmp_cfg_attr_unity_def_domain, tvb, offset, value_len, ENC_ASCII|ENC_NA, pinfo->pool, &str);
      proto_item_append_text(attr_item, ": %s", str);
      break;
/* TODO: Support other UNITY Attributes ! */
    default:
      /* No Default Action */
      break;
  }

  return headerlen + value_len;
}

static void
dissect_config(tvbuff_t *tvb, packet_info *pinfo, int offset, int length, proto_tree *tree, int isakmp_version, gboolean is_request)
{
  int offset_end = 0;
  offset_end = offset + length;
  if (isakmp_version == 1) {

    proto_tree_add_item(tree, hf_isakmp_cfg_type_v1,tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_isakmp_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_isakmp_cfg_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

  } else if (isakmp_version == 2) {

    proto_tree_add_item(tree, hf_isakmp_cfg_type_v2,tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_isakmp_reserved, tvb, offset, 3, ENC_NA);
    offset += 3;

  } else {
    /* Skip attribute dissection for unknown IKE versions. */
    return;
  }

  while (offset < offset_end) {
    offset += dissect_config_attribute(tvb, pinfo, tree, offset, isakmp_version, is_request);
  }
}

static void
dissect_sa_kek(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, int length, proto_tree *tree)
{
  int payload_end = 0;
  guint32 src_id_length, dst_id_length;

  guint8 next_payload;
  guint16 payload_length;

  next_payload = tvb_get_guint8(tvb, offset);
  payload_length = tvb_get_ntohs(tvb, offset + 2);

  payload_end = offset + payload_length;
  proto_tree_add_item(tree, hf_isakmp_sak_next_payload, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_isakmp_sak_reserved, tvb, offset+1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_isakmp_sak_payload_len, tvb, offset+2, 2, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_isakmp_sak_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, hf_isakmp_sak_src_id_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, hf_isakmp_sak_src_id_port, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item_ret_uint(tree, hf_isakmp_sak_src_id_length, tvb, offset, 1, ENC_BIG_ENDIAN, &src_id_length);
  offset += 1;
  if (src_id_length > 0) {
    proto_tree_add_item(tree, hf_isakmp_sak_src_id_data, tvb, offset, src_id_length, ENC_NA);
    offset += src_id_length;
  }
  proto_tree_add_item(tree, hf_isakmp_sak_dst_id_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;
  proto_tree_add_item(tree, hf_isakmp_sak_dst_id_port, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item_ret_uint(tree, hf_isakmp_sak_dst_id_length, tvb, offset, 1, ENC_BIG_ENDIAN, &dst_id_length);
  offset += 1;
  if (dst_id_length > 0) {
    proto_tree_add_item(tree, hf_isakmp_sak_dst_id_data, tvb, offset, dst_id_length, ENC_NA);
    offset += dst_id_length;
  }
  proto_tree_add_item(tree, hf_isakmp_sak_spi, tvb, offset, 16, ENC_NA);
  offset += 16;
  proto_tree_add_item(tree, hf_isakmp_reserved, tvb, offset, 4, ENC_NA);
  offset += 4;
  while (offset < payload_end) {
      offset += dissect_ipsec_attribute(tvb, pinfo, tree, offset);
  }
  if(PLOAD_IKE_SAT == next_payload)
  {
     dissect_sa_tek(tvb, pinfo, offset, length, tree);
  }
  /* GAP payload could also be here*/
}

static void
dissect_sa_tek(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, int length, proto_tree *tree)
{
  int offset_end = 0, payload_end=0;
  guint32 protocol_id, src_id_length, dst_id_length;
  offset_end = offset + length;
  guint8 next_payload, id_type;
  guint16 payload_length;
  proto_item * ti;
  proto_item * ntree;
  proto_item * idit;
  proto_tree * idtree;

  next_payload = tvb_get_guint8(tvb, offset);
  payload_length = tvb_get_ntohs(tvb, offset + 2);

  payload_end = offset + payload_length;

  ti = proto_tree_add_uint(tree, hf_isakmp_typepayload, tvb, offset, payload_length, PLOAD_IKE_SAT);

  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);

  proto_tree_add_item(ntree, hf_isakmp_sat_next_payload, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(ntree, hf_isakmp_sat_reserved, tvb, offset+1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(ntree, hf_isakmp_sat_payload_len, tvb, offset+2, 2, ENC_BIG_ENDIAN);

  offset += 4;
  proto_tree_add_item_ret_uint(ntree, hf_isakmp_sat_protocol_id, tvb, offset, 1, ENC_BIG_ENDIAN, &protocol_id);
  offset += 1;
  if (protocol_id == 1 || protocol_id == 2) {
    proto_tree_add_item(ntree, hf_isakmp_sat_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    id_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(ntree, hf_isakmp_sat_src_id_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ntree, hf_isakmp_sat_src_id_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item_ret_uint(ntree, hf_isakmp_sat_src_id_length, tvb, offset, 2, ENC_BIG_ENDIAN, &src_id_length);
    offset += 2;
    if (src_id_length > 0) {
        idit = proto_tree_add_item(ntree, hf_isakmp_sat_src_id_data, tvb, offset, src_id_length, ENC_NA);
        idtree = proto_item_add_subtree(idit, ett_isakmp_id);
        dissect_id_type(tvb, offset, src_id_length, id_type, idtree, idit, pinfo);
        offset += src_id_length;
    }
    id_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(ntree, hf_isakmp_sat_dst_id_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ntree, hf_isakmp_sat_dst_id_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item_ret_uint(ntree, hf_isakmp_sat_dst_id_length, tvb, offset, 2, ENC_BIG_ENDIAN, &dst_id_length);
    offset += 2;
    if (dst_id_length > 0) {
        idit = proto_tree_add_item(ntree, hf_isakmp_sat_dst_id_data, tvb, offset, dst_id_length, ENC_NA);
        idtree = proto_item_add_subtree(idit, ett_isakmp_id);
        dissect_id_type(tvb, offset, dst_id_length, id_type, idtree, idit, pinfo);
        offset += dst_id_length;
    }
    proto_tree_add_item(ntree, hf_isakmp_sat_transform_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ntree, hf_isakmp_sat_spi, tvb, offset, 4, ENC_NA);
    offset += 4;
    while (offset < payload_end) {
        offset += dissect_ipsec_attribute(tvb, pinfo, ntree, offset);
    }
    if(PLOAD_IKE_SAT == next_payload)
    {
        dissect_sa_tek(tvb, pinfo, offset, length, tree);
    }
  } else {
    proto_tree_add_item(ntree, hf_isakmp_sat_payload, tvb, offset, offset_end - offset, ENC_NA);
  }

}

/* Returns the number of bytes consumed by this attribute. */
static int
dissect_tek_key_attribute(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
  guint headerlen, value_len, attr_type;
  proto_item *attr_item;
  proto_tree *attr_tree;

  dissect_attribute_header(tvb, tree, offset,
                           hf_isakmp_tek_key_attr, tek_key_attr_type,
                           &headerlen, &value_len, &attr_type,
                           &attr_item, &attr_tree);

  if (value_len == 0)
  {
    expert_add_info(pinfo, attr_item, &ei_isakmp_attribute_value_empty);
    return headerlen;
  }

  return headerlen + value_len;
}

static void
dissect_key_download(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, int length, proto_tree *tree, int isakmp_version)
{
  int offset_end = 0, payload_end=0;
  guint32 num_key_pkt, kdp_length, kdp_spi_size;
  proto_item    *kd_item;
  proto_tree    *payload_tree;
  offset_end = offset + length;

  if (isakmp_version == 1) {

    proto_tree_add_item_ret_uint(tree, hf_isakmp_kd_num_key_pkt, tvb, offset, 2, ENC_BIG_ENDIAN, &num_key_pkt);
    offset += 2;
    proto_tree_add_item(tree, hf_isakmp_reserved, tvb, offset, 2, ENC_NA);
    offset += 2;
    while ((num_key_pkt > 0) && (offset_end > offset)) {
      kd_item = proto_tree_add_item(tree, hf_isakmp_kd_payload, tvb, offset, tvb_get_ntohs(tvb, offset + 2), ENC_NA);
      payload_tree = proto_item_add_subtree(kd_item, ett_isakmp_kd);
      proto_tree_add_item(payload_tree, hf_isakmp_kdp_type, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
      proto_tree_add_item(payload_tree, hf_isakmp_reserved, tvb, offset, 1, ENC_NA);
      offset += 1;
      proto_tree_add_item_ret_uint(payload_tree, hf_isakmp_kdp_length, tvb, offset, 2, ENC_BIG_ENDIAN, &kdp_length);
      payload_end = offset + kdp_length -2;
      offset += 2;
      proto_tree_add_item_ret_uint(payload_tree, hf_isakmp_kdp_spi_size, tvb, offset, 1, ENC_BIG_ENDIAN, &kdp_spi_size);
      offset += 1;
      if (kdp_spi_size > 0) {
        proto_tree_add_item(payload_tree, hf_isakmp_kdp_spi, tvb, offset, kdp_spi_size, ENC_NA);
        offset += kdp_spi_size;
      }
      while (offset < payload_end) {
        offset += dissect_tek_key_attribute(tvb, pinfo, payload_tree, offset);
      }
      num_key_pkt -= 1;
    }

  } else {
    /* TODO: For IKEv2: currently only draft status: draft-yeung-g-ikev2-15 */
    /* Skip dissection for unknown IKE versions. */
    return;
  }
}

static void
dissect_sequence(tvbuff_t *tvb, packet_info *pinfo, int offset, int length, proto_tree *tree)
{
  if (length != 4) {
    proto_tree_add_expert_format(tree, pinfo, &ei_isakmp_payload_bad_length, tvb, 0, 0,
                                 "Payload (bogus, length is %u, should be 4", length);
    return;
  }
  proto_tree_add_item(tree, hf_isakmp_seq_seq, tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void
dissect_nat_discovery(tvbuff_t *tvb, int offset, int length, proto_tree *tree )
{
  proto_tree_add_item(tree, hf_isakmp_nat_hash, tvb, offset, length, ENC_NA);
}

static void
dissect_nat_original_address(tvbuff_t *tvb, int offset, int length _U_, proto_tree *tree, int isakmp_version)
{
  guint8 id_type;

  id_type = tvb_get_guint8(tvb, offset);
  if (isakmp_version == 1)
  {
     proto_tree_add_item(tree, hf_isakmp_id_type_v1, tvb, offset, 1, ENC_BIG_ENDIAN);
  }else if (isakmp_version == 2)
  {
     proto_tree_add_item(tree, hf_isakmp_id_type_v2, tvb, offset, 1, ENC_BIG_ENDIAN);
  }
  offset += 1;

  offset += 3;          /* reserved */

  switch (id_type) {

  case IKE_ID_IPV4_ADDR:
    proto_tree_add_item(tree, hf_isakmp_nat_original_address_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
    break;

  case IKE_ID_IPV6_ADDR:
    proto_tree_add_item(tree, hf_isakmp_nat_original_address_ipv6, tvb, offset, 16, ENC_NA);
    break;

  default:
    break;
  }
}

static int
dissect_ts(tvbuff_t *tvb, int offset, proto_tree *payload_tree)
{
  guint8        tstype, protocol_id;
  guint16       len;
  proto_item    *ts_item;
  proto_tree    *tree;
  const gchar   *ts_typename;

  len = tvb_get_guint16(tvb, offset + 2, ENC_BIG_ENDIAN);
  if (len < 4)
    return 4;

  ts_item = proto_tree_add_item(payload_tree, hf_isakmp_ts_data, tvb, offset, len, ENC_NA);
  tree = proto_item_add_subtree(ts_item, ett_isakmp_ts);

  tstype = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_isakmp_ts_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  ts_typename = rval_to_str(tstype, traffic_selector_type, "Unknown Type (%d)");
  proto_item_append_text(ts_item, ": %s", ts_typename);

  offset += 1;

  switch (tstype) {
  case IKEV2_TS_IPV4_ADDR_RANGE:
    protocol_id = tvb_get_guint8(tvb, offset);
    if (protocol_id == 0)
        proto_tree_add_uint_format_value(tree, hf_isakmp_ts_protoid, tvb, offset,1,
                           protocol_id, "Unused");
    else
        proto_tree_add_item(tree, hf_isakmp_ts_protoid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_isakmp_ts_selector_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_isakmp_ts_start_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_isakmp_ts_end_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_isakmp_ts_start_addr_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_isakmp_ts_end_addr_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
    break;

  case IKEV2_TS_IPV6_ADDR_RANGE:
    protocol_id = tvb_get_guint8(tvb, offset);
    if (protocol_id == 0)
        proto_tree_add_uint_format_value(tree, hf_isakmp_ts_protoid, tvb, offset,1,
                           protocol_id, "Unused");
    else
        proto_tree_add_item(tree, hf_isakmp_ts_protoid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_isakmp_ts_selector_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_isakmp_ts_start_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_isakmp_ts_end_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_isakmp_ts_start_addr_ipv6, tvb, offset, 16, ENC_NA);
    offset += 16;

    proto_tree_add_item(tree, hf_isakmp_ts_end_addr_ipv6, tvb, offset, 16, ENC_NA);
    break;

  case IKEV2_TS_FC_ADDR_RANGE:
    proto_tree_add_item(tree, hf_isakmp_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_isakmp_ts_selector_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_isakmp_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_isakmp_ts_start_addr_fc, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    proto_tree_add_item(tree, hf_isakmp_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_isakmp_ts_end_addr_fc, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    proto_tree_add_item(tree, hf_isakmp_ts_start_r_ctl, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_isakmp_ts_end_r_ctl, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_isakmp_ts_start_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_isakmp_ts_end_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    break;
  }

  return len;
}

static void
dissect_ts_payload(tvbuff_t *tvb, int offset, int length, proto_tree *tree)
{
  guint8        num;
  int           offset_end = offset + length;

  num = tvb_get_guint8(tvb, offset);
  proto_item_append_text(tree," # %d", num);
  proto_tree_add_item(tree, hf_isakmp_ts_number_of_ts, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(tree, hf_isakmp_reserved, tvb, offset, 3, ENC_NA);
  offset += 3;

  while (offset < offset_end) {
    offset += dissect_ts(tvb, offset, tree);
  }
}

/* For IKEv2, decrypt payload if necessary and dissect using inner_payload */
/* For RFC 7383 reassembly, only need decrypted payload, so don't set dissect_payload_now .*/
/* TODO: rename? */
static tvbuff_t*
dissect_enc(tvbuff_t *tvb,
            int offset,
            int length,
            proto_tree *tree,
            packet_info *pinfo,
            guint8 inner_payload,
            gboolean is_request,
            void* decr_info,
            gboolean dissect_payload_now)
{
  ikev2_decrypt_data_t *key_info = NULL;
  gint iv_len, encr_data_len, icd_len, decr_data_len, md_len, icv_len, encr_key_len, encr_iv_len;
  guint8 pad_len;
  guchar *iv = NULL, *encr_data = NULL, *decr_data = NULL, *entire_message = NULL, *md = NULL, *encr_iv = NULL;
  gcry_cipher_hd_t cipher_hd;
  gcry_md_hd_t md_hd;
  gcry_error_t err = 0;
  proto_item *item = NULL, *icd_item = NULL, *encr_data_item = NULL, *padlen_item = NULL, *iv_item = NULL;
  tvbuff_t *decr_tvb = NULL;
  gint payloads_len;
  proto_tree *decr_tree = NULL, *decr_payloads_tree = NULL;
  guchar *aa_data = NULL, *icv_data = NULL;
  gint aad_len = 0;

  if (decr_info) {
    /* Need decryption details to know field lengths. */
    key_info = (ikev2_decrypt_data_t*)(decr_info);

    /* Check if encr/auth specs are set properly (if for some case not, wireshark would crash) */
    if (!key_info->encr_spec || !key_info->auth_spec) {
      REPORT_DISSECTOR_BUG("IKEv2: decryption/integrity specs not set-up properly: encr_spec: %p, auth_spec: %p",
        (void *)key_info->encr_spec, (void*)key_info->auth_spec);
    }

    iv_len = key_info->encr_spec->iv_len;
    icv_len = key_info->encr_spec->icv_len;
    icd_len = icv_len ? icv_len : (gint)key_info->auth_spec->trunc_len;
    encr_data_len = length - iv_len - icd_len;
    encr_key_len = key_info->encr_spec->key_len;
    encr_iv_len = iv_len;

    /*
     * Zero or negative length of encrypted data shows that the user specified
     * wrong encryption algorithm and/or authentication algorithm.
     */
    if (encr_data_len <= 0) {
      proto_tree_add_expert(tree, pinfo, &ei_isakmp_enc_iv, tvb, offset, length);
      return NULL;
    }

    /*
     * Add the IV to the tree and store it in a packet scope buffer for later decryption
     * if the specified encryption algorithm uses IV.
     */
    if (iv_len) {
      if (dissect_payload_now) {
        iv_item = proto_tree_add_item(tree, hf_isakmp_enc_iv, tvb, offset, iv_len, ENC_NA);
        proto_item_append_text(iv_item, " (%d bytes)", iv_len);
      }
      iv = (guchar *)tvb_memdup(pinfo->pool, tvb, offset, iv_len);
      encr_iv = iv;

      offset += iv_len;
    }

    /*
     * Add the encrypted portion to the tree and store it in a packet scope buffer for later decryption.
     */
    if (dissect_payload_now) {
      encr_data_item = proto_tree_add_item(tree, hf_isakmp_enc_data, tvb, offset, encr_data_len, ENC_NA);
      proto_item_append_text(encr_data_item, " (%d bytes)",encr_data_len);
      proto_item_append_text(encr_data_item, " <%s>", val_to_str(key_info->encr_spec->number, vs_ikev2_encr_algs, "Unknown cipher: %d"));
    }
    encr_data = (guchar *)tvb_memdup(pinfo->pool, tvb, offset, encr_data_len);
    offset += encr_data_len;

    /*
     * Add the ICD (Integrity Checksum Data) to the tree before decryption to ensure
     * the ICD be displayed even if the decryption fails.
     */
    if (icd_len) {
      icd_item = proto_tree_add_item(tree, hf_isakmp_enc_icd, tvb, offset, icd_len, ENC_NA);
      proto_item_append_text(icd_item, " (%d bytes)",icd_len);

      /*
       * Recalculate ICD value if the specified authentication algorithm allows it.
       */
      if (icv_len) {
        /* For GCM/CCM algorithms ICD is computed during decryption.
          Must save offset and length of authenticated additional data (whole ISAKMP header
          without iv and encrypted data) and ICV for later verification */
        aad_len = offset - iv_len - encr_data_len;
        aa_data = (guchar *)tvb_memdup(pinfo->pool, tvb, 0, aad_len);
        icv_data = (guchar *)tvb_memdup(pinfo->pool, tvb, offset, icv_len);
      } else
      if (key_info->auth_spec->gcry_alg) {
        proto_item_append_text(icd_item, " <%s>", val_to_str(key_info->auth_spec->number, vs_ikev2_auth_algs, "Unknown mac algo: %d"));
        err = gcry_md_open(&md_hd, key_info->auth_spec->gcry_alg, key_info->auth_spec->gcry_flag);
        if (err) {
          REPORT_DISSECTOR_BUG("IKEv2 hashing error: algorithm %d: gcry_md_open failed: %s",
            key_info->auth_spec->gcry_alg, gcry_strerror(err));
        }
        err = gcry_md_setkey(md_hd, key_info->auth_key, key_info->auth_spec->key_len);
        if (err) {
          gcry_md_close(md_hd);
          REPORT_DISSECTOR_BUG("IKEv2 hashing error: algorithm %s, key length %u: gcry_md_setkey failed: %s",
            gcry_md_algo_name(key_info->auth_spec->gcry_alg), key_info->auth_spec->key_len, gcry_strerror(err));
        }

        /* Calculate hash over the bytes from the beginning of the ISAKMP header to the right before the ICD. */
        entire_message = (guchar *)tvb_memdup(pinfo->pool, tvb, 0, offset);
        gcry_md_write(md_hd, entire_message, offset);
        md = gcry_md_read(md_hd, 0);
        md_len = gcry_md_get_algo_dlen(key_info->auth_spec->gcry_alg);
        if (md_len < icd_len) {
          gcry_md_close(md_hd);
          REPORT_DISSECTOR_BUG("IKEv2 hashing error: algorithm %s: gcry_md_get_algo_dlen returned %d which is smaller than icd length %d",
            gcry_md_algo_name(key_info->auth_spec->gcry_alg), md_len, icd_len);
        }
        if (tvb_memeql(tvb, offset, md, icd_len) == 0) {
          proto_item_append_text(icd_item, "[correct]");
        } else {
          proto_item_append_text(icd_item, "[incorrect, should be %s]", bytes_to_str(pinfo->pool, md, icd_len));
          expert_add_info(pinfo, icd_item, &ei_isakmp_ikev2_integrity_checksum);
        }
        gcry_md_close(md_hd);
      } else {
        proto_item_append_text(icd_item, "[not validated]");
      }
    }

    /*
     * Confirm encrypted data length is multiple of block size.
     */
    if (encr_data_len % key_info->encr_spec->block_len != 0) {
      proto_item_append_text(encr_data_item, "[Invalid length, should be a multiple of block size (%u)]",
                             key_info->encr_spec->block_len);
      expert_add_info(pinfo, encr_data_item, &ei_isakmp_enc_data_length_mult_block_size);
      return NULL;
    }

    /*
     * Allocate buffer for decrypted data.
     */
    decr_data = (guchar*)wmem_alloc(pinfo->pool, encr_data_len);
    decr_data_len = encr_data_len;

    /*
     * If the cipher is NULL, just copy the encrypted data to the decrypted data buffer.
     * And otherwise perform decryption with libgcrypt.
     */
    if (key_info->encr_spec->number == IKEV2_ENCR_NULL) {
      memcpy(decr_data, encr_data, decr_data_len);
    } else {
      err = gcry_cipher_open(&cipher_hd, key_info->encr_spec->gcry_alg, key_info->encr_spec->gcry_mode, 0);
      if (err) {
        REPORT_DISSECTOR_BUG("IKEv2 decryption error: algorithm %d, mode %d: gcry_cipher_open failed: %s",
          key_info->encr_spec->gcry_alg, key_info->encr_spec->gcry_mode, gcry_strerror(err));
      }

      /* Handling CTR mode and AEAD ciphers */
      if( key_info->encr_spec->salt_len ) {
        int encr_iv_offset  = 0;
        encr_key_len = key_info->encr_spec->key_len - key_info->encr_spec->salt_len;
        encr_iv_len = key_info->encr_spec->salt_len + iv_len;
        if (key_info->encr_spec->gcry_mode == GCRY_CIPHER_MODE_CTR) {
          encr_iv_len = (int)gcry_cipher_get_algo_blklen(key_info->encr_spec->gcry_alg);
          if ((key_info->encr_spec->number >= IKEV2_ENCR_AES_CCM_128_16 && key_info->encr_spec->number <= IKEV2_ENCR_AES_CCM_256_12))
            encr_iv_offset = 1;
        }

        if (encr_key_len < 0 || encr_iv_len < encr_iv_offset + (int)key_info->encr_spec->salt_len + iv_len) {
          gcry_cipher_close(cipher_hd);
          REPORT_DISSECTOR_BUG("IKEv2 decryption error: algorithm %d, key length %d, salt length %d, input iv length %d, cipher iv length: %d: invalid length(s) of cipher parameters",
            key_info->encr_spec->gcry_alg, encr_key_len, key_info->encr_spec->salt_len, iv_len, encr_iv_len);
        }

        encr_iv = (guchar *)wmem_alloc0(pinfo->pool, encr_iv_len);
        memcpy( encr_iv + encr_iv_offset, key_info->encr_key + encr_key_len, key_info->encr_spec->salt_len );
        if(iv) {
          memcpy( encr_iv + encr_iv_offset + key_info->encr_spec->salt_len, iv, iv_len );
        }
        if (key_info->encr_spec->gcry_mode == GCRY_CIPHER_MODE_CTR) {
          encr_iv[encr_iv_len-1] = 1;
          /* fallback for gcrypt not having AEAD ciphers */
          if ((key_info->encr_spec->number >= IKEV2_ENCR_AES_GCM_128_16 && key_info->encr_spec->number <= IKEV2_ENCR_AES_GCM_256_12))
            encr_iv[encr_iv_len-1]++;
          if ((key_info->encr_spec->number >= IKEV2_ENCR_AES_CCM_128_16 && key_info->encr_spec->number <= IKEV2_ENCR_AES_CCM_256_12))
            encr_iv[0] = (guchar)(encr_iv_len - 2 - key_info->encr_spec->salt_len - iv_len);
        }
      }

      err = gcry_cipher_setkey(cipher_hd, key_info->encr_key, encr_key_len);
      if (err) {
        REPORT_DISSECTOR_BUG("IKEv2 decryption error: algorithm %d, key length %d:  gcry_cipher_setkey failed: %s",
          key_info->encr_spec->gcry_alg, encr_key_len, gcry_strerror(err));
      }
      if (key_info->encr_spec->gcry_mode == GCRY_CIPHER_MODE_CTR)
        err = gcry_cipher_setctr(cipher_hd, encr_iv, encr_iv_len);
      else
        err = gcry_cipher_setiv(cipher_hd, encr_iv, encr_iv_len);
      if (err) {
        REPORT_DISSECTOR_BUG("IKEv2 decryption error: algorithm %d, iv length %d:  gcry_cipher_setiv/gcry_cipher_setctr failed: %s",
          key_info->encr_spec->gcry_alg, encr_iv_len, gcry_strerror(err));
      }

      if (key_info->encr_spec->gcry_mode == GCRY_CIPHER_MODE_CCM) {
        guint64 ccm_lengths[3];
        ccm_lengths[0] = encr_data_len;
        ccm_lengths[1] = aad_len;
        ccm_lengths[2] = icv_len;

        err = gcry_cipher_ctl(cipher_hd, GCRYCTL_SET_CCM_LENGTHS, ccm_lengths, sizeof(ccm_lengths));
        if (err) {
          gcry_cipher_close(cipher_hd);
          REPORT_DISSECTOR_BUG("IKEv2 decryption error: algorithm %d:  gcry_cipher_ctl(GCRYCTL_SET_CCM_LENGTHS) failed: %s",
            key_info->encr_spec->gcry_alg, gcry_strerror(err));
        }
      }

      if (aad_len) {
        err = gcry_cipher_authenticate(cipher_hd, aa_data, aad_len);
        if (err) {
          gcry_cipher_close(cipher_hd);
          REPORT_DISSECTOR_BUG("IKEv2 decryption error: algorithm %d:  gcry_cipher_authenticate failed: %s",
            key_info->encr_spec->gcry_alg, gcry_strerror(err));
        }
      }

      err = gcry_cipher_decrypt(cipher_hd, decr_data, decr_data_len, encr_data, encr_data_len);
      if (err) {
        gcry_cipher_close(cipher_hd);
        REPORT_DISSECTOR_BUG("IKEv2 decryption error: algorithm %d:  gcry_cipher_decrypt failed: %s",
          key_info->encr_spec->gcry_alg, gcry_strerror(err));
      }

      if (icv_len) {
        /* gcry_cipher_checktag() doesn't work on 1.6.x version well - requires all of 16 bytes
         * of ICV, so it won't work with 12 and 8 bytes of ICV.
         * For 1.7.x version of libgcrypt we could use it safely. But for libgcrypt-1.6.x
         * we need to read tag from library and compare manually. Using that way we can also show
         * correct value if it is not valid.
         * CCM mode is not affected, but requires to pass icv_len to cry_cipher_gettag().
         *
         * Unfortunately gcrypt_cipher_gettag() have nothing similar to gcry_md_read(),
         * so we need copy data to buffer here.
         * Here, depending on cgrypt version gcm length shall be given differently:
         * - in 1.7.x length can be of any aproved length (4,8,12,13,14,15,16 bytes),
         * - in 1.6.x length must be equal of cipher block length. Aaargh... :-(
         * We use accepted for both versions length of block size for GCM (16 bytes).
         * For CCM length given must be the same as given to gcry_cipher_ctl(GCRYCTL_SET_CCM_LENGTHS)
         *
         * XXX: We now require libgcrypt 1.8.0, so presumably this could
         * be updated?
         */
        guchar *tag;
        gint tag_len = icv_len;
        if (key_info->encr_spec->gcry_mode == GCRY_CIPHER_MODE_GCM)
          tag_len = (int)gcry_cipher_get_algo_blklen(key_info->encr_spec->gcry_alg);

        if (tag_len < icv_len) {
          gcry_cipher_close(cipher_hd);
          REPORT_DISSECTOR_BUG("IKEv2 decryption error: algorithm %d:  gcry_cipher_get_algo_blklen returned %d which is smaller than icv length %d",
            key_info->encr_spec->gcry_alg, tag_len, icv_len);
        }

        tag = (guchar *)wmem_alloc(pinfo->pool, tag_len);
        err = gcry_cipher_gettag(cipher_hd, tag, tag_len);
        if (err) {
          gcry_cipher_close(cipher_hd);
          REPORT_DISSECTOR_BUG("IKEv2 decryption error: algorithm %d:  gcry_cipher_gettag failed: %s",
            key_info->encr_spec->gcry_alg, gcry_strerror(err));
        }
        else if (memcmp(tag, icv_data, icv_len) == 0)
          proto_item_append_text(icd_item, "[correct]");
        else {
          proto_item_append_text(icd_item, "[incorrect, should be %s]", bytes_to_str(pinfo->pool, tag, icv_len));
          expert_add_info(pinfo, icd_item, &ei_isakmp_ikev2_integrity_checksum);
        }
      }

      gcry_cipher_close(cipher_hd);
    }

    decr_tvb = tvb_new_child_real_data(tvb, decr_data, decr_data_len, decr_data_len);
    add_new_data_source(pinfo, decr_tvb, "Decrypted Data");
    item = proto_tree_add_item(tree, hf_isakmp_enc_decrypted_data, decr_tvb, 0, decr_data_len, ENC_NA);
    proto_item_append_text(item, " (%d byte%s)", decr_data_len, plurality(decr_data_len, "", "s"));

    /* Move the ICD item to the bottom of the tree. */
    if (icd_item) {
      proto_tree_move_item(tree, item, icd_item);
    }
    decr_tree = proto_item_add_subtree(item, ett_isakmp_decrypted_data);

    pad_len = tvb_get_guint8(decr_tvb, decr_data_len - 1);
    payloads_len = decr_data_len - 1 - pad_len;

    if (payloads_len > 0) {
      item = proto_tree_add_item(decr_tree, hf_isakmp_enc_contained_data, decr_tvb, 0, payloads_len, ENC_NA);
      proto_item_append_text(item, " (%d byte%s)", payloads_len, plurality(payloads_len, "", "s"));
      decr_payloads_tree = proto_item_add_subtree(item, ett_isakmp_decrypted_payloads);
    }

    padlen_item = proto_tree_add_item(decr_tree, hf_isakmp_enc_pad_length, decr_tvb, payloads_len + pad_len, 1, ENC_BIG_ENDIAN);
    if (pad_len > 0) {
      if (payloads_len < 0) {
        proto_item_append_text(padlen_item, " [too long]");
        expert_add_info(pinfo, padlen_item, &ei_isakmp_enc_pad_length_big);
      } else {
        item = proto_tree_add_item(decr_tree, hf_isakmp_enc_padding, decr_tvb, payloads_len, pad_len, ENC_NA);
        proto_item_append_text(item, " (%d byte%s)", pad_len, plurality(pad_len, "", "s"));
        proto_tree_move_item(decr_tree, item, padlen_item);
      }
    }

    /*
     * We dissect the inner payloads at last in order to ensure displaying Padding, Pad Length and ICD
     * even if the dissection fails. This may occur when the user specify wrong encryption key.
     */
    if (dissect_payload_now) {
      dissect_payloads(decr_tvb, decr_payloads_tree, 2, inner_payload, 0, payloads_len, pinfo, 0, is_request, decr_info);
    }
  }else{
     proto_tree_add_item(tree, hf_isakmp_enc_iv, tvb, offset, 4, ENC_NA);
     proto_tree_add_item(tree, hf_isakmp_enc_data, tvb, offset+4 , length, ENC_NA);
  }
  return decr_tvb;
}

static void
dissect_eap(tvbuff_t *tvb, int offset, int length, proto_tree *tree, packet_info *pinfo)
{
  tvbuff_t *eap_tvb;

  eap_tvb = tvb_new_subset_length(tvb, offset, length);
  if ((eap_tvb != NULL)&& eap_handle != NULL){
    call_dissector(eap_handle, eap_tvb, pinfo, tree);
  }else{
    proto_tree_add_item(tree, hf_isakmp_eap_data, tvb, offset, length, ENC_NA);
  }
}

static void
dissect_gspm(tvbuff_t *tvb, int offset, int length, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_isakmp_gspm_data, tvb, offset, length, ENC_NA);

}

/*
 * Protocol initialization
 */

static guint
isakmp_hash_func(gconstpointer c) {
  const guint8 *i_cookie = (const guint8 *) c;
  guint   val = 0, keychunk, i;

  /* XOR our icookie down to the size of a guint */
  for (i = 0; i < COOKIE_SIZE - (COOKIE_SIZE % (guint)sizeof(keychunk)); i += (guint)sizeof(keychunk)) {
    memcpy(&keychunk, &i_cookie[i], sizeof(keychunk));
    val ^= keychunk;
  }

  return val;
}

static gint
isakmp_equal_func(gconstpointer ic1, gconstpointer ic2) {

  if (memcmp(ic1, ic2, COOKIE_SIZE) == 0)
    return 1;

  return 0;
}

static guint ikev2_key_hash_func(gconstpointer k) {
  const ikev2_uat_data_key_t *key = (const ikev2_uat_data_key_t*)k;
  guint hash, *key_segs;
  size_t key_segcount, i;

  hash = 0;

  /*
   * XOR our icookie down to the size of a guint.
   *
   * The cast to guint suppresses a warning 64-bit-to-32-bit narrowing
   * from some buggy C compilers (I'm looking at *you*,
   * i686-apple-darwin11-llvm-gcc-4.2 (GCC) 4.2.1
   * (Based on Apple Inc. build 5658) (LLVM build 2336.11.00).)
   */
  key_segcount = key->spii_len / (guint)sizeof(guint);
  key_segs = (guint *)key->spii;
  for (i = 0; i < key_segcount; i++) {
    hash ^= key_segs[i];
  }
  key_segcount = key->spir_len / (guint)sizeof(guint);
  key_segs = (guint *)key->spir;
  for (i = 0; i < key_segcount; i++) {
    hash ^= key_segs[i];
  }

  return hash;
}

static gint ikev2_key_equal_func(gconstpointer k1, gconstpointer k2) {
  const ikev2_uat_data_key_t *key1 = (const ikev2_uat_data_key_t *)k1;
  const ikev2_uat_data_key_t *key2 = (const ikev2_uat_data_key_t *)k2;
  if (key1->spii_len != key2->spii_len) return 0;
  if (key1->spir_len != key2->spir_len) return 0;
  if (memcmp(key1->spii, key2->spii, key1->spii_len) != 0) return 0;
  if (memcmp(key1->spir, key2->spir, key1->spir_len) != 0) return 0;

  return 1;
}

static void
free_cookie_key(gpointer key_arg)
{
  guint8 *ic_key = (guint8 *)key_arg;

  g_slice_free1(COOKIE_SIZE, ic_key);
}

static void
free_cookie_value(gpointer value)
{
  decrypt_data_t *decr = (decrypt_data_t *)value;

  g_free(decr->gi);
  g_free(decr->gr);
  g_hash_table_destroy(decr->iv_hash);
  g_slice_free1(sizeof(decrypt_data_t), decr);
}

static void
isakmp_init_protocol(void) {
  guint i;
  decrypt_data_t *decr;
  guint8   *ic_key;
  isakmp_hash = g_hash_table_new_full(isakmp_hash_func, isakmp_equal_func,
      free_cookie_key, free_cookie_value);

  for (i = 0; i < num_ikev1_uat_data; i++) {
    ic_key = (guint8 *)g_slice_alloc(COOKIE_SIZE);
    memcpy(ic_key, ikev1_uat_data[i].icookie, COOKIE_SIZE);

    decr = create_decrypt_data();
    memcpy(decr->secret, ikev1_uat_data[i].key, ikev1_uat_data[i].key_len);
    decr->secret_len = ikev1_uat_data[i].key_len;

    g_hash_table_insert(isakmp_hash, ic_key, decr);
  }
  ikev2_key_hash = g_hash_table_new(ikev2_key_hash_func, ikev2_key_equal_func);
  for (i = 0; i < num_ikev2_uat_data; i++) {
    g_hash_table_insert(ikev2_key_hash, &(ikev2_uat_data[i].key), &(ikev2_uat_data[i]));
    /* Need find references to algorithms (as UAT table editing looses data not stored in file) */
    ikev2_uat_data[i].encr_spec = ikev2_decrypt_find_encr_spec(ikev2_uat_data[i].encr_alg);
    ikev2_uat_data[i].auth_spec = ikev2_decrypt_find_auth_spec(ikev2_uat_data[i].auth_alg);
  }
  defrag_next_payload_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
}

static void
isakmp_cleanup_protocol(void) {
  g_hash_table_destroy(isakmp_hash);
  g_hash_table_destroy(ikev2_key_hash);
  g_hash_table_destroy(defrag_next_payload_hash);
}

UAT_BUFFER_CB_DEF(ikev1_users, icookie, ikev1_uat_data_key_t, icookie, icookie_len)
UAT_BUFFER_CB_DEF(ikev1_users, key, ikev1_uat_data_key_t, key, key_len)

static gboolean ikev1_uat_data_update_cb(void* p, char** err) {
  ikev1_uat_data_key_t *ud = (ikev1_uat_data_key_t *)p;

  if (ud->icookie_len != COOKIE_SIZE) {
    *err = ws_strdup_printf("Length of Initiator's COOKIE must be %d octets (%d hex characters).", COOKIE_SIZE, COOKIE_SIZE * 2);
    return FALSE;
  }

  if (ud->key_len == 0) {
    *err = g_strdup("Must have Encryption key.");
    return FALSE;
  }

  if (ud->key_len > MAX_KEY_SIZE) {
    *err = ws_strdup_printf("Length of Encryption key limited to %d octets (%d hex characters).", MAX_KEY_SIZE, MAX_KEY_SIZE * 2);
    return FALSE;
  }

  return TRUE;
}

static void*
ikev1_uat_data_copy_cb(void *dest, const void *source, size_t len _U_)
{
  const ikev1_uat_data_key_t* o = (const ikev1_uat_data_key_t*)source;
  ikev1_uat_data_key_t* d = (ikev1_uat_data_key_t*)dest;

  d->icookie = (guchar *)g_memdup2(o->icookie, o->icookie_len);
  d->icookie_len = o->icookie_len;
  d->key = (guchar *)g_memdup2(o->key, o->key_len);
  d->key_len = o->key_len;

  return dest;
}

static void
ikev1_uat_data_free_cb(void *r)
{
  ikev1_uat_data_key_t *rec = (ikev1_uat_data_key_t *)r;
  g_free(rec->icookie);
  g_free(rec->key);
}

UAT_BUFFER_CB_DEF(ikev2_users, spii, ikev2_uat_data_t, key.spii, key.spii_len)
UAT_BUFFER_CB_DEF(ikev2_users, spir, ikev2_uat_data_t, key.spir, key.spir_len)
UAT_BUFFER_CB_DEF(ikev2_users, sk_ei, ikev2_uat_data_t, sk_ei, sk_ei_len)
UAT_BUFFER_CB_DEF(ikev2_users, sk_er, ikev2_uat_data_t, sk_er, sk_er_len)
UAT_VS_DEF(ikev2_users, encr_alg, ikev2_uat_data_t, guint, IKEV2_ENCR_3DES, IKEV2_ENCR_3DES_STR)
UAT_BUFFER_CB_DEF(ikev2_users, sk_ai, ikev2_uat_data_t, sk_ai, sk_ai_len)
UAT_BUFFER_CB_DEF(ikev2_users, sk_ar, ikev2_uat_data_t, sk_ar, sk_ar_len)
UAT_VS_DEF(ikev2_users, auth_alg, ikev2_uat_data_t, guint, IKEV2_AUTH_HMAC_SHA1_96, IKEV2_AUTH_HMAC_SHA1_96_STR)

static void*
ikev2_uat_data_copy_cb(void *dest, const void *source, size_t len _U_)
{
  const ikev2_uat_data_t* o = (const ikev2_uat_data_t*)source;
  ikev2_uat_data_t* d = (ikev2_uat_data_t*)dest;

  d->key.spii = (guchar *)g_memdup2(o->key.spii, o->key.spii_len);
  d->key.spii_len = o->key.spii_len;

  d->key.spir = (guchar *)g_memdup2(o->key.spir, o->key.spir_len);
  d->key.spir_len = o->key.spir_len;

  d->encr_alg = o->encr_alg;
  d->auth_alg = o->auth_alg;

  d->sk_ei = (guchar *)g_memdup2(o->sk_ei, o->sk_ei_len);
  d->sk_ei_len = o->sk_ei_len;

  d->sk_er = (guchar *)g_memdup2(o->sk_er, o->sk_er_len);
  d->sk_er_len = o->sk_er_len;

  d->sk_ai = (guchar *)g_memdup2(o->sk_ai, o->sk_ai_len);
  d->sk_ai_len = o->sk_ai_len;

  d->sk_ar = (guchar *)g_memdup2(o->sk_ar, o->sk_ar_len);
  d->sk_ar_len = o->sk_ar_len;

  d->encr_spec = (ikev2_encr_alg_spec_t *)g_memdup2(o->encr_spec, sizeof(ikev2_encr_alg_spec_t));
  d->auth_spec = (ikev2_auth_alg_spec_t *)g_memdup2(o->auth_spec, sizeof(ikev2_auth_alg_spec_t));

  return dest;
}

static gboolean ikev2_uat_data_update_cb(void* p, char** err) {
  ikev2_uat_data_t *ud = (ikev2_uat_data_t *)p;

  if (ud->key.spii_len != COOKIE_SIZE) {
    *err = ws_strdup_printf("Length of Initiator's SPI must be %d octets (%d hex characters).", COOKIE_SIZE, COOKIE_SIZE * 2);
    return FALSE;
  }

  if (ud->key.spir_len != COOKIE_SIZE) {
    *err = ws_strdup_printf("Length of Responder's SPI must be %d octets (%d hex characters).", COOKIE_SIZE, COOKIE_SIZE * 2);
    return FALSE;
  }

  if ((ud->encr_spec = ikev2_decrypt_find_encr_spec(ud->encr_alg)) == NULL) {
    REPORT_DISSECTOR_BUG("Couldn't get IKEv2 encryption algorithm spec.");
  }

  if ((ud->auth_spec = ikev2_decrypt_find_auth_spec(ud->auth_alg)) == NULL) {
    REPORT_DISSECTOR_BUG("Couldn't get IKEv2 authentication algorithm spec.");
  }

  if (ud->encr_spec->icv_len && ud->auth_spec->number != IKEV2_AUTH_NONE) {
    *err = ws_strdup_printf("Selected encryption_algorithm %s requires selecting NONE integrity algorithm.",
             val_to_str(ud->encr_spec->number, vs_ikev2_encr_algs, "other-%d"));
    return FALSE;
  }

  if (ud->sk_ei_len != ud->encr_spec->key_len) {
    *err = ws_strdup_printf("Length of SK_ei (%u octets) does not match the key length (%u octets) of the selected encryption algorithm.",
             ud->sk_ei_len, ud->encr_spec->key_len);
    return FALSE;
  }

  if (ud->sk_er_len != ud->encr_spec->key_len) {
    *err = ws_strdup_printf("Length of SK_er (%u octets) does not match the key length (%u octets) of the selected encryption algorithm.",
             ud->sk_er_len, ud->encr_spec->key_len);
    return FALSE;
  }

  if (ud->sk_ai_len != ud->auth_spec->key_len) {
    *err = ws_strdup_printf("Length of SK_ai (%u octets) does not match the key length (%u octets) of the selected integrity algorithm.",
             ud->sk_ai_len, ud->auth_spec->key_len);
    return FALSE;
  }

  if (ud->sk_ar_len != ud->auth_spec->key_len) {
    *err = ws_strdup_printf("Length of SK_ar (%u octets) does not match the key length (%u octets) of the selected integrity algorithm.",
             ud->sk_ar_len, ud->auth_spec->key_len);
    return FALSE;
  }

  return TRUE;
}

static void
ikev2_uat_data_free_cb(void *r)
{
  ikev2_uat_data_t *rec = (ikev2_uat_data_t *)r;
  g_free(rec->key.spii);
  g_free(rec->key.spir);
  g_free(rec->sk_ei);
  g_free(rec->sk_er);
  g_free(rec->sk_ai);
  g_free(rec->sk_ar);
}

void
proto_register_isakmp(void)
{
  module_t *isakmp_module;
  static hf_register_info hf[] = {
    { &hf_isakmp_ispi,
      { "Initiator SPI", "isakmp.ispi",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "ISAKMP Initiator SPI", HFILL }},
    { &hf_isakmp_rspi,
      { "Responder SPI", "isakmp.rspi",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "ISAKMP Responder SPI", HFILL }},
    { &hf_isakmp_typepayload,
      { "Payload", "isakmp.typepayload",
        FT_UINT8,BASE_RANGE_STRING | BASE_DEC, RVALS(payload_type), 0x0,
        "ISAKMP Payload Type", HFILL }},
    { &hf_isakmp_nextpayload,
      { "Next payload", "isakmp.nextpayload",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(payload_type), 0x0,
        "ISAKMP Next Payload", HFILL }},
    { &hf_isakmp_criticalpayload,
      { "Critical Bit", "isakmp.criticalpayload",
        FT_BOOLEAN, 8,TFS(&tfs_critical_not_critical), 0x80,
        "IKEv2 Critical Payload", HFILL }},
    { &hf_isakmp_reserved7,
      { "Reserved", "isakmp.reserved7",
        FT_UINT8, BASE_HEX, NULL, 0x7F,
        NULL, HFILL }},
    { &hf_isakmp_reserved,
      { "Reserved", "isakmp.reserved",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_extradata,
      { "Extra data", "isakmp.extradata",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Extra data ??????", HFILL }},
    { &hf_isakmp_datapayload,
      { "Data Payload", "isakmp.datapayload",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Data Payload (not dissect)", HFILL }},
    { &hf_isakmp_version,
      { "Version", "isakmp.version",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "ISAKMP Version (major + minor)", HFILL }},
    { &hf_isakmp_mjver,
      { "MjVer", "isakmp.mjver",
        FT_UINT8, BASE_HEX, NULL, 0xF0,
        "ISAKMP MjVer", HFILL }},
    { &hf_isakmp_mnver,
      { "MnVer", "isakmp.mnver",
        FT_UINT8, BASE_HEX, NULL, 0x0F,
        "ISAKMP MnVer", HFILL }},
    { &hf_isakmp_exchangetype_v1,
      { "Exchange type", "isakmp.exchangetype",
        FT_UINT8, BASE_DEC, VALS(exchange_v1_type), 0x0,
        "ISAKMP Exchange Type", HFILL }},
    { &hf_isakmp_exchangetype_v2,
      { "Exchange type", "isakmp.exchangetype",
        FT_UINT8, BASE_DEC, VALS(exchange_v2_type), 0x0,
        "ISAKMP Exchange Type", HFILL }},
    { &hf_isakmp_flags,
      { "Flags", "isakmp.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "ISAKMP Flags", HFILL }},
    { &hf_isakmp_flag_e,
      { "Encryption", "isakmp.flag_e",
        FT_BOOLEAN, 8, TFS(&flag_e), E_FLAG,
        "Encryption Bit", HFILL }},
    { &hf_isakmp_flag_c,
      { "Commit", "isakmp.flag_c",
        FT_BOOLEAN, 8, TFS(&flag_c), C_FLAG,
        "Commit Bit", HFILL }},
    { &hf_isakmp_flag_a,
      { "Authentication", "isakmp.flag_a",
        FT_BOOLEAN, 8, TFS(&flag_a), A_FLAG,
        "Authentication Bit", HFILL }},
    { &hf_isakmp_flag_i,
      { "Initiator", "isakmp.flag_i",
        FT_BOOLEAN, 8, TFS(&flag_i), I_FLAG,
        "Initiator Bit", HFILL }},
    { &hf_isakmp_flag_v,
      { "Version", "isakmp.flag_v",
        FT_BOOLEAN, 8, TFS(&flag_v), V_FLAG,
        "Version Bit", HFILL }},
    { &hf_isakmp_flag_r,
      { "Response", "isakmp.flag_r",
        FT_BOOLEAN, 8, TFS(&tfs_response_request), R_FLAG,
        "Response Bit", HFILL }},
    { &hf_isakmp_messageid,
      { "Message ID", "isakmp.messageid",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "ISAKMP Message ID", HFILL }},
    { &hf_isakmp_length,
      { "Length", "isakmp.length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "ISAKMP Length", HFILL }},
    { &hf_isakmp_payloadlen,
      { "Payload length", "isakmp.payloadlength",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "ISAKMP Payload Length", HFILL }},
    { &hf_isakmp_sa_doi,
      { "Domain of interpretation", "isakmp.sa.doi",
        FT_UINT32, BASE_DEC, VALS(doi_type), 0x0,
        "ISAKMP Domain of Interpretation", HFILL }},
    { &hf_isakmp_sa_situation,
      { "Situation", "isakmp.sa.situation",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "ISAKMP SA Situation", HFILL }},
    { &hf_isakmp_sa_attribute_next_payload,
      { "SA Attribute Next Payload", "isakmp.sa.next_attribute_payload",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Payloads that define specific security association attributes for the KEK and/or TEKs", HFILL }},
    { &hf_isakmp_reserved2,
      { "Reserved2", "isakmp.reserved2",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sa_situation_identity_only,
      { "Identity Only", "isakmp.sa.situation.identity_only",
        FT_BOOLEAN, 32, NULL, SIT_IDENTITY_ONLY,
        "The type specifies that the SA will be identified by source identity information present in an associated Identification Payload", HFILL }},
    { &hf_isakmp_sa_situation_secrecy,
      { "Secrecy", "isakmp.sa.situation.secrecy",
        FT_BOOLEAN, 32, NULL, SIT_SECRECY,
        "The type specifies that the SA is being negotiated in an environment that requires labeled secrecy.", HFILL }},
    { &hf_isakmp_sa_situation_integrity,
      { "Integrity", "isakmp.sa.situation.integrity",
        FT_BOOLEAN, 32, NULL, SIT_INTEGRITY,
        "The type specifies that the SA is being negotiated in an environment that requires labeled integrity", HFILL }},
    { &hf_isakmp_prop_protoid_v1,
      { "Protocol ID", "isakmp.prop.protoid",
        FT_UINT32, BASE_DEC, VALS(protoid_v1_type), 0x0,
        "ISAKMP Proposal Protocol ID", HFILL }},
    { &hf_isakmp_prop_protoid_v2,
      { "Protocol ID", "isakmp.prop.protoid",
        FT_UINT32, BASE_DEC, VALS(protoid_v2_type), 0x0,
        "IKEv2 Proposal Protocol ID", HFILL }},
    { &hf_isakmp_prop_number,
      { "Proposal number", "isakmp.prop.number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP Proposal Number", HFILL }},
    { &hf_isakmp_spisize,
      { "SPI Size", "isakmp.spisize",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_spi,
      { "SPI", "isakmp.spi",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_prop_transforms,
      { "Proposal transforms", "isakmp.prop.transforms",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP Proposal Transforms", HFILL }},
    { &hf_isakmp_trans_number,
      { "Transform number", "isakmp.trans.number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP Transform Number", HFILL }},
    { &hf_isakmp_trans_id,
      { "Transform ID", "isakmp.trans.id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP Transform ID", HFILL }},
    { &hf_isakmp_id_type_v1,
      { "ID type", "isakmp.id.type",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(vs_v1_id_type), 0x0,
        "IKEv1 ID Type", HFILL }},
    { &hf_isakmp_id_type_v2,
      { "ID type", "isakmp.id.type",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(vs_v2_id_type), 0x0,
        "IKEv2 ID Type", HFILL }},
    { &hf_isakmp_id_protoid,
      { "Protocol ID", "isakmp.id.protoid",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ipproto_val_ext, 0x0,
        "ISAKMP ID Protocol ID", HFILL }},
    { &hf_isakmp_id_port,
      { "Port", "isakmp.id.port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "ISAKMP ID Port", HFILL }},
    { &hf_isakmp_id_data,
      { "Identification Data:", "isakmp.id.data",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "ISAKMP ID Data", HFILL }},
    { &hf_isakmp_id_data_ipv4_addr,
      { "ID_IPV4_ADDR", "isakmp.id.data.ipv4_addr",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "The type specifies a single four (4) octet IPv4 address", HFILL }},
    { &hf_isakmp_id_data_fqdn,
      { "ID_FQDN", "isakmp.id.data.fqdn",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "The type specifies a fully-qualified domain name string", HFILL }},
    { &hf_isakmp_id_data_user_fqdn,
      { "ID_FQDN", "isakmp.id.data.user_fqdn",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "The type specifies a fully-qualified username string", HFILL }},
    { &hf_isakmp_id_data_ipv4_subnet,
      { "ID_IPV4_SUBNET", "isakmp.id.data.ipv4_subnet",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "The second is an IPv4 network mask", HFILL }},
    { &hf_isakmp_id_data_ipv4_range_start,
      { "ID_IPV4_RANGE (Start)", "isakmp.id.data.ipv4_range_start",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "The first value is the beginning IPv4 address (inclusive)", HFILL }},
    { &hf_isakmp_id_data_ipv4_range_end,
      { "ID_IPV4_RANGE (End)", "isakmp.id.data.ipv4_range_end",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        "The second value is the ending IPv4 address (inclusive)", HFILL }},
    { &hf_isakmp_id_data_ipv6_addr,
      { "ID_IPV6_ADDR", "isakmp.id.data.ipv6_addr",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        "The type specifies a single sixteen (16) octet IPv6 address", HFILL }},
    { &hf_isakmp_id_data_ipv6_subnet,
      { "ID_IPV6A_ADDR_SUBNET", "isakmp.id.data.ipv6_subnet",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        "The type specifies a range of IPv6 addresses represented by two sixteen (16) octet values", HFILL }},
    { &hf_isakmp_id_data_ipv6_range_start,
      { "ID_IPV6_ADDR_RANGE (Start)", "isakmp.id.data.ipv6_range_start",
        FT_IPv6, BASE_NONE, NULL, 0x0,
       "The first value is the beginning IPv6 address (inclusive)", HFILL }},
    { &hf_isakmp_id_data_ipv6_range_end,
      { "ID_IPV6_ADDR_RANGE (End)", "isakmp.id.data.ipv6_range_end",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        "the second value is the ending IPv6 address (inclusive)", HFILL }},
    { &hf_isakmp_id_data_key_id,
      { "ID_KEY_ID", "isakmp.id.data.key_id",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "The type specifies an opaque byte stream which may be used to pass vendor-specific information necessary to identify which pre-shared key should be used to authenticate Aggressive mode negotiations", HFILL }},
    { &hf_isakmp_id_data_cert,
      { "ID_DER_ASN1_DN", "isakmp.id.data.der_asn1_dn",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },
    { &hf_isakmp_cert_encoding_v1,
      { "Certificate Encoding", "isakmp.cert.encoding",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(cert_v1_type), 0x0,
        "ISAKMP Certificate Encoding", HFILL }},
    { &hf_isakmp_cert_encoding_v2,
      { "Certificate Encoding", "isakmp.cert.encoding",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(cert_v2_type), 0x0,
        "IKEv2 Certificate Encoding", HFILL }},
    { &hf_isakmp_cert_data,
      { "Certificate Data", "isakmp.cert.data",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "ISAKMP Certificate Data", HFILL }},
    { &hf_isakmp_cert_x509_hash,
      { "Hash", "isakmp.cert.x509.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_cert_x509_url,
      { "URL", "isakmp.cert.x509.url",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_certreq_type_v1,
      { "Certificate Type", "isakmp.certreq.type",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(cert_v1_type), 0x0,
        "ISAKMP Certificate Type", HFILL }},
    { &hf_isakmp_certreq_type_v2,
      { "Certificate Type", "isakmp.certreq.type",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(cert_v2_type), 0x0,
        "IKEv2 Certificate Type", HFILL }},
    { &hf_isakmp_auth_meth,
      { "Authentication Method", "isakmp.auth.method",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(authmeth_v2_type), 0x0,
        "IKEv2 Authentication Method", HFILL }},
    { &hf_isakmp_auth_data,
      { "Authentication Data", "isakmp.auth.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "IKEv2 Authentication Data", HFILL }},
    { &hf_isakmp_auth_digital_sig_asn1_len,
      { "ASN.1 Length", "isakmp.auth.data.sig.asn1.len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "IKEv2 Authentication Data Digital Signature ASN.1 Length", HFILL } },
    { &hf_isakmp_auth_digital_sig_asn1_data,
      { "ASN.1 Data", "isakmp.auth.data.sig.asn1.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "IKEv2 Authentication Data Digital Signature ASN.1 Data", HFILL } },
    { &hf_isakmp_auth_digital_sig_value,
      { "Signature Value", "isakmp.auth.data.sig.value",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "IKEv2 Authentication Data Digital Signature Value", HFILL } },
    { &hf_isakmp_notify_doi,
      { "Domain of interpretation", "isakmp.notify.doi",
        FT_UINT32, BASE_DEC, VALS(doi_type), 0x0,
        "ISAKMP Notify Domain of Interpretation", HFILL }},
    { &hf_isakmp_notify_protoid_v1,
      { "Protocol ID", "isakmp.notify.protoid",
        FT_UINT32, BASE_DEC, VALS(protoid_v1_type), 0x0,
        "ISAKMP Notify Protocol ID", HFILL }},
    { &hf_isakmp_notify_protoid_v2,
      { "Protocol ID", "isakmp.notify.protoid",
        FT_UINT32, BASE_DEC, VALS(protoid_v2_type), 0x0,
        "IKEv2 Notify Protocol ID", HFILL }},
    { &hf_isakmp_notify_msgtype_v1,
      { "Notify Message Type", "isakmp.notify.msgtype",
        FT_UINT16, BASE_RANGE_STRING | BASE_DEC, RVALS(notifmsg_v1_type), 0x0,
        "ISAKMP Notify Message Type", HFILL }},
    { &hf_isakmp_notify_msgtype_v2,
      { "Notify Message Type", "isakmp.notify.msgtype",
        FT_UINT16, BASE_RANGE_STRING | BASE_DEC, RVALS(notifmsg_v2_type), 0x0,
        "ISAKMP Notify Message Type", HFILL }},
    { &hf_isakmp_notify_data,
      { "Notification DATA", "isakmp.notify.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_dpd_are_you_there,
      { "DPD ARE-YOU-THERE sequence", "isakmp.notify.data.dpd.are_you_there",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_dpd_are_you_there_ack,
      { "DPD ARE-YOU-THERE-ACK sequence", "isakmp.notify.data.dpd.are_you_there_ack",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_unity_load_balance,
      { "UNITY LOAD BALANCE", "isakmp.notify.data.unity.load_balance",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_accepted_dh_group,
      { "Accepted DH group number", "isakmp.notify.data.accepted_dh_group",
        FT_UINT16, BASE_DEC, VALS(dh_group), 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_ipcomp_cpi,
      { "IPCOMP CPI", "isakmp.notify.data.ipcomp.cpi",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_ipcomp_transform_id,
      { "IPCOMP Transform ID", "isakmp.notify.data.ipcomp.transform_id",
        FT_UINT8, BASE_DEC, VALS(transform_id_ipcomp), 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_auth_lifetime,
      { "Authentication Lifetime", "isakmp.notify.data.auth_lifetime",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_redirect_gw_ident_type,
      { "Gateway Identity Type", "isakmp.notify.data.redirect.gw_ident.type",
        FT_UINT8, BASE_DEC, VALS(redirect_gateway_identity_type), 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_redirect_gw_ident_len,
      { "Gateway Identity Length", "isakmp.notify.data.redirect.gw_ident.len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_redirect_new_resp_gw_ident_ipv4,
      { "New Responder Gateway Identity (IPv4)", "isakmp.notify.data.redirect.new_resp_gw_ident.ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_redirect_new_resp_gw_ident_ipv6,
      { "New Responder Gateway Identity (IPv6)", "isakmp.notify.data.redirect.new_resp_gw_ident.ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_redirect_new_resp_gw_ident_fqdn,
      { "New Responder Gateway Identity (FQDN)", "isakmp.notify.data.redirect.new_resp_gw_ident.fqdn",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_redirect_new_resp_gw_ident,
      { "New Responder Gateway Identity (DATA)", "isakmp.notify.data.redirect.new_resp_gw_ident.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_redirect_nonce_data,
      { "Redirect Nonce Data", "isakmp.notify.data.redirect.nonce_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_redirect_org_resp_gw_ident_ipv4,
      { "Original Responder Gateway Identity (IPv4)", "isakmp.notify.data.redirect.org_resp_gw_ident.ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_redirect_org_resp_gw_ident_ipv6,
      { "Original Responder Gateway Identity (IPv6)", "isakmp.notify.data.redirect.org_resp_gw_ident.ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_redirect_org_resp_gw_ident,
      { "Original Responder Gateway Identity (DATA)", "isakmp.notify.data.redirect.org_resp_gw_ident.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isakmp_notify_data_ticket_lifetime,
      { "TICKET OPAQUE Lifetime", "isakmp.notify.data.ticket_opaque.lifetime",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "The Lifetime field contains a relative time value, the number of seconds until the ticket expires (encoded as an unsigned integer).", HFILL }},
    { &hf_isakmp_notify_data_ticket_data,
      { "TICKET OPAQUE Data", "isakmp.notify.data.ticket_opaque.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* ROHC Attributes Type */
    { &hf_isakmp_notify_data_rohc_attr.all,
      { "ROHC Attribute Type", "isakmp.notify.data.rohc.attr",
        FT_NONE, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_rohc_attr.type,
      { "ROHC Attribute Type", "isakmp.notify.data.rohc.attr.type",
        FT_UINT16, BASE_RANGE_STRING | BASE_DEC, RVALS(rohc_attr_type), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_rohc_attr.format,
      { "ROHC Format", "isakmp.notify.data.rohc.attr.format",
        FT_BOOLEAN, 16, TFS(&attribute_format), 0x8000,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_rohc_attr.length,
      { "Length", "isakmp.notify.data.rohc.attr.length",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_rohc_attr.value,
      { "Value", "isakmp.notify.data.rohc.attr.value",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_rohc_attr_max_cid,
      { "Maximum Context Identifier", "isakmp.notify.data.rohc.attr.max_cid",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_rohc_attr_profile,
      { "ROHC Profile", "isakmp.notify.data.rohc.attr.profile",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_rohc_attr_integ,
      { "ROHC Integrity Algorithm", "isakmp.notify.data.rohc.attr.integ",
        FT_UINT16, BASE_DEC, VALS(transform_ike2_integ_type), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_rohc_attr_icv_len,
      { "ROHC ICV Length in bytes", "isakmp.notify.data.rohc.attr.icv_len",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        "In bytes", HFILL }},
    { &hf_isakmp_notify_data_rohc_attr_mrru,
      { "MRRU", "isakmp.notify.data.rohc.attr.mrru",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},

    { &hf_isakmp_notify_data_qcd_token_secret_data,
      { "Token Secret Data", "isakmp.notify.data.qcd.token_secret_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isakmp_notify_data_ha_nonce_data,
      { "Nonce Data", "isakmp.notify.data.ha.nonce_data",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "Random nonce data, the data should be identical in the synchronization request and response", HFILL }},
    { &hf_isakmp_notify_data_ha_expected_send_req_msg_id,
      { "EXPECTED SEND REQ MESSAGE ID", "isakmp.notify.data.ha.expected_send_req_message_id",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "Indicate the Message ID it will use in the next request that it will send to the other protocol peer", HFILL }},
    { &hf_isakmp_notify_data_ha_expected_recv_req_msg_id,
      { "EXPECTED RECV REQ MESSAGE ID", "isakmp.notify.data.ha.expected_recv_req_message_id",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "Indicate the Message ID it is expecting in the next request to be received from the other protocol peer", HFILL }},
    { &hf_isakmp_notify_data_ha_incoming_ipsec_sa_delta_value,
      { "Incoming IPsec SA delta value", "isakmp.notify.data.ha.incoming_ipsec_sa_delta_value",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "The sender requests that the peer should increment all the Child SA Replay Counters for the sender's incomingtraffic by this value", HFILL }},
    { &hf_isakmp_notify_data_secure_password_methods,
      { "Secure Password Methods", "isakmp.notify.data.secure_password_methods",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_signature_hash_algorithms,
      { "Supported Signature Hash Algorithm", "isakmp.notify.data.signature_hash_algorithms",
        FT_UINT16, BASE_RANGE_STRING | BASE_DEC, RVALS(signature_hash_algorithms), 0x0,
        NULL, HFILL }},

    { &hf_isakmp_delete_doi,
      { "Domain of interpretation", "isakmp.delete.doi",
        FT_UINT32, BASE_DEC, VALS(doi_type), 0x0,
        "ISAKMP Delete Domain of Interpretation", HFILL }},
    { &hf_isakmp_delete_protoid_v1,
      { "Protocol ID", "isakmp.delete.protoid",
        FT_UINT32, BASE_DEC, VALS(protoid_v1_type), 0x0,
        "ISAKMP Delete Protocol ID", HFILL }},
    { &hf_isakmp_delete_protoid_v2,
      { "Protocol ID", "isakmp.delete.protoid",
        FT_UINT32, BASE_DEC, VALS(protoid_v2_type), 0x0,
        "IKEv2 Delete Protocol ID", HFILL }},
    { &hf_isakmp_delete_spi,
      { "Delete SPI", "isakmp.delete.spi",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Identifies the specific security association(s) to delete", HFILL }},
    { &hf_isakmp_vid_bytes,
      { "Vendor ID", "isakmp.vid_bytes",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_vid_string,
      { "Vendor ID", "isakmp.vid_string",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_vid_cp_product,
      { "Checkpoint Product", "isakmp.vid.cp.product",
        FT_UINT32, BASE_DEC, VALS(cp_product), 0x0,
        NULL, HFILL }},
    { &hf_isakmp_vid_cp_version,
      { "Checkpoint Version", "isakmp.vid.cp.version",
        FT_UINT32, BASE_DEC, VALS(cp_version), 0x0,
        "Encoded Version number", HFILL }},
    { &hf_isakmp_vid_cp_timestamp,
      { "Checkpoint Timestamp", "isakmp.vid.cp.timestamp",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Timestamp (NGX only; always zero in 4.1 or NG)", HFILL }},
    { &hf_isakmp_vid_cp_reserved,
      { "Checkpoint Reserved", "isakmp.vid.cp.reserved",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_vid_cp_features,
      { "Checkpoint Features", "isakmp.vid.cp.features",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isakmp_vid_cisco_unity_major,
      { "CISCO-UNITY Major version", "isakmp.vid.cisco_unity.major",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_vid_cisco_unity_minor,
      { "CISCO-UNITY Minor version", "isakmp.vid.cisco_unity.minor",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isakmp_vid_ms_nt5_isakmpoakley,
      { "MS NT5 ISAKMPOAKLEY", "isakmp.vid.ms_nt5_isakmpoakley",
        FT_UINT32, BASE_DEC, VALS(ms_nt5_isakmpoakley_type), 0x0,
        NULL, HFILL }},

    { &hf_isakmp_vid_aruba_via_auth_profile,
      { "Auth Profile", "isakmp.vid.aruba_via_auth_profile",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Aruba Networks Auth Profile for VIA Client", HFILL }},

    { &hf_isakmp_vid_fortinet_fortigate_release,
      { "Release", "isakmp.vid.fortinet.fortigate.release",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Release of Fortigate", HFILL }},

    { &hf_isakmp_vid_fortinet_fortigate_build,
      { "Build", "isakmp.vid.fortinet.fortigate.build",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Build of Fortigate", HFILL }},

    { &hf_isakmp_ts_number_of_ts,
      { "Number of Traffic Selectors", "isakmp.ts.number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_ts_type,
      { "Traffic Selector Type", "isakmp.ts.type",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(traffic_selector_type), 0x0,
        NULL, HFILL }},
    { &hf_isakmp_ts_protoid,
      { "Protocol ID", "isakmp.ts.protoid",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ipproto_val_ext, 0x0,
        "IKEv2 Traffic Selector Protocol ID", HFILL }},
    { &hf_isakmp_ts_selector_length,
      { "Selector Length", "isakmp.ts.selector_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_ts_start_port,
      { "Start Port", "isakmp.ts.start_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_ts_end_port,
      { "End Port", "isakmp.ts.end_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_ts_start_addr_ipv4,
      { "Starting Addr", "isakmp.ts.start_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_ts_end_addr_ipv4,
      { "Ending Addr", "isakmp.ts.end_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_ts_start_addr_ipv6,
      { "Starting Addr", "isakmp.ts.start_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_ts_end_addr_ipv6,
      { "Ending Addr", "isakmp.ts.end_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_ts_start_addr_fc,
      { "Starting Addr", "isakmp.ts.start_fc",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_ts_end_addr_fc,
      { "Ending Addr", "isakmp.ts.end_fc",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_ts_start_r_ctl,
      { "Starting R_CTL", "isakmp.ts.start_r_ctl",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_ts_end_r_ctl,
      { "Ending R_CTL", "isakmp.ts.end_r_ctl",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_ts_start_type,
      { "Starting Type", "isakmp.ts.start_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_ts_end_type,
      { "Ending Type", "isakmp.ts.end_type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_ts_data,
      { "Traffic Selector", "isakmp.ts.data",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "An individual traffic selector", HFILL }},

    { &hf_isakmp_num_spis,
      { "Number of SPIs", "isakmp.spinum",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "ISAKMP Number of SPIs", HFILL }},
    { &hf_isakmp_hash,
      { "Hash DATA", "isakmp.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sig,
      { "Signature DATA", "isakmp.sig",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_nonce,
      { "Nonce DATA", "isakmp.nonce",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isakmp_ike2_fragment_number,
      { "Fragment Number", "isakmp.frag.number",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "ISAKMP fragment number", HFILL }},
    { &hf_isakmp_ike2_total_fragments,
      { "Total Fragments", "isakmp.frag.total",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "ISAKMP total number of fragments", HFILL }},

    { &hf_isakmp_cisco_frag_packetid,
      { "Frag ID", "isakmp.frag.packetid",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "ISAKMP fragment packet-id", HFILL }},
    { &hf_isakmp_cisco_frag_seq,
      { "Frag seq", "isakmp.frag.seq",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP fragment number", HFILL }},
    { &hf_isakmp_cisco_frag_last,
      { "Frag last", "isakmp.frag.last",
        FT_UINT8, BASE_DEC, VALS(frag_last_vals), 0x0,
        "ISAKMP last fragment", HFILL }},
    { &hf_isakmp_fragments,
      {"Message fragments", "isakmp.fragments",
        FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_isakmp_fragment,
      {"Message fragment", "isakmp.fragment",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_isakmp_fragment_overlap,
      {"Message fragment overlap", "isakmp.fragment.overlap",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_isakmp_fragment_overlap_conflicts,
      {"Message fragment overlapping with conflicting data",
       "isakmp.fragment.overlap.conflicts",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_isakmp_fragment_multiple_tails,
      {"Message has multiple tail fragments",
       "isakmp.fragment.multiple_tails",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_isakmp_fragment_too_long_fragment,
      {"Message fragment too long", "isakmp.fragment.too_long_fragment",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_isakmp_fragment_error,
      {"Message defragmentation error", "isakmp.fragment.error",
       FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_isakmp_fragment_count,
      {"Message fragment count", "isakmp.fragment.count",
       FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    { &hf_isakmp_reassembled_in,
      {"Reassembled in", "isakmp.reassembled.in",
       FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_isakmp_reassembled_length,
      {"Reassembled ISAKMP length", "isakmp.reassembled.length",
       FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    { &hf_isakmp_certreq_authority_sig,
      { "Certificate Authority Signature", "isakmp.ike.certreq.authority.sig",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },
    { &hf_isakmp_certreq_authority_v1,
      { "Certificate Authority Data", "isakmp.ike.certreq.authority",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },
    { &hf_isakmp_certreq_authority_v2,
      { "Certificate Authority Data", "isakmp.ike.certreq.authority",
       FT_BYTES, BASE_NONE, NULL, 0x0,
        "SHA-1 hash of the Certificate Authority", HFILL } },
    { &hf_isakmp_nat_keepalive,
      { "NAT Keepalive", "isakmp.ike.nat_keepalive",
       FT_NONE, BASE_NONE, NULL, 0x0, "NAT Keepalive packet", HFILL } },
    { &hf_isakmp_nat_hash,
      { "HASH of the address and port", "isakmp.ike.nat_hash",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_nat_original_address_ipv4,
      { "NAT Original IPv4 Address", "isakmp.ike.nat_original_address_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_nat_original_address_ipv6,
      { "NAT Original IPv6 Address", "isakmp.ike.nat_original_address_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},

    /*tek key download type (ISAKMP phase 2 GDOI)*/
    { &hf_isakmp_tek_key_attr.all,
      { "Key download Tek Attribute", "isakmp.key_download.attr",
        FT_NONE, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_tek_key_attr.type,
      { "Type", "isakmp.key_download.attr.type",
        FT_UINT16, BASE_RANGE_STRING | BASE_DEC, NULL, 0x00,
        "key_download Attribute type", HFILL }},
    { &hf_isakmp_tek_key_attr.format,
      { "Format", "isakmp.key_download.attr.format",
        FT_BOOLEAN, 16, TFS(&attribute_format), 0x8000,
        "key_download Attribute format", HFILL }},
    { &hf_isakmp_tek_key_attr.length,
      { "Length", "isakmp.key_download.attr.length",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        "key_download Attribute length", HFILL }},
    { &hf_isakmp_tek_key_attr.value,
      { "Value", "isakmp.key_download.attr.value",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        "key_download Attribute value", HFILL }},
    /* IPsec SA Attributes (ISAKMP Phase 2) */
    { &hf_isakmp_ipsec_attr.all,
      { "IPsec Attribute", "isakmp.ipsec.attr",
        FT_NONE, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ipsec_attr.type,
      { "Type", "isakmp.ipsec.attr.type",
        FT_UINT16, BASE_RANGE_STRING | BASE_DEC, RVALS(ipsec_attr_type), 0x00,
        "IPsec Attribute type", HFILL }},
    { &hf_isakmp_ipsec_attr.format,
      { "Format", "isakmp.ipsec.attr.format",
        FT_BOOLEAN, 16, TFS(&attribute_format), 0x8000,
        "IPsec Attribute format", HFILL }},
    { &hf_isakmp_ipsec_attr.length,
      { "Length", "isakmp.ipsec.attr.length",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        "IPsec Attribute length", HFILL }},
    { &hf_isakmp_ipsec_attr.value,
      { "Value", "isakmp.ipsec.attr.value",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        "IPsec Attribute value", HFILL }},
    { &hf_isakmp_ipsec_attr_life_type,
      { "Life Type", "isakmp.ipsec.attr.life_type",
        FT_UINT16, BASE_DEC, VALS(attr_life_type), 0x00,
        "The unit (seconds or kilobytes) of the associated Life Duration attribute.", HFILL }},
    { &hf_isakmp_ipsec_attr_life_duration_uint32,
      { "Life Duration", "isakmp.ipsec.attr.life_duration",
        FT_UINT32, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ipsec_attr_life_duration_uint64,
      { "Life Duration", "isakmp.ipsec.attr.life_duration64",
        FT_UINT64, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ipsec_attr_life_duration_bytes,
      { "Life Duration", "isakmp.ipsec.attr.life_duration_bytes",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ipsec_attr_group_description,
      { "Group Description", "isakmp.ipsec.attr.group_description",
        FT_UINT16, BASE_DEC, VALS(dh_group), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ipsec_attr_encap_mode,
      { "Encapsulation Mode", "isakmp.ipsec.attr.encap_mode",
        FT_UINT16, BASE_DEC, VALS(ipsec_attr_encap_mode), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ipsec_attr_auth_algorithm,
      { "Authentication Algorithm", "isakmp.ipsec.attr.auth_algorithm",
        FT_UINT16, BASE_DEC, VALS(ipsec_attr_auth_algo), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ipsec_attr_key_length,
      { "Key Length", "isakmp.ipsec.attr.key_length",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ipsec_attr_key_rounds,
      { "Key Rounds", "isakmp.ipsec.attr.key_rounds",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ipsec_attr_cmpr_dict_size,
      { "Compress Dictionary Size", "isakmp.ipsec.attr.cmpr_dict_size",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ipsec_attr_cmpr_algorithm,
      { "Compress Private Algorithm", "isakmp.ipsec.attr.cmpr_algorithm",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ipsec_attr_ecn_tunnel,
      { "ECN Tunnel", "isakmp.ipsec.attr.ecn_tunnel",
        FT_UINT16, BASE_DEC, VALS(ipsec_attr_ecn_tunnel), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ipsec_attr_ext_seq_nbr,
      { "Extended (64-bit) Sequence Number", "isakmp.ipsec.attr.ext_seq_nbr",
        FT_UINT16, BASE_DEC, VALS(ipsec_attr_ext_seq_nbr), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ipsec_attr_auth_key_length,
      { "Authentication Key Length", "isakmp.ipsec.attr.auth_key_length",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ipsec_attr_sig_enco_algorithm,
      { "Signature Encoding Algorithm", "isakmp.ipsec.attr.sig_enco_algorithm",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ipsec_attr_addr_preservation,
      { "Address Preservation", "isakmp.ipsec.attr.addr_preservation",
        FT_UINT16, BASE_DEC, VALS(ipsec_attr_addr_preservation), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ipsec_attr_sa_direction,
      { "SA Direction", "isakmp.ipsec.attr.sa_direction",
        FT_UINT16, BASE_DEC, VALS(ipsec_attr_sa_direction), 0x00,
        NULL, HFILL }},

    /* Responder Lifetime Notification for IPsec SA */
    { &hf_isakmp_resp_lifetime_ipsec_attr.all,
      { "IPsec Attribute", "isakmp.notify.data.resp_lifetime.ipsec.attr",
        FT_NONE, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_resp_lifetime_ipsec_attr.type,
      { "Type", "isakmp.notify.data.resp_lifetime.ipsec.attr.type",
        FT_UINT16, BASE_RANGE_STRING | BASE_DEC, RVALS(ipsec_attr_type), 0x00,
        "IPsec Attribute type", HFILL }},
    { &hf_isakmp_resp_lifetime_ipsec_attr.format,
      { "Format", "isakmp.notify.data.resp_lifetime.ipsec.attr.format",
        FT_BOOLEAN, 16, TFS(&attribute_format), 0x8000,
        "IPsec Attribute format", HFILL }},
    { &hf_isakmp_resp_lifetime_ipsec_attr.length,
      { "Length", "isakmp.notify.data.resp_lifetime.ipsec.attr.length",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        "IPsec Attribute length", HFILL }},
    { &hf_isakmp_resp_lifetime_ipsec_attr.value,
      { "Value", "isakmp.notify.data.resp_lifetime.ipsec.attr.value",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        "IPsec Attribute value", HFILL }},

    { &hf_isakmp_resp_lifetime_ipsec_attr_life_type,
      { "Life Type", "isakmp.notify.data.resp_lifetime.ipsec.attr.life_type",
        FT_UINT16, BASE_DEC, VALS(attr_life_type), 0x00,
        "The unit (seconds or kilobytes) of the associated Life Duration attribute.", HFILL }},
    { &hf_isakmp_resp_lifetime_ipsec_attr_life_duration_uint32,
      { "Life Duration", "isakmp.notify.data.resp_lifetime.ipsec.attr.life_duration",
        FT_UINT32, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_resp_lifetime_ipsec_attr_life_duration_uint64,
      { "Life Duration", "isakmp.notify.data.resp_lifetime.ipsec.attr.life_duration64",
        FT_UINT64, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_resp_lifetime_ipsec_attr_life_duration_bytes,
      { "Life Duration", "isakmp.notify.data.resp_lifetime.ipsec.attr.life_duration_bytes",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},

    /* IKEv1 SA Attributes (ISAKMP SA, Phase 1) */
    { &hf_isakmp_ike_attr.all,
      { "IKE Attribute", "isakmp.ike.attr",
        FT_NONE, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr.type,
      { "Type", "isakmp.ike.attr.type",
        FT_UINT16, BASE_RANGE_STRING | BASE_DEC, RVALS(ike_attr_type), 0x00,
        "IKEv1 Attribute type", HFILL }},
    { &hf_isakmp_ike_attr.format,
      { "Format", "isakmp.ike.attr.format",
        FT_BOOLEAN, 16, TFS(&attribute_format), 0x8000,
        "IKEv1 Attribute format", HFILL }},
    { &hf_isakmp_ike_attr.length,
      { "Length", "isakmp.ike.attr.length",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        "IKEv1 Attribute length", HFILL }},
    { &hf_isakmp_ike_attr.value,
      { "Value", "isakmp.ike.attr.value",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        "IKEv1 Attribute value", HFILL }},

    { &hf_isakmp_ike_attr_encryption_algorithm,
      { "Encryption Algorithm", "isakmp.ike.attr.encryption_algorithm",
        FT_UINT16, BASE_DEC, VALS(ike_attr_enc_algo), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_hash_algorithm,
      { "HASH Algorithm", "isakmp.ike.attr.hash_algorithm",
        FT_UINT16, BASE_DEC, VALS(ike_attr_hash_algo), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_authentication_method,
      { "Authentication Method", "isakmp.ike.attr.authentication_method",
        FT_UINT16, BASE_DEC, VALS(ike_attr_authmeth), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_group_description,
      { "Group Description", "isakmp.ike.attr.group_description",
        FT_UINT16, BASE_DEC, VALS(dh_group), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_group_type,
      { "Group Type", "isakmp.ike.attr.group_type",
        FT_UINT16, BASE_DEC, VALS(ike_attr_grp_type), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_group_prime,
      { "Group Prime", "isakmp.ike.attr.group_prime",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_group_generator_one,
      { "Group Generator One", "isakmp.ike.attr.group_generator_one",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_group_generator_two,
      { "Group Generator Two", "isakmp.ike.attr.group_generator_two",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_group_curve_a,
      { "Group Curve A", "isakmp.ike.attr.group_curve_a",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_group_curve_b,
      { "Group Curve B", "isakmp.ike.attr.group_curve_b",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_life_type,
      { "Life Type", "isakmp.ike.attr.life_type",
        FT_UINT16, BASE_DEC, VALS(attr_life_type), 0x00,
        "The unit (seconds or kilobytes) of the associated Life Duration attribute.", HFILL }},
    { &hf_isakmp_ike_attr_life_duration_uint32,
      { "Life Duration", "isakmp.ike.attr.life_duration",
        FT_UINT32, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_life_duration_uint64,
      { "Life Duration", "isakmp.ike.attr.life_duration64",
        FT_UINT64, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_life_duration_bytes,
      { "Life Duration", "isakmp.ike.attr.life_duration_bytes",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_prf,
      { "PRF", "isakmp.ike.attr.prf",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_key_length,
      { "Key Length", "isakmp.ike.attr.key_length",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_field_size,
      { "Field Size", "isakmp.ike.attr.field_size",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_group_order,
      { "Group Order", "isakmp.ike.attr.group_order",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_block_size,
      { "Block Size", "isakmp.ike.attr.block_size",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_ike_attr_asymmetric_cryptographic_algorithm_type,
      { "Asymmetric Cryptographic Algorithm Type", "isakmp.ike.attr.asymmetric_cryptographic_algorithm_type",
        FT_UINT16, BASE_DEC, VALS(ike_attr_asym_algo), 0x00,
        NULL, HFILL }},

    /* Responder Lifetime Notification for IKEv1 SA */
    { &hf_isakmp_resp_lifetime_ike_attr.all,
      { "IKE Attribute", "isakmp.notify.data.resp_lifetime.ike.attr",
        FT_NONE, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_resp_lifetime_ike_attr.type,
      { "Type", "isakmp.notify.data.resp_lifetime.ike.attr.type",
        FT_UINT16, BASE_RANGE_STRING | BASE_DEC, RVALS(ike_attr_type), 0x00,
        "IKEv1 Attribute type", HFILL }},
    { &hf_isakmp_resp_lifetime_ike_attr.format,
      { "Format", "isakmp.notify.data.resp_lifetime.ike.attr.format",
        FT_BOOLEAN, 16, TFS(&attribute_format), 0x8000,
        "IKEv1 Attribute format", HFILL }},
    { &hf_isakmp_resp_lifetime_ike_attr.length,
      { "Length", "isakmp.notify.data.resp_lifetime.ike.attr.length",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        "IKEv1 Attribute length", HFILL }},
    { &hf_isakmp_resp_lifetime_ike_attr.value,
      { "Value", "isakmp.notify.data.resp_lifetime.ike.attr.value",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        "IKEv1 Attribute value", HFILL }},

    { &hf_isakmp_resp_lifetime_ike_attr_life_type,
      { "Life Type", "isakmp.notify.data.resp_lifetime.ike.attr.life_type",
        FT_UINT16, BASE_DEC, VALS(attr_life_type), 0x00,
        "The unit (seconds or kilobytes) of the associated Life Duration attribute.", HFILL }},
    { &hf_isakmp_resp_lifetime_ike_attr_life_duration_uint32,
      { "Life Duration", "isakmp.notify.data.resp_lifetime.ike.attr.life_duration",
        FT_UINT32, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_resp_lifetime_ike_attr_life_duration_uint64,
      { "Life Duration", "isakmp.notify.data.resp_lifetime.ike.attr.life_duration64",
        FT_UINT64, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_resp_lifetime_ike_attr_life_duration_bytes,
      { "Life Duration", "isakmp.notify.data.resp_lifetime.ike.attr.life_duration_bytes",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},

    /* IKEv2 Transform */
    { &hf_isakmp_trans_type,
      { "Transform Type", "isakmp.tf.type",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(transform_ike2_type), 0x00,
        NULL, HFILL }},

    { &hf_isakmp_trans_encr,
      { "Transform ID (ENCR)", "isakmp.tf.id.encr",
        FT_UINT16, BASE_DEC, VALS(transform_ike2_encr_type), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_trans_prf,
      { "Transform ID (PRF)", "isakmp.tf.id.prf",
        FT_UINT16, BASE_DEC, VALS(transform_ike2_prf_type), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_trans_integ,
      { "Transform ID (INTEG)", "isakmp.tf.id.integ",
        FT_UINT16, BASE_DEC, VALS(transform_ike2_integ_type), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_trans_dh,
      { "Transform ID (D-H)", "isakmp.tf.id.dh",
        FT_UINT16, BASE_DEC, VALS(dh_group), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_trans_esn,
      { "Transform ID (ESN)", "isakmp.tf.id.esn",
        FT_UINT16, BASE_DEC, VALS(transform_ike2_esn_type), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_trans_id_v2,
      { "Transform ID", "isakmp.tf.id",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},

    /* IKEv2 Transform Attributes */
    { &hf_isakmp_ike2_attr.all,
      { "Transform Attribute", "isakmp.ike2.attr",
        FT_NONE, BASE_NONE, NULL, 0x00,
        "IKEv2 Transform Attribute", HFILL }},
    { &hf_isakmp_ike2_attr.type,
      { "Type", "isakmp.ike2.attr.type",
        FT_UINT16, BASE_RANGE_STRING | BASE_DEC, RVALS(transform_ike2_attr_type), 0x00,
        "IKEv2 Transform Attribute type", HFILL }},
    { &hf_isakmp_ike2_attr.format,
      { "Format", "isakmp.ike2.attr.format",
        FT_BOOLEAN, 16, TFS(&attribute_format), 0x8000,
        "IKEv2 Transform Attribute format", HFILL }},
    { &hf_isakmp_ike2_attr.length,
      { "Length", "isakmp.ike2.attr.length",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        "IKEv2 Transform Attribute length", HFILL }},
    { &hf_isakmp_ike2_attr.value,
      { "Value", "isakmp.ike2.attr.value",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        "IKEv2 Transform Attribute value", HFILL }},
    { &hf_isakmp_ike2_attr_key_length,
      { "Key Length", "isakmp.ike2.attr.key_length",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},


    { &hf_isakmp_key_exch_dh_group,
      { "DH Group #", "isakmp.key_exchange.dh_group",
        FT_UINT16, BASE_DEC, VALS(dh_group), 0x00,
        NULL, HFILL }},
    { &hf_isakmp_key_exch_data,
      { "Key Exchange Data", "isakmp.key_exchange.data",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_eap_data,
      { "EAP Message", "isakmp.eap.data",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},

    { &hf_isakmp_gspm_data,
      { "GSPM", "isakmp.gspm.data",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        "Generic Secure Password Method", HFILL }},

    /* Config Payload */
    { &hf_isakmp_cfg_type_v1,
      { "Type", "isakmp.cfg.type",
         FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(vs_v1_cfgtype), 0x0,
         "IKEv1 Config Type", HFILL }},
    { &hf_isakmp_cfg_identifier,
      { "Identifier", "isakmp.cfg.identifier",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         "IKEv1 Config Identifier", HFILL }},
    { &hf_isakmp_cfg_type_v2,
      { "Type", "isakmp.cfg.type",
         FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(vs_v2_cfgtype), 0x0,
         "IKEv2 Config Type", HFILL }},

    /* Config Attributes */
    { &hf_isakmp_cfg_attr.all,
      { "Config Attribute", "isakmp.cfg.attr",
        FT_NONE, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_cfg_attr_type_v1,
      { "Type", "isakmp.cfg.attr.type",
        FT_UINT16, BASE_RANGE_STRING | BASE_DEC, RVALS(vs_v1_cfgattr), 0x00,
        "IKEv1 Config Attribute type", HFILL }},
    { &hf_isakmp_cfg_attr_type_v2,
      { "Type", "isakmp.cfg.attr.type",
        FT_UINT16, BASE_RANGE_STRING | BASE_DEC, RVALS(vs_v2_cfgattr), 0x00,
        "IKEv2 Config Attribute type", HFILL }},
    { &hf_isakmp_cfg_attr.format,
      { "Format", "isakmp.cfg.attr.format",
        FT_BOOLEAN, 16, TFS(&attribute_format), 0x8000,
        "Config Attribute format", HFILL }},
    { &hf_isakmp_cfg_attr.length,
      { "Length", "isakmp.cfg.attr.length",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        "Config Attribute length", HFILL }},
    { &hf_isakmp_cfg_attr.value,
      { "Value", "isakmp.cfg.attr.value",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        "Config Attribute value", HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip4_address,
      { "INTERNAL IP4 ADDRESS", "isakmp.cfg.attr.internal_ip4_address",
        FT_IPv4, BASE_NONE, NULL, 0x00,
        "An IPv4 address on the internal network", HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip4_netmask,
      { "INTERNAL IP4 NETMASK", "isakmp.cfg.attr.internal_ip4_netmask",
        FT_IPv4, BASE_NETMASK, NULL, 0x00,
        "The internal network's netmask", HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip4_dns,
      { "INTERNAL IP4 DNS", "isakmp.cfg.attr.internal_ip4_dns",
        FT_IPv4, BASE_NONE, NULL, 0x00,
        "An IPv4 address of a DNS server within the network", HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip4_nbns,
      { "INTERNAL IP4 NBNS", "isakmp.cfg.attr.internal_ip4_nbns",
        FT_IPv4, BASE_NONE, NULL, 0x00,
        "An IPv4 address of a NetBios Name Server (WINS) within the network", HFILL }},
    { &hf_isakmp_cfg_attr_internal_address_expiry,
      { "INTERNAL ADDRESS EXPIRY (Secs)", "isakmp.cfg.attr.internal_address_expiry",
        FT_UINT32, BASE_DEC, NULL, 0x00,
        "Specifies the number of seconds that the host can use the internal IP address", HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip4_dhcp,
      { "INTERNAL IP4 DHCP", "isakmp.cfg.attr.internal_ip4_dhcp",
        FT_IPv4, BASE_NONE, NULL, 0x00,
        "the host to send any internal DHCP requests to the address", HFILL }},
    { &hf_isakmp_cfg_attr_application_version,
      { "APPLICATION VERSION", "isakmp.cfg.attr.application_version",
        FT_STRING, BASE_NONE, NULL, 0x00,
        "The version or application information of the IPsec host", HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip6_address_ip,
      { "INTERNAL IP6 ADDRESS", "isakmp.cfg.attr.internal_ip6_address",
        FT_IPv6, BASE_NONE, NULL, 0x00,
        "An IPv6 address on the internal network", HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip6_address_prefix,
      { "INTERNAL IP6 ADDRESS (PREFIX)", "isakmp.cfg.attr.internal_ip6_address.prefix",
        FT_UINT8, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip6_netmask,
      { "INTERNAL IP4 NETMASK", "isakmp.cfg.attr.internal_ip6_netmask",
        FT_IPv6, BASE_NONE, NULL, 0x00,
        "The internal network's netmask", HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip6_dns,
      { "INTERNAL IP6 DNS", "isakmp.cfg.attr.internal_ip6_dns",
        FT_IPv6, BASE_NONE, NULL, 0x00,
        "An IPv6 address of a DNS server within the network", HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip6_nbns,
      { "INTERNAL IP6 NBNS", "isakmp.cfg.attr.internal_ip6_nbns",
        FT_IPv6, BASE_NONE, NULL, 0x00,
        "An IPv6 address of a NetBios Name Server (WINS) within the network", HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip6_dhcp,
      { "INTERNAL IP6 DHCP", "isakmp.cfg.attr.internal_ip6_dhcp",
        FT_IPv6, BASE_NONE, NULL, 0x00,
        "The host to send any internal DHCP requests to the address", HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip4_subnet_ip,
      { "INTERNAL IP4 SUBNET (IP)", "isakmp.cfg.attr.internal_ip4_subnet_ip",
        FT_IPv4, BASE_NONE, NULL, 0x00,
        "The protected sub-networks that this edge-device protects (IP)", HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip4_subnet_netmask,
      { "INTERNAL IP4 SUBNET (NETMASK)", "isakmp.cfg.attr.internal_ip4_subnet_netmask",
        FT_IPv4, BASE_NETMASK, NULL, 0x00,
        "The protected sub-networks that this edge-device protects (IP)", HFILL }},
    { &hf_isakmp_cfg_attr_supported_attributes,
      { "SUPPORTED ATTRIBUTES", "isakmp.cfg.attr.supported_attributes",
        FT_UINT16, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip6_subnet_ip,
      { "INTERNAL_IP6_SUBNET (IP)", "isakmp.cfg.attr.internal_ip6_subnet_ip",
        FT_IPv6, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip6_subnet_prefix,
      { "INTERNAL_IP6_SUBNET (PREFIX)", "isakmp.cfg.attr.internal_ip6_subnet_prefix",
        FT_UINT8, BASE_DEC, NULL, 0x00,
        NULL, HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip6_link_interface,
      { "INTERNAL_IP6_LINK (Link-Local Interface ID)", "isakmp.cfg.attr.internal_ip6_link_interface",
        FT_UINT64, BASE_DEC, NULL, 0x00,
        "The Interface ID used for link-local address (by the party that sent this attribute)", HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip6_link_id,
      { "INTERNAL_IP6_LINK (IKEv2 Link ID)", "isakmp.cfg.attr.internal_ip6_link_id",
        FT_BYTES, BASE_NONE, NULL, 0x00,
        "The Link ID is selected by the VPN gateway and is treated as an opaque octet string by the client.", HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip6_prefix_ip,
      { "INTERNAL_IP6_PREFIX (IP)", "isakmp.cfg.attr.internal_ip6_prefix_ip",
        FT_IPv6, BASE_NONE, NULL, 0x00,
        "An IPv6 prefix assigned to the virtual link", HFILL }},
    { &hf_isakmp_cfg_attr_internal_ip6_prefix_length,
      { "INTERNAL_IP6_PREFIX (Length)", "isakmp.cfg.attr.internal_ip6_prefix_length",
        FT_UINT8, BASE_DEC, NULL, 0x00,
         "The length of the prefix in bits (usually 64)", HFILL }},
    { &hf_isakmp_cfg_attr_p_cscf_ip4_address,
      { "P_CSCF_IP4_ADDRESS (IP)", "isakmp.cfg.attr.p_cscf_ip4_address",
        FT_IPv4, BASE_NONE, NULL, 0x00,
        "An IPv4 address of the P-CSCF server", HFILL }},
    { &hf_isakmp_cfg_attr_p_cscf_ip6_address,
      { "P_CSCF_IP6_ADDRESS (IP)", "isakmp.cfg.attr.p_cscf_ip6_address",
        FT_IPv6, BASE_NONE, NULL, 0x00,
        "An IPv6 address of the P-CSCF server", HFILL }},

    { &hf_isakmp_cfg_attr_xauth_type,
      { "XAUTH TYPE", "isakmp.cfg.attr.xauth.type",
        FT_UINT16, BASE_RANGE_STRING | BASE_DEC, RVALS(cfgattr_xauth_type), 0x00,
        "The type of extended authentication requested", HFILL }},
    { &hf_isakmp_cfg_attr_xauth_user_name,
      { "XAUTH USER NAME", "isakmp.cfg.attr.xauth.user_name",
        FT_STRING, BASE_NONE, NULL, 0x00,
        "The user name", HFILL }},
    { &hf_isakmp_cfg_attr_xauth_user_password,
      { "XAUTH USER PASSWORD", "isakmp.cfg.attr.xauth.user_password",
        FT_STRING, BASE_NONE, NULL, 0x00,
        "The user's password", HFILL }},
    { &hf_isakmp_cfg_attr_xauth_passcode,
      { "XAUTH PASSCODE", "isakmp.cfg.attr.xauth.passcode",
        FT_STRING, BASE_NONE, NULL, 0x00,
        "A token card's passcode", HFILL }},
    { &hf_isakmp_cfg_attr_xauth_message,
      { "XAUTH MESSAGE", "isakmp.cfg.attr.xauth.message",
        FT_STRING, BASE_NONE, NULL, 0x00,
        "A textual message from an edge device to an IPSec host", HFILL }},
    { &hf_isakmp_cfg_attr_xauth_challenge,
      { "XAUTH CHALLENGE", "isakmp.cfg.attr.xauth.challenge",
        FT_STRING, BASE_NONE, NULL, 0x00,
        "A challenge string sent from the edge device to the IPSec host for it to include in its calculation of a password", HFILL }},
    { &hf_isakmp_cfg_attr_xauth_domain,
      { "XAUTH DOMAIN", "isakmp.cfg.attr.xauth.domain",
        FT_STRING, BASE_NONE, NULL, 0x00,
        "The domain to be authenticated in", HFILL }},
    { &hf_isakmp_cfg_attr_xauth_status,
      { "XAUTH STATUS", "isakmp.cfg.attr.xauth.status",
        FT_UINT16, BASE_DEC, VALS(cfgattr_xauth_status), 0x00,
        "A variable that is used to denote authentication success or failure", HFILL }},
    { &hf_isakmp_cfg_attr_xauth_next_pin,
      { "XAUTH TYPE", "isakmp.cfg.attr.xauth.next_pin",
        FT_STRING, BASE_NONE, NULL, 0x00,
        "A variable which is used when the edge device is requesting that the user choose a new pin number", HFILL }},
    { &hf_isakmp_cfg_attr_xauth_answer,
      { "XAUTH ANSWER", "isakmp.cfg.attr.xauth.answer",
        FT_STRING, BASE_NONE, NULL, 0x00,
        "A variable length ASCII string used to send input to the edge device", HFILL }},
    { &hf_isakmp_cfg_attr_unity_banner,
      { "UNITY BANNER", "isakmp.cfg.attr.unity.banner",
        FT_STRING, BASE_NONE, NULL, 0x00,
        "Banner", HFILL }},
    { &hf_isakmp_cfg_attr_unity_def_domain,
      { "UNITY DEF DOMAIN", "isakmp.cfg.attr.unity.def_domain",
        FT_STRING, BASE_NONE, NULL, 0x00,
        NULL, HFILL }},

    /* SA KEK Payload */
    { &hf_isakmp_sak_next_payload,
      { "Next Payload", "isakmp.sak.nextpayload",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sak_reserved,
      { "Reserved", "isakmp.sak.reserved",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sak_payload_len ,
      { "Payload length", "isakmp.sak.payload_len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sak_protocol,
      { "Protocol ID", "isakmp.sak.protoid",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ipproto_val_ext, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sak_src_id_type,
      { "SRC ID Type", "isakmp.sak.src_id_type",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(vs_v1_id_type), 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sak_src_id_port,
      { "SRC ID Port", "isakmp.sak.src_id_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sak_src_id_length,
      { "SRC ID Data Length", "isakmp.sak.src_id_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sak_src_id_data,
      { "SRC ID Data", "isakmp.sak.src_id_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sak_dst_id_type,
      { "DST ID Type", "isakmp.sak.dst_id_type",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(vs_v1_id_type), 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sak_dst_id_port,
      { "DST ID Port", "isakmp.sak.dst_id_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sak_dst_id_length,
      { "DST ID Data Length", "isakmp.sak.dst_id_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sak_dst_id_data,
      { "DST ID Data", "isakmp.sak.dst_id_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sak_spi,
      { "SPI", "isakmp.sak.spi",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* SA TEK Payload */
    { &hf_isakmp_sat_next_payload,
      { "Next Payload", "isakmp.sat.nextpayload",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sat_reserved,
      { "Reserved", "isakmp.sat.reserved",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sat_payload_len ,
      { "Payload length", "isakmp.sat.payload_len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sat_protocol_id,
      { "Protocol ID", "isakmp.sat.protocol_id",
         FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(sat_protocol_ids), 0x0,
         NULL, HFILL }},
    { &hf_isakmp_sat_protocol,
      { "Internet Protocol", "isakmp.sat.protocol",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &ipproto_val_ext, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sat_src_id_type,
      { "SRC ID Type", "isakmp.sat.src_id_type",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(vs_v1_id_type), 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sat_src_id_port,
      { "SRC ID Port", "isakmp.sat.src_id_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sat_src_id_length,
      { "SRC ID Data Length", "isakmp.sat.src_id_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sat_src_id_data,
      { "SRC ID Data", "isakmp.sat.src_id_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sat_dst_id_type,
      { "DST ID Type", "isakmp.sat.dst_id_type",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(vs_v1_id_type), 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sat_dst_id_port,
      { "DST ID Port", "isakmp.sat.dst_id_port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sat_dst_id_length,
      { "DST ID Data Length", "isakmp.sat.dst_id_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sat_dst_id_data,
      { "DST ID Data", "isakmp.sat.dst_id_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sat_transform_id,
      { "Transform ID", "isakmp.sat.transform_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sat_spi,
      { "SPI", "isakmp.sat.spi",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_sat_payload,
      { "TEK Payload", "isakmp.sat.payload",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    /* Key Download Payload */
    { &hf_isakmp_kd_num_key_pkt,
      { "Number of Key Packets", "isakmp.kd.num_pkt",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }},
    { &hf_isakmp_kd_payload,
      { "Key Download Payload", "isakmp.kd.payload",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_kdp_type,
      { "Type", "isakmp.kd.payload.type",
         FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(key_download_types), 0x0,
         NULL, HFILL }},
    { &hf_isakmp_kdp_length,
      { "Length", "isakmp.kd.payload.length",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         NULL, HFILL }},
    { &hf_isakmp_kdp_spi_size,
      { "SPI Size", "isakmp.kd.payload.spi_size",
         FT_UINT8, BASE_DEC, NULL, 0x0,
         NULL, HFILL }},
    { &hf_isakmp_kdp_spi,
      { "SPI", "isakmp.kd.payload.spi",
         FT_BYTES, BASE_NONE, NULL, 0x0,
         NULL, HFILL }},
    /* Sequence Payload */
    { &hf_isakmp_seq_seq,
      { "Sequence Number", "isakmp.seq.seq",
         FT_UINT32, BASE_DEC, NULL, 0x0,
         NULL, HFILL }},

    { &hf_isakmp_enc_decrypted_data,
      { "Decrypted Data", "isakmp.enc.decrypted",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_enc_contained_data,
      { "Contained Data", "isakmp.enc.contained",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_enc_padding,
      { "Padding", "isakmp.enc.padding",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_enc_pad_length,
      { "Pad Length", "isakmp.enc.pad_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_enc_data,
      { "Encrypted Data", "isakmp.enc.data",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_enc_iv,
      { "Initialization Vector", "isakmp.enc.iv",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_enc_icd,
      { "Integrity Checksum Data", "isakmp.enc.icd",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_3gpp_backoff_timer_len,
      { "Length", "isakmp.notify.priv.3gpp.backoff_timer_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isakmp_notify_data_3gpp_device_identity_len,
      { "Identity Length", "isakmp.notify.priv.3gpp.device_identity_len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_3gpp_device_identity_type,
      { "Identity Type", "isakmp.notify.priv.3gpp.device_identity_type",
        FT_UINT8, BASE_DEC, VALS(device_identity_types), 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_3gpp_device_identity_imei,
      { "IMEI", "isakmp.notify.priv.3gpp.device_identity_imei",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_3gpp_device_identity_imeisv,
      { "IMEISV", "isakmp.notify.priv.3gpp.device_identity_imeisv",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_isakmp_notify_data_3gpp_emergency_call_numbers_len,
      { "Total Length", "isakmp.notify.priv.3gpp.emergency_call_numbers_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_3gpp_emergency_call_numbers_spare,
      { "Spare", "isakmp.notify.priv.3gpp.emergency_call_numbers_spare",
        FT_UINT8, BASE_DEC, NULL, 0xE0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_3gpp_emergency_call_numbers_element_len,
      { "Length", "isakmp.notify.priv.3gpp.emergency_call_numbers_element_len",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_isakmp_notify_data_3gpp_emergency_call_numbers_flags,
      { "Service Category Value", "isakmp.notify.priv.3gpp.emergency_call_numbers_flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isakmp_notify_data_3gpp_emergency_call_numbers_flag_b1_police,
      { "Police", "isakmp.notify.priv.3gpp.emergency_call_numbers_flag_b1_police",
        FT_UINT8, BASE_DEC, NULL, 0x01,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_3gpp_emergency_call_numbers_flag_b2_ambulance,
      { "Ambulance", "isakmp.notify.priv.3gpp.emergency_call_numbers_flag_b2_ambulance",
        FT_UINT8, BASE_DEC, NULL, 0x02,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_3gpp_emergency_call_numbers_flag_b3_fire_brigade,
      { "Fire Brigade", "isakmp.notify.priv.3gpp.emergency_call_numbers_flag_b3_fire_brigade",
        FT_UINT8, BASE_DEC, NULL, 0x04,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_3gpp_emergency_call_numbers_flag_b4_marine_guard,
	  { "Marine Guard", "isakmp.notify.priv.3gpp.emergency_call_numbers_b4_marine_guard",
        FT_UINT8, BASE_DEC, NULL, 0x08,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_3gpp_emergency_call_numbers_flag_b5_mountain_rescue,
      { "Mountain Rescue", "isakmp.notify.priv.3gpp.emergency_call_numbers_flag_b5_mountain_rescue",
        FT_UINT8, BASE_DEC, NULL, 0x10,
        NULL, HFILL }},
    { &hf_iskamp_notify_data_3gpp_emergency_call_number,
      { "Emergency Number", "isakmp.notify.priv.3gpp.emergency_call_number",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }}
  };


  static gint *ett[] = {
    &ett_isakmp,
    &ett_isakmp_version,
    &ett_isakmp_flags,
    &ett_isakmp_payload,
    &ett_isakmp_payload_digital_signature,
    &ett_isakmp_payload_digital_signature_asn1_data,
    &ett_isakmp_fragment,
    &ett_isakmp_fragments,
    &ett_isakmp_sa,
    &ett_isakmp_attr,
    &ett_isakmp_id,
    &ett_isakmp_notify_data,
    &ett_isakmp_notify_data_3gpp_emergency_call_numbers_main,
    &ett_isakmp_notify_data_3gpp_emergency_call_numbers_element,
    &ett_isakmp_ts,
    &ett_isakmp_kd,
    &ett_isakmp_decrypted_data,
    &ett_isakmp_decrypted_payloads
  };

  static ei_register_info ei[] = {
     { &ei_isakmp_enc_iv, { "isakmp.enc.iv.not_enough_data", PI_MALFORMED, PI_WARN, "Not enough data in IKEv2 Encrypted payload", EXPFILL }},
     { &ei_isakmp_ikev2_integrity_checksum, { "isakmp.ikev2.integrity_checksum", PI_CHECKSUM, PI_WARN, "IKEv2 Integrity Checksum Data is incorrect", EXPFILL }},
     { &ei_isakmp_enc_data_length_mult_block_size, { "isakmp.enc_data_length_mult_block_size", PI_MALFORMED, PI_WARN, "Encrypted data length isn't a multiple of block size", EXPFILL }},
     { &ei_isakmp_enc_pad_length_big, { "isakmp.enc.pad_length.big", PI_MALFORMED, PI_WARN, "Pad length is too big", EXPFILL }},
     { &ei_isakmp_attribute_value_empty, { "isakmp.attribute_value_empty", PI_PROTOCOL, PI_NOTE, "Attribute value is empty", EXPFILL }},
     { &ei_isakmp_payload_bad_length, { "isakmp.payloadlength.invalid", PI_MALFORMED, PI_ERROR, "Invalid payload length", EXPFILL }},
     { &ei_isakmp_bad_fragment_number, { "isakmp.fragment_number.invalid", PI_MALFORMED, PI_ERROR, "Invalid fragment numbering", EXPFILL }},
     { &ei_isakmp_notify_data_3gpp_unknown_device_identity, { "isakmp.notify.priv.3gpp.unknown_device_identity", PI_PROTOCOL, PI_WARN, "Type of device identity not known", EXPFILL }},
  };

  expert_module_t* expert_isakmp;

  static uat_field_t ikev1_uat_flds[] = {
    UAT_FLD_BUFFER(ikev1_users, icookie, "Initiator's COOKIE", "Initiator's COOKIE"),
    UAT_FLD_BUFFER(ikev1_users, key, "Encryption Key", "Encryption Key"),
    UAT_END_FIELDS
  };

  static uat_field_t ikev2_uat_flds[] = {
    UAT_FLD_BUFFER(ikev2_users, spii, "Initiator's SPI", "Initiator's SPI value of the IKE_SA"),
    UAT_FLD_BUFFER(ikev2_users, spir, "Responder's SPI", "Responder's SPI value of the IKE_SA"),
    UAT_FLD_BUFFER(ikev2_users, sk_ei, "SK_ei", "Key used to encrypt/decrypt IKEv2 packets from initiator to responder"),
    UAT_FLD_BUFFER(ikev2_users, sk_er, "SK_er", "Key used to encrypt/decrypt IKEv2 packets from responder to initiator"),
    UAT_FLD_VS(ikev2_users, encr_alg, "Encryption algorithm", vs_ikev2_encr_algs, "Encryption algorithm of IKE_SA"),
    UAT_FLD_BUFFER(ikev2_users, sk_ai, "SK_ai", "Key used to calculate Integrity Checksum Data for IKEv2 packets from initiator to responder"),
    UAT_FLD_BUFFER(ikev2_users, sk_ar, "SK_ar", "Key used to calculate Integrity Checksum Data for IKEv2 packets from responder to initiator"),
    UAT_FLD_VS(ikev2_users, auth_alg, "Integrity algorithm", vs_ikev2_auth_algs, "Integrity algorithm of IKE_SA"),
    UAT_END_FIELDS
  };

  proto_isakmp = proto_register_protocol("Internet Security Association and Key Management Protocol",
                                               "ISAKMP", "isakmp");
  proto_register_field_array(proto_isakmp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_isakmp = expert_register_protocol(proto_isakmp);
  expert_register_field_array(expert_isakmp, ei, array_length(ei));
  register_init_routine(&isakmp_init_protocol);
  register_cleanup_routine(&isakmp_cleanup_protocol);
  reassembly_table_register(&isakmp_cisco_reassembly_table,
                        &addresses_reassembly_table_functions);
  reassembly_table_register(&isakmp_ike2_reassembly_table,
                        &addresses_reassembly_table_functions);

  isakmp_handle = register_dissector("isakmp", dissect_isakmp, proto_isakmp);

  isakmp_module = prefs_register_protocol(proto_isakmp, NULL);
  ikev1_uat = uat_new("IKEv1 Decryption Table",
      sizeof(ikev1_uat_data_key_t),
      "ikev1_decryption_table",
      TRUE,
      &ikev1_uat_data,
      &num_ikev1_uat_data,
      UAT_AFFECTS_DISSECTION, /* affects dissection of packets, but not set of named fields */
      "ChIKEv1DecryptionSection",
      ikev1_uat_data_copy_cb,
      ikev1_uat_data_update_cb,
      ikev1_uat_data_free_cb,
      NULL,
      NULL,
      ikev1_uat_flds);

  prefs_register_uat_preference(isakmp_module,
      "ikev1_decryption_table",
      "IKEv1 Decryption Table",
      "Table of IKE_SA security parameters for decryption of IKEv1 packets",
      ikev1_uat);

  ikev2_uat = uat_new("IKEv2 Decryption Table",
      sizeof(ikev2_uat_data_t),
      "ikev2_decryption_table",
      TRUE,
      &ikev2_uat_data,
      &num_ikev2_uat_data,
      UAT_AFFECTS_DISSECTION, /* affects dissection of packets, but not set of named fields */
      "ChIKEv2DecryptionSection",
      ikev2_uat_data_copy_cb,
      ikev2_uat_data_update_cb,
      ikev2_uat_data_free_cb,
      NULL,
      NULL,
      ikev2_uat_flds);

  prefs_register_uat_preference(isakmp_module,
      "ikev2_decryption_table",
      "IKEv2 Decryption Table",
      "Table of IKE_SA security parameters for decryption of IKEv2 packets",
      ikev2_uat);
}

void
proto_reg_handoff_isakmp(void)
{
  eap_handle = find_dissector_add_dependency("eap", proto_isakmp);
  dissector_add_uint_with_preference("udp.port", UDP_PORT_ISAKMP, isakmp_handle);
  dissector_add_uint_with_preference("tcp.port", TCP_PORT_ISAKMP, isakmp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
