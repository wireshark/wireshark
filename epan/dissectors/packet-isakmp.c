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
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 *
 * References:
 * IKEv2 http://www.ietf.org/rfc/rfc4306.txt?number=4306
 * IKEv2bis http://www.ietf.org/rfc/rfc5996.txt?number=5996
 *
 * http://www.iana.org/assignments/isakmp-registry (last updated 2011-11-07)
 * http://www.iana.org/assignments/ipsec-registry (last updated 2011-03-14)
 * http://www.iana.org/assignments/ikev2-parameters (last updated 2011-12-19)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>

#include <epan/ipproto.h>
#include <epan/asn1.h>
#include <epan/reassemble.h>
#include <epan/dissectors/packet-x509if.h>
#include <epan/dissectors/packet-x509af.h>
#include <epan/dissectors/packet-isakmp.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#include <epan/strutil.h>
#include <epan/uat.h>
#endif

/* Struct for the byte_to_str, match_bytestr_idx, and match_bytestr functions */

typedef struct _byte_string {
  const gchar   *value;
  const guint16 len;
  const gchar   *strptr;
} byte_string;

static int proto_isakmp = -1;

static int hf_isakmp_nat_keepalive = -1;
static int hf_isakmp_nat_hash = -1;
static int hf_isakmp_nat_original_address_ipv6 = -1;
static int hf_isakmp_nat_original_address_ipv4 = -1;

static int hf_isakmp_icookie         = -1;
static int hf_isakmp_rcookie         = -1;
static int hf_isakmp_typepayload     = -1;
static int hf_isakmp_nextpayload     = -1;
static int hf_isakmp_criticalpayload = -1;
static int hf_isakmp_datapayload     = -1;
static int hf_isakmp_extradata       = -1;
static int hf_isakmp_version         = -1;
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
static int hf_isakmp_id_data	     = -1;
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
static int hf_isakmp_certreq_type_v1 = -1;
static int hf_isakmp_certreq_type_v2 = -1;
static int hf_isakmp_certreq_authority_v1  = -1;
static int hf_isakmp_certreq_authority_v2 = -1;
static int hf_isakmp_certreq_authority_sig = -1;
static int hf_isakmp_auth_meth = -1;
static int hf_isakmp_auth_data = -1;
static int hf_isakmp_notify_doi = -1;
static int hf_isakmp_notify_protoid_v1 = -1;
static int hf_isakmp_notify_protoid_v2 = -1;
static int hf_isakmp_notify_msgtype_v1 = -1;
static int hf_isakmp_notify_msgtype_v2 = -1;
static int hf_isakmp_notify_data = -1;
static int hf_isakmp_notify_data_dpd_are_you_there = -1;
static int hf_isakmp_notify_data_dpd_are_you_there_ack = -1;
static int hf_isakmp_notify_data_unity_load_balance = -1;
static int hf_isakmp_notify_data_ipcomp_cpi = -1;
static int hf_isakmp_notify_data_ipcomp_transform_id = -1;
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
static int hf_isakmp_notify_data_rohc_attr = -1;
static int hf_isakmp_notify_data_rohc_attr_type = -1;
static int hf_isakmp_notify_data_rohc_attr_format = -1;
static int hf_isakmp_notify_data_rohc_attr_length = -1;
static int hf_isakmp_notify_data_rohc_attr_value = -1;
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

static int hf_isakmp_tf_attr = -1;
static int hf_isakmp_tf_attr_type_v1 = -1;
static int hf_isakmp_tf_attr_format = -1;
static int hf_isakmp_tf_attr_length = -1;
static int hf_isakmp_tf_attr_value = -1;
static int hf_isakmp_tf_attr_life_type = -1;
static int hf_isakmp_tf_attr_life_duration_uint32 = -1;
static int hf_isakmp_tf_attr_life_duration_uint64 = -1;
static int hf_isakmp_tf_attr_life_duration_bytes = -1;
static int hf_isakmp_tf_attr_group_description = -1;
static int hf_isakmp_tf_attr_encap_mode = -1;
static int hf_isakmp_tf_attr_auth_algorithm = -1;
static int hf_isakmp_tf_attr_key_length = -1;
static int hf_isakmp_tf_attr_key_rounds = -1;
static int hf_isakmp_tf_attr_cmpr_dict_size = -1;
static int hf_isakmp_tf_attr_cmpr_algorithm = -1;
static int hf_isakmp_tf_attr_ecn_tunnel = -1;
static int hf_isakmp_tf_attr_ext_seq_nbr = -1;
static int hf_isakmp_tf_attr_auth_key_length = -1;
static int hf_isakmp_tf_attr_sig_enco_algorithm = -1;
static int hf_isakmp_tf_attr_addr_preservation = -1;
static int hf_isakmp_tf_attr_sa_direction = -1;

static int hf_isakmp_ike_attr = -1;
static int hf_isakmp_ike_attr_type = -1;
static int hf_isakmp_ike_attr_format = -1;
static int hf_isakmp_ike_attr_length = -1;
static int hf_isakmp_ike_attr_value = -1;
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

static int hf_isakmp_trans_type = -1;
static int hf_isakmp_trans_encr = -1;
static int hf_isakmp_trans_prf = -1;
static int hf_isakmp_trans_integ = -1;
static int hf_isakmp_trans_dh = -1;
static int hf_isakmp_trans_esn = -1;
static int hf_isakmp_trans_id_v2 = -1;

static int hf_isakmp_ike2_attr = -1;
static int hf_isakmp_ike2_attr_type = -1;
static int hf_isakmp_ike2_attr_format = -1;
static int hf_isakmp_ike2_attr_length = -1;
static int hf_isakmp_ike2_attr_value = -1;
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
static int hf_isakmp_cfg_attr = -1;
static int hf_isakmp_cfg_attr_type_v1 = -1;
static int hf_isakmp_cfg_attr_type_v2 = -1;
static int hf_isakmp_cfg_attr_format = -1;
static int hf_isakmp_cfg_attr_length = -1;
static int hf_isakmp_cfg_attr_value = -1;

static int hf_isakmp_cfg_attr_internal_ip4_address = -1;
static int hf_isakmp_cfg_attr_internal_ip4_netmask = -1;
static int hf_isakmp_cfg_attr_internal_ip4_dns = -1;
static int hf_isakmp_cfg_attr_internal_ip4_nbns = -1;
static int hf_isakmp_cfg_attr_internal_address_expiry = -1;
static int hf_isakmp_cfg_attr_internal_ip4_dhcp = -1;
static int hf_isakmp_cfg_attr_application_version = -1;
static int hf_isakmp_cfg_attr_internal_ip6_address = -1;
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

static int hf_isakmp_enc_decrypted_data = -1;
static int hf_isakmp_enc_contained_data = -1;
static int hf_isakmp_enc_pad_length= -1;
static int hf_isakmp_enc_padding = -1;
static int hf_isakmp_enc_data = -1;
static int hf_isakmp_enc_iv = -1;
static int hf_isakmp_enc_icd = -1;

static gint ett_isakmp = -1;
static gint ett_isakmp_flags = -1;
static gint ett_isakmp_payload = -1;
static gint ett_isakmp_fragment = -1;
static gint ett_isakmp_fragments = -1;
static gint ett_isakmp_sa = -1;
static gint ett_isakmp_tf_attr = -1;
static gint ett_isakmp_tf_ike_attr = -1;
static gint ett_isakmp_tf_ike2_attr = -1;
static gint ett_isakmp_id = -1;
static gint ett_isakmp_cfg_attr = -1;
static gint ett_isakmp_rohc_attr = -1;
#ifdef HAVE_LIBGCRYPT
/* For decrypted IKEv2 Encrypted payload*/
static gint ett_isakmp_decrypted_data = -1;
static gint ett_isakmp_decrypted_payloads = -1;
#endif /* HAVE_LIBGCRYPT */

static dissector_handle_t eap_handle = NULL;

static GHashTable *isakmp_fragment_table = NULL;
static GHashTable *isakmp_reassembled_table = NULL;

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
#define IKE_ID_IPV4_ADDR		1
#define IKE_ID_FQDN			2
#define IKE_ID_USER_FQDN		3
#define IKE_ID_IPV4_ADDR_SUBNET		4
#define IKE_ID_IPV6_ADDR		5
#define IKE_ID_IPV6_ADDR_SUBNET		6
#define IKE_ID_IPV4_ADDR_RANGE		7
#define IKE_ID_IPV6_ADDR_RANGE		8
#define IKE_ID_DER_ASN1_DN		9
#define IKE_ID_DER_ASN1_GN		10
#define IKE_ID_KEY_ID			11
#define IKE_ID_LIST			12
#define IKE_ID_FC_NAME			12
#define IKE_ID_RFC822_ADDR		3
/*
 * Traffic Selector Type
 *   Not in use for IKEv1
 */
#define IKEV2_TS_IPV4_ADDR_RANGE	7
#define IKEV2_TS_IPV6_ADDR_RANGE	8
#define IKEV2_TS_FC_ADDR_RANGE		9
/*
 * Configuration Payload Attribute Types
 *   draft-ietf-ipsec-isakmp-mode-cfg-05.txt for IKEv1
 *   draft-ietf-ipsec-isakmp-xauth-06.txt and draft-beaulieu-ike-xauth-02.txt for XAUTH
 *   RFC4306 for IKEv2
 *   RFC5739 for INTERNAL_IP6_LINK and INTERNAL_IP6_PREFIX
 */
#define INTERNAL_IP4_ADDRESS		1
#define INTERNAL_IP4_NETMASK		2
#define INTERNAL_IP4_DNS		3
#define INTERNAL_IP4_NBNS		4
#define INTERNAL_ADDRESS_EXPIRY		5
#define INTERNAL_IP4_DHCP           	6
#define APPLICATION_VERSION         	7
#define INTERNAL_IP6_ADDRESS        	8
#define INTERNAL_IP6_NETMASK 		9
#define INTERNAL_IP6_DNS		10
#define INTERNAL_IP6_NBNS		11
#define INTERNAL_IP6_DHCP		12
#define INTERNAL_IP4_SUBNET		13
#define SUPPORTED_ATTRIBUTES		14
#define INTERNAL_IP6_SUBNET		15
#define MIP6_HOME_PREFIX		16
#define INTERNAL_IP6_LINK		17
#define INTERNAL_IP6_PREFIX		18
/* checkpoint configuration attributes */
#define CHKPT_DEF_DOMAIN		16387
#define CHKPT_MAC_ADDRESS		16388
#define CHKPT_MARCIPAN_REASON_CODE      16389
#define CHKPT_UNKNOWN1			16400
#define CHKPT_UNKNOWN2			16401
#define CHKPT_UNKNOWN3			16402
/* XAUTH configuration attributes */
#define XAUTH_TYPE			16520
#define XAUTH_USER_NAME			16521
#define XAUTH_USER_PASSWORD		16522
#define XAUTH_PASSCODE			16523
#define XAUTH_MESSAGE			16524
#define XAUTH_CHALLENGE			16525
#define XAUTH_DOMAIN			16526
#define XAUTH_STATUS			16527
#define XAUTH_NEXT_PIN			16528
#define XAUTH_ANSWER			16529
/* unity (CISCO) configuration attributes */
#define UNITY_BANNER			28672
#define UNITY_SAVE_PASSWD		28673
#define UNITY_DEF_DOMAIN		28674
#define UNITY_SPLIT_DOMAIN		28675
#define UNITY_SPLIT_INCLUDE		28676
#define UNITY_NATT_PORT			28677
#define UNITY_SPLIT_EXCLUDE		28678
#define UNITY_PFS			28679
#define UNITY_FW_TYPE			28680
#define UNITY_BACKUP_SERVERS		28681
#define UNITY_DDNS_HOSTNAME		28682

/* Payload Type
* RFC2408 / RFC3547 for IKEv1
* RFC4306 for IKEv2
*/
#define PLOAD_IKE_NONE 			0
#define PLOAD_IKE_SA			1
#define PLOAD_IKE_P			2
#define PLOAD_IKE_T			3
#define PLOAD_IKE_KE 			4
#define PLOAD_IKE_ID 			5
#define PLOAD_IKE_CERT 			6
#define PLOAD_IKE_CR 			7
#define PLOAD_IKE_HASH 			8
#define PLOAD_IKE_SIG			9
#define PLOAD_IKE_NONCE			10
#define PLOAD_IKE_N			11
#define PLOAD_IKE_D			12
#define PLOAD_IKE_VID			13
#define PLOAD_IKE_A			14
#define PLOAD_IKE_NAT_D48		15
#define PLOAD_IKE_NAT_OA58		16
#define PLOAD_IKE_NAT_D			20
#define PLOAD_IKE_NAT_OA		21
#define PLOAD_IKE_GAP			22
#define PLOAD_IKE2_SA			33
#define PLOAD_IKE2_KE			34
#define PLOAD_IKE2_IDI			35
#define PLOAD_IKE2_IDR			36
#define PLOAD_IKE2_CERT			37
#define PLOAD_IKE2_CERTREQ		38
#define PLOAD_IKE2_AUTH			39
#define PLOAD_IKE2_NONCE		40
#define PLOAD_IKE2_N			41
#define PLOAD_IKE2_D			42
#define PLOAD_IKE2_V			43
#define PLOAD_IKE2_TSI			44
#define PLOAD_IKE2_TSR			45
#define PLOAD_IKE2_SK			46
#define PLOAD_IKE2_CP			47
#define PLOAD_IKE2_EAP			48
#define PLOAD_IKE2_GSPM			49
#define PLOAD_IKE_NAT_D13		130
#define PLOAD_IKE_NAT_OA14		131
#define PLOAD_IKE_CISCO_FRAG		132
/*
* IPSEC Situation Definition (RFC2407)
*/
#define SIT_IDENTITY_ONLY	0x01
#define SIT_SECRECY	        0x02
#define SIT_INTEGRITY	        0x04


static const value_string exchange_v1_type[] = {
  { 0,	"NONE" },
  { 1,	"Base" },
  { 2,	"Identity Protection (Main Mode)" },
  { 3,	"Authentication Only" },
  { 4,	"Aggressive" },
  { 5,	"Informational" },
  { 6,	"Transaction (Config Mode)" },
  { 32,	"Quick Mode" },
  { 33,	"New Group Mode" },
  { 0,	NULL },
};

static const value_string exchange_v2_type[] = {
  { 34,	"IKE_SA_INIT" },
  { 35,	"IKE_AUTH " },
  { 36,	"CREATE_CHILD_SA" },
  { 37,	"INFORMATIONAL" },
  { 38,	"IKE_SESSION_RESUME" }, /* RFC5723 */
  { 0,	NULL },
};

static const value_string frag_last_vals[] = {
  { 0,	"More fragments" },
  { 1,	"Last fragment" },
  { 0,  NULL },
};
/* Ex vs_proto */
static const value_string protoid_v1_type[] = {
  { 0,	"RESERVED" },
  { 1,	"ISAKMP" },
  { 2,	"IPSEC_AH" },
  { 3,	"IPSEC_ESP" },
  { 4,	"IPCOMP" },
  { 5,  "GIGABEAM_RADIO" }, /* RFC4705 */
  { 0,	NULL },
};

static const value_string protoid_v2_type[] = {
  { 0,	"RESERVED" },
  { 1,	"IKE" },
  { 2,	"AH" },
  { 3,	"ESP" },
  { 4,	"FC_ESP_HEADER" },
  { 5,	"FC_CT_AUTHENTICATION" },
  { 0,	NULL },
};

static const range_string payload_type[] = {
  { PLOAD_IKE_NONE,PLOAD_IKE_NONE,	"NONE / No Next Payload " },
  { PLOAD_IKE_SA,PLOAD_IKE_SA,	"Security Association" },
  { PLOAD_IKE_P,PLOAD_IKE_P,	"Proposal" },
  { PLOAD_IKE_T,PLOAD_IKE_T,	"Transform" },
  { PLOAD_IKE_KE,PLOAD_IKE_KE,	"Key Exchange" },
  { PLOAD_IKE_ID,PLOAD_IKE_ID,	"Identification" },
  { PLOAD_IKE_CERT,PLOAD_IKE_CERT,	"Certificate" },
  { PLOAD_IKE_CR,PLOAD_IKE_CR,	"Certificate Request" },
  { PLOAD_IKE_HASH,PLOAD_IKE_HASH,	"Hash" },
  { PLOAD_IKE_SIG,PLOAD_IKE_SIG,	"Signature" },
  { PLOAD_IKE_NONCE,PLOAD_IKE_NONCE,	"Nonce" },
  { PLOAD_IKE_N,PLOAD_IKE_N,	"Notification" },
  { PLOAD_IKE_D,PLOAD_IKE_D,	"Delete" },
  { PLOAD_IKE_VID,PLOAD_IKE_VID,	"Vendor ID" },
  { PLOAD_IKE_A,PLOAD_IKE_A,	"Attributes" }, /* draft-ietf-ipsec-isakmp-mode-cfg-05.txt */
  { PLOAD_IKE_NAT_D48,PLOAD_IKE_NAT_D48, "NAT-Discovery" }, /* draft-ietf-ipsec-nat-t-ike-04 to 08 */
  { PLOAD_IKE_NAT_OA58,PLOAD_IKE_NAT_OA58, "NAT-Original Address"}, /* draft-ietf-ipsec-nat-t-ike-05 to 08*/
  { PLOAD_IKE_NAT_D,PLOAD_IKE_NAT_D, "NAT-D (RFC 3947)" },
  { PLOAD_IKE_NAT_OA,PLOAD_IKE_NAT_OA, "NAT-OA (RFC 3947)"},
  { PLOAD_IKE_GAP,PLOAD_IKE_GAP, "Group Associated Policy"},
  { PLOAD_IKE2_SA,PLOAD_IKE2_SA, "Security Association"},
  { PLOAD_IKE2_KE,PLOAD_IKE2_KE, "Key Exchange"},
  { PLOAD_IKE2_IDI,PLOAD_IKE2_IDI, "Identification - Initiator"},
  { PLOAD_IKE2_IDR,PLOAD_IKE2_IDR, "Identification - Responder"},
  { PLOAD_IKE2_CERT,PLOAD_IKE2_CERT, "Certificate"},
  { PLOAD_IKE2_CERTREQ,PLOAD_IKE2_CERTREQ, "Certificate Request"},
  { PLOAD_IKE2_AUTH,PLOAD_IKE2_AUTH, "Authentication"},
  { PLOAD_IKE2_NONCE,PLOAD_IKE2_NONCE, "Nonce"},
  { PLOAD_IKE2_N,PLOAD_IKE2_N, "Notify"},
  { PLOAD_IKE2_D,PLOAD_IKE2_D, "Delete"},
  { PLOAD_IKE2_V,PLOAD_IKE2_V, "Vendor ID"},
  { PLOAD_IKE2_TSI,PLOAD_IKE2_TSI, "Traffic Selector - Initiator"},
  { PLOAD_IKE2_TSR,PLOAD_IKE2_TSR, "Traffic Selector - Responder"},
  { PLOAD_IKE2_SK,PLOAD_IKE2_SK, "Encrypted and Authenticated"},
  { PLOAD_IKE2_CP,PLOAD_IKE2_CP, "Configuration"},
  { PLOAD_IKE2_EAP,PLOAD_IKE2_EAP, "Extensible Authentication"},
  { PLOAD_IKE2_GSPM,PLOAD_IKE2_GSPM, "Generic Secure Password Method"},
  { 50,127,    "Unassigned"	},
  { 128,129,    "Private Use"	},
  { PLOAD_IKE_NAT_D13,PLOAD_IKE_NAT_D13, "NAT-D (draft-ietf-ipsec-nat-t-ike-01 to 03)"},
  { PLOAD_IKE_NAT_OA14,PLOAD_IKE_NAT_OA14, "NAT-OA (draft-ietf-ipsec-nat-t-ike-01 to 03)"},
  { PLOAD_IKE_CISCO_FRAG,PLOAD_IKE_CISCO_FRAG, "Cisco-Fragmentation"},
  { 133,256,    "Private Use"	},
  { 0,0,	NULL },
  };

/*
 * ISAKMP Domain of Interpretation (DOI)
 *   RFC2408 for ISAKMP
 *   RFC2407 for IPSEC
 *   RFC3547 for GDOI
 */
static const value_string doi_type[] = {
  { 0,	"ISAKMP" },
  { 1,	"IPSEC" },
  { 2,	"GDOI" },
  { 0,	NULL },
};

/* Transform Type */

#define ISAKMP_ATTR_LIFE_TYPE			1
#define ISAKMP_ATTR_LIFE_DURATION		2
#define ISAKMP_ATTR_GROUP_DESC			3
#define ISAKMP_ATTR_ENCAP_MODE			4
#define ISAKMP_ATTR_AUTH_ALGORITHM		5
#define ISAKMP_ATTR_KEY_LENGTH			6
#define ISAKMP_ATTR_KEY_ROUNDS			7
#define ISAKMP_ATTR_CMPR_DICT_SIZE		8
#define ISAKMP_ATTR_CMPR_ALGORITHM		9
#define ISAKMP_ATTR_ECN_TUNNEL			10      /* [RFC3168] */
#define ISAKMP_ATTR_EXT_SEQ_NBR			11      /* [RFC4304] */
#define ISAKMP_ATTR_AUTH_KEY_LENGTH		12      /* [RFC4359] */
#define ISAKMP_ATTR_SIG_ENCO_ALGORITHM          13      /* [RFC4359] */
#define ISAKMP_ATTR_ADDR_PRESERVATION           14      /* [RFC6407] */
#define ISAKMP_ATTR_SA_DIRECTION                15      /* [RFC6407] */

static const value_string transform_isakmp_attr_type[] = {
  { ISAKMP_ATTR_LIFE_TYPE,	"SA-Life-Type" },
  { ISAKMP_ATTR_LIFE_DURATION,	"SA-Life-Duration" },
  { ISAKMP_ATTR_GROUP_DESC,	"Group-Description" },
  { ISAKMP_ATTR_ENCAP_MODE,	"Encapsulation-Mode" },
  { ISAKMP_ATTR_AUTH_ALGORITHM,	"Authentication-Algorithm" },
  { ISAKMP_ATTR_KEY_LENGTH,	"Key-Length" },
  { ISAKMP_ATTR_KEY_ROUNDS,	"Key-Rounds" },
  { ISAKMP_ATTR_CMPR_DICT_SIZE,	"Compress-Dictionary-Size" },
  { ISAKMP_ATTR_CMPR_ALGORITHM,	"Compress-Private-Algorithm" },
  { ISAKMP_ATTR_ECN_TUNNEL,	"ECN Tunnel" },
  { ISAKMP_ATTR_EXT_SEQ_NBR,	"Extended (64-bit) Sequence Number" },
  { ISAKMP_ATTR_AUTH_KEY_LENGTH, "Authentication Key Length" },
  { ISAKMP_ATTR_SIG_ENCO_ALGORITHM, "Signature Encoding Algorithm" },
  { ISAKMP_ATTR_ADDR_PRESERVATION, "Address Preservation" },
  { ISAKMP_ATTR_SA_DIRECTION, "SA Direction" },
  { 0,	NULL },
};

/* Transform IKE Type */
#define IKE_ATTR_ENCRYPTION_ALGORITHM	1
#define IKE_ATTR_HASH_ALGORITHM			2
#define IKE_ATTR_AUTHENTICATION_METHOD	3
#define IKE_ATTR_GROUP_DESCRIPTION		4
#define IKE_ATTR_GROUP_TYPE				5
#define IKE_ATTR_GROUP_PRIME			6
#define IKE_ATTR_GROUP_GENERATOR_ONE	7
#define IKE_ATTR_GROUP_GENERATOR_TWO	8
#define IKE_ATTR_GROUP_CURVE_A			9
#define IKE_ATTR_GROUP_CURVE_B			10
#define IKE_ATTR_LIFE_TYPE				11
#define IKE_ATTR_LIFE_DURATION			12
#define IKE_ATTR_PRF					13
#define IKE_ATTR_KEY_LENGTH				14
#define IKE_ATTR_FIELD_SIZE				15
#define IKE_ATTR_GROUP_ORDER			16



static const value_string transform_ike_attr_type[] = {
  { IKE_ATTR_ENCRYPTION_ALGORITHM,"Encryption-Algorithm" },
  { IKE_ATTR_HASH_ALGORITHM,	"Hash-Algorithm" },
  { IKE_ATTR_AUTHENTICATION_METHOD,"Authentication-Method" },
  { IKE_ATTR_GROUP_DESCRIPTION,	"Group-Description" },
  { IKE_ATTR_GROUP_TYPE,	"Group-Type" },
  { IKE_ATTR_GROUP_PRIME,	"Group-Prime" },
  { IKE_ATTR_GROUP_GENERATOR_ONE,"Group-Generator-One" },
  { IKE_ATTR_GROUP_GENERATOR_TWO,"Group-Generator-Two" },
  { IKE_ATTR_GROUP_CURVE_A,	"Group-Curve-A" },
  { IKE_ATTR_GROUP_CURVE_B,	"Group-Curve-B" },
  { IKE_ATTR_LIFE_TYPE,		"Life-Type" },
  { IKE_ATTR_LIFE_DURATION,	"Life-Duration" },
  { IKE_ATTR_PRF,		"PRF" },
  { IKE_ATTR_KEY_LENGTH,	"Key-Length" },
  { IKE_ATTR_FIELD_SIZE,	"Field-Size" },
  { IKE_ATTR_GROUP_ORDER,	"Group-Order" },
  { 0,	NULL },
};

static const value_string vs_v2_sttr[] = {
  { 1,	"SA-Life-Type" },
  { 2,	"SA-Life-Duration" },
  { 3,	"Group-Description" },
  { 4,	"Encapsulation-Mode" },
  { 5,	"Authentication-Algorithm" },
  { 6,	"Key-Length" },
  { 7,	"Key-Rounds" },
  { 8,	"Compress-Dictionary-Size" },
  { 9,	"Compress-Private-Algorithm" },
  { 10,	"ECN Tunnel" },
  { 0,	NULL },
};

static const value_string vs_v1_trans_isakmp[] = {
  { 0,	"RESERVED" },
  { 1,	"KEY_IKE" },
  { 0,	NULL },
};

static const value_string vs_v1_trans_ah[] = {
  { 0,	"RESERVED" },
  { 1,	"RESERVED" },
  { 2,	"MD5" },
  { 3,	"SHA" },
  { 4,	"DES" },
  { 5,	"SHA2-256" },
  { 6,	"SHA2-384" },
  { 7,	"SHA2-512" },
  { 0,	NULL },
};

static const value_string vs_v1_trans_esp[] = {
  { 0,	"RESERVED" },
  { 1,	"DES-IV64" },
  { 2,	"DES" },
  { 3,	"3DES" },
  { 4,	"RC5" },
  { 5,	"IDEA" },
  { 6,	"CAST" },
  { 7,	"BLOWFISH" },
  { 8,	"3IDEA" },
  { 9,	"DES-IV32" },
  { 10,	"RC4" },
  { 11,	"NULL" },
  { 12,	"AES" },
  { 0,	NULL },
};

static const value_string transform_id_ipcomp[] = {
  { 0,	"RESERVED" },
  { 1,	"OUI" },
  { 2,	"DEFLATE" },
  { 3,	"LZS" },
  { 4,	"LZJH" },
  { 0,	NULL },
};
static const value_string redirect_gateway_identity_type[] = {
  { 1,	"IPv4 address" },
  { 2,	"IPv6 address" },
  { 3,	"FQDN" },
  { 0,	NULL },
};
static const value_string transform_attr_sa_life_type[] = {
  { 0,	"RESERVED" },
  { 1,	"Seconds" },
  { 2,	"Kilobytes" },
  { 0,	NULL },
};

static const value_string transform_attr_encap_type[] = {
  { 0,	"RESERVED" },
  { 1,	"Tunnel" },
  { 2,	"Transport" },
  { 3,	"UDP-Encapsulated-Tunnel" }, /* RFC3947 */
  { 4,	"UDP-Encapsulated-Transport" }, /* RFC3947 */
  { 61440,	"Check Point IPSec UDP Encapsulation" },
  { 61443,	"UDP-Encapsulated-Tunnel (draft)" },
  { 61444,	"UDP-Encapsulated-Transport (draft)" },
  { 0,	NULL },
};

static const value_string transform_attr_auth_type[] = {
  { 0,	"RESERVED" },
  { 1,	"HMAC-MD5" },
  { 2,	"HMAC-SHA" },
  { 3,	"DES-MAC" },
  { 4,	"KPDK" },
  { 5,	"HMAC-SHA2-256" },
  { 6,	"HMAC-SHA2-384" },
  { 7,	"HMAC-SHA2-512" },
  { 8,	"HMAC-RIPEMD" },		/* [RFC2857] */
  { 9,	"AES-XCBC-MAC" },		/* [RFC3566] */
  { 10,	"SIG-RSA" },			/* [RFC4359] */
  { 11, "AES-128-GMAC" },		/* [RFC4543][Errata1821] */
  { 12, "AES-192-GMAC" },		/* [RFC4543][Errata1821] */
  { 13, "AES-256-GMAC" },		/* [RFC4543][Errata1821] */

/*
	Values 11-61439 are reserved to IANA.  Values 61440-65535 are
	for private use.
*/
  { 0,	NULL },
};

#define ENC_DES_CBC		1
#define ENC_IDEA_CBC		2
#define ENC_BLOWFISH_CBC	3
#define ENC_RC5_R16_B64_CBC	4
#define ENC_3DES_CBC		5
#define ENC_CAST_CBC		6
#define ENC_AES_CBC		7
#define ENC_CAMELLIA_CBC	8

static const value_string transform_attr_enc_type[] = {
  { 0,				"RESERVED" },
  { ENC_DES_CBC,		"DES-CBC" },
  { ENC_IDEA_CBC,		"IDEA-CBC" },
  { ENC_BLOWFISH_CBC,		"BLOWFISH-CBC" },
  { ENC_RC5_R16_B64_CBC,	"RC5-R16-B64-CBC" },
  { ENC_3DES_CBC,		"3DES-CBC" },
  { ENC_CAST_CBC,		"CAST-CBC" },
  { ENC_AES_CBC,		"AES-CBC" },
  { ENC_CAMELLIA_CBC,		"CAMELLIA-CBC" },
  { 0,	NULL },
};

#define HMAC_MD5	1
#define HMAC_SHA	2
#define HMAC_TIGER	3
#define HMAC_SHA2_256	4
#define HMAC_SHA2_384	5
#define HMAC_SHA2_512	6

static const value_string transform_attr_hash_type[] = {
  { 0,			"RESERVED" },
  { HMAC_MD5,		"MD5" },
  { HMAC_SHA,		"SHA" },
  { HMAC_TIGER,		"TIGER" },
  { HMAC_SHA2_256,	"SHA2-256" },
  { HMAC_SHA2_384,	"SHA2-384" },
  { HMAC_SHA2_512,	"SHA2-512" },
  { 0,	NULL },
};

static const value_string transform_attr_ecn_type[] = {
  { 0, "RESERVED" },
  { 1, "Allowed" },
  { 2, "Forbidden" },
  { 0,	NULL },
};

static const value_string transform_attr_ext_seq_nbr_type[] = {
  { 0, "RESERVED" },
  { 1, "64-bit Sequence Number" },
  { 0,	NULL },
};

static const value_string transform_attr_sig_enco_algo_type[] = {
  { 0, "RESERVED" },
  { 1, "RSASSA-PKCS1-v1_5" },
  { 2, "RSASSA-PSS" },
  { 0,	NULL },
};

static const value_string transform_attr_addr_preservation_type[] = {
  { 0, "Reserved" },
  { 1, "None" },
  { 2, "Source-Only" },
  { 3, "Destination-Only" },
  { 4, "Source-and-Destination" },
  { 0,	NULL },
};

static const value_string transform_attr_sa_direction_type[] = {
  { 0, "Reserved" },
  { 1, "Sender-Only" },
  { 2, "Receiver-Only" },
  { 3, "Symmetric" },
  { 0,	NULL },
};

static const value_string transform_attr_authmeth_type[] = {
  { 0,	"RESERVED" },
  { 1,	"PSK" },
  { 2,	"DSS-SIG" },
  { 3,	"RSA-SIG" },
  { 4,	"RSA-ENC" },
  { 5,	"RSA-Revised-ENC" },
  { 6,	"Encryption with El-Gamal" },
  { 7,	"Revised encryption with El-Gamal" },
  { 8,	"ECDSA signatures" },
  { 9,	"AES-XCBC-MAC" },
  { 64221,	"HybridInitRSA" },
  { 64222,	"HybridRespRSA" },
  { 64223,	"HybridInitDSS" },
  { 64224,	"HybridRespDSS" },
  { 65001,	"XAUTHInitPreShared" },
  { 65002,	"XAUTHRespPreShared" },
  { 65003,	"XAUTHInitDSS" },
  { 65004,	"XAUTHRespDSS" },
  { 65005,	"XAUTHInitRSA" },
  { 65006,	"XAUTHRespRSA" },
  { 65007,	"XAUTHInitRSAEncryption" },
  { 65008,	"XAUTHRespRSAEncryption" },
  { 65009,	"XAUTHInitRSARevisedEncryption" },
  { 65010,	"XAUTHRespRSARevisedEncryption" },
  { 0,	NULL },
};


static const value_string transform_dh_group_type[] = {
  { 0,	"UNDEFINED - 0" },
  { 1,	"Default 768-bit MODP group" },
  { 2,	"Alternate 1024-bit MODP group" },
  { 3,	"EC2N group on GP[2^155] group" },
  { 4,	"EC2N group on GP[2^185] group" },
  { 5,	"1536 bit MODP group" },
  { 6,	"EC2N group over GF[2^163]" },
  { 7,	"EC2N group over GF[2^163]" },
  { 8,	"EC2N group over GF[2^283]" },
  { 9,	"EC2N group over GF[2^283]" },
  { 10,	"EC2N group over GF[2^409]" },
  { 11,	"EC2N group over GF[2^409]" },
  { 12,	"EC2N group over GF[2^571]" },
  { 13,	"EC2N group over GF[2^571]" },
  { 14,	"2048 bit MODP group" },
  { 15,	"3072 bit MODP group" },
  { 16,	"4096 bit MODP group" },
  { 17,	"6144 bit MODP group" },
  { 18,	"8192 bit MODP group" },
  { 19, "256-bit random ECP group" },
  { 20, "384-bit random ECP group" },
  { 21, "521-bit random ECP group" },
  { 22, "1024-bit MODP Group with 160-bit Prime Order Subgroup" },
  { 23, "2048-bit MODP Group with 224-bit Prime Order Subgroup" },
  { 24, "2048-bit MODP Group with 256-bit Prime Order Subgroup" },
  { 25, "192-bit Random ECP Group" },
  { 26, "224-bit Random ECP Group" },
  { 0,	NULL }
};

static const value_string transform_attr_grp_type[] = {
  { 0,	"UNDEFINED - 0" },
  { 1,	"MODP" },
  { 2,	"ECP" },
  { 3,	"EC2N" },
  { 0,	NULL },
};

#define TF_IKE2_ENCR	1
#define TF_IKE2_PRF	2
#define TF_IKE2_INTEG	3
#define TF_IKE2_DH	4
#define TF_IKE2_ESN	5
static const range_string transform_ike2_type[] = {
  { 0,0,	"RESERVED" },
  { TF_IKE2_ENCR,TF_IKE2_ENCR,	"Encryption Algorithm (ENCR)" },
  { TF_IKE2_PRF,TF_IKE2_PRF,	"Pseudo-random Function (PRF)"},
  { TF_IKE2_INTEG,TF_IKE2_INTEG,"Integrity Algorithm (INTEG)"},
  { TF_IKE2_DH,TF_IKE2_DH,	"Diffie-Hellman Group (D-H)"},
  { TF_IKE2_ESN,TF_IKE2_ESN,	"Extended Sequence Numbers (ESN)"},
  { 6,240,	"Reserved to IANA"},
  { 241,255,	"Private Use"},
  { 0,0,		NULL },
};
/* For Transform Type 1 (Encryption Algorithm), defined Transform IDs */
static const value_string transform_ike2_encr_type[] = {
  { 0,	"RESERVED" },
  { 1,	"ENCR_DES_IV64" },
  { 2,	"ENCR_DES" },
  { 3,	"ENCR_3DES" },
  { 4,	"ENCR_RC5" },
  { 5,	"ENCR_IDEA" },
  { 6,	"ENCR_CAST" },
  { 7,	"ENCR_BLOWFISH" },
  { 8,	"ENCR_3IDEA" },
  { 9,	"ENCR_DES_IV32" },
  { 10,	"RESERVED" },
  { 11,	"ENCR_NULL" },
  { 12,	"ENCR_AES_CBC" },
  { 13,	"ENCR_AES_CTR" },		 		/* [RFC3686] */
  { 14,	"ENCR_AES-CCM_8" },		 		/* [RFC4309] */
  { 15,	"ENCR-AES-CCM_12" },		 		/* [RFC4309] */
  { 16,	"ENCR-AES-CCM_16" },		 		/* [RFC4309] */
  { 17,	"UNASSIGNED" },
  { 18,	"AES-GCM with a 8 octet ICV" },	 		/* [RFC4106] */
  { 19,	"AES-GCM with a 12 octet ICV" },		/* [RFC4106] */
  { 20,	"AES-GCM with a 16 octet ICV" }, 		/* [RFC4106] */
  { 21,	"ENCR_NULL_AUTH_AES_GMAC" },	 		/* [RFC4543] */
  { 22,	"Reserved for IEEE P1619 XTS-AES" },	 	/* [Ball] */
  { 23,	"ENCR_CAMELLIA_CBC" },	 			/* [RFC5529] */
  { 24,	"ENCR_CAMELLIA_CTR" },	 			/* [RFC5529] */
  { 25,	"ENCR_CAMELLIA_CCM with an 8-octet ICV" },	/* [RFC5529] */
  { 26,	"ENCR_CAMELLIA_CCM with a 12-octet ICV" },	/* [RFC5529] */
  { 27,	"ENCR_CAMELLIA_CCM with a 16-octet ICV" },	/* [RFC5529] */
/*
 *		28-1023    RESERVED TO IANA         [RFC4306]
 *		1024-65535    PRIVATE USE           [RFC4306]
 */
    { 0,	NULL },
  };

/* For Transform Type 2 (Pseudo-random Function), defined Transform IDs */
static const value_string transform_ike2_prf_type[] = {
  { 0,	"RESERVED" },
  { 1,	"PRF_HMAC_MD5" },
  { 2,	"PRF_HMAC_SHA1" },
  { 3,	"PRF_HMAC_TIGER" },
  { 4,	"PRF_AES128_CBC" },
  { 5,	"PRF_HMAC_SHA2_256" },		/* [RFC4868] */
  { 6,	"PRF_HMAC_SHA2_384" },		/* [RFC4868] */
  { 7,	"PRF_HMAC_SHA2_512" },		/* [RFC4868] */
  { 8,	"PRF_AES128_CMAC6" },		/* [RFC4615] */
/*
     9-1023    RESERVED TO IANA	   	   [RFC4306]
     1024-65535    PRIVATE USE		   [RFC4306]
*/
  { 0,	NULL },
};

/* For Transform Type 3 (Integrity Algorithm), defined Transform IDs */
static const value_string transform_ike2_integ_type[] = {
  { 0,	"NONE" },
  { 1,	"AUTH_HMAC_MD5_96" },
  { 2,	"AUTH_HMAC_SHA1_96" },
  { 3,	"AUTH_DES_MAC" },
  { 4,	"AUTH_KPDK_MD5" },
  { 5,	"AUTH_AES_XCBC_96" },
  { 6,	"AUTH_HMAC_MD5_128" },		/* [RFC4595] */
  { 7,	"AUTH_HMAC_SHA1_160" },		/* [RFC4595] */
  { 8,	"AUTH_AES_CMAC_96" },		/* [RFC4494] */
  { 9,	"AUTH_AES_128_GMAC" },		/* [RFC4543] */
  { 10,	"AUTH_AES_192_GMAC" },		/* [RFC4543] */
  { 11,	"AUTH_AES_256_GMAC" },		/* [RFC4543] */
  { 12, "AUTH_HMAC_SHA2_256_128" },	/* [RFC4868] */
  { 13, "AUTH_HMAC_SHA2_384_192" },	/* [RFC4868] */
  { 14, "AUTH_HMAC_SHA2_512_256" },	/* [RFC4868] */
/*
 15-1023    RESERVED TO IANA               [RFC4306]
 1024-65535    PRIVATE USE                 [RFC4306]
*/
  { 0,	NULL },
};
/* For Transform Type 5 (Extended Sequence Numbers), defined Transform */
static const value_string transform_ike2_esn_type[] = {
  { 0,	"No Extended Sequence Numbers" },
  { 1,	"Extended Sequence Numbers" },
  { 0,	NULL },
};
/* Transform IKE2 Type */
#define IKE2_ATTR_KEY_LENGTH		14

static const value_string transform_ike2_attr_type[] = {
  { IKE2_ATTR_KEY_LENGTH,		"Key-Length" },
  { 0,	NULL },
};

static const range_string cert_v1_type[] = {
  { 0,0,	"NONE" },
  { 1,1,	"PKCS #7 wrapped X.509 certificate" },
  { 2,2,	"PGP Certificate" },
  { 3,3,	"DNS Signed Key" },
  { 4,4,	"X.509 Certificate - Signature" },
  { 5,5,	"X.509 Certificate - Key Exchange" },
  { 6,6,	"Kerberos Tokens" },
  { 7,7,	"Certificate Revocation List (CRL)" },
  { 8,8,	"Authority Revocation List (ARL)" },
  { 9,9,	"SPKI Certificate" },
  { 10,10,	"X.509 Certificate - Attribute" },
  { 11,255,	"RESERVED" },
  { 0,0,	NULL },
};

static const range_string cert_v2_type[] = {
  { 0,0,	"RESERVED" },
  { 1,1,	"PKCS #7 wrapped X.509 certificate" },
  { 2,2,	"PGP Certificate" },
  { 3,3,	"DNS Signed Key" },
  { 4,4,	"X.509 Certificate - Signature" },
  { 5,5,	"*undefined by any document*" },
  { 6,6,	"Kerberos Tokens" },
  { 7,7,	"Certificate Revocation List (CRL)" },
  { 8,8,	"Authority Revocation List (ARL)" },
  { 9,9,	"SPKI Certificate" },
  { 10,10,	"X.509 Certificate - Attribute" },
  { 11,11,	"Raw RSA Key" },
  { 12,12,	"Hash and URL of X.509 certificate" },
  { 13,13,	"Hash and URL of X.509 bundle" },
  { 14,14,      "OCSP Content" }, 			/* [RFC4806] */
  { 15,200,	"RESERVED to IANA" },
  { 201,255,	"PRIVATE USE" },
  { 0,0,	NULL },
};

static const range_string authmeth_v2_type[] = {
  { 0,0,	"RESERVED TO IANA" },
  { 1,1,	"RSA Digital Signature" },
  { 2,2,	"Shared Key Message Integrity Code" },
  { 3,3,	"DSS Digital Signature" },
  { 4,8,	"RESERVED TO IANA" },
  { 9,9,	"ECDSA with SHA-256 on the P-256 curve" }, /* RFC4754 */
  { 10,10,	"ECDSA with SHA-256 on the P-256 curve" }, /* RFC4754 */
  { 11,11,	"ECDSA with SHA-256 on the P-256 curve" }, /* RFC4754 */
  { 12,12,	"Generic Secure Password Authentication Method" }, /* RFC6467 */
  { 13,200,	"RESERVED TO IANA" },
  { 201,255,	"PRIVATE USE" },
  { 0,0,	NULL },
};

static const range_string notifmsg_v1_type[] = {
  { 0,0,	"<UNKNOWN>" },
  { 1,1,	"INVALID-PAYLOAD-TYPE" },
  { 2,2,	"DOI-NOT-SUPPORTED" },
  { 3,3,	"SITUATION-NOT-SUPPORTED" },
  { 4,4,	"INVALID-COOKIE" },
  { 5,5,	"INVALID-MAJOR-VERSION" },
  { 6,6,	"INVALID-MINOR-VERSION" },
  { 7,7,	"INVALID-EXCHANGE-TYPE" },
  { 8,8,	"INVALID-FLAGS" },
  { 9,9,	"INVALID-MESSAGE-ID" },
  { 10,10,	"INVALID-PROTOCOL-ID" },
  { 11,11,	"INVALID-SPI" },
  { 12,12,	"INVALID-TRANSFORM-ID" },
  { 13,13,	"ATTRIBUTES-NOT-SUPPORTED" },
  { 14,14,	"NO-PROPOSAL-CHOSEN" },
  { 15,15,	"BAD-PROPOSAL-SYNTAX" },
  { 16,16,	"PAYLOAD-MALFORMED" },
  { 17,17,	"INVALID-KEY-INFORMATION" },
  { 18,18,	"INVALID-ID-INFORMATION" },
  { 19,19,	"INVALID-CERT-ENCODING" },
  { 20,20,	"INVALID-CERTIFICATE" },
  { 21,21,	"CERT-TYPE-UNSUPPORTED" },
  { 22,22,	"INVALID-CERT-AUTHORITY" },
  { 23,23,	"INVALID-HASH-INFORMATION" },
  { 24,24,	"AUTHENTICATION-FAILED" },
  { 25,25,	"INVALID-SIGNATURE" },
  { 26,26,	"ADDRESS-NOTIFICATION" },
  { 27,27,	"NOTIFY-SA-LIFETIME" },
  { 28,28,	"CERTIFICATE-UNAVAILABLE" },
  { 29,29,	"UNSUPPORTED-EXCHANGE-TYPE" },
  { 30,30,	"UNEQUAL-PAYLOAD-LENGTHS" },
  { 31,8191,	"RESERVED (Future Use)" },
  { 8192,16383,	"Private Use" },
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
  { 0,0,	NULL },
};

static const range_string notifmsg_v2_type[] = {
  { 0,0,	"RESERVED" },
  { 1,1,	"UNSUPPORTED_CRITICAL_PAYLOAD" },
  { 2,3,	"RESERVED" },
  { 4,4,	"INVALID_IKE_SPI" },
  { 5,5,	"INVALID_MAJOR_VERSION" },
  { 6,6,	"RESERVED" },
  { 7,7,	"INVALID_SYNTAX" },
  { 8,8,	"RESERVED" },
  { 9,9,	"INVALID_MESSAGE_ID" },
  { 10,10,	"RESERVED" },
  { 11,11,	"INVALID_SPI" },
  { 12,13,	"RESERVED" },
  { 14,14,	"NO_PROPOSAL_CHOSEN" },
  { 15,16,	"RESERVED" },
  { 17,17,	"INVALID_KE_PAYLOAD" },
  { 15,16,	"RESERVED" },
  { 24,24,	"AUTHENTICATION_FAILED" },
  { 25,33,	"RESERVED" },
  { 34,34,	"SINGLE_PAIR_REQUIRED" },
  { 35,35,	"NO_ADDITIONAL_SAS" },
  { 36,36,	"INTERNAL_ADDRESS_FAILURE" },
  { 37,37,	"FAILED_CP_REQUIRED" },
  { 38,38,	"TS_UNACCEPTABLE" },
  { 39,39,	"INVALID_SELECTORS" },
  { 40,40,	"UNACCEPTABLE_ADDRESSES" },			/* RFC4555 */
  { 41,41,	"UNEXPECTED_NAT_DETECTED" },			/* RFC4555 */
  { 42,42,	"USE_ASSIGNED_HoA" }, 				/* RFC5026 */
  { 43,43,	"TEMPORARY_FAILURE" }, 				/* RFC5996 */
  { 44,44,	"CHILD_SA_NOT_FOUND" }, 			/* RFC5996 */
  { 45,8191,	"RESERVED TO IANA - Error types" },
  { 8192,16383,	"Private Use - Errors" },
  { 16384,16384,	"INITIAL_CONTACT" },
  { 16385,16385,	"SET_WINDOW_SIZE" },
  { 16386,16386,	"ADDITIONAL_TS_POSSIBLE" },
  { 16387,16387,	"IPCOMP_SUPPORTED" },
  { 16388,16388,	"NAT_DETECTION_SOURCE_IP" },
  { 16389,16389,	"NAT_DETECTION_DESTINATION_IP" },
  { 16390,16390,	"COOKIE" },
  { 16391,16391,	"USE_TRANSPORT_MODE" },
  { 16392,16392,	"HTTP_CERT_LOOKUP_SUPPORTED" },
  { 16393,16393,	"REKEY_SA" },
  { 16394,16394,	"ESP_TFC_PADDING_NOT_SUPPORTED" },
  { 16395,16395,	"NON_FIRST_FRAGMENTS_ALSO" },
  { 16396,16396,	"MOBIKE_SUPPORTED" },			/* RFC4555 */
  { 16397,16397,	"ADDITIONAL_IP4_ADDRESS" },		/* RFC4555 */
  { 16398,16398,	"ADDITIONAL_IP6_ADDRESS" },		/* RFC4555 */
  { 16399,16399,	"NO_ADDITIONAL_ADDRESSES" }, 		/* RFC4555 */
  { 16400,16400,	"UPDATE_SA_ADDRESSES" },  		/* RFC4555 */
  { 16401,16401,	"COOKIE2" }, 				/* RFC4555 */
  { 16402,16402,	"NO_NATS_ALLOWED" },  			/* RFC4555 */
  { 16403,16403,        "AUTH_LIFETIME" },			/* RFC4478 */
  { 16404,16404,        "MULTIPLE_AUTH_SUPPORTED" },		/* RFC4739 */
  { 16405,16405,        "ANOTHER_AUTH_FOLLOWS" },		/* RFC4739 */
  { 16406,16406,        "REDIRECT_SUPPORTED" },			/* RFC5685 */
  { 16407,16407,        "REDIRECT" },				/* RFC5685 */
  { 16408,16408,        "REDIRECTED_FROM" },			/* RFC5685 */
  { 16409,16409,        "TICKET_LT_OPAQUE" },			/* RFC5723 */
  { 16410,16410,        "TICKET_REQUEST" },			/* RFC5723 */
  { 16411,16411,        "TICKET_ACK" },				/* RFC5723 */
  { 16412,16412,        "TICKET_NACK" },			/* RFC5723 */
  { 16413,16413,        "TICKET_OPAQUE" },			/* RFC5723 */
  { 16414,16414,        "LINK_ID" },				/* RFC5739 */
  { 16415,16415,        "USE_WESP_MODE" },			/* RFC5840 */
  { 16416,16416,        "ROHC_SUPPORTED" },			/* RFC5857 */
  { 16417,16417,        "EAP_ONLY_AUTHENTICATION" },		/* RFC5998 */
  { 16418,16418,        "CHILDLESS_IKEV2_SUPPORTED" },		/* RFC6023 */
  { 16419,16419,        "QUICK_CRASH_DETECTION" },              /* RFC6290 */
  { 16420,16420,        "IKEV2_MESSAGE_ID_SYNC_SUPPORTED" },    /* RFC6311 */
  { 16421,16421,        "IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED" },/* RFC6311 */
  { 16422,16422,        "IKEV2_MESSAGE_ID_SYNC" },              /* RFC6311 */
  { 16423,16423,        "IPSEC_REPLAY_COUNTER_SYNC" },          /* RFC6311 */
  { 16424,16424,        "SECURE_PASSWORD_METHODS" },            /* RFC6467 */
  { 16425,40959,        "RESERVED TO IANA - STATUS TYPES" },
  { 40960,65535,        "Private Use - STATUS TYPES" },
  { 0,0,	NULL },
};

static const range_string vs_v1_cfgtype[] = {
  { 0,0,	"Reserved" },
  { 1,1,	"ISAKMP_CFG_REQUEST" },
  { 2,2,	"ISAKMP_CFG_REPLY" },
  { 3,3,	"ISAKMP_CFG_SET" },
  { 4,4,	"ISAKMP_CFG_ACK" },
  { 5,127,	"Future use"	},
  { 128,256,    "Private Use"	},
  { 0,0,	NULL },
  };


static const range_string vs_v2_cfgtype[] = {
  { 0,0,	"RESERVED" },
  { 1,1,	"CFG_REQUEST" },
  { 2,2,	"CFG_REPLY" },
  { 3,3,	"CFG_SET" },
  { 4,4,	"CFG_ACK" },
  { 5,127,	"Future use"	},
  { 128,256,    "Private Use"	},
  { 0,0,	NULL },
  };

static const range_string vs_v1_cfgattr[] = {
  { 0,0,	 "RESERVED" },
  { 1,1,	 "INTERNAL_IP4_ADDRESS" },
  { 2,2,	 "INTERNAL_IP4_NETMASK" },
  { 3,3,	 "INTERNAL_IP4_DNS" },
  { 4,4,	 "INTERNAL_IP4_NBNS" },
  { 5,5,	 "INTERNAL_ADDRESS_EXPIREY" },
  { 6,6,	 "INTERNAL_IP4_DHCP" },
  { 7,7,	 "APPLICATION_VERSION" },
  { 8,8,	 "INTERNAL_IP6_ADDRESS" },
  { 9,9,	 "INTERNAL_IP6_NETMASK" },
  { 10,10,	 "INTERNAL_IP6_DNS" },
  { 11,11,	 "INTERNAL_IP6_NBNS" },
  { 12,12,	 "INTERNAL_IP6_DHCP" },
  { 13,13,	 "INTERNAL_IP4_SUBNET" },
  { 14,14,	 "SUPPORTED_ATTRIBUTES" },
  { 15,16383,    "FUTURE USE"},
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
  { 0,0,	 NULL },
  };

static const range_string vs_v2_cfgattr[] = {
  { 0,0,	 "RESERVED" },
  { 1,1,	 "INTERNAL_IP4_ADDRESS" },
  { 2,2,	 "INTERNAL_IP4_NETMASK" },
  { 3,3,	 "INTERNAL_IP4_DNS" },
  { 4,4,	 "INTERNAL_IP4_NBNS" },
  { 5,5,	 "INTERNAL_ADDRESS_EXPIREY" },	/* OBSO */
  { 6,6,	 "INTERNAL_IP4_DHCP" },
  { 7,7,	 "APPLICATION_VERSION" },
  { 8,8,	 "INTERNAL_IP6_ADDRESS" },
  { 9,9, 	 "RESERVED" },
  { 10,10,	 "INTERNAL_IP6_DNS" },
  { 11,11,	 "INTERNAL_IP6_NBNS" }, 	/* OBSO */
  { 12,12,	 "INTERNAL_IP6_DHCP" },
  { 13,13,	 "INTERNAL_IP4_SUBNET" },
  { 14,14,	 "SUPPORTED_ATTRIBUTES" },
  { 15,15, 	 "INTERNAL_IP6_SUBNET" },
  { 16,16,       "MIP6_HOME_PREFIX" },
  { 17,17,       "INTERNAL_IP6_LINK" },
  { 18,18,       "INTERNAL_IP6_PREFIX" },
  { 19,19,       "HOME_AGENT_ADDRESS" },	/* 3GPP TS 24.302 http://www.3gpp.org/ftp/Specs/html-info/24302.htm */
  { 20,16383,    "RESERVED TO IANA"},
  { 16384,32767, "PRIVATE USE"},
  { 0,0,   	  NULL },
  };

static const range_string cfgattr_xauth_type[] = {
  { 0,0,	 "Generic" },
  { 1,1,	 "RADIUS-CHAP" },
  { 2,2,	 "OTP" },
  { 3,3,	 "S/KEY" },
  { 4,32767,	 "Future use" },
  { 32768,65535, "Private use" },
  { 0,0,   	  NULL },
  };


static const value_string cfgattr_xauth_status[] = {
  { 0,	"Fail" },
  { 1,	"Success" },
  { 0,	NULL },
};

static const value_string cp_product[] = {
  { 1,	"Firewall-1" },
  { 2,	"SecuRemote/SecureClient" },
  { 0,	NULL },
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
  { 0,	NULL },
};
static const range_string traffic_selector_type[] = {
  { 0,6,	"Reserved" },
  { 7,7,	"TS_IPV4_ADDR_RANGE" },
  { 8,8,	"TS_IPV6_ADDR_RANGE" },
  { 9,9,	"TS_FC_ADDR_RANGE" },
  { 10,240,	"Future use" },
  { 241,255,	"Private use" },
  { 0,0,   	  NULL },
  };
static const value_string ms_nt5_isakmpoakley_type[] = {
  { 2, "Windows 2000" },
  { 3, "Windows XP SP1" },
  { 4, "Windows 2003 and Windows XP SP2" },
  { 5, "Windows Vista" },
  { 0, NULL }
};
static const range_string vs_v1_id_type[] = {
  { 0,0,						"RESERVED" },
  { IKE_ID_IPV4_ADDR,IKE_ID_IPV4_ADDR,			"IPV4_ADDR" },
  { IKE_ID_FQDN,IKE_ID_FQDN,				"FQDN" },
  { IKE_ID_USER_FQDN,IKE_ID_USER_FQDN,			"USER_FQDN" },
  { IKE_ID_IPV4_ADDR_SUBNET,IKE_ID_IPV4_ADDR_SUBNET,	"IPV4_ADDR_SUBNET" },
  { IKE_ID_IPV6_ADDR,IKE_ID_IPV6_ADDR,			"IPV6_ADDR" },
  { IKE_ID_IPV6_ADDR_SUBNET,IKE_ID_IPV6_ADDR_SUBNET,	"IPV6_ADDR_SUBNET" },
  { IKE_ID_IPV4_ADDR_RANGE,IKE_ID_IPV4_ADDR_RANGE,	"IPV4_ADDR_RANGE" },
  { IKE_ID_IPV6_ADDR_RANGE,IKE_ID_IPV6_ADDR_RANGE,	"IPV6_ADDR_RANGE" },
  { IKE_ID_DER_ASN1_DN,IKE_ID_DER_ASN1_DN,		"DER_ASN1_DN" },
  { IKE_ID_DER_ASN1_GN,IKE_ID_DER_ASN1_GN,		"DER_ASN1_GN" },
  { IKE_ID_KEY_ID,IKE_ID_KEY_ID,			"KEY_ID" },
  { IKE_ID_LIST,IKE_ID_LIST,				"KEY_LIST" },
  { 13,248,						"Future use" },
  { 249,255,						"Private Use" },
  { 0,0,   	  NULL },
  };
static const range_string vs_v2_id_type[] = {
  { 0,0,						"RESERVED" },
  { IKE_ID_IPV4_ADDR,IKE_ID_IPV4_ADDR,			"IPV4_ADDR" },
  { IKE_ID_FQDN,IKE_ID_FQDN,				"FQDN" },
  { IKE_ID_RFC822_ADDR,IKE_ID_RFC822_ADDR,		"ID_RFC822_ADDR" },
  { 4,4,						"Unassigned" },
  { IKE_ID_IPV6_ADDR,IKE_ID_IPV6_ADDR,			"IPV6_ADDR" },
  { 6,8,						"Unassigned" },
  { IKE_ID_DER_ASN1_DN,IKE_ID_DER_ASN1_DN,		"DER_ASN1_DN" },
  { IKE_ID_DER_ASN1_GN,IKE_ID_DER_ASN1_GN,		"DER_ASN1_GN" },
  { IKE_ID_KEY_ID,IKE_ID_KEY_ID,			"KEY_ID" },
  { IKE_ID_FC_NAME,IKE_ID_FC_NAME,			"KEY_LIST" },
  { 13,200,						"Future use" },
  { 201,255,						"Private Use" },
  { 0,0,   	  NULL },
  };
#define COOKIE_SIZE 8

typedef struct isakmp_hdr {
  guint8	next_payload;
  guint8	version;
  guint8	exch_type;
  guint8	flags;
#define E_FLAG		0x01
#define C_FLAG		0x02
#define A_FLAG		0x04
#define I_FLAG		0x08
#define V_FLAG		0x10
#define R_FLAG		0x20
  guint32	message_id;
  guint32	length;
} isakmp_hdr_t;

static const true_false_string criticalpayload = {
  "Critical",
  "Not Critical"
};
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
static const true_false_string flag_r = {
  "Response",
  "Request"
};

/* ROHC Attribute Type RFC5857 */

#define ROHC_MAX_CID		1
#define ROHC_PROFILE		2
#define ROHC_INTEG		3
#define ROHC_ICV_LEN		4
#define ROHC_MRRU		5

static const value_string rohc_attr_type[] = {
  { ROHC_MAX_CID,	"Maximum Context Identifier (MAX_CID)" },
  { ROHC_PROFILE,	"ROHC Profile (ROHC_PROFILE)" },
  { ROHC_INTEG,		"ROHC Integrity Algorithm (ROHC_INTEG)" },
  { ROHC_ICV_LEN,	"ROHC ICV Length in bytes (ROHC_ICV_LEN)" },
  { ROHC_MRRU,		"Maximum Reconstructed Reception Unit (MRRU)" },
  { 0,	NULL },
};

#define ISAKMP_HDR_SIZE (sizeof(struct isakmp_hdr) + (2 * COOKIE_SIZE))


#ifdef HAVE_LIBGCRYPT

#define MAX_KEY_SIZE       256
#define MAX_DIGEST_SIZE     64
#define MAX_OAKLEY_KEY_LEN  32

typedef struct _ikev1_uat_data_key {
  guchar *icookie;
  guint icookie_len;
  guchar *key;
  guint key_len;
} ikev1_uat_data_key_t;

typedef struct iv_data {
  guchar  iv[MAX_DIGEST_SIZE];
  guint   iv_len;
  guint32 frame_num;
} iv_data_t;

typedef struct decrypt_data {
  gboolean       is_psk;
  address	 initiator;
  guint          encr_alg;
  guint          hash_alg;
  guint          group;
  gchar         *gi;
  guint          gi_len;
  gchar         *gr;
  guint          gr_len;
  guchar         secret[MAX_KEY_SIZE];
  guint          secret_len;
  GList         *iv_list;
  gchar          last_cbc[MAX_DIGEST_SIZE];
  guint          last_cbc_len;
  gchar          last_p1_cbc[MAX_DIGEST_SIZE];
  guint          last_p1_cbc_len;
  guint32        last_message_id;
} decrypt_data_t;

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
} ikev2_encr_alg_spec_t;

#define IKEV2_ENCR_NULL        1
#define IKEV2_ENCR_3DES        2
#define IKEV2_ENCR_AES_CBC_128 3
#define IKEV2_ENCR_AES_CBC_192 4
#define IKEV2_ENCR_AES_CBC_256 5

static ikev2_encr_alg_spec_t ikev2_encr_algs[] = {
  {IKEV2_ENCR_NULL, 0, 1, 0, GCRY_CIPHER_NONE, GCRY_CIPHER_MODE_NONE},
  {IKEV2_ENCR_3DES, 24, 8, 8, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC},
  {IKEV2_ENCR_AES_CBC_128, 16, 16, 16, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC},
  {IKEV2_ENCR_AES_CBC_192, 24, 16, 16, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CBC},
  {IKEV2_ENCR_AES_CBC_256, 32, 16, 16, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC},
  {0, 0, 0, 0, 0, 0}
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
#define IKEV2_AUTH_ANY_96BITS   4
#define IKEV2_AUTH_ANY_128BITS  5
#define IKEV2_AUTH_ANY_160BITS  6
#define IKEV2_AUTH_ANY_192BITS  7
#define IKEV2_AUTH_ANY_256BITS  8

static ikev2_auth_alg_spec_t ikev2_auth_algs[] = {
  {IKEV2_AUTH_NONE, 0, 0, 0, GCRY_MD_NONE, 0},
  {IKEV2_AUTH_HMAC_MD5_96, 16, 16, 12, GCRY_MD_MD5, GCRY_MD_FLAG_HMAC},
  {IKEV2_AUTH_HMAC_SHA1_96, 20, 20, 12, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC},
  {IKEV2_AUTH_ANY_96BITS, 0, 0, 12, 0, 0},
  {IKEV2_AUTH_ANY_128BITS, 0, 0, 16, 0, 0},
  {IKEV2_AUTH_ANY_160BITS, 0, 0, 20, 0, 0},
  {IKEV2_AUTH_ANY_192BITS, 0, 0, 24, 0, 0},
  {IKEV2_AUTH_ANY_256BITS, 0, 0, 32, 0, 0},
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

static GHashTable *ikev2_key_hash = NULL;

#define IKEV2_ENCR_3DES_STR "3DES [RFC2451]"
static const value_string vs_ikev2_encr_algs[] = {
  {IKEV2_ENCR_3DES,        IKEV2_ENCR_3DES_STR},
  {IKEV2_ENCR_AES_CBC_128, "AES-CBC-128 [RFC3602]"},
  {IKEV2_ENCR_AES_CBC_192, "AES-CBC-192 [RFC3602]"},
  {IKEV2_ENCR_AES_CBC_256, "AES-CBC-256 [RFC3602]"},
  {IKEV2_ENCR_NULL,        "NULL [RFC2410]"},
  {0, NULL}
};

#define IKEV2_AUTH_HMAC_SHA1_96_STR "HMAC_SHA1_96 [RFC2404]"
static const value_string vs_ikev2_auth_algs[] = {
  {IKEV2_AUTH_HMAC_MD5_96,  "HMAC_MD5_96 [RFC2403]"},
  {IKEV2_AUTH_HMAC_SHA1_96, IKEV2_AUTH_HMAC_SHA1_96_STR},
  {IKEV2_AUTH_NONE,         "NONE [RFC4306]"},
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

static tvbuff_t *
decrypt_payload(tvbuff_t *tvb, packet_info *pinfo, const guint8 *buf, guint buf_len, isakmp_hdr_t *hdr) {
  decrypt_data_t *decr = (decrypt_data_t *) pinfo->private_data;
  guint8 *decrypted_data = NULL;
  gint gcry_md_algo, gcry_cipher_algo;
  gcry_md_hd_t md_ctx;
  gcry_cipher_hd_t decr_ctx;
  tvbuff_t *encr_tvb;
  iv_data_t *ivd = NULL;
  GList *ivl;
  guchar iv[MAX_DIGEST_SIZE];
  guint iv_len = 0;
  guint32 message_id, cbc_block_size, digest_size;

  if (!decr ||
      decr->is_psk == FALSE ||
      decr->gi_len == 0 ||
      decr->gr_len == 0)
    return NULL;

  switch(decr->encr_alg) {
    case ENC_3DES_CBC:
      gcry_cipher_algo = GCRY_CIPHER_3DES;
      break;
    case ENC_DES_CBC:
      gcry_cipher_algo = GCRY_CIPHER_DES;
      break;
    default:
      return NULL;
      break;
  }
  if (decr->secret_len < gcry_cipher_get_algo_keylen(gcry_cipher_algo))
    return NULL;
  cbc_block_size = (guint32) gcry_cipher_get_algo_blklen(gcry_cipher_algo);
  if (cbc_block_size > MAX_DIGEST_SIZE) {
    /* This shouldn't happen but we pass cbc_block_size to memcpy size below. */
    return NULL;
  }

  switch(decr->hash_alg) {
    case HMAC_MD5:
      gcry_md_algo = GCRY_MD_MD5;
      break;
    case HMAC_SHA:
      gcry_md_algo = GCRY_MD_SHA1;
      break;
    default:
      return NULL;
      break;
  }
  digest_size = gcry_md_get_algo_dlen(gcry_md_algo);

  for (ivl = g_list_first(decr->iv_list); ivl != NULL; ivl = g_list_next(ivl)) {
    ivd = (iv_data_t *) ivl->data;
    if (ivd->frame_num == pinfo->fd->num) {
      iv_len = ivd->iv_len;
      memcpy(iv, ivd->iv, iv_len);
    }
  }

  /*
   * Set our initialization vector as follows:
   * - If the IV list is empty, assume we have the first packet in a phase 1
   *   exchange.  The IV is built from DH values.
   * - If our message ID changes, assume we're entering a new mode.  The IV
   *   is built from the message ID and the last phase 1 CBC.
   * - Otherwise, use the last CBC.
   */
  if (iv_len == 0) {
    if (gcry_md_open(&md_ctx, gcry_md_algo, 0) != GPG_ERR_NO_ERROR)
      return NULL;
    if (decr->iv_list == NULL) {
      /* First packet */
      ivd = g_malloc(sizeof(iv_data_t));
      ivd->frame_num = pinfo->fd->num;
      ivd->iv_len = digest_size;
      decr->last_message_id = hdr->message_id;
      gcry_md_reset(md_ctx);
      gcry_md_write(md_ctx, decr->gi, decr->gi_len);
      gcry_md_write(md_ctx, decr->gr, decr->gr_len);
      gcry_md_final(md_ctx);
      memcpy(ivd->iv, gcry_md_read(md_ctx, gcry_md_algo), digest_size);
      decr->iv_list = g_list_append(decr->iv_list, ivd);
      iv_len = ivd->iv_len;
      memcpy(iv, ivd->iv, iv_len);
    } else if (decr->last_cbc_len >= cbc_block_size) {
      ivd = g_malloc(sizeof(iv_data_t));
      ivd->frame_num = pinfo->fd->num;
      if (hdr->message_id != decr->last_message_id) {
	if (decr->last_p1_cbc_len == 0) {
	  memcpy(decr->last_p1_cbc, decr->last_cbc, cbc_block_size);
	  decr->last_p1_cbc_len = cbc_block_size;
        }
        ivd->iv_len = digest_size;
	decr->last_message_id = hdr->message_id;
	message_id = g_htonl(decr->last_message_id);
        gcry_md_reset(md_ctx);
        gcry_md_write(md_ctx, decr->last_p1_cbc, cbc_block_size);
        gcry_md_write(md_ctx, &message_id, sizeof(message_id));
        memcpy(ivd->iv, gcry_md_read(md_ctx, gcry_md_algo), digest_size);
      } else {
        ivd->iv_len = cbc_block_size;
        memcpy(ivd->iv, decr->last_cbc, ivd->iv_len);
      }
      decr->iv_list = g_list_append(decr->iv_list, ivd);
      iv_len = ivd->iv_len;
      memcpy(iv, ivd->iv, iv_len);
    }
    gcry_md_close(md_ctx);
  }

  if (ivd == NULL) return NULL;

  if (gcry_cipher_open(&decr_ctx, gcry_cipher_algo, GCRY_CIPHER_MODE_CBC, 0) != GPG_ERR_NO_ERROR)
    return NULL;
  if (iv_len > cbc_block_size)
      iv_len = cbc_block_size; /* gcry warns otherwise */
  if (gcry_cipher_setiv(decr_ctx, iv, iv_len))
    return NULL;
  if (gcry_cipher_setkey(decr_ctx, decr->secret, decr->secret_len))
    return NULL;

  decrypted_data = g_malloc(buf_len);

  if (gcry_cipher_decrypt(decr_ctx, decrypted_data, buf_len, buf, buf_len) != GPG_ERR_NO_ERROR) {
    g_free(decrypted_data);
    return NULL;
  }
  gcry_cipher_close(decr_ctx);

  encr_tvb = tvb_new_child_real_data(tvb, decrypted_data, buf_len, buf_len);
  tvb_set_free_cb(encr_tvb, g_free);

  /* Add the decrypted data to the data source list. */
  add_new_data_source(pinfo, encr_tvb, "Decrypted IKE");

  /* Fill in the next IV */
  if (tvb_length(tvb) > cbc_block_size) {
    decr->last_cbc_len = cbc_block_size;
    memcpy(decr->last_cbc, buf + buf_len - cbc_block_size, cbc_block_size);
  } else {
    decr->last_cbc_len = 0;
  }

  return encr_tvb;
}

#endif /* HAVE_LIBGCRYPT */

static proto_tree *dissect_payload_header(tvbuff_t *, int, int, int, guint8,
    guint8 *, guint16 *, proto_tree *);

static void dissect_sa(tvbuff_t *, int, int, proto_tree *, int, packet_info *);
static void dissect_proposal(tvbuff_t *, int, int, proto_tree *, int, packet_info *);
static void dissect_transform(tvbuff_t *, int, int, proto_tree *, packet_info *, int, int);
static void dissect_key_exch(tvbuff_t *, int, int, proto_tree *, int, packet_info *);
static void dissect_id(tvbuff_t *, int, int, proto_tree *, int, packet_info *);
static void dissect_cert(tvbuff_t *, int, int, proto_tree *, int, packet_info *);
static void dissect_certreq(tvbuff_t *, int, int, proto_tree *, int, packet_info *);
static void dissect_auth(tvbuff_t *, int, int, proto_tree *);
static void dissect_hash(tvbuff_t *, int, int, proto_tree *);
static void dissect_sig(tvbuff_t *, int, int, proto_tree *);
static void dissect_nonce(tvbuff_t *, int, int, proto_tree *);
static void dissect_notif(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_delete(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_vid(tvbuff_t *, int, int, proto_tree *);
static void dissect_config(tvbuff_t *, int, int, proto_tree *, int);
static void dissect_nat_discovery(tvbuff_t *, int, int, proto_tree * );
static void dissect_nat_original_address(tvbuff_t *, int, int, proto_tree *, int );
static void dissect_ts(tvbuff_t *, int, int, proto_tree *);
static void dissect_enc(tvbuff_t *, int, int, proto_tree *, packet_info *, guint8);
static void dissect_eap(tvbuff_t *, int, int, proto_tree *, packet_info *);
static void dissect_gspm(tvbuff_t *, int, int, proto_tree *);
static void dissect_cisco_fragmentation(tvbuff_t *, int, int, proto_tree *, packet_info *);

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

static const guint8 VID_MS_L2TP_IPSEC_VPN_CLIENT[]= { /* Microsoft L2TP/IPSec VPN Client */
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

static const guint8 VID_CP[] = { /* Check Point */
	0xF4, 0xED, 0x19, 0xE0, 0xC1, 0x14, 0xEB, 0x51,
	0x6F, 0xAA, 0xAC, 0x0E, 0xE3, 0x7D, 0xAF, 0x28,
	0x7, 0xB4, 0x38, 0x1F
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

/* Based from value_string.c/h */
static const byte_string vendor_id[] = {
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
  { VID_MS_L2TP_IPSEC_VPN_CLIENT, sizeof(VID_MS_L2TP_IPSEC_VPN_CLIENT), "Microsoft L2TP/IPSec VPN Client" },
  { VID_MS_VID_INITIAL_CONTACT, sizeof(VID_MS_VID_INITIAL_CONTACT), "Microsoft Vid-Initial-Contact" },
  { VID_GSS_API_1, sizeof(VID_GSS_API_1), "A GSS-API Authentication Method for IKE" },
  { VID_GSS_API_2, sizeof(VID_GSS_API_2), "A GSS-API Authentication Method for IKE" },
  { VID_GSSAPI, sizeof(VID_GSSAPI), "GSSAPI" },
  { VID_MS_NT5_ISAKMPOAKLEY, sizeof(VID_MS_NT5_ISAKMPOAKLEY), "MS NT5 ISAKMPOAKLEY" },
  { VID_CISCO_UNITY, sizeof(VID_CISCO_UNITY), "CISCO-UNITY" },
  { VID_CISCO_CONCENTRATOR, sizeof(VID_CISCO_CONCENTRATOR), "CISCO-CONCENTRATOR" },
  { VID_CISCO_FRAG, sizeof(VID_CISCO_FRAG), "Cisco Fragmentation" },
  { VID_CP, sizeof(VID_CP), "Check Point" },
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
  { 0, 0, NULL }
};


/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr, and sets "*idx" to the index in
   that table, on a match, and returns NULL, and sets "*idx" to -1,
   on failure. */
static const gchar*
match_strbyte_idx(const guint8 *val, const gint val_len, const byte_string *vs, gint *idx) {
  gint i = 0;

  if (vs) {
    while (vs[i].strptr) {
      if (val_len >= vs[i].len && !memcmp(vs[i].value, val, vs[i].len)) {
        *idx = i;
        return(vs[i].strptr);
      }
      i++;
    }
  }

  *idx = -1;
  return NULL;
}
/* Like match_strbyte_idx(), but doesn't return the index. */
static const gchar*
match_strbyte(const guint8 *val,const gint val_len, const byte_string *vs) {
    gint ignore_me;
    return match_strbyte_idx(val, val_len, vs, &ignore_me);
}

/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr on a match.
   Formats val with fmt, and returns the resulting string, on failure. */
static const gchar*
byte_to_str(const guint8 *val,const gint val_len, const byte_string *vs, const char *fmt) {
  const gchar *ret;

  DISSECTOR_ASSERT(fmt != NULL);
  ret = match_strbyte(val, val_len, vs);
  if (ret != NULL)
    return ret;

  return ep_strdup_printf(fmt, val);
}




static void
dissect_payloads(tvbuff_t *tvb, proto_tree *tree, proto_tree *parent_tree _U_,
		int isakmp_version, guint8 initial_payload, int offset, int length,
		packet_info *pinfo)
{
  guint8 payload, next_payload;
  guint16		payload_length;
  proto_tree *		ntree;

 for (payload = initial_payload; length > 0; payload = next_payload) {
    if (payload == PLOAD_IKE_NONE) {
      /*
       * What?  There's more stuff in this chunk of data, but the
       * previous payload had a "next payload" type of None?
       */
      proto_tree_add_item(tree, hf_isakmp_extradata, tvb, offset, length, ENC_NA);
      break;
    }

    ntree = dissect_payload_header(tvb, offset, length, isakmp_version, payload, &next_payload, &payload_length, tree);
    if (ntree == NULL)
      break;
    if (payload_length >= 4) {	/* XXX = > 4? */
      tvb_ensure_bytes_exist(tvb, offset + 4, payload_length - 4);
	switch(payload){
	   case PLOAD_IKE_SA:
	   case PLOAD_IKE2_SA:
	   dissect_sa(tvb, offset + 4, payload_length - 4, ntree, isakmp_version, pinfo );
	   break;
	   case PLOAD_IKE_P:
	   dissect_proposal(tvb, offset + 4, payload_length - 4, ntree, isakmp_version, pinfo );
	   break;
	   case PLOAD_IKE_KE:
	   case PLOAD_IKE2_KE:
	   dissect_key_exch(tvb, offset + 4, payload_length - 4, ntree, isakmp_version, pinfo );
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
	   dissect_notif(tvb, offset + 4, payload_length - 4, ntree, isakmp_version);
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
	   dissect_config(tvb, offset + 4, payload_length - 4, ntree, isakmp_version);
	   break;
	   case PLOAD_IKE2_AUTH:
	   dissect_auth(tvb, offset + 4, payload_length - 4, ntree);
	   break;
	   case PLOAD_IKE2_TSI:
	   case PLOAD_IKE2_TSR:
	   dissect_ts(tvb, offset + 4, payload_length - 4, ntree);
	   break;
	   case PLOAD_IKE2_SK:
	   if(isakmp_version == 2)
	     dissect_enc(tvb, offset + 4, payload_length - 4, ntree, pinfo, next_payload);
	   break;
	   case PLOAD_IKE2_EAP:
	   dissect_eap(tvb, offset + 4, payload_length - 4, ntree, pinfo );
	   break;
	   case PLOAD_IKE2_GSPM:
	   dissect_gspm(tvb, offset + 4, payload_length - 4, ntree);
	   break;
	   case PLOAD_IKE_NAT_D:
	   case PLOAD_IKE_NAT_D13:
	   case PLOAD_IKE_NAT_D48:
	   dissect_nat_discovery(tvb, offset + 4, payload_length - 4, ntree );
	   break;
	   case PLOAD_IKE_NAT_OA:
	   case PLOAD_IKE_NAT_OA14:
	   case PLOAD_IKE_NAT_OA58:
	   dissect_nat_original_address(tvb, offset + 4, payload_length - 4, ntree, isakmp_version );
	   break;
	   case PLOAD_IKE_CISCO_FRAG:
	   dissect_cisco_fragmentation(tvb, offset + 4, payload_length - 4, ntree, pinfo );
	   break;
	   default:
	   proto_tree_add_item(ntree, hf_isakmp_datapayload, tvb, offset + 4, payload_length-4, ENC_NA);
	   break;
       }

    }
    else if (payload_length > length) {
        proto_tree_add_text(ntree, tvb, 0, 0,
                            "Payload (bogus, length is %u, greater than remaining length %d",
                            payload_length, length);
        return;
    }
    else {
        proto_tree_add_text(ntree, tvb, 0, 0,
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
  dissect_payloads(tvb, tree, tree, isakmp_version, initial_payload, offset, length,
		   pinfo);
}

static void
dissect_isakmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int			offset = 0, len;
  isakmp_hdr_t	hdr;
  proto_item *	ti;
  proto_tree *	isakmp_tree = NULL;
  int			isakmp_version;
#ifdef HAVE_LIBGCRYPT
  guint8                i_cookie[COOKIE_SIZE], *ic_key;
  decrypt_data_t       *decr = NULL;
  tvbuff_t             *decr_tvb;
  proto_tree           *decr_tree;
  address               null_addr;
  void                 *pd_save = NULL;
  gboolean             pd_changed = FALSE;
#endif /* HAVE_LIBGCRYPT */

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISAKMP");
  col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_isakmp, tvb, offset, -1, ENC_NA);
    isakmp_tree = proto_item_add_subtree(ti, ett_isakmp);
  }

  /* RFC3948 2.3 NAT Keepalive packet:
   * 1 byte payload with the value 0xff.
   */
  if ( (tvb_length(tvb)==1) && (tvb_get_guint8(tvb, offset)==0xff) ){
    col_set_str(pinfo->cinfo, COL_INFO, "NAT Keepalive");
    proto_tree_add_item(isakmp_tree, hf_isakmp_nat_keepalive, tvb, offset, 1, ENC_NA);
    return;
  }

  hdr.length = tvb_get_ntohl(tvb, offset + ISAKMP_HDR_SIZE - 4);
  hdr.exch_type = tvb_get_guint8(tvb, COOKIE_SIZE + COOKIE_SIZE + 1 + 1);
  hdr.version = tvb_get_guint8(tvb, COOKIE_SIZE + COOKIE_SIZE + 1);
  isakmp_version = hi_nibble(hdr.version);	/* save the version */
  hdr.flags = tvb_get_guint8(tvb, COOKIE_SIZE + COOKIE_SIZE + 1 + 1 + 1);

#ifdef HAVE_LIBGCRYPT
  if (isakmp_version == 1) {
    SET_ADDRESS(&null_addr, AT_NONE, 0, NULL);

    tvb_memcpy(tvb, i_cookie, offset, COOKIE_SIZE);
    decr = (decrypt_data_t*) g_hash_table_lookup(isakmp_hash, i_cookie);

    if (! decr) {
      ic_key = g_slice_alloc(COOKIE_SIZE);
      decr   = g_slice_alloc(sizeof(decrypt_data_t));
      memcpy(ic_key, i_cookie, COOKIE_SIZE);
      memset(decr, 0, sizeof(decrypt_data_t));
      SET_ADDRESS(&decr->initiator, AT_NONE, 0, NULL);

      g_hash_table_insert(isakmp_hash, ic_key, decr);
    }

    if (ADDRESSES_EQUAL(&decr->initiator, &null_addr)) {
      /* XXX - We assume that we're seeing the second packet in an exchange here.
       * Is there a way to verify this? */
      SE_COPY_ADDRESS(&decr->initiator, &pinfo->src);
    }

    pd_save = pinfo->private_data;
    pinfo->private_data = decr;
    pd_changed = TRUE;
  } else if (isakmp_version == 2) {
    ikev2_uat_data_key_t hash_key;
    ikev2_uat_data_t *ike_sa_data = NULL;
    ikev2_decrypt_data_t *ikev2_dec_data;
    guchar spii[COOKIE_SIZE], spir[COOKIE_SIZE];

    tvb_memcpy(tvb, spii, offset, COOKIE_SIZE);
    tvb_memcpy(tvb, spir, offset + COOKIE_SIZE, COOKIE_SIZE);
    hash_key.spii = spii;
    hash_key.spir = spir;
    hash_key.spii_len = COOKIE_SIZE;
    hash_key.spir_len = COOKIE_SIZE;

    ike_sa_data = g_hash_table_lookup(ikev2_key_hash, &hash_key);
    if (ike_sa_data) {
      guint8 initiator_flag;
      initiator_flag = hdr.flags & I_FLAG;
      ikev2_dec_data = ep_alloc(sizeof(ikev2_decrypt_data_t));
      ikev2_dec_data->encr_key = initiator_flag ? ike_sa_data->sk_ei : ike_sa_data->sk_er;
      ikev2_dec_data->auth_key = initiator_flag ? ike_sa_data->sk_ai : ike_sa_data->sk_ar;
      ikev2_dec_data->encr_spec = ike_sa_data->encr_spec;
      ikev2_dec_data->auth_spec = ike_sa_data->auth_spec;

      pd_save = pinfo->private_data;
      pinfo->private_data = ikev2_dec_data;
      pd_changed = TRUE;
    }
  }
#endif /* HAVE_LIBGCRYPT */

  if (tree) {
    proto_tree_add_item(isakmp_tree, hf_isakmp_icookie, tvb, offset, COOKIE_SIZE, ENC_NA);
    offset += COOKIE_SIZE;

    proto_tree_add_item(isakmp_tree, hf_isakmp_rcookie, tvb, offset, COOKIE_SIZE, ENC_NA);
    offset += COOKIE_SIZE;

    hdr.next_payload = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(isakmp_tree,  hf_isakmp_nextpayload, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;

    proto_tree_add_uint_format(isakmp_tree, hf_isakmp_version, tvb, offset,
                               1, hdr.version, "Version: %u.%u",
                               hi_nibble(hdr.version), lo_nibble(hdr.version));
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
      proto_item *	fti;
      proto_tree *	ftree;

      fti   = proto_tree_add_item(isakmp_tree, hf_isakmp_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
      ftree = proto_item_add_subtree(fti, ett_isakmp_flags);

      if (isakmp_version == 1) {
        proto_tree_add_item(ftree, hf_isakmp_flag_e, tvb, offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(ftree, hf_isakmp_flag_c, tvb, offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(ftree, hf_isakmp_flag_a, tvb, offset, 1, ENC_BIG_ENDIAN);

      } else if (isakmp_version == 2) {
        proto_tree_add_item(ftree, hf_isakmp_flag_i, tvb, offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(ftree, hf_isakmp_flag_v, tvb, offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(ftree, hf_isakmp_flag_r, tvb, offset, 1, ENC_BIG_ENDIAN);

      }
      offset += 1;
    }

    hdr.message_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(isakmp_tree, hf_isakmp_messageid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (hdr.length < ISAKMP_HDR_SIZE) {
      proto_tree_add_uint_format(isakmp_tree, hf_isakmp_length, tvb, offset, 4,
                                 hdr.length, "Length: (bogus, length is %u, should be at least %lu)",
                                 hdr.length, (unsigned long)ISAKMP_HDR_SIZE);
#ifdef HAVE_LIBGCRYPT
      if (pd_changed) pinfo->private_data = pd_save;
#endif /* HAVE_LIBGCRYPT */
      return;
    }

    len = hdr.length - ISAKMP_HDR_SIZE;

    if (len < 0) {
      proto_tree_add_uint_format(isakmp_tree, hf_isakmp_length, tvb, offset, 4,
                                 hdr.length, "Length: (bogus, length is %u, which is too large)",
                                 hdr.length);
#ifdef HAVE_LIBGCRYPT
      if (pd_changed) pinfo->private_data = pd_save;
#endif /* HAVE_LIBGCRYPT */
      return;
    }
    tvb_ensure_bytes_exist(tvb, offset, len);
    proto_tree_add_item(isakmp_tree, hf_isakmp_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (hdr.flags & E_FLAG) {
      if (len && isakmp_tree) {
        ti = proto_tree_add_item(isakmp_tree, hf_isakmp_enc_data, tvb, offset, len, ENC_NA);
        proto_item_append_text(ti, " (%d byte%s)", len, plurality(len, "", "s"));

#ifdef HAVE_LIBGCRYPT

	if (decr) {
	  decr_tvb = decrypt_payload(tvb, pinfo, tvb_get_ptr(tvb, offset, len), len, &hdr);
	  if (decr_tvb) {
            decr_tree = proto_item_add_subtree(ti, ett_isakmp);
            dissect_payloads(decr_tvb, decr_tree, tree, isakmp_version,
                             hdr.next_payload, 0, tvb_length(decr_tvb), pinfo);

	  }
	}
#endif /* HAVE_LIBGCRYPT */
      }
    } else {
      dissect_payloads(tvb, isakmp_tree, tree, isakmp_version, hdr.next_payload,
		       offset, len, pinfo);
	}
  }
#ifdef HAVE_LIBGCRYPT
  if (pd_changed) pinfo->private_data = pd_save;
#endif /* HAVE_LIBGCRYPT */
}


static proto_tree *
dissect_payload_header(tvbuff_t *tvb, int offset, int length,
    int isakmp_version, guint8 payload _U_, guint8 *next_payload_p,
    guint16 *payload_length_p, proto_tree *tree)
{
  guint8		next_payload;
  guint16		payload_length;
  proto_item *		ti;
  proto_tree *		ntree;

  if (length < 4) {
    proto_tree_add_text(tree, tvb, offset, length,
                        "Not enough room in payload for all transforms");
    return NULL;
  }
  next_payload = tvb_get_guint8(tvb, offset);
  payload_length = tvb_get_ntohs(tvb, offset + 2);

  ti = proto_tree_add_uint(tree, hf_isakmp_typepayload, tvb, offset, payload_length, payload);

  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);

  proto_tree_add_item(ntree, hf_isakmp_nextpayload, tvb, offset, 1, ENC_BIG_ENDIAN);

  if (isakmp_version == 2) {
    proto_tree_add_item(ntree, hf_isakmp_criticalpayload, tvb, offset+1, 1, ENC_BIG_ENDIAN);
  }
  proto_tree_add_item(ntree, hf_isakmp_payloadlen, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

  *next_payload_p = next_payload;
  *payload_length_p = payload_length;
  return ntree;
}

static void
dissect_sa(tvbuff_t *tvb, int offset, int length, proto_tree *tree, int isakmp_version, packet_info *pinfo )
{
  guint32		doi;
  proto_item		*sti;
  proto_tree		*stree;

  if (isakmp_version == 1) {
    doi = tvb_get_ntohl(tvb, offset);

    proto_tree_add_item(tree, hf_isakmp_sa_doi, tvb, offset, 4, ENC_BIG_ENDIAN);

    offset += 4;
    length -= 4;

    if (doi == 1) {
      /* IPSEC */
      if (length < 4) {
        proto_tree_add_bytes_format(tree, hf_isakmp_sa_situation, tvb, offset, length,
                                    NULL,
                                    "Situation: %s (length is %u, should be >= 4)",
                                    tvb_bytes_to_str(tvb, offset, length), length);
        return;
      }
      sti = proto_tree_add_item(tree, hf_isakmp_sa_situation, tvb, offset, 4, ENC_NA);
      stree = proto_item_add_subtree(sti, ett_isakmp_sa);

      proto_tree_add_item(stree, hf_isakmp_sa_situation_identity_only, tvb, offset, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(stree, hf_isakmp_sa_situation_secrecy, tvb, offset, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(stree, hf_isakmp_sa_situation_integrity, tvb, offset, 4, ENC_BIG_ENDIAN);

      offset += 4;
      length -= 4;

      dissect_payloads(tvb, tree, tree, isakmp_version, PLOAD_IKE_P, offset,
		       length, pinfo);
    } else {
      /* Unknown */
      proto_tree_add_item(tree, hf_isakmp_sa_situation, tvb, offset, length, ENC_NA);
    }
  } else if (isakmp_version == 2) {
    dissect_payloads(tvb, tree, tree, isakmp_version, PLOAD_IKE_P, offset,
		     length, pinfo);
  }
}

static void
dissect_proposal(tvbuff_t *tvb, int offset, int length, proto_tree *tree, int isakmp_version, packet_info *pinfo )
{
  guint8		protocol_id;
  guint8		spi_size;
  guint8		num_transforms;
  guint8		next_payload;
  guint16		payload_length;
  proto_tree *		ntree;
  guint8		proposal_num;

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
    ntree = dissect_payload_header(tvb, offset, length, isakmp_version,
                                   PLOAD_IKE_T, &next_payload, &payload_length, tree);
    if (ntree == NULL)
      break;
    if (length < payload_length) {
      proto_tree_add_text(tree, tvb, offset + 4, length,
                          "Not enough room in payload for all transforms");
      break;
    }
 dissect_transform(tvb, offset + 4, payload_length - 4, ntree, pinfo, isakmp_version, protocol_id);

    offset += payload_length;
    length -= payload_length;
    num_transforms--;

  }
}

/* Returns the number of bytes consumed by this option. */
static int
dissect_rohc_supported(tvbuff_t *tvb, proto_tree *rohc_tree, int offset )
{
	guint optlen, rohc, len = 0;
	proto_item *rohc_item = NULL;
	proto_tree *sub_rohc_tree = NULL;

	rohc = tvb_get_ntohs(tvb, offset);
	optlen = tvb_get_ntohs(tvb, offset+2);
	len = 2;

	/* is TV ? (Type/Value) ? */
   	if (rohc & 0x8000) {
	      rohc = rohc & 0x7fff;
	      len = 0;
	      optlen = 2;
   	}


	rohc_item = proto_tree_add_item(rohc_tree, hf_isakmp_notify_data_rohc_attr, tvb, offset, 2+len+optlen, ENC_NA);
        proto_item_append_text(rohc_item," (t=%d,l=%d) %s",rohc, optlen, val_to_str(rohc, rohc_attr_type, "Unknown Attribute Type (%02d)") );
	sub_rohc_tree = proto_item_add_subtree(rohc_item, ett_isakmp_rohc_attr);
	proto_tree_add_item(sub_rohc_tree, hf_isakmp_notify_data_rohc_attr_format, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_uint(sub_rohc_tree, hf_isakmp_notify_data_rohc_attr_type, tvb, offset, 2, rohc);

	offset += 2;
	if (len)
	{
	   proto_tree_add_item(sub_rohc_tree, hf_isakmp_notify_data_rohc_attr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
           offset += 2;
	}
	if (optlen==0)
 	{
    	   proto_tree_add_text(sub_rohc_tree, tvb, offset, 0,"Attribut value is empty");
	   return 2+len;
	}
	proto_tree_add_item(sub_rohc_tree, hf_isakmp_notify_data_rohc_attr_value, tvb, offset, optlen, ENC_NA);
	switch(rohc) {
		case ROHC_MAX_CID:
		proto_tree_add_item(sub_rohc_tree, hf_isakmp_notify_data_rohc_attr_max_cid, tvb, offset, optlen, ENC_BIG_ENDIAN);
		break;
		case ROHC_PROFILE:
		proto_tree_add_item(sub_rohc_tree, hf_isakmp_notify_data_rohc_attr_profile, tvb, offset, optlen, ENC_BIG_ENDIAN);
		break;
		case ROHC_INTEG:
		proto_tree_add_item(sub_rohc_tree, hf_isakmp_notify_data_rohc_attr_integ, tvb, offset, optlen, ENC_BIG_ENDIAN);
		break;
		case ROHC_ICV_LEN:
		proto_tree_add_item(sub_rohc_tree, hf_isakmp_notify_data_rohc_attr_icv_len, tvb, offset, optlen, ENC_BIG_ENDIAN);
		break;
		case ROHC_MRRU:
		proto_tree_add_item(sub_rohc_tree, hf_isakmp_notify_data_rohc_attr_mrru, tvb, offset, optlen, ENC_BIG_ENDIAN);
		break;

		default:
		/* No Default Action */
		break;
	}

	return 2+len+optlen;
}

/* Dissect life duration, which is variable-length.  Note that this function
 * handles both/either the security association life duration as defined in
 * section 4.5 of RFC2407 (http://tools.ietf.org/html/rfc2407), as well as the
 * life duration according to the attribute classes table in Appendix A of
 * RFC2409: http://tools.ietf.org/html/rfc2409#page-33 */
static void
dissect_life_duration(tvbuff_t *tvb, proto_tree *tree, proto_item *ti, int hf_uint32, int hf_uint64, int hf_bytes, int offset, guint len)
{
	switch (len) {
		case 0:
			break;
		case 1: {
			guint8 val;
			val = tvb_get_guint8(tvb, offset);

			proto_tree_add_uint_format_value(tree, hf_uint32, tvb, offset, len, val, "%u", val);
			proto_item_append_text(ti, " : %u", val);
			break;
		}
		case 2: {
			guint16 val;
			val = tvb_get_ntohs(tvb, offset);

			proto_tree_add_uint_format_value(tree, hf_uint32, tvb, offset, len, val, "%u", val);
			proto_item_append_text(ti, " : %u", val);
			break;
		}
		case 3: {
			guint32 val;
			val = tvb_get_ntoh24(tvb, offset);

			proto_tree_add_uint_format_value(tree, hf_uint32, tvb, offset, len, val, "%u", val);
			proto_item_append_text(ti, " : %u", val);
			break;
		}
		case 4: {
			guint32 val;
			val = tvb_get_ntohl(tvb, offset);

			proto_tree_add_uint_format_value(tree, hf_uint32, tvb, offset, len, val, "%u", val);
			proto_item_append_text(ti, " : %u", val);
			break;
		}
		case 5: {
			guint64 val;
			val = tvb_get_ntoh40(tvb, offset);

			proto_tree_add_uint64_format_value(tree, hf_uint64, tvb, offset, len, val, "%" G_GINT64_MODIFIER "u", val);
			proto_item_append_text(ti, " : %" G_GINT64_MODIFIER "u", val);
			break;
		}
		case 6: {
			guint64 val;
			val = tvb_get_ntoh48(tvb, offset);

			proto_tree_add_uint64_format_value(tree, hf_uint64, tvb, offset, len, val, "%" G_GINT64_MODIFIER "u", val);
			proto_item_append_text(ti, " : %" G_GINT64_MODIFIER "u", val);
			break;
		}
		case 7: {
			guint64 val;
			val = tvb_get_ntoh56(tvb, offset);

			proto_tree_add_uint64_format_value(tree, hf_uint64, tvb, offset, len, val, "%" G_GINT64_MODIFIER "u", val);
			proto_item_append_text(ti, " : %" G_GINT64_MODIFIER "u", val);
			break;
		}
		case 8: {
			guint64 val;
			val = tvb_get_ntoh64(tvb, offset);

			proto_tree_add_uint64_format_value(tree, hf_uint64, tvb, offset, len, val, "%" G_GINT64_MODIFIER "u", val);
			proto_item_append_text(ti, " : %" G_GINT64_MODIFIER "u", val);
			break;
		}
		default:
			proto_tree_add_item(tree, hf_bytes, tvb, offset, len, ENC_NA);
			proto_item_append_text(ti, " : %" G_GINT64_MODIFIER "x ...", tvb_get_ntoh64(tvb, offset));
			break;
	}
}

/* Returns the number of bytes consumed by this option. */
static int
dissect_transform_attribute(tvbuff_t *tvb, proto_tree *transform_attr_type_tree, int offset )
{
	guint optlen, transform_attr_type, len = 0;
	proto_item *transform_attr_type_item = NULL;
	proto_tree *sub_transform_attr_type_tree = NULL;

	transform_attr_type = tvb_get_ntohs(tvb, offset);
	optlen = tvb_get_ntohs(tvb, offset+2);
	len = 2;

	/* is TV ? (Type/Value) ? */
   	if (transform_attr_type & 0x8000) {
	      transform_attr_type = transform_attr_type & 0x7fff;
	      len = 0;
	      optlen = 2;
   	}


	transform_attr_type_item = proto_tree_add_item(transform_attr_type_tree, hf_isakmp_tf_attr, tvb, offset, 2+len+optlen, ENC_NA);
        proto_item_append_text(transform_attr_type_item, " (t=%d,l=%d) %s",transform_attr_type, optlen, val_to_str(transform_attr_type, transform_isakmp_attr_type, "Unknown Attribute Type (%02d)") );
	sub_transform_attr_type_tree = proto_item_add_subtree(transform_attr_type_item, ett_isakmp_tf_attr);
	proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_tf_attr_format, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_uint(sub_transform_attr_type_tree, hf_isakmp_tf_attr_type_v1, tvb, offset, 2, transform_attr_type);

	offset += 2;
	if (len)
	{
	   proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_tf_attr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
           offset += 2;
	}
	if (optlen==0)
 	{
    	   proto_tree_add_text(sub_transform_attr_type_tree, tvb, offset, 0,"Attribute value is empty");
	   return 2+len;
	}
	proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_tf_attr_value, tvb, offset, optlen, ENC_NA);
	switch(transform_attr_type) {
		case ISAKMP_ATTR_LIFE_TYPE:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_tf_attr_life_type, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %s", val_to_str(tvb_get_ntohs(tvb, offset), transform_attr_sa_life_type, "Unknown %d"));
		break;
		case ISAKMP_ATTR_LIFE_DURATION:
		dissect_life_duration(tvb, sub_transform_attr_type_tree, transform_attr_type_item, hf_isakmp_tf_attr_life_duration_uint32, hf_isakmp_tf_attr_life_duration_uint64, hf_isakmp_tf_attr_life_duration_bytes , offset, optlen);
		break;
		case ISAKMP_ATTR_GROUP_DESC:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_tf_attr_group_description, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %s", val_to_str(tvb_get_ntohs(tvb, offset), transform_dh_group_type, "Unknown %d"));
		break;
		case ISAKMP_ATTR_ENCAP_MODE:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_tf_attr_encap_mode, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %s", val_to_str(tvb_get_ntohs(tvb, offset), transform_attr_encap_type, "Unknown %d"));
		break;
		case ISAKMP_ATTR_AUTH_ALGORITHM:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_tf_attr_auth_algorithm, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %s", val_to_str(tvb_get_ntohs(tvb, offset), transform_attr_auth_type, "Unknown %d"));
		break;
		case ISAKMP_ATTR_KEY_LENGTH:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_tf_attr_key_length, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %d", tvb_get_ntohs(tvb, offset));
		break;
		case ISAKMP_ATTR_KEY_ROUNDS:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_tf_attr_key_rounds, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %d", tvb_get_ntohs(tvb, offset));
		break;
		case ISAKMP_ATTR_CMPR_DICT_SIZE:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_tf_attr_cmpr_dict_size, tvb, offset, optlen, ENC_BIG_ENDIAN);
		break;
		case ISAKMP_ATTR_CMPR_ALGORITHM:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_tf_attr_cmpr_algorithm, tvb, offset, optlen, ENC_NA);
		break;
		case ISAKMP_ATTR_ECN_TUNNEL:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_tf_attr_ecn_tunnel, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %s", val_to_str(tvb_get_ntohs(tvb, offset), transform_attr_ecn_type, "Unknown %d"));
		break;
		case ISAKMP_ATTR_EXT_SEQ_NBR:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_tf_attr_ext_seq_nbr, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %s", val_to_str(tvb_get_ntohs(tvb, offset), transform_attr_ext_seq_nbr_type, "Unknown %d"));
		case ISAKMP_ATTR_AUTH_KEY_LENGTH:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_tf_attr_auth_key_length, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %d", tvb_get_ntohs(tvb, offset));
		break;
		case ISAKMP_ATTR_SIG_ENCO_ALGORITHM:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_tf_attr_sig_enco_algorithm, tvb, offset, optlen, ENC_NA);
		break;

		case ISAKMP_ATTR_ADDR_PRESERVATION:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_tf_attr_addr_preservation, tvb, offset, optlen, ENC_BIG_ENDIAN);
		proto_item_append_text(transform_attr_type_item," : %s", val_to_str(tvb_get_ntohs(tvb, offset), transform_attr_addr_preservation_type, "Unknown %d"));
		break;

		case ISAKMP_ATTR_SA_DIRECTION:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_tf_attr_sa_direction, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %s", val_to_str(tvb_get_ntohs(tvb, offset), transform_attr_sa_direction_type, "Unknown %d"));
		default:
		/* No Default Action */
		break;
	}

	return 2+len+optlen;
}


/* Returns the number of bytes consumed by this option. */
static int
dissect_transform_ike_attribute(tvbuff_t *tvb, proto_tree *transform_attr_type_tree, int offset
												#ifdef HAVE_LIBGCRYPT
												, decrypt_data_t *decr
												#endif
)
{
	guint optlen, transform_attr_type, len = 0;
	proto_item *transform_attr_type_item = NULL;
	proto_tree *sub_transform_attr_type_tree = NULL;

	transform_attr_type = tvb_get_ntohs(tvb, offset);
	optlen = tvb_get_ntohs(tvb, offset+2);
	len = 2;

	/* is TV ? (Type/Value) ? */
   	if (transform_attr_type & 0x8000) {
	      transform_attr_type = transform_attr_type & 0x7fff;
	      len = 0;
	      optlen = 2;
   	}


	transform_attr_type_item = proto_tree_add_item(transform_attr_type_tree, hf_isakmp_ike_attr, tvb, offset, 2+len+optlen, ENC_NA);
        proto_item_append_text(transform_attr_type_item," (t=%d,l=%d) %s",transform_attr_type, optlen, val_to_str(transform_attr_type,transform_ike_attr_type,"Unknown Attribute Type (%02d)") );
	sub_transform_attr_type_tree = proto_item_add_subtree(transform_attr_type_item, ett_isakmp_tf_ike_attr);
	proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_format, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_uint(sub_transform_attr_type_tree, hf_isakmp_ike_attr_type, tvb, offset, 2, transform_attr_type);

	offset += 2;
	if (len)
	{
	   proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
           offset += 2;
	}
	if (optlen==0)
 	{
    	   proto_tree_add_text(sub_transform_attr_type_tree, tvb, offset, 0,"Attribut value is empty");
	   return 2+len;
	}
	proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_value, tvb, offset, optlen, ENC_NA);
	switch(transform_attr_type) {

		case IKE_ATTR_ENCRYPTION_ALGORITHM:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_encryption_algorithm, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %s", val_to_str(tvb_get_ntohs(tvb, offset), transform_attr_enc_type, "Unknown %d"));
		#ifdef HAVE_LIBGCRYPT
		decr->encr_alg = tvb_get_ntohs(tvb, offset);
		#endif
		break;
		case IKE_ATTR_HASH_ALGORITHM:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_hash_algorithm, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %s", val_to_str(tvb_get_ntohs(tvb, offset), transform_attr_hash_type, "Unknown %d"));
		#ifdef HAVE_LIBGCRYPT
		decr->hash_alg = tvb_get_ntohs(tvb, offset);
		#endif
		break;
		case IKE_ATTR_AUTHENTICATION_METHOD:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_authentication_method, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %s", val_to_str(tvb_get_ntohs(tvb, offset), transform_attr_authmeth_type, "Unknown %d"));
		#ifdef HAVE_LIBGCRYPT
		decr->is_psk = tvb_get_ntohs(tvb, offset) == 0x01 ? TRUE : FALSE;
		#endif
		break;
		case IKE_ATTR_GROUP_DESCRIPTION:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_group_description, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %s", val_to_str(tvb_get_ntohs(tvb, offset), transform_dh_group_type, "Unknown %d"));
		#ifdef HAVE_LIBGCRYPT
		decr->group = tvb_get_ntohs(tvb, offset);
		#endif
		break;
		case IKE_ATTR_GROUP_TYPE:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_group_type, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %s", val_to_str(tvb_get_ntohs(tvb, offset), transform_attr_grp_type, "Unknown %d"));
		break;
		case IKE_ATTR_GROUP_PRIME:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_group_prime, tvb, offset, optlen, ENC_NA);
		break;
		case IKE_ATTR_GROUP_GENERATOR_ONE:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_group_generator_one, tvb, offset, optlen, ENC_NA);
		break;
		case IKE_ATTR_GROUP_GENERATOR_TWO:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_group_generator_two, tvb, offset, optlen, ENC_NA);
		break;
		case IKE_ATTR_GROUP_CURVE_A:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_group_curve_a, tvb, offset, optlen, ENC_NA);
		break;
		case IKE_ATTR_GROUP_CURVE_B:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_group_curve_b, tvb, offset, optlen, ENC_NA);
		break;
		case IKE_ATTR_LIFE_TYPE:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_life_type, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %s", val_to_str(tvb_get_ntohs(tvb, offset), transform_attr_sa_life_type, "Unknown %d"));
		break;
		case IKE_ATTR_LIFE_DURATION:
		dissect_life_duration(tvb, sub_transform_attr_type_tree, transform_attr_type_item, hf_isakmp_ike_attr_life_duration_uint32, hf_isakmp_ike_attr_life_duration_uint64, hf_isakmp_ike_attr_life_duration_bytes, offset, optlen);
		break;
		case IKE_ATTR_PRF:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_prf, tvb, offset, optlen, ENC_NA);
		break;
		case IKE_ATTR_KEY_LENGTH:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_key_length, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %d", tvb_get_ntohs(tvb, offset));
		break;
		case IKE_ATTR_FIELD_SIZE:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_field_size, tvb, offset, optlen, ENC_NA);
		break;
		case IKE_ATTR_GROUP_ORDER:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike_attr_group_order, tvb, offset, optlen, ENC_NA);
		break;
	default:
		/* No Default Action */
		break;
	}

	return 2+len+optlen;
}
/* Returns the number of bytes consumed by this option. */
static int
dissect_transform_ike2_attribute(tvbuff_t *tvb, proto_tree *transform_attr_type_tree, int offset )
{
	guint optlen, transform_attr_type, len = 0;
	proto_item *transform_attr_type_item = NULL;
	proto_tree *sub_transform_attr_type_tree = NULL;

	transform_attr_type = tvb_get_ntohs(tvb, offset);
	optlen = tvb_get_ntohs(tvb, offset+2);
	len = 2;

	/* is TV ? (Type/Value) ? */
   	if (transform_attr_type & 0x8000) {
	      transform_attr_type = transform_attr_type & 0x7fff;
	      len = 0;
	      optlen = 2;
   	}


	transform_attr_type_item = proto_tree_add_item(transform_attr_type_tree, hf_isakmp_ike2_attr, tvb, offset, 2+len+optlen, ENC_NA);
        proto_item_append_text(transform_attr_type_item," (t=%d,l=%d) %s",transform_attr_type, optlen, val_to_str(transform_attr_type,transform_ike2_attr_type,"Unknown Attribute Type (%02d)") );
	sub_transform_attr_type_tree = proto_item_add_subtree(transform_attr_type_item, ett_isakmp_tf_ike2_attr);
	proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike2_attr_format, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_uint(sub_transform_attr_type_tree, hf_isakmp_ike2_attr_type, tvb, offset, 2, transform_attr_type);

	offset += 2;
	if (len)
	{
	   proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike2_attr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
           offset += 2;
	}
	if (optlen==0)
 	{
    	   proto_tree_add_text(sub_transform_attr_type_tree, tvb, offset, 0,"Attribut value is empty");
	   return 2+len;
	}
	proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike2_attr_value, tvb, offset, optlen, ENC_NA);
	switch(transform_attr_type) {
		case IKE2_ATTR_KEY_LENGTH:
		proto_tree_add_item(sub_transform_attr_type_tree, hf_isakmp_ike2_attr_key_length, tvb, offset, optlen, ENC_BIG_ENDIAN);
                proto_item_append_text(transform_attr_type_item," : %d", tvb_get_ntohs(tvb, offset));
		break;
		break;
	default:
		/* No Default Action */
		break;
	}

	return 2+len+optlen;
}
static void
dissect_transform(tvbuff_t *tvb, int offset, int length, proto_tree *tree, packet_info *pinfo
#ifndef HAVE_LIBGCRYPT
_U_
#endif
, int isakmp_version, int protocol_id )
{
  if (isakmp_version == 1)
  {
    guint8		transform_id;
    guint8		transform_num;
#ifdef HAVE_LIBGCRYPT
    decrypt_data_t *decr = (decrypt_data_t *) pinfo->private_data;
#endif /* HAVE_LIBGCRYPT */
    int offset_end = 0;
    offset_end = offset + length;

    transform_num = tvb_get_guint8(tvb, offset);
    proto_item_append_text(tree," # %d",transform_num);

    proto_tree_add_item(tree, hf_isakmp_trans_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    transform_id = tvb_get_guint8(tvb, offset);
    switch (protocol_id) {
    case 1:	/* ISAKMP */
      proto_tree_add_uint_format(tree, hf_isakmp_trans_id, tvb, offset, 1,
                                 transform_id, "Transform ID: %s (%u)",
                                 val_to_str(transform_id, vs_v1_trans_isakmp, "UNKNOWN-TRANS-TYPE"), transform_id);
      break;
    case 2:	/* AH */
      proto_tree_add_uint_format(tree, hf_isakmp_trans_id, tvb, offset, 1,
                                 transform_id, "Transform ID: %s (%u)",
                                 val_to_str(transform_id, vs_v1_trans_ah, "UNKNOWN-AH-TRANS-TYPE"), transform_id);
      break;
    case 3:	/* ESP */
      proto_tree_add_uint_format(tree, hf_isakmp_trans_id, tvb, offset, 1,
                                 transform_id, "Transform ID: %s (%u)",
                                 val_to_str(transform_id, vs_v1_trans_esp, "UNKNOWN-ESP-TRANS-TYPE"), transform_id);
      break;
    case 4:	/* IPCOMP */
      proto_tree_add_uint_format(tree, hf_isakmp_trans_id, tvb, offset, 1,
                                 transform_id, "Transform ID: %s (%u)",
                                 val_to_str(transform_id, transform_id_ipcomp, "UNKNOWN-IPCOMP-TRANS-TYPE"), transform_id);
      break;
    default:
      proto_tree_add_item(tree, hf_isakmp_trans_id, tvb, offset, 1, ENC_BIG_ENDIAN);
      break;
    }
    offset += 3;

    if (protocol_id == 1 && transform_id == 1) {
       while (offset < offset_end) {
         offset += dissect_transform_ike_attribute(tvb, tree, offset
#ifdef HAVE_LIBGCRYPT
                                                   , decr
#endif
         );
       }
    }
    else {
       while (offset < offset_end) {
         offset += dissect_transform_attribute(tvb, tree, offset);
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

    offset += 1; /* Reserved */

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
      offset += dissect_transform_ike2_attribute(tvb, tree, offset);
    }
  }
}

static void
dissect_key_exch(tvbuff_t *tvb, int offset, int length, proto_tree *tree, int isakmp_version, packet_info *pinfo
#ifndef HAVE_LIBGCRYPT
_U_
#endif
)
{
#ifdef HAVE_LIBGCRYPT
  decrypt_data_t *decr = (decrypt_data_t *) pinfo->private_data;
#endif /* HAVE_LIBGCRYPT */

  if (isakmp_version == 2) {
    proto_tree_add_item(tree, hf_isakmp_key_exch_dh_group, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 4;
    length -= 4;
  }

  proto_tree_add_item(tree, hf_isakmp_key_exch_data, tvb, offset, length, ENC_NA);

#ifdef HAVE_LIBGCRYPT
  if (decr && decr->gi_len == 0 && ADDRESSES_EQUAL(&decr->initiator, &pinfo->src)) {
    decr->gi = g_malloc(length);
    tvb_memcpy(tvb, decr->gi, offset, length);
    decr->gi_len = length;
  } else if (decr && decr->gr_len == 0 && !ADDRESSES_EQUAL(&decr->initiator, &pinfo->src)) {
    decr->gr = g_malloc(length);
    tvb_memcpy(tvb, decr->gr, offset, length);
    decr->gr_len = length;
  }
#endif /* HAVE_LIBGCRYPT */
}

static void
dissect_id(tvbuff_t *tvb, int offset, int length, proto_tree *tree, int isakmp_version, packet_info *pinfo )
{
  guint8		id_type;
  guint8		protocol_id;
  guint16		port;
  proto_item		*idit;
  proto_tree		*idtree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

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

  protocol_id= tvb_get_guint8(tvb, offset);
  if (protocol_id == 0)
    proto_tree_add_uint_format(tree, hf_isakmp_id_protoid, tvb, offset,1,
                               protocol_id, "Protocol ID: Unused");
  else
    proto_tree_add_item(tree, hf_isakmp_id_protoid, tvb, offset, 1, ENC_BIG_ENDIAN);

  offset += 1;
  length -= 1;

  port = tvb_get_ntohs(tvb, offset);
  if (port == 0)
    proto_tree_add_uint_format(tree, hf_isakmp_id_port, tvb, offset, 2,
                               port, "Port: Unused");
  else
    proto_tree_add_item(tree, hf_isakmp_id_port, tvb, offset, 2, ENC_BIG_ENDIAN);

  offset += 2;
  length -= 2;


  /*
   * It shows strings of all types though some of types are not
   * supported in IKEv2 specification actually.
   */
  idit = proto_tree_add_item(tree, hf_isakmp_id_data, tvb, offset, length, ENC_NA);
  idtree = proto_item_add_subtree(idit, ett_isakmp_id);
  switch (id_type) {
    case IKE_ID_IPV4_ADDR:
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv4_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
      proto_item_append_text(idit, "%s", tvb_ip_to_str(tvb, offset));
      break;
    case IKE_ID_FQDN:
      proto_tree_add_item(idtree, hf_isakmp_id_data_fqdn, tvb, offset, length, ENC_ASCII|ENC_NA);
      proto_item_append_text(idit, "%s", tvb_get_ephemeral_string(tvb, offset,length));
      break;
    case IKE_ID_USER_FQDN:
      proto_tree_add_item(idtree, hf_isakmp_id_data_user_fqdn, tvb, offset, length, ENC_ASCII|ENC_NA);
      proto_item_append_text(idit, "%s", tvb_get_ephemeral_string(tvb, offset,length));
      break;
    case IKE_ID_IPV4_ADDR_SUBNET:
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv4_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv4_subnet, tvb, offset+4, 4, ENC_BIG_ENDIAN);
      proto_item_append_text(idit, "%s/%s", tvb_ip_to_str(tvb, offset), tvb_ip_to_str(tvb, offset+4));
      break;
    case IKE_ID_IPV4_ADDR_RANGE:
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv4_range_start, tvb, offset, 4, ENC_BIG_ENDIAN);
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv4_range_end, tvb, offset+4, 4, ENC_BIG_ENDIAN);
      proto_item_append_text(idit, "%s/%s", tvb_ip_to_str(tvb, offset), tvb_ip_to_str(tvb, offset+4));
      break;
    case IKE_ID_IPV6_ADDR:
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv6_addr, tvb, offset, 16, ENC_NA);
      proto_item_append_text(idit, "%s", tvb_ip6_to_str(tvb, offset));
      break;
    case IKE_ID_IPV6_ADDR_SUBNET:
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv6_addr, tvb, offset, 16, ENC_NA);
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv6_subnet, tvb, offset+16, 16, ENC_NA);
      proto_item_append_text(idit, "%s/%s", tvb_ip6_to_str(tvb, offset), tvb_ip6_to_str(tvb, offset+16));
      break;
    case IKE_ID_IPV6_ADDR_RANGE:
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv6_range_start, tvb, offset, 16, ENC_NA);
      proto_tree_add_item(idtree, hf_isakmp_id_data_ipv6_range_end, tvb, offset+16, 16, ENC_NA);
      proto_item_append_text(idit, "%s/%s", tvb_ip6_to_str(tvb, offset), tvb_ip6_to_str(tvb, offset+16));
      break;
    case IKE_ID_KEY_ID:
      proto_tree_add_item(idtree, hf_isakmp_id_data_key_id, tvb, offset, length, ENC_NA);
      break;
    case IKE_ID_DER_ASN1_DN:
      dissect_x509if_Name(FALSE, tvb, offset, &asn1_ctx, tree, hf_isakmp_id_data_cert);
      break;
    default:
      proto_item_append_text(idit, "%s", tvb_bytes_to_str(tvb,offset,length));
      break;
  }
}

static void
dissect_cert(tvbuff_t *tvb, int offset, int length, proto_tree *tree, int isakmp_version, packet_info *pinfo )
{
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);

  if (isakmp_version == 1)
  {
     proto_tree_add_item(tree, hf_isakmp_cert_encoding_v1, tvb, offset, 1, ENC_BIG_ENDIAN);
  }else if (isakmp_version == 2)
  {
     proto_tree_add_item(tree, hf_isakmp_cert_encoding_v2, tvb, offset, 1, ENC_BIG_ENDIAN);
  }

  offset += 1;
  length -= 1;

  dissect_x509af_Certificate(FALSE, tvb, offset, &asn1_ctx, tree, hf_isakmp_cert_data);
}

static void
dissect_certreq(tvbuff_t *tvb, int offset, int length, proto_tree *tree, int isakmp_version, packet_info *pinfo )
{
  guint8		cert_type;
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
dissect_auth(tvbuff_t *tvb, int offset, int length, proto_tree *tree)
{

  proto_tree_add_item(tree, hf_isakmp_auth_meth, tvb, offset, 1, ENC_BIG_ENDIAN);

  offset += 4;
  length -= 4;

  proto_tree_add_item(tree, hf_isakmp_auth_data, tvb, offset, length, ENC_NA);

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
  proto_tree *ptree = NULL;
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
  length-=4;

  /* Start Reassembly stuff for Cisco IKE fragmentation */
  {
    gboolean save_fragmented;
    tvbuff_t *defrag_isakmp_tvb = NULL;
    fragment_data *frag_msg = NULL;

    save_fragmented = pinfo->fragmented;
    pinfo->fragmented = TRUE;
    frag_msg = fragment_add_seq_check(tvb, offset, pinfo,
                                      12345,                    /*FIXME:  Fragmented packet id, guint16, somehow get CKY here */
                                      isakmp_fragment_table,    /* list of message fragments */
                                      isakmp_reassembled_table, /* list of reassembled messages */
                                      seq-1,                    /* fragment sequence number, starting from 0 */
                                      tvb_length_remaining(tvb, offset), /* fragment length - to the end */
                                      last);                    /* More fragments? */
    defrag_isakmp_tvb = process_reassembled_data(tvb, offset, pinfo,
                                                 "Reassembled ISAKMP", frag_msg, &isakmp_frag_items,
                                                 NULL, ptree);

    if (defrag_isakmp_tvb) { /* take it all */
      dissect_isakmp(defrag_isakmp_tvb, pinfo, ptree);
    }
    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO,
                      " (%sMessage fragment %u%s)",
                      (frag_msg ? "Reassembled + " : ""),
                      seq, (last ? " - last" : ""));
    pinfo->fragmented = save_fragmented;
  }
  /* End Reassembly stuff for Cisco IKE fragmentation */

}
static void
dissect_notif(tvbuff_t *tvb, int offset, int length, proto_tree *tree, int isakmp_version)
{

  guint8		spi_size;
  guint16		msgtype;
  int 			offset_end = 0;
  offset_end = offset + length;

  if (isakmp_version == 1) {

    proto_tree_add_item(tree, hf_isakmp_notify_doi, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 4;
    length -= 4;
  }

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
     proto_tree_add_item(tree, hf_isakmp_notify_msgtype_v2, tvb, offset, 2, ENC_BIG_ENDIAN);
  }
  offset += 2;
  length -= 2;

  if (spi_size) {
    proto_tree_add_item(tree, hf_isakmp_spi, tvb, offset, spi_size, ENC_NA);
    offset += spi_size;
    length -= spi_size;
  }

  /* Notification Data */

  proto_tree_add_item(tree, hf_isakmp_notify_data, tvb, offset, length, ENC_NA);

  if (isakmp_version == 1)
  {
      switch (msgtype) {
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
          case 16387: /* IPCOMP_SUPPORTED */
               proto_tree_add_item(tree, hf_isakmp_notify_data_ipcomp_cpi, tvb, offset, 2, ENC_BIG_ENDIAN);
               proto_tree_add_item(tree, hf_isakmp_notify_data_ipcomp_transform_id, tvb, offset+2, 1, ENC_BIG_ENDIAN);
          break;
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
                 proto_tree_add_item(tree, hf_isakmp_notify_data_redirect_new_resp_gw_ident_fqdn, tvb, offset+2, tvb_get_guint8(tvb,offset+1), ENC_ASCII|ENC_NA);
                break;
                default :
                  proto_tree_add_item(tree, hf_isakmp_notify_data_redirect_new_resp_gw_ident, tvb, offset+2, tvb_get_guint8(tvb,offset+1), ENC_NA);
                break;
               }
               length -= tvb_get_guint8(tvb, offset+1) - 2;
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
               length -= tvb_get_guint8(tvb, offset+1) - 2;
               offset += tvb_get_guint8(tvb, offset+1) + 2;
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
                      offset += dissect_rohc_supported(tvb, tree, offset);
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
          default:
               /* No Default Action */
          break;
      }
  }

}

static void
dissect_delete(tvbuff_t *tvb, int offset, int length, proto_tree *tree, int isakmp_version)
{
  guint8		spi_size;

  if (isakmp_version == 1) {

    proto_tree_add_item(tree, hf_isakmp_delete_doi, tvb, offset, 1, ENC_BIG_ENDIAN);
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


static void
dissect_vid(tvbuff_t *tvb, int offset, int length, proto_tree *tree)
{
  const guint8 * pVID;
  const char * vendorstring;

  pVID = tvb_get_ptr(tvb, offset, length);

  vendorstring = byte_to_str(pVID, (gint)length, vendor_id, "Unknown Vendor ID");
  proto_tree_add_item(tree, hf_isakmp_vid_bytes, tvb, offset, length, ENC_NA);
  proto_tree_add_string(tree, hf_isakmp_vid_string, tvb, offset, length, vendorstring);
  proto_item_append_text(tree," : %s", vendorstring);

  /* Check Point VID */
  if (length >= 20 && memcmp(pVID, VID_CP, 20) == 0)
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
    proto_tree_add_item(tree, hf_isakmp_vid_aruba_via_auth_profile, tvb, offset, length-19, ENC_ASCII|ENC_NA);
    offset += 4;
  }
}
/* Returns the number of bytes consumed by this option. */
static int
dissect_config_attribute(tvbuff_t *tvb, proto_tree *cfg_attr_type_tree, int offset, int isakmp_version)
{
	guint optlen, cfg_attr_type, len = 0;
        int offset_end = 0;
	proto_item *cfg_attr_type_item = NULL;
	proto_tree *sub_cfg_attr_type_tree = NULL;

	cfg_attr_type = tvb_get_ntohs(tvb, offset);
	optlen = tvb_get_ntohs(tvb, offset+2);
	len = 2;

	/* No Length ? */
   	if (cfg_attr_type & 0x8000) {
	      cfg_attr_type = cfg_attr_type & 0x7fff;
	      len = 0;
	      optlen = 2;
   	}

  	if (isakmp_version == 1) {

	   cfg_attr_type_item = proto_tree_add_none_format(cfg_attr_type_tree, hf_isakmp_cfg_attr, tvb, offset, 2+len+optlen, "Attribute Type: (t=%d,l=%d) %s", cfg_attr_type, optlen, rval_to_str(cfg_attr_type,vs_v1_cfgattr,"Unknown Attribute Type (%02d)") );
	   sub_cfg_attr_type_tree = proto_item_add_subtree(cfg_attr_type_item, ett_isakmp_cfg_attr);
	   proto_tree_add_uint(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_type_v1, tvb, offset, 2, cfg_attr_type);
  	} else if (isakmp_version == 2) {
	   cfg_attr_type_item = proto_tree_add_none_format(cfg_attr_type_tree, hf_isakmp_cfg_attr, tvb, offset, 2+len+optlen, "Attribute Type: (t=%d,l=%d) %s", cfg_attr_type, optlen, rval_to_str(cfg_attr_type,vs_v2_cfgattr,"Unknown Attribute Type (%02d)") );
	   sub_cfg_attr_type_tree = proto_item_add_subtree(cfg_attr_type_item, ett_isakmp_cfg_attr);
	   proto_tree_add_uint(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_type_v2, tvb, offset, 2, cfg_attr_type);
	}
        proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_format, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	if (len)
	{
	   proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
           offset += 2;
	}
	if (optlen==0)
 	{
    	   proto_tree_add_text(sub_cfg_attr_type_tree, tvb, offset, 0,"Attribut value is empty");
	   return 2+len;
	}
	proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_value, tvb, offset, optlen, ENC_NA);
	switch (cfg_attr_type) {
	case INTERNAL_IP4_ADDRESS: /* 1 */
		offset_end = offset + optlen;

		if (optlen%4 == 0)
		{
			while (offset_end-offset > 0)
			{
				proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip4_address, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}

		}
		break;
	case INTERNAL_IP4_NETMASK: /* 2 */
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip4_netmask, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;
	case INTERNAL_IP4_DNS: /* 3 */
		offset_end = offset + optlen;

		if (optlen%4 == 0)
		{
			while (offset_end-offset > 0)
			{
				proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip4_dns, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}

		}
		break;
	case INTERNAL_IP4_NBNS: /* 4 */
		offset_end = offset + optlen;

		if (optlen%4 == 0)
		{
			while (offset_end-offset > 0)
			{
				proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip4_nbns, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}

		}
		break;
	case INTERNAL_ADDRESS_EXPIRY: /* 5 */
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_address_expiry, tvb, offset, 4, ENC_BIG_ENDIAN);
		break;
	case INTERNAL_IP4_DHCP: /* 6 */
		offset_end = offset + optlen;

		if (optlen%4 == 0)
		{
			while (offset_end-offset > 0)
			{
				proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip4_dhcp, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
			}

		}
		break;
	case APPLICATION_VERSION: /* 7 */
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_application_version, tvb, offset, optlen, ENC_ASCII|ENC_NA);
		proto_item_append_text(cfg_attr_type_item," : %s", tvb_get_ephemeral_string(tvb, offset,optlen));
		break;
	case INTERNAL_IP6_ADDRESS: /* 8 */
		offset_end = offset + optlen;

		if (optlen%16 == 0)
		{
			while (offset_end-offset > 0)
			{
				proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip6_address, tvb, offset, 16, ENC_BIG_ENDIAN);
				offset += 16;
			}

		}
		break;
	case INTERNAL_IP6_NETMASK: /* 9 Only in IKEv1 */
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip6_netmask, tvb, offset, 18, ENC_NA);
		break;
	case INTERNAL_IP6_DNS: /* 10 */
		offset_end = offset + optlen;

		if (optlen%16 == 0)
		{
			while (offset_end-offset > 0)
			{
				proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip6_dns, tvb, offset, 16, ENC_NA);
				offset += 16;
			}

		}
		break;
	case INTERNAL_IP6_NBNS: /* 11 */
		offset_end = offset + optlen;

		if (optlen%16 == 0)
		{
			while (offset_end-offset > 0)
			{
				proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip6_nbns, tvb, offset, 16, ENC_NA);
				offset += 16;
			}

		}
		break;
	case INTERNAL_IP6_DHCP: /* 12 */
		offset_end = offset + optlen;

		if (optlen%16 == 0)
		{
			while (offset_end-offset > 0)
			{
				proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip6_dhcp, tvb, offset, 16, ENC_NA);
				offset += 16;
			}

		}
		break;
	case INTERNAL_IP4_SUBNET: /* 13 */
		offset_end = offset + optlen;

		if (optlen%8 == 0)
		{
			while (offset_end-offset > 0)
			{
				proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip4_subnet_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
				proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip4_subnet_netmask, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 8;
			}

		}
		break;
	case SUPPORTED_ATTRIBUTES: /* 14 */
		offset_end = offset + optlen;

		if (optlen%2 == 0)
		{
			while (offset_end-offset > 0)
			{
				proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_supported_attributes, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
			}

		}
		break;
	case INTERNAL_IP6_SUBNET: /* 15 */
		offset_end = offset + optlen;

		if (optlen%17 == 0)
		{
			while (offset_end-offset > 0)
			{
				proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip6_subnet_ip, tvb, offset, 16, ENC_NA);
				offset += 16;
				proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip6_subnet_prefix, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
			}

		}
		break;
	case INTERNAL_IP6_LINK: /* 17 */
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip6_link_interface, tvb, offset, 8, ENC_BIG_ENDIAN);
		offset += 8;
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip6_link_id, tvb, offset, optlen-8, ENC_NA);
		offset += optlen-8;
		break;
	case INTERNAL_IP6_PREFIX: /* 18 */
		offset_end = offset + optlen;

		if (optlen%17 == 0)
		{
			while (offset_end-offset > 0)
			{
				proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip6_prefix_ip, tvb, offset, 16, ENC_NA);
				offset += 16;
				proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_internal_ip6_prefix_length, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
			}

		}
		break;
	case XAUTH_TYPE: /* 16520 */
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_xauth_type, tvb, offset, optlen, ENC_BIG_ENDIAN);
		proto_item_append_text(cfg_attr_type_item," : %s", rval_to_str(tvb_get_ntohs(tvb, offset), cfgattr_xauth_type, "Unknown %d"));
		break;
	case XAUTH_USER_NAME: /* 16521 */
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_xauth_user_name, tvb, offset, optlen, ENC_ASCII|ENC_NA);
		proto_item_append_text(cfg_attr_type_item," : %s", tvb_get_ephemeral_string(tvb, offset,optlen));
		break;
	case XAUTH_USER_PASSWORD: /* 16522 */
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_xauth_user_password, tvb, offset, optlen, ENC_ASCII|ENC_NA);
		proto_item_append_text(cfg_attr_type_item," : %s", tvb_get_ephemeral_string(tvb, offset,optlen));
		break;
	case XAUTH_PASSCODE: /* 16523 */
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_xauth_passcode, tvb, offset, optlen, ENC_ASCII|ENC_NA);
		proto_item_append_text(cfg_attr_type_item," : %s", tvb_get_ephemeral_string(tvb, offset,optlen));
		break;
	case XAUTH_MESSAGE: /* 16524 */
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_xauth_message, tvb, offset, optlen, ENC_ASCII|ENC_NA);
		proto_item_append_text(cfg_attr_type_item," : %s", tvb_get_ephemeral_string(tvb, offset,optlen));
		break;
	case XAUTH_CHALLENGE: /* 16525 */
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_xauth_challenge, tvb, offset, optlen, ENC_ASCII|ENC_NA);
		proto_item_append_text(cfg_attr_type_item," : %s", tvb_get_ephemeral_string(tvb, offset,optlen));
		break;
	case XAUTH_DOMAIN: /* 16526 */
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_xauth_domain, tvb, offset, optlen, ENC_ASCII|ENC_NA);
		proto_item_append_text(cfg_attr_type_item," : %s", tvb_get_ephemeral_string(tvb, offset,optlen));
		break;
	case XAUTH_STATUS: /* 16527 */
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_xauth_status, tvb, offset, optlen, ENC_BIG_ENDIAN);
		proto_item_append_text(cfg_attr_type_item," : %s", val_to_str(tvb_get_ntohs(tvb, offset), cfgattr_xauth_status, "Unknown %d"));
		break;
	case XAUTH_NEXT_PIN: /* 16528 */
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_xauth_next_pin, tvb, offset, optlen, ENC_ASCII|ENC_NA);
		proto_item_append_text(cfg_attr_type_item," : %s", tvb_get_ephemeral_string(tvb, offset,optlen));
		break;
	case XAUTH_ANSWER: /* 16527 */
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_xauth_answer, tvb, offset, optlen, ENC_ASCII|ENC_NA);
		proto_item_append_text(cfg_attr_type_item," : %s", tvb_get_ephemeral_string(tvb, offset,optlen));
		break;

	case UNITY_BANNER: /* 28672 */
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_unity_banner, tvb, offset, optlen, ENC_ASCII|ENC_NA);
		proto_item_append_text(cfg_attr_type_item," : %s", tvb_get_ephemeral_string(tvb, offset,optlen));
		break;
	case UNITY_DEF_DOMAIN: /* 28674 */
		proto_tree_add_item(sub_cfg_attr_type_tree, hf_isakmp_cfg_attr_unity_def_domain, tvb, offset, optlen, ENC_ASCII|ENC_NA);
		proto_item_append_text(cfg_attr_type_item," : %s", tvb_get_ephemeral_string(tvb, offset,optlen));
		break;
/* TODO: Support other UNITY Attributes ! */
	default:
		/* No Default Action */
		break;
	}

	return 2+len+optlen;
}
static void
dissect_config(tvbuff_t *tvb, int offset, int length, proto_tree *tree, int isakmp_version)
{
  int offset_end = 0;
  offset_end = offset + length;
  if (isakmp_version == 1) {

    proto_tree_add_item(tree, hf_isakmp_cfg_type_v1,tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_isakmp_cfg_identifier,tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 2;

  } else if (isakmp_version == 2) {

    proto_tree_add_item(tree, hf_isakmp_cfg_type_v2,tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 4;

  }

  while (offset < offset_end) {
    offset += dissect_config_attribute(tvb, tree, offset, isakmp_version);
}
}

static void
dissect_nat_discovery(tvbuff_t *tvb, int offset, int length, proto_tree *tree )
{
  proto_tree_add_item(tree, hf_isakmp_nat_hash, tvb, offset, length, ENC_NA);
}

static void
dissect_nat_original_address(tvbuff_t *tvb, int offset, int length, proto_tree *tree, int isakmp_version)
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
  length -= 1;

  offset += 3;		/* reserved */

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

static void
dissect_ts(tvbuff_t *tvb, int offset, int length, proto_tree *tree)
{
  guint8	num, tstype, protocol_id;

  num = tvb_get_guint8(tvb, offset);
  proto_item_append_text(tree," # %d", num);
  proto_tree_add_item(tree, hf_isakmp_ts_number_of_ts, tvb, offset, 1, ENC_BIG_ENDIAN);

  offset += 1;
  length -= 1;

  offset += 3; /* Reserved */
  length -= 3;

  while (length > 0) {
    tstype = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_isakmp_ts_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    length -= 1;
    switch (tstype) {
    case IKEV2_TS_IPV4_ADDR_RANGE:
	protocol_id = tvb_get_guint8(tvb, offset);
	if (protocol_id == 0)
	    proto_tree_add_uint_format(tree, hf_isakmp_ts_protoid, tvb, offset,1,
                               protocol_id, "Protocol ID: Unused");
        else
	    proto_tree_add_item(tree, hf_isakmp_ts_protoid, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(tree, hf_isakmp_ts_selector_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(tree, hf_isakmp_ts_start_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(tree, hf_isakmp_ts_end_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(tree, hf_isakmp_ts_start_addr_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;
	proto_tree_add_item(tree, hf_isakmp_ts_end_addr_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	length -= 4;
	break;
    case IKEV2_TS_IPV6_ADDR_RANGE:
	protocol_id = tvb_get_guint8(tvb, offset);
	if (protocol_id == 0)
	    proto_tree_add_uint_format(tree, hf_isakmp_ts_protoid, tvb, offset,1,
                               protocol_id, "Protocol ID: Unused");
        else
	    proto_tree_add_item(tree, hf_isakmp_ts_protoid, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(tree, hf_isakmp_ts_selector_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(tree, hf_isakmp_ts_start_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(tree, hf_isakmp_ts_end_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	proto_tree_add_item(tree, hf_isakmp_ts_start_addr_ipv6, tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;

	proto_tree_add_item(tree, hf_isakmp_ts_end_addr_ipv6, tvb, offset, 16, ENC_NA);
	offset += 16;
	length -= 16;
	break;
    case IKEV2_TS_FC_ADDR_RANGE:

	offset += 1; /* Reserved */
	length -= 1;

	proto_tree_add_item(tree, hf_isakmp_ts_selector_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	length -= 2;

	offset += 1; /* Reserved */
	length -= 1;

	proto_tree_add_item(tree, hf_isakmp_ts_start_addr_fc, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	length -= 3;

	offset += 1; /* Reserved */
	length -= 1;

	proto_tree_add_item(tree, hf_isakmp_ts_end_addr_fc, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;
	length -= 3;

	proto_tree_add_item(tree, hf_isakmp_ts_start_r_ctl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(tree, hf_isakmp_ts_end_r_ctl, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(tree, hf_isakmp_ts_start_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;

	proto_tree_add_item(tree, hf_isakmp_ts_end_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	length -= 1;
	break;
    default:
	proto_tree_add_item(tree, hf_isakmp_ts_data, tvb, offset, length, ENC_NA);
    	offset += length;
    	length -= length;
      break;

    }
  }
}

static void
dissect_enc(tvbuff_t *tvb,
            int offset,
            int length,
            proto_tree *tree,
#ifdef HAVE_LIBGCRYPT
            packet_info *pinfo,
            guint8 inner_payload)
#else
            packet_info *pinfo _U_,
            guint8 inner_payload _U_)
#endif
{
#ifdef HAVE_LIBGCRYPT
  ikev2_decrypt_data_t *key_info = NULL;
  gint iv_len, encr_data_len, icd_len, decr_data_len, md_len;
  guint8 pad_len;
  guchar *iv = NULL, *encr_data = NULL, *decr_data = NULL, *entire_message = NULL, *md = NULL;
  gcry_cipher_hd_t cipher_hd;
  gcry_md_hd_t md_hd;
  gcry_error_t err = 0;
  proto_item *item = NULL, *icd_item = NULL, *encr_data_item = NULL, *padlen_item = NULL, *iv_item = NULL;
  tvbuff_t *decr_tvb = NULL;
  gint payloads_len;
  proto_tree *decr_tree = NULL, *decr_payloads_tree = NULL;

  if (pinfo->private_data) {
    key_info = (ikev2_decrypt_data_t*)(pinfo->private_data);
    iv_len = key_info->encr_spec->iv_len;
    icd_len = key_info->auth_spec->trunc_len;
    encr_data_len = length - iv_len - icd_len;
    /*
     * Zero or negative length of encrypted data shows that the user specified
     * wrong encryption algorithm and/or authentication algorithm.
     */
    if (encr_data_len <= 0) {
      item = proto_tree_add_text(tree, tvb, offset, length, "Not enough data for IV, Encrypted data and ICD.");
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "Not enough data in IKEv2 Encrypted payload");
      PROTO_ITEM_SET_GENERATED(item);
      return;
    }

    /*
     * Add the IV to the tree and store it in a packet scope buffer for later decryption
     * if the specified encryption algorithm uses IV.
     */
    if (iv_len) {
      iv_item = proto_tree_add_item(tree, hf_isakmp_enc_iv, tvb, offset, iv_len, ENC_NA);
      proto_item_append_text(iv_item, " (%d bytes)", iv_len);
      iv = ep_tvb_memdup(tvb, offset, iv_len);

      offset += iv_len;
    }

    /*
     * Add the encrypted portion to the tree and store it in a packet scope buffer for later decryption.
     */
    encr_data_item = proto_tree_add_item(tree, hf_isakmp_enc_data, tvb, offset, encr_data_len, ENC_NA);
    proto_item_append_text(encr_data_item, " (%d bytes)",encr_data_len);
    encr_data = ep_tvb_memdup(tvb, offset, encr_data_len);
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
      if (key_info->auth_spec->gcry_alg) {
        err = gcry_md_open(&md_hd, key_info->auth_spec->gcry_alg, key_info->auth_spec->gcry_flag);
        if (err) {
          REPORT_DISSECTOR_BUG(ep_strdup_printf("IKEv2 hashing error: algorithm %d: gcry_md_open failed: %s",
            key_info->auth_spec->gcry_alg, gcry_strerror(err)));
        }
        err = gcry_md_setkey(md_hd, key_info->auth_key, key_info->auth_spec->key_len);
        if (err) {
          REPORT_DISSECTOR_BUG(ep_strdup_printf("IKEv2 hashing error: algorithm %s, key length %u: gcry_md_setkey failed: %s",
            gcry_md_algo_name(key_info->auth_spec->gcry_alg), key_info->auth_spec->key_len, gcry_strerror(err)));
        }

        /* Calculate hash over the bytes from the beginning of the ISAKMP header to the right before the ICD. */
        entire_message = ep_tvb_memdup(tvb, 0, offset);
        gcry_md_write(md_hd, entire_message, offset);
        md = gcry_md_read(md_hd, 0);
        md_len = gcry_md_get_algo_dlen(key_info->auth_spec->gcry_alg);
        if (md_len < icd_len) {
          gcry_md_close(md_hd);
          REPORT_DISSECTOR_BUG(ep_strdup_printf("IKEv2 hashing error: algorithm %s: gcry_md_get_algo_dlen returned %d which is smaller than icd length %d",
            gcry_md_algo_name(key_info->auth_spec->gcry_alg), md_len, icd_len));
        }
        if (tvb_memeql(tvb, offset, md, icd_len) == 0) {
          proto_item_append_text(icd_item, "[correct]");
        } else {
          proto_item_append_text(icd_item, "[incorrect, should be %s]", bytes_to_str(md, icd_len));
          expert_add_info_format(pinfo, icd_item, PI_CHECKSUM, PI_WARN, "IKEv2 Integrity Checksum Data is incorrect");
        }
        gcry_md_close(md_hd);
      } else {
        proto_item_append_text(icd_item, "[not validated]");
      }
      offset += icd_len;
    }

    /*
     * Confirm encrypted data length is multiple of block size.
     */
    if (encr_data_len % key_info->encr_spec->block_len != 0) {
      proto_item_append_text(encr_data_item, "[Invalid length, should be a multiple of block size (%u)]",
        key_info->encr_spec->block_len);
      expert_add_info_format(pinfo, encr_data_item, PI_MALFORMED, PI_WARN, "Encrypted data length isn't a multiple of block size");
      return;
    }

    /*
     * Allocate buffer for decrypted data.
     */
    decr_data = (guchar*)g_malloc(encr_data_len);
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
        g_free(decr_data);
        REPORT_DISSECTOR_BUG(ep_strdup_printf("IKEv2 decryption error: algorithm %d, mode %d: gcry_cipher_open failed: %s",
          key_info->encr_spec->gcry_alg, key_info->encr_spec->gcry_mode, gcry_strerror(err)));
      }
      err = gcry_cipher_setkey(cipher_hd, key_info->encr_key, key_info->encr_spec->key_len);
      if (err) {
        g_free(decr_data);
        REPORT_DISSECTOR_BUG(ep_strdup_printf("IKEv2 decryption error: algorithm %d, key length %d:  gcry_cipher_setkey failed: %s",
          key_info->encr_spec->gcry_alg, key_info->encr_spec->key_len, gcry_strerror(err)));
      }
      err = gcry_cipher_setiv(cipher_hd, iv, iv_len);
      if (err) {
        g_free(decr_data);
        REPORT_DISSECTOR_BUG(ep_strdup_printf("IKEv2 decryption error: algorithm %d, iv length %d:  gcry_cipher_setiv failed: %s",
          key_info->encr_spec->gcry_alg, iv_len, gcry_strerror(err)));
      }
      err = gcry_cipher_decrypt(cipher_hd, decr_data, decr_data_len, encr_data, encr_data_len);
      if (err) {
        g_free(decr_data);
        REPORT_DISSECTOR_BUG(ep_strdup_printf("IKEv2 decryption error: algorithm %d:  gcry_cipher_decrypt failed: %s",
          key_info->encr_spec->gcry_alg, gcry_strerror(err)));
      }
      gcry_cipher_close(cipher_hd);
    }

    decr_tvb = tvb_new_child_real_data(tvb, decr_data, decr_data_len, decr_data_len);
    tvb_set_free_cb(decr_tvb, g_free);
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
        expert_add_info_format(pinfo, padlen_item, PI_MALFORMED, PI_WARN, "Pad length is too big");
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
    if (decr_payloads_tree) {
      dissect_payloads(decr_tvb, decr_payloads_tree, decr_tree, 2, inner_payload, 0, payloads_len, pinfo);
    }
  }else{
#endif /* HAVE_LIBGCRYPT */
     proto_tree_add_item(tree, hf_isakmp_enc_iv, tvb, offset, 4, ENC_NA);
     proto_tree_add_item(tree, hf_isakmp_enc_data, tvb, offset+4 , length, ENC_NA);
#ifdef HAVE_LIBGCRYPT
  }
#endif /* HAVE_LIBGCRYPT */
}

static void
dissect_eap(tvbuff_t *tvb, int offset, int length, proto_tree *tree, packet_info *pinfo)
{
  tvbuff_t *eap_tvb = NULL;

  eap_tvb = tvb_new_subset(tvb, offset,length, length );
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

#ifdef HAVE_LIBGCRYPT
static guint
isakmp_hash_func(gconstpointer c) {
  const guint8 *i_cookie = (guint8 *) c;
  guint   val = 0, keychunk, i;

  /* XOR our icookie down to the size of a guint */
  for (i = 0; i < COOKIE_SIZE - (COOKIE_SIZE % sizeof(keychunk)); i += sizeof(keychunk)) {
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
  guint hash = 0, keychunk, i;

  /* XOR our icookie down to the size of a guint */
  for (i = 0; i < key->spii_len - (key->spii_len % sizeof(keychunk)); i += sizeof(keychunk)) {
    memcpy(&keychunk, &key->spii[i], sizeof(keychunk));
    hash ^= keychunk;
  }
  for (i = 0; i < key->spir_len - (key->spir_len % sizeof(keychunk)); i += sizeof(keychunk)) {
    memcpy(&keychunk, &key->spir[i], sizeof(keychunk));
    hash ^= keychunk;
  }

  return hash;
}

static gint ikev2_key_equal_func(gconstpointer k1, gconstpointer k2) {
  const ikev2_uat_data_key_t *key1 = k1, *key2 = k2;
  if (key1->spii_len != key2->spii_len) return 0;
  if (key1->spir_len != key2->spir_len) return 0;
  if (memcmp(key1->spii, key2->spii, key1->spii_len) != 0) return 0;
  if (memcmp(key1->spir, key2->spir, key1->spir_len) != 0) return 0;

  return 1;
}
#endif /* HAVE_LIBGCRYPT */

#ifdef HAVE_LIBGCRYPT
static gboolean
free_cookie(gpointer key_arg, gpointer value, gpointer user_data _U_)
{
  guint8 *ic_key = key_arg;
  decrypt_data_t *decr = value;

  g_slice_free1(COOKIE_SIZE, ic_key);
  g_slice_free1(sizeof(decrypt_data_t), decr);
  return TRUE;
}
#endif

static void
isakmp_init_protocol(void) {
#ifdef HAVE_LIBGCRYPT
  guint i;
  decrypt_data_t *decr;
  guint8   *ic_key;
#endif /* HAVE_LIBGCRYPT */
  fragment_table_init(&isakmp_fragment_table);
  reassembled_table_init(&isakmp_reassembled_table);

#ifdef HAVE_LIBGCRYPT
  if (isakmp_hash) {
    g_hash_table_foreach_remove(isakmp_hash, free_cookie, NULL);
    g_hash_table_destroy(isakmp_hash);
  }
  isakmp_hash = g_hash_table_new(isakmp_hash_func, isakmp_equal_func);

  for (i = 0; i < num_ikev1_uat_data; i++) {
      ic_key = g_slice_alloc(COOKIE_SIZE);
      decr   = g_slice_alloc(sizeof(decrypt_data_t));
      memcpy(ic_key, ikev1_uat_data[i].icookie, COOKIE_SIZE);
      memset(decr, 0, sizeof(decrypt_data_t));

      memcpy(decr->secret, ikev1_uat_data[i].key, ikev1_uat_data[i].key_len);
      decr->secret_len = ikev1_uat_data[i].key_len;

      g_hash_table_insert(isakmp_hash, ic_key, decr);
  }

  if (ikev2_key_hash) {
    g_hash_table_destroy(ikev2_key_hash);
  }

  ikev2_key_hash = g_hash_table_new(ikev2_key_hash_func, ikev2_key_equal_func);
  for (i = 0; i < num_ikev2_uat_data; i++) {
    g_hash_table_insert(ikev2_key_hash, &(ikev2_uat_data[i].key), &(ikev2_uat_data[i]));
  }
#endif /* HAVE_LIBGCRYPT */
}

#ifdef HAVE_LIBGCRYPT
static void
isakmp_prefs_apply_cb(void) {
  isakmp_init_protocol();
}
#endif /* HAVE_LIBGCRYPT */

#ifdef HAVE_LIBGCRYPT

UAT_BUFFER_CB_DEF(ikev1_users, icookie, ikev1_uat_data_key_t, icookie, icookie_len)
UAT_BUFFER_CB_DEF(ikev1_users, key, ikev1_uat_data_key_t, key, key_len)

static void ikev1_uat_data_update_cb(void* p, const char** err) {
  ikev1_uat_data_key_t *ud = p;

  if (ud->icookie_len != COOKIE_SIZE) {
    *err = ep_strdup_printf("Length of Initiator's COOKIE must be %d octets (%d hex characters).", COOKIE_SIZE, COOKIE_SIZE * 2);
    return;
  }

  if (ud->key_len == 0) {
    *err = ep_strdup_printf("Must have Encryption key.");
    return;
  }

  if (ud->key_len > MAX_KEY_SIZE) {
    *err = ep_strdup_printf("Length of Encryption key limited to %d octets (%d hex characters).", MAX_KEY_SIZE, MAX_KEY_SIZE * 2);
    return;
  }

}

UAT_BUFFER_CB_DEF(ikev2_users, spii, ikev2_uat_data_t, key.spii, key.spii_len)
UAT_BUFFER_CB_DEF(ikev2_users, spir, ikev2_uat_data_t, key.spir, key.spir_len)
UAT_BUFFER_CB_DEF(ikev2_users, sk_ei, ikev2_uat_data_t, sk_ei, sk_ei_len)
UAT_BUFFER_CB_DEF(ikev2_users, sk_er, ikev2_uat_data_t, sk_er, sk_er_len)
UAT_VS_DEF(ikev2_users, encr_alg, ikev2_uat_data_t, IKEV2_ENCR_3DES, IKEV2_ENCR_3DES_STR)
UAT_BUFFER_CB_DEF(ikev2_users, sk_ai, ikev2_uat_data_t, sk_ai, sk_ai_len)
UAT_BUFFER_CB_DEF(ikev2_users, sk_ar, ikev2_uat_data_t, sk_ar, sk_ar_len)
UAT_VS_DEF(ikev2_users, auth_alg, ikev2_uat_data_t, IKEV2_AUTH_HMAC_SHA1_96, IKEV2_AUTH_HMAC_SHA1_96_STR)

static void ikev2_uat_data_update_cb(void* p, const char** err) {
  ikev2_uat_data_t *ud = p;

  if (ud->key.spii_len != COOKIE_SIZE) {
    *err = ep_strdup_printf("Length of Initiator's SPI must be %d octets (%d hex characters).", COOKIE_SIZE, COOKIE_SIZE * 2);
    return;
  }

  if (ud->key.spir_len != COOKIE_SIZE) {
    *err = ep_strdup_printf("Length of Responder's SPI must be %d octets (%d hex characters).", COOKIE_SIZE, COOKIE_SIZE * 2);
    return;
  }

  if ((ud->encr_spec = ikev2_decrypt_find_encr_spec(ud->encr_alg)) == NULL) {
    REPORT_DISSECTOR_BUG("Couldn't get IKEv2 encryption algorithm spec.");
  }

  if ((ud->auth_spec = ikev2_decrypt_find_auth_spec(ud->auth_alg)) == NULL) {
    REPORT_DISSECTOR_BUG("Couldn't get IKEv2 authentication algorithm spec.");
  }

  if (ud->sk_ei_len != ud->encr_spec->key_len) {
    *err = ep_strdup_printf("Length of SK_ei (%u octets) does not match the key length (%u octets) of the selected encryption algorithm.",
             ud->sk_ei_len, ud->encr_spec->key_len);
    return;
  }

  if (ud->sk_er_len != ud->encr_spec->key_len) {
    *err = ep_strdup_printf("Length of SK_er (%u octets) does not match the key length (%u octets) of the selected encryption algorithm.",
             ud->sk_er_len, ud->encr_spec->key_len);
    return;
  }

  if (ud->sk_ai_len != ud->auth_spec->key_len) {
    *err = ep_strdup_printf("Length of SK_ai (%u octets) does not match the key length (%u octets) of the selected integrity algorithm.",
             ud->sk_ai_len, ud->auth_spec->key_len);
    return;
  }

  if (ud->sk_ar_len != ud->auth_spec->key_len) {
    *err = ep_strdup_printf("Length of SK_ar (%u octets) does not match the key length (%u octets) of the selected integrity algorithm.",
             ud->sk_ar_len, ud->auth_spec->key_len);
    return;
  }
}
#endif /* HAVE_LIBGCRYPT */

void
proto_register_isakmp(void)
{
#ifdef HAVE_LIBGCRYPT
  module_t *isakmp_module;
#endif
  static hf_register_info hf[] = {
    { &hf_isakmp_icookie,
      { "Initiator cookie", "isakmp.icookie",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "ISAKMP Initiator Cookie", HFILL }},
    { &hf_isakmp_rcookie,
      { "Responder cookie", "isakmp.rcookie",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "ISAKMP Responder Cookie", HFILL }},
    { &hf_isakmp_typepayload,
      { "Type Payload", "isakmp.typepayload",
        FT_UINT8,BASE_RANGE_STRING | BASE_DEC, RVALS(&payload_type), 0x0,
        "ISAKMP Type Payload", HFILL }},
    { &hf_isakmp_nextpayload,
      { "Next payload", "isakmp.nextpayload",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(&payload_type), 0x0,
        "ISAKMP Next Payload", HFILL }},
    { &hf_isakmp_criticalpayload,
      { "Critical Bit", "isakmp.criticalpayload",
        FT_BOOLEAN, 8,TFS(&criticalpayload), 0x80,
        "ISAKMP (v2) Critical Payload", HFILL }},
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
        FT_BOOLEAN, 8, TFS(&flag_r), R_FLAG,
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
        "ISAKMP SPI Size", HFILL }},
    { &hf_isakmp_spi,
      { "SPI Size", "isakmp.spi",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "ISAKMP SPI", HFILL }},
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
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(&vs_v1_id_type), 0x0,
        "ISAKMP (v1) ID Type", HFILL }},
    { &hf_isakmp_id_type_v2,
      { "ID type", "isakmp.id.type",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(&vs_v2_id_type), 0x0,
        "ISAKMP (v2) ID Type", HFILL }},
    { &hf_isakmp_id_protoid,
      { "Protocol ID", "isakmp.id.protoid",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, (&ipproto_val_ext), 0x0,
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
      { "ID_IPV4_SUBNET", "isakmp.id.data.ipv4_range_start",
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
        "The type specifies an opaque byte stream which may be used to pass vendor-specific information necessary to identify which pre-hared key should be used to authenticate Aggressive mode negotiations", HFILL }},
    { &hf_isakmp_id_data_cert,
      { "ID_DER_ASN1_DN", "isakmp.id.data.der_asn1_dn",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },
    { &hf_isakmp_cert_encoding_v1,
      { "Certificate Encoding", "isakmp.cert.encoding",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(&cert_v1_type), 0x0,
        "ISAKMP Certificate Encoding", HFILL }},
    { &hf_isakmp_cert_encoding_v2,
      { "Certificate Encoding", "isakmp.cert.encoding",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(&cert_v2_type), 0x0,
        "IKEv2 Certificate Encoding", HFILL }},
    { &hf_isakmp_cert_data,
      { "Certificate Data", "isakmp.cert.data",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "ISAKMP Certificate Data", HFILL }},
    { &hf_isakmp_certreq_type_v1,
      { "Certificate Type", "isakmp.certreq.type",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(&cert_v1_type), 0x0,
        "ISAKMP Certificate Type", HFILL }},
    { &hf_isakmp_certreq_type_v2,
      { "Certificate Type", "isakmp.certreq.type",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(&cert_v2_type), 0x0,
        "IKEv2 Certificate Type", HFILL }},
    { &hf_isakmp_auth_meth,
      { "Authentication Method", "isakmp.auth.method",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(&authmeth_v2_type), 0x0,
        "IKEv2 Authentication Method", HFILL }},
    { &hf_isakmp_auth_data,
      { "Authentication Data", "isakmp.auth.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "IKEv2 Authentication Data", HFILL }},
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
    { &hf_isakmp_notify_data_ipcomp_cpi,
      { "IPCOMP CPI", "isakmp.notify.data.ipcomp.cpi",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_notify_data_ipcomp_transform_id,
      { "IPCOMP Transform ID", "isakmp.notify.data.ipcomp.transform_id",
        FT_UINT8, BASE_DEC, VALS(transform_id_ipcomp), 0x0,
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
   { &hf_isakmp_notify_data_rohc_attr,
      { "ROHC Attribute Type",	"isakmp.notify.data.rohc.attr",
	FT_NONE, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_notify_data_rohc_attr_type,
      { "ROHC Attribute Type",	"isakmp.notify.data.rohc.attr.type",
	FT_UINT16, BASE_DEC, VALS(rohc_attr_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_notify_data_rohc_attr_format,
      { "ROHC Format",	"isakmp.notify.data.rohc.attr.format",
	FT_BOOLEAN, 16, TFS(&attribute_format), 0x8000,
	NULL, HFILL }},
   { &hf_isakmp_notify_data_rohc_attr_length,
      { "Length",	"isakmp.notify.data.rohc.attr.length",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_notify_data_rohc_attr_value,
      { "Value",	"isakmp.notify.data.rohc.attr.value",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_notify_data_rohc_attr_max_cid,
      { "Maximum Context Identifier",	"isakmp.notify.data.rohc.attr.max_cid",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_notify_data_rohc_attr_profile,
      { "ROHC Profile",	"isakmp.notify.data.rohc.attr.profile",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_notify_data_rohc_attr_integ,
      { "ROHC Integrity Algorithm",	"isakmp.notify.data.rohc.attr.integ",
	FT_UINT16, BASE_DEC, VALS(transform_ike2_integ_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_notify_data_rohc_attr_icv_len,
      { "ROHC ICV Length in bytes",	"isakmp.notify.data.rohc.attr.icv_len",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	"In bytes", HFILL }},
   { &hf_isakmp_notify_data_rohc_attr_mrru,
      { "MRRU",	"isakmp.notify.data.rohc.attr.mrru",
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

    { &hf_isakmp_ts_number_of_ts,
      { "Number of Traffic Selector", "isakmp.ts.number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_isakmp_ts_type,
      { "Traffic Selector Type", "isakmp.ts.type",
        FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(traffic_selector_type), 0x0,
        NULL, HFILL }},
    { &hf_isakmp_ts_protoid,
      { "Protocol ID", "isakmp.ts.protoid",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, (&ipproto_val_ext), 0x0,
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
      { "Traffic Selector Data", "isakmp.ts.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_isakmp_num_spis,
      { "Port", "isakmp.spinum",
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
      { "Certificate Authority Signature", "ike.certreq.authority.sig",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL } },
    { &hf_isakmp_certreq_authority_v1,
      { "Certificate Authority Data", "ike.certreq.authority",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL } },
    { &hf_isakmp_certreq_authority_v2,
      { "Certificate Authority Data", "ike.certreq.authority",
       FT_BYTES, BASE_NONE, NULL, 0x0,
        "SHA-1 hash of the Certificate Authority", HFILL } },
    { &hf_isakmp_nat_keepalive,
      { "NAT Keepalive", "ike.nat_keepalive",
       FT_NONE, BASE_NONE, NULL, 0x0, "NAT Keepalive packet", HFILL } },
   { &hf_isakmp_nat_hash,
      { "HASH of the address and port",	"ike.nat_hash",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_nat_original_address_ipv4,
      { "NAT Original IPv4 Address",	"ike.nat_original_address_ipv4",
	FT_IPv4, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_nat_original_address_ipv6,
      { "NAT Original IPv6 Address",	"ike.nat_original_address_ipv6",
	FT_IPv6, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},

	/* Transform Attributes Type */
   { &hf_isakmp_tf_attr,
      { "Transform Attribute Type",	"isakmp.tf.attr",
	FT_NONE, BASE_NONE, NULL, 0x00,
	"ISAKMP Transform Attribute", HFILL }},
   { &hf_isakmp_tf_attr_type_v1,
      { "Transform Attribute Type",	"isakmp.tf.attr.type_v1",
	FT_UINT16, BASE_DEC, VALS(transform_isakmp_attr_type), 0x00,
	"ISAKMP (v1) Transform Attribute type", HFILL }},
   { &hf_isakmp_tf_attr_format,
      { "Transform Format",	"isakmp.tf.attr.format",
	FT_BOOLEAN, 16, TFS(&attribute_format), 0x8000,
	"ISAKMP Transform Attribute Format", HFILL }},
   { &hf_isakmp_tf_attr_length,
      { "Length",	"isakmp.tf.attr.length",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	"ISAKMP Tranform Attribute length", HFILL }},
   { &hf_isakmp_tf_attr_value,
      { "Value",	"isakmp.tf.attr.value",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	"ISAKMP Transform Attribute value", HFILL }},
   { &hf_isakmp_tf_attr_life_type,
      { "Life Type",	"isakmp.tf.attr.life_type",
	FT_UINT16, BASE_DEC, VALS(transform_attr_sa_life_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_tf_attr_life_duration_uint32,
      { "Life Duration",	"isakmp.tf.attr.life_duration",
	FT_UINT32, BASE_DEC, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_tf_attr_life_duration_uint64,
      { "Life Duration",	"isakmp.tf.attr.life_duration",
	FT_UINT64, BASE_DEC, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_tf_attr_life_duration_bytes,
      { "Life Duration",	"isakmp.tf.attr.life_duration",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_tf_attr_group_description,
      { "Group Description",	"isakmp.tf.attr.group_description",
	FT_UINT16, BASE_DEC, VALS(transform_dh_group_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_tf_attr_encap_mode,
      { "Encapsulation Mode",	"isakmp.tf.attr.encap_mode",
	FT_UINT16, BASE_DEC, VALS(transform_attr_encap_type), 0x00,
	NULL, HFILL }},
  { &hf_isakmp_tf_attr_auth_algorithm,
      { "Authentication Algorithm",	"isakmp.tf.attr.auth_algorithm",
	FT_UINT16, BASE_DEC, VALS(transform_attr_auth_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_tf_attr_key_length,
      { "Key Length",	"isakmp.tf.attr.key_length",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_tf_attr_key_rounds,
      { "Key Rounds",	"isakmp.tf.attr.key_rounds",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_tf_attr_cmpr_dict_size,
      { "Compress Dictionary Size",	"isakmp.tf.attr.cmpr_dict_size",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_tf_attr_cmpr_algorithm,
      { "Compress Private Algorithm",	"isakmp.tf.attr.cmpr_algorithm",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},
  { &hf_isakmp_tf_attr_ecn_tunnel,
      { "ECN Tunnel",	"isakmp.tf.attr.ecn_tunnel",
	FT_UINT16, BASE_DEC, VALS(transform_attr_ecn_type), 0x00,
	NULL, HFILL }},
  { &hf_isakmp_tf_attr_ext_seq_nbr,
      { "Extended (64-bit) Sequence Number",	"isakmp.tf.attr.ext_seq_nbr",
	FT_UINT16, BASE_DEC, VALS(transform_attr_ext_seq_nbr_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_tf_attr_auth_key_length,
      { "Authentication Key Length",	"isakmp.tf.attr.auth_key_length",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_tf_attr_sig_enco_algorithm,
      { "Signature Encoding Algorithm",	"isakmp.tf.attr.sig_enco_algorithm",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},
  { &hf_isakmp_tf_attr_addr_preservation,
      { "Address Preservation", "isakmp.tf.attr.addr_preservation",
        FT_UINT16, BASE_DEC, VALS(transform_attr_addr_preservation_type), 0x00,
        NULL, HFILL }},
  { &hf_isakmp_tf_attr_sa_direction,
      { "SA Direction", "isakmp.tf.attr.sa_direction",
        FT_UINT16, BASE_DEC, VALS(transform_attr_sa_direction_type), 0x00,
        NULL, HFILL }},

   { &hf_isakmp_ike_attr,
      { "Transform IKE Attribute Type",	"isakmp.ike.attr",
	FT_NONE, BASE_NONE, NULL, 0x00,
	"IKE Transform Attribute", HFILL }},
   { &hf_isakmp_ike_attr_type,
      { "Transform IKE Attribute Type",	"isakmp.ike.attr.type",
	FT_UINT16, BASE_DEC, VALS(transform_ike_attr_type), 0x00,
	"IKE Transform Attribute type", HFILL }},
   { &hf_isakmp_ike_attr_format,
      { "Transform IKE Format",	"isakmp.ike.attr.format",
	FT_BOOLEAN, 16, TFS(&attribute_format), 0x8000,
	"IKE Transform Attribute Format", HFILL }},
   { &hf_isakmp_ike_attr_length,
      { "Length",	"isakmp.ike.attr.length",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	"IKE Tranform Attribute length", HFILL }},
   { &hf_isakmp_ike_attr_value,
      { "Value",	"isakmp.ike.attr.value",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	"IKE Transform Attribute value", HFILL }},

   { &hf_isakmp_ike_attr_encryption_algorithm,
      { "Encryption Algorithm",	"isakmp.ike.attr.encryption_algorithm",
	FT_UINT16, BASE_DEC, VALS(transform_attr_enc_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike_attr_hash_algorithm,
      { "HASH Algorithm",	"isakmp.ike.attr.hash_algorithm",
	FT_UINT16, BASE_DEC, VALS(transform_attr_hash_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike_attr_authentication_method,
      { "Authentication Method",	"isakmp.ike.attr.authentication_method",
	FT_UINT16, BASE_DEC, VALS(transform_attr_authmeth_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike_attr_group_description,
      { "Group Description",	"isakmp.ike.attr.group_description",
	FT_UINT16, BASE_DEC, VALS(transform_dh_group_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike_attr_group_type,
      { "Groupe Type",	"isakmp.ike.attr.group_type",
	FT_UINT16, BASE_DEC, VALS(transform_attr_grp_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike_attr_group_prime,
      { "Groupe Prime",	"isakmp.ike.attr.group_prime",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike_attr_group_generator_one,
      { "Groupe Generator One",	"isakmp.ike.attr.group_generator_one",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike_attr_group_generator_two,
      { "Groupe Generator Two",	"isakmp.ike.attr.group_generator_two",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike_attr_group_curve_a,
      { "Groupe Curve A",	"isakmp.ike.attr.group_curve_a",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike_attr_group_curve_b,
      { "Groupe Curve B",	"isakmp.ike.attr.group_curve_b",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike_attr_life_type,
      { "Life Type",	"isakmp.ike.attr.life_type",
	FT_UINT16, BASE_DEC, VALS(transform_attr_sa_life_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike_attr_life_duration_uint32,
      { "Life Duration",	"isakmp.ike.attr.life_duration",
	FT_UINT32, BASE_DEC, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike_attr_life_duration_uint64,
      { "Life Duration",	"isakmp.ike.attr.life_duration",
	FT_UINT64, BASE_DEC, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike_attr_life_duration_bytes,
      { "Life Duration",	"isakmp.ike.attr.life_duration",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike_attr_prf,
      { "PRF",	"isakmp.ike.attr.prf",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike_attr_key_length,
      { "Key Length",	"isakmp.ike.attr.key_length",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike_attr_field_size,
      { "Field Size",	"isakmp.ike.attr.field_size",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike_attr_group_order,
      { "Key Length",	"isakmp.ike.attr.group_order",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},

   { &hf_isakmp_trans_type,
      { "Transform Type",	"isakmp.tf.type",
	FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(transform_ike2_type), 0x00,
	NULL, HFILL }},

   { &hf_isakmp_trans_encr,
      { "Transform ID (ENCR)",	"isakmp.tf.id.encr",
	FT_UINT16, BASE_DEC, VALS(transform_ike2_encr_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_trans_prf,
      { "Transform ID (PRF)",	"isakmp.tf.id.prf",
	FT_UINT16, BASE_DEC, VALS(transform_ike2_prf_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_trans_integ,
      { "Transform ID (INTEG)",	"isakmp.tf.id.integ",
	FT_UINT16, BASE_DEC, VALS(transform_ike2_integ_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_trans_dh,
      { "Transform ID (D-H)",	"isakmp.tf.id.dh",
	FT_UINT16, BASE_DEC, VALS(transform_dh_group_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_trans_esn,
      { "Transform ID (ESN)",	"isakmp.tf.id.esn",
	FT_UINT16, BASE_DEC, VALS(transform_ike2_esn_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_trans_id_v2,
      { "Transform ID",	"isakmp.tf.id",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_ike2_attr,
      { "Transform IKE2 Attribute Type",	"isakmp.ike2.attr",
	FT_NONE, BASE_NONE, NULL, 0x00,
	"IKE2 Transform Attribute", HFILL }},
   { &hf_isakmp_ike2_attr_type,
      { "Transform IKE2 Attribute Type",	"isakmp.ike2.attr.type",
	FT_UINT16, BASE_DEC, VALS(transform_ike2_attr_type), 0x00,
	"IKE2 Transform Attribute type", HFILL }},
   { &hf_isakmp_ike2_attr_format,
      { "Transform IKE2 Format",	"isakmp.ike2.attr.format",
	FT_BOOLEAN, 16, TFS(&attribute_format), 0x8000,
	"IKE2 Transform Attribute Format", HFILL }},
   { &hf_isakmp_ike2_attr_length,
      { "Length",	"isakmp.ike2.attr.length",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	"IKE2 Tranform Attribute length", HFILL }},
   { &hf_isakmp_ike2_attr_value,
      { "Value",	"isakmp.ike2.attr.value",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	"IKE2 Transform Attribute value", HFILL }},
   { &hf_isakmp_ike2_attr_key_length,
      { "Key Length",	"isakmp.ike2.attr.key_length",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	NULL, HFILL }},


   { &hf_isakmp_key_exch_dh_group,
      { "DH Group #",	"isakmp.key_exchange.dh_group",
	FT_UINT16, BASE_DEC, VALS(transform_dh_group_type), 0x00,
	NULL, HFILL }},
   { &hf_isakmp_key_exch_data,
      { "Key Exchange Data",	"isakmp.key_exchange.data",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},
   { &hf_isakmp_eap_data,
      { "EAP Message",	"isakmp.eap.data",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},

   { &hf_isakmp_gspm_data,
      { "GSPM",	"isakmp.gspm.data",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	"Generic Secure Password Method", HFILL }},

    { &hf_isakmp_cfg_type_v1,
      { "Type", "isakmp.cfg.type",
         FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(&vs_v1_cfgtype), 0x0,
         "ISAKMP (v1) Config Type", HFILL }},
    { &hf_isakmp_cfg_identifier,
      { "Identifier", "isakmp.cfg.identifier",
         FT_UINT16, BASE_DEC, NULL, 0x0,
         "ISAKMP (v1) Config Identifier", HFILL }},
    { &hf_isakmp_cfg_type_v2,
      { "Type", "isakmp.cfg.type",
         FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(&vs_v2_cfgtype), 0x0,
         "ISAKMP (v2) Config Type", HFILL }},
	/* Config Attributes Type */
   { &hf_isakmp_cfg_attr,
      { "Config Attribute Type",	"isakmp.cfg.attr",
	FT_NONE, BASE_NONE, NULL, 0x00,
	"ISAKMP Config Attribute", HFILL }},
   { &hf_isakmp_cfg_attr_type_v1,
      { "Type",	"isakmp.cfg.attr.type",
	FT_UINT16, BASE_RANGE_STRING | BASE_DEC, RVALS(&vs_v1_cfgattr), 0x00,
	"ISAKMP (v1) Config Attribute type", HFILL }},
   { &hf_isakmp_cfg_attr_type_v2,
      { "Type",	"isakmp.cfg.attr.type",
	FT_UINT16, BASE_RANGE_STRING | BASE_DEC, RVALS(&vs_v2_cfgattr), 0x00,
	"ISAKMP (v2) Config Attribute type", HFILL }},
   { &hf_isakmp_cfg_attr_format,
      { "Config Attribute Format",	"isakmp.cfg.attr.format",
	FT_BOOLEAN, 16, TFS(&attribute_format), 0x8000,
	"ISAKMP Config Attribute Format", HFILL }},
   { &hf_isakmp_cfg_attr_length,
      { "Length",	"isakmp.cfg.attr.length",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	"ISAKMP Config Attribute length", HFILL }},
   { &hf_isakmp_cfg_attr_value,
      { "Value",	"isakmp.cfg.attr.value",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	"ISAKMP Config Attribute value", HFILL }},
  { &hf_isakmp_cfg_attr_internal_ip4_address,
      { "INTERNAL IP4 ADDRESS",	"isakmp.cfg.attr.internal_ip4_address",
	FT_IPv4, BASE_NONE, NULL, 0x00,
	"An IPv4 address on the internal network", HFILL }},
 { &hf_isakmp_cfg_attr_internal_ip4_netmask,
      { "INTERNAL IP4 NETMASK",	"isakmp.cfg.attr.internal_ip4_netmask",
	FT_IPv4, BASE_NONE, NULL, 0x00,
	"The internal network's netmask", HFILL }},
 { &hf_isakmp_cfg_attr_internal_ip4_dns,
      { "INTERNAL IP4 DNS",	"isakmp.cfg.attr.internal_ip4_dns",
	FT_IPv4, BASE_NONE, NULL, 0x00,
	"An IPv4 address of a DNS server within the network", HFILL }},
 { &hf_isakmp_cfg_attr_internal_ip4_nbns,
      { "INTERNAL IP4 NBNS",	"isakmp.cfg.attr.internal_ip4_nbns",
	FT_IPv4, BASE_NONE, NULL, 0x00,
	"An IPv4 address of a NetBios Name Server (WINS) within the network", HFILL }},
 { &hf_isakmp_cfg_attr_internal_address_expiry,
      { "INTERNAL ADDRESS EXPIRY (Secs)",	"isakmp.cfg.attr.internal_address_expiry",
	FT_UINT32, BASE_DEC, NULL, 0x00,
	"Specifies the number of seconds that the host can use the internal IP address", HFILL }},
 { &hf_isakmp_cfg_attr_internal_ip4_dhcp,
      { "INTERNAL IP4 DHCP",	"isakmp.cfg.attr.internal_ip4_dhcp",
	FT_IPv4, BASE_NONE, NULL, 0x00,
	"the host to send any internal DHCP requests to the address", HFILL }},
  { &hf_isakmp_cfg_attr_application_version,
      { "APPLICATION VERSION",	"isakmp.cfg.attr.application_version",
	FT_STRING, BASE_NONE, NULL, 0x00,
	"The version or application information of the IPsec host", HFILL }},
  { &hf_isakmp_cfg_attr_internal_ip6_address,
      { "INTERNAL IP6 ADDRESS",	"isakmp.cfg.attr.internal_ip6_address",
	FT_IPv4, BASE_NONE, NULL, 0x00,
	"An IPv6 address on the internal network", HFILL }},
 { &hf_isakmp_cfg_attr_internal_ip6_netmask,
      { "INTERNAL IP4 NETMASK",	"isakmp.cfg.attr.internal_ip6_netmask",
	FT_IPv6, BASE_NONE, NULL, 0x00,
	"The internal network's netmask", HFILL }},
 { &hf_isakmp_cfg_attr_internal_ip6_dns,
      { "INTERNAL IP6 DNS",	"isakmp.cfg.attr.internal_ip6_dns",
	FT_IPv6, BASE_NONE, NULL, 0x00,
	"An IPv6 address of a DNS server within the network", HFILL }},
 { &hf_isakmp_cfg_attr_internal_ip6_nbns,
      { "INTERNAL IP6 NBNS",	"isakmp.cfg.attr.internal_ip6_nbns",
	FT_IPv6, BASE_NONE, NULL, 0x00,
	"An IPv6 address of a NetBios Name Server (WINS) within the network", HFILL }},
 { &hf_isakmp_cfg_attr_internal_ip6_dhcp,
      { "INTERNAL IP6 DHCP",	"isakmp.cfg.attr.internal_ip6_dhcp",
	FT_IPv6, BASE_NONE, NULL, 0x00,
	"The host to send any internal DHCP requests to the address", HFILL }},
 { &hf_isakmp_cfg_attr_internal_ip4_subnet_ip,
      { "INTERNAL IP4 SUBNET (IP)",	"isakmp.cfg.attr.internal_ip4_subnet_ip",
	FT_IPv4, BASE_NONE, NULL, 0x00,
	"The protected sub-networks that this edge-device protects (IP)", HFILL }},
 { &hf_isakmp_cfg_attr_internal_ip4_subnet_netmask,
      { "INTERNAL IP4 SUBNET (NETMASK)",	"isakmp.cfg.attr.internal_ip4_subnet_netmask",
	FT_IPv4, BASE_NONE, NULL, 0x00,
	"The protected sub-networks that this edge-device protects (IP)", HFILL }},
 { &hf_isakmp_cfg_attr_supported_attributes,
      { "SUPPORTED ATTRIBUTES",	"isakmp.cfg.attr.supported_attributes",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	NULL, HFILL }},
 { &hf_isakmp_cfg_attr_internal_ip6_subnet_ip,
      { "INTERNAL_IP6_SUBNET (IP)",	"isakmp.cfg.attr.internal_ip6_subnet_ip",
	FT_IPv6, BASE_NONE, NULL, 0x00,
	NULL, HFILL }},
 { &hf_isakmp_cfg_attr_internal_ip6_subnet_prefix,
      { "INTERNAL_IP6_SUBNET (PREFIX)",	"isakmp.cfg.attr.internal_ip6_subnet_prefix",
	FT_UINT8, BASE_DEC, NULL, 0x00,
	NULL, HFILL }},
 { &hf_isakmp_cfg_attr_internal_ip6_link_interface,
      { "INTERNAL_IP6_LINK (Link-Local Interface ID)",	"isakmp.cfg.attr.internal_ip6_link_interface",
	FT_UINT64, BASE_DEC, NULL, 0x00,
	"The Interface ID used for link-local address (by the party that sent this attribute)", HFILL }},
 { &hf_isakmp_cfg_attr_internal_ip6_link_id,
      { "INTERNAL_IP6_LINK (IKEv2 Link ID)",	"isakmp.cfg.attr.internal_ip6_link_id",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	"The Link ID is selected by the VPN gateway and is treated as an opaque octet string by the client.", HFILL }},
 { &hf_isakmp_cfg_attr_internal_ip6_prefix_ip,
      { "INTERNAL_IP6_PREFIX (IP)",	"isakmp.cfg.attr.internal_ip6_prefix_ip",
	FT_IPv6, BASE_NONE, NULL, 0x00,
	"An IPv6 prefix assigned to the virtual link", HFILL }},
 { &hf_isakmp_cfg_attr_internal_ip6_prefix_length,
      { "INTERNAL_IP6_PREFIX (Length)",	"isakmp.cfg.attr.internal_ip6_prefix_length",
	FT_UINT8, BASE_DEC, NULL, 0x00,
	 "The length of the prefix in bits (usually 64)", HFILL }},

  { &hf_isakmp_cfg_attr_xauth_type,
      { "XAUTH TYPE",	"isakmp.cfg.attr.xauth.type",
	FT_UINT16, BASE_RANGE_STRING | BASE_DEC, RVALS(cfgattr_xauth_type), 0x00,
	"The type of extended authentication requested", HFILL }},
  { &hf_isakmp_cfg_attr_xauth_user_name,
      { "XAUTH USER NAME",	"isakmp.cfg.attr.xauth.user_name",
	FT_STRING, BASE_NONE, NULL, 0x00,
	"The user name", HFILL }},
  { &hf_isakmp_cfg_attr_xauth_user_password,
      { "XAUTH USER PASSWORD",	"isakmp.cfg.attr.xauth.user_password",
	FT_STRING, BASE_NONE, NULL, 0x00,
	"The user's password", HFILL }},
  { &hf_isakmp_cfg_attr_xauth_passcode,
      { "XAUTH PASSCODE",	"isakmp.cfg.attr.xauth.passcode",
	FT_STRING, BASE_NONE, NULL, 0x00,
	"A token card's passcode", HFILL }},
  { &hf_isakmp_cfg_attr_xauth_message,
      { "XAUTH MESSAGE",	"isakmp.cfg.attr.xauth.message",
	FT_STRING, BASE_NONE, NULL, 0x00,
	"A textual message from an edge device to an IPSec host", HFILL }},
  { &hf_isakmp_cfg_attr_xauth_challenge,
      { "XAUTH CHALLENGE",	"isakmp.cfg.attr.xauth.challenge",
	FT_STRING, BASE_NONE, NULL, 0x00,
	"A challenge string sent from the edge device to the IPSec host for it to include in its calculation of a password", HFILL }},
  { &hf_isakmp_cfg_attr_xauth_domain,
      { "XAUTH DOMAIN",	"isakmp.cfg.attr.xauth.domain",
	FT_STRING, BASE_NONE, NULL, 0x00,
	"The domain to be authenticated in", HFILL }},
  { &hf_isakmp_cfg_attr_xauth_status,
      { "XAUTH STATUS",	"isakmp.cfg.attr.xauth.status",
	FT_UINT16, BASE_DEC, VALS(cfgattr_xauth_status), 0x00,
	"A variable that is used to denote authentication success or failure", HFILL }},
  { &hf_isakmp_cfg_attr_xauth_next_pin,
      { "XAUTH TYPE",	"isakmp.cfg.attr.xauth.next_pin",
	FT_STRING, BASE_NONE, NULL, 0x00,
	"A variable which is used when the edge device is requesting that the user choose a new pin number", HFILL }},
  { &hf_isakmp_cfg_attr_xauth_answer,
      { "XAUTH ANSWER",	"isakmp.cfg.attr.xauth.answer",
	FT_STRING, BASE_NONE, NULL, 0x00,
	"A variable length ASCII string used to send input to the edge device", HFILL }},
  { &hf_isakmp_cfg_attr_unity_banner,
      { "UNITY BANNER",	"isakmp.cfg.attr.unity.banner",
	FT_STRING, BASE_NONE, NULL, 0x00,
	"Banner", HFILL }},
  { &hf_isakmp_cfg_attr_unity_def_domain,
      { "UNITY DEF DOMAIN",	"isakmp.cfg.attr.unity.def_domain",
	FT_STRING, BASE_NONE, NULL, 0x00,
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
        FT_UINT16, BASE_DEC, NULL, 0x0,
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
  };


  static gint *ett[] = {
    &ett_isakmp,
    &ett_isakmp_flags,
    &ett_isakmp_payload,
    &ett_isakmp_fragment,
    &ett_isakmp_fragments,
    &ett_isakmp_sa,
    &ett_isakmp_tf_attr,
    &ett_isakmp_tf_ike_attr,
    &ett_isakmp_tf_ike2_attr,
    &ett_isakmp_id,
    &ett_isakmp_cfg_attr,
    &ett_isakmp_rohc_attr,
#ifdef HAVE_LIBGCRYPT
    &ett_isakmp_decrypted_data,
    &ett_isakmp_decrypted_payloads
#endif /* HAVE_LIBGCRYPT */
  };
#ifdef HAVE_LIBGCRYPT
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
#endif /* HAVE_LIBGCRYPT */
  proto_isakmp = proto_register_protocol("Internet Security Association and Key Management Protocol",
					       "ISAKMP", "isakmp");
  proto_register_field_array(proto_isakmp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine(&isakmp_init_protocol);

  register_dissector("isakmp", dissect_isakmp, proto_isakmp);

#ifdef HAVE_LIBGCRYPT
  isakmp_module = prefs_register_protocol(proto_isakmp, isakmp_prefs_apply_cb);
  ikev1_uat = uat_new("IKEv1 Decryption Table",
      sizeof(ikev1_uat_data_key_t),
      "ikev1_decryption_table",
      TRUE,
      (void*)&ikev1_uat_data,
      &num_ikev1_uat_data,
      UAT_CAT_CRYPTO,
      "ChIKEv1DecryptionSection",
      NULL,
      ikev1_uat_data_update_cb,
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
      (void*)&ikev2_uat_data,
      &num_ikev2_uat_data,
      UAT_CAT_CRYPTO,
      "ChIKEv2DecryptionSection",
      NULL,
      ikev2_uat_data_update_cb,
      NULL,
      NULL,
      ikev2_uat_flds);

  prefs_register_uat_preference(isakmp_module,
      "ikev2_decryption_table",
      "IKEv2 Decryption Table",
      "Table of IKE_SA security parameters for decryption of IKEv2 packets",
      ikev2_uat);

#endif /* HAVE_LIBGCRYPT */
}

void
proto_reg_handoff_isakmp(void)
{
  dissector_handle_t isakmp_handle;

  isakmp_handle = find_dissector("isakmp");
  eap_handle = find_dissector("eap");
  dissector_add_uint("udp.port", UDP_PORT_ISAKMP, isakmp_handle);
  dissector_add_uint("tcp.port", TCP_PORT_ISAKMP, isakmp_handle);
}
