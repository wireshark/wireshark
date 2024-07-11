/* packet-kerberos.c
 * Routines for Kerberos
 * Wes Hardaker (c) 2000
 * wjhardaker@ucdavis.edu
 * Richard Sharpe (C) 2002, rsharpe@samba.org, modularized a bit more and
 *                          added AP-REQ and AP-REP dissection
 *
 * Ronnie Sahlberg (C) 2004, major rewrite for new ASN.1/BER API.
 *                           decryption of kerberos blobs if keytab is provided
 *
 * See RFC 1510, and various I-Ds and other documents showing additions,
 * e.g. ones listed under
 *
 *	http://clifford.neuman.name/krb-revisions/
 *
 * and
 *
 *	https://tools.ietf.org/html/rfc4120
 *
 * and
 *
 *  https://tools.ietf.org/html/rfc6806
 *
 * Some structures from RFC2630
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Some of the development of the Kerberos protocol decoder was sponsored by
 * Cable Television Laboratories, Inc. ("CableLabs") based upon proprietary
 * CableLabs' specifications. Your license and use of this protocol decoder
 * does not mean that you are licensed to use the CableLabs'
 * specifications.  If you have questions about this protocol, contact
 * jf.mule [AT] cablelabs.com or c.stuart [AT] cablelabs.com for additional
 * information.
 */

#include <config.h>

#include <stdio.h>

// krb5.h needs to be included before the defines in packet-kerberos.h
#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
#ifdef _WIN32
/* prevent redefinition warnings in krb5's win-mac.h */
#define SSIZE_T_DEFINED
#endif /* _WIN32 */
#include <krb5.h>
#endif

#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/exceptions.h>
#include <epan/strutil.h>
#include <epan/conversation.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/srt_table.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/file_util.h>
#include <wsutil/str_util.h>
#include <wsutil/pint.h>
#include "packet-kerberos.h"
#include "packet-netbios.h"
#include "packet-tcp.h"
#include "packet-ber.h"
#include "packet-pkinit.h"
#include "packet-cms.h"
#include "packet-windows-common.h"

#include "read_keytab_file.h"

#include "packet-dcerpc-netlogon.h"
#include "packet-dcerpc.h"

#include "packet-gssapi.h"
#include "packet-x509af.h"

#define KEY_USAGE_FAST_REQ_CHKSUM       50
#define KEY_USAGE_FAST_ENC              51
#define KEY_USAGE_FAST_REP              52
#define KEY_USAGE_FAST_FINISHED         53
#define KEY_USAGE_ENC_CHALLENGE_CLIENT  54
#define KEY_USAGE_ENC_CHALLENGE_KDC     55

void proto_register_kerberos(void);
void proto_reg_handoff_kerberos(void);

#define UDP_PORT_KERBEROS		88
#define TCP_PORT_KERBEROS		88

#define ADDRESS_STR_BUFSIZ 256

typedef struct kerberos_key {
	uint32_t keytype;
	int keylength;
	const uint8_t *keyvalue;
} kerberos_key_t;

typedef void (*kerberos_key_save_fn)(tvbuff_t *tvb _U_, int offset _U_, int length _U_,
				     asn1_ctx_t *actx _U_, proto_tree *tree _U_,
				     int parent_hf_index _U_,
				     int hf_index _U_);

typedef struct kerberos_conv_t {
	wmem_list_t *frames;
} kerberos_conv_t;

typedef struct kerberos_frame_t {
	struct kerberos_frame_t *req;
	uint32_t frame;
	nstime_t time;
	uint32_t msg_type;
	int srt_idx;
} kerberos_frame_t;

typedef struct {
	uint32_t msg_type;
	bool is_win2k_pkinit;
	uint32_t errorcode;
	uint32_t etype;
	uint32_t padata_type;
	uint32_t is_enc_padata;
	uint32_t enctype;
	kerberos_key_t key;
	proto_tree *key_tree;
	proto_item *key_hidden_item;
	tvbuff_t *key_tvb;
	kerberos_callbacks *callbacks;
	uint32_t ad_type;
	uint32_t addr_type;
	uint32_t checksum_type;
#ifdef HAVE_KERBEROS
	enc_key_t *last_decryption_key;
	enc_key_t *last_added_key;
	enc_key_t *current_ticket_key;
	tvbuff_t *last_ticket_enc_part_tvb;
#endif
	int save_encryption_key_parent_hf_index;
	kerberos_key_save_fn save_encryption_key_fn;
	unsigned learnt_key_ids;
	unsigned missing_key_ids;
	wmem_list_t *decryption_keys;
	wmem_list_t *learnt_keys;
	wmem_list_t *missing_keys;
	uint32_t within_PA_TGS_REQ;
	struct _kerberos_PA_FX_FAST_REQUEST {
		bool defer;
		tvbuff_t *tvb;
		proto_tree *tree;
	} PA_FX_FAST_REQUEST;
#ifdef HAVE_KERBEROS
	enc_key_t *PA_TGS_REQ_key;
	enc_key_t *PA_TGS_REQ_subkey;
#endif
	uint32_t fast_type;
	uint32_t fast_armor_within_armor_value;
#ifdef HAVE_KERBEROS
	enc_key_t *PA_FAST_ARMOR_AP_key;
	enc_key_t *PA_FAST_ARMOR_AP_subkey;
	enc_key_t *fast_armor_key;
	enc_key_t *fast_strengthen_key;
#endif
	kerberos_conv_t *krb5_conv;
	uint32_t frame_req, frame_rep;
	nstime_t req_time;
} kerberos_private_data_t;

static dissector_handle_t kerberos_handle_tcp;
static dissector_handle_t kerberos_handle_udp;

/* Forward declarations */
static kerberos_private_data_t *kerberos_get_private_data(asn1_ctx_t *actx);
static int dissect_kerberos_Applications(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_AuthorizationData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_ENC_TIMESTAMP(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
#ifdef HAVE_KERBEROS
static int dissect_kerberos_PA_ENC_TS_ENC(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
#endif
static int dissect_kerberos_PA_PAC_REQUEST(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_S4U2Self(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_S4U_X509_USER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_ETYPE_INFO(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_ETYPE_INFO2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_AD_IF_RELEVANT(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_AUTHENTICATION_SET_ELEM(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_FX_FAST_REQUEST(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_EncryptedChallenge(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_KERB_KEY_LIST_REQ(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_KERB_KEY_LIST_REP(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_FX_FAST_REPLY(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_PAC_OPTIONS(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_KERB_AD_RESTRICTION_ENTRY(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_SEQUENCE_OF_ENCTYPE(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_SPAKE(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_DATA(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_T_rEP_SEQUENCE_OF_PA_DATA(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
#ifdef HAVE_KERBEROS
static int dissect_kerberos_KrbFastReq(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_KrbFastResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_FastOptions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
#endif
static int dissect_kerberos_KRB5_SRP_PA_ANNOUNCE(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_KRB5_SRP_PA_INIT(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_KRB5_SRP_PA_SERVER_CHALLENGE(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_KRB5_SRP_PA_CLIENT_RESPONSE(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_KRB5_SRP_PA_SERVER_VERIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* Desegment Kerberos over TCP messages */
static bool krb_desegment = true;

static int proto_kerberos;
static int kerberos_tap;

static int hf_krb_response_to;
static int hf_krb_response_in;
static int hf_krb_time;
static int hf_krb_rm_reserved;
static int hf_krb_rm_reclen;
static int hf_krb_provsrv_location;
static int hf_krb_pw_salt;
static int hf_krb_ext_error_nt_status;
static int hf_krb_ext_error_reserved;
static int hf_krb_ext_error_flags;
static int hf_krb_address_ip;
static int hf_krb_address_netbios;
static int hf_krb_address_ipv6;
static int hf_krb_gssapi_len;
static int hf_krb_gssapi_bnd;
static int hf_krb_gssapi_dlgopt;
static int hf_krb_gssapi_dlglen;
static int hf_krb_gssapi_c_flag_deleg;
static int hf_krb_gssapi_c_flag_mutual;
static int hf_krb_gssapi_c_flag_replay;
static int hf_krb_gssapi_c_flag_sequence;
static int hf_krb_gssapi_c_flag_conf;
static int hf_krb_gssapi_c_flag_integ;
static int hf_krb_gssapi_c_flag_dce_style;
static int hf_krb_midl_version;
static int hf_krb_midl_hdr_len;
static int hf_krb_midl_fill_bytes;
static int hf_krb_midl_blob_len;
static int hf_krb_pac_signature_type;
static int hf_krb_pac_signature_signature;
static int hf_krb_w2k_pac_entries;
static int hf_krb_w2k_pac_version;
static int hf_krb_w2k_pac_type;
static int hf_krb_w2k_pac_size;
static int hf_krb_w2k_pac_offset;
static int hf_krb_pac_clientid;
static int hf_krb_pac_namelen;
static int hf_krb_pac_clientname;
static int hf_krb_pac_logon_info;
static int hf_krb_pac_credential_data;
static int hf_krb_pac_credential_info;
static int hf_krb_pac_credential_info_version;
static int hf_krb_pac_credential_info_etype;
static int hf_krb_pac_s4u_delegation_info;
static int hf_krb_pac_upn_dns_info;
static int hf_krb_pac_upn_flags;
static int hf_krb_pac_upn_flag_upn_constructed;
static int hf_krb_pac_upn_flag_has_sam_name_and_sid;
static int hf_krb_pac_upn_upn_offset;
static int hf_krb_pac_upn_upn_len;
static int hf_krb_pac_upn_upn_name;
static int hf_krb_pac_upn_dns_offset;
static int hf_krb_pac_upn_dns_len;
static int hf_krb_pac_upn_dns_name;
static int hf_krb_pac_upn_samaccountname_offset;
static int hf_krb_pac_upn_samaccountname_len;
static int hf_krb_pac_upn_samaccountname;
static int hf_krb_pac_upn_objectsid_offset;
static int hf_krb_pac_upn_objectsid_len;
static int hf_krb_pac_server_checksum;
static int hf_krb_pac_privsvr_checksum;
static int hf_krb_pac_client_info_type;
static int hf_krb_pac_client_claims_info;
static int hf_krb_pac_device_info;
static int hf_krb_pac_device_claims_info;
static int hf_krb_pac_ticket_checksum;
static int hf_krb_pac_attributes_info;
static int hf_krb_pac_attributes_info_length;
static int hf_krb_pac_attributes_info_flags;
static int hf_krb_pac_attributes_info_flags_pac_was_requested;
static int hf_krb_pac_attributes_info_flags_pac_was_given_implicitly;
static int hf_krb_pac_requester_sid;
static int hf_krb_pac_full_checksum;
static int hf_krb_pa_supported_enctypes;
static int hf_krb_pa_supported_enctypes_des_cbc_crc;
static int hf_krb_pa_supported_enctypes_des_cbc_md5;
static int hf_krb_pa_supported_enctypes_rc4_hmac;
static int hf_krb_pa_supported_enctypes_aes128_cts_hmac_sha1_96;
static int hf_krb_pa_supported_enctypes_aes256_cts_hmac_sha1_96;
static int hf_krb_pa_supported_enctypes_aes256_cts_hmac_sha1_96_sk;
static int hf_krb_pa_supported_enctypes_fast_supported;
static int hf_krb_pa_supported_enctypes_compound_identity_supported;
static int hf_krb_pa_supported_enctypes_claims_supported;
static int hf_krb_pa_supported_enctypes_resource_sid_compression_disabled;
static int hf_krb_ad_ap_options;
static int hf_krb_ad_ap_options_cbt;
static int hf_krb_ad_ap_options_unverified_target_name;
static int hf_krb_ad_target_principal;
static int hf_krb_key_hidden_item;
static int hf_kerberos_KERB_TICKET_LOGON;
static int hf_kerberos_KERB_TICKET_LOGON_MessageType;
static int hf_kerberos_KERB_TICKET_LOGON_Flags;
static int hf_kerberos_KERB_TICKET_LOGON_ServiceTicketLength;
static int hf_kerberos_KERB_TICKET_LOGON_TicketGrantingTicketLength;
static int hf_kerberos_KERB_TICKET_LOGON_ServiceTicket;
static int hf_kerberos_KERB_TICKET_LOGON_TicketGrantingTicket;
static int hf_kerberos_KERB_TICKET_LOGON_FLAG_ALLOW_EXPIRED_TICKET;
static int hf_kerberos_KERB_TICKET_LOGON_FLAG_REDIRECTED;
#ifdef HAVE_KERBEROS
static int hf_kerberos_KrbFastResponse;
static int hf_kerberos_strengthen_key;
static int hf_kerberos_finished;
static int hf_kerberos_fast_options;
static int hf_kerberos_ticket_checksum;
static int hf_krb_patimestamp;
static int hf_krb_pausec;
static int hf_kerberos_FastOptions_reserved;
static int hf_kerberos_FastOptions_hide_client_names;
static int hf_kerberos_FastOptions_spare_bit2;
static int hf_kerberos_FastOptions_spare_bit3;
static int hf_kerberos_FastOptions_spare_bit4;
static int hf_kerberos_FastOptions_spare_bit5;
static int hf_kerberos_FastOptions_spare_bit6;
static int hf_kerberos_FastOptions_spare_bit7;
static int hf_kerberos_FastOptions_spare_bit8;
static int hf_kerberos_FastOptions_spare_bit9;
static int hf_kerberos_FastOptions_spare_bit10;
static int hf_kerberos_FastOptions_spare_bit11;
static int hf_kerberos_FastOptions_spare_bit12;
static int hf_kerberos_FastOptions_spare_bit13;
static int hf_kerberos_FastOptions_spare_bit14;
static int hf_kerberos_FastOptions_spare_bit15;
static int hf_kerberos_FastOptions_kdc_follow_referrals;

#endif
#include "packet-kerberos-hf.c"

/* Initialize the subtree pointers */
static int ett_kerberos;
static int ett_krb_recordmark;
static int ett_krb_pac;
static int ett_krb_pac_drep;
static int ett_krb_pac_midl_blob;
static int ett_krb_pac_logon_info;
static int ett_krb_pac_credential_info;
static int ett_krb_pac_s4u_delegation_info;
static int ett_krb_pac_upn_dns_info;
static int ett_krb_pac_upn_dns_info_flags;
static int ett_krb_pac_device_info;
static int ett_krb_pac_server_checksum;
static int ett_krb_pac_privsvr_checksum;
static int ett_krb_pac_client_info_type;
static int ett_krb_pac_ticket_checksum;
static int ett_krb_pac_attributes_info;
static int ett_krb_pac_attributes_info_flags;
static int ett_krb_pac_requester_sid;
static int ett_krb_pac_full_checksum;
static int ett_krb_pa_supported_enctypes;
static int ett_krb_ad_ap_options;
static int ett_kerberos_KERB_TICKET_LOGON;
#ifdef HAVE_KERBEROS
static int ett_krb_pa_enc_ts_enc;
static int ett_kerberos_KrbFastFinished;
static int ett_kerberos_KrbFastResponse;
static int ett_kerberos_KrbFastReq;
static int ett_kerberos_FastOptions;
#endif
#include "packet-kerberos-ett.c"

static expert_field ei_kerberos_missing_keytype;
static expert_field ei_kerberos_decrypted_keytype;
static expert_field ei_kerberos_learnt_keytype;
static expert_field ei_kerberos_address;
static expert_field ei_krb_gssapi_dlglen;

static dissector_handle_t krb4_handle;

/* Global variables */
static uint32_t gbl_keytype;
static bool gbl_do_col_info;

#include "packet-kerberos-val.h"

static void
call_kerberos_callbacks(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int tag, kerberos_callbacks *cb)
{
	if(!cb){
		return;
	}

	while(cb->tag){
		if(cb->tag==tag){
			cb->callback(pinfo, tvb, tree);
			return;
		}
		cb++;
	}
	return;
}

static int
krb5_frame_compare(gconstpointer a, gconstpointer b)
{
	kerberos_frame_t *fa = (kerberos_frame_t *)a;
	kerberos_frame_t *fb = (kerberos_frame_t *)b;

	return fa->frame - fb->frame;
}

static kerberos_conv_t *krb5_conv_find_or_create(packet_info *pinfo)
{
	conversation_t *conversation = NULL;
	kerberos_conv_t *kconv = NULL;

	conversation = find_or_create_conversation(pinfo);
	kconv = (kerberos_conv_t *)conversation_get_proto_data(conversation,
								proto_kerberos);
	if (kconv == NULL) {
		kconv = wmem_new0(wmem_file_scope(), kerberos_conv_t);
		kconv->frames = wmem_list_new(wmem_file_scope());

		conversation_add_proto_data(conversation, proto_kerberos, kconv);
	}

	return kconv;
}

static void krb5_conf_add_request(asn1_ctx_t *actx)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	packet_info *pinfo = actx->pinfo;
	kerberos_frame_t _krqf = { .frame = 0, };
	kerberos_frame_t *krqf = NULL;
	wmem_list_frame_t *wf = NULL;
	kerberos_frame_t *krpf = NULL;

	if (private_data->krb5_conv == NULL)
		return;

	if (!pinfo->fd->visited) {
		krqf = wmem_new0(wmem_file_scope(), kerberos_frame_t);
		if (krqf == NULL) {
			return;
		}
	} else {
		krqf = &_krqf;
	}

	krqf->frame = pinfo->num;
	krqf->time = pinfo->abs_ts;
	krqf->msg_type = private_data->msg_type;
	krqf->srt_idx = -1;

	if (!pinfo->fd->visited) {
		wmem_list_insert_sorted(private_data->krb5_conv->frames,
					krqf, krb5_frame_compare);
	}

	wf = wmem_list_find_custom(private_data->krb5_conv->frames,
				   krqf, krb5_frame_compare);
	if (wf != NULL) {
		/*
		 * replace the pointer with the one allocated on
		 * wmem_file_scope()
		 */
		krqf = (kerberos_frame_t *)wmem_list_frame_data(wf);
		/* The next one should be the response */
		wf = wmem_list_frame_next(wf);
	}
	if (wf == NULL) {
		return;
	}
	krpf = (kerberos_frame_t *)wmem_list_frame_data(wf);

	switch (krpf->msg_type) {
	case KERBEROS_APPLICATIONS_AS_REP:
	case KERBEROS_APPLICATIONS_TGS_REP:
	case KERBEROS_APPLICATIONS_KRB_ERROR:
		break;
	default:
		return;
	}

	private_data->frame_rep = krpf->frame;
}

static void krb5_conf_add_response(asn1_ctx_t *actx)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	packet_info *pinfo = actx->pinfo;
	kerberos_frame_t _krpf = { .frame = 0, };
	kerberos_frame_t *krpf = NULL;
	wmem_list_frame_t *wf = NULL;
	kerberos_frame_t *krqf = NULL;

	if (private_data->krb5_conv == NULL)
		return;

	if (!pinfo->fd->visited) {
		krpf = wmem_new0(wmem_file_scope(), kerberos_frame_t);
		if (krpf == NULL) {
			return;
		}
	} else {
		krpf = &_krpf;
	}

	krpf->frame = pinfo->num;
	krpf->time = pinfo->abs_ts;
	krpf->msg_type = private_data->msg_type;
	krpf->srt_idx = -1;

	if (!pinfo->fd->visited) {
		wmem_list_insert_sorted(private_data->krb5_conv->frames,
					krpf, krb5_frame_compare);
	}

	wf = wmem_list_find_custom(private_data->krb5_conv->frames,
				   krpf, krb5_frame_compare);
	if (wf != NULL) {
		/*
		 * replace the pointer with the one allocated on
		 * wmem_file_scope()
		 */
		krpf = (kerberos_frame_t *)wmem_list_frame_data(wf);
		/* The previous one should be the request */
		wf = wmem_list_frame_prev(wf);
	}
	if (wf == NULL) {
		return;
	}
	krqf = (kerberos_frame_t *)wmem_list_frame_data(wf);
	krpf->req = krqf;

	switch (krqf->msg_type) {
	case KERBEROS_APPLICATIONS_AS_REQ:
		if (private_data->msg_type == KERBEROS_APPLICATIONS_AS_REP) {
			krpf->srt_idx = 0;
			break;
		}
		if (private_data->msg_type == KERBEROS_APPLICATIONS_KRB_ERROR) {
			krpf->srt_idx = 1;
			break;
		}
		return;
	case KERBEROS_APPLICATIONS_TGS_REQ:
		if (private_data->msg_type == KERBEROS_APPLICATIONS_TGS_REP) {
			krpf->srt_idx = 2;
			break;
		}
		if (private_data->msg_type == KERBEROS_APPLICATIONS_KRB_ERROR) {
			krpf->srt_idx = 3;
			break;
		}
		return;
	default:
		return;
	}

	private_data->frame_req = krqf->frame;
	private_data->req_time = krqf->time;

	tap_queue_packet(kerberos_tap, pinfo, krpf);
}

static void
krb5stat_init(struct register_srt* srt _U_, GArray* srt_array _U_)
{
	srt_stat_table *krb5_srt_table = NULL;

	krb5_srt_table = init_srt_table("Kerberos", "krb5", srt_array, 4, NULL, "kerberos.msg_type", NULL);
	init_srt_table_row(krb5_srt_table, 0, "AS-REP");
	init_srt_table_row(krb5_srt_table, 1, "AS-ERROR");
	init_srt_table_row(krb5_srt_table, 2, "TGS-REP");
	init_srt_table_row(krb5_srt_table, 3, "TGS-ERROR");
}

static tap_packet_status
krb5stat_packet(void *pss _U_, packet_info *pinfo, epan_dissect_t *edt _U_, const void *prv, tap_flags_t flags _U_)
{
	srt_stat_table *krb5_srt_table = NULL;
	srt_data_t *data = (srt_data_t *)pss;
	kerberos_frame_t *krpf = (kerberos_frame_t *)prv;

	if (krpf == NULL)
		return TAP_PACKET_DONT_REDRAW;

	if (krpf->req == NULL)
		return TAP_PACKET_DONT_REDRAW;

	krb5_srt_table = g_array_index(data->srt_array, srt_stat_table*, 0);
	add_srt_table_data(krb5_srt_table, krpf->srt_idx, &krpf->req->time, pinfo);
	return TAP_PACKET_REDRAW;
}

static kerberos_private_data_t*
kerberos_new_private_data(packet_info *pinfo)
{
	kerberos_private_data_t *p;
	void *existing;

	p = wmem_new0(pinfo->pool, kerberos_private_data_t);
	if (p == NULL) {
		return NULL;
	}
	p->frame_req = UINT32_MAX;
	p->frame_rep = UINT32_MAX;

	p->decryption_keys = wmem_list_new(pinfo->pool);
	p->learnt_keys = wmem_list_new(pinfo->pool);
	p->missing_keys = wmem_list_new(pinfo->pool);

	existing = p_get_proto_data(pinfo->pool, pinfo, proto_kerberos, 0);
	if (existing != NULL) {
		/*
		 * We only remember the first one.
		 */
		return p;
	}

	p_add_proto_data(pinfo->pool, pinfo, proto_kerberos, 0, p);
	p->krb5_conv = krb5_conv_find_or_create(pinfo);
	return p;
}

static kerberos_private_data_t*
kerberos_get_private_data(asn1_ctx_t *actx)
{
	if (!actx->private_data) {
		actx->private_data = kerberos_new_private_data(actx->pinfo);
	}
	return (kerberos_private_data_t *)(actx->private_data);
}

static bool
kerberos_private_is_kdc_req(kerberos_private_data_t *private_data)
{
	switch (private_data->msg_type) {
	case KERBEROS_APPLICATIONS_AS_REQ:
	case KERBEROS_APPLICATIONS_TGS_REQ:
		return true;
	}

	return false;
}

bool
kerberos_is_win2k_pkinit(asn1_ctx_t *actx)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

	return private_data->is_win2k_pkinit;
}

static int dissect_kerberos_defer_PA_FX_FAST_REQUEST(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
	kerberos_private_data_t* private_data = kerberos_get_private_data(actx);

	/*
	 * dissect_ber_octet_string_wcb() always passes
	 * implicit_tag=false, offset=0 and hf_index=-1
	 *
	 * It means we only need to remember tvb and tree
	 * in order to replay dissect_kerberos_PA_FX_FAST_REQUEST()
	 * in dissect_kerberos_T_rEQ_SEQUENCE_OF_PA_DATA()
	 */
	ws_assert(implicit_tag == false);
	ws_assert(offset == 0);
	ws_assert(hf_index <= 0);

	if (private_data->PA_FX_FAST_REQUEST.defer) {
		/*
		 * Remember the tvb (and the optional tree)
		 */
		private_data->PA_FX_FAST_REQUEST.tvb = tvb;
		private_data->PA_FX_FAST_REQUEST.tree = tree;
		/*
		 * only handle the first PA_FX_FAST_REQUEST...
		 */
		private_data->PA_FX_FAST_REQUEST.defer = false;
		return tvb_reported_length_remaining(tvb, offset);
	}

	return dissect_kerberos_PA_FX_FAST_REQUEST(implicit_tag, tvb, offset, actx, tree, hf_index);
}

#ifdef HAVE_KERBEROS

/* Decrypt Kerberos blobs */
bool krb_decrypt;

/* keytab filename */
static const char *keytab_filename = "";

void
read_keytab_file_from_preferences(void)
{
	static char *last_keytab = NULL;

	if (!krb_decrypt) {
		return;
	}

	if (keytab_filename == NULL) {
		return;
	}

	if (last_keytab && !strcmp(last_keytab, keytab_filename)) {
		return;
	}

	g_free(last_keytab);
	last_keytab = g_strdup(keytab_filename);

	read_keytab_file(last_keytab);
}
#endif /* HAVE_KERBEROS */

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
enc_key_t *enc_key_list=NULL;
static unsigned kerberos_longterm_ids;
wmem_map_t *kerberos_longterm_keys;
static wmem_map_t *kerberos_all_keys;
static wmem_map_t *kerberos_app_session_keys;

static bool
enc_key_list_cb(wmem_allocator_t* allocator _U_, wmem_cb_event_t event _U_, void *user_data _U_)
{
	enc_key_list = NULL;
	kerberos_longterm_ids = 0;
	/* keep the callback registered */
	return true;
}

static int enc_key_cmp_id(const void *k1, const void *k2)
{
	const enc_key_t *key1 = (const enc_key_t *)k1;
	const enc_key_t *key2 = (const enc_key_t *)k2;

	if (key1->fd_num < key2->fd_num) {
		return -1;
	}
	if (key1->fd_num > key2->fd_num) {
		return 1;
	}

	if (key1->id < key2->id) {
		return -1;
	}
	if (key1->id > key2->id) {
		return 1;
	}

	return 0;
}

static gboolean
enc_key_content_equal(const void *k1, const void *k2)
{
	const enc_key_t *key1 = (const enc_key_t *)k1;
	const enc_key_t *key2 = (const enc_key_t *)k2;
	int cmp;

	if (key1->keytype != key2->keytype) {
		return false;
	}

	if (key1->keylength != key2->keylength) {
		return false;
	}

	cmp = memcmp(key1->keyvalue, key2->keyvalue, key1->keylength);
	if (cmp != 0) {
		return false;
	}

	return true;
}

static unsigned
enc_key_content_hash(const void *k)
{
	const enc_key_t *key = (const enc_key_t *)k;
	unsigned ret = 0;

	ret += wmem_strong_hash((const uint8_t *)&key->keytype,
				sizeof(key->keytype));
	ret += wmem_strong_hash((const uint8_t *)&key->keylength,
				sizeof(key->keylength));
	ret += wmem_strong_hash((const uint8_t *)key->keyvalue,
				key->keylength);

	return ret;
}

static void
kerberos_key_map_insert(wmem_map_t *key_map, enc_key_t *new_key)
{
	enc_key_t *existing = NULL;
	enc_key_t *cur = NULL;
	int cmp;

	existing = (enc_key_t *)wmem_map_lookup(key_map, new_key);
	if (existing == NULL) {
		wmem_map_insert(key_map, new_key, new_key);
		return;
	}

	if (key_map != kerberos_all_keys) {
		/*
		 * It should already be linked to the existing key...
		 */
		return;
	}

	if (existing->fd_num == -1 && new_key->fd_num != -1) {
		/*
		 * We can't reference a learnt key
		 * from a longterm key. As they have
		 * a shorter lifetime.
		 *
		 * So just let the learnt key remember the
		 * match.
		 */
		new_key->same_list = existing;
		new_key->num_same = existing->num_same + 1;
		return;
	}

	/*
	 * If a key with the same content (keytype,keylength,keyvalue)
	 * already exists, we want the earliest key to be
	 * in the list.
	 */
	cmp = enc_key_cmp_id(new_key, existing);
	if (cmp == 0) {
		/*
		 * It's the same, nothing to do...
		 */
		return;
	}
	if (cmp < 0) {
		/* The new key has should be added to the list. */
		new_key->same_list = existing;
		new_key->num_same = existing->num_same + 1;
		wmem_map_insert(key_map, new_key, new_key);
		return;
	}

	/*
	 * We want to link the new_key to the existing one.
	 *
	 * But we want keep the list sorted, so we need to forward
	 * to the correct spot.
	 */
	for (cur = existing; cur->same_list != NULL; cur = cur->same_list) {
		cmp = enc_key_cmp_id(new_key, cur->same_list);
		if (cmp == 0) {
			/*
			 * It's the same, nothing to do...
			 */
			return;
		}

		if (cmp < 0) {
			/*
			 * We found the correct spot,
			 * the new_key should added
			 * between existing and existing->same_list
			 */
			new_key->same_list = cur->same_list;
			new_key->num_same = cur->num_same;
			break;
		}
	}

	/*
	 * finally link new_key to existing
	 * and fix up the numbers
	 */
	cur->same_list = new_key;
	for (cur = existing; cur != new_key; cur = cur->same_list) {
		cur->num_same += 1;
	}

	return;
}

struct insert_longterm_keys_into_key_map_state {
	wmem_map_t *key_map;
};

static void insert_longterm_keys_into_key_map_cb(void *__key _U_,
						 void *value,
						 void *user_data)
{
	struct insert_longterm_keys_into_key_map_state *state =
		(struct insert_longterm_keys_into_key_map_state *)user_data;
	enc_key_t *key = (enc_key_t *)value;

	kerberos_key_map_insert(state->key_map, key);
}

static void insert_longterm_keys_into_key_map(wmem_map_t *key_map)
{
	/*
	 * Because the kerberos_longterm_keys are allocated on
	 * wmem_epan_scope() and kerberos_all_keys are allocated
	 * on wmem_file_scope(), we need to plug the longterm keys
	 * back to kerberos_all_keys if a new file was loaded
	 * and wmem_file_scope() got cleared.
	 */
	if (wmem_map_size(key_map) < wmem_map_size(kerberos_longterm_keys)) {
		struct insert_longterm_keys_into_key_map_state state = {
			.key_map = key_map,
		};
		/*
		 * Reference all longterm keys into kerberos_all_keys
		 */
		wmem_map_foreach(kerberos_longterm_keys,
				 insert_longterm_keys_into_key_map_cb,
				 &state);
	}
}

static void
kerberos_key_list_append(wmem_list_t *key_list, enc_key_t *new_key)
{
	enc_key_t *existing = NULL;

	existing = (enc_key_t *)wmem_list_find(key_list, new_key);
	if (existing != NULL) {
		return;
	}

	wmem_list_append(key_list, new_key);
}

static void
add_encryption_key(packet_info *pinfo,
		   kerberos_private_data_t *private_data,
		   proto_tree *key_tree,
		   proto_item *key_hidden_item,
		   tvbuff_t *key_tvb,
		   int keytype, int keylength, const char *keyvalue,
		   const char *origin,
		   enc_key_t *src1, enc_key_t *src2)
{
	wmem_allocator_t *key_scope = NULL;
	enc_key_t *new_key = NULL;
	const char *methodl = "learnt";
	const char *methodu = "Learnt";
	proto_item *item = NULL;

	private_data->last_added_key = NULL;

	if (src1 != NULL && src2 != NULL) {
		methodl = "derived";
		methodu = "Derived";
	}

	if(pinfo->fd->visited){
		/*
		 * We already processed this,
		 * we can use a shortterm scope
		 */
		key_scope = pinfo->pool;
	} else {
		/*
		 * As long as we have enc_key_list, we need to
		 * use wmem_epan_scope(), when that's gone
		 * we can dynamically select the scope based on
		 * how long we'll need the particular key.
		 */
		key_scope = wmem_epan_scope();
	}

	new_key = wmem_new0(key_scope, enc_key_t);
	snprintf(new_key->key_origin, KRB_MAX_ORIG_LEN, "%s %s in frame %u",
		   methodl, origin, pinfo->num);
	new_key->fd_num = pinfo->num;
	new_key->id = ++private_data->learnt_key_ids;
	snprintf(new_key->id_str, KRB_MAX_ID_STR_LEN, "%d.%u",
		   new_key->fd_num, new_key->id);
	new_key->keytype=keytype;
	new_key->keylength=keylength;
	memcpy(new_key->keyvalue, keyvalue, MIN(keylength, KRB_MAX_KEY_LENGTH));
	new_key->src1 = src1;
	new_key->src2 = src2;

	if(!pinfo->fd->visited){
		/*
		 * Only keep it if we don't processed it before.
		 */
		new_key->next=enc_key_list;
		enc_key_list=new_key;
		insert_longterm_keys_into_key_map(kerberos_all_keys);
		kerberos_key_map_insert(kerberos_all_keys, new_key);
	}

	item = proto_tree_add_expert_format(key_tree, pinfo, &ei_kerberos_learnt_keytype,
			key_tvb, 0, keylength,
			"%s %s keytype %d (id=%d.%u) (%02x%02x%02x%02x...)",
			methodu, origin, keytype, pinfo->num, new_key->id,
			keyvalue[0] & 0xFF, keyvalue[1] & 0xFF,
			keyvalue[2] & 0xFF, keyvalue[3] & 0xFF);
	if (item != NULL && key_hidden_item != NULL) {
		proto_tree_move_item(key_tree, key_hidden_item, item);
	}
	if (src1 != NULL) {
		enc_key_t *sek = src1;
		expert_add_info_format(pinfo, item, &ei_kerberos_learnt_keytype,
				       "SRC1 %s keytype %d (id=%s same=%u) (%02x%02x%02x%02x...)",
				       sek->key_origin, sek->keytype,
				       sek->id_str, sek->num_same,
				       sek->keyvalue[0] & 0xFF, sek->keyvalue[1] & 0xFF,
				       sek->keyvalue[2] & 0xFF, sek->keyvalue[3] & 0xFF);
	}
	if (src2 != NULL) {
		enc_key_t *sek = src2;
		expert_add_info_format(pinfo, item, &ei_kerberos_learnt_keytype,
				       "SRC2 %s keytype %d (id=%s same=%u) (%02x%02x%02x%02x...)",
				       sek->key_origin, sek->keytype,
				       sek->id_str, sek->num_same,
				       sek->keyvalue[0] & 0xFF, sek->keyvalue[1] & 0xFF,
				       sek->keyvalue[2] & 0xFF, sek->keyvalue[3] & 0xFF);
	}

	kerberos_key_list_append(private_data->learnt_keys, new_key);
	private_data->last_added_key = new_key;
}

static void
save_encryption_key(tvbuff_t *tvb _U_, int offset _U_, int length _U_,
		    asn1_ctx_t *actx _U_, proto_tree *tree _U_,
		    int parent_hf_index _U_,
		    int hf_index _U_)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	const char *parent = proto_registrar_get_name(parent_hf_index);
	const char *element = proto_registrar_get_name(hf_index);
	char origin[KRB_MAX_ORIG_LEN] = { 0, };

	snprintf(origin, KRB_MAX_ORIG_LEN, "%s_%s", parent, element);

	add_encryption_key(actx->pinfo,
			   private_data,
			   private_data->key_tree,
			   private_data->key_hidden_item,
			   private_data->key_tvb,
			   private_data->key.keytype,
			   private_data->key.keylength,
			   private_data->key.keyvalue,
			   origin,
			   NULL,
			   NULL);
}

static void
save_Authenticator_subkey(tvbuff_t *tvb, int offset, int length,
			  asn1_ctx_t *actx, proto_tree *tree,
			  int parent_hf_index,
			  int hf_index)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

	save_encryption_key(tvb, offset, length, actx, tree, parent_hf_index, hf_index);

	if (private_data->last_decryption_key == NULL) {
		return;
	}
	if (private_data->last_added_key == NULL) {
		return;
	}

	if (private_data->within_PA_TGS_REQ != 0) {
		private_data->PA_TGS_REQ_key = private_data->last_decryption_key;
		private_data->PA_TGS_REQ_subkey = private_data->last_added_key;
	}
	if (private_data->fast_armor_within_armor_value != 0) {
		private_data->PA_FAST_ARMOR_AP_key = private_data->last_decryption_key;
		private_data->PA_FAST_ARMOR_AP_subkey = private_data->last_added_key;
	}
}

static void
save_EncAPRepPart_subkey(tvbuff_t *tvb, int offset, int length,
			 asn1_ctx_t *actx, proto_tree *tree,
			 int parent_hf_index,
			 int hf_index)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

	save_encryption_key(tvb, offset, length, actx, tree, parent_hf_index, hf_index);

	if (actx->pinfo->fd->visited) {
		return;
	}

	if (private_data->last_added_key == NULL) {
		return;
	}

	private_data->last_added_key->is_ap_rep_key = true;

	if (private_data->last_decryption_key != NULL &&
	    private_data->last_decryption_key->is_ticket_key)
	{
		enc_key_t *ak = private_data->last_added_key;
		enc_key_t *tk = private_data->last_decryption_key;

		/*
		 * The enc_key_t structures and their strings
		 * in pac_names are all allocated on wmem_epan_scope(),
		 * so we don't need to copy the content.
		 */
		ak->pac_names = tk->pac_names;
	}

	kerberos_key_map_insert(kerberos_app_session_keys, private_data->last_added_key);
}

static void
save_EncKDCRepPart_key(tvbuff_t *tvb, int offset, int length,
		       asn1_ctx_t *actx, proto_tree *tree,
		       int parent_hf_index,
		       int hf_index)
{
	save_encryption_key(tvb, offset, length, actx, tree, parent_hf_index, hf_index);
}

static void
save_EncTicketPart_key(tvbuff_t *tvb, int offset, int length,
		       asn1_ctx_t *actx, proto_tree *tree,
		       int parent_hf_index,
		       int hf_index)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

	save_encryption_key(tvb, offset, length, actx, tree, parent_hf_index, hf_index);

	if (actx->pinfo->fd->visited) {
		return;
	}

	if (private_data->last_added_key == NULL) {
		return;
	}

	private_data->current_ticket_key = private_data->last_added_key;
	private_data->current_ticket_key->is_ticket_key = true;
}

static void
save_KrbCredInfo_key(tvbuff_t *tvb, int offset, int length,
		     asn1_ctx_t *actx, proto_tree *tree,
		     int parent_hf_index,
		     int hf_index)
{
	save_encryption_key(tvb, offset, length, actx, tree, parent_hf_index, hf_index);
}

static void
save_KrbFastResponse_strengthen_key(tvbuff_t *tvb, int offset, int length,
				    asn1_ctx_t *actx, proto_tree *tree,
				    int parent_hf_index,
				    int hf_index)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

	save_encryption_key(tvb, offset, length, actx, tree, parent_hf_index, hf_index);

	private_data->fast_strengthen_key = private_data->last_added_key;
}

static void used_encryption_key(proto_tree *tree, packet_info *pinfo,
				kerberos_private_data_t *private_data,
				enc_key_t *ek, int usage, tvbuff_t *cryptotvb,
				const char *keymap_name,
				unsigned keymap_size,
				unsigned decryption_count)
{
	proto_item *item = NULL;
	enc_key_t *sek = NULL;

	item = proto_tree_add_expert_format(tree, pinfo, &ei_kerberos_decrypted_keytype,
				     cryptotvb, 0, 0,
				     "Decrypted keytype %d usage %d "
				     "using %s (id=%s same=%u) (%02x%02x%02x%02x...)",
				     ek->keytype, usage, ek->key_origin, ek->id_str, ek->num_same,
				     ek->keyvalue[0] & 0xFF, ek->keyvalue[1] & 0xFF,
				     ek->keyvalue[2] & 0xFF, ek->keyvalue[3] & 0xFF);
	expert_add_info_format(pinfo, item, &ei_kerberos_decrypted_keytype,
			       "Used keymap=%s num_keys=%u num_tries=%u)",
			       keymap_name,
			       keymap_size,
			       decryption_count);
	if (ek->src1 != NULL) {
		sek = ek->src1;
		expert_add_info_format(pinfo, item, &ei_kerberos_decrypted_keytype,
				       "SRC1 %s keytype %d (id=%s same=%u) (%02x%02x%02x%02x...)",
				       sek->key_origin, sek->keytype,
				       sek->id_str, sek->num_same,
				       sek->keyvalue[0] & 0xFF, sek->keyvalue[1] & 0xFF,
				       sek->keyvalue[2] & 0xFF, sek->keyvalue[3] & 0xFF);
	}
	if (ek->src2 != NULL) {
		sek = ek->src2;
		expert_add_info_format(pinfo, item, &ei_kerberos_decrypted_keytype,
				       "SRC2 %s keytype %d (id=%s same=%u) (%02x%02x%02x%02x...)",
				       sek->key_origin, sek->keytype,
				       sek->id_str, sek->num_same,
				       sek->keyvalue[0] & 0xFF, sek->keyvalue[1] & 0xFF,
				       sek->keyvalue[2] & 0xFF, sek->keyvalue[3] & 0xFF);
	}
	sek = ek->same_list;
	while (sek != NULL) {
		expert_add_info_format(pinfo, item, &ei_kerberos_decrypted_keytype,
				       "Decrypted keytype %d usage %d "
				       "using %s (id=%s same=%u) (%02x%02x%02x%02x...)",
				       sek->keytype, usage, sek->key_origin, sek->id_str, sek->num_same,
				       sek->keyvalue[0] & 0xFF, sek->keyvalue[1] & 0xFF,
				       sek->keyvalue[2] & 0xFF, sek->keyvalue[3] & 0xFF);
		sek = sek->same_list;
	}
	kerberos_key_list_append(private_data->decryption_keys, ek);
	private_data->last_decryption_key = ek;
}
#endif /* HAVE_HEIMDAL_KERBEROS || HAVE_MIT_KERBEROS */

#ifdef HAVE_MIT_KERBEROS

static void missing_encryption_key(proto_tree *tree, packet_info *pinfo,
				   kerberos_private_data_t *private_data,
				   int keytype, int usage, tvbuff_t *cryptotvb,
				   const char *keymap_name,
				   unsigned keymap_size,
				   unsigned decryption_count)
{
	proto_item *item = NULL;
	enc_key_t *mek = NULL;

	mek = wmem_new0(pinfo->pool, enc_key_t);
	snprintf(mek->key_origin, KRB_MAX_ORIG_LEN,
		   "keytype %d usage %d missing in frame %u",
		   keytype, usage, pinfo->num);
	mek->fd_num = pinfo->num;
	mek->id = ++private_data->missing_key_ids;
	snprintf(mek->id_str, KRB_MAX_ID_STR_LEN, "missing.%u",
		   mek->id);
	mek->keytype=keytype;

	item = proto_tree_add_expert_format(tree, pinfo, &ei_kerberos_missing_keytype,
					    cryptotvb, 0, 0,
					    "Missing keytype %d usage %d (id=%s)",
					    keytype, usage, mek->id_str);
	expert_add_info_format(pinfo, item, &ei_kerberos_missing_keytype,
			       "Used keymap=%s num_keys=%u num_tries=%u)",
			       keymap_name,
			       keymap_size,
			       decryption_count);

	kerberos_key_list_append(private_data->missing_keys, mek);
}

#ifdef HAVE_KRB5_PAC_VERIFY
static void used_signing_key(proto_tree *tree, packet_info *pinfo,
			     kerberos_private_data_t *private_data,
			     enc_key_t *ek, tvbuff_t *tvb,
			     krb5_cksumtype checksum,
			     const char *reason,
			     const char *keymap_name,
			     unsigned keymap_size,
			     unsigned verify_count)
{
	proto_item *item = NULL;
	enc_key_t *sek = NULL;

	item = proto_tree_add_expert_format(tree, pinfo, &ei_kerberos_decrypted_keytype,
				     tvb, 0, 0,
				     "%s checksum %d keytype %d "
				     "using %s (id=%s same=%u) (%02x%02x%02x%02x...)",
				     reason, checksum, ek->keytype, ek->key_origin,
				     ek->id_str, ek->num_same,
				     ek->keyvalue[0] & 0xFF, ek->keyvalue[1] & 0xFF,
				     ek->keyvalue[2] & 0xFF, ek->keyvalue[3] & 0xFF);
	expert_add_info_format(pinfo, item, &ei_kerberos_decrypted_keytype,
			       "Used keymap=%s num_keys=%u num_tries=%u)",
			       keymap_name,
			       keymap_size,
			       verify_count);
	sek = ek->same_list;
	while (sek != NULL) {
		expert_add_info_format(pinfo, item, &ei_kerberos_decrypted_keytype,
				       "%s checksum %d keytype %d "
				       "using %s (id=%s same=%u) (%02x%02x%02x%02x...)",
				       reason, checksum, sek->keytype, sek->key_origin,
				       sek->id_str, sek->num_same,
				       sek->keyvalue[0] & 0xFF, sek->keyvalue[1] & 0xFF,
				       sek->keyvalue[2] & 0xFF, sek->keyvalue[3] & 0xFF);
		sek = sek->same_list;
	}
	kerberos_key_list_append(private_data->decryption_keys, ek);
}

static void missing_signing_key(proto_tree *tree, packet_info *pinfo,
				kerberos_private_data_t *private_data,
				tvbuff_t *tvb,
				krb5_cksumtype checksum,
				int keytype,
				const char *reason,
				const char *keymap_name,
				unsigned keymap_size,
				unsigned verify_count)
{
	proto_item *item = NULL;
	enc_key_t *mek = NULL;

	mek = wmem_new0(pinfo->pool, enc_key_t);
	snprintf(mek->key_origin, KRB_MAX_ORIG_LEN,
		   "checksum %d keytype %d missing in frame %u",
		   checksum, keytype, pinfo->num);
	mek->fd_num = pinfo->num;
	mek->id = ++private_data->missing_key_ids;
	snprintf(mek->id_str, KRB_MAX_ID_STR_LEN, "missing.%u",
		   mek->id);
	mek->keytype=keytype;

	item = proto_tree_add_expert_format(tree, pinfo, &ei_kerberos_missing_keytype,
					    tvb, 0, 0,
					    "%s checksum %d keytype %d (id=%s)",
					    reason, checksum, keytype, mek->id_str);
	expert_add_info_format(pinfo, item, &ei_kerberos_missing_keytype,
			       "Used keymap=%s num_keys=%u num_tries=%u)",
			       keymap_name,
			       keymap_size,
			       verify_count);

	kerberos_key_list_append(private_data->missing_keys, mek);
}

#endif /* HAVE_KRB5_PAC_VERIFY */

static krb5_context krb5_ctx;

#ifdef HAVE_KRB5_C_FX_CF2_SIMPLE
static void
krb5_fast_key(asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb,
	      enc_key_t *ek1 _U_, const char *p1 _U_,
	      enc_key_t *ek2 _U_, const char *p2 _U_,
	      const char *origin _U_)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	krb5_error_code ret;
	krb5_keyblock k1;
	krb5_keyblock k2;
	krb5_keyblock *k = NULL;

	if (!krb_decrypt) {
		return;
	}

	if (ek1 == NULL) {
		return;
	}

	if (ek2 == NULL) {
		return;
	}

	k1.magic = KV5M_KEYBLOCK;
	k1.enctype = ek1->keytype;
	k1.length = ek1->keylength;
	k1.contents = (uint8_t *)ek1->keyvalue;

	k2.magic = KV5M_KEYBLOCK;
	k2.enctype = ek2->keytype;
	k2.length = ek2->keylength;
	k2.contents = (uint8_t *)ek2->keyvalue;

	ret = krb5_c_fx_cf2_simple(krb5_ctx, &k1, p1, &k2, p2, &k);
	if (ret != 0) {
		return;
	}

	add_encryption_key(actx->pinfo,
			   private_data,
			   tree, NULL, tvb,
			   k->enctype, k->length,
			   (const char *)k->contents,
			   origin,
			   ek1, ek2);

	krb5_free_keyblock(krb5_ctx, k);
}
#else /* HAVE_KRB5_C_FX_CF2_SIMPLE */
static void
krb5_fast_key(asn1_ctx_t *actx _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_,
	      enc_key_t *ek1 _U_, const char *p1 _U_,
	      enc_key_t *ek2 _U_, const char *p2 _U_,
	      const char *origin _U_)
{
}
#endif /* HAVE_KRB5_C_FX_CF2_SIMPLE */

USES_APPLE_DEPRECATED_API
void
read_keytab_file(const char *filename)
{
	krb5_keytab keytab;
	krb5_error_code ret;
	krb5_keytab_entry key;
	krb5_kt_cursor cursor;
	static bool first_time=true;

	if (filename == NULL || filename[0] == 0) {
		return;
	}

	if(first_time){
		first_time=false;
		ret = krb5_init_context(&krb5_ctx);
		if(ret && ret != KRB5_CONFIG_CANTOPEN){
			return;
		}
	}

	/* should use a file in the wireshark users dir */
	ret = krb5_kt_resolve(krb5_ctx, filename, &keytab);
	if(ret){
		fprintf(stderr, "KERBEROS ERROR: Badly formatted keytab filename :%s\n",filename);

		return;
	}

	ret = krb5_kt_start_seq_get(krb5_ctx, keytab, &cursor);
	if(ret){
		fprintf(stderr, "KERBEROS ERROR: Could not open or could not read from keytab file :%s\n",filename);
		return;
	}

	do{
		ret = krb5_kt_next_entry(krb5_ctx, keytab, &key, &cursor);
		if(ret==0){
			enc_key_t *new_key;
			int i;
			char *pos;

			new_key = wmem_new0(wmem_epan_scope(), enc_key_t);
			new_key->fd_num = -1;
			new_key->id = ++kerberos_longterm_ids;
			snprintf(new_key->id_str, KRB_MAX_ID_STR_LEN, "keytab.%u", new_key->id);
			new_key->next = enc_key_list;

			/* generate origin string, describing where this key came from */
			pos=new_key->key_origin;
			pos+=MIN(KRB_MAX_ORIG_LEN,
					 snprintf(pos, KRB_MAX_ORIG_LEN, "keytab principal "));
			for(i=0;i<key.principal->length;i++){
				pos+=MIN(KRB_MAX_ORIG_LEN-(pos-new_key->key_origin),
						 snprintf(pos, KRB_MAX_ORIG_LEN-(pos-new_key->key_origin), "%s%s",(i?"/":""),(key.principal->data[i]).data));
			}
			pos+=MIN(KRB_MAX_ORIG_LEN-(pos-new_key->key_origin),
					 snprintf(pos, KRB_MAX_ORIG_LEN-(pos-new_key->key_origin), "@%s",key.principal->realm.data));
			*pos=0;
			new_key->keytype=key.key.enctype;
			new_key->keylength=key.key.length;
			memcpy(new_key->keyvalue,
			       key.key.contents,
			       MIN(key.key.length, KRB_MAX_KEY_LENGTH));

			enc_key_list=new_key;
			ret = krb5_free_keytab_entry_contents(krb5_ctx, &key);
			if (ret) {
				fprintf(stderr, "KERBEROS ERROR: Could not release the entry: %d", ret);
				ret = 0; /* try to continue with the next entry */
			}
			kerberos_key_map_insert(kerberos_longterm_keys, new_key);
		}
	}while(ret==0);

	ret = krb5_kt_end_seq_get(krb5_ctx, keytab, &cursor);
	if(ret){
		fprintf(stderr, "KERBEROS ERROR: Could not release the keytab cursor: %d", ret);
	}
	ret = krb5_kt_close(krb5_ctx, keytab);
	if(ret){
		fprintf(stderr, "KERBEROS ERROR: Could not close the key table handle: %d", ret);
	}
}

struct decrypt_krb5_with_cb_state {
	proto_tree *tree;
	packet_info *pinfo;
	kerberos_private_data_t *private_data;
	int usage;
	int keytype;
	tvbuff_t *cryptotvb;
	krb5_error_code (*decrypt_cb_fn)(
		const krb5_keyblock *key,
		int usage,
		void *decrypt_cb_data);
	void *decrypt_cb_data;
	unsigned count;
	enc_key_t *ek;
};

static void
decrypt_krb5_with_cb_try_key(void *__key _U_, void *value, void *userdata)
{
	struct decrypt_krb5_with_cb_state *state =
		(struct decrypt_krb5_with_cb_state *)userdata;
	enc_key_t *ek = (enc_key_t *)value;
	krb5_error_code ret;
	krb5_keytab_entry key;
#ifdef HAVE_KRB5_C_FX_CF2_SIMPLE
	enc_key_t *ak = state->private_data->fast_armor_key;
	enc_key_t *sk = state->private_data->fast_strengthen_key;
	bool try_with_armor_key = false;
	bool try_with_strengthen_key = false;
#endif

	if (state->ek != NULL) {
		/*
		 * we're done.
		 */
		return;
	}

#ifdef HAVE_KRB5_C_FX_CF2_SIMPLE
	if (ak != NULL && ak != ek && ak->keytype == state->keytype && ek->fd_num == -1) {
		switch (state->usage) {
		case KEY_USAGE_ENC_CHALLENGE_CLIENT:
		case KEY_USAGE_ENC_CHALLENGE_KDC:
			if (ek->fd_num == -1) {
				/* Challenges are based on a long term key */
				try_with_armor_key = true;
			}
			break;
		}

		/*
		 * If we already have a strengthen_key
		 * we don't need to try with the armor key
		 * again
		 */
		if (sk != NULL) {
			try_with_armor_key = false;
		}
	}

	if (sk != NULL && sk != ek && sk->keytype == state->keytype && sk->keytype == ek->keytype) {
		switch (state->usage) {
		case 3:
			if (ek->fd_num == -1) {
				/* AS-REP is based on a long term key */
				try_with_strengthen_key = true;
			}
			break;
		case 8:
		case 9:
			if (ek->fd_num != -1) {
				/* TGS-REP is not based on a long term key */
				try_with_strengthen_key = true;
			}
			break;
		}
	}

	if (try_with_armor_key) {
		krb5_keyblock k1;
		krb5_keyblock k2;
		krb5_keyblock *k = NULL;
		const char *p1 = NULL;

		k1.magic = KV5M_KEYBLOCK;
		k1.enctype = ak->keytype;
		k1.length = ak->keylength;
		k1.contents = (uint8_t *)ak->keyvalue;

		k2.magic = KV5M_KEYBLOCK;
		k2.enctype = ek->keytype;
		k2.length = ek->keylength;
		k2.contents = (uint8_t *)ek->keyvalue;

		switch (state->usage) {
		case KEY_USAGE_ENC_CHALLENGE_CLIENT:
			p1 = "clientchallengearmor";
			break;
		case KEY_USAGE_ENC_CHALLENGE_KDC:
			p1 = "kdcchallengearmor";
			break;
		default:
			/*
			 * Should never be called!
			 */
			/*
			 * try the next one...
			 */
			return;
		}

		ret = krb5_c_fx_cf2_simple(krb5_ctx,
					   &k1, p1,
					   &k2, "challengelongterm",
					   &k);
		if (ret != 0) {
			/*
			 * try the next one...
			 */
			return;
		}

		state->count += 1;
		ret = state->decrypt_cb_fn(k,
					   state->usage,
					   state->decrypt_cb_data);
		if (ret == 0) {
			add_encryption_key(state->pinfo,
					   state->private_data,
					   state->tree,
					   NULL,
					   state->cryptotvb,
					   k->enctype, k->length,
					   (const char *)k->contents,
					   p1,
					   ak, ek);
			krb5_free_keyblock(krb5_ctx, k);
			/*
			 * remember the key and stop traversing
			 */
			state->ek = state->private_data->last_added_key;
			return;
		}
		krb5_free_keyblock(krb5_ctx, k);
		/*
		 * don't stop traversing...
		 * try the next one...
		 */
		return;
	}

	if (try_with_strengthen_key) {
		krb5_keyblock k1;
		krb5_keyblock k2;
		krb5_keyblock *k = NULL;

		k1.magic = KV5M_KEYBLOCK;
		k1.enctype = sk->keytype;
		k1.length = sk->keylength;
		k1.contents = (uint8_t *)sk->keyvalue;

		k2.magic = KV5M_KEYBLOCK;
		k2.enctype = ek->keytype;
		k2.length = ek->keylength;
		k2.contents = (uint8_t *)ek->keyvalue;

		ret = krb5_c_fx_cf2_simple(krb5_ctx,
					   &k1, "strengthenkey",
					   &k2, "replykey",
					   &k);
		if (ret != 0) {
			/*
			 * try the next one...
			 */
			return;
		}

		state->count += 1;
		ret = state->decrypt_cb_fn(k,
					   state->usage,
					   state->decrypt_cb_data);
		if (ret == 0) {
			add_encryption_key(state->pinfo,
					   state->private_data,
					   state->tree,
					   NULL,
					   state->cryptotvb,
					   k->enctype, k->length,
					   (const char *)k->contents,
					    "strengthen-reply-key",
					   sk, ek);
			krb5_free_keyblock(krb5_ctx, k);
			/*
			 * remember the key and stop traversing
			 */
			state->ek = state->private_data->last_added_key;
			return;
		}
		krb5_free_keyblock(krb5_ctx, k);
		/*
		 * don't stop traversing...
		 * try the next one...
		 */
		return;
	}
#endif /* HAVE_KRB5_C_FX_CF2_SIMPLE */

	/* shortcircuit and bail out if enctypes are not matching */
	if ((state->keytype != -1) && (ek->keytype != state->keytype)) {
		/*
		 * don't stop traversing...
		 * try the next one...
		 */
		return;
	}

	key.key.enctype=ek->keytype;
	key.key.length=ek->keylength;
	key.key.contents=ek->keyvalue;
	state->count += 1;
	ret = state->decrypt_cb_fn(&(key.key),
				   state->usage,
				   state->decrypt_cb_data);
	if (ret != 0) {
		/*
		 * don't stop traversing...
		 * try the next one...
		 */
		return;
	}

	/*
	 * we're done, remember the key
	 */
	state->ek = ek;
}

static krb5_error_code
decrypt_krb5_with_cb(proto_tree *tree,
		     packet_info *pinfo,
		     kerberos_private_data_t *private_data,
		     int usage,
		     int keytype,
		     tvbuff_t *cryptotvb,
		     krb5_error_code (*decrypt_cb_fn)(
			const krb5_keyblock *key,
			int usage,
			void *decrypt_cb_data),
		     void *decrypt_cb_data)
{
	const char *key_map_name = NULL;
	wmem_map_t *key_map = NULL;
	struct decrypt_krb5_with_cb_state state = {
		.tree = tree,
		.pinfo = pinfo,
		.private_data = private_data,
		.usage = usage,
		.cryptotvb = cryptotvb,
		.keytype = keytype,
		.decrypt_cb_fn = decrypt_cb_fn,
		.decrypt_cb_data = decrypt_cb_data,
	};

	read_keytab_file_from_preferences();

	switch (usage) {
	case KRB5_KU_USAGE_INITIATOR_SEAL:
	case KRB5_KU_USAGE_ACCEPTOR_SEAL:
		key_map_name = "app_session_keys";
		key_map = kerberos_app_session_keys;
		break;
	default:
		key_map_name = "all_keys";
		key_map = kerberos_all_keys;
		insert_longterm_keys_into_key_map(key_map);
		break;
	}

	wmem_map_foreach(key_map, decrypt_krb5_with_cb_try_key, &state);
	if (state.ek != NULL) {
		used_encryption_key(tree, pinfo, private_data,
				    state.ek, usage, cryptotvb,
				    key_map_name,
				    wmem_map_size(key_map),
				    state.count);
		return 0;
	}

	missing_encryption_key(tree, pinfo, private_data,
			       keytype, usage, cryptotvb,
			       key_map_name,
			       wmem_map_size(key_map),
			       state.count);
	return -1;
}

struct decrypt_krb5_data_state {
	krb5_data input;
	krb5_data output;
};

static krb5_error_code
decrypt_krb5_data_cb(const krb5_keyblock *key,
		     int usage,
		     void *decrypt_cb_data)
{
	struct decrypt_krb5_data_state *state =
		(struct decrypt_krb5_data_state *)decrypt_cb_data;
	krb5_enc_data input;

	memset(&input, 0, sizeof(input));
	input.enctype = key->enctype;
	input.ciphertext = state->input;

	return krb5_c_decrypt(krb5_ctx,
			      key,
			      usage,
			      0,
			      &input,
			      &state->output);
}

static uint8_t *
decrypt_krb5_data_private(proto_tree *tree _U_, packet_info *pinfo,
			  kerberos_private_data_t *private_data,
			  int usage, tvbuff_t *cryptotvb, int keytype,
			  int *datalen)
{
#define HAVE_DECRYPT_KRB5_DATA_PRIVATE 1
	struct decrypt_krb5_data_state state;
	krb5_error_code ret;
	int length = tvb_captured_length(cryptotvb);
	const uint8_t *cryptotext = tvb_get_ptr(cryptotvb, 0, length);

	/* don't do anything if we are not attempting to decrypt data */
	if(!krb_decrypt || length < 1){
		return NULL;
	}

	/* make sure we have all the data we need */
	if (tvb_captured_length(cryptotvb) < tvb_reported_length(cryptotvb)) {
		return NULL;
	}

	memset(&state, 0, sizeof(state));
	state.input.length = length;
	state.input.data = (uint8_t *)cryptotext;
	state.output.data = (char *)wmem_alloc(pinfo->pool, length);
	state.output.length = length;

	ret = decrypt_krb5_with_cb(tree,
				   pinfo,
				   private_data,
				   usage,
				   keytype,
				   cryptotvb,
				   decrypt_krb5_data_cb,
				   &state);
	if (ret != 0) {
		return NULL;
	}

	if (datalen) {
		*datalen = state.output.length;
	}
	return (uint8_t *)state.output.data;
}

uint8_t *
decrypt_krb5_data(proto_tree *tree _U_, packet_info *pinfo,
					int usage,
					tvbuff_t *cryptotvb,
					int keytype,
					int *datalen)
{
	kerberos_private_data_t *zero_private = kerberos_new_private_data(pinfo);
	return decrypt_krb5_data_private(tree, pinfo, zero_private,
					 usage, cryptotvb, keytype,
					 datalen);
}

USES_APPLE_RST

#ifdef KRB5_CRYPTO_TYPE_SIGN_ONLY
struct decrypt_krb5_krb_cfx_dce_state {
	const uint8_t *gssapi_header_ptr;
	unsigned gssapi_header_len;
	tvbuff_t *gssapi_encrypted_tvb;
	uint8_t *gssapi_payload;
	unsigned gssapi_payload_len;
	const uint8_t *gssapi_trailer_ptr;
	unsigned gssapi_trailer_len;
	tvbuff_t *checksum_tvb;
	uint8_t *checksum;
	unsigned checksum_len;
};

static krb5_error_code
decrypt_krb5_krb_cfx_dce_cb(const krb5_keyblock *key,
			    int usage,
			    void *decrypt_cb_data)
{
	struct decrypt_krb5_krb_cfx_dce_state *state =
		(struct decrypt_krb5_krb_cfx_dce_state *)decrypt_cb_data;
	unsigned int k5_headerlen = 0;
	unsigned int k5_headerofs = 0;
	unsigned int k5_trailerlen = 0;
	unsigned int k5_trailerofs = 0;
	size_t _k5_blocksize = 0;
	unsigned k5_blocksize;
	krb5_crypto_iov iov[6];
	krb5_error_code ret;
	unsigned checksum_remain = state->checksum_len;
	unsigned checksum_crypt_len;

	memset(iov, 0, sizeof(iov));

	ret = krb5_c_crypto_length(krb5_ctx,
				   key->enctype,
				   KRB5_CRYPTO_TYPE_HEADER,
				   &k5_headerlen);
	if (ret != 0) {
		return ret;
	}
	if (checksum_remain < k5_headerlen) {
		return -1;
	}
	checksum_remain -= k5_headerlen;
	k5_headerofs = checksum_remain;
	ret = krb5_c_crypto_length(krb5_ctx,
				   key->enctype,
				   KRB5_CRYPTO_TYPE_TRAILER,
				   &k5_trailerlen);
	if (ret != 0) {
		return ret;
	}
	if (checksum_remain < k5_trailerlen) {
		return -1;
	}
	checksum_remain -= k5_trailerlen;
	k5_trailerofs = checksum_remain;
	checksum_crypt_len = checksum_remain;

	ret = krb5_c_block_size(krb5_ctx,
				key->enctype,
				&_k5_blocksize);
	if (ret != 0) {
		return ret;
	}
	/*
	 * The cast is required for the Windows build in order
	 * to avoid the following warning.
	 *
	 * warning C4267: '-=': conversion from 'size_t' to 'unsigned',
	 * possible loss of data
	 */
	k5_blocksize = (unsigned)_k5_blocksize;
	if (checksum_remain < k5_blocksize) {
		return -1;
	}
	checksum_remain -= k5_blocksize;
	if (checksum_remain < 16) {
		return -1;
	}

	tvb_memcpy(state->gssapi_encrypted_tvb,
		   state->gssapi_payload,
		   0,
		   state->gssapi_payload_len);
	tvb_memcpy(state->checksum_tvb,
		   state->checksum,
		   0,
		   state->checksum_len);

	iov[0].flags = KRB5_CRYPTO_TYPE_HEADER;
	iov[0].data.data = state->checksum + k5_headerofs;
	iov[0].data.length = k5_headerlen;

	if (state->gssapi_header_ptr != NULL) {
		iov[1].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
		iov[1].data.data = (uint8_t *)(guintptr)state->gssapi_header_ptr;
		iov[1].data.length = state->gssapi_header_len;
	} else {
		iov[1].flags = KRB5_CRYPTO_TYPE_EMPTY;
	}

	iov[2].flags = KRB5_CRYPTO_TYPE_DATA;
	iov[2].data.data = state->gssapi_payload;
	iov[2].data.length = state->gssapi_payload_len;

	if (state->gssapi_trailer_ptr != NULL) {
		iov[3].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
		iov[3].data.data = (uint8_t *)(guintptr)state->gssapi_trailer_ptr;
		iov[3].data.length = state->gssapi_trailer_len;
	} else {
		iov[3].flags = KRB5_CRYPTO_TYPE_EMPTY;
	}

	iov[4].flags = KRB5_CRYPTO_TYPE_DATA;
	iov[4].data.data = state->checksum;
	iov[4].data.length = checksum_crypt_len;

	iov[5].flags = KRB5_CRYPTO_TYPE_TRAILER;
	iov[5].data.data = state->checksum + k5_trailerofs;
	iov[5].data.length = k5_trailerlen;

	return krb5_c_decrypt_iov(krb5_ctx,
				  key,
				  usage,
				  0,
				  iov,
				  6);
}

tvbuff_t *
decrypt_krb5_krb_cfx_dce(proto_tree *tree,
			 packet_info *pinfo,
			 int usage,
			 int keytype,
			 tvbuff_t *gssapi_header_tvb,
			 tvbuff_t *gssapi_encrypted_tvb,
			 tvbuff_t *gssapi_trailer_tvb,
			 tvbuff_t *checksum_tvb)
{
	struct decrypt_krb5_krb_cfx_dce_state state;
	kerberos_private_data_t *zero_private = kerberos_new_private_data(pinfo);
	tvbuff_t *gssapi_decrypted_tvb = NULL;
	krb5_error_code ret;

	/* don't do anything if we are not attempting to decrypt data */
	if (!krb_decrypt) {
		return NULL;
	}

	memset(&state, 0, sizeof(state));

	/* make sure we have all the data we need */
#define __CHECK_TVB_LEN(__tvb) (tvb_captured_length(__tvb) < tvb_reported_length(__tvb))
	if (gssapi_header_tvb != NULL) {
		if (__CHECK_TVB_LEN(gssapi_header_tvb)) {
			return NULL;
		}

		state.gssapi_header_len = tvb_captured_length(gssapi_header_tvb);
		state.gssapi_header_ptr = tvb_get_ptr(gssapi_header_tvb,
						       0,
						       state.gssapi_header_len);
	}
	if (gssapi_encrypted_tvb == NULL || __CHECK_TVB_LEN(gssapi_encrypted_tvb)) {
		return NULL;
	}
	state.gssapi_encrypted_tvb = gssapi_encrypted_tvb;
	state.gssapi_payload_len = tvb_captured_length(gssapi_encrypted_tvb);
	state.gssapi_payload = (uint8_t *)wmem_alloc0(pinfo->pool, state.gssapi_payload_len);
	if (state.gssapi_payload == NULL) {
		return NULL;
	}
	if (gssapi_trailer_tvb != NULL) {
		if (__CHECK_TVB_LEN(gssapi_trailer_tvb)) {
			return NULL;
		}

		state.gssapi_trailer_len = tvb_captured_length(gssapi_trailer_tvb);
		state.gssapi_trailer_ptr = tvb_get_ptr(gssapi_trailer_tvb,
						       0,
						       state.gssapi_trailer_len);
	}
	if (checksum_tvb == NULL || __CHECK_TVB_LEN(checksum_tvb)) {
		return NULL;
	}
	state.checksum_tvb = checksum_tvb;
	state.checksum_len = tvb_captured_length(checksum_tvb);
	state.checksum = (uint8_t *)wmem_alloc0(pinfo->pool, state.checksum_len);
	if (state.checksum == NULL) {
		return NULL;
	}

	ret = decrypt_krb5_with_cb(tree,
				   pinfo,
				   zero_private,
				   usage,
				   keytype,
				   gssapi_encrypted_tvb,
				   decrypt_krb5_krb_cfx_dce_cb,
				   &state);
	wmem_free(pinfo->pool, state.checksum);
	if (ret != 0) {
		wmem_free(pinfo->pool, state.gssapi_payload);
		return NULL;
	}

	gssapi_decrypted_tvb = tvb_new_child_real_data(gssapi_encrypted_tvb,
						       state.gssapi_payload,
						       state.gssapi_payload_len,
						       state.gssapi_payload_len);
	if (gssapi_decrypted_tvb == NULL) {
		wmem_free(pinfo->pool, state.gssapi_payload);
		return NULL;
	}

	return gssapi_decrypted_tvb;
}
#else /* NOT KRB5_CRYPTO_TYPE_SIGN_ONLY */
#define NEED_DECRYPT_KRB5_KRB_CFX_DCE_NOOP 1
#endif /* NOT KRB5_CRYPTO_TYPE_SIGN_ONLY */

#ifdef HAVE_KRB5_PAC_VERIFY
/*
 * macOS up to 10.14.5 only has a MIT shim layer on top
 * of heimdal. It means that krb5_pac_verify() is not available
 * in /usr/lib/libkrb5.dylib
 *
 * https://opensource.apple.com/tarballs/Heimdal/Heimdal-520.260.1.tar.gz
 * https://opensource.apple.com/tarballs/MITKerberosShim/MITKerberosShim-71.200.1.tar.gz
 */

extern krb5_error_code
krb5int_c_mandatory_cksumtype(krb5_context, krb5_enctype, krb5_cksumtype *);

extern void krb5_free_enc_tkt_part(krb5_context, krb5_enc_tkt_part *);
extern krb5_error_code
decode_krb5_enc_tkt_part(const krb5_data *output, krb5_enc_tkt_part **rep);
extern krb5_error_code
encode_krb5_enc_tkt_part(const krb5_enc_tkt_part *rep, krb5_data **code);

static int
keytype_for_cksumtype(krb5_cksumtype checksum)
{
	static const int keytypes[] = {
		18,
		17,
		23,
	};
	unsigned i;

	for (i = 0; i < array_length(keytypes); i++) {
		krb5_cksumtype checksumtype = 0;
		krb5_error_code ret;

		ret = krb5int_c_mandatory_cksumtype(krb5_ctx,
						    keytypes[i],
						    &checksumtype);
		if (ret != 0) {
			continue;
		}
		if (checksum == checksumtype) {
			return keytypes[i];
		}
	}

	return -1;
}

struct verify_krb5_pac_state {
	int pacbuffer_length;
	const uint8_t *pacbuffer;
	krb5_pac pac;
	krb5_cksumtype server_checksum;
	unsigned server_count;
	enc_key_t *server_ek;
	krb5_cksumtype kdc_checksum;
	unsigned kdc_count;
	enc_key_t *kdc_ek;
	krb5_cksumtype ticket_checksum_type;
	const krb5_data *ticket_checksum_data;
	krb5_cksumtype full_checksum_type;
	const krb5_data *full_checksum_data;
	unsigned full_count;
	enc_key_t *full_ek;
};

static void
verify_krb5_pac_try_server_key(void *__key _U_, void *value, void *userdata)
{
	struct verify_krb5_pac_state *state =
		(struct verify_krb5_pac_state *)userdata;
	enc_key_t *ek = (enc_key_t *)value;
	krb5_keyblock keyblock;
	krb5_cksumtype checksumtype = 0;
	krb5_error_code ret;

	if (state->server_checksum == 0) {
		/*
		 * nothing more todo, stop traversing.
		 */
		return;
	}

	if (state->server_ek != NULL) {
		/*
		 * we're done.
		 */
		return;
	}

	ret = krb5int_c_mandatory_cksumtype(krb5_ctx, ek->keytype,
					    &checksumtype);
	if (ret != 0) {
		/*
		 * the key is not usable, keep traversing.
		 * try the next key...
		 */
		return;
	}

	keyblock.magic = KV5M_KEYBLOCK;
	keyblock.enctype = ek->keytype;
	keyblock.length = ek->keylength;
	keyblock.contents = (uint8_t *)ek->keyvalue;

	if (checksumtype == state->server_checksum) {
		state->server_count += 1;
		ret = krb5_pac_verify(krb5_ctx, state->pac, 0, NULL,
				      &keyblock, NULL);
		if (ret == 0) {
			state->server_ek = ek;
		}
	}
}

static void
verify_krb5_pac_try_kdc_key(void *__key _U_, void *value, void *userdata)
{
	struct verify_krb5_pac_state *state =
		(struct verify_krb5_pac_state *)userdata;
	enc_key_t *ek = (enc_key_t *)value;
	krb5_keyblock keyblock;
	krb5_cksumtype checksumtype = 0;
	krb5_error_code ret;

	if (state->kdc_checksum == 0) {
		/*
		 * nothing more todo, stop traversing.
		 */
		return;
	}

	if (state->kdc_ek != NULL) {
		/*
		 * we're done.
		 */
		return;
	}

	ret = krb5int_c_mandatory_cksumtype(krb5_ctx, ek->keytype,
					    &checksumtype);
	if (ret != 0) {
		/*
		 * the key is not usable, keep traversing.
		 * try the next key...
		 */
		return;
	}

	keyblock.magic = KV5M_KEYBLOCK;
	keyblock.enctype = ek->keytype;
	keyblock.length = ek->keylength;
	keyblock.contents = (uint8_t *)ek->keyvalue;

	if (checksumtype == state->kdc_checksum) {
		state->kdc_count += 1;
		ret = krb5_pac_verify(krb5_ctx, state->pac, 0, NULL,
				      NULL, &keyblock);
		if (ret == 0) {
			state->kdc_ek = ek;
		}
	}
}

#define __KRB5_PAC_TICKET_CHECKSUM 16

static void
verify_krb5_pac_ticket_checksum(proto_tree *tree _U_,
				asn1_ctx_t *actx _U_,
				tvbuff_t *pactvb _U_,
				struct verify_krb5_pac_state *state _U_)
{
#ifdef HAVE_DECODE_KRB5_ENC_TKT_PART
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *teptvb = private_data->last_ticket_enc_part_tvb;
	unsigned teplength = 0;
	const uint8_t *tepbuffer = NULL;
	krb5_data tepdata = { .length = 0, };
	krb5_enc_tkt_part *tep = NULL;
	krb5_data *tmpdata = NULL;
	krb5_error_code ret;
	krb5_authdata **recoded_container = NULL;
	int ad_orig_idx = -1;
	krb5_authdata *ad_orig_ptr = NULL;
	int l0idx = 0;
	krb5_keyblock kdc_key = { .magic = KV5M_KEYBLOCK, };
	size_t checksum_length = 0;
	krb5_checksum checksum = { .checksum_type = 0, };
	krb5_boolean valid = false;

	if (state->kdc_ek == NULL) {
		int keytype = keytype_for_cksumtype(state->ticket_checksum_type);
		missing_signing_key(tree, actx->pinfo, private_data,
				    pactvb, state->ticket_checksum_type,
				    keytype,
				    "Missing KDC (for ticket)",
				    "kdc_checksum_key",
				    0,
				    0);
		return;
	}

	if (teptvb == NULL) {
		return;
	}

	teplength = tvb_captured_length(teptvb);
	/* make sure we have all the data we need */
	if (teplength < tvb_reported_length(teptvb)) {
		return;
	}

	tepbuffer = tvb_get_ptr(teptvb, 0, teplength);
	if (tepbuffer == NULL) {
		return;
	}

	kdc_key.magic = KV5M_KEYBLOCK;
	kdc_key.enctype = state->kdc_ek->keytype;
	kdc_key.length = state->kdc_ek->keylength;
	kdc_key.contents = (uint8_t *)state->kdc_ek->keyvalue;

	checksum.checksum_type = state->ticket_checksum_type;
	checksum.length = state->ticket_checksum_data->length;
	checksum.contents = (uint8_t *)state->ticket_checksum_data->data;
	if (checksum.length >= 4) {
		checksum.length -= 4;
		checksum.contents += 4;
	}

	ret = krb5_c_checksum_length(krb5_ctx,
				     checksum.checksum_type,
				     &checksum_length);
	if (ret != 0) {
		missing_signing_key(tree, actx->pinfo, private_data,
				    pactvb, state->ticket_checksum_type,
				    state->kdc_ek->keytype,
				    "krb5_c_checksum_length failed for Ticket Signature",
				    "kdc_checksum_key",
				    1,
				    0);
		return;
	}
	checksum.length = MIN(checksum.length, (unsigned int)checksum_length);

	tepdata.data = (void *)tepbuffer;
	tepdata.length = teplength;

	ret = decode_krb5_enc_tkt_part(&tepdata, &tep);
	if (ret != 0) {
		missing_signing_key(tree, actx->pinfo, private_data,
				    pactvb, state->ticket_checksum_type,
				    state->kdc_ek->keytype,
				    "decode_krb5_enc_tkt_part failed",
				    "kdc_checksum_key",
				    1,
				    0);
		return;
	}

	for (l0idx = 0; tep->authorization_data[l0idx]; l0idx++) {
		krb5_authdata *adl0 = tep->authorization_data[l0idx];
		krb5_authdata **decoded_container = NULL;
		krb5_authdata *ad_pac = NULL;
		int l1idx = 0;

		if (adl0->ad_type != KRB5_AUTHDATA_IF_RELEVANT) {
			continue;
		}

		ret = krb5_decode_authdata_container(krb5_ctx,
						     KRB5_AUTHDATA_IF_RELEVANT,
						     adl0,
						     &decoded_container);
		if (ret != 0) {
			missing_signing_key(tree, actx->pinfo, private_data,
					    pactvb, state->ticket_checksum_type,
					    state->kdc_ek->keytype,
					    "krb5_decode_authdata_container failed",
					    "kdc_checksum_key",
					    1,
					    0);
			krb5_free_enc_tkt_part(krb5_ctx, tep);
			return;
		}

		for (l1idx = 0; decoded_container[l1idx]; l1idx++) {
			krb5_authdata *adl1 = decoded_container[l1idx];

			if (adl1->ad_type != KRB5_AUTHDATA_WIN2K_PAC) {
				continue;
			}

			ad_pac = adl1;
			break;
		}

		if (ad_pac == NULL) {
			krb5_free_authdata(krb5_ctx, decoded_container);
			continue;
		}

		ad_pac->length = 1;
		ad_pac->contents[0] = '\0';

		ret = krb5_encode_authdata_container(krb5_ctx,
						     KRB5_AUTHDATA_IF_RELEVANT,
						     decoded_container,
						     &recoded_container);
		krb5_free_authdata(krb5_ctx, decoded_container);
		decoded_container = NULL;
		if (ret != 0) {
			missing_signing_key(tree, actx->pinfo, private_data,
					    pactvb, state->ticket_checksum_type,
					    state->kdc_ek->keytype,
					    "krb5_encode_authdata_container failed",
					    "kdc_checksum_key",
					    1,
					    0);
			krb5_free_enc_tkt_part(krb5_ctx, tep);
			return;
		}

		ad_orig_idx = l0idx;
		ad_orig_ptr = adl0;
		tep->authorization_data[l0idx] = recoded_container[0];
		break;
	}

	ret = encode_krb5_enc_tkt_part(tep, &tmpdata);
	if (ad_orig_ptr != NULL) {
		tep->authorization_data[ad_orig_idx] = ad_orig_ptr;
	}
	krb5_free_enc_tkt_part(krb5_ctx, tep);
	tep = NULL;
	if (recoded_container != NULL) {
		krb5_free_authdata(krb5_ctx, recoded_container);
		recoded_container = NULL;
	}
	if (ret != 0) {
		missing_signing_key(tree, actx->pinfo, private_data,
				    pactvb, state->ticket_checksum_type,
				    state->kdc_ek->keytype,
				    "encode_krb5_enc_tkt_part failed",
				    "kdc_checksum_key",
				    1,
				    0);
		return;
	}

	ret = krb5_c_verify_checksum(krb5_ctx, &kdc_key,
				     KRB5_KEYUSAGE_APP_DATA_CKSUM,
				     tmpdata, &checksum, &valid);
	krb5_free_data(krb5_ctx, tmpdata);
	tmpdata = NULL;
	if (ret != 0) {
		missing_signing_key(tree, actx->pinfo, private_data,
				    pactvb, state->ticket_checksum_type,
				    state->kdc_ek->keytype,
				    "krb5_c_verify_checksum failed for Ticket Signature",
				    "kdc_checksum_key",
				    1,
				    1);
		return;
	}

	if (valid == false) {
		missing_signing_key(tree, actx->pinfo, private_data,
				    pactvb, state->ticket_checksum_type,
				    state->kdc_ek->keytype,
				    "Invalid Ticket",
				    "kdc_checksum_key",
				    1,
				    1);
		return;
	}

	used_signing_key(tree, actx->pinfo, private_data,
			 state->kdc_ek, pactvb,
			 state->ticket_checksum_type,
			 "Verified Ticket",
			 "kdc_checksum_key",
			 1,
			 1);
#endif /* HAVE_DECODE_KRB5_ENC_TKT_PART */
}

#define __KRB5_PAC_FULL_CHECKSUM 19

static void
verify_krb5_pac_full_checksum(proto_tree *tree,
			      asn1_ctx_t *actx,
			      tvbuff_t *orig_pactvb,
			      struct verify_krb5_pac_state *state)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	krb5_error_code ret;
	krb5_keyblock kdc_key = { .magic = KV5M_KEYBLOCK, };
	size_t checksum_length = 0;
	krb5_checksum checksum = { .checksum_type = 0, };
	krb5_data pac_data = { .length = 0, };
	tvbuff_t *copy_pactvb = NULL;
	uint32_t cur_offset;
	uint32_t num_buffers;
	uint32_t idx;
	krb5_boolean valid = false;

	if (state->kdc_ek == NULL) {
		int keytype = keytype_for_cksumtype(state->full_checksum_type);
		missing_signing_key(tree, actx->pinfo, private_data,
				    orig_pactvb, state->full_checksum_type,
				    keytype,
				    "Missing KDC (for full)",
				    "kdc_checksum_key",
				    0,
				    0);
		return;
	}

	kdc_key.magic = KV5M_KEYBLOCK;
	kdc_key.enctype = state->kdc_ek->keytype;
	kdc_key.length = state->kdc_ek->keylength;
	kdc_key.contents = (uint8_t *)state->kdc_ek->keyvalue;

	ret = krb5_c_checksum_length(krb5_ctx,
				     state->full_checksum_type,
				     &checksum_length);
	if (ret != 0) {
		missing_signing_key(tree, actx->pinfo, private_data,
				    orig_pactvb, state->full_checksum_type,
				    state->kdc_ek->keytype,
				    "krb5_c_checksum_length failed for Full Signature",
				    "kdc_checksum_key",
				    1,
				    0);
		return;
	}

	/*
	 * The checksum element begins with 4 bytes of type
	 * (state->full_checksum_type) before the crypto checksum
	 */
	if (state->full_checksum_data->length < (4 + checksum_length)) {
		missing_signing_key(tree, actx->pinfo, private_data,
				    orig_pactvb, state->full_checksum_type,
				    state->kdc_ek->keytype,
				    "pacbuffer_length too short for Full Signature",
				    "kdc_checksum_key",
				    1,
				    0);
		return;
	}

	pac_data.data = wmem_memdup(actx->pinfo->pool, state->pacbuffer, state->pacbuffer_length);
	if (pac_data.data == NULL) {
		missing_signing_key(tree, actx->pinfo, private_data,
				    orig_pactvb, state->full_checksum_type,
				    state->kdc_ek->keytype,
				    "wmem_memdup(pacbuffer) failed",
				    "kdc_checksum_key",
				    1,
				    0);
		return;
	}
	pac_data.length = state->pacbuffer_length;

	copy_pactvb = tvb_new_child_real_data(orig_pactvb,
					      (uint8_t *)pac_data.data,
					      pac_data.length,
					      pac_data.length);
	if (copy_pactvb == NULL) {
		missing_signing_key(tree, actx->pinfo, private_data,
				    orig_pactvb, state->full_checksum_type,
				    state->kdc_ek->keytype,
				    "tvb_new_child_real_data(pac_copy) failed",
				    "kdc_checksum_key",
				    1,
				    0);
		return;
	}

#define __PAC_CHECK_OFFSET_SIZE(__offset, __length, __reason) do { \
	uint64_t __end = state->pacbuffer_length; \
	uint64_t __offset64 = __offset; \
	uint64_t __length64 = __length; \
	uint64_t __last; \
	if (__offset64 > INT32_MAX) { \
		missing_signing_key(tree, actx->pinfo, private_data, \
				    orig_pactvb, state->full_checksum_type, \
				    state->kdc_ek->keytype, \
				    __reason, \
				    "kdc_checksum_key", \
				    1, \
				    0); \
		return; \
	} \
	if (__length64 > INT32_MAX) { \
		missing_signing_key(tree, actx->pinfo, private_data, \
				    orig_pactvb, state->full_checksum_type, \
				    state->kdc_ek->keytype, \
				    __reason, \
				    "kdc_checksum_key", \
				    1, \
				    0); \
		return; \
	} \
	__last = __offset64 + __length64; \
	if (__last > __end) { \
		missing_signing_key(tree, actx->pinfo, private_data, \
				    orig_pactvb, state->full_checksum_type, \
				    state->kdc_ek->keytype, \
				    __reason, \
				    "kdc_checksum_key", \
				    1, \
				    0); \
		return; \
	} \
} while(0)

	cur_offset = 0;
	__PAC_CHECK_OFFSET_SIZE(cur_offset, 8, "PACTYPE Header");
	num_buffers = tvb_get_uint32(copy_pactvb, cur_offset, ENC_LITTLE_ENDIAN);
	cur_offset += 4;
	/* ignore 4 byte version */
	cur_offset += 4;

	for (idx = 0; idx < num_buffers; idx++) {
		uint32_t b_type;
		uint32_t b_length;
		uint64_t b_offset;

		__PAC_CHECK_OFFSET_SIZE(cur_offset, 16, "PAC_INFO_BUFFER Header");
		b_type = tvb_get_uint32(copy_pactvb, cur_offset, ENC_LITTLE_ENDIAN);
		cur_offset += 4;
		b_length = tvb_get_uint32(copy_pactvb, cur_offset, ENC_LITTLE_ENDIAN);
		cur_offset += 4;
		b_offset = tvb_get_uint64(copy_pactvb, cur_offset, ENC_LITTLE_ENDIAN);
		cur_offset += 8;

		__PAC_CHECK_OFFSET_SIZE(b_offset, b_length, "PAC_INFO_BUFFER Payload");

		if (b_length <= 4) {
			continue;
		}

		/*
		 * Leave PAC_TICKET_CHECKSUM and clear all other checksums
		 * and their possible RODC identifier, but leaving their
		 * checksum type as is.
		 */
		switch (b_type) {
		case KRB5_PAC_SERVER_CHECKSUM:
		case KRB5_PAC_PRIVSVR_CHECKSUM:
		case __KRB5_PAC_FULL_CHECKSUM:
			memset(pac_data.data + b_offset+4, 0, b_length-4);
			break;
		}
	}

	checksum.checksum_type = state->full_checksum_type;
	checksum.contents = (uint8_t *)state->full_checksum_data->data + 4;
	checksum.length = (unsigned)checksum_length;

	ret = krb5_c_verify_checksum(krb5_ctx, &kdc_key,
				     KRB5_KEYUSAGE_APP_DATA_CKSUM,
				     &pac_data, &checksum, &valid);
	if (ret != 0) {
		missing_signing_key(tree, actx->pinfo, private_data,
				    orig_pactvb, state->full_checksum_type,
				    state->kdc_ek->keytype,
				    "krb5_c_verify_checksum failed for Full PAC Signature",
				    "kdc_checksum_key",
				    1,
				    1);
		return;
	}

	if (valid == false) {
		missing_signing_key(tree, actx->pinfo, private_data,
				    orig_pactvb, state->full_checksum_type,
				    state->kdc_ek->keytype,
				    "Invalid Full PAC Signature",
				    "kdc_checksum_key",
				    1,
				    1);
		return;
	}

	used_signing_key(tree, actx->pinfo, private_data,
			 state->kdc_ek, orig_pactvb,
			 state->full_checksum_type,
			 "Verified Full PAC",
			 "kdc_checksum_key",
			 1,
			 1);
}

static void
verify_krb5_pac(proto_tree *tree _U_, asn1_ctx_t *actx, tvbuff_t *pactvb)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	krb5_error_code ret;
	krb5_data checksum_data = {0,0,NULL};
	krb5_data ticket_checksum_data = {0,0,NULL};
	krb5_data full_checksum_data = {0,0,NULL};
	int length = tvb_captured_length(pactvb);
	const uint8_t *pacbuffer = NULL;
	struct verify_krb5_pac_state state = {
		.kdc_checksum = 0,
	};

	/* don't do anything if we are not attempting to decrypt data */
	if(!krb_decrypt || length < 1){
		return;
	}

	/* make sure we have all the data we need */
	if (tvb_captured_length(pactvb) < tvb_reported_length(pactvb)) {
		return;
	}

	pacbuffer = tvb_get_ptr(pactvb, 0, length);
	state.pacbuffer_length = length;
	state.pacbuffer = pacbuffer;

	ret = krb5_pac_parse(krb5_ctx, pacbuffer, length, &state.pac);
	if (ret != 0) {
		proto_tree_add_expert_format(tree, actx->pinfo, &ei_kerberos_decrypted_keytype,
					     pactvb, 0, 0,
					     "Failed to parse PAC buffer %d in frame %u",
					     ret, actx->pinfo->fd->num);
		return;
	}

	ret = krb5_pac_get_buffer(krb5_ctx, state.pac, KRB5_PAC_SERVER_CHECKSUM,
				  &checksum_data);
	if (ret == 0) {
		state.server_checksum = pletoh32(checksum_data.data);
		krb5_free_data_contents(krb5_ctx, &checksum_data);
	};
	ret = krb5_pac_get_buffer(krb5_ctx, state.pac, KRB5_PAC_PRIVSVR_CHECKSUM,
				  &checksum_data);
	if (ret == 0) {
		state.kdc_checksum = pletoh32(checksum_data.data);
		krb5_free_data_contents(krb5_ctx, &checksum_data);
	};
	ret = krb5_pac_get_buffer(krb5_ctx, state.pac,
				  __KRB5_PAC_TICKET_CHECKSUM,
				  &ticket_checksum_data);
	if (ret == 0) {
		state.ticket_checksum_data = &ticket_checksum_data;
		state.ticket_checksum_type = pletoh32(ticket_checksum_data.data);
	};
	ret = krb5_pac_get_buffer(krb5_ctx, state.pac,
				  __KRB5_PAC_FULL_CHECKSUM,
				  &full_checksum_data);
	if (ret == 0) {
		state.full_checksum_data = &full_checksum_data;
		state.full_checksum_type = pletoh32(full_checksum_data.data);
	};

	read_keytab_file_from_preferences();

	wmem_map_foreach(kerberos_all_keys,
			 verify_krb5_pac_try_server_key,
			 &state);
	if (state.server_ek != NULL) {
		used_signing_key(tree, actx->pinfo, private_data,
				 state.server_ek, pactvb,
				 state.server_checksum, "Verified Server",
				 "all_keys",
				 wmem_map_size(kerberos_all_keys),
				 state.server_count);
	} else {
		int keytype = keytype_for_cksumtype(state.server_checksum);
		missing_signing_key(tree, actx->pinfo, private_data,
				    pactvb, state.server_checksum, keytype,
				    "Missing Server",
				    "all_keys",
				    wmem_map_size(kerberos_all_keys),
				    state.server_count);
	}
	wmem_map_foreach(kerberos_longterm_keys,
			 verify_krb5_pac_try_kdc_key,
			 &state);
	if (state.kdc_ek != NULL) {
		used_signing_key(tree, actx->pinfo, private_data,
				 state.kdc_ek, pactvb,
				 state.kdc_checksum, "Verified KDC",
				 "longterm_keys",
				 wmem_map_size(kerberos_longterm_keys),
				 state.kdc_count);
	} else {
		int keytype = keytype_for_cksumtype(state.kdc_checksum);
		missing_signing_key(tree, actx->pinfo, private_data,
				    pactvb, state.kdc_checksum, keytype,
				    "Missing KDC",
				    "longterm_keys",
				    wmem_map_size(kerberos_longterm_keys),
				    state.kdc_count);
	}

	if (state.ticket_checksum_type != 0) {
		verify_krb5_pac_ticket_checksum(tree, actx, pactvb, &state);
	}

	if (state.ticket_checksum_data != NULL) {
		krb5_free_data_contents(krb5_ctx, &ticket_checksum_data);
	}

	if (state.full_checksum_type != 0) {
		verify_krb5_pac_full_checksum(tree, actx, pactvb, &state);
	}

	if (state.full_checksum_data != NULL) {
		krb5_free_data_contents(krb5_ctx, &full_checksum_data);
	}

	krb5_pac_free(krb5_ctx, state.pac);
}
#endif /* HAVE_KRB5_PAC_VERIFY */

#elif defined(HAVE_HEIMDAL_KERBEROS)
static krb5_context krb5_ctx;

USES_APPLE_DEPRECATED_API

static void
krb5_fast_key(asn1_ctx_t *actx _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_,
	      enc_key_t *ek1 _U_, const char *p1 _U_,
	      enc_key_t *ek2 _U_, const char *p2 _U_,
	      const char *origin _U_)
{
/* TODO: use krb5_crypto_fx_cf2() from Heimdal */
}
void
read_keytab_file(const char *filename)
{
	krb5_keytab keytab;
	krb5_error_code ret;
	krb5_keytab_entry key;
	krb5_kt_cursor cursor;
	enc_key_t *new_key;
	static bool first_time=true;

	if (filename == NULL || filename[0] == 0) {
		return;
	}

	if(first_time){
		first_time=false;
		ret = krb5_init_context(&krb5_ctx);
		if(ret){
			return;
		}
	}

	/* should use a file in the wireshark users dir */
	ret = krb5_kt_resolve(krb5_ctx, filename, &keytab);
	if(ret){
		fprintf(stderr, "KERBEROS ERROR: Could not open keytab file :%s\n",filename);

		return;
	}

	ret = krb5_kt_start_seq_get(krb5_ctx, keytab, &cursor);
	if(ret){
		fprintf(stderr, "KERBEROS ERROR: Could not read from keytab file :%s\n",filename);
		return;
	}

	do{
		ret = krb5_kt_next_entry(krb5_ctx, keytab, &key, &cursor);
		if(ret==0){
			unsigned int i;
			char *pos;

			new_key = wmem_new0(wmem_epan_scope(), enc_key_t);
			new_key->fd_num = -1;
			new_key->id = ++kerberos_longterm_ids;
			snprintf(new_key->id_str, KRB_MAX_ID_STR_LEN, "keytab.%u", new_key->id);
			new_key->next = enc_key_list;

			/* generate origin string, describing where this key came from */
			pos=new_key->key_origin;
			pos+=MIN(KRB_MAX_ORIG_LEN,
					 snprintf(pos, KRB_MAX_ORIG_LEN, "keytab principal "));
			for(i=0;i<key.principal->name.name_string.len;i++){
				pos+=MIN(KRB_MAX_ORIG_LEN-(pos-new_key->key_origin),
						 snprintf(pos, KRB_MAX_ORIG_LEN-(pos-new_key->key_origin), "%s%s",(i?"/":""),key.principal->name.name_string.val[i]));
			}
			pos+=MIN(KRB_MAX_ORIG_LEN-(pos-new_key->key_origin),
					 snprintf(pos, KRB_MAX_ORIG_LEN-(pos-new_key->key_origin), "@%s",key.principal->realm));
			*pos=0;
			new_key->keytype=key.keyblock.keytype;
			new_key->keylength=(int)key.keyblock.keyvalue.length;
			memcpy(new_key->keyvalue,
			       key.keyblock.keyvalue.data,
			       MIN((unsigned)key.keyblock.keyvalue.length, KRB_MAX_KEY_LENGTH));

			enc_key_list=new_key;
			ret = krb5_kt_free_entry(krb5_ctx, &key);
			if (ret) {
				fprintf(stderr, "KERBEROS ERROR: Could not release the entry: %d", ret);
				ret = 0; /* try to continue with the next entry */
			}
			kerberos_key_map_insert(kerberos_longterm_keys, new_key);
		}
	}while(ret==0);

	ret = krb5_kt_end_seq_get(krb5_ctx, keytab, &cursor);
	if(ret){
		fprintf(stderr, "KERBEROS ERROR: Could not release the keytab cursor: %d", ret);
	}
	ret = krb5_kt_close(krb5_ctx, keytab);
	if(ret){
		fprintf(stderr, "KERBEROS ERROR: Could not close the key table handle: %d", ret);
	}

}
USES_APPLE_RST


uint8_t *
decrypt_krb5_data(proto_tree *tree _U_, packet_info *pinfo,
					int usage,
					tvbuff_t *cryptotvb,
					int keytype,
					int *datalen)
{
	kerberos_private_data_t *zero_private = kerberos_new_private_data(pinfo);
	krb5_error_code ret;
	krb5_data data;
	enc_key_t *ek;
	int length = tvb_captured_length(cryptotvb);
	const uint8_t *cryptotext = tvb_get_ptr(cryptotvb, 0, length);

	/* don't do anything if we are not attempting to decrypt data */
	if(!krb_decrypt){
		return NULL;
	}

	/* make sure we have all the data we need */
	if (tvb_captured_length(cryptotvb) < tvb_reported_length(cryptotvb)) {
		return NULL;
	}

	read_keytab_file_from_preferences();

	for(ek=enc_key_list;ek;ek=ek->next){
		krb5_keytab_entry key;
		krb5_crypto crypto;
		uint8_t *cryptocopy; /* workaround for pre-0.6.1 heimdal bug */

		/* shortcircuit and bail out if enctypes are not matching */
		if((keytype != -1) && (ek->keytype != keytype)) {
			continue;
		}

		key.keyblock.keytype=ek->keytype;
		key.keyblock.keyvalue.length=ek->keylength;
		key.keyblock.keyvalue.data=ek->keyvalue;
		ret = krb5_crypto_init(krb5_ctx, &(key.keyblock), (krb5_enctype)ENCTYPE_NULL, &crypto);
		if(ret){
			return NULL;
		}

		/* pre-0.6.1 versions of Heimdal would sometimes change
		   the cryptotext data even when the decryption failed.
		   This would obviously not work since we iterate over the
		   keys. So just give it a copy of the crypto data instead.
		   This has been seen for RC4-HMAC blobs.
		*/
		cryptocopy = (uint8_t *)wmem_memdup(pinfo->pool, cryptotext, length);
		ret = krb5_decrypt_ivec(krb5_ctx, crypto, usage,
								cryptocopy, length,
								&data,
								NULL);
		if((ret == 0) && (length>0)){
			char *user_data;

			used_encryption_key(tree, pinfo, zero_private,
					    ek, usage, cryptotvb,
					    "enc_key_list", 0, 0);

			krb5_crypto_destroy(krb5_ctx, crypto);
			/* return a private wmem_alloced blob to the caller */
			user_data = (char *)wmem_memdup(pinfo->pool, data.data, (unsigned)data.length);
			if (datalen) {
				*datalen = (int)data.length;
			}
			return user_data;
		}
		krb5_crypto_destroy(krb5_ctx, crypto);
	}
	return NULL;
}

#define NEED_DECRYPT_KRB5_KRB_CFX_DCE_NOOP 1

#elif defined (HAVE_LIBNETTLE)

#define SERVICE_KEY_SIZE (DES3_KEY_SIZE + 2)
#define KEYTYPE_DES3_CBC_MD5 5	/* Currently the only one supported */

typedef struct _service_key_t {
	uint16_t kvno;
	int     keytype;
	int     length;
	uint8_t *contents;
	char    origin[KRB_MAX_ORIG_LEN+1];
} service_key_t;
GSList *service_key_list;


static void
add_encryption_key(packet_info *pinfo, int keytype, int keylength, const char *keyvalue, const char *origin)
{
	service_key_t *new_key;

	if(pinfo->fd->visited){
		return;
	}

	new_key = g_malloc(sizeof(service_key_t));
	new_key->kvno = 0;
	new_key->keytype = keytype;
	new_key->length = keylength;
	new_key->contents = g_memdup2(keyvalue, keylength);
	snprintf(new_key->origin, KRB_MAX_ORIG_LEN, "%s learnt from frame %u", origin, pinfo->num);
	service_key_list = g_slist_append(service_key_list, (void *) new_key);
}

static void
save_encryption_key(tvbuff_t *tvb _U_, int offset _U_, int length _U_,
		    asn1_ctx_t *actx _U_, proto_tree *tree _U_,
		    int parent_hf_index _U_,
		    int hf_index _U_)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	const char *parent = proto_registrar_get_name(parent_hf_index);
	const char *element = proto_registrar_get_name(hf_index);
	char origin[KRB_MAX_ORIG_LEN] = { 0, };

	snprintf(origin, KRB_MAX_ORIG_LEN, "%s_%s", parent, element);

	add_encryption_key(actx->pinfo,
			   private_data->key.keytype,
			   private_data->key.keylength,
			   private_data->key.keyvalue,
			   origin);
}

static void
save_Authenticator_subkey(tvbuff_t *tvb, int offset, int length,
			  asn1_ctx_t *actx, proto_tree *tree,
			  int parent_hf_index,
			  int hf_index)
{
	save_encryption_key(tvb, offset, length, actx, tree, parent_hf_index, hf_index);
}

static void
save_EncAPRepPart_subkey(tvbuff_t *tvb, int offset, int length,
			 asn1_ctx_t *actx, proto_tree *tree,
			 int parent_hf_index,
			 int hf_index)
{
	save_encryption_key(tvb, offset, length, actx, tree, parent_hf_index, hf_index);
}

static void
save_EncKDCRepPart_key(tvbuff_t *tvb, int offset, int length,
		       asn1_ctx_t *actx, proto_tree *tree,
		       int parent_hf_index,
		       int hf_index)
{
	save_encryption_key(tvb, offset, length, actx, tree, parent_hf_index, hf_index);
}

static void
save_EncTicketPart_key(tvbuff_t *tvb, int offset, int length,
		       asn1_ctx_t *actx, proto_tree *tree,
		       int parent_hf_index,
		       int hf_index)
{
	save_encryption_key(tvb, offset, length, actx, tree, parent_hf_index, hf_index);
}

static void
save_KrbCredInfo_key(tvbuff_t *tvb, int offset, int length,
		     asn1_ctx_t *actx, proto_tree *tree,
		     int parent_hf_index,
		     int hf_index)
{
	save_encryption_key(tvb, offset, length, actx, tree, parent_hf_index, hf_index);
}

static void
save_KrbFastResponse_strengthen_key(tvbuff_t *tvb _U_, int offset _U_, int length _U_,
				    asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
	save_encryption_key(tvb, offset, length, actx, tree, hf_index);
}

static void
clear_keytab(void) {
	GSList *ske;
	service_key_t *sk;

	for(ske = service_key_list; ske != NULL; ske = g_slist_next(ske)){
		sk = (service_key_t *) ske->data;
		if (sk) {
			g_free(sk->contents);
			g_free(sk);
		}
	}
	g_slist_free(service_key_list);
	service_key_list = NULL;
}

static void
read_keytab_file(const char *service_key_file)
{
	FILE *skf;
	ws_statb64 st;
	service_key_t *sk;
	unsigned char buf[SERVICE_KEY_SIZE];
	int newline_skip = 0, count = 0;

	if (service_key_file != NULL && ws_stat64 (service_key_file, &st) == 0) {

		/* The service key file contains raw 192-bit (24 byte) 3DES keys.
		 * There can be zero, one (\n), or two (\r\n) characters between
		 * keys.  Trailing characters are ignored.
		 */

		/* XXX We should support the standard keytab format instead */
		if (st.st_size > SERVICE_KEY_SIZE) {
			if ( (st.st_size % (SERVICE_KEY_SIZE + 1) == 0) ||
				 (st.st_size % (SERVICE_KEY_SIZE + 1) == SERVICE_KEY_SIZE) ) {
				newline_skip = 1;
			} else if ( (st.st_size % (SERVICE_KEY_SIZE + 2) == 0) ||
				 (st.st_size % (SERVICE_KEY_SIZE + 2) == SERVICE_KEY_SIZE) ) {
				newline_skip = 2;
			}
		}

		skf = ws_fopen(service_key_file, "rb");
		if (! skf) return;

		while (fread(buf, SERVICE_KEY_SIZE, 1, skf) == 1) {
			sk = g_malloc(sizeof(service_key_t));
			sk->kvno = buf[0] << 8 | buf[1];
			sk->keytype = KEYTYPE_DES3_CBC_MD5;
			sk->length = DES3_KEY_SIZE;
			sk->contents = g_memdup2(buf + 2, DES3_KEY_SIZE);
			snprintf(sk->origin, KRB_MAX_ORIG_LEN, "3DES service key file, key #%d, offset %ld", count, ftell(skf));
			service_key_list = g_slist_append(service_key_list, (void *) sk);
			if (fseek(skf, newline_skip, SEEK_CUR) < 0) {
				fprintf(stderr, "unable to seek...\n");
				fclose(skf);
				return;
			}
			count++;
		}
		fclose(skf);
	}
}

#define CONFOUNDER_PLUS_CHECKSUM 24

uint8_t *
decrypt_krb5_data(proto_tree *tree, packet_info *pinfo,
					int _U_ usage,
					tvbuff_t *cryptotvb,
					int keytype,
					int *datalen)
{
	tvbuff_t *encr_tvb;
	uint8_t *decrypted_data = NULL, *plaintext = NULL;
	uint8_t cls;
	bool pc;
	uint32_t tag, item_len, data_len;
	int id_offset, offset;
	uint8_t key[DES3_KEY_SIZE];
	uint8_t initial_vector[DES_BLOCK_SIZE];
	gcry_md_hd_t md5_handle;
	uint8_t *digest;
	uint8_t zero_fill[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	uint8_t confounder[8];
	bool ind;
	GSList *ske;
	service_key_t *sk;
	struct des3_ctx ctx;
	int length = tvb_captured_length(cryptotvb);
	const uint8_t *cryptotext = tvb_get_ptr(cryptotvb, 0, length);


	/* don't do anything if we are not attempting to decrypt data */
	if(!krb_decrypt){
		return NULL;
	}

	/* make sure we have all the data we need */
	if (tvb_captured_length(cryptotvb) < tvb_reported_length(cryptotvb)) {
		return NULL;
	}

	if (keytype != KEYTYPE_DES3_CBC_MD5 || service_key_list == NULL) {
		return NULL;
	}

	decrypted_data = wmem_alloc(pinfo->pool, length);
	for(ske = service_key_list; ske != NULL; ske = g_slist_next(ske)){
		bool do_continue = false;
		bool digest_ok;
		sk = (service_key_t *) ske->data;

		des_fix_parity(DES3_KEY_SIZE, key, sk->contents);

		memset(initial_vector, 0, DES_BLOCK_SIZE);
		des3_set_key(&ctx, key);
		cbc_decrypt(&ctx, des3_decrypt, DES_BLOCK_SIZE, initial_vector,
					length, decrypted_data, cryptotext);
		encr_tvb = tvb_new_real_data(decrypted_data, length, length);

		tvb_memcpy(encr_tvb, confounder, 0, 8);

		/* We have to pull the decrypted data length from the decrypted
		 * content.  If the key doesn't match or we otherwise get garbage,
		 * an exception may get thrown while decoding the ASN.1 header.
		 * Catch it, just in case.
		 */
		TRY {
			id_offset = get_ber_identifier(encr_tvb, CONFOUNDER_PLUS_CHECKSUM, &cls, &pc, &tag);
			offset = get_ber_length(encr_tvb, id_offset, &item_len, &ind);
		}
		CATCH_BOUNDS_ERRORS {
			tvb_free(encr_tvb);
			do_continue = true;
		}
		ENDTRY;

		if (do_continue) continue;

		data_len = item_len + offset - CONFOUNDER_PLUS_CHECKSUM;
		if ((int) item_len + offset > length) {
			tvb_free(encr_tvb);
			continue;
		}

		if (gcry_md_open(&md5_handle, GCRY_MD_MD5, 0)) {
			return NULL;
		}
		gcry_md_write(md5_handle, confounder, 8);
		gcry_md_write(md5_handle, zero_fill, 16);
		gcry_md_write(md5_handle, decrypted_data + CONFOUNDER_PLUS_CHECKSUM, data_len);
		digest = gcry_md_read(md5_handle, 0);

		digest_ok = (tvb_memeql (encr_tvb, 8, digest, HASH_MD5_LENGTH) == 0);
		gcry_md_close(md5_handle);
		if (digest_ok) {
			plaintext = (uint8_t* )tvb_memdup(pinfo->pool, encr_tvb, CONFOUNDER_PLUS_CHECKSUM, data_len);
			tvb_free(encr_tvb);

			if (datalen) {
				*datalen = data_len;
			}
			return plaintext;
		}
		tvb_free(encr_tvb);
	}

	return NULL;
}

#endif	/* HAVE_MIT_KERBEROS / HAVE_HEIMDAL_KERBEROS / HAVE_LIBNETTLE */

#ifdef NEED_DECRYPT_KRB5_KRB_CFX_DCE_NOOP
tvbuff_t *
decrypt_krb5_krb_cfx_dce(proto_tree *tree _U_,
			 packet_info *pinfo _U_,
			 int usage _U_,
			 int keytype _U_,
			 tvbuff_t *gssapi_header_tvb _U_,
			 tvbuff_t *gssapi_encrypted_tvb _U_,
			 tvbuff_t *gssapi_trailer_tvb _U_,
			 tvbuff_t *checksum_tvb _U_)
{
	return NULL;
}
#endif /* NEED_DECRYPT_KRB5_KRB_CFX_DCE_NOOP */

#define	INET6_ADDRLEN	16

/* TCP Record Mark */
#define	KRB_RM_RESERVED	0x80000000U
#define	KRB_RM_RECLEN	0x7fffffffU

#define KRB5_MSG_TICKET			1	/* Ticket */
#define KRB5_MSG_AUTHENTICATOR		2	/* Authenticator */
#define KRB5_MSG_ENC_TICKET_PART	3	/* EncTicketPart */
#define KRB5_MSG_AS_REQ			10	/* AS-REQ type */
#define KRB5_MSG_AS_REP			11	/* AS-REP type */
#define KRB5_MSG_TGS_REQ		12	/* TGS-REQ type */
#define KRB5_MSG_TGS_REP		13	/* TGS-REP type */
#define KRB5_MSG_AP_REQ			14	/* AP-REQ type */
#define KRB5_MSG_AP_REP			15	/* AP-REP type */
#define KRB5_MSG_TGT_REQ		16	/* TGT-REQ type */
#define KRB5_MSG_TGT_REP		17	/* TGT-REP type */

#define KRB5_MSG_SAFE			20	/* KRB-SAFE type */
#define KRB5_MSG_PRIV			21	/* KRB-PRIV type */
#define KRB5_MSG_CRED			22	/* KRB-CRED type */
#define KRB5_MSG_ENC_AS_REP_PART	25	/* EncASRepPart */
#define KRB5_MSG_ENC_TGS_REP_PART	26	/* EncTGSRepPart */
#define KRB5_MSG_ENC_AP_REP_PART	27	/* EncAPRepPart */
#define KRB5_MSG_ENC_KRB_PRIV_PART	28	/* EncKrbPrivPart */
#define KRB5_MSG_ENC_KRB_CRED_PART	29	/* EncKrbCredPart */
#define KRB5_MSG_ERROR			30	/* KRB-ERROR type */

#define KRB5_CHKSUM_GSSAPI		0x8003
/*
 * For KERB_ENCTYPE_RC4_HMAC and KERB_ENCTYPE_RC4_HMAC_EXP, see
 *
 *	https://tools.ietf.org/html/draft-brezak-win2k-krb-rc4-hmac-04
 *
 * unless it's expired.
 */

/* Principal name-type */
#define KRB5_NT_UNKNOWN		0
#define KRB5_NT_PRINCIPAL	1
#define KRB5_NT_SRV_INST	2
#define KRB5_NT_SRV_HST		3
#define KRB5_NT_SRV_XHST	4
#define KRB5_NT_UID		5
#define KRB5_NT_X500_PRINCIPAL	6
#define KRB5_NT_SMTP_NAME	7
#define KRB5_NT_ENTERPRISE	10

/*
 * MS specific name types, from
 *
 *	http://msdn.microsoft.com/library/en-us/security/security/kerb_external_name.asp
 */
#define KRB5_NT_MS_PRINCIPAL		-128
#define KRB5_NT_MS_PRINCIPAL_AND_SID	-129
#define KRB5_NT_ENT_PRINCIPAL_AND_SID	-130
#define KRB5_NT_PRINCIPAL_AND_SID 	-131
#define KRB5_NT_SRV_INST_AND_SID	-132

/* error table constants */
/* I prefixed the krb5_err.et constant names with KRB5_ET_ for these */
#define KRB5_ET_KRB5KDC_ERR_NONE			0
#define KRB5_ET_KRB5KDC_ERR_NAME_EXP			1
#define KRB5_ET_KRB5KDC_ERR_SERVICE_EXP			2
#define KRB5_ET_KRB5KDC_ERR_BAD_PVNO			3
#define KRB5_ET_KRB5KDC_ERR_C_OLD_MAST_KVNO		4
#define KRB5_ET_KRB5KDC_ERR_S_OLD_MAST_KVNO		5
#define KRB5_ET_KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN		6
#define KRB5_ET_KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN		7
#define KRB5_ET_KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE	8
#define KRB5_ET_KRB5KDC_ERR_NULL_KEY			9
#define KRB5_ET_KRB5KDC_ERR_CANNOT_POSTDATE		10
#define KRB5_ET_KRB5KDC_ERR_NEVER_VALID			11
#define KRB5_ET_KRB5KDC_ERR_POLICY			12
#define KRB5_ET_KRB5KDC_ERR_BADOPTION			13
#define KRB5_ET_KRB5KDC_ERR_ETYPE_NOSUPP		14
#define KRB5_ET_KRB5KDC_ERR_SUMTYPE_NOSUPP		15
#define KRB5_ET_KRB5KDC_ERR_PADATA_TYPE_NOSUPP		16
#define KRB5_ET_KRB5KDC_ERR_TRTYPE_NOSUPP		17
#define KRB5_ET_KRB5KDC_ERR_CLIENT_REVOKED		18
#define KRB5_ET_KRB5KDC_ERR_SERVICE_REVOKED		19
#define KRB5_ET_KRB5KDC_ERR_TGT_REVOKED			20
#define KRB5_ET_KRB5KDC_ERR_CLIENT_NOTYET		21
#define KRB5_ET_KRB5KDC_ERR_SERVICE_NOTYET		22
#define KRB5_ET_KRB5KDC_ERR_KEY_EXP			23
#define KRB5_ET_KRB5KDC_ERR_PREAUTH_FAILED		24
#define KRB5_ET_KRB5KDC_ERR_PREAUTH_REQUIRED		25
#define KRB5_ET_KRB5KDC_ERR_SERVER_NOMATCH		26
#define KRB5_ET_KRB5KDC_ERR_MUST_USE_USER2USER		27
#define KRB5_ET_KRB5KDC_ERR_PATH_NOT_ACCEPTED		28
#define KRB5_ET_KRB5KDC_ERR_SVC_UNAVAILABLE		29
#define KRB5_ET_KRB5KRB_AP_ERR_BAD_INTEGRITY		31
#define KRB5_ET_KRB5KRB_AP_ERR_TKT_EXPIRED		32
#define KRB5_ET_KRB5KRB_AP_ERR_TKT_NYV			33
#define KRB5_ET_KRB5KRB_AP_ERR_REPEAT			34
#define KRB5_ET_KRB5KRB_AP_ERR_NOT_US			35
#define KRB5_ET_KRB5KRB_AP_ERR_BADMATCH			36
#define KRB5_ET_KRB5KRB_AP_ERR_SKEW			37
#define KRB5_ET_KRB5KRB_AP_ERR_BADADDR			38
#define KRB5_ET_KRB5KRB_AP_ERR_BADVERSION		39
#define KRB5_ET_KRB5KRB_AP_ERR_MSG_TYPE			40
#define KRB5_ET_KRB5KRB_AP_ERR_MODIFIED			41
#define KRB5_ET_KRB5KRB_AP_ERR_BADORDER			42
#define KRB5_ET_KRB5KRB_AP_ERR_ILL_CR_TKT		43
#define KRB5_ET_KRB5KRB_AP_ERR_BADKEYVER		44
#define KRB5_ET_KRB5KRB_AP_ERR_NOKEY			45
#define KRB5_ET_KRB5KRB_AP_ERR_MUT_FAIL			46
#define KRB5_ET_KRB5KRB_AP_ERR_BADDIRECTION		47
#define KRB5_ET_KRB5KRB_AP_ERR_METHOD			48
#define KRB5_ET_KRB5KRB_AP_ERR_BADSEQ			49
#define KRB5_ET_KRB5KRB_AP_ERR_INAPP_CKSUM		50
#define KRB5_ET_KRB5KDC_AP_PATH_NOT_ACCEPTED		51
#define KRB5_ET_KRB5KRB_ERR_RESPONSE_TOO_BIG		52
#define KRB5_ET_KRB5KRB_ERR_GENERIC			60
#define KRB5_ET_KRB5KRB_ERR_FIELD_TOOLONG		61
#define KRB5_ET_KDC_ERROR_CLIENT_NOT_TRUSTED		62
#define KRB5_ET_KDC_ERROR_KDC_NOT_TRUSTED		63
#define KRB5_ET_KDC_ERROR_INVALID_SIG			64
#define KRB5_ET_KDC_ERR_KEY_TOO_WEAK			65
#define KRB5_ET_KDC_ERR_CERTIFICATE_MISMATCH		66
#define KRB5_ET_KRB_AP_ERR_NO_TGT			67
#define KRB5_ET_KDC_ERR_WRONG_REALM			68
#define KRB5_ET_KRB_AP_ERR_USER_TO_USER_REQUIRED	69
#define KRB5_ET_KDC_ERR_CANT_VERIFY_CERTIFICATE		70
#define KRB5_ET_KDC_ERR_INVALID_CERTIFICATE		71
#define KRB5_ET_KDC_ERR_REVOKED_CERTIFICATE		72
#define KRB5_ET_KDC_ERR_REVOCATION_STATUS_UNKNOWN	73
#define KRB5_ET_KDC_ERR_REVOCATION_STATUS_UNAVAILABLE	74
#define KRB5_ET_KDC_ERR_CLIENT_NAME_MISMATCH		75
#define KRB5_ET_KDC_ERR_KDC_NAME_MISMATCH		76
#define KRB5_ET_KDC_ERR_PREAUTH_EXPIRED			90
#define KRB5_ET_KDC_ERR_MORE_PREAUTH_DATA_REQUIRED	91
#define KRB5_ET_KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET	92
#define KRB5_ET_KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS	93

static const value_string krb5_error_codes[] = {
	{ KRB5_ET_KRB5KDC_ERR_NONE, "KRB5KDC_ERR_NONE" },
	{ KRB5_ET_KRB5KDC_ERR_NAME_EXP, "KRB5KDC_ERR_NAME_EXP" },
	{ KRB5_ET_KRB5KDC_ERR_SERVICE_EXP, "KRB5KDC_ERR_SERVICE_EXP" },
	{ KRB5_ET_KRB5KDC_ERR_BAD_PVNO, "KRB5KDC_ERR_BAD_PVNO" },
	{ KRB5_ET_KRB5KDC_ERR_C_OLD_MAST_KVNO, "KRB5KDC_ERR_C_OLD_MAST_KVNO" },
	{ KRB5_ET_KRB5KDC_ERR_S_OLD_MAST_KVNO, "KRB5KDC_ERR_S_OLD_MAST_KVNO" },
	{ KRB5_ET_KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN, "KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN" },
	{ KRB5_ET_KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN, "KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN" },
	{ KRB5_ET_KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE, "KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE" },
	{ KRB5_ET_KRB5KDC_ERR_NULL_KEY, "KRB5KDC_ERR_NULL_KEY" },
	{ KRB5_ET_KRB5KDC_ERR_CANNOT_POSTDATE, "KRB5KDC_ERR_CANNOT_POSTDATE" },
	{ KRB5_ET_KRB5KDC_ERR_NEVER_VALID, "KRB5KDC_ERR_NEVER_VALID" },
	{ KRB5_ET_KRB5KDC_ERR_POLICY, "KRB5KDC_ERR_POLICY" },
	{ KRB5_ET_KRB5KDC_ERR_BADOPTION, "KRB5KDC_ERR_BADOPTION" },
	{ KRB5_ET_KRB5KDC_ERR_ETYPE_NOSUPP, "KRB5KDC_ERR_ETYPE_NOSUPP" },
	{ KRB5_ET_KRB5KDC_ERR_SUMTYPE_NOSUPP, "KRB5KDC_ERR_SUMTYPE_NOSUPP" },
	{ KRB5_ET_KRB5KDC_ERR_PADATA_TYPE_NOSUPP, "KRB5KDC_ERR_PADATA_TYPE_NOSUPP" },
	{ KRB5_ET_KRB5KDC_ERR_TRTYPE_NOSUPP, "KRB5KDC_ERR_TRTYPE_NOSUPP" },
	{ KRB5_ET_KRB5KDC_ERR_CLIENT_REVOKED, "KRB5KDC_ERR_CLIENT_REVOKED" },
	{ KRB5_ET_KRB5KDC_ERR_SERVICE_REVOKED, "KRB5KDC_ERR_SERVICE_REVOKED" },
	{ KRB5_ET_KRB5KDC_ERR_TGT_REVOKED, "KRB5KDC_ERR_TGT_REVOKED" },
	{ KRB5_ET_KRB5KDC_ERR_CLIENT_NOTYET, "KRB5KDC_ERR_CLIENT_NOTYET" },
	{ KRB5_ET_KRB5KDC_ERR_SERVICE_NOTYET, "KRB5KDC_ERR_SERVICE_NOTYET" },
	{ KRB5_ET_KRB5KDC_ERR_KEY_EXP, "KRB5KDC_ERR_KEY_EXP" },
	{ KRB5_ET_KRB5KDC_ERR_PREAUTH_FAILED, "KRB5KDC_ERR_PREAUTH_FAILED" },
	{ KRB5_ET_KRB5KDC_ERR_PREAUTH_REQUIRED, "KRB5KDC_ERR_PREAUTH_REQUIRED" },
	{ KRB5_ET_KRB5KDC_ERR_SERVER_NOMATCH, "KRB5KDC_ERR_SERVER_NOMATCH" },
	{ KRB5_ET_KRB5KDC_ERR_MUST_USE_USER2USER, "KRB5KDC_ERR_MUST_USE_USER2USER" },
	{ KRB5_ET_KRB5KDC_ERR_PATH_NOT_ACCEPTED, "KRB5KDC_ERR_PATH_NOT_ACCEPTED" },
	{ KRB5_ET_KRB5KDC_ERR_SVC_UNAVAILABLE, "KRB5KDC_ERR_SVC_UNAVAILABLE" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BAD_INTEGRITY, "KRB5KRB_AP_ERR_BAD_INTEGRITY" },
	{ KRB5_ET_KRB5KRB_AP_ERR_TKT_EXPIRED, "KRB5KRB_AP_ERR_TKT_EXPIRED" },
	{ KRB5_ET_KRB5KRB_AP_ERR_TKT_NYV, "KRB5KRB_AP_ERR_TKT_NYV" },
	{ KRB5_ET_KRB5KRB_AP_ERR_REPEAT, "KRB5KRB_AP_ERR_REPEAT" },
	{ KRB5_ET_KRB5KRB_AP_ERR_NOT_US, "KRB5KRB_AP_ERR_NOT_US" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADMATCH, "KRB5KRB_AP_ERR_BADMATCH" },
	{ KRB5_ET_KRB5KRB_AP_ERR_SKEW, "KRB5KRB_AP_ERR_SKEW" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADADDR, "KRB5KRB_AP_ERR_BADADDR" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADVERSION, "KRB5KRB_AP_ERR_BADVERSION" },
	{ KRB5_ET_KRB5KRB_AP_ERR_MSG_TYPE, "KRB5KRB_AP_ERR_MSG_TYPE" },
	{ KRB5_ET_KRB5KRB_AP_ERR_MODIFIED, "KRB5KRB_AP_ERR_MODIFIED" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADORDER, "KRB5KRB_AP_ERR_BADORDER" },
	{ KRB5_ET_KRB5KRB_AP_ERR_ILL_CR_TKT, "KRB5KRB_AP_ERR_ILL_CR_TKT" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADKEYVER, "KRB5KRB_AP_ERR_BADKEYVER" },
	{ KRB5_ET_KRB5KRB_AP_ERR_NOKEY, "KRB5KRB_AP_ERR_NOKEY" },
	{ KRB5_ET_KRB5KRB_AP_ERR_MUT_FAIL, "KRB5KRB_AP_ERR_MUT_FAIL" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADDIRECTION, "KRB5KRB_AP_ERR_BADDIRECTION" },
	{ KRB5_ET_KRB5KRB_AP_ERR_METHOD, "KRB5KRB_AP_ERR_METHOD" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADSEQ, "KRB5KRB_AP_ERR_BADSEQ" },
	{ KRB5_ET_KRB5KRB_AP_ERR_INAPP_CKSUM, "KRB5KRB_AP_ERR_INAPP_CKSUM" },
	{ KRB5_ET_KRB5KDC_AP_PATH_NOT_ACCEPTED, "KRB5KDC_AP_PATH_NOT_ACCEPTED" },
	{ KRB5_ET_KRB5KRB_ERR_RESPONSE_TOO_BIG, "KRB5KRB_ERR_RESPONSE_TOO_BIG"},
	{ KRB5_ET_KRB5KRB_ERR_GENERIC, "KRB5KRB_ERR_GENERIC" },
	{ KRB5_ET_KRB5KRB_ERR_FIELD_TOOLONG, "KRB5KRB_ERR_FIELD_TOOLONG" },
	{ KRB5_ET_KDC_ERROR_CLIENT_NOT_TRUSTED, "KDC_ERROR_CLIENT_NOT_TRUSTED" },
	{ KRB5_ET_KDC_ERROR_KDC_NOT_TRUSTED, "KDC_ERROR_KDC_NOT_TRUSTED" },
	{ KRB5_ET_KDC_ERROR_INVALID_SIG, "KDC_ERROR_INVALID_SIG" },
	{ KRB5_ET_KDC_ERR_KEY_TOO_WEAK, "KDC_ERR_KEY_TOO_WEAK" },
	{ KRB5_ET_KDC_ERR_CERTIFICATE_MISMATCH, "KDC_ERR_CERTIFICATE_MISMATCH" },
	{ KRB5_ET_KRB_AP_ERR_NO_TGT, "KRB_AP_ERR_NO_TGT" },
	{ KRB5_ET_KDC_ERR_WRONG_REALM, "KDC_ERR_WRONG_REALM" },
	{ KRB5_ET_KRB_AP_ERR_USER_TO_USER_REQUIRED, "KRB_AP_ERR_USER_TO_USER_REQUIRED" },
	{ KRB5_ET_KDC_ERR_CANT_VERIFY_CERTIFICATE, "KDC_ERR_CANT_VERIFY_CERTIFICATE" },
	{ KRB5_ET_KDC_ERR_INVALID_CERTIFICATE, "KDC_ERR_INVALID_CERTIFICATE" },
	{ KRB5_ET_KDC_ERR_REVOKED_CERTIFICATE, "KDC_ERR_REVOKED_CERTIFICATE" },
	{ KRB5_ET_KDC_ERR_REVOCATION_STATUS_UNKNOWN, "KDC_ERR_REVOCATION_STATUS_UNKNOWN" },
	{ KRB5_ET_KDC_ERR_REVOCATION_STATUS_UNAVAILABLE, "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE" },
	{ KRB5_ET_KDC_ERR_CLIENT_NAME_MISMATCH, "KDC_ERR_CLIENT_NAME_MISMATCH" },
	{ KRB5_ET_KDC_ERR_KDC_NAME_MISMATCH, "KDC_ERR_KDC_NAME_MISMATCH" },
	{ KRB5_ET_KDC_ERR_PREAUTH_EXPIRED, "KDC_ERR_PREAUTH_EXPIRED" },
	{ KRB5_ET_KDC_ERR_MORE_PREAUTH_DATA_REQUIRED, "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED" },
	{ KRB5_ET_KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET, "KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET" },
	{ KRB5_ET_KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS, "KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS" },
	{ 0, NULL }
};


#define PAC_LOGON_INFO		1
#define PAC_CREDENTIAL_TYPE	2
#define PAC_SERVER_CHECKSUM	6
#define PAC_PRIVSVR_CHECKSUM	7
#define PAC_CLIENT_INFO_TYPE	10
#define PAC_S4U_DELEGATION_INFO	11
#define PAC_UPN_DNS_INFO	12
#define PAC_CLIENT_CLAIMS_INFO	13
#define PAC_DEVICE_INFO		14
#define PAC_DEVICE_CLAIMS_INFO	15
#define PAC_TICKET_CHECKSUM	16
#define PAC_ATTRIBUTES_INFO	17
#define PAC_REQUESTER_SID	18
#define PAC_FULL_CHECKSUM	19
static const value_string w2k_pac_types[] = {
	{ PAC_LOGON_INFO		, "Logon Info" },
	{ PAC_CREDENTIAL_TYPE		, "Credential Type" },
	{ PAC_SERVER_CHECKSUM		, "Server Checksum" },
	{ PAC_PRIVSVR_CHECKSUM		, "Privsvr Checksum" },
	{ PAC_CLIENT_INFO_TYPE		, "Client Info Type" },
	{ PAC_S4U_DELEGATION_INFO	, "S4U Delegation Info" },
	{ PAC_UPN_DNS_INFO		, "UPN DNS Info" },
	{ PAC_CLIENT_CLAIMS_INFO	, "Client Claims Info" },
	{ PAC_DEVICE_INFO		, "Device Info" },
	{ PAC_DEVICE_CLAIMS_INFO	, "Device Claims Info" },
	{ PAC_TICKET_CHECKSUM		, "Ticket Checksum" },
	{ PAC_ATTRIBUTES_INFO		, "Attributes Info" },
	{ PAC_REQUESTER_SID		, "Requester Sid" },
	{ PAC_FULL_CHECKSUM		, "Full Checksum" },
	{ 0, NULL },
};

static const value_string krb5_msg_types[] = {
	{ KRB5_MSG_TICKET,		"Ticket" },
	{ KRB5_MSG_AUTHENTICATOR,	"Authenticator" },
	{ KRB5_MSG_ENC_TICKET_PART,	"EncTicketPart" },
	{ KRB5_MSG_TGS_REQ,		"TGS-REQ" },
	{ KRB5_MSG_TGS_REP,		"TGS-REP" },
	{ KRB5_MSG_AS_REQ,		"AS-REQ" },
	{ KRB5_MSG_AS_REP,		"AS-REP" },
	{ KRB5_MSG_AP_REQ,		"AP-REQ" },
	{ KRB5_MSG_AP_REP,		"AP-REP" },
	{ KRB5_MSG_TGT_REQ,		"TGT-REQ" },
	{ KRB5_MSG_TGT_REP,		"TGT-REP" },
	{ KRB5_MSG_SAFE,		"KRB-SAFE" },
	{ KRB5_MSG_PRIV,		"KRB-PRIV" },
	{ KRB5_MSG_CRED,		"KRB-CRED" },
	{ KRB5_MSG_ENC_AS_REP_PART,	"EncASRepPart" },
	{ KRB5_MSG_ENC_TGS_REP_PART,	"EncTGSRepPart" },
	{ KRB5_MSG_ENC_AP_REP_PART,	"EncAPRepPart" },
	{ KRB5_MSG_ENC_KRB_PRIV_PART,	"EncKrbPrivPart" },
	{ KRB5_MSG_ENC_KRB_CRED_PART,	"EncKrbCredPart" },
	{ KRB5_MSG_ERROR,		"KRB-ERROR" },
	{ 0, NULL },
};

#define KRB5_GSS_C_DELEG_FLAG             0x01
#define KRB5_GSS_C_MUTUAL_FLAG            0x02
#define KRB5_GSS_C_REPLAY_FLAG            0x04
#define KRB5_GSS_C_SEQUENCE_FLAG          0x08
#define KRB5_GSS_C_CONF_FLAG              0x10
#define KRB5_GSS_C_INTEG_FLAG             0x20
#define KRB5_GSS_C_DCE_STYLE            0x1000

static const true_false_string tfs_gss_flags_deleg = {
	"Delegate credentials to remote peer",
	"Do NOT delegate"
};
static const true_false_string tfs_gss_flags_mutual = {
	"Request that remote peer authenticates itself",
	"Mutual authentication NOT required"
};
static const true_false_string tfs_gss_flags_replay = {
	"Enable replay protection for signed or sealed messages",
	"Do NOT enable replay protection"
};
static const true_false_string tfs_gss_flags_sequence = {
	"Enable Out-of-sequence detection for sign or sealed messages",
	"Do NOT enable out-of-sequence detection"
};
static const true_false_string tfs_gss_flags_conf = {
	"Confidentiality (sealing) may be invoked",
	"Do NOT use Confidentiality (sealing)"
};
static const true_false_string tfs_gss_flags_integ = {
	"Integrity protection (signing) may be invoked",
	"Do NOT use integrity protection"
};

static const true_false_string tfs_gss_flags_dce_style = {
	"DCE-STYLE",
	"Not using DCE-STYLE"
};

static int dissect_kerberos_KRB5_SRP_PA_APPLICATIONS(bool implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	proto_item *pi1 = proto_item_get_parent(actx->created_item);
	proto_item *pi2 = proto_item_get_parent(pi1);
	int8_t ber_class;
	bool pc;
	int32_t tag;

	/*
	 * dissect_ber_octet_string_wcb() always passes
	 * implicit_tag=false, offset=0 and hf_index=-1
	 */
	ws_assert(implicit_tag == false);
	ws_assert(offset == 0);
	ws_assert(hf_index <= 0);

	get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
	if (ber_class != BER_CLASS_APP) {
		if (kerberos_private_is_kdc_req(private_data)) {
			goto unknown;
		}
		if (private_data->errorcode != KRB5_ET_KRB5KDC_ERR_PREAUTH_REQUIRED) {
			goto unknown;
		}

		proto_item_append_text(pi1, " KRB5_SRP_PA_ANNOUNCE");
		proto_item_append_text(pi2, ": KRB5_SRP_PA_ANNOUNCE");
		return dissect_kerberos_KRB5_SRP_PA_ANNOUNCE(implicit_tag, tvb, offset, actx, tree, hf_index);
	}

	switch (tag) {
	case 0:
		proto_item_append_text(pi1, " KRB5_SRP_PA_INIT");
		proto_item_append_text(pi2, ": KRB5_SRP_PA_INIT");
		return dissect_kerberos_KRB5_SRP_PA_INIT(implicit_tag, tvb, offset, actx, tree, hf_index);
	case 1:
		proto_item_append_text(pi1, " KRB5_SRP_PA_SERVER_CHALLENGE");
		proto_item_append_text(pi2, ": KRB5_SRP_PA_SERVER_CHALLENGE");
		return dissect_kerberos_KRB5_SRP_PA_SERVER_CHALLENGE(implicit_tag, tvb, offset, actx, tree, hf_index);
	case 2:
		proto_item_append_text(pi1, " KRB5_SRP_PA_CLIENT_RESPONSE");
		proto_item_append_text(pi2, ": KRB5_SRP_PA_CLIENT_RESPONSE");
		return dissect_kerberos_KRB5_SRP_PA_CLIENT_RESPONSE(implicit_tag, tvb, offset, actx, tree, hf_index);
	case 3:
		proto_item_append_text(pi1, " KRB5_SRP_PA_SERVER_VERIFIER");
		proto_item_append_text(pi2, ": KRB5_SRP_PA_SERVER_VERIFIER");
		return dissect_kerberos_KRB5_SRP_PA_SERVER_VERIFIER(implicit_tag, tvb, offset, actx, tree, hf_index);
	default:
		break;
	}

unknown:
	proto_item_append_text(pi1, " KRB5_SRP_PA_UNKNOWN: ber_class:%u ber_pc=%u ber_tag:%"PRIu32"", ber_class, pc, tag);
	proto_item_append_text(pi2, ": KRB5_SRP_PA_UNKNOWN");
	return tvb_reported_length_remaining(tvb, offset);
}

#ifdef HAVE_KERBEROS
static uint8_t *
decrypt_krb5_data_asn1(proto_tree *tree, asn1_ctx_t *actx,
		       int usage, tvbuff_t *cryptotvb, int *datalen)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

#ifdef HAVE_DECRYPT_KRB5_DATA_PRIVATE
	return decrypt_krb5_data_private(tree, actx->pinfo, private_data,
					 usage, cryptotvb,
					 private_data->etype,
					 datalen);
#else
	return decrypt_krb5_data(tree, actx->pinfo, usage, cryptotvb,
				 private_data->etype, datalen);
#endif
}

static int
dissect_krb5_decrypt_ticket_data (bool imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	uint8_t *plaintext;
	int length;
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * All Ticket encrypted parts use usage == 2
	 */
	plaintext=decrypt_krb5_data_asn1(tree, actx, 2, next_tvb, &length);

	if(plaintext){
		kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
		tvbuff_t *last_ticket_enc_part_tvb = private_data->last_ticket_enc_part_tvb;
		enc_key_t *current_ticket_key = private_data->current_ticket_key;
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Krb5 Ticket");

		private_data->last_ticket_enc_part_tvb = child_tvb;
		private_data->current_ticket_key = NULL;
		offset=dissect_kerberos_Applications(false, child_tvb, 0, actx , tree, /* hf_index*/ -1);
		private_data->current_ticket_key = current_ticket_key;
		private_data->last_ticket_enc_part_tvb = last_ticket_enc_part_tvb;
	}
	return offset;
}

static int
dissect_krb5_decrypt_authenticator_data (bool imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
											proto_tree *tree, int hf_index _U_)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	uint8_t *plaintext;
	int length;
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * Authenticators are encrypted with usage
	 * == 7 or
	 * == 11
	 *
	 * 7.  TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator
	 *     (includes TGS authenticator subkey), encrypted with the
	 *     TGS session key (section 5.5.1)
	 * 11. AP-REQ Authenticator (includes application
	 *     authenticator subkey), encrypted with the application
	 *     session key (section 5.5.1)
	 */
	if (private_data->within_PA_TGS_REQ > 0) {
		plaintext=decrypt_krb5_data_asn1(tree, actx, 7, next_tvb, &length);
	} else {
		plaintext=decrypt_krb5_data_asn1(tree, actx, 11, next_tvb, &length);
	}

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Krb5 Authenticator");

		offset=dissect_kerberos_Applications(false, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_authorization_data(bool imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
					proto_tree *tree, int hf_index _U_)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	uint8_t *plaintext;
	int length;
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * Authenticators are encrypted with usage
	 * == 5 or
	 * == 4
	 *
	 * 4. TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with
	 *    the TGS session key (section 5.4.1)
	 * 5. TGS-REQ KDC-REQ-BODY AuthorizationData, encrypted with
	 *    the TGS authenticator subkey (section 5.4.1)
	 */
	if (private_data->PA_TGS_REQ_subkey != NULL) {
		plaintext=decrypt_krb5_data_asn1(tree, actx, 5, next_tvb, &length);
	} else {
		plaintext=decrypt_krb5_data_asn1(tree, actx, 4, next_tvb, &length);
	}

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Krb5 AuthorizationData");

		offset=dissect_kerberos_AuthorizationData(false, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_KDC_REP_data (bool imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	uint8_t *plaintext = NULL;
	int length;
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * ASREP/TGSREP encryptedparts are encrypted with usage
	 * == 3 or
	 * == 8 or
	 * == 9
	 *
	 * 3. AS-REP encrypted part (includes TGS session key or
	 *    application session key), encrypted with the client key
	 *    (section 5.4.2)
	 *
	 * 8. TGS-REP encrypted part (includes application session
	 *    key), encrypted with the TGS session key (section
	 *    5.4.2)
	 * 9. TGS-REP encrypted part (includes application session
	 *    key), encrypted with the TGS authenticator subkey
	 *    (section 5.4.2)
	 *
	 * We currently don't have a way to find the TGS-REQ state
	 * in order to check if an authenticator subkey was used.
	 *
	 * But if we client used FAST and we got a strengthen_key,
	 * we're sure an authenticator subkey was used.
	 *
	 * Windows don't use an authenticator subkey without FAST,
	 * but heimdal does.
	 *
	 * For now try 8 before 9 in order to avoid overhead and false
	 * positives for the 'kerberos.missing_keytype' filter in pure
	 * windows captures.
	 */
	switch (private_data->msg_type) {
	case KERBEROS_APPLICATIONS_AS_REP:
		plaintext=decrypt_krb5_data_asn1(tree, actx, 3, next_tvb, &length);
		break;
	case KERBEROS_APPLICATIONS_TGS_REP:
		if (private_data->fast_strengthen_key != NULL) {
			plaintext=decrypt_krb5_data_asn1(tree, actx, 9, next_tvb, &length);
		} else {
			plaintext=decrypt_krb5_data_asn1(tree, actx, 8, next_tvb, &length);
			if(!plaintext){
				plaintext=decrypt_krb5_data_asn1(tree, actx, 9, next_tvb, &length);
			}
		}
		break;
	}

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Krb5 KDC-REP");

		offset=dissect_kerberos_Applications(false, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_PA_ENC_TIMESTAMP (bool imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
										proto_tree *tree, int hf_index _U_)
{
	uint8_t *plaintext;
	int length;
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * AS-REQ PA_ENC_TIMESTAMP are encrypted with usage
	 * == 1
	 */
	plaintext=decrypt_krb5_data_asn1(tree, actx, 1, next_tvb, &length);

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Krb5 EncTimestamp");

		offset=dissect_kerberos_PA_ENC_TS_ENC(false, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_AP_REP_data (bool imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	uint8_t *plaintext;
	int length;
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * AP-REP are encrypted with usage == 12
	 */
	plaintext=decrypt_krb5_data_asn1(tree, actx, 12, next_tvb, &length);

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Krb5 AP-REP");

		offset=dissect_kerberos_Applications(false, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_PRIV_data (bool imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	uint8_t *plaintext;
	int length;
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* RFC4120 :
	 * EncKrbPrivPart encrypted with usage
	 * == 13
	 */
	plaintext=decrypt_krb5_data_asn1(tree, actx, 13, next_tvb, &length);

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Krb5 PRIV");

		offset=dissect_kerberos_Applications(false, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_CRED_data (bool imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	uint8_t *plaintext;
	int length;
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	if (private_data->etype == 0) {
		offset=dissect_kerberos_Applications(false, next_tvb, 0, actx , tree, /* hf_index*/ -1);
		return offset;
	}

	/* RFC4120 :
	 * EncKrbCredPart encrypted with usage
	 * == 14
	 */
	plaintext=decrypt_krb5_data_asn1(tree, actx, 14, next_tvb, &length);

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Krb5 CRED");

		offset=dissect_kerberos_Applications(false, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_KrbFastReq(bool imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
				proto_tree *tree, int hf_index _U_)
{
	uint8_t *plaintext;
	int length;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	private_data->fast_armor_key = NULL;
	if (private_data->PA_FAST_ARMOR_AP_subkey != NULL) {
		krb5_fast_key(actx, tree, tvb,
			      private_data->PA_FAST_ARMOR_AP_subkey,
			      "subkeyarmor",
			      private_data->PA_FAST_ARMOR_AP_key,
			      "ticketarmor",
			      "KrbFastReq_FAST_armorKey");
		if (private_data->PA_TGS_REQ_subkey != NULL) {
			enc_key_t *explicit_armor_key = private_data->last_added_key;

			/*
			 * See [MS-KILE] 3.3.5.7.4 Compound Identity
			 */
			krb5_fast_key(actx, tree, tvb,
				      explicit_armor_key,
				      "explicitarmor",
				      private_data->PA_TGS_REQ_subkey,
				      "tgsarmor",
				      "KrbFastReq_explicitArmorKey");
		}
		private_data->fast_armor_key = private_data->last_added_key;
	} else if (private_data->PA_TGS_REQ_subkey != NULL) {
		krb5_fast_key(actx, tree, tvb,
			      private_data->PA_TGS_REQ_subkey,
			      "subkeyarmor",
			      private_data->PA_TGS_REQ_key,
			      "ticketarmor",
			      "KrbFastReq_TGS_armorKey");
		private_data->fast_armor_key = private_data->last_added_key;
	}

	/* RFC6113 :
	 * KrbFastResponse encrypted with usage
	 * KEY_USAGE_FAST_ENC 51
	 */
	plaintext=decrypt_krb5_data_asn1(tree, actx, KEY_USAGE_FAST_ENC,
					 next_tvb, &length);

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Krb5 FastReq");

		offset=dissect_kerberos_KrbFastReq(false, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_KrbFastResponse(bool imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
				     proto_tree *tree, int hf_index _U_)
{
	uint8_t *plaintext;
	int length;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/*
	 * RFC6113 :
	 * KrbFastResponse encrypted with usage
	 * KEY_USAGE_FAST_REP 52
	 */
	plaintext=decrypt_krb5_data_asn1(tree, actx, KEY_USAGE_FAST_REP,
					 next_tvb, &length);

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Krb5 FastRep");

		private_data->fast_armor_key = private_data->last_decryption_key;
		offset=dissect_kerberos_KrbFastResponse(false, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_EncryptedChallenge(bool imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
					proto_tree *tree, int hf_index _U_)
{
	uint8_t *plaintext;
	int length;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *next_tvb;
	int usage = 0;
	const char *name = NULL;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* RFC6113 :
	 * KEY_USAGE_ENC_CHALLENGE_CLIENT  54
	 * KEY_USAGE_ENC_CHALLENGE_KDC     55
	 */
	if (kerberos_private_is_kdc_req(private_data)) {
		usage = KEY_USAGE_ENC_CHALLENGE_CLIENT;
		name = "Krb5 CHALLENGE_CLIENT";
	} else {
		usage = KEY_USAGE_ENC_CHALLENGE_KDC;
		name = "Krb5 CHALLENGE_KDC";
	}
	plaintext=decrypt_krb5_data_asn1(tree, actx, usage, next_tvb, &length);

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, name);

		offset=dissect_kerberos_PA_ENC_TS_ENC(false, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}
#endif /* HAVE_KERBEROS */

static int * const hf_krb_pa_supported_enctypes_fields[] = {
	&hf_krb_pa_supported_enctypes_des_cbc_crc,
	&hf_krb_pa_supported_enctypes_des_cbc_md5,
	&hf_krb_pa_supported_enctypes_rc4_hmac,
	&hf_krb_pa_supported_enctypes_aes128_cts_hmac_sha1_96,
	&hf_krb_pa_supported_enctypes_aes256_cts_hmac_sha1_96,
	&hf_krb_pa_supported_enctypes_aes256_cts_hmac_sha1_96_sk,
	&hf_krb_pa_supported_enctypes_fast_supported,
	&hf_krb_pa_supported_enctypes_compound_identity_supported,
	&hf_krb_pa_supported_enctypes_claims_supported,
	&hf_krb_pa_supported_enctypes_resource_sid_compression_disabled,
	NULL,
};

static int
dissect_kerberos_PA_SUPPORTED_ENCTYPES(bool implicit_tag _U_, tvbuff_t *tvb _U_,
				       int offset _U_, asn1_ctx_t *actx _U_,
				       proto_tree *tree _U_, int hf_index _U_)
{
	actx->created_item = proto_tree_add_bitmask(tree, tvb, offset,
						    hf_krb_pa_supported_enctypes,
						    ett_krb_pa_supported_enctypes,
						    hf_krb_pa_supported_enctypes_fields,
						    ENC_LITTLE_ENDIAN);
	offset += 4;

	return offset;
}

static int * const hf_krb_ad_ap_options_fields[] = {
	&hf_krb_ad_ap_options_cbt,
	&hf_krb_ad_ap_options_unverified_target_name,
	NULL,
};


static int
dissect_kerberos_AD_AP_OPTIONS(bool implicit_tag _U_, tvbuff_t *tvb _U_,
			       int offset _U_, asn1_ctx_t *actx _U_,
			       proto_tree *tree _U_, int hf_index _U_)
{
	actx->created_item = proto_tree_add_bitmask(tree, tvb, offset,
						    hf_krb_ad_ap_options,
						    ett_krb_ad_ap_options,
						    hf_krb_ad_ap_options_fields,
						    ENC_LITTLE_ENDIAN);
	offset += 4;

	return offset;
}

static int
dissect_kerberos_AD_TARGET_PRINCIPAL(bool implicit_tag _U_, tvbuff_t *tvb _U_,
				     int offset _U_, asn1_ctx_t *actx _U_,
				     proto_tree *tree _U_, int hf_index _U_)
{
	int tp_offset, tp_len;
	uint16_t bc;

	bc = tvb_reported_length_remaining(tvb, offset);
	tp_offset = offset;
	tp_len = bc;
	proto_tree_add_item(tree, hf_krb_ad_target_principal, tvb,
			    tp_offset, tp_len,
			    ENC_UTF_16 | ENC_LITTLE_ENDIAN);

	return offset;
}

/* Dissect a GSSAPI checksum as per RFC1964. This is NOT ASN.1 encoded.
 */
static int
dissect_krb5_rfc1964_checksum(asn1_ctx_t *actx _U_, proto_tree *tree, tvbuff_t *tvb)
{
	int offset=0;
	uint32_t len;
	uint16_t dlglen;

	/* Length of Bnd field */
	len=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_krb_gssapi_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* Bnd field */
	proto_tree_add_item(tree, hf_krb_gssapi_bnd, tvb, offset, len, ENC_NA);
	offset += len;


	/* flags */
	proto_tree_add_item(tree, hf_krb_gssapi_c_flag_dce_style, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_krb_gssapi_c_flag_integ, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_krb_gssapi_c_flag_conf, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_krb_gssapi_c_flag_sequence, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_krb_gssapi_c_flag_replay, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_krb_gssapi_c_flag_mutual, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_krb_gssapi_c_flag_deleg, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* the next fields are optional so we have to check that we have
	 * more data in our buffers */
	if(tvb_reported_length_remaining(tvb, offset)<2){
		return offset;
	}
	/* dlgopt identifier */
	proto_tree_add_item(tree, hf_krb_gssapi_dlgopt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	if(tvb_reported_length_remaining(tvb, offset)<2){
		return offset;
	}
	/* dlglen identifier */
	dlglen=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_krb_gssapi_dlglen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	if(dlglen!=tvb_reported_length_remaining(tvb, offset)){
		proto_tree_add_expert_format(tree, actx->pinfo, &ei_krb_gssapi_dlglen, tvb, 0, 0,
				"Error: DlgLen:%d is not the same as number of bytes remaining:%d", dlglen, tvb_captured_length_remaining(tvb, offset));
		return offset;
	}

	/* this should now be a KRB_CRED message */
	offset=dissect_kerberos_Applications(false, tvb, offset, actx, tree, /* hf_index */ -1);

	return offset;
}

static int
dissect_krb5_PA_PROV_SRV_LOCATION(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
	offset=dissect_ber_GeneralString(actx, tree, tvb, offset, hf_krb_provsrv_location, NULL, 0);

	return offset;
}

static int
dissect_krb5_PW_SALT(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	int length;
	uint32_t nt_status = 0;
	uint32_t reserved = 0;
	uint32_t flags = 0;

	/*
	 * Microsoft stores a special 12 byte blob here
	 * [MS-KILE] 2.2.1 KERB-EXT-ERROR
	 * uint32_t NT_status
	 * uint32_t reserved (== 0)
	 * uint32_t flags (at least 0x00000001 is set)
	 */
	length = tvb_reported_length_remaining(tvb, offset);
	if (length <= 0) {
		return offset;
	}
	if (length != 12) {
		goto no_error;
	}

	if (private_data->errorcode == 0) {
		goto no_error;
	}

	nt_status = tvb_get_letohl(tvb, offset);
	reserved = tvb_get_letohl(tvb, offset + 4);
	flags = tvb_get_letohl(tvb, offset + 8);

	if (reserved != 0 || flags != 1 || !try_val_to_str_ext(nt_status, &NT_errors_ext)) {
		goto no_error;
	}

	proto_tree_add_item(tree, hf_krb_ext_error_nt_status, tvb, offset, 4,
			ENC_LITTLE_ENDIAN);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO,
			" NT Status: %s",
			val_to_str_ext(nt_status, &NT_errors_ext,
			"Unknown error code %#x"));
	offset += 4;

	proto_tree_add_item(tree, hf_krb_ext_error_reserved, tvb, offset, 4,
			ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_krb_ext_error_flags, tvb, offset, 4,
			ENC_LITTLE_ENDIAN);
	offset += 4;

	return offset;

 no_error:
	proto_tree_add_item(tree, hf_krb_pw_salt, tvb, offset, length, ENC_NA);
	offset += length;

	return offset;
}

static int
dissect_krb5_PAC_DREP(proto_tree *parent_tree, tvbuff_t *tvb, int offset, uint8_t *drep)
{
	proto_tree *tree;
	uint8_t val;

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 16, ett_krb_pac_drep, NULL, "DREP");

	val = tvb_get_uint8(tvb, offset);
	proto_tree_add_uint(tree, hf_dcerpc_drep_byteorder, tvb, offset, 1, val>>4);

	offset++;

	if (drep) {
		*drep = val;
	}

	return offset;
}

/* This might be some sort of header that MIDL generates when creating
 * marshalling/unmarshalling code for blobs that are not to be transported
 * ontop of DCERPC and where the DREP fields specifying things such as
 * endianess and similar are not available.
 */
static int
dissect_krb5_PAC_NDRHEADERBLOB(proto_tree *parent_tree, tvbuff_t *tvb, int offset, uint8_t *drep, asn1_ctx_t *actx _U_)
{
	proto_tree *tree;

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 16, ett_krb_pac_midl_blob, NULL, "MES header");

	/* modified DREP field that is used for stuff that is transporetd ontop
	   of non dcerpc
	*/
	proto_tree_add_item(tree, hf_krb_midl_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;

	offset = dissect_krb5_PAC_DREP(tree, tvb, offset, drep);


	proto_tree_add_item(tree, hf_krb_midl_hdr_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset+=2;

	proto_tree_add_item(tree, hf_krb_midl_fill_bytes, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* length of blob that follows */
	proto_tree_add_item(tree, hf_krb_midl_blob_len, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	return offset;
}

static int
dissect_krb5_PAC_LOGON_INFO(proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	proto_item *item;
	proto_tree *tree;
	uint8_t drep[4] = { 0x10, 0x00, 0x00, 0x00}; /* fake DREP struct */
	/* fake dcerpc_info struct */
	dcerpc_call_value call_data = { .flags = 0, };
	dcerpc_info di = { .ptype = UINT8_MAX, .call_data = &call_data, };

	item = proto_tree_add_item(parent_tree, hf_krb_pac_logon_info, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_krb_pac_logon_info);

	/* skip the first 16 bytes, they are some magic created by the idl
	 * compiler   the first 4 bytes might be flags?
	 */
	offset = dissect_krb5_PAC_NDRHEADERBLOB(tree, tvb, offset, &drep[0], actx);

	/* the PAC_LOGON_INFO blob */
	init_ndr_pointer_list(&di);
	offset = dissect_ndr_pointer(tvb, offset, actx->pinfo, tree, &di, drep,
									netlogon_dissect_PAC_LOGON_INFO, NDR_POINTER_UNIQUE,
									"PAC_LOGON_INFO:", -1);
	free_ndr_pointer_list(&di);

	return offset;
}


static int
dissect_krb5_PAC_CREDENTIAL_DATA(proto_tree *parent_tree, tvbuff_t *tvb, int offset, packet_info *pinfo _U_)
{
	proto_tree_add_item(parent_tree, hf_krb_pac_credential_data, tvb, offset, -1, ENC_NA);

	return offset;
}

static int
dissect_krb5_PAC_CREDENTIAL_INFO(proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx)
{
	proto_item *item;
	proto_tree *tree;
	uint8_t *plaintext = NULL;
	int plainlen = 0;
	int length = 0;
#define KRB5_KU_OTHER_ENCRYPTED 16
#ifdef  HAVE_KERBEROS
	uint32_t etype;
	tvbuff_t *next_tvb;
	int usage = KRB5_KU_OTHER_ENCRYPTED;
#endif

	item = proto_tree_add_item(parent_tree, hf_krb_pac_credential_info, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_krb_pac_credential_info);

	/* version */
	proto_tree_add_item(tree, hf_krb_pac_credential_info_version, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;

#ifdef HAVE_KERBEROS
	/* etype */
	etype = tvb_get_letohl(tvb, offset);
#endif
	proto_tree_add_item(tree, hf_krb_pac_credential_info_etype, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;

#ifdef HAVE_KERBEROS
	/* data */
	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	plaintext=decrypt_krb5_data(tree, actx->pinfo, usage, next_tvb, (int)etype, &plainlen);
#endif

	if (plaintext != NULL) {
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, plainlen, plainlen);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Krb5 PAC_CREDENTIAL");

		dissect_krb5_PAC_CREDENTIAL_DATA(tree, child_tvb, 0, actx->pinfo);
	}

	return offset + length;
}

static int
dissect_krb5_PAC_S4U_DELEGATION_INFO(proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx)
{
	proto_item *item;
	proto_tree *tree;
	uint8_t drep[4] = { 0x10, 0x00, 0x00, 0x00}; /* fake DREP struct */
	/* fake dcerpc_info struct */
	dcerpc_call_value call_data = { .flags = 0, };
	dcerpc_info di = { .ptype = UINT8_MAX, .call_data = &call_data, };

	item = proto_tree_add_item(parent_tree, hf_krb_pac_s4u_delegation_info, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_krb_pac_s4u_delegation_info);

	/* skip the first 16 bytes, they are some magic created by the idl
	 * compiler   the first 4 bytes might be flags?
	 */
	offset = dissect_krb5_PAC_NDRHEADERBLOB(tree, tvb, offset, &drep[0], actx);

	/* the S4U_DELEGATION_INFO blob. See [MS-PAC] */
	init_ndr_pointer_list(&di);
	offset = dissect_ndr_pointer(tvb, offset, actx->pinfo, tree, &di, drep,
									netlogon_dissect_PAC_S4U_DELEGATION_INFO, NDR_POINTER_UNIQUE,
									"PAC_S4U_DELEGATION_INFO:", -1);
	free_ndr_pointer_list(&di);

	return offset;
}

#define PAC_UPN_DNS_FLAG_CONSTRUCTED		0x00000001
#define PAC_UPN_DNS_FLAG_HAS_SAM_NAME_AND_SID	0x00000002
static const true_false_string tfs_krb_pac_upn_flag_upn_constructed = {
	"UPN Name is Constructed",
	"UPN Name is NOT Constructed",
};
static const true_false_string tfs_krb_pac_upn_flag_has_sam_name_and_sid = {
	"SAM_NAME and SID are included",
	"SAM_NAME and SID are NOT included",
};
static int * const hf_krb_pac_upn_flags_fields[] = {
	&hf_krb_pac_upn_flag_upn_constructed,
	&hf_krb_pac_upn_flag_has_sam_name_and_sid,
	NULL
};

static int
dissect_krb5_PAC_UPN_DNS_INFO(proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
#ifdef HAVE_KERBEROS
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
#endif /* HAVE_KERBEROS */
	proto_item *item;
	proto_tree *tree;
	uint16_t dns_offset, dns_len;
	uint16_t upn_offset, upn_len;
	uint16_t samaccountname_offset = 0, samaccountname_len = 0;
	uint16_t objectsid_offset = 0, objectsid_len = 0;
	char *sid_str = NULL;
	uint32_t flags;

	item = proto_tree_add_item(parent_tree, hf_krb_pac_upn_dns_info, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_krb_pac_upn_dns_info);

	/* upn */
	upn_len = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_krb_pac_upn_upn_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset+=2;
	upn_offset = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_krb_pac_upn_upn_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset+=2;

	/* dns */
	dns_len = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_krb_pac_upn_dns_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset+=2;
	dns_offset = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_krb_pac_upn_dns_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset+=2;

	/* flags */
	flags = tvb_get_letohl(tvb, offset);
	proto_tree_add_bitmask(tree, tvb, offset,
			       hf_krb_pac_upn_flags,
			       ett_krb_pac_upn_dns_info_flags,
			       hf_krb_pac_upn_flags_fields,
			       ENC_LITTLE_ENDIAN);
	offset+=4;

	if (flags & PAC_UPN_DNS_FLAG_HAS_SAM_NAME_AND_SID) {
		samaccountname_len = tvb_get_letohs(tvb, offset);
		proto_tree_add_item(tree, hf_krb_pac_upn_samaccountname_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset+=2;
		samaccountname_offset = tvb_get_letohs(tvb, offset);
		proto_tree_add_item(tree, hf_krb_pac_upn_samaccountname_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset+=2;

		objectsid_len = tvb_get_letohs(tvb, offset);
		proto_tree_add_item(tree, hf_krb_pac_upn_objectsid_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset+=2;
		objectsid_offset = tvb_get_letohs(tvb, offset);
		proto_tree_add_item(tree, hf_krb_pac_upn_objectsid_offset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		/* offset+=2; */
	}

	/* upn */
	proto_tree_add_item(tree, hf_krb_pac_upn_upn_name, tvb, upn_offset, upn_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);

	/* dns */
	proto_tree_add_item(tree, hf_krb_pac_upn_dns_name, tvb, dns_offset, dns_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);

	/* samaccountname */
	if (samaccountname_offset != 0 && samaccountname_len != 0) {
		proto_tree_add_item(tree, hf_krb_pac_upn_samaccountname, tvb, samaccountname_offset, samaccountname_len, ENC_UTF_16|ENC_LITTLE_ENDIAN);
	}
	/* objectsid */
	if (objectsid_offset != 0 && objectsid_len != 0) {
		tvbuff_t *sid_tvb;
		sid_tvb=tvb_new_subset_length(tvb, objectsid_offset, objectsid_len);
		dissect_nt_sid(sid_tvb, 0, tree, "objectSid", &sid_str, -1);
	}

#ifdef HAVE_KERBEROS
	if (private_data->current_ticket_key != NULL) {
		enc_key_t *ek = private_data->current_ticket_key;

		if (samaccountname_offset != 0 && samaccountname_len != 0) {
			ek->pac_names.account_name = tvb_get_string_enc(wmem_epan_scope(),
									tvb,
									samaccountname_offset,
									samaccountname_len,
									ENC_UTF_16|ENC_LITTLE_ENDIAN);
		} else {
			ek->pac_names.account_name = tvb_get_string_enc(wmem_epan_scope(),
									tvb,
									upn_offset,
									upn_len,
									ENC_UTF_16|ENC_LITTLE_ENDIAN);
		}
		ek->pac_names.account_domain = tvb_get_string_enc(wmem_epan_scope(),
								  tvb,
								  dns_offset,
								  dns_len,
								  ENC_UTF_16|ENC_LITTLE_ENDIAN);
		if (sid_str != NULL) {
			ek->pac_names.account_sid = wmem_strdup(wmem_epan_scope(),
								sid_str);
		}
	}
#endif /* HAVE_KERBEROS */

	return dns_offset;
}

static int
dissect_krb5_PAC_CLIENT_CLAIMS_INFO(proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	int length = tvb_captured_length_remaining(tvb, offset);

	if (length == 0) {
		return offset;
	}

	proto_tree_add_item(parent_tree, hf_krb_pac_client_claims_info, tvb, offset, -1, ENC_NA);

	return offset;
}

static int
dissect_krb5_PAC_DEVICE_INFO(proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
#ifdef HAVE_KERBEROS
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	const char *device_sid = NULL;
#endif /* HAVE_KERBEROS */
	proto_item *item;
	proto_tree *tree;
	uint8_t drep[4] = { 0x10, 0x00, 0x00, 0x00}; /* fake DREP struct */
	/* fake dcerpc_info struct */
	dcerpc_call_value call_data = { .flags = 0, };
	dcerpc_info di = { .ptype = UINT8_MAX, .call_data = &call_data, };

#ifdef HAVE_KERBEROS
	if (private_data->current_ticket_key != NULL) {
		call_data.private_data = (void*)&device_sid;
	}
#endif /* HAVE_KERBEROS */

	item = proto_tree_add_item(parent_tree, hf_krb_pac_device_info, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_krb_pac_device_info);

	/* skip the first 16 bytes, they are some magic created by the idl
	 * compiler   the first 4 bytes might be flags?
	 */
	offset = dissect_krb5_PAC_NDRHEADERBLOB(tree, tvb, offset, &drep[0], actx);

	/* the PAC_DEVICE_INFO blob */
	init_ndr_pointer_list(&di);
	offset = dissect_ndr_pointer(tvb, offset, actx->pinfo, tree, &di, drep,
				     netlogon_dissect_PAC_DEVICE_INFO, NDR_POINTER_UNIQUE,
				     "PAC_DEVICE_INFO:", -1);
	free_ndr_pointer_list(&di);

#ifdef HAVE_KERBEROS
	if (private_data->current_ticket_key != NULL) {
		enc_key_t *ek = private_data->current_ticket_key;

		/*
		 * netlogon_dissect_PAC_DEVICE_INFO allocated on
		 * wmem_epan_scope() for us
		 */
		ek->pac_names.device_sid = device_sid;
	}
#endif /* HAVE_KERBEROS */

	return offset;
}

static int
dissect_krb5_PAC_DEVICE_CLAIMS_INFO(proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	int length = tvb_captured_length_remaining(tvb, offset);

	if (length == 0) {
		return offset;
	}

	proto_tree_add_item(parent_tree, hf_krb_pac_device_claims_info, tvb, offset, -1, ENC_NA);

	return offset;
}

static int
dissect_krb5_PAC_SERVER_CHECKSUM(proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	proto_item *item;
	proto_tree *tree;

	item = proto_tree_add_item(parent_tree, hf_krb_pac_server_checksum, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_krb_pac_server_checksum);

	/* signature type */
	proto_tree_add_item(tree, hf_krb_pac_signature_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;

	/* signature data */
	proto_tree_add_item(tree, hf_krb_pac_signature_signature, tvb, offset, -1, ENC_NA);

	return offset;
}

static int
dissect_krb5_PAC_PRIVSVR_CHECKSUM(proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	proto_item *item;
	proto_tree *tree;

	item = proto_tree_add_item(parent_tree, hf_krb_pac_privsvr_checksum, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_krb_pac_privsvr_checksum);

	/* signature type */
	proto_tree_add_item(tree, hf_krb_pac_signature_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;

	/* signature data */
	proto_tree_add_item(tree, hf_krb_pac_signature_signature, tvb, offset, -1, ENC_NA);

	return offset;
}

static int
dissect_krb5_PAC_CLIENT_INFO_TYPE(proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	proto_item *item;
	proto_tree *tree;
	uint16_t namelen;

	item = proto_tree_add_item(parent_tree, hf_krb_pac_client_info_type, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_krb_pac_client_info_type);

	/* clientid */
	offset = dissect_nt_64bit_time(tvb, tree, offset, hf_krb_pac_clientid);

	/* name length */
	namelen=tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_krb_pac_namelen, tvb, offset, 2, namelen);
	offset+=2;

	/* client name */
	proto_tree_add_item(tree, hf_krb_pac_clientname, tvb, offset, namelen, ENC_UTF_16|ENC_LITTLE_ENDIAN);
	offset+=namelen;

	return offset;
}

static int
dissect_krb5_PAC_TICKET_CHECKSUM(proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	proto_item *item;
	proto_tree *tree;

	item = proto_tree_add_item(parent_tree, hf_krb_pac_ticket_checksum, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_krb_pac_ticket_checksum);

	/* signature type */
	proto_tree_add_item(tree, hf_krb_pac_signature_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;

	/* signature data */
	proto_tree_add_item(tree, hf_krb_pac_signature_signature, tvb, offset, -1, ENC_NA);

	return offset;
}

#define PAC_ATTRIBUTE_FLAG_PAC_WAS_REQUESTED		0x00000001
#define PAC_ATTRIBUTE_FLAG_PAC_WAS_GIVEN_IMPLICITLY	0x00000002
static const true_false_string tfs_krb_pac_attributes_info_pac_was_requested = {
	"PAC was requested",
	"PAC was NOT requested",
};
static const true_false_string tfs_krb_pac_attributes_info_pac_was_given_implicitly = {
	"PAC was given implicitly",
	"PAC was NOT given implicitly",
};
static int * const hf_krb_pac_attributes_info_flags_fields[] = {
	&hf_krb_pac_attributes_info_flags_pac_was_requested,
	&hf_krb_pac_attributes_info_flags_pac_was_given_implicitly,
	NULL
};

static int
dissect_krb5_PAC_ATTRIBUTES_INFO(proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	proto_item *item;
	proto_tree *tree;

	item = proto_tree_add_item(parent_tree, hf_krb_pac_attributes_info, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_krb_pac_attributes_info);

	/* flags length*/
	proto_tree_add_item(tree, hf_krb_pac_attributes_info_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;

	/* flags */
	proto_tree_add_bitmask(tree, tvb, offset,
			       hf_krb_pac_attributes_info_flags,
			       ett_krb_pac_attributes_info_flags,
			       hf_krb_pac_attributes_info_flags_fields,
			       ENC_LITTLE_ENDIAN);
	offset+=4;

	return offset;
}

static int
dissect_krb5_PAC_REQUESTER_SID(proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	proto_item *item;
	proto_tree *tree;

	item = proto_tree_add_item(parent_tree, hf_krb_pac_requester_sid, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_krb_pac_requester_sid);

	offset = dissect_nt_sid(tvb, offset, tree, "RequesterSid", NULL, -1);

	return offset;
}

static int
dissect_krb5_PAC_FULL_CHECKSUM(proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	proto_item *item;
	proto_tree *tree;

	item = proto_tree_add_item(parent_tree, hf_krb_pac_full_checksum, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_krb_pac_full_checksum);

	/* signature type */
	proto_tree_add_item(tree, hf_krb_pac_signature_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;

	/* signature data */
	proto_tree_add_item(tree, hf_krb_pac_signature_signature, tvb, offset, -1, ENC_NA);

	return offset;
}

static int
dissect_krb5_AD_WIN2K_PAC_struct(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx)
{
	uint32_t pac_type;
	uint32_t pac_size;
	uint32_t pac_offset;
	proto_item *it=NULL;
	proto_tree *tr=NULL;
	tvbuff_t *next_tvb;

	/* type of pac data */
	pac_type=tvb_get_letohl(tvb, offset);
	it=proto_tree_add_uint(tree, hf_krb_w2k_pac_type, tvb, offset, 4, pac_type);
	tr=proto_item_add_subtree(it, ett_krb_pac);

	offset += 4;

	/* size of pac data */
	pac_size=tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tr, hf_krb_w2k_pac_size, tvb, offset, 4, pac_size);
	offset += 4;

	/* offset to pac data */
	pac_offset=tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tr, hf_krb_w2k_pac_offset, tvb, offset, 4, pac_offset);
	offset += 8;

	next_tvb=tvb_new_subset_length_caplen(tvb, pac_offset, pac_size, pac_size);
	switch(pac_type){
	case PAC_LOGON_INFO:
		dissect_krb5_PAC_LOGON_INFO(tr, next_tvb, 0, actx);
		break;
	case PAC_CREDENTIAL_TYPE:
		dissect_krb5_PAC_CREDENTIAL_INFO(tr, next_tvb, 0, actx);
		break;
	case PAC_SERVER_CHECKSUM:
		dissect_krb5_PAC_SERVER_CHECKSUM(tr, next_tvb, 0, actx);
		break;
	case PAC_PRIVSVR_CHECKSUM:
		dissect_krb5_PAC_PRIVSVR_CHECKSUM(tr, next_tvb, 0, actx);
		break;
	case PAC_CLIENT_INFO_TYPE:
		dissect_krb5_PAC_CLIENT_INFO_TYPE(tr, next_tvb, 0, actx);
		break;
	case PAC_S4U_DELEGATION_INFO:
		dissect_krb5_PAC_S4U_DELEGATION_INFO(tr, next_tvb, 0, actx);
		break;
	case PAC_UPN_DNS_INFO:
		dissect_krb5_PAC_UPN_DNS_INFO(tr, next_tvb, 0, actx);
		break;
	case PAC_CLIENT_CLAIMS_INFO:
		dissect_krb5_PAC_CLIENT_CLAIMS_INFO(tr, next_tvb, 0, actx);
		break;
	case PAC_DEVICE_INFO:
		dissect_krb5_PAC_DEVICE_INFO(tr, next_tvb, 0, actx);
		break;
	case PAC_DEVICE_CLAIMS_INFO:
		dissect_krb5_PAC_DEVICE_CLAIMS_INFO(tr, next_tvb, 0, actx);
		break;
	case PAC_TICKET_CHECKSUM:
		dissect_krb5_PAC_TICKET_CHECKSUM(tr, next_tvb, 0, actx);
		break;
	case PAC_ATTRIBUTES_INFO:
		dissect_krb5_PAC_ATTRIBUTES_INFO(tr, next_tvb, 0, actx);
		break;
	case PAC_REQUESTER_SID:
		dissect_krb5_PAC_REQUESTER_SID(tr, next_tvb, 0, actx);
		break;
	case PAC_FULL_CHECKSUM:
		dissect_krb5_PAC_FULL_CHECKSUM(tr, next_tvb, 0, actx);
		break;

	default:
		break;
	}
	return offset;
}

static int
dissect_krb5_AD_WIN2K_PAC(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_)
{
	uint32_t entries;
	uint32_t version;
	uint32_t i;

#if defined(HAVE_MIT_KERBEROS) && defined(HAVE_KRB5_PAC_VERIFY)
	verify_krb5_pac(tree, actx, tvb);
#endif

	/* first in the PAC structure comes the number of entries */
	entries=tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_krb_w2k_pac_entries, tvb, offset, 4, entries);
	offset += 4;

	/* second comes the version */
	version=tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_krb_w2k_pac_version, tvb, offset, 4, version);
	offset += 4;

	for(i=0;i<entries;i++){
		offset=dissect_krb5_AD_WIN2K_PAC_struct(tree, tvb, offset, actx);
	}

	return offset;
}

static int dissect_kerberos_T_e_data_octets(bool implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
	int8_t ber_class;
	bool pc;
	int32_t tag;
	int len_offset;
	uint32_t len;
	bool ind;
	int next_offset;

	/*
	 * dissect_ber_octet_string_wcb() always passes
	 * implicit_tag=false, offset=0 and hf_index=-1
	 */
	ws_assert(implicit_tag == false);
	ws_assert(offset == 0);
	ws_assert(hf_index <= 0);

	len_offset = get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
	if (ber_class != BER_CLASS_UNI || !pc || tag != BER_UNI_TAG_SEQUENCE) {
		goto unknown;
	}
	next_offset = get_ber_length(tvb, len_offset, &len, &ind);
	if (len < 1) {
		goto unknown;
	}
	get_ber_identifier(tvb, next_offset, &ber_class, &pc, &tag);
	if (ber_class == BER_CLASS_CON && pc && tag == 1) {
		return dissect_kerberos_PA_DATA(implicit_tag, tvb, offset, actx, tree, hf_index);
	}
	if (ber_class == BER_CLASS_UNI && pc && tag == BER_UNI_TAG_SEQUENCE) {
		return dissect_kerberos_T_rEP_SEQUENCE_OF_PA_DATA(implicit_tag, tvb, offset, actx, tree, hf_index);
	}
unknown:
	return tvb_reported_length_remaining(tvb, offset);
}

#include "packet-kerberos-fn.c"

#ifdef HAVE_KERBEROS
static const ber_sequence_t PA_ENC_TS_ENC_sequence[] = {
	{ &hf_krb_patimestamp, BER_CLASS_CON, 0, 0, dissect_kerberos_KerberosTime },
	{ &hf_krb_pausec     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_Microseconds },
	{ NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_PA_ENC_TS_ENC(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
									PA_ENC_TS_ENC_sequence, hf_index, ett_krb_pa_enc_ts_enc);
	return offset;
}

static int
dissect_kerberos_T_strengthen_key(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  int save_encryption_key_parent_hf_index = private_data->save_encryption_key_parent_hf_index;
  kerberos_key_save_fn saved_encryption_key_fn = private_data->save_encryption_key_fn;
  private_data->save_encryption_key_parent_hf_index = hf_kerberos_KrbFastResponse;
#ifdef HAVE_KERBEROS
  private_data->save_encryption_key_fn = save_KrbFastResponse_strengthen_key;
#endif
  offset = dissect_kerberos_EncryptionKey(implicit_tag, tvb, offset, actx, tree, hf_index);

  private_data->save_encryption_key_parent_hf_index = save_encryption_key_parent_hf_index;
  private_data->save_encryption_key_fn = saved_encryption_key_fn;
  return offset;
}

static const ber_sequence_t KrbFastFinished_sequence[] = {
  { &hf_kerberos_timestamp  , BER_CLASS_CON, 0, 0, dissect_kerberos_KerberosTime },
  { &hf_kerberos_usec       , BER_CLASS_CON, 1, 0, dissect_kerberos_Microseconds },
  { &hf_kerberos_crealm     , BER_CLASS_CON, 2, 0, dissect_kerberos_Realm },
  { &hf_kerberos_cname_01   , BER_CLASS_CON, 3, 0, dissect_kerberos_PrincipalName },
  { &hf_kerberos_ticket_checksum, BER_CLASS_CON, 4, 0, dissect_kerberos_Checksum },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_KrbFastFinished(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KrbFastFinished_sequence, hf_index, ett_kerberos_KrbFastFinished);

  return offset;
}

static const ber_sequence_t KrbFastResponse_sequence[] = {
  { &hf_kerberos_rEP_SEQUENCE_OF_PA_DATA, BER_CLASS_CON, 0, 0, dissect_kerberos_T_rEP_SEQUENCE_OF_PA_DATA },
  { &hf_kerberos_strengthen_key, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_T_strengthen_key },
  { &hf_kerberos_finished   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_kerberos_KrbFastFinished },
  { &hf_kerberos_nonce      , BER_CLASS_CON, 3, 0, dissect_kerberos_UInt32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_KrbFastResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KrbFastResponse_sequence, hf_index, ett_kerberos_KrbFastResponse);

  return offset;
}

static const ber_sequence_t KrbFastReq_sequence[] = {
  { &hf_kerberos_fast_options, BER_CLASS_CON, 0, 0, dissect_kerberos_FastOptions },
  { &hf_kerberos_rEQ_SEQUENCE_OF_PA_DATA, BER_CLASS_CON, 1, 0, dissect_kerberos_T_rEQ_SEQUENCE_OF_PA_DATA },
  { &hf_kerberos_req_body   , BER_CLASS_CON, 2, 0, dissect_kerberos_KDC_REQ_BODY },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_KrbFastReq(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  struct _kerberos_PA_FX_FAST_REQUEST saved_stack = private_data->PA_FX_FAST_REQUEST;
  private_data->PA_FX_FAST_REQUEST = (struct _kerberos_PA_FX_FAST_REQUEST) { .defer = false, };
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KrbFastReq_sequence, hf_index, ett_kerberos_KrbFastReq);
  private_data->PA_FX_FAST_REQUEST = saved_stack;

  return offset;
}

static int * const FastOptions_bits[] = {
  &hf_kerberos_FastOptions_reserved,
  &hf_kerberos_FastOptions_hide_client_names,
  &hf_kerberos_FastOptions_spare_bit2,
  &hf_kerberos_FastOptions_spare_bit3,
  &hf_kerberos_FastOptions_spare_bit4,
  &hf_kerberos_FastOptions_spare_bit5,
  &hf_kerberos_FastOptions_spare_bit6,
  &hf_kerberos_FastOptions_spare_bit7,
  &hf_kerberos_FastOptions_spare_bit8,
  &hf_kerberos_FastOptions_spare_bit9,
  &hf_kerberos_FastOptions_spare_bit10,
  &hf_kerberos_FastOptions_spare_bit11,
  &hf_kerberos_FastOptions_spare_bit12,
  &hf_kerberos_FastOptions_spare_bit13,
  &hf_kerberos_FastOptions_spare_bit14,
  &hf_kerberos_FastOptions_spare_bit15,
  &hf_kerberos_FastOptions_kdc_follow_referrals,
  NULL
};

static int
dissect_kerberos_FastOptions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    FastOptions_bits, 17, hf_index, ett_kerberos_FastOptions,
                                    NULL);

  return offset;
}

#endif /* HAVE_KERBEROS */

/* Make wrappers around exported functions for now */
int
dissect_krb5_Checksum(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	return dissect_kerberos_Checksum(false, tvb, offset, actx, tree, hf_kerberos_cksum);

}

int
dissect_krb5_ctime(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	return dissect_kerberos_KerberosTime(false, tvb, offset, actx, tree, hf_kerberos_ctime);
}


int
dissect_krb5_cname(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	return dissect_kerberos_PrincipalName(false, tvb, offset, actx, tree, hf_kerberos_cname);
}
int
dissect_krb5_realm(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	return dissect_kerberos_Realm(false, tvb, offset, actx, tree, hf_kerberos_realm);
}

struct kerberos_display_key_state {
	proto_tree *tree;
	packet_info *pinfo;
	expert_field *expindex;
	const char *name;
	tvbuff_t *tvb;
	int start;
	int length;
};

static void
#ifdef HAVE_KERBEROS
kerberos_display_key(void *data, void *userdata)
#else
kerberos_display_key(void *data _U_, void *userdata _U_)
#endif
{
#ifdef HAVE_KERBEROS
	struct kerberos_display_key_state *state =
		(struct kerberos_display_key_state *)userdata;
	const enc_key_t *ek = (const enc_key_t *)data;
	proto_item *item = NULL;
	enc_key_t *sek = NULL;

	item = proto_tree_add_expert_format(state->tree,
					    state->pinfo,
					    state->expindex,
					    state->tvb,
					    state->start,
					    state->length,
					    "%s %s keytype %d (id=%s same=%u) (%02x%02x%02x%02x...)",
					    state->name,
					    ek->key_origin, ek->keytype,
					    ek->id_str, ek->num_same,
					    ek->keyvalue[0] & 0xFF, ek->keyvalue[1] & 0xFF,
					    ek->keyvalue[2] & 0xFF, ek->keyvalue[3] & 0xFF);
	if (ek->src1 != NULL) {
		sek = ek->src1;
		expert_add_info_format(state->pinfo,
				       item,
				       state->expindex,
				       "SRC1 %s keytype %d (id=%s same=%u) (%02x%02x%02x%02x...)",
				       sek->key_origin, sek->keytype,
				       sek->id_str, sek->num_same,
				       sek->keyvalue[0] & 0xFF, sek->keyvalue[1] & 0xFF,
				       sek->keyvalue[2] & 0xFF, sek->keyvalue[3] & 0xFF);
	}
	if (ek->src2 != NULL) {
		sek = ek->src2;
		expert_add_info_format(state->pinfo,
				       item,
				       state->expindex,
				       "SRC2 %s keytype %d (id=%s same=%u) (%02x%02x%02x%02x...)",
				       sek->key_origin, sek->keytype,
				       sek->id_str, sek->num_same,
				       sek->keyvalue[0] & 0xFF, sek->keyvalue[1] & 0xFF,
				       sek->keyvalue[2] & 0xFF, sek->keyvalue[3] & 0xFF);
	}
	sek = ek->same_list;
	while (sek != NULL) {
		expert_add_info_format(state->pinfo,
				       item,
				       state->expindex,
				       "%s %s keytype %d (id=%s same=%u) (%02x%02x%02x%02x...)",
				       state->name,
				       sek->key_origin, sek->keytype,
				       sek->id_str, sek->num_same,
				       sek->keyvalue[0] & 0xFF, sek->keyvalue[1] & 0xFF,
				       sek->keyvalue[2] & 0xFF, sek->keyvalue[3] & 0xFF);
		sek = sek->same_list;
	}
#endif /* HAVE_KERBEROS */
}

static const value_string KERB_LOGON_SUBMIT_TYPE[] = {
    { 2, "KerbInteractiveLogon" },
    { 6, "KerbSmartCardLogon" },
    { 7, "KerbWorkstationUnlockLogon" },
    { 8, "KerbSmartCardUnlockLogon" },
    { 9, "KerbProxyLogon" },
    { 10, "KerbTicketLogon" },
    { 11, "KerbTicketUnlockLogon" },
    { 12, "KerbS4ULogon" },
    { 13, "KerbCertificateLogon" },
    { 14, "KerbCertificateS4ULogon" },
    { 15, "KerbCertificateUnlockLogon" },
    { 0, NULL }
};


#define KERB_LOGON_FLAG_ALLOW_EXPIRED_TICKET 0x1
#define KERB_LOGON_FLAG_REDIRECTED           0x2

static int* const ktl_flags_bits[] = {
	&hf_kerberos_KERB_TICKET_LOGON_FLAG_ALLOW_EXPIRED_TICKET,
	&hf_kerberos_KERB_TICKET_LOGON_FLAG_REDIRECTED,
	NULL
};

int
dissect_kerberos_KERB_TICKET_LOGON(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree)
{
	proto_item *item;
	proto_tree *subtree;
	uint32_t ServiceTicketLength;
	uint32_t TicketGrantingTicketLength;
	int orig_offset;

	if (tvb_captured_length(tvb) < 32)
		return offset;

	item = proto_tree_add_item(tree, hf_kerberos_KERB_TICKET_LOGON, tvb, offset, -1, ENC_NA);
	subtree = proto_item_add_subtree(item, ett_kerberos_KERB_TICKET_LOGON);

	proto_tree_add_item(subtree, hf_kerberos_KERB_TICKET_LOGON_MessageType, tvb, offset, 4,
			    ENC_LITTLE_ENDIAN);
	offset+=4;

	proto_tree_add_bitmask(subtree, tvb, offset, hf_kerberos_KERB_TICKET_LOGON_Flags,
			       ett_kerberos, ktl_flags_bits, ENC_LITTLE_ENDIAN);
	offset+=4;

	ServiceTicketLength = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(subtree, hf_kerberos_KERB_TICKET_LOGON_ServiceTicketLength, tvb,
			    offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;

	TicketGrantingTicketLength = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(subtree, hf_kerberos_KERB_TICKET_LOGON_TicketGrantingTicketLength,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset+=4;

	/* Skip two PUCHAR of ServiceTicket and TicketGrantingTicket */
	offset+=16;

	if (ServiceTicketLength == 0)
		return offset;

	orig_offset = offset;
	offset = dissect_kerberos_Ticket(false, tvb, offset, actx, subtree,
					 hf_kerberos_KERB_TICKET_LOGON_ServiceTicket);

	if ((unsigned)(offset-orig_offset) != ServiceTicketLength)
		return offset;

	if (TicketGrantingTicketLength == 0)
		return offset;

	offset = dissect_kerberos_KRB_CRED(false, tvb, offset, actx, subtree,
					   hf_kerberos_KERB_TICKET_LOGON_TicketGrantingTicket);

	if ((unsigned)(offset-orig_offset) != ServiceTicketLength + TicketGrantingTicketLength)
		return offset;

	return offset;
}

static int
dissect_kerberos_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    bool dci, bool do_col_protocol, bool have_rm,
    kerberos_callbacks *cb)
{
	volatile int offset = 0;
	proto_tree *volatile kerberos_tree = NULL;
	proto_item *volatile item = NULL;
	kerberos_private_data_t *private_data = NULL;
	asn1_ctx_t asn1_ctx;

	/* TCP record mark and length */
	uint32_t krb_rm = 0;
	int krb_reclen = 0;

	gbl_do_col_info=dci;

	if (have_rm) {
		krb_rm = tvb_get_ntohl(tvb, offset);
		krb_reclen = kerberos_rm_to_reclen(krb_rm);
		/*
		 * What is a reasonable size limit?
		 */
		if (krb_reclen > 10 * 1024 * 1024) {
			return (-1);
		}

		if (do_col_protocol) {
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "KRB5");
		}

		if (tree) {
			item = proto_tree_add_item(tree, proto_kerberos, tvb, 0, -1, ENC_NA);
			kerberos_tree = proto_item_add_subtree(item, ett_kerberos);
		}

		show_krb_recordmark(kerberos_tree, tvb, offset, krb_rm);
		offset += 4;
	} else {
		/* Do some sanity checking here,
		 * All krb5 packets start with a TAG class that is BER_CLASS_APP
		 * and a tag value that is either of the values below:
		 * If it doesn't look like kerberos, return 0 and let someone else have
		 * a go at it.
		 */
		int8_t tmp_class;
		bool tmp_pc;
		int32_t tmp_tag;

		get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);
		if(tmp_class!=BER_CLASS_APP){
			return 0;
		}
		switch(tmp_tag){
			case KRB5_MSG_TICKET:
			case KRB5_MSG_AUTHENTICATOR:
			case KRB5_MSG_ENC_TICKET_PART:
			case KRB5_MSG_AS_REQ:
			case KRB5_MSG_AS_REP:
			case KRB5_MSG_TGS_REQ:
			case KRB5_MSG_TGS_REP:
			case KRB5_MSG_AP_REQ:
			case KRB5_MSG_AP_REP:
			case KRB5_MSG_ENC_AS_REP_PART:
			case KRB5_MSG_ENC_TGS_REP_PART:
			case KRB5_MSG_ENC_AP_REP_PART:
			case KRB5_MSG_ENC_KRB_PRIV_PART:
			case KRB5_MSG_ENC_KRB_CRED_PART:
			case KRB5_MSG_SAFE:
			case KRB5_MSG_PRIV:
			case KRB5_MSG_ERROR:
				break;
			default:
				return 0;
		}
		if (do_col_protocol) {
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "KRB5");
		}
		if (gbl_do_col_info) {
			col_clear(pinfo->cinfo, COL_INFO);
		}
		if (tree) {
			item = proto_tree_add_item(tree, proto_kerberos, tvb, 0, -1, ENC_NA);
			kerberos_tree = proto_item_add_subtree(item, ett_kerberos);
		}
	}
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
	asn1_ctx.private_data = NULL;
	private_data = kerberos_get_private_data(&asn1_ctx);
	private_data->callbacks = cb;

	TRY {
		offset=dissect_kerberos_Applications(false, tvb, offset, &asn1_ctx , kerberos_tree, /* hf_index */ -1);
	} CATCH_BOUNDS_ERRORS {
		RETHROW;
	} ENDTRY;

	if (private_data->frame_rep != UINT32_MAX) {
		proto_item *tmp_item;

		tmp_item = proto_tree_add_uint(kerberos_tree, hf_krb_response_in, tvb, 0, 0, private_data->frame_rep);
		proto_item_set_generated(tmp_item);
	}

	if (private_data->frame_req != UINT32_MAX) {
		proto_item *tmp_item;
		nstime_t    t, deltat;

		tmp_item = proto_tree_add_uint(kerberos_tree, hf_krb_response_to, tvb, 0, 0, private_data->frame_req);
		proto_item_set_generated(tmp_item);

		t = pinfo->abs_ts;
		nstime_delta(&deltat, &t, &private_data->req_time);
		tmp_item = proto_tree_add_time(kerberos_tree, hf_krb_time, tvb, 0, 0, &deltat);
		proto_item_set_generated(tmp_item);
	}

	if (kerberos_tree != NULL) {
		struct kerberos_display_key_state display_state = {
			.tree = kerberos_tree,
			.pinfo = pinfo,
			.expindex = &ei_kerberos_learnt_keytype,
			.name = "Provides",
			.tvb = tvb,
		};

		wmem_list_foreach(private_data->learnt_keys,
				  kerberos_display_key,
				  &display_state);
	}

	if (kerberos_tree != NULL) {
		struct kerberos_display_key_state display_state = {
			.tree = kerberos_tree,
			.pinfo = pinfo,
			.expindex = &ei_kerberos_missing_keytype,
			.name = "Missing",
			.tvb = tvb,
		};

		wmem_list_foreach(private_data->missing_keys,
				  kerberos_display_key,
				  &display_state);
	}

	if (kerberos_tree != NULL) {
		struct kerberos_display_key_state display_state = {
			.tree = kerberos_tree,
			.pinfo = pinfo,
			.expindex = &ei_kerberos_decrypted_keytype,
			.name = "Used",
			.tvb = tvb,
		};

		wmem_list_foreach(private_data->decryption_keys,
				  kerberos_display_key,
				  &display_state);
	}

	proto_item_set_len(item, offset);
	return offset;
}

/*
 * Display the TCP record mark.
 */
void
show_krb_recordmark(proto_tree *tree, tvbuff_t *tvb, int start, uint32_t krb_rm)
{
	int rec_len;
	proto_tree *rm_tree;

	if (tree == NULL)
		return;

	rec_len = kerberos_rm_to_reclen(krb_rm);
	rm_tree = proto_tree_add_subtree_format(tree, tvb, start, 4, ett_krb_recordmark, NULL,
		"Record Mark: %u %s", rec_len, plurality(rec_len, "byte", "bytes"));
	proto_tree_add_boolean(rm_tree, hf_krb_rm_reserved, tvb, start, 4, krb_rm);
	proto_tree_add_uint(rm_tree, hf_krb_rm_reclen, tvb, start, 4, krb_rm);
}

int
dissect_kerberos_main(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bool do_col_info, kerberos_callbacks *cb)
{
	return (dissect_kerberos_common(tvb, pinfo, tree, do_col_info, false, false, cb));
}

uint32_t
kerberos_output_keytype(void)
{
	return gbl_keytype;
}

static int
dissect_kerberos_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	/* Some weird kerberos implementation apparently do krb4 on the krb5 port.
	   Since all (except weirdo transarc krb4 stuff) use
	   an opcode <=16 in the first byte, use this to see if it might
	   be krb4.
	   All krb5 commands start with an APPL tag and thus is >=0x60
	   so if first byte is <=16  just blindly assume it is krb4 then
	*/
	if(tvb_captured_length(tvb) >= 1 && tvb_get_uint8(tvb, 0)<=0x10){
		if(krb4_handle){
			bool res;

			res=call_dissector_only(krb4_handle, tvb, pinfo, tree, NULL);
			return res;
		}else{
			return 0;
		}
	}


	return dissect_kerberos_common(tvb, pinfo, tree, true, true, false, NULL);
}

int
kerberos_rm_to_reclen(unsigned krb_rm)
{
    return (krb_rm & KRB_RM_RECLEN);
}

unsigned
get_krb_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	unsigned krb_rm;
	int pdulen;

	krb_rm = tvb_get_ntohl(tvb, offset);
	pdulen = kerberos_rm_to_reclen(krb_rm);
	return (pdulen + 4);
}
static void
kerberos_prefs_apply_cb(void) {
#ifdef HAVE_LIBNETTLE
	clear_keytab();
	read_keytab_file(keytab_filename);
#endif
}

static int
dissect_kerberos_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	pinfo->fragmented = true;
	if (dissect_kerberos_common(tvb, pinfo, tree, true, true, true, NULL) < 0) {
		/*
		 * The dissector failed to recognize this as a valid
		 * Kerberos message.  Mark it as a continuation packet.
		 */
		col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
	}

	return tvb_captured_length(tvb);
}

static int
dissect_kerberos_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "KRB5");
	col_clear(pinfo->cinfo, COL_INFO);

	tcp_dissect_pdus(tvb, pinfo, tree, krb_desegment, 4, get_krb_pdu_len,
					 dissect_kerberos_tcp_pdu, data);
	return tvb_captured_length(tvb);
}

/*--- proto_register_kerberos -------------------------------------------*/
void proto_register_kerberos(void) {

	/* List of fields */

	static hf_register_info hf[] = {
	{ &hf_krb_response_to,
		{ "Response to", "kerberos.response_to", FT_FRAMENUM, BASE_NONE,
		FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0, "This packet is a response to the packet in this frame", HFILL }},
	{ &hf_krb_response_in,
		{ "Response in", "kerberos.response_in", FT_FRAMENUM, BASE_NONE,
		FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0, "The response to this packet is in this packet", HFILL }},
	{ &hf_krb_time,
		{ "Time from request", "kerberos.time", FT_RELATIVE_TIME, BASE_NONE,
		NULL, 0, "Time between Request and Response for Kerberos KDC requests", HFILL }},
	{ &hf_krb_rm_reserved, {
		"Reserved", "kerberos.rm.reserved", FT_BOOLEAN, 32,
		TFS(&tfs_set_notset), KRB_RM_RESERVED, "Record mark reserved bit", HFILL }},
	{ &hf_krb_rm_reclen, {
		"Record Length", "kerberos.rm.length", FT_UINT32, BASE_DEC,
		NULL, KRB_RM_RECLEN, NULL, HFILL }},
	{ &hf_krb_provsrv_location, {
		"PROVSRV Location", "kerberos.provsrv_location", FT_STRING, BASE_NONE,
		NULL, 0, "PacketCable PROV SRV Location", HFILL }},
	{ &hf_krb_pw_salt,
		{ "pw-salt", "kerberos.pw_salt", FT_BYTES, BASE_NONE,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_ext_error_nt_status, /* we keep kerberos.smb.nt_status for compat reasons */
		{ "NT Status", "kerberos.smb.nt_status", FT_UINT32, BASE_HEX|BASE_EXT_STRING,
		&NT_errors_ext, 0, "NT Status code", HFILL }},
	{ &hf_krb_ext_error_reserved,
		{ "Reserved", "kerberos.ext_error.reserved", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_ext_error_flags,
		{ "Flags", "kerberos.ext_error.flags", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_address_ip, {
		"IP Address", "kerberos.addr_ip", FT_IPv4, BASE_NONE,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_address_ipv6, {
		"IPv6 Address", "kerberos.addr_ipv6", FT_IPv6, BASE_NONE,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_address_netbios, {
		"NetBIOS Address", "kerberos.addr_nb", FT_STRING, BASE_NONE,
		NULL, 0, "NetBIOS Address and type", HFILL }},
	{ &hf_krb_gssapi_len, {
		"Length", "kerberos.gssapi.len", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of GSSAPI Bnd field", HFILL }},
	{ &hf_krb_gssapi_bnd, {
		"Bnd", "kerberos.gssapi.bdn", FT_BYTES, BASE_NONE,
		NULL, 0, "GSSAPI Bnd field", HFILL }},
	{ &hf_krb_gssapi_c_flag_deleg, {
		"Deleg", "kerberos.gssapi.checksum.flags.deleg", FT_BOOLEAN, 32,
		TFS(&tfs_gss_flags_deleg), KRB5_GSS_C_DELEG_FLAG, NULL, HFILL }},
	{ &hf_krb_gssapi_c_flag_mutual, {
		"Mutual", "kerberos.gssapi.checksum.flags.mutual", FT_BOOLEAN, 32,
		TFS(&tfs_gss_flags_mutual), KRB5_GSS_C_MUTUAL_FLAG, NULL, HFILL }},
	{ &hf_krb_gssapi_c_flag_replay, {
		"Replay", "kerberos.gssapi.checksum.flags.replay", FT_BOOLEAN, 32,
		TFS(&tfs_gss_flags_replay), KRB5_GSS_C_REPLAY_FLAG, NULL, HFILL }},
	{ &hf_krb_gssapi_c_flag_sequence, {
		"Sequence", "kerberos.gssapi.checksum.flags.sequence", FT_BOOLEAN, 32,
		TFS(&tfs_gss_flags_sequence), KRB5_GSS_C_SEQUENCE_FLAG, NULL, HFILL }},
	{ &hf_krb_gssapi_c_flag_conf, {
		"Conf", "kerberos.gssapi.checksum.flags.conf", FT_BOOLEAN, 32,
		TFS(&tfs_gss_flags_conf), KRB5_GSS_C_CONF_FLAG, NULL, HFILL }},
	{ &hf_krb_gssapi_c_flag_integ, {
		"Integ", "kerberos.gssapi.checksum.flags.integ", FT_BOOLEAN, 32,
		TFS(&tfs_gss_flags_integ), KRB5_GSS_C_INTEG_FLAG, NULL, HFILL }},
	{ &hf_krb_gssapi_c_flag_dce_style, {
		"DCE-style", "kerberos.gssapi.checksum.flags.dce-style", FT_BOOLEAN, 32,
		TFS(&tfs_gss_flags_dce_style), KRB5_GSS_C_DCE_STYLE, NULL, HFILL }},
	{ &hf_krb_gssapi_dlgopt, {
		"DlgOpt", "kerberos.gssapi.dlgopt", FT_UINT16, BASE_DEC,
		NULL, 0, "GSSAPI DlgOpt", HFILL }},
	{ &hf_krb_gssapi_dlglen, {
		"DlgLen", "kerberos.gssapi.dlglen", FT_UINT16, BASE_DEC,
		NULL, 0, "GSSAPI DlgLen", HFILL }},
	{ &hf_krb_midl_blob_len, {
		"Blob Length", "kerberos.midl_blob_len", FT_UINT64, BASE_DEC,
		NULL, 0, "Length of NDR encoded data that follows", HFILL }},
	{ &hf_krb_midl_fill_bytes, {
		"Fill bytes", "kerberos.midl.fill_bytes", FT_UINT32, BASE_HEX,
		NULL, 0, "Just some fill bytes", HFILL }},
	{ &hf_krb_midl_version, {
	"Version", "kerberos.midl.version", FT_UINT8, BASE_DEC,
	NULL, 0, "Version of pickling", HFILL }},
	{ &hf_krb_midl_hdr_len, {
		"HDR Length", "kerberos.midl.hdr_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Length of header", HFILL }},
	{ &hf_krb_pac_signature_type, {
		"Type", "kerberos.pac.signature.type", FT_INT32, BASE_DEC,
		NULL, 0, "PAC Signature Type", HFILL }},
	{ &hf_krb_pac_signature_signature, {
		"Signature", "kerberos.pac.signature.signature", FT_BYTES, BASE_NONE,
		NULL, 0, "A PAC signature blob", HFILL }},
	{ &hf_krb_w2k_pac_entries, {
		"Num Entries", "kerberos.pac.entries", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of W2k PAC entries", HFILL }},
	{ &hf_krb_w2k_pac_version, {
		"Version", "kerberos.pac.version", FT_UINT32, BASE_DEC,
		NULL, 0, "Version of PAC structures", HFILL }},
	{ &hf_krb_w2k_pac_type, {
		"Type", "kerberos.pac.type", FT_UINT32, BASE_DEC,
		VALS(w2k_pac_types), 0, "Type of W2k PAC entry", HFILL }},
	{ &hf_krb_w2k_pac_size, {
		"Size", "kerberos.pac.size", FT_UINT32, BASE_DEC,
		NULL, 0, "Size of W2k PAC entry", HFILL }},
	{ &hf_krb_w2k_pac_offset, {
		"Offset", "kerberos.pac.offset", FT_UINT32, BASE_DEC,
		NULL, 0, "Offset to W2k PAC entry", HFILL }},
	{ &hf_krb_pac_clientid, {
		"ClientID", "kerberos.pac.clientid", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
		NULL, 0, "ClientID Timestamp", HFILL }},
	{ &hf_krb_pac_namelen, {
		"Name Length", "kerberos.pac.namelen", FT_UINT16, BASE_DEC,
		NULL, 0, "Length of client name", HFILL }},
	{ &hf_krb_pac_clientname, {
		"Name", "kerberos.pac.name", FT_STRING, BASE_NONE,
		NULL, 0, "Name of the Client in the PAC structure", HFILL }},
	{ &hf_krb_pac_logon_info, {
		"PAC_LOGON_INFO", "kerberos.pac_logon_info", FT_BYTES, BASE_NONE,
		NULL, 0, "PAC_LOGON_INFO structure", HFILL }},
	{ &hf_krb_pac_credential_data, {
		"PAC_CREDENTIAL_DATA", "kerberos.pac_credential_data", FT_BYTES, BASE_NONE,
		NULL, 0, "PAC_CREDENTIAL_DATA structure", HFILL }},
	{ &hf_krb_pac_credential_info, {
		"PAC_CREDENTIAL_INFO", "kerberos.pac_credential_info", FT_BYTES, BASE_NONE,
		NULL, 0, "PAC_CREDENTIAL_INFO structure", HFILL }},
	{ &hf_krb_pac_credential_info_version, {
		"Version", "kerberos.pac_credential_info.version", FT_UINT32, BASE_DEC,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_credential_info_etype, {
		"Etype", "kerberos.pac_credential_info.etype", FT_UINT32, BASE_DEC,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_server_checksum, {
		"PAC_SERVER_CHECKSUM", "kerberos.pac_server_checksum", FT_BYTES, BASE_NONE,
		NULL, 0, "PAC_SERVER_CHECKSUM structure", HFILL }},
	{ &hf_krb_pac_privsvr_checksum, {
		"PAC_PRIVSVR_CHECKSUM", "kerberos.pac_privsvr_checksum", FT_BYTES, BASE_NONE,
		NULL, 0, "PAC_PRIVSVR_CHECKSUM structure", HFILL }},
	{ &hf_krb_pac_client_info_type, {
		"PAC_CLIENT_INFO_TYPE", "kerberos.pac_client_info_type", FT_BYTES, BASE_NONE,
		NULL, 0, "PAC_CLIENT_INFO_TYPE structure", HFILL }},
	{ &hf_krb_pac_s4u_delegation_info, {
		"PAC_S4U_DELEGATION_INFO", "kerberos.pac_s4u_delegation_info", FT_BYTES, BASE_NONE,
		NULL, 0, "PAC_S4U_DELEGATION_INFO structure", HFILL }},
	{ &hf_krb_pac_upn_dns_info, {
		"UPN_DNS_INFO", "kerberos.pac_upn_dns_info", FT_BYTES, BASE_NONE,
		NULL, 0, "UPN_DNS_INFO structure", HFILL }},
	{ &hf_krb_pac_upn_flags, {
		"Flags", "kerberos.pac.upn.flags", FT_UINT32, BASE_HEX,
		NULL, 0, "UPN flags", HFILL }},
	{ &hf_krb_pac_upn_flag_upn_constructed, {
		"UPN Name Constructed",
		"kerberos.pac.upn.flags.upn_constructed",
		FT_BOOLEAN, 32,
		TFS(&tfs_krb_pac_upn_flag_upn_constructed),
		PAC_UPN_DNS_FLAG_CONSTRUCTED,
		"Is the UPN Name constructed?", HFILL }},
	{ &hf_krb_pac_upn_flag_has_sam_name_and_sid, {
		"SAM_NAME and SID Included",
		"kerberos.pac.upn.flags.has_sam_name_and_sid",
		FT_BOOLEAN, 32,
		TFS(&tfs_krb_pac_upn_flag_has_sam_name_and_sid),
		PAC_UPN_DNS_FLAG_HAS_SAM_NAME_AND_SID,
		"Are SAM_NAME and SID included?", HFILL }},
	{ &hf_krb_pac_upn_upn_offset, {
		"UPN Offset", "kerberos.pac.upn.upn_offset", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_upn_upn_len, {
		"UPN Len", "kerberos.pac.upn.upn_len", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_upn_upn_name, {
		"UPN Name", "kerberos.pac.upn.upn_name", FT_STRING, BASE_NONE,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_upn_dns_offset, {
		"DNS Offset", "kerberos.pac.upn.dns_offset", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_upn_dns_len, {
		"DNS Len", "kerberos.pac.upn.dns_len", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_upn_dns_name, {
		"DNS Name", "kerberos.pac.upn.dns_name", FT_STRING, BASE_NONE,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_upn_samaccountname_offset, {
		"sAMAccountName Offset", "kerberos.pac.upn.samaccountname_offset", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_upn_samaccountname_len, {
		"sAMAccountName Len", "kerberos.pac.upn.samaccountname_len", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_upn_samaccountname, {
		"sAMAccountName", "kerberos.pac.upn.samaccountname", FT_STRING, BASE_NONE,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_upn_objectsid_offset, {
		"objectSid Offset", "kerberos.pac.upn.objectsid_offset", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_upn_objectsid_len, {
		"objectSid Len", "kerberos.pac.upn.objectsid_len", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_client_claims_info, {
		"PAC_CLIENT_CLAIMS_INFO", "kerberos.pac_client_claims_info", FT_BYTES, BASE_NONE,
		NULL, 0, "PAC_CLIENT_CLAIMS_INFO structure", HFILL }},
	{ &hf_krb_pac_device_info, {
		"PAC_DEVICE_INFO", "kerberos.pac_device_info", FT_BYTES, BASE_NONE,
		NULL, 0, "PAC_DEVICE_INFO structure", HFILL }},
	{ &hf_krb_pac_device_claims_info, {
		"PAC_DEVICE_CLAIMS_INFO", "kerberos.pac_device_claims_info", FT_BYTES, BASE_NONE,
		NULL, 0, "PAC_DEVICE_CLAIMS_INFO structure", HFILL }},
	{ &hf_krb_pac_ticket_checksum, {
		"PAC_TICKET_CHECKSUM", "kerberos.pac_ticket_checksum", FT_BYTES, BASE_NONE,
		NULL, 0, "PAC_TICKET_CHECKSUM structure", HFILL }},
	{ &hf_krb_pac_attributes_info, {
		"PAC_ATTRIBUTES_INFO", "kerberos.pac_attributes_info", FT_BYTES, BASE_NONE,
		NULL, 0, "PAC_ATTRIBUTES_INFO structure", HFILL }},
	{ &hf_krb_pac_attributes_info_length, {
		"Flags Valid Length", "kerberos.pac.attributes_info.length", FT_UINT32, BASE_DEC,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_attributes_info_flags, {
		"Flags", "kerberos.pac.attributes_info.flags",
		FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_attributes_info_flags_pac_was_requested, {
		"PAC Requested",
		"kerberos.pac.attributes.flags.pac_was_requested",
		FT_BOOLEAN, 32,
		TFS(&tfs_krb_pac_attributes_info_pac_was_requested),
		PAC_ATTRIBUTE_FLAG_PAC_WAS_REQUESTED,
		"Was a PAC requested?", HFILL }},
	{ &hf_krb_pac_attributes_info_flags_pac_was_given_implicitly, {
		"PAC given Implicitly",
		"kerberos.pac.attributes.flags.pac_was_given_implicitly",
		FT_BOOLEAN, 32,
		TFS(&tfs_krb_pac_attributes_info_pac_was_given_implicitly),
		PAC_ATTRIBUTE_FLAG_PAC_WAS_GIVEN_IMPLICITLY,
		"Was PAC given implicitly?", HFILL }},
	{ &hf_krb_pac_requester_sid, {
		"PAC_REQUESTER_SID", "kerberos.pac_requester_sid", FT_BYTES, BASE_NONE,
		NULL, 0, "PAC_REQUESTER_SID structure", HFILL }},
	{ &hf_krb_pac_full_checksum, {
		"PAC_FULL_CHECKSUM", "kerberos.pac_full_checksum", FT_BYTES, BASE_NONE,
		NULL, 0, "PAC_FULL_CHECKSUM structure", HFILL }},
	{ &hf_krb_pa_supported_enctypes,
	  { "SupportedEnctypes", "kerberos.supported_entypes",
	    FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_krb_pa_supported_enctypes_des_cbc_crc,
	  { "des-cbc-crc", "kerberos.supported_entypes.des-cbc-crc",
		FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000001, NULL, HFILL }},
	{ &hf_krb_pa_supported_enctypes_des_cbc_md5,
	  { "des-cbc-md5", "kerberos.supported_entypes.des-cbc-md5",
		FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000002, NULL, HFILL }},
	{ &hf_krb_pa_supported_enctypes_rc4_hmac,
	  { "rc4-hmac", "kerberos.supported_entypes.rc4-hmac",
		FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000004, NULL, HFILL }},
	{ &hf_krb_pa_supported_enctypes_aes128_cts_hmac_sha1_96,
	  { "aes128-cts-hmac-sha1-96", "kerberos.supported_entypes.aes128-cts-hmac-sha1-96",
		FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000008, NULL, HFILL }},
	{ &hf_krb_pa_supported_enctypes_aes256_cts_hmac_sha1_96,
	  { "aes256-cts-hmac-sha1-96", "kerberos.supported_entypes.aes256-cts-hmac-sha1-96",
		FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000010, NULL, HFILL }},
	{ &hf_krb_pa_supported_enctypes_aes256_cts_hmac_sha1_96_sk,
	  { "aes256-cts-hmac-sha1-96-sk", "kerberos.supported_entypes.aes256-cts-hmac-sha1-96-sk",
		FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000020, NULL, HFILL }},
	{ &hf_krb_pa_supported_enctypes_fast_supported,
	  { "fast-supported", "kerberos.supported_entypes.fast-supported",
		FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00010000, NULL, HFILL }},
	{ &hf_krb_pa_supported_enctypes_compound_identity_supported,
	  { "compound-identity-supported", "kerberos.supported_entypes.compound-identity-supported",
		FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00020000, NULL, HFILL }},
	{ &hf_krb_pa_supported_enctypes_claims_supported,
	  { "claims-supported", "kerberos.supported_entypes.claims-supported",
		FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00040000, NULL, HFILL }},
	{ &hf_krb_pa_supported_enctypes_resource_sid_compression_disabled,
	  { "resource-sid-compression-disabled", "kerberos.supported_entypes.resource-sid-compression-disabled",
		FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00080000, NULL, HFILL }},
	{ &hf_krb_ad_ap_options,
	  { "AD-AP-Options", "kerberos.ad_ap_options",
	    FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }},
	{ &hf_krb_ad_ap_options_cbt,
	  { "ChannelBindings", "kerberos.ad_ap_options.cbt",
		FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00004000, NULL, HFILL }},
	{ &hf_krb_ad_ap_options_unverified_target_name,
	  { "UnverifiedTargetName", "kerberos.ad_ap_options.unverified_target_name",
		FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00008000, NULL, HFILL }},
	{ &hf_krb_ad_target_principal,
	  { "Target Principal", "kerberos.ad_target_principal",
	    FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_krb_key_hidden_item,
	  { "KeyHiddenItem", "krb5.key_hidden_item",
	    FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_kerberos_KERB_TICKET_LOGON,
      { "KERB_TICKET_LOGON", "kerberos.KERB_TICKET_LOGON",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_KERB_TICKET_LOGON_MessageType,
      { "MessageType", "kerberos.KERB_TICKET_LOGON.MessageType",
        FT_UINT32, BASE_DEC, VALS(KERB_LOGON_SUBMIT_TYPE), 0,
        NULL, HFILL }},
    { &hf_kerberos_KERB_TICKET_LOGON_Flags,
      { "Flags", "kerberos.KERB_TICKET_LOGON.Flags",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_KERB_TICKET_LOGON_ServiceTicketLength,
      { "ServiceTicketLength", "kerberos.KERB_TICKET_LOGON.ServiceTicketLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_KERB_TICKET_LOGON_TicketGrantingTicketLength,
      { "TicketGrantingTicketLength", "kerberos.KERB_TICKET_LOGON.TicketGrantingTicketLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_KERB_TICKET_LOGON_ServiceTicket,
      { "ServiceTicket", "kerberos.KERB_TICKET_LOGON.ServiceTicket",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_KERB_TICKET_LOGON_TicketGrantingTicket,
      { "TicketGrantingTicket", "kerberos.KERB_TICKET_LOGON.TicketGrantingTicket",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_KERB_TICKET_LOGON_FLAG_ALLOW_EXPIRED_TICKET,
      { "allow_expired_ticket", "kerberos.KERB_TICKET_LOGON.FLAG_ALLOW_EXPIRED_TICKET",
        FT_BOOLEAN, 32, NULL, KERB_LOGON_FLAG_ALLOW_EXPIRED_TICKET,
        NULL, HFILL }},
    { &hf_kerberos_KERB_TICKET_LOGON_FLAG_REDIRECTED,
      { "redirected", "kerberos.KERB_TICKET_LOGON.FLAG_REDIRECTED",
        FT_BOOLEAN, 32, NULL, KERB_LOGON_FLAG_REDIRECTED,
        NULL, HFILL }},
#ifdef HAVE_KERBEROS
	{ &hf_kerberos_KrbFastResponse,
	   { "KrbFastResponse", "kerberos.KrbFastResponse_element",
	    FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	{ &hf_kerberos_strengthen_key,
      { "strengthen-key", "kerberos.strengthen_key_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_finished,
      { "finished", "kerberos.finished_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "KrbFastFinished", HFILL }},
    { &hf_kerberos_fast_options,
      { "fast-options", "kerberos.fast_options",
        FT_BYTES, BASE_NONE, NULL, 0,
        "FastOptions", HFILL }},
    { &hf_kerberos_FastOptions_reserved,
      { "reserved", "kerberos.FastOptions.reserved",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_FastOptions_hide_client_names,
      { "hide-client-names", "kerberos.FastOptions.hide.client.names",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_kerberos_FastOptions_spare_bit2,
      { "spare_bit2", "kerberos.FastOptions.spare.bit2",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_kerberos_FastOptions_spare_bit3,
      { "spare_bit3", "kerberos.FastOptions.spare.bit3",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_kerberos_FastOptions_spare_bit4,
      { "spare_bit4", "kerberos.FastOptions.spare.bit4",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_kerberos_FastOptions_spare_bit5,
      { "spare_bit5", "kerberos.FastOptions.spare.bit5",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_kerberos_FastOptions_spare_bit6,
      { "spare_bit6", "kerberos.FastOptions.spare.bit6",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_kerberos_FastOptions_spare_bit7,
      { "spare_bit7", "kerberos.FastOptions.spare.bit7",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_kerberos_FastOptions_spare_bit8,
      { "spare_bit8", "kerberos.FastOptions.spare.bit8",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_FastOptions_spare_bit9,
      { "spare_bit9", "kerberos.FastOptions.spare.bit9",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_kerberos_FastOptions_spare_bit10,
      { "spare_bit10", "kerberos.FastOptions.spare.bit10",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_kerberos_FastOptions_spare_bit11,
      { "spare_bit11", "kerberos.FastOptions.spare.bit11",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_kerberos_FastOptions_spare_bit12,
      { "spare_bit12", "kerberos.FastOptions.spare.bit12",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_kerberos_FastOptions_spare_bit13,
      { "spare_bit13", "kerberos.FastOptions.spare.bit13",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_kerberos_FastOptions_spare_bit14,
      { "spare_bit14", "kerberos.FastOptions.spare.bit14",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_kerberos_FastOptions_spare_bit15,
      { "spare_bit15", "kerberos.FastOptions.spare.bit15",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_kerberos_FastOptions_kdc_follow_referrals,
      { "kdc-follow-referrals", "kerberos.FastOptions.kdc.follow.referrals",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_ticket_checksum,
      { "ticket-checksum", "kerberos.ticket_checksum_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Checksum", HFILL }},
    { &hf_krb_patimestamp,
      { "patimestamp", "kerberos.patimestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, "KerberosTime", HFILL }},
    { &hf_krb_pausec,
      { "pausec", "kerberos.pausec",
        FT_UINT32, BASE_DEC, NULL, 0, "Microseconds", HFILL }},
#endif /* HAVE_KERBEROS */

#include "packet-kerberos-hfarr.c"
	};

	/* List of subtrees */
	static int *ett[] = {
		&ett_kerberos,
		&ett_krb_recordmark,
		&ett_krb_pac,
		&ett_krb_pac_drep,
		&ett_krb_pac_midl_blob,
		&ett_krb_pac_logon_info,
		&ett_krb_pac_credential_info,
		&ett_krb_pac_s4u_delegation_info,
		&ett_krb_pac_upn_dns_info,
		&ett_krb_pac_upn_dns_info_flags,
		&ett_krb_pac_device_info,
		&ett_krb_pac_server_checksum,
		&ett_krb_pac_privsvr_checksum,
		&ett_krb_pac_client_info_type,
		&ett_krb_pac_ticket_checksum,
		&ett_krb_pac_attributes_info,
		&ett_krb_pac_attributes_info_flags,
		&ett_krb_pac_requester_sid,
		&ett_krb_pac_full_checksum,
		&ett_krb_pa_supported_enctypes,
		&ett_krb_ad_ap_options,
		&ett_kerberos_KERB_TICKET_LOGON,
#ifdef HAVE_KERBEROS
		&ett_krb_pa_enc_ts_enc,
	    &ett_kerberos_KrbFastFinished,
	    &ett_kerberos_KrbFastResponse,
        &ett_kerberos_KrbFastReq,
        &ett_kerberos_FastOptions,
#endif
#include "packet-kerberos-ettarr.c"
	};

	static ei_register_info ei[] = {
		{ &ei_kerberos_missing_keytype, { "kerberos.missing_keytype", PI_DECRYPTION, PI_WARN, "Missing keytype", EXPFILL }},
		{ &ei_kerberos_decrypted_keytype, { "kerberos.decrypted_keytype", PI_SECURITY, PI_CHAT, "Decrypted keytype", EXPFILL }},
		{ &ei_kerberos_learnt_keytype, { "kerberos.learnt_keytype", PI_SECURITY, PI_CHAT, "Learnt keytype", EXPFILL }},
		{ &ei_kerberos_address, { "kerberos.address.unknown", PI_UNDECODED, PI_WARN, "KRB Address: I don't know how to parse this type of address yet", EXPFILL }},
		{ &ei_krb_gssapi_dlglen, { "kerberos.gssapi.dlglen.error", PI_MALFORMED, PI_ERROR, "DlgLen is not the same as number of bytes remaining", EXPFILL }},
	};

	expert_module_t* expert_krb;
	module_t *krb_module;

	proto_kerberos = proto_register_protocol("Kerberos", "KRB5", "kerberos");
	proto_register_field_array(proto_kerberos, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_krb = expert_register_protocol(proto_kerberos);
	expert_register_field_array(expert_krb, ei, array_length(ei));

	kerberos_tap = register_tap("kerberos");
	register_srt_table(proto_kerberos, NULL, 1, krb5stat_packet, krb5stat_init, NULL);

	/* Register dissectors */
	kerberos_handle_udp = register_dissector("kerberos.udp", dissect_kerberos_udp, proto_kerberos);
	kerberos_handle_tcp = register_dissector("kerberos.tcp", dissect_kerberos_tcp, proto_kerberos);

	/* Register preferences */
	krb_module = prefs_register_protocol(proto_kerberos, kerberos_prefs_apply_cb);
	prefs_register_bool_preference(krb_module, "desegment",
	"Reassemble Kerberos over TCP messages spanning multiple TCP segments",
	"Whether the Kerberos dissector should reassemble messages spanning multiple TCP segments."
	" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	&krb_desegment);
#ifdef HAVE_KERBEROS
	prefs_register_bool_preference(krb_module, "decrypt",
	"Try to decrypt Kerberos blobs",
	"Whether the dissector should try to decrypt "
	"encrypted Kerberos blobs. This requires that the proper "
	"keytab file is installed as well.", &krb_decrypt);

	prefs_register_filename_preference(krb_module, "file",
				   "Kerberos keytab file",
				   "The keytab file containing all the secrets",
				   &keytab_filename, false);

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
	wmem_register_callback(wmem_epan_scope(), enc_key_list_cb, NULL);
	kerberos_longterm_keys = wmem_map_new(wmem_epan_scope(),
					      enc_key_content_hash,
					      enc_key_content_equal);
	kerberos_all_keys = wmem_map_new_autoreset(wmem_epan_scope(),
						   wmem_file_scope(),
						   enc_key_content_hash,
						   enc_key_content_equal);
	kerberos_app_session_keys = wmem_map_new_autoreset(wmem_epan_scope(),
							   wmem_file_scope(),
							   enc_key_content_hash,
							   enc_key_content_equal);
#endif /* defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS) */
#endif /* HAVE_KERBEROS */

}
static int wrap_dissect_gss_kerb(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, dcerpc_info *di _U_,uint8_t *drep _U_)
{
	tvbuff_t *auth_tvb;

	auth_tvb = tvb_new_subset_remaining(tvb, offset);

	dissect_kerberos_main(auth_tvb, pinfo, tree, false, NULL);

	return tvb_captured_length_remaining(tvb, offset);
}


static dcerpc_auth_subdissector_fns gss_kerb_auth_connect_fns = {
	wrap_dissect_gss_kerb,                      /* Bind */
	wrap_dissect_gss_kerb,                      /* Bind ACK */
	wrap_dissect_gss_kerb,                      /* AUTH3 */
	NULL,                                       /* Request verifier */
	NULL,                                       /* Response verifier */
	NULL,                                       /* Request data */
	NULL                                        /* Response data */
};

static dcerpc_auth_subdissector_fns gss_kerb_auth_sign_fns = {
	wrap_dissect_gss_kerb,                      /* Bind */
	wrap_dissect_gss_kerb,                      /* Bind ACK */
	wrap_dissect_gss_kerb,                      /* AUTH3 */
	wrap_dissect_gssapi_verf,                   /* Request verifier */
	wrap_dissect_gssapi_verf,                   /* Response verifier */
	NULL,                                       /* Request data */
	NULL                                        /* Response data */
};

static dcerpc_auth_subdissector_fns gss_kerb_auth_seal_fns = {
	wrap_dissect_gss_kerb,                      /* Bind */
	wrap_dissect_gss_kerb,                      /* Bind ACK */
	wrap_dissect_gss_kerb,                      /* AUTH3 */
	wrap_dissect_gssapi_verf,                   /* Request verifier */
	wrap_dissect_gssapi_verf,                   /* Response verifier */
	wrap_dissect_gssapi_payload,                /* Request data */
	wrap_dissect_gssapi_payload                 /* Response data */
};



void
proto_reg_handoff_kerberos(void)
{
	krb4_handle = find_dissector_add_dependency("krb4", proto_kerberos);

	dissector_add_uint_with_preference("udp.port", UDP_PORT_KERBEROS, kerberos_handle_udp);
	dissector_add_uint_with_preference("tcp.port", TCP_PORT_KERBEROS, kerberos_handle_tcp);

	register_dcerpc_auth_subdissector(DCE_C_AUTHN_LEVEL_CONNECT,
									  DCE_C_RPC_AUTHN_PROTOCOL_GSS_KERBEROS,
									  &gss_kerb_auth_connect_fns);

	register_dcerpc_auth_subdissector(DCE_C_AUTHN_LEVEL_PKT_INTEGRITY,
									  DCE_C_RPC_AUTHN_PROTOCOL_GSS_KERBEROS,
									  &gss_kerb_auth_sign_fns);

	register_dcerpc_auth_subdissector(DCE_C_AUTHN_LEVEL_PKT_PRIVACY,
									  DCE_C_RPC_AUTHN_PROTOCOL_GSS_KERBEROS,
									  &gss_kerb_auth_seal_fns);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
