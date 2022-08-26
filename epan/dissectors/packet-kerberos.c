/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-kerberos.c                                                          */
/* asn2wrs.py -b -p kerberos -c ./kerberos.cnf -s ./packet-kerberos-template -D . -O ../.. KerberosV5Spec2.asn k5.asn RFC3244.asn RFC6113.asn SPAKE.asn */

/* Input file: packet-kerberos-template.c */

#line 1 "./asn1/kerberos/packet-kerberos-template.c"
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
 *	https://tools.ietf.org/html/draft-ietf-krb-wg-kerberos-clarifications-07
 *
 * and
 *
 *  https://tools.ietf.org/html/draft-ietf-krb-wg-kerberos-referrals-05
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
#include <epan/exceptions.h>
#include <epan/strutil.h>
#include <epan/conversation.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/prefs.h>
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
	guint32 keytype;
	int keylength;
	const guint8 *keyvalue;
} kerberos_key_t;

typedef void (*kerberos_key_save_fn)(tvbuff_t *tvb _U_, int offset _U_, int length _U_,
				     asn1_ctx_t *actx _U_, proto_tree *tree _U_,
				     int parent_hf_index _U_,
				     int hf_index _U_);

typedef struct {
	guint32 msg_type;
	gboolean is_win2k_pkinit;
	guint32 errorcode;
	gboolean try_nt_status;
	guint32 etype;
	guint32 padata_type;
	guint32 is_enc_padata;
	guint32 enctype;
	kerberos_key_t key;
	proto_tree *key_tree;
	proto_item *key_hidden_item;
	tvbuff_t *key_tvb;
	kerberos_callbacks *callbacks;
	guint32 ad_type;
	guint32 addr_type;
	guint32 checksum_type;
#ifdef HAVE_KERBEROS
	enc_key_t *last_decryption_key;
	enc_key_t *last_added_key;
	tvbuff_t *last_ticket_enc_part_tvb;
#endif
	gint save_encryption_key_parent_hf_index;
	kerberos_key_save_fn save_encryption_key_fn;
	guint learnt_key_ids;
	guint missing_key_ids;
	wmem_list_t *decryption_keys;
	wmem_list_t *learnt_keys;
	wmem_list_t *missing_keys;
	guint32 within_PA_TGS_REQ;
	struct _kerberos_PA_FX_FAST_REQUEST {
		gboolean defer;
		tvbuff_t *tvb;
		proto_tree *tree;
	} PA_FX_FAST_REQUEST;
#ifdef HAVE_KERBEROS
	enc_key_t *PA_TGS_REQ_key;
	enc_key_t *PA_TGS_REQ_subkey;
#endif
	guint32 fast_type;
	guint32 fast_armor_within_armor_value;
#ifdef HAVE_KERBEROS
	enc_key_t *PA_FAST_ARMOR_AP_key;
	enc_key_t *PA_FAST_ARMOR_AP_subkey;
	enc_key_t *fast_armor_key;
	enc_key_t *fast_strengthen_key;
#endif
} kerberos_private_data_t;

static dissector_handle_t kerberos_handle_udp;

/* Forward declarations */
static int dissect_kerberos_Applications(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_AuthorizationData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_ENC_TIMESTAMP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
#ifdef HAVE_KERBEROS
static int dissect_kerberos_PA_ENC_TS_ENC(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
#endif
static int dissect_kerberos_PA_PAC_REQUEST(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_S4U2Self(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_S4U_X509_USER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_ETYPE_INFO(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_ETYPE_INFO2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_AD_IF_RELEVANT(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_AUTHENTICATION_SET_ELEM(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_FX_FAST_REQUEST(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_EncryptedChallenge(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_KERB_KEY_LIST_REQ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_KERB_KEY_LIST_REP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_FX_FAST_REPLY(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_PAC_OPTIONS(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_KERB_AD_RESTRICTION_ENTRY(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_SEQUENCE_OF_ENCTYPE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_SPAKE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
#ifdef HAVE_KERBEROS
static int dissect_kerberos_KrbFastReq(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_KrbFastResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_FastOptions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
#endif

/* Desegment Kerberos over TCP messages */
static gboolean krb_desegment = TRUE;

static gint proto_kerberos = -1;

static gint hf_krb_rm_reserved = -1;
static gint hf_krb_rm_reclen = -1;
static gint hf_krb_provsrv_location = -1;
static gint hf_krb_pw_salt = -1;
static gint hf_krb_ext_error_nt_status = -1;
static gint hf_krb_ext_error_reserved = -1;
static gint hf_krb_ext_error_flags = -1;
static gint hf_krb_address_ip = -1;
static gint hf_krb_address_netbios = -1;
static gint hf_krb_address_ipv6 = -1;
static gint hf_krb_gssapi_len = -1;
static gint hf_krb_gssapi_bnd = -1;
static gint hf_krb_gssapi_dlgopt = -1;
static gint hf_krb_gssapi_dlglen = -1;
static gint hf_krb_gssapi_c_flag_deleg = -1;
static gint hf_krb_gssapi_c_flag_mutual = -1;
static gint hf_krb_gssapi_c_flag_replay = -1;
static gint hf_krb_gssapi_c_flag_sequence = -1;
static gint hf_krb_gssapi_c_flag_conf = -1;
static gint hf_krb_gssapi_c_flag_integ = -1;
static gint hf_krb_gssapi_c_flag_dce_style = -1;
static gint hf_krb_midl_version = -1;
static gint hf_krb_midl_hdr_len = -1;
static gint hf_krb_midl_fill_bytes = -1;
static gint hf_krb_midl_blob_len = -1;
static gint hf_krb_pac_signature_type = -1;
static gint hf_krb_pac_signature_signature = -1;
static gint hf_krb_w2k_pac_entries = -1;
static gint hf_krb_w2k_pac_version = -1;
static gint hf_krb_w2k_pac_type = -1;
static gint hf_krb_w2k_pac_size = -1;
static gint hf_krb_w2k_pac_offset = -1;
static gint hf_krb_pac_clientid = -1;
static gint hf_krb_pac_namelen = -1;
static gint hf_krb_pac_clientname = -1;
static gint hf_krb_pac_logon_info = -1;
static gint hf_krb_pac_credential_data = -1;
static gint hf_krb_pac_credential_info = -1;
static gint hf_krb_pac_credential_info_version = -1;
static gint hf_krb_pac_credential_info_etype = -1;
static gint hf_krb_pac_s4u_delegation_info = -1;
static gint hf_krb_pac_upn_dns_info = -1;
static gint hf_krb_pac_upn_flags = -1;
static gint hf_krb_pac_upn_flag_upn_constructed = -1;
static gint hf_krb_pac_upn_flag_has_sam_name_and_sid = -1;
static gint hf_krb_pac_upn_upn_offset = -1;
static gint hf_krb_pac_upn_upn_len = -1;
static gint hf_krb_pac_upn_upn_name = -1;
static gint hf_krb_pac_upn_dns_offset = -1;
static gint hf_krb_pac_upn_dns_len = -1;
static gint hf_krb_pac_upn_dns_name = -1;
static gint hf_krb_pac_upn_samaccountname_offset = -1;
static gint hf_krb_pac_upn_samaccountname_len = -1;
static gint hf_krb_pac_upn_samaccountname = -1;
static gint hf_krb_pac_upn_objectsid_offset = -1;
static gint hf_krb_pac_upn_objectsid_len = -1;
static gint hf_krb_pac_server_checksum = -1;
static gint hf_krb_pac_privsvr_checksum = -1;
static gint hf_krb_pac_client_info_type = -1;
static gint hf_krb_pac_client_claims_info = -1;
static gint hf_krb_pac_device_info = -1;
static gint hf_krb_pac_device_claims_info = -1;
static gint hf_krb_pac_ticket_checksum = -1;
static gint hf_krb_pac_attributes_info = -1;
static gint hf_krb_pac_attributes_info_length = -1;
static gint hf_krb_pac_attributes_info_flags = -1;
static gint hf_krb_pac_attributes_info_flags_pac_was_requested = -1;
static gint hf_krb_pac_attributes_info_flags_pac_was_given_implicitly = -1;
static gint hf_krb_pac_requester_sid = -1;
static gint hf_krb_pa_supported_enctypes = -1;
static gint hf_krb_pa_supported_enctypes_des_cbc_crc = -1;
static gint hf_krb_pa_supported_enctypes_des_cbc_md5 = -1;
static gint hf_krb_pa_supported_enctypes_rc4_hmac = -1;
static gint hf_krb_pa_supported_enctypes_aes128_cts_hmac_sha1_96 = -1;
static gint hf_krb_pa_supported_enctypes_aes256_cts_hmac_sha1_96 = -1;
static gint hf_krb_pa_supported_enctypes_fast_supported = -1;
static gint hf_krb_pa_supported_enctypes_compound_identity_supported = -1;
static gint hf_krb_pa_supported_enctypes_claims_supported = -1;
static gint hf_krb_pa_supported_enctypes_resource_sid_compression_disabled = -1;
static gint hf_krb_ad_ap_options = -1;
static gint hf_krb_ad_ap_options_cbt = -1;
static gint hf_krb_ad_target_principal = -1;
static gint hf_krb_key_hidden_item = -1;
static gint hf_kerberos_KERB_TICKET_LOGON = -1;
static gint hf_kerberos_KERB_TICKET_LOGON_MessageType = -1;
static gint hf_kerberos_KERB_TICKET_LOGON_Flags = -1;
static gint hf_kerberos_KERB_TICKET_LOGON_ServiceTicketLength = -1;
static gint hf_kerberos_KERB_TICKET_LOGON_TicketGrantingTicketLength = -1;
static gint hf_kerberos_KERB_TICKET_LOGON_ServiceTicket = -1;
static gint hf_kerberos_KERB_TICKET_LOGON_TicketGrantingTicket = -1;
static gint hf_kerberos_KERB_TICKET_LOGON_FLAG_ALLOW_EXPIRED_TICKET = -1;
static gint hf_kerberos_KERB_TICKET_LOGON_FLAG_REDIRECTED = -1;
#ifdef HAVE_KERBEROS
static gint hf_kerberos_KrbFastResponse = -1;
static gint hf_kerberos_strengthen_key = -1;
static gint hf_kerberos_finished = -1;
static gint hf_kerberos_fast_options = -1;
static gint hf_kerberos_ticket_checksum = -1;
static gint hf_krb_patimestamp = -1;
static gint hf_krb_pausec = -1;
static gint hf_kerberos_FastOptions_reserved = -1;
static gint hf_kerberos_FastOptions_hide_client_names = -1;
static gint hf_kerberos_FastOptions_spare_bit2 = -1;
static gint hf_kerberos_FastOptions_spare_bit3 = -1;
static gint hf_kerberos_FastOptions_spare_bit4 = -1;
static gint hf_kerberos_FastOptions_spare_bit5 = -1;
static gint hf_kerberos_FastOptions_spare_bit6 = -1;
static gint hf_kerberos_FastOptions_spare_bit7 = -1;
static gint hf_kerberos_FastOptions_spare_bit8 = -1;
static gint hf_kerberos_FastOptions_spare_bit9 = -1;
static gint hf_kerberos_FastOptions_spare_bit10 = -1;
static gint hf_kerberos_FastOptions_spare_bit11 = -1;
static gint hf_kerberos_FastOptions_spare_bit12 = -1;
static gint hf_kerberos_FastOptions_spare_bit13 = -1;
static gint hf_kerberos_FastOptions_spare_bit14 = -1;
static gint hf_kerberos_FastOptions_spare_bit15 = -1;
static gint hf_kerberos_FastOptions_kdc_follow_referrals = -1;

#endif

/*--- Included file: packet-kerberos-hf.c ---*/
#line 1 "./asn1/kerberos/packet-kerberos-hf.c"
static int hf_kerberos_ticket = -1;               /* Ticket */
static int hf_kerberos_authenticator = -1;        /* Authenticator */
static int hf_kerberos_encTicketPart = -1;        /* EncTicketPart */
static int hf_kerberos_as_req = -1;               /* AS_REQ */
static int hf_kerberos_as_rep = -1;               /* AS_REP */
static int hf_kerberos_tgs_req = -1;              /* TGS_REQ */
static int hf_kerberos_tgs_rep = -1;              /* TGS_REP */
static int hf_kerberos_ap_req = -1;               /* AP_REQ */
static int hf_kerberos_ap_rep = -1;               /* AP_REP */
static int hf_kerberos_krb_safe = -1;             /* KRB_SAFE */
static int hf_kerberos_krb_priv = -1;             /* KRB_PRIV */
static int hf_kerberos_krb_cred = -1;             /* KRB_CRED */
static int hf_kerberos_encASRepPart = -1;         /* EncASRepPart */
static int hf_kerberos_encTGSRepPart = -1;        /* EncTGSRepPart */
static int hf_kerberos_encAPRepPart = -1;         /* EncAPRepPart */
static int hf_kerberos_encKrbPrivPart = -1;       /* ENC_KRB_PRIV_PART */
static int hf_kerberos_encKrbCredPart = -1;       /* EncKrbCredPart */
static int hf_kerberos_krb_error = -1;            /* KRB_ERROR */
static int hf_kerberos_name_type = -1;            /* NAME_TYPE */
static int hf_kerberos_name_string = -1;          /* SEQUENCE_OF_KerberosString */
static int hf_kerberos_name_string_item = -1;     /* KerberosString */
static int hf_kerberos_cname_string = -1;         /* SEQUENCE_OF_CNameString */
static int hf_kerberos_cname_string_item = -1;    /* CNameString */
static int hf_kerberos_sname_string = -1;         /* SEQUENCE_OF_SNameString */
static int hf_kerberos_sname_string_item = -1;    /* SNameString */
static int hf_kerberos_addr_type = -1;            /* ADDR_TYPE */
static int hf_kerberos_address = -1;              /* T_address */
static int hf_kerberos_HostAddresses_item = -1;   /* HostAddress */
static int hf_kerberos_AuthorizationData_item = -1;  /* AuthorizationData_item */
static int hf_kerberos_ad_type = -1;              /* AUTHDATA_TYPE */
static int hf_kerberos_ad_data = -1;              /* T_ad_data */
static int hf_kerberos_padata_type = -1;          /* PADATA_TYPE */
static int hf_kerberos_padata_value = -1;         /* T_padata_value */
static int hf_kerberos_keytype = -1;              /* T_keytype */
static int hf_kerberos_keyvalue = -1;             /* T_keyvalue */
static int hf_kerberos_cksumtype = -1;            /* CKSUMTYPE */
static int hf_kerberos_checksum = -1;             /* T_checksum */
static int hf_kerberos_etype = -1;                /* ENCTYPE */
static int hf_kerberos_kvno = -1;                 /* UInt32 */
static int hf_kerberos_encryptedTicketData_cipher = -1;  /* T_encryptedTicketData_cipher */
static int hf_kerberos_encryptedAuthorizationData_cipher = -1;  /* T_encryptedAuthorizationData_cipher */
static int hf_kerberos_encryptedAuthenticator_cipher = -1;  /* T_encryptedAuthenticator_cipher */
static int hf_kerberos_encryptedKDCREPData_cipher = -1;  /* T_encryptedKDCREPData_cipher */
static int hf_kerberos_encryptedAPREPData_cipher = -1;  /* T_encryptedAPREPData_cipher */
static int hf_kerberos_encryptedKrbPrivData_cipher = -1;  /* T_encryptedKrbPrivData_cipher */
static int hf_kerberos_encryptedKrbCredData_cipher = -1;  /* T_encryptedKrbCredData_cipher */
static int hf_kerberos_tkt_vno = -1;              /* INTEGER_5 */
static int hf_kerberos_realm = -1;                /* Realm */
static int hf_kerberos_sname = -1;                /* SName */
static int hf_kerberos_ticket_enc_part = -1;      /* EncryptedTicketData */
static int hf_kerberos_flags = -1;                /* TicketFlags */
static int hf_kerberos_encTicketPart_key = -1;    /* T_encTicketPart_key */
static int hf_kerberos_crealm = -1;               /* Realm */
static int hf_kerberos_cname = -1;                /* CName */
static int hf_kerberos_transited = -1;            /* TransitedEncoding */
static int hf_kerberos_authtime = -1;             /* KerberosTime */
static int hf_kerberos_starttime = -1;            /* KerberosTime */
static int hf_kerberos_endtime = -1;              /* KerberosTime */
static int hf_kerberos_renew_till = -1;           /* KerberosTime */
static int hf_kerberos_caddr = -1;                /* HostAddresses */
static int hf_kerberos_authorization_data = -1;   /* AuthorizationData */
static int hf_kerberos_tr_type = -1;              /* Int32 */
static int hf_kerberos_contents = -1;             /* OCTET_STRING */
static int hf_kerberos_pvno = -1;                 /* INTEGER_5 */
static int hf_kerberos_msg_type = -1;             /* MESSAGE_TYPE */
static int hf_kerberos_rEQ_SEQUENCE_OF_PA_DATA = -1;  /* T_rEQ_SEQUENCE_OF_PA_DATA */
static int hf_kerberos_rEQ_SEQUENCE_OF_PA_DATA_item = -1;  /* PA_DATA */
static int hf_kerberos_req_body = -1;             /* KDC_REQ_BODY */
static int hf_kerberos_kdc_options = -1;          /* KDCOptions */
static int hf_kerberos_from = -1;                 /* KerberosTime */
static int hf_kerberos_till = -1;                 /* KerberosTime */
static int hf_kerberos_rtime = -1;                /* KerberosTime */
static int hf_kerberos_nonce = -1;                /* UInt32 */
static int hf_kerberos_kDC_REQ_BODY_etype = -1;   /* SEQUENCE_OF_ENCTYPE */
static int hf_kerberos_kDC_REQ_BODY_etype_item = -1;  /* ENCTYPE */
static int hf_kerberos_addresses = -1;            /* HostAddresses */
static int hf_kerberos_enc_authorization_data = -1;  /* EncryptedAuthorizationData */
static int hf_kerberos_additional_tickets = -1;   /* SEQUENCE_OF_Ticket */
static int hf_kerberos_additional_tickets_item = -1;  /* Ticket */
static int hf_kerberos_rEP_SEQUENCE_OF_PA_DATA = -1;  /* T_rEP_SEQUENCE_OF_PA_DATA */
static int hf_kerberos_rEP_SEQUENCE_OF_PA_DATA_item = -1;  /* PA_DATA */
static int hf_kerberos_kDC_REP_enc_part = -1;     /* EncryptedKDCREPData */
static int hf_kerberos_encKDCRepPart_key = -1;    /* T_encKDCRepPart_key */
static int hf_kerberos_last_req = -1;             /* LastReq */
static int hf_kerberos_key_expiration = -1;       /* KerberosTime */
static int hf_kerberos_srealm = -1;               /* Realm */
static int hf_kerberos_encrypted_pa_data = -1;    /* T_encrypted_pa_data */
static int hf_kerberos_LastReq_item = -1;         /* LastReq_item */
static int hf_kerberos_lr_type = -1;              /* LR_TYPE */
static int hf_kerberos_lr_value = -1;             /* KerberosTime */
static int hf_kerberos_ap_options = -1;           /* APOptions */
static int hf_kerberos_authenticator_enc_part = -1;  /* EncryptedAuthenticator */
static int hf_kerberos_authenticator_vno = -1;    /* INTEGER_5 */
static int hf_kerberos_cksum = -1;                /* Checksum */
static int hf_kerberos_cusec = -1;                /* Microseconds */
static int hf_kerberos_ctime = -1;                /* KerberosTime */
static int hf_kerberos_authenticator_subkey = -1;  /* T_authenticator_subkey */
static int hf_kerberos_seq_number = -1;           /* UInt32 */
static int hf_kerberos_aP_REP_enc_part = -1;      /* EncryptedAPREPData */
static int hf_kerberos_encAPRepPart_subkey = -1;  /* T_encAPRepPart_subkey */
static int hf_kerberos_safe_body = -1;            /* KRB_SAFE_BODY */
static int hf_kerberos_kRB_SAFE_BODY_user_data = -1;  /* T_kRB_SAFE_BODY_user_data */
static int hf_kerberos_timestamp = -1;            /* KerberosTime */
static int hf_kerberos_usec = -1;                 /* Microseconds */
static int hf_kerberos_s_address = -1;            /* HostAddress */
static int hf_kerberos_r_address = -1;            /* HostAddress */
static int hf_kerberos_kRB_PRIV_enc_part = -1;    /* EncryptedKrbPrivData */
static int hf_kerberos_encKrbPrivPart_user_data = -1;  /* T_encKrbPrivPart_user_data */
static int hf_kerberos_tickets = -1;              /* SEQUENCE_OF_Ticket */
static int hf_kerberos_tickets_item = -1;         /* Ticket */
static int hf_kerberos_kRB_CRED_enc_part = -1;    /* EncryptedKrbCredData */
static int hf_kerberos_ticket_info = -1;          /* SEQUENCE_OF_KrbCredInfo */
static int hf_kerberos_ticket_info_item = -1;     /* KrbCredInfo */
static int hf_kerberos_krbCredInfo_key = -1;      /* T_krbCredInfo_key */
static int hf_kerberos_prealm = -1;               /* Realm */
static int hf_kerberos_pname = -1;                /* PrincipalName */
static int hf_kerberos_stime = -1;                /* KerberosTime */
static int hf_kerberos_susec = -1;                /* Microseconds */
static int hf_kerberos_error_code = -1;           /* ERROR_CODE */
static int hf_kerberos_e_text = -1;               /* KerberosString */
static int hf_kerberos_e_data = -1;               /* T_e_data */
static int hf_kerberos_e_checksum = -1;           /* Checksum */
static int hf_kerberos_METHOD_DATA_item = -1;     /* PA_DATA */
static int hf_kerberos_pA_ENC_TIMESTAMP_cipher = -1;  /* T_pA_ENC_TIMESTAMP_cipher */
static int hf_kerberos_info_salt = -1;            /* OCTET_STRING */
static int hf_kerberos_ETYPE_INFO_item = -1;      /* ETYPE_INFO_ENTRY */
static int hf_kerberos_info2_salt = -1;           /* KerberosString */
static int hf_kerberos_s2kparams = -1;            /* OCTET_STRING */
static int hf_kerberos_ETYPE_INFO2_item = -1;     /* ETYPE_INFO2_ENTRY */
static int hf_kerberos_server_name = -1;          /* PrincipalName */
static int hf_kerberos_include_pac = -1;          /* BOOLEAN */
static int hf_kerberos_name = -1;                 /* PrincipalName */
static int hf_kerberos_auth = -1;                 /* GeneralString */
static int hf_kerberos_user_id = -1;              /* S4UUserID */
static int hf_kerberos_checksum_01 = -1;          /* Checksum */
static int hf_kerberos_cname_01 = -1;             /* PrincipalName */
static int hf_kerberos_subject_certificate = -1;  /* T_subject_certificate */
static int hf_kerberos_options = -1;              /* BIT_STRING */
static int hf_kerberos_flags_01 = -1;             /* PAC_OPTIONS_FLAGS */
static int hf_kerberos_restriction_type = -1;     /* Int32 */
static int hf_kerberos_restriction = -1;          /* OCTET_STRING */
static int hf_kerberos_PA_KERB_KEY_LIST_REQ_item = -1;  /* ENCTYPE */
static int hf_kerberos_kerbKeyListRep_key = -1;   /* PA_KERB_KEY_LIST_REP_item */
static int hf_kerberos_newpasswd = -1;            /* OCTET_STRING */
static int hf_kerberos_targname = -1;             /* PrincipalName */
static int hf_kerberos_targrealm = -1;            /* Realm */
static int hf_kerberos_pa_type = -1;              /* PADATA_TYPE */
static int hf_kerberos_pa_hint = -1;              /* OCTET_STRING */
static int hf_kerberos_pa_value = -1;             /* OCTET_STRING */
static int hf_kerberos_armor_type = -1;           /* KrbFastArmorTypes */
static int hf_kerberos_armor_value = -1;          /* T_armor_value */
static int hf_kerberos_armored_data_request = -1;  /* KrbFastArmoredReq */
static int hf_kerberos_encryptedKrbFastReq_cipher = -1;  /* T_encryptedKrbFastReq_cipher */
static int hf_kerberos_armor = -1;                /* KrbFastArmor */
static int hf_kerberos_req_checksum = -1;         /* Checksum */
static int hf_kerberos_enc_fast_req = -1;         /* EncryptedKrbFastReq */
static int hf_kerberos_armored_data_reply = -1;   /* KrbFastArmoredRep */
static int hf_kerberos_encryptedKrbFastResponse_cipher = -1;  /* T_encryptedKrbFastResponse_cipher */
static int hf_kerberos_enc_fast_rep = -1;         /* EncryptedKrbFastResponse */
static int hf_kerberos_encryptedChallenge_cipher = -1;  /* T_encryptedChallenge_cipher */
static int hf_kerberos_cipher = -1;               /* OCTET_STRING */
static int hf_kerberos_groups = -1;               /* SEQUENCE_SIZE_1_MAX_OF_SPAKEGroup */
static int hf_kerberos_groups_item = -1;          /* SPAKEGroup */
static int hf_kerberos_group = -1;                /* SPAKEGroup */
static int hf_kerberos_pubkey = -1;               /* OCTET_STRING */
static int hf_kerberos_factors = -1;              /* SEQUENCE_SIZE_1_MAX_OF_SPAKESecondFactor */
static int hf_kerberos_factors_item = -1;         /* SPAKESecondFactor */
static int hf_kerberos_type = -1;                 /* SPAKESecondFactorType */
static int hf_kerberos_data = -1;                 /* OCTET_STRING */
static int hf_kerberos_factor = -1;               /* EncryptedSpakeResponseData */
static int hf_kerberos_support = -1;              /* SPAKESupport */
static int hf_kerberos_challenge = -1;            /* SPAKEChallenge */
static int hf_kerberos_response = -1;             /* SPAKEResponse */
static int hf_kerberos_encdata = -1;              /* EncryptedSpakeData */
/* named bits */
static int hf_kerberos_APOptions_reserved = -1;
static int hf_kerberos_APOptions_use_session_key = -1;
static int hf_kerberos_APOptions_mutual_required = -1;
static int hf_kerberos_TicketFlags_reserved = -1;
static int hf_kerberos_TicketFlags_forwardable = -1;
static int hf_kerberos_TicketFlags_forwarded = -1;
static int hf_kerberos_TicketFlags_proxiable = -1;
static int hf_kerberos_TicketFlags_proxy = -1;
static int hf_kerberos_TicketFlags_may_postdate = -1;
static int hf_kerberos_TicketFlags_postdated = -1;
static int hf_kerberos_TicketFlags_invalid = -1;
static int hf_kerberos_TicketFlags_renewable = -1;
static int hf_kerberos_TicketFlags_initial = -1;
static int hf_kerberos_TicketFlags_pre_authent = -1;
static int hf_kerberos_TicketFlags_hw_authent = -1;
static int hf_kerberos_TicketFlags_transited_policy_checked = -1;
static int hf_kerberos_TicketFlags_ok_as_delegate = -1;
static int hf_kerberos_TicketFlags_unused = -1;
static int hf_kerberos_TicketFlags_enc_pa_rep = -1;
static int hf_kerberos_TicketFlags_anonymous = -1;
static int hf_kerberos_KDCOptions_reserved = -1;
static int hf_kerberos_KDCOptions_forwardable = -1;
static int hf_kerberos_KDCOptions_forwarded = -1;
static int hf_kerberos_KDCOptions_proxiable = -1;
static int hf_kerberos_KDCOptions_proxy = -1;
static int hf_kerberos_KDCOptions_allow_postdate = -1;
static int hf_kerberos_KDCOptions_postdated = -1;
static int hf_kerberos_KDCOptions_unused7 = -1;
static int hf_kerberos_KDCOptions_renewable = -1;
static int hf_kerberos_KDCOptions_unused9 = -1;
static int hf_kerberos_KDCOptions_unused10 = -1;
static int hf_kerberos_KDCOptions_opt_hardware_auth = -1;
static int hf_kerberos_KDCOptions_unused12 = -1;
static int hf_kerberos_KDCOptions_unused13 = -1;
static int hf_kerberos_KDCOptions_constrained_delegation = -1;
static int hf_kerberos_KDCOptions_canonicalize = -1;
static int hf_kerberos_KDCOptions_request_anonymous = -1;
static int hf_kerberos_KDCOptions_unused17 = -1;
static int hf_kerberos_KDCOptions_unused18 = -1;
static int hf_kerberos_KDCOptions_unused19 = -1;
static int hf_kerberos_KDCOptions_unused20 = -1;
static int hf_kerberos_KDCOptions_unused21 = -1;
static int hf_kerberos_KDCOptions_unused22 = -1;
static int hf_kerberos_KDCOptions_unused23 = -1;
static int hf_kerberos_KDCOptions_unused24 = -1;
static int hf_kerberos_KDCOptions_unused25 = -1;
static int hf_kerberos_KDCOptions_disable_transited_check = -1;
static int hf_kerberos_KDCOptions_renewable_ok = -1;
static int hf_kerberos_KDCOptions_enc_tkt_in_skey = -1;
static int hf_kerberos_KDCOptions_unused29 = -1;
static int hf_kerberos_KDCOptions_renew = -1;
static int hf_kerberos_KDCOptions_validate = -1;
static int hf_kerberos_PAC_OPTIONS_FLAGS_claims = -1;
static int hf_kerberos_PAC_OPTIONS_FLAGS_branch_aware = -1;
static int hf_kerberos_PAC_OPTIONS_FLAGS_forward_to_full_dc = -1;
static int hf_kerberos_PAC_OPTIONS_FLAGS_resource_based_constrained_delegation = -1;

/*--- End of included file: packet-kerberos-hf.c ---*/
#line 314 "./asn1/kerberos/packet-kerberos-template.c"

/* Initialize the subtree pointers */
static gint ett_kerberos = -1;
static gint ett_krb_recordmark = -1;
static gint ett_krb_pac = -1;
static gint ett_krb_pac_drep = -1;
static gint ett_krb_pac_midl_blob = -1;
static gint ett_krb_pac_logon_info = -1;
static gint ett_krb_pac_credential_info = -1;
static gint ett_krb_pac_s4u_delegation_info = -1;
static gint ett_krb_pac_upn_dns_info = -1;
static gint ett_krb_pac_upn_dns_info_flags = -1;
static gint ett_krb_pac_device_info = -1;
static gint ett_krb_pac_server_checksum = -1;
static gint ett_krb_pac_privsvr_checksum = -1;
static gint ett_krb_pac_client_info_type = -1;
static gint ett_krb_pac_ticket_checksum = -1;
static gint ett_krb_pac_attributes_info = -1;
static gint ett_krb_pac_attributes_info_flags = -1;
static gint ett_krb_pac_requester_sid = -1;
static gint ett_krb_pa_supported_enctypes = -1;
static gint ett_krb_ad_ap_options = -1;
static gint ett_kerberos_KERB_TICKET_LOGON = -1;
#ifdef HAVE_KERBEROS
static gint ett_krb_pa_enc_ts_enc = -1;
static gint ett_kerberos_KrbFastFinished = -1;
static gint ett_kerberos_KrbFastResponse = -1;
static gint ett_kerberos_KrbFastReq = -1;
static gint ett_kerberos_FastOptions = -1;
#endif

/*--- Included file: packet-kerberos-ett.c ---*/
#line 1 "./asn1/kerberos/packet-kerberos-ett.c"
static gint ett_kerberos_Applications = -1;
static gint ett_kerberos_PrincipalName = -1;
static gint ett_kerberos_SEQUENCE_OF_KerberosString = -1;
static gint ett_kerberos_CName = -1;
static gint ett_kerberos_SEQUENCE_OF_CNameString = -1;
static gint ett_kerberos_SName = -1;
static gint ett_kerberos_SEQUENCE_OF_SNameString = -1;
static gint ett_kerberos_HostAddress = -1;
static gint ett_kerberos_HostAddresses = -1;
static gint ett_kerberos_AuthorizationData = -1;
static gint ett_kerberos_AuthorizationData_item = -1;
static gint ett_kerberos_PA_DATA = -1;
static gint ett_kerberos_EncryptionKey = -1;
static gint ett_kerberos_Checksum = -1;
static gint ett_kerberos_EncryptedTicketData = -1;
static gint ett_kerberos_EncryptedAuthorizationData = -1;
static gint ett_kerberos_EncryptedAuthenticator = -1;
static gint ett_kerberos_EncryptedKDCREPData = -1;
static gint ett_kerberos_EncryptedAPREPData = -1;
static gint ett_kerberos_EncryptedKrbPrivData = -1;
static gint ett_kerberos_EncryptedKrbCredData = -1;
static gint ett_kerberos_Ticket_U = -1;
static gint ett_kerberos_EncTicketPart_U = -1;
static gint ett_kerberos_TransitedEncoding = -1;
static gint ett_kerberos_KDC_REQ = -1;
static gint ett_kerberos_T_rEQ_SEQUENCE_OF_PA_DATA = -1;
static gint ett_kerberos_KDC_REQ_BODY = -1;
static gint ett_kerberos_SEQUENCE_OF_ENCTYPE = -1;
static gint ett_kerberos_SEQUENCE_OF_Ticket = -1;
static gint ett_kerberos_KDC_REP = -1;
static gint ett_kerberos_T_rEP_SEQUENCE_OF_PA_DATA = -1;
static gint ett_kerberos_EncKDCRepPart = -1;
static gint ett_kerberos_LastReq = -1;
static gint ett_kerberos_LastReq_item = -1;
static gint ett_kerberos_AP_REQ_U = -1;
static gint ett_kerberos_Authenticator_U = -1;
static gint ett_kerberos_AP_REP_U = -1;
static gint ett_kerberos_EncAPRepPart_U = -1;
static gint ett_kerberos_KRB_SAFE_U = -1;
static gint ett_kerberos_KRB_SAFE_BODY = -1;
static gint ett_kerberos_KRB_PRIV_U = -1;
static gint ett_kerberos_EncKrbPrivPart = -1;
static gint ett_kerberos_KRB_CRED_U = -1;
static gint ett_kerberos_EncKrbCredPart_U = -1;
static gint ett_kerberos_SEQUENCE_OF_KrbCredInfo = -1;
static gint ett_kerberos_KrbCredInfo = -1;
static gint ett_kerberos_KRB_ERROR_U = -1;
static gint ett_kerberos_METHOD_DATA = -1;
static gint ett_kerberos_PA_ENC_TIMESTAMP = -1;
static gint ett_kerberos_ETYPE_INFO_ENTRY = -1;
static gint ett_kerberos_ETYPE_INFO = -1;
static gint ett_kerberos_ETYPE_INFO2_ENTRY = -1;
static gint ett_kerberos_ETYPE_INFO2 = -1;
static gint ett_kerberos_TGT_REQ = -1;
static gint ett_kerberos_TGT_REP = -1;
static gint ett_kerberos_APOptions = -1;
static gint ett_kerberos_TicketFlags = -1;
static gint ett_kerberos_KDCOptions = -1;
static gint ett_kerberos_PA_PAC_REQUEST = -1;
static gint ett_kerberos_PA_S4U2Self = -1;
static gint ett_kerberos_PA_S4U_X509_USER = -1;
static gint ett_kerberos_S4UUserID = -1;
static gint ett_kerberos_PAC_OPTIONS_FLAGS = -1;
static gint ett_kerberos_PA_PAC_OPTIONS = -1;
static gint ett_kerberos_KERB_AD_RESTRICTION_ENTRY_U = -1;
static gint ett_kerberos_PA_KERB_KEY_LIST_REQ = -1;
static gint ett_kerberos_PA_KERB_KEY_LIST_REP = -1;
static gint ett_kerberos_ChangePasswdData = -1;
static gint ett_kerberos_PA_AUTHENTICATION_SET_ELEM = -1;
static gint ett_kerberos_KrbFastArmor = -1;
static gint ett_kerberos_PA_FX_FAST_REQUEST = -1;
static gint ett_kerberos_EncryptedKrbFastReq = -1;
static gint ett_kerberos_KrbFastArmoredReq = -1;
static gint ett_kerberos_PA_FX_FAST_REPLY = -1;
static gint ett_kerberos_EncryptedKrbFastResponse = -1;
static gint ett_kerberos_KrbFastArmoredRep = -1;
static gint ett_kerberos_EncryptedChallenge = -1;
static gint ett_kerberos_EncryptedSpakeData = -1;
static gint ett_kerberos_EncryptedSpakeResponseData = -1;
static gint ett_kerberos_SPAKESupport = -1;
static gint ett_kerberos_SEQUENCE_SIZE_1_MAX_OF_SPAKEGroup = -1;
static gint ett_kerberos_SPAKEChallenge = -1;
static gint ett_kerberos_SEQUENCE_SIZE_1_MAX_OF_SPAKESecondFactor = -1;
static gint ett_kerberos_SPAKESecondFactor = -1;
static gint ett_kerberos_SPAKEResponse = -1;
static gint ett_kerberos_PA_SPAKE = -1;

/*--- End of included file: packet-kerberos-ett.c ---*/
#line 345 "./asn1/kerberos/packet-kerberos-template.c"

static expert_field ei_kerberos_missing_keytype = EI_INIT;
static expert_field ei_kerberos_decrypted_keytype = EI_INIT;
static expert_field ei_kerberos_learnt_keytype = EI_INIT;
static expert_field ei_kerberos_address = EI_INIT;
static expert_field ei_krb_gssapi_dlglen = EI_INIT;

static dissector_handle_t krb4_handle=NULL;

/* Global variables */
static guint32 gbl_keytype;
static gboolean gbl_do_col_info;


/*--- Included file: packet-kerberos-val.h ---*/
#line 1 "./asn1/kerberos/packet-kerberos-val.h"
#define id_krb5                        "1.3.6.1.5.2"

typedef enum _KERBEROS_AUTHDATA_TYPE_enum {
  KERBEROS_AD_IF_RELEVANT =   1,
  KERBEROS_AD_INTENDED_FOR_SERVER =   2,
  KERBEROS_AD_INTENDED_FOR_APPLICATION_CLASS =   3,
  KERBEROS_AD_KDC_ISSUED =   4,
  KERBEROS_AD_AND_OR =   5,
  KERBEROS_AD_MANDATORY_TICKET_EXTENSIONS =   6,
  KERBEROS_AD_IN_TICKET_EXTENSIONS =   7,
  KERBEROS_AD_MANDATORY_FOR_KDC =   8,
  KERBEROS_AD_INITIAL_VERIFIED_CAS =   9,
  KERBEROS_AD_OSF_DCE =  64,
  KERBEROS_AD_SESAME =  65,
  KERBEROS_AD_OSF_DCE_PKI_CERTID =  66,
  KERBEROS_AD_AUTHENTICATION_STRENGTH =  70,
  KERBEROS_AD_FX_FAST_ARMOR =  71,
  KERBEROS_AD_FX_FAST_USED =  72,
  KERBEROS_AD_WIN2K_PAC = 128,
  KERBEROS_AD_GSS_API_ETYPE_NEGOTIATION = 129,
  KERBEROS_AD_TOKEN_RESTRICTIONS = 141,
  KERBEROS_AD_LOCAL = 142,
  KERBEROS_AD_AP_OPTIONS = 143,
  KERBEROS_AD_TARGET_PRINCIPAL = 144,
  KERBEROS_AD_SIGNTICKET_OLDER = -17,
  KERBEROS_AD_SIGNTICKET = 512
} KERBEROS_AUTHDATA_TYPE_enum;

/* enumerated values for ADDR_TYPE */
#define KERBEROS_ADDR_TYPE_IPV4   2
#define KERBEROS_ADDR_TYPE_CHAOS   5
#define KERBEROS_ADDR_TYPE_XEROX   6
#define KERBEROS_ADDR_TYPE_ISO   7
#define KERBEROS_ADDR_TYPE_DECNET  12
#define KERBEROS_ADDR_TYPE_APPLETALK  16
#define KERBEROS_ADDR_TYPE_NETBIOS  20
#define KERBEROS_ADDR_TYPE_IPV6  24

typedef enum _KERBEROS_PADATA_TYPE_enum {
  KERBEROS_PA_NONE =   0,
  KERBEROS_PA_TGS_REQ =   1,
  KERBEROS_PA_ENC_TIMESTAMP =   2,
  KERBEROS_PA_PW_SALT =   3,
  KERBEROS_PA_ENC_UNIX_TIME =   5,
  KERBEROS_PA_SANDIA_SECUREID =   6,
  KERBEROS_PA_SESAME =   7,
  KERBEROS_PA_OSF_DCE =   8,
  KERBEROS_PA_CYBERSAFE_SECUREID =   9,
  KERBEROS_PA_AFS3_SALT =  10,
  KERBEROS_PA_ETYPE_INFO =  11,
  KERBEROS_PA_SAM_CHALLENGE =  12,
  KERBEROS_PA_SAM_RESPONSE =  13,
  KERBEROS_PA_PK_AS_REQ_19 =  14,
  KERBEROS_PA_PK_AS_REP_19 =  15,
  KERBEROS_PA_PK_AS_REQ =  16,
  KERBEROS_PA_PK_AS_REP =  17,
  KERBEROS_PA_PK_OCSP_RESPONSE =  18,
  KERBEROS_PA_ETYPE_INFO2 =  19,
  KERBEROS_PA_USE_SPECIFIED_KVNO =  20,
  KERBEROS_PA_SAM_REDIRECT =  21,
  KERBEROS_PA_GET_FROM_TYPED_DATA =  22,
  KERBEROS_TD_PADATA =  22,
  KERBEROS_PA_SAM_ETYPE_INFO =  23,
  KERBEROS_PA_ALT_PRINC =  24,
  KERBEROS_PA_SERVER_REFERRAL =  25,
  KERBEROS_PA_SAM_CHALLENGE2 =  30,
  KERBEROS_PA_SAM_RESPONSE2 =  31,
  KERBEROS_PA_EXTRA_TGT =  41,
  KERBEROS_TD_PKINIT_CMS_CERTIFICATES = 101,
  KERBEROS_TD_KRB_PRINCIPAL = 102,
  KERBEROS_TD_KRB_REALM = 103,
  KERBEROS_TD_TRUSTED_CERTIFIERS = 104,
  KERBEROS_TD_CERTIFICATE_INDEX = 105,
  KERBEROS_TD_APP_DEFINED_ERROR = 106,
  KERBEROS_TD_REQ_NONCE = 107,
  KERBEROS_TD_REQ_SEQ = 108,
  KERBEROS_TD_DH_PARAMETERS = 109,
  KERBEROS_TD_CMS_DIGEST_ALGORITHMS = 111,
  KERBEROS_TD_CERT_DIGEST_ALGORITHMS = 112,
  KERBEROS_PA_PAC_REQUEST = 128,
  KERBEROS_PA_FOR_USER = 129,
  KERBEROS_PA_FOR_X509_USER = 130,
  KERBEROS_PA_FOR_CHECK_DUPS = 131,
  KERBEROS_PA_PK_AS_09_BINDING = 132,
  KERBEROS_PA_FX_COOKIE = 133,
  KERBEROS_PA_AUTHENTICATION_SET = 134,
  KERBEROS_PA_AUTH_SET_SELECTED = 135,
  KERBEROS_PA_FX_FAST = 136,
  KERBEROS_PA_FX_ERROR = 137,
  KERBEROS_PA_ENCRYPTED_CHALLENGE = 138,
  KERBEROS_PA_OTP_CHALLENGE = 141,
  KERBEROS_PA_OTP_REQUEST = 142,
  KERBEROS_PA_OTP_CONFIRM = 143,
  KERBEROS_PA_OTP_PIN_CHANGE = 144,
  KERBEROS_PA_EPAK_AS_REQ = 145,
  KERBEROS_PA_EPAK_AS_REP = 146,
  KERBEROS_PA_PKINIT_KX = 147,
  KERBEROS_PA_PKU2U_NAME = 148,
  KERBEROS_PA_REQ_ENC_PA_REP = 149,
  KERBEROS_PA_SPAKE = 151,
  KERBEROS_PA_KERB_KEY_LIST_REQ = 161,
  KERBEROS_PA_KERB_KEY_LIST_REP = 162,
  KERBEROS_PA_SUPPORTED_ETYPES = 165,
  KERBEROS_PA_EXTENDED_ERROR = 166,
  KERBEROS_PA_PAC_OPTIONS = 167,
  KERBEROS_PA_PROV_SRV_LOCATION =  -1
} KERBEROS_PADATA_TYPE_enum;

typedef enum _KERBEROS_KRBFASTARMORTYPES_enum {
  KERBEROS_FX_FAST_RESERVED =   0,
  KERBEROS_FX_FAST_ARMOR_AP_REQUEST =   1
} KERBEROS_KRBFASTARMORTYPES_enum;

/*--- End of included file: packet-kerberos-val.h ---*/
#line 359 "./asn1/kerberos/packet-kerberos-template.c"

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

static kerberos_private_data_t*
kerberos_new_private_data(packet_info *pinfo)
{
	kerberos_private_data_t *p;

	p = wmem_new0(pinfo->pool, kerberos_private_data_t);
	if (p == NULL) {
		return NULL;
	}

	p->decryption_keys = wmem_list_new(pinfo->pool);
	p->learnt_keys = wmem_list_new(pinfo->pool);
	p->missing_keys = wmem_list_new(pinfo->pool);

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

static gboolean
kerberos_private_is_kdc_req(kerberos_private_data_t *private_data)
{
	switch (private_data->msg_type) {
	case KERBEROS_APPLICATIONS_AS_REQ:
	case KERBEROS_APPLICATIONS_TGS_REQ:
		return TRUE;
	}

	return FALSE;
}

gboolean
kerberos_is_win2k_pkinit(asn1_ctx_t *actx)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

	return private_data->is_win2k_pkinit;
}

static int dissect_kerberos_defer_PA_FX_FAST_REQUEST(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
	kerberos_private_data_t* private_data = kerberos_get_private_data(actx);

	/*
	 * dissect_ber_octet_string_wcb() always passes
	 * implicit_tag=FALSE, offset=0 and hf_index=-1
	 *
	 * It means we only need to remember tvb and tree
	 * in order to replay dissect_kerberos_PA_FX_FAST_REQUEST()
	 * in dissect_kerberos_T_rEQ_SEQUENCE_OF_PA_DATA()
	 */
	ws_assert(implicit_tag == FALSE);
	ws_assert(offset == 0);
	ws_assert(hf_index == -1);

	if (private_data->PA_FX_FAST_REQUEST.defer) {
		/*
		 * Remember the tvb (and the optional tree)
		 */
		private_data->PA_FX_FAST_REQUEST.tvb = tvb;
		private_data->PA_FX_FAST_REQUEST.tree = tree;
		/*
		 * only handle the first PA_FX_FAST_REQUEST...
		 */
		private_data->PA_FX_FAST_REQUEST.defer = FALSE;
		return tvb_reported_length_remaining(tvb, offset);
	}

	return dissect_kerberos_PA_FX_FAST_REQUEST(implicit_tag, tvb, offset, actx, tree, hf_index);
}

#ifdef HAVE_KERBEROS

/* Decrypt Kerberos blobs */
gboolean krb_decrypt = FALSE;

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
static guint kerberos_longterm_ids = 0;
wmem_map_t *kerberos_longterm_keys = NULL;
static wmem_map_t *kerberos_all_keys = NULL;
static wmem_map_t *kerberos_app_session_keys = NULL;

static gboolean
enc_key_list_cb(wmem_allocator_t* allocator _U_, wmem_cb_event_t event _U_, void *user_data _U_)
{
	enc_key_list = NULL;
	kerberos_longterm_ids = 0;
	/* keep the callback registered */
	return TRUE;
}

static gint enc_key_cmp_id(gconstpointer k1, gconstpointer k2)
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
enc_key_content_equal(gconstpointer k1, gconstpointer k2)
{
	const enc_key_t *key1 = (const enc_key_t *)k1;
	const enc_key_t *key2 = (const enc_key_t *)k2;
	int cmp;

	if (key1->keytype != key2->keytype) {
		return FALSE;
	}

	if (key1->keylength != key2->keylength) {
		return FALSE;
	}

	cmp = memcmp(key1->keyvalue, key2->keyvalue, key1->keylength);
	if (cmp != 0) {
		return FALSE;
	}

	return TRUE;
}

static guint
enc_key_content_hash(gconstpointer k)
{
	const enc_key_t *key = (const enc_key_t *)k;
	guint ret = 0;

	ret += wmem_strong_hash((const guint8 *)&key->keytype,
				sizeof(key->keytype));
	ret += wmem_strong_hash((const guint8 *)&key->keylength,
				sizeof(key->keylength));
	ret += wmem_strong_hash((const guint8 *)key->keyvalue,
				key->keylength);

	return ret;
}

static void
kerberos_key_map_insert(wmem_map_t *key_map, enc_key_t *new_key)
{
	enc_key_t *existing = NULL;
	enc_key_t *cur = NULL;
	gint cmp;

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

static void insert_longterm_keys_into_key_map_cb(gpointer __key _U_,
						 gpointer value,
						 gpointer user_data)
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
				guint keymap_size,
				guint decryption_count)
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
				   guint keymap_size,
				   guint decryption_count)
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
			     guint keymap_size,
			     guint verify_count)
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
				guint keymap_size,
				guint verify_count)
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
	k1.contents = (guint8 *)ek1->keyvalue;

	k2.magic = KV5M_KEYBLOCK;
	k2.enctype = ek2->keytype;
	k2.length = ek2->keylength;
	k2.contents = (guint8 *)ek2->keyvalue;

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
	static gboolean first_time=TRUE;

	if (filename == NULL || filename[0] == 0) {
		return;
	}

	if(first_time){
		first_time=FALSE;
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
						 snprintf(pos, (gulong)(KRB_MAX_ORIG_LEN-(pos-new_key->key_origin)), "%s%s",(i?"/":""),(key.principal->data[i]).data));
			}
			pos+=MIN(KRB_MAX_ORIG_LEN-(pos-new_key->key_origin),
					 snprintf(pos, (gulong)(KRB_MAX_ORIG_LEN-(pos-new_key->key_origin)), "@%s",key.principal->realm.data));
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
	guint count;
	enc_key_t *ek;
};

static void
decrypt_krb5_with_cb_try_key(gpointer __key _U_, gpointer value, gpointer userdata)
{
	struct decrypt_krb5_with_cb_state *state =
		(struct decrypt_krb5_with_cb_state *)userdata;
	enc_key_t *ek = (enc_key_t *)value;
	krb5_error_code ret;
	krb5_keytab_entry key;
#ifdef HAVE_KRB5_C_FX_CF2_SIMPLE
	enc_key_t *ak = state->private_data->fast_armor_key;
	enc_key_t *sk = state->private_data->fast_strengthen_key;
	gboolean try_with_armor_key = FALSE;
	gboolean try_with_strengthen_key = FALSE;
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
				try_with_armor_key = TRUE;
			}
			break;
		}

		/*
		 * If we already have a strengthen_key
		 * we don't need to try with the armor key
		 * again
		 */
		if (sk != NULL) {
			try_with_armor_key = FALSE;
		}
	}

	if (sk != NULL && sk != ek && sk->keytype == state->keytype && sk->keytype == ek->keytype) {
		switch (state->usage) {
		case 3:
			if (ek->fd_num == -1) {
				/* AS-REP is based on a long term key */
				try_with_strengthen_key = TRUE;
			}
			break;
		case 8:
		case 9:
			if (ek->fd_num != -1) {
				/* TGS-REP is not based on a long term key */
				try_with_strengthen_key = TRUE;
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
		k1.contents = (guint8 *)ak->keyvalue;

		k2.magic = KV5M_KEYBLOCK;
		k2.enctype = ek->keytype;
		k2.length = ek->keylength;
		k2.contents = (guint8 *)ek->keyvalue;

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
		k1.contents = (guint8 *)sk->keyvalue;

		k2.magic = KV5M_KEYBLOCK;
		k2.enctype = ek->keytype;
		k2.length = ek->keylength;
		k2.contents = (guint8 *)ek->keyvalue;

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

static guint8 *
decrypt_krb5_data_private(proto_tree *tree _U_, packet_info *pinfo,
			  kerberos_private_data_t *private_data,
			  int usage, tvbuff_t *cryptotvb, int keytype,
			  int *datalen)
{
#define HAVE_DECRYPT_KRB5_DATA_PRIVATE 1
	struct decrypt_krb5_data_state state;
	krb5_error_code ret;
	int length = tvb_captured_length(cryptotvb);
	const guint8 *cryptotext = tvb_get_ptr(cryptotvb, 0, length);

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
	state.input.data = (guint8 *)cryptotext;
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
	return (guint8 *)state.output.data;
}

guint8 *
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
	const guint8 *gssapi_header_ptr;
	guint gssapi_header_len;
	tvbuff_t *gssapi_encrypted_tvb;
	guint8 *gssapi_payload;
	guint gssapi_payload_len;
	const guint8 *gssapi_trailer_ptr;
	guint gssapi_trailer_len;
	tvbuff_t *checksum_tvb;
	guint8 *checksum;
	guint checksum_len;
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
	guint k5_blocksize;
	krb5_crypto_iov iov[6];
	krb5_error_code ret;
	guint checksum_remain = state->checksum_len;
	guint checksum_crypt_len;

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
	 * warning C4267: '-=': conversion from 'size_t' to 'guint',
	 * possible loss of data
	 */
	k5_blocksize = (guint)_k5_blocksize;
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
		iov[1].data.data = (guint8 *)(guintptr)state->gssapi_header_ptr;
		iov[1].data.length = state->gssapi_header_len;
	} else {
		iov[1].flags = KRB5_CRYPTO_TYPE_EMPTY;
	}

	iov[2].flags = KRB5_CRYPTO_TYPE_DATA;
	iov[2].data.data = state->gssapi_payload;
	iov[2].data.length = state->gssapi_payload_len;

	if (state->gssapi_trailer_ptr != NULL) {
		iov[3].flags = KRB5_CRYPTO_TYPE_SIGN_ONLY;
		iov[3].data.data = (guint8 *)(guintptr)state->gssapi_trailer_ptr;
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
	state.gssapi_payload = (guint8 *)wmem_alloc0(pinfo->pool, state.gssapi_payload_len);
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
	state.checksum = (guint8 *)wmem_alloc0(pinfo->pool, state.checksum_len);
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
#define _ARRAY_SIZE(X) (sizeof(X) / sizeof((X)[0]))
	static const int keytypes[] = {
		18,
		17,
		23,
	};
	guint i;

	for (i = 0; i < _ARRAY_SIZE(keytypes); i++) {
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
	krb5_pac pac;
	krb5_cksumtype server_checksum;
	guint server_count;
	enc_key_t *server_ek;
	krb5_cksumtype kdc_checksum;
	guint kdc_count;
	enc_key_t *kdc_ek;
	krb5_cksumtype ticket_checksum_type;
	const krb5_data *ticket_checksum_data;
};

static void
verify_krb5_pac_try_server_key(gpointer __key _U_, gpointer value, gpointer userdata)
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
	keyblock.contents = (guint8 *)ek->keyvalue;

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
verify_krb5_pac_try_kdc_key(gpointer __key _U_, gpointer value, gpointer userdata)
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
	keyblock.contents = (guint8 *)ek->keyvalue;

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
	guint teplength = 0;
	const guint8 *tepbuffer = NULL;
	krb5_data tepdata = { .length = 0, };
	krb5_enc_tkt_part *tep = NULL;
	krb5_data *tmpdata = NULL;
	krb5_error_code ret;
	krb5_authdata **recoded_container = NULL;
	gint ad_orig_idx = -1;
	krb5_authdata *ad_orig_ptr = NULL;
	gint l0idx = 0;
	krb5_keyblock kdc_key = { .magic = KV5M_KEYBLOCK, };
	size_t checksum_length = 0;
	krb5_checksum checksum = { .checksum_type = 0, };
	krb5_boolean valid = FALSE;

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
	kdc_key.contents = (guint8 *)state->kdc_ek->keyvalue;

	checksum.checksum_type = state->ticket_checksum_type;
	checksum.length = state->ticket_checksum_data->length;
	checksum.contents = (guint8 *)state->ticket_checksum_data->data;
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

	tepdata.data = (void *)(uintptr_t)tepbuffer;
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
		gint l1idx = 0;

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

	if (valid == FALSE) {
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

static void
verify_krb5_pac(proto_tree *tree _U_, asn1_ctx_t *actx, tvbuff_t *pactvb)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	krb5_error_code ret;
	krb5_data checksum_data = {0,0,NULL};
	krb5_data ticket_checksum_data = {0,0,NULL};
	int length = tvb_captured_length(pactvb);
	const guint8 *pacbuffer = NULL;
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
	static gboolean first_time=TRUE;

	if (filename == NULL || filename[0] == 0) {
		return;
	}

	if(first_time){
		first_time=FALSE;
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
			       MIN((guint)key.keyblock.keyvalue.length, KRB_MAX_KEY_LENGTH));

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


guint8 *
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
	const guint8 *cryptotext = tvb_get_ptr(cryptotvb, 0, length);

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
		guint8 *cryptocopy; /* workaround for pre-0.6.1 heimdal bug */

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
		cryptocopy = (guint8 *)wmem_memdup(pinfo->pool, cryptotext, length);
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
			user_data = (char *)wmem_memdup(pinfo->pool, data.data, (guint)data.length);
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
	guint16 kvno;
	int     keytype;
	int     length;
	guint8 *contents;
	char    origin[KRB_MAX_ORIG_LEN+1];
} service_key_t;
GSList *service_key_list = NULL;


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
	service_key_list = g_slist_append(service_key_list, (gpointer) new_key);
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
			service_key_list = g_slist_append(service_key_list, (gpointer) sk);
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

guint8 *
decrypt_krb5_data(proto_tree *tree, packet_info *pinfo,
					int _U_ usage,
					tvbuff_t *cryptotvb,
					int keytype,
					int *datalen)
{
	tvbuff_t *encr_tvb;
	guint8 *decrypted_data = NULL, *plaintext = NULL;
	guint8 cls;
	gboolean pc;
	guint32 tag, item_len, data_len;
	int id_offset, offset;
	guint8 key[DES3_KEY_SIZE];
	guint8 initial_vector[DES_BLOCK_SIZE];
	gcry_md_hd_t md5_handle;
	guint8 *digest;
	guint8 zero_fill[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	guint8 confounder[8];
	gboolean ind;
	GSList *ske;
	service_key_t *sk;
	struct des3_ctx ctx;
	int length = tvb_captured_length(cryptotvb);
	const guint8 *cryptotext = tvb_get_ptr(cryptotvb, 0, length);


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
		gboolean do_continue = FALSE;
		gboolean digest_ok;
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
			do_continue = TRUE;
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
			plaintext = (guint8* )tvb_memdup(pinfo->pool, encr_tvb, CONFOUNDER_PLUS_CHECKSUM, data_len);
			tvb_free(encr_tvb);

			if (datalen) {
				*datalen = data_len;
			}
			return(plaintext);
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

#ifdef HAVE_KERBEROS
static guint8 *
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
dissect_krb5_decrypt_ticket_data (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
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
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Krb5 Ticket");

		private_data->last_ticket_enc_part_tvb = child_tvb;
		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
		private_data->last_ticket_enc_part_tvb = last_ticket_enc_part_tvb;
	}
	return offset;
}

static int
dissect_krb5_decrypt_authenticator_data (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
											proto_tree *tree, int hf_index _U_)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	guint8 *plaintext;
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

		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_authorization_data(gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
					proto_tree *tree, int hf_index _U_)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	guint8 *plaintext;
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

		offset=dissect_kerberos_AuthorizationData(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_KDC_REP_data (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	guint8 *plaintext = NULL;
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

		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_PA_ENC_TIMESTAMP (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
										proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
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

		offset=dissect_kerberos_PA_ENC_TS_ENC(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_AP_REP_data (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
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

		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_PRIV_data (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
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

		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_CRED_data (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	guint8 *plaintext;
	int length;
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	if (private_data->etype == 0) {
		offset=dissect_kerberos_Applications(FALSE, next_tvb, 0, actx , tree, /* hf_index*/ -1);
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

		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_KrbFastReq(gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
				proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
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

		offset=dissect_kerberos_KrbFastReq(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_KrbFastResponse(gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
				     proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
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
		offset=dissect_kerberos_KrbFastResponse(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_EncryptedChallenge(gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
					proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
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

		offset=dissect_kerberos_PA_ENC_TS_ENC(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
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
	&hf_krb_pa_supported_enctypes_fast_supported,
	&hf_krb_pa_supported_enctypes_compound_identity_supported,
	&hf_krb_pa_supported_enctypes_claims_supported,
	&hf_krb_pa_supported_enctypes_resource_sid_compression_disabled,
	NULL,
};

static int
dissect_kerberos_PA_SUPPORTED_ENCTYPES(gboolean implicit_tag _U_, tvbuff_t *tvb _U_,
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
	NULL,
};


static int
dissect_kerberos_AD_AP_OPTIONS(gboolean implicit_tag _U_, tvbuff_t *tvb _U_,
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
dissect_kerberos_AD_TARGET_PRINCIPAL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_,
				     int offset _U_, asn1_ctx_t *actx _U_,
				     proto_tree *tree _U_, int hf_index _U_)
{
	int tp_offset, tp_len;
	guint16 bc;

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
	guint32 len;
	guint16 dlglen;

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
	offset=dissect_kerberos_Applications(FALSE, tvb, offset, actx, tree, /* hf_index */ -1);

	return offset;
}

static int
dissect_krb5_PA_PROV_SRV_LOCATION(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
	offset=dissect_ber_GeneralString(actx, tree, tvb, offset, hf_krb_provsrv_location, NULL, 0);

	return offset;
}

static int
dissect_krb5_PW_SALT(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	gint length;
	guint32 nt_status = 0;
	guint32 reserved = 0;
	guint32 flags = 0;

	/*
	 * Microsoft stores a special 12 byte blob here
	 * [MS-KILE] 2.2.1 KERB-EXT-ERROR
	 * guint32 NT_status
	 * guint32 reserved (== 0)
	 * guint32 flags (at least 0x00000001 is set)
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

	if (!private_data->try_nt_status) {
		goto no_error;
	}

	nt_status = tvb_get_letohl(tvb, offset);
	reserved = tvb_get_letohl(tvb, offset + 4);
	flags = tvb_get_letohl(tvb, offset + 8);

	if (nt_status == 0 || reserved != 0 || flags == 0) {
		goto no_error;
	}

	proto_tree_add_item(tree, hf_krb_ext_error_nt_status, tvb, offset, 4,
			ENC_LITTLE_ENDIAN);
	col_append_fstr(actx->pinfo->cinfo, COL_INFO,
			" NT Status: %s",
			val_to_str(nt_status, NT_errors,
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
dissect_krb5_PAC_DREP(proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint8 *drep)
{
	proto_tree *tree;
	guint8 val;

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 16, ett_krb_pac_drep, NULL, "DREP");

	val = tvb_get_guint8(tvb, offset);
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
dissect_krb5_PAC_NDRHEADERBLOB(proto_tree *parent_tree, tvbuff_t *tvb, int offset, guint8 *drep, asn1_ctx_t *actx _U_)
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
	guint8 drep[4] = { 0x10, 0x00, 0x00, 0x00}; /* fake DREP struct */
	static dcerpc_info di;      /* fake dcerpc_info struct */
	static dcerpc_call_value call_data;

	item = proto_tree_add_item(parent_tree, hf_krb_pac_logon_info, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_krb_pac_logon_info);

	/* skip the first 16 bytes, they are some magic created by the idl
	 * compiler   the first 4 bytes might be flags?
	 */
	offset = dissect_krb5_PAC_NDRHEADERBLOB(tree, tvb, offset, &drep[0], actx);

	/* the PAC_LOGON_INFO blob */
	/* fake whatever state the dcerpc runtime support needs */
	di.conformant_run=0;
	/* we need di->call_data->flags.NDR64 == 0 */
	di.call_data=&call_data;
	init_ndr_pointer_list(&di);
	offset = dissect_ndr_pointer(tvb, offset, actx->pinfo, tree, &di, drep,
									netlogon_dissect_PAC_LOGON_INFO, NDR_POINTER_UNIQUE,
									"PAC_LOGON_INFO:", -1);

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
	guint8 *plaintext = NULL;
	int plainlen = 0;
	int length = 0;
#define KRB5_KU_OTHER_ENCRYPTED 16
#ifdef  HAVE_KERBEROS
	guint32 etype;
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
	guint8 drep[4] = { 0x10, 0x00, 0x00, 0x00}; /* fake DREP struct */
	static dcerpc_info di;      /* fake dcerpc_info struct */
	static dcerpc_call_value call_data;

	item = proto_tree_add_item(parent_tree, hf_krb_pac_s4u_delegation_info, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_krb_pac_s4u_delegation_info);

	/* skip the first 16 bytes, they are some magic created by the idl
	 * compiler   the first 4 bytes might be flags?
	 */
	offset = dissect_krb5_PAC_NDRHEADERBLOB(tree, tvb, offset, &drep[0], actx);


	/* the S4U_DELEGATION_INFO blob. See [MS-PAC] */
	/* fake whatever state the dcerpc runtime support needs */
	di.conformant_run=0;
	/* we need di->call_data->flags.NDR64 == 0 */
	di.call_data=&call_data;
	init_ndr_pointer_list(&di);
	offset = dissect_ndr_pointer(tvb, offset, actx->pinfo, tree, &di, drep,
									netlogon_dissect_PAC_S4U_DELEGATION_INFO, NDR_POINTER_UNIQUE,
									"PAC_S4U_DELEGATION_INFO:", -1);

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
	proto_item *item;
	proto_tree *tree;
	guint16 dns_offset, dns_len;
	guint16 upn_offset, upn_len;
	guint16 samaccountname_offset = 0, samaccountname_len = 0;
	guint16 objectsid_offset = 0, objectsid_len = 0;
	guint32 flags;

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
		dissect_nt_sid(sid_tvb, 0, tree, "objectSid", NULL, -1);
	}

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
	proto_item *item;
	proto_tree *tree;
	guint8 drep[4] = { 0x10, 0x00, 0x00, 0x00}; /* fake DREP struct */
	static dcerpc_info di;      /* fake dcerpc_info struct */
	static dcerpc_call_value call_data;

	item = proto_tree_add_item(parent_tree, hf_krb_pac_device_info, tvb, offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_krb_pac_device_info);

	/* skip the first 16 bytes, they are some magic created by the idl
	 * compiler   the first 4 bytes might be flags?
	 */
	offset = dissect_krb5_PAC_NDRHEADERBLOB(tree, tvb, offset, &drep[0], actx);

	/* the PAC_DEVICE_INFO blob */
	/* fake whatever state the dcerpc runtime support needs */
	di.conformant_run=0;
	/* we need di->call_data->flags.NDR64 == 0 */
	di.call_data=&call_data;
	init_ndr_pointer_list(&di);
	offset = dissect_ndr_pointer(tvb, offset, actx->pinfo, tree, &di, drep,
				     netlogon_dissect_PAC_DEVICE_INFO, NDR_POINTER_UNIQUE,
				     "PAC_DEVICE_INFO:", -1);

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
	guint16 namelen;

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
dissect_krb5_AD_WIN2K_PAC_struct(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx)
{
	guint32 pac_type;
	guint32 pac_size;
	guint32 pac_offset;
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

	default:
		break;
	}
	return offset;
}

static int
dissect_krb5_AD_WIN2K_PAC(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_)
{
	guint32 entries;
	guint32 version;
	guint32 i;

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


/*--- Included file: packet-kerberos-fn.c ---*/
#line 1 "./asn1/kerberos/packet-kerberos-fn.c"


static int
dissect_kerberos_INTEGER_5(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_kerberos_KerberosString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GeneralString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_kerberos_Realm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_kerberos_KerberosString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string kerberos_NAME_TYPE_vals[] = {
  {   0, "kRB5-NT-UNKNOWN" },
  {   1, "kRB5-NT-PRINCIPAL" },
  {   2, "kRB5-NT-SRV-INST" },
  {   3, "kRB5-NT-SRV-HST" },
  {   4, "kRB5-NT-SRV-XHST" },
  {   5, "kRB5-NT-UID" },
  {   6, "kRB5-NT-X500-PRINCIPAL" },
  {   7, "kRB5-NT-SMTP-NAME" },
  {  10, "kRB5-NT-ENTERPRISE-PRINCIPAL" },
  {  11, "kRB5-NT-WELLKNOWN" },
  {  12, "kRB5-NT-SRV-HST-DOMAIN" },
  { -130, "kRB5-NT-ENT-PRINCIPAL-AND-ID" },
  { -128, "kRB5-NT-MS-PRINCIPAL" },
  { -129, "kRB5-NT-MS-PRINCIPAL-AND-ID" },
  { -1200, "kRB5-NT-NTLM" },
  { -1201, "kRB5-NT-X509-GENERAL-NAME" },
  { -1202, "kRB5-NT-GSS-HOSTBASED-SERVICE" },
  { -1203, "kRB5-NT-CACHE-UUID" },
  { -195894762, "kRB5-NT-SRV-HST-NEEDS-CANON" },
  { 0, NULL }
};


static int
dissect_kerberos_NAME_TYPE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_kerberos_SNameString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GeneralString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_SNameString_sequence_of[1] = {
  { &hf_kerberos_sname_string_item, BER_CLASS_UNI, BER_UNI_TAG_GeneralString, BER_FLAGS_NOOWNTAG, dissect_kerberos_SNameString },
};

static int
dissect_kerberos_SEQUENCE_OF_SNameString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_SNameString_sequence_of, hf_index, ett_kerberos_SEQUENCE_OF_SNameString);

  return offset;
}


static const ber_sequence_t SName_sequence[] = {
  { &hf_kerberos_name_type  , BER_CLASS_CON, 0, 0, dissect_kerberos_NAME_TYPE },
  { &hf_kerberos_sname_string, BER_CLASS_CON, 1, 0, dissect_kerberos_SEQUENCE_OF_SNameString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_SName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SName_sequence, hf_index, ett_kerberos_SName);

  return offset;
}


static const value_string kerberos_ENCTYPE_vals[] = {
  {   0, "eTYPE-NULL" },
  {   1, "eTYPE-DES-CBC-CRC" },
  {   2, "eTYPE-DES-CBC-MD4" },
  {   3, "eTYPE-DES-CBC-MD5" },
  {   5, "eTYPE-DES3-CBC-MD5" },
  {   7, "eTYPE-OLD-DES3-CBC-SHA1" },
  {   8, "eTYPE-SIGN-DSA-GENERATE" },
  {   9, "eTYPE-DSA-SHA1" },
  {  10, "eTYPE-RSA-MD5" },
  {  11, "eTYPE-RSA-SHA1" },
  {  12, "eTYPE-RC2-CBC" },
  {  13, "eTYPE-RSA" },
  {  14, "eTYPE-RSAES-OAEP" },
  {  15, "eTYPE-DES-EDE3-CBC" },
  {  16, "eTYPE-DES3-CBC-SHA1" },
  {  17, "eTYPE-AES128-CTS-HMAC-SHA1-96" },
  {  18, "eTYPE-AES256-CTS-HMAC-SHA1-96" },
  {  19, "eTYPE-AES128-CTS-HMAC-SHA256-128" },
  {  20, "eTYPE-AES256-CTS-HMAC-SHA384-192" },
  {  23, "eTYPE-ARCFOUR-HMAC-MD5" },
  {  24, "eTYPE-ARCFOUR-HMAC-MD5-56" },
  {  25, "eTYPE-CAMELLIA128-CTS-CMAC" },
  {  26, "eTYPE-CAMELLIA256-CTS-CMAC" },
  {  48, "eTYPE-ENCTYPE-PK-CROSS" },
  { -128, "eTYPE-ARCFOUR-MD4" },
  { -133, "eTYPE-ARCFOUR-HMAC-OLD" },
  { -135, "eTYPE-ARCFOUR-HMAC-OLD-EXP" },
  { -4096, "eTYPE-DES-CBC-NONE" },
  { -4097, "eTYPE-DES3-CBC-NONE" },
  { -4098, "eTYPE-DES-CFB64-NONE" },
  { -4099, "eTYPE-DES-PCBC-NONE" },
  { -4100, "eTYPE-DIGEST-MD5-NONE" },
  { -4101, "eTYPE-CRAM-MD5-NONE" },
  { 0, NULL }
};


static int
dissect_kerberos_ENCTYPE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 356 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &(private_data->etype));




  return offset;
}



static int
dissect_kerberos_UInt32(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_kerberos_T_encryptedTicketData_cipher(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 360 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
  offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_ticket_data);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif



  return offset;
}


static const ber_sequence_t EncryptedTicketData_sequence[] = {
  { &hf_kerberos_etype      , BER_CLASS_CON, 0, 0, dissect_kerberos_ENCTYPE },
  { &hf_kerberos_kvno       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { &hf_kerberos_encryptedTicketData_cipher, BER_CLASS_CON, 2, 0, dissect_kerberos_T_encryptedTicketData_cipher },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncryptedTicketData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedTicketData_sequence, hf_index, ett_kerberos_EncryptedTicketData);

  return offset;
}


static const ber_sequence_t Ticket_U_sequence[] = {
  { &hf_kerberos_tkt_vno    , BER_CLASS_CON, 0, 0, dissect_kerberos_INTEGER_5 },
  { &hf_kerberos_realm      , BER_CLASS_CON, 1, 0, dissect_kerberos_Realm },
  { &hf_kerberos_sname      , BER_CLASS_CON, 2, 0, dissect_kerberos_SName },
  { &hf_kerberos_ticket_enc_part, BER_CLASS_CON, 3, 0, dissect_kerberos_EncryptedTicketData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_Ticket_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Ticket_U_sequence, hf_index, ett_kerberos_Ticket_U);

  return offset;
}



static int
dissect_kerberos_Ticket(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 1, FALSE, dissect_kerberos_Ticket_U);

  return offset;
}



static int
dissect_kerberos_CNameString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GeneralString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_CNameString_sequence_of[1] = {
  { &hf_kerberos_cname_string_item, BER_CLASS_UNI, BER_UNI_TAG_GeneralString, BER_FLAGS_NOOWNTAG, dissect_kerberos_CNameString },
};

static int
dissect_kerberos_SEQUENCE_OF_CNameString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_CNameString_sequence_of, hf_index, ett_kerberos_SEQUENCE_OF_CNameString);

  return offset;
}


static const ber_sequence_t CName_sequence[] = {
  { &hf_kerberos_name_type  , BER_CLASS_CON, 0, 0, dissect_kerberos_NAME_TYPE },
  { &hf_kerberos_cname_string, BER_CLASS_CON, 1, 0, dissect_kerberos_SEQUENCE_OF_CNameString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_CName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CName_sequence, hf_index, ett_kerberos_CName);

  return offset;
}


static const value_string kerberos_CKSUMTYPE_vals[] = {
  {   0, "cKSUMTYPE-NONE" },
  {   1, "cKSUMTYPE-CRC32" },
  {   2, "cKSUMTYPE-RSA-MD4" },
  {   3, "cKSUMTYPE-RSA-MD4-DES" },
  {   4, "cKSUMTYPE-DES-MAC" },
  {   5, "cKSUMTYPE-DES-MAC-K" },
  {   6, "cKSUMTYPE-RSA-MD4-DES-K" },
  {   7, "cKSUMTYPE-RSA-MD5" },
  {   8, "cKSUMTYPE-RSA-MD5-DES" },
  {   9, "cKSUMTYPE-RSA-MD5-DES3" },
  {  10, "cKSUMTYPE-SHA1-OTHER" },
  {  12, "cKSUMTYPE-HMAC-SHA1-DES3-KD" },
  {  13, "cKSUMTYPE-HMAC-SHA1-DES3" },
  {  14, "cKSUMTYPE-SHA1" },
  {  15, "cKSUMTYPE-HMAC-SHA1-96-AES-128" },
  {  16, "cKSUMTYPE-HMAC-SHA1-96-AES-256" },
  {  17, "cKSUMTYPE-CMAC-CAMELLIA128" },
  {  18, "cKSUMTYPE-CMAC-CAMELLIA256" },
  {  19, "cKSUMTYPE-HMAC-SHA256-128-AES128" },
  {  20, "cKSUMTYPE-HMAC-SHA384-192-AES256" },
  { 32771, "cKSUMTYPE-GSSAPI" },
  { -138, "cKSUMTYPE-HMAC-MD5" },
  { -1138, "cKSUMTYPE-HMAC-MD5-ENC" },
  { 0, NULL }
};


static int
dissect_kerberos_CKSUMTYPE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 416 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &(private_data->checksum_type));




  return offset;
}



static int
dissect_kerberos_T_checksum(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 420 "./asn1/kerberos/kerberos.cnf"
  tvbuff_t *next_tvb;
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

  switch(private_data->checksum_type){
  case KRB5_CHKSUM_GSSAPI:
    offset=dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_index, &next_tvb);
    dissect_krb5_rfc1964_checksum(actx, tree, next_tvb);
    break;
  default:
    offset=dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_index, NULL);
    break;
  }



  return offset;
}


static const ber_sequence_t Checksum_sequence[] = {
  { &hf_kerberos_cksumtype  , BER_CLASS_CON, 0, 0, dissect_kerberos_CKSUMTYPE },
  { &hf_kerberos_checksum   , BER_CLASS_CON, 1, 0, dissect_kerberos_T_checksum },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_Checksum(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Checksum_sequence, hf_index, ett_kerberos_Checksum);

  return offset;
}



static int
dissect_kerberos_Microseconds(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_kerberos_KerberosTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_kerberos_Int32(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_kerberos_T_keytype(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 434 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

  private_data->key_hidden_item = proto_tree_add_item(tree, hf_krb_key_hidden_item,
                                                      tvb, 0, 0, ENC_NA);
  if (private_data->key_hidden_item != NULL) {
    proto_item_set_hidden(private_data->key_hidden_item);
  }

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                  &gbl_keytype);
  private_data->key.keytype = gbl_keytype;



  return offset;
}



static int
dissect_kerberos_T_keyvalue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 447 "./asn1/kerberos/kerberos.cnf"
  tvbuff_t *out_tvb;
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &out_tvb);


  private_data->key.keylength = tvb_reported_length(out_tvb);
  private_data->key.keyvalue = tvb_get_ptr(out_tvb, 0, private_data->key.keylength);
  private_data->key_tree = tree;
  private_data->key_tvb = out_tvb;



  return offset;
}


static const ber_sequence_t EncryptionKey_sequence[] = {
  { &hf_kerberos_keytype    , BER_CLASS_CON, 0, 0, dissect_kerberos_T_keytype },
  { &hf_kerberos_keyvalue   , BER_CLASS_CON, 1, 0, dissect_kerberos_T_keyvalue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncryptionKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 458 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
#ifdef HAVE_KERBEROS
  int start_offset = offset;
#endif

    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptionKey_sequence, hf_index, ett_kerberos_EncryptionKey);


  if (private_data->key.keytype != 0 && private_data->key.keylength > 0) {
#ifdef HAVE_KERBEROS
    int length = offset - start_offset;
    private_data->last_added_key = NULL;
    private_data->save_encryption_key_fn(tvb, start_offset, length, actx, tree,
                                         private_data->save_encryption_key_parent_hf_index,
                                         hf_index);
    private_data->last_added_key = NULL;
#endif
  }



  return offset;
}



static int
dissect_kerberos_T_authenticator_subkey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 477 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  gint save_encryption_key_parent_hf_index = private_data->save_encryption_key_parent_hf_index;
  kerberos_key_save_fn saved_encryption_key_fn = private_data->save_encryption_key_fn;
  private_data->save_encryption_key_parent_hf_index = hf_kerberos_authenticator;
#ifdef HAVE_KERBEROS
  private_data->save_encryption_key_fn = save_Authenticator_subkey;
#endif
  offset = dissect_kerberos_EncryptionKey(implicit_tag, tvb, offset, actx, tree, hf_index);

  private_data->save_encryption_key_parent_hf_index = save_encryption_key_parent_hf_index;
  private_data->save_encryption_key_fn = saved_encryption_key_fn;



  return offset;
}


static const value_string kerberos_AUTHDATA_TYPE_vals[] = {
  { KERBEROS_AD_IF_RELEVANT, "aD-IF-RELEVANT" },
  { KERBEROS_AD_INTENDED_FOR_SERVER, "aD-INTENDED-FOR-SERVER" },
  { KERBEROS_AD_INTENDED_FOR_APPLICATION_CLASS, "aD-INTENDED-FOR-APPLICATION-CLASS" },
  { KERBEROS_AD_KDC_ISSUED, "aD-KDC-ISSUED" },
  { KERBEROS_AD_AND_OR, "aD-AND-OR" },
  { KERBEROS_AD_MANDATORY_TICKET_EXTENSIONS, "aD-MANDATORY-TICKET-EXTENSIONS" },
  { KERBEROS_AD_IN_TICKET_EXTENSIONS, "aD-IN-TICKET-EXTENSIONS" },
  { KERBEROS_AD_MANDATORY_FOR_KDC, "aD-MANDATORY-FOR-KDC" },
  { KERBEROS_AD_INITIAL_VERIFIED_CAS, "aD-INITIAL-VERIFIED-CAS" },
  { KERBEROS_AD_OSF_DCE, "aD-OSF-DCE" },
  { KERBEROS_AD_SESAME, "aD-SESAME" },
  { KERBEROS_AD_OSF_DCE_PKI_CERTID, "aD-OSF-DCE-PKI-CERTID" },
  { KERBEROS_AD_AUTHENTICATION_STRENGTH, "aD-authentication-strength" },
  { KERBEROS_AD_FX_FAST_ARMOR, "aD-fx-fast-armor" },
  { KERBEROS_AD_FX_FAST_USED, "aD-fx-fast-used" },
  { KERBEROS_AD_WIN2K_PAC, "aD-WIN2K-PAC" },
  { KERBEROS_AD_GSS_API_ETYPE_NEGOTIATION, "aD-GSS-API-ETYPE-NEGOTIATION" },
  { KERBEROS_AD_TOKEN_RESTRICTIONS, "aD-TOKEN-RESTRICTIONS" },
  { KERBEROS_AD_LOCAL, "aD-LOCAL" },
  { KERBEROS_AD_AP_OPTIONS, "aD-AP-OPTIONS" },
  { KERBEROS_AD_TARGET_PRINCIPAL, "aD-TARGET-PRINCIPAL" },
  { KERBEROS_AD_SIGNTICKET_OLDER, "aD-SIGNTICKET-OLDER" },
  { KERBEROS_AD_SIGNTICKET, "aD-SIGNTICKET" },
  { 0, NULL }
};


static int
dissect_kerberos_AUTHDATA_TYPE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 558 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &(private_data->ad_type));




  return offset;
}



static int
dissect_kerberos_T_ad_data(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 562 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

  switch(private_data->ad_type){
  case KERBEROS_AD_WIN2K_PAC:
    offset=dissect_ber_octet_string_wcb(implicit_tag, actx, tree, tvb, offset, hf_index, dissect_krb5_AD_WIN2K_PAC);
    break;
  case KERBEROS_AD_IF_RELEVANT:
    offset=dissect_ber_octet_string_wcb(implicit_tag, actx, tree, tvb, offset, hf_index, dissect_kerberos_AD_IF_RELEVANT);
    break;
  case KERBEROS_AD_AUTHENTICATION_STRENGTH:
    offset=dissect_ber_octet_string_wcb(implicit_tag, actx, tree, tvb, offset, hf_index, dissect_kerberos_PA_AUTHENTICATION_SET_ELEM);
    break;
  case KERBEROS_AD_GSS_API_ETYPE_NEGOTIATION:
    offset=dissect_ber_octet_string_wcb(implicit_tag, actx, tree, tvb, offset, hf_index, dissect_kerberos_SEQUENCE_OF_ENCTYPE);
    break;
  case KERBEROS_AD_TOKEN_RESTRICTIONS:
    offset=dissect_ber_octet_string_wcb(implicit_tag, actx, tree, tvb, offset, hf_index, dissect_kerberos_KERB_AD_RESTRICTION_ENTRY);
    break;
  case KERBEROS_AD_AP_OPTIONS:
    offset=dissect_ber_octet_string_wcb(implicit_tag, actx, tree, tvb, offset, hf_index, dissect_kerberos_AD_AP_OPTIONS);
    break;
  case KERBEROS_AD_TARGET_PRINCIPAL:
    offset=dissect_ber_octet_string_wcb(implicit_tag, actx, tree, tvb, offset, hf_index, dissect_kerberos_AD_TARGET_PRINCIPAL);
    break;
  default:
    offset=dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);
    break;
  }



  return offset;
}


static const ber_sequence_t AuthorizationData_item_sequence[] = {
  { &hf_kerberos_ad_type    , BER_CLASS_CON, 0, 0, dissect_kerberos_AUTHDATA_TYPE },
  { &hf_kerberos_ad_data    , BER_CLASS_CON, 1, 0, dissect_kerberos_T_ad_data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_AuthorizationData_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthorizationData_item_sequence, hf_index, ett_kerberos_AuthorizationData_item);

  return offset;
}


static const ber_sequence_t AuthorizationData_sequence_of[1] = {
  { &hf_kerberos_AuthorizationData_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_kerberos_AuthorizationData_item },
};

static int
dissect_kerberos_AuthorizationData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AuthorizationData_sequence_of, hf_index, ett_kerberos_AuthorizationData);

  return offset;
}


static const ber_sequence_t Authenticator_U_sequence[] = {
  { &hf_kerberos_authenticator_vno, BER_CLASS_CON, 0, 0, dissect_kerberos_INTEGER_5 },
  { &hf_kerberos_crealm     , BER_CLASS_CON, 1, 0, dissect_kerberos_Realm },
  { &hf_kerberos_cname      , BER_CLASS_CON, 2, 0, dissect_kerberos_CName },
  { &hf_kerberos_cksum      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_kerberos_Checksum },
  { &hf_kerberos_cusec      , BER_CLASS_CON, 4, 0, dissect_kerberos_Microseconds },
  { &hf_kerberos_ctime      , BER_CLASS_CON, 5, 0, dissect_kerberos_KerberosTime },
  { &hf_kerberos_authenticator_subkey, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_kerberos_T_authenticator_subkey },
  { &hf_kerberos_seq_number , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { &hf_kerberos_authorization_data, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_kerberos_AuthorizationData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_Authenticator_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Authenticator_U_sequence, hf_index, ett_kerberos_Authenticator_U);

  return offset;
}



static int
dissect_kerberos_Authenticator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 2, FALSE, dissect_kerberos_Authenticator_U);

  return offset;
}


static int * const TicketFlags_bits[] = {
  &hf_kerberos_TicketFlags_reserved,
  &hf_kerberos_TicketFlags_forwardable,
  &hf_kerberos_TicketFlags_forwarded,
  &hf_kerberos_TicketFlags_proxiable,
  &hf_kerberos_TicketFlags_proxy,
  &hf_kerberos_TicketFlags_may_postdate,
  &hf_kerberos_TicketFlags_postdated,
  &hf_kerberos_TicketFlags_invalid,
  &hf_kerberos_TicketFlags_renewable,
  &hf_kerberos_TicketFlags_initial,
  &hf_kerberos_TicketFlags_pre_authent,
  &hf_kerberos_TicketFlags_hw_authent,
  &hf_kerberos_TicketFlags_transited_policy_checked,
  &hf_kerberos_TicketFlags_ok_as_delegate,
  &hf_kerberos_TicketFlags_unused,
  &hf_kerberos_TicketFlags_enc_pa_rep,
  &hf_kerberos_TicketFlags_anonymous,
  NULL
};

static int
dissect_kerberos_TicketFlags(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    TicketFlags_bits, 17, hf_index, ett_kerberos_TicketFlags,
                                    NULL);

  return offset;
}



static int
dissect_kerberos_T_encTicketPart_key(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 522 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  gint save_encryption_key_parent_hf_index = private_data->save_encryption_key_parent_hf_index;
  kerberos_key_save_fn saved_encryption_key_fn = private_data->save_encryption_key_fn;
  private_data->save_encryption_key_parent_hf_index = hf_kerberos_encTicketPart;
#ifdef HAVE_KERBEROS
  private_data->save_encryption_key_fn = save_EncTicketPart_key;
#endif
  offset = dissect_kerberos_EncryptionKey(implicit_tag, tvb, offset, actx, tree, hf_index);

  private_data->save_encryption_key_parent_hf_index = save_encryption_key_parent_hf_index;
  private_data->save_encryption_key_fn = saved_encryption_key_fn;



  return offset;
}



static int
dissect_kerberos_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t TransitedEncoding_sequence[] = {
  { &hf_kerberos_tr_type    , BER_CLASS_CON, 0, 0, dissect_kerberos_Int32 },
  { &hf_kerberos_contents   , BER_CLASS_CON, 1, 0, dissect_kerberos_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_TransitedEncoding(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TransitedEncoding_sequence, hf_index, ett_kerberos_TransitedEncoding);

  return offset;
}


static const value_string kerberos_ADDR_TYPE_vals[] = {
  { KERBEROS_ADDR_TYPE_IPV4, "iPv4" },
  { KERBEROS_ADDR_TYPE_CHAOS, "cHAOS" },
  { KERBEROS_ADDR_TYPE_XEROX, "xEROX" },
  { KERBEROS_ADDR_TYPE_ISO, "iSO" },
  { KERBEROS_ADDR_TYPE_DECNET, "dECNET" },
  { KERBEROS_ADDR_TYPE_APPLETALK, "aPPLETALK" },
  { KERBEROS_ADDR_TYPE_NETBIOS, "nETBIOS" },
  { KERBEROS_ADDR_TYPE_IPV6, "iPv6" },
  { 0, NULL }
};


static int
dissect_kerberos_ADDR_TYPE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 595 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &(private_data->addr_type));




  return offset;
}



static int
dissect_kerberos_T_address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 305 "./asn1/kerberos/kerberos.cnf"
  gint8 appclass;
  gboolean pc;
  gint32 tag;
  guint32 len;
  const char *address_str;
  proto_item *it=NULL;
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

  /* read header and len for the octet string */
  offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &appclass, &pc, &tag);
  offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);

  switch(private_data->addr_type){
  case KERBEROS_ADDR_TYPE_IPV4:
    it=proto_tree_add_item(tree, hf_krb_address_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
    address_str = tvb_ip_to_str(actx->pinfo->pool, tvb, offset);
    break;
  case KERBEROS_ADDR_TYPE_NETBIOS:
    {
    char netbios_name[(NETBIOS_NAME_LEN - 1)*4 + 1];
    int netbios_name_type;
    int netbios_name_len = (NETBIOS_NAME_LEN - 1)*4 + 1;

    netbios_name_type = process_netbios_name(tvb_get_ptr(tvb, offset, 16), netbios_name, netbios_name_len);
    address_str = wmem_strdup_printf(actx->pinfo->pool, "%s<%02x>", netbios_name, netbios_name_type);
    it=proto_tree_add_string_format(tree, hf_krb_address_netbios, tvb, offset, 16, netbios_name, "NetBIOS Name: %s (%s)", address_str, netbios_name_type_descr(netbios_name_type));
    }
    break;
  case KERBEROS_ADDR_TYPE_IPV6:
    it=proto_tree_add_item(tree, hf_krb_address_ipv6, tvb, offset, INET6_ADDRLEN, ENC_NA);
    address_str = tvb_ip6_to_str(actx->pinfo->pool, tvb, offset);
    break;
  default:
    proto_tree_add_expert(tree, actx->pinfo, &ei_kerberos_address, tvb, offset, len);
    address_str = NULL;
    break;
  }

  /* push it up two levels in the decode pane */
  if(it && address_str){
    proto_item_append_text(proto_item_get_parent(it), " %s",address_str);
    proto_item_append_text(proto_item_get_parent_nth(it, 2), " %s",address_str);
  }

  offset+=len;




  return offset;
}


static const ber_sequence_t HostAddress_sequence[] = {
  { &hf_kerberos_addr_type  , BER_CLASS_CON, 0, 0, dissect_kerberos_ADDR_TYPE },
  { &hf_kerberos_address    , BER_CLASS_CON, 1, 0, dissect_kerberos_T_address },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_HostAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HostAddress_sequence, hf_index, ett_kerberos_HostAddress);

  return offset;
}


static const ber_sequence_t HostAddresses_sequence_of[1] = {
  { &hf_kerberos_HostAddresses_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_kerberos_HostAddress },
};

static int
dissect_kerberos_HostAddresses(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      HostAddresses_sequence_of, hf_index, ett_kerberos_HostAddresses);

  return offset;
}


static const ber_sequence_t EncTicketPart_U_sequence[] = {
  { &hf_kerberos_flags      , BER_CLASS_CON, 0, 0, dissect_kerberos_TicketFlags },
  { &hf_kerberos_encTicketPart_key, BER_CLASS_CON, 1, 0, dissect_kerberos_T_encTicketPart_key },
  { &hf_kerberos_crealm     , BER_CLASS_CON, 2, 0, dissect_kerberos_Realm },
  { &hf_kerberos_cname      , BER_CLASS_CON, 3, 0, dissect_kerberos_CName },
  { &hf_kerberos_transited  , BER_CLASS_CON, 4, 0, dissect_kerberos_TransitedEncoding },
  { &hf_kerberos_authtime   , BER_CLASS_CON, 5, 0, dissect_kerberos_KerberosTime },
  { &hf_kerberos_starttime  , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosTime },
  { &hf_kerberos_endtime    , BER_CLASS_CON, 7, 0, dissect_kerberos_KerberosTime },
  { &hf_kerberos_renew_till , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosTime },
  { &hf_kerberos_caddr      , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_kerberos_HostAddresses },
  { &hf_kerberos_authorization_data, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_kerberos_AuthorizationData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncTicketPart_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncTicketPart_U_sequence, hf_index, ett_kerberos_EncTicketPart_U);

  return offset;
}



static int
dissect_kerberos_EncTicketPart(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 3, FALSE, dissect_kerberos_EncTicketPart_U);

  return offset;
}


static const value_string kerberos_MESSAGE_TYPE_vals[] = {
  {  10, "krb-as-req" },
  {  11, "krb-as-rep" },
  {  12, "krb-tgs-req" },
  {  13, "krb-tgs-rep" },
  {  14, "krb-ap-req" },
  {  15, "krb-ap-rep" },
  {  16, "krb-tgt-req" },
  {  17, "krb-tgt-rep" },
  {  20, "krb-safe" },
  {  21, "krb-priv" },
  {  22, "krb-cred" },
  {  30, "krb-error" },
  { 0, NULL }
};


static int
dissect_kerberos_MESSAGE_TYPE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 102 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  guint32 msgtype;

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &msgtype);




#line 108 "./asn1/kerberos/kerberos.cnf"
  if (gbl_do_col_info) {
    col_add_str(actx->pinfo->cinfo, COL_INFO,
      val_to_str(msgtype, krb5_msg_types,
      "Unknown msg type %#x"));
  }
  gbl_do_col_info=FALSE;

#if 0
  /* append the application type to the tree */
  proto_item_append_text(tree, " %s", val_to_str(msgtype, krb5_msg_types, "Unknown:0x%x"));
#endif
  if (private_data->msg_type == 0) {
    private_data->msg_type = msgtype;
  }


  return offset;
}


static const value_string kerberos_PADATA_TYPE_vals[] = {
  { KERBEROS_PA_NONE, "pA-NONE" },
  { KERBEROS_PA_TGS_REQ, "pA-TGS-REQ" },
  { KERBEROS_PA_ENC_TIMESTAMP, "pA-ENC-TIMESTAMP" },
  { KERBEROS_PA_PW_SALT, "pA-PW-SALT" },
  { KERBEROS_PA_ENC_UNIX_TIME, "pA-ENC-UNIX-TIME" },
  { KERBEROS_PA_SANDIA_SECUREID, "pA-SANDIA-SECUREID" },
  { KERBEROS_PA_SESAME, "pA-SESAME" },
  { KERBEROS_PA_OSF_DCE, "pA-OSF-DCE" },
  { KERBEROS_PA_CYBERSAFE_SECUREID, "pA-CYBERSAFE-SECUREID" },
  { KERBEROS_PA_AFS3_SALT, "pA-AFS3-SALT" },
  { KERBEROS_PA_ETYPE_INFO, "pA-ETYPE-INFO" },
  { KERBEROS_PA_SAM_CHALLENGE, "pA-SAM-CHALLENGE" },
  { KERBEROS_PA_SAM_RESPONSE, "pA-SAM-RESPONSE" },
  { KERBEROS_PA_PK_AS_REQ_19, "pA-PK-AS-REQ-19" },
  { KERBEROS_PA_PK_AS_REP_19, "pA-PK-AS-REP-19" },
  { KERBEROS_PA_PK_AS_REQ, "pA-PK-AS-REQ" },
  { KERBEROS_PA_PK_AS_REP, "pA-PK-AS-REP" },
  { KERBEROS_PA_PK_OCSP_RESPONSE, "pA-PK-OCSP-RESPONSE" },
  { KERBEROS_PA_ETYPE_INFO2, "pA-ETYPE-INFO2" },
  { KERBEROS_PA_USE_SPECIFIED_KVNO, "pA-USE-SPECIFIED-KVNO" },
  { KERBEROS_PA_SAM_REDIRECT, "pA-SAM-REDIRECT" },
  { KERBEROS_PA_GET_FROM_TYPED_DATA, "pA-GET-FROM-TYPED-DATA" },
  { KERBEROS_TD_PADATA, "tD-PADATA" },
  { KERBEROS_PA_SAM_ETYPE_INFO, "pA-SAM-ETYPE-INFO" },
  { KERBEROS_PA_ALT_PRINC, "pA-ALT-PRINC" },
  { KERBEROS_PA_SERVER_REFERRAL, "pA-SERVER-REFERRAL" },
  { KERBEROS_PA_SAM_CHALLENGE2, "pA-SAM-CHALLENGE2" },
  { KERBEROS_PA_SAM_RESPONSE2, "pA-SAM-RESPONSE2" },
  { KERBEROS_PA_EXTRA_TGT, "pA-EXTRA-TGT" },
  { KERBEROS_TD_PKINIT_CMS_CERTIFICATES, "tD-PKINIT-CMS-CERTIFICATES" },
  { KERBEROS_TD_KRB_PRINCIPAL, "tD-KRB-PRINCIPAL" },
  { KERBEROS_TD_KRB_REALM, "tD-KRB-REALM" },
  { KERBEROS_TD_TRUSTED_CERTIFIERS, "tD-TRUSTED-CERTIFIERS" },
  { KERBEROS_TD_CERTIFICATE_INDEX, "tD-CERTIFICATE-INDEX" },
  { KERBEROS_TD_APP_DEFINED_ERROR, "tD-APP-DEFINED-ERROR" },
  { KERBEROS_TD_REQ_NONCE, "tD-REQ-NONCE" },
  { KERBEROS_TD_REQ_SEQ, "tD-REQ-SEQ" },
  { KERBEROS_TD_DH_PARAMETERS, "tD-DH-PARAMETERS" },
  { KERBEROS_TD_CMS_DIGEST_ALGORITHMS, "tD-CMS-DIGEST-ALGORITHMS" },
  { KERBEROS_TD_CERT_DIGEST_ALGORITHMS, "tD-CERT-DIGEST-ALGORITHMS" },
  { KERBEROS_PA_PAC_REQUEST, "pA-PAC-REQUEST" },
  { KERBEROS_PA_FOR_USER, "pA-FOR-USER" },
  { KERBEROS_PA_FOR_X509_USER, "pA-FOR-X509-USER" },
  { KERBEROS_PA_FOR_CHECK_DUPS, "pA-FOR-CHECK-DUPS" },
  { KERBEROS_PA_PK_AS_09_BINDING, "pA-PK-AS-09-BINDING" },
  { KERBEROS_PA_FX_COOKIE, "pA-FX-COOKIE" },
  { KERBEROS_PA_AUTHENTICATION_SET, "pA-AUTHENTICATION-SET" },
  { KERBEROS_PA_AUTH_SET_SELECTED, "pA-AUTH-SET-SELECTED" },
  { KERBEROS_PA_FX_FAST, "pA-FX-FAST" },
  { KERBEROS_PA_FX_ERROR, "pA-FX-ERROR" },
  { KERBEROS_PA_ENCRYPTED_CHALLENGE, "pA-ENCRYPTED-CHALLENGE" },
  { KERBEROS_PA_OTP_CHALLENGE, "pA-OTP-CHALLENGE" },
  { KERBEROS_PA_OTP_REQUEST, "pA-OTP-REQUEST" },
  { KERBEROS_PA_OTP_CONFIRM, "pA-OTP-CONFIRM" },
  { KERBEROS_PA_OTP_PIN_CHANGE, "pA-OTP-PIN-CHANGE" },
  { KERBEROS_PA_EPAK_AS_REQ, "pA-EPAK-AS-REQ" },
  { KERBEROS_PA_EPAK_AS_REP, "pA-EPAK-AS-REP" },
  { KERBEROS_PA_PKINIT_KX, "pA-PKINIT-KX" },
  { KERBEROS_PA_PKU2U_NAME, "pA-PKU2U-NAME" },
  { KERBEROS_PA_REQ_ENC_PA_REP, "pA-REQ-ENC-PA-REP" },
  { KERBEROS_PA_SPAKE, "pA-SPAKE" },
  { KERBEROS_PA_KERB_KEY_LIST_REQ, "pA-KERB-KEY-LIST-REQ" },
  { KERBEROS_PA_KERB_KEY_LIST_REP, "pA-KERB-KEY-LIST-REP" },
  { KERBEROS_PA_SUPPORTED_ETYPES, "pA-SUPPORTED-ETYPES" },
  { KERBEROS_PA_EXTENDED_ERROR, "pA-EXTENDED-ERROR" },
  { KERBEROS_PA_PAC_OPTIONS, "pA-PAC-OPTIONS" },
  { KERBEROS_PA_PROV_SRV_LOCATION, "pA-PROV-SRV-LOCATION" },
  { 0, NULL }
};


static int
dissect_kerberos_PADATA_TYPE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 167 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t* private_data = kerberos_get_private_data(actx);
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &(private_data->padata_type));



#line 170 "./asn1/kerberos/kerberos.cnf"
  if(tree){
    proto_item_append_text(tree, " %s",
      val_to_str(private_data->padata_type, kerberos_PADATA_TYPE_vals,
      "Unknown:%d"));
  }


  return offset;
}



static int
dissect_kerberos_T_padata_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 208 "./asn1/kerberos/kerberos.cnf"
  proto_tree *sub_tree=tree;
  kerberos_private_data_t* private_data = kerberos_get_private_data(actx);

  if(actx->created_item){
    sub_tree=proto_item_add_subtree(actx->created_item, ett_kerberos_PA_DATA);
  }

  switch(private_data->padata_type){
  case KERBEROS_PA_TGS_REQ:
    private_data->within_PA_TGS_REQ++;
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_Applications);
    private_data->within_PA_TGS_REQ--;
    break;
  case KERBEROS_PA_PK_AS_REP_19:
    private_data->is_win2k_pkinit = TRUE;
    if (kerberos_private_is_kdc_req(private_data)) {
      offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_pkinit_PA_PK_AS_REQ_Win2k);
    } else {
      offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_pkinit_PA_PK_AS_REP_Win2k);
    }
    break;
  case KERBEROS_PA_PK_AS_REQ:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_pkinit_PaPkAsReq);
    break;
  case KERBEROS_PA_PK_AS_REP:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_pkinit_PaPkAsRep);
    break;
  case KERBEROS_PA_PAC_REQUEST:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_PA_PAC_REQUEST);
    break;
  case KERBEROS_PA_FOR_USER: /* S4U2SELF */
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_PA_S4U2Self);
    break;
  case KERBEROS_PA_FOR_X509_USER:
    if(private_data->msg_type == KRB5_MSG_AS_REQ){
      offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_x509af_Certificate);
    }else if(private_data->is_enc_padata){
      offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, NULL);
    }else{
      offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_PA_S4U_X509_USER);
    }
    break;
  case KERBEROS_PA_PROV_SRV_LOCATION:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_krb5_PA_PROV_SRV_LOCATION);
    break;
  case KERBEROS_PA_ENC_TIMESTAMP:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_PA_ENC_TIMESTAMP);
    break;
  case KERBEROS_PA_ETYPE_INFO:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_ETYPE_INFO);
    break;
  case KERBEROS_PA_ETYPE_INFO2:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_ETYPE_INFO2);
    break;
  case KERBEROS_PA_PW_SALT:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_krb5_PW_SALT);
    break;
  case KERBEROS_PA_AUTH_SET_SELECTED:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_PA_AUTHENTICATION_SET_ELEM);
    break;
  case KERBEROS_PA_FX_FAST:
    if (kerberos_private_is_kdc_req(private_data)) {
      offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_defer_PA_FX_FAST_REQUEST);
    }else{
      offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_PA_FX_FAST_REPLY);
    }
    break;
  case KERBEROS_PA_FX_ERROR:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_Applications);
    break;
  case KERBEROS_PA_ENCRYPTED_CHALLENGE:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_EncryptedChallenge);
    break;
  case KERBEROS_PA_KERB_KEY_LIST_REQ:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset, hf_index, dissect_kerberos_PA_KERB_KEY_LIST_REQ);
    break;
  case KERBEROS_PA_KERB_KEY_LIST_REP:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset, hf_index, dissect_kerberos_PA_KERB_KEY_LIST_REP);
    break;
  case KERBEROS_PA_SUPPORTED_ETYPES:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_PA_SUPPORTED_ENCTYPES);
    break;
  case KERBEROS_PA_PAC_OPTIONS:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset, hf_index, dissect_kerberos_PA_PAC_OPTIONS);
    break;
  case KERBEROS_PA_REQ_ENC_PA_REP:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_Checksum);
    break;
  case KERBEROS_PA_SPAKE:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_PA_SPAKE);
    break;
  default:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, NULL);
    break;
  }



  return offset;
}


static const ber_sequence_t PA_DATA_sequence[] = {
  { &hf_kerberos_padata_type, BER_CLASS_CON, 1, 0, dissect_kerberos_PADATA_TYPE },
  { &hf_kerberos_padata_value, BER_CLASS_CON, 2, 0, dissect_kerberos_T_padata_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_PA_DATA(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PA_DATA_sequence, hf_index, ett_kerberos_PA_DATA);

  return offset;
}


static const ber_sequence_t T_rEQ_SEQUENCE_OF_PA_DATA_sequence_of[1] = {
  { &hf_kerberos_rEQ_SEQUENCE_OF_PA_DATA_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_kerberos_PA_DATA },
};

static int
dissect_kerberos_T_rEQ_SEQUENCE_OF_PA_DATA(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 177 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t* private_data = kerberos_get_private_data(actx);
  struct _kerberos_PA_FX_FAST_REQUEST saved_stack = private_data->PA_FX_FAST_REQUEST;

  /*
   * we need to defer calling dissect_kerberos_PA_FX_FAST_REQUEST,
   * see dissect_kerberos_defer_PA_FX_FAST_REQUEST()
   */
  private_data->PA_FX_FAST_REQUEST = (struct _kerberos_PA_FX_FAST_REQUEST) { .defer = TRUE, };
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_rEQ_SEQUENCE_OF_PA_DATA_sequence_of, hf_index, ett_kerberos_T_rEQ_SEQUENCE_OF_PA_DATA);

  if (private_data->PA_FX_FAST_REQUEST.tvb != NULL) {
    struct _kerberos_PA_FX_FAST_REQUEST used_stack = private_data->PA_FX_FAST_REQUEST;
    private_data->PA_FX_FAST_REQUEST = (struct _kerberos_PA_FX_FAST_REQUEST) { .defer = FALSE, };

    /*
     * dissect_kerberos_defer_PA_FX_FAST_REQUEST() remembered
     * a tvb, so replay dissect_kerberos_PA_FX_FAST_REQUEST()
     * here.
     */
    dissect_kerberos_PA_FX_FAST_REQUEST(FALSE,
                                        used_stack.tvb,
                                        0,
                                        actx,
                                        used_stack.tree,
                                        -1);
  }
  private_data->PA_FX_FAST_REQUEST = saved_stack;



  return offset;
}


static int * const KDCOptions_bits[] = {
  &hf_kerberos_KDCOptions_reserved,
  &hf_kerberos_KDCOptions_forwardable,
  &hf_kerberos_KDCOptions_forwarded,
  &hf_kerberos_KDCOptions_proxiable,
  &hf_kerberos_KDCOptions_proxy,
  &hf_kerberos_KDCOptions_allow_postdate,
  &hf_kerberos_KDCOptions_postdated,
  &hf_kerberos_KDCOptions_unused7,
  &hf_kerberos_KDCOptions_renewable,
  &hf_kerberos_KDCOptions_unused9,
  &hf_kerberos_KDCOptions_unused10,
  &hf_kerberos_KDCOptions_opt_hardware_auth,
  &hf_kerberos_KDCOptions_unused12,
  &hf_kerberos_KDCOptions_unused13,
  &hf_kerberos_KDCOptions_constrained_delegation,
  &hf_kerberos_KDCOptions_canonicalize,
  &hf_kerberos_KDCOptions_request_anonymous,
  &hf_kerberos_KDCOptions_unused17,
  &hf_kerberos_KDCOptions_unused18,
  &hf_kerberos_KDCOptions_unused19,
  &hf_kerberos_KDCOptions_unused20,
  &hf_kerberos_KDCOptions_unused21,
  &hf_kerberos_KDCOptions_unused22,
  &hf_kerberos_KDCOptions_unused23,
  &hf_kerberos_KDCOptions_unused24,
  &hf_kerberos_KDCOptions_unused25,
  &hf_kerberos_KDCOptions_disable_transited_check,
  &hf_kerberos_KDCOptions_renewable_ok,
  &hf_kerberos_KDCOptions_enc_tkt_in_skey,
  &hf_kerberos_KDCOptions_unused29,
  &hf_kerberos_KDCOptions_renew,
  &hf_kerberos_KDCOptions_validate,
  NULL
};

static int
dissect_kerberos_KDCOptions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    KDCOptions_bits, 32, hf_index, ett_kerberos_KDCOptions,
                                    NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ENCTYPE_sequence_of[1] = {
  { &hf_kerberos_kDC_REQ_BODY_etype_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_kerberos_ENCTYPE },
};

static int
dissect_kerberos_SEQUENCE_OF_ENCTYPE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ENCTYPE_sequence_of, hf_index, ett_kerberos_SEQUENCE_OF_ENCTYPE);

  return offset;
}



static int
dissect_kerberos_T_encryptedAuthorizationData_cipher(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 367 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
  offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_authorization_data);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif



  return offset;
}


static const ber_sequence_t EncryptedAuthorizationData_sequence[] = {
  { &hf_kerberos_etype      , BER_CLASS_CON, 0, 0, dissect_kerberos_ENCTYPE },
  { &hf_kerberos_kvno       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { &hf_kerberos_encryptedAuthorizationData_cipher, BER_CLASS_CON, 2, 0, dissect_kerberos_T_encryptedAuthorizationData_cipher },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncryptedAuthorizationData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedAuthorizationData_sequence, hf_index, ett_kerberos_EncryptedAuthorizationData);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Ticket_sequence_of[1] = {
  { &hf_kerberos_additional_tickets_item, BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_kerberos_Ticket },
};

static int
dissect_kerberos_SEQUENCE_OF_Ticket(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Ticket_sequence_of, hf_index, ett_kerberos_SEQUENCE_OF_Ticket);

  return offset;
}


static const ber_sequence_t KDC_REQ_BODY_sequence[] = {
  { &hf_kerberos_kdc_options, BER_CLASS_CON, 0, 0, dissect_kerberos_KDCOptions },
  { &hf_kerberos_cname      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_CName },
  { &hf_kerberos_realm      , BER_CLASS_CON, 2, 0, dissect_kerberos_Realm },
  { &hf_kerberos_sname      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_kerberos_SName },
  { &hf_kerberos_from       , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosTime },
  { &hf_kerberos_till       , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosTime },
  { &hf_kerberos_rtime      , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosTime },
  { &hf_kerberos_nonce      , BER_CLASS_CON, 7, 0, dissect_kerberos_UInt32 },
  { &hf_kerberos_kDC_REQ_BODY_etype, BER_CLASS_CON, 8, 0, dissect_kerberos_SEQUENCE_OF_ENCTYPE },
  { &hf_kerberos_addresses  , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_kerberos_HostAddresses },
  { &hf_kerberos_enc_authorization_data, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_kerberos_EncryptedAuthorizationData },
  { &hf_kerberos_additional_tickets, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_kerberos_SEQUENCE_OF_Ticket },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_KDC_REQ_BODY(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 599 "./asn1/kerberos/kerberos.cnf"
  conversation_t *conversation;

  /*
   * UDP replies to KDC_REQs are sent from the server back to the client's
   * source port, similar to the way TFTP works.  Set up a conversation
   * accordingly.
   *
   * Ref: Section 7.2.1 of
   * http://www.ietf.org/internet-drafts/draft-ietf-krb-wg-kerberos-clarifications-07.txt
   */
  if (actx->pinfo->destport == UDP_PORT_KERBEROS && actx->pinfo->ptype == PT_UDP) {
    conversation = find_conversation(actx->pinfo->num, &actx->pinfo->src, &actx->pinfo->dst, CONVERSATION_UDP,
                      actx->pinfo->srcport, 0, NO_PORT_B);
    if (conversation == NULL) {
      conversation = conversation_new(actx->pinfo->num, &actx->pinfo->src, &actx->pinfo->dst, CONVERSATION_UDP,
                      actx->pinfo->srcport, 0, NO_PORT2);
      conversation_set_dissector(conversation, kerberos_handle_udp);
    }
  }

    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KDC_REQ_BODY_sequence, hf_index, ett_kerberos_KDC_REQ_BODY);




  return offset;
}


static const ber_sequence_t KDC_REQ_sequence[] = {
  { &hf_kerberos_pvno       , BER_CLASS_CON, 1, 0, dissect_kerberos_INTEGER_5 },
  { &hf_kerberos_msg_type   , BER_CLASS_CON, 2, 0, dissect_kerberos_MESSAGE_TYPE },
  { &hf_kerberos_rEQ_SEQUENCE_OF_PA_DATA, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_kerberos_T_rEQ_SEQUENCE_OF_PA_DATA },
  { &hf_kerberos_req_body   , BER_CLASS_CON, 4, 0, dissect_kerberos_KDC_REQ_BODY },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_KDC_REQ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KDC_REQ_sequence, hf_index, ett_kerberos_KDC_REQ);

  return offset;
}



static int
dissect_kerberos_AS_REQ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 10, FALSE, dissect_kerberos_KDC_REQ);

  return offset;
}


static const ber_sequence_t T_rEP_SEQUENCE_OF_PA_DATA_sequence_of[1] = {
  { &hf_kerberos_rEP_SEQUENCE_OF_PA_DATA_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_kerberos_PA_DATA },
};

static int
dissect_kerberos_T_rEP_SEQUENCE_OF_PA_DATA(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 205 "./asn1/kerberos/kerberos.cnf"
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_rEP_SEQUENCE_OF_PA_DATA_sequence_of, hf_index, ett_kerberos_T_rEP_SEQUENCE_OF_PA_DATA);




  return offset;
}



static int
dissect_kerberos_T_encryptedKDCREPData_cipher(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 381 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
  offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_KDC_REP_data);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif



  return offset;
}


static const ber_sequence_t EncryptedKDCREPData_sequence[] = {
  { &hf_kerberos_etype      , BER_CLASS_CON, 0, 0, dissect_kerberos_ENCTYPE },
  { &hf_kerberos_kvno       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { &hf_kerberos_encryptedKDCREPData_cipher, BER_CLASS_CON, 2, 0, dissect_kerberos_T_encryptedKDCREPData_cipher },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncryptedKDCREPData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedKDCREPData_sequence, hf_index, ett_kerberos_EncryptedKDCREPData);

  return offset;
}


static const ber_sequence_t KDC_REP_sequence[] = {
  { &hf_kerberos_pvno       , BER_CLASS_CON, 0, 0, dissect_kerberos_INTEGER_5 },
  { &hf_kerberos_msg_type   , BER_CLASS_CON, 1, 0, dissect_kerberos_MESSAGE_TYPE },
  { &hf_kerberos_rEP_SEQUENCE_OF_PA_DATA, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_kerberos_T_rEP_SEQUENCE_OF_PA_DATA },
  { &hf_kerberos_crealm     , BER_CLASS_CON, 3, 0, dissect_kerberos_Realm },
  { &hf_kerberos_cname      , BER_CLASS_CON, 4, 0, dissect_kerberos_CName },
  { &hf_kerberos_ticket     , BER_CLASS_CON, 5, 0, dissect_kerberos_Ticket },
  { &hf_kerberos_kDC_REP_enc_part, BER_CLASS_CON, 6, 0, dissect_kerberos_EncryptedKDCREPData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_KDC_REP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KDC_REP_sequence, hf_index, ett_kerberos_KDC_REP);

  return offset;
}



static int
dissect_kerberos_AS_REP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 11, FALSE, dissect_kerberos_KDC_REP);

  return offset;
}



static int
dissect_kerberos_TGS_REQ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 12, FALSE, dissect_kerberos_KDC_REQ);

  return offset;
}



static int
dissect_kerberos_TGS_REP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 13, FALSE, dissect_kerberos_KDC_REP);

  return offset;
}


static int * const APOptions_bits[] = {
  &hf_kerberos_APOptions_reserved,
  &hf_kerberos_APOptions_use_session_key,
  &hf_kerberos_APOptions_mutual_required,
  NULL
};

static int
dissect_kerberos_APOptions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    APOptions_bits, 3, hf_index, ett_kerberos_APOptions,
                                    NULL);

  return offset;
}



static int
dissect_kerberos_T_encryptedAuthenticator_cipher(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 374 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
  offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_authenticator_data);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif



  return offset;
}


static const ber_sequence_t EncryptedAuthenticator_sequence[] = {
  { &hf_kerberos_etype      , BER_CLASS_CON, 0, 0, dissect_kerberos_ENCTYPE },
  { &hf_kerberos_kvno       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { &hf_kerberos_encryptedAuthenticator_cipher, BER_CLASS_CON, 2, 0, dissect_kerberos_T_encryptedAuthenticator_cipher },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncryptedAuthenticator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedAuthenticator_sequence, hf_index, ett_kerberos_EncryptedAuthenticator);

  return offset;
}


static const ber_sequence_t AP_REQ_U_sequence[] = {
  { &hf_kerberos_pvno       , BER_CLASS_CON, 0, 0, dissect_kerberos_INTEGER_5 },
  { &hf_kerberos_msg_type   , BER_CLASS_CON, 1, 0, dissect_kerberos_MESSAGE_TYPE },
  { &hf_kerberos_ap_options , BER_CLASS_CON, 2, 0, dissect_kerberos_APOptions },
  { &hf_kerberos_ticket     , BER_CLASS_CON, 3, 0, dissect_kerberos_Ticket },
  { &hf_kerberos_authenticator_enc_part, BER_CLASS_CON, 4, 0, dissect_kerberos_EncryptedAuthenticator },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_AP_REQ_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AP_REQ_U_sequence, hf_index, ett_kerberos_AP_REQ_U);

  return offset;
}



static int
dissect_kerberos_AP_REQ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 14, FALSE, dissect_kerberos_AP_REQ_U);

  return offset;
}



static int
dissect_kerberos_T_encryptedAPREPData_cipher(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 395 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
  offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_AP_REP_data);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif



  return offset;
}


static const ber_sequence_t EncryptedAPREPData_sequence[] = {
  { &hf_kerberos_etype      , BER_CLASS_CON, 0, 0, dissect_kerberos_ENCTYPE },
  { &hf_kerberos_kvno       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { &hf_kerberos_encryptedAPREPData_cipher, BER_CLASS_CON, 2, 0, dissect_kerberos_T_encryptedAPREPData_cipher },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncryptedAPREPData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedAPREPData_sequence, hf_index, ett_kerberos_EncryptedAPREPData);

  return offset;
}


static const ber_sequence_t AP_REP_U_sequence[] = {
  { &hf_kerberos_pvno       , BER_CLASS_CON, 0, 0, dissect_kerberos_INTEGER_5 },
  { &hf_kerberos_msg_type   , BER_CLASS_CON, 1, 0, dissect_kerberos_MESSAGE_TYPE },
  { &hf_kerberos_aP_REP_enc_part, BER_CLASS_CON, 2, 0, dissect_kerberos_EncryptedAPREPData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_AP_REP_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AP_REP_U_sequence, hf_index, ett_kerberos_AP_REP_U);

  return offset;
}



static int
dissect_kerberos_AP_REP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 15, FALSE, dissect_kerberos_AP_REP_U);

  return offset;
}



static int
dissect_kerberos_T_kRB_SAFE_BODY_user_data(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 622 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t* private_data = kerberos_get_private_data(actx);
  tvbuff_t *new_tvb;
  offset=dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_index, &new_tvb);
  if (new_tvb) {
    call_kerberos_callbacks(actx->pinfo, tree, new_tvb, KRB_CBTAG_SAFE_USER_DATA, private_data->callbacks);
  }



  return offset;
}


static const ber_sequence_t KRB_SAFE_BODY_sequence[] = {
  { &hf_kerberos_kRB_SAFE_BODY_user_data, BER_CLASS_CON, 0, 0, dissect_kerberos_T_kRB_SAFE_BODY_user_data },
  { &hf_kerberos_timestamp  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosTime },
  { &hf_kerberos_usec       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_kerberos_Microseconds },
  { &hf_kerberos_seq_number , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { &hf_kerberos_s_address  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_kerberos_HostAddress },
  { &hf_kerberos_r_address  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_kerberos_HostAddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_KRB_SAFE_BODY(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KRB_SAFE_BODY_sequence, hf_index, ett_kerberos_KRB_SAFE_BODY);

  return offset;
}


static const ber_sequence_t KRB_SAFE_U_sequence[] = {
  { &hf_kerberos_pvno       , BER_CLASS_CON, 0, 0, dissect_kerberos_INTEGER_5 },
  { &hf_kerberos_msg_type   , BER_CLASS_CON, 1, 0, dissect_kerberos_MESSAGE_TYPE },
  { &hf_kerberos_safe_body  , BER_CLASS_CON, 2, 0, dissect_kerberos_KRB_SAFE_BODY },
  { &hf_kerberos_cksum      , BER_CLASS_CON, 3, 0, dissect_kerberos_Checksum },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_KRB_SAFE_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KRB_SAFE_U_sequence, hf_index, ett_kerberos_KRB_SAFE_U);

  return offset;
}



static int
dissect_kerberos_KRB_SAFE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 20, FALSE, dissect_kerberos_KRB_SAFE_U);

  return offset;
}



static int
dissect_kerberos_T_encryptedKrbPrivData_cipher(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 402 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
  offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_PRIV_data);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif



  return offset;
}


static const ber_sequence_t EncryptedKrbPrivData_sequence[] = {
  { &hf_kerberos_etype      , BER_CLASS_CON, 0, 0, dissect_kerberos_ENCTYPE },
  { &hf_kerberos_kvno       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { &hf_kerberos_encryptedKrbPrivData_cipher, BER_CLASS_CON, 2, 0, dissect_kerberos_T_encryptedKrbPrivData_cipher },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncryptedKrbPrivData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedKrbPrivData_sequence, hf_index, ett_kerberos_EncryptedKrbPrivData);

  return offset;
}


static const ber_sequence_t KRB_PRIV_U_sequence[] = {
  { &hf_kerberos_pvno       , BER_CLASS_CON, 0, 0, dissect_kerberos_INTEGER_5 },
  { &hf_kerberos_msg_type   , BER_CLASS_CON, 1, 0, dissect_kerberos_MESSAGE_TYPE },
  { &hf_kerberos_kRB_PRIV_enc_part, BER_CLASS_CON, 3, 0, dissect_kerberos_EncryptedKrbPrivData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_KRB_PRIV_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KRB_PRIV_U_sequence, hf_index, ett_kerberos_KRB_PRIV_U);

  return offset;
}



static int
dissect_kerberos_KRB_PRIV(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 21, FALSE, dissect_kerberos_KRB_PRIV_U);

  return offset;
}



static int
dissect_kerberos_T_encryptedKrbCredData_cipher(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 409 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
  offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_CRED_data);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif



  return offset;
}


static const ber_sequence_t EncryptedKrbCredData_sequence[] = {
  { &hf_kerberos_etype      , BER_CLASS_CON, 0, 0, dissect_kerberos_ENCTYPE },
  { &hf_kerberos_kvno       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { &hf_kerberos_encryptedKrbCredData_cipher, BER_CLASS_CON, 2, 0, dissect_kerberos_T_encryptedKrbCredData_cipher },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncryptedKrbCredData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedKrbCredData_sequence, hf_index, ett_kerberos_EncryptedKrbCredData);

  return offset;
}


static const ber_sequence_t KRB_CRED_U_sequence[] = {
  { &hf_kerberos_pvno       , BER_CLASS_CON, 0, 0, dissect_kerberos_INTEGER_5 },
  { &hf_kerberos_msg_type   , BER_CLASS_CON, 1, 0, dissect_kerberos_MESSAGE_TYPE },
  { &hf_kerberos_tickets    , BER_CLASS_CON, 2, 0, dissect_kerberos_SEQUENCE_OF_Ticket },
  { &hf_kerberos_kRB_CRED_enc_part, BER_CLASS_CON, 3, 0, dissect_kerberos_EncryptedKrbCredData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_KRB_CRED_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KRB_CRED_U_sequence, hf_index, ett_kerberos_KRB_CRED_U);

  return offset;
}



static int
dissect_kerberos_KRB_CRED(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 22, FALSE, dissect_kerberos_KRB_CRED_U);

  return offset;
}



static int
dissect_kerberos_T_encKDCRepPart_key(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 501 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  gint save_encryption_key_parent_hf_index = private_data->save_encryption_key_parent_hf_index;
  kerberos_key_save_fn saved_encryption_key_fn = private_data->save_encryption_key_fn;
  switch (private_data->msg_type) {
  case KERBEROS_APPLICATIONS_AS_REP:
    private_data->save_encryption_key_parent_hf_index = hf_kerberos_encASRepPart;
    break;
  case KERBEROS_APPLICATIONS_TGS_REP:
    private_data->save_encryption_key_parent_hf_index = hf_kerberos_encTGSRepPart;
    break;
  default:
    private_data->save_encryption_key_parent_hf_index = -1;
  }
#ifdef HAVE_KERBEROS
  private_data->save_encryption_key_fn = save_EncKDCRepPart_key;
#endif
  offset = dissect_kerberos_EncryptionKey(implicit_tag, tvb, offset, actx, tree, hf_index);

  private_data->save_encryption_key_parent_hf_index = save_encryption_key_parent_hf_index;
  private_data->save_encryption_key_fn = saved_encryption_key_fn;



  return offset;
}


static const value_string kerberos_LR_TYPE_vals[] = {
  {   0, "lR-NONE" },
  {   1, "lR-INITIAL-TGT" },
  {   2, "lR-INITIAL" },
  {   3, "lR-ISSUE-USE-TGT" },
  {   4, "lR-RENEWAL" },
  {   5, "lR-REQUEST" },
  {   6, "lR-PW-EXPTIME" },
  {   7, "lR-ACCT-EXPTIME" },
  { 0, NULL }
};


static int
dissect_kerberos_LR_TYPE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t LastReq_item_sequence[] = {
  { &hf_kerberos_lr_type    , BER_CLASS_CON, 0, 0, dissect_kerberos_LR_TYPE },
  { &hf_kerberos_lr_value   , BER_CLASS_CON, 1, 0, dissect_kerberos_KerberosTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_LastReq_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LastReq_item_sequence, hf_index, ett_kerberos_LastReq_item);

  return offset;
}


static const ber_sequence_t LastReq_sequence_of[1] = {
  { &hf_kerberos_LastReq_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_kerberos_LastReq_item },
};

static int
dissect_kerberos_LastReq(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      LastReq_sequence_of, hf_index, ett_kerberos_LastReq);

  return offset;
}


static const ber_sequence_t METHOD_DATA_sequence_of[1] = {
  { &hf_kerberos_METHOD_DATA_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_kerberos_PA_DATA },
};

static int
dissect_kerberos_METHOD_DATA(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      METHOD_DATA_sequence_of, hf_index, ett_kerberos_METHOD_DATA);

  return offset;
}



static int
dissect_kerberos_T_encrypted_pa_data(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 638 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t* private_data = kerberos_get_private_data(actx);
  private_data->is_enc_padata = TRUE;


  offset = dissect_kerberos_METHOD_DATA(implicit_tag, tvb, offset, actx, tree, hf_index);

#line 642 "./asn1/kerberos/kerberos.cnf"
  private_data->is_enc_padata = FALSE;


  return offset;
}


static const ber_sequence_t EncKDCRepPart_sequence[] = {
  { &hf_kerberos_encKDCRepPart_key, BER_CLASS_CON, 0, 0, dissect_kerberos_T_encKDCRepPart_key },
  { &hf_kerberos_last_req   , BER_CLASS_CON, 1, 0, dissect_kerberos_LastReq },
  { &hf_kerberos_nonce      , BER_CLASS_CON, 2, 0, dissect_kerberos_UInt32 },
  { &hf_kerberos_key_expiration, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosTime },
  { &hf_kerberos_flags      , BER_CLASS_CON, 4, 0, dissect_kerberos_TicketFlags },
  { &hf_kerberos_authtime   , BER_CLASS_CON, 5, 0, dissect_kerberos_KerberosTime },
  { &hf_kerberos_starttime  , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosTime },
  { &hf_kerberos_endtime    , BER_CLASS_CON, 7, 0, dissect_kerberos_KerberosTime },
  { &hf_kerberos_renew_till , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosTime },
  { &hf_kerberos_srealm     , BER_CLASS_CON, 9, 0, dissect_kerberos_Realm },
  { &hf_kerberos_sname      , BER_CLASS_CON, 10, 0, dissect_kerberos_SName },
  { &hf_kerberos_caddr      , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_kerberos_HostAddresses },
  { &hf_kerberos_encrypted_pa_data, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_kerberos_T_encrypted_pa_data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncKDCRepPart(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncKDCRepPart_sequence, hf_index, ett_kerberos_EncKDCRepPart);

  return offset;
}



static int
dissect_kerberos_EncASRepPart(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 25, FALSE, dissect_kerberos_EncKDCRepPart);

  return offset;
}



static int
dissect_kerberos_EncTGSRepPart(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 26, FALSE, dissect_kerberos_EncKDCRepPart);

  return offset;
}



static int
dissect_kerberos_T_encAPRepPart_subkey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 489 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  gint save_encryption_key_parent_hf_index = private_data->save_encryption_key_parent_hf_index;
  kerberos_key_save_fn saved_encryption_key_fn = private_data->save_encryption_key_fn;
  private_data->save_encryption_key_parent_hf_index = hf_kerberos_encAPRepPart;
#ifdef HAVE_KERBEROS
  private_data->save_encryption_key_fn = save_EncAPRepPart_subkey;
#endif
  offset = dissect_kerberos_EncryptionKey(implicit_tag, tvb, offset, actx, tree, hf_index);

  private_data->save_encryption_key_parent_hf_index = save_encryption_key_parent_hf_index;
  private_data->save_encryption_key_fn = saved_encryption_key_fn;



  return offset;
}


static const ber_sequence_t EncAPRepPart_U_sequence[] = {
  { &hf_kerberos_ctime      , BER_CLASS_CON, 0, 0, dissect_kerberos_KerberosTime },
  { &hf_kerberos_cusec      , BER_CLASS_CON, 1, 0, dissect_kerberos_Microseconds },
  { &hf_kerberos_encAPRepPart_subkey, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_kerberos_T_encAPRepPart_subkey },
  { &hf_kerberos_seq_number , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncAPRepPart_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncAPRepPart_U_sequence, hf_index, ett_kerberos_EncAPRepPart_U);

  return offset;
}



static int
dissect_kerberos_EncAPRepPart(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 27, FALSE, dissect_kerberos_EncAPRepPart_U);

  return offset;
}



static int
dissect_kerberos_T_encKrbPrivPart_user_data(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 630 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t* private_data = kerberos_get_private_data(actx);
  tvbuff_t *new_tvb;
  offset=dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_index, &new_tvb);
  if (new_tvb) {
    call_kerberos_callbacks(actx->pinfo, tree, new_tvb, KRB_CBTAG_PRIV_USER_DATA, private_data->callbacks);
  }



  return offset;
}


static const ber_sequence_t EncKrbPrivPart_sequence[] = {
  { &hf_kerberos_encKrbPrivPart_user_data, BER_CLASS_CON, 0, 0, dissect_kerberos_T_encKrbPrivPart_user_data },
  { &hf_kerberos_timestamp  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosTime },
  { &hf_kerberos_usec       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_kerberos_Microseconds },
  { &hf_kerberos_seq_number , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { &hf_kerberos_s_address  , BER_CLASS_CON, 4, 0, dissect_kerberos_HostAddress },
  { &hf_kerberos_r_address  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_kerberos_HostAddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncKrbPrivPart(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncKrbPrivPart_sequence, hf_index, ett_kerberos_EncKrbPrivPart);

  return offset;
}



static int
dissect_kerberos_ENC_KRB_PRIV_PART(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 28, FALSE, dissect_kerberos_EncKrbPrivPart);

  return offset;
}



static int
dissect_kerberos_T_krbCredInfo_key(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 534 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  gint save_encryption_key_parent_hf_index = private_data->save_encryption_key_parent_hf_index;
  kerberos_key_save_fn saved_encryption_key_fn = private_data->save_encryption_key_fn;
  private_data->save_encryption_key_parent_hf_index = hf_kerberos_ticket_info_item;
#ifdef HAVE_KERBEROS
  private_data->save_encryption_key_fn = save_KrbCredInfo_key;
#endif
  offset = dissect_kerberos_EncryptionKey(implicit_tag, tvb, offset, actx, tree, hf_index);

  private_data->save_encryption_key_parent_hf_index = save_encryption_key_parent_hf_index;
  private_data->save_encryption_key_fn = saved_encryption_key_fn;



  return offset;
}


static const ber_sequence_t SEQUENCE_OF_KerberosString_sequence_of[1] = {
  { &hf_kerberos_name_string_item, BER_CLASS_UNI, BER_UNI_TAG_GeneralString, BER_FLAGS_NOOWNTAG, dissect_kerberos_KerberosString },
};

static int
dissect_kerberos_SEQUENCE_OF_KerberosString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_KerberosString_sequence_of, hf_index, ett_kerberos_SEQUENCE_OF_KerberosString);

  return offset;
}


static const ber_sequence_t PrincipalName_sequence[] = {
  { &hf_kerberos_name_type  , BER_CLASS_CON, 0, 0, dissect_kerberos_NAME_TYPE },
  { &hf_kerberos_name_string, BER_CLASS_CON, 1, 0, dissect_kerberos_SEQUENCE_OF_KerberosString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_PrincipalName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PrincipalName_sequence, hf_index, ett_kerberos_PrincipalName);

  return offset;
}


static const ber_sequence_t KrbCredInfo_sequence[] = {
  { &hf_kerberos_krbCredInfo_key, BER_CLASS_CON, 0, 0, dissect_kerberos_T_krbCredInfo_key },
  { &hf_kerberos_prealm     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_Realm },
  { &hf_kerberos_pname      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_kerberos_PrincipalName },
  { &hf_kerberos_flags      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_kerberos_TicketFlags },
  { &hf_kerberos_authtime   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosTime },
  { &hf_kerberos_starttime  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosTime },
  { &hf_kerberos_endtime    , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosTime },
  { &hf_kerberos_renew_till , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosTime },
  { &hf_kerberos_srealm     , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_kerberos_Realm },
  { &hf_kerberos_sname      , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_kerberos_SName },
  { &hf_kerberos_caddr      , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_kerberos_HostAddresses },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_KrbCredInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KrbCredInfo_sequence, hf_index, ett_kerberos_KrbCredInfo);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_KrbCredInfo_sequence_of[1] = {
  { &hf_kerberos_ticket_info_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_kerberos_KrbCredInfo },
};

static int
dissect_kerberos_SEQUENCE_OF_KrbCredInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_KrbCredInfo_sequence_of, hf_index, ett_kerberos_SEQUENCE_OF_KrbCredInfo);

  return offset;
}


static const ber_sequence_t EncKrbCredPart_U_sequence[] = {
  { &hf_kerberos_ticket_info, BER_CLASS_CON, 0, 0, dissect_kerberos_SEQUENCE_OF_KrbCredInfo },
  { &hf_kerberos_nonce      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { &hf_kerberos_timestamp  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosTime },
  { &hf_kerberos_usec       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_kerberos_Microseconds },
  { &hf_kerberos_s_address  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_kerberos_HostAddress },
  { &hf_kerberos_r_address  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_kerberos_HostAddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncKrbCredPart_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncKrbCredPart_U_sequence, hf_index, ett_kerberos_EncKrbCredPart_U);

  return offset;
}



static int
dissect_kerberos_EncKrbCredPart(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 29, FALSE, dissect_kerberos_EncKrbCredPart_U);

  return offset;
}


static const value_string kerberos_ERROR_CODE_vals[] = {
  {   0, "eRR-NONE" },
  {   1, "eRR-NAME-EXP" },
  {   2, "eRR-SERVICE-EXP" },
  {   3, "eRR-BAD-PVNO" },
  {   4, "eRR-C-OLD-MAST-KVNO" },
  {   5, "eRR-S-OLD-MAST-KVNO" },
  {   6, "eRR-C-PRINCIPAL-UNKNOWN" },
  {   7, "eRR-S-PRINCIPAL-UNKNOWN" },
  {   8, "eRR-PRINCIPAL-NOT-UNIQUE" },
  {   9, "eRR-NULL-KEY" },
  {  10, "eRR-CANNOT-POSTDATE" },
  {  11, "eRR-NEVER-VALID" },
  {  12, "eRR-POLICY" },
  {  13, "eRR-BADOPTION" },
  {  14, "eRR-ETYPE-NOSUPP" },
  {  15, "eRR-SUMTYPE-NOSUPP" },
  {  16, "eRR-PADATA-TYPE-NOSUPP" },
  {  17, "eRR-TRTYPE-NOSUPP" },
  {  18, "eRR-CLIENT-REVOKED" },
  {  19, "eRR-SERVICE-REVOKED" },
  {  20, "eRR-TGT-REVOKED" },
  {  21, "eRR-CLIENT-NOTYET" },
  {  22, "eRR-SERVICE-NOTYET" },
  {  23, "eRR-KEY-EXP" },
  {  24, "eRR-PREAUTH-FAILED" },
  {  25, "eRR-PREAUTH-REQUIRED" },
  {  26, "eRR-SERVER-NOMATCH" },
  {  27, "eRR-MUST-USE-USER2USER" },
  {  28, "eRR-PATH-NOT-ACCEPTED" },
  {  29, "eRR-SVC-UNAVAILABLE" },
  {  31, "eRR-BAD-INTEGRITY" },
  {  32, "eRR-TKT-EXPIRED" },
  {  33, "eRR-TKT-NYV" },
  {  34, "eRR-REPEAT" },
  {  35, "eRR-NOT-US" },
  {  36, "eRR-BADMATCH" },
  {  37, "eRR-SKEW" },
  {  38, "eRR-BADADDR" },
  {  39, "eRR-BADVERSION" },
  {  40, "eRR-MSG-TYPE" },
  {  41, "eRR-MODIFIED" },
  {  42, "eRR-BADORDER" },
  {  43, "eRR-ILL-CR-TKT" },
  {  44, "eRR-BADKEYVER" },
  {  45, "eRR-NOKEY" },
  {  46, "eRR-MUT-FAIL" },
  {  47, "eRR-BADDIRECTION" },
  {  48, "eRR-METHOD" },
  {  49, "eRR-BADSEQ" },
  {  50, "eRR-INAPP-CKSUM" },
  {  51, "pATH-NOT-ACCEPTED" },
  {  52, "eRR-RESPONSE-TOO-BIG" },
  {  60, "eRR-GENERIC" },
  {  61, "eRR-FIELD-TOOLONG" },
  {  62, "eRROR-CLIENT-NOT-TRUSTED" },
  {  63, "eRROR-KDC-NOT-TRUSTED" },
  {  64, "eRROR-INVALID-SIG" },
  {  65, "eRR-KEY-TOO-WEAK" },
  {  66, "eRR-CERTIFICATE-MISMATCH" },
  {  67, "eRR-NO-TGT" },
  {  68, "eRR-WRONG-REALM" },
  {  69, "eRR-USER-TO-USER-REQUIRED" },
  {  70, "eRR-CANT-VERIFY-CERTIFICATE" },
  {  71, "eRR-INVALID-CERTIFICATE" },
  {  72, "eRR-REVOKED-CERTIFICATE" },
  {  73, "eRR-REVOCATION-STATUS-UNKNOWN" },
  {  74, "eRR-REVOCATION-STATUS-UNAVAILABLE" },
  {  75, "eRR-CLIENT-NAME-MISMATCH" },
  {  76, "eRR-KDC-NAME-MISMATCH" },
  { 0, NULL }
};


static int
dissect_kerberos_ERROR_CODE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 124 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &private_data->errorcode);




#line 128 "./asn1/kerberos/kerberos.cnf"
  if (private_data->errorcode) {
    col_add_fstr(actx->pinfo->cinfo, COL_INFO,
      "KRB Error: %s",
      val_to_str(private_data->errorcode, krb5_error_codes,
      "Unknown error code %#x"));
  }


  return offset;
}



static int
dissect_kerberos_T_e_data(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 137 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

  switch (private_data->errorcode) {
  case KRB5_ET_KRB5KDC_ERR_BADOPTION:
  case KRB5_ET_KRB5KDC_ERR_CLIENT_REVOKED:
  case KRB5_ET_KRB5KDC_ERR_KEY_EXP:
  case KRB5_ET_KRB5KDC_ERR_POLICY:
    /* ms windows kdc sends e-data of this type containing a "salt"
     * that contains the nt_status code for these error codes.
     */
    private_data->try_nt_status = TRUE;
    offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_kerberos_e_data, dissect_kerberos_PA_DATA);
    break;
  case KRB5_ET_KRB5KDC_ERR_PREAUTH_REQUIRED:
  case KRB5_ET_KRB5KDC_ERR_PREAUTH_FAILED:
  case KRB5_ET_KRB5KDC_ERR_ETYPE_NOSUPP:
  case KRB5_ET_KDC_ERR_WRONG_REALM:
  case KRB5_ET_KDC_ERR_PREAUTH_EXPIRED:
  case KRB5_ET_KDC_ERR_MORE_PREAUTH_DATA_REQUIRED:
  case KRB5_ET_KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET:
  case KRB5_ET_KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS:
    offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_kerberos_e_data, dissect_kerberos_T_rEP_SEQUENCE_OF_PA_DATA);
    break;
  default:
    offset=dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_kerberos_e_data, NULL);
    break;
  }




  return offset;
}


static const ber_sequence_t KRB_ERROR_U_sequence[] = {
  { &hf_kerberos_pvno       , BER_CLASS_CON, 0, 0, dissect_kerberos_INTEGER_5 },
  { &hf_kerberos_msg_type   , BER_CLASS_CON, 1, 0, dissect_kerberos_MESSAGE_TYPE },
  { &hf_kerberos_ctime      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosTime },
  { &hf_kerberos_cusec      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_kerberos_Microseconds },
  { &hf_kerberos_stime      , BER_CLASS_CON, 4, 0, dissect_kerberos_KerberosTime },
  { &hf_kerberos_susec      , BER_CLASS_CON, 5, 0, dissect_kerberos_Microseconds },
  { &hf_kerberos_error_code , BER_CLASS_CON, 6, 0, dissect_kerberos_ERROR_CODE },
  { &hf_kerberos_crealm     , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_kerberos_Realm },
  { &hf_kerberos_cname      , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_kerberos_CName },
  { &hf_kerberos_realm      , BER_CLASS_CON, 9, 0, dissect_kerberos_Realm },
  { &hf_kerberos_sname      , BER_CLASS_CON, 10, 0, dissect_kerberos_SName },
  { &hf_kerberos_e_text     , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosString },
  { &hf_kerberos_e_data     , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_kerberos_T_e_data },
  { &hf_kerberos_e_checksum , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL, dissect_kerberos_Checksum },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_KRB_ERROR_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KRB_ERROR_U_sequence, hf_index, ett_kerberos_KRB_ERROR_U);

  return offset;
}



static int
dissect_kerberos_KRB_ERROR(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 30, FALSE, dissect_kerberos_KRB_ERROR_U);

  return offset;
}


static const ber_choice_t Applications_choice[] = {
  { KERBEROS_APPLICATIONS_TICKET, &hf_kerberos_ticket     , BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_kerberos_Ticket },
  { KERBEROS_APPLICATIONS_AUTHENTICATOR, &hf_kerberos_authenticator, BER_CLASS_APP, 2, BER_FLAGS_NOOWNTAG, dissect_kerberos_Authenticator },
  { KERBEROS_APPLICATIONS_ENCTICKETPART, &hf_kerberos_encTicketPart, BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_kerberos_EncTicketPart },
  { KERBEROS_APPLICATIONS_AS_REQ, &hf_kerberos_as_req     , BER_CLASS_APP, 10, BER_FLAGS_NOOWNTAG, dissect_kerberos_AS_REQ },
  { KERBEROS_APPLICATIONS_AS_REP, &hf_kerberos_as_rep     , BER_CLASS_APP, 11, BER_FLAGS_NOOWNTAG, dissect_kerberos_AS_REP },
  { KERBEROS_APPLICATIONS_TGS_REQ, &hf_kerberos_tgs_req    , BER_CLASS_APP, 12, BER_FLAGS_NOOWNTAG, dissect_kerberos_TGS_REQ },
  { KERBEROS_APPLICATIONS_TGS_REP, &hf_kerberos_tgs_rep    , BER_CLASS_APP, 13, BER_FLAGS_NOOWNTAG, dissect_kerberos_TGS_REP },
  { KERBEROS_APPLICATIONS_AP_REQ, &hf_kerberos_ap_req     , BER_CLASS_APP, 14, BER_FLAGS_NOOWNTAG, dissect_kerberos_AP_REQ },
  { KERBEROS_APPLICATIONS_AP_REP, &hf_kerberos_ap_rep     , BER_CLASS_APP, 15, BER_FLAGS_NOOWNTAG, dissect_kerberos_AP_REP },
  { KERBEROS_APPLICATIONS_KRB_SAFE, &hf_kerberos_krb_safe   , BER_CLASS_APP, 20, BER_FLAGS_NOOWNTAG, dissect_kerberos_KRB_SAFE },
  { KERBEROS_APPLICATIONS_KRB_PRIV, &hf_kerberos_krb_priv   , BER_CLASS_APP, 21, BER_FLAGS_NOOWNTAG, dissect_kerberos_KRB_PRIV },
  { KERBEROS_APPLICATIONS_KRB_CRED, &hf_kerberos_krb_cred   , BER_CLASS_APP, 22, BER_FLAGS_NOOWNTAG, dissect_kerberos_KRB_CRED },
  { KERBEROS_APPLICATIONS_ENCASREPPART, &hf_kerberos_encASRepPart, BER_CLASS_APP, 25, BER_FLAGS_NOOWNTAG, dissect_kerberos_EncASRepPart },
  { KERBEROS_APPLICATIONS_ENCTGSREPPART, &hf_kerberos_encTGSRepPart, BER_CLASS_APP, 26, BER_FLAGS_NOOWNTAG, dissect_kerberos_EncTGSRepPart },
  { KERBEROS_APPLICATIONS_ENCAPREPPART, &hf_kerberos_encAPRepPart, BER_CLASS_APP, 27, BER_FLAGS_NOOWNTAG, dissect_kerberos_EncAPRepPart },
  { KERBEROS_APPLICATIONS_ENCKRBPRIVPART, &hf_kerberos_encKrbPrivPart, BER_CLASS_APP, 28, BER_FLAGS_NOOWNTAG, dissect_kerberos_ENC_KRB_PRIV_PART },
  { KERBEROS_APPLICATIONS_ENCKRBCREDPART, &hf_kerberos_encKrbCredPart, BER_CLASS_APP, 29, BER_FLAGS_NOOWNTAG, dissect_kerberos_EncKrbCredPart },
  { KERBEROS_APPLICATIONS_KRB_ERROR, &hf_kerberos_krb_error  , BER_CLASS_APP, 30, BER_FLAGS_NOOWNTAG, dissect_kerberos_KRB_ERROR },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_Applications(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Applications_choice, hf_index, ett_kerberos_Applications,
                                 NULL);

  return offset;
}



static int
dissect_kerberos_T_pA_ENC_TIMESTAMP_cipher(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 388 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
  offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_PA_ENC_TIMESTAMP);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif



  return offset;
}


static const ber_sequence_t PA_ENC_TIMESTAMP_sequence[] = {
  { &hf_kerberos_etype      , BER_CLASS_CON, 0, 0, dissect_kerberos_ENCTYPE },
  { &hf_kerberos_kvno       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { &hf_kerberos_pA_ENC_TIMESTAMP_cipher, BER_CLASS_CON, 2, 0, dissect_kerberos_T_pA_ENC_TIMESTAMP_cipher },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_PA_ENC_TIMESTAMP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PA_ENC_TIMESTAMP_sequence, hf_index, ett_kerberos_PA_ENC_TIMESTAMP);

  return offset;
}


static const ber_sequence_t ETYPE_INFO_ENTRY_sequence[] = {
  { &hf_kerberos_etype      , BER_CLASS_CON, 0, 0, dissect_kerberos_ENCTYPE },
  { &hf_kerberos_info_salt  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_ETYPE_INFO_ENTRY(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ETYPE_INFO_ENTRY_sequence, hf_index, ett_kerberos_ETYPE_INFO_ENTRY);

  return offset;
}


static const ber_sequence_t ETYPE_INFO_sequence_of[1] = {
  { &hf_kerberos_ETYPE_INFO_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_kerberos_ETYPE_INFO_ENTRY },
};

static int
dissect_kerberos_ETYPE_INFO(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ETYPE_INFO_sequence_of, hf_index, ett_kerberos_ETYPE_INFO);

  return offset;
}


static const ber_sequence_t ETYPE_INFO2_ENTRY_sequence[] = {
  { &hf_kerberos_etype      , BER_CLASS_CON, 0, 0, dissect_kerberos_ENCTYPE },
  { &hf_kerberos_info2_salt , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosString },
  { &hf_kerberos_s2kparams  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_kerberos_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_ETYPE_INFO2_ENTRY(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ETYPE_INFO2_ENTRY_sequence, hf_index, ett_kerberos_ETYPE_INFO2_ENTRY);

  return offset;
}


static const ber_sequence_t ETYPE_INFO2_sequence_of[1] = {
  { &hf_kerberos_ETYPE_INFO2_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_kerberos_ETYPE_INFO2_ENTRY },
};

static int
dissect_kerberos_ETYPE_INFO2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ETYPE_INFO2_sequence_of, hf_index, ett_kerberos_ETYPE_INFO2);

  return offset;
}



static int
dissect_kerberos_AD_IF_RELEVANT(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_kerberos_AuthorizationData(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t TGT_REQ_sequence[] = {
  { &hf_kerberos_pvno       , BER_CLASS_CON, 0, 0, dissect_kerberos_INTEGER_5 },
  { &hf_kerberos_msg_type   , BER_CLASS_CON, 1, 0, dissect_kerberos_MESSAGE_TYPE },
  { &hf_kerberos_server_name, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_kerberos_PrincipalName },
  { &hf_kerberos_realm      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_kerberos_Realm },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_kerberos_TGT_REQ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TGT_REQ_sequence, hf_index, ett_kerberos_TGT_REQ);

  return offset;
}


static const ber_sequence_t TGT_REP_sequence[] = {
  { &hf_kerberos_pvno       , BER_CLASS_CON, 0, 0, dissect_kerberos_INTEGER_5 },
  { &hf_kerberos_msg_type   , BER_CLASS_CON, 1, 0, dissect_kerberos_MESSAGE_TYPE },
  { &hf_kerberos_ticket     , BER_CLASS_CON, 2, 0, dissect_kerberos_Ticket },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_kerberos_TGT_REP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TGT_REP_sequence, hf_index, ett_kerberos_TGT_REP);

  return offset;
}



static int
dissect_kerberos_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t PA_PAC_REQUEST_sequence[] = {
  { &hf_kerberos_include_pac, BER_CLASS_CON, 0, 0, dissect_kerberos_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_PA_PAC_REQUEST(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PA_PAC_REQUEST_sequence, hf_index, ett_kerberos_PA_PAC_REQUEST);

  return offset;
}



static int
dissect_kerberos_GeneralString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GeneralString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t PA_S4U2Self_sequence[] = {
  { &hf_kerberos_name       , BER_CLASS_CON, 0, 0, dissect_kerberos_PrincipalName },
  { &hf_kerberos_realm      , BER_CLASS_CON, 1, 0, dissect_kerberos_Realm },
  { &hf_kerberos_cksum      , BER_CLASS_CON, 2, 0, dissect_kerberos_Checksum },
  { &hf_kerberos_auth       , BER_CLASS_CON, 3, 0, dissect_kerberos_GeneralString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_PA_S4U2Self(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PA_S4U2Self_sequence, hf_index, ett_kerberos_PA_S4U2Self);

  return offset;
}



static int
dissect_kerberos_T_subject_certificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 592 "./asn1/kerberos/kerberos.cnf"
  offset=dissect_ber_octet_string_wcb(implicit_tag, actx, tree, tvb, offset,hf_index, dissect_x509af_Certificate);



  return offset;
}



static int
dissect_kerberos_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t S4UUserID_sequence[] = {
  { &hf_kerberos_nonce      , BER_CLASS_CON, 0, 0, dissect_kerberos_UInt32 },
  { &hf_kerberos_cname_01   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_PrincipalName },
  { &hf_kerberos_crealm     , BER_CLASS_CON, 2, 0, dissect_kerberos_Realm },
  { &hf_kerberos_subject_certificate, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_kerberos_T_subject_certificate },
  { &hf_kerberos_options    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_kerberos_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_S4UUserID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   S4UUserID_sequence, hf_index, ett_kerberos_S4UUserID);

  return offset;
}


static const ber_sequence_t PA_S4U_X509_USER_sequence[] = {
  { &hf_kerberos_user_id    , BER_CLASS_CON, 0, 0, dissect_kerberos_S4UUserID },
  { &hf_kerberos_checksum_01, BER_CLASS_CON, 1, 0, dissect_kerberos_Checksum },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_PA_S4U_X509_USER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PA_S4U_X509_USER_sequence, hf_index, ett_kerberos_PA_S4U_X509_USER);

  return offset;
}


static int * const PAC_OPTIONS_FLAGS_bits[] = {
  &hf_kerberos_PAC_OPTIONS_FLAGS_claims,
  &hf_kerberos_PAC_OPTIONS_FLAGS_branch_aware,
  &hf_kerberos_PAC_OPTIONS_FLAGS_forward_to_full_dc,
  &hf_kerberos_PAC_OPTIONS_FLAGS_resource_based_constrained_delegation,
  NULL
};

static int
dissect_kerberos_PAC_OPTIONS_FLAGS(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    PAC_OPTIONS_FLAGS_bits, 4, hf_index, ett_kerberos_PAC_OPTIONS_FLAGS,
                                    NULL);

  return offset;
}


static const ber_sequence_t PA_PAC_OPTIONS_sequence[] = {
  { &hf_kerberos_flags_01   , BER_CLASS_CON, 0, 0, dissect_kerberos_PAC_OPTIONS_FLAGS },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_PA_PAC_OPTIONS(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PA_PAC_OPTIONS_sequence, hf_index, ett_kerberos_PA_PAC_OPTIONS);

  return offset;
}


static const ber_sequence_t KERB_AD_RESTRICTION_ENTRY_U_sequence[] = {
  { &hf_kerberos_restriction_type, BER_CLASS_CON, 0, 0, dissect_kerberos_Int32 },
  { &hf_kerberos_restriction, BER_CLASS_CON, 1, 0, dissect_kerberos_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_KERB_AD_RESTRICTION_ENTRY_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KERB_AD_RESTRICTION_ENTRY_U_sequence, hf_index, ett_kerberos_KERB_AD_RESTRICTION_ENTRY_U);

  return offset;
}



static int
dissect_kerberos_KERB_AD_RESTRICTION_ENTRY(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_UNI, 16, FALSE, dissect_kerberos_KERB_AD_RESTRICTION_ENTRY_U);

  return offset;
}


static const ber_sequence_t PA_KERB_KEY_LIST_REQ_sequence_of[1] = {
  { &hf_kerberos_PA_KERB_KEY_LIST_REQ_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_kerberos_ENCTYPE },
};

static int
dissect_kerberos_PA_KERB_KEY_LIST_REQ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PA_KERB_KEY_LIST_REQ_sequence_of, hf_index, ett_kerberos_PA_KERB_KEY_LIST_REQ);

  return offset;
}



static int
dissect_kerberos_PA_KERB_KEY_LIST_REP_Key(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_kerberos_EncryptionKey(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_kerberos_PA_KERB_KEY_LIST_REP_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 546 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  gint save_encryption_key_parent_hf_index = private_data->save_encryption_key_parent_hf_index;
  kerberos_key_save_fn saved_encryption_key_fn = private_data->save_encryption_key_fn;
  private_data->save_encryption_key_parent_hf_index = hf_kerberos_kerbKeyListRep_key;
#ifdef HAVE_KERBEROS
  private_data->save_encryption_key_fn = save_encryption_key;
#endif
  offset = dissect_kerberos_PA_KERB_KEY_LIST_REP_Key(implicit_tag, tvb, offset, actx, tree, hf_index);

  private_data->save_encryption_key_parent_hf_index = save_encryption_key_parent_hf_index;
  private_data->save_encryption_key_fn = saved_encryption_key_fn;



  return offset;
}


static const ber_sequence_t PA_KERB_KEY_LIST_REP_sequence_of[1] = {
  { &hf_kerberos_kerbKeyListRep_key, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_kerberos_PA_KERB_KEY_LIST_REP_item },
};

static int
dissect_kerberos_PA_KERB_KEY_LIST_REP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PA_KERB_KEY_LIST_REP_sequence_of, hf_index, ett_kerberos_PA_KERB_KEY_LIST_REP);

  return offset;
}


static const ber_sequence_t ChangePasswdData_sequence[] = {
  { &hf_kerberos_newpasswd  , BER_CLASS_CON, 0, 0, dissect_kerberos_OCTET_STRING },
  { &hf_kerberos_targname   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_PrincipalName },
  { &hf_kerberos_targrealm  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_kerberos_Realm },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_kerberos_ChangePasswdData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChangePasswdData_sequence, hf_index, ett_kerberos_ChangePasswdData);

  return offset;
}


static const ber_sequence_t PA_AUTHENTICATION_SET_ELEM_sequence[] = {
  { &hf_kerberos_pa_type    , BER_CLASS_CON, 0, 0, dissect_kerberos_PADATA_TYPE },
  { &hf_kerberos_pa_hint    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_OCTET_STRING },
  { &hf_kerberos_pa_value   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_kerberos_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_PA_AUTHENTICATION_SET_ELEM(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PA_AUTHENTICATION_SET_ELEM_sequence, hf_index, ett_kerberos_PA_AUTHENTICATION_SET_ELEM);

  return offset;
}


static const value_string kerberos_KrbFastArmorTypes_vals[] = {
  { KERBEROS_FX_FAST_RESERVED, "fX-FAST-reserved" },
  { KERBEROS_FX_FAST_ARMOR_AP_REQUEST, "fX-FAST-ARMOR-AP-REQUEST" },
  { 0, NULL }
};


static int
dissect_kerberos_KrbFastArmorTypes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 669 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &(private_data->fast_type));




  return offset;
}



static int
dissect_kerberos_T_armor_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 673 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

  switch(private_data->fast_type){
  case KERBEROS_FX_FAST_ARMOR_AP_REQUEST:
    private_data->fast_armor_within_armor_value++;
    offset=dissect_ber_octet_string_wcb(implicit_tag, actx, tree, tvb, offset, hf_index, dissect_kerberos_Applications);
    private_data->fast_armor_within_armor_value--;
    break;
  default:
    offset=dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);
    break;
  }



  return offset;
}


static const ber_sequence_t KrbFastArmor_sequence[] = {
  { &hf_kerberos_armor_type , BER_CLASS_CON, 0, 0, dissect_kerberos_KrbFastArmorTypes },
  { &hf_kerberos_armor_value, BER_CLASS_CON, 1, 0, dissect_kerberos_T_armor_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_KrbFastArmor(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KrbFastArmor_sequence, hf_index, ett_kerberos_KrbFastArmor);

  return offset;
}



static int
dissect_kerberos_T_encryptedKrbFastReq_cipher(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 645 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
  offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_KrbFastReq);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif
  return offset;



  return offset;
}


static const ber_sequence_t EncryptedKrbFastReq_sequence[] = {
  { &hf_kerberos_etype      , BER_CLASS_CON, 0, 0, dissect_kerberos_ENCTYPE },
  { &hf_kerberos_kvno       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { &hf_kerberos_encryptedKrbFastReq_cipher, BER_CLASS_CON, 2, 0, dissect_kerberos_T_encryptedKrbFastReq_cipher },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncryptedKrbFastReq(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedKrbFastReq_sequence, hf_index, ett_kerberos_EncryptedKrbFastReq);

  return offset;
}


static const ber_sequence_t KrbFastArmoredReq_sequence[] = {
  { &hf_kerberos_armor      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_kerberos_KrbFastArmor },
  { &hf_kerberos_req_checksum, BER_CLASS_CON, 1, 0, dissect_kerberos_Checksum },
  { &hf_kerberos_enc_fast_req, BER_CLASS_CON, 2, 0, dissect_kerberos_EncryptedKrbFastReq },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_KrbFastArmoredReq(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KrbFastArmoredReq_sequence, hf_index, ett_kerberos_KrbFastArmoredReq);

  return offset;
}


static const ber_choice_t PA_FX_FAST_REQUEST_choice[] = {
  {   0, &hf_kerberos_armored_data_request, BER_CLASS_CON, 0, 0, dissect_kerberos_KrbFastArmoredReq },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_PA_FX_FAST_REQUEST(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PA_FX_FAST_REQUEST_choice, hf_index, ett_kerberos_PA_FX_FAST_REQUEST,
                                 NULL);

  return offset;
}



static int
dissect_kerberos_T_encryptedKrbFastResponse_cipher(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 653 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
  offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_KrbFastResponse);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif
  return offset;



  return offset;
}


static const ber_sequence_t EncryptedKrbFastResponse_sequence[] = {
  { &hf_kerberos_etype      , BER_CLASS_CON, 0, 0, dissect_kerberos_ENCTYPE },
  { &hf_kerberos_kvno       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { &hf_kerberos_encryptedKrbFastResponse_cipher, BER_CLASS_CON, 2, 0, dissect_kerberos_T_encryptedKrbFastResponse_cipher },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncryptedKrbFastResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedKrbFastResponse_sequence, hf_index, ett_kerberos_EncryptedKrbFastResponse);

  return offset;
}


static const ber_sequence_t KrbFastArmoredRep_sequence[] = {
  { &hf_kerberos_enc_fast_rep, BER_CLASS_CON, 0, 0, dissect_kerberos_EncryptedKrbFastResponse },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_KrbFastArmoredRep(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KrbFastArmoredRep_sequence, hf_index, ett_kerberos_KrbFastArmoredRep);

  return offset;
}


static const ber_choice_t PA_FX_FAST_REPLY_choice[] = {
  {   0, &hf_kerberos_armored_data_reply, BER_CLASS_CON, 0, 0, dissect_kerberos_KrbFastArmoredRep },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_PA_FX_FAST_REPLY(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PA_FX_FAST_REPLY_choice, hf_index, ett_kerberos_PA_FX_FAST_REPLY,
                                 NULL);

  return offset;
}



static int
dissect_kerberos_T_encryptedChallenge_cipher(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 661 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
  offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_EncryptedChallenge);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif
  return offset;



  return offset;
}


static const ber_sequence_t EncryptedChallenge_sequence[] = {
  { &hf_kerberos_etype      , BER_CLASS_CON, 0, 0, dissect_kerberos_ENCTYPE },
  { &hf_kerberos_kvno       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { &hf_kerberos_encryptedChallenge_cipher, BER_CLASS_CON, 2, 0, dissect_kerberos_T_encryptedChallenge_cipher },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncryptedChallenge(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedChallenge_sequence, hf_index, ett_kerberos_EncryptedChallenge);

  return offset;
}


static const ber_sequence_t EncryptedSpakeData_sequence[] = {
  { &hf_kerberos_etype      , BER_CLASS_CON, 0, 0, dissect_kerberos_ENCTYPE },
  { &hf_kerberos_kvno       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { &hf_kerberos_cipher     , BER_CLASS_CON, 2, 0, dissect_kerberos_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncryptedSpakeData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedSpakeData_sequence, hf_index, ett_kerberos_EncryptedSpakeData);

  return offset;
}


static const ber_sequence_t EncryptedSpakeResponseData_sequence[] = {
  { &hf_kerberos_etype      , BER_CLASS_CON, 0, 0, dissect_kerberos_ENCTYPE },
  { &hf_kerberos_kvno       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_UInt32 },
  { &hf_kerberos_cipher     , BER_CLASS_CON, 2, 0, dissect_kerberos_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncryptedSpakeResponseData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedSpakeResponseData_sequence, hf_index, ett_kerberos_EncryptedSpakeResponseData);

  return offset;
}


static const value_string kerberos_SPAKEGroup_vals[] = {
  {   1, "sPAKEGroup-edwards25519" },
  {   2, "sPAKEGroup-P-256" },
  {   3, "sPAKEGroup-P-384" },
  {   4, "sPAKEGroup-P-521" },
  { 0, NULL }
};


static int
dissect_kerberos_SPAKEGroup(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string kerberos_SPAKESecondFactorType_vals[] = {
  {   1, "sPAKESecondFactor-SF-NONE" },
  { 0, NULL }
};


static int
dissect_kerberos_SPAKESecondFactorType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_SPAKEGroup_sequence_of[1] = {
  { &hf_kerberos_groups_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_kerberos_SPAKEGroup },
};

static int
dissect_kerberos_SEQUENCE_SIZE_1_MAX_OF_SPAKEGroup(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_SPAKEGroup_sequence_of, hf_index, ett_kerberos_SEQUENCE_SIZE_1_MAX_OF_SPAKEGroup);

  return offset;
}


static const ber_sequence_t SPAKESupport_sequence[] = {
  { &hf_kerberos_groups     , BER_CLASS_CON, 0, 0, dissect_kerberos_SEQUENCE_SIZE_1_MAX_OF_SPAKEGroup },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_SPAKESupport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SPAKESupport_sequence, hf_index, ett_kerberos_SPAKESupport);

  return offset;
}


static const ber_sequence_t SPAKESecondFactor_sequence[] = {
  { &hf_kerberos_type       , BER_CLASS_CON, 0, 0, dissect_kerberos_SPAKESecondFactorType },
  { &hf_kerberos_data       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_SPAKESecondFactor(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SPAKESecondFactor_sequence, hf_index, ett_kerberos_SPAKESecondFactor);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_SPAKESecondFactor_sequence_of[1] = {
  { &hf_kerberos_factors_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_kerberos_SPAKESecondFactor },
};

static int
dissect_kerberos_SEQUENCE_SIZE_1_MAX_OF_SPAKESecondFactor(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_SPAKESecondFactor_sequence_of, hf_index, ett_kerberos_SEQUENCE_SIZE_1_MAX_OF_SPAKESecondFactor);

  return offset;
}


static const ber_sequence_t SPAKEChallenge_sequence[] = {
  { &hf_kerberos_group      , BER_CLASS_CON, 0, 0, dissect_kerberos_SPAKEGroup },
  { &hf_kerberos_pubkey     , BER_CLASS_CON, 1, 0, dissect_kerberos_OCTET_STRING },
  { &hf_kerberos_factors    , BER_CLASS_CON, 2, 0, dissect_kerberos_SEQUENCE_SIZE_1_MAX_OF_SPAKESecondFactor },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_SPAKEChallenge(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SPAKEChallenge_sequence, hf_index, ett_kerberos_SPAKEChallenge);

  return offset;
}


static const ber_sequence_t SPAKEResponse_sequence[] = {
  { &hf_kerberos_pubkey     , BER_CLASS_CON, 0, 0, dissect_kerberos_OCTET_STRING },
  { &hf_kerberos_factor     , BER_CLASS_CON, 1, 0, dissect_kerberos_EncryptedSpakeResponseData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_SPAKEResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SPAKEResponse_sequence, hf_index, ett_kerberos_SPAKEResponse);

  return offset;
}


static const value_string kerberos_PA_SPAKE_vals[] = {
  {   0, "support" },
  {   1, "challenge" },
  {   2, "response" },
  {   3, "encdata" },
  { 0, NULL }
};

static const ber_choice_t PA_SPAKE_choice[] = {
  {   0, &hf_kerberos_support    , BER_CLASS_CON, 0, 0, dissect_kerberos_SPAKESupport },
  {   1, &hf_kerberos_challenge  , BER_CLASS_CON, 1, 0, dissect_kerberos_SPAKEChallenge },
  {   2, &hf_kerberos_response   , BER_CLASS_CON, 2, 0, dissect_kerberos_SPAKEResponse },
  {   3, &hf_kerberos_encdata    , BER_CLASS_CON, 3, 0, dissect_kerberos_EncryptedSpakeData },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_PA_SPAKE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 687 "./asn1/kerberos/kerberos.cnf"
  kerberos_private_data_t* private_data = kerberos_get_private_data(actx);
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PA_SPAKE_choice, hf_index, ett_kerberos_PA_SPAKE,
                                 &(private_data->padata_type));



#line 690 "./asn1/kerberos/kerberos.cnf"
  if(tree){
    proto_item_append_text(tree, " %s",
      val_to_str(private_data->padata_type, kerberos_PA_SPAKE_vals,
      "Unknown:%d"));
  }

  return offset;
}


/*--- End of included file: packet-kerberos-fn.c ---*/
#line 4330 "./asn1/kerberos/packet-kerberos-template.c"

#ifdef HAVE_KERBEROS
static const ber_sequence_t PA_ENC_TS_ENC_sequence[] = {
	{ &hf_krb_patimestamp, BER_CLASS_CON, 0, 0, dissect_kerberos_KerberosTime },
	{ &hf_krb_pausec     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_Microseconds },
	{ NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_PA_ENC_TS_ENC(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
									PA_ENC_TS_ENC_sequence, hf_index, ett_krb_pa_enc_ts_enc);
	return offset;
}

static int
dissect_kerberos_T_strengthen_key(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  gint save_encryption_key_parent_hf_index = private_data->save_encryption_key_parent_hf_index;
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
dissect_kerberos_KrbFastFinished(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_kerberos_KrbFastResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_kerberos_KrbFastReq(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  struct _kerberos_PA_FX_FAST_REQUEST saved_stack = private_data->PA_FX_FAST_REQUEST;
  private_data->PA_FX_FAST_REQUEST = (struct _kerberos_PA_FX_FAST_REQUEST) { .defer = FALSE, };
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
dissect_kerberos_FastOptions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
	return dissect_kerberos_Checksum(FALSE, tvb, offset, actx, tree, hf_kerberos_cksum);

}

int
dissect_krb5_ctime(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	return dissect_kerberos_KerberosTime(FALSE, tvb, offset, actx, tree, hf_kerberos_ctime);
}


int
dissect_krb5_cname(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	return dissect_kerberos_PrincipalName(FALSE, tvb, offset, actx, tree, hf_kerberos_cname);
}
int
dissect_krb5_realm(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	return dissect_kerberos_Realm(FALSE, tvb, offset, actx, tree, hf_kerberos_realm);
}

struct kerberos_display_key_state {
	proto_tree *tree;
	packet_info *pinfo;
	expert_field *expindex;
	const char *name;
	tvbuff_t *tvb;
	gint start;
	gint length;
};

static void
#ifdef HAVE_KERBEROS
kerberos_display_key(gpointer data, gpointer userdata)
#else
kerberos_display_key(gpointer data _U_, gpointer userdata _U_)
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
	guint32 ServiceTicketLength;
	guint32 TicketGrantingTicketLength;
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
	offset = dissect_kerberos_Ticket(FALSE, tvb, offset, actx, subtree,
					 hf_kerberos_KERB_TICKET_LOGON_ServiceTicket);

	if ((unsigned)(offset-orig_offset) != ServiceTicketLength)
		return offset;

	if (TicketGrantingTicketLength == 0)
		return offset;

	offset = dissect_kerberos_KRB_CRED(FALSE, tvb, offset, actx, subtree,
					   hf_kerberos_KERB_TICKET_LOGON_TicketGrantingTicket);

	if ((unsigned)(offset-orig_offset) != ServiceTicketLength + TicketGrantingTicketLength)
		return offset;

	return offset;
}

static gint
dissect_kerberos_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean dci, gboolean do_col_protocol, gboolean have_rm,
    kerberos_callbacks *cb)
{
	volatile int offset = 0;
	proto_tree *volatile kerberos_tree = NULL;
	proto_item *volatile item = NULL;
	kerberos_private_data_t *private_data = NULL;
	asn1_ctx_t asn1_ctx;

	/* TCP record mark and length */
	guint32 krb_rm = 0;
	gint krb_reclen = 0;

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
		gint8 tmp_class;
		gboolean tmp_pc;
		gint32 tmp_tag;

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
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
	asn1_ctx.private_data = NULL;
	private_data = kerberos_get_private_data(&asn1_ctx);
	private_data->callbacks = cb;

	TRY {
		offset=dissect_kerberos_Applications(FALSE, tvb, offset, &asn1_ctx , kerberos_tree, /* hf_index */ -1);
	} CATCH_BOUNDS_ERRORS {
		RETHROW;
	} ENDTRY;

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
show_krb_recordmark(proto_tree *tree, tvbuff_t *tvb, gint start, guint32 krb_rm)
{
	gint rec_len;
	proto_tree *rm_tree;

	if (tree == NULL)
		return;

	rec_len = kerberos_rm_to_reclen(krb_rm);
	rm_tree = proto_tree_add_subtree_format(tree, tvb, start, 4, ett_krb_recordmark, NULL,
		"Record Mark: %u %s", rec_len, plurality(rec_len, "byte", "bytes"));
	proto_tree_add_boolean(rm_tree, hf_krb_rm_reserved, tvb, start, 4, krb_rm);
	proto_tree_add_uint(rm_tree, hf_krb_rm_reclen, tvb, start, 4, krb_rm);
}

gint
dissect_kerberos_main(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int do_col_info, kerberos_callbacks *cb)
{
	return (dissect_kerberos_common(tvb, pinfo, tree, do_col_info, FALSE, FALSE, cb));
}

guint32
kerberos_output_keytype(void)
{
	return gbl_keytype;
}

static gint
dissect_kerberos_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	/* Some weird kerberos implementation apparently do krb4 on the krb5 port.
	   Since all (except weirdo transarc krb4 stuff) use
	   an opcode <=16 in the first byte, use this to see if it might
	   be krb4.
	   All krb5 commands start with an APPL tag and thus is >=0x60
	   so if first byte is <=16  just blindly assume it is krb4 then
	*/
	if(tvb_captured_length(tvb) >= 1 && tvb_get_guint8(tvb, 0)<=0x10){
		if(krb4_handle){
			gboolean res;

			res=call_dissector_only(krb4_handle, tvb, pinfo, tree, NULL);
			return res;
		}else{
			return 0;
		}
	}


	return dissect_kerberos_common(tvb, pinfo, tree, TRUE, TRUE, FALSE, NULL);
}

gint
kerberos_rm_to_reclen(guint krb_rm)
{
    return (krb_rm & KRB_RM_RECLEN);
}

guint
get_krb_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	guint krb_rm;
	gint pdulen;

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
	pinfo->fragmented = TRUE;
	if (dissect_kerberos_common(tvb, pinfo, tree, TRUE, TRUE, TRUE, NULL) < 0) {
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
		{ "NT Status", "kerberos.smb.nt_status", FT_UINT32, BASE_HEX,
		VALS(NT_errors), 0, "NT Status code", HFILL }},
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


/*--- Included file: packet-kerberos-hfarr.c ---*/
#line 1 "./asn1/kerberos/packet-kerberos-hfarr.c"
    { &hf_kerberos_ticket,
      { "ticket", "kerberos.ticket_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_authenticator,
      { "authenticator", "kerberos.authenticator_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_encTicketPart,
      { "encTicketPart", "kerberos.encTicketPart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_as_req,
      { "as-req", "kerberos.as_req_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_as_rep,
      { "as-rep", "kerberos.as_rep_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_tgs_req,
      { "tgs-req", "kerberos.tgs_req_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_tgs_rep,
      { "tgs-rep", "kerberos.tgs_rep_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_ap_req,
      { "ap-req", "kerberos.ap_req_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_ap_rep,
      { "ap-rep", "kerberos.ap_rep_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_krb_safe,
      { "krb-safe", "kerberos.krb_safe_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_krb_priv,
      { "krb-priv", "kerberos.krb_priv_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_krb_cred,
      { "krb-cred", "kerberos.krb_cred_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_encASRepPart,
      { "encASRepPart", "kerberos.encASRepPart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_encTGSRepPart,
      { "encTGSRepPart", "kerberos.encTGSRepPart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_encAPRepPart,
      { "encAPRepPart", "kerberos.encAPRepPart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_encKrbPrivPart,
      { "encKrbPrivPart", "kerberos.encKrbPrivPart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ENC_KRB_PRIV_PART", HFILL }},
    { &hf_kerberos_encKrbCredPart,
      { "encKrbCredPart", "kerberos.encKrbCredPart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_krb_error,
      { "krb-error", "kerberos.krb_error_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_name_type,
      { "name-type", "kerberos.name_type",
        FT_INT32, BASE_DEC, VALS(kerberos_NAME_TYPE_vals), 0,
        NULL, HFILL }},
    { &hf_kerberos_name_string,
      { "name-string", "kerberos.name_string",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_KerberosString", HFILL }},
    { &hf_kerberos_name_string_item,
      { "KerberosString", "kerberos.KerberosString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_cname_string,
      { "cname-string", "kerberos.cname_string",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CNameString", HFILL }},
    { &hf_kerberos_cname_string_item,
      { "CNameString", "kerberos.CNameString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_sname_string,
      { "sname-string", "kerberos.sname_string",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SNameString", HFILL }},
    { &hf_kerberos_sname_string_item,
      { "SNameString", "kerberos.SNameString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_addr_type,
      { "addr-type", "kerberos.addr_type",
        FT_INT32, BASE_DEC, VALS(kerberos_ADDR_TYPE_vals), 0,
        NULL, HFILL }},
    { &hf_kerberos_address,
      { "address", "kerberos.address",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_HostAddresses_item,
      { "HostAddress", "kerberos.HostAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_AuthorizationData_item,
      { "AuthorizationData item", "kerberos.AuthorizationData_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_ad_type,
      { "ad-type", "kerberos.ad_type",
        FT_INT32, BASE_DEC, VALS(kerberos_AUTHDATA_TYPE_vals), 0,
        "AUTHDATA_TYPE", HFILL }},
    { &hf_kerberos_ad_data,
      { "ad-data", "kerberos.ad_data",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_padata_type,
      { "padata-type", "kerberos.padata_type",
        FT_INT32, BASE_DEC, VALS(kerberos_PADATA_TYPE_vals), 0,
        NULL, HFILL }},
    { &hf_kerberos_padata_value,
      { "padata-value", "kerberos.padata_value",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_keytype,
      { "keytype", "kerberos.keytype",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_keyvalue,
      { "keyvalue", "kerberos.keyvalue",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_cksumtype,
      { "cksumtype", "kerberos.cksumtype",
        FT_INT32, BASE_DEC, VALS(kerberos_CKSUMTYPE_vals), 0,
        NULL, HFILL }},
    { &hf_kerberos_checksum,
      { "checksum", "kerberos.checksum",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_etype,
      { "etype", "kerberos.etype",
        FT_INT32, BASE_DEC, VALS(kerberos_ENCTYPE_vals), 0,
        "ENCTYPE", HFILL }},
    { &hf_kerberos_kvno,
      { "kvno", "kerberos.kvno",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UInt32", HFILL }},
    { &hf_kerberos_encryptedTicketData_cipher,
      { "cipher", "kerberos.cipher",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_encryptedTicketData_cipher", HFILL }},
    { &hf_kerberos_encryptedAuthorizationData_cipher,
      { "cipher", "kerberos.cipher",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_encryptedAuthorizationData_cipher", HFILL }},
    { &hf_kerberos_encryptedAuthenticator_cipher,
      { "cipher", "kerberos.cipher",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_encryptedAuthenticator_cipher", HFILL }},
    { &hf_kerberos_encryptedKDCREPData_cipher,
      { "cipher", "kerberos.cipher",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_encryptedKDCREPData_cipher", HFILL }},
    { &hf_kerberos_encryptedAPREPData_cipher,
      { "cipher", "kerberos.cipher",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_encryptedAPREPData_cipher", HFILL }},
    { &hf_kerberos_encryptedKrbPrivData_cipher,
      { "cipher", "kerberos.cipher",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_encryptedKrbPrivData_cipher", HFILL }},
    { &hf_kerberos_encryptedKrbCredData_cipher,
      { "cipher", "kerberos.cipher",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_encryptedKrbCredData_cipher", HFILL }},
    { &hf_kerberos_tkt_vno,
      { "tkt-vno", "kerberos.tkt_vno",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_5", HFILL }},
    { &hf_kerberos_realm,
      { "realm", "kerberos.realm",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_sname,
      { "sname", "kerberos.sname_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_ticket_enc_part,
      { "enc-part", "kerberos.enc_part_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedTicketData", HFILL }},
    { &hf_kerberos_flags,
      { "flags", "kerberos.flags",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TicketFlags", HFILL }},
    { &hf_kerberos_encTicketPart_key,
      { "key", "kerberos.key_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_encTicketPart_key", HFILL }},
    { &hf_kerberos_crealm,
      { "crealm", "kerberos.crealm",
        FT_STRING, BASE_NONE, NULL, 0,
        "Realm", HFILL }},
    { &hf_kerberos_cname,
      { "cname", "kerberos.cname_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_transited,
      { "transited", "kerberos.transited_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TransitedEncoding", HFILL }},
    { &hf_kerberos_authtime,
      { "authtime", "kerberos.authtime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_starttime,
      { "starttime", "kerberos.starttime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_endtime,
      { "endtime", "kerberos.endtime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_renew_till,
      { "renew-till", "kerberos.renew_till",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_caddr,
      { "caddr", "kerberos.caddr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HostAddresses", HFILL }},
    { &hf_kerberos_authorization_data,
      { "authorization-data", "kerberos.authorization_data",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AuthorizationData", HFILL }},
    { &hf_kerberos_tr_type,
      { "tr-type", "kerberos.tr_type",
        FT_INT32, BASE_DEC, NULL, 0,
        "Int32", HFILL }},
    { &hf_kerberos_contents,
      { "contents", "kerberos.contents",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_kerberos_pvno,
      { "pvno", "kerberos.pvno",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_5", HFILL }},
    { &hf_kerberos_msg_type,
      { "msg-type", "kerberos.msg_type",
        FT_INT32, BASE_DEC, VALS(kerberos_MESSAGE_TYPE_vals), 0,
        "MESSAGE_TYPE", HFILL }},
    { &hf_kerberos_rEQ_SEQUENCE_OF_PA_DATA,
      { "padata", "kerberos.padata",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_rEQ_SEQUENCE_OF_PA_DATA", HFILL }},
    { &hf_kerberos_rEQ_SEQUENCE_OF_PA_DATA_item,
      { "PA-DATA", "kerberos.PA_DATA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_req_body,
      { "req-body", "kerberos.req_body_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "KDC_REQ_BODY", HFILL }},
    { &hf_kerberos_kdc_options,
      { "kdc-options", "kerberos.kdc_options",
        FT_BYTES, BASE_NONE, NULL, 0,
        "KDCOptions", HFILL }},
    { &hf_kerberos_from,
      { "from", "kerberos.from",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_till,
      { "till", "kerberos.till",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_rtime,
      { "rtime", "kerberos.rtime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_nonce,
      { "nonce", "kerberos.nonce",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UInt32", HFILL }},
    { &hf_kerberos_kDC_REQ_BODY_etype,
      { "etype", "kerberos.kdc-req-body.etype",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ENCTYPE", HFILL }},
    { &hf_kerberos_kDC_REQ_BODY_etype_item,
      { "ENCTYPE", "kerberos.ENCTYPE",
        FT_INT32, BASE_DEC, VALS(kerberos_ENCTYPE_vals), 0,
        NULL, HFILL }},
    { &hf_kerberos_addresses,
      { "addresses", "kerberos.addresses",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HostAddresses", HFILL }},
    { &hf_kerberos_enc_authorization_data,
      { "enc-authorization-data", "kerberos.enc_authorization_data_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedAuthorizationData", HFILL }},
    { &hf_kerberos_additional_tickets,
      { "additional-tickets", "kerberos.additional_tickets",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Ticket", HFILL }},
    { &hf_kerberos_additional_tickets_item,
      { "Ticket", "kerberos.Ticket_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_rEP_SEQUENCE_OF_PA_DATA,
      { "padata", "kerberos.padata",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_rEP_SEQUENCE_OF_PA_DATA", HFILL }},
    { &hf_kerberos_rEP_SEQUENCE_OF_PA_DATA_item,
      { "PA-DATA", "kerberos.PA_DATA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_kDC_REP_enc_part,
      { "enc-part", "kerberos.enc_part_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedKDCREPData", HFILL }},
    { &hf_kerberos_encKDCRepPart_key,
      { "key", "kerberos.key_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_encKDCRepPart_key", HFILL }},
    { &hf_kerberos_last_req,
      { "last-req", "kerberos.last_req",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LastReq", HFILL }},
    { &hf_kerberos_key_expiration,
      { "key-expiration", "kerberos.key_expiration",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_srealm,
      { "srealm", "kerberos.srealm",
        FT_STRING, BASE_NONE, NULL, 0,
        "Realm", HFILL }},
    { &hf_kerberos_encrypted_pa_data,
      { "encrypted-pa-data", "kerberos.encrypted_pa_data",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_LastReq_item,
      { "LastReq item", "kerberos.LastReq_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_lr_type,
      { "lr-type", "kerberos.lr_type",
        FT_INT32, BASE_DEC, VALS(kerberos_LR_TYPE_vals), 0,
        NULL, HFILL }},
    { &hf_kerberos_lr_value,
      { "lr-value", "kerberos.lr_value",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_ap_options,
      { "ap-options", "kerberos.ap_options",
        FT_BYTES, BASE_NONE, NULL, 0,
        "APOptions", HFILL }},
    { &hf_kerberos_authenticator_enc_part,
      { "authenticator", "kerberos.authenticator_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedAuthenticator", HFILL }},
    { &hf_kerberos_authenticator_vno,
      { "authenticator-vno", "kerberos.authenticator_vno",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_5", HFILL }},
    { &hf_kerberos_cksum,
      { "cksum", "kerberos.cksum_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Checksum", HFILL }},
    { &hf_kerberos_cusec,
      { "cusec", "kerberos.cusec",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Microseconds", HFILL }},
    { &hf_kerberos_ctime,
      { "ctime", "kerberos.ctime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_authenticator_subkey,
      { "subkey", "kerberos.subkey_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_authenticator_subkey", HFILL }},
    { &hf_kerberos_seq_number,
      { "seq-number", "kerberos.seq_number",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UInt32", HFILL }},
    { &hf_kerberos_aP_REP_enc_part,
      { "enc-part", "kerberos.enc_part_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedAPREPData", HFILL }},
    { &hf_kerberos_encAPRepPart_subkey,
      { "subkey", "kerberos.subkey_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_encAPRepPart_subkey", HFILL }},
    { &hf_kerberos_safe_body,
      { "safe-body", "kerberos.safe_body_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "KRB_SAFE_BODY", HFILL }},
    { &hf_kerberos_kRB_SAFE_BODY_user_data,
      { "user-data", "kerberos.user_data",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_kRB_SAFE_BODY_user_data", HFILL }},
    { &hf_kerberos_timestamp,
      { "timestamp", "kerberos.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_usec,
      { "usec", "kerberos.usec",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Microseconds", HFILL }},
    { &hf_kerberos_s_address,
      { "s-address", "kerberos.s_address_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HostAddress", HFILL }},
    { &hf_kerberos_r_address,
      { "r-address", "kerberos.r_address_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HostAddress", HFILL }},
    { &hf_kerberos_kRB_PRIV_enc_part,
      { "enc-part", "kerberos.enc_part_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedKrbPrivData", HFILL }},
    { &hf_kerberos_encKrbPrivPart_user_data,
      { "user-data", "kerberos.user_data",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_encKrbPrivPart_user_data", HFILL }},
    { &hf_kerberos_tickets,
      { "tickets", "kerberos.tickets",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Ticket", HFILL }},
    { &hf_kerberos_tickets_item,
      { "Ticket", "kerberos.Ticket_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_kRB_CRED_enc_part,
      { "enc-part", "kerberos.enc_part_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedKrbCredData", HFILL }},
    { &hf_kerberos_ticket_info,
      { "ticket-info", "kerberos.ticket_info",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_KrbCredInfo", HFILL }},
    { &hf_kerberos_ticket_info_item,
      { "KrbCredInfo", "kerberos.KrbCredInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_krbCredInfo_key,
      { "key", "kerberos.key_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_krbCredInfo_key", HFILL }},
    { &hf_kerberos_prealm,
      { "prealm", "kerberos.prealm",
        FT_STRING, BASE_NONE, NULL, 0,
        "Realm", HFILL }},
    { &hf_kerberos_pname,
      { "pname", "kerberos.pname_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrincipalName", HFILL }},
    { &hf_kerberos_stime,
      { "stime", "kerberos.stime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_susec,
      { "susec", "kerberos.susec",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Microseconds", HFILL }},
    { &hf_kerberos_error_code,
      { "error-code", "kerberos.error_code",
        FT_INT32, BASE_DEC, VALS(kerberos_ERROR_CODE_vals), 0,
        NULL, HFILL }},
    { &hf_kerberos_e_text,
      { "e-text", "kerberos.e_text",
        FT_STRING, BASE_NONE, NULL, 0,
        "KerberosString", HFILL }},
    { &hf_kerberos_e_data,
      { "e-data", "kerberos.e_data",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_e_checksum,
      { "e-checksum", "kerberos.e_checksum_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Checksum", HFILL }},
    { &hf_kerberos_METHOD_DATA_item,
      { "PA-DATA", "kerberos.PA_DATA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_pA_ENC_TIMESTAMP_cipher,
      { "cipher", "kerberos.cipher",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_pA_ENC_TIMESTAMP_cipher", HFILL }},
    { &hf_kerberos_info_salt,
      { "salt", "kerberos.info_salt",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_kerberos_ETYPE_INFO_item,
      { "ETYPE-INFO-ENTRY", "kerberos.ETYPE_INFO_ENTRY_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_info2_salt,
      { "salt", "kerberos.info2_salt",
        FT_STRING, BASE_NONE, NULL, 0,
        "KerberosString", HFILL }},
    { &hf_kerberos_s2kparams,
      { "s2kparams", "kerberos.s2kparams",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_kerberos_ETYPE_INFO2_item,
      { "ETYPE-INFO2-ENTRY", "kerberos.ETYPE_INFO2_ENTRY_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_server_name,
      { "server-name", "kerberos.server_name_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrincipalName", HFILL }},
    { &hf_kerberos_include_pac,
      { "include-pac", "kerberos.include_pac",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_kerberos_name,
      { "name", "kerberos.name_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrincipalName", HFILL }},
    { &hf_kerberos_auth,
      { "auth", "kerberos.auth",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralString", HFILL }},
    { &hf_kerberos_user_id,
      { "user-id", "kerberos.user_id_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "S4UUserID", HFILL }},
    { &hf_kerberos_checksum_01,
      { "checksum", "kerberos.checksum_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_cname_01,
      { "cname", "kerberos.cname_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrincipalName", HFILL }},
    { &hf_kerberos_subject_certificate,
      { "subject-certificate", "kerberos.subject_certificate",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_subject_certificate", HFILL }},
    { &hf_kerberos_options,
      { "options", "kerberos.options",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_kerberos_flags_01,
      { "flags", "kerberos.flags",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PAC_OPTIONS_FLAGS", HFILL }},
    { &hf_kerberos_restriction_type,
      { "restriction-type", "kerberos.restriction_type",
        FT_INT32, BASE_DEC, NULL, 0,
        "Int32", HFILL }},
    { &hf_kerberos_restriction,
      { "restriction", "kerberos.restriction",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_kerberos_PA_KERB_KEY_LIST_REQ_item,
      { "ENCTYPE", "kerberos.ENCTYPE",
        FT_INT32, BASE_DEC, VALS(kerberos_ENCTYPE_vals), 0,
        NULL, HFILL }},
    { &hf_kerberos_kerbKeyListRep_key,
      { "key", "kerberos.kerbKeyListRep.key_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PA_KERB_KEY_LIST_REP_item", HFILL }},
    { &hf_kerberos_newpasswd,
      { "newpasswd", "kerberos.newpasswd",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_kerberos_targname,
      { "targname", "kerberos.targname_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrincipalName", HFILL }},
    { &hf_kerberos_targrealm,
      { "targrealm", "kerberos.targrealm",
        FT_STRING, BASE_NONE, NULL, 0,
        "Realm", HFILL }},
    { &hf_kerberos_pa_type,
      { "pa-type", "kerberos.pa_type",
        FT_INT32, BASE_DEC, VALS(kerberos_PADATA_TYPE_vals), 0,
        "PADATA_TYPE", HFILL }},
    { &hf_kerberos_pa_hint,
      { "pa-hint", "kerberos.pa_hint",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_kerberos_pa_value,
      { "pa-value", "kerberos.pa_value",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_kerberos_armor_type,
      { "armor-type", "kerberos.armor_type",
        FT_INT32, BASE_DEC, VALS(kerberos_KrbFastArmorTypes_vals), 0,
        "KrbFastArmorTypes", HFILL }},
    { &hf_kerberos_armor_value,
      { "armor-value", "kerberos.armor_value",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_armored_data_request,
      { "armored-data", "kerberos.armored_data_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "KrbFastArmoredReq", HFILL }},
    { &hf_kerberos_encryptedKrbFastReq_cipher,
      { "cipher", "kerberos.cipher",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_encryptedKrbFastReq_cipher", HFILL }},
    { &hf_kerberos_armor,
      { "armor", "kerberos.armor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "KrbFastArmor", HFILL }},
    { &hf_kerberos_req_checksum,
      { "req-checksum", "kerberos.req_checksum_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Checksum", HFILL }},
    { &hf_kerberos_enc_fast_req,
      { "enc-fast-req", "kerberos.enc_fast_req_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedKrbFastReq", HFILL }},
    { &hf_kerberos_armored_data_reply,
      { "armored-data", "kerberos.armored_data_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "KrbFastArmoredRep", HFILL }},
    { &hf_kerberos_encryptedKrbFastResponse_cipher,
      { "cipher", "kerberos.cipher",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_encryptedKrbFastResponse_cipher", HFILL }},
    { &hf_kerberos_enc_fast_rep,
      { "enc-fast-rep", "kerberos.enc_fast_rep_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedKrbFastResponse", HFILL }},
    { &hf_kerberos_encryptedChallenge_cipher,
      { "cipher", "kerberos.cipher",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_encryptedChallenge_cipher", HFILL }},
    { &hf_kerberos_cipher,
      { "cipher", "kerberos.cipher",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_kerberos_groups,
      { "groups", "kerberos.groups",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_SPAKEGroup", HFILL }},
    { &hf_kerberos_groups_item,
      { "SPAKEGroup", "kerberos.SPAKEGroup",
        FT_INT32, BASE_DEC, VALS(kerberos_SPAKEGroup_vals), 0,
        NULL, HFILL }},
    { &hf_kerberos_group,
      { "group", "kerberos.group",
        FT_INT32, BASE_DEC, VALS(kerberos_SPAKEGroup_vals), 0,
        "SPAKEGroup", HFILL }},
    { &hf_kerberos_pubkey,
      { "pubkey", "kerberos.pubkey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_kerberos_factors,
      { "factors", "kerberos.factors",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_SPAKESecondFactor", HFILL }},
    { &hf_kerberos_factors_item,
      { "SPAKESecondFactor", "kerberos.SPAKESecondFactor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_type,
      { "type", "kerberos.type",
        FT_INT32, BASE_DEC, VALS(kerberos_SPAKESecondFactorType_vals), 0,
        "SPAKESecondFactorType", HFILL }},
    { &hf_kerberos_data,
      { "data", "kerberos.data",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_kerberos_factor,
      { "factor", "kerberos.factor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedSpakeResponseData", HFILL }},
    { &hf_kerberos_support,
      { "support", "kerberos.support_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SPAKESupport", HFILL }},
    { &hf_kerberos_challenge,
      { "challenge", "kerberos.challenge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SPAKEChallenge", HFILL }},
    { &hf_kerberos_response,
      { "response", "kerberos.response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SPAKEResponse", HFILL }},
    { &hf_kerberos_encdata,
      { "encdata", "kerberos.encdata_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedSpakeData", HFILL }},
    { &hf_kerberos_APOptions_reserved,
      { "reserved", "kerberos.APOptions.reserved",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_APOptions_use_session_key,
      { "use-session-key", "kerberos.APOptions.use.session.key",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_kerberos_APOptions_mutual_required,
      { "mutual-required", "kerberos.APOptions.mutual.required",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_reserved,
      { "reserved", "kerberos.TicketFlags.reserved",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_forwardable,
      { "forwardable", "kerberos.TicketFlags.forwardable",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_forwarded,
      { "forwarded", "kerberos.TicketFlags.forwarded",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_proxiable,
      { "proxiable", "kerberos.TicketFlags.proxiable",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_proxy,
      { "proxy", "kerberos.TicketFlags.proxy",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_may_postdate,
      { "may-postdate", "kerberos.TicketFlags.may.postdate",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_postdated,
      { "postdated", "kerberos.TicketFlags.postdated",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_invalid,
      { "invalid", "kerberos.TicketFlags.invalid",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_renewable,
      { "renewable", "kerberos.TicketFlags.renewable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_initial,
      { "initial", "kerberos.TicketFlags.initial",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_pre_authent,
      { "pre-authent", "kerberos.TicketFlags.pre.authent",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_hw_authent,
      { "hw-authent", "kerberos.TicketFlags.hw.authent",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_transited_policy_checked,
      { "transited-policy-checked", "kerberos.TicketFlags.transited.policy.checked",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_ok_as_delegate,
      { "ok-as-delegate", "kerberos.TicketFlags.ok.as.delegate",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_unused,
      { "unused", "kerberos.TicketFlags.unused",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_enc_pa_rep,
      { "enc-pa-rep", "kerberos.TicketFlags.enc.pa.rep",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_anonymous,
      { "anonymous", "kerberos.TicketFlags.anonymous",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_reserved,
      { "reserved", "kerberos.KDCOptions.reserved",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_forwardable,
      { "forwardable", "kerberos.KDCOptions.forwardable",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_forwarded,
      { "forwarded", "kerberos.KDCOptions.forwarded",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_proxiable,
      { "proxiable", "kerberos.KDCOptions.proxiable",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_proxy,
      { "proxy", "kerberos.KDCOptions.proxy",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_allow_postdate,
      { "allow-postdate", "kerberos.KDCOptions.allow.postdate",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_postdated,
      { "postdated", "kerberos.KDCOptions.postdated",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused7,
      { "unused7", "kerberos.KDCOptions.unused7",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_renewable,
      { "renewable", "kerberos.KDCOptions.renewable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused9,
      { "unused9", "kerberos.KDCOptions.unused9",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused10,
      { "unused10", "kerberos.KDCOptions.unused10",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_opt_hardware_auth,
      { "opt-hardware-auth", "kerberos.KDCOptions.opt.hardware.auth",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused12,
      { "unused12", "kerberos.KDCOptions.unused12",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused13,
      { "unused13", "kerberos.KDCOptions.unused13",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_constrained_delegation,
      { "constrained-delegation", "kerberos.KDCOptions.constrained.delegation",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_canonicalize,
      { "canonicalize", "kerberos.KDCOptions.canonicalize",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_request_anonymous,
      { "request-anonymous", "kerberos.KDCOptions.request.anonymous",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused17,
      { "unused17", "kerberos.KDCOptions.unused17",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused18,
      { "unused18", "kerberos.KDCOptions.unused18",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused19,
      { "unused19", "kerberos.KDCOptions.unused19",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused20,
      { "unused20", "kerberos.KDCOptions.unused20",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused21,
      { "unused21", "kerberos.KDCOptions.unused21",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused22,
      { "unused22", "kerberos.KDCOptions.unused22",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused23,
      { "unused23", "kerberos.KDCOptions.unused23",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused24,
      { "unused24", "kerberos.KDCOptions.unused24",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused25,
      { "unused25", "kerberos.KDCOptions.unused25",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_disable_transited_check,
      { "disable-transited-check", "kerberos.KDCOptions.disable.transited.check",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_renewable_ok,
      { "renewable-ok", "kerberos.KDCOptions.renewable.ok",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_enc_tkt_in_skey,
      { "enc-tkt-in-skey", "kerberos.KDCOptions.enc.tkt.in.skey",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused29,
      { "unused29", "kerberos.KDCOptions.unused29",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_renew,
      { "renew", "kerberos.KDCOptions.renew",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_validate,
      { "validate", "kerberos.KDCOptions.validate",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_kerberos_PAC_OPTIONS_FLAGS_claims,
      { "claims", "kerberos.PAC.OPTIONS.FLAGS.claims",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_PAC_OPTIONS_FLAGS_branch_aware,
      { "branch-aware", "kerberos.PAC.OPTIONS.FLAGS.branch.aware",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_kerberos_PAC_OPTIONS_FLAGS_forward_to_full_dc,
      { "forward-to-full-dc", "kerberos.PAC.OPTIONS.FLAGS.forward.to.full.dc",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_kerberos_PAC_OPTIONS_FLAGS_resource_based_constrained_delegation,
      { "resource-based-constrained-delegation", "kerberos.PAC.OPTIONS.FLAGS.resource.based.constrained.delegation",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},

/*--- End of included file: packet-kerberos-hfarr.c ---*/
#line 5281 "./asn1/kerberos/packet-kerberos-template.c"
	};

	/* List of subtrees */
	static gint *ett[] = {
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

/*--- Included file: packet-kerberos-ettarr.c ---*/
#line 1 "./asn1/kerberos/packet-kerberos-ettarr.c"
    &ett_kerberos_Applications,
    &ett_kerberos_PrincipalName,
    &ett_kerberos_SEQUENCE_OF_KerberosString,
    &ett_kerberos_CName,
    &ett_kerberos_SEQUENCE_OF_CNameString,
    &ett_kerberos_SName,
    &ett_kerberos_SEQUENCE_OF_SNameString,
    &ett_kerberos_HostAddress,
    &ett_kerberos_HostAddresses,
    &ett_kerberos_AuthorizationData,
    &ett_kerberos_AuthorizationData_item,
    &ett_kerberos_PA_DATA,
    &ett_kerberos_EncryptionKey,
    &ett_kerberos_Checksum,
    &ett_kerberos_EncryptedTicketData,
    &ett_kerberos_EncryptedAuthorizationData,
    &ett_kerberos_EncryptedAuthenticator,
    &ett_kerberos_EncryptedKDCREPData,
    &ett_kerberos_EncryptedAPREPData,
    &ett_kerberos_EncryptedKrbPrivData,
    &ett_kerberos_EncryptedKrbCredData,
    &ett_kerberos_Ticket_U,
    &ett_kerberos_EncTicketPart_U,
    &ett_kerberos_TransitedEncoding,
    &ett_kerberos_KDC_REQ,
    &ett_kerberos_T_rEQ_SEQUENCE_OF_PA_DATA,
    &ett_kerberos_KDC_REQ_BODY,
    &ett_kerberos_SEQUENCE_OF_ENCTYPE,
    &ett_kerberos_SEQUENCE_OF_Ticket,
    &ett_kerberos_KDC_REP,
    &ett_kerberos_T_rEP_SEQUENCE_OF_PA_DATA,
    &ett_kerberos_EncKDCRepPart,
    &ett_kerberos_LastReq,
    &ett_kerberos_LastReq_item,
    &ett_kerberos_AP_REQ_U,
    &ett_kerberos_Authenticator_U,
    &ett_kerberos_AP_REP_U,
    &ett_kerberos_EncAPRepPart_U,
    &ett_kerberos_KRB_SAFE_U,
    &ett_kerberos_KRB_SAFE_BODY,
    &ett_kerberos_KRB_PRIV_U,
    &ett_kerberos_EncKrbPrivPart,
    &ett_kerberos_KRB_CRED_U,
    &ett_kerberos_EncKrbCredPart_U,
    &ett_kerberos_SEQUENCE_OF_KrbCredInfo,
    &ett_kerberos_KrbCredInfo,
    &ett_kerberos_KRB_ERROR_U,
    &ett_kerberos_METHOD_DATA,
    &ett_kerberos_PA_ENC_TIMESTAMP,
    &ett_kerberos_ETYPE_INFO_ENTRY,
    &ett_kerberos_ETYPE_INFO,
    &ett_kerberos_ETYPE_INFO2_ENTRY,
    &ett_kerberos_ETYPE_INFO2,
    &ett_kerberos_TGT_REQ,
    &ett_kerberos_TGT_REP,
    &ett_kerberos_APOptions,
    &ett_kerberos_TicketFlags,
    &ett_kerberos_KDCOptions,
    &ett_kerberos_PA_PAC_REQUEST,
    &ett_kerberos_PA_S4U2Self,
    &ett_kerberos_PA_S4U_X509_USER,
    &ett_kerberos_S4UUserID,
    &ett_kerberos_PAC_OPTIONS_FLAGS,
    &ett_kerberos_PA_PAC_OPTIONS,
    &ett_kerberos_KERB_AD_RESTRICTION_ENTRY_U,
    &ett_kerberos_PA_KERB_KEY_LIST_REQ,
    &ett_kerberos_PA_KERB_KEY_LIST_REP,
    &ett_kerberos_ChangePasswdData,
    &ett_kerberos_PA_AUTHENTICATION_SET_ELEM,
    &ett_kerberos_KrbFastArmor,
    &ett_kerberos_PA_FX_FAST_REQUEST,
    &ett_kerberos_EncryptedKrbFastReq,
    &ett_kerberos_KrbFastArmoredReq,
    &ett_kerberos_PA_FX_FAST_REPLY,
    &ett_kerberos_EncryptedKrbFastResponse,
    &ett_kerberos_KrbFastArmoredRep,
    &ett_kerberos_EncryptedChallenge,
    &ett_kerberos_EncryptedSpakeData,
    &ett_kerberos_EncryptedSpakeResponseData,
    &ett_kerberos_SPAKESupport,
    &ett_kerberos_SEQUENCE_SIZE_1_MAX_OF_SPAKEGroup,
    &ett_kerberos_SPAKEChallenge,
    &ett_kerberos_SEQUENCE_SIZE_1_MAX_OF_SPAKESecondFactor,
    &ett_kerberos_SPAKESecondFactor,
    &ett_kerberos_SPAKEResponse,
    &ett_kerberos_PA_SPAKE,

/*--- End of included file: packet-kerberos-ettarr.c ---*/
#line 5314 "./asn1/kerberos/packet-kerberos-template.c"
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
				   &keytab_filename, FALSE);

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
				 proto_tree *tree, dcerpc_info *di _U_,guint8 *drep _U_)
{
	tvbuff_t *auth_tvb;

	auth_tvb = tvb_new_subset_remaining(tvb, offset);

	dissect_kerberos_main(auth_tvb, pinfo, tree, FALSE, NULL);

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
	dissector_handle_t kerberos_handle_tcp;

	krb4_handle = find_dissector_add_dependency("krb4", proto_kerberos);

	kerberos_handle_udp = create_dissector_handle(dissect_kerberos_udp,
	proto_kerberos);

	kerberos_handle_tcp = create_dissector_handle(dissect_kerberos_tcp,
	proto_kerberos);

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
