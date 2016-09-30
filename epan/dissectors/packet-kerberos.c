/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-kerberos.c                                                          */
/* asn2wrs.py -b -p kerberos -c ./kerberos.cnf -s ./packet-kerberos-template -D . -O ../.. KerberosV5Spec2.asn k5.asn RFC3244.asn */

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
 *	http://www.isi.edu/people/bcn/krb-revisions/
 *
 * and
 *
 *	http://www.ietf.org/internet-drafts/draft-ietf-krb-wg-kerberos-clarifications-07.txt
 *
 * and
 *
 *      http://www.ietf.org/internet-drafts/draft-ietf-krb-wg-kerberos-referrals-05.txt
 *
 * Some structures from RFC2630
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/strutil.h>
#include <epan/conversation.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <wsutil/file_util.h>
#include <wsutil/str_util.h>
#include "packet-kerberos.h"
#include "packet-netbios.h"
#include "packet-tcp.h"
#include "packet-ber.h"
#include "packet-pkinit.h"
#include "packet-cms.h"
#include "packet-windows-common.h"

#include "packet-dcerpc-netlogon.h"
#include "packet-dcerpc.h"

#include "packet-gssapi.h"
#include "packet-smb-common.h"


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

typedef struct {
	guint32 etype;
	guint32 padata_type;
	guint32 enctype;
	kerberos_key_t key;
	guint32 ad_type;
	guint32 addr_type;
	guint32 checksum_type;
} kerberos_private_data_t;

static dissector_handle_t kerberos_handle_udp;

/* Forward declarations */
static int dissect_kerberos_Applications(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_ENC_TIMESTAMP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_KERB_PA_PAC_REQUEST(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_S4U2Self(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_ETYPE_INFO(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_ETYPE_INFO2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_AD_IF_RELEVANT(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);


/* Desegment Kerberos over TCP messages */
static gboolean krb_desegment = TRUE;

static gint proto_kerberos = -1;

static gint hf_krb_rm_reserved = -1;
static gint hf_krb_rm_reclen = -1;
static gint hf_krb_provsrv_location = -1;
static gint hf_krb_smb_nt_status = -1;
static gint hf_krb_smb_unknown = -1;
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
static gint hf_krb_pac_credential_type = -1;
static gint hf_krb_pac_s4u_delegation_info = -1;
static gint hf_krb_pac_upn_dns_info = -1;
static gint hf_krb_pac_upn_flags = -1;
static gint hf_krb_pac_upn_dns_offset = -1;
static gint hf_krb_pac_upn_dns_len = -1;
static gint hf_krb_pac_upn_upn_offset = -1;
static gint hf_krb_pac_upn_upn_len = -1;
static gint hf_krb_pac_upn_upn_name = -1;
static gint hf_krb_pac_upn_dns_name = -1;
static gint hf_krb_pac_server_checksum = -1;
static gint hf_krb_pac_privsvr_checksum = -1;
static gint hf_krb_pac_client_info_type = -1;

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
static int hf_kerberos_ad_type = -1;              /* T_ad_type */
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
static int hf_kerberos_encryptedKDCREPData_cipher = -1;  /* T_encryptedKDCREPData_cipher */
static int hf_kerberos_encryptedAPREPData_cipher = -1;  /* T_encryptedAPREPData_cipher */
static int hf_kerberos_encryptedKrbPrivData_cipher = -1;  /* T_encryptedKrbPrivData_cipher */
static int hf_kerberos_encryptedKrbCredData_cipher = -1;  /* T_encryptedKrbCredData_cipher */
static int hf_kerberos_tkt_vno = -1;              /* INTEGER_5 */
static int hf_kerberos_realm = -1;                /* Realm */
static int hf_kerberos_sname = -1;                /* SName */
static int hf_kerberos_ticket_enc_part = -1;      /* EncryptedTicketData */
static int hf_kerberos_flags = -1;                /* TicketFlags */
static int hf_kerberos_key = -1;                  /* EncryptionKey */
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
static int hf_kerberos_padata = -1;               /* SEQUENCE_OF_PA_DATA */
static int hf_kerberos_padata_item = -1;          /* PA_DATA */
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
static int hf_kerberos_kDC_REP_enc_part = -1;     /* EncryptedKDCREPData */
static int hf_kerberos_last_req = -1;             /* LastReq */
static int hf_kerberos_key_expiration = -1;       /* KerberosTime */
static int hf_kerberos_srealm = -1;               /* Realm */
static int hf_kerberos_encrypted_pa_data = -1;    /* METHOD_DATA */
static int hf_kerberos_LastReq_item = -1;         /* LastReq_item */
static int hf_kerberos_lr_type = -1;              /* LR_TYPE */
static int hf_kerberos_lr_value = -1;             /* KerberosTime */
static int hf_kerberos_ap_options = -1;           /* APOptions */
static int hf_kerberos_authenticator_01 = -1;     /* EncryptedAuthorizationData */
static int hf_kerberos_authenticator_vno = -1;    /* INTEGER_5 */
static int hf_kerberos_cksum = -1;                /* Checksum */
static int hf_kerberos_cusec = -1;                /* Microseconds */
static int hf_kerberos_ctime = -1;                /* KerberosTime */
static int hf_kerberos_subkey = -1;               /* EncryptionKey */
static int hf_kerberos_seq_number = -1;           /* UInt32 */
static int hf_kerberos_aP_REP_enc_part = -1;      /* EncryptedAPREPData */
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
static int hf_kerberos_salt = -1;                 /* OCTET_STRING */
static int hf_kerberos_ETYPE_INFO_item = -1;      /* ETYPE_INFO_ENTRY */
static int hf_kerberos_salt_01 = -1;              /* KerberosString */
static int hf_kerberos_s2kparams = -1;            /* OCTET_STRING */
static int hf_kerberos_ETYPE_INFO2_item = -1;     /* ETYPE_INFO2_ENTRY */
static int hf_kerberos_name = -1;                 /* PrincipalName */
static int hf_kerberos_auth = -1;                 /* GeneralString */
static int hf_kerberos_include_pac = -1;          /* BOOLEAN */
static int hf_kerberos_newpasswd = -1;            /* OCTET_STRING */
static int hf_kerberos_targname = -1;             /* PrincipalName */
static int hf_kerberos_targrealm = -1;            /* Realm */
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
static int hf_kerberos_KDCOptions_request_anonymous = -1;
static int hf_kerberos_KDCOptions_canonicalize = -1;
static int hf_kerberos_KDCOptions_constrained_delegation = -1;
static int hf_kerberos_KDCOptions_disable_transited_check = -1;
static int hf_kerberos_KDCOptions_renewable_ok = -1;
static int hf_kerberos_KDCOptions_enc_tkt_in_skey = -1;
static int hf_kerberos_KDCOptions_renew = -1;
static int hf_kerberos_KDCOptions_validate = -1;

/*--- End of included file: packet-kerberos-hf.c ---*/
#line 172 "./asn1/kerberos/packet-kerberos-template.c"

/* Initialize the subtree pointers */
static gint ett_kerberos = -1;
static gint ett_krb_recordmark = -1;
static gint ett_krb_pac = -1;
static gint ett_krb_pac_drep = -1;
static gint ett_krb_pac_midl_blob = -1;
static gint ett_krb_pac_logon_info = -1;
static gint ett_krb_pac_s4u_delegation_info = -1;
static gint ett_krb_pac_upn_dns_info = -1;
static gint ett_krb_pac_server_checksum = -1;
static gint ett_krb_pac_privsvr_checksum = -1;
static gint ett_krb_pac_client_info_type = -1;

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
static gint ett_kerberos_EncryptedKDCREPData = -1;
static gint ett_kerberos_EncryptedAPREPData = -1;
static gint ett_kerberos_EncryptedKrbPrivData = -1;
static gint ett_kerberos_EncryptedKrbCredData = -1;
static gint ett_kerberos_Ticket_U = -1;
static gint ett_kerberos_EncTicketPart_U = -1;
static gint ett_kerberos_TransitedEncoding = -1;
static gint ett_kerberos_KDC_REQ = -1;
static gint ett_kerberos_SEQUENCE_OF_PA_DATA = -1;
static gint ett_kerberos_KDC_REQ_BODY = -1;
static gint ett_kerberos_SEQUENCE_OF_ENCTYPE = -1;
static gint ett_kerberos_SEQUENCE_OF_Ticket = -1;
static gint ett_kerberos_KDC_REP = -1;
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
static gint ett_kerberos_APOptions = -1;
static gint ett_kerberos_TicketFlags = -1;
static gint ett_kerberos_KDCOptions = -1;
static gint ett_kerberos_PA_S4U2Self = -1;
static gint ett_kerberos_KERB_PA_PAC_REQUEST = -1;
static gint ett_kerberos_ChangePasswdData = -1;

/*--- End of included file: packet-kerberos-ett.c ---*/
#line 186 "./asn1/kerberos/packet-kerberos-template.c"

static expert_field ei_kerberos_decrypted_keytype = EI_INIT;
static expert_field ei_kerberos_address = EI_INIT;
static expert_field ei_krb_gssapi_dlglen = EI_INIT;

static dissector_handle_t krb4_handle=NULL;

/* Global variables */
static guint32 krb5_errorcode;
static guint32 gbl_keytype;
static gboolean gbl_do_col_info;


/*--- Included file: packet-kerberos-val.h ---*/
#line 1 "./asn1/kerberos/packet-kerberos-val.h"
#define id_krb5                        "1.3.6.1.5.2"

/* enumerated values for ADDR_TYPE */
#define KERBEROS_ADDR_TYPE_IPV4   2
#define KERBEROS_ADDR_TYPE_CHAOS   5
#define KERBEROS_ADDR_TYPE_XEROX   6
#define KERBEROS_ADDR_TYPE_ISO   7
#define KERBEROS_ADDR_TYPE_DECNET  12
#define KERBEROS_ADDR_TYPE_APPLETALK  16
#define KERBEROS_ADDR_TYPE_NETBIOS  20
#define KERBEROS_ADDR_TYPE_IPV6  24

/*--- End of included file: packet-kerberos-val.h ---*/
#line 199 "./asn1/kerberos/packet-kerberos-template.c"

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
kerberos_get_private_data(asn1_ctx_t *actx)
{
	if (!actx->private_data) {
		actx->private_data = wmem_new0(wmem_packet_scope(), kerberos_private_data_t);
	}
	return (kerberos_private_data_t *)(actx->private_data);
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

	if (last_keytab != NULL) {
		g_free(last_keytab);
		last_keytab = NULL;
	}
	last_keytab = g_strdup(keytab_filename);

	read_keytab_file(last_keytab);
}
#endif /* HAVE_KERBEROS */

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
#ifdef _WIN32
/* prevent redefinition warnings in kfw-2.5\inc\win_mac.h */
#undef HAVE_GETADDRINFO
#undef HAVE_SYS_TYPES_H
#endif /* _WIN32 */
#include <krb5.h>
enc_key_t *enc_key_list=NULL;

static void
add_encryption_key(packet_info *pinfo, int keytype, int keylength, const char *keyvalue, const char *origin)
{
	enc_key_t *new_key;

	if(pinfo->fd->flags.visited){
		return;
	}

	new_key=(enc_key_t *)g_malloc(sizeof(enc_key_t));
	g_snprintf(new_key->key_origin, KRB_MAX_ORIG_LEN, "%s learnt from frame %u",origin,pinfo->num);
	new_key->fd_num = pinfo->num;
	new_key->next=enc_key_list;
	enc_key_list=new_key;
	new_key->keytype=keytype;
	new_key->keylength=keylength;
	/*XXX this needs to be freed later */
	new_key->keyvalue=(char *)g_memdup(keyvalue, keylength);
}
#endif /* HAVE_HEIMDAL_KERBEROS || HAVE_MIT_KERBEROS */

#if defined(HAVE_MIT_KERBEROS)

static krb5_context krb5_ctx;

USES_APPLE_DEPRECATED_API
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
		new_key=(enc_key_t *)g_malloc(sizeof(enc_key_t));
		new_key->fd_num = -1;
		new_key->next=enc_key_list;
		ret = krb5_kt_next_entry(krb5_ctx, keytab, &key, &cursor);
		if(ret==0){
			int i;
			char *pos;

			/* generate origin string, describing where this key came from */
			pos=new_key->key_origin;
			pos+=MIN(KRB_MAX_ORIG_LEN,
					 g_snprintf(pos, KRB_MAX_ORIG_LEN, "keytab principal "));
			for(i=0;i<key.principal->length;i++){
				pos+=MIN(KRB_MAX_ORIG_LEN-(pos-new_key->key_origin),
						 g_snprintf(pos, (gulong)(KRB_MAX_ORIG_LEN-(pos-new_key->key_origin)), "%s%s",(i?"/":""),(key.principal->data[i]).data));
			}
			pos+=MIN(KRB_MAX_ORIG_LEN-(pos-new_key->key_origin),
					 g_snprintf(pos, (gulong)(KRB_MAX_ORIG_LEN-(pos-new_key->key_origin)), "@%s",key.principal->realm.data));
			*pos=0;
			new_key->keytype=key.key.enctype;
			new_key->keylength=key.key.length;
			new_key->keyvalue=(char *)g_memdup(key.key.contents, key.key.length);
			enc_key_list=new_key;
		}
	}while(ret==0);

	ret = krb5_kt_end_seq_get(krb5_ctx, keytab, &cursor);
	if(ret){
		krb5_kt_close(krb5_ctx, keytab);
	}
}


guint8 *
decrypt_krb5_data(proto_tree *tree _U_, packet_info *pinfo,
					int usage,
					tvbuff_t *cryptotvb,
					int keytype,
					int *datalen)
{
	krb5_error_code ret;
	enc_key_t *ek;
	krb5_data data = {0,0,NULL};
	krb5_keytab_entry key;
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

	read_keytab_file_from_preferences();
	data.data = (char *)g_malloc(length);
	data.length = length;

	for(ek=enc_key_list;ek;ek=ek->next){
		krb5_enc_data input;

		/* shortcircuit and bail out if enctypes are not matching */
		if((keytype != -1) && (ek->keytype != keytype)) {
			continue;
		}

		input.enctype = ek->keytype;
		input.ciphertext.length = length;
		input.ciphertext.data = (guint8 *)cryptotext;

		key.key.enctype=ek->keytype;
		key.key.length=ek->keylength;
		key.key.contents=ek->keyvalue;
		ret = krb5_c_decrypt(krb5_ctx, &(key.key), usage, 0, &input, &data);
		if(ret == 0){
			char *user_data;

			expert_add_info_format(pinfo, NULL, &ei_kerberos_decrypted_keytype,
								   "Decrypted keytype %d in frame %u using %s",
								   ek->keytype, pinfo->num, ek->key_origin);

			/* return a private g_malloced blob to the caller */
			user_data=data.data;
			if (datalen) {
				*datalen = data.length;
			}
			return user_data;
		}
	}
	g_free(data.data);

	return NULL;
}
USES_APPLE_RST

#elif defined(HAVE_HEIMDAL_KERBEROS)
static krb5_context krb5_ctx;

USES_APPLE_DEPRECATED_API
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
		new_key = (enc_key_t *)g_malloc(sizeof(enc_key_t));
		new_key->fd_num = -1;
		new_key->next=enc_key_list;
		ret = krb5_kt_next_entry(krb5_ctx, keytab, &key, &cursor);
		if(ret==0){
			unsigned int i;
			char *pos;

			/* generate origin string, describing where this key came from */
			pos=new_key->key_origin;
			pos+=MIN(KRB_MAX_ORIG_LEN,
					 g_snprintf(pos, KRB_MAX_ORIG_LEN, "keytab principal "));
			for(i=0;i<key.principal->name.name_string.len;i++){
				pos+=MIN(KRB_MAX_ORIG_LEN-(pos-new_key->key_origin),
						 g_snprintf(pos, KRB_MAX_ORIG_LEN-(pos-new_key->key_origin), "%s%s",(i?"/":""),key.principal->name.name_string.val[i]));
			}
			pos+=MIN(KRB_MAX_ORIG_LEN-(pos-new_key->key_origin),
					 g_snprintf(pos, KRB_MAX_ORIG_LEN-(pos-new_key->key_origin), "@%s",key.principal->realm));
			*pos=0;
			new_key->keytype=key.keyblock.keytype;
			new_key->keylength=(int)key.keyblock.keyvalue.length;
			new_key->keyvalue = (guint8 *)g_memdup(key.keyblock.keyvalue.data, (guint)key.keyblock.keyvalue.length);
			enc_key_list=new_key;
		}
	}while(ret==0);

	ret = krb5_kt_end_seq_get(krb5_ctx, keytab, &cursor);
	if(ret){
		krb5_kt_close(krb5_ctx, keytab);
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
		cryptocopy = (guint8 *)g_memdup(cryptotext, length);
		ret = krb5_decrypt_ivec(krb5_ctx, crypto, usage,
								cryptocopy, length,
								&data,
								NULL);
		g_free(cryptocopy);
		if((ret == 0) && (length>0)){
			char *user_data;

			expert_add_info_format(pinfo, NULL, &ei_kerberos_decrypted_keytype,
								   "Decrypted keytype %d in frame %u using %s",
								   ek->keytype, pinfo->num, ek->key_origin);

			krb5_crypto_destroy(krb5_ctx, crypto);
			/* return a private g_malloced blob to the caller */
			user_data = (char *)g_memdup(data.data, (guint)data.length);
			if (datalen) {
				*datalen = (int)data.length;
			}
			return user_data;
		}
		krb5_crypto_destroy(krb5_ctx, crypto);
	}
	return NULL;
}

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

	if(pinfo->fd->flags.visited){
		return;
	}

	new_key = g_malloc(sizeof(service_key_t));
	new_key->kvno = 0;
	new_key->keytype = keytype;
	new_key->length = keylength;
	new_key->contents = g_memdup(keyvalue, keylength);
	g_snprintf(new_key->origin, KRB_MAX_ORIG_LEN, "%s learnt from frame %u", origin, pinfo->num);
	service_key_list = g_slist_append(service_key_list, (gpointer) new_key);
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
			sk->contents = g_memdup(buf + 2, DES3_KEY_SIZE);
			g_snprintf(sk->origin, KRB_MAX_ORIG_LEN, "3DES service key file, key #%d, offset %ld", count, ftell(skf));
			service_key_list = g_slist_append(service_key_list, (gpointer) sk);
			if (fseek(skf, newline_skip, SEEK_CUR) < 0) {
				fprintf(stderr, "unable to seek...\n");
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
	md5_state_t md5s;
	md5_byte_t digest[16];
	md5_byte_t zero_fill[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	md5_byte_t confounder[8];
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

	decrypted_data = g_malloc(length);
	for(ske = service_key_list; ske != NULL; ske = g_slist_next(ske)){
		gboolean do_continue = FALSE;
		sk = (service_key_t *) ske->data;

		des_fix_parity(DES3_KEY_SIZE, key, sk->contents);

		md5_init(&md5s);
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

		md5_append(&md5s, confounder, 8);
		md5_append(&md5s, zero_fill, 16);
		md5_append(&md5s, decrypted_data + CONFOUNDER_PLUS_CHECKSUM, data_len);
		md5_finish(&md5s, digest);

		if (tvb_memeql (encr_tvb, 8, digest, 16) == 0) {
			plaintext = g_malloc(data_len);
			tvb_memcpy(encr_tvb, plaintext, CONFOUNDER_PLUS_CHECKSUM, data_len);
			tvb_free(encr_tvb);

			if (datalen) {
				*datalen = data_len;
			}
			g_free(decrypted_data);
			return(plaintext);
		}
		tvb_free(encr_tvb);
	}

	g_free(decrypted_data);
	return NULL;
}

#endif	/* HAVE_MIT_KERBEROS / HAVE_HEIMDAL_KERBEROS / HAVE_LIBNETTLE */

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
 *	http://www.ietf.org/internet-drafts/draft-brezak-win2k-krb-rc4-hmac-04.txt
 *
 * unless it's expired.
 */

/* pre-authentication type constants */
#define KRB5_PA_TGS_REQ			1
#define KRB5_PA_ENC_TIMESTAMP		2
#define KRB5_PA_PW_SALT			3
#define KRB5_PA_ENC_ENCKEY		4
#define KRB5_PA_ENC_UNIX_TIME		5
#define KRB5_PA_ENC_SANDIA_SECURID	6
#define KRB5_PA_SESAME			7
#define KRB5_PA_OSF_DCE			8
#define KRB5_PA_CYBERSAFE_SECUREID	9
#define KRB5_PA_AFS3_SALT		10
#define KRB5_PA_ENCTYPE_INFO		11
#define KRB5_PA_SAM_CHALLENGE		12
#define KRB5_PA_SAM_RESPONSE		13
#define KRB5_PA_PK_AS_REQ		14
#define KRB5_PA_PK_AS_REP		15
#define KRB5_PA_DASS			16
#define KRB5_PA_ENCTYPE_INFO2		19
#define KRB5_PA_USE_SPECIFIED_KVNO	20
#define KRB5_PA_SAM_REDIRECT		21
#define KRB5_PA_GET_FROM_TYPED_DATA	22
#define KRB5_PA_SAM_ETYPE_INFO		23
#define KRB5_PA_ALT_PRINC		24
#define KRB5_PA_SAM_CHALLENGE2		30
#define KRB5_PA_SAM_RESPONSE2		31
#define KRB5_TD_PKINIT_CMS_CERTIFICATES	101
#define KRB5_TD_KRB_PRINCIPAL		102
#define KRB5_TD_KRB_REALM		103
#define KRB5_TD_TRUSTED_CERTIFIERS	104
#define KRB5_TD_CERTIFICATE_INDEX	105
#define KRB5_TD_APP_DEFINED_ERROR	106
#define KRB5_TD_REQ_NONCE		107
#define KRB5_TD_REQ_SEQ			108
/* preauthentication types >127 (i.e. negative ones) are app specific.
   however since Microsoft is the dominant(only?) user of types in this range
   we also treat the type as unsigned.
*/
#define KRB5_PA_PAC_REQUEST		128    /* (Microsoft extension) */
#define KRB5_PA_FOR_USER		129    /* Impersonation (Microsoft extension) See [MS-SFU]. XXX - replaced by KRB5_PA_S4U2SELF */
#define KRB5_PA_S4U2SELF		129

#define KRB5_PA_PROV_SRV_LOCATION 0xffffffff    /* (gint32)0xFF) packetcable stuff */
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
	{ 0, NULL }
};


#define PAC_LOGON_INFO		1
#define PAC_CREDENTIAL_TYPE	2
#define PAC_SERVER_CHECKSUM	6
#define PAC_PRIVSVR_CHECKSUM	7
#define PAC_CLIENT_INFO_TYPE	10
#define PAC_S4U_DELEGATION_INFO	11
#define PAC_UPN_DNS_INFO		12
static const value_string w2k_pac_types[] = {
	{ PAC_LOGON_INFO		, "Logon Info" },
	{ PAC_CREDENTIAL_TYPE	, "Credential Type" },
	{ PAC_SERVER_CHECKSUM	, "Server Checksum" },
	{ PAC_PRIVSVR_CHECKSUM	, "Privsvr Checksum" },
	{ PAC_CLIENT_INFO_TYPE	, "Client Info Type" },
	{ PAC_S4U_DELEGATION_INFO, "S4U Delegation Info" },
	{ PAC_UPN_DNS_INFO		, "UPN DNS Info" },
	{ 0, NULL },
};

#if 0
static const value_string krb5_princ_types[] = {
	{ KRB5_NT_UNKNOWN              , "Unknown" },
	{ KRB5_NT_PRINCIPAL            , "Principal" },
	{ KRB5_NT_SRV_INST             , "Service and Instance" },
	{ KRB5_NT_SRV_HST              , "Service and Host" },
	{ KRB5_NT_SRV_XHST             , "Service and Host Components" },
	{ KRB5_NT_UID                  , "Unique ID" },
	{ KRB5_NT_X500_PRINCIPAL       , "Encoded X.509 Distinguished Name" },
	{ KRB5_NT_SMTP_NAME            , "SMTP Name" },
	{ KRB5_NT_ENTERPRISE           , "Enterprise Name" },
	{ KRB5_NT_MS_PRINCIPAL         , "NT 4.0 style name (MS specific)" },
	{ KRB5_NT_MS_PRINCIPAL_AND_SID , "NT 4.0 style name with SID (MS specific)"},
	{ KRB5_NT_ENT_PRINCIPAL_AND_SID, "UPN and SID (MS specific)"},
	{ KRB5_NT_PRINCIPAL_AND_SID    , "Principal name and SID (MS specific)"},
	{ KRB5_NT_SRV_INST_AND_SID     , "SPN and SID (MS specific)"},
	{ 0                            , NULL },
};
#endif

static const value_string krb5_preauthentication_types[] = {
	{ KRB5_PA_TGS_REQ              , "PA-TGS-REQ" },
	{ KRB5_PA_ENC_TIMESTAMP        , "PA-ENC-TIMESTAMP" },
	{ KRB5_PA_PW_SALT              , "PA-PW-SALT" },
	{ KRB5_PA_ENC_ENCKEY           , "PA-ENC-ENCKEY" },
	{ KRB5_PA_ENC_UNIX_TIME        , "PA-ENC-UNIX-TIME" },
	{ KRB5_PA_ENC_SANDIA_SECURID   , "PA-PW-SALT" },
	{ KRB5_PA_SESAME               , "PA-SESAME" },
	{ KRB5_PA_OSF_DCE              , "PA-OSF-DCE" },
	{ KRB5_PA_CYBERSAFE_SECUREID   , "PA-CYBERSAFE-SECURID" },
	{ KRB5_PA_AFS3_SALT            , "PA-AFS3-SALT" },
	{ KRB5_PA_ENCTYPE_INFO         , "PA-ENCTYPE-INFO" },
	{ KRB5_PA_ENCTYPE_INFO2         , "PA-ENCTYPE-INFO2" },
	{ KRB5_PA_SAM_CHALLENGE        , "PA-SAM-CHALLENGE" },
	{ KRB5_PA_SAM_RESPONSE         , "PA-SAM-RESPONSE" },
	{ KRB5_PA_PK_AS_REQ            , "PA-PK-AS-REQ" },
	{ KRB5_PA_PK_AS_REP            , "PA-PK-AS-REP" },
	{ KRB5_PA_DASS                 , "PA-DASS" },
	{ KRB5_PA_USE_SPECIFIED_KVNO   , "PA-USE-SPECIFIED-KVNO" },
	{ KRB5_PA_SAM_REDIRECT         , "PA-SAM-REDIRECT" },
	{ KRB5_PA_GET_FROM_TYPED_DATA  , "PA-GET-FROM-TYPED-DATA" },
	{ KRB5_PA_SAM_ETYPE_INFO       , "PA-SAM-ETYPE-INFO" },
	{ KRB5_PA_ALT_PRINC            , "PA-ALT-PRINC" },
	{ KRB5_PA_SAM_CHALLENGE2       , "PA-SAM-CHALLENGE2" },
	{ KRB5_PA_SAM_RESPONSE2        , "PA-SAM-RESPONSE2" },
	{ KRB5_TD_PKINIT_CMS_CERTIFICATES, "TD-PKINIT-CMS-CERTIFICATES" },
	{ KRB5_TD_KRB_PRINCIPAL        , "TD-KRB-PRINCIPAL" },
	{ KRB5_TD_KRB_REALM , "TD-KRB-REALM" },
	{ KRB5_TD_TRUSTED_CERTIFIERS   , "TD-TRUSTED-CERTIFIERS" },
	{ KRB5_TD_CERTIFICATE_INDEX    , "TD-CERTIFICATE-INDEX" },
	{ KRB5_TD_APP_DEFINED_ERROR    , "TD-APP-DEFINED-ERROR" },
	{ KRB5_TD_REQ_NONCE            , "TD-REQ-NONCE" },
	{ KRB5_TD_REQ_SEQ              , "TD-REQ-SEQ" },
	{ KRB5_PA_PAC_REQUEST          , "PA-PAC-REQUEST" },
	{ KRB5_PA_FOR_USER             , "PA-FOR-USER" },
	{ KRB5_PA_PROV_SRV_LOCATION    , "PA-PROV-SRV-LOCATION" },
	{ 0                            , NULL },
};

#define KRB5_AD_IF_RELEVANT			1
#define KRB5_AD_INTENDED_FOR_SERVER		2
#define KRB5_AD_INTENDED_FOR_APPLICATION_CLASS	3
#define KRB5_AD_KDC_ISSUED			4
#define KRB5_AD_OR				5
#define KRB5_AD_MANDATORY_TICKET_EXTENSIONS	6
#define KRB5_AD_IN_TICKET_EXTENSIONS		7
#define KRB5_AD_MANDATORY_FOR_KDC		8
#define KRB5_AD_OSF_DCE				64
#define KRB5_AD_SESAME				65
#define KRB5_AD_OSF_DCE_PKI_CERTID		66
#define KRB5_AD_WIN2K_PAC				128
#define KRB5_AD_SIGNTICKET			0xffffffef

static const value_string krb5_ad_types[] = {
	{ KRB5_AD_IF_RELEVANT	  		, "AD-IF-RELEVANT" },
	{ KRB5_AD_INTENDED_FOR_SERVER		, "AD-Intended-For-Server" },
	{ KRB5_AD_INTENDED_FOR_APPLICATION_CLASS	, "AD-Intended-For-Application-Class" },
	{ KRB5_AD_KDC_ISSUED			, "AD-KDCIssued" },
	{ KRB5_AD_OR 				, "AD-AND-OR" },
	{ KRB5_AD_MANDATORY_TICKET_EXTENSIONS	, "AD-Mandatory-Ticket-Extensions" },
	{ KRB5_AD_IN_TICKET_EXTENSIONS		, "AD-IN-Ticket-Extensions" },
	{ KRB5_AD_MANDATORY_FOR_KDC			, "AD-MANDATORY-FOR-KDC" },
	{ KRB5_AD_OSF_DCE				, "AD-OSF-DCE" },
	{ KRB5_AD_SESAME				, "AD-SESAME" },
	{ KRB5_AD_OSF_DCE_PKI_CERTID		, "AD-OSF-DCE-PKI-CertID" },
	{ KRB5_AD_WIN2K_PAC				, "AD-Win2k-PAC" },
	{ KRB5_AD_SIGNTICKET			, "AD-SignTicket" },
	{ 0	, NULL },
};
#if 0
static const value_string krb5_transited_types[] = {
	{ 1                           , "DOMAIN-X500-COMPRESS" },
	{ 0                           , NULL }
};
#endif

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
static int
dissect_krb5_decrypt_ticket_data (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
	int length;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * All Ticket encrypted parts use usage == 2
	 */
	plaintext=decrypt_krb5_data(tree, actx->pinfo, 2, next_tvb, private_data->etype, NULL);

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);
		tvb_set_free_cb(child_tvb, g_free);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Decrypted Krb5");

		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_authenticator_data (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
											proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
	int length;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * Authenticators are encrypted with usage
	 * == 7 or
	 * == 11
	 */
	plaintext=decrypt_krb5_data(tree, actx->pinfo, 7, next_tvb, private_data->etype, NULL);

	if(!plaintext){
		plaintext=decrypt_krb5_data(tree, actx->pinfo, 11, next_tvb, private_data->etype, NULL);
	}

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);
		tvb_set_free_cb(child_tvb, g_free);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Decrypted Krb5");

		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_KDC_REP_data (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
	int length;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * ASREP/TGSREP encryptedparts are encrypted with usage
	 * == 3 or
	 * == 8 or
	 * == 9
	 */
	plaintext=decrypt_krb5_data(tree, actx->pinfo, 3, next_tvb, private_data->etype, NULL);

	if(!plaintext){
		plaintext=decrypt_krb5_data(tree, actx->pinfo, 8, next_tvb, private_data->etype, NULL);
	}

	if(!plaintext){
		plaintext=decrypt_krb5_data(tree, actx->pinfo, 9, next_tvb, private_data->etype, NULL);
	}

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);
		tvb_set_free_cb(child_tvb, g_free);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Decrypted Krb5");

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
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * AS-REQ PA_ENC_TIMESTAMP are encrypted with usage
	 * == 1
	 */
	plaintext=decrypt_krb5_data(tree, actx->pinfo, 1, next_tvb, private_data->etype, NULL);

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);
		tvb_set_free_cb(child_tvb, g_free);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Decrypted Krb5");

		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_AP_REP_data (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
	int length;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * AP-REP are encrypted with usage == 12
	 */
	plaintext=decrypt_krb5_data(tree, actx->pinfo, 12, next_tvb, private_data->etype, NULL);

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);
		tvb_set_free_cb(child_tvb, g_free);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Decrypted Krb5");

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
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* RFC4120 :
	 * EncKrbPrivPart encrypted with usage
	 * == 13
	 */
	plaintext=decrypt_krb5_data(tree, actx->pinfo, 13, next_tvb, private_data->etype, NULL);

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);
		tvb_set_free_cb(child_tvb, g_free);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Decrypted Krb5");

		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_CRED_data (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
	int length;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* RFC4120 :
	 * EncKrbCredPart encrypted with usage
	 * == 14
	 */
	plaintext=decrypt_krb5_data(tree, actx->pinfo, 14, next_tvb, private_data->etype, NULL);

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);
		tvb_set_free_cb(child_tvb, g_free);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Decrypted Krb5");

		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}
#endif

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
	guint32 nt_status;

	/* Microsoft stores a special 12 byte blob here
	 * guint32 NT_status
	 * guint32 unknown
	 * guint32 unknown
	 * decode everything as this blob for now until we see if anyone
	 * else ever uses it   or we learn how to tell whether this
	 * is such an MS blob or not.
	 */
	proto_tree_add_item(tree, hf_krb_smb_nt_status, tvb, offset, 4,
			ENC_LITTLE_ENDIAN);
	nt_status=tvb_get_letohl(tvb, offset);
	if(nt_status) {
		col_append_fstr(actx->pinfo->cinfo, COL_INFO,
			" NT Status: %s",
			val_to_str(nt_status, NT_errors,
			"Unknown error code %#x"));
	}
	offset += 4;

	proto_tree_add_item(tree, hf_krb_smb_unknown, tvb, offset, 4,
			ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_krb_smb_unknown, tvb, offset, 4,
			ENC_LITTLE_ENDIAN);
	offset += 4;

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

static int
dissect_krb5_PAC_UPN_DNS_INFO(proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	proto_item *item;
	proto_tree *tree;
	guint16 dns_offset, dns_len;
	guint16 upn_offset, upn_len;
	const char *dn;
	int dn_len;
	guint16 bc;

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
	proto_tree_add_item(tree, hf_krb_pac_upn_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);

	/* upn */
	offset = upn_offset;
	dn_len = upn_len;
	bc = tvb_reported_length_remaining(tvb, offset);
	dn = get_unicode_or_ascii_string(tvb, &offset, TRUE, &dn_len, TRUE, TRUE, &bc);
	proto_tree_add_string(tree, hf_krb_pac_upn_upn_name, tvb, upn_offset, upn_len, dn);

	/* dns */
	offset = dns_offset;
	dn_len = dns_len;
	bc = tvb_reported_length_remaining(tvb, offset);
	dn = get_unicode_or_ascii_string(tvb, &offset, TRUE, &dn_len, TRUE, TRUE, &bc);
	proto_tree_add_string(tree, hf_krb_pac_upn_dns_name, tvb, dns_offset, dns_len, dn);

	return offset;
}

static int
dissect_krb5_PAC_CREDENTIAL_TYPE(proto_tree *parent_tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	proto_tree_add_item(parent_tree, hf_krb_pac_credential_type, tvb, offset, -1, ENC_NA);

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

	next_tvb=tvb_new_subset(tvb, pac_offset, pac_size, pac_size);
	switch(pac_type){
	case PAC_LOGON_INFO:
		dissect_krb5_PAC_LOGON_INFO(tr, next_tvb, 0, actx);
		break;
	case PAC_CREDENTIAL_TYPE:
		dissect_krb5_PAC_CREDENTIAL_TYPE(tr, next_tvb, 0, actx);
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
  { -130, "kRB5-NT-ENT-PRINCIPAL-AND-ID" },
  { -128, "kRB5-NT-MS-PRINCIPAL" },
  { -129, "kRB5-NT-MS-PRINCIPAL-AND-ID" },
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
#line 225 "./asn1/kerberos/kerberos.cnf"
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
#line 229 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_ticket_data);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif
	return offset;



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
  { 32771, "cKSUMTYPE-GSSAPI" },
  { -138, "cKSUMTYPE-HMAC-MD5" },
  { -1138, "cKSUMTYPE-HMAC-MD5-ENC" },
  { 0, NULL }
};


static int
dissect_kerberos_CKSUMTYPE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 286 "./asn1/kerberos/kerberos.cnf"
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &(private_data->checksum_type));




  return offset;
}



static int
dissect_kerberos_T_checksum(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 290 "./asn1/kerberos/kerberos.cnf"
	tvbuff_t *next_tvb;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

	switch(private_data->checksum_type){
	case KRB5_CHKSUM_GSSAPI:
		offset=dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_index, &next_tvb);
		dissect_krb5_rfc1964_checksum(actx, tree, next_tvb);
		break;
	default:
		offset=dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_index, NULL);
	}
	return offset;



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
#line 304 "./asn1/kerberos/kerberos.cnf"
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

	offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
									&gbl_keytype);
	private_data->key.keytype = gbl_keytype;



  return offset;
}



static int
dissect_kerberos_T_keyvalue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 311 "./asn1/kerberos/kerberos.cnf"
	tvbuff_t *out_tvb;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &out_tvb);


	private_data->key.keylength = tvb_reported_length(out_tvb);
	private_data->key.keyvalue = tvb_get_ptr(out_tvb, 0, private_data->key.keylength);



  return offset;
}


static const ber_sequence_t EncryptionKey_sequence[] = {
  { &hf_kerberos_keytype    , BER_CLASS_CON, 0, 0, dissect_kerberos_T_keytype },
  { &hf_kerberos_keyvalue   , BER_CLASS_CON, 1, 0, dissect_kerberos_T_keyvalue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_EncryptionKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 320 "./asn1/kerberos/kerberos.cnf"
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptionKey_sequence, hf_index, ett_kerberos_EncryptionKey);


	if (private_data->key.keytype != 0) {
#ifdef HAVE_KERBEROS
		add_encryption_key(actx->pinfo, private_data->key.keytype, private_data->key.keylength, private_data->key.keyvalue, "key");
#endif
	}



  return offset;
}



static int
dissect_kerberos_T_ad_type(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 331 "./asn1/kerberos/kerberos.cnf"
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
									&(private_data->ad_type));


  return offset;
}



static int
dissect_kerberos_T_ad_data(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 338 "./asn1/kerberos/kerberos.cnf"
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);

	switch(private_data->ad_type){
	case KRB5_AD_WIN2K_PAC:
		offset=dissect_ber_octet_string_wcb(implicit_tag, actx, tree, tvb, offset, hf_index, dissect_krb5_AD_WIN2K_PAC);
		break;
	case KRB5_AD_IF_RELEVANT:
		offset=dissect_ber_octet_string_wcb(implicit_tag, actx, tree, tvb, offset, hf_index, dissect_kerberos_AD_IF_RELEVANT);
		break;
	default:
		offset=dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);
	}



  return offset;
}


static const ber_sequence_t AuthorizationData_item_sequence[] = {
  { &hf_kerberos_ad_type    , BER_CLASS_CON, 0, 0, dissect_kerberos_T_ad_type },
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
  { &hf_kerberos_subkey     , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_kerberos_EncryptionKey },
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


static const asn_namedbit TicketFlags_bits[] = {
  {  0, &hf_kerberos_TicketFlags_reserved, -1, -1, "reserved", NULL },
  {  1, &hf_kerberos_TicketFlags_forwardable, -1, -1, "forwardable", NULL },
  {  2, &hf_kerberos_TicketFlags_forwarded, -1, -1, "forwarded", NULL },
  {  3, &hf_kerberos_TicketFlags_proxiable, -1, -1, "proxiable", NULL },
  {  4, &hf_kerberos_TicketFlags_proxy, -1, -1, "proxy", NULL },
  {  5, &hf_kerberos_TicketFlags_may_postdate, -1, -1, "may-postdate", NULL },
  {  6, &hf_kerberos_TicketFlags_postdated, -1, -1, "postdated", NULL },
  {  7, &hf_kerberos_TicketFlags_invalid, -1, -1, "invalid", NULL },
  {  8, &hf_kerberos_TicketFlags_renewable, -1, -1, "renewable", NULL },
  {  9, &hf_kerberos_TicketFlags_initial, -1, -1, "initial", NULL },
  { 10, &hf_kerberos_TicketFlags_pre_authent, -1, -1, "pre-authent", NULL },
  { 11, &hf_kerberos_TicketFlags_hw_authent, -1, -1, "hw-authent", NULL },
  { 12, &hf_kerberos_TicketFlags_transited_policy_checked, -1, -1, "transited-policy-checked", NULL },
  { 13, &hf_kerberos_TicketFlags_ok_as_delegate, -1, -1, "ok-as-delegate", NULL },
  { 14, &hf_kerberos_TicketFlags_anonymous, -1, -1, "anonymous", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_kerberos_TicketFlags(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    TicketFlags_bits, hf_index, ett_kerberos_TicketFlags,
                                    NULL);

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
#line 352 "./asn1/kerberos/kerberos.cnf"
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &(private_data->addr_type));




  return offset;
}



static int
dissect_kerberos_T_address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 174 "./asn1/kerberos/kerberos.cnf"
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
		address_str = tvb_ip_to_str(tvb, offset);
		break;
	case KERBEROS_ADDR_TYPE_NETBIOS:
		{
		char netbios_name[(NETBIOS_NAME_LEN - 1)*4 + 1];
		int netbios_name_type;
		int netbios_name_len = (NETBIOS_NAME_LEN - 1)*4 + 1;

		netbios_name_type = process_netbios_name(tvb_get_ptr(tvb, offset, 16), netbios_name, netbios_name_len);
		address_str = wmem_strdup_printf(wmem_packet_scope(), "%s<%02x>", netbios_name, netbios_name_type);
		it=proto_tree_add_string_format(tree, hf_krb_address_netbios, tvb, offset, 16, netbios_name, "NetBIOS Name: %s (%s)", address_str, netbios_name_type_descr(netbios_name_type));
		}
		break;
	case KERBEROS_ADDR_TYPE_IPV6:
		it=proto_tree_add_item(tree, hf_krb_address_ipv6, tvb, offset, INET6_ADDRLEN, ENC_NA);
		address_str = tvb_ip6_to_str(tvb, offset);
		break;
	default:
		proto_tree_add_expert(tree, actx->pinfo, &ei_kerberos_address, tvb, offset, len);
		address_str = NULL;
	}

	/* push it up two levels in the decode pane */
	if(it && address_str){
		proto_item_append_text(proto_item_get_parent(it), " %s",address_str);
		proto_item_append_text(proto_item_get_parent_nth(it, 2), " %s",address_str);
	}

	offset+=len;
	return offset;




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
  { &hf_kerberos_key        , BER_CLASS_CON, 1, 0, dissect_kerberos_EncryptionKey },
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
  {  20, "krb-safe" },
  {  21, "krb-priv" },
  {  22, "krb-cred" },
  {  30, "krb-error" },
  { 0, NULL }
};


static int
dissect_kerberos_MESSAGE_TYPE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 68 "./asn1/kerberos/kerberos.cnf"
guint32 msgtype;

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &msgtype);




#line 73 "./asn1/kerberos/kerberos.cnf"
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


  return offset;
}


static const value_string kerberos_PADATA_TYPE_vals[] = {
  {   0, "kRB5-PADATA-NONE" },
  {   1, "kRB5-PADATA-TGS-REQ" },
  {   1, "kRB5-PADATA-AP-REQ" },
  {   2, "kRB5-PADATA-ENC-TIMESTAMP" },
  {   3, "kRB5-PADATA-PW-SALT" },
  {   5, "kRB5-PADATA-ENC-UNIX-TIME" },
  {   6, "kRB5-PADATA-SANDIA-SECUREID" },
  {   7, "kRB5-PADATA-SESAME" },
  {   8, "kRB5-PADATA-OSF-DCE" },
  {   9, "kRB5-PADATA-CYBERSAFE-SECUREID" },
  {  10, "kRB5-PADATA-AFS3-SALT" },
  {  11, "kRB5-PADATA-ETYPE-INFO" },
  {  12, "kRB5-PADATA-SAM-CHALLENGE" },
  {  13, "kRB5-PADATA-SAM-RESPONSE" },
  {  14, "kRB5-PADATA-PK-AS-REQ-19" },
  {  15, "kRB5-PADATA-PK-AS-REP-19" },
  {  15, "kRB5-PADATA-PK-AS-REQ-WIN" },
  {  16, "kRB5-PADATA-PK-AS-REQ" },
  {  17, "kRB5-PADATA-PK-AS-REP" },
  {  18, "kRB5-PADATA-PA-PK-OCSP-RESPONSE" },
  {  19, "kRB5-PADATA-ETYPE-INFO2" },
  {  20, "kRB5-PADATA-USE-SPECIFIED-KVNO" },
  {  20, "kRB5-PADATA-SVR-REFERRAL-INFO" },
  {  21, "kRB5-PADATA-SAM-REDIRECT" },
  {  22, "kRB5-PADATA-GET-FROM-TYPED-DATA" },
  {  23, "kRB5-PADATA-SAM-ETYPE-INFO" },
  {  25, "kRB5-PADATA-SERVER-REFERRAL" },
  { 102, "kRB5-PADATA-TD-KRB-PRINCIPAL" },
  { 104, "kRB5-PADATA-PK-TD-TRUSTED-CERTIFIERS" },
  { 105, "kRB5-PADATA-PK-TD-CERTIFICATE-INDEX" },
  { 106, "kRB5-PADATA-TD-APP-DEFINED-ERROR" },
  { 107, "kRB5-PADATA-TD-REQ-NONCE" },
  { 108, "kRB5-PADATA-TD-REQ-SEQ" },
  { 128, "kRB5-PADATA-PA-PAC-REQUEST" },
  { 129, "kRB5-PADATA-S4U2SELF" },
  { 132, "kRB5-PADATA-PK-AS-09-BINDING" },
  { 133, "kRB5-PADATA-CLIENT-CANONICALIZED" },
  { 0, NULL }
};


static int
dissect_kerberos_PADATA_TYPE(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 121 "./asn1/kerberos/kerberos.cnf"
	kerberos_private_data_t* private_data = kerberos_get_private_data(actx);
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &(private_data->padata_type));



#line 124 "./asn1/kerberos/kerberos.cnf"
	if(tree){
		proto_item_append_text(tree, " %s",
			val_to_str(private_data->padata_type, krb5_preauthentication_types,
			"Unknown:%d"));
	}


  return offset;
}



static int
dissect_kerberos_T_padata_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 131 "./asn1/kerberos/kerberos.cnf"
	proto_tree *sub_tree=tree;
	kerberos_private_data_t* private_data = kerberos_get_private_data(actx);

	if(actx->created_item){
		sub_tree=proto_item_add_subtree(actx->created_item, ett_kerberos_PA_DATA);
	}

	switch(private_data->padata_type){
	case KRB5_PA_TGS_REQ:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_Applications);
 		break;
	case KRB5_PA_PK_AS_REQ:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_pkinit_PaPkAsReq);
 		break;
 	case KRB5_PA_PK_AS_REP:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_pkinit_PaPkAsRep);
 		break;
	case KRB5_PA_PAC_REQUEST:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_KERB_PA_PAC_REQUEST);
		break;
	case KRB5_PA_S4U2SELF:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_PA_S4U2Self);
 		break;
	case KRB5_PA_PROV_SRV_LOCATION:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_krb5_PA_PROV_SRV_LOCATION);
 		break;
	case KRB5_PA_ENC_TIMESTAMP:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_PA_ENC_TIMESTAMP);
 		break;
	case KRB5_PA_ENCTYPE_INFO:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_ETYPE_INFO);
 		break;
	case KRB5_PA_ENCTYPE_INFO2:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_kerberos_ETYPE_INFO2);
 		break;
	case KRB5_PA_PW_SALT:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, dissect_krb5_PW_SALT);
 		break;
	default:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, sub_tree, tvb, offset,hf_index, NULL);
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


static const ber_sequence_t SEQUENCE_OF_PA_DATA_sequence_of[1] = {
  { &hf_kerberos_padata_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_kerberos_PA_DATA },
};

static int
dissect_kerberos_SEQUENCE_OF_PA_DATA(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_PA_DATA_sequence_of, hf_index, ett_kerberos_SEQUENCE_OF_PA_DATA);

  return offset;
}


static const asn_namedbit KDCOptions_bits[] = {
  {  0, &hf_kerberos_KDCOptions_reserved, -1, -1, "reserved", NULL },
  {  1, &hf_kerberos_KDCOptions_forwardable, -1, -1, "forwardable", NULL },
  {  2, &hf_kerberos_KDCOptions_forwarded, -1, -1, "forwarded", NULL },
  {  3, &hf_kerberos_KDCOptions_proxiable, -1, -1, "proxiable", NULL },
  {  4, &hf_kerberos_KDCOptions_proxy, -1, -1, "proxy", NULL },
  {  5, &hf_kerberos_KDCOptions_allow_postdate, -1, -1, "allow-postdate", NULL },
  {  6, &hf_kerberos_KDCOptions_postdated, -1, -1, "postdated", NULL },
  {  7, &hf_kerberos_KDCOptions_unused7, -1, -1, "unused7", NULL },
  {  8, &hf_kerberos_KDCOptions_renewable, -1, -1, "renewable", NULL },
  {  9, &hf_kerberos_KDCOptions_unused9, -1, -1, "unused9", NULL },
  { 10, &hf_kerberos_KDCOptions_unused10, -1, -1, "unused10", NULL },
  { 11, &hf_kerberos_KDCOptions_opt_hardware_auth, -1, -1, "opt-hardware-auth", NULL },
  { 14, &hf_kerberos_KDCOptions_request_anonymous, -1, -1, "request-anonymous", NULL },
  { 15, &hf_kerberos_KDCOptions_canonicalize, -1, -1, "canonicalize", NULL },
  { 16, &hf_kerberos_KDCOptions_constrained_delegation, -1, -1, "constrained-delegation", NULL },
  { 26, &hf_kerberos_KDCOptions_disable_transited_check, -1, -1, "disable-transited-check", NULL },
  { 27, &hf_kerberos_KDCOptions_renewable_ok, -1, -1, "renewable-ok", NULL },
  { 28, &hf_kerberos_KDCOptions_enc_tkt_in_skey, -1, -1, "enc-tkt-in-skey", NULL },
  { 30, &hf_kerberos_KDCOptions_renew, -1, -1, "renew", NULL },
  { 31, &hf_kerberos_KDCOptions_validate, -1, -1, "validate", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_kerberos_KDCOptions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    KDCOptions_bits, hf_index, ett_kerberos_KDCOptions,
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
#line 237 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_authenticator_data);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif
	return offset;



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
#line 356 "./asn1/kerberos/kerberos.cnf"
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
		conversation = find_conversation(actx->pinfo->num, &actx->pinfo->src, &actx->pinfo->dst, PT_UDP,
											actx->pinfo->srcport, 0, NO_PORT_B);
		if (conversation == NULL) {
			conversation = conversation_new(actx->pinfo->num, &actx->pinfo->src, &actx->pinfo->dst, PT_UDP,
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
  { &hf_kerberos_padata     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_kerberos_SEQUENCE_OF_PA_DATA },
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



static int
dissect_kerberos_T_encryptedKDCREPData_cipher(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 245 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_KDC_REP_data);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif
	return offset;



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
  { &hf_kerberos_padata     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_kerberos_SEQUENCE_OF_PA_DATA },
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


static const asn_namedbit APOptions_bits[] = {
  {  0, &hf_kerberos_APOptions_reserved, -1, -1, "reserved", NULL },
  {  1, &hf_kerberos_APOptions_use_session_key, -1, -1, "use-session-key", NULL },
  {  2, &hf_kerberos_APOptions_mutual_required, -1, -1, "mutual-required", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_kerberos_APOptions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    APOptions_bits, hf_index, ett_kerberos_APOptions,
                                    NULL);

  return offset;
}


static const ber_sequence_t AP_REQ_U_sequence[] = {
  { &hf_kerberos_pvno       , BER_CLASS_CON, 0, 0, dissect_kerberos_INTEGER_5 },
  { &hf_kerberos_msg_type   , BER_CLASS_CON, 1, 0, dissect_kerberos_MESSAGE_TYPE },
  { &hf_kerberos_ap_options , BER_CLASS_CON, 2, 0, dissect_kerberos_APOptions },
  { &hf_kerberos_ticket     , BER_CLASS_CON, 3, 0, dissect_kerberos_Ticket },
  { &hf_kerberos_authenticator_01, BER_CLASS_CON, 4, 0, dissect_kerberos_EncryptedAuthorizationData },
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
#line 261 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_AP_REP_data);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif
	return offset;



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
#line 379 "./asn1/kerberos/kerberos.cnf"
	tvbuff_t *new_tvb;
	offset=dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_index, &new_tvb);
	if (new_tvb) {
		call_kerberos_callbacks(actx->pinfo, tree, new_tvb, KRB_CBTAG_SAFE_USER_DATA, (kerberos_callbacks*)actx->private_data);
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
#line 269 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_PRIV_data);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif
	return offset;



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
#line 277 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_CRED_data);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif
	return offset;




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


static const ber_sequence_t EncKDCRepPart_sequence[] = {
  { &hf_kerberos_key        , BER_CLASS_CON, 0, 0, dissect_kerberos_EncryptionKey },
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
  { &hf_kerberos_encrypted_pa_data, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_kerberos_METHOD_DATA },
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


static const ber_sequence_t EncAPRepPart_U_sequence[] = {
  { &hf_kerberos_ctime      , BER_CLASS_CON, 0, 0, dissect_kerberos_KerberosTime },
  { &hf_kerberos_cusec      , BER_CLASS_CON, 1, 0, dissect_kerberos_Microseconds },
  { &hf_kerberos_subkey     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_kerberos_EncryptionKey },
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
#line 386 "./asn1/kerberos/kerberos.cnf"
	tvbuff_t *new_tvb;
	offset=dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_index, &new_tvb);
	if (new_tvb) {
		call_kerberos_callbacks(actx->pinfo, tree, new_tvb, KRB_CBTAG_PRIV_USER_DATA, (kerberos_callbacks*)actx->private_data);
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
  { &hf_kerberos_key        , BER_CLASS_CON, 0, 0, dissect_kerberos_EncryptionKey },
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
#line 86 "./asn1/kerberos/kerberos.cnf"
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &krb5_errorcode);




#line 89 "./asn1/kerberos/kerberos.cnf"
	if(krb5_errorcode) {
		col_add_fstr(actx->pinfo->cinfo, COL_INFO,
			"KRB Error: %s",
			val_to_str(krb5_errorcode, krb5_error_codes,
			"Unknown error code %#x"));
	}

	return offset;

  return offset;
}



static int
dissect_kerberos_T_e_data(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 99 "./asn1/kerberos/kerberos.cnf"
	switch(krb5_errorcode){
	case KRB5_ET_KRB5KDC_ERR_BADOPTION:
	case KRB5_ET_KRB5KDC_ERR_CLIENT_REVOKED:
	case KRB5_ET_KRB5KDC_ERR_KEY_EXP:
	case KRB5_ET_KRB5KDC_ERR_POLICY:
		/* ms windows kdc sends e-data of this type containing a "salt"
		 * that contains the nt_status code for these error codes.
		 */
		offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_kerberos_e_data, dissect_kerberos_PA_DATA);
		break;
	case KRB5_ET_KRB5KDC_ERR_PREAUTH_REQUIRED:
	case KRB5_ET_KRB5KDC_ERR_PREAUTH_FAILED:
	case KRB5_ET_KRB5KDC_ERR_ETYPE_NOSUPP:
		offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_kerberos_e_data, dissect_kerberos_SEQUENCE_OF_PA_DATA);

		break;
	default:
		offset=dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_kerberos_e_data, NULL);
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
#line 253 "./asn1/kerberos/kerberos.cnf"
#ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, actx, tree, tvb, offset, hf_index, dissect_krb5_decrypt_PA_ENC_TIMESTAMP);
#else
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

#endif
	return offset;



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
  { &hf_kerberos_salt       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_OCTET_STRING },
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
  { &hf_kerberos_salt_01    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_kerberos_KerberosString },
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
dissect_kerberos_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t KERB_PA_PAC_REQUEST_sequence[] = {
  { &hf_kerberos_include_pac, BER_CLASS_CON, 0, 0, dissect_kerberos_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_kerberos_KERB_PA_PAC_REQUEST(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KERB_PA_PAC_REQUEST_sequence, hf_index, ett_kerberos_KERB_PA_PAC_REQUEST);

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


/*--- End of included file: packet-kerberos-fn.c ---*/
#line 1861 "./asn1/kerberos/packet-kerberos-template.c"

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


static gint
dissect_kerberos_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean dci, gboolean do_col_protocol, gboolean have_rm,
    kerberos_callbacks *cb)
{
	volatile int offset = 0;
	proto_tree *volatile kerberos_tree = NULL;
	proto_item *volatile item = NULL;
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
	asn1_ctx.private_data = cb;

	TRY {
		offset=dissect_kerberos_Applications(FALSE, tvb, offset, &asn1_ctx , kerberos_tree, /* hf_index */ -1);
	} CATCH_BOUNDS_ERRORS {
		RETHROW;
	} ENDTRY;

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
	{ &hf_krb_smb_nt_status,
		{ "NT Status", "kerberos.smb.nt_status", FT_UINT32, BASE_HEX,
		VALS(NT_errors), 0, "NT Status code", HFILL }},
	{ &hf_krb_smb_unknown,
		{ "Unknown", "kerberos.smb.unknown", FT_UINT32, BASE_HEX,
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
	{ &hf_krb_pac_credential_type, {
		"PAC_CREDENTIAL_TYPE", "kerberos.pac_credential_type", FT_BYTES, BASE_NONE,
		NULL, 0, "PAC_CREDENTIAL_TYPE structure", HFILL }},
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
	{ &hf_krb_pac_upn_dns_offset, {
		"DNS Offset", "kerberos.pac.upn.dns_offset", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_upn_dns_len, {
		"DNS Len", "kerberos.pac.upn.dns_len", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_upn_upn_offset, {
		"UPN Offset", "kerberos.pac.upn.upn_offset", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_upn_upn_len, {
		"UPN Len", "kerberos.pac.upn.upn_len", FT_UINT16, BASE_DEC,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_upn_upn_name, {
		"UPN Name", "kerberos.pac.upn.upn_name", FT_STRING, BASE_NONE,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_pac_upn_dns_name, {
		"DNS Name", "kerberos.pac.upn.dns_name", FT_STRING, BASE_NONE,
		NULL, 0, NULL, HFILL }},


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
        FT_INT32, BASE_DEC, VALS(krb5_ad_types), 0,
        NULL, HFILL }},
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
    { &hf_kerberos_key,
      { "key", "kerberos.key_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptionKey", HFILL }},
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
        FT_STRING, BASE_NONE, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_starttime,
      { "starttime", "kerberos.starttime",
        FT_STRING, BASE_NONE, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_endtime,
      { "endtime", "kerberos.endtime",
        FT_STRING, BASE_NONE, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_renew_till,
      { "renew-till", "kerberos.renew_till",
        FT_STRING, BASE_NONE, NULL, 0,
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
    { &hf_kerberos_padata,
      { "padata", "kerberos.padata",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PA_DATA", HFILL }},
    { &hf_kerberos_padata_item,
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
        FT_STRING, BASE_NONE, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_till,
      { "till", "kerberos.till",
        FT_STRING, BASE_NONE, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_rtime,
      { "rtime", "kerberos.rtime",
        FT_STRING, BASE_NONE, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_nonce,
      { "nonce", "kerberos.nonce",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UInt32", HFILL }},
    { &hf_kerberos_kDC_REQ_BODY_etype,
      { "etype", "kerberos.etype",
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
    { &hf_kerberos_kDC_REP_enc_part,
      { "enc-part", "kerberos.enc_part_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedKDCREPData", HFILL }},
    { &hf_kerberos_last_req,
      { "last-req", "kerberos.last_req",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LastReq", HFILL }},
    { &hf_kerberos_key_expiration,
      { "key-expiration", "kerberos.key_expiration",
        FT_STRING, BASE_NONE, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_srealm,
      { "srealm", "kerberos.srealm",
        FT_STRING, BASE_NONE, NULL, 0,
        "Realm", HFILL }},
    { &hf_kerberos_encrypted_pa_data,
      { "encrypted-pa-data", "kerberos.encrypted_pa_data",
        FT_UINT32, BASE_DEC, NULL, 0,
        "METHOD_DATA", HFILL }},
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
        FT_STRING, BASE_NONE, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_ap_options,
      { "ap-options", "kerberos.ap_options",
        FT_BYTES, BASE_NONE, NULL, 0,
        "APOptions", HFILL }},
    { &hf_kerberos_authenticator_01,
      { "authenticator", "kerberos.authenticator_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedAuthorizationData", HFILL }},
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
        FT_STRING, BASE_NONE, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_kerberos_subkey,
      { "subkey", "kerberos.subkey_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptionKey", HFILL }},
    { &hf_kerberos_seq_number,
      { "seq-number", "kerberos.seq_number",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UInt32", HFILL }},
    { &hf_kerberos_aP_REP_enc_part,
      { "enc-part", "kerberos.enc_part_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedAPREPData", HFILL }},
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
        FT_STRING, BASE_NONE, NULL, 0,
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
        FT_STRING, BASE_NONE, NULL, 0,
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
    { &hf_kerberos_salt,
      { "salt", "kerberos.salt",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_kerberos_ETYPE_INFO_item,
      { "ETYPE-INFO-ENTRY", "kerberos.ETYPE_INFO_ENTRY_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_kerberos_salt_01,
      { "salt", "kerberos.salt",
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
    { &hf_kerberos_name,
      { "name", "kerberos.name_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrincipalName", HFILL }},
    { &hf_kerberos_auth,
      { "auth", "kerberos.auth",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralString", HFILL }},
    { &hf_kerberos_include_pac,
      { "include-pac", "kerberos.include_pac",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
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
    { &hf_kerberos_APOptions_reserved,
      { "reserved", "kerberos.reserved",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_APOptions_use_session_key,
      { "use-session-key", "kerberos.use-session-key",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_kerberos_APOptions_mutual_required,
      { "mutual-required", "kerberos.mutual-required",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_reserved,
      { "reserved", "kerberos.reserved",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_forwardable,
      { "forwardable", "kerberos.forwardable",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_forwarded,
      { "forwarded", "kerberos.forwarded",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_proxiable,
      { "proxiable", "kerberos.proxiable",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_proxy,
      { "proxy", "kerberos.proxy",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_may_postdate,
      { "may-postdate", "kerberos.may-postdate",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_postdated,
      { "postdated", "kerberos.postdated",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_invalid,
      { "invalid", "kerberos.invalid",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_renewable,
      { "renewable", "kerberos.renewable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_initial,
      { "initial", "kerberos.initial",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_pre_authent,
      { "pre-authent", "kerberos.pre-authent",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_hw_authent,
      { "hw-authent", "kerberos.hw-authent",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_transited_policy_checked,
      { "transited-policy-checked", "kerberos.transited-policy-checked",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_ok_as_delegate,
      { "ok-as-delegate", "kerberos.ok-as-delegate",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_kerberos_TicketFlags_anonymous,
      { "anonymous", "kerberos.anonymous",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_reserved,
      { "reserved", "kerberos.reserved",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_forwardable,
      { "forwardable", "kerberos.forwardable",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_forwarded,
      { "forwarded", "kerberos.forwarded",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_proxiable,
      { "proxiable", "kerberos.proxiable",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_proxy,
      { "proxy", "kerberos.proxy",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_allow_postdate,
      { "allow-postdate", "kerberos.allow-postdate",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_postdated,
      { "postdated", "kerberos.postdated",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused7,
      { "unused7", "kerberos.unused7",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_renewable,
      { "renewable", "kerberos.renewable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused9,
      { "unused9", "kerberos.unused9",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_unused10,
      { "unused10", "kerberos.unused10",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_opt_hardware_auth,
      { "opt-hardware-auth", "kerberos.opt-hardware-auth",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_request_anonymous,
      { "request-anonymous", "kerberos.request-anonymous",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_canonicalize,
      { "canonicalize", "kerberos.canonicalize",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_constrained_delegation,
      { "constrained-delegation", "kerberos.constrained-delegation",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_disable_transited_check,
      { "disable-transited-check", "kerberos.disable-transited-check",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_renewable_ok,
      { "renewable-ok", "kerberos.renewable-ok",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_enc_tkt_in_skey,
      { "enc-tkt-in-skey", "kerberos.enc-tkt-in-skey",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_renew,
      { "renew", "kerberos.renew",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_kerberos_KDCOptions_validate,
      { "validate", "kerberos.validate",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},

/*--- End of included file: packet-kerberos-hfarr.c ---*/
#line 2242 "./asn1/kerberos/packet-kerberos-template.c"
	};

	/* List of subtrees */
	static gint *ett[] = {
		&ett_kerberos,
		&ett_krb_recordmark,
		&ett_krb_pac,
		&ett_krb_pac_drep,
		&ett_krb_pac_midl_blob,
		&ett_krb_pac_logon_info,
		&ett_krb_pac_s4u_delegation_info,
		&ett_krb_pac_upn_dns_info,
		&ett_krb_pac_server_checksum,
		&ett_krb_pac_privsvr_checksum,
		&ett_krb_pac_client_info_type,

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
    &ett_kerberos_EncryptedKDCREPData,
    &ett_kerberos_EncryptedAPREPData,
    &ett_kerberos_EncryptedKrbPrivData,
    &ett_kerberos_EncryptedKrbCredData,
    &ett_kerberos_Ticket_U,
    &ett_kerberos_EncTicketPart_U,
    &ett_kerberos_TransitedEncoding,
    &ett_kerberos_KDC_REQ,
    &ett_kerberos_SEQUENCE_OF_PA_DATA,
    &ett_kerberos_KDC_REQ_BODY,
    &ett_kerberos_SEQUENCE_OF_ENCTYPE,
    &ett_kerberos_SEQUENCE_OF_Ticket,
    &ett_kerberos_KDC_REP,
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
    &ett_kerberos_APOptions,
    &ett_kerberos_TicketFlags,
    &ett_kerberos_KDCOptions,
    &ett_kerberos_PA_S4U2Self,
    &ett_kerberos_KERB_PA_PAC_REQUEST,
    &ett_kerberos_ChangePasswdData,

/*--- End of included file: packet-kerberos-ettarr.c ---*/
#line 2258 "./asn1/kerberos/packet-kerberos-template.c"
	};

	static ei_register_info ei[] = {
		{ &ei_kerberos_decrypted_keytype, { "kerberos.decrypted_keytype", PI_SECURITY, PI_CHAT, "Decryted keytype", EXPFILL }},
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
				   &keytab_filename);
#endif

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

	dissector_add_uint("udp.port", UDP_PORT_KERBEROS, kerberos_handle_udp);
	dissector_add_uint("tcp.port", TCP_PORT_KERBEROS, kerberos_handle_tcp);

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
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
