/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-credssp.c                                                           */
/* asn2wrs.py -b -C -p credssp -c ./credssp.cnf -s ./packet-credssp-template -D . -O ../.. CredSSP.asn */

/* Input file: packet-credssp-template.c */

#line 1 "./asn1/credssp/packet-credssp-template.c"
/* packet-credssp.c
 * Routines for CredSSP (Credential Security Support Provider) packet dissection
 * Graeme Lunt 2011
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/tap.h>
#include <epan/exported_pdu.h>

#include "packet-ber.h"
#include "packet-dcerpc.h"
#include "packet-gssapi.h"
#include "packet-kerberos.h"
#include "packet-ntlmssp.h"
#include "packet-credssp.h"

#define PNAME  "Credential Security Support Provider"
#define PSNAME "CredSSP"
#define PFNAME "credssp"

#define TS_PASSWORD_CREDS   1
#define TS_SMARTCARD_CREDS  2
#define TS_REMOTEGUARD_CREDS  6

static gint creds_type;
static gint credssp_ver;

static char kerberos_pname[] = "K\0e\0r\0b\0e\0r\0o\0s";
static char ntlm_pname[] = "N\0T\0L\0M";

#define TS_RGC_UNKNOWN	0
#define TS_RGC_KERBEROS	1
#define TS_RGC_NTLM	2

static gint credssp_TS_RGC_package;

static gint exported_pdu_tap = -1;

/* Initialize the protocol and registered fields */
static int proto_credssp = -1;

/* List of dissectors to call for negoToken data */
static heur_dissector_list_t credssp_heur_subdissector_list;

static dissector_handle_t gssapi_handle;
static dissector_handle_t gssapi_wrap_handle;

static int hf_credssp_TSPasswordCreds = -1;   /* TSPasswordCreds */
static int hf_credssp_TSSmartCardCreds = -1;  /* TSSmartCardCreds */
static int hf_credssp_TSRemoteGuardCreds = -1;/* TSRemoteGuardCreds */
static int hf_credssp_TSCredentials = -1;     /* TSCredentials */
static int hf_credssp_decr_PublicKeyAuth = -1;/* decr_PublicKeyAuth */

/*--- Included file: packet-credssp-hf.c ---*/
#line 1 "./asn1/credssp/packet-credssp-hf.c"
static int hf_credssp_TSRequest_PDU = -1;         /* TSRequest */
static int hf_credssp_NegoData_item = -1;         /* NegoData_item */
static int hf_credssp_negoToken = -1;             /* T_negoToken */
static int hf_credssp_domainName = -1;            /* OCTET_STRING */
static int hf_credssp_userName = -1;              /* OCTET_STRING */
static int hf_credssp_password = -1;              /* OCTET_STRING */
static int hf_credssp_keySpec = -1;               /* INTEGER */
static int hf_credssp_cardName = -1;              /* OCTET_STRING */
static int hf_credssp_readerName = -1;            /* OCTET_STRING */
static int hf_credssp_containerName = -1;         /* OCTET_STRING */
static int hf_credssp_cspName = -1;               /* OCTET_STRING */
static int hf_credssp_pin = -1;                   /* OCTET_STRING */
static int hf_credssp_cspData = -1;               /* TSCspDataDetail */
static int hf_credssp_userHint = -1;              /* OCTET_STRING */
static int hf_credssp_domainHint = -1;            /* OCTET_STRING */
static int hf_credssp_packageName = -1;           /* T_packageName */
static int hf_credssp_credBuffer = -1;            /* T_credBuffer */
static int hf_credssp_logonCred = -1;             /* TSRemoteGuardPackageCred */
static int hf_credssp_supplementalCreds = -1;     /* SEQUENCE_OF_TSRemoteGuardPackageCred */
static int hf_credssp_supplementalCreds_item = -1;  /* TSRemoteGuardPackageCred */
static int hf_credssp_credType = -1;              /* T_credType */
static int hf_credssp_credentials = -1;           /* T_credentials */
static int hf_credssp_version = -1;               /* T_version */
static int hf_credssp_negoTokens = -1;            /* NegoData */
static int hf_credssp_authInfo = -1;              /* T_authInfo */
static int hf_credssp_pubKeyAuth = -1;            /* T_pubKeyAuth */
static int hf_credssp_errorCode = -1;             /* T_errorCode */
static int hf_credssp_clientNonce = -1;           /* T_clientNonce */

/*--- End of included file: packet-credssp-hf.c ---*/
#line 63 "./asn1/credssp/packet-credssp-template.c"

/* Initialize the subtree pointers */
static gint ett_credssp = -1;
static gint ett_credssp_RGC_CredBuffer = -1;


/*--- Included file: packet-credssp-ett.c ---*/
#line 1 "./asn1/credssp/packet-credssp-ett.c"
static gint ett_credssp_NegoData = -1;
static gint ett_credssp_NegoData_item = -1;
static gint ett_credssp_TSPasswordCreds = -1;
static gint ett_credssp_TSCspDataDetail = -1;
static gint ett_credssp_TSSmartCardCreds = -1;
static gint ett_credssp_TSRemoteGuardPackageCred = -1;
static gint ett_credssp_TSRemoteGuardCreds = -1;
static gint ett_credssp_SEQUENCE_OF_TSRemoteGuardPackageCred = -1;
static gint ett_credssp_TSCredentials = -1;
static gint ett_credssp_TSRequest = -1;

/*--- End of included file: packet-credssp-ett.c ---*/
#line 69 "./asn1/credssp/packet-credssp-template.c"


/*--- Included file: packet-credssp-fn.c ---*/
#line 1 "./asn1/credssp/packet-credssp-fn.c"


static int
dissect_credssp_T_negoToken(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 81 "./asn1/credssp/credssp.cnf"
	tvbuff_t *token_tvb = NULL;

	  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &token_tvb);


	if(token_tvb != NULL)
		call_dissector(gssapi_handle, token_tvb, actx->pinfo, tree);




  return offset;
}


static const ber_sequence_t NegoData_item_sequence[] = {
  { &hf_credssp_negoToken   , BER_CLASS_CON, 0, 0, dissect_credssp_T_negoToken },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_credssp_NegoData_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NegoData_item_sequence, hf_index, ett_credssp_NegoData_item);

  return offset;
}


static const ber_sequence_t NegoData_sequence_of[1] = {
  { &hf_credssp_NegoData_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_credssp_NegoData_item },
};

static int
dissect_credssp_NegoData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      NegoData_sequence_of, hf_index, ett_credssp_NegoData);

  return offset;
}



static int
dissect_credssp_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t TSPasswordCreds_sequence[] = {
  { &hf_credssp_domainName  , BER_CLASS_CON, 0, 0, dissect_credssp_OCTET_STRING },
  { &hf_credssp_userName    , BER_CLASS_CON, 1, 0, dissect_credssp_OCTET_STRING },
  { &hf_credssp_password    , BER_CLASS_CON, 2, 0, dissect_credssp_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_credssp_TSPasswordCreds(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TSPasswordCreds_sequence, hf_index, ett_credssp_TSPasswordCreds);

  return offset;
}



static int
dissect_credssp_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t TSCspDataDetail_sequence[] = {
  { &hf_credssp_keySpec     , BER_CLASS_CON, 0, 0, dissect_credssp_INTEGER },
  { &hf_credssp_cardName    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_credssp_OCTET_STRING },
  { &hf_credssp_readerName  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_credssp_OCTET_STRING },
  { &hf_credssp_containerName, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_credssp_OCTET_STRING },
  { &hf_credssp_cspName     , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_credssp_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_credssp_TSCspDataDetail(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TSCspDataDetail_sequence, hf_index, ett_credssp_TSCspDataDetail);

  return offset;
}


static const ber_sequence_t TSSmartCardCreds_sequence[] = {
  { &hf_credssp_pin         , BER_CLASS_CON, 0, 0, dissect_credssp_OCTET_STRING },
  { &hf_credssp_cspData     , BER_CLASS_CON, 1, 0, dissect_credssp_TSCspDataDetail },
  { &hf_credssp_userHint    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_credssp_OCTET_STRING },
  { &hf_credssp_domainHint  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_credssp_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_credssp_TSSmartCardCreds(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TSSmartCardCreds_sequence, hf_index, ett_credssp_TSSmartCardCreds);

  return offset;
}



static int
dissect_credssp_T_packageName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 93 "./asn1/credssp/credssp.cnf"
	tvbuff_t *pname = NULL;

	offset = dissect_ber_octet_string(implicit_tag, actx, NULL, tvb, offset, hf_index, &pname);

	if(pname != NULL) {
		gint nlen = tvb_captured_length(pname);

		if (nlen == sizeof(kerberos_pname) && memcmp(tvb_get_ptr(pname, 0, nlen), kerberos_pname, nlen) == 0) {
			credssp_TS_RGC_package = TS_RGC_KERBEROS;
		} else if (nlen == sizeof(ntlm_pname) && memcmp(tvb_get_ptr(pname, 0, nlen), ntlm_pname, nlen) == 0) {
			credssp_TS_RGC_package = TS_RGC_NTLM;
		}
		proto_tree_add_item(tree, hf_index, pname, 0, -1, ENC_UTF_16|ENC_LITTLE_ENDIAN);
	}



  return offset;
}



static int
dissect_credssp_T_credBuffer(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 109 "./asn1/credssp/credssp.cnf"
	tvbuff_t *creds= NULL;
	proto_tree *subtree;

	  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &creds);


	if (!creds)
		return offset;

	switch(credssp_TS_RGC_package) {
	case TS_RGC_KERBEROS:
		subtree = proto_item_add_subtree(actx->created_item, ett_credssp_RGC_CredBuffer);
		dissect_kerberos_KERB_TICKET_LOGON(creds, 0, actx, subtree);
		break;
	case TS_RGC_NTLM:
		subtree = proto_item_add_subtree(actx->created_item, ett_credssp_RGC_CredBuffer);
		dissect_ntlmssp_NTLM_REMOTE_SUPPLEMENTAL_CREDENTIAL(creds, 0, subtree);
		break;
	}



  return offset;
}


static const ber_sequence_t TSRemoteGuardPackageCred_sequence[] = {
  { &hf_credssp_packageName , BER_CLASS_CON, 0, 0, dissect_credssp_T_packageName },
  { &hf_credssp_credBuffer  , BER_CLASS_CON, 1, 0, dissect_credssp_T_credBuffer },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_credssp_TSRemoteGuardPackageCred(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TSRemoteGuardPackageCred_sequence, hf_index, ett_credssp_TSRemoteGuardPackageCred);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_TSRemoteGuardPackageCred_sequence_of[1] = {
  { &hf_credssp_supplementalCreds_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_credssp_TSRemoteGuardPackageCred },
};

static int
dissect_credssp_SEQUENCE_OF_TSRemoteGuardPackageCred(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_TSRemoteGuardPackageCred_sequence_of, hf_index, ett_credssp_SEQUENCE_OF_TSRemoteGuardPackageCred);

  return offset;
}


static const ber_sequence_t TSRemoteGuardCreds_sequence[] = {
  { &hf_credssp_logonCred   , BER_CLASS_CON, 0, 0, dissect_credssp_TSRemoteGuardPackageCred },
  { &hf_credssp_supplementalCreds, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_credssp_SEQUENCE_OF_TSRemoteGuardPackageCred },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_credssp_TSRemoteGuardCreds(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TSRemoteGuardCreds_sequence, hf_index, ett_credssp_TSRemoteGuardCreds);

  return offset;
}



static int
dissect_credssp_T_credType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &creds_type);

  return offset;
}



static int
dissect_credssp_T_credentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 61 "./asn1/credssp/credssp.cnf"
	tvbuff_t *creds_tvb = NULL;

	  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &creds_tvb);


	switch(creds_type) {
	case TS_PASSWORD_CREDS:
		dissect_credssp_TSPasswordCreds(FALSE, creds_tvb, 0, actx, tree, hf_credssp_TSPasswordCreds);
		break;
	case TS_SMARTCARD_CREDS:
		dissect_credssp_TSSmartCardCreds(FALSE, creds_tvb, 0, actx, tree, hf_credssp_TSSmartCardCreds);
		break;
	case TS_REMOTEGUARD_CREDS:
		dissect_credssp_TSRemoteGuardCreds(FALSE, creds_tvb, 0, actx, tree, hf_credssp_TSRemoteGuardCreds);
		break;
	}




  return offset;
}


static const ber_sequence_t TSCredentials_sequence[] = {
  { &hf_credssp_credType    , BER_CLASS_CON, 0, 0, dissect_credssp_T_credType },
  { &hf_credssp_credentials , BER_CLASS_CON, 1, 0, dissect_credssp_T_credentials },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_credssp_TSCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TSCredentials_sequence, hf_index, ett_credssp_TSCredentials);

  return offset;
}



static int
dissect_credssp_T_version(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &credssp_ver);

  return offset;
}



static int
dissect_credssp_T_authInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 10 "./asn1/credssp/credssp.cnf"
	tvbuff_t *auth_tvb = NULL;
	tvbuff_t *decr_tvb = NULL;
	gssapi_encrypt_info_t gssapi_encrypt;

	  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &auth_tvb);


	memset(&gssapi_encrypt, 0, sizeof(gssapi_encrypt));
	gssapi_encrypt.decrypt_gssapi_tvb=DECRYPT_GSSAPI_NORMAL;
	call_dissector_with_data(gssapi_wrap_handle, auth_tvb, actx->pinfo, tree, &gssapi_encrypt);
	decr_tvb = gssapi_encrypt.gssapi_decrypted_tvb;

	if(decr_tvb != NULL)
		dissect_credssp_TSCredentials(FALSE, decr_tvb, 0, actx, tree, hf_credssp_TSCredentials);



  return offset;
}



static int
dissect_credssp_T_pubKeyAuth(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 25 "./asn1/credssp/credssp.cnf"
	tvbuff_t *auth_tvb = NULL;
	tvbuff_t *decr_tvb = NULL;
	gssapi_encrypt_info_t gssapi_encrypt;

	  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &auth_tvb);


	memset(&gssapi_encrypt, 0, sizeof(gssapi_encrypt));
	gssapi_encrypt.decrypt_gssapi_tvb=DECRYPT_GSSAPI_NORMAL;
	call_dissector_with_data(gssapi_wrap_handle, auth_tvb, actx->pinfo, tree, &gssapi_encrypt);
	decr_tvb = gssapi_encrypt.gssapi_decrypted_tvb;

	if(decr_tvb != NULL)
		proto_tree_add_item(tree, hf_credssp_decr_PublicKeyAuth, decr_tvb, 0, -1, ENC_NA);



  return offset;
}



static int
dissect_credssp_T_errorCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 40 "./asn1/credssp/credssp.cnf"

	if (credssp_ver < 3) {
		return 0;
	}

	  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);





  return offset;
}



static int
dissect_credssp_T_clientNonce(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 49 "./asn1/credssp/credssp.cnf"

	if (credssp_ver < 5) {
		return 0;
	}

	  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);





  return offset;
}


static const ber_sequence_t TSRequest_sequence[] = {
  { &hf_credssp_version     , BER_CLASS_CON, 0, 0, dissect_credssp_T_version },
  { &hf_credssp_negoTokens  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_credssp_NegoData },
  { &hf_credssp_authInfo    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_credssp_T_authInfo },
  { &hf_credssp_pubKeyAuth  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_credssp_T_pubKeyAuth },
  { &hf_credssp_errorCode   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_credssp_T_errorCode },
  { &hf_credssp_clientNonce , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_credssp_T_clientNonce },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_credssp_TSRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TSRequest_sequence, hf_index, ett_credssp_TSRequest);

  return offset;
}

/*--- PDUs ---*/

static int dissect_TSRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_credssp_TSRequest(FALSE, tvb, offset, &asn1_ctx, tree, hf_credssp_TSRequest_PDU);
  return offset;
}


/*--- End of included file: packet-credssp-fn.c ---*/
#line 71 "./asn1/credssp/packet-credssp-template.c"

/*
* Dissect CredSSP PDUs
*/
static int
dissect_credssp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_credssp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_credssp);
	}
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CredSSP");
  	col_clear(pinfo->cinfo, COL_INFO);

	creds_type = -1;
	credssp_ver = -1;

	return dissect_TSRequest_PDU(tvb, pinfo, tree, data);
}

static gboolean
dissect_credssp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
  asn1_ctx_t asn1_ctx;
  int offset = 0;
  gint8 ber_class;
  gboolean pc;
  gint32 tag;
  guint32 length;
  gint8 ver;

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  /* Look for SEQUENCE, CONTEXT 0, and INTEGER 2 */
  if(tvb_captured_length(tvb) > 7) {
    offset = get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
    if((ber_class == BER_CLASS_UNI) && (tag == BER_UNI_TAG_SEQUENCE) && (pc == TRUE)) {
      offset = get_ber_length(tvb, offset, NULL, NULL);
      offset = get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
      if((ber_class == BER_CLASS_CON) && (tag == 0)) {
        offset = get_ber_length(tvb, offset, NULL, NULL);
        offset = get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
        if((ber_class == BER_CLASS_UNI) && (tag == BER_UNI_TAG_INTEGER)) {
          offset = get_ber_length(tvb, offset, &length, NULL);
          ver = tvb_get_guint8(tvb, offset);
          if((length == 1) && (ver > 1) && (ver < 99)) {
            if (have_tap_listener(exported_pdu_tap)) {
              exp_pdu_data_t *exp_pdu_data = export_pdu_create_common_tags(pinfo, "credssp", EXP_PDU_TAG_PROTO_NAME);

              exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
              exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
              exp_pdu_data->pdu_tvb = tvb;

              tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
            }
            dissect_credssp(tvb, pinfo, parent_tree, NULL);
            return TRUE;
          }
        }
      }
    }
  }
  return FALSE;
}


/*--- proto_register_credssp -------------------------------------------*/
void proto_register_credssp(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
    { &hf_credssp_TSPasswordCreds,
      { "TSPasswordCreds", "credssp.TSPasswordCreds",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_TSSmartCardCreds,
      { "TSSmartCardCreds", "credssp.TSSmartCardCreds",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_TSRemoteGuardCreds,
      { "TSRemoteGuardCreds", "credssp.TSRemoteGuardCreds",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_TSCredentials,
      { "TSCredentials", "credssp.TSCredentials",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_decr_PublicKeyAuth,
      { "Decrypted PublicKeyAuth (sha256)", "credssp.decr_PublicKeyAuth",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- Included file: packet-credssp-hfarr.c ---*/
#line 1 "./asn1/credssp/packet-credssp-hfarr.c"
    { &hf_credssp_TSRequest_PDU,
      { "TSRequest", "credssp.TSRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_NegoData_item,
      { "NegoData item", "credssp.NegoData_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_negoToken,
      { "negoToken", "credssp.negoToken",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_domainName,
      { "domainName", "credssp.domainName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_credssp_userName,
      { "userName", "credssp.userName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_credssp_password,
      { "password", "credssp.password",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_credssp_keySpec,
      { "keySpec", "credssp.keySpec",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_credssp_cardName,
      { "cardName", "credssp.cardName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_credssp_readerName,
      { "readerName", "credssp.readerName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_credssp_containerName,
      { "containerName", "credssp.containerName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_credssp_cspName,
      { "cspName", "credssp.cspName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_credssp_pin,
      { "pin", "credssp.pin",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_credssp_cspData,
      { "cspData", "credssp.cspData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TSCspDataDetail", HFILL }},
    { &hf_credssp_userHint,
      { "userHint", "credssp.userHint",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_credssp_domainHint,
      { "domainHint", "credssp.domainHint",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_credssp_packageName,
      { "packageName", "credssp.packageName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_credBuffer,
      { "credBuffer", "credssp.credBuffer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_logonCred,
      { "logonCred", "credssp.logonCred_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TSRemoteGuardPackageCred", HFILL }},
    { &hf_credssp_supplementalCreds,
      { "supplementalCreds", "credssp.supplementalCreds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_TSRemoteGuardPackageCred", HFILL }},
    { &hf_credssp_supplementalCreds_item,
      { "TSRemoteGuardPackageCred", "credssp.TSRemoteGuardPackageCred_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_credType,
      { "credType", "credssp.credType",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_credentials,
      { "credentials", "credssp.credentials",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_version,
      { "version", "credssp.version",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_negoTokens,
      { "negoTokens", "credssp.negoTokens",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NegoData", HFILL }},
    { &hf_credssp_authInfo,
      { "authInfo", "credssp.authInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_pubKeyAuth,
      { "pubKeyAuth", "credssp.pubKeyAuth",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_errorCode,
      { "errorCode", "credssp.errorCode",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_clientNonce,
      { "clientNonce", "credssp.clientNonce",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- End of included file: packet-credssp-hfarr.c ---*/
#line 167 "./asn1/credssp/packet-credssp-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_credssp,
    &ett_credssp_RGC_CredBuffer,

/*--- Included file: packet-credssp-ettarr.c ---*/
#line 1 "./asn1/credssp/packet-credssp-ettarr.c"
    &ett_credssp_NegoData,
    &ett_credssp_NegoData_item,
    &ett_credssp_TSPasswordCreds,
    &ett_credssp_TSCspDataDetail,
    &ett_credssp_TSSmartCardCreds,
    &ett_credssp_TSRemoteGuardPackageCred,
    &ett_credssp_TSRemoteGuardCreds,
    &ett_credssp_SEQUENCE_OF_TSRemoteGuardPackageCred,
    &ett_credssp_TSCredentials,
    &ett_credssp_TSRequest,

/*--- End of included file: packet-credssp-ettarr.c ---*/
#line 174 "./asn1/credssp/packet-credssp-template.c"
  };


  /* Register protocol */
  proto_credssp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("credssp", dissect_credssp, proto_credssp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_credssp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* heuristic dissectors for any premable e.g. CredSSP before RDP */
  credssp_heur_subdissector_list = register_heur_dissector_list("credssp", proto_credssp);

}


/*--- proto_reg_handoff_credssp --- */
void proto_reg_handoff_credssp(void) {

  gssapi_handle = find_dissector_add_dependency("gssapi", proto_credssp);
  gssapi_wrap_handle = find_dissector_add_dependency("gssapi_verf", proto_credssp);

  heur_dissector_add("tls", dissect_credssp_heur, "CredSSP over TLS", "credssp_tls", proto_credssp, HEURISTIC_ENABLE);
  heur_dissector_add("rdp", dissect_credssp_heur, "CredSSP in TPKT", "credssp_tpkt", proto_credssp, HEURISTIC_ENABLE);
  exported_pdu_tap = find_tap_id(EXPORT_PDU_TAP_NAME_LAYER_7);
}

