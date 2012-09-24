/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-credssp.c                                                           */
/* ../../tools/asn2wrs.py -b -C -p credssp -c ./credssp.cnf -s ./packet-credssp-template -D . -O ../../epan/dissectors CredSSP.asn */

/* Input file: packet-credssp-template.c */

#line 1 "../../asn1/credssp/packet-credssp-template.c"
/* packet-credssp.c
 * Routines for CredSSP (Credential Security Support Provider) packet dissection
 * Graeme Lunt 2011
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-credssp.h"


#define PNAME  "Credential Security Support Provider"
#define PSNAME "CredSSP"
#define PFNAME "credssp"

#define TS_PASSWORD_CREDS   1
#define TS_SMARTCARD_CREDS  2
static gint creds_type;

/* Initialize the protocol and registered fields */
static int proto_credssp = -1;

/* List of dissectors to call for negoToken data */
static heur_dissector_list_t credssp_heur_subdissector_list;

static int hf_credssp_TSPasswordCreds = -1;   /* TSPasswordCreds */
static int hf_credssp_TSSmartCardCreds = -1;  /* TSSmartCardCreds */
static int hf_credssp_TSCredentials = -1;     /* TSCredentials */

/*--- Included file: packet-credssp-hf.c ---*/
#line 1 "../../asn1/credssp/packet-credssp-hf.c"
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
static int hf_credssp_credType = -1;              /* T_credType */
static int hf_credssp_credentials = -1;           /* T_credentials */
static int hf_credssp_version = -1;               /* INTEGER */
static int hf_credssp_negoTokens = -1;            /* NegoData */
static int hf_credssp_authInfo = -1;              /* T_authInfo */
static int hf_credssp_pubKeyAuth = -1;            /* OCTET_STRING */

/*--- End of included file: packet-credssp-hf.c ---*/
#line 54 "../../asn1/credssp/packet-credssp-template.c"

/* Initialize the subtree pointers */
static gint ett_credssp = -1;

/*--- Included file: packet-credssp-ett.c ---*/
#line 1 "../../asn1/credssp/packet-credssp-ett.c"
static gint ett_credssp_NegoData = -1;
static gint ett_credssp_NegoData_item = -1;
static gint ett_credssp_TSPasswordCreds = -1;
static gint ett_credssp_TSCspDataDetail = -1;
static gint ett_credssp_TSSmartCardCreds = -1;
static gint ett_credssp_TSCredentials = -1;
static gint ett_credssp_TSRequest = -1;

/*--- End of included file: packet-credssp-ett.c ---*/
#line 58 "../../asn1/credssp/packet-credssp-template.c"


/*--- Included file: packet-credssp-fn.c ---*/
#line 1 "../../asn1/credssp/packet-credssp-fn.c"


static int
dissect_credssp_T_negoToken(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 46 "../../asn1/credssp/credssp.cnf"
	tvbuff_t *token_tvb = NULL;

	  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &token_tvb);


	if(token_tvb != NULL)
		      dissector_try_heuristic(credssp_heur_subdissector_list, 
		      token_tvb, actx->pinfo, proto_tree_get_root(tree), NULL);




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
dissect_credssp_T_credType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &creds_type);

  return offset;
}



static int
dissect_credssp_T_credentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 24 "../../asn1/credssp/credssp.cnf"
	tvbuff_t *creds_tvb = NULL;
	tvbuff_t *decr_tvb = NULL;

	  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &creds_tvb);


	if((decr_tvb != NULL) && 
	((creds_type == TS_PASSWORD_CREDS) || (creds_type == TS_SMARTCARD_CREDS))) {

		      switch(creds_type) {
		      case TS_PASSWORD_CREDS:
		    offset = dissect_credssp_TSPasswordCreds(FALSE, decr_tvb, 0, actx, tree, hf_credssp_TSPasswordCreds);
		    	   break;
			   case TS_SMARTCARD_CREDS:
		    offset = dissect_credssp_TSSmartCardCreds(FALSE, decr_tvb, 0, actx, tree, hf_credssp_TSSmartCardCreds);
		    	   break;
		   }
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
dissect_credssp_T_authInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 11 "../../asn1/credssp/credssp.cnf"
	tvbuff_t *auth_tvb = NULL;
	tvbuff_t *decr_tvb = NULL;

	  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &auth_tvb);


	if(decr_tvb != NULL)
		    offset = dissect_credssp_TSCredentials(FALSE, decr_tvb, 0, actx, tree, hf_credssp_TSCredentials);




  return offset;
}


static const ber_sequence_t TSRequest_sequence[] = {
  { &hf_credssp_version     , BER_CLASS_CON, 0, 0, dissect_credssp_INTEGER },
  { &hf_credssp_negoTokens  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_credssp_NegoData },
  { &hf_credssp_authInfo    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_credssp_T_authInfo },
  { &hf_credssp_pubKeyAuth  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_credssp_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_credssp_TSRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TSRequest_sequence, hf_index, ett_credssp_TSRequest);

  return offset;
}

/*--- PDUs ---*/

static void dissect_TSRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_credssp_TSRequest(FALSE, tvb, 0, &asn1_ctx, tree, hf_credssp_TSRequest_PDU);
}


/*--- End of included file: packet-credssp-fn.c ---*/
#line 60 "../../asn1/credssp/packet-credssp-template.c"

/*
* Dissect CredSSP PDUs
*/
static void
dissect_credssp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
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
	dissect_TSRequest_PDU(tvb, pinfo, tree);
}

static gboolean
dissect_credssp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
  asn1_ctx_t asn1_ctx;
  int offset = 0;
  gint8 class;
  gboolean pc;
  gint32 tag;
  guint32 length;

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  /* Look for SEQUENCE, CONTEXT 0, and INTEGER 2 */  
  if(tvb_length(tvb) > 7) {
    offset = get_ber_identifier(tvb, offset, &class, &pc, &tag); 
    if((class == BER_CLASS_UNI) && (tag == BER_UNI_TAG_SEQUENCE) && (pc == TRUE)) {
      offset = get_ber_length(tvb, offset, NULL, NULL);
      offset = get_ber_identifier(tvb, offset, &class, &pc, &tag); 
      if((class == BER_CLASS_CON) && (tag == 0)) {
	offset = get_ber_length(tvb, offset, NULL, NULL);
	offset = get_ber_identifier(tvb, offset, &class, &pc, &tag); 
	if((class == BER_CLASS_UNI) && (tag == BER_UNI_TAG_INTEGER)) {
	  offset = get_ber_length(tvb, offset, &length, NULL);
	  if((length == 1) && (tvb_get_guint8(tvb, offset) == 2)) {
	    dissect_credssp(tvb, pinfo, parent_tree);
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
    { &hf_credssp_TSCredentials,
      { "TSCredentials", "credssp.TSCredentials",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- Included file: packet-credssp-hfarr.c ---*/
#line 1 "../../asn1/credssp/packet-credssp-hfarr.c"
    { &hf_credssp_TSRequest_PDU,
      { "TSRequest", "credssp.TSRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_credssp_NegoData_item,
      { "NegoData item", "credssp.NegoData_item",
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
      { "cspData", "credssp.cspData",
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
        "INTEGER", HFILL }},
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
        "OCTET_STRING", HFILL }},

/*--- End of included file: packet-credssp-hfarr.c ---*/
#line 135 "../../asn1/credssp/packet-credssp-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_credssp,

/*--- Included file: packet-credssp-ettarr.c ---*/
#line 1 "../../asn1/credssp/packet-credssp-ettarr.c"
    &ett_credssp_NegoData,
    &ett_credssp_NegoData_item,
    &ett_credssp_TSPasswordCreds,
    &ett_credssp_TSCspDataDetail,
    &ett_credssp_TSSmartCardCreds,
    &ett_credssp_TSCredentials,
    &ett_credssp_TSRequest,

/*--- End of included file: packet-credssp-ettarr.c ---*/
#line 141 "../../asn1/credssp/packet-credssp-template.c"
  };


  /* Register protocol */
  proto_credssp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("credssp", dissect_credssp, proto_credssp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_credssp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* heuristic dissectors for any premable e.g. CredSSP before RDP */
  register_heur_dissector_list("credssp", &credssp_heur_subdissector_list);

}


/*--- proto_reg_handoff_credssp --- */
void proto_reg_handoff_credssp(void) {

  heur_dissector_add("ssl", dissect_credssp_heur, proto_credssp);

}

