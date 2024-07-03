/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-acse.c                                                              */
/* asn2wrs.py -b -C -q -L -p acse -c ./acse.cnf -s ./packet-acse-template -D . -O ../.. acse.asn */

/*XXX
  There is a bug in asn2wrs that it can not yet handle tagged assignments such
  as EXTERNAL  ::=  [UNIVERSAL 8] IMPLICIT SEQUENCE {

  This bug is workedaround by some .cnf magic but this should be cleaned up
  once asn2wrs learns how to deal with tagged assignments
*/

/* packet-acse.c
 * Routines for ACSE packet dissection
 *   Ronnie Sahlberg 2005
 * dissect_acse() based original handwritten dissector by Sid
 *   Yuriy Sidelnikov <YSidelnikov@hotmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ses.h"
#include "packet-pres.h"
#include "packet-x509if.h"

#define PNAME  "ISO 8650-1 OSI Association Control Service"
#define PSNAME "ACSE"
#define PFNAME "acse"

#define CLPNAME  "ISO 10035-1 OSI Connectionless Association Control Service"
#define CLPSNAME "CLACSE"
#define CLPFNAME "clacse"

#define ACSE_APDU_OID "2.2.1.0.1"

void proto_register_acse(void);
void proto_reg_handoff_acse(void);

/* Initialize the protocol and registered fields */
int proto_acse;
int proto_clacse;



static int hf_acse_direct_reference;              /* T_direct_reference */
static int hf_acse_indirect_reference;            /* T_indirect_reference */
static int hf_acse_data_value_descriptor;         /* ObjectDescriptor */
static int hf_acse_encoding;                      /* T_encoding */
static int hf_acse_single_ASN1_type;              /* T_single_ASN1_type */
static int hf_acse_octet_aligned;                 /* T_octet_aligned */
static int hf_acse_arbitrary;                     /* BIT_STRING */
static int hf_acse_aarq;                          /* AARQ_apdu */
static int hf_acse_aare;                          /* AARE_apdu */
static int hf_acse_rlrq;                          /* RLRQ_apdu */
static int hf_acse_rlre;                          /* RLRE_apdu */
static int hf_acse_abrt;                          /* ABRT_apdu */
static int hf_acse_adt;                           /* A_DT_apdu */
static int hf_acse_acrq;                          /* ACRQ_apdu */
static int hf_acse_acrp;                          /* ACRP_apdu */
static int hf_acse_aARQ_protocol_version;         /* T_AARQ_protocol_version */
static int hf_acse_aARQ_aSO_context_name;         /* T_AARQ_aSO_context_name */
static int hf_acse_called_AP_title;               /* AP_title */
static int hf_acse_called_AE_qualifier;           /* AE_qualifier */
static int hf_acse_called_AP_invocation_identifier;  /* AP_invocation_identifier */
static int hf_acse_called_AE_invocation_identifier;  /* AE_invocation_identifier */
static int hf_acse_calling_AP_title;              /* AP_title */
static int hf_acse_calling_AE_qualifier;          /* AE_qualifier */
static int hf_acse_calling_AP_invocation_identifier;  /* AP_invocation_identifier */
static int hf_acse_calling_AE_invocation_identifier;  /* AE_invocation_identifier */
static int hf_acse_sender_acse_requirements;      /* ACSE_requirements */
static int hf_acse_mechanism_name;                /* Mechanism_name */
static int hf_acse_calling_authentication_value;  /* Authentication_value */
static int hf_acse_aSO_context_name_list;         /* ASO_context_name_list */
static int hf_acse_implementation_information;    /* Implementation_data */
static int hf_acse_p_context_definition_list;     /* Syntactic_context_list */
static int hf_acse_called_asoi_tag;               /* ASOI_tag */
static int hf_acse_calling_asoi_tag;              /* ASOI_tag */
static int hf_acse_aARQ_user_information;         /* Association_data */
static int hf_acse_aARE_protocol_version;         /* T_AARE_protocol_version */
static int hf_acse_aARE_aSO_context_name;         /* T_AARE_aSO_context_name */
static int hf_acse_result;                        /* Associate_result */
static int hf_acse_result_source_diagnostic;      /* Associate_source_diagnostic */
static int hf_acse_responding_AP_title;           /* AP_title */
static int hf_acse_responding_AE_qualifier;       /* AE_qualifier */
static int hf_acse_responding_AP_invocation_identifier;  /* AP_invocation_identifier */
static int hf_acse_responding_AE_invocation_identifier;  /* AE_invocation_identifier */
static int hf_acse_responder_acse_requirements;   /* ACSE_requirements */
static int hf_acse_responding_authentication_value;  /* Authentication_value */
static int hf_acse_p_context_result_list;         /* P_context_result_list */
static int hf_acse_aARE_user_information;         /* Association_data */
static int hf_acse_rLRQ_reason;                   /* Release_request_reason */
static int hf_acse_aso_qualifier;                 /* ASO_qualifier */
static int hf_acse_asoi_identifier;               /* ASOI_identifier */
static int hf_acse_rLRQ_user_information;         /* Association_data */
static int hf_acse_rLRE_reason;                   /* Release_response_reason */
static int hf_acse_rLRE_user_information;         /* Association_data */
static int hf_acse_abort_source;                  /* ABRT_source */
static int hf_acse_abort_diagnostic;              /* ABRT_diagnostic */
static int hf_acse_aBRT_user_information;         /* Association_data */
static int hf_acse_a_user_data;                   /* User_Data */
static int hf_acse_aCRQ_aSO_context_name;         /* T_ACRQ_aSO_context_name */
static int hf_acse_user_information;              /* User_information */
static int hf_acse_aSO_context_name;              /* T_ACRP_aSO_context_name */
static int hf_acse_ap_title_form1;                /* AP_title_form1 */
static int hf_acse_ap_title_form2;                /* AP_title_form2 */
static int hf_acse_ap_title_form3;                /* AP_title_form3 */
static int hf_acse_aso_qualifier_form1;           /* ASO_qualifier_form1 */
static int hf_acse_aso_qualifier_form2;           /* ASO_qualifier_form2 */
static int hf_acse_aso_qualifier_form3;           /* ASO_qualifier_form3 */
static int hf_acse_aso_qualifier_form_any_octets;  /* ASO_qualifier_form_octets */
static int hf_acse_ae_title_form1;                /* AE_title_form1 */
static int hf_acse_ae_title_form2;                /* AE_title_form2 */
static int hf_acse_ASOI_tag_item;                 /* ASOI_tag_item */
static int hf_acse_qualifier;                     /* ASO_qualifier */
static int hf_acse_identifier;                    /* ASOI_identifier */
static int hf_acse_ASO_context_name_list_item;    /* ASO_context_name */
static int hf_acse_context_list;                  /* Context_list */
static int hf_acse_default_contact_list;          /* Default_Context_List */
static int hf_acse_Context_list_item;             /* Context_list_item */
static int hf_acse_pci;                           /* Presentation_context_identifier */
static int hf_acse_abstract_syntax;               /* Abstract_syntax_name */
static int hf_acse_transfer_syntaxes;             /* SEQUENCE_OF_TransferSyntaxName */
static int hf_acse_transfer_syntaxes_item;        /* TransferSyntaxName */
static int hf_acse_Default_Context_List_item;     /* Default_Context_List_item */
static int hf_acse_abstract_syntax_name;          /* Abstract_syntax_name */
static int hf_acse_transfer_syntax_name;          /* TransferSyntaxName */
static int hf_acse_P_context_result_list_item;    /* P_context_result_list_item */
static int hf_acse_pcontext_result;               /* Result */
static int hf_acse_concrete_syntax_name;          /* Concrete_syntax_name */
static int hf_acse_provider_reason;               /* T_provider_reason */
static int hf_acse_service_user;                  /* T_service_user */
static int hf_acse_service_provider;              /* T_service_provider */
static int hf_acse_Association_data_item;         /* EXTERNALt */
static int hf_acse_simply_encoded_data;           /* Simply_encoded_data */
static int hf_acse_fully_encoded_data;            /* PDV_list */
static int hf_acse_presentation_context_identifier;  /* Presentation_context_identifier */
static int hf_acse_presentation_data_values;      /* T_presentation_data_values */
static int hf_acse_simple_ASN1_type;              /* T_simple_ASN1_type */
static int hf_acse_pDVList_octet_aligned;         /* OCTET_STRING */
static int hf_acse_other_mechanism_name;          /* T_other_mechanism_name */
static int hf_acse_other_mechanism_value;         /* T_other_mechanism_value */
static int hf_acse_charstring;                    /* GraphicString */
static int hf_acse_bitstring;                     /* BIT_STRING */
static int hf_acse_external;                      /* EXTERNALt */
static int hf_acse_other;                         /* Authentication_value_other */
/* named bits */
static int hf_acse_T_AARQ_protocol_version_version1;
static int hf_acse_T_AARE_protocol_version_version1;
static int hf_acse_ACSE_requirements_authentication;
static int hf_acse_ACSE_requirements_aSO_context_negotiation;
static int hf_acse_ACSE_requirements_higher_level_association;
static int hf_acse_ACSE_requirements_nested_association;
static int hf_acse_user_data;

/* Initialize the subtree pointers */
static int ett_acse;
static int ett_acse_EXTERNALt_U;
static int ett_acse_T_encoding;
static int ett_acse_ACSE_apdu;
static int ett_acse_AARQ_apdu_U;
static int ett_acse_T_AARQ_protocol_version;
static int ett_acse_AARE_apdu_U;
static int ett_acse_T_AARE_protocol_version;
static int ett_acse_RLRQ_apdu_U;
static int ett_acse_RLRE_apdu_U;
static int ett_acse_ABRT_apdu_U;
static int ett_acse_A_DT_apdu_U;
static int ett_acse_ACRQ_apdu_U;
static int ett_acse_ACRP_apdu_U;
static int ett_acse_ACSE_requirements;
static int ett_acse_AP_title;
static int ett_acse_ASO_qualifier;
static int ett_acse_AE_title;
static int ett_acse_ASOI_tag;
static int ett_acse_ASOI_tag_item;
static int ett_acse_ASO_context_name_list;
static int ett_acse_Syntactic_context_list;
static int ett_acse_Context_list;
static int ett_acse_Context_list_item;
static int ett_acse_SEQUENCE_OF_TransferSyntaxName;
static int ett_acse_Default_Context_List;
static int ett_acse_Default_Context_List_item;
static int ett_acse_P_context_result_list;
static int ett_acse_P_context_result_list_item;
static int ett_acse_Associate_source_diagnostic;
static int ett_acse_Association_data;
static int ett_acse_User_Data;
static int ett_acse_PDV_list;
static int ett_acse_T_presentation_data_values;
static int ett_acse_Authentication_value_other;
static int ett_acse_Authentication_value;

static expert_field ei_acse_dissector_not_available;
static expert_field ei_acse_malformed;
static expert_field ei_acse_invalid_oid;

static dissector_handle_t acse_handle;

/* indirect_reference, used to pick up the signalling so we know what
   kind of data is transferred in SES_DATA_TRANSFER_PDUs */
static uint32_t indir_ref=0;

#if NOT_NEEDED
/* to keep track of presentation context identifiers and protocol-oids */
typedef struct _acse_ctx_oid_t {
	/* XXX here we should keep track of ADDRESS/PORT as well */
	uint32_t ctx_id;
	char *oid;
} acse_ctx_oid_t;
static wmem_map_t *acse_ctx_oid_table;

static unsigned
acse_ctx_oid_hash(const void *k)
{
	acse_ctx_oid_t *aco=(acse_ctx_oid_t *)k;
	return aco->ctx_id;
}
/* XXX this one should be made ADDRESS/PORT aware */
static int
acse_ctx_oid_equal(const void *k1, const void *k2)
{
	acse_ctx_oid_t *aco1=(acse_ctx_oid_t *)k1;
	acse_ctx_oid_t *aco2=(acse_ctx_oid_t *)k2;
	return aco1->ctx_id==aco2->ctx_id;
}

static void
register_ctx_id_and_oid(packet_info *pinfo _U_, uint32_t idx, char *oid)
{
	acse_ctx_oid_t *aco, *tmpaco;
	aco=wmem_new(wmem_file_scope(), acse_ctx_oid_t);
	aco->ctx_id=idx;
	aco->oid=wmem_strdup(wmem_file_scope(), oid);

	/* if this ctx already exists, remove the old one first */
	tmpaco=(acse_ctx_oid_t *)wmem_map_lookup(acse_ctx_oid_table, aco);
	if (tmpaco) {
		wmem_map_remove(acse_ctx_oid_table, tmpaco);
	}
	wmem_map_insert(acse_ctx_oid_table, aco, aco);
}
static char *
find_oid_by_ctx_id(packet_info *pinfo _U_, uint32_t idx)
{
	acse_ctx_oid_t aco, *tmpaco;
	aco.ctx_id=idx;
	tmpaco=(acse_ctx_oid_t *)wmem_map_lookup(acse_ctx_oid_table, &aco);
	if (tmpaco) {
		return tmpaco->oid;
	}
	return NULL;
}

# endif /* NOT_NEEDED */



static int
dissect_acse_T_direct_reference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &actx->external.direct_reference);

  actx->external.direct_ref_present = (actx->external.direct_reference != NULL) ? true : false;


  return offset;
}



static int
dissect_acse_T_indirect_reference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  char *oid;
  struct SESSION_DATA_STRUCTURE* session = (struct SESSION_DATA_STRUCTURE*) actx->private_data;

  offset = dissect_ber_integer(false, actx, tree, tvb, offset,
                hf_acse_indirect_reference,
                &indir_ref);

  /* look up the indirect reference */
  if((oid = find_oid_by_pres_ctx_id(actx->pinfo, indir_ref)) != NULL) {
    actx->external.direct_reference = wmem_strdup(actx->pinfo->pool, oid);
    actx->external.direct_ref_present = true;
  }

  if(session)
	session->pres_ctx_id = indir_ref;


  return offset;
}



static int
dissect_acse_ObjectDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_ObjectDescriptor,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_acse_T_single_ASN1_type(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  if (actx->external.direct_ref_present) {
    offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, actx->subtree.top_tree ? actx->subtree.top_tree : tree, actx->private_data);
  }


  return offset;
}



static int
dissect_acse_T_octet_aligned(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  if (actx->external.direct_ref_present) {
    offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, actx->subtree.top_tree ? actx->subtree.top_tree : tree, actx->private_data);
  }


  return offset;
}



static int
dissect_acse_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const value_string acse_T_encoding_vals[] = {
  {   0, "single-ASN1-type" },
  {   1, "octet-aligned" },
  {   2, "arbitrary" },
  { 0, NULL }
};

static const ber_choice_t T_encoding_choice[] = {
  {   0, &hf_acse_single_ASN1_type, BER_CLASS_CON, 0, 0, dissect_acse_T_single_ASN1_type },
  {   1, &hf_acse_octet_aligned  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_acse_T_octet_aligned },
  {   2, &hf_acse_arbitrary      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_acse_BIT_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_T_encoding(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_encoding_choice, hf_index, ett_acse_T_encoding,
                                 NULL);

  return offset;
}


static const ber_sequence_t EXTERNALt_U_sequence[] = {
  { &hf_acse_direct_reference, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_acse_T_direct_reference },
  { &hf_acse_indirect_reference, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_acse_T_indirect_reference },
  { &hf_acse_data_value_descriptor, BER_CLASS_UNI, BER_UNI_TAG_ObjectDescriptor, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_acse_ObjectDescriptor },
  { &hf_acse_encoding       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_acse_T_encoding },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_EXTERNALt_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EXTERNALt_U_sequence, hf_index, ett_acse_EXTERNALt_U);

  return offset;
}



int
dissect_acse_EXTERNALt(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_UNI, 8, true, dissect_acse_EXTERNALt_U);

  return offset;
}


static int * const T_AARQ_protocol_version_bits[] = {
  &hf_acse_T_AARQ_protocol_version_version1,
  NULL
};

static int
dissect_acse_T_AARQ_protocol_version(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_AARQ_protocol_version_bits, 1, hf_index, ett_acse_T_AARQ_protocol_version,
                                    NULL);

  return offset;
}



static int
dissect_acse_ASO_context_name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_acse_T_AARQ_aSO_context_name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(false, actx, tree, tvb, offset,
                                         hf_index, &actx->external.direct_reference);
  actx->external.direct_ref_present = (actx->external.direct_reference != NULL) ? true : false;


  return offset;
}



static int
dissect_acse_AP_title_form1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509if_Name(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_acse_AP_title_form2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_acse_AP_title_form3(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


const value_string acse_AP_title_vals[] = {
  {   0, "ap-title-form1" },
  {   1, "ap-title-form2" },
  {   2, "ap-title-form3" },
  { 0, NULL }
};

static const ber_choice_t AP_title_choice[] = {
  {   0, &hf_acse_ap_title_form1 , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_acse_AP_title_form1 },
  {   1, &hf_acse_ap_title_form2 , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_acse_AP_title_form2 },
  {   2, &hf_acse_ap_title_form3 , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_acse_AP_title_form3 },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_acse_AP_title(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AP_title_choice, hf_index, ett_acse_AP_title,
                                 NULL);

  return offset;
}



static int
dissect_acse_ASO_qualifier_form1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509if_RelativeDistinguishedName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_acse_ASO_qualifier_form2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_acse_ASO_qualifier_form3(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_acse_ASO_qualifier_form_octets(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


const value_string acse_ASO_qualifier_vals[] = {
  {   0, "aso-qualifier-form1" },
  {   1, "aso-qualifier-form2" },
  {   2, "aso-qualifier-form3" },
  {   3, "aso-qualifier-form-any-octets" },
  { 0, NULL }
};

static const ber_choice_t ASO_qualifier_choice[] = {
  {   0, &hf_acse_aso_qualifier_form1, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_acse_ASO_qualifier_form1 },
  {   1, &hf_acse_aso_qualifier_form2, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_acse_ASO_qualifier_form2 },
  {   2, &hf_acse_aso_qualifier_form3, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_acse_ASO_qualifier_form3 },
  {   3, &hf_acse_aso_qualifier_form_any_octets, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_acse_ASO_qualifier_form_octets },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_acse_ASO_qualifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ASO_qualifier_choice, hf_index, ett_acse_ASO_qualifier,
                                 NULL);

  return offset;
}



int
dissect_acse_AE_qualifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_acse_ASO_qualifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_acse_AP_invocation_identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



int
dissect_acse_AE_invocation_identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static int * const ACSE_requirements_bits[] = {
  &hf_acse_ACSE_requirements_authentication,
  &hf_acse_ACSE_requirements_aSO_context_negotiation,
  &hf_acse_ACSE_requirements_higher_level_association,
  &hf_acse_ACSE_requirements_nested_association,
  NULL
};

static int
dissect_acse_ACSE_requirements(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ACSE_requirements_bits, 4, hf_index, ett_acse_ACSE_requirements,
                                    NULL);

  return offset;
}



static int
dissect_acse_Mechanism_name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_acse_GraphicString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_acse_T_other_mechanism_name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &actx->external.direct_reference);

  actx->external.direct_ref_present = (actx->external.direct_reference != NULL) ? true : false;


  return offset;
}



static int
dissect_acse_T_other_mechanism_value(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  if (actx->external.direct_ref_present) {
    offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, actx->subtree.top_tree, actx->private_data);
  }


  return offset;
}


static const ber_sequence_t Authentication_value_other_sequence[] = {
  { &hf_acse_other_mechanism_name, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_acse_T_other_mechanism_name },
  { &hf_acse_other_mechanism_value, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_acse_T_other_mechanism_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_Authentication_value_other(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Authentication_value_other_sequence, hf_index, ett_acse_Authentication_value_other);

  return offset;
}


static const value_string acse_Authentication_value_vals[] = {
  {   0, "charstring" },
  {   1, "bitstring" },
  {   2, "external" },
  {   3, "other" },
  { 0, NULL }
};

static const ber_choice_t Authentication_value_choice[] = {
  {   0, &hf_acse_charstring     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_acse_GraphicString },
  {   1, &hf_acse_bitstring      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_acse_BIT_STRING },
  {   2, &hf_acse_external       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_acse_EXTERNALt },
  {   3, &hf_acse_other          , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_acse_Authentication_value_other },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_Authentication_value(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Authentication_value_choice, hf_index, ett_acse_Authentication_value,
                                 NULL);

  return offset;
}


static const ber_sequence_t ASO_context_name_list_sequence_of[1] = {
  { &hf_acse_ASO_context_name_list_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_acse_ASO_context_name },
};

static int
dissect_acse_ASO_context_name_list(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ASO_context_name_list_sequence_of, hf_index, ett_acse_ASO_context_name_list);

  return offset;
}



static int
dissect_acse_Implementation_data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_acse_Presentation_context_identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_acse_Abstract_syntax_name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_acse_TransferSyntaxName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_TransferSyntaxName_sequence_of[1] = {
  { &hf_acse_transfer_syntaxes_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_acse_TransferSyntaxName },
};

static int
dissect_acse_SEQUENCE_OF_TransferSyntaxName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_TransferSyntaxName_sequence_of, hf_index, ett_acse_SEQUENCE_OF_TransferSyntaxName);

  return offset;
}


static const ber_sequence_t Context_list_item_sequence[] = {
  { &hf_acse_pci            , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_acse_Presentation_context_identifier },
  { &hf_acse_abstract_syntax, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_acse_Abstract_syntax_name },
  { &hf_acse_transfer_syntaxes, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_acse_SEQUENCE_OF_TransferSyntaxName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_Context_list_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Context_list_item_sequence, hf_index, ett_acse_Context_list_item);

  return offset;
}


static const ber_sequence_t Context_list_sequence_of[1] = {
  { &hf_acse_Context_list_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_acse_Context_list_item },
};

static int
dissect_acse_Context_list(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Context_list_sequence_of, hf_index, ett_acse_Context_list);

  return offset;
}


static const ber_sequence_t Default_Context_List_item_sequence[] = {
  { &hf_acse_abstract_syntax_name, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_Abstract_syntax_name },
  { &hf_acse_transfer_syntax_name, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_acse_TransferSyntaxName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_Default_Context_List_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Default_Context_List_item_sequence, hf_index, ett_acse_Default_Context_List_item);

  return offset;
}


static const ber_sequence_t Default_Context_List_sequence_of[1] = {
  { &hf_acse_Default_Context_List_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_acse_Default_Context_List_item },
};

static int
dissect_acse_Default_Context_List(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Default_Context_List_sequence_of, hf_index, ett_acse_Default_Context_List);

  return offset;
}


static const value_string acse_Syntactic_context_list_vals[] = {
  {   0, "context-list" },
  {   1, "default-contact-list" },
  { 0, NULL }
};

static const ber_choice_t Syntactic_context_list_choice[] = {
  {   0, &hf_acse_context_list   , BER_CLASS_CON, 0, 0, dissect_acse_Context_list },
  {   1, &hf_acse_default_contact_list, BER_CLASS_CON, 1, 0, dissect_acse_Default_Context_List },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_Syntactic_context_list(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Syntactic_context_list_choice, hf_index, ett_acse_Syntactic_context_list,
                                 NULL);

  return offset;
}



static int
dissect_acse_ASOI_identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            1U, 128U, hf_index, NULL);

  return offset;
}


static const ber_sequence_t ASOI_tag_item_sequence[] = {
  { &hf_acse_qualifier      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_acse_ASO_qualifier },
  { &hf_acse_identifier     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_acse_ASOI_identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_ASOI_tag_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ASOI_tag_item_sequence, hf_index, ett_acse_ASOI_tag_item);

  return offset;
}


static const ber_sequence_t ASOI_tag_sequence_of[1] = {
  { &hf_acse_ASOI_tag_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_acse_ASOI_tag_item },
};

static int
dissect_acse_ASOI_tag(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  0, 7, ASOI_tag_sequence_of, hf_index, ett_acse_ASOI_tag);

  return offset;
}


static const ber_sequence_t Association_data_sequence_of[1] = {
  { &hf_acse_Association_data_item, BER_CLASS_UNI, 8, BER_FLAGS_NOOWNTAG, dissect_acse_EXTERNALt },
};

static int
dissect_acse_Association_data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Association_data_sequence_of, hf_index, ett_acse_Association_data);

  return offset;
}


static const ber_sequence_t AARQ_apdu_U_sequence[] = {
  { &hf_acse_aARQ_protocol_version, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_T_AARQ_protocol_version },
  { &hf_acse_aARQ_aSO_context_name, BER_CLASS_CON, 1, 0, dissect_acse_T_AARQ_aSO_context_name },
  { &hf_acse_called_AP_title, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_acse_AP_title },
  { &hf_acse_called_AE_qualifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_acse_AE_qualifier },
  { &hf_acse_called_AP_invocation_identifier, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_acse_AP_invocation_identifier },
  { &hf_acse_called_AE_invocation_identifier, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_acse_AE_invocation_identifier },
  { &hf_acse_calling_AP_title, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_acse_AP_title },
  { &hf_acse_calling_AE_qualifier, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_acse_AE_qualifier },
  { &hf_acse_calling_AP_invocation_identifier, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_acse_AP_invocation_identifier },
  { &hf_acse_calling_AE_invocation_identifier, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_acse_AE_invocation_identifier },
  { &hf_acse_sender_acse_requirements, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_ACSE_requirements },
  { &hf_acse_mechanism_name , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_Mechanism_name },
  { &hf_acse_calling_authentication_value, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_acse_Authentication_value },
  { &hf_acse_aSO_context_name_list, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_ASO_context_name_list },
  { &hf_acse_implementation_information, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_Implementation_data },
  { &hf_acse_p_context_definition_list, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_acse_Syntactic_context_list },
  { &hf_acse_called_asoi_tag, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_ASOI_tag },
  { &hf_acse_calling_asoi_tag, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_ASOI_tag },
  { &hf_acse_aARQ_user_information, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_Association_data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_AARQ_apdu_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AARQ_apdu_U_sequence, hf_index, ett_acse_AARQ_apdu_U);

  return offset;
}



static int
dissect_acse_AARQ_apdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_str(actx->pinfo->cinfo, COL_INFO, "A-Associate-Request");

    offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, true, dissect_acse_AARQ_apdu_U);



  return offset;
}


static int * const T_AARE_protocol_version_bits[] = {
  &hf_acse_T_AARE_protocol_version_version1,
  NULL
};

static int
dissect_acse_T_AARE_protocol_version(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_AARE_protocol_version_bits, 1, hf_index, ett_acse_T_AARE_protocol_version,
                                    NULL);

  return offset;
}



static int
dissect_acse_T_AARE_aSO_context_name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(false, actx, tree, tvb, offset,
                                         hf_index, &actx->external.direct_reference);
  actx->external.direct_ref_present = (actx->external.direct_reference != NULL) ? true : false;


  return offset;
}


static const value_string acse_Associate_result_vals[] = {
  {   0, "accepted" },
  {   1, "rejected-permanent" },
  {   2, "rejected-transient" },
  { 0, NULL }
};


static int
dissect_acse_Associate_result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, 2U, hf_index, NULL);

  return offset;
}


static const value_string acse_T_service_user_vals[] = {
  {   0, "null" },
  {   1, "no-reason-given" },
  {   2, "application-context-name-not-supported" },
  {   3, "calling-AP-title-not-recognized" },
  {   4, "calling-AP-invocation-identifier-not-recognized" },
  {   5, "calling-AE-qualifier-not-recognized" },
  {   6, "calling-AE-invocation-identifier-not-recognized" },
  {   7, "called-AP-title-not-recognized" },
  {   8, "called-AP-invocation-identifier-not-recognized" },
  {   9, "called-AE-qualifier-not-recognized" },
  {  10, "called-AE-invocation-identifier-not-recognized" },
  {  11, "authentication-mechanism-name-not-recognized" },
  {  12, "authentication-mechanism-name-required" },
  {  13, "authentication-failure" },
  {  14, "authentication-required" },
  { 0, NULL }
};


static int
dissect_acse_T_service_user(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, 14U, hf_index, NULL);

  return offset;
}


static const value_string acse_T_service_provider_vals[] = {
  {   0, "null" },
  {   1, "no-reason-given" },
  {   2, "no-common-acse-version" },
  { 0, NULL }
};


static int
dissect_acse_T_service_provider(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, 2U, hf_index, NULL);

  return offset;
}


static const value_string acse_Associate_source_diagnostic_vals[] = {
  {   1, "service-user" },
  {   2, "service-provider" },
  { 0, NULL }
};

static const ber_choice_t Associate_source_diagnostic_choice[] = {
  {   1, &hf_acse_service_user   , BER_CLASS_CON, 1, 0, dissect_acse_T_service_user },
  {   2, &hf_acse_service_provider, BER_CLASS_CON, 2, 0, dissect_acse_T_service_provider },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_Associate_source_diagnostic(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Associate_source_diagnostic_choice, hf_index, ett_acse_Associate_source_diagnostic,
                                 NULL);

  return offset;
}


static const value_string acse_Result_vals[] = {
  {   0, "acceptance" },
  {   1, "user-rejection" },
  {   2, "provider-rejection" },
  { 0, NULL }
};


static int
dissect_acse_Result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_acse_Concrete_syntax_name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_acse_TransferSyntaxName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string acse_T_provider_reason_vals[] = {
  {   0, "reason-not-specified" },
  {   1, "abstract-syntax-not-supported" },
  {   2, "proposed-transfer-syntaxes-not-supported" },
  {   3, "local-limit-on-DCS-exceeded" },
  { 0, NULL }
};


static int
dissect_acse_T_provider_reason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t P_context_result_list_item_sequence[] = {
  { &hf_acse_pcontext_result, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_acse_Result },
  { &hf_acse_concrete_syntax_name, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_Concrete_syntax_name },
  { &hf_acse_provider_reason, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_T_provider_reason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_P_context_result_list_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   P_context_result_list_item_sequence, hf_index, ett_acse_P_context_result_list_item);

  return offset;
}


static const ber_sequence_t P_context_result_list_sequence_of[1] = {
  { &hf_acse_P_context_result_list_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_acse_P_context_result_list_item },
};

static int
dissect_acse_P_context_result_list(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      P_context_result_list_sequence_of, hf_index, ett_acse_P_context_result_list);

  return offset;
}


static const ber_sequence_t AARE_apdu_U_sequence[] = {
  { &hf_acse_aARE_protocol_version, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_T_AARE_protocol_version },
  { &hf_acse_aARE_aSO_context_name, BER_CLASS_CON, 1, 0, dissect_acse_T_AARE_aSO_context_name },
  { &hf_acse_result         , BER_CLASS_CON, 2, 0, dissect_acse_Associate_result },
  { &hf_acse_result_source_diagnostic, BER_CLASS_CON, 3, BER_FLAGS_NOTCHKTAG, dissect_acse_Associate_source_diagnostic },
  { &hf_acse_responding_AP_title, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_acse_AP_title },
  { &hf_acse_responding_AE_qualifier, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_acse_AE_qualifier },
  { &hf_acse_responding_AP_invocation_identifier, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_acse_AP_invocation_identifier },
  { &hf_acse_responding_AE_invocation_identifier, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_acse_AE_invocation_identifier },
  { &hf_acse_responder_acse_requirements, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_ACSE_requirements },
  { &hf_acse_mechanism_name , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_Mechanism_name },
  { &hf_acse_responding_authentication_value, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_acse_Authentication_value },
  { &hf_acse_aSO_context_name_list, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_ASO_context_name_list },
  { &hf_acse_implementation_information, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_Implementation_data },
  { &hf_acse_p_context_result_list, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_P_context_result_list },
  { &hf_acse_called_asoi_tag, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_ASOI_tag },
  { &hf_acse_calling_asoi_tag, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_ASOI_tag },
  { &hf_acse_aARE_user_information, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_Association_data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_AARE_apdu_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AARE_apdu_U_sequence, hf_index, ett_acse_AARE_apdu_U);

  return offset;
}



static int
dissect_acse_AARE_apdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_str(actx->pinfo->cinfo, COL_INFO, "A-Associate-Response");

    offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 1, true, dissect_acse_AARE_apdu_U);



  return offset;
}


static const value_string acse_Release_request_reason_vals[] = {
  {   0, "normal" },
  {   1, "urgent" },
  {  30, "user-defined" },
  { 0, NULL }
};


static int
dissect_acse_Release_request_reason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int reason = -1;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &reason);


  if(reason != -1)
   col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (%s)", val_to_str(reason, acse_Release_request_reason_vals, "reason(%d)"));


  return offset;
}


static const ber_sequence_t RLRQ_apdu_U_sequence[] = {
  { &hf_acse_rLRQ_reason    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_Release_request_reason },
  { &hf_acse_aso_qualifier  , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_acse_ASO_qualifier },
  { &hf_acse_asoi_identifier, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_ASOI_identifier },
  { &hf_acse_rLRQ_user_information, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_Association_data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_RLRQ_apdu_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RLRQ_apdu_U_sequence, hf_index, ett_acse_RLRQ_apdu_U);

  return offset;
}



static int
dissect_acse_RLRQ_apdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_str(actx->pinfo->cinfo, COL_INFO, "Release-Request");

    offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 2, true, dissect_acse_RLRQ_apdu_U);



  return offset;
}


static const value_string acse_Release_response_reason_vals[] = {
  {   0, "normal" },
  {   1, "not-finished" },
  {  30, "user-defined" },
  { 0, NULL }
};


static int
dissect_acse_Release_response_reason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int reason = -1;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &reason);


  if(reason != -1)
   col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (%s)", val_to_str(reason, acse_Release_response_reason_vals, "reason(%d)"));


  return offset;
}


static const ber_sequence_t RLRE_apdu_U_sequence[] = {
  { &hf_acse_rLRE_reason    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_Release_response_reason },
  { &hf_acse_aso_qualifier  , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_acse_ASO_qualifier },
  { &hf_acse_asoi_identifier, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_ASOI_identifier },
  { &hf_acse_rLRE_user_information, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_Association_data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_RLRE_apdu_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RLRE_apdu_U_sequence, hf_index, ett_acse_RLRE_apdu_U);

  return offset;
}



static int
dissect_acse_RLRE_apdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_str(actx->pinfo->cinfo, COL_INFO, "Release-Response");

    offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 3, true, dissect_acse_RLRE_apdu_U);



  return offset;
}


static const value_string acse_ABRT_source_vals[] = {
  {   0, "service-user" },
  {   1, "service-provider" },
  { 0, NULL }
};


static int
dissect_acse_ABRT_source(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int source = -1;

    offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, 1U, hf_index, &source);


  if(source != -1)
   col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (%s)", val_to_str(source, acse_ABRT_source_vals, "source(%d)"));


  return offset;
}


static const value_string acse_ABRT_diagnostic_vals[] = {
  {   1, "no-reason-given" },
  {   2, "protocol-error" },
  {   3, "authentication-mechanism-name-not-recognized" },
  {   4, "authentication-mechanism-name-required" },
  {   5, "authentication-failure" },
  {   6, "authentication-required" },
  { 0, NULL }
};


static int
dissect_acse_ABRT_diagnostic(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t ABRT_apdu_U_sequence[] = {
  { &hf_acse_abort_source   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_acse_ABRT_source },
  { &hf_acse_abort_diagnostic, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_ABRT_diagnostic },
  { &hf_acse_aso_qualifier  , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_acse_ASO_qualifier },
  { &hf_acse_asoi_identifier, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_ASOI_identifier },
  { &hf_acse_aBRT_user_information, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_Association_data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_ABRT_apdu_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ABRT_apdu_U_sequence, hf_index, ett_acse_ABRT_apdu_U);

  return offset;
}



static int
dissect_acse_ABRT_apdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_str(actx->pinfo->cinfo, COL_INFO, "Abort");

    offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 4, true, dissect_acse_ABRT_apdu_U);



  return offset;
}



static int
dissect_acse_User_information(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_acse_Association_data(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_acse_Simply_encoded_data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_acse_T_simple_ASN1_type(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
/*XXX not implemented yet */


  return offset;
}



static int
dissect_acse_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string acse_T_presentation_data_values_vals[] = {
  {   0, "simple-ASN1-type" },
  {   1, "octet-aligned" },
  {   2, "arbitrary" },
  { 0, NULL }
};

static const ber_choice_t T_presentation_data_values_choice[] = {
  {   0, &hf_acse_simple_ASN1_type, BER_CLASS_CON, 0, 0, dissect_acse_T_simple_ASN1_type },
  {   1, &hf_acse_pDVList_octet_aligned, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_acse_OCTET_STRING },
  {   2, &hf_acse_arbitrary      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_acse_BIT_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_T_presentation_data_values(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_presentation_data_values_choice, hf_index, ett_acse_T_presentation_data_values,
                                 NULL);

  return offset;
}


static const ber_sequence_t PDV_list_sequence[] = {
  { &hf_acse_transfer_syntax_name, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_acse_TransferSyntaxName },
  { &hf_acse_presentation_context_identifier, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_acse_Presentation_context_identifier },
  { &hf_acse_presentation_data_values, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_acse_T_presentation_data_values },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_PDV_list(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PDV_list_sequence, hf_index, ett_acse_PDV_list);

  return offset;
}


static const value_string acse_User_Data_vals[] = {
  {   0, "user-information" },
  {   1, "simply-encoded-data" },
  {   2, "fully-encoded-data" },
  { 0, NULL }
};

static const ber_choice_t User_Data_choice[] = {
  {   0, &hf_acse_user_information, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_acse_User_information },
  {   1, &hf_acse_simply_encoded_data, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_acse_Simply_encoded_data },
  {   2, &hf_acse_fully_encoded_data, BER_CLASS_CON, 0, 0, dissect_acse_PDV_list },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_User_Data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 User_Data_choice, hf_index, ett_acse_User_Data,
                                 NULL);

  return offset;
}


static const ber_sequence_t A_DT_apdu_U_sequence[] = {
  { &hf_acse_aso_qualifier  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_acse_ASO_qualifier },
  { &hf_acse_asoi_identifier, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_ASOI_identifier },
  { &hf_acse_a_user_data    , BER_CLASS_CON, 30, BER_FLAGS_NOTCHKTAG, dissect_acse_User_Data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_A_DT_apdu_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   A_DT_apdu_U_sequence, hf_index, ett_acse_A_DT_apdu_U);

  return offset;
}



static int
dissect_acse_A_DT_apdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 5, true, dissect_acse_A_DT_apdu_U);

  return offset;
}



static int
dissect_acse_T_ACRQ_aSO_context_name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(false, actx, tree, tvb, offset,
                                         hf_index, &actx->external.direct_reference);
  actx->external.direct_ref_present = (actx->external.direct_reference != NULL) ? true : false;


  return offset;
}


static const ber_sequence_t ACRQ_apdu_U_sequence[] = {
  { &hf_acse_aso_qualifier  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_acse_ASO_qualifier },
  { &hf_acse_asoi_identifier, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_ASOI_identifier },
  { &hf_acse_aCRQ_aSO_context_name, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_T_ACRQ_aSO_context_name },
  { &hf_acse_aSO_context_name_list, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_ASO_context_name_list },
  { &hf_acse_p_context_definition_list, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_acse_Syntactic_context_list },
  { &hf_acse_user_information, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_User_information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_ACRQ_apdu_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ACRQ_apdu_U_sequence, hf_index, ett_acse_ACRQ_apdu_U);

  return offset;
}



static int
dissect_acse_ACRQ_apdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 6, true, dissect_acse_ACRQ_apdu_U);

  return offset;
}



static int
dissect_acse_T_ACRP_aSO_context_name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(false, actx, tree, tvb, offset,
                                         hf_index, &actx->external.direct_reference);
  actx->external.direct_ref_present = (actx->external.direct_reference != NULL) ? true : false;


  return offset;
}


static const ber_sequence_t ACRP_apdu_U_sequence[] = {
  { &hf_acse_aso_qualifier  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_acse_ASO_qualifier },
  { &hf_acse_asoi_identifier, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_ASOI_identifier },
  { &hf_acse_aSO_context_name, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_T_ACRP_aSO_context_name },
  { &hf_acse_p_context_result_list, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_P_context_result_list },
  { &hf_acse_user_information, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acse_User_information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_ACRP_apdu_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ACRP_apdu_U_sequence, hf_index, ett_acse_ACRP_apdu_U);

  return offset;
}



static int
dissect_acse_ACRP_apdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 7, true, dissect_acse_ACRP_apdu_U);

  return offset;
}


static const ber_choice_t ACSE_apdu_choice[] = {
  {   0, &hf_acse_aarq           , BER_CLASS_APP, 0, BER_FLAGS_IMPLTAG, dissect_acse_AARQ_apdu },
  {   1, &hf_acse_aare           , BER_CLASS_APP, 1, BER_FLAGS_IMPLTAG, dissect_acse_AARE_apdu },
  {   2, &hf_acse_rlrq           , BER_CLASS_APP, 2, BER_FLAGS_IMPLTAG, dissect_acse_RLRQ_apdu },
  {   3, &hf_acse_rlre           , BER_CLASS_APP, 3, BER_FLAGS_IMPLTAG, dissect_acse_RLRE_apdu },
  {   4, &hf_acse_abrt           , BER_CLASS_APP, 4, BER_FLAGS_IMPLTAG, dissect_acse_ABRT_apdu },
  {   5, &hf_acse_adt            , BER_CLASS_APP, 5, BER_FLAGS_IMPLTAG, dissect_acse_A_DT_apdu },
  {   6, &hf_acse_acrq           , BER_CLASS_APP, 6, BER_FLAGS_IMPLTAG, dissect_acse_ACRQ_apdu },
  {   7, &hf_acse_acrp           , BER_CLASS_APP, 7, BER_FLAGS_IMPLTAG, dissect_acse_ACRP_apdu },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_acse_ACSE_apdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ACSE_apdu_choice, hf_index, ett_acse_ACSE_apdu,
                                 NULL);

  return offset;
}



static int
dissect_acse_AE_title_form1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509if_Name(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_acse_AE_title_form2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


const value_string acse_AE_title_vals[] = {
  {   0, "ae-title-form1" },
  {   1, "ae-title-form2" },
  { 0, NULL }
};

static const ber_choice_t AE_title_choice[] = {
  {   0, &hf_acse_ae_title_form1 , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_acse_AE_title_form1 },
  {   1, &hf_acse_ae_title_form2 , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_acse_AE_title_form2 },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_acse_AE_title(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AE_title_choice, hf_index, ett_acse_AE_title,
                                 NULL);

  return offset;
}



/*
* Dissect ACSE PDUs inside a PPDU.
*/
static int
dissect_acse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
	int offset = 0;
	proto_item *item;
	proto_tree *tree;
	char *oid;
	struct SESSION_DATA_STRUCTURE* session;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	/* do we have spdu type from the session dissector?  */
	if (data == NULL) {
		return 0;
	}

	/* first, try to check length   */
	/* do we have at least 2 bytes  */
	if (!tvb_bytes_exist(tvb, 0, 2)) {
		proto_tree_add_item(parent_tree, hf_acse_user_data, tvb, offset,
			tvb_reported_length_remaining(tvb,offset), ENC_NA);
		return 0;  /* no, it isn't a ACSE PDU */
	}

	session = ( (struct SESSION_DATA_STRUCTURE*)data);
	if (session->spdu_type == 0) {
		if (parent_tree) {
			REPORT_DISSECTOR_BUG("Wrong spdu type %x from session dissector.",session->spdu_type);
			return 0;
		}
	}

	asn1_ctx.private_data = session;
	/* save parent_tree so subdissectors can create new top nodes */
	asn1_ctx.subtree.top_tree = parent_tree;

	/*  ACSE has only AARQ,AARE,RLRQ,RLRE,ABRT type of pdu */
	/*  reject everything else                              */
	/*  data pdu is not ACSE pdu and has to go directly to app dissector */
	switch (session->spdu_type) {
	case SES_CONNECTION_REQUEST:		/*   AARQ   */
	case SES_CONNECTION_ACCEPT:		/*   AARE   */
	case SES_REFUSE:			/*   RLRE   */
	case SES_DISCONNECT:			/*   RLRQ   */
	case SES_FINISH:			/*   RLRE   */
	case SES_ABORT:				/*   ABRT   */
	case CLSES_UNIT_DATA:		/* AARQ Connectionless session */
		break;
	case SES_DATA_TRANSFER:
		oid=find_oid_by_pres_ctx_id(pinfo, indir_ref);
		if (oid) {
			if (strcmp(oid, ACSE_APDU_OID) == 0) {
				proto_tree_add_expert_format(parent_tree, pinfo, &ei_acse_invalid_oid, tvb, offset, -1,
				    "Invalid OID: %s", ACSE_APDU_OID);
			}
		 else {
			call_ber_oid_callback(oid, tvb, offset, pinfo, parent_tree, NULL);
		 }
		} else {
			proto_tree_add_expert(parent_tree, pinfo, &ei_acse_dissector_not_available,
									tvb, offset, -1);
		}
		return 0;
	default:
		return 0;
	}

	if (session->spdu_type == CLSES_UNIT_DATA) {
		/* create display subtree for the connectionless protocol */
		item = proto_tree_add_item(parent_tree, proto_clacse, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_acse);

		col_set_str(pinfo->cinfo, COL_PROTOCOL, "CL-ACSE");
		col_clear(pinfo->cinfo, COL_INFO);
	} else {
		/* create display subtree for the protocol */
		item = proto_tree_add_item(parent_tree, proto_acse, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_acse);

		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ACSE");
		col_clear(pinfo->cinfo, COL_INFO);
	}

	/*  we can't make any additional checking here   */
	/*  postpone it before dissector will have more information */
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		int old_offset=offset;
		offset = dissect_acse_ACSE_apdu(false, tvb, offset, &asn1_ctx, tree, -1);
		if (offset == old_offset) {
			proto_tree_add_expert(tree, pinfo, &ei_acse_malformed, tvb, offset, -1);
			break;
		}
	}

	return tvb_captured_length(tvb);
}

/*--- proto_register_acse ----------------------------------------------*/
void proto_register_acse(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_acse_user_data,
      { "User data", "acse.user_data",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_direct_reference,
      { "direct-reference", "acse.direct_reference",
        FT_OID, BASE_NONE, NULL, 0,
        "T_direct_reference", HFILL }},
    { &hf_acse_indirect_reference,
      { "indirect-reference", "acse.indirect_reference",
        FT_INT32, BASE_DEC, NULL, 0,
        "T_indirect_reference", HFILL }},
    { &hf_acse_data_value_descriptor,
      { "data-value-descriptor", "acse.data_value_descriptor",
        FT_STRING, BASE_NONE, NULL, 0,
        "ObjectDescriptor", HFILL }},
    { &hf_acse_encoding,
      { "encoding", "acse.encoding",
        FT_UINT32, BASE_DEC, VALS(acse_T_encoding_vals), 0,
        NULL, HFILL }},
    { &hf_acse_single_ASN1_type,
      { "single-ASN1-type", "acse.single_ASN1_type_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_octet_aligned,
      { "octet-aligned", "acse.octet_aligned",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_octet_aligned", HFILL }},
    { &hf_acse_arbitrary,
      { "arbitrary", "acse.arbitrary",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_acse_aarq,
      { "aarq", "acse.aarq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AARQ_apdu", HFILL }},
    { &hf_acse_aare,
      { "aare", "acse.aare_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AARE_apdu", HFILL }},
    { &hf_acse_rlrq,
      { "rlrq", "acse.rlrq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RLRQ_apdu", HFILL }},
    { &hf_acse_rlre,
      { "rlre", "acse.rlre_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RLRE_apdu", HFILL }},
    { &hf_acse_abrt,
      { "abrt", "acse.abrt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ABRT_apdu", HFILL }},
    { &hf_acse_adt,
      { "adt", "acse.adt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "A_DT_apdu", HFILL }},
    { &hf_acse_acrq,
      { "acrq", "acse.acrq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ACRQ_apdu", HFILL }},
    { &hf_acse_acrp,
      { "acrp", "acse.acrp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ACRP_apdu", HFILL }},
    { &hf_acse_aARQ_protocol_version,
      { "protocol-version", "acse.protocol_version",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_AARQ_protocol_version", HFILL }},
    { &hf_acse_aARQ_aSO_context_name,
      { "aSO-context-name", "acse.aSO_context_name",
        FT_OID, BASE_NONE, NULL, 0,
        "T_AARQ_aSO_context_name", HFILL }},
    { &hf_acse_called_AP_title,
      { "called-AP-title", "acse.called_AP_title",
        FT_UINT32, BASE_DEC, VALS(acse_AP_title_vals), 0,
        "AP_title", HFILL }},
    { &hf_acse_called_AE_qualifier,
      { "called-AE-qualifier", "acse.called_AE_qualifier",
        FT_UINT32, BASE_DEC, VALS(acse_ASO_qualifier_vals), 0,
        "AE_qualifier", HFILL }},
    { &hf_acse_called_AP_invocation_identifier,
      { "called-AP-invocation-identifier", "acse.called_AP_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AP_invocation_identifier", HFILL }},
    { &hf_acse_called_AE_invocation_identifier,
      { "called-AE-invocation-identifier", "acse.called_AE_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AE_invocation_identifier", HFILL }},
    { &hf_acse_calling_AP_title,
      { "calling-AP-title", "acse.calling_AP_title",
        FT_UINT32, BASE_DEC, VALS(acse_AP_title_vals), 0,
        "AP_title", HFILL }},
    { &hf_acse_calling_AE_qualifier,
      { "calling-AE-qualifier", "acse.calling_AE_qualifier",
        FT_UINT32, BASE_DEC, VALS(acse_ASO_qualifier_vals), 0,
        "AE_qualifier", HFILL }},
    { &hf_acse_calling_AP_invocation_identifier,
      { "calling-AP-invocation-identifier", "acse.calling_AP_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AP_invocation_identifier", HFILL }},
    { &hf_acse_calling_AE_invocation_identifier,
      { "calling-AE-invocation-identifier", "acse.calling_AE_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AE_invocation_identifier", HFILL }},
    { &hf_acse_sender_acse_requirements,
      { "sender-acse-requirements", "acse.sender_acse_requirements",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ACSE_requirements", HFILL }},
    { &hf_acse_mechanism_name,
      { "mechanism-name", "acse.mechanism_name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_calling_authentication_value,
      { "calling-authentication-value", "acse.calling_authentication_value",
        FT_UINT32, BASE_DEC, VALS(acse_Authentication_value_vals), 0,
        "Authentication_value", HFILL }},
    { &hf_acse_aSO_context_name_list,
      { "aSO-context-name-list", "acse.aSO_context_name_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_implementation_information,
      { "implementation-information", "acse.implementation_information",
        FT_STRING, BASE_NONE, NULL, 0,
        "Implementation_data", HFILL }},
    { &hf_acse_p_context_definition_list,
      { "p-context-definition-list", "acse.p_context_definition_list",
        FT_UINT32, BASE_DEC, VALS(acse_Syntactic_context_list_vals), 0,
        "Syntactic_context_list", HFILL }},
    { &hf_acse_called_asoi_tag,
      { "called-asoi-tag", "acse.called_asoi_tag",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ASOI_tag", HFILL }},
    { &hf_acse_calling_asoi_tag,
      { "calling-asoi-tag", "acse.calling_asoi_tag",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ASOI_tag", HFILL }},
    { &hf_acse_aARQ_user_information,
      { "user-information", "acse.user_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Association_data", HFILL }},
    { &hf_acse_aARE_protocol_version,
      { "protocol-version", "acse.protocol_version",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_AARE_protocol_version", HFILL }},
    { &hf_acse_aARE_aSO_context_name,
      { "aSO-context-name", "acse.aSO_context_name",
        FT_OID, BASE_NONE, NULL, 0,
        "T_AARE_aSO_context_name", HFILL }},
    { &hf_acse_result,
      { "result", "acse.result",
        FT_UINT32, BASE_DEC, VALS(acse_Associate_result_vals), 0,
        "Associate_result", HFILL }},
    { &hf_acse_result_source_diagnostic,
      { "result-source-diagnostic", "acse.result_source_diagnostic",
        FT_UINT32, BASE_DEC, VALS(acse_Associate_source_diagnostic_vals), 0,
        "Associate_source_diagnostic", HFILL }},
    { &hf_acse_responding_AP_title,
      { "responding-AP-title", "acse.responding_AP_title",
        FT_UINT32, BASE_DEC, VALS(acse_AP_title_vals), 0,
        "AP_title", HFILL }},
    { &hf_acse_responding_AE_qualifier,
      { "responding-AE-qualifier", "acse.responding_AE_qualifier",
        FT_UINT32, BASE_DEC, VALS(acse_ASO_qualifier_vals), 0,
        "AE_qualifier", HFILL }},
    { &hf_acse_responding_AP_invocation_identifier,
      { "responding-AP-invocation-identifier", "acse.responding_AP_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AP_invocation_identifier", HFILL }},
    { &hf_acse_responding_AE_invocation_identifier,
      { "responding-AE-invocation-identifier", "acse.responding_AE_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AE_invocation_identifier", HFILL }},
    { &hf_acse_responder_acse_requirements,
      { "responder-acse-requirements", "acse.responder_acse_requirements",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ACSE_requirements", HFILL }},
    { &hf_acse_responding_authentication_value,
      { "responding-authentication-value", "acse.responding_authentication_value",
        FT_UINT32, BASE_DEC, VALS(acse_Authentication_value_vals), 0,
        "Authentication_value", HFILL }},
    { &hf_acse_p_context_result_list,
      { "p-context-result-list", "acse.p_context_result_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_aARE_user_information,
      { "user-information", "acse.user_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Association_data", HFILL }},
    { &hf_acse_rLRQ_reason,
      { "reason", "acse.reason",
        FT_INT32, BASE_DEC, VALS(acse_Release_request_reason_vals), 0,
        "Release_request_reason", HFILL }},
    { &hf_acse_aso_qualifier,
      { "aso-qualifier", "acse.aso_qualifier",
        FT_UINT32, BASE_DEC, VALS(acse_ASO_qualifier_vals), 0,
        NULL, HFILL }},
    { &hf_acse_asoi_identifier,
      { "asoi-identifier", "acse.asoi_identifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_rLRQ_user_information,
      { "user-information", "acse.user_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Association_data", HFILL }},
    { &hf_acse_rLRE_reason,
      { "reason", "acse.reason",
        FT_INT32, BASE_DEC, VALS(acse_Release_response_reason_vals), 0,
        "Release_response_reason", HFILL }},
    { &hf_acse_rLRE_user_information,
      { "user-information", "acse.user_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Association_data", HFILL }},
    { &hf_acse_abort_source,
      { "abort-source", "acse.abort_source",
        FT_UINT32, BASE_DEC, VALS(acse_ABRT_source_vals), 0,
        "ABRT_source", HFILL }},
    { &hf_acse_abort_diagnostic,
      { "abort-diagnostic", "acse.abort_diagnostic",
        FT_UINT32, BASE_DEC, VALS(acse_ABRT_diagnostic_vals), 0,
        "ABRT_diagnostic", HFILL }},
    { &hf_acse_aBRT_user_information,
      { "user-information", "acse.user_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Association_data", HFILL }},
    { &hf_acse_a_user_data,
      { "a-user-data", "acse.a_user_data",
        FT_UINT32, BASE_DEC, VALS(acse_User_Data_vals), 0,
        "User_Data", HFILL }},
    { &hf_acse_aCRQ_aSO_context_name,
      { "aSO-context-name", "acse.aSO_context_name",
        FT_OID, BASE_NONE, NULL, 0,
        "T_ACRQ_aSO_context_name", HFILL }},
    { &hf_acse_user_information,
      { "user-information", "acse.user_information",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_aSO_context_name,
      { "aSO-context-name", "acse.aSO_context_name",
        FT_OID, BASE_NONE, NULL, 0,
        "T_ACRP_aSO_context_name", HFILL }},
    { &hf_acse_ap_title_form1,
      { "ap-title-form1", "acse.ap_title_form1",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        NULL, HFILL }},
    { &hf_acse_ap_title_form2,
      { "ap-title-form2", "acse.ap_title_form2",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_ap_title_form3,
      { "ap-title-form3", "acse.ap_title_form3",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_aso_qualifier_form1,
      { "aso-qualifier-form1", "acse.aso_qualifier_form1",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_aso_qualifier_form2,
      { "aso-qualifier-form2", "acse.aso_qualifier_form2",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_aso_qualifier_form3,
      { "aso-qualifier-form3", "acse.aso_qualifier_form3",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_aso_qualifier_form_any_octets,
      { "aso-qualifier-form-any-octets", "acse.aso_qualifier_form_any_octets",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ASO_qualifier_form_octets", HFILL }},
    { &hf_acse_ae_title_form1,
      { "ae-title-form1", "acse.ae_title_form1",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        NULL, HFILL }},
    { &hf_acse_ae_title_form2,
      { "ae-title-form2", "acse.ae_title_form2",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_ASOI_tag_item,
      { "ASOI-tag item", "acse.ASOI_tag_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_qualifier,
      { "qualifier", "acse.qualifier",
        FT_UINT32, BASE_DEC, VALS(acse_ASO_qualifier_vals), 0,
        "ASO_qualifier", HFILL }},
    { &hf_acse_identifier,
      { "identifier", "acse.identifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ASOI_identifier", HFILL }},
    { &hf_acse_ASO_context_name_list_item,
      { "ASO-context-name", "acse.ASO_context_name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_context_list,
      { "context-list", "acse.context_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_default_contact_list,
      { "default-contact-list", "acse.default_contact_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Default_Context_List", HFILL }},
    { &hf_acse_Context_list_item,
      { "Context-list item", "acse.Context_list_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_pci,
      { "pci", "acse.pci",
        FT_INT32, BASE_DEC, NULL, 0,
        "Presentation_context_identifier", HFILL }},
    { &hf_acse_abstract_syntax,
      { "abstract-syntax", "acse.abstract_syntax",
        FT_OID, BASE_NONE, NULL, 0,
        "Abstract_syntax_name", HFILL }},
    { &hf_acse_transfer_syntaxes,
      { "transfer-syntaxes", "acse.transfer_syntaxes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_TransferSyntaxName", HFILL }},
    { &hf_acse_transfer_syntaxes_item,
      { "TransferSyntaxName", "acse.TransferSyntaxName",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_Default_Context_List_item,
      { "Default-Context-List item", "acse.Default_Context_List_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_abstract_syntax_name,
      { "abstract-syntax-name", "acse.abstract_syntax_name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_transfer_syntax_name,
      { "transfer-syntax-name", "acse.transfer_syntax_name",
        FT_OID, BASE_NONE, NULL, 0,
        "TransferSyntaxName", HFILL }},
    { &hf_acse_P_context_result_list_item,
      { "P-context-result-list item", "acse.P_context_result_list_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_pcontext_result,
      { "result", "acse.pcontext.result",
        FT_INT32, BASE_DEC, VALS(acse_Result_vals), 0,
        NULL, HFILL }},
    { &hf_acse_concrete_syntax_name,
      { "concrete-syntax-name", "acse.concrete_syntax_name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_provider_reason,
      { "provider-reason", "acse.provider_reason",
        FT_INT32, BASE_DEC, VALS(acse_T_provider_reason_vals), 0,
        NULL, HFILL }},
    { &hf_acse_service_user,
      { "service-user", "acse.service_user",
        FT_UINT32, BASE_DEC, VALS(acse_T_service_user_vals), 0,
        NULL, HFILL }},
    { &hf_acse_service_provider,
      { "service-provider", "acse.service_provider",
        FT_UINT32, BASE_DEC, VALS(acse_T_service_provider_vals), 0,
        NULL, HFILL }},
    { &hf_acse_Association_data_item,
      { "Association-data", "acse.EXTERNALt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNALt", HFILL }},
    { &hf_acse_simply_encoded_data,
      { "simply-encoded-data", "acse.simply_encoded_data",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_fully_encoded_data,
      { "fully-encoded-data", "acse.fully_encoded_data_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDV_list", HFILL }},
    { &hf_acse_presentation_context_identifier,
      { "presentation-context-identifier", "acse.presentation_context_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_presentation_data_values,
      { "presentation-data-values", "acse.presentation_data_values",
        FT_UINT32, BASE_DEC, VALS(acse_T_presentation_data_values_vals), 0,
        NULL, HFILL }},
    { &hf_acse_simple_ASN1_type,
      { "simple-ASN1-type", "acse.simple_ASN1_type_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_pDVList_octet_aligned,
      { "octet-aligned", "acse.octet_aligned",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_acse_other_mechanism_name,
      { "other-mechanism-name", "acse.other_mechanism_name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_other_mechanism_value,
      { "other-mechanism-value", "acse.other_mechanism_value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acse_charstring,
      { "charstring", "acse.charstring",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_acse_bitstring,
      { "bitstring", "acse.bitstring",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_acse_external,
      { "external", "acse.external_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNALt", HFILL }},
    { &hf_acse_other,
      { "other", "acse.other_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Authentication_value_other", HFILL }},
    { &hf_acse_T_AARQ_protocol_version_version1,
      { "version1", "acse.T.AARQ.protocol.version.version1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_acse_T_AARE_protocol_version_version1,
      { "version1", "acse.T.AARE.protocol.version.version1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_acse_ACSE_requirements_authentication,
      { "authentication", "acse.ACSE.requirements.authentication",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_acse_ACSE_requirements_aSO_context_negotiation,
      { "aSO-context-negotiation", "acse.ACSE.requirements.aSO.context.negotiation",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_acse_ACSE_requirements_higher_level_association,
      { "higher-level-association", "acse.ACSE.requirements.higher.level.association",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_acse_ACSE_requirements_nested_association,
      { "nested-association", "acse.ACSE.requirements.nested.association",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_acse,
    &ett_acse_EXTERNALt_U,
    &ett_acse_T_encoding,
    &ett_acse_ACSE_apdu,
    &ett_acse_AARQ_apdu_U,
    &ett_acse_T_AARQ_protocol_version,
    &ett_acse_AARE_apdu_U,
    &ett_acse_T_AARE_protocol_version,
    &ett_acse_RLRQ_apdu_U,
    &ett_acse_RLRE_apdu_U,
    &ett_acse_ABRT_apdu_U,
    &ett_acse_A_DT_apdu_U,
    &ett_acse_ACRQ_apdu_U,
    &ett_acse_ACRP_apdu_U,
    &ett_acse_ACSE_requirements,
    &ett_acse_AP_title,
    &ett_acse_ASO_qualifier,
    &ett_acse_AE_title,
    &ett_acse_ASOI_tag,
    &ett_acse_ASOI_tag_item,
    &ett_acse_ASO_context_name_list,
    &ett_acse_Syntactic_context_list,
    &ett_acse_Context_list,
    &ett_acse_Context_list_item,
    &ett_acse_SEQUENCE_OF_TransferSyntaxName,
    &ett_acse_Default_Context_List,
    &ett_acse_Default_Context_List_item,
    &ett_acse_P_context_result_list,
    &ett_acse_P_context_result_list_item,
    &ett_acse_Associate_source_diagnostic,
    &ett_acse_Association_data,
    &ett_acse_User_Data,
    &ett_acse_PDV_list,
    &ett_acse_T_presentation_data_values,
    &ett_acse_Authentication_value_other,
    &ett_acse_Authentication_value,
  };

  static ei_register_info ei[] = {
     { &ei_acse_dissector_not_available, { "acse.dissector_not_available", PI_UNDECODED, PI_WARN, "Dissector is not available", EXPFILL }},
     { &ei_acse_malformed, { "acse.malformed", PI_MALFORMED, PI_ERROR, "Malformed packet", EXPFILL }},
     { &ei_acse_invalid_oid, { "acse.invalid_oid", PI_UNDECODED, PI_WARN, "Invalid OID", EXPFILL }},
  };

  expert_module_t* expert_acse;

  /* Register protocol */
  proto_acse = proto_register_protocol(PNAME, PSNAME, PFNAME);
  acse_handle = register_dissector("acse", dissect_acse, proto_acse);

  /* Register connectionless protocol */
  proto_clacse = proto_register_protocol(CLPNAME, CLPSNAME, CLPFNAME);


  /* Register fields and subtrees */
  proto_register_field_array(proto_acse, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_acse = expert_register_protocol(proto_acse);
  expert_register_field_array(expert_acse, ei, array_length(ei));

#if NOT_NEEDED
  acse_ctx_oid_table = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), acse_ctx_oid_hash,
			acse_ctx_oid_equal);
#endif
}


/*--- proto_reg_handoff_acse -------------------------------------------*/
void proto_reg_handoff_acse(void) {
/*#include "packet-acse-dis-tab.c"*/
	oid_add_from_string("id-aCSE","2.2.3.1.1");
	register_ber_oid_dissector_handle(ACSE_APDU_OID, acse_handle, proto_acse, "id-as-acse");


}

