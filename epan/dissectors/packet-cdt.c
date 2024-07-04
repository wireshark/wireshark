/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-cdt.c                                                               */
/* asn2wrs.py -b -q -L -p cdt -c ./cdt.cnf -s ./packet-cdt-template -D . -O ../.. cdt.asn */

/* packet-cdt.c
 *
 * Routines for Compressed Data Type packet dissection.
 *
 * Copyright 2005, Stig Bjorlykke <stig@bjorlykke.org>, Thales Norway AS
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref: STANAG 4406 Annex E
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/expert.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-p1.h"

#include "packet-cdt.h"

#define CDT_UNDEFINED  0
#define CDT_EXTERNAL   1
#define CDT_P1         2
#define CDT_P3         3
#define CDT_P7         4

#define PNAME  "Compressed Data Type"
#define PSNAME "CDT"
#define PFNAME "cdt"

void proto_register_cdt(void);
void proto_reg_handoff_cdt(void);

static proto_tree *top_tree;
static proto_item *cdt_item;

static uint32_t content_type;

/* Initialize the protocol and registered fields */
static int proto_cdt;
static int hf_cdt_CompressedData_PDU;             /* CompressedData */
static int hf_cdt_compressionAlgorithm;           /* CompressionAlgorithmIdentifier */
static int hf_cdt_compressedContentInfo;          /* CompressedContentInfo */
static int hf_cdt_algorithmID_ShortForm;          /* AlgorithmID_ShortForm */
static int hf_cdt_algorithmID_OID;                /* OBJECT_IDENTIFIER */
static int hf_cdt_contentType;                    /* T_contentType */
static int hf_cdt_contentType_ShortForm;          /* ContentType_ShortForm */
static int hf_cdt_contentType_OID;                /* T_contentType_OID */
static int hf_cdt_compressedContent;              /* CompressedContent */

/* Initialize the subtree pointers */
static int ett_cdt_CompressedData;
static int ett_cdt_CompressionAlgorithmIdentifier;
static int ett_cdt_CompressedContentInfo;
static int ett_cdt_T_contentType;

static expert_field ei_cdt_unable_compress_content;
static expert_field ei_cdt_unable_uncompress_content;


static const value_string cdt_AlgorithmID_ShortForm_vals[] = {
  {   0, "zlibCompress" },
  { 0, NULL }
};


static int
dissect_cdt_AlgorithmID_ShortForm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t value;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &value);

  proto_item_append_text (cdt_item, ", %s",
                          val_to_str (value, cdt_AlgorithmID_ShortForm_vals,
                                      "unknown"));

  col_append_fstr (actx->pinfo->cinfo, COL_INFO, "%s ",
                   val_to_str (value, cdt_AlgorithmID_ShortForm_vals,
                               "unknown"));


  return offset;
}



static int
dissect_cdt_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string cdt_CompressionAlgorithmIdentifier_vals[] = {
  {   0, "algorithmID-ShortForm" },
  {   1, "algorithmID-OID" },
  { 0, NULL }
};

static const ber_choice_t CompressionAlgorithmIdentifier_choice[] = {
  {   0, &hf_cdt_algorithmID_ShortForm, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cdt_AlgorithmID_ShortForm },
  {   1, &hf_cdt_algorithmID_OID , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cdt_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cdt_CompressionAlgorithmIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CompressionAlgorithmIdentifier_choice, hf_index, ett_cdt_CompressionAlgorithmIdentifier,
                                 NULL);

  return offset;
}


static const value_string cdt_ContentType_ShortForm_vals[] = {
  {   0, "unidentified" },
  {   1, "external" },
  {   2, "p1" },
  {   3, "p3" },
  {   4, "p7" },
  { 0, NULL }
};


static int
dissect_cdt_ContentType_ShortForm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &content_type);

  proto_item_append_text (cdt_item, ", %s",
                          val_to_str (content_type, cdt_ContentType_ShortForm_vals,
                                      "unknown"));

  col_append_fstr (actx->pinfo->cinfo, COL_INFO, "%s ",
                   val_to_str (content_type, cdt_ContentType_ShortForm_vals,
                               "unknown"));


  return offset;
}



static int
dissect_cdt_T_contentType_OID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  const char *obj_id = NULL;

    offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &obj_id);

  if (obj_id) {
    const char *name = oid_resolved_from_string (actx->pinfo->pool, obj_id);

    if (!name) {
      name = obj_id;
    }

    proto_item_append_text (cdt_item, ", %s", name);

    col_append_fstr (actx->pinfo->cinfo, COL_INFO, "%s ", name);
  }


  return offset;
}


static const value_string cdt_T_contentType_vals[] = {
  {   0, "contentType-ShortForm" },
  {   1, "contentType-OID" },
  { 0, NULL }
};

static const ber_choice_t T_contentType_choice[] = {
  {   0, &hf_cdt_contentType_ShortForm, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cdt_ContentType_ShortForm },
  {   1, &hf_cdt_contentType_OID , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cdt_T_contentType_OID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cdt_T_contentType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_contentType_choice, hf_index, ett_cdt_T_contentType,
                                 NULL);

  return offset;
}



static int
dissect_cdt_CompressedContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t   *next_tvb = NULL, *compr_tvb = NULL;
  int         save_offset = offset;

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &compr_tvb);

  if (compr_tvb == NULL) {
    proto_tree_add_expert(top_tree, actx->pinfo, &ei_cdt_unable_compress_content,
							tvb, save_offset, -1);
    col_append_str (actx->pinfo->cinfo, COL_INFO,
                    "[Error: Unable to get compressed content]");
    return offset;
  }

  next_tvb = tvb_child_uncompress_zlib(tvb, compr_tvb, 0, tvb_reported_length (compr_tvb));

  if (next_tvb == NULL) {
    proto_tree_add_expert(top_tree, actx->pinfo, &ei_cdt_unable_uncompress_content,
							tvb, save_offset, -1);
    col_append_str (actx->pinfo->cinfo, COL_INFO,
                    "[Error: Unable to uncompress content]");
    return offset;
  }

  add_new_data_source (actx->pinfo, next_tvb, "Uncompressed Content");

   switch (content_type) {
   case CDT_UNDEFINED:
     call_data_dissector(next_tvb, actx->pinfo, top_tree);
     break;
   case CDT_EXTERNAL:
     dissect_unknown_ber (actx->pinfo, next_tvb, 0, top_tree);
     break;
   case CDT_P1:
     dissect_p1_mts_apdu (next_tvb, actx->pinfo, top_tree, NULL);
     break;
   default:
     call_data_dissector(next_tvb, actx->pinfo, top_tree);
     break;
   }


  return offset;
}


static const ber_sequence_t CompressedContentInfo_sequence[] = {
  { &hf_cdt_contentType     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cdt_T_contentType },
  { &hf_cdt_compressedContent, BER_CLASS_CON, 0, 0, dissect_cdt_CompressedContent },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cdt_CompressedContentInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompressedContentInfo_sequence, hf_index, ett_cdt_CompressedContentInfo);

  return offset;
}


static const ber_sequence_t CompressedData_sequence[] = {
  { &hf_cdt_compressionAlgorithm, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cdt_CompressionAlgorithmIdentifier },
  { &hf_cdt_compressedContentInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cdt_CompressedContentInfo },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cdt_CompressedData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  content_type = 0;

    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompressedData_sequence, hf_index, ett_cdt_CompressedData);



  return offset;
}

/*--- PDUs ---*/

static int dissect_CompressedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cdt_CompressedData(false, tvb, offset, &asn1_ctx, tree, hf_cdt_CompressedData_PDU);
  return offset;
}



/*--- proto_register_cdt -------------------------------------------*/

/*
** Dissect Compressed Data Type
*/
void dissect_cdt (tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  proto_tree *tree = NULL;

  /* save parent_tree so subdissectors can create new top nodes */
  top_tree = parent_tree;

  if (parent_tree) {
    cdt_item = proto_tree_add_item (parent_tree, proto_cdt, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree (cdt_item, ett_cdt_CompressedData);
  } else {
    cdt_item = NULL;
  }

  col_set_str (pinfo->cinfo, COL_PROTOCOL, "CDT");
  col_clear (pinfo->cinfo, COL_INFO);

  dissect_CompressedData_PDU (tvb, pinfo, tree, NULL);
}

void proto_register_cdt (void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cdt_CompressedData_PDU,
      { "CompressedData", "cdt.CompressedData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cdt_compressionAlgorithm,
      { "compressionAlgorithm", "cdt.compressionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(cdt_CompressionAlgorithmIdentifier_vals), 0,
        "CompressionAlgorithmIdentifier", HFILL }},
    { &hf_cdt_compressedContentInfo,
      { "compressedContentInfo", "cdt.compressedContentInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cdt_algorithmID_ShortForm,
      { "algorithmID-ShortForm", "cdt.algorithmID_ShortForm",
        FT_INT32, BASE_DEC, VALS(cdt_AlgorithmID_ShortForm_vals), 0,
        NULL, HFILL }},
    { &hf_cdt_algorithmID_OID,
      { "algorithmID-OID", "cdt.algorithmID_OID",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_cdt_contentType,
      { "contentType", "cdt.contentType",
        FT_UINT32, BASE_DEC, VALS(cdt_T_contentType_vals), 0,
        NULL, HFILL }},
    { &hf_cdt_contentType_ShortForm,
      { "contentType-ShortForm", "cdt.contentType_ShortForm",
        FT_INT32, BASE_DEC, VALS(cdt_ContentType_ShortForm_vals), 0,
        NULL, HFILL }},
    { &hf_cdt_contentType_OID,
      { "contentType-OID", "cdt.contentType_OID",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cdt_compressedContent,
      { "compressedContent", "cdt.compressedContent",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_cdt_CompressedData,
    &ett_cdt_CompressionAlgorithmIdentifier,
    &ett_cdt_CompressedContentInfo,
    &ett_cdt_T_contentType,
  };

  static ei_register_info ei[] = {
     { &ei_cdt_unable_compress_content, { "cdt.unable_compress_content", PI_UNDECODED, PI_ERROR, "Unable to get compressed content", EXPFILL }},
     { &ei_cdt_unable_uncompress_content, { "cdt.unable_uncompress_content", PI_UNDECODED, PI_ERROR, "Unable to get uncompressed content", EXPFILL }},
  };

  expert_module_t* expert_cdt;

  /* Register protocol */
  proto_cdt = proto_register_protocol (PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array (proto_cdt, hf, array_length(hf));
  proto_register_subtree_array (ett, array_length(ett));
  expert_cdt = expert_register_protocol(proto_cdt);
  expert_register_field_array(expert_cdt, ei, array_length(ei));
}


/*--- proto_reg_handoff_cdt ---------------------------------------*/
void proto_reg_handoff_cdt (void) {
  register_ber_oid_dissector("1.3.26.0.4406.0.4.2", dissect_CompressedData_PDU, proto_cdt, "cdt");

}
