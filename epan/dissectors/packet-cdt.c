/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-cdt.c                                                               */
/* ../../tools/asn2wrs.py -b -p cdt -c ./cdt.cnf -s ./packet-cdt-template -D . -O ../../epan/dissectors cdt.asn */

/* Input file: packet-cdt-template.c */

#line 1 "../../asn1/cdt/packet-cdt-template.c"
/* packet-cdt.c
 *
 * Routines for Compressed Data Type packet dissection.
 *
 * Copyright 2005, Stig Bjorlykke <stig@bjorlykke.org>, Thales Norway AS
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
 * Ref: STANAG 4406 Annex E
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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

static proto_tree *top_tree = NULL;
static proto_item *cdt_item = NULL;

static guint32 content_type = 0;

/* Initialize the protocol and registered fields */
static int proto_cdt = -1;

/*--- Included file: packet-cdt-hf.c ---*/
#line 1 "../../asn1/cdt/packet-cdt-hf.c"
static int hf_cdt_CompressedData_PDU = -1;        /* CompressedData */
static int hf_cdt_compressionAlgorithm = -1;      /* CompressionAlgorithmIdentifier */
static int hf_cdt_compressedContentInfo = -1;     /* CompressedContentInfo */
static int hf_cdt_algorithmID_ShortForm = -1;     /* AlgorithmID_ShortForm */
static int hf_cdt_algorithmID_OID = -1;           /* OBJECT_IDENTIFIER */
static int hf_cdt_contentType = -1;               /* T_contentType */
static int hf_cdt_contentType_ShortForm = -1;     /* ContentType_ShortForm */
static int hf_cdt_contentType_OID = -1;           /* T_contentType_OID */
static int hf_cdt_compressedContent = -1;         /* CompressedContent */

/*--- End of included file: packet-cdt-hf.c ---*/
#line 62 "../../asn1/cdt/packet-cdt-template.c"

static dissector_handle_t data_handle = NULL;

/* Initialize the subtree pointers */

/*--- Included file: packet-cdt-ett.c ---*/
#line 1 "../../asn1/cdt/packet-cdt-ett.c"
static gint ett_cdt_CompressedData = -1;
static gint ett_cdt_CompressionAlgorithmIdentifier = -1;
static gint ett_cdt_CompressedContentInfo = -1;
static gint ett_cdt_T_contentType = -1;

/*--- End of included file: packet-cdt-ett.c ---*/
#line 67 "../../asn1/cdt/packet-cdt-template.c"


/*--- Included file: packet-cdt-fn.c ---*/
#line 1 "../../asn1/cdt/packet-cdt-fn.c"

static const value_string cdt_AlgorithmID_ShortForm_vals[] = {
  {   0, "zlibCompress" },
  { 0, NULL }
};


static int
dissect_cdt_AlgorithmID_ShortForm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 21 "../../asn1/cdt/cdt.cnf"
  guint32 value;

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
dissect_cdt_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cdt_CompressionAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cdt_ContentType_ShortForm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 36 "../../asn1/cdt/cdt.cnf"

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
dissect_cdt_T_contentType_OID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 50 "../../asn1/cdt/cdt.cnf"
  const char *obj_id = NULL;

    offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &obj_id);

  if (obj_id) {
    const char *name = oid_resolved_from_string (obj_id);

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
dissect_cdt_T_contentType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_contentType_choice, hf_index, ett_cdt_T_contentType,
                                 NULL);

  return offset;
}



static int
dissect_cdt_CompressedContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 69 "../../asn1/cdt/cdt.cnf"
  tvbuff_t   *next_tvb = NULL, *compr_tvb = NULL;
  proto_item *tf = NULL;
  int         save_offset = offset;

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &compr_tvb);

  if (compr_tvb == NULL) {
    tf = proto_tree_add_text (top_tree, tvb, save_offset, -1,
                              "[Error: Unable to get compressed content]");
    expert_add_info_format (actx->pinfo, tf, PI_UNDECODED, PI_ERROR,
                            "Unable to get compressed content");
    col_append_str (actx->pinfo->cinfo, COL_INFO, 
                    "[Error: Unable to get compressed content]");
    return offset;
  }
  
  next_tvb = tvb_child_uncompress (tvb, compr_tvb, 0, tvb_length (compr_tvb));

  if (next_tvb == NULL) {
    tf = proto_tree_add_text (top_tree, tvb, save_offset, -1,
                              "[Error: Unable to uncompress content]");
    expert_add_info_format (actx->pinfo, tf, PI_UNDECODED, PI_ERROR,
                            "Unable to uncompress content");
    col_append_str (actx->pinfo->cinfo, COL_INFO, 
                    "[Error: Unable to uncompress content]");
    return offset;
  }

  add_new_data_source (actx->pinfo, next_tvb, "Uncompressed Content");

   switch (content_type) {
   case CDT_UNDEFINED:
     call_dissector (data_handle, next_tvb, actx->pinfo, top_tree);
     break;
   case CDT_EXTERNAL:
     dissect_unknown_ber (actx->pinfo, next_tvb, 0, top_tree);
     break;
   case CDT_P1:
     dissect_p1_mts_apdu (next_tvb, actx->pinfo, top_tree);
     break;
   default:
     call_dissector (data_handle, next_tvb, actx->pinfo, top_tree);
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
dissect_cdt_CompressedContentInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cdt_CompressedData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 13 "../../asn1/cdt/cdt.cnf"
  content_type = 0;

    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompressedData_sequence, hf_index, ett_cdt_CompressedData);




  return offset;
}

/*--- PDUs ---*/

static void dissect_CompressedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cdt_CompressedData(FALSE, tvb, 0, &asn1_ctx, tree, hf_cdt_CompressedData_PDU);
}


/*--- End of included file: packet-cdt-fn.c ---*/
#line 69 "../../asn1/cdt/packet-cdt-template.c"


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
  }

  col_set_str (pinfo->cinfo, COL_PROTOCOL, "CDT");
  col_clear (pinfo->cinfo, COL_INFO);

  dissect_CompressedData_PDU (tvb, pinfo, tree);
}

void proto_register_cdt (void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-cdt-hfarr.c ---*/
#line 1 "../../asn1/cdt/packet-cdt-hfarr.c"
    { &hf_cdt_CompressedData_PDU,
      { "CompressedData", "cdt.CompressedData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cdt_compressionAlgorithm,
      { "compressionAlgorithm", "cdt.compressionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(cdt_CompressionAlgorithmIdentifier_vals), 0,
        "CompressionAlgorithmIdentifier", HFILL }},
    { &hf_cdt_compressedContentInfo,
      { "compressedContentInfo", "cdt.compressedContentInfo",
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

/*--- End of included file: packet-cdt-hfarr.c ---*/
#line 99 "../../asn1/cdt/packet-cdt-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-cdt-ettarr.c ---*/
#line 1 "../../asn1/cdt/packet-cdt-ettarr.c"
    &ett_cdt_CompressedData,
    &ett_cdt_CompressionAlgorithmIdentifier,
    &ett_cdt_CompressedContentInfo,
    &ett_cdt_T_contentType,

/*--- End of included file: packet-cdt-ettarr.c ---*/
#line 104 "../../asn1/cdt/packet-cdt-template.c"
  };

  /* Register protocol */
  proto_cdt = proto_register_protocol (PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array (proto_cdt, hf, array_length(hf));
  proto_register_subtree_array (ett, array_length(ett));

}


/*--- proto_reg_handoff_cdt ---------------------------------------*/
void proto_reg_handoff_cdt (void) {

/*--- Included file: packet-cdt-dis-tab.c ---*/
#line 1 "../../asn1/cdt/packet-cdt-dis-tab.c"
  register_ber_oid_dissector("1.3.26.0.4406.0.4.2", dissect_CompressedData_PDU, proto_cdt, "cdt");


/*--- End of included file: packet-cdt-dis-tab.c ---*/
#line 119 "../../asn1/cdt/packet-cdt-template.c"

  data_handle = find_dissector ("data");
}
