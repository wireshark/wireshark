/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* ./packet-cdt.c                                                             */
/* ../../tools/asn2wrs.py -b -e -p cdt -c cdt.cnf -s packet-cdt-template cdt.asn */

/* Input file: packet-cdt-template.c */

#line 1 "packet-cdt-template.c"
/* packet-cdt.c
 *
 * Routines for Compressed Data Type packet dissection.
 *
 * Copyright 2005, Stig Bj>rlykke <stig@bjorlykke.org>, Thales Norway AS
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
#include <epan/oid_resolv.h>

#include "packet-ber.h"
#include "packet-x411.h"

#include "packet-cdt.h"

#define PNAME  "Compressed Data Type"
#define PSNAME "CDT"
#define PFNAME "cdt"

static proto_tree *top_tree = NULL;
static proto_item *cdt_item = NULL;

/* Initialize the protocol and registered fields */
int proto_cdt = -1;

/*--- Included file: packet-cdt-hf.c ---*/
#line 1 "packet-cdt-hf.c"
static int hf_cdt_CompressedData_PDU = -1;        /* CompressedData */
static int hf_cdt_compressionAlgorithm = -1;      /* CompressionAlgorithmIdentifier */
static int hf_cdt_compressedContentInfo = -1;     /* CompressedContentInfo */
static int hf_cdt_algorithmID_ShortForm = -1;     /* AlgorithmID_ShortForm */
static int hf_cdt_algorithmID_OID = -1;           /* OBJECT_IDENTIFIER */
static int hf_cdt_contentType = -1;               /* T_contentType */
static int hf_cdt_contentType_ShortForm = -1;     /* ContentType_ShortForm */
static int hf_cdt_contentType_OID = -1;           /* OBJECT_IDENTIFIER */
static int hf_cdt_compressedContent = -1;         /* CompressedContent */

/*--- End of included file: packet-cdt-hf.c ---*/
#line 52 "packet-cdt-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-cdt-ett.c ---*/
#line 1 "packet-cdt-ett.c"
static gint ett_cdt_CompressedData = -1;
static gint ett_cdt_CompressionAlgorithmIdentifier = -1;
static gint ett_cdt_CompressedContentInfo = -1;
static gint ett_cdt_T_contentType = -1;

/*--- End of included file: packet-cdt-ett.c ---*/
#line 55 "packet-cdt-template.c"


/*--- Included file: packet-cdt-fn.c ---*/
#line 1 "packet-cdt-fn.c"
/*--- Fields for imported types ---*/



static const value_string cdt_AlgorithmID_ShortForm_vals[] = {
  {   0, "zlibCompress" },
  { 0, NULL }
};


static int
dissect_cdt_AlgorithmID_ShortForm(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 16 "cdt.cnf"
  guint32 value;

    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &value);

  proto_item_append_text (cdt_item, ", %s",
                          val_to_str (value, cdt_AlgorithmID_ShortForm_vals,
                                      "unknown"));

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, "%s ", 
                     val_to_str (value, cdt_AlgorithmID_ShortForm_vals, 
                                 "unknown"));



  return offset;
}
static int dissect_algorithmID_ShortForm_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cdt_AlgorithmID_ShortForm(TRUE, tvb, offset, pinfo, tree, hf_cdt_algorithmID_ShortForm);
}



static int
dissect_cdt_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 48 "cdt.cnf"
  const char *obj_id = NULL;

    offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_index, &obj_id);

  if (obj_id) {
    const char *name = get_oid_str_name (obj_id);

    if (!name) {
      name = obj_id;
    }

    proto_item_append_text (cdt_item, ", %s", name);

    if (check_col (pinfo->cinfo, COL_INFO))
      col_append_fstr (pinfo->cinfo, COL_INFO, "%s ", name);
  }



  return offset;
}
static int dissect_algorithmID_OID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cdt_OBJECT_IDENTIFIER(TRUE, tvb, offset, pinfo, tree, hf_cdt_algorithmID_OID);
}
static int dissect_contentType_OID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cdt_OBJECT_IDENTIFIER(TRUE, tvb, offset, pinfo, tree, hf_cdt_contentType_OID);
}


static const value_string cdt_CompressionAlgorithmIdentifier_vals[] = {
  {   0, "algorithmID-ShortForm" },
  {   1, "algorithmID-OID" },
  { 0, NULL }
};

static const ber_choice_t CompressionAlgorithmIdentifier_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_algorithmID_ShortForm_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_algorithmID_OID_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cdt_CompressionAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CompressionAlgorithmIdentifier_choice, hf_index, ett_cdt_CompressionAlgorithmIdentifier,
                                 NULL);

  return offset;
}
static int dissect_compressionAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cdt_CompressionAlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cdt_compressionAlgorithm);
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
dissect_cdt_ContentType_ShortForm(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 32 "cdt.cnf"
  guint32 value;

    offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &value);

  proto_item_append_text (cdt_item, ", %s",
                          val_to_str (value, cdt_ContentType_ShortForm_vals, 
                                      "unknown"));

  if (check_col (pinfo->cinfo, COL_INFO))
    col_append_fstr (pinfo->cinfo, COL_INFO, "%s ", 
                     val_to_str (value, cdt_ContentType_ShortForm_vals, 
                                 "unknown"));



  return offset;
}
static int dissect_contentType_ShortForm_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cdt_ContentType_ShortForm(TRUE, tvb, offset, pinfo, tree, hf_cdt_contentType_ShortForm);
}


static const value_string cdt_T_contentType_vals[] = {
  {   0, "contentType-ShortForm" },
  {   1, "contentType-OID" },
  { 0, NULL }
};

static const ber_choice_t T_contentType_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_contentType_ShortForm_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_contentType_OID_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cdt_T_contentType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_contentType_choice, hf_index, ett_cdt_T_contentType,
                                 NULL);

  return offset;
}
static int dissect_contentType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cdt_T_contentType(FALSE, tvb, offset, pinfo, tree, hf_cdt_contentType);
}



static int
dissect_cdt_CompressedContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 68 "cdt.cnf"
  tvbuff_t   *next_tvb = NULL, *compr_tvb = NULL;
  int         save_offset = offset;

    offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &compr_tvb);

  if (compr_tvb == NULL) {
    proto_tree_add_text (top_tree, tvb, save_offset, -1,
                         "[Error: Unable to get compressed content]");
    if (check_col (pinfo->cinfo, COL_INFO))
      col_append_fstr (pinfo->cinfo, COL_INFO, 
                       "[Error: Unable to get compressed content]");
    return offset;
  }
  
  next_tvb = tvb_uncompress (compr_tvb, 0, tvb_length (compr_tvb));

  if (next_tvb == NULL) {
    proto_tree_add_text (top_tree, tvb, save_offset, -1,
                         "[Error: Unable to uncompress content]");
    if (check_col (pinfo->cinfo, COL_INFO))
      col_append_fstr (pinfo->cinfo, COL_INFO, 
                       "[Error: Unable to uncompress content]");
    return offset;
  }

  tvb_set_child_real_data_tvbuff (tvb, next_tvb);
  add_new_data_source (pinfo, next_tvb, "Uncompressed Content");

  dissect_x411_mts_apdu (next_tvb, pinfo, top_tree);
  


  return offset;
}
static int dissect_compressedContent(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cdt_CompressedContent(FALSE, tvb, offset, pinfo, tree, hf_cdt_compressedContent);
}


static const ber_sequence_t CompressedContentInfo_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_contentType },
  { BER_CLASS_CON, 0, 0, dissect_compressedContent },
  { 0, 0, 0, NULL }
};

static int
dissect_cdt_CompressedContentInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CompressedContentInfo_sequence, hf_index, ett_cdt_CompressedContentInfo);

  return offset;
}
static int dissect_compressedContentInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cdt_CompressedContentInfo(FALSE, tvb, offset, pinfo, tree, hf_cdt_compressedContentInfo);
}


static const ber_sequence_t CompressedData_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_compressionAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_compressedContentInfo },
  { 0, 0, 0, NULL }
};

int
dissect_cdt_CompressedData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CompressedData_sequence, hf_index, ett_cdt_CompressedData);

  return offset;
}

/*--- PDUs ---*/

static void dissect_CompressedData_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_cdt_CompressedData(FALSE, tvb, 0, pinfo, tree, hf_cdt_CompressedData_PDU);
}


/*--- End of included file: packet-cdt-fn.c ---*/
#line 57 "packet-cdt-template.c"


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
    cdt_item = proto_tree_add_item (parent_tree, proto_cdt, tvb, 0, -1, FALSE);
    tree = proto_item_add_subtree (cdt_item, ett_cdt_CompressedData);
  }

  if (check_col (pinfo->cinfo, COL_PROTOCOL))
    col_set_str (pinfo->cinfo, COL_PROTOCOL, "CDT");
  if (check_col (pinfo->cinfo, COL_INFO))
    col_clear (pinfo->cinfo, COL_INFO);

  dissect_CompressedData_PDU (tvb, pinfo, tree);
}

void proto_register_cdt (void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-cdt-hfarr.c ---*/
#line 1 "packet-cdt-hfarr.c"
    { &hf_cdt_CompressedData_PDU,
      { "CompressedData", "cdt.CompressedData",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompressedData", HFILL }},
    { &hf_cdt_compressionAlgorithm,
      { "compressionAlgorithm", "cdt.compressionAlgorithm",
        FT_UINT32, BASE_DEC, VALS(cdt_CompressionAlgorithmIdentifier_vals), 0,
        "CompressedData/compressionAlgorithm", HFILL }},
    { &hf_cdt_compressedContentInfo,
      { "compressedContentInfo", "cdt.compressedContentInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "CompressedData/compressedContentInfo", HFILL }},
    { &hf_cdt_algorithmID_ShortForm,
      { "algorithmID-ShortForm", "cdt.algorithmID_ShortForm",
        FT_INT32, BASE_DEC, VALS(cdt_AlgorithmID_ShortForm_vals), 0,
        "CompressionAlgorithmIdentifier/algorithmID-ShortForm", HFILL }},
    { &hf_cdt_algorithmID_OID,
      { "algorithmID-OID", "cdt.algorithmID_OID",
        FT_OID, BASE_NONE, NULL, 0,
        "CompressionAlgorithmIdentifier/algorithmID-OID", HFILL }},
    { &hf_cdt_contentType,
      { "contentType", "cdt.contentType",
        FT_UINT32, BASE_DEC, VALS(cdt_T_contentType_vals), 0,
        "CompressedContentInfo/contentType", HFILL }},
    { &hf_cdt_contentType_ShortForm,
      { "contentType-ShortForm", "cdt.contentType_ShortForm",
        FT_INT32, BASE_DEC, VALS(cdt_ContentType_ShortForm_vals), 0,
        "CompressedContentInfo/contentType/contentType-ShortForm", HFILL }},
    { &hf_cdt_contentType_OID,
      { "contentType-OID", "cdt.contentType_OID",
        FT_OID, BASE_NONE, NULL, 0,
        "CompressedContentInfo/contentType/contentType-OID", HFILL }},
    { &hf_cdt_compressedContent,
      { "compressedContent", "cdt.compressedContent",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CompressedContentInfo/compressedContent", HFILL }},

/*--- End of included file: packet-cdt-hfarr.c ---*/
#line 89 "packet-cdt-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-cdt-ettarr.c ---*/
#line 1 "packet-cdt-ettarr.c"
    &ett_cdt_CompressedData,
    &ett_cdt_CompressionAlgorithmIdentifier,
    &ett_cdt_CompressedContentInfo,
    &ett_cdt_T_contentType,

/*--- End of included file: packet-cdt-ettarr.c ---*/
#line 94 "packet-cdt-template.c"
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
#line 1 "packet-cdt-dis-tab.c"
  register_ber_oid_dissector("1.3.26.0.4406.0.4.2", dissect_CompressedData_PDU, proto_cdt, "cdt");


/*--- End of included file: packet-cdt-dis-tab.c ---*/
#line 109 "packet-cdt-template.c"
}
