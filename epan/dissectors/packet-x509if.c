/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-x509if.c                                                          */
/* ../../tools/asn2eth.py -X -b -e -p x509if -c x509if.cnf -s packet-x509if-template InformationFramework.asn */

/* Input file: packet-x509if-template.c */

/* packet-x509if.c
 * Routines for X.509 Information Framework packet dissection
 *
 * $Id: packet-x509if-template.c 12245 2004-10-08 20:28:04Z guy $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-x509if.h"

#define PNAME  "X.509 Information Framework"
#define PSNAME "X509IF"
#define PFNAME "x509if"

/* Initialize the protocol and registered fields */
int proto_x509if = -1;
int hf_x509if_ATADV_attribute_id = -1;

/*--- Included file: packet-x509if-hf.c ---*/

static int hf_x509if_rdnSequence = -1;            /* RDNSequence */
static int hf_x509if_RDNSequence_item = -1;       /* RelativeDistinguishedName */
static int hf_x509if_RelativeDistinguishedName_item = -1;  /* AttributeTypeAndDistinguishedValue */
/* named bits */
static int hf_x509if_AllowedSubset_baseObject = -1;
static int hf_x509if_AllowedSubset_oneLevel = -1;
static int hf_x509if_AllowedSubset_wholeSubtree = -1;

/*--- End of included file: packet-x509if-hf.c ---*/


/* Initialize the subtree pointers */
static gint ett_x509if_Attribute = -1;

/*--- Included file: packet-x509if-ett.c ---*/

static gint ett_x509if_Name = -1;
static gint ett_x509if_RDNSequence = -1;
static gint ett_x509if_RelativeDistinguishedName = -1;
static gint ett_x509if_AttributeTypeAndDistinguishedValue = -1;
static gint ett_x509if_AllowedSubset = -1;

/*--- End of included file: packet-x509if-ett.c ---*/



static const ber_sequence Attribute_sequence[] = {
  /*  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_hf_x509if_type },*/
  /*XXX  missing stuff here */
  { 0, 0, 0, NULL }
};

int
dissect_x509if_Attribute(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Attribute_sequence, hf_index, ett_x509if_Attribute);

  return offset;
}



static char ATADV_attribute_id[64]; /*64 chars should be long enough? */
static int 
dissect_hf_x509if_ATADV_attribute_id(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) 
{
  offset = dissect_ber_object_identifier(FALSE, pinfo, tree, tvb, offset,
                                         hf_x509if_ATADV_attribute_id, ATADV_attribute_id);
  return offset;
}
static int 
dissect_hf_x509if_ATADV_attribute_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) 
{
  offset=call_ber_oid_callback(ATADV_attribute_id, tvb, offset, pinfo, tree);
  return offset;
}

static const ber_sequence AttributeTypeAndDistinguishedValue_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_hf_x509if_ATADV_attribute_id },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_hf_x509if_ATADV_attribute_value },
  /*XXX  missing stuff here */
  { 0, 0, 0, NULL }
};

static int
dissect_x509if_AttributeTypeAndDistinguishedValue(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                AttributeTypeAndDistinguishedValue_sequence, hf_index, ett_x509if_AttributeTypeAndDistinguishedValue);

  return offset;
}


/*--- Included file: packet-x509if-fn.c ---*/

/*--- Fields for imported types ---*/



static int
dissect_x509if_AttributeId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset,
                                         hf_index, NULL);

  return offset;
}


int
dissect_x509if_AttributeType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509if_AttributeId(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}

static int dissect_RelativeDistinguishedName_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeTypeAndDistinguishedValue(FALSE, tvb, offset, pinfo, tree, hf_x509if_RelativeDistinguishedName_item);
}

static const ber_sequence RelativeDistinguishedName_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RelativeDistinguishedName_item },
};

int
dissect_x509if_RelativeDistinguishedName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                              RelativeDistinguishedName_set_of, hf_index, ett_x509if_RelativeDistinguishedName);

  return offset;
}
static int dissect_RDNSequence_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_RelativeDistinguishedName(FALSE, tvb, offset, pinfo, tree, hf_x509if_RDNSequence_item);
}

static const ber_sequence RDNSequence_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_RDNSequence_item },
};

static int
dissect_x509if_RDNSequence(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   RDNSequence_sequence_of, hf_index, ett_x509if_RDNSequence);

  return offset;
}
static int dissect_rdnSequence(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_RDNSequence(FALSE, tvb, offset, pinfo, tree, hf_x509if_rdnSequence);
}


const value_string Name_vals[] = {
  {   0, "rdnSequence" },
  { 0, NULL }
};

static const ber_choice Name_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_rdnSequence },
  { 0, 0, 0, 0, NULL }
};

int
dissect_x509if_Name(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              Name_choice, hf_index, ett_x509if_Name);

  return offset;
}


static int
dissect_x509if_DistinguishedName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509if_RDNSequence(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const value_string ObjectClassKind_vals[] = {
  {   0, "abstract" },
  {   1, "structural" },
  {   2, "auxiliary" },
  { 0, NULL }
};


static int
dissect_x509if_ObjectClassKind(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}

static const asn_namedbit AllowedSubset_bits[] = {
  {  0, &hf_x509if_AllowedSubset_baseObject, -1, -1, NULL, NULL },
  {  1, &hf_x509if_AllowedSubset_oneLevel, -1, -1, NULL, NULL },
  {  2, &hf_x509if_AllowedSubset_wholeSubtree, -1, -1, NULL, NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x509if_AllowedSubset(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                 AllowedSubset_bits, hf_index, ett_x509if_AllowedSubset,
                                 NULL);

  return offset;
}


static const value_string ImposedSubset_vals[] = {
  {   0, "baseObject" },
  {   1, "oneLevel" },
  {   2, "wholeSubtree" },
  { 0, NULL }
};


static int
dissect_x509if_ImposedSubset(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}


/*--- End of included file: packet-x509if-fn.c ---*/



/*--- proto_register_x509if ----------------------------------------------*/
void proto_register_x509if(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509if_ATADV_attribute_id,
      { "Attribute Id", "x509if.attribute.id",
        FT_STRING, BASE_NONE, NULL, 0,
        "Attribute Id", HFILL }},

/*--- Included file: packet-x509if-hfarr.c ---*/

    { &hf_x509if_rdnSequence,
      { "rdnSequence", "x509if.rdnSequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Name/rdnSequence", HFILL }},
    { &hf_x509if_RDNSequence_item,
      { "Item", "x509if.RDNSequence_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RDNSequence/_item", HFILL }},
    { &hf_x509if_RelativeDistinguishedName_item,
      { "Item", "x509if.RelativeDistinguishedName_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelativeDistinguishedName/_item", HFILL }},
    { &hf_x509if_AllowedSubset_baseObject,
      { "baseObject", "x509if.baseObject",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x509if_AllowedSubset_oneLevel,
      { "oneLevel", "x509if.oneLevel",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x509if_AllowedSubset_wholeSubtree,
      { "wholeSubtree", "x509if.wholeSubtree",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},

/*--- End of included file: packet-x509if-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_x509if_Attribute,

/*--- Included file: packet-x509if-ettarr.c ---*/

    &ett_x509if_Name,
    &ett_x509if_RDNSequence,
    &ett_x509if_RelativeDistinguishedName,
    &ett_x509if_AttributeTypeAndDistinguishedValue,
    &ett_x509if_AllowedSubset,

/*--- End of included file: packet-x509if-ettarr.c ---*/

  };

  /* Register protocol */
  proto_x509if = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x509if, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_x509if -------------------------------------------*/
void proto_reg_handoff_x509if(void) {
}

