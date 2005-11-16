/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-x501.c                                                            */
/* ../../tools/asn2eth.py -X -b -e -p x501 -c x501.cnf -s packet-x501-template x501.asn */

/* Input file: packet-x501-template.c */

/* packet-x501.c
 * Routines for X.501 (DSA Operational Attributes)  packet dissection
 * Graeme Lunt 2005
 *
 * $Id: packet-x501-template.c 14773 2005-06-26 10:59:15Z etxrab $
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

#include "packet-x509sat.h"
#include "packet-x509if.h"
#include "packet-dap.h"
#include "packet-dsp.h"


#include "packet-x501.h"

#define PNAME  "X.501 Operational Attributes"
#define PSNAME "X501"
#define PFNAME "x501"

/* Initialize the protocol and registered fields */
int proto_x501 = -1;


/*--- Included file: packet-x501-hf.c ---*/

static int hf_x501_DSEType_PDU = -1;              /* DSEType */
static int hf_x501_SupplierInformation_PDU = -1;  /* SupplierInformation */
static int hf_x501_ConsumerInformation_PDU = -1;  /* ConsumerInformation */
static int hf_x501_SupplierAndConsumers_PDU = -1;  /* SupplierAndConsumers */
static int hf_x501_ae_title = -1;                 /* Name */
static int hf_x501_address = -1;                  /* PresentationAddress */
static int hf_x501_protocolInformation = -1;      /* SET_OF_ProtocolInformation */
static int hf_x501_protocolInformation_item = -1;  /* ProtocolInformation */
static int hf_x501_agreementID = -1;              /* OperationalBindingID */
static int hf_x501_supplier_is_master = -1;       /* BOOLEAN */
static int hf_x501_non_supplying_master = -1;     /* AccessPoint */
static int hf_x501_consumers = -1;                /* SET_OF_AccessPoint */
static int hf_x501_consumers_item = -1;           /* AccessPoint */
/* named bits */
static int hf_x501_DSEType_root = -1;
static int hf_x501_DSEType_glue = -1;
static int hf_x501_DSEType_cp = -1;
static int hf_x501_DSEType_entry = -1;
static int hf_x501_DSEType_alias = -1;
static int hf_x501_DSEType_subr = -1;
static int hf_x501_DSEType_nssr = -1;
static int hf_x501_DSEType_supr = -1;
static int hf_x501_DSEType_xr = -1;
static int hf_x501_DSEType_admPoint = -1;
static int hf_x501_DSEType_subentry = -1;
static int hf_x501_DSEType_shadow = -1;
static int hf_x501_DSEType_immSupr = -1;
static int hf_x501_DSEType_rhob = -1;
static int hf_x501_DSEType_sa = -1;
static int hf_x501_DSEType_dsSubentry = -1;
static int hf_x501_DSEType_familyMember = -1;

/*--- End of included file: packet-x501-hf.c ---*/


/* Initialize the subtree pointers */
static gint ett_x501 = -1;

/*--- Included file: packet-x501-ett.c ---*/

static gint ett_x501_DSEType = -1;
static gint ett_x501_SupplierOrConsumer = -1;
static gint ett_x501_SET_OF_ProtocolInformation = -1;
static gint ett_x501_SupplierInformation = -1;
static gint ett_x501_SupplierAndConsumers = -1;
static gint ett_x501_SET_OF_AccessPoint = -1;

/*--- End of included file: packet-x501-ett.c ---*/



/*--- Included file: packet-x501-fn.c ---*/

/*--- Fields for imported types ---*/

static int dissect_ae_title(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(FALSE, tvb, offset, pinfo, tree, hf_x501_ae_title);
}
static int dissect_address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_PresentationAddress(FALSE, tvb, offset, pinfo, tree, hf_x501_address);
}
static int dissect_protocolInformation_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_ProtocolInformation(FALSE, tvb, offset, pinfo, tree, hf_x501_protocolInformation_item);
}
static int dissect_agreementID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dap_OperationalBindingID(FALSE, tvb, offset, pinfo, tree, hf_x501_agreementID);
}
static int dissect_non_supplying_master(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_AccessPoint(FALSE, tvb, offset, pinfo, tree, hf_x501_non_supplying_master);
}
static int dissect_consumers_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_dsp_AccessPoint(FALSE, tvb, offset, pinfo, tree, hf_x501_consumers_item);
}


static const asn_namedbit DSEType_bits[] = {
  {  0, &hf_x501_DSEType_root, -1, -1, "root", NULL },
  {  1, &hf_x501_DSEType_glue, -1, -1, "glue", NULL },
  {  2, &hf_x501_DSEType_cp, -1, -1, "cp", NULL },
  {  3, &hf_x501_DSEType_entry, -1, -1, "entry", NULL },
  {  4, &hf_x501_DSEType_alias, -1, -1, "alias", NULL },
  {  5, &hf_x501_DSEType_subr, -1, -1, "subr", NULL },
  {  6, &hf_x501_DSEType_nssr, -1, -1, "nssr", NULL },
  {  7, &hf_x501_DSEType_supr, -1, -1, "supr", NULL },
  {  8, &hf_x501_DSEType_xr, -1, -1, "xr", NULL },
  {  9, &hf_x501_DSEType_admPoint, -1, -1, "admPoint", NULL },
  { 10, &hf_x501_DSEType_subentry, -1, -1, "subentry", NULL },
  { 11, &hf_x501_DSEType_shadow, -1, -1, "shadow", NULL },
  { 13, &hf_x501_DSEType_immSupr, -1, -1, "immSupr", NULL },
  { 14, &hf_x501_DSEType_rhob, -1, -1, "rhob", NULL },
  { 15, &hf_x501_DSEType_sa, -1, -1, "sa", NULL },
  { 16, &hf_x501_DSEType_dsSubentry, -1, -1, "dsSubentry", NULL },
  { 17, &hf_x501_DSEType_familyMember, -1, -1, "familyMember", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

int
dissect_x501_DSEType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    DSEType_bits, hf_index, ett_x501_DSEType,
                                    NULL);

  return offset;
}


static const ber_sequence_t SET_OF_ProtocolInformation_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_protocolInformation_item },
};

static int
dissect_x501_SET_OF_ProtocolInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_ProtocolInformation_set_of, hf_index, ett_x501_SET_OF_ProtocolInformation);

  return offset;
}
static int dissect_protocolInformation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x501_SET_OF_ProtocolInformation(FALSE, tvb, offset, pinfo, tree, hf_x501_protocolInformation);
}


static const ber_sequence_t SupplierOrConsumer_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_ae_title },
  { BER_CLASS_CON, 1, 0, dissect_address },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_protocolInformation },
  { BER_CLASS_CON, 3, 0, dissect_agreementID },
  { 0, 0, 0, NULL }
};

static int
dissect_x501_SupplierOrConsumer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SupplierOrConsumer_set, hf_index, ett_x501_SupplierOrConsumer);

  return offset;
}



static int
dissect_x501_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_supplier_is_master(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x501_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_x501_supplier_is_master);
}


static const ber_sequence_t SupplierInformation_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_ae_title },
  { BER_CLASS_CON, 1, 0, dissect_address },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_protocolInformation },
  { BER_CLASS_CON, 3, 0, dissect_agreementID },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_supplier_is_master },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_non_supplying_master },
  { 0, 0, 0, NULL }
};

static int
dissect_x501_SupplierInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SupplierInformation_set, hf_index, ett_x501_SupplierInformation);

  return offset;
}



static int
dissect_x501_ConsumerInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x501_SupplierOrConsumer(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const ber_sequence_t SET_OF_AccessPoint_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_consumers_item },
};

static int
dissect_x501_SET_OF_AccessPoint(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_AccessPoint_set_of, hf_index, ett_x501_SET_OF_AccessPoint);

  return offset;
}
static int dissect_consumers(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x501_SET_OF_AccessPoint(FALSE, tvb, offset, pinfo, tree, hf_x501_consumers);
}


static const ber_sequence_t SupplierAndConsumers_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_ae_title },
  { BER_CLASS_CON, 1, 0, dissect_address },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_protocolInformation },
  { BER_CLASS_CON, 3, 0, dissect_consumers },
  { 0, 0, 0, NULL }
};

int
dissect_x501_SupplierAndConsumers(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SupplierAndConsumers_set, hf_index, ett_x501_SupplierAndConsumers);

  return offset;
}

/*--- PDUs ---*/

static void dissect_DSEType_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x501_DSEType(FALSE, tvb, 0, pinfo, tree, hf_x501_DSEType_PDU);
}
static void dissect_SupplierInformation_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x501_SupplierInformation(FALSE, tvb, 0, pinfo, tree, hf_x501_SupplierInformation_PDU);
}
static void dissect_ConsumerInformation_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x501_ConsumerInformation(FALSE, tvb, 0, pinfo, tree, hf_x501_ConsumerInformation_PDU);
}
static void dissect_SupplierAndConsumers_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x501_SupplierAndConsumers(FALSE, tvb, 0, pinfo, tree, hf_x501_SupplierAndConsumers_PDU);
}


/*--- End of included file: packet-x501-fn.c ---*/


/*--- proto_register_x501 -------------------------------------------*/
void proto_register_x501(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {

/*--- Included file: packet-x501-hfarr.c ---*/

    { &hf_x501_DSEType_PDU,
      { "DSEType", "x501.DSEType",
        FT_BYTES, BASE_HEX, NULL, 0,
        "DSEType", HFILL }},
    { &hf_x501_SupplierInformation_PDU,
      { "SupplierInformation", "x501.SupplierInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupplierInformation", HFILL }},
    { &hf_x501_ConsumerInformation_PDU,
      { "ConsumerInformation", "x501.ConsumerInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "ConsumerInformation", HFILL }},
    { &hf_x501_SupplierAndConsumers_PDU,
      { "SupplierAndConsumers", "x501.SupplierAndConsumers",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupplierAndConsumers", HFILL }},
    { &hf_x501_ae_title,
      { "ae-title", "x501.ae_title",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x501_address,
      { "address", "x501.address",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x501_protocolInformation,
      { "protocolInformation", "x501.protocolInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x501_protocolInformation_item,
      { "Item", "x501.protocolInformation_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x501_agreementID,
      { "agreementID", "x501.agreementID",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x501_supplier_is_master,
      { "supplier-is-master", "x501.supplier_is_master",
        FT_BOOLEAN, 8, NULL, 0,
        "SupplierInformation/supplier-is-master", HFILL }},
    { &hf_x501_non_supplying_master,
      { "non-supplying-master", "x501.non_supplying_master",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupplierInformation/non-supplying-master", HFILL }},
    { &hf_x501_consumers,
      { "consumers", "x501.consumers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SupplierAndConsumers/consumers", HFILL }},
    { &hf_x501_consumers_item,
      { "Item", "x501.consumers_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupplierAndConsumers/consumers/_item", HFILL }},
    { &hf_x501_DSEType_root,
      { "root", "x501.root",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x501_DSEType_glue,
      { "glue", "x501.glue",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x501_DSEType_cp,
      { "cp", "x501.cp",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x501_DSEType_entry,
      { "entry", "x501.entry",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x501_DSEType_alias,
      { "alias", "x501.alias",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x501_DSEType_subr,
      { "subr", "x501.subr",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_x501_DSEType_nssr,
      { "nssr", "x501.nssr",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_x501_DSEType_supr,
      { "supr", "x501.supr",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_x501_DSEType_xr,
      { "xr", "x501.xr",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x501_DSEType_admPoint,
      { "admPoint", "x501.admPoint",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x501_DSEType_subentry,
      { "subentry", "x501.subentry",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x501_DSEType_shadow,
      { "shadow", "x501.shadow",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x501_DSEType_immSupr,
      { "immSupr", "x501.immSupr",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_x501_DSEType_rhob,
      { "rhob", "x501.rhob",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_x501_DSEType_sa,
      { "sa", "x501.sa",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_x501_DSEType_dsSubentry,
      { "dsSubentry", "x501.dsSubentry",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x501_DSEType_familyMember,
      { "familyMember", "x501.familyMember",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},

/*--- End of included file: packet-x501-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_x501,

/*--- Included file: packet-x501-ettarr.c ---*/

    &ett_x501_DSEType,
    &ett_x501_SupplierOrConsumer,
    &ett_x501_SET_OF_ProtocolInformation,
    &ett_x501_SupplierInformation,
    &ett_x501_SupplierAndConsumers,
    &ett_x501_SET_OF_AccessPoint,

/*--- End of included file: packet-x501-ettarr.c ---*/

  };

  /* Register protocol */
  proto_x501 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x501, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_x501 --- */
void proto_reg_handoff_x501(void) {


/*--- Included file: packet-x501-dis-tab.c ---*/

  register_ber_oid_dissector("2.5.12.0", dissect_DSEType_PDU, proto_x501, "id-doa-dseType");
  register_ber_oid_dissector("2.5.12.5", dissect_SupplierInformation_PDU, proto_x501, "id-doa-supplierKnowledge");
  register_ber_oid_dissector("2.5.12.6", dissect_ConsumerInformation_PDU, proto_x501, "id-doa-consumerKnowledge");
  register_ber_oid_dissector("2.5.12.7", dissect_SupplierAndConsumers_PDU, proto_x501, "id-doa-secondaryShadows");


/*--- End of included file: packet-x501-dis-tab.c ---*/


}
