/* packet-ftam_asn1.c
 * Routine to dissect OSI ISO 8571 FTAM Protocol packets
 * based on the ASN.1 specification from http://www.itu.int/ITU-T/asn1/database/iso/8571-4/1988/
 *
 * also based on original handwritten dissector by
 * Yuriy Sidelnikov <YSidelnikov@hotmail.com>
 *
 * Anders Broman and Ronnie Sahlberg 2005 - 2006
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

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ftam.h"

#define PNAME  "ISO 8571 FTAM"
#define PSNAME "FTAM"
#define PFNAME "ftam"

void proto_register_ftam(void);
void proto_reg_handoff_ftam(void);

/* Initialize the protocol and registered fields */
static int proto_ftam = -1;

/* Declare the function to avoid a compiler warning */
static int dissect_ftam_OR_Set(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_);

static int hf_ftam_unstructured_text = -1;              /* ISO FTAM unstructured text */
static int hf_ftam_unstructured_binary = -1;            /* ISO FTAM unstructured binary */
#include "packet-ftam-hf.c"

/* Initialize the subtree pointers */
static gint ett_ftam = -1;
#include "packet-ftam-ett.c"

static expert_field ei_ftam_zero_pdu = EI_INIT;

#include "packet-ftam-fn.c"

/*
* Dissect FTAM unstructured text
*/
static int
dissect_ftam_unstructured_text(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, void* data _U_)
{
	proto_tree_add_item (parent_tree, hf_ftam_unstructured_text, tvb, 0, tvb_reported_length_remaining(tvb, 0), ENC_ASCII|ENC_NA);
	return tvb_captured_length(tvb);
}

/*
* Dissect FTAM unstructured binary
*/
static int
dissect_ftam_unstructured_binary(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, void* data _U_)
{
	proto_tree_add_item (parent_tree, hf_ftam_unstructured_binary, tvb, 0, tvb_reported_length_remaining(tvb, 0), ENC_NA);
	return tvb_captured_length(tvb);
}

/*
* Dissect FTAM PDUs inside a PPDU.
*/
static int
dissect_ftam(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_ftam, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_ftam);
	}
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "FTAM");
  	col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=dissect_ftam_PDU(FALSE, tvb, offset, &asn1_ctx, tree, -1);
		if(offset == old_offset){
			proto_tree_add_expert(tree, pinfo, &ei_ftam_zero_pdu, tvb, offset, -1);
			break;
		}
	}
	return tvb_captured_length(tvb);
}


/*--- proto_register_ftam -------------------------------------------*/
void proto_register_ftam(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
     { &hf_ftam_unstructured_text,
       { "ISO FTAM unstructured text", "ftam.unstructured_text", FT_STRING,
          BASE_NONE, NULL, 0x0, NULL, HFILL } },
     { &hf_ftam_unstructured_binary,
       { "ISO FTAM unstructured binary", "ftam.unstructured_binary", FT_BYTES,
          BASE_NONE, NULL, 0x0, NULL, HFILL } },
#include "packet-ftam-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_ftam,
#include "packet-ftam-ettarr.c"
  };
  static ei_register_info ei[] = {
    { &ei_ftam_zero_pdu, { "ftam.zero_pdu", PI_PROTOCOL, PI_ERROR, "Internal error, zero-byte FTAM PDU", EXPFILL }},
  };

  expert_module_t* expert_ftam;

  /* Register protocol */
  proto_ftam = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("ftam", dissect_ftam, proto_ftam);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ftam, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_ftam = expert_register_protocol(proto_ftam);
  expert_register_field_array(expert_ftam, ei, array_length(ei));

}


/*--- proto_reg_handoff_ftam --- */
void proto_reg_handoff_ftam(void) {
	register_ber_oid_dissector("1.0.8571.1.1", dissect_ftam, proto_ftam,"iso-ftam(1)");
	register_ber_oid_dissector("1.0.8571.2.1", dissect_ftam, proto_ftam,"ftam-pci(1)");
	register_ber_oid_dissector("1.3.14.5.2.2", dissect_ftam, proto_ftam,"NIST file directory entry abstract syntax");

	/* Unstructured text file document type FTAM-1 */
	register_ber_oid_dissector("1.0.8571.5.1", dissect_ftam_unstructured_text, proto_ftam,"ISO FTAM unstructured text");
	oid_add_from_string("ISO FTAM sequential text","1.0.8571.5.2");
	oid_add_from_string("FTAM unstructured text abstract syntax","1.0.8571.2.3");
	oid_add_from_string("FTAM simple-hierarchy","1.0.8571.2.5");
	oid_add_from_string("FTAM hierarchical file model","1.0.8571.3.1");
	oid_add_from_string("FTAM unstructured constraint set","1.0.8571.4.1");

	/* Unstructured binary file document type FTAM-3 */
	register_ber_oid_dissector("1.0.8571.5.3", dissect_ftam_unstructured_binary, proto_ftam,"ISO FTAM unstructured binary");
	oid_add_from_string("FTAM unstructured binary abstract syntax","1.0.8571.2.4");

	/* Filedirectory file document type NBS-9 */
	oid_add_from_string("NBS-9 FTAM file directory file","1.3.14.5.5.9");

	/* Filedirectory file document type NBS-9 (WITH OLD NIST OIDs)*/
	oid_add_from_string("NBS-9-OLD FTAM file directory file","1.3.9999.1.5.9");
	oid_add_from_string("NIST file directory entry abstract syntax","1.3.9999.1.2.2");
}
