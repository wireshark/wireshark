/* packet-p22.c
 * Routines for X.420 (X.400 Message Transfer)  packet dissection
 * Graeme Lunt 2005
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ros.h"

#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-ftam.h"
#include "packet-p1.h"
#include "packet-p7.h"

#include "packet-p22.h"

#define PNAME  "X.420 Information Object"
#define PSNAME "P22"
#define PFNAME "p22"

/* Initialize the protocol and registered fields */
static int proto_p22 = -1;

static const char *object_identifier_id; /* content type identifier */

static const value_string charsetreg_vals [] = {
  { 1, "C0: (ISO/IEC 6429)"},
  { 6, "G0: ASCII (ISO/IEC 646)"},
  { 77, "C1: (ISO/IEC 6429)"},
  { 100, "Gn: Latin Alphabet No.1, Western European Supplementary Set (GR area of ISO-8859-1)"},
  { 101, "Gn: Latin Alphabet No.2, Central EuropeanSupplementary Set (GR area of ISO-8859-2)"},
  { 104, "C0: (ISO/IEC 4873)"},
  { 105, "C1: (ISO/IEC 4873)"},
  { 106, "C0: Teletex (CCITT T.61)"},
  { 107, "C1: Teletex (CCITT T.61)"},
  { 109, "Gn: Latin Alphabet No.3, Southern European Supplementary Set (GR area of ISO-8859-3)"},
  { 110, "Gn: Latin Alphabet No.4, Baltic Supplementary Set (GR area of ISO-8859-4)"},
  { 126, "Gn: Greek Supplementary Set (GR area of ISO-8859-7)"},
  { 127, "Gn: Arabic Supplementary Set (GR area of ISO-8859-6)"},
  { 138, "Gn: Hebrew Supplementary Set (GR area of ISO-8859-8)"},
  { 144, "Gn: Cyrillic Supplementary Set (GR area of ISO-8859-5)"},
  { 148, "Gn: Latin Alphabet No.5, Cyrillic Supplementary Set (GR area of ISO-8859-9)"},
  { 154, "Gn: Supplementary Set for Latin Alphabets No.1 or No.5, and No.2"},
  { 157, "Gn: Latin Alphabet No.6, Arabic Supplementary Set (GR area of ISO-8859-10)"},
  { 158, "Gn: Supplementary Set for Sami (Lappish) to complement Latin Alphabet No.6 (from Annex A  of ISO-8859-10)"},
  { 166, "Gn: Thai Supplementary Set (GR area of ISO-8859-11)"},
  { 179, "Gn: Latin Alphabet No.7, Baltic Rim Supplementary Set (GR area of ISO-8859-13)"},
  { 182, "Gn: Welsh Variant of Latin Alphabet No.1, Supplementary Set (GR area of ISO-8859-1)"},
  { 197, "Gn: Supplementary Set for Sami to complement Latin Alphabet No.6 (from Annex A  of ISO-8859-10)"},
  { 199, "Gn: Latin Alphabet No.8, Celtic Supplementary Set (GR area of ISO-8859-14)"},
  { 203, "Gn: Latin Alphabet No.9, European Rim Supplementary Set (GR area of ISO-8859-15)"},
  { 0, NULL}
};

#include "packet-p22-val.h"

#include "packet-p22-hf.c"

/* Initialize the subtree pointers */
static gint ett_p22 = -1;
#include "packet-p22-ett.c"

#include "packet-p22-fn.c"

/*
* Dissect P22 PDUs inside a PPDU.
*/
static void
dissect_p22(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_p22, tvb, 0, -1, ENC_BIG_ENDIAN);
		tree = proto_item_add_subtree(item, ett_p22);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "P22");
	col_set_str(pinfo->cinfo, COL_INFO, "InterPersonal");

	dissect_p22_InformationObject(TRUE, tvb, offset, &asn1_ctx , tree, -1);
}


/*--- proto_register_p22 -------------------------------------------*/
void proto_register_p22(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-p22-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_p22,
#include "packet-p22-ettarr.c"
  };

  /* Register protocol */
  proto_p22 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("p22", dissect_p22, proto_p22);
  /* Register fields and subtrees */
  proto_register_field_array(proto_p22, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_p22 --- */
void proto_reg_handoff_p22(void) {

#include "packet-p22-dis-tab.c" 

  register_ber_oid_dissector("2.6.1.10.0", dissect_p22, proto_p22, "InterPersonal Message (1984)");
  register_ber_oid_dissector("2.6.1.10.1", dissect_p22, proto_p22, "InterPersonal Message (1988)");


}
