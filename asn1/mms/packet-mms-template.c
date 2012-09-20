/* packet-mms_asn1.c
 *
 * Ronnie Sahlberg 2005
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
#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/nstime.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-mms.h"

#define PNAME  "MMS"
#define PSNAME "MMS"
#define PFNAME "mms"

/* Initialize the protocol and registered fields */
static int proto_mms = -1;

#include "packet-mms-hf.c"

/* Initialize the subtree pointers */
static gint ett_mms = -1;
#include "packet-mms-ett.c"

#include "packet-mms-fn.c"

/*
* Dissect MMS PDUs inside a PPDU.
*/
static void
dissect_mms(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_mms, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_mms);
	}
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MMS");
  	col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=dissect_mms_MMSpdu(FALSE, tvb, offset, &asn1_ctx , tree, -1);
		if(offset == old_offset){
			proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte MMS PDU");
			break;
		}
	}
}


/*--- proto_register_mms -------------------------------------------*/
void proto_register_mms(void) {

	/* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-mms-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_mms,
#include "packet-mms-ettarr.c"
  };

  /* Register protocol */
  proto_mms = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("mms", dissect_mms, proto_mms);
  /* Register fields and subtrees */
  proto_register_field_array(proto_mms, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


}


static gboolean
dissect_mms_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	/* must check that this really is an mms packet */
	int offset = 0;
	guint32 length = 0 ;
	guint32 oct;
	gint idx = 0 ;

	gint8 tmp_class;
	gboolean tmp_pc;
	gint32 tmp_tag;

		/* first, check do we have at least 2 bytes (pdu) */
	if (!tvb_bytes_exist(tvb, 0, 2))
		return FALSE;	/* no */

	/* can we recognize MMS PDU ? Return FALSE if  not */
	/*   get MMS PDU type */
	offset = get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);

	/* check MMS type */

	/* Class should be constructed */
	if (tmp_class!=BER_CLASS_CON)
		return FALSE;

	/* see if the tag is a valid MMS PDU */
	match_strval_idx(tmp_tag, mms_MMSpdu_vals, &idx);
	if  (idx == -1) {
	 	return FALSE;  /* no, it isn't an MMS PDU */
	}

	/* check MMS length  */
	oct = tvb_get_guint8(tvb, offset)& 0x7F;
	if (oct==0)
		/* MMS requires length after tag so not MMS if indefinite length*/
		return FALSE;

	offset = get_ber_length(tvb, offset, &length, NULL);
	/* do we have enough bytes? */
	if (!tvb_bytes_exist(tvb, offset, length))
		return FALSE;

	dissect_mms(tvb, pinfo, parent_tree);
	return TRUE;
}

/*--- proto_reg_handoff_mms --- */
void proto_reg_handoff_mms(void) {
	register_ber_oid_dissector("1.0.9506.2.3", dissect_mms, proto_mms,"MMS");
	register_ber_oid_dissector("1.0.9506.2.1", dissect_mms, proto_mms,"mms-abstract-syntax-version1(1)");
	heur_dissector_add("cotp", dissect_mms_heur, proto_mms);
	heur_dissector_add("cotp_is", dissect_mms_heur, proto_mms);
}

