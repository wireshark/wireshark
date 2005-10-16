/* packet-rtse_asn1.c
 * Routines for RTSE packet dissection
 * Graeme Lunt 2005
 *
 * $Id$
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
#include "packet-pres.h"
#include "packet-acse.h"
#include "packet-ros.h"
#include "packet-rtse.h"

#define PNAME  "X.228 OSI Reliable Transfer Service"
#define PSNAME "RTSE"
#define PFNAME "rtse"

/* Initialize the protocol and registered fields */
int proto_rtse = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;

static char object_identifier_id[MAX_OID_STR_LEN];
/* indirect_reference, used to pick up the signalling so we know what
   kind of data is transferred in SES_DATA_TRANSFER_PDUs */
static guint32 indir_ref=0;
static guint32 app_proto=0;

static proto_tree *top_tree=NULL;

int dissect_rtse_EXTERNAL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_);


#include "packet-rtse-hf.c"

/* Initialize the subtree pointers */
static gint ett_rtse = -1;
#include "packet-rtse-ett.c"


static dissector_table_t rtse_oid_dissector_table=NULL;
static GHashTable *oid_table=NULL;
static gint ett_rtse_unknown = -1;

void
register_rtse_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto _U_, const char *name)
{
	dissector_add_string("rtse.oid", oid, dissector);
	g_hash_table_insert(oid_table, (gpointer)oid, (gpointer)name);
}

static int
call_rtse_oid_callback(const char *oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *next_tvb;

	next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), tvb_reported_length_remaining(tvb, offset));
	if(!dissector_try_string(rtse_oid_dissector_table, oid, next_tvb, pinfo, tree)){
		proto_item *item=NULL;
		proto_tree *next_tree=NULL;

		item=proto_tree_add_text(tree, next_tvb, 0, tvb_length_remaining(tvb, offset), "RTSE: Dissector for OID:%s not implemented. Contact Ethereal developers if you want this supported", oid);
		if(item){
			next_tree=proto_item_add_subtree(item, ett_rtse_unknown);
		}
		dissect_unknown_ber(pinfo, next_tvb, offset, next_tree);
	}

	/*XXX until we change the #.REGISTER signature for _PDU()s 
	 * into new_dissector_t   we have to do this kludge with
	 * manually step past the content in the ANY type.
	 */
	offset+=tvb_length_remaining(tvb, offset);

	return offset;
}

#include "packet-rtse-fn.c"

/*
* Dissect RTSE PDUs inside a PPDU.
*/
static void
dissect_rtse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	/* save parent_tree so subdissectors can create new top nodes */
	top_tree=parent_tree;

	/* do we have application context from the acse dissector?  */
	if( !pinfo->private_data ){
		if(parent_tree){
			proto_tree_add_text(parent_tree, tvb, offset, -1,
				"Internal error:can't get application context from ACSE dissector.");
		} 
		return  ;
	} else {
		session  = ( (struct SESSION_DATA_STRUCTURE*)(pinfo->private_data) );

	}

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_rtse, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_rtse);
	}
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTSE");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=dissect_rtse_RTSE_apdus(FALSE, tvb, offset, pinfo , tree, -1);
		if(offset == old_offset){
			proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte RTSE PDU");
			offset = tvb_length(tvb);
			break;
		}
	}

	top_tree = NULL;
}


/*--- proto_register_rtse -------------------------------------------*/
void proto_register_rtse(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-rtse-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_rtse,
    &ett_rtse_unknown,
#include "packet-rtse-ettarr.c"
  };

  /* Register protocol */
  proto_rtse = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("rtse", dissect_rtse, proto_rtse);
  /* Register fields and subtrees */
  proto_register_field_array(proto_rtse, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  rtse_oid_dissector_table = register_dissector_table("rtse.oid", "RTSE OID Dissectors", FT_STRING, BASE_NONE);
  oid_table=g_hash_table_new(g_str_hash, g_str_equal);

}


/*--- proto_reg_handoff_rtse --- */
void proto_reg_handoff_rtse(void) {
}
