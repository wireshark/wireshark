/* packet-ros_asn1.c
 * Routines for ROS packet dissection
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
#include "packet-acse.h"
#include "packet-ros.h"

#define PNAME  "X.880 OSI Remote Operations Service"
#define PSNAME "ROS"
#define PFNAME "ros"

/* Initialize the protocol and registered fields */
int proto_ros = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;

static proto_tree *top_tree=NULL;
static guint32 opcode;

#include "packet-ros-hf.c"

/* Initialize the subtree pointers */
static gint ett_ros = -1;
#include "packet-ros-ett.c"

#include "packet-ros-fn.c"

static dissector_table_t ros_oid_dissector_table=NULL;
static GHashTable *oid_table=NULL;
static gint ett_ros_unknown = -1;

void
register_ros_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto _U_, const char *name)
{
	dissector_add_string("ros.oid", oid, dissector);
	g_hash_table_insert(oid_table, (gpointer)oid, (gpointer)name);
}

static int
call_ros_oid_callback(const char *oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *next_tvb;

	next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), tvb_reported_length_remaining(tvb, offset));
	if(!dissector_try_string(ros_oid_dissector_table, oid, next_tvb, pinfo, tree)){
		proto_item *item=NULL;
		proto_tree *next_tree=NULL;

		item=proto_tree_add_text(tree, next_tvb, 0, tvb_length_remaining(tvb, offset), "RTSE: Dissector for OID:%s not implemented. Contact Ethereal developers if you want this supported", oid);
		if(item){
			next_tree=proto_item_add_subtree(item, ett_ros_unknown);
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

/*
* Dissect ROS PDUs inside a PPDU.
*/
static void
dissect_ros(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
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
		item = proto_tree_add_item(parent_tree, proto_ros, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_ros);
	}
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ROS");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=dissect_ros_ROS(FALSE, tvb, offset, pinfo , tree, -1);
		if(offset == old_offset){
			proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte ROS PDU");
			offset = tvb_length(tvb);
			break;
		}
	}
}


/*--- proto_register_ros -------------------------------------------*/
void proto_register_ros(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-ros-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_ros,
    &ett_ros_unknown,
#include "packet-ros-ettarr.c"
  };

  /* Register protocol */
  proto_ros = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("ros", dissect_ros, proto_ros);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ros, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ros_oid_dissector_table = register_dissector_table("ros.oid", "ROS OID Dissectors", FT_STRING, BASE_NONE);
  oid_table=g_hash_table_new(g_str_hash, g_str_equal);
}


/*--- proto_reg_handoff_ros --- */
void proto_reg_handoff_ros(void) {
}
