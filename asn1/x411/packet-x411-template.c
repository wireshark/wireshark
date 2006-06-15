/* packet-x411.c
 * Routines for X.411 (X.400 Message Transfer)  packet dissection
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
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ros.h"
#include "packet-rtse.h"

#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"

#include "packet-x411.h"
#include <epan/emem.h>
#include <epan/strutil.h>

#define PNAME  "X.411 Message Transfer Service"
#define PSNAME "X411"
#define PFNAME "x411"

/* Initialize the protocol and registered fields */
int proto_x411 = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;
static int extension_id = -1; /* integer extension id */
static const char *object_identifier_id; /* extensions identifier */
static const char *content_type_id; /* content type identifier */

#define MAX_ORA_STR_LEN     256
static char *oraddress = NULL;
static gboolean doing_address=FALSE;
static proto_item *address_item;

static proto_tree *top_tree=NULL;

static int
call_x411_oid_callback(char *base_oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

#include "packet-x411-hf.c"

/* Initialize the subtree pointers */
static gint ett_x411 = -1;
#include "packet-x411-ett.c"

#include "packet-x411-fn.c"

static int
call_x411_oid_callback(char *base_oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
  const char *name = NULL;
  char extension_oid[MAX_OID_STR_LEN];

  sprintf(extension_oid, "%s.%d", base_oid, extension_id);	

  name = get_ber_oid_name(extension_oid);
  proto_item_append_text(tree, " (%s)", name ? name : extension_oid); 

  return call_ber_oid_callback(extension_oid, tvb, offset, pinfo, tree);

}


/*
 * Dissect X411 MTS APDU
 */
int 
dissect_x411_mts_apdu (tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	/* save parent_tree so subdissectors can create new top nodes */
	top_tree=parent_tree;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_x411, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_x411);
	}

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "P1");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_set_str(pinfo->cinfo, COL_INFO, "Transfer");

	return dissect_x411_MTS_APDU (FALSE, tvb, 0, pinfo, tree, hf_x411_MTS_APDU_PDU);
}

/*
* Dissect X411 PDUs inside a PPDU.
*/
static void
dissect_x411(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int (*x411_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) = NULL;
	char *x411_op_name;
	int hf_x411_index;

	/* save parent_tree so subdissectors can create new top nodes */
	top_tree=parent_tree;

	/* do we have operation information from the ROS dissector?  */
	if( !pinfo->private_data ){
		if(parent_tree){
			proto_tree_add_text(parent_tree, tvb, offset, -1,
				"Internal error: can't get operation information from ROS dissector.");
		} 
		return  ;
	} else {
		session  = ( (struct SESSION_DATA_STRUCTURE*)(pinfo->private_data) );
	}

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_x411, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_x411);
	}
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "P1");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);

	switch(session->ros_op & ROS_OP_MASK) {
	case (ROS_OP_BIND | ROS_OP_ARGUMENT):	/*  BindInvoke */
	  x411_dissector = dissect_x411_MTABindArgument;
	  x411_op_name = "Bind-Argument";
	  hf_x411_index = hf_x411_MTABindArgument_PDU;
	  break;
	case (ROS_OP_BIND | ROS_OP_RESULT):	/*  BindResult */
	  x411_dissector = dissect_x411_MTABindResult;
	  x411_op_name = "Bind-Result";
	  hf_x411_index = hf_x411_MTABindResult_PDU;
	  break;
	case (ROS_OP_BIND | ROS_OP_ERROR):	/*  BindError */
	  x411_dissector = dissect_x411_MTABindError;
	  x411_op_name = "Bind-Error";
	  hf_x411_index = hf_x411_MTABindError_PDU;
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ARGUMENT):	/*  Invoke Argument */
	  x411_dissector = dissect_x411_MTS_APDU;
	  x411_op_name = "Transfer";
	  hf_x411_index = hf_x411_MTS_APDU_PDU;
	  break;
	default:
	  proto_tree_add_text(tree, tvb, offset, -1,"Unsupported X411 PDU");
	  return;
	}

	if (check_col(pinfo->cinfo, COL_INFO))
	  col_add_str(pinfo->cinfo, COL_INFO, x411_op_name);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=(*x411_dissector)(FALSE, tvb, offset, pinfo , tree, hf_x411_index);
		if(offset == old_offset){
			proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte X411 PDU");
			offset = tvb_length(tvb);
			break;
		}
	}
}


/*--- proto_register_x411 -------------------------------------------*/
void proto_register_x411(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-x411-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_x411,
#include "packet-x411-ettarr.c"
  };

  /* Register protocol */
  proto_x411 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("x411", dissect_x411, proto_x411);
  /* Register fields and subtrees */
  proto_register_field_array(proto_x411, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_x411 --- */
void proto_reg_handoff_x411(void) {
  dissector_handle_t handle = NULL;

#include "packet-x411-dis-tab.c"

  /* APPLICATION CONTEXT */

  register_ber_oid_name("2.6.0.1.6", "id-ac-mts-transfer");

  /* ABSTRACT SYNTAXES */

  if((handle = find_dissector("x411")) != NULL) {
    register_rtse_oid_dissector_handle("2.6.0.2.12", handle, 0, "id-as-mta-rtse", TRUE); 
    register_rtse_oid_dissector_handle("2.6.0.2.7", handle, 0, "id-as-mtse", FALSE);

    register_rtse_oid_dissector_handle("applicationProtocol.1", handle, 0, "mts-transfer-protocol-1984", FALSE);
    register_rtse_oid_dissector_handle("applicationProtocol.12", handle, 0, "mta-transfer-protocol", FALSE);
  }


}
