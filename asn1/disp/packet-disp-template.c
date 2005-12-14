/* packet-disp.c
 * Routines for X.525 (X.500 Directory Shadow Asbtract Service) and X.519 DISP packet dissection
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
#include <epan/prefs.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ros.h"
#include "packet-rtse.h"

#include "packet-x509if.h"
#include "packet-x509af.h"
#include "packet-x509sat.h"
#include "packet-crmf.h"

#include "packet-dop.h"
#include "packet-dap.h"
#include "packet-dsp.h"
#include "packet-disp.h"
#include "packet-acse.h"


/* we don't have a separate dissector for X519 - 
   and most of DISP is defined in X525 */
#define PNAME  "X.519 Directory Information Shadowing Protocol"
#define PSNAME "DISP"
#define PFNAME "disp"

static guint global_disp_tcp_port = 102;
static guint tcp_port = 0;
static dissector_handle_t tpkt_handle = NULL;
void prefs_register_disp(void); /* forwad declaration for use in preferences registration */


/* Initialize the protocol and registered fields */
int proto_disp = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;

#include "packet-disp-hf.c"

/* Initialize the subtree pointers */
static gint ett_disp = -1;
#include "packet-disp-ett.c"

#include "packet-disp-fn.c"

/*
* Dissect DISP PDUs inside a ROS PDUs
*/
static void
dissect_disp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int (*disp_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) = NULL;
	char *disp_op_name;

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
		item = proto_tree_add_item(parent_tree, proto_disp, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_disp);
	}
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "DISP");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);

	switch(session->ros_op & ROS_OP_MASK) {
	case (ROS_OP_BIND | ROS_OP_ARGUMENT):	/*  BindInvoke */
	  disp_dissector = dissect_disp_DSAShadowBindArgument;
	  disp_op_name = "Shadow-Bind-Argument";
	  break;
	case (ROS_OP_BIND | ROS_OP_RESULT):	/*  BindResult */
	  disp_dissector = dissect_disp_DSAShadowBindResult;
	  disp_op_name = "Shadow-Bind-Result";
	  break;
	case (ROS_OP_BIND | ROS_OP_ERROR):	/*  BindError */
	  disp_dissector = dissect_disp_DSAShadowBindError;
	  disp_op_name = "Shadow-Bind-Error";
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ARGUMENT):	/*  Invoke Argument */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* requestShadowUpdate */
	    disp_dissector = dissect_disp_RequestShadowUpdateArgument;
	    disp_op_name = "Request-Shadow-Update-Argument";
	    break;
	  case 2: /* updateShadow*/
	    disp_dissector = dissect_disp_UpdateShadowArgument;
	    disp_op_name = "Update-Shadow-Argument";
	    break;
	  case 3: /* coordinateShadowUpdate */
	    disp_dissector = dissect_disp_CoordinateShadowUpdateArgument;
	    disp_op_name = "Coordinate-Shadow-Update-Argument";
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DISP opcode (%d)",
				session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_RESULT):	/*  Return Result */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* requestShadowUpdate */
	    disp_dissector = dissect_disp_RequestShadowUpdateResult;
	    disp_op_name = "Request-Shadow-Result";
	    break;
	  case 2: /* updateShadow */
	    disp_dissector = dissect_disp_UpdateShadowResult;
	    disp_op_name = "Update-Shadow-Result";
	    break;
	  case 3: /* coordinateShadowUpdate */
	    disp_dissector = dissect_disp_CoordinateShadowUpdateResult;
	    disp_op_name = "Coordinate-Shadow-Update-Result";
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DISP opcode");
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ERROR):	/*  Return Error */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* shadowError */
	    disp_dissector = dissect_disp_ShadowError;
	    disp_op_name = "Shadow-Error";
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DISP errcode");
	    break;
	  }
	  break;
	default:
	  proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DISP PDU");
	  return;
	}

	if(disp_dissector) {
	  if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_str(pinfo->cinfo, COL_INFO, disp_op_name);

	  while (tvb_reported_length_remaining(tvb, offset) > 0){
	    old_offset=offset;
	    offset=(*disp_dissector)(FALSE, tvb, offset, pinfo , tree, -1);
	    if(offset == old_offset){
	      proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte DISP PDU");
	      offset = tvb_length(tvb);
	      break;
	    }
	  }
	}
}


/*--- proto_register_disp -------------------------------------------*/
void proto_register_disp(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-disp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_disp,
#include "packet-disp-ettarr.c"
  };
  module_t *disp_module;

  /* Register protocol */
  proto_disp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("disp", dissect_disp, proto_disp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_disp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for DISP, particularly our port */

#ifdef PREFERENCE_GROUPING
  disp_module = prefs_register_protocol_subtree("OSI/X.500", proto_disp, prefs_register_disp);
#else
  disp_module = prefs_register_protocol(proto_disp, prefs_register_disp);
#endif

  prefs_register_uint_preference(disp_module, "tcp.port", "DISP TCP Port",
				 "Set the port for DISP operations (if other"
				 " than the default of 102)",
				 10, &global_disp_tcp_port);

}


/*--- proto_reg_handoff_disp --- */
void proto_reg_handoff_disp(void) {
  dissector_handle_t handle = NULL;

  #include "packet-disp-dis-tab.c"

  /* APPLICATION CONTEXT */

  register_ber_oid_name("2.5.3.4", "id-ac-shadow-consumer-initiated");
  register_ber_oid_name("2.5.3.5", "id-ac-shadow-supplier-initiated");
  register_ber_oid_name("2.5.3.6", "id-ac-reliable-shadow-consumer-initiated");
  register_ber_oid_name("2.5.3.7", "id-ac-reliable-shadow-supplier-initiated");

  /* ABSTRACT SYNTAXES */

  if((handle = find_dissector("disp"))) {

    register_ros_oid_dissector_handle("2.5.9.3", handle, 0, "id-as-directory-shadow", FALSE); 

    register_rtse_oid_dissector_handle("2.5.9.5", handle, 0, "id-as-directory-reliable-shadow", FALSE); 
    register_rtse_oid_dissector_handle("2.5.9.6", handle, 0, "id-as-directory-reliable-binding", FALSE); 
  } 

  /* OPERATIONAL BINDING */
  register_ber_oid_name("2.5.1.0.5.1", "id-op-binding-shadow");

  tpkt_handle = find_dissector("tpkt");

  /* DNs */
  x509if_register_fmt(hf_disp_contextPrefix, "cp=");

}


void prefs_register_disp(void) {

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port != 102) && tpkt_handle)
    dissector_delete("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_disp_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add("tcp.port", global_disp_tcp_port, tpkt_handle);

}
