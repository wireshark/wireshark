/* packet-dap.c
 * Routines for X.511 (X.500 Directory Asbtract Service) and X.519 DAP  packet dissection
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

#include "packet-x509if.h"
#include "packet-x509af.h"
#include "packet-x509sat.h"
#include "packet-crmf.h"

#include "packet-dsp.h"
#include "packet-disp.h"
#include "packet-dap.h"
#include <epan/strutil.h>

/* we don't have a separate dissector for X519 - 
   most of DAP is defined in X511 */
#define PNAME  "X.519 Directory Access Protocol"
#define PSNAME "DAP"
#define PFNAME "dap"

static guint global_dap_tcp_port = 102;
static guint tcp_port = 0;
static dissector_handle_t tpkt_handle = NULL;
void prefs_register_dap(void); /* forwad declaration for use in preferences registration */


/* Initialize the protocol and registered fields */
int proto_dap = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;

#include "packet-dap-hf.c"

/* Initialize the subtree pointers */
static gint ett_dap = -1;
#include "packet-dap-ett.c"

#include "packet-dap-fn.c"

/*
* Dissect DAP PDUs inside a ROS PDUs
*/
static void
dissect_dap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int (*dap_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) = NULL;
	char *dap_op_name;

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
		item = proto_tree_add_item(parent_tree, proto_dap, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_dap);
	}
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "DAP");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);

	switch(session->ros_op & ROS_OP_MASK) {
	case (ROS_OP_BIND | ROS_OP_ARGUMENT):	/*  BindInvoke */
	  dap_dissector = dissect_dap_DirectoryBindArgument;
	  dap_op_name = "Bind-Argument";
	  break;
	case (ROS_OP_BIND | ROS_OP_RESULT):	/*  BindResult */
	  dap_dissector = dissect_dap_DirectoryBindResult;
	  dap_op_name = "Bind-Result";
	  break;
	case (ROS_OP_BIND | ROS_OP_ERROR):	/*  BindError */
	  dap_dissector = dissect_dap_DirectoryBindError;
	  dap_op_name = "Bind-Error";
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ARGUMENT):	/*  Invoke Argument */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* read */
	    dap_dissector = dissect_dap_ReadArgument;
	    dap_op_name = "Read-Argument";
	    break;
	  case 2: /* compare */
	    dap_dissector = dissect_dap_CompareArgument;
	    dap_op_name = "Compare-Argument";
	    break;
	  case 3: /* abandon */
	    dap_dissector = dissect_dap_AbandonArgument;
	    dap_op_name = "Abandon-Argument";
	    break;
	  case 4: /* list */
	    dap_dissector = dissect_dap_ListArgument;
	    dap_op_name = "List-Argument";
	    break;
	  case 5: /* search */
	    dap_dissector = dissect_dap_SearchArgument;
	    dap_op_name = "Search-Argument";
	    break;
	  case 6: /* addEntry */
	    dap_dissector = dissect_dap_AddEntryArgument;
	    dap_op_name = "Add-Entry-Argument";
	    break;
	  case 7: /* removeEntry */
	    dap_dissector = dissect_dap_RemoveEntryArgument;
	    dap_op_name = "Remove-Entry-Argument";
	    break;
	  case 8: /* modifyEntry */
	    dap_dissector = dissect_dap_ModifyEntryArgument;
	    dap_op_name = "Modify-Entry-Argument";
	    break;
	  case 9: /* modifyDN */
	    dap_dissector = dissect_dap_ModifyDNArgument;
	    dap_op_name = "Modify-DN-Argument";
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DAP opcode (%d)",
				session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_RESULT):	/*  Return Result */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* read */
	    dap_dissector = dissect_dap_ReadResult;
	    dap_op_name = "Read-Result";
	    break;
	  case 2: /* compare */
	    dap_dissector = dissect_dap_CompareResult;
	    dap_op_name = "Compare-Result";
	    break;
	  case 3: /* abandon */
	    dap_dissector = dissect_dap_AbandonResult;
	    dap_op_name = "Abandon-Result";
	    break;
	  case 4: /* list */
	    dap_dissector = dissect_dap_ListResult;
	    dap_op_name = "List-Result";
	    break;
	  case 5: /* search */
	    dap_dissector = dissect_dap_SearchResult;
	    dap_op_name = "Search-Result";
	    break;
	  case 6: /* addEntry */
	    dap_dissector = dissect_dap_AddEntryResult;
	    dap_op_name = "Add-Entry-Result";
	    break;
	  case 7: /* removeEntry */
	    dap_dissector = dissect_dap_RemoveEntryResult;
	    dap_op_name = "Remove-Entry-Result";
	    break;
	  case 8: /* modifyEntry */
	    dap_dissector = dissect_dap_ModifyEntryResult;
	    dap_op_name = "Modify-Entry-Result";
	    break;
	  case 9: /* modifyDN */
	    dap_dissector = dissect_dap_ModifyDNResult;
	    dap_op_name = "Modify-DN-Result";
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DAP opcode");
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ERROR):	/*  Return Error */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* attributeError */
	    dap_dissector = dissect_dap_AttributeError;
	    dap_op_name = "Attribute-Error";
	    break;
	  case 2: /* nameError */
	    dap_dissector = dissect_dap_NameError;
	    dap_op_name = "Name-Error";
	    break;
	  case 3: /* serviceError */
	    dap_dissector = dissect_dap_ServiceError;
	    dap_op_name = "Service-Error";
	    break;
	  case 4: /* referral */
	    dap_dissector = dissect_dap_Referral;
	    dap_op_name = "Referral";
	    break;
	  case 5: /* abandoned */
	    dap_dissector = dissect_dap_Abandoned;
	    dap_op_name = "Abandoned";
	    break;
	  case 6: /* securityError */
	    dap_dissector = dissect_dap_SecurityError;
	    dap_op_name = "Security-Error";
	    break;
	  case 7: /* abandonFailed */
	    dap_dissector = dissect_dap_AbandonFailedError;
	    dap_op_name = "Abandon-Failed-Error";
	    break;
	  case 8: /* updateError */
	    dap_dissector = dissect_dap_UpdateError;
	    dap_op_name = "Update-Error";
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DAP errcode");
	    break;
	  }
	  break;
	default:
	  proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DAP PDU");
	  return;
	}

	if(dap_dissector) {
	  if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_str(pinfo->cinfo, COL_INFO, dap_op_name);

	  while (tvb_reported_length_remaining(tvb, offset) > 0){
	    old_offset=offset;
	    offset=(*dap_dissector)(FALSE, tvb, offset, pinfo , tree, -1);
	    if(offset == old_offset){
	      proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte DAP PDU");
	      offset = tvb_length(tvb);
	      break;
	    }
	  }
	}
}


/*--- proto_register_dap -------------------------------------------*/
void proto_register_dap(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-dap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_dap,
#include "packet-dap-ettarr.c"
  };
  module_t *dap_module;

  /* Register protocol */
  proto_dap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("dap", dissect_dap, proto_dap);

  /* Register fields and subtrees */
  proto_register_field_array(proto_dap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for DAP, particularly our port */

#ifdef PREFERENCE_GROUPING
  dap_module = prefs_register_protocol_subtree("OSI/X.500", proto_dap, prefs_register_dap);
#else
  dap_module = prefs_register_protocol(proto_dap, prefs_register_dap);
#endif

  prefs_register_uint_preference(dap_module, "tcp.port", "DAP TCP Port",
				 "Set the port for DAP operations (if other"
				 " than the default of 102)",
				 10, &global_dap_tcp_port);

}


/*--- proto_reg_handoff_dap --- */
void proto_reg_handoff_dap(void) {
  dissector_handle_t handle = NULL;

  /* #include "packet-dap-dis-tab.c" */

  /* APPLICATION CONTEXT */

  register_ber_oid_name("2.5.3.1", "id-ac-directory-access");

  /* ABSTRACT SYNTAXES */
    
  /* Register DAP with ROS (with no use of RTSE) */
  if((handle = find_dissector("dap"))) {
    register_ros_oid_dissector_handle("2.5.9.1", handle, 0, "id-as-directory-access", FALSE); 
  }

  /* remember the tpkt handler for change in preferences */
  tpkt_handle = find_dissector("tpkt");

  /* AttributeValueAssertions */
  x509if_register_fmt(hf_dap_equality, "=");
  x509if_register_fmt(hf_dap_greaterOrEqual, ">=");
  x509if_register_fmt(hf_dap_lessOrEqual, "<=");
  x509if_register_fmt(hf_dap_approximateMatch, "=~");
  /* AttributeTypes */
  x509if_register_fmt(hf_dap_present, "= *");


}


void prefs_register_dap(void) {

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port != 102) && tpkt_handle)
    dissector_delete("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_dap_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add("tcp.port", global_dap_tcp_port, tpkt_handle);

}
