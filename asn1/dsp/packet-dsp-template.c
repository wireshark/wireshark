/* packet-dsp.c
 * Routines for X.518 (X.500 Distributed Operations)  packet dissection
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

#include "packet-dap.h"
#include "packet-dsp.h"


#define PNAME  "X.519 Directory System Protocol"
#define PSNAME "DSP"
#define PFNAME "dsp"

static guint global_dsp_tcp_port = 102;
static guint tcp_port = 0;
static dissector_handle_t tpkt_handle = NULL;
void prefs_register_dsp(void); /* forwad declaration for use in preferences registration */


/* Initialize the protocol and registered fields */
int proto_dsp = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;

#include "packet-dsp-hf.c"

/* Initialize the subtree pointers */
static gint ett_dsp = -1;
#include "packet-dsp-ett.c"

#include "packet-dsp-fn.c"

/*
* Dissect X518 PDUs inside a ROS PDUs
*/
static void
dissect_dsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int (*dsp_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) = NULL;
	char *dsp_op_name;

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
		item = proto_tree_add_item(parent_tree, proto_dsp, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_dsp);
	}
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "DAP");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);

	switch(session->ros_op & ROS_OP_MASK) {
	case (ROS_OP_BIND | ROS_OP_ARGUMENT):	/*  BindInvoke */
	  dsp_dissector = dissect_dsp_DSASystemBindArgument;
	  dsp_op_name = "System-Bind-Argument";
	  break;
	case (ROS_OP_BIND | ROS_OP_RESULT):	/*  BindResult */
	  dsp_dissector = dissect_dsp_DSASystemBindResult;
	  dsp_op_name = "System-Bind-Result";
	  break;
	case (ROS_OP_BIND | ROS_OP_ERROR):	/*  BindError */
	  dsp_dissector = dissect_dsp_DSASystemBindError;
	  dsp_op_name = "System-Bind-Error";
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ARGUMENT):	/*  Invoke Argument */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* read */
	    dsp_dissector = dissect_dsp_ChainedReadArgument;
	    dsp_op_name = "Chained-Read-Argument";
	    break;
	  case 2: /* compare */
	    dsp_dissector = dissect_dsp_ChainedCompareArgument;
	    dsp_op_name = "Chained-Compare-Argument";
	    break;
	  case 3: /* abandon */
	    dsp_dissector = dissect_dsp_ChainedAbandonArgument;
	    dsp_op_name = "Chained-Abandon-Argument";
	    break;
	  case 4: /* list */
	    dsp_dissector = dissect_dsp_ChainedListArgument;
	    dsp_op_name = "Chained-List-Argument";
	    break;
	  case 5: /* search */
	    dsp_dissector = dissect_dsp_ChainedSearchArgument;
	    dsp_op_name = "Chained-Search-Argument";
	    break;
	  case 6: /* addEntry */
	    dsp_dissector = dissect_dsp_ChainedAddEntryArgument;
	    dsp_op_name = "Chained-Add-Entry-Argument";
	    break;
	  case 7: /* removeEntry */
	    dsp_dissector = dissect_dsp_ChainedRemoveEntryArgument;
	    dsp_op_name = "Chained-Remove-Entry-Argument";
	    break;
	  case 8: /* modifyEntry */
	    dsp_dissector = dissect_dsp_ChainedModifyEntryArgument;
	    dsp_op_name = "ChainedModify-Entry-Argument";
	    break;
	  case 9: /* modifyDN */
	    dsp_dissector = dissect_dsp_ChainedModifyDNArgument;
	    dsp_op_name = "ChainedModify-DN-Argument";
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DSP opcode (%d)",
				session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_RESULT):	/*  Return Result */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* read */
	    dsp_dissector = dissect_dsp_ChainedReadResult;
	    dsp_op_name = "Chained-Read-Result";
	    break;
	  case 2: /* compare */
	    dsp_dissector = dissect_dsp_ChainedCompareResult;
	    dsp_op_name = "Chained-Compare-Result";
	    break;
	  case 3: /* abandon */
	    dsp_dissector = dissect_dsp_ChainedAbandonResult;
	    dsp_op_name = "Chained-Abandon-Result";
	    break;
	  case 4: /* list */
	    dsp_dissector = dissect_dsp_ChainedListResult;
	    dsp_op_name = "Chained-List-Result";
	    break;
	  case 5: /* search */
	    dsp_dissector = dissect_dsp_ChainedSearchResult;
	    dsp_op_name = "Chained-Search-Result";
	    break;
	  case 6: /* addEntry */
	    dsp_dissector = dissect_dsp_ChainedAddEntryResult;
	    dsp_op_name = "Chained-Add-Entry-Result";
	    break;
	  case 7: /* removeEntry */
	    dsp_dissector = dissect_dsp_ChainedRemoveEntryResult;
	    dsp_op_name = "Chained-Remove-Entry-Result";
	    break;
	  case 8: /* modifyEntry */
	    dsp_dissector = dissect_dsp_ChainedModifyEntryResult;
	    dsp_op_name = "Chained-Modify-Entry-Result";
	    break;
	  case 9: /* modifyDN */
	    dsp_dissector = dissect_dsp_ChainedModifyDNResult;
	    dsp_op_name = "ChainedModify-DN-Result";
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DSP opcode");
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ERROR):	/*  Return Error */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 1: /* attributeError */
	    dsp_dissector = dissect_dap_AttributeError;
	    dsp_op_name = "Attribute-Error";
	    break;
	  case 2: /* nameError */
	    dsp_dissector = dissect_dap_NameError;
	    dsp_op_name = "Name-Error";
	    break;
	  case 3: /* serviceError */
	    dsp_dissector = dissect_dap_ServiceError;
	    dsp_op_name = "Service-Error";
	    break;
	  case 4: /* referral */
	    dsp_dissector = dissect_dap_Referral;
	    dsp_op_name = "Referral";
	    break;
	  case 5: /* abandoned */
	    dsp_dissector = dissect_dap_Abandoned;
	    dsp_op_name = "Abandoned";
	    break;
	  case 6: /* securityError */
	    dsp_dissector = dissect_dap_SecurityError;
	    dsp_op_name = "Security-Error";
	    break;
	  case 7: /* abandonFailed */
	    dsp_dissector = dissect_dap_AbandonFailedError;
	    dsp_op_name = "Abandon-Failed-Error";
	    break;
	  case 8: /* updateError */
	    dsp_dissector = dissect_dap_UpdateError;
	    dsp_op_name = "Update-Error";
	    break;
	  case 9: /* DSAReferral */
	    dsp_dissector = dissect_dsp_DSAReferral;
	    dsp_op_name = "DSA-Referral";
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DSP errcode");
	    break;
	  }
	  break;
	default:
	  proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DSP PDU");
	  return;
	}

	if(dsp_dissector) {
	  if (check_col(pinfo->cinfo, COL_INFO))
	    col_add_str(pinfo->cinfo, COL_INFO, dsp_op_name);

	  while (tvb_reported_length_remaining(tvb, offset) > 0){
	    old_offset=offset;
	    offset=(*dsp_dissector)(FALSE, tvb, offset, pinfo , tree, -1);
	    if(offset == old_offset){
	      proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte DSP PDU");
	      offset = tvb_length(tvb);
	      break;
	    }
	  }
	}
}


/*--- proto_register_dsp -------------------------------------------*/
void proto_register_dsp(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-dsp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_dsp,
#include "packet-dsp-ettarr.c"
  };
  module_t *dsp_module;

  /* Register protocol */
  proto_dsp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* initially disable the protocol */
  proto_set_decoding(proto_dsp, FALSE);

  register_dissector("dsp", dissect_dsp, proto_dsp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_dsp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for DSP, particularly our port */

#ifdef PREFERENCE_GROUPING
  dsp_module = prefs_register_protocol_subtree("OSI/X.500", proto_dsp, prefs_register_dsp);
#else
  dsp_module = prefs_register_protocol(proto_dsp, prefs_register_dsp);
#endif

  prefs_register_uint_preference(dsp_module, "tcp.port", "DSP TCP Port",
				 "Set the port for DSP operations (if other"
				 " than the default of 102)",
				 10, &global_dsp_tcp_port);


}


/*--- proto_reg_handoff_dsp --- */
void proto_reg_handoff_dsp(void) {
  dissector_handle_t handle = NULL;

#include "packet-dsp-dis-tab.c" 

  /* APPLICATION CONTEXT */

  register_ber_oid_name("2.5.3.2", "id-ac-directory-system");

  /* ABSTRACT SYNTAXES */
    
  /* Register DSP with ROS (with no use of RTSE) */
  if((handle = find_dissector("dsp"))) {
    register_ros_oid_dissector_handle("2.5.9.2", handle, 0, "id-as-directory-system", FALSE); 
  }


}

void prefs_register_dsp(void) {

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port != 102) && tpkt_handle)
    dissector_delete("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_dsp_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add("tcp.port", global_dsp_tcp_port, tpkt_handle);

}
