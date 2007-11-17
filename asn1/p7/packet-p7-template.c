/* packet-p7.c
 * Routines for X.413 (P7) packet dissection
 * Graeme Lunt 2007
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
#include <epan/oids.h>
#include <epan/asn1.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ros.h"

#include "packet-x411.h"
#include <epan/strutil.h>

#define PNAME  "X.413 Message Store Service"
#define PSNAME "P7"
#define PFNAME "p7"

static guint global_p7_tcp_port = 102;
static guint tcp_port = 0;
static dissector_handle_t tpkt_handle = NULL;
static const char *object_identifier_id = NULL; /* attribute identifier */
static int seqno = 0;

void prefs_register_p7(void); /* forwad declaration for use in preferences registration */


/* Initialize the protocol and registered fields */
int proto_p7 = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;

#include "packet-p7-hf.c"

/* Initialize the subtree pointers */
static gint ett_p7 = -1;
#include "packet-p7-ett.c"

#include "packet-p7-fn.c"

/*
* Dissect P7 PDUs inside a ROS PDUs
*/
static void
dissect_p7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int (*p7_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) = NULL;
	char *p7_op_name;
	int hf_p7_index = -1;
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

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
		item = proto_tree_add_item(parent_tree, proto_p7, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_p7);
	}
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "P7");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);

	switch(session->ros_op & ROS_OP_MASK) {
	case (ROS_OP_BIND | ROS_OP_ARGUMENT):	/*  BindInvoke */
	  p7_dissector = dissect_p7_MSBindArgument;
	  p7_op_name = "MS-Bind-Argument";
	  hf_p7_index = hf_p7_MSBindArgument_PDU;
	  break;
	case (ROS_OP_BIND | ROS_OP_RESULT):	/*  BindResult */
	  p7_dissector = dissect_p7_MSBindResult;
	  p7_op_name = "MS-Bind-Result";
	  hf_p7_index = hf_p7_MSBindResult_PDU;
	  break;
	case (ROS_OP_BIND | ROS_OP_ERROR):	/*  BindError */
	  p7_dissector = dissect_p7_MSBindError;
	  p7_op_name = "MS-Bind-Error";
	  hf_p7_index = hf_p7_MSBindError_PDU;
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ARGUMENT):	/*  Invoke Argument */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 3: /* msMessageSubmission */
	    p7_dissector = dissect_p7_MSMessageSubmissionArgument;
	    p7_op_name = "MS-Message-Submission-Argument";
	    hf_p7_index = hf_p7_MSMessageSubmissionArgument_PDU;
	    break;
	  case 4: /* msProbeSubmission */
	    p7_dissector = dissect_p7_MSProbeSubmissionArgument;
	    p7_op_name = "MS-Probe-Submission-Argument";
	    hf_p7_index = hf_p7_MSProbeSubmissionArgument_PDU;
	    break;
	  case 20: /* summarize */
	    p7_dissector = dissect_p7_SummarizeArgument;
	    p7_op_name = "Summarize-Argument";
	    hf_p7_index = hf_p7_SummarizeArgument_PDU;
	    break;
	  case 21: /* list */
	    p7_dissector = dissect_p7_ListArgument;
	    p7_op_name = "List-Argument";
	    hf_p7_index = hf_p7_ListArgument_PDU;
	    break;
	  case 22: /* fetch */
	    p7_dissector = dissect_p7_FetchArgument;
	    p7_op_name = "Fetch-Argument";
	    hf_p7_index = hf_p7_FetchArgument_PDU;
	    break;
	  case 23: /* delete */
	    p7_dissector = dissect_p7_DeleteArgument;
	    p7_op_name = "Delete-Argument";
	    hf_p7_index = hf_p7_DeleteArgument_PDU;
	    break;
	  case 24: /* register-ms */
	    p7_dissector = dissect_p7_Register_MSArgument;
	    p7_op_name = "RegisterMS-Argument";
	    hf_p7_index = hf_p7_Register_MSArgument_PDU;
	    break;
	  case 25: /* alert */
	    p7_dissector = dissect_p7_AlertArgument;
	    p7_op_name = "Alert-Argument";
	    hf_p7_index = hf_p7_AlertArgument_PDU;
	    break;
	  case 26: /* modify */
	    p7_dissector = dissect_p7_ModifyArgument;
	    p7_op_name = "Modify-Argument";
	    hf_p7_index = hf_p7_ModifyArgument_PDU;
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported P7 argument opcode (%d)",
				session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_RESULT):	/*  Return Result */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 3: /* msMessageSubmission */
	    p7_dissector = dissect_p7_MSMessageSubmissionResult;
	    p7_op_name = "MS-Message-Submission-Result";
	    hf_p7_index = hf_p7_MSMessageSubmissionResult_PDU;
	    break;
	  case 4: /* msProbeSubmission */
	    p7_dissector = dissect_p7_MSProbeSubmissionResult;
	    p7_op_name = "MS-Probe-Submission-Result";
	    hf_p7_index = hf_p7_MSProbeSubmissionResult_PDU;
	    break;
	  case 20: /* summarize */
	    p7_dissector = dissect_p7_SummarizeResult;
	    p7_op_name = "Summarize-Result";
	    hf_p7_index = hf_p7_SummarizeResult_PDU;
	    break;
	  case 21: /* list */
	    p7_dissector = dissect_p7_ListResult;
	    p7_op_name = "List-Result";
	    hf_p7_index = hf_p7_ListResult_PDU;
	    break;
	  case 22: /* fetch */
	    p7_dissector = dissect_p7_FetchResult;
	    p7_op_name = "Fetch-Result";
	    hf_p7_index = hf_p7_FetchResult_PDU;
	    break;
	  case 23: /* delete */
	    p7_dissector = dissect_p7_DeleteResult;
	    p7_op_name = "Delete-Result";
	    break;
	  case 24: /* register-ms */
	    p7_dissector = dissect_p7_Register_MSResult;
	    p7_op_name = "RegisterMS-Result";
	    hf_p7_index = hf_p7_Register_MSResult_PDU;
	    break;
	  case 25: /* alert */
	    p7_dissector = dissect_p7_AlertResult;
	    p7_op_name = "Alert-Result";
	    hf_p7_index = hf_p7_AlertResult_PDU;
	    break;
	  case 26: /* modify */
	    p7_dissector = dissect_p7_ModifyResult;
	    p7_op_name = "Modify-Result";
	    hf_p7_index = hf_p7_ModifyResult_PDU;
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported P7 result opcode (%d)",
				session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ERROR):	/*  Return Error */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 21: /* attributeError */
	    p7_dissector = dissect_p7_AttributeErrorParameter;
	    p7_op_name = "Attribute-Error";
	    hf_p7_index = hf_p7_AttributeErrorParameter_PDU;
	    break;
	  case 22: /* autoActionRequestError */
	    p7_dissector = dissect_p7_AutoActionRequestErrorParameter;
	    p7_op_name = "Auto-Action-Request-Error";
	    hf_p7_index = hf_p7_AutoActionRequestErrorParameter_PDU;
	    break;
	  case 23: /* deleteError */
	    p7_dissector = dissect_p7_DeleteErrorParameter;
	    p7_op_name = "Delete-Error";
	    hf_p7_index = hf_p7_DeleteErrorParameter_PDU;
	    break;
	  case 24: /* fetchRestrictionError */
	    p7_dissector = dissect_p7_FetchRestrictionErrorParameter;
	    p7_op_name = "Fetch-Restriction-Error";
	    hf_p7_index = hf_p7_FetchRestrictionErrorParameter_PDU;
	    break;
	  case 25: /* rangeError */
	    p7_dissector = dissect_p7_RangeErrorParameter;
	    p7_op_name = "Range-Error";
	    hf_p7_index = hf_p7_RangeErrorParameter_PDU;
	    break;
	  case 26: /* securityError */
	    p7_dissector = dissect_x411_SecurityProblem;
	    p7_op_name = "Security-Error";
	    break;
	  case 27: /* serviceError*/
	    p7_dissector = dissect_p7_ServiceErrorParameter;
	    p7_op_name = "Service-Error";
	    hf_p7_index = hf_p7_ServiceErrorParameter_PDU;
	    break;
	  case 28: /* sequenceNumberError */
	    p7_dissector = dissect_p7_SequenceNumberErrorParameter;
	    p7_op_name = "Sequence-Number-Error";
	    hf_p7_index = hf_p7_SequenceNumberErrorParameter_PDU;
	    break;
	  case 29: /* invalidParametersError */
	    p7_dissector = NULL;
	    p7_op_name = "Invalid-Parameters-Error";
	    break;
	  case 30: /* messageGroupError */
	    p7_dissector = dissect_p7_MessageGroupErrorParameter;
	    p7_op_name = "Message-Group-Error";
	    hf_p7_index = hf_p7_MessageGroupErrorParameter_PDU;
	    break;
	  case 31: /* msExtensioError */
	    p7_dissector = dissect_p7_MSExtensionErrorParameter;
	    p7_op_name = "MS-Extension-Error";
	    hf_p7_index = hf_p7_MSExtensionErrorParameter_PDU;
	    break;
	  case 32: /* registerMSError */
	    p7_dissector = dissect_p7_RegisterMSErrorParameter;
	    p7_op_name = "Register-MS-Error";
	    hf_p7_index = hf_p7_RegisterMSErrorParameter_PDU;
	    break;
	  case 33: /* sequenceNumberError */
	    p7_dissector = dissect_p7_ModifyErrorParameter;
	    p7_op_name = "Modify-Error";
	    hf_p7_index = hf_p7_ModifyErrorParameter_PDU;
	    break;
	  case 34: /* entryClassError */
	    p7_dissector = dissect_p7_EntryClassErrorParameter;
	    p7_op_name = "Entry-Class-Error";
	    hf_p7_index = hf_p7_EntryClassErrorParameter_PDU;
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported P7 error opcode (%d)",
				session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	default:
	  proto_tree_add_text(tree, tvb, offset, -1,"Unsupported P7 PDU");
	  return;
	}

	if(p7_dissector) {
	  if (check_col(pinfo->cinfo, COL_INFO))
	    col_set_str(pinfo->cinfo, COL_INFO, p7_op_name);

	  while (tvb_reported_length_remaining(tvb, offset) > 0){
	    old_offset=offset;
	    offset=(*p7_dissector)(FALSE, tvb, offset, &asn1_ctx, tree, hf_p7_index);
	    if(offset == old_offset){
	      proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte P7 PDU");
	      offset = tvb_length(tvb);
	      break;
	    }
	  }
	}
}


/*--- proto_register_p7 -------------------------------------------*/
void proto_register_p7(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-p7-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_p7,
#include "packet-p7-ettarr.c"
  };
  module_t *p7_module;

  /* Register protocol */
  proto_p7 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("p7", dissect_p7, proto_p7);

  /* Register fields and subtrees */
  proto_register_field_array(proto_p7, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for P7, particularly our port */

  p7_module = prefs_register_protocol_subtree("OSI/X.400", proto_p7, prefs_register_p7);

  prefs_register_uint_preference(p7_module, "tcp.port", "P7 TCP Port",
				 "Set the port for P7 operations (if other"
				 " than the default of 102)",
				 10, &global_p7_tcp_port);

}


/*--- proto_reg_handoff_p7 --- */
void proto_reg_handoff_p7(void) {
  dissector_handle_t handle = NULL;

  /* #include "packet-p7-dis-tab.c" */

  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-ms-access","2.6.0.1.11");
  oid_add_from_string("id-ac-ms-reliable-access","2.6.0.1.12");

  /* ABSTRACT SYNTAXES */
    
  /* Register P7 with ROS (with no use of RTSE) */
  if((handle = find_dissector("p7"))) {
    register_ros_oid_dissector_handle("2.6.0.2.9", handle, 0, "id-as-ms", FALSE); 
    register_ros_oid_dissector_handle("2.6.0.2.5", handle, 0, "id-as-mrse", FALSE); 
    register_ros_oid_dissector_handle("2.6.0.2.1", handle, 0, "id-as-msse", FALSE); 
  }

  /* remember the tpkt handler for change in preferences */
  tpkt_handle = find_dissector("tpkt");
}


void prefs_register_p7(void) {

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port != 102) && tpkt_handle)
    dissector_delete("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_p7_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add("tcp.port", global_p7_tcp_port, tpkt_handle);

}
