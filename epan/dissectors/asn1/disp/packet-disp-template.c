/* packet-disp.c
 * Routines for X.525 (X.500 Directory Shadow Asbtract Service) and X.519 DISP packet dissection
 * Graeme Lunt 2005
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
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/asn1.h>

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


/* we don't have a separate dissector for X519 -
   and most of DISP is defined in X525 */
#define PNAME  "X.519 Directory Information Shadowing Protocol"
#define PSNAME "DISP"
#define PFNAME "disp"

void proto_register_disp(void);
void proto_reg_handoff_disp(void);

static guint global_disp_tcp_port = 102;
static dissector_handle_t tpkt_handle;
static void prefs_register_disp(void); /* forward declaration for use in preferences registration */


/* Initialize the protocol and registered fields */
static int proto_disp = -1;

#include "packet-disp-hf.c"

/* Initialize the subtree pointers */
static gint ett_disp = -1;
#include "packet-disp-ett.c"

static expert_field ei_disp_unsupported_opcode = EI_INIT;
static expert_field ei_disp_unsupported_errcode = EI_INIT;
static expert_field ei_disp_unsupported_pdu = EI_INIT;
static expert_field ei_disp_zero_pdu = EI_INIT;

static dissector_handle_t disp_handle = NULL;

#include "packet-disp-fn.c"

/*
* Dissect DISP PDUs inside a ROS PDUs
*/
static int
dissect_disp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
	int offset = 0;
	int old_offset;
	proto_item *item;
	proto_tree *tree;
	struct SESSION_DATA_STRUCTURE* session;
	int (*disp_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) = NULL;
	const char *disp_op_name;
	asn1_ctx_t asn1_ctx;

	/* do we have operation information from the ROS dissector */
	if (data == NULL)
		return 0;
	session  = (struct SESSION_DATA_STRUCTURE*)data;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	asn1_ctx.private_data = session;

	item = proto_tree_add_item(parent_tree, proto_disp, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_disp);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DISP");
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
	    proto_tree_add_expert_format(tree, pinfo, &ei_disp_unsupported_opcode, tvb, offset, -1,
	        "Unsupported DISP opcode (%d)", session->ros_op & ROS_OP_OPCODE_MASK);
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
	    proto_tree_add_expert_format(tree, pinfo, &ei_disp_unsupported_opcode, tvb, offset, -1,
	        "Unsupported DISP opcode (%d)", session->ros_op & ROS_OP_OPCODE_MASK);
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
	    proto_tree_add_expert_format(tree, pinfo, &ei_disp_unsupported_errcode, tvb, offset, -1,
	            "Unsupported DISP errcode (%d)", session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	default:
	  proto_tree_add_expert(tree, pinfo, &ei_disp_unsupported_pdu, tvb, offset, -1);
	  return tvb_captured_length(tvb);
	}

	if(disp_dissector) {
	  col_set_str(pinfo->cinfo, COL_INFO, disp_op_name);

	  while (tvb_reported_length_remaining(tvb, offset) > 0){
	    old_offset=offset;
	    offset=(*disp_dissector)(FALSE, tvb, offset, &asn1_ctx, tree, -1);
	    if(offset == old_offset){
	      proto_tree_add_expert(tree, pinfo, &ei_disp_zero_pdu, tvb, offset, -1);
	      break;
	    }
	  }
	}

	return tvb_captured_length(tvb);
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

  static ei_register_info ei[] = {
    { &ei_disp_unsupported_opcode, { "disp.unsupported_opcode", PI_UNDECODED, PI_WARN, "Unsupported DISP opcode", EXPFILL }},
    { &ei_disp_unsupported_errcode, { "disp.unsupported_errcode", PI_UNDECODED, PI_WARN, "Unsupported DISP errcode", EXPFILL }},
    { &ei_disp_unsupported_pdu, { "disp.unsupported_pdu", PI_UNDECODED, PI_WARN, "Unsupported DISP PDU", EXPFILL }},
    { &ei_disp_zero_pdu, { "disp.zero_pdu", PI_PROTOCOL, PI_ERROR, "Internal error, zero-byte DISP PDU", EXPFILL }},
  };

  module_t *disp_module;
  expert_module_t* expert_disp;

  /* Register protocol */
  proto_disp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  disp_handle = register_dissector("disp", dissect_disp, proto_disp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_disp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_disp = expert_register_protocol(proto_disp);
  expert_register_field_array(expert_disp, ei, array_length(ei));

  /* Register our configuration options for DISP, particularly our port */

  disp_module = prefs_register_protocol_subtree("OSI/X.500", proto_disp, prefs_register_disp);

  prefs_register_uint_preference(disp_module, "tcp.port", "DISP TCP Port",
				 "Set the port for DISP operations (if other"
				 " than the default of 102)",
				 10, &global_disp_tcp_port);

}


/*--- proto_reg_handoff_disp --- */
void proto_reg_handoff_disp(void) {
  #include "packet-disp-dis-tab.c"

  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-shadow-consumer-initiated","2.5.3.4");
  oid_add_from_string("id-ac-shadow-supplier-initiated","2.5.3.5");
  oid_add_from_string("id-ac-reliable-shadow-consumer-initiated","2.5.3.6");
  oid_add_from_string("id-ac-reliable-shadow-supplier-initiated","2.5.3.7");

  /* ABSTRACT SYNTAXES */
  register_ros_oid_dissector_handle("2.5.9.3", disp_handle, 0, "id-as-directory-shadow", FALSE);
  register_rtse_oid_dissector_handle("2.5.9.5", disp_handle, 0, "id-as-directory-reliable-shadow", FALSE);
  register_rtse_oid_dissector_handle("2.5.9.6", disp_handle, 0, "id-as-directory-reliable-binding", FALSE);

  /* OPERATIONAL BINDING */
  oid_add_from_string("id-op-binding-shadow","2.5.1.0.5.1");

  tpkt_handle = find_dissector("tpkt");

  /* DNs */
  x509if_register_fmt(hf_disp_contextPrefix, "cp=");

}


static void
prefs_register_disp(void)
{
  static guint tcp_port = 0;

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_delete_uint("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_disp_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add_uint("tcp.port", global_disp_tcp_port, tpkt_handle);

}
