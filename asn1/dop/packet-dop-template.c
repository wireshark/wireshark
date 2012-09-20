/* packet-dop.c
 * Routines for X.501 (DSA Operational Attributes)  packet dissection
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ros.h"

#include "packet-x509sat.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-dap.h"
#include "packet-dsp.h"
#include "packet-crmf.h"


#include "packet-dop.h"

#define PNAME  "X.501 Directory Operational Binding Management Protocol"
#define PSNAME "DOP"
#define PFNAME "dop"

static guint global_dop_tcp_port = 102;
static dissector_handle_t tpkt_handle;
static void prefs_register_dop(void); /* forward declaration for use in preferences registration */

/* Initialize the protocol and registered fields */
static int proto_dop = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;
static const char *binding_type = NULL; /* binding_type */

static int call_dop_oid_callback(char *base_string, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, char *col_info);

#include "packet-dop-hf.c"

/* Initialize the subtree pointers */
static gint ett_dop = -1;
static gint ett_dop_unknown = -1;
#include "packet-dop-ett.c"

/* Dissector table */
static dissector_table_t dop_dissector_table;

static void append_oid(packet_info *pinfo, const char *oid)
{
  	const char *name = NULL;

    name = oid_resolved_from_string(oid);
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name ? name : oid);
}

#include "packet-dop-fn.c"

static int
call_dop_oid_callback(char *base_string, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, char *col_info)
{
  char* binding_param;

  binding_param = ep_strdup_printf("%s.%s", base_string, binding_type ? binding_type : "");

  col_append_fstr(pinfo->cinfo, COL_INFO, " %s", col_info);

  if (dissector_try_string(dop_dissector_table, binding_param, tvb, pinfo, tree)) {
     offset += tvb_length_remaining (tvb, offset);
  } else {
     proto_item *item=NULL;
     proto_tree *next_tree=NULL;

     item = proto_tree_add_text(tree, tvb, 0, tvb_length_remaining(tvb, offset), "Dissector for parameter %s OID:%s not implemented. Contact Wireshark developers if you want this supported", base_string, binding_type ? binding_type : "<empty>");
     if (item) {
        next_tree = proto_item_add_subtree(item, ett_dop_unknown);
     }
     offset = dissect_unknown_ber(pinfo, tvb, offset, next_tree);
     expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "Unknown binding-parameter");
   }

   return offset;
}


/*
* Dissect DOP PDUs inside a ROS PDUs
*/
static void
dissect_dop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	int (*dop_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) = NULL;
	char *dop_op_name;
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
		item = proto_tree_add_item(parent_tree, proto_dop, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_dop);
	}
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DOP");
  	col_clear(pinfo->cinfo, COL_INFO);

	switch(session->ros_op & ROS_OP_MASK) {
	case (ROS_OP_BIND | ROS_OP_ARGUMENT):	/*  BindInvoke */
	  dop_dissector = dissect_dop_DSAOperationalManagementBindArgument;
	  dop_op_name = "DSA-Operational-Bind-Argument";
	  break;
	case (ROS_OP_BIND | ROS_OP_RESULT):	/*  BindResult */
	  dop_dissector = dissect_dop_DSAOperationalManagementBindResult;
	  dop_op_name = "DSA-Operational-Bind-Result";
	  break;
	case (ROS_OP_BIND | ROS_OP_ERROR):	/*  BindError */
	  dop_dissector = dissect_dop_DSAOperationalManagementBindError;
	  dop_op_name = "DSA-Operational-Management-Bind-Error";
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ARGUMENT):	/*  Invoke Argument */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 100: /* establish */
	    dop_dissector = dissect_dop_EstablishOperationalBindingArgument;
	    dop_op_name = "Establish-Operational-Binding-Argument";
	    break;
	  case 101: /* terminate */
	    dop_dissector = dissect_dop_TerminateOperationalBindingArgument;
	    dop_op_name = "Terminate-Operational-Binding-Argument";
	    break;
	  case 102: /* modify */
	    dop_dissector = dissect_dop_ModifyOperationalBindingArgument;
	    dop_op_name = "Modify-Operational-Binding-Argument";
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DOP Argument opcode (%d)",
				session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_RESULT):	/*  Return Result */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 100: /* establish */
	    dop_dissector = dissect_dop_EstablishOperationalBindingResult;
	    dop_op_name = "Establish-Operational-Binding-Result";
	    break;
	  case 101: /* terminate */
	    dop_dissector = dissect_dop_TerminateOperationalBindingResult;
	    dop_op_name = "Terminate-Operational-Binding-Result";
	    break;
	  case 102: /* modify */
	    dop_dissector = dissect_dop_ModifyOperationalBindingResult;
	    dop_op_name = "Modify-Operational-Binding-Result";
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DOP Result opcode (%d)",
				session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ERROR):	/*  Return Error */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 100: /* operational-binding */
	    dop_dissector = dissect_dop_OpBindingErrorParam;
	    dop_op_name = "Operational-Binding-Error";
	    break;
	  default:
	    proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DOP Error opcode (%d)",
				session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	default:
	  proto_tree_add_text(tree, tvb, offset, -1,"Unsupported DOP PDU");
	  return;
	}

	if(dop_dissector) {
      col_set_str(pinfo->cinfo, COL_INFO, dop_op_name);

	  while (tvb_reported_length_remaining(tvb, offset) > 0){
	    old_offset=offset;
	    offset=(*dop_dissector)(FALSE, tvb, offset, &asn1_ctx, tree, -1);
	    if(offset == old_offset){
	      proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte DOP PDU");
	      break;
	    }
	  }
	}
}



/*--- proto_register_dop -------------------------------------------*/
void proto_register_dop(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-dop-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_dop,
    &ett_dop_unknown,
#include "packet-dop-ettarr.c"
  };

  module_t *dop_module;

  /* Register protocol */
  proto_dop = proto_register_protocol(PNAME, PSNAME, PFNAME);

  register_dissector("dop", dissect_dop, proto_dop);

  dop_dissector_table = register_dissector_table("dop.oid", "DOP OID Dissectors", FT_STRING, BASE_NONE);

  /* Register fields and subtrees */
  proto_register_field_array(proto_dop, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for DOP, particularly our port */

  dop_module = prefs_register_protocol_subtree("OSI/X.500", proto_dop, prefs_register_dop);

  prefs_register_uint_preference(dop_module, "tcp.port", "DOP TCP Port",
				 "Set the port for DOP operations (if other"
				 " than the default of 102)",
				 10, &global_dop_tcp_port);


}


/*--- proto_reg_handoff_dop --- */
void proto_reg_handoff_dop(void) {
  dissector_handle_t dop_handle;

#include "packet-dop-dis-tab.c"
  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-directory-operational-binding-management","2.5.3.3");

  /* ABSTRACT SYNTAXES */

  /* Register DOP with ROS (with no use of RTSE) */
  dop_handle = find_dissector("dop");
  register_ros_oid_dissector_handle("2.5.9.4", dop_handle, 0, "id-as-directory-operational-binding-management", FALSE);

  /* BINDING TYPES */

  oid_add_from_string("shadow-agreement","2.5.19.1");
  oid_add_from_string("hierarchical-agreement","2.5.19.2");
  oid_add_from_string("non-specific-hierarchical-agreement","2.5.19.3");

  /* ACCESS CONTROL SCHEMES */
  oid_add_from_string("basic-ACS","2.5.28.1");
  oid_add_from_string("simplified-ACS","2.5.28.2");
  oid_add_from_string("ruleBased-ACS","2.5.28.3");
  oid_add_from_string("ruleAndBasic-ACS","2.5.28.4");
  oid_add_from_string("ruleAndSimple-ACS","2.5.28.5");

  /* ADMINISTRATIVE ROLES */
  oid_add_from_string("id-ar-autonomousArea","2.5.23.1");
  oid_add_from_string("id-ar-accessControlSpecificArea","2.5.23.2");
  oid_add_from_string("id-ar-accessControlInnerArea","2.5.23.3");
  oid_add_from_string("id-ar-subschemaAdminSpecificArea","2.5.23.4");
  oid_add_from_string("id-ar-collectiveAttributeSpecificArea","2.5.23.5");
  oid_add_from_string("id-ar-collectiveAttributeInnerArea","2.5.23.6");
  oid_add_from_string("id-ar-contextDefaultSpecificArea","2.5.23.7");
  oid_add_from_string("id-ar-serviceSpecificArea","2.5.23.8");

  /* remember the tpkt handler for change in preferences */
  tpkt_handle = find_dissector("tpkt");

}

static void
prefs_register_dop(void)
{
  static guint tcp_port = 0;

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_delete_uint("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_dop_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add_uint("tcp.port", tcp_port, tpkt_handle);

}
