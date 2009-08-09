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
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/expert.h>

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
#include <epan/strutil.h>

#define PNAME  "X.411 Message Transfer Service"
#define PSNAME "X411"
#define PFNAME "x411"

static guint global_x411_tcp_port = 102;
static dissector_handle_t tpkt_handle;
void prefs_register_x411(void); /* forward declaration for use in preferences registration */

/* Initialize the protocol and registered fields */
int proto_x411 = -1;
int proto_p3 = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;
static int extension_id = -1; /* integer extension id */
static const char *object_identifier_id = NULL; /* extensions identifier */
static const char *content_type_id = NULL; /* content type identifier */

#define MAX_ORA_STR_LEN     256
static char *oraddress = NULL;
static char *ddatype = NULL;
static gboolean doing_address=FALSE;
static gboolean doing_subjectid=FALSE;
static proto_item *address_item = NULL;

static proto_tree *top_tree=NULL;

static int hf_x411_MTS_APDU_PDU = -1;
static int hf_x411_MTABindArgument_PDU = -1;
static int hf_x411_MTABindResult_PDU = -1;
static int hf_x411_MTABindError_PDU = -1;

#include "packet-x411-hf.c"

/* Initialize the subtree pointers */
static gint ett_x411 = -1;
static gint ett_p3 = -1;
static gint ett_x411_content_unknown = -1;
static gint ett_x411_bilateral_information = -1;
static gint ett_x411_additional_information = -1;
static gint ett_x411_unknown_standard_extension = -1;
static gint ett_x411_unknown_extension_attribute_type = -1;
static gint ett_x411_unknown_tokendata_type = -1;
#include "packet-x411-ett.c"

/* Dissector tables */
static dissector_table_t x411_extension_dissector_table;
static dissector_table_t x411_extension_attribute_dissector_table;
static dissector_table_t x411_tokendata_dissector_table;

#include "packet-x411-val.h"

#include "packet-x411-table.c"   /* operation and error codes */

#include "packet-x411-fn.c"

#include "packet-x411-table11.c" /* operation argument/result dissectors */
#include "packet-x411-table21.c" /* error dissector */

static const ros_info_t p3_ros_info = {
  "P3",
  &proto_p3,
  &ett_p3,
  p3_opr_code_string_vals,
  p3_opr_tab,
  p3_err_code_string_vals,
  p3_err_tab
};


char* x411_get_last_oraddress() { return oraddress; }

/*
 * Dissect X411 MTS APDU
 */
void
dissect_x411_mts_apdu (tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	/* save parent_tree so subdissectors can create new top nodes */
	top_tree=parent_tree;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_x411, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_x411);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "P1");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_set_str(pinfo->cinfo, COL_INFO, "Transfer");

	dissect_x411_MTS_APDU (FALSE, tvb, 0, &asn1_ctx, tree, hf_x411_MTS_APDU_PDU);
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
	int (*x411_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) = NULL;
	char *x411_op_name;
	int hf_x411_index = -1;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

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
	  col_set_str(pinfo->cinfo, COL_INFO, x411_op_name);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=(*x411_dissector)(FALSE, tvb, offset, &asn1_ctx , tree, hf_x411_index);
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
	  /* "Created by defining PDU in .cnf */
    { &hf_x411_MTABindArgument_PDU,
      { "MTABindArgument", "x411.MTABindArgument",
        FT_UINT32, BASE_DEC, VALS(x411_MTABindArgument_vals), 0,
        "x411.MTABindArgument", HFILL }},
    { &hf_x411_MTABindResult_PDU,
      { "MTABindResult", "x411.MTABindResult",
        FT_UINT32, BASE_DEC, VALS(x411_MTABindResult_vals), 0,
        "x411.MTABindResult", HFILL }},
    { &hf_x411_MTABindError_PDU,
      { "MTABindError", "x411.MTABindError",
        FT_UINT32, BASE_DEC, VALS(x411_MTABindError_vals), 0,
        "x411.MTABindError", HFILL }},
    { &hf_x411_MTS_APDU_PDU,
      { "MTS-APDU", "x411.MTS_APDU",
        FT_UINT32, BASE_DEC, VALS(x411_MTS_APDU_vals), 0,
        "x411.MTS_APDU", HFILL }},

#include "packet-x411-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_x411,
    &ett_p3,
    &ett_x411_content_unknown,
    &ett_x411_bilateral_information,
    &ett_x411_additional_information,
    &ett_x411_unknown_standard_extension,
    &ett_x411_unknown_extension_attribute_type,
    &ett_x411_unknown_tokendata_type,
#include "packet-x411-ettarr.c"
  };

  module_t *x411_module;

  /* Register protocol */
  proto_x411 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("x411", dissect_x411, proto_x411);

  proto_p3 = proto_register_protocol("X.411 Message Access Service", "P3", "p3");

  /* Register fields and subtrees */
  proto_register_field_array(proto_x411, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  x411_extension_dissector_table = register_dissector_table("x411.extension", "X411-EXTENSION", FT_UINT32, BASE_DEC);
  x411_extension_attribute_dissector_table = register_dissector_table("x411.extension-attribute", "X411-EXTENSION-ATTRIBUTE", FT_UINT32, BASE_DEC);
  x411_tokendata_dissector_table = register_dissector_table("x411.tokendata", "X411-TOKENDATA", FT_UINT32, BASE_DEC);

  /* Register our configuration options for X411, particularly our port */

  x411_module = prefs_register_protocol_subtree("OSI/X.400", proto_x411, prefs_register_x411);

  prefs_register_uint_preference(x411_module, "tcp.port", "X.411 TCP Port",
				 "Set the port for P1 operations (if other"
				 " than the default of 102)",
				 10, &global_x411_tcp_port);

}


/*--- proto_reg_handoff_x411 --- */
void proto_reg_handoff_x411(void) {
  dissector_handle_t x411_handle;

#include "packet-x411-dis-tab.c"

  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-mts-transfer","2.6.0.1.6");

  /* ABSTRACT SYNTAXES */

  x411_handle = find_dissector("x411");
  register_rtse_oid_dissector_handle("2.6.0.2.12", x411_handle, 0, "id-as-mta-rtse", TRUE); 
  register_rtse_oid_dissector_handle("2.6.0.2.7", x411_handle, 0, "id-as-mtse", FALSE);

  register_ber_syntax_dissector("X.411 Message", proto_x411, dissect_x411_mts_apdu);
  register_rtse_oid_dissector_handle("applicationProtocol.1", x411_handle, 0, "mts-transfer-protocol-1984", FALSE);
  register_rtse_oid_dissector_handle("applicationProtocol.12", x411_handle, 0, "mta-transfer-protocol", FALSE);

  /* remember the tpkt handler for change in preferences */
  tpkt_handle = find_dissector("tpkt");

  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-mts-access-88", id_ac_mts_access_88);
  oid_add_from_string("id-ac-mts-forced-access-88", id_ac_mts_forced_access_88);
  oid_add_from_string("id-ac-mts-access-94", id_ac_mts_access_94);
  oid_add_from_string("id-ac-mts-forced-access-94", id_ac_mts_forced_access_94);


  /* Register P3 with ROS */
  register_ros_protocol_info(id_as_msse, &p3_ros_info, 0, "id-as-msse", FALSE); 

  register_ros_protocol_info(id_as_mdse_88, &p3_ros_info, 0, "id-as-mdse-88", FALSE); 
  register_ros_protocol_info(id_as_mdse_94, &p3_ros_info, 0, "id-as-mdse-94", FALSE); 

  register_ros_protocol_info(id_as_mase_88, &p3_ros_info, 0, "id-as-mase-88", FALSE); 
  register_ros_protocol_info(id_as_mase_94, &p3_ros_info, 0, "id-as-mase-94", FALSE); 

  register_ros_protocol_info(id_as_mts, &p3_ros_info, 0, "id-as-mts", FALSE); 

}

void prefs_register_x411(void) {
  static guint tcp_port = 0;

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_delete("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_x411_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add("tcp.port", tcp_port, tpkt_handle);

}
