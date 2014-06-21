/* packet-p1.c
 * Routines for X.411 (X.400 Message Transfer)  packet dissection
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/wmem/wmem.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ros.h"
#include "packet-rtse.h"

#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"

#include "packet-p1.h"
#include <epan/strutil.h>

#define PNAME  "X.411 Message Transfer Service"
#define PSNAME "P1"
#define PFNAME "p1"

static guint global_p1_tcp_port = 102;
static dissector_handle_t tpkt_handle;
static void prefs_register_p1(void); /* forward declaration for use in preferences registration */

/* Initialize the protocol and registered fields */
static int proto_p1 = -1;
static int proto_p3 = -1;

static int hf_p1_MTS_APDU_PDU = -1;
static int hf_p1_MTABindArgument_PDU = -1;
static int hf_p1_MTABindResult_PDU = -1;
static int hf_p1_MTABindError_PDU = -1;

#include "packet-p1-hf.c"

/* Initialize the subtree pointers */
static gint ett_p1 = -1;
static gint ett_p3 = -1;
static gint ett_p1_content_unknown = -1;
static gint ett_p1_bilateral_information = -1;
static gint ett_p1_additional_information = -1;
static gint ett_p1_unknown_standard_extension = -1;
static gint ett_p1_unknown_extension_attribute_type = -1;
static gint ett_p1_unknown_tokendata_type = -1;
#include "packet-p1-ett.c"

static expert_field ei_p1_unknown_extension_attribute_type = EI_INIT;
static expert_field ei_p1_unknown_standard_extension = EI_INIT;
static expert_field ei_p1_unknown_built_in_content_type = EI_INIT;
static expert_field ei_p1_unknown_tokendata_type = EI_INIT;

/* Dissector tables */
static dissector_table_t p1_extension_dissector_table;
static dissector_table_t p1_extension_attribute_dissector_table;
static dissector_table_t p1_tokendata_dissector_table;

#include "packet-p1-table.c"   /* operation and error codes */

typedef struct p1_address_ctx {
	gboolean do_address;
	const char *content_type_id;
	gboolean report_unknown_content_type;
	wmem_strbuf_t* oraddress;
} p1_address_ctx_t;

static void set_do_address(asn1_ctx_t* actx, gboolean do_address)
{
	p1_address_ctx_t* ctx;

	if (actx->subtree.tree_ctx == NULL) {
		actx->subtree.tree_ctx = wmem_new0(wmem_packet_scope(), p1_address_ctx_t);
	}

	ctx = (p1_address_ctx_t*)actx->subtree.tree_ctx;
	ctx->do_address = do_address;
}

static void do_address(const char* addr, tvbuff_t* tvb_string, asn1_ctx_t* actx)
{
	p1_address_ctx_t* ctx = (p1_address_ctx_t*)actx->subtree.tree_ctx;

	if (ctx && ctx->do_address) {
		if (addr) {
			wmem_strbuf_append(ctx->oraddress, addr);
		}
		if (tvb_string) {
			wmem_strbuf_append(ctx->oraddress, tvb_format_text(tvb_string, 0, tvb_captured_length(tvb_string)));
		}
	}

}

static void do_address_str(const char* addr, tvbuff_t* tvb_string, asn1_ctx_t* actx)
{
	wmem_strbuf_t *ddatype = (wmem_strbuf_t *)actx->value_ptr;
	p1_address_ctx_t* ctx = (p1_address_ctx_t*)actx->subtree.tree_ctx;

	do_address(addr, tvb_string, actx);

	if (ctx && ctx->do_address && ddatype && tvb_string)
		wmem_strbuf_append(ddatype, tvb_format_text(tvb_string, 0, tvb_captured_length(tvb_string)));
}

static void do_address_str_tree(const char* addr, tvbuff_t* tvb_string, asn1_ctx_t* actx, proto_tree* tree)
{
	wmem_strbuf_t *ddatype = (wmem_strbuf_t *)actx->value_ptr;
	p1_address_ctx_t* ctx = (p1_address_ctx_t*)actx->subtree.tree_ctx;

	do_address(addr, tvb_string, actx);

	if (ctx && ctx->do_address && tvb_string && ddatype) {
		if (wmem_strbuf_get_len(ddatype) > 0) {
			proto_item_append_text (tree, " (%s=%s)", wmem_strbuf_get_str(ddatype), tvb_format_text(tvb_string, 0, tvb_captured_length(tvb_string)));
		}
	}
}

#include "packet-p1-fn.c"

#include "packet-p1-table11.c" /* operation argument/result dissectors */
#include "packet-p1-table21.c" /* error dissector */

static const ros_info_t p3_ros_info = {
  "P3",
  &proto_p3,
  &ett_p3,
  p3_opr_code_string_vals,
  p3_opr_tab,
  p3_err_code_string_vals,
  p3_err_tab
};

void p1_initialize_content_globals (asn1_ctx_t* actx, proto_tree *tree, gboolean report_unknown_cont_type)
{
	p1_address_ctx_t* ctx;

	if (actx->subtree.tree_ctx == NULL) {
		actx->subtree.tree_ctx = wmem_new0(wmem_packet_scope(), p1_address_ctx_t);
	}

	ctx = (p1_address_ctx_t*)actx->subtree.tree_ctx;

	actx->subtree.top_tree = tree;
	actx->external.direct_reference = NULL;
	ctx->content_type_id = NULL;
	ctx->report_unknown_content_type = report_unknown_cont_type;
}

const char* p1_get_last_oraddress (asn1_ctx_t* actx)
{
	p1_address_ctx_t* ctx;

	if ((actx == NULL) || (actx->subtree.tree_ctx == NULL))
		return "";

	ctx = (p1_address_ctx_t*)actx->subtree.tree_ctx;
	if (wmem_strbuf_get_len(ctx->oraddress) <= 0)
		return "";

	return wmem_strbuf_get_str(ctx->oraddress);
}

/*
 * Dissect P1 MTS APDU
 */
void
dissect_p1_mts_apdu (tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	/* save parent_tree so subdissectors can create new top nodes */
	p1_initialize_content_globals (&asn1_ctx, parent_tree, TRUE);

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_p1, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_p1);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "P1");
  	col_set_str(pinfo->cinfo, COL_INFO, "Transfer");

	dissect_p1_MTS_APDU (FALSE, tvb, 0, &asn1_ctx, tree, hf_p1_MTS_APDU_PDU);
	p1_initialize_content_globals (&asn1_ctx, NULL, FALSE);
}

/*
* Dissect P1 PDUs inside a PPDU.
*/
static int
dissect_p1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
	int offset = 0;
	int old_offset;
	proto_item *item;
	proto_tree *tree;
	struct SESSION_DATA_STRUCTURE* session;
	int (*p1_dissector)(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) = NULL;
	const char *p1_op_name;
	int hf_p1_index = -1;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	/* do we have operation information from the ROS dissector? */
	if (data == NULL)
		return 0;
	session  = (struct SESSION_DATA_STRUCTURE*)data;

	/* save parent_tree so subdissectors can create new top nodes */
	p1_initialize_content_globals (&asn1_ctx, parent_tree, TRUE);

	asn1_ctx.private_data = session;

	item = proto_tree_add_item(parent_tree, proto_p1, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_p1);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "P1");
	col_clear(pinfo->cinfo, COL_INFO);

	switch(session->ros_op & ROS_OP_MASK) {
	case (ROS_OP_BIND | ROS_OP_ARGUMENT):	/*  BindInvoke */
	  p1_dissector = dissect_p1_MTABindArgument;
	  p1_op_name = "Bind-Argument";
	  hf_p1_index = hf_p1_MTABindArgument_PDU;
	  break;
	case (ROS_OP_BIND | ROS_OP_RESULT):	/*  BindResult */
	  p1_dissector = dissect_p1_MTABindResult;
	  p1_op_name = "Bind-Result";
	  hf_p1_index = hf_p1_MTABindResult_PDU;
	  break;
	case (ROS_OP_BIND | ROS_OP_ERROR):	/*  BindError */
	  p1_dissector = dissect_p1_MTABindError;
	  p1_op_name = "Bind-Error";
	  hf_p1_index = hf_p1_MTABindError_PDU;
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ARGUMENT):	/*  Invoke Argument */
	  p1_dissector = dissect_p1_MTS_APDU;
	  p1_op_name = "Transfer";
	  hf_p1_index = hf_p1_MTS_APDU_PDU;
	  break;
	default:
	  proto_tree_add_text(tree, tvb, offset, -1,"Unsupported P1 PDU");
	  return tvb_captured_length(tvb);
	}

	col_set_str(pinfo->cinfo, COL_INFO, p1_op_name);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=(*p1_dissector)(FALSE, tvb, offset, &asn1_ctx , tree, hf_p1_index);
		if(offset == old_offset){
			proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte P1 PDU");
			break;
		}
	}
	p1_initialize_content_globals (&asn1_ctx, NULL, FALSE);
	return tvb_captured_length(tvb);
}


/*--- proto_register_p1 -------------------------------------------*/
void proto_register_p1(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
      /* "Created by defining PDU in .cnf */
    { &hf_p1_MTABindArgument_PDU,
      { "MTABindArgument", "p1.MTABindArgument",
        FT_UINT32, BASE_DEC, VALS(p1_MTABindArgument_vals), 0,
        "p1.MTABindArgument", HFILL }},
    { &hf_p1_MTABindResult_PDU,
      { "MTABindResult", "p1.MTABindResult",
        FT_UINT32, BASE_DEC, VALS(p1_MTABindResult_vals), 0,
        "p1.MTABindResult", HFILL }},
    { &hf_p1_MTABindError_PDU,
      { "MTABindError", "p1.MTABindError",
        FT_UINT32, BASE_DEC, VALS(p1_MTABindError_vals), 0,
        "p1.MTABindError", HFILL }},
    { &hf_p1_MTS_APDU_PDU,
      { "MTS-APDU", "p1.MTS_APDU",
        FT_UINT32, BASE_DEC, VALS(p1_MTS_APDU_vals), 0,
        "p1.MTS_APDU", HFILL }},

#include "packet-p1-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_p1,
    &ett_p3,
    &ett_p1_content_unknown,
    &ett_p1_bilateral_information,
    &ett_p1_additional_information,
    &ett_p1_unknown_standard_extension,
    &ett_p1_unknown_extension_attribute_type,
    &ett_p1_unknown_tokendata_type,
#include "packet-p1-ettarr.c"
  };

  static ei_register_info ei[] = {
     { &ei_p1_unknown_extension_attribute_type, { "p1.unknown.extension_attribute_type", PI_UNDECODED, PI_WARN, "Unknown extension-attribute-type", EXPFILL }},
     { &ei_p1_unknown_standard_extension, { "p1.unknown.standard_extension", PI_UNDECODED, PI_WARN, "Unknown standard-extension", EXPFILL }},
     { &ei_p1_unknown_built_in_content_type, { "p1.unknown.built_in_content_type", PI_UNDECODED, PI_WARN, "P1 Unknown Content (unknown built-in content-type)", EXPFILL }},
     { &ei_p1_unknown_tokendata_type, { "p1.unknown.tokendata_type", PI_UNDECODED, PI_WARN, "Unknown tokendata-type", EXPFILL }},
  };

  expert_module_t* expert_p1;
  module_t *p1_module;

  /* Register protocol */
  proto_p1 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  new_register_dissector("p1", dissect_p1, proto_p1);

  proto_p3 = proto_register_protocol("X.411 Message Access Service", "P3", "p3");

  /* Register fields and subtrees */
  proto_register_field_array(proto_p1, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_p1 = expert_register_protocol(proto_p1);
  expert_register_field_array(expert_p1, ei, array_length(ei));

  p1_extension_dissector_table = register_dissector_table("p1.extension", "P1-EXTENSION", FT_UINT32, BASE_DEC);
  p1_extension_attribute_dissector_table = register_dissector_table("p1.extension-attribute", "P1-EXTENSION-ATTRIBUTE", FT_UINT32, BASE_DEC);
  p1_tokendata_dissector_table = register_dissector_table("p1.tokendata", "P1-TOKENDATA", FT_UINT32, BASE_DEC);

  /* Register our configuration options for P1, particularly our port */

  p1_module = prefs_register_protocol_subtree("OSI/X.400", proto_p1, prefs_register_p1);

  prefs_register_uint_preference(p1_module, "tcp.port", "P1 TCP Port",
				 "Set the port for P1 operations (if other"
				 " than the default of 102)",
				 10, &global_p1_tcp_port);

  register_ber_syntax_dissector("P1 Message", proto_p1, dissect_p1_mts_apdu);
}


/*--- proto_reg_handoff_p1 --- */
void proto_reg_handoff_p1(void) {
  dissector_handle_t p1_handle;

#include "packet-p1-dis-tab.c"

  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-mts-transfer","2.6.0.1.6");

  /* ABSTRACT SYNTAXES */

  p1_handle = find_dissector("p1");
  register_rtse_oid_dissector_handle("2.6.0.2.12", p1_handle, 0, "id-as-mta-rtse", TRUE);
  register_rtse_oid_dissector_handle("2.6.0.2.7", p1_handle, 0, "id-as-mtse", FALSE);

  register_rtse_oid_dissector_handle("applicationProtocol.1", p1_handle, 0, "mts-transfer-protocol-1984", FALSE);
  register_rtse_oid_dissector_handle("applicationProtocol.12", p1_handle, 0, "mta-transfer-protocol", FALSE);

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

static void
prefs_register_p1(void)
{
  static guint tcp_port = 0;

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_delete_uint("tcp.port", tcp_port, tpkt_handle);

  /* Set our port number for future use */
  tcp_port = global_p1_tcp_port;

  if((tcp_port > 0) && (tcp_port != 102) && tpkt_handle)
    dissector_add_uint("tcp.port", tcp_port, tpkt_handle);

}
