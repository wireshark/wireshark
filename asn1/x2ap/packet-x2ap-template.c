/* packet-x2ap.c
 * Routines for dissecting Evolved Universal Terrestrial Radio Access Network (EUTRAN);
 * X2 Application Protocol (X2AP);
 * 3GPP TS 36.423 packet dissection
 * Copyright 2007-2010, Anders Broman <anders.broman@ericsson.com>
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
 *
 * Ref:
 * 3GPP TS 36.423 V9.2.0 (2010-03)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>

#include "packet-per.h"
#include "packet-e212.h"
#include "packet-frame.h"
#include "packet-lte-rrc.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "EUTRAN X2 Application Protocol (X2AP)"
#define PSNAME "X2AP"
#define PFNAME "x2ap"

/* Dissector will use SCTP PPID 27 or SCTP port. IANA assigned port = 36422 */
#define SCTP_PORT_X2AP	36422

#include "packet-x2ap-val.h"

/* Initialize the protocol and registered fields */
static int proto_x2ap = -1;
static int hf_x2ap_transportLayerAddressIPv4 = -1;
static int hf_x2ap_transportLayerAddressIPv6 = -1;
#include "packet-x2ap-hf.c"

/* Initialize the subtree pointers */
static int ett_x2ap = -1;
static int ett_x2ap_TransportLayerAddress = -1;
#include "packet-x2ap-ett.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint gbl_x2apSctpPort=SCTP_PORT_X2AP;

/* Dissector tables */
static dissector_table_t x2ap_ies_dissector_table;
static dissector_table_t x2ap_extension_dissector_table;
static dissector_table_t x2ap_proc_imsg_dissector_table;
static dissector_table_t x2ap_proc_sout_dissector_table;
static dissector_table_t x2ap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void proto_reg_handoff_x2ap(void);

#include "packet-x2ap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(x2ap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(x2ap_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(x2ap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(x2ap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(x2ap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static void
dissect_x2ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*x2ap_item = NULL;
	proto_tree	*x2ap_tree = NULL;

	/* make entry in the Protocol column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "X2AP");

	/* create the x2ap protocol tree */
	x2ap_item = proto_tree_add_item(tree, proto_x2ap, tvb, 0, -1, ENC_NA);
	x2ap_tree = proto_item_add_subtree(x2ap_item, ett_x2ap);

	dissect_X2AP_PDU_PDU(tvb, pinfo, x2ap_tree);
}

/*--- proto_register_x2ap -------------------------------------------*/
void proto_register_x2ap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_x2ap_transportLayerAddressIPv4,
      { "transportLayerAddress(IPv4)", "x2ap.transportLayerAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x2ap_transportLayerAddressIPv6,
      { "transportLayerAddress(IPv6)", "x2ap.transportLayerAddressIPv6",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},

#include "packet-x2ap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_x2ap,
		  &ett_x2ap_TransportLayerAddress,
#include "packet-x2ap-ettarr.c"
  };

  module_t *x2ap_module;

  /* Register protocol */
  proto_x2ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_x2ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  register_dissector("x2ap", dissect_x2ap, proto_x2ap);

  /* Register dissector tables */
  x2ap_ies_dissector_table = register_dissector_table("x2ap.ies", "X2AP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  x2ap_extension_dissector_table = register_dissector_table("x2ap.extension", "X2AP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  x2ap_proc_imsg_dissector_table = register_dissector_table("x2ap.proc.imsg", "X2AP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_UINT32, BASE_DEC);
  x2ap_proc_sout_dissector_table = register_dissector_table("x2ap.proc.sout", "X2AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_UINT32, BASE_DEC);
  x2ap_proc_uout_dissector_table = register_dissector_table("x2ap.proc.uout", "X2AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_UINT32, BASE_DEC);

  /* Register configuration options for ports */
  x2ap_module = prefs_register_protocol(proto_x2ap, proto_reg_handoff_x2ap);

  prefs_register_uint_preference(x2ap_module, "sctp.port",
                                 "X2AP SCTP Port",
                                 "Set the SCTP port for X2AP messages",
                                 10,
                                 &gbl_x2apSctpPort);

}


/*--- proto_reg_handoff_x2ap ---------------------------------------*/
void
proto_reg_handoff_x2ap(void)
{
	dissector_handle_t x2ap_handle;
	static gboolean Initialized=FALSE;
	static guint SctpPort;

	x2ap_handle = find_dissector("x2ap");
	if (!Initialized) {
		dissector_add_handle("sctp.port", x2ap_handle);  /* for "decode-as" */
		dissector_add_uint("sctp.ppi", X2AP_PAYLOAD_PROTOCOL_ID, x2ap_handle);
		Initialized=TRUE;
#include "packet-x2ap-dis-tab.c"
	} else {
		if (SctpPort != 0) {
			dissector_delete_uint("sctp.port", SctpPort, x2ap_handle);
		}
	}

	SctpPort=gbl_x2apSctpPort;
	if (SctpPort != 0) {
		dissector_add_uint("sctp.port", SctpPort, x2ap_handle);
	}

}


