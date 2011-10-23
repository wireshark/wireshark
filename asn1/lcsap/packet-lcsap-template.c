/* packet-lcsap.c
 * Routines for LCS-AP packet dissembly.
 *
 * Copyright (c) 2011 by Spenser Sheng <spenser.sheng@ericsson.com>
 *
 * $Id: packet-lcsap.c 28770 2011-06-18 21:30:42Z stig  Spenser Sheng$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
 * References:
 * ETSI TS 129 171 V9.2.0 (2010-10)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-sccp.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "LCS Application Protocol"
#define PSNAME "LCSAP"
#define PFNAME "lcsap"

static dissector_handle_t lpp_handle;
static dissector_handle_t lppa_handle;

#define SCTP_PORT_LCSAP 9082
#include "packet-lcsap-val.h"
/* Strcture to hold ProcedureCode */
struct pro_code {
        guint8 code;
} _pro_code;

/* Initialize the protocol and registered fields */
static int proto_lcsap  =   -1;
#include "packet-lcsap-hf.c"

/* Initialize the subtree pointers */
static int ett_lcsap = -1;

#include "packet-lcsap-ett.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint32 ProtocolExtensionID;
static guint32 PayloadType = -1;
static guint gbl_lcsapSctpPort=SCTP_PORT_LCSAP;

/* Dissector tables */
static dissector_table_t lcsap_ies_dissector_table;

static dissector_table_t lcsap_extension_dissector_table;
static dissector_table_t lcsap_proc_imsg_dissector_table;
static dissector_table_t lcsap_proc_sout_dissector_table;
static dissector_table_t lcsap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#include "packet-lcsap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(lcsap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}


static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(lcsap_extension_dissector_table, ProtocolExtensionID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(lcsap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(lcsap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(lcsap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}


static void
dissect_lcsap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*lcsap_item = NULL;
	proto_tree	*lcsap_tree = NULL;

	/* make entry in the Protocol column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "LCSAP");

	/* create the lcsap protocol tree */
	lcsap_item = proto_tree_add_item(tree, proto_lcsap, tvb, 0, -1, ENC_NA);
	lcsap_tree = proto_item_add_subtree(lcsap_item, ett_lcsap);

	dissect_LCS_AP_PDU_PDU(tvb, pinfo, lcsap_tree);
}

/*--- proto_reg_handoff_lcsap ---------------------------------------*/
void
proto_reg_handoff_lcsap(void)
{
	static gboolean Initialized=FALSE;
	static dissector_handle_t lcsap_handle;
	static guint SctpPort;

	if (!Initialized) {
		lcsap_handle = find_dissector("lcsap");
		lpp_handle = find_dissector("lpp");
		lppa_handle = find_dissector("lppa");
		dissector_add_handle("sctp.port", lcsap_handle);   /* for "decode-as"  */
		dissector_add_uint("sctp.ppi", LCS_AP_PAYLOAD_PROTOCOL_ID,   lcsap_handle);
		Initialized=TRUE;
#include "packet-lcsap-dis-tab.c"
	} else {
		if (SctpPort != 0) {
			dissector_delete_uint("sctp.port", SctpPort, lcsap_handle);
		}
	}

	SctpPort=gbl_lcsapSctpPort;
	if (SctpPort != 0) {
		dissector_add_uint("sctp.port", SctpPort, lcsap_handle);
	}
}

/*--- proto_register_lcsap -------------------------------------------*/
void proto_register_lcsap(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-lcsap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_lcsap,
#include "packet-lcsap-ettarr.c"
 };

  module_t *lcsap_module;

  /* Register protocol */
  proto_lcsap = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_lcsap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("lcsap", dissect_lcsap, proto_lcsap);

  /* Register dissector tables */
  lcsap_ies_dissector_table = register_dissector_table("lcsap.ies", "LCS-AP-PROTOCOL-IES", FT_UINT32, BASE_DEC);


  lcsap_extension_dissector_table = register_dissector_table("lcsap.extension", "LCS-AP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  lcsap_proc_imsg_dissector_table = register_dissector_table("lcsap.proc.imsg", "LCS-AP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_UINT32, BASE_DEC);
  lcsap_proc_sout_dissector_table = register_dissector_table("lcsap.proc.sout", "LCS-AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_UINT32, BASE_DEC);
  lcsap_proc_uout_dissector_table = register_dissector_table("lcsap.proc.uout", "LCS-AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_UINT32, BASE_DEC);

  /* Register configuration options for ports */
  lcsap_module = prefs_register_protocol(proto_lcsap, proto_reg_handoff_lcsap);

  prefs_register_uint_preference(lcsap_module, "sctp.port",
                                 "LCSAP SCTP Port",
                                 "Set the SCTP port for LCSAP messages",
                                 10,
                                 &gbl_lcsapSctpPort);

}


