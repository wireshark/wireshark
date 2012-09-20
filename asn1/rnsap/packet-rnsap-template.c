/* packet-rnsap.c
 * Routines for dissecting Universal Mobile Telecommunications System (UMTS);
 * UTRAN Iur interface Radio Network Subsystem
 * Application Part (RNSAP) signalling
 * (3GPP TS 25.423 version 6.7.0 Release 6) packet dissection
 * Copyright 2005 - 2006, Anders Broman <anders.broman@ericsson.com>
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
 *
 * Ref: 3GPP TS 25.423 version 6.7.0 Release 6
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-ber.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "UTRAN Iur interface Radio Network Subsystem Application Part"
#define PSNAME "RNSAP"
#define PFNAME "rnsap"

#define SCCP_SSN_RNSAP 143

#include "packet-rnsap-val.h"

static dissector_handle_t rrc_dl_dcch_handle = NULL;

/* Initialize the protocol and registered fields */
static int proto_rnsap = -1;

#include "packet-rnsap-hf.c"

/* Initialize the subtree pointers */
static int ett_rnsap = -1;

#include "packet-rnsap-ett.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint32 ddMode;
static const gchar *ProcedureID;
static const char *obj_id = NULL;


/* Dissector tables */
static dissector_table_t rnsap_ies_dissector_table;
static dissector_table_t rnsap_extension_dissector_table;
static dissector_table_t rnsap_proc_imsg_dissector_table;
static dissector_table_t rnsap_proc_sout_dissector_table;
static dissector_table_t rnsap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_PrivateIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

#include "packet-rnsap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(rnsap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(rnsap_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_PrivateIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (call_ber_oid_callback(obj_id, tvb, 0, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(rnsap_proc_imsg_dissector_table, ProcedureID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(rnsap_proc_sout_dissector_table, ProcedureID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(rnsap_proc_uout_dissector_table, ProcedureID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static void
dissect_rnsap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*rnsap_item = NULL;
	proto_tree	*rnsap_tree = NULL;

	/* make entry in the Protocol column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RNSAP");

	/* create the rnsap protocol tree */
	rnsap_item = proto_tree_add_item(tree, proto_rnsap, tvb, 0, -1, ENC_NA);
	rnsap_tree = proto_item_add_subtree(rnsap_item, ett_rnsap);
	
	dissect_RNSAP_PDU_PDU(tvb, pinfo, rnsap_tree);
}

/*--- proto_register_rnsap -------------------------------------------*/
void proto_register_rnsap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
#include "packet-rnsap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_rnsap,
#include "packet-rnsap-ettarr.c"
  };


  /* Register protocol */
  proto_rnsap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_rnsap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
 
  /* Register dissector */
  register_dissector("rnsap", dissect_rnsap, proto_rnsap);

  /* Register dissector tables */
  rnsap_ies_dissector_table = register_dissector_table("rnsap.ies", "RNSAP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  rnsap_extension_dissector_table = register_dissector_table("rnsap.extension", "RNSAP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  rnsap_proc_imsg_dissector_table = register_dissector_table("rnsap.proc.imsg", "RNSAP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_STRING, BASE_NONE);
  rnsap_proc_sout_dissector_table = register_dissector_table("rnsap.proc.sout", "RNSAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_STRING, BASE_NONE);
  rnsap_proc_uout_dissector_table = register_dissector_table("rnsap.proc.uout", "RNSAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_STRING, BASE_NONE);

}


/*--- proto_reg_handoff_rnsap ---------------------------------------*/
void
proto_reg_handoff_rnsap(void)
{
	dissector_handle_t rnsap_handle;

	rnsap_handle = find_dissector("rnsap");
	rrc_dl_dcch_handle = find_dissector("rrc.dl.dcch");

	dissector_add_uint("sccp.ssn", SCCP_SSN_RNSAP, rnsap_handle);
	/* Add heuristic dissector
	 * Perhaps we want a preference whether the heuristic dissector
	 * is or isn't enabled
	 */
	/*heur_dissector_add("sccp", dissect_sccp_rnsap_heur, proto_rnsap); */

#include "packet-rnsap-dis-tab.c"
}


