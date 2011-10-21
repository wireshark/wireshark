/* packet-nbap-template.c
 * Routines for UMTS Node B Application Part(NBAP) packet dissection
 * Copyright 2005, 2009 Anders Broman <anders.broman@ericsson.com>
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
 * Ref: 3GPP TS 25.433 version 6.6.0 Release 6
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/sctpppids.h>
#include <epan/asn1.h>

#include "packet-per.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "UTRAN Iub interface NBAP signalling"
#define PSNAME "NBAP"
#define PFNAME "nbap"

#include "packet-nbap-val.h"

/* Initialize the protocol and registered fields */
static int proto_nbap = -1;
static int hf_nbap_transportLayerAddress_ipv4 = -1;
static int hf_nbap_transportLayerAddress_ipv6 = -1;

#include "packet-nbap-hf.c"

/* Initialize the subtree pointers */
static int ett_nbap = -1;
static int ett_nbap_TransportLayerAddress = -1;

#include "packet-nbap-ett.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint32 ddMode;
static const gchar *ProcedureID;

/* Dissector tables */
static dissector_table_t nbap_ies_dissector_table;
static dissector_table_t nbap_extension_dissector_table;
static dissector_table_t nbap_proc_imsg_dissector_table;
static dissector_table_t nbap_proc_sout_dissector_table;
static dissector_table_t nbap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#include "packet-nbap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(nbap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(nbap_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(nbap_proc_imsg_dissector_table, ProcedureID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(nbap_proc_sout_dissector_table, ProcedureID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!ProcedureID) return 0;
  return (dissector_try_string(nbap_proc_uout_dissector_table, ProcedureID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static void
dissect_nbap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*nbap_item = NULL;
	proto_tree	*nbap_tree = NULL;

	/* make entry in the Protocol column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NBAP");

	/* create the nbap protocol tree */
	nbap_item = proto_tree_add_item(tree, proto_nbap, tvb, 0, -1, ENC_NA);
	nbap_tree = proto_item_add_subtree(nbap_item, ett_nbap);

	dissect_NBAP_PDU_PDU(tvb, pinfo, nbap_tree);
}

/*--- proto_register_nbap -------------------------------------------*/
void proto_register_nbap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_nbap_transportLayerAddress_ipv4,
      { "transportLayerAddress IPv4", "nbap.transportLayerAddress_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nbap_transportLayerAddress_ipv6,
      { "transportLayerAddress IPv6", "nbap.transportLayerAddress_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},

#include "packet-nbap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_nbap,
		  &ett_nbap_TransportLayerAddress,
#include "packet-nbap-ettarr.c"
  };


  /* Register protocol */
  proto_nbap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_nbap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  register_dissector("nbap", dissect_nbap, proto_nbap);

  /* Register dissector tables */
  nbap_ies_dissector_table = register_dissector_table("nbap.ies", "NBAP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  nbap_extension_dissector_table = register_dissector_table("nbap.extension", "NBAP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  nbap_proc_imsg_dissector_table = register_dissector_table("nbap.proc.imsg", "NBAP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_STRING, BASE_NONE);
  nbap_proc_sout_dissector_table = register_dissector_table("nbap.proc.sout", "NBAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_STRING, BASE_NONE);
  nbap_proc_uout_dissector_table = register_dissector_table("nbap.proc.uout", "NBAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_STRING, BASE_NONE);

}


/*--- proto_reg_handoff_nbap ---------------------------------------*/
void
proto_reg_handoff_nbap(void)
{
	dissector_handle_t nbap_handle;

	nbap_handle = find_dissector("nbap");
	dissector_add_uint("sctp.ppi", NBAP_PAYLOAD_PROTOCOL_ID, nbap_handle);
	dissector_add_handle("sctp.port", nbap_handle);  /* for "decode-as" */

#include "packet-nbap-dis-tab.c"
}


