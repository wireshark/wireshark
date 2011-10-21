/* packet-sbap.c
 * Routines for UTRAN Iu-BC Interface: Service Area Broadcast Protocol (SBAP) packet dissection
 * Copyright 2007, Tomas Kukosa <tomas.kukosa@siemens.com>
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
 * Ref: 3GPP TS 25.419 version  V9.0.0 (2009-12)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <epan/asn1.h>

#include "packet-tcp.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-gsm_map.h"
#include "packet-gsm_sms.h"
#include <epan/sctpppids.h>

#define PNAME  "UTRAN IuBC interface SABP signaling"
#define PSNAME "SABP"
#define PFNAME "sabp"

#include "packet-sabp-val.h"

/* Initialize the protocol and registered fields */
static int proto_sabp = -1;

static int hf_sabp_no_of_pages = -1;
#include "packet-sabp-hf.c"

/* Initialize the subtree pointers */
static int ett_sabp = -1;
static int ett_sabp_e212 = -1;
static int ett_sabp_cbs_data_coding = -1;
static int ett_sabp_bcast_msg = -1;

#include "packet-sabp-ett.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint32 ProtocolExtensionID;
static guint8 sms_encoding;

/* desegmentation of sabp over TCP */
static gboolean gbl_sabp_desegment = TRUE;

/* Dissector tables */
static dissector_table_t sabp_ies_dissector_table;
static dissector_table_t sabp_extension_dissector_table;
static dissector_table_t sabp_proc_imsg_dissector_table;
static dissector_table_t sabp_proc_sout_dissector_table;
static dissector_table_t sabp_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#include "packet-sabp-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(sabp_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(sabp_extension_dissector_table, ProtocolExtensionID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(sabp_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(sabp_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(sabp_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static guint
get_sabp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint32 type_length;
	int bit_offset;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);

	/* Length should be in the 3:d octet */
	offset = offset + 3;

	bit_offset = offset<<3;
	/* Get the length of the sabp packet. offset in bits  */
	offset = dissect_per_length_determinant(tvb, bit_offset, &asn1_ctx, NULL, -1, &type_length);

	/*
	 * Return the length of the PDU
	 * which is 3 + the length of the length, we only care about length up to 16K
	 * ("n" less than 128) a single octet containing "n" with bit 8 set to zero;
	 * ("n" less than 16K) two octets containing "n" with bit 8 of the first octet set to 1 and bit 7 set to zero;
	 */
	if (type_length < 128)
		return type_length+4;

	return type_length+5;
}


static void
dissect_sabp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*sabp_item = NULL;
	proto_tree	*sabp_tree = NULL;

	/* make entry in the Protocol column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

	/* create the sbap protocol tree */
	sabp_item = proto_tree_add_item(tree, proto_sabp, tvb, 0, -1, ENC_NA);
	sabp_tree = proto_item_add_subtree(sabp_item, ett_sabp);

	dissect_SABP_PDU_PDU(tvb, pinfo, sabp_tree);
}

/* Note a little bit of a hack assumes length max takes two bytes and that the length starts at byte 4 */
static void
dissect_sabp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, gbl_sabp_desegment, 5,
					 get_sabp_pdu_len, dissect_sabp);
}

/*--- proto_register_sbap -------------------------------------------*/
void proto_register_sabp(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_sabp_no_of_pages,
      { "Number-of-Pages", "sabp.no_of_pages",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},

#include "packet-sabp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_sabp,
		  &ett_sabp_e212,
		  &ett_sabp_cbs_data_coding,
		  &ett_sabp_bcast_msg,
#include "packet-sabp-ettarr.c"
  };


  /* Register protocol */
  proto_sabp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_sabp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  register_dissector("sabp", dissect_sabp, proto_sabp);
  register_dissector("sabp.tcp", dissect_sabp_tcp, proto_sabp);

  /* Register dissector tables */
  sabp_ies_dissector_table = register_dissector_table("sabp.ies", "SABP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  sabp_extension_dissector_table = register_dissector_table("sabp.extension", "SABP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  sabp_proc_imsg_dissector_table = register_dissector_table("sabp.proc.imsg", "SABP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_UINT32, BASE_DEC);
  sabp_proc_sout_dissector_table = register_dissector_table("sabp.proc.sout", "SABP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_UINT32, BASE_DEC);
  sabp_proc_uout_dissector_table = register_dissector_table("sabp.proc.uout", "SABP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_UINT32, BASE_DEC);

}


/*--- proto_reg_handoff_sbap ---------------------------------------*/
void
proto_reg_handoff_sabp(void)
{
  dissector_handle_t sabp_handle;
  dissector_handle_t sabp_tcp_handle;

  sabp_handle = find_dissector("sabp");
  sabp_tcp_handle = find_dissector("sabp.tcp");
  dissector_add_uint("udp.port", 3452, sabp_handle);
  dissector_add_uint("tcp.port", 3452, sabp_tcp_handle);
  dissector_add_uint("sctp.ppi", SABP_PAYLOAD_PROTOCOL_ID,   sabp_handle);

#include "packet-sabp-dis-tab.c"

}


