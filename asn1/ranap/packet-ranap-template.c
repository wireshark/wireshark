/* packet-ranap.c
 * Routines for UMTS Node B Application Part(RANAP) packet dissection
 * Copyright 2005 - 2010, Anders Broman <anders.broman[AT]ericsson.com>
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
 * References: 3GPP TS 25.413 version 10.4.0 Release 10
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

#include <epan/wmem/wmem.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-gsm_map.h"
#include "packet-ranap.h"
#include "packet-e212.h"
#include "packet-sccp.h"
#include "packet-gsm_a_common.h"
#include "packet-isup.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define SCCP_SSN_RANAP 142

#define PNAME  "Radio Access Network Application Part"
#define PSNAME "RANAP"
#define PFNAME "ranap"

/* Higest Ranap_ProcedureCode_value, use in heuristics */
#define RANAP_MAX_PC  45 /* id_RANAPenhancedRelocation =  45 */

#include "packet-ranap-val.h"

void proto_register_ranap(void);
void proto_reg_handoff_ranap(void);

/* Initialize the protocol and registered fields */
static int proto_ranap = -1;

/* initialise sub-dissector handles */
static dissector_handle_t rrc_s_to_trnc_handle = NULL;
static dissector_handle_t rrc_t_to_srnc_handle = NULL;
static dissector_handle_t rrc_ho_to_utran_cmd = NULL;

static int hf_ranap_imsi_digits = -1;
static int hf_ranap_transportLayerAddress_ipv4 = -1;
static int hf_ranap_transportLayerAddress_ipv6 = -1;
static int hf_ranap_transportLayerAddress_nsap = -1;

#include "packet-ranap-hf.c"

/* Initialize the subtree pointers */
static int ett_ranap = -1;
static int ett_ranap_TransportLayerAddress = -1;
static int ett_ranap_TransportLayerAddress_nsap = -1;

#include "packet-ranap-ett.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint32 ProtocolExtensionID;
static gboolean glbl_dissect_container = FALSE;
/* Some IE:s identities uses the same value for different IE:s
 * depending on PDU type:
 * InitiatingMessage
 * SuccessfulOutcome
 * UnsuccessfulOutcome
 * Outcome
 * As a workarond a value is added to the IE:id in the .cnf file.
 * Example:
 * ResetResourceList                N rnsap.ies IMSG||id-IuSigConIdList  # no spaces are allowed in value as a space is delimiter
 * PDU type is stored in a global variable and can is used in the IE decoding section.
 */
/*
 * 	&InitiatingMessage				,
 *	&SuccessfulOutcome				OPTIONAL,
 *	&UnsuccessfulOutcome				OPTIONAL,
 *	&Outcome					OPTIONAL,
 *
 * Only these two needed currently
 */
#define IMSG (1<<16)
#define SOUT (2<<16)
#define SPECIAL (4<<16)

int pdu_type = 0; /* 0 means wildcard */

/* Initialise the Preferences */
static gint global_ranap_sccp_ssn = SCCP_SSN_RANAP;

/* Dissector tables */
static dissector_table_t ranap_ies_dissector_table;
static dissector_table_t ranap_ies_p1_dissector_table;
static dissector_table_t ranap_ies_p2_dissector_table;
static dissector_table_t ranap_extension_dissector_table;
static dissector_table_t ranap_proc_imsg_dissector_table;
static dissector_table_t ranap_proc_sout_dissector_table;
static dissector_table_t ranap_proc_uout_dissector_table;
static dissector_table_t ranap_proc_out_dissector_table;
static dissector_table_t nas_pdu_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_OutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static int dissect_ranap_SourceRNC_ToTargetRNC_TransparentContainer(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
static int dissect_ranap_TargetRNC_ToSourceRNC_TransparentContainer(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);


#include "packet-ranap-fn.c"

static int
dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

  int ret = 0;
  int key;

  /* Special handling, same ID used for different IE's depending on signal */
  switch(ProcedureCode){
	  case id_RelocationPreparation:
		  if((ProtocolIE_ID == id_Source_ToTarget_TransparentContainer)||(ProtocolIE_ID == id_Target_ToSource_TransparentContainer)){
			  key = SPECIAL | ProtocolIE_ID;
			  ret = (dissector_try_uint_new(ranap_ies_dissector_table, key, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
			  break;
		  }
		  /* Fall trough */
	  default:
		  /* no special handling */
		  ret = (dissector_try_uint_new(ranap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
		  if (ret == 0) {
			  key = pdu_type | ProtocolIE_ID;
			  ret = (dissector_try_uint_new(ranap_ies_dissector_table, key, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
		  }
		  break;
  }
  return ret;
}

static int
dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(ranap_ies_p1_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(ranap_ies_p2_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(ranap_extension_dissector_table, ProtocolExtensionID, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  gboolean ret;

  pdu_type = IMSG;
  ret = dissector_try_uint_new(ranap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE, NULL);
  pdu_type = 0;
  return ret ? tvb_captured_length(tvb) : 0;
}

static int
dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  gboolean ret;

  pdu_type = SOUT;
  ret = dissector_try_uint_new(ranap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE, NULL);
  pdu_type = 0;
  return ret ? tvb_captured_length(tvb) : 0;
}

static int
dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(ranap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_OutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(ranap_proc_out_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static void
dissect_ranap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*ranap_item = NULL;
	proto_tree	*ranap_tree = NULL;

	pdu_type = 0;
	ProtocolIE_ID = 0;

	/* make entry in the Protocol column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RANAP");

	/* create the ranap protocol tree */
	ranap_item = proto_tree_add_item(tree, proto_ranap, tvb, 0, -1, ENC_NA);
	ranap_tree = proto_item_add_subtree(ranap_item, ett_ranap);

	dissect_RANAP_PDU_PDU(tvb, pinfo, ranap_tree, NULL);
	if (pinfo->sccp_info) {
		sccp_msg_info_t* sccp_msg_lcl = pinfo->sccp_info;

		if (sccp_msg_lcl->data.co.assoc)
			sccp_msg_lcl->data.co.assoc->payload = SCCP_PLOAD_RANAP;

		if (! sccp_msg_lcl->data.co.label && ProcedureCode != 0xFFFFFFFF) {
			const gchar* str = val_to_str(ProcedureCode, ranap_ProcedureCode_vals,"Unknown RANAP");
			sccp_msg_lcl->data.co.label = wmem_strdup(wmem_file_scope(), str);
		}
	}
}

#define RANAP_MSG_MIN_LENGTH 7
static gboolean
dissect_sccp_ranap_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8 temp;
	guint16 word;
	asn1_ctx_t asn1_ctx;
	guint length;
	int offset;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);

    /* Is it a ranap packet?
     *
     * 4th octet should be the length of the rest of the message.
     * 2nd octet is the message-type e Z[0, 28]
     * (obviously there must be at least four octets)
     *
     * If both hold true we'll assume its RANAP
     */

    #define LENGTH_OFFSET 3
    #define MSG_TYPE_OFFSET 1
    if (tvb_captured_length(tvb) < RANAP_MSG_MIN_LENGTH) { return FALSE; }
	/* Read the length NOTE offset in bits */
	offset = dissect_per_length_determinant(tvb, LENGTH_OFFSET<<3, &asn1_ctx, tree, -1, &length);
	offset = offset>>3;
	if (length!= (tvb_reported_length(tvb) - offset)){
		return FALSE;
	}

    temp = tvb_get_guint8(tvb, MSG_TYPE_OFFSET);
    if (temp > RANAP_MAX_PC) { return FALSE; }

    /* Try to strengthen the heuristic further, by checking byte 6 and 7 which usually is a sequence-of length */
    word = tvb_get_ntohs(tvb,5);
    if(word > 0x1ff){
        return FALSE;
    }
    dissect_ranap(tvb, pinfo, tree);

    return TRUE;
}

/*--- proto_register_ranap -------------------------------------------*/
void proto_register_ranap(void) {
  module_t *ranap_module;

  /* List of fields */

  static hf_register_info hf[] = {
	{ &hf_ranap_imsi_digits,
      { "IMSI digits", "ranap.imsi_digits",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_transportLayerAddress_ipv4,
      { "transportLayerAddress IPv4", "ranap.transportLayerAddress_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_transportLayerAddress_ipv6,
      { "transportLayerAddress IPv6", "ranap.transportLayerAddress_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ranap_transportLayerAddress_nsap,
      { "transportLayerAddress NSAP", "ranap.transportLayerAddress_NSAP",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},


#include "packet-ranap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_ranap,
		  &ett_ranap_TransportLayerAddress,
		  &ett_ranap_TransportLayerAddress_nsap,
#include "packet-ranap-ettarr.c"
  };


  /* Register protocol */
  proto_ranap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ranap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  register_dissector("ranap", dissect_ranap, proto_ranap);

  /* Register dissector tables */
  ranap_ies_dissector_table = register_dissector_table("ranap.ies", "RANAP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  ranap_ies_p1_dissector_table = register_dissector_table("ranap.ies.pair.first", "RANAP-PROTOCOL-IES-PAIR FirstValue", FT_UINT32, BASE_DEC);
  ranap_ies_p2_dissector_table = register_dissector_table("ranap.ies.pair.second", "RANAP-PROTOCOL-IES-PAIR SecondValue", FT_UINT32, BASE_DEC);
  ranap_extension_dissector_table = register_dissector_table("ranap.extension", "RANAP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  ranap_proc_imsg_dissector_table = register_dissector_table("ranap.proc.imsg", "RANAP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_UINT32, BASE_DEC);
  ranap_proc_sout_dissector_table = register_dissector_table("ranap.proc.sout", "RANAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_UINT32, BASE_DEC);
  ranap_proc_uout_dissector_table = register_dissector_table("ranap.proc.uout", "RANAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_UINT32, BASE_DEC);
  ranap_proc_out_dissector_table = register_dissector_table("ranap.proc.out", "RANAP-ELEMENTARY-PROCEDURE Outcome", FT_UINT32, BASE_DEC);

  nas_pdu_dissector_table = register_dissector_table("ranap.nas_pdu", "RANAP NAS PDU", FT_UINT8, BASE_DEC);

  ranap_module = prefs_register_protocol(proto_ranap, proto_reg_handoff_ranap);
  prefs_register_uint_preference(ranap_module, "sccp_ssn", "SCCP SSN for RANAP",
				 "The SCCP SubSystem Number for RANAP (default 142)", 10,
				 &global_ranap_sccp_ssn);
  prefs_register_bool_preference(ranap_module, "dissect_rrc_container",
                                 "Attempt to dissect RRC-Container",
                                 "Attempt to dissect RRC message embedded in RRC-Container IE",
                                 &glbl_dissect_container);
}


/*--- proto_reg_handoff_ranap ---------------------------------------*/
void
proto_reg_handoff_ranap(void)
{
	static gboolean initialized = FALSE;
	static dissector_handle_t ranap_handle;
	static gint local_ranap_sccp_ssn;

	if (!initialized) {
		ranap_handle = find_dissector("ranap");
		rrc_s_to_trnc_handle = find_dissector("rrc.s_to_trnc_cont");
		rrc_t_to_srnc_handle = find_dissector("rrc.t_to_srnc_cont");
		rrc_ho_to_utran_cmd = find_dissector("rrc.irat.ho_to_utran_cmd");
		initialized = TRUE;
#include "packet-ranap-dis-tab.c"
	} else {
		dissector_delete_uint("sccp.ssn", local_ranap_sccp_ssn, ranap_handle);
	}

	dissector_add_uint("sccp.ssn", global_ranap_sccp_ssn, ranap_handle);
	local_ranap_sccp_ssn = global_ranap_sccp_ssn;
	/* Add heuristic dissector
	* Perhaps we want a preference whether the heuristic dissector
	* is or isn't enabled
	*/
	heur_dissector_add("sccp", dissect_sccp_ranap_heur, proto_ranap);
	heur_dissector_add("sua", dissect_sccp_ranap_heur, proto_ranap);
}


