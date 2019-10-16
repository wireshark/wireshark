/* packet-rnsap.c
 * Routines for dissecting Universal Mobile Telecommunications System (UMTS);
 * UTRAN Iur interface Radio Network Subsystem
 * Application Part (RNSAP) signalling
 * (3GPP TS 25.423 version 6.7.0 Release 6) packet dissection
 * Copyright 2005 - 2006, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref: 3GPP TS 25.423 version 6.7.0 Release 6
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>

#include "packet-isup.h"
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

void proto_register_rnsap(void);
void proto_reg_handoff_rnsap(void);

typedef struct {
    guint32     ProcedureCode;
    guint32     ProtocolIE_ID;
    guint32     ddMode;
    const char *ProcedureID;
    const char *obj_id;
} rnsap_private_data_t;

static dissector_handle_t ranap_handle = NULL;
static dissector_handle_t rrc_dl_ccch_handle = NULL;
static dissector_handle_t rrc_ul_ccch_handle = NULL;

/* Initialize the protocol and registered fields */
static int proto_rnsap = -1;

static int hf_rnsap_transportLayerAddress_ipv4 = -1;
static int hf_rnsap_transportLayerAddress_ipv6 = -1;
static int hf_rnsap_transportLayerAddress_nsap = -1;
#include "packet-rnsap-hf.c"

/* Initialize the subtree pointers */
static int ett_rnsap = -1;
static int ett_rnsap_transportLayerAddress = -1;
static int ett_rnsap_transportLayerAddress_nsap = -1;

#include "packet-rnsap-ett.c"


/* Dissector tables */
static dissector_table_t rnsap_ies_dissector_table;
static dissector_table_t rnsap_extension_dissector_table;
static dissector_table_t rnsap_proc_imsg_dissector_table;
static dissector_table_t rnsap_proc_sout_dissector_table;
static dissector_table_t rnsap_proc_uout_dissector_table;

static dissector_handle_t rnsap_handle;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_PrivateIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static rnsap_private_data_t *
rnsap_get_private_data(packet_info *pinfo)
{

    rnsap_private_data_t *pdata = (rnsap_private_data_t *)p_get_proto_data(pinfo->pool, pinfo, proto_rnsap, 0);
    if (!pdata) {
        pdata = wmem_new0(pinfo->pool, rnsap_private_data_t);
        pdata->ProcedureCode = 0xFFFF;
        pdata->ddMode = 0xFFFF;
        p_add_proto_data(pinfo->pool, pinfo, proto_rnsap, 0, pdata);
    }
    return pdata;
}

#include "packet-rnsap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  rnsap_private_data_t *pdata = rnsap_get_private_data(pinfo);
  return (dissector_try_uint(rnsap_ies_dissector_table, pdata->ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  rnsap_private_data_t *pdata = rnsap_get_private_data(pinfo);
  return (dissector_try_uint(rnsap_extension_dissector_table, pdata->ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_PrivateIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  rnsap_private_data_t *pdata = rnsap_get_private_data(pinfo);
  return (call_ber_oid_callback(pdata->obj_id, tvb, 0, pinfo, tree, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  rnsap_private_data_t *pdata = rnsap_get_private_data(pinfo);
  if (!pdata->ProcedureID) return 0;
  return (dissector_try_string(rnsap_proc_imsg_dissector_table, pdata->ProcedureID, tvb, pinfo, tree, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  rnsap_private_data_t *pdata = rnsap_get_private_data(pinfo);
  if (!pdata->ProcedureID) return 0;
  return (dissector_try_string(rnsap_proc_sout_dissector_table, pdata->ProcedureID, tvb, pinfo, tree, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  rnsap_private_data_t *pdata = rnsap_get_private_data(pinfo);
  if (!pdata->ProcedureID) return 0;
  return (dissector_try_string(rnsap_proc_uout_dissector_table, pdata->ProcedureID, tvb, pinfo, tree, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_rnsap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	proto_item	*rnsap_item = NULL;
	proto_tree	*rnsap_tree = NULL;

	/* make entry in the Protocol column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RNSAP");

	/* create the rnsap protocol tree */
	rnsap_item = proto_tree_add_item(tree, proto_rnsap, tvb, 0, -1, ENC_NA);
	rnsap_tree = proto_item_add_subtree(rnsap_item, ett_rnsap);

	/* remove any rnsap_private_data_t state from previous PDUs in this packet. */
	p_remove_proto_data(pinfo->pool, pinfo, proto_rnsap, 0);

	return dissect_RNSAP_PDU_PDU(tvb, pinfo, rnsap_tree, data);
}

/* Highest ProcedureCode value, used in heuristics */
#define RNSAP_MAX_PC 61 /* id-enhancedRelocationResourceRelease = 61*/
#define RNSAP_MSG_MIN_LENGTH 7
static gboolean
dissect_sccp_rnsap_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  guint8 pdu_type;
  guint8 procedure_id;
  guint8 dd_mode;
  guint8 criticality;
  guint8 transaction_id_type;
  guint length;
  int length_field_offset;

  #define PDU_TYPE_OFFSET 0
  #define PROC_CODE_OFFSET 1
  #define DD_CRIT_OFFSET 2
  if (tvb_captured_length(tvb) < RNSAP_MSG_MIN_LENGTH) {
    return FALSE;
  }

  pdu_type = tvb_get_guint8(tvb, PDU_TYPE_OFFSET);
  if (pdu_type & 0x1F) {
    /* pdu_type is not 0x00 (initiatingMessage), 0x20 (succesfulOutcome),
       0x40 (unsuccesfulOutcome) or 0x60 (outcome), ignore extension bit (0x80) */
    return FALSE;
  }

  procedure_id = tvb_get_guint8(tvb, PROC_CODE_OFFSET);
  if (procedure_id > RNSAP_MAX_PC) {
      return FALSE;
  }

  dd_mode = tvb_get_guint8(tvb, DD_CRIT_OFFSET) >> 5;
  if (dd_mode >= 0x03) {
    /* dd_mode is not 0x00 (tdd), 0x01 (fdd) or 0x02 (common) */
    return FALSE;
  }

  criticality = (tvb_get_guint8(tvb, DD_CRIT_OFFSET) & 0x18) >> 3;
  if (criticality == 0x03) {
    /* criticality is not 0x00 (reject), 0x01 (ignore) or 0x02 (notify) */
    return FALSE;
  }

  /* Finding the offset for the length field - depends on wether the transaction id is long or short */
  transaction_id_type = (tvb_get_guint8(tvb, DD_CRIT_OFFSET) & 0x04) >> 2;
  if(transaction_id_type == 0x00) { /* Short transaction id - 1 byte*/
    length_field_offset = 4;
  }
  else { /* Long transaction id - 2 bytes*/
    length_field_offset = 5;
  }

  /* compute aligned PER length determinant without calling dissect_per_length_determinant()
     to avoid exceptions and info added to tree, info column and expert info */
  length = tvb_get_guint8(tvb, length_field_offset);
  length_field_offset += 1;
  if (length & 0x80) {
    if ((length & 0xc0) == 0x80) {
      length &= 0x3f;
      length <<= 8;
      length += tvb_get_guint8(tvb, length_field_offset);
      length_field_offset += 1;
    } else {
      length = 0;
    }
  }
  if (length!= (tvb_reported_length(tvb) - length_field_offset)){
    return FALSE;
  }

  dissect_rnsap(tvb, pinfo, tree, data);

  return TRUE;
}


/*--- proto_register_rnsap -------------------------------------------*/
void proto_register_rnsap(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_rnsap_transportLayerAddress_ipv4,
      { "transportLayerAddress IPv4", "rnsap.transportLayerAddress_ipv4",
      FT_IPv4, BASE_NONE, NULL, 0,
    NULL, HFILL }},
    { &hf_rnsap_transportLayerAddress_ipv6,
      { "transportLayerAddress IPv6", "rnsap.transportLayerAddress_ipv6",
      FT_IPv6, BASE_NONE, NULL, 0,
      NULL, HFILL }},
    { &hf_rnsap_transportLayerAddress_nsap,
      { "transportLayerAddress NSAP", "rnsap.transportLayerAddress_NSAP",
      FT_BYTES, BASE_NONE, NULL, 0,
      NULL, HFILL }},
#include "packet-rnsap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_rnsap,
    &ett_rnsap_transportLayerAddress,
    &ett_rnsap_transportLayerAddress_nsap,
#include "packet-rnsap-ettarr.c"
  };


  /* Register protocol */
  proto_rnsap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_rnsap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  rnsap_handle = register_dissector("rnsap", dissect_rnsap, proto_rnsap);

  /* Register dissector tables */
  rnsap_ies_dissector_table = register_dissector_table("rnsap.ies", "RNSAP-PROTOCOL-IES", proto_rnsap, FT_UINT32, BASE_DEC);
  rnsap_extension_dissector_table = register_dissector_table("rnsap.extension", "RNSAP-PROTOCOL-EXTENSION", proto_rnsap, FT_UINT32, BASE_DEC);
  rnsap_proc_imsg_dissector_table = register_dissector_table("rnsap.proc.imsg", "RNSAP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_rnsap, FT_STRING, BASE_NONE);
  rnsap_proc_sout_dissector_table = register_dissector_table("rnsap.proc.sout", "RNSAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_rnsap, FT_STRING, BASE_NONE);
  rnsap_proc_uout_dissector_table = register_dissector_table("rnsap.proc.uout", "RNSAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_rnsap, FT_STRING, BASE_NONE);

}


/*--- proto_reg_handoff_rnsap ---------------------------------------*/
void
proto_reg_handoff_rnsap(void)
{
	ranap_handle = find_dissector("ranap");
	rrc_dl_ccch_handle = find_dissector_add_dependency("rrc.dl.ccch", proto_rnsap);
	rrc_ul_ccch_handle = find_dissector_add_dependency("rrc.ul.ccch", proto_rnsap);

	dissector_add_uint("sccp.ssn", SCCP_SSN_RNSAP, rnsap_handle);
	heur_dissector_add("sccp", dissect_sccp_rnsap_heur, "RNSAP over SCCP", "rnsap_sccp", proto_rnsap, HEURISTIC_ENABLE);

#include "packet-rnsap-dis-tab.c"
}


