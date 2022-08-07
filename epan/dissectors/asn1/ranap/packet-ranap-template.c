/* packet-ranap.c
 * Routines for UMTS Node B Application Part(RANAP) packet dissection
 * Copyright 2005 - 2010, Anders Broman <anders.broman[AT]ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: 3GPP TS 25.413 version 10.4.0 Release 10
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-gsm_map.h"
#include "packet-ranap.h"
#include "packet-e212.h"
#include "packet-sccp.h"
#include "packet-gsm_a_common.h"
#include "packet-isup.h"
#include "packet-s1ap.h"
#include "packet-rtp.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define SCCP_SSN_RANAP 142

#define PNAME  "Radio Access Network Application Part"
#define PSNAME "RANAP"
#define PFNAME "ranap"

/* Highest Ranap_ProcedureCode_value, use in heuristics */
#define RANAP_MAX_PC  49 /* id_RerouteNASRequest =  49 */

#include "packet-ranap-val.h"

void proto_register_ranap(void);
void proto_reg_handoff_ranap(void);

/* Initialize the protocol and registered fields */
static int proto_ranap = -1;

/* initialise sub-dissector handles */
static dissector_handle_t rrc_s_to_trnc_handle = NULL;
static dissector_handle_t rrc_t_to_srnc_handle = NULL;
static dissector_handle_t rrc_ho_to_utran_cmd = NULL;
static dissector_handle_t bssgp_handle = NULL;

static int hf_ranap_transportLayerAddress_ipv4 = -1;
static int hf_ranap_transportLayerAddress_ipv6 = -1;
static int hf_ranap_transportLayerAddress_nsap = -1;

#include "packet-ranap-hf.c"

/* Initialize the subtree pointers */
static int ett_ranap = -1;
static int ett_ranap_transportLayerAddress = -1;
static int ett_ranap_transportLayerAddress_nsap = -1;

#include "packet-ranap-ett.c"

/*****************************************************************************/
/* Packet private data                                                       */
/* For this dissector, all access to actx->private_data should be made       */
/* through this API, which ensures that they will not overwrite each other!! */
/*****************************************************************************/


typedef struct ranap_private_data_t
{
  guint32 transportLayerAddress_ipv4;
  guint16 binding_id_port;
  e212_number_type_t number_type;
} ranap_private_data_t;


/* Helper function to get or create the private data struct */
static ranap_private_data_t* ranap_get_private_data(asn1_ctx_t *actx)
{
  packet_info *pinfo = actx->pinfo;
  ranap_private_data_t *private_data = (ranap_private_data_t *)p_get_proto_data(pinfo->pool, pinfo, proto_ranap, 0);
  if(private_data == NULL ) {
    private_data = wmem_new0(pinfo->pool, ranap_private_data_t);
    p_add_proto_data(pinfo->pool, pinfo, proto_ranap, 0, private_data);
  }
  return private_data;
}

/* Helper function to reset the private data struct */
static void ranap_reset_private_data(packet_info *pinfo)
{
  p_remove_proto_data(pinfo->pool, pinfo, proto_ranap, 0);
}

static guint32 private_data_get_transportLayerAddress_ipv4(asn1_ctx_t *actx)
{
  ranap_private_data_t *private_data = (ranap_private_data_t*)ranap_get_private_data(actx);
  return private_data->transportLayerAddress_ipv4;
}

static void private_data_set_transportLayerAddress_ipv4(asn1_ctx_t *actx, guint32 transportLayerAddress_ipv4)
{
  ranap_private_data_t *private_data = (ranap_private_data_t*)ranap_get_private_data(actx);
  private_data->transportLayerAddress_ipv4 = transportLayerAddress_ipv4;
}

static guint16 private_data_get_binding_id_port(asn1_ctx_t *actx)
{
  ranap_private_data_t *private_data = (ranap_private_data_t*)ranap_get_private_data(actx);
  return private_data->binding_id_port;
}

static void private_data_set_binding_id_port(asn1_ctx_t *actx, guint16 binding_id_port)
{
  ranap_private_data_t *private_data = (ranap_private_data_t*)ranap_get_private_data(actx);
  private_data->binding_id_port = binding_id_port;
}

/*****************************************************************************/


/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint32 ProtocolExtensionID;
static gboolean glbl_dissect_container = FALSE;

static dissector_handle_t ranap_handle;

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
 *  &InitiatingMessage        ,
 *  &SuccessfulOutcome        OPTIONAL,
 *  &UnsuccessfulOutcome      OPTIONAL,
 *  &Outcome                  OPTIONAL,
 *
 * Only these two needed currently
 */
#define IMSG (1U<<16)
#define SOUT (2U<<16)
#define SPECIAL (4U<<16)

int pdu_type = 0; /* 0 means wildcard */

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
      /* Fall through */
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

static int
dissect_ranap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  proto_item *ranap_item = NULL;
  proto_tree *ranap_tree = NULL;
  sccp_msg_info_t *sccp_msg_lcl = (sccp_msg_info_t *)data;

  pdu_type = 0;
  ProtocolIE_ID = 0;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "RANAP");

  /* create the ranap protocol tree */
  ranap_item = proto_tree_add_item(tree, proto_ranap, tvb, 0, -1, ENC_NA);
  ranap_tree = proto_item_add_subtree(ranap_item, ett_ranap);

  /* Save the sccp_msg_info_t data (if present) because it can't be passed
     through function calls */
  p_add_proto_data(pinfo->pool, pinfo, proto_ranap, pinfo->curr_layer_num, data);

  /* Clearing any old 'private data' stored */
  ranap_reset_private_data(pinfo);

  dissect_RANAP_PDU_PDU(tvb, pinfo, ranap_tree, NULL);
  if (sccp_msg_lcl) {

    if (sccp_msg_lcl->data.co.assoc)
      sccp_msg_lcl->data.co.assoc->payload = SCCP_PLOAD_RANAP;

    if (! sccp_msg_lcl->data.co.label && ProcedureCode != 0xFFFFFFFF) {
      const gchar* str = val_to_str(ProcedureCode, ranap_ProcedureCode_vals,"Unknown RANAP");
      sccp_msg_lcl->data.co.label = wmem_strdup(wmem_file_scope(), str);
    }
  }

  return tvb_reported_length(tvb);
}

#define RANAP_MSG_MIN_LENGTH 7
static gboolean
dissect_sccp_ranap_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  guint8 temp;
  guint16 word;
  guint length;
  int offset;

  /* Is it a ranap packet?
   *
   * 4th octet should be the length of the rest of the message.
   * 3th octed is the Criticality field
   * 2nd octet is the message-type e Z[0, 28]
   * 1st octet is the PDU type (with the extension bit)
   * (obviously there must be at least four octets)
   *
   * If all of them hold true we'll assume it's RANAP
   */

  #define LENGTH_OFFSET 3
  #define CRIT_OFFSET 2
  #define MSG_TYPE_OFFSET 1
  #define PDU_TYPE_OFFSET 0
  if (tvb_captured_length(tvb) < RANAP_MSG_MIN_LENGTH) { return FALSE; }

  temp = tvb_get_guint8(tvb, PDU_TYPE_OFFSET);
  if (temp & 0x1F) {
    /* PDU Type byte is not 0x00 (initiatingMessage), 0x20 (succesfulOutcome),
       0x40 (unsuccesfulOutcome) or 0x60 (outcome), ignore extension bit (0x80) */
    return FALSE;
  }

  temp = tvb_get_guint8(tvb, CRIT_OFFSET);
  if (temp == 0xC0 || temp & 0x3F) {
    /* Criticality byte is not 0x00 (reject), 0x40 (ignore) or 0x80 (notify) */
    return FALSE;
  }

  /* compute aligned PER length determinant without calling dissect_per_length_determinant()
     to avoid exceptions and info added to tree, info column and expert info */
  offset = LENGTH_OFFSET;
  length = tvb_get_guint8(tvb, offset);
  offset += 1;
  if ((length & 0x80) == 0x80) {
    if ((length & 0xc0) == 0x80) {
      length &= 0x3f;
      length <<= 8;
      length += tvb_get_guint8(tvb, offset);
      offset += 1;
    } else {
      length = 0;
    }
  }
  if (length!= (tvb_reported_length(tvb) - offset)){
    return FALSE;
  }

  temp = tvb_get_guint8(tvb, MSG_TYPE_OFFSET);
  if (temp > RANAP_MAX_PC) { return FALSE; }

  /* Try to strengthen the heuristic further, by checking the byte following the length and the bitfield indicating extensions etc
   * which usually is a sequence-of length
   */
  word = tvb_get_ntohs(tvb, offset + 1);
  if (word > 0x1ff){
    return FALSE;
  }
  dissect_ranap(tvb, pinfo, tree, data);

  return TRUE;
}

/*--- proto_register_ranap -------------------------------------------*/
void proto_register_ranap(void) {
  module_t *ranap_module;

  /* List of fields */

  static hf_register_info hf[] = {
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
    &ett_ranap_transportLayerAddress,
    &ett_ranap_transportLayerAddress_nsap,
#include "packet-ranap-ettarr.c"
  };


  /* Register protocol */
  proto_ranap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ranap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  ranap_handle = register_dissector("ranap", dissect_ranap, proto_ranap);

  /* Register dissector tables */
  ranap_ies_dissector_table = register_dissector_table("ranap.ies", "RANAP-PROTOCOL-IES", proto_ranap, FT_UINT32, BASE_DEC);
  ranap_ies_p1_dissector_table = register_dissector_table("ranap.ies.pair.first", "RANAP-PROTOCOL-IES-PAIR FirstValue", proto_ranap, FT_UINT32, BASE_DEC);
  ranap_ies_p2_dissector_table = register_dissector_table("ranap.ies.pair.second", "RANAP-PROTOCOL-IES-PAIR SecondValue", proto_ranap, FT_UINT32, BASE_DEC);
  ranap_extension_dissector_table = register_dissector_table("ranap.extension", "RANAP-PROTOCOL-EXTENSION", proto_ranap, FT_UINT32, BASE_DEC);
  ranap_proc_imsg_dissector_table = register_dissector_table("ranap.proc.imsg", "RANAP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_ranap, FT_UINT32, BASE_DEC);
  ranap_proc_sout_dissector_table = register_dissector_table("ranap.proc.sout", "RANAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_ranap, FT_UINT32, BASE_DEC);
  ranap_proc_uout_dissector_table = register_dissector_table("ranap.proc.uout", "RANAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_ranap, FT_UINT32, BASE_DEC);
  ranap_proc_out_dissector_table = register_dissector_table("ranap.proc.out", "RANAP-ELEMENTARY-PROCEDURE Outcome", proto_ranap, FT_UINT32, BASE_DEC);

  nas_pdu_dissector_table = register_dissector_table("ranap.nas_pdu", "RANAP NAS PDU", proto_ranap, FT_UINT8, BASE_DEC);

  ranap_module = prefs_register_protocol(proto_ranap, NULL);
  prefs_register_bool_preference(ranap_module, "dissect_rrc_container",
                                 "Attempt to dissect RRC-Container",
                                 "Attempt to dissect RRC message embedded in RRC-Container IE",
                                 &glbl_dissect_container);
}


/*--- proto_reg_handoff_ranap ---------------------------------------*/
void
proto_reg_handoff_ranap(void)
{
  rrc_s_to_trnc_handle = find_dissector_add_dependency("rrc.s_to_trnc_cont", proto_ranap);
  rrc_t_to_srnc_handle = find_dissector_add_dependency("rrc.t_to_srnc_cont", proto_ranap);
  rrc_ho_to_utran_cmd = find_dissector_add_dependency("rrc.irat.ho_to_utran_cmd", proto_ranap);
  bssgp_handle = find_dissector("bssgp");
  heur_dissector_add("sccp", dissect_sccp_ranap_heur, "RANAP over SCCP", "ranap_sccp", proto_ranap, HEURISTIC_ENABLE);
  heur_dissector_add("sua", dissect_sccp_ranap_heur, "RANAP over SUA", "ranap_sua", proto_ranap, HEURISTIC_ENABLE);
  dissector_add_uint_with_preference("sccp.ssn", SCCP_SSN_RANAP, ranap_handle);
#include "packet-ranap-dis-tab.c"

}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
