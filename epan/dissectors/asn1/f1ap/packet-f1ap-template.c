/* packet-f1ap.c
 * Routines for E-UTRAN F1 Application Protocol (F1AP) packet dissection
 * Copyright 2018-2020, Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: 3GPP TS 38.473 V15.8.0 (2019-12)
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/asn1.h>
#include <epan/sctpppids.h>
#include <epan/proto_data.h>

#include "packet-per.h"
#include "packet-x2ap.h"
#include "packet-nr-rrc.h"
#include "packet-e212.h"
#include "packet-pdcp-nr.h"

#define PNAME  "F1 Application Protocol"
#define PSNAME "F1AP"
#define PFNAME "f1ap"

#define SCTP_PORT_F1AP 38472

void proto_register_f1ap(void);
void proto_reg_handoff_f1ap(void);

#include "packet-f1ap-val.h"

/* Initialize the protocol and registered fields */
static int proto_f1ap = -1;

static int hf_f1ap_transportLayerAddressIPv4 = -1;
static int hf_f1ap_transportLayerAddressIPv6 = -1;
#include "packet-f1ap-hf.c"

/* Initialize the subtree pointers */
static gint ett_f1ap = -1;
static gint ett_f1ap_ResourceCoordinationTransferContainer = -1;
static gint ett_f1ap_PLMN_Identity = -1;
static gint ett_f1ap_MIB_message = -1;
static gint ett_f1ap_SIB1_message = -1;
static gint ett_f1ap_CG_ConfigInfo = -1;
static gint ett_f1ap_CellGroupConfig = -1;
static gint ett_f1ap_TransportLayerAddress = -1;
static gint ett_f1ap_UE_CapabilityRAT_ContainerList = -1;
static gint ett_f1ap_measurementTimingConfiguration = -1;
static gint ett_f1ap_DUtoCURRCContainer = -1;
static gint ett_f1ap_requestedP_MaxFR1 = -1;
static gint ett_f1ap_HandoverPreparationInformation = -1;
static gint ett_f1ap_MeasConfig = -1;
static gint ett_f1ap_MeasGapConfig = -1;
static gint ett_f1ap_MeasGapSharingConfig = -1;
static gint ett_f1ap_EUTRA_NR_CellResourceCoordinationReq_Container = -1;
static gint ett_f1ap_EUTRA_NR_CellResourceCoordinationReqAck_Container = -1;
static gint ett_f1ap_ProtectedEUTRAResourceIndication = -1;
static gint ett_f1ap_RRCContainer = -1;
static gint ett_f1ap_RRCContainer_RRCSetupComplete = -1;
static gint ett_f1ap_sIBmessage = -1;
static gint ett_f1ap_UplinkTxDirectCurrentListInformation = -1;
static gint ett_f1ap_DRX_Config = -1;
static gint ett_f1ap_Ph_InfoSCG = -1;
static gint ett_f1ap_RequestedBandCombinationIndex = -1;
static gint ett_f1ap_RequestedFeatureSetEntryIndex = -1;
static gint ett_f1ap_RequestedP_MaxFR2 = -1;
static gint ett_f1ap_UEAssistanceInformation = -1;
static gint ett_f1ap_CG_Config = -1;
static gint ett_f1ap_Ph_InfoMCG = -1;
#include "packet-f1ap-ett.c"

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

typedef struct {
  guint32 message_type;
  guint32 procedure_code;
  guint32 protocol_ie_id;
  guint32 protocol_extension_id;
  const char *obj_id;
  guint32 sib_type;
  guint32 srb_id;
} f1ap_private_data_t;

typedef struct {
  guint32 message_type;
  guint32 ProcedureCode;
  guint32 ProtocolIE_ID;
  guint32 ProtocolExtensionID;
} f1ap_ctx_t;

/* Global variables */
static dissector_handle_t f1ap_handle;
static dissector_handle_t nr_rrc_ul_ccch_handle;
static dissector_handle_t nr_rrc_dl_ccch_handle;
static dissector_handle_t nr_rrc_ul_dcch_handle;
static dissector_handle_t nr_pdcp_handle;

/* Dissector tables */
static dissector_table_t f1ap_ies_dissector_table;
static dissector_table_t f1ap_extension_dissector_table;
static dissector_table_t f1ap_proc_imsg_dissector_table;
static dissector_table_t f1ap_proc_sout_dissector_table;
static dissector_table_t f1ap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static void
f1ap_MaxPacketLossRate_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1f%% (%u)", (float)v/10, v);
}

static void
f1ap_PacketDelayBudget_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%u)", (float)v/2, v);
}

static f1ap_private_data_t*
f1ap_get_private_data(packet_info *pinfo)
{
  f1ap_private_data_t *f1ap_data = (f1ap_private_data_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_f1ap, 0);
  if (!f1ap_data) {
    f1ap_data = wmem_new0(wmem_file_scope(), f1ap_private_data_t);
    f1ap_data->srb_id = -1;
    p_add_proto_data(wmem_file_scope(), pinfo, proto_f1ap, 0, f1ap_data);
  }
  return f1ap_data;
}

static void
add_nr_pdcp_meta_data(packet_info *pinfo, guint8 direction, guint8 srb_id)
{
  pdcp_nr_info *p_pdcp_nr_info;

  /* Only need to set info once per session. */
  if (get_pdcp_nr_proto_data(pinfo)) {
      return;
  }

  p_pdcp_nr_info = wmem_new0(wmem_file_scope(), pdcp_nr_info);
  p_pdcp_nr_info->direction = direction;
  p_pdcp_nr_info->bearerType = Bearer_DCCH;
  p_pdcp_nr_info->bearerId = srb_id;
  p_pdcp_nr_info->plane = NR_SIGNALING_PLANE;
  p_pdcp_nr_info->seqnum_length = PDCP_NR_SN_LENGTH_12_BITS;
  p_pdcp_nr_info->maci_present = TRUE;
  set_pdcp_nr_proto_data(pinfo, p_pdcp_nr_info);
}

#include "packet-f1ap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  f1ap_ctx_t f1ap_ctx;
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  f1ap_ctx.message_type        = f1ap_data->message_type;
  f1ap_ctx.ProcedureCode       = f1ap_data->procedure_code;
  f1ap_ctx.ProtocolIE_ID       = f1ap_data->protocol_ie_id;
  f1ap_ctx.ProtocolExtensionID = f1ap_data->protocol_extension_id;

  return (dissector_try_uint_new(f1ap_ies_dissector_table, f1ap_data->protocol_ie_id, tvb, pinfo, tree, FALSE, &f1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  f1ap_ctx_t f1ap_ctx;
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  f1ap_ctx.message_type        = f1ap_data->message_type;
  f1ap_ctx.ProcedureCode       = f1ap_data->procedure_code;
  f1ap_ctx.ProtocolIE_ID       = f1ap_data->protocol_ie_id;
  f1ap_ctx.ProtocolExtensionID = f1ap_data->protocol_extension_id;

  return (dissector_try_uint_new(f1ap_extension_dissector_table, f1ap_data->protocol_extension_id, tvb, pinfo, tree, FALSE, &f1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(f1ap_proc_imsg_dissector_table, f1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(f1ap_proc_sout_dissector_table, f1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  f1ap_private_data_t *f1ap_data = f1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(f1ap_proc_uout_dissector_table, f1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}


static int
dissect_f1ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *f1ap_item = NULL;
  proto_tree *f1ap_tree = NULL;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "F1AP");
  col_clear(pinfo->cinfo, COL_INFO);

  /* create the f1ap protocol tree */
  f1ap_item = proto_tree_add_item(tree, proto_f1ap, tvb, 0, -1, ENC_NA);
  f1ap_tree = proto_item_add_subtree(f1ap_item, ett_f1ap);

  dissect_F1AP_PDU_PDU(tvb, pinfo, f1ap_tree, NULL);
  return tvb_captured_length(tvb);
}

void proto_register_f1ap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_f1ap_transportLayerAddressIPv4,
      { "IPv4 transportLayerAddress", "f1ap.transportLayerAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_transportLayerAddressIPv6,
      { "IPv6 transportLayerAddress", "f1ap.transportLayerAddressIPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
#include "packet-f1ap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_f1ap,
    &ett_f1ap_ResourceCoordinationTransferContainer,
    &ett_f1ap_PLMN_Identity,
    &ett_f1ap_MIB_message,
    &ett_f1ap_SIB1_message,
    &ett_f1ap_CG_ConfigInfo,
    &ett_f1ap_CellGroupConfig,
    &ett_f1ap_TransportLayerAddress,
    &ett_f1ap_UE_CapabilityRAT_ContainerList,
    &ett_f1ap_measurementTimingConfiguration,
    &ett_f1ap_DUtoCURRCContainer,
    &ett_f1ap_requestedP_MaxFR1,
    &ett_f1ap_HandoverPreparationInformation,
    &ett_f1ap_MeasConfig,
    &ett_f1ap_MeasGapConfig,
    &ett_f1ap_MeasGapSharingConfig,
    &ett_f1ap_EUTRA_NR_CellResourceCoordinationReq_Container,
    &ett_f1ap_EUTRA_NR_CellResourceCoordinationReqAck_Container,
    &ett_f1ap_ProtectedEUTRAResourceIndication,
    &ett_f1ap_RRCContainer,
    &ett_f1ap_RRCContainer_RRCSetupComplete,
    &ett_f1ap_sIBmessage,
    &ett_f1ap_UplinkTxDirectCurrentListInformation,
    &ett_f1ap_DRX_Config,
    &ett_f1ap_Ph_InfoSCG,
    &ett_f1ap_RequestedBandCombinationIndex,
    &ett_f1ap_RequestedFeatureSetEntryIndex,
    &ett_f1ap_RequestedP_MaxFR2,
    &ett_f1ap_UEAssistanceInformation,
    &ett_f1ap_CG_Config,
    &ett_f1ap_Ph_InfoMCG,
#include "packet-f1ap-ettarr.c"
  };

  /* Register protocol */
  proto_f1ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_f1ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  f1ap_handle = register_dissector("f1ap", dissect_f1ap, proto_f1ap);

  /* Register dissector tables */
  f1ap_ies_dissector_table = register_dissector_table("f1ap.ies", "F1AP-PROTOCOL-IES", proto_f1ap, FT_UINT32, BASE_DEC);
  f1ap_extension_dissector_table = register_dissector_table("f1ap.extension", "F1AP-PROTOCOL-EXTENSION", proto_f1ap, FT_UINT32, BASE_DEC);
  f1ap_proc_imsg_dissector_table = register_dissector_table("f1ap.proc.imsg", "F1AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_f1ap, FT_UINT32, BASE_DEC);
  f1ap_proc_sout_dissector_table = register_dissector_table("f1ap.proc.sout", "F1AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_f1ap, FT_UINT32, BASE_DEC);
  f1ap_proc_uout_dissector_table = register_dissector_table("f1ap.proc.uout", "F1AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_f1ap, FT_UINT32, BASE_DEC);
}

void
proto_reg_handoff_f1ap(void)
{
  dissector_add_uint_with_preference("sctp.port", SCTP_PORT_F1AP, f1ap_handle);
  dissector_add_uint("sctp.ppi", F1AP_PROTOCOL_ID, f1ap_handle);
  nr_rrc_ul_ccch_handle = find_dissector_add_dependency("nr-rrc.ul.ccch", proto_f1ap);
  nr_rrc_dl_ccch_handle = find_dissector_add_dependency("nr-rrc.dl.ccch", proto_f1ap);
  nr_rrc_ul_dcch_handle = find_dissector_add_dependency("nr-rrc.ul.dcch", proto_f1ap);
  nr_pdcp_handle = find_dissector_add_dependency("pdcp-nr", proto_f1ap);
#include "packet-f1ap-dis-tab.c"
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
