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
 * References: 3GPP TS 38.473 V16.5.0 (2021-04)
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/asn1.h>
#include <epan/sctpppids.h>
#include <epan/proto_data.h>

#include "packet-per.h"
#include "packet-f1ap.h"
#include "packet-x2ap.h"
#include "packet-nr-rrc.h"
#include "packet-e212.h"
#include "packet-pdcp-nr.h"
#include "packet-lte-rrc.h"
#include "packet-nrppa.h"

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
static int hf_f1ap_IABTNLAddressIPv4 = -1;
static int hf_f1ap_IABTNLAddressIPv6 = -1;
static int hf_f1ap_IABTNLAddressIPv6Prefix = -1;
static int hf_f1ap_interfacesToTrace_NG_C = -1;
static int hf_f1ap_interfacesToTrace_Xn_C = -1;
static int hf_f1ap_interfacesToTrace_Uu = -1;
static int hf_f1ap_interfacesToTrace_F1_C = -1;
static int hf_f1ap_interfacesToTrace_E1 = -1;
static int hf_f1ap_interfacesToTrace_Reserved = -1;
static int hf_f1ap_MeasurementsToActivate_Reserved1 = -1;
static int hf_f1ap_MeasurementsToActivate_M2 = -1;
static int hf_f1ap_MeasurementsToActivate_Reserved2 = -1;
static int hf_f1ap_MeasurementsToActivate_M5 = -1;
static int hf_f1ap_MeasurementsToActivate_Reserved3 = -1;
static int hf_f1ap_MeasurementsToActivate_M6 = -1;
static int hf_f1ap_MeasurementsToActivate_M7 = -1;
static int hf_f1ap_ReportCharacteristics_PRBPeriodic = -1;
static int hf_f1ap_ReportCharacteristics_TNLCapacityIndPeriodic = -1;
static int hf_f1ap_ReportCharacteristics_CompositeAvailableCapacityPeriodic = -1;
static int hf_f1ap_ReportCharacteristics_HWLoadIndPeriodic = -1;
static int hf_f1ap_ReportCharacteristics_NumberOfActiveUEs = -1;
static int hf_f1ap_ReportCharacteristics_Reserved = -1;
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
static gint ett_f1ap_BurstArrivalTime = -1;
static gint ett_f1ap_cSI_RS_Configuration = -1;
static gint ett_f1ap_sR_Configuration = -1;
static gint ett_f1ap_pDCCH_ConfigSIB1 = -1;
static gint ett_f1ap_sCS_Common = -1;
static gint ett_f1ap_IABTNLAddressIPv4Address = -1;
static gint ett_f1ap_IABTNLAddressIPv6Address = -1;
static gint ett_f1ap_IABTNLAddressIPv6Prefix = -1;
static gint ett_f1ap_InterfacesToTrace = -1;
static gint ett_f1ap_MeasurementsToActivate = -1;
static gint ett_f1ap_NRUERLFReportContainer = -1;
static gint ett_f1ap_RACH_Config_Common = -1;
static gint ett_f1ap_RACH_Config_Common_IAB = -1;
static gint ett_f1ap_RACHReportContainer = -1;
static gint ett_f1ap_ReferenceTime = -1;
static gint ett_f1ap_ReportCharacteristics = -1;
static gint ett_f1ap_SIB10_message = -1;
static gint ett_f1ap_SIB12_message = -1;
static gint ett_f1ap_SIB13_message = -1;
static gint ett_f1ap_SIB14_message = -1;
static gint ett_f1ap_SL_PHY_MAC_RLC_Config = -1;
static gint ett_f1ap_SL_ConfigDedicatedEUTRA_Info = -1;
static gint ett_f1ap_TDD_UL_DLConfigCommonNR = -1;
static gint ett_f1ap_UEAssistanceInformationEUTRA = -1;
static gint ett_f1ap_PosAssistance_Information = -1;
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
  e212_number_type_t number_type;
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
static dissector_handle_t lte_rrc_conn_reconf_handle;

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

static const true_false_string f1ap_tfs_interfacesToTrace = {
  "Should be traced",
  "Should not be traced"
};

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

static void
f1ap_ExtendedPacketDelayBudget_fmt(gchar *s, guint32 v)
{
  g_snprintf(s, ITEM_LABEL_LENGTH, "%.2fms (%u)", (float)v/100, v);
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
    { &hf_f1ap_IABTNLAddressIPv4,
      { "IPv4 IABTNLAddress", "f1ap.IABTNLAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_IABTNLAddressIPv6,
      { "IPv6 IABTNLAddress", "f1ap.IABTNLAddressIPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_IABTNLAddressIPv6Prefix,
      { "IPv6 Prefix IABTNLAddress", "f1ap.IABTNLAddressIPv6Prefix",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_f1ap_interfacesToTrace_NG_C,
      { "NG-C", "f1ap.interfacesToTrace.NG_C",
        FT_BOOLEAN, 8, TFS(&f1ap_tfs_interfacesToTrace), 0x80,
        NULL, HFILL }},
    { &hf_f1ap_interfacesToTrace_Xn_C,
      { "Xn-C", "f1ap.interfacesToTrace.Xn_C",
        FT_BOOLEAN, 8, TFS(&f1ap_tfs_interfacesToTrace), 0x40,
        NULL, HFILL }},
    { &hf_f1ap_interfacesToTrace_Uu,
      { "Uu", "f1ap.interfacesToTrace.Uu",
        FT_BOOLEAN, 8, TFS(&f1ap_tfs_interfacesToTrace), 0x20,
        NULL, HFILL }},
    { &hf_f1ap_interfacesToTrace_F1_C,
      { "F1-C", "f1ap.interfacesToTrace.F1_C",
        FT_BOOLEAN, 8, TFS(&f1ap_tfs_interfacesToTrace), 0x10,
        NULL, HFILL }},
    { &hf_f1ap_interfacesToTrace_E1,
      { "E1", "f1ap.interfacesToTrace.E1",
        FT_BOOLEAN, 8, TFS(&f1ap_tfs_interfacesToTrace), 0x08,
        NULL, HFILL }},
    { &hf_f1ap_interfacesToTrace_Reserved,
      { "Reserved", "f1ap.interfacesToTrace.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x07,
        NULL, HFILL }},
    { &hf_f1ap_MeasurementsToActivate_Reserved1,
      { "Reserved", "f1ap.MeasurementsToActivate.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x80,
        NULL, HFILL }},
    { &hf_f1ap_MeasurementsToActivate_M2,
      { "M2", "f1ap.MeasurementsToActivate.M2",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x40,
        NULL, HFILL }},
    { &hf_f1ap_MeasurementsToActivate_Reserved2,
      { "Reserved", "f1ap.MeasurementsToActivate.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x30,
        NULL, HFILL }},
    { &hf_f1ap_MeasurementsToActivate_M5,
      { "M5", "f1ap.MeasurementsToActivate.M5",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x08,
        NULL, HFILL }},
    { &hf_f1ap_MeasurementsToActivate_Reserved3,
      { "Reserved", "f1ap.MeasurementsToActivate.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x04,
        NULL, HFILL }},
    { &hf_f1ap_MeasurementsToActivate_M6,
      { "M6", "f1ap.MeasurementsToActivate.M6",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x02,
        NULL, HFILL }},
    { &hf_f1ap_MeasurementsToActivate_M7,
      { "M7", "f1ap.MeasurementsToActivate.M7",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x01,
        NULL, HFILL }},
    { &hf_f1ap_ReportCharacteristics_PRBPeriodic,
      { "PRBPeriodic", "f1ap.ReportCharacteristics.PRBPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x80000000,
        NULL, HFILL }},
    { &hf_f1ap_ReportCharacteristics_TNLCapacityIndPeriodic,
      { "TNLCapacityIndPeriodic", "f1ap.ReportCharacteristics.TNLCapacityIndPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x40000000,
        NULL, HFILL }},
    { &hf_f1ap_ReportCharacteristics_CompositeAvailableCapacityPeriodic,
      { "CompositeAvailableCapacityPeriodic", "f1ap.ReportCharacteristics.CompositeAvailableCapacityPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x20000000,
        NULL, HFILL }},
    { &hf_f1ap_ReportCharacteristics_HWLoadIndPeriodic,
      { "HWLoadIndPeriodic", "f1ap.ReportCharacteristics.HWLoadIndPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x10000000,
        NULL, HFILL }},
    { &hf_f1ap_ReportCharacteristics_NumberOfActiveUEs,
      { "NumberOfActiveUEs", "f1ap.ReportCharacteristics.NumberOfActiveUEs",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x08000000,
        NULL, HFILL }},
    { &hf_f1ap_ReportCharacteristics_Reserved,
      { "Reserved", "f1ap.ReportCharacteristics.Reserved",
        FT_UINT32, BASE_HEX, NULL, 0x07ffffff,
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
    &ett_f1ap_BurstArrivalTime,
    &ett_f1ap_cSI_RS_Configuration,
    &ett_f1ap_sR_Configuration,
    &ett_f1ap_pDCCH_ConfigSIB1,
    &ett_f1ap_sCS_Common,
    &ett_f1ap_IABTNLAddressIPv4Address,
    &ett_f1ap_IABTNLAddressIPv6Address,
    &ett_f1ap_IABTNLAddressIPv6Prefix,
    &ett_f1ap_InterfacesToTrace,
    &ett_f1ap_MeasurementsToActivate,
    &ett_f1ap_NRUERLFReportContainer,
    &ett_f1ap_RACH_Config_Common,
    &ett_f1ap_RACH_Config_Common_IAB,
    &ett_f1ap_RACHReportContainer,
    &ett_f1ap_ReferenceTime,
    &ett_f1ap_ReportCharacteristics,
    &ett_f1ap_SIB10_message,
    &ett_f1ap_SIB12_message,
    &ett_f1ap_SIB13_message,
    &ett_f1ap_SIB14_message,
    &ett_f1ap_SL_PHY_MAC_RLC_Config,
    &ett_f1ap_SL_ConfigDedicatedEUTRA_Info,
    &ett_f1ap_TDD_UL_DLConfigCommonNR,
    &ett_f1ap_UEAssistanceInformationEUTRA,
    &ett_f1ap_PosAssistance_Information,
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
  lte_rrc_conn_reconf_handle = find_dissector_add_dependency("lte-rrc.rrc_conn_reconf", proto_f1ap);
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
