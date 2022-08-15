/* packet-xnap.c
 * Routines for dissecting NG-RAN Xn application protocol (XnAP)
 * 3GPP TS 38.423 packet dissection
 * Copyright 2018-2022, Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref:
 * 3GPP TS 38.423 V17.1.0 (2022-06)
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>

#include "packet-xnap.h"
#include "packet-per.h"
#include "packet-lte-rrc.h"
#include "packet-nr-rrc.h"
#include "packet-e212.h"
#include "packet-ngap.h"
#include "packet-s1ap.h"
#include "packet-ranap.h"
#include "packet-ntp.h"
#include "packet-f1ap.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "NG-RAN Xn Application Protocol (XnAP)"
#define PSNAME "XnAP"
#define PFNAME "xnap"

/* Dissector will use SCTP PPID 61 or SCTP port. IANA assigned port = 38422 */
#define SCTP_PORT_XnAP	38422

#include "packet-xnap-val.h"

/* Initialize the protocol and registered fields */
static int proto_xnap = -1;
static int hf_xnap_transportLayerAddressIPv4 = -1;
static int hf_xnap_transportLayerAddressIPv6 = -1;
static int hf_xnap_NG_RANTraceID_TraceID = -1;
static int hf_xnap_NG_RANTraceID_TraceRecordingSessionReference = -1;
static int hf_xnap_primaryRATRestriction_e_UTRA = -1;
static int hf_xnap_primaryRATRestriction_nR = -1;
static int hf_xnap_primaryRATRestriction_nR_unlicensed = -1;
static int hf_xnap_primaryRATRestriction_nR_LEO = -1;
static int hf_xnap_primaryRATRestriction_nR_MEO = -1;
static int hf_xnap_primaryRATRestriction_nR_GEO = -1;
static int hf_xnap_primaryRATRestriction_nR_OTHERSAT = -1;
static int hf_xnap_primaryRATRestriction_reserved = -1;
static int hf_xnap_secondaryRATRestriction_e_UTRA = -1;
static int hf_xnap_secondaryRATRestriction_nR = -1;
static int hf_xnap_secondaryRATRestriction_e_UTRA_unlicensed = -1;
static int hf_xnap_secondaryRATRestriction_nR_unlicensed = -1;
static int hf_xnap_secondaryRATRestriction_reserved = -1;
static int hf_xnap_MDT_Location_Info_GNSS = -1;
static int hf_xnap_MDT_Location_Info_reserved = -1;
static int hf_xnap_MeasurementsToActivate_M1 = -1;
static int hf_xnap_MeasurementsToActivate_M2 = -1;
static int hf_xnap_MeasurementsToActivate_M3 = -1;
static int hf_xnap_MeasurementsToActivate_M4 = -1;
static int hf_xnap_MeasurementsToActivate_M5 = -1;
static int hf_xnap_MeasurementsToActivate_LoggingM1FromEventTriggered = -1;
static int hf_xnap_MeasurementsToActivate_M6 = -1;
static int hf_xnap_MeasurementsToActivate_M7 = -1;
static int hf_xnap_ReportCharacteristics_PRBPeriodic = -1;
static int hf_xnap_ReportCharacteristics_TNLCapacityIndPeriodic = -1;
static int hf_xnap_ReportCharacteristics_CompositeAvailableCapacityPeriodic = -1;
static int hf_xnap_ReportCharacteristics_NumberOfActiveUEs = -1;
static int hf_xnap_ReportCharacteristics_Reserved = -1;
#include "packet-xnap-hf.c"

/* Initialize the subtree pointers */
static gint ett_xnap = -1;
static gint ett_xnap_RRC_Context = -1;
static gint ett_nxap_container = -1;
static gint ett_xnap_PLMN_Identity = -1;
static gint ett_xnap_measurementTimingConfiguration = -1;
static gint ett_xnap_TransportLayerAddress = -1;
static gint ett_xnap_NG_RANTraceID = -1;
static gint ett_xnap_LastVisitedEUTRANCellInformation = -1;
static gint ett_xnap_LastVisitedNGRANCellInformation = -1;
static gint ett_xnap_LastVisitedUTRANCellInformation = -1;
static gint ett_xnap_LastVisitedGERANCellInformation = -1;
static gint ett_xnap_UERadioCapabilityForPagingOfNR = -1;
static gint ett_xnap_UERadioCapabilityForPagingOfEUTRA = -1;
static gint ett_xnap_FiveGCMobilityRestrictionListContainer = -1;
static gint ett_xnap_primaryRATRestriction = -1;
static gint ett_xnap_secondaryRATRestriction = -1;
static gint ett_xnap_ImmediateMDT_EUTRA = -1;
static gint ett_xnap_MDT_Location_Info = -1;
static gint ett_xnap_MeasurementsToActivate = -1;
static gint ett_xnap_NRMobilityHistoryReport = -1;
static gint ett_xnap_RACHReportContainer = -1;
static gint ett_xnap_TargetCellinEUTRAN = -1;
static gint ett_xnap_TDDULDLConfigurationCommonNR = -1;
static gint ett_xnap_UERLFReportContainerLTE = -1;
static gint ett_xnap_UERLFReportContainerNR = -1;
static gint ett_xnap_burstArrivalTime = -1;
static gint ett_xnap_ReportCharacteristics = -1;
static gint ett_xnap_NRCellPRACHConfig = -1;
static gint ett_xnap_anchorCarrier_NPRACHConfig = -1;
static gint ett_xnap_anchorCarrier_EDT_NPRACHConfig = -1;
static gint ett_xnap_anchorCarrier_Format2_NPRACHConfig = -1;
static gint ett_xnap_anchorCarrier_Format2_EDT_NPRACHConfig = -1;
static gint ett_xnap_non_anchorCarrier_NPRACHConfig = -1;
static gint ett_xnap_non_anchorCarrier_Format2_NPRACHConfig = -1;
static gint ett_xnap_anchorCarrier_NPRACHConfigTDD = -1;
static gint ett_xnap_non_anchorCarrier_NPRACHConfigTDD = -1;
static gint ett_xnap_non_anchorCarrierFrequency = -1;
static gint ett_xnap_cSI_RS_Configuration = -1;
static gint ett_xnap_sR_Configuration = -1;
static gint ett_xnap_pDCCH_ConfigSIB1 = -1;
static gint ett_xnap_sCS_Common = -1;
static gint ett_xnap_LastVisitedPSCellInformation = -1;
static gint ett_xnap_MeasObjectContainer = -1;
static gint ett_xnap_RACH_Config_Common = -1;
static gint ett_xnap_RACH_Config_Common_IAB = -1;
static gint ett_xnap_ReportConfigContainer = -1;
static gint ett_xnap_RLC_Bearer_Configuration = -1;
static gint ett_xnap_SuccessfulHOReportContainer = -1;
#include "packet-xnap-ett.c"

enum {
  XNAP_NG_RAN_CONTAINER_AUTOMATIC,
  XNAP_NG_RAN_CONTAINER_GNB,
  XNAP_NG_RAN_CONTAINER_NG_ENB
};

static const enum_val_t xnap_target_ng_ran_container_vals[] = {
  {"automatic", "automatic", XNAP_NG_RAN_CONTAINER_AUTOMATIC},
  {"gnb", "gNB", XNAP_NG_RAN_CONTAINER_GNB},
  {"ng-enb","ng-eNB", XNAP_NG_RAN_CONTAINER_NG_ENB},
  {NULL, NULL, -1}
};

enum {
  XNAP_LTE_RRC_CONTEXT_LTE,
  XNAP_LTE_RRC_CONTEXT_NBIOT
};

static const enum_val_t xnap_lte_rrc_context_vals[] = {
  {"lte", "LTE", XNAP_LTE_RRC_CONTEXT_LTE},
  {"nb-iot","NB-IoT", XNAP_LTE_RRC_CONTEXT_NBIOT},
  {NULL, NULL, -1}
};

/* Global variables */
static gint xnap_dissect_target_ng_ran_container_as = XNAP_NG_RAN_CONTAINER_AUTOMATIC;
static gint xnap_dissect_lte_rrc_context_as = XNAP_LTE_RRC_CONTEXT_LTE;

/* Dissector tables */
static dissector_table_t xnap_ies_dissector_table;
static dissector_table_t xnap_extension_dissector_table;
static dissector_table_t xnap_proc_imsg_dissector_table;
static dissector_table_t xnap_proc_sout_dissector_table;
static dissector_table_t xnap_proc_uout_dissector_table;

void proto_register_xnap(void);
void proto_reg_handoff_xnap(void);
static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_XnAP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

static dissector_handle_t xnap_handle;

static void
xnap_PacketLossRate_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1f%% (%u)", (float)v/10, v);
}

static void
xnap_PacketDelayBudget_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%u)", (float)v/2, v);
}

static void
xnap_ExtendedPacketDelayBudget_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.2fms (%u)", (float)v/100, v);
}

static void
xnap_handoverTriggerChange_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB (%d)", ((float)v)/2, (gint32)v);
}

static void
xnap_Threshold_RSRP_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%ddBm (%u)", (gint32)v-156, v);
}

static void
xnap_Threshold_RSRQ_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB (%u)", ((float)v/2)-43, v);
}

static void
xnap_Threshold_SINR_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB (%u)", ((float)v/2)-23, v);
}

static const true_false_string xnap_tfs_activate_do_not_activate = {
  "Activate",
  "Do not activate"
};

typedef enum {
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
} xnap_message_type;

struct xnap_conv_info {
  address addr_a;
  guint32 port_a;
  GlobalNG_RANNode_ID_enum ranmode_id_a;
  address addr_b;
  guint32 port_b;
  GlobalNG_RANNode_ID_enum ranmode_id_b;
};

struct xnap_private_data {
  struct xnap_conv_info *xnap_conv;
  xnap_message_type message_type;
  guint32 procedure_code;
  guint32 protocol_ie_id;
  e212_number_type_t number_type;
};

static struct xnap_private_data*
xnap_get_private_data(packet_info *pinfo)
{
  struct xnap_private_data *xnap_data = (struct xnap_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_xnap, 0);
  if (!xnap_data) {
    xnap_data = wmem_new0(pinfo->pool, struct xnap_private_data);
    p_add_proto_data(pinfo->pool, pinfo, proto_xnap, 0, xnap_data);
  }
  return xnap_data;
}

static GlobalNG_RANNode_ID_enum
xnap_get_ranmode_id(address *addr, guint32 port, packet_info *pinfo)
{
  struct xnap_private_data *xnap_data = xnap_get_private_data(pinfo);
  GlobalNG_RANNode_ID_enum ranmode_id = (GlobalNG_RANNode_ID_enum)-1;

  if (xnap_data->xnap_conv) {
    if (addresses_equal(addr, &xnap_data->xnap_conv->addr_a) && port == xnap_data->xnap_conv->port_a) {
      ranmode_id = xnap_data->xnap_conv->ranmode_id_a;
    } else if (addresses_equal(addr, &xnap_data->xnap_conv->addr_b) && port == xnap_data->xnap_conv->port_b) {
      ranmode_id = xnap_data->xnap_conv->ranmode_id_b;
    }
  }
  return ranmode_id;
}

#include "packet-xnap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct xnap_private_data *xnap_data = xnap_get_private_data(pinfo);

  return (dissector_try_uint_new(xnap_ies_dissector_table, xnap_data->protocol_ie_id, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct xnap_private_data *xnap_data = xnap_get_private_data(pinfo);

  return (dissector_try_uint_new(xnap_extension_dissector_table, xnap_data->protocol_ie_id, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct xnap_private_data *xnap_data = xnap_get_private_data(pinfo);

  return (dissector_try_uint_new(xnap_proc_imsg_dissector_table, xnap_data->procedure_code, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct xnap_private_data *xnap_data = xnap_get_private_data(pinfo);

  return (dissector_try_uint_new(xnap_proc_sout_dissector_table, xnap_data->procedure_code, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  struct xnap_private_data *xnap_data = xnap_get_private_data(pinfo);

  return (dissector_try_uint_new(xnap_proc_uout_dissector_table, xnap_data->procedure_code, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_xnap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  proto_item *xnap_item;
  proto_tree *xnap_tree;
  conversation_t *conversation;
  struct xnap_private_data* xnap_data;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "XnAP");
  col_clear_fence(pinfo->cinfo, COL_INFO);
  col_clear(pinfo->cinfo, COL_INFO);

  xnap_item = proto_tree_add_item(tree, proto_xnap, tvb, 0, -1, ENC_NA);
  xnap_tree = proto_item_add_subtree(xnap_item, ett_xnap);

  xnap_data = xnap_get_private_data(pinfo);
  conversation = find_or_create_conversation(pinfo);
  xnap_data->xnap_conv = (struct xnap_conv_info *)conversation_get_proto_data(conversation, proto_xnap);
  if (!xnap_data->xnap_conv) {
    xnap_data->xnap_conv = wmem_new0(wmem_file_scope(), struct xnap_conv_info);
    copy_address_wmem(wmem_file_scope(), &xnap_data->xnap_conv->addr_a, &pinfo->src);
    xnap_data->xnap_conv->port_a = pinfo->srcport;
    xnap_data->xnap_conv->ranmode_id_a = (GlobalNG_RANNode_ID_enum)-1;
    copy_address_wmem(wmem_file_scope(), &xnap_data->xnap_conv->addr_b, &pinfo->dst);
    xnap_data->xnap_conv->port_b = pinfo->destport;
    xnap_data->xnap_conv->ranmode_id_b = (GlobalNG_RANNode_ID_enum)-1;
    conversation_add_proto_data(conversation, proto_xnap, xnap_data->xnap_conv);
  }

  return dissect_XnAP_PDU_PDU(tvb, pinfo, xnap_tree, data);
}

void proto_register_xnap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_xnap_transportLayerAddressIPv4,
      { "TransportLayerAddress (IPv4)", "xnap.TransportLayerAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_transportLayerAddressIPv6,
      { "TransportLayerAddress (IPv6)", "xnap.TransportLayerAddressIPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_NG_RANTraceID_TraceID,
      { "TraceID", "xnap.NG_RANTraceID.TraceID",
        FT_UINT24, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_NG_RANTraceID_TraceRecordingSessionReference,
      { "TraceRecordingSessionReference", "xnap.NG_RANTraceID.TraceRecordingSessionReference",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_xnap_primaryRATRestriction_e_UTRA,
      { "e-UTRA", "xnap.primaryRATRestriction.e_UTRA",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x80,
        NULL, HFILL }},
    { &hf_xnap_primaryRATRestriction_nR,
      { "nR", "xnap.primaryRATRestriction.nR",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x40,
        NULL, HFILL }},
    { &hf_xnap_primaryRATRestriction_nR_unlicensed,
      { "nR-unlicensed", "xnap.primaryRATRestriction.nR_unlicensed",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x20,
        NULL, HFILL }},
    { &hf_xnap_primaryRATRestriction_nR_LEO,
      { "nR-LEO", "xnap.primaryRATRestriction.nR_LEO",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x10,
        NULL, HFILL }},
    { &hf_xnap_primaryRATRestriction_nR_MEO,
      { "nR-MEO", "xnap.primaryRATRestriction.nR_MEO",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x08,
        NULL, HFILL }},
    { &hf_xnap_primaryRATRestriction_nR_GEO,
      { "nR-GEO", "xnap.primaryRATRestriction.nR_GEO",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x04,
        NULL, HFILL }},
    { &hf_xnap_primaryRATRestriction_nR_OTHERSAT,
      { "nR-unlicensed", "xnap.primaryRATRestriction.nR_unlicensed",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x02,
        NULL, HFILL }},
    { &hf_xnap_primaryRATRestriction_reserved,
      { "reserved", "xnap.primaryRATRestriction.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x01,
        NULL, HFILL }},
    { &hf_xnap_secondaryRATRestriction_e_UTRA,
      { "e-UTRA", "xnap.secondaryRATRestriction.e_UTRA",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x80,
        NULL, HFILL }},
    { &hf_xnap_secondaryRATRestriction_nR,
      { "nR", "xnap.secondaryRATRestriction.nR",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x40,
        NULL, HFILL }},
    { &hf_xnap_secondaryRATRestriction_e_UTRA_unlicensed,
      { "e-UTRA-unlicensed", "xnap.secondaryRATRestriction.e_UTRA_unlicensed",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x20,
        NULL, HFILL }},
    { &hf_xnap_secondaryRATRestriction_nR_unlicensed,
      { "nR-unlicensed", "xnap.secondaryRATRestriction.nR_unlicensed",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x10,
        NULL, HFILL }},
    { &hf_xnap_secondaryRATRestriction_reserved,
      { "reserved", "xnap.secondaryRATRestriction.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x0f,
        NULL, HFILL }},
    { &hf_xnap_MDT_Location_Info_GNSS,
      { "GNSS", "xnap.MDT_Location_Info.GNSS",
        FT_BOOLEAN, 8, TFS(&tfs_activated_deactivated), 0x80,
        NULL, HFILL }},
    { &hf_xnap_MDT_Location_Info_reserved,
      { "Reserved", "xnap.MDT_Location_Info.reserved",
        FT_UINT8, BASE_HEX, NULL, 0x7f,
        NULL, HFILL }},
    { &hf_xnap_MeasurementsToActivate_M1,
      { "M1", "xnap.MeasurementsToActivate.M1",
        FT_BOOLEAN, 8, TFS(&xnap_tfs_activate_do_not_activate), 0x80,
        NULL, HFILL }},
    { &hf_xnap_MeasurementsToActivate_M2,
      { "M2", "xnap.MeasurementsToActivate.M2",
        FT_BOOLEAN, 8, TFS(&xnap_tfs_activate_do_not_activate), 0x40,
        NULL, HFILL }},
    { &hf_xnap_MeasurementsToActivate_M3,
      { "M3", "xnap.MeasurementsToActivate.M3",
        FT_BOOLEAN, 8, TFS(&xnap_tfs_activate_do_not_activate), 0x20,
        NULL, HFILL }},
    { &hf_xnap_MeasurementsToActivate_M4,
      { "M4", "xnap.MeasurementsToActivate.M4",
        FT_BOOLEAN, 8, TFS(&xnap_tfs_activate_do_not_activate), 0x10,
        NULL, HFILL }},
    { &hf_xnap_MeasurementsToActivate_M5,
      { "M5", "xnap.MeasurementsToActivate.M5",
        FT_BOOLEAN, 8, TFS(&xnap_tfs_activate_do_not_activate), 0x08,
        NULL, HFILL }},
    { &hf_xnap_MeasurementsToActivate_LoggingM1FromEventTriggered,
      { "LoggingOfM1FromEventTriggeredMeasurementReports", "xnap.MeasurementsToActivate.LoggingM1FromEventTriggered",
        FT_BOOLEAN, 8, TFS(&xnap_tfs_activate_do_not_activate), 0x04,
        NULL, HFILL }},
    { &hf_xnap_MeasurementsToActivate_M6,
      { "M6", "xnap.MeasurementsToActivate.M6",
        FT_BOOLEAN, 8, TFS(&xnap_tfs_activate_do_not_activate), 0x02,
        NULL, HFILL }},
    { &hf_xnap_MeasurementsToActivate_M7,
      { "M7", "xnap.MeasurementsToActivate.M7",
        FT_BOOLEAN, 8, TFS(&xnap_tfs_activate_do_not_activate), 0x01,
        NULL, HFILL }},
    { &hf_xnap_ReportCharacteristics_PRBPeriodic,
      { "PRBPeriodic", "xnap.ReportCharacteristics.PRBPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x80000000,
        NULL, HFILL }},
    { &hf_xnap_ReportCharacteristics_TNLCapacityIndPeriodic,
      { "TNLCapacityIndPeriodic", "xnap.ReportCharacteristics.TNLCapacityIndPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x40000000,
        NULL, HFILL }},
    { &hf_xnap_ReportCharacteristics_CompositeAvailableCapacityPeriodic,
      { "CompositeAvailableCapacityPeriodic", "xnap.ReportCharacteristics.CompositeAvailableCapacityPeriodic",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x20000000,
        NULL, HFILL }},
    { &hf_xnap_ReportCharacteristics_NumberOfActiveUEs,
      { "NumberOfActiveUEs", "xnap.ReportCharacteristics.NumberOfActiveUEs",
        FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x10000000,
        NULL, HFILL }},
    { &hf_xnap_ReportCharacteristics_Reserved,
      { "Reserved", "xnap.ReportCharacteristics.Reserved",
        FT_UINT32, BASE_HEX, NULL, 0x0fffffff,
        NULL, HFILL }},
#include "packet-xnap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_xnap,
    &ett_xnap_RRC_Context,
    &ett_nxap_container,
    &ett_xnap_PLMN_Identity,
    &ett_xnap_measurementTimingConfiguration,
    &ett_xnap_TransportLayerAddress,
    &ett_xnap_NG_RANTraceID,
    &ett_xnap_LastVisitedEUTRANCellInformation,
    &ett_xnap_LastVisitedNGRANCellInformation,
    &ett_xnap_LastVisitedUTRANCellInformation,
    &ett_xnap_LastVisitedGERANCellInformation,
    &ett_xnap_UERadioCapabilityForPagingOfNR,
    &ett_xnap_UERadioCapabilityForPagingOfEUTRA,
    &ett_xnap_FiveGCMobilityRestrictionListContainer,
    &ett_xnap_primaryRATRestriction,
    &ett_xnap_secondaryRATRestriction,
    &ett_xnap_ImmediateMDT_EUTRA,
    &ett_xnap_MDT_Location_Info,
    &ett_xnap_MeasurementsToActivate,
    &ett_xnap_NRMobilityHistoryReport,
    &ett_xnap_RACHReportContainer,
    &ett_xnap_TargetCellinEUTRAN,
    &ett_xnap_TDDULDLConfigurationCommonNR,
    &ett_xnap_UERLFReportContainerLTE,
    &ett_xnap_UERLFReportContainerNR,
    &ett_xnap_burstArrivalTime,
    &ett_xnap_ReportCharacteristics,
    &ett_xnap_NRCellPRACHConfig,
    &ett_xnap_anchorCarrier_NPRACHConfig,
    &ett_xnap_anchorCarrier_EDT_NPRACHConfig,
    &ett_xnap_anchorCarrier_Format2_NPRACHConfig,
    &ett_xnap_anchorCarrier_Format2_EDT_NPRACHConfig,
    &ett_xnap_non_anchorCarrier_NPRACHConfig,
    &ett_xnap_non_anchorCarrier_Format2_NPRACHConfig,
    &ett_xnap_anchorCarrier_NPRACHConfigTDD,
    &ett_xnap_non_anchorCarrier_NPRACHConfigTDD,
    &ett_xnap_non_anchorCarrierFrequency,
    &ett_xnap_cSI_RS_Configuration,
    &ett_xnap_sR_Configuration,
    &ett_xnap_pDCCH_ConfigSIB1,
    &ett_xnap_sCS_Common,
    &ett_xnap_LastVisitedPSCellInformation,
    &ett_xnap_MeasObjectContainer,
    &ett_xnap_RACH_Config_Common,
    &ett_xnap_RACH_Config_Common_IAB,
    &ett_xnap_ReportConfigContainer,
    &ett_xnap_RLC_Bearer_Configuration,
    &ett_xnap_SuccessfulHOReportContainer,
#include "packet-xnap-ettarr.c"
  };

  module_t *xnap_module;

  proto_xnap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  proto_register_field_array(proto_xnap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  xnap_handle = register_dissector("xnap", dissect_xnap, proto_xnap);

  xnap_ies_dissector_table = register_dissector_table("xnap.ies", "XNAP-PROTOCOL-IES", proto_xnap, FT_UINT32, BASE_DEC);
  xnap_extension_dissector_table = register_dissector_table("xnap.extension", "XNAP-PROTOCOL-EXTENSION", proto_xnap, FT_UINT32, BASE_DEC);
  xnap_proc_imsg_dissector_table = register_dissector_table("xnap.proc.imsg", "XNAP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_xnap, FT_UINT32, BASE_DEC);
  xnap_proc_sout_dissector_table = register_dissector_table("xnap.proc.sout", "XNAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_xnap, FT_UINT32, BASE_DEC);
  xnap_proc_uout_dissector_table = register_dissector_table("xnap.proc.uout", "XNAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_xnap, FT_UINT32, BASE_DEC);

  xnap_module = prefs_register_protocol(proto_xnap, NULL);

  prefs_register_enum_preference(xnap_module, "dissect_target_ng_ran_container_as", "Dissect target NG-RAN container as",
                                 "Select whether target NG-RAN container should be decoded automatically"
                                 " (based on Xn Setup procedure) or manually",
                                 &xnap_dissect_target_ng_ran_container_as, xnap_target_ng_ran_container_vals, FALSE);
  prefs_register_enum_preference(xnap_module, "dissect_lte_rrc_context_as", "Dissect LTE RRC Context as",
                                 "Select whether LTE RRC Context should be dissected as legacy LTE or NB-IOT",
                                 &xnap_dissect_lte_rrc_context_as, xnap_lte_rrc_context_vals, FALSE);
}


void
proto_reg_handoff_xnap(void)
{
  dissector_add_uint_with_preference("sctp.port", SCTP_PORT_XnAP, xnap_handle);
  dissector_add_uint("sctp.ppi", XNAP_PROTOCOL_ID, xnap_handle);
#include "packet-xnap-dis-tab.c"
}
