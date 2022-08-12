/* packet-s1ap.c
 * Routines for E-UTRAN S1 Application Protocol (S1AP) packet dissection
 * Copyright 2007-2016, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Based on the RANAP dissector
 *
 * References: 3GPP TS 36.413 V17.1.0 (2022-06)
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-sccp.h"
#include "packet-lte-rrc.h"
#include "packet-ranap.h"
#include "packet-bssgp.h"
#include "packet-s1ap.h"
#include "packet-a21.h"
#include "packet-gsm_map.h"
#include "packet-cell_broadcast.h"
#include "packet-gsm_a_common.h"
#include "packet-ntp.h"
#include "packet-ngap.h"

#define PNAME  "S1 Application Protocol"
#define PSNAME "S1AP"
#define PFNAME "s1ap"

/* Dissector will use SCTP PPID 18 or SCTP port. IANA assigned port = 36412 */
#define SCTP_PORT_S1AP 36412

void proto_register_s1ap(void);
void proto_reg_handoff_s1ap(void);

static dissector_handle_t gcsna_handle;
static dissector_handle_t nas_eps_handle;
static dissector_handle_t lppa_handle;
static dissector_handle_t bssgp_handle;
static dissector_handle_t lte_rrc_ue_radio_access_cap_info_handle;
static dissector_handle_t lte_rrc_ue_radio_access_cap_info_nb_handle;
static dissector_handle_t nr_rrc_ue_radio_access_cap_info_handle;
static dissector_handle_t lte_rrc_ue_radio_paging_info_handle;
static dissector_handle_t lte_rrc_ue_radio_paging_info_nb_handle;
static dissector_handle_t nr_rrc_ue_radio_paging_info_handle;

#include "packet-s1ap-val.h"

/* Initialize the protocol and registered fields */
static int proto_s1ap = -1;

static int hf_s1ap_transportLayerAddressIPv4 = -1;
static int hf_s1ap_transportLayerAddressIPv6 = -1;
static int hf_s1ap_E_UTRAN_Trace_ID_TraceID = -1;
static int hf_s1ap_E_UTRAN_Trace_ID_TraceRecordingSessionReference = -1;
static int hf_s1ap_interfacesToTrace_S1_MME = -1;
static int hf_s1ap_interfacesToTrace_X2 = -1;
static int hf_s1ap_interfacesToTrace_Uu = -1;
static int hf_s1ap_interfacesToTrace_F1_C = -1;
static int hf_s1ap_interfacesToTrace_E1 = -1;
static int hf_s1ap_interfacesToTrace_Reserved = -1;
static int hf_s1ap_encryptionAlgorithms_EEA1 = -1;
static int hf_s1ap_encryptionAlgorithms_EEA2 = -1;
static int hf_s1ap_encryptionAlgorithms_EEA3 = -1;
static int hf_s1ap_encryptionAlgorithms_Reserved = -1;
static int hf_s1ap_integrityProtectionAlgorithms_EIA1 = -1;
static int hf_s1ap_integrityProtectionAlgorithms_EIA2 = -1;
static int hf_s1ap_integrityProtectionAlgorithms_EIA3 = -1;
static int hf_s1ap_integrityProtectionAlgorithms_Reserved = -1;
static int hf_s1ap_SerialNumber_gs = -1;
static int hf_s1ap_SerialNumber_msg_code = -1;
static int hf_s1ap_SerialNumber_upd_nb = -1;
static int hf_s1ap_WarningType_value = -1;
static int hf_s1ap_WarningType_emergency_user_alert = -1;
static int hf_s1ap_WarningType_popup = -1;
static int hf_s1ap_WarningMessageContents_nb_pages = -1;
static int hf_s1ap_WarningMessageContents_decoded_page = -1;
static int hf_s1ap_measurementsToActivate_M1 = -1;
static int hf_s1ap_measurementsToActivate_M2 = -1;
static int hf_s1ap_measurementsToActivate_M3 = -1;
static int hf_s1ap_measurementsToActivate_M4 = -1;
static int hf_s1ap_measurementsToActivate_M5 = -1;
static int hf_s1ap_measurementsToActivate_LoggingM1FromEventTriggered = -1;
static int hf_s1ap_measurementsToActivate_M6 = -1;
static int hf_s1ap_measurementsToActivate_M7 = -1;
static int hf_s1ap_MDT_Location_Info_GNSS = -1;
static int hf_s1ap_MDT_Location_Info_E_CID = -1;
static int hf_s1ap_MDT_Location_Info_Reserved = -1;
static int hf_s1ap_NRencryptionAlgorithms_NEA1 = -1;
static int hf_s1ap_NRencryptionAlgorithms_NEA2 = -1;
static int hf_s1ap_NRencryptionAlgorithms_NEA3 = -1;
static int hf_s1ap_NRencryptionAlgorithms_Reserved = -1;
static int hf_s1ap_NRintegrityProtectionAlgorithms_NIA1 = -1;
static int hf_s1ap_NRintegrityProtectionAlgorithms_NIA2 = -1;
static int hf_s1ap_NRintegrityProtectionAlgorithms_NIA3 = -1;
static int hf_s1ap_NRintegrityProtectionAlgorithms_Reserved = -1;
static int hf_s1ap_UE_Application_Layer_Measurement_Capability_QoE_Measurement_for_streaming_service = -1;
static int hf_s1ap_UE_Application_Layer_Measurement_Capability_QoE_Measurement_for_MTSI_service = -1;
static int hf_s1ap_UE_Application_Layer_Measurement_Capability_Reserved = -1;
static int hf_s1ap_rAT_RestrictionInformation_LEO = -1;
static int hf_s1ap_rAT_RestrictionInformation_MEO = -1;
static int hf_s1ap_rAT_RestrictionInformation_GEO = -1;
static int hf_s1ap_rAT_RestrictionInformation_OTHERSAT = -1;
static int hf_s1ap_rAT_RestrictionInformation_Reserved = -1;
#include "packet-s1ap-hf.c"

/* Initialize the subtree pointers */
static int ett_s1ap = -1;
static int ett_s1ap_TransportLayerAddress = -1;
static int ett_s1ap_ToTargetTransparentContainer = -1;
static int ett_s1ap_ToSourceTransparentContainer = -1;
static int ett_s1ap_RRCContainer = -1;
static int ett_s1ap_UERadioCapability = -1;
static int ett_s1ap_RIMInformation = -1;
static int ett_s1ap_Cdma2000PDU = -1;
static int ett_s1ap_Cdma2000SectorID = -1;
static int ett_s1ap_UERadioPagingInformation = -1;
static int ett_s1ap_UE_HistoryInformationFromTheUE = -1;
static int ett_s1ap_CELevel = -1;
static int ett_s1ap_UE_RLF_Report_Container = -1;
static int ett_s1ap_UE_RLF_Report_Container_for_extended_bands = -1;
static int ett_s1ap_S1_Message = -1;
static int ett_s1ap_E_UTRAN_Trace_ID = -1;
static int ett_s1ap_InterfacesToTrace = -1;
static int ett_s1ap_EncryptionAlgorithms = -1;
static int ett_s1ap_IntegrityProtectionAlgorithms = -1;
static int ett_s1ap_LastVisitedNGRANCellInformation = -1;
static int ett_s1ap_LastVisitedUTRANCellInformation = -1;
static int ett_s1ap_SerialNumber = -1;
static int ett_s1ap_WarningType = -1;
static int ett_s1ap_DataCodingScheme = -1;
static int ett_s1ap_WarningMessageContents = -1;
static int ett_s1ap_MSClassmark = -1;
static int ett_s1ap_MeasurementsToActivate = -1;
static int ett_s1ap_MDT_Location_Info = -1;
static int ett_s1ap_IMSI = -1;
static int ett_s1ap_NASSecurityParameters = -1;
static int ett_s1ap_NRencryptionAlgorithms = -1;
static int ett_s1ap_NRintegrityProtectionAlgorithms = -1;
static int ett_s1ap_UE_Application_Layer_Measurement_Capability = -1;
static int ett_s1ap_sMTC = -1;
static int ett_s1ap_threshRS_Index_r15 = -1;
static int ett_s1ap_sSBToMeasure = -1;
static int ett_s1ap_sSRSSIMeasurement = -1;
static int ett_s1ap_quantityConfigNR_R15 = -1;
static int ett_s1ap_excludedCellsToAddModList = -1;
static int ett_s1ap_NB_IoT_RLF_Report_Container = -1;
static int ett_s1ap_MDT_ConfigurationNR = -1;
static int ett_s1ap_IntersystemSONConfigurationTransfer = -1;
static int ett_s1ap_rAT_RestrictionInformation = -1;
#include "packet-s1ap-ett.c"

static expert_field ei_s1ap_number_pages_le15 = EI_INIT;

enum{
  INITIATING_MESSAGE,
  SUCCESSFUL_OUTCOME,
  UNSUCCESSFUL_OUTCOME
};

struct s1ap_conv_info {
  wmem_map_t *nbiot_ta;
  wmem_tree_t *nbiot_enb_ue_s1ap_id;
};

struct s1ap_supported_ta {
  guint16 tac;
  wmem_array_t *plmn;
};

struct s1ap_tai {
  guint32 plmn;
  guint16 tac;
};

struct s1ap_private_data {
  struct s1ap_conv_info *s1ap_conv;
  guint32 procedure_code;
  guint32 protocol_ie_id;
  guint32 protocol_extension_id;
  guint32 handover_type_value;
  guint32 message_type;
  guint8 data_coding_scheme;
  struct s1ap_supported_ta *supported_ta;
  const char *obj_id;
  struct s1ap_tai *tai;
  guint16 enb_ue_s1ap_id;
  gboolean srvcc_ho_cs_only;
  guint8 transparent_container_type;
  e212_number_type_t number_type;
};

enum {
  S1AP_LTE_CONTAINER_AUTOMATIC,
  S1AP_LTE_CONTAINER_LEGACY,
  S1AP_LTE_CONTAINER_NBIOT
};

static const enum_val_t s1ap_lte_container_vals[] = {
  {"automatic", "Automatic", S1AP_LTE_CONTAINER_AUTOMATIC},
  {"legacy", "Legacy LTE", S1AP_LTE_CONTAINER_LEGACY},
  {"nb-iot","NB-IoT", S1AP_LTE_CONTAINER_NBIOT},
  {NULL, NULL, -1}
};

enum {
  SOURCE_TO_TARGET_TRANSPARENT_CONTAINER = 1,
  TARGET_TO_SOURCE_TRANSPARENT_CONTAINER
};

/* Global variables */
static gboolean g_s1ap_dissect_container = TRUE;
static gint g_s1ap_dissect_lte_container_as = S1AP_LTE_CONTAINER_AUTOMATIC;

static dissector_handle_t s1ap_handle;

/* Dissector tables */
static dissector_table_t s1ap_ies_dissector_table;
static dissector_table_t s1ap_ies_p1_dissector_table;
static dissector_table_t s1ap_ies_p2_dissector_table;
static dissector_table_t s1ap_extension_dissector_table;
static dissector_table_t s1ap_proc_imsg_dissector_table;
static dissector_table_t s1ap_proc_sout_dissector_table;
static dissector_table_t s1ap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
/* Currently not used
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
*/
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static int dissect_InitialUEMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data);
#if 0
static int dissect_SourceRNC_ToTargetRNC_TransparentContainer_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_TargetRNC_ToSourceRNC_TransparentContainer_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_SourceBSS_ToTargetBSS_TransparentContainer_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_TargetBSS_ToSourceBSS_TransparentContainer_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
#endif

static void
s1ap_Threshold_RSRP_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%ddBm (%u)", (gint32)v-140, v);
}

static void
s1ap_Threshold_RSRQ_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB (%u)", ((float)v/2)-20, v);
}

static const true_false_string s1ap_tfs_interfacesToTrace = {
  "Should be traced",
  "Should not be traced"
};

static void
s1ap_Time_UE_StayedInCell_EnhancedGranularity_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fs", ((float)v)/10);
}

const value_string s1ap_serialNumber_gs_vals[] = {
  { 0, "Display mode immediate, cell wide"},
  { 1, "Display mode normal, PLMN wide"},
  { 2, "Display mode normal, tracking area wide"},
  { 3, "Display mode normal, cell wide"},
  { 0, NULL},
};

const value_string s1ap_warningType_vals[] = {
  { 0, "Earthquake"},
  { 1, "Tsunami"},
  { 2, "Earthquake and Tsunami"},
  { 3, "Test"},
  { 4, "Other"},
  { 0, NULL},
};

void
dissect_s1ap_warningMessageContents(tvbuff_t *warning_msg_tvb, proto_tree *tree, packet_info *pinfo, guint8 dcs, int hf_nb_pages, int hf_decoded_page)
{
  guint32 offset;
  guint8 nb_of_pages, length, *str;
  proto_item *ti;
  tvbuff_t *cb_data_page_tvb, *cb_data_tvb;
  int i;

  nb_of_pages = tvb_get_guint8(warning_msg_tvb, 0);
  ti = proto_tree_add_uint(tree, hf_nb_pages, warning_msg_tvb, 0, 1, nb_of_pages);
  if (nb_of_pages > 15) {
    expert_add_info_format(pinfo, ti, &ei_s1ap_number_pages_le15,
                           "Number of pages should be <=15 (found %u)", nb_of_pages);
    nb_of_pages = 15;
  }
  for (i = 0, offset = 1; i < nb_of_pages; i++) {
    length = tvb_get_guint8(warning_msg_tvb, offset+82);
    cb_data_page_tvb = tvb_new_subset_length(warning_msg_tvb, offset, length);
    cb_data_tvb = dissect_cbs_data(dcs, cb_data_page_tvb, tree, pinfo, 0);
    if (cb_data_tvb) {
      str = tvb_get_string_enc(pinfo->pool, cb_data_tvb, 0, tvb_reported_length(cb_data_tvb), ENC_UTF_8|ENC_NA);
      proto_tree_add_string_format(tree, hf_decoded_page, warning_msg_tvb, offset, 83,
                                   str, "Decoded Page %u: %s", i+1, str);
    }
    offset += 83;
  }
}

static void
s1ap_EUTRANRoundTripDelayEstimationInfo_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%uTs (%u)", 16*v, v);
}

static const true_false_string s1ap_tfs_activate_do_not_activate = {
  "Activate",
  "Do not activate"
};

static void
s1ap_Packet_LossRate_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1f %% (%u)", (float)v/10, v);
}

static void
s1ap_threshold_nr_rsrp_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%ddBm (%u)", (gint32)v-156, v);
}

static void
s1ap_threshold_nr_rsrq_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB (%u)", ((float)v/2)-43, v);
}

static void
s1ap_threshold_nr_sinr_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB (%u)", ((float)v/2)-23, v);
}

static struct s1ap_private_data*
s1ap_get_private_data(packet_info *pinfo)
{
  struct s1ap_private_data *s1ap_data = (struct s1ap_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_s1ap, 0);
  if (!s1ap_data) {
    s1ap_data = wmem_new0(pinfo->pool, struct s1ap_private_data);
    p_add_proto_data(pinfo->pool, pinfo, proto_s1ap, 0, s1ap_data);
  }
  return s1ap_data;
}

static gboolean
s1ap_is_nbiot_ue(packet_info *pinfo)
{
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(pinfo);

  if (s1ap_data->s1ap_conv) {
    wmem_tree_key_t tree_key[3];
    guint32 *id;
    guint32 enb_ue_s1ap_id = s1ap_data->enb_ue_s1ap_id;

    tree_key[0].length = 1;
    tree_key[0].key = &enb_ue_s1ap_id;
    tree_key[1].length = 1;
    tree_key[1].key = &pinfo->num;
    tree_key[2].length = 0;
    tree_key[2].key = NULL;
    id = (guint32*)wmem_tree_lookup32_array_le(s1ap_data->s1ap_conv->nbiot_enb_ue_s1ap_id, tree_key);
    if (id && (*id == enb_ue_s1ap_id)) {
      return TRUE;
    }
  }
  return FALSE;
}

#include "packet-s1ap-fn.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  s1ap_ctx_t s1ap_ctx;
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(pinfo);

  s1ap_ctx.message_type        = s1ap_data->message_type;
  s1ap_ctx.ProcedureCode       = s1ap_data->procedure_code;
  s1ap_ctx.ProtocolIE_ID       = s1ap_data->protocol_ie_id;
  s1ap_ctx.ProtocolExtensionID = s1ap_data->protocol_extension_id;

  return (dissector_try_uint_new(s1ap_ies_dissector_table, s1ap_data->protocol_ie_id, tvb, pinfo, tree, FALSE, &s1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}
/* Currently not used
static int dissect_ProtocolIEFieldPairFirstValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(pinfo);

  return (dissector_try_uint(s1ap_ies_p1_dissector_table, s1ap_data->protocol_ie_id, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolIEFieldPairSecondValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(pinfo);

  return (dissector_try_uint(s1ap_ies_p2_dissector_table, s1ap_data->protocol_ie_id, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}
*/

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  s1ap_ctx_t s1ap_ctx;
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(pinfo);

  s1ap_ctx.message_type        = s1ap_data->message_type;
  s1ap_ctx.ProcedureCode       = s1ap_data->procedure_code;
  s1ap_ctx.ProtocolIE_ID       = s1ap_data->protocol_ie_id;
  s1ap_ctx.ProtocolExtensionID = s1ap_data->protocol_extension_id;

  return (dissector_try_uint_new(s1ap_extension_dissector_table, s1ap_data->protocol_extension_id, tvb, pinfo, tree, FALSE, &s1ap_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(s1ap_proc_imsg_dissector_table, s1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(s1ap_proc_sout_dissector_table, s1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct s1ap_private_data *s1ap_data = s1ap_get_private_data(pinfo);

  return (dissector_try_uint_new(s1ap_proc_uout_dissector_table, s1ap_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}


static int
dissect_s1ap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *s1ap_item = NULL;
  proto_tree *s1ap_tree = NULL;
  conversation_t *conversation;
  struct s1ap_private_data* s1ap_data;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "S1AP");
  col_clear(pinfo->cinfo, COL_INFO);

  /* create the s1ap protocol tree */
  s1ap_item = proto_tree_add_item(tree, proto_s1ap, tvb, 0, -1, ENC_NA);
  s1ap_tree = proto_item_add_subtree(s1ap_item, ett_s1ap);

  s1ap_data = s1ap_get_private_data(pinfo);
  conversation = find_or_create_conversation(pinfo);
  s1ap_data->s1ap_conv = (struct s1ap_conv_info *)conversation_get_proto_data(conversation, proto_s1ap);
  if (!s1ap_data->s1ap_conv) {
    s1ap_data->s1ap_conv = wmem_new(wmem_file_scope(), struct s1ap_conv_info);
    s1ap_data->s1ap_conv->nbiot_ta = wmem_map_new(wmem_file_scope(), wmem_int64_hash, g_int64_equal);
    s1ap_data->s1ap_conv->nbiot_enb_ue_s1ap_id = wmem_tree_new(wmem_file_scope());
    conversation_add_proto_data(conversation, proto_s1ap, s1ap_data->s1ap_conv);
  }

  dissect_S1AP_PDU_PDU(tvb, pinfo, s1ap_tree, NULL);
  return tvb_captured_length(tvb);
}

/*--- proto_reg_handoff_s1ap ---------------------------------------*/
void
proto_reg_handoff_s1ap(void)
{
  gcsna_handle = find_dissector_add_dependency("gcsna", proto_s1ap);
  nas_eps_handle = find_dissector_add_dependency("nas-eps", proto_s1ap);
  lppa_handle = find_dissector_add_dependency("lppa", proto_s1ap);
  bssgp_handle = find_dissector_add_dependency("bssgp", proto_s1ap);
  lte_rrc_ue_radio_access_cap_info_handle = find_dissector_add_dependency("lte-rrc.ue_radio_access_cap_info", proto_s1ap);
  lte_rrc_ue_radio_access_cap_info_nb_handle = find_dissector_add_dependency("lte-rrc.ue_radio_access_cap_info.nb", proto_s1ap);
  nr_rrc_ue_radio_access_cap_info_handle = find_dissector_add_dependency("nr-rrc.ue_radio_access_cap_info", proto_s1ap);
  lte_rrc_ue_radio_paging_info_handle = find_dissector_add_dependency("lte-rrc.ue_radio_paging_info", proto_s1ap);
  lte_rrc_ue_radio_paging_info_nb_handle = find_dissector_add_dependency("lte-rrc.ue_radio_paging_info.nb", proto_s1ap);
  nr_rrc_ue_radio_paging_info_handle = find_dissector_add_dependency("nr-rrc.ue_radio_paging_info", proto_s1ap);
  dissector_add_uint("sctp.ppi", S1AP_PAYLOAD_PROTOCOL_ID, s1ap_handle);
  dissector_add_uint_with_preference("sctp.port", SCTP_PORT_S1AP, s1ap_handle);
#include "packet-s1ap-dis-tab.c"
}

/*--- proto_register_s1ap -------------------------------------------*/
void proto_register_s1ap(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_s1ap_transportLayerAddressIPv4,
      { "transportLayerAddress(IPv4)", "s1ap.transportLayerAddressIPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_transportLayerAddressIPv6,
      { "transportLayerAddress(IPv6)", "s1ap.transportLayerAddressIPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_UTRAN_Trace_ID_TraceID,
      { "TraceID", "s1ap.E_UTRAN_Trace_ID.TraceID",
        FT_UINT24, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_E_UTRAN_Trace_ID_TraceRecordingSessionReference,
      { "TraceRecordingSessionReference", "s1ap.E_UTRAN_Trace_ID.TraceRecordingSessionReference",
        FT_UINT16, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_interfacesToTrace_S1_MME,
      { "S1-MME", "s1ap.interfacesToTrace.S1_MME",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_interfacesToTrace), 0x80,
        NULL, HFILL }},
    { &hf_s1ap_interfacesToTrace_X2,
      { "X2", "s1ap.interfacesToTrace.X2",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_interfacesToTrace), 0x40,
        NULL, HFILL }},
    { &hf_s1ap_interfacesToTrace_Uu,
      { "Uu", "s1ap.interfacesToTrace.Uu",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_interfacesToTrace), 0x20,
        NULL, HFILL }},
    { &hf_s1ap_interfacesToTrace_F1_C,
      { "F1-C", "s1ap.interfacesToTrace.F1_C",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_interfacesToTrace), 0x10,
        NULL, HFILL }},
    { &hf_s1ap_interfacesToTrace_E1,
      { "E1", "s1ap.interfacesToTrace.E1",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_interfacesToTrace), 0x08,
        NULL, HFILL }},
    { &hf_s1ap_interfacesToTrace_Reserved,
      { "Reserved", "s1ap.interfacesToTrace.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x07,
        NULL, HFILL }},
    { &hf_s1ap_encryptionAlgorithms_EEA1,
      { "128-EEA1", "s1ap.encryptionAlgorithms.EEA1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_s1ap_encryptionAlgorithms_EEA2,
      { "128-EEA2", "s1ap.encryptionAlgorithms.EEA2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_s1ap_encryptionAlgorithms_EEA3,
      { "128-EEA3", "s1ap.encryptionAlgorithms.EEA3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_s1ap_encryptionAlgorithms_Reserved,
      { "Reserved", "s1ap.encryptionAlgorithms.Reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_s1ap_integrityProtectionAlgorithms_EIA1,
      { "128-EIA1", "s1ap.integrityProtectionAlgorithms.EIA1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_s1ap_integrityProtectionAlgorithms_EIA2,
      { "128-EIA2", "s1ap.integrityProtectionAlgorithms.EIA2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_s1ap_integrityProtectionAlgorithms_EIA3,
      { "128-EIA3", "s1ap.integrityProtectionAlgorithms.EIA3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_s1ap_integrityProtectionAlgorithms_Reserved,
      { "Reserved", "s1ap.integrityProtectionAlgorithms.Reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_s1ap_SerialNumber_gs,
      { "Geographical Scope", "s1ap.SerialNumber.gs",
        FT_UINT16, BASE_DEC, VALS(s1ap_serialNumber_gs_vals), 0xc000,
        NULL, HFILL }},
    { &hf_s1ap_SerialNumber_msg_code,
      { "Message Code", "s1ap.SerialNumber.msg_code",
        FT_UINT16, BASE_DEC, NULL, 0x3ff0,
        NULL, HFILL }},
    { &hf_s1ap_SerialNumber_upd_nb,
      { "Update Number", "s1ap.SerialNumber.upd_nb",
        FT_UINT16, BASE_DEC, NULL, 0x000f,
        NULL, HFILL }},
    { &hf_s1ap_WarningType_value,
      { "Warning Type Value", "s1ap.WarningType.value",
        FT_UINT16, BASE_DEC, VALS(s1ap_warningType_vals), 0xfe00,
        NULL, HFILL }},
    { &hf_s1ap_WarningType_emergency_user_alert,
      { "Emergency User Alert", "s1ap.WarningType.emergency_user_alert",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0100,
        NULL, HFILL }},
    { &hf_s1ap_WarningType_popup,
      { "Popup", "s1ap.WarningType.popup",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0080,
        NULL, HFILL }},
    { &hf_s1ap_WarningMessageContents_nb_pages,
      { "Number of Pages", "s1ap.WarningMessageContents.nb_pages",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_WarningMessageContents_decoded_page,
      { "Decoded Page", "s1ap.WarningMessageContents.decoded_page",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_s1ap_measurementsToActivate_M1,
      { "M1", "s1ap.measurementsToActivate.M1",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x80,
        NULL, HFILL }},
    { &hf_s1ap_measurementsToActivate_M2,
      { "M2", "s1ap.measurementsToActivate.M2",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x40,
        NULL, HFILL }},
    { &hf_s1ap_measurementsToActivate_M3,
      { "M3", "s1ap.measurementsToActivate.M3",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x20,
        NULL, HFILL }},
    { &hf_s1ap_measurementsToActivate_M4,
      { "M4", "s1ap.measurementsToActivate.M4",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x10,
        NULL, HFILL }},
    { &hf_s1ap_measurementsToActivate_M5,
      { "M5", "s1ap.measurementsToActivate.M5",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x08,
        NULL, HFILL }},
    { &hf_s1ap_measurementsToActivate_LoggingM1FromEventTriggered,
      { "LoggingOfM1FromEventTriggeredMeasurementReports", "s1ap.measurementsToActivate.LoggingM1FromEventTriggered",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x04,
        NULL, HFILL }},
    { &hf_s1ap_measurementsToActivate_M6,
      { "M6", "s1ap.measurementsToActivate.M6",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x02,
        NULL, HFILL }},
    { &hf_s1ap_measurementsToActivate_M7,
      { "M7", "s1ap.measurementsToActivate.M7",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x01,
        NULL, HFILL }},
    { &hf_s1ap_MDT_Location_Info_GNSS,
      { "GNSS", "s1ap.MDT_Location_Info.GNSS",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x80,
        NULL, HFILL }},
    { &hf_s1ap_MDT_Location_Info_E_CID,
      { "E-CID", "s1ap.MDT_Location_Info.E_CID",
        FT_BOOLEAN, 8, TFS(&s1ap_tfs_activate_do_not_activate), 0x40,
        NULL, HFILL }},
    { &hf_s1ap_MDT_Location_Info_Reserved,
      { "Reserved", "s1ap.MDT_Location_Info.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x3f,
        NULL, HFILL }},
    { &hf_s1ap_NRencryptionAlgorithms_NEA1,
      { "128-NEA1", "s1ap.NRencryptionAlgorithms.NEA1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_s1ap_NRencryptionAlgorithms_NEA2,
      { "128-NEA2", "s1ap.NRencryptionAlgorithms.NEA2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_s1ap_NRencryptionAlgorithms_NEA3,
      { "128-NEA3", "s1ap.NRencryptionAlgorithms.NEA3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_s1ap_NRencryptionAlgorithms_Reserved,
      { "Reserved", "s1ap.NRencryptionAlgorithms.Reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_s1ap_NRintegrityProtectionAlgorithms_NIA1,
      { "128-NIA1", "s1ap.NRintegrityProtectionAlgorithms.NIA1",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x8000,
        NULL, HFILL }},
    { &hf_s1ap_NRintegrityProtectionAlgorithms_NIA2,
      { "128-NIA2", "s1ap.NRintegrityProtectionAlgorithms.NIA2",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x4000,
        NULL, HFILL }},
    { &hf_s1ap_NRintegrityProtectionAlgorithms_NIA3,
      { "128-NIA3", "s1ap.NRintegrityProtectionAlgorithms.NIA3",
        FT_BOOLEAN, 16, TFS(&tfs_supported_not_supported), 0x2000,
        NULL, HFILL }},
    { &hf_s1ap_NRintegrityProtectionAlgorithms_Reserved,
      { "Reserved", "s1ap.NRintegrityProtectionAlgorithms.Reserved",
        FT_UINT16, BASE_HEX, NULL, 0x1fff,
        NULL, HFILL }},
    { &hf_s1ap_UE_Application_Layer_Measurement_Capability_QoE_Measurement_for_streaming_service,
      { "QoE Measurement for streaming service", "s1ap.UE_Application_Layer_Measurement_Capability.QoE_Measurement_for_streaming_service",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
        NULL, HFILL }},
    { &hf_s1ap_UE_Application_Layer_Measurement_Capability_QoE_Measurement_for_MTSI_service,
      { "QoE Measurement for MTSI service", "s1ap.UE_Application_Layer_Measurement_Capability.QoE_Measurement_for_MTSI_service",
        FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
        NULL, HFILL }},
    { &hf_s1ap_UE_Application_Layer_Measurement_Capability_Reserved,
      { "Reserved", "s1ap.UE_Application_Layer_Measurement_Capability.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x3f,
        NULL, HFILL }},
    { &hf_s1ap_rAT_RestrictionInformation_LEO,
      { "LEO", "s1ap.rAT_RestrictionInformation.LEO",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x80,
        NULL, HFILL }},
    { &hf_s1ap_rAT_RestrictionInformation_MEO,
      { "MEO", "s1ap.rAT_RestrictionInformation.MEO",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x40,
        NULL, HFILL }},
    { &hf_s1ap_rAT_RestrictionInformation_GEO,
      { "GEO", "s1ap.rAT_RestrictionInformation.GEO",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x20,
        NULL, HFILL }},
    { &hf_s1ap_rAT_RestrictionInformation_OTHERSAT,
      { "OTHERSAT", "s1ap.rAT_RestrictionInformation.OTHERSAT",
        FT_BOOLEAN, 8, TFS(&tfs_restricted_not_restricted), 0x10,
        NULL, HFILL }},
    { &hf_s1ap_rAT_RestrictionInformation_Reserved,
      { "Reserved", "s1ap.rAT_RestrictionInformation.Reserved",
        FT_UINT8, BASE_HEX, NULL, 0x0f,
        NULL, HFILL }},
#include "packet-s1ap-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_s1ap,
    &ett_s1ap_TransportLayerAddress,
    &ett_s1ap_ToTargetTransparentContainer,
    &ett_s1ap_ToSourceTransparentContainer,
    &ett_s1ap_RRCContainer,
    &ett_s1ap_UERadioCapability,
    &ett_s1ap_RIMInformation,
    &ett_s1ap_Cdma2000PDU,
    &ett_s1ap_Cdma2000SectorID,
    &ett_s1ap_UERadioPagingInformation,
    &ett_s1ap_UE_HistoryInformationFromTheUE,
    &ett_s1ap_CELevel,
    &ett_s1ap_UE_RLF_Report_Container,
    &ett_s1ap_UE_RLF_Report_Container_for_extended_bands,
    &ett_s1ap_S1_Message,
    &ett_s1ap_E_UTRAN_Trace_ID,
    &ett_s1ap_InterfacesToTrace,
    &ett_s1ap_EncryptionAlgorithms,
    &ett_s1ap_IntegrityProtectionAlgorithms,
    &ett_s1ap_LastVisitedNGRANCellInformation,
    &ett_s1ap_LastVisitedUTRANCellInformation,
    &ett_s1ap_SerialNumber,
    &ett_s1ap_WarningType,
    &ett_s1ap_DataCodingScheme,
    &ett_s1ap_WarningMessageContents,
    &ett_s1ap_MSClassmark,
    &ett_s1ap_MeasurementsToActivate,
    &ett_s1ap_MDT_Location_Info,
    &ett_s1ap_IMSI,
    &ett_s1ap_NASSecurityParameters,
    &ett_s1ap_NRencryptionAlgorithms,
    &ett_s1ap_NRintegrityProtectionAlgorithms,
    &ett_s1ap_UE_Application_Layer_Measurement_Capability,
    &ett_s1ap_sMTC,
    &ett_s1ap_threshRS_Index_r15,
    &ett_s1ap_sSBToMeasure,
    &ett_s1ap_sSRSSIMeasurement,
    &ett_s1ap_quantityConfigNR_R15,
    &ett_s1ap_excludedCellsToAddModList,
    &ett_s1ap_NB_IoT_RLF_Report_Container,
    &ett_s1ap_MDT_ConfigurationNR,
    &ett_s1ap_IntersystemSONConfigurationTransfer,
    &ett_s1ap_rAT_RestrictionInformation,
#include "packet-s1ap-ettarr.c"
  };

  static ei_register_info ei[] = {
    { &ei_s1ap_number_pages_le15, { "s1ap.number_pages_le15", PI_MALFORMED, PI_ERROR, "Number of pages should be <=15", EXPFILL }}
  };

  module_t *s1ap_module;
  expert_module_t* expert_s1ap;

  /* Register protocol */
  proto_s1ap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_s1ap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_s1ap = expert_register_protocol(proto_s1ap);
  expert_register_field_array(expert_s1ap, ei, array_length(ei));

  /* Register dissector */
  s1ap_handle = register_dissector("s1ap", dissect_s1ap, proto_s1ap);

  /* Register dissector tables */
  s1ap_ies_dissector_table = register_dissector_table("s1ap.ies", "S1AP-PROTOCOL-IES", proto_s1ap, FT_UINT32, BASE_DEC);
  s1ap_ies_p1_dissector_table = register_dissector_table("s1ap.ies.pair.first", "S1AP-PROTOCOL-IES-PAIR FirstValue", proto_s1ap, FT_UINT32, BASE_DEC);
  s1ap_ies_p2_dissector_table = register_dissector_table("s1ap.ies.pair.second", "S1AP-PROTOCOL-IES-PAIR SecondValue", proto_s1ap, FT_UINT32, BASE_DEC);
  s1ap_extension_dissector_table = register_dissector_table("s1ap.extension", "S1AP-PROTOCOL-EXTENSION", proto_s1ap, FT_UINT32, BASE_DEC);
  s1ap_proc_imsg_dissector_table = register_dissector_table("s1ap.proc.imsg", "S1AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_s1ap, FT_UINT32, BASE_DEC);
  s1ap_proc_sout_dissector_table = register_dissector_table("s1ap.proc.sout", "S1AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_s1ap, FT_UINT32, BASE_DEC);
  s1ap_proc_uout_dissector_table = register_dissector_table("s1ap.proc.uout", "S1AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_s1ap, FT_UINT32, BASE_DEC);

  /* Register configuration options for ports */
  s1ap_module = prefs_register_protocol(proto_s1ap, NULL);

  prefs_register_bool_preference(s1ap_module, "dissect_container", "Dissect TransparentContainer", "Dissect TransparentContainers that are opaque to S1AP", &g_s1ap_dissect_container);
  prefs_register_enum_preference(s1ap_module, "dissect_lte_container_as", "Dissect LTE TransparentContainer as",
                                 "Select whether LTE TransparentContainer should be dissected as NB-IOT or legacy LTE",
                                 &g_s1ap_dissect_lte_container_as, s1ap_lte_container_vals, FALSE);
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
