/* packet-nr-rrc-template.c
 * NR;
 * Radio Resource Control (RRC) protocol specification
 * (3GPP TS 38.331 V17.1.0 Release 17) packet dissection
 * Copyright 2018-2022, Pascal Quantin
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/proto_data.h>
#include <epan/prefs.h>

#include <wsutil/str_util.h>
#include <wsutil/epochs.h>

#include "packet-per.h"
#include "packet-gsm_map.h"
#include "packet-cell_broadcast.h"
#include "packet-mac-nr.h"
#include "packet-rlc-nr.h"
#include "packet-pdcp-nr.h"
#include "packet-rrc.h"
#include "packet-lte-rrc.h"
#include "packet-nr-rrc.h"
#include "packet-gsm_a_common.h"
#include "packet-lpp.h"

#define PNAME  "NR Radio Resource Control (RRC) protocol"
#define PSNAME "NR RRC"
#define PFNAME "nr-rrc"

void proto_register_nr_rrc(void);
void proto_reg_handoff_nr_rrc(void);

static dissector_handle_t nas_5gs_handle = NULL;
static dissector_handle_t lte_rrc_conn_reconf_handle = NULL;
static dissector_handle_t lte_rrc_conn_reconf_compl_handle = NULL;
static dissector_handle_t lte_rrc_ul_dcch_handle = NULL;
static dissector_handle_t lte_rrc_dl_dcch_handle = NULL;

static wmem_map_t *nr_rrc_etws_cmas_dcs_hash = NULL;

static reassembly_table nr_rrc_sib7_reassembly_table;
static reassembly_table nr_rrc_sib8_reassembly_table;

static gboolean nr_rrc_nas_in_root_tree;

extern int proto_mac_nr;
extern int proto_pdcp_nr;

/* Include constants */
#include "packet-nr-rrc-val.h"

/* Initialize the protocol and registered fields */
static int proto_nr_rrc = -1;
#include "packet-nr-rrc-hf.c"
static int hf_nr_rrc_serialNumber_gs = -1;
static int hf_nr_rrc_serialNumber_msg_code = -1;
static int hf_nr_rrc_serialNumber_upd_nb = -1;
static int hf_nr_rrc_warningType_value = -1;
static int hf_nr_rrc_warningType_emergency_user_alert = -1;
static int hf_nr_rrc_warningType_popup = -1;
static int hf_nr_rrc_warningMessageSegment_nb_pages = -1;
static int hf_nr_rrc_warningMessageSegment_decoded_page = -1;
static int hf_nr_rrc_sib7_fragments = -1;
static int hf_nr_rrc_sib7_fragment = -1;
static int hf_nr_rrc_sib7_fragment_overlap = -1;
static int hf_nr_rrc_sib7_fragment_overlap_conflict = -1;
static int hf_nr_rrc_sib7_fragment_multiple_tails = -1;
static int hf_nr_rrc_sib7_fragment_too_long_fragment = -1;
static int hf_nr_rrc_sib7_fragment_error = -1;
static int hf_nr_rrc_sib7_fragment_count = -1;
static int hf_nr_rrc_sib7_reassembled_in = -1;
static int hf_nr_rrc_sib7_reassembled_length = -1;
static int hf_nr_rrc_sib7_reassembled_data = -1;
static int hf_nr_rrc_sib8_fragments = -1;
static int hf_nr_rrc_sib8_fragment = -1;
static int hf_nr_rrc_sib8_fragment_overlap = -1;
static int hf_nr_rrc_sib8_fragment_overlap_conflict = -1;
static int hf_nr_rrc_sib8_fragment_multiple_tails = -1;
static int hf_nr_rrc_sib8_fragment_too_long_fragment = -1;
static int hf_nr_rrc_sib8_fragment_error = -1;
static int hf_nr_rrc_sib8_fragment_count = -1;
static int hf_nr_rrc_sib8_reassembled_in = -1;
static int hf_nr_rrc_sib8_reassembled_length = -1;
static int hf_nr_rrc_sib8_reassembled_data = -1;
static int hf_nr_rrc_utc_time = -1;
static int hf_nr_rrc_local_time = -1;
static int hf_nr_rrc_absolute_time = -1;

/* Initialize the subtree pointers */
static gint ett_nr_rrc = -1;
#include "packet-nr-rrc-ett.c"
static gint ett_nr_rrc_DedicatedNAS_Message = -1;
static gint ett_nr_rrc_targetRAT_MessageContainer = -1;
static gint ett_nr_rrc_nas_Container = -1;
static gint ett_nr_rrc_serialNumber = -1;
static gint ett_nr_rrc_warningType = -1;
static gint ett_nr_rrc_dataCodingScheme = -1;
static gint ett_nr_rrc_sib7_fragment = -1;
static gint ett_nr_rrc_sib7_fragments = -1;
static gint ett_nr_rrc_sib8_fragment = -1;
static gint ett_nr_rrc_sib8_fragments = -1;
static gint ett_nr_rrc_warningMessageSegment = -1;
static gint ett_nr_rrc_timeInfo = -1;
static gint ett_nr_rrc_capabilityRequestFilter = -1;
static gint ett_nr_rrc_sourceSCG_EUTRA_Config = -1;
static gint ett_nr_rrc_scg_CellGroupConfigEUTRA = -1;
static gint ett_nr_rrc_candidateCellInfoListSN_EUTRA = -1;
static gint ett_nr_rrc_candidateCellInfoListMN_EUTRA = -1;
static gint ett_nr_rrc_sourceConfigSCG_EUTRA = -1;
static gint ett_nr_rrc_eutra_SCG = -1;
static gint ett_nr_rrc_nr_SCG_Response = -1;
static gint ett_nr_rrc_eutra_SCG_Response = -1;
static gint ett_nr_rrc_measResultSCG_FailureMRDC = -1;
static gint ett_nr_rrc_ul_DCCH_MessageNR = -1;
static gint ett_nr_rrc_ul_DCCH_MessageEUTRA = -1;
static gint ett_rr_rrc_nas_SecurityParamFromNR = -1;
static gint ett_nr_rrc_sidelinkUEInformationNR = -1;
static gint ett_nr_rrc_sidelinkUEInformationEUTRA = -1;
static gint ett_nr_rrc_ueAssistanceInformationEUTRA = -1;
static gint ett_nr_rrc_dl_DCCH_MessageNR = -1;
static gint ett_nr_rrc_dl_DCCH_MessageEUTRA = -1;
static gint ett_nr_rrc_sl_ConfigDedicatedEUTRA = -1;
static gint ett_nr_rrc_sl_CapabilityInformationSidelink = -1;
static gint ett_nr_rrc_measResult_RLF_Report_EUTRA = -1;
static gint ett_nr_rrc_measResult_RLF_Report_EUTRA_v1690 = -1;
static gint ett_nr_rrc_locationTimestamp_r16 = -1;
static gint ett_nr_rrc_locationCoordinate_r16 = -1;
static gint ett_nr_rrc_locationError_r16 = -1;
static gint ett_nr_rrc_locationSource_r16 = -1;
static gint ett_nr_rrc_velocityEstimate_r16 = -1;
static gint ett_nr_rrc_sensor_MeasurementInformation_r16 = -1;
static gint ett_nr_rrc_sensor_MotionInformation_r16 = -1;
static gint ett_nr_rrc_bandParametersSidelinkEUTRA1_r16 = -1;
static gint ett_nr_rrc_bandParametersSidelinkEUTRA2_r16 = -1;
static gint ett_nr_rrc_sl_ParametersEUTRA1_r16 = -1;
static gint ett_nr_rrc_sl_ParametersEUTRA2_r16 = -1;
static gint ett_nr_rrc_sl_ParametersEUTRA3_r16 = -1;
static gint ett_nr_rrc_absTimeInfo = -1;
static gint ett_nr_rrc_assistanceDataSIB_Element_r16 = -1;
static gint ett_nr_sl_V2X_ConfigCommon_r16 = -1;
static gint ett_nr_tdd_Config_r16 = -1;
static gint ett_nr_coarseLocationInfo_r17 = -1;
static gint ett_nr_sl_MeasResultsCandRelay_r17 = -1;
static gint ett_nr_sl_MeasResultServingRelay_r17 = -1;
static gint ett_nr_ReferenceLocation_r17 = -1;

static expert_field ei_nr_rrc_number_pages_le15 = EI_INIT;

/* Forward declarations */
static int dissect_UECapabilityInformationSidelink_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_DL_DCCH_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_DL_CCCH_Message_PDU(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_);
static int dissect_UL_CCCH_Message_PDU(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_);
static int dissect_UERadioAccessCapabilityInformation_PDU(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_);
static int dissect_SL_MeasResultListRelay_r17_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_SL_MeasResultRelay_r17_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

static const unit_name_string units_periodicities = { " periodicity", " periodicities" };
static const unit_name_string units_prbs = { " PRB", " PRBs" };
static const unit_name_string units_slots = { " slot", " slots" };

typedef struct {
  guint8 rat_type;
  guint8 target_rat_type;
  guint16 message_identifier;
  guint8 warning_message_segment_type;
  guint8 warning_message_segment_number;
  nr_drb_mac_rlc_mapping_t drb_rlc_mapping;
  nr_drb_rlc_pdcp_mapping_t drb_pdcp_mapping;
  lpp_pos_sib_type_t pos_sib_type;
  pdcp_nr_security_info_t pdcp_security;
} nr_rrc_private_data_t;

/* Helper function to get or create a struct that will be actx->private_data */
static nr_rrc_private_data_t*
nr_rrc_get_private_data(asn1_ctx_t *actx)
{
  if (actx->private_data == NULL) {
    actx->private_data = wmem_new0(actx->pinfo->pool, nr_rrc_private_data_t);
  }
  return (nr_rrc_private_data_t*)actx->private_data;
}


static void
nr_rrc_call_dissector(dissector_handle_t handle, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  TRY {
    call_dissector(handle, tvb, pinfo, tree);
  }
  CATCH_BOUNDS_ERRORS {
    show_exception(tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);
  }
  ENDTRY;
}

static void
nr_rrc_q_RxLevMin_fmt(gchar *s, guint32 v)
{
  gint32 d = (gint32)v;

  snprintf(s, ITEM_LABEL_LENGTH, "%d dB (%d)", 2*d, d);
}

static const value_string nr_rrc_serialNumber_gs_vals[] = {
  { 0, "Display mode immediate, cell wide"},
  { 1, "Display mode normal, PLMN wide"},
  { 2, "Display mode normal, tracking area wide"},
  { 3, "Display mode normal, cell wide"},
  { 0, NULL},
};

static const value_string nr_rrc_warningType_vals[] = {
  { 0, "Earthquake"},
  { 1, "Tsunami"},
  { 2, "Earthquake and Tsunami"},
  { 3, "Test"},
  { 4, "Other"},
  { 0, NULL},
};

static const fragment_items nr_rrc_sib7_frag_items = {
    &ett_nr_rrc_sib7_fragment,
    &ett_nr_rrc_sib7_fragments,
    &hf_nr_rrc_sib7_fragments,
    &hf_nr_rrc_sib7_fragment,
    &hf_nr_rrc_sib7_fragment_overlap,
    &hf_nr_rrc_sib7_fragment_overlap_conflict,
    &hf_nr_rrc_sib7_fragment_multiple_tails,
    &hf_nr_rrc_sib7_fragment_too_long_fragment,
    &hf_nr_rrc_sib7_fragment_error,
    &hf_nr_rrc_sib7_fragment_count,
    &hf_nr_rrc_sib7_reassembled_in,
    &hf_nr_rrc_sib7_reassembled_length,
    &hf_nr_rrc_sib7_reassembled_data,
    "SIB7 warning message segments"
};

static const fragment_items nr_rrc_sib8_frag_items = {
    &ett_nr_rrc_sib8_fragment,
    &ett_nr_rrc_sib8_fragments,
    &hf_nr_rrc_sib8_fragments,
    &hf_nr_rrc_sib8_fragment,
    &hf_nr_rrc_sib8_fragment_overlap,
    &hf_nr_rrc_sib8_fragment_overlap_conflict,
    &hf_nr_rrc_sib8_fragment_multiple_tails,
    &hf_nr_rrc_sib8_fragment_too_long_fragment,
    &hf_nr_rrc_sib8_fragment_error,
    &hf_nr_rrc_sib8_fragment_count,
    &hf_nr_rrc_sib8_reassembled_in,
    &hf_nr_rrc_sib8_reassembled_length,
    &hf_nr_rrc_sib8_reassembled_data,
    "SIB8 warning message segments"
};

static void
dissect_nr_rrc_warningMessageSegment(tvbuff_t *warning_msg_seg_tvb, proto_tree *tree, packet_info *pinfo, guint8 dataCodingScheme)
{
  guint32 offset;
  guint8 nb_of_pages, length, *str;
  proto_item *ti;
  tvbuff_t *cb_data_page_tvb, *cb_data_tvb;
  int i;

  nb_of_pages = tvb_get_guint8(warning_msg_seg_tvb, 0);
  ti = proto_tree_add_uint(tree, hf_nr_rrc_warningMessageSegment_nb_pages, warning_msg_seg_tvb, 0, 1, nb_of_pages);
  if (nb_of_pages > 15) {
    expert_add_info_format(pinfo, ti, &ei_nr_rrc_number_pages_le15,
                           "Number of pages should be <=15 (found %u)", nb_of_pages);
    nb_of_pages = 15;
  }
  for (i = 0, offset = 1; i < nb_of_pages; i++) {
    length = tvb_get_guint8(warning_msg_seg_tvb, offset+82);
    cb_data_page_tvb = tvb_new_subset_length(warning_msg_seg_tvb, offset, length);
    cb_data_tvb = dissect_cbs_data(dataCodingScheme, cb_data_page_tvb, tree, pinfo, 0);
    if (cb_data_tvb) {
      str = tvb_get_string_enc(pinfo->pool, cb_data_tvb, 0, tvb_reported_length(cb_data_tvb), ENC_UTF_8|ENC_NA);
      proto_tree_add_string_format(tree, hf_nr_rrc_warningMessageSegment_decoded_page, warning_msg_seg_tvb, offset, 83,
                                   str, "Decoded Page %u: %s", i+1, str);
    }
    offset += 83;
  }
}

static const value_string nr_rrc_daylightSavingTime_vals[] = {
  { 0, "No adjustment for Daylight Saving Time"},
  { 1, "+1 hour adjustment for Daylight Saving Time"},
  { 2, "+2 hours adjustment for Daylight Saving Time"},
  { 3, "Reserved"},
  { 0, NULL},
};

static void
nr_rrc_localTimeOffset_fmt(gchar *s, guint32 v)
{
  gint32 time_offset = (gint32) v;

  snprintf(s, ITEM_LABEL_LENGTH, "UTC time %c %dhr %dmin (%d)",
             (time_offset < 0) ? '-':'+', abs(time_offset) >> 2,
             (abs(time_offset) & 0x03) * 15, time_offset);
}

static void
nr_rrc_drx_SlotOffset_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%g ms (%u)", 1./32 * v, v);
}

static void
nr_rrc_Hysteresis_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%gdB (%u)", 0.5 * v, v);
}

static void
nr_rrc_msg3_DeltaPreamble_fmt(gchar *s, guint32 v)
{
  gint32 d = (gint32)v;

  snprintf(s, ITEM_LABEL_LENGTH, "%ddB (%d)", 2 * d, d);
}

static void
nr_rrc_Q_RxLevMin_fmt(gchar *s, guint32 v)
{
  gint32 d = (gint32)v;

  snprintf(s, ITEM_LABEL_LENGTH, "%ddBm (%d)", 2 * d, d);
}

static void
nr_rrc_RSRP_RangeEUTRA_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSRP < -140dBm (0)");
  } else if (v < 97) {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= RSRP < %ddBm (%u)", v-141, v-140, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "-44dBm <= RSRP (97)");
  }
}

static void
nr_rrc_RSRQ_RangeEUTRA_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSRQ < -19.5dB (0)");
  } else if (v < 34) {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= RSRQ < %.1fdB (%u)", ((float)v/2)-20, (((float)v+1)/2)-20, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "-3dB <= RSRQ (34)");
  }
}

static void
nr_rrc_SINR_RangeEUTRA_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "SINR < -23dB (0)");
  } else if (v == 127) {
    snprintf(s, ITEM_LABEL_LENGTH, "40dB <= SINR (127)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= SINR < %.1fdB (%u)", (((float)v-1)/2)-23, ((float)v/2)-23, v);
  }
}

static void
nr_rrc_ReselectionThreshold_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%udB (%u)", 2 * v, v);
}

static void
nr_rrc_RSRP_Range_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "SS-RSRP < -156dBm (0)");
  } else if (v < 126) {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= SS-RSRP < %ddBm (%u)", v-157, v-156, v);
  } else if (v == 126) {
    snprintf(s, ITEM_LABEL_LENGTH, "-31dBm <= SS-RSRP (126)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "infinity (127)");
  }
}

static void
nr_rrc_RSRQ_Range_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "SS-RSRQ < -43dB (0)");
  } else if (v < 127) {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= SS-RSRQ < %.1fdB (%u)", (((float)v-1)/2)-43, ((float)v/2)-43, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "-20dB <= SS-RSRQ (127)");
  }
}

static void
nr_rrc_SINR_Range_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "SS-SINR < -23dB (0)");
  } else if (v < 127) {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= SS-SINR < %.1fdB (%u)", (((float)v-1)/2)-23, ((float)v/2)-23, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "40dB <= SS-SINR (127)");
  }
}

static void
nr_rrc_dl_1024QAM_TotalWeightedLayers_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%u (%u)", 10+(2*v), v);
}

static void
nr_rrc_timeConnFailure_r16_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%ums (%u)", 100*v, v);
}

static void
nr_rrc_RSSI_Range_r16_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSSI < -100dBm (0)");
  } else if (v < 76) {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= RSSI < %ddBm (%u)", v-101, v-100, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "-25dBm <= RSSI (76)");
  }
}

static void
nr_rrc_RSRQ_RangeEUTRA_r16_fmt(gchar *s, guint32 v)
{
  gint32 d = (gint32)v;

  if (d == -34) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSRQ < -36dB (-34)");
  } else if (d < 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= RSRQ < %.1fdB (%d)", (((float)d-1)/2)-19, ((float)d/2)-19, d);
  } else if (d == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSRQ < -19.5dB (0)");
  } else if (d < 34) {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= RSRQ < %.1fdB (%d)", (((float)d-1)/2)-19.5, ((float)d/2)-19.5, d);
  } else if (d == 34) {
    snprintf(s, ITEM_LABEL_LENGTH, "-3dB <= RSRQ (34)");
  } else if (d < 46) {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= RSRQ < %.1fdB (%d)", (((float)d-1)/2)-20, ((float)d/2)-20, d);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "2.5dB <= RSRQ (46)");
  }
}

static void
nr_rrc_utra_FDD_RSCP_r16_fmt(gchar *s, guint32 v)
{
  gint32 d = (gint32)v;

  if (d == -5) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSCP < -120dBm (-5)");
  } else if (d < 91) {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= RSCP < %ddB (%d)", d-116, d-115, d);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "-25dBm <= RSCP (91)");
  }
}

static void
nr_rrc_utra_FDD_EcN0_r16_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "Ec/No < -24dB (0)");
  } else if (v < 49) {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= Ec/No < %.1fdB (%u)", (((float)v-1)/2)-24, ((float)v/2)-24, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "0dB <= Ec/No (49)");
  }
}

static void
nr_rrc_averageDelay_r16_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fms (%u)", (float)v/10, v);
}

static void
nr_rrc_measTriggerQuantity_utra_FDD_RSCP_r16_fmt(gchar *s, guint32 v)
{
  gint32 d = (gint32)v;

  snprintf(s, ITEM_LABEL_LENGTH, "%ddBm (%d)", d-115, d);
}

static void
nr_rrc_measTriggerQuantity_utra_FDD_EcN0_r16_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB (%u)", (float)v/2-24.5, v);
}

static void
nr_rrc_SRS_RSRP_r16_fmt(gchar *s, guint32 v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "SRS-RSRP < -140dBm (0)");
  } else if (v < 97) {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= SRS-RSRP < %ddB (%u)", v-141, v-140, v);
  } else if (v == 97) {
    snprintf(s, ITEM_LABEL_LENGTH, "-44dBm <= SRS-RSRP (97)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "Infinity (98)");
  }
}

static void
nr_rrc_MeasTriggerQuantityOffset_fmt(gchar *s, guint32 v)
{
  gint32 d = (gint32)v;

  snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB (%d)", (float)d/2, d);
}

static void
nr_rrc_TimeSinceCHO_Reconfig_r17_fmt(gchar *s, guint32 v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fs (%u)", (float)v/10, v);
}

static int
dissect_nr_rrc_cg_configinfo_msg(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    proto_item* ti;
    proto_tree* sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NR RRC");
    col_set_str(pinfo->cinfo, COL_INFO, "CG-ConfigInfo");

    ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_nr_rrc);
    return dissect_nr_rrc_CG_ConfigInfo_PDU(tvb, pinfo, sub_tree, NULL);
}

static int
dissect_nr_rrc_radiobearerconfig_msg(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    proto_item* ti;
    proto_tree* sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NR RRC");
    col_set_str(pinfo->cinfo, COL_INFO, "RadioBearerConfig");

    ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_nr_rrc);
    return dissect_nr_rrc_RadioBearerConfig_PDU(tvb, pinfo, sub_tree, NULL);
}

static int
dissect_nr_rrc_ue_mrdc_capability_msg(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    proto_item* ti;
    proto_tree* sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NR RRC");
    col_set_str(pinfo->cinfo, COL_INFO, "UE-MRDC-Capability");

    ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_nr_rrc);
    return dissect_nr_rrc_UE_MRDC_Capability_PDU(tvb, pinfo, sub_tree, NULL);
}

static int
dissect_nr_rrc_ue_nr_capability_msg(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    proto_item* ti;
    proto_tree* sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NR RRC");
    col_set_str(pinfo->cinfo, COL_INFO, "UE-NR-Capability");

    ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_nr_rrc);
    return dissect_nr_rrc_UE_NR_Capability_PDU(tvb, pinfo, sub_tree, NULL);
}

static int
dissect_nr_rrc_ul_dcch_message_msg(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    proto_item* ti;
    proto_tree* sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NR RRC");
    col_set_str(pinfo->cinfo, COL_INFO, "UL-DCCH-Message");

    ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_nr_rrc);
    return dissect_nr_rrc_UL_DCCH_Message_PDU(tvb, pinfo, sub_tree, NULL);
}

static int
dissect_nr_rrc_dl_dcch_message_msg(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    proto_item* ti;
    proto_tree* sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NR RRC");
    col_set_str(pinfo->cinfo, COL_INFO, "DL-DCCH-Message");

    ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_nr_rrc);
    return dissect_DL_DCCH_Message_PDU(tvb, pinfo, sub_tree, NULL);
}

static int
dissect_nr_rrc_dl_ccch_message_msg(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    proto_item* ti;
    proto_tree* sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NR RRC");
    col_set_str(pinfo->cinfo, COL_INFO, "DL-CCCH-Message");

    ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_nr_rrc);
    return dissect_DL_CCCH_Message_PDU(tvb, pinfo, sub_tree, NULL);
}

static int
dissect_nr_rrc_ul_ccch_message_msg(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    proto_item* ti;
    proto_tree* sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NR RRC");
    col_set_str(pinfo->cinfo, COL_INFO, "UL-CCCH-Message");

    ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_nr_rrc);
    return dissect_UL_CCCH_Message_PDU(tvb, pinfo, sub_tree, NULL);
}


static int
dissect_nr_rrc_cellgroupconfig_msg(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    proto_item* ti;
    proto_tree* sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NR RRC");
    col_set_str(pinfo->cinfo, COL_INFO, "CellGroupConfig");

    ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_nr_rrc);
    return dissect_nr_rrc_CellGroupConfig_PDU(tvb, pinfo, sub_tree, NULL);
}

static int
dissect_ueradioaccesscapabilityinformation_msg(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    proto_item* ti;
    proto_tree* sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NR RRC");
    col_set_str(pinfo->cinfo, COL_INFO, "UERadioAccessCapabilityInformation");

    ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_nr_rrc);
    return dissect_UERadioAccessCapabilityInformation_PDU(tvb, pinfo, sub_tree, NULL);
}

static int
dissect_nr_rrc_measconfig_msg(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    proto_item* ti;
    proto_tree* sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NR RRC");
    col_set_str(pinfo->cinfo, COL_INFO, "MeasConfig");

    ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_nr_rrc);
    return dissect_nr_rrc_MeasConfig_PDU(tvb, pinfo, sub_tree, NULL);
}

static int
dissect_nr_rrc_measgapconfig_msg(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    proto_item* ti;
    proto_tree* sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NR RRC");
    col_set_str(pinfo->cinfo, COL_INFO, "MeasGapConfig");

    ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_nr_rrc);
    return dissect_nr_rrc_MeasGapConfig_PDU(tvb, pinfo, sub_tree, NULL);
}

static int
dissect_nr_rrc_handoverpreparationinformation_msg(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    proto_item* ti;
    proto_tree* sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NR RRC");
    col_set_str(pinfo->cinfo, COL_INFO, "HandoverPreparationInformation");

    ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_nr_rrc);
    return dissect_nr_rrc_HandoverPreparationInformation_PDU(tvb, pinfo, sub_tree, NULL);
}



static int
dissect_nr_rrc_rrcreconfiguration_msg(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    proto_item* ti;
    proto_tree* sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NR RRC");
    col_set_str(pinfo->cinfo, COL_INFO, "RRCReconfiguration");

    ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_nr_rrc);
    return dissect_nr_rrc_RRCReconfiguration_PDU(tvb, pinfo, sub_tree, NULL);
}


static int
dissect_nr_rrc_ue_capabilityrat_containerlist_msg(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    proto_item* ti;
    proto_tree* sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NR RRC");
    col_set_str(pinfo->cinfo, COL_INFO, "UE-CapabilityRAT-ContainerList");

    ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_nr_rrc);
    return dissect_nr_rrc_UE_CapabilityRAT_ContainerList_PDU(tvb, pinfo, sub_tree, NULL);
}

static int
dissect_nr_rrc_handovercommand_msg(tvbuff_t* tvb _U_, packet_info* pinfo _U_, proto_tree* tree _U_, void* data _U_)
{
    proto_item* ti;
    proto_tree* sub_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NR RRC");
    col_set_str(pinfo->cinfo, COL_INFO, "HandoverCommand");

    ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(ti, ett_nr_rrc);
    return dissect_nr_rrc_HandoverCommand_PDU(tvb, pinfo, sub_tree, NULL);
}


#include "packet-nr-rrc-fn.c"

int
dissect_nr_rrc_nr_RLF_Report_r16_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  proto_item *prot_ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
  proto_item_set_hidden(prot_ti);
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_nr_rrc_T_nr_RLF_Report_r16(tvb, offset, &asn1_ctx, tree, hf_nr_rrc_BCCH_DL_SCH_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}

int
dissect_nr_rrc_subCarrierSpacingCommon_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  proto_item *prot_ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
  proto_item_set_hidden(prot_ti);
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_nr_rrc_T_subCarrierSpacingCommon(tvb, offset, &asn1_ctx, tree, hf_nr_rrc_BCCH_DL_SCH_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}

int
dissect_nr_rrc_rach_ConfigCommonIAB_r16_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  proto_item *prot_ti = proto_tree_add_item(tree, proto_nr_rrc, tvb, 0, -1, ENC_NA);
  proto_item_set_hidden(prot_ti);
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_nr_rrc_T_rach_ConfigCommonIAB_r16(tvb, offset, &asn1_ctx, tree, hf_nr_rrc_BCCH_DL_SCH_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}

void
proto_register_nr_rrc(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-nr-rrc-hfarr.c"

    { &hf_nr_rrc_serialNumber_gs,
      { "Geographical Scope", "nr-rrc.serialNumber.gs",
        FT_UINT16, BASE_DEC, VALS(nr_rrc_serialNumber_gs_vals), 0xc000,
        NULL, HFILL }},
    { &hf_nr_rrc_serialNumber_msg_code,
      { "Message Code", "nr-rrc.serialNumber.msg_code",
        FT_UINT16, BASE_DEC, NULL, 0x3ff0,
        NULL, HFILL }},
    { &hf_nr_rrc_serialNumber_upd_nb,
      { "Update Number", "nr-rrc.serialNumber.upd_nb",
        FT_UINT16, BASE_DEC, NULL, 0x000f,
        NULL, HFILL }},
    { &hf_nr_rrc_warningType_value,
      { "Warning Type Value", "nr-rrc.warningType.value",
        FT_UINT16, BASE_DEC, VALS(nr_rrc_warningType_vals), 0xfe00,
        NULL, HFILL }},
    { &hf_nr_rrc_warningType_emergency_user_alert,
      { "Emergency User Alert", "nr-rrc.warningType.emergency_user_alert",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0100,
        NULL, HFILL }},
    { &hf_nr_rrc_warningType_popup,
      { "Popup", "nr-rrc.warningType.popup",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0080,
        NULL, HFILL }},
    { &hf_nr_rrc_warningMessageSegment_nb_pages,
      { "Number of Pages", "nr-rrc.warningMessageSegment.nb_pages",
        FT_UINT8, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_warningMessageSegment_decoded_page,
      { "Decoded Page", "nr-rrc.warningMessageSegment.decoded_page",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib7_fragments,
      { "Fragments", "nr-rrc.warningMessageSegment.fragments",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib7_fragment,
      { "Fragment", "nr-rrc.warningMessageSegment.fragment",
         FT_FRAMENUM, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib7_fragment_overlap,
      { "Fragment Overlap", "nr-rrc.warningMessageSegment.fragment_overlap",
         FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib7_fragment_overlap_conflict,
      { "Fragment Overlap Conflict", "nr-rrc.warningMessageSegment.fragment_overlap_conflict",
         FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib7_fragment_multiple_tails,
      { "Fragment Multiple Tails", "nr-rrc.warningMessageSegment.fragment_multiple_tails",
         FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib7_fragment_too_long_fragment,
      { "Too Long Fragment", "nr-rrc.warningMessageSegment.fragment_too_long_fragment",
         FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib7_fragment_error,
      { "Fragment Error", "nr-rrc.warningMessageSegment.fragment_error",
         FT_FRAMENUM, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib7_fragment_count,
      { "Fragment Count", "nr-rrc.warningMessageSegment.fragment_count",
         FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib7_reassembled_in,
      { "Reassembled In", "nr-rrc.warningMessageSegment.reassembled_in",
         FT_FRAMENUM, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib7_reassembled_length,
      { "Reassembled Length", "nr-rrc.warningMessageSegment.reassembled_length",
         FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib7_reassembled_data,
      { "Reassembled Data", "nr-rrc.warningMessageSegment.reassembled_data",
         FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib8_fragments,
      { "Fragments", "nr-rrc.warningMessageSegment.fragments",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib8_fragment,
      { "Fragment", "nr-rrc.warningMessageSegment.fragment",
         FT_FRAMENUM, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib8_fragment_overlap,
      { "Fragment Overlap", "nr-rrc.warningMessageSegment.fragment_overlap",
         FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib8_fragment_overlap_conflict,
      { "Fragment Overlap Conflict", "nr-rrc.warningMessageSegment.fragment_overlap_conflict",
         FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib8_fragment_multiple_tails,
      { "Fragment Multiple Tails", "nr-rrc.warningMessageSegment.fragment_multiple_tails",
         FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib8_fragment_too_long_fragment,
      { "Too Long Fragment", "nr-rrc.warningMessageSegment.fragment_too_long_fragment",
         FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib8_fragment_error,
      { "Fragment Error", "nr-rrc.warningMessageSegment.fragment_error",
         FT_FRAMENUM, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib8_fragment_count,
      { "Fragment Count", "nr-rrc.warningMessageSegment.fragment_count",
         FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib8_reassembled_in,
      { "Reassembled In", "nr-rrc.warningMessageSegment.reassembled_in",
         FT_FRAMENUM, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib8_reassembled_length,
      { "Reassembled Length", "nr-rrc.warningMessageSegment.reassembled_length",
         FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_sib8_reassembled_data,
      { "Reassembled Data", "nr-rrc.warningMessageSegment.reassembled_data",
         FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nr_rrc_utc_time,
      { "UTC   time", "nr-rrc.utc_time",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_nr_rrc_local_time,
      { "Local time", "nr-rrc.local_time",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL, HFILL }},
    { &hf_nr_rrc_absolute_time,
      { "Absolute time", "nr-rrc.absolute_time",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
  };

  static gint *ett[] = {
    &ett_nr_rrc,
#include "packet-nr-rrc-ettarr.c"
    &ett_nr_rrc_DedicatedNAS_Message,
    &ett_nr_rrc_targetRAT_MessageContainer,
    &ett_nr_rrc_nas_Container,
    &ett_nr_rrc_serialNumber,
    &ett_nr_rrc_warningType,
    &ett_nr_rrc_dataCodingScheme,
    &ett_nr_rrc_sib7_fragment,
    &ett_nr_rrc_sib7_fragments,
    &ett_nr_rrc_sib8_fragment,
    &ett_nr_rrc_sib8_fragments,
    &ett_nr_rrc_warningMessageSegment,
    &ett_nr_rrc_timeInfo,
    &ett_nr_rrc_capabilityRequestFilter,
    &ett_nr_rrc_sourceSCG_EUTRA_Config,
    &ett_nr_rrc_scg_CellGroupConfigEUTRA,
    &ett_nr_rrc_candidateCellInfoListSN_EUTRA,
    &ett_nr_rrc_candidateCellInfoListMN_EUTRA,
    &ett_nr_rrc_sourceConfigSCG_EUTRA,
    &ett_nr_rrc_eutra_SCG,
    &ett_nr_rrc_nr_SCG_Response,
    &ett_nr_rrc_eutra_SCG_Response,
    &ett_nr_rrc_measResultSCG_FailureMRDC,
    &ett_nr_rrc_ul_DCCH_MessageNR,
    &ett_nr_rrc_ul_DCCH_MessageEUTRA,
    &ett_rr_rrc_nas_SecurityParamFromNR,
    &ett_nr_rrc_sidelinkUEInformationNR,
    &ett_nr_rrc_sidelinkUEInformationEUTRA,
    &ett_nr_rrc_ueAssistanceInformationEUTRA,
    &ett_nr_rrc_dl_DCCH_MessageNR,
    &ett_nr_rrc_dl_DCCH_MessageEUTRA,
    &ett_nr_rrc_sl_ConfigDedicatedEUTRA,
    &ett_nr_rrc_sl_CapabilityInformationSidelink,
    &ett_nr_rrc_measResult_RLF_Report_EUTRA,
    &ett_nr_rrc_measResult_RLF_Report_EUTRA_v1690,
    &ett_nr_rrc_locationTimestamp_r16,
    &ett_nr_rrc_locationCoordinate_r16,
    &ett_nr_rrc_locationError_r16,
    &ett_nr_rrc_locationSource_r16,
    &ett_nr_rrc_velocityEstimate_r16,
    &ett_nr_rrc_sensor_MeasurementInformation_r16,
    &ett_nr_rrc_sensor_MotionInformation_r16,
    &ett_nr_rrc_bandParametersSidelinkEUTRA1_r16,
    &ett_nr_rrc_bandParametersSidelinkEUTRA2_r16,
    &ett_nr_rrc_sl_ParametersEUTRA1_r16,
    &ett_nr_rrc_sl_ParametersEUTRA2_r16,
    &ett_nr_rrc_sl_ParametersEUTRA3_r16,
    &ett_nr_rrc_absTimeInfo,
    &ett_nr_rrc_assistanceDataSIB_Element_r16,
    &ett_nr_sl_V2X_ConfigCommon_r16,
    &ett_nr_tdd_Config_r16,
    &ett_nr_coarseLocationInfo_r17,
    &ett_nr_sl_MeasResultsCandRelay_r17,
    &ett_nr_sl_MeasResultServingRelay_r17,
    &ett_nr_ReferenceLocation_r17
  };

  static ei_register_info ei[] = {
     { &ei_nr_rrc_number_pages_le15, { "nr-rrc.number_pages_le15", PI_MALFORMED, PI_ERROR, "Number of pages should be <=15", EXPFILL }},
  };

  expert_module_t* expert_nr_rrc;
  module_t *nr_rrc_module;

  /* Register protocol */
  proto_nr_rrc = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_nr_rrc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_nr_rrc = expert_register_protocol(proto_nr_rrc);
  expert_register_field_array(expert_nr_rrc, ei, array_length(ei));

  /* Register the dissectors defined in nr-rrc.cnf */
  register_dissector("nr-rrc.cg_configinfo", dissect_nr_rrc_cg_configinfo_msg, proto_nr_rrc);
  register_dissector("nr-rrc.radiobearerconfig", dissect_nr_rrc_radiobearerconfig_msg, proto_nr_rrc);
  register_dissector("nr-rrc.rrc_reconf_msg", dissect_nr_rrc_rrcreconfiguration_msg, proto_nr_rrc);
  register_dissector("nr-rrc.ue_capabilityrat_containerlist", dissect_nr_rrc_ue_capabilityrat_containerlist_msg, proto_nr_rrc);
  register_dissector("nr-rrc.ue_mrdc_cap_msg", dissect_nr_rrc_ue_mrdc_capability_msg, proto_nr_rrc);
  register_dissector("nr-rrc.ue_nr_cap_msg", dissect_nr_rrc_ue_nr_capability_msg, proto_nr_rrc);
  register_dissector("nr-rrc.ul.dcch_msg_msg", dissect_nr_rrc_ul_dcch_message_msg, proto_nr_rrc);
  register_dissector("nr-rrc.dl.dcch_msg_msg", dissect_nr_rrc_dl_dcch_message_msg, proto_nr_rrc);
  register_dissector("nr-rrc.ul.ccch_msg_msg", dissect_nr_rrc_ul_ccch_message_msg, proto_nr_rrc);
  register_dissector("nr-rrc.dl.ccch_msg_msg", dissect_nr_rrc_dl_ccch_message_msg, proto_nr_rrc);
  register_dissector("nr-rrc.cellgroupconfig_msg", dissect_nr_rrc_cellgroupconfig_msg, proto_nr_rrc);
  register_dissector("nr-rrc.ue_radio_access_cap_info_msg", dissect_ueradioaccesscapabilityinformation_msg, proto_nr_rrc);
  register_dissector("nr-rrc.measconfig_msg", dissect_nr_rrc_measconfig_msg, proto_nr_rrc);
  register_dissector("nr-rrc.measgapconfig_msg", dissect_nr_rrc_measgapconfig_msg, proto_nr_rrc);
  register_dissector("nr-rrc.handoverpreparationinformation_msg", dissect_nr_rrc_handoverpreparationinformation_msg, proto_nr_rrc);
  register_dissector("nr-rrc.handovercommand_msg", dissect_nr_rrc_handovercommand_msg, proto_nr_rrc);

#include "packet-nr-rrc-dis-reg.c"

  nr_rrc_etws_cmas_dcs_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(),
                                                     g_direct_hash, g_direct_equal);

  reassembly_table_register(&nr_rrc_sib7_reassembly_table,
                            &addresses_reassembly_table_functions);
  reassembly_table_register(&nr_rrc_sib8_reassembly_table,
                            &addresses_reassembly_table_functions);

  /* Register configuration preferences */
  nr_rrc_module = prefs_register_protocol(proto_nr_rrc, NULL);
  prefs_register_bool_preference(nr_rrc_module, "nas_in_root_tree",
                                 "Show NAS PDU in root packet details",
                                 "Whether the NAS PDU should be shown in the root packet details tree",
                                 &nr_rrc_nas_in_root_tree);
}

void
proto_reg_handoff_nr_rrc(void)
{
  nas_5gs_handle = find_dissector("nas-5gs");
  lte_rrc_conn_reconf_handle = find_dissector("lte-rrc.rrc_conn_reconf");
  lte_rrc_conn_reconf_compl_handle = find_dissector("lte-rrc.rrc_conn_reconf_compl");
  lte_rrc_ul_dcch_handle = find_dissector("lte-rrc.ul.dcch");
  lte_rrc_dl_dcch_handle = find_dissector("lte-rrc.dl.dcch");
}
