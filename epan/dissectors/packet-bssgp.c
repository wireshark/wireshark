/* packet-bssgp.c
 * Routines for Base Station Subsystem GPRS Protocol dissection
 * Copyright 2000, Susanne Edlund <susanne.edlund@ericsson.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* 3GPP TS 48.018 V 6.5.0 (2004-07) Release 6 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <prefs.h>

/*#define BSSGP_DEBUG*/
#define BSSGP_LITTLE_ENDIAN FALSE
#define BSSGP_TRANSLATION_MAX_LEN 50
#define BSSGP_MASK_LEFT_OCTET_HALF 0xf0
#define BSSGP_MASK_RIGHT_OCTET_HALF 0x0f
#define BSSGP_MOBILE_IDENTITY_TYPE_IMSI 1
#define BSSGP_MOBILE_IDENTITY_TYPE_IMEI 2
#define BSSGP_MOBILE_IDENTITY_TYPE_IMEISV 3
#define BSSGP_MOBILE_IDENTITY_TYPE_TMSI_PTMSI 4
#define BSSGP_MOBILE_IDENTITY_TYPE_NO_IDENTITY 0
#define BSSGP_SEP ", "
#define BSSGP_NOT_DECODED "< Not decoded yet >"
#define BSSGP_UNKNOWN (-1)
static int bssgp_decode_nri = 0;
static guint bssgp_nri_length = 4;

static dissector_handle_t bssgp_handle;
static dissector_handle_t llc_handle;
static dissector_handle_t rrlp_handle;
static dissector_handle_t data_handle;

module_t *bssgp_module;
void proto_reg_handoff_bssgp(void);

/* Initialize the protocol and registered fields */
static int proto_bssgp = -1;
static int hf_bssgp_pdu_type = -1;
static int hf_bssgp_ie_type = -1;
static int hf_bssgp_mcc = -1;
static int hf_bssgp_mnc = -1;
static int hf_bssgp_lac = -1;
static int hf_bssgp_rac = -1;
static int hf_bssgp_ci = -1;
static int hf_bssgp_nri = -1;
static int hf_bssgp_imsi = -1;
static int hf_bssgp_imei = -1;
static int hf_bssgp_imeisv = -1;
static int hf_bssgp_tmsi_ptmsi = -1;
static int hf_bssgp_bvci = -1;
static int hf_bssgp_nsei = -1;
static int hf_bssgp_tlli = -1;

/* Initialize the subtree pointers */
static gint ett_bssgp = -1;
static gint ett_bssgp_qos_profile = -1; 
static gint ett_bssgp_gprs_timer = -1;
static gint ett_bssgp_cell_identifier = -1;
static gint ett_bssgp_channel_needed = -1;
static gint ett_bssgp_drx_parameters = -1;
static gint ett_bssgp_mobile_identity = -1;
static gint ett_bssgp_priority = -1;
static gint ett_bssgp_lsa_identifier_list = -1;
static gint ett_bssgp_lsa_information = -1;
static gint ett_bssgp_lsa_information_lsa_identification_and_attributes = -1;
static gint ett_bssgp_abqp = -1;
static gint ett_bssgp_lcs_qos = -1;
static gint ett_bssgp_lcs_client_type = -1;
static gint ett_bssgp_requested_gps_assistance_data = -1;
static gint ett_bssgp_requested_gps_assistance_data_satellite = -1;
static gint ett_bssgp_location_type = -1;
static gint ett_bssgp_positioning_data_positioning_method = -1;
static gint ett_bssgp_deciphering_keys = -1;
static gint ett_bssgp_lcs_cause = -1;
static gint ett_bssgp_lcs_capability = -1;
static gint ett_bssgp_rrlp_flags = -1;
static gint ett_bssgp_ran_information_indications = -1;
static gint ett_bssgp_mcc = -1;
static gint ett_bssgp_mnc = -1;
static gint ett_bssgp_routeing_area = -1;
static gint ett_bssgp_location_area = -1;
static gint ett_bssgp_rai_ci = -1;
static gint ett_bssgp_ran_information_request_container_unit = -1;
static gint ett_bssgp_ran_information_container_unit = -1;
static gint ett_bssgp_pfc_flow_control_parameters = -1;
static gint ett_bssgp_pfc_flow_control_parameters_pfc = -1;
static gint ett_bssgp_global_cn_id = -1;
static gint ett_bssgp_ms_radio_access_capability = -1;
static gint ett_bssgp_msrac_value_part = -1;
static gint ett_bssgp_msrac_additional_access_technologies = -1;
static gint ett_bssgp_msrac_access_capabilities = -1;
static gint ett_bssgp_msrac_a5_bits = -1;
static gint ett_bssgp_msrac_multislot_capability = -1;
static gint ett_bssgp_feature_bitmap = -1;
static gint ett_bssgp_positioning_data = -1;
static gint ett_bssgp_tlli = -1;
static gint ett_bssgp_tmsi_ptmsi = -1;

/* PDU type coding, v6.5.0, table 11.3.26, p 80 */
#define BSSGP_PDU_DL_UNITDATA                  0x00
#define BSSGP_PDU_UL_UNITDATA                  0x01
#define BSSGP_PDU_RA_CAPABILITY                0x02
#define BSSGP_PDU_PTM_UNITDATA                 0x03
#define BSSGP_PDU_PAGING_PS                    0x06
#define BSSGP_PDU_PAGING_CS                    0x07
#define BSSGP_PDU_RA_CAPABILITY_UPDATE         0x08
#define BSSGP_PDU_RA_CAPABILITY_UPDATE_ACK     0x09
#define BSSGP_PDU_RADIO_STATUS                 0x0a
#define BSSGP_PDU_SUSPEND                      0x0b
#define BSSGP_PDU_SUSPEND_ACK                  0x0c
#define BSSGP_PDU_SUSPEND_NACK                 0x0d
#define BSSGP_PDU_RESUME                       0x0e
#define BSSGP_PDU_RESUME_ACK                   0x0f
#define BSSGP_PDU_RESUME_NACK                  0x10
#define BSSGP_PDU_BVC_BLOCK                    0x20
#define BSSGP_PDU_BVC_BLOCK_ACK                0x21
#define BSSGP_PDU_BVC_RESET                    0x22
#define BSSGP_PDU_BVC_RESET_ACK                0x23
#define BSSGP_PDU_BVC_UNBLOCK                  0x24
#define BSSGP_PDU_BVC_UNBLOCK_ACK              0x25
#define BSSGP_PDU_FLOW_CONTROL_BVC             0x26
#define BSSGP_PDU_FLOW_CONTROL_BVC_ACK         0x27
#define BSSGP_PDU_FLOW_CONTROL_MS              0x28
#define BSSGP_PDU_FLOW_CONTROL_MS_ACK          0x29
#define BSSGP_PDU_FLUSH_LL                     0x2a
#define BSSGP_PDU_FLUSH_LL_ACK                 0x2b
#define BSSGP_PDU_LLC_DISCARDED                0x2c
#define BSSGP_PDU_FLOW_CONTROL_PFC             0x2d
#define BSSGP_PDU_FLOW_CONTROL_PFC_ACK         0x2e
#define BSSGP_PDU_SGSN_INVOKE_TRACE            0x40
#define BSSGP_PDU_STATUS                       0x41
#define BSSGP_PDU_DOWNLOAD_BSS_PFC             0x50
#define BSSGP_PDU_CREATE_BSS_PFC               0x51
#define BSSGP_PDU_CREATE_BSS_PFC_ACK           0x52
#define BSSGP_PDU_CREATE_BSS_PFC_NACK          0x53
#define BSSGP_PDU_MODIFY_BSS_PFC               0x54
#define BSSGP_PDU_MODIFY_BSS_PFC_ACK           0x55
#define BSSGP_PDU_DELETE_BSS_PFC               0x56
#define BSSGP_PDU_DELETE_BSS_PFC_ACK           0x57
#define BSSGP_PDU_DELETE_BSS_PFC_REQ           0x58
#define BSSGP_PDU_PERFORM_LOCATION_REQUEST     0x60
#define BSSGP_PDU_PERFORM_LOCATION_RESPONSE    0x61
#define BSSGP_PDU_PERFORM_LOCATION_ABORT       0x62
#define BSSGP_PDU_POSITION_COMMAND             0x63
#define BSSGP_PDU_POSITION_RESPONSE            0x64
#define BSSGP_PDU_RAN_INFORMATION              0x70
#define BSSGP_PDU_RAN_INFORMATION_REQUEST      0x71
#define BSSGP_PDU_RAN_INFORMATION_ACK          0x72
#define BSSGP_PDU_RAN_INFORMATION_ERROR        0x73

static const value_string tab_bssgp_pdu_types[] = {
  { BSSGP_PDU_DL_UNITDATA,                  "DL-UNITDATA" },
  { BSSGP_PDU_UL_UNITDATA,                  "UL-UNITDATA" },
  { BSSGP_PDU_RA_CAPABILITY,                "RA-CAPABILITY" },
  { BSSGP_PDU_PTM_UNITDATA,                 "PTM-UNITDATA" },
  { BSSGP_PDU_PAGING_PS,                    "PAGING-PS" },
  { BSSGP_PDU_PAGING_CS,                    "PAGING-CS" },
  { BSSGP_PDU_RA_CAPABILITY_UPDATE,         "RA-CAPABILITY-UPDATE" },
  { BSSGP_PDU_RA_CAPABILITY_UPDATE_ACK,     "RA-CAPABILITY-UPDATE-ACK" },
  { BSSGP_PDU_RADIO_STATUS,                 "RADIO-STATUS" },
  { BSSGP_PDU_SUSPEND,                      "SUSPEND" },
  { BSSGP_PDU_SUSPEND_ACK,                  "SUSPEND-ACK" },
  { BSSGP_PDU_SUSPEND_NACK,                 "SUSPEND-NACK" },
  { BSSGP_PDU_RESUME,                       "RESUME" },
  { BSSGP_PDU_RESUME_ACK,                   "RESUME-ACK" },
  { BSSGP_PDU_RESUME_NACK,                  "RESUME-NACK" },
  { BSSGP_PDU_BVC_BLOCK,                    "BVC-BLOCK" },
  { BSSGP_PDU_BVC_BLOCK_ACK,                "BVC-BLOCK-ACK" },
  { BSSGP_PDU_BVC_RESET,                    "BVC-RESET" },
  { BSSGP_PDU_BVC_RESET_ACK,                "BVC-RESET-ACK" },
  { BSSGP_PDU_BVC_UNBLOCK,                  "UNBLOCK" },
  { BSSGP_PDU_BVC_UNBLOCK_ACK,              "UNBLOCK-ACK" },
  { BSSGP_PDU_FLOW_CONTROL_BVC,             "FLOW-CONTROL-BVC" },
  { BSSGP_PDU_FLOW_CONTROL_BVC_ACK,         "FLOW-CONTROL-BVC-ACK" },
  { BSSGP_PDU_FLOW_CONTROL_MS,              "FLOW-CONTROL-MS" },
  { BSSGP_PDU_FLOW_CONTROL_MS_ACK,          "FLOW-CONTROL-MS-ACK" },
  { BSSGP_PDU_FLUSH_LL,                     "FLUSH-LL" },
  { BSSGP_PDU_FLUSH_LL_ACK,                 "FLUSH_LL_ACK" },
  { BSSGP_PDU_LLC_DISCARDED,                "LLC-DISCARDED" },
  { BSSGP_PDU_FLOW_CONTROL_PFC,             "FLOW-CONTROL-PFC" },
  { BSSGP_PDU_FLOW_CONTROL_PFC_ACK,         "FLOW-CONTROL-PFC-ACK" },
  { BSSGP_PDU_SGSN_INVOKE_TRACE,            "SGSN-INVOKE-TRACE" },
  { BSSGP_PDU_STATUS,                       "STATUS" },
  { BSSGP_PDU_DOWNLOAD_BSS_PFC,             "DOWNLOAD-BSS-PFC" },
  { BSSGP_PDU_CREATE_BSS_PFC,               "CREATE-BSS-PFC" },
  { BSSGP_PDU_CREATE_BSS_PFC_ACK,           "CREATE-BSS-PFC-ACK" },
  { BSSGP_PDU_CREATE_BSS_PFC_NACK,          "CREATE-BSS-PFC-NACK" },
  { BSSGP_PDU_MODIFY_BSS_PFC,               "MODIFY-BSS-PFC" },
  { BSSGP_PDU_MODIFY_BSS_PFC_ACK,           "MODIFY-BSS-PFC-ACK" },
  { BSSGP_PDU_DELETE_BSS_PFC,               "DELETE-BSS-PFC" },
  { BSSGP_PDU_DELETE_BSS_PFC_ACK,           "DELETE-BSS-PFC-ACK" },
  { BSSGP_PDU_DELETE_BSS_PFC_REQ,           "DELETE-BSS-PFC-REQ" },
  { BSSGP_PDU_PERFORM_LOCATION_REQUEST,     "PERFORM-LOCATION-REQUEST" },
  { BSSGP_PDU_PERFORM_LOCATION_RESPONSE,    "PERFORM-LOCATION-RESPONSE" },
  { BSSGP_PDU_PERFORM_LOCATION_ABORT,       "PERFORM-LOCATION-ABORT" },
  { BSSGP_PDU_POSITION_COMMAND,             "POSITION-COMMAND" },
  { BSSGP_PDU_POSITION_RESPONSE,            "POSITION-RESPONSE" },
  { BSSGP_PDU_RAN_INFORMATION,              "RAN-INFORMATION" },
  { BSSGP_PDU_RAN_INFORMATION_REQUEST,      "RAN-INFORMATION-REQUEST" },
  { BSSGP_PDU_RAN_INFORMATION_ACK,          "RAN-INFORMATION-ACK" },
  { BSSGP_PDU_RAN_INFORMATION_ERROR,        "RAN-INFORMATION-ERROR" },
  { 0,                                NULL },
};

/* Information element coding, v 6.5.0, table 11.3, p 72 */
#define BSSGP_IEI_ALIGNMENT_OCTETS                         0x00
#define BSSGP_IEI_BMAX_DEFAULT_MS                          0x01              
#define BSSGP_IEI_BSS_AREA_INDICATION                      0x02
#define BSSGP_IEI_BUCKET_LEAK_RATE                         0x03
#define BSSGP_IEI_BVCI                                     0x04
#define BSSGP_IEI_BVC_BUCKET_SIZE                          0x05
#define BSSGP_IEI_BVC_MEASUREMENT                          0x06
#define BSSGP_IEI_CAUSE                                    0x07
#define BSSGP_IEI_CELL_IDENTIFIER                          0x08
#define BSSGP_IEI_CHANNEL_NEEDED                           0x09
#define BSSGP_IEI_DRX_PARAMETERS                           0x0a
#define BSSGP_IEI_EMLPP_PRIORITY                           0x0b
#define BSSGP_IEI_FLUSH_ACTION                             0x0c
#define BSSGP_IEI_IMSI                                     0x0d
#define BSSGP_IEI_LLC_PDU                                  0x0e
#define BSSGP_IEI_LLC_FRAMES_DISCARDED                     0x0f
#define BSSGP_IEI_LOCATION_AREA                            0x10
#define BSSGP_IEI_MOBILE_ID                                0x11
#define BSSGP_IEI_MS_BUCKET_SIZE                           0x12
#define BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY               0x13
#define BSSGP_IEI_OMC_ID                                   0x14
#define BSSGP_IEI_PDU_IN_ERROR                             0x15
#define BSSGP_IEI_PDU_LIFETIME                             0x16
#define BSSGP_IEI_PRIORITY                                 0x17
#define BSSGP_IEI_QOS_PROFILE                              0x18
#define BSSGP_IEI_RADIO_CAUSE                              0x19
#define BSSGP_IEI_RA_CAP_UPD_CAUSE                         0x1a
#define BSSGP_IEI_ROUTEING_AREA                            0x1b
#define BSSGP_IEI_R_DEFAULT_MS                             0x1c
#define BSSGP_IEI_SUSPEND_REFERENCE_NUMBER                 0x1d
#define BSSGP_IEI_TAG                                      0x1e
#define BSSGP_IEI_TLLI                                     0x1f
#define BSSGP_IEI_TMSI                                     0x20
#define BSSGP_IEI_TRACE_REFERENCE                          0x21
#define BSSGP_IEI_TRACE_TYPE                               0x22
#define BSSGP_IEI_TRANSACTION_ID                           0x23
#define BSSGP_IEI_TRIGGER_ID                               0x24
#define BSSGP_IEI_NUMBER_OF_OCTETS_AFFECTED                0x25
#define BSSGP_IEI_LSA_IDENTIFIER_LIST                      0x26
#define BSSGP_IEI_LSA_INFORMATION                          0x27
#define BSSGP_IEI_PFI                                      0x28
#define BSSGP_IEI_GPRS_TIMER                               0x29
#define BSSGP_IEI_ABQP                                     0x3a
#define BSSGP_IEI_FEATURE_BITMAP                           0x3b
#define BSSGP_IEI_BUCKET_FULL_RATIO                        0x3c
#define BSSGP_IEI_SERVICE_UTRAN_CCO                        0x3d
#define BSSGP_IEI_NSEI                                     0x3e
#define BSSGP_IEI_RRLP_APDU                                0x3f
#define BSSGP_IEI_LCS_QOS                                  0x40
#define BSSGP_IEI_LCS_CLIENT_TYPE                          0x41
#define BSSGP_IEI_REQUESTED_GPS_ASSISTANCE_DATA            0x42
#define BSSGP_IEI_LOCATION_TYPE                            0x43
#define BSSGP_IEI_LOCATION_ESTIMATE                        0x44
#define BSSGP_IEI_POSITIONING_DATA                         0x45
#define BSSGP_IEI_DECIPHERING_KEYS                         0x46
#define BSSGP_IEI_LCS_PRIORITY                             0x47
#define BSSGP_IEI_LCS_CAUSE                                0x48
#define BSSGP_IEI_LCS_CAPABILITY                           0x49
#define BSSGP_IEI_RRLP_FLAGS                               0x4a
#define BSSGP_IEI_RIM_APPLICATION_IDENTITY                 0x4b
#define BSSGP_IEI_RIM_SEQUENCE_NUMBER                      0x4c
#define BSSGP_IEI_RAN_INFORMATION_REQUEST_CONTAINER_UNIT   0x4d
#define BSSGP_IEI_RAN_INFORMATION_CONTAINER_UNIT           0x4e
#define BSSGP_IEI_RAN_INFORMATION_INDICATIONS              0x4f
#define BSSGP_IEI_NUMBER_OF_CONTAINER_UNITS                0x50
#define BSSGP_IEI_PFC_FLOW_CONTROL_PARAMETERS              0x52
#define BSSGP_IEI_GLOBAL_CN_ID                             0x53

static const value_string tab_bssgp_ie_types[] = {
  { BSSGP_IEI_ALIGNMENT_OCTETS,            "Alignment Octets" },
  { BSSGP_IEI_BMAX_DEFAULT_MS,             "Bmax Default MS" },
  { BSSGP_IEI_BSS_AREA_INDICATION,         "BSS Area Indication" },
  { BSSGP_IEI_BUCKET_LEAK_RATE,            "Bucket Leak Rate" },
  { BSSGP_IEI_BVCI,                        "BVCI" },
  { BSSGP_IEI_BVC_BUCKET_SIZE,             "BVC Bucket Size" },
  { BSSGP_IEI_BVC_MEASUREMENT,             "BVC Measurement" },
  { BSSGP_IEI_CAUSE,                       "Cause" },
  { BSSGP_IEI_CELL_IDENTIFIER,             "Cell Identifier" },
  { BSSGP_IEI_CHANNEL_NEEDED,              "Channel Needed" },
  { BSSGP_IEI_DRX_PARAMETERS,              "DRX Parameters" },
  { BSSGP_IEI_EMLPP_PRIORITY,              "eMLPP Priority" },
  { BSSGP_IEI_FLUSH_ACTION,                "Flush Action" },
  { BSSGP_IEI_IMSI,                        "IMSI" },
  { BSSGP_IEI_LLC_PDU,                     "LLC PDU" },
  { BSSGP_IEI_LLC_FRAMES_DISCARDED,        "LLC Frames Discarded" },
  { BSSGP_IEI_LOCATION_AREA,               "Location Area" },
  { BSSGP_IEI_MOBILE_ID,                   "Mobile Id" },
  { BSSGP_IEI_MS_BUCKET_SIZE,              "MS Bucket Size" },
  { BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY,  "MS Radio Access Capability" },
  { BSSGP_IEI_OMC_ID,                      "OMC Id" },
  { BSSGP_IEI_PDU_IN_ERROR,                "PDU In Error" },
  { BSSGP_IEI_PDU_LIFETIME,                "PDU Lifetime" },
  { BSSGP_IEI_PRIORITY,                    "Priority" },
  { BSSGP_IEI_QOS_PROFILE,                 "QoS Profile" },
  { BSSGP_IEI_RADIO_CAUSE,                 "Radio Cause" },
  { BSSGP_IEI_RA_CAP_UPD_CAUSE,            "RA-Cap-UPD-Cause" },
  { BSSGP_IEI_ROUTEING_AREA,               "Routeing Area" },
  { BSSGP_IEI_R_DEFAULT_MS,                "R_default_MS" },
  { BSSGP_IEI_SUSPEND_REFERENCE_NUMBER,    "Suspend Reference Number" },
  { BSSGP_IEI_TAG,                         "Tag" },
  { BSSGP_IEI_TLLI,                        "TLLI" },
  { BSSGP_IEI_TMSI,                        "TMSI" },
  { BSSGP_IEI_TRACE_REFERENCE,             "Trace Reference" },
  { BSSGP_IEI_TRACE_TYPE,                  "Trace Type" },
  { BSSGP_IEI_TRANSACTION_ID,              "Transaction Id" },
  { BSSGP_IEI_TRIGGER_ID,                  "Trigger Id" },
  { BSSGP_IEI_NUMBER_OF_OCTETS_AFFECTED,   "Number of Octets Affected" },
  { BSSGP_IEI_LSA_IDENTIFIER_LIST,         "LSA Identifier List" },
  { BSSGP_IEI_LSA_INFORMATION,             "LSA Information" },
  { BSSGP_IEI_PFI,                         "Packet Flow Identiifer" },
  { BSSGP_IEI_GPRS_TIMER,                  "GPRS Timer" },
  { BSSGP_IEI_ABQP,                        "ABQP" },
  { BSSGP_IEI_FEATURE_BITMAP,              "Feature Bitmap" },
  { BSSGP_IEI_BUCKET_FULL_RATIO,           "Bucket Full Ratio" },
  { BSSGP_IEI_SERVICE_UTRAN_CCO,           "Service UTRAN CCO" },
  { BSSGP_IEI_NSEI,                        "NSEI" },
  { BSSGP_IEI_RRLP_APDU,                   "RRLP APDU" },
  { BSSGP_IEI_LCS_QOS,                     "LCS QoS" },
  { BSSGP_IEI_LCS_CLIENT_TYPE,             "LCS Client Type" },
  { BSSGP_IEI_REQUESTED_GPS_ASSISTANCE_DATA, "Requested GPS Assistance Data" },
  { BSSGP_IEI_LOCATION_TYPE,               "Location Type" },
  { BSSGP_IEI_LOCATION_ESTIMATE,           "Location Estimate" },
  { BSSGP_IEI_POSITIONING_DATA,            "Positioning Data" },
  { BSSGP_IEI_DECIPHERING_KEYS,            "Deciphering Keys" },
  { BSSGP_IEI_LCS_PRIORITY,                "LCS Priority" },
  { BSSGP_IEI_LCS_CAUSE,                   "LCS Cause" },
  { BSSGP_IEI_LCS_CAPABILITY,              "LCS Capability" },
  { BSSGP_IEI_RRLP_FLAGS,                  "RRLP Flags" },
  { BSSGP_IEI_RIM_APPLICATION_IDENTITY,    "RIM Application Identity" },
  { BSSGP_IEI_RIM_SEQUENCE_NUMBER,         "RIM Sequence Number" },
  { BSSGP_IEI_RAN_INFORMATION_REQUEST_CONTAINER_UNIT, "RAN INFORMATION REQUEST Container Unit" },
  { BSSGP_IEI_RAN_INFORMATION_CONTAINER_UNIT, "RAN INFORMATION Container Unit" },
  { BSSGP_IEI_RAN_INFORMATION_INDICATIONS,  "RAN INFORMATION Indications" },
  { BSSGP_IEI_NUMBER_OF_CONTAINER_UNITS,    "Number of Container Units" },
  { BSSGP_IEI_PFC_FLOW_CONTROL_PARAMETERS,  "PFC Flow Control Parameters" },
  { BSSGP_IEI_GLOBAL_CN_ID,                 "Global CN Id" }, 
  { 0,                                NULL },
};

/* Presence requirements of Information Elements
   48.016 v 5.3.0, chapter 8.1.1, p. 35 */
#define BSSGP_IE_PRESENCE_M 1   /* Mandatory */
#define BSSGP_IE_PRESENCE_O 2   /* Conditional */
#define BSSGP_IE_PRESENCE_C 3   /* Optional */

/* Format options */
#define BSSGP_IE_FORMAT_V 1
#define BSSGP_IE_FORMAT_TV 2
#define BSSGP_IE_FORMAT_TLV 3

typedef struct {
  guint8        iei;
  const char   *name;
  guint8        presence_req;
  int           format;
  gint16        value_length; /* in bytes (read from capture)*/
  gint16        total_length; /* as specified, or 0 if unspecified */
} bssgp_ie_t;

typedef struct {
  tvbuff_t     *tvb;
  guint32       offset;
  packet_info  *pinfo;
  proto_tree   *bssgp_tree;
  proto_tree   *parent_tree;
  gboolean      dl_data;
  gboolean      ul_data;
} build_info_t;

static guint8
get_masked_guint8(guint8 value, guint8 mask) {
  const guint8 MASK_BIT_1 = 0x01; 
  guint8 i = 0;
  
  while (!((mask >> i) & MASK_BIT_1)) {
    i++;
    if (i > 7) return 0; 
  }
  return (value & mask) >> i;
}

#if 0
static guint16
get_masked_guint16(guint16 value, guint16 mask) {
  const guint16 MASK_BIT_1 = 0x01; 
  guint8 i = 0;
  
  while (!((mask >> i) & MASK_BIT_1)) {
    i++;
    if (i > 15) return 0; 
  }
  return (value & mask) >> i;
}
#endif

static gint32
make_mask32(guint8 num_bits, guint8 shift_value) {
  const guint32 LEFT_MOST_1 = 0x80000000;
  int i;
  guint32 mask = LEFT_MOST_1;
  
  for (i = 0; i < (num_bits - 1); i++) {
    mask = (mask >> 1) | LEFT_MOST_1;
  }
  return mask >> shift_value;
}

static guint32
get_masked_guint32(guint32 value, guint32 mask) {
  const guint16 MASK_BIT_1 = 0x01; 
  guint8 i = 0;
  
  while (!((mask >> i) & MASK_BIT_1)) {
    i++;
    if (i > 31) return 0; 
  }
  return (value & mask) >> i;
}

static guint8
tvb_get_masked_guint8(tvbuff_t *tvb, int offset, guint8 mask) {
  guint8 value = tvb_get_guint8(tvb, offset);
  return get_masked_guint8(value, mask);
}

static char*
get_bit_field_label(guint16 value, guint16 value_mask, guint16 num_bits) {
#define MAX_NUM_BITS 16
  guint16 i, bit_mask;
  static char label[MAX_NUM_BITS + 1];

  DISSECTOR_ASSERT(num_bits <= MAX_NUM_BITS);
  for (i = 0; i < num_bits; i++) {
    bit_mask = 1 << i;
    if (value_mask & bit_mask) {
      label[num_bits - 1 - i] = (value & bit_mask) ? '1' : '0';
    }
    else {
      label[num_bits - 1 - i] = '.';
    }
  }
#undef MAX_NUM_BITS
  return label;
}

static char*
get_bit_field_label8(guint8 value, guint8 value_mask) {
  char *bits;
  static char formatted_label[10];
  bits = get_bit_field_label(value, value_mask, 8);
  g_snprintf(formatted_label, 10, "%c%c%c%c %c%c%c%c",
	     bits[0], bits[1], bits[2], bits[3],
	     bits[4], bits[5], bits[6], bits[7]);
  return formatted_label;  
}

static char*
get_bit_field_label16(guint16 value, guint16 value_mask) {
  char *bits;
  static char formatted_label[18];
  bits = get_bit_field_label(value, value_mask, 16);
  g_snprintf(formatted_label, 18, "%c%c%c%c%c%c%c%c %c%c%c%c%c%c%c%c",
	     bits[0], bits[1], bits[2], bits[3],
	     bits[4], bits[5], bits[6], bits[7],
	     bits[8], bits[9], bits[10], bits[11],
	     bits[12], bits[13], bits[14], bits[15]);
  return formatted_label;  
}

static proto_item *
proto_tree_add_bitfield8(proto_tree *tree, tvbuff_t *tvb, int offset, guint8 mask) {
  /* XXX: Use varargs */
  guint8 value = tvb_get_guint8(tvb, offset);
  char *label = get_bit_field_label8(value, mask);
  proto_item *pi = proto_tree_add_text(tree, tvb, offset, 1, "%s = ",
				       label);
  return pi;
}

#if 0
static proto_item *
proto_tree_add_bitfield16(proto_tree *tree, tvbuff_t *tvb, int offset, guint16 mask) {
  /* XXX: Use varargs */
  guint16 value = tvb_get_ntohs(tvb, offset);
  char *label = get_bit_field_label16(value, mask);
  proto_item *pi = proto_tree_add_text(tree, tvb, offset, 2, "%s = ",
				       label);
 return pi;
}
#endif

static guint8
get_byte_offset(guint64 bo) {
  return (guint8) bo % 8;
}

static guint32
get_start_octet(guint64 bo) {
  return (guint32) floor((gint64)bo / 8.0);
}

static guint32
get_end_octet(guint64 bo, guint32 bl) 
{
  return (guint32) ceil((gint64)(bo + bl) / 8.0);
}

static guint32
get_num_octets_spanned(guint64 bo, guint32 bl) 
{
  return get_end_octet(bo, bl) - get_start_octet(bo);
}

static gint16
make_mask(guint8 num_bits, guint8 shift_value) {
  guint16 mask;

  switch (num_bits) {
  case 0: mask = 0x0000; break;
  case 1: mask = 0x8000; break;
  case 2: mask = 0xc000; break;
  case 3: mask = 0xe000; break;
  case 4: mask = 0xf000; break;
  case 5: mask = 0xf800; break;
  case 6: mask = 0xfc00; break;
  case 7: mask = 0xfe00; break;
  case 8: mask = 0xff00; break;
  default: DISSECTOR_ASSERT_NOT_REACHED(); mask = 0; break;
  }
  return mask >> shift_value;
}

static guint8
tvb_get_bits8(tvbuff_t *tvb, guint64 bo, guint8 num_bits) {
  /* Returns 0-8 bits from tvb */
  guint8 shift_value;
  guint16 mask, data;
  
  shift_value = get_byte_offset(bo);
  mask = make_mask(num_bits, shift_value);
  if (( mask & 0xff ) == 0 ) data = tvb_get_guint8(tvb, get_start_octet(bo)) << 8;
  else data = tvb_get_ntohs(tvb, get_start_octet(bo));
  return (data & mask) >> (16 - shift_value - num_bits);
}

static proto_item *
bit_proto_tree_add_text(proto_tree *tree, tvbuff_t *tvb, 
			guint64 bo, guint8 bl, const char *value) {
  /* XXX: Use varargs */
  return proto_tree_add_text(tree, tvb, get_start_octet(bo),
			     get_num_octets_spanned(bo, bl), value);
}

static proto_item *
bit_proto_tree_add_bit_field8(proto_tree *tree, tvbuff_t *tvb,
			      guint64 bo, guint8 bl) {
  /* XXX: Use varargs */
  guint16 mask = make_mask(bl, get_byte_offset(bo));
  guint16 value;
  guint8 end_i;
  int i;
  proto_item *pi;
  char *label;
  if (( mask & 0xff ) == 0 ) value = tvb_get_guint8 ( tvb , get_start_octet(bo)) << 8;
  else value = tvb_get_ntohs(tvb, get_start_octet(bo));
  label = get_bit_field_label16(value, mask);

  DISSECTOR_ASSERT(bl < 9);
  
  if (get_num_octets_spanned(bo, bl) == 1) {
    end_i = 7;
  }
  else {
    end_i = 16;
  }
  pi = bit_proto_tree_add_text(tree, tvb, bo, bl, "");

  for (i = 0; i <=end_i; i++) {
    proto_item_append_text(pi, "%c", label[i]);
  }
  proto_item_append_text(pi, " = ");
  return pi;
}

static const char*
translate_abqp_reliability_class(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0: 
    if (bi->ul_data) {
      return "Subscribed reliability class";
    }
    else {
      return "Reserved";
    }
  case 1: 
    return "Unused (Unacknowledged GTP; Acknowledged LLc and RLC, Protected data)"; 
  case 2: 
    return "Unacknowledged GTP; Acknowledged LLc and RLC, Protected data"; 
  case 3: 
    return "Unacknowledged GTP and LLC; Acknowledged RLC, Protected data";
  case 4: 
    return "Unacknowledged GTP, LLC, and RLC, Protected data";
  case 5:
    return "Unacknowledged GTP, LLC, and RLC, Unprotedcted data";
  case 7: 
    return "Reserved";
  default:
    return "Unacknowledged GTP and LLC; Acknowledged RLC, Protected data"; 
  }
}
static const char*
translate_abqp_delay_class(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0: 
    if (bi->ul_data) {
      return "Subscribed delay class";
    }
    else {
      return "Reserved";
    }
  case 1: return "Delay class 1";
  case 2: return "Delay class 2";
  case 3: return "Delay class 3";
  case 4: return "Delay class 4 (best effort)";
  case 7: return "Reserved";
  default:
    return "Delay class 4 (best effort)";
  }
}
static const char*
translate_abqp_peak_throughput(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed peak throughput";
    }
    else {
      return "Reserved";
    }
  case 1: return "Up to 1 000 octets/s";
  case 2: return "Up to 2 000 octets/s";
  case 3: return "Up to 4 000 octets/s";
  case 4: return "Up to 8 000 octets/s";
  case 5: return "Up to 16 000 octets/s";
  case 6: return "Up to 32 000 octets/s";
  case 7: return "Up to 64 000 octets/s";
  case 8: return "Up to 128 000 octets/s";
  case 9: return "Up to 256 000 octets/s";
  case 15: return "Reserved";
  default:
    return "Up to 1 000 octets/s";
  }
}
static const char*
translate_abqp_precedence_class(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0: 
    if (bi->ul_data) {
      return "Subscribed precedence";
    }
    else {
      return "Reserved";
    }
  case 1: return "High priority";
  case 2: return "Normal priority";
  case 3: return "Low priority";
  case 7: return "Reserved";
  default:
    return "Normal priority";
  }
}
static const char*
translate_abqp_mean_throughput(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed mean throughput";
    }
    else {
      return "Reserved";
    }
  case 1: return "100 octets/h";
  case 2: return "200 octets/h";
  case 3: return "500 octets/h";
  case 4: return "1 000 octets/h";
  case 5: return "2 000 octets/h";
  case 6: return "5 000 octets/h";
  case 7: return "10 000 octets/h";
  case 8: return "20 000 octets/h";
  case 9: return "50 000 octets/h";
  case 0x0a: return "100 000 octets/h";
  case 0x0b: return "200 000 octets/h";
  case 0x0c: return "500 000 octets/h";
  case 0x0d: return "1 000 000 octets/h";
  case 0x0e: return "2 000 000 octets/h";
  case 0x0f: return "5 000 000 octets/h";
  case 0x10: return "10 000 000 octets/h";
  case 0x11: return "20 000 000 octets/h";
  case 0x12: return "50 000 000 octets/h";
  case 0x1e: return "Reserved";
  case 0x1f: return "Best effort";
  default:
    return "Best effort";
  }
}
static const char*
translate_abqp_traffic_class(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed traffic class";
    }
    else {
      return "Reserved";
    }
  case 1: return "Conversational class";
  case 2: return "Streaming class";
  case 3: return "Interactive class";
  case 4: return "Background class";
  case 7: return "Reserved";
  default:
    if (bi->ul_data) {
      /* The MS shall consider all other values as reserved */
      return "Reserved";
    }
    else {
      /* The network shall map all other values not explicitly defined onto one of the values defined in this version of the protocol. The network shall return a negotiated value which is explicitly defined in this version of the protocol */
      return "Error";
    }
  }
}
static const char*
translate_abqp_delivery_order(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0: 
    if (bi->ul_data) {
      return "Subscribed delivery order";
    }
    else {
      return "Reserved";
    }
  case 1: return "With delivery order ('yes')";
  case 2: return "Without delivery order ('no')";
  case 3: return "Reserved";
  default:
    return "Error in BSSGP dissector";
  }
}
static const char*
translate_abqp_delivery_of_erroneous_sdu(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed delivery of erroneous SDUs";
    }
    else {
      return "Reserved";
    }
  case 1: return "No detect ('-')";
  case 2: return "Erroneous SDUs are delivered ('yes')";
  case 3: return "Erroneous SDUs are not delivered ('no')";
  case 7: return "Reserved";
  default:
    if (bi->ul_data) {
      /* The MS shall consider all other values as reserved */
      return "Reserved";
    }
    else {
      /* The network shall map all other values not explicitly defined onto one of the values defined in this version of the protocol. The network shall return a negotiated value which is explicitly defined in this version of the protocol */
      return "Error";
    }
  }
}
static const char*
translate_abqp_max_sdu_size(guint8 value, build_info_t *bi) {
  static char result[BSSGP_TRANSLATION_MAX_LEN];

  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed maximum SDU size";
    }
    else {
      return "Reserved";
    }
  case 0xff:
    if (bi->ul_data) {
      return "Reserved";
    }
    else {
      return "Reserved";
    }
  case 0x97: return "1502 octets";
  case 0x98: return "1510 octets";
  case 0x99: return "1520 octets";
  }
  if ((value >= 1) && (value <= 0x96)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u octets", value * 10);
    return result;
  }
  if (bi->ul_data) {
    /* The MS shall consider all other values as reserved */
    return "Reserved";
  }
  else {
    /* The network shall map all other values not explicitly defined onto one of the values defined in this version of the protocol. The network shall return a negotiated value which is explicitly defined in this version of the protocol */
    return "Error";
  }
}  

static const char*
translate_abqp_max_bit_rate_for_ul(guint8 value, build_info_t *bi) {
  static char result[BSSGP_TRANSLATION_MAX_LEN];

  if (value == 0) {
    if (bi->ul_data) {
      return "Subscribed maximum bit rate for uplink";
    }
    else {
      return "Reserved";
    }
  }
  if ((value >= 1) && (value <= 0x3f)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u kbps", value);
    return result;
  }
  if ((value >= 0x40) && (value <= 0x7f)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u kbps", 64 + (value - 0x40) * 8);
    return result;
  }
  if ((value >= 0x80) && (value <= 0xfe)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u kbps", 576 + (value - 0x80) * 64);
    return result;
  }
  return "0 kbps";
}

static const char*
translate_abqp_max_bit_rate_for_dl(guint8 value, build_info_t *bi) {
  return translate_abqp_max_bit_rate_for_ul(value, bi);
}

static const char*
translate_abqp_residual_ber(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed residual BER";
    }
    else {
      return "Reserved";
    }
  case 1: return "5*10^-2";
  case 2: return "1*10^-2";
  case 3: return "5*10^-3";
  case 4: return "4*10^-3";
  case 5: return "1*10^-3";
  case 6: return "1*10^-4";
  case 7: return "1*10^-5";
  case 8: return "1*10^-6";
  case 9: return "6*10^-8";
  case 15: return "Reserved";
  }
  if (bi->ul_data) {
    /* The MS shall consider all other values as reserved */
    return "Reserved";
  }
  else {
    /* The network shall map all other values not explicitly defined onto one of the values defined in this version of the protocol. The network shall return a negotiated value which is explicitly defined in this version of the protocol */
    return "Error";
  }
}

static const char*
translate_abqp_sdu_error_ratio(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed SDU error ratio";
    }
    else {
      return "Reserved";
    }
  case 1: return "1*10^-2";
  case 2: return "7*10^-3";
  case 3: return "1*10^-3";
  case 4: return "1*10^-4";
  case 5: return "1*10^-5";
  case 6: return "1*10^-6";
  case 7: return "1*10^-1";
  case 15: return "Reserved";
  }
  if (bi->ul_data) {
    /* The MS shall consider all other values as reserved */
    return "Reserved";
  }
  else {
    /* The network shall map all other values not explicitly defined onto one of the values defined in this version of the protocol. The network shall return a negotiated value which is explicitly defined in this version of the protocol */
    return "";
  }
}

static const char*
translate_abqp_transfer_delay(guint8 value, build_info_t *bi) {
  static char result[BSSGP_TRANSLATION_MAX_LEN];

  if (value == 0) {
    if (bi->ul_data) {
      return "Subscribed transfer delay";
    }
    else {
      return "Reserved";
    }
  }
  if ((value >= 1) && (value <= 0x0f)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u ms", value * 10);
    return result;
  }
  if ((value >= 0x10) && (value <= 0x1f)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u ms", 200 + (value - 0x10) * 50);
    return result;
  }
  if ((value >= 0x20) && (value <= 0x3e)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u ms", 1000 + (value - 0x20) * 100);
    return result;
  }
  return "Reserved";
}

static const char*
translate_abqp_traffic_handling_priority(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed traffic handling_priority";
    }
    else {
      return "Reserved";
    }
  case 1: return "Priority level 1";
  case 2: return "Priority level 2";
  case 3: return "Priority level 3";
  default: return "";
  }
}

static const char*
translate_abqp_guaranteed_bit_rate_for_ul(guint8 value, build_info_t *bi) {
  return translate_abqp_max_bit_rate_for_ul(value, bi);
}
static const char*
translate_abqp_guaranteed_bit_rate_for_dl(guint8 value, build_info_t *bi) {
  return translate_abqp_max_bit_rate_for_ul(value, bi);
}

static const char*
translate_abqp_source_statistics_descriptor(guint8 value, build_info_t *bi) {
  if (bi->ul_data) {
    switch (value) {
    case 0: return "Unknown";
    case 1: return "Speech";
    default: return "Unknown";
    }
  }
  else {
    return "Spare";
  }
}

static const char*
translate_abqp_max_bit_rate_for_dl_extended(guint8 value, build_info_t *bi _U_) {
  static char result[BSSGP_TRANSLATION_MAX_LEN];

  if (value == 0) {
    return "Use the value indicated by the Maximum bit rate for downlink";
  }
  if ((value >= 1) || (value <= 0x4a)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u kbps", 8600 + value * 100);
    return result;
  }
  /* The network shall map all other values not explicitly defined onto one of the values defined in this version of the protocol. The network shall return a negotiated value which is explicitly defined in this version of the protocol */
  return "";
}

static const char*
translate_abqp_guaranteed_bit_rate_for_dl_extended(guint8 value, build_info_t *bi _U_) {
  static char result[BSSGP_TRANSLATION_MAX_LEN];

  if (value == 0) {
    return "Use the value indicated by the Guaranteed bit rate for downlink";
  }
  if ((value >= 1) || (value <= 0x4a)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u kbps", 8600 + value * 100);
    return result;
  }
  /* The network shall map all other values not explicitly defined onto one of the values defined in this version of the protocol. The network shall return a negotiated value which is explicitly defined in this version of the protocol */
  return "";
}

static const char*
translate_msrac_access_technology_type(guint8 value) {
  static const value_string tab_values[] = {
    { 0, "GSM P" },
    { 1, "GSM E" },
    { 2, "GSM R" },
    { 3, "GSM 1800" },
    { 4, "GSM 1900" },
    { 5, "GSM 450" },
    { 6, "GSM 480" },
    { 7, "GSM 850" },
    { 8, "GSM 700" },
    { 9, "GSM T 380" },
    { 10, "GSM T 410" },
    { 11, "GSM T 900" },
    { 15, "List of Additional Access Technologies present" },
    { 0, NULL },
    /* Otherwise "Unknown" */
  };
  return val_to_str(value, tab_values, "Unknown");
}

static const char*
translate_msrac_dtm_gprs_multislot_class(guint8 value) {
 static const value_string tab_values[] = {
    { 0, "Unused, interpreted as \"Multislot class 5 supported\"" },
    { 1, "Multislot class 5 supported" },
    { 2, "Multislot class 9 supported" },
    { 3, "Multislot class 11 supported" },
    { 0, NULL },
    /* No other combinations*/
  };
  return val_to_str(value, tab_values, "");
}

static const char*
translate_msrac_extended_dtm_gprs_multislot_class(guint8 value, guint8 dgmsc) {
  switch (dgmsc) {
  case 0: return "Unused, interpreted as Multislot class 5 supported";
  case 1: 
    switch (value) {
    case 0: return "Multislot class 5 supported";
    case 1: return "Multislot class 6 supported";
    case 2: 
    case 3: 
      return "Unused, interpreted as Multislot class 5 supported";
    }
  case 2: 
    switch (value) {
    case 0: return "Multislot class 9 supported";
    case 1: return "Multislot class 10 supported";
    case 2: 
    case 3: 
      return "Unused, interpreted as Multislot class 5 supported";
    }
  case 3: 
    switch (value) {
    case 0: return "Multislot class 11 supported";
    case 1:
    case 2:
    case 3: 
      return "Unused, interpreted as Multislot class 5 supported";
    }
  }
  DISSECTOR_ASSERT_NOT_REACHED();
  return "Error"; /* Dummy */
}

#if 0
static guint8
translate_msrac_high_multislot_capability(guint8 capability, guint8 class) {
  switch (capability) {
  case 0:
    switch (class) {
    case 8: 
      return 30;
    case 10:
    case 23:
    case 28: 
    case 29: 
      return 39;
    case 11:
    case 20:
    case 25:
      return 32;
    case 12:
    case 21:
    case 22:
    case 26:
    case 27:
      return 33;
    default: 
      return class;
    }
  case 1:    
    switch (class) {
    case 8: 
      return 35;
    case 10:
    case 19:
    case 24:
      return 36;
    case 11:
    case 23:
    case 28:
    case 29:
      return 45;
    case 12:
    case 21:
    case 22:
    case 26:
    case 27:
      return 38;
    default: 
      return class;
    }
  case 2:
    switch (class) {
    case 8:
      return 40;
    case 10:
    case 19:
    case 24:
      return 41;
    case 11:
    case 20:
    case 25:
      return 42;
    case 12:
    case 23:
    case 28:
    case 29:
      return 44;
    default:
      return class;
    }
  case 3:
    switch (class) {
    case 12:
    case 21:
    case 22:
    case 26:
    case 27:
      return 43;
    case 11:
    case 20:
    case 25:
      return 37;
    case 10:
    case 19:
    case 24:
      return 31;
    case 9:
    case 23:
    case 28:
    case 29:
      return 34;
    default:
      return class;
    }
  }
  DISSECTOR_ASSERT_NOT_REACHED();
  return 0;
}
#endif

static const char*
translate_channel_needed(guint8 value) {
  switch (value) {
  case 0: return "Any channel";
  case 1: return "SDCCH";
  case 2: return "TCH/F (Full rate)";
  case 3: return "TCH/H or TCH/F (Dual rate)";
  }
  DISSECTOR_ASSERT_NOT_REACHED();
  return NULL;
}

static proto_item* 
bssgp_proto_tree_add_ie(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  return proto_tree_add_uint_format(bi->bssgp_tree, hf_bssgp_ie_type, 
				  bi->tvb, ie_start_offset, ie->total_length, 
				  ie->iei, ie->name);
}

static void
bssgp_proto_handoff(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset, dissector_handle_t handle) {
  tvbuff_t *next_tvb;

  next_tvb = tvb_new_subset(bi->tvb, bi->offset, -1, -1);

  if (bi->bssgp_tree) {
    bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  }
  if (handle) {
    call_dissector(handle, next_tvb, bi->pinfo, bi->parent_tree);    
  }
  else if (data_handle) {
    call_dissector(data_handle, next_tvb, bi->pinfo, bi->parent_tree);
  }
}

static void 
decode_nri(proto_tree *tf, build_info_t *bi, guint32 tmsi_tlli) {
  const guint32 LOCAL_TLLI_MASK = 0xc0000000;
  const guint32 FOREIGN_TLLI_MASK = 0x80000000;
  guint16 nri;
  
  if (bssgp_decode_nri && (bssgp_nri_length != 0) && 
    (((tmsi_tlli & LOCAL_TLLI_MASK) == LOCAL_TLLI_MASK) ||
     ((tmsi_tlli & FOREIGN_TLLI_MASK) == FOREIGN_TLLI_MASK))) {
    nri = get_masked_guint32(tmsi_tlli, make_mask32( (guint8) bssgp_nri_length, 8));
    if (tf) {
      proto_tree_add_uint_hidden(tf, hf_bssgp_nri, bi->tvb, bi->offset, 4, 
      nri);     
    }
    if (check_col(bi->pinfo->cinfo, COL_INFO)) {
      col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, BSSGP_SEP, 
	  "NRI %u", nri);
	}
  }
}

static void
decode_mobile_identity(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
#define MAX_NUM_IMSI_DIGITS 15
  const guint8 MASK_ODD_EVEN_INDICATION = 0x08;
  const guint8 MASK_TYPE_OF_IDENTITY = 0x07;
  const guint8 ODD = 1;
  proto_item *ti = NULL, *pi;
  proto_tree *tf = NULL;
  guint8 data, odd_even, type, num_digits, i;
  int hf_id;
  guint32 tmsi;
  guint8 digits[MAX_NUM_IMSI_DIGITS];
  char digits_str[MAX_NUM_IMSI_DIGITS + 1];

  static const value_string tab_type_of_identity[] = {
    { BSSGP_MOBILE_IDENTITY_TYPE_IMSI, "IMSI" },
    { BSSGP_MOBILE_IDENTITY_TYPE_IMEI, "IMEI" },
    { BSSGP_MOBILE_IDENTITY_TYPE_IMEISV, "IMEISV" },
    { BSSGP_MOBILE_IDENTITY_TYPE_TMSI_PTMSI, "TMSI//P-TMSI" },
    { BSSGP_MOBILE_IDENTITY_TYPE_NO_IDENTITY, "No identity" },
    { 0, NULL },
    /* Otherwise "Reserved" */
  };

  digits_str[0] = '\0'; /* conceivably num_digits below could be zero */

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    tf = proto_item_add_subtree(ti, ett_bssgp_mobile_identity);
  }
  data = tvb_get_guint8(bi->tvb, bi->offset);
  odd_even = get_masked_guint8(data, MASK_ODD_EVEN_INDICATION);

  if (bi->bssgp_tree) {
    pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, 
				  MASK_ODD_EVEN_INDICATION);
    proto_item_append_text(pi, "Odd/Even Indication: %s number of identity digits%s",
			odd_even == ODD ? "Odd" : "Even",
			odd_even == ODD ? "" : " and also when the TMSI/P_TMSI is used");
  }
  type = get_masked_guint8(data, MASK_TYPE_OF_IDENTITY);

  if (bi->bssgp_tree) {
    pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, 
				  MASK_TYPE_OF_IDENTITY);
    proto_item_append_text(pi, "Type of Identity: %s",
			   val_to_str(type, tab_type_of_identity, 
				      "Reserved"));
  }
  bi->offset++;
  switch (type) {
  case BSSGP_MOBILE_IDENTITY_TYPE_IMSI:
  case BSSGP_MOBILE_IDENTITY_TYPE_IMEI:
  case BSSGP_MOBILE_IDENTITY_TYPE_IMEISV:
    num_digits = 1 + (ie->value_length - 1) * 2;
    if (odd_even != ODD ) num_digits--;
    if (num_digits > MAX_NUM_IMSI_DIGITS) THROW(ReportedBoundsError);

    i = 0;
    digits[i] = get_masked_guint8(data, BSSGP_MASK_LEFT_OCTET_HALF);

    i++;
    while (TRUE) {
      data = tvb_get_guint8(bi->tvb, bi->offset);

      digits[i] = get_masked_guint8(data, BSSGP_MASK_RIGHT_OCTET_HALF);
      i++;
      if (i >= num_digits) break;

      digits[i] = get_masked_guint8(data, BSSGP_MASK_LEFT_OCTET_HALF);
      i++;
      if (i >= num_digits) break;
      bi->offset++;
    }
    bi->offset++;
    
    if (bi->bssgp_tree) {
      proto_item_append_text(ti, ": ");
      for (i = 0; i < num_digits; i++) {
	proto_item_append_text(ti, "%u", digits[i]);
	g_snprintf(&digits_str[i], 2, "%u", digits[i]);
      }
      switch (type) {
      case BSSGP_MOBILE_IDENTITY_TYPE_IMSI:
        hf_id = hf_bssgp_imsi;
        break;
      case BSSGP_MOBILE_IDENTITY_TYPE_IMEI:
        hf_id = hf_bssgp_imei;
        break;
      case BSSGP_MOBILE_IDENTITY_TYPE_IMEISV:
        hf_id = hf_bssgp_imeisv;
        break;
      default:
        DISSECTOR_ASSERT_NOT_REACHED();
        hf_id = -1;
        break;
      }
	  if (tf)
		  proto_tree_add_string(tf, hf_id, bi->tvb, ie_start_offset + 2, ((num_digits/2)+1), digits_str);

    } 
    if (check_col(bi->pinfo->cinfo, COL_INFO)) {
      col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, BSSGP_SEP, "%s %s", 
			  val_to_str(type, tab_type_of_identity, 
				     "Mobile identity unknown"),
			  digits_str);
    }
    break;
  case BSSGP_MOBILE_IDENTITY_TYPE_TMSI_PTMSI:
    tmsi = tvb_get_ntohl(bi->tvb, bi->offset);
    if (check_col(bi->pinfo->cinfo, COL_INFO)) {
      col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, BSSGP_SEP, 
			  "TMSI/P-TMSI %0x04x", tmsi);
    }
    if (bi->bssgp_tree) {
      proto_tree_add_item(tf, hf_bssgp_tmsi_ptmsi, bi->tvb, bi->offset, 4, 
			  BSSGP_LITTLE_ENDIAN);
      proto_item_append_text(ti, ": %#04x", tmsi);
    }
    decode_nri(tf, bi, tmsi);
    bi->offset += 4;
    break;
  default:
    ;    
  }
#undef MAX_NUM_IMSI_DIGITS
}

static char*
decode_mcc_mnc(build_info_t *bi, proto_tree *parent_tree) {
#define RES_LEN 15
  const guint8 UNUSED_MNC3 = 0x0f;
  proto_item *pi_mcc, *pi_mnc;
  guint8 mcc1, mcc2, mcc3, mnc1, mnc2, mnc3, data;
  guint16 start_offset, mcc, mnc;
  static char mcc_mnc[RES_LEN];

  start_offset = bi->offset;

  pi_mcc = proto_tree_add_text(parent_tree, bi->tvb, bi->offset, 3, "MCC");
  pi_mnc = proto_tree_add_text(parent_tree, bi->tvb, bi->offset, 3, "MNC");

  data = tvb_get_guint8(bi->tvb, bi->offset);
  mcc2 = get_masked_guint8(data, BSSGP_MASK_LEFT_OCTET_HALF);
  mcc1 = get_masked_guint8(data, BSSGP_MASK_RIGHT_OCTET_HALF);
  bi->offset++;
  
  data = tvb_get_guint8(bi->tvb, bi->offset);
  mnc3 = get_masked_guint8(data, BSSGP_MASK_LEFT_OCTET_HALF);
  mcc3 = get_masked_guint8(data, BSSGP_MASK_RIGHT_OCTET_HALF);
  bi->offset++;

  data = tvb_get_guint8(bi->tvb, bi->offset);
  mnc2 = get_masked_guint8(data, BSSGP_MASK_LEFT_OCTET_HALF);
  mnc1 = get_masked_guint8(data, BSSGP_MASK_RIGHT_OCTET_HALF);
  bi->offset++;

  /* XXX: If mxci out of range the ms should transmit the values using full hexademical encoding? */

  /* XXX: Interpretation of mcci? */
  mcc = 100 * mcc1 + 10 * mcc2 + mcc3;

  /* XXX: Interpretation of mnci? */
  mnc = 10 * mnc1 + mnc2;
 
  if (mnc3 != UNUSED_MNC3) {
    mnc += 10 * mnc + mnc3;
  }

  proto_tree_add_uint_hidden(bi->bssgp_tree, hf_bssgp_mcc, 
			     bi->tvb, start_offset, 3, mcc);
  proto_tree_add_uint_hidden(bi->bssgp_tree, hf_bssgp_mnc, 
			     bi->tvb, start_offset, 3, mnc);

  proto_item_append_text(pi_mcc, ": %03u", mcc);

  if (mnc3 != UNUSED_MNC3) {
    /* Three digits mnc */
    proto_item_append_text(pi_mnc, ": %03u", mnc);
    g_snprintf(mcc_mnc, RES_LEN, "%u-%03u", mcc, mnc);
  }
  else {
    /* Two digits mnc */
    proto_item_append_text(pi_mnc, ": %02u", mnc);
    g_snprintf(mcc_mnc, RES_LEN, "%u-%02u", mcc, mnc);
  }
#undef RES_LEN
  return mcc_mnc;
}

static char*
decode_lai(build_info_t *bi, proto_tree *parent_tree) {
#define RES_LEN 15
  guint16 lac;
  char *mcc_mnc;
  static char lai[RES_LEN];
  
  mcc_mnc = decode_mcc_mnc(bi, parent_tree);

  lac = tvb_get_ntohs(bi->tvb, bi->offset);
  proto_tree_add_item(parent_tree, hf_bssgp_lac, 
		      bi->tvb, bi->offset, 2, BSSGP_LITTLE_ENDIAN);
  bi->offset += 2;

  g_snprintf(lai, RES_LEN, "%s-%u", mcc_mnc, lac);
#undef RES_LEN
  return lai;
}

static char*
decode_rai(build_info_t *bi, proto_tree *parent_tree) {
#define RES_LEN 20
  guint8 rac;
  static char rai[RES_LEN];
  char *lai = decode_lai(bi, parent_tree);  
 
  rac = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_item(parent_tree, hf_bssgp_rac, bi->tvb, bi->offset, 1, BSSGP_LITTLE_ENDIAN);
  bi->offset++;

  g_snprintf(rai, RES_LEN, "%s-%u", lai, rac);
#undef RES_LEN
  return rai;
}

static char*
decode_rai_ci(build_info_t *bi, proto_tree *parent_tree) {
#define RES_LEN 30
  char *rai;
  static char rai_ci[RES_LEN];
  guint16 ci;

  rai = decode_rai(bi, parent_tree);

  ci = tvb_get_ntohs(bi->tvb, bi->offset);
  proto_tree_add_item(parent_tree, hf_bssgp_ci, 
		      bi->tvb, bi->offset, 2, BSSGP_LITTLE_ENDIAN);
  bi->offset += 2;

  g_snprintf(rai_ci, RES_LEN, "RAI %s, CI %u", rai, ci);
#undef RES_LEN
  return rai_ci;
}

static void
bssgp_pi_append_queuing_delay(proto_item *pi, tvbuff_t *tvb, int offset) {
  const guint16 INFINITE_DELAY = 0xffff;
  guint16 value = tvb_get_ntohs(tvb, offset);
  if (value == INFINITE_DELAY) {
    proto_item_append_text(pi, ": Infinite delay (%#4x)", value);
  }
  else {
    proto_item_append_text(pi, ": %u centi-seconds delay", value);
  }
}

static void 
bssgp_pi_append_bucket_leak_rate(proto_item *pi, tvbuff_t *tvb, int offset) {
  guint16 value = tvb_get_ntohs(tvb, offset);
  proto_item_append_text(pi, ": %u bytes", value * 100);
}

static void 
bssgp_pi_append_bucket_size(proto_item *pi, tvbuff_t *tvb, int offset) {
  guint16 value = tvb_get_ntohs(tvb, offset);
  proto_item_append_text(pi, ": %u bytes", value * 100);
}

static void 
bssgp_pi_append_bucket_full_ratio(proto_item *pi, tvbuff_t *tvb, int offset) {
  guint8 value = tvb_get_guint8(tvb, offset);
  proto_item_append_text(pi, ": %.2f * Bmax ", value / 100.0);
}

static void
bssgp_pi_append_pfi(proto_item *pi, tvbuff_t *tvb, int offset) {
  const guint8 MASK_PFI = 0x7f;
  guint8 value;

  static const value_string tab_pfi[] = {
    { 0, "Best effort" },
    { 1, "Signaling" },
    { 2, "SMS" },
    { 3, "TOMB" },
    { 4, "Reserved" },
    { 5, "Reserved" },
    { 6, "Reserved" },
    { 7, "Reserved" },
    { 0, NULL },
    /* Otherwise "Dynamically assigned */
  };
  value = tvb_get_masked_guint8(tvb, offset, MASK_PFI);
  proto_item_append_text(pi, 
			 val_to_str(value, tab_pfi, "Dynamically assigned"));
}

static void 
decode_pfi(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    bssgp_pi_append_pfi(ti, bi->tvb, bi->offset);
  }
  bi->offset += ie->value_length;
}

static void
decode_queuing_delay(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    bssgp_pi_append_queuing_delay(ti, bi->tvb, bi->offset);
  }
  bi->offset += ie->value_length;
}

static void 
decode_bucket_size(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    bssgp_pi_append_bucket_size(ti, bi->tvb, bi->offset);
  }
  bi->offset += ie->value_length;
}

static void 
decode_bucket_leak_rate(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    bssgp_pi_append_bucket_leak_rate(ti, bi->tvb, bi->offset);
  }
  bi->offset += ie->value_length;
}

static void 
get_value_length(bssgp_ie_t *ie, build_info_t *bi) {
  /* length indicator in bit 8, 0 => two bytes, 1 => one byte */
  const guint8 MASK_LENGTH_INDICATOR = 0x80;
  const guint8 MASK_ONE_BYTE_LENGTH = 0x7f;
  guint8 length_len;
  guint16 length;
  
  length = tvb_get_guint8(bi->tvb, bi->offset);
  length_len = 1;
  
  if (length & MASK_LENGTH_INDICATOR) {
    length &= MASK_ONE_BYTE_LENGTH;
  }
  else {
    length_len++;
    length <<= 8;
    length |= tvb_get_guint8(bi->tvb, bi->offset);
  }
  ie->value_length = length;
  ie->total_length += length_len + length;
  bi->offset += length_len;
}

static void
decode_simple_ie(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset, 
		 const char *pre_str, const char *post_str, 
		 gboolean show_as_dec) {
  /* XXX: Allow mask? */
  proto_item *ti;
  guint32 value;

  switch (ie->value_length) {
  case 1: value = tvb_get_guint8(bi->tvb, bi->offset); break;
  case 2: value = tvb_get_ntohs(bi->tvb, bi->offset); break;
  case 3: value = tvb_get_ntoh24(bi->tvb, bi->offset); break;
  case 4: value = tvb_get_ntohl(bi->tvb, bi->offset); break;
  default: value = 0; break;
  }

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    
    proto_item_append_text(ti, ": ");
    
    if (pre_str) {
      proto_item_append_text(ti, "%s ", pre_str);
    }
    if (show_as_dec) {
      proto_item_append_text(ti, "%u", value);
    }
    else {
      switch (ie->value_length) {
      case 1: proto_item_append_text(ti, "%#1x", value); break;
      case 2: proto_item_append_text(ti, "%#2x", value); break;
      case 3: proto_item_append_text(ti, "%#3x", value); break;
      case 4: proto_item_append_text(ti, "%#4x", value); break;
      default: ;
      }
    }
    proto_item_append_text(ti, " %s", post_str);
  }
  bi->offset += ie->value_length;
}

static int 
check_correct_iei(bssgp_ie_t *ie, build_info_t *bi) {
  guint8 fetched_iei = tvb_get_guint8(bi->tvb, bi->offset);

#ifdef BSSGP_DEBUG
  if (fetched_iei != ie->iei) {
  proto_tree_add_text(bi->bssgp_tree, bi->tvb, bi->offset, 1, 
			"Tried IEI %s (%#02x), found IEI %s (%#02x)", 
			val_to_str(ie->iei, tab_bssgp_ie_types, "Unknown"), 
			ie->iei, 
			val_to_str(fetched_iei, tab_bssgp_ie_types, "Unknown"), 
			fetched_iei);
  }
#endif
  return (fetched_iei == ie->iei);
}

static void 
decode_iei_alignment_octets(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    proto_item_append_text(ti, " (%u bytes)", ie->value_length);
  }  
  bi->offset += ie->value_length;
}

static void 
decode_iei_bvci(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  guint16 bvci;

  bvci = tvb_get_ntohs(bi->tvb, bi->offset);

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    proto_item_append_text(ti, ": %u", bvci);
    proto_tree_add_item_hidden(bi->bssgp_tree, hf_bssgp_bvci, 
			       bi->tvb, bi->offset, ie->value_length, 
			       BSSGP_LITTLE_ENDIAN);
  }
  bi->offset += ie->value_length;

  if (check_col(bi->pinfo->cinfo, COL_INFO)) {
    col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, BSSGP_SEP, 
			"BVCI %u", bvci);
  }
}

static void 
decode_iei_cause(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  guint8 value;

  static const value_string tab_cause[] = {
    { 0x00, "Processor overload" },
    { 0x01, "Equipment failure" },
    { 0x02, "Transit network service failure" },
    { 0x03, "Network service transmission capacity modified from zero kbps to greater than zero kbps" },
    { 0x04, "Unknown MS" },
    { 0x05, "BVCI unknown" },
    { 0x06, "Cell traffic congestion" },
    { 0x07, "SGSN congestion" },
    { 0x08, "O&M intervention" },
    { 0x09, "BVCI blocked" },
    { 0x0a, "PFC create failure" },
    { 0x0b, "PFC preempted" },
    { 0x0c, "ABQP no more supported" },
    { 0x20, "Semantically incorrect PDU" },
    { 0x21, "Invalid mandatory information" },
    { 0x22, "Missing mandatory IE" },
    { 0x23, "Missing conditional IE" },
    { 0x24, "Unexpected conditional IE" },
    { 0x25, "Conditional IE error" },
    { 0x26, "PDU not compatible with the protocol state" },
    { 0x27, "Protocol error - unspecified" },
    { 0x28, "PDU not compatible with the feature set" },
    { 0x29, "Requested information not available" },
    { 0x2a, "Unknown destination address" },
    { 0x2b, "Unknown RIM application identity" },
    { 0x2c, "Invalid container unit information" },
    { 0x2d, "PFC queuing" },
    { 0x2e, "PFC created successfully" },
    { 0,    NULL },
  };

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    value = tvb_get_guint8(bi->tvb, bi->offset);
    proto_item_append_text(ti, ": %s (%#02x)", 
			   val_to_str(value, tab_cause, 
				      "Protocol error - unspecified"),
			   value);
  }
  bi->offset += ie->value_length;
}

static void 
decode_iei_cell_identifier(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;
  char *rai_ci;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    tf = proto_item_add_subtree(ti, ett_bssgp_cell_identifier);
    
    rai_ci = decode_rai_ci(bi, tf);
    proto_item_append_text(ti, ": %s", rai_ci);
  }else{
  bi->offset += ie->value_length;
  }
}

static void 
decode_iei_channel_needed(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  /* XXX: 'If this IE is used for only one MS, the the first CHANNEL field 
     is used and the second CHANNEL field is spare.' How know? */
  const guint8 MASK_CH1 = 0x03;
  const guint8 MASK_CH2 = 0x0c;
  proto_item *ti;
  guint8 data, ch1, ch2;
  
  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    data = tvb_get_guint8(bi->tvb, bi->offset);
    ch1 = get_masked_guint8(data, MASK_CH1);
    ch2 = get_masked_guint8(data, MASK_CH2);
    proto_item_append_text(ti, ": Ch1: %s (%u), Ch2: %s (%u)", 
			   translate_channel_needed(ch1),
			   ch1,
			   translate_channel_needed(ch2),
			   ch2);
  }
  bi->offset += ie->value_length;
}

static void 
decode_iei_drx_parameters(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_CYCLE_LENGTH_COEFFICIENT = 0xf0;
  const guint8 MASK_SPLIT_ON_CCCH = 0x08;
  const guint8 MASK_NON_DRX_TIMER = 0x07;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value;
  guint16 cycle_value;

  static const value_string tab_non_drx_timer[] = {
    { 0, "No non-DRX mode after transfer state" },
    { 1, "Max. 1 sec non-DRX mode after transfer state" },
    { 2, "Max. 2 sec non-DRX mode after transfer state" },
    { 3, "Max. 4 sec non-DRX mode after transfer state" },
    { 4, "Max. 8 sec non-DRX mode after transfer state" },
    { 5, "Max. 16 sec non-DRX mode after transfer state" },
    { 6, "Max. 32 sec non-DRX mode after transfer state" },
    { 7, "Max. 64 sec non-DRX mode after transfer state" },
    { 0, NULL},
    /* Otherwise "" */
  };

  static const value_string tab_cycle_length_coefficient[] = {
    { 0, "CN Specific DRX cycle length coefficient not specified by the MS, ie. the system information value 'CN domain specific DRX cycle length' is used" },
    { 6, "CN Specific DRX cycle length coefficient 6" },
    { 7, "CN Specific DRX cycle length coefficient 7" },
    { 8, "CN Specific DRX cycle length coefficient 8" },
    { 9, "CN Specific DRX cycle length coefficient 9" },
    { 0, NULL },
    /* Otherwise "CN Specific DRX cycle length coefficient not specified by the MS" */
  };

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_drx_parameters);

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1, 
		      "SPLIT PG CYCLE: code %u", value);
  if ((value >= 1) && (value <= 64)) {
    cycle_value = value;
  }
  else {
    switch (value) {
    case 0: cycle_value = 704; break;
    case 65: cycle_value = 71; break;
    case 66: cycle_value = 72; break;
    case 67: cycle_value = 74; break;
    case 68: cycle_value = 75; break;
    case 69: cycle_value = 77; break;
    case 70: cycle_value = 79; break;
    case 71: cycle_value = 80; break;
    case 72: cycle_value = 83; break;
    case 73: cycle_value = 86; break;
    case 74: cycle_value = 88; break;
    case 75: cycle_value = 90; break;
    case 76: cycle_value = 92; break;
    case 77: cycle_value = 96; break;
    case 78: cycle_value = 101; break;
    case 79: cycle_value = 103; break;
    case 80: cycle_value = 107; break;
    case 81: cycle_value = 112; break;
    case 82: cycle_value = 116; break;
    case 83: cycle_value = 118; break;
    case 84: cycle_value = 128; break;
    case 85: cycle_value = 141; break;
    case 86: cycle_value = 144; break;
    case 87: cycle_value = 150; break;
    case 88: cycle_value = 160; break;
    case 89: cycle_value = 171; break;
    case 90: cycle_value = 176; break;
    case 91: cycle_value = 192; break;
    case 92: cycle_value = 214; break;
    case 93: cycle_value = 224; break;
    case 94: cycle_value = 235; break;
    case 95: cycle_value = 256; break;
    case 96: cycle_value = 288; break;
    case 97: cycle_value = 320; break;
    case 98: cycle_value = 352; break;
    default:
      cycle_value = 1;
    }
    proto_item_append_text(ti, " => value %u", cycle_value);
    if (cycle_value == 704) {
      proto_item_append_text(ti, " (equivalent to no DRX)");
    }
  }
  bi->offset++;

  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_CYCLE_LENGTH_COEFFICIENT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, 
				MASK_CYCLE_LENGTH_COEFFICIENT);
  proto_item_append_text(pi, "CN specific DRX cycle length coefficient: %s (%#02x)",
			 val_to_str(value, tab_cycle_length_coefficient,
				    "Not specified by the MS"),
			 value);

  value = get_masked_guint8(data, MASK_SPLIT_ON_CCCH);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_SPLIT_ON_CCCH);
  proto_item_append_text(pi, "SPLIT on CCCH: Split pg cycle on CCCH is%s supported by the mobile station",
			 value == 0 ? " not" : "");
  
  value = get_masked_guint8(data, MASK_NON_DRX_TIMER);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_NON_DRX_TIMER);
  proto_item_append_text(pi, "Non-DRX Timer: %s (%#x)",
			 val_to_str(value, tab_non_drx_timer, ""), value);
  bi->offset++;
}

static void 
decode_iei_emlpp_priority(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_CALL_PRIORITY = 0x07;
  proto_item *ti;
  guint8 data, value;

  static const value_string tab_call_priority[] = {
    { 0, "No priority applied" },
    { 1, "Call priority level 4" },
    { 2, "Call priority level 3" },
    { 3, "Call priority level 2" },
    { 4, "Call priority level 1" },
    { 5, "Call priority level 0" },
    { 6, "Call priority level B" },
    { 7, "Call priority level A" },
    { 0, NULL },
  };

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    data = tvb_get_guint8(bi->tvb, bi->offset);
    value = get_masked_guint8(data, MASK_CALL_PRIORITY);
    proto_item_append_text(ti, ": %s", 
			   val_to_str(value, tab_call_priority, ""));
  }
  bi->offset += ie->value_length;
}

static void 
decode_iei_flush_action(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  guint8 value;

  static const value_string tab_action_value[] = {
    { 0x00, "LLC-PDU(s) deleted" },
    { 0x01, "LLC-PDU(s) transferred" },
    { 0,    NULL },
    /* Otherwise "Reserved" */
  };

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    value = tvb_get_guint8(bi->tvb, bi->offset);
    proto_item_append_text(ti, ": %s (%u)",
			   val_to_str(value, tab_action_value, "Reserved"),
			   value);

  }
  bi->offset += ie->value_length;
}

static void 
decode_iei_llc_frames_discarded(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  decode_simple_ie(ie, bi, ie_start_offset, "", " frames discarded", TRUE);
}

static void 
decode_iei_location_area(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;
  char *lai;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_location_area);

  lai = decode_rai(bi, tf);
  proto_item_append_text(ti, ": LAI %s", lai);
}

static void
decode_msrac_additional_access_technologies(proto_tree *tree, tvbuff_t *tvb, 
					    guint64 bo, guint32 length _U_) {
  proto_item *pi;
  guint8 value;
  guint8 bl; /* Bit length */

  bl = 4;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "Access Technology Type: %s (%#01x)", 
			 translate_msrac_access_technology_type(value), 
			 value);

  bl = 3;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "GMSK Power Class: Power class %u", value);

  bl = 2;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "8PSK Power Class");
  if (value == 0) {
    proto_item_append_text(pi, ": 8PSK modulation not supported for uplink");
  }
  else{
    proto_item_append_text(pi, ": Power Class E%u", value);
  }
}

static gboolean
struct_bits_exist(guint64 start_bo, guint32 struct_length, 
		  guint64 bo, guint32 num_bits) {
  return (bo + num_bits) <= (start_bo + struct_length);

}

static void 
decode_msrac_access_capabilities(proto_tree *tree, tvbuff_t *tvb,
				 guint64 bo, guint32 struct_length) {
  /* Error handling:
     - Struct too short: assume features do not exist
     - Struct too long: ignore data and jump to next Access Technology */
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 value, i;
  guint8 dgmsc = 0, demsc = 0; /* DTM GPRS/EGPRS Multi Slot Class */
  guint8 bl; /* Bit length */
  guint64 start_bo = bo;

  /* RF Power Capability */
  bl = 3;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "RF Power Capability");
  if (value == 0) {
    proto_item_append_text(pi, ": The MS does not support any GSM access technology type");
  }
  else {
    proto_item_append_text(pi, ": GMSK Power Class %u", value);
  }

  /* A5 bits */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  if (value == 1) {
    bo += bl;
    bl = 7;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    ti = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
    proto_item_append_text(ti, "A5 Bits: %#02x", value); 
    tf = proto_item_add_subtree(ti, ett_bssgp_msrac_a5_bits);
    for (i = 0; i < bl; i++) {
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo + i, 1);
      proto_item_append_text(pi, "Encryption algorithm A5/%u%s available",
			     i + 1,
			     value & (0x40 >> i) ? "" : " not");
    }
    bo += bl;
  }
  else {
    pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
    bo += bl;
    proto_item_append_text(pi, "A5 bits: Same as in the immediately preceding Access capabilities field within this IE"); 
  }

  /* ES IND */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "ESD IND: Controlled Early Classmark Sending"" option is%s implemented",
			 value == 0 ? " not" : "");

  /* PS */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "PS: PS capability%s present",
			 value == 0 ? " not" : "");

  /* VGCS */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "VBCS:%s VGCS capability %s notifications wanted",
			 value == 0 ? " No" : "",
			 value == 0 ? "or no" : "and");

  /* VBS */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "VBS:%s VBS capability %s notifications wanted",
			 value == 0 ? " No" : "",
			 value == 0 ? "or no" : "and");

  /* Multislot capability */
  /* XXX: 'Error: struct too short, assume features do not exist'
     No length is given! */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  if (value == 1) {
    bo += bl;
    ti = bit_proto_tree_add_text(tree, tvb, bo, bl, "Multislot capability"); 
    tf = proto_item_add_subtree(ti, ett_bssgp_msrac_multislot_capability);

    /* HSCSD Multislot Class */
    bl = 1;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    bo += bl;
    if (value == 1) {
      bl = 5;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi, "HSCSD Multislot Class");
      if ((value > 0 ) && (value < 19)) {
	proto_item_append_text(pi, ": Multislot Class %u", value);
      }
      else {
	proto_item_append_text(pi, ": Reserved");
      }
    }
    else
    {
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo-1, bl);
      proto_item_append_text(pi, "HSCSD Multislot Class - Bits are not available" );
    }
    
    /* GPRS Multislot Class, GPRS Extended Dynamic Allocation Capability */
    bl = 1;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    bo += bl;
    if (value == 1) {
      bl = 5;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi, "GPRS Multislot Class: Multislot Class %u", 
			     value);

      bl = 1;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi, "GPRS Extended Dynamic Allocation Capability: Extended Dynamic Allocation for GPRS is%s implemented",
			     value == 0 ? " not" : "");
    }
    else
    {
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo-1, bl);
      proto_item_append_text(pi, "GPRS Multislot Class: Multislot Class - Bits are not available" );
    }

    /* SMS Value, SM Value */
    bl = 1;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    bo += bl;
    if (value == 1) {
      bl = 4;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi, 
			     "SMS_VALUE: %u/4 timeslot (~%u microseconds)", 
			     value + 1, (value + 1) * 144);

      bl = 4;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi, 
			     "SM_VALUE: %u/4 timeslot (~%u microseconds)", 
			     value + 1, (value + 1) * 144);
    }
    else
    {
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo-1, bl);
      proto_item_append_text(pi, "SMS Value, SM Value - Bits are not available" );
    }

    /* Additions in release 99 */

    /* ECSD Multislot Class */
    bl = 1;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    bo += bl;
    if (value == 1) {
      bl = 5;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi, "ECSD Multislot Class");
      if ((value > 0 ) && (value < 19)) {
	proto_item_append_text(pi, ": Multislot Class %u", value);
      }
      else {
	proto_item_append_text(pi, ": Reserved");
      }
    }
    else
    {
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo-1, bl);
      proto_item_append_text(pi, "ECSD Multislot Class - Bits are not available" );
    }

    /* EGPRS Multislot Class, EGPRS Extended Dynamic Allocation Capability */
    bl = 1;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    bo += bl;
    if (value == 1) {
      bl = 5;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi, "EGPRS Multislot Class: Multislot Class %u",
			     value);

      bl = 1;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi, "EGPRS Extended Dynamic Allocation Capability: Extended Dynamic Allocation for EGPRS is%s implemented",
			     value == 0 ? " not" : "");
    }
    else
    {
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo-1, bl);
      proto_item_append_text(pi, "EGPRS Multislot Class: Multislot Class - Bits are not available");
    }

    /* DTM GPRS Multislot Class */
    bl = 1;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    bo += bl;
    if (value == 1) {
      bl = 2;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      dgmsc = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi, "DTM GPRS Multislot Class: %s", 
			     translate_msrac_dtm_gprs_multislot_class(dgmsc));

      /* Single slot DTM */
      bl = 1;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi, 
			     "Single Slot DTM: Single slot DTM%s supported",
			     value == 0 ? " not" : "");
      
      /* DTM EGPRS Multislot Class */
      bl = 1;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      bo += bl;
      if (value == 1) {
	bl = 2;
	if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
	demsc = tvb_get_bits8(tvb, bo, bl);
	pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
	bo += bl;
	proto_item_append_text(pi, "DTM EGPRS Multislot Class: %s", 
			       translate_msrac_dtm_gprs_multislot_class(demsc));
      }
    }
    proto_item_set_len(ti, get_num_octets_spanned(start_bo, 
						  (guint32) (bo - start_bo)));
  }
  else {
    pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
    bo += bl;
    proto_item_append_text(pi, "Multislot capability: Same as in the immediately preceding Access capabilities field within this IE"); 
  }

  /* Additions in release 99 */

  /* 8PSK Power Capability */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  bo += bl;
  if (value == 1) {
    bl = 2;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
    bo += bl;
    proto_item_append_text(pi, "8PSK Power Capability");

    if (value == 0) {
      proto_item_append_text(pi, ": Reserved");
    }
    else{
      proto_item_append_text(pi, ": Power Class E%u", value);
    }
    proto_item_append_text(pi, ", 8PSK modulation capability in uplink");
  }
  
  /* COMPACT Interference Measurement Capability */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, 
			 "COMPACT Interference Measurement Capability: %s",
			 value == 0 ? "Not implemented" : "Implemented");

  /* Revision level indicator */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "Revision Level Indicator: The ME is Release '%u %s", 
			 value == 0 ? 98 : 99,
			 value == 0 ? "or older" : "onwards");


  /* 3G RAT */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "UMTS FDD Radio Access Technology Capability: UMTS FDD%s supported", 
			 value == 0 ? " not" : "");

  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "UMTS 3.84 Mcps TDD Radio Access Technology Capability: UMTS 3.84 Mcps TDD%s supported", 
			 value == 0 ? " not" : "");

  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "CDMA 2000 Radio Access Technology Capability: CDMA 2000%s supported", 
			 value == 0 ? " not" : "");


  /* Additions in release 4*/
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "UMTS 1.28 Mcps TDD Radio Access Technology Capability: UMTS 1.28 Mcps TDD%s supported", 
			 value == 0 ? " not" : "");


  /* GERAN Feature Package 1 */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "GERAN Feature Package 1: GERAN Feature Package 1%s supported", 
			 value == 0 ? " not" : "");


  /* Extended DTM xGPRS Multislot Class */  
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  bo += bl;
  if (value == 1) {
    bl = 2;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
    bo += bl;
    proto_item_append_text(pi, "Extended DTM GPRS Multi Slot Class: %s", 
			   translate_msrac_extended_dtm_gprs_multislot_class(value, dgmsc));

    /* XXX: 'This field shall be included only if the MS supports EGPRS DTM'.
       How know? */
    bl = 2;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
    bo += bl;
    proto_item_append_text(pi, "Extended DTM EGPRS Multi Slot Class: %s", 
			   translate_msrac_extended_dtm_gprs_multislot_class(value, demsc));
  }

  /* Modulation based multislot class support */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "Modulation based multislot class support: %s supported", 
			 value == 0 ? "Not" : "");

  /* Additions in release 5 */

  /* High multislot capability */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  bo += bl;
  if (value == 1) {
    bl = 2;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
    bo += bl;
    proto_item_append_text(pi, "High Multislot Capability: %u", value);
    /* XXX: Translate? In that case, which values to compare with?
     What if Multislot capability struct was not included? */
  }

  /* GERAN Iu Mode Capabilities */
  /* XXX: Interpretation? Length? */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "GERAN Iu Mode Capabilities: %s",
			 value == 0 ? "Not supported" : "Supported");

  /* GMSK Multislot Power Profile */
  bl = 2;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "GMSK Multislot Power Profile: GMSK_MULTI_SLOT_POWER_PROFILE %u",
			 value);

  /* 8PSK Multislot Power Profile */
  /* XXX: 'If the MS does not support 8PSK in the uplink, then it shall
     set this field to 00' */
  bl = 2;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "8PSK Multislot Power Profile: 8PSK_MULTI_SLOT_POWER_PROFILE %u",
			 value);

  /* Additions in release 6 */

  /* Multiple TBF Capability */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "Multiple TBF Capability: Multiple TBF procedures in A/Gb mode%s supported",
			 value == 0 ? " not" : "");

  /* Downlink Advanced Receiver Performance */
  bl = 2;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "Donwlink Advanced Receiver Performance: Downlink Advanced Receiver Performance %s supported",
			 value == 0 ? "not" : "- phase 1");
  

  /* Extended RLC_MAC Control Message Segmentation Capability */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "Extended RLC/MAC Control Message Segmentation Capability: Extended RLC/MAC Control Message Segmentation%s supported",
			 value == 0 ? " not" : "");
}

static void 
decode_msrac_value_part(proto_tree *tree, tvbuff_t *tvb, guint64 bo) {
  /* No need to check bi->bssgp_tree here */
  const guint8 ADD_ACC_TECHN = 0x0f;
  guint8 att, length, bit, bl;
  proto_item *ti, *ti2, *pi;
  proto_tree *tf, *tf2;
  const char *att_name;
  guint64 start_bo;
  
  start_bo = bo;
  ti = bit_proto_tree_add_text(tree, tvb, bo, 8,
			       "MS RA capability value part");
  /* Temporary length of item */
  tf = proto_item_add_subtree(ti, ett_bssgp_msrac_value_part);

  bl = 4;
  att = tvb_get_bits8(tvb, bo, bl);
  att_name = translate_msrac_access_technology_type(att);
  pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
  proto_item_append_text(pi, "Access Technology Type: %s (%#01x)", att_name, att);
  proto_item_append_text(ti, ": Technology Type %s", att_name);
  bo += bl;

  bl = 7;
  length = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
  proto_item_append_text(pi, "Length: %u bits", length);
  bo += bl;
 
  if (att == ADD_ACC_TECHN) {
    bo++; /* Always '1' */
    ti2 = bit_proto_tree_add_text(tf, tvb, bo, length,
				  "Additional Access Technologies");
    tf2 = proto_item_add_subtree(ti2, ett_bssgp_msrac_additional_access_technologies);
    proto_item_set_len(ti, get_num_octets_spanned(start_bo, 4 + 7 + length + 1 + 1));
    decode_msrac_additional_access_technologies(tf2, tvb, bo, length);
  }
  else if (att <= 0x0b) { 
    ti2 = bit_proto_tree_add_text(tf, tvb, bo, length, "Access Capabilities");
    tf2 = proto_item_add_subtree(ti2, ett_bssgp_msrac_access_capabilities);
    proto_item_set_len(ti, get_num_octets_spanned(start_bo, 4 + 7 + length + 1));
    decode_msrac_access_capabilities(tf2, tvb, bo, length); 
  }
  /* else unknown Access Technology Type */

  bo += length;
  bit = tvb_get_bits8(tvb, bo, 1);
  bo++;
  if (bit == 1) {
    decode_msrac_value_part(tree, tvb, bo);
  }
}

static void 
decode_iei_ms_radio_access_capability(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;
  
  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;  
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_ms_radio_access_capability);
  
  decode_msrac_value_part(tf, bi->tvb, bi->offset * 8);
  bi->offset += ie->value_length;
}

static void 
decode_iei_omc_id(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  /* XXX: Translation: where in 3GPP TS 12.20? */
  proto_item *ti;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    proto_item_append_text(ti, ": %s", BSSGP_NOT_DECODED);
  }
  bi->offset += ie->value_length;
}

static void 
decode_iei_pdu_in_error(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    proto_item_append_text(ti, ": Erroneous BSSGP PDU (%u bytes)", 
			   ie->value_length);
  }
  bi->offset += ie->value_length;
}

static void 
decode_iei_priority(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_PCI = 0x40;
  const guint8 MASK_PRIORITY_LEVEL = 0x3c;
  const guint8 MASK_QA = 0x02;
  const guint8 MASK_PVI = 0x01;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value;

  static const value_string tab_priority_level[] = {
    { 0, "Spare" },
    { 1, "Priority Level 1 = highest priority" },
    { 2, "Priority Level 2 = 2nd highest priority" },
    { 3, "Priority Level 3 = 3rd highest priority" },
    { 4, "Priority Level 4 = 4th highest priority" },
    { 5, "Priority Level 5 = 5th highest priority" },
    { 6, "Priority Level 6 = 6th highest priority" },
    { 7, "Priority Level 7 = 7th highest priority" },
    { 8, "Priority Level 8 = 8th highest priority" },
    { 9, "Priority Level 9 = 9th highest priority" },
    { 10, "Priority Level 10 = 10th highest priority" },
    { 11, "Priority Level 11 = 11th highest priority" },
    { 12, "Priority Level 12 = 12th highest priority" },
    { 13, "Priority Level 13 = 13th highest priority" },
    { 14, "Priority Level 14 = lowest priority" },
    { 15, "Priority not used" },
    { 0, NULL },
  };

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }   
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_priority);
  
  data = tvb_get_guint8(bi->tvb, bi->offset); 
  
  value = get_masked_guint8(data, MASK_PCI);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, 
				MASK_PCI);
  proto_item_append_text(pi, "PCI: This allocation request %s preempt an existing connection",
			 value == 0 ? "shall not" : "may");
  
  value = get_masked_guint8(data, MASK_PRIORITY_LEVEL);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_PRIORITY_LEVEL);
  proto_item_append_text(pi, "Priority Level: %s",
			 val_to_str(value, tab_priority_level, ""));
  
  value = get_masked_guint8(data, MASK_QA);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_QA);
  proto_item_append_text(pi, "QA: Queuing%s allowed",
			 value == 0 ? " not" : "");
  
  value = get_masked_guint8(data, MASK_PVI);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_PVI);
  proto_item_append_text(pi, "PVI: This connection %s be preempted by another allocation request",
		      value == 0 ? "shall not" : "might");
  
  bi->offset += ie->value_length;
}

static void 
decode_iei_qos_profile(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_CR_BIT = 0x20;
  const guint8 MASK_T_BIT = 0x10;
  const guint8 MASK_A_BIT = 0x08;
  const guint8 MASK_PRECEDENCE = 0x07;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value;
  guint16 peak_bit_rate;

  static const value_string tab_precedence_ul[] = {
    { 0,   "High priority" }, 
    { 1,   "Normal priority" },
    { 2,   "Low priority" },
    { 0,   NULL },
  };

  static const value_string tab_precedence_dl[] = {
    { 0,   "Radio priority 1" }, 
    { 1,   "Radio priority 2" },
    { 2,   "Radio priority 3" },
    { 3,   "Radio priority 4" },
    { 4,   "Radio priority unknown" },
    { 0,   NULL },
  };

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_qos_profile);

  peak_bit_rate = tvb_get_ntohs(bi->tvb, bi->offset);
  pi = proto_tree_add_text(tf, bi->tvb, bi->offset, 1, "Peak bit rate: ");
  if (peak_bit_rate == 0) {
    proto_item_append_text(pi, "Best effort");
  }
  else {
    proto_item_append_text(pi, "%u bits/s", peak_bit_rate * 100);
  }
  bi->offset += 2;

  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_CR_BIT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_CR_BIT);
  proto_item_append_text(pi, "C/R: The SDU %s command/response frame type",
			 value == 0 ? "contains" : "does not contain");

  value = get_masked_guint8(data, MASK_T_BIT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_T_BIT);
  proto_item_append_text(pi, "T: The SDU contains %s",
			 value == 0 ? 
			 "data" : 
			 "signalling (e.g. related to GMM)");

  value = get_masked_guint8(data, MASK_A_BIT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_A_BIT);
  proto_item_append_text(pi, "A: Radio interface uses RLC/MAC %s functionality",
			 value == 0 ? "ARQ " : "UNITDATA ");
  
  value = get_masked_guint8(data, MASK_PRECEDENCE);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_PRECEDENCE);
  proto_item_append_text(pi, "Precedence: ");

  if (bi->ul_data) {
    proto_item_append_text(pi, val_to_str(value, tab_precedence_ul, 
					  "Reserved (Low priority)"));
  }
  else {
    proto_item_append_text(pi, val_to_str(value, tab_precedence_dl,
					  "Reserved (Radio priority 3)"));
  }
  proto_item_append_text(pi, " (%#x)", value);
  bi->offset++;
}

static void 
decode_iei_radio_cause(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  guint8 value;

  static const value_string tab_radio_cause[] = {
    { 0x00, "Radio contact lost with the MS" },
    { 0x01, "Radio link quality insufficient to continue communication" },
    { 0x02, "Cell reselection ordered" },
    { 0x03, "Cell reselection prepare" },
    { 0x04, "Cell reselection failure" },
    { 0,    NULL },
    /* Otherwise "Reserved (Radio contact lost with the MS)" */
  };

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    value = tvb_get_guint8(bi->tvb, bi->offset);
    proto_item_append_text(ti, ": %s (%#02x)",
			   val_to_str(value, tab_radio_cause, "Reserved (Radio contact lost with the MS)"),
			   value);
  }
  bi->offset += ie->value_length;
}

static void 
decode_iei_ra_cap_upd_cause(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  guint8 value;

  static const value_string tab_cause[] = {
    { 0x00, "OK, RA capability IE present" },
    { 0x01, "TLLI unknown in SGSN" },
    { 0x02, "No RA capabilities or IMSI available for this MS" },
    { 0,    NULL },
    /* Otherwise "Reserved (TLLI unknown in SGSN)" */
  };

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    value = tvb_get_guint8(bi->tvb, bi->offset);
    proto_item_append_text(ti, ": %s (%#2x)",
			   val_to_str(value, tab_cause, "Reserved (TLLI unknown in SGSN)"),
			   value);
  }
  bi->offset += ie->value_length;
}

static void 
decode_iei_routeing_area(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;
  char *rai;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_routeing_area);

  rai = decode_rai(bi, tf);
  proto_item_append_text(ti, ": RAI %s", rai);
}

static void 
decode_iei_tlli(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;
  guint32 tlli;

  tlli = tvb_get_ntohl(bi->tvb, bi->offset);

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    proto_item_append_text(ti, ": %#04x", tlli);
    
    ti = bssgp_proto_tree_add_ie(ie, bi, bi->offset);
    tf = proto_item_add_subtree(ti, ett_bssgp_tlli);
        
    proto_tree_add_item(tf, hf_bssgp_tlli, 
			       bi->tvb, bi->offset, 4, BSSGP_LITTLE_ENDIAN);
  }
  bi->offset += 4;

  if (check_col(bi->pinfo->cinfo, COL_INFO)) {
    col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, BSSGP_SEP, 
			"TLLI %#4x", tlli);
  }
  decode_nri(bi->bssgp_tree, bi, tlli);
}

static void 
decode_iei_tmsi(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;
  guint32 tmsi;

  tmsi = tvb_get_ntohl(bi->tvb, bi->offset);

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    proto_item_append_text(ti, ": %#04x", tmsi);
    
    ti = bssgp_proto_tree_add_ie(ie, bi, bi->offset);
    tf = proto_item_add_subtree(ti, ett_bssgp_tmsi_ptmsi);
        
    proto_tree_add_item(tf, hf_bssgp_tmsi_ptmsi, 
			       bi->tvb, bi->offset, 4, BSSGP_LITTLE_ENDIAN);
  }
  bi->offset += 4;

  if (check_col(bi->pinfo->cinfo, COL_INFO)) {
    col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, BSSGP_SEP, 
			"(P)TMSI %#4x", tmsi);
  }
  decode_nri(bi->bssgp_tree, bi, tmsi);
}

static void 
decode_iei_trigger_id(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  /* XXX: value is 20 octets long! How add/show? */
  proto_item *ti;
  
  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  }
  bi->offset += ie->value_length;
}

static void 
proto_tree_add_lsa_id(build_info_t *bi, proto_tree *tree) {
  guint32 data, lsa_id;
  proto_item *pi;
  
  data = tvb_get_ntoh24(bi->tvb, bi->offset);
  lsa_id = data >> 1;
  
  pi = proto_tree_add_text(tree, bi->tvb, bi->offset, 3, 
			   "LSA ID: %#03x (%s)", lsa_id,
			   data & 1 ? 
			   "Universal LSA" : "PLMN significant number");
  bi->offset += 3;
}

static void 
decode_iei_lsa_identifier_list(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_EP = 0x01;
  proto_item *ti, *pi;
  proto_tree *tf;
  int num_lsa_ids, i;
  guint32 value;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_lsa_identifier_list);

  value = tvb_get_masked_guint8(bi->tvb, bi->offset, MASK_EP);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_EP);
  proto_item_append_text(pi, "EP: The escape PLMN is%s broadcast",
			 value == 0 ? " not" : "");
  bi->offset++;

  num_lsa_ids = (ie->value_length - 1) / 3;

  for (i = 0; i < num_lsa_ids; i++) {
    proto_tree_add_lsa_id(bi, tf);
  }
}

static void 
decode_iei_lsa_information(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_LSA_ONLY = 0x01;
  const guint8 MASK_ACT = 0x20;
  const guint8 MASK_PREF = 0x10;
  const guint8 MASK_PRIORITY = 0x0f;
  proto_item *ti, *ti2, *pi;
  proto_tree *tf, *tf2;
  int num_lsa_infos, i;
  guint8 data, value;

  static const value_string tab_priority[] = {
    { 0, "Priority 1 = lowest priority" },
    { 1, "Priority 2 = 2nd lowest priority" },
    { 2, "Priority 3 = 3rd lowest priority" },
    { 3, "Priority 4 = 4th lowest priority" },
    { 4, "Priority 5 = 5th lowest priority" },
    { 5, "Priority 6 = 6th lowest priority" },
    { 6, "Priority 7 = 7th lowest priority" },
    { 7, "Priority 8 = 8th lowest priority" },
    { 8, "Priority 9 = 9th lowest priority" },
    { 9, "Priority 10 = 10th lowest priority" },
    { 10, "Priority 11 = 11th lowest priority" },
    { 11, "Priority 12 = 12th lowest priority" },
    { 12, "Priority 13 = 13th lowest priority" },
    { 13, "Priority 14 = 14th lowest priority" },
    { 14, "Priority 15 = 15th lowest priority" },
    { 15, "Priority 16 = highest priority" },
    { 0, NULL },
  };

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_lsa_information);

  value = tvb_get_masked_guint8(bi->tvb, bi->offset, MASK_LSA_ONLY);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_LSA_ONLY);
  proto_item_append_text(pi, "LSA Only: %s",
			 value == 0 ? 
			 "The subscriber has only access to the LSAs that are defined by the LSA information element" :
			 "Allow an emergency call");
  bi->offset++;

  num_lsa_infos = (ie->value_length - 1) / 4;

  for (i = 0; i < num_lsa_infos; i++) {
    ti2 = proto_tree_add_text(tf, bi->tvb, bi->offset, 4, 
			      "LSA Identification and attributes %u", i + 1);
    tf2 = proto_item_add_subtree(ti2, ett_bssgp_lsa_information_lsa_identification_and_attributes);
    
    data = tvb_get_guint8(bi->tvb, bi->offset);
    
    value = get_masked_guint8(data, MASK_ACT);
    pi = proto_tree_add_bitfield8(tf2, bi->tvb, bi->offset, MASK_ACT);
    proto_item_append_text(pi, "Act: The subscriber %s active mode support in the LSA",
			   value == 0 ? "does not have" : "has");
        
    value = get_masked_guint8(data, MASK_PREF);
    pi = proto_tree_add_bitfield8(tf2, bi->tvb, bi->offset, MASK_PREF);
    proto_item_append_text(pi, "Pref: The subscriber %s preferential access in the LSA",
			   value == 0 ? "does not have" : "has");

    value = get_masked_guint8(data, MASK_PRIORITY);
    pi = proto_tree_add_bitfield8(tf2, bi->tvb, bi->offset, MASK_PRIORITY);
    proto_item_append_text(pi, "Priority: %s",
			   val_to_str(value, tab_priority, ""));
    bi->offset++;
    
    proto_tree_add_lsa_id(bi, tf2);
  }
}

static void 
decode_iei_gprs_timer(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_UNIT_VALUE = 0xe0;
  const guint8 MASK_TIMER_VALUE = 0x1f;
  proto_item *ti;
  guint8 data, value;

  static const value_string tab_unit_value[] = {
    { 0, "incremented in multiples of 2 s" },
    { 1, "incremented in multiples of 1 minute" },
    { 2, "incremented in multiples of decihours" },
    { 3, "incremented in multiples of 500 msec" },
    { 7, "the timer does not expire" },
    { 0, NULL},
    /* Otherwise "incremented in multiples of 1 minute" */
  };

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    data = tvb_get_guint8(bi->tvb, bi->offset);
    value = get_masked_guint8(data, MASK_TIMER_VALUE);
    proto_item_append_text(ti, ": %u", value);
    
    value = get_masked_guint8(data, MASK_UNIT_VALUE);
    proto_item_append_text(ti, ", %s",
			   val_to_str(value, tab_unit_value, 
				      "incremented in multiples of 1 minute"));
  }
  bi->offset += ie->value_length;
}

static void 
decode_iei_abqp(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_DELAY_CLASS = 0x38;
  const guint8 MASK_RELIABILITY_CLASS = 0x07;
  const guint8 MASK_PEAK_THROUGHPUT = 0xf0;
  const guint8 MASK_PRECEDENCE_CLASS = 0x07;
  const guint8 MASK_MEAN_THROUGHPUT = 0x1f;
  const guint8 MASK_TRAFFIC_CLASS = 0xe0;
  const guint8 MASK_DELIVERY_ORDER = 0x18;
  const guint8 MASK_DELIVERY_OF_ERRONEOUS_SDU = 0x07;
  const guint8 MASK_RESIDUAL_BER = 0xf0;
  const guint8 MASK_SDU_ERROR_RATIO = 0x0f;
  const guint8 MASK_TRANSFER_DELAY = 0xfc;
  const guint8 MASK_TRAFFIC_HANDLING_PRIORITY = 0x03;
  const guint8 MASK_SIGNALLING_INDICATION = 0x10;
  const guint8 MASK_SOURCE_STATISTICS_DESCRIPTOR = 0x0f;
  const guint8 TRAFFIC_CLASS_CONVERSATIONAL = 1;
  const guint8 TRAFFIC_CLASS_STREAMING = 2;
  const guint8 TRAFFIC_CLASS_INTERACTIVE = 3;
  const guint8 TRAFFIC_CLASS_BACKGROUND = 4;
  guint8 data, value, traffic_class;
  proto_item *ti, *pi;
  proto_tree *tf;

  if (bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_abqp);
    
  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_DELAY_CLASS);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_DELAY_CLASS);
  proto_item_append_text(pi, "Delay Class: %s (%#x)",  
			 translate_abqp_delay_class(value, bi), value);

  value = get_masked_guint8(data, MASK_RELIABILITY_CLASS);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, 
				MASK_RELIABILITY_CLASS);
  proto_item_append_text(pi, "Reliability Class: %s (%#x)",
			 translate_abqp_reliability_class(value, bi), value);
  bi->offset++;
  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_PEAK_THROUGHPUT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, 
				MASK_PEAK_THROUGHPUT);
  proto_item_append_text(pi, "Peak Throughput: %s (%#x)",
			 translate_abqp_peak_throughput(value, bi), value);

  value = get_masked_guint8(data, MASK_PRECEDENCE_CLASS);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, 
				MASK_PRECEDENCE_CLASS);
  proto_item_append_text(pi, "Precedence Class: %s (%#x)",
			 translate_abqp_precedence_class(value, bi), value);
  bi->offset++;
  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_MEAN_THROUGHPUT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, 
				MASK_MEAN_THROUGHPUT);
  proto_item_append_text(pi, "Mean Throughput: %s (%#02x)",
			 translate_abqp_mean_throughput(value, bi), value);
  bi->offset++;
  data = tvb_get_guint8(bi->tvb, bi->offset);

  traffic_class = get_masked_guint8(data, MASK_TRAFFIC_CLASS);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_TRAFFIC_CLASS);
  proto_item_append_text(pi, "Traffic Class: %s (%#x)",
			 translate_abqp_traffic_class(traffic_class, bi), 
			 value);
  if ((traffic_class == TRAFFIC_CLASS_INTERACTIVE) || 
      (traffic_class == TRAFFIC_CLASS_BACKGROUND)) {
    proto_item_append_text(pi, " (ignored)");
  }

  value = get_masked_guint8(data, MASK_DELIVERY_ORDER);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_DELIVERY_ORDER);
  proto_item_append_text(pi, "Delivery Order: %s (%#x)",
			 translate_abqp_delivery_order(value, bi), value);

  value = get_masked_guint8(data, MASK_DELIVERY_OF_ERRONEOUS_SDU);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, 
				MASK_DELIVERY_OF_ERRONEOUS_SDU);
  proto_item_append_text(pi, "Delivery of Erroneous SDU: %s (%#x)",
			 translate_abqp_delivery_of_erroneous_sdu(value, bi),
			 value);
  bi->offset++;

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1, 
		      "Maximum SDU Size: %s",
		      translate_abqp_max_sdu_size(value, bi));
  bi->offset++;

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1, 
		      "Maximum bit rate for uplink: %s",
		      translate_abqp_max_bit_rate_for_ul(value, bi));
  bi->offset++;

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1, 
		      "Maximum bit rate for downlink: %s",
		      translate_abqp_max_bit_rate_for_dl(value, bi));
  bi->offset++;
  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_RESIDUAL_BER);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_RESIDUAL_BER);
  proto_item_append_text(pi, "Residual BER: %s (%#x)",
			 translate_abqp_residual_ber(value, bi), value);

  value = get_masked_guint8(data, MASK_SDU_ERROR_RATIO);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, 
				MASK_SDU_ERROR_RATIO);
  proto_item_append_text(pi, "SDU Error Ratio: %s (%#x)",
			 translate_abqp_sdu_error_ratio(value, bi), value);
  bi->offset++;
  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_TRANSFER_DELAY);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_TRANSFER_DELAY);
  proto_item_append_text(pi, "Transfer Delay: %s (%#02x)",
			 translate_abqp_transfer_delay(value, bi), value);

  value = get_masked_guint8(data, MASK_TRAFFIC_HANDLING_PRIORITY);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, 
				MASK_TRAFFIC_HANDLING_PRIORITY);
  proto_item_append_text(pi, "Traffic Handling Priority: %s (%#x)",
			 translate_abqp_traffic_handling_priority(value, bi),
			 value);
  if ((traffic_class == TRAFFIC_CLASS_CONVERSATIONAL) ||
      (traffic_class == TRAFFIC_CLASS_STREAMING) ||
      (traffic_class == TRAFFIC_CLASS_BACKGROUND)) {
    proto_item_append_text(pi, " (ignored)");
  }
  bi->offset++;

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1, 
		      "Guaranteed bit rate for uplink: %s",
		      translate_abqp_guaranteed_bit_rate_for_ul(value, bi));
  bi->offset++;

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1, 
		      "Guaranteed bit rate for downlink: %s",
		      translate_abqp_guaranteed_bit_rate_for_dl(value, bi));
  bi->offset++;

  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_SIGNALLING_INDICATION);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, 
				MASK_SIGNALLING_INDICATION);
  proto_item_append_text(pi, "Signalling Indication: %s for signalling traffic",
			 value == 0 ? "Not optimized" : "Optimized");
  if ((traffic_class == TRAFFIC_CLASS_CONVERSATIONAL) ||
      (traffic_class == TRAFFIC_CLASS_STREAMING) ||
      (traffic_class == TRAFFIC_CLASS_BACKGROUND)) {
    proto_item_append_text(pi, " (ignored)");
  }

  value = get_masked_guint8(data, MASK_SOURCE_STATISTICS_DESCRIPTOR);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, 
				MASK_SOURCE_STATISTICS_DESCRIPTOR);
  proto_item_append_text(pi, "Source Statistics Descriptor: %s (%#x)",
			 translate_abqp_source_statistics_descriptor(value, bi),
			 value);
  if ((traffic_class == TRAFFIC_CLASS_INTERACTIVE) ||
      (traffic_class == TRAFFIC_CLASS_BACKGROUND)) {
    proto_item_append_text(pi, " (ignored)");
  }
  bi->offset++;

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1, 
		      "Maximum bit rate for downlink (extended): %s",
		      translate_abqp_max_bit_rate_for_dl_extended(value, bi));
  bi->offset++;

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1, 
		      "Guaranteed bit rate for downlink (extended): %s",
		      translate_abqp_guaranteed_bit_rate_for_dl_extended(value, bi));
  bi->offset++;
}

static void 
decode_iei_feature_bitmap(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_ENHANCED_RADIO_STATUS = 0x40;
  const guint8 MASK_PFC_FC = 0x20;
  const guint8 MASK_RIM = 0x10;
  const guint8 MASK_LCS = 0x08;
  const guint8 MASK_INR = 0x04;
  const guint8 MASK_CBL = 0x02;
  const guint8 MASK_PFC = 0x01;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_feature_bitmap);
  
  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_ENHANCED_RADIO_STATUS);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, 
				MASK_ENHANCED_RADIO_STATUS);
  proto_item_append_text(pi, "Enhanced Radio Status: Enhanced Radio Status Procedures%s supported",
			 value == 0 ? " not" : "");
  
  value = get_masked_guint8(data, MASK_PFC_FC);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_PFC_FC);
  proto_item_append_text(pi, "PFC_FC: PFC Flow Control Procedures%s supported",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_RIM);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_RIM);
  proto_item_append_text(pi, "RIM: RAN Information Management (RIM) Procedures%s supported",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_LCS);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_LCS);
  proto_item_append_text(pi, "LCS: LCS Procedures%s supported",
		      value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_INR);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_INR);
  proto_item_append_text(pi, "INR: Inter-NSE re-routeing%s supported",
			 value == 0 ? " not" : "");
  
  value = get_masked_guint8(data, MASK_CBL);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_CBL);
  proto_item_append_text(pi, "CBL: Current Bucket Level Procedures%s supported",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_PFC);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_PFC);
  proto_item_append_text(pi, "PFC: Packet Flow Context Procedures%s supported",
			 value == 0 ? " not" : ""); 

  bi->offset += ie->value_length; 
}

static void 
decode_iei_bucket_full_ratio(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  
  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    bssgp_pi_append_bucket_full_ratio(ti, bi->tvb, bi->offset);
  }
  bi->offset += ie->value_length;
}

static void 
decode_iei_service_utran_cco(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_SERVICE_UTRAN_CCO = 0x07;
  proto_item *ti;
  guint8 data, value; 

  static const value_string tab_service_utran_cco[] = {
    { 0, "Network initiated cell change order procedure to UTRAN should be performed" },
    { 1, "Network initiated cell change order procedure to UTRAN should not be performed" },
    { 2, "Network initiated cell change order procedure to UTRAN shall not be performed" },
    { 0,    NULL },
    /* Otherwise "No information available" */
  };

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    data = tvb_get_guint8(bi->tvb, bi->offset);
    value = get_masked_guint8(data, MASK_SERVICE_UTRAN_CCO);
    proto_item_append_text(ti, ": %s (%#02x)",
			   val_to_str(value, tab_service_utran_cco, 
				      "No information available"),
			   value);
  }
  bi->offset += ie->value_length;
}

static void 
decode_iei_nsei(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  guint16 nsei;

  nsei = tvb_get_ntohs(bi->tvb, bi->offset);

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    proto_item_append_text(ti, ": %u", nsei);
    proto_tree_add_item_hidden(bi->bssgp_tree, hf_bssgp_nsei, 
			       bi->tvb, bi->offset, 2, BSSGP_LITTLE_ENDIAN);
  }
  bi->offset += ie->value_length;

  if (check_col(bi->pinfo->cinfo, COL_INFO)) {
    col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, BSSGP_SEP, 
			"NSEI %u", nsei);
  }
}

static void 
decode_iei_lcs_qos(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_VERT = 0x01;
  const guint8 MASK_XA = 0x80;
  const guint8 MASK_ACCURACY = 0x7f;
  const guint8 MASK_RT = 0xc0;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value, vert;

  static const value_string tab_rt[] = {
    { 0, "Response time is not specified" },
    { 1, "Low delay" },
    { 2, "Delay tolerant" },
    { 3, "Reserved" },
    { 0, NULL },
  };

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_lcs_qos);

  data = tvb_get_guint8(bi->tvb, bi->offset);
  vert = get_masked_guint8(data, MASK_VERT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_VERT);
  proto_item_append_text(pi, "VERT: Vertical coordinate is%s requested",
			 vert == 0 ? " not" : "");
  bi->offset++;

  data = tvb_get_guint8(bi->tvb, bi->offset);
  
  value = get_masked_guint8(data, MASK_XA);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_XA);
  proto_item_append_text(pi, "HA: Horizontal Accuracy is%s specified",
			 value == 0 ? " not" : "");

  if (value == 1) {
    value = get_masked_guint8(data, MASK_ACCURACY);
    pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_ACCURACY);
    proto_item_append_text(pi, "Horizontal Accuracy: %.1f m", 
			   10 * (pow(1.1, (double)value) - 1));
  }
  bi->offset++;

  data = tvb_get_guint8(bi->tvb, bi->offset);
  
  if (vert == 1) {
    value = get_masked_guint8(data, MASK_XA);
    pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_XA);
    proto_item_append_text(pi, "VA: Vertical Accuracy is%s specified",
			   value == 0 ? " not" : "");

    value = get_masked_guint8(data, MASK_ACCURACY);
    pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_ACCURACY);
    proto_item_append_text(pi, "Vertical Accuracy: %.1f m", 
			   45 * (pow(1.025, (double)value) - 1));
  }
  bi->offset++;

  data = tvb_get_guint8(bi->tvb, bi->offset);
  value = get_masked_guint8(data, MASK_RT);
  
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_RT);
  proto_item_append_text(pi, "RT: %s",
			 val_to_str(value, tab_rt, ""));
  bi->offset++;
}

static void 
decode_iei_lcs_client_type(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_CATEGORY = 0xf0;
  const guint8 MASK_SUBTYPE = 0x0f;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, category, subtype;

  static const value_string tab_category[] = {
    { 0, "Value Added Client" },
    /* { 1, ??? XXX }, */
    { 2, "PLMN Operator" },
    { 3, "Emergency Services" },
    { 4, "Lawful Intercept Services" },
    { 0, NULL },
    /* Otherwise "Reserved" */
  };

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_lcs_client_type);

  data = tvb_get_guint8(bi->tvb, bi->offset);
  
  category = get_masked_guint8(data, MASK_CATEGORY);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_CATEGORY);
  proto_item_append_text(pi, "Category: %s (%#x)",
			 val_to_str(category, tab_category, "Reserved"),
			 category);

  subtype = get_masked_guint8(data, MASK_SUBTYPE);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_SUBTYPE);
  proto_item_append_text(pi, "Subtype: ");

  switch (category) {
  case 0:
    if (subtype == 0) {
      proto_item_append_text(pi, "Unspecified"); break;
    }
    else {
      proto_item_append_text(pi, "Reserved"); break;
    }
    /* case 1: ??? XXX*/
  case 2:
    switch (subtype) {
    case 0: proto_item_append_text(pi, "Unspecified"); break;
    case 1: proto_item_append_text(pi, "Broadcast service"); break;
    case 2: proto_item_append_text(pi, "O&M"); break;
    case 3: proto_item_append_text(pi, "Anonymous statistics"); break;
    case 4: proto_item_append_text(pi, "Target MS service support node"); break;
    default: proto_item_append_text(pi, "Reserved"); break;
    }
    break;
  case 3:
  case 4:
    if (subtype == 0) {
      proto_item_append_text(pi, "Unspecified"); break;
    }
    else {
      proto_item_append_text(pi, "Reserved"); break;
    }
  default: /* Not category == 1! */
    proto_item_append_text(pi, "Reserved"); break;
  }

  bi->offset++;
}

static void 
decode_iei_requested_gps_assistance_data(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_A = 0x01;
  const guint8 MASK_B = 0x02;
  const guint8 MASK_C = 0x04;
  const guint8 MASK_D = 0x08;
  const guint8 MASK_E = 0x10;
  const guint8 MASK_F = 0x20;
  const guint8 MASK_G = 0x40;
  const guint8 MASK_H = 0x80;
  const guint8 MASK_I = 0x01;
  const guint8 MASK_NSAT = 0xf0;
  const guint8 MASK_T_TOE_LIMIT = 0x0f;
  const guint8 MASK_SAT_ID =0x3f;
  proto_tree *tf, *tf2;
  proto_item *ti, *ti2, *pi;
  guint8 data, value, d, nsat;
  guint16 gps_week;
  int i;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_requested_gps_assistance_data);

  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_A);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_A);
  proto_item_append_text(pi, "A: Almanac is%s srequested",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_B);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_B);
  proto_item_append_text(pi, "B: UTC Model is%s requested",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_C);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_C);
  proto_item_append_text(pi, "C: Ionospheric Model is%s requested",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_D);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_D);
  proto_item_append_text(pi, "D: Navigation Model is%s requested",
			 value == 0 ? " not" : "");
  d = value;

  value = get_masked_guint8(data, MASK_E);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_E);
  proto_item_append_text(pi, "E: DGPS Corrections are%s requested",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_F);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_F);
  proto_item_append_text(pi, "F: Reference Location is%s requested",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_G);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_G);
  proto_item_append_text(pi, "G: Reference Time is%s requested",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_H);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_H);
  proto_item_append_text(pi, "H: Acquisition Asssistance is%s requested",
			 value == 0 ? " not" : "");

  bi->offset++;

  value = tvb_get_masked_guint8(bi->tvb, bi->offset, MASK_I);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_I);
  proto_item_append_text(pi, "I: Real-Time Integrity is%s requested",
			 value == 0 ? " not" : "");
  if (d == 0) return;

  data = tvb_get_guint8(bi->tvb, bi->offset);
  gps_week = (data & 0xc0) << 2;
  data = tvb_get_guint8(bi->tvb, bi->offset + 1);
  gps_week += data;
  proto_tree_add_text(tf, bi->tvb, bi->offset, 2, 
		      "GPS Week: %u", gps_week);  
  bi->offset += 2;

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1,
		      "GPS Toe: %u", value);
  bi->offset++;

  data = tvb_get_guint8(bi->tvb, bi->offset);
  nsat = get_masked_guint8(data, MASK_NSAT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_NSAT);
  proto_item_append_text(pi, "NSAT: %u", value);

  value = get_masked_guint8(data, MASK_T_TOE_LIMIT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_T_TOE_LIMIT);
  proto_item_append_text(pi, "T-Toe Limit: %u", value);
  bi->offset++;

  for (i = 0; i < nsat; i++) {
    ti2 = proto_tree_add_text(tf, bi->tvb, bi->offset, 2, "Satellite %u", i);
    tf2 = proto_item_add_subtree(ti2, ett_bssgp_requested_gps_assistance_data_satellite);

    value = tvb_get_masked_guint8(bi->tvb, bi->offset, MASK_SAT_ID);
    pi = proto_tree_add_bitfield8(tf2, bi->tvb, bi->offset, MASK_SAT_ID);
    proto_item_append_text(pi, "SatId: %u", value);
    proto_item_append_text(ti2, ": Id %u", value);
    bi->offset++;

    value = tvb_get_guint8(bi->tvb, bi->offset);
    proto_tree_add_text(tf2, bi->tvb, bi->offset, 1, 
			"IODE: %u", value);
    proto_item_append_text(ti2, ", IODE %u", value);
    bi->offset++;
  }
}

static void 
decode_iei_location_type(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 LOCATION_ASSISTANCE = 1;
  const guint8 DECIPHERING_KEYS = 2;
  proto_item *ti;
  proto_tree *tf;
  guint8 value;

  static const value_string tab_location_information[] = {
    { 0, "Current geographic location" },
    { 1, "Location assistance information for the target MS" },
    { 2, "Deciphering keys for broadcast assistance data for the target MS" },
    { 0, NULL },
    /* Otherwise "Reserved" */
  };

  static const value_string tab_positioning_method[] = {
    { 0, "Reserved" },
    { 1, "Mobile Assisted E-OTD" },
    { 2, "Mobile Based E-OTD" },
    { 3, "Assisted GPS" },
    { 0, NULL },
    /* Otherwise "Reserved" */
  };

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_location_type);

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1, "Location Information: %s",
		      val_to_str(value, tab_location_information, 
				 "Reserved"));
  bi->offset++;

  if ((value == LOCATION_ASSISTANCE) || (value == DECIPHERING_KEYS)) {
    value = tvb_get_guint8(bi->tvb, bi->offset);
    proto_tree_add_text(tf, bi->tvb, bi->offset, 1, "Positioning Method: %s",
			val_to_str(value, tab_positioning_method, 
				   "Reserved"));
    bi->offset++;
  }
}

static void 
decode_iei_location_estimate(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  /* XXX: Which paragraph in 3GPP TS 23.032?*/
  proto_item *ti;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    proto_item_append_text(ti, ": %s", BSSGP_NOT_DECODED);
  }
  if (ie->value_length != BSSGP_UNKNOWN) {
    bi->offset += ie->value_length;
  }
}

static void 
decode_iei_positioning_data(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_PDD = 0x0f;
  const guint8 MASK_METHOD = 0xf8;
  const guint8 MASK_USAGE = 0x07;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value, i, num_methods;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }  
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_positioning_data);

  value = tvb_get_masked_guint8(bi->tvb, bi->offset, MASK_PDD);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_PDD);
  proto_item_append_text(pi, "Positioning Data Discriminator: %s",
		      value == 0 ? 
		      "Indicate usage of each positioning method that was attempted either successfully or unseccessfully" : 
		      "Reserved");
  bi->offset++;

  num_methods = ie->value_length - 1;
  for (i = 0; i < num_methods; i++) {
    data = tvb_get_guint8(bi->tvb, bi->offset);

    value = get_masked_guint8(data, MASK_METHOD);
    pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_METHOD);
    proto_item_append_text(pi, "Method: ");
    
    switch (value) {
    case 0: proto_item_set_text(pi, "Timing Advance"); break;
    case 1: proto_item_set_text(pi, "Reserved"); break;
    case 2: proto_item_set_text(pi, "Reserved"); break;
    case 3: proto_item_set_text(pi, "Mobile Assisted E-OTD"); break;
    case 4: proto_item_set_text(pi, "Mobile Based E-OTD"); break;
    case 5: proto_item_set_text(pi, "Mobile Assisted GPS"); break;
    case 6: proto_item_set_text(pi, "Mobile Based GPS"); break;
    case 7: proto_item_set_text(pi, "Conventional GPS"); break;
    case 8: proto_item_set_text(pi, "U-TDOA"); break;
    default:
      if ((value >= 9) && (value <= 0x0f)) {
	proto_item_set_text(pi, "Reserved for GSM");
      }
      else {
	proto_item_set_text(pi, "Reserved for network specific positioning methods");
      }
    }
    proto_item_append_text(pi, " (%#02x)", value); /* Method */
    
    value = get_masked_guint8(data, MASK_USAGE);

    switch (value) {
    case 0: proto_item_append_text(pi, " attempted unsuccessfully due to failure or interruption "); break;
    case 1: proto_item_append_text(pi, " attempted successfully: results not used to generate location"); break;
    case 2: proto_item_append_text(pi, " attempted successfully: results used to verify but not generate location"); break;
    case 3: proto_item_append_text(pi, "attempted successfully: results used to generate location"); break;
    case 4: proto_item_append_text(pi, "a temmpted successfully: case where MS supports multiple mobile based positioning methods and the actual method or methods used by the MS cannot be determined"); break;
    default: ; /* ??? */    
    }
    proto_item_append_text(pi, " (%#x)", value); /* Usage */
    bi->offset++;
  }
}

static void 
decode_iei_deciphering_keys(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_KEY_FLAG = 0x01;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }

  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_deciphering_keys);

  data = tvb_get_guint8(bi->tvb, bi->offset);
  value = get_masked_guint8(data, MASK_KEY_FLAG);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_KEY_FLAG);
  proto_item_append_text(pi, "Ciphering Key Flag: %u", value);
  bi->offset++;

  proto_tree_add_text(tf, bi->tvb, bi->offset, 7,
		      "Current Deciphering Key Value");
  bi->offset += 7;

  proto_tree_add_text(tf, bi->tvb, bi->offset, 7, 
		      "Next Deciphering Key Value");
  bi->offset += 7;
}

static void 
decode_iei_lcs_priority(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  /* XXX: coding (3GPP TS 29.002 7.6.11.7)? */
  proto_item *ti;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    proto_item_append_text(ti, ": %s", BSSGP_NOT_DECODED);
  }
  bi->offset += ie->value_length;
}

static void 
decode_iei_lcs_cause(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;
  guint8 value;

  static const value_string tab_cause_value[] = {
    { 0, "Unspecified" },
    { 1, "System failure" },
    { 2, "Protocol error" },
    { 3, "Data missing in position request" },
    { 4, "Unexpected value in position request" },
    { 5, "Position method failure" },
    { 6, "Target MS unreacheable" },
    { 7, "Location request aborted" },
    { 8, "Facility not supported" },
    { 9, "Inter-BSC handover ongoing" },
    { 10, "Intra-BSC handover ongoing" },
    { 11, "Congestion" },
    { 12, "Inter NSE cell change" },
    { 13, "Routeing area update" },
    { 14, "PTMSI reallocation" },
    { 15, "Suspension of GPRS services" },
    { 0, NULL },
    /* Otherwise "Unspecified" */
  };

  static const value_string tab_diagnostic_value[] = {
    { 0, "Congestion" },
    { 1, "Insufficient resources" },
    { 2, "Insufficient measurement data" },
    { 3, "Inconsistent measurement data" },
    { 4, "Location procedure not completed" },
    { 5, "Location procedure not supported by target MS" },
    { 6, "QoS not attainable" },
    { 7, "Position method not available in network" },
    { 8, "Position method not available in location area" },
    { 0, NULL },
    /* Otherwise "Unrecognized => ignored" */
  };

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  value = tvb_get_guint8(bi->tvb, bi->offset);

  if (ie->value_length == 1) {
    /* Diagnostic value not included */
    proto_item_append_text(ti, ": %s (%#02x)",
			 val_to_str(value, tab_cause_value, "Unspecified"),
			 value);
    bi->offset++;
    return;
  }

  tf = proto_item_add_subtree(ti, ett_bssgp_lcs_cause);

  proto_tree_add_text(tf, bi->tvb, bi->offset, 1, ": %s (%#02x)",
			 val_to_str(value, tab_cause_value, "Unspecified"),
			 value);
  bi->offset++;
  
  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1, ": %s (%#02x)",
			 val_to_str(value, tab_diagnostic_value, 
				    "Unrecognized => ignored"),
		      value);
  bi->offset++;
}

static void 
decode_iei_lcs_capability(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_OTD_A = 0x10;
  const guint8 MASK_OTD_B = 0x08;
  const guint8 MASK_GPS_A = 0x04;
  const guint8 MASK_GPS_B = 0x02;
  const guint8 MASK_GPS_C = 0x01;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_lcs_capability);

  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_OTD_A);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_OTD_A);
  proto_item_append_text(pi, "OTD-A: MS Assisted E-OTD%s supported",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_OTD_B);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_OTD_B);
  proto_item_append_text(pi, "OTD-B: MS Based E-OTD%s supported",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_GPS_A);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_GPS_A);
  proto_item_append_text(pi, "GPS-A: MS Assisted GPS%s supported",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_GPS_B);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_GPS_B);
  proto_item_append_text(pi, "GPS-B: MS Based GPS%s supported",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_GPS_C);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_GPS_C);
  proto_item_append_text(pi, "GPS-C: Conventional GPS%s supported",
			 value == 0 ? " not" : "");

  bi->offset++;
}

static void 
decode_iei_rrlp_flags(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_FLAG1 = 0x01;
  proto_item *ti;
  guint8 value;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    value = tvb_get_masked_guint8(bi->tvb, bi->offset, MASK_FLAG1);
    proto_item_append_text(ti, ": Flag1:%s Position Command (BSS to SGSN) or final response (SGSN to BSS) (%u)",
			   value == 0 ? " Not a" : "", value);    
  }
  bi->offset++;
}

static void 
decode_iei_rim_application_identity(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  guint8 value;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    value = tvb_get_guint8(bi->tvb, bi->offset);
    switch (value) {
    case 0: proto_item_append_text(ti, ": Reserved"); break;
    case 1: proto_item_append_text(ti, ": Network Assisted Cell Change (NACC)"); break;
    default: proto_item_append_text(ti, ": Reserved");
    }
  }
  bi->offset++;
}

static void 
decode_ran_information_common(build_info_t *bi, proto_tree *parent_tree) {
  proto_tree *tf;
  proto_item *ti;
  char *rai_ci;
  guint8 num_rai_cis, i;

  ti = proto_tree_add_text(parent_tree, bi->tvb, bi->offset, 8, 
			   "RAI + CI for Source Cell");
  tf = proto_item_add_subtree(ti, ett_bssgp_rai_ci);

  rai_ci = decode_rai_ci(bi, tf);
  proto_item_append_text(ti, ": %s", rai_ci);

  num_rai_cis = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1, 
		      "%u ""RAI+CI for Destination Cell"" follow%s", 
		      num_rai_cis, (num_rai_cis == 0) ? "" : "s");
  bi->offset++;

  for (i = 0; i < num_rai_cis; i++) {
    ti = proto_tree_add_text(parent_tree, bi->tvb, bi->offset, 8, 
			     """RAI + CI for Destination Cell"" (%u)", i + 1);
    tf = proto_item_add_subtree(ti, ett_bssgp_rai_ci);
    rai_ci = decode_rai_ci(bi, tf);
    proto_item_append_text(ti, ": %s", rai_ci);
  }
}

static void 
decode_iei_ran_information_request_container_unit(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;

  if (! bi->bssgp_tree) {
    bi->offset += 8;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_ran_information_request_container_unit);
 
  decode_ran_information_common(bi, tf);
}

static void 
decode_iei_ran_information_container_unit(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_NUMBER_OF_SI_PSI = 0xfe;
  const guint8 MASK_UNIT_TYPE = 0x01;
  const guint8 TYPE_SI = 0;
  const guint8 TYPE_PSI = 1;
  const guint8 LEN_SI = 23;
  const guint8 LEN_PSI = 22;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 num_si_psi, type_si_psi, data, i;

  if (! bi->bssgp_tree) {
    bi->offset += 8;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_ran_information_container_unit);
 
  decode_ran_information_common(bi, tf);

  data = tvb_get_guint8(bi->tvb, bi->offset);
  num_si_psi = get_masked_guint8(data, MASK_NUMBER_OF_SI_PSI);
  type_si_psi = get_masked_guint8(data, MASK_UNIT_TYPE);

  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, 
				MASK_NUMBER_OF_SI_PSI);
  proto_item_append_text(pi, "Number of SI/PSI: %u ""SI/PSI"" follow%s",
			   num_si_psi,
			   num_si_psi < 2 ? "s" : "");

  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_UNIT_TYPE);
  proto_item_append_text(pi, "Type: %s messages as specified for %s follow",
			   type_si_psi == TYPE_SI ? "SI" : "PSI",
			   type_si_psi == TYPE_SI ? "BCCH" : "PBCCH");
			   
  bi->offset++;

  for (i = 0; i < num_si_psi; i++) {
    if (type_si_psi == TYPE_SI) {
      proto_tree_add_text(tf, bi->tvb, bi->offset, LEN_SI, 
			  " SI (%u), %u octets", i + 1, LEN_SI);
      /* XXX: Not decoded yet; which section in 3GPP TS 44.018? */
      bi->offset += LEN_SI;
    }
    else if (type_si_psi == TYPE_PSI) {
      proto_tree_add_text(tf, bi->tvb, bi->offset, LEN_PSI, 
			  " PSI (%u), %u octets", i + 1, LEN_PSI);
      /* XXX: Not decoded yet; which section in 3GPP TS 44.060? */
      bi->offset += LEN_PSI;
    }
  }
}

static void 
decode_iei_ran_information_indications(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_END = 0x02;
  const guint8 MASK_ACK = 0x01;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_ran_information_indications);
    
  data = tvb_get_guint8(bi->tvb, bi->offset);
  
  value = get_masked_guint8(data, MASK_END);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_END);
  proto_item_append_text(pi, "END: %sEND indicated",
			 value == 0 ? "No " : "");

  value = get_masked_guint8(data, MASK_ACK);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_ACK);
  proto_item_append_text(pi, "ACK: %sACK requested",
			 value == 0 ? "No " : "");
  bi->offset++;
}

static void 
decode_iei_number_of_container_units(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  guint8 value;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_item_append_text(ti, ": %u Container Unit%s follow%s",
			 value + 1,
			 value == 0 ? "" : "s",
			 value > 0 ? "s" : "");
  bi->offset++;
}

static void 
decode_iei_pfc_flow_control_parameters(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_tree *tf, *tf2;
  proto_item *ti, *ti2, *pi;
  guint8 num_pfc, i, pfc_len;
  gboolean b_pfc_included;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_pfc_flow_control_parameters);

  num_pfc = tvb_get_guint8(bi->tvb, bi->offset); 
  pi = proto_tree_add_text(bi->bssgp_tree, bi->tvb, bi->offset, 1, 
			   "Number of PFCs: ");

  if (num_pfc < 12) {
    proto_item_append_text(pi, "%u", num_pfc);
  }
  else {
    proto_item_append_text(pi, "Reserved");
    return;
  }
  bi->offset++;
  if (num_pfc == 0) return;

  pfc_len = (ie->value_length - 1) / num_pfc;
  b_pfc_included = (pfc_len == 6);

  for (i = 0; i < num_pfc; i++) {
    ti2 = proto_tree_add_text(tf, bi->tvb, bi->offset, pfc_len, 
			      "PFC (%u)", i + 1);
    tf2 = proto_item_add_subtree(ti2, ett_bssgp_pfc_flow_control_parameters_pfc);

    pi = proto_tree_add_text(tf2, bi->tvb, bi->offset, 1, "PFI");
    bssgp_pi_append_pfi(pi, bi->tvb, bi->offset);
    bi->offset++;

    pi = proto_tree_add_text(tf2, bi->tvb, bi->offset, 2, "BMax_PFC");
    bssgp_pi_append_bucket_size(pi, bi->tvb, bi->offset);
    bi->offset += 2;

    pi = proto_tree_add_text(tf2, bi->tvb, bi->offset, 2, "R_PFC");
    bssgp_pi_append_bucket_leak_rate(pi, bi->tvb, bi->offset);
    bi->offset += 2;

    if (b_pfc_included) {
      pi = proto_tree_add_text(tf2, bi->tvb, bi->offset, 1, "B_PFC");
      bssgp_pi_append_bucket_full_ratio(pi, bi->tvb, bi->offset);
      bi->offset++;
    } 
  }
}

static void 
decode_iei_global_cn_id(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_tree *ti;
  proto_tree *tf;
  guint16 value;
  char *mcc_mnc;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_global_cn_id);

  mcc_mnc = decode_mcc_mnc(bi, tf);
  proto_item_append_text(ti, ": PLMN-Id %s", mcc_mnc);

  value = tvb_get_ntohs(bi->tvb, bi->offset);  
  proto_tree_add_text(tf, bi->tvb, bi->offset, 2, 
		      "CN-ID: %u", value);
  proto_item_append_text(ti, ", CN-Id %u", value);
  bi->offset += 2; 
}

static void
decode_ie(bssgp_ie_t *ie, build_info_t *bi) {
  int org_offset = bi->offset;
  const char *iename = val_to_str(ie->iei, tab_bssgp_ie_types, "Unknown");
  gboolean use_default_ie_name = (ie->name == NULL);

  if (tvb_length_remaining(bi->tvb, bi->offset) < 1) {
    return;
  }
  switch (ie->format) {
  case BSSGP_IE_FORMAT_TLV:
    if (!check_correct_iei(ie, bi)) {
      return;
    }
    bi->offset++; /* Account for type */
    ie->total_length = 1;
    get_value_length(ie, bi);
    break;
  case BSSGP_IE_FORMAT_TV:
    if (!check_correct_iei(ie, bi)) {
      return;
    }
    bi->offset++; /* Account for type */
    ie->value_length = ie->total_length - 1;
    break;
  case BSSGP_IE_FORMAT_V:
    ie->value_length = ie->total_length;
    break;
  default:
    ;
  }

  if (use_default_ie_name) {
    ie->name = g_strdup(iename);
  }

  switch (ie->iei) {
  case BSSGP_IEI_ALIGNMENT_OCTETS:
    decode_iei_alignment_octets(ie, bi, org_offset);
    break;
  case BSSGP_IEI_BMAX_DEFAULT_MS:
    decode_bucket_size(ie, bi, org_offset);
    break;
  case BSSGP_IEI_BSS_AREA_INDICATION:
    /* XXX: 'The recipient shall ignore the value of this octet'??? */
    decode_simple_ie(ie, bi, org_offset, "BSS Indicator", "", TRUE);
    break;
  case BSSGP_IEI_BUCKET_LEAK_RATE:
    decode_bucket_leak_rate(ie, bi, org_offset);
    break;
  case BSSGP_IEI_BVCI:
    decode_iei_bvci(ie, bi, org_offset);
    break;
  case BSSGP_IEI_BVC_BUCKET_SIZE:
    decode_bucket_size(ie, bi, org_offset);
    break;
  case BSSGP_IEI_BVC_MEASUREMENT:
    decode_queuing_delay(ie, bi, org_offset);
    break;
  case BSSGP_IEI_CAUSE:
    decode_iei_cause(ie, bi, org_offset);
    break;
  case BSSGP_IEI_CELL_IDENTIFIER:
    decode_iei_cell_identifier(ie, bi, org_offset);
    break;
  case BSSGP_IEI_CHANNEL_NEEDED:
    decode_iei_channel_needed(ie, bi, org_offset);
    break;
  case BSSGP_IEI_DRX_PARAMETERS:
    decode_iei_drx_parameters(ie, bi, org_offset);
    break;
  case BSSGP_IEI_EMLPP_PRIORITY:
    decode_iei_emlpp_priority(ie, bi, org_offset);
    break;
  case BSSGP_IEI_FLUSH_ACTION:
    decode_iei_flush_action(ie, bi, org_offset);
    break;
  case BSSGP_IEI_IMSI:
    decode_mobile_identity(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LLC_PDU:
    bssgp_proto_handoff(ie, bi, org_offset, llc_handle);
    break;
  case BSSGP_IEI_LLC_FRAMES_DISCARDED:
    decode_iei_llc_frames_discarded(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LOCATION_AREA:
    decode_iei_location_area(ie, bi, org_offset);
    break;
  case BSSGP_IEI_MOBILE_ID:
    decode_mobile_identity(ie, bi, org_offset);
    break;
  case BSSGP_IEI_MS_BUCKET_SIZE:
    decode_bucket_size(ie, bi, org_offset);
    break;
  case BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY:
    decode_iei_ms_radio_access_capability(ie, bi, org_offset);
    break;
  case BSSGP_IEI_OMC_ID:
    decode_iei_omc_id(ie, bi, org_offset);
    break;
  case BSSGP_IEI_PDU_IN_ERROR:
    decode_iei_pdu_in_error(ie, bi, org_offset);
    break;
  case BSSGP_IEI_PDU_LIFETIME:
    decode_queuing_delay(ie, bi, org_offset);
    break;
  case BSSGP_IEI_PRIORITY:
    decode_iei_priority(ie, bi, org_offset);
    break;
  case BSSGP_IEI_QOS_PROFILE:
    decode_iei_qos_profile(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RADIO_CAUSE:
    decode_iei_radio_cause(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RA_CAP_UPD_CAUSE:
    decode_iei_ra_cap_upd_cause(ie, bi, org_offset);
    break;
  case BSSGP_IEI_ROUTEING_AREA:
    decode_iei_routeing_area(ie, bi, org_offset);
    break;
  case BSSGP_IEI_R_DEFAULT_MS:
    decode_bucket_leak_rate(ie, bi, org_offset);
    break;
  case BSSGP_IEI_SUSPEND_REFERENCE_NUMBER:
    decode_simple_ie(ie, bi, org_offset, "", "", TRUE);
    break;
  case BSSGP_IEI_TAG:
    decode_simple_ie(ie, bi, org_offset, "", "", TRUE);
    break;
  case BSSGP_IEI_TLLI:
    decode_iei_tlli(ie, bi, org_offset);
    break; 
  case BSSGP_IEI_TMSI:
    decode_iei_tmsi(ie, bi, org_offset);
    break;
  case BSSGP_IEI_TRACE_REFERENCE:
    decode_simple_ie(ie, bi, org_offset, "", "", TRUE);
    break;
  case BSSGP_IEI_TRACE_TYPE:
    /* XXX: Coding unknown (Specification withdrawn) 3GPP TS 32.008 */
    decode_simple_ie(ie, bi, org_offset, "", "", TRUE);
    break;
  case BSSGP_IEI_TRANSACTION_ID:
    decode_simple_ie(ie, bi, org_offset, "", "", TRUE);
    break;
  case BSSGP_IEI_TRIGGER_ID:
    decode_iei_trigger_id(ie, bi, org_offset);
    break;
  case BSSGP_IEI_NUMBER_OF_OCTETS_AFFECTED:
    decode_simple_ie(ie, bi, org_offset, "", "", TRUE);
    break;
  case BSSGP_IEI_LSA_IDENTIFIER_LIST:
    decode_iei_lsa_identifier_list(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LSA_INFORMATION:
    decode_iei_lsa_information(ie, bi, org_offset);
    break;
  case BSSGP_IEI_PFI:
    decode_pfi(ie, bi, org_offset);
    break;
  case BSSGP_IEI_GPRS_TIMER:
    decode_iei_gprs_timer(ie, bi, org_offset);
    break;
  case BSSGP_IEI_ABQP:
    decode_iei_abqp(ie, bi, org_offset);
    break;
  case BSSGP_IEI_FEATURE_BITMAP:
    decode_iei_feature_bitmap(ie, bi, org_offset);
    break;
  case BSSGP_IEI_BUCKET_FULL_RATIO:
    decode_iei_bucket_full_ratio(ie, bi, org_offset);
    break;
  case BSSGP_IEI_SERVICE_UTRAN_CCO:
    decode_iei_service_utran_cco(ie, bi, org_offset);
    break;
  case BSSGP_IEI_NSEI:
    decode_iei_nsei(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RRLP_APDU:
    bssgp_proto_handoff(ie, bi, org_offset, rrlp_handle);
    break;
  case BSSGP_IEI_LCS_QOS:
    decode_iei_lcs_qos(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LCS_CLIENT_TYPE:
    decode_iei_lcs_client_type(ie, bi, org_offset);
    break;
  case BSSGP_IEI_REQUESTED_GPS_ASSISTANCE_DATA:
    decode_iei_requested_gps_assistance_data(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LOCATION_TYPE:
    decode_iei_location_type(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LOCATION_ESTIMATE:
    decode_iei_location_estimate(ie, bi, org_offset);
    break;
  case BSSGP_IEI_POSITIONING_DATA:
    decode_iei_positioning_data(ie, bi, org_offset);
    break;
  case BSSGP_IEI_DECIPHERING_KEYS:
    decode_iei_deciphering_keys(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LCS_PRIORITY:
    decode_iei_lcs_priority(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LCS_CAUSE:
    decode_iei_lcs_cause(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LCS_CAPABILITY:
    decode_iei_lcs_capability(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RRLP_FLAGS:
    decode_iei_rrlp_flags(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RIM_APPLICATION_IDENTITY:
    decode_iei_rim_application_identity(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RIM_SEQUENCE_NUMBER:
    decode_simple_ie(ie, bi, org_offset, "", "", TRUE);
    break;
  case BSSGP_IEI_RAN_INFORMATION_REQUEST_CONTAINER_UNIT:
    decode_iei_ran_information_request_container_unit(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RAN_INFORMATION_CONTAINER_UNIT:
    decode_iei_ran_information_container_unit(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RAN_INFORMATION_INDICATIONS:
    decode_iei_ran_information_indications(ie, bi, org_offset);
    break;
  case BSSGP_IEI_NUMBER_OF_CONTAINER_UNITS:
    decode_iei_number_of_container_units(ie, bi, org_offset);
    break;
  case BSSGP_IEI_PFC_FLOW_CONTROL_PARAMETERS:
    decode_iei_pfc_flow_control_parameters(ie, bi, org_offset);
    break;
  case BSSGP_IEI_GLOBAL_CN_ID:
    decode_iei_global_cn_id(ie, bi, org_offset);
    break;
  default:
    ;
  }
  if (use_default_ie_name) {
    /* Memory has been allocated; free it */
    g_free( (gpointer) ie->name);
    ie->name = NULL;
  }
}

static void
decode_pdu_general(bssgp_ie_t *ies, int num_ies, build_info_t *bi) {
  int i;
  for (i = 0; i < num_ies; i++) {
    decode_ie(&ies[i], bi);
  }
}

static void 
decode_pdu_dl_unitdata(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, "TLLI (current)",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_V, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_QOS_PROFILE, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_V, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_PDU_LIFETIME, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4},

    { BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN},

    { BSSGP_IEI_PRIORITY, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3},

    { BSSGP_IEI_DRX_PARAMETERS, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4},

    { BSSGP_IEI_IMSI, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN},

    { BSSGP_IEI_TLLI, "TLLI (old)", 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6},

    { BSSGP_IEI_PFI, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3},

    { BSSGP_IEI_LSA_INFORMATION, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN},

    { BSSGP_IEI_SERVICE_UTRAN_CCO, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3},

    { BSSGP_IEI_ALIGNMENT_OCTETS, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN},

    { BSSGP_IEI_LLC_PDU, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN},
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 13, bi);
}


static void 
decode_pdu_ul_unitdata(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_V, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_QOS_PROFILE, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_V, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_CELL_IDENTIFIER, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_PFI, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_LSA_IDENTIFIER_LIST, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_ALIGNMENT_OCTETS, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_LLC_PDU, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 7, bi);
}

static void 
decode_pdu_ra_capability(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN},
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 2, bi);
}

static void 
decode_pdu_ptm_unitdata(build_info_t *bi) {
  proto_tree_add_text(bi->bssgp_tree, bi->tvb, bi->offset, -1, 
		      "This shall be developed in GPRS phase 2");
}

static void 
decode_pdu_paging_ps(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_IMSI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_DRX_PARAMETERS, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BVCI, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_LOCATION_AREA, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 7 },

    { BSSGP_IEI_ROUTEING_AREA, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 8 },

    { BSSGP_IEI_BSS_AREA_INDICATION, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_PFI, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_ABQP, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_QOS_PROFILE, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 5 },

    { BSSGP_IEI_TMSI, "P-TMSI", 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 10, bi);
}

static void 
decode_pdu_paging_cs(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_IMSI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_DRX_PARAMETERS, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BVCI, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_LOCATION_AREA, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 7 },

    { BSSGP_IEI_ROUTEING_AREA, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 8 },

    { BSSGP_IEI_BSS_AREA_INDICATION, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_CHANNEL_NEEDED, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_EMLPP_PRIORITY, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_TMSI, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_GLOBAL_CN_ID, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 7 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 11, bi);
}

static void 
decode_pdu_ra_capability_update(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_TAG, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 2, bi);
}

static void 
decode_pdu_ra_capability_update_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_TAG, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_IMSI, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_RA_CAP_UPD_CAUSE, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN},
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 5, bi);
}

static void 
decode_pdu_radio_status(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_TMSI, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_IMSI, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_RADIO_CAUSE, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 4, bi);
}

static void 
decode_pdu_suspend(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_ROUTEING_AREA, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 8 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 2, bi);
}

static void 
decode_pdu_suspend_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_ROUTEING_AREA, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 8 },

    { BSSGP_IEI_SUSPEND_REFERENCE_NUMBER, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 3, bi);
}

static void 
decode_pdu_suspend_nack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_ROUTEING_AREA, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 8 },

    { BSSGP_IEI_CAUSE, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 3, bi);
}

static void 
decode_pdu_resume(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_ROUTEING_AREA, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 8 },

    { BSSGP_IEI_SUSPEND_REFERENCE_NUMBER, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 3, bi);
}

static void 
decode_pdu_resume_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_ROUTEING_AREA, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 8 },

  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 2, bi);
}

static void 
decode_pdu_resume_nack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_ROUTEING_AREA, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 8 },

    { BSSGP_IEI_CAUSE, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 3, bi);
}

static void 
decode_pdu_bvc_block(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_BVCI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_CAUSE, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 2, bi);
}

static void 
decode_pdu_bvc_block_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_BVCI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4},
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 1, bi);
}

static void 
decode_pdu_bvc_reset(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_BVCI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_CAUSE, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_CELL_IDENTIFIER, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_FEATURE_BITMAP, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 4, bi);
}

static void 
decode_pdu_bvc_reset_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_BVCI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_CELL_IDENTIFIER, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_FEATURE_BITMAP, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 3, bi);
}

static void 
decode_pdu_bvc_unblock(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_BVCI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 1, bi);
}

static void 
decode_pdu_bvc_unblock_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_BVCI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 1, bi);
}

static void 
decode_pdu_flow_control_bvc(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TAG, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_BVC_BUCKET_SIZE, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BUCKET_LEAK_RATE, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BMAX_DEFAULT_MS, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_R_DEFAULT_MS, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BUCKET_FULL_RATIO, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_BVC_MEASUREMENT, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 7, bi);
}

static void 
decode_pdu_flow_control_bvc_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TAG, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 1, bi);
}

static void 
decode_pdu_flow_control_ms(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_TAG, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_MS_BUCKET_SIZE, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BUCKET_LEAK_RATE, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BUCKET_FULL_RATIO, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 5, bi);
}

static void 
decode_pdu_flow_control_ms_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_TAG, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 2, bi);
}

static void 
decode_pdu_flush_ll(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_BVCI, "BVCI (old)", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BVCI, "BVCI (new)", 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_NSEI, "NSEI (new)", 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 4, bi);
}

static void 
decode_pdu_flush_ll_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_FLUSH_ACTION, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_BVCI, "BVCI (new)", 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_NUMBER_OF_OCTETS_AFFECTED, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 5 },

    { BSSGP_IEI_NSEI, "NSEI (new)", 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 5, bi);
}

static void 
decode_pdu_llc_discarded(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_LLC_FRAMES_DISCARDED, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_BVCI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_NUMBER_OF_OCTETS_AFFECTED, "Number of octets deleted", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 5 },

    { BSSGP_IEI_PFI, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 5, bi);
}

static void 
decode_pdu_flow_control_pfc(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_TAG, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_MS_BUCKET_SIZE, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BUCKET_LEAK_RATE, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BUCKET_FULL_RATIO, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_PFC_FLOW_CONTROL_PARAMETERS, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 6, bi);
}

static void 
decode_pdu_flow_control_pfc_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_TAG, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 2, bi);
}

static void 
decode_pdu_sgsn_invoke_trace(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TRACE_TYPE, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_TRACE_REFERENCE, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_TRIGGER_ID, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_MOBILE_ID, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_OMC_ID, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_TRANSACTION_ID, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 6, bi);
}

static void 
decode_pdu_status(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_CAUSE, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_BVCI, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_PDU_IN_ERROR, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = TRUE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 3, bi);
}

static void 
decode_pdu_download_bss_pfc(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_PFI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 2, bi);
}

static void 
decode_pdu_create_bss_pfc(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_IMSI, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_PFI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_GPRS_TIMER, "PFT", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_ABQP, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_SERVICE_UTRAN_CCO, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_PRIORITY, "Allocation/Retention Priority", 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_GPRS_TIMER, "T10", 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 9, bi);
}

static void 
decode_pdu_create_bss_pfc_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_PFI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_ABQP, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_CAUSE, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 4, bi);
}

static void 
decode_pdu_create_bss_pfc_nack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_PFI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_CAUSE, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 3, bi);
}

static void 
decode_pdu_modify_bss_pfc(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_PFI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_ABQP, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 3, bi);
}

static void 
decode_pdu_modify_bss_pfc_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_PFI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_GPRS_TIMER, "PFT", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_ABQP, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 4, bi);
}

static void 
decode_pdu_delete_bss_pfc(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_PFI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 2, bi);
}

static void 
decode_pdu_delete_bss_pfc_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_PFI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 2, bi);
}

static void 
decode_pdu_delete_bss_pfc_req(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_PFI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_CAUSE, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 3, bi);
}

static void 
decode_pdu_perform_location_request(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_IMSI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_DRX_PARAMETERS, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BVCI, "BVCI (PCU-PTP)", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_NSEI, "NSEI (PCU-PTP)", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_LOCATION_TYPE, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_CELL_IDENTIFIER, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_LCS_CAPABILITY, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_LCS_PRIORITY, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_LCS_QOS, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_LCS_CLIENT_TYPE, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_REQUESTED_GPS_ASSISTANCE_DATA, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 12, bi);
}

static void 
decode_pdu_perform_location_response(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_BVCI, "BVCI (PCU-PTP)", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_LOCATION_ESTIMATE, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_POSITIONING_DATA, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_DECIPHERING_KEYS, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_LCS_CAUSE, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 6, bi);
}

static void 
decode_pdu_perform_location_abort(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_BVCI, "BVCI (PCU-PTP)", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_LCS_CAUSE, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 3, bi);
}

static void 
decode_pdu_position_command(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_BVCI, "BVCI (PCU-PTP)", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_RRLP_FLAGS, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_RRLP_APDU, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 4, bi);
}

static void 
decode_pdu_position_response(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_BVCI, "BVCI (PCU-PTP)", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_RRLP_FLAGS, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_RRLP_APDU, NULL, 
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_LCS_CAUSE, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 5, bi);
}


static void 
decode_pdu_ran_information(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_CELL_IDENTIFIER, "Destination Cell identifier", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_CELL_IDENTIFIER, "Source Cell Identifier", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_RIM_APPLICATION_IDENTITY, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_RIM_SEQUENCE_NUMBER, "Sequence Number", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_RAN_INFORMATION_INDICATIONS, NULL, 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_CAUSE, "RIM Cause", 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_NUMBER_OF_CONTAINER_UNITS, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_RAN_INFORMATION_CONTAINER_UNIT, "Container Unit", 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = TRUE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 7, bi);

  while (tvb_length_remaining(bi->tvb, bi->offset) >= 4) {
    guint32 org_offset = bi->offset;

    decode_ie(&ies[7], bi);

    /* prevent an endless loop */
    if(org_offset == bi->offset) {
        THROW(ReportedBoundsError);
    }
  }
}

static void 
decode_pdu_ran_information_request(build_info_t *bi) {
  const guint8 MASK_EVENT_MR = 0x01;
  guint8 value;
  
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_CELL_IDENTIFIER, "Destination Cell Identifier", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_CELL_IDENTIFIER, "Source Cell Identifier", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_RIM_APPLICATION_IDENTITY, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_RIM_SEQUENCE_NUMBER, "Sequence Number", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },
    /* Unknown IEI! 
       { BSSGP_IEI_RAN_INFORMATION_REQUEST_INDICATIONS, NULL, 
       BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
    */
    { BSSGP_IEI_RAN_INFORMATION_REQUEST_CONTAINER_UNIT, "Container Unit", 
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };

  bi->dl_data = TRUE;
  bi->ul_data = TRUE;
  
  decode_pdu_general(ies, 4, bi);

  /* Account for type and length; assume length field = 1 as total length = 3: */
  bi->offset += 2; 
  if (bi->bssgp_tree) {
    value = tvb_get_masked_guint8(bi->tvb, bi->offset, MASK_EVENT_MR);
    proto_tree_add_text(bi->bssgp_tree, bi->tvb, bi->offset - 2, 3, 
			"RAN Information Request Indications: Event MR = %u: %s-driven multiple reports requested",
			value, 
			value == 0 ? "No event" : "Event");
  }
  bi->offset++;
  decode_pdu_general(&ies[5], 1, bi);
}

static void 
decode_pdu_ran_information_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_CELL_IDENTIFIER, "Destination Cell Identifier", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_CELL_IDENTIFIER, "Source Cell Identifier", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_RIM_APPLICATION_IDENTITY, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_RIM_SEQUENCE_NUMBER, "Sequence Number", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 4, bi);
}

static void 
decode_pdu_ran_information_error(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_CELL_IDENTIFIER, "Destination Cell Identifier", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_CELL_IDENTIFIER, "Source Cell Identifier", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_RIM_APPLICATION_IDENTITY, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_CAUSE, "RIM Cause", 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_PDU_IN_ERROR, NULL, 
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = TRUE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 5, bi);
}

static void
decode_pdu(guint8 pdutype, build_info_t *bi) {

  switch (pdutype) {
  case BSSGP_PDU_DL_UNITDATA:
    decode_pdu_dl_unitdata(bi);
    break;
  case BSSGP_PDU_UL_UNITDATA:
    decode_pdu_ul_unitdata(bi);
    break; 
  case BSSGP_PDU_RA_CAPABILITY:
    decode_pdu_ra_capability(bi);
    break;
  case BSSGP_PDU_PTM_UNITDATA:
    decode_pdu_ptm_unitdata(bi);
    break;
  case BSSGP_PDU_PAGING_PS:
    decode_pdu_paging_ps(bi);
    break;
  case BSSGP_PDU_PAGING_CS:
    decode_pdu_paging_cs(bi);
    break;
  case BSSGP_PDU_RA_CAPABILITY_UPDATE:
    decode_pdu_ra_capability_update(bi);
    break;
  case BSSGP_PDU_RA_CAPABILITY_UPDATE_ACK:
    decode_pdu_ra_capability_update_ack(bi);
    break;
  case BSSGP_PDU_RADIO_STATUS:
    decode_pdu_radio_status(bi);
    break;
  case BSSGP_PDU_SUSPEND:
    decode_pdu_suspend(bi);
    break;
  case BSSGP_PDU_SUSPEND_ACK:
    decode_pdu_suspend_ack(bi);
    break;
  case BSSGP_PDU_SUSPEND_NACK:
    decode_pdu_suspend_nack(bi);
    break;
  case BSSGP_PDU_RESUME:
    decode_pdu_resume(bi);
    break;
  case BSSGP_PDU_RESUME_ACK:
    decode_pdu_resume_ack(bi);
    break;
  case BSSGP_PDU_RESUME_NACK:
    decode_pdu_resume_nack(bi);
    break;
  case BSSGP_PDU_BVC_BLOCK:
    decode_pdu_bvc_block(bi);
    break;
  case BSSGP_PDU_BVC_BLOCK_ACK:
    decode_pdu_bvc_block_ack(bi);
    break;
  case BSSGP_PDU_BVC_RESET:
    decode_pdu_bvc_reset(bi);
    break;
  case BSSGP_PDU_BVC_RESET_ACK:
    decode_pdu_bvc_reset_ack(bi);
    break;
  case BSSGP_PDU_BVC_UNBLOCK:
    decode_pdu_bvc_unblock(bi);
    break;
  case BSSGP_PDU_BVC_UNBLOCK_ACK:
    decode_pdu_bvc_unblock_ack(bi);
    break;
  case BSSGP_PDU_FLOW_CONTROL_BVC:
    decode_pdu_flow_control_bvc(bi);
    break;
  case BSSGP_PDU_FLOW_CONTROL_BVC_ACK:
    decode_pdu_flow_control_bvc_ack(bi);
    break;
  case BSSGP_PDU_FLOW_CONTROL_MS:
    decode_pdu_flow_control_ms(bi);
    break;
  case BSSGP_PDU_FLOW_CONTROL_MS_ACK:
    decode_pdu_flow_control_ms_ack(bi);
    break;
  case BSSGP_PDU_FLUSH_LL:
    decode_pdu_flush_ll(bi);
    break;
  case BSSGP_PDU_FLUSH_LL_ACK:
    decode_pdu_flush_ll_ack(bi);
    break;
  case BSSGP_PDU_LLC_DISCARDED:
    decode_pdu_llc_discarded(bi);
    break;
  case BSSGP_PDU_FLOW_CONTROL_PFC:
    decode_pdu_flow_control_pfc(bi);
    break;
  case BSSGP_PDU_FLOW_CONTROL_PFC_ACK:
    decode_pdu_flow_control_pfc_ack(bi);
    break;
  case BSSGP_PDU_SGSN_INVOKE_TRACE:
    decode_pdu_sgsn_invoke_trace(bi);
    break;
  case BSSGP_PDU_STATUS:
    decode_pdu_status(bi);
    break;
  case BSSGP_PDU_DOWNLOAD_BSS_PFC:
    decode_pdu_download_bss_pfc(bi);
    break;
  case BSSGP_PDU_CREATE_BSS_PFC:
    decode_pdu_create_bss_pfc(bi);
    break;
  case BSSGP_PDU_CREATE_BSS_PFC_ACK:
    decode_pdu_create_bss_pfc_ack(bi);
    break;
  case BSSGP_PDU_CREATE_BSS_PFC_NACK:
    decode_pdu_create_bss_pfc_nack(bi);
    break;
  case BSSGP_PDU_MODIFY_BSS_PFC:
    decode_pdu_modify_bss_pfc(bi);
    break;
  case BSSGP_PDU_MODIFY_BSS_PFC_ACK:
    decode_pdu_modify_bss_pfc_ack(bi);
    break;
  case BSSGP_PDU_DELETE_BSS_PFC:
    decode_pdu_delete_bss_pfc(bi);
    break;
  case BSSGP_PDU_DELETE_BSS_PFC_ACK:
    decode_pdu_delete_bss_pfc_ack(bi);
    break;
  case BSSGP_PDU_DELETE_BSS_PFC_REQ:
    decode_pdu_delete_bss_pfc_req(bi);
    break;
  case BSSGP_PDU_PERFORM_LOCATION_REQUEST:
    decode_pdu_perform_location_request(bi);
    break;
  case BSSGP_PDU_PERFORM_LOCATION_RESPONSE:
    decode_pdu_perform_location_response(bi);
    break;
  case BSSGP_PDU_PERFORM_LOCATION_ABORT:
    decode_pdu_perform_location_abort(bi);
    break;
  case BSSGP_PDU_POSITION_COMMAND:
    decode_pdu_position_command(bi);
    break;
  case BSSGP_PDU_POSITION_RESPONSE:
    decode_pdu_position_response(bi);
    break;
  case BSSGP_PDU_RAN_INFORMATION:
    decode_pdu_ran_information(bi);
    break;
  case BSSGP_PDU_RAN_INFORMATION_REQUEST:
    decode_pdu_ran_information_request(bi);
    break;
  case BSSGP_PDU_RAN_INFORMATION_ACK:
    decode_pdu_ran_information_ack(bi);
    break;
  case BSSGP_PDU_RAN_INFORMATION_ERROR:
    decode_pdu_ran_information_error(bi);
    break;
  default:
    ;
  }
}

static void
dissect_bssgp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8 pdutype;
  build_info_t bi = { NULL, 0, NULL, NULL, NULL, FALSE, FALSE };

  proto_item *ti;
  proto_tree *bssgp_tree;

  bi.tvb = tvb;
  bi.pinfo = pinfo;
  bi.parent_tree = tree;

  pinfo->current_proto = "BSSGP";

  if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BSSGP");
    
  if (check_col(pinfo->cinfo, COL_INFO)) 
    col_clear(pinfo->cinfo, COL_INFO);

  pdutype = tvb_get_guint8(tvb, 0);
  bi.offset++;

  if (tree) {
    ti = proto_tree_add_item(tree, proto_bssgp, tvb, 0, -1, FALSE);
    bssgp_tree = proto_item_add_subtree(ti, ett_bssgp);
    proto_tree_add_uint_format(bssgp_tree, hf_bssgp_pdu_type, tvb, 0, 1, 
			       pdutype,
			       "PDU Type: %s (%#02x)",
			       val_to_str(pdutype, tab_bssgp_pdu_types, 
					  "Unknown"), pdutype);
    bi.bssgp_tree = bssgp_tree;
  }
  
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(pdutype, 
						   tab_bssgp_pdu_types, 
						   "Unknown PDU type"));
  }
  decode_pdu(pdutype, &bi);
}

void
proto_register_bssgp(void)
{                 
  static hf_register_info hf[] = {
    { &hf_bssgp_pdu_type,
      { "PDU Type", "bssgp.pdu_type",
	FT_UINT8, BASE_HEX, VALS(tab_bssgp_pdu_types), 0x0,          
	"", HFILL }
    },
    { &hf_bssgp_ie_type,
      { "IE Type", "bssgp.ie_type",
	FT_UINT8, BASE_HEX, VALS(tab_bssgp_ie_types), 0x0,          
	"Information element type", HFILL }
    },
    { &hf_bssgp_bvci,
      { "BVCI", "bssgp.bvci",
	FT_UINT16, BASE_HEX, NULL, 0x0,          
	"", HFILL }
    },
    { &hf_bssgp_tlli,
      { "TLLI", "bssgp.tlli",
	FT_UINT32, BASE_HEX, NULL, 0x0,          
	"", HFILL }
    },
    { &hf_bssgp_nsei,
      { "NSEI", "bssgp.nsei",
	FT_UINT16, BASE_HEX, NULL, 0x0,          
	"", HFILL }
    },
    { &hf_bssgp_mcc,
      { "MCC", "bssgp.mcc",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_bssgp_mnc,
      { "MNC", "bssgp.mnc",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_bssgp_lac,
      { "LAC", "bssgp.lac",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_bssgp_rac,
      { "RAC", "bssgp.rac",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
    { &hf_bssgp_ci,
      { "CI", "bssgp.ci",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"Cell Identity", HFILL }
    },
    { &hf_bssgp_tmsi_ptmsi,
      { "TMSI/PTMSI", "bssgp.tmsi_ptmsi",
	FT_UINT32, BASE_HEX, NULL, 0x0,
	"", HFILL }
    },
    { &hf_bssgp_imsi,
      { "IMSI", "bssgp.imsi",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"", HFILL }
    },
    { &hf_bssgp_imei,
      { "IMEI", "bssgp.imei",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"", HFILL }
    },
    { &hf_bssgp_imeisv,
      { "IMEISV", "bssgp.imeisv",
	FT_STRING, BASE_NONE, NULL, 0x0,
	"", HFILL }
    },
    { &hf_bssgp_nri,
      { "NRI", "bssgp.nri",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"", HFILL }
    },
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_bssgp,
    &ett_bssgp_qos_profile,
    &ett_bssgp_gprs_timer,
    &ett_bssgp_cell_identifier,
    &ett_bssgp_channel_needed,
    &ett_bssgp_drx_parameters,
    &ett_bssgp_mobile_identity,
    &ett_bssgp_priority,
    &ett_bssgp_lsa_identifier_list,
    &ett_bssgp_lsa_information,
    &ett_bssgp_lsa_information_lsa_identification_and_attributes,
    &ett_bssgp_abqp,
    &ett_bssgp_lcs_qos,
    &ett_bssgp_lcs_client_type,
    &ett_bssgp_requested_gps_assistance_data,
    &ett_bssgp_requested_gps_assistance_data_satellite,
    &ett_bssgp_location_type,
    &ett_bssgp_positioning_data_positioning_method,
    &ett_bssgp_lcs_cause,
    &ett_bssgp_lcs_capability,
    &ett_bssgp_rrlp_flags,
    &ett_bssgp_ran_information_indications,
    &ett_bssgp_mcc,
    &ett_bssgp_mnc,
    &ett_bssgp_routeing_area,
    &ett_bssgp_location_area,
    &ett_bssgp_rai_ci,
    &ett_bssgp_ran_information_request_container_unit,
    &ett_bssgp_ran_information_container_unit,
    &ett_bssgp_pfc_flow_control_parameters,
    &ett_bssgp_pfc_flow_control_parameters_pfc,
    &ett_bssgp_global_cn_id,
    &ett_bssgp_ms_radio_access_capability,
    &ett_bssgp_feature_bitmap,
    &ett_bssgp_positioning_data,
    &ett_bssgp_msrac_value_part,
    &ett_bssgp_msrac_additional_access_technologies,
    &ett_bssgp_msrac_access_capabilities,
    &ett_bssgp_msrac_a5_bits,
    &ett_bssgp_msrac_multislot_capability,
    &ett_bssgp_tlli,
    &ett_bssgp_tmsi_ptmsi,
  };

  /* Register the protocol name and description */
  proto_bssgp = proto_register_protocol("Base Station Subsystem GPRS Protocol", "BSSGP", "bssgp");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_bssgp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("bssgp", dissect_bssgp, proto_bssgp);
  
  /* Register configuration options */
  bssgp_module = prefs_register_protocol(proto_bssgp, proto_reg_handoff_bssgp);
  prefs_register_bool_preference(bssgp_module, "decode_nri",
				 "Decode NRI",
				 "Decode NRI (for use with SGSN in Pool)",
				 &bssgp_decode_nri);
  prefs_register_uint_preference(bssgp_module, "nri_length", "NRI length",
				 "NRI length, in bits",
				 10, &bssgp_nri_length); 
}

/* If this dissector uses sub-dissector registration add a registration routine.
*/
void
proto_reg_handoff_bssgp(void)
{
  bssgp_handle = create_dissector_handle(dissect_bssgp, proto_bssgp);
  llc_handle = find_dissector("llcgprs");
  rrlp_handle = find_dissector("rrlp");
  data_handle = find_dissector("data");  
}
