/* packet-mdd.c
 *
 * Routines for MDD Message dissection
 * Copyright 2014, Adrian Simionov <adrian.simionov@arrisi.com>
 * Copyright 2007, Bruno Verstuyft <bruno.verstuyft@excentis.com>
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
 */

#include "config.h"

#include <epan/packet.h>

#define DOWNSTREAM_ACTIVE_CHANNEL_LIST 1
#define MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP 2
#define DOWNSTREAM_AMBIGUITY_RESOLUTION_FREQUENCY_LIST 3
#define RECEIVE_CHANNEL_PROFILE_REPORTING_CONTROL 4
#define IP_INITIALIZATION_PARAMETERS 5
#define EARLY_AUTHENTICATION_AND_ENCRYPTION 6
#define UPSTREAM_ACTIVE_CHANNEL_LIST 7
#define UPSTREAM_AMBIGUITY_RESOLUTION_CHANNEL_LIST 8
#define UPSTREAM_FREQUENCY_RANGE 9
#define SYMBOL_CLOCK_LOCKING_INDICATOR 10
#define CM_STATUS_EVENT_CONTROL 11
#define UPSTREAM_TRANSMIT_POWER_REPORTING 12
#define DSG_DA_TO_DSID_ASSOCIATION_ENTRY 13
#define CM_STATUS_EVENT_ENABLE_NON_CHANNEL_SPECIFIC_EVENTS 15
#define EXTENDED_UPSTREAM_TRANSMIT_POWER_SUPPORT 16

/*Downstream Active Channel List*/
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_CHANNEL_ID 1
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_FREQUENCY 2
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_MODULATION_ORDER_ANNEX 3
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_PRIMARY_CAPABLE 4
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK 5
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_MAP_UCD_TRANSPORT_INDICATOR 6
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_OFDM_PLC_PARAMETERS 7

/*Mac Domain Downstream Service Group*/
#define MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_MD_DS_SG_IDENTIFIER 1
#define MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_CHANNEL_IDS 2

/*Modulation Orders*/
#define QAM64 0
#define QAM256 1

/*Annexes*/
#define J83_ANNEX_A 0
#define J83_ANNEX_B 1
#define J83_ANNEX_C 2

/*Primary Capable*/
#define NOT_PRIMARY_CAPABLE 0
#define PRIMARY_CAPABLE 1

/*Can carry MAP and UCD*/
#define CANNOT_CARRY_MAP_UCD 0
#define CAN_CARRY_MAP_UCD 1

/*Receive Channel Profile Reporting Control*/
#define RCP_CENTER_FREQUENCY_SPACING 1
#define VERBOSE_RCP_REPORTING 2

/*Frequency spacing*/
#define ASSUME_6MHZ_CENTER_FREQUENCY_SPACING 0
#define ASSUME_8MHZ_CENTER_FREQUENCY_SPACING 1

/*Verbose RCP reporting*/
#define RCP_NO_VERBOSE_REPORTING 0
#define RCP_VERBOSE_REPORTING 1

/*Sub-TLVs for IP Initialization Parameters*/
#define IP_PROVISIONING_MODE 1
#define PRE_REGISTRATION_DSID 2

/*IP Provisioning Modes*/
#define IPv4_ONLY 0
#define IPv6_ONLY 1
#define IP_ALTERNATE 2
#define DUAL_STACK 3

/*Early authentication and encryption*/
#define EAE_DISABLED 0
#define EAE_ENABLED 1

/*Upstream Active Channel List*/
#define UPSTREAM_ACTIVE_CHANNEL_LIST_UPSTREAM_CHANNEL_ID 1
#define UPSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK 2

/*Upstream Frequency Range*/
#define STANDARD_UPSTREAM_FREQUENCY_RANGE 0
#define EXTENDED_UPSTREAM_FREQUENCY_RANGE 1

/*Symbol Clock Locking Indicator*/
#define NOT_LOCKED_TO_MASTER_CLOCK 0
#define LOCKED_TO_MASTER_CLOCK 1

/*CM-STATUS Event Control */
#define EVENT_TYPE_CODE 1
#define MAXIMUM_EVENT_HOLDOFF_TIMER 2
#define MAXIMUM_NUMBER_OF_REPORTS_PER_EVENT 3

/*CM-STATUS Events*/
#define SECONDARY_CHANNEL_MDD_TIMEOUT 1
#define QAM_FEC_LOCK_FAILURE 2
#define SEQUENCE_OUT_OF_RANGE 3
#define MDD_RECOVERY 4
#define QAM_FEC_LOCK_RECOVERY 5
#define T4_TIMEOUT 6
#define T3_RETRIES_EXCEEDED 7
#define SUCCESFUL_RANGING_AFTER_T3_RETRIES_EXCEEDED 8
#define CM_OPERATING_ON_BATTERY_BACKUP 9
#define CM_RETURNED_TO_AC_POWER 10

/*Upstream Transmit Power Reporting*/
#define CM_DOESNT_REPORT_TRANSMIT_POWER 0
#define CM_REPORTS_TRANSMIT_POWER 1

/*Dsg DA to DSID association entry*/
#define DSG_DA_TO_DSID_ASSOCIATION_DA 1
#define DSG_DA_TO_DSID_ASSOCIATION_DSID 2

/* Define Tukey raised cosine window */
#define TUKEY_0TS 0
#define TUKEY_64TS 1
#define TUKEY_128TS 2
#define TUKEY_192TS 3
#define TUKEY_256TS 4

/* Define Cyclic prefix */
#define CYCLIC_PREFIX_192_TS 0
#define CYCLIC_PREFIX_256_TS 1
#define CYCLIC_PREFIX_512_TS 2
#define CYCLIC_PREFIX_768_TS 3
#define CYCLIC_PREFIX_1024_TS 4

/* Define Sub carrier spacing */
#define SPACING_25KHZ 0
#define SPACING_50KHZ 1

void proto_register_docsis_mdd(void);
void proto_reg_handoff_docsis_mdd(void);

static const value_string J83_annex_vals[] = {
  {J83_ANNEX_A, "J.83 Annex A"},
  {J83_ANNEX_B, "J.83 Annex B"},
  {J83_ANNEX_C, "J.83 Annex C"},
  {0, NULL}
};

static const value_string modulation_order_vals[] = {
  {QAM64,  "64 QAM"},
  {QAM256, "256 QAM"},
  {0, NULL}
};

static const value_string primary_capable_vals[] = {
  {NOT_PRIMARY_CAPABLE, "Channel is not primary-capable"},
  {PRIMARY_CAPABLE,     "channel is primary-capable"},
  {0, NULL}
};

static const value_string map_ucd_transport_indicator_vals[] = {
  {CANNOT_CARRY_MAP_UCD, "Channel cannot carry MAPs and UCDs for the MAC domain for which the MDD is sent"},
  {CAN_CARRY_MAP_UCD,    "Channel can carry MAPs and UCDs for the MAC domain for which the MDD is sent"},
  {0, NULL}
};

static const value_string tukey_raised_cosine_vals[] = {
  {TUKEY_0TS,   "0 microseconds (0 * Ts)"},
  {TUKEY_64TS,  "0.3125 microseconds (64 * Ts)"},
  {TUKEY_128TS, "0.625 microseconds (128 * Ts)"},
  {TUKEY_192TS, "0.9375 microseconds (192 * Ts)"},
  {TUKEY_256TS, "1.25 microseconds (256 * Ts)"},
  {0, NULL}
};

static const value_string cyclic_prefix_vals[] = {
  {CYCLIC_PREFIX_192_TS,  "0.9375 microseconds (192 * Ts)"},
  {CYCLIC_PREFIX_256_TS,  "1.25 microseconds (256 * Ts)"},
  {CYCLIC_PREFIX_512_TS,  "2.5 microseconds (512 * Ts) 3"},
  {CYCLIC_PREFIX_768_TS,  "3.75 microseconds (768 * Ts)"},
  {CYCLIC_PREFIX_1024_TS, "5 microseconds (1024 * Ts)"},
  {0, NULL}
};

static const value_string spacing_vals[] = {
  {SPACING_25KHZ, "25Khz"},
  {SPACING_50KHZ, "50Khz"},
  {0, NULL}
};

static const value_string mdd_tlv_vals[] = {
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST,                       "Downstream Active Channel List"},
  {MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP,                  "Mac Domain Downstream Service Group"},
  {DOWNSTREAM_AMBIGUITY_RESOLUTION_FREQUENCY_LIST,       "Downstream Ambiguity Resolution Frequency List "},
  {RECEIVE_CHANNEL_PROFILE_REPORTING_CONTROL ,           "Receive Channel Profile Reporting Control"},
  {IP_INITIALIZATION_PARAMETERS ,                        "IP Initialization Parameters"},
  {EARLY_AUTHENTICATION_AND_ENCRYPTION ,                 "Early Authentication and Encryption"},
  {UPSTREAM_ACTIVE_CHANNEL_LIST ,                        "Upstream Active Channel List"},
  {UPSTREAM_AMBIGUITY_RESOLUTION_CHANNEL_LIST ,          "Upstream Ambiguity Resolution Channel List"},
  {UPSTREAM_FREQUENCY_RANGE  ,                           "Upstream Frequency Range"},
  {SYMBOL_CLOCK_LOCKING_INDICATOR  ,                     "Symbol Clock Locking Indicator"},
  {CM_STATUS_EVENT_CONTROL  ,                            "CM-STATUS Event Control"},
  {UPSTREAM_TRANSMIT_POWER_REPORTING  ,                  "Upstream Transmit Power Reporting"},
  {DSG_DA_TO_DSID_ASSOCIATION_ENTRY  ,                   "DSG DA-to-DSID Association Entry"},
  {CM_STATUS_EVENT_ENABLE_NON_CHANNEL_SPECIFIC_EVENTS  , "CM-STATUS Event Enable for Non-Channel-Specific-Events"},
  {EXTENDED_UPSTREAM_TRANSMIT_POWER_SUPPORT  ,           "Extended Upstream Transmit Power Support"},
  {0, NULL}
};


static const value_string rpc_center_frequency_spacing_vals[] = {
  {ASSUME_6MHZ_CENTER_FREQUENCY_SPACING  , "CM MUST report only Receive Channel Profiles assuming 6 MHz center frequency spacing"},
  {ASSUME_8MHZ_CENTER_FREQUENCY_SPACING  , "CM MUST report only Receive Channel Profiles assuming 8 MHz center frequency spacing"},
  {0, NULL}
};

static const value_string verbose_rpc_reporting_vals[] = {
  {RCP_NO_VERBOSE_REPORTING  , "CM MUST NOT provide verbose reporting of all its Receive Channel Profile(s) (both standard profiles and manufacturers profiles)."},
  {RCP_VERBOSE_REPORTING  ,    "CM MUST provide verbose reporting of Receive Channel Profile(s) (both standard profiles and manufacturers profiles)."},
  {0, NULL}
};

static const value_string ip_provisioning_mode_vals[] = {
  {IPv4_ONLY  ,  "IPv4 Only"},
  {IPv6_ONLY ,   "IPv6 Only"},
  {IP_ALTERNATE, "Alternate"},
  {DUAL_STACK ,  "Dual Stack"},
  {0, NULL}
};

static const value_string eae_vals[] = {
  {EAE_DISABLED  , "early authentication and encryption disabled"},
  {EAE_ENABLED ,   "early authentication and encryption enabled"},
  {0, NULL}
};

static const value_string upstream_frequency_range_vals[] = {
  {STANDARD_UPSTREAM_FREQUENCY_RANGE, "Standard Upstream Frequency Range"},
  {EXTENDED_UPSTREAM_FREQUENCY_RANGE, "Extended Upstream Frequency Range"},
  {0, NULL}
};

static const value_string symbol_clock_locking_indicator_vals[] = {
  {NOT_LOCKED_TO_MASTER_CLOCK, "Symbol Clock is not locked to Master Clock"},
  {LOCKED_TO_MASTER_CLOCK,     "Symbol Clock is locked to Master Clock"},
  {0, NULL}
};

static const value_string symbol_cm_status_event_vals[] = {
  {SECONDARY_CHANNEL_MDD_TIMEOUT,               "Secondary Channel MDD timeout"},
  {QAM_FEC_LOCK_FAILURE,                        "Qam FEC Lock Failure"},
  {SEQUENCE_OUT_OF_RANGE,                       "Sequence out of Range"},
  {MDD_RECOVERY,                                "MDD Recovery"},
  {QAM_FEC_LOCK_RECOVERY,                       "Qam FEC Lock Recovery"},
  {T4_TIMEOUT,                                  "T4 Timeout"},
  {T3_RETRIES_EXCEEDED,                         "T3 Retries Exceeded"},
  {SUCCESFUL_RANGING_AFTER_T3_RETRIES_EXCEEDED, "Successful ranging after T3 Retries Exceeded"},
  {CM_OPERATING_ON_BATTERY_BACKUP,              "CM Operating on Battery Backup"},
  {CM_RETURNED_TO_AC_POWER,                     "CM Returned to AC Power"},
  {0, NULL}
};

static const value_string upstream_transmit_power_reporting_vals[] = {
  {CM_DOESNT_REPORT_TRANSMIT_POWER, "CM does not report transmit power in RNG-REQ, INIT-RNG-REQ, and B-INIT-RNG-REQ messages"},
  {CM_REPORTS_TRANSMIT_POWER,       "CM reports transmit power in RNG-REQ, INIT-RNG-REQ, and B-INIT-RNG-REQ messages"},
  {0, NULL}
};

static const value_string mdd_ds_active_channel_list_vals[] = {
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_CHANNEL_ID, "Channel ID"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_FREQUENCY, "Frequency"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_MODULATION_ORDER_ANNEX, "Annex/Modulation Order"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_PRIMARY_CAPABLE, "Primary Capable"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK, "CM-STATUS Event Enable Bitmask"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_MAP_UCD_TRANSPORT_INDICATOR, "MAP and UCD transport indicator"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_OFDM_PLC_PARAMETERS, "OFDM PLC Parameters"},
  {0, NULL}
};

static const value_string mdd_ds_service_group_vals[] = {
  {MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_MD_DS_SG_IDENTIFIER, "MD-DS-SG Identifier"},
  {MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_CHANNEL_IDS,       "Channel Ids"},
  {0, NULL}
};

static const value_string mdd_channel_profile_reporting_control_vals[] = {
  {RCP_CENTER_FREQUENCY_SPACING, "RPC Center Frequency Spacing"},
  {VERBOSE_RCP_REPORTING,       "Verbose RCP reporting"},
  {0, NULL}
};

static const value_string mdd_ip_init_param_vals[] = {
  {IP_PROVISIONING_MODE, "IP Provisioning Mode"},
  {PRE_REGISTRATION_DSID, "Pre-registration DSID"},
  {0, NULL}
};

static const value_string mdd_up_active_channel_list_vals[] = {
  {UPSTREAM_ACTIVE_CHANNEL_LIST_UPSTREAM_CHANNEL_ID, "Upstream Channel Id"},
  {UPSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK, "CM-STATUS Event Enable Bitmask"},
  {0, NULL}
};

static const value_string mdd_cm_status_event_control_vals[] = {
  {EVENT_TYPE_CODE, "Event Type"},
  {MAXIMUM_EVENT_HOLDOFF_TIMER,    "Maximum Event Holdoff Timer"},
  {MAXIMUM_NUMBER_OF_REPORTS_PER_EVENT,    "Maximum Number of Reports per Event"},
  {0, NULL}
};

static const value_string mdd_cm_dsg_da_to_dsid_vals[] = {
  {DSG_DA_TO_DSID_ASSOCIATION_DA, "Destination Address"},
  {DSG_DA_TO_DSID_ASSOCIATION_DSID, "DSID"},
  {0, NULL}
};

static const value_string unique_unlimited[] = {
  { 0, "Unlimited" },
  {0, NULL}
};


/* Windows does not allow data copy between dlls */
const true_false_string mdd_tfs_on_off = { "On", "Off" };

/* Initialize the protocol and registered fields */
static int proto_docsis_mdd = -1;
static int hf_docsis_mdd_ccc = -1;
static int hf_docsis_mdd_number_of_fragments = -1;
static int hf_docsis_mdd_fragment_sequence_number = -1;
static int hf_docsis_mdd_current_channel_dcid = -1;

static int hf_docsis_mdd_ds_active_channel_list_subtype = -1;
static int hf_docsis_mdd_ds_active_channel_list_length = -1;
static int hf_docsis_mdd_downstream_active_channel_list_channel_id = -1;
static int hf_docsis_mdd_downstream_active_channel_list_frequency = -1;
static int hf_docsis_mdd_downstream_active_channel_list_annex = -1;
static int hf_docsis_mdd_downstream_active_channel_list_modulation_order = -1;
static int hf_docsis_mdd_downstream_active_channel_list_primary_capable = -1;
static int hf_docsis_mdd_downstream_active_channel_list_map_ucd_transport_indicator = -1;

static int hf_docsis_mdd_cm_status_event_enable_bitmask = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_timeout = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_failure = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_recovery = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_recovery = -1;
static int hf_docsis_mdd_ofdm_plc_parameters = -1;
static int hf_docsis_mdd_ofdm_plc_parameters_tukey_raised_cosine_window = -1;
static int hf_docsis_mdd_ofdm_plc_parameters_cyclic_prefix = -1;
static int hf_docsis_mdd_ofdm_plc_parameters_sub_carrier_spacing = -1;
static int hf_docsis_mdd_up_active_channel_list_subtype = -1;
static int hf_docsis_mdd_up_active_channel_list_length = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_t4_timeout = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_t3_retries_exceeded = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_successful_ranging_after_t3_retries_exceeded = -1;

static int hf_docsis_mdd_ds_service_group_subtype = -1;
static int hf_docsis_mdd_ds_service_group_length = -1;
static int hf_docsis_mdd_mac_domain_downstream_service_group_md_ds_sg_identifier = -1;
static int hf_docsis_mdd_mac_domain_downstream_service_group_channel_id = -1;

static int hf_docsis_mdd_type = -1;
static int hf_docsis_mdd_length = -1;
static int hf_docsis_mdd_downstream_ambiguity_resolution_frequency = -1;

static int hf_docsis_mdd_channel_profile_reporting_control_subtype = -1;
static int hf_docsis_mdd_channel_profile_reporting_control_length = -1;
static int hf_docsis_mdd_rpc_center_frequency_spacing = -1;
static int hf_docsis_mdd_verbose_rcp_reporting = -1;

static int hf_docsis_mdd_ip_init_param_subtype = -1;
static int hf_docsis_mdd_ip_init_param_length = -1;
static int hf_docsis_mdd_ip_provisioning_mode = -1;
static int hf_docsis_mdd_pre_registration_dsid = -1;

static int hf_docsis_mdd_early_authentication_and_encryption = -1;

static int hf_docsis_mdd_upstream_active_channel_list_upstream_channel_id = -1;

static int hf_docsis_mdd_upstream_ambiguity_resolution_channel_list_channel_id = -1;

static int hf_docsis_mdd_upstream_frequency_range = -1;

static int hf_docsis_mdd_symbol_clock_locking_indicator = -1;

static int hf_docsis_mdd_cm_status_event_control_subtype = -1;
static int hf_docsis_mdd_cm_status_event_control_length = -1;
static int hf_docsis_mdd_event_type = -1;

static int hf_docsis_mdd_maximum_event_holdoff_timer = -1;

static int hf_docsis_mdd_maximum_number_of_reports_per_event = -1;
static int hf_docsis_mdd_upstream_transmit_power_reporting = -1;

static int hf_docsis_mdd_dsg_da_to_dsid_subtype = -1;
static int hf_docsis_mdd_dsg_da_to_dsid_length = -1;
static int hf_docsis_mdd_dsg_da_to_dsid_association_da = -1;
static int hf_docsis_mdd_dsg_da_to_dsid_association_dsid = -1;

static int hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events = -1;
static int hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_sequence_out_of_range = -1;
static int hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_operating_on_battery_backup = -1;
static int hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_returned_to_ac_power = -1;

static int hf_docsis_mdd_extended_upstream_transmit_power_support = -1;

/* Initialize the subtree pointers */
static gint ett_docsis_mdd = -1;
static gint ett_tlv = -1;
static gint ett_sub_tlv = -1;
static gint ett_docsis_mdd_ds_active_channel_list = -1;
static gint ett_docsis_mdd_ds_service_group = -1;
static gint ett_docsis_mdd_channel_profile_reporting_control = -1;
static gint ett_docsis_mdd_ip_init_param = -1;
static gint ett_docsis_mdd_up_active_channel_list = -1;
static gint ett_docsis_mdd_cm_status_event_control = -1;
static gint ett_docsis_mdd_dsg_da_to_dsid = -1;

static dissector_handle_t docsis_mdd_handle;

/* Dissection */
static void
dissect_mdd_ds_active_channel_list(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;
  static const int * order_annex[] = {
    &hf_docsis_mdd_downstream_active_channel_list_modulation_order,
    &hf_docsis_mdd_downstream_active_channel_list_annex,
    NULL
  };
  static const int * cm_status_event[] = {
    &hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_timeout,
    &hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_failure,
    &hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_recovery,
    &hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_recovery,
    NULL
  };
  static const int * ofdm_plc_parameters[] = {
    &hf_docsis_mdd_ofdm_plc_parameters_tukey_raised_cosine_window,
    &hf_docsis_mdd_ofdm_plc_parameters_cyclic_prefix,
    &hf_docsis_mdd_ofdm_plc_parameters_sub_carrier_spacing,
    NULL
  };

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_ds_active_channel_list, &mdd_item,
                                            val_to_str(type, mdd_ds_active_channel_list_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_ds_active_channel_list_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_ds_active_channel_list_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_CHANNEL_ID:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_downstream_active_channel_list_channel_id, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_FREQUENCY:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_downstream_active_channel_list_frequency, tvb, pos, 4, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_MODULATION_ORDER_ANNEX:
      proto_tree_add_bitmask_list(mdd_tree, tvb, pos, 1, order_annex, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_PRIMARY_CAPABLE:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_downstream_active_channel_list_primary_capable, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK:
      proto_tree_add_bitmask(mdd_tree, tvb, pos, hf_docsis_mdd_cm_status_event_enable_bitmask, ett_sub_tlv, cm_status_event, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_MAP_UCD_TRANSPORT_INDICATOR:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_downstream_active_channel_list_map_ucd_transport_indicator, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_OFDM_PLC_PARAMETERS:
      proto_tree_add_bitmask(mdd_tree, tvb, pos, hf_docsis_mdd_ofdm_plc_parameters, ett_sub_tlv, ofdm_plc_parameters, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_ds_service_group(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 i, length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_ds_service_group, &mdd_item,
                                            val_to_str(type, mdd_ds_service_group_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_ds_service_group_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_ds_service_group_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_MD_DS_SG_IDENTIFIER:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_mac_domain_downstream_service_group_md_ds_sg_identifier, tvb, pos, 1, ENC_BIG_ENDIAN);
     break;
    case MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_CHANNEL_IDS:
      for (i = 0; i < length; i++) {
        proto_tree_add_item (mdd_tree, hf_docsis_mdd_mac_domain_downstream_service_group_channel_id, tvb, pos + i , 1, ENC_BIG_ENDIAN);
      }
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_channel_profile_reporting_control(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_channel_profile_reporting_control, &mdd_item,
                                            val_to_str(type, mdd_channel_profile_reporting_control_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_channel_profile_reporting_control_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_channel_profile_reporting_control_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case RCP_CENTER_FREQUENCY_SPACING:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_rpc_center_frequency_spacing, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case VERBOSE_RCP_REPORTING:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_verbose_rcp_reporting, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_ip_init_param(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_ip_init_param, &mdd_item,
                                            val_to_str(type, mdd_ip_init_param_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_ip_init_param_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_ip_init_param_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case IP_PROVISIONING_MODE:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_ip_provisioning_mode, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case PRE_REGISTRATION_DSID:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_pre_registration_dsid, tvb, pos, 3, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_upstream_active_channel_list(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;
  static const int * cm_status_event[] = {
    &hf_docsis_mdd_cm_status_event_enable_bitmask_t4_timeout,
    &hf_docsis_mdd_cm_status_event_enable_bitmask_t3_retries_exceeded,
    &hf_docsis_mdd_cm_status_event_enable_bitmask_successful_ranging_after_t3_retries_exceeded,
    NULL
  };

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_up_active_channel_list, &mdd_item,
                                            val_to_str(type, mdd_up_active_channel_list_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_up_active_channel_list_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_up_active_channel_list_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case UPSTREAM_ACTIVE_CHANNEL_LIST_UPSTREAM_CHANNEL_ID:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_upstream_active_channel_list_upstream_channel_id, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case UPSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK:
      proto_tree_add_bitmask(mdd_tree, tvb, pos, hf_docsis_mdd_cm_status_event_enable_bitmask, ett_sub_tlv, cm_status_event, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_cm_status_event_control(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length, timer;
  proto_tree *mdd_tree;
  proto_item *mdd_item, *text_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_cm_status_event_control, &mdd_item,
                                            val_to_str(type, mdd_cm_status_event_control_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_cm_status_event_control_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_cm_status_event_control_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case EVENT_TYPE_CODE:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_event_type, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case MAXIMUM_EVENT_HOLDOFF_TIMER:
      text_item = proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_maximum_event_holdoff_timer, tvb, pos, 2, ENC_BIG_ENDIAN, &timer);
      proto_item_append_text(text_item, " (%d ms)", timer * 20);
      break;
    case MAXIMUM_NUMBER_OF_REPORTS_PER_EVENT:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_maximum_number_of_reports_per_event, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_dsg_da_to_dsid(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, guint16 len)
{
  guint8 type;
  guint32 length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_guint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_dsg_da_to_dsid, &mdd_item,
                                            val_to_str(type, mdd_cm_dsg_da_to_dsid_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_dsg_da_to_dsid_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_dsg_da_to_dsid_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case DSG_DA_TO_DSID_ASSOCIATION_DA:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_dsg_da_to_dsid_association_da, tvb, pos, 6, ENC_NA);
      break;
    case DSG_DA_TO_DSID_ASSOCIATION_DSID:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_dsg_da_to_dsid_association_dsid, tvb, pos, 3, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static int
dissect_mdd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *mdd_tree;

  int pos;
  guint8 type;
  guint32 i, length;
  proto_tree *tlv_tree;
  proto_item *tlv_item;
  static const int * non_channel_events[] = {
      &hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_sequence_out_of_range,
      &hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_operating_on_battery_backup,
      &hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_returned_to_ac_power,
      NULL
  };

  col_set_str(pinfo->cinfo, COL_INFO, "MDD Message:");

  it = proto_tree_add_protocol_format (tree, proto_docsis_mdd, tvb, 0, -1,"MDD Message");
  mdd_tree = proto_item_add_subtree (it, ett_docsis_mdd);

  proto_tree_add_item (mdd_tree, hf_docsis_mdd_ccc, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mdd_tree, hf_docsis_mdd_number_of_fragments, tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mdd_tree, hf_docsis_mdd_fragment_sequence_number, tvb, 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mdd_tree, hf_docsis_mdd_current_channel_dcid, tvb, 3, 1, ENC_BIG_ENDIAN);

  /*TLVs...*/
  pos = 4;
  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_guint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(mdd_tree, tvb, pos, -1,
                                            ett_tlv, &tlv_item,
                                            val_to_str(type, mdd_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_mdd_type, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_mdd_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch(type)
    {
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST:
      dissect_mdd_ds_active_channel_list(tvb, pinfo, tlv_tree, pos, length );
      break;
    case MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP:
      dissect_mdd_ds_service_group(tvb, pinfo, tlv_tree, pos, length );
      break;
    case DOWNSTREAM_AMBIGUITY_RESOLUTION_FREQUENCY_LIST:
      for (i = 0; i < length; i+=4) {
        proto_tree_add_item (tlv_tree, hf_docsis_mdd_downstream_ambiguity_resolution_frequency, tvb, pos + i, 4, ENC_BIG_ENDIAN);
      }
      break;
    case RECEIVE_CHANNEL_PROFILE_REPORTING_CONTROL:
      dissect_mdd_channel_profile_reporting_control(tvb, pinfo, tlv_tree, pos, length );
      break;
    case IP_INITIALIZATION_PARAMETERS:
      dissect_mdd_ip_init_param(tvb, pinfo, tlv_tree, pos, length );
      break;
    case EARLY_AUTHENTICATION_AND_ENCRYPTION:
      proto_tree_add_item (tlv_tree, hf_docsis_mdd_early_authentication_and_encryption, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case UPSTREAM_ACTIVE_CHANNEL_LIST:
      dissect_mdd_upstream_active_channel_list(tvb, pinfo, tlv_tree, pos, length );
      break;
    case UPSTREAM_AMBIGUITY_RESOLUTION_CHANNEL_LIST:
      for (i = 0; i < length; i++) {
        proto_tree_add_item (tlv_tree, hf_docsis_mdd_upstream_ambiguity_resolution_channel_list_channel_id, tvb, pos + i , 1, ENC_BIG_ENDIAN);
      }
      break;
    case UPSTREAM_FREQUENCY_RANGE:
      proto_tree_add_item (tlv_tree, hf_docsis_mdd_upstream_frequency_range, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case SYMBOL_CLOCK_LOCKING_INDICATOR:
      proto_tree_add_item (tlv_tree, hf_docsis_mdd_symbol_clock_locking_indicator, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case CM_STATUS_EVENT_CONTROL:
      dissect_mdd_cm_status_event_control(tvb, pinfo, tlv_tree, pos, length );
      break;
    case UPSTREAM_TRANSMIT_POWER_REPORTING:
      proto_tree_add_item (tlv_tree, hf_docsis_mdd_upstream_transmit_power_reporting, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case DSG_DA_TO_DSID_ASSOCIATION_ENTRY:
      dissect_mdd_dsg_da_to_dsid(tvb, pinfo, tlv_tree, pos, length );
      break;
    case CM_STATUS_EVENT_ENABLE_NON_CHANNEL_SPECIFIC_EVENTS:
      proto_tree_add_bitmask(tlv_tree, tvb, pos, hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events, ett_sub_tlv, non_channel_events, ENC_BIG_ENDIAN);
      break;
    case EXTENDED_UPSTREAM_TRANSMIT_POWER_SUPPORT:
      proto_tree_add_item (tlv_tree, hf_docsis_mdd_extended_upstream_transmit_power_support, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }

  return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void proto_register_docsis_mdd (void)
{
  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_mdd_ccc,
     {"Configuration Change Count", "docsis_mdd.ccc",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Configuration Change Count", HFILL}
    },
    {&hf_docsis_mdd_number_of_fragments,
     {"Number of Fragments", "docsis_mdd.number_of_fragments",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Number of Fragments", HFILL}
    },
    {&hf_docsis_mdd_fragment_sequence_number,
     {"Fragment Sequence Number", "docsis_mdd.fragment_sequence_number",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Fragment Sequence Number", HFILL}
    },
    {&hf_docsis_mdd_current_channel_dcid,
     {"Current Channel DCID", "docsis_mdd.current_channel_dcid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Current Channel DCID", HFILL}
    },
    {&hf_docsis_mdd_ds_active_channel_list_subtype,
     {"Type", "docsis_mdd.downstream_active_channel_list_tlvtype",
      FT_UINT8, BASE_DEC, VALS(mdd_ds_active_channel_list_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_ds_active_channel_list_length,
     {"Length", "docsis_mdd.downstream_active_channel_list_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_channel_id,
     {"Channel ID", "docsis_mdd.downstream_active_channel_list_channel_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Downstream Active Channel List Channel ID", HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_frequency,
     {"Frequency", "docsis_mdd.downstream_active_channel_list_frequency",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Mdd Downstream Active Channel List Frequency", HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_annex,
     {"Annex", "docsis_mdd.downstream_active_channel_list_annex",
      FT_UINT8, BASE_DEC, VALS(J83_annex_vals), 0xF0,
      "Mdd Downstream Active Channel List Annex", HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_modulation_order,
     {"Modulation Order", "docsis_mdd.downstream_active_channel_list_modulation_order",
      FT_UINT8, BASE_DEC, VALS(modulation_order_vals), 0x0F,
      "Mdd Downstream Active Channel List Modulation Order", HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_primary_capable,
     {"Primary Capable", "docsis_mdd.downstream_active_channel_list_primary_capable",
      FT_UINT8, BASE_DEC, VALS(primary_capable_vals), 0x0,
      "Mdd Downstream Active Channel List Primary Capable", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask,
     {"CM-STATUS Event Enable Bitmask", "docsis_mdd.cm_status_event_enable_bitmask",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_timeout,
     {"MDD Timeout", "docsis_mdd.downstream_active_channel_list_mdd_timeout",
      FT_UINT16, BASE_DEC, NULL, 0x0002,
      "Mdd Downstream Active Channel List MDD Timeout", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_failure,
     {"QAM/FEC Lock Failure", "docsis_mdd.cm_status_event_enable_bitmask_qam_fec_lock_failure",
      FT_UINT16, BASE_DEC, NULL, 0x0004,
      "Mdd Downstream Active Channel List QAM/FEC Lock Failure", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_recovery,
     {"MDD Recovery", "docsis_mdd.cm_status_event_enable_bitmask_mdd_recovery",
      FT_UINT16, BASE_DEC, NULL, 0x0010,
      "CM-STATUS event MDD Recovery", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_recovery,
     {"QAM/FEC Lock Recovery", "docsis_mdd.cm_status_event_enable_bitmask_qam_fec_lock_recovery",
      FT_UINT16, BASE_DEC, NULL, 0x0020,
      "CM-STATUS event QAM/FEC Lock Recovery", HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_map_ucd_transport_indicator,
     {"MAP and UCD transport indicator", "docsis_mdd.downstream_active_channel_list_map_ucd_transport_indicator",
      FT_UINT8, BASE_DEC, VALS(map_ucd_transport_indicator_vals), 0x0,
      "Mdd Downstream Active Channel List MAP and UCD Transport Indicator", HFILL}
    },
    {&hf_docsis_mdd_ofdm_plc_parameters,
     {"OFDM PLC Parameters", "docsis_mdd.ofdm_plc_parameters",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_ofdm_plc_parameters_tukey_raised_cosine_window,
     {"Tukey raised cosine window", "docsis_mdd.ofdm_plc_parameters_tukey_raised_cosine_window",
      FT_UINT8, BASE_DEC, VALS(tukey_raised_cosine_vals), 0x07,
      "OFDM PLC Parameters Tukey raised cosine window", HFILL}
    },
    {&hf_docsis_mdd_ofdm_plc_parameters_cyclic_prefix,
     {"Cyclic prefix", "docsis_mdd.ofdm_plc_parameters_cyclic_prefix",
      FT_UINT8, BASE_DEC, VALS(cyclic_prefix_vals), 0x38,
      "OFDM PLC parameters Cyclic prefix", HFILL}
    },
    {&hf_docsis_mdd_ofdm_plc_parameters_sub_carrier_spacing,
     {"Sub carrier spacing", "docsis_mdd.ofdm_plc_parameters_sub_carrier_spacing",
      FT_UINT8, BASE_DEC, VALS(spacing_vals), 0x40,
      "OFDM PLC parameters Sub carrier spacing", HFILL}
    },
    {&hf_docsis_mdd_up_active_channel_list_subtype,
     {"Type", "docsis_mdd.up_active_channel_list_tlvtype",
      FT_UINT8, BASE_DEC, VALS(mdd_up_active_channel_list_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_up_active_channel_list_length,
     {"Length", "docsis_mdd.up_active_channel_list_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_t4_timeout,
     {"T4 timeout", "docsis_mdd.cm_status_event_enable_bitmask_t4_timeout",
      FT_UINT16, BASE_DEC, NULL, 0x0040,
      "CM-STATUS event T4 timeout", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_t3_retries_exceeded,
     {"T3 Retries Exceeded", "docsis_mdd.cm_status_event_enable_bitmask_t3_retries_exceeded",
      FT_UINT16, BASE_DEC, NULL, 0x0080,
      "CM-STATUS event T3 Retries Exceeded", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_successful_ranging_after_t3_retries_exceeded,
     {"Successful Ranging after T3 Retries Exceeded", "docsis_mdd.cm_status_event_enable_bitmask_successful_ranging_after_t3_retries_exceeded",
      FT_UINT16, BASE_DEC, NULL, 0x0100,
      "CM-STATUS event Successful Ranging after T3 Retries Exceeded", HFILL}
    },
    {&hf_docsis_mdd_mac_domain_downstream_service_group_channel_id,
     {"Channel Id", "docsis_mdd.mac_domain_downstream_service_group_channel_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Mac Domain Downstream Service Group Channel Id", HFILL}
    },
    {&hf_docsis_mdd_ds_service_group_subtype,
     {"Type", "docsis_mdd.ds_service_group_type",
      FT_UINT8, BASE_DEC, VALS(mdd_ds_service_group_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_ds_service_group_length,
     {"Length", "docsis_mdd.ds_service_group_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_mac_domain_downstream_service_group_md_ds_sg_identifier,
     {"MD-DS-SG Identifier", "docsis_mdd.mac_domain_downstream_service_group_md_ds_sg_identifier",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Mac Domain Downstream Service Group MD-DS-SG Identifier", HFILL}
    },
    {&hf_docsis_mdd_type,
     {"Type", "docsis_mdd.type",
      FT_UINT8, BASE_DEC, VALS(mdd_tlv_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_length,
     {"Length", "docsis_mdd.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_downstream_ambiguity_resolution_frequency,
     {"Frequency", "docsis_mdd.downstream_ambiguity_resolution_frequency",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Mdd Downstream Ambiguity Resolution frequency", HFILL}
    },
    {&hf_docsis_mdd_channel_profile_reporting_control_subtype,
     {"Type", "docsis_mdd.channel_profile_reporting_control_type",
      FT_UINT8, BASE_DEC, VALS(mdd_channel_profile_reporting_control_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_channel_profile_reporting_control_length,
     {"Length", "docsis_mdd.channel_profile_reporting_control_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_rpc_center_frequency_spacing,
     {"RPC Center Frequency Spacing", "docsis_mdd.rpc_center_frequency_spacing",
      FT_UINT8, BASE_DEC, VALS(rpc_center_frequency_spacing_vals), 0x0,
      "Mdd RPC Center Frequency Spacing", HFILL}
    },
    {&hf_docsis_mdd_verbose_rcp_reporting,
     {"Verbose RCP reporting", "docsis_mdd.verbose_rpc_reporting",
      FT_UINT8, BASE_DEC, VALS(verbose_rpc_reporting_vals), 0x0,
      "Mdd Verbose RPC Reporting", HFILL}
    },
    {&hf_docsis_mdd_ip_init_param_subtype,
     {"Type", "docsis_mdd.ip_init_param_type",
      FT_UINT8, BASE_DEC, VALS(mdd_ip_init_param_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_ip_init_param_length,
     {"Length", "docsis_mdd.ip_init_param_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_ip_provisioning_mode,
     {"IP Provisioning Mode", "docsis_mdd.ip_provisioning_mode",
      FT_UINT8, BASE_DEC, VALS(ip_provisioning_mode_vals), 0x0,
      "Mdd IP Provisioning Mode", HFILL}
    },
    {&hf_docsis_mdd_pre_registration_dsid,
     {"Pre-registration DSID", "docsis_mdd.pre_registration_dsid",
      FT_UINT24, BASE_DEC, NULL, 0x0FFFFF,
      "Mdd Pre-registration DSID", HFILL}
    },
    {&hf_docsis_mdd_early_authentication_and_encryption,
     {"Early Authentication and Encryption", "docsis_mdd.early_authentication_and_encryption",
      FT_UINT8, BASE_DEC, VALS(eae_vals), 0x0,
      "Mdd Early Authentication and Encryption", HFILL}
    },
    {&hf_docsis_mdd_upstream_active_channel_list_upstream_channel_id,
     {"Upstream Channel Id", "docsis_mdd.upstream_active_channel_list_upstream_channel_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Upstream Active Channel List Upstream Channel Id", HFILL}
    },
    {&hf_docsis_mdd_upstream_ambiguity_resolution_channel_list_channel_id,
     {"Channel Id", "docsis_mdd.upstream_ambiguity_resolution_channel_list_channel_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Mdd Mac Domain Upstream Ambiguity Resolution Channel List Channel Id", HFILL}
    },
    {&hf_docsis_mdd_upstream_frequency_range,
     {"Upstream Frequency Range", "docsis_mdd.upstream_frequency_range",
      FT_UINT8, BASE_DEC, VALS(upstream_frequency_range_vals), 0x0,
      "Mdd Upstream Frequency Range", HFILL}
    },
    {&hf_docsis_mdd_symbol_clock_locking_indicator,
     {"Symbol Clock Locking Indicator", "docsis_mdd.symbol_clock_locking_indicator",
      FT_UINT8, BASE_DEC, VALS(symbol_clock_locking_indicator_vals), 0x0,
      "Mdd Symbol Clock Locking Indicator", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_control_subtype,
     {"Type", "docsis_mdd.cm_status_event_control_type",
      FT_UINT8, BASE_DEC, VALS(mdd_cm_status_event_control_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_control_length,
     {"Length", "docsis_mdd.cm_status_event_control_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_event_type,
     {"Event Type", "docsis_mdd.event_type",
      FT_UINT8, BASE_DEC, VALS(symbol_cm_status_event_vals), 0x0,
      "Mdd CM-STATUS Event Type", HFILL}
    },
    {&hf_docsis_mdd_maximum_event_holdoff_timer,
     {"Maximum Event Holdoff Timer (units of 20 ms)", "docsis_mdd.maximum_event_holdoff_timer",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Mdd Maximum Event Holdoff Timer", HFILL}
    },
    {&hf_docsis_mdd_maximum_number_of_reports_per_event,
     {"Maximum Number of Reports per Event", "docsis_mdd.maximum_number_of_reports_per_event",
      FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS, VALS(unique_unlimited), 0x0,
      "Mdd Maximum Number of Reports per Event", HFILL}
    },
    {&hf_docsis_mdd_upstream_transmit_power_reporting,
     {"Upstream Transmit Power Reporting", "docsis_mdd.upstream_transmit_power_reporting",
      FT_UINT8, BASE_DEC, VALS(upstream_transmit_power_reporting_vals), 0x0,
      "Mdd Upstream Transmit Power Reporting", HFILL}
    },
    {&hf_docsis_mdd_dsg_da_to_dsid_subtype,
     {"Type", "docsis_mdd.dsg_da_to_dsid_type",
      FT_UINT8, BASE_DEC, VALS(mdd_cm_dsg_da_to_dsid_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_dsg_da_to_dsid_length,
     {"Length", "docsis_mdd.dsg_da_to_dsid_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_dsg_da_to_dsid_association_da,
     {"Destination Address", "docsis_mdd.dsg_da_to_dsid_association_da",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      "Mdd DSG DA to DSID association Destination Address", HFILL}
    },
    {&hf_docsis_mdd_dsg_da_to_dsid_association_dsid,
     {"DSID", "docsis_mdd.dsg_da_to_dsid_association_dsid",
      FT_UINT24, BASE_DEC, NULL, 0x0FFFFF,
      "Mdd Mdd DSG DA to DSID association DSID", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events,
     {"CM-STATUS Event Enable Bitmask for Non-Channel-Specific Events", "docsis_mdd.cm_status_event_enable_non_channel_specific_events",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_sequence_out_of_range,
     {"Sequence out of range", "docsis_mdd.cm_status_event_enable_non_channel_specific_events_sequence_out_of_range",
      FT_UINT16, BASE_DEC, NULL, 0x0008,
      "CM-STATUS event non-channel-event Sequence out of range", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_operating_on_battery_backup,
     {"CM operating on battery backup", "docsis_mdd.cm_status_event_enable_non_channel_specific_events_cm_operating_on_battery_backup",
      FT_UINT16, BASE_DEC, NULL, 0x0200,
      "CM-STATUS event non-channel-event Cm operating on battery backup", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_returned_to_ac_power,
     {"Returned to AC power", "docsis_mdd.cm_status_event_enable_non_channel_specific_events_cm_returned_to_ac_power",
      FT_UINT16, BASE_DEC, NULL, 0x0400,
      "CM-STATUS event non-channel-event Cm returned to AC power", HFILL}
    },
    {&hf_docsis_mdd_extended_upstream_transmit_power_support,
     { "Extended Upstream Transmit Power Support", "docsis_mdd.extended_upstream_transmit_power_support",
       FT_BOOLEAN, BASE_NONE, TFS(&mdd_tfs_on_off), 0x0,
       "Mdd Extended Upstream Transmit Power Support", HFILL}
    },
  };

  static gint *ett[] = {
    &ett_docsis_mdd,
    &ett_tlv,
    &ett_sub_tlv,
    &ett_docsis_mdd_ds_active_channel_list,
    &ett_docsis_mdd_ds_service_group,
    &ett_docsis_mdd_channel_profile_reporting_control,
    &ett_docsis_mdd_ip_init_param,
    &ett_docsis_mdd_up_active_channel_list,
    &ett_docsis_mdd_cm_status_event_control,
    &ett_docsis_mdd_dsg_da_to_dsid,
  };

  proto_docsis_mdd =
    proto_register_protocol ("DOCSIS Mac Domain Description",
                             "DOCSIS Mdd", "docsis_mdd");

  proto_register_field_array (proto_docsis_mdd, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  docsis_mdd_handle = register_dissector ("docsis_mdd", dissect_mdd, proto_docsis_mdd);
}

void
proto_reg_handoff_docsis_mdd (void)
{
  dissector_add_uint ("docsis_mgmt", 33, docsis_mdd_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
