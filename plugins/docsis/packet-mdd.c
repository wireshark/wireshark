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
#include <epan/tfs.h>

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

void proto_register_docsis_mdd(void);
void proto_reg_handoff_docsis_mdd(void);

static const value_string J83_annex_vals[] = {
	{J83_ANNEX_A, "J.83 Annex A"},
	{J83_ANNEX_B, "J.83 Annex B"},
	{J83_ANNEX_C, "J.83 Annex C"},
	{0, NULL}
};


static const value_string modulation_order_vals[] = {
	{QAM64, "64 QAM"},
	{QAM256, "256 QAM"},
	{0, NULL}
};

static const value_string primary_capable_vals[] = {
	{NOT_PRIMARY_CAPABLE, "Channel is not primary-capable"},
	{PRIMARY_CAPABLE, "channel is primary-capable"},
	{0, NULL}
};


static const value_string mdd_tlv_vals[] = {
	 {DOWNSTREAM_ACTIVE_CHANNEL_LIST, "Downstream Active Channel List"},
	 {MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP, "Mac Domain Downstream Service Group"},
	 {DOWNSTREAM_AMBIGUITY_RESOLUTION_FREQUENCY_LIST, "Downstream Ambiguity Resolution Frequency List "},
	 {RECEIVE_CHANNEL_PROFILE_REPORTING_CONTROL , "Receive Channel Profile Reporting Control"},
	 {IP_INITIALIZATION_PARAMETERS , "IP Initialization Parameters"},
	 {EARLY_AUTHENTICATION_AND_ENCRYPTION , "Early Authentication and Encryption"},
	 {UPSTREAM_ACTIVE_CHANNEL_LIST , "Upstream Active Channel List"},
	 {UPSTREAM_AMBIGUITY_RESOLUTION_CHANNEL_LIST , "Upstream Ambiguity Resolution Channel List"},
	 {UPSTREAM_FREQUENCY_RANGE  , "Upstream Frequency Range"},
	 {SYMBOL_CLOCK_LOCKING_INDICATOR  , "Symbol Clock Locking Indicator"},
	 {CM_STATUS_EVENT_CONTROL  , "CM-STATUS Event Control"},
	 {UPSTREAM_TRANSMIT_POWER_REPORTING  , "Upstream Transmit Power Reporting"},
	 {DSG_DA_TO_DSID_ASSOCIATION_ENTRY  , "DSG DA-to-DSID Association Entry"},
	 {CM_STATUS_EVENT_ENABLE_NON_CHANNEL_SPECIFIC_EVENTS  , "CM-STATUS Event Enable for Non-Channel-Specific-Events"},
	 {EXTENDED_UPSTREAM_TRANSMIT_POWER_SUPPORT  , "Extended Upstream Transmit Power Support"},
	 {0, NULL}
};


static const value_string rpc_center_frequency_spacing_vals[] = {
	{ASSUME_6MHZ_CENTER_FREQUENCY_SPACING  , "CM MUST report only Receive Channel Profiles assuming 6 MHz center frequency spacing"},
	{ASSUME_8MHZ_CENTER_FREQUENCY_SPACING  , "CM MUST report only Receive Channel Profiles assuming 8 MHz center frequency spacing"},
	{0, NULL}
};

static const value_string verbose_rpc_reporting_vals[] = {
	{RCP_NO_VERBOSE_REPORTING  , "CM MUST NOT provide verbose reporting of all its Receive Channel Profile(s) (both standard profiles and manufacturers profiles)."},
	{RCP_VERBOSE_REPORTING  , "CM MUST provide verbose reporting of Receive Channel Profile(s) (both standard profiles and manufacturers profiles)."},
	{0, NULL}
};

static const value_string ip_provisioning_mode_vals[] = {
	{IPv4_ONLY  , "IPv4 Only"},
	{IPv6_ONLY , "IPv6 Only"},
	{IP_ALTERNATE, "Alternate"},
	{DUAL_STACK , "Dual Stack"},
	{0, NULL}
};

static const value_string eae_vals[] = {
	{EAE_DISABLED  , "early authentication and encryption disabled"},
	{EAE_ENABLED , "early authentication and encryption enabled"},
	{0, NULL}
};

static const value_string upstream_frequency_range_vals[] = {
	{STANDARD_UPSTREAM_FREQUENCY_RANGE, "Standard Upstream Frequency Range"},
	{EXTENDED_UPSTREAM_FREQUENCY_RANGE, "Extended Upstream Frequency Range"},
	{0, NULL}
};

static const value_string symbol_clock_locking_indicator_vals[] = {
	{NOT_LOCKED_TO_MASTER_CLOCK, "Symbol Clock is not locked to Master Clock"},
	{LOCKED_TO_MASTER_CLOCK, "Symbol Clock is locked to Master Clock"},
	{0, NULL}
};

static const value_string symbol_cm_status_event_vals[] = {
	{SECONDARY_CHANNEL_MDD_TIMEOUT, "Secondary Channel MDD timeout"},
	{QAM_FEC_LOCK_FAILURE, "Qam FEC Lock Failure"},
	{SEQUENCE_OUT_OF_RANGE, "Sequence out of Range"},
	{MDD_RECOVERY, "MDD Recovery"},
	{QAM_FEC_LOCK_RECOVERY, "Qam FEC Lock Recovery"},
	{T4_TIMEOUT, "T4 Timeout"},
	{T3_RETRIES_EXCEEDED, "T3 Retries Exceeded"},
	{SUCCESFUL_RANGING_AFTER_T3_RETRIES_EXCEEDED, "Successful ranging after T3 Retries Exceeded"},
	{CM_OPERATING_ON_BATTERY_BACKUP, "CM Operating on Battery Backup"},
	{CM_RETURNED_TO_AC_POWER, "CM Returned to AC Power"},
	{0, NULL}
};

static const value_string upstream_transmit_power_reporting_vals[] = {
	{CM_DOESNT_REPORT_TRANSMIT_POWER, "CM does not report transmit power in RNG-REQ, INIT-RNG-REQ, and B-INIT-RNG-REQ messages"},
	{CM_REPORTS_TRANSMIT_POWER, "CM reports transmit power in RNG-REQ, INIT-RNG-REQ, and B-INIT-RNG-REQ messages"},
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

static int hf_docsis_mdd_downstream_active_channel_list_channel_id = -1;
static int hf_docsis_mdd_downstream_active_channel_list_frequency = -1;
static int hf_docsis_mdd_downstream_active_channel_list_annex = -1;
static int hf_docsis_mdd_downstream_active_channel_list_modulation_order = -1;
static int hf_docsis_mdd_downstream_active_channel_list_primary_capable = -1;

static int hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_timeout = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_failure = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_recovery = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_recovery = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_t4_timeout = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_t3_retries_exceeded = -1;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_successful_ranging_after_t3_retries_exceeded = -1;


static int hf_docsis_mdd_mac_domain_downstream_service_group_md_ds_sg_identifier = -1;
static int hf_docsis_mdd_mac_domain_downstream_service_group_channel_id = -1;

static int hf_docsis_mdd_downstream_ambiguity_resolution_frequency = -1;

static int hf_docsis_mdd_rpc_center_frequency_spacing = -1;
static int hf_docsis_mdd_verbose_rcp_reporting = -1;

static int hf_docsis_mdd_ip_provisioning_mode = -1;
static int hf_docsis_mdd_pre_registration_dsid = -1;

static int hf_docsis_mdd_early_authentication_and_encryption = -1;

static int hf_docsis_mdd_upstream_active_channel_list_upstream_channel_id = -1;

static int hf_docsis_mdd_upstream_ambiguity_resolution_channel_list_channel_id = -1;

static int hf_docsis_mdd_upstream_frequency_range = -1;

static int hf_docsis_mdd_symbol_clock_locking_indicator = -1;

static int hf_docsis_mdd_event_type = -1;

static int hf_docsis_mdd_maximum_event_holdoff_timer = -1;

static int hf_docsis_mdd_maximum_number_of_reports_per_event = -1;
static int hf_docsis_mdd_upstream_transmit_power_reporting = -1;

static int hf_docsis_mdd_dsg_da_to_dsid_association_da = -1;
static int hf_docsis_mdd_dsg_da_to_dsid_association_dsid = -1;

static int hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_sequence_out_of_range = -1;
static int hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_operating_on_battery_backup = -1;
static int hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_returned_to_ac_power = -1;

static int hf_docsis_mdd_extended_upstream_transmit_power_support = -1;


/* Initialize the subtree pointers */
static gint ett_docsis_mdd = -1;
static gint ett_tlv = -1;
static gint ett_sub_tlv = -1;

static void
dissect_mdd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
	proto_item *it;
	proto_tree *mdd_tree;

	int pos;
	int subpos = 0;
	gint len;
	guint8 type, length;
	guint8 subtype, sublength;
	int i;

	proto_item *tlv_item;
	proto_tree *tlv_tree;

	proto_item *tlv_sub_item;
	proto_tree *tlv_sub_tree;
	proto_item *text_item;


	len = tvb_reported_length_remaining (tvb, 0);

	col_set_str(pinfo->cinfo, COL_INFO, "MDD Message:");

	if (tree)
	{
		it = proto_tree_add_protocol_format (tree, proto_docsis_mdd, tvb, 0, -1,"MDD Message");
		mdd_tree = proto_item_add_subtree (it, ett_docsis_mdd);

		proto_tree_add_item (mdd_tree, hf_docsis_mdd_ccc, tvb, 0, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item (mdd_tree, hf_docsis_mdd_number_of_fragments, tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item (mdd_tree, hf_docsis_mdd_fragment_sequence_number, tvb, 2, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item (mdd_tree, hf_docsis_mdd_current_channel_dcid, tvb, 3, 1, ENC_BIG_ENDIAN);

		/*TLVs...*/
		pos = 4;
		while (pos < len)
	  	{
			type = tvb_get_guint8 (tvb, pos);
			length = tvb_get_guint8 (tvb, pos + 1);
			tlv_item = proto_tree_add_text (mdd_tree, tvb, pos, length + 2,"%s", val_to_str(type, mdd_tlv_vals, "Unknown TLV (%u)"));
			tlv_tree = proto_item_add_subtree (tlv_item, ett_tlv);

			switch(type) {

				case DOWNSTREAM_ACTIVE_CHANNEL_LIST:
					subpos = pos + 2;
					while (subpos < pos + length + 2) {
						subtype = tvb_get_guint8 (tvb, subpos);
						sublength = tvb_get_guint8 (tvb, subpos + 1);
						switch(subtype) {
							case DOWNSTREAM_ACTIVE_CHANNEL_LIST_CHANNEL_ID:
								proto_tree_add_item (tlv_tree, hf_docsis_mdd_downstream_active_channel_list_channel_id, tvb, subpos + 2 , 1, ENC_BIG_ENDIAN);
								break;
							case DOWNSTREAM_ACTIVE_CHANNEL_LIST_FREQUENCY:
								proto_tree_add_item (tlv_tree, hf_docsis_mdd_downstream_active_channel_list_frequency, tvb, subpos + 2 , 4, ENC_BIG_ENDIAN);
								break;
							case DOWNSTREAM_ACTIVE_CHANNEL_LIST_MODULATION_ORDER_ANNEX:
								tlv_sub_item = proto_tree_add_text (tlv_tree, tvb, subpos + 2, 1, "Modulation Order/Annex");
								tlv_sub_tree = proto_item_add_subtree (tlv_sub_item, ett_sub_tlv);
								proto_tree_add_item (tlv_sub_tree, hf_docsis_mdd_downstream_active_channel_list_modulation_order, tvb, subpos + 2 , 1, ENC_BIG_ENDIAN);
								proto_tree_add_item (tlv_sub_tree, hf_docsis_mdd_downstream_active_channel_list_annex, tvb, subpos + 2 , 1, ENC_BIG_ENDIAN);
								break;
							case DOWNSTREAM_ACTIVE_CHANNEL_LIST_PRIMARY_CAPABLE:
								proto_tree_add_item (tlv_tree, hf_docsis_mdd_downstream_active_channel_list_primary_capable, tvb, subpos + 2 , 1, ENC_BIG_ENDIAN);
								break;
							case DOWNSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK:
								tlv_sub_item = proto_tree_add_text (tlv_tree, tvb, subpos + 2, 2, "CM-STATUS Event Enable Bitmask");
								tlv_sub_tree = proto_item_add_subtree (tlv_sub_item, ett_sub_tlv);
								proto_tree_add_item (tlv_sub_tree, hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_timeout, tvb, subpos + 2 , 2,ENC_BIG_ENDIAN);
								proto_tree_add_item (tlv_sub_tree, hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_failure, tvb, subpos + 2 , 2, ENC_BIG_ENDIAN);
								proto_tree_add_item (tlv_sub_tree, hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_recovery, tvb, subpos + 2 , 2,ENC_BIG_ENDIAN);
								proto_tree_add_item (tlv_sub_tree, hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_recovery, tvb, subpos + 2 , 2, ENC_BIG_ENDIAN);
								break;
						}
						subpos += sublength + 2;
					}
					break;
				case MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP:
					subpos = pos + 2;
					while (subpos < pos + length + 2) {
						subtype = tvb_get_guint8 (tvb, subpos);
						sublength = tvb_get_guint8 (tvb, subpos + 1);
						switch(subtype) {
							case MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_MD_DS_SG_IDENTIFIER:
								proto_tree_add_item (tlv_tree, hf_docsis_mdd_mac_domain_downstream_service_group_md_ds_sg_identifier, tvb, subpos + 2 , 1, ENC_BIG_ENDIAN);
								break;
							case MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_CHANNEL_IDS:
								for (i = 0; i < sublength; i++) {
									proto_tree_add_item (tlv_tree, hf_docsis_mdd_mac_domain_downstream_service_group_channel_id, tvb, subpos + 2 + i , 1, ENC_BIG_ENDIAN);
								}
								break;
						}
						subpos += sublength + 2;
					}
					break;
				case DOWNSTREAM_AMBIGUITY_RESOLUTION_FREQUENCY_LIST:
					subpos = pos + 2;
					for (i = 0; i < length; i+=4) {
						proto_tree_add_item (tlv_tree, hf_docsis_mdd_downstream_ambiguity_resolution_frequency, tvb, subpos + i , 4, ENC_BIG_ENDIAN);
					}
					break;
				case RECEIVE_CHANNEL_PROFILE_REPORTING_CONTROL:
					subpos = pos + 2;
					while (subpos < pos + length + 2) {
						subtype = tvb_get_guint8 (tvb, subpos);
						sublength = tvb_get_guint8 (tvb, subpos + 1);
						switch(subtype) {
							case RCP_CENTER_FREQUENCY_SPACING:
								proto_tree_add_item (tlv_tree, hf_docsis_mdd_rpc_center_frequency_spacing, tvb, subpos + 2 , 1, ENC_BIG_ENDIAN);
								break;
							case VERBOSE_RCP_REPORTING:
								proto_tree_add_item (tlv_tree, hf_docsis_mdd_verbose_rcp_reporting, tvb, subpos + 2 , 1, ENC_BIG_ENDIAN);
								break;
						}
						subpos += sublength + 2;
					}
					break;
				case IP_INITIALIZATION_PARAMETERS:
					subpos = pos + 2;
					while (subpos < pos + length + 2) {
						subtype = tvb_get_guint8 (tvb, subpos);
						sublength = tvb_get_guint8 (tvb, subpos + 1);
						switch(subtype) {
							case IP_PROVISIONING_MODE:
								proto_tree_add_item (tlv_tree, hf_docsis_mdd_ip_provisioning_mode, tvb, subpos + 2 , 1, ENC_BIG_ENDIAN);
								break;
							case PRE_REGISTRATION_DSID:
								proto_tree_add_item (tlv_tree, hf_docsis_mdd_pre_registration_dsid, tvb, subpos + 2 , 3, ENC_BIG_ENDIAN);
								break;
						}
						subpos += sublength + 2;
					}
					break;
				case EARLY_AUTHENTICATION_AND_ENCRYPTION:
					subpos = pos + 2;
					proto_tree_add_item (tlv_tree, hf_docsis_mdd_early_authentication_and_encryption, tvb, subpos, 1, ENC_BIG_ENDIAN);
					break;
				case UPSTREAM_ACTIVE_CHANNEL_LIST:
					subpos = pos + 2;
					while (subpos < pos + length + 2) {
						subtype = tvb_get_guint8 (tvb, subpos);
						sublength = tvb_get_guint8 (tvb, subpos + 1);
						switch(subtype) {
							case UPSTREAM_ACTIVE_CHANNEL_LIST_UPSTREAM_CHANNEL_ID:
								proto_tree_add_item (tlv_tree, hf_docsis_mdd_upstream_active_channel_list_upstream_channel_id, tvb, subpos + 2 , 1, ENC_BIG_ENDIAN);
								break;
							case UPSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK:
								tlv_sub_item = proto_tree_add_text (tlv_tree, tvb, subpos + 2, 2, "CM-STATUS Event Enable Bitmask");
								tlv_sub_tree = proto_item_add_subtree (tlv_sub_item, ett_sub_tlv);
								proto_tree_add_item (tlv_sub_tree, hf_docsis_mdd_cm_status_event_enable_bitmask_t4_timeout, tvb, subpos + 2 , 2, ENC_BIG_ENDIAN);
								proto_tree_add_item (tlv_sub_tree, hf_docsis_mdd_cm_status_event_enable_bitmask_t3_retries_exceeded, tvb, subpos + 2 , 2, ENC_BIG_ENDIAN);
								proto_tree_add_item (tlv_sub_tree, hf_docsis_mdd_cm_status_event_enable_bitmask_successful_ranging_after_t3_retries_exceeded, tvb, subpos + 2 , 2, ENC_BIG_ENDIAN);
								break;
						}
						subpos += sublength + 2;
					}
					break;
				case UPSTREAM_AMBIGUITY_RESOLUTION_CHANNEL_LIST:
					sublength = tvb_get_guint8 (tvb, subpos + 1);
					for (i = 0; i < sublength; i++) {
						proto_tree_add_item (tlv_tree, hf_docsis_mdd_upstream_ambiguity_resolution_channel_list_channel_id, tvb, pos + 2 + i , 1, ENC_BIG_ENDIAN);
					}
					break;
				case UPSTREAM_FREQUENCY_RANGE:
					subpos = pos + 2;
					proto_tree_add_item (tlv_tree, hf_docsis_mdd_upstream_frequency_range, tvb, subpos, 1, ENC_BIG_ENDIAN);
					break;
				case SYMBOL_CLOCK_LOCKING_INDICATOR:
					subpos = pos + 2;
					proto_tree_add_item (tlv_tree, hf_docsis_mdd_symbol_clock_locking_indicator, tvb, subpos, 1, ENC_BIG_ENDIAN);
					break;
				case CM_STATUS_EVENT_CONTROL:
					subpos = pos + 2;
					while (subpos < pos + length + 2) {
						subtype = tvb_get_guint8 (tvb, subpos);
						sublength = tvb_get_guint8 (tvb, subpos + 1);
						switch(subtype) {
							case EVENT_TYPE_CODE:
								proto_tree_add_item (tlv_tree, hf_docsis_mdd_event_type, tvb, subpos+2, 1, ENC_BIG_ENDIAN);
								break;
							case MAXIMUM_EVENT_HOLDOFF_TIMER:
								text_item = proto_tree_add_item (tlv_tree, hf_docsis_mdd_maximum_event_holdoff_timer, tvb, subpos, 2, ENC_BIG_ENDIAN);
								proto_item_append_text(text_item, " (%d ms)", (256*tvb_get_guint8 (tvb, subpos) + tvb_get_guint8 (tvb, subpos + 1)) * 20);
								break;
							case MAXIMUM_NUMBER_OF_REPORTS_PER_EVENT:
								text_item = proto_tree_add_item (tlv_tree, hf_docsis_mdd_maximum_number_of_reports_per_event, tvb, subpos, 1, ENC_BIG_ENDIAN);
								if ( tvb_get_guint8 (tvb, subpos) == 0) {
									proto_item_append_text(text_item, " (Unlimited)");
								}
								break;
						}
						subpos += sublength + 2;
					}
					break;
				case UPSTREAM_TRANSMIT_POWER_REPORTING:
					subpos = pos + 2;
					proto_tree_add_item (tlv_tree, hf_docsis_mdd_upstream_transmit_power_reporting, tvb, subpos, 1, ENC_BIG_ENDIAN);
					break;
				case DSG_DA_TO_DSID_ASSOCIATION_ENTRY:
					subpos = pos + 2;
					while (subpos < pos + length + 2) {
						subtype = tvb_get_guint8 (tvb, subpos);
						sublength = tvb_get_guint8 (tvb, subpos + 1);
						switch(subtype) {
							case DSG_DA_TO_DSID_ASSOCIATION_DA:
								proto_tree_add_item (tlv_tree, hf_docsis_mdd_dsg_da_to_dsid_association_da, tvb, subpos + 2, 6, ENC_BIG_ENDIAN);
								break;
							case DSG_DA_TO_DSID_ASSOCIATION_DSID:
								proto_tree_add_item (tlv_tree, hf_docsis_mdd_dsg_da_to_dsid_association_dsid, tvb, subpos + 2, 3, ENC_BIG_ENDIAN);
								break;
						}
						subpos += sublength + 2;
					}
					break;
				case CM_STATUS_EVENT_ENABLE_NON_CHANNEL_SPECIFIC_EVENTS:
					subpos = pos + 2;
					tlv_sub_item = proto_tree_add_text (tlv_tree, tvb, subpos, 2, "CM-STATUS Event Enable Bitmask for Non-Channel-Specific Events");
					tlv_sub_tree = proto_item_add_subtree (tlv_sub_item, ett_sub_tlv);
					proto_tree_add_item (tlv_sub_tree, hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_sequence_out_of_range, tvb, subpos, 2,ENC_BIG_ENDIAN);
					proto_tree_add_item (tlv_sub_tree, hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_operating_on_battery_backup, tvb, subpos , 2,ENC_BIG_ENDIAN);
					proto_tree_add_item (tlv_sub_tree, hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_returned_to_ac_power, tvb, subpos , 2,ENC_BIG_ENDIAN);
					break;
				case EXTENDED_UPSTREAM_TRANSMIT_POWER_SUPPORT:
					subpos = pos + 2;
					proto_tree_add_item (tlv_tree, hf_docsis_mdd_extended_upstream_transmit_power_support, tvb, subpos, 1, ENC_BIG_ENDIAN);
					break;
			}
			pos += length + 2;
	  	}
	}				/* if(tree) */
}




/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


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
		{&hf_docsis_mdd_mac_domain_downstream_service_group_md_ds_sg_identifier,
		{"MD-DS-SG Identifier", "docsis_mdd.mac_domain_downstream_service_group_md_ds_sg_identifier",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Mdd Mac Domain Downstream Service Group MD-DS-SG Identifier", HFILL}
		},
		{&hf_docsis_mdd_downstream_ambiguity_resolution_frequency,
		{"Frequency", "docsis_mdd.downstream_ambiguity_resolution_frequency",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"Mdd Downstream Ambiguity Resolution frequency", HFILL}
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
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Mdd Maximum Number of Reports per Event", HFILL}
		},
		{&hf_docsis_mdd_upstream_transmit_power_reporting,
		{"Upstream Transmit Power Reporting", "docsis_mdd.upstream_transmit_power_reporting",
		FT_UINT8, BASE_DEC, VALS(upstream_transmit_power_reporting_vals), 0x0,
		"Mdd Upstream Transmit Power Reporting", HFILL}
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

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_docsis_mdd,
		&ett_tlv,
		&ett_sub_tlv
	};

	/* Register the protocol name and description */
	proto_docsis_mdd =
		proto_register_protocol ("DOCSIS Mac Domain Description",
					"DOCSIS Mdd", "docsis_mdd");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array (proto_docsis_mdd, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));

	register_dissector ("docsis_mdd", dissect_mdd, proto_docsis_mdd);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_mdd (void)
{
	dissector_handle_t docsis_mdd_handle;

	docsis_mdd_handle = find_dissector ("docsis_mdd");
	dissector_add_uint ("docsis_mgmt", 33, docsis_mdd_handle);
}
