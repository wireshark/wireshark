/*
 * packet-radius_packetcable.c
 *
 * Routines for Packetcable's RADIUS AVPs dissection
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
 *
 */


/*
 * Some of the development of the RADIUS protocol decoder was sponsored by
 * Cable Television Laboratories, Inc. ("CableLabs") based upon proprietary
 * CableLabs' specifications. Your license and use of this protocol decoder
 * does not mean that you are licensed to use the CableLabs'
 * specifications.  If you have questions about this protocol, contact
 * jf.mule [AT] cablelabs.com or c.stuart [AT] cablelabs.com for additional
 * information.
 */

/*
  See:
       PacketCable(TM) 1.5 Specification: Event Messages [PKT-SP-EM1.5-I03-070412]
       PacketCable(TM) Specification: Multimedia Specification [PKT-SP-MM-I04-080522]
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/sminmpec.h>

#include "packet-radius.h"

void proto_register_packetcable(void);
void proto_reg_handoff_packetcable(void);

static int proto_packetcable = -1;

static int hf_packetcable_em_header_version_id = -1;
static int hf_packetcable_bcid_timestamp = -1;
static int hf_packetcable_bcid_event_counter = -1;
static int hf_packetcable_em_header_event_message_type = -1;
static int hf_packetcable_em_header_element_type = -1;
static int hf_packetcable_em_header_sequence_number = -1;
static int hf_packetcable_em_header_status = -1;
static int hf_packetcable_em_header_status_error_indicator = -1;
static int hf_packetcable_em_header_status_event_origin = -1;
static int hf_packetcable_em_header_status_event_message_proxied = -1;
static int hf_packetcable_em_header_priority = -1;
static int hf_packetcable_em_header_attribute_count = -1;
static int hf_packetcable_em_header_event_object = -1;
static int hf_packetcable_call_termination_cause_source_document = -1;
static int hf_packetcable_call_termination_cause_code = -1;
static int hf_packetcable_trunk_group_id_trunk_type = -1;
static int hf_packetcable_trunk_group_id_trunk_number = -1;
static int hf_packetcable_qos_status = -1;
static int hf_packetcable_qos_status_indication = -1;
static int hf_packetcable_time_adjustment = -1;
static int hf_packetcable_redirected_from_info_number_of_redirections = -1;
static int hf_packetcable_electronic_surveillance_indication_df_cdc_address = -1;
static int hf_packetcable_electronic_surveillance_indication_df_ccc_address = -1;
static int hf_packetcable_electronic_surveillance_indication_cdc_port = -1;
static int hf_packetcable_electronic_surveillance_indication_ccc_port = -1;
static int hf_packetcable_terminal_display_info_terminal_display_status_bitmask = -1;
static int hf_packetcable_terminal_display_info_sbm_general_display = -1;
static int hf_packetcable_terminal_display_info_sbm_calling_number = -1;
static int hf_packetcable_terminal_display_info_sbm_calling_name = -1;
static int hf_packetcable_terminal_display_info_sbm_message_waiting = -1;
static int hf_packetcable_terminal_display_info_general_display = -1;
static int hf_packetcable_terminal_display_info_calling_number = -1;
static int hf_packetcable_terminal_display_info_calling_name = -1;
static int hf_packetcable_terminal_display_info_message_waiting = -1;
static int hf_packetcable_qos_desc_flags_sfst = -1;
static int hf_packetcable_qos_desc_flags_gi = -1;
static int hf_packetcable_qos_desc_flags_tgj = -1;
static int hf_packetcable_qos_desc_flags_gpi = -1;
static int hf_packetcable_qos_desc_flags_ugs = -1;
static int hf_packetcable_qos_desc_flags_tp = -1;
static int hf_packetcable_qos_desc_flags_msr = -1;
static int hf_packetcable_qos_desc_flags_mtb = -1;
static int hf_packetcable_qos_desc_flags_mrtr = -1;
static int hf_packetcable_qos_desc_flags_mps = -1;
static int hf_packetcable_qos_desc_flags_mcb = -1;
static int hf_packetcable_qos_desc_flags_srtp = -1;
static int hf_packetcable_qos_desc_flags_npi = -1;
static int hf_packetcable_qos_desc_flags_tpj = -1;
static int hf_packetcable_qos_desc_flags_toso = -1;
static int hf_packetcable_qos_desc_flags_mdl = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_packetcable_bcid_time_zone_offset = -1;
static int hf_packetcable_bcid_element_id = -1;
static int hf_packetcable_electronic_surveillance_indication_df_df_key = -1;
static int hf_packetcable_redirected_from_original_called_party = -1;
static int hf_packetcable_em_header_element_id = -1;
static int hf_packetcable_redirected_from_last_redirecting_party = -1;
static int hf_packetcable_bcid_time_zone_dst = -1;
static int hf_packetcable_em_header_time_zone_offset = -1;
static int hf_packetcable_qos_service_class_name = -1;
static int hf_packetcable_em_header_event_time = -1;
static int hf_packetcable_em_header_time_zone_dst = -1;

/* This is slightly ugly.  */
static int hf_packetcable_qos_desc_fields[] =
{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};


static gint ett_radius_vendor_packetcable_bcid = -1;
static gint ett_radius_vendor_packetcable_status = -1;
static gint ett_radius_vendor_packetcable_qos_status = -1;
static gint ett_packetcable_term_dsply = -1;


#define PACKETCABLE_QOS_STATE_INDICATION_MASK 0X0003
#define PACKETCABLE_SERVICE_FLOW_SCHEDULING_TYPE_MASK  (1 << 2)
#define PACKETCABLE_NOMINAL_GRANT_INTERVAL_MASK        (1 << 3)
#define PACKETCABLE_TOLERATED_GRANT_JITTER_MASK        (1 << 4)
#define PACKETCABLE_GRANTS_PER_INTERVAL_MASK   (1 << 5)
#define PACKETCABLE_UNSOLICITED_GRANT_SIZE_MASK        (1 << 6)
#define PACKETCABLE_TRAFFIC_PRIORITY_MASK      (1 << 7)
#define PACKETCABLE_MAXIMUM_SUSTAINED_RATE_MASK        (1 << 8)
#define PACKETCABLE_MAXIMUM_TRAFFIC_BURST_MASK (1 << 9)
#define PACKETCABLE_MINIMUM_RESERVED_TRAFFIC_RATE_MASK (1 << 10)
#define PACKETCABLE_MINIMUM_PACKET_SIZE_MASK   (1 << 11)
#define PACKETCABLE_MAXIMUM_CONCATENATED_BURST_MASK    (1 << 12)
#define PACKETCABLE_REQUEST_TRANSMISSION_POLICY_MASK   (1 << 13)
#define PACKETCABLE_NOMINAL_POLLING_INTERVAL_MASK      (1 << 14)
#define PACKETCABLE_TOLERATED_POLL_JITTER_MASK (1 << 15)
#define PACKETCABLE_IP_TYPE_OF_SERVICE_OVERRIDE_MASK   (1 << 16)
#define PACKETCABLE_MAXIMUM_DOWNSTREAM_LATENCY_MASK    (1 << 17)

#define PACKETCABLE_QOS_DESC_BITFIELDS 16

#define PACKETCABLE_EMHS_EI_MASK 0X0003
#define PACKETCABLE_EMHS_EO_MASK 0X0004
#define PACKETCABLE_EMHS_EMP_MASK 0X0008
#define PACKETCABLE_EMHS_RESERVED_MASK 0Xfff0


static guint32 packetcable_qos_desc_mask[] =
{
	PACKETCABLE_SERVICE_FLOW_SCHEDULING_TYPE_MASK,
	PACKETCABLE_NOMINAL_GRANT_INTERVAL_MASK,
	PACKETCABLE_TOLERATED_GRANT_JITTER_MASK,
	PACKETCABLE_GRANTS_PER_INTERVAL_MASK,
	PACKETCABLE_UNSOLICITED_GRANT_SIZE_MASK,
	PACKETCABLE_TRAFFIC_PRIORITY_MASK,
	PACKETCABLE_MAXIMUM_SUSTAINED_RATE_MASK,
	PACKETCABLE_MAXIMUM_TRAFFIC_BURST_MASK,
	PACKETCABLE_MINIMUM_RESERVED_TRAFFIC_RATE_MASK,
	PACKETCABLE_MINIMUM_PACKET_SIZE_MASK,
	PACKETCABLE_MAXIMUM_CONCATENATED_BURST_MASK,
	PACKETCABLE_REQUEST_TRANSMISSION_POLICY_MASK,
	PACKETCABLE_NOMINAL_POLLING_INTERVAL_MASK,
	PACKETCABLE_TOLERATED_POLL_JITTER_MASK,
	PACKETCABLE_IP_TYPE_OF_SERVICE_OVERRIDE_MASK,
	PACKETCABLE_MAXIMUM_DOWNSTREAM_LATENCY_MASK
};

static const value_string radius_vendor_packetcable_event_message_vals[] =
{
	{0,  "Reserved"},
	{1,  "Signaling_Start"},
	{2,  "Signaling_Stop"},
	{3,  "Database_Query"},
	{4,  "Intelligent_Peripheral_Usage_Start"},
	{5,  "Intelligent_Peripheral_Usage_Stop"},
	{6,  "Service_Instance"},
	{7,  "QoS_Reserve"},
	{8,  "QoS_Release"},
	{9,  "Service_Activation"},
	{10, "Service_Deactivation"},
	{11,  "Media_Report"},
	{12,  "Signal_Instance"},
	{13, "Interconnect_(Signaling)_Start"},
	{14, "Interconnect_(Signaling)_Stop"},
	{15, "Call_Answer"},
	{16, "Call_Disconnect"},
	{17, "Time_Change"},
	{19, "QoS_Commit"},
	{20, "Media_Alive"},
	{31,  "Policy_Request"},
	{32,  "Policy_Delete"},
	{33,  "Policy_Update"},
	{0, NULL}
};

static const value_string packetcable_em_header_element_type_vals[] =
{
	{0,  "Reserved"},
	{1,  "CMS"},
	{2,  "CMTS"},
	{3,  "Media Gateway Controller"},
	{4,  "Policy Server"},
	{0, NULL}
};

static const value_string packetcable_em_header_status_error_indicator_vals[] =
{
	{0,  "No Error"},
	{1,  "Possible Error"},
	{2,  "Known Error"},
	{3,  "Reserved"},
	{0, NULL}
};

static const value_string packetcable_em_header_status_event_origin_vals[] =
{
	{0,  "Trusted Element"},
	{1,  "Untrusted Element"},
	{0, NULL}
};

static const value_string packetcable_em_header_status_event_message_proxied_vals[] =
{
	{0,  "Not proxied"},
	{1,  "Proxied"},
	{0, NULL}
};

static const value_string packetcable_call_termination_cause_vals[] =
{
	{0,  "Reserved"},
	{1,  "BAF"},
	{2,  "Reserved"},
	{0, NULL}
};

static const value_string packetcable_trunk_type_vals[] =
{
	{1,  "Not Used"},
	{2,  "Not Used"},
	{3,  "SS7 direct trunk group member"},
	{4,  "SS7 from IC to AT and SS7 from AT to EO"},
	{5,  "Not Used"},
	{6,  "SS7 from IC to AT and non-SS7 from AT to EO (terminating only)"},
	{9,  "Signaling type not specified"},
	{0, NULL}
};

static const value_string packetcable_state_indication_vals[] =
{
	{0,  "Illegal Value"},
	{1,  "Resource Reserved but not Activated"},
	{2,  "Resource Activated"},
	{3,  "Resource Reserved & Activated"},
	{ 0, NULL }
};


/* Decode a PacketCable BCID. */
/* XXX - This should probably be combined with the equivalent COPS code */
static void decode_packetcable_bcid (tvbuff_t *tvb, proto_tree *tree, int offset)
{

	proto_tree_add_item(tree, hf_packetcable_bcid_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_bcid_element_id, tvb, offset + 4, 8, ENC_ASCII|ENC_NA);
	proto_tree_add_item(tree, hf_packetcable_bcid_time_zone_dst, tvb, offset + 12, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_bcid_time_zone_offset, tvb, offset + 13, 7, ENC_ASCII|ENC_NA);
	proto_tree_add_item(tree, hf_packetcable_bcid_event_counter, tvb, offset + 20, 4, ENC_BIG_ENDIAN);
}

static const gchar* dissect_packetcable_em_hdr(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo _U_) {
	proto_item *ti;
	proto_tree *obj_tree;

	proto_tree_add_item(tree, hf_packetcable_em_header_version_id, tvb,  0, 2, ENC_BIG_ENDIAN);
	obj_tree = proto_tree_add_subtree(tree, tvb, 2, 24, ett_radius_vendor_packetcable_bcid, NULL, "BCID");
	decode_packetcable_bcid(tvb, obj_tree,  2);

	proto_tree_add_item(tree, hf_packetcable_em_header_event_message_type, tvb,  26, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_em_header_element_type, tvb,  28, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_em_header_element_id, tvb, 30, 8, ENC_ASCII|ENC_NA);
	proto_tree_add_item(tree, hf_packetcable_em_header_time_zone_dst, tvb, 38, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_em_header_time_zone_offset, tvb, 39, 7, ENC_ASCII|ENC_NA);
	proto_tree_add_item(tree, hf_packetcable_em_header_sequence_number, tvb,  46, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_em_header_event_time, tvb, 50, 18, ENC_ASCII|ENC_NA);

	ti = proto_tree_add_item(tree, hf_packetcable_em_header_status, tvb,  68, 4, ENC_BIG_ENDIAN);
	obj_tree = proto_item_add_subtree(ti, ett_radius_vendor_packetcable_status);
	proto_tree_add_item(obj_tree, hf_packetcable_em_header_status_error_indicator, tvb,  68, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(obj_tree, hf_packetcable_em_header_status_event_origin, tvb,  68, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(obj_tree, hf_packetcable_em_header_status_event_message_proxied, tvb,  68, 4, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_packetcable_em_header_priority, tvb,  72, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_em_header_attribute_count, tvb,  73, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_em_header_event_object, tvb,  75, 1, ENC_BIG_ENDIAN);
	return "";
}

static const gchar* dissect_packetcable_call_term_cause(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo _U_) {
	proto_tree_add_item(tree, hf_packetcable_call_termination_cause_source_document,
						tvb, 0, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_call_termination_cause_code,
						tvb, 2, 4, ENC_BIG_ENDIAN);

	return "";
}

static const gchar* dissect_packetcable_rel_call_billing_correlation(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo _U_) {
	decode_packetcable_bcid(tvb, tree, 0);
	return "";
}

static const gchar* dissect_packetcable_trunk_group_id(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo _U_) {
	proto_tree_add_item(tree, hf_packetcable_trunk_group_id_trunk_type,
						tvb, 0, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_trunk_group_id_trunk_number,
						tvb, 2, 4, ENC_BIG_ENDIAN);
	return "";
}

static const gchar* dissect_packetcable_qos_descriptor(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo _U_) {
	guint32 intval;
	guint32 packetcable_qos_flags = tvb_get_ntohl(tvb, 0);
	guint packetcable_qos_off = 20;
	static const int * qos_flags[] = {
        &hf_packetcable_qos_status_indication,
		&hf_packetcable_qos_desc_flags_sfst,
		&hf_packetcable_qos_desc_flags_gi,
		&hf_packetcable_qos_desc_flags_tgj,
		&hf_packetcable_qos_desc_flags_gpi,
		&hf_packetcable_qos_desc_flags_ugs,
		&hf_packetcable_qos_desc_flags_tp,
		&hf_packetcable_qos_desc_flags_msr,
		&hf_packetcable_qos_desc_flags_mtb,
		&hf_packetcable_qos_desc_flags_mrtr,
		&hf_packetcable_qos_desc_flags_mps,
		&hf_packetcable_qos_desc_flags_mcb,
		&hf_packetcable_qos_desc_flags_srtp,
		&hf_packetcable_qos_desc_flags_npi,
		&hf_packetcable_qos_desc_flags_tpj,
		&hf_packetcable_qos_desc_flags_toso,
		&hf_packetcable_qos_desc_flags_mdl,
		NULL
	};

	proto_tree_add_bitmask(tree, tvb, 0, hf_packetcable_qos_status,
			       ett_radius_vendor_packetcable_qos_status, qos_flags, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_packetcable_qos_service_class_name, tvb, 4, 16, ENC_ASCII|ENC_NA);

	for (intval = 0; intval < PACKETCABLE_QOS_DESC_BITFIELDS; intval++) {
		if (packetcable_qos_flags & packetcable_qos_desc_mask[intval]) {
			proto_tree_add_item(tree, hf_packetcable_qos_desc_fields[intval],
								tvb, packetcable_qos_off, 4, ENC_BIG_ENDIAN);
			packetcable_qos_off += 4;
		}
	}

	return "";
}

static const gchar* dissect_packetcable_time_adjustment(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo _U_) {
	proto_tree_add_item(tree, hf_packetcable_time_adjustment, tvb, 0, 8, ENC_BIG_ENDIAN);

	return "";
}

static const gchar* dissect_packetcable_redirected_from_info(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo _U_) {

	proto_tree_add_item(tree, hf_packetcable_redirected_from_last_redirecting_party, tvb, 0, 20, ENC_ASCII|ENC_NA);

	proto_tree_add_item(tree, hf_packetcable_redirected_from_original_called_party, tvb, 20, 20, ENC_ASCII|ENC_NA);

	proto_tree_add_item(tree, hf_packetcable_redirected_from_info_number_of_redirections,
						tvb, 40, 2, ENC_BIG_ENDIAN);

	return "";
}

static const gchar* dissect_packetcable_time_electr_surv_ind(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo _U_) {

	if (tvb_reported_length(tvb) == 0)
		return "None";

	proto_tree_add_item(tree, hf_packetcable_electronic_surveillance_indication_df_cdc_address,
						tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_electronic_surveillance_indication_df_ccc_address,
						tvb, 4, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_electronic_surveillance_indication_cdc_port,
						tvb, 8, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_electronic_surveillance_indication_ccc_port,
						tvb, 10, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_electronic_surveillance_indication_df_df_key, tvb, 12, -1, ENC_NA);

	return "";
}

static const gchar* dissect_packetcable_surv_df_sec(proto_tree* tree _U_, tvbuff_t* tvb _U_, packet_info *pinfo _U_) {
		return "";
}

#define PACKETCABLE_GENERAL_DISPLAY (1 << 0)
#define PACKETCABLE_CALLING_NUMBER  (1 << 1)
#define PACKETCABLE_CALLING_NAME    (1 << 2)
#define PACKETCABLE_MESSAGE_WAITING (1 << 3)

static const gchar* dissect_packetcable_term_dsply_info(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo _U_) {
	/* XXX - this logic seems buggy because the offsets don't line up */
	guint8 bitmask = tvb_get_guint8(tvb, 2);
	guint intval = 1;
	static const int * flags[] = {
		&hf_packetcable_terminal_display_info_sbm_general_display,
		&hf_packetcable_terminal_display_info_sbm_calling_number,
		&hf_packetcable_terminal_display_info_sbm_calling_name,
		&hf_packetcable_terminal_display_info_sbm_message_waiting,
		NULL
	};

	proto_item* ti = proto_tree_add_bitmask_with_flags(tree, tvb, 0, hf_packetcable_terminal_display_info_terminal_display_status_bitmask,
										ett_packetcable_term_dsply, flags, ENC_NA, BMT_NO_APPEND|BMT_NO_FALSE);

	proto_tree* obj_tree = proto_item_add_subtree(ti, ett_packetcable_term_dsply);

	if (bitmask & PACKETCABLE_GENERAL_DISPLAY) {
		proto_tree_add_item(obj_tree, hf_packetcable_terminal_display_info_general_display,
							tvb, intval, 80, ENC_ASCII|ENC_NA);
		intval += 80;
	}

	if (bitmask & PACKETCABLE_CALLING_NUMBER) {
		proto_tree_add_item(obj_tree, hf_packetcable_terminal_display_info_calling_number,
							tvb, intval, 40, ENC_ASCII|ENC_NA);
		intval += 40;
	}

	if (bitmask & PACKETCABLE_CALLING_NAME) {
		proto_tree_add_item(obj_tree, hf_packetcable_terminal_display_info_calling_name,
							tvb, intval, 40, ENC_ASCII|ENC_NA);
		intval += 40;
	}

	if (bitmask & PACKETCABLE_MESSAGE_WAITING) {
		proto_tree_add_item(obj_tree, hf_packetcable_terminal_display_info_message_waiting,
							tvb, intval, 40, ENC_ASCII|ENC_NA);
	}

	return "";
}


void proto_register_packetcable(void) {

	static hf_register_info hf[] = {
		{ &hf_packetcable_em_header_version_id,
		{ "Event Message Version ID","packetcable_avps.emh.vid",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"PacketCable Event Message header version ID", HFILL }
		},
		{ &hf_packetcable_bcid_timestamp,
		{ "Timestamp","packetcable_avps.bcid.ts",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable Event Message BCID Timestamp", HFILL }
		},
		{ &hf_packetcable_bcid_event_counter,
		{ "Event Counter","packetcable_avps.bcid.ec",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable Event Message BCID Event Counter", HFILL }
		},
		{ &hf_packetcable_em_header_event_message_type,
		{ "Event Message Type","packetcable_avps.emh.emt",
			FT_UINT16, BASE_DEC, VALS(radius_vendor_packetcable_event_message_vals), 0x0,
			"PacketCable Event Message Type", HFILL }
		},
		{ &hf_packetcable_em_header_element_type,
		{ "Element Type","packetcable_avps.emh.et",
			FT_UINT16, BASE_DEC, VALS(packetcable_em_header_element_type_vals), 0x0,
			"PacketCable Event Message Element Type", HFILL }
		},
		{ &hf_packetcable_em_header_sequence_number,
		{ "Sequence Number","packetcable_avps.emh.sn",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable Event Message Sequence Number", HFILL }
		},
		{ &hf_packetcable_em_header_status,
		{ "Status","packetcable_avps.emh.st",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"PacketCable Event Message Status", HFILL }
		},
		{ &hf_packetcable_em_header_status_error_indicator,
		{ "Status","packetcable_avps.emh.st.ei",
			FT_UINT32, BASE_HEX, VALS(packetcable_em_header_status_error_indicator_vals),
			PACKETCABLE_EMHS_EI_MASK,
			"PacketCable Event Message Status Error Indicator", HFILL }
		},
		{ &hf_packetcable_em_header_status_event_origin,
		{ "Event Origin","packetcable_avps.emh.st.eo",
			FT_UINT32, BASE_HEX, VALS(packetcable_em_header_status_event_origin_vals),
			PACKETCABLE_EMHS_EO_MASK,
			"PacketCable Event Message Status Event Origin", HFILL }
		},
		{ &hf_packetcable_em_header_status_event_message_proxied,
		{ "Event Message Proxied","packetcable_avps.emh.st.emp",
			FT_UINT32, BASE_HEX, VALS(packetcable_em_header_status_event_message_proxied_vals),
			PACKETCABLE_EMHS_EMP_MASK,
			"PacketCable Event Message Status Event Message Proxied", HFILL }
		},
		{ &hf_packetcable_em_header_priority,
		{ "Priority","packetcable_avps.emh.priority",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"PacketCable Event Message Priority", HFILL }
		},
		{ &hf_packetcable_em_header_attribute_count,
		{ "Attribute Count","packetcable_avps.emh.ac",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"PacketCable Event Message Attribute Count", HFILL }
		},
		{ &hf_packetcable_em_header_event_object,
		{ "Event Object","packetcable_avps.emh.eo",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"PacketCable Event Message Event Object", HFILL }
		},
		{ &hf_packetcable_call_termination_cause_source_document,
		{ "Source Document","packetcable_avps.ctc.sd",
			FT_UINT16, BASE_HEX, VALS(packetcable_call_termination_cause_vals), 0x0,
			"PacketCable Call Termination Cause Source Document", HFILL }
		},
		{ &hf_packetcable_call_termination_cause_code,
		{ "Event Object","packetcable_avps.ctc.cc",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable Call Termination Cause Code", HFILL }
		},
		{ &hf_packetcable_trunk_group_id_trunk_type,
		{ "Trunk Type","packetcable_avps.tgid.tt",
			FT_UINT16, BASE_HEX, VALS(packetcable_trunk_type_vals), 0x0,
			"PacketCable Trunk Group ID Trunk Type", HFILL }
		},
		{ &hf_packetcable_trunk_group_id_trunk_number,
		{ "Event Object","packetcable_avps.tgid.tn",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable Trunk Group ID Trunk Number", HFILL }
		},
		{ &hf_packetcable_qos_status,
		{ "QoS Status","packetcable_avps.qs",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute QoS Status", HFILL }
		},
		{ &hf_packetcable_qos_status_indication,
		{ "Status Indication","packetcable_avps.qs.si",
			FT_UINT32, BASE_DEC, VALS(packetcable_state_indication_vals), PACKETCABLE_QOS_STATE_INDICATION_MASK,
			"PacketCable QoS Descriptor Attribute QoS State Indication", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags_sfst,
		{ "Service Flow Scheduling Type","packetcable_avps.qs.flags.sfst",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_SERVICE_FLOW_SCHEDULING_TYPE_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Service Flow Scheduling Type", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags_gi,
		{ "Grant Interval","packetcable_avps.qs.flags.gi",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_NOMINAL_GRANT_INTERVAL_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Grant Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags_tgj,
		{ "Tolerated Grant Jitter","packetcable_avps.qs.flags.tgj",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_TOLERATED_GRANT_JITTER_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Tolerated Grant Jitter", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags_gpi,
		{ "Grants Per Interval","packetcable_avps.qs.flags.gpi",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_GRANTS_PER_INTERVAL_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Grants Per Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags_ugs,
		{ "Unsolicited Grant Size","packetcable_avps.qs.flags.ugs",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_UNSOLICITED_GRANT_SIZE_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Unsolicited Grant Size", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags_tp,
		{ "Traffic Priority","packetcable_avps.qs.flags.tp",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_TRAFFIC_PRIORITY_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Traffic Priority", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags_msr,
		{ "Maximum Sustained Rate","packetcable_avps.qs.flags.msr",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MAXIMUM_SUSTAINED_RATE_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Maximum Sustained Rate", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags_mtb,
		{ "Maximum Traffic Burst","packetcable_avps.qs.flags.mtb",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MAXIMUM_TRAFFIC_BURST_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Maximum Traffic Burst", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags_mrtr,
		{ "Minimum Reserved Traffic Rate","packetcable_avps.qs.flags.mrtr",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MINIMUM_RESERVED_TRAFFIC_RATE_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Minimum Reserved Traffic Rate", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags_mps,
		{ "Minimum Packet Size","packetcable_avps.qs.flags.mps",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MINIMUM_PACKET_SIZE_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Minimum Packet Size", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags_mcb,
		{ "Maximum Concatenated Burst","packetcable_avps.qs.flags.mcb",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MAXIMUM_CONCATENATED_BURST_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Maximum Concatenated Burst", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags_srtp,
		{ "Status Request/Transmission Policy","packetcable_avps.qs.flags.srtp",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_REQUEST_TRANSMISSION_POLICY_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Status Request/Transmission Policy", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags_npi,
		{ "Nominal Polling Interval","packetcable_avps.qs.flags.npi",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_NOMINAL_POLLING_INTERVAL_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Nominal Polling Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags_tpj,
		{ "Tolerated Poll Jitter","packetcable_avps.qs.flags.tpj",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_TOLERATED_POLL_JITTER_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Tolerated Poll Jitter", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags_toso,
		{ "Type of Service Override","packetcable_avps.qs.flags.toso",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_IP_TYPE_OF_SERVICE_OVERRIDE_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Type of Service Override", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags_mdl,
		{ "Maximum Downstream Latency","packetcable_avps.qs.flags.mdl",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MAXIMUM_DOWNSTREAM_LATENCY_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Maximum Downstream Latency", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[0],
		{ "Service Flow Scheduling Type","packetcable_avps.qs.sfst",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Service Flow Scheduling Type", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[1],
		{ "Grant Interval","packetcable_avps.qs.gi",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Grant Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[2],
		{ "Tolerated Grant Jitter","packetcable_avps.qs.tgj",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Tolerated Grant Jitter", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[3],
		{ "Grants Per Interval","packetcable_avps.qs.gpi",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Grants Per Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[4],
		{ "Unsolicited Grant Size","packetcable_avps.qs.ugs",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Unsolicited Grant Size", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[5],
		{ "Traffic Priority","packetcable_avps.qs.tp",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Traffic Priority", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[6],
		{ "Maximum Sustained Rate","packetcable_avps.qs.msr",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Maximum Sustained Rate", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[7],
		{ "Maximum Traffic Burst","packetcable_avps.qs.mtb",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Maximum Traffic Burst", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[8],
		{ "Minimum Reserved Traffic Rate","packetcable_avps.qs.mrtr",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Minimum Reserved Traffic Rate", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[9],
		{ "Minimum Packet Size","packetcable_avps.qs.mps",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Minimum Packet Size", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[10],
		{ "Maximum Concatenated Burst","packetcable_avps.qs.mcb",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Maximum Concatenated Burst", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[11],
		{ "Status Request/Transmission Policy","packetcable_avps.qs.srtp",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Status Request/Transmission Policy", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[12],
		{ "Nominal Polling Interval","packetcable_avps.qs.npi",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Nominal Polling Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[13],
		{ "Tolerated Poll Jitter","packetcable_avps.qs.tpj",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Tolerated Poll Jitter", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[14],
		{ "Type of Service Override","packetcable_avps.qs.toso",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Type of Service Override", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[15],
		{ "Maximum Downstream Latency","packetcable_avps.qs.mdl",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Maximum Downstream Latency", HFILL }
		},
		{ &hf_packetcable_time_adjustment,
		{ "Time Adjustment","packetcable_avps.ti",
			FT_UINT64, BASE_DEC, NULL, 0x0,
			"PacketCable Time Adjustment", HFILL }
		},
		{ &hf_packetcable_redirected_from_info_number_of_redirections,
		{ "Number-of-Redirections","packetcable_avps.rfi.nr",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"PacketCable Redirected-From-Info Number-of-Redirections", HFILL }
		},
		{ &hf_packetcable_electronic_surveillance_indication_df_cdc_address,
		{ "DF_CDC_Address","packetcable_avps.esi.dfcdca",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			"PacketCable Electronic-Surveillance-Indication DF_CDC_Address", HFILL }
		},
		{ &hf_packetcable_electronic_surveillance_indication_df_ccc_address,
		{ "DF_CDC_Address","packetcable_avps.esi.dfccca",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			"PacketCable Electronic-Surveillance-Indication DF_CCC_Address", HFILL }
		},
		{ &hf_packetcable_electronic_surveillance_indication_cdc_port,
		{ "CDC-Port","packetcable_avps.esi.cdcp",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"PacketCable Electronic-Surveillance-Indication CDC-Port", HFILL }
		},
		{ &hf_packetcable_electronic_surveillance_indication_ccc_port,
		{ "CCC-Port","packetcable_avps.esi.cccp",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"PacketCable Electronic-Surveillance-Indication CCC-Port", HFILL }
		},

		{ &hf_packetcable_terminal_display_info_terminal_display_status_bitmask,
		{ "Terminal_Display_Status_Bitmask","packetcable_avps.tdi.sbm",
			FT_UINT8, BASE_HEX, NULL, 0xff,
			"PacketCable Terminal_Display_Info Terminal_Display_Status_Bitmask", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_sbm_general_display,
		{ "General_Display","packetcable_avps.tdi.sbm.gd",
			FT_BOOLEAN, 8, NULL, 0x01,
			"PacketCable Terminal_Display_Info Terminal_Display_Status_Bitmask General_Display", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_sbm_calling_number,
		{ "Calling_Number","packetcable_avps.tdi.sbm.cnum",
			FT_BOOLEAN, 8, NULL, 0x02,
			"PacketCable Terminal_Display_Info Terminal_Display_Status_Bitmask Calling_Number", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_sbm_calling_name,
		{ "Calling_Name","packetcable_avps.tdi.sbm.cname",
			FT_BOOLEAN, 8, NULL, 0x04,
			"PacketCable Terminal_Display_Info Terminal_Display_Status_Bitmask Calling_Name", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_sbm_message_waiting,
		{ "Message_Waiting","packetcable_avps.tdi.sbm.mw",
			FT_BOOLEAN, 8, NULL, 0x08,
			"PacketCable Terminal_Display_Info Terminal_Display_Status_Bitmask Message_Waiting", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_general_display,
		{ "General_Display","packetcable_avps.tdi.gd",
			FT_STRING, BASE_NONE, NULL, 0,
			"PacketCable Terminal_Display_Info General_Display", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_calling_number,
		{ "Calling_Number","packetcable_avps.tdi.cnum",
			FT_STRING, BASE_NONE, NULL, 0,
			"PacketCable Terminal_Display_Info Calling_Number", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_calling_name,
		{ "Calling_Name","packetcable_avps.tdi.cname",
			FT_STRING, BASE_NONE, NULL, 0,
			"PacketCable Terminal_Display_Info Calling_Name", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_message_waiting,
		{ "Message_Waiting","packetcable_avps.tdi.mw",
			FT_STRING, BASE_NONE, NULL, 0,
			"PacketCable Terminal_Display_Info Message_Waiting", HFILL }
		},
		/* Generated from convert_proto_tree_add_text.pl */
		{ &hf_packetcable_bcid_element_id, { "Element ID", "packetcable_avps.bcid.element_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_packetcable_bcid_time_zone_dst, { "Time Zone: DST", "packetcable_avps.bcid.time_zone.dst", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_packetcable_bcid_time_zone_offset, { "Time Zone: Offset", "packetcable_avps.bcid.time_zone.offset", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_packetcable_em_header_element_id, { "Element ID", "packetcable_avps.emh.element_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_packetcable_em_header_time_zone_dst, { "Time Zone: DST", "packetcable_avps.emh.time_zone.dst", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_packetcable_em_header_time_zone_offset, { "Time Zone: Offset", "packetcable_avps.emh.time_zone.offset", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_packetcable_em_header_event_time, { "Event Time", "packetcable_avps.emh.event_time", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_packetcable_qos_service_class_name, { "Service Class Name", "packetcable_avps.qs.sc_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_packetcable_redirected_from_last_redirecting_party, { "Last-Redirecting-Party", "packetcable_avps.rfi.last_redirecting_party", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_packetcable_redirected_from_original_called_party, { "Original-Called-Party", "packetcable_avps.rfi.original_called_party", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_packetcable_electronic_surveillance_indication_df_df_key, { "DF-DF-Key", "packetcable_avps.esi.df_df_key", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_radius_vendor_packetcable_bcid,
		&ett_radius_vendor_packetcable_status,
		&ett_radius_vendor_packetcable_qos_status,
		&ett_packetcable_term_dsply
	};

	proto_packetcable = proto_register_protocol("PacketCable AVPs", "PACKETCABLE", "packetcable_avps");

	proto_register_field_array(proto_packetcable, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_packetcable(void)
{

	radius_register_avp_dissector(VENDOR_CABLELABS, 1, dissect_packetcable_em_hdr);
	radius_register_avp_dissector(VENDOR_CABLELABS, 11, dissect_packetcable_call_term_cause);
	radius_register_avp_dissector(VENDOR_CABLELABS, 13, dissect_packetcable_rel_call_billing_correlation);
	radius_register_avp_dissector(VENDOR_CABLELABS, 24, dissect_packetcable_trunk_group_id);
	radius_register_avp_dissector(VENDOR_CABLELABS, 32, dissect_packetcable_qos_descriptor);
	radius_register_avp_dissector(VENDOR_CABLELABS, 38, dissect_packetcable_time_adjustment);
	radius_register_avp_dissector(VENDOR_CABLELABS, 43, dissect_packetcable_redirected_from_info);
	radius_register_avp_dissector(VENDOR_CABLELABS, 44, dissect_packetcable_time_electr_surv_ind);
	radius_register_avp_dissector(VENDOR_CABLELABS, 47, dissect_packetcable_surv_df_sec);
	radius_register_avp_dissector(VENDOR_CABLELABS, 54, dissect_packetcable_term_dsply_info);
/*	radius_register_avp_dissector(VENDOR_CABLELABS, 90, dissect_packetcable_party_info);
	radius_register_avp_dissector(VENDOR_CABLELABS, 91, dissect_packetcable_party_info);
	radius_register_avp_dissector(VENDOR_CABLELABS, 92, dissect_packetcable_party_info); */
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
