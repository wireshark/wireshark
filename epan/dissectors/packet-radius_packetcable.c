/*
 * packet-radius_packetcable.c
 *
 * Routines for Packetcable's RADIUS AVPs dissection
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/sminmpec.h>

#include "packet-radius.h"



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

/* This is slightly ugly.  */
static int hf_packetcable_qos_desc_flags[] =
{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};
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
/* XXX - This should probably be combinde with the equivalent COPS code */
static void decode_packetcable_bcid (tvbuff_t *tvb, proto_tree *tree, int offset)
{
	guint8 packetcable_buf[64];

	proto_tree_add_item(tree, hf_packetcable_bcid_timestamp,
						tvb, offset, 4, ENC_BIG_ENDIAN);
	tvb_memcpy(tvb, packetcable_buf, offset + 4, 8); packetcable_buf[8] = '\0';
	proto_tree_add_text(tree, tvb, offset + 4, 8,
						"Element ID: %s", packetcable_buf);
	tvb_memcpy(tvb, packetcable_buf, offset + 13, 7); packetcable_buf[7] = '\0';
	proto_tree_add_text(tree, tvb, offset + 12, 8,
						"Time Zone: DST: %c, Offset: %s", tvb_get_guint8(tvb, offset + 12),
						packetcable_buf);
	proto_tree_add_item(tree, hf_packetcable_bcid_event_counter,
						tvb, offset + 20, 4, ENC_BIG_ENDIAN);
}

static const gchar* dissect_packetcable_em_hdr(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo _U_) {
	guint8 packetcable_buf[64];
	proto_item *ti;
	proto_tree *obj_tree;

	proto_tree_add_item(tree, hf_packetcable_em_header_version_id, tvb,  0, 2, ENC_BIG_ENDIAN);
	ti = proto_tree_add_text(tree, tvb,  2, 24, "BCID");
	obj_tree = proto_item_add_subtree(ti, ett_radius_vendor_packetcable_bcid);
	decode_packetcable_bcid(tvb, obj_tree,  2);

	proto_tree_add_item(tree, hf_packetcable_em_header_event_message_type, tvb,  26, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_em_header_element_type, tvb,  28, 2, ENC_BIG_ENDIAN);
	tvb_memcpy(tvb, packetcable_buf,  30, 8); packetcable_buf[8] = '\0';
	proto_tree_add_text(tree, tvb,  30, 8, "Element ID: %s", packetcable_buf );
	tvb_memcpy(tvb, packetcable_buf,  39, 7); packetcable_buf[7] = '\0';
	proto_tree_add_text(tree, tvb,  38, 8, "Time Zone: DST: %c, Offset: %s", tvb_get_guint8(tvb,  38), packetcable_buf);
	proto_tree_add_item(tree, hf_packetcable_em_header_sequence_number, tvb,  46, 4, ENC_BIG_ENDIAN);
	tvb_memcpy(tvb, packetcable_buf,  50, 18); packetcable_buf[18] = '\0';
	proto_tree_add_text(tree, tvb,  50, 18, "Event Time: %s", packetcable_buf);

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
	guint8 packetcable_buf[64];
	guint32 intval;
	guint32 packetcable_qos_flags = tvb_get_ntohl(tvb, 0);
	proto_item* ti = proto_tree_add_item(tree, hf_packetcable_qos_status, tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree* obj_tree = proto_item_add_subtree(ti, ett_radius_vendor_packetcable_qos_status);

	guint packetcable_qos_off = 20;

	proto_tree_add_item(obj_tree, hf_packetcable_qos_status_indication, tvb, 0, 4, ENC_BIG_ENDIAN);

	for (intval = 0; intval < PACKETCABLE_QOS_DESC_BITFIELDS; intval++) {
		proto_tree_add_item(obj_tree, hf_packetcable_qos_desc_flags[intval], tvb, 0, 4, FALSE);
	}

	tvb_memcpy(tvb, packetcable_buf, 4, 16);
	packetcable_buf[16] = '\0';

	proto_tree_add_text(tree, tvb, 4, 16, "Service Class Name: %s", packetcable_buf);

	for (intval = 0; intval < PACKETCABLE_QOS_DESC_BITFIELDS; intval++) {
		if (packetcable_qos_flags & packetcable_qos_desc_mask[intval]) {
			proto_tree_add_item(tree, hf_packetcable_qos_desc_fields[intval],
								tvb, packetcable_qos_off, 4, FALSE);
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
	guint8 packetcable_buf[64];

	tvb_memcpy(tvb, packetcable_buf, 0, 20); packetcable_buf[20] = '\0';
	proto_tree_add_text(tree, tvb, 0, 20,
						"Last-Redirecting-Party: %s", packetcable_buf);

	tvb_memcpy(tvb, packetcable_buf, 20, 20); packetcable_buf[20] = '\0';
	proto_tree_add_text(tree, tvb, 20, 20,
						"Original-Called-Party: %s", packetcable_buf);

	proto_tree_add_item(tree, hf_packetcable_redirected_from_info_number_of_redirections,
						tvb, 40, 2, ENC_BIG_ENDIAN);

	return "";
}

static const gchar* dissect_packetcable_time_electr_surv_ind(proto_tree* tree, tvbuff_t* tvb, packet_info *pinfo _U_) {

	if (tvb_length(tvb) == 0)
		return "None";

	proto_tree_add_item(tree, hf_packetcable_electronic_surveillance_indication_df_cdc_address,
						tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_electronic_surveillance_indication_df_ccc_address,
						tvb, 4, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_electronic_surveillance_indication_cdc_port,
						tvb, 8, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_packetcable_electronic_surveillance_indication_ccc_port,
						tvb, 10, 2, ENC_BIG_ENDIAN);
	proto_tree_add_text(tree, tvb, 12, tvb_length(tvb) - 12, "DF-DF-Key");

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
	guint8 bitmask = tvb_get_guint8(tvb, 2);
	guint intval = 1;
	proto_item* ti = proto_tree_add_item(tree, hf_packetcable_terminal_display_info_terminal_display_status_bitmask,
							 tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree* obj_tree = proto_item_add_subtree(ti, ett_packetcable_term_dsply);

	proto_tree_add_item(obj_tree, hf_packetcable_terminal_display_info_sbm_general_display,
						tvb, 0, 1, bitmask);
	proto_tree_add_item(obj_tree, hf_packetcable_terminal_display_info_sbm_calling_number,
						tvb, 0, 1, bitmask);
	proto_tree_add_item(obj_tree, hf_packetcable_terminal_display_info_sbm_calling_name,
						tvb, 0, 1, bitmask);
	proto_tree_add_item(obj_tree, hf_packetcable_terminal_display_info_sbm_message_waiting,
						tvb, 0, 1, bitmask);

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
		{ "Event Message Version ID","radius.vendor.pkt.emh.vid",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"PacketCable Event Message header version ID", HFILL }
		},
		{ &hf_packetcable_bcid_timestamp,
		{ "Timestamp","radius.vendor.pkt.bcid.ts",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable Event Message BCID Timestamp", HFILL }
		},
		{ &hf_packetcable_bcid_event_counter,
		{ "Event Counter","radius.vendor.pkt.bcid.ec",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable Event Message BCID Event Counter", HFILL }
		},
		{ &hf_packetcable_em_header_event_message_type,
		{ "Event Message Type","radius.vendor.pkt.emh.emt",
			FT_UINT16, BASE_DEC, radius_vendor_packetcable_event_message_vals, 0x0,
			"PacketCable Event Message Type", HFILL }
		},
		{ &hf_packetcable_em_header_element_type,
		{ "Element Type","radius.vendor.pkt.emh.et",
			FT_UINT16, BASE_DEC, packetcable_em_header_element_type_vals, 0x0,
			"PacketCable Event Message Element Type", HFILL }
		},
		{ &hf_packetcable_em_header_sequence_number,
		{ "Sequence Number","radius.vendor.pkt.emh.sn",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable Event Message Sequence Number", HFILL }
		},
		{ &hf_packetcable_em_header_status,
		{ "Status","radius.vendor.pkt.emh.st",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"PacketCable Event Message Status", HFILL }
		},
		{ &hf_packetcable_em_header_status_error_indicator,
		{ "Status","radius.vendor.pkt.emh.st.ei",
			FT_UINT32, BASE_HEX, packetcable_em_header_status_error_indicator_vals,
			PACKETCABLE_EMHS_EI_MASK,
			"PacketCable Event Message Status Error Indicator", HFILL }
		},
		{ &hf_packetcable_em_header_status_event_origin,
		{ "Event Origin","radius.vendor.pkt.emh.st.eo",
			FT_UINT32, BASE_HEX, packetcable_em_header_status_event_origin_vals,
			PACKETCABLE_EMHS_EO_MASK,
			"PacketCable Event Message Status Event Origin", HFILL }
		},
		{ &hf_packetcable_em_header_status_event_message_proxied,
		{ "Event Message Proxied","radius.vendor.pkt.emh.st.emp",
			FT_UINT32, BASE_HEX, packetcable_em_header_status_event_message_proxied_vals,
			PACKETCABLE_EMHS_EMP_MASK,
			"PacketCable Event Message Status Event Message Proxied", HFILL }
		},
		{ &hf_packetcable_em_header_priority,
		{ "Priority","radius.vendor.pkt.emh.priority",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"PacketCable Event Message Priority", HFILL }
		},
		{ &hf_packetcable_em_header_attribute_count,
		{ "Attribute Count","radius.vendor.pkt.emh.ac",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"PacketCable Event Message Attribute Count", HFILL }
		},
		{ &hf_packetcable_em_header_event_object,
		{ "Event Object","radius.vendor.pkt.emh.eo",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"PacketCable Event Message Event Object", HFILL }
		},
		{ &hf_packetcable_call_termination_cause_source_document,
		{ "Source Document","radius.vendor.pkt.ctc.sd",
			FT_UINT16, BASE_HEX, packetcable_call_termination_cause_vals, 0x0,
			"PacketCable Call Termination Cause Source Document", HFILL }
		},
		{ &hf_packetcable_call_termination_cause_code,
		{ "Event Object","radius.vendor.pkt.ctc.cc",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable Call Termination Cause Code", HFILL }
		},
		{ &hf_packetcable_trunk_group_id_trunk_type,
		{ "Trunk Type","radius.vendor.pkt.tgid.tt",
			FT_UINT16, BASE_HEX, packetcable_trunk_type_vals, 0x0,
			"PacketCable Trunk Group ID Trunk Type", HFILL }
		},
		{ &hf_packetcable_trunk_group_id_trunk_number,
		{ "Event Object","radius.vendor.pkt.tgid.tn",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable Trunk Group ID Trunk Number", HFILL }
		},
		{ &hf_packetcable_qos_status,
		{ "QoS Status","radius.vendor.pkt.qs",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute QoS Status", HFILL }
		},
		{ &hf_packetcable_qos_status_indication,
		{ "Status Indication","radius.vendor.pkt.qs.si",
			FT_UINT32, BASE_DEC, packetcable_state_indication_vals, PACKETCABLE_QOS_STATE_INDICATION_MASK,
			"PacketCable QoS Descriptor Attribute QoS State Indication", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[0],
		{ "Service Flow Scheduling Type","radius.vendor.pkt.qs.flags.sfst",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_SERVICE_FLOW_SCHEDULING_TYPE_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Service Flow Scheduling Type", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[1],
		{ "Grant Interval","radius.vendor.pkt.qs.flags.gi",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_NOMINAL_GRANT_INTERVAL_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Grant Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[2],
		{ "Tolerated Grant Jitter","radius.vendor.pkt.qs.flags.tgj",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_TOLERATED_GRANT_JITTER_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Tolerated Grant Jitter", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[3],
		{ "Grants Per Interval","radius.vendor.pkt.qs.flags.gpi",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_GRANTS_PER_INTERVAL_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Grants Per Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[4],
		{ "Unsolicited Grant Size","radius.vendor.pkt.qs.flags.ugs",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_UNSOLICITED_GRANT_SIZE_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Unsolicited Grant Size", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[5],
		{ "Traffic Priority","radius.vendor.pkt.qs.flags.tp",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_TRAFFIC_PRIORITY_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Traffic Priority", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[6],
		{ "Maximum Sustained Rate","radius.vendor.pkt.qs.flags.msr",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MAXIMUM_SUSTAINED_RATE_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Maximum Sustained Rate", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[7],
		{ "Maximum Traffic Burst","radius.vendor.pkt.qs.flags.mtb",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MAXIMUM_TRAFFIC_BURST_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Maximum Traffic Burst", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[8],
		{ "Minimum Reserved Traffic Rate","radius.vendor.pkt.qs.flags.mrtr",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MINIMUM_RESERVED_TRAFFIC_RATE_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Minimum Reserved Traffic Rate", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[9],
		{ "Minimum Packet Size","radius.vendor.pkt.qs.flags.mps",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MINIMUM_PACKET_SIZE_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Minimum Packet Size", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[10],
		{ "Maximum Concatenated Burst","radius.vendor.pkt.qs.flags.mcb",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MAXIMUM_CONCATENATED_BURST_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Maximum Concatenated Burst", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[11],
		{ "Status Request/Transmission Policy","radius.vendor.pkt.qs.flags.srtp",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_REQUEST_TRANSMISSION_POLICY_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Status Request/Transmission Policy", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[12],
		{ "Nominal Polling Interval","radius.vendor.pkt.qs.flags.npi",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_NOMINAL_POLLING_INTERVAL_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Nominal Polling Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[13],
		{ "Tolerated Poll Jitter","radius.vendor.pkt.qs.flags.tpj",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_TOLERATED_POLL_JITTER_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Tolerated Poll Jitter", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[14],
		{ "Type of Service Override","radius.vendor.pkt.qs.flags.toso",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_IP_TYPE_OF_SERVICE_OVERRIDE_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Type of Service Override", HFILL }
		},
		{ &hf_packetcable_qos_desc_flags[15],
		{ "Maximum Downstream Latency","radius.vendor.pkt.qs.flags.mdl",
			FT_UINT32, BASE_DEC, NULL, PACKETCABLE_MAXIMUM_DOWNSTREAM_LATENCY_MASK,
			"PacketCable QoS Descriptor Attribute Bitmask: Maximum Downstream Latency", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[0],
		{ "Service Flow Scheduling Type","radius.vendor.pkt.qs.sfst",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Service Flow Scheduling Type", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[1],
		{ "Grant Interval","radius.vendor.pkt.qs.gi",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Grant Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[2],
		{ "Tolerated Grant Jitter","radius.vendor.pkt.qs.tgj",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Tolerated Grant Jitter", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[3],
		{ "Grants Per Interval","radius.vendor.pkt.qs.gpi",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Grants Per Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[4],
		{ "Unsolicited Grant Size","radius.vendor.pkt.qs.ugs",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Unsolicited Grant Size", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[5],
		{ "Traffic Priority","radius.vendor.pkt.qs.tp",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Traffic Priority", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[6],
		{ "Maximum Sustained Rate","radius.vendor.pkt.qs.msr",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Maximum Sustained Rate", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[7],
		{ "Maximum Traffic Burst","radius.vendor.pkt.qs.mtb",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Maximum Traffic Burst", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[8],
		{ "Minimum Reserved Traffic Rate","radius.vendor.pkt.qs.mrtr",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Minimum Reserved Traffic Rate", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[9],
		{ "Minimum Packet Size","radius.vendor.pkt.qs.mps",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Minimum Packet Size", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[10],
		{ "Maximum Concatenated Burst","radius.vendor.pkt.qs.mcb",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Maximum Concatenated Burst", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[11],
		{ "Status Request/Transmission Policy","radius.vendor.pkt.qs.srtp",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Status Request/Transmission Policy", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[12],
		{ "Nominal Polling Interval","radius.vendor.pkt.qs.npi",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Nominal Polling Interval", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[13],
		{ "Tolerated Poll Jitter","radius.vendor.pkt.qs.tpj",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Tolerated Poll Jitter", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[14],
		{ "Type of Service Override","radius.vendor.pkt.qs.toso",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Type of Service Override", HFILL }
		},
		{ &hf_packetcable_qos_desc_fields[15],
		{ "Maximum Downstream Latency","radius.vendor.pkt.qs.mdl",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"PacketCable QoS Descriptor Attribute Maximum Downstream Latency", HFILL }
		},
		{ &hf_packetcable_time_adjustment,
		{ "Time Adjustment","radius.vendor.pkt.ti",
			FT_UINT64, BASE_DEC, NULL, 0x0,
			"PacketCable Time Adjustment", HFILL }
		},
		{ &hf_packetcable_redirected_from_info_number_of_redirections,
		{ "Number-of-Redirections","radius.vendor.pkt.rfi.nr",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"PacketCable Redirected-From-Info Number-of-Redirections", HFILL }
		},
		{ &hf_packetcable_electronic_surveillance_indication_df_cdc_address,
		{ "DF_CDC_Address","radius.vendor.pkt.esi.dfcdca",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			"PacketCable Electronic-Surveillance-Indication DF_CDC_Address", HFILL }
		},
		{ &hf_packetcable_electronic_surveillance_indication_df_ccc_address,
		{ "DF_CDC_Address","radius.vendor.pkt.esi.dfccca",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			"PacketCable Electronic-Surveillance-Indication DF_CCC_Address", HFILL }
		},
		{ &hf_packetcable_electronic_surveillance_indication_cdc_port,
		{ "CDC-Port","radius.vendor.pkt.esi.cdcp",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"PacketCable Electronic-Surveillance-Indication CDC-Port", HFILL }
		},
		{ &hf_packetcable_electronic_surveillance_indication_ccc_port,
		{ "CCC-Port","radius.vendor.pkt.esi.cccp",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"PacketCable Electronic-Surveillance-Indication CCC-Port", HFILL }
		},

		{ &hf_packetcable_terminal_display_info_terminal_display_status_bitmask,
		{ "Terminal_Display_Status_Bitmask","radius.vendor.pkt.tdi.sbm",
			FT_UINT8, BASE_HEX, NULL, 0xff,
			"PacketCable Terminal_Display_Info Terminal_Display_Status_Bitmask", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_sbm_general_display,
		{ "General_Display","radius.vendor.pkt.tdi.sbm.gd",
			FT_BOOLEAN, 8, NULL, 0x01,
			"PacketCable Terminal_Display_Info Terminal_Display_Status_Bitmask General_Display", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_sbm_calling_number,
		{ "Calling_Number","radius.vendor.pkt.tdi.sbm.cnum",
			FT_BOOLEAN, 8, NULL, 0x02,
			"PacketCable Terminal_Display_Info Terminal_Display_Status_Bitmask Calling_Number", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_sbm_calling_name,
		{ "Calling_Name","radius.vendor.pkt.tdi.sbm.cname",
			FT_BOOLEAN, 8, NULL, 0x04,
			"PacketCable Terminal_Display_Info Terminal_Display_Status_Bitmask Calling_Name", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_sbm_message_waiting,
		{ "Message_Waiting","radius.vendor.pkt.tdi.sbm.mw",
			FT_BOOLEAN, 8, NULL, 0x08,
			"PacketCable Terminal_Display_Info Terminal_Display_Status_Bitmask Message_Waiting", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_general_display,
		{ "General_Display","radius.vendor.pkt.tdi.gd",
			FT_STRING, BASE_NONE, NULL, 0,
			"PacketCable Terminal_Display_Info General_Display", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_calling_number,
		{ "Calling_Number","radius.vendor.pkt.tdi.cnum",
			FT_STRING, BASE_NONE, NULL, 0,
			"PacketCable Terminal_Display_Info Calling_Number", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_calling_name,
		{ "Calling_Name","radius.vendor.pkt.tdi.cname",
			FT_STRING, BASE_NONE, NULL, 0,
			"PacketCable Terminal_Display_Info Calling_Name", HFILL }
		},
		{ &hf_packetcable_terminal_display_info_message_waiting,
		{ "Message_Waiting","radius.vendor.pkt.tdi.mw",
			FT_STRING, BASE_NONE, NULL, 0,
			"PacketCable Terminal_Display_Info Message_Waiting", HFILL }
		}
	};

	static gint *ett[] = {
		&ett_radius_vendor_packetcable_bcid,
		&ett_radius_vendor_packetcable_status,
		&ett_radius_vendor_packetcable_qos_status,
		&ett_packetcable_term_dsply
	};

	proto_packetcable = proto_register_protocol("PacketCable AVPs", "PACKETCABLE", "paketcable_avps");

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

