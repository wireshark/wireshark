/* packet-messageanalyzer.c
 * Routines for Message Analyzer capture dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/expert.h>
#include <wsutil/inet_ipv6.h>
#include <wsutil/utf8_entities.h>
#include <wiretap/wtap.h>

#include "packet-netmon.h"
#include "packet-windows-common.h"

void proto_register_message_analyzer(void);
void proto_reg_handoff_message_analyzer(void);

/* Initialize the protocol and registered fields */
static int proto_ma_wfp_capture_v4 = -1;
static int proto_ma_wfp_capture2_v4 = -1;
static int proto_ma_wfp_capture_v6 = -1;
static int proto_ma_wfp_capture2_v6 = -1;
static int proto_ma_wfp_capture_auth_v4 = -1;
static int proto_ma_wfp_capture_auth_v6 = -1;
static int proto_etw_wfp_capture = -1;
static int proto_etw_ndis = -1;

static int hf_ma_wfp_capture_flow_context = -1;
static int hf_ma_wfp_capture_payload_length = -1;
static int hf_ma_wfp_capture_auth_src_port = -1;
static int hf_ma_wfp_capture_auth_dst_port = -1;
static int hf_ma_wfp_capture_auth_interface_id = -1;
static int hf_ma_wfp_capture_auth_direction = -1;
static int hf_ma_wfp_capture_auth_process_id = -1;
static int hf_ma_wfp_capture_auth_process_path = -1;

static int hf_etw_wfp_capture_event_id = -1;
static int hf_etw_wfp_capture_driver_name = -1;
static int hf_etw_wfp_capture_major_version = -1;
static int hf_etw_wfp_capture_minor_version = -1;
static int hf_etw_wfp_capture_callout = -1;
static int hf_etw_wfp_capture_filter_id = -1;
static int hf_etw_wfp_capture_filter_weight = -1;
static int hf_etw_wfp_capture_driver_error_message = -1;
static int hf_etw_wfp_capture_nt_status = -1;
static int hf_etw_wfp_capture_callout_error_message = -1;

static int hf_etw_ndis_event_id = -1;
static int hf_etw_ndis_miniport_if_index = -1;
static int hf_etw_ndis_lower_if_index = -1;
static int hf_etw_ndis_fragment_size = -1;
static int hf_etw_ndis_fragment = -1;
static int hf_etw_ndis_metadata_size = -1;
static int hf_etw_ndis_metadata = -1;
static int hf_etw_ndis_source_port_id = -1;
static int hf_etw_ndis_source_port_name = -1;
static int hf_etw_ndis_source_nic_name = -1;
static int hf_etw_ndis_source_nic_type = -1;
static int hf_etw_ndis_destination_count = -1;
static int hf_etw_ndis_destination_port_id = -1;
static int hf_etw_ndis_destination_port_name = -1;
static int hf_etw_ndis_destination_nic_name = -1;
static int hf_etw_ndis_destination_nic_type = -1;
static int hf_etw_ndis_oob_data_size = -1;
static int hf_etw_ndis_oob_data = -1;
static int hf_etw_ndis_rules_count = -1;
static int hf_etw_ndis_friendly_name = -1;
static int hf_etw_ndis_unique_name = -1;
static int hf_etw_ndis_service_name = -1;
static int hf_etw_ndis_version = -1;
static int hf_etw_ndis_media_type = -1;
static int hf_etw_ndis_reference_context = -1;
static int hf_etw_ndis_rule_id = -1;
static int hf_etw_ndis_directive = -1;
static int hf_etw_ndis_value_length = -1;
static int hf_etw_ndis_value = -1;
static int hf_etw_ndis_error_code = -1;
static int hf_etw_ndis_location = -1;
static int hf_etw_ndis_context = -1;
static int hf_etw_ndis_previous_state = -1;
static int hf_etw_ndis_next_state = -1;
static int hf_etw_ndis_source_id = -1;
static int hf_etw_ndis_rundown_id = -1;
static int hf_etw_ndis_param1 = -1;
static int hf_etw_ndis_param2 = -1;
static int hf_etw_ndis_param_str = -1;
static int hf_etw_ndis_description = -1;
static int hf_etw_ndis_source_name = -1;
static int hf_etw_ndis_if_index = -1;
static int hf_etw_ndis_layer_count = -1;
static int hf_etw_ndis_layer_id = -1;
static int hf_etw_ndis_layer_name = -1;
static int hf_etw_ndis_keyword = -1;
static int hf_etw_ndis_keyword_ethernet8023 = -1;
static int hf_etw_ndis_keyword_reserved1 = -1;
static int hf_etw_ndis_keyword_wireless_wan = -1;
static int hf_etw_ndis_keyword_reserved2 = -1;
static int hf_etw_ndis_keyword_tunnel = -1;
static int hf_etw_ndis_keyword_native80211 = -1;
static int hf_etw_ndis_keyword_reserved3 = -1;
static int hf_etw_ndis_keyword_vmswitch = -1;
static int hf_etw_ndis_keyword_reserved4 = -1;
static int hf_etw_ndis_keyword_packet_start = -1;
static int hf_etw_ndis_keyword_packet_end = -1;
static int hf_etw_ndis_keyword_send_path = -1;
static int hf_etw_ndis_keyword_receive_path = -1;
static int hf_etw_ndis_keyword_l3_connect_path = -1;
static int hf_etw_ndis_keyword_l2_connect_path = -1;
static int hf_etw_ndis_keyword_close_path = -1;
static int hf_etw_ndis_keyword_authentication = -1;
static int hf_etw_ndis_keyword_configuration = -1;
static int hf_etw_ndis_keyword_global = -1;
static int hf_etw_ndis_keyword_dropped = -1;
static int hf_etw_ndis_keyword_pii_present = -1;
static int hf_etw_ndis_keyword_packet = -1;
static int hf_etw_ndis_keyword_address = -1;
static int hf_etw_ndis_keyword_std_template_hint = -1;
static int hf_etw_ndis_keyword_state_transition = -1;
static int hf_etw_ndis_keyword_reserved5 = -1;
static int hf_etw_ndis_packet_metadata_type = -1;
static int hf_etw_ndis_packet_metadata_revision = -1;
static int hf_etw_ndis_packet_metadata_size = -1;
static int hf_etw_ndis_packet_metadata_wifi_flags = -1;
static int hf_etw_ndis_packet_metadata_wifi_phytype = -1;
static int hf_etw_ndis_packet_metadata_wifi_channel = -1;
static int hf_etw_ndis_packet_metadata_wifi_mpdus_received = -1;
static int hf_etw_ndis_packet_metadata_wifi_mpdu_padding = -1;
static int hf_etw_ndis_packet_metadata_wifi_rssi = -1;
static int hf_etw_ndis_packet_metadata_wifi_datarate = -1;
static int hf_etw_ndis_packet_metadata_data = -1;
static int hf_etw_ndis_tcp_ip_checksum_net_buffer_list = -1;
static int hf_etw_ndis_ipsec_offload_v1_net_buffer_list_info = -1;
static int hf_etw_ndis_tcp_large_send_net_buffer_list_info = -1;
static int hf_etw_ndis_classification_handle_net_buffer_list_info = -1;
static int hf_etw_ndis_ieee8021q_net_buffer_list_info = -1;
static int hf_etw_ndis_net_buffer_cancel_id = -1;
static int hf_etw_ndis_media_specific_information = -1;
static int hf_etw_ndis_net_buffer_list_frame_type = -1;
static int hf_etw_ndis_net_buffer_list_hash_value = -1;
static int hf_etw_ndis_net_buffer_list_hash_info = -1;
static int hf_etw_ndis_wpf_net_buffer_list_info = -1;
static int hf_etw_ndis_max_net_buffer_list_info = -1;

/* Fields used from other common dissectors */
static int hf_ip_src = -1;
static int hf_ip_addr = -1;
static int hf_ip_src_host = -1;
static int hf_ip_host = -1;
static int hf_ip_dst = -1;
static int hf_ip_dst_host = -1;
static int hf_ip_proto = -1;
static int hf_ipv6_src = -1;
static int hf_ipv6_addr = -1;
static int hf_ipv6_src_host = -1;
static int hf_ipv6_host = -1;
static int hf_ipv6_dst = -1;
static int hf_ipv6_dst_host = -1;


/* Initialize the subtree pointers */
static gint ett_ma_wfp_capture_v4 = -1;
static gint ett_ma_wfp_capture_v6 = -1;
static gint ett_ma_wfp_capture_auth = -1;
static gint ett_etw_wfp_capture = -1;
static gint ett_etw_ndis = -1;
static gint ett_etw_ndis_dest = -1;
static gint ett_etw_ndis_layer = -1;
static gint ett_etw_ndis_keyword = -1;
static gint ett_etw_ndis_packet_metadata = -1;
static gint ett_etw_ndis_oob_data = -1;

static dissector_handle_t ma_wfp_capture_v4_handle;
static dissector_handle_t ma_wfp_capture2_v4_handle;
static dissector_handle_t ma_wfp_capture_v6_handle;
static dissector_handle_t ma_wfp_capture2_v6_handle;
static dissector_handle_t ma_wfp_capture_auth_v4_handle;
static dissector_handle_t ma_wfp_capture_auth_v6_handle;
static dissector_handle_t ip_handle;
static dissector_handle_t eth_handle;
static dissector_handle_t ieee80211_handle;

static dissector_table_t ip_dissector_table;

static void
add_ipv4_src_address(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, proto_item* parent_item)
{
	proto_item *item;
	guint32 addr;

	set_address_tvb(&pinfo->net_src, AT_IPv4, 4, tvb, offset);
	copy_address_shallow(&pinfo->src, &pinfo->net_src);

	if (tree) {
		const char *src_host;

		memcpy(&addr, pinfo->net_src.data, 4);
		src_host = get_hostname(addr);
		proto_item_append_text(parent_item, ", Src: %s", address_with_resolution_to_str(wmem_packet_scope(), &pinfo->net_src));

		proto_tree_add_ipv4(tree, hf_ip_src, tvb, offset, 4, addr);
		item = proto_tree_add_ipv4(tree, hf_ip_addr, tvb, offset, 4, addr);
		proto_item_set_hidden(item);

		item = proto_tree_add_string(tree, hf_ip_src_host, tvb, offset, 4, src_host);
		proto_item_set_generated(item);
		proto_item_set_hidden(item);

		item = proto_tree_add_string(tree, hf_ip_host, tvb, offset, 4, src_host);
		proto_item_set_generated(item);
		proto_item_set_hidden(item);
	}
}

static void
add_ipv4_dst_address(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, proto_item* parent_item)
{
	proto_item *item;
	guint32 addr;

	set_address_tvb(&pinfo->net_dst, AT_IPv4, 4, tvb, offset);
	copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

	if (tree) {
		const char *dst_host;

		memcpy(&addr, pinfo->net_dst.data, 4);
		dst_host = get_hostname(addr);
		proto_item_append_text(parent_item, ", Dst: %s", address_with_resolution_to_str(wmem_packet_scope(), &pinfo->net_dst));

		proto_tree_add_ipv4(tree, hf_ip_dst, tvb, offset, 4, addr);
		item = proto_tree_add_ipv4(tree, hf_ip_addr, tvb, offset, 4, addr);
		proto_item_set_hidden(item);

		item = proto_tree_add_string(tree, hf_ip_dst_host, tvb, offset, 4, dst_host);
		proto_item_set_generated(item);
		proto_item_set_hidden(item);

		item = proto_tree_add_string(tree, hf_ip_host, tvb, offset, 4, dst_host);
		proto_item_set_generated(item);
		proto_item_set_hidden(item);
	}
}

static void
add_ipv6_src_address(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
	proto_item *item;

	set_address_tvb(&pinfo->net_src, AT_IPv6, IPv6_ADDR_SIZE, tvb, offset);
	copy_address_shallow(&pinfo->src, &pinfo->net_src);

	if (tree) {
		const char *src_host;

		src_host = address_to_display(wmem_packet_scope(), &pinfo->net_src);

		proto_tree_add_item(tree, hf_ipv6_src, tvb, offset, IPv6_ADDR_SIZE, ENC_NA);
		item = proto_tree_add_item(tree, hf_ipv6_addr, tvb, offset, IPv6_ADDR_SIZE, ENC_NA);
		proto_item_set_hidden(item);

		item = proto_tree_add_string(tree, hf_ipv6_src_host, tvb, offset, IPv6_ADDR_SIZE, src_host);
		proto_item_set_generated(item);
		proto_item_set_hidden(item);

		item = proto_tree_add_string(tree, hf_ipv6_host, tvb, offset, IPv6_ADDR_SIZE, src_host);
		proto_item_set_generated(item);
		proto_item_set_hidden(item);
	}
}

static void
add_ipv6_dst_address(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
	proto_item *item;

	set_address_tvb(&pinfo->net_dst, AT_IPv6, IPv6_ADDR_SIZE, tvb, offset);
	copy_address_shallow(&pinfo->dst, &pinfo->net_dst);

	if (tree) {
		const char *dst_host;

		dst_host = address_to_display(wmem_packet_scope(), &pinfo->net_dst);

		proto_tree_add_item(tree, hf_ipv6_dst, tvb, offset, IPv6_ADDR_SIZE, ENC_NA);
		item = proto_tree_add_item(tree, hf_ipv6_addr, tvb, offset, IPv6_ADDR_SIZE, ENC_NA);
		proto_item_set_hidden(item);

		item = proto_tree_add_string(tree, hf_ipv6_dst_host, tvb, offset, IPv6_ADDR_SIZE, dst_host);
		proto_item_set_generated(item);
		proto_item_set_hidden(item);

		item = proto_tree_add_string(tree, hf_ipv6_host, tvb, offset, IPv6_ADDR_SIZE, dst_host);
		proto_item_set_generated(item);
		proto_item_set_hidden(item);
	}
}

static int
dissect_ma_wfp_capture_v4_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int proto)
{
	proto_item *ti;
	proto_tree *wfp_tree;
	int offset = 0;
	guint32 ip_proto, payload_length;
	tvbuff_t *next_tvb;

	ti = proto_tree_add_item(tree, proto, tvb, 0, -1, ENC_NA);
	wfp_tree = proto_item_add_subtree(ti, ett_ma_wfp_capture_v4);

	add_ipv4_src_address(wfp_tree, tvb, pinfo, offset, ti);
	offset += 4;

	add_ipv4_dst_address(wfp_tree, tvb, pinfo, offset, ti);
	offset += 4;

	proto_tree_add_item_ret_uint(wfp_tree, hf_ip_proto, tvb, offset, 1, ENC_NA, &ip_proto);
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s (%u)", ipprotostr(ip_proto), ip_proto);
	offset += 1;

	if (proto == proto_ma_wfp_capture2_v4)
	{
		proto_tree_add_item(wfp_tree, hf_ma_wfp_capture_flow_context, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
	}

	proto_tree_add_item_ret_uint(wfp_tree, hf_ma_wfp_capture_payload_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &payload_length);
	offset += 2;

	proto_item_set_len(ti, offset);

	next_tvb = tvb_new_subset_remaining(tvb, offset);

	if (!dissector_try_uint_new(ip_dissector_table, ip_proto, next_tvb, pinfo, tree, TRUE, NULL)) {
		call_data_dissector(next_tvb, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

static int
dissect_ma_wfp_capture_v4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MA WFP Capture v4");
	col_clear(pinfo->cinfo, COL_INFO);

	return dissect_ma_wfp_capture_v4_common(tvb, pinfo, tree, proto_ma_wfp_capture_v4);
}

static int
dissect_ma_wfp_capture2_v4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MA WFP Capture2 v4");
	col_clear(pinfo->cinfo, COL_INFO);

	return dissect_ma_wfp_capture_v4_common(tvb, pinfo, tree, proto_ma_wfp_capture2_v4);
}

static int
dissect_ma_wfp_capture_v6_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int proto)
{
	proto_item *ti;
	proto_tree *wfp_tree;
	int offset = 0;
	guint32 ip_proto, payload_length;
	tvbuff_t *next_tvb;

	ti = proto_tree_add_item(tree, proto, tvb, 0, -1, ENC_NA);
	wfp_tree = proto_item_add_subtree(ti, ett_ma_wfp_capture_v4);

	add_ipv6_src_address(wfp_tree, tvb, pinfo, offset);
	offset += IPv6_ADDR_SIZE;

	add_ipv6_dst_address(wfp_tree, tvb, pinfo, offset);
	offset += IPv6_ADDR_SIZE;

	proto_tree_add_item_ret_uint(wfp_tree, hf_ip_proto, tvb, offset, 1, ENC_NA, &ip_proto);
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s (%u)", ipprotostr(ip_proto), ip_proto);
	offset += 1;

	if (proto == proto_ma_wfp_capture2_v6)
	{
		proto_tree_add_item(wfp_tree, hf_ma_wfp_capture_flow_context, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
	}

	proto_tree_add_item_ret_uint(wfp_tree, hf_ma_wfp_capture_payload_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &payload_length);
	offset += 2;

	next_tvb = tvb_new_subset_remaining(tvb, offset);

	proto_item_set_len(ti, offset);

	if (!dissector_try_uint_new(ip_dissector_table, ip_proto, next_tvb, pinfo, tree, TRUE, NULL)) {
		call_data_dissector(next_tvb, pinfo, tree);
	}

	return tvb_captured_length(tvb);
}

static int
dissect_ma_wfp_capture_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MA WFP Capture v6");
	col_clear(pinfo->cinfo, COL_INFO);

	return dissect_ma_wfp_capture_v6_common(tvb, pinfo, tree, proto_ma_wfp_capture_v6);
}

static int
dissect_ma_wfp_capture2_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MA WFP Capture2 v6");
	col_clear(pinfo->cinfo, COL_INFO);

	return dissect_ma_wfp_capture_v6_common(tvb, pinfo, tree, proto_ma_wfp_capture2_v6);
}

static int
dissect_ma_wfp_capture_auth_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int proto)
{
	proto_item *ti;
	proto_tree *wfp_tree;
	int offset = 0;
	guint32 length, ip_proto;

	ti = proto_tree_add_item(tree, proto, tvb, 0, -1, ENC_NA);
	wfp_tree = proto_item_add_subtree(ti, ett_ma_wfp_capture_auth);

	if (proto == proto_ma_wfp_capture_auth_v4)
	{
		add_ipv4_src_address(wfp_tree, tvb, pinfo, offset, ti);
		offset += 4;
	}
	else
	{
		add_ipv6_src_address(wfp_tree, tvb, pinfo, offset);
		offset += IPv6_ADDR_SIZE;
	}

	if (proto == proto_ma_wfp_capture_auth_v4)
	{
		add_ipv4_dst_address(wfp_tree, tvb, pinfo, offset, ti);
		offset += 4;
	}
	else
	{
		add_ipv6_dst_address(wfp_tree, tvb, pinfo, offset);
		offset += IPv6_ADDR_SIZE;
	}

	proto_tree_add_item_ret_uint(wfp_tree, hf_ma_wfp_capture_auth_src_port, tvb, offset, 2, ENC_LITTLE_ENDIAN, &pinfo->srcport);
	offset += 2;
	proto_tree_add_item_ret_uint(wfp_tree, hf_ma_wfp_capture_auth_dst_port, tvb, offset, 2, ENC_LITTLE_ENDIAN, &pinfo->destport);
	offset += 2;
	col_add_fstr(pinfo->cinfo, COL_INFO, "%d %s %d", pinfo->srcport, UTF8_RIGHTWARDS_ARROW, pinfo->destport);

	proto_tree_add_item(wfp_tree, hf_ma_wfp_capture_auth_interface_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;
	proto_tree_add_item(wfp_tree, hf_ma_wfp_capture_auth_direction, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item_ret_uint(wfp_tree, hf_ip_proto, tvb, offset, 1, ENC_LITTLE_ENDIAN, &ip_proto);
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s (%u)", ipprotostr(ip_proto), ip_proto);
	offset += 1;

	proto_tree_add_item(wfp_tree, hf_ma_wfp_capture_flow_context, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;
	proto_tree_add_item(wfp_tree, hf_ma_wfp_capture_auth_process_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;
	proto_tree_add_item_ret_length(wfp_tree, hf_ma_wfp_capture_auth_process_path, tvb, offset, 2, ENC_LITTLE_ENDIAN|ENC_UTF_16, &length);
	offset += length;

	proto_item_set_len(ti, offset);

	return tvb_captured_length(tvb);
}

static int
dissect_ma_wfp_capture_auth_v4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MA WFP Capture AUTH v4");
	col_clear(pinfo->cinfo, COL_INFO);

	return dissect_ma_wfp_capture_auth_common(tvb, pinfo, tree, proto_ma_wfp_capture_auth_v4);
}

static int
dissect_ma_wfp_capture_auth_v6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MA WFP Capture AUTH v6");
	col_clear(pinfo->cinfo, COL_INFO);

	return dissect_ma_wfp_capture_auth_common(tvb, pinfo, tree, proto_ma_wfp_capture_auth_v6);
}

static const value_string etw_wfp_capture_event_vals[] = {
	{ 10001, "DriverLoad"},
	{ 10002, "DriverUnload"},
	{ 10003, "CalloutRegister"},
	{ 10004, "CalloutUnregister"},
	{ 10005, "CalloutNotifyFilterAdd"},
	{ 10006, "CalloutNotifyFilterDelete"},
	{ 20001, "DriverLoadError"},
	{ 20002, "DriverUnloadError"},
	{ 20003, "CalloutRegisterError"},
	{ 20004, "CalloutUnregisterError"},
	{ 20005, "CalloutClassifyError"},
	{ 60011, "TransportMessageV4"},
	{ 60012, "TransportMessage2V4"},
	{ 60021, "TransportMessageV6"},
	{ 60022, "TransportMessage2V6"},
	{ 60031, "AleAuthMessageV4"},
	{ 60041, "AleAuthMessageV6"},
	{ 60050, "Discard"},
	{ 0,	NULL }
};

static const value_string etw_wfp_capture_callout_vals[] = {
	{ 0, "CALLOUT_INBOUND_TRANSPORT_V4"},
	{ 1, "CALLOUT_OUTBOUND_TRANSPORT_V4"},
	{ 2, "CALLOUT_OUTBOUND_TRANSPORT_V6"},
	{ 3, "CALLOUT_ALE_AUTH_CONNECT_V4"},
	{ 4, "CALLOUT_ALE_AUTH_CONNECT_V6"},
	{ 5, "CALLOUT_ALE_AUTH_RECV_ACCEPT_V4"},
	{ 6, "CALLOUT_ALE_AUTH_RECV_ACCEPT_V6"},
	{ 7, "CALLOUT_INBOUND_IPPACKET_V4_DISCARD"},
	{ 8, "CALLOUT_INBOUND_IPPACKET_V6_DISCARD"},
	{ 9, "CALLOUT_OUTBOUND_IPPACKET_V4_DISCARD"},
	{ 10, "CALLOUT_OUTBOUND_IPPACKET_V6_DISCARD"},
	{ 11, "CALLOUT_IPFORWARD_V4_DISCARD"},
	{ 12, "CALLOUT_IPFORWARD_V6_DISCARD"},
	{ 13, "CALLOUT_INBOUND_TRANSPORT_V4_DISCARD"},
	{ 14, "CALLOUT_INBOUND_TRANSPORT_V6_DISCARD"},
	{ 15, "CALLOUT_OUTBOUND_TRANSPORT_V4_DISCARD"},
	{ 16, "CALLOUT_OUTBOUND_TRANSPORT_V6_DISCARD"},
	{ 17, "CALLOUT_DATAGRAM_DATA_V4_DISCARD"},
	{ 18, "CALLOUT_DATAGRAM_DATA_V6_DISCARD"},
	{ 19, "CALLOUT_INBOUND_ICMP_ERROR_V4_DISCARD"},
	{ 20, "CALLOUT_INBOUND_ICMP_ERROR_V6_DISCARD"},
	{ 21, "CALLOUT_OUTBOUND_ICMP_ERROR_V4_DISCARD"},
	{ 22, "CALLOUT_OUTBOUND_ICMP_ERROR_V6_DISCARD"},
	{ 23, "CALLOUT_ALE_RESOURCE_ASSIGNMENT_V4_DISCARD"},
	{ 24, "CALLOUT_ALE_RESOURCE_ASSIGNMENT_V6_DISCARD"},
	{ 25, "CALLOUT_ALE_AUTH_LISTEN_V4_DISCARD"},
	{ 26, "CALLOUT_ALE_AUTH_LISTEN_V6_DISCARD"},
	{ 27, "CALLOUT_ALE_AUTH_RECV_ACCEPT_V4_DISCARD"},
	{ 28, "CALLOUT_ALE_AUTH_RECV_ACCEPT_V6_DISCARD"},
	{ 29, "CALLOUT_ALE_AUTH_CONNECT_V4_DISCARD"},
	{ 30, "CALLOUT_ALE_AUTH_CONNECT_V6_DISCARD"},
	{ 31, "CALLOUT_ALE_FLOW_ESTABLISHED_V4_DISCARD"},
	{ 32, "CALLOUT_ALE_FLOW_ESTABLISHED_V6_DISCARD"},
	{ 0, NULL }
};

static int
dissect_etw_wfp_capture(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	proto_item *ti, *generated;
	proto_tree *etw_tree;
	int offset = 0;
	struct netmon_provider_id_data *provider_id_data = (struct netmon_provider_id_data*)data;
	guint length;

	DISSECTOR_ASSERT(provider_id_data != NULL);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETW WFP Capture");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_etw_wfp_capture, tvb, 0, -1, ENC_NA);
	etw_tree = proto_item_add_subtree(ti, ett_etw_wfp_capture);

	generated = proto_tree_add_uint(etw_tree, hf_etw_wfp_capture_event_id, tvb, 0, 0, provider_id_data->event_id);
	proto_item_set_generated(generated);
	col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(provider_id_data->event_id, etw_wfp_capture_event_vals, "Unknown"));

	switch (provider_id_data->event_id)
	{
	case 10001: // DriverLoad
	case 10002: // DriverUnload
		length = tvb_unicode_strsize(tvb, offset);
		proto_tree_add_item(etw_tree, hf_etw_wfp_capture_driver_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
		offset += length;
		proto_tree_add_item(etw_tree, hf_etw_wfp_capture_major_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(etw_tree, hf_etw_wfp_capture_minor_version, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		break;

	case 10003: // CalloutRegister
	case 10004: // CalloutUnregister
		proto_tree_add_item(etw_tree, hf_etw_wfp_capture_callout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		break;

	case 10005: // CalloutNotifyFilterAdd
	case 10006: // CalloutNotifyFilterDelete
		proto_tree_add_item(etw_tree, hf_etw_wfp_capture_filter_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
		proto_tree_add_item(etw_tree, hf_etw_wfp_capture_callout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(etw_tree, hf_etw_wfp_capture_filter_weight, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
		break;

	case 20001: // DriverLoadError
	case 20002: // DriverUnloadError
		length = tvb_unicode_strsize(tvb, offset);
		proto_tree_add_item(etw_tree, hf_etw_wfp_capture_driver_error_message, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
		offset += length;
		proto_tree_add_item(etw_tree, hf_etw_wfp_capture_nt_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		break;

	case 20003: // CalloutRegisterError
	case 20004: // CalloutUnregisterError
	case 20005: // CalloutClassifyError
		proto_tree_add_item(etw_tree, hf_etw_wfp_capture_callout, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		length = tvb_unicode_strsize(tvb, offset);
		proto_tree_add_item(etw_tree, hf_etw_wfp_capture_callout_error_message, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
		offset += length;
		proto_tree_add_item(etw_tree, hf_etw_wfp_capture_nt_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		break;

	case 60011: // TransportMessageV4
		call_dissector(ma_wfp_capture_v4_handle, tvb, pinfo, tree);
		break;

	case 60012: // TransportMessage2V4
		call_dissector(ma_wfp_capture2_v4_handle, tvb, pinfo, tree);
		break;

	case 60021: // TransportMessageV6
		call_dissector(ma_wfp_capture_v6_handle, tvb, pinfo, tree);
		break;

	case 60022: // TransportMessage2V6
		call_dissector(ma_wfp_capture2_v6_handle, tvb, pinfo, tree);
		break;

	case 60031: // AleAuthMessageV4
		call_dissector(ma_wfp_capture_auth_v4_handle, tvb, pinfo, tree);
		break;

	case 60041: // AleAuthMessageV6
		call_dissector(ma_wfp_capture_auth_v6_handle, tvb, pinfo, tree);
		break;
	}

	proto_item_set_len(ti, offset);
	return tvb_captured_length(tvb);
}

static const value_string etw_ndis_event_vals[] = {
	{ 1001, "EventPacketFragment"},
	{ 1002, "EventPacketMetadata"},
	{ 1003, "EventVMSwitchPacketFragment"},
	{ 1011, "EventCaptureRules"},
	{ 1012, "EventDriverLoad"},
	{ 1013, "EventDriverUnload"},
	{ 1014, "EventLayerLoad"},
	{ 1015, "EventLayerUnload"},
	{ 1016, "EventCaptureRule"},
	{ 2001, "EventDriverLoadError"},
	{ 2002, "EventLayerLoadError"},
	{ 2003, "EventRuleLoadError"},
	{ 3001, "EventStartLayerLoad"},
	{ 3002, "EventEndLayerLoad"},
	{ 5000, "EventRxPacketStart"},
	{ 5001, "EventRxPacketComplete"},
	{ 5002, "EventTxPacketStart"},
	{ 5003, "EventTxPacketComplete"},
	{ 5100, "EventStateRundown"},
	{ 5101, "EventPktSourceInfo"},
	{ 0, NULL }
};

static const value_string etw_ndis_rule_vals[] = {
	{ 2, "FrameControl"},
	{ 3, "MultiLayer"},
	{ 4, "InterfaceIndex"},
	{ 6, "EtherType"},
	{ 7, "Source_MAC_Address"},
	{ 8, "Destination_MAC_Address"},
	{ 9, "Any_MAC_Address"},
	{ 10, "Source_IPv4_Address"},
	{ 11, "Destination_IPv4_Address"},
	{ 12, "Any_IPv4_Address"},
	{ 13, "Source_IPv6_Address"},
	{ 14, "Destination_IPv6_Address"},
	{ 15, "Any_IPv6_Address"},
	{ 16, "IP_Protocol"},
	{ 17, "Packet_Truncate_Bytes"},
	{ 18, "Custom_MAC_Offset"},
	{ 19, "Custom_IP_Offset"},
	{ 0, NULL }
};

static const value_string etw_ndis_directive_vals[] = {
	{ 0, "OFF"},
	{ 1, "LTE"},
	{ 2, "GTE"},
	{ 3, "EQU"},
	{ 4, "MASK"},
	{ 5, "LIST"},
	{ 6, "RANGE"},
	{ 131, "NEQ"},
	{ 132, "NMASK"},
	{ 133, "NLIST"},
	{ 134, "NRANGE"},
	{ 0, NULL }
};

static const value_string etw_ndis_opcode_vals[] = {
	{ 1, "Start_State"},
	{ 2, "End_State"},
	{ 21, "Loading_State"},
	{ 22, "Unloading_State"},
	{ 0, NULL }
};

static const value_string etw_ndis_map_capture_vals[] = {
	{ 0, "Undefined"},
	{ 1, "NDIS"},
	{ 2, "VM_Switch"},
	{ 3, "Test"},
	{ 0, NULL }
};

#define ETW_NDIS_WIFI_PHYTYPE_80211A    4
#define ETW_NDIS_WIFI_PHYTYPE_80211B    5
#define ETW_NDIS_WIFI_PHYTYPE_80211G    6
#define ETW_NDIS_WIFI_PHYTYPE_80211N    7

static const value_string etw_ndis_wifi_phytype_vals[] = {
	{ ETW_NDIS_WIFI_PHYTYPE_80211A, "802.11a"},
	{ ETW_NDIS_WIFI_PHYTYPE_80211B, "802.11b"},
	{ ETW_NDIS_WIFI_PHYTYPE_80211G, "802.11g"},
	{ ETW_NDIS_WIFI_PHYTYPE_80211N, "802.11n"},
	{ 0, NULL }
};


#define ETW_NDIS_KEYWORD_ETHERNET8023       G_GUINT64_CONSTANT(0x0000000000000001)
#define ETW_NDIS_KEYWORD_RESERVED1          G_GUINT64_CONSTANT(0x00000000000001FE)
#define ETW_NDIS_KEYWORD_WIRELESS_WAN       G_GUINT64_CONSTANT(0x0000000000000200)
#define ETW_NDIS_KEYWORD_RESERVED2          G_GUINT64_CONSTANT(0x0000000000007C00)
#define ETW_NDIS_KEYWORD_TUNNEL             G_GUINT64_CONSTANT(0x0000000000008000)
#define ETW_NDIS_KEYWORD_NATIVE_80211       G_GUINT64_CONSTANT(0x0000000000010000)
#define ETW_NDIS_KEYWORD_RESERVED3          G_GUINT64_CONSTANT(0x0000000000FE0000)
#define ETW_NDIS_KEYWORD_VM_SWITCH          G_GUINT64_CONSTANT(0x0000000001000000)
#define ETW_NDIS_KEYWORD_RESERVED4          G_GUINT64_CONSTANT(0x000000003E000000)
#define ETW_NDIS_KEYWORD_PACKET_START       G_GUINT64_CONSTANT(0x0000000040000000)
#define ETW_NDIS_KEYWORD_PACKET_END         G_GUINT64_CONSTANT(0x0000000080000000)
#define ETW_NDIS_KEYWORD_SEND_PATH          G_GUINT64_CONSTANT(0x0000000100000000)
#define ETW_NDIS_KEYWORD_RECV_PATH          G_GUINT64_CONSTANT(0x0000000200000000)
#define ETW_NDIS_KEYWORD_L3_CONN_PATH       G_GUINT64_CONSTANT(0x0000000400000000)
#define ETW_NDIS_KEYWORD_L2_CONN_PATH       G_GUINT64_CONSTANT(0x0000000800000000)
#define ETW_NDIS_KEYWORD_CLOSE_PATH         G_GUINT64_CONSTANT(0x0000001000000000)
#define ETW_NDIS_KEYWORD_AUTHENTICATION     G_GUINT64_CONSTANT(0x0000002000000000)
#define ETW_NDIS_KEYWORD_CONFIGURATION      G_GUINT64_CONSTANT(0x0000004000000000)
#define ETW_NDIS_KEYWORD_GLOBAL             G_GUINT64_CONSTANT(0x0000008000000000)
#define ETW_NDIS_KEYWORD_DROPPED            G_GUINT64_CONSTANT(0x0000010000000000)
#define ETW_NDIS_KEYWORD_PII_PRESENT        G_GUINT64_CONSTANT(0x0000020000000000)
#define ETW_NDIS_KEYWORD_PACKET             G_GUINT64_CONSTANT(0x0000040000000000)
#define ETW_NDIS_KEYWORD_ADDRESS            G_GUINT64_CONSTANT(0x0000080000000000)
#define ETW_NDIS_KEYWORD_STD_TEMPLATE_HINT  G_GUINT64_CONSTANT(0x0000100000000000)
#define ETW_NDIS_KEYWORD_STATE_TRANSITION   G_GUINT64_CONSTANT(0x0000200000000000)
#define ETW_NDIS_KEYWORD_RESERVED5          G_GUINT64_CONSTANT(0xFFFFC00000000000)

static void
etw_ndis_packet_metadata(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
	int start_offset = offset;
	proto_tree* metadata_tree;
	proto_item* metadata_item;
	guint32 revision, length;

	metadata_tree = proto_tree_add_subtree(tree, tvb, offset, 4, ett_etw_ndis_packet_metadata, &metadata_item, "WiFiMetadata");

	proto_tree_add_item(metadata_tree, hf_etw_ndis_packet_metadata_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item_ret_uint(metadata_tree, hf_etw_ndis_packet_metadata_revision, tvb, offset, 1, ENC_LITTLE_ENDIAN, &revision);
	offset += 1;
	proto_tree_add_item_ret_uint(metadata_tree, hf_etw_ndis_packet_metadata_size, tvb, offset, 2, ENC_LITTLE_ENDIAN, &length);
	offset += 2;

	if (revision == 1)
	{
		guint32 phytype, channel, rate;
		gint32 rssi;

		proto_tree_add_item(metadata_tree, hf_etw_ndis_packet_metadata_wifi_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item_ret_uint(metadata_tree, hf_etw_ndis_packet_metadata_wifi_phytype, tvb, offset, 4, ENC_LITTLE_ENDIAN, &phytype);
		offset += 4;
		channel = tvb_get_letohl(tvb, offset);
		if (channel > 0)
		{
			if (phytype == ETW_NDIS_WIFI_PHYTYPE_80211A)
			{
				channel = (channel-5180)/5 + 36;
			}
			else
			{
				channel = (channel-2412)/5 + 1;
			}
		}
		proto_tree_add_uint(metadata_tree, hf_etw_ndis_packet_metadata_wifi_channel, tvb, offset, 4, channel);
		offset += 4;
		proto_tree_add_item(metadata_tree, hf_etw_ndis_packet_metadata_wifi_mpdus_received, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		proto_tree_add_item(metadata_tree, hf_etw_ndis_packet_metadata_wifi_mpdu_padding, tvb, offset, 2, ENC_NA);
		offset += 2;
		proto_tree_add_item_ret_int(metadata_tree, hf_etw_ndis_packet_metadata_wifi_rssi, tvb, offset, 4, ENC_LITTLE_ENDIAN, &rssi);
		offset += 4;
		rate = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint_format_value(metadata_tree, hf_etw_ndis_packet_metadata_wifi_datarate, tvb, offset, 1, rate, "%u.%u Mbps", rate / 2, rate % 2 > 0 ? 5 : 0);
		offset += 1;
		col_append_fstr(pinfo->cinfo, COL_INFO, ": RSSI = %d dBm, Rate = %u.%u Mbps", rssi, rate / 2, rate % 2 > 0 ? 5 : 0);
	}
	else
	{
		proto_tree_add_item(metadata_tree, hf_etw_ndis_packet_metadata_data, tvb, offset, length, ENC_NA);
		offset += length;
	}

	proto_item_set_len(metadata_item, offset-start_offset);
}


static int
dissect_etw_ndis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	proto_item *ti, *generated, *dest_item, *layer_item;
	proto_tree *etw_tree, *dest_tree, *layer_tree, *oob_tree;
	int offset = 0, dest_start, layer_start;
	struct netmon_provider_id_data *provider_id_data = (struct netmon_provider_id_data*)data;
	guint i, length;
	tvbuff_t *next_tvb;

	static int * const keyword_fields[] = {
		&hf_etw_ndis_keyword_ethernet8023,
		&hf_etw_ndis_keyword_reserved1,
		&hf_etw_ndis_keyword_wireless_wan,
		&hf_etw_ndis_keyword_reserved2,
		&hf_etw_ndis_keyword_tunnel,
		&hf_etw_ndis_keyword_native80211,
		&hf_etw_ndis_keyword_reserved3,
		&hf_etw_ndis_keyword_vmswitch,
		&hf_etw_ndis_keyword_reserved4,
		&hf_etw_ndis_keyword_packet_start,
		&hf_etw_ndis_keyword_packet_end,
		&hf_etw_ndis_keyword_send_path,
		&hf_etw_ndis_keyword_receive_path,
		&hf_etw_ndis_keyword_l3_connect_path,
		&hf_etw_ndis_keyword_l2_connect_path,
		&hf_etw_ndis_keyword_close_path,
		&hf_etw_ndis_keyword_authentication,
		&hf_etw_ndis_keyword_configuration,
		&hf_etw_ndis_keyword_global,
		&hf_etw_ndis_keyword_dropped,
		&hf_etw_ndis_keyword_pii_present,
		&hf_etw_ndis_keyword_packet,
		&hf_etw_ndis_keyword_address,
		&hf_etw_ndis_keyword_std_template_hint,
		&hf_etw_ndis_keyword_state_transition,
		&hf_etw_ndis_keyword_reserved5,
		NULL
	};

	DISSECTOR_ASSERT(provider_id_data != NULL);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ETW Ndis");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_etw_ndis, tvb, 0, -1, ENC_NA);
	etw_tree = proto_item_add_subtree(ti, ett_etw_ndis);

	generated = proto_tree_add_uint(etw_tree, hf_etw_ndis_event_id, tvb, 0, 0, provider_id_data->event_id);
	proto_item_set_generated(generated);
	col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(provider_id_data->event_id, etw_ndis_event_vals, "Unknown"));
	generated = proto_tree_add_bitmask_value(etw_tree, tvb, 0, hf_etw_ndis_keyword, ett_etw_ndis_keyword, keyword_fields, provider_id_data->keyword);
	proto_item_set_generated(generated);



	switch (provider_id_data->event_id)
	{
	case 1001: // EventPacketFragment
		proto_tree_add_item(etw_tree, hf_etw_ndis_miniport_if_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(etw_tree, hf_etw_ndis_lower_if_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item_ret_uint(etw_tree, hf_etw_ndis_fragment_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
		offset += 4;
		if ((provider_id_data->keyword & (ETW_NDIS_KEYWORD_PACKET_START|ETW_NDIS_KEYWORD_PACKET_END)) == (ETW_NDIS_KEYWORD_PACKET_START|ETW_NDIS_KEYWORD_PACKET_END))
		{
			/* This is a complete packet */
			next_tvb = tvb_new_subset_length(tvb, offset, length);

			if (provider_id_data->keyword & ETW_NDIS_KEYWORD_ETHERNET8023)
			{
				call_dissector(eth_handle, next_tvb, pinfo, tree);
			}
			else if (provider_id_data->keyword & ETW_NDIS_KEYWORD_NATIVE_80211)
			{
				call_dissector(ieee80211_handle, next_tvb, pinfo, tree);
			}
			else if (provider_id_data->keyword & ETW_NDIS_KEYWORD_WIRELESS_WAN)
			{
				call_dissector(ip_handle, next_tvb, pinfo, tree);
			}
		}
		else
		{
			proto_tree_add_item(etw_tree, hf_etw_ndis_fragment, tvb, offset, length, ENC_NA);
			offset += length;
		}
		break;

	case 1002: // EventPacketMetadata
		proto_tree_add_item(etw_tree, hf_etw_ndis_miniport_if_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(etw_tree, hf_etw_ndis_lower_if_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item_ret_uint(etw_tree, hf_etw_ndis_metadata_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
		offset += 4;
		if (provider_id_data->keyword & ETW_NDIS_KEYWORD_NATIVE_80211)
		{
			etw_ndis_packet_metadata(etw_tree, tvb, pinfo, offset);
		}
		else
		{
			proto_tree_add_item(etw_tree, hf_etw_ndis_metadata, tvb, offset, length, ENC_NA);
		}
		offset += length;
		break;

	case 1003: // EventVMSwitchPacketFragment
		proto_tree_add_item(etw_tree, hf_etw_ndis_miniport_if_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(etw_tree, hf_etw_ndis_lower_if_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(etw_tree, hf_etw_ndis_source_port_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		length = tvb_unicode_strsize(tvb, offset);
		proto_tree_add_item(etw_tree, hf_etw_ndis_source_port_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
		offset += length;
		length = tvb_unicode_strsize(tvb, offset);
		proto_tree_add_item(etw_tree, hf_etw_ndis_source_nic_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
		offset += length;
		length = tvb_unicode_strsize(tvb, offset);
		proto_tree_add_item(etw_tree, hf_etw_ndis_source_nic_type, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
		offset += length;
		proto_tree_add_item_ret_uint(etw_tree, hf_etw_ndis_destination_count, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
		offset += 4;
		for (i = 1; i <= length; i++)
		{
			dest_start = offset;
			dest_tree = proto_tree_add_subtree_format(etw_tree, tvb, offset, 4, ett_etw_ndis_dest, &dest_item, "Destination #%d", i);

			proto_tree_add_item(dest_tree, hf_etw_ndis_destination_port_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(dest_tree, hf_etw_ndis_destination_port_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(dest_tree, hf_etw_ndis_destination_nic_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(dest_tree, hf_etw_ndis_destination_nic_type, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;

			proto_item_set_len(dest_item, offset-dest_start);
		}

		proto_tree_add_item_ret_uint(etw_tree, hf_etw_ndis_fragment_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
		offset += 4;
		if (provider_id_data->keyword & ETW_NDIS_KEYWORD_PACKET_START)
		{
			/* This is a complete packet */
			next_tvb = tvb_new_subset_length(tvb, offset, length);

			if (provider_id_data->keyword & ETW_NDIS_KEYWORD_ETHERNET8023)
			{
				call_dissector(eth_handle, next_tvb, pinfo, tree);
			}
			else if (provider_id_data->keyword & ETW_NDIS_KEYWORD_NATIVE_80211)
			{
				call_dissector(ieee80211_handle, next_tvb, pinfo, tree);
			}
			else if (provider_id_data->keyword & ETW_NDIS_KEYWORD_WIRELESS_WAN)
			{
				call_dissector(ip_handle, next_tvb, pinfo, tree);
			}
		}
		else
		{
			proto_tree_add_item(etw_tree, hf_etw_ndis_fragment, tvb, offset, length, ENC_NA);
			offset += length;
		}
		proto_tree_add_item_ret_uint(etw_tree, hf_etw_ndis_oob_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
		offset += 4;

		if ((gint)length == tvb_reported_length_remaining(tvb, offset))
		{
			oob_tree = proto_tree_add_subtree(etw_tree, tvb, offset, length, ett_etw_ndis_oob_data, NULL, "OOB Data");

			/* XXX - Need Provider ID version information here */
			if (provider_id_data->event_flags & EVENT_HEADER_FLAG_64_BIT_HEADER)
			{
				proto_tree_add_item(oob_tree, hf_etw_ndis_tcp_ip_checksum_net_buffer_list, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				offset += 8;
				proto_tree_add_item(oob_tree, hf_etw_ndis_ipsec_offload_v1_net_buffer_list_info, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				offset += 8;
				proto_tree_add_item(oob_tree, hf_etw_ndis_tcp_large_send_net_buffer_list_info, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				offset += 8;
				proto_tree_add_item(oob_tree, hf_etw_ndis_classification_handle_net_buffer_list_info, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				offset += 8;
				proto_tree_add_item(oob_tree, hf_etw_ndis_ieee8021q_net_buffer_list_info, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				offset += 8;
				proto_tree_add_item(oob_tree, hf_etw_ndis_net_buffer_cancel_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				offset += 8;
				proto_tree_add_item(oob_tree, hf_etw_ndis_media_specific_information, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				offset += 8;
				proto_tree_add_item(oob_tree, hf_etw_ndis_net_buffer_list_frame_type, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				offset += 8;
				proto_tree_add_item(oob_tree, hf_etw_ndis_net_buffer_list_hash_value, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				offset += 8;
				proto_tree_add_item(oob_tree, hf_etw_ndis_net_buffer_list_hash_info, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				offset += 8;
				proto_tree_add_item(oob_tree, hf_etw_ndis_wpf_net_buffer_list_info, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				offset += 8;
				proto_tree_add_item(oob_tree, hf_etw_ndis_max_net_buffer_list_info, tvb, offset, 8, ENC_LITTLE_ENDIAN);
				offset += 8;
			}
			else
			{
				proto_tree_add_item(oob_tree, hf_etw_ndis_tcp_ip_checksum_net_buffer_list, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(oob_tree, hf_etw_ndis_ipsec_offload_v1_net_buffer_list_info, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(oob_tree, hf_etw_ndis_tcp_large_send_net_buffer_list_info, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(oob_tree, hf_etw_ndis_classification_handle_net_buffer_list_info, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(oob_tree, hf_etw_ndis_ieee8021q_net_buffer_list_info, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(oob_tree, hf_etw_ndis_net_buffer_cancel_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(oob_tree, hf_etw_ndis_media_specific_information, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(oob_tree, hf_etw_ndis_net_buffer_list_frame_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(oob_tree, hf_etw_ndis_net_buffer_list_hash_value, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(oob_tree, hf_etw_ndis_net_buffer_list_hash_info, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(oob_tree, hf_etw_ndis_wpf_net_buffer_list_info, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
				proto_tree_add_item(oob_tree, hf_etw_ndis_max_net_buffer_list_info, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;
			}
		}
		else
		{
			proto_tree_add_item(etw_tree, hf_etw_ndis_oob_data, tvb, offset, length, ENC_NA);
			offset += length;
		}
		break;

	case 1011: // EventCaptureRules
		proto_tree_add_item(etw_tree, hf_etw_ndis_rules_count, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		break;

	case 1012: // EventDriverLoad
	case 1013: // EventDriverUnload
		length = tvb_unicode_strsize(tvb, offset);
		proto_tree_add_item(etw_tree, hf_etw_ndis_friendly_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
		offset += length;
		length = tvb_unicode_strsize(tvb, offset);
		proto_tree_add_item(etw_tree, hf_etw_ndis_unique_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
		offset += length;
		length = tvb_unicode_strsize(tvb, offset);
		proto_tree_add_item(etw_tree, hf_etw_ndis_service_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
		offset += length;
		length = tvb_unicode_strsize(tvb, offset);
		proto_tree_add_item(etw_tree, hf_etw_ndis_version, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
		offset += length;
		break;

	case 1014: // EventLayerLoad
	case 1015: // EventLayerUnload
		proto_tree_add_item(etw_tree, hf_etw_ndis_miniport_if_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(etw_tree, hf_etw_ndis_lower_if_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(etw_tree, hf_etw_ndis_media_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(etw_tree, hf_etw_ndis_reference_context, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		break;

	case 1016: // EventCaptureRule
	case 2003: // EventRuleLoadError
		proto_tree_add_item(etw_tree, hf_etw_ndis_rule_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		proto_tree_add_item(etw_tree, hf_etw_ndis_directive, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		proto_tree_add_item_ret_uint(etw_tree, hf_etw_ndis_value_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
		offset += 4;
		proto_tree_add_item(etw_tree, hf_etw_ndis_value, tvb, offset, length, ENC_NA);
		offset += length;
		break;

	case 2001:  // EventDriverLoadError
	case 2002:  // EventLayerLoadError
		proto_tree_add_item(etw_tree, hf_etw_ndis_error_code, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(etw_tree, hf_etw_ndis_location, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(etw_tree, hf_etw_ndis_context, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		break;

	case 3001:  // EventStartLayerLoad
	case 3002:  // EventEndLayerLoad
		proto_tree_add_item(etw_tree, hf_etw_ndis_previous_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		proto_tree_add_item(etw_tree, hf_etw_ndis_next_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		proto_tree_add_item(etw_tree, hf_etw_ndis_location, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(etw_tree, hf_etw_ndis_context, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		break;

	case 5000:  // EventRxPacketStart
	case 5001:  // EventRxPacketComplete
	case 5002:  // EventTxPacketStart
	case 5003:  // EventTxPacketComplete
		break;

	case 5100:  // EventStateRundown
		proto_tree_add_item(etw_tree, hf_etw_ndis_source_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		proto_tree_add_item(etw_tree, hf_etw_ndis_rundown_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(etw_tree, hf_etw_ndis_param1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(etw_tree, hf_etw_ndis_param2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		length = tvb_unicode_strsize(tvb, offset);
		proto_tree_add_item(etw_tree, hf_etw_ndis_param_str, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
		offset += length;
		length = tvb_unicode_strsize(tvb, offset);
		proto_tree_add_item(etw_tree, hf_etw_ndis_description, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
		offset += length;
		break;

	case 5101:  // EventPktSourceInfo
		proto_tree_add_item(etw_tree, hf_etw_ndis_source_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		length = tvb_unicode_strsize(tvb, offset);
		proto_tree_add_item(etw_tree, hf_etw_ndis_source_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
		offset += length;
		proto_tree_add_item(etw_tree, hf_etw_ndis_if_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item_ret_uint(etw_tree, hf_etw_ndis_layer_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &length);
		offset += 2;
		for (i = 1; i <= length; i++)
		{
			layer_start = offset;
			layer_tree = proto_tree_add_subtree_format(etw_tree, tvb, offset, 4, ett_etw_ndis_layer, &layer_item, "Layer #%d", i);
			proto_tree_add_item(layer_tree, hf_etw_ndis_layer_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			length = tvb_unicode_strsize(tvb, offset);
			proto_tree_add_item(layer_tree, hf_etw_ndis_layer_name, tvb, offset, length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
			offset += length;

			proto_item_set_len(layer_item, offset-layer_start);
		}
		break;
	}

	proto_item_set_len(ti, offset);
	return offset;
}

void proto_register_message_analyzer(void)
{
	static hf_register_info hf_wfp_capture[] = {
		{ &hf_ma_wfp_capture_flow_context,
			{ "Flow Context", "message_analyzer.wfp_capture.flow_context",
			FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ma_wfp_capture_payload_length,
			{ "Payload Length", "message_analyzer.wfp_capture.payload_length",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
	};

	static hf_register_info hf_wfp_capture_auth[] = {
		{ &hf_ma_wfp_capture_auth_src_port,
			{ "Source Port", "message_analyzer.wfp_capture.auth.src_port",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ma_wfp_capture_auth_dst_port,
			{ "Destination Port", "message_analyzer.wfp_capture.auth.dst_port",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ma_wfp_capture_auth_interface_id,
			{ "Interface ID", "message_analyzer.wfp_capture.auth.interface_id",
			FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ma_wfp_capture_auth_direction,
			{ "Direction", "message_analyzer.wfp_capture.auth.direction",
			FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ma_wfp_capture_auth_process_id,
			{ "Process ID", "message_analyzer.wfp_capture.auth.process_id",
			FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ma_wfp_capture_auth_process_path,
			{ "Payload Length", "message_analyzer.wfp_capture.auth.process_path",
			FT_UINT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
	};

	static hf_register_info hf_etw_wfp_capture[] = {
		{ &hf_etw_wfp_capture_event_id,
			{ "Event ID", "etw.wfp_capture.event_id",
			FT_UINT32, BASE_DEC_HEX, VALS(etw_wfp_capture_event_vals), 0x0, NULL, HFILL }
		},
		{ &hf_etw_wfp_capture_driver_name,
			{ "Driver Name", "etw.wfp_capture.driver_name",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_wfp_capture_major_version,
			{ "Major Version", "etw.wfp_capture.major_version",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_wfp_capture_minor_version,
			{ "Minor Version", "etw.wfp_capture.minor_version",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_wfp_capture_callout,
			{ "Callout", "etw.wfp_capture.callout",
			FT_UINT32, BASE_DEC, VALS(etw_wfp_capture_callout_vals), 0x0, NULL, HFILL }
		},
		{ &hf_etw_wfp_capture_filter_id,
			{ "Filter ID", "etw.wfp_capture.filter_id",
			FT_UINT64, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_wfp_capture_filter_weight,
			{ "Filter Weight", "etw.wfp_capture.filter_weight",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_wfp_capture_driver_error_message,
			{ "Driver Name", "etw.wfp_capture.driver_error_message",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_wfp_capture_callout_error_message,
			{ "Driver Name", "etw.wfp_capture.callout_error_message",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_wfp_capture_nt_status,
			{ "NT Status", "etw.wfp_capture.nt_status",
			FT_UINT32, BASE_HEX|BASE_EXT_STRING, &HRES_errors_ext, 0x0, NULL, HFILL }
		},
	};

	static hf_register_info hf_etw_ndis[] = {
		{ &hf_etw_ndis_event_id,
			{ "Event ID", "etw.ndis.event_id",
			FT_UINT32, BASE_DEC_HEX, VALS(etw_ndis_event_vals), 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_miniport_if_index,
			{ "MiniportIfIndex", "etw.ndis.miniport_if_index",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_lower_if_index,
			{ "LowerIfIndex", "etw.ndis.lower_if_index",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_fragment_size,
			{ "Fragment size", "etw.ndis.fragment_size",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_fragment,
			{ "Fragment", "etw.ndis.fragment",
			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_metadata_size,
			{ "Metadata size", "etw.ndis.metadata_size",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_metadata,
			{ "Metadata", "etw.ndis.metadata",
			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_source_port_id,
			{ "Source port ID", "etw.ndis.source_port_id",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_source_port_name,
			{ "Source port name", "etw.ndis.source_port_name",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_source_nic_name,
			{ "Source NIC name", "etw.ndis.source_nic_name",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_source_nic_type,
			{ "Source NIC type", "etw.ndis.source_nic_type",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_destination_count,
			{ "Destination count", "etw.ndis.destination_count",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_destination_port_id,
			{ "Destination port ID", "etw.ndis.destination_port_id",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_destination_port_name,
			{ "Destination port name", "etw.ndis.destination_port_name",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_destination_nic_name,
			{ "Destination NIC name", "etw.ndis.destination_nic_name",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_destination_nic_type,
			{ "Destination NIC type", "etw.ndis.destination_nic_type",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_oob_data_size,
			{ "OOB data size", "etw.ndis.oob_data_size",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_oob_data,
			{ "OOB data", "etw.ndis.oob_data",
			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_rules_count,
			{ "Rules count", "etw.ndis.rules_count",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_friendly_name,
			{ "Friendly name", "etw.ndis.friendly_name",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_unique_name,
			{ "Unique name", "etw.ndis.unique_name",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_service_name,
			{ "Service name", "etw.ndis.service_name",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_version,
			{ "Version", "etw.ndis.version",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_media_type,
			{ "Media types", "etw.ndis.media_type",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_reference_context,
			{ "Reference context", "etw.ndis.reference_context",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_rule_id,
			{ "Rule ID", "etw.ndis.rule_id",
			FT_UINT8, BASE_DEC, VALS(etw_ndis_rule_vals), 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_directive,
			{ "Directive", "etw.ndis.directive",
			FT_UINT8, BASE_DEC, VALS(etw_ndis_directive_vals), 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_value_length,
			{ "Value length", "etw.ndis.value_length",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_value,
			{ "Value", "etw.ndis.value",
			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_previous_state,
			{ "Previous state", "etw.ndis.previous_state",
			FT_UINT8, BASE_DEC, VALS(etw_ndis_opcode_vals), 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_next_state,
			{ "Next state", "etw.ndis.next_state",
			FT_UINT8, BASE_DEC, VALS(etw_ndis_opcode_vals), 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_error_code,
			{ "Error code", "etw.ndis.error_code",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_location,
			{ "Location", "etw.ndis.location",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_context,
			{ "Context", "etw.ndis.context",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_source_id,
			{ "Source ID", "etw.ndis.source_id",
			FT_UINT8, BASE_DEC, VALS(etw_ndis_map_capture_vals), 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_rundown_id,
			{ "Rundown ID", "etw.ndis.rundown_id",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_param1,
			{ "Param1", "etw.ndis.param1",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_param2,
			{ "Param2", "etw.ndis.param2",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_param_str,
			{ "Param String", "etw.ndis.param_str",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_description,
			{ "Description", "etw.ndis.description",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_source_name,
			{ "Source name", "etw.ndis.source_name",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_if_index,
			{ "IfIndex", "etw.ndis.if_index",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_layer_count,
			{ "Layer count", "etw.ndis.layer_count",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_layer_id,
			{ "Layer ID", "etw.ndis.layer_id",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_layer_name,
			{ "Layer name", "etw.ndis.layer_name",
			FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword,
			{ "Keyword", "etw.ndis.keyword",
			FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_ethernet8023,
			{ "KW_MEDIA_802_3", "etw.ndis.keyword.ethernet8023",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_ETHERNET8023, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_reserved1,
			{ "Reserved1", "etw.ndis.keyword.reserved1",
			FT_UINT64, BASE_HEX, NULL, ETW_NDIS_KEYWORD_RESERVED1, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_wireless_wan,
			{ "KW_MEDIA_WIRELESS_WAN", "etw.ndis.keyword.wireless_wan",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_WIRELESS_WAN, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_reserved2,
			{ "Reserved2", "etw.ndis.keyword.reserved2",
			FT_UINT64, BASE_HEX, NULL, ETW_NDIS_KEYWORD_RESERVED2, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_tunnel,
			{ "KW_MEDIA_TUNNEL", "etw.ndis.keyword.tunnel",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_TUNNEL, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_native80211,
			{ "KW_MEDIA_NATIVE_802_11", "etw.ndis.keyword.native80211",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_NATIVE_80211, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_reserved3,
			{ "Reserved3", "etw.ndis.keyword.reserved3",
			FT_UINT64, BASE_HEX, NULL, ETW_NDIS_KEYWORD_RESERVED3, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_vmswitch,
			{ "KW_VMSWITCH", "etw.ndis.keyword.vmswitch",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_VM_SWITCH, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_reserved4,
			{ "Reserved4", "etw.ndis.keyword.reserved4",
			FT_UINT64, BASE_HEX, NULL, ETW_NDIS_KEYWORD_RESERVED4, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_packet_start,
			{ "KW_PACKET_START", "etw.ndis.keyword.packet_start",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_PACKET_START, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_packet_end,
			{ "KW_PACKET_END", "etw.ndis.keyword.packet_end",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_PACKET_END, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_send_path,
			{ "KW_SEND", "etw.ndis.keyword.send_path",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_SEND_PATH, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_receive_path,
			{ "KW_RECEIVE", "etw.ndis.keyword.receive_path",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_RECV_PATH, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_l3_connect_path,
			{ "KW_L3_CONNECT", "etw.ndis.keyword.l3_connect_path",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_L3_CONN_PATH, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_l2_connect_path,
			{ "KW_L2_CONNECT", "etw.ndis.keyword.connect_path",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_L2_CONN_PATH, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_close_path,
			{ "KW_CLOSE", "etw.ndis.keyword.close_path",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_CLOSE_PATH, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_authentication,
			{ "KW_AUTHENTICATION", "etw.ndis.keyword.authentication",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_AUTHENTICATION, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_configuration,
			{ "KW_CONFIGURATION", "etw.ndis.keyword.configuration",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_CONFIGURATION, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_global,
			{ "KW_GLOBAL", "etw.ndis.keyword.global",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_GLOBAL, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_dropped,
			{ "KW_DROPPED", "etw.ndis.keyword.dropped",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_DROPPED, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_pii_present,
			{ "KW_PII_PRESENT", "etw.ndis.keyword.pii_present",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_PII_PRESENT, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_packet,
			{ "KW_PACKET", "etw.ndis.keyword.packet",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_PACKET, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_address,
			{ "KW_ADDRESS", "etw.ndis.keyword.address",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_ADDRESS, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_std_template_hint,
			{ "KW_STD_TEMPLATE_HINT", "etw.ndis.keyword.std_template_hint",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_STD_TEMPLATE_HINT, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_state_transition,
			{ "KW_STATE_TRANSITION", "etw.ndis.keyword.state_transition",
			FT_BOOLEAN, 64, NULL, ETW_NDIS_KEYWORD_STATE_TRANSITION, NULL, HFILL }
		},
		{ &hf_etw_ndis_keyword_reserved5,
			{ "Reserved5", "etw.ndis.keyword.reserved5",
			FT_UINT64, BASE_HEX, NULL, ETW_NDIS_KEYWORD_RESERVED5, NULL, HFILL }
		},
		{ &hf_etw_ndis_packet_metadata_type,
			{ "Type", "etw.ndis.packet_metadata.type",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_packet_metadata_revision,
			{ "Revision", "etw.ndis.packet_metadata.revision",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_packet_metadata_size,
			{ "Size", "etw.ndis.packet_metadata.size",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_packet_metadata_wifi_flags,
			{ "Flags", "etw.ndis.packet_metadata.wifi_flags",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_packet_metadata_wifi_phytype,
			{ "PHY type", "etw.ndis.packet_metadata.wifi_phytype",
			FT_UINT32, BASE_DEC, VALS(etw_ndis_wifi_phytype_vals), 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_packet_metadata_wifi_channel,
			{ "Channel", "etw.ndis.packet_metadata.wifi_channel",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_packet_metadata_wifi_mpdus_received,
			{ "MPDUs received", "etw.ndis.packet_metadata.wifi_mpdus_received",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_packet_metadata_wifi_mpdu_padding,
			{ "MPDU padding", "etw.ndis.packet_metadata.wifi_mpdu_padding",
			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_packet_metadata_wifi_rssi,
			{ "RSSI", "etw.ndis.packet_metadata.wifi_rssi",
			FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_packet_metadata_wifi_datarate,
			{ "Datarate", "etw.ndis.packet_metadata.wifi_datarate",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_packet_metadata_data,
			{ "MPDU padding", "etw.ndis.packet_metadata.data",
			FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_tcp_ip_checksum_net_buffer_list,
			{ "TcpIpChecksumNetBufferListInfoOrTcpOffloadBytesTransferred", "etw.ndis.tcp_ip_checksum_net_buffer_list",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_ipsec_offload_v1_net_buffer_list_info,
			{ "IPsecOffloadV2NetBufferListInfo", "etw.ndis.ipsec_offload_v1_net_buffer_list_info",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_tcp_large_send_net_buffer_list_info,
			{ "TcpLargeSendNetBufferListInfoOrTcpReceiveNoPush", "etw.ndis.tcp_large_send_net_buffer_list_info",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_classification_handle_net_buffer_list_info,
			{ "ClassificationHandleNetBufferListInfo", "etw.ndis.classification_handle_net_buffer_list_info",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_ieee8021q_net_buffer_list_info,
			{ "Ieee8021QNetBufferListInfo", "etw.ndis.ieee8021q_net_buffer_list_info",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_net_buffer_cancel_id,
			{ "NetBufferListCancelId", "etw.ndis.net_buffer_cancel_id",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_media_specific_information,
			{ "MediaSpecificInformation", "etw.ndis.media_specific_information",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_net_buffer_list_frame_type,
			{ "NetBufferListFrameTypeOrNetBufferListProtocolId", "etw.ndis.net_buffer_list_frame_type",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_net_buffer_list_hash_value,
			{ "NetBufferListHashValue", "etw.ndis.net_buffer_list_hash_value",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_net_buffer_list_hash_info,
			{ "NetBufferListHashInfo", "etw.ndis.net_buffer_list_hash_info",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_wpf_net_buffer_list_info,
			{ "WfpNetBufferListInfo", "etw.ndis.wpf_net_buffer_list_info",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_etw_ndis_max_net_buffer_list_info,
			{ "MaxNetBufferListInfo", "etw.ndis.max_net_buffer_list_info",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_ma_wfp_capture_v4,
		&ett_ma_wfp_capture_v6,
		&ett_ma_wfp_capture_auth,
		&ett_etw_wfp_capture,
		&ett_etw_ndis,
		&ett_etw_ndis_dest,
		&ett_etw_ndis_layer,
		&ett_etw_ndis_keyword,
		&ett_etw_ndis_packet_metadata,
		&ett_etw_ndis_oob_data,
	};

	proto_ma_wfp_capture_v4 = proto_register_protocol ("Message Analyzer WFP Capture v4", "MA WFP Capture v4", "message_analyzer.wfp_capture.v4" );
	proto_ma_wfp_capture2_v4 = proto_register_protocol ("Message Analyzer WFP Capture2 v4", "MA WFP Capture2 v4", "message_analyzer.wfp_capture2.v4" );
	proto_ma_wfp_capture_v6 = proto_register_protocol ("Message Analyzer WFP Capture v6", "MA WFP Capture v6", "message_analyzer.wfp_capture.v6" );
	proto_ma_wfp_capture2_v6 = proto_register_protocol ("Message Analyzer WFP Capture2 v6", "MA WFP Capture2 v6", "message_analyzer.wfp_capture2.v6" );
	proto_ma_wfp_capture_auth_v4 = proto_register_protocol ("Message Analyzer WFP Capture AUTH v4", "MA WFP Capture AUTH v4", "message_analyzer.wfp_capture.auth.v4" );
	proto_ma_wfp_capture_auth_v6 = proto_register_protocol ("Message Analyzer WFP Capture AUTH v6", "MA WFP Capture AUTH v6", "message_analyzer.wfp_capture.auth.v6" );
	proto_etw_wfp_capture = proto_register_protocol ("ETW WFP Capture", "ETW WFP Capture", "etw.wfp_capture" );
	proto_etw_ndis = proto_register_protocol ("ETW Ndis", "ETW Ndis", "etw.ndis" );

	proto_register_field_array(proto_ma_wfp_capture_v4, hf_wfp_capture, array_length(hf_wfp_capture));
	proto_register_field_array(proto_ma_wfp_capture_auth_v4, hf_wfp_capture_auth, array_length(hf_wfp_capture_auth));
	proto_register_field_array(proto_etw_wfp_capture, hf_etw_wfp_capture, array_length(hf_etw_wfp_capture));
	proto_register_field_array(proto_etw_ndis, hf_etw_ndis, array_length(hf_etw_ndis));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_message_analyzer(void)
{
	dissector_handle_t etw_wfp_capture_handle, etw_ndis_handle;
	static guid_key etw_wfp_capture_guid = {{ 0xc22d1b14, 0xc242, 0x49de, { 0x9f, 0x17, 0x1d, 0x76, 0xb8, 0xb9, 0xc4, 0x58 }}, 0 };
	static guid_key etw_ndis_guid = {{ 0x2ed6006e, 0x4729, 0x4609, { 0xb4, 0x23, 0x3e, 0xe7, 0xbc, 0xd6, 0x78, 0xef }}, 0 };

	ma_wfp_capture_v4_handle = create_dissector_handle(dissect_ma_wfp_capture_v4, proto_ma_wfp_capture_v4);
	ma_wfp_capture2_v4_handle = create_dissector_handle(dissect_ma_wfp_capture2_v4, proto_ma_wfp_capture2_v4);
	ma_wfp_capture_v6_handle = create_dissector_handle(dissect_ma_wfp_capture_v6, proto_ma_wfp_capture_v6);
	ma_wfp_capture2_v6_handle = create_dissector_handle(dissect_ma_wfp_capture2_v6, proto_ma_wfp_capture2_v6);
	ma_wfp_capture_auth_v4_handle = create_dissector_handle(dissect_ma_wfp_capture_auth_v4, proto_ma_wfp_capture_auth_v4);
	ma_wfp_capture_auth_v6_handle = create_dissector_handle(dissect_ma_wfp_capture_auth_v6, proto_ma_wfp_capture_auth_v6);

	dissector_add_uint("wtap_encap", WTAP_ENCAP_MA_WFP_CAPTURE_V4, ma_wfp_capture_v4_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_MA_WFP_CAPTURE_2V4, ma_wfp_capture2_v4_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_MA_WFP_CAPTURE_V6, ma_wfp_capture_v6_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_MA_WFP_CAPTURE_2V6, ma_wfp_capture2_v6_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_MA_WFP_CAPTURE_AUTH_V4, ma_wfp_capture_auth_v4_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_MA_WFP_CAPTURE_AUTH_V6, ma_wfp_capture_auth_v6_handle);

	etw_wfp_capture_handle = create_dissector_handle( dissect_etw_wfp_capture, proto_etw_wfp_capture);
	dissector_add_guid( "netmon.provider_id", &etw_wfp_capture_guid, etw_wfp_capture_handle);
	etw_ndis_handle = create_dissector_handle( dissect_etw_ndis, proto_etw_ndis);
	dissector_add_guid( "netmon.provider_id", &etw_ndis_guid, etw_ndis_handle);

	ip_dissector_table = find_dissector_table("ip.proto");
	ip_handle = find_dissector_add_dependency("ip", proto_etw_ndis);
	eth_handle = find_dissector_add_dependency("eth_withoutfcs", proto_etw_ndis);
	ieee80211_handle = find_dissector_add_dependency("wlan", proto_etw_ndis);

	/* Find all of the fields used from other common dissectors */
	hf_ip_src = proto_registrar_get_id_byname("ip.src");
	hf_ip_addr = proto_registrar_get_id_byname("ip.addr");
	hf_ip_src_host = proto_registrar_get_id_byname("ip.src_host");
	hf_ip_dst = proto_registrar_get_id_byname("ip.dst");
	hf_ip_dst_host = proto_registrar_get_id_byname("ip.dst_host");
	hf_ip_host = proto_registrar_get_id_byname("ip.host");
	hf_ip_proto = proto_registrar_get_id_byname("ip.proto");
	hf_ipv6_src = proto_registrar_get_id_byname("ipv6.src");
	hf_ipv6_addr = proto_registrar_get_id_byname("ipv6.addr");
	hf_ipv6_src_host = proto_registrar_get_id_byname("ipv6.src_host");
	hf_ipv6_host = proto_registrar_get_id_byname("ipv6.host");
	hf_ipv6_dst = proto_registrar_get_id_byname("ipv6.dst");
	hf_ipv6_dst_host = proto_registrar_get_id_byname("ipv6.dst_host");

}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
