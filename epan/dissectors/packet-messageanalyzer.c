/* packet-messageanalyzer.c
 * Routines for Message Analyzer capture dissection
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <wsutil/inet_ipv6.h>
#include <wsutil/utf8_entities.h>
#include <wiretap/wtap.h>

void proto_register_message_analyzer(void);
void proto_reg_handoff_message_analyzer(void);

/* Initialize the protocol and registered fields */
static int proto_ma_wfp_capture_v4 = -1;
static int proto_ma_wfp_capture2_v4 = -1;
static int proto_ma_wfp_capture_v6 = -1;
static int proto_ma_wfp_capture2_v6 = -1;
static int proto_ma_wfp_capture_auth_v4 = -1;
static int proto_ma_wfp_capture_auth_v6 = -1;

static int hf_ma_wfp_capture_flow_context = -1;
static int hf_ma_wfp_capture_payload_length = -1;
static int hf_ma_wfp_capture_auth_src_port = -1;
static int hf_ma_wfp_capture_auth_dst_port = -1;
static int hf_ma_wfp_capture_auth_interface_id = -1;
static int hf_ma_wfp_capture_auth_direction = -1;
static int hf_ma_wfp_capture_auth_process_id = -1;
static int hf_ma_wfp_capture_auth_process_path = -1;

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
		PROTO_ITEM_SET_HIDDEN(item);

		item = proto_tree_add_string(tree, hf_ip_src_host, tvb, offset, 4, src_host);
		PROTO_ITEM_SET_GENERATED(item);
		PROTO_ITEM_SET_HIDDEN(item);

		item = proto_tree_add_string(tree, hf_ip_host, tvb, offset, 4, src_host);
		PROTO_ITEM_SET_GENERATED(item);
		PROTO_ITEM_SET_HIDDEN(item);
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
		PROTO_ITEM_SET_HIDDEN(item);

		item = proto_tree_add_string(tree, hf_ip_dst_host, tvb, offset, 4, dst_host);
		PROTO_ITEM_SET_GENERATED(item);
		PROTO_ITEM_SET_HIDDEN(item);

		item = proto_tree_add_string(tree, hf_ip_host, tvb, offset, 4, dst_host);
		PROTO_ITEM_SET_GENERATED(item);
		PROTO_ITEM_SET_HIDDEN(item);
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
		PROTO_ITEM_SET_HIDDEN(item);

		item = proto_tree_add_string(tree, hf_ipv6_src_host, tvb, offset, IPv6_ADDR_SIZE, src_host);
		PROTO_ITEM_SET_GENERATED(item);
		PROTO_ITEM_SET_HIDDEN(item);

		item = proto_tree_add_string(tree, hf_ipv6_host, tvb, offset, IPv6_ADDR_SIZE, src_host);
		PROTO_ITEM_SET_GENERATED(item);
		PROTO_ITEM_SET_HIDDEN(item);
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
		PROTO_ITEM_SET_HIDDEN(item);

		item = proto_tree_add_string(tree, hf_ipv6_dst_host, tvb, offset, IPv6_ADDR_SIZE, dst_host);
		PROTO_ITEM_SET_GENERATED(item);
		PROTO_ITEM_SET_HIDDEN(item);

		item = proto_tree_add_string(tree, hf_ipv6_host, tvb, offset, IPv6_ADDR_SIZE, dst_host);
		PROTO_ITEM_SET_GENERATED(item);
		PROTO_ITEM_SET_HIDDEN(item);
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

	static gint *ett[] = {
		&ett_ma_wfp_capture_v4,
		&ett_ma_wfp_capture_v6,
		&ett_ma_wfp_capture_auth,
	};

	proto_ma_wfp_capture_v4 = proto_register_protocol ("Message Analyzer WFP Capture v4", "MA WFP Capture v4", "message_analyzer.wfp_capture.v4" );
	proto_ma_wfp_capture2_v4 = proto_register_protocol ("Message Analyzer WFP Capture2 v4", "MA WFP Capture2 v4", "message_analyzer.wfp_capture2.v4" );
	proto_ma_wfp_capture_v6 = proto_register_protocol ("Message Analyzer WFP Capture v6", "MA WFP Capture v6", "message_analyzer.wfp_capture.v6" );
	proto_ma_wfp_capture2_v6 = proto_register_protocol ("Message Analyzer WFP Capture2 v6", "MA WFP Capture2 v6", "message_analyzer.wfp_capture2.v6" );
	proto_ma_wfp_capture_auth_v4 = proto_register_protocol ("Message Analyzer WFP Capture AUTH v4", "MA WFP Capture AUTH v4", "message_analyzer.wfp_capture.auth.v4" );
	proto_ma_wfp_capture_auth_v6 = proto_register_protocol ("Message Analyzer WFP Capture AUTH v6", "MA WFP Capture AUTH v6", "message_analyzer.wfp_capture.auth.v6" );

	proto_register_field_array(proto_ma_wfp_capture_v4, hf_wfp_capture, array_length(hf_wfp_capture));
	proto_register_field_array(proto_ma_wfp_capture_auth_v4, hf_wfp_capture_auth, array_length(hf_wfp_capture_auth));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_message_analyzer(void)
{
	dissector_handle_t ma_wfp_capture_v4_handle, ma_wfp_capture2_v4_handle,
						ma_wfp_capture_v6_handle, ma_wfp_capture2_v6_handle,
						ma_wfp_capture_auth_v4_handle, ma_wfp_capture_auth_v6_handle;

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

	ip_dissector_table = find_dissector_table("ip.proto");

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
