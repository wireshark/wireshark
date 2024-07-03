/*
 * exported_pdu.c
 * exported_pdu helper functions
 * Copyright 2013, Anders Broman <anders-broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <glib.h>

#include <epan/packet.h>
#include <epan/exported_pdu.h>
#include <epan/address_types.h>
#include <epan/tap.h>
#include <wiretap/wtap.h>

#include <wsutil/pint.h>

static GSList *export_pdu_tap_name_list;
static wmem_map_t *export_pdu_encap_table;

static int exp_pdu_data_ip_size(const address* addr)
{
	if (addr->type == AT_IPv4){
		return 4 + EXP_PDU_TAG_IPV4_LEN;
	} else if(addr->type == AT_IPv6){
		return 4 + EXP_PDU_TAG_IPV6_LEN;
	}

	return 0;
}

static int exp_pdu_data_src_ip_size(packet_info *pinfo, void* data _U_)
{
	return exp_pdu_data_ip_size(&pinfo->net_src);
}

static int exp_pdu_data_src_ip_populate_data(packet_info *pinfo, void* data _U_, uint8_t *tlv_buffer, uint32_t buffer_size _U_)
{
	if(pinfo->net_src.type == AT_IPv4){
		phton16(tlv_buffer+0, EXP_PDU_TAG_IPV4_SRC);
		phton16(tlv_buffer+2, EXP_PDU_TAG_IPV4_LEN); /* tag length */
		memcpy(tlv_buffer+4, pinfo->net_src.data, EXP_PDU_TAG_IPV4_LEN);
		return 4 + EXP_PDU_TAG_IPV4_LEN;
	}else if(pinfo->net_src.type == AT_IPv6){
		phton16(tlv_buffer+0, EXP_PDU_TAG_IPV6_SRC);
		phton16(tlv_buffer+2, EXP_PDU_TAG_IPV6_LEN); /* tag length */
		memcpy(tlv_buffer+4, pinfo->net_src.data, EXP_PDU_TAG_IPV6_LEN);
		return 4 + EXP_PDU_TAG_IPV6_LEN;
	}

	return 0;
}

static int exp_pdu_data_dst_ip_size(packet_info *pinfo, void* data _U_)
{
	return exp_pdu_data_ip_size(&pinfo->net_dst);
}

static int exp_pdu_data_dst_ip_populate_data(packet_info *pinfo, void* data _U_, uint8_t *tlv_buffer, uint32_t buffer_size _U_)
{
	if(pinfo->net_dst.type == AT_IPv4){
		phton16(tlv_buffer+0, EXP_PDU_TAG_IPV4_DST);
		phton16(tlv_buffer+2, EXP_PDU_TAG_IPV4_LEN); /* tag length */
		memcpy(tlv_buffer+4, pinfo->net_dst.data, EXP_PDU_TAG_IPV4_LEN);
		return 4 + EXP_PDU_TAG_IPV4_LEN;
	}else if(pinfo->net_dst.type == AT_IPv6){
		phton16(tlv_buffer+0, EXP_PDU_TAG_IPV6_DST);
		phton16(tlv_buffer+2, EXP_PDU_TAG_IPV6_LEN); /* tag length */
		memcpy(tlv_buffer+4, pinfo->net_dst.data, EXP_PDU_TAG_IPV6_LEN);
		return 4 + EXP_PDU_TAG_IPV6_LEN;
	}

	return 0;
}

static int exp_pdu_data_port_type_size(packet_info *pinfo _U_, void* data _U_)
{
	return EXP_PDU_TAG_PORT_LEN + 4;
}

static unsigned exp_pdu_ws_port_type_to_exp_pdu_port_type(port_type pt)
{
	switch (pt)
	{
	case PT_NONE:
		return EXP_PDU_PT_NONE;
	case PT_SCTP:
		return EXP_PDU_PT_SCTP;
	case PT_TCP:
		return EXP_PDU_PT_TCP;
	case PT_UDP:
		return EXP_PDU_PT_UDP;
	case PT_DCCP:
		return EXP_PDU_PT_DCCP;
	case PT_IPX:
		return EXP_PDU_PT_IPX;
	case PT_DDP:
		return EXP_PDU_PT_DDP;
	case PT_IDP:
		return EXP_PDU_PT_IDP;
	case PT_USB:
		return EXP_PDU_PT_USB;
	case PT_I2C:
		return EXP_PDU_PT_I2C;
	case PT_IBQP:
		return EXP_PDU_PT_IBQP;
	case PT_BLUETOOTH:
		return EXP_PDU_PT_BLUETOOTH;
	case PT_IWARP_MPA:
		return EXP_PDU_PT_IWARP_MPA;
	case PT_MCTP:
		return EXP_PDU_PT_MCTP;
	}

	DISSECTOR_ASSERT(false);
	return EXP_PDU_PT_NONE;
}

static int exp_pdu_data_port_type_populate_data(packet_info *pinfo, void* data, uint8_t *tlv_buffer, uint32_t buffer_size _U_)
{
	unsigned pt;

	phton16(tlv_buffer+0, EXP_PDU_TAG_PORT_TYPE);
	phton16(tlv_buffer+2, EXP_PDU_TAG_PORT_TYPE_LEN); /* tag length */
	pt = exp_pdu_ws_port_type_to_exp_pdu_port_type(pinfo->ptype);
	phton32(tlv_buffer+4, pt);

	return exp_pdu_data_port_type_size(pinfo, data);
}

static int exp_pdu_data_port_size(packet_info *pinfo _U_, void* data _U_)
{
	return EXP_PDU_TAG_PORT_LEN + 4;
}

static int exp_pdu_data_port_populate_data(uint32_t port, uint8_t porttype, uint8_t *tlv_buffer, uint32_t buffer_size _U_)
{
	phton16(tlv_buffer+0, porttype);
	phton16(tlv_buffer+2, EXP_PDU_TAG_PORT_LEN); /* tag length */
	phton32(tlv_buffer+4, port);

	return EXP_PDU_TAG_PORT_LEN + 4;
}

static int exp_pdu_data_src_port_populate_data(packet_info *pinfo, void* data _U_, uint8_t *tlv_buffer, uint32_t buffer_size)
{
	return exp_pdu_data_port_populate_data(pinfo->srcport, EXP_PDU_TAG_SRC_PORT, tlv_buffer, buffer_size);
}

static int exp_pdu_data_dst_port_populate_data(packet_info *pinfo, void* data _U_, uint8_t *tlv_buffer, uint32_t buffer_size)
{
	return exp_pdu_data_port_populate_data(pinfo->destport, EXP_PDU_TAG_DST_PORT, tlv_buffer, buffer_size);
}

static int exp_pdu_data_orig_frame_num_size(packet_info *pinfo _U_, void* data _U_)
{
	return EXP_PDU_TAG_ORIG_FNO_LEN + 4;
}

static int exp_pdu_data_orig_frame_num_populate_data(packet_info *pinfo, void* data, uint8_t *tlv_buffer, uint32_t buffer_size _U_)
{
	phton16(tlv_buffer+0, EXP_PDU_TAG_ORIG_FNO);
	phton16(tlv_buffer+2, EXP_PDU_TAG_ORIG_FNO_LEN); /* tag length */
	phton32(tlv_buffer+4, pinfo->num);

	return exp_pdu_data_orig_frame_num_size(pinfo, data);
}

WS_DLL_PUBLIC int exp_pdu_data_dissector_table_num_value_size(packet_info *pinfo _U_, void* data _U_)
{
	return EXP_PDU_TAG_DISSECTOR_TABLE_NUM_VAL_LEN + 4;
}

WS_DLL_PUBLIC int exp_pdu_data_dissector_table_num_value_populate_data(packet_info *pinfo _U_, void* data, uint8_t *tlv_buffer, uint32_t buffer_size _U_)
{
	uint32_t value = GPOINTER_TO_UINT(data);

	phton16(tlv_buffer+0, EXP_PDU_TAG_DISSECTOR_TABLE_NAME_NUM_VAL);
	phton16(tlv_buffer+2, EXP_PDU_TAG_DISSECTOR_TABLE_NUM_VAL_LEN); /* tag length */
	phton32(tlv_buffer+4, value);

	return exp_pdu_data_dissector_table_num_value_size(pinfo, data);
}


exp_pdu_data_item_t exp_pdu_data_src_ip = {exp_pdu_data_src_ip_size, exp_pdu_data_src_ip_populate_data, NULL};
exp_pdu_data_item_t exp_pdu_data_dst_ip = {exp_pdu_data_dst_ip_size, exp_pdu_data_dst_ip_populate_data, NULL};
exp_pdu_data_item_t exp_pdu_data_port_type = {exp_pdu_data_port_type_size, exp_pdu_data_port_type_populate_data, NULL};
exp_pdu_data_item_t exp_pdu_data_src_port = {exp_pdu_data_port_size, exp_pdu_data_src_port_populate_data, NULL};
exp_pdu_data_item_t exp_pdu_data_dst_port = {exp_pdu_data_port_size, exp_pdu_data_dst_port_populate_data, NULL};
exp_pdu_data_item_t exp_pdu_data_orig_frame_num = {exp_pdu_data_orig_frame_num_size, exp_pdu_data_orig_frame_num_populate_data, NULL};

exp_pdu_data_t *export_pdu_create_common_tags(packet_info *pinfo, const char *proto_name, uint16_t tag_type)
{
	const exp_pdu_data_item_t *common_exp_pdu_items[] = {
		&exp_pdu_data_src_ip,
		&exp_pdu_data_dst_ip,
		&exp_pdu_data_port_type,
		&exp_pdu_data_src_port,
		&exp_pdu_data_dst_port,
		&exp_pdu_data_orig_frame_num,
		NULL
	};

	return export_pdu_create_tags(pinfo, proto_name, tag_type, common_exp_pdu_items);
}

/**
 * Allocates and fills the exp_pdu_data_t struct according to the list of items
 *
 * The tags in the tag buffer SHOULD be added in numerical order.
 */
exp_pdu_data_t *
export_pdu_create_tags(packet_info *pinfo, const char* proto_name, uint16_t tag_type, const exp_pdu_data_item_t **items_list)
{
	exp_pdu_data_t *exp_pdu_data;
	const exp_pdu_data_item_t **loop_items = items_list;
	int tag_buf_size = 0;
	int proto_str_len, proto_tag_len, buf_remaining, item_size;
	uint8_t* buffer_data;

	DISSECTOR_ASSERT(proto_name != NULL);
	DISSECTOR_ASSERT((tag_type == EXP_PDU_TAG_DISSECTOR_NAME) || (tag_type == EXP_PDU_TAG_HEUR_DISSECTOR_NAME) || (tag_type == EXP_PDU_TAG_DISSECTOR_TABLE_NAME));

	exp_pdu_data = wmem_new(pinfo->pool, exp_pdu_data_t);

	/* Start by computing size of protocol name as a tag */
	proto_str_len = (int)strlen(proto_name);

	/* Ensure that tag length is a multiple of 4 bytes */
	proto_tag_len = ((proto_str_len + 3) & 0xfffffffc);

	/* Add Tag + length */
	tag_buf_size += (proto_tag_len + 4);

	/* Compute size of items */
	while (*loop_items) {
		tag_buf_size += (*loop_items)->size_func(pinfo, (*loop_items)->data);
		loop_items++;
	}

	/* Add end of options length */
	tag_buf_size+=4;

	exp_pdu_data->tlv_buffer = (uint8_t *)wmem_alloc0(pinfo->pool, tag_buf_size);
	exp_pdu_data->tlv_buffer_len = tag_buf_size;

	buffer_data = exp_pdu_data->tlv_buffer;
	buf_remaining = exp_pdu_data->tlv_buffer_len;

	/* Start by adding protocol name as a tag */
	phton16(buffer_data+0, tag_type);
	phton16(buffer_data+2, proto_tag_len); /* tag length */
	memcpy(buffer_data+4, proto_name, proto_str_len);
	buffer_data += (proto_tag_len+4);
	buf_remaining -= (proto_tag_len+4);

	/* Populate data */
	loop_items = items_list;
	while (*loop_items) {
		item_size = (*loop_items)->populate_data(pinfo, (*loop_items)->data, buffer_data, buf_remaining);
		buffer_data += item_size;
		buf_remaining -= item_size;
		loop_items++;
	}

	return exp_pdu_data;
}

int
register_export_pdu_tap_with_encap(const char *name, int encap)
{
	char *tap_name = g_strdup(name);
	export_pdu_tap_name_list = g_slist_prepend(export_pdu_tap_name_list, tap_name);
	wmem_map_insert(export_pdu_encap_table, tap_name, GINT_TO_POINTER(encap));
	return register_tap(tap_name);
}

int
register_export_pdu_tap(const char *name)
{
#if 0
	/* XXX: We could register it like this, but don't have to, since
	 * export_pdu_tap_get_encap() returns WTAP_ENCAP_WIRESHARK_UPPER_PDU
	 * if it's not in the encap hash table anyway.
	 */
	return register_export_pdu_tap_with_encap(name, WTAP_ENCAP_WIRESHARK_UPPER_PDU);
#endif
	char *tap_name = g_strdup(name);
	export_pdu_tap_name_list = g_slist_prepend(export_pdu_tap_name_list, tap_name);
	return register_tap(tap_name);
}

static
int sort_pdu_tap_name_list(const void *a, const void *b)
{
	return g_strcmp0((const char *)a, (const char*)b);
}

GSList *
get_export_pdu_tap_list(void)
{
	export_pdu_tap_name_list = g_slist_sort(export_pdu_tap_name_list, sort_pdu_tap_name_list);
	return export_pdu_tap_name_list;
}

int
export_pdu_tap_get_encap(const char* name)
{
	void *value;
	if (wmem_map_lookup_extended(export_pdu_encap_table, name, NULL, &value)) {
		return GPOINTER_TO_INT(value);
	}

	return WTAP_ENCAP_WIRESHARK_UPPER_PDU;
}

void export_pdu_init(void)
{
	export_pdu_encap_table = wmem_map_new(wmem_epan_scope(), wmem_str_hash, g_str_equal);
}

void export_pdu_cleanup(void)
{
	g_slist_free_full(export_pdu_tap_name_list, g_free);
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
