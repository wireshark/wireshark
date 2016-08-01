/*
 * exported_pdu.c
 * exported_pdu helper functions
 * Copyright 2013, Anders Broman <anders-broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include <glib.h>

#include <epan/packet.h>
#include <epan/exported_pdu.h>
#include <epan/address_types.h>
#include <epan/tap.h>

static GSList *export_pdu_tap_name_list = NULL;

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

static int exp_pdu_data_src_ip_populate_data(packet_info *pinfo, void* data _U_, guint8 *tlv_buffer, guint32 buffer_size _U_)
{
	if(pinfo->net_src.type == AT_IPv4){
		tlv_buffer[0] = 0;
		tlv_buffer[1] = EXP_PDU_TAG_IPV4_SRC;
		tlv_buffer[2] = 0;
		tlv_buffer[3] = EXP_PDU_TAG_IPV4_LEN; /* tag length */
		memcpy(tlv_buffer+4, pinfo->net_src.data, EXP_PDU_TAG_IPV4_LEN);
		return 4 + EXP_PDU_TAG_IPV4_LEN;
	}else if(pinfo->net_src.type == AT_IPv6){
		tlv_buffer[0] = 0;
		tlv_buffer[1] = EXP_PDU_TAG_IPV6_SRC;
		tlv_buffer[2] = 0;
		tlv_buffer[3] = EXP_PDU_TAG_IPV6_LEN; /* tag length */
		memcpy(tlv_buffer+4, pinfo->net_src.data, EXP_PDU_TAG_IPV6_LEN);
		return 4 + EXP_PDU_TAG_IPV6_LEN;
	}

	return 0;
}

static int exp_pdu_data_dst_ip_size(packet_info *pinfo, void* data _U_)
{
	return exp_pdu_data_ip_size(&pinfo->net_dst);
}

static int exp_pdu_data_dst_ip_populate_data(packet_info *pinfo, void* data _U_, guint8 *tlv_buffer, guint32 buffer_size _U_)
{
	if(pinfo->net_dst.type == AT_IPv4){
		tlv_buffer[0] = 0;
		tlv_buffer[1] = EXP_PDU_TAG_IPV4_DST;
		tlv_buffer[2] = 0;
		tlv_buffer[3] = EXP_PDU_TAG_IPV4_LEN; /* tag length */
		memcpy(tlv_buffer+4, pinfo->net_dst.data, EXP_PDU_TAG_IPV4_LEN);
		return 4 + EXP_PDU_TAG_IPV4_LEN;
	}else if(pinfo->net_dst.type == AT_IPv6){
		tlv_buffer[0] = 0;
		tlv_buffer[1] = EXP_PDU_TAG_IPV6_DST;
		tlv_buffer[2] = 0;
		tlv_buffer[3] = EXP_PDU_TAG_IPV6_LEN; /* tag length */
		memcpy(tlv_buffer+4, pinfo->net_dst.data, EXP_PDU_TAG_IPV6_LEN);
		return 4 + EXP_PDU_TAG_IPV6_LEN;
	}

	return 0;
}

static int exp_pdu_data_port_type_size(packet_info *pinfo _U_, void* data _U_)
{
	return EXP_PDU_TAG_PORT_LEN + 4;
}

static int exp_pdu_data_port_type_populate_data(packet_info *pinfo, void* data, guint8 *tlv_buffer, guint32 buffer_size _U_)
{
	tlv_buffer[0] = 0;
	tlv_buffer[1] = EXP_PDU_TAG_PORT_TYPE;
	tlv_buffer[2] = 0;
	tlv_buffer[3] = EXP_PDU_TAG_PORT_TYPE_LEN; /* tag length */
	tlv_buffer[4] = (pinfo->ptype & 0xff000000) >> 24;
	tlv_buffer[5] = (pinfo->ptype & 0x00ff0000) >> 16;
	tlv_buffer[6] = (pinfo->ptype & 0x0000ff00) >> 8;
	tlv_buffer[7] = (pinfo->ptype & 0x000000ff);

	return exp_pdu_data_port_type_size(pinfo, data);
}

static int exp_pdu_data_port_size(packet_info *pinfo _U_, void* data _U_)
{
	return EXP_PDU_TAG_PORT_LEN + 4;
}

static int exp_pdu_data_port_populate_data(guint32 port, guint8 porttype, guint8 *tlv_buffer, guint32 buffer_size _U_)
{
	tlv_buffer[0] = 0;
	tlv_buffer[1] = porttype;
	tlv_buffer[2] = 0;
	tlv_buffer[3] = EXP_PDU_TAG_PORT_LEN; /* tag length */
	tlv_buffer[4] = (port & 0xff000000) >> 24;
	tlv_buffer[5] = (port & 0x00ff0000) >> 16;
	tlv_buffer[6] = (port & 0x0000ff00) >> 8;
	tlv_buffer[7] = (port & 0x000000ff);

	return EXP_PDU_TAG_PORT_LEN + 4;
}

static int exp_pdu_data_src_port_populate_data(packet_info *pinfo, void* data _U_, guint8 *tlv_buffer, guint32 buffer_size)
{
	return exp_pdu_data_port_populate_data(pinfo->srcport, EXP_PDU_TAG_SRC_PORT, tlv_buffer, buffer_size);
}

static int exp_pdu_data_dst_port_populate_data(packet_info *pinfo, void* data _U_, guint8 *tlv_buffer, guint32 buffer_size)
{
	return exp_pdu_data_port_populate_data(pinfo->destport, EXP_PDU_TAG_DST_PORT, tlv_buffer, buffer_size);
}

static int exp_pdu_data_orig_frame_num_size(packet_info *pinfo _U_, void* data _U_)
{
	return EXP_PDU_TAG_ORIG_FNO_LEN + 4;
}

static int exp_pdu_data_orig_frame_num_populate_data(packet_info *pinfo, void* data, guint8 *tlv_buffer, guint32 buffer_size _U_)
{
	tlv_buffer[0] = 0;
	tlv_buffer[1] = EXP_PDU_TAG_ORIG_FNO;
	tlv_buffer[2] = 0;
	tlv_buffer[3] = EXP_PDU_TAG_ORIG_FNO_LEN; /* tag length */
	tlv_buffer[4] = (pinfo->num & 0xff000000) >> 24;
	tlv_buffer[5] = (pinfo->num & 0x00ff0000) >> 16;
	tlv_buffer[6] = (pinfo->num & 0x0000ff00) >> 8;
	tlv_buffer[7] = (pinfo->num & 0x000000ff);

	return exp_pdu_data_orig_frame_num_size(pinfo, data);
}

exp_pdu_data_item_t exp_pdu_data_src_ip = {exp_pdu_data_src_ip_size, exp_pdu_data_src_ip_populate_data, NULL};
exp_pdu_data_item_t exp_pdu_data_dst_ip = {exp_pdu_data_dst_ip_size, exp_pdu_data_dst_ip_populate_data, NULL};
exp_pdu_data_item_t exp_pdu_data_port_type = {exp_pdu_data_port_type_size, exp_pdu_data_port_type_populate_data, NULL};
exp_pdu_data_item_t exp_pdu_data_src_port = {exp_pdu_data_port_size, exp_pdu_data_src_port_populate_data, NULL};
exp_pdu_data_item_t exp_pdu_data_dst_port = {exp_pdu_data_port_size, exp_pdu_data_dst_port_populate_data, NULL};
exp_pdu_data_item_t exp_pdu_data_orig_frame_num = {exp_pdu_data_orig_frame_num_size, exp_pdu_data_orig_frame_num_populate_data, NULL};

exp_pdu_data_t *export_pdu_create_common_tags(packet_info *pinfo, const char *proto_name, guint16 tag_type)
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
export_pdu_create_tags(packet_info *pinfo, const char* proto_name, guint16 tag_type, const exp_pdu_data_item_t **items_list)
{
	exp_pdu_data_t *exp_pdu_data;
	const exp_pdu_data_item_t **loop_items = items_list;
	int tag_buf_size = 0;
	int proto_str_len, proto_tag_len, buf_remaining, item_size;
	guint8* buffer_data;

	DISSECTOR_ASSERT(proto_name != NULL);
	DISSECTOR_ASSERT((tag_type == EXP_PDU_TAG_PROTO_NAME) || (tag_type == EXP_PDU_TAG_HEUR_PROTO_NAME) || (tag_type == EXP_PDU_TAG_DISSECTOR_TABLE_NAME));

	exp_pdu_data = (exp_pdu_data_t *)g_malloc(sizeof(exp_pdu_data_t));

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

	exp_pdu_data->tlv_buffer = (guint8 *)g_malloc0(tag_buf_size);
	exp_pdu_data->tlv_buffer_len = tag_buf_size;

	buffer_data = exp_pdu_data->tlv_buffer;
	buf_remaining = exp_pdu_data->tlv_buffer_len;

	/* Start by adding protocol name as a tag */
	buffer_data[0] = (tag_type & 0xff00) >> 8;
	buffer_data[1] = tag_type & 0x00ff;
	buffer_data[2] = (proto_tag_len & 0xff00) >> 8;
	buffer_data[3] = proto_tag_len & 0x00ff; /* tag length */
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

gint
register_export_pdu_tap(const char *name)
{
	gchar *tap_name = g_strdup(name);
	export_pdu_tap_name_list = g_slist_prepend(export_pdu_tap_name_list, tap_name);
	return register_tap(tap_name);
}

static
gint sort_pdu_tap_name_list(gconstpointer a, gconstpointer b)
{
	return g_strcmp0((const char *)a, (const char*)b);
}

GSList *
get_export_pdu_tap_list(void)
{
	export_pdu_tap_name_list = g_slist_sort(export_pdu_tap_name_list, sort_pdu_tap_name_list);
	return export_pdu_tap_name_list;
}

void export_pdu_init(void)
{
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
