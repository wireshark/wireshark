/* 
 * exported_pdu.c
 * exported_pdu helper functions
 * Copyright 2013, Anders Broman <anders-broman@ericsson.com>
 *
 * $Id$
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

/**
 * Allocates and fills the exp_pdu_data_t struct according to the wanted_exp_tags
 * bit_fileld, if proto_name is != NULL, wtap_encap must be -1 or vice-versa
 */
exp_pdu_data_t *
load_export_pdu_tags(packet_info *pinfo, const char* proto_name, int wtap_encap _U_, guint32 tags_bit_field)
{
	exp_pdu_data_t *exp_pdu_data;
	int tag_buf_size = 0;
	int str_len = 0;
	int tag_str_len = 0;
	int i = 0;

	exp_pdu_data = (exp_pdu_data_t *)g_malloc(sizeof(exp_pdu_data_t));

	/* If we have a protocol name, calculate the buffer size needed including padding and tag + length */
	if(proto_name){
		str_len = (int)strlen(proto_name);

		/* Ensure that tag length is a multiple of 4 bytes */
		tag_str_len = (str_len + 3) & 0xfffffffc;
		/* Add Tag + length */
		tag_buf_size = tag_str_len + 4;
	}

	if((tags_bit_field & EXP_PDU_TAG_IP_SRC_BIT) == EXP_PDU_TAG_IP_SRC_BIT){
		/* tag+length */
		tag_buf_size+=4;
		if(pinfo->net_src.type == AT_IPv4){
			tag_buf_size = tag_buf_size + EXP_PDU_TAG_IPV4_SRC_LEN;
		}else{
			tag_buf_size = tag_buf_size + EXP_PDU_TAG_IPV6_SRC_LEN;
		}
	}

	if((tags_bit_field & EXP_PDU_TAG_IP_DST_BIT) == EXP_PDU_TAG_IP_DST_BIT){
		/* tag+length */
		tag_buf_size+=4;
		if(pinfo->net_dst.type == AT_IPv4){
			tag_buf_size = tag_buf_size + EXP_PDU_TAG_IPV4_DST_LEN;
		}else{
			tag_buf_size = tag_buf_size + EXP_PDU_TAG_IPV6_DST_LEN;
		}
	}

	if((tags_bit_field & EXP_PDU_TAG_SRC_PORT_BIT) == EXP_PDU_TAG_SRC_PORT_BIT){
		tag_buf_size= tag_buf_size + EXP_PDU_TAG_SRC_PORT_LEN + 4;
	}

	if((tags_bit_field & EXP_PDU_TAG_DST_PORT_BIT) == EXP_PDU_TAG_DST_PORT_BIT){
		tag_buf_size= tag_buf_size + EXP_PDU_TAG_DST_PORT_LEN + 4;
	}

	if((tags_bit_field & EXP_PDU_TAG_ORIG_FNO_BIT) == EXP_PDU_TAG_ORIG_FNO_BIT){
		tag_buf_size= tag_buf_size + EXP_PDU_TAG_ORIG_FNO_LEN + 4;
	}

	/* Add end of options length */
	tag_buf_size+=4;

	exp_pdu_data->tlv_buffer = (guint8 *)g_malloc0(tag_buf_size);
	exp_pdu_data->tlv_buffer_len = tag_buf_size;

	if(proto_name){
		exp_pdu_data->tlv_buffer[i] = 0;
		i++;
		exp_pdu_data->tlv_buffer[i] = EXP_PDU_TAG_PROTO_NAME;
		i++;
		exp_pdu_data->tlv_buffer[i] = 0;
		i++;
		exp_pdu_data->tlv_buffer[i] = tag_str_len; /* tag length */
		i++;
		memcpy(exp_pdu_data->tlv_buffer+i, proto_name, str_len);
		i = i + tag_str_len;

	}

	if((tags_bit_field & EXP_PDU_TAG_IP_SRC_BIT) == EXP_PDU_TAG_IP_SRC_BIT){
		if(pinfo->net_src.type == AT_IPv4){
			exp_pdu_data->tlv_buffer[i] = 0;
			i++;
			exp_pdu_data->tlv_buffer[i] = EXP_PDU_TAG_IPV4_SRC;
			i++;
			exp_pdu_data->tlv_buffer[i] = 0;
			i++;
			exp_pdu_data->tlv_buffer[i] = EXP_PDU_TAG_IPV4_SRC_LEN; /* tag length */
			i++;
		}else{
			exp_pdu_data->tlv_buffer[i] = 0;
			i++;
			exp_pdu_data->tlv_buffer[i] = EXP_PDU_TAG_IPV6_SRC;
			i++;
			exp_pdu_data->tlv_buffer[i] = 0;
			i++;
			exp_pdu_data->tlv_buffer[i] = EXP_PDU_TAG_IPV6_SRC_LEN; /* tag length */
			i++;
		}

		memcpy(exp_pdu_data->tlv_buffer+i, pinfo->net_src.data, pinfo->net_src.len);
		i += (pinfo->net_src.type == AT_IPv4) ? EXP_PDU_TAG_IPV4_SRC_LEN : EXP_PDU_TAG_IPV6_SRC_LEN;
	}

	if((tags_bit_field & EXP_PDU_TAG_IP_DST_BIT) == EXP_PDU_TAG_IP_DST_BIT){
		if(pinfo->net_dst.type == AT_IPv4){
			exp_pdu_data->tlv_buffer[i] = 0;
			i++;
			exp_pdu_data->tlv_buffer[i] = EXP_PDU_TAG_IPV4_DST;
			i++;
			exp_pdu_data->tlv_buffer[i] = 0;
			i++;
			exp_pdu_data->tlv_buffer[i] = EXP_PDU_TAG_IPV4_DST_LEN; /* tag length */
			i++;
		}else{
			exp_pdu_data->tlv_buffer[i] = 0;
			i++;
			exp_pdu_data->tlv_buffer[i] = EXP_PDU_TAG_IPV6_DST;
			i++;
			exp_pdu_data->tlv_buffer[i] = 0;
			i++;
			exp_pdu_data->tlv_buffer[i] = EXP_PDU_TAG_IPV6_DST_LEN; /* tag length */
			i++;
		}

		memcpy(exp_pdu_data->tlv_buffer+i, pinfo->net_dst.data, pinfo->net_dst.len);
		i += (pinfo->net_dst.type == AT_IPv4) ? EXP_PDU_TAG_IPV4_DST_LEN : EXP_PDU_TAG_IPV6_DST_LEN;
	}

	if((tags_bit_field & EXP_PDU_TAG_SRC_PORT_BIT) == EXP_PDU_TAG_SRC_PORT_BIT){
			exp_pdu_data->tlv_buffer[i] = 0;
			i++;
			exp_pdu_data->tlv_buffer[i] = EXP_PDU_TAG_SRC_PORT;
			i++;
			exp_pdu_data->tlv_buffer[i] = 0;
			i++;
			exp_pdu_data->tlv_buffer[i] = EXP_PDU_TAG_SRC_PORT_LEN; /* tag length */
			i++;
			exp_pdu_data->tlv_buffer[i]   = (pinfo->srcport & 0xff000000) >> 24;
			exp_pdu_data->tlv_buffer[i+1] = (pinfo->srcport & 0x00ff0000) >> 16;
			exp_pdu_data->tlv_buffer[i+2] = (pinfo->srcport & 0x0000ff00) >> 8;
			exp_pdu_data->tlv_buffer[i+3] = (pinfo->srcport & 0x000000ff);
			i = i +EXP_PDU_TAG_SRC_PORT_LEN;
	}

	if((tags_bit_field & EXP_PDU_TAG_DST_PORT_BIT) == EXP_PDU_TAG_DST_PORT_BIT){
			exp_pdu_data->tlv_buffer[i] = 0;
			i++;
			exp_pdu_data->tlv_buffer[i] = EXP_PDU_TAG_DST_PORT;
			i++;
			exp_pdu_data->tlv_buffer[i] = 0;
			i++;
			exp_pdu_data->tlv_buffer[i] = EXP_PDU_TAG_DST_PORT_LEN; /* tag length */
			i++;
			exp_pdu_data->tlv_buffer[i]   = (pinfo->destport & 0xff000000) >> 24;
			exp_pdu_data->tlv_buffer[i+1] = (pinfo->destport & 0x00ff0000) >> 16;
			exp_pdu_data->tlv_buffer[i+2] = (pinfo->destport & 0x0000ff00) >> 8;
			exp_pdu_data->tlv_buffer[i+3] = (pinfo->destport & 0x000000ff);
			i = i +EXP_PDU_TAG_DST_PORT_LEN;
	}

	if((tags_bit_field & EXP_PDU_TAG_ORIG_FNO_BIT) == EXP_PDU_TAG_ORIG_FNO_BIT){
			exp_pdu_data->tlv_buffer[i] = 0;
			i++;
			exp_pdu_data->tlv_buffer[i] = EXP_PDU_TAG_ORIG_FNO;
			i++;
			exp_pdu_data->tlv_buffer[i] = 0;
			i++;
			exp_pdu_data->tlv_buffer[i] = EXP_PDU_TAG_ORIG_FNO_LEN; /* tag length */
			i++;
			exp_pdu_data->tlv_buffer[i]   = (pinfo->fd->num & 0xff000000) >> 24;
			exp_pdu_data->tlv_buffer[i+1] = (pinfo->fd->num & 0x00ff0000) >> 16;
			exp_pdu_data->tlv_buffer[i+2] = (pinfo->fd->num & 0x0000ff00) >> 8;
			exp_pdu_data->tlv_buffer[i+3] = (pinfo->fd->num & 0x000000ff);
			/*i = i +EXP_PDU_TAG_ORIG_FNO_LEN;*/
	}

	return exp_pdu_data;

}
