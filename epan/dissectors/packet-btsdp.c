/* packet-btsdp.c
 * Routines for Bluetooth SDP dissection
 * Copyright 2002, Wolfgang Hansmann <hansmann@cs.uni-bonn.de>
 *
 * Refactored for wireshark checkin
 *   Ronnie Sahlberg 2006
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <etypes.h>
#include <epan/tap.h>
#include "packet-btsdp.h"
#include "packet-btl2cap.h"

/* Initialize the protocol and registered fields */
static int proto_btsdp = -1;
static int hf_pduid = -1;
static int hf_tid = -1;
static int hf_plen = -1;
static int hf_ssr_total_count = -1;
static int hf_ssr_current_count = -1;
static int hf_error_code = -1;
static int hf_ssares_al_bytecount = -1;


/* Initialize the subtree pointers */
static gint ett_btsdp = -1;
static gint ett_btsdp_ssr = -1;
static gint ett_btsdp_des = -1;
static gint ett_btsdp_attribute = -1;
static gint ett_btsdp_service_search_pattern = -1;
static gint ett_btsdp_attribute_idlist = -1;

static int btsdp_tap = -1;

/* This table maps rfcomm service channels and dynamic l2cap
 * PSM's to profile service uuids.
 * The same table is used both for local and remote servers.
 * For received CIDs we mask the cid with 0x8000 in this table
 */
static emem_tree_t *service_table = NULL;

static const value_string vs_pduid[] = {
	{0x1, "Error Response"},
	{0x2, "Service Search Request"},
	{0x3, "Service Search Response"},
	{0x4, "Service Attribute Request"},
	{0x5, "Service Attribute Response"},
	{0x6, "Service Search Attribute Request"},
	{0x7, "Service Search Attribute Response"},
	{0, NULL}
};

#define ATTR_ID_SERVICE_CLASS_ID_LIST			0x0001
#define ATTR_ID_PROTOCOL_DESCRIPTOR_LIST		0x0004
#define ATTR_ID_BT_PROFILE_DESCRIPTOR_LIST		0x0009
#define ATTR_ID_ADDITIONAL_PROTOCOL_DESCRIPTOR_LISTS	0x000d
#define ATTR_ID_GOEP_L2CAP_PSM_GROUP_ID_IP_SUBNET	0x0200

static const value_string vs_general_attribute_id[] = {
	{0x0000, "Service Record Handle"},
	{0x0001, "Service Class ID List"},
	{0x0002, "Service Record State"},
	{0x0003, "Service ID"},
	{0x0004, "Protocol Descriptor List"},
	{0x0005, "Browse Group List"},
	{0x0006, "Language Base Attribute ID List"},
	{0x0007, "Serviceinfo Time To Live"},
	{0x0008, "Service Availability"},
	{0x0009, "Bluetooth Profile Descriptor List"},
	{0x000a, "Documentation URL"},
	{0x000b, "Client Executable URL"},
	{0x000c, "Icon URL"},
	{0x000d, "Additional Protocol Descriptor Lists"},
	{0x0100, "Service Name"},
	{0x0101, "Service Description"},
	{0x0102, "Provider Name"},
	{0x0200, "GOEP L2CAP PSM/Group Id/IP Subnet"},
	{0x0201, "Service Database State"},
	{0x0300, "Service Version"},
	{0x0301, "Data Exchange Spec/Network/Supported Data Stores List"},
	{0x0302, "Remote Audio Volume Control/MCAP Supported Features"},
	{0x0303, "Supported Formats"},
	{0x0304, "Fax Class 2 Support"},
	{0x0305, "Audio Feedback Support"},
	{0x0306, "Network Address"},
	{0x0307, "WAP Gateway"},
	{0x0308, "Home Page URL"},
	{0x0309, "WAP Stack Type"},
	{0x030a, "Security Description"},
	{0x030b, "Net Access Type"},
	{0x030c, "Max Net Accessrate"},
	{0x030d, "IPv4 Subnet"},
	{0x030e, "IPv6 Subnet"},
	{0x0310, "Supported Capabilities"},
	{0x0311, "Supported Features"},
	{0x0312, "Supported Functions"},
	{0x0313, "Total Imaging Data Capacity"},
	{0x0314, "Supported Repositories"},
	{0x0315, "MAS Instance ID"},
	{0x0316, "Supported Message Types"},
	{0, NULL}
};

static int
get_type_length(tvbuff_t *tvb, int offset, int *length)
{
	int size = 0;
	guint8 byte0 = tvb_get_guint8(tvb, offset);
	offset++;

	switch (byte0 & 0x07) {
	case 0:
		size = (byte0 >> 3) == 0 ? 0 : 1;
		break;
	case 1:
		size = 2;
		break;
	case 2:
		size = 4;
		break;
	case 3:
		size = 8;
		break;
	case 4:
		size = 16;
		break;
	case 5:
		size = tvb_get_guint8(tvb, offset);
		offset++;
		break;
	case 6:
		size = tvb_get_ntohs(tvb, offset);
		offset += 2;
		break;
	case 7:
		size = tvb_get_ntohl(tvb, offset);
		offset += 4;
		break;
	}

	*length = size;
	return offset;
}


static guint32
get_uint_by_size(tvbuff_t *tvb, int off, int size)
{
	switch(size) {
	case 0:
		return tvb_get_guint8(tvb, off);
	case 1:
		return tvb_get_ntohs(tvb, off);
	case 2:
		return tvb_get_ntohl(tvb, off);
	default:
		return 0xffffffff;
	}
}


static gint32
get_int_by_size(tvbuff_t *tvb, int off, int size)
{
	switch(size) {
	case 0:
		return tvb_get_guint8(tvb, off);
	case 1:
		return tvb_get_ntohs(tvb, off);
	case 2:
		return tvb_get_ntohl(tvb, off);
	default:
		return -1;
	}
}


static int
dissect_attribute_id_list(proto_tree *t, tvbuff_t *tvb, int offset, packet_info *pinfo)
{
	proto_item *ti;
	proto_tree *st;
	int start_offset, bytes_to_go;
	guint16 id;
	const char *att_name;

	start_offset=offset;
	ti = proto_tree_add_text(t, tvb, offset, 2, "Attribute ID List");
	st = proto_item_add_subtree(ti, ett_btsdp_attribute_idlist);

	offset = get_type_length(tvb, offset, &bytes_to_go);
	proto_item_set_len(ti, offset - start_offset + bytes_to_go);

	while(bytes_to_go>0){
		guint8 byte0 = tvb_get_guint8(tvb, offset);

		if (byte0 == 0x09) { /* 16 bit attribute id */

			id = tvb_get_ntohs(tvb, offset+1);
			att_name = val_to_str(id, vs_general_attribute_id, "Unknown");
			proto_tree_add_text(st, tvb, offset, 3, "%s (0x%04x)", att_name, id);
			offset+=3;
			bytes_to_go-=3;

			col_append_fstr(pinfo->cinfo, COL_INFO, " (%s) ", att_name);

		} else if (byte0 == 0x0a) { /* 32 bit attribute range */
			col_append_fstr(pinfo->cinfo, COL_INFO, " (0x%04x - 0x%04x) ",
							tvb_get_ntohs(tvb, offset + 1), tvb_get_ntohs(tvb, offset + 3));

			proto_tree_add_text(st, tvb, offset, 5, "0x%04x - 0x%04x",
					    tvb_get_ntohs(tvb, offset + 1),
					    tvb_get_ntohs(tvb, offset + 3));
			offset+=5;
			bytes_to_go-=5;
		} else {
			break;
		}
	}
	return offset - start_offset;
}


static int
dissect_sdp_error_response(proto_tree *t, tvbuff_t *tvb, int offset) {

	proto_tree_add_item(t, hf_error_code, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;

	return offset;
}

static int
get_sdp_data_element(tvbuff_t *tvb, int offset, guint16 id, guint8 *type, void **val, guint32 *service, guint32 *service_val)
{
	int size, start_offset, type_size;
	guint8 byte0;
	/* guint8 size_index; */

	byte0=tvb_get_guint8(tvb, offset);
	*type = (byte0>>3) & 0x1f;
	/* size_index = byte0 & 0x07; set but not used, so commented out */

	/* Initialize the rest of the outputs */
	*val = NULL;
	*service = 0;
	*service_val = 0;

	start_offset=offset;
	offset = get_type_length(tvb, offset, &size);
	type_size = offset - start_offset + size;

	switch (*type) {
	case 0: { /* null */
		*val = NULL;
		break;
	}
	case 1: /* unsigned integer */
	case 2: /* signed integer */
	case 3: { /* uuid */
		*val = ep_alloc(size);

		if (size == 1) {
			*((guint8 *) *val) = tvb_get_guint8(tvb, offset);
		}
		else if (size == 2) {
			*((guint16 *) *val) = tvb_get_ntohs(tvb, offset);
		}
		else if  (size == 4) {
			*((guint32 *) *val) = tvb_get_ntohl(tvb, offset);
		}
		else if (size == 8) {
			*((guint64 *) *val) = tvb_get_ntoh64(tvb, offset);
		}
		else if (size == 16) {
			/* store the short UUID part of the 128-bit base UUID */
			*((guint32 *) *val) = tvb_get_ntohl(tvb, offset);
		}
		break;
	}
	case 8:	/* fall through */
	case 4: {
		*val = tvb_bytes_to_str(tvb, offset, size);
		break;
	}
	case 5: {
		*val = ep_alloc(sizeof(type_size));
		*((guint8 *) *val) = tvb_get_guint8(tvb, offset);
		break;
	}
	case 6: /* Data Element sequence */
	case 7: /* Data Element alternative */ {
		gboolean flag = FALSE;
		int bytes_to_go = size;
		int len;
		guint32 value = 0;

		while(bytes_to_go > 0) {
			size = get_sdp_data_element(tvb, offset, id, type, val, service, service_val);
			if (size < 1 || *val == NULL) {
				break;
			}

			get_type_length(tvb, offset, &len);
			offset += size;
			bytes_to_go -= size;

			if( len == 1 ) {
				value = *((guint8 *) *val);
			}
			else if( len == 2 ) {
				value = *((guint16 *) *val);
			}
			else if ( len == 4 ) {
				value = *((guint32 *) *val);
			}
			else if ( len == 16 ) {
				value = *((guint32 *) *val);
			}

			/* pick special values of interest */
			/* protocol or additional protocol list with UUID values for L2CAP or RFCOMM */
			if ( ((id == 4) || (id == 0xd)) && (*type == 3) && ((value == 0x100) || (value == 0x0003)) ) {
				*service = value;
				flag = TRUE;
			}
			/* profile descriptor list with UUID */
			else if ( (id == 9) && (*type == 3) ) {
				*service = value;
				flag = TRUE;
			}
			/* service class id list with UUID */
			else if ( (id == 1) && (*type == 3) ) {
				*service = value;
				flag = TRUE;
			}
			/* unsigned int found after value of interest */
			else if ( (flag == TRUE) && *type == 1) {
				*service_val = value;
				flag = FALSE;
			}
			else {
				flag = FALSE;
			}
		}
		break;
	}
	}

	return type_size;
}


static int
dissect_sdp_type(proto_tree *t, tvbuff_t *tvb, int offset, char **attr_val)
{
#define MAX_SDP_LEN 1024
	int strpos=0, size, start_offset, type_size;
	char *str;
	guint8 byte0;
	guint8 type;
	guint8 size_index;

	str=ep_alloc(MAX_SDP_LEN+1);
	*attr_val=str;
	str[0]=0;

	byte0=tvb_get_guint8(tvb, offset);
	type=(byte0>>3)&0x1f;
	size_index=byte0&0x07;

	start_offset=offset;
	offset = get_type_length(tvb, offset, &size);
	type_size = offset - start_offset + size;


	switch (type) {
	case 0:
		proto_tree_add_text(t, tvb, start_offset, type_size, "Nil ");
		if(strpos<MAX_SDP_LEN){
			/* strpos+= */ g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "Nil ");
		}
		break;
	case 1: {
		guint32 val = get_uint_by_size(tvb, offset, size_index);
		proto_tree_add_text(t, tvb, start_offset, type_size,
				    "unsigned int %d ", val);
		if(strpos<MAX_SDP_LEN){
			/* strpos+= */ g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "%u ", val);
		}
		break;
	}
	case 2: {
		guint32 val = get_int_by_size(tvb, offset, size_index);
		proto_tree_add_text(t, tvb, start_offset, type_size,
				    "signed int %d ", val);
		if(strpos<MAX_SDP_LEN){
			/* strpos+= */ g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "%d ", val);
		}
		break;
	}
	case 3: {
		guint32 id;
		const char *uuid_name;
		char *ptr = tvb_bytes_to_str(tvb, offset, size);

		if(size == 2){
			id = tvb_get_ntohs(tvb, offset);
		} else {
			id = tvb_get_ntohl(tvb, offset);
		}
		uuid_name = val_to_str(id, vs_service_classes, "Unknown service");

		proto_tree_add_text(t, tvb, start_offset, type_size, "%s (0x%s) ", uuid_name, ptr);

		if(strpos<MAX_SDP_LEN){
			/* strpos+= */ g_snprintf(str+strpos, MAX_SDP_LEN-strpos, ": %s", uuid_name);
		}
		break;
	}
	case 8:	/* fall through */
	case 4: {
		char *ptr = (gchar*)tvb_get_ephemeral_string(tvb, offset, size);

		proto_tree_add_text(t, tvb, start_offset, type_size, "%s \"%s\"",
				    type == 8 ? "URL" : "String", ptr);
		if(strpos<MAX_SDP_LEN){
			/* strpos+= */g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "%s ", ptr);
		}
		break;
	}
	case 5: {
		guint8 var = tvb_get_guint8(tvb, offset);

		proto_tree_add_text(t, tvb, start_offset, type_size, "%s",
				    var ? "true" : "false");
		if(strpos<MAX_SDP_LEN){
			/* strpos+= */g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "%s ", var?"true":"false");
		}
		break;
	}
	case 6: /* Data Element sequence */
	case 7: /* Data Element alternative */ {
		proto_tree *st;
		proto_item *ti;
		int bytes_to_go = size;
		int first = 1;
		char *substr;

		ti = proto_tree_add_text(t, tvb, start_offset, type_size, "%s",
					 type == 6 ? "Data Element sequence" :
					 "Data Element alternative");
		st = proto_item_add_subtree(ti, ett_btsdp_des);

		if(strpos<MAX_SDP_LEN){
			strpos+=g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "{ ");
		}

		while(bytes_to_go > 0){
			if(!first){
				if(strpos<MAX_SDP_LEN){
					strpos+=g_snprintf(str+strpos, MAX_SDP_LEN-strpos, ", ");
				}
			} else {
				first = 0;
			}

			size = dissect_sdp_type(st, tvb, offset, &substr);
			if (size < 1) {
				break;
			}
			if(strpos<MAX_SDP_LEN){
				strpos+=g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "%s ", substr);
			}
			offset += size;
			bytes_to_go -= size;
		}

		if(strpos<MAX_SDP_LEN){
			/* strpos+= */ g_snprintf(str+strpos, MAX_SDP_LEN-strpos, "} ");
		}
		break;
	}
	}

	/* make sure the string is 0 terminated */
	str[MAX_SDP_LEN]=0;


	return type_size;
}




static int
dissect_sdp_service_attribute(proto_tree *tree, tvbuff_t *tvb, int offset, packet_info *pinfo, guint32 token)
{
	proto_tree *st, *ti_sa, *ti_av;
	int size;
	const char *att_name;
	guint16 id;
	char *attr_val;

	id = tvb_get_ntohs(tvb, offset+1);
	att_name = val_to_str(id, vs_general_attribute_id, "Unknown");

	ti_sa = proto_tree_add_text(tree, tvb, offset, -1,
				    "Service Attribute: id = %s (0x%x)", att_name, id);
	st = proto_item_add_subtree(ti_sa, ett_btsdp_attribute);

	proto_tree_add_text(st, tvb, offset, 3, "Attribute ID: %s (0x%x)", att_name, id);
	ti_av = proto_tree_add_text(st, tvb, offset + 3, -1, "Attribute Value");
	st = proto_item_add_subtree(ti_av, ett_btsdp_attribute);

	size = dissect_sdp_type(st, tvb, offset + 3, &attr_val);
	proto_item_append_text(ti_sa, ", value = %s", attr_val);

	if( pinfo->fd->flags.visited ==0) {
		void *val;
		guint8 type;
		guint32 service, service_val;
		btsdp_data_t *service_item;

		service_item=se_tree_lookup32(service_table, token);

		if(service_item != NULL) {
			switch(id) {

			case ATTR_ID_PROTOCOL_DESCRIPTOR_LIST:
			case ATTR_ID_BT_PROFILE_DESCRIPTOR_LIST:
			case ATTR_ID_ADDITIONAL_PROTOCOL_DESCRIPTOR_LISTS:
				get_sdp_data_element(tvb, offset+ 3, id, &type, &val,  &service, &service_val);

				if( (service == BTSDP_L2CAP_PROTOCOL_UUID)
					|| (service == BTSDP_RFCOMM_PROTOCOL_UUID) ) {
					service_item->channel = service_val;
					service_item->protocol = (guint16) service;
				}
				else {
					service_item->service = service;
				}

				service_item->flags = 0;
				if(id == ATTR_ID_ADDITIONAL_PROTOCOL_DESCRIPTOR_LISTS) {
					service_item->flags = BTSDP_SECONDARY_CHANNEL_FLAG_MASK;
				}
				break;

			case ATTR_ID_SERVICE_CLASS_ID_LIST:
				get_sdp_data_element(tvb, offset+ 3, id, &type, &val,  &service, &service_val);
				service_item->service = service;
				break;

			case ATTR_ID_GOEP_L2CAP_PSM_GROUP_ID_IP_SUBNET:
				/* GOEP L2CAP PSM? */
				{
				void *psm;
				guint8 *psm_guint8;

				get_sdp_data_element(tvb, offset+ 3, id, &type, &psm,  &service, &service_val);
				psm_guint8 = psm;

				if( (type == 1) && (*psm_guint8 & 0x1) ) {
					service_item->channel = *psm_guint8;
					service_item->protocol = BTSDP_L2CAP_PROTOCOL_UUID;
					service_item->flags = 0;
				}
				}
				break;
			}

			if( service_item->service != 0 && service_item->channel != 0 ) {
				service_item->flags |= token >>15; /* set flag when local service */
				tap_queue_packet(btsdp_tap, NULL, (void *) service_item);
			}
		}
	}

	proto_item_set_len(ti_sa, size + 3);
	proto_item_set_len(ti_av, size);

	return offset+size+3;
}


static int
dissect_sdp_service_attribute_list(proto_tree *tree, tvbuff_t *tvb, int offset, packet_info *pinfo, guint32 token)
{
	proto_item *ti;
	proto_tree *st;
	int start_offset = offset, len;

	offset = get_type_length(tvb, offset, &len);

	ti = proto_tree_add_text(tree, tvb, start_offset, -1, "Attribute List");
	st = proto_item_add_subtree(ti, ett_btsdp_attribute);

	if(!len){
		return offset;
	}

	while (offset - start_offset < len) {
		offset = dissect_sdp_service_attribute(st, tvb, offset, pinfo, token);
	}

	proto_item_set_len(ti, offset - start_offset);
	return offset;
}



static int
dissect_sdp_service_attribute_list_array(proto_tree *tree, tvbuff_t *tvb, int offset, packet_info *pinfo, guint32 token)
{
	proto_item *ti;
	proto_tree *st;
	int start_offset, len;

	start_offset=offset;
	offset = get_type_length(tvb, offset, &len);
	ti = proto_tree_add_text(tree, tvb, start_offset, offset-start_offset+len, "Attribute Lists");
	st = proto_item_add_subtree(ti, ett_btsdp_attribute);

	start_offset=offset;
	while(offset-start_offset < len) {
		offset = dissect_sdp_service_attribute_list(st, tvb, offset, pinfo, token);
	}

	return offset;
}



static int
dissect_sdp_service_search_attribute_response(proto_tree *tree, tvbuff_t *tvb, int offset, packet_info *pinfo, guint32 token)
{
	proto_tree_add_item(tree, hf_ssares_al_bytecount, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	offset += dissect_sdp_service_attribute_list_array(tree, tvb, offset, pinfo, token);

	return offset;
}


static int
dissect_sdp_service_search_attribute_request(proto_tree *t, tvbuff_t *tvb, int offset, packet_info *pinfo, guint32 token)
{
	proto_tree *st;
	proto_item *ti;
	int start_offset;
	int size, bytes_to_go;
	char *str;
	btsdp_data_t *service_item = NULL;

	start_offset = offset;
	ti = proto_tree_add_text(t, tvb, offset, 2, "Service Search Pattern");
	st = proto_item_add_subtree(ti, ett_btsdp_attribute);

	offset = get_type_length(tvb, offset, &bytes_to_go);
	proto_item_set_len(ti, offset - start_offset + bytes_to_go);

	while(bytes_to_go>0) {
		if (pinfo->fd->flags.visited == 0)  {
			service_item=se_tree_lookup32(service_table, token);

			if(service_item == NULL) {
				service_item=se_alloc(sizeof(btsdp_data_t));
				se_tree_insert32(service_table, token, service_item);
			}
			service_item->channel = 0;
			service_item->service = 0;
		}

		size = dissect_sdp_type(st, tvb, offset, &str);
		proto_item_append_text(st, " %s", str);
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s", str);

		if (size < 1) {
			break;
		}
		offset+=size;
		bytes_to_go-=size;
	}

	/* dissect maximum attribute byte count */
	proto_tree_add_text(t, tvb, offset, 2, "Maximum Attribute Byte Count: %d", tvb_get_ntohs(tvb, offset));
	offset+=2;

	offset += dissect_attribute_id_list(t, tvb, offset, pinfo);

	proto_tree_add_text(t, tvb, offset, -1, "Continuation State");

	return offset;
}

static int
dissect_sdp_service_attribute_response(proto_tree *t, tvbuff_t *tvb, int offset, packet_info *pinfo, guint32 token)
{
	proto_tree_add_text(t, tvb, offset, 2, "Attribute List Byte Count: %d",
			    tvb_get_ntohs(tvb, offset));
	offset+=2;

	offset = dissect_sdp_service_attribute_list(t, tvb, offset, pinfo, token);

	proto_tree_add_text(t, tvb, offset, -1, "Continuation State");
	offset+=tvb_length_remaining(tvb, offset);

	return offset;
}


static int
dissect_sdp_service_attribute_request(proto_tree *t, tvbuff_t *tvb, int offset, packet_info *pinfo)
{
	proto_tree_add_text(t, tvb, offset, 4, "Service Record Handle: 0x%x",
			    tvb_get_ntohl(tvb, offset));
	offset+=4;

	proto_tree_add_text(t, tvb, offset, 2, "Maximum Attribute Byte Count: %d",
			    tvb_get_ntohs(tvb, offset));
	offset+=2;

	offset += dissect_attribute_id_list(t, tvb, offset, pinfo);

	proto_tree_add_text(t, tvb, offset, -1, "Continuation State");
	offset+=tvb_length_remaining(tvb, offset);
	return offset;
}


static int
dissect_sdp_service_search_request(proto_tree *t, tvbuff_t *tvb, int offset, packet_info *pinfo, guint32 token)
{
	int start_offset, bytes_to_go, size;
	proto_item *ti;
	proto_tree *st;

	start_offset=offset;

	ti = proto_tree_add_text(t, tvb, offset, 2, "Service Search Pattern");
	st = proto_item_add_subtree(ti, ett_btsdp_service_search_pattern);

	offset = get_type_length(tvb, offset, &bytes_to_go);
	proto_item_set_len(ti, offset - start_offset + bytes_to_go);

	while(bytes_to_go>0){
		char *str;
		btsdp_data_t *service_item = NULL;

		if (pinfo->fd->flags.visited == 0)  {
			guint32 service, service_val;
			guint8 type;
			void *val = NULL;

			service_item=se_tree_lookup32(service_table, token);

			if(service_item == NULL) {
				service_item=se_alloc(sizeof(btsdp_data_t));
				se_tree_insert32(service_table, token, service_item);
			}
			service_item->channel = 0;
			service_item->service = 0;

			get_sdp_data_element(tvb, offset, 4, &type, &val,  &service, &service_val);

			if( type==3 && val != NULL)
				service_item->service = *((guint32 *) val);
		}

		size = dissect_sdp_type(st, tvb, offset, &str);

		proto_item_append_text(st, " %s", str);

		col_append_fstr(pinfo->cinfo, COL_INFO, "%s", str);

		if (size < 1) {
			break;
		}
		offset+=size;
		bytes_to_go-=size;
	}

	/* dissect maximum service record count */
	proto_tree_add_text(t, tvb, offset, 2, "Maximum Service Record Count: %d",
			    tvb_get_ntohs(tvb, offset));
	offset+=2;

	proto_tree_add_text(t, tvb, offset, -1, "Continuation State");
	offset+=tvb_length_remaining(tvb, offset);
	return offset;
}


static int
dissect_sdp_service_search_response(proto_tree *t, tvbuff_t *tvb, int offset)
{
	proto_tree *st;
	proto_item *ti;
	gint curr_count;

	proto_tree_add_item(t, hf_ssr_total_count, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;

	curr_count = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(t, hf_ssr_current_count, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;

	ti = proto_tree_add_text(t, tvb, offset,
				 curr_count * 4, "Service Record Handle List");
	st = proto_item_add_subtree(ti, ett_btsdp_ssr);

	while(curr_count>0){
		proto_tree_add_text(st, tvb, offset, 4, "0x%x", tvb_get_ntohl(tvb, offset));
		offset+=4;
		curr_count--;
	}

	proto_tree_add_text(t, tvb, offset, -1, "Continuation State");
	offset+=tvb_length_remaining(tvb, offset);

	return offset;
}


static int
dissect_btsdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *st;
	guint8 pdu;
	guint16 acl_handle;
	guint32 token;
	const char *pdu_name;
	int offset=0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SDP");

	ti = proto_tree_add_item(tree, proto_btsdp, tvb, 0, -1, ENC_NA);
	st = proto_item_add_subtree(ti, ett_btsdp);

	/* pdu id */
	pdu = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(st, hf_pduid, tvb, offset, 1, ENC_BIG_ENDIAN);
	pdu_name = val_to_str(pdu, vs_pduid, "Unknown");
	switch (pinfo->p2p_dir) {

	case P2P_DIR_SENT:
		col_add_str(pinfo->cinfo, COL_INFO, "Sent ");
		break;

	case P2P_DIR_RECV:
		col_add_str(pinfo->cinfo, COL_INFO, "Rcvd ");
		break;

	case P2P_DIR_UNKNOWN:
		col_clear(pinfo->cinfo, COL_INFO);
		break;

	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
		    pinfo->p2p_dir);
		break;
	}
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", pdu_name);
	proto_item_append_text(ti, ": %s (0x%x)", pdu_name, pdu);
	offset++;

	/* tid */
	proto_tree_add_item(st, hf_tid, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;

	/* plen */
	proto_tree_add_item(st, hf_plen, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;

	acl_handle = ((btl2cap_data_t *) pinfo->private_data)->chandle;
	if( pdu & 0x01)
		token = acl_handle | ((pinfo->p2p_dir != P2P_DIR_RECV)?0x8000:0x0000);
	else
		token = acl_handle | ((pinfo->p2p_dir == P2P_DIR_RECV)?0x8000:0x0000);

	switch(pdu) {
	case 0x1:
		offset=dissect_sdp_error_response(st, tvb, offset);
		break;
	case 0x2:
		offset=dissect_sdp_service_search_request(st, tvb, offset, pinfo, token);
		break;
	case 0x3:
		offset=dissect_sdp_service_search_response(st, tvb, offset);
		break;
	case 0x4:
		offset=dissect_sdp_service_attribute_request(st, tvb, offset, pinfo);
		break;
	case 0x5:
		offset=dissect_sdp_service_attribute_response(st, tvb, offset, pinfo, token);
		break;
	case 0x6:
		offset=dissect_sdp_service_search_attribute_request(st, tvb, offset, pinfo, token);
		break;
	case 07:
		offset=dissect_sdp_service_search_attribute_response(st, tvb, offset, pinfo, token);
		break;
	}
return offset;
}

void
proto_register_btsdp(void)
{
	static hf_register_info hf[] = {
		{&hf_pduid,
			{"PDU", "btsdp.pdu",
			FT_UINT8, BASE_HEX, VALS(vs_pduid), 0,
			"PDU type", HFILL}
		},
		{&hf_tid,
			{"Transaction Id", "btsdp.tid",
			FT_UINT16, BASE_HEX, NULL, 0,
			NULL, HFILL}
		},
		{&hf_plen,
			{"Parameter Length", "btsdp.len",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL}
		},
		{&hf_error_code,
			{"Error Code", "btsdp.error_code",
			FT_UINT16, BASE_HEX, NULL, 0,
			NULL, HFILL}
		},
		{&hf_ssr_total_count,
			{"Total Service Record Count", "btsdp.ssr.total_count",
			FT_UINT16, BASE_DEC, NULL, 0,
			 "Total count of service records", HFILL}
		},
		{&hf_ssr_current_count,
		        {"Current Service Record Count", "btsdp.ssr.current_count",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Count of service records in this message", HFILL}
		},
		{&hf_ssares_al_bytecount,
			{"Attribute Lists Byte Count", "btsdp.ssares.byte_count",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Count of bytes in attribute list response", HFILL}
		}
	};

	/* Setup protocol subtree array */

	static gint *ett[] = {
		&ett_btsdp,
		&ett_btsdp_ssr,
		&ett_btsdp_des,
		&ett_btsdp_attribute,
		&ett_btsdp_service_search_pattern,
		&ett_btsdp_attribute_idlist
	};

	proto_btsdp = proto_register_protocol("Bluetooth SDP Protocol", "BTSDP", "btsdp");

	new_register_dissector("btsdp", dissect_btsdp, proto_btsdp);

	btsdp_tap = register_tap("btsdp");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_btsdp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	service_table=se_tree_create(EMEM_TREE_TYPE_RED_BLACK, "mapping of rfcomm channel/l2cap PSM to service uuid");
}


void
proto_reg_handoff_btsdp(void)
{
	dissector_handle_t btsdp_handle;

	btsdp_handle = find_dissector("btsdp");
	dissector_add_uint("btl2cap.psm", BTL2CAP_PSM_SDP, btsdp_handle);
}

