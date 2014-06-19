/* packet-dtpt.c
 * Routines for Microsoft ActiveSync Desktop Pass-Through (DTPT) packet
 * dissection
 *
 * Uwe Girlich <uwe@planetquake.com>
 *	http://www.synce.org/moin/ProtocolDocumentation/DesktopPassThrough
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-quake.c
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

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/to_str.h>
#include <epan/aftypes.h>
#include <epan/ipproto.h>

void proto_register_dtpt(void);

static int proto_dtpt = -1;

static int hf_dtpt_version = -1;
static int hf_dtpt_message_type = -1;
static int hf_dtpt_flags = -1;
static int hf_dtpt_flags_deep = -1;
static int hf_dtpt_flags_containers = -1;
static int hf_dtpt_flags_nocontainers = -1;
static int hf_dtpt_flags_nearest = -1;
static int hf_dtpt_flags_return_name = -1;
static int hf_dtpt_flags_return_type = -1;
static int hf_dtpt_flags_return_version = -1;
static int hf_dtpt_flags_return_comment = -1;
static int hf_dtpt_flags_return_addr = -1;
static int hf_dtpt_flags_return_blob = -1;
static int hf_dtpt_flags_return_aliases = -1;
static int hf_dtpt_flags_return_query_string = -1;
static int hf_dtpt_flags_flushcache = -1;
static int hf_dtpt_flags_flushprevious = -1;
static int hf_dtpt_flags_res_service = -1;
static int hf_dtpt_payload_size = -1;
static int hf_dtpt_handle = -1;
static int hf_dtpt_error = -1;
static int hf_dtpt_buffer_size = -1;
static int hf_dtpt_data_size = -1;
static int hf_dtpt_queryset_rawsize = -1;
static int hf_dtpt_queryset_size = -1;
static int hf_dtpt_queryset_service_instance_name_pointer = -1;
static int hf_dtpt_queryset_service_class_id_pointer = -1;
static int hf_dtpt_queryset_version = -1;
static int hf_dtpt_queryset_comment_pointer = -1;
static int hf_dtpt_queryset_namespace = -1;
static int hf_dtpt_queryset_provider_id_pointer = -1;
static int hf_dtpt_queryset_context_pointer = -1;
static int hf_dtpt_queryset_protocols_number = -1;
static int hf_dtpt_queryset_protocols_pointer = -1;
static int hf_dtpt_queryset_query_string_pointer = -1;
static int hf_dtpt_queryset_cs_addrs_number = -1;
static int hf_dtpt_queryset_cs_addrs_pointer = -1;
static int hf_dtpt_queryset_output_flags = -1;
static int hf_dtpt_queryset_blob_pointer = -1;
static int hf_dtpt_wstring_length = -1;
static int hf_dtpt_wstring_data = -1;
static int hf_dtpt_guid_length = -1;
static int hf_dtpt_guid_data = -1;
static int hf_dtpt_service_instance_name = -1;
static int hf_dtpt_service_class_id = -1;
static int hf_dtpt_comment = -1;
static int hf_dtpt_ns_provider_id = -1;
static int hf_dtpt_context = -1;
static int hf_dtpt_protocols_number = -1;
static int hf_dtpt_protocols_length = -1;
static int hf_dtpt_protocol_family = -1;
static int hf_dtpt_protocol_protocol = -1;
static int hf_dtpt_query_string = -1;
static int hf_dtpt_cs_addrs_number = -1;
static int hf_dtpt_cs_addrs_length1 = -1;
static int hf_dtpt_cs_addr_socket_type = -1;
static int hf_dtpt_cs_addr_protocol = -1;
static int hf_dtpt_cs_addr_local_pointer = -1;
static int hf_dtpt_cs_addr_local_length = -1;
static int hf_dtpt_cs_addr_local = -1;
static int hf_dtpt_cs_addr_remote_pointer = -1;
static int hf_dtpt_cs_addr_remote_length = -1;
static int hf_dtpt_cs_addr_remote = -1;
static int hf_dtpt_sockaddr_length = -1;
static int hf_dtpt_sockaddr_family = -1;
static int hf_dtpt_sockaddr_port = -1;
static int hf_dtpt_sockaddr_address = -1;
static int hf_dtpt_blob_rawsize = -1;
static int hf_dtpt_blob_size = -1;
static int hf_dtpt_blob_data_pointer = -1;
static int hf_dtpt_blob_data_length = -1;
static int hf_dtpt_blob_data = -1;
static int hf_dtpt_connect_addr = -1;

static gint ett_dtpt = -1;
static gint ett_dtpt_flags = -1;
static gint ett_dtpt_queryset = -1;
static gint ett_dtpt_wstring = -1;
static gint ett_dtpt_guid = -1;
static gint ett_dtpt_protocols = -1;
static gint ett_dtpt_protocol = -1;
static gint ett_dtpt_cs_addrs = -1;
static gint ett_dtpt_cs_addr1 = -1;
static gint ett_dtpt_cs_addr2 = -1;
static gint ett_dtpt_sockaddr = -1;
static gint ett_dtpt_blobraw = -1;
static gint ett_dtpt_blob = -1;



static dissector_handle_t	dtpt_conversation_handle;
/** static dissector_handle_t	dtpt_data_handle;  **/
static dissector_handle_t	data_handle;


/* Server port */
static unsigned int gbl_dtptServerPort=5721;

static const value_string names_message_type[] = {
#define LookupBeginRequest 9
	{	LookupBeginRequest, "LookupBeginRequest" },
#define LookupBeginResponse 10
	{	LookupBeginResponse, "LookupBeginResponse" },
#define LookupNextRequest 11
	{	LookupNextRequest, "LookupNextRequest" },
#define LookupNextResponse 12
	{	LookupNextResponse, "LookupNextResponse" },
#define LookupEndRequest 13
	{	LookupEndRequest, "LookupEndRequest" },
#define ConnectRequest 1
	{	ConnectRequest, "ConnectRequest" },
#define ConnectResponseOK 0x5A
	{	ConnectResponseOK, "ConnectResponseOK" },
#define ConnectResponseERR 0x5B
	{	ConnectResponseERR, "ConnectResponseERR" },
	{ 0, NULL }
};

static const value_string names_error[] = {
	{	0,     "OK" },
	{	10014, "WSAEFAULT" },
	{	10060, "WSAETIMEDOUT" },
	{	10108, "WSASERVICE_NOT_FOUND" },
	{	11001, "WSAHOST_NOT_FOUND" },
	{	0, NULL	}
};

static const value_string names_family[] = {
	{	WINSOCK_AF_INET, "AF_INET"	},
	{	0, NULL	}
};

/*
 * Winsock's SOCK_ values.  These are probably the same as they are on
 * other OSes, as they probably all come from 4.2BSD, but it's still
 * best to define them ourselves (to avoid problems if other OSes
 * define them differently, and to avoid having to include system
 * header files that might require a bunch of other includes).
 */
#define WINSOCK_SOCK_STREAM	1
#define WINSOCK_SOCK_DGRAM	2
#define WINSOCK_SOCK_RAW	3

static const value_string names_socket_type[] = {
	{	WINSOCK_SOCK_STREAM,	"SOCK_STREAM"	},
	{	WINSOCK_SOCK_DGRAM,	"SOCK_DGRAM"	},
	{	WINSOCK_SOCK_RAW,	"SOCK_RAW"	},
	{	0, NULL	}
};

static const value_string names_protocol[] = {
	{	IP_PROTO_IP,	"IPPROTO_IP"	},
	{	IP_PROTO_TCP,	"IPPROTO_TCP"	},
	{	IP_PROTO_UDP,	"IPPROTP_UDP"	},
	{	0, NULL	}
};

#define LUP_DEEP                0x0001
#define LUP_CONTAINERS          0x0002
#define LUP_NOCONTAINERS        0x0004
#define LUP_NEAREST             0x0008
#define LUP_RETURN_NAME         0x0010
#define LUP_RETURN_TYPE         0x0020
#define LUP_RETURN_VERSION      0x0040
#define LUP_RETURN_COMMENT      0x0080
#define LUP_RETURN_ADDR         0x0100
#define LUP_RETURN_BLOB         0x0200
#define LUP_RETURN_ALIASES      0x0400
#define LUP_RETURN_QUERY_STRING 0x0800
#define LUP_FLUSHCACHE          0x1000
#define LUP_FLUSHPREVIOUS       0x2000
#define LUP_RES_SERVICE         0x8000

#define SOCKADDR_WITH_LEN	1
#define SOCKADDR_CONNECT	2

static int
dissect_dtpt_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int
dissect_dtpt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);


static int
dissect_dtpt_wstring(tvbuff_t *tvb, guint offset, proto_tree *tree, int hfindex)
{
	guint32	wstring_length;
	guint32	wstring_size;
	char	*wstring_data = NULL;
	guint32	wstring_padding = 0;

	wstring_length = tvb_get_letohl(tvb, offset);
	wstring_data = tvb_get_string_enc(wmem_packet_scope(), tvb, offset+4, wstring_length, ENC_UTF_16|ENC_LITTLE_ENDIAN);
	wstring_size = wstring_length;
	if (wstring_size%4) {
		wstring_padding = (4-wstring_size%4);
		wstring_size += wstring_padding;
	}
	if (tree) {
		proto_item	*dtpt_wstring_item = NULL;
		proto_tree	*dtpt_wstring_tree = NULL;
		dtpt_wstring_item = proto_tree_add_string(tree, hfindex,
			tvb, offset+0, 4+wstring_size, wstring_data);
		if (dtpt_wstring_item)
			dtpt_wstring_tree = proto_item_add_subtree(dtpt_wstring_item, ett_dtpt_wstring);
		if (dtpt_wstring_tree) {
			proto_tree_add_uint(dtpt_wstring_tree, hf_dtpt_wstring_length,
				tvb, offset+0, 4, wstring_length);
			if (wstring_length)
				proto_tree_add_string(dtpt_wstring_tree, hf_dtpt_wstring_data,
					tvb, offset+4, wstring_length, wstring_data);
			if (wstring_padding)
				proto_tree_add_text(dtpt_wstring_tree, tvb,
					offset+4+wstring_length,wstring_padding, "Padding");
		}
	}
	offset += 4+wstring_size;
	return offset;
}

static int
dissect_dtpt_guid(tvbuff_t *tvb, guint offset, proto_tree *tree, int hfindex)
{
	guint32	guid_length;

	guid_length = tvb_get_letohl(tvb, offset);
	if (tree) {
		e_guid_t	guid;
		proto_item	*dtpt_guid_item = NULL;
		proto_tree	*dtpt_guid_tree = NULL;
		const gchar	*guid_name = NULL;

		if (guid_length) {
			tvb_get_guid(tvb, offset+4, &guid, ENC_LITTLE_ENDIAN);
		}
		else {
			memset(&guid, 0, sizeof(guid));
		}
		dtpt_guid_item = proto_tree_add_guid(tree, hfindex, tvb, offset, 4 + guid_length, &guid);
		if (dtpt_guid_item) {
			guid_name = guids_get_guid_name(&guid);
			if (guid_name != NULL)
				proto_item_set_text(dtpt_guid_item, "%s: %s (%s)",
				proto_registrar_get_name(hfindex), guid_name, guid_to_ep_str(&guid));
			dtpt_guid_tree = proto_item_add_subtree(dtpt_guid_item, ett_dtpt_guid);
		}
		if (dtpt_guid_tree) {
			proto_item	*dtpt_guid_data_item = NULL;

			proto_tree_add_uint(dtpt_guid_tree, hf_dtpt_guid_length,
				tvb, offset, 4, guid_length);
			if (guid_length) {
				dtpt_guid_data_item = proto_tree_add_guid(dtpt_guid_tree, hf_dtpt_guid_data,
					tvb, offset+4, guid_length, &guid);
				if (guid_name != NULL && dtpt_guid_data_item != NULL) {
					proto_item_set_text(dtpt_guid_data_item, "%s: %s (%s)",
					proto_registrar_get_name(hf_dtpt_guid_data),
					guid_name, guid_to_ep_str(&guid));
				}
			}
		}
	}
	offset+=4;
	offset+=guid_length;

	return offset;
}

static int
dissect_dtpt_sockaddr(tvbuff_t *tvb, guint offset, proto_tree *tree, int hfindex, int sockaddr_type)
{
	guint32	sockaddr_length = 0;
	proto_item	*sockaddr_item = NULL;
	proto_tree	*sockaddr_tree = NULL;
	guint32		sockaddr_len1 = 0;
	guint32		sockaddr_len2 = 0;

	switch (sockaddr_type) {
		case SOCKADDR_WITH_LEN:
			sockaddr_len1=4;
			sockaddr_len2=16;
		break;
		case SOCKADDR_CONNECT:
			sockaddr_len1=0;
			sockaddr_len2=30;
		break;
	}

	if (sockaddr_type == SOCKADDR_WITH_LEN)
		sockaddr_length = tvb_get_letohl(tvb, offset + 0);

	if (tree) {
		sockaddr_item = proto_tree_add_text(tree,
			tvb, offset, sockaddr_len1+sockaddr_len2, "%s", proto_registrar_get_name(hfindex));

		if (sockaddr_item)
			sockaddr_tree = proto_item_add_subtree(sockaddr_item, ett_dtpt_sockaddr);
		if (sockaddr_tree) {
			if (sockaddr_type == SOCKADDR_WITH_LEN)
				proto_tree_add_uint(sockaddr_tree, hf_dtpt_sockaddr_length,
						tvb, offset+0, 4, sockaddr_length);
		}
	}

	offset += sockaddr_len1;

	if (sockaddr_tree) {
		switch (sockaddr_type) {
			case SOCKADDR_WITH_LEN: {
				guint16 family;

				family = tvb_get_letohs(tvb, offset);
				proto_tree_add_uint(sockaddr_tree, hf_dtpt_sockaddr_family,
						tvb, offset, 2, family);
				switch (family) {
					case WINSOCK_AF_INET: {
						guint16 port;
						guint32	addr;

						port = tvb_get_ntohs(tvb,offset+2);
						proto_tree_add_uint(sockaddr_tree, hf_dtpt_sockaddr_port,
						tvb, offset+2,2,port);
						addr = tvb_get_ipv4(tvb,offset+4);
						proto_tree_add_ipv4(sockaddr_tree, hf_dtpt_sockaddr_address,
						tvb, offset+4,4,addr);
						proto_tree_add_text(sockaddr_tree, tvb, offset+8, 8, "Padding");
							proto_item_append_text(sockaddr_item, ": %s:%d", ip_to_str((guint8*)&addr), port);
					}
					break;
				}
			}
			break;
			case SOCKADDR_CONNECT: {
				guint32	family;

				family = tvb_get_letohl(tvb, offset+0);
				proto_tree_add_uint(sockaddr_tree, hf_dtpt_sockaddr_family,
						tvb, offset+0, 4, family);
				switch (family) {
					case WINSOCK_AF_INET: {
						guint16 port;
						guint32	addr;

						proto_tree_add_text(sockaddr_tree, tvb, offset+4, 4, "Padding");
						port = tvb_get_ntohs(tvb,offset+8);
						proto_tree_add_uint(sockaddr_tree, hf_dtpt_sockaddr_port,
							tvb, offset+8,2,port);
						addr = tvb_get_ipv4(tvb,offset+10);
						proto_tree_add_ipv4(sockaddr_tree, hf_dtpt_sockaddr_address,
							tvb, offset+10,4,addr);
						proto_tree_add_text(sockaddr_tree, tvb, offset+14, 16, "Padding");
						proto_item_append_text(sockaddr_item, ": %s:%d", ip_to_str((guint8*)&addr), port);
					}
					break;
				}
			}
			break;
		}

	}
	offset += sockaddr_len2;
	return offset;
}

static int
dissect_dtpt_conversation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint		offset = 0;

	/* First try to decode it as "normal" DTPT packets. */
	offset = dissect_dtpt(tvb, pinfo, tree, NULL);

	if (offset == 0) {
		/* No, maybe it was a DTPT data packet. */
		offset = dissect_dtpt_data(tvb, pinfo, tree);
	}

	/* Handle any remaining bytes ... */
	if (tvb_reported_length_remaining(tvb, offset) > 0) {
		/* ... as data. */
		call_dissector(data_handle,
			tvb_new_subset_remaining(tvb, offset), pinfo, tree);
	}
	return tvb_reported_length(tvb);
}


static int
dissect_dtpt_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*dtpt_item = NULL;
	proto_tree	*dtpt_tree = NULL;
	proto_item	*dtpt_queryset_item = NULL;
	proto_tree	*dtpt_queryset_tree = NULL;
	guint		offset = 0;
	guint32		queryset_rawsize;
	guint32		queryset_size;
	guint32		num_protocols;
	guint32		protocols_length = 0;
	guint32		addrs_start;
	guint32		num_addrs;
	guint32		addrs_length1 = 0;
	proto_item	*dtpt_addrs_item = NULL;
	proto_tree	*dtpt_addrs_tree = NULL;
	guint32		blob_rawsize = 0;
	guint32		blob_size = 0;
	guint32		blob_data_length = 0;

	queryset_rawsize = tvb_get_letohl(tvb, offset + 0);
	if (queryset_rawsize != 60) return 0;
	queryset_size = tvb_get_letohl(tvb, offset + 4);
	if (queryset_size != 60) return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DTPT");
	col_set_str(pinfo->cinfo, COL_INFO, "QuerySet");

	if (tree) {
		dtpt_item = proto_tree_add_item(tree, proto_dtpt,
				tvb, 0, -1, ENC_NA);
		if (dtpt_item)
			dtpt_tree = proto_item_add_subtree(dtpt_item, ett_dtpt);
	}

	if (dtpt_tree) {
		proto_tree_add_uint(dtpt_tree, hf_dtpt_queryset_rawsize,
			tvb, 0, 4, queryset_rawsize);

		dtpt_queryset_item = proto_tree_add_text(dtpt_tree,
			tvb, 4, 60, "QuerySet raw");
		if (dtpt_queryset_item)
			dtpt_queryset_tree = proto_item_add_subtree(dtpt_queryset_item, ett_dtpt_queryset);

		if (dtpt_queryset_tree) {
			proto_tree_add_uint(dtpt_queryset_tree, hf_dtpt_queryset_size,
				tvb, offset+4+0,  4, queryset_size);
			proto_tree_add_uint(dtpt_queryset_tree, hf_dtpt_queryset_service_instance_name_pointer,
				tvb, offset+4+4,  4, tvb_get_letohl(tvb, offset+4+ 4));
			proto_tree_add_uint(dtpt_queryset_tree, hf_dtpt_queryset_service_class_id_pointer,
				tvb, offset+4+8,  4, tvb_get_letohl(tvb, offset+4+ 8));
			proto_tree_add_uint(dtpt_queryset_tree, hf_dtpt_queryset_version,
				tvb, offset+4+12, 4, tvb_get_letohl(tvb, offset+4+12));
			proto_tree_add_uint(dtpt_queryset_tree, hf_dtpt_queryset_comment_pointer,
				tvb, offset+4+16, 4, tvb_get_letohl(tvb, offset+4+16));
			proto_tree_add_uint(dtpt_queryset_tree, hf_dtpt_queryset_namespace,
				tvb, offset+4+20, 4, tvb_get_letohl(tvb, offset+4+20));
			proto_tree_add_uint(dtpt_queryset_tree, hf_dtpt_queryset_provider_id_pointer,
				tvb, offset+4+24, 4, tvb_get_letohl(tvb, offset+4+24));
			proto_tree_add_uint(dtpt_queryset_tree, hf_dtpt_queryset_context_pointer,
				tvb, offset+4+28, 4, tvb_get_letohl(tvb, offset+4+28));
			proto_tree_add_uint(dtpt_queryset_tree, hf_dtpt_queryset_protocols_number,
				tvb, offset+4+32, 4, tvb_get_letohl(tvb, offset+4+32));
			proto_tree_add_uint(dtpt_queryset_tree, hf_dtpt_queryset_protocols_pointer,
				tvb, offset+4+36, 4, tvb_get_letohl(tvb, offset+4+36));
			proto_tree_add_uint(dtpt_queryset_tree, hf_dtpt_queryset_query_string_pointer,
				tvb, offset+4+40, 4, tvb_get_letohl(tvb, offset+4+40));
			proto_tree_add_uint(dtpt_queryset_tree, hf_dtpt_queryset_cs_addrs_number,
				tvb, offset+4+44, 4, tvb_get_letohl(tvb, offset+4+44));
			proto_tree_add_uint(dtpt_queryset_tree, hf_dtpt_queryset_cs_addrs_pointer,
				tvb, offset+4+48, 4, tvb_get_letohl(tvb, offset+4+48));
			proto_tree_add_uint(dtpt_queryset_tree, hf_dtpt_queryset_output_flags,
				tvb, offset+4+52, 4, tvb_get_letohl(tvb, offset+4+52));
			proto_tree_add_uint(dtpt_queryset_tree, hf_dtpt_queryset_blob_pointer,
				tvb, offset+4+56, 4, tvb_get_letohl(tvb, offset+4+56));
		}
	}

	offset += 4;
	offset += 60;

	offset = dissect_dtpt_wstring(tvb, offset, dtpt_tree, hf_dtpt_service_instance_name);
	offset = dissect_dtpt_guid   (tvb, offset, dtpt_tree, hf_dtpt_service_class_id     );
	offset = dissect_dtpt_wstring(tvb, offset, dtpt_tree, hf_dtpt_comment              );
	offset = dissect_dtpt_guid   (tvb, offset, dtpt_tree, hf_dtpt_ns_provider_id       );
	offset = dissect_dtpt_wstring(tvb, offset, dtpt_tree, hf_dtpt_context              );
	num_protocols = tvb_get_letohl(tvb, offset);
	if (num_protocols>0) {
		protocols_length = tvb_get_letohl(tvb, offset+4);
	}
	if (dtpt_tree) {
		proto_item	*dtpt_protocols_item = NULL;
		proto_tree	*dtpt_protocols_tree = NULL;
		guint32		i;

		dtpt_protocols_item = proto_tree_add_text(dtpt_tree,
				tvb, offset, 4+(num_protocols>0?4:0)+num_protocols*8,
				"Protocols: %d", num_protocols);
		if (dtpt_protocols_item)
			dtpt_protocols_tree = proto_item_add_subtree(dtpt_protocols_item, ett_dtpt_protocols);
		if (dtpt_protocols_tree) {
			proto_tree_add_uint(dtpt_protocols_tree, hf_dtpt_protocols_number,
					tvb, offset, 4, num_protocols);
			if (num_protocols>0)
				proto_tree_add_uint(dtpt_protocols_tree, hf_dtpt_protocols_length,
						tvb, offset+4, 4, protocols_length);
			for (i=0;i<num_protocols;i++) {
				proto_item	*dtpt_protocol_item = NULL;
				proto_tree	*dtpt_protocol_tree = NULL;

				dtpt_protocol_item = proto_tree_add_text(dtpt_protocols_tree,
						tvb, offset+4+4+i*8, 8, "Protocol[%d]", i+1);
				if (dtpt_protocol_item)
					dtpt_protocol_tree = proto_item_add_subtree(dtpt_protocol_item, ett_dtpt_protocol);
				if (dtpt_protocol_tree) {
					proto_tree_add_uint(dtpt_protocol_tree, hf_dtpt_protocol_family,
					tvb, offset+4+4+i*8, 4, tvb_get_letohl(tvb, offset+4+4+i*8));
					proto_tree_add_uint(dtpt_protocol_tree, hf_dtpt_protocol_protocol,
					tvb, offset+4+4+i*8+4, 4, tvb_get_letohl(tvb, offset+4+4+i*8+4));
				}
			}
		}
	}
	offset += 4 + (num_protocols>0?4:0) + num_protocols*8;
	offset = dissect_dtpt_wstring(tvb, offset, dtpt_tree, hf_dtpt_query_string         );

	addrs_start = offset;
	num_addrs = tvb_get_letohl(tvb, offset);
	if (num_addrs>0) {
		addrs_length1 = tvb_get_letohl(tvb, offset+4);
	}
	if (dtpt_tree) {
		dtpt_addrs_item = proto_tree_add_text(dtpt_tree,
			tvb, offset, -1, "Addresses");
		if (dtpt_addrs_item)
			dtpt_addrs_tree = proto_item_add_subtree(dtpt_addrs_item, ett_dtpt_cs_addrs);
		if (dtpt_addrs_tree) {
			proto_tree_add_uint(dtpt_addrs_tree, hf_dtpt_cs_addrs_number,
				tvb, offset, 4, num_addrs);
			if (num_addrs>0)
				proto_tree_add_uint(dtpt_addrs_tree, hf_dtpt_cs_addrs_length1,
					tvb, offset+4, 4, addrs_length1);
		}
	}
	offset += 4 + (num_addrs>0?4:0);

	if (num_addrs>0) {
		guint32	i;
		guint32	offset2;

		offset2 = offset + 24*num_addrs;

		for (i=0;i<num_addrs;i++,offset+=24) {
			proto_item	*dtpt_addr1_item = NULL;
			proto_tree	*dtpt_addr1_tree = NULL;
			proto_item	*dtpt_addr2_item = NULL;
			proto_tree	*dtpt_addr2_tree = NULL;
			guint32		offset2_start;

			if (dtpt_addrs_tree) {
				dtpt_addr1_item = proto_tree_add_text(dtpt_addrs_tree,
					tvb, offset, 24, "Address[%u] Part 1", i+1);
				if (dtpt_addr1_item)
					dtpt_addr1_tree = proto_item_add_subtree(dtpt_addr1_item,
						ett_dtpt_cs_addr1);
				if (dtpt_addr1_tree) {
					proto_tree_add_uint(dtpt_addr1_tree, hf_dtpt_cs_addr_local_pointer,
						tvb, offset+ 0, 4, tvb_get_letohl(tvb, offset+ 0));
					proto_tree_add_uint(dtpt_addr1_tree, hf_dtpt_cs_addr_local_length,
						tvb, offset+ 4, 4, tvb_get_letohl(tvb, offset+ 4));
					proto_tree_add_uint(dtpt_addr1_tree, hf_dtpt_cs_addr_remote_pointer,
						tvb, offset+ 8, 4, tvb_get_letohl(tvb, offset+ 8));
					proto_tree_add_uint(dtpt_addr1_tree, hf_dtpt_cs_addr_remote_length,
						tvb, offset+12, 4, tvb_get_letohl(tvb, offset+12));
					proto_tree_add_uint(dtpt_addr1_tree, hf_dtpt_cs_addr_socket_type,
						tvb, offset+16, 4, tvb_get_letohl(tvb, offset+16));
					proto_tree_add_uint(dtpt_addr1_tree, hf_dtpt_cs_addr_protocol,
						tvb, offset+20, 4, tvb_get_letohl(tvb, offset+20));
				}

				dtpt_addr2_item = proto_tree_add_text(dtpt_addrs_tree,
					tvb, offset2, -1, "Address[%u] Part 2", i+1);
				if (dtpt_addr2_item)
					dtpt_addr2_tree = proto_item_add_subtree(dtpt_addr2_item,
						ett_dtpt_cs_addr2);
			}

			offset2_start = offset2;

			offset2 = dissect_dtpt_sockaddr(tvb, offset2, dtpt_addr2_tree, hf_dtpt_cs_addr_local, SOCKADDR_WITH_LEN);
			offset2 = dissect_dtpt_sockaddr(tvb, offset2, dtpt_addr2_tree, hf_dtpt_cs_addr_remote, SOCKADDR_WITH_LEN);

			if (dtpt_addr2_item)
				proto_item_set_len(dtpt_addr2_item,
					offset2 - offset2_start);
		}
		offset = offset2;
	}

	if (dtpt_addrs_item)
		proto_item_set_len(dtpt_addrs_item, offset - addrs_start);

	if (dtpt_item)
		proto_item_set_len(dtpt_item, offset);

	blob_rawsize = tvb_get_letohl(tvb, offset);
	if (blob_rawsize>=4) {
		blob_size = tvb_get_letohl(tvb,offset+4+0);
	}
	if (dtpt_tree) {
		proto_item	*dtpt_blobraw_item = NULL;
		proto_tree	*dtpt_blobraw_tree = NULL;

		proto_tree_add_uint(dtpt_tree, hf_dtpt_blob_rawsize,
				tvb, offset+0, 4, blob_rawsize);
		if (blob_rawsize>0) {
			dtpt_blobraw_item = proto_tree_add_text(dtpt_tree,
				tvb, offset+4, blob_rawsize, "Blob raw");
			if (dtpt_blobraw_item)
				dtpt_blobraw_tree = proto_item_add_subtree(dtpt_blobraw_item,
					ett_dtpt_blobraw);
			if (dtpt_blobraw_tree) {
				proto_tree_add_uint(dtpt_blobraw_tree, hf_dtpt_blob_size,
					tvb, offset+4+0, 4, blob_size);
				proto_tree_add_uint(dtpt_blobraw_tree, hf_dtpt_blob_data_pointer,
					tvb, offset+4+4, 4, tvb_get_letohl(tvb,offset+4+4));
			}
		}
	}

	offset += 4+blob_rawsize;

	if (dtpt_item)
		proto_item_set_len(dtpt_item, offset);

	if (blob_size>0) {
		proto_item	*dtpt_blob_item = NULL;
		proto_tree	*dtpt_blob_tree = NULL;

		blob_data_length = tvb_get_letohl(tvb,offset);

		if (dtpt_tree) {
			dtpt_blob_item = proto_tree_add_text(dtpt_tree,
				tvb, offset, 4+blob_data_length, "Blob");
			if (dtpt_blob_item)
				dtpt_blob_tree = proto_item_add_subtree(dtpt_blob_item,
					ett_dtpt_blob);
			if (dtpt_blob_tree) {
				proto_tree_add_uint(dtpt_blob_tree, hf_dtpt_blob_data_length,
					tvb, offset+0, 4, blob_data_length);
				proto_tree_add_item(dtpt_blob_tree, hf_dtpt_blob_data,
					tvb, offset+4, blob_data_length, ENC_NA);
			}
		}
		offset += 4+blob_data_length;
		if (dtpt_item)
			proto_item_set_len(dtpt_item, offset);
	}

	return offset;
}

static int
dissect_dtpt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_tree	*dtpt_tree = NULL;
	proto_item	*dtpt_item = NULL;
	guint8		version;
	guint8		message_type;
	guint32		flags;
	guint32		payload_size;

	version = tvb_get_guint8(tvb, 0);
	if (version != 1) return 0;
	message_type = tvb_get_guint8(tvb, 1);
	switch (message_type) {
		case LookupBeginRequest:
		case LookupBeginResponse:
		case LookupNextRequest:
		case LookupNextResponse:
		case LookupEndRequest:
			if (tvb_reported_length(tvb) != 20) return 0;
		break;
		case ConnectRequest:
		case ConnectResponseOK:
		case ConnectResponseERR:
			if (tvb_reported_length(tvb) != 36) return 0;
		break;
		default:
			return 0;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DTPT");
	col_add_str(pinfo->cinfo, COL_INFO, val_to_str(message_type, names_message_type, "Unknown (%d)"));

	if (message_type == LookupBeginRequest) {
		conversation_t *c;
		c = find_or_create_conversation(pinfo);
		conversation_set_dissector(c, dtpt_conversation_handle);
	}

	if (tree) {
		dtpt_item = proto_tree_add_item(tree, proto_dtpt,
				tvb, 0, -1, ENC_NA);
		if (dtpt_item)
			dtpt_tree = proto_item_add_subtree(dtpt_item, ett_dtpt);
	}

	if (dtpt_tree) {
		proto_tree_add_uint(dtpt_tree, hf_dtpt_version,
			tvb, 0, 1, version);
		proto_tree_add_uint(dtpt_tree, hf_dtpt_message_type,
			tvb, 1, 1, message_type);

		switch (message_type) {
			case LookupBeginRequest: {
				proto_item* flags_item = NULL;
				proto_tree*	flags_tree = NULL;

				flags = tvb_get_letohl(tvb, 12);

				flags_item = proto_tree_add_uint(dtpt_tree, hf_dtpt_flags,
					tvb, 12, 4, flags);
				if (flags_item) {
					flags_tree = proto_item_add_subtree(flags_item, ett_dtpt_flags);
				}
				if (flags_tree) {
					proto_tree_add_boolean(flags_tree, hf_dtpt_flags_res_service,   tvb, 12, 4, flags);
					proto_tree_add_boolean(flags_tree, hf_dtpt_flags_flushprevious, tvb, 12, 4, flags);
					proto_tree_add_boolean(flags_tree, hf_dtpt_flags_flushcache,    tvb, 12, 4, flags);
					proto_tree_add_boolean(flags_tree, hf_dtpt_flags_return_query_string, tvb, 12, 4, flags);
					proto_tree_add_boolean(flags_tree, hf_dtpt_flags_return_aliases, tvb, 12, 4, flags);
					proto_tree_add_boolean(flags_tree, hf_dtpt_flags_return_blob, tvb, 12, 4, flags);
					proto_tree_add_boolean(flags_tree, hf_dtpt_flags_return_addr, tvb, 12, 4, flags);
					proto_tree_add_boolean(flags_tree, hf_dtpt_flags_return_comment, tvb, 12, 4, flags);
					proto_tree_add_boolean(flags_tree, hf_dtpt_flags_return_version, tvb, 12, 4, flags);
					proto_tree_add_boolean(flags_tree, hf_dtpt_flags_return_type, tvb, 12, 4, flags);
					proto_tree_add_boolean(flags_tree, hf_dtpt_flags_return_name, tvb, 12, 4, flags);
					proto_tree_add_boolean(flags_tree, hf_dtpt_flags_nearest, tvb, 12, 4, flags);
					proto_tree_add_boolean(flags_tree, hf_dtpt_flags_nocontainers, tvb, 12, 4, flags);
					proto_tree_add_boolean(flags_tree, hf_dtpt_flags_containers, tvb, 12, 4, flags);
					proto_tree_add_boolean(flags_tree, hf_dtpt_flags_deep, tvb, 12, 4, flags);
				}
				payload_size = tvb_get_letohl(tvb, 16);
				proto_tree_add_uint(dtpt_tree, hf_dtpt_payload_size,
					tvb, 16, 4, payload_size);
			}
			break;
			case LookupBeginResponse: {
				proto_tree_add_uint64(dtpt_tree, hf_dtpt_handle,
					tvb, 4, 8, tvb_get_letoh64(tvb, 4));
				proto_tree_add_uint(dtpt_tree, hf_dtpt_error,
					tvb, 12, 4, tvb_get_letohl(tvb, 12));
			}
			break;
			case LookupNextRequest: {
				proto_tree_add_uint64(dtpt_tree, hf_dtpt_handle,
					tvb, 4, 8, tvb_get_letoh64(tvb, 4));
				proto_tree_add_uint(dtpt_tree, hf_dtpt_buffer_size,
					tvb, 16, 4, tvb_get_letohl(tvb, 16));
			}
			break;
			case LookupNextResponse: {
				proto_tree_add_uint(dtpt_tree, hf_dtpt_error,
					tvb, 12, 4, tvb_get_letohl(tvb, 12));
				proto_tree_add_uint(dtpt_tree, hf_dtpt_data_size,
					tvb, 16, 4, tvb_get_letohl(tvb, 16));
			}
			break;
			case LookupEndRequest: {
				proto_tree_add_uint64(dtpt_tree, hf_dtpt_handle,
					tvb, 4, 8, tvb_get_letoh64(tvb, 4));
			}
			break;
			case ConnectRequest: {
				dissect_dtpt_sockaddr(tvb, 2, dtpt_tree, hf_dtpt_connect_addr, SOCKADDR_CONNECT);
				proto_tree_add_uint(dtpt_tree, hf_dtpt_error,
					tvb, 32, 4, tvb_get_letohl(tvb, 32));
			}
			break;
			case ConnectResponseOK: {
				dissect_dtpt_sockaddr(tvb, 2, dtpt_tree, hf_dtpt_connect_addr, SOCKADDR_CONNECT);
				proto_tree_add_uint(dtpt_tree, hf_dtpt_error,
					tvb, 32, 4, tvb_get_letohl(tvb, 32));
			}
			break;
			case ConnectResponseERR: {
				dissect_dtpt_sockaddr(tvb, 2, dtpt_tree, hf_dtpt_connect_addr, SOCKADDR_CONNECT);
				proto_tree_add_uint(dtpt_tree, hf_dtpt_error,
					tvb, 32, 4, tvb_get_letohl(tvb, 32));
			}
			break;
		}
	}

	return tvb_length(tvb);
}

void proto_reg_handoff_dtpt(void);

void
proto_register_dtpt(void)
{
	static hf_register_info hf[] = {
		{ &hf_dtpt_version,
		  { "Version", "dtpt.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Protocol Version", HFILL }},

		{ &hf_dtpt_message_type,
		  { "Message Type", "dtpt.message_type",
		    FT_UINT8, BASE_DEC, VALS(names_message_type), 0x0,
		    "Packet Message Type", HFILL }},

		{ &hf_dtpt_flags,
		  { "ControlFlags", "dtpt.flags",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "ControlFlags as documented for WSALookupServiceBegin", HFILL }},

		{ &hf_dtpt_flags_deep,
		  { "DEEP", "dtpt.flags.deep",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), LUP_DEEP,
		    NULL, HFILL }},

		{ &hf_dtpt_flags_containers,
		  { "CONTAINERS", "dtpt.flags.containers",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), LUP_CONTAINERS,
		    NULL, HFILL }},

		{ &hf_dtpt_flags_nocontainers,
		  { "NOCONTAINERS", "dtpt.flags.nocontainers",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), LUP_NOCONTAINERS,
		    NULL, HFILL }},

		{ &hf_dtpt_flags_nearest,
		  { "NEAREST", "dtpt.flags.nearest",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), LUP_NEAREST,
		    NULL, HFILL }},

		{ &hf_dtpt_flags_return_name,
		  { "RETURN_NAME", "dtpt.flags.return_name",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), LUP_RETURN_NAME,
		    NULL, HFILL }},

		{ &hf_dtpt_flags_return_type,
		  { "RETURN_TYPE", "dtpt.flags.return_type",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), LUP_RETURN_TYPE,
		    NULL, HFILL }},

		{ &hf_dtpt_flags_return_version,
		  { "RETURN_VERSION", "dtpt.flags.return_version",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), LUP_RETURN_VERSION,
		    NULL, HFILL }},

		{ &hf_dtpt_flags_return_comment,
		  { "RETURN_COMMENT", "dtpt.flags.return_comment",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), LUP_RETURN_COMMENT,
		    NULL, HFILL }},

		{ &hf_dtpt_flags_return_addr,
		  { "RETURN_ADDR", "dtpt.flags.return_addr",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), LUP_RETURN_ADDR,
		    NULL, HFILL }},

		{ &hf_dtpt_flags_return_blob,
		  { "RETURN_BLOB", "dtpt.flags.return_blob",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), LUP_RETURN_BLOB,
		    NULL, HFILL }},

		{ &hf_dtpt_flags_return_aliases,
		  { "RETURN_ALIASES", "dtpt.flags.return_aliases",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), LUP_RETURN_ALIASES,
		    NULL, HFILL }},

		{ &hf_dtpt_flags_return_query_string,
		  { "RETURN_QUERY_STRING", "dtpt.flags.return_query_string",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), LUP_RETURN_QUERY_STRING,
		    NULL, HFILL }},

		{ &hf_dtpt_flags_flushcache,
		  { "FLUSHCACHE", "dtpt.flags.flushcache",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), LUP_FLUSHCACHE,
		    NULL, HFILL }},

		{ &hf_dtpt_flags_flushprevious,
		  { "FLUSHPREVIOUS", "dtpt.flags.flushprevious",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), LUP_FLUSHPREVIOUS,
		    NULL, HFILL }},

		{ &hf_dtpt_flags_res_service,
		  { "RES_SERVICE", "dtpt.flags.res_service",
		    FT_BOOLEAN, 32, TFS(&tfs_set_notset), LUP_RES_SERVICE,
		    NULL, HFILL }},

		{ &hf_dtpt_payload_size,
		  { "Payload Size", "dtpt.payload_size",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Payload Size of the following packet containing a serialized WSAQUERYSET", HFILL }},

		{ &hf_dtpt_handle,
		  { "Handle", "dtpt.handle",
		    FT_UINT64, BASE_HEX, NULL, 0x0,
		    "Lookup handle", HFILL }},

		{ &hf_dtpt_error,
		  { "Last Error", "dtpt.error",
		    FT_UINT32, BASE_DEC, VALS(names_error), 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_buffer_size,
		  { "Buffer Size", "dtpt.buffer_size",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_data_size,
		  { "Data Size", "dtpt.data_size",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_queryset_rawsize,
		  { "QuerySet Size", "dtpt.queryset_size",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Size of the binary WSAQUERYSET", HFILL }},

		{ &hf_dtpt_queryset_size,
		  { "dwSize", "dtpt.queryset.dwSize",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "dwSize field in WSAQUERYSET", HFILL }},

		{ &hf_dtpt_queryset_service_instance_name_pointer,
		  { "lpszServiceInstanceName", "dtpt.queryset.lpszServiceInstanceName",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "lpszServiceInstanceName field in WSAQUERYSET", HFILL }},

		{ &hf_dtpt_queryset_service_class_id_pointer,
		  { "lpServiceClassId", "dtpt.queryset.lpServiceClassId",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "lpServiceClassId in the WSAQUERYSET", HFILL }},

		{ &hf_dtpt_queryset_version,
		  { "lpVersion", "dtpt.queryset.lpVersion",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "lpVersion in WSAQUERYSET", HFILL }},

		{ &hf_dtpt_queryset_comment_pointer,
		  { "lpszComment", "dtpt.lpszComment",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "lpszComment field in WSAQUERYSET", HFILL }},

		{ &hf_dtpt_queryset_namespace,
		  { "dwNameSpace", "dtpt.queryset.dwNameSpace",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "dwNameSpace field in WSAQUERYSE", HFILL }},

		{ &hf_dtpt_queryset_provider_id_pointer,
		  { "lpNSProviderId", "dtpt.queryset.lpNSProviderId",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "lpNSProviderId field in WSAQUERYSET", HFILL }},

		{ &hf_dtpt_queryset_context_pointer,
		  { "lpszContext", "dtpt.queryset.lpszContext",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "lpszContext field in WSAQUERYSET", HFILL }},

		{ &hf_dtpt_queryset_protocols_number,
		  { "dwNumberOfProtocols", "dtpt.queryset.dwNumberOfProtocols",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "dwNumberOfProtocols field in WSAQUERYSET", HFILL }},

		{ &hf_dtpt_queryset_protocols_pointer,
		  { "lpafpProtocols", "dtpt.queryset.lpafpProtocols",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "lpafpProtocols field in WSAQUERYSET", HFILL }},

		{ &hf_dtpt_queryset_query_string_pointer,
		  { "lpszQueryString", "dtpt.queryset.lpszQueryString",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "lpszQueryString field in WSAQUERYSET", HFILL }},

		{ &hf_dtpt_queryset_cs_addrs_number,
		  { "dwNumberOfCsAddrs", "dtpt.queryset.dwNumberOfCsAddrs",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "dwNumberOfCsAddrs field in WSAQUERYSET", HFILL }},

		{ &hf_dtpt_queryset_cs_addrs_pointer,
		  { "lpcsaBuffer", "dtpt.queryset.lpcsaBuffer",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "lpcsaBuffer field in WSAQUERYSET", HFILL }},

		{ &hf_dtpt_queryset_output_flags,
		  { "dwOutputFlags", "dtpt.queryset.dwOutputFlags",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "dwOutputFlags field in WSAQUERYSET", HFILL }},

		{ &hf_dtpt_queryset_blob_pointer,
		  { "lpBlob", "dtpt.queryset.lpBlob",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "lpBlob field in WSAQUERYSET", HFILL }},

		{ &hf_dtpt_wstring_length,
		  { "Length", "dtpt.wstring.length",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "String Length", HFILL }},

		{ &hf_dtpt_wstring_data,
		  { "Data", "dtpt.wstring.data",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "String Data", HFILL }},

		{ &hf_dtpt_guid_length,
		  { "Length", "dtpt.guid.length",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "GUID Length", HFILL }},

		{ &hf_dtpt_guid_data,
		  { "Data", "dtpt.guid.data",
		    FT_GUID, BASE_NONE, NULL, 0x0,
		    "GUID Data", HFILL }},

		{ &hf_dtpt_service_instance_name,
		  { "Service Instance Name", "dtpt.service_instance_name",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_service_class_id,
		  { "Service Class ID", "dtpt.service_class_id",
		    FT_GUID, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_comment,
		  { "Comment", "dtpt.comment",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_ns_provider_id,
		  { "NS Provider ID", "dtpt.ns_provider_id",
		    FT_GUID, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_context,
		  { "Context", "dtpt.context",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_protocols_number,
		  { "Number of Protocols", "dtpt.protocols.number",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_protocols_length,
		  { "Length of Protocols", "dtpt.protocols.length",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_protocol_family,
		  { "Family", "dtpt.protocol.family",
		    FT_UINT32, BASE_DEC, VALS(names_family), 0x0,
		    "Protocol Family", HFILL }},

		{ &hf_dtpt_protocol_protocol,
		  { "Protocol", "dtpt.protocol.protocol",
		    FT_UINT32, BASE_DEC, VALS(names_protocol), 0x0,
		    "Protocol Protocol", HFILL }},

		{ &hf_dtpt_query_string,
		  { "Query String", "dtpt.query_string",
		    FT_STRINGZ, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_cs_addrs_number,
		  { "Number of CS Addresses", "dtpt.cs_addrs.number",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_cs_addrs_length1,
		  { "Length of CS Addresses Part 1", "dtpt.cs_addrs.length1",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_cs_addr_socket_type,
		  { "Socket Type", "dtpt.cs_addrs.socket_type",
		    FT_UINT32, BASE_DEC, VALS(names_socket_type), 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_cs_addr_protocol,
		  { "Protocol", "dtpt.cs_addrs.protocol",
		    FT_UINT32, BASE_DEC, VALS(names_protocol), 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_cs_addr_local_pointer,
		  { "Local Address Pointer", "dtpt.cs_addr.local_pointer",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_cs_addr_local_length,
		  { "Local Address Length", "dtpt.cs_addr.local_length",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Local Address Pointer", HFILL }},

		{ &hf_dtpt_cs_addr_local,
		  { "Local Address", "dtpt.cs_addr.local",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_cs_addr_remote_pointer,
		  { "Remote Address Pointer", "dtpt.cs_addr.remote_pointer",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_cs_addr_remote_length,
		  { "Remote Address Length", "dtpt.cs_addr.remote_length",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Remote Address Pointer", HFILL }},

		{ &hf_dtpt_cs_addr_remote,
		  { "Remote Address", "dtpt.cs_addr.remote",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dtpt_sockaddr_length,
		  { "Length", "dtpt.sockaddr.length",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Socket Address Length", HFILL }},

		{ &hf_dtpt_sockaddr_family,
		  { "Family", "dtpt.sockaddr.family",
		    FT_UINT16, BASE_DEC, VALS(names_family), 0x0,
		    "Socket Address Family", HFILL }},

		{ &hf_dtpt_sockaddr_port,
		  { "Port", "dtpt.sockaddr.port",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Socket Address Port", HFILL }},

		{ &hf_dtpt_sockaddr_address,
		  { "Address", "dtpt.sockaddr.address",
		    FT_IPv4, BASE_NONE, NULL, 0x0,
		    "Socket Address Address", HFILL }},

		{ &hf_dtpt_blob_rawsize,
		  { "Blob Size", "dtpt.blob_size",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Size of the binary BLOB", HFILL }},

		{ &hf_dtpt_blob_size,
		  { "cbSize", "dtpt.blob.cbSize",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "cbSize field in BLOB", HFILL }},

		{ &hf_dtpt_blob_data_pointer,
		  { "pBlobData", "dtpt.blob.pBlobData",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "pBlobData field in BLOB", HFILL }},

		{ &hf_dtpt_blob_data_length,
		  { "Length", "dtpt.blob.data_length",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Length of the Blob Data Block", HFILL }},

		{ &hf_dtpt_blob_data,
		  { "Data", "dtpt.blob.data",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Blob Data Block", HFILL }},

		{ &hf_dtpt_connect_addr,
		  { "Address", "dtpt.connect_addr",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Connect to Address", HFILL }},
	};
	static gint *ett[] = {
		&ett_dtpt,
		&ett_dtpt_flags,
		&ett_dtpt_queryset,
		&ett_dtpt_wstring,
		&ett_dtpt_guid,
		&ett_dtpt_protocols,
		&ett_dtpt_protocol,
		&ett_dtpt_cs_addrs,
		&ett_dtpt_cs_addr1,
		&ett_dtpt_cs_addr2,
		&ett_dtpt_sockaddr,
		&ett_dtpt_blobraw,
		&ett_dtpt_blob,
	};
	module_t *dtpt_module;
	e_guid_t guid_svcid_inet_hostaddrbyname       = {0x0002A803, 0x0000, 0x0000, {0xC0,0,0,0,0,0,0,0x46}};
	e_guid_t guid_svcid_inet_hostaddrbyinetstring = {0x0002A801, 0x0000, 0x0000, {0xC0,0,0,0,0,0,0,0x46}};
	guids_add_guid(&guid_svcid_inet_hostaddrbyname,       "SVCID_INET_HOSTADDRBYNAME");
	guids_add_guid(&guid_svcid_inet_hostaddrbyinetstring, "SVCID_INET_HOSTADDRBYINETSTRING");

	proto_dtpt = proto_register_protocol("DeskTop PassThrough Protocol",
					     "DTPT", "dtpt");
	proto_register_field_array(proto_dtpt, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register a configuration option for port */
	dtpt_module = prefs_register_protocol(proto_dtpt,
					      proto_reg_handoff_dtpt);
	prefs_register_uint_preference(dtpt_module, "tcp.port",
				       "DTPT Server TCP Port",
				       "Set the TDP port for the DTPT Server",
				       10, &gbl_dtptServerPort);
}


void
proto_reg_handoff_dtpt(void)
{
	static dissector_handle_t	dtpt_handle;
	static gboolean Initialized=FALSE;
	static int ServerPort;

	if (!Initialized) {
		dtpt_handle = new_create_dissector_handle(dissect_dtpt, proto_dtpt);
		dtpt_conversation_handle = new_create_dissector_handle(dissect_dtpt_conversation, proto_dtpt);
/**		dtpt_data_handle = new_create_dissector_handle(dissect_dtpt_data, proto_dtpt); **/

		data_handle = find_dissector("data");
		Initialized=TRUE;
	} else {
		dissector_delete_uint("tcp.port", ServerPort, dtpt_handle);
	}

	/* set port for future deletes */
	ServerPort=gbl_dtptServerPort;

	dissector_add_uint("tcp.port", gbl_dtptServerPort, dtpt_handle);
}


