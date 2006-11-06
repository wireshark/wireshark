/*
 * packet-radius.h
 *
 * Definitions for RADIUS packet disassembly
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
 */

#define RADIUS_ACCESS_REQUEST			1
#define RADIUS_ACCESS_ACCEPT			2
#define RADIUS_ACCESS_REJECT			3
#define RADIUS_ACCOUNTING_REQUEST		4
#define RADIUS_ACCOUNTING_RESPONSE		5
#define RADIUS_ACCOUNTING_STATUS		6
#define RADIUS_ACCESS_PASSWORD_REQUEST		7
#define RADIUS_ACCESS_PASSWORD_ACK		8
#define RADIUS_ACCESS_PASSWORD_REJECT		9
#define RADIUS_ACCOUNTING_MESSAGE		10
#define RADIUS_ACCESS_CHALLENGE			11
#define RADIUS_STATUS_SERVER			12
#define RADIUS_STATUS_CLIENT			13

#define RADIUS_VENDOR_SPECIFIC_CODE		26
#define RADIUS_ASCEND_ACCESS_NEXT_CODE		29
#define RADIUS_ASCEND_ACCESS_NEW_PIN		30
#define RADIUS_ASCEND_PASSWORD_EXPIRED		32
#define RADIUS_ASCEND_ACCESS_EVENT_REQUEST	33
#define RADIUS_ASCEND_ACCESS_EVENT_RESPONSE	34
#define RADIUS_DISCONNECT_REQUEST		40
#define RADIUS_DISCONNECT_REQUEST_ACK		41
#define RADIUS_DISCONNECT_REQUEST_NAK		42
#define RADIUS_CHANGE_FILTER_REQUEST		43
#define RADIUS_CHANGE_FILTER_REQUEST_ACK	44
#define RADIUS_CHANGE_FILTER_REQUEST_NAK	45
#define RADIUS_EAP_MESSAGE_CODE				79
#define RADIUS_RESERVED				255

typedef struct _radius_vendor_info_t {
	const gchar *name;
	guint code;
	GHashTable* attrs_by_id;
    gint ett;
} radius_vendor_info_t;

typedef struct _radius_attr_info_t radius_attr_info_t;
typedef void (radius_attr_dissector_t)(radius_attr_info_t*, proto_tree*, packet_info*, tvbuff_t*, int, int, proto_item* );

typedef const gchar* (radius_avp_dissector_t)(proto_tree*,tvbuff_t*);

struct _radius_attr_info_t {
	const gchar *name;
	guint code;
	gboolean encrypt;
	gboolean tagged;
	radius_attr_dissector_t* type;
	radius_avp_dissector_t* dissector;
	const value_string *vs;
	gint ett;
	int hf;
	int hf64;
	int hf_tag;
	int hf_len;
};

typedef struct _radius_dictionary_t {
	GHashTable* attrs_by_id;
	GHashTable* attrs_by_name;
	GHashTable* vendors_by_id;
	GHashTable* vendors_by_name;
} radius_dictionary_t;

radius_attr_dissector_t radius_integer;
radius_attr_dissector_t radius_string;
radius_attr_dissector_t radius_octets;
radius_attr_dissector_t radius_ipaddr;
radius_attr_dissector_t radius_ipv6addr;
radius_attr_dissector_t radius_ipxnet;
radius_attr_dissector_t radius_date;
radius_attr_dissector_t radius_abinary;
radius_attr_dissector_t radius_ifid;

extern void radius_register_avp_dissector(guint32 vendor_id, guint32 attribute_id, radius_avp_dissector_t dissector);

/* from radius_dict.l */
radius_dictionary_t* radius_load_dictionary (gchar* directory, const gchar* filename, gchar** err_str);

/* Item of request list */
typedef struct _radius_call_t
{
	guint code;
	guint ident;

	guint32 req_num; /* frame number request seen */
	guint32 rsp_num; /* frame number response seen */
	guint32 rspcode;
	nstime_t req_time;
	gboolean responded;
} radius_call_t;

/* Container for tapping relevant data */
typedef struct _radius_info_t
{
	guint code;
	guint ident;
	nstime_t req_time;
	gboolean is_duplicate;
	gboolean request_available;
	guint32 req_num; /* frame number request seen */
	guint32 rspcode;
} radius_info_t;

