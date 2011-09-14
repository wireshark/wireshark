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

/* radius packet-type codes */
/* 09/12/2011: Updated from IANA:
 * http://www.iana.org/assignments/radius-types/radius-types.xml#radius-types-27
 */
#define RADIUS_PKT_TYPE_ACCESS_REQUEST				1
#define RADIUS_PKT_TYPE_ACCESS_ACCEPT				2
#define RADIUS_PKT_TYPE_ACCESS_REJECT				3
#define RADIUS_PKT_TYPE_ACCOUNTING_REQUEST			4
#define RADIUS_PKT_TYPE_ACCOUNTING_RESPONSE			5
#define RADIUS_PKT_TYPE_ACCOUNTING_STATUS			6
#define RADIUS_PKT_TYPE_PASSWORD_REQUEST			7
#define RADIUS_PKT_TYPE_PASSWORD_ACK				8
#define RADIUS_PKT_TYPE_PASSWORD_REJECT				9
#define RADIUS_PKT_TYPE_ACCOUNTING_MESSAGE			10
#define RADIUS_PKT_TYPE_ACCESS_CHALLENGE			11
#define RADIUS_PKT_TYPE_STATUS_SERVER				12
#define RADIUS_PKT_TYPE_STATUS_CLIENT				13

#define RADIUS_PKT_TYPE_RESOURCE_FREE_REQUEST			21
#define RADIUS_PKT_TYPE_RESOURCE_FREE_RESPONSE			22
#define RADIUS_PKT_TYPE_RESOURCE_QUERY_REQUEST			23
#define RADIUS_PKT_TYPE_RESOURCE_QUERY_RESPONSE			24
#define RADIUS_PKT_TYPE_ALTERNATE_RESOURCE_RECLAIM_REQUEST	25
#define RADIUS_PKT_TYPE_NAS_REBOOT_REQUEST			26
#define RADIUS_PKT_TYPE_NAS_REBOOT_RESPONSE			27

#define RADIUS_PKT_TYPE_NEXT_PASSCODE				29
#define RADIUS_PKT_TYPE_NEW_PIN					30
#define RADIUS_PKT_TYPE_TERMINATE_SESSION			31
#define RADIUS_PKT_TYPE_PASSWORD_EXPIRED			32
#define RADIUS_PKT_TYPE_EVENT_REQUEST				33
#define RADIUS_PKT_TYPE_EVENT_RESPONSE				34

#define RADIUS_PKT_TYPE_DISCONNECT_REQUEST			40
#define RADIUS_PKT_TYPE_DISCONNECT_ACK				41
#define RADIUS_PKT_TYPE_DISCONNECT_NAK				42
#define RADIUS_PKT_TYPE_COA_REQUEST				43
#define RADIUS_PKT_TYPE_COA_ACK					44
#define RADIUS_PKT_TYPE_COA_NAK					45

#define RADIUS_PKT_TYPE_IP_ADDRESS_ALLOCATE			50
#define RADIUS_PKT_TYPE_IP_ADDRESS_RELEASE			51


/* Radius Attribute Types*/
/* 09/12/2011: Updated from IANA:
 * http://www.iana.org/assignments/radius-types/radius-types.xml#radius-types-1
 */
#define RADIUS_ATTR_TYPE_VENDOR_SPECIFIC			26
#define RADIUS_ATTR_TYPE_EAP_MESSAGE				79


typedef struct _radius_vendor_info_t {
	const gchar *name;
	guint code;
	GHashTable* attrs_by_id;
	gint ett;
	guint type_octets;
	guint length_octets;
	gboolean has_flags;
} radius_vendor_info_t;

typedef struct _radius_attr_info_t radius_attr_info_t;
typedef void (radius_attr_dissector_t)(radius_attr_info_t*, proto_tree*, packet_info*, tvbuff_t*, int, int, proto_item* );

typedef const gchar* (radius_avp_dissector_t)(proto_tree*,tvbuff_t*, packet_info*);

struct _radius_attr_info_t {
	const gchar *name;
	guint code;
	gboolean encrypt;  /* True if attribute has "encrypt=1" option */
	gboolean tagged;
	radius_attr_dissector_t* type;
	radius_avp_dissector_t* dissector;
	const value_string *vs;
	gint ett;
	int hf;
	int hf64;
	int hf_tag;
	int hf_len;
	GHashTable* tlvs_by_id;
};

typedef struct _radius_dictionary_t {
	GHashTable* attrs_by_id;
	GHashTable* attrs_by_name;
	GHashTable* vendors_by_id;
	GHashTable* vendors_by_name;
	GHashTable* tlvs_by_name;
} radius_dictionary_t;

radius_attr_dissector_t radius_integer;
radius_attr_dissector_t radius_string;
radius_attr_dissector_t radius_octets;
radius_attr_dissector_t radius_ipaddr;
radius_attr_dissector_t radius_ipv6addr;
radius_attr_dissector_t radius_ipv6prefix;
radius_attr_dissector_t radius_ipxnet;
radius_attr_dissector_t radius_date;
radius_attr_dissector_t radius_abinary;
radius_attr_dissector_t radius_ether;
radius_attr_dissector_t radius_ifid;
radius_attr_dissector_t radius_byte;
radius_attr_dissector_t radius_short;
radius_attr_dissector_t radius_signed;
radius_attr_dissector_t radius_combo_ip;
radius_attr_dissector_t radius_tlv;

extern void radius_register_avp_dissector(guint32 vendor_id, guint32 attribute_id, radius_avp_dissector_t dissector);

/* from radius_dict.l */
gboolean radius_load_dictionary (radius_dictionary_t* dict, gchar* directory, const gchar* filename, gchar** err_str);

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

