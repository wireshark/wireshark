/*
 * packet-radius.h
 *
 * Definitions for RADIUS packet disassembly
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/proto.h>

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

/* ALU proprietary packet type codes */
#define RADIUS_PKT_TYPE_ALU_STATE_REQUEST			129
#define RADIUS_PKT_TYPE_ALU_STATE_ACCEPT			130
#define RADIUS_PKT_TYPE_ALU_STATE_REJECT			131
#define RADIUS_PKT_TYPE_ALU_STATE_ERROR 			132

/* Radius Attribute Types*/
/* 09/12/2011: Updated from IANA:
 * http://www.iana.org/assignments/radius-types/radius-types.xml#radius-types-1
 */
#define RADIUS_ATTR_TYPE_VENDOR_SPECIFIC			26
#define RADIUS_ATTR_TYPE_EAP_MESSAGE				79
#define RADIUS_ATTR_TYPE_EXTENDED_1				241
#define RADIUS_ATTR_TYPE_EXTENDED_2				242
#define RADIUS_ATTR_TYPE_EXTENDED_3				243
#define RADIUS_ATTR_TYPE_EXTENDED_4				244
#define RADIUS_ATTR_TYPE_EXTENDED_5				245
#define RADIUS_ATTR_TYPE_EXTENDED_6				246

#define RADIUS_ATTR_TYPE_IS_EXTENDED(avp_type)			\
	((avp_type) == RADIUS_ATTR_TYPE_EXTENDED_1 ||		\
		(avp_type) == RADIUS_ATTR_TYPE_EXTENDED_2 ||	\
		(avp_type) == RADIUS_ATTR_TYPE_EXTENDED_3 ||	\
		(avp_type) == RADIUS_ATTR_TYPE_EXTENDED_4 ||	\
		(avp_type) == RADIUS_ATTR_TYPE_EXTENDED_5 ||	\
		(avp_type) == RADIUS_ATTR_TYPE_EXTENDED_6)

#define RADIUS_ATTR_TYPE_IS_EXTENDED_LONG(avp_type)		\
	((avp_type) == RADIUS_ATTR_TYPE_EXTENDED_5 ||		\
		(avp_type) == RADIUS_ATTR_TYPE_EXTENDED_6)


typedef struct _radius_vendor_info_t {
	gchar *name;
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

typedef union _radius_attr_type_t {
	guint8 u8_code[2];
	guint  value;
} radius_attr_type_t;

struct _radius_attr_info_t {
	gchar *name;
	radius_attr_type_t code;
	guint encrypt;  /* 0 or value for "encrypt=" option */
	gboolean tagged;
	radius_attr_dissector_t* type;
	radius_avp_dissector_t* dissector;
	const value_string *vs;
	gint ett;
	int hf;
	int hf_alt;     /* 64-bit version for integers, encrypted version for strings, IPv6 for radius_combo_ip */
	int hf_tag;
	int hf_len;
	GHashTable* tlvs_by_id; /**< Owns the data (see also radius_dictionary_t). */
};

/*
 * Attributes and Vendors are a mapping between IDs and names. Names
 * are normally uniquely identified by a number. Identifiers for
 * Vendor-Specific Attributes (VSA) are scoped within the vendor.
 *
 * The attribute/vendor structures are owned by the by_id tables,
 * the by_name tables point to the same data.
 */
typedef struct _radius_dictionary_t {
	GHashTable* attrs_by_id;
	GHashTable* attrs_by_name;
	GHashTable* vendors_by_id;
	GHashTable* vendors_by_name;
	GHashTable* tlvs_by_name;   /**< Used for debugging duplicate assignments, does not own the data. */
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
void dissect_attribute_value_pairs(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset, guint length);
extern void free_radius_attr_info(gpointer data);

/* from radius_dict.l */
gboolean radius_load_dictionary (radius_dictionary_t* dict, gchar* directory, const gchar* filename, gchar** err_str);
