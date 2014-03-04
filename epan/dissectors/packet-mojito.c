/* packet-mojito.c
 * Routines for Dissecting the Gnutella Mojito DHT Protocol
 * http://limewire.negatis.com/index.php?title=Mojito_Message_Format
 *
 * Copyright (c) 2008 by Travis Dawson <travis.dawson@sprint.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

void proto_register_mojito(void);
void proto_reg_handoff_mojito(void);

#define MOJITO_HEADER_LENGTH    38

/* All the Defines for OpCodes */
#define MOJITO_PING_REQUEST                1
#define MOJITO_PING_RESPONSE               2
#define MOJITO_STORE_REQUEST               3
#define MOJITO_STORE_RESPONSE              4
#define MOJITO_FIND_NODE_REQUEST           5
#define MOJITO_FIND_NODE_RESPONSE          6
#define MOJITO_FIND_VALUE_REQUEST          7
#define MOJITO_FIND_VALUE_RESPONSE         8
#define MOJITO_STATS_REQUEST_DEPRECATED    9
#define MOJITO_STATS_RESPONSE_DEPRECATED  10

/* Initialize the protocol and registered fields */
static int proto_mojito = -1;

/* Start of fields */
static int hf_mojito_messageid = -1;
static int hf_mojito_fdhtmessage = -1;
static int hf_mojito_mjrversion = -1;
static int hf_mojito_mnrversion = -1;
static int hf_mojito_length = -1;
static int hf_mojito_opcode = -1;
static int hf_mojito_vendor = -1;
static int hf_mojito_origmjrversion = -1;
static int hf_mojito_origmnrversion = -1;
static int hf_mojito_kuid = -1;
static int hf_mojito_socketaddress_version = -1;
static int hf_mojito_socketaddress_ipv4 = -1;
static int hf_mojito_socketaddress_ipv6 = -1;
static int hf_mojito_socketaddress_port = -1;
static int hf_mojito_instanceid = -1;
static int hf_mojito_flags = -1;
static int hf_mojito_flags_shutdown = -1;
static int hf_mojito_flags_firewalled = -1;
static int hf_mojito_extendedlength = -1;
static int hf_mojito_kuidcount = -1;
static int hf_mojito_bigintegerlen = -1;
static int hf_mojito_bigintegerval = -1;
static int hf_mojito_dhtvaluetype = -1;
static int hf_mojito_sectokenlen = -1;
static int hf_mojito_sectoken = -1;
static int hf_mojito_contactcount = -1;
static int hf_mojito_contactvendor = -1;
static int hf_mojito_contactversion = -1;
static int hf_mojito_contactkuid = -1;
static int hf_mojito_dhtvaluecount = -1;
static int hf_mojito_dhtvalue_kuid = -1;
static int hf_mojito_target_kuid = -1;
static int hf_mojito_dhtvalue_valuetype = -1;
static int hf_mojito_dhtvalue_version = -1;
static int hf_mojito_dhtvalue_length = -1;
static int hf_mojito_dhtvalue_value = -1;
static int hf_mojito_bigint_value_one = -1;
static int hf_mojito_bigint_value_two = -1;
static int hf_mojito_bigint_value_three = -1;
static int hf_mojito_bigint_value_four = -1;
static int hf_mojito_storestatuscode_count = -1;
static int hf_mojito_storestatuscode_code = -1;
static int hf_mojito_storestatuscode_kuid = -1;
static int hf_mojito_storestatuscode_secondary_kuid = -1;
static int hf_mojito_requestload = -1;
#if 0
static int hf_mojito_startflag = -1;
static int hf_mojito_endflag = -1;
static int hf_mojito_priorityflag = -1;
#endif
static int hf_mojito_opcode_data = -1;

/* Initialize the subtree pointers */
static gint ett_mojito = -1;
static gint ett_mojito_header = -1;
static gint ett_mojito_header_version = -1;
static gint ett_mojito_contact = -1;
static gint ett_mojito_contact_version = -1;
static gint ett_mojito_socket_address = -1;
static gint ett_mojito_flags = -1;
static gint ett_mojito_bigint = -1;
static gint ett_mojito_opcode = -1;
static gint ett_mojito_dht_version = -1;
static gint ett_mojito_dht = -1;
static gint ett_mojito_status_code = -1;
static gint ett_mojito_kuids = -1;

static expert_field ei_mojito_socketaddress_unknown = EI_INIT;
static expert_field ei_mojito_bigint_unsupported = EI_INIT;

/* Preferences */
static int udp_mojito_port = 0;

typedef struct mojito_header_data {
	guint8 opcode;
	guint32 payloadlength;
} mojito_header_data_t;

/* Values for OPCode Flags */
static const value_string opcodeflags[] = {
	{ MOJITO_PING_REQUEST,              "PING REQUEST" },
	{ MOJITO_PING_RESPONSE,             "PING RESPONSE" },
	{ MOJITO_STORE_REQUEST,             "STORE REQUEST" },
	{ MOJITO_STORE_RESPONSE,            "STORE RESPONSE" },
	{ MOJITO_FIND_NODE_REQUEST,         "FIND NODE REQUEST" },
	{ MOJITO_FIND_NODE_RESPONSE,        "FIND NODE RESPONSE" },
	{ MOJITO_FIND_VALUE_REQUEST,        "FIND VALUE REQUEST" },
	{ MOJITO_FIND_VALUE_RESPONSE,       "FIND VALUE RESPONSE" },
	{ MOJITO_STATS_REQUEST_DEPRECATED,  "STATS REQUEST (DEPRECATED)" },
	{ MOJITO_STATS_RESPONSE_DEPRECATED, "STATS RESPONSE (DEPRECATED)" },
	{ 0, NULL }
};

static const value_string statuscodeflags[] = {
	{ 1, "OK" },
	{ 2, "Error" },
	{ 0, NULL }
};

#if 0
static const value_string vendorcodeflags[] = {
	{  0, "MESSAGES_SUPPORTED" },
	{  4, "HOPS_FLOW" },
	{  5, "CRAWLER_PING" },
	{  6, "CRAWLER_PONG" },
	{  7, "UDP_CONNECT_BACK" },
	{  8, "UDP_CONNECT_BACK_REDIR" },
	{  9, "NGTH_MINUS_PAYLOAD" },
	{ 10, "CAPABILITIES" },
	{ 11, "LIME_ACK" },
	{ 12, "REPLY_NUMBER" },
	{ 13, "OOB_PROXYING_CONTROL" },
	{ 14, "GIVE_STATS" },
	{ 15, "STATISTICS" },
	{ 16, "SIMPP_REQ" },
	{ 17, "SIMPP" },
	{ 21, "PUSH_PROXY_REQ" },
	{ 22, "PUSH_PROXY_ACK" },
	{ 23, "UDP_HEAD_PING" },
	{ 24, "UDP_HEAD_PONG" },
	{ 25, "HEADER_UPDATE" },
	{ 26, "UPDATE_REQ" },
	{ 27, "UPDATE_RESP" },
	{ 28, "CONTENT_REQ" },
	{ 29, "CONTENT_RESP" },
	{ 30, "INSPECTION_REQ" },
	{ 31, "INSPECTION_RESP" },
	{ 32, "ADVANCED_TOGGLE" },
	{ 33, "DHT_CONTACTS" },

	{ 0, NULL }
};
#endif

static int
dissect_mojito_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		int offset, const char *title)
{
	int         offset_start;
	guint8      socket_address_version;
	proto_tree *socket_tree;
	proto_item *socket_item;

	offset_start = offset;

	/* new subtree for socket address*/
	socket_address_version = tvb_get_guint8(tvb, offset);
	socket_item = proto_tree_add_text(tree, tvb, offset, 1, "%s", title);
	socket_tree = proto_item_add_subtree(socket_item, ett_mojito_socket_address);

	proto_tree_add_item(socket_tree, hf_mojito_socketaddress_version, tvb, offset, 1, ENC_NA);
	offset += 1;

	switch (socket_address_version)
	{
	case FT_IPv4_LEN: /* IPv4 */

		proto_tree_add_item(socket_tree, hf_mojito_socketaddress_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		break;

	case FT_IPv6_LEN: /* IPv6 */

		proto_tree_add_item(socket_tree, hf_mojito_socketaddress_ipv6, tvb, offset, 16, ENC_NA);
		offset += 16;
		break;

	default: /* ABORT */
		expert_add_info(pinfo, socket_item, &ei_mojito_socketaddress_unknown);
		return 0;
	}

	proto_tree_add_item(socket_tree, hf_mojito_socketaddress_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_item_set_len(socket_item, offset - offset_start);

	return offset;
}

static int
dissect_mojito_contact(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int contact_id)
{
	int         offset_start;
	proto_tree *contact_tree, *version_tree;
	proto_item *contact_item, *version_item;

	offset_start = offset;

	if (contact_id > 0)
	{
		contact_item = proto_tree_add_text(tree, tvb, offset, 1, "Contact #%d", contact_id);
	}
	else
	{
		contact_item = proto_tree_add_text(tree, tvb, offset, 1, "Contact");
	}
	contact_tree = proto_item_add_subtree(contact_item, ett_mojito_contact);

	proto_tree_add_item(contact_tree, hf_mojito_contactvendor, tvb, offset, 4, ENC_ASCII|ENC_NA);
	offset += 4;

	version_item = proto_tree_add_item(contact_tree, hf_mojito_contactversion, tvb, offset, 2, ENC_BIG_ENDIAN);
	version_tree = proto_item_add_subtree(version_item, ett_mojito_contact_version);
	proto_tree_add_item(version_tree, hf_mojito_mjrversion, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(version_tree, hf_mojito_mnrversion, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(contact_tree, hf_mojito_contactkuid, tvb, offset, 20, ENC_NA);
	offset += 20;

	offset = dissect_mojito_address(tvb, pinfo, contact_tree, offset, "Socket Address");

	if (offset == 0)
	{
		return 0;
	}

	proto_item_set_len(contact_item, offset - offset_start);

	return offset - offset_start;
}

static int
dissect_mojito_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      int offset, mojito_header_data_t* header_data)
{
	proto_tree *header_tree, *version_tree, *contact_tree, *flag_tree;
	proto_item *header_item, *version_item, *contact_item, *flag_item;
	int         start_offset = offset;
	int         contact_start_offset;

	header_item = proto_tree_add_text(tree, tvb, offset, 61, "Gnutella Header");
	header_tree = proto_item_add_subtree(header_item, ett_mojito_header);

	proto_tree_add_item(header_tree, hf_mojito_messageid, tvb, offset, 16, ENC_NA);
	offset += 16;

	proto_tree_add_item(header_tree, hf_mojito_fdhtmessage, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	version_item = proto_tree_add_text(header_tree, tvb, offset, 2, "Version");
	version_tree = proto_item_add_subtree(version_item, ett_mojito_header_version);

	proto_tree_add_item(version_tree, hf_mojito_mjrversion, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(version_tree, hf_mojito_mnrversion, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* Payload Length : in Little Endian */
	header_data->payloadlength = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(header_tree, hf_mojito_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	header_data->opcode = tvb_get_guint8(tvb, offset);
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_const(header_data->opcode, opcodeflags, "Unknown"));
	proto_tree_add_item(header_tree, hf_mojito_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	contact_start_offset = offset;
	contact_item = proto_tree_add_text(header_tree, tvb, offset, 35, "Originating Contact");
	contact_tree = proto_item_add_subtree(contact_item, ett_mojito_contact);

	proto_tree_add_item(contact_tree, hf_mojito_vendor, tvb, offset, 4, ENC_ASCII|ENC_NA);
	offset += 4;

	version_item = proto_tree_add_text(contact_tree, tvb, offset, 2, "Contact Version");
	version_tree = proto_item_add_subtree(version_item, ett_mojito_contact_version);

	proto_tree_add_item(version_tree, hf_mojito_origmjrversion, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	proto_tree_add_item(version_tree, hf_mojito_origmnrversion, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(contact_tree, hf_mojito_kuid, tvb, offset, 20, ENC_NA);
	offset += 20;

	offset = dissect_mojito_address(tvb, pinfo, contact_tree, offset, "Socket Address");

	if (offset == 0)
	{
		return 0;
	}

	proto_item_set_len(contact_item, offset - contact_start_offset);

	proto_tree_add_item(header_tree, hf_mojito_instanceid, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/*Flags*/
	flag_item = proto_tree_add_item(header_tree, hf_mojito_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
	flag_tree = proto_item_add_subtree(flag_item, ett_mojito_flags);
	proto_tree_add_item(flag_tree, hf_mojito_flags_shutdown, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(flag_tree, hf_mojito_flags_firewalled, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(header_tree, hf_mojito_extendedlength, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_item_set_len(header_item, offset-start_offset);
	return offset;
}

static void
dissect_mojito_ping_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	guint8      bigintlen;
	proto_tree *bigint_tree;
	proto_item *bigint_item;

	offset = dissect_mojito_address(tvb, pinfo, tree,
			offset, "Requester's External Socket Address");

	if (offset == 0)
	{
		return;
	}

	/* BigInt subtree */
	bigintlen = tvb_get_guint8(tvb, offset);
	bigint_item = proto_tree_add_text(tree, tvb, offset, bigintlen + 1 , "Estimated DHT size");
	bigint_tree = proto_item_add_subtree(bigint_item, ett_mojito_bigint);

	proto_tree_add_item(bigint_tree, hf_mojito_bigintegerlen, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	switch (bigintlen)
	{
	case 1: /* 1 byte */
		proto_tree_add_item(bigint_tree, hf_mojito_bigint_value_one, tvb, offset, bigintlen, ENC_BIG_ENDIAN);
		break;

	case 2: /* 2 byte */
		proto_tree_add_item(bigint_tree, hf_mojito_bigint_value_two, tvb, offset, bigintlen, ENC_BIG_ENDIAN);
		break;

	case 3: /* 3 byte */
		proto_tree_add_item(bigint_tree, hf_mojito_bigint_value_three, tvb, offset, bigintlen, ENC_BIG_ENDIAN);
		break;

	case 4: /* 4 byte */
		proto_tree_add_item(bigint_tree, hf_mojito_bigint_value_four, tvb, offset, bigintlen, ENC_BIG_ENDIAN);
		break;
	default: /* ABORT */
		expert_add_info(pinfo, bigint_item, &ei_mojito_bigint_unsupported);
		return;
	}

	/* BigInt Value */
	proto_tree_add_item(bigint_tree, hf_mojito_bigintegerval, tvb, offset, bigintlen, ENC_NA);
}

static void
dissect_mojito_store_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	proto_tree *dht_tree, *version_tree;
	proto_item *dht_item, *version_item;
	guint8      ii, contactcount;
	guint8      sectokenlen = tvb_get_guint8(tvb, offset);
	guint16     dhtvaluelength;
	int         contact_offset, start_offset;

	proto_tree_add_item(tree, hf_mojito_sectokenlen, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_mojito_sectoken, tvb, offset, sectokenlen, ENC_NA);
	offset += sectokenlen;

	/* Contact count */
	proto_tree_add_item(tree, hf_mojito_dhtvaluecount, tvb, offset, 1, ENC_BIG_ENDIAN);
	contactcount = tvb_get_guint8(tvb, offset);
	offset += 1;

	/* For each Contact, display the info */
	for (ii = 0; ii < contactcount; ii++)
	{
		dht_item = proto_tree_add_text(tree, tvb, offset, 1, "DHTValue #%d", ii+1);
		dht_tree = proto_item_add_subtree(dht_item, ett_mojito_dht);
		start_offset = offset;
		contact_offset = dissect_mojito_contact(tvb, pinfo, dht_tree, offset, -1);
		if (contact_offset == 0)
			return;
		offset += contact_offset;

		proto_tree_add_item(dht_tree, hf_mojito_dhtvalue_kuid, tvb, offset, 20, ENC_NA);
		offset += 20;

		proto_tree_add_item(dht_tree, hf_mojito_dhtvalue_valuetype, tvb, offset, 4, ENC_ASCII|ENC_NA);
		offset += 4;

		/* Version */
		version_item = proto_tree_add_item(dht_tree, hf_mojito_dhtvalue_version, tvb, offset, 2, ENC_BIG_ENDIAN);
		version_tree = proto_item_add_subtree(version_item, ett_mojito_dht_version);

		proto_tree_add_item(version_tree, hf_mojito_mjrversion, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(version_tree, hf_mojito_mnrversion, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		dhtvaluelength = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(dht_tree, hf_mojito_dhtvalue_length, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(dht_tree, hf_mojito_dhtvalue_value, tvb, offset, dhtvaluelength, ENC_ASCII|ENC_NA);
		offset += dhtvaluelength;

		proto_item_set_len(dht_item, offset-start_offset);
	}
}

static void
dissect_mojito_store_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_tree *sc_tree;
	proto_item *sc_item;
	guint8      ii, contactcount = tvb_get_guint8(tvb, offset);
	guint16     dhtvaluelength;
	int         start_offset;

	proto_tree_add_item(tree, hf_mojito_storestatuscode_count, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* For each Contact, display the info */
	for (ii = 0; ii < contactcount; ii++)
	{
		sc_item = proto_tree_add_text(tree, tvb, offset, 23, "Status Code %d", ii+1);
		sc_tree = proto_item_add_subtree(sc_item, ett_mojito_status_code);

		start_offset = offset;

		/*Primary KUID */
		proto_tree_add_item(sc_tree, hf_mojito_storestatuscode_kuid, tvb, offset, 20, ENC_NA);
		offset += 20;

		if (tvb_reported_length_remaining(tvb, offset+3) > 0)
		{
			/* Must be a secondard KUID */
			proto_tree_add_item(sc_tree, hf_mojito_storestatuscode_secondary_kuid, tvb, offset, 20, ENC_NA);
			offset += 20;
		}

		proto_tree_add_item(sc_tree, hf_mojito_storestatuscode_code, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		dhtvaluelength = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(sc_tree, hf_mojito_dhtvalue_length, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(sc_tree, hf_mojito_dhtvalue_value, tvb, offset, dhtvaluelength, ENC_ASCII|ENC_NA);
		offset += dhtvaluelength;

		proto_item_set_len(sc_item, offset-start_offset);
	}
}

static void
dissect_mojito_find_node_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	guint8 ii, contactcount;
	guint8 sectokenlen = tvb_get_guint8(tvb, offset);
	int    contact_offset;

	proto_tree_add_item(tree, hf_mojito_sectokenlen, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_mojito_sectoken, tvb, offset, sectokenlen, ENC_NA);
	offset += sectokenlen;

	contactcount = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_mojito_contactcount, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* For each Contact, display the info */
	for (ii = 0; ii < contactcount; ii++)
	{
		contact_offset = dissect_mojito_contact(tvb, pinfo, tree, offset, ii+1);
		if (contact_offset == 0)
			return;
		offset += contact_offset;
	}
}

static void
dissect_mojito_find_value_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
	proto_tree *kuid_tree;
	proto_item *kuid_item;
	guint8      i, kuidcount;

	if (!tree)
		return;

	proto_tree_add_item(tree, hf_mojito_target_kuid, tvb, offset, 20, ENC_NA);
	offset += 20;

	kuidcount = tvb_get_guint8(tvb, offset);

	kuid_item = proto_tree_add_text(tree, tvb, offset, (20 * kuidcount) + 1 , "Secondary KUID\'s");
	kuid_tree = proto_item_add_subtree(kuid_item, ett_mojito_kuids);

	proto_tree_add_item(kuid_tree, hf_mojito_kuidcount, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* All the Secondary KUID's */
	for (i = 0; i < kuidcount; i++)
	{
		proto_tree_add_item(kuid_tree, hf_mojito_kuid, tvb, offset, 20, ENC_NA);
		offset += 20;
	}

	proto_tree_add_item(tree, hf_mojito_dhtvaluetype, tvb, offset, 4, ENC_ASCII|ENC_NA);
	/*offset += 4;*/
}

static void
dissect_mojito_find_value_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	proto_tree *dht_tree, *version_tree, *kuid_tree;
	proto_item *dht_item, *version_item, *kuid_item;
	guint16     dhtvaluelength;
	int         contact_offset, start_offset;
	guint8      ii, dhtvaluescount, kuidcount;

	proto_tree_add_item(tree, hf_mojito_requestload, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	dhtvaluescount = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(tree, hf_mojito_dhtvaluecount, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* For each Contact, display the info */
	for (ii = 0; ii < dhtvaluescount; ii++)
	{
		dht_item = proto_tree_add_text(tree, tvb, offset, 1, "DHTValue #%d", ii+1);
		dht_tree = proto_item_add_subtree(dht_item, ett_mojito_dht);
		start_offset = offset;
		contact_offset = dissect_mojito_contact(tvb, pinfo, dht_tree, offset, -1);
		if (contact_offset == 0)
			return;

		offset += contact_offset;

		proto_tree_add_item(dht_tree, hf_mojito_dhtvalue_kuid, tvb, offset, 20, ENC_NA);
		offset += 20;

		proto_tree_add_item(dht_tree, hf_mojito_dhtvalue_valuetype, tvb, offset, 4, ENC_ASCII|ENC_NA);
		offset += 4;

		/* Version */
		version_item = proto_tree_add_item(dht_tree, hf_mojito_dhtvalue_version, tvb, offset, 2, ENC_BIG_ENDIAN);
		version_tree = proto_item_add_subtree(version_item, ett_mojito_dht_version);

		proto_tree_add_item(version_tree, hf_mojito_mjrversion, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		proto_tree_add_item(version_tree, hf_mojito_mnrversion, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		/* Length */
		dhtvaluelength = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(dht_tree, hf_mojito_dhtvalue_length, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		/* Value */
		proto_tree_add_item(dht_tree, hf_mojito_dhtvalue_value, tvb, offset, dhtvaluelength, ENC_ASCII|ENC_NA);
		offset += dhtvaluelength;

		proto_item_set_len(dht_item, offset-start_offset);
	}

	/*KUID Count */
	kuidcount = tvb_get_guint8(tvb, offset);
	kuid_item = proto_tree_add_text(tree, tvb, offset, (20 * kuidcount) + 1 , "Secondary KUID\'s");
	kuid_tree = proto_item_add_subtree(kuid_item, ett_mojito_kuids);
	proto_tree_add_item(kuid_tree, hf_mojito_kuidcount, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* All the Secondary KUID's */
	for (ii = 0; ii < kuidcount; ii++)
	{
		proto_tree_add_item(kuid_tree, hf_mojito_kuid, tvb, offset, 20, ENC_NA);
		offset += 20;
	}
}

static int
dissect_mojito(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_tree           *mojito_tree, *opcode_tree;
	proto_item           *ti, *opcode_item;
	mojito_header_data_t  header_data;
	gint                  offset = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Mojito");
	col_clear(pinfo->cinfo, COL_INFO);

	/* Add a new item to the tree */
	ti = proto_tree_add_item(tree, proto_mojito, tvb, 0, -1, ENC_NA);
	mojito_tree = proto_item_add_subtree(ti, ett_mojito);

	offset = dissect_mojito_header(tvb, pinfo, mojito_tree, offset, &header_data);
	if (offset == 0) /* Some error occurred */
		return 0;

	opcode_item = proto_tree_add_text(mojito_tree, tvb,
					  offset, header_data.payloadlength - MOJITO_HEADER_LENGTH,
					  "Opcode specific data (%s)",
					  val_to_str_const(header_data.opcode, opcodeflags, "Unknown"));
	opcode_tree = proto_item_add_subtree(opcode_item, ett_mojito_opcode);

	/* Now use the opcode to figure out what to do next */
	switch (header_data.opcode)
	{
	case MOJITO_PING_RESPONSE: /* PING RESPONSE */
		dissect_mojito_ping_response(tvb, pinfo, opcode_tree, offset);
		break;

	case MOJITO_STORE_REQUEST: /* STORE REQUEST */
		dissect_mojito_store_request(tvb, pinfo, opcode_tree, offset);
		break;

	case MOJITO_STORE_RESPONSE: /* STORE RESPONSE */
		dissect_mojito_store_response(tvb, pinfo, opcode_tree, offset);
		break;

	case MOJITO_FIND_NODE_REQUEST: /* FIND NODE REQUEST */
		proto_tree_add_item(opcode_tree, hf_mojito_target_kuid, tvb, offset, 20, ENC_NA);
		break;

	case MOJITO_FIND_NODE_RESPONSE: /* FIND NODE RESPONSE */
		dissect_mojito_find_node_response(tvb, pinfo, opcode_tree, offset);
		break;

	case MOJITO_FIND_VALUE_REQUEST: /* FIND VALUE REQUEST */
		dissect_mojito_find_value_request(tvb, pinfo, opcode_tree, offset);
		break;

	case MOJITO_FIND_VALUE_RESPONSE: /* FIND VALUE RESPONSE */
		dissect_mojito_find_value_response(tvb, pinfo, opcode_tree, offset);
		break;

	case MOJITO_PING_REQUEST: /* PING REQUEST */
	case MOJITO_STATS_REQUEST_DEPRECATED: /* STATS REQUEST (DEPRECATED) */
	case MOJITO_STATS_RESPONSE_DEPRECATED: /* STATS RESPONSE (DEPRECATED) */
	default:
		if (header_data.payloadlength - MOJITO_HEADER_LENGTH > 0)
			proto_tree_add_item(opcode_tree, hf_mojito_opcode_data, tvb,
					    offset, header_data.payloadlength - MOJITO_HEADER_LENGTH, ENC_NA);
		break;
	}

	return tvb_length(tvb);
}

static gboolean dissect_mojito_heuristic (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	/*
	  Test the overall length to make sure it's at least 61 bytes (the header)
	  Test to make sure that it's of type 44 (mojito)
	  Test to make sure that the length field is there and correct
	  (tvb_get_letohl(tvb, 20) + 23) == tvb_length(tvb)
	*/
	if ((tvb_length(tvb) >= 60) &&
	    (tvb_get_guint8(tvb, 16) == 68) &&
	    ((tvb_get_letohl(tvb, 19) + 23) == tvb_reported_length(tvb)))
	{
		dissect_mojito(tvb, pinfo, tree, NULL);
		return TRUE;
	}

	return FALSE;
}

/* Register the mojito dissector */
void
proto_register_mojito(void)
{
	module_t *mojito_module;
	expert_module_t* expert_mojito;

	static hf_register_info hf[] = {
		{ &hf_mojito_dhtvaluecount,
		  { "DHTValue Count", "mojito.dhtvaluecount",
		    FT_UINT8, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_messageid,
		  { "Message ID", "mojito.messageid",
		    FT_BYTES, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_requestload,
		  { "Request Load", "mojito.requestload",
		    FT_UINT32, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_fdhtmessage,
		  { "FDHTMessage", "mojito.fdhtmessage",
		    FT_UINT8, BASE_HEX,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_mjrversion,
		  { "Major Version", "mojito.majorversion",
		    FT_UINT8, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_mnrversion,
		  { "Minor Version", "mojito.minorversion",
		    FT_UINT8, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_length,
		  { "Payload Length", "mojito.payloadlength",
		    FT_UINT32, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_opcode,
		  { "OPCode", "mojito.opcode",
		    FT_UINT8, BASE_DEC,
		    VALS(opcodeflags), 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_vendor,
		  { "Vendor", "mojito.vendor",
		    FT_STRING, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_origmjrversion,
		  { "Major Version", "mojito.majorversion",
		    FT_UINT8, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_origmnrversion,
		  { "Minor Version", "mojito.minorversion",
		    FT_UINT8, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_kuid,
		  { "Kademlia Unique ID (KUID)", "mojito.kuid",
		    FT_BYTES, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_socketaddress_version,
		  { "IP Version", "mojito.socketaddressversion",
		    FT_UINT8, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_socketaddress_ipv4,
		  { "IP Address", "mojito.socketaddressipv4",
		    FT_IPv4, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_socketaddress_ipv6,
		  { "IP Address", "mojito.socketaddressipv6",
		    FT_IPv6, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_socketaddress_port,
		  { "IP Port", "mojito.socketaddressport",
		    FT_UINT16, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_instanceid,
		  { "Instance ID", "mojito.instanceid",
		    FT_UINT8, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_flags,
		  { "Flags", "mojito.flags",
		    FT_UINT8, BASE_HEX,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_flags_shutdown,
		  { "SHUTDOWN", "mojito.shutdownflag",
		    FT_BOOLEAN, 8,
		    NULL, 2,
		    NULL, HFILL }
		},
		{ &hf_mojito_flags_firewalled,
		  { "Firewalled", "mojito.firewalledflag",
		    FT_BOOLEAN, 8,
		    NULL, 1,
		    NULL, HFILL }
		},
		{ &hf_mojito_extendedlength,
		  { "Extended Length", "mojito.extlength",
		    FT_UINT16, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_kuidcount,
		  { "Secondary KUID Count", "mojito.kuidcount",
		    FT_UINT8, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_dhtvaluetype,
		  { "DHT Value Type", "mojito.dhtvaluetype",
		    FT_STRING, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_bigintegerlen,
		  { "Big Integer Length", "mojito.bigintegerlen",
		    FT_UINT8, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_bigintegerval,
		  { "Big Integer HEX Value", "mojito.bigintegerhexval",
		    FT_BYTES, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_sectokenlen,
		  { "Security Token Length", "mojito.sectokenlen",
		    FT_UINT8, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_sectoken,
		  { "Security Token", "mojito.sectoken",
		    FT_BYTES, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_contactcount,
		  { "Contact Count", "mojito.contactcount",
		    FT_UINT8, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_contactvendor,
		  { "Vendor", "mojito.contactvendor",
		    FT_STRING, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_contactversion,
		  { "Contact Version", "mojito.contactversion",
		    FT_UINT16, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_contactkuid,
		  { "KUID of the Contact", "mojito.contactkuid",
		    FT_BYTES, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_dhtvalue_valuetype,
		  { "DHTValue ValueType", "mojito.dhtvaluevaluetype",
		    FT_STRING, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_dhtvalue_version,
		  { "DHTValue Version", "mojito.dhtvalueversion",
		    FT_UINT16, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_dhtvalue_length,
		  { "DHTValue Length", "mojito.dhtvaluelength",
		    FT_UINT16, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_dhtvalue_value,
		  { "DHTValue", "mojito.dhtvaluehexvalue",
		    FT_STRING, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_bigint_value_one,
		  { "Big Integer DEC Value", "mojito.bigintegerval",
		    FT_UINT8, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_bigint_value_two,
		  { "Big Integer DEC Value", "mojito.bigintegerval",
		    FT_UINT16, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_bigint_value_three,
		  { "Big Integer DEC Value", "mojito.bigintegerval",
		    FT_UINT24, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_bigint_value_four,
		  { "Big Integer DEC Value", "mojito.bigintegerval",
		    FT_UINT32, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_dhtvalue_kuid,
		  { "Kademlia Unique ID (KUID)", "mojito.kuid",
		    FT_BYTES, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_target_kuid,
		  { "Target Kademlia Unique ID (KUID)", "mojito.kuid",
		    FT_BYTES, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_storestatuscode_count,
		  { "Status Code Count", "mojito.statuscodecount",
		    FT_UINT8, BASE_DEC,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_storestatuscode_code,
		  { "StatusCode", "mojito.statuscodecount",
		    FT_UINT16, BASE_DEC,
		    VALS(statuscodeflags), 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_storestatuscode_kuid,
		  { "Primary KUID of the Status Code", "mojito.statuscodekuid",
		    FT_BYTES, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_storestatuscode_secondary_kuid,
		  { "Secondary KUID of the Status Code", "mojito.statuscodesecondarykuid",
		    FT_BYTES, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_mojito_opcode_data,
		  { "Data", "mojito.opcode.data",
		    FT_BYTES, BASE_NONE,
		    NULL, 0x0,
		    NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_mojito,
		&ett_mojito_header,
		&ett_mojito_header_version,
		&ett_mojito_contact,
		&ett_mojito_contact_version,
		&ett_mojito_socket_address,
		&ett_mojito_flags,
		&ett_mojito_bigint,
		&ett_mojito_opcode,
		&ett_mojito_dht_version,
		&ett_mojito_dht,
		&ett_mojito_status_code,
		&ett_mojito_kuids
	};

	static ei_register_info ei[] = {
		{ &ei_mojito_socketaddress_unknown, { "mojito.socketaddress.unknown", PI_PROTOCOL, PI_ERROR, "Unsupported Socket Address Type", EXPFILL }},
		{ &ei_mojito_bigint_unsupported, { "mojito.bigint.unsupported", PI_PROTOCOL, PI_ERROR, "Unsupported BigInt length", EXPFILL }},
	};

	proto_mojito = proto_register_protocol("Mojito DHT", "Mojito", "mojito");

	proto_register_field_array(proto_mojito, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_mojito = expert_register_protocol(proto_mojito);
	expert_register_field_array(expert_mojito, ei, array_length(ei));

	/* Set the Prefs */
	mojito_module = prefs_register_protocol(proto_mojito, NULL);

	prefs_register_uint_preference(mojito_module,
				       "udp.port",
				       "Mojito UDP Port",
				       "Mojito UDP Port",
				       10,
				       &udp_mojito_port);
}

/* Control the handoff */
void
proto_reg_handoff_mojito(void)
{
	static gboolean           initialized         = FALSE;
	static int                old_mojito_udp_port = 0;
	static dissector_handle_t mojito_handle;

	if (!initialized) {
		mojito_handle = new_create_dissector_handle(dissect_mojito, proto_mojito);
		heur_dissector_add("udp", dissect_mojito_heuristic, proto_mojito);
		initialized = TRUE;
	}

	/* Register UDP port for dissection */
	if(old_mojito_udp_port != 0 && old_mojito_udp_port != udp_mojito_port){
		dissector_delete_uint("udp.port", old_mojito_udp_port, mojito_handle);
	}

	if(udp_mojito_port != 0 && old_mojito_udp_port != udp_mojito_port) {
		dissector_add_uint("udp.port", udp_mojito_port, mojito_handle);
	}

	old_mojito_udp_port = udp_mojito_port;
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
